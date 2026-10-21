"""Q1 (minimal payloads, codec, what stays plaintext), Q2 (who can signal), Q7 (workflow-ID dedupe).

Every process is real. History is read back with the official CLI (`temporal workflow show
--output json`), which has no codec, i.e. it shows what the server stores and any namespace
client can read.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import time
import uuid
from datetime import timedelta

import pytest
from temporalio.api.common.v1 import Payload
from temporalio.client import Client, WorkflowFailureError
from temporalio.common import (
    SearchAttributeKey,
    SearchAttributePair,
    TypedSearchAttributes,
    WorkflowIDConflictPolicy,
    WorkflowIDReusePolicy,
)
from temporalio.exceptions import WorkflowAlreadyStartedError

from harness import fresh_dir, log, start_ticket_service, start_worker, tickets, wait_status
from secure_fixtures import sec_server  # noqa: F401  (fixture)
from secure_harness import (
    PROPOSAL, SECRET_MARKERS, api_approve, cli, history_json, new_action, show_sdb, start_secure_worker,
)
from spike import secure_db as sdb
from spike.codec import (
    ENCODE_FAILURES_ENV, KEYS_ENV, TenantAesGcmCodec, data_converter, keyring_spec, workflow_id_for,
)
from spike.models import Approval, RemediationInput
from spike.secure_models import SecureInput, SecureOutcome
from spike.secure_workflow import SecureRemediationWorkflow
from spike.workflows import RemediationWorkflow

TENANT_KEY = SearchAttributeKey.for_keyword("TenantId")


def run(coro):
    return asyncio.run(coro)


# ---- history inspection helpers -----------------------------------------------------------------
def _walk(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
    else:
        yield path, obj


def payload_dicts(obj):
    """Every dict that looks like a Payload ({metadata: {encoding: ...}, data: ...})."""
    if isinstance(obj, dict):
        md = obj.get("metadata")
        if isinstance(md, dict) and "encoding" in md:
            yield obj
        for v in obj.values():
            yield from payload_dicts(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from payload_dicts(v)


def b64(s: str) -> str:
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def find_markers(raw_json: str, markers: list[str]) -> dict[str, list[str]]:
    """Where each marker appears: in the raw JSON text, or inside base64-decoded string fields."""
    doc = json.loads(raw_json)
    hits: dict[str, list[str]] = {m: [] for m in markers}
    for path, val in _walk(doc):
        if not isinstance(val, str):
            continue
        for m in markers:
            if m in val:
                hits[m].append(f"{path} (plain)")
            elif len(val) >= 8 and m in b64(val):
                hits[m].append(f"{path} (base64)")
    return {m: h for m, h in hits.items() if h}


def encodings(raw_json: str, skip_search_attributes: bool = False) -> dict[str, int]:
    doc = json.loads(raw_json)
    if skip_search_attributes:
        for ev in doc.get("events", []):
            for attrs in ev.values():
                if isinstance(attrs, dict):
                    attrs.pop("searchAttributes", None)
    out: dict[str, int] = {}
    for p in payload_dicts(doc):
        enc = p["metadata"]["encoding"]
        enc = b64(enc) or enc
        out[enc] = out.get(enc, 0) + 1
    return out


def key_ids(raw_json: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for p in payload_dicts(json.loads(raw_json)):
        kid = p["metadata"].get("encryption-key-id")
        if kid:
            kid = b64(kid) or kid
            out[kid] = out.get(kid, 0) + 1
    return out


def plaintext_fields(raw_json: str) -> dict[str, list[str]]:
    """Selected non-payload fields that the server stores readable, whatever the codec does."""
    doc = json.loads(raw_json)
    wanted = ("workflowType", "taskQueue", "activityType", "signalName", "identity", "searchAttributes",
              "eventTime", "failure", "memo")
    out: dict[str, list[str]] = {}
    for ev in doc.get("events", []):
        for attrs_name, attrs in ev.items():
            if not attrs_name.endswith("EventAttributes"):
                continue
            for k in wanted:
                if k in attrs:
                    out.setdefault(k, []).append(json.dumps(attrs[k])[:160])
        out.setdefault("eventTime", []).append(ev.get("eventTime", ""))
    return {k: sorted(set(v))[:6] for k, v in out.items()}


# =================================================================================================
# Q1. Minimal payloads + payload codec + what stays plaintext.
def test_q1_minimal_payloads_and_codec(sec_server):
    async def body():
        d = fresh_dir("q1-payloads")
        pdb = str(d / "platform.db")
        ts, url = start_ticket_service(d)
        keyring = {"platform": os.urandom(32), "tenant-a": os.urandom(32), "tenant-b": os.urandom(32)}
        codec_env = {KEYS_ENV: keyring_spec(keyring)}
        q_orig, q_plain, q_enc = (f"q1-{x}-{uuid.uuid4().hex[:4]}" for x in ("orig", "plain", "enc"))
        w_orig = start_worker(d, sec_server.address, q_orig, 1)
        w_plain = start_secure_worker(d, sec_server.address, q_plain, "w-plain", platform_db=pdb, ticket_url=url)
        w_enc = start_secure_worker(d, sec_server.address, q_enc, "w-enc", platform_db=pdb, ticket_url=url,
                                    env=codec_env)
        plain_client = await Client.connect(sec_server.address)
        enc_client = await Client.connect(sec_server.address, data_converter=data_converter(keyring, False))
        results = {}
        try:
            # A. Baseline: the original workflow carries the whole proposal as input.
            wf_a = f"orig-{uuid.uuid4().hex[:8]}"
            h = await plain_client.start_workflow(
                RemediationWorkflow.run, RemediationInput(proposal=PROPOSAL, platform_db=str(d / "orig.db"),
                                                          ticket_url=url), id=wf_a, task_queue=q_orig)
            await wait_status(h, "awaiting_approval")
            hj = history_json(sec_server.address, wf_a)
            (d / "history-A-original.json").write_text(hj)
            results["A"] = find_markers(hj, SECRET_MARKERS)
            log(f"A original workflow, no codec: markers found = {json.dumps(results['A'])[:400]}")
            log(f"A payload encodings: {encodings(hj)}")
            await h.terminate("q1 done")
            assert results["A"], "expected the original workflow to expose proposal text in history"

            # B. Ids-only workflow, no codec.
            run_b, dig_b, wf_b = new_action(pdb, "tenant-a")
            h = await plain_client.start_workflow(SecureRemediationWorkflow.run, SecureInput("tenant-a", run_b, dig_b),
                                                  id=wf_b, task_queue=q_plain)
            await wait_status(h, "awaiting_approval")
            apr_b = api_approve(pdb, "tenant-a", run_b, dig_b)
            await h.signal(SecureRemediationWorkflow.approval_ready, apr_b)
            out_b = await asyncio.wait_for(h.result(), 60)
            log(f"B result: {out_b}")
            assert out_b.status == "completed"
            hj = history_json(sec_server.address, wf_b)
            (d / "history-B-ids-only.json").write_text(hj)
            results["B"] = find_markers(hj, SECRET_MARKERS)
            ids = find_markers(hj, ["tenant-a", run_b, dig_b, apr_b, out_b.ticket_id])
            log(f"B ids-only, no codec: secret markers = {results['B']}")
            log(f"B identifiers visible: {sorted(ids)}")
            log(f"B payload encodings: {encodings(hj)}")
            assert results["B"] == {}
            assert dig_b in ids and apr_b in ids  # identifiers are in plaintext without a codec

            # C. Ids-only workflow with the AES-GCM codec, plus memo and a search attribute.
            run_c, dig_c, wf_c = new_action(pdb, "tenant-a")
            h = await enc_client.start_workflow(
                SecureRemediationWorkflow.run, SecureInput("tenant-a", run_c, dig_c), id=wf_c, task_queue=q_enc,
                memo={"memo_note": "MEMO-NOTE-c41"},
                search_attributes=TypedSearchAttributes([SearchAttributePair(TENANT_KEY, "tenant-a")]))
            await wait_status(h, "awaiting_approval")
            apr_c = api_approve(pdb, "tenant-a", run_c, dig_c)
            await h.signal(SecureRemediationWorkflow.approval_ready, apr_c)
            out_c = await asyncio.wait_for(h.result(), 60)
            log(f"C result (decoded by codec client): {out_c}")
            hj = history_json(sec_server.address, wf_c)
            (d / "history-C-ids-only-codec.json").write_text(hj)
            sec = find_markers(hj, SECRET_MARKERS)
            ids = find_markers(hj, ["tenant-a", run_c, dig_c, apr_c, out_c.ticket_id, "MEMO-NOTE-c41"])
            log(f"C codec: secret markers = {sec}")
            log(f"C codec: identifiers still visible = { {k: v[:3] for k, v in ids.items()} }")
            log(f"C payload encodings: {encodings(hj)}")
            log(f"C key ids used: {key_ids(hj)}")
            for k, v in plaintext_fields(hj).items():
                log(f"C plaintext field {k}: {v}")
            assert sec == {}
            for opaque in (dig_c, apr_c, out_c.ticket_id, "MEMO-NOTE-c41", run_c):
                assert not any(opaque in h_ for h_ in ids.get(opaque, []) if "workflowId" not in h_), \
                    f"{opaque} visible outside workflowId: {ids.get(opaque)}"
            # The only unencoded payloads are search attributes (the server must index them).
            log(f"C payload encodings excluding search attributes: {encodings(hj, True)}")
            assert set(encodings(hj, True)) == {"binary/encrypted"}
            # Describe output: memo and search attributes as the server returns them.
            r = cli(sec_server.address, "workflow", "describe", "--workflow-id", wf_c, "--output", "json", check=True)
            desc = json.loads(r.stdout)
            ex = desc.get("workflowExecutionInfo", {})
            log(f"C describe.memo = {json.dumps(ex.get('memo'))[:200]}")
            log(f"C describe.searchAttributes = {json.dumps(ex.get('searchAttributes'))[:200]}")
            # Visibility query by tenant works because search attributes are NOT encoded.
            r = cli(sec_server.address, "workflow", "list", "--query", 'TenantId="tenant-a"', "--output", "json")
            log(f"C list TenantId=tenant-a -> {len(json.loads(r.stdout or '[]'))} execution(s)")

            # Crypto-shredding check: without tenant-a's key the history cannot be decoded.
            hist = await enc_client.get_workflow_handle(wf_c).fetch_history()
            started = hist.events[0].workflow_execution_started_event_attributes.input.payloads
            ok = await TenantAesGcmCodec(keyring).decode(list(started))
            log(f"C decode with full keyring: {ok[0].data[:80]!r}")
            try:
                await TenantAesGcmCodec({k: v for k, v in keyring.items() if k != "tenant-a"}).decode(list(started))
                shred = "decoded"
            except KeyError as e:
                shred = f"KeyError: {e}"
            log(f"C decode after destroying tenant-a key: {shred}")
            assert shred.startswith("KeyError")

            # D. Failure messages: default failure converter vs encode_common_attributes, codec on both.
            for encode_failures in (False, True):
                q = f"q1-fail{int(encode_failures)}-{uuid.uuid4().hex[:4]}"
                w = start_secure_worker(d, sec_server.address, q, f"w-fail{int(encode_failures)}", platform_db=pdb,
                                        ticket_url=url, env={**codec_env,
                                                             ENCODE_FAILURES_ENV: "1" if encode_failures else "0"})
                cl = await Client.connect(sec_server.address, data_converter=data_converter(keyring, encode_failures))
                run_d, dig_d, wf_d = new_action(pdb, "tenant-a", {**PROPOSAL, "force_failure": True})
                h = await cl.start_workflow(SecureRemediationWorkflow.run, SecureInput("tenant-a", run_d, dig_d),
                                            id=wf_d, task_queue=q)
                try:
                    await asyncio.wait_for(h.result(), 60)
                    err = "no error"
                except WorkflowFailureError as e:
                    err = f"{e.cause}"
                log(f"D encode_common_attributes={encode_failures}: client-side (decoded) error: {err[:120]}")
                hj = history_json(sec_server.address, wf_d)
                (d / f"history-D-failure-encode{int(encode_failures)}.json").write_text(hj)
                leak = find_markers(hj, ["openssl", "scanner rejected proposal"])
                msgs = sorted({v for p, v in _walk(json.loads(hj)) if p.endswith(".message") and isinstance(v, str)})
                log(f"D encode_common_attributes={encode_failures}: failure .message values in history = {msgs}")
                log(f"D encode_common_attributes={encode_failures}: leaked markers = {leak}")
                results[f"D{int(encode_failures)}"] = leak
                w.stop()
            assert results["D0"], "expected the default failure converter to leak the message"
            assert results["D1"] == {}, "expected encoded failure attributes to hide the message"
        finally:
            for w in (w_orig, w_plain, w_enc):
                w.stop()
            ts.stop()
    run(body())


# =================================================================================================
# Q2. Any client with namespace access can read history and send the approval signal.
def test_q2_any_client_can_signal(sec_server):
    async def body():
        d = fresh_dir("q2-signal-authz")
        pdb = str(d / "platform.db")
        ts, url = start_ticket_service(d)
        q_orig = f"q2-orig-{uuid.uuid4().hex[:4]}"
        q_sec = f"q2-sec-{uuid.uuid4().hex[:4]}"
        w_orig = start_worker(d, sec_server.address, q_orig, 1)
        w_sec = start_secure_worker(d, sec_server.address, q_sec, "w-sec", platform_db=pdb, ticket_url=url)
        app = await Client.connect(sec_server.address, identity="platform-api")
        # "Attacker": any process that can reach the frontend. No credentials of any kind.
        attacker = await Client.connect(sec_server.address, identity="definitely-the-approver")
        try:
            # A. Original design: approval is the signal payload. The attacker reads the proposal
            #    from history, computes its digest and approves it.
            wf = f"orig-{uuid.uuid4().hex[:8]}"
            h = await app.start_workflow(RemediationWorkflow.run,
                                         RemediationInput(proposal=PROPOSAL, platform_db=str(d / "orig.db"),
                                                          ticket_url=url), id=wf, task_queue=q_orig)
            await wait_status(h, "awaiting_approval")
            ah = attacker.get_workflow_handle(wf)
            hist = await ah.fetch_history()
            stolen = json.loads(hist.events[0].workflow_execution_started_event_attributes.input.payloads[0].data)
            from spike.activities import digest_of
            forged = Approval(approver="ceo@example.test", payload_digest=digest_of(stolen["proposal"]),
                              expires_at="2099-01-01T00:00:00+00:00")
            await ah.signal("approve", forged)
            out = await asyncio.wait_for(h.result(), 60)
            hist = await h.fetch_history()
            sig = [e for e in hist.events if e.HasField("workflow_execution_signaled_event_attributes")][0]
            log(f"A attacker read input ({len(stolen['proposal'])} proposal fields) and signalled; "
                f"result={out.status}/{out.detail}; tickets={len(tickets(url))}; "
                f"signal event identity={sig.workflow_execution_signaled_event_attributes.identity!r}")
            assert out.status == "completed" and len(tickets(url)) == 1

            # B. Ids-only design: signal carries only an approval id; the activity checks the DB.
            run_b, dig_b, wf_b = new_action(pdb, "tenant-a")
            h = await app.start_workflow(SecureRemediationWorkflow.run, SecureInput("tenant-a", run_b, dig_b),
                                         id=wf_b, task_queue=q_sec)
            await wait_status(h, "awaiting_approval")
            # Another tenant's real approval, and a made-up id.
            run_x, dig_x, _ = new_action(pdb, "tenant-b")
            other_tenant_apr = api_approve(pdb, "tenant-b", run_x, dig_x)
            ah = attacker.get_workflow_handle(wf_b)
            await ah.signal("approval_ready", "apr-forged-000")
            await ah.signal("approval_ready", other_tenant_apr)
            await asyncio.sleep(3)
            st = await h.query(SecureRemediationWorkflow.status)
            log(f"B after 2 attacker signals: status={st}, tickets={len(tickets(url))}")
            assert st == "awaiting_approval" and len(tickets(url)) == 1  # still only the ticket from A
            apr = api_approve(pdb, "tenant-a", run_b, dig_b)
            await h.signal(SecureRemediationWorkflow.approval_ready, apr)
            out = await asyncio.wait_for(h.result(), 60)
            log(f"B after API approval: {out}")
            show_sdb(pdb, ("workflow_events",))
            ev = [(e["event"], e["detail"]) for e in sdb.dump(pdb, "workflow_events") if e["run_id"] == run_b]
            assert ev[:2] == [("approval_signal_rejected", "unknown_approval"),
                              ("approval_signal_rejected", "wrong_tenant_or_run")]
            assert out.status == "completed" and len(tickets(url)) == 2

            # C. The same unauthenticated client can also terminate any execution (denial of service).
            run_c, dig_c, wf_c = new_action(pdb, "tenant-a")
            h = await app.start_workflow(SecureRemediationWorkflow.run, SecureInput("tenant-a", run_c, dig_c),
                                         id=wf_c, task_queue=q_sec)
            await wait_status(h, "awaiting_approval")
            await attacker.get_workflow_handle(wf_c).terminate("attacker")
            desc = await h.describe()
            log(f"C attacker terminate -> status={desc.status.name}")
            assert desc.status.name == "TERMINATED"
        finally:
            w_orig.stop(); w_sec.stop(); ts.stop()
    run(body())


# =================================================================================================
# Q7. Workflow-ID conflict and reuse policies as the duplicate-action guard.
def test_q7_workflow_id_dedupe(sec_server):
    async def body():
        d = fresh_dir("q7-dedupe")
        pdb = str(d / "platform.db")
        ts, url = start_ticket_service(d)
        q = f"q7-{uuid.uuid4().hex[:4]}"
        w = start_secure_worker(d, sec_server.address, q, "w-q7", platform_db=pdb, ticket_url=url)
        c = await Client.connect(sec_server.address)
        try:
            run_id, dig, wf = new_action(pdb, "tenant-a")
            inp = SecureInput("tenant-a", run_id, dig, approval_window_seconds=4)
            h1 = await c.start_workflow(SecureRemediationWorkflow.run, inp, id=wf, task_queue=q)
            log(f"start #1 ok run_id={h1.result_run_id}")
            # Second start while running, default policy.
            try:
                await c.start_workflow(SecureRemediationWorkflow.run, inp, id=wf, task_queue=q)
                second = "started"
            except WorkflowAlreadyStartedError as e:
                second = f"WorkflowAlreadyStartedError: {e}"
            log(f"start #2 (default conflict policy) -> {second}")
            assert second.startswith("WorkflowAlreadyStartedError")
            # USE_EXISTING returns the running execution.
            h3 = await c.start_workflow(SecureRemediationWorkflow.run, inp, id=wf, task_queue=q,
                                        id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING)
            log(f"start #3 (USE_EXISTING) -> run_id={h3.result_run_id} same={h3.result_run_id == h1.result_run_id}")
            assert h3.result_run_id == h1.result_run_id
            # 20 concurrent starts of a fresh id: exactly one wins.
            run2, dig2, wf2 = new_action(pdb, "tenant-a")
            inp2 = SecureInput("tenant-a", run2, dig2, approval_window_seconds=4)
            clients = [await Client.connect(sec_server.address) for _ in range(4)]
            res = await asyncio.gather(*(clients[i % 4].start_workflow(SecureRemediationWorkflow.run, inp2, id=wf2,
                                                                       task_queue=q) for i in range(20)),
                                       return_exceptions=True)
            wins = [r for r in res if not isinstance(r, Exception)]
            errs = {type(r).__name__ for r in res if isinstance(r, Exception)}
            log(f"20 concurrent starts of {wf2}: {len(wins)} started, {20 - len(wins)} rejected ({errs})")
            assert len(wins) == 1
            # After the run closes: default reuse policy allows a new run; REJECT_DUPLICATE does not.
            out = await asyncio.wait_for(h1.result(), 30)
            log(f"run #1 closed: {out.status}")
            try:
                await c.start_workflow(SecureRemediationWorkflow.run, inp, id=wf, task_queue=q,
                                       id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE)
                rej = "started"
            except WorkflowAlreadyStartedError as e:
                rej = f"WorkflowAlreadyStartedError: {e}"
            log(f"start after close with REJECT_DUPLICATE -> {rej}")
            assert rej.startswith("WorkflowAlreadyStartedError")
            h5 = await c.start_workflow(SecureRemediationWorkflow.run, inp, id=wf, task_queue=q)
            log(f"start after close with default reuse policy -> NEW run_id={h5.result_run_id} "
                f"(differs={h5.result_run_id != h1.result_run_id})")
            assert h5.result_run_id != h1.result_run_id
            await h5.terminate("q7 done")
            await asyncio.wait_for(wins[0].result(), 30)
        finally:
            w.stop(); ts.stop()
    run(body())
