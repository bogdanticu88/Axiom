// Priority rationale and overrides; action proposals, approvals, execution and reconciliation; remediation reports,
// verification and closure.
import { useState } from "react";
import { newKey, post, useGet } from "../api";
import { Badge, Field, Loaded, Section, fmt, short, supportLabel, useCommand } from "../ui";
import { priorityBadge } from "./Cases";

function inDays(days: number) {
  return new Date(Date.now() + days * 86400_000).toISOString().slice(0, 16);
}
function iso(local: string) {
  return local ? new Date(local).toISOString() : null;
}

export function Priority({ c, onChange }: { c: any; onChange: () => void }) {
  const [p, reload] = useGet<any>(`/cases/${c.id}/priority`, [c.record_version]);
  const cmd = useCommand(() => { reload(); onChange(); });
  const [rationale, setRationale] = useState("");
  const [level, setLevel] = useState("high");
  const [expires, setExpires] = useState(inDays(30));
  return (
    <>
      <Section title="Priority rationale">
        <Loaded load={p} onRetry={reload}>
          {(d) => {
            const active = d.overrides.find((o: any) => !o.ended_at);
            return (
              <>
                <div className="facts"><span>Current {priorityBadge(d.priority)}</span>
                  {active && <span data-testid="active-override"><Badge kind="manual">manual override</Badge> until {fmt(active.expires_at)}
                    {" "}(was {active.priority_before})</span>}</div>
                {d.decisions.length === 0 ? <div className="state" data-state="empty">No priority decision yet.</div> : (
                  <table data-testid="priority-decisions">
                    <thead><tr><th>When</th><th>Kind</th><th>Result</th><th>Rationale</th><th>Inputs and provenance</th></tr></thead>
                    <tbody>{d.decisions.map((x: any) => (
                      <tr key={x.id}><td>{fmt(x.recorded_at)}</td>
                        <td>{x.kind === "priority_override" ? <Badge kind="manual">override</Badge> : "policy"}</td>
                        <td>{x.outcome}</td><td className="small">{x.rationale}
                          {x.limitations && <div className="muted">Limitations: {x.limitations}</div>}</td>
                        <td className="small">{x.policy_version_id && <div>policy {short(x.policy_version_id)}</div>}
                          {x.payload?.provenance?.override_id && <div data-testid="expiry-provenance">
                            <Badge kind="info">override expiry reassessment</Badge> override {short(x.payload.provenance.override_id)}
                            {" "}({x.payload.provenance.override_priority}) expired {fmt(x.payload.provenance.override_expired_at)}</div>}
                          {x.payload?.inputs && <details><summary>inputs</summary>
                            <pre>{JSON.stringify(x.payload.inputs, null, 1)}</pre></details>}</td></tr>))}</tbody>
                  </table>)}
                <h3>Overrides</h3>
                {d.overrides.length === 0 ? <div className="state" data-state="empty">None.</div> : (
                  <table data-testid="overrides">
                    <thead><tr><th>Set</th><th>Priority</th><th>Expires</th><th>Ended</th></tr></thead>
                    <tbody>{d.overrides.map((o: any) => (
                      <tr key={o.id}><td>{fmt(o.created_at)} by {short(o.created_by)}</td><td>{o.priority}</td>
                        <td>{fmt(o.expires_at)}</td>
                        <td>{o.ended_at ? <>{fmt(o.ended_at)} ({o.end_reason})</> : "in force"}</td></tr>))}</tbody>
                  </table>)}
                <p className="muted small">When an override expires the platform re-applies the published policy to current
                  inputs and records why. It never restores the priority that was in force before the override.</p>
              </>);
          }}
        </Loaded>
      </Section>
      <Section title="Change priority">
        <Field label="Rationale"><textarea data-testid="priority-rationale" value={rationale}
          onChange={(e) => setRationale(e.target.value)} /></Field>
        <div className="row">
          <button data-testid="apply-policy" disabled={cmd.busy || !rationale} onClick={() => cmd.run(() =>
            post(`/cases/${c.id}/commands/apply-priority-policy`, { expected_version: c.record_version, rationale }),
            "Policy applied.")}>Apply published policy</button>
          <Field label="Override to">
            <select data-testid="override-level" value={level} onChange={(e) => setLevel(e.target.value)}>
              {["urgent", "high", "medium", "low"].map((l) => <option key={l}>{l}</option>)}</select></Field>
          <Field label="Override expires (max 365 days)">
            <input type="datetime-local" data-testid="override-expires" value={expires}
                   onChange={(e) => setExpires(e.target.value)} /></Field>
          <button data-testid="override" disabled={cmd.busy || !rationale} onClick={() => cmd.run(() =>
            post(`/cases/${c.id}/commands/override-priority`, { expected_version: c.record_version, rationale,
              priority: level, expires_at: iso(expires) }), "Override recorded.")}>Override</button>
        </div>
        {cmd.status}
      </Section>
    </>
  );
}

export function Actions({ c, onChange }: { c: any; onChange: () => void }) {
  const [list, reload] = useGet<{ items: any[] }>(`/cases/${c.id}/action-proposals`, [c.record_version]);
  const [conns] = useGet<{ items: any[] }>("/connections");
  const cmd = useCommand(() => { reload(); onChange(); });
  const [connection, setConnection] = useState("");
  const [summary, setSummary] = useState(`Remediate: ${c.title}`.slice(0, 200));
  const [project, setProject] = useState("SEC");
  const [criteria, setCriteria] = useState("Rescan shows the vulnerability absent on the deployed digest.");
  return (
    <>
      <Section title="Propose a ticket">
        <p className="muted small">A proposal changes nothing outside the platform. Another person must approve the exact
          payload; execution then uses that approval once. Production changes are a separately controlled capability and
          are not enabled.</p>
        <Loaded load={conns} isEmpty={(d) => d.items.length === 0} empty="No ticketing connection is configured.">
          {(d) => (
            <form className="inline" onSubmit={(e) => { e.preventDefault(); const id = connection || d.items[0].id;
              const adapter = d.items.find((x) => x.id === id)?.adapter;
              cmd.run(() => post("/action-proposals", { case_id: c.id, effect_class: "ticket.create", connection_id: id,
                payload: adapter === "jira_style" ? { project_key: project, summary } : { summary },
                verification_criteria: criteria, expires_at: new Date(Date.now() + 14 * 86400_000).toISOString() },
                { "Idempotency-Key": newKey() }), "Proposal created."); }}>
              <Field label="Connection">
                <select data-testid="connection" value={connection} onChange={(e) => setConnection(e.target.value)}>
                  {d.items.map((x) => <option key={x.id} value={x.id}>{x.display_name} ({x.adapter})</option>)}
                </select></Field>
              <span>{supportLabel((d.items.find((x) => x.id === connection) ?? d.items[0]).support_level)}</span>
              <Field label="Project key (Jira-style)"><input value={project} onChange={(e) => setProject(e.target.value)} /></Field>
              <Field label="Summary"><input className="wide" value={summary} onChange={(e) => setSummary(e.target.value)} /></Field>
              <Field label="Verification criteria"><input className="wide" value={criteria}
                onChange={(e) => setCriteria(e.target.value)} /></Field>
              <button data-testid="propose" disabled={cmd.busy}>Propose</button>
            </form>)}
        </Loaded>
        {cmd.status}
      </Section>
      <Section title="Proposals">
        <Loaded load={list} onRetry={reload} isEmpty={(d) => d.items.length === 0} empty="No proposal for this case.">
          {(d) => <>{d.items.map((p) => <Proposal key={p.id} p={p} conns={conns.state === "ok" ? conns.data.items : []}
                                                    onChange={() => { reload(); onChange(); }} />)}</>}
        </Loaded>
      </Section>
    </>
  );
}

function Proposal({ p, conns, onChange }: { p: any; conns: any[]; onChange: () => void }) {
  const cmd = useCommand(onChange);
  const [rationale, setRationale] = useState("");
  const current = p.versions.find((v: any) => v.version === p.current_version) ?? p.versions[p.versions.length - 1];
  const usable = p.approvals.filter((a: any) => a.decision === "approved" && a.status === "active"
    && a.proposal_version_id === current?.id);
  const conn = conns.find((x) => x.id === p.connection_id);
  return (
    <div className="claim" data-testid="proposal" data-status={p.status}>
      <div><strong>{p.effect_class}</strong> v{p.current_version} · <Badge kind={p.status === "open" ? "info" : "warn"}>{p.status}</Badge>
        {conn && <> · {conn.display_name} {supportLabel(conn.support_level)}</>}</div>
      {current && <>
        <pre className="small" data-testid="approved-payload">{JSON.stringify(current.canonical_payload ?? current.payload, null, 1)}</pre>
        <div className="small muted">payload digest {String(current.payload_digest).slice(0, 16)} · expires {fmt(current.expires_at)}
          · proposed by {short(current.created_by)}</div>
        <div className="small">Verification criteria: {current.verification_criteria}</div></>}
      <h3>Approvals</h3>
      {p.approvals.length === 0 ? <div className="small muted">None yet. The proposer cannot approve their own proposal.</div> :
        <ul className="small" data-testid="approvals">{p.approvals.map((a: any) => <li key={a.id}>{a.decision} by {short(a.approver_principal_id)} ·
          {" "}{a.status} · uses {a.uses_reserved - a.uses_released}/{a.max_uses} · valid until {fmt(a.valid_until)}
          {a.revocation_reason && <> · revoked: {a.revocation_reason}</>}</li>)}</ul>}
      {p.status === "open" && <div className="row">
        <input aria-label="decision rationale" placeholder="rationale" value={rationale} onChange={(e) => setRationale(e.target.value)} />
        <button data-testid="approve" disabled={cmd.busy || !rationale} onClick={() => cmd.run(() =>
          post(`/action-proposals/${p.id}/versions/${p.current_version}/decisions`, { decision: "approved", rationale },
               { "Idempotency-Key": newKey() }), "Approved.")}>Approve this version</button>
        <button disabled={cmd.busy || !rationale} onClick={() => cmd.run(() =>
          post(`/action-proposals/${p.id}/versions/${p.current_version}/decisions`, { decision: "rejected", rationale },
               { "Idempotency-Key": newKey() }), "Rejected.")}>Reject</button>
        {usable.map((a: any) => <button key={a.id} data-testid="execute" disabled={cmd.busy} onClick={() => cmd.run(() =>
          post(`/action-proposals/${p.id}/versions/${p.current_version}/executions`, { approval_id: a.id },
               { "Idempotency-Key": newKey() }), "Execution requested.")}>Execute with approval {short(a.id)}</button>)}
      </div>}
      <h3>Executions</h3>
      {p.executions.length === 0 ? <div className="small muted">None.</div> :
        <table className="small"><thead><tr><th>Requested</th><th>State</th><th>External ref</th><th>Detail</th><th /></tr></thead>
          <tbody>{p.executions.map((x: any) => <tr key={x.id} data-testid="execution"><td>{fmt(x.created_at)}</td>
            <td>{x.state === "reconciling" ? <Badge kind="warn">outcome unknown — reconcile</Badge> : x.state}</td>
            <td>{x.external_ref ?? "—"}</td><td><code>{JSON.stringify(x.outcome_detail)}</code></td>
            <td>{x.state === "reconciling" && <Reconcile id={x.id} onDone={onChange} />}</td></tr>)}</tbody></table>}
      {cmd.status}
    </div>
  );
}

function Reconcile({ id, onDone }: { id: string; onDone: () => void }) {
  const cmd = useCommand(onDone);
  const [resolution, setResolution] = useState("adopt");
  const [ref, setRef] = useState("");
  const [rationale, setRationale] = useState("");
  return (
    <form className="inline" onSubmit={(e) => { e.preventDefault(); cmd.run(() => post(`/action-executions/${id}/reconcile`,
      { resolution, rationale, external_ref: ref || null }), "Reconciled."); }}>
      <select aria-label="resolution" value={resolution} onChange={(e) => setResolution(e.target.value)}>
        <option value="adopt">ticket exists: adopt</option><option value="not_applied">not created</option>
        <option value="abandon">abandon</option></select>
      <input aria-label="external reference" placeholder="external ref" value={ref} onChange={(e) => setRef(e.target.value)} />
      <input aria-label="reconcile rationale" placeholder="what you checked" value={rationale}
             onChange={(e) => setRationale(e.target.value)} required />
      <button disabled={cmd.busy}>Record</button>{cmd.status}
    </form>
  );
}

export function Verification({ c, onChange }: { c: any; onChange: () => void }) {
  const [h, reload] = useGet<any>(`/cases/${c.id}/history`, [c.record_version]);
  const [ctx] = useGet<any>(`/cases/${c.id}/context`, [c.id]);
  const cmd = useCommand(() => { reload(); onChange(); });
  const [rationale, setRationale] = useState("");
  const [owner, setOwner] = useState("");
  const [target, setTarget] = useState("");
  const [change, setChange] = useState("");
  const [result, setResult] = useState("passed");
  const [coverage, setCoverage] = useState("complete");
  const [observed, setObserved] = useState("");
  const [evidence, setEvidence] = useState("");
  const v = c.record_version;
  const send = (path: string, body: object, ok: string) =>
    cmd.run(() => post(`/cases/${c.id}/commands/${path}`, { expected_version: v, rationale, ...body }), ok);
  const versions: any[] = ctx.state === "ok" ? ctx.data.asset_versions : [];
  return (
    <>
      <Section title="Verification runs and closure">
        <Loaded load={h} onRetry={reload}>
          {(d) => (
            <>
              {d.verifications.length === 0 ? <div className="state" data-state="empty">No verification recorded.</div> : (
                <table data-testid="verifications">
                  <thead><tr><th>Recorded</th><th>Outcome</th><th>Coverage</th><th>Observed deployment</th><th>Reason</th><th /></tr></thead>
                  <tbody>{d.verifications.map((r: any) => (
                    <tr key={r.id} data-outcome={r.outcome} data-recorder={r.recorder_kind}><td>{fmt(r.recorded_at)}
                      <div className="small">{r.recorder_kind === "workload"
                        ? <><Badge kind="info" title="Recorded by the tenant's verification identity from a check
                            endpoint response; not a person's judgement">automated check (worker)</Badge>{" "}
                            {supportLabel("fixture-tested")}</>
                        : <Badge kind="manual">recorded by a person</Badge>} {short(r.recorded_by)}</div>
                      {r.observation && <dl className="small" data-testid="observation">
                        <dt>Source</dt><dd>{r.observation.source_origin}</dd>
                        <dt>Examined by the endpoint</dt><dd>{r.observation.target_observed_at
                          ? fmt(r.observation.target_observed_at) : "unknown"}</dd>
                        <dt>Rule</dt><dd>{r.observation.rule}</dd></dl>}</td>
                      <td><Badge kind={r.outcome === "passed" ? "ok" : r.outcome === "failed" ? "bad" : "warn"}>{r.outcome}</Badge></td>
                      <td>{r.coverage}</td><td>{short(r.observed_asset_version_id)}</td><td className="small">{r.outcome_reason}</td>
                      <td>{r.outcome === "passed" && c.workflow === "awaiting_verification" &&
                        <button data-testid="close-verified" disabled={cmd.busy || !rationale}
                          onClick={() => send("close-verified", { verification_run_id: r.id }, "Case closed.")}>Close as verified</button>}</td>
                    </tr>))}</tbody>
                </table>)}
              {d.closures.length > 0 && <ul data-testid="closures">{d.closures.map((x: any) =>
                <li key={x.id ?? x.case_event_sequence}>Closed: {x.disposition ?? x.kind} {fmt(x.closed_at ?? x.created_at)}</li>)}</ul>}
              <p className="muted small">Results come from a person after a check, or from the verification worker
                when a check endpoint is configured for this project (tested only against a local fixture endpoint).
                The platform recomputes every outcome: a pass needs complete coverage of the reported deployment and
                verified evidence, and the person who reported the change cannot verify it. Closing is always a
                person's decision.</p>
            </>)}
        </Loaded>
      </Section>
      <Section title={`Next step (workflow: ${c.workflow})`}>
        <Field label="Rationale (required for every decision)"><textarea data-testid="verify-rationale" value={rationale}
          onChange={(e) => setRationale(e.target.value)} /></Field>
        {c.workflow === "review_required" && c.assessment === "supported" && (
          <div className="row"><Field label="Remediation owner principal id"><input value={owner}
            onChange={(e) => setOwner(e.target.value)} /></Field>
            <button disabled={cmd.busy || !rationale || !owner} onClick={() => send("plan-remediation",
              { owner_principal_id: owner }, "Remediation planned.")}>Plan remediation</button></div>)}
        {c.workflow === "remediation_planned" && (
          <div className="row">
            <Field label="External work reference (e.g. ticket key)"><input data-testid="external-ref" value={change}
              onChange={(e) => setChange(e.target.value)} /></Field>
            <button data-testid="record-external-work" disabled={cmd.busy || !rationale || !change} onClick={() =>
              send("record-external-work", { external_reference: change }, "External work recorded.")}>
              Record external work</button></div>)}
        {c.workflow === "remediating" && (
          <div className="row">
            <Field label="Fixed deployment"><select value={target} onChange={(e) => setTarget(e.target.value)}>
              <option value="">choose…</option>{versions.map((x) => <option key={x.id} value={x.id}>
                {x.deployment_digest ?? short(x.id)}{x.provenance !== "ingestion" ? " (manually recorded)" : ""}</option>)}</select></Field>
            <Field label="Change reference"><input value={change} onChange={(e) => setChange(e.target.value)} /></Field>
            <button data-testid="report-change" disabled={cmd.busy || !rationale || !target || !change} onClick={() =>
              send("report-change", { target_asset_version_id: target, change_reference: change }, "Change reported.")}>
              Report change deployed</button></div>)}
        {c.workflow === "awaiting_verification" && (
          <div className="row">
            <Field label="Result"><select data-testid="verify-result" value={result} onChange={(e) => setResult(e.target.value)}>
              <option>passed</option><option>failed</option><option>inconclusive</option></select></Field>
            <Field label="Coverage"><select data-testid="verify-coverage" value={coverage} onChange={(e) => setCoverage(e.target.value)}>
              <option>complete</option><option>partial</option><option>none</option></select></Field>
            <Field label="Observed deployment"><select data-testid="verify-observed" value={observed}
              onChange={(e) => setObserved(e.target.value)}>
              <option value="">unknown</option>{versions.map((x) => <option key={x.id} value={x.id}>
                {x.deployment_digest ?? short(x.id)}</option>)}</select></Field>
            <Field label="Verified evidence id (upload first)"><input data-testid="verify-evidence" value={evidence}
              onChange={(e) => setEvidence(e.target.value)} /></Field>
            <button data-testid="record-verification" disabled={cmd.busy || !rationale} onClick={() =>
              send("record-verification", { claimed_result: result, coverage, criteria: { check: "rescan", by: "ui" },
                observed_asset_version_id: observed || null, evidence_id: evidence || null }, "Verification recorded.")}>
              Record verification</button></div>)}
        {cmd.status}
      </Section>
    </>
  );
}
