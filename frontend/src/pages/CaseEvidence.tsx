// Evidence snapshots, investigation runs (progress, limitations, claims), human claim review and the assessment.
import { useEffect, useRef, useState } from "react";
import { newKey, post, useGet } from "../api";
import { Badge, ErrorView, Field, Loaded, Section, fmt, routeLabel, short, useCommand } from "../ui";

export function Evidence({ c }: { c: any }) {
  const [list, reload] = useGet<{ items: any[] }>(`/cases/${c.id}/evidence-snapshots`, [c.record_version]);
  const [open, setOpen] = useState<string | null>(null);
  const cmd = useCommand(reload);
  return (
    <>
      <Section title="Evidence snapshots" actions={
        <button data-testid="freeze-snapshot" disabled={cmd.busy}
                onClick={() => cmd.run(() => post(`/cases/${c.id}/evidence-snapshots`, { purpose: "assessment" }),
                                       "Snapshot frozen.")}>Freeze a new snapshot</button>}>
        {cmd.status}
        <Loaded load={list} onRetry={reload} isEmpty={(d) => d.items.length === 0} empty="No snapshot yet.">
          {(d) => (
            <table data-testid="snapshots">
              <thead><tr><th>Frozen</th><th>Members</th><th>Contradictions</th><th>Gaps</th><th>Digest</th><th /></tr></thead>
              <tbody>{d.items.map((s) => (
                <tr key={s.id}><td>{fmt(s.as_of)}</td><td>{s.member_count}</td>
                  <td>{s.contradictions ? <Badge kind="warn">{s.contradictions}</Badge> : 0}</td>
                  <td>{s.gaps ? <Badge kind="warn">{s.gaps}</Badge> : 0}</td>
                  <td className="mono small">{s.digest.slice(0, 12)}</td>
                  <td><button className="link" onClick={() => setOpen(s.id)}>Open</button></td></tr>))}</tbody>
            </table>)}
        </Loaded>
      </Section>
      {open && <Snapshot id={open} />}
    </>
  );
}

export function Snapshot({ id }: { id: string }) {
  const [snap, reload] = useGet<any>(`/evidence-snapshots/${id}`, [id]);
  return (
    <Loaded load={snap} onRetry={reload}>
      {(s) => (
        <Section title={`Snapshot ${short(s.id)}`}>
          <p className="muted small">Frozen {fmt(s.as_of)}. Digest {s.digest_verified ? <Badge kind="ok">verified</Badge>
            : <Badge kind="bad">does not match</Badge>}. Later evidence makes a new snapshot; this one never changes.</p>
          <h3>Contradictions (kept open for a person unless the order is defensible)</h3>
          {s.contradictions.length === 0 ? <div className="state" data-state="empty">None recorded.</div> : (
            <ul data-testid="contradictions">{s.contradictions.map((x: any, i: number) => (
              <li key={i}><strong>{x.kind}</strong> {x.vulnerability_ref ?? ""} — {x.ordering === "by_scan_time"
                ? <>latest scan: <Badge kind="info">{x.latest_status}</Badge></>
                : <Badge kind="warn">order undetermined: {x.ordering_reason}</Badge>}
                <span className="muted small"> members {(x.member_keys ?? []).join(", ")}</span></li>))}</ul>)}
          <h3>Missing information</h3>
          {s.gaps.length === 0 ? <div className="state" data-state="empty">None recorded.</div> : (
            <ul data-testid="gaps">{s.gaps.map((g: any, i: number) => <li key={i}><strong>{g.kind}</strong> {g.description}</li>)}</ul>)}
          <h3>Members</h3>
          <table data-testid="members">
            <thead><tr><th>Key</th><th>Kind</th><th>Freshness</th><th>Classification</th><th>Detail</th></tr></thead>
            <tbody>{s.members.map((m: any) => (
              <tr key={m.member_key}>
                <td className="mono">{m.member_key}</td><td>{m.kind}</td>
                <td>{m.freshness === "stale" ? <Badge kind="bad">stale</Badge> : m.freshness}</td>
                <td>{m.classification ?? "—"}</td>
                <td className="small">
                  {m.content_withheld && <div><Badge kind="withheld">content withheld</Badge> {m.content_withheld}</div>}
                  {m.metadata_withheld && <div><Badge kind="withheld">metadata withheld</Badge> {m.metadata_withheld}</div>}
                  {m.attributes.observed_status && <div>status {m.attributes.observed_status}, scan {fmt(m.attributes.scan_time)}</div>}
                  {m.attributes.vulnerability_ref && <div>{m.attributes.vulnerability_ref}</div>}
                  {m.attributes.coverage && <div>run coverage {m.attributes.coverage}</div>}
                  {m.ref_digest && <div className="mono">digest {String(m.ref_digest).slice(0, 16)}</div>}
                  {m.attributes.original_filename && <div>file {m.attributes.original_filename}</div>}
                  {m.attributes.source_text && <details><summary>source text (untrusted)</summary>
                    <pre>{JSON.stringify(m.attributes.source_text, null, 1)}</pre></details>}
                </td>
              </tr>))}</tbody>
          </table>
        </Section>)}
    </Loaded>
  );
}

const TERMINAL = ["completed", "incomplete", "failed", "cancelled"];

export function Investigations({ c }: { c: any }) {
  const [runs, reload] = useGet<{ items: any[] }>(`/cases/${c.id}/investigations`, [c.record_version]);
  const [routes] = useGet<{ items: any[] }>("/model-routes");
  const [open, setOpen] = useState<string | null>(null);
  const [question, setQuestion] = useState("Is the reported vulnerability present in the deployed image?");
  const [route, setRoute] = useState("");
  const cmd = useCommand(reload);
  return (
    <>
      <Section title="Start an investigation">
        <p className="muted small">The model only analyses a frozen snapshot. Its claims are checked against record
          identifiers, statuses and freshness, not for reasoning, and a person must review every claim before an
          assessment can cite the run. It cannot change priority, dismiss, accept risk or approve anything.</p>
        <Loaded load={routes} isEmpty={(d) => !d.items.some((r) => r.status === "approved")}
                empty="No approved model route. An administrator must propose one and another must approve it.">
          {(d) => (
            <form className="inline" onSubmit={(e) => { e.preventDefault(); cmd.run(async () => {
              const r: any = await post(`/cases/${c.id}/investigations`, { questions: [question],
                route: route || d.items.find((x) => x.status === "approved").name }, { "Idempotency-Key": newKey() });
              setOpen(r.id); }, "Investigation queued."); }}>
              <Field label="Question"><input className="wide" value={question} onChange={(e) => setQuestion(e.target.value)} /></Field>
              <Field label="Model route">
                <select data-testid="route" value={route} onChange={(e) => setRoute(e.target.value)}>
                  {d.items.filter((r) => r.status === "approved").map((r) => (
                    <option key={r.id} value={r.name}>{r.name} ({r.provider === "deterministic_fake" ? "FAKE MODEL"
                      : "UNVERIFIED"}, {r.region}, up to {r.max_classification})</option>))}
                </select>
              </Field>
              <button data-testid="start-investigation" disabled={cmd.busy}>Start</button>
            </form>)}
        </Loaded>
        {cmd.status}
      </Section>
      <Section title="Runs">
        <Loaded load={runs} onRetry={reload} isEmpty={(d) => d.items.length === 0} empty="No investigation yet.">
          {(d) => (
            <table data-testid="runs">
              <thead><tr><th>Started</th><th>Status</th><th>Model calls</th><th>Tool calls</th><th>Tokens</th><th /></tr></thead>
              <tbody>{d.items.map((r) => (
                <tr key={r.id}><td>{fmt(r.created_at)}</td><td>{statusBadge(r.status)} {r.outcome_reason ?? ""}</td>
                  <td>{r.model_calls}</td><td>{r.tool_calls}</td><td className="small">{r.input_tokens} in / {r.output_tokens} out</td>
                  <td><button className="link" onClick={() => setOpen(r.id)}>Open</button></td></tr>))}</tbody>
            </table>)}
        </Loaded>
      </Section>
      {open && <Run id={open} onChange={reload} />}
    </>
  );
}

function statusBadge(s: string) {
  const k = s === "completed" ? "ok" : s === "incomplete" ? "warn" : s === "failed" || s === "cancelled" ? "bad" : "info";
  return <Badge kind={k as any}>{s}</Badge>;
}

export function Run({ id, onChange }: { id: string; onChange?: () => void }) {
  const [run, reload] = useGet<any>(`/investigations/${id}`, [id]);
  const cmd = useCommand(() => { reload(); onChange?.(); });
  const last = useRef<string | null>(null);
  useEffect(() => {                                   // refresh the run list once the run finishes
    if (run.state !== "ok") return;
    if (last.current && !TERMINAL.includes(last.current) && TERMINAL.includes(run.data.status)) onChange?.();
    last.current = run.data.status;
  }, [run, onChange]);
  useEffect(() => {                                   // poll while the run is in progress
    if (run.state === "ok" && !TERMINAL.includes(run.data.status)) {
      const t = window.setTimeout(reload, 1500);
      return () => window.clearTimeout(t);
    }
  }, [run, reload]);
  return (
    <Loaded load={run} onRetry={reload}>
      {(r) => (
        <Section title={`Investigation ${short(r.id)}`} actions={!TERMINAL.includes(r.status) &&
          <button disabled={cmd.busy} onClick={() => cmd.run(() => post(`/investigations/${r.id}/cancel`,
            { reason: "cancelled from the UI" }), "Cancellation requested.")}>Cancel</button>}>
          <div className="facts" data-testid="run-status">
            <span>Status {statusBadge(r.status)}</span>{r.outcome_reason && <span>Reason <strong>{r.outcome_reason}</strong></span>}
            <span>Route {r.route_binding.route_name} {routeLabel(r.route_binding.provider)}</span>
            <span className="muted">snapshot {short(r.snapshot_id)}</span>
            <span className="muted">{r.model_calls} model / {r.tool_calls} tool calls, cost {r.cost_micros}, {r.redactions} redaction(s)</span>
          </div>
          {!TERMINAL.includes(r.status) && <div className="state" data-state="loading">In progress… (refreshing)</div>}
          {r.limitations.length > 0 && <ul className="warnlist">{r.limitations.map((l: any, i: number) =>
            <li key={i}>{l.message}</li>)}</ul>}
          {r.next_checks.length > 0 && <><h3>Proposed next checks (suggestions only)</h3>
            <ul>{r.next_checks.map((n: any, i: number) => <li key={i}>{n.description}</li>)}</ul></>}
          <h3>Claims <Badge kind="ai">AI analysis — references checked, reasoning not verified</Badge></h3>
          {r.claims.length === 0 ? <div className="state" data-state="empty">No claims.</div> :
            r.claims.map((cl: any) => <Claim key={cl.id} cl={cl} onReviewed={reload} />)}
          <details><summary>Steps ({r.steps.length})</summary>
            <table className="small"><thead><tr><th>#</th><th>Kind</th><th>Name</th><th>Status</th><th>Latency</th><th>Error</th></tr></thead>
              <tbody>{r.steps.map((s: any) => <tr key={s.seq}><td>{s.seq}</td><td>{s.kind}</td><td>{s.name}</td>
                <td>{s.status}</td><td>{s.latency_ms ?? "—"} ms</td><td>{s.error ?? ""}</td></tr>)}</tbody></table>
          </details>
          {cmd.status}
        </Section>)}
    </Loaded>
  );
}

function Claim({ cl, onReviewed }: { cl: any; onReviewed: () => void }) {
  const [verdict, setVerdict] = useState("confirmed");
  const [corrected, setCorrected] = useState("unknown");
  const [note, setNote] = useState("");
  const cmd = useCommand(onReviewed);
  const kind = cl.validation === "rejected" ? "bad" : cl.validation === "downgraded" ? "warn" : "info";
  return (
    <div className="claim" data-testid="claim" data-validation={cl.validation}>
      <div><Badge kind={kind as any}>{cl.validation}</Badge> <strong>{cl.statement}</strong></div>
      <div className="small">Subject: {cl.subject.vulnerability_ref} · {cl.subject.attribute}
        {cl.subject.asset_version_id && <> · deployment {short(cl.subject.asset_version_id)}</>}</div>
      <div className="small">Proposed: {cl.proposed_conclusion} → accepted as candidate: <strong>{cl.accepted_conclusion ?? "none (rejected)"}</strong>
        {cl.model_stated_confidence && <span className="muted"> (model said "{cl.model_stated_confidence}"; uncalibrated)</span>}</div>
      <div className="small">Supporting {cl.supporting.join(", ") || "—"} · Contradicting {cl.contradicting.join(", ") || "—"}</div>
      {cl.validation_reasons.length > 0 && <ul className="small reasons">{cl.validation_reasons.map((x: any, i: number) =>
        <li key={i}><code>{x.code}</code> {x.message}</li>)}</ul>}
      {cl.limitations && <div className="small muted">Limitations: {cl.limitations}</div>}
      {cl.reviews.length > 0 ? cl.reviews.map((rv: any) => <div key={rv.id} className="small" data-testid="review">
        <Badge kind="manual">reviewed: {rv.verdict}</Badge> {rv.corrected_conclusion && `→ ${rv.corrected_conclusion}`} {rv.note}</div>)
        : cl.validation !== "rejected" && (
        <form className="inline" onSubmit={(e) => { e.preventDefault(); cmd.run(() => post(`/investigation-claims/${cl.id}/reviews`,
          { verdict, note, corrected_conclusion: verdict === "corrected" ? corrected : null }), "Review recorded."); }}>
          <select aria-label="verdict" value={verdict} onChange={(e) => setVerdict(e.target.value)}>
            <option value="confirmed">confirm</option><option value="rejected">reject</option><option value="corrected">correct</option>
          </select>
          {verdict === "corrected" && <select aria-label="corrected conclusion" value={corrected} onChange={(e) => setCorrected(e.target.value)}>
            <option>supported</option><option>contradicted</option><option>unknown</option></select>}
          <input aria-label="review note" placeholder="what you checked" value={note} onChange={(e) => setNote(e.target.value)} required />
          <button disabled={cmd.busy}>Record review</button>
        </form>)}
      {cmd.status}
    </div>
  );
}

export function Assessment({ c, onChange }: { c: any; onChange: () => void }) {
  const [runs] = useGet<{ items: any[] }>(`/cases/${c.id}/investigations`, [c.record_version]);
  const [ctx] = useGet<any>(`/cases/${c.id}/context`, [c.id]);
  const cmd = useCommand(onChange);
  const start = useCommand(onChange);
  const [assessment, setAssessment] = useState("supported");
  const [rationale, setRationale] = useState("");
  const [limitations, setLimitations] = useState("");
  const [runId, setRunId] = useState("");
  const [evidenceId, setEvidenceId] = useState("");
  const version = c.record_version;
  return (
    <>
      {c.workflow === "received" && (
        <Section title="Start investigation">
          <button data-testid="start-case-investigation" disabled={start.busy} onClick={() => start.run(() =>
            post(`/cases/${c.id}/commands/start-investigation`, { expected_version: version,
              rationale: "investigation started from the UI" }), "Investigation started.")}>Move to investigating</button>
        </Section>)}
      {/* Outside the section above: that section is removed once the reloaded case is investigating, and the result
          of the command (confirmation or refusal) must stay visible after the reload. */}
      {start.status}
      <Section title="Record assessment (human decision)">
        {c.workflow !== "investigating" ? <div className="state" data-state="empty">Assessments are recorded while the
          case is investigating (now: {c.workflow}).</div> : (
          <form onSubmit={(e) => { e.preventDefault(); cmd.run(() => post(`/cases/${c.id}/commands/record-assessment`, {
            expected_version: version, assessment, rationale, limitations,
            evidence: evidenceId ? [{ evidence_id: evidenceId, relation: "supports" }] : [],
            investigation_run_id: runId || null }), "Assessment recorded."); }}>
            <Field label="Assessment">
              <select data-testid="assessment" value={assessment} onChange={(e) => setAssessment(e.target.value)}>
                <option value="supported">supported</option><option value="not_supported">not supported</option>
                <option value="inconclusive">inconclusive</option></select></Field>
            <Field label="Cite investigation (all its claims must be reviewed)">
              <Loaded load={runs}>{(d) => (
                <select data-testid="cite-run" value={runId} onChange={(e) => setRunId(e.target.value)}>
                  <option value="">none</option>
                  {d.items.filter((r) => r.status === "completed" || r.status === "incomplete").map((r) =>
                    <option key={r.id} value={r.id}>{short(r.id)} ({r.status})</option>)}
                </select>)}</Loaded></Field>
            <Field label="Supporting evidence (verified evidence id)">
              <Loaded load={ctx}>{() => <input data-testid="evidence-id" value={evidenceId}
                onChange={(e) => setEvidenceId(e.target.value)} placeholder="evidence id" />}</Loaded></Field>
            <Field label="Rationale"><textarea data-testid="rationale" value={rationale} onChange={(e) => setRationale(e.target.value)} required /></Field>
            <Field label="Limitations (state 'none identified' explicitly)">
              <textarea data-testid="limitations" value={limitations} onChange={(e) => setLimitations(e.target.value)} required /></Field>
            <button data-testid="record-assessment" disabled={cmd.busy}>Record assessment</button>
          </form>)}
        {cmd.status}
      </Section>
    </>
  );
}

export { ErrorView };
