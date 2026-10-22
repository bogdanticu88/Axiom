// Risk acceptance: request, authorise or reject, withdraw, expiry and history. Every command goes to the server, which
// decides permission, delegation limits, independence and staleness; buttons are shown to everyone who can read the
// case, and a refusal comes back as an explained error.
import { useState } from "react";
import { post, useGet } from "../api";
import { Badge, Field, Loaded, Section, fmt, short, useCommand } from "../ui";

function inDays(days: number) {
  return new Date(Date.now() + days * 86400_000).toISOString().slice(0, 16);
}

function statusBadge(s: string) {
  const k = s === "active" || s === "authorised" ? "ok" : s === "pending" ? "info"
    : s === "rejected" || s === "revoked" ? "bad" : "warn";
  return <Badge kind={k as any}>{s}</Badge>;
}

export function Risk({ c, onChange }: { c: any; onChange: () => void }) {
  const [risk, reload] = useGet<any>(`/cases/${c.id}/risk`, [c.record_version]);
  const cmd = useCommand(() => { reload(); onChange(); });
  const [expires, setExpires] = useState(inDays(30));
  const [rationale, setRationale] = useState("");
  const [controls, setControls] = useState("");
  return (
    <>
      <Section title="Risk acceptance">
        <p className="muted small">Accepting risk closes the case until the acceptance expires; at expiry the platform
          reopens it automatically (reason <code>acceptance_expiry</code>). The server decides who may authorise: it
          checks the permission, the authoriser's delegation limit for this priority and duration, and whether someone
          other than the requester must authorise. Thresholds are provisional defaults (D-RISK-1).</p>
        <Loaded load={risk} onRetry={reload}>
          {(d) => {
            const active = d.acceptances.find((a: any) => a.status === "active");
            return (
              <>
                <div className="facts" data-testid="risk-summary">
                  <span>Workflow <strong>{d.case.workflow}</strong></span>
                  <span>Priority <strong>{d.case.priority}</strong></span>
                  {active ? <span data-testid="active-acceptance">{statusBadge("active")} until {fmt(active.expires_at)}</span>
                    : <span className="muted">no active acceptance</span>}
                </div>
                <h3>Requests</h3>
                {d.requests.length === 0 ? <div className="state" data-state="empty">No request.</div> : (
                  <table data-testid="risk-requests">
                    <thead><tr><th>Requested</th><th>Kind</th><th>Status</th><th>Expiry asked</th><th>Rules applied</th>
                      <th>Decision</th><th /></tr></thead>
                    <tbody>{d.requests.map((r: any) => (
                      <tr key={r.id} data-status={r.status}>
                        <td>{fmt(r.created_at)}<div className="muted small">by {short(r.requested_by)}</div></td>
                        <td>{r.kind}</td><td>{statusBadge(r.status)}{r.status === "pending" &&
                          <div className="muted small">lapses {fmt(r.lapses_at)}</div>}</td>
                        <td>{fmt(r.requested_expires_at)}</td>
                        <td className="small">{r.independent_required
                          ? <Badge kind="warn">independent authoriser required</Badge> : "requester may authorise"}
                          {(r.policy?.reasons ?? []).map((x: string, i: number) => <div key={i}>{x}</div>)}
                          <div className="muted">priority at request: {r.case_priority}, case version {r.case_record_version}</div></td>
                        <td className="small">{r.decided_at ? <>{fmt(r.decided_at)} by {short(r.decided_by)}
                          <div>{r.decision_rationale}</div></> : "—"}</td>
                        <td>{r.status === "pending" && <Decide id={r.id} onDone={() => { reload(); onChange(); }} />}</td>
                      </tr>))}</tbody>
                  </table>)}
                <h3>Acceptances</h3>
                {d.acceptances.length === 0 ? <div className="state" data-state="empty">None.</div> : (
                  <table data-testid="risk-acceptances">
                    <thead><tr><th>Starts</th><th>Expires</th><th>Status</th><th>Owner</th><th>Rationale and controls</th></tr></thead>
                    <tbody>{d.acceptances.map((a: any) => (
                      <tr key={a.id}><td>{fmt(a.starts_at)}</td><td>{fmt(a.expires_at)}</td><td>{statusBadge(a.status)}
                        {a.ended_at && <div className="muted small">ended {fmt(a.ended_at)}</div>}</td>
                        <td>{short(a.owner_principal_id)}</td>
                        <td className="small">{a.rationale}{a.compensating_controls &&
                          <div className="muted">Controls: {a.compensating_controls}</div>}</td></tr>))}</tbody>
                  </table>)}
                <h3>History</h3>
                <ul className="small" data-testid="risk-decisions">{d.decisions.map((x: any) => (
                  <li key={x.id}>{fmt(x.recorded_at)} · {x.kind} {x.outcome} · {x.authority?.system
                    ? <Badge kind="info">system result (expiry)</Badge> : <>by {short(x.actor_principal_id)}</>} · {x.rationale}</li>))}
                  {d.decisions.length === 0 && <li className="muted">No risk decision recorded.</li>}</ul>
                {d.audit ? (
                  <table className="small" data-testid="risk-audit">
                    <thead><tr><th>When</th><th>Action</th><th>Actor</th><th>Outcome</th></tr></thead>
                    <tbody>{d.audit.map((e: any, i: number) => (
                      <tr key={i}><td>{fmt(e.occurred_at)}</td><td>{e.action}</td>
                        <td>{short(e.actor_principal_id)} ({e.actor_kind})</td><td>{e.outcome}</td></tr>))}</tbody>
                  </table>) : <div className="state" data-state="denied" data-testid="risk-audit-withheld">
                    Audit trail not shown: {d.audit_withheld}.</div>}
              </>);
          }}
        </Loaded>
      </Section>
      <Section title="Request acceptance">
        <form onSubmit={(e) => { e.preventDefault(); cmd.run(() => post(`/cases/${c.id}/risk-acceptance-requests`, {
          expected_version: c.record_version, expires_at: new Date(expires).toISOString(), rationale,
          compensating_controls: controls || null }), "Request recorded."); }}>
          <Field label="Accept until"><input type="datetime-local" data-testid="risk-expires" value={expires}
            onChange={(e) => setExpires(e.target.value)} /></Field>
          <Field label="Why the risk can be accepted"><textarea data-testid="risk-rationale" value={rationale}
            onChange={(e) => setRationale(e.target.value)} required /></Field>
          <Field label="Compensating controls"><textarea data-testid="risk-controls" value={controls}
            onChange={(e) => setControls(e.target.value)} /></Field>
          <button data-testid="risk-request" disabled={cmd.busy}>Request acceptance</button>
        </form>
        {cmd.status}
      </Section>
    </>
  );
}

function Decide({ id, onDone }: { id: string; onDone: () => void }) {
  const cmd = useCommand(onDone);
  const [text, setText] = useState("");
  return (
    <div className="row" data-testid="risk-decide">
      <input aria-label="decision rationale" placeholder="rationale" value={text} onChange={(e) => setText(e.target.value)} />
      <button data-testid="risk-authorise" disabled={cmd.busy || !text} onClick={() =>
        cmd.run(() => post(`/risk-acceptance-requests/${id}/authorise`, { rationale: text }), "Authorised.")}>Authorise</button>
      <button data-testid="risk-reject" disabled={cmd.busy || !text} onClick={() =>
        cmd.run(() => post(`/risk-acceptance-requests/${id}/reject`, { rationale: text }), "Rejected.")}>Reject</button>
      <button data-testid="risk-withdraw" disabled={cmd.busy || !text} onClick={() =>
        cmd.run(() => post(`/risk-acceptance-requests/${id}/withdraw`, { reason: text }), "Withdrawn.")}>Withdraw</button>
      {cmd.status}
    </div>
  );
}
