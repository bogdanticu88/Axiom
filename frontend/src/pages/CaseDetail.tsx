import { useState } from "react";
import { NavLink, Route, Routes, useParams } from "react-router-dom";
import { post, useGet } from "../api";
import { Badge, Field, Loaded, Section, basisLabel, fmt, short, useCommand } from "../ui";
import { priorityBadge } from "./Cases";
import { Assessment, Evidence, Investigations } from "./CaseEvidence";
import { Actions, Priority, Verification } from "./CaseActions";
import { Risk } from "./CaseRisk";

export default function CaseDetail() {
  const { caseId } = useParams();
  const [load, reload] = useGet<any>(`/cases/${caseId}`, [caseId]);
  return (
    <Loaded load={load} onRetry={reload}>
      {(c) => (
        <>
          <h1 data-testid="case-title">{c.title}</h1>
          <div className="facts">
            <span>Workflow <strong data-testid="case-workflow">{c.workflow}</strong></span>
            <span>Assessment <strong>{c.assessment}</strong></span>
            <span>Priority {priorityBadge(c.priority)}</span>
            <span>Disposition <strong>{c.disposition}</strong></span>
            <span className="muted">version {c.record_version}</span>
          </div>
          <nav className="tabs">
            {[["", "Overview"], ["context", "Assets & ownership"], ["evidence", "Evidence snapshots"],
              ["investigations", "Investigations"], ["assessment", "Assessment"], ["priority", "Priority"],
              ["actions", "Proposals & approvals"], ["risk", "Risk acceptance"],
              ["verification", "Verification & closure"]].map(([to, label]) => (
              <NavLink key={to} end to={to} data-testid={`tab-${to || "overview"}`}>{label}</NavLink>))}
          </nav>
          <Routes>
            <Route index element={<Overview c={c} />} />
            <Route path="context" element={<Context c={c} onChange={reload} />} />
            <Route path="evidence" element={<Evidence c={c} />} />
            <Route path="investigations" element={<Investigations c={c} />} />
            <Route path="assessment" element={<Assessment c={c} onChange={reload} />} />
            <Route path="priority" element={<Priority c={c} onChange={reload} />} />
            <Route path="actions" element={<Actions c={c} onChange={reload} />} />
            <Route path="risk" element={<Risk c={c} onChange={reload} />} />
            <Route path="verification" element={<Verification c={c} onChange={reload} />} />
          </Routes>
        </>
      )}
    </Loaded>
  );
}

function Overview({ c }: { c: any }) {
  const [history, reload] = useGet<any>(`/cases/${c.id}/history`, [c.record_version]);
  const [sla] = useGet<{ items: any[] }>(`/cases/${c.id}/sla`, [c.record_version]);
  return (
    <>
      <Section title="SLA clocks">
        <Loaded load={sla} isEmpty={(d) => d.items.length === 0} empty="No SLA clock has started yet.">
          {(d) => (
            <table data-testid="sla">
              <thead><tr><th>Clock</th><th>Status</th><th>Due</th><th>Gross elapsed</th><th>Paused</th>
                <th>Adjusted</th><th>Pauses (authorised reasons)</th></tr></thead>
              <tbody>{d.items.map((t) => (
                <tr key={t.id}>
                  <td>{t.kind} (cycle {t.cycle})<div className="muted small">{t.priority}
                    {t.policy_snapshot?.provisional && <> <Badge kind="provisional">provisional target</Badge></>}</div></td>
                  <td>{t.status}{t.exceeds_target_on_gross_time && !t.exceeds_target_on_adjusted_time &&
                    <div><Badge kind="warn">over target on gross time</Badge></div>}</td>
                  <td>{fmt(t.due_at)}</td>
                  <td>{hours(t.gross_elapsed_seconds)}</td><td>{hours(t.paused_seconds_total)}</td>
                  <td>{hours(t.adjusted_elapsed_seconds)}</td>
                  <td>{(t.pauses ?? []).map((p: any, i: number) => <div key={i} className="small">{p.reason}:
                    {" "}{fmt(p.from)} → {p.to ? fmt(p.to) : "open"}</div>)}</td>
                </tr>))}</tbody>
            </table>)}
        </Loaded>
      </Section>
      <Section title="Decisions">
        <Loaded load={history} onRetry={reload}>
          {(h) => (
            <table data-testid="decisions">
              <thead><tr><th>When</th><th>Decision</th><th>Outcome</th><th>Rationale and limitations</th><th>Basis</th></tr></thead>
              <tbody>{h.decisions.map((d: any) => (
                <tr key={d.id}>
                  <td>{fmt(d.recorded_at)}</td><td>{d.kind}</td><td>{d.outcome}</td>
                  <td>{d.rationale}{d.limitations && <div className="muted small">Limitations: {d.limitations}</div>}</td>
                  <td className="small">
                    {d.authority?.system ? <Badge kind="info">system result</Badge>
                      : <span>by {short(d.actor_principal_id)}</span>}
                    {d.policy_version_id && <div>policy {short(d.policy_version_id)}</div>}
                    {d.evidence_snapshot_id && <div>snapshot {short(d.evidence_snapshot_id)}</div>}
                    {d.investigation_run_id && <div><Badge kind="ai">cites investigation {short(d.investigation_run_id)}</Badge></div>}
                    {d.evidence?.length > 0 && <div>{d.evidence.length} evidence object(s)</div>}
                  </td>
                </tr>))}</tbody>
            </table>)}
        </Loaded>
      </Section>
    </>
  );
}

export function hours(s?: number) {
  if (s === undefined || s === null) return "—";
  return s < 3600 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`;
}

function Context({ c, onChange }: { c: any; onChange: () => void }) {
  const [ctx, reload] = useGet<any>(`/cases/${c.id}/context`, [c.record_version]);
  const [own, reloadOwn] = useGet<{ items: any[] }>(`/cases/${c.id}/ownership`, [c.record_version]);
  const cmd = useCommand(() => { reloadOwn(); onChange(); });
  const [owner, setOwner] = useState("");
  const [reason, setReason] = useState("");
  return (
    <>
      <Section title="Affected deployments">
        <Loaded load={ctx} onRetry={reload} isEmpty={(d) => d.occurrences.length === 0}
                empty="No scanner occurrence is linked to this case.">
          {(d) => (
            <>
              <table data-testid="occurrences">
                <thead><tr><th>Vulnerability</th><th>Component</th><th>Source severity</th><th>Asset</th><th>Deployment</th></tr></thead>
                <tbody>{d.occurrences.map((o: any) => (
                  <tr key={o.id}><td>{o.vulnerability_ref}</td><td className="small">{o.component_locator}</td>
                    <td>{o.source_severity ?? <Badge kind="warn">none reported</Badge>}</td>
                    <td>{o.display_name}<div className="muted small">{o.asset_kind}, {o.lifecycle_status}</div></td>
                    <td className="mono small">{o.deployment_digest ?? "no digest"}</td></tr>))}</tbody>
              </table>
              <h3>Deployment history</h3>
              <table data-testid="asset-versions">
                <thead><tr><th>Observed</th><th>Digest</th><th>Provenance</th></tr></thead>
                <tbody>{d.asset_versions.map((v: any) => (
                  <tr key={v.id}><td>{fmt(v.observed_at)}</td><td className="mono small">{v.deployment_digest ?? "—"}</td>
                    <td>{v.provenance === "ingestion" ? <Badge kind="info">Observed in an imported report</Badge>
                      : v.provenance === "manual_with_evidence"
                        ? <Badge kind="manual">Manually recorded, with supporting evidence</Badge>
                        : <Badge kind="manual">Manually recorded (no scanner observation or evidence)</Badge>}</td></tr>))}</tbody>
              </table>
              <h3>Business context</h3>
              {d.business_context.length === 0 ? <div className="state" data-state="empty">No owner, criticality or
                environment recorded.</div> : (
                <table data-testid="business-context">
                  <thead><tr><th>Recorded</th><th>Owner ref</th><th>Criticality</th><th>Environment</th><th>Basis</th></tr></thead>
                  <tbody>{d.business_context.map((b: any) => (
                    <tr key={b.id}><td>{fmt(b.recorded_at)}</td><td>{b.owner_ref ?? "—"}</td><td>{b.criticality ?? "—"}</td>
                      <td>{b.environment ?? "—"}</td><td>{basisLabel(b.basis)}</td></tr>))}</tbody>
                </table>)}
            </>)}
        </Loaded>
      </Section>
      <Section title="Ownership" actions={
        <button disabled={cmd.busy} onClick={() => cmd.run(() => post(`/cases/${c.id}/ownership/route`), "Routed.")}>
          Route by policy</button>}>
        <Loaded load={own} onRetry={reloadOwn} isEmpty={(d) => d.items.length === 0} empty="Never routed.">
          {(d) => (
            <table data-testid="ownership">
              <thead><tr><th>When</th><th>Basis</th><th>Owner</th><th>Reason</th></tr></thead>
              <tbody>{d.items.map((o: any) => (
                <tr key={o.id}><td>{fmt(o.created_at)}</td><td>{o.basis === "manual_override"
                  ? <Badge kind="manual">manual override</Badge> : o.basis}</td>
                  <td>{o.owner_principal_id ? short(o.owner_principal_id) : <Badge kind="warn">unresolved</Badge>}</td>
                  <td className="small">{o.reason}</td></tr>))}</tbody>
            </table>)}
        </Loaded>
        <p className="muted small">Ownership gives no approval or risk-acceptance authority.</p>
        <form className="inline" onSubmit={(e) => { e.preventDefault(); cmd.run(() => post(`/cases/${c.id}/ownership/override`,
          { owner_principal_id: owner, reason }), "Owner recorded."); }}>
          <Field label="Owner principal id"><input value={owner} onChange={(e) => setOwner(e.target.value)} required /></Field>
          <Field label="Reason"><input value={reason} onChange={(e) => setReason(e.target.value)} required /></Field>
          <button disabled={cmd.busy}>Override owner</button>
        </form>
        {cmd.status}
      </Section>
    </>
  );
}
