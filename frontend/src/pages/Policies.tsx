// Policy versions and the read-only impact preview of a priority policy.
import { useState } from "react";
import { Link } from "react-router-dom";
import { post, useGet } from "../api";
import { Badge, Loaded, Section, fmt, short, useCommand } from "../ui";
import { priorityBadge } from "./Cases";

export default function Policies() {
  const [list, reload] = useGet<{ items: any[] }>("/policies");
  const [preview, setPreview] = useState<any>(null);
  const cmd = useCommand();
  return (
    <>
      <h1>Policies</h1>
      <Section title="Versions">
        <Loaded load={list} onRetry={reload} isEmpty={(d) => d.items.length === 0} empty="No policy has been drafted.">
          {(d) => (
            <table data-testid="policies">
              <thead><tr><th>Kind</th><th>Version</th><th>Status</th><th>Created</th><th /></tr></thead>
              <tbody>{d.items.map((p) => (
                <tr key={p.id}><td>{p.kind}</td><td>{p.version}</td>
                  <td>{p.status}{p.provisional && <> <Badge kind="provisional">provisional</Badge></>}</td>
                  <td>{fmt(p.created_at)}</td>
                  <td>{p.kind === "priority" && <button data-testid={`preview-${p.version}`} disabled={cmd.busy}
                    onClick={() => cmd.run(async () => setPreview(await post(`/policies/${p.id}/preview`)), "Preview computed.")}>
                    Preview impact</button>}</td></tr>))}</tbody>
            </table>)}
        </Loaded>
        {cmd.status}
      </Section>
      {preview && <Preview p={preview} />}
    </>
  );
}

function Preview({ p }: { p: any }) {
  const [onlyChanges, setOnlyChanges] = useState(true);
  const items = p.items.filter((i: any) => !onlyChanges || i.changes || i.missing_inputs.length);
  return (
    <Section title={`Impact preview of policy ${short(p.policy_version_id)}`}>
      <p className="muted small" data-testid="preview-note">Read-only: nothing was changed. Cases you cannot read are not
        included. {p.provisional && <Badge kind="provisional">provisional policy</Badge>}</p>
      <div className="facts" data-testid="preview-counts">
        <span>cases <strong>{p.counts.cases}</strong></span><span>would change <strong>{p.counts.would_change}</strong></span>
        <span>held by override <strong>{p.counts.held_by_override}</strong></span>
        <span>missing inputs <strong>{p.counts.with_missing_inputs}</strong></span>
        {p.truncated && <Badge kind="warn">truncated</Badge>}
      </div>
      <label className="check"><input type="checkbox" checked={onlyChanges} onChange={(e) => setOnlyChanges(e.target.checked)} />
        Only changes and missing inputs</label>
      {items.length === 0 ? <div className="state" data-state="empty">No case would change.</div> : (
        <table data-testid="preview">
          <thead><tr><th>Case</th><th>Now</th><th>Preview</th><th>Missing inputs</th><th>Current policy</th><th>Note</th></tr></thead>
          <tbody>{items.map((i: any) => (
            <tr key={i.case_id} data-changes={i.changes}>
              <td><Link to={`/cases/${i.case_id}/priority`}>{i.title}</Link></td>
              <td>{priorityBadge(i.current_priority)}</td><td>{priorityBadge(i.preview_priority)}</td>
              <td className="small">{i.missing_inputs.join("; ") || "—"}</td>
              <td className="small">{short(i.current_policy_version_id)}</td>
              <td className="small">{i.override && <Badge kind="manual">override {i.override.priority} until {fmt(i.override.expires_at)}</Badge>}
                {i.note}</td></tr>))}</tbody>
        </table>)}
    </Section>
  );
}
