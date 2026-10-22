// Case queue and the unresolved-ownership queue.
import { useState } from "react";
import { Link } from "react-router-dom";
import { useGet } from "../api";
import { Badge, Field, Loaded, Section, fmt } from "../ui";

const WORKFLOWS = ["", "received", "investigating", "review_required", "remediation_planned", "remediating",
  "awaiting_verification", "closed"];

export function priorityBadge(p: string) {
  const kind = p === "urgent" ? "bad" : p === "high" ? "warn" : p === "pending" ? "info" : "ok";
  return <Badge kind={kind as any}>{p}</Badge>;
}

export default function Cases() {
  const [workflow, setWorkflow] = useState("");
  const [cases, reload] = useGet<{ items: any[] }>(`/cases?limit=200${workflow ? `&workflow=${workflow}` : ""}`,
                                                   [workflow]);
  const [unowned, reloadUnowned] = useGet<{ items: any[] }>("/ownership/unresolved");
  return (
    <>
      <h1>Cases</h1>
      <Section title="Queue" actions={
        <Field label="Workflow">
          <select data-testid="workflow-filter" value={workflow} onChange={(e) => setWorkflow(e.target.value)}>
            {WORKFLOWS.map((w) => <option key={w} value={w}>{w || "all open and closed"}</option>)}
          </select>
        </Field>}>
        <Loaded load={cases} onRetry={reload} isEmpty={(d) => d.items.length === 0} empty="No cases match.">
          {(d) => (
            <table data-testid="case-queue">
              <thead><tr><th>Case</th><th>Workflow</th><th>Assessment</th><th>Priority</th><th>Updated</th></tr></thead>
              <tbody>{d.items.map((c) => (
                <tr key={c.id}>
                  <td><Link to={`/cases/${c.id}`}>{c.title}</Link></td>
                  <td>{c.workflow}</td><td>{c.assessment}</td><td>{priorityBadge(c.priority)}</td>
                  <td>{fmt(c.updated_at ?? c.created_at)}</td>
                </tr>))}
              </tbody>
            </table>)}
        </Loaded>
      </Section>
      <Section title="Unresolved ownership">
        <Loaded load={unowned} onRetry={reloadUnowned} isEmpty={(d) => d.items.length === 0}
                empty="Every open case you can see has an owner.">
          {(d) => (
            <table data-testid="unowned">
              <thead><tr><th>Case</th><th>Reason</th></tr></thead>
              <tbody>{d.items.map((c) => (
                <tr key={c.id}><td><Link to={`/cases/${c.id}`}>{c.title}</Link></td>
                  <td>{c.unresolved_reason ?? "never routed"}</td></tr>))}</tbody>
            </table>)}
        </Loaded>
      </Section>
    </>
  );
}
