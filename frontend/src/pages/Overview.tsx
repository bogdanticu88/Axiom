// Source coverage and freshness for a scope, computed now (not stored). Successful sync and complete coverage are
// shown separately; unknowns are listed explicitly.
import { useState } from "react";
import { useGet } from "../api";
import { Badge, Field, Loaded, Section, fmt } from "../ui";

type Scope = { id: string; kind: string; name: string; report_read: boolean };

export default function Overview() {
  const [scopes] = useGet<{ items: Scope[] }>("/scopes");
  const [scope, setScope] = useState<string | null>(null);
  return (
    <>
      <h1>Coverage and freshness</h1>
      <Loaded load={scopes} isEmpty={(d) => !d.items.some((s) => s.report_read)}
              empty="You have no scope where you can read reports.">
        {(d) => {
          const readable = d.items.filter((s) => s.report_read);
          const current = scope ?? readable[0].id;
          return (
            <>
              <Field label="Scope">
                <select data-testid="scope" value={current} onChange={(e) => setScope(e.target.value)}>
                  {readable.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.kind})</option>)}
                </select>
              </Field>
              <Coverage scope={current} />
            </>
          );
        }}
      </Loaded>
    </>
  );
}

function freshnessBadge(f: string) {
  if (f === "fresh") return <Badge kind="ok">fresh</Badge>;
  if (f === "stale") return <Badge kind="bad">stale</Badge>;
  return <Badge kind="warn">never succeeded</Badge>;
}

function Coverage({ scope }: { scope: string }) {
  const [live, reload] = useGet<any>(`/reports/live?scope_id=${scope}`, [scope]);
  return (
    <Loaded load={live} onRetry={reload}>
      {({ content }) => (
        <>
          <p className="muted">Computed now and not stored. Generate a report snapshot for a reproducible record.
            Freshness limits: {content.freshness_policy.provisional
              ? <Badge kind="provisional">provisional defaults</Badge> : "published policy"}</p>
          <Section title="Sources">
            {content.coverage_by_source.length === 0 ? (
              <div className="state" data-state="empty">No source has reported into this scope.</div>
            ) : (
              <table data-testid="sources">
                <thead><tr><th>Source</th><th>Last run</th><th>Last successful</th><th>Completeness</th>
                  <th>Last complete coverage</th><th>Freshness</th></tr></thead>
                <tbody>
                  {content.coverage_by_source.map((s: any) => (
                    <tr key={s.source}>
                      <td>{s.adapter}<div className="muted small">{s.source_kind}</div></td>
                      <td>{fmt(s.last_run_at)}<div className="muted small">{s.last_run_status}</div></td>
                      <td>{fmt(s.last_successful_run_at)}</td>
                      <td>{s.completeness === "complete" ? <Badge kind="ok">complete</Badge>
                        : <Badge kind="warn">{s.completeness}</Badge>}</td>
                      <td>{fmt(s.last_complete_coverage_at)}</td>
                      <td>{freshnessBadge(s.freshness)}<div className="muted small">limit {s.max_age_hours} h</div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <p className="muted small">A successful synchronisation does not prove complete coverage.</p>
          </Section>
          <Section title="What is not known">
            <ul data-testid="unknowns" className="kv">
              {Object.entries(content.unknowns).map(([k, v]) => <li key={k}><span>{k.replace(/_/g, " ")}</span>
                <strong>{String(v)}</strong></li>)}
            </ul>
          </Section>
          <Section title="Denominators">
            <ul className="kv">
              <li><span>cases (open / closed)</span><strong>{content.denominators.cases.open} / {content.denominators.cases.closed}</strong></li>
              <li><span>occurrences</span><strong>{content.denominators.occurrences.total}</strong></li>
              <li><span>assets</span><strong>{content.denominators.assets.total}</strong></li>
            </ul>
          </Section>
        </>
      )}
    </Loaded>
  );
}
