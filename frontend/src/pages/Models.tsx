// Model routes with honest labels: the fake is not a language model; real-provider routes are unverified.
import { useGet } from "../api";
import { Badge, Loaded, Section, fmt, routeLabel, short } from "../ui";

export default function Models() {
  const [routes, reload] = useGet<{ items: any[] }>("/model-routes");
  return (
    <>
      <h1>Model routes</h1>
      <Section title="Routes">
        <p className="muted small">Real-provider execution is disabled until separately authorised. Results produced with the
          fake model show that the platform's controls work; they say nothing about the quality of any language model.</p>
        <Loaded load={routes} onRetry={reload} isEmpty={(d) => d.items.length === 0} empty="No model route is configured.">
          {(d) => (
            <table data-testid="routes">
              <thead><tr><th>Name</th><th>Provider</th><th>Model</th><th>Region</th><th>Max data class</th><th>Status</th>
                <th>Proposed / approved</th></tr></thead>
              <tbody>{d.items.map((r) => (
                <tr key={r.id} data-provider={r.provider}><td>{r.name}</td><td>{routeLabel(r.provider)}</td>
                  <td className="small">{r.model}</td><td>{r.region}</td><td>{r.max_classification}</td>
                  <td>{r.status === "approved" ? <Badge kind="ok">approved</Badge> : <Badge kind="warn">{r.status}</Badge>}</td>
                  <td className="small">{short(r.proposed_by)} / {short(r.approved_by)}<div className="muted">{fmt(r.created_at)}</div></td>
                </tr>))}</tbody>
            </table>)}
        </Loaded>
      </Section>
    </>
  );
}
