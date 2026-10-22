// Reproducible report snapshots, JSON/CSV exports and auditor evidence packages. Downloads carry the server's SHA-256.
import { useState } from "react";
import { download, post, useGet } from "../api";
import { Badge, Field, Loaded, Section, fmt, short, useCommand } from "../ui";

export default function Reports() {
  const [scopes] = useGet<{ items: any[] }>("/scopes");
  const [scope, setScope] = useState("");
  const [snap, setSnap] = useState<any>(null);
  const [exports, setExports] = useState<{ id: string; format: string; sha256: string; checked?: string | null }[]>([]);
  const [caseId, setCaseId] = useState("");
  const [pkg, setPkg] = useState<any>(null);
  const cmd = useCommand();

  async function exportAs(format: "json" | "csv") {
    const e: any = await post(`/reports/snapshots/${snap.id}/exports`, { format });
    setExports((x) => [...x, { id: e.id, format, sha256: e.sha256 }]);
  }
  async function fetchExport(id: string, format: string, name: string) {
    const sha = await download(`/reports/exports/${id}/content`, `${name}.${format}`);
    setExports((x) => x.map((e) => e.id === id ? { ...e, checked: sha } : e));
  }

  return (
    <>
      <h1>Reports and auditor exports</h1>
      <Section title="Exposure summary snapshot">
        <p className="muted small">A snapshot is stored with a content digest and can be reproduced; exports are rendered from
          the stored snapshot, not recomputed.</p>
        <Loaded load={scopes} isEmpty={(d) => !d.items.some((s) => s.report_generate)}
                empty="You cannot generate reports in any scope of this tenant.">
          {(d) => {
            const allowed = d.items.filter((s) => s.report_generate);
            const current = scope || allowed[0].id;
            return (
              <form className="inline" onSubmit={(e) => { e.preventDefault(); cmd.run(async () => {
                setSnap(await post("/reports/snapshots", { kind: "exposure_summary", scope_id: current })); setExports([]);
              }, "Snapshot generated."); }}>
                <Field label="Scope"><select data-testid="report-scope" value={current} onChange={(e) => setScope(e.target.value)}>
                  {allowed.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.kind})</option>)}</select></Field>
                <button data-testid="generate-report" disabled={cmd.busy}>Generate snapshot</button>
              </form>);
          }}
        </Loaded>
        {snap && (
          <div data-testid="report-snapshot">
            <div className="facts"><span>Snapshot {short(snap.id)}</span><span>generated {fmt(snap.generated_at ?? snap.created_at)}</span>
              <span className="mono small">digest {snap.content_digest.slice(0, 16)}</span></div>
            <ul className="kv">{Object.entries(snap.content.unknowns ?? {}).map(([k, v]) =>
              <li key={k}><span>{k.replace(/_/g, " ")}</span><strong>{String(v)}</strong></li>)}</ul>
            <div className="row">
              <button data-testid="export-json" disabled={cmd.busy} onClick={() => cmd.run(() => exportAs("json"), "JSON export stored.")}>Export JSON</button>
              <button data-testid="export-csv" disabled={cmd.busy} onClick={() => cmd.run(() => exportAs("csv"), "CSV export stored.")}>Export CSV</button>
            </div>
            <ul data-testid="exports">{exports.map((e) => <li key={e.id}>{e.format} · sha256 <span className="mono small">{e.sha256.slice(0, 16)}</span>
              {" "}<button className="link" onClick={() => cmd.run(() => fetchExport(e.id, e.format, `report-${short(snap.id)}`), "Downloaded.")}>
                Download</button>{e.checked !== undefined && (e.checked === e.sha256
                  ? <Badge kind="ok">server digest matches</Badge> : <Badge kind="bad">digest header differs</Badge>)}</li>)}</ul>
          </div>)}
      </Section>
      <Section title="Case evidence package (auditor)">
        <p className="muted small">The package includes decisions, policy versions, evidence references, approvals and
          verifications. Evidence you are not allowed to read is listed as withheld, with its metadata withheld too when
          you lack metadata access.</p>
        <form className="inline" onSubmit={(e) => { e.preventDefault(); cmd.run(async () => {
          setPkg(await post(`/cases/${caseId}/evidence-package`)); }, "Evidence package stored."); }}>
          <Field label="Case id"><input data-testid="package-case" value={caseId} onChange={(e) => setCaseId(e.target.value)} required /></Field>
          <button data-testid="build-package" disabled={cmd.busy}>Build package</button>
        </form>
        {pkg && <div data-testid="package">
          <div className="facts"><span>{pkg.snapshot.content.decisions.length} decisions</span>
            <span>{pkg.snapshot.content.evidence.length} evidence objects</span>
            <span>withheld content <strong data-testid="withheld-evidence">{pkg.snapshot.content.withheld_evidence}</strong></span>
            <span>withheld metadata <strong data-testid="withheld-metadata">{pkg.snapshot.content.withheld_metadata}</strong></span></div>
          <button className="link" onClick={() => cmd.run(() => download(`/reports/exports/${pkg.export.id}/content`,
            `evidence-package-${short(caseId)}.json`), "Downloaded.")}>Download package (sha256 {pkg.export.sha256.slice(0, 16)})</button>
        </div>}
        {cmd.status}
      </Section>
    </>
  );
}
