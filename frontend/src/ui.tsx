// Shared building blocks: state views (loading, empty, denied, stale, dependency failure), honesty labels, forms.
import { ReactNode, useState } from "react";
import { ApiError, Load } from "./api";

const MESSAGES: Record<string, string> = {
  signed_out: "Your session has ended. Sign in again to continue.",
  denied: "You do not have permission to see or do this in the selected tenant.",
  not_found: "Not found, or not visible to you.",
  stale: "Someone changed this record since you loaded it. Reload to see the current version, then try again.",
  conflict: "The change conflicts with the record's current state.",
  invalid: "The request was not valid.",
  dependency: "A service the platform depends on did not respond. Nothing was changed by this request; try again.",
};

export function ErrorView({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  return (
    <div className={`state state-${error.kind}`} data-state={error.kind} role="alert">
      <strong>{MESSAGES[error.kind]}</strong>
      {error.kind !== "denied" && error.kind !== "not_found" && <div className="muted">{error.message}</div>}
      {error.correlationId && <div className="muted small">Reference: {error.correlationId}</div>}
      {error.kind === "signed_out" && <a className="button" href="/auth/login?return_to=/ui/">Sign in</a>}
      {onRetry && (error.kind === "stale" || error.kind === "dependency") &&
        <button onClick={onRetry}>{error.kind === "stale" ? "Reload" : "Try again"}</button>}
    </div>
  );
}

export function Loaded<T>({ load, children, empty, isEmpty, onRetry }: {
  load: Load<T>; children: (data: T) => ReactNode; empty?: string; isEmpty?: (d: T) => boolean;
  onRetry?: () => void;
}) {
  if (load.state === "loading") return <div className="state" data-state="loading" aria-busy="true">Loading…</div>;
  if (load.state === "error") return <ErrorView error={load.error} onRetry={onRetry} />;
  if (isEmpty && isEmpty(load.data)) return <div className="state" data-state="empty">{empty ?? "Nothing here yet."}</div>;
  return <>{children(load.data)}</>;
}

export type BadgeKind = "fake" | "manual" | "unverified" | "fixture" | "provisional" | "ai" | "withheld" | "ok" |
  "warn" | "bad" | "info";

export function Badge({ kind, children, title }: { kind: BadgeKind; children: ReactNode; title?: string }) {
  return <span className={`badge badge-${kind}`} title={title} data-badge={kind}>{children}</span>;
}

export function routeLabel(provider: string) {
  if (provider === "deterministic_fake")
    return <Badge kind="fake" title="Rule-based stand-in used for testing; it is not a language model">
      Fake model (not a language model)</Badge>;
  return <Badge kind="unverified" title="This provider has never been called in this project; real-provider execution
      is disabled until separately authorised">Unverified route</Badge>;
}

export function supportLabel(level: string) {
  if (level === "fixture-tested")
    return <Badge kind="fixture" title="Tested only against local fixtures and fakes; never validated against the live
      service">Fixture-tested integration</Badge>;
  if (level === "planned") return <Badge kind="warn">Planned (not built)</Badge>;
  return <Badge kind="info">{level}</Badge>;
}

export function basisLabel(basis: string) {
  if (basis === "user_assertion") return <Badge kind="manual">Manual assertion</Badge>;
  if (basis === "source_tag_assertion") return <Badge kind="info">From source tags</Badge>;
  return <Badge kind="info">{basis}</Badge>;
}

export function fmt(t?: string | null) {
  if (!t) return "—";
  const d = new Date(t);
  return isNaN(d.getTime()) ? t : d.toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

export function short(id?: string | null) {
  return id ? id.slice(0, 8) : "—";
}

export function Section({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="card">
      <header className="card-head"><h2>{title}</h2>{actions}</header>
      {children}
    </section>
  );
}

// A command form: runs `submit`, shows the result state (including stale-version conflicts) and calls onDone.
export function useCommand(onDone?: () => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  async function run(fn: () => Promise<unknown>, success = "Saved.") {
    setBusy(true); setError(null); setOk(null);
    try { await fn(); setOk(success); onDone?.(); }
    catch (e) { setError(e as ApiError); }
    finally { setBusy(false); }
  }
  const status = (
    <>
      {error && <ErrorView error={error} onRetry={onDone} />}
      {ok && <div className="state state-ok" role="status" data-state="ok">{ok}</div>}
    </>
  );
  return { busy, run, status };
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="field"><span>{label}</span>{children}</label>;
}
