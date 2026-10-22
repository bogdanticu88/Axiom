import { useEffect, useState } from "react";
import { BrowserRouter, NavLink, Navigate, Route, Routes } from "react-router-dom";
import { api, ApiError, setTenant } from "./api";
import { ErrorView } from "./ui";
import Overview from "./pages/Overview";
import Cases from "./pages/Cases";
import CaseDetail from "./pages/CaseDetail";
import Reports from "./pages/Reports";
import Policies from "./pages/Policies";
import Models from "./pages/Models";

type Tenant = { tenant_id: string; slug: string; display_name: string };
type Session = { principal_id: string; kind: string; issuer: string; tenants: Tenant[]; sso_configured: boolean };

function remembered(): string | null {
  try { return window.localStorage.getItem("axiom.tenant"); } catch { return null; }
}
function remember(slug: string) {
  try { window.localStorage.setItem("axiom.tenant", slug); } catch { /* storage unavailable: not needed */ }
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [tenant, choose] = useState<string | null>(null);

  useEffect(() => {
    api<Session>("GET", "/auth/session").then((s) => {
      setSession(s);
      const pick = s.tenants.find((t) => t.slug === remembered())?.slug ?? (s.tenants.length === 1 ? s.tenants[0].slug : null);
      setTenant(pick); choose(pick);
    }, setError);
  }, []);

  if (error?.kind === "signed_out") {
    const here = window.location.pathname + window.location.search;
    return (
      <main className="signin">
        <h1>Axiom</h1>
        <p>Sign in with your organisation's identity provider.</p>
        <a className="button primary" data-testid="sign-in" href={`/auth/login?return_to=${encodeURIComponent(here)}`}>
          Sign in</a>
      </main>
    );
  }
  if (error) return <main className="page"><ErrorView error={error} /></main>;
  if (!session) return <main className="page"><div className="state" data-state="loading">Loading…</div></main>;

  async function signOut() {
    try {
      const r = await api<{ end_session_url: string | null }>("POST", "/auth/logout");
      window.location.href = r.end_session_url ?? "/ui/";
    } catch { window.location.href = "/ui/"; }
  }

  function pick(slug: string) { setTenant(slug); remember(slug); choose(slug); }

  return (
    <BrowserRouter basename="/ui">
      <header className="top">
        <span className="brand">Axiom</span>
        <nav>
          <NavLink to="/">Coverage</NavLink>
          <NavLink to="/cases">Cases</NavLink>
          <NavLink to="/reports">Reports</NavLink>
          <NavLink to="/policies">Policies</NavLink>
          <NavLink to="/models">Model routes</NavLink>
        </nav>
        <span className="spacer" />
        <label className="tenant">
          Tenant
          <select data-testid="tenant" value={tenant ?? ""} onChange={(e) => pick(e.target.value)}>
            <option value="" disabled>Choose…</option>
            {session.tenants.map((t) => <option key={t.slug} value={t.slug}>{t.display_name}</option>)}
          </select>
        </label>
        <button className="link" data-testid="sign-out" onClick={signOut}>Sign out</button>
      </header>
      {!tenant ? (
        <main className="page">
          <div className="state" data-state="empty">
            {session.tenants.length ? "Choose a tenant to continue." : "You are signed in but have no active tenant membership."}
          </div>
        </main>
      ) : (
        <main className="page" key={tenant}>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/cases" element={<Cases />} />
            <Route path="/cases/:caseId/*" element={<CaseDetail />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/models" element={<Models />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      )}
    </BrowserRouter>
  );
}
