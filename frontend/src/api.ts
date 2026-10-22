// API client for the analyst UI. Same origin as the API: the session cookie is HttpOnly and sent by the browser; the
// CSRF token cookie is read and echoed in X-CSRF-Token on every state-changing request. The selected tenant goes in
// X-Axiom-Tenant and is re-checked by the server on every request.
import { useCallback, useEffect, useState } from "react";

export type ErrorKind =
  | "signed_out" | "denied" | "not_found" | "stale" | "conflict" | "invalid" | "dependency";

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public kind: ErrorKind,
              public correlationId?: string) {
    super(message);
  }
}

let tenant: string | null = null;
export function setTenant(slug: string | null) { tenant = slug; }
export function currentTenant() { return tenant; }

function csrf(): string {
  const m = document.cookie.match(/(?:^|;\s*)axiom_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

function kindFor(status: number, code: string): ErrorKind {
  if (status === 401) return "signed_out";
  if (status === 403) return "denied";
  if (status === 404) return "not_found";
  if (status === 409 && code === "stale_version") return "stale";
  if (status === 409) return "conflict";
  if (status === 422) return "invalid";
  return "dependency";
}

export async function api<T = any>(method: string, path: string, body?: unknown,
                                   extraHeaders: Record<string, string> = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json", ...extraHeaders };
  if (tenant && path.startsWith("/api/")) headers["X-Axiom-Tenant"] = tenant;
  if (method !== "GET") headers["X-CSRF-Token"] = csrf();
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let resp: Response;
  try {
    resp = await fetch(path, { method, headers, credentials: "same-origin",
                               body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new ApiError(0, "network_error", "The platform could not be reached.", "dependency");
  }
  const text = await resp.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (!resp.ok) {
    const e = data?.error ?? {};
    throw new ApiError(resp.status, e.code ?? `http_${resp.status}`, e.message ?? resp.statusText,
                       kindFor(resp.status, e.code ?? ""), e.correlation_id);
  }
  return data as T;
}

export const get = <T = any>(path: string) => api<T>("GET", `/api/v1${path}`);
export const post = <T = any>(path: string, body?: unknown, headers?: Record<string, string>) =>
  api<T>("POST", `/api/v1${path}`, body ?? {}, headers);

export function newKey(): string {
  return (crypto as any).randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2);
}

export type Load<T> = { state: "loading" } | { state: "ok"; data: T } | { state: "error"; error: ApiError };

export function useGet<T = any>(path: string | null, deps: unknown[] = []): [Load<T>, () => void] {
  const [load, setLoad] = useState<Load<T>>({ state: "loading" });
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  useEffect(() => {
    if (path === null) return;
    let live = true;
    setLoad({ state: "loading" });
    get<T>(path).then((data) => live && setLoad({ state: "ok", data }),
                      (error) => live && setLoad({ state: "error", error }));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, tick, ...deps]);
  return [load, reload];
}

// Downloads go through fetch so the tenant header is sent; the browser then saves the blob.
export async function download(path: string, filename: string): Promise<string | null> {
  const headers: Record<string, string> = {};
  if (tenant) headers["X-Axiom-Tenant"] = tenant;
  const resp = await fetch(`/api/v1${path}`, { headers, credentials: "same-origin" });
  if (!resp.ok) throw new ApiError(resp.status, `http_${resp.status}`, resp.statusText, kindFor(resp.status, ""));
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  return resp.headers.get("X-Content-SHA256");
}
