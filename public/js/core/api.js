// The one client for the Darknode API (the Cloudflare Worker). Every call to the
// proxy should go through api(): it resolves the base URL, attaches the signed-in
// user's Firebase ID token, retries once with a force-refreshed token on 401, and
// turns any error body into an ApiError carrying status, code, message, request id
// and Retry-After. It understands both the current { error: "msg" } body and the
// Phase 4 envelope { error: { code, message } }.

const FIREBASE = "/js/firebase.js?v=20261021a"; // same specifier as every other importer: one auth singleton

export class ApiError extends Error {
  constructor(status, message, { code = "", requestId = "", retryAfter = 0 } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code || codeFor(status);
    this.requestId = requestId;
    this.retryAfter = retryAfter;
  }
}

function codeFor(status) {
  return status === 0 ? "network" : status === 401 ? "unauthenticated" : status === 403 ? "forbidden"
    : status === 404 ? "not_found" : status === 413 ? "too_large" : status === 429 ? "rate_limited"
    : status >= 500 ? "server_error" : "bad_request";
}

// window.DARKNODE_PROXY_URL points at the chat route; the API root is its origin.
export function apiBase() {
  try { return String(globalThis.DARKNODE_PROXY_URL || "").replace(/\/api\/chat$/, ""); } catch (_) { return ""; }
}
export const apiAvailable = () => !!apiBase();

async function currentUser() {
  const { auth } = await import(FIREBASE);
  return (auth && auth.currentUser) || null;
}

// Map a non-OK response to an ApiError.
export async function toApiError(res, fallback) {
  let body = null;
  try { body = await res.json(); } catch (_) {}
  const e = body && body.error;
  const message = (typeof e === "string" && e) || (e && typeof e.message === "string" && e.message) || fallback || ("Request failed (" + res.status + ")");
  return new ApiError(res.status, message, {
    code: e && typeof e.code === "string" ? e.code : "",
    requestId: res.headers.get("x-request-id") || "",
    retryAfter: parseInt(res.headers.get("retry-after"), 10) || 0,
  });
}

// api("/api/keys/" + wid, { method: "POST", body: { op: "list" } })
// opts.auth: "user" (default; throws ApiError 401 when signed out, with
// opts.signedOut as the message), "optional" (token when signed in), "none".
// opts.raw returns the Response (for streams); otherwise the parsed JSON body
// (null for 204). opts.user / opts.fetch / opts.base are injectable for tests.
export async function api(path, opts = {}) {
  const base = opts.base ?? apiBase();
  if (!base) throw new ApiError(0, opts.unconfigured || "This build has no cloud API configured.", { code: "unconfigured" });
  const mode = opts.auth || "user";
  const doFetch = opts.fetch || globalThis.fetch.bind(globalThis);
  const user = mode === "none" ? null : (opts.user !== undefined ? opts.user : await currentUser());
  if (mode === "user" && !user) throw new ApiError(401, opts.signedOut || "Sign in first.", { code: "unauthenticated" });
  let url = base + path;
  if (opts.query) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(opts.query)) if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
    const s = q.toString();
    if (s) url += (url.includes("?") ? "&" : "?") + s;
  }
  const send = async (forceRefresh) => {
    const headers = { ...(opts.headers || {}) };
    let body = opts.body;
    if (body !== undefined && typeof body !== "string" && !(body instanceof Blob) && !(body instanceof FormData)) {
      body = JSON.stringify(body);
      headers["Content-Type"] = "application/json";
    }
    if (user) {
      const token = await user.getIdToken(forceRefresh);
      if (token) headers.Authorization = "Bearer " + token;
    }
    try {
      return await doFetch(url, { method: opts.method || (body === undefined ? "GET" : "POST"), headers, body, signal: opts.signal });
    } catch (e) {
      if (e && e.name === "AbortError") throw e;
      throw new ApiError(0, "Could not reach the Darknode API. Check your connection and try again.", { code: "network" });
    }
  };
  let res = await send(false);
  // An ID token can expire between refreshes (laptop sleep); refresh once and retry.
  if (res.status === 401 && user) res = await send(true);
  if (!res.ok) throw await toApiError(res, opts.failed);
  if (opts.raw) return res;
  if (res.status === 204) return null;
  try { return await res.json(); } catch (_) { return null; }
}

// Report an uncaught client error to the Worker log. Never throws, never retries.
export function reportClientError(err, extra = {}) {
  const base = apiBase();
  if (!base) return;
  const e = err || {};
  const payload = JSON.stringify({
    message: String(e.message || e).slice(0, 500), stack: String(e.stack || "").slice(0, 2000),
    source: extra.source, line: extra.line, col: extra.col,
    page: (globalThis.location && location.pathname) || "", release: extra.release || "",
  });
  try { globalThis.fetch(base + "/api/v1/client-errors", { method: "POST", body: payload, headers: { "Content-Type": "application/json" }, keepalive: true }).catch(() => {}); } catch (_) {}
}
