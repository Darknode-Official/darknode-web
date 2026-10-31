// Shared request authentication, the route table, and principal-keyed rate limits.
//
// Every route the proxy serves is declared once in ROUTES with the access it needs;
// the router (worker.js) matches it, authenticates the caller with authenticate(),
// enforces the declaration, and rate-limits by principal before any handler runs.
// Handlers that need the caller (role lookups, DO headers) read it back with
// requireUser(), which reuses the router's verified principal instead of verifying
// the Firebase token a second time.
import { verifyIdToken } from "./vault-auth.js";
import { isSuspended } from "./gate.js";

// auth: "none" (anyone, the token is not even read), "user" (Firebase ID token),
// "key" (a dk_ workspace API key; the IngestDO verifies the hash and its scopes).
// plan / role are enforced from the token's custom claims when a route sets them.
// methods: omitted means the handler checks the method itself.
export const ROUTES = [
  { id: "health", path: "/api/v1/health", methods: ["GET"], auth: "none" },
  { id: "client-errors", path: "/api/v1/client-errors", methods: ["POST"], auth: "none" },
  { id: "fetch", path: "/api/fetch", methods: ["GET", "POST"], auth: "none" },
  { id: "smart", path: "/api/smart", methods: ["POST"], auth: "none" },
  { id: "intel", path: "/api/intel", auth: "none" },
  { id: "chat", path: "/api/chat", methods: ["POST"], auth: "none" },
  { id: "vault", prefix: "/api/vault/", auth: "user" },
  { id: "graph", prefix: "/api/graph/", auth: "user" },
  { id: "monitor", prefix: "/api/monitor/", auth: "user" },
  { id: "keys", prefix: "/api/keys/", auth: "user" },
  { id: "ingest", prefix: "/api/v1/ingest/", auth: "key", scope: "ingest:write" },
  { id: "findings", prefix: "/api/v1/findings/", auth: "key", scope: "findings:read" },
];

// -> { route, rest } | { status: 404 } | { status: 405, allow }
export function matchRoute(pathname, method, routes = ROUTES) {
  for (const r of routes) {
    const hit = r.path ? pathname === r.path : pathname.startsWith(r.prefix);
    if (!hit) continue;
    if (r.methods && !r.methods.includes(method)) return { status: 405, allow: r.methods };
    return { route: r, rest: r.prefix ? pathname.slice(r.prefix.length) : "" };
  }
  return { status: 404 };
}

export const presentedKey = (request) =>
  request.headers.get("x-darknode-key") || (/^Bearer\s+(dk_\S+)$/.exec(request.headers.get("Authorization") || "") || [])[1] || "";

// A stable, non-reversible id for a presented key, used only to key its rate limit.
async function keyFingerprint(key) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)));
  return Array.from(d.slice(0, 8), (b) => b.toString(16).padStart(2, "0")).join("");
}

const ANON = Object.freeze({ kind: "anonymous", uid: null, email: null, keyId: null, scopes: null, claims: null });

// -> { principal } | { status, error }. principal = { kind, uid, email, keyId, scopes, claims }
// (+ token for a user, which downstream Firestore role lookups need). The error
// messages match what the handlers returned before this module existed.
export async function authenticate(request, env, opts = {}) {
  const key = presentedKey(request);
  if (key) return { principal: { kind: "key", uid: null, email: null, keyId: await keyFingerprint(key), scopes: null, claims: null, key } };
  const m = /^Bearer\s+(\S+)$/.exec(request.headers.get("Authorization") || "");
  if (!m) return { principal: ANON };
  const projectId = env.FIREBASE_PROJECT_ID;
  if (!projectId) return { status: 503, error: "FIREBASE_PROJECT_ID is not set" };
  let who;
  try { who = await (opts.verify || verifyIdToken)(m[1], projectId); }
  catch (e) { return { status: 401, error: "Invalid sign-in token: " + e.message }; }
  if (await (opts.suspended || isSuspended)(projectId, who, m[1])) return { status: 403, error: "Your access has been suspended by an administrator." };
  return { principal: { kind: "user", uid: who.uid, email: who.email || "", keyId: null, scopes: null, claims: who.claims || {}, token: m[1] } };
}

const PLAN_RANK = { free: 0, pro: 1, team: 2, business: 3, enterprise: 4 };

// Does `principal` satisfy `route`? -> null | { status, error }
export function authorize(route, principal) {
  if (route.auth === "user" && principal.kind !== "user") return { status: 401, error: "Sign in required" };
  if (route.auth === "key" && principal.kind !== "key") return { status: 401, error: "API key required (send header x-darknode-key or Authorization: Bearer dk_...)." };
  const claims = principal.claims || {};
  if (route.role === "admin" && claims.admin !== true) return { status: 403, error: "Administrator access required." };
  if (route.plan && !((PLAN_RANK[claims.plan] ?? 0) >= (PLAN_RANK[route.plan] ?? Infinity))) return { status: 403, error: "This feature needs the " + route.plan + " plan." };
  if (route.scope && Array.isArray(principal.scopes) && !principal.scopes.includes(route.scope)) return { status: 403, error: "API key lacks scope " + route.scope + "." };
  return null;
}

// The router stores the verified principal here so handlers never re-verify.
const verified = new WeakMap();
export const attachPrincipal = (request, principal) => verified.set(request, principal);

// For handlers on "user" routes: the router's principal when present, otherwise a
// full check (handlers stay safe to call directly, e.g. from tests).
// -> { uid, email, claims, token } | { err: Response }
export async function requireUser(request, env, json, opts) {
  let p = verified.get(request);
  if (!p) {
    if (!env.FIREBASE_PROJECT_ID) return { err: json({ error: "FIREBASE_PROJECT_ID is not set" }, 503) };
    const a = await authenticate(request, env, opts);
    if (a.error) return { err: json({ error: a.error }, a.status) };
    p = a.principal;
  }
  if (p.kind !== "user") return { err: json({ error: "Sign in required" }, 401) };
  return p;
}

// ---- rate limits ----------------------------------------------------------------
// Anonymous callers are limited per IP in this isolate (cheap, no DO request per
// call, which matters on the free plan's daily DO quota). Signed-in users and API
// keys are limited per principal in a RateLimiterDO, so the limit is global and an
// office NAT no longer shares one budget. A missing binding or a DO error falls back
// to the in-isolate limiter rather than failing the request.
export const LIMITS = { anonymous: 40, user: 120, key: 300, ipCeiling: 300 };
export const WINDOW_MS = 60000;

export class WindowLimiter {
  constructor(max = 5000) { this.hits = new Map(); this.maxKeys = max; }
  // -> 0 when allowed, else seconds until a slot frees
  take(id, limit, now = Date.now()) {
    let arr = this.hits.get(id);
    if (!arr) { arr = []; this.hits.set(id, arr); }
    while (arr.length && now - arr[0] >= WINDOW_MS) arr.shift();
    if (arr.length >= limit) return Math.max(1, Math.ceil((WINDOW_MS - (now - arr[0])) / 1000));
    arr.push(now);
    if (this.hits.size > this.maxKeys) for (const [k, v] of this.hits) if (!v.length || now - v[v.length - 1] >= WINDOW_MS) this.hits.delete(k);
    return 0;
  }
}

const local = new WindowLimiter();

export function principalKey(p, ip) {
  if (p.kind === "user") return "u:" + p.uid;
  if (p.kind === "key") return "k:" + p.keyId;
  return "ip:" + ip;
}

// -> 0 when allowed, else Retry-After seconds
// `limit` overrides the per-kind default (e.g. a tighter budget for a costly model).
export async function rateCheck(env, principal, ip, limiter = local, limit = LIMITS[principal.kind] || LIMITS.anonymous) {
  const id = principalKey(principal, ip);
  if (principal.kind === "anonymous" || !env.RATE) return limiter.take(id, limit);
  try {
    const res = await env.RATE.get(env.RATE.idFromName(id)).fetch("https://rate/?limit=" + limit);
    const out = await res.json();
    return out.ok ? 0 : Math.max(1, out.retryAfter | 0);
  } catch (_) { return limiter.take(id, limit); }
}

// Coarse per-IP ceiling applied before authentication, so unauthenticated floods on
// signed-in routes cannot make the worker verify tokens without bound.
export const ipCeiling = (ip, limiter = local) => limiter.take("ceil:" + ip, LIMITS.ipCeiling);

// One instance per principal. State lives in memory only: a sliding window does not
// need to survive eviction, and skipping storage keeps each check a single cheap call.
export class RateLimiterDO {
  constructor() { this.limiter = new WindowLimiter(1); }
  async fetch(request) {
    const limit = Math.max(1, Math.min(10000, parseInt(new URL(request.url).searchParams.get("limit"), 10) || LIMITS.user));
    const wait = this.limiter.take("p", limit);
    return new Response(JSON.stringify({ ok: wait === 0, retryAfter: wait }), { headers: { "Content-Type": "application/json" } });
  }
}

// ---- request ids ----------------------------------------------------------------
// A caller-supplied x-request-id is kept when it is well formed, so a client can
// correlate its own logs; otherwise a fresh one is minted.
export function requestId(request) {
  const given = request.headers.get("x-request-id") || "";
  return /^[A-Za-z0-9._:-]{8,64}$/.test(given) ? given : crypto.randomUUID();
}

export function withHeaders(res, extra) {
  const h = new Headers(res.headers);
  for (const [k, v] of Object.entries(extra)) h.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}
