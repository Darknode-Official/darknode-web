// Unit tests for worker/auth.js (Phase 0 shared auth middleware) and the router
// that enforces it. No network: token verification and the ban check are injected.
import { test, group, assert } from "../harness.mjs";
import {
  ROUTES, matchRoute, authenticate, authorize, attachPrincipal, requireUser,
  WindowLimiter, rateCheck, principalKey, RateLimiterDO, requestId, LIMITS, WINDOW_MS,
} from "../../worker/auth.js";
import worker from "../../worker/worker.js";

const env = { FIREBASE_PROJECT_ID: "p1" };
const req = (path, init = {}) => new Request("https://w.test" + path, init);
const bearer = (t) => ({ headers: { Authorization: "Bearer " + t } });
const okVerify = async (tok) => { if (tok !== "good") throw new Error("bad signature"); return { uid: "u1", email: "a@b.c", claims: { plan: "pro" } }; };
const notSuspended = async () => false;
const json = (obj, s = 200) => ({ obj, s });

let ipN = 0;
const call = (path, init = {}, e = {}) => {
  const headers = new Headers(init.headers || {});
  if (!headers.has("cf-connecting-ip")) headers.set("cf-connecting-ip", "198.51.100." + (ipN++ % 250));
  return worker.fetch(req(path, { ...init, headers }), e);
};

group("worker/auth route table", () => {
  test("every route declares a known auth level and ids are unique", () => {
    const ids = new Set();
    for (const r of ROUTES) {
      assert.ok(["none", "user", "key"].includes(r.auth), r.id);
      assert.ok(!!r.path !== !!r.prefix, r.id + " has exactly one of path/prefix");
      assert.ok(!ids.has(r.id), "duplicate " + r.id); ids.add(r.id);
    }
  });
  test("matchRoute: exact paths, prefixes with the remainder, 404 and 405", () => {
    assert.equal(matchRoute("/api/chat", "POST").route.id, "chat");
    assert.deepEqual(matchRoute("/api/chat", "GET"), { status: 405, allow: ["POST"] });
    const v = matchRoute("/api/vault/abc12345", "GET");
    assert.equal(v.route.id, "vault"); assert.equal(v.rest, "abc12345");
    assert.equal(matchRoute("/api/v1/findings/w1", "GET").route.auth, "key");
    assert.equal(matchRoute("/api/chatty", "POST").status, 404);
    assert.equal(matchRoute("/api/intel", "DELETE").route.id, "intel"); // handler checks its own method
  });
  test("today's anonymous routes stay anonymous until Phase 3", () => {
    for (const id of ["chat", "smart", "fetch", "intel", "health"]) assert.equal(ROUTES.find((r) => r.id === id).auth, "none", id);
  });
});

group("worker/auth authenticate + authorize", () => {
  const opts = { verify: okVerify, suspended: notSuspended };
  test("no credentials is anonymous", async () => {
    assert.equal((await authenticate(req("/"), env, opts)).principal.kind, "anonymous");
  });
  test("a valid Firebase token is a user principal with claims", async () => {
    const p = (await authenticate(req("/", bearer("good")), env, opts)).principal;
    assert.equal(p.kind, "user"); assert.equal(p.uid, "u1"); assert.equal(p.claims.plan, "pro"); assert.equal(p.token, "good");
  });
  test("a bad token is 401, a suspended user 403, a missing project 503", async () => {
    const bad = await authenticate(req("/", bearer("nope")), env, opts);
    assert.equal(bad.status, 401); assert.ok(bad.error.startsWith("Invalid sign-in token"));
    assert.equal((await authenticate(req("/", bearer("good")), env, { verify: okVerify, suspended: async () => true })).status, 403);
    assert.equal((await authenticate(req("/", bearer("good")), {}, opts)).status, 503);
  });
  test("a dk_ key (header or bearer) is a key principal with a stable fingerprint, never verified as a JWT", async () => {
    let verified = 0;
    const o = { verify: async () => { verified++; throw new Error("x"); }, suspended: notSuspended };
    const a = (await authenticate(req("/", { headers: { "x-darknode-key": "dk_abc" } }), env, o)).principal;
    const b = (await authenticate(req("/", bearer("dk_abc")), env, o)).principal;
    assert.equal(a.kind, "key"); assert.equal(a.keyId, b.keyId); assert.equal(a.keyId.length, 16);
    assert.ok(!a.keyId.includes("abc")); assert.equal(verified, 0);
  });
  test("authorize enforces auth level, admin role, plan rank and known key scopes", () => {
    const user = { kind: "user", claims: { plan: "pro" } };
    assert.equal(authorize({ auth: "user" }, { kind: "anonymous" }).status, 401);
    assert.equal(authorize({ auth: "key" }, user).status, 401);
    assert.equal(authorize({ auth: "user" }, user), null);
    assert.equal(authorize({ auth: "user", role: "admin" }, user).status, 403);
    assert.equal(authorize({ auth: "user", role: "admin" }, { kind: "user", claims: { admin: true } }), null);
    assert.equal(authorize({ auth: "user", plan: "pro" }, user), null);
    assert.equal(authorize({ auth: "user", plan: "team" }, user).status, 403);
    assert.equal(authorize({ auth: "user", plan: "nonsense" }, user).status, 403);
    assert.equal(authorize({ auth: "key", scope: "a" }, { kind: "key", scopes: null }), null); // DO enforces
    assert.equal(authorize({ auth: "key", scope: "a" }, { kind: "key", scopes: ["b"] }).status, 403);
  });
  test("requireUser reuses the router's principal and falls back to a full check", async () => {
    const r1 = req("/");
    attachPrincipal(r1, { kind: "user", uid: "u9", token: "t" });
    assert.equal((await requireUser(r1, {}, json)).uid, "u9");
    assert.equal((await requireUser(req("/"), {}, json)).err.s, 503);
    assert.equal((await requireUser(req("/"), env, json)).err.s, 401);
    assert.equal((await requireUser(req("/", bearer("good")), env, json, { verify: okVerify, suspended: notSuspended })).uid, "u1");
    assert.equal((await requireUser(req("/", bearer("dk_x")), env, json)).err.s, 401);
  });
});

group("worker/auth rate limits", () => {
  test("WindowLimiter allows `limit` per window, then reports seconds to wait, then frees", () => {
    const l = new WindowLimiter();
    for (let i = 0; i < 3; i++) assert.equal(l.take("a", 3, 1000 + i), 0);
    const w = l.take("a", 3, 1010);
    assert.ok(w >= 1 && w <= 60, String(w));
    assert.equal(l.take("b", 3, 1010), 0); // separate bucket
    assert.equal(l.take("a", 3, 1000 + WINDOW_MS), 0);
  });
  test("principal keys: uid, key fingerprint, IP for anonymous", () => {
    assert.equal(principalKey({ kind: "user", uid: "u" }, "1.2.3.4"), "u:u");
    assert.equal(principalKey({ kind: "key", keyId: "k" }, "1.2.3.4"), "k:k");
    assert.equal(principalKey({ kind: "anonymous" }, "1.2.3.4"), "ip:1.2.3.4");
  });
  test("signed-in principals use the RATE DO; anonymous never does; a DO error falls back locally", async () => {
    const seen = [];
    const doNs = (impl) => ({ idFromName: (n) => n, get: (id) => ({ fetch: async (u) => { seen.push([id, u]); return impl(); } }) });
    const ok = doNs(() => new Response(JSON.stringify({ ok: true, retryAfter: 0 })));
    assert.equal(await rateCheck({ RATE: ok }, { kind: "user", uid: "u1" }, "ip", new WindowLimiter()), 0);
    assert.equal(seen[0][0], "u:u1"); assert.ok(seen[0][1].endsWith("limit=" + LIMITS.user));
    await rateCheck({ RATE: ok }, { kind: "anonymous" }, "ip", new WindowLimiter());
    assert.equal(seen.length, 1);
    const deny = doNs(() => new Response(JSON.stringify({ ok: false, retryAfter: 17 })));
    assert.equal(await rateCheck({ RATE: deny }, { kind: "key", keyId: "k" }, "ip", new WindowLimiter()), 17);
    const broken = doNs(() => { throw new Error("DO down"); });
    assert.equal(await rateCheck({ RATE: broken }, { kind: "user", uid: "u2" }, "ip", new WindowLimiter()), 0);
  });
  test("RateLimiterDO counts per instance and clamps the requested limit", async () => {
    const d = new RateLimiterDO();
    const hit = async (q) => (await d.fetch(new Request("https://rate/?limit=" + q))).json();
    assert.equal((await hit(2)).ok, true);
    assert.equal((await hit(2)).ok, true);
    const third = await hit(2);
    assert.equal(third.ok, false); assert.ok(third.retryAfter >= 1);
    const d2 = new RateLimiterDO();
    assert.equal((await (await d2.fetch(new Request("https://rate/?limit=-5"))).json()).ok, true); // clamped to >= 1
  });
});

group("worker router (Phase 0)", () => {
  test("GET /api/v1/health answers ok with bindings and an x-request-id", async () => {
    const r = await call("/api/v1/health", {}, { VAULT: {} });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.equal(j.ok, true); assert.equal(j.bindings.vault, true); assert.equal(j.bindings.rate, false);
    assert.ok(/^[0-9a-f-]{36}$/.test(r.headers.get("x-request-id")));
    assert.ok(r.headers.get("access-control-expose-headers").includes("x-request-id"));
  });
  test("a well-formed caller x-request-id is echoed; a malformed one is replaced", async () => {
    assert.equal((await call("/api/v1/health", { headers: { "x-request-id": "client-abc-123" } })).headers.get("x-request-id"), "client-abc-123");
    assert.notEqual(requestId(req("/", { headers: { "x-request-id": "bad id\twith space" } })), "bad id\twith space");
  });
  test("wrong method is 405 with Allow; unknown path 404; both keep CORS and a request id", async () => {
    const r = await call("/api/smart");
    assert.equal(r.status, 405); assert.equal(r.headers.get("allow"), "POST");
    assert.ok(r.headers.get("access-control-allow-origin") && r.headers.get("x-request-id"));
    assert.equal((await call("/api/nope")).status, 404);
  });
  test("signed-in routes reject anonymous callers at the router with the old message", async () => {
    for (const p of ["/api/vault/abc12345", "/api/graph/w1", "/api/monitor/w1", "/api/keys/w1"]) {
      const r = await call(p, { method: "POST", body: "{}" }, env);
      assert.equal(r.status, 401, p); assert.equal((await r.json()).error, "Sign in required", p);
    }
    const k = await call("/api/v1/findings/w1", {}, env);
    assert.equal(k.status, 401); assert.ok((await k.json()).error.startsWith("API key required"));
  });
  test("anonymous callers hit the per-IP limit with 429 and Retry-After", async () => {
    const h = { headers: { "cf-connecting-ip": "192.0.2.77" } };
    for (let i = 0; i < LIMITS.anonymous; i++) assert.equal((await call("/api/v1/health", h)).status, 200, "call " + i);
    const r = await call("/api/v1/health", h);
    assert.equal(r.status, 429); assert.ok(Number(r.headers.get("retry-after")) >= 1);
  });
  test("POST /api/v1/client-errors logs a clipped record and answers 204", async () => {
    const real = console.error; const logged = [];
    console.error = (s) => logged.push(s);
    try {
      const r = await call("/api/v1/client-errors", { method: "POST", body: JSON.stringify({ message: "x".repeat(900), line: 4, stack: { no: 1 } }) });
      assert.equal(r.status, 204);
      const rec = JSON.parse(logged[0]);
      assert.equal(rec.type, "client-error"); assert.equal(rec.message.length, 500); assert.equal(rec.line, 4);
      assert.equal(rec.stack, undefined); assert.equal(rec.rid, r.headers.get("x-request-id"));
    } finally { console.error = real; }
    assert.equal((await call("/api/v1/client-errors", { method: "POST", body: "nope" })).status, 400);
    assert.equal((await call("/api/v1/client-errors", { method: "POST", body: "x".repeat(9000) })).status, 413);
  });
});
