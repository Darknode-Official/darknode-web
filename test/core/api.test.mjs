// Unit tests for public/js/core/api.js — the single Darknode API client. No network:
// fetch and the signed-in user are injected.
import { test, group, assert } from "../harness.mjs";
import { api, ApiError, apiBase, toApiError } from "../../public/js/core/api.js";

const BASE = "https://w.test";
const jsonRes = (obj, status = 200, headers = {}) => new Response(obj === null ? null : JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...headers } });
function fakeUser(tokens = ["t1", "t2"]) {
  const u = { calls: [], getIdToken: async (force) => { u.calls.push(!!force); return force ? tokens[1] : tokens[0]; } };
  return u;
}
function fakeFetch(...responses) {
  const f = async (url, init) => { f.seen.push({ url, init }); const r = responses.shift(); if (r instanceof Error) throw r; return r; };
  f.seen = [];
  return f;
}

group("core/api client", () => {
  test("apiBase strips the chat route from DARKNODE_PROXY_URL", () => {
    const prev = globalThis.DARKNODE_PROXY_URL;
    globalThis.DARKNODE_PROXY_URL = "https://p.example/api/chat";
    try { assert.equal(apiBase(), "https://p.example"); } finally { globalThis.DARKNODE_PROXY_URL = prev; }
  });
  test("attaches the ID token, JSON-encodes an object body and defaults to POST", async () => {
    const f = fakeFetch(jsonRes({ ok: 1 }));
    const out = await api("/api/keys/w1", { base: BASE, user: fakeUser(), fetch: f, body: { op: "list" } });
    assert.deepEqual(out, { ok: 1 });
    const { url, init } = f.seen[0];
    assert.equal(url, BASE + "/api/keys/w1"); assert.equal(init.method, "POST");
    assert.equal(init.headers.Authorization, "Bearer t1"); assert.equal(init.headers["Content-Type"], "application/json");
    assert.equal(init.body, '{"op":"list"}');
  });
  test("a 401 retries once with a force-refreshed token", async () => {
    const u = fakeUser();
    const f = fakeFetch(jsonRes({ error: "Invalid sign-in token: token expired" }, 401), jsonRes({ ok: 2 }));
    assert.deepEqual(await api("/x", { base: BASE, user: u, fetch: f }), { ok: 2 });
    assert.deepEqual(u.calls, [false, true]);
    assert.equal(f.seen[1].init.headers.Authorization, "Bearer t2");
  });
  test("a second 401 surfaces as ApiError without looping", async () => {
    const f = fakeFetch(jsonRes({ error: "no" }, 401), jsonRes({ error: "still no" }, 401));
    const e = await api("/x", { base: BASE, user: fakeUser(), fetch: f }).catch((x) => x);
    assert.ok(e instanceof ApiError); assert.equal(e.status, 401); assert.equal(e.message, "still no"); assert.equal(e.code, "unauthenticated");
    assert.equal(f.seen.length, 2);
  });
  test("signed out on an auth route fails before any request; auth none sends no token", async () => {
    const f = fakeFetch(jsonRes({ ok: 1 }));
    const e = await api("/x", { base: BASE, user: null, fetch: f, signedOut: "Sign in to manage API keys." }).catch((x) => x);
    assert.equal(e.status, 401); assert.equal(e.message, "Sign in to manage API keys."); assert.equal(f.seen.length, 0);
    await api("/api/v1/health", { base: BASE, auth: "none", fetch: f });
    assert.equal(f.seen[0].init.method, "GET"); assert.equal(f.seen[0].init.headers.Authorization, undefined);
  });
  test("maps both error shapes plus request id and Retry-After", async () => {
    const legacy = await toApiError(jsonRes({ error: "Rate limit exceeded" }, 429, { "x-request-id": "rid-1", "retry-after": "12" }));
    assert.equal(legacy.message, "Rate limit exceeded"); assert.equal(legacy.code, "rate_limited");
    assert.equal(legacy.requestId, "rid-1"); assert.equal(legacy.retryAfter, 12);
    const env = await toApiError(jsonRes({ error: { code: "plan_required", message: "Needs team" } }, 403));
    assert.equal(env.code, "plan_required"); assert.equal(env.message, "Needs team");
    const html = await toApiError(new Response("<html>", { status: 502 }), "Key request failed");
    assert.equal(html.message, "Key request failed"); assert.equal(html.code, "server_error");
  });
  test("network failure becomes ApiError(0, network); an abort is rethrown as-is", async () => {
    const e = await api("/x", { base: BASE, auth: "none", fetch: fakeFetch(new TypeError("fetch failed")) }).catch((x) => x);
    assert.equal(e.status, 0); assert.equal(e.code, "network");
    const abort = Object.assign(new Error("aborted"), { name: "AbortError" });
    assert.equal((await api("/x", { base: BASE, auth: "none", fetch: fakeFetch(abort) }).catch((x) => x)), abort);
  });
  test("query params skip empty values; 204 returns null; raw returns the Response", async () => {
    const f = fakeFetch(new Response(null, { status: 204 }), jsonRes({ a: 1 }));
    assert.equal(await api("/g?x=1", { base: BASE, auth: "none", fetch: f, query: { since: 5, empty: "", none: null } }), null);
    assert.equal(f.seen[0].url, BASE + "/g?x=1&since=5");
    const r = await api("/g", { base: BASE, auth: "none", fetch: f, raw: true });
    assert.ok(r instanceof Response);
  });
  test("no configured base is an 'unconfigured' error", async () => {
    const e = await api("/x", { base: "", auth: "none" }).catch((x) => x);
    assert.equal(e.code, "unconfigured");
  });
});
