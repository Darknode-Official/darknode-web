// Server plan gating for paid platform features (worker/plan.js featureDenied): cloud sync,
// shared team workspaces, monitors and API keys are checked against the CALLER'S OWN plan,
// so calling the API directly cannot get around the Deck hiding them.
import { test, group, assert } from "../harness.mjs";
import { featureDenied, FEATURE_PLAN, _resetPlanCache } from "../../worker/plan.js";
import { attachPrincipal } from "../../worker/auth.js";
import { handleGraph } from "../../worker/graph.js";
import { handleMonitor } from "../../worker/monitor.js";
import { handleKeys } from "../../worker/ingest.js";

const TEAM = "AbCdEfGhIjKlMnOpQrSt"; // team ids are 20 alphanumerics (Firestore auto-id)
const json = (body, status = 200) => ({ status, body });
const doStub = () => { const calls = []; return { calls, idFromName: (x) => x, get: () => ({ fetch: async (u, init) => { calls.push(init && init.body); return new Response(JSON.stringify({ ok: true }), { status: 200 }); } }) }; };
const env = () => ({ FIREBASE_PROJECT_ID: "p1", GRAPH: doStub(), MONITOR: doStub(), INGEST: doStub() });
// Firestore: users/{uid} has no tier (free); the caller is a member of TEAM.
function firestore() {
  return async (url) => {
    if (String(url).includes("/members/")) return { ok: true, status: 200, json: async () => ({ fields: { uid: { stringValue: "u1" }, role: { stringValue: "owner" } } }) };
    return { ok: false, status: 404, json: async () => ({}) };
  };
}
async function call(handler, wid, { plan, claims, method = "POST", body } = {}) {
  _resetPlanCache();
  const real = globalThis.fetch; globalThis.fetch = firestore();
  try {
    const e = env();
    const req = new Request("https://w.test/x", { method, body: method === "GET" ? undefined : JSON.stringify(body || {}) });
    attachPrincipal(req, { kind: "user", uid: "u1", token: "tok", claims: claims || (plan ? { plan } : {}) });
    const r = await handler(req, e, wid, json);
    return { ...r, reached: (e.GRAPH.calls.length + e.MONITOR.calls.length + e.INGEST.calls.length) > 0 };
  } finally { globalThis.fetch = real; }
}

group("worker: paid platform features", () => {
  test("the feature map matches the Plans page", () => {
    assert.equal(FEATURE_PLAN.sync.need, "pro");
    assert.equal(FEATURE_PLAN.monitors.need, "pro");
    assert.equal(FEATURE_PLAN.teamSync.need, "team");
    assert.equal(FEATURE_PLAN.apiKeys.need, "team");
    assert.equal(featureDenied("sync", "pro"), null);
    assert.equal(featureDenied("apiKeys", "enterprise"), null);
    assert.equal(featureDenied("sync", "free"), "Cloud sync is part of the Pro plan. Request an upgrade under Plans.");
  });
  test("personal cloud sync: Free is refused before the graph is touched, Pro goes through", async () => {
    const free = await call(handleGraph, "u1", { method: "GET" });
    assert.equal(free.status, 402); assert.equal(free.body.plan, true); assert.equal(free.reached, false);
    const pro = await call(handleGraph, "u1", { plan: "pro", body: { entities: [] } });
    assert.equal(pro.status, 200); assert.equal(pro.reached, true);
  });
  test("a team workspace needs Team on the member's own plan", async () => {
    assert.equal((await call(handleGraph, TEAM, { plan: "pro", method: "GET" })).status, 402);
    assert.equal((await call(handleGraph, TEAM, { plan: "team", method: "GET" })).status, 200);
  });
  test("monitors: adding, running and testing need Pro; list, pause and delete stay open", async () => {
    for (const op of ["upsert", "run", "test"]) assert.equal((await call(handleMonitor, "u1", { body: { op } })).status, 402, op);
    for (const op of ["list", "pause", "delete"]) assert.equal((await call(handleMonitor, "u1", { body: { op } })).reached, true, op);
    assert.equal((await call(handleMonitor, "u1", { plan: "pro", body: { op: "upsert" } })).reached, true);
  });
  test("API keys: creating one needs Team; list and revoke stay open", async () => {
    assert.equal((await call(handleKeys, "u1", { plan: "pro", body: { op: "create" } })).status, 402);
    assert.equal((await call(handleKeys, "u1", { body: { op: "revoke" } })).reached, true);
    assert.equal((await call(handleKeys, "u1", { body: { op: "list" } })).reached, true);
    assert.equal((await call(handleKeys, "u1", { plan: "team", body: { op: "create" } })).reached, true);
  });
  test("the admin claim counts as Enterprise", async () => {
    assert.equal((await call(handleKeys, TEAM, { claims: { admin: true }, body: { op: "create" } })).reached, true);
    assert.equal((await call(handleGraph, TEAM, { claims: { admin: true }, method: "GET" })).status, 200);
  });
});
