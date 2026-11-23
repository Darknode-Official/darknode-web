// Workspace plan sharing (worker/plan-share.js): a team workspace owner can lend their plan
// to the workspace's members. The Worker trusts only the owner's live users/{uid} plan, and
// only while the person who turned sharing on is still the workspace's owner.
import { test, group, assert } from "../harness.mjs";
import { sharedWorkspaceTier, workspaceTier, _resetShareCache } from "../../worker/plan-share.js";
import { _resetPlanCache } from "../../worker/plan.js";
import { attachPrincipal } from "../../worker/auth.js";
import { handleGraph } from "../../worker/graph.js";

const TEAM = "AbCdEfGhIjKlMnOpQrSt";
const ENV = { FIREBASE_PROJECT_ID: "p1" };
const me = { kind: "user", uid: "u1", token: "tok", claims: {} };
const ok = (fields) => ({ ok: true, status: 200, json: async () => ({ fields }) });
const nope = { ok: false, status: 404, json: async () => ({}) };

// ws: workspace doc fields; roles: uid -> role; users: uid -> { tier, admin }; seen: tokens per path
function fs({ ws = {}, roles = { u1: "analyst", boss: "owner" }, users = {} } = {}, seen = []) {
  return async (url, init) => {
    const u = String(url), tok = ((init && init.headers && init.headers.Authorization) || "").slice(7);
    const m = u.match(/members\/([^?]+)/);
    if (m) { seen.push(["member", tok]); const id = decodeURIComponent(m[1]); return roles[id] ? ok({ uid: { stringValue: id }, role: { stringValue: roles[id] } }) : nope; }
    const us = u.match(/\/users\/([^?]+)/);
    if (us) {
      seen.push(["user", tok]);
      const d = users[decodeURIComponent(us[1])]; if (!d) return nope;
      const f = {}; if (d.tier) f.tier = { stringValue: d.tier }; if (d.admin) f.admin = { booleanValue: true };
      return ok(f);
    }
    if (u.includes("/workspaces/")) { seen.push(["ws", tok]); return ok(ws); }
    return nope;
  };
}
const on = (by = "boss") => ({ sharePlan: { booleanValue: true }, sharePlanBy: { stringValue: by }, sharePlanTier: { stringValue: "enterprise" } });
const opts = (fetch) => ({ fetch, token: async () => "sa-token", cache: new Map(), userCache: new Map() });

group("worker: workspace plan sharing", () => {
  test("sharing off: members keep their own plan", async () => {
    assert.equal(await workspaceTier(ENV, TEAM, me, opts(fs({ users: { boss: { tier: "team" } } }))), "free");
  });
  test("sharing on: a member gets the owner's live plan, read with the service account", async () => {
    const seen = [];
    assert.equal(await workspaceTier(ENV, TEAM, me, opts(fs({ ws: on(), users: { boss: { tier: "team" } } }, seen))), "team");
    assert.deepEqual(seen.find((s) => s[0] === "user" && s[1] === "sa-token") ? true : false, true);
    assert.equal(seen.filter((s) => s[0] === "ws" || s[0] === "member").every((s) => s[1] === "tok"), true);
  });
  test("the tier written on the workspace doc is never trusted", async () => {
    // doc claims enterprise; the owner's real plan is pro
    assert.equal(await sharedWorkspaceTier(ENV, TEAM, me, opts(fs({ ws: on(), users: { boss: { tier: "pro" } } }))), "pro");
  });
  test("an admin owner lends Enterprise", async () => {
    assert.equal(await sharedWorkspaceTier(ENV, TEAM, me, opts(fs({ ws: on(), users: { boss: { admin: true } } }))), "enterprise");
  });
  test("ignored when the sharer is no longer the owner", async () => {
    const f = fs({ ws: on("boss"), roles: { u1: "analyst", boss: "admin" }, users: { boss: { tier: "team" } } });
    assert.equal(await workspaceTier(ENV, TEAM, me, opts(f)), "free");
  });
  test("never lowers the member's own plan", async () => {
    const f = fs({ ws: on(), users: { boss: { tier: "pro" } } });
    assert.equal(await workspaceTier(ENV, TEAM, { ...me, claims: { plan: "team" } }, opts(f)), "team");
  });
  test("personal workspaces always use the caller's own plan", async () => {
    let calls = 0; const f = async () => { calls++; return nope; };
    assert.equal(await workspaceTier(ENV, "u1", me, opts(f)), "free");
    assert.equal(await sharedWorkspaceTier(ENV, "u1", me, opts(f)), "free");
  });
  test("fails closed when the service account is unavailable", async () => {
    const o = { ...opts(fs({ ws: on(), users: { boss: { tier: "team" } } })), token: async () => { throw new Error("FIREBASE_SA is not set"); } };
    assert.equal(await sharedWorkspaceTier(ENV, TEAM, me, o), "free");
  });
  test("graph: a Free member of a non-sharing team workspace is still refused", async () => {
    _resetPlanCache(); _resetShareCache();
    const real = globalThis.fetch; globalThis.fetch = fs({ users: { boss: { tier: "team" } } });
    try {
      const req = new Request("https://w.test/x", { method: "GET" });
      attachPrincipal(req, me);
      const calls = [];
      const env = { FIREBASE_PROJECT_ID: "p1", GRAPH: { idFromName: (x) => x, get: () => ({ fetch: async () => { calls.push(1); return new Response("{}"); } }) } };
      const r = await handleGraph(req, env, TEAM, (body, status = 200) => ({ status, body }));
      assert.equal(r.status, 402); assert.equal(calls.length, 0);
    } finally { globalThis.fetch = real; _resetShareCache(); }
  });
});

// liveTier: the plan behind work with no user request (monitor alarms, API-key ingest).
import { liveTier } from "../../worker/plan-share.js";
group("worker: live plan for background work", () => {
  const lo = (fetch) => ({ fetch, token: async () => "sa-token", cache: new Map(), shareCache: new Map() });
  test("reads the creator's live plan with the service account", async () => {
    const seen = [];
    assert.equal(await liveTier(ENV, "u1", "u1", lo(fs({ users: { u1: { tier: "pro" } } }, seen))), "pro");
    assert.ok(seen.every(([, t]) => t === "sa-token"), "service account token");
  });
  test("a downgraded creator reads as free; no profile reads as free", async () => {
    assert.equal(await liveTier(ENV, "u1", "u1", lo(fs({ users: { u1: { tier: "free" } } }))), "free");
    assert.equal(await liveTier(ENV, "u1", "u1", lo(fs({ users: {} }))), "free");
  });
  test("the owner's admin flag counts as the top plan", async () => {
    assert.equal(await liveTier(ENV, "boss", "boss", lo(fs({ users: { boss: { admin: true } } }))), "enterprise");
  });
  test("no recorded creator: personal workspace uses its own user, a team workspace its createdBy", async () => {
    assert.equal(await liveTier(ENV, "u9", "", lo(fs({ users: { u9: { tier: "pro" } } }))), "pro");
    assert.equal(await liveTier(ENV, TEAM, "", lo(fs({ ws: { createdBy: { stringValue: "boss" } }, users: { boss: { tier: "team" } } }))), "team");
  });
  test("a member's work in a team workspace counts the owner's shared plan", async () => {
    assert.equal(await liveTier(ENV, TEAM, "u1", lo(fs({ ws: on(), users: { boss: { tier: "team" } } }))), "team");
  });
  test("an unreadable profile or missing service account is unknown (null), never a false downgrade", async () => {
    assert.equal(await liveTier(ENV, "u1", "u1", lo(async () => ({ ok: false, status: 503, json: async () => ({}) }))), null);
    assert.equal(await liveTier(ENV, "u1", "u1", { fetch: fs(), token: async () => { throw new Error("FIREBASE_SA is not set"); }, cache: new Map() }), null);
    assert.equal(await liveTier(undefined, "u1", "u1", lo(fs())), null);
  });
});
