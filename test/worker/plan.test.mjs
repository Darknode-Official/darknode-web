// Paid AI models (worker/plan.js): the plan lookup, the gate message, and the /api/chat
// paths that must refuse paid or unknown models before any upstream call.
import { test, group, assert } from "../harness.mjs";
import { readFileSync } from "node:fs";
import worker from "../../worker/worker.js";
import { GEMINI_MODELS, CLAUDE_PLAN, userTier, planDenied } from "../../worker/plan.js";

const P = (o = {}) => ({ kind: "user", uid: "u1", token: "tok", claims: {}, ...o });
const docFetch = (tier, status = 200) => { const f = async () => { f.calls++; return { ok: status === 200, status, json: async () => (tier ? { fields: { tier: { stringValue: tier } } } : { fields: {} }) }; }; f.calls = 0; return f; };

let ipN = 0;
async function chat(body, env = {}) {
  const realFetch = globalThis.fetch;
  let upstreamCalls = 0;
  globalThis.fetch = async () => { upstreamCalls++; throw new Error("no network in tests"); };
  try {
    const h = new Headers({ "cf-connecting-ip": "198.51.100." + (ipN++ % 200) });
    const r = await worker.fetch(new Request("https://w.test/api/chat", { method: "POST", body: JSON.stringify(body), headers: h }), { GEMINI_KEY: "g", ANTHROPIC_KEY: "a", FIREBASE_PROJECT_ID: "p1", ...env });
    return { status: r.status, body: await r.json().catch(() => ({})), upstreamCalls };
  } finally { globalThis.fetch = realFetch; }
}

group("worker: paid AI models", () => {
  test("Fable 5.1, Opus 5.5 and Darknode Max need Pro; the everyday models stay free", () => {
    assert.equal(CLAUDE_PLAN.get("claude-fable-5-1"), "pro");
    assert.equal(CLAUDE_PLAN.get("claude-opus-5-5"), "pro");
    assert.equal(CLAUDE_PLAN.get("claude-sonnet-5-5"), "free");
    assert.equal(GEMINI_MODELS.get("gemini-3.8-flash"), "pro");
    assert.equal(GEMINI_MODELS.get("gemini-3.5-flash"), "free");
    assert.equal(GEMINI_MODELS.get("gemini-3.1-pro-preview"), undefined);
  });

  test("tier: admin claim, plan claim, user doc, missing doc and failed read", async () => {
    assert.equal(await userTier("p1", P({ claims: { admin: true } }), { cache: new Map() }), "enterprise");
    assert.equal(await userTier("p1", P({ claims: { plan: "team" } }), { cache: new Map() }), "team");
    assert.equal(await userTier("p1", P(), { fetch: docFetch("pro"), cache: new Map() }), "pro");
    assert.equal(await userTier("p1", P(), { fetch: docFetch(""), cache: new Map() }), "free");
    assert.equal(await userTier("p1", P(), { fetch: docFetch("pro", 403), cache: new Map() }), "free");
    const boom = async () => { throw new Error("down"); };
    assert.equal(await userTier("p1", P(), { fetch: boom, cache: new Map() }), "free");
    assert.equal(await userTier("p1", P(), { fetch: docFetch("bogus"), cache: new Map() }), "free");
  });

  test("tier is cached per uid for a minute", async () => {
    const cache = new Map(), f = docFetch("pro");
    await userTier("p1", P(), { fetch: f, cache, now: 0 });
    await userTier("p1", P(), { fetch: f, cache, now: 30_000 });
    assert.equal(f.calls, 1);
    await userTier("p1", P(), { fetch: f, cache, now: 61_000 });
    assert.equal(f.calls, 2);
  });

  test("planDenied: pro and above pass, free gets the upgrade message", () => {
    assert.equal(planDenied("pro", "pro"), null);
    assert.equal(planDenied("pro", "enterprise"), null);
    assert.equal(planDenied("free", "free"), null);
    assert.ok(/Pro plan/.test(planDenied("pro", "free")));
  });

  test("/api/chat: unknown Gemini model 400, paid Gemini signed out 401, none reach Google", async () => {
    const m = (model) => ({ provider: "gemini", model, messages: [{ role: "user", content: "hi" }] });
    const a = await chat(m("gemini-3.1-pro-preview"));
    assert.equal(a.status, 400);
    const b = await chat(m("gemini-3.8-flash"));
    assert.equal(b.status, 401); assert.equal(b.body.code, "plan_required");
    for (const r of [a, b]) assert.equal(r.upstreamCalls, 0);
  });

  test("webai lists the paid models with plan: pro and filters them by tier", () => {
    const src = readFileSync(new URL("../../public/js/webai.js", import.meta.url), "utf8");
    for (const id of ["claude-fable-5-1", "claude-opus-5-5", "gemini-3.8-flash"]) assert.ok(new RegExp('id: "' + id + '"[^\\n]*plan: "pro"').test(src), id);
    assert.ok(/MODELS\.filter\(\(m\) => !m\.plan/.test(src));
  });
});
