// Unit tests for worker/usage.js — product heartbeats (Nexus, desktop app, app VMs) that the
// owner's admin panel lists.
import { test, group, assert } from "../harness.mjs";
import { handleUsage, validatePing, mergeUsage } from "../../worker/usage.js";
import { matchRoute, authorize } from "../../worker/auth.js";

const json = (body, status = 200) => ({ status, body });
const ENV = { FIREBASE_PROJECT_ID: "p" };
const me = { kind: "user", uid: "u1", email: "test@darknode.ai", claims: {} };
const req = (b) => ({ text: async () => (typeof b === "string" ? b : JSON.stringify(b)) });
const NOW = Date.parse("2026-11-07T12:00:00Z");
const fsFake = (doc, calls) => async (url, init = {}) => {
  calls.push({ url, method: init.method || "GET", body: init.body ? JSON.parse(init.body) : null });
  if ((init.method || "GET") === "GET") return doc ? { ok: true, status: 200, json: async () => doc } : { ok: false, status: 404, json: async () => ({}) };
  return { ok: true, status: 200, json: async () => ({}) };
};

group("usage", () => {
  test("the route needs a signed-in user, not the owner", () => {
    const { route } = matchRoute("/api/v1/usage", "POST");
    assert.equal(route.id, "usage");
    assert.equal(authorize(route, { kind: "anonymous" }).status, 401);
    assert.equal(authorize(route, { kind: "user", claims: {} }), null);
    assert.equal(matchRoute("/api/v1/usage", "GET").status, 405);
  });
  test("only known products, clean versions and known systems are kept", () => {
    assert.ok(validatePing({ product: "vm" }).error);
    assert.ok(validatePing(null).error);
    const p = validatePing({ product: "nexus", version: "2.56.0", os: "linux", vm: { count: 3 } });
    assert.deepEqual(p, { product: "nexus", version: "2.56.0", os: "linux", vm: null });
    const q = validatePing({ product: "app", version: "<b>x</b>", os: "beos", vm: { count: 5000, running: 9, lastStart: "x" } });
    assert.deepEqual(q, { product: "app", version: "", os: "", vm: { count: 999, running: 9, lastStart: 0 } });
  });
  test("a first ping creates the product entry with the signed-in email", async () => {
    const calls = [];
    const r = await handleUsage(req({ product: "nexus", version: "2.56.0", os: "linux" }), ENV, json, me, { fetch: fsFake(null, calls), token: async () => "t", now: NOW });
    assert.equal(r.body.ok, true);
    const w = calls.find((c) => c.method === "PATCH");
    assert.ok(w.url.includes("/usage/u1?") && w.url.includes("updateMask.fieldPaths=nexus") && w.url.includes("updateMask.fieldPaths=email"));
    assert.ok(!w.url.includes("fieldPaths=app"), "other products are left alone");
    const n = w.body.fields.nexus.mapValue.fields;
    assert.equal(w.body.fields.email.stringValue, "test@darknode.ai");
    assert.equal(n.first.timestampValue, new Date(NOW).toISOString());
    assert.equal(n.version.stringValue, "2.56.0");
    assert.equal(n.pings.integerValue, "1");
  });
  test("a later ping keeps first seen and counts up", () => {
    const prev = { fields: { nexus: { mapValue: { fields: { first: { timestampValue: "2026-10-01T00:00:00Z" }, last: { timestampValue: "2026-11-06T00:00:00Z" }, pings: { integerValue: "4" }, version: { stringValue: "2.55.0" } } } } } };
    const f = mergeUsage(prev, { product: "nexus", version: "2.56.0", os: "linux", vm: null }, "a@b.c", NOW);
    assert.equal(f.nexus.mapValue.fields.first.timestampValue, "2026-10-01T00:00:00Z");
    assert.equal(f.nexus.mapValue.fields.pings.integerValue, "5");
  });
  test("a repeat ping within minutes writes nothing", async () => {
    const prev = { fields: { app: { mapValue: { fields: { last: { timestampValue: new Date(NOW - 60000).toISOString() }, version: { stringValue: "2.55.3" } } } } } };
    const calls = [];
    const r = await handleUsage(req({ product: "app", version: "2.55.3", os: "linux" }), ENV, json, me, { fetch: fsFake(prev, calls), token: async () => "t", now: NOW });
    assert.equal(r.body.skipped, true);
    assert.equal(calls.filter((c) => c.method === "PATCH").length, 0);
  });
  test("the app's VMs are recorded once it has one; none means no VM entry", () => {
    const none = mergeUsage(null, { product: "app", version: "2.55.4", os: "linux", vm: { count: 0, running: 0, lastStart: 0 } }, "", NOW);
    assert.equal(none.vm, undefined);
    const start = NOW - 3600e3;
    const f = mergeUsage(null, { product: "app", version: "2.55.4", os: "linux", vm: { count: 2, running: 0, lastStart: start } }, "", NOW);
    const v = f.vm.mapValue.fields;
    assert.equal(v.count.integerValue, "2");
    assert.equal(v.last.timestampValue, new Date(start).toISOString());
    const run = mergeUsage(null, { product: "app", version: "2.55.4", os: "linux", vm: { count: 2, running: 1, lastStart: start } }, "", NOW);
    assert.equal(run.vm.mapValue.fields.last.timestampValue, new Date(NOW).toISOString(), "a running VM is in use now");
  });
  test("bad input is refused before anything is read", async () => {
    const calls = [];
    const r = await handleUsage(req("{nope"), ENV, json, me, { fetch: fsFake(null, calls), token: async () => "t" });
    assert.equal(r.status, 400);
    const big = await handleUsage(req("x".repeat(3000)), ENV, json, me, { fetch: fsFake(null, calls), token: async () => "t" });
    assert.equal(big.status, 413);
    assert.equal(calls.length, 0);
  });
});
