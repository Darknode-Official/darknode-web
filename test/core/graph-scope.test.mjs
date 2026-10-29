// Per-account scoping of the personal security graph and trend history: localStorage is
// shared by every account that signs in on a browser, so the personal store must be keyed
// by the signed-in uid (window.__dnUid) and re-point when the account changes.
import { test, group, assert } from "../harness.mjs";

if (typeof globalThis.localStorage === "undefined") {
  const m = new Map();
  globalThis.localStorage = {
    getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k), clear: () => m.clear(),
  };
}
const SG = await import("../../public/js/security-graph.js");
const TS = await import("../../public/js/deck/trend-store.js");

// Run fn as the given account; window is globalThis here, restored afterwards.
function as(uid, fn) {
  const hadWin = "window" in globalThis, prevWin = globalThis.window, prevUid = globalThis.__dnUid;
  globalThis.window = globalThis; globalThis.__dnUid = uid;
  try { return fn(); } finally {
    if (hadWin) globalThis.window = prevWin; else delete globalThis.window;
    if (prevUid === undefined) delete globalThis.__dnUid; else globalThis.__dnUid = prevUid;
  }
}
const names = () => SG.listEntities({ type: "ASSET" }).map((e) => e.name).filter((n) => n.startsWith("scope-")).sort();

group("personal graph is per account", () => {
  test("one account's personal entities are not visible to another on the same browser", () => {
    localStorage.removeItem("dn_active_ws");
    as("alpha1", () => SG.createEntity("ASSET", "scope-a.example", {}));
    as("beta22", () => {
      assert.deepEqual(names(), []);
      SG.createEntity("ASSET", "scope-b.example", {});
    });
    as("alpha1", () => assert.deepEqual(names(), ["scope-a.example"]));
    as("beta22", () => assert.deepEqual(names(), ["scope-b.example"]));
  });

  test("personal keys carry the account; team keys do not; guests share one store", () => {
    as("alpha1", () => {
      assert.equal(SG.storeKeyFor(null), "dn_security_graph__u_alpha1");
      assert.equal(SG.storeKeyFor("w9"), "dn_security_graph__ws_w9");
    });
    as("test-0a1b", () => assert.equal(SG.storeKeyFor(null), "dn_security_graph__guest"));
    as("app-guest-ff", () => assert.equal(SG.storeKeyFor(null), "dn_security_graph__guest"));
    assert.equal(localStorage.getItem("dn_security_graph"), null, "nothing is written to the unscoped key");
  });

  test("recent activity (Overview feed, bell) is per account", () => {
    const k = (uid) => as(uid, () => SG.activityKey());
    assert.equal(k("alpha1"), "dn_recent_activity__u_alpha1");
    assert.notEqual(k("alpha1"), k("beta22"));
    assert.equal(k("test-0a"), k("app-guest-1b"));
  });

  test("trend history is per account for the personal workspace", () => {
    const st = (() => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, v) }; })();
    const snap = { day: "2026-10-28", ts: 1, open: 1, closed: 0, exposureScore: 1, slaCompliancePct: 1, mttrDays: 1, kevOpen: 0, bySeverity: {} };
    as("alpha1", () => TS.recordSnapshot(null, snap, st));
    as("beta22", () => assert.equal(TS.readTrend(null, st).length, 0));
    as("alpha1", () => assert.equal(TS.readTrend(null, st).length, 1));
  });
});
