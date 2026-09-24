// Unit tests for public/js/core/store.js
import { test, group, assert } from "../harness.mjs";
import { Store, MemoryBackend, StoreQuotaError } from "../../public/js/core/store.js";

const fresh = () => new Store({ backend: new MemoryBackend() });

group("store", () => {
  test("set/get round-trips JSON values", () => {
    const ns = fresh().namespace("prefs");
    ns.set("theme", "pro");
    ns.set("obj", { a: 1, b: [2, 3] });
    assert.equal(ns.get("theme"), "pro");
    assert.deepEqual(ns.get("obj"), { a: 1, b: [2, 3] });
  });

  test("get returns fallback for missing keys", () => {
    const ns = fresh().namespace("prefs");
    assert.equal(ns.get("nope", "dflt"), "dflt");
    assert.equal(ns.get("nope"), null);
  });

  test("get returns fallback for corrupt JSON instead of throwing", () => {
    const store = fresh();
    // Write raw garbage straight to the backend under the namespaced key.
    store.backend.setItem("dn:prefs:bad", "{not json");
    const ns = store.namespace("prefs");
    assert.equal(ns.get("bad", "safe"), "safe");
  });

  test("namespaces are isolated by prefix", () => {
    const store = fresh();
    const a = store.namespace("alpha"), b = store.namespace("beta");
    a.set("k", 1); b.set("k", 2);
    assert.equal(a.get("k"), 1);
    assert.equal(b.get("k"), 2);
  });

  test("has / remove work", () => {
    const ns = fresh().namespace("prefs");
    ns.set("k", 1);
    assert.ok(ns.has("k"));
    ns.remove("k");
    assert.notOk(ns.has("k"));
  });

  test("update merges a patch object", () => {
    const ns = fresh().namespace("prefs");
    ns.set("cfg", { a: 1, b: 2 });
    const next = ns.update("cfg", { b: 3, c: 4 });
    assert.deepEqual(next, { a: 1, b: 3, c: 4 });
    assert.deepEqual(ns.get("cfg"), { a: 1, b: 3, c: 4 });
  });

  test("update accepts a patch function", () => {
    const ns = fresh().namespace("counter");
    ns.set("c", { n: 1 });
    ns.update("c", (cur) => ({ n: cur.n + 1 }));
    assert.deepEqual(ns.get("c"), { n: 2 });
  });

  test("keys() lists namespace keys excluding meta", () => {
    const ns = fresh().namespace("prefs");
    ns.set("a", 1); ns.set("b", 2);
    const keys = ns.keys().sort();
    assert.deepEqual(keys, ["a", "b"]);
  });

  test("clear() empties a namespace only", () => {
    const store = fresh();
    const a = store.namespace("alpha"), b = store.namespace("beta");
    a.set("x", 1); b.set("y", 2);
    a.clear();
    assert.deepEqual(a.keys(), []);
    assert.equal(b.get("y"), 2);
  });

  test("migrations run once and advance the version", () => {
    const backend = new MemoryBackend();
    // v1 store writes legacy shape
    let s1 = new Store({ backend });
    const ns1 = s1.namespace("graph"); // version defaults to 1
    ns1.set("legacy", { title: "x" });
    // Re-open at v2 with a migration that renames title -> name
    let ran = 0;
    const s2 = new Store({ backend });
    s2.namespace("graph", {
      version: 2,
      migrations: { 2: (ns) => { ran++; const v = ns.get("legacy"); if (v) ns.set("legacy", { name: v.title }); } },
    });
    assert.equal(ran, 1);
    assert.deepEqual(s2.namespace("graph").get("legacy"), { name: "x" });
    // Opening again at v2 must NOT re-run the migration.
    const s3 = new Store({ backend });
    s3.namespace("graph", { version: 2, migrations: { 2: () => { ran++; } } });
    assert.equal(ran, 1);
  });

  test("subscribe() is notified on writes and removes", () => {
    const store = fresh();
    const events = [];
    store.subscribe((e) => events.push(e));
    const ns = store.namespace("prefs");
    ns.set("k", 5);
    ns.remove("k");
    assert.equal(events.length, 2);
    assert.deepEqual(events[0], { namespace: "prefs", key: "k", value: 5 });
    assert.equal(events[1].value, undefined);
  });

  test("invalid namespace names are rejected", () => {
    const store = fresh();
    assert.throws(() => store.namespace("Bad_Name"));
    assert.throws(() => store.namespace("9lives"));
  });

  test("MemoryBackend reports non-persistent", () => {
    assert.notOk(fresh().persistent);
  });

  test("non-serializable values fail gracefully (return false)", () => {
    const ns = fresh().namespace("prefs");
    const circular = {}; circular.self = circular;
    assert.equal(ns.set("bad", circular), false);
  });

  test("quota errors surface as StoreQuotaError", () => {
    const store = fresh();
    const ns = store.namespace("prefs"); // constructed fine with a working backend
    // Now simulate the disk filling up on subsequent writes.
    store.backend.setItem = () => { const e = new Error("full"); e.name = "QuotaExceededError"; throw e; };
    assert.throws(() => ns.set("k", 1));
    let caught = null;
    try { ns.set("k", 1); } catch (e) { caught = e; }
    assert.ok(caught instanceof StoreQuotaError, "throws a typed StoreQuotaError");
  });
});
