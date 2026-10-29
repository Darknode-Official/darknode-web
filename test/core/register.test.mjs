// Unit tests for public/js/core/register.js (storage + graph adapter injected)
import { test, group, assert } from "../harness.mjs";
import { wsKey, isTeam, openRegister } from "../../public/js/core/register.js";
import { DATA_CAP } from "../../public/js/core/sink-map.js";

function fakeStorage(init) {
  const m = new Map(Object.entries(init || {}));
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), _m: m };
}
// Fake graph adapter: in-memory entities keyed by id, like graph-sync.test.mjs's makeGraph.
function fakeGraph(seed) {
  const E = { ...(seed || {}) }; let n = Object.keys(E).length;
  return {
    E,
    create: (type, name, data, opts) => { const e = { id: "g" + (++n), type, name, data, tags: [], severity: (opts || {}).severity || null, status: (opts || {}).status || "new", source: (opts || {}).source || "manual" }; E[e.id] = e; return e; },
    update: (id, u) => { if (!E[id]) return null; Object.assign(E[id], u, { data: { ...E[id].data, ...(u.data || {}) } }); return E[id]; },
    remove: (id) => { delete E[id]; return true; },
    list: (type) => Object.values(E).filter((e) => e.type === type),
    get: (id) => E[id] || null,
  };
}
const clock = () => { let t = 0; return () => `2026-10-16T00:00:${String(t++).padStart(2, "0")}.000Z`; };
const schema = {
  name: (r) => r.legalName,
  severity: (r) => ({ critical: "critical", high: "high" }[r.tier] || null),
  status: (r) => (r.active === false ? "closed" : "open"),
  summary: (r) => ({ legalName: r.legalName, tier: r.tier }),
  columns: [{ key: "id", label: "ID" }, { key: "legalName", label: "Legal name" }, { key: "tier", label: "Tier" }],
};
const open = (o = {}) => {
  const storage = o.storage || fakeStorage(o.team ? { dn_active_ws: "ws1" } : {});
  const graph = o.graph === null ? null : o.graph || fakeGraph();
  const reg = openRegister("vendors", "VENDOR", { schema, storage, graph, now: o.now || clock() });
  return { reg, storage, graph };
};

group("register: wsKey / isTeam", () => {
  test("personal workspace key carries the signed-in account", () => {
    const s = fakeStorage();
    assert.equal(wsKey("reg_x", s), "reg_x__nouser");
    assert.notOk(isTeam(s));
    const prev = globalThis.__dnUid;
    try {
      globalThis.__dnUid = "alpha1"; const a = wsKey("reg_x", s);
      globalThis.__dnUid = "beta22"; const b = wsKey("reg_x", s);
      globalThis.__dnUid = "test-0a"; const g = wsKey("reg_x", s);
      assert.equal(a, "reg_x__u_alpha1");
      assert.notEqual(a, b);
      assert.equal(g, "reg_x__guest");
      globalThis.__dnUid = "beta22";
      assert.equal(wsKey("reg_x", fakeStorage({ dn_active_ws: "team-9" })), "reg_x__ws_team-9");
    } finally { if (prev === undefined) delete globalThis.__dnUid; else globalThis.__dnUid = prev; }
  });
  test("team workspace suffixes __ws_<id>", () => {
    const s = fakeStorage({ dn_active_ws: "team-9" });
    assert.equal(wsKey("reg_x", s), "reg_x__ws_team-9");
    assert.ok(isTeam(s));
  });
  test("broken storage falls back to base / not team", () => {
    const bad = { getItem() { throw new Error("nope"); } };
    assert.equal(wsKey("reg_x", bad), "reg_x__nouser");
    assert.notOk(isTeam(bad));
  });
});

group("register: upsert / get / remove", () => {
  test("upsert assigns id + timestamps and mirrors with registerId/_full", () => {
    const { reg, graph, storage } = open();
    const r = reg.upsert({ legalName: "Acme Payroll", tier: "critical" });
    assert.ok(/^r-[0-9a-z]+$/.test(r.id));
    assert.equal(r.createdAt, r.updatedAt);
    assert.ok(r.graphId, "graphId stored");
    const e = graph.E[r.graphId];
    assert.equal(e.type, "VENDOR");
    assert.equal(e.name, "Acme Payroll");
    assert.equal(e.source, "vendors");
    assert.equal(e.severity, "critical");
    assert.equal(e.status, "open");
    assert.equal(e.data.registerId, "vendors");
    assert.equal(e.data._toolSource, "vendors");
    assert.equal(e.data.tier, "critical");
    assert.equal(e.data._full.id, r.id);
    assert.notOk("graphId" in e.data._full, "_full excludes graph pointer");
    assert.equal(JSON.parse(storage.getItem("reg_vendors__nouser")).length, 1);
  });
  test("ids are deterministic given injected now()", () => {
    const a = open({ now: () => "2026-01-01T00:00:00.000Z" }).reg.upsert({ legalName: "Z" });
    const b = open({ now: () => "2026-01-01T00:00:00.000Z" }).reg.upsert({ legalName: "Z" });
    assert.equal(a.id, b.id);
    assert.equal(a.createdAt, "2026-01-01T00:00:00.000Z");
  });
  test("update path reuses graphId, bumps updatedAt, keeps createdAt", () => {
    const { reg, graph } = open();
    const r = reg.upsert({ legalName: "Acme", tier: "low" });
    const r2 = reg.upsert({ id: r.id, legalName: "Acme Ltd", tier: "high" });
    assert.equal(r2.graphId, r.graphId);
    assert.equal(Object.keys(graph.E).length, 1);
    assert.equal(graph.E[r.graphId].name, "Acme Ltd");
    assert.equal(graph.E[r.graphId].severity, "high");
    assert.equal(r2.createdAt, r.createdAt);
    assert.notEqual(r2.updatedAt, r.updatedAt);
    assert.equal(reg.count(), 1);
  });
  test("get returns the record or null", () => {
    const { reg } = open();
    const r = reg.upsert({ legalName: "A" });
    assert.equal(reg.get(r.id).legalName, "A");
    assert.equal(reg.get("missing"), null);
  });
  test("remove deletes locally and unmirrors", () => {
    const { reg, graph } = open();
    const r = reg.upsert({ legalName: "Gone" });
    assert.ok(reg.remove(r.id));
    assert.equal(reg.count(), 0);
    assert.equal(Object.keys(graph.E).length, 0);
    assert.notOk(reg.remove(r.id));
  });
  test("works with no graph adapter (pure local)", () => {
    const { reg } = open({ graph: null });
    const r = reg.upsert({ legalName: "Local only" });
    assert.notOk(r.graphId);
    assert.equal(reg.list().length, 1);
  });
});

group("register: workspace scoping", () => {
  test("personal and team registers use different keys", () => {
    const storage = fakeStorage();
    const p = openRegister("vendors", "VENDOR", { schema, storage, graph: fakeGraph(), now: clock() });
    p.upsert({ legalName: "Personal" });
    storage.setItem("dn_active_ws", "ws1");
    const t = openRegister("vendors", "VENDOR", { schema, storage, graph: fakeGraph(), now: clock() });
    assert.equal(t.list().length, 0);
    t.upsert({ legalName: "Team" });
    assert.ok(storage.getItem("reg_vendors__ws_ws1"));
    assert.equal(JSON.parse(storage.getItem("reg_vendors__nouser")).length, 1);
    storage.removeItem("dn_active_ws");
    assert.equal(p.list()[0].legalName, "Personal");
  });
  test("team list() rebuilds from graph _full and merges unmirrored locals", () => {
    const graph = fakeGraph();
    graph.create("VENDOR", "Shared Co", { registerId: "vendors", _full: { id: "v-shared", legalName: "Shared Co", tier: "high" } }, { source: "vendors" });
    graph.create("VENDOR", "Other tool", { registerId: "other", _full: { id: "x" } }, { source: "other" });
    graph.create("VENDOR", "Manual", {}, { source: "manual" });
    const storage = fakeStorage({ dn_active_ws: "ws1", reg_vendors__ws_ws1: JSON.stringify([{ id: "v-local", legalName: "Local draft" }, { id: "v-shared", legalName: "stale copy", graphId: "g1" }]) });
    const reg = openRegister("vendors", "VENDOR", { schema, storage, graph, now: clock() });
    const l = reg.list();
    assert.equal(l.length, 2);
    assert.equal(l[0].id, "v-shared");
    assert.equal(l[0].legalName, "Shared Co", "graph copy wins over stale local");
    assert.equal(l[0].graphId, "g1");
    assert.equal(l[1].id, "v-local");
  });
  test("personal list() ignores the graph", () => {
    const graph = fakeGraph();
    graph.create("VENDOR", "Shared Co", { registerId: "vendors", _full: { id: "v-shared" } }, { source: "vendors" });
    const { reg } = open({ graph });
    assert.equal(reg.list().length, 0);
  });
});

group("register: backfill / subscribe", () => {
  test("backfill mirrors local records lacking graphId", async () => {
    const storage = fakeStorage({ reg_vendors__nouser: JSON.stringify([{ id: "a", legalName: "A" }, { id: "b", legalName: "B", graphId: "g1" }]) });
    const graph = fakeGraph({ g1: { id: "g1", type: "VENDOR", name: "B", data: {} } });
    const reg = openRegister("vendors", "VENDOR", { schema, storage, graph, now: clock() });
    const n = await reg.backfill();
    assert.equal(n, 1);
    const saved = JSON.parse(storage.getItem("reg_vendors__nouser"));
    assert.ok(saved[0].graphId);
    assert.equal(saved[1].graphId, "g1");
    assert.equal(graph.list("VENDOR").length, 2);
  });
  test("subscribe is a no-op outside a browser", () => {
    const { reg } = open();
    const off = reg.subscribe(() => {});
    assert.equal(typeof off, "function");
    off();
  });
});

group("register: export / import", () => {
  test("exportCsv uses schema column labels and quotes/guards cells", () => {
    const { reg } = open();
    reg.upsert({ id: "v1", legalName: 'Acme, "Inc"', tier: "=high" });
    const csv = reg.exportCsv();
    const lines = csv.split("\r\n");
    assert.equal(lines[0], "ID,Legal name,Tier");
    assert.equal(lines[1], 'v1,"Acme, ""Inc""",\'=high');
  });
  test("exportCsv accepts explicit columns", () => {
    const { reg } = open();
    reg.upsert({ id: "v1", legalName: "A", tier: "low" });
    assert.equal(reg.exportCsv(["tier"]).split("\r\n")[0], "tier");
    assert.equal(reg.exportCsv([{ key: "legalName", label: "Name" }]).split("\r\n")[1], "A");
  });
  test("exportJson strips graphId", () => {
    const { reg } = open();
    reg.upsert({ id: "v1", legalName: "A" });
    const arr = JSON.parse(reg.exportJson());
    assert.equal(arr.length, 1);
    assert.notOk("graphId" in arr[0]);
    assert.equal(arr[0].legalName, "A");
  });
  test("importJson counts added / updated / rejected and mirrors", () => {
    const { reg, graph } = open();
    reg.upsert({ id: "v1", legalName: "Old" });
    const r = reg.importJson(JSON.stringify([{ id: "v1", legalName: "New" }, { legalName: "Fresh" }, "junk", 7, null, [1]]));
    assert.deepEqual(r, { added: 1, updated: 1, rejected: 4 });
    assert.equal(reg.count(), 2);
    assert.equal(reg.get("v1").legalName, "New");
    assert.equal(Object.keys(graph.E).length, 2);
  });
  test("importJson rejects non-array / bad JSON", () => {
    const { reg } = open();
    assert.throws(() => reg.importJson("{"));
    assert.throws(() => reg.importJson('{"a":1}'));
  });
});

group("register: size cap", () => {
  test("oversize records are fitted under DATA_CAP in the graph mirror", () => {
    const { reg, graph } = open();
    const r = reg.upsert({ legalName: "Big", evidence: Array.from({ length: 3000 }, (_, i) => ({ i, s: "e".repeat(100) })) });
    const e = graph.E[r.graphId];
    assert.ok(JSON.stringify(e.data._full).length <= DATA_CAP);
    assert.equal(e.data._full.evidenceTruncated, true);
    assert.equal(e.data._full.evidenceCount, 3000);
    assert.equal(reg.get(r.id).evidence.length, 3000, "local copy stays complete");
  });
});
