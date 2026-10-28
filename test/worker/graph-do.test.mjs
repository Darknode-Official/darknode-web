// Unit tests for the GraphDO audit chain (Deck D6) — the per-workspace, hash-chained
// record of graph writes. Driven with an in-memory Durable Object storage shim.
import { test, group, assert } from "../harness.mjs";
import { GraphDO } from "../../worker/graph.js";

// Storage shim: supports single + array get, object + (k,v) put, single + array delete, and a
// sorted list({ prefix, start, reverse, limit }) — enough for GraphDO's pull / index / audit
// paths. `start` (inclusive lower bound) and array delete mirror the real DO storage API, which
// the rev-cursor index relies on. `_lists` records each list() prefix so a test can assert the
// incremental fast path never full-scans "e:"/"r:".
function memState() {
  const map = new Map();
  const lists = [];
  const storage = {
    async get(k) {
      if (Array.isArray(k)) { const m = new Map(); for (const key of k) if (map.has(key)) m.set(key, map.get(key)); return m; }
      return map.has(k) ? map.get(k) : undefined;
    },
    async put(k, v) { if (k && typeof k === "object") { for (const [kk, vv] of Object.entries(k)) map.set(kk, vv); } else { map.set(k, v); } },
    async delete(k) { if (Array.isArray(k)) { let n = 0; for (const key of k) n += map.delete(key) ? 1 : 0; return n; } return map.delete(k); },
    async list({ prefix = "", start = "", reverse = false, limit = Infinity } = {}) {
      lists.push({ prefix, start });
      let keys = [...map.keys()].filter((x) => x.startsWith(prefix) && (!start || x >= start)).sort();
      if (reverse) keys.reverse();
      keys = keys.slice(0, limit);
      const out = new Map(); for (const key of keys) out.set(key, map.get(key)); return out;
    },
  };
  return { storage, blockConcurrencyWhile: async (fn) => fn(), _map: map, _lists: lists };
}

const ent = (id, name, extra = {}) => ({ id, type: "ASSET", name, updatedAt: Date.now(), ...extra });

async function push(doInst, body, uid = "u1") {
  const res = await doInst.fetch(new Request("https://graph/", { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json", "x-graph-uid": uid } }));
  return { status: res.status, json: await res.json() };
}
async function getAudit(doInst, q = "audit=1", uid = "u1") {
  const res = await doInst.fetch(new Request("https://graph/?" + q, { method: "GET", headers: { "x-graph-uid": uid } }));
  return { status: res.status, json: await res.json() };
}

group("GraphDO/audit chain", () => {
  test("a write that changes something appends one audit entry", async () => {
    const st = memState(); const g = new GraphDO(st);
    const r = await push(g, { entities: [ent("a-1", "host1.test.darknode.ai")] });
    assert.equal(r.status, 200);
    assert.equal(r.json.applied.entities, 1);
    const a = await getAudit(g);
    assert.equal(a.json.count, 1);
    assert.equal(a.json.entries.length, 1);
    assert.equal(a.json.entries[0].op, "push");
    assert.equal(a.json.entries[0].uid, "u1");
    assert.equal(a.json.entries[0].entities, 1);
  });

  test("an idle write (nothing wins) appends no audit entry", async () => {
    const st = memState(); const g = new GraphDO(st);
    await push(g, { entities: [ent("a-1", "host1.test.darknode.ai", { updatedAt: 5000 })] });
    const before = (await getAudit(g)).json.count;
    // same record with an older timestamp loses the LWW merge, so nothing changes
    await push(g, { entities: [ent("a-1", "host1.test.darknode.ai", { updatedAt: 1000 })] });
    assert.equal((await getAudit(g)).json.count, before);
  });

  test("records carry the writer uid as _by", async () => {
    const st = memState(); const g = new GraphDO(st);
    await push(g, { entities: [ent("a-2", "host2.test.darknode.ai")] }, "alice-uid");
    assert.equal(st._map.get("e:a-2")._by, "alice-uid");
  });

  test("the chain verifies from genesis", async () => {
    const st = memState(); const g = new GraphDO(st);
    await push(g, { entities: [ent("a-1", "h1.test.darknode.ai")] });
    await push(g, { entities: [ent("a-2", "h2.test.darknode.ai")] });
    await push(g, { relationships: [{ id: "r-1", fromId: "a-1", toId: "a-2", type: "related_to", createdAt: Date.now() }] });
    const v = await getAudit(g, "audit=verify");
    assert.equal(v.json.ok, true);
    assert.equal(v.json.count, 3);
  });

  test("tampering with a stored audit record breaks verification", async () => {
    const st = memState(); const g = new GraphDO(st);
    await push(g, { entities: [ent("a-1", "h1.test.darknode.ai")] });
    await push(g, { entities: [ent("a-2", "h2.test.darknode.ai")] });
    const rec = st._map.get("a:0000000000");
    st._map.set("a:0000000000", { ...rec, op: "delete" }); // forge the op after the fact
    const v = await getAudit(g, "audit=verify");
    assert.equal(v.json.ok, false);
    assert.equal(v.json.brokenAt, 0);
  });

  test("audit entries read back newest-first", async () => {
    const st = memState(); const g = new GraphDO(st);
    await push(g, { entities: [ent("a-1", "h1.test.darknode.ai")] });
    await push(g, { entities: [ent("a-2", "h2.test.darknode.ai")] });
    const a = await getAudit(g);
    assert.equal(a.json.entries[0].n, 1); // newest first
    assert.equal(a.json.entries[1].n, 0);
  });

  test("the audit summary records only real record keys, never index keys", async () => {
    const st = memState(); const g = new GraphDO(st);
    await push(g, { entities: [ent("a-1", "h1.test.darknode.ai")] });
    const a = await getAudit(g);
    assert.ok(a.json.entries[0].ids.every((k) => k.startsWith("e:") || k.startsWith("r:")), "no x: index keys leak into the audit ids");
  });
});

async function pull(doInst, since = 0, uid = "u1") {
  const res = await doInst.fetch(new Request("https://graph/?since=" + since, { method: "GET", headers: { "x-graph-uid": uid } }));
  return { status: res.status, json: await res.json() };
}

group("GraphDO/rev-cursor delta index", () => {
  test("an incremental pull returns only records changed after the cursor", async () => {
    const st = memState(); const g = new GraphDO(st);
    const a = await push(g, { entities: [ent("a-1", "h1.test.darknode.ai")] });
    const b = await push(g, { entities: [ent("a-2", "h2.test.darknode.ai")] });
    const full = await pull(g, 0);
    assert.equal(full.json.entities.length, 2, "since=0 is a full snapshot");
    const delta = await pull(g, a.json.rev); // cursor just after the first write
    assert.equal(delta.json.entities.length, 1, "only the second record is new");
    assert.equal(delta.json.entities[0].id, "a-2");
    assert.equal(delta.json.rev, b.json.rev);
    const none = await pull(g, b.json.rev);
    assert.equal(none.json.entities.length, 0, "cursor at head -> nothing new");
  });

  test("the incremental fast path does not full-scan e:/r:", async () => {
    const st = memState(); const g = new GraphDO(st);
    const a = await push(g, { entities: [ent("a-1", "h1.test.darknode.ai")] });
    await push(g, { entities: [ent("a-2", "h2.test.darknode.ai")] });
    st._lists.length = 0; // watch only this pull's list() calls
    await pull(g, a.json.rev);
    assert.ok(st._lists.some((l) => l.prefix === "x:"), "it scans the x: index");
    assert.ok(!st._lists.some((l) => l.prefix === "e:" || l.prefix === "r:"), "it never scans all entities/relationships");
  });

  test("a full snapshot (since=0) still scans every record, not the index", async () => {
    const st = memState(); const g = new GraphDO(st);
    await push(g, { entities: [ent("a-1", "h1.test.darknode.ai")] });
    st._lists.length = 0;
    const r = await pull(g, 0);
    assert.equal(r.json.entities.length, 1);
    assert.ok(st._lists.some((l) => l.prefix === "e:"), "since=0 uses the full scan");
  });

  test("an updated record keeps exactly one index entry (the stale one is removed)", async () => {
    const st = memState(); const g = new GraphDO(st);
    const a = await push(g, { entities: [ent("a-1", "old.test.darknode.ai", { updatedAt: 1000 })] });
    await push(g, { entities: [ent("a-1", "new.test.darknode.ai", { updatedAt: 2000 })] });
    const xKeys = [...st._map.keys()].filter((k) => k.startsWith("x:") && k.endsWith(":e:a-1"));
    assert.equal(xKeys.length, 1, "one x: entry per record, at its current rev");
    const delta = await pull(g, a.json.rev);
    assert.equal(delta.json.entities.length, 1, "the update surfaces exactly once");
    assert.equal(delta.json.entities[0].name, "new.test.darknode.ai", "and carries the new value");
  });

  test("a tombstone propagates through the index", async () => {
    const st = memState(); const g = new GraphDO(st);
    const a = await push(g, { entities: [ent("a-1", "h1.test.darknode.ai", { updatedAt: 1000 })] });
    await push(g, { entities: [{ id: "a-1", deleted: true, updatedAt: 2000 }] });
    const delta = await pull(g, a.json.rev);
    assert.equal(delta.json.entities.length, 1);
    assert.equal(delta.json.entities[0].deleted, true, "the delete reaches an incremental puller");
  });

  test("migration: records written before the index are still returned to a pre-boundary cursor", async () => {
    // Simulate a DO deployed before the index: raw records carry _rev but there is no "x:" entry
    // and meta has no xBase.
    const st = memState(); const g = new GraphDO(st);
    st._map.set("e:legacy", { id: "legacy", type: "ASSET", name: "legacy.test.darknode.ai", updatedAt: 1000, _rev: 5, _by: "u1" });
    st._map.set("meta", { rev: 5, count: 1 }); // no xBase
    // A new push sets xBase = 5 and indexes the new record (rev 6).
    const b = await push(g, { entities: [ent("a-2", "fresh.test.darknode.ai", { updatedAt: 2000 })] });
    assert.equal(st._map.get("meta").xBase, 5, "xBase pins to the pre-index head");
    // A client catching up from before the boundary (since < xBase) must see BOTH via full scan.
    const behind = await pull(g, 3);
    const ids = behind.json.entities.map((e) => e.id).sort();
    assert.deepEqual(ids, ["a-2", "legacy"], "full-scan fallback returns the legacy record too");
    // A client at/after the boundary uses the index and correctly sees only the fresh record.
    const atBoundary = await pull(g, 5);
    assert.equal(atBoundary.json.entities.length, 1);
    assert.equal(atBoundary.json.entities[0].id, "a-2");
    assert.equal(atBoundary.json.rev, b.json.rev);
  });

  test("a duplicate id in one push applies once (LWW winner), one index entry, rev +1", async () => {
    const st = memState(); const g = new GraphDO(st);
    const r = await push(g, { entities: [
      ent("a-1", "stale.test.darknode.ai", { updatedAt: 1000 }),
      ent("a-1", "winner.test.darknode.ai", { updatedAt: 3000 }),
      ent("a-1", "middle.test.darknode.ai", { updatedAt: 2000 }),
    ] });
    assert.equal(r.json.applied.entities, 1, "one effective change");
    assert.equal(r.json.rev, 1, "rev advanced by exactly one");
    assert.equal(st._map.get("e:a-1").name, "winner.test.darknode.ai", "the LWW winner is stored");
    const xKeys = [...st._map.keys()].filter((k) => k.startsWith("x:") && k.endsWith(":e:a-1"));
    assert.equal(xKeys.length, 1, "exactly one index entry");
    const delta = await pull(g, 0);
    assert.equal(delta.json.entities.filter((e) => e.id === "a-1").length, 1, "surfaces once, not thrice");
  });

  test("relationships are indexed too (keyed by createdAt)", async () => {
    const st = memState(); const g = new GraphDO(st);
    await push(g, { entities: [ent("a-1", "h1.test.darknode.ai"), ent("a-2", "h2.test.darknode.ai")] });
    const mid = await push(g, { relationships: [{ id: "r-1", fromId: "a-1", toId: "a-2", type: "related_to", createdAt: 1000 }] });
    const delta = await pull(g, mid.json.rev - 1);
    assert.equal(delta.json.relationships.length, 1, "the relationship surfaces via the index");
    assert.equal(delta.json.relationships[0].id, "r-1");
  });
});

group("GraphDO/monitor writes keep analyst workflow", () => {
  const fnd = (extra = {}) => ({ id: "f-1", type: "FINDING", name: "Certificate expiring: test.darknode.ai", source: "monitor:m1", createdAt: "2026-10-01T00:00:00.000Z", updatedAt: "2026-10-01T00:00:00.000Z", severity: "medium", status: "open", data: { findingKey: "k1", tool: "monitor:m1", description: "expires in 20 days" }, ...extra });
  const stored = (st) => st._map.get("e:f-1");

  test("a worsened monitor run keeps owner, comments, triage status and severity override", async () => {
    const st = memState(); const g = new GraphDO(st);
    await push(g, { entities: [fnd()] }, "monitor:m1");
    const edited = { ...stored(st), status: "investigating", updatedAt: "2026-10-05T00:00:00.000Z", data: { ...stored(st).data, owner: "u1", comments: [{ by: "u1", text: "on it" }], commentCount: 1 } };
    await push(g, { entities: [edited] }, "u1");
    const r = await push(g, { entities: [fnd({ severity: "high", updatedAt: "2026-10-03T00:00:00.000Z", data: { findingKey: "k1", tool: "monitor:m1", description: "expires in 5 days" } })] }, "monitor:m1");
    assert.equal(r.json.applied.entities, 1);
    const s = stored(st);
    assert.equal(s.data.owner, "u1");
    assert.equal(s.data.commentCount, 1);
    assert.equal(s.status, "investigating");
    assert.equal(s.severity, "high");
    assert.equal(s.data.description, "expires in 5 days");
    assert.equal(s.createdAt, "2026-10-01T00:00:00.000Z");
    assert.ok(Date.parse(s.updatedAt) > Date.parse("2026-10-05T00:00:00.000Z"));
  });

  test("a monitor resolve closes the finding without dropping its workflow; an unchanged rerun applies nothing", async () => {
    const st = memState(); const g = new GraphDO(st);
    await push(g, { entities: [fnd()] }, "monitor:m1");
    assert.equal((await push(g, { entities: [fnd()] }, "monitor:m1")).json.applied.entities, 0, "an unchanged rerun of a new finding is a no-op");
    await push(g, { entities: [{ ...stored(st), updatedAt: "2026-10-05T00:00:00.000Z", data: { ...stored(st).data, owner: "u1", severityOverride: "low" }, severity: "low" }] }, "u1");
    const resolved = fnd({ status: "resolved", severity: "high", updatedAt: "2026-10-04T00:00:00.000Z", data: { findingKey: "k1", tool: "monitor:m1", resolution: "fixed" } });
    await push(g, { entities: [resolved] }, "monitor:m1");
    const s = stored(st);
    assert.equal(s.status, "resolved");
    assert.equal(s.data.resolution, "fixed");
    assert.equal(s.data.owner, "u1");
    assert.equal(s.severity, "low");
    const again = await push(g, { entities: [resolved] }, "monitor:m1");
    assert.equal(again.json.applied.entities, 0);
  });
});
