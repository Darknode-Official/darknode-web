// Unit tests for the GraphDO audit chain (Deck D6) — the per-workspace, hash-chained
// record of graph writes. Driven with an in-memory Durable Object storage shim.
import { test, group, assert } from "../harness.mjs";
import { GraphDO } from "../../worker/graph.js";

// Storage shim: supports single + array get, object + (k,v) put, delete, and a sorted
// list({ prefix, reverse, limit }) — enough for GraphDO's pull / audit paths.
function memState() {
  const map = new Map();
  const storage = {
    async get(k) {
      if (Array.isArray(k)) { const m = new Map(); for (const key of k) if (map.has(key)) m.set(key, map.get(key)); return m; }
      return map.has(k) ? map.get(k) : undefined;
    },
    async put(k, v) { if (k && typeof k === "object") { for (const [kk, vv] of Object.entries(k)) map.set(kk, vv); } else { map.set(k, v); } },
    async delete(k) { map.delete(k); },
    async list({ prefix = "", reverse = false, limit = Infinity } = {}) {
      let keys = [...map.keys()].filter((x) => x.startsWith(prefix)).sort();
      if (reverse) keys.reverse();
      keys = keys.slice(0, limit);
      const out = new Map(); for (const key of keys) out.set(key, map.get(key)); return out;
    },
  };
  return { storage, blockConcurrencyWhile: async (fn) => fn(), _map: map };
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
});
