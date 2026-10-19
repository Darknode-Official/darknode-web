import { test, group, assert } from "../harness.mjs";
import { createSyncEngine } from "../../public/js/graph-sync.js";
import { wins } from "../../public/js/core/graph-merge.js";

// A fake GraphDO: the same LWW + rev-stamping the real worker does, in memory.
function makeServer() {
  const E = {}, R = {}; let rev = 0;
  const apply = (map, list, key) => { for (const rec of list || []) { if (!rec || !rec.id) continue; if (wins(rec, map[rec.id], key)) { rev++; map[rec.id] = { ...rec, _rev: rev }; } } };
  return {
    E, R,
    push: async (p) => { apply(E, p.entities, "updatedAt"); apply(R, p.relationships, "createdAt"); return { rev }; },
    pull: async (since) => { since = Number(since) || 0; return { rev, entities: Object.values(E).filter((v) => v._rev > since), relationships: Object.values(R).filter((v) => v._rev > since) }; },
  };
}

// A minimal local graph with applyRemote + a manual event channel, like security-graph.js.
function makeGraph(seed) {
  const E = { ...(seed || {}) }, R = {}; let sub = null;
  return {
    E, R,
    exportAll: () => ({ entities: Object.values(E).filter((x) => !x.deleted), relationships: Object.values(R).filter((x) => !x.deleted) }),
    applyRemote: (remote) => {
      for (const rec of remote.entities || []) if (wins(rec, E[rec.id], "updatedAt")) { if (rec.deleted) delete E[rec.id]; else E[rec.id] = rec; }
      for (const rec of remote.relationships || []) if (wins(rec, R[rec.id], "createdAt")) { if (rec.deleted) delete R[rec.id]; else R[rec.id] = rec; }
    },
    subscribe: (h) => { sub = h; },
    unsubscribe: () => { sub = null; },
    create: (e) => { E[e.id] = e; if (sub) sub.onEntity(e, false); },
    del: (id) => { delete E[id]; if (sub) sub.onEntity({ id }, true); },
    rel: (r) => { R[r.id] = r; if (sub) sub.onRelationship(r, false); },
  };
}

// Engine bound to a graph + server, timers disabled (tests drive syncNow explicitly).
function mkEngine(graph, server, extra) {
  const box = { v: null };
  const eng = createSyncEngine({
    transport: { pull: server.pull, push: server.push }, graph,
    loadState: () => box.v, saveState: (s) => { box.v = s; },
    debounceMs: 0, pollMs: 0, setTimer: () => 0, clearTimer: () => {},
    ...(extra || {}),
  });
  eng._box = box;
  return eng;
}

const ent = (id, t, extra) => ({ id, type: "DOMAIN", name: id, updatedAt: t, ...(extra || {}) });

group("graph-sync engine", () => {
  test("first start seeds local records up to the server", async () => {
    const server = makeServer();
    const g = makeGraph({ a: ent("a", "2026-01-01"), b: ent("b", "2026-01-02") });
    const eng = mkEngine(g, server);
    await eng.start();
    assert.ok(server.E.a && server.E.b, "both local entities reached the server");
    assert.equal(eng.state().seeded, true);
    assert.ok(eng.state().rev > 0);
  });

  test("a second device pulls what the first pushed", async () => {
    const server = makeServer();
    const A = makeGraph({ x: ent("x", "2026-01-01") });
    await mkEngine(A, server).start();
    const B = makeGraph();
    const engB = mkEngine(B, server);
    await engB.start();
    assert.ok(B.E.x, "device B received entity x via the cloud");
  });

  test("a change on one device propagates to the other", async () => {
    const server = makeServer();
    const A = makeGraph(), B = makeGraph();
    const engA = mkEngine(A, server), engB = mkEngine(B, server);
    await engA.start(); await engB.start();
    A.create(ent("y", "2026-02-01"));   // local edit on A
    await engA.syncNow();               // push it
    await engB.syncNow();               // B pulls it
    assert.ok(B.E.y, "entity y synced A -> B");
  });

  test("conflicting edits converge to the later timestamp", async () => {
    const server = makeServer();
    const A = makeGraph(), B = makeGraph();
    const engA = mkEngine(A, server), engB = mkEngine(B, server);
    await engA.start(); await engB.start();
    A.create(ent("z", "2026-01-01", { name: "old" }));
    B.create(ent("z", "2026-03-01", { name: "new" }));
    await engA.syncNow(); await engB.syncNow();
    await engA.syncNow(); await engB.syncNow(); // one more round to fully converge
    assert.equal(A.E.z.name, "new");
    assert.equal(B.E.z.name, "new");
  });

  test("a delete propagates as a tombstone", async () => {
    const server = makeServer();
    const A = makeGraph({ d: ent("d", "2026-01-01") }), B = makeGraph();
    const engA = mkEngine(A, server), engB = mkEngine(B, server);
    await engA.start(); await engB.start();
    assert.ok(B.E.d, "B first sees d");
    A.del("d");               // delete on A (later-stamped tombstone)
    await engA.syncNow();
    await engB.syncNow();
    assert.ok(!B.E.d, "d removed on B after the delete synced");
  });

  test("a failed push is not lost — it retries", async () => {
    const server = makeServer();
    const g = makeGraph();
    let fail = true;
    const flaky = { pull: server.pull, push: async (p) => { if (fail) throw new Error("network down"); return server.push(p); } };
    const statuses = [];
    const eng = mkEngine(g, server, { transport: flaky, onStatus: (s) => statuses.push(s) });
    await eng.start();
    g.create(ent("k", "2026-01-01"));
    await eng.syncNow();                       // push fails
    assert.ok(statuses.includes("error"), "surfaced an error");
    assert.equal(eng.pending().entities, 1, "the change is still queued");
    fail = false;
    await eng.syncNow();                       // retry succeeds
    assert.ok(server.E.k, "retry delivered the change");
    assert.equal(eng.pending().entities, 0);
  });

  test("a writer with a pending edit still receives a concurrent writer's records in one sync", async () => {
    // Regression: poll sync() pushes then pulls. If push adopted the server head as the cursor,
    // the pull would start past a concurrent writer's new revs and skip them permanently.
    const server = makeServer();
    const X = makeGraph(), Y = makeGraph();
    const engX = mkEngine(X, server), engY = mkEngine(Y, server);
    await engX.start(); await engY.start();          // both synced at the empty head
    Y.create(ent("y1", "2026-02-01"));               // teammate Y writes two records...
    Y.create(ent("y2", "2026-02-02"));
    await engY.syncNow();                            // ...now on the server, X has not pulled them
    X.create(ent("x1", "2026-03-01"));               // X has its own pending local edit
    await engX.syncNow();                            // X syncs ONCE (push x1, then pull)
    assert.ok(X.E.y1 && X.E.y2, "X received Y's records despite pushing its own edit first");
    assert.ok(server.E.x1, "X's own edit still reached the server");
    assert.equal(X.E.x1.name, "x1");
  });

  test("relationships sync alongside entities", async () => {
    const server = makeServer();
    const A = makeGraph({ p: ent("p", "2026-01-01"), q: ent("q", "2026-01-01") });
    const engA = mkEngine(A, server); await engA.start();
    A.rel({ id: "r1", fromId: "p", toId: "q", type: "related_to", createdAt: "2026-01-03" });
    await engA.syncNow();
    const B = makeGraph(); const engB = mkEngine(B, server); await engB.start();
    assert.ok(B.R.r1, "relationship reached device B");
  });
});
