// Security Graph layout tests (public/js/secgraph/graph-view.js):
// deterministic force-directed layout math + export/import normalization.

import { test, assert, group } from "../harness.mjs";
import { layout, dist, normalizeImport, normalizeEdges, mulberry32 } from "../../public/js/secgraph/graph-view.js";

const finite = (p) => Number.isFinite(p.x) && Number.isFinite(p.y);

function makeNodes(n) {
  return Array.from({ length: n }, (_, i) => ({ id: "n" + i }));
}

group("secgraph: prng", () => {
  test("mulberry32 is deterministic for a seed", () => {
    const a = mulberry32(7), b = mulberry32(7);
    for (let i = 0; i < 5; i++) assert.equal(a(), b(), "same seed must match");
  });
  test("different seeds diverge", () => {
    assert.notEqual(mulberry32(1)(), mulberry32(2)(), "different seeds should differ");
  });
});

group("secgraph: layout determinism", () => {
  test("same input + seed gives identical positions", () => {
    const nodes = makeNodes(8);
    const edges = [{ fromId: "n0", toId: "n1" }, { fromId: "n2", toId: "n3" }, { fromId: "n4", toId: "n0" }];
    const a = layout(nodes, edges, { seed: 42, iterations: 120 });
    const b = layout(nodes, edges, { seed: 42, iterations: 120 });
    assert.deepEqual(a, b);
  });
  test("different seed gives different positions", () => {
    const nodes = makeNodes(6);
    const a = layout(nodes, [], { seed: 1, iterations: 80 });
    const b = layout(nodes, [], { seed: 2, iterations: 80 });
    assert.notEqual(a.n0.x, b.n0.x, "seed should move layout");
  });
});

group("secgraph: layout numeric safety", () => {
  test("no NaN/Infinity in output", () => {
    const nodes = makeNodes(20);
    const edges = Array.from({ length: 25 }, (_, i) => ({ fromId: "n" + (i % 20), toId: "n" + ((i * 7 + 3) % 20) }));
    const pos = layout(nodes, edges, { seed: 5, iterations: 150 });
    for (const id in pos) assert.ok(finite(pos[id]), id + " must be finite");
  });
  test("coincident / self edges do not break the math", () => {
    const nodes = makeNodes(3);
    const edges = [{ fromId: "n0", toId: "n0" }, { fromId: "n1", toId: "n1" }];
    const pos = layout(nodes, edges, { seed: 3, iterations: 60 });
    for (const id in pos) assert.ok(finite(pos[id]), id + " finite");
  });
  test("empty and single-node inputs", () => {
    assert.deepEqual(layout([], [], {}), {});
    const one = layout([{ id: "solo" }], [], { seed: 9 });
    assert.ok(finite(one.solo), "single node finite");
  });
});

group("secgraph: layout bounds", () => {
  test("positions stay within the configured canvas", () => {
    const w = 900, h = 600, margin = 30;
    const nodes = makeNodes(30);
    const edges = Array.from({ length: 40 }, (_, i) => ({ fromId: "n" + (i % 30), toId: "n" + ((i * 3 + 1) % 30) }));
    const pos = layout(nodes, edges, { seed: 11, iterations: 200, width: w, height: h, margin });
    for (const id in pos) {
      assert.ok(pos[id].x >= margin - 1e-6 && pos[id].x <= w - margin + 1e-6, id + " x in bounds");
      assert.ok(pos[id].y >= margin - 1e-6 && pos[id].y <= h - margin + 1e-6, id + " y in bounds");
    }
  });
  test("a pinned node keeps its given position", () => {
    const nodes = makeNodes(5);
    const pos = layout(nodes, [{ fromId: "n0", toId: "n1" }], { seed: 4, iterations: 100, pinned: { n0: { x: 123, y: 234 } } });
    assert.ok(Math.abs(pos.n0.x - 123) < 1e-6 && Math.abs(pos.n0.y - 234) < 1e-6, "pinned node fixed");
  });
});

group("secgraph: layout semantics", () => {
  test("connected nodes end closer than unconnected ones", () => {
    // n0-n1 are linked; n2-n3 are not. The attractive force should pull the
    // connected pair together while repulsion pushes the free pair apart.
    const nodes = makeNodes(4);
    const edges = [{ fromId: "n0", toId: "n1" }];
    const pos = layout(nodes, edges, { seed: 42, iterations: 300 });
    const connected = dist(pos.n0, pos.n1);
    const unconnected = dist(pos.n2, pos.n3);
    assert.ok(connected < unconnected, `connected ${connected.toFixed(1)} should be < unconnected ${unconnected.toFixed(1)}`);
  });
});

group("secgraph: edge normalization", () => {
  test("accepts relationship/source-target/from-to shapes and drops self/missing", () => {
    const has = (id) => ["a", "b", "c"].includes(id);
    const e = normalizeEdges([
      { fromId: "a", toId: "b" },
      { source: "b", target: "c" },
      { from: "a", to: "c" },
      { fromId: "a", toId: "a" }, // self
      { fromId: "a", toId: "z" }, // missing endpoint
      null,
    ], has);
    assert.deepEqual(e, [["a", "b"], ["b", "c"], ["a", "c"]]);
  });
});

group("secgraph: import normalization round-trip", () => {
  test("export payload and bare array normalize identically", () => {
    const entities = [
      { id: "e1", type: "IP", name: "10.0.0.1" },
      { id: "e2", type: "DOMAIN", name: "example.com" },
    ];
    const fromExport = normalizeImport({ entities, relationships: [], exportedAt: "x" });
    const fromArray = normalizeImport(entities);
    assert.deepEqual(fromExport, fromArray);
    assert.deepEqual(fromExport, entities);
  });
  test("drops entries without a usable type and tolerates junk", () => {
    assert.deepEqual(normalizeImport(null), []);
    assert.deepEqual(normalizeImport({}), []);
    const r = normalizeImport([{ type: "IP", name: "a" }, { name: "no-type" }, null, 5, { type: "" }]);
    assert.equal(r.length, 1);
    assert.equal(r[0].name, "a");
  });
});
