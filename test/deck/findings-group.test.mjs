// Unit tests for the queue group-by helper in public/js/deck/findings-queue.js
import { test, group, assert } from "../harness.mjs";
import { groupRows, GROUPS } from "../../public/js/deck/findings-queue.js";

const rows = [
  { id: "a", source: "codescan", severity: "high", owner: "u1", ownerShow: "Alex", status: "new" },
  { id: "b", source: "codescan", severity: "critical", owner: "", ownerShow: "Unassigned", status: "investigating" },
  { id: "c", source: "vulnimport", severity: "high", owner: "u1", ownerShow: "Alex", status: "new" },
  { id: "d", source: "vulnimport", severity: "low", owner: "u2", ownerShow: "Sam", status: "new" },
  { id: "e", source: "vulnimport", severity: null, owner: "", ownerShow: "Unassigned", status: "resolved" },
];

group("findings/group", () => {
  test("GROUPS lists the supported dimensions", () => {
    assert.deepEqual(GROUPS, ["none", "source", "severity", "owner", "status"]);
  });

  test("unknown dimension returns one group holding every row", () => {
    const g = groupRows(rows, "nope");
    assert.equal(g.length, 1);
    assert.equal(g[0].rows.length, rows.length);
  });

  test("groups by source, ordered by size then label, with no rows lost", () => {
    const g = groupRows(rows, "source");
    assert.deepEqual(g.map((x) => x.key), ["vulnimport", "codescan"]); // 3 then 2
    assert.equal(g.reduce((n, x) => n + x.rows.length, 0), rows.length);
  });

  test("severity groups come back in severity order, missing severity last", () => {
    const g = groupRows(rows, "severity");
    assert.deepEqual(g.map((x) => x.key), ["critical", "high", "low", "none"]);
    assert.equal(g.find((x) => x.key === "none").label, "Unrated");
  });

  test("owner groups key on uid and label with the display name", () => {
    const g = groupRows(rows, "owner");
    const alex = g.find((x) => x.key === "u1");
    assert.equal(alex.rows.length, 2);
    assert.equal(alex.label, "Alex");
    assert.equal(g.find((x) => x.key === "").label, "Unassigned");
  });

  test("every row lands in exactly one group", () => {
    for (const by of ["source", "severity", "owner", "status"]) {
      const seen = new Set();
      for (const grp of groupRows(rows, by)) for (const r of grp.rows) seen.add(r.id);
      assert.equal(seen.size, rows.length, `dimension ${by} lost or duplicated a row`);
    }
  });
});
