import { test, group, assert } from "../harness.mjs";
import { isSimulated, realEntities, postureStats } from "../../public/js/core/posture.js";

group("core/posture", () => {
  const ents = [
    { id: "a", type: "FINDING", severity: "high", status: "open", tags: ["cve"] },
    { id: "b", type: "FINDING", severity: "critical", status: "open", tags: ["crucible", "simulated"] },
    { id: "c", type: "ASSET", severity: null, status: "new", tags: [], data: { simulated: true } },
    { id: "d", type: "FINDING", severity: "high", status: "new", tags: ["aegis", "firewall", "flow"] },
    { id: "e", type: "ALERT", severity: "medium", status: "new", tags: ["citadel", "soc"], data: { simulated: false } },
    { id: "f", type: "IOC", severity: "low", status: "new", tags: ["Sample"] },
  ];
  const rels = [
    { fromId: "a", toId: "e" },
    { fromId: "a", toId: "b" },
    { fromId: "c", toId: "d" },
  ];

  test("isSimulated recognises tags, data flag and legacy AEGIS flows", () => {
    assert.equal(ents.map(isSimulated).join(","), "false,true,true,true,false,true");
    assert.notOk(isSimulated(null));
    assert.notOk(isSimulated({ id: "x" }));
  });

  test("realEntities keeps only real data", () => {
    assert.deepEqual(realEntities(ents).map((e) => e.id), ["a", "e"]);
    assert.deepEqual(realEntities(undefined), []);
  });

  test("postureStats mirrors getStats over real entities", () => {
    const s = postureStats(ents, rels);
    assert.equal(s.totalEntities, 2);
    assert.equal(s.simulated, 4);
    assert.equal(s.totalRelationships, 1);
    assert.deepEqual(s.bySeverity, { high: 1, medium: 1 });
    assert.deepEqual(s.byType, { FINDING: 1, ALERT: 1 });
    assert.deepEqual(s.byStatus, { open: 1, new: 1 });
  });

  test("postureStats on an empty graph", () => {
    const s = postureStats([], []);
    assert.equal(s.totalEntities, 0);
    assert.equal(s.simulated, 0);
    assert.deepEqual(s.bySeverity, {});
  });
});
