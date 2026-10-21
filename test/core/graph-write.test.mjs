// Graph-write correctness: relationship-rule enforcement in security-graph
// createRelationship, sink-map link typing, per-source data merge (mergeToolData),
// the tool-status guard (nextStatus) and the FINDING lifecycle schema.
import { test, group, assert } from "../harness.mjs";
import { RELATIONSHIP_RULES as RULES, ruleAllows } from "../../public/js/core/relationship-rules.js";
import { RELATIONSHIP_RULES, isValidRelationship, validateData } from "../../public/js/core/entities.js";
import { DATA_CAP, toEntities, mergeToolData, nextStatus } from "../../public/js/core/sink-map.js";
import { analyze, exampleDataset, graphItems } from "../../public/js/exposure/vulnimport-engine.js";

// security-graph.js persists to localStorage; give it a minimal in-memory one.
if (typeof globalThis.localStorage === "undefined") {
  const m = new Map();
  globalThis.localStorage = {
    getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k), clear: () => m.clear(),
  };
}
const SG = await import("../../public/js/security-graph.js");

const KEV = { updated: "2026-10-15", count: 1, data: [
  { cve: "CVE-2008-4250", vendor: "Microsoft", product: "Windows", name: "Microsoft Windows Server Service RCE", dateAdded: "2026-05-20", dueDate: "2026-06-03", ransomware: "Unknown" },
] };
const vulnRun = () => analyze(exampleDataset().files, { kev: KEV, now: "2026-10-15T12:00:00Z" });

group("relationship rules", () => {
  test("entities.js re-exports the leaf's rules (one source of truth)", () => {
    assert.equal(RELATIONSHIP_RULES, RULES);
    assert.ok(isValidRelationship("affects", "FINDING", "ASSET"));
    assert.notOk(isValidRelationship("affects", "FINDING", "VULNERABILITY"));
    assert.notOk(ruleAllows("toString", "ASSET", "ASSET"));
  });

  test("every combo the platform's tools write is allowed", () => {
    const combos = [
      ["contains", "INVESTIGATION", "FINDING"], ["contains", "CASE", "ASSET"], ["contains", "INCIDENT", "ALERT"], // graph-bridge / investigation / citadel
      ["affects", "FINDING", "ASSET"], ["affects", "FINDING", "DOMAIN"], ["affects", "FINDING", "IP"], ["affects", "FINDING", "IDENTITY"], ["affects", "FINDING", "VENDOR"], // sink, spectre, ssl, dns, http
      ["mitigates", "CONTROL", "FINDING"], ["related_to", "FINDING", "VULNERABILITY"], ["related_to", "FINDING", "INCIDENT"], // sink-map
      ["affects", "VULNERABILITY", "ASSET"], // vulnimport graphItems
      ["related_to", "CERTIFICATE", "DOMAIN"], ["related_to", "DOMAIN", "DOMAIN"], ["related_to", "DOMAIN", "IP"], // ssl, dns, subdomain tools
      ["observed_in", "IP", "ALERT"], ["observed_in", "DOMAIN", "ALERT"], ["observed_in", "ASSET", "ALERT"], ["related_to", "ALERT", "DOMAIN"], ["related_to", "ALERT", "TECHNIQUE"], // phantom, citadel
      ["contains", "ASSET", "VULNERABILITY"], ["related_to", "ASSET", "TECHNIQUE"], // threatforest
      ["attributed_to", "IP", "THREAT_ACTOR"], ["attributed_to", "DOMAIN", "THREAT_ACTOR"], ["attributed_to", "INDICATOR", "THREAT_ACTOR"], ["attributed_to", "CAMPAIGN", "THREAT_ACTOR"], ["exploits", "THREAT_ACTOR", "VULNERABILITY"], // oracle
    ];
    for (const [rel, from, to] of combos) assert.ok(isValidRelationship(rel, from, to), `${from} -${rel}-> ${to}`);
  });

  test("sink-map links a VULNERABILITY / INCIDENT asset related_to, a real asset affects", () => {
    const { links } = toEntities("t", [{ title: "x", severity: "high", assets: [{ type: "VULNERABILITY", name: "CVE-1" }, { type: "INCIDENT", name: "I" }, { type: "ASSET", name: "web01" }] }]);
    const rel = (to) => links.find((l) => l.to === to).rel;
    assert.equal(rel("VULNERABILITY:CVE-1"), "related_to");
    assert.equal(rel("INCIDENT:I"), "related_to");
    assert.equal(rel("ASSET:web01"), "affects");
  });

  test("vulnimport's sink links and graphItems links are all valid", () => {
    const r = vulnRun();
    const typeOf = (k) => k.slice(0, k.indexOf(":"));
    const sink = toEntities("vulnimport", r.findings).links;
    assert.ok(sink.some((l) => typeOf(l.from) === "FINDING" && typeOf(l.to) === "VULNERABILITY"), "fixture has a KEV finding -> VULNERABILITY link");
    for (const l of [...sink, ...graphItems(r).links]) assert.ok(isValidRelationship(l.rel, typeOf(l.from), typeOf(l.to)), JSON.stringify(l));
  });
});

group("security-graph createRelationship enforcement", () => {
  test("invalid link dropped and counted, valid link kept", () => {
    SG.clearAll();
    const f = SG.createEntity("FINDING", "KEV open", {});
    const v = SG.createEntity("VULNERABILITY", "CVE-2008-4250", {});
    const a = SG.createEntity("ASSET", "web01", {});
    const before = SG.getStats().droppedLinks;
    assert.equal(SG.createRelationship(f.id, v.id, "affects"), null);
    assert.equal(SG.getStats().droppedLinks, before + 1);
    assert.ok(SG.createRelationship(f.id, v.id, "related_to"), "vulnimport's corrected link is stored");
    assert.ok(SG.createRelationship(f.id, a.id, "affects"));
    assert.ok(SG.createRelationship(v.id, a.id, "affects"));
    assert.equal(SG.getStats().totalRelationships, 3);
    assert.equal(SG.getStats().droppedLinks, before + 1);
  });

  test("unknown relationship type is still rejected (not counted as a rule drop)", () => {
    SG.clearAll();
    const a = SG.createEntity("ASSET", "a", {}), b = SG.createEntity("ASSET", "b", {});
    const before = SG.getStats().droppedLinks;
    assert.equal(SG.createRelationship(a.id, b.id, "befriends"), null);
    assert.equal(SG.getStats().droppedLinks, before);
  });

  test("a tool status the guard allows is applied by updateEntity", () => {
    SG.clearAll();
    const e = SG.createEntity("FINDING", "x", {}, { status: "open" });
    const ns = nextStatus(e.status, "resolved");
    assert.equal(SG.updateEntity(e.id, { status: ns }).status, "resolved");
  });
});

group("mergeToolData (upsertToolResult)", () => {
  test("a second tool keeps the first tool's facts; incoming wins on shared keys", () => {
    const first = { os: "Windows", ip: "10.0.0.1", _toolSource: "vulnimport" };
    const m = mergeToolData(first, { ip: "10.0.0.2", openPorts: [445] }, "netexposure");
    assert.equal(m.os, "Windows");
    assert.equal(m.ip, "10.0.0.2");
    assert.deepEqual(m.openPorts, [445]);
    assert.equal(m._toolSource, "netexposure");
    assert.deepEqual(m.bySource.vulnimport, { os: "Windows", ip: "10.0.0.1" });
    assert.deepEqual(m.bySource.netexposure, { ip: "10.0.0.2", openPorts: [445] });
    assert.deepEqual(Object.keys(m.bySource), ["vulnimport", "netexposure"]);
    assert.equal(first.bySource, undefined, "input not mutated");
  });

  test("a re-run of a source replaces its own entry and moves it newest", () => {
    const m1 = mergeToolData({ a: 1, _toolSource: "t1" }, { b: 2 }, "t2");
    const m2 = mergeToolData(m1, { a: 9 }, "t1");
    assert.deepEqual(m2.bySource.t1, { a: 9 });
    assert.deepEqual(Object.keys(m2.bySource), ["t2", "t1"]);
    assert.equal(m2.b, 2);
  });

  test("a single-source re-run does not duplicate data into bySource", () => {
    const m = mergeToolData({ a: 1, _toolSource: "t1" }, { a: 2, c: 3 }, "t1");
    assert.deepEqual(m, { a: 2, c: 3, _toolSource: "t1" });
  });

  test("over the cap, the oldest sources are dropped first", () => {
    const big = "x".repeat(400);
    let d = { _toolSource: "s0", f0: big };
    for (let i = 1; i <= 4; i++) d = mergeToolData(d, { ["f" + i]: big }, "s" + i, 4000);
    assert.ok(JSON.stringify(d).length <= 4000);
    const kept = Object.keys(d.bySource);
    assert.ok(!kept.includes("s0") && kept.includes("s4"), kept.join(","));
    assert.equal(kept[kept.length - 1], "s4");
    for (let i = 0; i <= 4; i++) assert.equal(d["f" + i], big, "top-level facts are kept");
    assert.ok(JSON.stringify(mergeToolData({ _toolSource: "a", x: 1 }, { y: 2 }, "b")).length <= DATA_CAP);
  });
});

group("tool status guard (nextStatus)", () => {
  test("applies resolves and reopens a fixed finding that came back", () => {
    assert.equal(nextStatus("open", "resolved"), "resolved");
    assert.equal(nextStatus("resolved", "open", "fixed"), "open");
    assert.equal(nextStatus("open", "open"), null);
    assert.equal(nextStatus("open", undefined), null);
  });
  test("does not undo analyst triage", () => {
    assert.equal(nextStatus("investigating", "open"), null);
    assert.equal(nextStatus("closed", "open", "false_positive"), null);
    assert.equal(nextStatus("resolved", "new", "accepted"), null);
    assert.equal(nextStatus("investigating", "resolved"), "resolved");
  });
});

group("FINDING lifecycle schema", () => {
  test("accepts graph statuses + resolution, keeps legacy statuses valid", () => {
    for (const status of ["new", "open", "investigating", "resolved", "closed", "remediated", "false-positive"]) {
      assert.ok(validateData("FINDING", { title: "t", status }).ok, status);
    }
    const r = validateData("FINDING", { title: "t", status: "closed", resolution: "false_positive" });
    assert.ok(r.ok);
    assert.equal(r.normalized.resolution, "false_positive");
    assert.notOk(validateData("FINDING", { title: "t", resolution: "wontfix" }).ok);
  });
});

group("mergeToolData: prototype-named tool ids don't corrupt or lose data", () => {
  test("a tool named __proto__ stores its payload as an own key, no proto poisoning", () => {
    const first = mergeToolData(null, { risk: "high" }, "scanner-a");
    const merged = mergeToolData(first, { c: 3 }, "__proto__");
    // the prototype was NOT reassigned...
    assert.equal(Object.getPrototypeOf(Object.create(null)), null);
    assert.equal(({}).c, undefined);
    // ...and the __proto__ source's payload is actually recorded
    assert.ok(merged.bySource && Object.prototype.hasOwnProperty.call(merged.bySource, "__proto__"));
    assert.equal(merged.bySource["__proto__"].c, 3);
  });
  test("an earlier tool named toString is still backed up into bySource", () => {
    const first = mergeToolData(null, { risk: "low" }, "toString");
    const merged = mergeToolData(first, { risk: "high" }, "scanner-b");
    assert.ok(Object.prototype.hasOwnProperty.call(merged.bySource, "toString"));
    assert.equal(merged.bySource["toString"].risk, "low");
  });
});
