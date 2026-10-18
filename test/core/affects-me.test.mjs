// Unit tests for public/js/core/affects-me.js — the "what affects me" live-exposure matcher.
import { test, group, assert } from "../harness.mjs";
import { affectsMe, graphCves } from "../../public/js/core/affects-me.js";

const V = (id, cve, severity, type = "VULNERABILITY", status = "open") => ({ id, type, name: cve, severity, status, data: { cves: [cve] } });

group("affects-me/affectsMe", () => {
  test("flags a graph CVE that is on the KEV set", () => {
    const r = affectsMe([V("v1", "CVE-2026-0001", "high")], { kevSet: new Set(["CVE-2026-0001"]) });
    assert.equal(r.matches.length, 1);
    assert.equal(r.matches[0].cve, "CVE-2026-0001");
    assert.equal(r.matches[0].kev, true);
    assert.equal(r.kevCount, 1);
  });

  test("flags a high-EPSS CVE even when not on KEV", () => {
    const r = affectsMe([V("v1", "CVE-2026-0002", "medium")], { kevSet: new Set(), epss: { "CVE-2026-0002": 0.8 }, epssFloor: 0.5 });
    assert.equal(r.matches.length, 1);
    assert.equal(r.epssCount, 1);
    assert.equal(r.matches[0].epss, 0.8);
  });

  test("a low-EPSS, non-KEV CVE is not flagged", () => {
    const r = affectsMe([V("v1", "CVE-2026-0003", "low")], { kevSet: new Set(), epss: { "CVE-2026-0003": 0.01 }, epssFloor: 0.5 });
    assert.equal(r.matches.length, 0);
  });

  test("KEV matches sort before EPSS-only, then by EPSS desc", () => {
    const r = affectsMe([
      V("a", "CVE-2026-0010", "low"),   // epss only 0.6
      V("b", "CVE-2026-0011", "low"),   // kev
      V("c", "CVE-2026-0012", "low"),   // epss only 0.9
    ], { kevSet: new Set(["CVE-2026-0011"]), epss: { "CVE-2026-0010": 0.6, "CVE-2026-0012": 0.9 }, epssFloor: 0.5 });
    assert.equal(r.matches[0].cve, "CVE-2026-0011"); // KEV first
    assert.equal(r.matches[1].cve, "CVE-2026-0012"); // then higher EPSS
    assert.equal(r.matches[2].cve, "CVE-2026-0010");
  });

  test("the same CVE on several entities becomes one match listing every subject", () => {
    const r = affectsMe([
      V("v1", "CVE-2026-0020", "high"),
      { id: "asset1", type: "ASSET", name: "web-01", data: { evidence: "affected by CVE-2026-0020" } },
    ], { kevSet: new Set(["CVE-2026-0020"]) });
    assert.equal(r.matches.length, 1);
    assert.equal(r.matches[0].subjectCount, 2);
    assert.equal(r.affectedSubjects, 2);
  });

  test("worst severity across subjects wins", () => {
    const r = affectsMe([V("v1", "CVE-2026-0030", "medium"), V("v2", "CVE-2026-0030", "critical")], { kevSet: new Set(["CVE-2026-0030"]) });
    assert.equal(r.matches[0].severity, "critical");
  });

  test("accepts a kevSet given as an array, and is deterministic", () => {
    const ents = [V("v1", "CVE-2026-0040", "high"), V("v2", "CVE-2026-0041", "high")];
    const a = affectsMe(ents, { kevSet: ["CVE-2026-0040", "CVE-2026-0041"] });
    assert.equal(a.matches.length, 2);
    assert.equal(JSON.stringify(a), JSON.stringify(affectsMe(ents, { kevSet: ["CVE-2026-0040", "CVE-2026-0041"] })));
  });

  test("empty graph is safe", () => {
    const r = affectsMe([], { kevSet: new Set(["CVE-2026-0001"]) });
    assert.equal(r.matches.length, 0);
    assert.equal(r.scanned, 0);
  });
});

group("affects-me/graphCves", () => {
  test("collects unique CVE ids and respects the cap", () => {
    assert.deepEqual(graphCves([V("v1", "CVE-2026-0001", "high"), V("v2", "CVE-2026-0001", "high")]).sort(), ["CVE-2026-0001"]);
    const many = []; for (let i = 0; i < 10; i++) many.push(V("v" + i, "CVE-2026-10" + (10 + i), "high"));
    assert.equal(graphCves(many, 3).length, 3);
  });
});
