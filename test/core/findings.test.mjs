import { test, group, assert } from "../harness.mjs";
import { collectFindings, filterFindings, findingCounts, toCSV, topActions, sectionEntities } from "../../public/js/core/findings.js";

group("core/findings", () => {
  const ents = [
    { id: "a", type: "FINDING", name: "AWS key in repo", severity: "critical", status: "open", source: "Code Scanner", tags: ["secret"], updatedAt: "2026-10-01" },
    { id: "b", type: "VULNERABILITY", name: "CVE-2026-1", severity: "high", status: "new", source: "Vanguard", tags: [], updatedAt: "2026-10-05" },
    { id: "c", type: "FINDING", name: "Crown jewel reached", severity: "critical", status: "open", tags: ["crucible", "simulated"], updatedAt: "2026-10-09" },
    { id: "d", type: "FINDING", name: "Weak TLS", severity: "medium", status: "resolved", source: "Vanguard", tags: [], updatedAt: "2026-10-08" },
    { id: "e", type: "ASSET", name: "web-01", tags: [], source: "Vanguard" },
  ];

  test("collectFindings keeps real finding types, most severe first", () => {
    assert.deepEqual(collectFindings(ents).map((r) => r.id), ["a", "b", "d"]);
    assert.deepEqual(collectFindings(ents, { includeSim: true }).map((r) => r.id), ["c", "a", "b", "d"]);
  });

  test("collectFindings breaks severity+updatedAt ties on id, independent of input order", () => {
    const same = [
      { id: "z", type: "FINDING", severity: "high", updatedAt: "2026-10-01" },
      { id: "a", type: "FINDING", severity: "high", updatedAt: "2026-10-01" },
    ];
    assert.deepEqual(collectFindings(same).map((r) => r.id), ["a", "z"]);
    assert.deepEqual(collectFindings(same.slice().reverse()).map((r) => r.id), ["a", "z"]);
  });

  test("filterFindings by severity, open status, source and text", () => {
    const rows = collectFindings(ents);
    assert.deepEqual(filterFindings(rows, { severity: "high" }).map((r) => r.id), ["b"]);
    assert.deepEqual(filterFindings(rows, { status: "open" }).map((r) => r.id), ["a", "b"]);
    assert.deepEqual(filterFindings(rows, { source: "Vanguard" }).map((r) => r.id), ["b", "d"]);
    assert.deepEqual(filterFindings(rows, { q: "secret" }).map((r) => r.id), ["a"]);
  });

  test("findingCounts", () => {
    assert.deepEqual(findingCounts(collectFindings(ents)), { total: 3, open: 2, critical: 1, high: 1, resolved: 1 });
  });

  test("toCSV quotes and neutralises formulas", () => {
    const csv = toCSV([{ severity: "high", name: '=HYPERLINK("x"), "q"', id: "1" }], ["severity", "name", "id"]);
    assert.equal(csv, 'severity,name,id\r\nhigh,"\'=HYPERLINK(""x""), ""q""",1\r\n');
  });

  test("topActions ranks real items and never uses sample data", () => {
    const acts = topActions({
      findings: collectFindings(ents, { includeSim: true }),
      cves: [{ id: "CVE-1", cvss: 7.5, title: "x" }, { id: "CVE-2", cvss: 9.8, title: "y" }, { id: "CVE-3", cvss: 5, title: "z" }],
      kev: new Set(["CVE-1"]), connected: new Set(["claude"]),
      integrations: [{ id: "claude", kind: "ai" }, { id: "virustotal", kind: "sec" }],
    });
    assert.deepEqual(acts.map((a) => a.kind + ":" + a.id), ["finding:a", "cve:CVE-1", "finding:b", "cve:CVE-2", "connect:intel"]);
  });

  test("topActions suggests a first scan when there is no real data", () => {
    const acts = topActions({ findings: collectFindings(ents.filter((e) => e.id === "c"), { includeSim: true }), cves: [], integrations: [] });
    assert.deepEqual(acts.map((a) => a.id), ["scan"]);
  });

  test("sectionEntities by type or source pattern, real only", () => {
    assert.deepEqual(sectionEntities(ents, { types: ["ASSET"] }).map((e) => e.id), ["e"]);
    assert.deepEqual(sectionEntities(ents, { match: /code scanner/i }).map((e) => e.id), ["a"]);
    assert.deepEqual(sectionEntities(ents, { types: ["FINDING"] }).map((e) => e.id), ["a", "d"]);
  });
});

group("core/findings: severity sort is proto-safe", () => {
  test("rows drop the finding's internal dedupe key", () => {
    const r = collectFindings([{ id: "k", type: "FINDING", name: "TLS 1.0 enabled (vulnimport:1zx)", severity: "high", data: { tool: "vulnimport", findingKey: "1zx" } }]);
    assert.equal(r[0].name, "TLS 1.0 enabled");
  });
  test("a finding whose severity is a prototype-member name doesn't scramble the order", () => {
    const rows = collectFindings([
      { id: "x", type: "FINDING", severity: "constructor", status: "open", updatedAt: "2026-10-01" },
      { id: "y", type: "FINDING", severity: "critical", status: "open", updatedAt: "2026-10-01" },
      { id: "z", type: "FINDING", severity: "low", status: "open", updatedAt: "2026-10-01" },
    ]);
    // critical (4) first, then low (1), then the bogus severity (ranked -1) last
    assert.deepEqual(rows.map((r) => r.id), ["y", "z", "x"]);
  });
});
