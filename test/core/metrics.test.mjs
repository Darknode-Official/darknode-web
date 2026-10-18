// Unit tests for public/js/core/metrics.js — the workspace metrics / trend snapshot.
import { test, group, assert } from "../harness.mjs";
import { snapshot, trendDelta } from "../../public/js/core/metrics.js";

const NOW = Date.parse("2026-10-18T00:00:00Z");
const day = (n) => new Date(NOW - n * 86400000).toISOString();
const F = (id, severity, status, createdAt, data = {}, source = "vulnimport") => ({ id, type: "FINDING", name: id, severity, status, source, createdAt, data });

group("metrics/snapshot", () => {
  test("counts open vs closed and severity over open only", () => {
    const s = snapshot([
      F("a", "critical", "open", day(1)),
      F("b", "high", "investigating", day(1)),
      F("c", "high", "closed", day(5)),
      { id: "x", type: "ASSET", name: "host" }, // non-findings ignored
    ], { now: NOW });
    assert.equal(s.findings, 3);
    assert.equal(s.open, 2);
    assert.equal(s.closed, 1);
    assert.equal(s.bySeverity.critical, 1);
    assert.equal(s.bySeverity.high, 1); // the closed high is not counted in the open distribution
  });

  test("SLA buckets and compliance% come from the computed due date", () => {
    const s = snapshot([
      F("a", "critical", "open", day(40)), // overdue (crit SLA 30)
      F("b", "critical", "open", day(1)),  // on track
      F("c", "info", "open", day(1)),      // no SLA
    ], { now: NOW });
    assert.equal(s.sla.overdue, 1);
    assert.equal(s.sla.on_track, 1);
    assert.equal(s.sla.none, 1);
    assert.equal(s.slaCompliancePct, 50); // 1 of 2 with a due date is not overdue
  });

  test("MTTR is the mean create->resolve over closed findings with history", () => {
    const s = snapshot([
      F("a", "high", "closed", day(30), { history: [{ field: "status", to: "closed", ts: day(20) }] }), // 10 days
      F("b", "high", "resolved", day(10), { history: [{ field: "status", to: "resolved", ts: day(6) }] }), // 4 days
    ], { now: NOW });
    assert.equal(s.mttrSampleSize, 2);
    assert.equal(s.mttrDays, 7); // (10 + 4) / 2
  });

  test("aging buckets open findings by age", () => {
    const s = snapshot([
      F("a", "high", "open", day(3)),
      F("b", "high", "open", day(20)),
      F("c", "high", "open", day(60)),
      F("d", "high", "open", day(200)),
    ], { now: NOW });
    assert.deepEqual(s.aging, { "0-7": 1, "8-30": 1, "31-90": 1, "90+": 1 });
  });

  test("groups open findings by tool and category", () => {
    const s = snapshot([
      F("a", "high", "open", day(1), { category: "vulnerability" }, "vulnimport"),
      F("b", "medium", "open", day(1), { category: "identity" }, "caaudit"),
      F("c", "medium", "open", day(1), { category: "vulnerability" }, "vulnimport"),
    ], { now: NOW });
    assert.equal(s.byTool.vulnimport, 2);
    assert.equal(s.byTool.caaudit, 1);
    assert.equal(s.byCategory.vulnerability, 2);
  });

  test("carries the exposure score and its breakdown", () => {
    const s = snapshot([F("a", "critical", "open", day(1), { kev: true })], { now: NOW });
    assert.ok(s.exposureScore > 0);
    assert.ok(s.exposure.raw > 0 && s.exposure.k === 50);
  });

  test("coverage is clamped to 0..1 or null", () => {
    assert.equal(snapshot([], { now: NOW }).coverage, null);
    assert.equal(snapshot([], { now: NOW, coverage: 1.4 }).coverage, 1);
    assert.equal(snapshot([], { now: NOW, coverage: 0.42 }).coverage, 0.42);
  });

  test("is deterministic", () => {
    const ents = [F("a", "critical", "open", day(40), { kev: true }), F("b", "high", "closed", day(10), { history: [{ field: "status", to: "closed", ts: day(5) }] })];
    assert.equal(JSON.stringify(snapshot(ents, { now: NOW })), JSON.stringify(snapshot(ents, { now: NOW })));
  });
});

group("metrics/trendDelta", () => {
  test("signed deltas against a previous snapshot; unknowns stay null", () => {
    const cur = snapshot([F("a", "critical", "open", day(1)), F("b", "high", "open", day(1))], { now: NOW });
    const prev = { open: 1, closed: 0, exposureScore: 10, slaCompliancePct: null, mttrDays: null, kevOpen: 0, bySeverity: { critical: 1, high: 0 } };
    const d = trendDelta(cur, prev);
    assert.equal(d.open, 1);
    assert.equal(d.criticalHigh, 1);
    assert.equal(d.slaCompliancePct, null); // cur has no due dates
  });

  test("null previous gives null deltas, not a throw", () => {
    const cur = snapshot([F("a", "high", "open", day(1))], { now: NOW });
    const d = trendDelta(cur, null);
    assert.equal(d.open, null);
  });
});
