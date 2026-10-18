// Unit tests for public/js/core/report-plans.js — remediation plan + SLA report.
import { test, group, assert } from "../harness.mjs";
import { remediationPlan, slaReport } from "../../public/js/core/report-plans.js";

const DAY = 86400000;
const NOW = Date.parse("2026-10-18T00:00:00Z");
// A finding with a created date `ageDays` ago so the default SLA policy produces a due date.
const F = (id, severity, status, ageDays, data = {}) => ({
  id, type: "FINDING", name: id, severity, status,
  createdAt: new Date(NOW - ageDays * DAY).toISOString(),
  data,
});

group("report-plans/remediationPlan", () => {
  test("groups open findings by owner and counts overdue", () => {
    const r = remediationPlan([
      F("a", "critical", "open", 60, { owner: "u1", ownerLabel: "Alex" }), // crit SLA 30d -> overdue
      F("b", "high", "open", 1, { owner: "u1", ownerLabel: "Alex" }),       // fresh -> on track
      F("c", "high", "open", 1, { owner: "u2", ownerLabel: "Bea" }),
      F("d", "low", "open", 1, {}),                                          // unassigned
    ], { now: NOW });
    const u1 = r.owners.find((g) => g.owner === "u1");
    assert.equal(u1.open, 2);
    assert.equal(u1.overdue, 1);
    assert.equal(u1.ownerLabel, "Alex");
    assert.equal(r.unassignedOpen, 1);
    assert.equal(r.totalOpen, 4);
    assert.equal(r.overdue, 1);
  });

  test("closed findings are excluded", () => {
    const r = remediationPlan([F("a", "high", "resolved", 1, { owner: "u1" }), F("b", "high", "closed", 1, {})], { now: NOW });
    assert.equal(r.totalOpen, 0);
    assert.equal(r.owners.length, 0);
  });

  test("unassigned owner group sorts last", () => {
    const r = remediationPlan([
      F("a", "low", "open", 1, {}),                 // unassigned
      F("b", "critical", "open", 1, { owner: "u1", ownerLabel: "Alex" }),
    ], { now: NOW });
    assert.equal(r.owners[r.owners.length - 1].owner, ""); // unassigned is last
    assert.equal(r.owners[0].owner, "u1");
  });

  test("items within an owner are most-urgent first (overdue, then severity)", () => {
    const r = remediationPlan([
      F("fresh", "critical", "open", 1, { owner: "u1" }),   // on track
      F("late", "low", "open", 365, { owner: "u1" }),       // low SLA 180d, 365d old -> overdue
    ], { now: NOW });
    const items = r.owners[0].items;
    assert.equal(items[0].id, "late");  // overdue outranks a fresh critical
    assert.equal(items[0].state, "overdue");
  });

  test("owners sort by overdue desc then open desc", () => {
    const r = remediationPlan([
      F("a", "critical", "open", 60, { owner: "u1", ownerLabel: "A" }),  // overdue
      F("b", "high", "open", 1, { owner: "u2", ownerLabel: "B" }),       // on track
      F("c", "high", "open", 1, { owner: "u2", ownerLabel: "B" }),
    ], { now: NOW });
    assert.equal(r.owners[0].owner, "u1"); // 1 overdue beats u2's 2 open on-track
  });

  test("is deterministic", () => {
    const ents = [F("a", "high", "open", 60, { owner: "u1" }), F("b", "low", "open", 1, {})];
    assert.equal(JSON.stringify(remediationPlan(ents, { now: NOW })), JSON.stringify(remediationPlan(ents, { now: NOW })));
  });
});

group("report-plans/slaReport", () => {
  test("per-severity open, overdue and compliance", () => {
    const r = slaReport([
      F("a", "critical", "open", 60, {}),  // crit 30d -> overdue
      F("b", "critical", "open", 1, {}),   // on track
      F("c", "high", "open", 1, {}),       // on track
    ], { now: NOW });
    const crit = r.bySeverity.find((x) => x.severity === "critical");
    assert.equal(crit.open, 2);
    assert.equal(crit.overdue, 1);
    assert.equal(crit.onTrack, 1);
    assert.equal(crit.compliancePct, 50);
  });

  test("overall compliance is over findings that have a due date", () => {
    const r = slaReport([
      F("a", "critical", "open", 60, {}),  // overdue
      F("b", "high", "open", 1, {}),        // on track
      F("c", "info", "open", 1, {}),        // info has no SLA target -> no date, excluded
    ], { now: NOW });
    assert.equal(r.overall.withDate, 2);
    assert.equal(r.overall.overdue, 1);
    assert.equal(r.overall.compliancePct, 50);
  });

  test("breaches are listed most-overdue first", () => {
    const r = slaReport([
      F("a", "critical", "open", 45, {}),   // 15d overdue
      F("b", "critical", "open", 120, {}),  // 90d overdue
    ], { now: NOW });
    assert.equal(r.breaches[0].id, "b");
    assert.ok(r.breaches[0].daysOverdue >= r.breaches[1].daysOverdue);
  });

  test("excepted findings do not count against compliance", () => {
    const r = slaReport([
      F("a", "critical", "open", 60, { exception: { reason: "accepted", approver: "u1", expiresAt: new Date(NOW + 30 * DAY).toISOString() } }),
      F("b", "high", "open", 1, {}),
    ], { now: NOW });
    assert.equal(r.overall.overdue, 0);        // the excepted critical is not overdue
    assert.equal(r.overall.compliancePct, 100);
    const crit = r.bySeverity.find((x) => x.severity === "critical");
    assert.equal(crit.excepted, 1);
  });

  test("KEV findings are tracked separately", () => {
    const kevSet = new Set(["CVE-2026-0001"]);
    const r = slaReport([
      F("a", "high", "open", 20, { cves: ["CVE-2026-0001"] }), // KEV 14d -> overdue at 20d old
    ], { now: NOW, kevSet });
    assert.equal(r.overall.kevOpen, 1);
    assert.equal(r.overall.kevOverdue, 1);
  });

  test("is deterministic and empty-safe", () => {
    assert.equal(slaReport([], { now: NOW }).overall.open, 0);
    const ents = [F("a", "critical", "open", 60, {})];
    assert.equal(JSON.stringify(slaReport(ents, { now: NOW })), JSON.stringify(slaReport(ents, { now: NOW })));
  });
});
