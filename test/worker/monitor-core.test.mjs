// Unit tests for worker/monitor-core.js — the pure monitoring brain.
import { test, group, assert } from "../harness.mjs";
import { diffFindings, diffToEvents, defaultAlertRules, inQuietHours, shouldAlert, sevRank } from "../../worker/monitor-core.js";

const F = (key, severity, title, status = "open") => ({ key, severity, title, status });

group("monitor/diff", () => {
  test("added, removed and changed are separated by stable key", () => {
    const prev = [F("a", "high", "A"), F("b", "medium", "B")];
    const next = [F("a", "critical", "A"), F("c", "low", "C")];
    const d = diffFindings(prev, next);
    assert.equal(d.added.map((f) => f.key).join(","), "c");
    assert.equal(d.removed.map((f) => f.key).join(","), "b");
    assert.equal(d.changed.length, 1);
    assert.equal(d.changed[0].key, "a");
    assert.ok(d.changed[0].fields.includes("severity"));
  });

  test("identical runs produce no changes (only changes alert)", () => {
    const list = [F("a", "high", "A"), F("b", "low", "B")];
    const d = diffFindings(list, list.map((f) => ({ ...f })));
    assert.equal(d.added.length + d.removed.length + d.changed.length, 0);
  });

  test("diff is deterministic regardless of input order", () => {
    const prev = [F("b", "low", "B"), F("a", "high", "A")];
    const next = [F("c", "low", "C"), F("a", "critical", "A")];
    const a = JSON.stringify(diffFindings(prev, next));
    const b = JSON.stringify(diffFindings(prev.slice().reverse(), next.slice().reverse()));
    assert.equal(a, b);
  });

  test("diffToEvents marks a severity rise as worsened", () => {
    const d = diffFindings([F("a", "medium", "A")], [F("a", "critical", "A")]);
    const ev = diffToEvents(d, "domainguard", 1000);
    assert.equal(ev[0].kind, "worsened");
    assert.equal(ev[0].at, 1000);
  });
});

group("monitor/alert rules", () => {
  test("new high finding alerts under the default floor; new low does not", () => {
    assert.equal(shouldAlert({ kind: "new", severity: "high" }).alert, true);
    assert.equal(shouldAlert({ kind: "new", severity: "low" }).alert, false);
  });

  test("KEV and correlation events alert regardless of severity", () => {
    assert.equal(shouldAlert({ kind: "kev", severity: "low" }).alert, true);
    assert.equal(shouldAlert({ kind: "correlation", severity: "info" }).alert, true);
  });

  test("cert event alerts only within the expiry window", () => {
    assert.equal(shouldAlert({ kind: "cert", daysToExpiry: 10 }).alert, true);
    assert.equal(shouldAlert({ kind: "cert", daysToExpiry: 60 }).alert, false);
  });

  test("a drift event (record weakened) alerts at any severity unless onDrift is off", () => {
    assert.equal(shouldAlert({ kind: "drift", severity: "low" }).alert, true);
    assert.equal(shouldAlert({ kind: "drift", severity: "low" }, { ...defaultAlertRules(), onDrift: false }).alert, false);
  });

  test("resolved is silent by default but can be enabled", () => {
    assert.equal(shouldAlert({ kind: "resolved", severity: "high" }).alert, false);
    assert.equal(shouldAlert({ kind: "resolved", severity: "high" }, { ...defaultAlertRules(), onResolved: true }).alert, true);
  });

  test("digest mode suppresses immediate delivery but records the reason", () => {
    const r = shouldAlert({ kind: "new", severity: "critical" }, { ...defaultAlertRules(), digest: true });
    assert.equal(r.alert, false);
    assert.equal(r.suppressed, true);
  });

  test("quiet hours suppress; the window wraps past midnight", () => {
    const rules = { ...defaultAlertRules(), quietHours: { startHour: 22, endHour: 6 } };
    const at = (h) => Date.UTC(2026, 0, 1, h, 0, 0);
    assert.equal(inQuietHours(at(23), rules), true);
    assert.equal(inQuietHours(at(3), rules), true);
    assert.equal(inQuietHours(at(12), rules), false);
    assert.equal(shouldAlert({ kind: "new", severity: "critical" }, rules, at(23)).suppressed, true);
    assert.equal(shouldAlert({ kind: "new", severity: "critical" }, rules, at(12)).alert, true);
  });

  test("sevRank orders severities", () => {
    assert.ok(sevRank("critical") > sevRank("high") && sevRank("high") > sevRank("low"));
  });
});
