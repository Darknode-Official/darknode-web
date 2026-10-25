// Unit tests for public/js/core/role-home.js — the role-based home focus.
import { test, group, assert } from "../harness.mjs";
import { roleFocus, ROLE_IDS } from "../../public/js/core/role-home.js";

const DAY = 86400000, NOW = Date.parse("2026-10-18T00:00:00Z");
const F = (id, severity, ageDays, data = {}, type = "FINDING", status = "open") => ({ id, type, name: id, severity, status, createdAt: new Date(NOW - ageDays * DAY).toISOString(), data });

group("role-home/roleFocus", () => {
  test("unknown role returns null", () => {
    assert.equal(roleFocus([], { role: "nope" }), null);
  });

  test("ciso focus reports exposure, crit+high, KEV and SLA", () => {
    const r = roleFocus([
      F("a", "critical", 60, {}),                        // overdue
      F("b", "high", 1, { cves: ["CVE-2026-1"] }),       // KEV
    ], { role: "ciso", now: NOW, kevSet: new Set(["CVE-2026-1"]) });
    assert.equal(r.role, "ciso");
    const labels = r.metrics.map((m) => m.label);
    assert.ok(labels.includes("Exposure") && labels.includes("Known-exploited"));
    assert.equal(r.items[0].id, "b"); // KEV ranks first
  });

  test("analyst focus prefers my own queue", () => {
    const r = roleFocus([
      F("mine", "low", 1, { owner: "u1" }),
      F("other", "critical", 1, { owner: "u2" }),
    ], { role: "analyst", now: NOW, myUid: "u1" });
    assert.equal(r.metrics.find((m) => m.label === "My open").value, 1);
    assert.equal(r.items[0].id, "mine");
  });

  test("analyst with no owned findings falls back to newest crit/high", () => {
    const r = roleFocus([F("c", "critical", 1, {}), F("l", "low", 1, {})], { role: "analyst", now: NOW, myUid: "u1" });
    assert.equal(r.items.length, 1);
    assert.equal(r.items[0].id, "c"); // low is not a pickup candidate
  });

  test("itops focus lists overdue vulnerabilities soonest-first", () => {
    const r = roleFocus([
      F("v1", "high", 120, {}, "VULNERABILITY"),  // very overdue
      F("v2", "high", 61, {}, "VULNERABILITY"),   // just overdue
      F("note", "high", 1, { category: "identity" }), // not a vuln
    ], { role: "itops", now: NOW });
    assert.equal(r.metrics.find((m) => m.label === "Open vulnerabilities").value, 2);
    assert.equal(r.items[0].id, "v1");
  });

  test("the retired finance view is no longer a role", () => {
    assert.ok(!ROLE_IDS.includes("finance"));
    assert.equal(roleFocus([F("pay", "high", 1, { category: "payment" })], { role: "finance", now: NOW }), null);
  });

  test("closed findings are excluded and empty graph is safe", () => {
    const r = roleFocus([F("x", "high", 1, {}, "FINDING", "closed")], { role: "ciso", now: NOW });
    assert.equal(r.items.length, 0);
    assert.ok(r.emptyText);
  });

  test("every role is deterministic", () => {
    const ents = [F("a", "critical", 60, {}, "VULNERABILITY"), F("b", "high", 1, { category: "payment" })];
    for (const role of ROLE_IDS) {
      assert.equal(JSON.stringify(roleFocus(ents, { role, now: NOW })), JSON.stringify(roleFocus(ents, { role, now: NOW })));
    }
  });
});
