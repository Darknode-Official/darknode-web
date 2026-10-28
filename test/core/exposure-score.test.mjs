// Unit tests for public/js/core/exposure-score.js — the documented 0–100 exposure score.
import { test, group, assert } from "../harness.mjs";
import { exposureScore, EXPOSURE_BASE_WEIGHTS, EXPOSURE_K } from "../../public/js/core/exposure-score.js";

const NOW = Date.parse("2026-10-18T00:00:00Z");
const day = (n) => new Date(NOW - n * 86400000).toISOString();
const F = (id, severity, createdAt, data = {}, status = "open") => ({ id, type: "FINDING", name: id, severity, status, createdAt, data });

group("exposure-score/score", () => {
  test("top drivers drop the finding's internal dedupe key", () => {
    const e = Object.assign(F("f", "high", day(1), { tool: "vulnimport", findingKey: "1zx" }), { name: "TLS 1.0 enabled (vulnimport:1zx)" });
    assert.equal(exposureScore([e], { now: NOW }).top[0].name, "TLS 1.0 enabled");
  });
  test("no open findings scores 0", () => {
    assert.equal(exposureScore([]).score, 0);
    assert.equal(exposureScore([F("f", "critical", day(1), {}, "closed")], { now: NOW }).score, 0);
  });

  test("info findings never contribute", () => {
    const r = exposureScore([F("i", "info", day(1))], { now: NOW });
    assert.equal(r.raw, 0);
    assert.equal(r.score, 0);
  });

  test("score rises with severity and saturates below 100", () => {
    const one = exposureScore([F("a", "low", day(1))], { now: NOW }).score;
    const crit = exposureScore([F("b", "critical", day(1))], { now: NOW }).score;
    assert.ok(crit > one);
    const many = exposureScore(Array.from({ length: 15 }, (_, i) => F("x" + i, "critical", day(1))), { now: NOW }).score;
    assert.ok(many > 90 && many <= 100);
  });

  test("excepted (risk-accepted) findings are excluded", () => {
    const base = exposureScore([F("a", "critical", day(1))], { now: NOW }).score;
    const excepted = exposureScore([F("a", "critical", day(1), { exception: { expiresAt: new Date(NOW + 86400000).toISOString() } })], { now: NOW }).score;
    assert.equal(excepted, 0);
    assert.ok(base > 0);
  });

  test("KEV doubles a finding's weight", () => {
    const plain = exposureScore([F("a", "high", day(1))], { now: NOW }).raw;
    const kev = exposureScore([F("a", "high", day(1), { kev: true })], { now: NOW }).raw;
    assert.ok(kev > plain * 1.95 && kev < plain * 2.05);
  });

  test("overdue uses the computed SLA date, not only a stored one", () => {
    const fresh = exposureScore([F("a", "critical", day(1))], { now: NOW });
    const overdue = exposureScore([F("a", "critical", day(40))], { now: NOW }); // >30d critical SLA
    assert.equal(overdue.top[0].overdue, true);
    assert.equal(fresh.top[0].overdue, false);
  });

  test("crown-jewel criticality raises the weight", () => {
    const f = F("a", "high", day(1), { assets: [{ type: "ASSET", name: "db1" }] });
    const normal = exposureScore([f], { now: NOW }).raw;
    const crown = exposureScore([f], { now: NOW, criticality: { db1: "crown-jewel" } }).raw;
    assert.ok(crown > normal * 1.95 && crown < normal * 2.05);
  });

  test("breakdown exposes raw, k and per-severity components (not a black box)", () => {
    const r = exposureScore([F("a", "critical", day(1)), F("b", "high", day(1))], { now: NOW });
    assert.equal(r.k, EXPOSURE_K);
    assert.ok(r.components.critical > 0 && r.components.high > 0);
    assert.equal(EXPOSURE_BASE_WEIGHTS.critical, 10);
  });

  test("is deterministic", () => {
    const ents = [F("a", "critical", day(40), { kev: true }), F("b", "high", day(5), { tags: ["internet-facing"] })];
    assert.equal(JSON.stringify(exposureScore(ents, { now: NOW })), JSON.stringify(exposureScore(ents, { now: NOW })));
  });

  test("an 8+ digit CVE id is matched against KEV without truncation", () => {
    const cve = "CVE-2021-12345678"; // the old /CVE-\d{4}-\d{4,7}/ truncated this to a different, wrong id
    const r = exposureScore([F("f", "high", day(1), { cve })], { now: NOW, kevSet: new Set([cve]) });
    assert.ok(r.top[0] && r.top[0].kev === true, "KEV x2 weight applied to the full 8-digit CVE");
  });
});
