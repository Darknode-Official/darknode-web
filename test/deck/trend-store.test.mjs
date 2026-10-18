// Unit tests for public/js/deck/trend-store.js — the per-workspace daily trend store.
import { test, group, assert } from "../harness.mjs";
import { compact, recordSnapshot, readTrend, baselineBefore, TREND_CAP } from "../../public/js/deck/trend-store.js";

// in-memory storage shim (getItem/setItem)
function mem() { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, v), _m: m }; }
const snap = (day, over = {}) => ({ day, ts: Date.parse(day + "T00:00:00Z"), open: 5, closed: 2, exposureScore: 40, slaCompliancePct: 80, mttrDays: 9, kevOpen: 1, bySeverity: { critical: 1, high: 2, medium: 1, low: 1, info: 0 }, ...over });

group("trend-store", () => {
  test("compact keeps only the small charted subset", () => {
    const c = compact(snap("2026-10-18"));
    assert.deepEqual(Object.keys(c).sort(), ["closed", "critical", "day", "exposureScore", "high", "info", "kevOpen", "low", "medium", "mttrDays", "open", "slaCompliancePct", "ts"].sort());
    assert.equal(c.critical, 1);
  });

  test("records one row per day, oldest first", () => {
    const st = mem();
    recordSnapshot("w1", snap("2026-10-16"), st);
    recordSnapshot("w1", snap("2026-10-17"), st);
    const series = readTrend("w1", st);
    assert.equal(series.length, 2);
    assert.equal(series[0].day, "2026-10-16");
  });

  test("today's row is overwritten, not appended", () => {
    const st = mem();
    recordSnapshot("w1", snap("2026-10-18", { open: 5 }), st);
    recordSnapshot("w1", snap("2026-10-18", { open: 3 }), st);
    const series = readTrend("w1", st);
    assert.equal(series.length, 1);
    assert.equal(series[0].open, 3);
  });

  test("workspaces are isolated", () => {
    const st = mem();
    recordSnapshot("w1", snap("2026-10-18"), st);
    recordSnapshot("w2", snap("2026-10-18"), st);
    recordSnapshot("w2", snap("2026-10-17"), st);
    assert.equal(readTrend("w1", st).length, 1);
    assert.equal(readTrend("w2", st).length, 2);
  });

  test("history is capped at TREND_CAP days", () => {
    const st = mem();
    for (let i = 0; i < TREND_CAP + 25; i++) { const d = new Date(Date.parse("2026-01-01T00:00:00Z") + i * 86400000).toISOString().slice(0, 10); recordSnapshot("w1", snap(d), st); }
    const series = readTrend("w1", st);
    assert.equal(series.length, TREND_CAP);
  });

  test("baselineBefore finds the newest row at or before a day", () => {
    const st = mem();
    recordSnapshot("w1", snap("2026-07-01"), st);
    recordSnapshot("w1", snap("2026-08-15"), st);
    recordSnapshot("w1", snap("2026-10-18"), st);
    assert.equal(baselineBefore("w1", "2026-09-01", st).day, "2026-08-15");
    assert.equal(baselineBefore("w1", "2026-06-01", st), null);
  });

  test("corrupt or missing storage never throws", () => {
    const bad = { getItem: () => "{not json", setItem: () => { throw new Error("quota"); } };
    assert.deepEqual(readTrend("w1", bad), []);        // corrupt read -> empty
    const out = recordSnapshot("w1", snap("2026-10-18"), bad); // save throws but is swallowed
    assert.equal(out.length, 1);                       // caller still gets the computed series
  });
});
