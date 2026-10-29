// Per-workspace daily trend store (Deck D7). Keeps one compact metrics snapshot per day
// so the Overview sparkline and the board report can show real movement over time — not a
// fabricated series. Today's row is overwritten as the graph recomputes; past days are
// immutable history. Persistence is localStorage (per viewer, per workspace); a later
// server cron can write the same snapshots into GraphDO meta for cross-device history.
//
// PURE given a storage object: every function takes an optional `storage` (default
// localStorage) with getItem/setItem, so the logic is node-testable without a browser.

const CAP = 180;                 // days of history kept
// Personal history is per signed-in account (window.__dnUid; guests and Test Mode share one
// guest series), matching the personal security-graph store, since localStorage is shared by
// every account on the browser. The old unscoped dn_deck_trend key is no longer used.
const _scope = () => { let u = null; try { u = globalThis.__dnUid || null; } catch (_) {} return !u ? "nouser" : /^(test|app-guest)-/.test(u) ? "guest" : "u_" + u; };
const KEY = (wid) => (wid ? "dn_deck_trend__ws_" + wid : "dn_deck_trend__" + _scope());

// The small subset charted/reported. The full snapshot (with top contributors) is not
// stored — history stays tiny and never holds finding detail.
export function compact(snap) {
  if (!snap || typeof snap !== "object") return null;
  const s = snap.bySeverity || {};
  return {
    day: snap.day || new Date(snap.ts || Date.now()).toISOString().slice(0, 10),
    ts: snap.ts || Date.now(),
    open: snap.open || 0,
    closed: snap.closed || 0,
    exposureScore: snap.exposureScore || 0,
    slaCompliancePct: snap.slaCompliancePct == null ? null : snap.slaCompliancePct,
    mttrDays: snap.mttrDays == null ? null : snap.mttrDays,
    kevOpen: snap.kevOpen || 0,
    critical: s.critical || 0, high: s.high || 0, medium: s.medium || 0, low: s.low || 0, info: s.info || 0,
  };
}

function store() { try { return typeof localStorage !== "undefined" ? localStorage : null; } catch (_) { return null; } }
function read(st, wid) {
  const s = st || store(); if (!s) return [];
  try { const raw = s.getItem(KEY(wid)); const a = raw ? JSON.parse(raw) : []; return Array.isArray(a) ? a : []; } catch (_) { return []; }
}

// Record (or overwrite today's) snapshot. Returns the stored series, oldest first.
export function recordSnapshot(wid, snap, st) {
  const row = compact(snap); if (!row) return read(st, wid);
  const s = st || store();
  let series = read(s, wid).filter((r) => r && r.day !== row.day);
  series.push(row);
  series.sort((a, b) => String(a.day).localeCompare(String(b.day)));
  if (series.length > CAP) series = series.slice(series.length - CAP);
  if (s) { try { s.setItem(KEY(wid), JSON.stringify(series)); } catch (_) {} }
  return series;
}

// The stored series, oldest first.
export function readTrend(wid, st) { return read(st, wid); }

// The most recent row at or before `beforeDay` (ISO yyyy-mm-dd) — for a quarter-over-quarter
// baseline. Returns null if the history does not reach that far back.
export function baselineBefore(wid, beforeDay, st) {
  const series = read(st, wid);
  let best = null;
  for (const r of series) if (r && r.day <= beforeDay) { if (!best || r.day > best.day) best = r; }
  return best;
}

export const TREND_CAP = CAP;
