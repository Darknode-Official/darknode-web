// Exposure score v2 (Deck D7). PURE — no DOM, no network, deterministic.
//
// One honest 0–100 number for "how exposed is this workspace right now", with its whole
// derivation returned so it is never a black box. Higher is worse. It is a function only
// of the OPEN findings in the graph (closed and risk-accepted/excepted findings do not
// count), so remediating or accepting risk always lowers it.
//
// Formula
// -------
// Each open finding contributes a weight:
//
//   weight = BASE[severity] × kevFactor × exposureFactor × ageFactor × overdueFactor × critFactor
//
//   BASE           critical 10, high 6, medium 3, low 1, info 0
//   kevFactor      ×2.0 if known-exploited (CISA KEV / data.kev), else ×1
//   exposureFactor ×1.5 if internet-facing (tag "internet-facing", data.internetFacing,
//                  or category mentioning "expos"), else ×1
//   ageFactor      ×(1 + min(ageDays,180)/180 × 0.5)  — up to ×1.5 for findings open ≥180d
//   overdueFactor  ×1.25 if past its SLA due date, else ×1
//   critFactor     asset criticality of the finding's most-critical asset:
//                  crown-jewel ×2, high ×1.5, normal ×1 (from opts.criticality, else normal)
//
// raw = Σ weight over open, non-excepted findings.
//
// The score saturates so that it is bounded and a few findings do not peg it at 100:
//
//   score = round( 100 × (1 − e^(−raw / K)) ),  K = 50
//
// K = 50 means raw≈35 → ~50, raw≈115 → ~90, raw≈150 → ~95. K is returned in the breakdown
// and is the one tunable; nothing else is hidden.

import { computeDue } from "./workflow.js";

const BASE = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };
const K = 50;
const DAY_MS = 86400000;
const str = (v) => String(v == null ? "" : v).toLowerCase();
const OPEN = new Set(["new", "open", "investigating"]);
const toMs = (v) => { if (typeof v === "number") return Number.isFinite(v) ? v : null; if (typeof v === "string" && v) { const n = Date.parse(v); return Number.isFinite(n) ? n : null; } return null; };
const CVE_RE = /CVE-\d{4}-\d{4,}/gi; // sequence is >=4 digits with NO upper bound (matches workflow.js), so an 8+ digit id is not truncated into a different, wrong CVE

function cvesOf(e) {
  const d = (e && e.data) || {}, out = new Set();
  const scan = (s) => { for (const m of String(s == null ? "" : s).match(CVE_RE) || []) out.add(m.toUpperCase()); };
  for (const v of [].concat(d.cve || [], d.cves || [])) scan(v);
  scan(e && e.name);
  return [...out];
}
function isKev(e, kevSet) {
  if (e && e.data && e.data.kev === true) return true;
  if (!kevSet) return false;
  const has = typeof kevSet.has === "function" ? (x) => kevSet.has(x) : (x) => kevSet.includes(x);
  return cvesOf(e).some(has);
}
function isExposed(e) {
  const d = (e && e.data) || {};
  if (d.internetFacing === true) return true;
  const tagList = [].concat(Array.isArray(e && e.tags) ? e.tags : [], Array.isArray(d.tags) ? d.tags : []).map(str);
  if (tagList.includes("internet-facing") || tagList.includes("internet_facing")) return true;
  return str(d.category).includes("expos");
}
function critFactor(e, criticality) {
  if (!criticality) return 1;
  const assets = Array.isArray(e && e.data && e.data.assets) ? e.data.assets : [];
  let best = 1;
  for (const a of assets) {
    const name = typeof a === "string" ? a : (a && a.name);
    const c = str(name && criticality[name]);
    if (c === "crown-jewel" || c === "crown_jewel" || c === "crownjewel") best = Math.max(best, 2);
    else if (c === "high") best = Math.max(best, 1.5);
  }
  return best;
}
const activeException = (e, now) => { const x = e && e.data && e.data.exception; const exp = x && toMs(x.expiresAt); return exp != null && exp > now; };

/**
 * exposureScore(findings, opts) -> { score, raw, k, contributing, components, top }
 * findings: FINDING entities (others are ignored). opts: { now, policy, kevSet, criticality }.
 * `components` sums the raw weight by severity; `top` lists the heaviest findings.
 */
export function exposureScore(findings, opts = {}) {
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const kevSet = opts.kevSet || null;
  const crit = opts.criticality || null;
  const list = (Array.isArray(findings) ? findings : []).filter((e) => e && str(e.type) === "finding");
  let raw = 0, contributing = 0;
  const components = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const scored = [];
  for (const e of list) {
    const sev = str(e.severity);
    if (!OPEN.has(str(e.status) || "new")) continue;
    if (activeException(e, now)) continue;
    const base = BASE[sev] || 0;
    if (base === 0) continue;
    const kev = isKev(e, kevSet) ? 2 : 1;
    const exp = isExposed(e) ? 1.5 : 1;
    const created = toMs(e.createdAt);
    const ageDays = created == null ? 0 : Math.max(0, (now - created) / DAY_MS);
    const age = 1 + Math.min(ageDays, 180) / 180 * 0.5;
    const due = computeDue(e, opts.policy, { kevSet });
    const overdue = due != null && now > due ? 1.25 : 1;
    const cf = critFactor(e, crit);
    const w = base * kev * exp * age * overdue * cf;
    raw += w; contributing++;
    components[sev] = (components[sev] || 0) + w;
    scored.push({ id: e.id, name: e.name, severity: sev, weight: Math.round(w * 100) / 100, kev: kev > 1, exposed: exp > 1, overdue: overdue > 1 });
  }
  const score = Math.round(100 * (1 - Math.exp(-raw / K)));
  for (const k of Object.keys(components)) components[k] = Math.round(components[k] * 100) / 100;
  scored.sort((a, b) => b.weight - a.weight || String(a.id).localeCompare(String(b.id)));
  return { score, raw: Math.round(raw * 100) / 100, k: K, contributing, components, top: scored.slice(0, 10) };
}

export const EXPOSURE_BASE_WEIGHTS = { ...BASE };
export const EXPOSURE_K = K;
