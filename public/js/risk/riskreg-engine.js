// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Risk Register engine (riskreg). Pure: no DOM, no network, no clock. Runs in a
// Blob module Worker and in node tests. Same input -> byte-identical JSON.
//
// What it does: takes the risk records a team keeps in its register (ranges the
// risk owner entered) and runs an Open FAIR-style Monte Carlo over them. It is a
// model of the ranges entered, not a prediction; it ships no loss figures and no
// industry benchmarks.
//
// Model (documented so a reviewer can reproduce it):
//   * PRNG: mulberry32, seeded per risk with fnv1a32(seed + "|" + risk id), so a
//     risk's numbers do not change when other risks are added or reordered.
//     Inherent and residual runs of one risk reuse the same stream (common
//     random numbers), so the difference between them is not sampling noise.
//   * Ranges (min / most likely / max) are beta-PERT with lambda = 4:
//     alpha = 1 + 4 (ml - min) / (max - min), beta = 1 + 4 (max - ml) / (max - min),
//     mean = (min + 4 ml + max) / 6. Beta draws use two Marsaglia-Tsang gamma draws.
//   * Frequency: each simulated year draws an annual rate from the PERT of the
//     Loss Event Frequency range (or TEF range x Vulnerability range), then the
//     number of loss events from Poisson(rate) (Knuth for rate < 30, normal
//     approximation rounded at >= 30).
//   * Each loss event costs PERT(primary magnitude) plus, with the secondary loss
//     probability, PERT(secondary magnitude). Annual loss = sum over events.
//   * Portfolio: per-iteration sum of every open risk's simulated annual loss,
//     per currency (mixed currencies are never summed). Risks are treated as
//     independent; correlated risks will be understated in the tail.
//
// Control references used in findings:
//   ISO/IEC 27001:2022 clauses 6.1.2 (risk assessment, incl. 6.1.2 c) 2) risk
//   owners), 6.1.3 (risk treatment, incl. f) owner approval / acceptance of
//   residual risk), 8.2 (risk assessment at planned intervals), 8.3 (risk
//   treatment); ISO/IEC 27005:2022 (risk treatment, monitoring and review);
//   NIST SP 800-30 Rev. 1 (Step 4: maintain the assessment); NIST CSF 2.0
//   GV.RM-02 (risk appetite and tolerance), GV.RR-02 (roles and responsibilities),
//   ID.RA-05 (likelihood and impact inform inherent risk), ID.RA-06 (risk
//   responses chosen, tracked, communicated); Open FAIR (The Open Group O-RT
//   risk taxonomy and O-RA risk analysis standards).

import { sniff, parseCsv, iterJson, findColumn } from "../ingest/parse.js";

export const TOOL_ID = "riskreg";
export const VERSION = "1.0.0";
const DAY = 86400000;

export const CATEGORIES = ["cyber", "third-party", "operational", "compliance", "financial", "physical"];
export const STATUSES = ["identified", "assessed", "treating", "accepted", "closed"];
export const TREATMENTS = ["mitigate", "transfer", "avoid", "accept"];
export const PERCENTILES = [10, 50, 90, 95, 99];
export const MAX_ITERATIONS = 100000;
export const HISTORY_CAP = 50;
export const LEC_POINTS = 60;
export const HIST_BINS = 24;
export const MODEL_NOTE = "Model of the ranges you entered, not a prediction.";

/** Engine options. Money settings ship empty on purpose: the user sets them. */
export const DEFAULTS = {
  iterations: 10000,
  seed: 1,
  currency: "USD",
  appetiteAmount: null, // annual loss amount, in `currency`
  appetitePercentile: 90, // compared against this percentile of a risk's annual loss
  staleDays: 365, // last review older than this is stale
  freqBands: [], // 4 ascending edges, events per year -> 5 likelihood bands
  magBands: [], // 4 ascending edges, loss per event in `currency` -> 5 impact bands
};

const R3 = ["min", "ml", "max"];
const RANGE_FIELDS = ["lef", "tef", "vuln", "plm", "slm"];
const RANGE_LABEL = { lef: "Loss event frequency", tef: "Threat event frequency", vuln: "Vulnerability", plm: "Primary loss magnitude", slm: "Secondary loss magnitude" };
const CANON_RANGE = { lef: "lef", tef: "tef", vuln: "vuln", plm: "plm", slm: "slm" };
const PART = { min: "min", ml: "likely", max: "max" };

// ---------------------------------------------------------------------------
// CSV columns: canonical header -> accepted aliases (case/spacing-insensitive)
// ---------------------------------------------------------------------------

function rangeAliases(key, words) {
  const out = {};
  for (const p of R3) {
    const part = PART[p];
    const extra = p === "ml" ? ["most likely", "ml", "mode", "likely"] : [p === "min" ? "minimum" : "maximum", p === "min" ? "low" : "high"];
    out[key + "_" + part] = [key + "_" + part, key + " " + part, ...words.flatMap((w) => [w + " " + part, ...extra.map((e) => w + " " + e)])];
  }
  return out;
}

/** Canonical CSV header -> aliases. The register CSV export uses the canonical names. */
export const COLUMNS = {
  id: ["id", "risk id", "ref", "reference"],
  title: ["title", "risk", "risk title", "risk name", "name"],
  scenario: ["scenario", "risk scenario", "description", "loss scenario"],
  assets: ["assets", "asset", "affected assets"],
  category: ["category", "risk category", "type"],
  owner: ["owner", "risk owner", "accountable"],
  status: ["status", "risk status", "state"],
  currency: ["currency", "ccy"],
  freq_mode: ["freq_mode", "frequency mode"],
  ...rangeAliases("lef", ["loss event frequency", "lef", "frequency", "events per year"]),
  ...rangeAliases("tef", ["threat event frequency", "tef"]),
  ...rangeAliases("vuln", ["vulnerability", "vuln", "susceptibility"]),
  ...rangeAliases("plm", ["primary loss", "primary loss magnitude", "plm", "loss", "impact"]),
  slp: ["slp", "secondary loss probability", "secondary probability"],
  ...rangeAliases("slm", ["secondary loss", "secondary loss magnitude", "slm"]),
  controls: ["controls", "controls in place", "existing controls"],
  control_refs: ["control_refs", "control ids", "control references"],
  treatment: ["treatment", "response", "risk response", "treatment option"],
  treatment_cost: ["treatment_cost", "treatment cost", "treatment cost per year", "annual cost", "cost"],
  residual_in_effect: ["residual_in_effect", "treatment implemented", "residual in effect"],
  ...rangeAliases("res_lef", ["residual lef", "residual loss event frequency", "residual frequency"]),
  ...rangeAliases("res_tef", ["residual tef", "residual threat event frequency"]),
  ...rangeAliases("res_vuln", ["residual vulnerability", "residual vuln"]),
  ...rangeAliases("res_plm", ["residual primary loss", "residual plm", "residual loss"]),
  res_slp: ["res_slp", "residual slp", "residual secondary loss probability"],
  ...rangeAliases("res_slm", ["residual secondary loss", "residual slm"]),
  acceptance_note: ["acceptance_note", "acceptance note", "acceptance rationale", "risk acceptance"],
  linked_findings: ["linked_findings", "linked findings", "findings"],
  review_date: ["review_date", "review date", "next review", "review due", "due date"],
  last_reviewed: ["last_reviewed", "last reviewed", "last review", "assessed on", "assessment date"],
  notes: ["notes", "comments", "comment"],
};
export const CANON_HEADERS = Object.keys(COLUMNS);

// ---------------------------------------------------------------------------
// Number helpers
// ---------------------------------------------------------------------------

const r2 = (x) => (Number.isFinite(x) ? Math.round(x * 100) / 100 : null);
const r4 = (x) => (Number.isFinite(x) ? Math.round(x * 10000) / 10000 : null);
const str = (v) => (v == null ? "" : String(v));

/** Parse a user number: "1,200,000", "$1.2M", "250k", "30%" (-> 0.3 when pct). Empty -> null. */
export function parseNum(v, { pct = false } = {}) {
  if (v == null) return null;
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  let s = String(v).trim();
  if (!s) return null;
  let isPct = false;
  if (s.endsWith("%")) { isPct = true; s = s.slice(0, -1); }
  s = s.replace(/[\s,_]/g, "").replace(/^[^\d.+-]+/, "").replace(/(usd|eur|gbp|inr|aud|cad|jpy|chf)$/i, "");
  const m = /^([+-]?(?:\d+(?:\.\d+)?|\.\d+)(?:e[+-]?\d+)?)([kmb])?$/i.exec(s); // one way to split the digits: \d*\.?\d+ was quadratic on a long digit run
  if (!m) return null;
  let n = Number(m[1]);
  const suf = (m[2] || "").toLowerCase();
  if (suf === "k") n *= 1e3; else if (suf === "m") n *= 1e6; else if (suf === "b") n *= 1e9;
  if (isPct || (pct && n > 1 && n <= 100 && /%/.test(String(v)))) n /= 100;
  return Number.isFinite(n) ? n : null;
}

function normRange(r) {
  const o = r && typeof r === "object" ? r : {};
  return { min: parseNum(o.min), ml: parseNum(o.ml != null ? o.ml : o.likely), max: parseNum(o.max) };
}
const rangeSet = (r) => !!r && R3.every((k) => Number.isFinite(r[k]));
const rangeAny = (r) => !!r && R3.some((k) => r[k] != null);

/** beta-PERT mean (min + 4 ml + max) / 6. */
export const pertMean = (r) => (r.min + 4 * r.ml + r.max) / 6;

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

const RESIDUAL_KEYS = ["freqMode", "lef", "tef", "vuln", "plm", "slp", "slm"];

/** Coerce a raw object (form, JSON, CSV row) into a register record. Never throws. */
export function normalizeRecord(raw) {
  const r = raw && typeof raw === "object" ? raw : {};
  const lef = normRange(r.lef), tef = normRange(r.tef), vuln = normRange(r.vuln);
  const freqMode = r.freqMode === "tef" || r.freqMode === "lef" ? r.freqMode : (!rangeAny(lef) && rangeAny(tef) ? "tef" : "lef");
  const res = r.residual && typeof r.residual === "object" ? r.residual : {};
  const residual = {
    freqMode: res.freqMode === "tef" || res.freqMode === "lef" ? res.freqMode : "",
    lef: normRange(res.lef), tef: normRange(res.tef), vuln: normRange(res.vuln), plm: normRange(res.plm),
    slp: parseNum(res.slp), slm: normRange(res.slm),
  };
  const arr = (v) => (Array.isArray(v) ? v : str(v).split(/[;|\n]/)).map((x) => (typeof x === "string" ? x.trim() : x)).filter((x) => x !== "" && x != null);
  const out = {
    id: str(r.id).trim() || undefined,
    title: str(r.title).trim(),
    scenario: str(r.scenario).trim(),
    assets: str(r.assets).trim(),
    assetRefs: (Array.isArray(r.assetRefs) ? r.assetRefs : []).filter((a) => a && a.name).map((a) => ({ id: str(a.id), type: str(a.type || "ASSET").toUpperCase(), name: str(a.name) })),
    category: str(r.category).trim().toLowerCase().replace(/[\s_]+/g, "-") || "cyber",
    owner: str(r.owner).trim(),
    status: str(r.status).trim().toLowerCase() || "identified",
    currency: str(r.currency).trim().toUpperCase(),
    freqMode, lef, tef, vuln,
    plm: normRange(r.plm), slp: parseNum(r.slp), slm: normRange(r.slm),
    controls: str(r.controls).trim(),
    controlRefs: arr(r.controlRefs).map(String),
    treatment: str(r.treatment).trim().toLowerCase(),
    treatmentCost: parseNum(r.treatmentCost),
    residualInEffect: r.residualInEffect === true || /^(true|yes|y|1)$/i.test(str(r.residualInEffect)),
    residual,
    acceptanceNote: str(r.acceptanceNote).trim(),
    linkedFindings: arr(r.linkedFindings).map(String),
    reviewDate: str(r.reviewDate).trim().slice(0, 10),
    lastReviewed: str(r.lastReviewed).trim().slice(0, 10),
    notes: str(r.notes),
    history: (Array.isArray(r.history) ? r.history : []).filter((h) => h && typeof h === "object").slice(-HISTORY_CAP),
  };
  for (const k of ["createdAt", "updatedAt", "graphId", "snapshot"]) if (r[k] != null) out[k] = r[k];
  if (out.id === undefined) delete out.id;
  return out;
}

/** True when any residual value was entered. */
export function hasResidual(rec) {
  const s = rec && rec.residual;
  if (!s) return false;
  return RANGE_FIELDS.some((k) => rangeAny(s[k])) || s.slp != null;
}

/** Inherent spec merged with residual overrides (blank residual ranges inherit). */
function residualSpec(rec) {
  const s = rec.residual || {};
  const out = { freqMode: s.freqMode || rec.freqMode };
  for (const k of RANGE_FIELDS) out[k] = rangeAny(s[k]) ? s[k] : rec[k];
  out.slp = s.slp != null ? s.slp : rec.slp;
  return out;
}

const isDate = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s) && Number.isFinite(Date.parse(s + "T00:00:00Z"));

function checkRange(errs, spec, key, prefix, { prob = false, required = true } = {}) {
  const r = spec[key];
  const label = (prefix ? "Residual " + RANGE_LABEL[key].toLowerCase() : RANGE_LABEL[key]);
  if (!rangeAny(r)) { if (required) errs.push({ field: (prefix || "") + key, message: label + ": enter min, most likely and max" }); return; }
  if (!rangeSet(r)) { errs.push({ field: (prefix || "") + key, message: label + ": all three values are needed" }); return; }
  if (r.min < 0) errs.push({ field: (prefix || "") + key, message: label + ": values cannot be negative" });
  if (!(r.min <= r.ml && r.ml <= r.max)) errs.push({ field: (prefix || "") + key, message: label + ": needs min <= most likely <= max" });
  if (prob && (r.min < 0 || r.max > 1)) errs.push({ field: (prefix || "") + key, message: label + ": probabilities must be between 0 and 1" });
}

function checkSpec(errs, spec, prefix) {
  if (spec.freqMode === "tef") {
    checkRange(errs, spec, "tef", prefix);
    checkRange(errs, spec, "vuln", prefix, { prob: true });
  } else checkRange(errs, spec, "lef", prefix);
  checkRange(errs, spec, "plm", prefix);
  if (spec.slp != null && (!(spec.slp >= 0) || spec.slp > 1)) errs.push({ field: (prefix || "") + "slp", message: (prefix ? "Residual s" : "S") + "econdary loss probability must be between 0 and 1" });
  if (spec.slp > 0) checkRange(errs, spec, "slm", prefix);
  else if (rangeAny(spec.slm)) checkRange(errs, spec, "slm", prefix, { required: false });
}

/** Validation: [{ field, message }]; empty array means the record can be simulated. */
export function validateRisk(raw) {
  const rec = normalizeRecord(raw);
  const errs = [];
  if (!rec.title) errs.push({ field: "title", message: "Title is required" });
  if (!CATEGORIES.includes(rec.category)) errs.push({ field: "category", message: "Category must be one of " + CATEGORIES.join(", ") });
  if (!STATUSES.includes(rec.status)) errs.push({ field: "status", message: "Status must be one of " + STATUSES.join(", ") });
  if (rec.treatment && !TREATMENTS.includes(rec.treatment)) errs.push({ field: "treatment", message: "Treatment must be one of " + TREATMENTS.join(", ") });
  if (rec.currency && !/^[A-Z]{3}$/.test(rec.currency)) errs.push({ field: "currency", message: "Currency must be a 3-letter ISO 4217 code" });
  checkSpec(errs, rec, "");
  if (hasResidual(rec)) {
    const s = rec.residual;
    for (const k of RANGE_FIELDS) if (rangeAny(s[k])) checkRange(errs, { [k]: s[k] }, k, "res_", { prob: k === "vuln" });
    if (s.slp != null && (!(s.slp >= 0) || s.slp > 1)) errs.push({ field: "res_slp", message: "Residual secondary loss probability must be between 0 and 1" });
    if (s.freqMode === "tef" && rec.freqMode !== "tef" && !(rangeSet(s.tef) && rangeSet(s.vuln))) errs.push({ field: "res_tef", message: "Residual TEF x vulnerability needs both ranges" });
  }
  if (rec.treatmentCost != null && rec.treatmentCost < 0) errs.push({ field: "treatmentCost", message: "Treatment cost cannot be negative" });
  if (rec.reviewDate && !isDate(rec.reviewDate)) errs.push({ field: "reviewDate", message: "Review date must be YYYY-MM-DD" });
  if (rec.lastReviewed && !isDate(rec.lastReviewed)) errs.push({ field: "lastReviewed", message: "Last reviewed must be YYYY-MM-DD" });
  return errs;
}

// ---------------------------------------------------------------------------
// PRNG and samplers
// ---------------------------------------------------------------------------

/** mulberry32: 32-bit seeded PRNG returning floats in [0, 1). */
export function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** FNV-1a 32-bit hash of a string (stream seeding). */
export function fnv1a32(s) {
  let h = 0x811c9dc5;
  const t = String(s);
  for (let i = 0; i < t.length; i++) { h ^= t.charCodeAt(i); h = Math.imul(h, 0x01000193); }
  return h >>> 0;
}

/** Normal(0,1) generator over a uniform source (Box-Muller, caches the pair). */
function normalGen(rng) {
  let spare = null;
  return () => {
    if (spare !== null) { const s = spare; spare = null; return s; }
    let u = 0;
    while (u <= 1e-300) u = rng();
    const v = rng();
    const m = Math.sqrt(-2 * Math.log(u));
    spare = m * Math.sin(2 * Math.PI * v);
    return m * Math.cos(2 * Math.PI * v);
  };
}

/** Gamma(shape >= 1, 1) via Marsaglia-Tsang. */
function gammaGen(shape, rng, norm) {
  const d = shape - 1 / 3, c = 1 / Math.sqrt(9 * d);
  return () => {
    for (;;) {
      let x, v;
      do { x = norm(); v = 1 + c * x; } while (v <= 0);
      v = v * v * v;
      const u = rng();
      const x2 = x * x;
      if (u < 1 - 0.0331 * x2 * x2) return d * v;
      if (Math.log(u) < 0.5 * x2 + d * (1 - v + Math.log(v))) return d * v;
    }
  };
}

/**
 * beta-PERT sampler (lambda 4) for a validated range. Degenerate ranges return
 * the constant. Returns () => number.
 */
export function makePert(range, rng, norm = normalGen(rng), lambda = 4) {
  const { min, ml, max } = range;
  if (!(max > min)) { const k = min; return () => k; }
  const span = max - min;
  const a = 1 + lambda * (ml - min) / span, b = 1 + lambda * (max - ml) / span;
  const ga = gammaGen(a, rng, norm), gb = gammaGen(b, rng, norm);
  return () => { const x = ga(), y = gb(); return min + span * (x / (x + y)); };
}

/** Poisson(lambda) count: Knuth for lambda < 30, rounded normal approximation above. */
export function samplePoisson(lambda, rng, norm) {
  if (!(lambda > 0)) return 0;
  if (lambda < 30) {
    const L = Math.exp(-lambda);
    let k = 0, p = 1;
    do { k++; p *= rng(); } while (p > L);
    return k - 1;
  }
  return Math.max(0, Math.round(lambda + Math.sqrt(lambda) * norm()));
}

function buildSampler(spec, rng, norm) {
  let rate;
  if (spec.freqMode === "tef") {
    const t = makePert(spec.tef, rng, norm), v = makePert(spec.vuln, rng, norm);
    rate = () => t() * v();
  } else rate = makePert(spec.lef, rng, norm);
  const pl = makePert(spec.plm, rng, norm);
  const slp = spec.slp > 0 ? spec.slp : 0;
  const sl = slp > 0 ? makePert(spec.slm, rng, norm) : null;
  return { rate, loss: () => pl() + (sl && rng() < slp ? sl() : 0) };
}

/**
 * Simulate one spec. Returns { losses: Float64Array, events: Float64Array } of
 * length `iterations` (events = loss events per simulated year).
 */
export function simulateSpec(spec, iterations, seed) {
  const rng = mulberry32(seed);
  const norm = normalGen(rng);
  const s = buildSampler(spec, rng, norm);
  const losses = new Float64Array(iterations), events = new Float64Array(iterations);
  for (let i = 0; i < iterations; i++) {
    const n = samplePoisson(s.rate(), rng, norm);
    let total = 0;
    for (let k = 0; k < n; k++) total += s.loss();
    losses[i] = total; events[i] = n;
  }
  return { losses, events };
}

const clampIter = (n) => Math.max(1, Math.min(MAX_ITERATIONS, Math.floor(Number(n) || DEFAULTS.iterations)));
const riskSeed = (seed, rec, i) => fnv1a32((seed >>> 0) + "|" + (rec.id || "#" + i));

/** Inherent (+ residual when entered) simulations of one record. Invalid -> null. */
export function simulateRisk(raw, opts = {}, index = 0) {
  const rec = normalizeRecord(raw);
  if (validateRisk(rec).length) return null;
  const it = clampIter(opts.iterations), seed = riskSeed(opts.seed == null ? DEFAULTS.seed : opts.seed, rec, index);
  const inherent = simulateSpec(rec, it, seed);
  const residual = hasResidual(rec) ? simulateSpec(residualSpec(rec), it, seed) : null;
  const current = residual && rec.residualInEffect ? residual : inherent;
  return { inherent, residual, current };
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/** Linear-interpolated quantile (type 7) of an ascending-sorted array, p in [0,1]. */
export function quantileSorted(sorted, p) {
  const n = sorted.length;
  if (!n) return null;
  const h = (n - 1) * Math.min(1, Math.max(0, p));
  const lo = Math.floor(h), hi = Math.ceil(h);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (h - lo);
}

const sortedCopy = (a) => Float64Array.from(a).sort();

// first index with sorted[i] > x
function upperBound(sorted, x) {
  let lo = 0, hi = sorted.length;
  while (lo < hi) { const m = (lo + hi) >>> 1; if (sorted[m] > x) hi = m; else lo = m + 1; }
  return lo;
}

/** Summary stats of simulated annual losses (and events when given). */
export function lossStats(losses, events, sorted = sortedCopy(losses)) {
  const n = losses.length;
  let sum = 0, sq = 0, anyN = 0, ev = 0;
  for (let i = 0; i < n; i++) { const x = losses[i]; sum += x; sq += x * x; }
  if (events) for (let i = 0; i < n; i++) { ev += events[i]; if (events[i] > 0) anyN++; }
  else for (let i = 0; i < n; i++) if (losses[i] > 0) anyN++;
  const mean = n ? sum / n : 0;
  const out = { mean: r2(mean), sd: r2(n > 1 ? Math.sqrt(Math.max(0, (sq - n * mean * mean) / (n - 1))) : 0) };
  for (const p of PERCENTILES) out["p" + p] = r2(quantileSorted(sorted, p / 100));
  out.max = r2(n ? sorted[n - 1] : 0);
  out.pAny = r4(n ? anyN / n : 0);
  if (events) { out.meanEvents = r4(n ? ev / n : 0); out.meanLossPerEvent = r2(ev ? sum / ev : 0); }
  return out;
}

/** Log-spaced x grid (>= 50 points) spanning the positive losses of the given sorted arrays. */
export function lecGrid(sortedArrays, points = LEC_POINTS) {
  let lo = Infinity, hi = 0;
  for (const s of sortedArrays) {
    if (!s || !s.length) continue;
    const i = upperBound(s, 0);
    if (i < s.length) { lo = Math.min(lo, s[i]); hi = Math.max(hi, s[s.length - 1]); }
  }
  if (!Number.isFinite(lo) || !(hi > 0)) return [];
  if (!(hi > lo)) { lo = lo / 2; hi = hi * 2; }
  lo = Math.max(lo, hi / 1e7);
  const a = Math.log10(lo), b = Math.log10(hi), n = Math.max(50, points);
  const out = [];
  for (let i = 0; i < n; i++) out.push(Math.pow(10, a + (b - a) * i / (n - 1)));
  return out;
}

/** P(annual loss > x) for each x of the grid. */
export function exceedance(sorted, grid) {
  const n = sorted.length;
  return grid.map((x) => r4(n ? (n - upperBound(sorted, x)) / n : 0));
}

/** Histogram over (0, P99]: { edges, counts, zero, over }. */
export function histogram(sorted, bins = HIST_BINS) {
  const n = sorted.length;
  const zeroN = upperBound(sorted, 0);
  const top = quantileSorted(sorted, 0.99) || 0;
  if (!(top > 0)) return { edges: [], counts: [], zero: zeroN, over: n - zeroN };
  const w = top / bins;
  const edges = [], counts = new Array(bins).fill(0);
  for (let i = 0; i <= bins; i++) edges.push(r2(w * i));
  let over = 0;
  for (let i = zeroN; i < n; i++) {
    const x = sorted[i];
    if (x > top) { over++; continue; }
    counts[Math.min(bins - 1, Math.floor(x / w - 1e-12))]++;
  }
  return { edges, counts, zero: zeroN, over };
}

/** Treatment ROI = (ALE_inherent - ALE_residual - cost) / cost; ROSI (Sonnenreich) = (ALE x mitigation ratio - cost) / cost. */
export function treatmentEconomics(aleInherent, aleResidual, cost, p90Inherent, p90Residual) {
  const reduction = aleInherent - aleResidual;
  const ratio = aleInherent > 0 ? reduction / aleInherent : null;
  const c = Number.isFinite(cost) && cost > 0 ? cost : null;
  return {
    cost: Number.isFinite(cost) ? r2(cost) : null,
    aleReduction: r2(reduction),
    mitigationRatio: r4(ratio),
    netBenefit: c != null ? r2(reduction - c) : null,
    roi: c != null ? r4((reduction - c) / c) : null,
    rosi: c != null && ratio != null ? r4((aleInherent * ratio - c) / c) : null,
    p90Reduction: Number.isFinite(p90Inherent) && Number.isFinite(p90Residual) ? r2(p90Inherent - p90Residual) : null,
  };
}

// ---------------------------------------------------------------------------
// Settings, bands, heatmap
// ---------------------------------------------------------------------------

/** Merge dataset settings with opts into one validated settings object. */
export function normalizeSettings(...srcs) {
  const s = { ...DEFAULTS };
  for (const src of srcs) {
    if (!src || typeof src !== "object") continue;
    for (const k of Object.keys(DEFAULTS)) if (src[k] !== undefined && src[k] !== "") s[k] = src[k];
  }
  s.iterations = clampIter(s.iterations);
  s.seed = Math.floor(Number(s.seed)) >>> 0;
  s.currency = str(s.currency).trim().toUpperCase() || "USD";
  s.appetiteAmount = parseNum(s.appetiteAmount);
  const pc = Number(s.appetitePercentile);
  s.appetitePercentile = Number.isFinite(pc) && pc >= 50 && pc <= 99.9 ? pc : 90;
  s.staleDays = Number(s.staleDays) > 0 ? Number(s.staleDays) : 365;
  const edges = (v) => (Array.isArray(v) ? v : str(v).split(/[,;\s]+/)).map((x) => parseNum(x)).filter((x) => x != null);
  s.freqBands = edges(s.freqBands);
  s.magBands = edges(s.magBands);
  return s;
}

/** Band edges are usable when there are exactly 4 strictly ascending non-negative numbers. */
export function bandsValid(edges) {
  return Array.isArray(edges) && edges.length === 4 && edges.every((x, i) => Number.isFinite(x) && x >= 0 && (i === 0 || x > edges[i - 1]));
}
const bandOf = (edges, v) => { let b = 0; for (const e of edges) if (v >= e) b++; return b; };

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

const C = {
  iso612: { framework: "ISO/IEC 27001:2022", id: "6.1.2" },
  iso613: { framework: "ISO/IEC 27001:2022", id: "6.1.3" },
  iso82: { framework: "ISO/IEC 27001:2022", id: "8.2" },
  iso83: { framework: "ISO/IEC 27001:2022", id: "8.3" },
  i27005t: { framework: "ISO/IEC 27005:2022", id: "Risk treatment" },
  i27005m: { framework: "ISO/IEC 27005:2022", id: "Monitoring and review" },
  sp80030: { framework: "NIST SP 800-30 Rev. 1", id: "Step 4 (maintain the assessment)" },
  gvrm02: { framework: "NIST CSF 2.0", id: "GV.RM-02" },
  gvrr02: { framework: "NIST CSF 2.0", id: "GV.RR-02" },
  idra05: { framework: "NIST CSF 2.0", id: "ID.RA-05" },
  idra06: { framework: "NIST CSF 2.0", id: "ID.RA-06" },
  ora: { framework: "Open FAIR", id: "O-RA (risk analysis)" },
};

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const money = (v, cur) => (v == null ? "n/a" : (cur ? cur + " " : "") + Math.round(v).toLocaleString("en-US"));

function riskAssets(rec) {
  const out = [];
  const seen = new Set();
  for (const a of rec.assetRefs || []) {
    const type = ["ASSET", "IDENTITY", "VENDOR", "DOMAIN", "IP"].includes(a.type) ? a.type : "ASSET";
    const k = type + ":" + a.name.toLowerCase();
    if (!seen.has(k)) { seen.add(k); out.push({ type, name: a.name }); }
  }
  for (const n of str(rec.assets).split(/[;,\n]/).map((x) => x.trim()).filter(Boolean)) {
    const k = "ASSET:" + n.toLowerCase();
    if (!seen.has(k)) { seen.add(k); out.push({ type: "ASSET", name: n }); }
  }
  return out.slice(0, 20);
}

function evidenceRow(rec, rr) {
  const cur = rr && rr.currentStats;
  return {
    risk: rec.title, id: rec.id || "", owner: rec.owner || "(none)", status: rec.status, category: rec.category,
    treatment: rec.treatment || "", currency: rec.currency || "",
    aleMean: cur ? cur.mean : "", p50: cur ? cur.p50 : "", p90: cur ? cur.p90 : "",
    reviewDate: rec.reviewDate || "", lastReviewed: rec.lastReviewed || "",
  };
}

// ---------------------------------------------------------------------------
// Input parsing
// ---------------------------------------------------------------------------

/** Auto-map CSV headers to canonical keys: { mapping: {canon: header}, confidence }. */
export function autoMap(headers) {
  const mapping = {};
  for (const [k, aliases] of Object.entries(COLUMNS)) {
    const h = findColumn(headers, aliases);
    if (h) mapping[k] = h;
  }
  const has3 = (p) => ["min", "likely", "max"].every((x) => mapping[p + "_" + x]);
  const core = !!mapping.title && has3("plm") && (has3("lef") || (has3("tef") && has3("vuln")));
  const exact = headers.length > 0 && Object.values(mapping).every((h) => CANON_HEADERS.includes(h));
  const confidence = core && exact ? "high" : core ? "medium" : mapping.title ? "low" : "none";
  return { mapping, confidence };
}

function rangeFromRow(row, mapping, prefix) {
  const g = (p) => (mapping[prefix + "_" + p] ? row[mapping[prefix + "_" + p]] : null);
  return { min: parseNum(g("min")), ml: parseNum(g("likely")), max: parseNum(g("max")) };
}

/** Build records from CSV rows with a { canon: header } mapping. */
export function rowsToRecords(rows, mapping, { currency = "", idPrefix = "csv" } = {}) {
  const g = (row, k) => (mapping[k] ? row[mapping[k]] : undefined);
  const out = [];
  (rows || []).forEach((row, i) => {
    const title = str(g(row, "title")).trim();
    if (!title) return;
    const residual = {
      lef: rangeFromRow(row, mapping, "res_lef"), tef: rangeFromRow(row, mapping, "res_tef"),
      vuln: rangeFromRow(row, mapping, "res_vuln"), plm: rangeFromRow(row, mapping, "res_plm"),
      slp: parseNum(g(row, "res_slp")), slm: rangeFromRow(row, mapping, "res_slm"),
    };
    const pct = (v) => { const n = parseNum(v); return n != null && n > 1 && n <= 100 ? n / 100 : n; };
    const vuln = rangeFromRow(row, mapping, "vuln");
    for (const r of [vuln, residual.vuln]) for (const k of R3) r[k] = r[k] != null && r[k] > 1 && r[k] <= 100 ? r[k] / 100 : r[k];
    out.push(normalizeRecord({
      id: str(g(row, "id")).trim() || idPrefix + "-" + String(i + 1).padStart(4, "0"),
      title, scenario: g(row, "scenario"), assets: g(row, "assets"), category: g(row, "category"),
      owner: g(row, "owner"), status: g(row, "status"), currency: str(g(row, "currency")).trim() || currency,
      freqMode: str(g(row, "freq_mode")).trim().toLowerCase(),
      lef: rangeFromRow(row, mapping, "lef"), tef: rangeFromRow(row, mapping, "tef"), vuln,
      plm: rangeFromRow(row, mapping, "plm"), slp: pct(g(row, "slp")), slm: rangeFromRow(row, mapping, "slm"),
      controls: g(row, "controls"), controlRefs: g(row, "control_refs"), treatment: g(row, "treatment"),
      treatmentCost: g(row, "treatment_cost"), residualInEffect: g(row, "residual_in_effect"),
      residual: { ...residual, slp: residual.slp != null && residual.slp > 1 && residual.slp <= 100 ? residual.slp / 100 : residual.slp },
      acceptanceNote: g(row, "acceptance_note"), linkedFindings: g(row, "linked_findings"),
      reviewDate: g(row, "review_date"), lastReviewed: g(row, "last_reviewed"), notes: g(row, "notes"),
    }));
  });
  return out;
}

function looksLikeRecord(o) { return o && typeof o === "object" && !Array.isArray(o) && typeof o.title === "string" && ("plm" in o || "lef" in o || "tef" in o || "freqMode" in o); }

/**
 * Parse text or [{ name, text }]. Returns
 * { format, headers, rows, records, settings, mapping, confidence, files, skipped }.
 * JSON exports from this tool (bundle or array) come back as records; CSV comes
 * back as rows + an auto mapping for the mapping panel.
 */
export function parseInput(input) {
  const files = Array.isArray(input) ? input : [{ name: "input", text: input }];
  const out = { format: "empty", headers: [], rows: [], records: [], settings: null, mapping: {}, confidence: "none", files: [], skipped: [] };
  for (const f of files) {
    const t = str(f && f.text);
    const name = str(f && f.name) || "input";
    if (!t.trim()) { out.files.push({ name, format: "empty", confidence: "none" }); continue; }
    const fmt = sniff(t).format;
    if (fmt === "json" || fmt === "ndjson") {
      let doc = null;
      try { doc = JSON.parse(t); } catch (_) { doc = null; }
      const list = doc && Array.isArray(doc.risks) ? doc.risks : Array.isArray(doc) ? doc : null;
      if (list && list.some(looksLikeRecord)) {
        const recs = list.filter(looksLikeRecord).map(normalizeRecord);
        for (const r of recs) out.records.push(r);
        if (doc && doc.settings && typeof doc.settings === "object") out.settings = doc.settings;
        if (list.length > recs.length) out.skipped.push({ check: "import", reason: name + ": " + (list.length - recs.length) + " item(s) are not risk records" });
        out.format = "riskreg-json";
        out.files.push({ name, format: "riskreg-json", confidence: "high", count: recs.length });
        continue;
      }
      const rows = [];
      for (const r of iterJson(t)) if (r && typeof r === "object" && !Array.isArray(r)) rows.push(r);
      if (!rows.length) { out.skipped.push({ check: "import", reason: name + ": no records found" }); out.files.push({ name, format: "json", confidence: "none" }); continue; }
      addRows(out, name, rows, "json");
      continue;
    }
    const { headers, rows } = parseCsv(t);
    if (!headers.length || !rows.length) { out.skipped.push({ check: "import", reason: name + ": no rows found" }); out.files.push({ name, format: fmt, confidence: "none" }); continue; }
    addRows(out, name, rows, fmt === "tsv" ? "tsv" : "csv");
  }
  if (out.format === "empty" && out.rows.length) out.format = out.files.find((x) => x.format !== "empty" && x.format !== "riskreg-json")?.format || "csv";
  return out;
}

function addRows(out, name, rows, format) {
  const headers = Object.keys(rows[0]);
  const { mapping, confidence } = autoMap(headers);
  if (!out.rows.length) { out.headers = headers; out.mapping = mapping; out.confidence = confidence; }
  for (const r of rows) out.rows.push(r); // one at a time: spreading 100k+ rows into push() overflows the call stack
  out.files.push({ name, format, confidence, count: rows.length });
  if (confidence === "none") out.skipped.push({ check: "import", reason: name + ": no risk title column (" + COLUMNS.title.join(", ") + ")" });
}

// ---------------------------------------------------------------------------
// analyze
// ---------------------------------------------------------------------------

function newestDate(records) {
  let best = null;
  for (const r of records) {
    for (const v of [r.updatedAt, r.lastReviewed, ...(r.history || []).map((h) => h && h.at)]) {
      const t = Date.parse(isDate(str(v)) ? v + "T00:00:00Z" : str(v));
      if (Number.isFinite(t) && (best == null || t > best)) best = t;
    }
  }
  return best;
}

const dayMs = (s) => Date.parse(s + "T00:00:00Z");

/**
 * Analyze a register. dataset = { records, settings? } or an array of records.
 * opts overrides settings (iterations, seed, currency, appetiteAmount,
 * appetitePercentile, staleDays, freqBands, magBands) and carries `now` (ISO).
 * Returns { summary, findings, tables, skipped, meta }.
 */
export function analyze(dataset, opts = {}, ctx) {
  const ds = Array.isArray(dataset) ? { records: dataset } : dataset && typeof dataset === "object" ? dataset : {};
  const S = normalizeSettings(ds.settings, opts);
  const all = (Array.isArray(ds.records) ? ds.records : Array.isArray(ds.rows) ? ds.rows : []).map(normalizeRecord);
  const nowMs = opts.now ? Date.parse(opts.now) : newestDate(all);
  const now = Number.isFinite(nowMs) ? new Date(nowMs).toISOString() : null;
  const skipped = [], findings = [], risks = [], invalid = [];
  const pctKey = S.appetitePercentile;
  const appetiteOn = S.appetiteAmount != null && S.appetiteAmount >= 0;
  if (!appetiteOn) skipped.push({ check: "over_appetite", reason: "risk appetite amount not set (Settings)" });
  if (!now) skipped.push({ check: "review_overdue", reason: "no reference date (no dates in the register and no 'now' passed)" });
  const n = all.length;
  const series = new Map(); // row index (ids may repeat) -> { current sorted, inherent sorted, residual sorted, raw current }
  const byCurrency = new Map();
  let noLastReviewed = 0;

  for (let i = 0; i < n; i++) {
    ctx?.progress?.(i, n, all[i].title || "risk " + (i + 1));
    const rec = all[i];
    const key = rec.id || "#" + i;
    const errors = validateRisk(rec);
    const currency = rec.currency || S.currency;
    const row = { id: key, title: rec.title, owner: rec.owner, status: rec.status, category: rec.category, treatment: rec.treatment, currency, reviewDate: rec.reviewDate, lastReviewed: rec.lastReviewed, valid: !errors.length, errors };
    if (errors.length) { invalid.push({ id: key, title: rec.title || "(untitled)", errors }); risks.push(row); continue; }
    const sim = simulateRisk({ ...rec, id: key }, S, i);
    const inhSorted = sortedCopy(sim.inherent.losses);
    const inherent = lossStats(sim.inherent.losses, sim.inherent.events, inhSorted);
    let residual = null, resSorted = null, econ = null;
    if (sim.residual) {
      resSorted = sortedCopy(sim.residual.losses);
      residual = lossStats(sim.residual.losses, sim.residual.events, resSorted);
      econ = treatmentEconomics(inherent.mean, residual.mean, rec.treatmentCost, inherent.p90, residual.p90);
    }
    const useRes = !!(sim.residual && rec.residualInEffect);
    const curSorted = useRes ? resSorted : inhSorted;
    const cur = useRes ? residual : inherent;
    const grid = lecGrid([inhSorted, resSorted]);
    const lec = grid.map((x, j) => ({ x: r2(x), inherent: 0, residual: null, _j: j }));
    const ei = exceedance(inhSorted, grid), er = resSorted ? exceedance(resSorted, grid) : null;
    lec.forEach((p, j) => { p.inherent = ei[j]; p.residual = er ? er[j] : null; delete p._j; });
    let appetite = null;
    if (appetiteOn && currency === S.currency) {
      const v = r2(quantileSorted(curSorted, pctKey / 100));
      appetite = { percentile: pctKey, amount: S.appetiteAmount, value: v, exceeds: v > S.appetiteAmount, basis: useRes ? "residual" : "inherent" };
    } else if (appetiteOn) appetite = { percentile: pctKey, amount: S.appetiteAmount, value: null, exceeds: null, basis: "currency " + currency + " differs from appetite currency " + S.currency };
    Object.assign(row, {
      inherent, residual, current: useRes ? "residual" : "inherent", currentStats: cur, treatmentEcon: econ, appetite,
      lec, histogram: histogram(curSorted),
    });
    risks.push(row);
    if (rec.status !== "closed") {
      series.set(i, { cur: useRes ? sim.residual.losses : sim.inherent.losses, inh: sim.inherent.losses, curEvents: useRes ? sim.residual.events : sim.inherent.events });
      if (!byCurrency.has(currency)) byCurrency.set(currency, []);
      byCurrency.get(currency).push(i);
    }
    // ---- findings ----
    if (rec.status === "closed") continue;
    const ev = [evidenceRow(rec, row)];
    const assets = riskAssets(rec);
    const fid = (c) => TOOL_ID + ":" + c + ":" + key;
    const tags = ["risk-register"];
    if (appetite && appetite.exceeds) {
      findings.push({
        id: fid("over_appetite"), title: "Risk exceeds appetite: " + rec.title, severity: "high", confidence: "likely", category: "risk-appetite",
        description: "P" + pctKey + " annual loss (" + appetite.basis + ") is " + money(appetite.value, currency) + ", above the appetite of " + money(S.appetiteAmount, currency) + ". " + MODEL_NOTE,
        recommendation: "Choose a treatment that brings P" + pctKey + " under appetite, or record a formal acceptance by the risk owner.",
        controls: [C.iso613, C.gvrm02, C.idra06, C.ora], evidence: ev, evidenceCount: 1, assets, tags,
      });
      if (rec.treatment === "accept" && !rec.acceptanceNote) {
        findings.push({
          id: fid("accept_no_note"), title: "Accepted above appetite without an acceptance note: " + rec.title, severity: "medium", confidence: "confirmed", category: "risk-acceptance",
          description: "Treatment is 'accept' while P" + pctKey + " exceeds appetite, and no acceptance rationale or approver is recorded.",
          recommendation: "Record who accepted the risk, why, and until when (risk owner approval of residual risk).",
          controls: [C.iso613, C.i27005t, C.idra06], evidence: ev, evidenceCount: 1, assets, tags,
        });
      }
    }
    if (now && rec.reviewDate && isDate(rec.reviewDate) && dayMs(rec.reviewDate) < dayMs(now.slice(0, 10))) {
      const late = Math.round((dayMs(now.slice(0, 10)) - dayMs(rec.reviewDate)) / DAY);
      findings.push({
        id: fid("review_overdue"), title: "Risk review overdue: " + rec.title, severity: "medium", confidence: "confirmed", category: "risk-review",
        description: "Review was due " + rec.reviewDate + " (" + late + " day(s) ago).",
        recommendation: "Re-assess the ranges with the owner, update Last reviewed and set the next review date.",
        controls: [C.iso82, C.sp80030, C.i27005m], evidence: ev, evidenceCount: 1, assets, tags,
      });
    }
    if (!rec.owner) {
      findings.push({
        id: fid("no_owner"), title: "Risk has no owner: " + rec.title, severity: "low", confidence: "confirmed", category: "risk-ownership",
        description: "No accountable owner is recorded for this risk.",
        recommendation: "Assign a risk owner with the authority to approve treatment and accept residual risk.",
        controls: [C.iso612, C.gvrr02], evidence: ev, evidenceCount: 1, assets, tags,
      });
    }
    if (!rec.lastReviewed) noLastReviewed++;
    else if (now && isDate(rec.lastReviewed)) {
      const age = Math.round((dayMs(now.slice(0, 10)) - dayMs(rec.lastReviewed)) / DAY);
      if (age > S.staleDays) {
        findings.push({
          id: fid("stale_assessment"), title: "Stale risk assessment: " + rec.title, severity: "low", confidence: "confirmed", category: "risk-review",
          description: "Last reviewed " + rec.lastReviewed + " (" + age + " days ago, limit " + S.staleDays + ").",
          recommendation: "Refresh the frequency and magnitude ranges with current evidence.",
          controls: [C.iso82, C.sp80030, C.idra05], evidence: ev, evidenceCount: 1, assets, tags,
        });
      }
    }
  }
  if (noLastReviewed) skipped.push({ check: "stale_assessment", reason: noLastReviewed + " risk(s) have no Last reviewed date" });
  if (invalid.length) skipped.push({ check: "simulation", reason: invalid.length + " risk(s) failed validation and were not simulated" });

  // ---- portfolios (one per currency) ----
  const portfolios = [];
  for (const currency of [...byCurrency.keys()].sort()) {
    const ids = byCurrency.get(currency);
    const len = series.get(ids[0]).cur.length;
    const tot = new Float64Array(len), inh = new Float64Array(len);
    for (const id of ids) { const s = series.get(id); for (let i = 0; i < len; i++) { tot[i] += s.cur[i]; inh[i] += s.inh[i]; } }
    const sTot = sortedCopy(tot), sInh = sortedCopy(inh);
    const stats = lossStats(tot, null, sTot), statsInh = lossStats(inh, null, sInh);
    const grid = lecGrid([sTot, sInh]);
    const et = exceedance(sTot, grid), ei = exceedance(sInh, grid);
    const contributors = ids.map((ix) => {
      const r = risks[ix];
      return { id: r.id, title: r.title, ale: r.currentStats.mean, share: r4(stats.mean > 0 ? r.currentStats.mean / stats.mean : 0), p90: r.currentStats.p90 };
    }).sort((a, b) => b.ale - a.ale || (a.title < b.title ? -1 : a.title > b.title ? 1 : 0));
    const p = { currency, risks: ids.length, current: stats, inherent: statsInh, lec: grid.map((x, j) => ({ x: r2(x), current: et[j], inherent: ei[j] })), histogram: histogram(sTot), topContributors: contributors.slice(0, 10) };
    if (appetiteOn && currency === S.currency) {
      const v = r2(quantileSorted(sTot, pctKey / 100));
      p.appetite = { percentile: pctKey, amount: S.appetiteAmount, value: v, exceeds: v > S.appetiteAmount };
    }
    portfolios.push(p);
  }

  // ---- heatmap (qualitative view derived from the simulation) ----
  let heatmap;
  if (!bandsValid(S.freqBands) || !bandsValid(S.magBands)) {
    heatmap = { ready: false, reason: "Set 4 ascending frequency band edges and 4 magnitude band edges in Settings." };
    skipped.push({ check: "heatmap", reason: "band edges not set (Settings)" });
  } else {
    const grid = Array.from({ length: 5 }, () => Array.from({ length: 5 }, () => []));
    const excluded = [];
    for (const r of risks) {
      if (!r.valid || r.status === "closed") continue;
      if (r.currency !== S.currency) { excluded.push({ id: r.id, title: r.title, reason: "currency " + r.currency }); continue; }
      const f = bandOf(S.freqBands, r.currentStats.meanEvents), m = bandOf(S.magBands, r.currentStats.meanLossPerEvent);
      r.heat = { f, m };
      grid[f][m].push(r.id);
    }
    heatmap = { ready: true, currency: S.currency, freqBands: S.freqBands, magBands: S.magBands, cells: grid, excluded, basis: "mean simulated events per year (likelihood) x mean simulated loss per event (impact)" };
  }

  // ---- sort + summary ----
  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const bySeverity = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  ctx?.progress?.(n, n, "done");
  const valid = risks.filter((r) => r.valid);
  const summary = {
    risks: n, simulated: valid.length, invalid: invalid.length,
    open: valid.filter((r) => r.status !== "closed").length,
    overAppetite: valid.filter((r) => r.status !== "closed" && r.appetite && r.appetite.exceeds).length,
    overdueReviews: findings.filter((f) => f.category === "risk-review" && f.id.includes(":review_overdue:")).length,
    noOwner: findings.filter((f) => f.id.includes(":no_owner:")).length,
    findings: findings.length, bySeverity,
    portfolioAle: Object.fromEntries(portfolios.map((p) => [p.currency, p.current.mean])),
    currencies: portfolios.map((p) => p.currency),
  };
  return {
    summary, findings,
    tables: { risks, portfolios, heatmap, invalid },
    skipped,
    meta: {
      tool: TOOL_ID, version: VERSION, rows: n, iterations: S.iterations, seed: S.seed, now, settings: S,
      model: "beta-PERT (lambda 4) ranges; annual rate ~ PERT, events ~ Poisson(rate); loss per event = PERT(primary) + Bernoulli(SLP) x PERT(secondary); mulberry32 seeded per risk; portfolio sums per iteration assuming independent risks; same-currency only.",
      note: MODEL_NOTE,
    },
  };
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

const DIFF_SKIP = new Set(["history", "updatedAt", "createdAt", "graphId", "snapshot"]);

/** Human summary of what changed between two records ("status: a -> b; plm"). */
export function diffSummary(prev, next) {
  if (!prev) return "created";
  const a = normalizeRecord(prev), b = normalizeRecord(next);
  const parts = [];
  for (const k of Object.keys(b).sort()) {
    if (DIFF_SKIP.has(k)) continue;
    const x = JSON.stringify(a[k] === undefined ? null : a[k]), y = JSON.stringify(b[k] === undefined ? null : b[k]);
    if (x === y) continue;
    if (["status", "treatment", "owner", "category", "reviewDate", "lastReviewed", "currency"].includes(k)) parts.push(k + ": " + (a[k] || "(none)") + " -> " + (b[k] || "(none)"));
    else parts.push(k);
  }
  return parts.length ? parts.join("; ") : "no changes";
}

/** Return `next` with one history entry appended (capped at HISTORY_CAP). */
export function withHistory(prev, next, { at, by } = {}) {
  const hist = ((prev && prev.history) || next.history || []).slice();
  const entry = { at: at || null, change: diffSummary(prev, next) };
  if (by) entry.by = by;
  hist.push(entry);
  return { ...next, history: hist.slice(-HISTORY_CAP) };
}

/** Compact result fields stored on a saved record (and mirrored to the graph). */
export function snapshotOf(riskRow, at) {
  if (!riskRow || !riskRow.valid) return null;
  const c = riskRow.currentStats;
  return { at: at || null, currency: riskRow.currency, aleMean: c.mean, p50: c.p50, p90: c.p90, pAny: c.pAny, overAppetite: !!(riskRow.appetite && riskRow.appetite.exceeds), basis: riskRow.current };
}

// ---------------------------------------------------------------------------
// Register schema (core/register.js) — risks mirror as FINDING, category "risk"
// ---------------------------------------------------------------------------

export const REGISTER_SCHEMA = {
  key: "id",
  name: (r) => "Risk: " + String(r.title || "Untitled risk"),
  severity: (r) => (r.status === "closed" ? null : r.snapshot && r.snapshot.overAppetite ? "high" : r.snapshot ? "medium" : "low"),
  status: (r) => ({ identified: "new", assessed: "open", treating: "investigating", accepted: "open", closed: "closed" }[r.status] || "open"),
  summary: (r) => ({
    title: "Risk: " + (r.title || ""), category: "risk", riskCategory: r.category || "", owner: r.owner || "", riskStatus: r.status || "",
    treatment: r.treatment || "", currency: r.currency || "", aleMean: r.snapshot ? r.snapshot.aleMean : null, p90: r.snapshot ? r.snapshot.p90 : null,
    overAppetite: !!(r.snapshot && r.snapshot.overAppetite), reviewDate: r.reviewDate || "", tags: ["risk-register"],
    recommendation: r.treatment ? "Treatment: " + r.treatment : "", affected: str(r.assets).split(/[;,]/).map((x) => x.trim()).filter(Boolean),
  }),
  columns: [
    { key: "id", label: "ID" }, { key: "title", label: "Risk" }, { key: "owner", label: "Owner" }, { key: "status", label: "Status" },
    { key: "category", label: "Category" }, { key: "treatment", label: "Treatment" }, { key: "reviewDate", label: "Review date" }, { key: "updatedAt", label: "Updated" },
  ],
};

/** Settings live in a one-record companion register mirrored as a REPORT entity. */
export const SETTINGS_SCHEMA = {
  key: "id",
  name: () => "Risk register settings",
  summary: (r) => ({ title: "Risk register settings", kind: "assessment", currency: r.currency || "", appetiteAmount: r.appetiteAmount ?? null, appetitePercentile: r.appetitePercentile ?? null }),
  columns: [{ key: "id", label: "ID" }],
};
export const SETTINGS_ID = "riskreg-settings";

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

const csvCell = (v) => {
  let s = Array.isArray(v) ? v.join("; ") : str(v);
  if (/^[=+\-@\t\r]/.test(s) && !/^-?\d+(\.\d+)?(e[+-]?\d+)?$/i.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};

/** Register CSV with canonical headers (re-importable through rowsToRecords + autoMap). */
export function registerToCsv(records) {
  const rows = (records || []).map((raw) => {
    const r = normalizeRecord(raw);
    const o = {
      id: r.id || "", title: r.title, scenario: r.scenario, assets: [r.assets, ...r.assetRefs.map((a) => a.name)].filter(Boolean).join("; "),
      category: r.category, owner: r.owner, status: r.status, currency: r.currency, freq_mode: r.freqMode,
      slp: r.slp, controls: r.controls, control_refs: r.controlRefs, treatment: r.treatment, treatment_cost: r.treatmentCost,
      residual_in_effect: r.residualInEffect ? "yes" : "", res_slp: r.residual.slp, acceptance_note: r.acceptanceNote,
      linked_findings: r.linkedFindings, review_date: r.reviewDate, last_reviewed: r.lastReviewed, notes: r.notes,
    };
    for (const k of RANGE_FIELDS) for (const p of R3) {
      o[k + "_" + PART[p]] = r[k][p];
      o["res_" + k + "_" + PART[p]] = r.residual[k][p];
    }
    return o;
  });
  return [CANON_HEADERS.join(","), ...rows.map((o) => CANON_HEADERS.map((h) => csvCell(o[h])).join(","))].join("\r\n") + "\r\n";
}

/** JSON bundle (re-importable via parseInput). */
export function registerToJson(records, settings) {
  return JSON.stringify({ tool: TOOL_ID, version: VERSION, settings: settings || null, risks: (records || []).map((r) => { const c = { ...r }; delete c.graphId; return c; }) }, null, 2) + "\n";
}

/** Loss-exceedance points as CSV: scope,risk_id,title,currency,loss,p_exceed_inherent,p_exceed_residual_or_current. */
export function lecToCsv(result) {
  const lines = ["scope,risk_id,title,currency,loss,p_exceed_inherent,p_exceed_residual,p_exceed_current"];
  for (const p of (result && result.tables.portfolios) || []) for (const pt of p.lec) lines.push(["portfolio", "", "Portfolio " + p.currency, p.currency, pt.x, pt.inherent, "", pt.current].map(csvCell).join(","));
  for (const r of (result && result.tables.risks) || []) {
    if (!r.valid) continue;
    for (const pt of r.lec) lines.push(["risk", r.id, r.title, r.currency, pt.x, pt.inherent, pt.residual == null ? "" : pt.residual, r.current === "residual" ? pt.residual : pt.inherent].map(csvCell).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}

/** Calendar events (core/export.js toIcs) for every open risk's review date. */
export function reviewEvents(records, { stamp } = {}) {
  return (records || []).map(normalizeRecord).filter((r) => r.status !== "closed" && isDate(r.reviewDate))
    .sort((a, b) => (a.reviewDate < b.reviewDate ? -1 : a.reviewDate > b.reviewDate ? 1 : str(a.id) < str(b.id) ? -1 : 1))
    .map((r) => ({
      uid: "riskreg-" + (r.id || fnv1a32(r.title).toString(16)) + "-" + r.reviewDate.replace(/-/g, "") + "@darknode.ai",
      start: r.reviewDate + "T00:00:00Z", end: new Date(dayMs(r.reviewDate) + DAY).toISOString(), allDay: true,
      summary: "Risk review: " + r.title,
      description: "Owner: " + (r.owner || "(none)") + "\nStatus: " + r.status + "\nTreatment: " + (r.treatment || "(none)"),
      stamp: stamp || r.reviewDate + "T00:00:00Z",
    }));
}

/** Plain-text board summary. */
export function boardSummary(result, { org = "", now } = {}) {
  const r = result || { tables: { risks: [], portfolios: [] }, findings: [], meta: {} };
  const m = r.meta || {};
  const L = [];
  L.push("RISK REGISTER - BOARD SUMMARY" + (org ? " - " + org : ""));
  L.push("As of: " + str(now || m.now || "").slice(0, 10));
  L.push(MODEL_NOTE);
  L.push("Simulation: " + m.iterations + " iterations, seed " + m.seed + ". " + (m.model || ""));
  L.push("");
  L.push("PORTFOLIO ANNUALIZED LOSS EXPOSURE (current treatment state, independent risks)");
  for (const p of r.tables.portfolios) {
    L.push("  " + p.currency + ": mean " + money(p.current.mean, p.currency) + " | P50 " + money(p.current.p50, p.currency) + " | P90 " + money(p.current.p90, p.currency) + " | P99 " + money(p.current.p99, p.currency) + " (" + p.risks + " risks)");
    if (p.appetite) L.push("    Appetite " + money(p.appetite.amount, p.currency) + " at P" + p.appetite.percentile + ": portfolio " + (p.appetite.exceeds ? "EXCEEDS" : "within"));
  }
  if (!r.tables.portfolios.length) L.push("  (no simulated open risks)");
  L.push("");
  L.push("TOP 10 RISKS BY ANNUALIZED LOSS EXPOSURE");
  const top = r.tables.risks.filter((x) => x.valid && x.status !== "closed").sort((a, b) => b.currentStats.mean - a.currentStats.mean || (a.title < b.title ? -1 : 1)).slice(0, 10);
  top.forEach((x, i) => L.push("  " + (i + 1) + ". " + x.title + " - ALE " + money(x.currentStats.mean, x.currency) + ", P90 " + money(x.currentStats.p90, x.currency) + ", owner " + (x.owner || "(none)") + ", " + x.status + (x.treatment ? ", " + x.treatment : "")));
  if (!top.length) L.push("  (none)");
  L.push("");
  L.push("OVER APPETITE");
  const over = r.tables.risks.filter((x) => x.valid && x.status !== "closed" && x.appetite && x.appetite.exceeds);
  over.forEach((x) => L.push("  - " + x.title + ": P" + x.appetite.percentile + " " + money(x.appetite.value, x.currency) + " vs appetite " + money(x.appetite.amount, x.currency)));
  if (!over.length) L.push(m.settings && m.settings.appetiteAmount != null ? "  (none)" : "  (appetite not set)");
  L.push("");
  L.push("OVERDUE REVIEWS");
  const od = r.findings.filter((f) => f.id && f.id.includes(":review_overdue:"));
  od.forEach((f) => L.push("  - " + f.title.replace(/^Risk review overdue: /, "") + " (" + f.description + ")"));
  if (!od.length) L.push("  (none)");
  L.push("");
  L.push("TREATMENTS");
  const tr = r.tables.risks.filter((x) => x.valid && x.treatmentEcon);
  tr.forEach((x) => L.push("  - " + x.title + ": ALE " + money(x.inherent.mean, x.currency) + " -> " + money(x.residual.mean, x.currency) + ", cost " + money(x.treatmentEcon.cost, x.currency) + "/yr, ROI " + (x.treatmentEcon.roi == null ? "n/a" : Math.round(x.treatmentEcon.roi * 100) + "%")));
  if (!tr.length) L.push("  (no residual ranges entered)");
  return L.join("\n") + "\n";
}

const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "evidenceCount"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const q = (v) => '"' + String(v ?? "").replace(/^(?=[=+@\t\r]|-(?!\d+(?:\.\d+)?$))/, "'").replace(/"/g, '""') + '"';
  const body = (findings || []).map((f) => [
    f.severity, f.confidence, f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
  ].map(q).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n");
}

// ---------------------------------------------------------------------------
// Synthetic example
// ---------------------------------------------------------------------------

/**
 * SYNTHETIC register for "Test Org (synthetic)": 8 risks, all ranges
 * invented for the demo. Dates are relative to `now` so review findings show.
 */
export function exampleDataset(seed = 1, now = "2026-10-16T00:00:00Z") {
  const base = Number.isFinite(Date.parse(now)) ? Date.parse(now) : Date.parse("2026-10-16T00:00:00Z");
  const d = (days) => new Date(base + days * DAY).toISOString().slice(0, 10);
  const R = (min, ml, max) => ({ min, ml, max });
  const own = (u) => u + "@test.darknode.ai";
  const records = [
    { id: "testorg-01", title: "Ransomware encrypts file servers", scenario: "Ransomware operator encrypts on-prem file servers and exfiltrates shares", assets: "File servers; Backup vault", category: "cyber", owner: own("user01"), status: "treating",
      freqMode: "tef", tef: R(0.5, 2, 6), vuln: R(0.05, 0.15, 0.3), plm: R(150000, 600000, 3000000), slp: 0.4, slm: R(100000, 500000, 4000000),
      controls: "EDR on servers; nightly backups (not immutable)", controlRefs: ["iso27001:8.13", "iso27001:8.7"], treatment: "mitigate", treatmentCost: 120000,
      residual: { vuln: R(0.01, 0.04, 0.1), plm: R(80000, 250000, 1200000) }, reviewDate: d(45), lastReviewed: d(-60) },
    { id: "testorg-02", title: "Business email compromise wire fraud", scenario: "Fraudster spoofs a supplier and redirects a wire payment", assets: "Accounts payable", category: "financial", owner: own("user02"), status: "treating",
      freqMode: "lef", lef: R(0.2, 0.6, 2), plm: R(25000, 120000, 900000), slp: 0.2, slm: R(10000, 40000, 200000),
      controls: "Callback verification on bank changes", treatment: "mitigate", treatmentCost: 30000, residualInEffect: true,
      residual: { lef: R(0.05, 0.15, 0.5) }, reviewDate: d(20), lastReviewed: d(-30) },
    { id: "testorg-03", title: "Cloud access key leaked in a public repo", scenario: "Developer pushes a long-lived cloud key; attacker mines crypto and reads buckets", assets: "Production cloud account", category: "cyber", owner: own("user04"), status: "assessed",
      freqMode: "lef", lef: R(0.1, 0.3, 1.2), plm: R(20000, 150000, 2000000), slp: 0.3, slm: R(50000, 300000, 2500000),
      controls: "Secret scanning on main branch only", treatment: "mitigate", reviewDate: d(60), lastReviewed: d(-90) },
    { id: "testorg-04", title: "Payroll diversion via HR portal", scenario: "Attacker takes over an employee account and changes the payroll bank account", assets: "HR portal", category: "financial", owner: own("user02"), status: "accepted",
      freqMode: "lef", lef: R(0.3, 1, 3), plm: R(3000, 9000, 40000), slp: 0.1, slm: R(2000, 10000, 50000),
      treatment: "accept", acceptanceNote: "Accepted by CFO (synthetic) until next review; losses within petty fraud budget.", reviewDate: d(90), lastReviewed: d(-120) },
    { id: "testorg-05", title: "Key vendor outage (payments processor)", scenario: "Payments processor outage stops checkout for a business day", assets: "Payments processor", category: "third-party", owner: own("user03"), status: "assessed",
      freqMode: "lef", lef: R(0.2, 0.5, 1.5), plm: R(40000, 200000, 1500000), slp: 0.25, slm: R(20000, 150000, 1000000),
      treatment: "transfer", controls: "Contractual SLA credits", reviewDate: d(30), lastReviewed: d(-200) },
    { id: "testorg-06", title: "DDoS on checkout", scenario: "Volumetric DDoS degrades checkout during a sale", assets: "Checkout service", category: "operational", owner: own("user03"), status: "assessed",
      freqMode: "lef", lef: R(0.5, 2, 6), plm: R(10000, 60000, 400000), slp: 0.1, slm: R(5000, 30000, 200000),
      treatment: "accept", reviewDate: d(-12), lastReviewed: d(-300) },
    { id: "testorg-07", title: "Insider data theft", scenario: "Departing engineer copies customer data to personal storage", assets: "Customer database", category: "cyber", owner: own("user01"), status: "assessed",
      freqMode: "lef", lef: R(0.05, 0.2, 0.6), plm: R(100000, 700000, 5000000), slp: 0.5, slm: R(200000, 1000000, 8000000),
      treatment: "accept", reviewDate: d(15), lastReviewed: d(-100) },
    { id: "testorg-08", title: "PCI DSS non-compliance fine", scenario: "Card brand fines after a failed assessment", assets: "Cardholder data environment", category: "compliance", owner: own("user04"), status: "identified",
      freqMode: "lef", lef: R(0.05, 0.1, 0.3), plm: R(50000, 250000, 1000000), slp: 0.3, slm: R(25000, 100000, 600000),
      treatment: "mitigate", reviewDate: d(-30), lastReviewed: d(-400) },
  ].map((r) => normalizeRecord({ ...r, currency: "USD", notes: "Synthetic example record (Test Org, synthetic)." }));
  return {
    label: "Test Org (synthetic) - example register, not real data",
    org: "Test Org (synthetic)",
    records,
    settings: { currency: "USD", appetiteAmount: 2000000, appetitePercentile: 90, freqBands: [0.05, 0.2, 1, 5], magBands: [50000, 250000, 1000000, 5000000], iterations: 10000, seed: seed >>> 0 },
    now: new Date(base).toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

/** Real deterministic checks of the engine. */
export function selfTest() {
  const tests = [];
  const t = (name, fn) => { let pass = false; try { pass = !!fn(); } catch (_) { pass = false; } tests.push({ name, pass }); };
  t("mulberry32 is deterministic", () => { const a = mulberry32(42), b = mulberry32(42); for (let i = 0; i < 50; i++) if (a() !== b()) return false; return true; });
  t("PERT mean within 1% of (min+4ml+max)/6", () => {
    const rng = mulberry32(7); const s = makePert({ min: 10, ml: 40, max: 100 }, rng); let sum = 0; const N = 20000;
    for (let i = 0; i < N; i++) sum += s();
    return Math.abs(sum / N - pertMean({ min: 10, ml: 40, max: 100 })) / 45 < 0.01;
  });
  t("validation rejects min > likely", () => validateRisk({ title: "x", lef: { min: 2, ml: 1, max: 3 }, plm: { min: 1, ml: 2, max: 3 } }).some((e) => e.field === "lef"));
  const ex = exampleDataset(1, "2026-10-16T00:00:00Z");
  const opts = { ...ex.settings, iterations: 2000, now: ex.now };
  const a = analyze({ records: ex.records }, opts);
  t("example analyses all 8 risks", () => a.summary.simulated === 8);
  t("analyze is deterministic", () => JSON.stringify(a) === JSON.stringify(analyze({ records: ex.records }, opts)));
  t("overdue review detected", () => a.findings.some((f) => f.id === "riskreg:review_overdue:testorg-06"));
  t("no appetite -> appetite check skipped", () => analyze({ records: ex.records.slice(0, 1) }, { iterations: 200, now: ex.now }).skipped.some((s) => s.check === "over_appetite"));
  return { pass: tests.every((x) => x.pass), tests };
}
