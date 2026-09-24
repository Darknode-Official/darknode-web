// Darknode in-memory query / filter / aggregate engine.
//
// Filtering, sorting, grouping, faceting and computing aggregates over arrays of
// records is done ad-hoc in dozens of modules (report.js, compliance-checker.js,
// siem-engine.js, security-graph's listEntities, most dashboards). Each rolls its
// own `.filter().sort().reduce()` with slightly different edge-case handling.
//
// This is one small, dependency-free engine for that, with:
//   - dot-path field access (get(obj, "data.cvss"))
//   - a chainable Query (where / search / sort / limit / pluck / all / count)
//   - an operator-object predicate language ({ cvss: { gte: 7 }, status: { in: [...] } })
//   - aggregates: count, sum, avg, min, max, median, percentile, distinct
//   - groupBy + aggregate rollups, and facet() for building filter UIs
//
// All pure functions over plain data — no DOM, no storage — so it is fully
// unit-testable in Node and reusable everywhere.

// --- field access ------------------------------------------------------------

/** Read a possibly-nested field by dot path. `get(o, "a.b.c")`. */
export function get(obj, path) {
  if (obj == null) return undefined;
  if (path.indexOf(".") === -1) return obj[path];
  let cur = obj;
  for (const part of path.split(".")) {
    if (cur == null) return undefined;
    cur = cur[part];
  }
  return cur;
}

// --- comparison + operators --------------------------------------------------

// Stable comparison usable for sorting mixed types: numbers < before strings,
// nullish sinks to the end.
export function compare(a, b) {
  if (a === b) return 0;
  const an = a === null || a === undefined;
  const bn = b === null || b === undefined;
  if (an && bn) return 0;
  if (an) return 1;
  if (bn) return -1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b));
}

const OPS = {
  eq: (v, t) => v === t,
  ne: (v, t) => v !== t,
  gt: (v, t) => compare(v, t) > 0 && v != null,
  gte: (v, t) => v != null && compare(v, t) >= 0,
  lt: (v, t) => v != null && compare(v, t) < 0,
  lte: (v, t) => v != null && compare(v, t) <= 0,
  in: (v, t) => Array.isArray(t) && t.includes(v),
  nin: (v, t) => Array.isArray(t) && !t.includes(v),
  contains: (v, t) => (Array.isArray(v) ? v.includes(t) : String(v ?? "").toLowerCase().includes(String(t).toLowerCase())),
  startsWith: (v, t) => String(v ?? "").toLowerCase().startsWith(String(t).toLowerCase()),
  endsWith: (v, t) => String(v ?? "").toLowerCase().endsWith(String(t).toLowerCase()),
  exists: (v, t) => (v !== undefined && v !== null) === !!t,
  between: (v, t) => Array.isArray(t) && v != null && compare(v, t[0]) >= 0 && compare(v, t[1]) <= 0,
  regex: (v, t) => { try { return new RegExp(t, "i").test(String(v ?? "")); } catch (_) { return false; } },
};

// Compile a spec object like { cvss: { gte: 7 }, status: "open", type: { in:[...] } }
// into a single predicate. A bare value means eq. All conditions AND together.
export function predicate(spec) {
  if (typeof spec === "function") return spec;
  const clauses = [];
  for (const field of Object.keys(spec || {})) {
    const cond = spec[field];
    if (cond !== null && typeof cond === "object" && !Array.isArray(cond)) {
      for (const op of Object.keys(cond)) {
        const fn = OPS[op];
        if (!fn) throw new Error(`query: unknown operator "${op}"`);
        const target = cond[op];
        clauses.push((rec) => fn(get(rec, field), target));
      }
    } else {
      clauses.push((rec) => get(rec, field) === cond);
    }
  }
  return (rec) => clauses.every((c) => c(rec));
}

// --- standalone aggregates ---------------------------------------------------

const nums = (records, field) => records
  .map((r) => (field ? get(r, field) : r))
  .filter((v) => typeof v === "number" && Number.isFinite(v));

export const count = (records) => records.length;
export const sum = (records, field) => nums(records, field).reduce((a, b) => a + b, 0);
export const avg = (records, field) => { const n = nums(records, field); return n.length ? sum(n) / n.length : 0; };
export const min = (records, field) => { const n = nums(records, field); return n.length ? Math.min(...n) : undefined; };
export const max = (records, field) => { const n = nums(records, field); return n.length ? Math.max(...n) : undefined; };

/** Linear-interpolated percentile (p in 0..100) over a numeric field. */
export function percentile(records, field, p) {
  const n = nums(records, field).sort((a, b) => a - b);
  if (!n.length) return undefined;
  if (n.length === 1) return n[0];
  const rank = (Math.min(100, Math.max(0, p)) / 100) * (n.length - 1);
  const lo = Math.floor(rank), hi = Math.ceil(rank);
  if (lo === hi) return n[lo];
  return n[lo] + (n[hi] - n[lo]) * (rank - lo);
}
export const median = (records, field) => percentile(records, field, 50);

/** Distinct values of a field, in first-seen order. */
export function distinct(records, field) {
  const seen = new Set(), out = [];
  for (const r of records) { const v = get(r, field); if (!seen.has(v)) { seen.add(v); out.push(v); } }
  return out;
}

/** { value: count } for a field, sorted by count desc. Great for filter facets. */
export function facet(records, field) {
  const m = new Map();
  for (const r of records) { const v = get(r, field); m.set(v, (m.get(v) || 0) + 1); }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).map(([value, n]) => ({ value, count: n }));
}

/** Group records into { key: [records] } by a field path or key function. */
export function groupBy(records, by) {
  const keyFn = typeof by === "function" ? by : (r) => get(r, by);
  const groups = new Map();
  for (const r of records) {
    const k = keyFn(r);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(r);
  }
  return groups;
}

const AGG_FNS = { count, sum, avg, min, max, median, percentile, distinct };

/**
 * Roll up groups into summary rows. `by` is a field/keyFn; `specs` maps output
 * names to { fn, field?, p? }.
 *   aggregate(vulns, "severity", { n: { fn: "count" }, avgCvss: { fn: "avg", field: "data.cvss" } })
 * -> [{ key: "critical", n: 12, avgCvss: 9.3 }, ...] sorted by count desc.
 */
export function aggregate(records, by, specs) {
  const groups = groupBy(records, by);
  const rows = [];
  for (const [key, recs] of groups.entries()) {
    const row = { key, count: recs.length };
    for (const name of Object.keys(specs || {})) {
      const s = specs[name];
      const fn = AGG_FNS[s.fn];
      if (!fn) throw new Error(`query: unknown aggregate "${s.fn}"`);
      row[name] = s.fn === "percentile" ? fn(recs, s.field, s.p) : fn(recs, s.field);
    }
    rows.push(row);
  }
  return rows.sort((a, b) => b.count - a.count);
}

// --- chainable Query ---------------------------------------------------------

export class Query {
  constructor(records) { this._records = Array.isArray(records) ? records.slice() : []; }

  /** Filter by a predicate function or an operator-spec object. Chainable. */
  where(spec) { const p = predicate(spec); this._records = this._records.filter(p); return this; }

  whereEq(field, value) { this._records = this._records.filter((r) => get(r, field) === value); return this; }

  whereIn(field, values) { const set = new Set(values); this._records = this._records.filter((r) => set.has(get(r, field))); return this; }

  /** Case-insensitive substring search across one or more fields. */
  search(text, fields) {
    const q = String(text || "").trim().toLowerCase();
    if (!q) return this;
    const fs = Array.isArray(fields) ? fields : [fields];
    this._records = this._records.filter((r) => fs.some((f) => String(get(r, f) ?? "").toLowerCase().includes(q)));
    return this;
  }

  /** Sort by a field path or comparator. dir "asc" (default) or "desc". */
  sort(by, dir = "asc") {
    const cmp = typeof by === "function" ? by : (a, b) => compare(get(a, by), get(b, by));
    this._records.sort(cmp);
    if (dir === "desc") this._records.reverse();
    return this;
  }

  limit(n) { this._records = this._records.slice(0, Math.max(0, n)); return this; }
  offset(n) { this._records = this._records.slice(Math.max(0, n)); return this; }
  page(pageNum, size) { const p = Math.max(1, pageNum); return this.offset((p - 1) * size).limit(size); }

  /** Extract one field from every record. */
  pluck(field) { return this._records.map((r) => get(r, field)); }

  // terminals
  all() { return this._records.slice(); }
  first() { return this._records[0] ?? null; }
  count() { return this._records.length; }
  facet(field) { return facet(this._records, field); }
  groupBy(by) { return groupBy(this._records, by); }
  aggregate(by, specs) { return aggregate(this._records, by, specs); }
  sum(field) { return sum(this._records, field); }
  avg(field) { return avg(this._records, field); }
}

/** Entry point: from(records).where(...).sort(...).all() */
export function from(records) { return new Query(records); }
