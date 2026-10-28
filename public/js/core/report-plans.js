// Operational reports (Deck D7): the remediation plan by owner and the vulnerability SLA
// report. PURE — no DOM, no network, deterministic. Both read FINDING entities out of the
// graph and reuse the D1 work-queue engine (core/workflow.js) for SLA position and
// known-exploited detection, so these reports never disagree with the Findings queue or the
// board pack. Every number traces to a real finding; nothing is invented.
import { slaState, isKnownExploited, OPEN_STATES, SEVERITY_LEVELS } from "./workflow.js";
import { cleanTitle } from "./queue-format.js";

const low = (v) => String(v == null ? "" : v).toLowerCase();
const OPEN = new Set(OPEN_STATES);
const isFinding = (e) => e && low(e.type) === "finding";
const isOpen = (e) => OPEN.has(low(e.status) || "new");
const sevOf = (e) => { const s = low(e.severity); return SEVERITY_LEVELS.includes(s) ? s : "info"; };
const emptySev = () => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
const sevRank = (s) => { const i = SEVERITY_LEVELS.indexOf(s); return i < 0 ? SEVERITY_LEVELS.length : i; };
// Overdue sorts before due_soon before on_track before the rest.
const STATE_RANK = { overdue: 0, due_soon: 1, on_track: 2, none: 3, excepted: 4, closed: 5 };

function itemOf(e, policy, now, kevSet) {
  const s = slaState(e, policy, now, { kevSet });
  const d = e.data || {};
  return {
    id: e.id,
    name: cleanTitle(e) || String(e.id || ""),
    severity: sevOf(e),
    source: e.source || d.tool || "unknown",
    category: low(d.category) || "",
    kev: !!isKnownExploited(e, kevSet),
    dueAt: s.dueAt,
    daysLeft: s.daysLeft,
    state: s.state,
  };
}
// Most-urgent first: overdue > due_soon, then by severity, then soonest due, then name.
function urgency(a, b) {
  return (STATE_RANK[a.state] ?? 9) - (STATE_RANK[b.state] ?? 9)
    || sevRank(a.severity) - sevRank(b.severity)
    || ((a.daysLeft == null ? Infinity : a.daysLeft) - (b.daysLeft == null ? Infinity : b.daysLeft))
    || a.name.localeCompare(b.name);
}

/**
 * remediationPlan(entities, opts) -> a plan grouping every OPEN finding by its owner.
 * opts: { now, policy, kevSet }.
 * -> { owners: [{ owner, ownerLabel, open, overdue, dueSoon, bySeverity, items:[item] }],
 *      unassignedOpen, totalOpen, overdue, asOf }
 * Owner groups are sorted by overdue desc, then open desc, then label; unassigned sorts last.
 */
export function remediationPlan(entities, opts = {}) {
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const policy = opts.policy || undefined;
  const kevSet = opts.kevSet || null;
  const open = (Array.isArray(entities) ? entities : []).filter((e) => isFinding(e) && isOpen(e));

  const groups = new Map(); // ownerKey -> group
  const UNASSIGNED = "\u0000unassigned";
  let overdue = 0;
  for (const e of open) {
    const d = e.data || {};
    const owner = d.owner ? String(d.owner) : "";
    const key = owner || UNASSIGNED;
    if (!groups.has(key)) {
      groups.set(key, { owner, ownerLabel: owner ? (d.ownerLabel ? String(d.ownerLabel) : "") : "", open: 0, overdue: 0, dueSoon: 0, bySeverity: emptySev(), items: [] });
    }
    const g = groups.get(key);
    // Prefer a non-empty stored label if any finding carries one.
    if (owner && !g.ownerLabel && d.ownerLabel) g.ownerLabel = String(d.ownerLabel);
    const it = itemOf(e, policy, now, kevSet);
    g.items.push(it); g.open++; g.bySeverity[it.severity]++;
    if (it.state === "overdue") { g.overdue++; overdue++; }
    else if (it.state === "due_soon") g.dueSoon++;
  }

  const owners = [...groups.values()].map((g) => { g.items.sort(urgency); return g; })
    .sort((a, b) => {
      const au = a.owner ? 0 : 1, bu = b.owner ? 0 : 1; // unassigned last
      return au - bu || b.overdue - a.overdue || b.open - a.open
        || (a.ownerLabel || a.owner).localeCompare(b.ownerLabel || b.owner);
    });
  const un = groups.get(UNASSIGNED);
  return { owners, unassignedOpen: un ? un.open : 0, totalOpen: open.length, overdue, asOf: now };
}

/**
 * slaReport(entities, opts) -> the vulnerability SLA report: per-severity SLA target, open
 * count, on-track vs overdue and compliance %, plus a breach list (most overdue first).
 * opts: { now, policy, kevSet }.
 * -> { bySeverity: [{ severity, targetDays, open, onTrack, dueSoon, overdue, noDate, compliancePct }],
 *      overall: { open, withDate, onTrack, overdue, compliancePct, kevOpen, kevOverdue },
 *      breaches: [{ id, name, severity, source, daysOverdue, kev }], asOf }
 * compliancePct is over findings that have an SLA date (excepted/no-date excluded), matching
 * the board report's definition so the two never disagree.
 */
export function slaReport(entities, opts = {}) {
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const policy = opts.policy || undefined;
  const kevSet = opts.kevSet || null;
  const open = (Array.isArray(entities) ? entities : []).filter((e) => isFinding(e) && isOpen(e));

  const per = {}; for (const s of SEVERITY_LEVELS) per[s] = { severity: s, targetDays: null, open: 0, onTrack: 0, dueSoon: 0, overdue: 0, excepted: 0, noDate: 0, withDate: 0 };
  const overall = { open: open.length, withDate: 0, onTrack: 0, overdue: 0, compliancePct: null, kevOpen: 0, kevOverdue: 0 };
  const breaches = [];

  for (const e of open) {
    const sev = sevOf(e);
    const row = per[sev];
    row.open++;
    const s = slaState(e, policy, now, { kevSet });
    const kev = !!isKnownExploited(e, kevSet);
    if (kev) overall.kevOpen++;
    if (row.targetDays == null && s.dueAt != null) {
      const created = Date.parse(e.createdAt); // target span in days, when derivable
      if (Number.isFinite(created)) row.targetDays = Math.round((s.dueAt - created) / 86400000);
    }
    if (s.state === "excepted") { row.excepted++; }
    else if (s.dueAt == null) { row.noDate++; }
    else {
      row.withDate++; overall.withDate++;
      if (s.state === "overdue") {
        row.overdue++; overall.overdue++; if (kev) overall.kevOverdue++;
        const daysOverdue = s.daysLeft == null ? 0 : Math.max(0, -s.daysLeft);
        breaches.push({ id: e.id, name: cleanTitle(e) || String(e.id || ""), severity: sev, source: e.source || (e.data && e.data.tool) || "unknown", daysOverdue, kev });
      } else { row.onTrack++; overall.onTrack++; if (s.state === "due_soon") row.dueSoon++; }
    }
  }

  const bySeverity = SEVERITY_LEVELS.map((s) => {
    const r = per[s];
    return { severity: s, targetDays: r.targetDays, open: r.open, onTrack: r.onTrack, dueSoon: r.dueSoon, overdue: r.overdue, excepted: r.excepted, noDate: r.noDate, compliancePct: r.withDate ? Math.round((r.onTrack / r.withDate) * 100) : null };
  });
  overall.compliancePct = overall.withDate ? Math.round((overall.onTrack / overall.withDate) * 100) : null;
  breaches.sort((a, b) => b.daysOverdue - a.daysOverdue || sevRank(a.severity) - sevRank(b.severity) || a.name.localeCompare(b.name));
  return { bySeverity, overall, breaches, asOf: now };
}
