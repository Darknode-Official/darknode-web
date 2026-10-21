// Workspace security metrics + daily trend snapshot (Deck D7). PURE — no DOM, no network,
// deterministic. Reads FINDING entities out of the graph and produces one snapshot object:
// the numbers the Overview, Reports and board pack chart, and the row the trend store keeps
// one of per day. Every number traces to a finding; nothing is invented.
//
// It reuses the D1 work-queue engine (core/workflow.js) for SLA position and known-exploited
// detection, and the D7 exposure engine (core/exposure-score.js) for the headline score, so
// the snapshot never disagrees with what the Findings queue shows.
import { slaState, isKnownExploited, OPEN_STATES, SEVERITY_LEVELS, WORKFLOW_STATUSES, DAY_MS } from "./workflow.js";
import { exposureScore } from "./exposure-score.js";

const str = (v) => String(v == null ? "" : v).toLowerCase();
const toMs = (v) => { if (typeof v === "number") return Number.isFinite(v) ? v : null; if (typeof v === "string" && v) { const n = Date.parse(v); return Number.isFinite(n) ? n : null; } return null; };
const OPEN = new Set(OPEN_STATES);
const isFinding = (e) => e && str(e.type) === "finding";
const isOpen = (e) => OPEN.has(str(e.status) || "new");

// First time this finding moved into a closed/resolved state (for MTTR), from its history.
function resolvedAt(e) {
  const h = e && e.data && Array.isArray(e.data.history) ? e.data.history : [];
  let best = null;
  for (const x of h) {
    if (x && x.field === "status" && (str(x.to) === "resolved" || str(x.to) === "closed")) {
      const t = toMs(x.ts);
      if (t != null && (best == null || t < best)) best = t;
    }
  }
  return best;
}

/**
 * snapshot(entities, opts) -> a deterministic metrics object.
 * opts: { now, policy (SLA policy), kevSet, coverage (0..1 from the inventory), criticality }.
 */
export function snapshot(entities, opts = {}) {
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const policy = opts.policy || undefined;
  const kevSet = opts.kevSet || null;
  const findings = (Array.isArray(entities) ? entities : []).filter(isFinding);

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }; // over OPEN findings
  const byStatus = {}; for (const s of WORKFLOW_STATUSES) byStatus[s] = 0;
  const byTool = Object.create(null), byCategory = Object.create(null); // keyed by untrusted tool/category strings — null-proto so "__proto__"/"constructor" are real counts, not pollution
  const sla = { overdue: 0, due_soon: 0, on_track: 0, excepted: 0, none: 0 };
  const aging = { "0-7": 0, "8-30": 0, "31-90": 0, "90+": 0 }; // open findings by age in days
  let open = 0, closed = 0, kevOpen = 0, withDue = 0, notOverdue = 0;
  let mttrSum = 0, mttrN = 0;

  for (const e of findings) {
    const st = str(e.status) || "new";
    byStatus[WORKFLOW_STATUSES.includes(st) ? st : "open"] = (byStatus[WORKFLOW_STATUSES.includes(st) ? st : "open"] || 0) + 1;
    if (isOpen(e)) {
      open++;
      const sev = str(e.severity);
      if (Object.prototype.hasOwnProperty.call(bySeverity, sev)) bySeverity[sev]++; // own-key only: `in` would match inherited "toString" etc. and make a NaN bucket
      const tool = e.source || (e.data && e.data.tool) || "unknown";
      byTool[tool] = (byTool[tool] || 0) + 1;
      const cat = str((e.data && e.data.category) || "uncategorised") || "uncategorised";
      byCategory[cat] = (byCategory[cat] || 0) + 1;
      if (isKnownExploited(e, kevSet)) kevOpen++;
      const s = slaState(e, policy, now, { kevSet });
      if (s.state === "overdue") sla.overdue++;
      else if (s.state === "due_soon") sla.due_soon++;
      else if (s.state === "on_track") sla.on_track++;
      else if (s.state === "excepted") sla.excepted++;
      else sla.none++;
      if (s.dueAt != null && s.state !== "excepted") { withDue++; if (s.state !== "overdue") notOverdue++; }
      const created = toMs(e.createdAt);
      const ageD = created == null ? 0 : Math.floor((now - created) / DAY_MS);
      if (ageD <= 7) aging["0-7"]++; else if (ageD <= 30) aging["8-30"]++; else if (ageD <= 90) aging["31-90"]++; else aging["90+"]++;
    } else {
      closed++;
      const created = toMs(e.createdAt), done = resolvedAt(e);
      if (created != null && done != null && done >= created) { mttrSum += (done - created) / DAY_MS; mttrN++; }
    }
  }

  const exp = exposureScore(findings, { now, policy, kevSet, criticality: opts.criticality });
  const coverage = Number.isFinite(opts.coverage) ? Math.max(0, Math.min(1, opts.coverage)) : null;

  return {
    ts: now,
    day: new Date(now).toISOString().slice(0, 10),
    findings: findings.length,
    open, closed,
    bySeverity, byStatus, byTool, byCategory,
    sla,
    slaCompliancePct: withDue ? Math.round((notOverdue / withDue) * 100) : null,
    aging,
    mttrDays: mttrN ? Math.round((mttrSum / mttrN) * 10) / 10 : null,
    mttrSampleSize: mttrN,
    kevOpen,
    coverage,
    exposureScore: exp.score,
    exposure: { raw: exp.raw, k: exp.k, contributing: exp.contributing, components: exp.components, top: exp.top },
  };
}

// Compare two snapshots for a board report's "quarter over quarter" deltas. Returns the
// signed change in the headline numbers; nulls (unknown) pass through as null.
export function trendDelta(current, previous) {
  if (!current) return null;
  const d = (a, b) => (a == null || b == null ? null : a - b);
  const p = previous || {};
  return {
    open: d(current.open, p.open),
    closed: d(current.closed, p.closed),
    exposureScore: d(current.exposureScore, p.exposureScore),
    slaCompliancePct: d(current.slaCompliancePct, p.slaCompliancePct),
    mttrDays: d(current.mttrDays, p.mttrDays),
    kevOpen: d(current.kevOpen, p.kevOpen),
    criticalHigh: d((current.bySeverity.critical + current.bySeverity.high), p.bySeverity ? (p.bySeverity.critical + p.bySeverity.high) : null),
  };
}

export { SEVERITY_LEVELS };
