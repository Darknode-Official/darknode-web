// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Pure findings workflow engine: SLA due dates, triage changes (assign, status,
// comment, severity, due date, risk exception, ticket), verify-fixed / regression
// reconciliation after a tool re-run, exception expiry and the queue views.
//
// No DOM, no storage, no network. Every function takes `now` (ms) rather than reading
// the clock, so results are deterministic; it falls back to Date.now() only when omitted.
// Changes return `updates` shaped for security-graph updateEntity(id, updates), which
// merges `data` shallowly: each update carries only the data fields it changes (arrays
// such as history are returned whole), and a cleared field is set to null.
//
// Workflow state lives in entity.data (see WORKFLOW_FIELDS). Tool re-runs never touch
// it: core/sink-map.js mergeToolData keeps these fields from the existing entity.

import { isSimulated } from "./posture.js";
import { canDo } from "./workspace-roles.js";

/** Remediation days per severity (null = no SLA). kev applies when it is sooner. */
export const SLA_DEFAULTS = { critical: 30, high: 60, medium: 90, low: 180, info: null, kev: 14 };
export const SLA_SOURCES = {
  critical: "PCI DSS v4.0 req. 6.3.3 (critical patches within one month)",
  kev: "CISA BOD 22-01 (known-exploited: two weeks)",
  other: "editable defaults, not a standard",
};
export const VIEWS = ["mine", "unassigned", "overdue", "due_week", "excepted", "open", "all"];
export const VIEW_LABEL = { mine: "My queue", unassigned: "Unassigned", overdue: "Overdue", due_week: "Due this week", excepted: "Exceptions", open: "All open", all: "All" };
export const RESOLUTIONS = ["fixed", "accepted", "false_positive", "duplicate"];
export const WORKFLOW_STATUSES = ["new", "open", "investigating", "resolved", "closed"];
export const OPEN_STATES = ["new", "open", "investigating"];
export const SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"];

/** entity.data keys owned by the workflow; a tool re-run never overwrites or moves them. */
export const WORKFLOW_FIELDS = [
  "owner", "ownerLabel", "history", "historyCount", "comments", "commentCount",
  "exception", "exceptionHistory", "tickets", "dueAt", "dueReason", "severityOverride",
  "regressed", "regressedAt", "verifiedBy", "verifiedAt",
];

export const DAY_MS = 86400000;
export const HISTORY_CAP = 100;
export const COMMENT_CAP = 200;
export const COMMENT_MAX = 4000;
export const TICKET_CAP = 20;
export const EXCEPTION_HISTORY_CAP = 20;
export const EXCEPTION_MAX_DAYS = 365;
const SOON_DAYS = 7;
const REASON_MAX = 500;

const str = (v) => String(v == null ? "" : v);
const clock = (now) => (Number.isFinite(now) ? now : Date.now());
const toMs = (v) => {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string" && v) { const n = Date.parse(v); return Number.isFinite(n) ? n : null; }
  return null;
};
const statusOf = (e) => str(e && e.status).toLowerCase() || "new";
const isOpen = (e) => OPEN_STATES.includes(statusOf(e));
const dataOf = (e) => (e && e.data && typeof e.data === "object" ? e.data : {});
const activeException = (d, now) => {
  const x = d.exception;
  if (!x || typeof x !== "object") return false;
  const exp = toMs(x.expiresAt);
  return exp != null && exp > now;
};

/**
 * Coerce a stored/edited SLA policy into { critical, high, medium, low, info, kev }:
 * each a positive integer number of days or null (no SLA). Anything else falls back
 * to that key's default; a non-object gives the defaults.
 * @param {object} p
 * @returns {{critical:number|null,high:number|null,medium:number|null,low:number|null,info:number|null,kev:number|null}}
 */
export function normalizePolicy(p) {
  const src = p && typeof p === "object" && !Array.isArray(p) ? p : {};
  const out = {};
  for (const k of Object.keys(SLA_DEFAULTS)) {
    const v = src[k];
    if (v === null) { out[k] = null; continue; }
    const n = typeof v === "string" && v.trim() ? Number(v) : v;
    out[k] = typeof n === "number" && Number.isInteger(n) && n > 0 && n <= 3650 ? n : SLA_DEFAULTS[k];
  }
  return out;
}

const CVE_RE = /CVE-\d{4}-\d+/gi;
/** CVE ids a finding mentions: data.cve / data.cves, its name and its evidence. Upper-case, unique. */
export function cveIds(entity) {
  const d = dataOf(entity), found = new Set();
  const scan = (s) => { for (const m of str(s).match(CVE_RE) || []) found.add(m.toUpperCase()); };
  for (const v of [].concat(d.cve || [], d.cves || [])) scan(v);
  scan(entity && entity.name);
  if (d.evidence != null) { try { scan(JSON.stringify(d.evidence)); } catch (_) {} }
  return Array.from(found);
}

/**
 * Known-exploited: data.kev === true, or any CVE it mentions is in kevSet (Set or array).
 * @param {object} entity
 * @param {Set<string>|string[]} [kevSet]
 */
export function isKnownExploited(entity, kevSet) {
  if (dataOf(entity).kev === true) return true;
  if (!kevSet) return false;
  const has = typeof kevSet.has === "function" ? (id) => kevSet.has(id) : (id) => kevSet.includes(id);
  return cveIds(entity).some(has);
}

/**
 * Remediation due date (ms) or null. Start = entity.createdAt (first seen); days =
 * policy[severity], or policy.kev when known-exploited and sooner. A manual data.dueAt
 * wins. Severity info (by default) or a null policy entry gives null.
 * @param {object} entity
 * @param {object} policy
 * @param {{ kevSet?: Set<string>|string[] }} [o]
 * @returns {number|null}
 */
export function computeDue(entity, policy, { kevSet } = {}) {
  const d = dataOf(entity);
  const manual = toMs(d.dueAt);
  if (manual != null) return manual;
  const pol = normalizePolicy(policy);
  const sev = str(entity && entity.severity).toLowerCase();
  if (!SEVERITY_LEVELS.includes(sev) || sev === "info") return null;
  let days = pol[sev];
  if (days == null) return null;
  if (pol.kev != null && pol.kev < days && isKnownExploited(entity, kevSet)) days = pol.kev;
  const start = toMs(entity && entity.createdAt);
  return start == null ? null : start + days * DAY_MS;
}

/**
 * SLA position at `now`. state: closed | excepted | none | overdue | due_soon | on_track.
 * daysLeft = ceil((dueAt - now) / 1 day), negative once overdue by a full day; null with no due date.
 * @param {object} entity
 * @param {object} policy
 * @param {number} [now]
 * @param {{ kevSet?: Set<string>|string[] }} [o]
 * @returns {{ dueAt:number|null, daysLeft:number|null, state:string }}
 */
export function slaState(entity, policy, now, o = {}) {
  now = clock(now);
  const dueAt = computeDue(entity, policy, o);
  const daysLeft = dueAt == null ? null : (Math.ceil((dueAt - now) / DAY_MS) || 0);
  let state;
  if (!isOpen(entity)) state = "closed";
  else if (activeException(dataOf(entity), now)) state = "excepted";
  else if (dueAt == null) state = "none";
  else if (now > dueAt) state = "overdue";
  else if (dueAt - now <= SOON_DAYS * DAY_MS) state = "due_soon";
  else state = "on_track";
  return { dueAt, daysLeft, state };
}

// Append history entries (newest HISTORY_CAP kept; historyCount = total ever) into `out`.
function addHistory(d, out, entries) {
  const prev = Array.isArray(d.history) ? d.history : [];
  const total = Number.isFinite(d.historyCount) ? d.historyCount : prev.length;
  out.history = prev.concat(entries).slice(-HISTORY_CAP);
  out.historyCount = total + entries.length;
  return out;
}
const entry = (ts, uid, field, from, to) => ({ ts, uid, field, from: from === undefined ? null : from, to: to === undefined ? null : to });
const reasonOf = (r) => str(r).trim().slice(0, REASON_MAX);

/**
 * Apply one analyst change. Never mutates `entity`. Returns { updates } for
 * updateEntity(entity.id, updates) ({ updates: {}, noop: true } when nothing would
 * change), or { error } with a message fit to show.
 * change ops: assign | status | comment | severity | due | exception | revokeException | ticket
 * @param {object} entity
 * @param {object} change
 * @param {{ uid?: string, now?: number, role?: string }} [ctx]
 * @returns {{ updates: object, noop?: true } | { error: string }}
 */
export function applyChange(entity, change, ctx = {}) {
  if (ctx.role !== undefined && !canDo(ctx.role, "write")) return { error: "Read-only role" };
  if (!entity || typeof entity !== "object") return { error: "Finding not found" };
  const c = change || {}, d = dataOf(entity), now = clock(ctx.now), uid = ctx.uid == null ? null : str(ctx.uid);
  const noop = { updates: {}, noop: true };
  const H = (field, from, to) => entry(now, uid, field, from, to);
  const status = statusOf(entity);

  switch (c.op) {
    case "assign": {
      const owner = c.owner == null || str(c.owner).trim() === "" ? null : str(c.owner).trim();
      const ownerLabel = owner ? (str(c.ownerLabel).trim().slice(0, 120) || null) : null;
      const prev = d.owner == null ? null : d.owner;
      if (prev === owner && (d.ownerLabel == null ? null : d.ownerLabel) === ownerLabel) return noop;
      const data = { owner, ownerLabel };
      return { updates: { data: prev === owner ? data : addHistory(d, data, [H("owner", prev, owner)]) } };
    }
    case "status": {
      const to = str(c.status).toLowerCase();
      if (!WORKFLOW_STATUSES.includes(to)) return { error: "Unknown status" };
      const closing = to === "resolved" || to === "closed";
      let resolution = null;
      if (closing) {
        if (c.resolution == null || c.resolution === "") return { error: "Choose a resolution" };
        resolution = str(c.resolution);
        if (!RESOLUTIONS.includes(resolution)) return { error: "Unknown resolution" };
        if (resolution === "accepted" && !activeException(d, now)) return { error: "Accepting a risk needs an exception with an expiry" };
      }
      const prevRes = d.resolution == null ? null : d.resolution;
      if (to === status && prevRes === resolution) return noop;
      const hist = [];
      if (to !== status) hist.push(H("status", status, to));
      if (prevRes !== resolution) hist.push(H("resolution", prevRes, resolution));
      const updates = { data: addHistory(d, { resolution }, hist) };
      if (to !== status) updates.status = to;
      return { updates };
    }
    case "comment": {
      const text = str(c.text).trim();
      if (!text) return { error: "Comment is empty" };
      if (text.length > COMMENT_MAX) return { error: `Comment is too long (${COMMENT_MAX} characters max)` };
      const prev = Array.isArray(d.comments) ? d.comments : [];
      const total = Number.isFinite(d.commentCount) ? d.commentCount : prev.length;
      // Comments are their own log (timeline merges them); they add no history entry.
      return { updates: { data: { comments: prev.concat([{ ts: now, uid, text }]).slice(-COMMENT_CAP), commentCount: total + 1 } } };
    }
    case "severity": {
      const to = str(c.severity).toLowerCase();
      if (!SEVERITY_LEVELS.includes(to)) return { error: "Unknown severity" };
      const reason = reasonOf(c.reason);
      if (!reason) return { error: "Give a reason for changing the severity" };
      const from = entity.severity == null ? null : str(entity.severity).toLowerCase();
      if (from === to) return noop;
      const data = addHistory(d, { severityOverride: { from, to, reason, uid, ts: now } }, [H("severity", from, to)]);
      return { updates: { severity: to, data } };
    }
    case "due": {
      const prev = toMs(d.dueAt);
      if (c.dueAt == null) {
        if (prev == null) return noop;
        return { updates: { data: addHistory(d, { dueAt: null, dueReason: null }, [H("dueAt", prev, null)]) } };
      }
      const at = toMs(c.dueAt);
      if (at == null || at <= 0) return { error: "Pick a valid due date" };
      const reason = reasonOf(c.reason);
      if (!reason) return { error: "Give a reason for the due date" };
      if (at === prev && reason === d.dueReason) return noop;
      return { updates: { data: addHistory(d, { dueAt: at, dueReason: reason }, [H("dueAt", prev, at)]) } };
    }
    case "exception": {
      const reason = reasonOf(c.reason), approver = str(c.approver).trim().slice(0, 120);
      if (!reason) return { error: "Give a reason for the exception" };
      if (!approver) return { error: "Name who approved the exception" };
      const exp = toMs(c.expiresAt);
      if (exp == null || exp <= now) return { error: "The exception must expire in the future" };
      if (exp > now + EXCEPTION_MAX_DAYS * DAY_MS) return { error: `An exception can last at most ${EXCEPTION_MAX_DAYS} days` };
      const riskId = str(c.riskId).trim().slice(0, 120) || null;
      const prev = d.exception && typeof d.exception === "object" ? d.exception : null;
      const data = { exception: { reason, approver, expiresAt: exp, riskId, by: uid, ts: now } };
      // A replaced exception is kept in exceptionHistory, like an expired or revoked one.
      if (prev) data.exceptionHistory = (Array.isArray(d.exceptionHistory) ? d.exceptionHistory : []).concat([{ ...prev, replacedAt: now, replacedBy: uid }]).slice(-EXCEPTION_HISTORY_CAP);
      return { updates: { data: addHistory(d, data, [H("exception", prev ? toMs(prev.expiresAt) : null, exp)]) } };
    }
    case "revokeException": {
      const prev = d.exception && typeof d.exception === "object" ? d.exception : null;
      if (!prev) return { error: "No exception to revoke" };
      const reason = reasonOf(c.reason) || null;
      const data = {
        exception: null,
        exceptionHistory: (Array.isArray(d.exceptionHistory) ? d.exceptionHistory : []).concat([{ ...prev, revokedAt: now, revokedBy: uid, revokeReason: reason }]).slice(-EXCEPTION_HISTORY_CAP),
      };
      const hist = [H("exception", toMs(prev.expiresAt), null)];
      const updates = {};
      if ((status === "resolved" || status === "closed") && d.resolution === "accepted") {
        data.resolution = null;
        updates.status = "open";
        hist.push(H("status", status, "open"), H("resolution", "accepted", null));
      }
      updates.data = addHistory(d, data, hist);
      return { updates };
    }
    case "ticket": {
      let u;
      try { u = new URL(str(c.url).trim()); } catch (_) { return { error: "Enter a full https:// ticket link" }; }
      if (u.protocol !== "https:") return { error: "Ticket links must use https" };
      const url = u.href, label = str(c.label).trim().slice(0, 120) || u.host;
      const prev = Array.isArray(d.tickets) ? d.tickets : [];
      const old = prev.find((t) => t && t.url === url);
      if (old && old.label === label) return noop;
      const tickets = prev.filter((t) => t && t.url !== url).concat([{ url, label, ts: now, uid }]).slice(-TICKET_CAP);
      return { updates: { data: addHistory(d, { tickets }, [H("ticket", old ? old.url : null, url)]) } };
    }
    default:
      return { error: "Unknown change" };
  }
}

/**
 * applyChange over many entities with one ctx (same `now` for all).
 * @returns {({ id: string, updates: object, noop?: true } | { id: string, error: string })[]}
 */
export function applyBulk(entities, change, ctx = {}) {
  const c = { ...ctx, now: clock(ctx.now) };
  return (entities || []).map((e) => ({ id: e && e.id, ...applyChange(e, change, c) }));
}

/**
 * Verify-fixed and regression after a run of `toolId` over `dataset`. Considers only
 * prevEntities from that tool with that data.dataset (never sample/simulated ones), as
 * they were BEFORE the run was written. currentKeys = the run's findingKeys.
 *  - open/new/investigating and absent from the run  -> fixed (resolved, resolution fixed)
 *  - resolved/closed as fixed and present in the run -> regressed (reopened)
 * accepted / false_positive / duplicate are never touched. With no dataset name nothing is
 * marked fixed (an unnamed input says nothing about what disappeared). ctx.regressOnly
 * ignores the dataset scope and returns only regressions (a key present in the run is the
 * same finding whatever input it came from).
 * This is the ONLY place a tool run reopens a fixed finding (sink-map nextStatus defers
 * to it for sink findings), so every reopen gets a history entry.
 * @param {string} toolId
 * @param {string} dataset
 * @param {object[]} prevEntities
 * @param {Iterable<string>} currentKeys
 * @param {{ now?: number, regressOnly?: boolean }} [ctx]
 * @returns {{ fixed: {id:string,updates:object}[], regressed: {id:string,updates:object}[] }}
 */
export function reconcileRun(toolId, dataset, prevEntities, currentKeys, ctx = {}) {
  const now = clock(ctx.now), uid = "system:" + str(toolId), keys = new Set(currentKeys || []);
  const fixed = [], regressed = [];
  const canFix = !ctx.regressOnly && !!dataset;
  for (const e of prevEntities || []) {
    if (!e || isSimulated(e)) continue;
    const d = dataOf(e);
    if (d.tool !== toolId || !d.findingKey) continue;
    if (!ctx.regressOnly && d.dataset !== dataset) continue;
    const st = statusOf(e), present = keys.has(d.findingKey);
    if (canFix && OPEN_STATES.includes(st) && !present) {
      const prevRes = d.resolution == null ? null : d.resolution;
      const data = addHistory(d, { resolution: "fixed", verifiedBy: str(toolId), verifiedAt: now },
        [entry(now, uid, "status", st, "resolved"), ...(prevRes !== "fixed" ? [entry(now, uid, "resolution", prevRes, "fixed")] : [])]);
      fixed.push({ id: e.id, updates: { status: "resolved", data } });
    } else if ((st === "resolved" || st === "closed") && d.resolution === "fixed" && present) {
      const data = addHistory(d, { resolution: null, regressed: true, regressedAt: now },
        [entry(now, uid, "status", st, "open"), entry(now, uid, "resolution", "fixed", null)]);
      regressed.push({ id: e.id, updates: { status: "open", data } });
    }
  }
  return { fixed, regressed };
}

/**
 * Exceptions whose expiresAt <= now: moved to exceptionHistory; a finding accepted on
 * the strength of that exception reopens.
 * @param {object[]} entities
 * @param {number} [now]
 * @returns {{ id: string, updates: object }[]}
 */
export function expiredExceptions(entities, now) {
  now = clock(now);
  const out = [], uid = "system:sla";
  for (const e of entities || []) {
    const d = dataOf(e), x = d.exception;
    if (!x || typeof x !== "object") continue;
    const exp = toMs(x.expiresAt);
    if (exp == null || exp > now) continue;
    const data = {
      exception: null,
      exceptionHistory: (Array.isArray(d.exceptionHistory) ? d.exceptionHistory : []).concat([{ ...x, expiredAt: now }]).slice(-EXCEPTION_HISTORY_CAP),
    };
    const hist = [entry(now, uid, "exception", exp, null)];
    const updates = {};
    const st = statusOf(e);
    if (d.resolution === "accepted") {
      data.resolution = null;
      hist.push(entry(now, uid, "resolution", "accepted", null));
      if (st === "resolved" || st === "closed") { updates.status = "open"; hist.push(entry(now, uid, "status", st, "open")); }
    }
    updates.data = addHistory(d, data, hist);
    out.push({ id: e.id, updates });
  }
  return out;
}

/**
 * Does `entity` belong in queue `view`? Sample/simulated entities only appear in "all".
 * @param {object} entity
 * @param {string} view one of VIEWS
 * @param {{ uid?: string, now?: number, policy?: object, kevSet?: Set<string>|string[] }} [o]
 * @returns {boolean}
 */
export function inView(entity, view, { uid, now, policy, kevSet } = {}) {
  if (!entity) return false;
  if (view === "all") return true;
  if (isSimulated(entity)) return false;
  const d = dataOf(entity), open = isOpen(entity);
  now = clock(now);
  switch (view) {
    case "mine": return open && !!uid && d.owner === uid;
    case "unassigned": return open && !d.owner;
    case "overdue": return slaState(entity, policy, now, { kevSet }).state === "overdue";
    case "due_week": return slaState(entity, policy, now, { kevSet }).state === "due_soon";
    case "excepted": return activeException(d, now);
    case "open": return open;
    default: return false;
  }
}

/**
 * History and comments merged, oldest first (stable: a change sorts before a comment
 * with the same ts).
 * @param {object} entity
 * @returns {{ ts:number, uid:string|null, kind:"change"|"comment", field?:string, from?:any, to?:any, text?:string }[]}
 */
export function timeline(entity) {
  const d = dataOf(entity);
  const rows = [];
  for (const h of Array.isArray(d.history) ? d.history : []) if (h) rows.push({ ts: h.ts, uid: h.uid == null ? null : h.uid, kind: "change", field: h.field, from: h.from, to: h.to });
  for (const c of Array.isArray(d.comments) ? d.comments : []) if (c) rows.push({ ts: c.ts, uid: c.uid == null ? null : c.uid, kind: "comment", text: c.text });
  return rows.map((r, i) => [r, i]).sort((a, b) => (toMs(a[0].ts) || 0) - (toMs(b[0].ts) || 0) || a[1] - b[1]).map((x) => x[0]);
}
