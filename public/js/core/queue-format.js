// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// Pure presentation helpers for the Deck findings work queue (deck/findings-queue.js):
// due chips, urgency order, owner names, readable timeline sentences, evidence lines,
// bulk-result summaries and saved-view lists. No DOM, no storage, no clock reads:
// every function that needs "now" takes it, so the output is deterministic.

import { DAY_MS, OPEN_STATES, SEVERITY_LEVELS, isKnownExploited, normalizePolicy, EXCEPTION_MAX_DAYS } from "./workflow.js";

export const RESOLUTION_LABEL = { fixed: "Fixed", accepted: "Risk accepted", false_positive: "False positive", duplicate: "Duplicate" };
export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const SAVED_VIEWS_MAX = 30;
export const SAVED_NAME_MAX = 60;

const str = (v) => String(v == null ? "" : v);
const toMs = (v) => {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string" && v) { const n = Date.parse(v); return Number.isFinite(n) ? n : null; }
  return null;
};

/** YYYY-MM-DD (UTC) for a ms / ISO value, or "" when unparseable. The default date formatter. */
export function isoDay(v) {
  const ms = toMs(v);
  return ms == null ? "" : new Date(ms).toISOString().slice(0, 10);
}

/** Readable status with its resolution: "Resolved (fixed)", "Open". */
export function statusText(status, resolution) {
  const s = str(status || "new");
  const base = s.charAt(0).toUpperCase() + s.slice(1);
  return resolution && RESOLUTION_LABEL[resolution] ? `${base} (${RESOLUTION_LABEL[resolution].toLowerCase()})` : base;
}

/**
 * The Due column chip for an slaState() result.
 * @param {{ dueAt:number|null, daysLeft:number|null, state:string }} sla
 * @param {number} now
 * @param {(ms:number)=>string} [fmtDate]
 * @returns {{ cls: string, text: string }} cls: overdue | soon | track | exc | none
 */
export function dueChip(sla, now, fmtDate = isoDay) {
  const s = sla || {};
  switch (s.state) {
    case "overdue": {
      const n = Math.max(1, Math.ceil((now - s.dueAt) / DAY_MS));
      return { cls: "overdue", text: `${n}d overdue` };
    }
    case "due_soon": {
      const n = Math.max(0, s.daysLeft == null ? 0 : s.daysLeft);
      return { cls: "soon", text: n === 0 ? "Due today" : `Due in ${n}d` };
    }
    case "on_track": return { cls: "track", text: fmtDate(s.dueAt) };
    case "excepted": return { cls: "exc", text: "Exception" };
    default: return { cls: "none", text: "-" };
  }
}

/**
 * How the due date was set, in one line, e.g. "High: 60 days from first seen".
 * @param {object} entity
 * @param {object} policy
 * @param {Set<string>|string[]} [kevSet]
 * @param {(ms:number)=>string} [fmtDate]
 */
export function slaBasis(entity, policy, kevSet, fmtDate = isoDay) {
  const d = (entity && entity.data) || {};
  if (toMs(d.dueAt) != null) return `Set manually${d.dueReason ? ": " + str(d.dueReason) : ""}`;
  const pol = normalizePolicy(policy);
  const sev = str(entity && entity.severity).toLowerCase();
  if (!SEVERITY_LEVELS.includes(sev)) return "No severity, so no SLA";
  const days = sev === "info" ? null : pol[sev];
  if (days == null) return `No SLA for ${sev} severity`;
  if (pol.kev != null && pol.kev < days && isKnownExploited(entity, kevSet)) return `Known exploited (CISA KEV): ${pol.kev} days from first seen`;
  const label = sev.charAt(0).toUpperCase() + sev.slice(1);
  const first = toMs(entity && entity.createdAt);
  return `${label}: ${days} days from first seen${first != null ? " (" + fmtDate(first) + ")" : ""}`;
}

/**
 * Order rows by SLA urgency: overdue (most overdue first), then due soon, then on track
 * (soonest first), then rows with no due date; ties by severity, then name.
 * @template T
 * @param {T[]} rows
 * @param {(row:T)=>{dueAt:number|null,state:string}} slaOf
 * @returns {T[]} a new array
 */
export function urgencySort(rows, slaOf) {
  const bucket = { overdue: 0, due_soon: 1, on_track: 2, excepted: 3, none: 4, closed: 5 };
  return (rows || []).map((r, i) => [r, slaOf(r) || {}, i]).sort((a, b) => {
    const ba = bucket[a[1].state] ?? 6, bb = bucket[b[1].state] ?? 6;
    if (ba !== bb) return ba - bb;
    const da = a[1].dueAt == null ? Infinity : a[1].dueAt, db = b[1].dueAt == null ? Infinity : b[1].dueAt;
    if (da !== db) return da < db ? -1 : 1;
    const sa = SEV_RANK[a[0].severity] ?? -1, sb = SEV_RANK[b[0].severity] ?? -1;
    if (sa !== sb) return sb - sa;
    return a[2] - b[2];
  }).map((x) => x[0]);
}

/** Finding title without the "(tool:key)" suffix the sink adds for dedupe. */
export function cleanTitle(entity) {
  const name = str(entity && entity.name).trim();
  const d = (entity && entity.data) || {};
  if (d.tool && d.findingKey) {
    const suf = ` (${d.tool}:${d.findingKey})`;
    if (name.endsWith(suf)) return name.slice(0, -suf.length).trim() || name;
  }
  return name;
}

/**
 * A member's display name. members: [{ uid, label }]. The signed-in user shows as
 * "<label> (you)"; an unknown uid falls back to `fallback` (e.g. data.ownerLabel), then
 * to a short uid.
 */
export function memberName(uid, members, { myUid, fallback } = {}) {
  if (!uid) return "Unassigned";
  const m = (members || []).find((x) => x && x.uid === uid);
  const label = str((m && m.label) || fallback).trim() || (str(uid).length > 10 ? str(uid).slice(0, 8) + "..." : str(uid));
  return uid === myUid ? `${label} (you)` : label;
}

/** Who did a timeline change: "system:<tool>" is "<tool> re-run", system:sla the expiry check. */
export function whoLabel(uid, nameOf, toolName) {
  const u = str(uid);
  if (!u) return "Someone";
  if (u === "system:sla") return "Exception expiry check";
  if (u.startsWith("system:")) { const t = u.slice(7); return `${(t && toolName && toolName(t)) || t || "Tool"} re-run`; }
  return nameOf ? nameOf(u) : u;
}

/**
 * timeline() rows -> readable sentences, oldest first. A status change and the resolution
 * change recorded with it (same ts and uid) read as one sentence.
 * @param {object[]} rows from workflow.timeline(entity)
 * @param {{ nameOf?: (uid:string)=>string, toolName?: (id:string)=>string|null, fmtDate?: (ms:number)=>string }} [o]
 * @returns {{ ts:number, uid:string|null, kind:"change"|"comment", text:string, comment?:string }[]}
 */
export function timelineSentences(rows, { nameOf, toolName, fmtDate = isoDay } = {}) {
  const out = [];
  const list = rows || [];
  const res = (r) => (r && RESOLUTION_LABEL[r] ? RESOLUTION_LABEL[r].toLowerCase() : str(r));
  for (let i = 0; i < list.length; i++) {
    const r = list[i];
    if (!r) continue;
    const who = whoLabel(r.uid, nameOf, toolName);
    if (r.kind === "comment") { out.push({ ts: r.ts, uid: r.uid, kind: "comment", text: `${who} commented`, comment: str(r.text) }); continue; }
    let text;
    switch (r.field) {
      case "status": {
        const nx = list[i + 1];
        const pair = nx && nx.kind === "change" && nx.field === "resolution" && nx.ts === r.ts && nx.uid === r.uid ? nx : null;
        if (pair) i++;
        text = `${who} changed status from ${str(r.from || "new")} to ${str(r.to)}${pair && pair.to ? ` (${res(pair.to)})` : ""}`;
        break;
      }
      case "resolution":
        text = r.to ? `${who} set the resolution to ${res(r.to)}` : `${who} cleared the resolution`;
        break;
      case "owner":
        text = !r.to ? `${who} unassigned the finding` : str(r.to) === str(r.uid) ? `${who} took ownership` : `${who} assigned to ${nameOf ? nameOf(str(r.to)) : str(r.to)}`;
        break;
      case "severity":
        text = `${who} changed severity from ${str(r.from || "none")} to ${str(r.to)}`;
        break;
      case "dueAt":
        text = r.to == null ? `${who} cleared the manual due date` : `${who} set the due date to ${fmtDate(r.to)}${r.from != null ? ` (was ${fmtDate(r.from)})` : ""}`;
        break;
      case "exception":
        if (r.to == null) text = str(r.uid) === "system:sla" ? "The risk exception expired" : `${who} revoked the risk exception`;
        else text = r.from == null ? `${who} added a risk exception until ${fmtDate(r.to)}` : `${who} replaced the risk exception (now until ${fmtDate(r.to)})`;
        break;
      case "ticket":
        text = `${who} linked a ticket`;
        break;
      default:
        text = `${who} changed ${str(r.field || "the finding")}`;
    }
    out.push({ ts: r.ts, uid: r.uid, kind: "change", text });
  }
  return out;
}

/**
 * Evidence as display lines: strings as-is, objects as compact JSON; split on newlines.
 * @param {object} data entity.data
 * @param {number} [max=50]
 * @returns {{ lines: string[], more: number, truncated: boolean }}
 */
export function evidenceLines(data, max = 50) {
  const d = data || {};
  const ev = Array.isArray(d.evidence) ? d.evidence : d.evidence != null ? [d.evidence] : [];
  const all = [];
  for (const item of ev) {
    let s;
    if (typeof item === "string") s = item;
    else { try { s = JSON.stringify(item); } catch (_) { s = str(item); } }
    for (const line of str(s).split(/\r?\n/)) all.push(line);
  }
  return { lines: all.slice(0, max), more: Math.max(0, all.length - max), truncated: !!d.evidenceTruncated };
}

/**
 * One-line summary of applyBulk results: "3 updated, 1 skipped: <reason>". Distinct skip
 * reasons are listed once each with their count when more than one.
 * @param {({id:string, updates?:object, noop?:true, error?:string})[]} results
 * @returns {{ updated:number, unchanged:number, skipped:number, text:string }}
 */
export function summarizeBulk(results) {
  let updated = 0, unchanged = 0;
  const reasons = new Map();
  for (const r of results || []) {
    if (!r) continue;
    if (r.error) reasons.set(r.error, (reasons.get(r.error) || 0) + 1);
    else if (r.noop) unchanged++;
    else updated++;
  }
  const skipped = [...reasons.values()].reduce((a, b) => a + b, 0);
  const parts = [`${updated} updated`];
  if (unchanged) parts.push(`${unchanged} unchanged`);
  let text = parts.join(", ");
  if (skipped) {
    const why = reasons.size === 1 ? [...reasons.keys()][0] : [...reasons].map(([m, n]) => `${m} (${n})`).join("; ");
    text += `, ${skipped} skipped: ${why}`;
  }
  return { updated, unchanged, skipped, text };
}

/**
 * A <input type=date> value (YYYY-MM-DD) as ms at the END of that local day, or null.
 * maxMs clamps (used for the 365-day exception limit, which counts from now).
 */
export function dateInputToMs(value, { maxMs } = {}) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(str(value).trim());
  if (!m) return null;
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 59, 0);
  if (d.getFullYear() !== Number(m[1]) || d.getMonth() !== Number(m[2]) - 1 || d.getDate() !== Number(m[3])) return null;
  const ms = d.getTime();
  return Number.isFinite(maxMs) ? Math.min(ms, maxMs) : ms;
}

/** Local YYYY-MM-DD for a ms value (for date input min/max/value). */
export function localDay(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** Latest date an exception may be set to expire, as a local YYYY-MM-DD. */
export const exceptionMaxDay = (now) => localDay(now + EXCEPTION_MAX_DAYS * DAY_MS);

const FILTER_KEYS = ["q", "severity", "status", "source"];
/** Coerce a stored saved-view list: valid entries only, unique names, newest SAVED_VIEWS_MAX. */
export function normalizeSaved(list, views) {
  const out = [], seen = new Set();
  for (const v of Array.isArray(list) ? list : []) {
    if (!v || typeof v !== "object") continue;
    const name = str(v.name).trim().slice(0, SAVED_NAME_MAX);
    if (!name || seen.has(name.toLowerCase())) continue;
    const f = {};
    for (const k of FILTER_KEYS) f[k] = str(v.f && v.f[k]).slice(0, 200);
    f.sim = !!(v.f && v.f.sim);
    out.push({ name, view: views && !views.includes(v.view) ? "open" : str(v.view || "open"), f, ts: Number.isFinite(v.ts) ? v.ts : 0 });
    seen.add(name.toLowerCase());
  }
  return out.slice(-SAVED_VIEWS_MAX);
}

/** Add or replace (by case-insensitive name) a saved view; returns a new list. */
export function upsertSaved(list, entry, views) {
  const name = str(entry && entry.name).trim().toLowerCase();
  const rest = normalizeSaved(list, views).filter((v) => v.name.toLowerCase() !== name);
  return normalizeSaved(rest.concat([entry]), views);
}

/** Remove a saved view by name; returns a new list. */
export function removeSaved(list, name, views) {
  const n = str(name).trim().toLowerCase();
  return normalizeSaved(list, views).filter((v) => v.name.toLowerCase() !== n);
}

/** Is the finding open (new / open / investigating)? */
export const isOpenStatus = (s) => OPEN_STATES.includes(str(s || "new").toLowerCase());
