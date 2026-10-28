// Role-based home focus (Deck D8). PURE — no DOM, no network, deterministic. Given the graph
// entities and a chosen role, it returns the handful of numbers and open findings that role
// cares about first: a CISO wants exposure and trend, an analyst their own queue and the newest
// criticals, IT ops the overdue patches. It reuses the
// D7 metrics engine and the D1 SLA engine so its numbers never disagree with the rest of the
// Deck. Everything is derived from real findings; nothing is invented.
import { slaState, isKnownExploited, OPEN_STATES, SEVERITY_LEVELS } from "./workflow.js";
import { snapshot } from "./metrics.js";
import { cleanTitle } from "./queue-format.js";

const low = (v) => String(v == null ? "" : v).toLowerCase();
const OPEN = new Set(OPEN_STATES);
// The Deck treats FINDING and VULNERABILITY entities alike as work-queue items (core/findings.js
// FINDING_TYPES), so role focus does too.
const isFinding = (e) => e && (low(e.type) === "finding" || low(e.type) === "vulnerability");
const isOpen = (e) => OPEN.has(low(e.status) || "new");
const sevRank = (s) => { const i = SEVERITY_LEVELS.indexOf(low(s)); return i < 0 ? SEVERITY_LEVELS.length : i; };
const toMs = (v) => { const n = Date.parse(v); return Number.isFinite(n) ? n : 0; };

export const ROLES = [
  { id: "ciso", label: "CISO" },
  { id: "analyst", label: "Analyst" },
  { id: "itops", label: "IT ops" },
];
export const ROLE_IDS = ROLES.map((r) => r.id);

const item = (e) => ({ id: e.id, name: cleanTitle(e) || String(e.id || ""), severity: SEVERITY_LEVELS.includes(low(e.severity)) ? low(e.severity) : "info", category: low((e.data || {}).category) });
const isVuln = (e) => low(e.type) === "vulnerability" || low((e.data || {}).category).includes("vuln");

/**
 * roleFocus(entities, opts) -> { role, label, lead, metrics:[{label,value,sub?}], items:[{id,name,severity}], emptyText }
 * opts: { role, now, myUid, policy, kevSet }. Returns null for an unknown role.
 * `items` are open FINDING entities (clickable), capped at 6, ordered for the role.
 */
export function roleFocus(entities, opts = {}) {
  const role = low(opts.role);
  if (!ROLE_IDS.includes(role)) return null;
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const policy = opts.policy || undefined;
  const kevSet = opts.kevSet || null;
  const ents = Array.isArray(entities) ? entities : [];
  const open = ents.filter((e) => isFinding(e) && isOpen(e));
  const sla = (e) => slaState(e, policy, now, { kevSet });
  const kev = (e) => isKnownExploited(e, kevSet);
  const label = (ROLES.find((r) => r.id === role) || {}).label || role;

  if (role === "ciso") {
    const snap = snapshot(ents, { now, policy, kevSet });
    // Highest-leverage open findings: known-exploited first, then severity, then overdue.
    const ranked = open.slice().sort((a, b) =>
      (kev(b) ? 1 : 0) - (kev(a) ? 1 : 0)
      || sevRank(a.severity) - sevRank(b.severity)
      || ((sla(b).state === "overdue" ? 1 : 0) - (sla(a).state === "overdue" ? 1 : 0))
      || toMs(b.createdAt) - toMs(a.createdAt));
    return {
      role, label, lead: "Board-level posture: exposure, exploited risk and SLA health.",
      metrics: [
        { label: "Exposure", value: snap.exposureScore + " / 100", sub: "higher is worse" },
        { label: "Critical + high", value: snap.bySeverity.critical + snap.bySeverity.high },
        { label: "Known-exploited", value: snap.kevOpen },
        { label: "SLA met", value: snap.slaCompliancePct == null ? "—" : snap.slaCompliancePct + "%" },
      ],
      items: ranked.slice(0, 6).map(item),
      emptyText: "No open findings. Posture is clean.",
    };
  }

  if (role === "analyst") {
    const myUid = opts.myUid ? String(opts.myUid) : "";
    const mine = open.filter((e) => myUid && (e.data || {}).owner === myUid);
    const unassigned = open.filter((e) => !(e.data || {}).owner);
    const overdue = open.filter((e) => sla(e).state === "overdue");
    // My queue first (most urgent), otherwise the newest open critical/high to pick up.
    const pool = mine.length ? mine : open.filter((e) => /^(critical|high)$/.test(low(e.severity)));
    const ranked = pool.slice().sort((a, b) =>
      ((sla(b).state === "overdue" ? 1 : 0) - (sla(a).state === "overdue" ? 1 : 0))
      || sevRank(a.severity) - sevRank(b.severity)
      || toMs(b.createdAt) - toMs(a.createdAt));
    return {
      role, label, lead: mine.length ? "Your queue, most urgent first." : "Newest critical and high findings to pick up.",
      metrics: [
        { label: "My open", value: mine.length },
        { label: "Unassigned", value: unassigned.length },
        { label: "Overdue", value: overdue.length },
      ],
      items: ranked.slice(0, 6).map(item),
      emptyText: mine.length ? "" : "No open critical or high findings to pick up.",
    };
  }

  if (role === "itops") {
    const vulns = open.filter(isVuln);
    const overdue = vulns.filter((e) => sla(e).state === "overdue");
    const dueWeek = vulns.filter((e) => sla(e).state === "due_soon");
    const ranked = vulns.slice().sort((a, b) => {
      const da = sla(a).daysLeft, db = sla(b).daysLeft;
      return ((da == null ? Infinity : da) - (db == null ? Infinity : db)) || sevRank(a.severity) - sevRank(b.severity);
    });
    return {
      role, label, lead: "Patches past or nearing their SLA, soonest first.",
      metrics: [
        { label: "Overdue patches", value: overdue.length },
        { label: "Due this week", value: dueWeek.length },
        { label: "Open vulnerabilities", value: vulns.length },
      ],
      items: ranked.slice(0, 6).map(item),
      emptyText: "No open vulnerabilities. Nothing to patch.",
    };
  }

  return null;
}
