// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Deadlines: one model for the clocks a security finding can start. PURE: no DOM, no network,
// no storage. The MonitorDO (worker/monitor.js) creates, stores and alerts them per workspace;
// the Deck (js/deck/deadlines.js) shows them. Both import this file, so the clock maths the
// server alerts on is the same the Deck counts down with.
//
// A deadline: { id, kind, clock, group, title, subject:{type,value,assets}, startedAt, dueAt,
//   status: open|done|dismissed, reason, closedAt, closedBy, monitorId, createdAt,
//   alerts:{created, quarter, holdUntil} }
// dueAt null = a clock that has not started yet (the CRA final report, until the fix is out).
// Steps and the source link come from the kind (stepsOf, sourceOf), so a stored record stays small.
//
// Kinds:
//  cra-exploited  Cyber Resilience Act Article 14(2): a known-exploited CVE (CISA KEV) in an asset
//                 the workspace marked as shipped in a product. Three linked clocks: early warning
//                 24 h and vulnerability notification 72 h after becoming aware, final report 14
//                 days after a fix or mitigation is available. Only with the workspace's CRA
//                 opt-in, and not before Article 14 applies (11 September 2026).
//  cert-expiry    a watched certificate's expiry date (the cert-expiry monitor, the Free watch too).
//  kev-due        CISA BOD 22-01: the KEV catalogue's due date for a matched CVE. Only with the
//                 workspace's BOD 22-01 opt-in.
// Darknode tracks the clocks and prepares facts. It does not decide whether a law applies and
// does not submit anything.

export const HOUR = 3600000;
export const DAY = 24 * HOUR;
export const KINDS = ["cra-exploited", "cert-expiry", "kev-due"];
export const MAX_SHIPPED = 200;
export const CLOSED = ["done", "dismissed"];

export const CRA = {
  appliesFrom: Date.UTC(2026, 8, 11),   // Article 71(2): Article 14 applies from 11 September 2026
  earlyMs: 24 * HOUR,
  notifyMs: 72 * HOUR,
  finalMs: 14 * DAY,
  source: { label: "Regulation (EU) 2024/2847 (Cyber Resilience Act), Article 14(2)", url: "https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng" },
  applies: "Article 14 applies from 11 September 2026 (Article 71(2)).",
  where: "Notifications go to the CSIRT designated as coordinator and to ENISA at the same time, through ENISA's single reporting platform (Article 14(1) and (7)).",
  quote: {
    early: "an early warning notification of an actively exploited vulnerability, without undue delay and in any event within 24 hours of the manufacturer becoming aware of it, indicating, where applicable, the Member States on the territory of which the manufacturer is aware that their product with digital elements has been made available",
    notify: "a vulnerability notification, without undue delay and in any event within 72 hours of the manufacturer becoming aware of the actively exploited vulnerability",
    final: "a final report, no later than 14 days after a corrective or mitigating measure is available",
  },
};
export const BOD2201 = {
  source: { label: "CISA Binding Operational Directive 22-01", url: "https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities" },
};
export const KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
export const kevLink = (cve) => KEV_URL + "?search_api_fulltext=" + encodeURIComponent(cve);
export const nvdLink = (cve) => "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(cve);
export const DISCLAIMER = "Darknode does not decide whether the Cyber Resilience Act or BOD 22-01 applies to you, and it does not submit anything. It tracks the clocks and prepares the facts; you decide and file.";

// The 27 EU Member States (EU country codes: Greece is EL; GR is accepted too).
export const EU_STATES = { AT: "Austria", BE: "Belgium", BG: "Bulgaria", HR: "Croatia", CY: "Cyprus", CZ: "Czechia", DK: "Denmark", EE: "Estonia", FI: "Finland", FR: "France", DE: "Germany", EL: "Greece", HU: "Hungary", IE: "Ireland", IT: "Italy", LV: "Latvia", LT: "Lithuania", LU: "Luxembourg", MT: "Malta", NL: "Netherlands", PL: "Poland", PT: "Portugal", RO: "Romania", SK: "Slovakia", SI: "Slovenia", ES: "Spain", SE: "Sweden" };

const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const str = (v) => (v == null ? "" : String(v));
const clip = (v, n) => str(v).replace(/\s+/g, " ").trim().slice(0, n);
const fin = (n) => typeof n === "number" && Number.isFinite(n);
const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;
const isCve = (s) => /^CVE-\d{4}-\d{4,7}$/.test(s);

// "2026-11-25 14:05 UTC"
export const utc = (ms) => (fin(ms) ? new Date(ms).toISOString().slice(0, 16).replace("T", " ") + " UTC" : "");

// ---- clock maths ------------------------------------------------------------------------------

// The three CRA clocks of a case { awareAt, fixAt }.
export function craClocks(c = {}) {
  const aware = fin(c.awareAt) ? c.awareAt : null, fix = fin(c.fixAt) ? c.fixAt : null;
  return {
    early: aware == null ? null : aware + CRA.earlyMs,
    notify: aware == null ? null : aware + CRA.notifyMs,
    final: fix == null ? null : fix + CRA.finalMs,
  };
}

// A KEV due date ("2026-12-01") ends at the end of that day, UTC.
export function kevDueAt(dueDate) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(str(dueDate).trim());
  if (!m) return null;
  const t = Date.UTC(+m[1], +m[2] - 1, +m[3], 23, 59, 59);
  return Number.isFinite(t) ? t : null;
}

export const timeLeft = (d, now) => (d && fin(d.dueAt) ? d.dueAt - now : null);

// When 25% of the deadline's time is left. null for a clock that has not started, or one
// that was already due when it started.
export function quarterAt(d) {
  if (!d || !fin(d.dueAt) || !fin(d.startedAt) || d.dueAt <= d.startedAt) return null;
  return d.startedAt + Math.round((d.dueAt - d.startedAt) * 0.75);
}

// open + no dueAt = waiting; open past dueAt = overdue.
export function stateOf(d, now) {
  if (!d) return "";
  if (d.status === "done" || d.status === "dismissed") return d.status;
  if (!fin(d.dueAt)) return "waiting";
  return now >= d.dueAt ? "overdue" : "open";
}

// "2d 4h left", "5h 12m left", "40m left", "overdue by 3h 5m"
export function fmtLeft(ms) {
  if (!fin(ms)) return "";
  const a = Math.abs(ms), d = Math.floor(a / DAY), h = Math.floor((a % DAY) / HOUR), m = Math.floor((a % HOUR) / 60000);
  const s = d ? d + "d " + h + "h" : h ? h + "h " + m + "m" : Math.max(m, ms < 0 ? 1 : 0) + "m";
  return ms < 0 ? "overdue by " + s : s + " left";
}

// Open deadlines first, soonest due first; waiting clocks after them; closed ones last, newest first.
export function sortDeadlines(list, now) {
  const rank = (d) => { const s = stateOf(d, now); return s === "overdue" || s === "open" ? 0 : s === "waiting" ? 1 : 2; };
  return [...(list || [])].sort((a, b) => rank(a) - rank(b)
    || (rank(a) === 0 ? a.dueAt - b.dueAt : rank(a) === 2 ? (b.closedAt || 0) - (a.closedAt || 0) : (a.createdAt || 0) - (b.createdAt || 0))
    || str(a.id).localeCompare(str(b.id)));
}

// ---- opt-ins --------------------------------------------------------------------------------

// The workspace's deadline settings. Nothing is assumed: both opt-ins default to off.
// shipped: the assets marked "shipped in a product" [{ id, type, name }].
export function normSettings(s) {
  const x = s && typeof s === "object" ? s : {};
  const shipped = [], seen = new Set();
  for (const a of Array.isArray(x.shipped) ? x.shipped : []) {
    if (!a || typeof a !== "object") continue;
    const name = clip(a.name, 120), id = clip(a.id, 128), type = clip(a.type, 32).toUpperCase();
    if (!name) continue;
    const k = id || type + "|" + name.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    shipped.push({ id, type, name });
    if (shipped.length >= MAX_SHIPPED) break;
  }
  return { cra: x.cra === true, bod2201: x.bod2201 === true, shipped };
}

// A settings write. `free`: the caller's plan is below Pro, so neither opt-in can be turned on
// (CRA and BOD clocks come from the known-exploited CVE monitor, which is a Pro monitor).
// -> { settings } | { error, plan? }
export function checkSettings(input, { free = false } = {}) {
  if (!input || typeof input !== "object") return { error: "settings required" };
  if (input.shipped != null && !Array.isArray(input.shipped)) return { error: "shipped must be a list" };
  if (Array.isArray(input.shipped) && input.shipped.length > MAX_SHIPPED) return { error: "At most " + MAX_SHIPPED + " assets can be marked as shipped in a product." };
  const settings = normSettings(input);
  if (free && (settings.cra || settings.bod2201)) return { error: "Cyber Resilience Act and BOD 22-01 clocks come from the known-exploited CVE monitor, which is part of the Pro plan. Request an upgrade under Plans.", plan: true };
  return { settings };
}

// CRA clocks start only with the opt-in, and not before Article 14 applies.
export const craApplies = (settings, at) => !!(settings && settings.cra === true) && fin(at) && at >= CRA.appliesFrom;
export const bodApplies = (settings) => !!(settings && settings.bod2201 === true);

// "DE, fr, Greece" -> { codes: ["DE","FR","EL"], bad: [] }
export function parseMemberStates(v) {
  const parts = Array.isArray(v) ? v : str(v).split(/[,;\n]+/);
  const byName = new Map(Object.entries(EU_STATES).map(([c, n]) => [n.toLowerCase(), c]));
  const codes = [], bad = [];
  for (const p of parts) {
    const t = clip(p, 40);
    if (!t) continue;
    const up = t.toUpperCase(), c = up === "GR" ? "EL" : own(EU_STATES, up) ? up : byName.get(t.toLowerCase()) || "";
    if (!c) { bad.push(t); continue; }
    if (!codes.includes(c)) codes.push(c);
  }
  return { codes, bad };
}
export const stateNames = (codes) => (codes || []).filter((c) => own(EU_STATES, c)).map((c) => EU_STATES[c] + " (" + c + ")");

// ---- which assets a CVE touches ----------------------------------------------------------------

function cvesOf(e) {
  const out = new Set(), d = (e && e.data) || {};
  const add = (v) => { const m = str(v).match(CVE_RE); if (m) for (const c of m) out.add(c.toUpperCase()); };
  add(e && e.name); add(d.cve);
  if (Array.isArray(d.cves)) for (const c of d.cves) add(c);
  add(d.evidence);
  return out;
}

// The shipped assets a CVE is in. inventory: the workspace graph { entities, relationships }
// (the monitor's own writes already removed). An asset counts when it is the entity that names
// the CVE, is linked to one by a relationship, or is listed in a finding's affected assets.
// A shipped entry matches by graph id, or by name (and type, when both sides have one).
// -> [{ id, type, name }]
export function shippedMatches(cve, inventory, shipped) {
  const want = str(cve).toUpperCase().trim();
  const list = Array.isArray(shipped) ? shipped : [];
  if (!isCve(want) || !list.length) return [];
  const ents = (inventory && Array.isArray(inventory.entities)) ? inventory.entities.filter((e) => e && typeof e === "object") : [];
  const rels = (inventory && Array.isArray(inventory.relationships)) ? inventory.relationships : [];
  const byId = new Map(ents.map((e) => [e.id, e]));
  const ids = new Set(), names = [];
  const add = (e) => { if (!e) return; if (e.id) ids.add(e.id); if (e.name) names.push({ type: str(e.type).toUpperCase(), name: str(e.name).trim().toLowerCase() }); };
  const hits = ents.filter((e) => cvesOf(e).has(want));
  const hitIds = new Set(hits.map((e) => e.id).filter(Boolean));
  for (const e of hits) {
    add(e);
    for (const n of Array.isArray(e.data && e.data.assets) ? e.data.assets : []) if (str(n).trim()) names.push({ type: "", name: str(n).trim().toLowerCase() });
  }
  for (const r of rels) {
    if (!r) continue;
    if (hitIds.has(r.fromId)) add(byId.get(r.toId));
    if (hitIds.has(r.toId)) add(byId.get(r.fromId));
  }
  const out = [];
  for (const s of list) {
    const nm = str(s.name).trim().toLowerCase(), ty = str(s.type).toUpperCase();
    const hit = (s.id && ids.has(s.id)) || (nm && names.some((n) => n.name === nm && (!n.type || !ty || n.type === ty)));
    if (hit && !out.includes(s)) out.push(s);
  }
  return out;
}

// ---- building deadlines ---------------------------------------------------------------------

const STEPS = {
  early: [
    "Check that the vulnerable component is in the product you ship.",
    "Note the Member States where the product is made available.",
    "Submit the early warning on ENISA's single reporting platform. It reaches your coordinating CSIRT and ENISA.",
    "Mark this clock done here, with the submission reference as the reason.",
  ],
  notify: [
    "Describe the product, the general nature of the exploit and of the vulnerability.",
    "List the corrective or mitigating measures taken, and the ones users can take.",
    "Say how sensitive you consider the information.",
    "Submit the vulnerability notification on the same platform, unless the early warning already gave all of this.",
  ],
  final: [
    "Mark the fix or mitigation available here: the 14-day clock starts then.",
    "Describe the vulnerability, its severity and impact.",
    "Add what is known about any malicious actor exploiting it.",
    "Give the details of the security update or other corrective measures.",
    "Submit the final report on the same platform.",
  ],
};
const CRA_TITLE = { early: "CRA early warning", notify: "CRA vulnerability notification", final: "CRA final report" };

function base(o) {
  return { id: o.id, kind: o.kind, clock: o.clock || "", group: o.group || "", title: o.title, subject: o.subject, startedAt: o.startedAt, dueAt: fin(o.dueAt) ? o.dueAt : null, status: "open", reason: "", closedAt: 0, closedBy: "", monitorId: o.monitorId || "", createdAt: o.at, alerts: o.alerts || {} };
}

// What to do for a deadline, in order.
export function stepsOf(d) {
  const v = (d && d.subject && d.subject.value) || "";
  if (!d) return [];
  if (d.kind === "cra-exploited") return STEPS[d.clock] || [];
  if (d.kind === "cert-expiry") return ["Renew the certificate for " + v + ".", "Install it on every server, load balancer and CDN that serves " + v + ".", "Run the watch again: this closes by itself when the monitor sees the new certificate."];
  if (d.kind === "kev-due") return ["Remediate " + v + " on every affected system by the KEV due date, following the required action in the catalogue.", "Mark it done here once it is remediated, with the change or ticket reference."];
  return [];
}
// The rule a deadline comes from: { label, url, quote? }.
export function sourceOf(d) {
  if (!d) return null;
  if (d.kind === "cra-exploited") return { ...CRA.source, quote: CRA.quote[d.clock] || "" };
  if (d.kind === "kev-due") return { ...BOD2201.source, quote: "remediate each vulnerability according to the timelines set forth in the CISA-managed vulnerability catalog" };
  if (d.kind === "cert-expiry") return { label: "Certificate Transparency logs", url: "https://crt.sh/?q=" + encodeURIComponent((d.subject && d.subject.value) || "") };
  return null;
}

// A new CRA case and its three clocks. `alertedAt`: when Darknode alerted; it is also the
// "became aware" time until the user corrects it.
export function craCase({ cve, assets, kevDateAdded, alertedAt, monitorId }) {
  return { cve, assets: assets.map((a) => a.name), kevDateAdded: str(kevDateAdded), alertedAt, awareAt: alertedAt, fixAt: null, measures: "", memberStates: [], monitorId: monitorId || "" };
}
export function craDeadlines(c, at) {
  const k = craClocks(c), what = c.cve + " in " + (c.assets.slice(0, 3).join(", ") + (c.assets.length > 3 ? " and " + (c.assets.length - 3) + " more" : ""));
  const subject = { type: "cve", value: c.cve, assets: c.assets.slice() };
  return ["early", "notify", "final"].map((clock) => base({
    id: "cra:" + c.cve + ":" + clock, kind: "cra-exploited", clock, group: "cra:" + c.cve,
    title: CRA_TITLE[clock] + ": " + what, subject, startedAt: clock === "final" ? (fin(c.fixAt) ? c.fixAt : null) : c.awareAt,
    dueAt: k[clock], monitorId: c.monitorId, at,
  }));
}

// Deadlines from one kev-epss run. events: the run's events (kind "kev" = a new or worsened
// match); findings: the run's findings (a KEV one carries cve, dueDate, dateAdded, kev:true).
// existing: deadlines by id; cases: CRA cases by CVE. Creates a CRA case only with the CRA
// opt-in, after Article 14 applies, for a CVE in an asset marked as shipped; a kev-due deadline
// only with the BOD 22-01 opt-in. Never re-creates one that exists, whatever its status.
// -> { add: deadline[], cases: case[] }
export function kevDeadlines({ events = [], findings = [], settings, inventory, existing = {}, cases = {}, monitorId = "", at }) {
  const s = normSettings(settings), add = [], newCases = [];
  const byKey = new Map((findings || []).map((f) => [f && f.key, f]));
  const done = new Set();
  for (const ev of events || []) {
    if (!ev || ev.kind !== "kev") continue;
    const f = byKey.get(ev.key);
    if (!f || f.kev !== true) continue;                       // an EPSS-only match is not known-exploited
    const cve = str(f.cve).toUpperCase();
    if (!isCve(cve) || done.has(cve)) continue;
    done.add(cve);
    if (bodApplies(s) && !own(existing, "kev-due:" + cve)) {
      const due = kevDueAt(f.dueDate);
      if (due != null) add.push(base({
        id: "kev-due:" + cve, kind: "kev-due", title: "BOD 22-01: remediate " + cve, subject: { type: "cve", value: cve, assets: [] },
        startedAt: at, dueAt: due, monitorId, at,
      }));
    }
    if (craApplies(s, at) && !own(cases, cve)) {
      const assets = shippedMatches(cve, inventory, s.shipped);
      if (!assets.length) continue;                           // not in anything marked as shipped
      const c = craCase({ cve, assets, kevDateAdded: f.dateAdded, alertedAt: at, monitorId });
      newCases.push(c);
      for (const d of craDeadlines(c, at)) if (!own(existing, d.id)) add.push(d);
    }
  }
  return { add, cases: newCases };
}

// Deadlines from one cert-expiry run. findings: the run's findings (key "cert:<domain>", domain,
// notAfter). firstSeen: finding key -> when the monitor first saw it; alerted: the keys this run
// alerted. A certificate's deadline is due when it expires. The monitor's own alert is the
// deadline's "created" alert (never a second email). An open deadline of this monitor closes as
// done when the monitor no longer sees that certificate expiring.
// -> { add: deadline[], close: [{ id, status, reason }] }
export function certDeadlines({ findings = [], existing = {}, monitorId = "", firstSeen = {}, alerted = new Set(), watched = null, at }) {
  const add = [], close = [], live = new Set();
  for (const f of findings || []) {
    if (!f || !str(f.key).startsWith("cert:") || !f.domain) continue;
    const due = Date.parse(f.notAfter);
    if (!Number.isFinite(due)) continue;
    const id = "cert:" + f.domain + ":" + new Date(due).toISOString().slice(0, 10);
    live.add(id);
    if (own(existing, id) || add.some((d) => d.id === id)) continue;
    add.push(base({
      id, kind: "cert-expiry", title: "Certificate for " + f.domain + " expires", subject: { type: "domain", value: f.domain, assets: [] },
      startedAt: fin(firstSeen[f.key]) ? Math.min(firstSeen[f.key], at) : at, dueAt: due, monitorId, at,
      alerts: { created: { at, via: "monitor", sent: alerted.has(f.key) } },
    }));
  }
  for (const d of Object.values(existing)) {
    if (!d || d.kind !== "cert-expiry" || d.status !== "open" || d.monitorId !== monitorId || live.has(d.id)) continue;
    const dom = d.subject && d.subject.value;
    const gone = watched && dom && !watched.has(dom);
    close.push({ id: d.id, status: "done", reason: gone ? "The domain is no longer in this watch." : "The monitor no longer sees this certificate expiring: it was renewed or replaced." });
  }
  return { add, close };
}

// ---- edits ------------------------------------------------------------------------------------

// Close a deadline as done or dismissed. A reason is required (it is the record).
// -> { deadline } | { error }
export function closeDeadline(d, { status, reason, by = "", at }) {
  if (!d) return { error: "not found" };
  if (!CLOSED.includes(status)) return { error: "status must be done or dismissed" };
  const why = clip(reason, 500);
  if (!why) return { error: status === "done" ? "Say what was done (for example the submission reference)." : "Say why you are dismissing it." };
  return { deadline: { ...d, status, reason: why, closedAt: at, closedBy: str(by).slice(0, 128) } };
}
export function reopenDeadline(d) {
  if (!d) return { error: "not found" };
  return { deadline: { ...d, status: "open", reason: "", closedAt: 0, closedBy: "" } };
}

// Edit a CRA case: when you became aware, when a fix or mitigation became available (null =
// not yet), the measures known and the Member States. -> { case } | { error }
export function updateCase(c, patch = {}, now) {
  if (!c) return { error: "not found" };
  const next = { ...c };
  const earliest = (fin(c.alertedAt) ? c.alertedAt : now) - 365 * DAY;
  if (patch.awareAt !== undefined) {
    const t = Number(patch.awareAt);
    if (!Number.isFinite(t)) return { error: "Enter when you became aware as a date and time." };
    if (t > now + 60000) return { error: "When you became aware cannot be in the future." };
    if (t < earliest) return { error: "When you became aware must be within a year before Darknode's alert." };
    next.awareAt = t;
  }
  if (patch.fixAt !== undefined) {
    if (patch.fixAt === null) next.fixAt = null;
    else {
      const t = Number(patch.fixAt);
      if (!Number.isFinite(t)) return { error: "Enter when the fix or mitigation became available as a date and time." };
      if (t > now + 60000) return { error: "A fix cannot be marked available in the future." };
      if (t < earliest) return { error: "When the fix became available must be within a year before Darknode's alert." };
      next.fixAt = t;
    }
  }
  if (patch.measures !== undefined) {
    const m = str(patch.measures).trim();
    if (m.length > 2000) return { error: "Keep the measures under 2,000 characters." };
    next.measures = m;
  }
  if (patch.memberStates !== undefined) {
    const p = parseMemberStates(patch.memberStates);
    if (p.bad.length) return { error: "Not an EU Member State: " + p.bad.slice(0, 5).join(", ") + ". Use the country name or its two-letter code, such as DE or FR." };
    next.memberStates = p.codes;
  }
  return { case: next };
}

// Bring a case's three clocks in line with it. A clock's alerts already sent stay sent; the final
// clock's are reset when the fix is cleared, so marking it again announces the new clock.
// -> the changed deadlines
export function syncCaseClocks(c, existing = {}) {
  const k = craClocks(c), out = [];
  for (const clock of ["early", "notify", "final"]) {
    const d = existing["cra:" + c.cve + ":" + clock];
    if (!d) continue;
    const startedAt = clock === "final" ? (fin(c.fixAt) ? c.fixAt : null) : c.awareAt;
    if (d.startedAt === startedAt && d.dueAt === k[clock]) continue;
    out.push({ ...d, startedAt, dueAt: k[clock], alerts: clock === "final" && k.final == null ? {} : d.alerts || {} });
  }
  return out;
}

// ---- alert schedule ---------------------------------------------------------------------------

// What to send now: a "created" alert once a clock starts (a cert deadline's is the monitor's own
// alert, recorded at creation), and a "quarter" alert when 25% of the time is left. A quarter
// alert that falls due together with the created one is folded into it; one whose deadline
// already passed is skipped (the Deck shows it overdue). -> [{ id, stage: created|quarter|skip }]
export function dueAlerts(list, now) {
  const out = [];
  for (const d of list || []) {
    if (!d || d.status !== "open" || !fin(d.dueAt)) continue;
    const a = d.alerts || {}, q = quarterAt(d);
    if (fin(a.holdUntil) && now < a.holdUntil) continue;      // held until the monitor's quiet hours end
    if (!a.created) { out.push({ id: d.id, stage: "created" }); continue; }
    if (a.quarter) continue;
    if (q == null || now >= d.dueAt) { out.push({ id: d.id, stage: "skip" }); continue; }
    if (now >= q) out.push({ id: d.id, stage: "quarter" });
  }
  return out;
}

// The next time dueAlerts has something to do (null = nothing scheduled).
export function nextAlertAt(list, now) {
  let next = null;
  const take = (t) => { if (next == null || t < next) next = t; };
  for (const d of list || []) {
    if (!d || d.status !== "open" || !fin(d.dueAt)) continue;
    const a = d.alerts || {};
    if (a.created && a.quarter) continue;
    if (fin(a.holdUntil) && now < a.holdUntil) { take(a.holdUntil); continue; }
    if (!a.created) { take(now); continue; }
    const q = quarterAt(d);
    if (q == null || now >= d.dueAt) take(now); else take(Math.max(q, now));
  }
  return next;
}

// One alert line for a deadline at a stage, for email, Slack, Teams and webhooks.
export function alertLine(d, stage, now) {
  const left = fmtLeft(timeLeft(d, now)), due = utc(d.dueAt);
  if (d.kind === "cra-exploited") {
    const q = CRA.quote[d.clock] ? " Article 14(2): \"" + CRA.quote[d.clock] + "\"." : "";
    return { title: d.title, detail: (stage === "quarter" ? "A quarter of the time is left: due " : "Due ") + due + " (" + left + ")." + q };
  }
  if (d.kind === "cert-expiry") return { title: d.title + " on " + utc(d.dueAt).slice(0, 10), detail: (stage === "quarter" ? "A quarter of the time is left (" + left + "). " : "") + "Renew it and install it everywhere it is served." };
  return { title: d.title, detail: (stage === "quarter" ? "A quarter of the time is left: " : "") + "KEV due date " + utc(d.dueAt).slice(0, 10) + " (" + left + ")." };
}

// ---- the facts for a CRA early warning ---------------------------------------------------------

// Plain facts to paste into the early warning. Nothing is guessed: what is not known says so.
// -> { rows: [[label, value]], text }
export function craFacts(c, deadlines = {}, now = Date.now()) {
  if (!c) return { rows: [], text: "" };
  const k = craClocks(c);
  const aware = utc(c.awareAt) + (fin(c.alertedAt) && c.awareAt !== c.alertedAt ? " (Darknode alerted " + utc(c.alertedAt) + ")" : " (when Darknode alerted)");
  const states = stateNames(c.memberStates);
  const rows = [
    ["Vulnerability", c.cve],
    ["Product or asset", (c.assets || []).join(", ") || "Not recorded"],
    ["Exploitation confirmed", c.kevDateAdded ? "Added to the CISA Known Exploited Vulnerabilities catalogue on " + c.kevDateAdded : "In the CISA Known Exploited Vulnerabilities catalogue (date added not recorded)"],
    ["Became aware", aware],
    ["Member States where the product is made available", states.length ? states.join(", ") : "Not entered yet"],
    ["Corrective or mitigating measures known", c.measures || "None entered yet"],
    ["Fix or mitigation available", fin(c.fixAt) ? utc(c.fixAt) : "Not marked yet"],
    ["Early warning due", utc(k.early)],
    ["Vulnerability notification due", utc(k.notify)],
    ["Final report due", k.final != null ? utc(k.final) : "14 days after a fix or mitigation is available"],
    ["CISA KEV catalogue", kevLink(c.cve)],
    ["NVD", nvdLink(c.cve)],
    ["Legal basis", CRA.source.label + ", " + CRA.source.url],
  ];
  const text = ["Cyber Resilience Act early-warning facts: " + c.cve, "Prepared " + utc(now) + " by Darknode from the CISA KEV catalogue and your entries.", ""]
    .concat(rows.map(([l, v]) => l + ": " + v), ["", CRA.where, DISCLAIMER]).join("\n");
  return { rows, text };
}
