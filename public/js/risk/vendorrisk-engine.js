// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Third-Party Risk engine (vendorrisk). Pure, deterministic scoring of a vendor
// register: inherent risk from a visible points table, assurance credit from the
// documents on file, an external posture grade from LIVE check results that the UI
// fetched (DoH JSON, CT rows, HTTP headers, security.txt, RDAP), residual risk,
// diffs between posture snapshots and findings with standard references.
// No DOM, no network, no clock: `now` is always passed in. Safe inside a Worker.

import { sniff, parseCsv, iterJson, findColumn, normHeader } from "../ingest/parse.js";
import { toCsv } from "../core/export.js";
import {
  parseSPF, parseDMARC, spfLookupCount, parseMtaSts, newestCert, certDaysLeft,
  gradeTransport, gradeHeaders, letterGrade,
} from "../dataprotect/posture-engine.js";

export const TOOL_ID = "vendorrisk";
export const VERSION = "1.0.0";

// ---------------------------------------------------------------------------
// Vocabularies
// ---------------------------------------------------------------------------

export const DATA_TIERS = [
  { id: "none", label: "None" },
  { id: "internal", label: "Internal" },
  { id: "confidential", label: "Confidential" },
  { id: "restricted", label: "Restricted / regulated" },
];
export const DATA_TYPES = [
  { id: "pii", label: "Personal data (PII)" },
  { id: "phi", label: "Health data (PHI)" },
  { id: "pci", label: "Cardholder data (PCI)" },
  { id: "financial", label: "Financial / banking" },
  { id: "credentials", label: "Credentials / secrets" },
  { id: "source", label: "Source code" },
  { id: "employee", label: "Employee / HR" },
  { id: "customer", label: "Customer content" },
];
export const SYSTEM_ACCESS = [
  { id: "none", label: "None" },
  { id: "read", label: "Read" },
  { id: "write", label: "Write" },
  { id: "admin", label: "Admin" },
  { id: "network", label: "Network / VPN" },
];
export const INTEGRATIONS = [
  { id: "sso", label: "SSO" },
  { id: "apikeys", label: "API keys" },
  { id: "oauth", label: "OAuth app" },
  { id: "agent", label: "On-prem agent" },
];
export const CRITICALITY = [
  { id: "low", label: "Low" },
  { id: "medium", label: "Medium" },
  { id: "high", label: "High" },
  { id: "critical", label: "Critical" },
];
export const DOC_TYPES = [
  { id: "soc2t2", label: "SOC 2 Type II" },
  { id: "soc2t1", label: "SOC 2 Type I" },
  { id: "iso27001", label: "ISO 27001 certificate" },
  { id: "pciaoc", label: "PCI AOC" },
  { id: "pentest", label: "Pentest summary" },
  { id: "questionnaire", label: "HECVAT / CAIQ / SIG questionnaire" },
  { id: "dpa", label: "DPA" },
  { id: "baa", label: "BAA" },
  { id: "insurance", label: "Cyber insurance" },
  { id: "bridge", label: "Bridge letter" },
];
export const BANDS = ["low", "medium", "high", "critical"];
const label = (list, id) => (list.find((x) => x.id === id) || { label: id || "" }).label;
export const docLabel = (id) => label(DOC_TYPES, id);

// ---------------------------------------------------------------------------
// Policy (every number the scoring uses; shown and editable in the UI)
// ---------------------------------------------------------------------------

export const DEFAULT_POLICY = {
  reviewMonths: { critical: 12, high: 12, medium: 24, low: 36 },
  points: {
    dataTier: { none: 0, internal: 2, confidential: 5, restricted: 8 },
    dataTypes: { pii: 3, phi: 4, pci: 4, financial: 3, credentials: 4, source: 3, employee: 2, customer: 2 },
    dataTypeCap: 8,
    systemAccess: { none: 0, read: 2, write: 4, admin: 6, network: 6 },
    integrations: { sso: 1, apikeys: 2, oauth: 2, agent: 3 },
    spof: 5,
    criticalityMultiplier: { low: 1, medium: 1.5, high: 2, critical: 2.5 },
  },
  credit: { soc2t2: 25, soc2t1: 10, iso27001: 20, pentest: 10, questionnaire: 5, insurance: 5, requiredContract: 5, cap: 60 },
  posture: { A: -5, B: 0, C: 0, D: 5, F: 10 },
  bands: { medium: 25, high: 50, critical: 75 },
};

/** Thresholds (days / months). The UI renders these with real labels. */
export const DEFAULTS = {
  docExpiringDays: 60,
  socStaleMonths: 12,
  freshMonths: 12,
  certWarnDays: 14,
  domainWarnDays: 30,
  upcomingDays: 90,
  renewalLeadDays: 30,
  snapshotCap: 12,
  historyCap: 50,
};

export const THRESHOLD_LABELS = {
  docExpiringDays: ["Document expiring window (days)", "Assurance documents expiring inside this window are medium findings."],
  socStaleMonths: ["SOC 2 period staleness (months)", "A SOC 2 report whose period ended longer ago than this needs a bridge letter."],
  freshMonths: ["Fresh evidence window (months)", "Pentests and questionnaires older than this earn no credit."],
  certWarnDays: ["Certificate warning (days)", "Newest certificate expiring inside this window is a medium finding."],
  domainWarnDays: ["Domain registration warning (days)", "Registration expiring inside this window is a high finding."],
  renewalLeadDays: ["Renewal lead time (days)", "Renewal is flagged this many days before the termination-notice deadline, and until the renewal date."],
  upcomingDays: ["Portfolio look-ahead (days)", "Documents expiring inside this window are listed on the Portfolio tab."],
};

// ---------------------------------------------------------------------------
// Controls (only references we are sure of)
// ---------------------------------------------------------------------------

const C = {
  iso519: { framework: "ISO27001", id: "A.5.19" },
  iso520: { framework: "ISO27001", id: "A.5.20" },
  iso521: { framework: "ISO27001", id: "A.5.21" },
  iso522: { framework: "ISO27001", id: "A.5.22" },
  iso523: { framework: "ISO27001", id: "A.5.23" },
  soc2: { framework: "SOC2", id: "CC9.2" },
  csfSc05: { framework: "NIST-CSF", id: "GV.SC-05" },
  csfSc07: { framework: "NIST-CSF", id: "GV.SC-07" },
  csfSc10: { framework: "NIST-CSF", id: "GV.SC-10" },
  sr6: { framework: "NIST SP 800-161r1", id: "SR-6" },
  iso27036: { framework: "ISO/IEC 27036", id: "Part 2" },
  pci128: { framework: "PCI", id: "12.8.4" },
  hipaaB: { framework: "HIPAA", id: "164.308(b)(1)" },
  hipaa314: { framework: "HIPAA", id: "164.314(a)" },
  gdpr28: { framework: "GDPR", id: "Art. 28" },
  dmarc: { framework: "RFC", id: "7489 (DMARC)" },
  spf: { framework: "RFC", id: "7208 (SPF)" },
  sectxt: { framework: "RFC", id: "9116 (security.txt)" },
  phish: { framework: "MITRE", id: "T1566" },
};

// ---------------------------------------------------------------------------
// Date helpers (UTC, all driven by an explicit `now`)
// ---------------------------------------------------------------------------

const DAY = 86400000;
function ts(d) {
  if (d == null || d === "") return NaN;
  const s = String(d).trim();
  const t = /^\d{4}-\d{2}-\d{2}$/.test(s) ? Date.parse(s + "T00:00:00Z") : parseDay(s);
  return Number.isFinite(t) ? t : NaN;
}
// Date.parse reads a date-only "Oct 30, 2026" / "2026/10/30" as LOCAL midnight, which is the
// previous UTC day east of UTC: keep the written calendar day. Strings with a time stay absolute.
function parseDay(s) {
  const t = Date.parse(s);
  if (!Number.isFinite(t) || /\d:\d/.test(s)) return t;
  const d = new Date(t);
  return Date.UTC(d.getFullYear(), d.getMonth(), d.getDate());
}
export const isDate = (d) => Number.isFinite(ts(d));
const ymd = (t) => new Date(t).toISOString().slice(0, 10);
/** Whole calendar days (UTC) from `now` to `d` (negative = in the past). null when d is not a date. */
export function daysUntil(d, now) {
  const a = ts(d), b = ts(now);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
  return Math.floor(a / DAY) - Math.floor(b / DAY);
}
/** Add calendar months to a date (UTC), clamping the day to the month length. */
export function addMonths(d, months) {
  const t = ts(d);
  if (!Number.isFinite(t)) return null;
  const x = new Date(t);
  const y = x.getUTCFullYear(), m = x.getUTCMonth() + Number(months || 0), day = x.getUTCDate();
  const last = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
  return ymd(Date.UTC(y, m, Math.min(day, last)));
}

const str = (v) => (v == null ? "" : String(v));
const lc = (v) => str(v).trim().toLowerCase();
const uniqSorted = (a) => [...new Set(a)].sort();
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const GRADE_ORDER = ["A", "B", "C", "D", "F"];

// ---------------------------------------------------------------------------
// Record normalisation
// ---------------------------------------------------------------------------

export function cleanDomain(raw) {
  return lc(raw).replace(/^[a-z]+:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "").replace(/^www\./, "").replace(/\.$/, "");
}
export const validDomain = (d) => /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d);

const enumOf = (list, v, dflt) => {
  const s = lc(v);
  if (!s) return dflt;
  const hit = list.find((x) => x.id === s || lc(x.label) === s || lc(x.label).startsWith(s));
  return hit ? hit.id : dflt;
};

const SYN = {
  dataTier: { public: "none", "restricted/regulated": "restricted", regulated: "restricted", sensitive: "confidential", secret: "restricted" },
  systemAccess: { vpn: "network", "read-only": "read", readonly: "read", "read/write": "write", administrator: "admin", privileged: "admin" },
  dataTypes: { personal: "pii", "personal data": "pii", health: "phi", hipaa: "phi", cardholder: "pci", card: "pci", payment: "pci", banking: "financial", secrets: "credentials", code: "source", "source code": "source", hr: "employee" },
  integrations: { "api key": "apikeys", api: "apikeys", "api keys": "apikeys", oauth: "oauth", "oauth app": "oauth", agent: "agent", "on-prem agent": "agent", saml: "sso", oidc: "sso" },
};
function enumSyn(kind, list, v, dflt) { const s = lc(v); const row = SYN[kind]; if (row && Object.prototype.hasOwnProperty.call(row, s)) return row[s]; return enumOf(list, s, dflt); }
const splitList = (v) => (Array.isArray(v) ? v : str(v).split(/[;,|\n]/)).map((x) => str(x).trim()).filter(Boolean);
const bool = (v) => v === true || /^(y|yes|true|1|x)$/i.test(str(v).trim());

/** Normalise a record to the canonical shape (never throws; unknown enum values fall back to blank). */
export function normalizeRecord(r) {
  r = r && typeof r === "object" ? r : {};
  const docs = (Array.isArray(r.docs) ? r.docs : []).filter((d) => d && typeof d === "object").map((d, i) => ({
    id: str(d.id) || "d" + (i + 1),
    type: enumOf(DOC_TYPES, d.type, "") || str(d.type),
    issued: str(d.issued), periodEnd: str(d.periodEnd), expires: str(d.expires),
    scope: str(d.scope), exceptions: bool(d.exceptions), exceptionsText: str(d.exceptionsText),
  }));
  return {
    ...r,
    legalName: str(r.legalName || r.name).trim(),
    domains: uniqSorted(splitList(r.domains != null ? r.domains : r.domain).map(cleanDomain).filter(Boolean)).slice(0, 10),
    services: str(r.services), owner: str(r.owner),
    dataTier: enumSyn("dataTier", DATA_TIERS, r.dataTier, ""),
    dataTypes: uniqSorted(splitList(r.dataTypes).map((x) => enumSyn("dataTypes", DATA_TYPES, x, "")).filter(Boolean)),
    systemAccess: enumSyn("systemAccess", SYSTEM_ACCESS, r.systemAccess, ""),
    integrations: uniqSorted(splitList(r.integrations).map((x) => enumSyn("integrations", INTEGRATIONS, x, "")).filter(Boolean)),
    criticality: enumOf(CRITICALITY, r.criticality || r.tier, ""),
    spof: bool(r.spof), sendsMail: bool(r.sendsMail), exitPlan: str(r.exitPlan),
    subProcessors: str(r.subProcessors), regions: str(r.regions),
    docs,
    contractStart: str(r.contractStart), renewal: str(r.renewal), noticeDays: r.noticeDays === "" || r.noticeDays == null ? "" : Number(r.noticeDays),
    lastReview: str(r.lastReview), nextReview: str(r.nextReview),
    questionnaireScore: r.questionnaireScore === "" || r.questionnaireScore == null ? "" : Number(r.questionnaireScore),
    payeeLink: r.payeeLink && typeof r.payeeLink === "object" ? r.payeeLink : null,
    linkedFindings: splitList(r.linkedFindings),
    notes: str(r.notes),
    history: Array.isArray(r.history) ? r.history.slice(-DEFAULTS.historyCap) : [],
    posture: Array.isArray(r.posture) ? r.posture.slice(-DEFAULTS.snapshotCap) : [],
  };
}

/** Problems that block saving (shown in the form). */
export function validateRecord(r) {
  const errs = [];
  if (!str(r.legalName).trim()) errs.push("Legal name is required.");
  const doms = splitList(r.domains);
  if (doms.length > 10) errs.push("At most 10 domains.");
  for (const d of doms) if (!validDomain(cleanDomain(d))) errs.push("Not a valid domain: " + d);
  for (const k of ["contractStart", "renewal", "lastReview", "nextReview"]) if (r[k] && !isDate(r[k])) errs.push(k + " is not a date (YYYY-MM-DD).");
  if (r.questionnaireScore !== "" && r.questionnaireScore != null && !(Number(r.questionnaireScore) >= 0 && Number(r.questionnaireScore) <= 100)) errs.push("Questionnaire score must be 0-100.");
  return errs;
}

/** Append a history line (cap 50). Returns a new record. */
export function addHistory(rec, at, what, cap = DEFAULTS.historyCap) {
  const history = (rec.history || []).concat([{ at: str(at), what: str(what) }]).slice(-cap);
  return { ...rec, history };
}

/** Register schema for openRegister("vendorrisk", "VENDOR", { schema }). Mirrors the VENDOR entity fields. */
export const REGISTER_SCHEMA = {
  key: "id",
  name: (r) => str(r.legalName) || "Unnamed vendor",
  severity: (r) => ({ critical: "critical", high: "high", medium: "medium", low: "low" }[r.criticality] || null),
  status: () => "open",
  summary: (r) => ({
    legalName: str(r.legalName),
    domain: (r.domains || [])[0] || "",
    tier: r.criticality || "",
    dataShared: (r.dataTypes || []).slice(),
    contractEnd: r.renewal || "",
    owner: str(r.owner),
    paymentsEnabled: !!(r.payeeLink && r.payeeLink.name),
  }),
  columns: [
    { key: "id", label: "ID" }, { key: "legalName", label: "Legal name" }, { key: "domains", label: "Domains" },
    { key: "services", label: "Services" }, { key: "owner", label: "Business owner" }, { key: "dataTier", label: "Data access tier" },
    { key: "dataTypes", label: "Data types" }, { key: "systemAccess", label: "System access" }, { key: "integrations", label: "Integration" },
    { key: "criticality", label: "Criticality" }, { key: "spof", label: "Single point of failure" }, { key: "regions", label: "Regions" },
    { key: "subProcessors", label: "Sub-processors" }, { key: "contractStart", label: "Contract start" }, { key: "renewal", label: "Renewal" },
    { key: "noticeDays", label: "Termination notice days" }, { key: "lastReview", label: "Last review" }, { key: "nextReview", label: "Next review" },
    { key: "questionnaireScore", label: "Questionnaire score" }, { key: "notes", label: "Notes" },
  ],
};

// ---------------------------------------------------------------------------
// Inherent risk, assurance credit, residual
// ---------------------------------------------------------------------------

function mergePolicy(p) {
  const d = DEFAULT_POLICY, q = p || {};
  const pt = q.points || {};
  return {
    reviewMonths: { ...d.reviewMonths, ...(q.reviewMonths || {}) },
    points: {
      dataTier: { ...d.points.dataTier, ...(pt.dataTier || {}) },
      dataTypes: { ...d.points.dataTypes, ...(pt.dataTypes || {}) },
      dataTypeCap: pt.dataTypeCap != null ? Number(pt.dataTypeCap) : d.points.dataTypeCap,
      systemAccess: { ...d.points.systemAccess, ...(pt.systemAccess || {}) },
      integrations: { ...d.points.integrations, ...(pt.integrations || {}) },
      spof: pt.spof != null ? Number(pt.spof) : d.points.spof,
      criticalityMultiplier: { ...d.points.criticalityMultiplier, ...(pt.criticalityMultiplier || {}) },
    },
    credit: { ...d.credit, ...(q.credit || {}) },
    posture: { ...d.posture, ...(q.posture || {}) },
    bands: { ...d.bands, ...(q.bands || {}) },
  };
}
export { mergePolicy };

export function bandOf(score, bands) {
  const b = bands || DEFAULT_POLICY.bands;
  if (score == null) return null;
  if (score >= b.critical) return "critical";
  if (score >= b.high) return "high";
  if (score >= b.medium) return "medium";
  return "low";
}

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
const r1 = (x) => Math.round(x * 10) / 10;

/** Inherent risk 0-100 from the points table: (tier + types(capped) + access + integrations + spof) x criticality multiplier, scaled by the table maximum. */
export function inherentRisk(rec, policy) {
  const P = mergePolicy(policy).points;
  const parts = [];
  const tierPts = num(P.dataTier[rec.dataTier]);
  parts.push({ factor: "Data access tier", value: label(DATA_TIERS, rec.dataTier) || "not set", points: tierPts });
  const typeRaw = (rec.dataTypes || []).reduce((a, t) => a + num(P.dataTypes[t]), 0);
  const typePts = Math.min(typeRaw, num(P.dataTypeCap));
  parts.push({ factor: "Data types", value: (rec.dataTypes || []).map((t) => label(DATA_TYPES, t)).join(", ") || "none", points: typePts, note: typeRaw > typePts ? "capped at " + P.dataTypeCap : "" });
  const accPts = num(P.systemAccess[rec.systemAccess]);
  parts.push({ factor: "System access", value: label(SYSTEM_ACCESS, rec.systemAccess) || "not set", points: accPts });
  const intPts = (rec.integrations || []).reduce((a, t) => a + num(P.integrations[t]), 0);
  parts.push({ factor: "Integration", value: (rec.integrations || []).map((t) => label(INTEGRATIONS, t)).join(", ") || "none", points: intPts });
  const spofPts = rec.spof ? num(P.spof) : 0;
  parts.push({ factor: "Single point of failure", value: rec.spof ? "yes" : "no", points: spofPts });
  const mult = rec.criticality ? num(P.criticalityMultiplier[rec.criticality]) : 1;
  const base = tierPts + typePts + accPts + intPts + spofPts;
  const raw = base * mult;
  const maxMult = Math.max(...Object.values(P.criticalityMultiplier).map(num), 1);
  const maxBase = Math.max(...Object.values(P.dataTier).map(num), 0) + num(P.dataTypeCap) + Math.max(...Object.values(P.systemAccess).map(num), 0) +
    Object.values(P.integrations).reduce((a, v) => a + num(v), 0) + num(P.spof);
  const max = maxBase * maxMult;
  const score = max > 0 ? Math.min(100, Math.round((raw / max) * 100)) : 0;
  return { score, band: bandOf(score, mergePolicy(policy).bands), base, multiplier: mult, criticality: rec.criticality || "not set", raw: r1(raw), max: r1(max), parts };
}

const docsOf = (rec, type) => (rec.docs || []).filter((d) => d.type === type);
const notExpired = (d, now) => !d.expires || (isDate(d.expires) && daysUntil(d.expires, now) >= 0);
const newestBy = (list, key) => list.slice().sort((a, b) => (ts(b[key]) || 0) - (ts(a[key]) || 0) || str(a.id).localeCompare(str(b.id)))[0] || null;

/** Is there a bridge letter issued on/after the report period end that has not expired? */
function bridgeCovers(rec, report, now) {
  return docsOf(rec, "bridge").some((b) => isDate(b.issued) && ts(b.issued) >= ts(report.periodEnd) && notExpired(b, now));
}

/** Current = period end within socStaleMonths (or bridged) and not expired. */
function socCurrent(rec, report, now, o) {
  if (!report || !isDate(report.periodEnd) || !notExpired(report, now)) return false;
  const stale = daysUntil(addMonths(report.periodEnd, o.socStaleMonths), now) < 0;
  return !stale || bridgeCovers(rec, report, now);
}

function freshDoc(d, now, months) {
  const ref = d.periodEnd || d.issued;
  return !!d && isDate(ref) && daysUntil(addMonths(ref, months), now) >= 0 && notExpired(d, now);
}

/** Required contractual documents given the data types. */
export function requiredDocs(rec) {
  const req = [];
  const t = new Set(rec.dataTypes || []);
  if (t.has("pii") || t.has("phi")) req.push("dpa");
  if (t.has("phi")) req.push("baa");
  if (t.has("pci")) req.push("pciaoc");
  return req;
}

/** Assurance credit (percent off inherent), with each line shown. */
export function assuranceCredit(rec, policy, now, opts) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  const K = mergePolicy(policy).credit;
  const parts = [];
  const t2 = newestBy(docsOf(rec, "soc2t2"), "periodEnd");
  const t1 = newestBy(docsOf(rec, "soc2t1"), "periodEnd");
  if (t2 && socCurrent(rec, t2, now, o)) parts.push({ item: "Current SOC 2 Type II", credit: num(K.soc2t2) });
  else if (t1 && socCurrent(rec, t1, now, o)) parts.push({ item: "Current SOC 2 Type I", credit: num(K.soc2t1) });
  const iso = docsOf(rec, "iso27001").find((d) => isDate(d.expires) && daysUntil(d.expires, now) >= 0);
  if (iso) parts.push({ item: "Valid ISO 27001 certificate", credit: num(K.iso27001) });
  const pt = newestBy(docsOf(rec, "pentest"), "issued");
  if (pt && freshDoc(pt, now, o.freshMonths)) parts.push({ item: "Pentest within " + o.freshMonths + " months", credit: num(K.pentest) });
  const q = newestBy(docsOf(rec, "questionnaire"), "issued");
  if (q && freshDoc(q, now, o.freshMonths)) {
    const qs = rec.questionnaireScore === "" || rec.questionnaireScore == null ? 100 : Math.max(0, Math.min(100, Number(rec.questionnaireScore)));
    const c = Math.round(num(K.questionnaire) * qs / 100 * 10) / 10;
    parts.push({ item: "Questionnaire within " + o.freshMonths + " months" + (rec.questionnaireScore !== "" && rec.questionnaireScore != null ? " (score " + qs + ")" : ""), credit: c });
  }
  const ins = docsOf(rec, "insurance").find((d) => isDate(d.expires) && daysUntil(d.expires, now) >= 0);
  if (ins) parts.push({ item: "Cyber insurance in force", credit: num(K.insurance) });
  for (const req of requiredDocs(rec)) {
    if (docsOf(rec, req).some((d) => notExpired(d, now))) parts.push({ item: docLabel(req) + " on file (required by data types)", credit: num(K.requiredContract) });
  }
  const total = parts.reduce((a, p) => a + p.credit, 0);
  const pct = Math.min(num(K.cap), r1(total));
  return { pct, uncapped: r1(total), cap: num(K.cap), parts };
}

// ---------------------------------------------------------------------------
// Posture: DoH / CT / HTTP / security.txt / RDAP raw results -> graded checks
// ---------------------------------------------------------------------------

export const CHECKS = [
  { id: "mx", label: "MX", category: "email" },
  { id: "spf", label: "SPF", category: "email" },
  { id: "dmarc", label: "DMARC", category: "email" },
  { id: "dkim", label: "DKIM", category: "email" },
  { id: "mtasts", label: "MTA-STS", category: "email" },
  { id: "tlsrpt", label: "TLS-RPT", category: "email" },
  { id: "dnssec", label: "DNSSEC", category: "dns" },
  { id: "caa", label: "CAA", category: "dns" },
  { id: "ns", label: "NS diversity", category: "dns" },
  { id: "cert", label: "Certificate (CT)", category: "web" },
  { id: "https", label: "HTTPS", category: "web" },
  { id: "hsts", label: "HSTS", category: "web" },
  { id: "headers", label: "Security headers", category: "web" },
  { id: "securitytxt", label: "security.txt", category: "disclosure" },
  { id: "rdap", label: "Domain registration", category: "registration" },
  { id: "leak", label: "Ransomware leak trackers", category: "exposure" },
];
const CHECK_ORDER = Object.assign(Object.create(null), Object.fromEntries(CHECKS.map((c, i) => [c.id, i])));
const STATUS_SCORE = { __proto__: null, pass: 100, warn: 55, fail: 0 };
export const DNS_TYPES = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, DS: 43, CAA: 257 };

/** Decode Answer data of one RR type from a DoH JSON response (dns.google or cloudflare-dns.com shape). */
export function dohAnswers(json, type) {
  const want = typeof type === "number" ? type : DNS_TYPES[type];
  const ans = (json && Array.isArray(json.Answer)) ? json.Answer : [];
  return ans.filter((a) => a && (a.type === want || a.type === type)).map((a) => {
    let d = str(a.data);
    if (want === 16) d = d.replace(/^"|"$/g, "").replace(/"\s*"/g, "");
    return d;
  });
}
/** DoH status: "ok" (NOERROR / NXDOMAIN, answers decoded) or "error". */
function dohState(resp) {
  if (!resp) return { state: "skip", reason: "not run" };
  if (resp.error) return { state: "error", reason: str(resp.error) };
  if (resp.Status === 0 || resp.Status === 3) return { state: "ok", nx: resp.Status === 3 };
  return { state: "error", reason: "DNS status " + resp.Status + (resp.Status === 2 ? " (SERVFAIL)" : "") };
}

/** Registrable-ish provider key for a nameserver host (last two labels). */
export function nsProvider(host) {
  const parts = lc(host).replace(/\.$/, "").split(".").filter(Boolean);
  return parts.slice(-2).join(".");
}

const MULTI_SLD = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "com.br", "com.mx", "com.cn", "com.sg", "com.hk", "co.in", "co.za", "co.kr", "com.tr", "com.ar", "co.il", "com.my", "com.tw"]);
/** Best-effort registrable domain (last two labels, three for common two-part suffixes). An approximation, not the Public Suffix List. */
export function registrableGuess(domain) {
  const p = cleanDomain(domain).split(".").filter(Boolean);
  if (p.length <= 2) return p.join(".");
  return MULTI_SLD.has(p.slice(-2).join(".")) ? p.slice(-3).join(".") : p.slice(-2).join(".");
}

/** ransomware.live /v2/searchvictims response -> { rows, keyword } or { error }. Its "No victims found" 404 body means zero rows. */
export function leakResponse(json, keyword) {
  if (Array.isArray(json)) return { rows: json, keyword: str(keyword) };
  if (json && typeof json === "object" && /no victims found/i.test(str(json.error))) return { rows: [], keyword: str(keyword) };
  const msg = json && typeof json === "object" ? str(json.message || json.error) : "";
  return { error: "ransomware.live: " + (msg || "unexpected response") + (/per\s+\d*\s*minute/i.test(msg) ? " (rate limited; try again in a minute)" : "") };
}

/** RDAP domain JSON (rdap.org shape) -> { expires, registrar, registered, status }. */
export function parseRdap(json) {
  const ev = Array.isArray(json && json.events) ? json.events : [];
  const at = (action) => { const e = ev.find((x) => lc(x.eventAction) === action); return e ? str(e.eventDate) : ""; };
  let registrar = "";
  for (const e of (json && json.entities) || []) {
    if (!(e.roles || []).includes("registrar")) continue;
    const v = (e.vcardArray && e.vcardArray[1]) || [];
    const fn = v.find((x) => Array.isArray(x) && x[0] === "fn");
    registrar = fn ? str(fn[3]) : str((e.publicIds || [])[0] && e.publicIds[0].identifier);
  }
  return { expires: at("expiration"), registered: at("registration"), registrar, status: (json && json.status) || [], dnssec: !!(json && json.secureDNS && json.secureDNS.delegationSigned) };
}

/** security.txt body -> { contact, expires } (RFC 9116 fields). */
export function parseSecurityTxt(body) {
  const lines = str(body).split(/\r?\n/);
  const contact = [], out = { contact, expires: "" };
  for (const l of lines) {
    const m = l.match(/^\s*([A-Za-z-]+)\s*:\s*(.+?)\s*$/);
    if (!m) continue;
    const k = m[1].toLowerCase();
    if (k === "contact") contact.push(m[2]);
    if (k === "expires" && !out.expires) out.expires = m[2];
  }
  return out;
}

const nameNorm = (s) => lc(s).replace(/[,.]/g, " ").replace(/\b(inc|llc|ltd|limited|corp|corporation|co|gmbh|plc|sa|ag|bv|pty|company)\b/g, " ").replace(/[^a-z0-9]+/g, " ").trim();

/** Match ransomware.live searchvictims rows to a vendor: exact domain or exact normalised name = match; anything else = possible. */
export function matchLeakRows(rows, { domains = [], legalName = "" } = {}) {
  const ds = new Set(domains.map(cleanDomain));
  const nn = nameNorm(legalName);
  const exact = [], possible = [];
  for (const r of Array.isArray(rows) ? rows : []) {
    if (!r || typeof r !== "object") continue;
    const d = cleanDomain(r.domain || ""), v = str(r.victim);
    const row = { victim: v, domain: d, group: str(r.group), attackdate: str(r.attackdate).slice(0, 10), discovered: str(r.discovered).slice(0, 10), country: str(r.country), url: str(r.url) };
    if ((d && ds.has(d)) || ds.has(cleanDomain(v)) || (nn && nameNorm(v) === nn)) exact.push(row); else possible.push(row);
  }
  const by = (a, b) => (b.discovered + b.victim).localeCompare(a.discovered + a.victim);
  return { exact: exact.sort(by), possible: possible.sort(by) };
}

/**
 * Grade one domain's raw live results. Every raw part is either a parsed
 * response or { error } (network failure) or undefined (not run); failures are
 * reported as status "error", never turned into pass or fail.
 * raw = { domain, mx, txt, dmarc, mtasts, mtastsPolicy:{status,body}, tlsrpt, ds, caa, ns,
 *         https:{status,headers,finalUrl}, http:{status,finalUrl}, cert:{rows}, securityTxt:{status,body}, rdap:{json}, leak:{rows, keyword} }
 */
export function gradeDomain(raw, { now, legalName = "", certWarnDays = DEFAULTS.certWarnDays, domainWarnDays = DEFAULTS.domainWarnDays } = {}) {
  const domain = cleanDomain(raw && raw.domain);
  const out = [];
  const put = (check, status, evidence) => out.push({ domain, check, status, evidence: str(evidence).slice(0, 400) });
  const nowMs = ts(now);
  raw = raw || {};
  const apexNote = raw.apex && cleanDomain(raw.apex) !== domain ? " (checked at " + cleanDomain(raw.apex) + ")" : "";

  // MX
  const mxS = dohState(raw.mx);
  let hasMx = false;
  if (mxS.state !== "ok") put("mx", mxS.state, mxS.reason);
  else {
    const mx = dohAnswers(raw.mx, "MX").sort();
    hasMx = mx.length > 0 && !(mx.length === 1 && /^0\s+\.$/.test(mx[0]));
    put("mx", "info", hasMx ? "MX: " + mx.join(", ") : mx.length ? "Null MX (domain does not accept mail)" : "No MX records");
  }
  // SPF
  const txtS = dohState(raw.txt);
  if (txtS.state !== "ok") put("spf", txtS.state, txtS.reason);
  else {
    const txts = dohAnswers(raw.txt, "TXT");
    const spfs = txts.filter((t) => /^v=spf1\b/i.test(t.trim()));
    const spf = parseSPF(txts);
    if (!spf.present) put("spf", "fail", "No v=spf1 TXT record");
    else if (spfs.length > 1) put("spf", "fail", spfs.length + " SPF records (RFC 7208 permerror): " + spfs.join(" | "));
    else {
      const n = spfLookupCount(spf.record);
      const q = spf.qualifier;
      const ev = spf.record + " [top-level lookups " + n + "]";
      if (q === "+" || (q == null && /(^|\s)all\b/i.test(spf.record))) put("spf", "fail", "+all lets any host send as this domain: " + ev);
      else if (n > 10) put("spf", "fail", "More than 10 DNS lookups (permerror): " + ev);
      else if (q === "?" || q == null) put("spf", "warn", (q === "?" ? "?all (neutral)" : "no all mechanism") + ": " + ev);
      else if (q === "~") put("spf", "warn", "~all (softfail): " + ev);
      else put("spf", "pass", ev);
    }
  }
  // DMARC
  const dmS = dohState(raw.dmarc);
  if (dmS.state !== "ok") put("dmarc", dmS.state, dmS.reason);
  else {
    const d = parseDMARC(dohAnswers(raw.dmarc, "TXT"));
    if (!d.present) put("dmarc", "fail", "No v=DMARC1 record at _dmarc." + domain);
    else {
      const ev = "p=" + d.policy + " pct=" + d.pct + " rua=" + (d.rua || "none") + " | " + d.record;
      if (d.policy === "none") put("dmarc", "warn", "Monitoring only: " + ev);
      else if (d.pct < 100) put("dmarc", "warn", "Enforcement on " + d.pct + "% only: " + ev);
      else put("dmarc", "pass", ev);
    }
  }
  put("dkim", "skip", "DKIM keys live under selector names the sender chooses; without the vendor's selectors it cannot be checked.");
  // MTA-STS
  const mtS = dohState(raw.mtasts);
  if (mtS.state !== "ok") put("mtasts", mtS.state, mtS.reason);
  else {
    const txts = dohAnswers(raw.mtasts, "TXT");
    const pol = raw.mtastsPolicy;
    const m = parseMtaSts(txts, pol && !pol.error && pol.status === 200 ? pol.body : null);
    if (!m.present) put("mtasts", "warn", "No _mta-sts TXT record");
    else if (!pol) put("mtasts", "skip", "TXT present (" + m.record + "); policy file not fetched");
    else if (pol.error) put("mtasts", "error", "TXT present; policy fetch failed: " + pol.error);
    else if (pol.status !== 200) put("mtasts", "fail", "TXT present but https://mta-sts." + domain + "/.well-known/mta-sts.txt returned HTTP " + pol.status);
    else if (m.mode === "enforce") put("mtasts", "pass", "mode=enforce max_age=" + m.maxAge);
    else put("mtasts", "warn", "mode=" + (m.mode || "missing") + " max_age=" + m.maxAge);
  }
  // TLS-RPT
  const trS = dohState(raw.tlsrpt);
  if (trS.state !== "ok") put("tlsrpt", trS.state, trS.reason);
  else {
    const t = dohAnswers(raw.tlsrpt, "TXT").find((x) => /^v=tlsrptv1\b/i.test(x.trim()));
    put("tlsrpt", t ? "pass" : "warn", t ? t : "No _smtp._tls TXT record");
  }
  // DNSSEC
  const dsS = dohState(raw.ds);
  if (dsS.state !== "ok") put("dnssec", dsS.state, dsS.reason);
  else {
    const ds = dohAnswers(raw.ds, "DS");
    put("dnssec", ds.length ? "pass" : "warn", (ds.length ? "DS " + ds.length + " record(s); resolver AD flag " + (raw.ds.AD ? "set (validated)" : "not set") : "No DS record at the parent: zone is unsigned") + apexNote);
  }
  // CAA
  const caaS = dohState(raw.caa);
  if (caaS.state !== "ok") put("caa", caaS.state, caaS.reason);
  else {
    const caa = dohAnswers(raw.caa, "CAA").sort();
    put("caa", caa.length ? "pass" : "warn", caa.length ? caa.join(" | ") : "No CAA record: any CA may issue certificates");
  }
  // NS diversity
  const nsS = dohState(raw.ns);
  if (nsS.state !== "ok") put("ns", nsS.state, nsS.reason);
  else {
    const ns = dohAnswers(raw.ns, "NS").map((h) => lc(h).replace(/\.$/, "")).sort();
    const prov = uniqSorted(ns.map(nsProvider));
    if (!ns.length) put("ns", "error", "No NS records returned at this name");
    else if (ns.length < 2) put("ns", "fail", "Single nameserver: " + ns.join(", "));
    else if (prov.length < 2) put("ns", "warn", "All " + ns.length + " nameservers at one provider (" + prov[0] + "): " + ns.join(", "));
    else put("ns", "pass", prov.length + " providers: " + ns.join(", ") + apexNote);
  }
  // Certificate via CT
  if (!raw.cert) put("cert", "skip", "not run");
  else if (raw.cert.error) put("cert", "error", raw.cert.error);
  else {
    const rows = Array.isArray(raw.cert.rows) ? raw.cert.rows : [];
    const c = rows.length ? newestCert(rows, nowMs) : null;
    if (!c) put("cert", "error", "No certificate-transparency rows returned (crt.sh and certspotter)");
    else {
      const days = certDaysLeft(c.notAfter, nowMs);
      const wild = /(^|\s)\*\./.test(c.names);
      const ev = "newest cert expires " + str(c.notAfter).slice(0, 10) + " (" + days + " days), issuer " + (c.issuer.match(/O=([^,]+)/) || [0, c.issuer])[1] + (wild ? ", wildcard" : "");
      put("cert", days < 0 ? "fail" : days < certWarnDays ? "warn" : "pass", ev);
    }
  }
  // HTTPS / HSTS / headers
  if (!raw.https) { put("https", "skip", "not run"); put("hsts", "skip", "not run"); put("headers", "skip", "not run"); }
  else if (raw.https.error) {
    put("https", "error", raw.https.error);
    put("hsts", "error", "HTTPS fetch failed"); put("headers", "error", "HTTPS fetch failed");
  } else {
    const http = raw.http && !raw.http.error ? raw.http : null;
    const input = {
      headers: raw.https.headers || {},
      httpsOk: raw.https.status > 0 && raw.https.status < 600, httpTested: !!http,
      httpRedirectsToHttps: http ? /^https:/i.test(http.finalUrl || "") : false,
    };
    const tr = gradeTransport(input).checks;
    const hs = tr.find((c) => c.name === "HSTS"), hc = tr.find((c) => c.name === "HTTPS"), rd = tr.find((c) => c.name === "HTTP to HTTPS redirect");
    put("https", hc.status === "pass" && (!rd || rd.status === "pass") ? "pass" : "fail", "HTTP " + raw.https.status + " at " + (raw.https.finalUrl || "https://" + domain) + (rd ? "; " + rd.detail : "; plain HTTP not tested"));
    put("hsts", hs.status, hs.detail);
    const hd = gradeHeaders(input).checks;
    const scored = hd.map((c) => STATUS_SCORE[c.status]).filter((s) => s != null);
    const sc = scored.length ? Math.round(scored.reduce((a, b) => a + b, 0) / scored.length) : null;
    const bad = hd.filter((c) => c.status === "fail").map((c) => c.name);
    put("headers", sc == null ? "skip" : sc >= 80 ? "pass" : sc >= 50 ? "warn" : "fail", "score " + sc + "/100" + (bad.length ? "; missing or failing: " + bad.join(", ") : "; no failing headers"));
  }
  // security.txt
  if (!raw.securityTxt) put("securitytxt", "skip", "not run");
  else if (raw.securityTxt.error) put("securitytxt", "error", raw.securityTxt.error);
  else if (raw.securityTxt.status !== 200 || /^\s*</.test(str(raw.securityTxt.body)) || !/^contact\s*:/im.test(str(raw.securityTxt.body))) put("securitytxt", "warn", "No /.well-known/security.txt with a Contact field (HTTP " + raw.securityTxt.status + ")");
  else {
    const s = parseSecurityTxt(raw.securityTxt.body);
    if (!s.expires) put("securitytxt", "warn", "Present but no Expires field (required by RFC 9116); Contact " + s.contact.join(", "));
    else if (isDate(s.expires) && ts(s.expires) < nowMs) put("securitytxt", "warn", "Expired " + s.expires + "; Contact " + s.contact.join(", "));
    else put("securitytxt", "pass", "Contact " + s.contact.join(", ") + "; Expires " + s.expires);
  }
  // RDAP
  if (!raw.rdap) put("rdap", "skip", "not run");
  else if (raw.rdap.error) put("rdap", "error", raw.rdap.error);
  else {
    const r = parseRdap(raw.rdap.json);
    const days = r.expires ? daysUntil(r.expires, now) : null;
    if (days == null) put("rdap", "error", "RDAP response has no expiration event" + (r.registrar ? "; registrar " + r.registrar : ""));
    else put("rdap", days < domainWarnDays ? "fail" : days < 60 ? "warn" : "pass", "expires " + r.expires.slice(0, 10) + " (" + days + " days); registrar " + (r.registrar || "not listed") + apexNote);
  }
  // Leak trackers (opt-in, not part of the grade)
  if (raw.leak) {
    if (raw.leak.error) put("leak", "error", raw.leak.error);
    else {
      const m = matchLeakRows(raw.leak.rows, { domains: [domain], legalName });
      if (m.exact.length) put("leak", "fail", "Listed: " + m.exact.map((x) => x.victim + " by " + x.group + " (" + x.discovered + ")").join("; "));
      else put("leak", "info", "No exact match for '" + str(raw.leak.keyword) + "'" + (m.possible.length ? "; " + m.possible.length + " unrelated name match(es) ignored" : ""));
    }
  }
  return out.sort((a, b) => CHECK_ORDER[a.check] - CHECK_ORDER[b.check]);
}

/** Score posture results: per-category average of pass/warn/fail, then mean of categories, per domain and overall. */
export function postureScore(results) {
  const byDomain = new Map();
  for (const r of results || []) {
    if (!byDomain.has(r.domain)) byDomain.set(r.domain, []);
    byDomain.get(r.domain).push(r);
  }
  const domains = [];
  for (const [domain, rs] of [...byDomain].sort((a, b) => a[0].localeCompare(b[0]))) {
    const cats = {};
    for (const r of rs) {
      const cat = (CHECKS[CHECK_ORDER[r.check]] || {}).category;
      if (!cat || cat === "exposure") continue;
      const s = STATUS_SCORE[r.status];
      if (s == null) continue;
      (cats[cat] = cats[cat] || []).push(s);
    }
    const cs = Object.keys(cats).sort().map((k) => ({ category: k, score: Math.round(cats[k].reduce((a, b) => a + b, 0) / cats[k].length) }));
    const score = cs.length ? Math.round(cs.reduce((a, c) => a + c.score, 0) / cs.length) : null;
    const counts = { __proto__: null, pass: 0, warn: 0, fail: 0, error: 0, skip: 0, info: 0 };
    for (const r of rs) counts[r.status] = (counts[r.status] || 0) + 1;
    domains.push({ domain, score, grade: letterGrade(score), categories: cs, counts });
  }
  const graded = domains.filter((d) => d.score != null);
  const score = graded.length ? Math.round(graded.reduce((a, d) => a + d.score, 0) / graded.length) : null;
  return { score, grade: letterGrade(score), domains };
}

/** Make a snapshot from graded results. */
export function makeSnapshot(results, at) {
  const ps = postureScore(results);
  return { at: str(at), score: ps.score, grade: ps.grade, results: (results || []).map((r) => ({ domain: r.domain, check: r.check, status: r.status, evidence: r.evidence })) };
}

/**
 * Add a snapshot, keep the last `cap` (12), and keep the serialised record under
 * `maxBytes` (the graph mirror limit) by dropping evidence, then per-check
 * results, from the OLDEST snapshots first. The newest two always keep results.
 */
export function addSnapshot(rec, snap, { cap = DEFAULTS.snapshotCap, maxBytes = 36000 } = {}) {
  const posture = (rec.posture || []).concat([snap]).sort((a, b) => str(a.at).localeCompare(str(b.at))).slice(-cap);
  return compactRecord({ ...rec, posture }, maxBytes);
}
export function compactRecord(rec, maxBytes = 36000) {
  const size = (r) => JSON.stringify(r).length;
  if (size(rec) <= maxBytes) return rec;
  const posture = (rec.posture || []).map((s) => ({ ...s, results: (s.results || []).slice() }));
  const out = { ...rec, posture };
  const keep = Math.max(0, posture.length - 2);
  for (let i = 0; i < keep && size(out) > maxBytes; i++) posture[i] = { ...posture[i], results: posture[i].results.map((r) => ({ domain: r.domain, check: r.check, status: r.status })), compacted: "evidence" };
  for (let i = 0; i < keep && size(out) > maxBytes; i++) posture[i] = { at: posture[i].at, score: posture[i].score, grade: posture[i].grade, results: [], compacted: "results" };
  for (let i = posture.length - 2; i < posture.length && i >= 0 && size(out) > maxBytes; i++) posture[i] = { ...posture[i], results: posture[i].results.map((r) => ({ ...r, evidence: str(r.evidence).slice(0, 80) })) };
  return out;
}

/** Diff two snapshots: new failures, fixed items, now-unreachable checks, grade change. */
export function diffSnapshots(prev, cur) {
  const res = { from: prev ? prev.at : null, to: cur ? cur.at : null, gradeFrom: prev ? prev.grade : null, gradeTo: cur ? cur.grade : null, scoreFrom: prev ? prev.score : null, scoreTo: cur ? cur.score : null, newFailures: [], fixed: [], worsened: [], improved: [], unreachable: [], added: [], gradeDrop: 0 };
  if (!prev || !cur) return res;
  const key = (r) => r.domain + "|" + r.check;
  const P = new Map((prev.results || []).map((r) => [key(r), r]));
  const rank = { pass: 0, warn: 1, fail: 2 };
  for (const r of (cur.results || []).slice().sort((a, b) => key(a).localeCompare(key(b)))) {
    const p = P.get(key(r));
    const row = { domain: r.domain, check: r.check, from: p ? p.status : "none", to: r.status, evidence: r.evidence || "" };
    if (!p) { if (!(prev.results || []).length) continue; res.added.push(row); continue; }
    if (r.status === p.status) continue;
    if (r.status === "error" && rank[p.status] != null) { res.unreachable.push(row); continue; }
    if (rank[r.status] == null || rank[p.status] == null) continue;
    if (r.status === "fail") res.newFailures.push(row);
    else if (p.status === "fail" && r.status === "pass") res.fixed.push(row);
    else if (rank[r.status] > rank[p.status]) res.worsened.push(row);
    else res.improved.push(row);
  }
  const gi = (g) => GRADE_ORDER.indexOf(g);
  if (gi(prev.grade) >= 0 && gi(cur.grade) >= 0) res.gradeDrop = gi(cur.grade) - gi(prev.grade);
  return res;
}

/** Trend text from the last two snapshots: "up", "down", "same" or "". */
export function trendOf(rec) {
  const p = rec.posture || [];
  if (p.length < 2) return "";
  const a = p[p.length - 2], b = p[p.length - 1];
  if (a.score == null || b.score == null) return "";
  return b.score > a.score ? "up" : b.score < a.score ? "down" : "same";
}

// ---------------------------------------------------------------------------
// Vendor grading + findings
// ---------------------------------------------------------------------------

export function nextReviewDate(rec, policy) {
  if (rec.nextReview && isDate(rec.nextReview)) return { date: rec.nextReview, source: "set on the record" };
  const months = mergePolicy(policy).reviewMonths[rec.criticality];
  if (rec.lastReview && isDate(rec.lastReview) && months) return { date: addMonths(rec.lastReview, months), source: "last review + " + months + " months (" + rec.criticality + " policy)" };
  return { date: "", source: rec.lastReview ? "no review frequency for this criticality" : "never reviewed" };
}

function vendorAsset(rec) {
  return { type: "VENDOR", name: rec.legalName || "Unnamed vendor", data: { legalName: rec.legalName, domain: (rec.domains || [])[0] || "", tier: rec.criticality || "", dataShared: (rec.dataTypes || []).slice(), contractEnd: rec.renewal || "", owner: rec.owner || "" } };
}

/**
 * Grade one vendor. postureResults defaults to the newest snapshot's results.
 * Returns inherent, credit, posture, residual, diff, nextReview and findings.
 */
export function gradeVendor(record, postureResults, policy, { now, ...opts } = {}) {
  const o = { ...DEFAULTS, ...opts };
  const rec = normalizeRecord(record);
  const P = mergePolicy(policy);
  const snaps = rec.posture || [];
  const latest = snaps[snaps.length - 1] || null;
  const results = postureResults || (latest ? latest.results : []);
  const inherent = inherentRisk(rec, P);
  const credit = assuranceCredit(rec, P, now, o);
  const posture = results && results.length ? postureScore(results) : (latest ? { score: latest.score, grade: latest.grade, domains: [] } : { score: null, grade: "N/A", domains: [] });
  const postureAdj = posture.grade && P.posture[posture.grade] != null ? num(P.posture[posture.grade]) : 0;
  const residualScore = Math.max(0, Math.min(100, Math.round(inherent.score * (1 - credit.pct / 100) + postureAdj)));
  const residual = { score: residualScore, band: bandOf(residualScore, P.bands), postureAdjustment: postureAdj, formula: inherent.score + " x (1 - " + credit.pct + "%) " + (postureAdj >= 0 ? "+ " : "- ") + Math.abs(postureAdj) + " (posture " + posture.grade + ")" };
  const prev = snaps.length >= 2 ? snaps[snaps.length - 2] : null;
  const diff = latest && prev ? diffSnapshots(prev, latest) : null;
  const nr = nextReviewDate(rec, P);
  const findings = [];
  const V = vendorAsset(rec);
  const add = (f) => findings.push({ confidence: "confirmed", evidence: [], ...f, assets: [V].concat(f.assets || []), evidenceCount: (f.evidence || []).length, tags: ["vendor-risk"].concat(f.tags || []) });
  const vn = rec.legalName || "Unnamed vendor";
  const id = (k) => "tpr-" + k + "-" + (rec.id || nameNorm(vn).replace(/ /g, "-"));
  const hasDates = isDate(now);

  if (hasDates) {
    // Assurance documents expired / expiring
    for (const d of rec.docs.slice().sort((a, b) => str(a.id).localeCompare(str(b.id)))) {
      if (!isDate(d.expires)) continue;
      const days = daysUntil(d.expires, now);
      if (days < 0 || days <= o.docExpiringDays) {
        add({
          id: id("doc-" + d.id), title: days < 0 ? "Assurance document expired" : "Assurance document expiring soon",
          severity: days < 0 ? "high" : "medium", category: "assurance",
          description: vn + ": " + docLabel(d.type) + (days < 0 ? " expired " + d.expires + " (" + -days + " days ago)." : " expires " + d.expires + " (in " + days + " days, window " + o.docExpiringDays + ")."),
          recommendation: "Request the renewed " + docLabel(d.type) + " from the vendor and record it in the register.",
          controls: [C.iso522, C.soc2, C.csfSc07], evidence: [{ vendor: vn, document: docLabel(d.type), issued: d.issued, periodEnd: d.periodEnd, expires: d.expires, daysLeft: days }],
        });
      }
    }
    // SOC 2 period staleness without bridge letter
    const soc = newestBy(docsOf(rec, "soc2t2"), "periodEnd") || newestBy(docsOf(rec, "soc2t1"), "periodEnd");
    if (soc && isDate(soc.periodEnd) && daysUntil(addMonths(soc.periodEnd, o.socStaleMonths), now) < 0 && !bridgeCovers(rec, soc, now)) {
      add({
        id: id("soc-stale"), title: "SOC 2 report period ended over " + o.socStaleMonths + " months ago with no bridge letter", severity: "medium", category: "assurance",
        description: vn + ": newest " + docLabel(soc.type) + " period ended " + soc.periodEnd + " (" + -daysUntil(soc.periodEnd, now) + " days ago) and no bridge letter issued after it is on file.",
        recommendation: "Ask for the current report or a bridge (gap) letter covering the period since " + soc.periodEnd + ".",
        controls: [C.soc2, C.iso522, C.sr6], evidence: [{ vendor: vn, document: docLabel(soc.type), periodEnd: soc.periodEnd, bridgeLetters: docsOf(rec, "bridge").length }],
      });
    }
    // Missing required contract documents
    const reqMap = {
      dpa: { why: "personal data (PII/PHI) is shared", controls: [C.gdpr28, C.iso520, C.csfSc05] },
      baa: { why: "health data (PHI) is shared", controls: [C.hipaaB, C.hipaa314, C.iso520] },
      pciaoc: { why: "cardholder data (PCI) is shared", controls: [C.pci128, C.iso520] },
    };
    for (const req of requiredDocs(rec)) {
      if (docsOf(rec, req).some((d) => notExpired(d, now))) continue;
      const expired = docsOf(rec, req).length > 0;
      add({
        id: id("missing-" + req), title: "Missing " + docLabel(req) + " for a vendor handling regulated data", severity: "high", category: "contract",
        description: vn + ": " + reqMap[req].why + " but no " + (expired ? "unexpired " : "") + docLabel(req) + " is on file.",
        recommendation: "Put a " + docLabel(req) + " in place (or record why it is not required) before more data is shared.",
        controls: reqMap[req].controls, evidence: [{ vendor: vn, dataTypes: rec.dataTypes.join(", "), required: docLabel(req), onFile: docsOf(rec, req).map((d) => d.expires || "no expiry").join(", ") || "none" }],
      });
    }
    // Review overdue
    if (rec.criticality) {
      const nd = nr.date ? daysUntil(nr.date, now) : null;
      if (!rec.lastReview && !rec.nextReview) {
        add({ id: id("review-none"), title: "Vendor has never been reviewed", severity: "medium", category: "review",
          description: vn + " (" + rec.criticality + ") has no last review date on record.", recommendation: "Run a vendor review and record the date.",
          controls: [C.iso522, C.csfSc07, C.soc2], evidence: [{ vendor: vn, criticality: rec.criticality, lastReview: "", policyMonths: P.reviewMonths[rec.criticality] }] });
      } else if (nd != null && nd < 0) {
        add({ id: id("review-overdue"), title: "Vendor review overdue", severity: "medium", category: "review",
          description: vn + ": review was due " + nr.date + " (" + -nd + " days ago; " + nr.source + ").", recommendation: "Complete the periodic review and update the last review date.",
          controls: [C.iso522, C.csfSc07, C.soc2], evidence: [{ vendor: vn, criticality: rec.criticality, lastReview: rec.lastReview, nextReview: nr.date, daysOverdue: -nd }] });
      }
    }
    // Contract renewal inside the notice window
    if (isDate(rec.renewal) && rec.noticeDays !== "" && Number.isFinite(Number(rec.noticeDays))) {
      const toRenewal = daysUntil(rec.renewal, now);
      const noticeBy = ymd(ts(rec.renewal) - Number(rec.noticeDays) * DAY);
      const toNotice = daysUntil(noticeBy, now);
      if (toRenewal >= 0 && toNotice <= o.renewalLeadDays) {
        const hi = residual.band === "high" || residual.band === "critical";
        add({ id: id("renewal"), title: "Contract renewal inside the termination-notice window", severity: hi ? "medium" : "info", category: "contract",
          description: vn + ": renews " + rec.renewal + " (in " + toRenewal + " days); notice to terminate " + (toNotice < 0 ? "was due by " + noticeBy + " (" + -toNotice + " days ago)" : "is due by " + noticeBy + " (in " + toNotice + " days)") + " under " + rec.noticeDays + " days' notice." + (hi ? " Residual risk is " + residual.band + "." : ""),
          recommendation: "Decide renew, renegotiate (add security terms) or exit before the notice date passes.",
          controls: [C.iso520, C.csfSc10], evidence: [{ vendor: vn, renewal: rec.renewal, noticeDays: rec.noticeDays, noticeBy, daysToRenewal: toRenewal, residual: residual.band }] });
      }
    }
  }
  // Exceptions noted in a report
  for (const d of rec.docs.filter((x) => x.exceptions).sort((a, b) => str(a.id).localeCompare(str(b.id)))) {
    add({ id: id("exc-" + d.id), title: "Exceptions noted in vendor assurance report", severity: "low", confidence: "review", category: "assurance",
      description: vn + ": " + docLabel(d.type) + (d.periodEnd ? " (period end " + d.periodEnd + ")" : "") + " notes exceptions. " + (d.exceptionsText || "No detail recorded."),
      recommendation: "Read the exceptions and the management response; confirm complementary user-entity controls on your side.",
      controls: [C.soc2, C.iso522], evidence: [{ vendor: vn, document: docLabel(d.type), periodEnd: d.periodEnd, exceptions: d.exceptionsText }] });
  }
  // Critical without exit plan
  if (rec.criticality === "critical" && !rec.exitPlan.trim()) {
    add({ id: id("exit"), title: "Critical vendor without an exit plan", severity: "low", category: "resilience",
      description: vn + " is marked critical" + (rec.spof ? " and a single point of failure" : "") + " but no exit plan note is recorded.",
      recommendation: "Document how you would replace or bring in-house this service, data return and deletion terms, and the time it would take.",
      controls: [C.csfSc10, C.iso523, C.sr6], evidence: [{ vendor: vn, criticality: rec.criticality, spof: rec.spof ? "yes" : "no" }] });
  }
  // Posture findings (from results)
  const R = (check) => (results || []).filter((r) => r.check === check);
  for (const r of R("dmarc")) {
    if (!rec.sendsMail) continue;
    if (r.status === "fail" || (r.status === "warn" && /^Monitoring only/.test(r.evidence))) {
      add({ id: id("dmarc-" + r.domain), title: r.status === "fail" ? "Vendor that emails you has no DMARC" : "Vendor that emails you has DMARC p=none", severity: "medium", category: "email",
        description: vn + " (" + r.domain + ") sends you mail but receivers are not told to reject spoofed mail from its domain, so forged invoices or bank-change requests can arrive looking genuine.",
        recommendation: "Ask the vendor to move DMARC to p=quarantine or p=reject; meanwhile verify any bank-detail change by a call-back to a known number.",
        controls: [C.dmarc, C.phish, C.iso519], evidence: [{ vendor: vn, domain: r.domain, status: r.status, evidence: r.evidence }], assets: [{ type: "DOMAIN", name: r.domain }] });
    }
  }
  for (const r of R("spf")) {
    if (r.status === "fail" && /\+all/.test(r.evidence)) {
      add({ id: id("spf-all-" + r.domain), title: "Vendor SPF allows any sender (+all)", severity: "high", category: "email",
        description: vn + " (" + r.domain + ") publishes SPF with +all, which authorises every host on the internet to send as this domain.",
        recommendation: "Tell the vendor to replace +all with -all after listing its real senders.",
        controls: [C.spf, C.phish, C.iso519], evidence: [{ vendor: vn, domain: r.domain, evidence: r.evidence }], assets: [{ type: "DOMAIN", name: r.domain }] });
    }
  }
  for (const r of R("cert")) {
    if (r.status === "fail" || r.status === "warn") {
      add({ id: id("cert-" + r.domain), title: r.status === "fail" ? "Vendor certificate expired" : "Vendor certificate expiring in under " + o.certWarnDays + " days", severity: r.status === "fail" ? "high" : "medium", category: "web",
        description: vn + " (" + r.domain + "): " + r.evidence + ".", recommendation: "Tell the vendor; an expiry breaks integrations and signals weak certificate management.",
        controls: [C.iso522, C.csfSc07], evidence: [{ vendor: vn, domain: r.domain, evidence: r.evidence }], assets: [{ type: "DOMAIN", name: r.domain }] });
    }
  }
  for (const r of R("rdap")) {
    if (r.status === "fail") {
      add({ id: id("domain-exp-" + r.domain), title: "Vendor domain registration expiring in under " + o.domainWarnDays + " days", severity: "high", category: "registration",
        description: vn + " (" + r.domain + "): " + r.evidence + ". A lapsed domain can be re-registered by anyone and used to receive your mail to the vendor.",
        recommendation: "Alert the vendor and confirm auto-renew; hold payments to new bank details sent from this domain until confirmed.",
        controls: [C.iso522, C.csfSc07], evidence: [{ vendor: vn, domain: r.domain, evidence: r.evidence }], assets: [{ type: "DOMAIN", name: r.domain }] });
    }
  }
  for (const r of R("securitytxt")) {
    if (r.status === "warn" && /^No \/\.well-known/.test(r.evidence)) {
      add({ id: id("sectxt-" + r.domain), title: "Vendor publishes no security.txt", severity: "info", category: "disclosure",
        description: vn + " (" + r.domain + "): " + r.evidence + ". There is no published route for reporting a vulnerability or breach to them.",
        recommendation: "Ask the vendor for their security contact and record it in the profile.",
        controls: [C.sectxt, C.iso519], evidence: [{ vendor: vn, domain: r.domain, evidence: r.evidence }], assets: [{ type: "DOMAIN", name: r.domain }] });
    }
  }
  for (const r of R("leak")) {
    if (r.status === "fail") {
      add({ id: id("leak-" + r.domain), title: "Vendor named on a ransomware leak-site tracker", severity: "high", confidence: "review", category: "exposure",
        description: vn + " (" + r.domain + "): " + r.evidence + " (source: ransomware.live). A listing is a claim by the group, not proof of what data was taken.",
        recommendation: "Ask the vendor for an incident statement, whether your data was in scope, and review their access now.",
        controls: [C.csfSc07, C.iso522, C.sr6], evidence: [{ vendor: vn, domain: r.domain, evidence: r.evidence }], assets: [{ type: "DOMAIN", name: r.domain }] });
    }
  }
  if (diff && diff.gradeDrop >= 1) {
    add({ id: id("grade-drop"), title: "Vendor posture grade dropped since the last check", severity: "medium", category: "posture",
      description: vn + ": posture went from " + diff.gradeFrom + " (" + diff.scoreFrom + ") on " + str(diff.from).slice(0, 10) + " to " + diff.gradeTo + " (" + diff.scoreTo + ") on " + str(diff.to).slice(0, 10) + "; " + diff.newFailures.length + " new failure(s).",
      recommendation: "Review the new failures on the Changes tab and raise them with the vendor.",
      controls: [C.iso522, C.csfSc07, C.sr6], evidence: diff.newFailures.concat(diff.worsened).slice(0, 50) });
  }
  for (const f of findings) { f.evidenceCount = Math.max(f.evidenceCount, f.evidence.length); f.evidence = f.evidence.slice(0, 50); }
  findings.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.id.localeCompare(b.id));
  const docsExpiring = hasDates ? rec.docs.filter((d) => isDate(d.expires) && daysUntil(d.expires, now) >= 0 && daysUntil(d.expires, now) <= o.upcomingDays).length : 0;
  return { id: rec.id || "", legalName: vn, criticality: rec.criticality, inherent, credit, posture, residual, diff, trend: trendOf(rec), nextReview: nr, docsExpiring, lastChecked: latest ? latest.at : "", findings, held: heldIds(results, id) };
}

// ---------------------------------------------------------------------------
// CSV import (bulk-load a vendor list)
// ---------------------------------------------------------------------------

export const COLUMNS = {
  legalName: ["legal name", "legalName", "vendor name", "vendor", "supplier", "supplier name", "company", "name"],
  domains: ["domains", "domain", "website", "url", "web site"],
  services: ["services", "service", "services provided", "description"],
  owner: ["business owner", "owner", "relationship owner"],
  dataTier: ["data access tier", "dataTier", "data tier", "data classification", "classification"],
  dataTypes: ["data types", "dataTypes", "data shared", "data"],
  systemAccess: ["system access", "systemAccess", "access"],
  integrations: ["integration", "integrations"],
  criticality: ["criticality", "tier", "risk tier", "vendor tier"],
  spof: ["single point of failure", "spof"],
  regions: ["regions", "country", "countries", "region", "processing location"],
  subProcessors: ["sub-processors", "subprocessors", "sub processors"],
  contractStart: ["contract start", "contractStart", "start date"],
  renewal: ["renewal", "renewal date", "contract end", "end date", "contractEnd"],
  noticeDays: ["termination notice days", "notice days", "noticeDays", "notice period"],
  lastReview: ["last review", "lastReview", "last reviewed"],
  nextReview: ["next review", "nextReview"],
  questionnaireScore: ["questionnaire score", "questionnaireScore", "score"],
  sendsMail: ["sends us email", "sendsMail", "emails us"],
  notes: ["notes", "comments"],
};
export const COLUMN_LABELS = Object.fromEntries(REGISTER_SCHEMA.columns.map((c) => [c.key, c.label]).concat([["sendsMail", "Sends us email"]]));

/** Auto-map headers to fields. confidence: high = name + domain found. */
export function autoMap(headers) {
  const mapping = {};
  for (const [k, aliases] of Object.entries(COLUMNS)) { const h = findColumn(headers, aliases); if (h) mapping[k] = h; }
  const confidence = mapping.legalName && mapping.domains ? "high" : mapping.legalName ? "medium" : "low";
  return { mapping, confidence };
}

const toIsoDate = (v) => {
  const s = str(v).trim();
  if (!s) return "";
  if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(0, 10);
  const m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/); // US m/d/yyyy (spreadsheet default)
  if (m) return m[3] + "-" + m[1].padStart(2, "0") + "-" + m[2].padStart(2, "0");
  const t = parseDay(s);
  return Number.isFinite(t) ? ymd(t) : s;
};

/** CSV rows + mapping -> records. Rows without a legal name are skipped with a reason. */
export function csvToRecords(rows, mapping) {
  const records = [], skipped = [];
  (rows || []).forEach((row, i) => {
    const get = (k) => (mapping[k] ? row[mapping[k]] : undefined);
    const name = str(get("legalName")).trim();
    if (!name) { skipped.push({ check: "row " + (i + 2), reason: "no legal name" }); return; }
    const r = {};
    for (const k of Object.keys(COLUMNS)) if (mapping[k]) r[k] = get(k);
    for (const k of ["contractStart", "renewal", "lastReview", "nextReview"]) if (r[k] != null) r[k] = toIsoDate(r[k]);
    const rec = normalizeRecord(r);
    const bad = splitList(r.domains).filter((d) => !validDomain(cleanDomain(d)));
    if (bad.length) skipped.push({ check: "row " + (i + 2), reason: "invalid domain(s) dropped: " + bad.join(", ") });
    rec.domains = rec.domains.filter(validDomain);
    records.push(rec);
  });
  return { records, skipped };
}

/** Parse dropped text: a register JSON export or a CSV vendor list. */
export function parseInput(input) {
  const files = Array.isArray(input) ? input : [{ name: "", text: input }];
  const skipped = [];
  const out = { format: "empty", confidence: "low", headers: [], rows: [], records: [], mapping: {}, files: [], skipped };
  for (const f of files) {
    const t = str(f && f.text);
    if (!t.trim()) continue;
    const fmt = sniff(t).format;
    if (fmt === "json" || fmt === "ndjson") {
      let arr = [];
      try { const j = JSON.parse(t); arr = Array.isArray(j) ? j : Array.isArray(j && j.records) ? j.records : [j]; } catch (_) { for (const r of iterJson(t)) arr.push(r); }
      const recs = arr.filter((r) => r && typeof r === "object" && (r.legalName || r.name));
      if (!recs.length) { skipped.push({ check: f.name || "json", reason: "no vendor records (legalName) found" }); continue; }
      out.records.push(...recs.map(normalizeRecord).map((r, i) => ({ ...r, id: str(recs[i].id) || undefined })));
      out.format = "vendorrisk-register"; out.confidence = "high";
      out.files.push({ name: f.name, format: "Third-Party Risk register JSON", confidence: "high", count: recs.length });
    } else if (fmt === "csv" || fmt === "tsv") {
      const { headers, rows } = parseCsv(t);
      const { mapping, confidence } = autoMap(headers);
      out.headers = headers; out.rows = rows; out.mapping = mapping; out.confidence = confidence; out.format = "vendor-csv";
      out.files.push({ name: f.name, format: "Vendor list CSV", confidence, count: rows.length });
      if (!mapping.legalName) skipped.push({ check: "csv-import", reason: "no legal name column (" + COLUMNS.legalName.join(", ") + "); map it by hand" });
    } else skipped.push({ check: f.name || "input", reason: "not JSON or CSV (" + fmt + ")" });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Portfolio analysis
// ---------------------------------------------------------------------------

function newestDate(records) {
  let best = "";
  for (const r of records) {
    for (const d of [r.updatedAt, r.lastReview, ...(r.posture || []).map((s) => s.at)]) if (isDate(d) && str(d) > best) best = str(d);
  }
  return best;
}

/** analyze({ records }, { now, policy, ...thresholds }) -> { summary, findings, tables, skipped, meta } */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...opts };
  const records = (Array.isArray(dataset) ? dataset : (dataset && dataset.records) || []).map(normalizeRecord)
    .sort((a, b) => a.legalName.localeCompare(b.legalName) || str(a.id).localeCompare(str(b.id)));
  const skipped = [];
  let now = o.now;
  if (!isDate(now)) {
    now = newestDate(records);
    if (now) skipped.push({ check: "clock", reason: "no current time passed; dates measured against the newest date in the data (" + now.slice(0, 10) + ")" });
    else if (records.length) skipped.push({ check: "date-checks", reason: "no current time and no dates in the data; expiry, review and renewal checks not run" });
  }
  const policy = mergePolicy(o.policy);
  const graded = [];
  const n = records.length;
  records.forEach((r, i) => {
    if (i % 1000 === 0) ctx?.progress?.(i, n, "grading vendors");
    graded.push(gradeVendor(r, null, policy, { ...o, now }));
  });
  ctx?.progress?.(n, n, "done");
  const noPosture = graded.filter((g) => !g.lastChecked).map((g) => g.legalName);
  if (noPosture.length) skipped.push({ check: "posture", reason: noPosture.length + " vendor(s) have no live posture check yet: " + noPosture.slice(0, 10).join(", ") + (noPosture.length > 10 ? ", ..." : "") });
  const noDomain = records.filter((r) => !r.domains.length).map((r) => r.legalName);
  if (noDomain.length) skipped.push({ check: "posture-domains", reason: noDomain.length + " vendor(s) have no domain to check: " + noDomain.slice(0, 10).join(", ") });
  skipped.push({ check: "dkim", reason: "DKIM is not checkable without the vendor's selector names" });

  const held = graded.flatMap((g) => g.held);
  const findings = graded.flatMap((g) => g.findings).sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.id.localeCompare(b.id));
  const vendors = graded.map((g, i) => ({
    id: g.id, legalName: g.legalName, criticality: g.criticality || "", inherent: g.inherent.score, inherentBand: g.inherent.band,
    credit: g.credit.pct, residual: g.residual.score, residualBand: g.residual.band, grade: g.posture.grade, postureScore: g.posture.score, trend: g.trend,
    nextReview: g.nextReview.date, docsExpiring: g.docsExpiring, lastChecked: g.lastChecked, findings: g.findings.length, domains: records[i].domains.join(", "),
  }));
  const grid = {};
  for (const c of BANDS) { grid[c] = {}; for (const b of BANDS) grid[c][b] = 0; }
  for (const v of vendors) if (grid[v.criticality] && grid[v.criticality][v.residualBand] != null) grid[v.criticality][v.residualBand]++;
  const expiring = [];
  if (isDate(now)) {
    for (const r of records) for (const d of r.docs) {
      const days = isDate(d.expires) ? daysUntil(d.expires, now) : null;
      if (days != null && days <= o.upcomingDays) expiring.push({ vendor: r.legalName, document: docLabel(d.type), expires: d.expires, daysLeft: days });
    }
  }
  expiring.sort((a, b) => a.daysLeft - b.daysLeft || a.vendor.localeCompare(b.vendor));
  const overdue = isDate(now) ? vendors.filter((v) => v.criticality && (!v.nextReview || daysUntil(v.nextReview, now) < 0))
    .map((v) => ({ vendor: v.legalName, criticality: v.criticality, nextReview: v.nextReview || "never reviewed", daysOverdue: v.nextReview ? -daysUntil(v.nextReview, now) : "" })) : [];
  const worst = vendors.filter((v) => v.postureScore != null).sort((a, b) => a.postureScore - b.postureScore || a.legalName.localeCompare(b.legalName)).slice(0, 10)
    .map((v) => ({ vendor: v.legalName, grade: v.grade, score: v.postureScore, trend: v.trend, lastChecked: v.lastChecked }));
  const bySeverity = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  const summary = {
    vendors: n, findings: findings.length, bySeverity,
    critical: vendors.filter((v) => v.criticality === "critical").length,
    residualHigh: vendors.filter((v) => v.residualBand === "high" || v.residualBand === "critical").length,
    docsExpiring: expiring.filter((e) => e.daysLeft >= 0).length, docsExpired: expiring.filter((e) => e.daysLeft < 0).length,
    reviewsOverdue: overdue.length, checked: vendors.filter((v) => v.lastChecked).length,
  };
  return { summary, findings, held, tables: { vendors, grid, expiring, overdue, worst, graded }, skipped, meta: { tool: TOOL_ID, version: VERSION, rows: n, now: str(now) } };
}

// A posture check that errored (a lookup that failed) decides nothing, so the finding it
// would raise is held: the sink then does not offer the last one as verified fixed.
const HELD_PREFIX = { dmarc: "dmarc-", spf: "spf-all-", cert: "cert-", rdap: "domain-exp-", securitytxt: "sectxt-", leak: "leak-" };
function heldIds(results, id) {
  return (results || []).filter((r) => r.status === "error" && HELD_PREFIX[r.check]).map((r) => id(HELD_PREFIX[r.check] + r.domain));
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

const FINDING_COLS = ["severity", "confidence", "category", "vendor", "title", "description", "recommendation", "controls", "evidenceCount"];
export function findingsToCsv(findings) {
  const rows = (findings || []).map((f) => ({
    severity: f.severity, confidence: f.confidence, category: f.category,
    vendor: ((f.assets || []).find((a) => a.type === "VENDOR") || {}).name || "",
    title: f.title, description: f.description, recommendation: f.recommendation,
    controls: (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), evidenceCount: f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
  }));
  return toCsv(rows, FINDING_COLS);
}

/** Register as CSV (one row per vendor, scores included when graded). */
export function registerToCsv(records, graded) {
  const g = new Map((graded || []).map((x) => [x.id + "|" + x.legalName, x]));
  const rows = (records || []).map(normalizeRecord).map((r) => {
    const x = g.get(str(r.id) + "|" + r.legalName) || {};
    return {
      ...Object.fromEntries(REGISTER_SCHEMA.columns.map((c) => [c.label, Array.isArray(r[c.key]) ? r[c.key].join("; ") : typeof r[c.key] === "boolean" ? (r[c.key] ? "yes" : "no") : r[c.key]])),
      "Sends us email": r.sendsMail ? "yes" : "no",
      "Documents": r.docs.map((d) => docLabel(d.type) + (d.expires ? " exp " + d.expires : "")).join("; "),
      "Inherent": x.inherent ? x.inherent.score : "", "Residual": x.residual ? x.residual.score : "", "Residual band": x.residual ? x.residual.band : "",
      "Posture grade": x.posture ? x.posture.grade : "", "Last checked": x.lastChecked || "",
    };
  });
  const cols = REGISTER_SCHEMA.columns.map((c) => c.label).concat(["Sends us email", "Documents", "Inherent", "Residual", "Residual band", "Posture grade", "Last checked"]);
  return toCsv(rows, cols);
}

/** Calendar events: notice deadline, renewal, next review, document expiries. */
export function icsEvents(records, { now, policy } = {}) {
  const ev = [];
  for (const r of (records || []).map(normalizeRecord)) {
    const vid = str(r.id) || nameNorm(r.legalName).replace(/ /g, "-");
    const vn = r.legalName;
    if (isDate(r.renewal)) {
      ev.push({ uid: vid + "-renewal@darknode.ai", start: r.renewal.slice(0, 10), allDay: true, stamp: now, summary: "Contract renewal: " + vn, description: "Third-Party Risk register. Renewal date for " + vn + "." });
      if (r.noticeDays !== "" && Number.isFinite(Number(r.noticeDays))) {
        const by = ymd(ts(r.renewal) - Number(r.noticeDays) * DAY);
        ev.push({ uid: vid + "-notice@darknode.ai", start: by, allDay: true, stamp: now, summary: "Termination notice deadline: " + vn, description: r.noticeDays + " days' notice before renewal on " + r.renewal + "." });
      }
    }
    const nr = nextReviewDate(r, policy);
    if (nr.date) ev.push({ uid: vid + "-review@darknode.ai", start: nr.date, allDay: true, stamp: now, summary: "Vendor review due: " + vn, description: "Next review (" + nr.source + ")." });
    for (const d of r.docs) if (isDate(d.expires)) ev.push({ uid: vid + "-doc-" + d.id + "@darknode.ai", start: d.expires.slice(0, 10), allDay: true, stamp: now, summary: docLabel(d.type) + " expires: " + vn, description: "Request the renewed document from " + vn + "." });
  }
  return ev.sort((a, b) => a.start.localeCompare(b.start) || a.uid.localeCompare(b.uid));
}

/** Plain-text one-pager for one vendor. */
export function onePager(record, grade) {
  const r = normalizeRecord(record), g = grade;
  const L = [];
  L.push("THIRD-PARTY RISK ONE-PAGER: " + r.legalName, "=".repeat(Math.min(78, 28 + r.legalName.length)), "");
  L.push("Domains:          " + (r.domains.join(", ") || "none"));
  L.push("Services:         " + (r.services || "-"));
  L.push("Business owner:   " + (r.owner || "-"));
  L.push("Criticality:      " + (r.criticality || "not set") + (r.spof ? " (single point of failure)" : ""));
  L.push("Data access:      " + (label(DATA_TIERS, r.dataTier) || "not set") + "; " + (r.dataTypes.map((t) => label(DATA_TYPES, t)).join(", ") || "no data types"));
  L.push("System access:    " + (label(SYSTEM_ACCESS, r.systemAccess) || "not set") + "; integration " + (r.integrations.map((t) => label(INTEGRATIONS, t)).join(", ") || "none"));
  L.push("Regions:          " + (r.regions || "-"));
  L.push("Sub-processors:   " + (r.subProcessors || "-"));
  L.push("Contract:         start " + (r.contractStart || "-") + ", renewal " + (r.renewal || "-") + ", notice " + (r.noticeDays === "" ? "-" : r.noticeDays + " days"));
  L.push("Reviews:          last " + (r.lastReview || "never") + ", next " + (g ? g.nextReview.date || g.nextReview.source : "-"));
  if (g) {
    L.push("", "SCORES (" + (g.asOf || "") + ")");
    L.push("Inherent risk:    " + g.inherent.score + "/100 (" + g.inherent.band + ")");
    L.push("Assurance credit: " + g.credit.pct + "% (" + (g.credit.parts.map((p) => p.item).join("; ") || "none") + ")");
    L.push("Posture grade:    " + g.posture.grade + (g.posture.score != null ? " (" + g.posture.score + "/100)" : "") + (g.lastChecked ? ", last checked " + g.lastChecked.slice(0, 16).replace("T", " ") + " UTC" : ", never checked"));
    L.push("Residual risk:    " + g.residual.score + "/100 (" + g.residual.band + ") = " + g.residual.formula);
  }
  L.push("", "ASSURANCE DOCUMENTS");
  if (!r.docs.length) L.push("  none on file");
  for (const d of r.docs) L.push("  - " + docLabel(d.type) + (d.periodEnd ? ", period end " + d.periodEnd : "") + (d.expires ? ", expires " + d.expires : "") + (d.exceptions ? ", EXCEPTIONS NOTED" : ""));
  if (g) {
    L.push("", "FINDINGS (" + g.findings.length + ")");
    for (const f of g.findings) L.push("  [" + f.severity.toUpperCase() + "] " + f.title, "      " + f.recommendation);
  }
  if (r.exitPlan) L.push("", "EXIT PLAN", "  " + r.exitPlan);
  if (r.notes) L.push("", "NOTES", "  " + r.notes);
  L.push("", "Posture is a point-in-time read of public DNS, certificate-transparency, HTTP and RDAP data; it does not test the vendor's internal controls.");
  return L.join("\n") + "\n";
}

/** Names of payees / graph vendors that match a register vendor (normalised legal name). */
export function matchPayees(legalName, candidates) {
  const n = nameNorm(legalName);
  if (!n) return [];
  return (candidates || []).filter((c) => c && nameNorm(c.name) === n).sort((a, b) => str(a.source + a.name).localeCompare(str(b.source + b.name)));
}

// ---------------------------------------------------------------------------
// Synthetic example (offline; posture graded from fixture DoH/CT/HTTP/RDAP data)
// ---------------------------------------------------------------------------

const DOH = (name, type, data, extra) => ({ Status: 0, TC: false, RD: true, RA: true, AD: !!(extra && extra.AD), CD: false, Question: [{ name: name + ".", type: DNS_TYPES[type] }], Answer: (data || []).map((d) => ({ name: name + ".", type: DNS_TYPES[type], TTL: 300, data: d })) });
const NX = (name, type) => ({ Status: 3, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: name + ".", type: DNS_TYPES[type] }] });

/** Build fixture raw results for one synthetic domain. p tunes each signal. */
function fixtureRaw(domain, p, at) {
  const plus = (days) => ymd(ts(at) + days * DAY);
  const hdrsGood = { "strict-transport-security": "max-age=31536000; includeSubDomains", "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin", "permissions-policy": "camera=()", "cross-origin-opener-policy": "same-origin", "cross-origin-resource-policy": "same-origin", "cross-origin-embedder-policy": "require-corp" };
  const hdrsWeak = { "server": "nginx/1.18.0" };
  return {
    domain,
    mx: DOH(domain, "MX", ["10 mx1." + domain + "."]),
    txt: DOH(domain, "TXT", p.spf ? [p.spf] : ["google-site-verification=synthetic"]),
    dmarc: p.dmarc ? DOH("_dmarc." + domain, "TXT", [p.dmarc]) : NX("_dmarc." + domain, "TXT"),
    mtasts: p.mtasts ? DOH("_mta-sts." + domain, "TXT", ["v=STSv1; id=20260101"]) : NX("_mta-sts." + domain, "TXT"),
    mtastsPolicy: p.mtasts ? { status: 200, body: "version: STSv1\nmode: " + p.mtasts + "\nmx: mx1." + domain + "\nmax_age: 604800\n" } : undefined,
    tlsrpt: p.tlsrpt ? DOH("_smtp._tls." + domain, "TXT", ["v=TLSRPTv1; rua=mailto:tlsrpt@" + domain]) : NX("_smtp._tls." + domain, "TXT"),
    ds: p.ds ? DOH(domain, "DS", ["12345 13 2 " + "AB".repeat(32)], { AD: true }) : DOH(domain, "DS", []),
    caa: p.caa ? DOH(domain, "CAA", ['0 issue "letsencrypt.org"']) : DOH(domain, "CAA", []),
    ns: DOH(domain, "NS", p.nsMulti ? ["ns1.dnsprov-a.test.darknode.ai.", "ns2.dnsprov-b-alt.test.", "ns3.dnsprov-a.test.darknode.ai."] : ["ns1.onehost.test.darknode.ai.", "ns2.onehost.test.darknode.ai."]),
    cert: { rows: [{ issuer_name: "C=US, O=Let's Encrypt, CN=R11", not_before: plus(-60), not_after: plus(p.certDays), name_value: (p.wildcard ? "*." : "") + domain }] },
    https: p.https === false ? { error: "connection refused" } : { status: 200, finalUrl: "https://" + domain + "/", headers: p.headers === "good" ? hdrsGood : hdrsWeak },
    http: { status: 200, finalUrl: (p.redirect === false ? "http://" : "https://") + domain + "/" },
    securityTxt: p.sectxt ? { status: 200, body: "Contact: mailto:security@" + domain + "\nExpires: " + plus(200) + "T00:00:00Z\n" } : { status: 404, body: "" },
    rdap: { json: { objectClassName: "domain", ldhName: domain.toUpperCase(), events: [{ eventAction: "registration", eventDate: "2015-03-02T00:00:00Z" }, { eventAction: "expiration", eventDate: plus(p.domainDays) + "T00:00:00Z" }], entities: [{ objectClassName: "entity", roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Test Registrar"]]] }] } },
  };
}

const GOOD = { spf: "v=spf1 include:_spf.test.darknode.ai -all", dmarc: "v=DMARC1; p=reject; rua=mailto:dmarc@test.darknode.ai", mtasts: "enforce", tlsrpt: true, ds: true, caa: true, nsMulti: true, certDays: 70, headers: "good", sectxt: true, domainDays: 400 };

/** SYNTHETIC register: 8 fictional vendors on *.test.darknode.ai with precomputed posture snapshots. No network. */
export function exampleDataset(seed = 7, nowIso = "2026-10-16T12:00:00Z") {
  void seed;
  const now = ts(nowIso);
  const d = (days) => ymd(now + days * DAY);
  const at = (days) => new Date(now + days * DAY).toISOString().slice(0, 19) + "Z";
  const snap = (domains, params, when) => makeSnapshot(domains.flatMap((dom, i) => gradeDomain(fixtureRaw(dom, Array.isArray(params) ? params[i] : params, when), { now: when })), when);
  const V = [];
  const base = (o) => normalizeRecord({ owner: "", services: "", regions: "", subProcessors: "", notes: "", exitPlan: "", history: [{ at: at(-200), what: "Created (synthetic example)" }], ...o });

  V.push(base({ id: "ex-vendor-a", legalName: "Vendor A Payroll Ltd", domains: ["vendor-a.test.darknode.ai"], services: "Payroll processing", owner: "people-ops@test.darknode.ai",
    dataTier: "restricted", dataTypes: ["pii", "financial", "employee"], systemAccess: "write", integrations: ["sso", "apikeys"], criticality: "critical", spof: true, sendsMail: true,
    exitPlan: "", regions: "UK, IE", subProcessors: "Vendor I Cloud Hosting", contractStart: d(-700), renewal: d(40), noticeDays: 60, lastReview: d(-400),
    docs: [{ id: "d1", type: "soc2t2", issued: d(-300), periodEnd: d(-380), expires: "" }, { id: "d2", type: "dpa", issued: d(-700) }, { id: "d3", type: "insurance", expires: d(25) }, { id: "d4", type: "pentest", issued: d(-120) }],
    posture: [
      snap(["vendor-a.test.darknode.ai"], { ...GOOD }, at(-30)),
      snap(["vendor-a.test.darknode.ai"], { ...GOOD, dmarc: "v=DMARC1; p=none; rua=mailto:dmarc@test.darknode.ai", mtasts: null, tlsrpt: false, headers: "weak", sectxt: false }, at(-1)),
    ] }));
  V.push(base({ id: "ex-vendor-b", legalName: "Vendor B Analytics Inc", domains: ["vendor-b.test.darknode.ai"], services: "Patient outcome analytics", owner: "clinical-it@test.darknode.ai",
    dataTier: "restricted", dataTypes: ["phi", "pii"], systemAccess: "read", integrations: ["oauth"], criticality: "high", sendsMail: false, regions: "US",
    contractStart: d(-400), renewal: d(300), noticeDays: 90, lastReview: d(-100), questionnaireScore: 82,
    docs: [{ id: "d1", type: "iso27001", issued: d(-200), expires: d(500) }, { id: "d2", type: "dpa", issued: d(-400) }, { id: "d3", type: "questionnaire", issued: d(-90) }, { id: "d4", type: "soc2t2", issued: d(-60), periodEnd: d(-90), exceptions: true, exceptionsText: "CC6.2: two terminated users kept access past 30 days." }],
    posture: [snap(["vendor-b.test.darknode.ai"], { ...GOOD, ds: false, caa: false }, at(-2))] }));
  V.push(base({ id: "ex-vendor-c", legalName: "Vendor C Payments GmbH", domains: ["vendor-c.test.darknode.ai", "pay.vendor-c.test.darknode.ai"], services: "Card acquiring and checkout", owner: "finance@test.darknode.ai",
    dataTier: "restricted", dataTypes: ["pci", "financial"], systemAccess: "network", integrations: ["apikeys", "agent"], criticality: "critical", spof: true, sendsMail: true, regions: "DE, EU",
    exitPlan: "Secondary acquirer contract signed; 30-day cut-over runbook in the payments wiki.", contractStart: d(-1000), renewal: d(500), noticeDays: 180, lastReview: d(-200),
    docs: [{ id: "d1", type: "pciaoc", issued: d(-380), expires: d(-15) }, { id: "d2", type: "soc2t2", issued: d(-100), periodEnd: d(-130) }, { id: "d3", type: "pentest", issued: d(-500) }],
    posture: [snap(["pay.vendor-c.test.darknode.ai", "vendor-c.test.darknode.ai"], [{ ...GOOD, certDays: 9, wildcard: true }, { ...GOOD, spf: "v=spf1 include:_spf.test.darknode.ai +all", domainDays: 21 }], at(-1))] }));
  V.push(base({ id: "ex-vendor-d", legalName: "Vendor D Ticketing Co", domains: ["vendor-d.test.darknode.ai"], services: "Support desk SaaS", owner: "support@test.darknode.ai",
    dataTier: "confidential", dataTypes: ["pii", "customer"], systemAccess: "read", integrations: ["sso"], criticality: "medium", sendsMail: true, regions: "US, EU",
    contractStart: d(-800), renewal: d(120), noticeDays: 30, lastReview: d(-900),
    docs: [{ id: "d1", type: "soc2t2", issued: d(-500), periodEnd: d(-540) }, { id: "d2", type: "bridge", issued: d(-170), expires: d(10) }, { id: "d3", type: "dpa", issued: d(-800) }],
    posture: [snap(["vendor-d.test.darknode.ai"], { ...GOOD, dmarc: null, mtasts: "testing", nsMulti: false }, at(-3))] }));
  V.push(base({ id: "ex-vendor-e", legalName: "Vendor E Print Services", domains: ["vendor-e.test.darknode.ai"], services: "Office printing", owner: "facilities@test.darknode.ai",
    dataTier: "internal", dataTypes: [], systemAccess: "none", integrations: [], criticality: "low", sendsMail: true, regions: "US",
    contractStart: d(-300), renewal: d(65), noticeDays: 30, lastReview: d(-200), docs: [],
    posture: [snap(["vendor-e.test.darknode.ai"], { ...GOOD, spf: "v=spf1 a mx ?all", dmarc: null, mtasts: null, tlsrpt: false, ds: false, caa: false, nsMulti: false, headers: "weak", sectxt: false }, at(-5))] }));
  V.push(base({ id: "ex-vendor-f", legalName: "Vendor F Dev Tools", domains: ["vendor-f.test.darknode.ai"], services: "CI/CD platform", owner: "platform@test.darknode.ai",
    dataTier: "confidential", dataTypes: ["source", "credentials"], systemAccess: "admin", integrations: ["oauth", "apikeys"], criticality: "high", sendsMail: false, regions: "US",
    contractStart: d(-500), renewal: d(230), noticeDays: 60, lastReview: d(-30),
    docs: [{ id: "d1", type: "soc2t2", issued: d(-40), periodEnd: d(-70) }, { id: "d2", type: "iso27001", issued: d(-300), expires: d(45) }, { id: "d3", type: "pentest", issued: d(-80) }],
    posture: [
      snap(["vendor-f.test.darknode.ai"], { ...GOOD, headers: "weak" }, at(-60)),
      snap(["vendor-f.test.darknode.ai"], { ...GOOD }, at(-2)),
    ] }));
  V.push(base({ id: "ex-vendor-g", legalName: "Vendor G Freight Brokers", domains: ["vendor-g.test.darknode.ai"], services: "Logistics brokerage", owner: "ops@test.darknode.ai",
    dataTier: "internal", dataTypes: ["financial"], systemAccess: "none", integrations: [], criticality: "medium", sendsMail: true, regions: "US, MX",
    contractStart: d(-200), renewal: d(500), noticeDays: 60, lastReview: "", docs: [{ id: "d1", type: "insurance", expires: d(220) }],
    posture: [] }));
  V.push(base({ id: "ex-vendor-h", legalName: "Vendor H Cloud Storage SA", domains: ["vendor-h.test.darknode.ai"], services: "Backup object storage", owner: "it@test.darknode.ai",
    dataTier: "confidential", dataTypes: ["pii", "customer"], systemAccess: "write", integrations: ["apikeys"], criticality: "critical", sendsMail: false, regions: "FR, EU",
    exitPlan: "Data mirrored to a second region with another provider weekly.", contractStart: d(-1200), renewal: d(20), noticeDays: 90, lastReview: d(-150),
    docs: [{ id: "d1", type: "iso27001", issued: d(-100), expires: d(900) }, { id: "d2", type: "soc2t2", issued: d(-50), periodEnd: d(-80) }],
    posture: [snap(["vendor-h.test.darknode.ai"], { ...GOOD, https: false }, at(-1))] }));
  return { label: "synthetic example (not real data)", now: nowIso, records: V };
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

export function selfTest() {
  const tests = [];
  const T = (name, cond) => tests.push({ name, pass: !!cond });
  const ex = exampleDataset();
  const r = analyze(ex, { now: ex.now });
  T("example grades 8 vendors", r.tables.vendors.length === 8);
  T("SPF +all fires high", r.findings.some((f) => f.title === "Vendor SPF allows any sender (+all)" && f.severity === "high"));
  T("grade drop fires on Vendor A", r.findings.some((f) => f.id === "tpr-grade-drop-ex-vendor-a"));
  T("deterministic", JSON.stringify(analyze(ex, { now: ex.now })) === JSON.stringify(r));
  const g = gradeDomain({ domain: "x.test.darknode.ai", txt: { error: "timeout" } }, { now: ex.now });
  T("network error is reported, not graded", g.find((x) => x.check === "spf").status === "error");
  T("empty register yields no findings", analyze({ records: [] }, { now: ex.now }).findings.length === 0);
  return { pass: tests.every((t) => t.pass), tests };
}
