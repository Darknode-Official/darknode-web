// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Breach Clock engine (breachclock). Given the facts of a security incident it
// works out, deterministically, which breach-notification obligations may apply,
// each deadline to the hour (calendar, hour or business-day maths as the rule
// says), who must be told, and a checklist + calendar. It is a decision aid: every
// obligation is "likely", "possible" or "not-indicated", never a legal verdict, and
// every output says to verify with counsel.
//
// Pure: no DOM, no network, no clock (time comes from opts.now). Reference data
// (US state breach laws, US federal holidays) is passed in through opts by the UI.
//
//   assess(facts, opts)   -> { obligations, timeline, checklist, missing, skipped, ... }
//   analyze(dataset, opts) -> { summary, findings, tables, skipped, meta }   (Deck contract)

export const TOOL_ID = "breachclock";
export const VERSION = "1.0.0";
export const VERIFY_LINE = "Decision aid, not legal advice. Verify every obligation with counsel.";

/** Header aliases for the jurisdiction count table (CSV paste / import). */
export const COLUMNS = {
  jurisdiction: ["jurisdiction", "state", "country", "region", "location", "code"],
  count: ["count", "individuals", "affected", "residents", "records", "n"],
};

/** Tunable windows; the UI renders these as the thresholds panel. */
export const DEFAULTS = {
  dueSoonHours: 72, // obligations due within this window become findings (medium)
  urgentHours: 24,  // obligations due within this window are high severity
};

export const SECTORS = [
  { id: "general", label: "General commercial" },
  { id: "hipaa-ce", label: "Healthcare covered entity (HIPAA)" },
  { id: "hipaa-ba", label: "HIPAA business associate" },
  { id: "glba", label: "Financial institution (GLBA, FTC Safeguards Rule)" },
  { id: "nydfs", label: "NYDFS-regulated (23 NYCRR 500)" },
  { id: "sec", label: "Public company (SEC registrant)" },
  { id: "eu", label: "EU/EEA establishment or EU data subjects" },
  { id: "uk", label: "United Kingdom" },
  { id: "nis2", label: "NIS2 essential or important entity" },
  { id: "au", label: "Australian APP entity" },
  { id: "in", label: "Indian body corporate (CERT-In)" },
  { id: "ca", label: "Canadian organisation (PIPEDA)" },
  { id: "pci", label: "Payment card merchant or service provider" },
];

export const DATA_TYPES = [
  { id: "ssn", label: "Name + Social Security number" },
  { id: "dl", label: "Driver's licence or state ID" },
  { id: "financial", label: "Financial account + access code" },
  { id: "pan", label: "Payment card number (PAN)" },
  { id: "medical", label: "Medical information" },
  { id: "healthins", label: "Health insurance information" },
  { id: "biometric", label: "Biometric data" },
  { id: "credentials", label: "Username + password or security question" },
  { id: "passport", label: "Passport number" },
  { id: "taxid", label: "Taxpayer ID" },
  { id: "emailpw", label: "Email + password" },
  { id: "geo", label: "Precise geolocation" },
  { id: "special", label: "Special-category data (GDPR Art. 9)" },
  { id: "phi", label: "Protected health information (PHI)" },
];

const SECTOR_IDS = new Set(SECTORS.map((s) => s.id));
const TYPE_IDS = new Set(DATA_TYPES.map((t) => t.id));
const typeLabel = (id) => (DATA_TYPES.find((t) => t.id === id) || { label: id }).label;

// Keywords searched in each state's piiDefinitionNotes (reference data, used as-is).
const STATE_KEYWORDS = {
  ssn: [/\bSSN\b/],
  dl: [/driver'?s licen[cs]e/i],
  financial: [/account number with access code/i],
  pan: [/account number with access code/i],
  medical: [/medical/i, /health information/i, /health records/i, /health-related/i],
  phi: [/medical/i, /health information/i, /health records/i, /health-related/i, /health[- ]insurance/i],
  healthins: [/health[- ]insurance/i],
  biometric: [/biometric/i, /fingerprints/i],
  credentials: [/password/i],
  emailpw: [/email with password/i],
  passport: [/passport/i],
  taxid: [/tax(payer)? ID/i, /tax information/i, /income-tax/i],
  geo: [],
  special: [],
};

const EU = {
  AT: "Austria", BE: "Belgium", BG: "Bulgaria", HR: "Croatia", CY: "Cyprus", CZ: "Czechia", DK: "Denmark", EE: "Estonia",
  FI: "Finland", FR: "France", DE: "Germany", GR: "Greece", HU: "Hungary", IE: "Ireland", IT: "Italy", LV: "Latvia",
  LT: "Lithuania", LU: "Luxembourg", MT: "Malta", NL: "Netherlands", PL: "Poland", PT: "Portugal", RO: "Romania",
  SK: "Slovakia", SI: "Slovenia", ES: "Spain", SE: "Sweden", IS: "Iceland", LI: "Liechtenstein", NO: "Norway",
};
const OTHER_COUNTRIES = { GB: "United Kingdom", CA: "Canada", AU: "Australia", IN: "India" };
/** Countries with a modelled regime (ISO code -> name), for the jurisdiction picker. */
export const COUNTRIES = { ...EU, ...OTHER_COUNTRIES };
/** EU/EEA member states (ISO code -> name). */
export const EU_STATES = { ...EU };
const COUNTRY_ALIASES = { __proto__: null, uk: "GB", "great britain": "GB", "united kingdom": "GB", england: "GB", scotland: "GB", wales: "GB", "northern ireland": "GB", el: "GR", czechrepublic: "CZ", "czech republic": "CZ" };

// ---------------------------------------------------------------------------
// Built-in regimes (statute table). Each row: citation, trigger, clock, recipients, source.
// ---------------------------------------------------------------------------

export const REGIMES = [
  { id: "gdpr-33", regime: "GDPR", citation: "GDPR Art. 33(1)", trigger: "becoming aware of a personal data breach", clock: "72 hours", recipients: "Competent supervisory authority (lead authority under Art. 56 where one-stop-shop applies)", sourceUrl: "https://eur-lex.europa.eu/eli/reg/2016/679/oj", confidence: "curated" },
  { id: "gdpr-34", regime: "GDPR", citation: "GDPR Art. 34(1)", trigger: "breach likely to result in a high risk to individuals", clock: "without undue delay", recipients: "Affected data subjects", sourceUrl: "https://eur-lex.europa.eu/eli/reg/2016/679/oj", confidence: "curated" },
  { id: "ukgdpr-33", regime: "UK GDPR", citation: "UK GDPR Art. 33(1)", trigger: "becoming aware of a personal data breach", clock: "72 hours", recipients: "Information Commissioner's Office (ICO)", sourceUrl: "https://ico.org.uk/for-organisations/report-a-breach/", confidence: "curated" },
  { id: "ukgdpr-34", regime: "UK GDPR", citation: "UK GDPR Art. 34(1)", trigger: "breach likely to result in a high risk to individuals", clock: "without undue delay", recipients: "Affected data subjects", sourceUrl: "https://ico.org.uk/for-organisations/report-a-breach/", confidence: "curated" },
  { id: "nis2-early", regime: "NIS2", citation: "Directive (EU) 2022/2555 Art. 23(4)(a)", trigger: "becoming aware of a significant incident", clock: "24 hours", recipients: "National CSIRT or competent authority", sourceUrl: "https://eur-lex.europa.eu/eli/dir/2022/2555/oj", confidence: "curated" },
  { id: "nis2-notify", regime: "NIS2", citation: "Directive (EU) 2022/2555 Art. 23(4)(b)", trigger: "becoming aware of a significant incident", clock: "72 hours", recipients: "National CSIRT or competent authority", sourceUrl: "https://eur-lex.europa.eu/eli/dir/2022/2555/oj", confidence: "curated" },
  { id: "nis2-final", regime: "NIS2", citation: "Directive (EU) 2022/2555 Art. 23(4)(d)", trigger: "submission of the incident notification", clock: "1 month", recipients: "National CSIRT or competent authority", sourceUrl: "https://eur-lex.europa.eu/eli/dir/2022/2555/oj", confidence: "curated" },
  { id: "sec-8k", regime: "SEC", citation: "Form 8-K Item 1.05 (Release 33-11216)", trigger: "determining the incident is material", clock: "4 business days", recipients: "SEC via EDGAR (public Form 8-K)", sourceUrl: "https://www.sec.gov/files/rules/final/2023/33-11216.pdf", confidence: "curated" },
  { id: "hipaa-individuals", regime: "HIPAA", citation: "45 CFR 164.404", trigger: "discovery of a breach of unsecured PHI", clock: "60 calendar days", recipients: "Affected individuals", sourceUrl: "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D", confidence: "curated" },
  { id: "hipaa-hhs", regime: "HIPAA", citation: "45 CFR 164.408", trigger: "discovery of a breach of unsecured PHI", clock: "60 calendar days (500 or more) or 60 days after year end", recipients: "HHS Office for Civil Rights (breach portal)", sourceUrl: "https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html", confidence: "curated" },
  { id: "hipaa-media", regime: "HIPAA", citation: "45 CFR 164.406", trigger: "more than 500 residents of a state or jurisdiction", clock: "60 calendar days", recipients: "Prominent media outlets serving the state", sourceUrl: "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D", confidence: "curated" },
  { id: "hipaa-ba-ce", regime: "HIPAA", citation: "45 CFR 164.410", trigger: "business associate discovers a breach of unsecured PHI", clock: "60 calendar days", recipients: "Covered entity (your customer)", sourceUrl: "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D", confidence: "curated" },
  { id: "glba-ftc", regime: "GLBA Safeguards Rule", citation: "16 CFR 314.4(j)", trigger: "discovery of a notification event involving unencrypted information of 500 or more consumers", clock: "30 calendar days", recipients: "Federal Trade Commission (online form)", sourceUrl: "https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314/section-314.4", confidence: "curated" },
  { id: "nydfs-72h", regime: "NYDFS", citation: "23 NYCRR 500.17(a)", trigger: "determining that a cybersecurity incident has occurred", clock: "72 hours", recipients: "NY Superintendent of Financial Services (DFS portal)", sourceUrl: "https://www.dfs.ny.gov/industry_guidance/cybersecurity", confidence: "curated" },
  { id: "nydfs-extortion-24h", regime: "NYDFS", citation: "23 NYCRR 500.17(c)(1)", trigger: "making an extortion payment", clock: "24 hours", recipients: "NY Superintendent of Financial Services", sourceUrl: "https://www.dfs.ny.gov/industry_guidance/cybersecurity", confidence: "curated" },
  { id: "nydfs-extortion-30d", regime: "NYDFS", citation: "23 NYCRR 500.17(c)(2)", trigger: "making an extortion payment", clock: "30 calendar days", recipients: "NY Superintendent of Financial Services", sourceUrl: "https://www.dfs.ny.gov/industry_guidance/cybersecurity", confidence: "curated" },
  { id: "pipeda-opc", regime: "PIPEDA", citation: "PIPEDA s. 10.1(1)-(2)", trigger: "determining the breach creates a real risk of significant harm", clock: "as soon as feasible", recipients: "Office of the Privacy Commissioner of Canada", sourceUrl: "https://www.priv.gc.ca/en/privacy-topics/business-privacy/breaches-and-safeguards/privacy-breaches-at-your-business/gd_pb_201810/", confidence: "curated" },
  { id: "pipeda-individuals", regime: "PIPEDA", citation: "PIPEDA s. 10.1(3)-(6)", trigger: "determining the breach creates a real risk of significant harm", clock: "as soon as feasible", recipients: "Affected individuals", sourceUrl: "https://www.priv.gc.ca/en/privacy-topics/business-privacy/breaches-and-safeguards/privacy-breaches-at-your-business/gd_pb_201810/", confidence: "curated" },
  { id: "pipeda-records", regime: "PIPEDA", citation: "PIPEDA s. 10.3; Breach of Security Safeguards Regulations s. 6", trigger: "any breach of security safeguards", clock: "keep records 24 months", recipients: "Internal record (produce to the OPC on request)", sourceUrl: "https://www.priv.gc.ca/en/privacy-topics/business-privacy/breaches-and-safeguards/privacy-breaches-at-your-business/gd_pb_201810/", confidence: "curated" },
  { id: "ndb-assess", regime: "Australia NDB", citation: "Privacy Act 1988 (Cth) s. 26WH", trigger: "suspecting an eligible data breach", clock: "30 calendar days", recipients: "Internal assessment", sourceUrl: "https://www.oaic.gov.au/privacy/notifiable-data-breaches", confidence: "curated" },
  { id: "ndb-oaic", regime: "Australia NDB", citation: "Privacy Act 1988 (Cth) s. 26WK", trigger: "reasonable grounds to believe an eligible data breach occurred", clock: "as soon as practicable", recipients: "Office of the Australian Information Commissioner (OAIC)", sourceUrl: "https://www.oaic.gov.au/privacy/notifiable-data-breaches", confidence: "curated" },
  { id: "ndb-individuals", regime: "Australia NDB", citation: "Privacy Act 1988 (Cth) s. 26WL", trigger: "reasonable grounds to believe an eligible data breach occurred", clock: "as soon as practicable", recipients: "Affected individuals", sourceUrl: "https://www.oaic.gov.au/privacy/notifiable-data-breaches", confidence: "curated" },
  { id: "certin-6h", regime: "CERT-In", citation: "CERT-In Directions under s. 70B(6) IT Act, 28 April 2022, para (ii)", trigger: "noticing a reportable cyber incident", clock: "6 hours", recipients: "CERT-In (Indian Computer Emergency Response Team)", sourceUrl: "https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf", confidence: "curated" },
  { id: "pci-acquirer", regime: "PCI DSS / card brands", citation: "PCI DSS v4.0.1 Req. 12.10.1; card brand rules", trigger: "suspected or confirmed compromise of cardholder data", clock: "immediately, per your acquirer contract", recipients: "Acquiring bank and the card brands", sourceUrl: "https://www.pcisecuritystandards.org/document_library/", confidence: "verify" },
];
const REG = Object.fromEntries(REGIMES.map((r) => [r.id, r]));

// ---------------------------------------------------------------------------
// Time maths. All instants are epoch ms (UTC); local wall time is derived with
// Intl for the incident's IANA time zone, so results are DST-correct.
// ---------------------------------------------------------------------------

const HOUR = 3600000, DAY = 86400000;
const pad = (n) => String(n).padStart(2, "0");
const fmtCache = new Map();
function partsFmt(tz) {
  let f = fmtCache.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
    fmtCache.set(tz, f);
  }
  return f;
}
/** Valid IANA zone? */
export function isValidTz(tz) {
  if (!tz || typeof tz !== "string") return false;
  try { new Intl.DateTimeFormat("en-US", { timeZone: tz }); return true; } catch (_) { return false; }
}
function tzParts(ms, tz) {
  const o = {};
  for (const p of partsFmt(tz).formatToParts(new Date(ms))) if (p.type !== "literal") o[p.type] = Number(p.value);
  return { y: o.year, m: o.month, d: o.day, h: o.hour === 24 ? 0 : o.hour, mi: o.minute, s: o.second };
}
function tzOffset(ms, tz) {
  const p = tzParts(ms, tz);
  return Date.UTC(p.y, p.m - 1, p.d, p.h, p.mi, p.s) - Math.floor(ms / 1000) * 1000;
}
/** Local wall time in tz -> epoch ms (overflowing fields roll over like Date.UTC). */
export function zonedToUtc(y, m, d, h, mi, s, tz) {
  const guess = Date.UTC(y, m - 1, d, h || 0, mi || 0, s || 0);
  const off = tzOffset(guess, tz);
  let t = guess - off;
  const off2 = tzOffset(t, tz);
  if (off2 !== off) t = guess - off2;
  return t;
}
/** Short zone name at an instant, e.g. "CDT" or "GMT+2". */
function tzName(ms, tz) {
  try {
    const p = new Intl.DateTimeFormat("en-US", { timeZone: tz, timeZoneName: "short" }).formatToParts(new Date(ms)).find((x) => x.type === "timeZoneName");
    return p ? p.value : tz;
  } catch (_) { return tz; }
}
/** "2026-10-16 14:00 CDT" */
export function formatLocal(ms, tz) {
  if (ms == null || !Number.isFinite(ms)) return "";
  const p = tzParts(ms, tz);
  return p.y + "-" + pad(p.m) + "-" + pad(p.d) + " " + pad(p.h) + ":" + pad(p.mi) + " " + tzName(ms, tz);
}
const iso = (ms) => (ms == null || !Number.isFinite(ms) ? null : new Date(ms).toISOString());

/**
 * Parse a timestamp. ISO with Z or an offset is absolute; "YYYY-MM-DD[ HH:MM[:SS]]"
 * (as an <input type=datetime-local> gives) is wall time in tz. Returns ms or null.
 */
export function parseTime(v, tz = "UTC") {
  if (v == null || v === "") return null;
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  const s = String(v).trim();
  if (!s) return null;
  if (/(Z|[+-]\d\d:?\d\d)$/i.test(s) && /\d{4}-\d\d-\d\d[T ]\d\d:\d\d/.test(s)) {
    const [y, mo, d] = s.slice(0, 10).split("-").map(Number);
    const t = Date.parse(s.replace(" ", "T"));
    return Number.isFinite(t) && d <= new Date(Date.UTC(y, mo, 0)).getUTCDate() ? t : null;
  }
  const m = /^(\d{4})-(\d\d)-(\d\d)(?:[T ](\d\d):(\d\d)(?::(\d\d)(?:\.\d+)?)?)?$/.exec(s);
  if (!m) return null;
  const [y, mo, d, h, mi, se] = [m[1], m[2], m[3], m[4] || 0, m[5] || 0, m[6] || 0].map(Number);
  if (mo < 1 || mo > 12 || d < 1 || d > new Date(Date.UTC(y, mo, 0)).getUTCDate() || h > 23 || mi > 59 || se > 59) return null; // 2026-02-30 would roll to March
  return zonedToUtc(y, mo, d, h, mi, se, isValidTz(tz) ? tz : "UTC");
}

/** Add n hours. */
export const addHours = (ms, n) => ms + n * HOUR;
/** Add n calendar days keeping the local wall-clock time in tz. */
export function addCalendarDays(ms, n, tz = "UTC") {
  const p = tzParts(ms, tz);
  return zonedToUtc(p.y, p.m, p.d + n, p.h, p.mi, p.s, tz);
}
/** Add n calendar months in tz; the day clamps to the end of a shorter month. */
export function addMonths(ms, n, tz = "UTC") {
  const p = tzParts(ms, tz);
  const tgt = new Date(Date.UTC(p.y, p.m - 1 + n, 1));
  const last = new Date(Date.UTC(tgt.getUTCFullYear(), tgt.getUTCMonth() + 1, 0)).getUTCDate();
  return zonedToUtc(tgt.getUTCFullYear(), tgt.getUTCMonth() + 1, Math.min(p.d, last), p.h, p.mi, p.s, tz);
}

/** Normalise holidays: envelope {data:[{date}]}, [{date}] or ["YYYY-MM-DD"] -> Set. */
export function holidaySet(h) {
  const arr = Array.isArray(h) ? h : h && Array.isArray(h.data) ? h.data : [];
  const out = new Set();
  for (const x of arr) { const d = typeof x === "string" ? x : x && x.date; if (/^\d{4}-\d\d-\d\d$/.test(String(d || ""))) out.add(d); }
  return out;
}
const ymd = (y, m, d) => { const t = new Date(Date.UTC(y, m - 1, d)); return { y: t.getUTCFullYear(), m: t.getUTCMonth() + 1, d: t.getUTCDate(), dow: t.getUTCDay(), key: t.toISOString().slice(0, 10) }; };
/** Business day = Mon-Fri and not in holidays (EDGAR closes on federal holidays). */
export function isBusinessDay(dateKey, holidays) {
  const [y, m, d] = dateKey.split("-").map(Number);
  const x = ymd(y, m, d);
  return x.dow !== 0 && x.dow !== 6 && !holidays.has(x.key);
}
/**
 * The nth business day after the local date of `ms` in tz (the event day is day 0),
 * returned as epoch ms at cutoff "HH:MM" local. Also returns the days skipped.
 */
export function addBusinessDays(ms, n, holidays, tz = "America/New_York", cutoff = "17:30") {
  const p = tzParts(ms, tz);
  let cur = ymd(p.y, p.m, p.d);
  let k = 0;
  const skipped = [];
  let guard = 0;
  while (k < n && guard++ < 400) {
    cur = ymd(cur.y, cur.m, cur.d + 1);
    if (isBusinessDay(cur.key, holidays)) k++;
    else skipped.push(cur.key + (holidays.has(cur.key) ? " (holiday)" : " (weekend)"));
  }
  const [hh, mm] = cutoff.split(":").map(Number);
  return { ms: zonedToUtc(cur.y, cur.m, cur.d, hh, mm, 0, tz), date: cur.key, skipped };
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

const lc = (s) => String(s == null ? "" : s).trim().toLowerCase();

/** Parse an integer count ("1,200", "1 200", "600"). Returns null when not a whole number >= 0. */
export function parseCount(v) {
  if (typeof v === "number") return Number.isInteger(v) && v >= 0 ? v : null;
  const s = String(v == null ? "" : v).trim().replace(/[,\s_']/g, "");
  if (!/^\d+$/.test(s)) return null;
  const n = Number(s);
  return Number.isSafeInteger(n) ? n : null;
}

// Split one line on its delimiter (tab, else semicolon, else comma), honouring double quotes
// ("1,200"). A spreadsheet paste is tab-separated with formatted counts: California<TAB>1,200.
function splitCells(line) {
  const out = [];
  const d = line.includes("\t") ? "\t" : line.includes(";") ? ";" : ",";
  let cur = "", inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') { if (inQ && line[i + 1] === '"') { cur += '"'; i++; } else inQ = !inQ; }
    else if (!inQ && c === d) { out.push(cur.trim()); cur = ""; }
    else cur += c;
  }
  out.push(cur.trim());
  return out;
}

/**
 * Parse a pasted `jurisdiction,count` table (comma, tab or semicolon; header optional).
 * @returns {{ rows: {jurisdiction:string, count:number}[], skipped: {line:number, text:string, reason:string}[] }}
 */
export function parseCounts(text) {
  const rows = [], skipped = [];
  const lines = String(text || "").split(/\r?\n/);
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    const cells = splitCells(line);
    if (cells.length < 2) { skipped.push({ line: i + 1, text: line, reason: "expected jurisdiction,count" }); return; }
    const count = parseCount(cells[cells.length - 1]);
    const jur = cells.slice(0, -1).join(", ").trim();
    if (count == null) {
      const isHeader = COLUMNS.jurisdiction.includes(lc(cells[0])) && COLUMNS.count.includes(lc(cells[cells.length - 1]));
      if (!(isHeader && i === lines.findIndex((l) => l.trim()))) skipped.push({ line: i + 1, text: line, reason: "count is not a whole number" });
      return;
    }
    if (!jur) { skipped.push({ line: i + 1, text: line, reason: "missing jurisdiction" }); return; }
    rows.push({ jurisdiction: jur, count });
  });
  return { rows, skipped };
}

/** Normalise reference envelopes {version, data} or bare arrays. */
function refList(ref) { return Array.isArray(ref) ? ref : ref && Array.isArray(ref.data) ? ref.data : []; }
function refVersion(ref) { return ref && !Array.isArray(ref) && ref.version ? String(ref.version) : null; }

/**
 * Resolve one jurisdiction string. 2-letter codes resolve to a US state when one
 * matches (CA = California, DE = Delaware, IN = Indiana); write the country name
 * (Canada, Germany, India) or "country:CA" for the country.
 */
export function resolveJurisdiction(raw, states) {
  const s = String(raw || "").trim();
  const low = s.toLowerCase();
  const byCode = new Map(states.map((x) => [String(x.code).toUpperCase(), x]));
  const byName = new Map(states.map((x) => [lc(x.jurisdiction), x]));
  let m;
  if ((m = /^us[-_ ]([a-z]{2})$/i.exec(s)) && byCode.has(m[1].toUpperCase())) return { kind: "us", code: m[1].toUpperCase(), name: byCode.get(m[1].toUpperCase()).jurisdiction, ref: byCode.get(m[1].toUpperCase()) };
  if (byName.has(low)) { const x = byName.get(low); return { kind: "us", code: x.code, name: x.jurisdiction, ref: x }; }
  const ctry = (code) => {
    if (EU[code]) return { kind: "eu", code, name: EU[code] };
    if (OTHER_COUNTRIES[code]) return { kind: code.toLowerCase(), code, name: OTHER_COUNTRIES[code] };
    return null;
  };
  if ((m = /^country:\s*([a-z]{2})$/i.exec(s))) { const c = ctry(m[1].toUpperCase()); if (c) return c; }
  if (/^[a-z]{2}$/i.test(s) && byCode.has(s.toUpperCase())) { const x = byCode.get(s.toUpperCase()); return { kind: "us", code: x.code, name: x.jurisdiction, ref: x, note: ctry(s.toUpperCase()) ? "read as the US state; write the country name for " + ctry(s.toUpperCase()).name : undefined }; }
  if (COUNTRY_ALIASES[low]) return ctry(COUNTRY_ALIASES[low]);
  for (const [code, name] of Object.entries({ ...EU, ...OTHER_COUNTRIES })) if (lc(name) === low) return ctry(code);
  if (/^[a-z]{2}$/i.test(s)) { const c = ctry(s.toUpperCase()); if (c) return c; }
  return { kind: "unknown", code: s, name: s };
}

/** Facts with defaults applied and values normalised (pure). */
export function normalizeFacts(f) {
  f = f && typeof f === "object" ? f : {};
  const arr = (v) => (Array.isArray(v) ? v : v ? [v] : []);
  const tri = (v, set, d) => (set.includes(v) ? v : d);
  const counts = arr(f.counts).map((r) => ({ jurisdiction: String((r && r.jurisdiction) || "").trim(), count: parseCount(r && r.count) }))
    .filter((r) => r.jurisdiction && r.count != null);
  const le = f.leDelay && typeof f.leDelay === "object" ? f.leDelay : {};
  return {
    title: String(f.title || "").trim(),
    sectors: [...new Set(arr(f.sectors).filter((s) => SECTOR_IDS.has(s)))].sort(),
    memberState: String(f.memberState || "").trim(),
    dataTypes: [...new Set(arr(f.dataTypes).filter((s) => TYPE_IDS.has(s)))].sort(),
    total: parseCount(f.total),
    counts,
    encrypted: tri(f.encrypted, ["yes", "no", "unknown"], "unknown"),
    harm: tri(f.harm, ["unknown", "unlikely", "risk", "high"], "unknown"),
    nis2Significant: tri(f.nis2Significant, ["yes", "no", "unknown"], "unknown"),
    timeZone: isValidTz(f.timeZone) ? f.timeZone : "UTC",
    timeZoneGiven: isValidTz(f.timeZone),
    occurredAt: f.occurredAt || "", discoveredAt: f.discoveredAt || "", determinedAt: f.determinedAt || "",
    materialityAt: f.materialityAt || "", ransomPaidAt: f.ransomPaidAt || "",
    leDelay: { requested: !!le.requested, from: le.from || "", until: le.until || "", agDetermination: !!le.agDetermination },
  };
}

// ---------------------------------------------------------------------------
// assess
// ---------------------------------------------------------------------------

const APPLIES_RANK = { likely: 0, possible: 1, "not-indicated": 2 };

/**
 * Work out obligations for an incident.
 * @param {object} facts incident facts (see normalizeFacts)
 * @param {{ now?: string, breachLaws?: object, holidays?: object, statuses?: object, dueSoonHours?: number, urgentHours?: number }} [opts]
 */
export function assess(facts, opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const F = normalizeFacts(facts);
  const tz = F.timeZone;
  const T = (v) => parseTime(v, tz);
  const t = {
    occurred: T(F.occurredAt), discovered: T(F.discoveredAt), determined: T(F.determinedAt),
    material: T(F.materialityAt), ransom: T(F.ransomPaidAt), leFrom: T(F.leDelay.from), leUntil: T(F.leDelay.until),
  };
  const missing = [], skipped = [], notes = [];
  const miss = (field, label, why) => { if (!missing.some((m) => m.field === field)) missing.push({ field, label, why }); };
  const has = (s) => F.sectors.includes(s);
  const hasType = (...ids) => ids.some((id) => F.dataTypes.includes(id));
  const states = refList(o.breachLaws);
  const holidays = holidaySet(o.holidays);
  const statuses = o.statuses && typeof o.statuses === "object" ? o.statuses : {};

  for (const [k, label] of [["occurredAt", "occurred"], ["discoveredAt", "discovered"], ["determinedAt", "determined"], ["materialityAt", "determined material"], ["ransomPaidAt", "extortion payment"]]) {
    if (F[k] && t[{ occurredAt: "occurred", discoveredAt: "discovered", determinedAt: "determined", materialityAt: "material", ransomPaidAt: "ransom" }[k]] == null) {
      skipped.push({ check: k, reason: "could not read the '" + label + "' time \"" + F[k] + "\" (use YYYY-MM-DDTHH:MM)" });
    }
  }
  if (!F.timeZoneGiven) miss("timeZone", "Time zone", "Times are read as UTC until the incident's time zone is set.");
  if (t.discovered == null) miss("discoveredAt", "Discovered", "Most clocks run from discovery or awareness; no deadline can be computed without it.");
  if (!F.sectors.length) miss("sectors", "Organisation sector", "Sector decides which regimes are in scope (HIPAA, GLBA, SEC, NIS2 ...).");
  if (!F.dataTypes.length) miss("dataTypes", "Data types", "State laws and HIPAA turn on what data was involved.");
  if (F.encrypted === "unknown") miss("encrypted", "Encryption", "Encrypted data with an uncompromised key usually falls under a safe harbor.");

  // Jurisdictions.
  const jur = F.counts.map((r) => ({ ...r, res: resolveJurisdiction(r.jurisdiction, states) }));
  const usRows = new Map(), countries = new Map();
  for (const j of jur) {
    if (j.res.kind === "us") usRows.set(j.res.code, { ...j.res, count: (usRows.get(j.res.code)?.count || 0) + j.count });
    else if (j.res.kind !== "unknown") countries.set(j.res.code, { ...j.res, count: (countries.get(j.res.code)?.count || 0) + j.count });
    else skipped.push({ check: "jurisdiction:" + j.jurisdiction, reason: "no regime modelled for \"" + j.jurisdiction + "\" (US states: name or code; countries: full name)" });
    if (j.res.note) notes.push(j.jurisdiction + ": " + j.res.note);
  }
  const sumCounts = jur.reduce((a, j) => a + j.count, 0);
  const total = F.total != null ? F.total : jur.length ? sumCounts : null;
  if (total == null) miss("total", "Affected individuals", "HIPAA, GLBA and state regulator notices depend on how many people are affected.");
  const kindCount = (k) => [...countries.values()].filter((c) => c.kind === k).reduce((a, c) => a + c.count, 0);

  const obligations = [];
  const nowMs = o.now ? parseTime(o.now, "UTC") : Math.max(...Object.values(t).filter((x) => x != null), -Infinity);
  const now = Number.isFinite(nowMs) ? nowMs : null;
  const confirmed = t.determined != null ? t.determined : t.discovered;

  const toll = (ob, deadline, trigger, reason) => {
    if (!F.leDelay.requested) return deadline;
    if (t.leUntil == null) { ob.conditions.push("Law-enforcement delay recorded without an end date: the pause cannot be computed. " + reason); miss("leDelay.until", "Law-enforcement delay end", "Needed to compute the paused deadline."); return deadline; }
    const start = Math.max(t.leFrom != null ? t.leFrom : trigger, trigger);
    if (t.leUntil <= start || start >= deadline) { ob.conditions.push("Law-enforcement delay does not overlap this clock."); return deadline; }
    const paused = t.leUntil - start;
    ob.why.push("Law-enforcement delay: clock paused " + formatLocal(start, tz) + " to " + formatLocal(t.leUntil, tz) + " (" + Math.round(paused / HOUR) + " h). " + reason);
    ob.lawEnforcementDelay = { from: iso(start), until: iso(t.leUntil), pausedHours: Math.round(paused / HOUR) };
    return deadline + paused;
  };

  const make = (regId, extra) => {
    const r = REG[regId] || {};
    const ob = {
      id: extra.id || regId, regime: r.regime || extra.regime, jurisdiction: extra.jurisdiction || "", recipient: extra.recipient || r.recipients,
      trigger: extra.trigger || r.trigger, triggerTime: null, triggerLocal: "", deadline: null, deadlineLocal: "", deadlineKind: extra.deadlineKind,
      clock: extra.clock || r.clock, applies: extra.applies, why: extra.why || [], conditions: extra.conditions || [],
      citation: extra.citation || r.citation, sourceUrl: extra.sourceUrl || r.sourceUrl, confidence: extra.confidence || r.confidence || "verify",
    };
    if (extra.triggerMs != null) { ob.triggerTime = iso(extra.triggerMs); ob.triggerLocal = formatLocal(extra.triggerMs, tz); }
    let dl = extra.deadlineMs;
    if (dl != null && extra.tollable) dl = toll(ob, dl, extra.triggerMs, extra.tollReason || "");
    if (dl != null) { ob.deadline = iso(dl); ob.deadlineLocal = formatLocal(dl, tz); }
    if (extra.deadlineEt) ob.deadlineEt = extra.deadlineEt;
    obligations.push(ob);
    return ob;
  };

  // --- GDPR / UK GDPR -----------------------------------------------------------
  const gdprBlock = (pfx, label, scopeSector, cnt) => {
    if (!has(scopeSector) && !cnt) return;
    const inScope = has(scopeSector) ? "likely" : "possible";
    const scopeWhy = has(scopeSector)
      ? (pfx === "gdpr" ? "Sector includes an EU/EEA establishment or EU data subjects." : "Sector includes the United Kingdom.")
      : cnt + " affected individuals in " + (pfx === "gdpr" ? "EU/EEA countries" : "the UK") + "; " + (pfx === "gdpr" ? "Art. 3(2)" : "UK GDPR Art. 3(2)") + " may apply if you offer goods or services to them or monitor them.";
    let a33 = inScope;
    const why33 = [scopeWhy];
    const cond33 = ["Not required where the breach is unlikely to result in a risk to individuals; document the reasoning either way (Art. 33(5)).", "A processor must instead tell the controller without undue delay (Art. 33(2)).", "Notice after 72 hours must give reasons for the delay (Art. 33(1)); information may be provided in phases (Art. 33(4))."];
    if (F.harm === "unlikely") { a33 = "possible"; why33.push("Harm assessed as unlikely: notice may not be required; confirm and record the assessment."); }
    if (F.encrypted === "yes") { a33 = a33 === "likely" ? "possible" : a33; why33.push("Data reported encrypted with an uncompromised key, which lowers the risk."); }
    if (F.harm === "unknown") miss("harm", "Risk to individuals", "GDPR Art. 33/34, PIPEDA and the Australian NDB scheme turn on the harm assessment.");
    const trig = t.discovered;
    const recip = pfx === "gdpr"
      ? "Competent supervisory authority" + (F.memberState ? " (" + F.memberState + ", or the lead authority under Art. 56)" : " (lead authority under Art. 56 one-stop-shop)")
      : "Information Commissioner's Office (ICO)";
    if (pfx === "gdpr" && !F.memberState) miss("memberState", "EU member state", "Names the supervisory authority and NIS2 CSIRT.");
    make(pfx + "-33", { applies: a33, why: why33, conditions: cond33, deadlineKind: "hours", triggerMs: trig, deadlineMs: trig != null ? addHours(trig, 72) : null, recipient: recip, jurisdiction: label,
      trigger: "becoming aware of the breach (clock shown from the discovery time; awareness means reasonable certainty that personal data was affected)" });
    let a34 = F.harm === "high" ? inScope : F.harm === "unlikely" ? "not-indicated" : "possible";
    const why34 = [scopeWhy];
    if (F.harm === "high") why34.push("Harm assessed as high risk to individuals.");
    else if (F.harm === "unlikely") why34.push("Harm assessed as unlikely; Art. 34 needs a high risk.");
    else why34.push("Art. 34 applies only when the breach is likely to result in a high risk; the risk level is " + (F.harm === "risk" ? "a risk, not stated as high." : "not yet assessed."));
    if (hasType("special", "credentials", "emailpw", "financial", "pan", "ssn", "biometric", "medical", "phi")) why34.push("Data types involved (" + F.dataTypes.filter((d) => ["special", "credentials", "emailpw", "financial", "pan", "ssn", "biometric", "medical", "phi"].includes(d)).map(typeLabel).join(", ") + ") point toward higher risk.");
    if (F.encrypted === "yes") { a34 = "not-indicated"; why34.push("Art. 34(3)(a): not required where the data was unintelligible to unauthorised persons, e.g. encrypted."); }
    make(pfx + "-34", { applies: a34, why: why34, conditions: ["Exceptions in Art. 34(3): encryption, subsequent measures removing the high risk, or disproportionate effort (then a public communication)."], deadlineKind: "without-undue-delay", triggerMs: trig, deadlineMs: null, jurisdiction: label, clock: "without undue delay" });
  };
  gdprBlock("gdpr", "EU/EEA", "eu", kindCount("eu"));
  gdprBlock("ukgdpr", "United Kingdom", "uk", kindCount("gb"));

  // --- NIS2 --------------------------------------------------------------------
  if (has("nis2")) {
    const ms = F.memberState || "member state";
    if (!F.memberState) miss("memberState", "EU member state", "Names the supervisory authority and NIS2 CSIRT.");
    if (F.nis2Significant === "unknown") miss("nis2Significant", "NIS2 significant incident", "NIS2 reporting applies only to significant incidents (Art. 23(3)).");
    const a = F.nis2Significant === "yes" ? "likely" : F.nis2Significant === "no" ? "not-indicated" : "possible";
    const why = ["Sector marked as an NIS2 essential or important entity" + (F.memberState ? " in " + F.memberState : "") + ".",
      F.nis2Significant === "yes" ? "Incident marked significant (Art. 23(3))." : F.nis2Significant === "no" ? "Incident marked not significant under Art. 23(3)." : "Whether the incident is significant (Art. 23(3)) is not yet decided."];
    const cond = ["National transposition may add detail (forms, portals, extra recipients); check the " + ms + " law.", "Recipients of your services may also need to be told of significant incidents (Art. 23(1))."];
    const trig = t.discovered;
    const recipient = "CSIRT or competent authority of " + ms;
    make("nis2-early", { applies: a, why: [...why], conditions: cond, deadlineKind: "hours", triggerMs: trig, deadlineMs: trig != null ? addHours(trig, 24) : null, recipient, jurisdiction: F.memberState || "EU" });
    const nTrig = make("nis2-notify", { applies: a, why: [...why], conditions: cond, deadlineKind: "hours", triggerMs: trig, deadlineMs: trig != null ? addHours(trig, 72) : null, recipient, jurisdiction: F.memberState || "EU" });
    const sent = statuses["nis2-notify"] && statuses["nis2-notify"].state === "sent" ? parseTime(statuses["nis2-notify"].at, "UTC") : null;
    const base = sent != null ? sent : nTrig.deadline ? Date.parse(nTrig.deadline) : null;
    make("nis2-final", { applies: a, why: [...why, sent != null ? "Counted from when the incident notification was recorded as sent." : "Counted from the 72-hour notification deadline; it moves once the notification is recorded as sent."],
      conditions: [...cond, "If the incident is still ongoing, a progress report replaces the final report and the final report is due within one month of handling it (Art. 23(4)(e))."],
      deadlineKind: "calendar-days", triggerMs: base, deadlineMs: base != null ? addMonths(base, 1, tz) : null, recipient, jurisdiction: F.memberState || "EU" });
  }

  // --- SEC Form 8-K Item 1.05 ----------------------------------------------------
  if (has("sec")) {
    const why = ["Sector marked as an SEC registrant."];
    const cond = ["Applies only to incidents the registrant determines are material; the materiality determination must be made without unreasonable delay after discovery.",
      "Business days exclude weekends and US federal holidays (EDGAR closed). 5:30 p.m. ET is used as a conservative filing cutoff; confirm EDGAR hours.",
      "Item 1.05(c): delay only on a written US Attorney General determination of a substantial risk to national security or public safety (30 days, extendable). A general law-enforcement request does not pause this clock."];
    if (!holidays.size) { skipped.push({ check: "sec-holidays", reason: "US federal holiday reference data not loaded; business days exclude weekends only" }); cond.push("Holiday data not loaded: only weekends were excluded."); }
    let dl = null, deadlineEt = "";
    if (t.material == null) {
      miss("materialityAt", "Determined material (SEC)", "The four-business-day Form 8-K clock starts at the materiality determination.");
      why.push("Materiality not yet determined: no deadline until it is.");
    } else {
      const b = addBusinessDays(t.material, 4, holidays, "America/New_York", "17:30");
      dl = b.ms; deadlineEt = formatLocal(b.ms, "America/New_York");
      why.push("Determined material " + formatLocal(t.material, tz) + "; 4 business days counted from " + formatLocal(t.material, "America/New_York").slice(0, 10) + " (ET)" + (b.skipped.length ? ", skipping " + b.skipped.join(", ") : "") + ".");
    }
    const ob = make("sec-8k", { applies: t.material == null ? "possible" : "likely", why, conditions: cond, deadlineKind: "business-days", triggerMs: t.material, deadlineMs: dl, deadlineEt });
    if (dl != null && F.leDelay.requested && F.leDelay.agDetermination) {
      const d2 = toll(ob, dl, t.material, "Item 1.05(c) Attorney General determination.");
      ob.deadline = iso(d2); ob.deadlineLocal = formatLocal(d2, tz); ob.deadlineEt = formatLocal(d2, "America/New_York");
    } else if (F.leDelay.requested) ob.conditions.push("A law-enforcement delay is recorded but no Attorney General determination: the SEC clock is not paused.");
  }

  // --- HIPAA ---------------------------------------------------------------------
  const phi = hasType("phi", "medical", "healthins");
  if (has("hipaa-ce") || has("hipaa-ba")) {
    const trig = t.discovered;
    const baseWhy = [];
    let a = "likely";
    if (!phi) { a = "not-indicated"; baseWhy.push("No PHI, medical or health-insurance data selected."); }
    else baseWhy.push("PHI or health data involved: " + F.dataTypes.filter((d) => ["phi", "medical", "healthins"].includes(d)).map(typeLabel).join(", ") + ".");
    if (F.encrypted === "yes") { a = "not-indicated"; baseWhy.push("Encrypted per HHS guidance with an uncompromised key is secured PHI, outside the rule."); }
    else if (F.encrypted === "unknown" && a === "likely") a = "possible";
    const cond = ["Breach is presumed unless a documented four-factor risk assessment shows a low probability of compromise (45 CFR 164.402).",
      "Law-enforcement delay (45 CFR 164.412): an oral request limits the delay to 30 days unless a written statement follows."];
    const le = "45 CFR 164.412 permits a law-enforcement delay.";
    if (has("hipaa-ce")) {
      make("hipaa-individuals", { applies: a, why: ["Sector marked as a HIPAA covered entity.", ...baseWhy], conditions: cond, deadlineKind: "calendar-days", triggerMs: trig, deadlineMs: trig != null ? addCalendarDays(trig, 60, tz) : null, tollable: true, tollReason: le, clock: "without unreasonable delay, no later than 60 calendar days" });
      if (total == null) {
        make("hipaa-hhs", { applies: a === "not-indicated" ? a : "possible", why: ["Sector marked as a HIPAA covered entity.", ...baseWhy, "Total affected unknown: 500 or more means notice within 60 days; fewer means the annual log."], conditions: cond, deadlineKind: "calendar-days", triggerMs: trig, deadlineMs: trig != null ? addCalendarDays(trig, 60, tz) : null, tollable: true, tollReason: le });
      } else if (total >= 500) {
        make("hipaa-hhs", { applies: a, why: ["Sector marked as a HIPAA covered entity.", ...baseWhy, total + " individuals affected (500 or more): notify HHS contemporaneously with individuals."], conditions: cond, deadlineKind: "calendar-days", triggerMs: trig, deadlineMs: trig != null ? addCalendarDays(trig, 60, tz) : null, tollable: true, tollReason: le, clock: "contemporaneously with individual notice, no later than 60 calendar days" });
      } else {
        let dl = null;
        if (trig != null) { const p = tzParts(trig, tz); dl = addCalendarDays(zonedToUtc(p.y + 1, 1, 1, 0, 0, 0, tz), 60, tz); }
        make("hipaa-hhs", { applies: a, why: ["Sector marked as a HIPAA covered entity.", ...baseWhy, total + " individuals affected (fewer than 500): log and report to HHS within 60 days after the end of the calendar year of discovery."], conditions: cond, deadlineKind: "calendar-days", triggerMs: trig, deadlineMs: dl, clock: "60 days after the end of the calendar year" });
      }
      for (const s of [...usRows.values()].sort((x, y) => (x.code < y.code ? -1 : 1))) {
        if (s.count > 500) make("hipaa-media", { id: "hipaa-media-" + s.code, jurisdiction: s.name, applies: a, why: ["Sector marked as a HIPAA covered entity.", ...baseWhy, s.count + " residents of " + s.name + " (more than 500)."], conditions: cond, deadlineKind: "calendar-days", triggerMs: trig, deadlineMs: trig != null ? addCalendarDays(trig, 60, tz) : null, tollable: true, tollReason: le, recipient: "Prominent media outlets serving " + s.name });
      }
      if (!usRows.size && phi) miss("counts", "Affected individuals per state", "HIPAA media notice depends on residents per state (more than 500).");
    }
    if (has("hipaa-ba")) {
      make("hipaa-ba-ce", { applies: a, why: ["Sector marked as a HIPAA business associate.", ...baseWhy], conditions: [...cond, "Your business associate agreement may set a shorter deadline; check it."], deadlineKind: "calendar-days", triggerMs: trig, deadlineMs: trig != null ? addCalendarDays(trig, 60, tz) : null, tollable: true, tollReason: le, clock: "without unreasonable delay, no later than 60 calendar days" });
    }
  }

  // --- GLBA Safeguards Rule --------------------------------------------------------
  if (has("glba")) {
    const why = ["Sector marked as a financial institution under the FTC Safeguards Rule."];
    let a = "likely";
    if (F.encrypted === "yes") { a = "not-indicated"; why.push("Only unencrypted customer information counts (information is unencrypted if the key was also acquired)."); }
    else if (F.encrypted === "unknown") a = "possible";
    if (total == null) { a = a === "not-indicated" ? a : "possible"; why.push("Total affected unknown: the rule needs 500 or more consumers."); }
    else if (total < 500) { a = "not-indicated"; why.push(total + " consumers affected, below the 500-consumer threshold."); }
    else why.push(total + " consumers affected (500 or more).");
    make("glba-ftc", { applies: a, why, conditions: ["Covers non-bank financial institutions under FTC jurisdiction; banks follow their federal regulator's 36-hour computer-security incident rule instead (not modelled).", "A law-enforcement request can delay public posting by the FTC, not the notice itself."],
      deadlineKind: "calendar-days", triggerMs: t.discovered, deadlineMs: t.discovered != null ? addCalendarDays(t.discovered, 30, tz) : null, clock: "as soon as possible, no later than 30 calendar days" });
  }

  // --- NYDFS --------------------------------------------------------------------
  if (has("nydfs")) {
    const trig = t.determined != null ? t.determined : t.discovered;
    const why = ["Sector marked as NYDFS-regulated."];
    if (t.determined == null) { miss("determinedAt", "Determined / confirmed", "NYDFS, PIPEDA and several states start their clock at the determination."); why.push("Determination time not given: clock shown from discovery (earlier, conservative)."); }
    make("nydfs-72h", { applies: "likely", why, conditions: ["Reportable cybersecurity incidents are defined in 500.1 (e.g. incidents requiring notice to another government body, or with a reasonable likelihood of material harm, or involving ransomware deployment).", "Includes incidents at affiliates and third-party service providers."], deadlineKind: "hours", triggerMs: trig, deadlineMs: trig != null ? addHours(trig, 72) : null });
    if (t.ransom != null) {
      make("nydfs-extortion-24h", { applies: "likely", why: ["Extortion payment recorded at " + formatLocal(t.ransom, tz) + "."], conditions: ["Also screen the payee against sanctions lists before paying."], deadlineKind: "hours", triggerMs: t.ransom, deadlineMs: addHours(t.ransom, 24) });
      make("nydfs-extortion-30d", { applies: "likely", why: ["Extortion payment recorded at " + formatLocal(t.ransom, tz) + "."], conditions: ["Written description of why payment was necessary, alternatives considered, and sanctions diligence."], deadlineKind: "calendar-days", triggerMs: t.ransom, deadlineMs: addCalendarDays(t.ransom, 30, tz) });
    } else skipped.push({ check: "nydfs-extortion", reason: "no extortion payment recorded" });
  }

  // --- PIPEDA -------------------------------------------------------------------------
  const caCount = kindCount("ca");
  if (has("ca") || caCount) {
    const scope = has("ca") ? "likely" : "possible";
    const why = [has("ca") ? "Sector marked as a Canadian organisation." : caCount + " affected individuals in Canada."];
    const a = F.harm === "unlikely" ? "not-indicated" : F.harm === "unknown" ? "possible" : scope;
    const hw = F.harm === "unlikely" ? "Harm assessed as unlikely: no real risk of significant harm (RROSH) indicated." : F.harm === "unknown" ? "Real risk of significant harm not yet assessed." : "Harm assessed as " + F.harm + ": RROSH indicated.";
    if (F.harm === "unknown") miss("harm", "Risk to individuals", "GDPR Art. 33/34, PIPEDA and the Australian NDB scheme turn on the harm assessment.");
    const trig = confirmed;
    const cond = ["Also notify other organisations or government institutions that may reduce the risk of harm (s. 10.2).", "Provincial laws (Quebec Law 25, Alberta PIPA) may apply instead or as well."];
    make("pipeda-opc", { applies: a, why: [...why, hw], conditions: cond, deadlineKind: "as-soon-as-practicable", triggerMs: trig, deadlineMs: null, clock: "as soon as feasible" });
    make("pipeda-individuals", { applies: a, why: [...why, hw], conditions: cond, deadlineKind: "as-soon-as-practicable", triggerMs: trig, deadlineMs: null, clock: "as soon as feasible" });
    make("pipeda-records", { applies: scope, why: [...why, "Every breach of security safeguards must be recorded, whatever the harm assessment."], conditions: [], deadlineKind: "as-soon-as-practicable", triggerMs: trig, deadlineMs: null });
  }

  // --- Australia NDB --------------------------------------------------------------------
  const auCount = kindCount("au");
  if (has("au") || auCount) {
    const scope = has("au") ? "likely" : "possible";
    const why = [has("au") ? "Sector marked as an Australian APP entity." : auCount + " affected individuals in Australia."];
    if (F.harm === "unknown") miss("harm", "Risk to individuals", "GDPR Art. 33/34, PIPEDA and the Australian NDB scheme turn on the harm assessment.");
    const a = F.harm === "unlikely" ? "not-indicated" : F.harm === "unknown" ? "possible" : scope;
    const cond = ["An eligible data breach needs likely serious harm that remedial action has not prevented (s. 26WE)."];
    make("ndb-assess", { applies: scope, why: [...why, "An assessment is needed whenever an eligible data breach is suspected."], conditions: cond, deadlineKind: "calendar-days", triggerMs: t.discovered, deadlineMs: t.discovered != null ? addCalendarDays(t.discovered, 30, tz) : null, clock: "reasonable and expeditious, within 30 calendar days" });
    const hw = F.harm === "unlikely" ? "Serious harm assessed as unlikely." : F.harm === "unknown" ? "Serious harm not yet assessed." : "Harm assessed as " + F.harm + ".";
    make("ndb-oaic", { applies: a, why: [...why, hw], conditions: cond, deadlineKind: "as-soon-as-practicable", triggerMs: confirmed, deadlineMs: null });
    make("ndb-individuals", { applies: a, why: [...why, hw], conditions: cond, deadlineKind: "as-soon-as-practicable", triggerMs: confirmed, deadlineMs: null });
  }

  // --- India CERT-In --------------------------------------------------------------------
  const inCount = kindCount("in");
  if (has("in") || inCount) {
    const a = has("in") ? "likely" : "possible";
    make("certin-6h", { applies: a, why: [has("in") ? "Sector marked as an Indian body corporate." : inCount + " affected individuals in India; CERT-In applies to entities with systems in India."],
      conditions: ["Covers the incident types listed in Annexure I of the Directions (e.g. data breaches, data leaks, ransomware, unauthorised access).", "The Digital Personal Data Protection Act 2023 and its Rules may add a separate notice to the Data Protection Board; verify."],
      deadlineKind: "hours", triggerMs: t.discovered, deadlineMs: t.discovered != null ? addHours(t.discovered, 6) : null });
  }

  // --- PCI ----------------------------------------------------------------------------
  if (has("pci") || hasType("pan")) {
    const a = has("pci") ? "likely" : "possible";
    make("pci-acquirer", { applies: a, why: [has("pci") ? "Sector marked as a payment card merchant or service provider." : "Payment card numbers are involved."], conditions: ["Deadlines come from your acquirer agreement and each brand's rules (e.g. Visa, Mastercard); they expect notice immediately on suspicion.", "A PCI Forensic Investigator may be required."],
      deadlineKind: "as-soon-as-practicable", triggerMs: t.discovered, deadlineMs: null, clock: "immediately, per your acquirer contract" });
  }

  // --- US states (reference data) -------------------------------------------------------
  if (usRows.size && !states.length) skipped.push({ check: "us-states", reason: "US breach-law reference data not loaded" });
  if (states.length && !usRows.size && (has("general") || has("hipaa-ce") || has("glba") || has("sec") || has("nydfs"))) miss("counts", "Affected individuals per state", "State notice duties and regulator thresholds depend on residents per state.");
  if (states.length) {
    for (const s of [...usRows.values()].sort((x, y) => (x.code < y.code ? -1 : 1))) {
      const r = s.ref;
      const covered = F.dataTypes.filter((d) => (STATE_KEYWORDS[d] || []).some((re) => re.test(r.piiDefinitionNotes || "")));
      let a = "likely";
      const why = [s.count.toLocaleString("en-US") + " residents of " + r.jurisdiction + " affected."];
      const cond = ["Statute: " + r.statute + ". Reference note: " + (r.piiDefinitionNotes || "none")];
      if (!F.dataTypes.length) { a = "possible"; why.push("Data types not given: coverage cannot be checked."); }
      else if (!covered.length) { a = "not-indicated"; why.push("None of the selected data types (" + F.dataTypes.map(typeLabel).join(", ") + ") appear in the reference summary of " + r.jurisdiction + "'s definition; verify against the statute."); }
      else why.push("Covered data: " + covered.map(typeLabel).join(", ") + ".");
      if (hasType("pan") && covered.includes("pan")) cond.push("Card numbers usually count only with any required security code or password.");
      if (F.encrypted === "yes") { a = "not-indicated"; why.push("Data reported encrypted with an uncompromised key: state statutes generally exempt encrypted data, but the reference file does not record each state's safe harbor."); }
      else if (F.encrypted === "unknown" && a === "likely") { a = "possible"; why.push("Encryption status unknown; an encryption safe harbor may apply."); }
      if (r.riskOfHarmTrigger) {
        cond.push("Notice may be skipped after a documented determination that harm is not reasonably likely.");
        if (F.harm === "unlikely" && a === "likely") { a = "possible"; why.push("Harm assessed as unlikely; this statute has a risk-of-harm exception."); }
      }
      if (hasType("phi") && (has("hipaa-ce") || has("hipaa-ba"))) cond.push("Some states deem HIPAA-compliant entities compliant with the state law; check the statute.");
      const fromDetermination = /determination|confirmation|identifying its scope/i.test(r.deadlineText || "");
      let trig = t.discovered;
      if (fromDetermination) {
        if (t.determined != null) trig = t.determined;
        else { miss("determinedAt", "Determined / confirmed", "NYDFS, PIPEDA and several states start their clock at the determination."); why.push("Clock runs from determination; determination time not given, so discovery is used (earlier, conservative)."); }
      }
      const le = "State statutes generally allow a delay at law enforcement's request; the reference file does not model it per state - confirm the statute and keep the written request.";
      const confidence = r.confidence === "verify" ? "verify" : "curated";
      const deadlineLabel = r.deadlineDays != null ? r.deadlineText : "deadline not fixed by statute: without unreasonable delay (" + r.deadlineText + ")";
      make("us-state", { id: "us-" + r.code + "-residents", regime: "US state law (" + r.code + ")", jurisdiction: r.jurisdiction, recipient: "Affected " + r.jurisdiction + " residents", trigger: r.deadlineText, applies: a, why, conditions: cond, citation: r.statute, sourceUrl: r.sourceUrl, confidence: F.leDelay.requested ? "verify" : confidence,
        deadlineKind: r.deadlineDays != null ? "calendar-days" : "without-undue-delay", clock: deadlineLabel, triggerMs: trig, deadlineMs: r.deadlineDays != null && trig != null ? addCalendarDays(trig, r.deadlineDays, tz) : null, tollable: true, tollReason: le });
      // Regulator / Attorney General notice.
      if (r.agThreshold == null) skipped.push({ check: "us-" + r.code + "-regulator", reason: "no regulator-notice duty identified for " + r.jurisdiction + " in the reference data" });
      else {
        let aa = a;
        const wa = ["Regulator threshold: " + (r.agThreshold === 0 ? "every breach that requires resident notice" : r.agThreshold.toLocaleString("en-US") + " residents") + "; " + s.count.toLocaleString("en-US") + " affected."];
        const ca = ["Recipient and timing per the reference note: " + (r.piiDefinitionNotes || "")];
        if (r.agThreshold > 0 && s.count < r.agThreshold) { aa = "not-indicated"; wa.push("Below the threshold."); }
        else if (r.agThreshold > 0 && s.count === r.agThreshold) { if (aa === "likely") aa = "possible"; wa.push("Exactly at the threshold: statutes differ between 'more than' and 'at least'; verify."); }
        if (r.agDeadlineDays != null) ca.push("Deadline computed conservatively from the breach trigger; some statutes count from notice to residents or in business days.");
        make("us-state", { id: "us-" + r.code + "-regulator", regime: "US state law (" + r.code + ")", jurisdiction: r.jurisdiction, recipient: r.jurisdiction + " Attorney General or designated regulator", trigger: r.deadlineText, applies: aa, why: [...why.slice(1), ...wa], conditions: ca, citation: r.statute, sourceUrl: r.sourceUrl, confidence,
          deadlineKind: r.agDeadlineDays != null ? "calendar-days" : "without-undue-delay", clock: r.agDeadlineDays != null ? r.agDeadlineDays + " calendar days" : "deadline not fixed by statute: no later than or with resident notice (see note)", triggerMs: trig, deadlineMs: r.agDeadlineDays != null && trig != null ? addCalendarDays(trig, r.agDeadlineDays, tz) : null });
      }
      if (r.creditBureauThreshold != null) {
        let ac = a;
        const wc = ["Consumer reporting agency threshold: " + (r.creditBureauThreshold === 0 ? "every breach requiring resident notice" : r.creditBureauThreshold.toLocaleString("en-US") + " residents") + "; " + s.count.toLocaleString("en-US") + " affected."];
        if (r.creditBureauThreshold > 0 && s.count < r.creditBureauThreshold) { ac = "not-indicated"; wc.push("Below the threshold."); }
        else if (r.creditBureauThreshold > 0 && s.count === r.creditBureauThreshold) { if (ac === "likely") ac = "possible"; wc.push("Exactly at the threshold: verify 'more than' versus 'at least'."); }
        if (ac !== "not-indicated" || r.creditBureauThreshold > 0) make("us-state", { id: "us-" + r.code + "-cra", regime: "US state law (" + r.code + ")", jurisdiction: r.jurisdiction, recipient: "Nationwide consumer reporting agencies (Equifax, Experian, TransUnion)", trigger: r.deadlineText, applies: ac, why: [...why.slice(1), ...wc], conditions: ["Timing and content per the statute; see the reference note."], citation: r.statute, sourceUrl: r.sourceUrl, confidence, deadlineKind: "without-undue-delay", clock: "deadline not fixed in the reference data: without unreasonable delay", triggerMs: trig, deadlineMs: null });
      }
    }
  }

  // Time left, status, sorting.
  for (const ob of obligations) {
    const st = statuses[ob.id] && typeof statuses[ob.id] === "object" ? statuses[ob.id] : {};
    ob.status = ["not-started", "drafted", "sent", "not-required"].includes(st.state) ? st.state : "not-started";
    if (st.at) ob.statusAt = String(st.at);
    if (st.reason) ob.statusReason = String(st.reason);
    ob.timeLeftHours = ob.deadline && now != null ? Math.round((Date.parse(ob.deadline) - now) / HOUR * 10) / 10 : null;
    ob.urgency = !ob.deadline ? "no-fixed-deadline" : ob.timeLeftHours == null ? "unknown" : ob.timeLeftHours < 0 ? "overdue" : ob.timeLeftHours < o.urgentHours ? "due-24h" : ob.timeLeftHours < o.dueSoonHours ? "due-72h" : "later";
    ob.why = ob.why.filter(Boolean); ob.conditions = ob.conditions.filter(Boolean);
  }
  obligations.sort((a, b) => (APPLIES_RANK[a.applies] - APPLIES_RANK[b.applies]) || cmpDeadline(a, b) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  const live = obligations.filter((ob) => ob.applies !== "not-indicated");
  const timeline = live.filter((ob) => ob.deadline).slice().sort((a, b) => cmpDeadline(a, b) || (a.id < b.id ? -1 : 1))
    .map((ob) => ({ id: ob.id, regime: ob.regime, recipient: ob.recipient, deadline: ob.deadline, deadlineLocal: ob.deadlineLocal, timeLeftHours: ob.timeLeftHours, urgency: ob.urgency, applies: ob.applies, status: ob.status }));

  missing.sort((a, b) => (a.field < b.field ? -1 : a.field > b.field ? 1 : 0));
  skipped.sort((a, b) => (a.check < b.check ? -1 : a.check > b.check ? 1 : 0));
  const open = live.filter((ob) => ob.status !== "sent" && ob.status !== "not-required");
  const next = open.filter((ob) => ob.deadline && ob.urgency !== "overdue").sort(cmpDeadline)[0] || null;
  return {
    facts: F, now: iso(now), timeZone: tz,
    reference: { breachLaws: refVersion(o.breachLaws), holidays: refVersion(o.holidays), statesLoaded: states.length, holidaysLoaded: holidays.size },
    jurisdictions: jur.map((j) => ({ input: j.jurisdiction, count: j.count, kind: j.res.kind, name: j.res.name, code: j.res.code, ...(j.res.note ? { note: j.res.note } : {}) })),
    total, obligations, timeline, checklist: buildChecklist(live), missing, skipped, notes,
    counts: {
      likely: obligations.filter((x) => x.applies === "likely").length, possible: obligations.filter((x) => x.applies === "possible").length,
      notIndicated: obligations.filter((x) => x.applies === "not-indicated").length,
      overdue: open.filter((x) => x.urgency === "overdue").length, due24h: open.filter((x) => x.urgency === "due-24h").length, due72h: open.filter((x) => x.urgency === "due-72h").length,
    },
    nextDeadline: next ? { id: next.id, deadline: next.deadline, deadlineLocal: next.deadlineLocal, recipient: next.recipient } : null,
    verify: VERIFY_LINE,
  };
}

function cmpDeadline(a, b) {
  if (a.deadline && b.deadline) return a.deadline < b.deadline ? -1 : a.deadline > b.deadline ? 1 : 0;
  if (a.deadline) return -1;
  if (b.deadline) return 1;
  return 0;
}

const EXTRA_STEPS = {
  "gdpr-33": ["Record the breach in the internal breach register (Art. 33(5))", "Prepare the Art. 33(3) content: nature, categories and approximate numbers, DPO contact, likely consequences, measures taken"],
  "ukgdpr-33": ["Record the breach in the internal breach log (UK GDPR Art. 33(5))"],
  "sec-8k": ["Document the materiality determination and who made it", "Draft Item 1.05 disclosure: nature, scope, timing, material impact or reasonably likely impact"],
  "hipaa-individuals": ["Complete and document the four-factor risk assessment (45 CFR 164.402)", "Set up substitute notice if 10 or more individuals have out-of-date contact information"],
  "hipaa-hhs": ["Submit through the HHS OCR breach portal"],
  "glba-ftc": ["Submit through the FTC Safeguards Rule notification form"],
  "nydfs-72h": ["Submit through the DFS portal and keep supporting records"],
  "pipeda-records": ["Keep a record of the breach for at least 24 months"],
  "ndb-assess": ["Document the assessment of whether serious harm is likely"],
  "nis2-final": ["Include root cause, mitigation applied and cross-border impact"],
  "pci-acquirer": ["Preserve logs and systems for a PCI Forensic Investigator"],
};

function buildChecklist(live) {
  const out = [];
  for (const ob of live) {
    const label = ob.regime + ": " + ob.recipient;
    const owner = /residents|individuals|data subjects|media/i.test(ob.recipient) ? "Privacy / Communications" : /SEC/.test(ob.regime) ? "Legal / Finance" : "Legal / Privacy";
    out.push({ obligationId: ob.id, obligation: label, step: "Confirm with counsel whether this obligation applies (" + ob.citation + ")", owner: "Legal", done: false });
    for (const s of EXTRA_STEPS[ob.id.replace(/-[A-Z]{2}$/, "")] || []) out.push({ obligationId: ob.id, obligation: label, step: s, owner, done: false });
    out.push({ obligationId: ob.id, obligation: label, step: "Draft the notice to " + ob.recipient, owner, done: false });
    out.push({ obligationId: ob.id, obligation: label, step: "Send by " + (ob.deadlineLocal || ob.clock) + " and keep proof of sending", owner, done: false });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Deck contract: parseInput / analyze / findings
// ---------------------------------------------------------------------------

/** Pull an incident record out of an exported JSON object (obligations export or bare record). */
function asRecord(o) {
  if (!o || typeof o !== "object") return null;
  if (o.tool === TOOL_ID && o.incident && typeof o.incident === "object") return o.incident;
  if (o.facts && typeof o.facts === "object") return o;
  if (o.discoveredAt !== undefined || o.sectors !== undefined || o.dataTypes !== undefined) return { facts: o };
  return null;
}

/**
 * Parse an exported incident JSON (re-import) or a `jurisdiction,count` table.
 * Accepts a string or [{name, text}].
 */
export function parseInput(input) {
  const files = Array.isArray(input) ? input : [{ name: "", text: input }];
  const rows = [], skipped = [];
  let format = "empty";
  for (const f of files) {
    const t = String((f && f.text) || "");
    if (!t.trim()) continue;
    const name = (f && f.name) || "input";
    if (/^\s*[[{]/.test(t)) {
      let j;
      try { j = JSON.parse(t); } catch (_) { skipped.push({ check: name, reason: "invalid JSON" }); continue; }
      const list = Array.isArray(j) ? j : [j];
      let n = 0;
      for (const it of list) { const rec = asRecord(it); if (rec) { rows.push(rec); n++; } }
      if (n) format = "breachclock-incident";
      else skipped.push({ check: name, reason: "JSON is not a Breach Clock incident export" });
      continue;
    }
    const c = parseCounts(t);
    if (c.rows.length) { format = format === "empty" ? "jurisdiction-counts" : format; for (const r of c.rows) rows.push({ ...r, _counts: true }); /* one at a time: spreading 100k+ rows into push() overflows the call stack */ }
    for (const s of c.skipped) skipped.push({ check: name + ":" + s.line, reason: s.reason });
  }
  const headers = format === "jurisdiction-counts" ? ["jurisdiction", "count"] : format === "breachclock-incident" ? ["facts", "statuses", "notes"] : [];
  return { format, headers, rows, skipped };
}

const CONTROLS_BASE = [{ framework: "ISO27001", id: "A.5.26" }, { framework: "ISO27001", id: "A.5.5" }];

/** Turn an assessment into Deck findings (overdue / due soon, open, applicable). */
export function toFindings(a, title) {
  const findings = [];
  for (const ob of a.obligations) {
    if (ob.applies === "not-indicated" || !ob.deadline || ob.status === "sent" || ob.status === "not-required") continue;
    if (!["overdue", "due-24h", "due-72h"].includes(ob.urgency)) continue;
    const severity = ob.urgency === "overdue" ? "critical" : ob.urgency === "due-24h" ? "high" : "medium";
    const left = ob.timeLeftHours;
    const when = left < 0 ? "overdue by " + fmtDur(-left) : "due in " + fmtDur(left);
    findings.push({
      id: TOOL_ID + ":" + ob.id,
      title: (ob.urgency === "overdue" ? "Notification deadline passed: " : "Notification deadline approaching: ") + ob.regime + " to " + ob.recipient,
      severity, confidence: ob.applies === "likely" ? "likely" : "review", status: "open", category: "breach-notification",
      description: ob.citation + " (" + ob.clock + "). Deadline " + ob.deadlineLocal + " (" + ob.deadline + "), " + when + ". Applies: " + ob.applies + ". " + ob.why.join(" ") + " " + VERIFY_LINE,
      recommendation: "Confirm applicability with counsel, then notify " + ob.recipient + " and record the time sent.",
      controls: [{ framework: ob.regime, id: ob.citation }, ...CONTROLS_BASE],
      evidence: [{ obligation: ob.id, regime: ob.regime, recipient: ob.recipient, trigger: ob.triggerLocal, deadlineUtc: ob.deadline, deadlineLocal: ob.deadlineLocal, timeLeftHours: left, applies: ob.applies, confidence: ob.confidence, status: ob.status }],
      evidenceCount: 1,
      assets: [{ type: "INCIDENT", name: title || "Incident" }],
      tags: ["breach-notification", ob.regime],
    });
  }
  const rank = { critical: 0, high: 1, medium: 2 };
  findings.sort((x, y) => rank[x.severity] - rank[y.severity] || (x.id < y.id ? -1 : 1));
  return findings;
}

/** Human duration: "3 d 4 h", "5 h", "40 min". */
export function fmtDur(h) {
  if (h == null || !Number.isFinite(h)) return "";
  const m = Math.round(Math.abs(h) * 60);
  if (m < 60) return m + " min";
  const d = Math.floor(m / 1440), hh = Math.floor((m % 1440) / 60);
  return d ? d + " d " + hh + " h" : hh + " h " + (m % 60 ? (m % 60) + " min" : "").trim();
}

/**
 * Deck entry point. dataset = incident record {facts, statuses}, bare facts, or
 * parseInput rows. Returns { summary, findings, tables, skipped, meta, assessment }.
 */
export function analyze(dataset, opts = {}, ctx) {
  let rec = null;
  if (Array.isArray(dataset)) {
    rec = dataset.map(asRecord).find(Boolean) || null;
    const counts = dataset.filter((r) => r && r._counts);
    if (!rec && counts.length) rec = { facts: { counts } };
  } else rec = asRecord(dataset);
  ctx?.progress?.(0, 1, "assess");
  const facts = (rec && rec.facts) || {};
  const a = assess(facts, { ...opts, statuses: { ...((rec && rec.statuses) || {}), ...(opts.statuses || {}) } });
  const findings = toFindings(a, a.facts.title || "Incident");
  ctx?.progress?.(1, 1, "assess");
  const bySeverity = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  return {
    summary: { obligations: a.obligations.length, likely: a.counts.likely, possible: a.counts.possible, notIndicated: a.counts.notIndicated, overdue: a.counts.overdue, findings: findings.length, bySeverity, missing: a.missing.length },
    findings,
    tables: { obligations: a.obligations, timeline: a.timeline, checklist: a.checklist, missing: a.missing, jurisdictions: a.jurisdictions },
    skipped: a.skipped,
    meta: { tool: TOOL_ID, version: VERSION, rows: a.obligations.length, now: a.now, timeZone: a.timeZone, reference: a.reference, verify: VERIFY_LINE },
    assessment: a,
  };
}

const q = (v) => { let s = String(v ?? ""); if (/^[=+@\t\r-]/.test(s) && !/^-\d+(\.\d+)?$/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; }; // a leading = + - @ would run as a spreadsheet formula
const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "evidenceCount"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const body = (findings || []).map((f) => [f.severity, f.confidence, f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length].map(q).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n");
}

/** Checklist as CSV. */
export function checklistToCsv(checklist) {
  const head = ["obligation_id", "obligation", "step", "owner", "done"];
  return [head.join(","), ...(checklist || []).map((c) => [c.obligationId, c.obligation, c.step, c.owner || "", c.done ? "yes" : "no"].map(q).join(","))].join("\n");
}

/** Calendar events (for core/export.js toIcs) for every applicable, open, fixed deadline. */
export function icsEvents(a, title) {
  const stamp = a.now || a.timeline.map((x) => x.deadline)[0] || "2000-01-01T00:00:00.000Z";
  const byId = Object.fromEntries(a.obligations.map((o) => [o.id, o]));
  return a.timeline.filter((x) => x.status !== "sent" && x.status !== "not-required").map((x) => {
    const ob = byId[x.id];
    return {
      uid: TOOL_ID + "-" + x.id + "-" + x.deadline.replace(/[^0-9]/g, "").slice(0, 12) + "@darknode.ai",
      start: x.deadline, end: new Date(Date.parse(x.deadline) + 30 * 60000).toISOString(), stamp,
      summary: "Deadline: " + ob.regime + " to " + ob.recipient + (title ? " (" + title + ")" : ""),
      description: ob.citation + " - " + ob.clock + ". Applies: " + ob.applies + ". Local: " + ob.deadlineLocal + ". " + VERIFY_LINE + " Source: " + ob.sourceUrl,
    };
  });
}

/** Re-importable obligations export. */
export function exportBundle(record, a) {
  return { tool: TOOL_ID, version: VERSION, exportedAt: a.now, verify: VERIFY_LINE, reference: a.reference, incident: record, obligations: a.obligations, timeline: a.timeline, missing: a.missing };
}

/** Plain-text summary. */
export function summaryText(a, title) {
  const L = [];
  L.push("Breach Clock summary: " + (title || a.facts.title || "Untitled incident"));
  L.push(VERIFY_LINE);
  L.push("As of " + (a.now || "unknown") + " (UTC). Incident time zone " + a.timeZone + ".");
  if (a.reference.breachLaws) L.push("Reference data " + a.reference.breachLaws + " (US breach laws), verify with counsel.");
  L.push("Obligations: " + a.counts.likely + " likely, " + a.counts.possible + " possible, " + a.counts.notIndicated + " not indicated. Overdue: " + a.counts.overdue + ".");
  L.push("");
  L.push("Deadlines:");
  for (const x of a.timeline) L.push("- " + x.deadlineLocal + " (" + x.deadline + ") " + x.regime + " -> " + x.recipient + " [" + x.applies + ", " + x.status + (x.timeLeftHours != null ? ", " + (x.timeLeftHours < 0 ? "overdue " : "left ") + fmtDur(x.timeLeftHours) : "") + "]");
  const nofixed = a.obligations.filter((o) => o.applies !== "not-indicated" && !o.deadline);
  if (nofixed.length) { L.push(""); L.push("No fixed deadline:"); for (const o of nofixed) L.push("- " + o.regime + " -> " + o.recipient + ": " + o.clock + " [" + o.applies + "]"); }
  if (a.missing.length) { L.push(""); L.push("Facts still needed:"); for (const m of a.missing) L.push("- " + m.label + ": " + m.why); }
  return L.join("\n") + "\n";
}

/** Plain-text notification draft template for one obligation. */
export function draftNotice(ob, facts) {
  const F = normalizeFacts(facts);
  const tz = F.timeZone;
  const fmt = (v) => { const ms = parseTime(v, tz); return ms == null ? "[date]" : formatLocal(ms, tz); };
  const types = F.dataTypes.length ? F.dataTypes.map(typeLabel).join(", ") : "[categories of data]";
  const sum = F.counts.reduce((x, c) => x + c.count, 0);
  const n = F.total != null ? F.total.toLocaleString("en-US") : F.counts.length ? sum.toLocaleString("en-US") : "[number]";
  const code = (/^us-([A-Z]{2})-/.exec(ob.id || "") || [])[1];
  const mine = code ? F.counts.filter((c) => [lc(ob.jurisdiction), code.toLowerCase(), "us-" + code.toLowerCase()].includes(lc(c.jurisdiction))) : [];
  const stateCount = mine.length ? mine.reduce((x, c) => x + c.count, 0) : null;
  const L = [
    "TEMPLATE - review with counsel before sending. " + VERIFY_LINE,
    "",
    "To: " + ob.recipient,
    "Re: Notification of a security incident" + (F.title ? " - " + F.title : ""),
    "Basis: " + ob.citation,
    "",
    "1. What happened: [describe the incident]. The incident " + (F.occurredAt ? "occurred on or about " + fmt(F.occurredAt) + " and " : "") + "was discovered on " + fmt(F.discoveredAt) + (F.determinedAt ? " and confirmed on " + fmt(F.determinedAt) : "") + ".",
    "2. Information involved: " + types + ".",
    "3. Number of individuals affected: approximately " + n + (stateCount != null ? " (" + stateCount.toLocaleString("en-US") + " in " + ob.jurisdiction + ")" : "") + ".",
    "4. What we are doing: [containment, investigation, law-enforcement contact, measures to mitigate harm].",
    "5. What individuals can do: [steps such as password resets, credit freezes, monitoring offer].",
    "6. Contact: [name, role, email, phone].",
  ];
  if (/GDPR/.test(ob.regime)) L.push("7. Data protection officer: [DPO contact]. Likely consequences: [assessment]. If later than 72 hours, reasons for the delay: [reasons].");
  if (ob.id === "sec-8k") L.push("7. Item 1.05: material aspects of the nature, scope and timing of the incident, and its material impact or reasonably likely material impact on the registrant.");
  return L.join("\n") + "\n";
}

/** Synthetic example: a US SaaS company with EU customers (fictional names). */
export function exampleDataset(seed = 7, now = "2026-10-16T15:00:00.000Z") {
  const base = Date.parse(now);
  const tz = "America/Chicago";
  const local = (ms) => { const p = tzParts(ms, tz); return p.y + "-" + pad(p.m) + "-" + pad(p.d) + "T" + pad(p.h) + ":" + pad(p.mi); };
  const jitter = (seed % 5) * 60000 * 7;
  const discovered = base - 48 * HOUR - jitter;
  return {
    label: "synthetic example (not real data)",
    record: {
      id: "bnc-example",
      title: "Test Org credential store exposure (synthetic)",
      status: "open",
      facts: {
        title: "Test Org credential store exposure (synthetic)",
        sectors: ["eu", "general"], memberState: "Ireland",
        dataTypes: ["emailpw", "ssn"],
        total: null,
        counts: [{ jurisdiction: "California", count: 1200 }, { jurisdiction: "Texas", count: 600 }, { jurisdiction: "New York", count: 300 }, { jurisdiction: "Germany", count: 450 }, { jurisdiction: "Ireland", count: 120 }],
        encrypted: "no", harm: "high", nis2Significant: "unknown",
        timeZone: tz,
        occurredAt: local(discovered - 5 * DAY),
        discoveredAt: local(discovered),
        determinedAt: local(discovered + 18 * HOUR),
        materialityAt: "", ransomPaidAt: "",
        leDelay: { requested: false, from: "", until: "", agDetermination: false },
      },
      statuses: {},
      notes: "Synthetic incident for the example. Contact: ir-lead@test.darknode.ai",
    },
  };
}

// ---------------------------------------------------------------------------
// Register (core/register.js) schema: one record per incident.
// record = { id, title, status: open|notified|closed, facts, statuses, notes,
//            obligationCount, overdueCount, due24hCount, due72hCount, nextDeadline }
// ---------------------------------------------------------------------------

export const INCIDENT_STATUSES = ["open", "notified", "closed"];

export const REGISTER_SCHEMA = {
  key: "id",
  name: (r) => String(r.title || (r.facts && r.facts.title) || "Untitled incident"),
  severity: (r) => (r.status === "closed" ? null : r.overdueCount > 0 ? "critical" : r.due24hCount > 0 ? "high" : r.due72hCount > 0 ? "medium" : null),
  status: (r) => ({ open: "open", notified: "investigating", closed: "closed" }[r.status] || "open"),
  summary: (r) => ({ title: r.title || "", incidentStatus: r.status || "open", nextDeadline: r.nextDeadline || null, overdue: r.overdueCount || 0, obligations: r.obligationCount || 0, sectors: ((r.facts && r.facts.sectors) || []).join(", ") }),
  columns: [
    { key: "id", label: "ID" }, { key: "title", label: "Incident" }, { key: "status", label: "Status" },
    { key: "nextDeadline", label: "Next deadline (UTC)" }, { key: "overdueCount", label: "Overdue" }, { key: "obligationCount", label: "Obligations" },
    { key: "updatedAt", label: "Updated" },
  ],
};

/** Copy an incident record with the assessment's roll-up fields filled in. */
export function snapshot(record, a) {
  const r = { ...(record || {}) };
  r.title = r.title || (r.facts && r.facts.title) || "Untitled incident";
  r.status = INCIDENT_STATUSES.includes(r.status) ? r.status : "open";
  r.statuses = r.statuses && typeof r.statuses === "object" ? r.statuses : {};
  r.obligationCount = a.counts.likely + a.counts.possible;
  r.overdueCount = a.counts.overdue;
  r.due24hCount = a.counts.due24h;
  r.due72hCount = a.counts.due72h;
  r.nextDeadline = a.nextDeadline ? a.nextDeadline.deadline : null;
  return r;
}

/** Real deterministic checks of the engine. */
export function selfTest() {
  const tests = [];
  const add = (name, fn) => { let pass = false; try { pass = !!fn(); } catch (_) { pass = false; } tests.push({ name, pass }); };
  add("GDPR 72 hours from discovery", () => {
    const a = assess({ sectors: ["eu"], discoveredAt: "2026-03-02T10:00:00Z", dataTypes: ["emailpw"], encrypted: "no", harm: "risk" }, { now: "2026-03-02T12:00:00Z" });
    return a.obligations.find((o) => o.id === "gdpr-33").deadline === "2026-03-05T10:00:00.000Z";
  });
  add("SEC 4 business days skip a weekend", () => {
    const a = assess({ sectors: ["sec"], discoveredAt: "2026-10-14T12:00:00Z", materialityAt: "2026-10-15T14:00:00Z" }, { now: "2026-10-15T15:00:00Z", holidays: ["2026-11-26"] });
    return a.obligations.find((o) => o.id === "sec-8k").deadline === "2026-10-21T21:30:00.000Z";
  });
  add("state regulator threshold below / above", () => {
    const laws = [{ jurisdiction: "Testland", code: "TL", statute: "T", deadlineDays: 30, deadlineText: "30 days after discovery", agDeadlineDays: 30, agThreshold: 500, creditBureauThreshold: null, substituteNoticeAllowed: true, riskOfHarmTrigger: false, piiDefinitionNotes: "Name plus SSN.", confidence: "curated", sourceUrl: "https://x" }];
    const f = (n) => assess({ discoveredAt: "2026-01-01T00:00:00Z", dataTypes: ["ssn"], encrypted: "no", counts: [{ jurisdiction: "TL", count: n }] }, { now: "2026-01-02T00:00:00Z", breachLaws: laws }).obligations.find((o) => o.id === "us-TL-regulator").applies;
    return f(499) === "not-indicated" && f(501) === "likely";
  });
  add("analyze is deterministic", () => { const ex = exampleDataset(); return JSON.stringify(analyze(ex.record, { now: "2026-10-16T15:00:00Z" })) === JSON.stringify(analyze(ex.record, { now: "2026-10-16T15:00:00Z" })); });
  add("empty input yields no findings", () => analyze({}).findings.length === 0);
  return { pass: tests.every((x) => x.pass), tests };
}
