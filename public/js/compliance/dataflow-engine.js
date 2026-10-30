// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Data Inventory & Processing Register engine (dataflow). Pure ESM: no DOM, no
// network, no clock (the current time is always passed in as opts.now), so it
// runs in a Blob Worker and in node tests and gives byte-identical output for
// the same input.
//
// Two record types, both kept by the UI in core/register.js registers:
//   - processing activities (the GDPR Art. 30 record)
//   - a DSAR log (data-subject requests, Art. 12(3) deadlines)
// analyze({ activities, dsars }, opts) scores them: Art. 30 completeness, lawful
// basis (Art. 6 / 9 / 10), retention (Art. 5(1)(e)), security (Art. 32), DPIA
// screening against the nine EDPB/WP29 WP248 rev.01 criteria (Art. 35),
// international transfers against the shipped adequacy reference file
// (Arts. 44-49), data minimisation (Art. 5(1)(c)) and DSAR deadlines.
// This is record-keeping support, not legal advice: verify with counsel.

import { sniff, parseCsv, iterJson, findColumn, normHeader } from "../ingest/parse.js";
import { toCsv } from "../core/export.js";
import { DETECTORS as DLP_DETECTORS, scan as dlpScan } from "../dataprotect/dlp-engine.js";

export const TOOL_ID = "dataflow";
export const VERSION = "1.0.0";

const str = (v) => (v == null ? "" : String(v)).trim();
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const uniq = (a) => [...new Set(a)];
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const pad = (n) => String(n).padStart(2, "0");

// ---------------------------------------------------------------------------
// Vocabularies
// ---------------------------------------------------------------------------

export const ROLES = [
  { id: "controller", label: "Controller" },
  { id: "joint-controller", label: "Joint controller" },
  { id: "processor", label: "Processor (on behalf of a controller)" },
];

export const LEGAL_BASES = [
  { id: "a", label: "Art. 6(1)(a) Consent" },
  { id: "b", label: "Art. 6(1)(b) Contract" },
  { id: "c", label: "Art. 6(1)(c) Legal obligation" },
  { id: "d", label: "Art. 6(1)(d) Vital interests" },
  { id: "e", label: "Art. 6(1)(e) Public task" },
  { id: "f", label: "Art. 6(1)(f) Legitimate interests" },
];

export const ART9_CONDITIONS = [
  { id: "a", label: "Art. 9(2)(a) Explicit consent" },
  { id: "b", label: "Art. 9(2)(b) Employment, social security and social protection law" },
  { id: "c", label: "Art. 9(2)(c) Vital interests (subject incapable of consent)" },
  { id: "d", label: "Art. 9(2)(d) Not-for-profit body, members only" },
  { id: "e", label: "Art. 9(2)(e) Manifestly made public by the data subject" },
  { id: "f", label: "Art. 9(2)(f) Legal claims or courts" },
  { id: "g", label: "Art. 9(2)(g) Substantial public interest (in law)" },
  { id: "h", label: "Art. 9(2)(h) Health or social care, occupational medicine" },
  { id: "i", label: "Art. 9(2)(i) Public health" },
  { id: "j", label: "Art. 9(2)(j) Archiving, research or statistics" },
];

/** Data subject categories. vulnerable = listed as vulnerable in WP248 rev.01 (criterion 7). */
export const SUBJECTS = [
  { id: "customers", label: "Customers", re: /\b(customers?|clients?|account holders?)\b/ },
  { id: "prospects", label: "Prospects and leads", re: /\b(prospects?|leads?|marketing contacts?)\b/ },
  { id: "website-visitors", label: "Website and app users", re: /\b(visitors?|website users?|app users?|end users?|users)\b/ },
  { id: "employees", label: "Employees", vulnerable: true, re: /\b(employees?|staff|workers?|personnel)\b/ },
  { id: "job-applicants", label: "Job applicants", re: /\b(applicants?|candidates?|recruit\w*)\b/ },
  { id: "contractors", label: "Contractors", re: /\b(contractors?|consultants?|freelancers?)\b/ },
  { id: "supplier-contacts", label: "Supplier and partner contacts", re: /\b(suppliers?|vendors?|partners?)\b/ },
  { id: "children", label: "Children", vulnerable: true, re: /\b(child(ren)?|minors?|pupils?|under ?1[3-8]s?)\b/ },
  { id: "patients", label: "Patients", vulnerable: true, re: /\bpatients?\b/ },
  { id: "elderly", label: "Elderly people", vulnerable: true, re: /\b(elderly|older (people|adults)|seniors?)\b/ },
  { id: "vulnerable-adults", label: "Other vulnerable people (e.g. asylum seekers, people with mental illness)", vulnerable: true, re: /\b(vulnerable|asylum|mental(ly)? ill\w*)\b/ },
  { id: "students", label: "Students", re: /\bstudents?\b/ },
  { id: "members", label: "Members and subscribers", re: /\b(members?|subscribers?)\b/ },
  { id: "public", label: "Members of the public", re: /\b(general public|members of the public|public)\b/ },
];

/**
 * Personal data categories. special = Art. 9(1), criminal = Art. 10, personal = data of a
 * highly personal nature that WP248 rev.01 criterion 4 names (financial, location,
 * communications). dlp = DLP detector ids (dataprotect/dlp-engine.js) that evidence the
 * category in a sample. `re` maps free text from imports to the category.
 */
const BASE_CATEGORIES = [
  { id: "racial-ethnic", label: "Racial or ethnic origin", special: true, re: /\b(race|racial|ethnic\w*)\b/ },
  { id: "political", label: "Political opinions", special: true, re: /\bpolitical\b/ },
  { id: "religious", label: "Religious or philosophical beliefs", special: true, re: /\b(religio\w*|philosophical beliefs?)\b/ },
  { id: "trade-union", label: "Trade union membership", special: true, re: /\b(trade[- ]?unions?|union membership)\b/ },
  { id: "genetic", label: "Genetic data", special: true, re: /\b(genetic|dna)\b/ },
  { id: "biometric", label: "Biometric data (for unique identification)", special: true, re: /\b(biometric\w*|fingerprints?|face ?(id|print|recognition)|facial)\b/ },
  { id: "health", label: "Health data", special: true, re: /\b(health|medical|sick(ness)?|disabilit\w*|allerg\w*)\b/ },
  { id: "sex-life", label: "Sex life or sexual orientation", special: true, re: /\b(sex(ual)? (life|orientation)|sexuality)\b/ },
  { id: "criminal", label: "Criminal convictions and offences", criminal: true, re: /\b(criminal|convictions?|offen[cs]es?|background checks?|dbs)\b/ },
  { id: "national-id", label: "National ID numbers (SSN, passport, tax ID)", dlp: ["ssn"], re: /\b(national (id|insurance)\w*|ssn|social security|passports?|tax (id|number))\b/ },
  { id: "payment-card", label: "Payment card data", personal: true, dlp: ["credit-card"], re: /\b(payment cards?|credit cards?|card numbers?|pan)\b/ },
  { id: "bank", label: "Bank account details", personal: true, dlp: ["iban"], re: /\b(bank\w*|iban|account numbers?|sort codes?)\b/ },
  { id: "credentials", label: "Account credentials", re: /\b(passwords?|credentials?|logins?)\b/ },
  { id: "online-id", label: "Online identifiers (IP address, cookie, device ID)", dlp: ["ipv4"], re: /\b(ip address\w*|cookies?|device ids?|online identifiers?)\b/ },
  { id: "comms", label: "Communications content", personal: true, re: /\b(communications? content|messages?|email content|call recordings?|chats?)\b/ },
  { id: "location", label: "Location data", personal: true, re: /\b(location|gps|geo\w*)\b/ },
  { id: "contact", label: "Contact details", dlp: ["email", "us-phone"], re: /\b(contact\w*|emails?|e-mail|phone|telephone|address(es)?)\b/ },
  { id: "financial", label: "Financial and transaction data", personal: true, re: /\b(financial|transactions?|salary|payroll|invoic\w*|purchase history)\b/ },
  { id: "employment", label: "Employment and HR records", re: /\b(employment|hr|performance|cvs?|resumes?|job history)\b/ },
  { id: "images", label: "Photos, video and CCTV", re: /\b(photos?\w*|cctv|video|images?)\b/ },
  { id: "usage", label: "Usage and behavioural data", re: /\b(usage|behaviou?r\w*|analytics|clickstream|telemetry)\b/ },
  { id: "demographic", label: "Demographics (age, gender, date of birth)", re: /\b(age|gender|date of birth|dob|demograph\w*)\b/ },
  { id: "identity", label: "Name and identifiers", re: /\b(names?|identif\w*|usernames?)\b/ },
];

/** Categories, seeded with every personal-data detector in the DLP engine so a sample scan always maps to a category. */
export const CATEGORIES = (() => {
  const out = BASE_CATEGORIES.map((c) => ({ ...c, dlp: c.dlp ? c.dlp.slice() : [] }));
  for (const d of DLP_DETECTORS) {
    if (d.kind !== "pii") continue;
    if (out.some((c) => c.dlp.includes(d.id))) continue;
    out.push({ id: "dlp-" + d.id, label: d.label, dlp: [d.id] });
  }
  return out;
})();
const CAT_BY_ID = Object.fromEntries(CATEGORIES.map((c) => [c.id, c]));
const SUBJ_BY_ID = Object.fromEntries(SUBJECTS.map((s) => [s.id, s]));
export const categoryLabel = (id) => (CAT_BY_ID[id] ? CAT_BY_ID[id].label : str(id));
export const subjectLabel = (id) => (SUBJ_BY_ID[id] ? SUBJ_BY_ID[id].label : str(id));
export const categoryKind = (id) => (CAT_BY_ID[id] ? (CAT_BY_ID[id].special ? "special" : CAT_BY_ID[id].criminal ? "criminal" : "general") : "custom");

/** The nine WP248 rev.01 criteria. derived = the engine can infer it from the record. */
export const DPIA_CRITERIA = [
  { id: "scoring", label: "Evaluation or scoring, including profiling and predicting" },
  { id: "automated-decision", label: "Automated decision-making with legal or similar significant effect" },
  { id: "monitoring", label: "Systematic monitoring" },
  { id: "sensitive", label: "Sensitive data or data of a highly personal nature", derived: true },
  { id: "large-scale", label: "Data processed on a large scale" },
  { id: "combining", label: "Matching or combining datasets" },
  { id: "vulnerable", label: "Data concerning vulnerable data subjects", derived: true },
  { id: "innovative", label: "Innovative use or applying new technological or organisational solutions" },
  { id: "prevents-rights", label: "Processing that prevents data subjects from exercising a right or using a service or contract" },
];

export const DPIA_STATUSES = [
  { id: "not-started", label: "Not started" },
  { id: "screening", label: "Screening" },
  { id: "in-progress", label: "In progress" },
  { id: "completed", label: "Completed" },
  { id: "not-needed", label: "Not needed (decision documented)" },
];

export const MECHANISMS = [
  { id: "adequacy", label: "Adequacy decision (Art. 45)" },
  { id: "scc-2021", label: "EU SCCs 2021 (Art. 46(2)(c))" },
  { id: "uk-idta", label: "UK IDTA or UK Addendum (UK GDPR Art. 46)" },
  { id: "bcr", label: "Binding Corporate Rules (Art. 47)" },
  { id: "codes-certification", label: "Code of conduct or certification (Art. 46(2)(e)/(f))" },
  { id: "ad-hoc-clauses", label: "Authorised ad hoc clauses (Art. 46(3)(a))" },
  { id: "derogations", label: "Art. 49 derogation" },
  { id: "none", label: "None" },
];
const ART46 = new Set(["scc-2021", "uk-idta", "bcr", "codes-certification", "ad-hoc-clauses"]);

export const DSAR_TYPES = [
  { id: "access", label: "Access", article: "Art.15" },
  { id: "rectification", label: "Rectification", article: "Art.16" },
  { id: "erasure", label: "Erasure", article: "Art.17" },
  { id: "restriction", label: "Restriction", article: "Art.18" },
  { id: "portability", label: "Portability", article: "Art.20" },
  { id: "objection", label: "Objection", article: "Art.21" },
];
const DSAR_BY_ID = Object.fromEntries(DSAR_TYPES.map((t) => [t.id, t]));

export const label = (list, id) => (list.find((x) => x.id === id) || { label: str(id) }).label;

/** Tunable thresholds (numbers). Non-numeric options: regime, clockStart, rollWeekends. */
export const DEFAULTS = {
  reviewMonths: 12,
  dpiaReviewMonths: 36,
  maxCategories: 10,
  dsarAtRiskDays: 7,
};

export const THRESHOLD_LABELS = {
  reviewMonths: ["Review each activity every (months)", "An activity whose last review is older than this is flagged. Your policy; 12 is a common internal cycle."],
  dpiaReviewMonths: ["Re-assess a completed DPIA after (months)", "WP248 rev.01 asks for DPIAs to be reviewed regularly; set your own cycle."],
  maxCategories: ["Data categories before a minimisation review", "An activity collecting more categories than this is flagged for a data-minimisation review (Art. 5(1)(c))."],
  dsarAtRiskDays: ["DSAR at risk within (days)", "An open request due within this many days is flagged as at risk."],
};

export const REGIMES = [
  { id: "eu", label: "EU GDPR" },
  { id: "uk", label: "UK GDPR" },
  { id: "both", label: "EU GDPR and UK GDPR" },
];

// ---------------------------------------------------------------------------
// Countries (ISO 3166-1 alpha-2). EEA = EU 27 + Iceland, Liechtenstein, Norway.
// ---------------------------------------------------------------------------

export const EEA = {
  AT: "Austria", BE: "Belgium", BG: "Bulgaria", HR: "Croatia", CY: "Cyprus", CZ: "Czechia", DK: "Denmark", EE: "Estonia", FI: "Finland",
  FR: "France", DE: "Germany", GR: "Greece", HU: "Hungary", IE: "Ireland", IT: "Italy", LV: "Latvia", LT: "Lithuania", LU: "Luxembourg",
  MT: "Malta", NL: "Netherlands", PL: "Poland", PT: "Portugal", RO: "Romania", SK: "Slovakia", SI: "Slovenia", ES: "Spain", SE: "Sweden",
  IS: "Iceland", LI: "Liechtenstein", NO: "Norway",
};
const OTHER_COUNTRIES = {
  GB: "United Kingdom", US: "United States", CH: "Switzerland", CA: "Canada", JP: "Japan", KR: "Republic of Korea", NZ: "New Zealand",
  IL: "Israel", AR: "Argentina", UY: "Uruguay", AD: "Andorra", FO: "Faroe Islands", GG: "Guernsey", IM: "Isle of Man", JE: "Jersey",
  GI: "Gibraltar", BR: "Brazil", IN: "India", CN: "China", PH: "Philippines", SG: "Singapore", AU: "Australia", ZA: "South Africa",
  MX: "Mexico", AE: "United Arab Emirates", HK: "Hong Kong", TW: "Taiwan", MY: "Malaysia", ID: "Indonesia", VN: "Vietnam", TR: "Turkey",
  RU: "Russia", UA: "Ukraine", NG: "Nigeria", KE: "Kenya", EG: "Egypt", SA: "Saudi Arabia", CO: "Colombia", CL: "Chile", PE: "Peru",
  PK: "Pakistan", BD: "Bangladesh", LK: "Sri Lanka", TH: "Thailand", RS: "Serbia", MA: "Morocco", QA: "Qatar", MK: "North Macedonia",
  AL: "Albania", BA: "Bosnia and Herzegovina", ME: "Montenegro", MD: "Moldova", GE: "Georgia", AM: "Armenia", BY: "Belarus",
};
export const COUNTRIES = { ...EEA, ...OTHER_COUNTRIES };
const COUNTRY_ALIASES = {
  uk: "GB", "great britain": "GB", britain: "GB", england: "GB", scotland: "GB", wales: "GB", "northern ireland": "GB",
  usa: "US", "u.s.": "US", "u.s.a.": "US", "united states of america": "US", america: "US",
  "south korea": "KR", korea: "KR", "republic of korea": "KR", holland: "NL", "czech republic": "CZ", el: "GR",
  turkiye: "TR", "türkiye": "TR", uae: "AE", "russian federation": "RU",
};

/** Normalise a destination (code or name) to { code, name }. "EU"/"EEA" -> code "EU". code "" when unknown. */
export function normCountry(v) {
  const raw = str(v);
  if (!raw) return { code: "", name: "" };
  const low = raw.toLowerCase().replace(/\s+/g, " ");
  if (/^(eu|eea|european union|european economic area|eu\/eea|eu member states?)$/.test(low)) return { code: "EU", name: "EU/EEA" };
  const up = raw.toUpperCase();
  if (/^[A-Z]{2}$/.test(up) && COUNTRIES[up]) return { code: up, name: COUNTRIES[up] };
  if (up === "UK") return { code: "GB", name: COUNTRIES.GB };
  if (up === "EL") return { code: "GR", name: COUNTRIES.GR };
  if (COUNTRY_ALIASES[low]) { const c = COUNTRY_ALIASES[low]; return { code: c, name: COUNTRIES[c] }; }
  for (const [c, n] of Object.entries(COUNTRIES)) if (n.toLowerCase() === low) return { code: c, name: n };
  return { code: "", name: raw };
}

// ---------------------------------------------------------------------------
// Dates (calendar arithmetic on YYYY-MM-DD, UTC, no clock)
// ---------------------------------------------------------------------------

const dim = (y, m) => new Date(Date.UTC(y, m, 0)).getUTCDate();
function dparts(s) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(str(s));
  if (!m) return null;
  const y = +m[1], mo = +m[2], d = +m[3];
  if (mo < 1 || mo > 12 || d < 1 || d > dim(y, mo)) return null;
  return { y, mo, d };
}
export const isDate = (s) => !!dparts(s);
const dayNum = (s) => { const p = dparts(s); return p ? Date.UTC(p.y, p.mo - 1, p.d) / 86400000 : NaN; };
const fromDayNum = (n) => new Date(n * 86400000).toISOString().slice(0, 10);
const ymd = (s) => (isDate(s) ? str(s).slice(0, 10) : "");

/** Add calendar months; a missing day clamps to the last day of the month (31 Jan + 1 month = 28/29 Feb). */
export function addMonths(s, n) {
  const p = dparts(s);
  if (!p) return "";
  const t = p.mo - 1 + Math.trunc(n);
  const y = p.y + Math.floor(t / 12);
  const mo = ((t % 12) + 12) % 12 + 1;
  return y + "-" + pad(mo) + "-" + pad(Math.min(p.d, dim(y, mo)));
}
export function addDays(s, n) { const v = dayNum(s); return Number.isFinite(v) ? fromDayNum(v + Math.trunc(n)) : ""; }
/** Whole days from a to b (b - a). NaN when either is not a date. */
export function daysBetween(a, b) { return dayNum(b) - dayNum(a); }
/** Saturday or Sunday moves to the following Monday. */
export function rollWeekend(s) {
  const v = dayNum(s);
  if (!Number.isFinite(v)) return "";
  const w = new Date(v * 86400000).getUTCDay();
  return w === 6 ? fromDayNum(v + 2) : w === 0 ? fromDayNum(v + 1) : fromDayNum(v);
}

const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, sept: 9, oct: 10, nov: 11, dec: 12 };
/** Guess D/M/Y vs M/D/Y from a column of slash dates: "dmy", "mdy" or "ambiguous". */
export function detectDateOrder(values) {
  let dmy = false, mdy = false;
  for (const v of values || []) {
    const m = /^(\d{1,2})[/.-](\d{1,2})[/.-](\d{2,4})/.exec(str(v));
    if (!m) continue;
    if (+m[1] > 12) dmy = true;
    if (+m[2] > 12) mdy = true;
  }
  return dmy && !mdy ? "dmy" : mdy && !dmy ? "mdy" : "ambiguous";
}
/** Parse an imported date to YYYY-MM-DD; "" when it cannot be read. order applies to slash dates. */
export function parseDate(v, order = "dmy") {
  const s = str(v);
  if (!s) return "";
  if (isDate(s)) return s.slice(0, 10);
  let m = /^(\d{1,2})[/.-](\d{1,2})[/.-](\d{2,4})\b/.exec(s);
  let y, mo, d;
  if (m) {
    y = +m[3]; if (y < 100) y += 2000;
    if (order === "mdy") { mo = +m[1]; d = +m[2]; } else { d = +m[1]; mo = +m[2]; }
  } else if ((m = /^(\d{1,2})\s+([A-Za-z]{3,})\.?,?\s+(\d{4})$/.exec(s))) { d = +m[1]; mo = MONTHS[m[2].slice(0, 3).toLowerCase()]; y = +m[3]; }
  else if ((m = /^([A-Za-z]{3,})\.?\s+(\d{1,2}),?\s+(\d{4})$/.exec(s))) { mo = MONTHS[m[1].slice(0, 3).toLowerCase()]; d = +m[2]; y = +m[3]; }
  else return "";
  if (!mo || mo > 12 || !d || d > dim(y, mo)) return "";
  return y + "-" + pad(mo) + "-" + pad(d);
}

/**
 * Read a retention period: "6 years", "18 months", "90 days", "2 weeks", "P6Y", "indefinite".
 * -> { months, days, indefinite, text } (months/days null when not machine-readable).
 */
export function parseRetention(v) {
  const text = str(v);
  const out = { months: null, days: null, indefinite: false, text };
  if (!text) return out;
  const low = text.toLowerCase();
  if (/\b(indefinite\w*|forever|permanent\w*|no limit|unlimited|perpetu\w*|never deleted|not defined|undefined)\b/.test(low)) { out.indefinite = true; return out; }
  let m = /^p(?:(\d+)y)?(?:(\d+)m)?(?:(\d+)w)?(?:(\d+)d)?$/i.exec(text.replace(/\s+/g, ""));
  if (m && (m[1] || m[2] || m[3] || m[4])) {
    const mo = (+m[1] || 0) * 12 + (+m[2] || 0), dd = (+m[3] || 0) * 7 + (+m[4] || 0);
    if (mo) out.months = mo;
    if (dd) out.days = dd;
    return out;
  }
  m = /(?<![\d.])(\d+(?:\.\d+)?)\s*(years?|yrs?|y|months?|mos?|m|weeks?|wks?|w|days?|d)\b/.exec(low); // lookbehind: one scan per digit run, not per digit
  if (!m) return out;
  const n = +m[1], u = m[2][0];
  if (u === "y") out.months = Math.round(n * 12);
  else if (u === "m") out.months = Math.round(n);
  else if (u === "w") out.days = Math.round(n * 7);
  else out.days = Math.round(n);
  return out;
}
function retentionEnd(start, r) {
  if (!isDate(start) || !r) return "";
  if (r.months != null) return addMonths(start, r.months);
  if (r.days != null) return addDays(start, r.days);
  return "";
}

// ---------------------------------------------------------------------------
// Free text -> vocabulary
// ---------------------------------------------------------------------------

function matchVocab(v, list, byId) {
  const s = str(v);
  if (!s) return "";
  if (byId[s]) return s;
  const low = s.toLowerCase();
  const exact = list.find((x) => x.label.toLowerCase() === low || x.id === low);
  if (exact) return exact.id;
  const hit = list.find((x) => x.re && x.re.test(low));
  return hit ? hit.id : s.slice(0, 120);
}
export const normCategory = (v) => matchVocab(v, CATEGORIES, CAT_BY_ID);
export const normSubject = (v) => matchVocab(v, SUBJECTS, SUBJ_BY_ID);

const LIST_RE = /[;|\n]+/;
const LIST_COMMA_RE = /[;|\n]+|,(?!\s*(?:inc|ltd|llc|gmbh|plc|limited|corp|s\.a|b\.v|pty|ag|sas|srl)\b)/i;
const toList = (v, re = LIST_RE) => (Array.isArray(v) ? v : str(v).split(re)).map(str).filter(Boolean);

/** Art. 6(1) letter from free text ("6(1)(f)", "f", "Legitimate interests") or "". */
export function parseLegalBasis(v) {
  const s = str(v).toLowerCase();
  if (!s) return "";
  let m = /6\s*\(\s*1\s*\)\s*\(\s*([a-f])\s*\)/.exec(s);
  if (m) return m[1];
  if ((m = /^\(?([a-f])\)?$/.exec(s))) return m[1];
  if (/legitimate/.test(s)) return "f";
  if (/consent/.test(s)) return "a";
  if (/contract/.test(s)) return "b";
  if (/legal obligation|statutory|required by law|legal requirement/.test(s)) return "c";
  if (/vital/.test(s)) return "d";
  if (/public task|public interest|official authority/.test(s)) return "e";
  return "";
}
/** Art. 9(2) letter from free text or "". */
export function parseArt9(v) {
  const s = str(v).toLowerCase();
  if (!s || /^(none|n\/a|no|not applicable|-)$/.test(s)) return "";
  let m = /9\s*\(\s*2\s*\)\s*\(\s*([a-j])\s*\)/.exec(s);
  if (m) return m[1];
  if ((m = /^\(?([a-j])\)?$/.exec(s))) return m[1];
  if (/explicit consent/.test(s)) return "a";
  if (/employment|social security|social protection/.test(s)) return "b";
  if (/vital/.test(s)) return "c";
  if (/not-for-profit|not for profit|foundation|association/.test(s)) return "d";
  if (/made public/.test(s)) return "e";
  if (/legal claims?|court/.test(s)) return "f";
  if (/substantial public interest/.test(s)) return "g";
  if (/public health/.test(s)) return "i";
  if (/health|social care|occupational|medical diagnosis/.test(s)) return "h";
  if (/archiv|research|statistic/.test(s)) return "j";
  return "";
}
/** Transfer mechanism id from free text or "". */
export function parseMechanism(v) {
  const s = str(v).toLowerCase();
  if (!s) return "";
  if (/\b(idta|uk addendum|international data transfer agreement)\b/.test(s)) return "uk-idta";
  if (/\b(sccs?|standard contractual)\b/.test(s)) return "scc-2021";
  if (/\b(bcrs?|binding corporate)\b/.test(s)) return "bcr";
  if (/code of conduct|certification/.test(s)) return "codes-certification";
  if (/ad hoc/.test(s)) return "ad-hoc-clauses";
  if (/derogation|art(icle)?\.?\s*49|explicit consent/.test(s)) return "derogations";
  if (/adequa|\bdpf\b|data privacy framework|data bridge/.test(s)) return "adequacy";
  if (/^(none|no|no safeguards?|n\/a)$/.test(s)) return "none";
  return "";
}
const yesNo = (v) => { const s = str(v).toLowerCase(); return /^(y|yes|true|1|certified|done|completed)$/.test(s) ? "yes" : /^(n|no|false|0|not certified)$/.test(s) ? "no" : ""; };

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

function normTransfer(t) {
  const x = t && typeof t === "object" ? t : { country: t };
  const c = normCountry(x.country);
  const mech = MECHANISMS.some((m) => m.id === x.mechanism) ? x.mechanism : parseMechanism(x.mechanism);
  return {
    country: c.code && c.code !== "EU" ? c.code : c.code === "EU" ? "EU" : c.name,
    recipient: str(x.recipient),
    mechanism: mech,
    dpfCertified: yesNo(x.dpfCertified) || (x.dpfCertified === true ? "yes" : x.dpfCertified === false ? "no" : ""),
    tia: x.tia === true || yesNo(x.tia) === "yes",
    notes: str(x.notes),
  };
}

/** Canonical activity record. Unknown values are left blank, never guessed. */
export function normalizeActivity(r) {
  const x = r && typeof r === "object" ? r : {};
  const uses = {};
  if (x.categoryUses && typeof x.categoryUses === "object") {
    for (const [k, v] of Object.entries(x.categoryUses)) if (str(v)) uses[normCategory(k)] = str(v);
  }
  const role = ROLES.some((o) => o.id === x.role) ? x.role : /joint/i.test(str(x.role)) ? "joint-controller" : /processor/i.test(str(x.role)) ? "processor" : /controller/i.test(str(x.role)) ? "controller" : "";
  const legalBasis = LEGAL_BASES.some((o) => o.id === x.legalBasis) ? x.legalBasis : parseLegalBasis(x.legalBasis);
  const art9Condition = ART9_CONDITIONS.some((o) => o.id === x.art9Condition) ? x.art9Condition : parseArt9(x.art9Condition);
  const dpiaStatus = DPIA_STATUSES.some((o) => o.id === x.dpiaStatus) ? x.dpiaStatus : (() => {
    const s = str(x.dpiaStatus).toLowerCase();
    if (!s) return "";
    if (/not (needed|required)|^no$|n\/a/.test(s)) return "not-needed";
    if (/complete|done|signed|approved|^yes$/.test(s)) return "completed";
    if (/progress|draft|ongoing/.test(s)) return "in-progress";
    if (/screen/.test(s)) return "screening";
    if (/not started|planned|to do|todo/.test(s)) return "not-started";
    return "";
  })();
  return {
    id: str(x.id),
    name: str(x.name),
    purpose: str(x.purpose),
    role,
    controllerName: str(x.controllerName),
    jointController: str(x.jointController),
    owner: str(x.owner),
    dataSubjects: uniq(toList(x.dataSubjects, LIST_COMMA_RE).map(normSubject)).sort(),
    dataCategories: uniq(toList(x.dataCategories, LIST_COMMA_RE).map(normCategory)).sort(),
    categoryUses: Object.fromEntries(Object.keys(uses).sort().map((k) => [k, uses[k]])),
    art9Condition,
    criminalBasis: str(x.criminalBasis),
    systems: uniq(toList(x.systems, LIST_COMMA_RE)).sort(cmp),
    recipients: uniq(toList(x.recipients, LIST_COMMA_RE)).sort(cmp),
    legalBasis,
    liaRef: str(x.liaRef),
    retention: str(x.retention),
    retentionTrigger: str(x.retentionTrigger),
    oldestRecord: ymd(x.oldestRecord),
    transfers: (Array.isArray(x.transfers) ? x.transfers : []).map(normTransfer).filter((t) => t.country || t.recipient),
    securityMeasures: str(x.securityMeasures),
    dpiaStatus,
    dpiaDate: ymd(x.dpiaDate),
    dpiaRef: str(x.dpiaRef),
    dpiaCriteria: uniq(toList(x.dpiaCriteria).filter((c) => DPIA_CRITERIA.some((d) => d.id === c && !d.derived))).sort(),
    subjectCount: str(x.subjectCount),
    lastReview: ymd(x.lastReview),
    notes: str(x.notes),
    createdAt: str(x.createdAt) || undefined,
    updatedAt: str(x.updatedAt) || undefined,
  };
}

/** Problems that block saving an activity (the form shows them). */
export function validateActivity(r) {
  const e = [];
  if (!str(r && r.name)) e.push("Activity name is required.");
  for (const k of ["oldestRecord", "dpiaDate", "lastReview"]) if (str(r && r[k]) && !isDate(r[k])) e.push(k + " must be a date (YYYY-MM-DD).");
  return e;
}

export function normalizeDsar(r) {
  const x = r && typeof r === "object" ? r : {};
  const tlow = str(x.type).toLowerCase();
  const type = DSAR_BY_ID[tlow] ? tlow : (DSAR_TYPES.find((t) => tlow.includes(t.id) || tlow.includes(t.label.toLowerCase())) || (/subject access|sar\b|copy/.test(tlow) ? DSAR_BY_ID.access : /delet|forget/.test(tlow) ? DSAR_BY_ID.erasure : /correct/.test(tlow) ? DSAR_BY_ID.rectification : /restrict/.test(tlow) ? DSAR_BY_ID.restriction : /port/.test(tlow) ? DSAR_BY_ID.portability : /object|opt.?out/.test(tlow) ? DSAR_BY_ID.objection : { id: tlow ? "other" : "" })).id;
  return {
    id: str(x.id),
    ref: str(x.ref),
    type,
    received: ymd(x.received),
    identityVerified: ymd(x.identityVerified),
    extended: x.extended === true || yesNo(x.extended) === "yes",
    extensionNotified: ymd(x.extensionNotified),
    completed: ymd(x.completed),
    owner: str(x.owner),
    notes: str(x.notes),
    createdAt: str(x.createdAt) || undefined,
    updatedAt: str(x.updatedAt) || undefined,
  };
}
export function validateDsar(r) {
  const e = [];
  if (!str(r && r.ref)) e.push("Reference is required (use your ticket number, not the requester's name).");
  if (!isDate(r && r.received)) e.push("Received date is required.");
  if (isDate(r && r.completed) && isDate(r && r.received) && daysBetween(r.received, r.completed) < 0) e.push("Completed date is before the received date.");
  return e;
}

const completeness = (a) => !!(a.purpose && a.dataSubjects.length && a.dataCategories.length && (a.role === "processor" || a.legalBasis) && a.retention && a.securityMeasures);

/** Register schema for openRegister("dataflow", "CONTROL"): each activity is an Art. 30 record. */
export const ACTIVITY_SCHEMA = {
  key: "id",
  name: (r) => "Processing activity: " + (str(r.name) || "Unnamed"),
  severity: () => null,
  status: () => null,
  summary: (r) => {
    const a = normalizeActivity(r);
    return {
      controlId: "Art.30", framework: "GDPR", title: a.name, implementation: completeness(a) ? "implemented" : "partial",
      purpose: a.purpose.slice(0, 300), role: a.role, legalBasis: a.legalBasis, systems: a.systems.slice(0, 30), recipients: a.recipients.slice(0, 30),
      dpiaStatus: a.dpiaStatus, owner: a.owner,
    };
  },
  columns: [
    { key: "id", label: "ID" }, { key: "name", label: "Activity" }, { key: "purpose", label: "Purpose" }, { key: "role", label: "Role" },
    { key: "legalBasis", label: "Lawful basis" }, { key: "dpiaStatus", label: "DPIA status" }, { key: "lastReview", label: "Last review" }, { key: "updatedAt", label: "Updated" },
  ],
};
/** Register schema for openRegister("dataflow-dsar", "CASE"). No requester names are stored. */
export const DSAR_SCHEMA = {
  key: "id",
  name: (r) => "DSAR " + (str(r.ref) || str(r.id)) + " (" + (label(DSAR_TYPES, r.type) || "request") + ")",
  severity: () => null,
  status: (r) => (isDate(r.completed) ? "closed" : "open"),
  summary: (r) => ({
    title: "DSAR " + str(r.ref), caseNumber: str(r.ref), owner: str(r.owner), state: isDate(r.completed) ? "closed" : "open",
    summary: label(DSAR_TYPES, r.type) + " request received " + str(r.received) + (isDate(r.completed) ? ", completed " + r.completed : ""),
  }),
  columns: [
    { key: "id", label: "ID" }, { key: "ref", label: "Reference" }, { key: "type", label: "Type" }, { key: "received", label: "Received" },
    { key: "completed", label: "Completed" }, { key: "updatedAt", label: "Updated" },
  ],
};

// ---------------------------------------------------------------------------
// DPIA screening (WP248 rev.01)
// ---------------------------------------------------------------------------

/** Screen one activity against the nine criteria. likely = 2 or more met (WP248 rule of thumb). */
export function screenDpia(rec) {
  const a = normalizeActivity(rec);
  const sens = a.dataCategories.filter((c) => CAT_BY_ID[c] && (CAT_BY_ID[c].special || CAT_BY_ID[c].criminal || CAT_BY_ID[c].personal));
  const vuln = a.dataSubjects.filter((s) => SUBJ_BY_ID[s] && SUBJ_BY_ID[s].vulnerable);
  const criteria = DPIA_CRITERIA.map((c) => {
    if (c.id === "sensitive") return { id: c.id, label: c.label, met: sens.length > 0, source: "derived", why: sens.length ? "categories: " + sens.map(categoryLabel).join(", ") : "" };
    if (c.id === "vulnerable") return { id: c.id, label: c.label, met: vuln.length > 0, source: "derived", why: vuln.length ? "data subjects: " + vuln.map(subjectLabel).join(", ") : "" };
    const met = a.dpiaCriteria.includes(c.id);
    return { id: c.id, label: c.label, met, source: "recorded", why: met ? "ticked on the record" : "" };
  });
  const count = criteria.filter((c) => c.met).length;
  return { criteria, count, likely: count >= 2 };
}

// ---------------------------------------------------------------------------
// Transfers (Chapter V) against the adequacy reference file
// ---------------------------------------------------------------------------

/** Build the adequacy lookups for a regime from the eu-adequacy.json envelope. */
export function adequacyIndex(env, regime) {
  const idx = new Map();
  if (!env || !Array.isArray(env.data)) return null;
  if (regime === "uk") {
    for (const c of Object.keys(EEA)) idx.set(c, { scope: "All transfers (EU/EEA)", limited: false, certifiedOnly: false, verify: false, source: "ukAdequacy" });
    const conf = str(env.ukAdequacy && env.ukAdequacy.confidence) === "verify";
    for (const d of (env.ukAdequacy && env.ukAdequacy.destinations) || []) {
      const ds = str(d);
      const base = ds.replace(/\s*\(.*$/, "").trim();
      const nc = normCountry(base);
      if (!nc.code || nc.code === "EU") continue;
      const scope = (/\((.*)\)/.exec(ds) || [])[1] || "All transfers";
      idx.set(nc.code, { scope, limited: /\(/.test(ds), certifiedOnly: nc.code === "US", verify: conf, source: "ukAdequacy" });
    }
    return idx;
  }
  for (const e of env.data) {
    const code = str(e.code).toUpperCase();
    if (!code) continue;
    const scope = str(e.scope);
    idx.set(code, {
      scope, limited: !/^all transfers\b/i.test(scope), proposed: /^proposed\b/i.test(scope), certifiedOnly: code === "US",
      verify: str(e.confidence) === "verify", decisionDate: str(e.decisionDate), source: "data",
    });
  }
  return idx;
}

/** Assess one transfer under one regime -> { status: n/a|ok|review|gap, note, issues[] }. */
export function assessTransfer(t, idx, regime) {
  const tr = normTransfer(t);
  const law = regime === "uk" ? "UK GDPR" : "GDPR";
  const home = regime === "uk" ? new Set(["GB"]) : new Set(Object.keys(EEA).concat(["EU"]));
  const code = /^[A-Z]{2}$/.test(tr.country) ? tr.country : "";
  const name = code ? (code === "EU" ? "EU/EEA" : COUNTRIES[code] || code) : tr.country;
  const issues = [];
  if (!code) {
    issues.push({ check: "transfer-unknown-country", severity: "low", confidence: "review", title: "Transfer destination not recognised",
      description: "\"" + tr.country + "\" is not a country this tool recognises, so the transfer could not be assessed under " + law + " Chapter V.",
      recommendation: "Record the destination as a country name or ISO code (for example US, IN, Philippines).", ctl: ["Art.44"] });
    return { status: "review", note: "destination not recognised", name, issues };
  }
  if (home.has(code) || (regime === "uk" && code === "EU") || (regime !== "uk" && code === "EU")) {
    if (regime === "uk" && (code === "EU" || EEA[code])) return { status: "ok", note: "EU/EEA: adequate under UK GDPR", name, issues };
    return { status: "n/a", note: regime === "uk" ? "domestic (UK)" : "within the EU/EEA, not a Chapter V transfer", name, issues };
  }
  const ad = idx ? idx.get(code) : null;
  const adequate = !!(ad && !ad.proposed);
  const m = tr.mechanism;
  const who = tr.recipient ? " (" + tr.recipient + ")" : "";
  if (code === "US" && adequate && (m === "adequacy" || m === "" || m === "none")) {
    if (tr.dpfCertified === "yes") return { status: "ok", note: "US recipient recorded as certified under the " + (regime === "uk" ? "UK Extension to the EU-US DPF" : "EU-US Data Privacy Framework"), name, issues };
    if (tr.dpfCertified === "no") {
      issues.push({ check: "transfer-us-not-dpf", severity: "high", confidence: "likely", title: "US transfer relies on adequacy but the recipient is not DPF-certified",
        description: "The US adequacy decision covers only organisations certified under the EU-US Data Privacy Framework" + (regime === "uk" ? " (UK Extension)" : "") + ". " + name + who + " is recorded as not certified, and no other mechanism is recorded.",
        recommendation: "Put SCCs" + (regime === "uk" ? " with the UK Addendum, or the IDTA," : "") + " plus a transfer impact assessment in place, or confirm certification on dataprivacyframework.gov. Verify with counsel.", ctl: ["Art.44", "Art.45", "Art.46"] });
      return { status: "gap", note: "not DPF-certified", name, issues };
    }
    issues.push({ check: "transfer-us-dpf-unknown", severity: "medium", confidence: "review", title: "US transfer: DPF certification not recorded",
      description: "Adequacy for the US applies only to DPF-certified organisations. Whether " + (tr.recipient || "the recipient") + " is certified is not recorded.",
      recommendation: "Check the recipient on dataprivacyframework.gov (active certification covering this data type) and record it, or use SCCs. Verify with counsel.", ctl: ["Art.45"] });
    return { status: "review", note: "DPF certification unknown", name, issues };
  }
  if (!adequate && (m === "" || m === "none")) {
    issues.push({ check: "transfer-no-mechanism", severity: "high", confidence: "confirmed", title: "Transfer to a third country without a transfer mechanism",
      description: name + who + " has no " + law + " adequacy decision" + (ad && ad.proposed ? " (a decision is only proposed)" : "") + " in the reference data, and no Art. 46 safeguard or Art. 49 derogation is recorded.",
      recommendation: "Put an Art. 46 mechanism in place (SCCs" + (regime === "uk" ? " with the UK Addendum, or the IDTA" : "") + ", BCRs) with a transfer impact assessment, or stop the transfer. Verify with counsel.", ctl: ["Art.44", "Art.46"] });
    return { status: "gap", note: "no mechanism", name, issues };
  }
  if (!adequate && m === "adequacy") {
    issues.push({ check: "transfer-false-adequacy", severity: "high", confidence: "confirmed", title: "Transfer relies on adequacy that does not exist",
      description: "The record says \"adequacy\" for " + name + who + ", but the reference data lists no " + (ad && ad.proposed ? "adopted " : "") + law + " adequacy decision for it.",
      recommendation: "Replace with an Art. 46 safeguard (SCCs, BCRs) plus a transfer impact assessment. Verify with counsel.", ctl: ["Art.44", "Art.45", "Art.46"] });
    return { status: "gap", note: "no adequacy decision", name, issues };
  }
  if (adequate && (m === "" || m === "adequacy" || m === "none")) {
    if (ad.limited) {
      issues.push({ check: "transfer-adequacy-scope", severity: "low", confidence: "review", title: "Adequacy decision has a limited scope",
        description: "The " + law + " adequacy for " + name + " covers: " + ad.scope + ". Whether " + (tr.recipient || "the recipient") + " falls inside that scope is not recorded.",
        recommendation: "Confirm the recipient is within the decision's scope; otherwise use SCCs. Verify with counsel.", ctl: ["Art.45"] });
      return { status: "review", note: "adequacy (limited scope)", name, issues };
    }
    return { status: "ok", note: "adequacy" + (ad.verify ? " (reference marked verify)" : ""), name, issues };
  }
  if (m === "derogations") {
    issues.push({ check: "transfer-derogation", severity: "medium", confidence: "review", title: "Recurring transfer relies on an Art. 49 derogation",
      description: "Art. 49 derogations are for occasional, specific situations (EDPB Guidelines 2/2018). A documented processing activity sending data to " + name + who + " is usually systematic.",
      recommendation: "Confirm the transfer is occasional; otherwise move to an Art. 46 safeguard. Verify with counsel.", ctl: ["Art.49"] });
    return { status: "review", note: "Art. 49 derogation", name, issues };
  }
  if (regime === "uk" && m === "scc-2021") {
    issues.push({ check: "transfer-uk-scc-only", severity: "medium", confidence: "likely", title: "UK transfer recorded on EU SCCs alone",
      description: "For UK GDPR transfers the EU SCCs need the ICO UK Addendum (or use the IDTA). Only EU SCCs are recorded for " + name + who + ".",
      recommendation: "Record the UK Addendum or the IDTA, or put one in place. Verify with counsel.", ctl: ["Art.46"] });
    return { status: "review", note: "EU SCCs without UK Addendum", name, issues };
  }
  if (regime !== "uk" && m === "uk-idta") {
    issues.push({ check: "transfer-eu-idta", severity: "medium", confidence: "likely", title: "EU transfer recorded on a UK-only instrument",
      description: "The IDTA and UK Addendum are UK GDPR instruments. EU GDPR transfers to " + name + who + " need the EU SCCs or another Art. 46 safeguard.",
      recommendation: "Record the EU SCC module in use. Verify with counsel.", ctl: ["Art.46"] });
    return { status: "review", note: "UK instrument for an EU transfer", name, issues };
  }
  if (ART46.has(m) && !adequate && !tr.tia) {
    issues.push({ check: "transfer-no-tia", severity: "medium", confidence: "review", title: "Transfer impact assessment not recorded",
      description: label(MECHANISMS, m) + " is recorded for " + name + who + " but no transfer impact assessment (Schrems II, EDPB Recommendations 01/2020).",
      recommendation: "Carry out and record a transfer impact assessment, with supplementary measures where needed. Verify with counsel.", ctl: ["Art.46"] });
    return { status: "review", note: label(MECHANISMS, m) + ", no TIA", name, issues };
  }
  return { status: "ok", note: label(MECHANISMS, m), name, issues };
}

// ---------------------------------------------------------------------------
// DSAR deadlines (Art. 12(3))
// ---------------------------------------------------------------------------

/**
 * Deadlines for one request. One calendar month from the clock start, or three when
 * extended (one month plus two further months). clockStart "receipt" (default) or
 * "identity" (start when identity was verified, where recorded). rollWeekends moves a
 * deadline that falls on Saturday or Sunday to Monday (public holidays are not modelled).
 */
export function dsarDue(rec, { clockStart = "receipt", rollWeekends = true } = {}) {
  const r = normalizeDsar(rec);
  if (!isDate(r.received)) return { start: "", baseDue: "", extendedDue: "", due: "" };
  const start = clockStart === "identity" && isDate(r.identityVerified) && r.identityVerified > r.received ? r.identityVerified : r.received;
  const roll = (d) => (rollWeekends ? rollWeekend(d) : d);
  const baseDue = roll(addMonths(start, 1));
  const extendedDue = roll(addMonths(start, 3));
  return { start, baseDue, extendedDue, due: r.extended ? extendedDue : baseDue };
}

function median(nums) {
  const a = nums.filter(Number.isFinite).slice().sort((x, y) => x - y);
  if (!a.length) return null;
  const m = a.length >> 1;
  return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2;
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

function newestDate(acts, dsars) {
  let best = "";
  for (const a of acts) for (const d of [a.lastReview, a.dpiaDate, a.oldestRecord, ymd(a.updatedAt)]) if (isDate(d) && d > best) best = d;
  for (const r of dsars) for (const d of [r.received, r.identityVerified, r.completed, r.extensionNotified]) if (isDate(d) && d > best) best = d;
  return best;
}

const ISO27001 = { framework: "ISO 27001:2022", id: "A.5.34" };
const ISO27701 = (id) => ({ framework: "ISO/IEC 27701:2019", id });
function ctlFor(regime, ids, extra = []) {
  const out = [];
  for (const id of ids) {
    if (regime !== "uk") out.push({ framework: "GDPR", id });
    if (regime !== "eu") out.push({ framework: "UK GDPR", id });
  }
  return out.concat(extra, [ISO27001]);
}
const vendorKey = (s) => str(s).toLowerCase().replace(/[.,]/g, " ").replace(/\b(inc|ltd|llc|gmbh|plc|limited|corp|corporation|co|s a|b v|pty|ag|sas|srl)\b/g, "").replace(/\s+/g, " ").trim();
const INTERNAL_RE = /\b(internal|staff|team|department|dept|authorit\w*|hmrc|irs|regulator\w*|police|courts?|none|n\/a|pension|auditors?|insurers?|tax)\b/i;

/**
 * analyze({ activities, dsars }, opts) -> { summary, findings, tables, skipped, meta }
 * opts: now (ISO), regime eu|uk|both, clockStart receipt|identity, rollWeekends, adequacy
 * (eu-adequacy.json envelope), org { name, contact, dpo, representative }, knownVendors
 * (names from the vendor register / graph), plus DEFAULTS.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...opts };
  const regime = ["eu", "uk", "both"].includes(o.regime) ? o.regime : "eu";
  const clockStart = o.clockStart === "identity" ? "identity" : "receipt";
  const rollWeekends = o.rollWeekends !== false;
  const ds = Array.isArray(dataset) ? { activities: dataset } : dataset || {};
  const acts = (ds.activities || ds.records || []).map((r, i) => { const a = normalizeActivity(r); if (!a.id) a.id = "act-" + (i + 1); return a; })
    .sort((a, b) => cmp(a.name.toLowerCase(), b.name.toLowerCase()) || cmp(a.id, b.id));
  const dsars = (ds.dsars || []).map((r, i) => { const d = normalizeDsar(r); if (!d.id) d.id = "dsar-" + (i + 1); return d; })
    .sort((a, b) => cmp(a.received, b.received) || cmp(a.ref, b.ref) || cmp(a.id, b.id));
  const skipped = [];
  const findings = [];
  let today = ymd(o.now);
  if (!today) {
    today = newestDate(acts, dsars);
    if (today) skipped.push({ check: "clock", reason: "no current time passed; dates measured against the newest date in the data (" + today + ")" });
    else if (acts.length || dsars.length) skipped.push({ check: "date-checks", reason: "no current time and no dates in the data; review, retention, DPIA-age and DSAR deadline checks not run" });
  }
  const regimes = regime === "both" ? ["eu", "uk"] : [regime];
  const idx = {};
  for (const rg of regimes) idx[rg] = adequacyIndex(o.adequacy, rg);
  const refInfo = o.adequacy && Array.isArray(o.adequacy.data) ? { version: str(o.adequacy.version), updated: str(o.adequacy.updated) } : null;
  const known = Array.isArray(o.knownVendors) ? new Set(o.knownVendors.map(vendorKey).filter(Boolean)) : null;
  const total = acts.length + dsars.length;

  const add = (check, key, f) => {
    const evidence = (f.evidence || []).slice(0, 50);
    findings.push({
      id: "dfr:" + check + ":" + key,
      title: f.title, severity: f.severity, confidence: f.confidence, category: f.category,
      description: f.description, recommendation: f.recommendation, controls: f.controls,
      evidence, evidenceCount: (f.evidence || []).length, assets: f.assets || [], tags: f.tags || [],
    });
  };
  const assetsOf = (a, recips) => a.systems.map((s) => ({ type: "ASSET", name: s })).concat((recips || []).filter((r) => !INTERNAL_RE.test(r)).map((r) => ({ type: "VENDOR", name: r }))).slice(0, 20);

  const tAct = [], tTransfers = [], tDpia = [];
  const catCount = new Map();
  let retentionNoDate = 0, transfersGap = 0, transfersReview = 0;
  const transferCtl = (ids) => ctlFor(regime, ids, [ISO27701("7.5.1")]);

  acts.forEach((a, i) => {
    if (i % 1000 === 0) ctx?.progress?.(i, total, "activities");
    const nm = a.name || "Unnamed activity";
    const ev = { activity: nm, role: label(ROLES, a.role) || "not set" };
    const isProc = a.role === "processor";
    const cats = a.dataCategories;
    for (const c of cats) catCount.set(c, (catCount.get(c) || 0) + 1);
    const special = cats.filter((c) => CAT_BY_ID[c] && CAT_BY_ID[c].special);
    const criminal = cats.filter((c) => CAT_BY_ID[c] && CAT_BY_ID[c].criminal);
    const before = findings.length;

    // Art. 30 completeness
    const missing = [];
    if (isProc) {
      if (!a.controllerName) missing.push("controller on whose behalf it is processed (Art. 30(2)(a))");
      if (!a.purpose) missing.push("categories of processing (Art. 30(2)(b))");
    } else {
      if (!a.purpose) missing.push("purposes (Art. 30(1)(b))");
      if (!a.dataSubjects.length) missing.push("categories of data subjects (Art. 30(1)(c))");
      if (!cats.length) missing.push("categories of personal data (Art. 30(1)(c))");
      if (!a.recipients.length) missing.push("categories of recipients, or \"none\" (Art. 30(1)(d))");
    }
    if (!a.role) missing.push("controller or processor role");
    if (missing.length) {
      add("ropa-incomplete", a.id, { title: "Article 30 record incomplete", severity: "medium", confidence: "confirmed", category: "record",
        description: nm + " is missing: " + missing.join("; ") + ".", recommendation: "Complete the record. Art. 30 requires these fields for every processing activity. Verify with counsel.",
        controls: ctlFor(regime, [isProc ? "Art.30(2)" : "Art.30(1)"], [ISO27701("7.2.8")]), evidence: [{ ...ev, missing: missing.join("; ") }], assets: assetsOf(a) });
    }

    if (!isProc) {
      if (!a.legalBasis) {
        add("no-legal-basis", a.id, { title: "No lawful basis recorded", severity: "high", confidence: "confirmed", category: "lawful-basis",
          description: nm + " has no Art. 6(1) lawful basis recorded.", recommendation: "Identify and record the lawful basis before processing; it cannot be swapped later. Verify with counsel.",
          controls: ctlFor(regime, ["Art.6(1)", "Art.5(1)(a)"], [ISO27701("7.2.2")]), evidence: [ev], assets: assetsOf(a) });
      }
      if (a.legalBasis === "a" && a.dataSubjects.includes("employees")) {
        add("consent-employees", a.id, { title: "Consent relied on for employee data", severity: "medium", confidence: "review", category: "lawful-basis",
          description: nm + " relies on consent for employees. Consent is rarely freely given where there is an imbalance of power (EDPB Guidelines 05/2020 on consent).",
          recommendation: "Check whether another basis (contract, legal obligation, legitimate interests) fits better. Verify with counsel.",
          controls: ctlFor(regime, ["Art.6(1)(a)", "Art.7"], [ISO27701("7.2.2")]), evidence: [{ ...ev, legalBasis: label(LEGAL_BASES, a.legalBasis), subjects: a.dataSubjects.map(subjectLabel).join("; ") }], assets: assetsOf(a) });
      }
      if (a.legalBasis === "f" && !a.liaRef) {
        add("li-no-lia", a.id, { title: "Legitimate interests without a recorded assessment", severity: "medium", confidence: "review", category: "lawful-basis",
          description: nm + " relies on legitimate interests but no legitimate interests assessment (purpose, necessity, balancing test) is referenced.",
          recommendation: "Carry out and link a legitimate interests assessment. Verify with counsel.",
          controls: ctlFor(regime, ["Art.6(1)(f)", "Art.5(2)"], [ISO27701("7.2.2")]), evidence: [ev], assets: assetsOf(a) });
      }
      if (special.length && !a.art9Condition) {
        add("art9-no-condition", a.id, { title: "Special category data without an Art. 9(2) condition", severity: "high", confidence: "confirmed", category: "lawful-basis",
          description: nm + " processes " + special.map(categoryLabel).join(", ") + " but no Art. 9(2) condition is recorded.",
          recommendation: "Record the Art. 9(2) condition (and, in the UK, the DPA 2018 Schedule 1 condition and appropriate policy document where needed), or stop collecting the data. Verify with counsel.",
          controls: ctlFor(regime, ["Art.9"], [ISO27701("7.2.2")]), evidence: [{ ...ev, special: special.map(categoryLabel).join("; ") }], assets: assetsOf(a) });
      }
      if (criminal.length && !a.criminalBasis) {
        add("art10-no-basis", a.id, { title: "Criminal offence data without a recorded Art. 10 basis", severity: "high", confidence: "confirmed", category: "lawful-basis",
          description: nm + " processes criminal convictions or offences data. Art. 10 allows this only under official authority or when authorised by law; no authorisation is recorded.",
          recommendation: "Record the legal authorisation (in the UK, the DPA 2018 Schedule 1 condition). Verify with counsel.",
          controls: ctlFor(regime, ["Art.10"]), evidence: [ev], assets: assetsOf(a) });
      }
    }

    // Retention
    const ret = parseRetention(a.retention);
    let retEnd = "";
    if (!a.retention) {
      add("retention-missing", a.id, { title: "No retention period", severity: isProc ? "low" : "medium", confidence: "confirmed", category: "retention",
        description: nm + " has no retention period recorded.", recommendation: "Set a retention period (or the criteria used to set it) and the event that starts it. Verify with counsel.",
        controls: ctlFor(regime, ["Art.5(1)(e)", isProc ? "Art.30(2)" : "Art.30(1)(f)"]), evidence: [ev], assets: assetsOf(a) });
    } else if (ret.indefinite) {
      add("retention-indefinite", a.id, { title: "Retention is indefinite", severity: "medium", confidence: "confirmed", category: "retention",
        description: nm + " keeps data \"" + a.retention + "\". Personal data may be kept no longer than necessary for the purpose.",
        recommendation: "Define a period or a deletion trigger and an erasure process. Verify with counsel.",
        controls: ctlFor(regime, ["Art.5(1)(e)"], [ISO27701("7.4.7")]), evidence: [{ ...ev, retention: a.retention }], assets: assetsOf(a) });
    } else if (ret.months != null || ret.days != null) {
      if (!a.oldestRecord) retentionNoDate++;
      else if (today) {
        retEnd = retentionEnd(a.oldestRecord, ret);
        if (retEnd && retEnd < today) {
          add("retention-overdue", a.id, { title: "Records held past their retention period", severity: "high", confidence: "likely", category: "retention",
            description: nm + ": the oldest record (" + a.oldestRecord + ") passed its " + a.retention + " retention on " + retEnd + ", " + daysBetween(retEnd, today) + " day(s) ago.",
            recommendation: "Delete or anonymise records past retention and check the deletion job runs. Verify with counsel.",
            controls: ctlFor(regime, ["Art.5(1)(e)"], [ISO27701("7.4.7")]), evidence: [{ ...ev, retention: a.retention, trigger: a.retentionTrigger, oldestRecord: a.oldestRecord, retentionEnded: retEnd, daysOver: daysBetween(retEnd, today) }], assets: assetsOf(a) });
        }
      }
    }

    // Security
    if (!a.securityMeasures) {
      add("no-security-measures", a.id, { title: "No security measures recorded", severity: "medium", confidence: "confirmed", category: "security",
        description: nm + " has no description of technical and organisational security measures.",
        recommendation: "Describe the measures (access control, encryption, logging, backups, testing). Verify with counsel.",
        controls: ctlFor(regime, ["Art.32", isProc ? "Art.30(2)(d)" : "Art.30(1)(g)"]), evidence: [ev], assets: assetsOf(a) });
    }

    // Review
    let nextReview = "";
    if (today) {
      if (a.lastReview) {
        nextReview = addMonths(a.lastReview, o.reviewMonths);
        if (nextReview < today) {
          add("review-overdue", a.id, { title: "Activity review overdue", severity: "low", confidence: "confirmed", category: "governance",
            description: nm + " was last reviewed " + a.lastReview + "; the " + o.reviewMonths + "-month review was due " + nextReview + ".",
            recommendation: "Review the record with its owner and update the last-review date.",
            controls: ctlFor(regime, ["Art.5(2)", "Art.30"], [ISO27701("7.2.8")]), evidence: [{ ...ev, lastReview: a.lastReview, due: nextReview, owner: a.owner }], assets: assetsOf(a) });
        }
      } else {
        nextReview = today;
        add("never-reviewed", a.id, { title: "Activity has no review date", severity: "low", confidence: "confirmed", category: "governance",
          description: nm + " has no last-review date recorded.", recommendation: "Review the record with its owner and record the date.",
          controls: ctlFor(regime, ["Art.5(2)", "Art.30"], [ISO27701("7.2.8")]), evidence: [{ ...ev, owner: a.owner }], assets: assetsOf(a) });
      }
    }

    // DPIA
    const scr = screenDpia(a);
    const met = scr.criteria.filter((c) => c.met);
    const dpiaDue = a.dpiaStatus === "completed" && a.dpiaDate ? addMonths(a.dpiaDate, o.dpiaReviewMonths) : "";
    tDpia.push({ id: a.id, activity: nm, criteria: met.map((c) => c.label).join("; "), count: scr.count, likely: scr.likely, status: label(DPIA_STATUSES, a.dpiaStatus) || "not recorded", date: a.dpiaDate, reviewDue: dpiaDue });
    if (!isProc && scr.likely) {
      const crit = met.map((c) => c.label + (c.why ? " (" + c.why + ")" : "")).join("; ");
      const dEv = [{ ...ev, criteriaMet: scr.count, criteria: crit, dpiaStatus: label(DPIA_STATUSES, a.dpiaStatus) || "not recorded", dpiaDate: a.dpiaDate }];
      if (a.dpiaStatus === "not-needed") {
        add("dpia-not-needed", a.id, { title: "DPIA marked not needed although " + scr.count + " WP248 criteria are met", severity: "medium", confidence: "review", category: "dpia",
          description: nm + " meets " + scr.count + " of the nine WP248 rev.01 criteria (" + met.map((c) => c.label).join("; ") + "). Two or more usually mean a DPIA is required; a decision not to carry one out must be documented with reasons.",
          recommendation: "Record why the processing is unlikely to result in high risk, or carry out a DPIA. Check your supervisory authority's Art. 35(4) list. Verify with counsel.",
          controls: ctlFor(regime, ["Art.35(1)", "Art.35(3)"], [ISO27701("7.2.5")]), evidence: dEv, assets: assetsOf(a) });
      } else if (a.dpiaStatus !== "completed") {
        add("dpia-required", a.id, { title: "DPIA likely required but not completed", severity: "high", confidence: "likely", category: "dpia",
          description: nm + " meets " + scr.count + " of the nine WP248 rev.01 criteria: " + crit + ". DPIA status: " + (label(DPIA_STATUSES, a.dpiaStatus) || "not recorded") + ".",
          recommendation: "Carry out the DPIA before (or alongside) the processing and consult the supervisory authority if high risk remains (Art. 36). Verify with counsel.",
          controls: ctlFor(regime, ["Art.35(1)", "Art.35(3)"], [ISO27701("7.2.5")]), evidence: dEv, assets: assetsOf(a) });
      }
    }
    if (!isProc && a.dpiaStatus === "completed") {
      if (!a.dpiaDate) {
        add("dpia-no-date", a.id, { title: "Completed DPIA has no date", severity: "low", confidence: "confirmed", category: "dpia",
          description: nm + ": the DPIA is marked completed but its date is not recorded, so its age cannot be checked.", recommendation: "Record the DPIA completion date and reference.",
          controls: ctlFor(regime, ["Art.35(11)"], [ISO27701("7.2.5")]), evidence: [ev], assets: assetsOf(a) });
      } else if (today && dpiaDue < today) {
        add("dpia-stale", a.id, { title: "DPIA due for re-assessment", severity: scr.likely ? "medium" : "low", confidence: "confirmed", category: "dpia",
          description: nm + ": DPIA completed " + a.dpiaDate + "; your " + o.dpiaReviewMonths + "-month re-assessment was due " + dpiaDue + ".",
          recommendation: "Review the DPIA against the current processing (Art. 35(11) requires review at least when the risk changes). Verify with counsel.",
          controls: ctlFor(regime, ["Art.35(11)"], [ISO27701("7.2.5")]), evidence: [{ ...ev, dpiaDate: a.dpiaDate, due: dpiaDue, dpiaRef: a.dpiaRef }], assets: assetsOf(a) });
      }
    }

    // Transfers
    a.transfers.forEach((t, ti) => {
      for (const rg of regimes) {
        if (!idx[rg]) continue;
        const res = assessTransfer(t, idx[rg], rg);
        if (res.status !== "n/a") {
          tTransfers.push({ activity: nm, regime: rg === "uk" ? "UK GDPR" : "EU GDPR", destination: res.name, recipient: t.recipient, mechanism: label(MECHANISMS, t.mechanism) || "not recorded", dpfCertified: t.dpfCertified, tia: t.tia ? "yes" : "no", status: res.status, note: res.note });
          if (res.status === "gap") transfersGap++; else if (res.status === "review") transfersReview++;
        }
        for (const is of res.issues) {
          add(is.check, a.id + ":" + ti + ":" + rg, { title: is.title + (regime === "both" ? (rg === "uk" ? " (UK GDPR)" : " (EU GDPR)") : ""), severity: is.severity, confidence: is.confidence, category: "transfer",
            description: nm + ": " + is.description, recommendation: is.recommendation,
            controls: ctlFor(rg, is.ctl, [ISO27701("7.5.1")]),
            evidence: [{ ...ev, destination: res.name, recipient: t.recipient, mechanism: label(MECHANISMS, t.mechanism) || "not recorded", dpfCertified: t.dpfCertified || "not recorded", tia: t.tia ? "yes" : "no", reference: refInfo ? "eu-adequacy.json " + refInfo.version : "" }],
            assets: (t.recipient ? [{ type: "VENDOR", name: t.recipient }] : []).concat(a.systems.map((s) => ({ type: "ASSET", name: s }))).slice(0, 20), tags: ["transfer", res.name] });
        }
      }
    });

    // Minimisation
    if (cats.length) {
      const noUse = cats.filter((c) => !a.categoryUses[c]);
      if (noUse.length) {
        add("min-no-use", a.id, { title: "Data categories without a stated use", severity: "low", confidence: "review", category: "minimisation",
          description: nm + " collects " + noUse.length + " of " + cats.length + " categories with no note of what each is used for: " + noUse.map(categoryLabel).join(", ") + ".",
          recommendation: "For each category, record the purpose it serves; stop collecting any that serve none.",
          controls: ctlFor(regime, ["Art.5(1)(c)", "Art.25"]), evidence: noUse.map((c) => ({ activity: nm, category: categoryLabel(c), kind: categoryKind(c), statedUse: "" })), assets: assetsOf(a) });
      }
      if (cats.length > o.maxCategories) {
        add("min-many-categories", a.id, { title: "Many data categories for one purpose", severity: "low", confidence: "review", category: "minimisation",
          description: nm + " collects " + cats.length + " categories (threshold " + o.maxCategories + ") for: " + (a.purpose || "an unstated purpose") + ".",
          recommendation: "Check each category is adequate, relevant and limited to what the purpose needs.",
          controls: ctlFor(regime, ["Art.5(1)(c)", "Art.25"]), evidence: cats.map((c) => ({ activity: nm, category: categoryLabel(c), statedUse: a.categoryUses[c] || "" })), assets: assetsOf(a) });
      }
    }

    // Recipients vs vendor register
    if (known) {
      const recips = uniq(a.recipients.concat(a.transfers.map((t) => t.recipient)).filter((r) => r && !INTERNAL_RE.test(r)));
      const missingV = recips.filter((r) => !known.has(vendorKey(r)));
      if (missingV.length) {
        add("recipient-not-in-register", a.id, { title: "Recipients not in the vendor register", severity: "low", confidence: "review", category: "vendors",
          description: nm + " shares data with " + missingV.join(", ") + ", which " + (missingV.length === 1 ? "is" : "are") + " not in the Third-Party Risk register or the Security Graph vendors.",
          recommendation: "Add each external recipient to the vendor register and confirm a data processing agreement (Art. 28) where it acts as a processor.",
          controls: ctlFor(regime, ["Art.28(1)"], [{ framework: "ISO 27001:2022", id: "A.5.19" }]), evidence: missingV.map((r) => ({ activity: nm, recipient: r })), assets: missingV.map((r) => ({ type: "VENDOR", name: r })) });
      }
    }

    tAct.push({
      id: a.id, activity: nm, role: label(ROLES, a.role) || "", legalBasis: label(LEGAL_BASES, a.legalBasis) || "", subjects: a.dataSubjects.length, categories: cats.length,
      special: special.length > 0, criminal: criminal.length > 0, dpiaCriteria: scr.count, dpiaLikely: scr.likely, dpiaStatus: label(DPIA_STATUSES, a.dpiaStatus) || "",
      transfers: a.transfers.length, retention: a.retention, retentionEnds: retEnd, nextReview, findings: findings.length - before,
    });
  });
  if (retentionNoDate) skipped.push({ check: "retention-overdue", reason: retentionNoDate + " activit" + (retentionNoDate === 1 ? "y has" : "ies have") + " a retention period but no oldest-record date, so records past retention cannot be checked" });
  if (acts.some((a) => a.transfers.length) && !refInfo) skipped.push({ check: "transfers", reason: "adequacy reference data (/data/ref/eu-adequacy.json) not loaded; transfers not assessed" });
  if (!known && acts.length) skipped.push({ check: "recipient-not-in-register", reason: "vendor register not available; recipients not cross-checked" });
  if (acts.length && o.org && typeof o.org === "object") {
    const miss = [];
    if (!str(o.org.name)) miss.push("name");
    if (!str(o.org.contact)) miss.push("contact details");
    if (miss.length) add("org-details", "org", { title: "Controller or processor details not set", severity: "low", confidence: "confirmed", category: "record",
      description: "The register has no organisation " + miss.join(" or ") + ". Art. 30(1)(a) and 30(2)(a) require the name and contact details (and the DPO and representative where applicable).",
      recommendation: "Fill in Settings > Organisation.", controls: ctlFor(regime, ["Art.30(1)(a)", "Art.30(2)(a)"]), evidence: [{ missing: miss.join(", ") }] });
  } else if (acts.length) skipped.push({ check: "org-details", reason: "organisation details not passed" });

  // DSARs
  const tDsar = [];
  const doneDays = [];
  let open = 0, overdue = 0, atRisk = 0, late = 0;
  dsars.forEach((r, i) => {
    if ((acts.length + i) % 1000 === 0) ctx?.progress?.(acts.length + i, total, "DSARs");
    const t = DSAR_BY_ID[r.type];
    const art = t ? t.article : "Art.15";
    const dd = dsarDue(r, { clockStart, rollWeekends });
    const ref = r.ref || r.id;
    const ev = { reference: ref, type: t ? t.label : r.type || "not recorded", received: r.received, clockStart: dd.start, due: dd.due, extended: r.extended ? "yes" : "no", extensionNotified: r.extensionNotified, completed: r.completed };
    const ctl = ctlFor(regime, ["Art.12(3)", art]);
    let status = "", daysLeft = null, toComplete = null;
    if (!r.received) {
      status = "no receipt date";
      add("dsar-no-date", r.id, { title: "DSAR has no receipt date", severity: "low", confidence: "confirmed", category: "dsar", description: "Request " + ref + " has no received date, so its deadline cannot be computed.",
        recommendation: "Record the date the request was received.", controls: ctl, evidence: [ev] });
    } else if (r.completed) {
      toComplete = daysBetween(r.received, r.completed);
      doneDays.push(toComplete);
      if (r.completed > dd.due) {
        status = "late"; late++;
        add("dsar-late", r.id, { title: "DSAR answered late", severity: "medium", confidence: "confirmed", category: "dsar",
          description: "Request " + ref + " (" + ev.type + ") was due " + dd.due + " and completed " + r.completed + ", " + daysBetween(dd.due, r.completed) + " day(s) late.",
          recommendation: "Review why it ran late; use the extension (with notice inside the first month) when a request is complex. Verify with counsel.", controls: ctl, evidence: [ev] });
      } else status = "on time";
    } else if (today) {
      open++;
      daysLeft = daysBetween(today, dd.due);
      if (daysLeft < 0) {
        status = "overdue"; overdue++;
        add("dsar-overdue", r.id, { title: "DSAR overdue", severity: "high", confidence: "confirmed", category: "dsar",
          description: "Request " + ref + " (" + ev.type + ", received " + r.received + ") was due " + dd.due + " and is " + (-daysLeft) + " day(s) overdue.",
          recommendation: "Respond now and tell the requester; record the reason for the delay. Verify with counsel.", controls: ctl, evidence: [{ ...ev, daysOverdue: -daysLeft }] });
      } else if (daysLeft <= o.dsarAtRiskDays) {
        status = "at risk"; atRisk++;
        const canExtend = !r.extended && today <= dd.baseDue;
        add("dsar-at-risk", r.id, { title: "DSAR due within " + o.dsarAtRiskDays + " days", severity: "medium", confidence: "confirmed", category: "dsar",
          description: "Request " + ref + " (" + ev.type + ") is due " + dd.due + " (" + daysLeft + " day(s) left).",
          recommendation: canExtend ? "Finish the response, or if the request is complex extend by up to two months and tell the requester why before " + dd.baseDue + ". Verify with counsel." : "Finish the response before " + dd.due + ".",
          controls: ctl, evidence: [{ ...ev, daysLeft }] });
      } else status = "open";
    } else { status = "open"; open++; }
    if (r.extended && r.received) {
      if (!r.extensionNotified) {
        add("dsar-extension-notice", r.id, { title: "Extension taken without a recorded notice", severity: "low", confidence: "review", category: "dsar",
          description: "Request " + ref + " was extended but the date the requester was told is not recorded. Art. 12(3) requires notice, with reasons, within one month of receipt.",
          recommendation: "Record when and how the requester was told of the extension.", controls: ctl, evidence: [ev] });
      } else if (r.extensionNotified > dd.baseDue) {
        add("dsar-extension-late", r.id, { title: "Extension notified after the first month", severity: "medium", confidence: "confirmed", category: "dsar",
          description: "Request " + ref + ": the extension was notified " + r.extensionNotified + ", after the one-month deadline of " + dd.baseDue + ". A late notice does not validly extend the deadline.",
          recommendation: "Notify extensions, with reasons, inside the first month. Verify with counsel.", controls: ctl, evidence: [ev] });
      }
    }
    tDsar.push({ id: r.id, reference: ref, type: ev.type, article: art, received: r.received, clockStart: dd.start, due: dd.due, extended: r.extended, completed: r.completed, status, daysLeft, daysToComplete: toComplete });
  });
  ctx?.progress?.(total, total, "done");

  findings.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || cmp(a.category, b.category) || cmp(a.id, b.id));
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySeverity[f.severity]++;
  const med = median(doneDays);
  const summary = {
    activities: acts.length, dsars: dsars.length, findings: findings.length, bySeverity,
    dpiaLikely: tDpia.filter((d) => d.likely).length,
    dpiaGaps: findings.filter((f) => f.category === "dpia" && f.severity !== "low").length,
    specialCategory: tAct.filter((x) => x.special || x.criminal).length,
    transfers: tTransfers.length, transfersGap, transfersReview,
    reviewsOverdue: findings.filter((f) => f.id.startsWith("dfr:review-overdue:") || f.id.startsWith("dfr:never-reviewed:")).length,
    dsarOpen: open, dsarOverdue: overdue, dsarAtRisk: atRisk, dsarLate: late, dsarMedianDays: med,
  };
  const categories = [...catCount].map(([c, n]) => ({ category: categoryLabel(c), kind: categoryKind(c), activities: n })).sort((a, b) => b.activities - a.activities || cmp(a.category, b.category));
  return {
    summary, findings,
    tables: { activities: tAct, transfers: tTransfers, dpia: tDpia, dsars: tDsar, categories },
    skipped,
    meta: { tool: TOOL_ID, version: VERSION, rows: total, activities: acts.length, dsars: dsars.length, now: today, regime, clockStart, rollWeekends, reference: refInfo },
  };
}

// ---------------------------------------------------------------------------
// DLP-assisted category suggestion
// ---------------------------------------------------------------------------

/** Scan a pasted sample with the DLP engine's personal-data detectors; returns categories found (values masked, never stored). */
export function suggestCategories(text) {
  const ids = CATEGORIES.flatMap((c) => c.dlp);
  const r = dlpScan(String(text || ""), { detectors: ids });
  const out = new Map();
  for (const f of r.findings) {
    const cat = CATEGORIES.find((c) => c.dlp.includes(f.id));
    if (!cat) continue;
    const e = out.get(cat.id) || { category: cat.id, label: cat.label, detectors: [], count: 0, examples: [] };
    e.count++;
    if (!e.detectors.includes(f.label)) e.detectors.push(f.label);
    if (e.examples.length < 3) e.examples.push(f.masked);
    out.set(cat.id, e);
  }
  return [...out.values()].sort((a, b) => b.count - a.count || cmp(a.category, b.category));
}

// ---------------------------------------------------------------------------
// Import (CSV / register JSON)
// ---------------------------------------------------------------------------

/** Activity CSV aliases. Includes the ICO "documentation template for controllers" headers and this tool's ROPA export. */
export const COLUMNS = {
  id: ["ID", "Record ID", "Activity ID"],
  name: ["Processing activity", "Activity", "Activity name", "Processing operation", "Process", "Name"],
  owner: ["Owner", "Business owner", "Business function", "Department"],
  purpose: ["Purposes of the processing", "Purpose of processing", "Purposes", "Purpose", "Categories of processing"],
  role: ["Role", "Controller or processor", "Controller/processor"],
  controllerName: ["Controller on whose behalf", "Controller name", "Name and contact details of controller", "Controller"],
  jointController: ["Joint controller", "Name and contact details of joint controller"],
  dataSubjects: ["Categories of data subjects", "Categories of individuals", "Data subjects", "Data subject categories"],
  dataCategories: ["Categories of personal data", "Personal data categories", "Data categories", "Personal data"],
  specialData: ["Special category data (Art. 9)", "Special category data", "Special categories"],
  art9Condition: ["Art. 9(2) condition", "Article 9 condition for processing special category data", "Article 9 basis for processing special category data", "Article 9 condition", "Special category condition"],
  criminalBasis: ["Art. 10 basis", "Article 10 basis", "Criminal offence data (Art. 10)", "Criminal offence data condition"],
  recipients: ["Categories of recipients", "Recipients", "Recipients / vendors", "Sub-processors (recipients)", "Processors"],
  transfers: ["Transfers to third countries", "Names of third countries or international organisations that personal data are transferred to", "Third countries", "International transfers", "Transfers"],
  transferSafeguards: ["Transfer safeguards", "Safeguards for exceptional transfers of personal data to third countries or international organisations", "Transfer mechanism", "Safeguards"],
  retention: ["Time limits for erasure", "Retention schedule", "Retention period", "Retention"],
  retentionTrigger: ["Retention trigger", "Retention starts"],
  oldestRecord: ["Oldest record", "Oldest record date", "Earliest record"],
  securityMeasures: ["Technical and organisational security measures", "General description of technical and organisational security measures", "Security measures", "TOMs"],
  legalBasis: ["Lawful basis (Art. 6)", "Article 6 lawful basis for processing personal data", "Lawful basis", "Legal basis"],
  liaRef: ["LIA reference", "Link to record of legitimate interests assessment", "Legitimate interests assessment", "LIA"],
  automated: ["Existence of automated decision-making, including profiling", "Automated decision-making", "Profiling"],
  dpiaRequired: ["Data Protection Impact Assessment required?", "DPIA required"],
  dpiaStatus: ["DPIA status", "Data Protection Impact Assessment progress", "DPIA progress"],
  dpiaDate: ["DPIA date", "DPIA completion date", "DPIA completed"],
  dpiaRef: ["DPIA reference", "Link to Data Protection Impact Assessment", "Link to DPIA"],
  systems: ["Systems", "Location of personal data", "Applications", "System"],
  subjectCount: ["Approximate number of data subjects", "Number of data subjects", "Volume"],
  lastReview: ["Last review", "Last reviewed", "Review date"],
  notes: ["Notes", "Comments"],
};
export const COLUMN_LABELS = {
  id: "Record ID", name: "Activity name", owner: "Owner / business function", purpose: "Purpose", role: "Controller or processor", controllerName: "Controller (for processor records)",
  jointController: "Joint controller", dataSubjects: "Data subjects", dataCategories: "Data categories", specialData: "Special category data", art9Condition: "Art. 9(2) condition",
  criminalBasis: "Art. 10 basis", recipients: "Recipients", transfers: "Third-country transfers", transferSafeguards: "Transfer safeguards", retention: "Retention period",
  retentionTrigger: "Retention trigger", oldestRecord: "Oldest record date", securityMeasures: "Security measures", legalBasis: "Lawful basis", liaRef: "LIA reference",
  automated: "Automated decisions / profiling", dpiaRequired: "DPIA required?", dpiaStatus: "DPIA status", dpiaDate: "DPIA date", dpiaRef: "DPIA reference", systems: "Systems",
  subjectCount: "Approx. number of data subjects", lastReview: "Last review", notes: "Notes",
};
export const DSAR_COLUMNS = {
  ref: ["Reference", "Request ID", "Ref", "Case ID", "Ticket", "Ticket ID"],
  type: ["Request type", "Type", "Right", "Right exercised"],
  received: ["Received", "Date received", "Received date", "Request date"],
  identityVerified: ["Identity verified", "ID verified", "Identity verified date", "Verified"],
  extended: ["Extended", "Extension taken", "Extension"],
  extensionNotified: ["Extension notified", "Extension notice sent", "Requester told of extension"],
  completed: ["Completed", "Date completed", "Completed date", "Response date", "Responded", "Closed"],
  owner: ["Owner", "Handler", "Assigned to"],
  notes: ["Notes", "Outcome", "Comments"],
};
export const DSAR_COLUMN_LABELS = {
  ref: "Reference", type: "Request type", received: "Received", identityVerified: "Identity verified", extended: "Extension taken",
  extensionNotified: "Extension notified", completed: "Completed", owner: "Owner", notes: "Notes",
};

function autoMapWith(headers, spec) {
  const mapping = {};
  const used = new Set();
  for (const [k, aliases] of Object.entries(spec)) {
    const h = findColumn(headers.filter((x) => !used.has(x)), aliases);
    if (h) { mapping[k] = h; used.add(h); }
  }
  return mapping;
}
/** Auto-map activity CSV headers. high = name or purpose, plus subjects and categories. */
export function autoMapActivities(headers) {
  const mapping = autoMapWith(headers, COLUMNS);
  const core = (mapping.name || mapping.purpose) ? 1 : 0;
  const n = core + (mapping.dataSubjects ? 1 : 0) + (mapping.dataCategories ? 1 : 0);
  return { mapping, confidence: n === 3 ? "high" : n === 2 ? "medium" : "low" };
}
export function autoMapDsars(headers) {
  const mapping = autoMapWith(headers, DSAR_COLUMNS);
  const n = (mapping.ref ? 1 : 0) + (mapping.type ? 1 : 0) + (mapping.received ? 1 : 0);
  return { mapping, confidence: n === 3 ? "high" : n === 2 ? "medium" : "low" };
}
const isDsarHeaders = (headers) => {
  const n = new Set(headers.map(normHeader));
  const has = (list) => list.some((a) => n.has(normHeader(a)));
  return has(DSAR_COLUMNS.received) && (has(DSAR_COLUMNS.type) || has(DSAR_COLUMNS.completed));
};

/** Parse "US (SCCs); India: SCCs" style cells into transfer objects. */
export function parseTransferCell(countries, safeguards) {
  const parts = toList(countries, LIST_RE);
  const one = parts.length === 1 ? parts : toList(countries, /[;|\n]+|,/);
  const out = [];
  const sg = str(safeguards);
  for (const p of one) {
    if (/^(none|n\/a|no|-|not applicable)$/i.test(p)) continue;
    const m = /^(.+?)\s*(?:\((.+)\)|[:–—-]\s*(.+))$/.exec(p);
    const country = m ? m[1] : p;
    const mech = parseMechanism(m ? (m[2] || m[3]) : "") || parseMechanism(sg);
    const dpf = /\bdpf\b|data privacy framework/i.test(p + " " + sg) ? "yes" : "";
    out.push({ country, mechanism: mech, dpfCertified: dpf, tia: /\b(tia|transfer impact)\b/i.test(p + " " + sg) });
  }
  return out;
}

/** Map CSV rows to activity records with a mapping { field: header }. Unknown values stay blank. */
export function csvToActivities(rows, mapping, { dateOrder = "dmy" } = {}) {
  const skipped = [];
  const records = [];
  const byKey = new Map();
  let merged = 0;
  // The ICO template writes "N/A" in cells that do not apply: read those as blank.
  const get = (r, k) => { const v = mapping[k] ? str(r[mapping[k]]) : ""; return /^(n\/a|not applicable)$/i.test(v) ? "" : v; };
  (rows || []).forEach((r, i) => {
    let name = get(r, "name");
    const purpose = get(r, "purpose");
    if (!name) name = [get(r, "owner"), purpose.slice(0, 60)].filter(Boolean).join(" - ");
    if (!name) { skipped.push({ check: "row " + (i + 2), reason: "no activity name or purpose" }); return; }
    const crit = [];
    const auto = get(r, "automated").toLowerCase();
    if (auto && !/^(no|none|n\/a|-|not applicable)/.test(auto)) { crit.push("scoring"); if (/legal|significant/.test(auto)) crit.push("automated-decision"); }
    let dpiaStatus = get(r, "dpiaStatus");
    if (!dpiaStatus && /^no/i.test(get(r, "dpiaRequired"))) dpiaStatus = "not-needed";
    const rec = normalizeActivity({
      id: get(r, "id"), name, purpose, owner: get(r, "owner"), role: get(r, "role") || (get(r, "controllerName") && !mapping.jointController ? "processor" : "controller"),
      controllerName: get(r, "controllerName"), jointController: get(r, "jointController"),
      dataSubjects: get(r, "dataSubjects"), dataCategories: [get(r, "dataCategories"), get(r, "specialData")].filter(Boolean).join("; "),
      art9Condition: get(r, "art9Condition"), criminalBasis: /^(no|none|n\/a|-)$/i.test(get(r, "criminalBasis")) ? "" : get(r, "criminalBasis"),
      recipients: get(r, "recipients"), transfers: parseTransferCell(get(r, "transfers"), get(r, "transferSafeguards")),
      retention: get(r, "retention"), retentionTrigger: get(r, "retentionTrigger"), oldestRecord: parseDate(get(r, "oldestRecord"), dateOrder),
      securityMeasures: get(r, "securityMeasures"), legalBasis: get(r, "legalBasis"), liaRef: get(r, "liaRef"),
      dpiaStatus, dpiaDate: parseDate(get(r, "dpiaDate"), dateOrder), dpiaRef: get(r, "dpiaRef"), dpiaCriteria: crit,
      systems: get(r, "systems"), subjectCount: get(r, "subjectCount"), lastReview: parseDate(get(r, "lastReview"), dateOrder), notes: get(r, "notes"),
    });
    if (get(r, "legalBasis") && !rec.legalBasis) skipped.push({ check: "row " + (i + 2), reason: "lawful basis \"" + get(r, "legalBasis") + "\" not recognised; left blank" });
    if (!rec.role) rec.role = "controller";
    if (!rec.id) delete rec.id;
    // The ICO template lists each personal-data category of one activity on its own row: fold
    // rows with the same id, or the same name and purpose, into one activity.
    const key = (rec.id || rec.name + "\u0000" + rec.purpose).toLowerCase();
    const prev = byKey.get(key);
    if (!prev) { byKey.set(key, rec); records.push(rec); return; }
    for (const k of ["dataSubjects", "dataCategories", "systems", "recipients", "dpiaCriteria"]) prev[k] = uniq([...prev[k], ...rec[k]]).sort(k === "systems" || k === "recipients" ? cmp : undefined);
    const tk = (t) => t.country + "|" + t.recipient + "|" + t.mechanism;
    for (const t of rec.transfers) if (!prev.transfers.some((u) => tk(u) === tk(t))) prev.transfers.push(t);
    for (const [c, u] of Object.entries(rec.categoryUses || {})) if (!prev.categoryUses[c]) prev.categoryUses[c] = u;
    for (const [k, v] of Object.entries(rec)) if (typeof v === "string" && v && !prev[k]) prev[k] = v;
    merged++;
  });
  if (merged) skipped.push({ check: "rows", reason: merged + " row(s) repeated an activity already listed (same name and purpose) and were merged into it" });
  return { records, skipped };
}

export function csvToDsars(rows, mapping, { dateOrder = "dmy" } = {}) {
  const skipped = [];
  const records = [];
  const get = (r, k) => (mapping[k] ? str(r[mapping[k]]) : "");
  (rows || []).forEach((r, i) => {
    const rec = normalizeDsar({
      ref: get(r, "ref"), type: get(r, "type"), received: parseDate(get(r, "received"), dateOrder), identityVerified: parseDate(get(r, "identityVerified"), dateOrder),
      extended: get(r, "extended"), extensionNotified: parseDate(get(r, "extensionNotified"), dateOrder), completed: parseDate(get(r, "completed"), dateOrder),
      owner: get(r, "owner"), notes: get(r, "notes"),
    });
    if (!rec.ref && !rec.received) { skipped.push({ check: "row " + (i + 2), reason: "no reference or received date" }); return; }
    if (get(r, "received") && !rec.received) skipped.push({ check: "row " + (i + 2), reason: "received date \"" + get(r, "received") + "\" not readable" });
    if (!rec.ref) rec.ref = "row-" + (i + 2);
    delete rec.id;
    records.push(rec);
  });
  return { records, skipped };
}

/**
 * The ICO controller template (Template / Example sheet saved as CSV) has the controller, DPO and
 * representative block (rows 1-6) and a section-title row (row 8) above the column headers (row 9):
 * start the CSV at the header row.
 */
function skipIcoPreamble(t) {
  if (/^\s*[[{]/.test(t)) return t;
  const lines = t.split(/\r?\n/);
  const i = lines.findIndex((l) => /purpose of processing/i.test(l) && /categories of individuals/i.test(l));
  return i > 0 ? lines.slice(i).join("\n") : t;
}

/**
 * parseInput(text | [{name, text}]) -> { format, confidence, headers, rows, mapping, kind, files[], activities[], dsars[], skipped[] }.
 * Accepts this tool's register JSON, an activity (ROPA) CSV and a DSAR log CSV. Top-level
 * headers/rows/mapping describe the first CSV; files[] has every file's own.
 */
export function parseInput(input) {
  const files = Array.isArray(input) ? input : [{ name: "", text: input }];
  const skipped = [];
  const out = { format: "empty", confidence: "low", headers: [], rows: [], mapping: {}, kind: "", files: [], activities: [], dsars: [], skipped };
  for (const f of files) {
    const t = skipIcoPreamble(str(f && f.text));
    const name = str(f && f.name) || "input";
    if (!t) continue;
    const fmt = sniff(t).format;
    if (fmt === "json" || fmt === "ndjson") {
      let j = null;
      try { j = JSON.parse(t); } catch (_) { j = [...iterJson(t)]; }
      let acts = [], ds = [];
      if (j && !Array.isArray(j) && (Array.isArray(j.activities) || Array.isArray(j.dsars))) { acts = j.activities || []; ds = j.dsars || []; }
      else if (Array.isArray(j)) {
        for (const r of j) { if (!r || typeof r !== "object") continue; if (r.received !== undefined && r.type !== undefined && r.name === undefined) ds.push(r); else if (r.name || r.purpose) acts.push(r); }
      }
      if (!acts.length && !ds.length) { skipped.push({ check: name, reason: "no processing activities or DSAR records found in the JSON" }); continue; }
      out.activities.push(...acts.map(normalizeActivity));
      out.dsars.push(...ds.map(normalizeDsar));
      if (out.format === "empty") { out.format = "dataflow-register"; out.confidence = "high"; out.kind = "register"; }
      out.files.push({ name, kind: "register", format: "Processing Register JSON", confidence: "high", count: acts.length + ds.length, activities: acts.length, dsars: ds.length });
    } else if (fmt === "csv" || fmt === "tsv") {
      const { headers, rows } = parseCsv(t);
      if (!headers.length) { skipped.push({ check: name, reason: "empty CSV" }); continue; }
      const dsar = isDsarHeaders(headers);
      const { mapping, confidence } = dsar ? autoMapDsars(headers) : autoMapActivities(headers);
      const order = detectDateOrder(rows.flatMap((r) => Object.values(r)).filter((v) => /^\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}/.test(str(v))));
      const ico = !dsar && !!findColumn(headers, ["Categories of individuals"]) && !!findColumn(headers, ["Purpose of processing"]);
      const file = { name, kind: dsar ? "dsar" : "activities", format: dsar ? "DSAR log CSV" : ico ? "ICO documentation template (controller) CSV" : "Processing activities CSV", confidence, count: rows.length, headers, rows, mapping, dateOrder: order };
      out.files.push(file);
      if (!out.headers.length) { out.headers = headers; out.rows = rows; out.mapping = mapping; out.confidence = confidence; out.kind = file.kind; out.format = dsar ? "dsar-csv" : "activities-csv"; }
      if (dsar && !mapping.received) skipped.push({ check: name, reason: "no received-date column (" + DSAR_COLUMNS.received.join(", ") + "); map it by hand" });
      if (!dsar && !mapping.name && !mapping.purpose) skipped.push({ check: name, reason: "no activity name or purpose column (" + COLUMNS.name.concat(COLUMNS.purpose).join(", ") + "); map it by hand" });
    } else skipped.push({ check: name, reason: "not JSON or CSV (" + fmt + ")" });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

const FINDING_COLS = ["id", "severity", "confidence", "category", "title", "description", "recommendation", "controls", "assets", "evidenceCount"];
/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const rows = (findings || []).map((f) => ({
    id: f.id || "", severity: f.severity, confidence: f.confidence, category: f.category || "", title: f.title, description: f.description || "", recommendation: f.recommendation || "",
    controls: (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), assets: (f.assets || []).map((a) => a.type + ":" + a.name).join("; "),
    evidenceCount: f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
  }));
  return toCsv(rows, FINDING_COLS);
}

const transfersText = (a) => a.transfers.map((t) => {
  const c = normCountry(t.country);
  return (c.code === "EU" ? "EU/EEA" : c.code ? COUNTRIES[c.code] : t.country) + (t.recipient ? " - " + t.recipient : "");
}).join("; ");
const safeguardsText = (a) => a.transfers.map((t) => (label(MECHANISMS, t.mechanism) || "not recorded") + (t.dpfCertified === "yes" ? " (DPF certified)" : "") + (t.tia ? " + TIA" : "")).join("; ");

/**
 * Art. 30 record as CSV. variant "controller" (Art. 30(1); controller and joint-controller
 * activities) or "processor" (Art. 30(2); processor activities).
 */
export function ropaCsv(activities, { variant = "controller", org = {} } = {}) {
  const acts = (activities || []).map(normalizeActivity).filter((a) => (variant === "processor" ? a.role === "processor" : a.role !== "processor"))
    .sort((a, b) => cmp(a.name.toLowerCase(), b.name.toLowerCase()) || cmp(a.id, b.id));
  const orgTxt = [str(org.name), str(org.contact)].filter(Boolean).join(", ");
  const cats = (a, kind) => a.dataCategories.filter((c) => (kind === "special" ? CAT_BY_ID[c] && CAT_BY_ID[c].special : kind === "criminal" ? CAT_BY_ID[c] && CAT_BY_ID[c].criminal : !(CAT_BY_ID[c] && (CAT_BY_ID[c].special || CAT_BY_ID[c].criminal)))).map(categoryLabel).join("; ");
  if (variant === "processor") {
    const cols = ["Processor name and contact details", "Data protection officer", "Representative", "Processing activity", "Controller on whose behalf", "Categories of processing",
      "Transfers to third countries", "Transfer safeguards", "Technical and organisational security measures", "Recipients (sub-processors)", "Systems", "Last review"];
    return toCsv(acts.map((a) => ({
      [cols[0]]: orgTxt, [cols[1]]: str(org.dpo), [cols[2]]: str(org.representative), [cols[3]]: a.name, [cols[4]]: a.controllerName, [cols[5]]: a.purpose,
      [cols[6]]: transfersText(a), [cols[7]]: safeguardsText(a), [cols[8]]: a.securityMeasures, [cols[9]]: a.recipients.join("; "), [cols[10]]: a.systems.join("; "), [cols[11]]: a.lastReview,
    })), cols);
  }
  const cols = ["Controller name and contact details", "Joint controller", "Representative", "Data protection officer", "Processing activity", "Purposes of the processing",
    "Lawful basis (Art. 6)", "Categories of data subjects", "Categories of personal data", "Special category data (Art. 9)", "Art. 9(2) condition", "Criminal offence data (Art. 10)",
    "Categories of recipients", "Transfers to third countries", "Transfer safeguards", "Time limits for erasure", "Retention trigger", "Technical and organisational security measures",
    "DPIA status", "Systems", "Owner", "Last review"];
  return toCsv(acts.map((a) => {
    const crim = cats(a, "criminal");
    return {
      [cols[0]]: orgTxt, [cols[1]]: a.jointController, [cols[2]]: str(org.representative), [cols[3]]: str(org.dpo), [cols[4]]: a.name, [cols[5]]: a.purpose,
      [cols[6]]: label(LEGAL_BASES, a.legalBasis), [cols[7]]: a.dataSubjects.map(subjectLabel).join("; "), [cols[8]]: cats(a, "general"), [cols[9]]: cats(a, "special"),
      [cols[10]]: a.art9Condition ? label(ART9_CONDITIONS, a.art9Condition) : "", [cols[11]]: crim ? crim + (a.criminalBasis ? " - " + a.criminalBasis : " - no basis recorded") : "",
      [cols[12]]: a.recipients.join("; "), [cols[13]]: transfersText(a), [cols[14]]: safeguardsText(a), [cols[15]]: a.retention, [cols[16]]: a.retentionTrigger,
      [cols[17]]: a.securityMeasures, [cols[18]]: label(DPIA_STATUSES, a.dpiaStatus) + (a.dpiaDate ? " " + a.dpiaDate : ""), [cols[19]]: a.systems.join("; "), [cols[20]]: a.owner, [cols[21]]: a.lastReview,
    };
  }), cols);
}

/** DSAR log as CSV with computed deadlines and status (from analyze().tables.dsars when given). */
export function dsarCsv(dsars, result) {
  const cols = ["Reference", "Request type", "Article", "Received", "Identity verified", "Clock start", "Extended", "Extension notified", "Due", "Completed", "Status", "Days left", "Days to complete", "Owner", "Notes"];
  const tbl = new Map(((result && result.tables && result.tables.dsars) || []).map((r) => [r.id, r]));
  const list = (dsars || []).map((r, i) => { const d = normalizeDsar(r); if (!d.id) d.id = "dsar-" + (i + 1); return d; }).sort((a, b) => cmp(a.received, b.received) || cmp(a.ref, b.ref));
  return toCsv(list.map((d) => {
    const t = tbl.get(d.id) || {};
    const dd = t.due ? t : dsarDue(d);
    return {
      Reference: d.ref, "Request type": label(DSAR_TYPES, d.type), Article: (DSAR_BY_ID[d.type] || {}).article || "", Received: d.received, "Identity verified": d.identityVerified,
      "Clock start": t.clockStart || dd.start || "", Extended: d.extended ? "yes" : "no", "Extension notified": d.extensionNotified, Due: dd.due || "", Completed: d.completed,
      Status: t.status || "", "Days left": t.daysLeft == null ? "" : t.daysLeft, "Days to complete": t.daysToComplete == null ? "" : t.daysToComplete, Owner: d.owner, Notes: d.notes,
    };
  }), cols);
}

/** DPIA screening memo (plain text) for one activity. */
export function dpiaMemo(rec, { now = "", org = {}, example = false } = {}) {
  const a = normalizeActivity(rec);
  const s = screenDpia(a);
  const L = [];
  L.push("DPIA SCREENING MEMO" + (example ? " (SYNTHETIC EXAMPLE)" : ""));
  L.push("Organisation: " + (str(org.name) || "not set"));
  L.push("Activity: " + (a.name || "Unnamed") + (a.id ? " [" + a.id + "]" : ""));
  L.push("Screened: " + (ymd(now) || "date not set") + "    Owner: " + (a.owner || "not set"));
  L.push("Role: " + (label(ROLES, a.role) || "not set") + "    Lawful basis: " + (label(LEGAL_BASES, a.legalBasis) || "not recorded"));
  L.push("", "Purpose: " + (a.purpose || "not recorded"));
  L.push("Data subjects: " + (a.dataSubjects.map(subjectLabel).join(", ") || "not recorded"));
  L.push("Data categories: " + (a.dataCategories.map(categoryLabel).join(", ") || "not recorded"));
  if (a.subjectCount) L.push("Approximate number of data subjects: " + a.subjectCount);
  L.push("", "CRITERIA (EDPB/WP29 Guidelines on DPIA, WP248 rev.01)");
  s.criteria.forEach((c, i) => L.push("  " + (i + 1) + ". [" + (c.met ? "X" : " ") + "] " + c.label + (c.met ? " - " + (c.source === "derived" ? "derived from the record: " : "") + c.why : "")));
  L.push("", "Criteria met: " + s.count + " of 9");
  L.push("Screening result: " + (s.likely
    ? "DPIA LIKELY REQUIRED (two or more criteria met; GDPR Art. 35(1)). Also check your supervisory authority's Art. 35(4) list."
    : s.count === 1 ? "One criterion met. A DPIA is not presumed, but record the reasoning and check your supervisory authority's Art. 35(4) list."
      : "No criteria met on this record. Record the decision and re-screen when the processing changes."));
  L.push("Current DPIA status: " + (label(DPIA_STATUSES, a.dpiaStatus) || "not recorded") + (a.dpiaDate ? " (" + a.dpiaDate + ")" : "") + (a.dpiaRef ? " ref " + a.dpiaRef : ""));
  if (a.transfers.length) L.push("Third-country transfers: " + transfersText(a) + " | safeguards: " + safeguardsText(a));
  L.push("", "This memo is a screening aid built from the record as entered. It is not legal advice and does not make the processing compliant. Verify with counsel and your DPO (Art. 35(2)).");
  return L.join("\n") + "\n";
}

/** Calendar events: open DSAR deadlines, activity reviews, DPIA re-assessments. */
export function icsEvents({ activities = [], dsars = [] } = {}, { now = "", reviewMonths = DEFAULTS.reviewMonths, dpiaReviewMonths = DEFAULTS.dpiaReviewMonths, clockStart = "receipt", rollWeekends = true, example = false } = {}) {
  const ev = [];
  const stamp = (ymd(now) || "2026-01-01") + "T00:00:00Z";
  const tag = example ? " (synthetic example)" : "";
  for (const r0 of dsars) {
    const r = normalizeDsar(r0);
    if (r.completed || !r.received) continue;
    const dd = dsarDue(r, { clockStart, rollWeekends });
    if (!dd.due) continue;
    ev.push({ uid: "dfr-dsar-" + (r.id || r.ref) + "@darknode.ai", start: dd.due, end: addDays(dd.due, 1), allDay: true, stamp,
      summary: "DSAR " + (r.ref || r.id) + " due (" + label(DSAR_TYPES, r.type) + ")" + tag,
      description: "Received " + r.received + (r.extended ? ", extended" : "") + ". GDPR Art. 12(3) deadline as computed by the Processing Register; verify with counsel." });
    if (!r.extended && dd.baseDue) ev.push({ uid: "dfr-dsar-ext-" + (r.id || r.ref) + "@darknode.ai", start: dd.baseDue, end: addDays(dd.baseDue, 1), allDay: true, stamp,
      summary: "DSAR " + (r.ref || r.id) + ": last day to notify an extension" + tag, description: "If the request is complex, tell the requester about the extension and the reasons by this date (Art. 12(3))." });
  }
  for (const a0 of activities) {
    const a = normalizeActivity(a0);
    const nm = a.name || "Unnamed activity";
    const due = a.lastReview ? addMonths(a.lastReview, reviewMonths) : ymd(now);
    if (due) ev.push({ uid: "dfr-review-" + (a.id || nm) + "@darknode.ai", start: due, end: addDays(due, 1), allDay: true, stamp, summary: "Review processing activity: " + nm + tag, description: "Art. 30 record review" + (a.owner ? " with " + a.owner : "") + "." });
    if (a.dpiaStatus === "completed" && a.dpiaDate) {
      const d = addMonths(a.dpiaDate, dpiaReviewMonths);
      ev.push({ uid: "dfr-dpia-" + (a.id || nm) + "@darknode.ai", start: d, end: addDays(d, 1), allDay: true, stamp, summary: "Re-assess DPIA: " + nm + tag, description: "DPIA completed " + a.dpiaDate + (a.dpiaRef ? " (" + a.dpiaRef + ")" : "") + "." });
    }
  }
  return ev.sort((x, y) => cmp(x.start, y.start) || cmp(x.uid, y.uid));
}

/** Plain-text summary of a result. */
export function summaryText(result, { org = {}, example = false } = {}) {
  const s = result.summary, m = result.meta;
  const L = ["Data Inventory & Processing Register summary" + (example ? " (SYNTHETIC EXAMPLE)" : ""), "Organisation: " + (str(org.name) || "not set"),
    "As of " + (m.now || "unknown") + "    Regime: " + label(REGIMES, m.regime) + "    DSAR clock starts at " + (m.clockStart === "identity" ? "identity verification" : "receipt"),
    m.reference ? "Transfers assessed against reference data " + m.reference.version + " (updated " + m.reference.updated + "), verify with counsel." : "Transfers not assessed (reference data not loaded).", "",
    "Processing activities: " + s.activities + " (special-category or criminal data: " + s.specialCategory + ")",
    "DPIA likely required (2+ WP248 criteria): " + s.dpiaLikely + "; DPIA gaps: " + s.dpiaGaps,
    "Third-country transfers assessed: " + s.transfers + " (gaps " + s.transfersGap + ", to review " + s.transfersReview + ")",
    "Reviews overdue or never done: " + s.reviewsOverdue,
    "DSARs: " + s.dsars + " (open " + s.dsarOpen + ", overdue " + s.dsarOverdue + ", at risk " + s.dsarAtRisk + ", answered late " + s.dsarLate + ", median days to complete " + (s.dsarMedianDays == null ? "-" : s.dsarMedianDays) + ")",
    "", "FINDINGS (" + result.findings.length + ")"];
  for (const f of result.findings) L.push("  [" + f.severity.toUpperCase() + "/" + f.confidence + "] " + f.title + " - " + f.description + " | " + (f.controls || []).map((c) => c.framework + " " + c.id).join(", "));
  if (result.skipped.length) L.push("", "NOT CHECKED", ...result.skipped.map((x) => "  " + x.check + ": " + x.reason));
  L.push("", "This register supports record-keeping. It does not make the organisation compliant. Verify legal requirements with counsel.");
  return L.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example (offline; never saved)
// ---------------------------------------------------------------------------

/** SYNTHETIC example: fictional "Test Org". Not real data. */
export function exampleDataset(seed = 7, nowIso = "2026-10-16T12:00:00Z") {
  void seed;
  const org = { name: "Test Org Ltd (fictional)", contact: "privacy@test.darknode.ai, 1 Example Quay, Dublin", dpo: "dpo@test.darknode.ai", representative: "" };
  const activities = [
    { id: "testorg-act-01", name: "Customer account management", purpose: "Provide and bill the Test Org platform to customer organisations", role: "controller", owner: "ops-lead@test.darknode.ai",
      dataSubjects: ["customers"], dataCategories: ["identity", "contact", "credentials", "usage"],
      categoryUses: { identity: "Account holder", contact: "Service notices and billing", credentials: "Sign-in", usage: "Fair-use limits and support" },
      systems: ["Test Org App (prod)", "Postgres eu-west-1"], recipients: ["Vendor A Hosting"], legalBasis: "b", retention: "6 years", retentionTrigger: "end of contract",
      oldestRecord: "2021-02-01", transfers: [{ country: "JP", recipient: "Vendor A Hosting", mechanism: "adequacy" }],
      securityMeasures: "SSO with MFA, encryption at rest and in transit, quarterly access review, daily backups", dpiaStatus: "not-needed", lastReview: "2026-03-10" },
    { id: "testorg-act-02", name: "Payroll and HR administration", purpose: "Pay staff, meet tax and employment law obligations", role: "controller", owner: "people-team@test.darknode.ai",
      dataSubjects: ["employees"], dataCategories: ["identity", "contact", "bank", "national-id", "employment", "health"],
      categoryUses: { identity: "Payroll record", contact: "Payslips", bank: "Salary payment", "national-id": "Tax reporting", employment: "Contract and pay", health: "Statutory sick pay" },
      art9Condition: "b", systems: ["HRIS"], recipients: ["Vendor B Payroll Ltd", "Revenue authority"], legalBasis: "c", retention: "7 years", retentionTrigger: "end of employment",
      oldestRecord: "2020-05-01", transfers: [{ country: "IN", recipient: "Vendor B Payroll Ltd", mechanism: "scc-2021", tia: true }],
      securityMeasures: "Role-based access, field encryption for bank details, audit logging", dpiaStatus: "completed", dpiaDate: "2022-05-01", dpiaRef: "DPIA-2022-03", lastReview: "2025-08-01" },
    { id: "testorg-act-03", name: "Marketing newsletter", purpose: "Send product news to customers and prospects", role: "controller", owner: "marketing@test.darknode.ai",
      dataSubjects: ["customers", "prospects"], dataCategories: ["contact", "usage", "online-id"], categoryUses: {},
      systems: ["Marketing automation"], recipients: ["Vendor C Inc"], legalBasis: "f", retention: "indefinite",
      transfers: [{ country: "US", recipient: "Vendor C Inc", mechanism: "adequacy", dpfCertified: "no" }], securityMeasures: "", dpiaStatus: "", lastReview: "2026-01-15" },
    { id: "testorg-act-04", name: "Product analytics and lead scoring", purpose: "Score trial accounts for sales follow-up", role: "controller", owner: "growth@test.darknode.ai",
      dataSubjects: ["website-visitors", "prospects"], dataCategories: ["identity", "contact", "usage", "online-id", "location", "demographic", "financial", "employment", "images", "credentials", "comms"],
      categoryUses: { identity: "Match to CRM", contact: "Sales outreach", usage: "Scoring model input", "online-id": "Session stitching", location: "Region routing" },
      dpiaCriteria: ["scoring", "combining", "large-scale"], subjectCount: "about 400,000",
      systems: ["Analytics warehouse", "CRM"], recipients: ["Vendor D Analytics"], legalBasis: "f", liaRef: "LIA-2026-02", retention: "24 months", retentionTrigger: "last activity",
      oldestRecord: "2025-03-01", transfers: [{ country: "US", recipient: "Vendor D Analytics", mechanism: "adequacy", dpfCertified: "yes" }],
      securityMeasures: "Pseudonymised event IDs, warehouse access limited to analysts", dpiaStatus: "", lastReview: "2026-06-01" },
    { id: "testorg-act-05", name: "Employee endpoint monitoring", purpose: "Detect data exfiltration on company laptops", role: "controller", owner: "security@test.darknode.ai",
      dataSubjects: ["employees"], dataCategories: ["identity", "online-id", "comms", "usage"],
      categoryUses: { identity: "Alert attribution", "online-id": "Device correlation", comms: "DLP content inspection", usage: "Anomaly baseline" },
      dpiaCriteria: ["monitoring"], systems: ["EDR console"], recipients: ["Internal security team"], legalBasis: "a", retention: "12 months", retentionTrigger: "event date",
      oldestRecord: "2025-12-01", securityMeasures: "Console access restricted to two analysts, all queries logged", dpiaStatus: "in-progress", lastReview: "2026-04-20" },
    { id: "testorg-act-06", name: "Customer support ticket handling", purpose: "Resolve support tickets raised by customers' end users", role: "processor", controllerName: "Each customer organisation (per DPA)", owner: "support-lead@test.darknode.ai",
      dataSubjects: ["website-visitors"], dataCategories: ["identity", "contact", "comms"], categoryUses: { identity: "Ticket owner", contact: "Replies", comms: "Ticket content" },
      systems: ["Helpdesk"], recipients: ["Vendor E Support BPO"], retention: "90 days", retentionTrigger: "ticket closed", oldestRecord: "2026-01-02",
      transfers: [{ country: "Philippines", recipient: "Vendor E Support BPO", mechanism: "none" }], securityMeasures: "Helpdesk SSO, redaction of card numbers", lastReview: "2026-02-11" },
    { id: "testorg-act-07", name: "Recruitment", purpose: "Assess candidates for open roles", role: "controller", owner: "people-team@test.darknode.ai",
      dataSubjects: ["job-applicants"], dataCategories: ["identity", "contact", "employment", "criminal"],
      categoryUses: { identity: "Candidate record", contact: "Interview scheduling", employment: "Assessment", criminal: "Background check for finance roles" },
      systems: ["Applicant tracking system"], recipients: ["Vendor A Hosting"], legalBasis: "f", liaRef: "LIA-2025-07", retention: "6 months", retentionTrigger: "end of recruitment campaign",
      oldestRecord: "2026-07-01", securityMeasures: "ATS access limited to hiring managers", dpiaStatus: "not-needed", lastReview: "2026-05-05" },
    { id: "testorg-act-08", name: "Office visitor CCTV", purpose: "Protect the Dublin office and staff", role: "controller", owner: "facilities@test.darknode.ai",
      dataSubjects: ["public", "employees"], dataCategories: ["images"], categoryUses: { images: "Incident investigation" },
      dpiaCriteria: ["monitoring"], systems: ["CCTV recorder"], recipients: ["none"], legalBasis: "f", liaRef: "LIA-2024-01", retention: "30 days", retentionTrigger: "recording date",
      oldestRecord: "2026-09-20", securityMeasures: "Recorder in locked comms room, export only by facilities manager", dpiaStatus: "completed", dpiaDate: "2024-09-01", dpiaRef: "DPIA-2024-01", lastReview: "2025-09-30" },
  ];
  const dsars = [
    { id: "testorg-dsar-01", ref: "DSR-2026-001", type: "access", received: "2026-01-12", identityVerified: "2026-01-13", completed: "2026-02-03", owner: "privacy@test.darknode.ai" },
    { id: "testorg-dsar-02", ref: "DSR-2026-002", type: "erasure", received: "2026-02-27", completed: "2026-03-20", owner: "privacy@test.darknode.ai" },
    { id: "testorg-dsar-03", ref: "DSR-2026-003", type: "access", received: "2026-03-31", identityVerified: "2026-04-02", completed: "2026-05-08", owner: "privacy@test.darknode.ai" },
    { id: "testorg-dsar-04", ref: "DSR-2026-004", type: "portability", received: "2026-05-05", extended: true, extensionNotified: "2026-05-29", completed: "2026-07-15", owner: "privacy@test.darknode.ai" },
    { id: "testorg-dsar-05", ref: "DSR-2026-005", type: "rectification", received: "2026-06-30", completed: "2026-07-02", owner: "privacy@test.darknode.ai" },
    { id: "testorg-dsar-06", ref: "DSR-2026-006", type: "restriction", received: "2026-07-31", extended: true, extensionNotified: "2026-09-05", completed: "2026-10-10", owner: "privacy@test.darknode.ai" },
    { id: "testorg-dsar-07", ref: "DSR-2026-007", type: "objection", received: "2026-08-14", completed: "2026-08-20", owner: "privacy@test.darknode.ai" },
    { id: "testorg-dsar-08", ref: "DSR-2026-008", type: "access", received: "2026-08-31", identityVerified: "2026-09-02", owner: "privacy@test.darknode.ai" },
    { id: "testorg-dsar-09", ref: "DSR-2026-009", type: "erasure", received: "2026-09-20", identityVerified: "2026-09-24", owner: "privacy@test.darknode.ai" },
    { id: "testorg-dsar-10", ref: "DSR-2026-010", type: "access", received: "2026-10-01", owner: "privacy@test.darknode.ai" },
  ];
  return {
    label: "Test Org (synthetic example, not real data)", now: nowIso, org, activities, dsars,
    knownVendors: ["Vendor A Hosting", "Vendor B Payroll Ltd", "Vendor D Analytics"],
    knownAssets: ["Test Org App (prod)", "Postgres eu-west-1", "HRIS", "Analytics warehouse", "CRM", "EDR console", "Helpdesk"],
  };
}

/** Real deterministic checks of the engine (no reference file needed). */
export function selfTest() {
  const tests = [];
  const t = (name, pass) => tests.push({ name, pass: !!pass });
  t("31 Jan + 1 month clamps to 28 Feb", addMonths("2026-01-31", 1) === "2026-02-28");
  t("leap year clamp to 29 Feb", addMonths("2028-01-31", 1) === "2028-02-29");
  t("Sunday deadline rolls to Monday", rollWeekend("2026-11-01") === "2026-11-02");
  t("extended DSAR gets three months", dsarDue({ received: "2026-05-05", extended: true }).due === "2026-08-05");
  t("two WP248 criteria -> DPIA likely", screenDpia({ dataSubjects: ["employees"], dpiaCriteria: ["monitoring"] }).likely);
  t("one criterion -> not presumed", !screenDpia({ dpiaCriteria: ["monitoring"] }).likely);
  const r = analyze({ activities: [{ id: "x", name: "X", role: "controller", purpose: "p", dataSubjects: ["customers"], dataCategories: ["health"], recipients: ["none"] }] }, { now: "2026-10-16", org: { name: "o", contact: "c" }, knownVendors: [] });
  t("missing lawful basis is high", r.findings.some((f) => f.id === "dfr:no-legal-basis:x" && f.severity === "high"));
  t("health without Art. 9(2) condition flagged", r.findings.some((f) => f.id === "dfr:art9-no-condition:x"));
  t("retention parse 6 years", parseRetention("6 years").months === 72);
  t("empty input yields no findings", analyze({}, { now: "2026-10-16" }).findings.length === 0);
  return { pass: tests.every((x) => x.pass), tests };
}
