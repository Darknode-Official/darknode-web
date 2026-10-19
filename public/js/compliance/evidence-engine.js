// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Control Evidence engine (evidence). Runs the year-round evidence program for
// SOC 2, ISO/IEC 27001:2022, PCI DSS v4.0.1, CIS Controls v8.1 and NIST CSF 2.0:
// which control needs which evidence, who owns it, when it is due, what was
// collected (SHA-256 of each file, computed in the browser), readiness per
// framework, a calendar and an auditor package.
//
// Pure: no DOM, no network, no clock (opts.now is passed in). Deterministic:
// the same input gives byte-identical JSON. Safe to run inside a Worker.
// Control catalogs are loaded by the UI from /data/controls and passed in.

import { sniff, parseCsv, iterJson, findColumn } from "../ingest/parse.js";
import { toCsv } from "../core/export.js";

export const TOOL_ID = "evidence";
export const VERSION = "1.0.0";

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/** Framework keys (catalog file names) with display and finding-control labels. */
export const FRAMEWORKS = [
  { key: "soc2", label: "SOC 2", ctl: "SOC2" },
  { key: "iso27001", label: "ISO 27001", ctl: "ISO27001" },
  { key: "pci4", label: "PCI DSS", ctl: "PCI" },
  { key: "cisv8", label: "CIS v8", ctl: "CIS" },
  { key: "nistcsf2", label: "NIST CSF 2.0", ctl: "NIST-CSF" },
];
const FW = Object.fromEntries(FRAMEWORKS.map((f) => [f.key, f]));
export const fwLabel = (k) => (FW[k] ? FW[k].label : String(k || ""));

export const FREQUENCIES = ["continuous", "daily", "weekly", "monthly", "quarterly", "semi-annual", "annual", "on-event"];
export const FREQ_LABEL = {
  continuous: "Continuous", daily: "Daily", weekly: "Weekly", monthly: "Monthly", quarterly: "Quarterly",
  "semi-annual": "Semi-annual", annual: "Annual", "on-event": "On event",
};
export const STATUSES = ["not-started", "collecting", "collected", "accepted", "exception"];
export const STATUS_LABEL = {
  "not-started": "Not started", collecting: "Collecting", collected: "Collected",
  accepted: "Accepted by auditor", exception: "Exception",
};

/** SOC 2 Trust Services Categories. Security (the Common Criteria) is always in scope. */
export const SOC2_CATEGORIES = [
  { key: "security", label: "Security (Common Criteria)", test: (id) => /^CC\d/.test(id), required: true },
  { key: "availability", label: "Availability", test: (id) => /^A1\./.test(id) },
  { key: "confidentiality", label: "Confidentiality", test: (id) => /^C1\./.test(id) },
  { key: "processing-integrity", label: "Processing Integrity", test: (id) => /^PI1\./.test(id) },
  { key: "privacy", label: "Privacy", test: (id) => /^P\d/.test(id) },
];
export const soc2Category = (id) => (SOC2_CATEGORIES.find((c) => c.test(String(id))) || { key: "" }).key;

/** PCI catalog row levels: principal requirement, x.y group, x.y.z with a prescribed cadence. */
export const PCI_LEVELS = [
  { key: "requirement", label: "Principal requirements (1-12)" },
  { key: "sub", label: "Sub-requirement groups (x.y)" },
  { key: "req", label: "Cadence requirements (x.y.z)" },
];

/** Column aliases for importing an existing evidence spreadsheet (case-insensitive). */
export const COLUMNS = {
  framework: ["framework", "standard", "framework name", "regime"],
  controlId: ["control id", "control_id", "controlid", "control ref", "control", "requirement", "criteria", "criterion", "clause", "reference", "ref", "id"],
  title: ["title", "control name", "control title", "name", "control description", "description"],
  domain: ["domain", "category", "family", "section", "theme"],
  owner: ["owner", "control owner", "owner email", "responsible", "assignee", "assigned to"],
  frequency: ["frequency", "cadence", "periodicity", "review frequency", "evidence frequency"],
  lastCollected: ["last collected", "date collected", "collected at", "collected", "last tested", "last evidence", "last review", "last reviewed"],
  nextDue: ["next due", "due date", "due", "next review", "next collection"],
  status: ["status", "state", "evidence status"],
  evidence: ["evidence", "evidence name", "evidence file", "artifact", "artefact", "document", "file"],
  sha256: ["sha256", "sha-256", "hash", "file hash"],
  notes: ["notes", "comments", "remarks", "comment"],
};

/** Tunable thresholds; the UI renders these with labels. */
export const DEFAULTS = {
  dueSoonDays: 30,          // "due soon" window
  overdueHighDays: 30,      // overdue longer than this is high severity
  exceptionWarnDays: 30,    // exceptions expiring within this window are listed
  firstDueDays: 30,         // first due date for a control with no evidence yet, counted from when it was scoped
  continuousPeriod: "monthly", // fresh sample cadence expected for continuous controls
  onEventMonths: 12,        // on-event evidence counts as current for this many months
  calendarMonths: 12,       // calendar / ICS horizon
};
export const DEFAULT_LABELS = {
  dueSoonDays: ["Due-soon window (days)", "Controls due within this many days are listed as due soon."],
  overdueHighDays: ["High severity after (days overdue)", "Overdue by more than this is reported as high instead of medium."],
  exceptionWarnDays: ["Exception expiry warning (days)", "Exceptions that expire within this many days are listed."],
  firstDueDays: ["First collection due (days after scoping)", "When a control has no evidence yet, its first due date is this many days after it was scoped."],
  onEventMonths: ["On-event evidence current for (months)", "On-event controls have no fixed due date; evidence older than this is stale."],
  calendarMonths: ["Calendar horizon (months)", "How far ahead the calendar and the .ics export project due dates."],
};

/**
 * Explicit, deliberately small mapping: which Deck tool's results are useful
 * evidence for which control ids. Only ids that exist in the shipped catalogs
 * (a test enforces that). A suggestion is never attached automatically.
 */
export const TOOL_EVIDENCE_MAP = {
  accessreview: { label: "Access Review", refs: { soc2: ["CC6.2", "CC6.3"], iso27001: ["5.18"], pci4: ["7.2.4"], cisv8: ["5.1", "5.3"], nistcsf2: ["PR.AA-05"] } },
  caaudit: { label: "Conditional Access Audit", refs: { soc2: ["CC6.1"], iso27001: ["8.5"], pci4: ["8.4"], cisv8: ["6.3", "6.4", "6.5"], nistcsf2: ["PR.AA-03"] } },
  privaudit: { label: "Privileged Access Audit", refs: { soc2: ["CC6.1", "CC6.3"], iso27001: ["8.2"], pci4: ["7.2"], cisv8: ["5.4"], nistcsf2: ["PR.AA-05"] } },
  jml: { label: "Lifecycle & Offboarding Verifier", refs: { soc2: ["CC6.2"], iso27001: ["5.18", "6.5"], pci4: ["8.2"], cisv8: ["6.1", "6.2"], nistcsf2: ["PR.AA-01"] } },
  nhi: { label: "Non-Human Identity Lifecycle", refs: { soc2: ["CC6.2"], iso27001: ["5.16"], cisv8: ["5.5"], nistcsf2: ["PR.AA-01"] } },
  fleetcomply: { label: "Endpoint Fleet Compliance", refs: { soc2: ["CC6.8", "CC7.1"], iso27001: ["8.1"], pci4: ["2.2", "5.2"], cisv8: ["4.1", "10.1"], nistcsf2: ["PR.PS-01"] } },
  vulnimport: { label: "Vulnerability Import & SLA", refs: { soc2: ["CC7.1"], iso27001: ["8.8"], pci4: ["11.3", "6.3.3"], cisv8: ["7.1", "7.7"], nistcsf2: ["ID.RA-01"] } },
  iacscan: { label: "IaC Scanner", refs: { soc2: ["CC8.1"], iso27001: ["8.9"], pci4: ["2.2"], cisv8: ["4.1"], nistcsf2: ["PR.PS-01"] } },
  k8saudit: { label: "Kubernetes Audit", refs: { soc2: ["CC7.1"], iso27001: ["8.9"], pci4: ["2.2"], cisv8: ["4.1"], nistcsf2: ["PR.PS-01"] } },
  cloudtrail: { label: "Cloud Audit Log Hunter", refs: { soc2: ["CC7.2"], iso27001: ["8.15", "8.16"], pci4: ["10.4.1"], cisv8: ["8.11"], nistcsf2: ["DE.CM-01"] } },
  fwaudit: { label: "Firewall Audit", refs: { soc2: ["CC6.6"], iso27001: ["8.20"], pci4: ["1.2", "1.2.7"], cisv8: ["4.4"], nistcsf2: ["PR.IR-01"] } },
  tlsfleet: { label: "TLS Fleet", refs: { soc2: ["CC6.7"], iso27001: ["8.24"], pci4: ["4.2"], cisv8: ["3.10"], nistcsf2: ["PR.DS-02"] } },
  posture: { label: "Email & Domain Posture", refs: { iso27001: ["5.14"], cisv8: ["9.5"] } },
  dmarcreports: { label: "DMARC Report Analyzer", refs: { iso27001: ["5.14"], cisv8: ["9.5"] } },
  backupready: { label: "Backup & Ransomware Readiness", refs: { soc2: ["A1.2", "A1.3"], iso27001: ["8.13"], cisv8: ["11.1", "11.2", "11.5"], nistcsf2: ["PR.DS-11"] } },
  breachclock: { label: "Breach Clock", refs: { soc2: ["CC7.4"], iso27001: ["5.26"], pci4: ["12.10"], cisv8: ["17.2"], nistcsf2: ["RS.CO-02"] } },
  riskreg: { label: "Risk Register", refs: { soc2: ["CC3.2"], pci4: ["12.3.1"], nistcsf2: ["ID.RA-05"] } },
  vendorrisk: { label: "Third-Party Risk Monitor", refs: { soc2: ["CC9.2"], iso27001: ["5.19", "5.22"], pci4: ["12.8"], cisv8: ["15.1"], nistcsf2: ["GV.SC-07"] } },
};

const MONITOR_REFS = [{ framework: "ISO27001", id: "Clause 9.1" }, { framework: "ISO27001", id: "Clause 9.2" }];
const HISTORY_CAP = 50;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const str = (v) => (v == null ? "" : String(v));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const uniq = (a) => Array.from(new Set(a));
const isObj = (v) => v != null && typeof v === "object" && !Array.isArray(v);
const refKey = (r) => r.fw + ":" + r.id;

/** Normalise a framework name ("SOC 2 Type II", "ISO/IEC 27001", "PCI DSS v4") to a catalog key, or "". */
export function normFramework(s) {
  const t = str(s).toLowerCase().replace(/[^a-z0-9]/g, "");
  if (!t) return "";
  if (FW[t]) return t;
  if (t.startsWith("soc2") || t === "soc" || t.includes("trustservices") || t === "tsc") return "soc2";
  if (t.includes("27001") || t === "iso" || t.includes("27002")) return "iso27001";
  if (t.startsWith("pci")) return "pci4";
  if (t.startsWith("cis")) return "cisv8";
  if (t.includes("csf") || t.startsWith("nist")) return "nistcsf2";
  return "";
}

/** Normalise a control id for its framework ("A.5.18" -> "5.18", "CC 6.2" -> "CC6.2", "Req 11.3" -> "11.3"). */
export function normControlId(fw, s) {
  let t = str(s).trim();
  if (!t) return "";
  if (fw === "iso27001") t = t.replace(/^(annex\s*)?a\s*\.?\s*/i, "");
  if (fw === "pci4") t = t.replace(/^(pci\s*(dss)?\s*)?(req(uirement)?\.?\s*)/i, "");
  if (fw === "cisv8") t = t.replace(/^(cis\s*)?(safeguard|control)?\s*/i, "");
  if (fw === "soc2") t = t.replace(/\s+/g, "").toUpperCase();
  if (fw === "nistcsf2") t = t.replace(/\s+/g, "").toUpperCase();
  return t.trim();
}

/** Normalise a frequency label ("Annually", "semiannual", "event", "As needed") to FREQUENCIES, or "". */
export function normFrequency(s) {
  const t = str(s).toLowerCase().replace(/[^a-z]/g, "");
  if (!t) return "";
  if (t === "continuous" || t === "continuously" || t === "realtime" || t === "ongoing") return "continuous";
  if (t === "daily") return "daily";
  if (t === "weekly") return "weekly";
  if (t === "monthly") return "monthly";
  if (t === "quarterly") return "quarterly";
  if (t === "semiannual" || t === "semiannually" || t === "biannual" || t === "biannually" || t === "halfyearly" || t === "twiceayear" || t === "everysixmonths") return "semi-annual";
  if (t === "annual" || t === "annually" || t === "yearly") return "annual";
  if (t === "event" || t === "onevent" || t === "asneeded" || t === "adhoc" || t === "eventdriven" || t === "perevent" || t === "ondemand") return "on-event";
  return "";
}

export function normStatus(s) {
  const t = str(s).toLowerCase().replace(/[^a-z]/g, "");
  if (!t) return "not-started";
  if (STATUSES.includes(s)) return s;
  if (t.startsWith("accepted") || t === "approved" || t === "passed" || t === "auditoraccepted") return "accepted";
  if (t === "collected" || t === "done" || t === "complete" || t === "completed" || t === "uploaded") return "collected";
  if (t === "collecting" || t === "inprogress" || t === "started" || t === "partial") return "collecting";
  if (t.startsWith("exception") || t === "waived" || t === "riskaccepted") return "exception";
  return "not-started";
}

// ---------------------------------------------------------------------------
// Date maths (UTC calendar days, "YYYY-MM-DD")
// ---------------------------------------------------------------------------

/** Parse ISO dates/datetimes and US m/d/yyyy to "YYYY-MM-DD" (UTC), or null. */
export function toDay(v) {
  const s = str(v).trim();
  if (!s) return null;
  let m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (m) return valid(+m[1], +m[2], +m[3]);
  m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(s);
  if (m) return valid(+m[3], +m[1], +m[2]);
  const t = Date.parse(s);
  if (!Number.isFinite(t)) return null;
  return new Date(t).toISOString().slice(0, 10);
}
function valid(y, mo, d) {
  if (mo < 1 || mo > 12 || d < 1 || d > daysInMonth(y, mo)) return null;
  return pad4(y) + "-" + pad2(mo) + "-" + pad2(d);
}
const pad2 = (n) => String(n).padStart(2, "0");
const pad4 = (n) => String(n).padStart(4, "0");
const isLeap = (y) => (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
export function daysInMonth(y, m) { return [31, isLeap(y) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]; }
const parts = (d) => d.split("-").map(Number);
export const dayNum = (d) => { const [y, m, dd] = parts(d); return Date.UTC(y, m - 1, dd) / 86400000; };
export const fromDayNum = (n) => new Date(n * 86400000).toISOString().slice(0, 10);
export const addDays = (d, n) => fromDayNum(dayNum(d) + n);
export const diffDays = (a, b) => dayNum(a) - dayNum(b);

/** Add calendar months, clamping to month end (Jan 31 + 1 month = Feb 28 or 29). */
export function addMonths(d, n) {
  const [y, m, dd] = parts(d);
  const total = m - 1 + n;
  const ny = y + Math.floor(total / 12), nm = ((total % 12) + 12) % 12 + 1;
  return pad4(ny) + "-" + pad2(nm) + "-" + pad2(Math.min(dd, daysInMonth(ny, nm)));
}

/** Next due date after `d` for a frequency; null for on-event. Continuous uses opts.continuousPeriod. */
export function addPeriod(d, freq, opts = {}) {
  const day = toDay(d);
  if (!day) return null;
  let f = normFrequency(freq) || freq;
  if (f === "continuous") f = normFrequency(opts.continuousPeriod || DEFAULTS.continuousPeriod) || "monthly";
  switch (f) {
    case "daily": return addDays(day, 1);
    case "weekly": return addDays(day, 7);
    case "monthly": return addMonths(day, 1);
    case "quarterly": return addMonths(day, 3);
    case "semi-annual": return addMonths(day, 6);
    case "annual": return addMonths(day, 12);
    default: return null;
  }
}

// ---------------------------------------------------------------------------
// SHA-256: pure-JS (sync, used for examples and as a fallback) + WebCrypto (async)
// ---------------------------------------------------------------------------

const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** SHA-256 of bytes or a UTF-8 string, lowercase hex. Synchronous, pure JS. */
export function sha256HexSync(input) {
  const msg = typeof input === "string" ? new TextEncoder().encode(input) : input instanceof Uint8Array ? input : new Uint8Array(input);
  const len = msg.length, bitLenHi = Math.floor(len / 0x20000000), bitLenLo = (len * 8) >>> 0;
  const padLen = ((len + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(padLen);
  buf.set(msg); buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, bitLenHi); dv.setUint32(padLen - 4, bitLenLo);
  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const W = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K256[i] + W[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22), mj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + mj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  return Array.from(H, (x) => x.toString(16).padStart(8, "0")).join("");
}

/** SHA-256 via WebCrypto (crypto.subtle.digest), lowercase hex. Needs the whole buffer in memory. */
export async function sha256Hex(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) return sha256HexSync(bytes);
  const dig = await subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(dig), (b) => b.toString(16).padStart(2, "0")).join("");
}

export const isSha256 = (s) => /^[0-9a-f]{64}$/.test(str(s).toLowerCase());
/** Largest single file the UI hashes: crypto.subtle.digest has no streaming mode, so the file is held in memory. */
export const MAX_HASH_BYTES = 512 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Catalogs
// ---------------------------------------------------------------------------

/** Validate a catalog envelope; returns { ok, errors, count }. */
export function checkCatalog(c) {
  const errors = [];
  if (!isObj(c)) return { ok: false, errors: ["not an object"], count: 0 };
  for (const k of ["framework", "version", "updated", "license", "sourceUrl"]) if (!str(c[k]).trim()) errors.push("missing " + k);
  if (!Array.isArray(c.data) || !c.data.length) errors.push("data is empty");
  const seen = new Set();
  for (const r of c.data || []) {
    if (!r || !str(r.id) || !str(r.title)) { errors.push("row without id/title"); continue; }
    if (seen.has(r.id)) errors.push("duplicate id " + r.id);
    seen.add(r.id);
    if (!normFrequency(r.defaultFrequency)) errors.push("unknown frequency for " + r.id + ": " + r.defaultFrequency);
  }
  return { ok: errors.length === 0, errors, count: seen.size };
}

/** Index catalogs: { fw: Map(id -> row) }. Accepts { soc2: envelope, ... }. */
export function indexCatalogs(catalogs) {
  const out = {};
  for (const f of FRAMEWORKS) {
    const c = catalogs && catalogs[f.key];
    if (c && Array.isArray(c.data)) out[f.key] = new Map(c.data.map((r) => [str(r.id), r]));
  }
  return out;
}

/** True when the catalogs carry a cross-framework mapping. The shipped files do not; links are made by hand. */
export function catalogsHaveCrosswalk(catalogs) {
  for (const f of FRAMEWORKS) {
    const c = catalogs && catalogs[f.key];
    if (c && (c.data || []).some((r) => r && (Array.isArray(r.mappings) || isObj(r.mappings) || Array.isArray(r.crosswalk)))) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/** Deterministic record id for a set of refs. */
export const recordId = (refs) => "ctl-" + refs.map((r) => r.fw + "-" + r.id).join("+").replace(/[^A-Za-z0-9+._-]/g, "_");

/** Append a history line (newest last), capped at 50 entries. */
export function addHistory(rec, at, action, by) {
  const h = Array.isArray(rec.history) ? rec.history.slice() : [];
  h.push({ at: str(at), action: str(action), ...(by ? { by: str(by) } : {}) });
  rec.history = h.slice(-HISTORY_CAP);
  return rec;
}

/** Fill defaults and normalise a record (never throws). */
export function normalizeRecord(r) {
  const rec = isObj(r) ? { ...r } : {};
  rec.refs = (Array.isArray(rec.refs) ? rec.refs : [])
    .map((x) => ({ fw: normFramework(x && (x.fw || x.framework)), id: str(x && (x.id || x.controlId)).trim() }))
    .filter((x) => x.fw && x.id);
  rec.refs = uniq(rec.refs.map(refKey)).map((k) => { const i = k.indexOf(":"); return { fw: k.slice(0, i), id: k.slice(i + 1) }; });
  rec.title = str(rec.title);
  rec.domain = str(rec.domain);
  rec.owner = str(rec.owner).trim();
  rec.frequency = normFrequency(rec.frequency) || "annual";
  rec.dueOverride = toDay(rec.dueOverride) || "";
  rec.status = STATUSES.includes(rec.status) ? rec.status : normStatus(rec.status);
  rec.scope = rec.scope === "out" ? "out" : "in";
  rec.outReason = str(rec.outReason);
  rec.evidence = (Array.isArray(rec.evidence) ? rec.evidence : []).filter(isObj).map((e) => ({ ...e, sha256: str(e.sha256).toLowerCase() }));
  rec.exceptions = (Array.isArray(rec.exceptions) ? rec.exceptions : []).filter(isObj);
  rec.notes = str(rec.notes);
  rec.history = (Array.isArray(rec.history) ? rec.history : []).slice(-HISTORY_CAP);
  if (!rec.id && rec.refs.length) rec.id = recordId(rec.refs);
  return rec;
}

/** Merge record b into a (manual crosswalk): refs, evidence, exceptions and history are unioned. */
export function mergeRecords(a, b, at = "") {
  const A = normalizeRecord(a), B = normalizeRecord(b);
  const out = { ...A };
  const refs = new Map(A.refs.concat(B.refs).map((r) => [refKey(r), r]));
  out.refs = Array.from(refs.values());
  const ev = new Map();
  for (const e of A.evidence.concat(B.evidence)) ev.set([e.sha256, e.name, e.collectedAt, e.tool, e.link].map(str).join("|"), e);
  out.evidence = Array.from(ev.values());
  out.exceptions = A.exceptions.concat(B.exceptions);
  out.owner = A.owner || B.owner;
  out.notes = [A.notes, B.notes].filter(Boolean).join("\n");
  const pa = periodRank(A.frequency), pb = periodRank(B.frequency);
  out.frequency = pb < pa ? B.frequency : A.frequency;
  out.history = A.history.concat(B.history).sort((x, y) => cmp(str(x.at), str(y.at))).slice(-HISTORY_CAP);
  addHistory(out, at, "Linked " + B.refs.map((r) => fwLabel(r.fw) + " " + r.id).join(", ") + " (merged record " + str(B.id) + ")");
  return out;
}
const periodRank = (f) => ({ daily: 1, weekly: 2, continuous: 3, monthly: 3, quarterly: 4, "semi-annual": 5, annual: 6, "on-event": 7 }[f] || 6);

/** Human label for a record's refs: "SOC 2 CC6.2 + ISO 27001 5.18". */
export const refsLabel = (refs) => (refs || []).map((r) => fwLabel(r.fw) + " " + r.id).join(" + ");

/** Register schema for openRegister(TOOL_ID, "CONTROL", { schema }); summary fits the CONTROL entity fields. */
export const REGISTER_SCHEMA = {
  key: "id",
  name: (r) => "Evidence: " + (refsLabel(r.refs) || str(r.id)) + (r.title ? " - " + r.title : ""),
  severity: () => null,
  status: () => null,
  summary: (r) => {
    const first = (r.refs || [])[0] || {};
    const impl = r.scope === "out" ? "not-applicable" : r.status === "accepted" || r.status === "collected" ? "implemented" : r.status === "collecting" || r.status === "exception" ? "partial" : "not-implemented";
    return {
      controlId: str(first.id), framework: fwLabel(first.fw), title: str(r.title), implementation: impl,
      covers: refsLabel(r.refs), owner: str(r.owner), frequency: str(r.frequency), evidenceStatus: str(r.status),
      evidenceCount: (r.evidence || []).length, scope: r.scope === "out" ? "out" : "in",
    };
  },
  columns: [
    { key: "id", label: "ID" }, { key: "refsText", label: "Controls" }, { key: "title", label: "Title" }, { key: "domain", label: "Domain" },
    { key: "owner", label: "Owner" }, { key: "frequency", label: "Frequency" }, { key: "status", label: "Status" },
    { key: "dueOverride", label: "Due override" }, { key: "evidenceCount", label: "Evidence items" }, { key: "scope", label: "Scope" },
    { key: "outReason", label: "Out-of-scope reason" }, { key: "updatedAt", label: "Updated" },
  ],
};

/** Flat rows for the register CSV export. */
export function registerCsv(records) {
  const rows = (records || []).map(normalizeRecord).sort((a, b) => cmp(a.id, b.id)).map((r) => ({
    ...r, refsText: refsLabel(r.refs), evidenceCount: r.evidence.length,
  }));
  return toCsv(rows.map((r) => Object.fromEntries(REGISTER_SCHEMA.columns.map((c) => [c.label, r[c.key]]))), REGISTER_SCHEMA.columns.map((c) => c.label));
}

// ---------------------------------------------------------------------------
// Scoping and bulk create
// ---------------------------------------------------------------------------

/**
 * Which catalog rows a scope selects.
 * scope = { frameworks: [key], soc2Categories: [key] (security always), cisIG: 1|2|3, pciLevels: [level], pciLabel, ... }
 * Returns [{ fw, row }] sorted by framework then catalog order.
 */
export function scopedRows(catalogs, scope = {}) {
  const fws = (scope.frameworks || []).filter((k) => FW[k]);
  const cats = new Set(["security", ...(scope.soc2Categories || [])]);
  const ig = Number(scope.cisIG) || 1;
  const pciLevels = new Set(scope.pciLevels && scope.pciLevels.length ? scope.pciLevels : ["sub", "req"]);
  const out = [];
  for (const f of FRAMEWORKS) {
    if (!fws.includes(f.key)) continue;
    const c = catalogs && catalogs[f.key];
    for (const row of (c && c.data) || []) {
      if (f.key === "soc2" && !cats.has(soc2Category(row.id))) continue;
      if (f.key === "cisv8" && !(row["ig" + ig] === true || (row.ig != null && Number(row.ig) <= ig))) continue;
      if (f.key === "pci4" && row.level && !pciLevels.has(row.level)) continue;
      out.push({ fw: f.key, row });
    }
  }
  return out;
}

/**
 * Bulk-create one record per scoped control. existing records (by id) are kept,
 * never overwritten. exclusions: { "soc2:CC1.1": "reason" } create out-of-scope
 * records so the package can show them. ownersByDomain: { domain: email }.
 * Returns { records (new only), excluded (new out-of-scope only), kept }.
 */
export function bulkCreate(catalogs, scope = {}, { existing = [], now = "", by = "" } = {}) {
  const at = str(now);
  const have = new Set();
  for (const r of existing || []) for (const ref of normalizeRecord(r).refs) have.add(refKey(ref));
  const excl = scope.exclusions || {};
  const owners = scope.ownersByDomain || {};
  const records = [], excluded = [];
  let kept = 0;
  for (const { fw, row } of scopedRows(catalogs, scope)) {
    const ref = { fw, id: str(row.id) };
    if (have.has(refKey(ref))) { kept++; continue; }
    const reason = excl[refKey(ref)];
    const rec = normalizeRecord({
      refs: [ref], title: str(row.title), domain: str(row.domain), owner: owners[str(row.domain)] || "",
      frequency: normFrequency(row.defaultFrequency) || "annual", status: "not-started",
      evidenceHints: Array.isArray(row.evidenceHints) ? row.evidenceHints.slice(0, 8) : [],
      scopedAt: toDay(at) || "", scope: reason != null ? "out" : "in", outReason: reason != null ? str(reason) || "excluded" : "",
      ...(fw === "pci4" && scope.pciLabel ? { assessment: str(scope.pciLabel) } : {}),
    });
    addHistory(rec, at, reason != null ? "Scoped out: " + (str(reason) || "excluded") : "Scoped in from the " + fwLabel(fw) + " catalog", by);
    (reason != null ? excluded : records).push(rec);
  }
  return { records, excluded, kept };
}

/** Assign owners in bulk by domain: returns the changed records only. Existing owners are kept unless overwrite. */
export function assignOwners(records, ownersByDomain, { overwrite = false, now = "", by = "" } = {}) {
  const changed = [];
  for (const r0 of records || []) {
    const r = normalizeRecord(r0);
    const o = str(ownersByDomain && ownersByDomain[r.domain]).trim();
    if (!o || (r.owner && !overwrite) || r.owner === o) continue;
    r.owner = o;
    addHistory(r, now, "Owner set to " + o + " (bulk by domain)", by);
    changed.push(r);
  }
  return changed;
}

// ---------------------------------------------------------------------------
// Per-control state
// ---------------------------------------------------------------------------

/** Newest collectedAt over evidence items (YYYY-MM-DD), or null. */
export function lastCollected(rec) {
  let best = null;
  for (const e of (rec && rec.evidence) || []) {
    const d = toDay(e.collectedAt);
    if (d && (!best || d > best)) best = d;
  }
  return best;
}

/** Active (unexpired) exception on `now`, or null. An exception with no expiry stays active. */
export function activeException(rec, now) {
  const list = ((rec && rec.exceptions) || []).filter((x) => { const e = toDay(x.expires); return !e || e >= now; });
  list.sort((a, b) => cmp(toDay(b.expires) || "9999-12-31", toDay(a.expires) || "9999-12-31"));
  return list[0] || null;
}

/**
 * Compute the evidence state of one record on `now`.
 * { last, nextDue, dueSource, current, ready, daysOverdue, periodEnd }
 */
export function controlState(rec0, now, opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const rec = normalizeRecord(rec0);
  const last = lastCollected(rec);
  let periodEnd = null, current = false;
  if (last) {
    if (rec.frequency === "on-event") { periodEnd = addMonths(last, Number(o.onEventMonths) || 12); current = periodEnd > now; }
    else { periodEnd = addPeriod(last, rec.frequency, o); current = !!periodEnd && periodEnd > now; }
  }
  let nextDue = null, dueSource = "none";
  if (rec.dueOverride) { nextDue = rec.dueOverride; dueSource = "override"; }
  else if (rec.frequency !== "on-event") {
    if (last) { nextDue = periodEnd; dueSource = "computed"; }
    else {
      const base = toDay(rec.scopedAt) || toDay(rec.createdAt);
      if (base) { nextDue = addDays(base, Number(o.firstDueDays) || 0); dueSource = "first"; }
    }
  }
  const ready = current && (rec.status === "collected" || rec.status === "accepted");
  const exc = activeException(rec, now);
  const daysOverdue = nextDue && nextDue < now ? diffDays(now, nextDue) : 0;
  return { last, nextDue, dueSource, current, ready, daysOverdue, periodEnd, exception: exc };
}

// ---------------------------------------------------------------------------
// Suggestions from Security Graph tool runs
// ---------------------------------------------------------------------------

const toolOf = (e) => str(e && (e.source || (e.data && (e.data._toolSource || e.data.tool)))).toLowerCase().replace(/[^a-z0-9]/g, "");

/**
 * Group graph entities (plain objects: { id, type, name, source, tags, createdAt, updatedAt, data })
 * into tool runs: one per tool per UTC day. Sample-tagged entities are ignored.
 */
export function toolRuns(entities) {
  const runs = new Map();
  for (const e of entities || []) {
    if (!e || !["FINDING", "CONTROL", "ASSET"].includes(e.type)) continue;
    if ((e.tags || []).includes("sample") || (e.data && e.data._simulated)) continue;
    const tool = toolOf(e);
    if (!TOOL_EVIDENCE_MAP[tool]) continue;
    const day = toDay(e.updatedAt || e.createdAt);
    if (!day) continue;
    const k = tool + "|" + day;
    if (!runs.has(k)) runs.set(k, { tool, runDate: day, findingCount: 0, entityCount: 0, bySeverity: {}, ids: [] });
    const r = runs.get(k);
    r.entityCount++;
    if (r.ids.length < 50) r.ids.push(str(e.id));
    if (e.type === "FINDING") { r.findingCount++; const s = str(e.severity) || "info"; r.bySeverity[s] = (r.bySeverity[s] || 0) + 1; }
  }
  return Array.from(runs.values()).map((r) => ({ ...r, ids: r.ids.sort() })).sort((a, b) => cmp(b.runDate, a.runDate) || cmp(a.tool, b.tool));
}

/** Propose tool runs as evidence for in-scope records whose refs the mapping covers. Never attaches. */
export function suggest(records, entities) {
  const runs = toolRuns(entities);
  const recs = (records || []).map(normalizeRecord).filter((r) => r.scope !== "out");
  const out = [];
  for (const run of runs) {
    const map = TOOL_EVIDENCE_MAP[run.tool];
    for (const r of recs) {
      const hits = r.refs.filter((ref) => (map.refs[ref.fw] || []).includes(ref.id));
      if (!hits.length) continue;
      const attached = r.evidence.some((e) => e.kind === "tool run" && e.tool === run.tool && toDay(e.runDate) === run.runDate);
      out.push({
        key: run.tool + "|" + run.runDate + "|" + r.id, recordId: r.id, refs: hits, refsText: refsLabel(hits), title: r.title,
        tool: run.tool, toolLabel: map.label, runDate: run.runDate, findingCount: run.findingCount, entityCount: run.entityCount,
        bySeverity: run.bySeverity, attached,
      });
    }
  }
  return out.sort((a, b) => cmp(b.runDate, a.runDate) || cmp(a.tool, b.tool) || cmp(a.recordId, b.recordId));
}

/** The evidence item a user creates by accepting a suggestion. */
export function suggestionEvidence(s, { now = "", by = "" } = {}) {
  return {
    kind: "tool run", name: s.toolLabel + " run " + s.runDate, tool: s.tool, runDate: s.runDate, findingCount: s.findingCount,
    sha256: "", size: 0, type: "", collectedAt: s.runDate, collectedBy: str(by), note: "Accepted from Security Graph suggestion on " + str(toDay(now) || now), link: "",
  };
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

function newestDate(records) {
  let best = "";
  for (const r of records || []) {
    for (const v of [r && r.updatedAt, ...((r && r.evidence) || []).map((e) => e && e.collectedAt)]) { const d = toDay(v); if (d && d > best) best = d; }
  }
  return best || "1970-01-01";
}

/**
 * analyze({ records, catalogs?, graphRuns? }, opts, ctx?) -> { summary, findings, tables, skipped, meta, suggestions }
 * A plain array is treated as records. opts.now (ISO) defaults to the newest date in the data.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...opts };
  const ds = Array.isArray(dataset) ? { records: dataset } : (dataset || {});
  const all = (Array.isArray(ds.records) ? ds.records : []).filter(isObj).map(normalizeRecord).sort((a, b) => cmp(str(a.id), str(b.id)));
  const now = toDay(o.now) || newestDate(all);
  const skipped = [], findings = [];
  const idx = indexCatalogs(ds.catalogs);
  if (!ds.catalogs) skipped.push({ check: "catalog titles", reason: "no control catalogs passed in; titles and domains come from the records only" });
  const inScope = all.filter((r) => r.scope !== "out" && r.refs.length);
  const outScope = all.filter((r) => r.scope === "out");
  const n = inScope.length;

  const rows = [];
  inScope.forEach((r, i) => {
    if (i % 1000 === 0) ctx?.progress?.(i, n, "controls");
    const s = controlState(r, now, o);
    const unknown = r.refs.filter((ref) => idx[ref.fw] && !idx[ref.fw].has(ref.id)).map((ref) => fwLabel(ref.fw) + " " + ref.id);
    rows.push({
      id: r.id, refs: r.refs, refsText: refsLabel(r.refs), title: r.title, domain: r.domain, owner: r.owner, frequency: r.frequency,
      status: r.status, last: s.last, nextDue: s.nextDue, dueSource: s.dueSource, periodEnd: s.periodEnd, current: s.current, ready: s.ready,
      daysOverdue: s.daysOverdue, exception: s.exception ? { reason: str(s.exception.reason), approvedBy: str(s.exception.approvedBy), expires: toDay(s.exception.expires) || "" } : null,
      evidenceCount: r.evidence.length, unknownRefs: unknown,
    });
  });
  const byId = new Map(inScope.map((r) => [r.id, r]));

  // Readiness per framework and coverage by domain.
  const readiness = [];
  const coverage = new Map();
  for (const f of FRAMEWORKS) {
    const fr = rows.filter((r) => r.refs.some((x) => x.fw === f.key));
    if (!fr.length) continue;
    const ready = fr.filter((r) => r.ready).length;
    const exc = fr.filter((r) => r.exception || r.status === "exception").length;
    readiness.push({
      fw: f.key, label: f.label, inScope: fr.length, ready, exceptions: exc,
      overdue: fr.filter((r) => r.daysOverdue > 0 && !r.exception).length,
      pct: Math.round((ready / fr.length) * 1000) / 10,
    });
    for (const r of fr) {
      const cat = idx[f.key] ? idx[f.key].get(r.refs.find((x) => x.fw === f.key).id) : null;
      const dom = str((cat && cat.domain) || r.domain || "(no domain)");
      const k = f.key + "|" + dom;
      if (!coverage.has(k)) coverage.set(k, { fw: f.key, label: f.label, domain: dom, inScope: 0, ready: 0 });
      const c = coverage.get(k); c.inScope++; if (r.ready) c.ready++;
    }
  }
  const coverageByDomain = Array.from(coverage.values())
    .map((c) => ({ ...c, pct: Math.round((c.ready / c.inScope) * 1000) / 10 }))
    .sort((a, b) => cmp(a.fw, b.fw) || cmp(a.domain, b.domain));

  const soonEnd = addDays(now, Number(o.dueSoonDays) || 0);
  const overdue = rows.filter((r) => r.daysOverdue > 0 && !r.exception).sort((a, b) => b.daysOverdue - a.daysOverdue || cmp(a.id, b.id));
  const dueSoon = rows.filter((r) => r.nextDue && r.nextDue >= now && r.nextDue <= soonEnd && !r.exception).sort((a, b) => cmp(a.nextDue, b.nextDue) || cmp(a.id, b.id));
  const noOwner = rows.filter((r) => !r.owner);
  const noEvidence = rows.filter((r) => !r.evidenceCount && !r.exception);
  const stale = rows.filter((r) => r.last && !r.current);
  const warnEnd = addDays(now, Number(o.exceptionWarnDays) || 0);
  const exceptionsExpiring = [], exceptionsExpired = [];
  for (const r of inScope) for (const x of r.exceptions) {
    const exp = toDay(x.expires);
    if (!exp) continue;
    const row = { id: r.id, refsText: refsLabel(r.refs), title: r.title, owner: r.owner, reason: str(x.reason), approvedBy: str(x.approvedBy), expires: exp, days: diffDays(exp, now) };
    if (exp < now) exceptionsExpired.push(row);
    else if (exp <= warnEnd) exceptionsExpiring.push(row);
  }
  exceptionsExpiring.sort((a, b) => cmp(a.expires, b.expires) || cmp(a.id, b.id));
  exceptionsExpired.sort((a, b) => cmp(a.expires, b.expires) || cmp(a.id, b.id));

  const fctl = (refs) => refs.map((x) => ({ framework: FW[x.fw].ctl, id: x.id })).concat(MONITOR_REFS);
  const ev = (r) => ({ controls: r.refsText, title: r.title, owner: r.owner || "(none)", frequency: FREQ_LABEL[r.frequency], status: STATUS_LABEL[r.status], lastCollected: r.last || "", nextDue: r.nextDue || "", daysOverdue: r.daysOverdue, evidenceItems: r.evidenceCount });

  const expiredIds = new Set(exceptionsExpired.map((x) => x.id));
  for (const r of overdue) {
    if (expiredIds.has(r.id) && !r.ready) continue; // reported once, as the expired exception
    const high = r.daysOverdue > (Number(o.overdueHighDays) || 0);
    findings.push({
      id: "overdue:" + r.id,
      title: "Evidence overdue: " + r.refsText,
      severity: high ? "high" : "medium", confidence: "confirmed", category: "overdue",
      description: (r.title ? r.title + ". " : "") + "Evidence was due " + r.nextDue + " (" + (r.dueSource === "override" ? "set by hand" : r.dueSource === "first" ? "first collection after scoping" : "last collected " + r.last + " + " + FREQ_LABEL[r.frequency].toLowerCase()) + ") and is " + r.daysOverdue + " day(s) overdue on " + now + ".",
      recommendation: "Collect the evidence and attach it (the file is hashed in the browser), or record an approved exception with an expiry date." + (r.owner ? " Owner: " + r.owner + "." : " Assign an owner."),
      controls: fctl(r.refs), evidence: [ev(r)], evidenceCount: 1,
      assets: r.owner ? [{ type: "IDENTITY", name: r.owner }] : [], tags: ["evidence", "overdue"],
    });
  }
  if (noOwner.length) findings.push({
    id: "no-owner",
    title: "Controls without an evidence owner",
    severity: "low", confidence: "confirmed", category: "ownership",
    description: noOwner.length + " in-scope control(s) have no owner, so nobody is accountable for collecting their evidence.",
    recommendation: "Assign an owner to each control (Setup can assign owners in bulk by domain).",
    controls: uniqControls(noOwner.flatMap((r) => fctl(r.refs))).slice(0, 40).concat(MONITOR_REFS.filter(() => false)),
    evidence: noOwner.slice(0, 50).map(ev), evidenceCount: noOwner.length, assets: [], tags: ["evidence", "owner"],
  });
  if (noEvidence.length) findings.push({
    id: "no-evidence",
    title: "Controls with no evidence ever collected",
    severity: "medium", confidence: "confirmed", category: "coverage",
    description: noEvidence.length + " in-scope control(s) have no evidence item at all (and no active exception).",
    recommendation: "Collect at least one evidence item per control before the audit period starts; the evidence hints from the catalog list what usually satisfies an auditor.",
    controls: uniqControls(noEvidence.flatMap((r) => fctl(r.refs))).slice(0, 40),
    evidence: noEvidence.slice(0, 50).map(ev), evidenceCount: noEvidence.length, assets: [], tags: ["evidence", "coverage"],
  });
  const expiredByRec = new Map();
  for (const x of exceptionsExpired) { if (!expiredByRec.has(x.id)) expiredByRec.set(x.id, []); expiredByRec.get(x.id).push(x); }
  for (const [id, list] of Array.from(expiredByRec).sort((a, b) => cmp(a[0], b[0]))) {
    const r = rows.find((x) => x.id === id);
    if (!r || r.ready || r.exception) continue; // current evidence or a newer exception supersedes it
    const latest = list[list.length - 1];
    findings.push({
      id: "exception-expired:" + id,
      title: "Control exception expired: " + r.refsText,
      severity: "high", confidence: "confirmed", category: "exception",
      description: "The exception \"" + latest.reason + "\" approved by " + (latest.approvedBy || "(not recorded)") + " expired on " + latest.expires + " and the control has no current evidence.",
      recommendation: "Renew the exception with a new approval and expiry, or collect evidence that the control now operates.",
      controls: fctl(r.refs), evidence: list.slice(0, 50).map((x) => ({ controls: x.refsText, reason: x.reason, approvedBy: x.approvedBy, expires: x.expires, daysAgo: -x.days })), evidenceCount: list.length,
      assets: r.owner ? [{ type: "IDENTITY", name: r.owner }] : [], tags: ["evidence", "exception"],
    });
  }
  findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || cmp(a.id, b.id));

  let suggestions = [];
  if (Array.isArray(ds.graphRuns)) suggestions = suggest(inScope, ds.graphRuns).filter((s) => !s.attached);
  else skipped.push({ check: "tool-run suggestions", reason: "no Security Graph entities passed in" });

  const unknownRefs = rows.filter((r) => r.unknownRefs.length).map((r) => ({ id: r.id, unknown: r.unknownRefs.join(", ") }));
  const calendar = calendarItems(inScope, { ...o, now });
  ctx?.progress?.(n, n, "controls");

  const exceptionsActive = rows.filter((r) => r.exception || r.status === "exception").length;
  const summary = {
    now, inScope: n, outOfScope: outScope.length, ready: rows.filter((r) => r.ready).length,
    collected: rows.filter((r) => r.status === "collected" || r.status === "accepted").length,
    overdue: overdue.length, dueSoon: dueSoon.length, exceptions: exceptionsActive, noOwner: noOwner.length,
    noEvidence: noEvidence.length, stale: stale.length, exceptionsExpiring: exceptionsExpiring.length, exceptionsExpired: exceptionsExpired.length,
    evidenceItems: inScope.reduce((s, r) => s + r.evidence.length, 0),
    readiness: Object.fromEntries(readiness.map((x) => [x.fw, x.pct])),
    findings: findings.length, bySeverity: countBy(findings, "severity"),
  };
  return {
    summary, findings,
    tables: {
      controls: rows, readiness, coverageByDomain, overdue, dueSoon, noOwner, noEvidence, stale, exceptionsExpiring, exceptionsExpired,
      exclusions: outScope.map((r) => ({ id: r.id, refsText: refsLabel(r.refs), title: r.title, reason: r.outReason || "excluded" })),
      calendar, unknownRefs, suggestions,
    },
    suggestions, skipped,
    meta: { tool: TOOL_ID, version: VERSION, now, records: all.length, catalogs: Object.keys(idx).sort(), crosswalk: catalogsHaveCrosswalk(ds.catalogs) ? "catalog" : "manual" },
  };
}

function uniqControls(list) {
  const m = new Map();
  for (const c of list) m.set(c.framework + "|" + c.id, c);
  return Array.from(m.values()).sort((a, b) => cmp(a.framework, b.framework) || cmp(a.id, b.id));
}
const sevRank = (s) => ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] ?? 0);
function countBy(items, key) {
  const out = {};
  for (const it of items) out[it[key]] = (out[it[key]] || 0) + 1;
  return Object.fromEntries(Object.entries(out).sort((a, b) => cmp(a[0], b[0])));
}

// ---------------------------------------------------------------------------
// Calendar and ICS
// ---------------------------------------------------------------------------

/**
 * Due dates from (and including overdue items before) `now` to now + calendarMonths.
 * Daily controls are rolled up into one weekly checkpoint so a year is 52 entries, not 365.
 */
export function calendarItems(records, opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const now = toDay(o.now) || newestDate(records);
  const end = addMonths(now, Number(o.calendarMonths) || 12);
  const out = [];
  for (const r0 of records || []) {
    const r = normalizeRecord(r0);
    if (r.scope === "out" || !r.refs.length) continue;
    const s = controlState(r, now, o);
    if (!s.nextDue || s.exception) continue;
    const base = { recordId: r.id, refsText: refsLabel(r.refs), title: r.title, owner: r.owner, frequency: r.frequency };
    if (s.nextDue < now) out.push({ ...base, date: s.nextDue, kind: "overdue" });
    let d = s.nextDue < now ? null : s.nextDue;
    const rollup = r.frequency === "daily";
    let guard = 0;
    while (d && d <= end && guard++ < 400) {
      out.push({ ...base, date: d, kind: rollup ? "weekly checkpoint" : "due" });
      d = rollup ? addDays(d, 7) : addPeriod(d, r.frequency, o);
      if (s.dueSource === "override" && !rollup && r.frequency === "on-event") break;
    }
  }
  return out.sort((a, b) => cmp(a.date, b.date) || cmp(a.recordId, b.recordId));
}

/** Calendar items as toIcs events (all-day, deterministic UID and DTSTAMP). */
export function icsEvents(records, opts = {}) {
  const now = toDay(opts.now) || newestDate(records);
  return calendarItems(records, { ...opts, now }).map((c) => ({
    uid: c.recordId + "-" + c.date.replace(/-/g, "") + "@evidence.darknode.ai",
    start: c.date + "T00:00:00Z", end: addDays(c.date, 1) + "T00:00:00Z", allDay: true, stamp: now + "T00:00:00Z",
    summary: (c.kind === "overdue" ? "OVERDUE evidence: " : c.kind === "weekly checkpoint" ? "Daily evidence, weekly check: " : "Evidence due: ") + c.refsText,
    description: [c.title, "Frequency: " + FREQ_LABEL[c.frequency], "Owner: " + (c.owner || "(unassigned)"), "Control Evidence (Darknode)"].filter(Boolean).join("\n"),
  }));
}

// ---------------------------------------------------------------------------
// Auditor package (file list; the UI zips it with zipFiles)
// ---------------------------------------------------------------------------

/**
 * Build the auditor package as text files. Evidence files themselves are not
 * stored, so they are not included: the auditor matches files by SHA-256.
 * @returns {{ name: string, text: string }[]}
 */
export function buildPackage(records, opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const res = analyze({ records, catalogs: opts.catalogs }, o);
  const now = res.meta.now;
  const recs = (records || []).filter(isObj).map(normalizeRecord).sort((a, b) => cmp(a.id, b.id));
  const states = new Map(res.tables.controls.map((r) => [r.id, r]));
  const index = [];
  for (const r of recs) {
    if (r.scope === "out") continue;
    const st = states.get(r.id) || {};
    const items = r.evidence.slice().sort((a, b) => cmp(str(a.collectedAt), str(b.collectedAt)) || cmp(str(a.name), str(b.name)));
    for (const ref of r.refs) {
      const base = { framework: fwLabel(ref.fw), control_id: ref.id, title: r.title, owner: r.owner, frequency: FREQ_LABEL[r.frequency], status: STATUS_LABEL[r.status], next_due: st.nextDue || "", current: st.current ? "yes" : "no" };
      if (!items.length) index.push({ ...base, evidence_name: "", kind: "", sha256: "", size_bytes: "", collected_at: "", collected_by: "", link: "", note: "" });
      for (const e of items) index.push({ ...base, evidence_name: str(e.name), kind: str(e.kind || "file"), sha256: str(e.sha256), size_bytes: e.size == null ? "" : String(e.size), collected_at: str(e.collectedAt), collected_by: str(e.collectedBy), link: str(e.link), note: str(e.note) + (e.kind === "tool run" ? (e.note ? "; " : "") + "tool " + str(e.tool) + ", run " + str(e.runDate) + ", " + str(e.findingCount) + " finding(s)" : "") });
    }
  }
  const IDX_COLS = ["framework", "control_id", "title", "owner", "frequency", "status", "next_due", "current", "evidence_name", "kind", "sha256", "size_bytes", "collected_at", "collected_by", "link", "note"];
  const exc = [];
  for (const r of recs) for (const x of r.exceptions) {
    const exp = toDay(x.expires);
    exc.push({ controls: refsLabel(r.refs), title: r.title, reason: str(x.reason), approved_by: str(x.approvedBy), expires: exp || "", state: !exp ? "active (no expiry)" : exp < now ? "expired" : "active" });
  }
  const outs = recs.filter((r) => r.scope === "out").flatMap((r) => r.refs.map((ref) => ({ framework: fwLabel(ref.fw), control_id: ref.id, title: r.title, scope: "out of scope: " + (r.outReason || "excluded") })));
  const s = res.summary;
  const lines = [
    "Control Evidence readiness summary",
    "Organisation: " + (str(opts.org) || "(not set)"),
    "As of: " + now,
    ...(opts.scopeNote ? ["Scope: " + str(opts.scopeNote)] : []),
    "",
    "Readiness = controls whose status is collected or accepted AND whose newest evidence is inside its current period, divided by in-scope controls. Exceptions are counted separately and are not ready.",
    "",
    ...res.tables.readiness.map((x) => pad(x.label, 14) + " " + pad(x.pct.toFixed(1) + "%", 7) + " ready " + x.ready + "/" + x.inScope + ", exceptions " + x.exceptions + ", overdue " + x.overdue),
    "",
    "In scope: " + s.inScope + "   Out of scope: " + s.outOfScope + "   Evidence items: " + s.evidenceItems,
    "Overdue: " + s.overdue + "   Due in " + o.dueSoonDays + " days: " + s.dueSoon + "   Exceptions: " + s.exceptions + "   No owner: " + s.noOwner + "   No evidence: " + s.noEvidence,
    "",
    "Findings:",
    ...(res.findings.length ? res.findings.map((f) => "- [" + f.severity + "] " + f.title) : ["- none"]),
  ];
  const readme = [
    "Auditor evidence package",
    "========================",
    "",
    "Generated by Control Evidence (Darknode) on " + now + ".",
    "",
    "What is in this archive",
    "  index.csv       One row per control reference and evidence item: name, SHA-256, size, collected date and collector.",
    "  exceptions.csv  Approved control exceptions with approver and expiry.",
    "  exclusions.csv  Controls placed out of scope, with the recorded reason.",
    "  readiness.txt   Readiness per framework and the open findings.",
    "",
    "What is NOT in this archive",
    "  The evidence files themselves. They were hashed in the collector's browser and never uploaded or stored;",
    "  only the file name, size, type and SHA-256 digest were kept. Request the files from the control owner",
    "  and match each one to index.csv by its SHA-256 digest.",
    "",
    "Verifying a file",
    "  Linux:    sha256sum <file>",
    "  macOS:    shasum -a 256 <file>",
    "  Windows:  Get-FileHash -Algorithm SHA256 <file>     (PowerShell; compare case-insensitively)",
    "  A matching digest shows the file is byte-for-byte the one recorded. A different digest means it changed.",
    "",
    "Rows of kind \"tool run\" record a Darknode tool run accepted as evidence (tool, run date, finding count);",
    "they carry no file hash. Rows of kind \"link\" point to evidence held elsewhere.",
    "",
    "Control identifiers follow each framework's own numbering. Catalog notes and licences:",
    ...FRAMEWORKS.filter((f) => opts.catalogs && opts.catalogs[f.key]).map((f) => "  " + f.label + ": " + str(opts.catalogs[f.key].version) + " - " + str(opts.catalogs[f.key].license)),
  ];
  return [
    { name: "README.txt", text: readme.join("\r\n") + "\r\n" },
    { name: "index.csv", text: toCsv(index, IDX_COLS) },
    { name: "exceptions.csv", text: toCsv(exc, ["controls", "title", "reason", "approved_by", "expires", "state"]) },
    { name: "exclusions.csv", text: toCsv(outs, ["framework", "control_id", "title", "scope"]) },
    { name: "readiness.txt", text: lines.join("\r\n") + "\r\n" },
  ];
}
const pad = (s, n) => (s + " ".repeat(n)).slice(0, Math.max(n, s.length));

// ---------------------------------------------------------------------------
// Import: register JSON or an existing evidence spreadsheet (CSV)
// ---------------------------------------------------------------------------

/**
 * Parse an import. Accepts text or [{ name, text }] (first file used).
 * A JSON array of records with refs -> format "evidence-register".
 * CSV -> { format: "csv", headers, rows, mapping, confidence }.
 */
export function parseInput(input) {
  const file = Array.isArray(input) ? input[0] || {} : { text: input };
  const t = str(file.text);
  const skipped = [];
  if (!t.trim()) return { format: "empty", headers: [], rows: [], skipped, mapping: {}, confidence: "low" };
  const fmt = sniff(t).format;
  if (fmt === "json" || fmt === "ndjson" || /^\s*[[{]/.test(t)) {
    let arr = null;
    try { const v = JSON.parse(t); arr = Array.isArray(v) ? v : Array.isArray(v && v.records) ? v.records : null; } catch (_) {
      arr = []; for (const r of iterJson(t)) if (isObj(r)) arr.push(r);
    }
    if (!arr) return { format: "unknown", headers: [], rows: [], skipped: [{ check: "import", reason: "JSON is not an array of records" }], mapping: {}, confidence: "low" };
    const recs = arr.filter(isObj);
    if (recs.length && recs.every((r) => Array.isArray(r.refs))) return { format: "evidence-register", headers: [], rows: recs, skipped, mapping: {}, confidence: "high" };
    const headers = uniq(recs.flatMap((r) => Object.keys(r)));
    const m = detectMapping(headers);
    return { format: "json-rows", headers, rows: recs, skipped, mapping: m.mapping, confidence: m.confidence };
  }
  const { headers, rows } = parseCsv(t);
  const m = detectMapping(headers);
  return { format: fmt === "tsv" ? "tsv" : "csv", headers, rows, skipped, mapping: m.mapping, confidence: m.confidence };
}

/** Header -> logical column mapping with a confidence class. */
export function detectMapping(headers) {
  const mapping = {};
  const used = new Set();
  for (const [key, aliases] of Object.entries(COLUMNS)) {
    const h = findColumn((headers || []).filter((x) => !used.has(x)), aliases);
    if (h) { mapping[key] = h; used.add(h); }
  }
  const core = mapping.controlId && mapping.framework;
  const extra = ["title", "owner", "frequency", "lastCollected", "status"].filter((k) => mapping[k]).length;
  return { mapping, confidence: core && extra >= 3 ? "high" : core ? "medium" : "low" };
}

/**
 * Turn spreadsheet rows into records using a mapping { logicalKey: header }.
 * opts.defaultFramework is used when there is no framework column.
 * Rows that share framework + control id are merged (several evidence rows per control).
 * Returns { records, skipped: [{ row, reason }], warnings: [{ row, reason }] }.
 */
export function importRows(rows, mapping = {}, { catalogs = null, now = "", by = "", defaultFramework = "" } = {}) {
  const idx = indexCatalogs(catalogs);
  const out = new Map(), skipped = [], warnings = [];
  const get = (row, k) => (mapping[k] ? str(row[mapping[k]]).trim() : "");
  (rows || []).forEach((row, i) => {
    const n = i + 2; // spreadsheet row number (header is row 1)
    const fw = normFramework(get(row, "framework")) || normFramework(defaultFramework);
    if (!fw) { skipped.push({ row: n, reason: "unknown framework \"" + get(row, "framework") + "\"" }); return; }
    const id = normControlId(fw, get(row, "controlId"));
    if (!id) { skipped.push({ row: n, reason: "no control id" }); return; }
    const cat = idx[fw] ? idx[fw].get(id) : null;
    if (idx[fw] && !cat) warnings.push({ row: n, reason: fwLabel(fw) + " " + id + " is not in the loaded catalog; imported as written" });
    const ref = { fw, id };
    const key = refKey(ref);
    let rec = out.get(key);
    if (!rec) {
      const freqRaw = get(row, "frequency");
      const freq = normFrequency(freqRaw) || normFrequency(cat && cat.defaultFrequency) || "annual";
      if (freqRaw && !normFrequency(freqRaw)) warnings.push({ row: n, reason: "frequency \"" + freqRaw + "\" not recognised; used " + freq });
      rec = normalizeRecord({
        refs: [ref], title: get(row, "title") || str(cat && cat.title), domain: get(row, "domain") || str(cat && cat.domain),
        owner: get(row, "owner"), frequency: freq, status: normStatus(get(row, "status")),
        dueOverride: toDay(get(row, "nextDue")) || "", notes: get(row, "notes"), scopedAt: toDay(now) || "",
      });
      addHistory(rec, now, "Imported from spreadsheet row " + n, by);
      out.set(key, rec);
    }
    const evName = get(row, "evidence");
    const collected = toDay(get(row, "lastCollected"));
    const hash = get(row, "sha256").toLowerCase();
    if (hash && !isSha256(hash)) warnings.push({ row: n, reason: "hash is not a SHA-256 hex digest; kept as a note" });
    if (evName || collected) {
      rec.evidence.push({
        kind: "imported", name: evName || "(collected per spreadsheet)", sha256: isSha256(hash) ? hash : "", size: null, type: "",
        collectedAt: collected || "", collectedBy: "", note: "Imported from spreadsheet row " + n + (hash && !isSha256(hash) ? "; hash as given: " + hash : ""), link: "",
      });
    }
  });
  return { records: Array.from(out.values()).sort((a, b) => cmp(a.id, b.id)), skipped, warnings };
}

// ---------------------------------------------------------------------------
// Findings CSV
// ---------------------------------------------------------------------------

const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "evidenceCount"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const q = (v) => '"' + String(v ?? "").replace(/"/g, '""') + '"';
  const head = FINDING_COLS.join(",");
  const body = (findings || []).map((f) => [
    f.severity, f.confidence, f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), f.evidenceCount ?? (f.evidence || []).length,
  ].map(q).join(","));
  return [head, ...body].join("\n") + "\n";
}

/** Plain-text summary for the TXT export. */
export function summaryText(r) {
  const s = r.summary;
  return [
    "Control Evidence summary (as of " + s.now + ")",
    "In scope " + s.inScope + ", ready " + s.ready + ", overdue " + s.overdue + ", due soon " + s.dueSoon + ", exceptions " + s.exceptions + ", no owner " + s.noOwner + ", no evidence " + s.noEvidence,
    "",
    "Readiness:",
    ...r.tables.readiness.map((x) => "  " + x.label + ": " + x.pct.toFixed(1) + "% (" + x.ready + "/" + x.inScope + ")"),
    "",
    "Findings:",
    ...(r.findings.length ? r.findings.map((f) => "- [" + f.severity + "] " + f.title + " - " + f.recommendation) : ["- none"]),
  ].join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example
// ---------------------------------------------------------------------------

const EX_ORG = "Test Org (synthetic)";
const EX_PEOPLE = ["user01", "user02", "user03", "user04", "user05", "user06"].map((p) => p + "@test.darknode.ai");

/**
 * Seeded SYNTHETIC register: SOC 2 Security + ISO 27001 for Test Org,
 * ~40 controls with mixed statuses relative to `now`, two exceptions (one active,
 * one expired), owners at test.darknode.ai, a few hand-linked cross-framework
 * records. Evidence digests are real SHA-256 values of the synthetic file text.
 * Also returns synthetic graph tool runs (tagged sample) for the Suggestions tab.
 */
export function exampleDataset(seed = 7, { now = "2026-10-16", catalogs = null } = {}) {
  let s = seed >>> 0 || 7;
  const rnd = () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 4294967296; };
  const today = toDay(now) || "2026-10-16";
  const idx = indexCatalogs(catalogs);
  const soc = ["CC1.1", "CC1.4", "CC2.1", "CC3.1", "CC3.2", "CC4.1", "CC5.2", "CC6.1", "CC6.2", "CC6.3", "CC6.6", "CC6.7", "CC6.8", "CC7.1", "CC7.2", "CC7.3", "CC7.4", "CC8.1", "CC9.1", "CC9.2", "CC2.2", "CC5.3"];
  const iso = ["5.1", "5.9", "5.15", "5.18", "5.19", "5.24", "5.30", "6.3", "7.4", "8.1", "8.2", "8.5", "8.8", "8.13", "8.15", "8.16", "8.20", "8.24", "8.32", "5.23", "8.7", "8.9", "8.12"];
  const link = { "CC6.2": "5.18", "CC7.1": "8.8", "CC9.2": "5.19", "CC8.1": "8.32", "CC6.7": "8.24" };
  const linked = new Set(Object.values(link));
  const specs = soc.map((id) => (link[id] ? [{ fw: "soc2", id }, { fw: "iso27001", id: link[id] }] : [{ fw: "soc2", id }]))
    .concat(iso.filter((id) => !linked.has(id)).map((id) => [{ fw: "iso27001", id }]));
  const FALLBACK_FREQ = { "CC6.2": "quarterly", "CC6.3": "quarterly", "CC7.2": "continuous", "CC7.1": "monthly", "8.15": "continuous", "8.16": "continuous", "CC6.8": "weekly" };
  const records = [];
  specs.forEach((refs, i) => {
    const first = refs[0];
    const cat = idx[first.fw] ? idx[first.fw].get(first.id) : null;
    const rec = {
      id: recordId(refs), refs, title: cat ? str(cat.title) : refsLabel(refs), domain: cat ? str(cat.domain) : "",
      owner: i % 13 === 5 ? "" : EX_PEOPLE[Math.floor(rnd() * EX_PEOPLE.length)],
      frequency: normFrequency(cat && cat.defaultFrequency) || FALLBACK_FREQ[first.id] || "annual",
      status: "not-started", scope: "in", evidence: [], exceptions: [], notes: "", history: [],
      scopedAt: addMonths(today, -14), dueOverride: "",
    };
    const roll = rnd();
    const pick = i % 10;
    let ago = null;
    if (pick === 0 || pick === 7) { ago = null; rec.scopedAt = addDays(today, -20); } // never collected, recently scoped
    else if (pick === 3) ago = "overdue";
    else if (pick === 9) ago = "late";
    else ago = "fresh";
    if (ago) {
      const per = addPeriod(today, rec.frequency === "on-event" ? "annual" : rec.frequency) || addMonths(today, 12);
      const len = Math.max(1, diffDays(per, today));
      const back = ago === "fresh" ? Math.floor(len * (0.1 + roll * 0.6)) : ago === "overdue" ? len + 5 + Math.floor(roll * 20) : len + 40 + Math.floor(roll * 30);
      const at = addDays(today, -back);
      const name = (refs[0].id + "-" + (cat && cat.evidenceHints && cat.evidenceHints[0] ? cat.evidenceHints[0] : "evidence")).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/-+$/, "") + ".pdf";
      const content = "SYNTHETIC evidence file for " + EX_ORG + ": " + refsLabel(refs) + " collected " + at;
      rec.evidence.push({ kind: "file", name, size: content.length, type: "application/pdf", sha256: sha256HexSync(content), collectedAt: at, collectedBy: rec.owner || EX_PEOPLE[0], note: "synthetic", link: "" });
      rec.status = ago === "fresh" ? (roll < 0.45 ? "accepted" : "collected") : "collected";
    } else if (rnd() < 0.5) rec.status = "collecting";
    addHistory(rec, rec.scopedAt, "Scoped in (synthetic example)", EX_PEOPLE[0]);
    records.push(rec);
  });
  // Two exceptions: one active, one expired.
  const a = records.find((r) => r.refs[0].id === "8.20") || records[records.length - 2];
  a.status = "exception"; a.evidence = [];
  a.exceptions.push({ reason: "Legacy branch-office firewall replaced in Q1; compensating NSG rules in place", approvedBy: EX_PEOPLE[1], expires: addDays(today, 21) });
  const b = records.find((r) => r.refs[0].id === "7.4") || records[records.length - 1];
  b.status = "exception"; b.evidence = [];
  b.exceptions.push({ reason: "CCTV upgrade deferred pending landlord approval", approvedBy: EX_PEOPLE[2], expires: addDays(today, -12) });
  for (const r of records) r.updatedAt = today + "T09:00:00.000Z";
  // A hand-set due override for one control.
  const ov = records.find((r) => r.refs[0].id === "CC9.1");
  if (ov) ov.dueOverride = addDays(today, 10);
  const graphRuns = [
    { id: "ex-g1", type: "FINDING", name: "Stale admin access (accessreview:1)", source: "accessreview", severity: "high", tags: ["sink", "accessreview"], updatedAt: addDays(today, -3) + "T10:00:00Z" },
    { id: "ex-g2", type: "FINDING", name: "Orphaned account (accessreview:2)", source: "accessreview", severity: "medium", tags: ["sink", "accessreview"], updatedAt: addDays(today, -3) + "T10:00:00Z" },
    { id: "ex-g3", type: "FINDING", name: "KEV past SLA (vulnimport:1)", source: "vulnimport", severity: "critical", tags: ["sink", "vulnimport"], updatedAt: addDays(today, -1) + "T08:30:00Z" },
    { id: "ex-g4", type: "FINDING", name: "Backup immutability off (backupready:1)", source: "backupready", severity: "high", tags: ["sink", "backupready"], updatedAt: addDays(today, -6) + "T15:00:00Z" },
  ];
  return {
    label: "synthetic example (not real data): " + EX_ORG, org: EX_ORG,
    scope: { frameworks: ["soc2", "iso27001"], soc2Categories: ["security"] },
    records: records.sort((x, y) => cmp(x.id, y.id)), graphRuns, now: today,
  };
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

/** Real deterministic checks of the engine. */
export function selfTest() {
  const tests = [];
  const t = (name, fn) => { let pass = false; try { pass = !!fn(); } catch (_) { pass = false; } tests.push({ name, pass }); };
  t("SHA-256 of 'abc' matches the FIPS 180-2 vector", () => sha256HexSync("abc") === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  t("Jan 31 + 1 month clamps to Feb 29 in a leap year", () => addMonths("2028-01-31", 1) === "2028-02-29");
  t("Feb 29 + 1 year clamps to Feb 28", () => addPeriod("2028-02-29", "annual") === "2029-02-28");
  const ex = exampleDataset(7, { now: "2026-10-16" });
  const r = analyze({ records: ex.records }, { now: "2026-10-16" });
  t("example has overdue controls", () => r.summary.overdue > 0);
  t("example has an expired-exception finding", () => r.findings.some((f) => f.category === "exception" && f.severity === "high"));
  t("analysis is deterministic", () => JSON.stringify(r) === JSON.stringify(analyze({ records: ex.records }, { now: "2026-10-16" })));
  t("empty input yields no findings", () => analyze({ records: [] }, { now: "2026-10-16" }).findings.length === 0);
  return { pass: tests.every((x) => x.pass), tests };
}
