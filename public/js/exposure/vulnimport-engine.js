// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Vulnerability Import & SLA engine (vulnimport). Pure logic: no DOM, no network, no timers.
//
// Builds one normalised vulnerability register from scanner exports, de-duplicated per
// asset + CVE (or scanner plugin id) + port/package, enriched with CISA KEV and FIRST EPSS
// (mirrored feeds, or a live EPSS map the UI fetched on request), prioritised with a fixed
// documented matrix, measured against SLA policies and compared with a baseline import
// (burn-down: new / still open / fixed / reopened).
//
// Inputs (auto-detected per file by content, several at once):
//   Tenable  Nessus .nessus v2 XML, Tenable.sc / Nessus CSV, Tenable vulnerability export CSV
//   Qualys   scan / detection CSV, asset data report XML, host list detection XML
//   Greenbone / OpenVAS report XML and CSV
//   Rapid7   InsightVM / Nexpose CSV export
//   Trivy, Grype, Snyk (test --json, single or multi-project), SARIF 2.1.0 with CVE rule ids
//   Microsoft Defender Vulnerability Management: weaknesses CSV, per-device CSV,
//            advanced hunting DeviceTvmSoftwareVulnerabilities CSV
//   Generic CSV (column mapping), and this tool's own JSON export (used as the baseline)
//
// XML is cut into one element per host / result before it is parsed, so file size is bounded
// by browser memory rather than by one DOM tree; a single element above MAX_ELEMENT_BYTES
// (50 MB) is skipped and reported.
//
// Same input -> byte-identical output: everything is sorted, no clock is read
// (opts.now, default = the newest timestamp in the data).

import { parseCsv, findColumn, normHeader, xmlLite, xmlFind, xmlFindAll, xmlText } from "../ingest/parse.js";

export const TOOL_ID = "vulnimport";
export const VERSION = "1.0.0";
export const MAX_ELEMENT_BYTES = 50 * 1024 * 1024;
const DAY = 86400000;

export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const PRIORITIES = ["P1", "P2", "P3", "P4"];

/** Tunable policy; the UI renders these as the policy panel. */
export const DEFAULTS = {
  now: null,                 // ISO reference date; default = newest timestamp in the data
  epssHigh: 0.30,            // EPSS at/above this with CVSS >= 7 -> P1
  epssMedium: 0.10,          // EPSS at/above this -> at least P2
  internetFacing: "",        // regex, or newline list of names / IPs / IPv4 CIDRs, of internet-facing assets
  manyCriticals: 10,         // open critical vulns on one asset before it is reported
  oldDays: 365,              // open vulns first seen longer ago than this are reported
  disagreeSteps: 2,          // severity rank gap between scanners reported as disagreement
  includeInfo: false,        // keep informational (severity 0 / Log) items in the register
  sla: { P1: 15, P2: 30, P3: 90, P4: 180, kevCatalogDue: true, kevInternetDays: 14, pciCriticalHighDays: 0 },
  columns: {},               // generic CSV header overrides { asset: "Header", ... }
};

/** Column aliases for generic CSV files (key -> accepted header names, case-insensitive). */
export const COLUMNS = {
  asset: ["asset", "host", "hostname", "ip", "ip address", "device", "device name", "computer", "server", "target", "fqdn", "dns name", "asset name"],
  cve: ["cve", "cve id", "cves", "cve ids", "cveid"],
  title: ["title", "name", "vulnerability", "vulnerability name", "summary", "plugin name", "issue"],
  severity: ["severity", "risk", "risk factor", "priority", "rating"],
  cvss: ["cvss", "cvss score", "cvss3", "cvss v3", "cvss3 base score", "cvssv3", "base score", "score"],
  first_seen: ["first seen", "first_seen", "first detected", "first found", "discovered", "detected", "created"],
  last_seen: ["last seen", "last_seen", "last detected", "last found", "updated"],
  status: ["status", "state", "vuln status"],
  port: ["port", "service port"],
  solution: ["solution", "remediation", "fix", "recommendation"],
};

/** Human labels and scanner names of every recognised format. */
export const FORMATS = {
  "nessus-xml": { label: "Nessus .nessus v2 XML", scanner: "Nessus" },
  "tenable-csv": { label: "Tenable / Nessus CSV", scanner: "Tenable" },
  "tenable-export": { label: "Tenable vulnerability export CSV", scanner: "Tenable" },
  "qualys-csv": { label: "Qualys CSV", scanner: "Qualys" },
  "qualys-xml": { label: "Qualys XML", scanner: "Qualys" },
  "openvas-xml": { label: "Greenbone / OpenVAS XML", scanner: "OpenVAS" },
  "greenbone-csv": { label: "Greenbone / OpenVAS CSV", scanner: "OpenVAS" },
  "rapid7-csv": { label: "Rapid7 InsightVM / Nexpose CSV", scanner: "Rapid7" },
  trivy: { label: "Trivy JSON", scanner: "Trivy" },
  grype: { label: "Grype JSON", scanner: "Grype" },
  snyk: { label: "Snyk JSON", scanner: "Snyk" },
  sarif: { label: "SARIF 2.1.0", scanner: "SARIF" },
  "mdvm-weaknesses": { label: "Defender TVM weaknesses CSV", scanner: "Defender" },
  "mdvm-device": { label: "Defender per-device vulnerabilities CSV", scanner: "Defender" },
  "mdvm-hunting": { label: "Defender DeviceTvmSoftwareVulnerabilities CSV", scanner: "Defender" },
  generic: { label: "Generic CSV (mapped)", scanner: "Generic" },
  baseline: { label: "vulnimport JSON (baseline)", scanner: "vulnimport" },
};

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------
const str = (v) => (v == null ? "" : String(v)).trim();
const lc = (v) => str(v).toLowerCase();
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const uniqSorted = (arr) => [...new Set(arr.filter((x) => x != null && x !== ""))].sort(cmp);
const num = (v) => { const s = str(v); if (!s) return null; const n = Number(s.replace(/,/g, "")); return Number.isFinite(n) ? n : null; };
const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
/** Every CVE id in a string or array, upper-cased, unique, sorted. */
export function extractCves(v) { return uniqSorted((str(Array.isArray(v) ? v.join(" ") : v).match(CVE_RE) || []).map((c) => c.toUpperCase())); }

/** Parse a timestamp from the formats scanners emit; returns epoch ms or null. */
export function parseTs(v) {
  const s = str(v);
  if (!s || s === "-" || /^n\/?a$/i.test(s)) return null;
  if (/^\d{10}$/.test(s)) return Number(s) * 1000;
  if (/^\d{13}$/.test(s)) return Number(s);
  let m = s.match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})(?:[T ](\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?)?\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?$/i);
  if (m) {
    const t = Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
    if (m[7] && /^[+-]/.test(m[7])) { const z = m[7].replace(":", ""); const off = (Number(z.slice(1, 3)) * 60 + Number(z.slice(3, 5))) * 60000; return z[0] === "+" ? t - off : t + off; }
    return t;
  }
  m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:[ ,]+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?)?/i);
  if (m) {
    let h = +(m[4] || 0);
    if (m[7]) { const pm = /pm/i.test(m[7]); if (h === 12) h = pm ? 12 : 0; else if (pm) h += 12; }
    return Date.UTC(+m[3], +m[1] - 1, +m[2], h, +(m[5] || 0), +(m[6] || 0));
  }
  return parseMonthName(s);
}
/** YYYY-MM-DD of epoch ms ("" when absent). */
export function isoDay(ms) { return Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 10) : ""; }

/** CVSS qualitative rating (v3.1 section 5). */
export function severityFromScore(s) {
  if (s == null || !Number.isFinite(s)) return null;
  if (s >= 9) return "critical";
  if (s >= 7) return "high";
  if (s >= 4) return "medium";
  if (s > 0) return "low";
  return "info";
}

/** Map a scanner's own severity label or number to the five-level scale. */
export function normSeverity(v, scheme) {
  const s = lc(v);
  if (!s) return null;
  if (scheme === "nessus" && /^[0-4]$/.test(s)) return ["info", "low", "medium", "high", "critical"][+s];
  if (scheme === "qualys" && /^[1-5]$/.test(s)) return ["info", "low", "medium", "high", "critical"][+s - 1];
  if (scheme === "rapid7" && /^\d+$/.test(s)) { const n = +s; return n >= 8 ? "critical" : n >= 4 ? "high" : n >= 1 ? "medium" : "info"; }
  if (/^(critical|crit|urgent|very high)$/.test(s)) return "critical";
  if (/^(high|important|severe)$/.test(s)) return "high";
  if (/^(medium|moderate|med|serious)$/.test(s)) return "medium";
  if (/^(low|minimal|negligible|minor)$/.test(s)) return "low";
  if (/^(info|informational|none|log|unknown|debug|false positive)$/.test(s)) return "info";
  if (/^\d+(\.\d+)?$/.test(s)) return severityFromScore(Number(s));
  return null;
}

// ---------------------------------------------------------------------------
// CVSS base score maths (CVSS v3.1 specification section 7; CVSS v2 guide section 3.2.1)
// ---------------------------------------------------------------------------
function roundup31(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}
const V3 = { AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 }, UI: { N: 0.85, R: 0.62 }, CIA: { H: 0.56, L: 0.22, N: 0 } };
function parseVector(vector) {
  const m = {};
  for (const part of str(vector).replace(/^\(|\)$/g, "").replace(/^CVSS2#/i, "").split("/")) {
    const kv = part.split(":");
    if (kv.length === 2) m[kv[0].trim().toUpperCase()] = kv[1].trim().toUpperCase();
  }
  return m;
}

// ---------------------------------------------------------------------------
// SSVC (CISA Stakeholder-Specific Vulnerability Categorization) decision tree: exploitation x
// technical impact x automatable x mission prevalence -> Act / Attend / Track* / Track. An
// optional second opinion beside the P1-P4 matrix; mission prevalence is never guessed.
// ---------------------------------------------------------------------------
export const SSVC_OPTIONS = {
  exploitation: [["none", "None"], ["poc", "Proof of concept"], ["active", "Active"]],
  impact: [["partial", "Partial"], ["total", "Total"]],
  automatable: [["no", "No"], ["yes", "Yes"]],
  prevalence: [["minimal", "Minimal"], ["support", "Support"], ["essential", "Essential"]],
};
const SSVC_TABLE = {
  active: { total: { yes: ["Attend", "Act", "Act"], no: ["Attend", "Attend", "Act"] }, partial: { yes: ["Track*", "Attend", "Attend"], no: ["Track*", "Track*", "Attend"] } },
  poc: { total: { yes: ["Track*", "Attend", "Attend"], no: ["Track", "Track*", "Attend"] }, partial: { yes: ["Track", "Track*", "Track*"], no: ["Track", "Track", "Track*"] } },
  none: { total: { yes: ["Track", "Track*", "Track*"], no: ["Track", "Track", "Track*"] }, partial: { yes: ["Track", "Track", "Track"], no: ["Track", "Track", "Track"] } },
};
export const SSVC_GUIDANCE = {
  Act: "Remediate or mitigate immediately (24-48 hours); escalate to leadership.",
  Attend: "Prioritise within the current patch cycle (7-14 days).",
  "Track*": "Watch closely and plan remediation within about 30 days.",
  Track: "Remediate within normal maintenance windows.",
};
/** SSVC decision for the four answers; null while any answer is missing or unknown. */
export function ssvcDecide(exploitation, impact, automatable, prevalence) {
  const row = ((SSVC_TABLE[exploitation] || {})[impact] || {})[automatable];
  const i = ["minimal", "support", "essential"].indexOf(prevalence);
  return row && i >= 0 ? row[i] : null;
}
/** The SSVC answers a register row supports on its own, each with its basis; "" = not derivable. */
export function ssvcInputs(v) {
  const out = { exploitation: "", impact: "", automatable: "", basis: {} };
  if (v.kev) { out.exploitation = "active"; out.basis.exploitation = "listed in CISA KEV"; }
  else if (v.exploit === true) { out.exploitation = "poc"; out.basis.exploitation = "scanner reports a public exploit"; }
  else if (v.exploit === false) { out.exploitation = "none"; out.basis.exploitation = "scanner reports no known exploit"; }
  const m = /^CVSS:3/i.test(str(v.cvssVector)) ? parseVector(v.cvssVector) : null;
  if (m && m.AV && m.AC && m.PR && m.UI) {
    out.automatable = m.AV === "N" && m.AC === "L" && m.PR === "N" && m.UI === "N" ? "yes" : "no";
    out.basis.automatable = "CVSS AV/AC/PR/UI " + [m.AV, m.AC, m.PR, m.UI].join("/");
  }
  if (m && m.C && m.I) {
    out.impact = m.C === "H" && m.I === "H" ? "total" : "partial";
    out.basis.impact = "CVSS C/I " + m.C + "/" + m.I;
  }
  return out;
}

/** CVSS 3.x base score from a vector ("CVSS:3.1/AV:N/..."); null when incomplete. */
export function computeCvss31(vector) {
  const m = parseVector(vector);
  if (!["AV", "AC", "PR", "UI", "S", "C", "I", "A"].every((k) => m[k])) return null;
  const changed = m.S === "C";
  if (!(m.S === "U" || changed)) return null;
  const is31 = /CVSS:3\.1/i.test(String(vector)); // v3.1 changed the scope-changed impact sub-formula (untagged defaults to v3.0)
  const av = V3.AV[m.AV], ac = V3.AC[m.AC], ui = V3.UI[m.UI], c = V3.CIA[m.C], i = V3.CIA[m.I], a = V3.CIA[m.A];
  const pr = m.PR === "N" ? 0.85 : m.PR === "L" ? (changed ? 0.68 : 0.62) : m.PR === "H" ? (changed ? 0.5 : 0.27) : undefined;
  if ([av, ac, ui, c, i, a, pr].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed
    ? (is31 ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss * 0.9731 - 0.02, 13)   // CVSS v3.1
            : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15))            // CVSS v3.0
    : 6.42 * iss;
  const expl = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  return roundup31(Math.min((changed ? 1.08 : 1) * (impact + expl), 10));
}

/** CVSS v2 base score from a vector ("AV:N/AC:L/Au:N/C:P/I:P/A:P"); null when incomplete. */
export function computeCvss2(vector) {
  const m = parseVector(vector);
  const AV = { L: 0.395, A: 0.646, N: 1.0 }[m.AV], AC = { H: 0.35, M: 0.61, L: 0.71 }[m.AC], AU = { M: 0.45, S: 0.56, N: 0.704 }[m.AU];
  const CIA = { N: 0, P: 0.275, C: 0.66 };
  const c = CIA[m.C], i = CIA[m.I], a = CIA[m.A];
  if ([AV, AC, AU, c, i, a].some((x) => x === undefined)) return null;
  const impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a));
  const expl = 20 * AV * AC * AU;
  const f = impact === 0 ? 0 : 1.176;
  return Math.round((0.6 * impact + 0.4 * expl - 1.5) * f * 10) / 10;
}

/** Pick a CVSS score: explicit numeric score first, else computed from the vector. */
function scoreOf(score, vector, v2) {
  const lead = str(score).match(/^(\d{1,2}(?:\.\d+)?)/);
  const n = lead ? Number(lead[1]) : null;
  if (n != null && n >= 0 && n <= 10) return n;
  if (!vector) { const inner = str(score).match(/\(([^)]+)\)/); if (inner) vector = inner[1]; }
  if (!vector) return null;
  return v2 ? computeCvss2(vector) : computeCvss31(vector);
}

// Month-name dates, read as UTC: Nessus ctime "Tue Oct 14 10:22:01 2026",
// Tenable "Oct 14, 2026 10:22:01 UTC", and "14 Oct 2026".
const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
const mon = (w) => MONTHS[String(w).slice(0, 3).toLowerCase()];
function hour12(h, ap) { if (!ap) return h; const pm = /pm/i.test(ap); return h === 12 ? (pm ? 12 : 0) : pm ? h + 12 : h; }
function parseMonthName(s) {
  let m = s.match(/^(?:[A-Za-z]{3,9},?\s+)?([A-Za-z]{3,9})\.?\s+(\d{1,2}),?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s+(\d{4})/);
  if (m && mon(m[1]) != null) return Date.UTC(+m[6], mon(m[1]), +m[2], +m[3], +m[4], +(m[5] || 0));
  m = s.match(/^(?:[A-Za-z]{3,9},?\s+)?([A-Za-z]{3,9})\.?\s+(\d{1,2}),?\s+(\d{4})(?:[ ,T]+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?)?/i);
  if (m && mon(m[1]) != null) return Date.UTC(+m[3], mon(m[1]), +m[2], hour12(+(m[4] || 0), m[7]), +(m[5] || 0), +(m[6] || 0));
  m = s.match(/^(\d{1,2})[\s-]+([A-Za-z]{3,9})[\s-]+(\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?/);
  if (m && mon(m[2]) != null) return Date.UTC(+m[3], mon(m[2]), +m[1], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
  return null;
}

// ---------------------------------------------------------------------------
// Normalised record
// ---------------------------------------------------------------------------
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const isIp = (s) => IPV4.test(s) || (/^[0-9a-f:]+$/i.test(s) && s.includes(":") && s.split(":").length > 2);

/** open | fixed | reopened | unknown from a scanner's status / state label. */
export function normStatus(v) {
  const s = lc(v);
  if (!s) return "open";
  if (/re-?opened/.test(s)) return "reopened";
  if (/^(fixed|closed|resolved|remediated|mitigated|patched|not vulnerable)$/.test(s)) return "fixed";
  if (/^(new|active|open|detected|vulnerable|confirmed|potential|exposed)$/.test(s)) return "open";
  return "unknown";
}

const truthy = (v) => /^(true|yes|y|1|available|exploits are available|mature|proof of concept|functional|high|attacked|has exploit)$/i.test(str(v)) || (num(v) || 0) > 0;

/**
 * Build normalised records from one scanner row. One record per CVE (so the same CVE found
 * by two scanners merges); a row without CVE becomes one record keyed by scanner:pluginId.
 */
function mkRecords(f) {
  const ip = isIp(str(f.ip)) ? str(f.ip) : "";
  let fqdn = lc(f.fqdn);
  let name = str(f.name);
  if (!ip && isIp(name)) return mkRecords({ ...f, ip: name, name: "" });
  if (!fqdn && /\./.test(name) && !isIp(name) && f.kind !== "image" && f.kind !== "package") fqdn = name.toLowerCase();
  const assetLabel = f.assetName || name || fqdn || ip;
  if (!assetLabel) return [];
  const sevScanner = f.severity || null;
  const v3 = scoreOf(f.cvss3, f.cvss3v, false);
  const v2 = scoreOf(f.cvss2, f.cvss2v, true);
  const cves = extractCves(f.cves);
  const base = {
    asset: { key: "", ip, fqdn, name: assetLabel, os: str(f.os), kind: f.kind || "host", aggregate: !!f.aggregate },
    vuln: {
      key: "", cve: "", cves, title: str(f.title), pluginId: str(f.pluginId), scanner: f.scanner, severityScanner: sevScanner,
      cvss3: { score: v3, vector: str(f.cvss3v) }, cvss2: v2, cvss2Vector: str(f.cvss2v),
      published: isoDay(parseTs(f.published)), firstSeen: parseTs(f.firstSeen), lastSeen: parseTs(f.lastSeen), lastFixed: parseTs(f.lastFixed),
      firstSeenBasis: f.firstSeen ? "scanner" : f.scanTime ? "scan date" : "", status: f.status ? normStatus(f.status) : "open",
      port: /^0?$/.test(str(f.port)) ? "" : str(f.port), protocol: lc(f.protocol), package: str(f.package), installed: str(f.installed),
      fixedVersion: str(f.fixedVersion), exploitAvailable: f.exploit == null ? null : !!f.exploit, solution: str(f.solution).slice(0, 2000),
      output: str(f.output).slice(0, 2000), references: str(f.references).slice(0, 1000), exposedDevices: f.exposedDevices == null ? null : num(f.exposedDevices),
    },
    file: f.file || "",
  };
  if (!base.vuln.firstSeen && f.scanTime) base.vuln.firstSeen = f.scanTime;
  if (!base.vuln.lastSeen && (f.scanTime || base.vuln.firstSeen)) base.vuln.lastSeen = f.scanTime || base.vuln.firstSeen;
  if (!base.vuln.title && !cves.length && !base.vuln.pluginId) return [];
  const keys = cves.length ? cves : [""];
  return keys.map((cve) => ({ asset: { ...base.asset }, vuln: { ...base.vuln, cve, key: cve || f.scanner + ":" + (base.vuln.pluginId || base.vuln.title) }, file: base.file }));
}

// ---------------------------------------------------------------------------
// XML element streaming: cut <tag ...>...</tag> slices (nesting-aware) so each host / result
// is parsed on its own instead of building one tree for the whole file.
// ---------------------------------------------------------------------------
function findOpen(text, open, pos) {
  for (;;) {
    const i = text.indexOf(open, pos);
    if (i < 0) return -1;
    const c = text[i + open.length];
    if (c === " " || c === ">" || c === "/" || c === "\n" || c === "\r" || c === "\t") return i;
    pos = i + 1;
  }
}
/** Yield { xml } per element, or { skip, bytes } for one above MAX_ELEMENT_BYTES. */
export function* xmlElements(text, tag, max = MAX_ELEMENT_BYTES) {
  const open = "<" + tag, close = "</" + tag + ">";
  let pos = 0;
  for (;;) {
    const i = findOpen(text, open, pos);
    if (i < 0) return;
    const gt = text.indexOf(">", i);
    if (gt < 0) return;
    if (text[gt - 1] === "/") { yield { xml: text.slice(i, gt + 1) }; pos = gt + 1; continue; }
    let depth = 1, p = gt + 1;
    while (depth > 0) {
      const o = findOpen(text, open, p), c = text.indexOf(close, p);
      if (c < 0) return;
      if (o >= 0 && o < c) { const g = text.indexOf(">", o); if (text[g - 1] !== "/") depth++; p = g + 1; }
      else { depth--; p = c + close.length; }
    }
    if (p - i > max) yield { skip: true, bytes: p - i }; else yield { xml: text.slice(i, p) };
    pos = p;
  }
}
const kid = (node, tag) => (node && node.children ? node.children.find((c) => c.tag === tag) || null : null);
const kidText = (node, tag) => { const k = kid(node, tag); return k ? xmlText(k) : ""; };
const kids = (node, tag) => (node && node.children ? node.children.filter((c) => c.tag === tag) : []);

// ---------------------------------------------------------------------------
// Format parsers. Each returns { records, notes[] } and never throws on bad rows.
// ---------------------------------------------------------------------------
function parseNessus(text, file, progress) {
  const records = [], notes = [];
  let n = 0;
  for (const el of xmlElements(text, "ReportHost")) {
    if (el.skip) { notes.push("one ReportHost element of " + Math.round(el.bytes / 1048576) + " MB exceeds the 50 MB per-element limit and was skipped"); continue; }
    const host = xmlLite(el.xml);
    const tags = {};
    for (const t of xmlFindAll(kid(host, "HostProperties"), "tag")) tags[t.attrs.name] = xmlText(t);
    const scanTime = tags.HOST_END_TIMESTAMP ? Number(tags.HOST_END_TIMESTAMP) * 1000 : parseTs(tags.HOST_END) || parseTs(tags.HOST_START) || null;
    const hn = str(host.attrs.name);
    for (const it of kids(host, "ReportItem")) {
      if (++n % 1000 === 0) progress?.(n, 0, "Nessus items");
      const a = it.attrs;
      const exploit = kidText(it, "exploit_available") ? truthy(kidText(it, "exploit_available")) : /exploits are available/i.test(kidText(it, "exploitability_ease")) ? true : null;
      records.push(...mkRecords({
        scanner: "Nessus", file, kind: "host", ip: tags["host-ip"] || hn, fqdn: tags["host-fqdn"], name: tags["netbios-name"] || hn, os: tags["operating-system"],
        pluginId: a.pluginID, title: a.pluginName, severity: normSeverity(a.severity, "nessus"), port: a.port, protocol: a.protocol,
        cves: kids(it, "cve").map(xmlText), cvss3: kidText(it, "cvss3_base_score"), cvss3v: kidText(it, "cvss3_vector"),
        cvss2: kidText(it, "cvss_base_score"), cvss2v: kidText(it, "cvss_vector"), published: kidText(it, "vuln_publication_date"),
        solution: kidText(it, "solution"), output: kidText(it, "plugin_output") || kidText(it, "synopsis"), references: kids(it, "see_also").map(xmlText).join(" "),
        exploit, scanTime,
      }));
    }
  }
  return { records, notes };
}

function parseQualysXml(text, file) {
  const records = [], notes = [];
  const glossary = new Map();
  for (const el of xmlElements(text, "VULN_DETAILS")) {
    if (el.skip) continue;
    const d = xmlLite(el.xml);
    const qid = str(kidText(d, "QID") || d.attrs.id).replace(/^qid_/i, "");
    glossary.set(qid, {
      title: kidText(d, "TITLE"), severity: kidText(d, "SEVERITY"), cves: xmlFindAll(d, "ID").map(xmlText),
      cvss2: xmlText(xmlFind(kid(d, "CVSS_SCORE"), "CVSS_BASE")), cvss3: xmlText(xmlFind(kid(d, "CVSS3_SCORE"), "CVSS3_BASE")), solution: kidText(d, "SOLUTION"),
    });
  }
  for (const el of xmlElements(text, "HOST")) {
    if (el.skip) { notes.push("one HOST element exceeds the 50 MB per-element limit and was skipped"); continue; }
    const h = xmlLite(el.xml);
    const ip = kidText(h, "IP"), dns = kidText(h, "DNS"), nb = kidText(h, "NETBIOS"), os = kidText(h, "OPERATING_SYSTEM") || kidText(h, "OS");
    const items = [...xmlFindAll(h, "VULN_INFO"), ...xmlFindAll(h, "DETECTION")];
    for (const v of items) {
      const qidNode = kid(v, "QID");
      const qid = str(xmlText(qidNode) || (qidNode && qidNode.attrs.id)).replace(/^qid_/i, "");
      const g = glossary.get(qid) || {};
      const type = lc(kidText(v, "TYPE"));
      const info = /^(ig|info|information gathered|practice)$/.test(type);
      const ownCves = xmlFindAll(kid(v, "CVE_ID_LIST"), "ID").map(xmlText);
      records.push(...mkRecords({
        scanner: "Qualys", file, kind: "host", ip, fqdn: dns || kidText(v, "FQDN"), name: nb || dns || ip, os,
        pluginId: "QID " + qid, title: kidText(v, "TITLE") || g.title || "QID " + qid,
        severity: info ? "info" : normSeverity(kidText(v, "SEVERITY") || g.severity, "qualys"),
        port: kidText(v, "PORT"), protocol: kidText(v, "PROTOCOL"), cves: ownCves.length ? ownCves : g.cves || [],
        cvss2: g.cvss2, cvss3: g.cvss3, solution: g.solution,
        firstSeen: kidText(v, "FIRST_FOUND") || kidText(v, "FIRST_FOUND_DATETIME"), lastSeen: kidText(v, "LAST_FOUND") || kidText(v, "LAST_FOUND_DATETIME"),
        lastFixed: kidText(v, "LAST_FIXED_DATETIME"), status: kidText(v, "VULN_STATUS") || kidText(v, "STATUS"), output: kidText(v, "RESULT") || kidText(v, "RESULTS"),
      }));
    }
  }
  return { records, notes };
}

function splitTags(s) {
  const o = {};
  for (const part of str(s).split("|")) { const i = part.indexOf("="); if (i > 0) o[part.slice(0, i).trim()] = part.slice(i + 1).trim(); }
  return o;
}
function parseOpenvasXml(text, file, progress) {
  const records = [], notes = [];
  let n = 0;
  for (const el of xmlElements(text, "result")) {
    if (el.skip) { notes.push("one result element exceeds the 50 MB per-element limit and was skipped"); continue; }
    const r = xmlLite(el.xml);
    const nvt = kid(r, "nvt");
    if (!nvt) continue;
    if (++n % 1000 === 0) progress?.(n, 0, "OpenVAS results");
    const host = kid(r, "host");
    const tags = splitTags(kidText(nvt, "tags"));
    const sevs = xmlFindAll(kid(nvt, "severities"), "severity");
    const v3sev = sevs.find((s) => /v3/.test(s.attrs.type || ""));
    const vecTag = tags.cvss_base_vector || "";
    const v3 = v3sev ? kidText(v3sev, "value") : /^CVSS:3/.test(vecTag) ? vecTag : "";
    const v2 = !/^CVSS:3/.test(vecTag) ? vecTag : "";
    const port = str(kidText(r, "port"));
    const pm = port.match(/^(\d+)\/(\w+)/);
    const cves = xmlFindAll(kid(nvt, "refs"), "ref").filter((x) => lc(x.attrs.type) === "cve").map((x) => x.attrs.id);
    const sevNum = num(kidText(r, "severity"));
    const threat = kidText(r, "threat");
    records.push(...mkRecords({
      scanner: "OpenVAS", file, kind: "host", ip: host ? host.text : "", fqdn: kidText(host, "hostname"), name: kidText(host, "hostname") || (host ? host.text : ""),
      pluginId: nvt.attrs.oid, title: kidText(nvt, "name") || kidText(r, "name"),
      severity: /^log$/i.test(threat) ? "info" : normSeverity(threat) || severityFromScore(sevNum),
      port: pm ? pm[1] : "", protocol: pm ? pm[2] : (port.split("/")[1] || ""), cves: cves.length ? cves : kidText(nvt, "cve"),
      cvss3: v3 ? sevNum : null, cvss3v: v3, cvss2: v3 ? null : kidText(nvt, "cvss_base") || sevNum, cvss2v: v2,
      solution: tags.solution || xmlText(kid(nvt, "solution")), output: kidText(r, "description"),
      firstSeen: kidText(r, "creation_time"), lastSeen: kidText(r, "modification_time") || kidText(r, "creation_time"),
    }));
  }
  return { records, notes };
}

// ---------------------------------------------------------------------------
// CSV formats: vendor column aliases + row builder
// ---------------------------------------------------------------------------
const CSV_SPECS = {
  "tenable-csv": {
    cols: {
      pluginId: ["Plugin ID", "Plugin"], cve: ["CVE"], cvss2: ["CVSS v2.0 Base Score", "CVSS V2 Base Score", "CVSS"], risk: ["Risk", "Risk Factor", "Severity"],
      host: ["Host", "IP Address"], fqdn: ["DNS Name", "FQDN"], netbios: ["NetBIOS Name"], protocol: ["Protocol"], port: ["Port"], title: ["Name", "Plugin Name"],
      synopsis: ["Synopsis"], solution: ["Solution"], refs: ["See Also"], output: ["Plugin Output", "Plugin Text"], cvss3: ["CVSS v3.0 Base Score", "CVSS V3 Base Score"],
      cvss3v: ["CVSS V3 Vector", "CVSS v3.0 Vector"], cvss2v: ["CVSS V2 Vector", "CVSS v2.0 Vector"], published: ["Vuln Publication Date", "Plugin Publication Date"],
      firstSeen: ["First Discovered", "First Seen"], lastSeen: ["Last Observed", "Last Seen"], exploit: ["Exploit?", "Exploit Available"],
      msf: ["Metasploit"], core: ["Core Impact"], canvas: ["CANVAS"], os: ["Operating System", "OS"], uuid: ["Asset UUID"],
    },
    build: (g) => ({
      scanner: "Tenable", kind: "host", ip: g("host"), fqdn: g("fqdn"), name: g("netbios") || g("host"), os: g("os"), pluginId: g("pluginId"), title: g("title"),
      severity: normSeverity(g("risk")), cves: g("cve"), cvss2: g("cvss2"), cvss2v: g("cvss2v"), cvss3: g("cvss3"), cvss3v: g("cvss3v"), port: g("port"), protocol: g("protocol"),
      solution: g("solution"), output: g("output") || g("synopsis"), references: g("refs"), published: g("published"), firstSeen: g("firstSeen"), lastSeen: g("lastSeen"),
      exploit: ["exploit", "msf", "core", "canvas"].some((k) => truthy(g(k))) ? true : ["exploit", "msf", "core", "canvas"].some((k) => g(k) !== "") ? false : null,
    }),
  },
  "tenable-export": {
    cols: {
      uuid: ["Asset UUID"], ip: ["IP Address"], fqdn: ["FQDN"], pluginId: ["Plugin ID"], title: ["Plugin Name"], sev: ["Severity"], cve: ["CVE"], cvss3: ["CVSSv3 Base Score", "CVSS v3.0 Base Score"],
      state: ["State"], firstSeen: ["First Seen"], lastSeen: ["Last Seen"], lastFixed: ["Last Fixed"], port: ["Port"], protocol: ["Protocol"], solution: ["Solution"], os: ["Operating System"],
    },
    build: (g) => ({
      scanner: "Tenable", kind: "host", ip: g("ip"), fqdn: g("fqdn"), name: g("fqdn") || g("ip") || g("uuid"), os: g("os"), pluginId: g("pluginId"), title: g("title"),
      severity: normSeverity(g("sev")), cves: g("cve"), cvss3: g("cvss3"), status: g("state"), firstSeen: g("firstSeen"), lastSeen: g("lastSeen"), lastFixed: g("lastFixed"),
      port: g("port"), protocol: g("protocol"), solution: g("solution"),
    }),
  },
  "qualys-csv": {
    cols: {
      ip: ["IP"], dns: ["DNS"], netbios: ["NetBIOS"], os: ["OS"], qid: ["QID"], title: ["Title"], status: ["Vuln Status"], type: ["Type"], sev: ["Severity"], port: ["Port"], protocol: ["Protocol"],
      fqdn: ["FQDN"], first: ["First Detected"], last: ["Last Detected"], fixed: ["Date Last Fixed"], cve: ["CVE ID"], cvss: ["CVSS Base", "CVSS"], cvss3: ["CVSS3 Base", "CVSS3"],
      solution: ["Solution"], exploitability: ["Exploitability"], malware: ["Associated Malware"], results: ["Results"], vendorRef: ["Vendor Reference"],
    },
    build: (g) => ({
      scanner: "Qualys", kind: "host", ip: g("ip"), fqdn: g("fqdn") || g("dns"), name: g("netbios") || g("dns") || g("ip"), os: g("os"), pluginId: "QID " + g("qid"), title: g("title"),
      severity: /^(ig|info|practice)/i.test(g("type")) ? "info" : normSeverity(g("sev"), "qualys"), cves: g("cve"), cvss2: g("cvss"), cvss3: g("cvss3"), port: g("port"), protocol: g("protocol"),
      status: g("status"), firstSeen: g("first"), lastSeen: g("last"), lastFixed: g("fixed"), solution: g("solution"), output: g("results"), references: g("vendorRef"),
      exploit: g("exploitability") || g("malware") ? true : null,
    }),
  },
  "greenbone-csv": {
    cols: {
      ip: ["IP"], host: ["Hostname"], port: ["Port"], protocol: ["Port Protocol"], cvss: ["CVSS"], sev: ["Severity"], title: ["NVT Name"], summary: ["Summary"], result: ["Specific Result"],
      oid: ["NVT OID"], cve: ["CVEs"], ts: ["Timestamp"], solution: ["Solution"], os: ["Affected Software/OS"],
    },
    build: (g) => ({
      scanner: "OpenVAS", kind: "host", ip: g("ip"), fqdn: g("host"), name: g("host") || g("ip"), pluginId: g("oid"), title: g("title"),
      severity: /^log$/i.test(g("sev")) ? "info" : normSeverity(g("sev")) || severityFromScore(num(g("cvss"))), cves: g("cve"), cvss2: g("cvss"),
      port: /^\d+$/.test(g("port")) ? g("port") : "", protocol: g("protocol"), firstSeen: g("ts"), lastSeen: g("ts"), solution: g("solution"), output: g("result") || g("summary"),
    }),
  },
  "rapid7-csv": {
    cols: {
      ip: ["Asset IP Address"], names: ["Asset Names"], os: ["Asset OS Name"], title: ["Vulnerability Title"], id: ["Vulnerability ID"], cve: ["Vulnerability CVE IDs"],
      cvss: ["Vulnerability CVSS Score"], cvss3: ["Vulnerability CVSSv3 Score"], sev: ["Vulnerability Severity Level"], port: ["Service Port"], protocol: ["Service Protocol"],
      proof: ["Vulnerability Proof"], solution: ["Vulnerability Solution"], published: ["Vulnerability Published Date"], test: ["Vulnerability Test Date"], since: ["Vulnerable Since"],
      exploits: ["Exploit Count"], malware: ["Malware Kit Count"],
    },
    build: (g) => {
      const name = g("names").split(/[,;]/)[0].trim();
      return {
        scanner: "Rapid7", kind: "host", ip: g("ip"), fqdn: name, name: name || g("ip"), os: g("os"), pluginId: g("id"), title: g("title"),
        severity: normSeverity(g("sev"), "rapid7"), cves: g("cve"), cvss2: g("cvss"), cvss3: g("cvss3"), port: g("port"), protocol: g("protocol"), output: g("proof"), solution: g("solution"),
        published: g("published"), firstSeen: g("since"), lastSeen: g("test"),
        exploit: g("exploits") !== "" || g("malware") !== "" ? (num(g("exploits")) || 0) + (num(g("malware")) || 0) > 0 : null,
      };
    },
  },
  "mdvm-weaknesses": {
    cols: {
      name: ["Name", "CVE"], sev: ["Severity"], cvss: ["CVSS"], exposed: ["Exposed devices"], published: ["Published on"], updated: ["Updated on"],
      threats: ["Threats"], exploit: ["Exploit available", "Exploited in the wild", "Public exploit"], software: ["Software", "Related software"], vendor: ["Vendor"],
    },
    build: (g) => ({
      scanner: "Defender", kind: "device", aggregate: true, name: "Defender exposed devices: " + (g("software") || "unspecified software"), assetName: "Defender exposed devices: " + (g("software") || "unspecified software"),
      title: g("name"), cves: g("name"), severity: normSeverity(g("sev")), cvss3: g("cvss"), published: g("published"), lastSeen: g("updated"), package: g("software"),
      exposedDevices: g("exposed"), exploit: truthy(g("exploit")) || /exploit/i.test(g("threats")) ? true : g("exploit") !== "" ? false : null,
    }),
  },
  "mdvm-device": {
    cols: {
      device: ["Device name"], id: ["Device ID"], os: ["OS Platform"], cve: ["CVE"], sev: ["Severity"], cvss: ["CVSS Score", "CVSS"], software: ["Software Name"], vendor: ["Software Vendor"],
      version: ["Software Version"], fixed: ["Fixed version?", "Fixed version"], update: ["Recommended security update"], first: ["First seen"], last: ["Last seen"],
    },
    build: (g) => ({
      scanner: "Defender", kind: "device", name: g("device") || g("id"), os: g("os"), title: g("cve") + (g("software") ? " in " + g("software") : ""), cves: g("cve"),
      severity: normSeverity(g("sev")), cvss3: g("cvss"), package: g("software"), installed: g("version"), fixedVersion: /^(no|false|-)$/i.test(g("fixed")) ? "" : g("fixed"),
      solution: g("update"), firstSeen: g("first"), lastSeen: g("last"),
    }),
  },
  "mdvm-hunting": {
    cols: {
      id: ["DeviceId"], device: ["DeviceName"], os: ["OSPlatform"], vendor: ["SoftwareVendor"], software: ["SoftwareName"], version: ["SoftwareVersion"], cve: ["CveId"],
      sev: ["VulnerabilitySeverityLevel"], update: ["RecommendedSecurityUpdate"], updateId: ["RecommendedSecurityUpdateId"],
    },
    build: (g) => ({
      scanner: "Defender", kind: "device", name: g("device") || g("id"), os: g("os"), title: g("cve") + (g("software") ? " in " + g("software") : ""), cves: g("cve"),
      severity: normSeverity(g("sev")), package: g("software"), installed: g("version"), solution: [g("update"), g("updateId")].filter(Boolean).join(" "),
    }),
  },
  generic: {
    cols: COLUMNS,
    build: (g) => {
      const sev = normSeverity(g("severity"));
      return {
        scanner: "Generic", kind: "host", name: g("asset"), cves: g("cve"), title: g("title") || g("cve"), pluginId: extractCves(g("cve")).length ? "" : g("cve"),
        severity: sev || severityFromScore(num(g("cvss"))), cvss3: g("cvss"), firstSeen: g("first_seen"), lastSeen: g("last_seen"), status: g("status"), port: g("port"), solution: g("solution"),
      };
    },
  },
};

/** Recognise a vendor CSV by its column signature. */
export function classifyHeaders(headers) {
  const H = new Set((headers || []).map(normHeader));
  const has = (...k) => k.every((x) => H.has(x));
  if (has("assetuuid", "pluginid", "state")) return { format: "tenable-export", confidence: 0.95 };
  if (has("pluginid") && (H.has("host") || H.has("ipaddress"))) return { format: "tenable-csv", confidence: 0.95 };
  if (has("qid") && (H.has("ip") || H.has("ipaddress"))) return { format: "qualys-csv", confidence: 0.95 };
  if (H.has("nvtoid") || has("nvtname", "ip")) return { format: "greenbone-csv", confidence: 0.95 };
  if (has("assetipaddress") && (H.has("vulnerabilityid") || H.has("vulnerabilitytitle"))) return { format: "rapid7-csv", confidence: 0.95 };
  if (has("deviceid", "cveid")) return { format: "mdvm-hunting", confidence: 0.95 };
  if (has("devicename", "cve")) return { format: "mdvm-device", confidence: 0.9 };
  if (H.has("exposeddevices")) return { format: "mdvm-weaknesses", confidence: 0.9 };
  const asset = findColumn(headers, COLUMNS.asset), id = findColumn(headers, COLUMNS.cve) || findColumn(headers, COLUMNS.title);
  return { format: "generic", confidence: asset && id ? 0.6 : 0.3 };
}

// Qualys and some Tenable.sc reports put a preamble above the column row: find the header line.
function locateHeader(text) {
  let pos = 0;
  for (let i = 0; i < 80 && pos < text.length; i++) {
    const nl = text.indexOf("\n", pos);
    const line = text.slice(pos, nl < 0 ? text.length : nl);
    if (line.trim()) {
      const h = parseCsv(line).headers;
      if (h.length >= 3 && classifyHeaders(h).format !== "generic") return pos;
    }
    if (nl < 0) break;
    pos = nl + 1;
  }
  return 0;
}

function parseCsvFormat(text, file, columns, progress) {
  const start = locateHeader(text);
  const body = start ? text.slice(start) : text;
  const nl = body.indexOf("\n");
  const headers = parseCsv(nl < 0 ? body : body.slice(0, nl)).headers;
  const cls = classifyHeaders(headers);
  const spec = CSV_SPECS[cls.format];
  const map = {};
  for (const [k, aliases] of Object.entries(spec.cols)) {
    const forced = cls.format === "generic" && columns && columns[k];
    const h = forced && headers.includes(columns[k]) ? columns[k] : findColumn(headers, aliases);
    if (h) map[k] = h;
  }
  const notes = [];
  const records = [];
  if (cls.format === "generic" && (!map.asset || !(map.cve || map.title))) {
    notes.push("generic CSV needs an asset column and a CVE or title column; map them in the column-mapping panel");
    return { records, notes, headers, format: cls.format, confidence: cls.confidence, map };
  }
  const { rows } = parseCsv(body);
  let n = 0;
  for (const row of rows) {
    if (++n % 1000 === 0) progress?.(n, rows.length, "rows");
    const g = (k) => (map[k] ? str(row[map[k]]) : "");
    records.push(...mkRecords({ ...spec.build(g), file }));
  }
  return { records, notes, headers, format: cls.format, confidence: cls.confidence, map };
}

// ---------------------------------------------------------------------------
// JSON formats
// ---------------------------------------------------------------------------
const pickScore = (cvssObj) => {
  if (!cvssObj || typeof cvssObj !== "object") return { score: null, vector: "" };
  const order = ["nvd", "ghsa", "redhat", ...Object.keys(cvssObj).sort()];
  for (const k of order) { const c = cvssObj[k]; if (c && (c.V3Score != null || c.V3Vector)) return { score: c.V3Score, vector: c.V3Vector || "", v2: c.V2Score, v2v: c.V2Vector }; }
  for (const k of order) { const c = cvssObj[k]; if (c && (c.V2Score != null || c.V2Vector)) return { score: null, vector: "", v2: c.V2Score, v2v: c.V2Vector }; }
  return { score: null, vector: "" };
};

function parseTrivy(o, file) {
  const records = [];
  const art = str(o.ArtifactName);
  const image = /container_image/i.test(str(o.ArtifactType)) || (!o.ArtifactType && /[:@]/.test(art) && !/[\\/]$/.test(art) && !/\.\w+$/.test(art));
  const osMeta = o.Metadata && o.Metadata.OS ? [o.Metadata.OS.Family, o.Metadata.OS.Name].filter(Boolean).join(" ") : "";
  const scanTime = parseTs(o.CreatedAt);
  for (const res of o.Results || []) {
    const osFromTarget = (str(res.Target).match(/\(([a-z-]+ [\d.]+)\)\s*$/i) || [])[1] || "";
    for (const v of res.Vulnerabilities || []) {
      const c = pickScore(v.CVSS);
      records.push(...mkRecords({
        scanner: "Trivy", file, kind: image ? "image" : "package", name: art || res.Target, os: osMeta || osFromTarget, pluginId: v.VulnerabilityID,
        title: v.Title || v.VulnerabilityID, cves: v.VulnerabilityID + " " + (v.VendorIDs || []).join(" "), severity: normSeverity(v.Severity),
        cvss3: c.score, cvss3v: c.vector, cvss2: c.v2, cvss2v: c.v2v, package: v.PkgName, installed: v.InstalledVersion, fixedVersion: v.FixedVersion,
        published: v.PublishedDate, references: (v.References || []).slice(0, 5).join(" ") || v.PrimaryURL, output: str(v.Description).slice(0, 600), scanTime,
        solution: v.FixedVersion ? "Upgrade " + v.PkgName + " to " + v.FixedVersion : "",
        status: /fixed|affected|will_not_fix|fix_deferred|end_of_life/i.test(str(v.Status)) ? "open" : "",
      }));
    }
  }
  return { records, notes: [] };
}

function parseGrype(o, file) {
  const records = [];
  const src = o.source || {};
  const t = src.target;
  const name = typeof t === "string" ? t : t ? t.userInput || t.imageID || t.path || "" : "";
  const kind = lc(src.type) === "image" ? "image" : "package";
  const os = o.distro ? [o.distro.name, o.distro.version].filter(Boolean).join(" ") : "";
  for (const m of o.matches || []) {
    const v = m.vulnerability || {}, a = m.artifact || {};
    const cv = (v.cvss || []).slice().sort((x, y) => cmp(str(y.version), str(x.version)))[0] || {};
    const related = (m.relatedVulnerabilities || []).map((r) => r.id);
    const fix = v.fix || {};
    records.push(...mkRecords({
      scanner: "Grype", file, kind, name: name || a.name, os, pluginId: v.id, title: v.id + " in " + str(a.name), cves: [v.id, ...related].join(" "),
      severity: normSeverity(v.severity), cvss3: /^3/.test(str(cv.version)) ? cv.metrics && cv.metrics.baseScore : null, cvss3v: /^3/.test(str(cv.version)) ? cv.vector : "",
      cvss2: /^2/.test(str(cv.version)) ? cv.metrics && cv.metrics.baseScore : null, package: a.name, installed: a.version, fixedVersion: (fix.versions || []).join(", "),
      output: (a.locations || []).map((l) => l.path).filter(Boolean).slice(0, 5).join(" "), references: (v.urls || []).slice(0, 5).join(" ") || v.dataSource,
      solution: (fix.versions || []).length ? "Upgrade " + a.name + " to " + fix.versions.join(" or ") : "",
    }));
  }
  return { records, notes: [] };
}

function parseSnyk(list, file) {
  const records = [];
  for (const o of list) {
    const project = str(o.projectName || o.displayTargetFile || o.path || file);
    const kind = o.docker || /^docker-image|^deb$|^apk$|^rpm$/.test(str(o.packageManager)) ? "image" : "package";
    for (const v of o.vulnerabilities || []) {
      const ids = v.identifiers || {};
      const fixed = (v.fixedIn || []).join(", ");
      records.push(...mkRecords({
        scanner: "Snyk", file, kind, name: project, pluginId: v.id, title: v.title, cves: (ids.CVE || []).join(" "), severity: normSeverity(v.severity),
        cvss3: v.cvssScore, cvss3v: v.CVSSv3, package: v.packageName, installed: v.version, fixedVersion: fixed, published: v.publicationTime,
        exploit: v.exploit ? truthy(v.exploit) : null, solution: fixed ? "Upgrade " + v.packageName + " to " + fixed : v.isPatchable ? "Apply the Snyk patch" : "",
        output: (v.from || []).join(" > "),
      }));
    }
  }
  return { records, notes: [] };
}

function parseSarif(o, file) {
  const records = [], notes = [];
  let noCve = 0;
  for (const run of o.runs || []) {
    const rules = new Map(((run.tool && run.tool.driver && run.tool.driver.rules) || []).map((r) => [r.id, r]));
    const project = str((run.automationDetails && run.automationDetails.id) || (run.properties && run.properties.imageName) || file);
    for (const r of run.results || []) {
      const rule = rules.get(r.ruleId) || {};
      const msg = str(r.message && r.message.text);
      const cves = extractCves([r.ruleId, rule.id, rule.name, msg].join(" "));
      if (!cves.length) { noCve++; continue; }
      const sec = num(rule.properties && rule.properties["security-severity"]);
      const loc = r.locations && r.locations[0] && r.locations[0].physicalLocation && r.locations[0].physicalLocation.artifactLocation;
      records.push(...mkRecords({
        scanner: "SARIF", file, kind: "package", name: project, pluginId: r.ruleId, title: str(rule.shortDescription && rule.shortDescription.text) || msg.slice(0, 160) || r.ruleId,
        cves: cves.join(" "), severity: sec != null ? severityFromScore(sec) : normSeverity({ error: "high", warning: "medium", note: "low" }[r.level] || r.level), cvss3: sec,
        output: (loc ? loc.uri + ": " : "") + msg.slice(0, 600), solution: str(rule.help && rule.help.text).slice(0, 600),
      }));
    }
  }
  if (noCve) notes.push(noCve + " SARIF result(s) without a CVE id were not imported (this register tracks CVE-identified vulnerabilities)");
  return { records, notes };
}

function parseBaseline(o, file) {
  const rows = (o.tables && Array.isArray(o.tables.vulns) && o.tables.vulns) || (Array.isArray(o.register) && o.register) || [];
  const records = [];
  for (const r of rows) {
    if (!r || typeof r !== "object" || !(r.assetName || r.ip || r.fqdn)) continue;
    records.push({
      asset: { key: "", ip: str(r.ip), fqdn: lc(r.fqdn), name: str(r.assetName || r.fqdn || r.ip), os: str(r.os), kind: str(r.kind) || "host", aggregate: !!r.aggregate },
      vuln: {
        key: str(r.vulnKey || r.cve), cve: str(r.cve), cves: extractCves(r.cve), title: str(r.title), pluginId: str(r.pluginId), scanner: str(r.scanners).split(/;\s*/)[0] || "vulnimport",
        severityScanner: normSeverity(r.severity), cvss3: { score: num(r.cvss), vector: str(r.cvssVector) }, cvss2: null, cvss2Vector: "", published: str(r.published),
        firstSeen: parseTs(r.firstSeen), lastSeen: parseTs(r.lastSeen), lastFixed: parseTs(r.lastFixed), firstSeenBasis: str(r.firstSeenBasis) || "baseline",
        status: normStatus(r.status), port: str(r.port), protocol: str(r.protocol), package: str(r.package), installed: str(r.installed), fixedVersion: str(r.fixedVersion),
        exploitAvailable: r.exploit === true || r.exploit === "yes" ? true : r.exploit === false || r.exploit === "no" ? false : null, solution: str(r.solution),
        output: "", references: "", exposedDevices: null,
      },
      file,
    });
  }
  return { records, notes: rows.length ? [] : ["vulnimport JSON has no register rows"] };
}

/** Detect one file's format by content. */
export function detectFormat(text) {
  const s = String(text || "").replace(/^﻿/, "");
  const head = s.slice(0, 65536);
  const t = head.trimStart();
  if (t[0] === "<") {
    if (head.includes("<NessusClientData_v2")) return { format: "nessus-xml", confidence: 1 };
    if (/<(ASSET_DATA_REPORT|HOST_LIST_VM_DETECTION_OUTPUT|SCAN\b|HOST_LIST)/.test(head) || head.includes("<VULN_INFO") || head.includes("<DETECTION")) return { format: "qualys-xml", confidence: 0.95 };
    if (/<report[\s>]/.test(head) && (head.includes("<nvt") || head.includes("<results") || head.includes("<result "))) return { format: "openvas-xml", confidence: 0.95 };
    return { format: "unknown", confidence: 0 };
  }
  if (t[0] === "{" || t[0] === "[") {
    let o;
    try { o = JSON.parse(s); } catch (_) { return { format: "unknown", confidence: 0 }; }
    if (o && o.meta && o.meta.tool === TOOL_ID) return { format: "baseline", confidence: 1, json: o };
    if (o && Array.isArray(o.Results) || (o && o.SchemaVersion && o.ArtifactName)) return { format: "trivy", confidence: 1, json: o };
    if (o && Array.isArray(o.matches)) return { format: "grype", confidence: 1, json: o };
    if (o && Array.isArray(o.runs) && (o.version === "2.1.0" || /sarif/i.test(str(o.$schema)))) return { format: "sarif", confidence: 1, json: o };
    if (o && Array.isArray(o.vulnerabilities)) return { format: "snyk", confidence: 0.95, json: [o] };
    if (Array.isArray(o) && o.length && o.every((x) => x && Array.isArray(x.vulnerabilities))) return { format: "snyk", confidence: 0.95, json: o };
    return { format: "unknown", confidence: 0 };
  }
  const nl = s.indexOf("\n");
  if (nl < 0 && !s.includes(",")) return { format: "unknown", confidence: 0 };
  const start = locateHeader(s);
  const e = s.indexOf("\n", start);
  return classifyHeaders(parseCsv(s.slice(start, e < 0 ? s.length : e)).headers);
}

function parseOne(name, text, columns, progress) {
  const s = String(text || "").replace(/^﻿/, "");
  const det = detectFormat(s);
  let out;
  switch (det.format) {
    case "nessus-xml": out = parseNessus(s, name, progress); break;
    case "qualys-xml": out = parseQualysXml(s, name); break;
    case "openvas-xml": out = parseOpenvasXml(s, name, progress); break;
    case "trivy": out = parseTrivy(det.json, name); break;
    case "grype": out = parseGrype(det.json, name); break;
    case "snyk": out = parseSnyk(det.json, name); break;
    case "sarif": out = parseSarif(det.json, name); break;
    case "baseline": out = parseBaseline(det.json, name); break;
    case "unknown": return { file: { name, format: "unknown", label: "Not recognised", scanner: "", confidence: 0, records: 0, headers: [], notes: ["format not recognised"] }, records: [] };
    default: {
      const r = parseCsvFormat(s, name, columns, progress);
      return { file: { name, format: r.format, label: FORMATS[r.format].label, scanner: FORMATS[r.format].scanner, confidence: r.confidence, records: r.records.length, headers: r.headers, map: r.map, notes: r.notes }, records: r.records };
    }
  }
  return { file: { name, format: det.format, label: FORMATS[det.format].label, scanner: FORMATS[det.format].scanner, confidence: det.confidence, records: out.records.length, headers: [], notes: out.notes }, records: out.records };
}

/**
 * Parse one or more exports. input: text | {name, text, role?} | array of those.
 * role "baseline" marks the previous import; this tool's own JSON is a baseline by default.
 * Returns { format, confidence, headers, rows (normalised records, each with .role), skipped, files }.
 */
export function parseInput(input, opts = {}, ctx) {
  const list = Array.isArray(input) ? input : input == null || input === "" ? [] : [input];
  const files = [], rows = [], skipped = [];
  let i = 0;
  for (const it of list) {
    i++;
    const name = it && typeof it === "object" ? str(it.name) || "file " + i : "file " + i;
    const text = it && typeof it === "object" ? it.text : it;
    if (!str(text)) { skipped.push({ check: "parse", reason: name + ": empty" }); continue; }
    let r;
    try { r = parseOne(name, text, opts.columns, ctx && ctx.progress); } catch (e) { skipped.push({ check: "parse", reason: name + ": " + ((e && e.message) || e) }); continue; }
    const role = it && typeof it === "object" && (it.role === "baseline" || it.role === "current") ? it.role : r.file.format === "baseline" ? "baseline" : "current";
    r.file.role = role;
    files.push(r.file);
    for (const n of r.file.notes || []) skipped.push({ check: "parse", reason: name + ": " + n });
    if (!r.records.length && !(r.file.notes || []).length) skipped.push({ check: "parse", reason: name + ": no vulnerability records recognised" });
    for (const rec of r.records) { rec.role = role; rows.push(rec); }
  }
  const format = files.length === 1 ? files[0].format : files.length ? "multi" : "empty";
  const confidence = files.length ? Math.min(...files.map((f) => f.confidence)) : 0;
  return { format, confidence, headers: files.length === 1 ? files[0].headers : [], rows, skipped, files };
}

// ---------------------------------------------------------------------------
// Asset identity: records sharing an IP or FQDN are one asset; a record that only has a
// short host / device name joins an asset only when exactly one known asset has that name.
// ---------------------------------------------------------------------------
function resolveAssets(rows) {
  const parent = new Map();
  const find = (x) => { let r = x; while (parent.get(r) !== r) r = parent.get(r); let c = x; while (parent.get(c) !== r) { const n = parent.get(c); parent.set(c, r); c = n; } return r; };
  const add = (x) => { if (!parent.has(x)) parent.set(x, x); return x; };
  const union = (a, b) => { const ra = find(a), rb = find(b); if (ra !== rb) { if (ra < rb) parent.set(rb, ra); else parent.set(ra, rb); } };
  const objKind = (a) => a.aggregate || a.kind === "image" || a.kind === "package";
  const ids = rows.map((r) => {
    const a = r.asset;
    if (objKind(a)) return { strong: [add("obj:" + a.kind + ":" + lc(a.name))], short: "" };
    const strong = [];
    if (a.ip) strong.push(add("ip:" + a.ip));
    if (a.fqdn) strong.push(add("fqdn:" + a.fqdn));
    const short = lc(a.name).split(".")[0];
    if (!strong.length && short) strong.push(add("name:" + short));
    return { strong, short: a.ip || a.fqdn ? "" : short, labels: [short, a.fqdn ? a.fqdn.split(".")[0] : ""].filter((l) => l && /\D/.test(l)) };
  });
  ids.forEach((x) => { for (let i = 1; i < x.strong.length; i++) union(x.strong[0], x.strong[i]); });
  const byShort = new Map();
  ids.forEach((x) => { if (x.short) return; for (const l of x.labels || []) { if (!byShort.has(l)) byShort.set(l, new Set()); byShort.get(l).add(x.strong[0]); } });
  ids.forEach((x) => {
    if (!x.short) return;
    const roots = new Set([...(byShort.get(x.short) || [])].map(find));
    if (roots.size === 1) union(x.strong[0], [...roots][0]);
  });
  const comp = new Map();
  rows.forEach((r, i) => { const root = find(ids[i].strong[0]); if (!comp.has(root)) comp.set(root, []); comp.get(root).push(i); });
  for (const members of comp.values()) {
    const as = members.map((i) => rows[i].asset);
    const fq = uniqSorted(as.map((a) => a.fqdn)), ips = uniqSorted(as.map((a) => a.ip)), names = uniqSorted(as.map((a) => a.name).filter((n) => !isIp(n)));
    const oses = uniqSorted(as.map((a) => a.os)).sort((x, y) => y.length - x.length || cmp(x, y));
    const kinds = uniqSorted(as.map((a) => a.kind));
    const key = objKindKey(as[0]) || fq[0] || ips[0] || lc(names[0]);
    const merged = { key, ip: ips[0] || "", ips, fqdn: fq[0] || "", name: fq[0] || names[0] || ips[0] || key, os: oses[0] || "", kind: kinds.includes("host") ? "host" : kinds[0] || "host", aggregate: as.some((a) => a.aggregate) };
    for (const i of members) rows[i].asset = merged;
  }
  function objKindKey(a) { return objKind(a) ? a.kind + ":" + a.name : ""; }
}

const STATUS_RANK = { reopened: 3, open: 2, unknown: 1, fixed: 0 };
// Package part: Maven group:artifact and path-style names reduce to the artifact so Trivy and Grype agree.
const dedupeKey = (r) => r.asset.key + "|" + r.vuln.key + "|" + (r.vuln.port ? lc(r.vuln.port) : lc(r.vuln.package).split(/[:/]/).pop());

/** Merge records sharing asset + CVE/plugin + port/package. */
function mergeRecords(rows) {
  const out = new Map();
  const sorted = rows.slice().sort((a, b) => cmp(a.vuln.scanner, b.vuln.scanner) || cmp(a.file, b.file) || cmp(a.vuln.pluginId, b.vuln.pluginId));
  for (const r of sorted) {
    const k = dedupeKey(r);
    const v = r.vuln;
    let m = out.get(k);
    if (!m) {
      m = { key: k, asset: r.asset, v: { ...v, cves: v.cves.slice(), pluginIds: v.pluginId ? [v.pluginId] : [], scanners: [v.scanner], severities: v.severityScanner ? { [v.scanner]: v.severityScanner } : {}, files: [r.file] }, statusAt: v.lastSeen || 0 };
      out.set(k, m);
      continue;
    }
    const x = m.v;
    if (v.firstSeen != null && (x.firstSeen == null || v.firstSeen < x.firstSeen)) { x.firstSeen = v.firstSeen; x.firstSeenBasis = v.firstSeenBasis; }
    if (v.lastSeen != null && (x.lastSeen == null || v.lastSeen > x.lastSeen)) x.lastSeen = v.lastSeen;
    if (v.lastFixed != null && (x.lastFixed == null || v.lastFixed > x.lastFixed)) x.lastFixed = v.lastFixed;
    const at = v.lastSeen || 0;
    if (at > m.statusAt || (at === m.statusAt && STATUS_RANK[v.status] > STATUS_RANK[x.status])) { x.status = v.status; m.statusAt = at; }
    if (!x.scanners.includes(v.scanner)) x.scanners.push(v.scanner);
    if (v.severityScanner && !x.severities[v.scanner]) x.severities[v.scanner] = v.severityScanner;
    if (!x.files.includes(r.file)) x.files.push(r.file);
    if (v.pluginId && !x.pluginIds.includes(v.pluginId)) x.pluginIds.push(v.pluginId);
    x.cves = uniqSorted([...x.cves, ...v.cves]);
    if (v.cvss3.score != null && (x.cvss3.score == null || v.cvss3.score > x.cvss3.score)) x.cvss3 = { ...v.cvss3 };
    if (v.cvss2 != null && (x.cvss2 == null || v.cvss2 > x.cvss2)) x.cvss2 = v.cvss2;
    if (v.exploitAvailable === true || (x.exploitAvailable == null && v.exploitAvailable === false)) x.exploitAvailable = v.exploitAvailable;
    if (v.published && (!x.published || v.published < x.published)) x.published = v.published;
    if (v.severityScanner && (!x.severityScanner || SEV_RANK[v.severityScanner] > SEV_RANK[x.severityScanner])) x.severityScanner = v.severityScanner;
    for (const f of ["title", "fixedVersion", "solution", "output", "references", "installed", "protocol", "cvss2Vector"]) if (!x[f] && v[f]) x[f] = v[f];
    if (v.exposedDevices != null) x.exposedDevices = Math.max(x.exposedDevices || 0, v.exposedDevices);
  }
  for (const m of out.values()) { m.v.scanners.sort(cmp); m.v.pluginIds.sort(cmp); m.v.files.sort(cmp); }
  return out;
}

// ---------------------------------------------------------------------------
// Feeds (passed in by the UI; the engine never fetches)
// ---------------------------------------------------------------------------
const feedRows = (f) => (Array.isArray(f) ? f : f && Array.isArray(f.data) ? f.data : f && Array.isArray(f.vulnerabilities) ? f.vulnerabilities : null);
/** CVE -> KEV entry from the mirrored /data/feeds/cisa-kev-index.json (full catalog), cisa-kev.json, or the CISA catalog shape. */
export function kevIndex(feed) {
  const m = new Map();
  for (const e of feedRows(feed) || []) {
    const cve = str(e.cve || e.cveID).toUpperCase();
    if (!cve) continue;
    const rw = str(e.knownRansomwareCampaignUse != null ? e.knownRansomwareCampaignUse : e.ransomware);
    m.set(cve, { dateAdded: str(e.dateAdded), dueDate: str(e.dueDate), ransomware: /^known$|^true$|^yes$/i.test(rw), vendor: str(e.vendor || e.vendorProject), product: str(e.product), name: str(e.name || e.vulnerabilityName) });
  }
  return m;
}
/** CVE -> {epss, percentile} from the mirrored epss-top.json, the FIRST API response, or a plain map. */
export function epssIndex(feed) {
  const m = new Map();
  const rows = feedRows(feed);
  if (rows) { for (const e of rows) { const cve = str(e.cve).toUpperCase(); const p = num(e.epss); if (cve && p != null) m.set(cve, { epss: p, percentile: num(e.percentile) }); } }
  else if (feed && typeof feed === "object") for (const k of Object.keys(feed)) { const e = feed[k]; const p = num(e && typeof e === "object" ? e.epss : e); if (p != null) m.set(k.toUpperCase(), { epss: p, percentile: e && typeof e === "object" ? num(e.percentile) : null }); }
  return m;
}

/** Internet-facing matcher from a regex string, or a list of names / IPs / IPv4 CIDRs. */
export function internetMatcher(spec) {
  if (spec instanceof RegExp) return (a) => [a.ip, a.fqdn, a.name, a.key, ...(a.ips || [])].some((x) => x && spec.test(x));
  const lines = (Array.isArray(spec) ? spec : str(spec).split(/[\r\n,]+/)).map(str).filter(Boolean);
  if (!lines.length) return () => false;
  const tests = [];
  const toInt = (ip) => { const m = ip.match(IPV4); return m ? ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + +m[4] : null; };
  for (const l of lines) {
    const cidr = l.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
    if (cidr) { const base = toInt(cidr[1]), bits = +cidr[2]; const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0; tests.push((x) => { const n = toInt(x); return n != null && ((n & mask) >>> 0) === ((base & mask) >>> 0); }); continue; }
    if (/^[\w.:-]+$/.test(l) && lines.length > 1 || IPV4.test(l) || /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(l)) { const w = l.toLowerCase(); tests.push((x) => lc(x) === w); continue; }
    try { const re = new RegExp(l, "i"); tests.push((x) => re.test(x)); } catch (_) { const w = l.toLowerCase(); tests.push((x) => lc(x) === w); }
  }
  return (a) => [a.ip, a.fqdn, a.name, a.key, ...(a.ips || [])].some((x) => x && tests.some((t) => t(x)));
}

/** The documented priority matrix. Returns { priority, reason }. */
export function priorityOf(it, o = DEFAULTS) {
  const cv = it.cvss;
  const ep = it.epss;
  if (it.kev) return { priority: "P1", reason: "in CISA KEV" };
  if (ep != null && ep >= o.epssHigh && cv != null && cv >= 7) return { priority: "P1", reason: "EPSS " + ep + " >= " + o.epssHigh + " and CVSS " + cv + " >= 7" };
  if (cv != null && cv >= 9 && (it.internetFacing || it.exploit === true)) return { priority: "P1", reason: "CVSS " + cv + " >= 9 and " + (it.internetFacing ? "internet-facing" : "exploit available") };
  if ((cv != null && cv >= 7) || (ep != null && ep >= o.epssMedium)) return { priority: "P2", reason: cv != null && cv >= 7 ? "CVSS " + cv + " >= 7" : "EPSS " + ep + " >= " + o.epssMedium };
  if (cv != null && cv >= 4) return { priority: "P3", reason: "CVSS " + cv + " >= 4" };
  return { priority: "P4", reason: cv == null ? "no CVSS or severity" : "CVSS " + cv + " < 4" };
}

/** SLA due date: the earliest of the applicable policies. Returns { due (ms|null), basis }. */
export function slaDue(it, sla = DEFAULTS.sla) {
  if (it.firstSeen == null) return { due: null, basis: "no first-seen or scan date" };
  const c = [];
  const d = sla[it.priority];
  if (Number.isFinite(d) && d > 0) c.push({ due: it.firstSeen + d * DAY, basis: "internal " + it.priority + " " + d + " days" });
  if (sla.pciCriticalHighDays > 0 && (it.severity === "critical" || it.severity === "high")) c.push({ due: it.firstSeen + sla.pciCriticalHighDays * DAY, basis: "PCI DSS 6.3.3 " + sla.pciCriticalHighDays + " days" });
  // CISA's catalog due date is a fixed calendar date. When it had already passed before this
  // asset was first seen, counting overdue days from it would report years of lateness on a
  // finding detected yesterday; the detection-based clocks apply instead and the basis says so.
  let kevPassed = "";
  if (it.kev && sla.kevCatalogDue && it.kevDue) { const t = parseTs(it.kevDue); if (t != null) { if (t >= it.firstSeen) c.push({ due: t, basis: "CISA KEV due date " + it.kevDue }); else kevPassed = "; CISA KEV due date " + it.kevDue + " had passed before first seen"; } }
  if (it.kev && it.internetFacing && sla.kevInternetDays > 0) c.push({ due: it.firstSeen + sla.kevInternetDays * DAY, basis: "BOD 22-01 internet-facing " + sla.kevInternetDays + " days" });
  if (!c.length) return { due: null, basis: "no SLA configured for " + it.priority };
  c.sort((a, b) => a.due - b.due);
  return kevPassed ? { due: c[0].due, basis: c[0].basis + kevPassed } : c[0];
}

// ---------------------------------------------------------------------------
// End-of-life matching against the mirrored endoflife.date feed
// ---------------------------------------------------------------------------
/** Product + cycle candidates from an OS string. */
export function osCandidates(os) {
  const s = lc(os);
  if (!s) return [];
  let m;
  if ((m = s.match(/windows server (\d{4})(\s*r2)?/))) {
    const y = m[1], r2 = !!m[2];
    const cyc = y === "2008" ? (r2 ? "2008-r2-sp1" : "2008-sp2") : y === "2003" ? "2003-sp2" : y === "2012" && r2 ? "2012-r2" : y;
    return [{ product: "windows-server", cycle: cyc }];
  }
  if ((m = s.match(/windows (xp|vista|7|8\.1|8)\b/))) return [{ product: "windows", cycle: { xp: "5-sp3", vista: "6-sp2", 7: "7-sp1" }[m[1]] || m[1] }];
  if ((m = s.match(/ubuntu[^\d]{0,12}(\d{2}\.\d{2})/))) return [{ product: "ubuntu", cycle: m[1] }];
  if ((m = s.match(/centos[^\d]{0,20}(\d+)/))) return [{ product: "centos", cycle: m[1] }];
  if ((m = s.match(/(?:red hat enterprise linux|rhel)[^\d]{0,20}(\d+)/))) return [{ product: "rhel", cycle: m[1] }];
  if ((m = s.match(/debian[^\d]{0,20}(\d+)/))) return [{ product: "debian", cycle: m[1] }];
  if ((m = s.match(/alpine[^\d]{0,12}(\d+\.\d+)/))) return [{ product: "alpine-linux", cycle: m[1] }];
  if ((m = s.match(/(?:amazon linux|amzn)[^\d]{0,4}(2023|2)\b/))) return [{ product: "amazon-linux", cycle: m[1] }];
  if ((m = s.match(/oracle linux[^\d]{0,12}(\d+)/))) return [{ product: "oracle-linux", cycle: m[1] }];
  if ((m = s.match(/rocky[^\d]{0,12}(\d+)/))) return [{ product: "rocky-linux", cycle: m[1] }];
  if ((m = s.match(/almalinux[^\d]{0,12}(\d+)/))) return [{ product: "almalinux", cycle: m[1] }];
  if ((m = s.match(/(?:suse linux enterprise server|sles)[^\d]{0,4}(\d+)(?:\s*sp(\d+))?/))) return [{ product: "sles", cycle: m[1] + "." + (m[2] || "0") }];
  if ((m = s.match(/(?:mac ?os(?: x)?)[^\d]{0,12}(\d+)(?:\.(\d+))?/))) return [{ product: "macos", cycle: +m[1] === 10 && m[2] ? "10." + m[2] : m[1] }];
  return [];
}
const PKG_PRODUCTS = [
  [/^(openssl|libssl[\d.]*|libcrypto[\d.]*)$/, "openssl"], [/(^|:)log4j(-core)?$/, "log4j"], [/(^|:)spring-(core|beans|webmvc|web|context)$/, "spring-framework"],
  [/^django$/, "django"], [/^(node|nodejs)$/, "nodejs"], [/^python[\d.]*$/, "python"], [/^php[\d.]*$/, "php"], [/^(tomcat[\d.]*|tomcat-embed-core|org\.apache\.tomcat\.embed:tomcat-embed-core)$/, "tomcat"], [/^nginx$/, "nginx"],
];
/** Product candidates from a package name + installed version. */
export function pkgCandidates(pkg, version) {
  const p = lc(pkg).replace(/^.*\//, "");
  const v = str(version).replace(/^[v=]/, "").replace(/^\d+:/, "");
  if (!p || !v) return [];
  for (const [re, product] of PKG_PRODUCTS) if (re.test(p)) return [{ product, version: v }];
  return [];
}
function eolIndex(feed) {
  const m = new Map();
  for (const p of feedRows(feed) || []) if (p && p.product && Array.isArray(p.cycles)) m.set(p.product, p.cycles.slice().sort((a, b) => str(b.cycle).length - str(a.cycle).length || cmp(str(a.cycle), str(b.cycle))));
  return m;
}
function matchCycle(cycles, cand) {
  if (!cycles) return null;
  if (cand.cycle) return cycles.find((c) => str(c.cycle) === cand.cycle) || null;
  const v = cand.version;
  // "1.1.1l-r0" is in cycle "1.1.1"; "2.14.1" is in "2" but not in "2.1".
  return cycles.find((c) => { const cy = str(c.cycle); return v === cy || (v.startsWith(cy) && !/\d/.test(v[cy.length])); }) || null;
}
const isEol = (cycle, now) => cycle && (cycle.eol === true || (typeof cycle.eol === "string" && parseTs(cycle.eol) != null && parseTs(cycle.eol) <= now));

// ---------------------------------------------------------------------------
// Controls cited by the detections
// ---------------------------------------------------------------------------
const C = {
  pci631: { framework: "PCI DSS 4.0.1", id: "6.3.1" }, pci633: { framework: "PCI DSS 4.0.1", id: "6.3.3" }, pci1131: { framework: "PCI DSS 4.0.1", id: "11.3.1" },
  bod: { framework: "CISA", id: "BOD 22-01" }, cis22: { framework: "CIS Controls v8", id: "2.2" }, cis72: { framework: "CIS Controls v8", id: "7.2" },
  cis73: { framework: "CIS Controls v8", id: "7.3" }, cis74: { framework: "CIS Controls v8", id: "7.4" }, cis75: { framework: "CIS Controls v8", id: "7.5" },
  cis76: { framework: "CIS Controls v8", id: "7.6" }, cis77: { framework: "CIS Controls v8", id: "7.7" }, ra5: { framework: "NIST-800-53", id: "RA-5" },
  si2: { framework: "NIST-800-53", id: "SI-2" }, sa22: { framework: "NIST-800-53", id: "SA-22" }, iso: { framework: "ISO27001", id: "A.8.8" },
  t1190: { framework: "MITRE", id: "T1190" }, t1203: { framework: "MITRE", id: "T1203" },
};

/** Every detection with the data it needs (shown in the UI). */
export const DETECTIONS = [
  { id: "kev", title: "Known exploited vulnerability present", needs: "CVE ids + the KEV mirror" },
  { id: "overdue_p1", title: "P1 vulnerabilities past SLA", needs: "first-seen or scan date" },
  { id: "overdue_p2", title: "P2 vulnerabilities past SLA", needs: "first-seen or scan date" },
  { id: "many_criticals", title: "Asset with many open criticals", needs: "severity or CVSS" },
  { id: "old_open", title: "Vulnerabilities open longer than a year", needs: "first-seen date" },
  { id: "exploit_no_fix", title: "Exploit available and no fix", needs: "exploit flag (Nessus, Tenable, Qualys, Rapid7, Snyk, Defender)" },
  { id: "reopened", title: "Reopened vulnerabilities", needs: "scanner state or a baseline" },
  { id: "disappeared", title: "Assets missing since baseline", needs: "a baseline import" },
  { id: "eol", title: "End-of-life OS or software", needs: "OS or package version + the EOL mirror" },
  { id: "disagree", title: "Scanners disagree on severity", needs: "two scanners on one asset + CVE" },
  { id: "coverage", title: "Scanner coverage gap", needs: "two or more network scanners" },
];

const EV_CAP = 50;
const capEv = (rows) => rows.slice(0, EV_CAP);
const evRow = (r) => ({ asset: r.assetName, ip: r.ip, cve: r.cve || r.vulnKey, title: r.title, port: r.port || r.package, severity: r.severity, cvss: r.cvss, epss: r.epss, priority: r.priority, firstSeen: r.firstSeen, due: r.due, daysOverdue: r.daysOverdue, status: r.status, scanners: r.scanners });
const assetRef = (r) => ({ type: "ASSET", name: r.assetName, data: { kind: r.kind, os: r.os, ip: r.ip, fqdn: r.fqdn } });
function uniqAssets(rows) { const seen = new Map(); for (const r of rows) if (!seen.has(r.assetKey)) seen.set(r.assetKey, assetRef(r)); return [...seen.values()].sort((a, b) => cmp(a.name, b.name)).slice(0, EV_CAP); }
const median = (xs) => { if (!xs.length) return null; const s = xs.slice().sort((a, b) => a - b); const m = s.length >> 1; return s.length % 2 ? s[m] : Math.round(((s[m - 1] + s[m]) / 2) * 10) / 10; };
const mean = (xs) => (xs.length ? Math.round((xs.reduce((a, b) => a + b, 0) / xs.length) * 10) / 10 : null);
const r4 = (x) => (x == null ? null : Math.round(x * 100000) / 100000);

function normOpts(opts) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  o.sla = { ...DEFAULTS.sla, ...((opts && opts.sla) || {}) };
  for (const k of ["epssHigh", "epssMedium", "manyCriticals", "oldDays", "disagreeSteps"]) { const n = Number(o[k]); o[k] = Number.isFinite(n) ? n : DEFAULTS[k]; }
  return o;
}

function toDataset(dataset, o, ctx) {
  if (typeof dataset === "string") return parseInput([{ name: "input", text: dataset }], o, ctx);
  if (Array.isArray(dataset)) {
    if (!dataset.length) return { rows: [], files: [], skipped: [] };
    if (dataset[0] && typeof dataset[0] === "object" && "text" in dataset[0]) return parseInput(dataset, o, ctx);
    return { rows: dataset.filter((r) => r && r.asset && r.vuln).map((r) => ({ ...r, role: r.role || "current" })), files: [], skipped: [] };
  }
  if (dataset && Array.isArray(dataset.files) && dataset.files.length && "text" in dataset.files[0]) return parseInput(dataset.files, o, ctx);
  if (dataset && Array.isArray(dataset.rows)) return { rows: dataset.rows, files: dataset.files || [], skipped: dataset.skipped || [] };
  return { rows: [], files: [], skipped: [] };
}

/**
 * Analyze imports. dataset: [{name, text, role?}] | parseInput() result | normalised records.
 * opts: DEFAULTS overrides plus feeds { kev, epss, epssLive, eol } (parsed JSON, passed by the UI).
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = normOpts(opts);
  const progress = ctx && ctx.progress;
  const ds = toDataset(dataset, o, ctx);
  const skipped = [...(ds.skipped || [])];
  // Records are cloned so asset resolution never mutates the caller's data.
  const all = ds.rows.map((r) => ({ ...r, asset: { ...r.asset }, vuln: { ...r.vuln } }));
  let infoExcluded = 0;
  const kept = [];
  for (const r of all) {
    const sevCv = severityFromScore(r.vuln.cvss3.score != null ? r.vuln.cvss3.score : r.vuln.cvss2);
    if (!o.includeInfo && (r.vuln.severityScanner === "info" && (sevCv == null || sevCv === "info"))) { infoExcluded++; continue; }
    kept.push(r);
  }
  resolveAssets(kept);
  const cur = kept.filter((r) => r.role !== "baseline"), base = kept.filter((r) => r.role === "baseline");
  const merged = mergeRecords(cur), mergedBase = mergeRecords(base);
  const hasBaseline = base.length > 0;
  progress?.(1, 4, "merged " + merged.size + " vulnerabilities");

  // Reference date: opts.now, else the newest timestamp in the current import.
  let maxTs = null;
  for (const m of merged.values()) for (const t of [m.v.lastSeen, m.v.firstSeen, m.v.lastFixed]) if (t != null && (maxTs == null || t > maxTs)) maxTs = t;
  const now = parseTs(o.now) != null ? parseTs(o.now) : maxTs;

  const kev = kevIndex(o.kev), epss = epssIndex(o.epss), epssLive = epssIndex(o.epssLive);
  const facing = o.internetFacing instanceof RegExp || str(o.internetFacing) || Array.isArray(o.internetFacing) ? internetMatcher(o.internetFacing) : () => false;
  if (!o.kev) skipped.push({ check: "kev", reason: "KEV mirror not loaded: KEV enrichment and the KEV finding are off" });
  if (!o.epss && !o.epssLive) skipped.push({ check: "epss", reason: "EPSS mirror not loaded: EPSS terms of the priority matrix are off" });

  // Register rows
  const rows = [];
  const missingEpss = new Set();
  let n = 0;
  for (const m of [...merged.values()].sort((a, b) => cmp(a.key, b.key))) {
    if (++n % 1000 === 0) progress?.(n, merged.size, "prioritising");
    const v = m.v, a = m.asset;
    const b = mergedBase.get(m.key);
    if (b && b.v.firstSeen != null && (v.firstSeen == null || b.v.firstSeen < v.firstSeen)) { v.firstSeen = b.v.firstSeen; v.firstSeenBasis = "baseline"; }
    const cve = v.cve;
    const k = cve ? kev.get(cve) : null;
    const e = cve ? epssLive.get(cve) || epss.get(cve) : null;
    if (cve && !e) missingEpss.add(cve);
    const cvssScore = v.cvss3.score != null ? v.cvss3.score : v.cvss2;
    const sev = severityFromScore(cvssScore) || v.severityScanner || "info";
    const proxy = { critical: 9, high: 7, medium: 4, low: 0.1, info: 0 };
    const it = {
      key: m.key, vulnKey: v.key, assetKey: a.key, assetName: a.name, ip: a.ip, fqdn: a.fqdn, os: a.os, kind: a.kind, aggregate: a.aggregate,
      cve, cves: v.cves.join(" "), pluginId: v.pluginIds.join(" "), title: v.title || cve || v.key, scanners: v.scanners.join("; "),
      severity: sev, severityScanner: Object.keys(v.severities).sort(cmp).map((s) => s + ":" + v.severities[s]).join("; "),
      cvss: cvssScore != null ? cvssScore : null, cvssVector: v.cvss3.vector || v.cvss2Vector || "", cvssSource: v.cvss3.score != null ? "CVSS v3" : v.cvss2 != null ? "CVSS v2" : v.severityScanner ? "scanner severity" : "none",
      epss: e ? r4(e.epss) : null, epssPercentile: e ? r4(e.percentile) : null, epssSource: e ? (epssLive.get(cve) ? "live" : "mirror") : "",
      kev: !!k, kevDateAdded: k ? k.dateAdded : "", kevDue: k ? k.dueDate : "", ransomware: !!(k && k.ransomware),
      internetFacing: facing(a), exploit: v.exploitAvailable, priority: "", priorityReason: "",
      firstSeen: isoDay(v.firstSeen), firstSeenBasis: v.firstSeenBasis || "", lastSeen: isoDay(v.lastSeen), lastFixed: isoDay(v.lastFixed),
      due: "", dueBasis: "", overdue: false, daysOverdue: 0, daysOpen: null, status: v.status, change: "",
      port: v.port, protocol: v.protocol, package: v.package, installed: v.installed, fixedVersion: v.fixedVersion, solution: v.solution,
      output: v.output, references: v.references, published: v.published, exposedDevices: v.exposedDevices,
      _first: v.firstSeen, _last: v.lastSeen, _fixed: v.lastFixed, _sevs: v.severities,
    };
    const pr = priorityOf({ cvss: it.cvss != null ? it.cvss : v.severityScanner ? proxy[v.severityScanner] : null, epss: it.epss, kev: it.kev, internetFacing: it.internetFacing, exploit: it.exploit }, o);
    it.priority = pr.priority; it.priorityReason = pr.reason + (it.cvss == null && v.severityScanner ? " (scanner severity " + v.severityScanner + ", no CVSS)" : "");
    const d = slaDue({ firstSeen: v.firstSeen, priority: it.priority, severity: sev, kev: it.kev, kevDue: it.kevDue, internetFacing: it.internetFacing }, o.sla);
    it.due = d.due != null ? isoDay(d.due) : ""; it.dueBasis = d.basis; it._due = d.due;
    if (it.status !== "fixed" && d.due != null && now != null && now > d.due) { it.overdue = true; it.daysOverdue = Math.floor((now - d.due) / DAY); }
    if (v.firstSeen != null && now != null) it.daysOpen = Math.max(0, Math.floor(((it.status === "fixed" ? v.lastFixed || v.lastSeen || now : now) - v.firstSeen) / DAY));
    rows.push(it);
  }

  // Burn-down vs baseline
  const curAssets = new Set(rows.map((r) => r.assetKey));
  const baselineOnly = [];
  if (hasBaseline) {
    for (const r of rows) {
      const b = mergedBase.get(r.key);
      if (r.status === "fixed") r.change = "fixed";
      else if (!b) r.change = r.status === "reopened" ? "reopened" : "new";
      else r.change = b.v.status === "fixed" || r.status === "reopened" ? "reopened" : "still open";
      if (r.change === "reopened" && r.status !== "fixed") r.status = "reopened";
    }
    for (const b of [...mergedBase.values()].sort((x, y) => cmp(x.key, y.key))) {
      if (merged.has(b.key) || b.v.status === "fixed") continue;
      const sev = severityFromScore(b.v.cvss3.score != null ? b.v.cvss3.score : b.v.cvss2) || b.v.severityScanner || "info";
      baselineOnly.push({
        key: b.key, vulnKey: b.v.key, assetKey: b.asset.key, assetName: b.asset.name, ip: b.asset.ip, fqdn: b.asset.fqdn, os: b.asset.os, kind: b.asset.kind, aggregate: b.asset.aggregate,
        cve: b.v.cve, title: b.v.title || b.v.cve || b.v.key, severity: sev, cvss: b.v.cvss3.score != null ? b.v.cvss3.score : b.v.cvss2, firstSeen: isoDay(b.v.firstSeen), lastSeen: isoDay(b.v.lastSeen),
        change: curAssets.has(b.asset.key) ? "fixed" : "not rescanned", port: b.v.port, package: b.v.package, scanners: b.v.scanners.join("; "), _first: b.v.firstSeen, _last: b.v.lastSeen,
      });
    }
  }
  const burndown = SEVERITIES.map((s) => ({ severity: s, new: hasBaseline ? 0 : null, stillOpen: 0, fixed: 0, reopened: 0, notRescanned: hasBaseline ? 0 : null }));
  const bIdx = Object.fromEntries(burndown.map((b, i) => [b.severity, i]));
  for (const r of rows) {
    const b = burndown[bIdx[r.severity]];
    if (hasBaseline) { if (r.change === "new") b.new++; else if (r.change === "still open") b.stillOpen++; else if (r.change === "fixed") b.fixed++; else if (r.change === "reopened") b.reopened++; }
    else if (r.status === "fixed") b.fixed++; else if (r.status === "reopened") b.reopened++; else b.stillOpen++;
  }
  for (const r of baselineOnly) { const b = burndown[bIdx[r.severity]]; if (r.change === "fixed") b.fixed++; else b.notRescanned++; }
  const total = { severity: "total" };
  for (const k of ["new", "stillOpen", "fixed", "reopened", "notRescanned"]) total[k] = hasBaseline || (k !== "new" && k !== "notRescanned") ? burndown.reduce((s, b) => s + (b[k] || 0), 0) : null;
  burndown.push(total);

  // Mean time to remediate: fixed items with a first-seen and a fix (or last-seen) date.
  const ttr = [];
  for (const r of rows) if (r.status === "fixed" && r._first != null && (r._fixed || r._last) != null) ttr.push(Math.max(0, ((r._fixed || r._last) - r._first) / DAY));
  for (const r of baselineOnly) if (r.change === "fixed" && r._first != null && r._last != null) ttr.push(Math.max(0, (r._last - r._first) / DAY));

  progress?.(2, 4, "detections");
  const open = rows.filter((r) => r.status !== "fixed");
  const findings = detect(rows, open, baselineOnly, mergedBase, merged, { o, now, hasBaseline, kev, skipped, curAssets });
  progress?.(3, 4, "tables");

  // Tables
  const assetsT = new Map();
  for (const r of rows) {
    let a = assetsT.get(r.assetKey);
    if (!a) { a = { key: r.assetKey, name: r.assetName, ip: r.ip, fqdn: r.fqdn, os: r.os, kind: r.kind, aggregate: r.aggregate, scanners: new Set(), critical: 0, high: 0, medium: 0, low: 0, info: 0, open: 0, fixed: 0, kev: 0, overdue: 0, maxPriority: "", internetFacing: r.internetFacing }; assetsT.set(r.assetKey, a); }
    r.scanners.split("; ").forEach((s) => a.scanners.add(s));
    if (r.status === "fixed") { a.fixed++; continue; }
    a.open++; a[r.severity]++; if (r.kev) a.kev++; if (r.overdue) a.overdue++;
    if (!a.maxPriority || r.priority < a.maxPriority) a.maxPriority = r.priority;
  }
  const assets = [...assetsT.values()].map((a) => ({ ...a, scanners: [...a.scanners].sort(cmp).join("; ") })).sort((x, y) => cmp(x.maxPriority || "P9", y.maxPriority || "P9") || y.critical - x.critical || cmp(x.name, y.name));
  const cvesT = new Map();
  for (const r of open) {
    if (!r.cve) continue;
    let c = cvesT.get(r.cve);
    if (!c) { c = { cve: r.cve, title: r.title, assets: new Set(), maxCvss: null, epss: r.epss, percentile: r.epssPercentile, kev: r.kev, kevDue: r.kevDue, ransomware: r.ransomware, fixAvailable: false, priority: r.priority, overdue: 0, scanners: new Set() }; cvesT.set(r.cve, c); }
    c.assets.add(r.assetKey);
    if (r.cvss != null && (c.maxCvss == null || r.cvss > c.maxCvss)) c.maxCvss = r.cvss;
    if (r.fixedVersion || (r.solution && !/no (known )?(solution|fix)|^n\/?a$|^none$/i.test(r.solution))) c.fixAvailable = true;
    if (r.priority < c.priority) c.priority = r.priority;
    if (r.overdue) c.overdue++;
    r.scanners.split("; ").forEach((s) => c.scanners.add(s));
  }
  const cves = [...cvesT.values()].map((c) => ({ ...c, assets: c.assets.size, scanners: [...c.scanners].sort(cmp).join("; ") })).sort((x, y) => cmp(x.priority, y.priority) || (y.kev - x.kev) || (y.maxCvss || 0) - (x.maxCvss || 0) || cmp(x.cve, y.cve));
  const sla = PRIORITIES.map((p) => {
    const inB = rows.filter((r) => r.priority === p);
    const op = inB.filter((r) => r.status !== "fixed");
    const fx = inB.filter((r) => r.status === "fixed");
    return {
      bucket: p, days: o.sla[p], total: op.length, within: op.filter((r) => r._due != null && !r.overdue).length, overdue: op.filter((r) => r.overdue).length,
      noDate: op.filter((r) => r._due == null).length, medianDaysOpen: median(op.filter((r) => r.daysOpen != null).map((r) => r.daysOpen)),
      fixed: fx.length, fixedWithinSla: fx.filter((r) => r._due != null && (r._fixed || r._last) != null && (r._fixed || r._last) <= r._due).length,
    };
  });
  const noDates = open.filter((r) => r._due == null).length;
  if (noDates) skipped.push({ check: "sla", reason: noDates + " open vulnerabilities have no first-seen or scan date (for example Defender advanced hunting exports); their SLA due date is not computed" });

  const register = rows.map(({ _first, _last, _fixed, _sevs, _due, ...r }) => r);
  const remediation = remediationPlan(register);
  const fixedSince = hasBaseline ? total.fixed : burndown[burndown.length - 1].fixed;
  const summary = {
    assets: assets.length, vulns: register.length, open: open.length, uniqueCves: cves.length, kev: open.filter((r) => r.kev).length,
    P1: open.filter((r) => r.priority === "P1").length, P2: open.filter((r) => r.priority === "P2").length, P3: open.filter((r) => r.priority === "P3").length, P4: open.filter((r) => r.priority === "P4").length,
    overdue: open.filter((r) => r.overdue).length, fixed: fixedSince, newSinceBaseline: hasBaseline ? total.new : null, reopened: total.reopened,
    meanTimeToRemediate: mean(ttr), medianTimeToRemediate: median(ttr.map((x) => Math.round(x * 10) / 10)), mttrSamples: ttr.length,
    baseline: hasBaseline, now: isoDay(now), infoExcluded, missingEpss: [...missingEpss].sort(cmp),
    findings: findings.length, bySeverity: countBy(findings, "severity"),
  };
  progress?.(4, 4, "done");
  return {
    summary, findings, skipped,
    tables: { vulns: register, assets, cves, sla, burndown, baselineOnly: baselineOnly.map(({ _first, _last, ...r }) => r), remediation },
    meta: {
      tool: TOOL_ID, version: VERSION, rows: all.length, now: isoDay(now),
      files: (ds.files || []).map((f) => ({ name: f.name, format: f.format, label: f.label, scanner: f.scanner, confidence: f.confidence, records: f.records, role: f.role })),
      policy: { epssHigh: o.epssHigh, epssMedium: o.epssMedium, manyCriticals: o.manyCriticals, oldDays: o.oldDays, disagreeSteps: o.disagreeSteps, internetFacing: str(o.internetFacing instanceof RegExp ? o.internetFacing.source : Array.isArray(o.internetFacing) ? o.internetFacing.join("\n") : o.internetFacing), sla: o.sla },
      feeds: { kev: str(o.kev && o.kev.updated), epss: str(o.epss && o.epss.updated), eol: str(o.eol && o.eol.updated), epssLive: str(o.epssLiveAt) },
    },
  };
}

function countBy(items, key) {
  const out = {};
  for (const it of items) out[it[key]] = (out[it[key]] || 0) + 1;
  return Object.fromEntries(Object.keys(out).sort().map((k) => [k, out[k]]));
}

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------
function mkFinding(f) {
  const evidenceCount = f.evidence.length;
  return { ...f, evidence: capEv(f.evidence), evidenceCount };
}

function detect(rows, open, baselineOnly, mergedBase, merged, { o, now, hasBaseline, kev, skipped, curAssets }) {
  const out = [];
  const anyPkg = (rs) => rs.some((r) => r.kind !== "host");
  const anyNet = (rs) => rs.some((r) => r.kind === "host" && r.port) || rs.some((r) => r.internetFacing);
  const mitre = (rs) => [...(anyNet(rs) ? [C.t1190] : []), ...(anyPkg(rs) ? [C.t1203] : [])];

  // 1. KEV present: one finding per CVE
  if (kev.size) {
    const byCve = new Map();
    for (const r of open) if (r.kev) { if (!byCve.has(r.cve)) byCve.set(r.cve, []); byCve.get(r.cve).push(r); }
    for (const cve of [...byCve.keys()].sort(cmp)) {
      const rs = byCve.get(cve).sort((a, b) => cmp(a.assetName, b.assetName));
      const k = kev.get(cve);
      const n = new Set(rs.map((r) => r.assetKey)).size;
      out.push(mkFinding({
        id: "kev:" + cve, check: "kev", title: "Known exploited vulnerability " + cve + " is open", severity: "critical", confidence: "confirmed", category: "known exploited",
        description: cve + (k.name ? " (" + k.name + ")" : "") + " is in the CISA Known Exploited Vulnerabilities catalog (added " + k.dateAdded + ", federal due date " + k.dueDate + ")" +
          (k.ransomware ? " and is known to be used in ransomware campaigns" : "") + ". It is open on " + n + " asset" + (n === 1 ? "" : "s") + ".",
        recommendation: "Patch or apply the vendor mitigation on every listed asset now; where that is not possible, isolate the service or take the asset offline as CISA BOD 22-01 directs.",
        controls: [C.bod, C.pci633, C.si2, C.cis77, C.iso, ...mitre(rs)], evidence: rs.map(evRow),
        assets: [{ type: "VULNERABILITY", name: cve, data: { cvss: rs[0].cvss, epss: rs[0].epss, kev: true, kevDue: k.dueDate, ransomware: k.ransomware, title: rs[0].title } }, ...uniqAssets(rs)],
        tags: ["kev", ...(k.ransomware ? ["ransomware"] : [])],
      }));
    }
  }

  // 2. Overdue P1 / P2
  const dated = open.filter((r) => r.due);
  if (!dated.length && open.length) skipped.push({ check: "overdue", reason: "no open vulnerability has a first-seen or scan date, so SLA overdue checks cannot run" });
  for (const [p, sev] of [["P1", "high"], ["P2", "medium"]]) {
    const rs = open.filter((r) => r.priority === p && r.overdue).sort((a, b) => b.daysOverdue - a.daysOverdue || cmp(a.key, b.key));
    if (!rs.length) continue;
    const n = new Set(rs.map((r) => r.assetKey)).size;
    out.push(mkFinding({
      id: "overdue:" + p, check: "overdue_" + p.toLowerCase(), title: rs.length + " " + p + " vulnerabilit" + (rs.length === 1 ? "y is" : "ies are") + " past the remediation SLA", severity: sev, confidence: "confirmed", category: "sla",
      description: rs.length + " open " + p + " vulnerabilities on " + n + " asset" + (n === 1 ? "" : "s") + " are past their due date (" + p + " policy " + o.sla[p] + " days" +
        (rs.some((r) => /KEV/.test(r.dueBasis)) ? "; KEV items use the catalog due date" : "") + "). The longest is " + rs[0].daysOverdue + " days overdue.",
      recommendation: "Remediate in order of days overdue, or record an approved exception with a compensating control and an expiry date for each item that cannot be patched.",
      controls: [C.pci633, C.si2, C.cis77, C.cis72, C.iso, ...(rs.some((r) => r.kev) ? [C.bod] : [])], evidence: rs.map(evRow), assets: uniqAssets(rs), tags: ["sla", p],
    }));
  }

  // 3. Assets with many open criticals
  const crit = new Map();
  for (const r of open) if (r.severity === "critical" && !r.aggregate) { if (!crit.has(r.assetKey)) crit.set(r.assetKey, []); crit.get(r.assetKey).push(r); }
  for (const key of [...crit.keys()].sort(cmp)) {
    const rs = crit.get(key);
    if (rs.length < o.manyCriticals) continue;
    out.push(mkFinding({
      id: "many_criticals:" + key, check: "many_criticals", title: rs[0].assetName + " has " + rs.length + " open critical vulnerabilities", severity: "high", confidence: "likely", category: "patch hygiene",
      description: rs[0].assetName + (rs[0].os ? " (" + rs[0].os + ")" : "") + " has " + rs.length + " open critical vulnerabilities (threshold " + o.manyCriticals + "). This many usually means patching has stopped on the asset or it runs unsupported software.",
      recommendation: "Confirm the asset is in a patch cycle and its OS and software are supported; rebuild or replace it if not.",
      controls: [C.cis73, C.cis74, C.si2, C.iso], evidence: rs.map(evRow), assets: [assetRef(rs[0])], tags: ["patching"],
    }));
  }

  // 4. Open longer than oldDays
  if (!open.some((r) => r.firstSeen)) skipped.push({ check: "old_open", reason: "no first-seen dates in the data" });
  else {
    const rs = open.filter((r) => r.daysOpen != null && r.daysOpen > o.oldDays).sort((a, b) => b.daysOpen - a.daysOpen || cmp(a.key, b.key));
    if (rs.length) out.push(mkFinding({
      id: "old_open", check: "old_open", title: rs.length + " vulnerabilit" + (rs.length === 1 ? "y has" : "ies have") + " been open for more than " + o.oldDays + " days", severity: "medium", confidence: "confirmed", category: "aging",
      description: "The oldest has been open " + rs[0].daysOpen + " days (" + rs[0].assetName + ", " + (rs[0].cve || rs[0].title) + "). Long-lived findings are usually unowned or blocked by an unsupported component.",
      recommendation: "Assign an owner to each item, then patch, retire the component, or record a time-bound risk acceptance.",
      controls: [C.cis77, C.ra5, C.si2, C.iso], evidence: rs.map((r) => ({ ...evRow(r), daysOpen: r.daysOpen })), assets: uniqAssets(rs), tags: ["aging"],
    }));
  }

  // 5. Exploit available and no fix
  if (!rows.some((r) => r.exploit !== null && r.exploit !== undefined)) skipped.push({ check: "exploit_no_fix", reason: "no source carries an exploit-availability field (Nessus, Tenable, Qualys, Rapid7, Snyk and Defender weaknesses do)" });
  else {
    const noFix = (r) => !r.fixedVersion && (!r.solution || /no (known )?(solution|fix|patch)|^n\/?a$|^none$|will not fix|won't fix/i.test(r.solution));
    const rs = open.filter((r) => r.exploit === true && noFix(r)).sort((a, b) => (b.cvss || 0) - (a.cvss || 0) || cmp(a.key, b.key));
    if (rs.length) out.push(mkFinding({
      id: "exploit_no_fix", check: "exploit_no_fix", title: rs.length + " exploitable vulnerabilit" + (rs.length === 1 ? "y has" : "ies have") + " no fix available", severity: "high", confidence: "likely", category: "compensating control",
      description: "These open vulnerabilities have a public exploit but the scanner reports no fixed version or solution.",
      recommendation: "Apply compensating controls (restrict network exposure, disable the affected feature, add detection rules) and track the vendor for a fix.",
      controls: [C.si2, C.ra5, C.cis77, ...mitre(rs)], evidence: rs.map(evRow), assets: uniqAssets(rs), tags: ["exploit"],
    }));
  }

  // 6. Reopened
  const reo = open.filter((r) => r.status === "reopened").sort((a, b) => cmp(a.key, b.key));
  if (reo.length) out.push(mkFinding({
    id: "reopened", check: "reopened", title: reo.length + " vulnerabilit" + (reo.length === 1 ? "y was" : "ies were") + " fixed and came back", severity: "medium", confidence: "confirmed", category: "regression",
    description: "These were fixed earlier (scanner state or baseline) and are open again. Common causes: an image or template rebuilt from an old base, a rolled-back patch, or a reinstalled component.",
    recommendation: "Fix the source (golden image, base container, configuration management) rather than the single host, then verify on the next scan.",
    controls: [C.cis72, C.si2, C.iso], evidence: reo.map(evRow), assets: uniqAssets(reo), tags: ["regression"],
  }));

  // 7. Assets missing since baseline
  if (!hasBaseline) skipped.push({ check: "disappeared", reason: "no baseline import: load last period's JSON export or mark a file as baseline" });
  else {
    const gone = new Map();
    for (const r of baselineOnly) if (r.change === "not rescanned" && !r.aggregate) { if (!gone.has(r.assetKey)) gone.set(r.assetKey, []); gone.get(r.assetKey).push(r); }
    const ev = [...gone.keys()].sort(cmp).map((k) => { const rs = gone.get(k); return { asset: rs[0].assetName, ip: rs[0].ip, kind: rs[0].kind, openInBaseline: rs.length, lastSeen: rs.map((r) => r.lastSeen).sort(cmp).pop(), cves: rs.map((r) => r.cve).filter(Boolean).slice(0, 10).join(" ") }; });
    if (ev.length) out.push(mkFinding({
      id: "disappeared", check: "disappeared", title: ev.length + " asset" + (ev.length === 1 ? "" : "s") + " with open vulnerabilities in the baseline were not scanned this time", severity: "low", confidence: "review", category: "coverage",
      description: "These assets had open vulnerabilities in the baseline and do not appear in the current import. Either they were decommissioned or the scan no longer reaches them; their vulnerabilities are counted as not rescanned, not fixed.",
      recommendation: "Confirm decommissioning in the asset inventory, or restore scan coverage (credentials, network reachability, scan scope).",
      controls: [C.ra5, C.cis75, C.cis76, C.pci1131], evidence: ev, assets: ev.map((e) => ({ type: "ASSET", name: e.asset, data: { ip: e.ip, kind: e.kind } })).slice(0, EV_CAP), tags: ["coverage"],
    }));
  }

  // 8. End-of-life OS / software
  if (!o.eol) skipped.push({ check: "eol", reason: "EOL mirror not loaded" });
  else {
    const idx = eolIndex(o.eol);
    const groups = new Map();
    const add = (cand, cyc, r, what) => {
      const k = cand.product + "|" + cyc.cycle;
      if (!groups.has(k)) groups.set(k, { product: cand.product, cycle: cyc, rows: new Map() });
      const g = groups.get(k);
      const ek = r.assetKey + "|" + what;
      if (!g.rows.has(ek)) g.rows.set(ek, { r, row: { asset: r.assetName, ip: r.ip, kind: r.kind, detected: what, product: cand.product, cycle: str(cyc.cycle), eol: cyc.eol === true ? "yes (no date)" : str(cyc.eol), extendedSupport: typeof cyc.extendedSupport === "string" ? cyc.extendedSupport : "", openVulns: 0 } });
      if (r.status !== "fixed") g.rows.get(ek).row.openVulns++;
    };
    for (const r of rows) {
      if (r.aggregate) continue;
      for (const cand of osCandidates(r.os)) { const cyc = matchCycle(idx.get(cand.product), cand); if (isEol(cyc, now)) add(cand, cyc, r, r.os); }
      for (const cand of pkgCandidates(r.package, r.installed)) { const cyc = matchCycle(idx.get(cand.product), cand); if (isEol(cyc, now)) add(cand, cyc, r, r.package + " " + r.installed); }
    }
    for (const k of [...groups.keys()].sort(cmp)) {
      const g = groups.get(k);
      const list = [...g.rows.values()].sort((a, b) => cmp(a.row.asset, b.row.asset));
      const ext = typeof g.cycle.extendedSupport === "string" && parseTs(g.cycle.extendedSupport) > now ? g.cycle.extendedSupport : "";
      out.push(mkFinding({
        id: "eol:" + k, check: "eol", title: g.product + " " + g.cycle.cycle + " is end-of-life on " + list.length + " asset" + (list.length === 1 ? "" : "s"), severity: ext ? "medium" : "high", confidence: "likely", category: "unsupported software",
        description: g.product + " " + g.cycle.cycle + " reached end of life on " + (g.cycle.eol === true ? "an unspecified date" : g.cycle.eol) + " (endoflife.date mirror)" + (ext ? "; paid extended support runs to " + ext + ", confirm it is in place" : "") + ". Unsupported components stop receiving security fixes, so their vulnerabilities cannot be closed by patching.",
        recommendation: "Upgrade to a supported release or replace the component; until then, record the exception and isolate the asset.",
        controls: [C.cis22, C.sa22, C.si2, C.iso, C.pci633], evidence: list.map((x) => x.row), assets: uniqAssets(list.map((x) => x.r)), tags: ["eol"],
      }));
    }
  }

  // 9. Scanner disagreement on severity
  const multi = rows.filter((r) => Object.keys(r._sevs || {}).length >= 2);
  if (!multi.length) skipped.push({ check: "disagree", reason: "no vulnerability was reported by two scanners" });
  else {
    const rs = multi.filter((r) => { const v = Object.values(r._sevs).map((s) => SEV_RANK[s]); return Math.max(...v) - Math.min(...v) >= o.disagreeSteps; }).sort((a, b) => cmp(a.key, b.key));
    if (rs.length) out.push(mkFinding({
      id: "disagree", check: "disagree", title: rs.length + " vulnerabilit" + (rs.length === 1 ? "y is" : "ies are") + " rated differently by different scanners", severity: "info", confidence: "review", category: "data quality",
      description: "Scanners disagree by " + o.disagreeSteps + " or more severity levels on these. The register uses the CVSS base score where one exists, so priority is unaffected; the disagreement is worth a look when a scanner rating drives tickets.",
      recommendation: "Check which scanner has the accurate version or configuration evidence, and align ticketing on CVSS plus the KEV/EPSS priority.",
      controls: [C.ra5, C.cis75], evidence: rs.map((r) => ({ asset: r.assetName, cve: r.cve || r.vulnKey, title: r.title, severities: r.severityScanner, cvss: r.cvss, used: r.severity })), assets: uniqAssets(rs), tags: ["data-quality"],
    }));
  }

  // 10. Coverage gap between network scanners in this import
  const NET = new Set(["Nessus", "Tenable", "Qualys", "OpenVAS", "Rapid7"]);
  const hostRows = rows.filter((r) => r.kind === "host" && !r.aggregate);
  const netScanners = uniqSorted(hostRows.flatMap((r) => r.scanners.split("; ")).filter((s) => NET.has(s)));
  if (netScanners.length < 2) skipped.push({ check: "coverage", reason: "fewer than two network scanners in the current import" });
  else {
    const seen = new Map();
    for (const r of hostRows) { if (!seen.has(r.assetKey)) seen.set(r.assetKey, { r, s: new Set() }); r.scanners.split("; ").forEach((s) => seen.get(r.assetKey).s.add(s)); }
    const ev = [...seen.values()].map(({ r, s }) => ({ r, row: { asset: r.assetName, ip: r.ip, seenBy: [...s].filter((x) => NET.has(x)).sort(cmp).join("; "), missing: netScanners.filter((x) => !s.has(x)).join("; ") } })).filter((x) => x.row.missing).sort((a, b) => cmp(a.row.asset, b.row.asset));
    if (ev.length) out.push(mkFinding({
      id: "coverage", check: "coverage", title: ev.length + " host" + (ev.length === 1 ? " was" : "s were") + " covered by only some of the network scanners", severity: "info", confidence: "review", category: "coverage",
      description: "This import has " + netScanners.join(", ") + ". These hosts were reported by some of them only. If the scanners are meant to overlap, a missing host means a scope or reachability gap.",
      recommendation: "Compare scan scopes and credentials; ignore when the scanners intentionally cover different networks.",
      controls: [C.ra5, C.cis75, C.pci1131], evidence: ev.map((x) => x.row), assets: uniqAssets(ev.map((x) => x.r)), tags: ["coverage"],
    }));
  }
  return out.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(a.check, b.check) || cmp(a.id, b.id));
}

// ---------------------------------------------------------------------------
// Remediation plan and exports
// ---------------------------------------------------------------------------
/** Group open register rows into patch actions. */
export function remediationPlan(register) {
  const g = new Map();
  for (const r of register) {
    if (r.status === "fixed") continue;
    const key = r.fixedVersion ? "u|" + lc(r.package) + "|" + r.fixedVersion : r.solution ? "s|" + r.solution.slice(0, 300) : "t|" + r.title;
    let x = g.get(key);
    if (!x) { x = { action: r.fixedVersion ? "Upgrade " + r.package + " to " + r.fixedVersion : r.solution ? r.solution.replace(/\s+/g, " ").slice(0, 300) : "No solution in the export: " + r.title, package: r.package, fixedVersion: r.fixedVersion, assets: new Set(), vulns: 0, cves: new Set(), priority: r.priority, earliestDue: "", overdue: 0, kev: 0 }; g.set(key, x); }
    x.assets.add(r.assetKey); x.vulns++; if (r.cve) x.cves.add(r.cve);
    if (r.priority < x.priority) x.priority = r.priority;
    if (r.due && (!x.earliestDue || r.due < x.earliestDue)) x.earliestDue = r.due;
    if (r.overdue) x.overdue++; if (r.kev) x.kev++;
  }
  return [...g.values()].map((x) => ({ ...x, assets: x.assets.size, cves: [...x.cves].sort(cmp).join(" ") }))
    .sort((a, b) => cmp(a.priority, b.priority) || b.kev - a.kev || b.assets - a.assets || cmp(a.action, b.action));
}

const q = (v) => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
// Export cells: a text cell that starts with = + - @ (or tab / CR) is prefixed with ' so a spreadsheet does not run it as a formula.
export const csvCell = (v) => { const s = String(v == null ? "" : v); return q(typeof v === "string" && /^[=+\-@\t\r]/.test(s) && !/^-?\d+(\.\d+)?$/.test(s) ? "'" + s : s); };
const csv = (cols, rows) => [cols.join(","), ...(rows || []).map((r) => cols.map((c) => csvCell(typeof r[c] === "boolean" ? (r[c] ? "yes" : "no") : r[c])).join(","))].join("\n");

const FINDING_COLS = ["severity", "confidence", "category", "check", "title", "description", "recommendation", "controls", "assets", "evidenceCount"];
/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  return csv(FINDING_COLS, (findings || []).map((f) => ({ ...f, controls: (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), assets: (f.assets || []).map((a) => a.name).join("; "), evidenceCount: f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length })));
}
export const REGISTER_COLS = ["priority", "priorityReason", "assetName", "ip", "fqdn", "os", "kind", "cve", "vulnKey", "pluginId", "title", "severity", "severityScanner", "cvss", "cvssVector", "cvssSource", "epss", "epssPercentile", "epssSource", "kev", "kevDue", "ransomware", "internetFacing", "exploit", "status", "change", "firstSeen", "firstSeenBasis", "lastSeen", "lastFixed", "due", "dueBasis", "overdue", "daysOverdue", "daysOpen", "port", "protocol", "package", "installed", "fixedVersion", "solution", "scanners"];
export function registerToCsv(rows) { return csv(REGISTER_COLS, rows); }
export function assetsToCsv(rows) { return csv(["name", "ip", "fqdn", "os", "kind", "scanners", "open", "critical", "high", "medium", "low", "kev", "overdue", "maxPriority", "fixed", "internetFacing"], rows); }
export function remediationToCsv(rows) { return csv(["priority", "action", "package", "fixedVersion", "assets", "vulns", "kev", "overdue", "earliestDue", "cves"], rows); }
/** Open CVE ids, one per line, in priority order. */
export function cveListText(result) { return (result.tables.cves || []).map((c) => c.cve).join("\n") + "\n"; }

/** Plain-text summary for tickets and email. */
export function summaryText(r) {
  const s = r.summary;
  const lines = [
    "Vulnerability Import & SLA summary (" + TOOL_ID + " " + VERSION + ")",
    "Reference date: " + (s.now || "-") + (s.baseline ? "   Baseline: yes" : "   Baseline: none"),
    "Files: " + (r.meta.files || []).map((f) => f.name + " [" + f.label + ", " + f.records + " records, " + f.role + "]").join("; "),
    "Assets: " + s.assets + "   Vulnerabilities: " + s.vulns + " (" + s.open + " open)   Unique open CVEs: " + s.uniqueCves,
    "KEV open: " + s.kev + "   P1: " + s.P1 + "   P2: " + s.P2 + "   P3: " + s.P3 + "   P4: " + s.P4 + "   Overdue: " + s.overdue,
    "Fixed: " + s.fixed + (s.baseline ? "   New since baseline: " + s.newSinceBaseline : "") + "   Reopened: " + s.reopened,
    "Mean time to remediate: " + (s.meanTimeToRemediate == null ? "-" : s.meanTimeToRemediate + " days (median " + s.medianTimeToRemediate + ", n=" + s.mttrSamples + ")"),
    "Feeds: KEV " + (r.meta.feeds.kev || "not loaded") + ", EPSS " + (r.meta.feeds.epss || "not loaded") + (r.meta.feeds.epssLive ? ", EPSS live " + r.meta.feeds.epssLive : "") + ", EOL " + (r.meta.feeds.eol || "not loaded"),
    "", "SLA (open):", ...r.tables.sla.map((b) => "  " + b.bucket + " (" + b.days + " days): " + b.total + " open, " + b.overdue + " overdue, " + b.within + " within, " + b.noDate + " no date"),
    "", "Findings (" + r.findings.length + "):",
    ...r.findings.map((f) => "- [" + f.severity + "] " + f.title + "\n    " + f.recommendation + "\n    Controls: " + f.controls.map((c) => c.framework + " " + c.id).join(", ")),
  ];
  if (r.skipped.length) lines.push("", "Skipped or limited checks:", ...r.skipped.map((k) => "- " + k.check + ": " + k.reason));
  return lines.join("\n") + "\n";
}

/** ASSET and VULNERABILITY items for the Security Graph, linked VULNERABILITY -affects-> ASSET. */
export function graphItems(result, { sample = false, max = 2000 } = {}) {
  const tags = sample ? ["sample"] : [];
  const assets = result.tables.assets.filter((a) => !a.aggregate).slice(0, max);
  const keep = new Set(assets.map((a) => a.key));
  const items = assets.map((a) => ({ type: "ASSET", name: a.name, data: { kind: a.kind, os: a.os, ip: a.ip, fqdn: a.fqdn, criticals: a.critical, highs: a.high, overdue: a.overdue }, opts: { tags: [TOOL_ID, ...tags] } }));
  const cves = result.tables.cves.slice(0, max);
  for (const c of cves) items.push({ type: "VULNERABILITY", name: c.cve, data: { cvss: c.maxCvss, epss: c.epss, kev: c.kev, assets: c.assets, title: c.title }, opts: { tags: [TOOL_ID, ...tags] } });
  const cset = new Set(cves.map((c) => c.cve));
  const names = new Map(assets.map((a) => [a.key, a.name]));
  const links = new Set();
  for (const r of result.tables.vulns) if (r.status !== "fixed" && r.cve && cset.has(r.cve) && keep.has(r.assetKey)) links.add(r.cve + "\u0000" + names.get(r.assetKey));
  return { items, links: [...links].sort(cmp).slice(0, max * 4).map((l) => { const [v, a] = l.split("\u0000"); return { from: "VULNERABILITY:" + v, to: "ASSET:" + a, rel: "affects" }; }) };
}

// ---------------------------------------------------------------------------
// Synthetic example (format-faithful; every host, finding and date is invented).
// CVE-2008-4250 and CVE-2016-3081 are in the mirrored CISA KEV catalog, so KEV
// enrichment is visible when the mirror is loaded.
// ---------------------------------------------------------------------------
function nessusItem(a, body) {
  return '<ReportItem port="' + a.port + '" svc_name="' + a.svc + '" protocol="tcp" severity="' + a.sev + '" pluginID="' + a.id + '" pluginName="' + a.name + '" pluginFamily="' + a.fam + '">\n' + body + "\n</ReportItem>";
}
function nessusHost(ip, fqdn, nb, os, items) {
  return '<ReportHost name="' + ip + '"><HostProperties>\n<tag name="HOST_END">Thu Oct 15 02:10:00 2026</tag>\n<tag name="host-ip">' + ip + '</tag>\n<tag name="host-fqdn">' + fqdn +
    '</tag>\n<tag name="netbios-name">' + nb + '</tag>\n<tag name="operating-system">' + os + '</tag>\n<tag name="HOST_START">Thu Oct 15 02:00:00 2026</tag>\n</HostProperties>\n' + items.join("\n") + "\n</ReportHost>";
}
const scanInfo = () => nessusItem({ port: 0, svc: "general", sev: 0, id: 19506, name: "Nessus Scan Information", fam: "Settings" }, "<risk_factor>None</risk_factor><plugin_output>Information about this scan : synthetic example</plugin_output>");
const terrapin = () => nessusItem({ port: 22, svc: "ssh", sev: 2, id: 187315, name: "SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795)", fam: "Misc." },
  "<cve>CVE-2023-48795</cve><cvss3_base_score>5.9</cvss3_base_score><cvss3_vector>CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N</cvss3_vector><risk_factor>Medium</risk_factor><exploit_available>false</exploit_available><solution>Contact the vendor for an update with the strict key exchange countermeasures or disable the affected algorithms.</solution><plugin_output>Supports following ChaCha20-Poly1305 Algorithm : chacha20-poly1305@openssh.com</plugin_output><vuln_publication_date>2023/12/18</vuln_publication_date>");

/** Small seeded SYNTHETIC dataset for "Load example" and tests: four files incl. a baseline. */
export function exampleDataset(seed = 7) {
  void seed;
  const nessus = '<?xml version="1.0" ?>\n<NessusClientData_v2>\n<Policy><policyName>Synthetic example</policyName></Policy>\n<Report name="Synthetic example scan" xmlns:cm="http://www.nessus.org/cm">\n' + [
    nessusHost("10.20.0.11", "web01.test.darknode.ai", "WEB01", "Microsoft Windows Server 2012 R2 Standard", [
      scanInfo(),
      nessusItem({ port: 445, svc: "cifs", sev: 4, id: 34477, name: "MS08-067: Microsoft Windows Server Service Crafted RPC Request Handling Remote Code Execution (958644) (uncredentialed check)", fam: "Windows" },
        "<cve>CVE-2008-4250</cve><cvss_base_score>10.0</cvss_base_score><cvss_vector>CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C</cvss_vector><risk_factor>Critical</risk_factor><exploit_available>true</exploit_available><exploitability_ease>Exploits are available</exploitability_ease><synopsis>Arbitrary code can be executed on the remote host due to a flaw in the 'Server' service.</synopsis><solution>Microsoft has released a set of patches for Windows 2000, XP, 2003, Vista and 2008.</solution><plugin_output>The remote host answered the crafted RPC request.</plugin_output><vuln_publication_date>2008/10/23</vuln_publication_date>"),
      nessusItem({ port: 3389, svc: "msrdp", sev: 2, id: 57582, name: "SSL Self-Signed Certificate", fam: "General" },
        "<cvss3_base_score>6.5</cvss3_base_score><cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N</cvss3_vector><risk_factor>Medium</risk_factor><solution>Purchase or generate a proper SSL certificate for this service.</solution><plugin_output>|-Subject : CN=web01.test.darknode.ai</plugin_output>"),
    ]),
    nessusHost("10.20.0.12", "app01.test.darknode.ai", "APP01", "Linux Kernel 4.15 on Ubuntu 18.04", [
      scanInfo(), terrapin(),
      nessusItem({ port: 8080, svc: "www", sev: 4, id: 90773, name: "Apache Struts 2 Dynamic Method Invocation RCE (S2-032)", fam: "CGI abuses" },
        "<cve>CVE-2016-3081</cve><cvss3_base_score>8.1</cvss3_base_score><cvss3_vector>CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</cvss3_vector><cvss_base_score>9.3</cvss_base_score><risk_factor>Critical</risk_factor><exploit_available>true</exploit_available><solution>Upgrade to Apache Struts version 2.3.20.3 / 2.3.24.3 / 2.3.28.1 or later.</solution><plugin_output>URL : http://app01.test.darknode.ai:8080/orders.action</plugin_output><vuln_publication_date>2016/04/26</vuln_publication_date>"),
    ]),
    nessusHost("10.20.0.13", "db01.test.darknode.ai", "DB01", "CentOS Linux 7", [
      scanInfo(), terrapin(),
      nessusItem({ port: 443, svc: "www", sev: 3, id: 73412, name: "OpenSSL Heartbeat Information Disclosure (Heartbleed)", fam: "Misc." },
        "<cve>CVE-2014-0160</cve><cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</cvss3_vector><risk_factor>High</risk_factor><exploit_available>true</exploit_available><solution>Upgrade to OpenSSL 1.0.1g or later.</solution><plugin_output>Nessus was able to read 16384 bytes of server memory.</plugin_output><vuln_publication_date>2014/04/07</vuln_publication_date>"),
    ]),
  ].join("\n") + "\n</Report>\n</NessusClientData_v2>\n";

  const trivy = JSON.stringify({
    SchemaVersion: 2, CreatedAt: "2026-10-14T21:00:00Z", ArtifactName: "registry.test.darknode.ai/shop/api:1.4.2", ArtifactType: "container_image",
    Metadata: { OS: { Family: "alpine", Name: "3.14.2" }, ImageID: "sha256:3f1c0e8b6a2d" },
    Results: [
      { Target: "registry.test.darknode.ai/shop/api:1.4.2 (alpine 3.14.2)", Class: "os-pkgs", Type: "alpine", Vulnerabilities: [
        { VulnerabilityID: "CVE-2022-0778", PkgName: "libssl1.1", InstalledVersion: "1.1.1l-r0", FixedVersion: "1.1.1n-r0", Status: "fixed", Severity: "HIGH", Title: "openssl: Infinite loop in BN_mod_sqrt() reachable when parsing certificates", CVSS: { nvd: { V3Score: 7.5, V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" } }, PublishedDate: "2022-03-15T17:15:00Z", References: ["https://www.openssl.org/news/secadv/20220315.txt"] },
        { VulnerabilityID: "CVE-2022-37434", PkgName: "zlib", InstalledVersion: "1.2.11-r3", FixedVersion: "1.2.12-r2", Status: "fixed", Severity: "CRITICAL", Title: "zlib: heap-based buffer over-read and overflow in inflate()", CVSS: { nvd: { V3Score: 9.8, V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }, PublishedDate: "2022-08-05T07:15:00Z" },
      ] },
      { Target: "app/lib/log4j-core-2.14.1.jar", Class: "lang-pkgs", Type: "jar", Vulnerabilities: [
        { VulnerabilityID: "CVE-2021-44228", PkgName: "org.apache.logging.log4j:log4j-core", InstalledVersion: "2.14.1", FixedVersion: "2.15.0, 2.12.2", Status: "fixed", Severity: "CRITICAL", Title: "log4j-core: Remote code execution in Log4j 2.x when logs contain an attacker-controlled string value", CVSS: { nvd: { V3Score: 10, V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" } }, PublishedDate: "2021-12-10T10:15:00Z" },
      ] },
    ],
  }, null, 2);

  const QH = ["IP", "DNS", "NetBIOS", "OS", "IP Status", "QID", "Title", "Vuln Status", "Type", "Severity", "Port", "Protocol", "FQDN", "SSL", "First Detected", "Last Detected", "Times Detected", "Date Last Fixed", "CVE ID", "Vendor Reference", "Bugtraq ID", "CVSS", "CVSS Base", "CVSS Temporal", "CVSS3", "CVSS3 Base", "Threat", "Impact", "Solution", "Exploitability", "Associated Malware", "Results", "PCI Vuln", "Ticket State", "Instance", "Category"];
  const qrow = (o) => QH.map((h) => q(o[h] || "")).join(",");
  const qualys = ['"Scan Results","Synthetic example (not real data)"', '"Report generated","10/15/2026 03:00:00"', "", QH.map(q).join(","),
    qrow({ IP: "10.20.0.11", DNS: "web01.test.darknode.ai", NetBIOS: "WEB01", OS: "Windows Server 2012 R2 Standard", "IP Status": "host scanned, found vuln", QID: "90464", Title: "Microsoft Windows Server Service Could Allow Remote Code Execution (MS08-067)", "Vuln Status": "Active", Type: "Vuln", Severity: "5", Port: "445", Protocol: "tcp", SSL: "no", "First Detected": "03/02/2026 06:14:00", "Last Detected": "10/14/2026 06:20:00", "Times Detected": "33", "CVE ID": "CVE-2008-4250", "Vendor Reference": "MS08-067", CVSS: "10.0", "CVSS Base": "10.0", Solution: "Apply MS08-067.", Exploitability: "Metasploit: ms08_067_netapi", "PCI Vuln": "yes", Category: "Windows" }),
    qrow({ IP: "10.20.0.12", DNS: "app01.test.darknode.ai", NetBIOS: "APP01", OS: "Ubuntu 18.04", "IP Status": "host scanned, found vuln", QID: "370094", Title: "Apache Struts Remote Code Execution Vulnerability (S2-032)", "Vuln Status": "New", Type: "Vuln", Severity: "3", Port: "8080", Protocol: "tcp", "First Detected": "09/28/2026 06:11:00", "Last Detected": "10/14/2026 06:22:00", "Times Detected": "3", "CVE ID": "CVE-2016-3081", "CVSS3 Base": "8.1", Solution: "Upgrade Apache Struts.", "PCI Vuln": "yes", Category: "CGI" }),
    qrow({ IP: "10.20.0.12", DNS: "app01.test.darknode.ai", NetBIOS: "APP01", OS: "Ubuntu 18.04", "IP Status": "host scanned, found vuln", QID: "87411", Title: "Apache Tomcat AJP File Read/Inclusion Vulnerability (Ghostcat)", "Vuln Status": "Fixed", Type: "Vuln", Severity: "5", Port: "8009", Protocol: "tcp", "First Detected": "05/10/2026 06:11:00", "Last Detected": "09/10/2026 06:22:00", "Times Detected": "18", "Date Last Fixed": "09/20/2026 06:30:00", "CVE ID": "CVE-2020-1938", "CVSS3 Base": "9.8", Solution: "Upgrade Apache Tomcat or disable the AJP connector.", Category: "Web server" }),
    qrow({ IP: "10.20.0.14", DNS: "mail01.test.darknode.ai", NetBIOS: "MAIL01", OS: "Debian GNU/Linux 9", "IP Status": "host scanned, found vuln", QID: "38739", Title: "Deprecated SSH Cryptographic Settings", "Vuln Status": "Active", Type: "Vuln", Severity: "2", Port: "22", Protocol: "tcp", "First Detected": "08/01/2025 06:10:00", "Last Detected": "10/14/2026 06:25:00", "Times Detected": "61", "CVSS3 Base": "5.3", Solution: "Disable CBC mode ciphers and weak MAC algorithms.", Category: "General remote services" }),
    qrow({ IP: "10.20.0.14", DNS: "mail01.test.darknode.ai", NetBIOS: "MAIL01", OS: "Debian GNU/Linux 9", "IP Status": "host scanned, found vuln", QID: "150379", Title: "Apache HTTP Server Path Traversal and Remote Code Execution", "Vuln Status": "Re-Opened", Type: "Vuln", Severity: "5", Port: "443", Protocol: "tcp", SSL: "yes", "First Detected": "01/10/2026 06:10:00", "Last Detected": "10/14/2026 06:25:00", "Times Detected": "12", "CVE ID": "CVE-2021-41773", "CVSS3 Base": "7.5", Solution: "Upgrade Apache HTTP Server to 2.4.51 or later.", Exploitability: "Exploit-DB: 50383", Category: "Web server" }),
  ].join("\n") + "\n";

  const b = (o) => ({ kind: "host", scanners: "Qualys", ...o });
  const baseline = JSON.stringify({
    meta: { tool: TOOL_ID, version: VERSION, now: "2026-09-15", note: "synthetic example baseline (last month)" },
    tables: { vulns: [
      b({ assetName: "web01.test.darknode.ai", ip: "10.20.0.11", fqdn: "web01.test.darknode.ai", os: "Windows Server 2012 R2 Standard", cve: "CVE-2008-4250", vulnKey: "CVE-2008-4250", title: "MS08-067 Server Service RCE", severity: "critical", cvss: 10, status: "open", firstSeen: "2026-03-02", lastSeen: "2026-09-14", port: "445" }),
      b({ assetName: "app01.test.darknode.ai", ip: "10.20.0.12", fqdn: "app01.test.darknode.ai", os: "Ubuntu 18.04", cve: "CVE-2023-48795", vulnKey: "CVE-2023-48795", title: "SSH Terrapin Prefix Truncation Weakness", severity: "medium", cvss: 5.9, status: "open", firstSeen: "2026-06-01", lastSeen: "2026-09-14", port: "22" }),
      b({ assetName: "db01.test.darknode.ai", ip: "10.20.0.13", fqdn: "db01.test.darknode.ai", os: "CentOS Linux 7", cve: "CVE-2021-3156", vulnKey: "CVE-2021-3156", title: "sudo heap-based buffer overflow (Baron Samedit)", severity: "high", cvss: 7.8, status: "open", firstSeen: "2026-04-01", lastSeen: "2026-09-14", port: "" }),
      b({ assetName: "files01.test.darknode.ai", ip: "10.20.0.15", fqdn: "files01.test.darknode.ai", os: "Windows Server 2016 Standard", cve: "CVE-2020-1472", vulnKey: "CVE-2020-1472", title: "Netlogon elevation of privilege (Zerologon)", severity: "critical", cvss: 10, status: "open", firstSeen: "2026-02-01", lastSeen: "2026-09-14", port: "445" }),
      b({ assetName: "mail01.test.darknode.ai", ip: "10.20.0.14", fqdn: "mail01.test.darknode.ai", os: "Debian GNU/Linux 9", cve: "CVE-2021-41773", vulnKey: "CVE-2021-41773", title: "Apache HTTP Server path traversal", severity: "high", cvss: 7.5, status: "fixed", firstSeen: "2026-01-10", lastSeen: "2026-08-01", port: "443" }),
    ] },
  }, null, 2);

  return {
    label: "synthetic example (not real data)",
    files: [
      { name: "example-scan.nessus", text: nessus, role: "current" },
      { name: "example-trivy-api.json", text: trivy, role: "current" },
      { name: "example-qualys.csv", text: qualys, role: "current" },
      { name: "example-baseline-last-month.json", text: baseline, role: "baseline" },
    ],
  };
}

/** Deterministic checks of the engine (no feeds needed). */
export function selfTest() {
  const tests = [];
  tests.push({ name: "CVSS 3.1 9.8 vector", pass: computeCvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") === 9.8 });
  tests.push({ name: "CVSS 3.1 scope changed 6.4", pass: computeCvss31("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N") === 6.4 });
  // Spec arithmetic: 6.42*0.22 + 8.22*0.55*0.44*0.27*0.62 = 1.745 -> roundup 1.8.
  tests.push({ name: "CVSS 3.1 low vector 1.8", pass: computeCvss31("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N") === 1.8 });
  tests.push({ name: "CVSS 2 7.5 vector", pass: computeCvss2("AV:N/AC:L/Au:N/C:P/I:P/A:P") === 7.5 });
  const ex = exampleDataset();
  const p = parseInput(ex.files);
  tests.push({ name: "four example files recognised", pass: p.files.length === 4 && p.files.every((f) => f.format !== "unknown" && f.format !== "generic") });
  const r = analyze(p, { now: "2026-10-15T12:00:00Z" });
  tests.push({ name: "Nessus + Qualys MS08-067 merged into one row", pass: r.tables.vulns.filter((v) => v.cve === "CVE-2008-4250").length === 1 && /Nessus/.test(r.tables.vulns.find((v) => v.cve === "CVE-2008-4250").scanners) && /Qualys/.test(r.tables.vulns.find((v) => v.cve === "CVE-2008-4250").scanners) });
  tests.push({ name: "burn-down shows new and fixed", pass: r.summary.newSinceBaseline > 0 && r.summary.fixed > 0 });
  tests.push({ name: "deterministic", pass: JSON.stringify(r) === JSON.stringify(analyze(p, { now: "2026-10-15T12:00:00Z" })) });
  tests.push({ name: "empty input yields no findings", pass: analyze([]).findings.length === 0 });
  return { pass: tests.every((t) => t.pass), tests };
}
