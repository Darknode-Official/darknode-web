// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Awareness & Phishing-Test Analytics engine (awareness). Reads phishing
// simulation results (GoPhish results / raw events CSV and API JSON, KnowBe4
// Reporting API JSON and CSV, Microsoft Defender Attack Simulation Training
// (Graph JSON or portal CSV), Proofpoint Security Awareness CSV, any generic
// results CSV), LMS training completions and an HR roster, then computes
// delivered / opened / clicked / submitted / reported rates with their
// denominators, privacy-suppressed breakdowns, people who need follow-up
// training (repeat clickers, across imports and the saved history), high-risk
// roles, overdue and missing remedial training, and per-campaign trends.
//
// Pure: no DOM, no network, no clock (opts.now or the newest date in the data).
// Deterministic: everything is sorted; same input -> byte-identical JSON. Runs in
// node tests and inside a Blob module Worker. Never stores message bodies: the
// GoPhish `details` column is ignored.

import { sniff, parseCsv, iterJson, findColumn, normHeader, flatten } from "../ingest/parse.js";

export const TOOL_ID = "awareness";
export const VERSION = "1.0.0";
const DAY = 86400000;

// ---------------------------------------------------------------------------
// Column aliases per logical column, grouped by input role. Alias order wins.
// ---------------------------------------------------------------------------
const EMAIL = ["email", "Email", "Email Address", "E-mail", "User Email", "Recipient Email", "Recipient", "user.email", "simulationUser.email", "User Principal Name", "UPN", "Work Email", "mail", "UserMail", "Username", "User"];

export const COLUMNS = {
  // Per-recipient result rows where every event is its own column (timestamp or yes/no).
  outcome: {
    email: EMAIL,
    campaign: ["campaign", "Campaign", "Campaign Name", "Campaign Title", "Simulation", "Simulation Name", "Phishing Test", "PST Name", "Test Name"],
    sent: ["sent", "Delivered At", "Delivered", "delivered_at", "Sent", "Sent At", "Sent Date", "Date Sent", "Delivered Date", "send_date", "Email Sent", "SuccessfullyDeliveredEmail_TimeStamp", "JustSimulationMessageDelivered_TimeStamp"],
    opened: ["opened", "Opened At", "Opened", "opened_at", "Email Opened", "Opened Date", "Message Read", "Read", "Primary Email Opened", "MessageRead_TimeStamp", "Message read on"],
    clicked: ["clicked", "Clicked At", "Clicked", "clicked_at", "Clicked Link", "Clicked Date", "Link Clicked", "Click Date", "Primary Clicked", "EmailLinkClicked_TimeStamp", "AttachmentLinkClicked_TimeStamp", "AttachmentOpened_TimeStamp"],
    submitted: ["submitted", "Data Entered At", "Data Entered", "data_entered_at", "Submitted Data", "Credentials Submitted", "Data Submitted", "Data Submission Date", "Compromised Date", "Compromised", "compromisedDateTime", "Credential Supplied", "Primary Compromised Login"],
    reported: ["reported", "Reported At", "Reported", "reported_at", "Email Reported", "Reported Date", "Reported Phish", "reportedPhishDateTime", "Report Date", "Phishing Reported On"],
    bounced: ["bounced", "Bounced At", "Bounced", "bounced_at", "Email Bounced", "FailedToDeliverEmail_TimeStamp"],
    title: ["position", "Position", "Title", "Job Title"],
    // Separate timestamp columns when the event columns are yes/no flags (e.g. "Clicked" + "Clicked Date").
    clickedTime: ["Clicked Date", "Click Date", "Clicked Date/Time", "Clicked Time", "Date Clicked"],
    submittedTime: ["Data Entered Date", "Data Submitted Date", "Data Submission Date", "Compromised Date", "Date Login Compromised", "CredSupplied_TimeStamp(Compromised)", "Compromised on"],
    reportedTime: ["Reported Date", "Report Date", "Reported Time", "Date Reported", "Reported on", "Phishing Reported On"],
  },
  // GoPhish "Export CSV - Results": one final status per recipient.
  status: {
    email: ["email"], campaign: ["campaign"], status: ["status"], sent: ["send_date"], reported: ["reported"], modified: ["modified_date"], title: ["position"],
  },
  // GoPhish "Export CSV - Raw Events" and API timeline: one event per row.
  events: {
    email: ["email"], campaign: ["campaign", "campaign_id"], time: ["time"], message: ["message"],
  },
  training: {
    email: EMAIL.concat(["Learner", "Learner Email"]),
    course: ["course", "Course", "Course Name", "Course Title", "Training", "Training Name", "Module", "Content Title", "Assignment", "Enrollment"],
    assigned: ["assigned", "Assigned", "Assigned Date", "Assigned At", "assigned_at", "Enrollment Date", "Enrolled", "Enrolled Date", "Enrollment Start"],
    due: ["due", "Due", "Due Date", "Due At", "due_date", "Deadline"],
    completed: ["completed", "Completed", "Completed Date", "Completion Date", "Completed At", "completion_date", "Date Completed"],
    status: ["status", "Status", "Completion Status", "Enrollment Status"],
  },
  roster: {
    email: EMAIL.slice(0, 13),
    name: ["name", "Full Name", "Display Name", "Employee Name"],
    department: ["department", "Department", "Dept", "Division", "Org Unit", "Team"],
    title: ["title", "Job Title", "Title", "Position", "Role"],
    manager: ["manager", "Manager", "Manager Email", "Manager Name", "Reports To", "Supervisor"],
    hireDate: ["hire date", "Hire Date", "hire_date", "Start Date", "Date Hired", "Original Hire Date", "Hired"],
    privileged: ["privileged", "Privileged", "Privileged Access", "Is Admin", "Admin", "IT Admin"],
    finance: ["finance", "Finance", "Finance Role", "Payments Access"],
    exec: ["exec", "Executive", "Exec", "Is Executive", "VIP"],
  },
};

/** Recognised input kinds. confidence comes from detect(). */
export const KINDS = {
  "gophish-results": { label: "GoPhish campaign results (CSV)", role: "outcome", mode: "status" },
  "gophish-events": { label: "GoPhish raw events (CSV)", role: "outcome", mode: "events" },
  "gophish-json": { label: "GoPhish API campaign (JSON)", role: "outcome", mode: "events" },
  "knowbe4-json": { label: "KnowBe4 Reporting API recipients (JSON)", role: "outcome", mode: "outcome" },
  "knowbe4-csv": { label: "KnowBe4 phishing test (CSV)", role: "outcome", mode: "outcome" },
  "mdo-json": { label: "Microsoft Graph attack simulation report (JSON)", role: "outcome", mode: "outcome" },
  "mdo-csv": { label: "Microsoft Defender Attack Simulation (CSV)", role: "outcome", mode: "outcome" },
  "proofpoint-csv": { label: "Proofpoint Security Awareness / ThreatSim (CSV)", role: "outcome", mode: "outcome" },
  "generic-phish": { label: "Phishing results (generic CSV)", role: "outcome", mode: "outcome" },
  lms: { label: "LMS training assignments (CSV)", role: "training", mode: "training" },
  roster: { label: "HR roster (CSV)", role: "roster", mode: "roster" },
  history: { label: "Awareness history (JSON)", role: "history", mode: null },
  unknown: { label: "Not recognised", role: null, mode: null },
};

/** Logical keys per mapping mode, in the order the mapping panel shows them. */
export const MODE_KEYS = {
  outcome: ["email", "campaign", "sent", "opened", "clicked", "submitted", "reported", "bounced", "title", "clickedTime", "submittedTime", "reportedTime"],
  status: ["email", "campaign", "status", "sent", "reported", "title"],
  events: ["email", "campaign", "time", "message"],
  training: ["email", "course", "assigned", "due", "completed", "status"],
  roster: ["email", "name", "department", "title", "manager", "hireDate", "privileged", "finance", "exec"],
};

/** Human labels for logical keys (mapping panel). */
export const KEY_LABELS = {
  email: "Email", campaign: "Campaign", sent: "Delivered / sent", opened: "Opened", clicked: "Clicked", submitted: "Submitted data / compromised",
  reported: "Reported", bounced: "Bounced / error", title: "Job title", status: "Status", time: "Event time", message: "Event message",
  course: "Course", assigned: "Assigned date", due: "Due date", completed: "Completed date", name: "Name", department: "Department",
  clickedTime: "Click time (if separate)", submittedTime: "Submit time (if separate)", reportedTime: "Report time (if separate)",
  manager: "Manager", hireDate: "Hire date", privileged: "Privileged flag", finance: "Finance flag", exec: "Executive flag",
};

/** Required keys per mode: without them the file cannot be used at all. */
const REQUIRED = { outcome: ["email", "clicked"], status: ["email", "status"], events: ["email", "message"], training: ["email", "course"], roster: ["email"] };

/** Tunable thresholds; the UI renders these with real labels. */
export const DEFAULTS = {
  minGroupSize: 5, // breakdown groups with fewer distinct people are suppressed
  repeatClickMin: 2, // clicked in at least this many campaigns -> needs follow-up training
  remedialDays: 30, // training assigned or completed within N days after a click
  remedialCourse: "", // optional keyword the remedial course name must contain; empty = any course
  highRiskKeywords: "finance, accounts payable, payroll, treasury, controller, cfo, ceo, coo, cto, ciso, chief, president, executive, it admin, administrator, sysadmin, domain admin, helpdesk",
  minTrendSample: 20, // a campaign needs this many delivered emails before it is used in a trend flag
  baselineClickRate: "", // optional baseline click rate in percent, entered by the user; empty = off
  reportTargetRate: "", // optional report-rate target in percent; empty = off
  now: "", // ISO date; empty = newest date found in the data
};

// ---------------------------------------------------------------------------
// Control references (real standards only)
// ---------------------------------------------------------------------------
const C = {
  sp80050: { framework: "NIST SP 800-50", id: "Rev. 1 (2024)" },
  iso: { framework: "ISO 27001:2022", id: "A.6.3" },
  pci1263: { framework: "PCI DSS 4.0.1", id: "12.6.3" },
  pci12631: { framework: "PCI DSS 4.0.1", id: "12.6.3.1" },
  cis141: { framework: "CIS Controls v8", id: "14.1" },
  cis142: { framework: "CIS Controls v8", id: "14.2" },
  cis146: { framework: "CIS Controls v8", id: "14.6" },
  cis149: { framework: "CIS Controls v8", id: "14.9" },
  at2: { framework: "NIST 800-53", id: "AT-2" },
  at21: { framework: "NIST 800-53", id: "AT-2(1)" },
  at23: { framework: "NIST 800-53", id: "AT-2(3)" },
  at3: { framework: "NIST 800-53", id: "AT-3" },
  cc14: { framework: "SOC 2", id: "CC1.4" },
  cc22: { framework: "SOC 2", id: "CC2.2" },
  t1566: { framework: "MITRE ATT&CK", id: "T1566" },
  t1566002: { framework: "MITRE ATT&CK", id: "T1566.002" },
};

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------
const str = (v) => (v == null ? "" : String(v)).trim();
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const FALSE_WORDS = new Set(["", "false", "no", "n", "0", "-", "n/a", "na", "none", "null", "never", "not clicked", "not reported", "not opened", "not delivered", "0001-01-01t00:00:00z"]);
const TRUE_WORDS = new Set(["true", "yes", "y", "1", "x", "t"]);

/** Parse a timestamp deterministically (ISO with any fraction / offset, or US M/D/YYYY [h:mm[:ss] AM|PM]) to epoch ms, UTC when no zone. */
export function parseTime(v) {
  if (v == null || v === "") return null;
  if (typeof v === "number") return Number.isFinite(v) && v > 31536000000 && v < 7258118400000 ? v : null;
  const s = String(v).trim();
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?\s*(Z|UTC|[+-]\d{2}:?\d{2})?$/i);
  if (m) {
    const y = +m[1];
    if (y < 1971 || y > 2199) return null;
    let t = Date.UTC(y, +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0), m[7] ? +(m[7] + "00").slice(0, 3) : 0);
    const tz = m[8];
    if (tz && !/^(z|utc)$/i.test(tz)) {
      const d = tz.replace(":", "");
      const sign = d[0] === "-" ? -1 : 1;
      t -= sign * (+d.slice(1, 3) * 60 + +d.slice(3, 5)) * 60000;
    }
    return Number.isFinite(t) ? t : null;
  }
  m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:[ T,]+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?)?(?:\s*(?:UTC|Z))?$/i);
  if (m) {
    const y = +m[3];
    if (y < 1971 || y > 2199) return null;
    let h = +(m[4] || 0);
    if (m[7]) { const pm = /pm/i.test(m[7]); if (h === 12) h = pm ? 12 : 0; else if (pm) h += 12; }
    const t = Date.UTC(y, +m[1] - 1, +m[2], h, +(m[5] || 0), +(m[6] || 0));
    return Number.isFinite(t) ? t : null;
  }
  return null;
}

/** Event / flag value: true for yes/true/1, a timestamp, a positive count, or other non-negative text. */
export function truthy(v) {
  if (v === true) return true;
  if (v === false || v == null) return false;
  if (typeof v === "number") return v > 0;
  const s = String(v).trim().toLowerCase();
  if (FALSE_WORDS.has(s)) return false;
  if (TRUE_WORDS.has(s)) return true;
  if (/^-?\d+(\.\d+)?$/.test(s)) return Number(s) > 0;
  if (/^(not|no|never|none|false)\b/.test(s)) return false;
  return true;
}

/** Normalised identity key: lower case, mailto: stripped. Never invents a domain. */
export function normEmail(v) {
  return str(v).replace(/^mailto:/i, "").replace(/^<|>$/g, "").toLowerCase();
}

const iso = (t) => (t == null ? "" : new Date(t).toISOString());
const day = (t) => (t == null ? "" : new Date(t).toISOString().slice(0, 10));
const round = (n, d = 1) => (n == null || !Number.isFinite(n) ? null : Math.round(n * 10 ** d) / 10 ** d);
const rate = (num, den) => ({ num, den, pct: den ? round((num / den) * 100, 1) : null });
const fmtRate = (r) => (r && r.den ? r.pct + "% (" + r.num + "/" + r.den + ")" : "n/a");

function median(arr) {
  const a = arr.filter((x) => x != null && Number.isFinite(x)).sort((x, y) => x - y);
  if (!a.length) return null;
  const mid = a.length >> 1;
  return a.length % 2 ? a[mid] : (a[mid - 1] + a[mid]) / 2;
}

function fileStem(name) {
  return str(name).replace(/^.*[\\/]/, "").replace(/\.(csv|tsv|json|txt)$/i, "") || "input";
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------
const GOPHISH_RESULT_HEADERS = ["id", "status", "ip", "latitude", "longitude", "send_date", "reported", "modified_date", "email", "first_name", "last_name", "position"];
const GOPHISH_EVENT_HEADERS = ["campaign_id", "email", "time", "message", "details"];
// Microsoft Defender Attack simulation training CSV export fields (Microsoft Learn,
// attack-simulation-training-insights, Appendix).
const MDO_CORE = ["UserName", "UserMail", "Compromised"];
// Proofpoint Security Awareness (ThreatSim) campaign CSV header definitions, common to
// the data-entry, attachment and drive-by layouts.
const PROOFPOINT_CORE = ["Email Address", "Campaign Title", "Date Sent", "Primary Clicked", "Date Clicked", "Reported", "Date Reported"];
// Documented exports that split one event across per-technique columns; the first non-empty one wins.
const COALESCE = {
  sent: ["SuccessfullyDeliveredEmail_TimeStamp", "JustSimulationMessageDelivered_TimeStamp"],
  clicked: ["EmailLinkClicked_TimeStamp", "AttachmentLinkClicked_TimeStamp", "AttachmentOpened_TimeStamp", "Primary Clicked", "Primary Attachment Opened"],
  clickedTime: ["Date Clicked", "Date Attachment Opened"],
};
const LMS_TEMPLATE = ["user", "course", "assigned", "due", "completed"];
const ROSTER_TEMPLATE = ["email", "department", "title", "manager", "hire date"];

function autoMap(headers, mode) {
  const spec = COLUMNS[mode] || {};
  const out = {};
  for (const k of MODE_KEYS[mode] || []) { const h = findColumn(headers, spec[k] || []); if (h) out[k] = h; }
  if (mode === "training" && !out.email) { const h = findColumn(headers, ["user", "User", "Learner", "Name"]); if (h) out.email = h; }
  return out;
}

/**
 * Detect the input kind from the header row (exact vendor header sets give
 * "high"; keyword matches give "medium"; generic aliases give "low").
 * @returns {{ kind, label, role, mode, confidence, mapping, missing }}
 */
export function detect(headers) {
  const hs = (headers || []).map(String);
  const exact = new Set(hs.map((h) => h.trim()));
  const norm = new Set(hs.map(normHeader));
  const has = (...n) => n.every((x) => norm.has(normHeader(x)));
  const any = (...n) => n.some((x) => norm.has(normHeader(x)));
  let kind = "unknown", confidence = "low";

  const gpr = GOPHISH_RESULT_HEADERS.filter((h) => exact.has(h)).length;
  if (gpr >= 10 && ["email", "status", "send_date", "reported"].every((h) => exact.has(h))) { kind = "gophish-results"; confidence = gpr === GOPHISH_RESULT_HEADERS.length ? "high" : "medium"; }
  else if (["campaign_id", "email", "time", "message"].every((h) => exact.has(h))) { kind = "gophish-events"; confidence = "high"; }
  else if (any("Campaign Title", "Campaign Type") || hs.some((h) => /threatsim/i.test(h))) { kind = "proofpoint-csv"; confidence = PROOFPOINT_CORE.every((h) => exact.has(h)) ? "high" : "medium"; }
  else if (any("Data Entered", "Data Entered At", "Macro Enabled", "Macro Enabled At", "Attachment Opened", "Attachment Opened At", "Replied At")) { kind = "knowbe4-csv"; confidence = "medium"; }
  else if (any("Compromised", "Compromised Date", "Simulation Name", "Reported Phish", "Simulation", "UserMail", "Phishing Reported On", "SuccessfullyDeliveredEmail_TimeStamp")) {
    kind = "mdo-csv"; confidence = MDO_CORE.every((h) => exact.has(h)) && hs.some((h) => /_TimeStamp/.test(h)) ? "high" : "medium";
  }
  else if (any("course", "course name", "course title", "training", "training name", "module", "content title") && any("completed", "completed date", "completion date", "completed at", "due", "due date", "status", "completion status")) {
    kind = "lms"; confidence = LMS_TEMPLATE.every((h) => exact.has(h)) ? "high" : "medium";
  } else if (any(...COLUMNS.outcome.clicked) && findColumn(hs, EMAIL)) { kind = "generic-phish"; confidence = "low"; }
  else if (findColumn(hs, COLUMNS.roster.email) && [COLUMNS.roster.department, COLUMNS.roster.title, COLUMNS.roster.manager, COLUMNS.roster.hireDate].filter((a) => findColumn(hs, a)).length >= 2) {
    kind = "roster"; confidence = ROSTER_TEMPLATE.every((h) => exact.has(h)) ? "high" : "medium";
  }
  return describe(kind, confidence, hs);
}

function describe(kind, confidence, headers, mappingOverride) {
  const k = KINDS[kind] || KINDS.unknown;
  const mapping = mappingOverride || (k.mode ? autoMap(headers, k.mode) : {});
  const missing = k.mode ? (REQUIRED[k.mode] || []).filter((x) => !mapping[x]) : [];
  return { kind, label: k.label, role: k.role, mode: k.mode, confidence, mapping, missing };
}

// JSON shapes -> canonical rows (fixed mapping, high confidence).
function jsonToFile(name, items) {
  const arr = (items || []).filter((x) => x && typeof x === "object");
  const first = arr[0] || {};
  // Awareness history (exported by this tool)
  if (arr.length && arr.every((x) => typeof x.email === "string" && Array.isArray(x.campaigns))) {
    return { ...describe("history", "high", []), headers: ["email", "campaigns"], rows: arr };
  }
  // GoPhish campaign objects (GET /api/campaigns/, /api/campaigns/:id, /api/campaigns/:id/results)
  if (arr.some((x) => Array.isArray(x.results) || Array.isArray(x.timeline))) {
    const rows = [];
    for (const c of arr) {
      const campaign = str(c.name) || (c.id != null ? "GoPhish campaign " + c.id : fileStem(name));
      const tl = Array.isArray(c.timeline) ? c.timeline : [];
      if (tl.length) {
        for (const e of tl) if (e && e.email) rows.push({ campaign, email: str(e.email), time: str(e.time), message: str(e.message) });
      } else {
        for (const r of Array.isArray(c.results) ? c.results : []) {
          if (!r || !r.email) continue;
          rows.push({ campaign, email: str(r.email), time: str(r.send_date), message: "Email Sent" });
          const st = str(r.status);
          if (/opened|clicked|submitted/i.test(st)) rows.push({ campaign, email: str(r.email), time: "", message: st });
          if (r.reported === true || /reported/i.test(st)) rows.push({ campaign, email: str(r.email), time: "", message: "Email Reported" });
          if (/error/i.test(st)) rows.push({ campaign, email: str(r.email), time: "", message: "Error Sending Email" });
        }
      }
    }
    const headers = ["campaign", "email", "time", "message"];
    return { ...describe("gophish-json", "high", headers), headers, rows };
  }
  // KnowBe4 Reporting API: /v1/phishing/security_tests/{pst_id}/recipients
  if (arr.length && ("pst_id" in first || ("clicked_at" in first && first.user && typeof first.user === "object"))) {
    const rows = arr.map((r) => {
      const click = r.clicked_at || r.attachment_opened_at || r.macro_enabled_at || (r.qr_code_scanned ? r.qr_code_scanned : "");
      return {
        email: str(r.user && r.user.email || r.email), campaign: r.pst_id != null ? "KnowBe4 PST " + r.pst_id : "",
        sent: str(r.delivered_at), opened: str(r.opened_at), clicked: click === true ? "true" : str(click), submitted: str(r.data_entered_at),
        reported: str(r.reported_at), bounced: str(r.bounced_at), title: "",
      };
    });
    const headers = ["email", "campaign", "sent", "opened", "clicked", "submitted", "reported", "bounced", "title"];
    return { ...describe("knowbe4-json", "high", headers), headers, rows };
  }
  // Microsoft Graph attack simulation: userSimulationDetails (simulations/{id}/report/simulationUsers)
  if (arr.length && first.simulationUser && typeof first.simulationUser === "object") {
    const rows = arr.map((u) => {
      const ev = Array.isArray(u.simulationEvents) ? u.simulationEvents : [];
      const at = (re) => { const t = ev.filter((e) => e && re.test(str(e.eventName))).map((e) => parseTime(e.eventDateTime)).filter((x) => x != null).sort((a, b) => a - b)[0]; return t != null ? iso(t) : ""; };
      const clicked = at(/click/i);
      return {
        email: str(u.simulationUser.email), campaign: "", sent: at(/deliver/i), opened: at(/read|open/i),
        clicked: clicked || (u.isCompromised ? (str(u.compromisedDateTime) || "true") : ""),
        submitted: u.isCompromised ? (str(u.compromisedDateTime) || "true") : at(/cred|submit/i),
        reported: str(u.reportedPhishDateTime) || at(/report/i), bounced: "", title: "",
      };
    });
    const headers = ["email", "campaign", "sent", "opened", "clicked", "submitted", "reported", "bounced", "title"];
    return { ...describe("mdo-json", "high", headers), headers, rows };
  }
  // Anything else: flatten and detect by headers.
  const rows = arr.map((x) => flatten(x));
  const hs = [...new Set(rows.flatMap((r) => Object.keys(r)))].sort();
  return { ...detect(hs), headers: hs, rows };
}

function parseOne(name, text) {
  const t = String(text == null ? "" : text);
  const skipped = [];
  if (!t.trim()) return { name, ...describe("unknown", "low", []), format: "empty", headers: [], rows: [], skipped, campaign: "" };
  const format = sniff(t).format;
  if (format === "json" || format === "ndjson") {
    let items = [];
    try {
      // A single GoPhish campaign object carries results[] and timeline[]; keep it whole
      // (iterJson would unwrap "results").
      let whole = null;
      try { whole = JSON.parse(t.replace(/^\uFEFF/, "")); } catch (_) {}
      items = whole && !Array.isArray(whole) && typeof whole === "object" && Array.isArray(whole.results) && ("timeline" in whole || "name" in whole) ? [whole] : iterJson(t);
    } catch (e) { skipped.push({ check: "parse " + name, reason: "invalid JSON: " + (e && e.message || e) }); }
    return { name, format: "json", ...jsonToFile(name, items), skipped, campaign: "" };
  }
  const { headers, rows } = parseCsv(t);
  return { name, format: format === "tsv" ? "tsv" : "csv", ...detect(headers), headers, rows, skipped, campaign: "" };
}

/**
 * Parse one text or many files ({name, text}[]). Never throws.
 * Returns { format, headers, rows, skipped, files[] } where top-level fields describe the first file.
 */
export function parseInput(input) {
  const list = Array.isArray(input) ? input : [{ name: "input", text: input }];
  const files = list.map((f, i) => parseOne(str(f && f.name) || "file-" + (i + 1), f && f.text));
  const f0 = files[0] || { format: "empty", headers: [], rows: [] };
  return { format: f0.format, headers: f0.headers, rows: f0.rows, skipped: files.flatMap((f) => f.skipped || []), files };
}

/** Re-describe a file for a user-chosen kind and/or mapping (UI mapping panel). */
export function remapFile(file, kind, mapping) {
  const d = describe(kind, "user", file.headers || [], mapping || null);
  return { ...file, ...d };
}

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------
const STATUS_RANK = { "email sent": 1, "email opened": 2, "clicked link": 3, "submitted data": 4 };

function emptyOutcome(campaign, email) {
  return { campaign, email, sent: false, opened: false, clicked: false, submitted: false, reported: false, bounced: false, sentAt: null, openedAt: null, clickedAt: null, submittedAt: null, reportedAt: null, title: "" };
}

const minT = (a, b) => (a == null ? b : b == null ? a : Math.min(a, b));

function mergeOutcome(into, o) {
  for (const k of ["sent", "opened", "clicked", "submitted", "reported", "bounced"]) into[k] = into[k] || o[k];
  for (const k of ["sentAt", "openedAt", "clickedAt", "submittedAt", "reportedAt"]) into[k] = minT(into[k], o[k]);
  if (!into.title && o.title) into.title = o.title;
}

function finishOutcome(o) {
  // A submission implies a click, a click implies an open, any engagement implies delivery.
  if (o.submitted) o.clicked = true;
  if (o.clicked) o.opened = true;
  if (o.opened || o.reported) o.sent = true;
  if (o.sent) o.bounced = false;
  return o;
}

function normalizeOutcomeFile(f, acc, ctx, progress) {
  const m = f.mapping || {};
  const rows = f.rows || [];
  const override = str(f.campaign);
  const stem = fileStem(f.name);
  const caps = { report: !!m.reported, open: !!m.opened, clickTime: false, reportTime: false, sentTime: false };
  let noEmail = 0;
  const touched = new Set();
  // Per-technique columns of one event (only when the mapped column is one of them).
  const alt = {};
  for (const [k, names] of Object.entries(COALESCE)) {
    const want = new Set(names.map(normHeader));
    if (!m[k] || !want.has(normHeader(m[k]))) continue;
    alt[k] = [m[k]].concat((f.headers || []).filter((h) => h !== m[k] && want.has(normHeader(h))));
  }
  const campaignOf = (r) => {
    if (override) return override;
    const v = m.campaign ? str(r[m.campaign]) : "";
    if (v) return f.kind === "gophish-events" && /^\d+$/.test(v) ? "GoPhish campaign " + v : v;
    return stem;
  };
  for (let i = 0; i < rows.length; i++) {
    progress(i);
    const r = rows[i];
    const email = normEmail(r[m.email]);
    if (!email) { if (f.mode !== "events") noEmail++; continue; } // GoPhish "Campaign Created" has no recipient
    const campaign = campaignOf(r);
    const o = emptyOutcome(campaign, email);
    if (f.mode === "events") {
      const msg = str(r[m.message]).toLowerCase();
      const t = parseTime(r[m.time]);
      if (/email sent/.test(msg)) { o.sent = true; o.sentAt = t; }
      else if (/opened/.test(msg)) { o.opened = true; o.openedAt = t; caps.open = true; }
      else if (/clicked/.test(msg)) { o.clicked = true; o.clickedAt = t; }
      else if (/submitted/.test(msg)) { o.submitted = true; o.submittedAt = t; }
      else if (/reported/.test(msg)) { o.reported = true; o.reportedAt = t; }
      else if (/error/.test(msg)) { o.bounced = true; }
      else continue; // "Campaign Created" and other non-recipient events
      caps.report = true; caps.open = true;
    } else if (f.mode === "status") {
      const st = str(r[m.status]).toLowerCase();
      const rank = STATUS_RANK[st] || 0;
      o.sent = rank >= 1 || st === "email reported";
      o.opened = rank >= 2; o.clicked = rank >= 3; o.submitted = rank >= 4;
      o.reported = st === "email reported" || (m.reported ? truthy(r[m.reported]) : false);
      o.bounced = /error/.test(st);
      o.sentAt = m.sent ? parseTime(r[m.sent]) : null;
      if (!o.sent && !o.bounced && !o.reported) continue; // scheduled / queued / sending
      caps.open = true; caps.report = caps.report || st === "email reported";
    } else {
      const val = (k) => {
        const cols = alt[k];
        if (cols) { for (const h of cols) if (truthy(r[h])) return r[h]; }
        return m[k] ? r[m[k]] : undefined;
      };
      const ev = (k) => { const v = val(k); return { on: m[k] ? truthy(v) : false, at: m[k] ? parseTime(v) : null }; };
      const s = ev("sent"), op = ev("opened"), c = ev("clicked"), su = ev("submitted"), re = ev("reported"), b = ev("bounced");
      o.sent = m.sent ? s.on : true; o.sentAt = s.at;
      o.opened = op.on; o.openedAt = op.at; o.clicked = c.on; o.clickedAt = c.at;
      o.submitted = su.on; o.submittedAt = su.at; o.reported = re.on; o.reportedAt = re.at; o.bounced = b.on && !o.sent;
      const sepT = (k, on) => (on && m[k] ? parseTime(val(k)) : null);
      if (o.clickedAt == null) o.clickedAt = sepT("clickedTime", o.clicked);
      if (o.submittedAt == null) o.submittedAt = sepT("submittedTime", o.submitted);
      if (o.reportedAt == null) o.reportedAt = sepT("reportedTime", o.reported);
      if (m.sent && !s.on && !b.on && !op.on && !c.on && !su.on && !re.on) o.bounced = false;
    }
    if (m.title) o.title = str(r[m.title]);
    if (o.clickedAt != null) caps.clickTime = true;
    if (o.reportedAt != null) caps.reportTime = true;
    if (o.sentAt != null) caps.sentTime = true;
    touched.add(campaign);
    const key = campaign + "\u0000" + email;
    const cur = acc.get(key);
    if (cur) mergeOutcome(cur, o); else acc.set(key, o);
  }
  if (noEmail) ctx.warnings.push(f.name + ": " + noEmail + " row(s) without an email were ignored.");
  return { caps, touched };
}

function normalizeTraining(f, out, ctx) {
  const m = f.mapping || {};
  let noEmail = 0;
  for (const r of f.rows || []) {
    const email = normEmail(r[m.email]);
    if (!email) { noEmail++; continue; }
    const statusTxt = m.status ? str(r[m.status]) : "";
    const completedAt = m.completed ? parseTime(r[m.completed]) : null;
    const completed = completedAt != null || (m.completed ? truthy(r[m.completed]) && !/^(in progress|not started|past due|overdue)/i.test(str(r[m.completed])) : false) || /^(completed?|passed|finished|done)\b/i.test(statusTxt);
    out.push({
      email, course: m.course ? str(r[m.course]) : "", assignedAt: m.assigned ? parseTime(r[m.assigned]) : null, dueAt: m.due ? parseTime(r[m.due]) : null,
      completed, completedAt, file: f.name,
    });
  }
  if (noEmail) ctx.warnings.push(f.name + ": " + noEmail + " training row(s) without a user were ignored.");
  return { due: !!m.due, assigned: !!m.assigned, completed: !!(m.completed || m.status) };
}

function normalizeRoster(f, out, ctx) {
  const m = f.mapping || {};
  for (const r of f.rows || []) {
    const email = normEmail(r[m.email]);
    if (!email) continue;
    const prev = out.get(email) || {};
    out.set(email, {
      email, name: m.name ? str(r[m.name]) : prev.name || "", department: m.department ? str(r[m.department]) : prev.department || "",
      title: m.title ? str(r[m.title]) : prev.title || "", manager: m.manager ? normEmailOrName(r[m.manager]) : prev.manager || "",
      hireAt: m.hireDate ? parseTime(r[m.hireDate]) : prev.hireAt == null ? null : prev.hireAt,
      privileged: m.privileged ? truthy(r[m.privileged]) : !!prev.privileged, finance: m.finance ? truthy(r[m.finance]) : !!prev.finance,
      exec: m.exec ? truthy(r[m.exec]) : !!prev.exec,
    });
  }
  return { department: !!m.department, title: !!m.title, manager: !!m.manager, hireDate: !!m.hireDate, flags: !!(m.privileged || m.finance || m.exec) };
}

function normEmailOrName(v) { const s = str(v); return s.includes("@") ? normEmail(s) : s; }

/** Normalise history records (register) into per-person campaign outcomes. */
function historyEntries(records) {
  const out = [];
  for (const rec of records || []) {
    const email = normEmail(rec && rec.email);
    if (!email || !Array.isArray(rec.campaigns)) continue;
    for (const c of rec.campaigns) {
      if (!c || !str(c.campaign)) continue;
      out.push({ email, campaign: str(c.campaign), date: str(c.date), clicked: !!c.clicked, submitted: !!c.submitted, reported: !!c.reported });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Statistics helpers
// ---------------------------------------------------------------------------
function stats(list) {
  const delivered = list.filter((o) => o.sent);
  const n = delivered.length;
  const c = (k) => delivered.filter((o) => o[k]).length;
  const rbc = delivered.filter((o) => o.reported && (!o.clicked || (o.reportedAt != null && o.clickedAt != null && o.reportedAt < o.clickedAt))).length;
  return {
    targeted: list.length, delivered: n, bounced: list.filter((o) => o.bounced).length,
    opened: rate(c("opened"), n), clicked: rate(c("clicked"), n), submitted: rate(c("submitted"), n), reported: rate(c("reported"), n),
    reportBeforeClick: rate(rbc, n),
  };
}

/** Two-proportion z statistic (pooled). Null when undefined. */
export function twoPropZ(x1, n1, x2, n2) {
  if (!n1 || !n2) return null;
  const p = (x1 + x2) / (n1 + n2);
  const se = Math.sqrt(p * (1 - p) * (1 / n1 + 1 / n2));
  if (!se) return null;
  return (x2 / n2 - x1 / n1) / se;
}

function tenureBand(hireAt, now) {
  if (hireAt == null || now == null) return "unknown";
  const d = (now - hireAt) / DAY;
  if (d < 0) return "unknown";
  if (d < 90) return "under 90 days";
  if (d < 365) return "90 days to 1 year";
  if (d < 3 * 365) return "1 to 3 years";
  if (d < 5 * 365) return "3 to 5 years";
  return "5 years or more";
}

function keywords(s) { return String(s || "").split(/[,;\n]+/).map((x) => x.trim().toLowerCase()).filter(Boolean); }

function finding(f) {
  const ev = f.evidence || [];
  return { ...f, evidenceCount: f.evidenceCount != null ? f.evidenceCount : ev.length, evidence: ev.slice(0, 50) };
}

const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
/**
 * analyze(dataset, opts, ctx?)
 * dataset = { files: parsed files (from parseInput, optionally remapped), history?: register records }
 *         | rows[] (one file, auto-detected)
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  const minGroup = Math.max(1, Math.floor(Number(o.minGroupSize) || DEFAULTS.minGroupSize));
  const repeatMin = Math.max(2, Math.floor(Number(o.repeatClickMin) || DEFAULTS.repeatClickMin));
  const remedialDays = Math.max(0, Math.floor(Number(o.remedialDays)));
  const minTrend = Math.max(1, Math.floor(Number(o.minTrendSample) || DEFAULTS.minTrendSample));
  const files = Array.isArray(dataset) ? [{ name: "input", rows: dataset, ...detect(dataset.length ? Object.keys(dataset[0]) : []) }]
    : (dataset && Array.isArray(dataset.files) ? dataset.files : []);
  const historyRecs = dataset && !Array.isArray(dataset) && Array.isArray(dataset.history) ? dataset.history : [];
  const skipped = [], findings = [], tables = {};
  const cx = { warnings: [] };

  // ---- normalise ----
  const totalRows = files.reduce((s, f) => s + ((f.rows || []).length), 0);
  let done = 0;
  const outcomeMap = new Map(), training = [], roster = new Map(), history = [];
  const capsByCampaign = new Map();
  let trainingCaps = null, rosterCaps = null;
  const usedFiles = [];
  for (const f of files) {
    const role = f.role || (KINDS[f.kind] || {}).role;
    const missing = f.mode ? (REQUIRED[f.mode] || []).filter((k) => !(f.mapping || {})[k]) : [];
    if (!role) { skipped.push({ check: "file " + f.name, reason: "format not recognised; choose a format and map the columns" }); done += (f.rows || []).length; continue; }
    if (missing.length) { skipped.push({ check: "file " + f.name, reason: "required column(s) not mapped: " + missing.map((k) => KEY_LABELS[k] || k).join(", ") }); done += (f.rows || []).length; continue; }
    const base = done;
    const progress = (i) => { if (i % 1000 === 0) ctx?.progress?.(base + i, totalRows, "reading " + f.name); };
    usedFiles.push({ name: f.name, kind: f.kind, label: (KINDS[f.kind] || {}).label || f.kind, rows: (f.rows || []).length });
    if (role === "outcome") {
      const { caps, touched } = normalizeOutcomeFile({ ...f, mode: f.mode || KINDS[f.kind].mode }, outcomeMap, cx, progress);
      for (const name of touched) {
        const cur = capsByCampaign.get(name) || { report: false, open: false, clickTime: false, reportTime: false, sentTime: false, sources: new Set() };
        cur.sources.add(f.name);
        for (const k of ["report", "open", "clickTime", "reportTime", "sentTime"]) cur[k] = cur[k] || caps[k];
        capsByCampaign.set(name, cur);
      }
    } else if (role === "training") trainingCaps = mergeCaps(trainingCaps, normalizeTraining(f, training, cx));
    else if (role === "roster") rosterCaps = mergeCaps(rosterCaps, normalizeRoster(f, roster, cx));
    else if (role === "history") history.push(...(f.rows || []));
    done += (f.rows || []).length;
  }
  const outcomes = [...outcomeMap.values()].map(finishOutcome).sort((a, b) => cmp(a.campaign, b.campaign) || cmp(a.email, b.email));
  training.sort((a, b) => cmp(a.email, b.email) || cmp(a.course, b.course) || (a.assignedAt || 0) - (b.assignedAt || 0));
  const histAll = historyEntries(historyRecs.concat(history));

  // ---- clock ----
  let nowT = parseTime(o.now);
  if (nowT == null) {
    let mx = null;
    for (const x of outcomes) for (const k of ["sentAt", "openedAt", "clickedAt", "submittedAt", "reportedAt"]) if (x[k] != null && (mx == null || x[k] > mx)) mx = x[k];
    for (const t of training) for (const k of ["assignedAt", "completedAt"]) if (t[k] != null && (mx == null || t[k] > mx)) mx = t[k];
    nowT = mx;
  }

  // ---- campaigns ----
  const byCampaign = new Map();
  for (const x of outcomes) { if (!byCampaign.has(x.campaign)) byCampaign.set(x.campaign, []); byCampaign.get(x.campaign).push(x); }
  const campaigns = [...byCampaign.entries()].map(([name, list]) => {
    const caps = capsByCampaign.get(name) || {};
    const st = stats(list);
    const launch = list.reduce((m, x) => minT(m, minT(x.sentAt, minT(x.openedAt, minT(x.clickedAt, x.reportedAt)))), null);
    const ttc = list.filter((x) => x.clicked && x.clickedAt != null && x.sentAt != null && x.clickedAt >= x.sentAt).map((x) => (x.clickedAt - x.sentAt) / 60000);
    const ttr = list.filter((x) => x.reported && x.reportedAt != null && x.sentAt != null && x.reportedAt >= x.sentAt).map((x) => (x.reportedAt - x.sentAt) / 60000);
    const firstClick = list.reduce((m, x) => (x.clicked ? minT(m, x.clickedAt) : m), null);
    const firstReport = list.reduce((m, x) => (x.reported ? minT(m, x.reportedAt) : m), null);
    return {
      campaign: name, date: day(launch), launchAt: launch, sources: [...(caps.sources || [])].sort(), ...st,
      hasReport: !!caps.report, hasOpen: !!caps.open,
      medianMinutesToClick: round(median(ttc)), medianMinutesToReport: round(median(ttr)), clickTimeSample: ttc.length, reportTimeSample: ttr.length,
      minutesToFirstClick: launch != null && firstClick != null ? round((firstClick - launch) / 60000) : null,
      minutesToFirstReport: launch != null && firstReport != null ? round((firstReport - launch) / 60000) : null,
    };
  }).sort((a, b) => (a.launchAt == null) - (b.launchAt == null) || (a.launchAt || 0) - (b.launchAt || 0) || cmp(a.campaign, b.campaign));
  for (const c of campaigns) {
    if (!c.hasReport) skipped.push({ check: "report rate: " + c.campaign, reason: "no reported column or Email Reported events in its file(s)" });
    if (!c.clickTimeSample && c.clicked.num) skipped.push({ check: "time to click: " + c.campaign, reason: "no click and delivery timestamps (GoPhish results CSV has final status only; add the raw events export)" });
  }
  if (!outcomes.length) skipped.push({ check: "campaign metrics", reason: "no phishing simulation results file was loaded" });
  tables.campaigns = campaigns.map(({ launchAt, ...rest }) => rest);

  const overall = stats(outcomes);
  const reportCampaigns = new Set(campaigns.filter((c) => c.hasReport).map((c) => c.campaign));
  const overallReport = stats(outcomes.filter((x) => reportCampaigns.has(x.campaign)));
  overall.reported = overallReport.reported;
  overall.reportBeforeClick = overallReport.reportBeforeClick;
  const ttcAll = outcomes.filter((x) => x.clicked && x.clickedAt != null && x.sentAt != null && x.clickedAt >= x.sentAt).map((x) => (x.clickedAt - x.sentAt) / 60000);
  const ttrAll = outcomes.filter((x) => x.reported && x.reportedAt != null && x.sentAt != null && x.reportedAt >= x.sentAt).map((x) => (x.reportedAt - x.sentAt) / 60000);
  overall.medianMinutesToClick = round(median(ttcAll)); overall.clickTimeSample = ttcAll.length;
  overall.medianMinutesToReport = round(median(ttrAll)); overall.reportTimeSample = ttrAll.length;
  overall.medianMinutesToFirstClick = round(median(campaigns.map((c) => c.minutesToFirstClick)));
  overall.medianMinutesToFirstReport = round(median(campaigns.map((c) => c.minutesToFirstReport)));
  overall.campaigns = campaigns.length;
  overall.people = new Set(outcomes.map((x) => x.email)).size;
  tables.overall = overall;

  // ---- people ----
  const person = (email) => roster.get(email) || null;
  const titleOf = (email) => { const p = person(email); if (p && p.title) return p.title; const t = outcomes.find((x) => x.email === email && x.title); return t ? t.title : ""; };
  const unmatched = [...new Set(outcomes.map((x) => x.email))].filter((e) => !roster.has(e));
  if (roster.size && unmatched.length) cx.warnings.push(unmatched.length + " recipient(s) are not in the HR roster; they appear as \"(not in roster)\" in breakdowns.");

  // ---- breakdowns ----
  const dims = [];
  if (!roster.size) skipped.push({ check: "breakdowns by department, manager and tenure", reason: "no HR roster loaded" });
  else {
    if (rosterCaps.department) dims.push(["department", (e) => (person(e) || {}).department]);
    else skipped.push({ check: "breakdown by department", reason: "roster has no department column" });
    if (rosterCaps.manager) dims.push(["manager", (e) => (person(e) || {}).manager]);
    else skipped.push({ check: "breakdown by manager", reason: "roster has no manager column" });
    if (rosterCaps.hireDate) dims.push(["tenure", (e) => { const p = person(e); return p ? tenureBand(p.hireAt, nowT) : ""; }]);
    else skipped.push({ check: "breakdown by tenure", reason: "roster has no hire date column" });
  }
  if ((roster.size && rosterCaps.title) || outcomes.some((x) => x.title)) dims.push(["title", (e) => titleOf(e)]);
  else skipped.push({ check: "breakdown by role / title", reason: "no title column in the roster or results" });
  tables.breakdowns = {};
  for (const [dim, fn] of dims) {
    const groups = new Map();
    for (const x of outcomes) {
      const g = str(fn(x.email)) || (roster.size && !roster.has(x.email) ? "(not in roster)" : "(blank)");
      if (!groups.has(g)) groups.set(g, []);
      groups.get(g).push(x);
    }
    tables.breakdowns[dim] = [...groups.entries()].map(([group, list]) => {
      const people = new Set(list.map((x) => x.email)).size;
      if (people < minGroup) return { group, people: null, suppressed: true, delivered: null, clicked: null, submitted: null, reported: null };
      const s = stats(list);
      const rl = list.filter((x) => reportCampaigns.has(x.campaign));
      return { group, people, suppressed: false, delivered: s.delivered, clicked: s.clicked, submitted: s.submitted, reported: stats(rl).reported };
    }).sort((a, b) => (a.suppressed - b.suppressed) || cmp(a.group, b.group));
  }
  tables.suppressionNote = "Groups with fewer than " + minGroup + " people are suppressed so individuals cannot be singled out.";

  // ---- per person history (current import + saved history) ----
  const perPerson = new Map(); // email -> Map(campaignKey -> {campaign,date,clicked,submitted,reported,source})
  const put = (email, e, source) => {
    if (!perPerson.has(email)) perPerson.set(email, new Map());
    const k = e.campaign.toLowerCase();
    const m = perPerson.get(email);
    if (source === "import" || !m.has(k)) m.set(k, { campaign: e.campaign, date: e.date || "", clicked: !!e.clicked, submitted: !!e.submitted, reported: !!e.reported, source });
  };
  for (const h of histAll) put(h.email, h, "history");
  const campDate = new Map(campaigns.map((c) => [c.campaign, c.date]));
  for (const x of outcomes) if (x.sent) put(x.email, { campaign: x.campaign, date: campDate.get(x.campaign) || "", clicked: x.clicked, submitted: x.submitted, reported: x.reported }, "import");
  tables.personCampaigns = [];
  for (const [email, m] of [...perPerson.entries()].sort((a, b) => cmp(a[0], b[0]))) {
    for (const e of [...m.values()].sort((a, b) => cmp(a.date, b.date) || cmp(a.campaign, b.campaign))) {
      if (e.source === "import" && (e.clicked || e.submitted)) tables.personCampaigns.push({ email, campaign: e.campaign, date: e.date, clicked: e.clicked, submitted: e.submitted, reported: e.reported });
    }
  }

  // ---- high-risk roles ----
  const kw = keywords(o.highRiskKeywords);
  const riskOf = (email) => {
    const p = person(email);
    const reasons = [];
    if (p && p.privileged) reasons.push("privileged flag");
    if (p && p.finance) reasons.push("finance flag");
    if (p && p.exec) reasons.push("executive flag");
    const t = titleOf(email).toLowerCase();
    const hit = t ? kw.find((k) => new RegExp("(^|[^a-z])" + k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "($|[^a-z])").test(t)) : null;
    if (hit) reasons.push('title matches "' + hit + '"');
    return { flagged: reasons.some((r) => /flag/.test(r)), reasons };
  };

  // ---- repeat clickers ----
  const repeat = [];
  for (const [email, m] of perPerson) {
    const list = [...m.values()];
    const clicked = list.filter((e) => e.clicked), submitted = list.filter((e) => e.submitted);
    if (clicked.length < repeatMin && submitted.length < repeatMin) continue;
    const p = person(email) || {};
    const risk = riskOf(email);
    repeat.push({
      email, department: p.department || "", title: titleOf(email), campaignsSeen: list.length, campaignsClicked: clicked.length, campaignsSubmitted: submitted.length,
      campaignsReported: list.filter((e) => e.reported).length, fromHistory: list.filter((e) => e.source === "history").length,
      lastClick: clicked.map((e) => e.date).filter(Boolean).sort().slice(-1)[0] || "", highRisk: risk.reasons.length ? risk.reasons.join("; ") : "",
      clickedCampaigns: clicked.map((e) => e.campaign).sort().join("; "), status: "needs follow-up training",
    });
  }
  repeat.sort((a, b) => b.campaignsSubmitted - a.campaignsSubmitted || b.campaignsClicked - a.campaignsClicked || cmp(a.email, b.email));
  tables.repeatClickers = repeat;
  const ident = (list) => list.slice(0, 100).map((r) => ({ type: "IDENTITY", name: r.email, data: { department: r.department || undefined, status: "needs follow-up training" } }));
  const repSub = repeat.filter((r) => r.campaignsSubmitted >= repeatMin);
  const repClk = repeat.filter((r) => r.campaignsSubmitted < repeatMin);
  if (outcomes.length || histAll.length) {
    if (repSub.length) findings.push(finding({
      id: "repeat-submit", title: "People who entered credentials in " + repeatMin + " or more simulations need follow-up training", severity: "high", confidence: "confirmed", category: "Follow-up training",
      description: repSub.length + " " + (repSub.length === 1 ? "person" : "people") + " submitted data on a simulated phishing page in at least " + repeatMin + " campaigns (" + perPerson.size + " people with recorded outcomes, imported plus saved history). Credential entry is the outcome a real attack needs.",
      recommendation: "Assign targeted follow-up training and a short one-to-one walkthrough of the lures they saw; consider phishing-resistant MFA (FIDO2 / passkeys) for these accounts so a captured password is not enough.",
      controls: [C.cis142, C.at23, C.iso, C.pci12631, C.t1566002], evidence: repSub, evidenceCount: repSub.length, assets: ident(repSub), tags: ["awareness", "repeat"],
    }));
    if (repClk.length) findings.push(finding({
      id: "repeat-click", title: "People who clicked in " + repeatMin + " or more simulations need follow-up training", severity: "medium", confidence: "confirmed", category: "Follow-up training",
      description: repClk.length + " " + (repClk.length === 1 ? "person" : "people") + " clicked a simulated phishing link in at least " + repeatMin + " campaigns without repeating a credential submission " + repeatMin + " times.",
      recommendation: "Assign follow-up training focused on link inspection and on reporting suspicious mail; re-check in the next campaign.",
      controls: [C.cis142, C.at23, C.iso, C.pci12631, C.t1566002], evidence: repClk, evidenceCount: repClk.length, assets: ident(repClk), tags: ["awareness", "repeat"],
    }));
  }

  // ---- high-risk roles that clicked / submitted ----
  if (!roster.size && !outcomes.some((x) => x.title)) skipped.push({ check: "high-risk roles", reason: "no HR roster or title column to identify finance, executive or admin roles" });
  else {
    const hr = new Map();
    for (const x of outcomes) {
      if (!x.clicked) continue;
      const risk = riskOf(x.email);
      if (!risk.reasons.length) continue;
      const cur = hr.get(x.email) || { email: x.email, department: (person(x.email) || {}).department || "", title: titleOf(x.email), reasons: risk.reasons.join("; "), confirmedFlag: risk.flagged, clicked: 0, submitted: 0, campaigns: [] };
      cur.clicked++; if (x.submitted) cur.submitted++;
      cur.campaigns.push(x.campaign);
      hr.set(x.email, cur);
    }
    const rows = [...hr.values()].map((r) => ({ ...r, campaigns: r.campaigns.sort().join("; ") })).sort((a, b) => b.submitted - a.submitted || b.clicked - a.clicked || cmp(a.email, b.email));
    tables.highRisk = rows;
    const sub = rows.filter((r) => r.submitted), clk = rows.filter((r) => !r.submitted);
    const conf = (list) => (list.every((r) => r.confirmedFlag) ? "confirmed" : "likely");
    if (sub.length) findings.push(finding({
      id: "highrisk-submit", title: "High-risk roles entered credentials in a simulation", severity: "high", confidence: conf(sub), category: "High-risk roles",
      description: sub.length + " finance, executive, privileged or admin " + (sub.length === 1 ? "person" : "people") + " submitted data on a simulated phishing page. Role is from roster flags or title keywords (see each row).",
      recommendation: "Prioritise role-specific training (payment fraud, executive impersonation, admin credential theft) and enforce phishing-resistant MFA and separate admin accounts for these people.",
      controls: [C.cis149, C.at3, C.iso, C.pci12631, C.t1566002], evidence: sub, evidenceCount: sub.length, assets: ident(sub), tags: ["awareness", "high-risk"],
    }));
    if (clk.length) findings.push(finding({
      id: "highrisk-click", title: "High-risk roles clicked a simulated phishing link", severity: "medium", confidence: conf(clk), category: "High-risk roles",
      description: clk.length + " finance, executive, privileged or admin " + (clk.length === 1 ? "person" : "people") + " clicked without submitting data.",
      recommendation: "Include these people in role-specific training and the next targeted campaign.",
      controls: [C.cis149, C.at3, C.iso, C.t1566002], evidence: clk, evidenceCount: clk.length, assets: ident(clk), tags: ["awareness", "high-risk"],
    }));
  }

  // ---- credential submissions per campaign ----
  const subCamp = campaigns.filter((c) => c.submitted.num > 0).map((c) => ({ campaign: c.campaign, date: c.date, delivered: c.delivered, submitted: c.submitted.num, submitRate: fmtRate(c.submitted), clicked: fmtRate(c.clicked) }));
  if (subCamp.length) {
    const tot = subCamp.reduce((s, c) => s + c.submitted, 0);
    findings.push(finding({
      id: "submissions", title: "Credentials entered on simulated phishing pages", severity: "medium", confidence: "confirmed", category: "Campaign results",
      description: tot + " submission(s) across " + subCamp.length + " campaign(s); overall submit rate " + fmtRate(overall.submitted) + " of delivered emails.",
      recommendation: "Brief everyone on the lure themes that worked, confirm the training landing page was shown, and check that real-world equivalents would be blocked by MFA and conditional access.",
      controls: [C.cis142, C.at21, C.sp80050, C.pci12631, C.t1566], evidence: subCamp, tags: ["awareness"],
    }));
  }

  // ---- reporting ----
  const target = o.reportTargetRate === "" || o.reportTargetRate == null ? null : Number(o.reportTargetRate);
  if (target != null && Number.isFinite(target) && target > 0 && overall.reported.den) {
    if (overall.reported.pct < target) findings.push(finding({
      id: "report-target", title: "Report rate is below the target you set", severity: "low", confidence: "confirmed", category: "Reporting",
      description: "Overall report rate " + fmtRate(overall.reported) + " against your target of " + target + "% (campaigns with report data only).",
      recommendation: "Make the report button prominent, acknowledge every report quickly, and teach that reporting is the expected action even after a click.",
      controls: [C.cis146, C.at2, C.cc22], evidence: campaigns.filter((c) => c.hasReport).map((c) => ({ campaign: c.campaign, date: c.date, reported: fmtRate(c.reported), reportBeforeClick: fmtRate(c.reportBeforeClick) })), tags: ["awareness"],
    }));
  }

  // ---- baseline ----
  const base = o.baselineClickRate === "" || o.baselineClickRate == null ? null : Number(o.baselineClickRate);
  if (base != null && Number.isFinite(base) && base >= 0 && overall.clicked.den) {
    const diff = round(overall.clicked.pct - base, 1);
    findings.push(finding({
      id: "baseline", title: diff > 0 ? "Click rate is above the baseline you entered" : "Click rate is at or below the baseline you entered", severity: "info", confidence: "confirmed", category: "Trend",
      description: "Overall click rate " + fmtRate(overall.clicked) + " against your baseline of " + base + "% (difference " + diff + " points). The baseline is user-entered, not an industry figure.",
      recommendation: diff > 0 ? "Review which campaigns drive the difference in the campaign table." : "Keep the cadence; vary lure difficulty so the rate stays meaningful.",
      controls: [C.sp80050, C.iso], evidence: [{ baselinePct: base, clickRate: fmtRate(overall.clicked), campaigns: campaigns.length }], tags: ["awareness"],
    }));
  }

  // ---- trend ----
  const eligible = campaigns.filter((c) => c.launchAt != null && c.delivered >= minTrend);
  tables.trend = { minSample: minTrend, eligible: eligible.map((c) => c.campaign), flags: [] };
  if (campaigns.length < 2) skipped.push({ check: "trend", reason: "needs at least two campaigns" });
  else if (eligible.length < 2) skipped.push({ check: "trend", reason: "fewer than two dated campaigns with at least " + minTrend + " delivered emails" });
  else {
    const a = eligible[0], b = eligible[eligible.length - 1];
    const flag = (metric, x1, x2, higherIsWorse) => {
      const z = twoPropZ(x1.num, x1.den, x2.num, x2.den);
      if (z == null) return null;
      const sig = Math.abs(z) >= 1.96;
      const up = x2.num / x2.den > x1.num / x1.den;
      const dir = !sig ? "no clear change" : (up === higherIsWorse ? "worsening" : "improving");
      return { metric, from: a.campaign, fromDate: a.date, to: b.campaign, toDate: b.date, fromRate: fmtRate(x1), toRate: fmtRate(x2), z: round(z, 2), direction: dir };
    };
    const fl = [flag("click rate", a.clicked, b.clicked, true)];
    if (a.hasReport && b.hasReport) fl.push(flag("report rate", a.reported, b.reported, false));
    tables.trend.flags = fl.filter(Boolean);
    const worse = tables.trend.flags.filter((f) => f.direction === "worsening"), better = tables.trend.flags.filter((f) => f.direction === "improving");
    if (worse.length) findings.push(finding({
      id: "trend-worse", title: "Phishing results are worsening between the first and latest campaign", severity: "low", confidence: "likely", category: "Trend",
      description: worse.map((f) => f.metric + " " + f.fromRate + " -> " + f.toRate).join("; ") + ". Two-proportion test, |z| >= 1.96; lure difficulty differs between campaigns, so treat this as a signal, not a verdict.",
      recommendation: "Compare the lure themes and audiences of the two campaigns before drawing conclusions; refresh training content on the theme that worked.",
      controls: [C.sp80050, C.iso, C.cis142], evidence: worse, tags: ["awareness", "trend"],
    }));
    if (better.length) findings.push(finding({
      id: "trend-better", title: "Phishing results are improving between the first and latest campaign", severity: "info", confidence: "likely", category: "Trend",
      description: better.map((f) => f.metric + " " + f.fromRate + " -> " + f.toRate).join("; ") + ". Two-proportion test, |z| >= 1.96.",
      recommendation: "Keep the cadence and raise lure difficulty gradually.",
      controls: [C.sp80050, C.iso], evidence: better, tags: ["awareness", "trend"],
    }));
  }

  // ---- training ----
  const rc = String(o.remedialCourse || "").trim().toLowerCase();
  if (!training.length) {
    skipped.push({ check: "overdue training", reason: "no LMS training file loaded" });
    if (outcomes.some((x) => x.clicked)) skipped.push({ check: "remedial training after a click", reason: "no LMS training file loaded" });
  } else {
    if (nowT == null) skipped.push({ check: "overdue training", reason: "no reference date: set Today's date" });
    else if (!trainingCaps.due) skipped.push({ check: "overdue training", reason: "training file has no due date column" });
    else {
      const overdue = training.filter((t) => !t.completed && t.dueAt != null && t.dueAt < nowT).map((t) => ({
        email: t.email, department: (person(t.email) || {}).department || "", course: t.course, assigned: day(t.assignedAt), due: day(t.dueAt), daysOverdue: Math.floor((nowT - t.dueAt) / DAY),
      })).sort((a, b) => b.daysOverdue - a.daysOverdue || cmp(a.email, b.email));
      tables.overdue = overdue;
      if (overdue.length) findings.push(finding({
        id: "overdue", title: "Awareness training assignments are past due", severity: "medium", confidence: "confirmed", category: "Training",
        description: overdue.length + " assignment(s) for " + new Set(overdue.map((r) => r.email)).size + " people are incomplete past their due date (as of " + day(nowT) + ").",
        recommendation: "Send reminders through the manager chain and escalate assignments more than 30 days late; PCI DSS expects training on hire and at least every 12 months.",
        controls: [C.pci1263, C.iso, C.cis141, C.at2, C.cc14], evidence: overdue, assets: ident(overdue.map((r) => ({ email: r.email, department: r.department })).filter((r, i, arr) => arr.findIndex((y) => y.email === r.email) === i)), tags: ["awareness", "training"],
      }));
    }
    // remedial
    if (outcomes.some((x) => x.clicked)) {
      if (!trainingCaps.assigned && !trainingCaps.completed) skipped.push({ check: "remedial training after a click", reason: "training file has no assigned or completed date column" });
      else if (nowT == null) skipped.push({ check: "remedial training after a click", reason: "no reference date: set Today's date" });
      else {
        const byEmail = new Map();
        for (const t of training) { if (rc && !t.course.toLowerCase().includes(rc)) continue; if (!byEmail.has(t.email)) byEmail.set(t.email, []); byEmail.get(t.email).push(t); }
        const missing = [], undated = [];
        let pending = 0;
        const startOfDay = (t) => t - (t % DAY);
        for (const x of outcomes) {
          if (!x.clicked) continue;
          const cDate = x.clickedAt != null ? x.clickedAt : (campaigns.find((c) => c.campaign === x.campaign) || {}).launchAt;
          if (cDate == null) { undated.push(x.email); continue; }
          const from = startOfDay(cDate), to = from + (remedialDays + 1) * DAY;
          if (nowT < to - DAY && nowT < cDate + remedialDays * DAY) { pending++; continue; }
          const hit = (byEmail.get(x.email) || []).some((t) => (t.assignedAt != null && t.assignedAt >= from && t.assignedAt < to) || (t.completedAt != null && t.completedAt >= from && t.completedAt < to));
          if (!hit) missing.push({ email: x.email, department: (person(x.email) || {}).department || "", campaign: x.campaign, clickDate: day(cDate), submitted: x.submitted ? "yes" : "no", windowDays: remedialDays });
        }
        missing.sort((a, b) => cmp(a.clickDate, b.clickDate) || cmp(a.email, b.email));
        tables.remedialMissing = missing;
        tables.remedialPending = pending;
        if (undated.length) skipped.push({ check: "remedial training (" + undated.length + " click(s))", reason: "no click or campaign date to measure the window from" });
        if (missing.length) findings.push(finding({
          id: "remedial", title: "Clicks without remedial training within " + remedialDays + " days", severity: "medium", confidence: "confirmed", category: "Training",
          description: missing.length + " click(s) by " + new Set(missing.map((r) => r.email)).size + " people had no training " + (rc ? 'matching "' + rc + '" ' : "") + "assigned or completed within " + remedialDays + " days. " + (pending ? pending + " more are still inside the window." : ""),
          recommendation: "Assign short remedial training (the remedial assignment CSV export lists them); automate assignment on click in the simulation platform.",
          controls: [C.sp80050, C.at21, C.cis142, C.pci12631], evidence: missing, assets: ident(missing.filter((r, i, arr) => arr.findIndex((y) => y.email === r.email) === i)), tags: ["awareness", "training"],
        }));
      }
    }
    // completion by department
    if (roster.size && rosterCaps.department) {
      const g = new Map();
      for (const t of training) {
        const d = (person(t.email) || {}).department || (roster.has(t.email) ? "(blank)" : "(not in roster)");
        if (!g.has(d)) g.set(d, { people: new Set(), assigned: 0, completed: 0, overdue: 0 });
        const e = g.get(d);
        e.people.add(t.email); e.assigned++; if (t.completed) e.completed++;
        if (!t.completed && t.dueAt != null && nowT != null && t.dueAt < nowT) e.overdue++;
      }
      tables.trainingByDept = [...g.entries()].map(([group, e]) => e.people.size < minGroup
        ? { group, suppressed: true, people: null, assigned: null, completion: null, overdue: null }
        : { group, suppressed: false, people: e.people.size, assigned: e.assigned, completion: rate(e.completed, e.assigned), overdue: e.overdue }).sort((a, b) => (a.suppressed - b.suppressed) || cmp(a.group, b.group));
    }
  }

  ctx?.progress?.(totalRows, totalRows, "done");
  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(a.category, b.category) || cmp(a.id || "", b.id || ""));
  skipped.sort((a, b) => cmp(a.check, b.check));
  const bySeverity = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  const summary = {
    rows: totalRows, files: usedFiles.length, campaigns: campaigns.length, people: overall.people, delivered: overall.delivered,
    clickRate: overall.clicked, submitRate: overall.submitted, reportRate: overall.reported, reportBeforeClick: overall.reportBeforeClick,
    medianMinutesToClick: overall.medianMinutesToClick, medianMinutesToReport: overall.medianMinutesToReport,
    needsFollowUp: repeat.length, rosterPeople: roster.size, trainingRows: training.length, historyEntries: histAll.length,
    findings: findings.length, bySeverity,
  };
  return {
    summary, findings, tables, skipped,
    meta: { tool: TOOL_ID, version: VERSION, rows: totalRows, now: nowT == null ? "" : iso(nowT), files: usedFiles, warnings: cx.warnings.sort(), options: { minGroupSize: minGroup, repeatClickMin: repeatMin, remedialDays, minTrendSample: minTrend } },
  };
}

function mergeCaps(a, b) {
  if (!a) return b;
  const out = { ...a };
  for (const k of Object.keys(b)) out[k] = a[k] || b[k];
  return out;
}

// ---------------------------------------------------------------------------
// History (register) helpers
// ---------------------------------------------------------------------------
/**
 * Merge this run's per-person outcomes (tables.personCampaigns) into register
 * records keyed by normalised email. Only people with a click or submission are
 * stored (that is all the repeat-clicker check needs). No message bodies.
 * @returns {object[]} records to upsert (sorted by email)
 */
export function mergeHistory(existing, personCampaigns) {
  const byEmail = new Map();
  for (const r of existing || []) { const e = normEmail(r && r.email); if (e) byEmail.set(e, { ...r, id: e, email: e, campaigns: Array.isArray(r.campaigns) ? r.campaigns.slice() : [] }); }
  const touched = new Set();
  for (const pc of personCampaigns || []) {
    const e = normEmail(pc.email);
    if (!e || !str(pc.campaign)) continue;
    const rec = byEmail.get(e) || { id: e, email: e, campaigns: [] };
    const k = str(pc.campaign).toLowerCase();
    const entry = { campaign: str(pc.campaign), date: str(pc.date), clicked: !!pc.clicked, submitted: !!pc.submitted, reported: !!pc.reported };
    const i = rec.campaigns.findIndex((c) => str(c.campaign).toLowerCase() === k);
    if (i >= 0) rec.campaigns[i] = entry; else rec.campaigns.push(entry);
    rec.campaigns.sort((a, b) => cmp(a.date, b.date) || cmp(a.campaign, b.campaign));
    rec.clicks = rec.campaigns.filter((c) => c.clicked).length;
    rec.submissions = rec.campaigns.filter((c) => c.submitted).length;
    byEmail.set(e, rec);
    touched.add(e);
  }
  return [...touched].sort().map((e) => byEmail.get(e));
}

/** Register schema for openRegister(TOOL_ID, "IDENTITY", { schema }). */
export const REGISTER_SCHEMA = {
  key: "id",
  name: (r) => r.email,
  severity: (r) => ((r.submissions || 0) >= 2 ? "high" : (r.clicks || 0) >= 2 ? "medium" : null),
  summary: (r) => ({ email: r.email, campaigns: (r.campaigns || []).length, clicks: r.clicks || 0, submissions: r.submissions || 0 }),
  columns: [{ key: "email", label: "Email" }, { key: "clicks", label: "Campaigns clicked" }, { key: "submissions", label: "Campaigns submitted" }, { key: "updatedAt", label: "Updated" }],
};

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
/** CSV cell: quoted, with spreadsheet formula prefixes neutralised. */
export function csvCell(v) {
  let s = v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}
const csv = (head, rows) => [head.map(csvCell).join(",")].concat(rows.map((r) => r.map(csvCell).join(","))).join("\n") + "\n";

const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "evidenceCount"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  return csv(FINDING_COLS, (findings || []).map((f) => [f.severity, f.confidence, f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length]));
}

/** People who need follow-up training. */
export function repeatClickersCsv(result) {
  const rows = (result && result.tables && result.tables.repeatClickers) || [];
  return csv(["email", "department", "title", "campaigns_seen", "campaigns_clicked", "campaigns_submitted", "campaigns_reported", "last_click", "high_risk_role", "clicked_campaigns", "status"],
    rows.map((r) => [r.email, r.department, r.title, r.campaignsSeen, r.campaignsClicked, r.campaignsSubmitted, r.campaignsReported, r.lastClick, r.highRisk, r.clickedCampaigns, r.status]));
}

/** Department scorecard: phishing outcomes + training completion, suppressed groups blank. */
export function departmentScorecardCsv(result) {
  const t = (result && result.tables) || {};
  const ph = new Map(((t.breakdowns || {}).department || []).map((r) => [r.group, r]));
  const tr = new Map((t.trainingByDept || []).map((r) => [r.group, r]));
  const groups = [...new Set([...ph.keys(), ...tr.keys()])].sort();
  const p = (r) => (r && r.den ? r.pct : "");
  return csv(["department", "people", "delivered", "click_rate_pct", "clicked", "submit_rate_pct", "report_rate_pct", "reported_of", "training_assigned", "training_completion_pct", "training_overdue", "note"],
    groups.map((g) => {
      const a = ph.get(g), b = tr.get(g);
      const sup = (a && a.suppressed) || (b && b.suppressed);
      if (sup) return [g, "", "", "", "", "", "", "", "", "", "", "suppressed: fewer than " + ((result.meta && result.meta.options && result.meta.options.minGroupSize) || DEFAULTS.minGroupSize) + " people"];
      return [g, a ? a.people : (b ? b.people : ""), a ? a.delivered : "", a ? p(a.clicked) : "", a && a.clicked ? a.clicked.num : "", a ? p(a.submitted) : "", a ? p(a.reported) : "", a && a.reported ? a.reported.den : "",
        b ? b.assigned : "", b ? p(b.completion) : "", b ? b.overdue : "", ""];
    }));
}

/** Remedial training assignment list (email, course) for people needing follow-up and clicks without remedial training. */
export function remedialAssignmentsCsv(result, course) {
  const t = (result && result.tables) || {};
  const reason = new Map();
  for (const r of t.repeatClickers || []) reason.set(r.email, "needs follow-up training (clicked in " + r.campaignsClicked + " campaigns)");
  for (const r of t.remedialMissing || []) if (!reason.has(r.email)) reason.set(r.email, "no remedial training after click in " + r.campaign);
  const c = str(course) || "Remedial phishing awareness";
  return csv(["email", "course", "reason"], [...reason.entries()].sort((a, b) => cmp(a[0], b[0])).map(([e, why]) => [e, c, why]));
}

const pctTxt = (r) => fmtRate(r);
const minTxt = (m) => (m == null ? "n/a" : m < 120 ? m + " min" : round(m / 60, 1) + " h");

/** Plain-text summary. */
export function summaryText(result) {
  const s = result.summary, t = result.tables || {};
  const lines = [
    "Awareness & Phishing-Test Analytics", "Generated by Darknode " + TOOL_ID + " " + VERSION + (result.meta.now ? ", reference date " + result.meta.now.slice(0, 10) : ""), "",
    "Campaigns: " + s.campaigns + ", people: " + s.people + ", delivered emails: " + s.delivered,
    "Click rate: " + pctTxt(s.clickRate), "Credential submit rate: " + pctTxt(s.submitRate), "Report rate: " + pctTxt(s.reportRate), "Reported before clicking: " + pctTxt(s.reportBeforeClick),
    "Median time to click: " + minTxt(s.medianMinutesToClick) + ", median time to report: " + minTxt(s.medianMinutesToReport),
    "People needing follow-up training: " + s.needsFollowUp, "",
    "Campaigns:",
  ];
  for (const c of t.campaigns || []) lines.push("- " + (c.date || "undated") + " " + c.campaign + ": delivered " + c.delivered + ", clicked " + pctTxt(c.clicked) + ", submitted " + pctTxt(c.submitted) + ", reported " + (c.hasReport ? pctTxt(c.reported) : "n/a"));
  if ((t.trend || {}).flags && t.trend.flags.length) { lines.push("", "Trend (first vs latest campaign with at least " + t.trend.minSample + " delivered):"); for (const f of t.trend.flags) lines.push("- " + f.metric + ": " + f.fromRate + " -> " + f.toRate + " (" + f.direction + ", z=" + f.z + ")"); }
  lines.push("", "Findings: " + result.findings.length);
  for (const f of result.findings) lines.push("- [" + f.severity + "] " + f.title + " (" + f.evidenceCount + ") - " + f.recommendation);
  if (result.skipped.length) { lines.push("", "Skipped checks:"); for (const k of result.skipped) lines.push("- " + k.check + ": " + k.reason); }
  if (t.suppressionNote) lines.push("", t.suppressionNote);
  lines.push("", "People analytics are sensitive. Use these results to target training, not to discipline individuals.");
  return lines.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example (seeded, format-faithful; never saved to the register)
// ---------------------------------------------------------------------------
const FIRST = ["Avery", "Blake", "Casey", "Devon", "Emery", "Finley", "Gray", "Harper", "Indy", "Jules", "Kai", "Logan", "Morgan", "Noel", "Oakley", "Parker", "Quinn", "Reese", "Sage", "Taylor", "Umi", "Vale", "Wren", "Xen", "Yael", "Zion", "Arden", "Briar", "Cove", "Dale"];
const LAST = ["Ashdown", "Brightwater", "Coldfield", "Dunmore", "Elmstead", "Fairhollow", "Greystone", "Hartwell", "Ironwood", "Juniper"];
const DEPTS = [["Finance", 9], ["Engineering", 14], ["Sales", 11], ["Marketing", 7], ["IT", 7], ["People", 6], ["Operations", 3], ["Legal", 3]];
const TITLES = { Finance: ["Accounts Payable Specialist", "Financial Analyst", "Controller", "Payroll Specialist"], Engineering: ["Software Engineer", "Senior Software Engineer", "Engineering Manager"], Sales: ["Account Executive", "Sales Development Rep", "Sales Manager"], Marketing: ["Marketing Specialist", "Content Lead"], IT: ["IT Admin", "Helpdesk Technician", "Systems Administrator"], People: ["HR Generalist", "Recruiter"], Operations: ["Operations Analyst", "COO"], Legal: ["Counsel", "Paralegal"] };

function rng(seed) { let s = seed >>> 0; return () => { s = (s + 0x6D2B79F5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const pad = (n) => String(n).padStart(2, "0");
const isoAt = (t) => new Date(t).toISOString().replace(/\.\d{3}Z$/, ".000000000Z");
const csvLine = (a) => a.map((v) => { const s = String(v == null ? "" : v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }).join(",");

/** Seeded SYNTHETIC dataset: 4 GoPhish campaigns, 2 KnowBe4 exports, an LMS file and a roster of 60 fictional people at test.darknode.ai. */
export function exampleDataset(seed = 7) {
  const r = rng(seed);
  const people = [];
  let i = 0;
  for (const [dept, n] of DEPTS) for (let k = 0; k < n; k++, i++) {
    const first = FIRST[i % FIRST.length], last = LAST[Math.floor(i / FIRST.length) * 3 % LAST.length + (i % 3)];
    const titles = TITLES[dept];
    const title = titles[k % titles.length];
    people.push({
      email: (first + "." + last).toLowerCase() + "@test.darknode.ai", first, last, dept, title,
      hire: Date.UTC(2014 + Math.floor(r() * 12), Math.floor(r() * 12), 1 + Math.floor(r() * 27)),
      p: 0.06 + r() * 0.3, rep: 0.1 + r() * 0.4,
    });
  }
  // A few people with a high click propensity (they become "needs follow-up training").
  for (const j of [2, 13, 25, 40, 47]) people[j].p = 0.85;
  for (let j = 0; j < people.length; j++) people[j].manager = people[people.findIndex((p) => p.dept === people[j].dept)].email;
  people[0].manager = "";
  const files = [];
  // HR roster
  files.push({ name: "hr-roster.csv", text: [csvLine(["email", "name", "department", "title", "manager", "hire date", "privileged", "finance", "exec"])]
    .concat(people.map((p) => csvLine([p.email, p.first + " " + p.last, p.dept, p.title, p.manager, new Date(p.hire).toISOString().slice(0, 10),
      /IT Admin|Systems Administrator/.test(p.title) ? "yes" : "no", p.dept === "Finance" ? "yes" : "no", /COO|Controller/.test(p.title) ? "yes" : "no"]))).join("\n") + "\n" });
  const clicks = [];
  let pendingClick = null;
  const clickAt0 = (sent) => { if (pendingClick == null) pendingClick = sent + Math.floor(3 + r() * 240) * 60000; return pendingClick; };
  const simulate = (launch, factor, repBoost) => people.map((p, idx) => {
    pendingClick = null;
    const sent = launch + idx * 20000;
    const opened = r() < 0.75;
    const clicked = r() < p.p * factor;
    const submitted = clicked && r() < 0.45;
    const reported = r() < Math.min(0.9, p.rep + repBoost) && (!clicked || r() < 0.5);
    const clickAt = clicked ? clickAt0(sent) : null;
    const reportAt = reported ? (clicked && r() < 0.5 ? clickAt + 300000 : sent + Math.floor(2 + r() * 120) * 60000) : null;
    if (clicked) clicks.push({ email: p.email, at: clickAt0(sent) });
    return { p, sent, opened: opened || clicked, clicked, submitted, reported, clickAt, reportAt, submitAt: submitted ? clickAt + 90000 : null, openAt: (opened || clicked) ? sent + 60000 : null, bounced: idx === 59 && factor > 1 };
  });
  const gpCamps = [["Q1 invoice lure", Date.UTC(2026, 2, 3, 14), 1.2, 0], ["Q2 password expiry", Date.UTC(2026, 4, 5, 14), 1.0, 0.05], ["Q3 shared document", Date.UTC(2026, 6, 7, 14), 0.75, 0.12], ["Q4 parcel delivery", Date.UTC(2026, 8, 8, 14), 0.55, 0.2]];
  gpCamps.forEach(([name, launch, factor, boost], ci) => {
    const res = simulate(launch, factor, boost);
    if (ci < 2) {
      // "Export CSV - Results"
      const lines = [csvLine(GOPHISH_RESULT_HEADERS)];
      res.forEach((x, idx) => {
        const status = x.bounced ? "Error" : x.submitted ? "Submitted Data" : x.clicked ? "Clicked Link" : x.opened ? "Email Opened" : "Email Sent";
        const mod = x.submitAt || x.clickAt || x.openAt || x.sent;
        lines.push(csvLine([idx + 1, status, x.clicked ? "203.0.113." + (10 + idx) : "", "0", "0", isoAt(x.sent), x.reported ? "true" : "false", isoAt(mod), x.p.email, x.p.first, x.p.last, x.p.title]));
      });
      files.push({ name: "gophish-" + (ci + 1) + "-" + name.toLowerCase().replace(/\s+/g, "-") + "-results.csv", text: lines.join("\n") + "\n", campaign: name });
    } else {
      // "Export CSV - Raw Events"
      const cid = 11 + ci;
      const ev = [[launch - 600000, "", "Campaign Created", ""]];
      for (const x of res) {
        ev.push([x.sent, x.p.email, "Email Sent", ""]);
        if (x.openAt) ev.push([x.openAt, x.p.email, "Email Opened", '{"payload":{"rid":["r' + cid + '"]},"browser":{"address":"203.0.113.20","user-agent":"Mozilla/5.0"}}']);
        if (x.clickAt) ev.push([x.clickAt, x.p.email, "Clicked Link", '{"payload":{"rid":["r' + cid + '"]},"browser":{"address":"203.0.113.21","user-agent":"Mozilla/5.0"}}']);
        if (x.submitAt) ev.push([x.submitAt, x.p.email, "Submitted Data", '{"payload":{"rid":["r' + cid + '"]},"browser":{"address":"203.0.113.21","user-agent":"Mozilla/5.0"}}']);
        if (x.reportAt) ev.push([x.reportAt, x.p.email, "Email Reported", '{"payload":{"rid":["r' + cid + '"]},"browser":{"address":"198.51.100.4","user-agent":"Outlook"}}']);
      }
      ev.sort((a, b) => a[0] - b[0] || cmp(a[1], b[1]));
      const lines = [csvLine(GOPHISH_EVENT_HEADERS)].concat(ev.map((e) => csvLine([cid, e[1], isoAt(e[0]), e[2], e[3]])));
      files.push({ name: "gophish-" + (ci + 1) + "-" + name.toLowerCase().replace(/\s+/g, "-") + "-events.csv", text: lines.join("\n") + "\n", campaign: name });
    }
  });
  // KnowBe4: one Reporting API JSON, one console CSV
  const kbIso = (t) => (t == null ? null : new Date(t).toISOString().replace(/\.\d{3}Z$/, ".000Z"));
  const kb1 = simulate(Date.UTC(2026, 3, 14, 15), 0.9, 0.05);
  files.push({ name: "knowbe4-pst-4101-recipients.json", text: JSON.stringify(kb1.map((x, idx) => ({
    recipient_id: 900100 + idx, pst_id: 4101, user: { id: 5000 + idx, active_directory_guid: null, first_name: x.p.first, last_name: x.p.last, email: x.p.email },
    template: { id: 77, name: "Synthetic: HR policy update" }, scheduled_at: kbIso(Date.UTC(2026, 3, 14, 15)), delivered_at: kbIso(x.sent), opened_at: kbIso(x.openAt), clicked_at: kbIso(x.clickAt),
    replied_at: null, attachment_opened_at: null, macro_enabled_at: null, data_entered_at: kbIso(x.submitAt), qr_code_scanned: null, reported_at: kbIso(x.reportAt), bounced_at: null,
    ip: x.clicked ? "203.0.113.40" : null, ip_location: null, browser: x.clicked ? "Chrome" : null, browser_version: null, os: x.clicked ? "Windows" : null,
  })), null, 2) + "\n" });
  const kb2 = simulate(Date.UTC(2026, 7, 11, 15), 0.65, 0.15);
  const kbCsv = (t) => (t == null ? "" : new Date(t).toISOString().slice(0, 19).replace("T", " "));
  files.push({ name: "knowbe4-pst-4188-export.csv", campaign: "KnowBe4 PST 4188", text: [csvLine(["First Name", "Last Name", "Email", "Delivered At", "Opened At", "Clicked At", "Replied At", "Attachment Opened At", "Macro Enabled At", "Data Entered At", "Reported At", "Bounced At"])]
    .concat(kb2.map((x) => csvLine([x.p.first, x.p.last, x.p.email, kbCsv(x.sent), kbCsv(x.openAt), kbCsv(x.clickAt), "", "", "", kbCsv(x.submitAt), kbCsv(x.reportAt), ""]))).join("\n") + "\n" });
  // LMS: annual training for everyone + remedial assignments for some clickers
  const lms = [csvLine(["user", "course", "assigned", "due", "completed"])];
  people.forEach((p, idx) => {
    const done = r() < 0.82;
    lms.push(csvLine([p.email, "Annual Security Awareness 2026", "2026-02-02", "2026-03-31", done ? "2026-03-" + pad(2 + Math.floor(r() * 27)) : ""]));
  });
  // Remedial training auto-assigned after most clicks (some never assigned, some late).
  for (const c of clicks) {
    if (r() < 0.3) continue;
    const a = c.at + Math.floor(1 + r() * 9) * DAY;
    lms.push(csvLine([c.email, "Remedial: Spotting Phishing Links", new Date(a).toISOString().slice(0, 10), new Date(a + 14 * DAY).toISOString().slice(0, 10), r() < 0.75 ? new Date(a + Math.floor(1 + r() * 10) * DAY).toISOString().slice(0, 10) : ""]));
  }
  files.push({ name: "lms-assignments.csv", text: lms.join("\n") + "\n" });
  return { label: "synthetic example (not real data): 60 fictional people at test.darknode.ai", files, now: "2026-10-01T00:00:00Z" };
}

/** Parse the example the way the UI does (with its campaign names applied). */
export function exampleParsed(seed = 7) {
  const ex = exampleDataset(seed);
  const parsed = parseInput(ex.files);
  parsed.files.forEach((f, i) => { f.campaign = ex.files[i].campaign || ""; });
  return { ...ex, parsed };
}

/** Real deterministic checks of the engine. */
export function selfTest() {
  const tests = [];
  const ex = exampleParsed();
  const kinds = ex.parsed.files.map((f) => f.kind);
  tests.push({ name: "example files detected", pass: kinds.join(",") === "roster,gophish-results,gophish-results,gophish-events,gophish-events,knowbe4-json,knowbe4-csv,lms" });
  const r = analyze({ files: ex.parsed.files }, { now: ex.now });
  tests.push({ name: "six campaigns analysed", pass: r.summary.campaigns === 6 });
  tests.push({ name: "repeat clickers flagged", pass: r.tables.repeatClickers.length > 0 && r.tables.repeatClickers.every((x) => x.status === "needs follow-up training") });
  tests.push({ name: "small groups suppressed", pass: (r.tables.breakdowns.department || []).some((g) => g.suppressed) });
  tests.push({ name: "deterministic", pass: JSON.stringify(r) === JSON.stringify(analyze({ files: ex.parsed.files }, { now: ex.now })) });
  tests.push({ name: "missing roster is skipped, not guessed", pass: analyze({ files: ex.parsed.files.filter((f) => f.kind !== "roster") }, { now: ex.now }).skipped.some((s) => /roster/.test(s.reason)) });
  tests.push({ name: "empty input yields no findings", pass: analyze([]).findings.length === 0 });
  return { pass: tests.every((t) => t.pass), tests };
}
