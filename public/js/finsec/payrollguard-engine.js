// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Payroll Integrity engine (payrollguard). Screens a payroll register against the HR
// roster, the direct-deposit (bank) change log and optional timesheets for the ACFE
// payroll schemes (ghost employees, falsified wages, commission schemes) and for
// payroll-diversion account takeover (an employee's direct deposit is changed shortly
// before payday). Pure: no DOM, no network, deterministic; safe inside a Worker.
//
// Money is held as integer cents. SSNs / national ids and full bank account numbers
// are matched on normalized values held in memory only; every output shows last 4.
// These are screens, not proof: every finding names the pattern and asks for review.

import { sniff, parseCsv, iterJson, findColumn, normHeader, flatten } from "../ingest/parse.js";
import { validateABA, validateIBAN } from "./vendor-engine.js";

export const TOOL_ID = "payrollguard";
export const VERSION = "1.0.0";

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const str = (v) => String(v == null ? "" : v).trim();
const low = (v) => str(v).toLowerCase();
const alnum = (v) => low(v).replace(/[^a-z0-9]/g, "");
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** File roles the tool understands. */
export const KINDS = ["register", "roster", "bank", "timesheet", "ignore"];

/** Column aliases per file role: logical key -> accepted headers (normalized match, order wins). */
export const COLUMNS = {
  register: {
    employeeId: ["employee_id", "employee id", "file #", "file number", "employee number", "emp id", "worker id", "associate id", "employee #"],
    name: ["name", "employee name", "employee", "worker", "full name", "legal name"],
    payDate: ["pay_date", "pay date", "check date", "payment date", "pay day", "paid date"],
    periodStart: ["period_start", "period start", "pay period start", "period start date", "period begin", "period begin date", "period beginning"],
    periodEnd: ["period_end", "period end", "pay period end", "period end date", "period ending"],
    regHours: ["regular_hours", "regular hours", "reg hours", "regular hrs"],
    otHours: ["overtime_hours", "overtime hours", "ot hours", "overtime hrs"],
    hours: ["hours", "total hours", "hours worked"],
    regEarn: ["regular earnings", "regular pay", "reg earnings", "regular amount"],
    otEarn: ["overtime earnings", "overtime pay", "ot earnings", "overtime amount"],
    gross: ["gross", "gross pay", "gross earnings", "gross amount", "total gross", "gross wages"],
    net: ["net", "net pay", "net amount", "net check", "net wages"],
    tax: ["tax", "employee taxes", "total employee taxes", "total taxes", "taxes", "total withholding"],
    fit: ["federal income tax", "fed income tax", "federal withholding", "fed withholding", "fit"],
    ss: ["social security", "social security tax", "oasdi", "ss tax", "fica ss"],
    medicare: ["medicare", "medicare tax", "fica med"],
    stateTax: ["state tax", "state income tax", "state withholding", "sit"],
    deductions: ["deductions", "employee deductions", "total deductions", "voluntary deductions"],
    bankAccount: ["bank_account", "bank account", "account number", "deposit account", "account"],
    bankLast4: ["bank account last 4", "account last 4", "last4", "last 4"],
    routing: ["routing", "routing number", "aba", "transit number", "bank routing", "routing #"],
    paymentMethod: ["payment_method", "payment method", "pay method", "deposit type"],
    paymentType: ["payment type", "run type", "check type", "pay run type", "payroll type"],
    department: ["department", "home department", "dept", "cost center", "department name"],
    checkNo: ["check/voucher #", "check number", "voucher number", "check #", "check no"],
    currency: ["currency", "currency code"],
  },
  roster: {
    employeeId: ["employee_id", "employee id", "employee #", "employee number", "worker id", "file #", "emp id"],
    name: ["name", "full name", "legal name", "employee name", "worker", "employee", "preferred name"],
    firstName: ["first name", "legal first name", "first_name"],
    lastName: ["last name", "legal last name", "last_name"],
    ssn: ["ssn_or_national_id", "ssn", "social security number", "national id", "national identifier", "tax id", "taxpayer id", "sin", "national id number"],
    dob: ["date_of_birth", "date of birth", "dob", "birth date", "birthdate"],
    address: ["address", "home address", "address line 1", "street", "address 1", "home address line 1", "street address"],
    city: ["city", "home city"],
    postal: ["postal_code", "postal code", "zip", "zip code", "postcode", "home postal code"],
    phone: ["phone", "mobile phone", "home phone", "phone number", "personal phone", "mobile", "work phone"],
    email: ["email", "work email", "personal email", "primary work email", "email - primary work", "home email", "email address"],
    department: ["department", "supervisory organization", "dept", "cost center", "division"],
    managerId: ["manager_id", "manager id", "manager employee id", "supervisor id", "reports to id", "reports to", "manager"],
    hireDate: ["hire_date", "hire date", "original hire date", "start date", "date of hire"],
    termDate: ["termination_date", "termination date", "term date", "end date", "separation date"],
    status: ["status", "employment status", "worker status", "active status", "employee status"],
    payType: ["pay_type", "pay type", "pay rate type", "compensation type", "flsa status", "pay basis", "worker type", "employee type", "employment type"],
    salary: ["salary", "annual salary", "base salary", "annual base pay", "annual base"],
    hourlyRate: ["hourly_rate", "hourly rate", "hourly pay rate", "rate"],
  },
  bank: {
    employeeId: ["employee_id", "employee id", "file #", "worker id", "employee number", "employee #", "associate id"],
    name: ["employee name", "name", "worker", "employee", "subject"],
    changedAt: ["changed_at", "changed at", "change date", "date changed", "timestamp", "completed on", "initiated on", "effective date", "modified date", "date", "date/time"],
    changedBy: ["changed_by", "changed by", "initiated by", "initiator", "modified by", "changed by user", "user", "performed by"],
    oldLast4: ["old_account_last4", "old account last4", "old account last 4", "previous account last 4"],
    newAccount: ["new_account", "new account", "new account number", "account number", "account"],
    newRouting: ["new_routing", "new routing", "new routing number", "routing number", "aba", "routing"],
    channel: ["channel", "source", "method", "change source"],
    ip: ["ip", "ip address", "source ip", "client ip"],
    field: ["field", "field name", "data element", "attribute", "item changed"],
    oldValue: ["old value", "previous value", "before", "from"],
    newValue: ["new value", "after", "current value", "to"],
    process: ["business process", "business process type", "event", "process"],
  },
  timesheet: {
    employeeId: ["employee_id", "employee id", "file #", "worker id", "employee number", "employee #"],
    name: ["employee name", "name", "worker", "employee"],
    date: ["date", "work date", "entry date", "time entry date"],
    hours: ["hours", "total hours", "duration", "quantity"],
    approvedBy: ["approved_by", "approved by", "approver"],
    project: ["project", "job", "task"],
  },
};

/** Human labels for the mapping panel. */
export const FIELD_LABELS = {
  employeeId: "Employee id", name: "Name", payDate: "Pay date", periodStart: "Period start", periodEnd: "Period end",
  regHours: "Regular hours", otHours: "Overtime hours", hours: "Total hours", regEarn: "Regular earnings", otEarn: "Overtime earnings",
  gross: "Gross pay", net: "Net pay", tax: "Employee taxes (total)", fit: "Federal income tax", ss: "Social Security", medicare: "Medicare",
  stateTax: "State tax", deductions: "Deductions", bankAccount: "Bank account (full)", bankLast4: "Bank account (last 4)", routing: "Routing number",
  paymentMethod: "Payment method", paymentType: "Payment / run type", department: "Department", checkNo: "Check / voucher #", currency: "Currency",
  firstName: "First name", lastName: "Last name", ssn: "SSN / national id", dob: "Date of birth", address: "Address", city: "City", postal: "Postal code",
  phone: "Phone", email: "Email", managerId: "Manager id", hireDate: "Hire date", termDate: "Termination date", status: "Status", payType: "Pay type",
  salary: "Annual salary", hourlyRate: "Hourly rate", changedAt: "Changed at", changedBy: "Changed by", oldLast4: "Old account last 4",
  newAccount: "New account", newRouting: "New routing", channel: "Channel", ip: "IP address", field: "Field (long-form audit)",
  oldValue: "Old value", newValue: "New value", process: "Business process", date: "Date", approvedBy: "Approved by", project: "Project",
};

/** Tunable thresholds; the UI renders these as the settings panel. */
export const DEFAULTS = {
  bankChangeDays: 5,        // a bank change this many days or fewer before the next pay date is screened
  spikeZ: 3.5,              // robust z-score (median / MAD) above which a period's gross is a spike
  maxOvertime: 20,          // overtime hours per week-equivalent
  minPeriods: 6,            // pay periods an employee needs before the spike test runs
  spikeMinPct: 20,          // a spike must also exceed the employee's median gross by this percentage
  maxWeeklyHours: 100,      // total paid hours per week-equivalent that are physically implausible
  campaignMin: 3,           // distinct employees changing to the same routing number within the window
  campaignWindowDays: 7,
  salaryTolerancePct: 5,    // salaried gross above salary / periods-per-year by more than this
  finalPayDays: 16,         // without period dates, pay this long after termination is still a plausible final check
  hoursTolerance: 0.25,     // paid hours may exceed approved timesheet hours by this much
  otShareMultiple: 3,       // OT share this many times the department median
};

// ---------------------------------------------------------------------------
// Controls (cite only what we are sure of)
// ---------------------------------------------------------------------------
const ACFE = (scheme) => ({ framework: "ACFE Fraud Tree", id: "Asset Misappropriation > Fraudulent Disbursements > Payroll > " + scheme });
const COSO10 = { framework: "COSO 2013", id: "Principle 10" };
const COSO12 = { framework: "COSO 2013", id: "Principle 12" };
const SOX = { framework: "SOX 404", id: "ITGC - logical access and change management" };
const AC5 = { framework: "NIST-800-53", id: "AC-5" };
const T1566 = { framework: "MITRE", id: "T1566" };
const T1534 = { framework: "MITRE", id: "T1534" };
const T1078 = { framework: "MITRE", id: "T1078" };
const T1656 = { framework: "MITRE", id: "T1656" };

// ---------------------------------------------------------------------------
// Primitives: money, dates, ids, bank accounts
// ---------------------------------------------------------------------------
/** Parse a money string to integer cents (currency symbols, thousands separators, parentheses negatives). null if empty. */
export function toCents(v) {
  if (typeof v === "number") return Number.isFinite(v) ? Math.round(v * 100) : null;
  let t = str(v);
  if (!t) return null;
  let neg = false;
  if (/^\(.*\)$/.test(t)) { neg = true; t = t.slice(1, -1); }
  if (/-/.test(t)) neg = !neg;
  t = t.replace(/[^0-9.,]/g, "");
  if (/^\d{1,3}(\.\d{3})+,\d{1,2}$/.test(t) || /^\d+,\d{1,2}$/.test(t)) t = t.replace(/\./g, "").replace(",", ".");
  else t = t.replace(/,/g, "");
  if (!/\d/.test(t) || !/^\d*\.?\d*$/.test(t)) return null;
  const [i, f = ""] = t.split(".");
  let cents = Number(i || "0") * 100 + Number((f + "00").slice(0, 2));
  if (f.length > 2 && Number(f[2]) >= 5) cents += 1;
  if (!Number.isSafeInteger(cents)) return null;
  return neg && cents ? -cents : cents;
}

/** Integer cents -> "1,234.56". */
export function formatCents(c) {
  if (c == null || !Number.isFinite(c)) return "";
  const neg = c < 0, a = Math.abs(Math.round(c));
  const whole = String(Math.floor(a / 100)).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return (neg ? "-" : "") + whole + "." + String(a % 100).padStart(2, "0");
}

const toNum = (v) => { const t = str(v).replace(/,/g, ""); if (!t) return null; const n = Number(t); return Number.isFinite(n) ? n : null; };

/** Date-ish -> UTC day number (days since epoch), or null. */
export function parseDay(s) {
  const t = str(s);
  if (!t) return null;
  let y, m, d;
  let mm = t.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})/);
  if (mm) { y = +mm[1]; m = +mm[2]; d = +mm[3]; } else {
    mm = t.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})(?!\d)/);
    if (mm) { m = +mm[1]; d = +mm[2]; y = +mm[3]; if (y < 100) y += 2000; }
  }
  if (!y) {
    const ts = Date.parse(t);
    if (!Number.isFinite(ts)) return null;
    return Math.floor(ts / 86400000);
  }
  if (m < 1 || m > 12 || d < 1 || d > 31) return null;
  const ms = Date.UTC(y, m - 1, d);
  const back = new Date(ms);
  if (back.getUTCDate() !== d) return null;
  return Math.floor(ms / 86400000);
}
export const dayIso = (n) => (n == null ? "" : new Date(n * 86400000).toISOString().slice(0, 10));

/** Normalized employee id: lower-cased; all-digit ids lose leading zeros (ADP File # is zero-padded). */
export function normId(v) {
  const s = low(v);
  if (!s) return "";
  return /^\d+$/.test(s) ? String(s.replace(/^0+(?=\d)/, "")) : s;
}
const normName = (v) => {
  const s = low(v);
  if (!s) return "";
  // "Last, First" -> "first last"
  const m = s.match(/^([^,]+),\s*(.+)$/);
  return alnum(m ? m[2] + " " + m[1] : s);
};

/**
 * Check an SSN / national id. Never returns the full number: { present, kind: ssn|national, valid, reasons, last4, masked }.
 * SSA rules: area 000, 666 and 900-999 are never issued; group 00 and serial 0000 are never issued.
 */
export function ssnCheck(raw) {
  const s = str(raw);
  if (!s) return { present: false, kind: null, valid: null, reasons: [], last4: "", masked: "" };
  const digits = s.replace(/[\s-]/g, "");
  const ssnShaped = /^\d{9}$/.test(digits) || /^\d{3}-\d{2}-\d{1,6}$/.test(s);
  if (ssnShaped) {
    const reasons = [];
    if (!/^\d{9}$/.test(digits)) reasons.push("not 9 digits");
    else {
      const area = digits.slice(0, 3), group = digits.slice(3, 5), serial = digits.slice(5);
      if (area === "000") reasons.push("area 000 is never issued");
      if (area === "666") reasons.push("area 666 is never issued");
      if (area[0] === "9") reasons.push("area 9xx is never issued as an SSN (ITIN / reserved range)");
      if (group === "00") reasons.push("group 00 is never issued");
      if (serial === "0000") reasons.push("serial 0000 is never issued");
      if (digits === "123456789" || digits === "078051120") reasons.push("publicly voided number");
    }
    const last4 = digits.slice(-4);
    return { present: true, kind: "ssn", valid: reasons.length === 0, reasons, last4, masked: "***-**-" + last4, key: "ssn:" + digits };
  }
  const a = s.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
  const last4 = a.slice(-4);
  return { present: true, kind: "national", valid: null, reasons: [], last4, masked: "****" + last4, key: "nid:" + a };
}

/**
 * Bank account fingerprint. Masked inputs ("XXXX1234") or fewer than 5 digits are last-4 only (no key).
 * Returns { key?, label, last4, routing, iban } with key held in memory only.
 */
export function accountInfo(account, routing) {
  const raw = str(account);
  if (!raw) return null;
  const a = raw.replace(/[\s-]/g, "").toUpperCase();
  if (/^[A-Z]{2}\d{2}[A-Z0-9]{8,}$/.test(a)) return { key: "iban:" + a, label: "IBAN ****" + a.slice(-4), last4: a.slice(-4), routing: "", iban: true };
  const digits = a.replace(/\D/g, "");
  if (!digits) return null;
  const masked = /[X*•#]/i.test(a) || digits.length < 5;
  const r = str(routing).replace(/\D/g, "");
  const last4 = digits.slice(-4);
  const label = "acct ****" + last4 + (r ? " / RTN " + r : "");
  if (masked) return { key: null, label, last4, routing: r, iban: false };
  return { key: (r ? "aba:" + r : "acct") + ":" + digits, label, last4, routing: r, iban: false };
}

function payTypeClass(payType, salaryC, rateC) {
  const p = low(payType);
  if (/contract|1099|freelanc|vendor|consultant/.test(p)) return "contractor";
  if (/hour|non-?exempt|wage/.test(p)) return "hourly";
  if (/salar|exempt/.test(p)) return "salary";
  if (salaryC > 0) return "salary";
  if (rateC > 0) return "hourly";
  return "";
}

function channelClass(v) {
  const c = low(v);
  if (!c) return "";
  if (/self|ess\b|employee portal|mobile|myadp|portal|app\b|employee/.test(c)) return "self-service";
  if (/help|support|service desk|call|phone|ticket/.test(c)) return "helpdesk";
  if (/admin|hr|payroll|back.?office|import|bulk|practitioner/.test(c)) return "admin";
  return c;
}

const BONUS_RE = /bonus|commission|supplemental|off.?cycle|retro|adjust/i;

// ---------------------------------------------------------------------------
// Classification and parsing
// ---------------------------------------------------------------------------
/** Classify one file by its headers: { kind, vendor, confidence: high|medium|low }. */
export function classifyFile(headers) {
  const n = new Set((headers || []).map(normHeader));
  const raw = (headers || []).map((h) => low(h));
  const has = (...ks) => ks.every((k) => n.has(normHeader(k)));
  const any = (...ks) => ks.some((k) => n.has(normHeader(k)));
  const r = (kind, vendor, confidence) => ({ kind, vendor, confidence });

  // Bank / direct-deposit change logs
  if (has("employee_id", "changed_at", "new_account") && any("new_routing")) return r("bank", "generic", "high");
  if (any("old value", "previous value") && any("new value") && any("field", "field name", "data element")) return r("bank", "adp-audit", "medium");
  if (any("business process", "business process type") && any("initiated on", "completed on")) return r("bank", "workday-bp", "medium");
  if (any("changed_at", "changed at", "change date", "date changed") && any("routing number", "new routing", "account number", "new account")) return r("bank", "gusto-history", "medium");

  // Timesheets
  if (any("approved_by", "approved by", "approver") && any("hours", "duration") && !any("gross", "gross pay", "gross earnings", "net pay")) {
    return r("timesheet", "generic", has("employee_id", "date", "hours", "approved_by") ? "high" : "medium");
  }

  // Payroll registers
  if (has("company code", "file #", "pay date", "gross pay", "net pay")) return r("register", "adp", raw.includes("check/voucher #") ? "high" : "medium");
  if (has("check date", "employee", "employee id", "gross earnings", "net pay") && any("employee taxes")) return r("register", "gusto", "high");
  if (has("worker", "employee id", "payment date", "gross amount", "net amount")) return r("register", "workday", "high");
  if (any("check date") && any("period begin", "period begin date") && any("gross", "gross pay") && any("net", "net pay")) return r("register", "paychex", "medium");
  if (has("employee_id", "pay_date", "gross", "net")) return r("register", "generic", has("period_start", "period_end") ? "high" : "medium");
  if (any("pay date", "check date", "payment date", "pay_date") && any("gross", "gross pay", "gross earnings", "gross amount", "gross wages")) return r("register", "generic", "medium");

  // HR rosters
  if (has("employee_id", "name", "ssn_or_national_id", "hire_date", "termination_date")) return r("roster", "generic", "high");
  const hrDate = any("hire date", "hire_date", "start date", "original hire date", "termination date", "termination_date");
  if (hrDate && any("worker", "employee id") && any("supervisory organization", "national id")) return r("roster", "workday", "medium");
  if (hrDate && raw.includes("employee #")) return r("roster", "bamboohr", "medium");
  if (hrDate && any("legal name", "employment status", "work email")) return r("roster", "rippling", "medium");
  if (hrDate && any("employee id", "employee_id", "name", "full name")) return r("roster", "generic", "medium");
  if (any("ssn", "ssn_or_national_id", "national id")) return r("roster", "generic", "low");
  return r("unknown", "generic", "low");
}

function parseOne(name, text) {
  const t = String(text || "").replace(/^﻿/, "");
  const trimmed = t.trim();
  if (!trimmed) return { name, format: "empty", headers: [], rows: [] };
  const format = sniff(trimmed).format;
  if (format === "json" || format === "ndjson") {
    let rows = [];
    try { rows = iterJson(trimmed).filter((x) => x && typeof x === "object").map((x) => flatten(x)); } catch (_) { rows = []; }
    const hs = [];
    for (const row of rows) for (const k of Object.keys(row)) if (!hs.includes(k)) hs.push(k);
    return { name, format, headers: hs, rows };
  }
  const { headers, rows } = parseCsv(trimmed);
  return { name, format: format === "tsv" ? "tsv" : "csv", headers, rows };
}

/**
 * Parse a string, {name,text}, or an array of either. Returns { format, headers, rows, files, skipped };
 * each file is { name, format, headers, rows, rowCount, kind, vendor, confidence, columns }. Never throws.
 */
export function parseInput(input) {
  const list = Array.isArray(input) ? input : [input];
  const skipped = [], files = [];
  list.forEach((it, i) => {
    const name = it && typeof it === "object" ? str(it.name) || "file-" + (i + 1) : "file-" + (i + 1);
    const text = it && typeof it === "object" ? (it.text != null ? it.text : "") : it;
    const p = parseOne(name, text);
    if (!p.rows.length) skipped.push({ check: "parse", reason: name + ": no rows (" + p.format + ")" });
    const cls = classifyFile(p.headers);
    if (cls.kind === "unknown" && p.rows.length) skipped.push({ check: "classify", reason: name + ": headers not recognised; choose the file role manually" });
    files.push({ name, format: p.format, headers: p.headers, rows: p.rows, rowCount: p.rows.length, ...cls, columns: {} });
  });
  const first = files[0] || { format: "empty", headers: [], rows: [] };
  return { format: files.length > 1 ? "multi" : first.format, headers: first.headers, rows: first.rows, files, skipped };
}

/** Resolve logical columns for a file: manual overrides first, then aliases. */
export function resolveColumns(file, kind) {
  const spec = COLUMNS[kind] || {};
  const headers = file.headers || [];
  const ov = file.columns || {};
  const out = {}, used = new Set();
  for (const k of Object.keys(spec)) if (ov[k] && headers.includes(ov[k])) { out[k] = ov[k]; used.add(ov[k]); }
  if (kind === "register" && !out.bankLast4) {
    const h = headers.find((x) => !used.has(x) && /last\s*-?\s*4|last four/i.test(x) && /account|acct|bank/i.test(x));
    if (h) { out.bankLast4 = h; used.add(h); }
  }
  for (const k of Object.keys(spec)) {
    if (out[k]) continue;
    const h = findColumn(headers.filter((x) => !used.has(x)), spec[k]);
    if (h) { out[k] = h; used.add(h); }
  }
  return out;
}

function normalizeFiles(dataset) {
  if (!dataset) return [];
  if (typeof dataset === "string") return parseInput(dataset).files;
  if (Array.isArray(dataset)) {
    if (!dataset.length) return [];
    if (dataset.every((f) => f && typeof f === "object" && Array.isArray(f.rows))) return dataset;
    if (dataset.every((f) => f && typeof f === "object" && typeof f.text === "string")) return parseInput(dataset).files;
    const headers = [];
    for (const row of dataset) for (const k of Object.keys(row || {})) if (!headers.includes(k)) headers.push(k);
    return [{ name: "rows", headers, rows: dataset, rowCount: dataset.length, ...classifyFile(headers), columns: {} }];
  }
  if (Array.isArray(dataset.files)) return normalizeFiles(dataset.files);
  if (Array.isArray(dataset.rows)) return normalizeFiles(dataset.rows);
  return [];
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------
function loadRoster(file, cols, people) {
  const g = (row, k) => (cols[k] ? row[cols[k]] : undefined);
  file.rows.forEach((row, i) => {
    const idRaw = str(g(row, "employeeId"));
    let name = str(g(row, "name"));
    if (!name && (cols.firstName || cols.lastName)) name = (str(g(row, "firstName")) + " " + str(g(row, "lastName"))).trim();
    const id = normId(idRaw);
    if (!id && !name) return;
    const salaryC = cols.salary ? toCents(g(row, "salary")) : null;
    const rateC = cols.hourlyRate ? toCents(g(row, "hourlyRate")) : null;
    const status = str(g(row, "status"));
    const rec = {
      file: file.name, row: i + 2, id: id || "name:" + normName(name), idRaw: idRaw || name, name: name || idRaw,
      ssn: ssnCheck(g(row, "ssn")), address: str(g(row, "address")), city: str(g(row, "city")), postal: str(g(row, "postal")),
      phone: str(g(row, "phone")), email: low(g(row, "email")), department: str(g(row, "department")),
      managerId: normId(g(row, "managerId")), hire: parseDay(g(row, "hireDate")), term: parseDay(g(row, "termDate")), status,
      payType: payTypeClass(g(row, "payType"), salaryC, rateC), payTypeRaw: str(g(row, "payType")), salaryC, rateC,
    };
    rec.terminated = rec.term != null || /term|inactive|separat|former|resign|dismiss/i.test(status);
    if (!people.has(rec.id)) people.set(rec.id, rec);
  });
}

function loadRegister(file, cols, out, ctx, counter) {
  const g = (row, k) => (cols[k] ? row[cols[k]] : undefined);
  const taxParts = ["fit", "ss", "medicare", "stateTax"].filter((k) => cols[k]);
  const rows = file.rows;
  for (let i = 0; i < rows.length; i++) {
    counter.n++;
    if (counter.n % 1000 === 0) ctx?.progress?.(counter.n, counter.total, "register");
    const row = rows[i];
    const idRaw = str(g(row, "employeeId")), name = str(g(row, "name"));
    if (!idRaw && !name) continue;
    let grossC = cols.gross ? toCents(g(row, "gross")) : null;
    if (grossC == null && (cols.regEarn || cols.otEarn)) {
      const a = toCents(g(row, "regEarn")), b = toCents(g(row, "otEarn"));
      if (a != null || b != null) grossC = (a || 0) + (b || 0);
    }
    let taxC = null;
    if (cols.tax) taxC = toCents(g(row, "tax"));
    else if (taxParts.length) { let s = 0, seen = false; for (const k of taxParts) { const c = toCents(g(row, k)); if (c != null) { s += c; seen = true; } } taxC = seen ? s : 0; }
    const regH = cols.regHours ? toNum(g(row, "regHours")) : null;
    const otH = cols.otHours ? toNum(g(row, "otHours")) : null;
    const totH = cols.hours ? toNum(g(row, "hours")) : null;
    const acct = cols.bankAccount ? accountInfo(g(row, "bankAccount"), g(row, "routing")) : null;
    const l4raw = cols.bankLast4 ? str(g(row, "bankLast4")).replace(/\D/g, "") : "";
    out.push({
      file: file.name, row: i + 2, idRaw, name, payDay: parseDay(g(row, "payDate")),
      pStart: parseDay(g(row, "periodStart")), pEnd: parseDay(g(row, "periodEnd")),
      regH, otH, totH, hours: totH != null ? totH : (regH != null || otH != null ? (regH || 0) + (otH || 0) : null),
      otEarnC: cols.otEarn ? toCents(g(row, "otEarn")) : null,
      grossC, netC: cols.net ? toCents(g(row, "net")) : null, taxC, dedC: cols.deductions ? toCents(g(row, "deductions")) : null,
      acct, last4: acct ? acct.last4 : l4raw ? l4raw.slice(-4) : "", routing: cols.routing ? str(g(row, "routing")).replace(/\D/g, "") : "",
      method: str(g(row, "paymentMethod")), ptype: str(g(row, "paymentType")), department: str(g(row, "department")),
      check: str(g(row, "checkNo")), currency: str(g(row, "currency")).toUpperCase(),
    });
  }
}

function loadBank(file, cols, out) {
  const g = (row, k) => (cols[k] ? row[cols[k]] : undefined);
  const longForm = !cols.newAccount && cols.field && cols.newValue;
  if (longForm) {
    // ADP-style audit: one row per changed field; group by employee + timestamp.
    const groups = new Map();
    file.rows.forEach((row, i) => {
      const fld = low(g(row, "field"));
      const proc = low(g(row, "process"));
      if (!/account|routing|transit|aba|direct deposit|bank|iban/.test(fld + " " + proc)) return;
      const key = normId(g(row, "employeeId")) + "|" + normName(g(row, "name")) + "|" + str(g(row, "changedAt"));
      let gr = groups.get(key);
      if (!gr) { gr = { row: i + 2, src: row, account: "", routing: "", old: "" }; groups.set(key, gr); }
      const nv = str(g(row, "newValue")), ov = str(g(row, "oldValue"));
      if (/routing|transit|aba/.test(fld)) gr.routing = nv;
      else if (/iban|account/.test(fld) && !/type|status|percent|amount/.test(fld)) { gr.account = nv; gr.old = ov.replace(/\D/g, "").slice(-4); }
    });
    for (const gr of groups.values()) pushChange(file, cols, gr.src, gr.row, gr.account, gr.routing, gr.old, out);
    return;
  }
  file.rows.forEach((row, i) => {
    if (cols.process && !cols.newAccount) {
      const proc = low(g(row, "process"));
      if (proc && !/payment election|direct deposit|bank|account/.test(proc)) return;
    }
    pushChange(file, cols, row, i + 2, g(row, "newAccount"), g(row, "newRouting"), str(g(row, "oldLast4")).replace(/\D/g, "").slice(-4), out);
  });
}

function pushChange(file, cols, row, rowNo, account, routing, oldLast4, out) {
  const g = (k) => (cols[k] ? row[cols[k]] : undefined);
  const idRaw = str(g("employeeId")), name = str(g("name"));
  if (!idRaw && !name) return;
  const acct = accountInfo(account, routing);
  const rt = str(routing).replace(/\D/g, "");
  out.push({
    file: file.name, row: rowNo, idRaw, name, day: parseDay(g("changedAt")), at: str(g("changedAt")),
    by: str(g("changedBy")), channelRaw: str(g("channel")), channel: channelClass(g("channel")), ip: str(g("ip")),
    acct, routing: rt || (acct ? acct.routing : ""), oldLast4: oldLast4 || "",
  });
}

function loadTimesheets(file, cols, out) {
  const g = (row, k) => (cols[k] ? row[cols[k]] : undefined);
  file.rows.forEach((row, i) => {
    const idRaw = str(g(row, "employeeId")), name = str(g(row, "name"));
    if (!idRaw && !name) return;
    out.push({ file: file.name, row: i + 2, idRaw, name, day: parseDay(g(row, "date")), hours: toNum(g(row, "hours")) || 0, approvedBy: str(g(row, "approvedBy")), project: str(g(row, "project")) });
  });
}

// ---------------------------------------------------------------------------
// Stats helpers
// ---------------------------------------------------------------------------
const median = (xs) => {
  if (!xs.length) return null;
  const s = xs.slice().sort((a, b) => a - b), m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};
const round2 = (x) => Math.round(x * 100) / 100;

function periodsPerYear(days) {
  if (days == null) return null;
  if (days <= 8) return 52;
  if (days <= 14.5) return 26;
  if (days <= 17) return 24;
  if (days <= 32) return 12;
  return null;
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
function cleanOpts(opts) {
  const o = {};
  for (const [k, v] of Object.entries(opts || {})) {
    if (k in DEFAULTS) { const n = Number(v); if (v !== "" && v != null && Number.isFinite(n)) o[k] = n; } else o[k] = v;
  }
  return o;
}

/**
 * Analyze a dataset ({files} from parseInput, an array of files, or an array of {name,text}).
 * Returns { summary, findings, tables, skipped, meta }. ctx.progress(i, n, label) every ~1000 rows.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...cleanOpts(opts) };
  const skipped = [], findings = [];
  const files = normalizeFiles(dataset).map((f) => (f.kind && (KINDS.includes(f.kind) || f.kind === "unknown") ? f : { ...f, ...classifyFile(f.headers || []) }));
  const total = files.reduce((n, f) => n + (f.rows ? f.rows.length : 0), 0);
  const counter = { n: 0, total: total || 1 };
  ctx?.progress?.(0, counter.total, "loading");

  const people = new Map(); // roster by normalized id
  const pay = [], changes = [], sheets = [];
  const has = { register: false, roster: false, bank: false, timesheet: false };
  const colInfo = { register: [], roster: [], bank: [], timesheet: [] };
  const metaFiles = [];
  for (const f of files) {
    const kind = f.kind;
    const cols = KINDS.includes(kind) && kind !== "ignore" ? resolveColumns(f, kind) : {};
    metaFiles.push({ name: f.name, kind, vendor: f.vendor || "generic", confidence: f.confidence || "low", rows: (f.rows || []).length, columns: cols });
    if (!f.rows || !f.rows.length || !KINDS.includes(kind) || kind === "ignore") {
      if (kind === "unknown") skipped.push({ check: "classify", reason: f.name + ": file role not recognised; set it in the Files panel" });
      continue;
    }
    if (kind === "register") {
      if (!cols.gross && !cols.regEarn && !cols.otEarn) { skipped.push({ check: "register", reason: f.name + ": no gross pay column mapped" }); continue; }
      if (!cols.employeeId && !cols.name) { skipped.push({ check: "register", reason: f.name + ": no employee id or name column mapped" }); continue; }
      has.register = true; colInfo.register.push(cols); loadRegister(f, cols, pay, ctx, counter);
    } else if (kind === "roster") {
      if (!cols.employeeId && !cols.name) { skipped.push({ check: "roster", reason: f.name + ": no employee id or name column mapped" }); continue; }
      has.roster = true; colInfo.roster.push(cols); loadRoster(f, cols, people);
    } else if (kind === "bank") {
      has.bank = true; colInfo.bank.push(cols); loadBank(f, cols, changes);
    } else if (kind === "timesheet") {
      has.timesheet = true; colInfo.timesheet.push(cols); loadTimesheets(f, cols, sheets);
    }
  }
  const anyCol = (kind, ...ks) => colInfo[kind].some((c) => ks.some((k) => c[k]));

  // --- identity resolution ---------------------------------------------------
  const byName = new Map();
  for (const p of people.values()) { const nn = normName(p.name); if (nn && !byName.has(nn)) byName.set(nn, p.id); }
  const resolve = (idRaw, name) => {
    const id = normId(idRaw);
    if (id) return id;
    const nn = normName(name);
    return byName.get(nn) || (nn ? "name:" + nn : "");
  };
  const emps = new Map();
  const emp = (key, name) => {
    let e = emps.get(key);
    if (!e) {
      const p = people.get(key) || null;
      e = { key, p, name: p ? p.name : name || key, rows: [], flags: new Map(), riskRows: new Set(), extraRisk: 0, department: p ? p.department : "" };
      emps.set(key, e);
    }
    if (!e.name && name) e.name = name;
    return e;
  };
  pay.forEach((r, i) => { r.idx = i; r.key = resolve(r.idRaw, r.name); const e = emp(r.key, r.name); e.rows.push(r); if (!e.department && r.department) e.department = r.department; });
  for (const c of changes) c.key = resolve(c.idRaw, c.name);
  for (const t of sheets) t.key = resolve(t.idRaw, t.name);
  for (const e of emps.values()) e.rows.sort((a, b) => cmp(a.payDay ?? 0, b.payDay ?? 0) || cmp(a.pStart ?? 0, b.pStart ?? 0) || a.idx - b.idx);

  const label = (e) => (e.name && e.name !== e.key ? e.name + " (" + (e.p ? e.p.idRaw : e.rows[0] ? e.rows[0].idRaw || e.key : e.key) + ")" : e.key);
  const labelFor = (key) => { const e = emps.get(key); if (e) return label(e); const p = people.get(key); return p ? p.name + " (" + p.idRaw + ")" : key; };
  const assetFor = (key) => ({ type: "IDENTITY", name: labelFor(key), _key: key });
  const flag = (key, f, sev, rows) => {
    const e = emps.get(key) || emp(key, people.get(key) ? people.get(key).name : key);
    const prev = e.flags.get(f);
    if (!prev || SEV_RANK[sev] > SEV_RANK[prev]) e.flags.set(f, sev);
    for (const r of rows || []) e.riskRows.add(r.idx);
  };
  const money = (c) => formatCents(c);
  const payEv = (r, extra) => ({
    file: r.file, row: r.row, employee: labelFor(r.key), pay_date: dayIso(r.payDay), period: r.pStart != null ? dayIso(r.pStart) + " to " + dayIso(r.pEnd) : "",
    gross: money(r.grossC), net: money(r.netC), tax: r.taxC == null ? "" : money(r.taxC), deductions: r.dedC == null ? "" : money(r.dedC),
    hours: r.hours == null ? "" : r.hours, overtime_hours: r.otH == null ? "" : r.otH, account: r.acct ? r.acct.label : r.last4 ? "****" + r.last4 : "", ...(extra || {}),
  });
  const netOf = (rows) => rows.reduce((s, r) => s + (r.netC != null ? r.netC : r.grossC || 0), 0);
  const push = (f) => {
    const ev = f.evidence || [];
    findings.push({
      id: f.id, title: f.title, severity: f.severity, confidence: f.confidence, category: f.category, description: f.description,
      recommendation: f.recommendation, controls: f.controls, evidence: ev.slice(0, 50), evidenceCount: ev.length,
      assets: (f.assets || []).slice(0, 50), amountAtRiskCents: f.amountAtRiskCents || 0, tags: f.tags || [],
    });
  };

  // "now": opts.now or newest date in the data.
  let nowDay = o.now ? parseDay(o.now) : null;
  if (nowDay == null) {
    let m = null; const bump = (d) => { if (d != null && (m == null || d > m)) m = d; };
    for (const r of pay) { bump(r.payDay); bump(r.pEnd); }
    for (const c of changes) bump(c.day);
    for (const t of sheets) bump(t.day);
    nowDay = m;
  }

  const companyPayDays = [...new Set(pay.map((r) => r.payDay).filter((d) => d != null))].sort((a, b) => a - b);
  const gapMedian = (() => {
    const g = []; for (let i = 1; i < companyPayDays.length; i++) g.push(companyPayDays[i] - companyPayDays[i - 1]);
    return median(g);
  })();
  const periodDays = (r) => (r.pStart != null && r.pEnd != null && r.pEnd >= r.pStart ? r.pEnd - r.pStart + 1 : gapMedian || 7);

  // =============================== Ghost employees ===========================
  const GHOST = [ACFE("Ghost Employee"), COSO10, COSO12];
  if (!has.register) skipped.push({ check: "all_pay_checks", reason: "no payroll register loaded" });
  if (has.register && !has.roster) {
    for (const c of ["not_on_roster", "paid_after_termination", "paid_before_hire", "tax_id_validity", "missing_contact", "salary_change"]) skipped.push({ check: c, reason: "no HR roster loaded" });
  }
  const weak = new Map(); // key -> [signal]
  const addWeak = (key, s) => { if (!weak.has(key)) weak.set(key, []); weak.get(key).push(s); };

  if (has.register && has.roster) {
    const keys = [...emps.keys()].sort();
    for (const key of keys) {
      const e = emps.get(key);
      if (!e.rows.length) continue;
      if (!e.p) {
        const nn = normName(e.name);
        const alt = nn ? byName.get(nn) : null;
        flag(key, "not on roster", alt ? "medium" : "high", e.rows);
        push({
          id: "ghost-not-on-roster:" + key, title: alt ? "Paid id not on roster (name matches another roster id)" : "Paid employee not on the HR roster",
          severity: alt ? "medium" : "high", confidence: alt ? "review" : "likely", category: "ghost-employee",
          description: label(e) + " received " + e.rows.length + " payment(s) totalling " + money(netOf(e.rows)) + " net, but the id is not in the HR roster" + (alt ? "; the name matches roster id " + people.get(alt).idRaw + ", which suggests an id mismatch rather than a ghost." : ". Pattern consistent with a ghost employee; it can also be a roster export that is out of date."),
          recommendation: "Confirm the person exists in HR (I-9 / onboarding file, badge, manager attestation) before the next pay run; hold pay until confirmed.",
          controls: GHOST, evidence: e.rows.map((r) => payEv(r)), assets: [assetFor(key)], amountAtRiskCents: netOf(e.rows),
        });
      } else {
        const p = e.p;
        if (p.term != null) {
          const after = e.rows.filter((r) => (r.pStart != null ? r.pStart > p.term : r.payDay != null && r.payDay > p.term + o.finalPayDays));
          if (after.length) {
            flag(key, "paid after termination", "high", after);
            push({
              id: "ghost-after-term:" + key, title: "Paid after termination date", severity: "high", confidence: "likely", category: "ghost-employee",
              description: label(e) + " was terminated " + dayIso(p.term) + " but has " + after.length + " later payment(s) (" + money(netOf(after)) + " net) " +
                (after.some((r) => r.pStart != null) ? "for pay periods that start after the termination date." : "more than " + o.finalPayDays + " days after the termination date (no period dates in the register)."),
              recommendation: "Stop the pay, confirm the termination was processed in payroll, and trace where the deposits went.",
              controls: GHOST, evidence: after.map((r) => payEv(r, { termination_date: dayIso(p.term) })), assets: [assetFor(key)], amountAtRiskCents: netOf(after),
            });
          }
        }
        if (p.hire != null) {
          const before = e.rows.filter((r) => (r.pEnd != null ? r.pEnd < p.hire : r.payDay != null && r.payDay < p.hire));
          if (before.length) {
            flag(key, "paid before hire", "high", before);
            push({
              id: "ghost-before-hire:" + key, title: "Paid before hire date", severity: "high", confidence: "likely", category: "ghost-employee",
              description: label(e) + " was hired " + dayIso(p.hire) + " but was paid for " + before.length + " period(s) that end before that date.",
              recommendation: "Confirm the hire date in HR; recover pay for periods before employment or correct the roster.",
              controls: GHOST, evidence: before.map((r) => payEv(r, { hire_date: dayIso(p.hire) })), assets: [assetFor(key)], amountAtRiskCents: netOf(before),
            });
          }
        }
        if (p.ssn && !p.ssn.present && colInfo.roster.some((c) => c.ssn)) addWeak(key, "missing SSN / national id");
        if (p.ssn && p.ssn.present && p.ssn.valid === false) addWeak(key, "invalid SSN pattern (" + p.ssn.reasons.join("; ") + ")");
        if (anyCol("roster", "address", "phone", "email") && !p.address && !p.phone && !p.email) addWeak(key, "no address, phone or email on file");
      }
    }
    if (!anyCol("roster", "ssn")) skipped.push({ check: "tax_id_validity", reason: "roster has no SSN / national id column" });
    if (!anyCol("roster", "address", "phone", "email")) skipped.push({ check: "missing_contact", reason: "roster has no address, phone or email column" });
  }

  // No withholding with gross > 0
  if (has.register) {
    if (!anyCol("register", "tax", "fit", "ss", "medicare", "stateTax")) skipped.push({ check: "no_withholding", reason: "register has no tax / withholding columns (Workday pay results carry none; add the tax columns or map them)" });
    else {
      for (const key of [...emps.keys()].sort()) {
        const e = emps.get(key);
        if (e.p && e.p.payType === "contractor") continue;
        const zero = e.rows.filter((r) => r.grossC > 0 && r.taxC === 0);
        if (zero.length) addWeak(key, "no tax withheld on " + zero.length + " of " + e.rows.length + " payment(s)");
      }
    }
  }
  // No deductions while department peers have them
  if (has.register) {
    if (!anyCol("register", "deductions")) skipped.push({ check: "no_deductions_vs_peers", reason: "register has no deductions column" });
    else {
      const byDept = new Map();
      for (const e of emps.values()) {
        if (!e.department || !e.rows.length || !e.rows.some((r) => r.dedC != null)) continue;
        if (!byDept.has(e.department)) byDept.set(e.department, []);
        byDept.get(e.department).push(e);
      }
      for (const [dept, list] of [...byDept].sort((a, b) => cmp(a[0], b[0]))) {
        for (const e of list) {
          if (e.rows.some((r) => (r.dedC || 0) > 0)) continue;
          const peers = list.filter((x) => x !== e);
          const withDed = peers.filter((x) => x.rows.some((r) => (r.dedC || 0) > 0)).length;
          if (peers.length >= 3 && withDed / peers.length >= 0.75) addWeak(e.key, "no deductions while " + withDed + " of " + peers.length + " peers in " + dept + " have them");
        }
      }
    }
  }
  // Weak-signal findings: one aggregate per signal type, plus a per-employee finding when 2+ signals stack.
  const weakTypes = [
    ["no tax withheld", "No tax withheld on gross pay", "Payroll systems withhold FICA on every W-2 payment; zero withholding on gross pay is a ghost-employee indicator (pay types marked contractor / 1099 on the roster are excluded; a missing pay type is treated as W-2).", "Confirm the employee's W-4 and tax setup; a real employee without withholding is still a compliance issue."],
    ["no deductions while", "No deductions where department peers have them", "Ghost employees rarely enrol in benefits or retirement plans.", "Confirm enrolment status; a real employee who waived all benefits is common, so treat as supporting evidence only."],
    ["missing SSN", "Missing SSN / national id", "A paid employee without a tax id on the roster cannot be reported on a W-2.", "Obtain and verify the tax id (SSA SSNVS or equivalent) before the next run."],
    ["invalid SSN", "SSN fails SSA issuance rules", "Area 000, 666 and 9xx, group 00 and serial 0000 are never issued as SSNs (9xx is the ITIN range). Numbers are shown as last 4 only.", "Verify through SSA SSNVS; correct the record or investigate the identity."],
    ["no address", "No address, phone or email on file", "A person with no contact details on the HR roster is hard to verify.", "Complete the record and confirm identity with the manager of record."],
  ];
  const wKeys = [...weak.keys()].sort();
  for (const [prefix, title, why, rec] of weakTypes) {
    const hit = wKeys.filter((k) => weak.get(k).some((s) => s.startsWith(prefix)));
    if (!hit.length) continue;
    for (const k of hit) flag(k, title.toLowerCase(), "medium", []);
    push({
      id: "ghost-signal:" + prefix.replace(/\W+/g, "-"), title, severity: "medium", confidence: "review", category: "ghost-indicator",
      description: hit.length + " employee(s): " + why,
      recommendation: rec, controls: GHOST,
      evidence: hit.map((k) => { const p = people.get(k); return { employee: labelFor(k), detail: weak.get(k).find((s) => s.startsWith(prefix)), department: (emps.get(k) || {}).department || (p ? p.department : ""), ssn: p && p.ssn.present ? p.ssn.masked : "" }; }),
      assets: hit.map(assetFor),
    });
  }
  for (const k of wKeys) {
    const sig = weak.get(k);
    if (sig.length < 2) continue;
    const e = emps.get(k);
    flag(k, "ghost indicators", "high", e ? e.rows : []);
    push({
      id: "ghost-combo:" + k, title: "Multiple ghost-employee indicators", severity: "high", confidence: "likely", category: "ghost-employee",
      description: labelFor(k) + " shows " + sig.length + " independent indicators: " + sig.join("; ") + ". Each alone is common; together they match the ghost-employee pattern.",
      recommendation: "Verify the person physically (manager attestation, badge records, I-9) and trace where the deposits go.",
      controls: GHOST, evidence: sig.map((s) => ({ employee: labelFor(k), indicator: s })), assets: [assetFor(k)], amountAtRiskCents: e ? netOf(e.rows) : 0,
    });
  }

  // =============================== Shared identifiers =========================
  const shared = [];
  const groups = { bank: new Map(), ssn: new Map(), address: new Map(), phone: new Map(), email: new Map() };
  const addG = (type, gkey, labelText, empKey, firstDay) => {
    if (!gkey || !empKey) return;
    let g = groups[type].get(gkey);
    if (!g) { g = { label: labelText, members: new Map() }; groups[type].set(gkey, g); }
    const prev = g.members.get(empKey);
    if (prev === undefined || (firstDay != null && (prev == null || firstDay < prev))) g.members.set(empKey, firstDay ?? prev ?? null);
  };
  for (const r of pay) if (r.acct && r.acct.key) addG("bank", r.acct.key, r.acct.label, r.key, r.payDay);
  for (const c of changes) if (c.acct && c.acct.key) addG("bank", c.acct.key, c.acct.label, c.key, c.day);
  for (const p of people.values()) {
    if (p.ssn.present) addG("ssn", p.ssn.key, (p.ssn.kind === "ssn" ? "SSN " : "National id ") + p.ssn.masked, p.id);
    if (p.address && p.postal) addG("address", alnum(p.address) + "|" + alnum(p.postal), p.address + ", " + (p.city ? p.city + " " : "") + p.postal, p.id);
    const ph = p.phone.replace(/\D/g, "");
    if (ph.length >= 7 && !/^(\d)\1+$/.test(ph)) addG("phone", ph.slice(-10), p.phone, p.id);
    if (p.email && /@/.test(p.email)) addG("email", p.email, p.email, p.id);
  }
  const SHARED = {
    bank: { sev: "high", conf: "likely", title: "Employees share a bank account", why: "Two or more people paid into one account is the classic ghost-employee payout route (ghost pay deposited to the perpetrator's own account).", rec: "Confirm with each employee; joint accounts between spouses on payroll exist but should be documented.", controls: [ACFE("Ghost Employee"), COSO10, SOX] },
    ssn: { sev: "high", conf: "likely", title: "Employees share an SSN / national id", why: "One tax id on two employee records means at least one record is wrong or fabricated.", rec: "Verify both identities through SSA SSNVS (or the national equivalent) and correct the roster.", controls: [ACFE("Ghost Employee"), COSO10] },
    address: { sev: "low", conf: "review", title: "Employees share a home address", why: "Families and housemates legitimately share addresses, so this is context only; it matters when combined with other indicators.", rec: "Review alongside other flags; no action needed when the relationship is known.", controls: [ACFE("Ghost Employee"), COSO10] },
    phone: { sev: "medium", conf: "review", title: "Employees share a phone number", why: "A shared personal phone can mean a fabricated record using the perpetrator's contact details; households share landlines too.", rec: "Confirm with each employee and HR.", controls: [ACFE("Ghost Employee"), COSO10] },
    email: { sev: "medium", conf: "review", title: "Employees share an email address", why: "Personal email shared by two employee records can route pay stubs and resets for a fabricated record to one person.", rec: "Confirm each employee's email; separate shared mailboxes.", controls: [ACFE("Ghost Employee"), COSO10, SOX] },
  };
  for (const type of ["bank", "ssn", "address", "phone", "email"]) {
    const list = [...groups[type].entries()].filter(([, g]) => g.members.size >= 2).sort((a, b) => cmp(a[1].label, b[1].label) || cmp(a[0], b[0]));
    list.forEach(([gk, g], gi) => {
      const members = [...g.members.keys()].sort();
      let reuse = null;
      if (type === "bank") {
        for (const a of members) {
          const pa = people.get(a);
          if (!pa || pa.term == null) continue;
          const later = members.filter((b) => b !== a && g.members.get(b) != null && g.members.get(b) > pa.term);
          if (later.length) { reuse = { from: a, to: later, term: pa.term }; break; }
        }
      }
      const spec = SHARED[type];
      const sev = reuse ? "high" : spec.sev;
      const flagName = reuse ? "terminated employee's account reused" : "shared " + type;
      for (const m of members) flag(m, flagName, sev, type === "bank" ? pay.filter((r) => r.key === m && r.acct && r.acct.key === gk) : []);
      shared.push({ type, identifier: g.label, employees: members.map(labelFor), count: members.length, severity: sev, note: reuse ? "terminated employee's account later used by another" : type === "address" ? "families share addresses" : "" });
      push({
        id: "shared-" + type + ":" + gi, title: reuse ? "Terminated employee's bank account used by another employee" : spec.title, severity: sev, confidence: spec.conf, category: "shared-identifier",
        description: reuse ? labelFor(reuse.from) + " was terminated " + dayIso(reuse.term) + "; the same account (" + g.label + ") was later used for " + reuse.to.map(labelFor).join(", ") + ". Pattern consistent with pay redirected through a departed employee's account."
          : members.length + " employees share " + g.label + ". " + spec.why,
        recommendation: reuse ? "Contact the current account holder, confirm ownership with the bank, and review every deposit to this account." : spec.rec,
        controls: reuse ? [ACFE("Ghost Employee"), COSO10, SOX] : spec.controls,
        evidence: members.map((m) => ({ employee: labelFor(m), identifier: g.label, first_seen: dayIso(g.members.get(m)), terminated: people.get(m) && people.get(m).term != null ? dayIso(people.get(m).term) : "" })),
        assets: members.map(assetFor),
      });
    });
  }
  if (has.register && !has.bank && !anyCol("register", "bankAccount")) skipped.push({ check: "shared_bank_account", reason: "no full bank account numbers in the register and no bank-change log (last-4 alone is not enough to match accounts)" });

  // =============================== Bank changes / payroll diversion ==========
  const bankRows = [];
  if (!has.bank) skipped.push({ check: "payroll_diversion", reason: "no direct-deposit / bank change log loaded" });
  else {
    if (!has.register) skipped.push({ check: "payroll_diversion_timing", reason: "no payroll register loaded, so days-to-payday cannot be measured" });
    const DIV = [T1566, T1534, T1078, COSO10, SOX];
    const sorted = changes.slice().sort((a, b) => cmp(a.day ?? 0, b.day ?? 0) || cmp(a.key, b.key) || cmp(a.file, b.file) || a.row - b.row);
    const identity = (key) => {
      const p = people.get(key); const e = emps.get(key);
      const t = new Set([alnum(key)]);
      const nm = p ? p.name : e ? e.name : "";
      if (nm) { t.add(normName(nm)); t.add(alnum(nm)); }
      if (p && p.idRaw) t.add(alnum(p.idRaw));
      if (p && p.email) { t.add(alnum(p.email)); t.add(alnum(p.email.split("@")[0])); }
      t.delete("");
      return t;
    };
    const byOther = [], selfAdmin = [], badRouting = [], byOtherKeys = new Set();
    sorted.forEach((c, ci) => {
      const e = emps.get(c.key);
      const own = e ? e.rows.filter((r) => r.payDay != null && c.day != null && r.payDay >= c.day) : [];
      let next = own[0] || null, nextDay = next ? next.payDay : null;
      if (!next && c.day != null) { const d = companyPayDays.find((x) => x >= c.day); nextDay = d ?? null; }
      const days = nextDay != null ? nextDay - c.day : null;
      let paidToNew = null;
      if (next && c.acct) {
        if (next.acct && next.acct.key && c.acct.key) paidToNew = next.acct.key === c.acct.key;
        else if (next.last4 && c.acct.last4) paidToNew = next.last4 === c.acct.last4;
      }
      const by = alnum(c.by);
      const selfBy = !by ? null : /^(self|employee|ess|selfservice)$/.test(by) || identity(c.key).has(by);
      let routingValid = null, routingReason = "";
      if (c.acct && c.acct.iban) { const v = validateIBAN(c.acct.key ? c.acct.key.slice(5) : ""); routingValid = v.ok; routingReason = v.ok ? "" : v.reason; }
      else if (c.routing) { const v = validateABA(c.routing); routingValid = v.ok; routingReason = v.ok ? "" : v.reason; }
      const flags = [];
      const within = days != null && days >= 0 && days <= o.bankChangeDays && paidToNew !== false;
      const privileged = c.channel === "helpdesk" || c.channel === "admin";
      if (within) flags.push("before payday");
      if (privileged) flags.push(c.channel);
      if (selfBy === false) flags.push("changed by someone else");
      if (selfBy === true && privileged) flags.push("own record via " + c.channel);
      if (routingValid === false) flags.push("invalid routing");
      if (paidToNew === true) flags.push("next pay went to new account");
      const row = {
        employee: labelFor(c.key), changed_at: c.at || dayIso(c.day), changed_by: c.by, channel: c.channel || c.channelRaw, ip: c.ip,
        old_account: c.oldLast4 ? "****" + c.oldLast4 : "", new_account: c.acct ? c.acct.label : "", routing: c.routing, routing_valid: routingValid,
        next_pay_date: dayIso(nextDay), days_to_payday: days, paid_to_new_account: paidToNew, next_net: next ? money(next.netC != null ? next.netC : next.grossC) : "",
        flags, _key: c.key, _ci: ci, _next: next, _day: c.day,
      };
      bankRows.push(row);
      const ev = { file: c.file, row: c.row, employee: row.employee, changed_at: row.changed_at, changed_by: c.by, channel: row.channel, ip: c.ip, new_account: row.new_account, next_pay_date: row.next_pay_date, days_to_payday: days, paid_to_new_account: paidToNew };
      if (within) {
        const sev = privileged ? "critical" : "high";
        flag(c.key, "bank change before payday", sev, next ? [next] : []);
        push({
          id: "diversion:" + c.key + ":" + ci, title: privileged ? "Direct deposit changed by " + c.channel + " " + days + " day(s) before payday" : "Direct deposit changed " + days + " day(s) before payday",
          severity: sev, confidence: paidToNew === true ? "likely" : "review", category: "payroll-diversion",
          description: row.employee + "'s deposit account was changed on " + row.changed_at + (c.channel ? " via " + c.channel : "") + (c.by ? " by " + c.by : "") + ", " + days + " day(s) before the " + row.next_pay_date + " pay date" +
            (paidToNew === true ? "; that pay went to the new account." : paidToNew == null ? "; the register does not show which account the pay went to." : ".") +
            " Pattern consistent with payroll-diversion account takeover" + (privileged ? " via social engineering of the help desk / admin." : " (phished employee credentials used on self-service)."),
          recommendation: "Call the employee on a number from the HR file (not from the request) before releasing the pay; if unconfirmed, revert the account and pay by check. Require out-of-band verification for every deposit change.",
          controls: privileged ? [T1656, ...DIV] : DIV, evidence: [ev], assets: [assetFor(c.key)], amountAtRiskCents: next ? (next.netC != null ? next.netC : next.grossC || 0) : 0,
        });
      }
      if (selfBy === false) { byOther.push(ev); byOtherKeys.add(c.key); }
      if (selfBy === true && privileged) selfAdmin.push(ev);
      if (routingValid === false) {
        flag(c.key, "invalid routing number", "high", []);
        badRouting.push({ ...ev, routing: c.routing, reason: routingReason });
      }
    });
    if (!colInfo.bank.some((c) => c.changedBy)) skipped.push({ check: "bank_change_by_other", reason: "bank change log has no changed-by column" });
    if (byOther.length) {
      for (const x of byOtherKeys) flag(x, "bank change by someone else", "medium", []);
      push({
        id: "bank-changed-by-other", title: "Direct deposit changed by someone other than the employee", severity: "medium", confidence: "review", category: "payroll-diversion",
        description: byOther.length + " deposit change(s) were made by a person other than the employee. Legitimate when HR / payroll keys a signed form; it is also how a help-desk social-engineering or insider redirect looks.",
        recommendation: "Match each change to a signed request and an out-of-band callback record.", controls: [AC5, T1078, COSO12, SOX],
        evidence: byOther, assets: [...new Set(byOther.map((x) => x.employee))].map((n) => ({ type: "IDENTITY", name: n })),
      });
    }
    if (selfAdmin.length) {
      push({
        id: "bank-own-record-admin", title: "Administrator changed their own direct deposit", severity: "medium", confidence: "likely", category: "separation-of-duties",
        description: selfAdmin.length + " change(s) were made through an admin / help-desk channel by the employee whose record changed. Using privileged access on one's own pay record defeats separation of duties.",
        recommendation: "Route own-record changes through self-service or a second administrator; review the change and the following deposits.", controls: [AC5, COSO10, SOX],
        evidence: selfAdmin, assets: [...new Set(selfAdmin.map((x) => x.employee))].map((n) => ({ type: "IDENTITY", name: n })),
      });
    }
    if (badRouting.length) {
      push({
        id: "bank-invalid-routing", title: "Bank change to an invalid routing number", severity: "high", confidence: "likely", category: "payroll-diversion",
        description: badRouting.length + " change(s) use a routing number that fails the ABA 3-7-1 checksum (or an IBAN that fails mod-97). Such a deposit is returned at best; at worst the number was mistyped by someone who did not have the employee's real details.",
        recommendation: "Reject the change and confirm the account with the employee out of band.", controls: [COSO10, SOX, T1078],
        evidence: badRouting, assets: [...new Set(badRouting.map((x) => x.employee))].map((n) => ({ type: "IDENTITY", name: n })),
      });
    }
    // Campaigns: distinct employees changing to the same routing number inside the window.
    const byRouting = new Map();
    for (const b of bankRows) if (b.routing && b._day != null) { if (!byRouting.has(b.routing)) byRouting.set(b.routing, []); byRouting.get(b.routing).push(b); }
    for (const [rt, list] of [...byRouting].sort((a, b) => cmp(a[0], b[0]))) {
      list.sort((a, b) => a._day - b._day || a._ci - b._ci);
      let best = null;
      for (let i = 0, j = 0; j < list.length; j++) {
        while (list[j]._day - list[i]._day > o.campaignWindowDays) i++;
        const win = list.slice(i, j + 1), n = new Set(win.map((x) => x._key)).size;
        if (!best || n > best.n) best = { n, win };
      }
      if (best && best.n >= o.campaignMin) {
        const keys = [...new Set(best.win.map((x) => x._key))].sort();
        for (const k of keys) flag(k, "bank change campaign", "critical", best.win.filter((x) => x._key === k && x._next).map((x) => x._next));
        for (const b of best.win) if (!b.flags.includes("campaign")) b.flags.push("campaign");
        const atRisk = best.win.reduce((s, b) => s + (b._next ? (b._next.netC != null ? b._next.netC : b._next.grossC || 0) : 0), 0);
        push({
          id: "diversion-campaign:" + rt, title: best.n + " employees changed deposits to the same routing number within " + o.campaignWindowDays + " days", severity: "critical", confidence: "likely", category: "payroll-diversion",
          description: best.n + " distinct employees switched their direct deposit to accounts at routing " + rt + " between " + dayIso(best.win[0]._day) + " and " + dayIso(best.win[best.win.length - 1]._day) +
            ". Pattern consistent with a payroll-diversion campaign (credential phishing of several employees, then deposit changes to one receiving bank). Large retail banks can produce coincidental clusters in big workforces.",
          recommendation: "Freeze these deposit changes, reset the affected employees' credentials and MFA, call each employee out of band, and notify the receiving bank.",
          controls: [T1566, T1534, T1078, COSO10, SOX], evidence: best.win.map((b) => ({ employee: b.employee, changed_at: b.changed_at, channel: b.channel, ip: b.ip, new_account: b.new_account, routing: b.routing, next_pay_date: b.next_pay_date })),
          assets: keys.map(assetFor), amountAtRiskCents: atRisk,
        });
      }
    }
  }

  // =============================== Pay spikes / falsified wages ===============
  const WAGES = [ACFE("Falsified Wages"), COSO10];
  if (has.register) {
    let eligible = 0;
    for (const key of [...emps.keys()].sort()) {
      const e = emps.get(key);
      const rows = e.rows.filter((r) => r.grossC != null && r.grossC > 0);
      if (rows.length < o.minPeriods) continue;
      eligible++;
      const xs = rows.map((r) => r.grossC);
      const med = median(xs), mad = median(xs.map((x) => Math.abs(x - med)));
      if (!mad) continue;
      const hits = rows.map((r) => ({ r, z: (0.6745 * (r.grossC - med)) / mad })).filter((h) => h.z > o.spikeZ && h.r.grossC > med * (1 + o.spikeMinPct / 100));
      if (!hits.length) continue;
      flag(key, "pay spike", "medium", hits.map((h) => h.r));
      const commission = hits.some((h) => BONUS_RE.test(h.r.ptype));
      push({
        id: "pay-spike:" + key, title: "Pay spike against the employee's own history", severity: "medium", confidence: "review", category: "falsified-wages",
        description: label(e) + ": " + hits.length + " period(s) above robust z " + o.spikeZ + " and at least " + o.spikeMinPct + "% over the median (median gross " + money(Math.round(med)) + ", n = " + rows.length + " periods). Bonuses and commissions cause legitimate spikes; inflated hours or rates look the same.",
        recommendation: "Match each spike to an approved bonus, commission statement, overtime approval or rate change.",
        controls: commission ? [ACFE("Commission Schemes"), ...WAGES] : WAGES,
        evidence: hits.map((h) => payEv(h.r, { robust_z: round2(h.z), median_gross: money(Math.round(med)) })), assets: [assetFor(key)],
        amountAtRiskCents: hits.reduce((s, h) => s + h.r.grossC - Math.round(med), 0),
      });
    }
    if (!eligible) skipped.push({ check: "pay_spike", reason: "no employee has " + o.minPeriods + " or more pay periods (minimum sample for the robust z-score)" });

    // Salaried gross above salary / periods-per-year
    if (has.roster) {
      if (!anyCol("roster", "salary")) skipped.push({ check: "salary_change", reason: "roster has no salary column" });
      else {
        for (const key of [...emps.keys()].sort()) {
          const e = emps.get(key);
          if (!e.p || e.p.payType !== "salary" || !(e.p.salaryC > 0)) continue;
          const hits = [];
          for (const r of e.rows) {
            if (r.grossC == null || BONUS_RE.test(r.ptype)) continue;
            const ppy = periodsPerYear(periodDays(r));
            if (!ppy) continue;
            const expected = Math.round(e.p.salaryC / ppy);
            if (r.grossC > expected * (1 + o.salaryTolerancePct / 100)) hits.push({ r, expected });
          }
          if (!hits.length) continue;
          flag(key, "salaried pay above salary", "medium", hits.map((h) => h.r));
          push({
            id: "salary-change:" + key, title: "Salaried pay above the roster salary", severity: "medium", confidence: "review", category: "falsified-wages",
            description: label(e) + " is salaried at " + money(e.p.salaryC) + " a year on the roster, but " + hits.length + " regular period(s) paid more than salary / periods-per-year + " + o.salaryTolerancePct + "%. A pay change not reflected in HR, or an unapproved rate change.",
            recommendation: "Match the pay rate in payroll to an approved HR compensation change.", controls: WAGES,
            evidence: hits.map((h) => payEv(h.r, { expected_gross: money(h.expected) })), assets: [assetFor(key)],
            amountAtRiskCents: hits.reduce((s, h) => s + h.r.grossC - h.expected, 0),
          });
        }
      }
    }

    // Overtime outliers and implausible hours
    if (!anyCol("register", "otHours")) skipped.push({ check: "overtime_outlier", reason: "register has no overtime hours column" });
    const hoursKnown = anyCol("register", "regHours", "otHours", "hours");
    if (!hoursKnown) skipped.push({ check: "implausible_hours", reason: "register has no hours columns" });
    const otList = [];
    const shareByDept = new Map();
    for (const key of [...emps.keys()].sort()) {
      const e = emps.get(key);
      let ot = 0, tot = 0;
      for (const r of e.rows) {
        const weeks = periodDays(r) / 7;
        const reasons = [];
        if (r.otH != null && r.otH / weeks > o.maxOvertime) reasons.push(round2(r.otH / weeks) + " OT h/week > " + o.maxOvertime);
        if (r.hours != null && r.hours / weeks > o.maxWeeklyHours) reasons.push(round2(r.hours / weeks) + " total h/week > " + o.maxWeeklyHours);
        if (reasons.length) otList.push({ key, r, reasons });
        if (r.otH != null) ot += r.otH;
        if (r.hours != null) tot += r.hours;
      }
      if (tot > 0 && e.department) { if (!shareByDept.has(e.department)) shareByDept.set(e.department, []); shareByDept.get(e.department).push({ key, share: ot / tot }); }
    }
    for (const [dept, list] of [...shareByDept].sort((a, b) => cmp(a[0], b[0]))) {
      if (list.length < 4) continue;
      for (const x of list) {
        const med = median(list.filter((y) => y !== x).map((y) => y.share));
        if (x.share >= 0.2 && x.share >= o.otShareMultiple * med) {
          const e = emps.get(x.key);
          otList.push({ key: x.key, r: null, reasons: ["OT share " + Math.round(x.share * 100) + "% vs " + dept + " median " + Math.round(med * 100) + "%"], share: true, rows: e.rows.filter((r) => (r.otH || 0) > 0) });
        }
      }
    }
    if (otList.length) {
      const keys = [...new Set(otList.map((x) => x.key))].sort();
      for (const k of keys) flag(k, "overtime outlier", "medium", otList.filter((x) => x.key === k).flatMap((x) => (x.r ? [x.r] : x.rows)));
      push({
        id: "overtime-outlier", title: "Overtime or hours outside plausible limits", severity: "medium", confidence: "review", category: "falsified-wages",
        description: keys.length + " employee(s) with overtime above " + o.maxOvertime + " h per week-equivalent, total paid hours above " + o.maxWeeklyHours + " h per week, or an overtime share at least " + o.otShareMultiple + "x the department median (departments with 4+ people). Peak seasons explain some of this; falsified hours look the same.",
        recommendation: "Match the overtime to approved timesheets and to the approver; confirm the hours with the supervisor.", controls: WAGES,
        evidence: otList.sort((a, b) => cmp(a.key, b.key)).map((x) => (x.r ? payEv(x.r, { reason: x.reasons.join("; "), weeks_in_period: round2(periodDays(x.r) / 7) }) : { employee: labelFor(x.key), reason: x.reasons.join("; ") })),
        assets: keys.map(assetFor), amountAtRiskCents: otList.reduce((s, x) => s + (x.r && x.r.otEarnC ? x.r.otEarnC : 0), 0),
      });
    }

    // Pay without hours (hourly), paid hours above approved timesheet hours
    const noHours = [];
    if (!hoursKnown) skipped.push({ check: "pay_without_hours", reason: "register has no hours columns" });
    else {
      for (const key of [...emps.keys()].sort()) {
        const e = emps.get(key);
        const hourly = e.p && e.p.payType ? e.p.payType === "hourly" : e.rows.some((r) => (r.hours || 0) > 0);
        if (!hourly) continue;
        for (const r of e.rows) if ((r.grossC || 0) > 0 && !BONUS_RE.test(r.ptype) && !(r.hours > 0)) noHours.push({ key, r, reason: "hourly pay with " + (r.hours == null ? "no" : "0") + " hours" });
      }
    }
    if (!has.timesheet) skipped.push({ check: "timesheet_reconciliation", reason: "no timesheets loaded (optional input)" });
    else if (!anyCol("register", "periodStart") || !anyCol("register", "periodEnd")) skipped.push({ check: "timesheet_reconciliation", reason: "register has no period start / end dates" });
    else if (!hoursKnown) skipped.push({ check: "timesheet_reconciliation", reason: "register has no hours columns" });
    else {
      const tsBy = new Map();
      for (const t of sheets) { if (!tsBy.has(t.key)) tsBy.set(t.key, []); tsBy.get(t.key).push(t); }
      for (const key of [...emps.keys()].sort()) {
        const list = tsBy.get(key);
        if (!list) continue;
        for (const r of emps.get(key).rows) {
          if (r.pStart == null || r.pEnd == null || !(r.hours > 0)) continue;
          const approved = list.filter((t) => t.day != null && t.day >= r.pStart && t.day <= r.pEnd && t.approvedBy).reduce((s, t) => s + t.hours, 0);
          if (r.hours > approved + o.hoursTolerance) noHours.push({ key, r, reason: "paid " + r.hours + " h vs " + round2(approved) + " approved timesheet h", approved: round2(approved) });
        }
      }
    }
    if (noHours.length) {
      const keys = [...new Set(noHours.map((x) => x.key))].sort();
      for (const k of keys) flag(k, "pay without supporting hours", "medium", noHours.filter((x) => x.key === k).map((x) => x.r));
      push({
        id: "pay-without-hours", title: "Pay without supporting hours", severity: "medium", confidence: "review", category: "falsified-wages",
        description: noHours.length + " payment(s) to " + keys.length + " employee(s): hourly pay with no hours recorded, or paid hours above the approved timesheet hours for the period (tolerance " + o.hoursTolerance + " h).",
        recommendation: "Obtain the approved timesheet for each period; recover pay for unsupported hours.", controls: WAGES,
        evidence: noHours.map((x) => payEv(x.r, { reason: x.reason })), assets: keys.map(assetFor), amountAtRiskCents: netOf(noHours.map((x) => x.r)),
      });
    }

    // Duplicate pay: overlapping periods (or same pay date + same gross without periods)
    const dupEv = []; let dupKeys = new Set(), dupExact = true;
    for (const key of [...emps.keys()].sort()) {
      const rows = emps.get(key).rows.filter((r) => (r.grossC || 0) > 0 && !BONUS_RE.test(r.ptype));
      for (let i = 0; i < rows.length; i++) for (let j = i + 1; j < rows.length; j++) {
        const a = rows[i], b = rows[j];
        let dup = false, exact = false;
        if (a.pStart != null && a.pEnd != null && b.pStart != null && b.pEnd != null) { dup = a.pStart <= b.pEnd && b.pStart <= a.pEnd; exact = dup && a.pStart === b.pStart && a.pEnd === b.pEnd && a.grossC === b.grossC; }
        else if (a.payDay != null && a.payDay === b.payDay && a.grossC === b.grossC) { dup = true; exact = true; }
        if (!dup) continue;
        if (!exact) dupExact = false;
        dupKeys.add(key);
        flag(key, "duplicate pay", "high", [b]);
        dupEv.push(payEv(a, { pair: "first" }), payEv(b, { pair: exact ? "duplicate (identical period and gross)" : "overlapping period" }));
      }
    }
    if (dupKeys.size) {
      const keys = [...dupKeys].sort();
      push({
        id: "duplicate-pay", title: "Employee paid twice for overlapping periods", severity: "high", confidence: dupExact ? "likely" : "review", category: "falsified-wages",
        description: keys.length + " employee(s) have regular payments whose pay periods overlap (bonus, commission and off-cycle runs excluded). Corrections and manual checks cause some; others are duplicate disbursements.",
        recommendation: "Confirm whether the second payment replaced a voided check; recover duplicates.", controls: WAGES,
        evidence: dupEv, assets: keys.map(assetFor), amountAtRiskCents: dupEv.filter((x) => x.pair !== "first").reduce((s, x) => s + (toCents(x.net) || toCents(x.gross) || 0), 0),
      });
    }
  }

  // Self-approval (timesheets)
  if (has.timesheet) {
    if (!colInfo.timesheet.some((c) => c.approvedBy)) skipped.push({ check: "self_approval", reason: "timesheets have no approved-by column" });
    else {
      const ev = [], keys = new Set();
      const tokenOwner = new Map();
      for (const p of people.values()) {
        for (const t of [alnum(p.id), alnum(p.idRaw), normName(p.name), alnum(p.email), alnum(p.email.split("@")[0])]) if (t && !tokenOwner.has(t)) tokenOwner.set(t, p.id);
      }
      for (const t of sheets) {
        const a = alnum(t.approvedBy);
        if (!a) continue;
        const selfTokens = new Set([alnum(t.key), alnum(t.idRaw), normName(t.name)]);
        const p = people.get(t.key);
        if (p) { selfTokens.add(normName(p.name)); selfTokens.add(alnum(p.email)); selfTokens.add(alnum(p.email.split("@")[0])); }
        selfTokens.delete("");
        let reason = "";
        if (selfTokens.has(a)) reason = "approved own timesheet";
        else {
          const approver = tokenOwner.get(a);
          const ap = approver ? people.get(approver) : null;
          if (ap && ap.managerId && ap.managerId === t.key) reason = "approved by a direct report (" + ap.name + ")";
        }
        if (!reason) continue;
        keys.add(t.key);
        ev.push({ file: t.file, row: t.row, employee: labelFor(t.key), date: dayIso(t.day), hours: t.hours, approved_by: t.approvedBy, project: t.project, reason });
      }
      if (ev.length) {
        const ks = [...keys].sort();
        for (const k of ks) flag(k, "self-approved time", "medium", []);
        push({
          id: "self-approval", title: "Timesheets approved by the employee or a subordinate", severity: "medium", confidence: "likely", category: "separation-of-duties",
          description: ev.length + " timesheet entr(ies) for " + ks.length + " employee(s) were approved by the employee or by someone who reports to them.",
          recommendation: "Route approval to the employee's own manager; re-approve the affected periods.", controls: [AC5, ACFE("Falsified Wages"), COSO10, SOX],
          evidence: ev, assets: ks.map(assetFor),
        });
      }
    }
  }

  // =============================== Tables =================================
  const sevOf = (e) => { let best = "none"; for (const s of e.flags.values()) if (best === "none" || SEV_RANK[s] > SEV_RANK[best]) best = s; return best; };
  const employees = [...emps.values()].map((e) => {
    const p = e.p;
    const mgr = p && p.managerId ? (people.get(p.managerId) ? people.get(p.managerId).name : p.managerId) : "";
    const risk = [...e.riskRows].map((i) => pay[i]);
    return {
      employee: labelFor(e.key), id: e.p ? e.p.idRaw : e.rows[0] ? e.rows[0].idRaw : e.key, name: e.name, department: e.department || "", manager: mgr,
      status: p ? (p.terminated ? "terminated" + (p.term != null ? " " + dayIso(p.term) : "") : p.status || "active") : "not on roster",
      payType: p ? p.payType || p.payTypeRaw : "", periods: e.rows.length,
      grossCents: e.rows.reduce((s, r) => s + (r.grossC || 0), 0), netCents: e.rows.reduce((s, r) => s + (r.netC || 0), 0),
      flags: [...e.flags.keys()].sort(), risk: sevOf(e), amountAtRiskCents: netOf(risk), _key: e.key,
    };
  }).filter((x) => x.periods > 0 || x.flags.length)
    .sort((a, b) => (SEV_RANK[b.risk] ?? -1) - (SEV_RANK[a.risk] ?? -1) || b.amountAtRiskCents - a.amountAtRiskCents || cmp(a.employee, b.employee));
  const empByKey = new Map(employees.map((x) => [x._key, x]));
  const periods = new Map();
  for (const r of pay) {
    if (r.payDay == null) continue;
    let pr = periods.get(r.payDay);
    if (!pr) { pr = { payDate: dayIso(r.payDay), emps: new Set(), flagged: new Set(), grossCents: 0, netCents: 0, payments: 0 }; periods.set(r.payDay, pr); }
    pr.emps.add(r.key); pr.payments++; pr.grossCents += r.grossC || 0; pr.netCents += r.netC || 0;
    const e = emps.get(r.key); if (e && e.riskRows.has(r.idx)) pr.flagged.add(r.key);
  }
  const periodRows = [...periods.entries()].sort((a, b) => a[0] - b[0]).map(([, p]) => ({ payDate: p.payDate, headcount: p.emps.size, payments: p.payments, grossCents: p.grossCents, netCents: p.netCents, flaggedEmployees: p.flagged.size }));
  const bankTable = bankRows.map(({ _key, _ci, _next, _day, ...rest }) => rest);

  // Finalize assets: IDENTITY data = department, flags, amount at risk (never SSN / account).
  for (const f of findings) {
    f.assets = f.assets.map((a) => {
      const key = a._key || [...empByKey.keys()].find((k) => empByKey.get(k).employee === a.name);
      const x = key ? empByKey.get(key) : null;
      return { type: "IDENTITY", name: a.name, data: { department: x ? x.department : "", flags: x ? x.flags : [], amountAtRisk: x ? formatCents(x.amountAtRiskCents) : "" } };
    });
  }
  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(a.category, b.category) || cmp(a.title, b.title) || cmp(a.id, b.id));
  for (const x of employees) delete x._key;

  ctx?.progress?.(counter.total, counter.total, "done");
  const ghostFlags = ["not on roster", "paid after termination", "paid before hire", "ghost indicators"];
  const currencies = [...new Set(pay.map((r) => r.currency).filter(Boolean))].sort();
  const bySeverity = {}; for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  const summary = {
    employeesPaid: [...emps.values()].filter((e) => e.rows.length).length, payments: pay.length, rosterEmployees: people.size,
    grossCents: pay.reduce((s, r) => s + (r.grossC || 0), 0), netCents: pay.reduce((s, r) => s + (r.netC || 0), 0),
    currency: currencies.length === 1 ? currencies[0] : currencies.length ? "mixed: " + currencies.join(", ") : "",
    ghostCandidates: employees.filter((x) => x.flags.some((f) => ghostFlags.includes(f))).length,
    sharedBankAccounts: shared.filter((s) => s.type === "bank").length,
    bankChanges: bankTable.length, bankChangesBeforePayday: bankTable.filter((b) => b.flags.includes("before payday")).length,
    flaggedEmployees: employees.filter((x) => x.flags.length).length,
    amountAtRiskCents: employees.reduce((s, x) => s + x.amountAtRiskCents, 0),
    payDates: periodRows.length, findings: findings.length, bySeverity,
  };
  return {
    summary, findings,
    tables: { employees, bankChanges: bankTable, shared, periods: periodRows },
    skipped,
    meta: { tool: TOOL_ID, version: VERSION, rows: total, now: dayIso(nowDay), files: metaFiles, options: o },
  };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
const q = (v) => {
  let s = String(v ?? "");
  if (/^[=+@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
};
const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "evidenceCount", "amountAtRisk", "assets"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const body = (findings || []).map((f) => [
    f.severity, f.confidence, f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), f.evidenceCount ?? (f.evidence || []).length,
    formatCents(f.amountAtRiskCents || 0), (f.assets || []).map((a) => a.name).join("; "),
  ].map(q).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n");
}

const NEXT_STEP = [
  ["bank change campaign", "Freeze the deposit changes, reset credentials and MFA, call each employee out of band"],
  ["bank change before payday", "Call the employee on the HR-file number before releasing pay; revert if unconfirmed"],
  ["terminated employee's account reused", "Confirm account ownership with the bank; review all deposits to it"],
  ["not on roster", "Confirm the person exists in HR (I-9, badge, manager); hold pay until confirmed"],
  ["paid after termination", "Stop pay; confirm termination processing; trace deposits"],
  ["paid before hire", "Confirm hire date; recover pre-employment pay"],
  ["ghost indicators", "Verify identity physically and trace deposits"],
  ["shared bank", "Confirm account ownership with each employee"],
  ["shared ssn", "Verify both identities through SSA SSNVS"],
  ["duplicate pay", "Confirm whether a check was voided; recover duplicates"],
  ["invalid routing number", "Reject the change; confirm the account out of band"],
  ["pay spike", "Match to approved bonus, commission or rate change"],
  ["salaried pay above salary", "Match the pay rate to an approved HR compensation change"],
  ["overtime outlier", "Match overtime to approved timesheets"],
  ["pay without supporting hours", "Obtain approved timesheets; recover unsupported pay"],
  ["self-approved time", "Re-approve through the employee's own manager"],
  ["bank change by someone else", "Match the change to a signed request and callback record"],
];

/** Investigation worklist: one row per flagged employee. */
export function worklistCsv(result) {
  const head = ["employee", "department", "manager", "status", "risk", "reason", "amount_at_risk", "next_step"];
  const rows = ((result && result.tables && result.tables.employees) || []).filter((e) => e.flags.length).map((e) => {
    const step = (NEXT_STEP.find(([f]) => e.flags.includes(f)) || [null, "Review the flagged items with HR and the manager"])[1];
    return [e.employee, e.department, e.manager, e.status, e.risk, e.flags.join("; "), formatCents(e.amountAtRiskCents), step].map(q).join(",");
  });
  return [head.join(","), ...rows].join("\n");
}

/** Bank-change review: every change with days-to-payday and flags (accounts last 4 only). */
export function bankChangesCsv(result) {
  const head = ["employee", "changed_at", "changed_by", "channel", "ip", "old_account", "new_account", "routing", "routing_valid", "next_pay_date", "days_to_payday", "paid_to_new_account", "next_net", "flags"];
  const rows = ((result && result.tables && result.tables.bankChanges) || []).map((b) => head.map((h) => (h === "flags" ? b.flags.join("; ") : b[h] == null ? "" : b[h])).map(q).join(","));
  return [head.join(","), ...rows].join("\n");
}

/** Plain-text summary. */
export function summaryText(result) {
  const r = result || {}, s = r.summary || {};
  const cur = s.currency ? " " + s.currency : "";
  return [
    "Payroll Integrity - summary (screening results, not findings of fact)",
    "As of: " + ((r.meta && r.meta.now) || "n/a"),
    "Files: " + ((r.meta && r.meta.files) || []).map((f) => f.name + " [" + f.kind + ", " + f.vendor + "]").join(", "),
    "Employees paid: " + s.employeesPaid + "  Payments: " + s.payments + "  Pay dates: " + s.payDates,
    "Gross: " + formatCents(s.grossCents) + cur + "  Net: " + formatCents(s.netCents) + cur,
    "Ghost candidates: " + s.ghostCandidates + "  Shared bank accounts: " + s.sharedBankAccounts + "  Bank changes before payday: " + s.bankChangesBeforePayday + " of " + s.bankChanges,
    "Flagged employees: " + s.flaggedEmployees + "  Net pay on flagged rows: " + formatCents(s.amountAtRiskCents) + cur,
    "Findings: " + s.findings + "  by severity: " + JSON.stringify(s.bySeverity || {}), "",
    ...(r.findings || []).map((f) => "- [" + f.severity + " / " + f.confidence + "] " + f.title + " (" + f.evidenceCount + " evidence) - " + f.recommendation),
    "", (r.skipped || []).length ? "Skipped checks: " + r.skipped.map((x) => x.check + " (" + x.reason + ")").join("; ") : "All checks ran.",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Synthetic example (Gusto journal + HR roster + bank-change log)
// ---------------------------------------------------------------------------
function abaWithCheck(prefix8) {
  const d = prefix8.split("").map(Number);
  const s = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5]);
  return prefix8 + String((10 - (s % 10)) % 10);
}

/** Seeded SYNTHETIC dataset (fictional company, people at test.darknode.ai, SSNs in the never-issued 9xx area). */
export function exampleDataset(seed = 7) {
  let s = seed >>> 0;
  const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const D = "@test.darknode.ai";
  const people = [
    ["E1001", "Ines Marlow", "Finance", "", "salary", 96000, 0],
    ["E1002", "Theo Brandt", "Operations", "E1001", "salary", 78000, 0],
    ["E1003", "Callum Reyes", "Warehouse", "E1002", "hourly", 0, 24.5],
    ["E1004", "Priya Okonkwo", "Sales", "E1002", "salary", 72000, 0],
    ["E1005", "Mateo Lindgren", "Warehouse", "E1002", "hourly", 0, 22],
    ["E1006", "Sana Whitcombe", "Warehouse", "E1002", "hourly", 0, 22],
    ["E1007", "Dara Feld", "Finance", "E1001", "salary", 61000, 0],
    ["E1008", "Ruth Achebe", "Sales", "E1002", "salary", 70000, 0],
    ["E1009", "Owen Pascoe", "Operations", "E1002", "salary", 66000, 0],
    ["E1010", "Lena Voss", "Warehouse", "E1002", "hourly", 0, 23],
    ["E1011", "Kofi Marsh", "Operations", "E1002", "hourly", 0, 25],
    ["E1012", "Yara Quint", "Finance", "E1001", "salary", 84000, 0],
  ];
  const termDay = parseDay("2026-08-14");
  const firstStart = parseDay("2026-05-31");
  const P = 8;
  const csvLine = (a) => a.map((v) => { const t = String(v); return /[",\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; }).join(",");
  const f2 = (c) => (c / 100).toFixed(2);

  // Roster
  const roster = [["employee_id", "name", "ssn_or_national_id", "date_of_birth", "address", "city", "postal_code", "phone", "email", "department", "manager_id", "hire_date", "termination_date", "status", "pay_type", "salary", "hourly_rate"]];
  const streets = ["Larch Way", "Copperfield Rd", "Ashby Lane", "Mill Pond Ct", "Heron St", "Quarry Row", "Tamsin Ave", "Old Ferry Rd", "Wren Close", "Saltmarsh Dr", "Kestrel Pl", "Bramble Hill"];
  people.forEach(([id, name, dept, mgr, type, sal, rate], i) => {
    const ssn = "9" + String(10 + Math.floor(rnd() * 89)) + "-" + String(10 + Math.floor(rnd() * 89)) + "-" + String(1000 + Math.floor(rnd() * 8999));
    const email = name.toLowerCase().replace(/\s+/g, ".") + D;
    roster.push([id, name, ssn, "19" + (70 + i) + "-0" + (1 + (i % 9)) + "-1" + (i % 9), (10 + i * 7) + " " + streets[i], "Harrow Point", "0" + (2100 + i), "555-01" + String(10 + i), email, dept, mgr,
      "20" + (18 + (i % 6)) + "-0" + (1 + (i % 8)) + "-15", id === "E1009" ? dayIso(termDay) : "", id === "E1009" ? "Terminated" : "Active", type === "salary" ? "Salaried" : "Hourly", sal ? sal.toFixed(2) : "", rate ? rate.toFixed(2) : ""]);
  });

  // Gusto payroll journal
  const journal = [["Pay Period Start", "Pay Period End", "Check Date", "Employee", "Employee ID", "Gross Earnings", "Employee Taxes", "Employee Deductions", "Net Pay", "Employer Taxes", "Payment Method", "Regular Hours", "Overtime Hours"]];
  const payDays = [];
  for (let k = 0; k < P; k++) {
    const ps = firstStart + 14 * k, pe = ps + 13, cd = pe + 5;
    payDays.push(cd);
    const line = (name, id, grossC, regH, otH, noTax) => {
      const tax = noTax ? 0 : Math.round(grossC * 0.214), ded = noTax ? 0 : regH ? 4500 : 15000;
      journal.push([dayIso(ps), dayIso(pe), dayIso(cd), name, id, f2(grossC), f2(tax), f2(ded), f2(grossC - tax - ded), f2(Math.round(grossC * 0.0765)), "Direct Deposit", regH ? regH.toFixed(2) : "", otH ? otH.toFixed(2) : regH ? "0.00" : ""]);
    };
    for (const [id, name, , , type, sal, rate] of people) {
      if (type === "salary") line(name, id, Math.round((sal * 100) / 26), 0, 0);
      else {
        const regH = 76 + Math.floor(rnd() * 5);
        const otH = id === "E1010" && k === 6 ? 62 : Math.floor(rnd() * 4);
        line(name, id, Math.round(regH * rate * 100 + otH * rate * 150), regH, otH);
      }
    }
    if (k >= 4) line("Jordan Vale", "E1099", 245000, 0, 0, true); // paid id that is not on the roster
  }

  // Direct-deposit change log
  const R1 = abaWithCheck("07100001"), R2 = abaWithCheck("12400008"), R3 = abaWithCheck("03100004");
  const at = (day, hm) => dayIso(day) + "T" + hm + ":00Z";
  const bank = [["employee_id", "changed_at", "changed_by", "old_account_last4", "new_account", "new_routing", "channel", "ip"]];
  bank.push(["E1007", at(payDays[0] + 3, "16:12"), "dara.feld" + D, "4410", "550018273641", R3, "self-service", "198.51.100.23"]);
  bank.push(["E1003", at(payDays[1] + 4, "10:41"), "dara.feld" + D, "7782", "550018273641", R3, "admin", "198.51.100.23"]); // shares E1007's account
  bank.push(["E1004", at(payDays[6] - 2, "18:55"), "helpdesk.t2" + D, "2291", "880044119275", R1, "helpdesk", "192.0.2.144"]);
  bank.push(["E1005", at(payDays[7] - 4, "02:17"), "mateo.lindgren" + D, "6130", "740000918822", R2, "self-service", "203.0.113.77"]);
  bank.push(["E1006", at(payDays[7] - 4, "02:31"), "sana.whitcombe" + D, "0457", "740000918839", R2, "self-service", "203.0.113.77"]);
  bank.push(["E1008", at(payDays[7] - 3, "03:05"), "ruth.achebe" + D, "9924", "740000918846", R2, "self-service", "203.0.113.77"]);
  bank.push(["E1012", at(payDays[2] + 2, "09:30"), "yara.quint" + D, "3307", "660021004719", R3, "self-service", "198.51.100.61"]);

  return {
    label: "synthetic example (not real data)",
    files: [
      { name: "gusto-payroll-journal.csv", text: journal.map(csvLine).join("\n") },
      { name: "hr-roster.csv", text: roster.map(csvLine).join("\n") },
      { name: "direct-deposit-changes.csv", text: bank.map(csvLine).join("\n") },
    ],
  };
}

/** Deterministic self-check of the engine's core rules. */
export function selfTest() {
  const tests = [];
  const t = (name, fn) => { let pass = false; try { pass = !!fn(); } catch (_) { pass = false; } tests.push({ name, pass }); };
  t("toCents parses currency, separators and parentheses", () => toCents("$1,234.56") === 123456 && toCents("(12.50)") === -1250 && toCents("") === null);
  t("SSN rules reject 000 / 666 / 9xx / group 00 / serial 0000", () => ["000-12-3456", "666-12-3456", "912-34-5678", "123-00-4567", "123-45-0000"].every((x) => ssnCheck(x).valid === false) && ssnCheck("212-34-5678").valid === true);
  t("accountInfo masks to last 4", () => { const a = accountInfo("123456789012", "021000021"); return a.label === "acct ****9012 / RTN 021000021" && !a.label.includes("12345678"); });
  const ex = exampleDataset();
  const parsed = parseInput(ex.files);
  t("example files classify as register / roster / bank", () => parsed.files.map((f) => f.kind).join() === "register,roster,bank");
  const r = analyze(parsed);
  const ids = r.findings.map((f) => f.id || "");
  t("example: paid id not on roster", () => ids.some((i) => i.startsWith("ghost-not-on-roster:e1099")));
  t("example: terminated employee paid", () => ids.some((i) => i.startsWith("ghost-after-term:e1009")));
  t("example: shared bank account", () => r.summary.sharedBankAccounts === 1);
  t("example: helpdesk change before payday is critical", () => r.findings.some((f) => f.id.startsWith("diversion:e1004") && f.severity === "critical"));
  t("example: routing campaign", () => ids.some((i) => i.startsWith("diversion-campaign:")));
  t("example: overtime outlier", () => ids.includes("overtime-outlier"));
  t("no full SSN in output", () => !/9\d\d-\d\d-\d{4}/.test(JSON.stringify(r)));
  t("deterministic", () => JSON.stringify(analyze(parsed)) === JSON.stringify(r));
  return { pass: tests.every((x) => x.pass), tests };
}
