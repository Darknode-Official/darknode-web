// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Card Audit engine (cardaudit). Screens corporate card transactions and expense report
// lines for the ACFE expense-reimbursement and card-misuse patterns so finance can review:
// split transactions, duplicate receipts / multiple reimbursements, prohibited and review
// MCCs, weekend and federal-holiday spend, spend after termination or before hire,
// self-approval and approvers who report to the submitter, policy limit breaches, missing
// receipts, round-number bias, monthly velocity spikes, gift-card / cash-like purchases and
// personal-use patterns.
//
// Pure ESM: no DOM, no network, no clock. Deterministic: the same input gives byte-identical
// JSON. Runs inside a Blob module Worker and in node tests. Amounts are integer minor units
// (cents) and are never converted between currencies. Card numbers are reduced to the last
// four digits at parse time; raw rows are never kept.
//
//   parseInput(text | {name,text,role?,columns?}[])   -> { format, confidence, headers, rows, skipped, files }
//   analyze(dataset, opts, ctx?)                       -> { summary, findings, tables, skipped, meta }

import { iterCsv, iterJson, normHeader, findColumn } from "../ingest/parse.js";

export const TOOL_ID = "cardaudit";
export const VERSION = "1.0.0";

// ---------------------------------------------------------------------------
// Column aliases and vendor layouts
// ---------------------------------------------------------------------------

/** Logical transaction columns -> accepted header names (generic mapping; alias order wins). */
export const COLUMNS = {
  date: ["date", "transaction date", "transaction time", "timestamp", "txn date", "purchase date", "trans date", "expense date"],
  employee: ["employee", "card holder", "cardholder", "card member", "user", "submitter", "employee name", "name", "spender"],
  employee_id: ["employee_id", "employee id", "emp id", "employee number", "worker id"],
  card_last4: ["card_last4", "card last four", "card last 4", "last4", "last four", "card", "account #", "card number"],
  merchant: ["merchant", "vendor", "merchant name", "payee", "description"],
  mcc: ["mcc", "merchant category code"],
  amount: ["amount", "original amount", "transaction amount", "total", "amount usd"],
  currency: ["currency", "original currency", "currency code"],
  receipt: ["receipt", "receipt status", "receipt received", "has receipt", "receipt attached"],
  approver: ["approver", "reviewer", "approved by"],
  report_id: ["report_id", "report id", "expense report id", "report"],
  category: ["category", "expense type", "accounting category", "expense category", "gl category"],
  memo: ["memo", "comment", "notes", "business purpose", "purpose", "description"],
  city: ["city", "merchant city", "city/state"],
  country: ["country", "merchant country", "country code"],
  reimbursable: ["reimbursable", "out of pocket", "is reimbursable"],
  payment_type: ["payment type", "payment method", "paid by"],
};

/** HR roster columns. */
export const ROSTER_COLUMNS = {
  employee_id: ["employee_id", "employee id", "worker id", "emp id", "id"],
  name: ["name", "full name", "employee name", "worker"],
  email: ["email", "work email", "email address", "mail"],
  department: ["department", "dept", "cost center"],
  title: ["title", "job title", "position"],
  manager_id: ["manager_id", "manager id", "manager employee id", "supervisor id", "manager"],
  hire_date: ["hire_date", "hire date", "start date", "original hire date"],
  termination_date: ["termination_date", "termination date", "term date", "separation date", "end date"],
  status: ["status", "employment status", "worker status"],
  city: ["city", "work city", "work location", "location", "office"],
};

/** Spend policy columns. */
export const POLICY_COLUMNS = {
  category: ["category", "expense type", "expense category"],
  limit_per_txn: ["limit_per_txn", "limit per txn", "per transaction limit", "transaction limit"],
  limit_per_day: ["limit_per_day", "limit per day", "daily limit", "per day limit"],
  currency: ["currency", "currency code"],
};

const ROLE_COLUMNS = { transactions: COLUMNS, roster: ROSTER_COLUMNS, policy: POLICY_COLUMNS };

/** Known layouts, matched by the exact header set the vendor exports. */
export const FORMATS = {
  amex: {
    label: "American Express card activity (CSV)", role: "transactions", kind: "card",
    headers: ["Date", "Description", "Card Member", "Account #", "Amount", "Extended Details", "Appears On Your Statement As", "Address", "City/State", "Zip Code", "Country", "Reference", "Category"],
    map: { date: "Date", merchant: "Description", employee: "Card Member", card_last4: "Account #", amount: "Amount", memo: "Extended Details", city: "City/State", country: "Country", category: "Category" },
  },
  brex: {
    label: "Brex card transactions (CSV)", role: "transactions", kind: "card",
    headers: ["Transaction Date", "Posted Date", "Description", "Amount", "Currency", "Card Holder", "Card Last Four", "Merchant Category", "MCC", "Receipt Status", "Memo", "Category", "Department"],
    map: { date: "Transaction Date", merchant: "Description", amount: "Amount", currency: "Currency", employee: "Card Holder", card_last4: "Card Last Four", mcc_label: "Merchant Category", mcc: "MCC", receipt: "Receipt Status", memo: "Memo", category: "Category", department: "Department" },
  },
  ramp: {
    label: "Ramp card transactions (CSV)", role: "transactions", kind: "card",
    headers: ["Transaction Time", "User", "Card", "Merchant", "Merchant Category Code", "Amount", "Currency", "Receipt", "Memo", "Accounting Category", "Department", "Location", "Reviewer", "Review Status"],
    map: { date: "Transaction Time", employee: "User", card_last4: "Card", merchant: "Merchant", mcc: "Merchant Category Code", amount: "Amount", currency: "Currency", receipt: "Receipt", memo: "Memo", category: "Accounting Category", department: "Department", approver: "Reviewer" },
  },
  expensify: {
    label: "Expensify expense export (CSV)", role: "transactions", kind: null,
    headers: ["Timestamp", "Merchant", "Amount", "MCC", "Category", "Tag", "Comment", "Reimbursable", "Original Currency", "Original Amount", "Receipt", "Report ID", "Report Name", "Submitter", "Approver"],
    map: { date: "Timestamp", merchant: "Merchant", amount_alt: "Amount", mcc: "MCC", category: "Category", memo: "Comment", reimbursable: "Reimbursable", currency: "Original Currency", amount: "Original Amount", receipt: "Receipt", report_id: "Report ID", report_name: "Report Name", employee: "Submitter", approver: "Approver" },
  },
  concur: {
    label: "SAP Concur expense report export (CSV)", role: "transactions", kind: null,
    headers: ["Report ID", "Report Name", "Employee", "Employee ID", "Expense Type", "Transaction Date", "Vendor", "City", "Country", "Payment Type", "Amount", "Currency", "Approved Amount", "Receipt Received", "Approver", "Approval Status", "Submit Date", "Policy"],
    map: { report_id: "Report ID", report_name: "Report Name", employee: "Employee", employee_id: "Employee ID", category: "Expense Type", date: "Transaction Date", merchant: "Vendor", city: "City", country: "Country", payment_type: "Payment Type", amount: "Amount", currency: "Currency", receipt: "Receipt Received", approver: "Approver" },
  },
  roster: {
    label: "HR roster (CSV)", role: "roster",
    headers: ["employee_id", "name", "email", "department", "title", "manager_id", "hire_date", "termination_date", "status"],
    map: { employee_id: "employee_id", name: "name", email: "email", department: "department", title: "title", manager_id: "manager_id", hire_date: "hire_date", termination_date: "termination_date", status: "status" },
  },
  policy: {
    label: "Spend policy limits (CSV)", role: "policy",
    headers: ["category", "limit_per_txn", "limit_per_day", "currency"],
    map: { category: "category", limit_per_txn: "limit_per_txn", limit_per_day: "limit_per_day", currency: "currency" },
  },
  generic: { label: "Generic card / expense CSV (mapped)", role: "transactions", kind: null },
  "generic-roster": { label: "Generic HR roster (mapped)", role: "roster" },
  "generic-policy": { label: "Generic policy table (mapped)", role: "policy" },
};

/**
 * Built-in REVIEW list (ISO 18245 merchant category codes, labels as in the Visa Merchant
 * Data Standards Manual). Spend here is not prohibited by default; it is surfaced for review.
 */
export const BUILTIN_MCC = [
  { mcc: "7995", label: "Betting, including lottery tickets, casino gaming chips, off-track betting and wagers at race tracks", severity: "medium" },
  { mcc: "7273", label: "Dating and escort services", severity: "medium" },
  { mcc: "7297", label: "Massage parlors", severity: "medium" },
  { mcc: "5967", label: "Direct marketing, inbound teleservices merchant (adult content)", severity: "medium" },
  { mcc: "5933", label: "Pawn shops", severity: "medium" },
  { mcc: "6051", label: "Quasi-cash: non-financial institutions, foreign currency, non-fiat currency (e.g. cryptocurrency), money orders, travelers cheques", severity: "medium" },
  { mcc: "6010", label: "Financial institutions, manual cash disbursements", severity: "medium" },
  { mcc: "6011", label: "Financial institutions, automated cash disbursements (ATM)", severity: "medium" },
  { mcc: "4829", label: "Wire transfers and money orders", severity: "medium" },
  { mcc: "5813", label: "Drinking places (alcoholic beverages): bars, taverns, nightclubs, cocktail lounges, discotheques", severity: "low" },
  { mcc: "5921", label: "Package stores: beer, wine and liquor", severity: "low" },
  { mcc: "5122", label: "Drugs, drug proprietaries and druggist sundries", severity: "info" },
  { mcc: "5912", label: "Drug stores and pharmacies", severity: "info" },
];

/** Tunable thresholds; the UI renders these with real labels. */
export const DEFAULTS = {
  cardTxnLimit: null, // single-transaction card limit in major units; blank = split check skipped
  splitHours: 24,
  receiptRequiredOver: 75,
  spikeZ: 3,
  minHistoryMonths: 4,
  spikeMinRatio: 2, // the month must also be at least this multiple of the median month
  roundMinTxns: 15,
  roundZ: 3,
  weekendMinTxns: 2,
  consecutiveWeekends: 3,
  homeMealsMin: 3,
  terminationGraceDays: 0,
  useBuiltinMcc: true,
  mccList: "",
};

/** What each check needs; mirrored in the UI. */
export const DETECTIONS = [
  { id: "split", title: "Split transactions", needs: "card transaction limit, cardholder, merchant, date, amount" },
  { id: "dup_cross", title: "Same receipt claimed by two employees", needs: "merchant, date, amount, a reimbursable / report line" },
  { id: "dup_self", title: "Multiple reimbursements for one expense", needs: "merchant, date, amount, reimbursable or report id" },
  { id: "mcc_user", title: "Prohibited MCC (your list)", needs: "MCC column and your list" },
  { id: "mcc_review", title: "Review-list MCC (built-in)", needs: "MCC column" },
  { id: "weekend_holiday", title: "Weekend and federal holiday spend", needs: "date (holidays from the reference file)" },
  { id: "post_termination", title: "Spend after termination", needs: "HR roster with termination_date" },
  { id: "pre_hire", title: "Spend before hire date", needs: "HR roster with hire_date" },
  { id: "self_approval", title: "Self-approved expenses", needs: "approver column" },
  { id: "approver_reports_to_submitter", title: "Approver reports to the submitter", needs: "approver column and HR roster with manager_id" },
  { id: "policy_limit", title: "Policy limit breaches", needs: "policy CSV and a category column" },
  { id: "missing_receipt", title: "Missing receipts", needs: "receipt column" },
  { id: "round_number", title: "Round-number bias", needs: "amounts (minimum sample per employee and fleet)" },
  { id: "velocity", title: "Monthly spend spike", needs: "dates across enough months" },
  { id: "gift_card", title: "Gift cards and cash-like purchases", needs: "merchant or memo text on rows without an MCC" },
  { id: "personal_weekends", title: "Same merchant on consecutive weekends", needs: "date, merchant" },
  { id: "home_city_meals", title: "Meals in the home city on non-travel days", needs: "HR roster city column and transaction city" },
];

const C = {
  acfeMulti: { framework: "ACFE Fraud Tree", id: "Expense reimbursement schemes: multiple reimbursements" },
  acfeOver: { framework: "ACFE Fraud Tree", id: "Expense reimbursement schemes: overstated expenses" },
  acfeFict: { framework: "ACFE Fraud Tree", id: "Expense reimbursement schemes: fictitious expenses" },
  acfeMisc: { framework: "ACFE Fraud Tree", id: "Expense reimbursement schemes: mischaracterized expenses" },
  acfePersonal: { framework: "ACFE Fraud Tree", id: "Billing schemes: personal purchases" },
  acfeDisb: { framework: "ACFE Fraud Tree", id: "Asset misappropriation: fraudulent disbursements" },
  coso8: { framework: "COSO 2013", id: "Principle 8" },
  coso10: { framework: "COSO 2013", id: "Principle 10" },
  coso12: { framework: "COSO 2013", id: "Principle 12" },
  coso16: { framework: "COSO 2013", id: "Principle 16" },
  soxSod: { framework: "SOX ITGC", id: "Segregation of duties" },
  iso53: { framework: "ISO 27001:2022", id: "A.5.3" },
  iso518: { framework: "ISO 27001:2022", id: "A.5.18" },
  iso65: { framework: "ISO 27001:2022", id: "A.6.5" },
};

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const RISK_W = { critical: 40, high: 25, medium: 12, low: 5, info: 1 };
const EVIDENCE_CAP = 50;
const ASSET_CAP = 25;
const MERCHANT_TABLE_CAP = 5000;
const ROUND_FLEET_MIN = 50;
const DAY_MIN = 1440;

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

const str = (v) => (v == null ? "" : String(v));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const uniqSorted = (a) => [...new Set(a)].sort(cmp);

/** Parse a money string to integer cents. Handles symbols, codes, thousands separators,
 *  parentheses and trailing minus, decimal comma. Returns null when unreadable. */
export function parseCents(v) {
  if (typeof v === "number") return Number.isFinite(v) ? Math.round(v * 100) : null;
  let s = str(v).trim();
  if (!s) return null;
  let neg = false;
  if (/^\(.*\)$/.test(s)) { neg = true; s = s.slice(1, -1); }
  s = s.replace(/[−‒–]/g, "-").replace(/[A-Za-z$€£¥₹\s']/g, "");
  if (s.endsWith("-")) { neg = !neg; s = s.slice(0, -1); }
  if (s.startsWith("-")) { neg = !neg; s = s.slice(1); } else if (s.startsWith("+")) s = s.slice(1);
  if (/^\d{1,3}(,\d{3})+(\.\d+)?$/.test(s)) s = s.replace(/,/g, "");
  else if (/^\d{1,3}(\.\d{3})+,\d{1,2}$/.test(s)) s = s.replace(/\./g, "").replace(",", ".");
  else if (/^\d+,\d{1,2}$/.test(s)) s = s.replace(",", ".");
  if (!s || s === "." || !/^\d*(\.\d+)?$/.test(s)) return null;
  const [ip, fp = ""] = s.split(".");
  let cents = Number(ip || "0") * 100 + Number((fp + "00").slice(0, 2));
  if (fp.length > 2 && Number(fp[2]) >= 5) cents += 1;
  if (!Number.isSafeInteger(cents)) return null;
  return neg && cents ? -cents : cents;
}

/** Integer cents -> "1,234.56" (locale-independent). */
export function fmtCents(c) {
  if (c == null || !Number.isFinite(c)) return "";
  const neg = c < 0, a = Math.abs(c);
  const ip = String(Math.floor(a / 100)).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return (neg ? "-" : "") + ip + "." + String(a % 100).padStart(2, "0");
}

const MON = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
function ymd(y, m, d) {
  if (!(m >= 1 && m <= 12 && d >= 1 && d <= 31 && y >= 1900 && y <= 2200)) return null;
  const t = Date.UTC(y, m - 1, d);
  if (new Date(t).getUTCDate() !== d) return null;
  return Math.floor(t / 86400000);
}
function hm(h, mi, ap) {
  let H = Number(h), M = Number(mi);
  if (ap) { const p = ap.toLowerCase(); if (p === "pm" && H < 12) H += 12; if (p === "am" && H === 12) H = 0; }
  return H >= 0 && H < 24 && M >= 0 && M < 60 ? H * 60 + M : null;
}

/** Parse a date / timestamp to { day (days since epoch), min (minute of day or null) }.
 *  Wall-clock time is taken as written; time-zone suffixes are ignored. */
export function parseWhen(v) {
  const s = str(v).trim();
  if (!s) return null;
  let m = s.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[T ](\d{1,2}):(\d{2})(?::\d{2}(?:\.\d+)?)?)?/);
  if (m) { const day = ymd(+m[1], +m[2], +m[3]); return day == null ? null : { day, min: m[4] != null ? hm(m[4], m[5]) : null }; }
  m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2,4})(?:,?\s+(\d{1,2}):(\d{2})(?::\d{2})?\s*([AaPp][Mm])?)?/);
  if (m) { let y = +m[3]; if (y < 100) y += 2000; const day = ymd(y, +m[1], +m[2]); return day == null ? null : { day, min: m[4] != null ? hm(m[4], m[5], m[6]) : null }; }
  m = s.match(/^(\d{1,2})[ -]([A-Za-z]{3})[A-Za-z]*[ -,]+(\d{4})/);
  if (m && MON[m[2].toLowerCase()]) { const day = ymd(+m[3], MON[m[2].toLowerCase()], +m[1]); return day == null ? null : { day, min: null }; }
  m = s.match(/^([A-Za-z]{3})[A-Za-z]*\.? (\d{1,2}),? (\d{4})/);
  if (m && MON[m[1].toLowerCase()]) { const day = ymd(+m[3], MON[m[1].toLowerCase()], +m[2]); return day == null ? null : { day, min: null }; }
  return null;
}

export const dayIso = (day) => new Date(day * 86400000).toISOString().slice(0, 10);
const dow = (day) => (((day + 4) % 7) + 7) % 7; // 0 = Sunday
const isWeekend = (day) => { const w = dow(day); return w === 0 || w === 6; };
const weekId = (day) => Math.floor((day + 3) / 7); // Monday-start week; Sat + Sun share an id
const monthIdx = (day) => { const d = new Date(day * 86400000); return d.getUTCFullYear() * 12 + d.getUTCMonth(); };
const monthIso = (mi) => Math.floor(mi / 12) + "-" + String((mi % 12) + 1).padStart(2, "0");

/** Last four digits only. Full card / account numbers never leave this function. */
export function maskCard(v) {
  const s = str(v).trim();
  if (!s) return "";
  const d = s.replace(/\D/g, "");
  if (d.length >= 4) return "****" + d.slice(-4);
  if (d.length) return "****" + d;
  return maskPans(s).slice(0, 60);
}

/** Replace anything that looks like a card or account number (12-19 digits) with its last four. */
export function maskPans(text) {
  return str(text).replace(/\d(?:[ -]?\d){11,18}/g, (m) => "****" + m.replace(/\D/g, "").slice(-4));
}

/** Normalised merchant key: processor prefixes, store numbers and punctuation removed. */
export function merchantKey(s) {
  return str(s).toLowerCase()
    .replace(/^(sq|tst|sp|pp|paypal|py|dd|in)\s*\*\s*/, "")
    .replace(/#\s*\d+/g, " ")
    .replace(/[^a-z0-9]+/g, " ")
    .replace(/(\s\d{3,})+\s*$/, "")
    .replace(/\s+/g, " ").trim();
}

/** Name key: lower-case tokens, initials dropped, sorted (so "User, Test" == "TEST J USER"). */
export function nameKey(s) {
  const t = str(s).toLowerCase().replace(/[^a-z0-9@.\s,'-]/g, " ").replace(/[,.'-]/g, " ").split(/\s+/).filter((x) => x.length > 1);
  return t.sort(cmp).join(" ");
}

function normMcc(v) {
  const d = str(v).replace(/\D/g, "");
  return d && d.length <= 4 ? d.padStart(4, "0") : "";
}

function parseReceipt(v) {
  const s = str(v).trim().toLowerCase();
  if (/^(not required|n\/a|na|exempt|waived|not needed)$/.test(s)) return null;
  if (!s || /^(no|n|false|0|missing|none|required|pending|not (attached|submitted|received|provided|uploaded|matched))$/.test(s)) return false;
  return true;
}

function parseYesNo(v) {
  const s = str(v).trim().toLowerCase();
  if (/^(yes|y|true|1|reimbursable|out of pocket)$/.test(s)) return true;
  if (/^(no|n|false|0|non-reimbursable|non reimbursable)$/.test(s)) return false;
  return null;
}

const TRAVEL_MCC = new Set(["4111", "4112", "4121", "4131", "4411", "4511", "4582", "4722", "4784", "4789", "7011", "7512", "7513", "7519"]);
const TRAVEL_RE = /travel|airline|airfare|\bair\b|flight|hotel|lodging|motel|taxi|limousine|ride ?share|uber|lyft|car rental|rental car|\brail|train|transit|parking|mileage|per ?diem|toll/;
const MEAL_MCC = new Set(["5811", "5812", "5813", "5814"]);
const MEAL_RE = /meal|restaurant|dining|food|lunch|dinner|breakfast|coffee|catering|eating/;
const GIFT_RE = /\bgift\s*cards?\b|\bprepaid\b|western\s*union|moneygram|money\s*orders?/i;
function isTravel(r) {
  const n = Number(r.mcc);
  if (r.mcc && ((n >= 3000 && n <= 3999) || TRAVEL_MCC.has(r.mcc))) return true;
  return TRAVEL_RE.test((r.category + " " + r.mccLabel).toLowerCase());
}
function isMeal(r) { return MEAL_MCC.has(r.mcc) || MEAL_RE.test((r.category + " " + r.mccLabel).toLowerCase()); }
const cityKey = (s) => str(s).split(/[\n,]/)[0].toLowerCase().replace(/[^a-z ]/g, " ").replace(/\s+/g, " ").trim();

/** Parse a user MCC list: one code or range per line, optional label; "#" starts a comment. */
export function parseMccList(text) {
  const entries = [], errors = [];
  const lines = str(text).split(/\r?\n/);
  lines.forEach((raw, i) => {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) return;
    const m = line.match(/^(\d{4})(?:\s*-\s*(\d{4}))?(?:[\s,;:|\t]+(.*))?$/);
    if (!m) { errors.push({ line: i + 1, text: raw.trim(), reason: "expected a 4-digit MCC or range like 6010-6011" }); return; }
    const lo = m[1], hi = m[2] || m[1];
    if (Number(hi) < Number(lo)) { errors.push({ line: i + 1, text: raw.trim(), reason: "range end is before its start" }); return; }
    entries.push({ lo, hi, label: str(m[3]).trim() });
  });
  entries.sort((a, b) => cmp(a.lo, b.lo) || cmp(a.hi, b.hi) || cmp(a.label, b.label));
  return { entries, errors };
}

function holidayMap(h) {
  const list = Array.isArray(h) ? h : h && Array.isArray(h.data) ? h.data : null;
  if (!list) return null;
  const m = new Map();
  for (const x of list) {
    const d = typeof x === "string" ? x : x && x.date;
    const w = parseWhen(d);
    if (w) m.set(w.day, typeof x === "string" ? "holiday" : str(x.name) || "holiday");
  }
  return m;
}

const csvCell = (v) => {
  let s = str(v);
  if (/^[=+@\t\r]/.test(s) || /^-[^0-9.]/.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};
export { csvCell };

// ---------------------------------------------------------------------------
// Format detection and row iteration
// ---------------------------------------------------------------------------

/** Iterate a file as arrays (first yielded array = header candidates). CSV/TSV or JSON. */
function* tableRows(text) {
  const t = str(text).replace(/^﻿/, "");
  const c = t.trimStart()[0];
  if (c === "[" || c === "{") {
    let list;
    try { list = iterJson(t); } catch (_) { list = null; }
    if (list) {
      const objs = Array.from(list).filter((o) => o && typeof o === "object" && !Array.isArray(o));
      const keys = [];
      for (const o of objs.slice(0, 50)) for (const k of Object.keys(o)) if (!keys.includes(k)) keys.push(k);
      yield keys;
      for (const o of objs) yield keys.map((k) => (o[k] == null ? "" : typeof o[k] === "object" ? JSON.stringify(o[k]) : o[k]));
      return;
    }
  }
  yield* iterCsv(t, { header: false });
}

const confLabel = (c) => (c >= 0.95 ? "high" : c >= 0.6 ? "medium" : "low");

/** Classify a header row. Returns { format, confidence } (confidence 0..1). */
export function classifyHeaders(headers) {
  const set = new Set((headers || []).map(normHeader).filter(Boolean));
  let best = null;
  for (const [id, f] of Object.entries(FORMATS)) {
    if (!f.headers) continue;
    const want = f.headers.map(normHeader);
    const hit = want.filter((h) => set.has(h)).length;
    const frac = hit / want.length;
    if (!best || frac > best.frac || (frac === best.frac && want.length > best.n)) best = { id, frac, n: want.length };
  }
  if (best && best.frac === 1) return { format: best.id, confidence: 1 };
  if (best && best.frac >= 0.75) return { format: best.id, confidence: 0.75 };
  const has = (spec, k) => findColumn(headers, spec[k]) != null;
  if (has(ROSTER_COLUMNS, "employee_id") && (has(ROSTER_COLUMNS, "name") || has(ROSTER_COLUMNS, "email")) &&
    (has(ROSTER_COLUMNS, "hire_date") || has(ROSTER_COLUMNS, "termination_date") || has(ROSTER_COLUMNS, "manager_id")) && !has(COLUMNS, "amount")) return { format: "generic-roster", confidence: 0.6 };
  if (has(POLICY_COLUMNS, "category") && (has(POLICY_COLUMNS, "limit_per_txn") || has(POLICY_COLUMNS, "limit_per_day"))) return { format: "generic-policy", confidence: 0.6 };
  if (has(COLUMNS, "date") && has(COLUMNS, "amount") && has(COLUMNS, "merchant") && (has(COLUMNS, "employee") || has(COLUMNS, "employee_id"))) return { format: "generic", confidence: 0.6 };
  if (has(COLUMNS, "date") && has(COLUMNS, "amount")) return { format: "generic", confidence: 0.4 };
  return { format: "unknown", confidence: 0 };
}

/** Build key -> column index for a file. overrides = { key: header | "" }. */
export function columnMap(format, headers, role, overrides) {
  const f = FORMATS[format] || {};
  const r = role || f.role || "transactions";
  const spec = ROLE_COLUMNS[r] || COLUMNS;
  const norm = headers.map(normHeader);
  const idxOf = (h) => { const n = normHeader(h); const i = norm.indexOf(n); return i < 0 ? null : i; };
  const map = {};
  if (f.map && f.role === r) for (const [k, h] of Object.entries(f.map)) { const i = idxOf(h); if (i != null) map[k] = i; }
  for (const k of Object.keys(spec)) {
    if (map[k] != null) continue;
    const h = findColumn(headers, spec[k]);
    if (h != null) { const i = headers.indexOf(h); if (i >= 0 && !Object.values(map).includes(i)) map[k] = i; }
  }
  if (r === "transactions" && map.memo != null && map.memo === map.merchant) delete map.memo;
  for (const [k, h] of Object.entries(overrides || {})) {
    if (h === "" || h == null) { delete map[k]; continue; }
    const i = headers.indexOf(h);
    if (i >= 0) map[k] = i;
  }
  return map;
}

function findHeaderRow(text) {
  const it = tableRows(text);
  const pre = [];
  let best = null;
  for (let i = 0; i < 15; i++) {
    const n = it.next();
    if (n.done) break;
    const row = (n.value || []).map((x) => str(x).trim());
    pre.push(row);
    const cls = classifyHeaders(row);
    if (cls.confidence > 0 && (!best || cls.confidence > best.cls.confidence)) best = { i, cls, row };
    if (cls.confidence >= 1) break;
  }
  return best || { i: 0, cls: { format: "unknown", confidence: 0 }, row: pre[0] || [] };
}

function* fileRecords(text, headerIndex) {
  let i = 0;
  for (const row of tableRows(text)) {
    if (i++ <= headerIndex) continue;
    if (!row || !row.some((x) => str(x).trim() !== "")) continue;
    yield { row, line: i };
  }
}

/** Describe one file (cheap: reads only the first rows). */
export function detectFile(file) {
  const name = str(file && file.name) || "input";
  const text = str(file && file.text);
  if (!text.trim()) return { name, format: "empty", label: "Empty file", role: str(file && file.role) || "transactions", confidence: 0, confidenceLabel: "low", headers: [], headerRow: 0, map: {} };
  const h = findHeaderRow(text);
  const format = h.cls.format;
  const role = str(file.role) || (FORMATS[format] && FORMATS[format].role) || "transactions";
  const map = columnMap(format, h.row, role, file.columns);
  return {
    name, format, role, label: format === "unknown" ? "Not recognised" : FORMATS[format].label,
    confidence: h.cls.confidence, confidenceLabel: confLabel(h.cls.confidence),
    headers: h.row, headerRow: h.i,
    map: Object.fromEntries(Object.entries(map).map(([k, i]) => [k, h.row[i]])),
    missing: Object.keys(ROLE_COLUMNS[role] || COLUMNS).filter((k) => map[k] == null),
  };
}

// ---------------------------------------------------------------------------
// Roster, policy and transaction normalisation
// ---------------------------------------------------------------------------

function buildRoster(list) {
  const byId = new Map(), byEmail = new Map(), byName = new Map(), ambiguous = new Set();
  for (const p of list) {
    if (!p.id) continue;
    byId.set(p.id.toLowerCase(), p);
    if (p.email) byEmail.set(p.email.toLowerCase(), p);
    const nk = nameKey(p.name);
    if (nk) { if (byName.has(nk) && byName.get(nk).id !== p.id) ambiguous.add(nk); else byName.set(nk, p); }
  }
  for (const k of ambiguous) byName.delete(k);
  return { list, byId, byEmail, byName, ambiguous, size: byId.size };
}

/** Resolve a person reference to { key, display, person }. */
function resolvePerson(roster, name, id) {
  const n = str(name).trim(), i = str(id).trim();
  let p = null;
  if (i && roster.byId.has(i.toLowerCase())) p = roster.byId.get(i.toLowerCase());
  else if (n && /@/.test(n) && roster.byEmail.has(n.toLowerCase())) p = roster.byEmail.get(n.toLowerCase());
  else if (n && roster.byId.has(n.toLowerCase())) p = roster.byId.get(n.toLowerCase());
  else if (n && roster.byName.has(nameKey(n))) p = roster.byName.get(nameKey(n));
  if (p) return { key: "r:" + p.id.toLowerCase(), display: p.name || p.email || p.id, person: p };
  if (i) return { key: "i:" + i.toLowerCase(), display: n || i, person: null };
  if (/@/.test(n)) return { key: "e:" + n.toLowerCase(), display: n, person: null };
  const nk = nameKey(n);
  if (nk) return { key: "n:" + nk, display: n, person: null };
  return null;
}

function kindOf(fmt, g, reportId) {
  const base = FORMATS[fmt] && FORMATS[fmt].kind;
  if (base) return base;
  const rb = parseYesNo(g("reimbursable"));
  if (rb === true) return "reimb";
  if (rb === false) return "card";
  const pt = g("payment_type").toLowerCase();
  if (pt) {
    if (/personal|cash|out.?of.?pocket|employee|reimburs/.test(pt)) return "reimb";
    if (/corporate|company|card|cbcp|ibcp|central/.test(pt)) return "card";
  }
  return reportId ? "unknown" : "card";
}

// ---------------------------------------------------------------------------
// parseInput
// ---------------------------------------------------------------------------

function toFiles(input) {
  if (input == null) return [];
  if (typeof input === "string") return [{ name: "input", text: input }];
  if (Array.isArray(input)) return input.filter((f) => f && typeof f === "object");
  if (Array.isArray(input.files)) return input.files;
  if (typeof input.text === "string") return [input];
  return [];
}

/** Load every file. Roster and policy first so card rows resolve to roster identities. */
function load(input, ctx) {
  const files = toFiles(input);
  const metas = [], skipped = [];
  const rosterRows = [], policyRows = [];
  const txns = [];
  let credits = 0, creditsCents = {};
  const det = files.map((f) => ({ f, d: detectFile(f) }));
  let totalLines = 0;
  for (const { f } of det) { const t = str(f.text); let n = 0, p = -1; while ((p = t.indexOf("\n", p + 1)) >= 0) n++; totalLines += n + 1; }
  let seen = 0;
  const tick = (label) => { seen++; if (seen % 1000 === 0) ctx?.progress?.(seen, totalLines, label); };
  const order = (d) => (d.role === "roster" ? 0 : d.role === "policy" ? 1 : 2);
  const sorted = det.map((x, i) => ({ ...x, i })).sort((a, b) => order(a.d) - order(b.d) || a.i - b.i);
  let roster = buildRoster([]);
  for (const { f, d } of sorted) {
    const meta = { name: d.name, format: d.format, label: d.label, role: d.role, confidence: d.confidence, confidenceLabel: d.confidenceLabel, headers: d.headers, map: d.map, missing: d.missing || [], records: 0, rejected: 0, notes: [] };
    metas.push(meta);
    if (d.format === "empty" || d.format === "unknown" && !Object.keys(d.map).length) { meta.notes.push(d.format === "empty" ? "empty file" : "format not recognised; map the columns"); continue; }
    const map = columnMap(d.format, d.headers, d.role, f.columns);
    const g0 = (row) => (k) => (map[k] == null ? "" : str(row[map[k]]).trim());
    if (d.role === "roster") {
      for (const { row } of fileRecords(f.text, d.headerRow)) {
        tick("roster");
        const g = g0(row);
        const id = g("employee_id");
        if (!id) { meta.rejected++; continue; }
        const term = parseWhen(g("termination_date")), hire = parseWhen(g("hire_date"));
        rosterRows.push({ id, name: g("name"), email: g("email").toLowerCase(), department: g("department"), title: g("title"), managerId: g("manager_id"), hire: hire ? hire.day : null, term: term ? term.day : null, status: g("status"), city: g("city") });
        meta.records++;
      }
      if (map.termination_date == null) meta.notes.push("no termination_date column");
      roster = buildRoster(rosterRows);
      continue;
    }
    if (d.role === "policy") {
      for (const { row } of fileRecords(f.text, d.headerRow)) {
        tick("policy");
        const g = g0(row);
        const cat = g("category");
        if (!cat) { meta.rejected++; continue; }
        const perTxn = parseCents(g("limit_per_txn")), perDay = parseCents(g("limit_per_day"));
        if (perTxn == null && perDay == null) { meta.rejected++; continue; }
        policyRows.push({ category: cat, key: cat.toLowerCase(), perTxn: perTxn != null && perTxn > 0 ? perTxn : null, perDay: perDay != null && perDay > 0 ? perDay : null, currency: g("currency").toUpperCase() });
        meta.records++;
      }
      continue;
    }
    // transactions
    meta.columns = Object.keys(map).sort(cmp);
    for (const { row, line } of fileRecords(f.text, d.headerRow)) {
      tick("transactions");
      const g = g0(row);
      const when = parseWhen(g("date"));
      let cents = parseCents(g("amount"));
      if (cents == null && map.amount_alt != null) cents = parseCents(g("amount_alt"));
      if (!when || cents == null) { meta.rejected++; continue; }
      let currency = g("currency").toUpperCase();
      if (!g("amount") && map.amount_alt != null) currency = "";
      const reportId = g("report_id");
      const who = resolvePerson(roster, g("employee"), g("employee_id"));
      if (!who) { meta.rejected++; continue; }
      if (cents < 0) { credits++; creditsCents[currency] = (creditsCents[currency] || 0) + cents; meta.records++; continue; }
      if (cents === 0) { meta.records++; continue; }
      const ap = map.approver != null && g("approver") ? resolvePerson(roster, g("approver"), "") : null;
      const merchantRaw = maskPans(g("merchant")) || maskPans(g("memo"));
      const t = {
        i: txns.length, file: d.name, format: d.format, line,
        day: when.day, min: when.min, date: dayIso(when.day),
        emp: who.key, employee: who.display, rosterId: who.person ? who.person.id : "", employeeId: g("employee_id"),
        card: maskCard(g("card_last4")), merchant: merchantRaw.slice(0, 120), mk: merchantKey(merchantRaw),
        mcc: normMcc(g("mcc")), mccLabel: g("mcc_label"), cents, currency,
        receipt: map.receipt != null ? parseReceipt(g("receipt")) : undefined,
        approver: ap ? ap.display : "", apKey: ap ? ap.key : "", apRosterId: ap && ap.person ? ap.person.id : "",
        reportId, category: g("category"), memo: maskPans(g("memo")).slice(0, 160), city: g("city").split(/\n/)[0].trim(), country: g("country"),
        department: g("department") || (who.person ? who.person.department : ""),
        kind: kindOf(d.format, g, reportId), linked: false, flags: [],
      };
      t.travel = isTravel(t);
      t.meal = isMeal(t);
      txns.push(t);
      meta.records++;
    }
    if (meta.rejected) meta.notes.push(meta.rejected + " row(s) without a readable date, amount or person");
  }
  // Without a roster match, a name-only row (card feed) and an id-bearing row (expense report) for
  // the same person get different keys; unify them when the name maps to exactly one id.
  const idByName = new Map();
  for (const t of txns) if (t.emp.startsWith("i:")) { const nk = nameKey(t.employee); if (nk) { if (!idByName.has(nk)) idByName.set(nk, new Set()); idByName.get(nk).add(t.emp); } }
  const unify = (key, name) => { if (!key.startsWith("n:")) return key; const s = idByName.get(nameKey(name)); return s && s.size === 1 ? [...s][0] : key; };
  if (idByName.size) for (const t of txns) { t.emp = unify(t.emp, t.employee); if (t.apKey) t.apKey = unify(t.apKey, t.approver); }
  metas.sort((a, b) => det.findIndex((x) => x.d.name === a.name) - det.findIndex((x) => x.d.name === b.name));
  for (const m of metas) if (m.rejected) skipped.push({ check: "rows", reason: m.name + ": " + m.rejected + " row(s) without a readable date, amount or person were not analysed" });
  return { files: metas, txns, roster, policyRows, credits, creditsCents, skipped };
}

/**
 * Parse input files. Accepts raw text, a file {name, text, role?, columns?} or an array of them.
 * Returns { format, confidence, headers, rows (normalised transactions), skipped, files, roster, policy }.
 */
export function parseInput(input, ctx) {
  const L = load(input, ctx);
  const tx = L.files.filter((f) => f.role === "transactions");
  const format = L.files.length === 1 ? L.files[0].format : L.files.length ? "multi" : "empty";
  return {
    format, confidence: L.files.length ? Math.min(...L.files.map((f) => f.confidence)) : 0,
    headers: L.files.length === 1 ? L.files[0].headers : [],
    rows: L.txns.map(publicRow), skipped: L.skipped, files: L.files,
    roster: L.roster.list.length, policy: L.policyRows.length, transactionFiles: tx.length,
  };
}

function publicRow(t) {
  return { date: t.date, employee: t.employee, card: t.card, merchant: t.merchant, mcc: t.mcc, amount: fmtCents(t.cents), cents: t.cents, currency: t.currency, category: t.category, report: t.reportId, approver: t.approver, kind: t.kind, file: t.file, line: t.line };
}

// ---------------------------------------------------------------------------
// analyze
// ---------------------------------------------------------------------------

function ev(t, extra) {
  const o = { date: t.date + (t.min != null ? " " + String(Math.floor(t.min / 60)).padStart(2, "0") + ":" + String(t.min % 60).padStart(2, "0") : ""), employee: t.employee };
  if (t.card) o.card = t.card;
  o.merchant = t.merchant;
  if (t.mcc) o.mcc = t.mcc;
  o.amount = fmtCents(t.cents);
  o.currency = t.currency || "unstated";
  if (t.category) o.category = t.category;
  if (t.reportId) o.report = t.reportId;
  if (t.approver) o.approver = t.approver;
  o.paid = t.kind === "reimb" ? "out of pocket" : t.kind === "card" ? "card" : "unknown";
  if (extra) Object.assign(o, extra);
  o.file = t.file + ":" + t.line;
  return o;
}

const sumBy = (rows) => { const m = {}; for (const r of rows) m[r.currency] = (m[r.currency] || 0) + r.cents; return m; };
const moneyText = (m) => Object.keys(m).sort(cmp).map((c) => fmtCents(m[c]) + " " + (c || "(currency unstated)")).join("; ");

function median(a) { const s = a.slice().sort((x, y) => x - y); const n = s.length; return n ? (n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2) : 0; }

/**
 * Analyze the dataset ({files:[{name,text,role?,columns?}]} or an array of files).
 * opts overrides DEFAULTS; opts.holidays = holiday list or the /data/ref/us-holidays.json envelope.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  const L = load(dataset, ctx);
  const skipped = L.skipped.slice();
  const findings = [];
  const all = L.txns;
  const roster = L.roster;
  const hasRoster = roster.size > 0;
  const files = L.files;
  const txFiles = files.filter((f) => f.role === "transactions" && f.records > 0);

  // ---- link report lines paid by company card to the card feed (no double counting) ----
  const feed = all.filter((t) => !t.reportId && t.kind === "card");
  const lines = all.filter((t) => t.reportId && t.kind === "card");
  let linked = 0;
  if (feed.length && lines.length) {
    const idx = new Map();
    for (const t of feed) { const k = t.emp + "|" + t.cents + "|" + t.currency; if (!idx.has(k)) idx.set(k, []); idx.get(k).push(t); }
    const used = new Set();
    for (const l of lines) {
      const cands = (idx.get(l.emp + "|" + l.cents + "|" + l.currency) || []).filter((t) => !used.has(t.i) && Math.abs(t.day - l.day) <= 1)
        .sort((a, b) => Math.abs(a.day - l.day) - Math.abs(b.day - l.day) || a.i - b.i);
      if (cands.length) { used.add(cands[0].i); l.linked = true; l.linkedTo = cands[0].i; linked++; }
    }
  }
  const act = all.filter((t) => !t.linked);
  const byEmp = new Map();
  for (const t of act) { if (!byEmp.has(t.emp)) byEmp.set(t.emp, []); byEmp.get(t.emp).push(t); }
  const empKeys = [...byEmp.keys()].sort(cmp);
  const empName = new Map();
  for (const t of all) if (!empName.has(t.emp)) empName.set(t.emp, t.employee);
  const personOf = (key) => (key.startsWith("r:") ? roster.byId.get(key.slice(2)) : null);

  const add = (check, f, rows, extra) => {
    const evRows = rows.slice(0, EVIDENCE_CAP).map((t) => ev(t, extra ? extra(t) : null));
    for (const t of rows) if (!t.flags.includes(check)) t.flags.push(check);
    const emps = uniqSorted(rows.map((t) => t.emp));
    findings.push({
      id: TOOL_ID + ":" + check + ":" + f.key,
      title: f.title, severity: f.severity, confidence: f.confidence, category: f.category,
      description: f.description, recommendation: f.recommendation, controls: f.controls,
      evidence: evRows, evidenceCount: rows.length,
      assets: emps.slice(0, ASSET_CAP).map((k) => ({ type: "IDENTITY", name: empName.get(k) || k, _k: k })),
      tags: ["cardaudit", check],
      check, employees: uniqSorted(emps.map((k) => empName.get(k) || k)),
    });
  };
  const timeOf = (t) => t.day * DAY_MIN + (t.min != null ? t.min : 0);
  ctx?.progress?.(1, 1, "detections");

  // ---- 1. split transactions ----
  const limit = o.cardTxnLimit == null || o.cardTxnLimit === "" ? null : parseCents(o.cardTxnLimit);
  if (limit == null || limit <= 0) skipped.push({ check: "split", reason: "card transaction limit is blank; enter your single-transaction limit to screen for split purchases" });
  else {
    const W = Math.max(0, Number(o.splitHours) || 0) * 60;
    const groups = new Map();
    for (const t of act) {
      if (t.kind === "reimb" || t.cents >= limit || !t.mk) continue;
      const k = t.emp + "|" + t.mk + "|" + t.currency;
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(t);
    }
    const perEmp = new Map();
    for (const k of [...groups.keys()].sort(cmp)) {
      const g = groups.get(k).sort((a, b) => timeOf(a) - timeOf(b) || a.i - b.i);
      let i = 0;
      while (i < g.length) {
        let j = i, sum = 0;
        while (j < g.length && timeOf(g[j]) - timeOf(g[i]) <= W) { sum += g[j].cents; j++; }
        if (j - i >= 2 && sum > limit) {
          const cl = g.slice(i, j), emp = cl[0].emp;
          if (!perEmp.has(emp)) perEmp.set(emp, []);
          perEmp.get(emp).push({ rows: cl, sum });
          i = j;
        } else i++;
      }
    }
    for (const emp of [...perEmp.keys()].sort(cmp)) {
      const cls = perEmp.get(emp), rows = cls.flatMap((c) => c.rows);
      const clusterOf = new Map(); cls.forEach((c, n) => c.rows.forEach((t) => clusterOf.set(t.i, { n: n + 1, sum: c.sum })));
      add("split", {
        key: emp, title: "Possible split transactions: " + empName.get(emp), severity: "high", confidence: "likely", category: "Split transactions",
        description: empName.get(emp) + " has " + cls.length + " group(s) of charges at the same merchant within " + o.splitHours + " hours where every charge is below the " + fmtCents(limit) + " single-transaction limit but the group totals more (largest group " + fmtCents(Math.max(...cls.map((c) => c.sum))) + "). This pattern is consistent with splitting a purchase to stay under the card limit. Rows without a time are placed at midnight, so with a 24-hour window charges on consecutive days count as inside it.",
        recommendation: "Ask the cardholder for the invoices behind each group; if one purchase was split, require approval at the combined amount and record a policy exception.",
        controls: [C.acfeDisb, C.coso10, C.coso12],
      }, rows, (t) => ({ group: clusterOf.get(t.i).n, groupTotal: fmtCents(clusterOf.get(t.i).sum) }));
    }
  }

  // ---- 2. duplicates / multiple reimbursements ----
  const recovery = [];
  {
    const isClaim = (t) => t.kind === "reimb" || (t.kind === "unknown" && !!t.reportId);
    const groups = new Map();
    for (const t of act) {
      if (!t.mk) continue;
      const k = t.mk + "|" + t.day + "|" + t.cents + "|" + t.currency;
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(t);
    }
    const cross = new Map(), self = new Map();
    for (const k of [...groups.keys()].sort(cmp)) {
      const g = groups.get(k);
      if (g.length < 2 || !g.some(isClaim)) continue;
      const emps = uniqSorted(g.map((t) => t.emp));
      let dupRows = [];
      let type = "";
      if (emps.length >= 2) {
        type = "same receipt, two or more employees";
        dupRows = g;
        const pk = emps.join("+");
        if (!cross.has(pk)) cross.set(pk, []);
        cross.get(pk).push(g);
      } else {
        const claims = g.filter(isClaim);
        if (claims.length >= 2 || (claims.length >= 1 && g.length >= 2)) {
          const reports = uniqSorted(claims.map((t) => t.reportId).filter(Boolean));
          type = claims.length === g.length ? (reports.length >= 2 ? "same expense in two reports" : "same expense entered twice") : "card charge also claimed out of pocket";
          dupRows = g;
          if (!self.has(emps[0])) self.set(emps[0], []);
          self.get(emps[0]).push({ g, type });
        }
      }
      if (dupRows.length) {
        const t0 = dupRows[0];
        recovery.push({ type, merchant: t0.merchant, date: t0.date, amount: fmtCents(t0.cents), cents: t0.cents, currency: t0.currency, claims: dupRows.length,
          recoverableCents: t0.cents * (dupRows.length - 1), recoverable: fmtCents(t0.cents * (dupRows.length - 1)),
          employees: uniqSorted(dupRows.map((t) => t.employee)).join("; "), reports: uniqSorted(dupRows.map((t) => t.reportId).filter(Boolean)).join("; "),
          files: uniqSorted(dupRows.map((t) => t.file + ":" + t.line)).join("; ") });
      }
    }
    for (const pk of [...cross.keys()].sort(cmp)) {
      const gs = cross.get(pk), rows = gs.flat();
      const names = uniqSorted(rows.map((t) => t.employee));
      const amt = moneyText(sumBy(gs.map((g) => ({ currency: g[0].currency, cents: g[0].cents * (g.length - 1) }))));
      add("dup_cross", {
        key: pk, title: "Possible duplicate receipt across employees: " + names.join(", "), severity: "high", confidence: "likely", category: "Duplicate receipts",
        description: gs.length + " expense(s) with the same merchant, date and amount were charged or claimed by more than one employee (" + names.join(", ") + "), and at least one of them is an out-of-pocket or report claim. This is consistent with one receipt being submitted twice (ACFE multiple reimbursements). Potential duplicate amount: " + amt + ".",
        recommendation: "Pull both receipts and the card statement line; if it is one expense, recover the duplicate reimbursement and check the approver's review of receipts.",
        controls: [C.acfeMulti, C.coso10, C.coso12],
      }, rows, (t) => ({ group: gs.findIndex((g) => g.includes(t)) + 1 }));
    }
    for (const emp of [...self.keys()].sort(cmp)) {
      const gs = self.get(emp), rows = gs.flatMap((x) => x.g);
      const types = uniqSorted(gs.map((x) => x.type));
      const amt = moneyText(sumBy(gs.map((x) => ({ currency: x.g[0].currency, cents: x.g[0].cents * (x.g.length - 1) }))));
      add("dup_self", {
        key: emp, title: "Possible multiple reimbursements: " + empName.get(emp), severity: "high", confidence: "likely", category: "Duplicate receipts",
        description: empName.get(emp) + " has " + gs.length + " expense(s) recorded more than once with the same merchant, date and amount (" + types.join("; ") + "). A card charge that is also claimed out of pocket, or a line submitted in two reports, is consistent with the ACFE multiple-reimbursement scheme. Potential duplicate amount: " + amt + ".",
        recommendation: "Compare the receipts; recover any amount reimbursed twice and add a duplicate-line check to report approval.",
        controls: [C.acfeMulti, C.coso10, C.coso12],
      }, rows, (t) => ({ pattern: (gs.find((x) => x.g.includes(t)) || {}).type }));
    }
  }

  // ---- 3. MCC lists ----
  const userList = parseMccList(o.mccList);
  if (userList.errors.length) skipped.push({ check: "mcc_user", reason: userList.errors.length + " line(s) in your MCC list were not understood: " + userList.errors.slice(0, 5).map((e) => "line " + e.line + " (" + e.reason + ")").join("; ") });
  const withMcc = act.filter((t) => t.mcc);
  const noMccFiles = txFiles.filter((f) => !f.map || !f.map.mcc).map((f) => f.name);
  if (!withMcc.length) {
    skipped.push({ check: "mcc", reason: "no MCC column in the transaction files" + (noMccFiles.length ? " (" + noMccFiles.join(", ") + ")" : "") + "; American Express and SAP Concur exports do not include MCC" });
  } else {
    if (noMccFiles.length) skipped.push({ check: "mcc (partial)", reason: "MCC checks did not run for files without an MCC column: " + noMccFiles.join(", ") });
    const userHit = new Map(), builtinHit = new Map();
    for (const t of withMcc) {
      const n = Number(t.mcc);
      const u = userList.entries.find((e) => n >= Number(e.lo) && n <= Number(e.hi));
      if (u) { const k = t.mcc; if (!userHit.has(k)) userHit.set(k, { e: u, rows: [] }); userHit.get(k).rows.push(t); continue; }
      if (o.useBuiltinMcc) { const b = BUILTIN_MCC.find((x) => x.mcc === t.mcc); if (b) { if (!builtinHit.has(b.mcc)) builtinHit.set(b.mcc, { e: b, rows: [] }); builtinHit.get(b.mcc).rows.push(t); } }
    }
    if (!userList.entries.length) skipped.push({ check: "mcc_user", reason: "your prohibited MCC list is empty" });
    for (const k of [...userHit.keys()].sort(cmp)) {
      const { e, rows } = userHit.get(k);
      const label = e.label || (BUILTIN_MCC.find((b) => b.mcc === k) || {}).label || "";
      add("mcc_user", {
        key: k, title: "Prohibited MCC " + k + (label ? " (" + label + ")" : "") + " on corporate spend", severity: "high", confidence: "likely", category: "Prohibited merchants",
        description: rows.length + " transaction(s) by " + uniqSorted(rows.map((t) => t.employee)).length + " employee(s) carry MCC " + k + ", which is on your prohibited list" + (e.lo !== e.hi ? " (range " + e.lo + "-" + e.hi + ")" : "") + ". Total " + moneyText(sumBy(rows)) + ". The MCC is assigned by the merchant's acquirer and can be wrong, so confirm the purchase.",
        recommendation: "Ask each cardholder for the business purpose; recover personal spend and consider blocking the MCC at the card program.",
        controls: [C.acfePersonal, C.coso12],
      }, rows);
    }
    for (const k of [...builtinHit.keys()].sort(cmp)) {
      const { e, rows } = builtinHit.get(k);
      add("mcc_review", {
        key: k, title: "Review-list MCC " + k + " (" + e.label + ")", severity: e.severity, confidence: "review", category: "Review merchants",
        description: rows.length + " transaction(s) by " + uniqSorted(rows.map((t) => t.employee)).length + " employee(s) carry MCC " + k + " (" + e.label + "), which is on the built-in review list. Total " + moneyText(sumBy(rows)) + ". Spend here is often outside card policy but can be legitimate (client entertainment, travel incidentals); this is a prompt to review, not a policy breach.",
        recommendation: "Confirm the business purpose with the cardholder; add the code to your prohibited list if your policy forbids it.",
        controls: [C.acfePersonal, C.coso12],
      }, rows);
    }
  }

  // ---- 4. weekend and holiday spend ----
  {
    const hol = holidayMap(o.holidays);
    if (!hol) skipped.push({ check: "weekend_holiday (holidays)", reason: "no holiday reference data supplied; only weekends were checked" });
    const per = new Map();
    for (const t of act) {
      if (t.travel) continue;
      const w = isWeekend(t.day), h = hol && hol.get(t.day);
      if (!w && !h) continue;
      if (!per.has(t.emp)) per.set(t.emp, []);
      per.get(t.emp).push(t);
    }
    const min = Math.max(1, Number(o.weekendMinTxns) || 1);
    for (const emp of [...per.keys()].sort(cmp)) {
      const rows = per.get(emp);
      if (rows.length < min) continue;
      add("weekend_holiday", {
        key: emp, title: "Weekend or holiday spend outside travel: " + empName.get(emp), severity: "low", confidence: "review", category: "Weekend and holiday spend",
        description: empName.get(emp) + " has " + rows.length + " non-travel transaction(s) dated on a weekend or US federal holiday (threshold " + min + "), total " + moneyText(sumBy(rows)) + ". Weekend and holiday spend outside travel is a common sign of mischaracterized personal expenses, but many roles work weekends.",
        recommendation: "Review the business purpose on these items with the employee's manager.",
        controls: [C.acfeMisc, C.coso16],
      }, rows, (t) => ({ day: hol && hol.get(t.day) ? hol.get(t.day) : ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][dow(t.day)] }));
    }
  }

  // ---- 5. spend after termination / before hire ----
  const postTerm = [];
  if (!hasRoster) skipped.push({ check: "post_termination / pre_hire", reason: "no HR roster loaded" });
  else {
    const grace = Math.max(0, Number(o.terminationGraceDays) || 0);
    const hasTerm = roster.list.some((p) => p.term != null), hasHire = roster.list.some((p) => p.hire != null);
    if (!hasTerm) skipped.push({ check: "post_termination", reason: "the roster has no termination dates" });
    if (!hasHire) skipped.push({ check: "pre_hire", reason: "the roster has no hire dates" });
    const unmatched = uniqSorted(act.filter((t) => !t.rosterId).map((t) => t.employee));
    if (unmatched.length) skipped.push({ check: "roster match", reason: unmatched.length + " cardholder(s) not found in the roster (" + unmatched.slice(0, 8).join(", ") + (unmatched.length > 8 ? ", ..." : "") + "); roster checks did not run for them" });
    for (const emp of empKeys) {
      const p = personOf(emp);
      if (!p) continue;
      const rows = byEmp.get(emp);
      if (p.term != null) {
        const after = rows.filter((t) => t.day > p.term + grace);
        if (after.length) {
          postTerm.push(...after);
          add("post_termination", {
            key: emp, title: "Spend after termination: " + p.name, severity: "critical", confidence: "likely", category: "Leaver spend",
            description: p.name + " (" + p.id + ") left on " + dayIso(p.term) + (grace ? " (grace " + grace + " days)" : "") + " but " + after.length + " transaction(s) totalling " + moneyText(sumBy(after)) + " are dated afterwards. A card or expense account that stays usable after termination exposes the company to personal purchases.",
            recommendation: "Cancel the card and expense access today, confirm whether these charges were authorised, and recover personal spend; review the offboarding checklist.",
            controls: [C.acfePersonal, C.iso518, C.iso65, C.coso10],
          }, after, (t) => ({ daysAfterTermination: t.day - p.term }));
        }
      }
      if (p.hire != null) {
        const before = rows.filter((t) => t.day < p.hire);
        if (before.length) add("pre_hire", {
          key: emp, title: "Spend before hire date: " + p.name, severity: "medium", confidence: "review", category: "Leaver spend",
          description: p.name + " (" + p.id + ") was hired on " + dayIso(p.hire) + " but " + before.length + " transaction(s) totalling " + moneyText(sumBy(before)) + " are dated earlier. Pre-start travel bookings can be legitimate; a roster or card-assignment error is also possible.",
          recommendation: "Confirm the hire date in HR and who held the card before that date.",
          controls: [C.iso518, C.coso10],
        }, before, (t) => ({ daysBeforeHire: p.hire - t.day }));
      }
    }
  }

  // ---- 6. self-approval / approver reports to submitter ----
  const withAp = all.filter((t) => t.apKey);
  if (!withAp.length) skipped.push({ check: "self_approval", reason: "no approver column in the transaction files (Brex and American Express exports have none)" });
  else {
    const self = new Map(), up = new Map();
    const reportsTo = (approverId, submitterId) => {
      let cur = roster.byId.get(approverId.toLowerCase()), guard = 0;
      while (cur && cur.managerId && guard++ < 25) {
        if (cur.managerId.toLowerCase() === submitterId.toLowerCase()) return guard;
        cur = roster.byId.get(cur.managerId.toLowerCase());
      }
      return 0;
    };
    for (const t of withAp) {
      if (t.apKey === t.emp) { if (!self.has(t.emp)) self.set(t.emp, []); self.get(t.emp).push(t); continue; }
      if (hasRoster && t.rosterId && t.apRosterId) {
        const lv = reportsTo(t.apRosterId, t.rosterId);
        if (lv) { t._lv = lv; if (!up.has(t.emp)) up.set(t.emp, []); up.get(t.emp).push(t); }
      }
    }
    if (!hasRoster) skipped.push({ check: "approver_reports_to_submitter", reason: "no HR roster with manager_id loaded" });
    for (const emp of [...self.keys()].sort(cmp)) {
      const rows = self.get(emp), byId = rows.every((t) => t.rosterId && t.apRosterId);
      const reports = uniqSorted(rows.map((t) => t.reportId).filter(Boolean));
      add("self_approval", {
        key: emp, title: "Self-approved expenses: " + empName.get(emp), severity: "medium", confidence: byId ? "confirmed" : "likely", category: "Approval",
        description: empName.get(emp) + " is recorded as the approver of " + rows.length + " of their own expense line(s)" + (reports.length ? " in report(s) " + reports.slice(0, 10).join(", ") : "") + ", total " + moneyText(sumBy(rows)) + ". " + (byId ? "Submitter and approver resolve to the same roster employee id." : "Matched on name or email; confirm it is the same person.") + " Approving your own spend removes the segregation of duties the approval step exists for.",
        recommendation: "Route these reports to an independent approver for re-review and block self-approval in the expense tool's workflow.",
        controls: [C.soxSod, C.iso53, C.coso10],
      }, rows);
    }
    for (const emp of [...up.keys()].sort(cmp)) {
      const rows = up.get(emp);
      const aps = uniqSorted(rows.map((t) => t.approver));
      add("approver_reports_to_submitter", {
        key: emp, title: "Approver reports to the submitter: " + empName.get(emp), severity: "medium", confidence: "likely", category: "Approval",
        description: empName.get(emp) + "'s expenses (" + rows.length + " line(s), " + moneyText(sumBy(rows)) + ") were approved by " + aps.join(", ") + ", who sit(s) below " + empName.get(emp) + " in the roster's manager chain. A subordinate approving a superior's spend is a weak segregation-of-duties control.",
        recommendation: "Have expenses approved by the submitter's own manager or finance, and add a hierarchy check to the approval workflow.",
        controls: [C.soxSod, C.iso53, C.coso10],
      }, rows, (t) => ({ levelsBelow: t._lv }));
    }
  }

  // ---- 7. policy limits ----
  if (!L.policyRows.length) skipped.push({ check: "policy_limit", reason: "no policy limits CSV loaded (category,limit_per_txn,limit_per_day,currency)" });
  else if (!act.some((t) => t.category)) skipped.push({ check: "policy_limit", reason: "no category column in the transaction files" });
  else {
    const pol = new Map();
    for (const p of L.policyRows) pol.set(p.key, p);
    const per = new Map(); let curSkip = 0;
    const note = new Map();
    const dayGroups = new Map();
    for (const t of act) {
      const p = pol.get(t.category.toLowerCase());
      if (!p) continue;
      if (p.currency && t.currency !== p.currency) { curSkip++; continue; }
      if (p.perTxn != null && t.cents > p.perTxn) { if (!per.has(t.emp)) per.set(t.emp, new Set()); per.get(t.emp).add(t); note.set(t.i, "over per-transaction limit " + fmtCents(p.perTxn)); }
      if (p.perDay != null) { const k = t.emp + "|" + p.key + "|" + t.day; if (!dayGroups.has(k)) dayGroups.set(k, { p, rows: [] }); dayGroups.get(k).rows.push(t); }
    }
    for (const k of [...dayGroups.keys()].sort(cmp)) {
      const { p, rows } = dayGroups.get(k);
      const sum = rows.reduce((s, t) => s + t.cents, 0);
      if (sum > p.perDay) for (const t of rows) { if (!per.has(t.emp)) per.set(t.emp, new Set()); per.get(t.emp).add(t); note.set(t.i, (note.has(t.i) ? note.get(t.i) + "; " : "") + "day total " + fmtCents(sum) + " over daily limit " + fmtCents(p.perDay)); }
    }
    if (curSkip) skipped.push({ check: "policy_limit (currency)", reason: curSkip + " row(s) in a policy category were not checked because their currency differs from the policy currency (no conversion is done)" });
    for (const emp of [...per.keys()].sort(cmp)) {
      const rows = [...per.get(emp)].sort((a, b) => a.day - b.day || a.i - b.i);
      add("policy_limit", {
        key: emp, title: "Policy limit breaches: " + empName.get(emp), severity: "medium", confidence: "likely", category: "Policy limits",
        description: empName.get(emp) + " has " + rows.length + " transaction(s) above the per-transaction or per-day limit in your policy table, total " + moneyText(sumBy(rows)) + ". Amounts above per-diem or category limits are where overstated expenses show up.",
        recommendation: "Check for a recorded pre-approval or exception; otherwise ask for repayment of the excess.",
        controls: [C.acfeOver, C.coso12],
      }, rows, (t) => ({ rule: note.get(t.i) }));
    }
  }

  // ---- 8. missing receipts ----
  {
    const withR = act.filter((t) => t.receipt !== undefined);
    const noRFiles = txFiles.filter((f) => !f.map || !f.map.receipt).map((f) => f.name);
    if (!withR.length) skipped.push({ check: "missing_receipt", reason: "no receipt column in the transaction files" + (noRFiles.length ? " (" + noRFiles.join(", ") + ")" : "") });
    else {
      if (noRFiles.length) skipped.push({ check: "missing_receipt (partial)", reason: "not checked for files without a receipt column: " + noRFiles.join(", ") });
      const thr = parseCents(o.receiptRequiredOver) ?? 0;
      const per = new Map();
      for (const t of withR) if (t.receipt === false && t.cents > thr) { if (!per.has(t.emp)) per.set(t.emp, []); per.get(t.emp).push(t); }
      for (const emp of [...per.keys()].sort(cmp)) {
        const rows = per.get(emp);
        add("missing_receipt", {
          key: emp, title: "Missing receipts: " + empName.get(emp), severity: "low", confidence: "review", category: "Receipts",
          description: empName.get(emp) + " has " + rows.length + " transaction(s) over " + fmtCents(thr) + " without a receipt, total " + moneyText(sumBy(rows)) + ". Missing support is where fictitious and overstated expenses hide.",
          recommendation: "Request the receipts; treat items still unsupported after the policy deadline as personal and recover them.",
          controls: [C.acfeFict, C.coso12],
        }, rows);
      }
    }
  }

  // ---- 9. round-number bias ----
  {
    const minN = Math.max(1, Number(o.roundMinTxns) || 15), zT = Number(o.roundZ) || 3;
    const N = act.length, R = act.filter((t) => t.cents % 100 === 0).length;
    const eligible = empKeys.filter((k) => byEmp.get(k).length >= minN);
    if (!eligible.length) skipped.push({ check: "round_number", reason: "no employee has at least " + minN + " transactions" });
    else if (N - Math.min(...eligible.map((k) => byEmp.get(k).length)) < ROUND_FLEET_MIN) skipped.push({ check: "round_number", reason: "fleet baseline needs at least " + ROUND_FLEET_MIN + " transactions from other employees" });
    else {
      for (const emp of eligible) {
        const rows = byEmp.get(emp), n = rows.length;
        const rr = rows.filter((t) => t.cents % 100 === 0);
        const on = N - n;
        if (on < ROUND_FLEET_MIN) continue;
        let p0 = (R - rr.length) / on;
        p0 = Math.min(1 - 0.5 / on, Math.max(0.5 / on, p0));
        const p = rr.length / n, z = (p - p0) / Math.sqrt((p0 * (1 - p0)) / n);
        if (z < zT) continue;
        add("round_number", {
          key: emp, title: "Round-number bias: " + empName.get(emp), severity: "low", confidence: "review", category: "Statistical screens",
          description: Math.round(p * 1000) / 10 + "% of " + empName.get(emp) + "'s " + n + " transactions are whole-currency amounts, against " + Math.round(p0 * 1000) / 10 + "% for the other " + on + " transactions (z = " + Math.round(z * 100) / 100 + ", threshold " + zT + ", minimum " + minN + " transactions). Invented or estimated amounts tend to be round; mileage, per-diem and subscription charges are legitimately round, so check the categories first.",
          recommendation: "Sample the round-amount items and compare them to receipts.",
          controls: [C.acfeFict, C.coso16],
        }, rr);
      }
    }
  }

  // ---- 10. velocity ----
  {
    const minH = Math.max(1, Number(o.minHistoryMonths) || 4), zT = Number(o.spikeZ) || 3, ratio = Math.max(1, Number(o.spikeMinRatio) || 1);
    let tested = 0;
    for (const emp of empKeys) {
      const byCur = new Map();
      for (const t of byEmp.get(emp)) { if (!byCur.has(t.currency)) byCur.set(t.currency, []); byCur.get(t.currency).push(t); }
      for (const cur of [...byCur.keys()].sort(cmp)) {
        const rows = byCur.get(cur);
        const sums = new Map();
        for (const t of rows) { const m = monthIdx(t.day); sums.set(m, (sums.get(m) || 0) + t.cents); }
        const ms = [...sums.keys()], lo = Math.min(...ms), hi = Math.max(...ms);
        if (hi - lo + 1 < minH + 1) continue;
        tested++;
        const series = []; for (let m = lo; m <= hi; m++) series.push({ m, v: sums.get(m) || 0 });
        const spikes = [];
        for (const s of series) {
          const others = series.filter((x) => x !== s).map((x) => x.v);
          const med = median(others);
          const mad = median(others.map((v) => Math.abs(v - med)));
          let z = null;
          if (mad > 0) z = (0.6745 * (s.v - med)) / mad;
          else { const mean = others.reduce((a, v) => a + Math.abs(v - med), 0) / others.length; if (mean > 0) z = (s.v - med) / (1.253314 * mean); }
          if (s.v < ratio * med) continue;
          if ((z != null && z > zT) || (z == null && med > 0)) spikes.push({ ...s, z, med });
        }
        if (!spikes.length) continue;
        const sm = new Set(spikes.map((s) => s.m));
        const flagged = rows.filter((t) => sm.has(monthIdx(t.day))).sort((a, b) => a.day - b.day || a.i - b.i);
        const top = spikes.slice().sort((a, b) => b.v - a.v)[0];
        add("velocity", {
          key: emp + "|" + cur, title: "Monthly spend spike: " + empName.get(emp), severity: "low", confidence: "review", category: "Statistical screens",
          description: empName.get(emp) + " spent " + fmtCents(top.v) + " " + (cur || "(currency unstated)") + " in " + monthIso(top.m) + " against a median of " + fmtCents(Math.round(top.med)) + " over the other " + (series.length - 1) + " months (robust z " + (top.z == null ? "n/a, flat history" : Math.round(top.z * 100) / 100) + ", threshold " + zT + ", at least " + ratio + "x the median, minimum " + minH + " months of history). " + spikes.length + " month(s) flagged: " + spikes.map((s) => monthIso(s.m)).join(", ") + ". Spikes often have a business reason (conference, offsite).",
          recommendation: "Ask the manager whether the spike matches a known event; review the largest items in the flagged month.",
          controls: [C.coso16, C.coso8],
        }, flagged, (t) => ({ month: monthIso(monthIdx(t.day)) }));
      }
    }
    if (!tested) skipped.push({ check: "velocity", reason: "no employee has " + (minH + 1) + " or more months of spend (" + minH + " months of history plus the month tested)" });
  }

  // ---- 11. gift cards / cash-like ----
  {
    const per = new Map();
    for (const t of act) {
      if (t.mcc) continue;
      if (!GIFT_RE.test(t.merchant + " " + t.memo)) continue;
      if (!per.has(t.emp)) per.set(t.emp, []);
      per.get(t.emp).push(t);
    }
    for (const emp of [...per.keys()].sort(cmp)) {
      const rows = per.get(emp);
      add("gift_card", {
        key: emp, title: "Gift card or cash-like purchase: " + empName.get(emp), severity: "medium", confidence: "review", category: "Cash-like purchases",
        description: empName.get(emp) + " has " + rows.length + " transaction(s) whose merchant or memo mentions gift cards, prepaid cards, money orders, Western Union or MoneyGram, total " + moneyText(sumBy(rows)) + ". These rows have no MCC, so this is a keyword match. Gift cards and money transfers convert company funds into cash equivalents and are hard to trace.",
        recommendation: "Confirm the recipients (e.g. a documented customer or employee award program) and how the cards were logged and handed out.",
        controls: [C.acfePersonal, C.coso12],
      }, rows);
    }
  }

  // ---- 12. personal-use patterns ----
  {
    const need = Math.max(2, Number(o.consecutiveWeekends) || 3);
    const per = new Map();
    for (const emp of empKeys) {
      const byM = new Map();
      for (const t of byEmp.get(emp)) { if (t.travel || !isWeekend(t.day) || !t.mk) continue; if (!byM.has(t.mk)) byM.set(t.mk, []); byM.get(t.mk).push(t); }
      for (const mk of [...byM.keys()].sort(cmp)) {
        const rows = byM.get(mk);
        const weeks = uniqSorted(rows.map((t) => weekId(t.day))).map(Number).sort((a, b) => a - b);
        let best = [], run = [];
        for (const w of weeks) { if (run.length && w === run[run.length - 1] + 1) run.push(w); else run = [w]; if (run.length > best.length) best = run.slice(); }
        if (best.length >= need) {
          const ws = new Set(best);
          if (!per.has(emp)) per.set(emp, []);
          per.get(emp).push(...rows.filter((t) => ws.has(weekId(t.day))));
        }
      }
    }
    for (const emp of [...per.keys()].sort(cmp)) {
      const rows = per.get(emp).sort((a, b) => a.day - b.day || a.i - b.i);
      add("personal_weekends", {
        key: emp, title: "Same merchant on consecutive weekends: " + empName.get(emp), severity: "low", confidence: "review", category: "Personal-use patterns",
        description: empName.get(emp) + " has non-travel charges at " + uniqSorted(rows.map((t) => t.merchant)).slice(0, 5).join(", ") + " on " + need + " or more consecutive weekends (" + rows.length + " transaction(s), " + moneyText(sumBy(rows)) + "). A recurring weekend charge at the same merchant can indicate personal use of the card; it can also be scheduled weekend work.",
        recommendation: "Ask the cardholder what the recurring charge is for; move personal subscriptions or purchases off the corporate card.",
        controls: [C.acfePersonal, C.coso16],
      }, rows);
    }
    // home city meals
    const hasCity = roster.list.some((p) => p.city);
    if (!hasRoster || !hasCity) skipped.push({ check: "home_city_meals", reason: "needs an HR roster with a city / work location column" });
    else if (!act.some((t) => t.city)) skipped.push({ check: "home_city_meals", reason: "no merchant city column in the transaction files" });
    else {
      const minM = Math.max(1, Number(o.homeMealsMin) || 3);
      for (const emp of empKeys) {
        const p = personOf(emp);
        if (!p || !p.city) continue;
        const home = cityKey(p.city);
        if (!home) continue;
        const rows = byEmp.get(emp);
        const travelDays = new Set(rows.filter((t) => t.travel).map((t) => t.day));
        const hits = rows.filter((t) => t.meal && t.city && cityKey(t.city) === home && !travelDays.has(t.day));
        if (hits.length < minM) continue;
        add("home_city_meals", {
          key: emp, title: "Meals in home city on non-travel days: " + p.name, severity: "low", confidence: "review", category: "Personal-use patterns",
          description: p.name + " has " + hits.length + " meal transaction(s) in their home city (" + p.city + ") on days with no travel spend (threshold " + minM + "), total " + moneyText(sumBy(hits)) + ". Local meals can be legitimate client or team meals; many policies require attendees and purpose for them.",
          recommendation: "Check that each meal lists attendees and a business purpose.",
          controls: [C.acfeMisc, C.coso12],
        }, hits);
      }
    }
  }

  // ---- tables ----
  ctx?.progress?.(1, 1, "tables");
  const SEV = (f) => SEV_RANK[f.severity] ?? 0;
  findings.sort((a, b) => SEV(b) - SEV(a) || cmp(a.category, b.category) || cmp(a.title, b.title) || cmp(a.id, b.id));
  const empFind = new Map();
  for (const f of findings) for (const a of f.assets) { if (!empFind.has(a._k)) empFind.set(a._k, []); empFind.get(a._k).push(f); }
  const primary = (m) => Object.keys(m).sort((a, b) => m[b] - m[a] || cmp(a, b))[0] || "";
  const employees = empKeys.map((k) => {
    const rows = byEmp.get(k), p = personOf(k), fs = empFind.get(k) || [];
    const sums = sumBy(rows), cur = primary(sums);
    const mgr = p && p.managerId ? roster.byId.get(p.managerId.toLowerCase()) : null;
    return {
      key: k, employee: empName.get(k), employeeId: p ? p.id : rows[0].employeeId || "", department: (p && p.department) || rows.find((t) => t.department)?.department || "",
      manager: mgr ? mgr.name : p && p.managerId ? p.managerId : "", status: p ? p.status : "", txns: rows.length,
      totalCents: sums[cur] || 0, currency: cur, total: moneyText(sums), flaggedTxns: rows.filter((t) => t.flags.length).length,
      findings: fs.length, riskScore: Math.min(100, fs.reduce((s, f) => s + (RISK_W[f.severity] || 0), 0)), checks: uniqSorted(fs.map((f) => f.check)).join(", "),
    };
  }).sort((a, b) => b.riskScore - a.riskScore || b.totalCents - a.totalCents || cmp(a.employee, b.employee));
  const empRow = new Map(employees.map((e) => [e.key, e]));
  for (const f of findings) {
    f.assets = f.assets.map((a) => { const e = empRow.get(a._k); return { type: "IDENTITY", name: a.name, data: { department: e ? e.department : "", total: e ? e.total : "", flags: e ? e.findings : 0 } }; });
  }

  const merch = new Map();
  for (const t of act) {
    const k = (t.mk || "(blank)") + "|" + t.mcc;
    if (!merch.has(k)) merch.set(k, { merchant: t.merchant || "(blank)", mcc: t.mcc, rows: 0, emps: new Set(), sums: {}, flags: 0 });
    const m = merch.get(k);
    m.rows++; m.emps.add(t.emp); m.sums[t.currency] = (m.sums[t.currency] || 0) + t.cents; if (t.flags.length) m.flags++;
  }
  const merchantsAll = [...merch.entries()].map(([k, m]) => { const cur = primary(m.sums); return { key: k, merchant: m.merchant, mcc: m.mcc, mccLabel: (BUILTIN_MCC.find((b) => b.mcc === m.mcc) || {}).label || "", txns: m.rows, employees: m.emps.size, totalCents: m.sums[cur] || 0, currency: cur, total: moneyText(m.sums), flags: m.flags }; })
    .sort((a, b) => b.flags - a.flags || b.totalCents - a.totalCents || cmp(a.key, b.key));
  const merchants = merchantsAll.slice(0, MERCHANT_TABLE_CAP);
  if (merchantsAll.length > MERCHANT_TABLE_CAP) skipped.push({ check: "merchants table", reason: "showing the top " + MERCHANT_TABLE_CAP + " of " + merchantsAll.length + " merchants (flagged first, then by spend)" });

  const mon = new Map();
  for (const t of act) {
    const k = monthIso(monthIdx(t.day)) + "|" + t.currency;
    if (!mon.has(k)) mon.set(k, { month: monthIso(monthIdx(t.day)), currency: t.currency, txns: 0, totalCents: 0, flaggedTxns: 0, flaggedCents: 0, emps: new Set() });
    const m = mon.get(k); m.txns++; m.totalCents += t.cents; m.emps.add(t.emp); if (t.flags.length) { m.flaggedTxns++; m.flaggedCents += t.cents; }
  }
  const monthly = [...mon.values()].map((m) => ({ month: m.month, currency: m.currency, txns: m.txns, employees: m.emps.size, totalCents: m.totalCents, total: fmtCents(m.totalCents), flaggedTxns: m.flaggedTxns, flaggedCents: m.flaggedCents, flagged: fmtCents(m.flaggedCents) }))
    .sort((a, b) => cmp(a.month, b.month) || cmp(a.currency, b.currency));

  const followup = employees.filter((e) => e.findings > 0).map((e) => {
    const rows = byEmp.get(e.key).filter((t) => t.flags.length);
    const fs = empFind.get(e.key) || [];
    return { employee: e.employee, employeeId: e.employeeId, manager: e.manager, department: e.department, items: rows.length, amount: moneyText(sumBy(rows)), riskScore: e.riskScore, reasons: uniqSorted(fs.map((f) => f.category)).join("; ") };
  });
  recovery.sort((a, b) => b.recoverableCents - a.recoverableCents || cmp(a.date, b.date) || cmp(a.merchant, b.merchant));

  const total = sumBy(act);
  const primaryCurrency = primary(total);
  const dupAmt = {}; for (const r of recovery) dupAmt[r.currency] = (dupAmt[r.currency] || 0) + r.recoverableCents;
  const bySeverity = {}; for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  const summary = {
    transactions: act.length, rowsLoaded: all.length, linkedReportLines: linked, credits: L.credits, creditsCents: L.creditsCents,
    totalSpend: total, primaryCurrency, totalSpendText: moneyText(total),
    employees: employees.length, flaggedEmployees: followup.length, merchants: merchantsAll.length,
    duplicateAmount: dupAmt, duplicateAmountText: moneyText(dupAmt), duplicateGroups: recovery.length,
    postTerminationSpend: sumBy(postTerm), postTerminationText: moneyText(sumBy(postTerm)), postTerminationTxns: postTerm.length,
    findings: findings.length, bySeverity, rosterSize: roster.size, policyRules: L.policyRows.length,
  };
  skipped.sort((a, b) => cmp(a.check, b.check) || cmp(a.reason, b.reason));
  ctx?.progress?.(1, 1, "done");
  return {
    summary, findings,
    tables: { employees, merchants, monthly, recovery, followup, files },
    skipped,
    meta: { tool: TOOL_ID, version: VERSION, rows: act.length, files: files.map((f) => ({ name: f.name, format: f.format, role: f.role, records: f.records, rejected: f.rejected, confidence: f.confidence })), cardTxnLimit: limit, builtinMcc: !!o.useBuiltinMcc, userMccEntries: userList.entries.length },
  };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "employees", "evidenceCount"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const body = (findings || []).map((f) => [
    f.severity, f.confidence, f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), (f.employees || (f.assets || []).map((a) => a.name)).join("; "),
    f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
  ].map(csvCell).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n") + "\n";
}

/** Employee follow-up list. */
export function followupToCsv(rows) {
  const cols = ["employee", "employeeId", "manager", "department", "items", "amount", "riskScore", "reasons"];
  return [["employee", "employee_id", "manager", "department", "items", "amount", "risk_score", "reasons"].join(","), ...(rows || []).map((r) => cols.map((c) => csvCell(r[c])).join(","))].join("\n") + "\n";
}

/** Duplicate recovery worksheet. */
export function recoveryToCsv(rows) {
  const cols = ["type", "merchant", "date", "amount", "currency", "claims", "recoverable", "employees", "reports", "files"];
  return [cols.join(","), ...(rows || []).map((r) => cols.map((c) => csvCell(r[c])).join(","))].join("\n") + "\n";
}

/** Plain-text summary. */
export function summaryText(r) {
  const s = r.summary;
  const out = [
    "Card Audit summary (" + TOOL_ID + " " + VERSION + ")",
    "These are screens for review, not conclusions.",
    "",
    "Transactions analysed: " + s.transactions + (s.linkedReportLines ? " (" + s.linkedReportLines + " company-card report lines matched to the card feed and counted once)" : ""),
    "Total spend: " + (s.totalSpendText || "0"),
    "Employees: " + s.employees + ", flagged: " + s.flaggedEmployees,
    "Potential duplicate amount: " + (s.duplicateAmountText || "0") + " in " + s.duplicateGroups + " group(s)",
    "Spend after termination: " + (s.postTerminationText || "0") + " (" + s.postTerminationTxns + " transactions)",
    "Findings: " + s.findings + " " + JSON.stringify(s.bySeverity),
    "",
    "Findings:",
    ...r.findings.map((f) => "- [" + f.severity + "/" + f.confidence + "] " + f.title + " (" + f.evidenceCount + " items)\n  " + f.recommendation),
    "",
    "Skipped or limited checks:",
    ...(r.skipped.length ? r.skipped.map((k) => "- " + k.check + ": " + k.reason) : ["- none"]),
  ];
  return out.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example (Brex + SAP Concur + HR roster + policy)
// ---------------------------------------------------------------------------

/** Seeded SYNTHETIC dataset in exact vendor layouts. People at test.darknode.ai. */
export function exampleDataset(seed = 11) {
  let s = seed >>> 0;
  const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const pick = (a) => a[Math.floor(rnd() * a.length)];
  const people = [
    ["E1001", "User 01", "Finance", "Finance Director", "", "2019-03-04", "", "Active"],
    ["E1002", "User 02", "Finance", "Financial Analyst", "E1001", "2021-07-12", "", "Active"],
    ["E1003", "User 03", "IT", "IT Manager", "E1001", "2020-01-06", "", "Active"],
    ["E1004", "User 04", "Marketing", "Marketing Manager", "E1001", "2020-09-14", "", "Active"],
    ["E1005", "User 05", "Marketing", "Events Specialist", "E1004", "2022-02-01", "", "Active"],
    ["E1006", "User 06", "Sales", "Account Executive", "E1007", "2022-05-16", "", "Active"],
    ["E1007", "User 07", "Sales", "Sales Director", "E1001", "2018-11-05", "", "Active"],
    ["E1008", "User 08", "Sales", "Account Executive", "E1007", "2021-03-22", "2026-08-31", "Terminated"],
    ["E1009", "User 09", "Engineering", "Software Engineer", "E1003", "2023-04-03", "", "Active"],
    ["E1010", "User 10", "Engineering", "Software Engineer", "E1003", "2024-01-08", "", "Active"],
  ];
  const email = (n) => n.toLowerCase().replace(" ", "") + "@test.darknode.ai";
  const roster = ["employee_id,name,email,department,title,manager_id,hire_date,termination_date,status",
    ...people.map((p) => [p[0], p[1], email(p[1]), p[2], p[3], p[4], p[5], p[6], p[7]].join(","))].join("\n") + "\n";
  const last4 = { E1001: "4417", E1002: "2290", E1003: "8812", E1004: "5531", E1005: "0764", E1006: "3381", E1007: "9902", E1008: "1146", E1009: "6620", E1010: "7735" };
  const M = [
    ["UNITED AIRLINES", "Airlines", "3000", "Travel", 180, 640],
    ["MARRIOTT HOTELS", "Hotels and Motels", "3509", "Travel", 160, 520],
    ["UBER TRIP", "Taxicabs and Limousines", "4121", "Travel", 12, 64],
    ["SWEETGREEN", "Eating Places and Restaurants", "5812", "Meals", 14, 48],
    ["STARBUCKS", "Fast Food Restaurants", "5814", "Meals", 4, 18],
    ["ADOBE", "Computer Software Stores", "5734", "Software", 20, 90],
    ["STAPLES", "Stationery, Office and School Supply Stores", "5943", "Office Supplies", 15, 140],
    ["FEDEX", "Courier Services", "4215", "Shipping", 18, 95],
  ];
  const H = "Transaction Date,Posted Date,Description,Amount,Currency,Card Holder,Card Last Four,Merchant Category,MCC,Receipt Status,Memo,Category,Department";
  const brex = [];
  const row = (date, posted, desc, amt, holder, id, cat, mcc, rec, memo, category, dept) =>
    [date, posted, csvCell(desc), amt, "USD", holder, last4[id], csvCell(cat), mcc, rec, csvCell(memo), category, dept].join(",");
  const iso = (d) => dayIso(d);
  const startDay = ymd(2026, 3, 2), endDay = ymd(2026, 9, 30);
  for (const p of people) {
    const term = p[6] ? parseWhen(p[6]).day : null;
    for (let d = startDay; d <= endDay; d++) {
      if (isWeekend(d) || rnd() > 0.45) continue;
      if (term != null && d > term) break;
      const m = pick(M.slice(2));
      let cents = Math.round((m[4] + rnd() * (m[5] - m[4])) * 100);
      if (cents % 100 === 0) cents += 37;
      const rec = cents > 7500 && rnd() < 0.06 ? "Missing" : "Submitted";
      brex.push({ d, line: row(iso(d), iso(d + 1), m[0], fmtCents(cents).replace(/,/g, ""), p[1], p[0], m[1], m[2], rec, "", m[3], p[2]) });
    }
  }
  // seeded: travel-heavy month for User 07 (velocity spike)
  for (const [d, mi, a] of [["2026-09-14", 0, "1486.40"], ["2026-09-15", 1, "1142.85"], ["2026-09-21", 0, "1318.22"], ["2026-09-22", 1, "964.31"]]) {
    const m = M[mi];
    brex.push({ d: parseWhen(d).day, line: row(d, d, m[0], a, "User 07", "E1007", m[1], m[2], "Submitted", "Customer roadshow", m[3], "Sales") });
  }
  // seeded: split purchase (User 03, Dell, limit 2,500.00)
  const seed1 = [["2026-08-12", "2412.37"], ["2026-08-12", "2398.90"], ["2026-08-13", "1875.40"]];
  for (const [d, a] of seed1) brex.push({ d: parseWhen(d).day, line: row(d, d, "DELL MARKETING", a, "User 03", "E1003", "Computers, Peripherals and Software", "5045", "Submitted", "Laptops for new hires", "Equipment", "IT") });
  // seeded: duplicate receipt across two employees (User 04 card; User 05 claims it out of pocket)
  brex.push({ d: parseWhen("2026-07-21").day, line: row("2026-07-21", "2026-07-22", "BLUE BOTTLE CATERING", "486.20", "User 04", "E1004", "Caterers", "5811", "Submitted", "Customer workshop lunch", "Meals", "Marketing") });
  // seeded: casino charge
  brex.push({ d: parseWhen("2026-08-22").day, line: row("2026-08-22", "2026-08-24", "BELLAGIO CASINO LAS VEGAS", "1200.00", "User 06", "E1006", "Betting/Casino Gambling", "7995", "Missing", "", "Entertainment", "Sales") });
  // seeded: over policy meal
  brex.push({ d: parseWhen("2026-06-17").day, line: row("2026-06-17", "2026-06-18", "NOBU RESTAURANT", "412.75", "User 06", "E1006", "Eating Places and Restaurants", "5812", "Submitted", "Client dinner", "Meals", "Sales") });
  // seeded: spend after termination
  brex.push({ d: parseWhen("2026-09-04").day, line: row("2026-09-04", "2026-09-05", "BEST BUY 00123", "899.99", "User 08", "E1008", "Electronics Stores", "5732", "Missing", "", "Equipment", "Sales") });
  brex.push({ d: parseWhen("2026-09-11").day, line: row("2026-09-11", "2026-09-12", "APPLE STORE R102", "1299.00", "User 08", "E1008", "Electronics Stores", "5732", "Missing", "", "Equipment", "Sales") });
  brex.sort((a, b) => a.d - b.d || cmp(a.line, b.line));
  const brexCsv = [H, ...brex.map((x) => x.line)].join("\n") + "\n";

  const CH = "Report ID,Report Name,Employee,Employee ID,Expense Type,Transaction Date,Vendor,City,Country,Payment Type,Amount,Currency,Approved Amount,Receipt Received,Approver,Approval Status,Submit Date,Policy";
  const us = (d) => { const [y, m, dd] = d.split("-"); return m + "/" + dd + "/" + y; };
  const cl = (rid, rname, last, first, id, type, date, vendor, city, pay, amt, rec, approver, submit) =>
    [rid, csvCell(rname), csvCell(last + ", " + first), id, type, us(date), csvCell(vendor), city, "US", pay, amt, "USD", amt, rec, csvCell(approver), "Approved", us(submit), "US Employee Policy"].join(",");
  const concur = [
    cl("R-2205", "July customer workshop", "04", "User", "E1004", "Meals", "2026-07-21", "Blue Bottle Catering", "San Francisco", "Corporate Card", "486.20", "Y", "01, User", "2026-07-24"),
    cl("R-2207", "July events", "05", "User", "E1005", "Meals", "2026-07-21", "Blue Bottle Catering", "San Francisco", "Cash", "486.20", "Y", "04, User", "2026-07-28"),
    cl("R-2207", "July events", "05", "User", "E1005", "Office Supplies", "2026-07-23", "Visa Prepaid Gift Card", "San Francisco", "Cash", "500.00", "N", "04, User", "2026-07-28"),
    cl("R-2210", "Client visit Austin", "09", "User", "E1009", "Taxi", "2026-08-05", "Lyft Ride", "Austin", "Personal Card", "38.40", "Y", "03, User", "2026-08-07"),
    cl("R-2215", "August expenses", "09", "User", "E1009", "Taxi", "2026-08-05", "Lyft Ride", "Austin", "Personal Card", "38.40", "Y", "03, User", "2026-08-29"),
    cl("R-2231", "Q3 sales kickoff", "07", "User", "E1007", "Meals", "2026-08-19", "The Capital Grille", "Chicago", "Personal Card", "684.15", "Y", "07, User", "2026-08-21"),
    cl("R-2231", "Q3 sales kickoff", "07", "User", "E1007", "Event Supplies", "2026-08-20", "Party City", "Chicago", "Personal Card", "212.48", "N", "07, User", "2026-08-21"),
    cl("R-2240", "Board dinner", "01", "User", "E1001", "Meals", "2026-09-09", "Zuni Cafe", "San Francisco", "Personal Card", "356.80", "Y", "02, User", "2026-09-11"),
  ].join("\n");
  const concurCsv = CH + "\n" + concur + "\n";
  const policyCsv = "category,limit_per_txn,limit_per_day,currency\nMeals,150.00,250.00,USD\nTaxi,120.00,,USD\n";
  return {
    label: "synthetic example (not real data)",
    files: [
      { name: "example-brex-transactions.csv", text: brexCsv, role: "transactions" },
      { name: "example-concur-expense-report.csv", text: concurCsv, role: "transactions" },
      { name: "example-hr-roster.csv", text: roster, role: "roster" },
      { name: "example-policy-limits.csv", text: policyCsv, role: "policy" },
    ],
    suggestedOpts: { cardTxnLimit: 2500 },
  };
}

// ---------------------------------------------------------------------------
// selfTest
// ---------------------------------------------------------------------------

/** Real deterministic checks of the engine. */
export function selfTest() {
  const tests = [];
  const t = (name, fn) => { let pass = false; try { pass = !!fn(); } catch (_) { pass = false; } tests.push({ name, pass }); };
  const ex = exampleDataset();
  const hol = [{ date: "2026-09-07", name: "Labor Day" }];
  const r = analyze(ex, { ...ex.suggestedOpts, holidays: hol });
  const has = (check, who) => r.findings.some((f) => f.check === check && (!who || f.employees.includes(who)));
  t("parser recognises Brex, Concur, roster and policy layouts", () => r.tables.files.map((f) => f.format).join(",") === "brex,concur,roster,policy");
  t("split purchase detected", () => has("split", "User 03"));
  t("duplicate receipt across two employees detected", () => r.findings.some((f) => f.check === "dup_cross" && f.employees.includes("User 04") && f.employees.includes("User 05")));
  t("7995 casino charge on review list", () => r.findings.some((f) => f.check === "mcc_review" && f.id.endsWith(":7995")));
  t("spend after termination is critical", () => r.findings.some((f) => f.check === "post_termination" && f.severity === "critical"));
  t("self-approved report detected", () => has("self_approval", "User 07"));
  t("split skipped without a card limit", () => analyze(ex, {}).skipped.some((k) => k.check === "split"));
  t("card numbers reduced to last four", () => maskCard("3782 822463 10005") === "****0005" && !JSON.stringify(r).includes("378282246310005"));
  t("money parsed to cents", () => parseCents("$1,234.56") === 123456 && parseCents("(12.30)") === -1230);
  t("empty input yields no findings", () => analyze([], {}).findings.length === 0);
  return { pass: tests.every((x) => x.pass), tests };
}
