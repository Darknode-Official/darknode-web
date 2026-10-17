// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// AP Forensics engine (apforensics). Forensic screens over an accounts-payable ledger
// (QuickBooks Online, Xero, NetSuite, SAP FBL1N, Sage Intacct or a mapped CSV), the vendor
// master (QuickBooks, SAP or mapped) and an optional employee roster: duplicate payments,
// duplicate vendors, vendor/employee identifier matches, split invoices, threshold
// clustering, round-amount bias, sequential invoice numbers, Benford screens, weekend and
// holiday postings, new/blocked vendors, P.O.-box vendors, segregation of duties, spend
// spikes and bank-detail checksums.
//
// These are SCREENS: each finding states the pattern that matched and needs review by an
// accountant or internal auditor. Nothing here is a verdict.
//
// Pure: no DOM, no network, no clock. Money is integer minor units (cents). Bank account
// numbers and tax ids are reduced to a hash (for matching) and the last four characters
// (for display) while parsing; the full values never reach the output.

import { sniff, iterCsv, parseCsv, findColumn, normHeader } from "../ingest/parse.js";
import { cyrb53 } from "../core/hash.js";
import { validateIBAN, validateABA } from "./vendor-engine.js";

export const TOOL_ID = "apforensics";
export const VERSION = "1.0.0";
export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Tunable thresholds; the UI renders these as the thresholds panel. */
export const DEFAULTS = {
  approvalThreshold: null, // currency units; blank = split / threshold checks skipped
  dupWindowDays: 30,       // fuzzy duplicates: same vendor + amount within this many days
  splitDays: 3,            // split invoices: same vendor within this many days
  newVendorDays: 7,        // vendor created -> first payment sooner than this
  spikeZ: 3,               // monthly spend robust z-score (median / MAD)
  spikeMinMonths: 6,       // months of spend history before a vendor is scored
  minVendorInvoices: 10,   // round-amount and sequential-invoice tests per vendor
  roundMinShare: 0.5,      // vendor share of whole-hundred invoices ...
  roundRatio: 3,           // ... and at least this multiple of the ledger share
  seqMinSpanDays: 180,     // sequential invoice numbers spanning at least this long
  benfordMin: 300,         // first-digit test minimum amounts (>= 1.00)
  benfordMinFT: 1000,      // first-two-digit test minimum amounts (>= 10.00)
  dateOrder: "auto",       // auto | mdy | dmy for slash dates
};

export const ROLE_LABEL = { ledger: "AP ledger", vendors: "Vendor master", employees: "Employees" };

/** Recognised exports. `headers` is the vendor's exact column signature. */
export const FORMATS = {
  "qbo-txn-vendor": { vendor: "QuickBooks Online", role: "ledger", label: "QuickBooks Transaction List by Vendor / Bill Payment List (CSV)",
    headers: ["Date", "Transaction Type", "Num", "Posting", "Name", "Memo/Description", "Account", "Split", "Amount", "Balance"] },
  "xero-bills": { vendor: "Xero", role: "ledger", label: "Xero Bills export (CSV)",
    headers: ["ContactName", "EmailAddress", "POAddressLine1", "POAddressLine2", "POAddressLine3", "POAddressLine4", "POCity", "PORegion", "POPostalCode", "POCountry", "InvoiceNumber", "InvoiceDate", "DueDate", "Total", "InventoryItemCode", "Description", "Quantity", "UnitAmount", "AccountCode", "TaxType", "TaxAmount", "TrackingName1", "TrackingOption1", "TrackingName2", "TrackingOption2", "Currency"] },
  "xero-payable": { vendor: "Xero", role: "ledger", label: "Xero Payable Invoice Detail (CSV)",
    headers: ["Contact", "Invoice Date", "Invoice Number", "Reference", "Due Date", "Invoice Total", "Paid", "Due", "Status"] },
  "netsuite-payments": { vendor: "NetSuite", role: "ledger", label: "NetSuite vendor payments saved search (CSV)",
    headers: ["Date", "Type", "Document Number", "Name", "Memo", "Account", "Amount", "Status"] },
  "sap-fbl1n": { vendor: "SAP", role: "ledger", label: "SAP FBL1N vendor line items (CSV)",
    headers: ["Company Code", "Vendor", "Document Number", "Document Type", "Posting Date", "Document Date", "Amount in local currency", "Local Currency", "Reference", "Text", "Clearing Document", "Clearing date", "Payment Method", "User Name"] },
  "sage-intacct-ap": { vendor: "Sage Intacct", role: "ledger", label: "Sage Intacct AP payments (CSV)",
    headers: ["Vendor ID", "Vendor Name", "Bill Number", "Bill Date", "Payment Date", "Payment Method", "Reference Number", "Amount Paid", "Currency", "State"] },
  "generic-ledger": { vendor: "Generic", role: "ledger", label: "Generic AP ledger (CSV, mapped)",
    headers: ["vendor", "vendor_id", "invoice_number", "invoice_date", "payment_date", "amount", "currency", "approver", "entered_by", "po_number", "gl_account", "memo", "payment_method", "bank_account"] },
  "qbo-vendors": { vendor: "QuickBooks Online", role: "vendors", label: "QuickBooks Vendor Contact List (CSV)",
    headers: ["Vendor", "Company name", "Street Address", "City", "State", "ZIP", "Country", "Phone", "Email", "Account #", "Tax ID", "1099 Tracking", "Open Balance"] },
  "sap-vendors": { vendor: "SAP", role: "vendors", label: "SAP vendor master (CSV)",
    headers: ["Vendor", "Name 1", "Street", "City", "Postal Code", "Country", "Tax Number 1", "Bank Key", "Bank Account", "IBAN", "Created On", "Created By", "Central posting block", "Payment block"] },
  "generic-vendors": { vendor: "Generic", role: "vendors", label: "Generic vendor master (CSV, mapped)",
    headers: ["vendor_id", "name", "address", "city", "postal_code", "country", "tax_id", "bank_account", "routing", "iban", "created_date", "created_by", "status", "inactivated_date", "phone", "email"] },
  "generic-employees": { vendor: "Workday / BambooHR / generic", role: "employees", label: "Employee roster (CSV, mapped)",
    headers: ["employee_id", "name", "address", "city", "postal_code", "phone", "email", "bank_account", "routing", "iban", "department", "hire_date", "termination_date"] },
};

/** Column aliases per role: key -> accepted header names (case/punctuation-insensitive). */
export const COLUMNS = {
  ledger: {
    vendor: ["vendor", "vendor name", "name", "payee", "supplier", "supplier name", "contact", "contactname"],
    vendorId: ["vendor_id", "vendor id", "vendor number", "vendor no", "supplier id", "supplier number"],
    invoice: ["invoice_number", "invoice number", "invoice no", "invoice #", "invoice", "bill number", "bill no", "reference", "ref", "num"],
    invoiceDate: ["invoice_date", "invoice date", "bill date", "document date", "doc date"],
    paymentDate: ["payment_date", "payment date", "paid date", "date paid", "check date", "pay date", "clearing date"],
    postingDate: ["posting_date", "posting date", "gl date", "transaction date", "date"],
    amount: ["amount", "amount paid", "payment amount", "invoice amount", "total", "gross", "invoice total", "amount in local currency", "net amount"],
    currency: ["currency", "currency code", "local currency", "curr"],
    approver: ["approver", "approved by", "approver name", "approved_by"],
    enteredBy: ["entered_by", "entered by", "created by", "user name", "user", "preparer", "posted by", "creator"],
    po: ["po_number", "po number", "po", "purchase order", "purchase order number", "po #", "po no"],
    gl: ["gl_account", "gl account", "account", "expense account", "account code"],
    memo: ["memo", "description", "memo/description", "text", "line description"],
    method: ["payment_method", "payment method", "method", "pay method"],
    bank: ["bank_account", "bank account", "payee account", "payee bank account"],
    ref: ["payment_ref", "payment reference", "payment number", "check number", "check no", "document number", "doc number", "clearing document"],
    type: ["type", "transaction type", "document type", "doc type"],
    status: ["status", "state"],
  },
  vendors: {
    vendorId: ["vendor_id", "vendor id", "vendor number", "vendor no", "supplier id", "supplier number", "id"],
    name: ["name", "vendor name", "vendor", "company name", "supplier name", "name 1", "legal name"],
    address: ["address", "street", "street address", "address line 1", "address1", "address_line_1"],
    city: ["city", "town"],
    postal: ["postal_code", "postal code", "zip", "zip code", "postcode"],
    country: ["country", "country code"],
    taxId: ["tax_id", "tax id", "tin", "ein", "tax number", "tax number 1", "vat number", "vat id", "tax registration number"],
    bank: ["bank_account", "bank account", "bank account number", "account number"],
    routing: ["routing", "routing number", "aba", "aba routing", "bank key", "sort code"],
    iban: ["iban"],
    created: ["created_date", "created date", "created on", "date created", "creation date"],
    createdBy: ["created_by", "created by"],
    status: ["status", "active", "vendor status"],
    inactive: ["inactivated_date", "inactivated date", "inactive date", "deactivated date", "inactivation date"],
    phone: ["phone", "phone number", "telephone", "main phone"],
    email: ["email", "e-mail", "email address"],
    paymentBlock: ["payment block", "payment_block", "on hold", "hold"],
    postingBlock: ["central posting block", "posting block", "posting_block"],
  },
  employees: {
    employeeId: ["employee_id", "employee id", "employee #", "employee number", "worker id", "emp id", "employee no"],
    name: ["name", "employee name", "legal name", "full name", "worker", "preferred name"],
    firstName: ["first name", "first_name", "legal first name"],
    lastName: ["last name", "last_name", "legal last name"],
    address: ["address", "address line 1", "address1", "home address", "street", "primary home address", "address_line_1"],
    city: ["city"],
    postal: ["postal_code", "postal code", "zip", "zip code", "postcode"],
    phone: ["phone", "home phone", "mobile phone", "phone number", "mobile", "personal phone"],
    email: ["email", "personal email", "home email", "work email", "email address"],
    bank: ["bank_account", "bank account", "account number", "direct deposit account"],
    routing: ["routing", "routing number", "aba", "bank routing"],
    iban: ["iban"],
    taxId: ["ssn", "tax_id", "tax id", "national id", "national_id", "sin", "social security number"],
    department: ["department", "dept", "cost center", "supervisory organization"],
    hire: ["hire_date", "hire date", "original hire date", "start date"],
    term: ["termination_date", "termination date", "term date", "end date"],
  },
};

/** Human labels for the column-mapping panel. */
export const COLUMN_LABEL = {
  vendor: "Vendor name", vendorId: "Vendor id", invoice: "Invoice number", invoiceDate: "Invoice date", paymentDate: "Payment date", postingDate: "Posting date",
  amount: "Amount", currency: "Currency", approver: "Approver", enteredBy: "Entered by", po: "PO number", gl: "GL account", memo: "Memo", method: "Payment method",
  bank: "Bank account", ref: "Payment / document ref", type: "Transaction type", status: "Status",
  name: "Name", address: "Street address", city: "City", postal: "Postal code", country: "Country", taxId: "Tax id", routing: "Routing / bank key", iban: "IBAN",
  created: "Created date", createdBy: "Created by", inactive: "Inactivated date", phone: "Phone", email: "Email", paymentBlock: "Payment block", postingBlock: "Posting block",
  employeeId: "Employee id", firstName: "First name", lastName: "Last name", department: "Department", hire: "Hire date", term: "Termination date",
};

/** Fixed column maps for recognised vendor layouts (header names exactly as exported). */
const FORMAT_COLS = {
  "qbo-txn-vendor": { postingDate: "Date", type: "Transaction Type", invoice: "Num", vendor: "Name", memo: "Memo/Description", gl: "Split", amount: "Amount" },
  "xero-bills": { vendor: "ContactName", invoice: "InvoiceNumber", invoiceDate: "InvoiceDate", amount: "Total", memo: "Description", gl: "AccountCode", currency: "Currency" },
  "xero-payable": { vendor: "Contact", invoiceDate: "Invoice Date", invoice: "Invoice Number", ref: "Reference", amount: "Invoice Total", status: "Status" },
  "netsuite-payments": { postingDate: "Date", type: "Type", invoice: "Document Number", vendor: "Name", memo: "Memo", gl: "Account", amount: "Amount", status: "Status" },
  "sap-fbl1n": { vendorId: "Vendor", ref: "Document Number", type: "Document Type", postingDate: "Posting Date", invoiceDate: "Document Date", amount: "Amount in local currency",
    currency: "Local Currency", invoice: "Reference", memo: "Text", payRef: "Clearing Document", paymentDate: "Clearing date", method: "Payment Method", enteredBy: "User Name" },
  "sage-intacct-ap": { vendorId: "Vendor ID", vendor: "Vendor Name", invoice: "Bill Number", invoiceDate: "Bill Date", paymentDate: "Payment Date", method: "Payment Method",
    ref: "Reference Number", amount: "Amount Paid", currency: "Currency", status: "State" },
  "qbo-vendors": { name: "Vendor", address: "Street Address", city: "City", postal: "ZIP", country: "Country", phone: "Phone", email: "Email", taxId: "Tax ID" },
  "sap-vendors": { vendorId: "Vendor", name: "Name 1", address: "Street", city: "City", postal: "Postal Code", country: "Country", taxId: "Tax Number 1", routing: "Bank Key",
    bank: "Bank Account", iban: "IBAN", created: "Created On", createdBy: "Created By", postingBlock: "Central posting block", paymentBlock: "Payment block" },
};

// ---------------------------------------------------------------------------
// Controls (cite only what is certain)
// ---------------------------------------------------------------------------
const C = {
  shell: { framework: "ACFE Fraud Tree", id: "Asset Misappropriation > Fraudulent Disbursements > Billing schemes: shell company" },
  nonAcc: { framework: "ACFE Fraud Tree", id: "Asset Misappropriation > Fraudulent Disbursements > Billing schemes: non-accomplice vendor" },
  personal: { framework: "ACFE Fraud Tree", id: "Asset Misappropriation > Fraudulent Disbursements > Billing schemes: personal purchases" },
  coi: { framework: "ACFE Fraud Tree", id: "Corruption > Conflicts of interest" },
  p8: { framework: "COSO 2013", id: "Principle 8 (fraud risk)" },
  p10: { framework: "COSO 2013", id: "Principle 10 (control activities)" },
  p12: { framework: "COSO 2013", id: "Principle 12 (policies and procedures)" },
  sox: { framework: "SOX 404", id: "ITGC segregation of duties" },
  iso: { framework: "ISO27001", id: "A.5.3" },
};

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------
const str = (v) => (v == null ? "" : String(v)).trim();
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const round = (n, d) => { const f = 10 ** d; return Math.round(n * f) / f; };

/** Amount text -> integer cents (sign kept) or null. Handles $, (x), trailing minus, 1.234,56. */
export function toCents(v) {
  if (typeof v === "number") return Number.isFinite(v) ? Math.round(v * 100) : null;
  let t = str(v);
  if (!t) return null;
  let neg = false;
  if (/^\(.*\)$/.test(t)) { neg = true; t = t.slice(1, -1).trim(); }
  if (/-\s*$/.test(t)) { neg = !neg; t = t.replace(/-\s*$/, ""); }
  const firstDigit = t.search(/\d/);
  if (firstDigit < 0) return null;
  if (t.slice(0, firstDigit).includes("-")) neg = !neg;
  t = t.slice(firstDigit).replace(/[^0-9.,]/g, "");
  if (!t) return null;
  const lastDot = t.lastIndexOf("."), lastComma = t.lastIndexOf(",");
  let intPart = t, frac = "";
  if (lastDot >= 0 && lastComma >= 0) {
    const dec = Math.max(lastDot, lastComma);
    intPart = t.slice(0, dec); frac = t.slice(dec + 1);
  } else if (lastComma >= 0) {
    const parts = t.split(",");
    if (parts.length === 2 && /^\d{1,2}$/.test(parts[1])) { intPart = parts[0]; frac = parts[1]; }
  } else if (lastDot >= 0) {
    const parts = t.split(".");
    if (parts.length === 2) { intPart = parts[0]; frac = parts[1]; }
  }
  intPart = intPart.replace(/[.,]/g, "");
  if (!/^\d*$/.test(intPart) || !/^\d*$/.test(frac) || (!intPart && !frac)) return null;
  let cents = Number(intPart || "0") * 100;
  const f = (frac + "000").slice(0, 3);
  cents += Number(f.slice(0, 2));
  if (Number(f[2]) >= 5) cents += 1;
  if (!Number.isSafeInteger(cents)) return null;
  return neg ? -cents : cents;
}

/** Integer cents -> "1,234.56" (with optional currency code prefix). */
export function fmtMoney(cents, cur) {
  if (cents == null || !Number.isFinite(cents)) return "";
  const neg = cents < 0, a = Math.abs(Math.round(cents));
  const whole = String(Math.floor(a / 100)).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const s = (neg ? "-" : "") + whole + "." + String(a % 100).padStart(2, "0");
  return cur ? cur + " " + s : s;
}

const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, sept: 9, oct: 10, nov: 11, dec: 12 };
function mkDay(y, m, d) {
  if (!(y >= 1900 && y <= 2200 && m >= 1 && m <= 12 && d >= 1 && d <= 31)) return null;
  const t = Date.UTC(y, m - 1, d);
  const dt = new Date(t);
  if (dt.getUTCDate() !== d || dt.getUTCMonth() !== m - 1) return null;
  return Math.floor(t / 86400000);
}
/** Date text -> UTC day number. order: auto (M/D/Y unless the first part is > 12) | mdy | dmy. */
export function parseDay(v, order = "auto") {
  const t = str(v);
  if (!t) return null;
  let m = t.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:$|[T\s])/);
  if (m) return mkDay(+m[1], +m[2], +m[3]);
  m = t.match(/^(\d{4})(\d{2})(\d{2})$/);
  if (m) return mkDay(+m[1], +m[2], +m[3]);
  m = t.match(/^(\d{1,2})\.(\d{1,2})\.(\d{2,4})(?:$|\s)/);
  if (m) { let y = +m[3]; if (y < 100) y += 2000; return mkDay(y, +m[2], +m[1]); }
  m = t.match(/^(\d{1,2})[/-](\d{1,2})[/-](\d{2,4})(?:$|[\sT,])/);
  if (m) {
    let y = +m[3]; if (y < 100) y += 2000;
    const a = +m[1], b = +m[2];
    const dmy = order === "dmy" || (order === "auto" && a > 12);
    return dmy ? mkDay(y, b, a) : mkDay(y, a, b);
  }
  m = t.match(/^([A-Za-z]{3,9})\.?\s+(\d{1,2}),?\s+(\d{4})/);
  if (m && MONTHS[m[1].toLowerCase().slice(0, 4)] != null) return mkDay(+m[3], MONTHS[m[1].toLowerCase().slice(0, 4)], +m[2]);
  if (m && MONTHS[m[1].toLowerCase().slice(0, 3)] != null) return mkDay(+m[3], MONTHS[m[1].toLowerCase().slice(0, 3)], +m[2]);
  m = t.match(/^(\d{1,2})[\s-]([A-Za-z]{3,9})\.?[\s-](\d{2,4})/);
  if (m && MONTHS[m[2].toLowerCase().slice(0, 3)] != null) { let y = +m[3]; if (y < 100) y += 2000; return mkDay(y, MONTHS[m[2].toLowerCase().slice(0, 3)], +m[1]); }
  return null;
}
export const dayISO = (d) => (d == null ? "" : new Date(d * 86400000).toISOString().slice(0, 10));
const monthOf = (d) => dayISO(d).slice(0, 7);
const weekday = (d) => (((d + 4) % 7) + 7) % 7; // 0 = Sunday

/** Invoice number normalisation: uppercase, strip #, prefixes (INV, INVOICE, NO, BILL), non-alphanumerics, leading zeros. */
export function normInvoice(v) {
  let s = str(v).toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (!s) return "";
  const p = s.match(/^(INVOICENO|INVOICENR|INVOICE|INVNO|INVNR|INV|BILLNO|BILL|NO|NR)(?=[A-Z0-9]*\d)/);
  if (p) s = s.slice(p[1].length);
  s = s.replace(/^0+(?=.)/, "");
  return s === "0" ? "" : s;
}

const NAME_SUFFIX = new Set(["inc", "incorporated", "llc", "l", "ltd", "limited", "gmbh", "corp", "corporation", "co", "company", "plc", "sa", "ag", "bv", "pty", "lp", "llp", "the", "srl", "sarl", "kg", "oy", "ab", "nv"]);
/** Vendor name normalisation: lowercase, & -> and, drop punctuation and legal-form words. */
export function normName(v) {
  const toks = str(v).toLowerCase().replace(/&/g, " and ").replace(/[^a-z0-9]+/g, " ").trim().split(/\s+/).filter(Boolean);
  const out = toks.filter((t) => !NAME_SUFFIX.has(t));
  return (out.length ? out : toks).join(" ");
}
const ADDR_ABBR = { street: "st", avenue: "ave", road: "rd", suite: "ste", boulevard: "blvd", drive: "dr", lane: "ln", court: "ct", place: "pl", highway: "hwy", parkway: "pkwy", north: "n", south: "s", east: "e", west: "w", floor: "fl", apartment: "apt", unit: "unit" };
export function normAddress(street, postal) {
  const s = str(street).toLowerCase().replace(/[^a-z0-9]+/g, " ").trim().split(/\s+/).filter(Boolean).map((t) => ADDR_ABBR[t] || t).join(" ");
  let p = str(postal).toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (/^\d{9}$/.test(p)) p = p.slice(0, 5);
  return s && p ? s + "|" + p : "";
}
const normPhone = (v) => { const d = str(v).replace(/\D/g, ""); return d.length >= 7 ? d.slice(-10) : ""; };
const normAcct = (v) => { const s = str(v).toUpperCase().replace(/[^A-Z0-9]/g, ""); return s.length >= 4 && /\d/.test(s) && !/^0+$/.test(s) ? s : ""; };
const normTax = (v) => { const s = str(v).toUpperCase().replace(/[^A-Z0-9]/g, ""); return s.length >= 5 && /\d{4}/.test(s) && !/^0+$/.test(s) ? s : ""; };
const normId = (v) => str(v).toUpperCase().replace(/[^A-Z0-9]/g, "").replace(/^0+(?=.)/, "");
const normUser = (v) => str(v).toLowerCase().replace(/^.*\\/, "").replace(/@.*$/, "").replace(/\s+/g, " ").trim();
const last4 = (s) => (s ? "****" + s.slice(-4) : "");
const H = (kind, v) => (v ? cyrb53(kind + ":" + v) : "");
const truthyFlag = (v) => { const s = str(v).toLowerCase(); return !!s && !/^(no|n|false|0|none|-|active)$/.test(s); };

/** Damerau (optimal string alignment) distance, capped: returns 0, 1 or 2 (meaning >= 2). */
export function editDistance1(a, b) {
  if (a === b) return 0;
  const la = a.length, lb = b.length;
  if (Math.abs(la - lb) > 1) return 2;
  if (la === lb) {
    const diff = [];
    for (let i = 0; i < la; i++) if (a[i] !== b[i]) { diff.push(i); if (diff.length > 2) return 2; }
    if (diff.length === 1) return 1;
    if (diff.length === 2 && diff[1] === diff[0] + 1 && a[diff[0]] === b[diff[1]] && a[diff[1]] === b[diff[0]]) return 1;
    return 2;
  }
  const [s, l] = la < lb ? [a, b] : [b, a];
  let i = 0, j = 0, skipped = false;
  while (i < s.length && j < l.length) {
    if (s[i] === l[j]) { i++; j++; continue; }
    if (skipped) return 2;
    skipped = true; j++;
  }
  return 1;
}
/** True when b is a with two adjacent characters swapped. */
export function isTransposition(a, b) {
  if (a.length !== b.length || a === b) return false;
  const diff = [];
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) diff.push(i);
  return diff.length === 2 && diff[1] === diff[0] + 1 && a[diff[0]] === b[diff[1]] && a[diff[1]] === b[diff[0]];
}

function median(sorted) { const n = sorted.length; if (!n) return 0; return n % 2 ? sorted[(n - 1) / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2; }

/** Modified z-scores (Iglewicz & Hoaglin): 0.6745 (x - median) / MAD; MAD = 0 falls back to mean absolute deviation x 1.253314. */
export function robustZ(values) {
  const s = values.slice().sort((a, b) => a - b);
  const med = median(s);
  const dev = values.map((v) => Math.abs(v - med)).sort((a, b) => a - b);
  const mad = median(dev);
  if (mad > 0) return { med, mad, z: values.map((v) => (0.6745 * (v - med)) / mad) };
  const meanAD = dev.reduce((a, b) => a + b, 0) / (dev.length || 1);
  if (meanAD > 0) return { med, mad: 0, z: values.map((v) => (v - med) / (1.253314 * meanAD)) };
  return { med, mad: 0, z: values.map(() => 0) };
}

// ---------------------------------------------------------------------------
// Benford (first digit and first-two digits; Nigrini MAD ranges + chi-square)
// ---------------------------------------------------------------------------
const NIGRINI = { first: [0.006, 0.012, 0.015], firstTwo: [0.0012, 0.0018, 0.0022] };
const CHI_CRIT_05 = { first: 15.507, firstTwo: 112.022 }; // chi-square 0.95 quantile, df 8 and df 89

/**
 * Benford test over cents. test: "first" (amounts >= 1.00, 9 digits) or "firstTwo" (amounts >= 10.00, 10..99).
 * Returns null when n < min. nonconforming = chi-square rejects at 0.05 AND MAD is in Nigrini's nonconformity range.
 */
export function benfordTest(centsList, test, min) {
  const two = test === "firstTwo";
  const lo = two ? 10 : 1, hi = two ? 99 : 9;
  const counts = new Array(hi + 1).fill(0);
  let n = 0;
  for (const c0 of centsList) {
    const c = Math.abs(c0);
    if (c < (two ? 1000 : 100)) continue;
    const s = String(Math.floor(c / 100));
    const d = two ? +s.slice(0, 2) : +s[0];
    counts[d]++; n++;
  }
  if (n < min) return { n, refused: true };
  let mad = 0, chi2 = 0;
  const rows = [];
  for (let d = lo; d <= hi; d++) {
    const p = Math.log10(1 + 1 / d), obs = counts[d] / n, e = p * n;
    mad += Math.abs(obs - p);
    chi2 += ((counts[d] - e) ** 2) / e;
    rows.push({ digits: String(d), count: counts[d], observed: round(obs * 100, 3), expected: round(p * 100, 3) });
  }
  mad /= hi - lo + 1;
  const r = NIGRINI[test];
  const conformity = mad <= r[0] ? "close conformity" : mad <= r[1] ? "acceptable conformity" : mad <= r[2] ? "marginal conformity" : "nonconformity";
  const crit = CHI_CRIT_05[test];
  return { test, n, mad: round(mad, 5), chi2: round(chi2, 2), critical: crit, df: hi - lo, conformity, nonconforming: chi2 > crit && conformity === "nonconformity", rows };
}

// ---------------------------------------------------------------------------
// Detection and classification
// ---------------------------------------------------------------------------
/** Score headers against every exact signature. */
export function classifyHeaders(headers) {
  const have = new Set((headers || []).map(normHeader).filter(Boolean));
  let best = null;
  for (const [key, f] of Object.entries(FORMATS)) {
    const hits = f.headers.filter((h) => have.has(normHeader(h))).length;
    const score = hits / f.headers.length;
    if (!best || score > best.score || (score === best.score && f.headers.length > best.n)) best = { format: key, score, n: f.headers.length };
  }
  if (best && best.score >= 0.85) return { format: best.format, role: FORMATS[best.format].role, confidence: "high", score: round(best.score, 3) };
  if (best && best.score >= 0.6) return { format: best.format, role: FORMATS[best.format].role, confidence: "medium", score: round(best.score, 3) };
  // Alias-based guess for unrecognised layouts.
  const hit = (role, k) => !!findColumn(headers, COLUMNS[role][k]);
  let role = "ledger";
  if (hit("employees", "employeeId") || hit("employees", "hire") || hit("employees", "term")) role = "employees";
  else if (hit("ledger", "amount")) role = "ledger";
  else if (hit("vendors", "name") && (hit("vendors", "taxId") || hit("vendors", "bank") || hit("vendors", "address") || hit("vendors", "created"))) role = "vendors";
  return { format: "generic-" + role, role, confidence: "low", score: best ? round(best.score, 3) : 0 };
}

function lineStarts(text, maxLines) {
  const out = [0];
  let i = 0;
  while (out.length < maxLines) { const j = text.indexOf("\n", i); if (j < 0) break; out.push(j + 1); i = j + 1; }
  return out;
}

/**
 * Detect one file: find the header row (reports such as QuickBooks put title lines first),
 * classify it and return { name, format, role, vendor, label, confidence, headers, offset }.
 */
export function detectFile(file) {
  const name = str(file && file.name) || "input";
  const text = String((file && file.text) || "").replace(/^﻿/, "");
  const base = (format, confidence, headers, offset, score) => ({ name, format, role: FORMATS[format] ? FORMATS[format].role : "ledger", vendor: FORMATS[format] ? FORMATS[format].vendor : "",
    label: FORMATS[format] ? FORMATS[format].label : format, confidence, headers: headers || [], offset: offset || 0, score: score || 0 });
  if (!text.trim()) return base("empty", "low");
  const sn = sniff(text);
  if (sn.format === "json" || sn.format === "ndjson") return base("unsupported-json", "low");
  const starts = lineStarts(text, 40);
  let first = null;
  for (let k = 0; k < starts.length; k++) {
    const end = k + 1 < starts.length ? starts[k + 1] : Math.min(text.length, starts[k] + 8192);
    const line = text.slice(starts[k], end).replace(/\r?\n$/, "");
    if (!line.trim()) continue;
    const { headers } = parseCsv(line);
    const nonEmpty = headers.filter((h) => h).length;
    if (nonEmpty < 3) continue;
    const c = classifyHeaders(headers);
    if (c.confidence !== "low") return base(c.format, c.confidence, headers, starts[k], c.score);
    if (!first) {
      const aliasHits = Object.values(COLUMNS[c.role]).filter((al) => findColumn(headers, al)).length;
      if (aliasHits >= 2) first = { c, headers, offset: starts[k] };
    }
  }
  if (first) return base(first.c.format, "low", first.headers, first.offset, first.c.score);
  const { headers } = parseCsv(text.slice(0, starts[1] || Math.min(text.length, 8192)));
  return base(classifyHeaders(headers).format, "low", headers, 0, 0);
}

/** Column map for one file: fixed for recognised layouts, alias-matched for generic ones, user overrides win. */
export function resolveColumns(format, role, headers, override) {
  const cols = {};
  const fixed = FORMAT_COLS[format];
  const spec = COLUMNS[role];
  for (const k of Object.keys(spec)) {
    const ov = override && override[k];
    if (ov && headers.includes(ov)) { cols[k] = ov; continue; }
    if (override && Object.prototype.hasOwnProperty.call(override, k) && !ov) continue; // explicitly unmapped
    if (fixed) { const h = fixed[k]; if (h) { const real = findColumn(headers, [h]); if (real) cols[k] = real; } continue; }
    const h = findColumn(headers, spec[k]);
    if (h) cols[k] = h;
  }
  if (fixed && fixed.payRef) { const real = findColumn(headers, [fixed.payRef]); if (real) cols.payRef = real; }
  // A generic header used twice (e.g. "date") stays with the first, more specific key.
  return cols;
}

/** Transaction type -> bill | payment | expense | generic | exclude. */
export function kindOf(type) {
  const t = str(type).toLowerCase();
  if (!t) return "generic";
  if (/payment|^check$|^cheque$|^chk$|^kz$|^zp$|^pymt/.test(t)) return "payment";
  if (/credit|refund|deposit|journal|transfer|revers|void|^kg$|^ka$|^sa$|^ab$/.test(t)) return "exclude";
  if (/bill|invoice|^kr$|^re$/.test(t)) return "bill";
  if (/expense|purchase|^check|cash/.test(t)) return "expense";
  return "generic";
}
const VOID_STATUS = /void|cancel|reject|revers|declin/i;

function toFiles(input) {
  if (input == null) return [];
  if (typeof input === "string") return [{ name: "input", text: input }];
  if (!Array.isArray(input) && typeof input === "object" && Array.isArray(input.files)) return toFiles(input.files);
  const list = Array.isArray(input) ? input : [input];
  return list.map((f, i) => (typeof f === "string" ? { name: "file " + (i + 1), text: f } : { name: str(f && f.name) || "file " + (i + 1), text: String((f && f.text) || "") }));
}
function countLines(text) { let n = 0, i = -1; while ((i = text.indexOf("\n", i + 1)) >= 0) n++; return n + 1; }

/**
 * Parse one or more exports ({name,text}[] or one text). Never throws.
 * opts.roles { fileName: ledger|vendors|employees }, opts.treatAs { fileName: format }, opts.columns { fileName: { key: header } }.
 * Returns { sources, ledger, vendors, employees, skipped, format, headers, rows }.
 * Bank and tax values are kept only as hashes + last four characters.
 */
export function parseInput(input, opts = {}, ctx) {
  const o = opts || {};
  const files = toFiles(input);
  const sources = [], skipped = [], ledger = [], vendors = [], employees = [];
  const total = files.reduce((a, f) => a + countLines(f.text), 0);
  let done = 0;
  files.forEach((file) => {
    const text = file.text.replace(/^﻿/, "");
    if (!text.trim()) { skipped.push({ check: "parse", reason: file.name + ": empty file" }); return; }
    const det = detectFile({ name: file.name, text });
    if (det.format === "unsupported-json") { skipped.push({ check: "parse", reason: file.name + ": JSON is not supported; export the report as CSV" }); return; }
    const forced = o.treatAs && FORMATS[o.treatAs[file.name]] ? o.treatAs[file.name] : "";
    let role = (o.roles && ROLE_LABEL[o.roles[file.name]]) ? o.roles[file.name] : forced ? FORMATS[forced].role : det.role;
    let format = forced || det.format;
    if (FORMATS[format].role !== role) format = "generic-" + role;
    const confidence = forced ? "high" : det.confidence;
    const body = text.slice(det.offset);
    const headers = det.headers;
    const cols = resolveColumns(format, role, headers, o.columns && o.columns[file.name]);
    const src = { index: sources.length, name: file.name, format, role, vendor: FORMATS[format].vendor, label: FORMATS[format].label, confidence, headers, columns: cols, rows: 0, records: 0, dropped: {} };
    const drop = (why) => { src.dropped[why] = (src.dropped[why] || 0) + 1; };
    const need = role === "ledger" ? ["amount"] : role === "vendors" ? ["name"] : [];
    if (role === "vendors" && !cols.name && cols.vendorId) need.length = 0;
    if (role === "employees" && !cols.name && !cols.firstName && !cols.employeeId) need.push("name");
    const missing = need.filter((k) => !cols[k]);
    if (missing.length) {
      skipped.push({ check: "parse", reason: file.name + ": no " + missing.map((k) => COLUMN_LABEL[k]).join(", ") + " column could be mapped; map it in the column-mapping panel" });
      src.unusable = true; sources.push(src); return;
    }
    const order = o.dateOrder || DEFAULTS.dateOrder;
    const day = (row, k) => (cols[k] ? parseDay(row[cols[k]], order) : null);
    const get = (row, k) => (cols[k] ? str(row[cols[k]]) : "");
    let section = "";
    const xero = format === "xero-bills" ? new Map() : null;
    const firstKey = headers[0] === "" ? "" : null;
    const headerLine = countLines(text.slice(0, det.offset));
    let i = 0;
    for (const row of iterCsv(body)) {
      i++; done++;
      if (done % 1000 === 0) ctx?.progress?.(done, total, "parsing " + file.name);
      src.rows++;
      const vals = Object.values(row);
      if (!vals.some((x) => str(x))) continue;
      const line = headerLine + i;
      if (role === "ledger") {
        const amtRaw = get(row, "amount");
        if (format === "qbo-txn-vendor") {
          const lead = firstKey != null ? str(row[firstKey]) : "";
          const dRaw = get(row, "postingDate");
          if (!amtRaw && !dRaw && lead && !/^total\b/i.test(lead)) { section = lead; continue; }
          if (!amtRaw && dRaw && parseDay(dRaw, order) == null && !vals.slice(1).some((x) => str(x))) { if (!/^total\b/i.test(dRaw)) section = dRaw; continue; }
          if (/^total\b/i.test(lead) || /^total\b/i.test(dRaw) || /^total\b/i.test(get(row, "type"))) continue;
        }
        const cents0 = toCents(amtRaw);
        if (cents0 == null) { drop("no amount"); continue; }
        if (cents0 === 0) { drop("zero amount"); continue; }
        const type = get(row, "type");
        const kind = kindOf(type);
        if (kind === "exclude") { drop("credit / journal / void type"); continue; }
        if (VOID_STATUS.test(get(row, "status"))) { drop("voided / cancelled status"); continue; }
        const vendor = get(row, "vendor") || section;
        const vendorId = get(row, "vendorId");
        const invoice = get(row, "invoice");
        const bankN = normAcct(get(row, "bank"));
        const rec = {
          src: src.index, file: file.name, line, kind, type,
          vendor, vendorId, vendorIdN: normId(vendorId), vendorN: normName(vendor),
          invoice, invNorm: normInvoice(invoice),
          invDay: day(row, "invoiceDate"), postDay: day(row, "postingDate"), payDay: day(row, "paymentDate"),
          cents: Math.abs(cents0), currency: get(row, "currency").toUpperCase(),
          approver: normUser(get(row, "approver")), enteredBy: normUser(get(row, "enteredBy")),
          po: get(row, "po"), gl: get(row, "gl"), memo: get(row, "memo").slice(0, 80), method: get(row, "method"),
          ref: get(row, "ref"), payRef: cols.payRef ? str(row[cols.payRef]) : "",
          bankH: H("acct", bankN), bank4: last4(bankN),
        };
        rec.day = rec.invDay ?? rec.postDay ?? rec.payDay; rec.paidDay = rec.payDay ?? rec.postDay ?? rec.invDay;
        if (xero) {
          const k = rec.vendorN + "|" + rec.invNorm + "|" + (rec.invoice || "line" + line);
          const prev = xero.get(k);
          if (!prev) xero.set(k, rec);
          // Total repeats on every line of a Xero bill: keep one row per bill.
        } else { ledger.push(rec); src.records++; }
      } else if (role === "vendors") {
        const name = get(row, "name");
        const vendorId = get(row, "vendorId");
        if (!name && !vendorId) { drop("no name or id"); continue; }
        const bankN = normAcct(get(row, "bank")), ibanN = str(get(row, "iban")).toUpperCase().replace(/\s+/g, ""), taxN = normTax(get(row, "taxId"));
        const routing = get(row, "routing").replace(/[\s-]/g, "");
        const street = get(row, "address");
        const status = get(row, "status");
        const rec = {
          src: src.index, file: file.name, line, vendorId, vendorIdN: normId(vendorId), name: name || vendorId, nameN: normName(name || vendorId),
          street, city: get(row, "city"), postal: get(row, "postal"), country: get(row, "country").toUpperCase(),
          addrH: H("addr", normAddress(street, get(row, "postal"))), phoneH: H("ph", normPhone(get(row, "phone"))), hasPhone: !!normPhone(get(row, "phone")), phoneCol: !!cols.phone,
          email: get(row, "email").toLowerCase(),
          taxH: H("tax", taxN), tax4: last4(taxN),
          bankH: H("acct", bankN), bank4: last4(bankN), routing, routingH: H("rt", routing),
          ibanH: H("iban", ibanN.length >= 15 ? ibanN : ""), iban4: last4(ibanN.length >= 15 ? ibanN : ""),
          created: day(row, "created"), createdBy: normUser(get(row, "createdBy")),
          inactive: day(row, "inactive"), statusInactive: /inactive|disabled|blocked|deleted/i.test(status),
          paymentBlock: cols.paymentBlock ? truthyFlag(row[cols.paymentBlock]) : false, postingBlock: cols.postingBlock ? truthyFlag(row[cols.postingBlock]) : false,
        };
        // Checksum results are computed now so the raw IBAN / routing never leave this function.
        rec.ibanCheck = ibanN ? validateIBAN(ibanN) : null;
        rec.abaCheck = routing && /^\d{9}$/.test(routing) && (!rec.country || /^(US|USA|UNITED STATES)$/.test(rec.country)) ? validateABA(routing) : null;
        rec.routing = routing ? last4(routing) : "";
        vendors.push(rec); src.records++;
      } else {
        const name = get(row, "name") || [get(row, "firstName"), get(row, "lastName")].filter(Boolean).join(" ");
        const employeeId = get(row, "employeeId");
        if (!name && !employeeId) { drop("no name or id"); continue; }
        const bankN = normAcct(get(row, "bank")), ibanN = str(get(row, "iban")).toUpperCase().replace(/\s+/g, ""), taxN = normTax(get(row, "taxId"));
        employees.push({
          src: src.index, file: file.name, line, employeeId, name: name || employeeId, email: get(row, "email").toLowerCase(), department: get(row, "department"),
          addrH: H("addr", normAddress(get(row, "address"), get(row, "postal"))), phoneH: H("ph", normPhone(get(row, "phone"))),
          bankH: H("acct", bankN), bank4: last4(bankN), routingH: H("rt", get(row, "routing").replace(/[\s-]/g, "")),
          ibanH: H("iban", ibanN.length >= 15 ? ibanN : ""), iban4: last4(ibanN.length >= 15 ? ibanN : ""),
          taxH: H("tax", taxN), tax4: last4(taxN),
          hire: day(row, "hire"), term: day(row, "term"),
        });
        src.records++;
      }
    }
    if (xero) for (const rec of xero.values()) { ledger.push(rec); src.records++; }
    if (!src.records) skipped.push({ check: "parse", reason: file.name + ": no usable rows (" + (Object.entries(src.dropped).map(([k, v]) => v + " " + k).join(", ") || "empty after the header") + ")" });
    sources.push(src);
  });
  ctx?.progress?.(total, total, "parsed");
  const first = sources[0];
  return { sources, ledger, vendors, employees, skipped, format: first ? first.format : "empty", headers: first ? first.headers : [], rows: ledger };
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
const RISK_WEIGHT = {
  "exact duplicate": 30, "possible duplicate": 15, "duplicate vendor record": 10, "employee match": 40, "split invoices": 15, "under-threshold cluster": 5,
  "round amounts": 10, "sequential invoices": 10, "benford": 5, "new vendor paid fast": 15, "paid after inactivation": 25, "blocked vendor paid": 25,
  "P.O. box address": 10, "segregation of duties": 15, "spend spike": 10, "invalid bank details": 5, "missing invoice / PO": 5, "weekend / holiday": 2,
};

function holidayMap(h) {
  if (!h) return null;
  const list = Array.isArray(h) ? h : Array.isArray(h.data) ? h.data : null;
  if (!list) return null;
  const m = new Map();
  for (const x of list) {
    const d = typeof x === "string" ? x : x && x.date;
    const day = parseDay(d);
    if (day != null) m.set(day, typeof x === "string" ? "federal holiday" : str(x.name) || "federal holiday");
  }
  if (!m.size) return null;
  const years = [...m.keys()].map((d) => +dayISO(d).slice(0, 4));
  return { map: m, from: Math.min(...years), to: Math.max(...years), version: h && !Array.isArray(h) ? str(h.version) : "" };
}

/**
 * Analyze AP exports. dataset: {name,text}[] | text | { files }. opts overrides DEFAULTS plus
 * roles / treatAs / columns (see parseInput), holidays (us-holidays.json envelope or list), now (ISO).
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  const p = parseInput(dataset, o, ctx);
  const skipped = p.skipped.slice();
  const findings = [];
  const ledgerSources = p.sources.filter((s) => s.role === "ledger" && !s.unusable);
  const recs = p.ledger;
  const master = p.vendors, emps = p.employees;
  const nAll = recs.length;
  ctx?.progress?.(0, 1, "analyzing");

  // Population (invoices/disbursements for pattern tests) and paid set (what left the bank).
  const bySrc = new Map();
  for (const r of recs) { if (!bySrc.has(r.src)) bySrc.set(r.src, []); bySrc.get(r.src).push(r); }
  const pop = [], paid = [];
  const basis = [];
  for (const [si, list] of [...bySrc.entries()].sort((a, b) => a[0] - b[0])) {
    const hasBills = list.some((r) => r.kind === "bill"), hasPay = list.some((r) => r.kind === "payment");
    for (const r of list) if (!(hasBills && r.kind === "payment")) pop.push(r);
    let pset;
    if (hasPay) { pset = list.filter((r) => r.kind !== "bill"); basis.push(p.sources[si].name + ": payment rows"); }
    else if (list.some((r) => r.payDay != null)) { pset = list.filter((r) => r.payDay != null); basis.push(p.sources[si].name + ": rows with a payment / clearing date"); }
    else { pset = list; basis.push(p.sources[si].name + ": all rows (no payment rows or payment dates in this export)"); }
    for (const r of pset) paid.push(r);
  }

  // Vendor master index and ledger -> vendor linking.
  const mById = new Map(), mByName = new Map();
  master.forEach((m, i) => {
    m.idx = i;
    m.key = m.vendorIdN ? "id:" + m.vendorIdN : "n:" + m.nameN;
    if (m.vendorIdN && !mById.has(m.vendorIdN)) mById.set(m.vendorIdN, m);
    if (m.nameN) { if (!mByName.has(m.nameN)) mByName.set(m.nameN, []); mByName.get(m.nameN).push(m); }
  });
  const V = new Map(); // vkey -> vendor aggregate
  const vOf = (r) => {
    let m = r.vendorIdN ? mById.get(r.vendorIdN) : null;
    if (!m && r.vendorN && mByName.has(r.vendorN) && mByName.get(r.vendorN).length === 1) m = mByName.get(r.vendorN)[0];
    const key = m ? m.key : r.vendorIdN ? "id:" + r.vendorIdN : "n:" + (r.vendorN || "(blank)");
    let v = V.get(key);
    if (!v) { v = { key, master: m || null, name: m ? m.name : r.vendor || r.vendorId || "(no vendor)", vendorId: m ? m.vendorId : r.vendorId, invoices: 0, payments: 0, totals: {}, first: null, last: null, flags: new Set(), pop: [], paid: [] }; V.set(key, v); }
    else if (!v.master && !v.name && r.vendor) v.name = r.vendor;
    return v;
  };
  for (const r of recs) { r.v = vOf(r); }
  for (const r of pop) { r.v.invoices++; r.v.pop.push(r); }
  for (const r of paid) {
    const v = r.v; v.payments++; v.paid.push(r);
    v.totals[r.currency] = (v.totals[r.currency] || 0) + r.cents;
    const d = r.paidDay;
    if (d != null) { if (v.first == null || d < v.first) v.first = d; if (v.last == null || d > v.last) v.last = d; }
  }
  for (const m of master) { if (!V.has(m.key)) V.set(m.key, { key: m.key, master: m, name: m.name, vendorId: m.vendorId, invoices: 0, payments: 0, totals: {}, first: null, last: null, flags: new Set(), pop: [], paid: [] }); }
  const vname = (v) => v.name + (v.vendorId && v.vendorId !== v.name ? " (" + v.vendorId + ")" : "");
  const flag = (v, f) => { if (v) v.flags.add(f); };
  const cur = (r) => r.currency;
  const ev = (r) => ({ vendor: vname(r.v), invoice: r.invoice, invoiceDate: dayISO(r.invDay), postingDate: dayISO(r.postDay), paymentDate: dayISO(r.payDay), amount: fmtMoney(r.cents, cur(r)),
    ref: [r.ref, r.payRef].filter(Boolean).join(" / "), enteredBy: r.enteredBy, approver: r.approver, file: r.file, line: r.line });
  const anyCol = (k) => ledgerSources.some((s) => s.columns[k]);
  const srcHas = (r, k) => !!p.sources[r.src].columns[k];
  const sortRecs = (a, b) => (a.day ?? 1e9) - (b.day ?? 1e9) || a.src - b.src || a.line - b.line;
  const F = [];
  const add = (id, f, vkeys, extraAssets) => { F.push({ id, f, vkeys: vkeys || [], extraAssets: extraAssets || [] }); };

  if (!recs.length) skipped.push({ check: "ledger", reason: "no AP ledger rows loaded; ledger checks need a payment or invoice export" });

  // ---- Duplicates -------------------------------------------------------
  const dupRows = [];
  const atRiskBy = {};
  const risk = (r) => { atRiskBy[cur(r)] = (atRiskBy[cur(r)] || 0) + r.cents; };
  const pairRow = (kind, a, b, reason, confidence, counts) => {
    const row = { kind, confidence, vendor: vname(a.v), vendorB: a.v === b.v ? "" : vname(b.v), invoice: a.invoice, invoiceB: b.invoice,
      invoiceDate: dayISO(a.invDay), invoiceDateB: dayISO(b.invDay), paymentDate: dayISO(a.paidDay), paymentDateB: dayISO(b.paidDay),
      amountCents: b.cents, amount: fmtMoney(b.cents, cur(b)), currency: cur(b), ref: [a.ref, a.payRef].filter(Boolean).join(" / "), refB: [b.ref, b.payRef].filter(Boolean).join(" / "),
      reason, atRiskCents: counts ? b.cents : 0, lineA: a.file + ":" + a.line, lineB: b.file + ":" + b.line };
    if (counts) risk(b);
    dupRows.push(row);
    return row;
  };
  if (!anyCol("invoice")) skipped.push({ check: "duplicate_payments", reason: "no invoice number column in the ledger; duplicate tests need one" });
  else {
    const exact = new Map();
    for (const r of pop) if (r.invNorm) { const k = cur(r) + "|" + r.v.key + "|" + r.invNorm + "|" + r.cents; if (!exact.has(k)) exact.set(k, []); exact.get(k).push(r); }
    const exactRows = [], exactV = new Set(), inExact = new Set();
    for (const g of exact.values()) {
      if (g.length < 2) continue;
      g.sort(sortRecs);
      for (let i = 1; i < g.length; i++) { exactRows.push(pairRow("exact", g[0], g[i], "same vendor, invoice number (normalized " + g[0].invNorm + ") and amount", "confirmed", true)); inExact.add(g[i]); }
      for (const r of g) inExact.add(r);
      exactV.add(g[0].v.key); flag(g[0].v, "exact duplicate");
    }
    if (exactRows.length) {
      const amt = exactRows.reduce((a, r) => ((a[r.currency] = (a[r.currency] || 0) + r.amountCents), a), {});
      add("dup_exact", { title: "Exact duplicate payments", severity: "high", confidence: "confirmed", category: "duplicate payment",
        description: exactRows.length + " invoice(s) appear more than once with the same vendor, the same normalized invoice number and the same amount (" + Object.entries(amt).map(([c, v]) => fmtMoney(v, c)).join("; ") + " in the later copies). Pattern consistent with a duplicate payment; confirm against the bank statement before recovery.",
        recommendation: "Confirm each pair against the bank statement, request a credit or refund from the vendor, and turn on duplicate-invoice blocking (vendor + invoice number + amount) in the AP system.",
        controls: [C.nonAcc, C.p10, C.p12], evidence: exactRows.map(dupEv) }, [...exactV]);
    }
    // Fuzzy: same vendor + amount within window, invoice numbers one edit apart or transposed.
    const byVA = new Map();
    for (const r of pop) if (r.invNorm && !inExact.has(r)) { const k = cur(r) + "|" + r.v.key + "|" + r.cents; if (!byVA.has(k)) byVA.set(k, []); byVA.get(k).push(r); }
    const trans = [], edit = [], tV = new Set(), eV = new Set();
    for (const g of byVA.values()) {
      if (g.length < 2) continue;
      g.sort(sortRecs);
      for (let i = 0; i < g.length; i++) for (let j = i + 1; j < g.length; j++) {
        const a = g[i], b = g[j];
        if (a.day != null && b.day != null && b.day - a.day > o.dupWindowDays) break;
        if (a.invNorm === b.invNorm) continue;
        if (isTransposition(a.invNorm, b.invNorm)) { trans.push(pairRow("transposed", a, b, "same vendor and amount within " + o.dupWindowDays + " days; invoice numbers are transpositions (" + a.invNorm + " / " + b.invNorm + ")", "likely", true)); tV.add(a.v.key); flag(a.v, "possible duplicate"); }
        else if (editDistance1(a.invNorm, b.invNorm) === 1 && a.invNorm.length >= 3) { edit.push(pairRow("one-edit", a, b, "same vendor and amount within " + o.dupWindowDays + " days; invoice numbers one character apart (" + a.invNorm + " / " + b.invNorm + ")", "review", false)); eV.add(a.v.key); flag(a.v, "possible duplicate"); }
      }
    }
    if (trans.length) add("dup_transposed", { title: "Possible duplicate payments: transposed invoice digits", severity: "high", confidence: "likely", category: "duplicate payment",
      description: trans.length + " pair(s) with the same vendor and amount within " + o.dupWindowDays + " days whose invoice numbers differ only by two swapped adjacent characters, a common keying error that bypasses exact duplicate checks.",
      recommendation: "Pull both invoices; if they are the same document, recover the later payment and add fuzzy invoice matching to the AP duplicate check.",
      controls: [C.nonAcc, C.p10, C.p12], evidence: trans.map(dupEv) }, [...tV]);
    if (edit.length) add("dup_one_edit", { title: "Possible duplicate payments: invoice numbers one character apart", severity: "medium", confidence: "review", category: "duplicate payment",
      description: edit.length + " pair(s) with the same vendor and amount within " + o.dupWindowDays + " days whose invoice numbers differ by one character. Recurring fixed-price bills also match this pattern; review each pair.",
      recommendation: "Compare the invoice documents; recurring contract bills can be closed as expected, the rest treated as possible duplicates.",
      controls: [C.nonAcc, C.p10], evidence: edit.map(dupEv) }, [...eV]);
  }

  // ---- Vendor master duplicates ----------------------------------------
  const clusterOf = new Map();
  if (!master.length) skipped.push({ check: "vendor_master", reason: "no vendor master loaded; duplicate-vendor, new-vendor, block, P.O. box, bank-checksum and segregation-of-duties checks need one" });
  else {
    const parent = master.map((_, i) => i);
    const find = (i) => { while (parent[i] !== i) { parent[i] = parent[parent[i]]; i = parent[i]; } return i; };
    const why = new Map();
    const link = (field, label) => {
      const idx = new Map();
      master.forEach((m, i) => { const k = m[field]; if (!k) return; if (!idx.has(k)) idx.set(k, []); idx.get(k).push(i); });
      for (const list of idx.values()) {
        if (list.length < 2) continue;
        for (let t = 1; t < list.length; t++) {
          const a = find(list[0]), b = find(list[t]); if (a !== b) parent[Math.max(a, b)] = Math.min(a, b);
          for (const i of [list[0], list[t]]) { if (!why.has(i)) why.set(i, new Set()); why.get(i).add(label); }
        }
      }
    };
    link("taxH", "same tax id"); link("bankH", "same bank account"); link("ibanH", "same IBAN"); link("addrH", "same address and postal code"); link("nameN", "same normalized name");
    const groups = new Map();
    master.forEach((m, i) => { const r = find(i); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(m); });
    const rows = [], gv = [];
    let gi = 0;
    for (const g of [...groups.values()].filter((g) => g.length > 1).sort((a, b) => a[0].idx - b[0].idx)) {
      gi++;
      for (const m of g) {
        const reasons = [...(why.get(m.idx) || [])].sort();
        rows.push({ group: gi, vendor: m.name, vendorId: m.vendorId, taxId: m.tax4, bankAccount: m.bank4 || m.iban4, matchedOn: reasons.join(", "), created: dayISO(m.created), file: m.file, line: m.line });
        clusterOf.set(m.key, gi);
        const v = V.get(m.key); flag(v, "duplicate vendor record"); gv.push(m.key);
      }
    }
    if (rows.length) add("vendor_dupes", { title: "Duplicate vendor records in the vendor master", severity: "medium", confidence: "review", category: "vendor master",
      description: gi + " group(s) of vendor records share a tax id, bank account, IBAN, address or normalized name. Duplicate records let the same invoice be paid twice under different vendor ids and can hide a shell vendor behind a real one.",
      recommendation: "Merge or block the redundant records, keep one vendor id per legal entity, and require a duplicate search before a new vendor is created.",
      controls: [C.shell, C.nonAcc, C.p10, C.p12], evidence: rows }, gv);
  }
  // Same invoice + amount paid under two vendor ids that are the same vendor.
  if (anyCol("invoice") && recs.length) {
    const byIA = new Map();
    for (const r of pop) if (r.invNorm) { const k = cur(r) + "|" + r.invNorm + "|" + r.cents; if (!byIA.has(k)) byIA.set(k, []); byIA.get(k).push(r); }
    const rows = [], vs = new Set();
    for (const g of byIA.values()) {
      if (g.length < 2) continue;
      g.sort(sortRecs);
      for (let i = 0; i < g.length; i++) for (let j = i + 1; j < g.length; j++) {
        const a = g[i], b = g[j];
        if (a.v === b.v) continue;
        const sameName = normName(a.v.name) === normName(b.v.name);
        const sameCluster = clusterOf.has(a.v.key) && clusterOf.get(a.v.key) === clusterOf.get(b.v.key);
        if (!sameName && !sameCluster) continue;
        rows.push(pairRow("cross-vendor", a, b, "same invoice number and amount paid to two vendor records that " + (sameCluster ? "share master data" : "have the same normalized name"), "likely", true));
        vs.add(a.v.key); vs.add(b.v.key); flag(a.v, "possible duplicate"); flag(b.v, "possible duplicate");
      }
    }
    if (rows.length) add("dup_cross_vendor", { title: "Same invoice paid to two vendor records", severity: "high", confidence: "likely", category: "duplicate payment",
      description: rows.length + " invoice(s) with the same number and amount were recorded against two vendor ids that appear to be one vendor. Pattern consistent with a duplicate payment through a duplicate vendor record.",
      recommendation: "Confirm with the vendor statement, recover the second payment and merge the vendor records.",
      controls: [C.nonAcc, C.shell, C.p10], evidence: rows.map(dupEv) }, [...vs]);
  }

  // ---- Vendor <-> employee ---------------------------------------------
  const empMatches = [];
  if (!emps.length) skipped.push({ check: "vendor_employee", reason: "no employee roster loaded; vendor/employee matching needs one" });
  else if (!master.length && !recs.some((r) => r.bankH)) skipped.push({ check: "vendor_employee", reason: "no vendor master and no bank account column in the ledger to compare with employees" });
  else {
    const fields = [["bankH", "bank account", "bank4"], ["ibanH", "IBAN", "iban4"], ["taxH", "tax id", "tax4"], ["addrH", "address and postal code", null], ["phoneH", "phone", null]];
    const idx = {};
    for (const [f] of fields) { idx[f] = new Map(); emps.forEach((e) => { if (e[f]) { if (!idx[f].has(e[f])) idx[f].set(e[f], []); idx[f].get(e[f]).push(e); } }); }
    const pairs = new Map();
    const note = (vkey, vlabel, e, what) => {
      const k = vkey + "|" + e.src + ":" + e.line;
      if (!pairs.has(k)) pairs.set(k, { vkey, vlabel, e, on: new Set() });
      pairs.get(k).on.add(what);
    };
    for (const m of master) for (const [f, label, l4] of fields) {
      if (!m[f] || !idx[f].has(m[f])) continue;
      for (const e of idx[f].get(m[f])) {
        if (f === "bankH" && m.routingH && e.routingH && m.routingH !== e.routingH) continue;
        note(m.key, vname(V.get(m.key)), e, label + (l4 ? " " + m[l4] : ""));
      }
    }
    for (const r of recs) if (r.bankH && idx.bankH.has(r.bankH)) for (const e of idx.bankH.get(r.bankH)) note(r.v.key, vname(r.v), e, "ledger payee bank account " + r.bank4);
    const rows = [], vs = new Set(), ids = [];
    for (const x of [...pairs.values()].sort((a, b) => cmp(a.vlabel, b.vlabel) || cmp(a.e.name, b.e.name))) {
      const v = V.get(x.vkey);
      rows.push({ vendor: x.vlabel, employee: x.e.name, employeeId: x.e.employeeId, department: x.e.department, matchedOn: [...x.on].sort().join(", "),
        employeeStatus: x.e.term != null ? "terminated " + dayISO(x.e.term) : "active", vendorTotalPaid: v ? totalsStr(v.totals) : "" });
      vs.add(x.vkey); flag(v, "employee match");
      ids.push({ type: "IDENTITY", name: x.e.email || x.e.name, data: { employeeId: x.e.employeeId, department: x.e.department, matchedVendor: x.vlabel } });
      empMatches.push(x);
    }
    if (rows.length) add("vendor_employee", { title: "Vendor shares identifiers with an employee", severity: "high", confidence: "likely", category: "conflict of interest",
      description: rows.length + " vendor/employee pair(s) share a bank account, IBAN, tax id, address or phone number. Pattern consistent with an undisclosed conflict of interest or a shell vendor controlled by an employee; a shared phone or address can also be a family member or a legitimate disclosed relationship.",
      recommendation: "Review each pair with HR and the vendor owner, obtain conflict-of-interest disclosures, verify the vendor's legal existence (registry, tax id) and freeze payments until cleared.",
      controls: [C.coi, C.shell, C.p8, C.p10], evidence: rows }, [...vs], ids);
  }

  // ---- Split invoices / threshold clustering ----------------------------
  const thr = o.approvalThreshold == null || o.approvalThreshold === "" ? null : Number(o.approvalThreshold);
  if (thr == null || !Number.isFinite(thr) || thr <= 0) {
    skipped.push({ check: "split_invoices", reason: "approval threshold is blank; enter your approval limit to test for split invoices and clustering under it" });
  } else if (recs.length) {
    const T = Math.round(thr * 100);
    const rows = [], vs = new Set();
    const byV = new Map();
    for (const r of pop) if (r.day != null) { const k = cur(r) + "|" + r.v.key; if (!byV.has(k)) byV.set(k, []); byV.get(k).push(r); }
    for (const list of byV.values()) {
      list.sort(sortRecs);
      let i = 0;
      while (i < list.length) {
        let j = i, sum = 0;
        const items = [];
        while (j < list.length && list[j].day - list[i].day <= o.splitDays) { if (list[j].cents < T) { items.push(list[j]); sum += list[j].cents; } j++; }
        if (items.length >= 2 && sum > T) {
          rows.push({ vendor: vname(items[0].v), invoices: items.map((r) => r.invoice || "(none)").join(", "), from: dayISO(items[0].day), to: dayISO(items[items.length - 1].day), count: items.length,
            largest: fmtMoney(Math.max(...items.map((r) => r.cents)), cur(items[0])), total: fmtMoney(sum, cur(items[0])), threshold: fmtMoney(T, cur(items[0])) });
          vs.add(items[0].v.key); flag(items[0].v, "split invoices");
          i = j;
        } else i++;
      }
    }
    if (rows.length) add("split_invoices", { title: "Invoices split below the approval threshold", severity: "medium", confidence: "review", category: "split invoices",
      description: rows.length + " cluster(s) of invoices from one vendor within " + o.splitDays + " days, each below the " + fmtMoney(T) + " approval threshold, whose combined amount exceeds it. Pattern consistent with splitting a purchase to avoid the higher approval.",
      recommendation: "Check whether each cluster is one purchase; if so, route it through the approval it avoided and remind requesters that splitting is prohibited.",
      controls: [C.personal, C.p10, C.p12], evidence: rows }, [...vs]);
    // Histogram spike just under the threshold.
    let near = 0, below = 0, above = 0;
    const nearRecs = [];
    for (const r of pop) {
      if (r.cents >= Math.round(T * 0.9) && r.cents < T) { near++; nearRecs.push(r); }
      else if (r.cents >= Math.round(T * 0.8) && r.cents < Math.round(T * 0.9)) below++;
      else if (r.cents >= T && r.cents < Math.round(T * 1.1)) above++;
    }
    const base = Math.max(1, (below + above) / 2);
    if (near >= 5 && near >= 2 * base) {
      const byVendor = new Map();
      for (const r of nearRecs) byVendor.set(r.v.key, (byVendor.get(r.v.key) || 0) + 1);
      add("threshold_spike", { title: "Spike of invoices just under the approval threshold", severity: "medium", confidence: "review", category: "split invoices",
        description: near + " invoice(s) fall within 90-99.99% of the " + fmtMoney(T) + " threshold, against " + below + " in the 80-90% band and " + above + " in the 100-110% band (" + round(near / base, 1) + "x the neighbouring average). Amounts that bunch just under an approval limit are consistent with threshold avoidance.",
        recommendation: "Review the listed invoices by requester and vendor; consider lowering the limit for vendors that concentrate here.",
        controls: [C.personal, C.p8, C.p10], evidence: nearRecs.sort(sortRecs).map(ev) }, [...byVendor.keys()]);
    }
  }

  // ---- Round amounts -----------------------------------------------------
  if (pop.length) {
    const isRound = (c) => c >= 10000 && c % 10000 === 0;
    const all = pop.filter((r) => isRound(r.cents)).length;
    const p0 = all / pop.length;
    const rows = [], vs = new Set();
    for (const v of [...V.values()]) {
      const n = v.pop.length;
      if (n < o.minVendorInvoices) continue;
      const k = v.pop.filter((r) => isRound(r.cents)).length;
      const pv = k / n;
      if (pv >= o.roundMinShare && pv >= o.roundRatio * p0) {
        rows.push({ vendor: vname(v), invoices: n, roundInvoices: k, vendorShare: round(pv * 100, 1) + "%", ledgerShare: round(p0 * 100, 1) + "%", total: totalsStr(v.totals) });
        vs.add(v.key); flag(v, "round amounts");
      }
    }
    if (rows.length) add("round_amounts", { title: "Round-amount bias by vendor", severity: "low", confidence: "review", category: "vendor pattern",
      description: rows.length + " vendor(s) with at least " + o.minVendorInvoices + " invoices bill whole hundreds in " + Math.round(o.roundMinShare * 100) + "% or more of invoices and at least " + o.roundRatio + "x the ledger rate (" + round(p0 * 100, 1) + "%). Fixed-fee contracts explain some; invented invoices also tend to be round.",
      recommendation: "Match the vendor's invoices to a contract or rate card and confirm goods or services were received.",
      controls: [C.shell, C.p8], evidence: rows }, [...vs]);
  }

  // ---- Sequential invoice numbers ---------------------------------------
  if (anyCol("invoice") && pop.length) {
    const rows = [], vs = new Set();
    for (const v of [...V.values()]) {
      const list = v.pop.filter((r) => r.day != null && /\d{3,}$/.test(r.invNorm)).sort(sortRecs);
      if (list.length < o.minVendorInvoices) continue;
      const nums = list.map((r) => Number(r.invNorm.match(/(\d{3,})$/)[1].slice(-9)));
      const span = list[list.length - 1].day - list[0].day;
      if (span < o.seqMinSpanDays) continue;
      let inc = 0;
      for (let i = 1; i < nums.length; i++) if (nums[i] > nums[i - 1]) inc++;
      const mono = inc / (nums.length - 1);
      const range = Math.max(...nums) - Math.min(...nums);
      const step = range / (nums.length - 1);
      if (mono >= 0.9 && step <= 2) {
        rows.push({ vendor: vname(v), invoices: list.length, firstInvoice: list[0].invoice, lastInvoice: list[list.length - 1].invoice, firstDate: dayISO(list[0].day), lastDate: dayISO(list[list.length - 1].day), spanDays: span, averageStep: round(step, 2) });
        vs.add(v.key); flag(v, "sequential invoices");
      }
    }
    if (rows.length) add("sequential_invoices", { title: "Sequential invoice numbers over a long period", severity: "medium", confidence: "review", category: "vendor pattern",
      description: rows.length + " vendor(s) issued invoice numbers that rise by about one per invoice over " + o.seqMinSpanDays + "+ days, so your company may be the vendor's only customer. Consistent with a shell vendor; also normal for small sole-trader suppliers.",
      recommendation: "Verify the vendor's legal existence, physical address and other customers; confirm goods or services were received.",
      controls: [C.shell, C.p8], evidence: rows }, [...vs]);
  }

  // ---- Benford -------------------------------------------------------------
  let benford = null;
  const benfordVendors = [];
  if (pop.length) {
    const cents = pop.map((r) => r.cents);
    const ft = benfordTest(cents, "firstTwo", o.benfordMinFT);
    const f1 = ft.refused ? benfordTest(cents, "first", o.benfordMin) : null;
    benford = !ft.refused ? ft : !f1.refused ? f1 : null;
    if (!benford) skipped.push({ check: "benford", reason: "ledger Benford test refused: " + f1.n + " amounts of 1.00 or more (first-digit minimum " + o.benfordMin + "), " + ft.n + " of 10.00 or more (first-two-digit minimum " + o.benfordMinFT + ")" });
    if (benford && benford.nonconforming) add("benford_ledger", { title: "Benford screen: ledger amounts do not conform", severity: "low", confidence: "review", category: "statistical screen",
      description: (benford.test === "firstTwo" ? "First-two-digit" : "First-digit") + " test over " + benford.n + " amounts: MAD " + benford.mad + " (" + benford.conformity + ", Nigrini ranges) and chi-square " + benford.chi2 + " above the 0.05 critical value " + benford.critical + " (df " + benford.df + "). Largest excess: " + topExcess(benford.rows) + ". A screen, not evidence: price lists, fixed fees and thresholds also distort digits.",
      recommendation: "Drill into the over-represented leading digits by vendor and approver; review the invoices behind them.",
      controls: [C.p8], evidence: benford.rows.map((r) => ({ digits: r.digits, count: r.count, observedPct: r.observed, expectedPct: r.expected })) }, []);
    const vrows = [], vs = new Set();
    for (const v of [...V.values()]) {
      if (v.pop.length < o.benfordMin) continue;
      const t = benfordTest(v.pop.map((r) => r.cents), "first", o.benfordMin);
      if (t.refused) continue;
      benfordVendors.push({ vendor: vname(v), key: v.key, ...t });
      if (t.nonconforming) { vrows.push({ vendor: vname(v), amounts: t.n, mad: t.mad, conformity: t.conformity, chi2: t.chi2, critical: t.critical, largestExcess: topExcess(t.rows) }); vs.add(v.key); flag(v, "benford"); }
    }
    if (!benfordVendors.length) skipped.push({ check: "benford_vendor", reason: "no vendor has " + o.benfordMin + " or more invoices (per-vendor first-digit minimum)" });
    if (vrows.length) add("benford_vendor", { title: "Benford screen: vendor amounts do not conform", severity: "low", confidence: "review", category: "statistical screen",
      description: vrows.length + " vendor(s) with " + o.benfordMin + "+ invoices fail the first-digit test (chi-square above " + CHI_CRIT_05.first + " at df 8 and MAD above " + NIGRINI.first[2] + "). A screen only.",
      recommendation: "Review the vendor's invoices for invented or manipulated amounts; compare with contract pricing.",
      controls: [C.shell, C.p8], evidence: vrows }, [...vs]);
  }

  // ---- Weekend / holiday -------------------------------------------------
  if (recs.length) {
    const dateKinds = [["postDay", "posting"], ["payDay", "payment"]];
    const usable = recs.filter((r) => r.postDay != null || r.payDay != null);
    if (!usable.length) skipped.push({ check: "weekend_postings", reason: "no posting or payment date column in the ledger" });
    else {
      const wk = [];
      for (const r of usable) for (const [k, label] of dateKinds) if (r[k] != null && (weekday(r[k]) === 0 || weekday(r[k]) === 6)) wk.push({ ...ev(r), dateType: label, day: weekday(r[k]) === 0 ? "Sunday" : "Saturday" });
      if (wk.length) add("weekend_postings", { title: "Postings or payments on weekends", severity: "low", confidence: "review", category: "timing",
        description: wk.length + " posting or payment date(s) fall on a Saturday or Sunday. Normal for some batch jobs; manual entries outside working hours deserve a look.",
        recommendation: "Check who entered these and whether the system or a person posted them.", controls: [C.p8, C.p10], evidence: wk }, [...new Set(usable.filter((r) => [r.postDay, r.payDay].some((d) => d != null && (weekday(d) === 0 || weekday(d) === 6))).map((r) => r.v.key))]);
      const hol = holidayMap(o.holidays);
      if (!hol) skipped.push({ check: "holiday_postings", reason: "US federal holiday reference (/data/ref/us-holidays.json) not provided; weekend check still ran" });
      else {
        const hv = [], hvKeys = new Set();
        let outside = 0;
        for (const r of usable) for (const [k, label] of dateKinds) {
          const d = r[k]; if (d == null) continue;
          const y = +dayISO(d).slice(0, 4);
          if (y < hol.from || y > hol.to) { outside++; continue; }
          if (hol.map.has(d)) { hv.push({ ...ev(r), dateType: label, holiday: hol.map.get(d) }); hvKeys.add(r.v.key); }
        }
        if (outside) skipped.push({ check: "holiday_postings", reason: outside + " date(s) outside the holiday reference coverage (" + hol.from + "-" + hol.to + ") were not checked" });
        if (hv.length) add("holiday_postings", { title: "Postings or payments on US federal holidays", severity: "low", confidence: "review", category: "timing",
          description: hv.length + " posting or payment date(s) fall on a US federal holiday (reference data " + (hol.version || "provided") + ", verify with counsel). Banks do not settle on these days, so a payment date here is unusual.",
          recommendation: "Confirm who entered these and why on a holiday.", controls: [C.p8, C.p10], evidence: hv }, [...hvKeys]);
      }
    }
  }

  // ---- Vendor lifecycle: new, inactive, blocked ---------------------------
  if (master.length && recs.length) {
    if (!master.some((m) => m.created != null)) skipped.push({ check: "new_vendor_paid", reason: "vendor master has no created date column" });
    else {
      const rows = [], vs = new Set();
      for (const v of V.values()) {
        const m = v.master; if (!m || m.created == null || !v.paid.length) continue;
        let firstPay = null;
        for (const r of v.paid) if (r.paidDay != null && (firstPay == null || r.paidDay < firstPay)) firstPay = r.paidDay;
        if (firstPay == null) continue;
        const gap = firstPay - m.created;
        if (gap >= 0 && gap < o.newVendorDays) { rows.push({ vendor: vname(v), created: dayISO(m.created), createdBy: m.createdBy, firstPayment: dayISO(firstPay), days: gap, totalPaid: totalsStr(v.totals) }); vs.add(v.key); flag(v, "new vendor paid fast"); }
      }
      if (rows.length) add("new_vendor_paid", { title: "Vendor paid within days of being created", severity: "medium", confidence: "review", category: "vendor lifecycle",
        description: rows.length + " vendor(s) received a first payment less than " + o.newVendorDays + " days after the vendor record was created. Pattern consistent with a shell vendor set up for an immediate payment, or an urgent but legitimate onboarding.",
        recommendation: "Confirm onboarding due diligence (tax id, bank verification call-back, contract) was completed before the first payment.",
        controls: [C.shell, C.p10, C.p12], evidence: rows }, [...vs]);
    }
    if (!master.some((m) => m.inactive != null || m.statusInactive)) skipped.push({ check: "paid_after_inactivation", reason: "vendor master has no inactivated date or inactive status" });
    else {
      const rows = [], vs = new Set();
      for (const v of V.values()) {
        const m = v.master; if (!m) continue;
        for (const r of v.paid) {
          const d = r.paidDay;
          if (m.inactive != null ? d != null && d > m.inactive : m.statusInactive) { rows.push({ ...ev(r), inactivated: m.inactive != null ? dayISO(m.inactive) : "status inactive (no date)" }); vs.add(v.key); flag(v, "paid after inactivation"); }
        }
      }
      if (rows.length) add("paid_after_inactivation", { title: "Payments to inactivated vendors", severity: "medium", confidence: rows.some((x) => !/^status/.test(x.inactivated)) ? "likely" : "review", category: "vendor lifecycle",
        description: rows.length + " payment(s) went to vendors after their inactivation date (or to vendors whose status is inactive). Dormant vendor records are a common vehicle for fictitious billing.",
        recommendation: "Find who reactivated or paid the vendor and why; block inactive vendors from payment runs.",
        controls: [C.shell, C.p10, C.p12], evidence: rows.sort((a, b) => cmp(a.vendor, b.vendor)) }, [...vs]);
    }
    if (!master.some((m) => m.paymentBlock || m.postingBlock) && !p.sources.some((s) => s.role === "vendors" && (s.columns.paymentBlock || s.columns.postingBlock))) skipped.push({ check: "blocked_vendor_paid", reason: "vendor master has no payment block or posting block column" });
    else {
      const rows = [], vs = new Set();
      for (const v of V.values()) {
        const m = v.master; if (!m || !(m.paymentBlock || m.postingBlock) || !v.paid.length) continue;
        rows.push({ vendor: vname(v), block: [m.paymentBlock ? "payment block" : "", m.postingBlock ? "central posting block" : ""].filter(Boolean).join(", "), payments: v.paid.length, lastPayment: dayISO(v.last), totalPaid: totalsStr(v.totals) });
        vs.add(v.key); flag(v, "blocked vendor paid");
      }
      if (rows.length) add("blocked_vendor_paid", { title: "Payments recorded for blocked vendors", severity: "medium", confidence: "review", category: "vendor lifecycle",
        description: rows.length + " vendor(s) carry a payment or posting block in the master yet have payments in the ledger. The block may postdate the payments; check the block's change date.",
        recommendation: "Compare the block's change date (SAP change documents) with the payment dates; investigate any payment released after the block.",
        controls: [C.shell, C.p10], evidence: rows }, [...vs]);
    }
  }
  // Missing invoice / PO
  if (recs.length) {
    for (const [k, id, title, label] of [["invoice", "missing_invoice", "Payments without an invoice number", "invoice number"], ["po", "missing_po", "Payments without a purchase order number", "PO number"]]) {
      if (!anyCol(k)) { skipped.push({ check: id, reason: "no " + label + " column in the ledger" }); continue; }
      const list = pop.filter((r) => srcHas(r, k) && !(k === "invoice" ? r.invoice : r.po)).sort(sortRecs);
      if (!list.length) continue;
      const amt = list.reduce((a, r) => ((a[cur(r)] = (a[cur(r)] || 0) + r.cents), a), {});
      const vs = [...new Set(list.map((r) => r.v.key))];
      for (const key of vs) flag(V.get(key), "missing invoice / PO");
      add(id, { title, severity: "medium", confidence: "review", category: "documentation",
        description: list.length + " payment(s) (" + Object.entries(amt).map(([c, v]) => fmtMoney(v, c)).join("; ") + ") have a blank " + label + " although the export has the column. Payments with no supporting document cannot be matched in a three-way match.",
        recommendation: "Obtain the supporting " + label + " for each payment or document the exception and its approver.",
        controls: [C.personal, C.p10, C.p12], evidence: list.map(ev) }, vs);
    }
  }

  // ---- P.O. box / mail drop ----------------------------------------------
  if (master.length) {
    const re = /\bP\.?\s*O\.?\s*Box\b|\bPost\s*Office\s*Box\b|\bPostfach\b|\bApartado\b|\bBo[iî]te\s+postale\b|\bPMB\b|\bPrivate\s+Mail\s*box\b|\bUPS\s+Store\b|\bMail\s*Boxes\s+Etc\b|\bPostal\s+Annex\b/i;
    const rows = [], vs = new Set();
    for (const m of master) {
      const addr = [m.street, m.city].filter(Boolean).join(", ");
      if (!re.test(addr) || m.hasPhone) continue;
      const v = V.get(m.key);
      rows.push({ vendor: vname(v), address: addr, postalCode: m.postal, phone: m.phoneCol ? "blank" : "not in export", totalPaid: v ? totalsStr(v.totals) : "" });
      vs.add(m.key); flag(v, "P.O. box address");
    }
    if (rows.length) add("po_box", { title: "Vendors with a P.O. box or mail-drop address and no phone", severity: "low", confidence: "review", category: "vendor master",
      description: rows.length + " vendor(s) list only a P.O. box, Postfach, Apartado, PMB or mail-drop address with no phone number. Consistent with a shell vendor that has no physical premises; many small legitimate vendors also use one.",
      recommendation: "Verify a physical address and a working phone for these vendors before the next payment.",
      controls: [C.shell, C.p10], evidence: rows }, [...vs]);
  }

  // ---- Bank details checksum -----------------------------------------------
  if (master.length) {
    const rows = [], vs = new Set();
    let checked = 0;
    for (const m of master) {
      if (m.ibanCheck) { checked++; if (!m.ibanCheck.ok) { rows.push({ vendor: vname(V.get(m.key)), field: "IBAN", value: m.iban4 || "(short)", problem: m.ibanCheck.reason }); vs.add(m.key); flag(V.get(m.key), "invalid bank details"); } }
      if (m.abaCheck) { checked++; if (!m.abaCheck.ok) { rows.push({ vendor: vname(V.get(m.key)), field: "ABA routing", value: m.routing, problem: m.abaCheck.reason }); vs.add(m.key); flag(V.get(m.key), "invalid bank details"); } }
    }
    if (!checked) skipped.push({ check: "bank_checksum", reason: "vendor master has no IBAN or 9-digit US routing number to validate" });
    if (rows.length) add("bank_checksum", { title: "Vendor bank details fail checksum validation", severity: "low", confidence: "confirmed", category: "vendor master",
      description: rows.length + " IBAN or ABA routing value(s) in the vendor master fail their check-digit test (ISO 13616 mod-97, ABA 3-7-1). Payments to these details will fail or have been keyed wrongly.",
      recommendation: "Re-verify the bank details with the vendor through a known phone number (call-back) and correct the record under dual control.",
      controls: [C.p10, C.p12], evidence: rows }, [...vs]);
  }

  // ---- Segregation of duties ----------------------------------------------
  if (recs.length) {
    const hasUsers = anyCol("enteredBy") || anyCol("approver");
    if (!master.some((m) => m.createdBy) || !hasUsers) skipped.push({ check: "sod_vendor_creator", reason: !hasUsers ? "no entered-by or approver column in the ledger" : "vendor master has no created-by column" });
    else {
      const rows = [], vs = new Set();
      for (const v of V.values()) {
        const m = v.master; if (!m || !m.createdBy) continue;
        const ent = v.pop.filter((r) => r.enteredBy === m.createdBy), apr = v.pop.filter((r) => r.approver === m.createdBy);
        if (!ent.length && !apr.length) continue;
        const both = [...new Set([...ent, ...apr])];
        rows.push({ vendor: vname(v), user: m.createdBy, vendorCreated: dayISO(m.created), entriesBySameUser: ent.length, approvalsBySameUser: apr.length, amount: totalsStr(sumBy(both)) });
        vs.add(v.key); flag(v, "segregation of duties");
      }
      if (rows.length) add("sod_vendor_creator", { title: "Same user created the vendor and entered or approved its invoices", severity: "medium", confidence: "likely", category: "segregation of duties",
        description: rows.length + " vendor(s) were created by a user who also entered or approved that vendor's invoices or payments. One person controlling vendor setup and payment can create and pay a fictitious vendor.",
        recommendation: "Separate vendor-master maintenance from invoice entry and approval (role design), and review these vendors' payments.",
        controls: [C.sox, C.iso, C.shell, C.p10], evidence: rows }, [...vs]);
    }
    if (!anyCol("enteredBy") || !anyCol("approver")) skipped.push({ check: "sod_self_approval", reason: "self-approval needs both an entered-by and an approver column" });
    else {
      const self = pop.filter((r) => r.enteredBy && r.approver && r.enteredBy === r.approver).sort(sortRecs);
      if (self.length) {
        const vs = [...new Set(self.map((r) => r.v.key))];
        for (const k of vs) flag(V.get(k), "segregation of duties");
        add("sod_self_approval", { title: "Invoices approved by the person who entered them", severity: "medium", confidence: "likely", category: "segregation of duties",
          description: self.length + " invoice(s) list the same user as preparer and approver (" + totalsStr(sumBy(self)) + ").",
          recommendation: "Enforce preparer != approver in the AP workflow and review these items.",
          controls: [C.sox, C.iso, C.p10], evidence: self.map(ev) }, vs);
      }
    }
  }

  // ---- Monthly spend + spikes ------------------------------------------------
  const monthsSet = new Set();
  const monthly = new Map();
  for (const r of pop) {
    if (r.day == null) continue;
    const m = monthOf(r.day); monthsSet.add(m);
    const k = r.v.key + "|" + cur(r);
    if (!monthly.has(k)) monthly.set(k, { v: r.v, currency: cur(r), m: new Map() });
    const x = monthly.get(k).m; x.set(m, (x.get(m) || 0) + r.cents);
  }
  const months = [...monthsSet].sort();
  if (pop.length) {
    const rows = [], vs = new Set();
    let scored = 0;
    for (const x of monthly.values()) {
      const entries = [...x.m.entries()].sort((a, b) => cmp(a[0], b[0]));
      if (entries.length < o.spikeMinMonths) continue;
      scored++;
      const vals = entries.map((e) => e[1]);
      const rz = robustZ(vals);
      entries.forEach(([mo, c], i) => {
        if (rz.z[i] > o.spikeZ && c >= 2 * rz.med) { rows.push({ vendor: vname(x.v), month: mo, amount: fmtMoney(c, x.currency), medianMonth: fmtMoney(Math.round(rz.med), x.currency), robustZ: round(rz.z[i], 2), monthsOfHistory: entries.length }); vs.add(x.v.key); flag(x.v, "spend spike"); }
      });
    }
    if (!scored) skipped.push({ check: "spend_spike", reason: "no vendor has " + o.spikeMinMonths + " or more months with spend" });
    if (rows.length) add("spend_spike", { title: "Monthly vendor spend spikes", severity: "low", confidence: "review", category: "velocity",
      description: rows.length + " vendor-month(s) exceed " + o.spikeZ + " robust z-scores (0.6745 x deviation / MAD around the vendor's median month, " + o.spikeMinMonths + "+ months of history) and are at least twice the median month. Months are by invoice date.",
      recommendation: "Check the spike months for one-off projects, catch-up billing or invoices that were not received.",
      controls: [C.p8, C.p10], evidence: rows.sort((a, b) => b.robustZ - a.robustZ || cmp(a.vendor, b.vendor)) }, [...vs]);
  }

  // ---- Assemble findings ------------------------------------------------------
  const vendorAsset = (key) => {
    const v = V.get(key); if (!v) return null;
    return { type: "VENDOR", name: v.name, data: { legalName: v.name, vendorId: v.vendorId || "", taxIdLast4: v.master ? v.master.tax4 : "", totalPaid: totalsStr(v.totals), flags: [...v.flags].sort() } };
  };
  for (const { id, f, vkeys, extraAssets } of F) {
    const keys = [...new Set(vkeys.filter(Boolean))].sort();
    const assets = keys.slice(0, 100).map(vendorAsset).filter(Boolean).concat(extraAssets.slice(0, 50));
    findings.push({ id: "apf-" + id, check: id, title: f.title, severity: f.severity, confidence: f.confidence, category: f.category, description: f.description, recommendation: f.recommendation,
      controls: f.controls, evidence: f.evidence.slice(0, 50), evidenceCount: f.evidence.length, assets, tags: [TOOL_ID, id] });
  }
  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(a.id, b.id));

  // ---- Tables -------------------------------------------------------------------
  const vendorRows = [...V.values()].filter((v) => v.invoices || v.payments || v.flags.size).map((v) => {
    const flags = [...v.flags].sort();
    return { vendor: v.name, vendorId: v.vendorId || "", key: v.key, invoices: v.invoices, payments: v.payments, totalCents: sumCents(v.totals), total: totalsStr(v.totals),
      currency: Object.keys(v.totals).sort().join(","), first: dayISO(v.first), last: dayISO(v.last), flags, risk: Math.min(100, flags.reduce((a, f) => a + (RISK_WEIGHT[f] || 5), 0)),
      taxIdLast4: v.master ? v.master.tax4 : "", inMaster: !!v.master };
  }).sort((a, b) => b.risk - a.risk || b.totalCents - a.totalCents || cmp(a.vendor, b.vendor));
  const topMonthly = [...monthly.values()].map((x) => ({ vendor: vname(x.v), key: x.v.key, currency: x.currency, totals: months.map((m) => x.m.get(m) || 0), flagged: x.v.flags.size > 0 }))
    .map((r) => ({ ...r, sum: r.totals.reduce((a, b) => a + b, 0) })).sort((a, b) => (b.flagged - a.flagged) || b.sum - a.sum || cmp(a.vendor, b.vendor));
  const tables = {
    vendors: vendorRows,
    duplicates: dupRows.sort((a, b) => cmp(a.kind, b.kind) || cmp(a.vendor, b.vendor) || cmp(a.paymentDateB, b.paymentDateB)),
    benford: benford ? { test: benford.test, n: benford.n, mad: benford.mad, chi2: benford.chi2, critical: benford.critical, df: benford.df, conformity: benford.conformity, nonconforming: benford.nonconforming, rows: benford.rows } : null,
    benfordVendors: benfordVendors.map(({ key, ...t }) => t),
    monthly: { months, rows: topMonthly.map(({ sum, ...r }) => ({ ...r, totalCents: sum })) },
    sources: p.sources.map((s) => ({ name: s.name, format: s.format, label: s.label, role: s.role, confidence: s.confidence, rows: s.rows, records: s.records, dropped: s.dropped, columns: s.columns, unusable: !!s.unusable })),
  };

  // ---- Summary --------------------------------------------------------------------
  const paidBy = sumBy(paid);
  const curs = Object.keys(paidBy).sort();
  const main = curs.slice().sort((a, b) => paidBy[b] - paidBy[a] || cmp(a, b))[0] ?? "";
  let newest = null;
  for (const r of recs) for (const d of [r.day, r.paidDay]) if (d != null && (newest == null || d > newest)) newest = d;
  const flaggedVendors = vendorRows.filter((v) => v.flags.length).length;
  const bySeverity = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  const summary = {
    rows: nAll, invoices: pop.length, payments: paid.length, vendors: vendorRows.length, masterVendors: master.length, employees: emps.length,
    currency: main, currencies: curs, totalPaidCents: paidBy[main] || 0, totalPaid: fmtMoney(paidBy[main] || 0, main), totalPaidByCurrency: paidBy,
    potentialDuplicateCents: atRiskBy[main] || 0, potentialDuplicate: fmtMoney(atRiskBy[main] || 0, main), potentialDuplicateByCurrency: atRiskBy,
    duplicatePairs: dupRows.length, flaggedVendors, vendorEmployeeMatches: empMatches.length, findings: findings.length, bySeverity,
    approvalThreshold: thr && thr > 0 ? thr : null, totalBasis: basis,
  };
  ctx?.progress?.(1, 1, "done");
  return { summary, findings, tables, skipped, meta: { tool: TOOL_ID, version: VERSION, rows: nAll, now: o.now ? str(o.now) : dayISO(newest), sources: tables.sources.length,
    options: { dupWindowDays: o.dupWindowDays, splitDays: o.splitDays, newVendorDays: o.newVendorDays, spikeZ: o.spikeZ, minVendorInvoices: o.minVendorInvoices, approvalThreshold: thr && thr > 0 ? thr : null, benfordMin: o.benfordMin, benfordMinFT: o.benfordMinFT } } };

  function dupEv(r) {
    return { vendor: r.vendor + (r.vendorB ? " / " + r.vendorB : ""), invoice: r.invoice, invoiceB: r.invoiceB, paymentDate: r.paymentDate, paymentDateB: r.paymentDateB, amount: r.amount, ref: r.ref, refB: r.refB, reason: r.reason, rows: r.lineA + " / " + r.lineB };
  }
}

function sumBy(list) { const o = {}; for (const r of list) o[r.currency] = (o[r.currency] || 0) + r.cents; return o; }
function sumCents(t) { return Object.values(t).reduce((a, b) => a + b, 0); }
function totalsStr(t) { const k = Object.keys(t || {}).sort(); return k.length ? k.map((c) => fmtMoney(t[c], c)).join("; ") : fmtMoney(0, ""); }
function topExcess(rows) {
  const r = rows.slice().sort((a, b) => (b.observed - b.expected) - (a.observed - a.expected) || cmp(a.digits, b.digits))[0];
  return r ? "leading " + r.digits + " at " + r.observed + "% vs " + r.expected + "% expected" : "";
}

// ---------------------------------------------------------------------------
// Serialisers
// ---------------------------------------------------------------------------
const q = (v) => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
function csv(cols, rows) { return [cols.join(","), ...rows.map((r) => cols.map((c) => q(Array.isArray(r[c]) ? r[c].join("; ") : r[c])).join(","))].join("\n") + "\n"; }

const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "evidenceCount", "assets"];
/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  return csv(FINDING_COLS, (findings || []).map((f) => ({ ...f, controls: (f.controls || []).map((c) => c.framework + " " + c.id).join("; "),
    evidenceCount: f.evidenceCount ?? (f.evidence || []).length, assets: (f.assets || []).map((a) => a.type + ":" + a.name).join("; ") })));
}
export const RECOVERY_COLS = ["vendor", "vendor_b", "invoice_first", "invoice_duplicate", "invoice_date_first", "invoice_date_duplicate", "payment_date_first", "payment_date_duplicate", "amount", "currency", "payment_ref_first", "payment_ref_duplicate", "match_reason", "confidence", "amount_at_risk"];
/** Duplicate-payment recovery worksheet. */
export function recoveryToCsv(dups) {
  return csv(RECOVERY_COLS, (dups || []).map((d) => ({ vendor: d.vendor, vendor_b: d.vendorB, invoice_first: d.invoice, invoice_duplicate: d.invoiceB, invoice_date_first: d.invoiceDate, invoice_date_duplicate: d.invoiceDateB,
    payment_date_first: d.paymentDate, payment_date_duplicate: d.paymentDateB, amount: fmtMoney(d.amountCents), currency: d.currency, payment_ref_first: d.ref, payment_ref_duplicate: d.refB,
    match_reason: d.reason, confidence: d.confidence, amount_at_risk: fmtMoney(d.atRiskCents) })));
}
export const VENDOR_COLS = ["vendor", "vendor_id", "invoices", "payments", "total_paid", "currency", "first_payment", "last_payment", "flags", "risk_score", "tax_id_last4", "in_master"];
/** Vendor risk register. */
export function vendorsToCsv(vendors) {
  return csv(VENDOR_COLS, (vendors || []).map((v) => ({ vendor: v.vendor, vendor_id: v.vendorId, invoices: v.invoices, payments: v.payments, total_paid: fmtMoney(v.totalCents), currency: v.currency,
    first_payment: v.first, last_payment: v.last, flags: v.flags, risk_score: v.risk, tax_id_last4: v.taxIdLast4, in_master: v.inMaster ? "yes" : "no" })));
}
/** Plain-text summary. */
export function summaryText(r) {
  const s = r.summary;
  const out = ["AP Forensics summary", "Screens for review by an accountant or internal auditor; not findings of fraud.", "",
    "Ledger rows: " + s.rows + " (invoices tested " + s.invoices + ", payments " + s.payments + ")", "Total paid: " + s.totalPaid + (s.currencies.length > 1 ? " (other currencies: " + s.currencies.filter((c) => c !== s.currency).map((c) => fmtMoney(s.totalPaidByCurrency[c], c)).join("; ") + ")" : ""),
    "Basis: " + s.totalBasis.join("; "), "Potential duplicate amount: " + s.potentialDuplicate + " (" + s.duplicatePairs + " pairs)", "Vendors flagged: " + s.flaggedVendors + " of " + s.vendors,
    "Vendor/employee matches: " + s.vendorEmployeeMatches, "Findings: " + s.findings, ""];
  for (const f of r.findings) out.push("[" + f.severity.toUpperCase() + " / " + f.confidence + "] " + f.title + " (" + f.evidenceCount + ")", "  " + f.description, "  Action: " + f.recommendation, "  Controls: " + f.controls.map((c) => c.framework + " " + c.id).join("; "), "");
  if (r.skipped.length) { out.push("Skipped or limited checks:"); for (const k of r.skipped) out.push("- " + k.check + ": " + k.reason); }
  return out.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example (seeded, format-faithful, fictional)
// ---------------------------------------------------------------------------
const csvLine = (cells) => cells.map((v) => { const s = String(v == null ? "" : v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }).join(",");
const usDate = (d) => { const s = dayISO(d); return s.slice(5, 7) + "/" + s.slice(8, 10) + "/" + s.slice(0, 4); };
const sapAmt = (c) => "-" + fmtMoney(c);
function abaWithCheck(eight) {
  const d = eight.split("").map(Number);
  const s = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5]);
  return eight + String((10 - (s % 10)) % 10);
}
function ibanDE(blz, acct) {
  const bban = blz + acct.padStart(10, "0");
  const num = (bban + "DE00").replace(/[A-Z]/g, (ch) => String(ch.charCodeAt(0) - 55));
  let rem = 0; for (const ch of num) rem = (rem * 10 + Number(ch)) % 97;
  return "DE" + String(98 - rem).padStart(2, "0") + bban;
}

/** Seeded SYNTHETIC dataset: SAP FBL1N ledger (~800 rows), SAP vendor master, employee roster. */
export function exampleDataset(seed = 7) {
  let s = seed >>> 0 || 7;
  const rnd = () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 4294967296; };
  const ri = (a, b) => a + Math.floor(rnd() * (b - a + 1));
  const start = mkDay(2025, 4, 1), end = mkDay(2026, 9, 30);
  // US federal holidays 2025-2026 (observed dates) so synthetic business days avoid them.
  const HOL = new Set(["2025-01-01", "2025-01-20", "2025-02-17", "2025-05-26", "2025-06-19", "2025-07-04", "2025-09-01", "2025-10-13", "2025-11-11", "2025-11-27", "2025-12-25",
    "2026-01-01", "2026-01-19", "2026-02-16", "2026-05-25", "2026-06-19", "2026-07-03", "2026-09-07", "2026-10-12", "2026-11-11", "2026-11-26", "2026-12-25"]);
  const bizDay = (d) => { while (weekday(d) === 0 || weekday(d) === 6 || HOL.has(dayISO(d))) d++; return d; };
  const V0 = [
    ["100101", "Vendor A Parts Co", 2400], ["100102", "Vendor B Fasteners Ltd", 900], ["100103", "Vendor C Supply LLC", 3100], ["100104", "Vendor D Services Inc", 2600],
    ["100105", "Vendor E Trading GmbH", 5200], ["100106", "Vendor F Consulting LLC", 0], ["100107", "Vendor G Logistics Inc", 1450], ["100108", "Vendor H Facilities Corp", 0],
    ["100109", "Vendor I Freight Ltd", 6100], ["100110", "Vendor J Mail Services", 760], ["100111", "Vendor K Office Supply", 340], ["100112", "Vendor L Packaging", 1800],
    ["100113", "Vendor M Electrical", 4300], ["100114", "Vendor N Machining", 12500], ["100115", "Vendor O Janitorial", 1250], ["100116", "Vendor P Printing", 520],
    ["100117", "Vendor Q Catering", 680], ["100118", "Vendor R Engineering", 18800], ["100119", "Vendor S IT Services", 7400], ["100120", "Vendor T Uniforms", 1100],
    ["100121", "Vendor U Waste Services", 2050], ["100122", "Vendor V Security Services", 9600], ["100123", "Vendor B Fasteners Limited", 900], ["100124", "Vendor W Media", 260],
  ];
  const users = ["APCLERK1", "APCLERK2", "APCLERK3"];
  const rows = [];
  let doc = 5100004100, clr = 1500002200;
  const push = (vid, post, cents, ref, text, user, o2 = {}) => {
    const docDate = post - ri(0, 6);
    const clear = o2.clear ?? bizDay(post + ri(12, 35));
    rows.push({ vid, post, docDate, cents, ref, text, user, clear: clear > end + 20 ? null : clear, method: o2.method || (rnd() < 0.8 ? "T" : "C"), docNo: o2.docNo || String(doc++), clrNo: o2.clrNo || String(clr++) });
    return rows[rows.length - 1];
  };
  const regular = [];
  for (const [vid, , base] of V0) {
    if (!base || vid === "100123") continue;
    let d = vid === "100105" ? mkDay(2026, 8, 4) : bizDay(start + ri(0, 20));
    let inv = ri(10000, 90000);
    const seq = vid === "100107";
    let n = 0;
    const prefix = vid === "100107" ? "SL-" : vid === "100101" ? "INV-0" : vid === "100113" ? "" : "";
    while (d <= end) {
      inv += seq ? 1 : ri(15, 400);
      const cents = Math.round(base * 100 * 10 ** ((rnd() - 0.5) * 0.9)) + ri(0, 99);
      const r = push(vid, d, cents, prefix + inv, vid === "100105" ? "Steel stock" : "Goods and services", vid === "100103" ? "USER04" : users[ri(0, users.length - 1)],
        vid === "100105" && n === 0 ? { clear: mkDay(2026, 8, 6) } : {});
      regular.push(r); n++;
      d = bizDay(d + ri(6, 21));
    }
  }
  // Vendor F: fixed-fee round invoices.
  for (let k = 0; k < 14; k++) push("100106", bizDay(start + 20 + k * 36), [250000, 400000, 150000, 300000][k % 4], "CL-" + (5000 + k * 7), "Advisory retainer", users[k % 3]);
  // Vendor H: steady monthly invoice, one spike month.
  for (let k = 0; k < 18; k++) {
    const d = bizDay(mkDay(2025, 4 + k > 12 ? 4 + k - 12 : 4 + k, 15) + (4 + k > 12 ? 365 : 0));
    push("100108", d, k === 11 ? 3812500 : 190000 + ri(0, 25000), "LF" + (88000 + k * 13), "Facilities service", users[k % 3]);
  }
  // Spike just under a 10,000.00 approval threshold: re-price 20 regular invoices to 9,1xx-9,9xx.
  const big = new Set(V0.filter((x) => x[2] >= 2400 && x[2] <= 7400).map((x) => x[0]));
  const pick = regular.filter((r) => big.has(r.vid) && r.vid !== "100104").filter((_, i) => i % 9 === 4).slice(0, 20);
  for (const r of pick) r.cents = 910000 + ri(0, 88000);
  // Split invoices: Vendor D, three invoices in three days, each under 10,000.00.
  const qd = bizDay(mkDay(2026, 2, 9));
  push("100104", qd, 481240, "QP-77120", "Site works phase 1", "APCLERK2");
  push("100104", qd + 1, 397515, "QP-77121", "Site works phase 2", "APCLERK2");
  push("100104", qd + 2, 264090, "QP-77122", "Site works phase 3", "APCLERK2");
  // Exact duplicates (3): re-entered 12-20 days later, one with a reformatted invoice number.
  const dupSrc = ["100101", "100112", "100118"].map((vid) => regular.find((r) => r.vid === vid && r.post > mkDay(2025, 10, 1) && r.cents < 900000));
  dupSrc.forEach((r, k) => push(r.vid, bizDay(r.post + 12 + k * 4), r.cents, k === 0 ? r.ref.replace(/^INV-0+/, "") : r.ref, r.text, users[(k + 1) % 3]));
  // Fuzzy duplicate: Vendor M invoice re-keyed with two digits transposed.
  const bw = regular.find((r) => r.vid === "100113" && r.post > mkDay(2026, 1, 1) && /^\d{5}$/.test(r.ref) && r.ref[2] !== r.ref[3]);
  push("100113", bizDay(bw.post + 9), bw.cents, bw.ref.slice(0, 2) + bw.ref[3] + bw.ref[2] + bw.ref.slice(4), bw.text, "APCLERK1");
  // Same invoice paid under the duplicate Vendor B record.
  const bg = regular.find((r) => r.vid === "100102" && r.post > mkDay(2026, 3, 1));
  push("100123", bizDay(bg.post + 5), bg.cents, bg.ref, bg.text, "APCLERK2");
  // Weekend and holiday postings.
  const shift = regular.filter((_, i) => i % 97 === 11).slice(0, 5);
  for (const r of shift) { r.post = r.post + (6 - weekday(r.post)); }
  const h1 = regular.find((r) => r.vid === "100115" && Math.abs(r.post - mkDay(2025, 7, 4)) < 40);
  if (h1) h1.post = mkDay(2025, 7, 4);
  const h2 = regular.find((r) => r.vid === "100116" && Math.abs(r.post - mkDay(2025, 11, 27)) < 40);
  if (h2) h2.post = mkDay(2025, 11, 27);

  rows.sort((a, b) => a.post - b.post || cmp(a.docNo, b.docNo));
  const FBL = FORMATS["sap-fbl1n"].headers;
  const ledger = [csvLine(FBL), ...rows.map((r) => csvLine(["1000", "0000" + r.vid, r.docNo, "KR", usDate(r.post), usDate(Math.min(r.docDate, r.post)), sapAmt(r.cents), "USD", r.ref, r.text,
    r.clear != null ? r.clrNo : "", r.clear != null ? usDate(r.clear) : "", r.clear != null ? r.method : "", r.user]))].join("\n") + "\n";

  // Vendor master (SAP).
  const bankFor = (k) => "77" + String(31000000 + k * 7919).padStart(8, "0");
  const VM = FORMATS["sap-vendors"].headers;
  const streets = ["Harbor Way", "Mill Road", "Station Street", "Orchard Lane", "Canal Street", "Quarry Road", "Market Square", "Ridge Avenue"];
  const vm = V0.map(([vid, name], k) => {
    const de = vid === "100118";
    let street = (100 + k * 37) + " " + streets[k % streets.length], city = de ? "Hamburg" : "Springfield", postal = de ? "20095" : String(62700 + k), country = de ? "DE" : "US";
    let tax = "9" + String(41000000 + k * 104729).slice(0, 8);
    let routing = de ? "" : abaWithCheck(String(21000000 + k * 1031).padStart(8, "0"));
    let acct = de ? "" : bankFor(k), iban = de ? ibanDE("20050550", "1234" + String(k).padStart(6, "0")) : "";
    let created = usDate(mkDay(2023, 1 + (k % 12), 3 + k)), createdBy = "VMDATA", pblock = "", cblock = "";
    if (vid === "100123") { tax = vmTax(V0, "100102"); street = (100 + 1 * 37) + " " + streets[1]; postal = String(62701); created = usDate(mkDay(2025, 11, 18)); createdBy = "APCLERK2"; routing = abaWithCheck(String(21000000 + 22 * 1031).padStart(8, "0")); acct = bankFor(40); }
    if (vid === "100103") { createdBy = "USER04"; acct = "7790031144"; routing = abaWithCheck("02200030"); created = usDate(mkDay(2024, 6, 12)); }
    if (vid === "100105") created = usDate(mkDay(2026, 8, 3));
    if (vid === "100109") pblock = "A";
    if (vid === "100121") cblock = "X";
    if (vid === "100110") { street = "PO Box 4471"; postal = "62790"; }
    if (vid === "100111") routing = routing.slice(0, 8) + String((Number(routing[8]) + 3) % 10);
    return csvLine([vid, name, street, city, postal, country, tax, routing, acct, iban, created, createdBy, cblock, pblock]);
  });
  function vmTax(list, id) { const k = list.findIndex((x) => x[0] === id); return "9" + String(41000000 + k * 104729).slice(0, 8); }
  const vendorsCsv = [csvLine(VM), ...vm].join("\n") + "\n";

  // Employee roster (generic layout).
  const EH = FORMATS["generic-employees"].headers;
  const first = Array.from({ length: 28 }, (_, k) => String(k + 1).padStart(2, "0"));
  const depts = ["Accounts Payable", "Finance", "Operations", "Engineering", "Sales", "Facilities", "IT"];
  const emps = first.map((fn, k) => {
    const name = "User " + fn;
    const isPlanted = k === 3;
    return csvLine(["E" + String(2001 + k), name, (10 + k * 3) + " Elm Court", "Springfield", String(62800 + k), "555-01" + String(10 + k).padStart(2, "0"), "user" + fn + "@test.darknode.ai",
      isPlanted ? "7790031144" : "66" + String(12000000 + k * 3571).padStart(8, "0"), isPlanted ? abaWithCheck("02200030") : abaWithCheck(String(11000000 + k * 77).padStart(8, "0")), "",
      isPlanted ? "Accounts Payable" : depts[k % depts.length], usDate(mkDay(2019 + (k % 6), 1 + (k % 12), 10)), k === 7 ? usDate(mkDay(2026, 2, 27)) : ""]);
  });
  const empCsv = [csvLine(EH), ...emps].join("\n") + "\n";
  return {
    label: "synthetic example (not real data)",
    files: [{ name: "fbl1n-vendor-line-items-synthetic.csv", text: ledger }, { name: "sap-vendor-master-synthetic.csv", text: vendorsCsv }, { name: "employee-roster-synthetic.csv", text: empCsv }],
    opts: { approvalThreshold: 10000 },
    now: "2026-10-16",
  };
}

/** Real deterministic checks of the engine. */
export function selfTest() {
  const tests = [];
  const t = (name, fn) => { let pass = false; try { pass = !!fn(); } catch (_) { pass = false; } tests.push({ name, pass }); };
  t("toCents parses ($1,234.50), 1.234,56- and 12", () => toCents("($1,234.50)") === -123450 && toCents("1.234,56-") === -123456 && toCents("12") === 1200);
  t("invoice normalisation strips prefix, punctuation and zeros", () => normInvoice("INV-004512") === "4512" && normInvoice("#4512") === "4512");
  t("transposition detected", () => isTransposition("58213", "58123") && !isTransposition("58213", "58214"));
  const ex = exampleDataset();
  const r = analyze(ex.files, { ...ex.opts, now: ex.now });
  const f = (id) => r.findings.find((x) => x.check === id);
  t("example: 3 exact duplicates", () => f("dup_exact") && f("dup_exact").evidenceCount === 3);
  t("example: 1 transposed duplicate", () => f("dup_transposed") && f("dup_transposed").evidenceCount === 1);
  t("example: vendor/employee bank match", () => f("vendor_employee") && f("vendor_employee").evidence.some((e) => /Vendor C/.test(e.vendor) && /bank account/.test(e.matchedOn)));
  t("example: split cluster under 10,000", () => f("split_invoices") && f("split_invoices").evidence.some((e) => /Vendor D/.test(e.vendor)));
  t("example: vendor paid 3 days after creation", () => f("new_vendor_paid") && f("new_vendor_paid").evidence.some((e) => e.days === 3));
  t("no full bank account in output", () => !JSON.stringify(r).includes("7790031144"));
  t("missing threshold skips split check", () => analyze(ex.files, {}).skipped.some((k) => k.check === "split_invoices"));
  return { pass: tests.every((x) => x.pass), tests };
}
