// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// STRONGROOM engine (v1 bridgehead) — pure, deterministic, dependency-free.
//
// This is the first real increment of the cyber-financial FUSION engine described in
// docs/STRONGROOM-FUSION-ENGINE.md. It runs entirely in the browser on data YOU load;
// nothing is uploaded. Every detection is deterministic: the same input always produces
// byte-identical findings. No AI decides anything here, and nothing is simulated — the
// engine analyses exactly the rows you give it.
//
// Two planes, matching the plan:
//   - Financial integrity screens (ACFE scheme taxonomy + Nigrini forensic analytics).
//   - Fusion correlation: join financial events with access/identity events to detect the
//     intrusion -> fund-theft kill chain that single-plane tools miss.
//
// Honesty: each rule declares a soundness class (exact | precise | heuristic | screen).
// A screen (e.g. Benford) highlights items for review; it is never proof of fraud.

// ------------------------------- CSV parsing -------------------------------

// RFC-4180-ish CSV parser: handles quoted fields, escaped quotes, CRLF/CR/LF.
export function parseCSV(text) {
  const rows = [];
  let row = [], field = "", i = 0, inQ = false;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (inQ) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
        inQ = false; i++; continue;
      }
      field += c; i++; continue;
    }
    if (c === '"') { inQ = true; i++; continue; }
    if (c === ",") { row.push(field); field = ""; i++; continue; }
    if (c === "\r") { i++; continue; }
    if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; i++; continue; }
    field += c; i++;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  // drop trailing all-empty row
  while (rows.length && rows[rows.length - 1].every((x) => x.trim() === "")) rows.pop();
  return rows;
}

// Column synonym maps — flexible header matching so users don't have to rename columns.
const COLS = {
  date: ["date", "txn_date", "transaction_date", "payment_date", "posted", "posting_date", "value_date", "ts", "timestamp"],
  vendor: ["vendor", "payee", "supplier", "beneficiary", "counterparty", "vendor_name", "payee_name", "merchant"],
  amount: ["amount", "value", "total", "debit", "paid", "payment_amount", "amt", "gross", "net"],
  invoice: ["invoice", "invoice_no", "invoice_number", "inv", "inv_no", "reference", "ref", "doc", "document", "voucher"],
  account: ["account", "iban", "bank_account", "acct", "account_no", "account_number", "bank", "routing"],
  approver: ["approver", "approved_by", "authorizer", "authorized_by", "signoff"],
  initiator: ["initiator", "created_by", "entered_by", "requester", "requested_by", "user", "operator", "clerk"],
};
const ACCESS_COLS = {
  date: COLS.date,
  actor: ["actor", "user", "identity", "account", "username", "email", "principal", "subject"],
  type: ["type", "event", "event_type", "action", "activity", "signal"],
  vendor: ["vendor", "payee", "supplier", "target", "object", "resource"],
  detail: ["detail", "details", "description", "note", "message", "raw"],
};

function norm(s) { return String(s || "").trim().toLowerCase().replace(/[\s./-]+/g, "_"); }

// Map header row -> index per logical column. Returns {col:index|-1}.
function mapHeader(header, spec) {
  const idx = {};
  const normalized = header.map(norm);
  for (const key of Object.keys(spec)) {
    idx[key] = -1;
    for (const syn of spec[key]) {
      const at = normalized.indexOf(syn);
      if (at >= 0) { idx[key] = at; break; }
    }
  }
  return idx;
}

// Parse a currency/number string: strips symbols, handles parentheses-negatives and commas.
export function parseAmount(s) {
  if (typeof s === "number") return s;
  let t = String(s == null ? "" : s).trim();
  if (!t) return NaN;
  let neg = false;
  if (/^\(.*\)$/.test(t)) { neg = true; t = t.slice(1, -1); }
  t = t.replace(/[^0-9.\-]/g, "");
  if (t === "" || t === "-" || t === ".") return NaN;
  let v = parseFloat(t);
  if (!isFinite(v)) return NaN;
  if (neg) v = -v;
  return v;
}

// Parse a date to a UTC day number (days since epoch) so comparisons are integer + stable.
// Accepts ISO (YYYY-MM-DD), US (M/D/Y), and a few common forms. Returns null if unparseable.
export function parseDay(s) {
  const t = String(s == null ? "" : s).trim();
  if (!t) return null;
  let y, m, d;
  let mm = t.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})/);
  if (mm) { y = +mm[1]; m = +mm[2]; d = +mm[3]; }
  else {
    mm = t.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})/);
    if (mm) { m = +mm[1]; d = +mm[2]; y = +mm[3]; if (y < 100) y += 2000; }
  }
  if (!y) {
    const ts = Date.parse(t);
    if (isFinite(ts)) { const dt = new Date(ts); y = dt.getUTCFullYear(); m = dt.getUTCMonth() + 1; d = dt.getUTCDate(); }
    else return null;
  }
  if (m < 1 || m > 12 || d < 1 || d > 31) return null;
  return Math.floor(Date.UTC(y, m - 1, d) / 86400000);
}

function dayToISO(day) {
  if (day == null) return "";
  const dt = new Date(day * 86400000);
  return dt.toISOString().slice(0, 10);
}
function isWeekend(day) { if (day == null) return false; const dow = (day + 4) % 7; return dow === 5 || dow === 6; } // epoch day0 = Thu

// ------------------------------- record loading -------------------------------

export function loadPayments(csvText) {
  const rows = parseCSV(csvText);
  if (rows.length < 2) return { records: [], warnings: ["Need a header row and at least one data row."], map: {} };
  const map = mapHeader(rows[0], COLS);
  const warnings = [];
  if (map.amount < 0) warnings.push("No amount/value column detected — most screens need one.");
  if (map.vendor < 0) warnings.push("No vendor/payee column detected — vendor screens will be skipped.");
  const records = [];
  for (let r = 1; r < rows.length; r++) {
    const row = rows[r];
    if (row.every((x) => x.trim() === "")) continue;
    const rec = {
      _row: r + 1,
      date: map.date >= 0 ? (row[map.date] || "").trim() : "",
      day: map.date >= 0 ? parseDay(row[map.date]) : null,
      vendor: map.vendor >= 0 ? (row[map.vendor] || "").trim() : "",
      amount: map.amount >= 0 ? parseAmount(row[map.amount]) : NaN,
      invoice: map.invoice >= 0 ? (row[map.invoice] || "").trim() : "",
      account: map.account >= 0 ? (row[map.account] || "").trim() : "",
      approver: map.approver >= 0 ? (row[map.approver] || "").trim() : "",
      initiator: map.initiator >= 0 ? (row[map.initiator] || "").trim() : "",
    };
    rec.vkey = norm(rec.vendor);
    records.push(rec);
  }
  return { records, warnings, map };
}

export function loadAccessEvents(csvText) {
  const rows = parseCSV(csvText);
  if (rows.length < 2) return { events: [], warnings: ["Need a header row and at least one data row."] };
  const map = mapHeader(rows[0], ACCESS_COLS);
  const events = [];
  for (let r = 1; r < rows.length; r++) {
    const row = rows[r];
    if (row.every((x) => x.trim() === "")) continue;
    events.push({
      _row: r + 1,
      date: map.date >= 0 ? (row[map.date] || "").trim() : "",
      day: map.date >= 0 ? parseDay(row[map.date]) : null,
      actor: map.actor >= 0 ? (row[map.actor] || "").trim() : "",
      type: norm(map.type >= 0 ? row[map.type] : ""),
      vendor: map.vendor >= 0 ? (row[map.vendor] || "").trim() : "",
      detail: map.detail >= 0 ? (row[map.detail] || "").trim() : "",
      vkey: norm(map.vendor >= 0 ? row[map.vendor] : ""),
      akey: norm(map.actor >= 0 ? row[map.actor] : ""),
    });
  }
  return { events, warnings: [] };
}

// ------------------------------- helpers -------------------------------

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
function round2(x) { return Math.round((x + Number.EPSILON) * 100) / 100; }
function sum(arr) { return arr.reduce((a, b) => a + (isFinite(b) ? b : 0), 0); }
function median(nums) {
  const a = nums.filter(isFinite).slice().sort((x, y) => x - y);
  if (!a.length) return NaN;
  const m = Math.floor(a.length / 2);
  return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2;
}
// deterministic 32-bit FNV-1a fingerprint of a finding's identity
function fp(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193); }
  return (h >>> 0).toString(16).padStart(8, "0");
}
function finding(o) {
  const money = round2(o.money || 0);
  const id = fp(o.rule + "|" + (o.key || "") + "|" + (o.rows || []).join(","));
  return { id, rule: o.rule, title: o.title, severity: o.severity, soundness: o.soundness,
    money, rows: o.rows || [], vendor: o.vendor || "", why: o.why, evidence: o.evidence || [] };
}

// ------------------------------- financial detections -------------------------------

function detDuplicatePayments(recs) {
  const out = [];
  const seen = new Map();
  for (const r of recs) {
    if (!isFinite(r.amount) || !r.vkey) continue;
    const k = r.vkey + "|" + round2(r.amount) + "|" + norm(r.invoice);
    if (!r.invoice) continue; // exact rule requires an invoice ref
    if (!seen.has(k)) seen.set(k, []);
    seen.get(k).push(r);
  }
  for (const [k, grp] of seen) {
    if (grp.length < 2) continue;
    const money = sum(grp.slice(1).map((g) => g.amount)); // the duplicates beyond the first
    out.push(finding({ rule: "duplicate-payment", title: "Exact duplicate payment", severity: money >= 10000 ? "high" : "medium",
      soundness: "exact", money, vendor: grp[0].vendor, key: k, rows: grp.map((g) => g._row),
      why: grp.length + " payments share the same vendor, amount and invoice reference — classic double-payment.",
      evidence: grp.map((g) => `row ${g._row}: ${g.vendor} ${round2(g.amount)} inv ${g.invoice} ${g.date}`) }));
  }
  // near-duplicate: same vendor + amount within 7 days, different/empty invoice
  const byVA = new Map();
  for (const r of recs) {
    if (!isFinite(r.amount) || !r.vkey) continue;
    const k = r.vkey + "|" + round2(r.amount);
    if (!byVA.has(k)) byVA.set(k, []);
    byVA.get(k).push(r);
  }
  for (const [k, grp] of byVA) {
    if (grp.length < 2) continue;
    const dated = grp.filter((g) => g.day != null).sort((a, b) => a.day - b.day);
    for (let i = 1; i < dated.length; i++) {
      if (dated[i].day - dated[i - 1].day <= 7 && norm(dated[i].invoice) !== norm(dated[i - 1].invoice)) {
        const pair = [dated[i - 1], dated[i]];
        out.push(finding({ rule: "near-duplicate-payment", title: "Near-duplicate payment", severity: "medium",
          soundness: "heuristic", money: dated[i].amount, vendor: pair[0].vendor, key: k + "|" + dated[i]._row,
          rows: pair.map((g) => g._row),
          why: "Same vendor and amount paid within 7 days under a different reference — possible resubmitted invoice.",
          evidence: pair.map((g) => `row ${g._row}: ${g.vendor} ${round2(g.amount)} inv ${g.invoice || "(none)"} ${g.date}`) }));
      }
    }
  }
  return out;
}

function detBenford(recs) {
  const amts = recs.map((r) => Math.abs(r.amount)).filter((a) => isFinite(a) && a >= 1);
  if (amts.length < 200) return []; // below this, Benford is noise — don't cry wolf
  const counts = new Array(10).fill(0);
  for (const a of amts) { const d = +String(Math.floor(a)).replace(/^0+/, "")[0]; if (d >= 1 && d <= 9) counts[d]++; }
  const total = counts.reduce((a, b) => a + b, 0);
  if (!total) return [];
  let mad = 0;
  const table = [];
  for (let d = 1; d <= 9; d++) {
    const expected = Math.log10(1 + 1 / d);
    const actual = counts[d] / total;
    mad += Math.abs(actual - expected);
    table.push({ d, actual: round2(actual * 100), expected: round2(expected * 100) });
  }
  mad = mad / 9;
  // Nigrini MAD thresholds (first digit): <.006 close, <.012 acceptable, <.015 marginal, else nonconforming
  let verdict, sev;
  if (mad < 0.006) { verdict = "close conformity"; sev = "info"; }
  else if (mad < 0.012) { verdict = "acceptable conformity"; sev = "info"; }
  else if (mad < 0.015) { verdict = "marginal conformity"; sev = "low"; }
  else { verdict = "nonconformity"; sev = "medium"; }
  return [finding({ rule: "benford-first-digit", title: "Benford first-digit screen: " + verdict, severity: sev,
    soundness: "screen", money: 0, key: "benford", rows: [],
    why: `MAD ${mad.toFixed(4)} across ${total} amounts (Nigrini first-digit thresholds). A screen only — nonconformity warrants review, it is NOT evidence of fraud.`,
    evidence: table.map((t) => `digit ${t.d}: actual ${t.actual}% vs expected ${t.expected}%`) })];
}

function detUnderThreshold(recs) {
  // common approval thresholds; flag clusters of payments to one vendor just below one
  const THRESH = [1000, 2500, 5000, 10000, 25000, 50000, 100000];
  const out = [];
  const byV = new Map();
  for (const r of recs) { if (!isFinite(r.amount) || !r.vkey) continue; if (!byV.has(r.vkey)) byV.set(r.vkey, []); byV.get(r.vkey).push(r); }
  for (const [vk, grp] of byV) {
    for (const t of THRESH) {
      const near = grp.filter((r) => r.amount >= t * 0.9 && r.amount < t);
      if (near.length >= 3) {
        out.push(finding({ rule: "under-threshold-structuring", title: `Payments clustered just below ${t.toLocaleString()}`,
          severity: near.length >= 5 ? "high" : "medium", soundness: "heuristic", money: sum(near.map((r) => r.amount)),
          vendor: near[0].vendor, key: vk + "|" + t, rows: near.map((r) => r._row),
          why: `${near.length} payments to this vendor sit within 10% below the ${t.toLocaleString()} approval threshold — possible structuring to avoid review.`,
          evidence: near.slice(0, 8).map((r) => `row ${r._row}: ${round2(r.amount)} ${r.date}`) }));
        break; // report the tightest threshold once per vendor
      }
    }
  }
  return out;
}

function detRoundNumber(recs) {
  const amts = recs.filter((r) => isFinite(r.amount) && r.amount > 0);
  if (amts.length < 50) return [];
  const round = amts.filter((r) => r.amount % 1000 === 0);
  const frac = round.length / amts.length;
  if (frac < 0.12) return [];
  return [finding({ rule: "round-number-cluster", title: "High share of round-number amounts", severity: frac > 0.25 ? "medium" : "low",
    soundness: "screen", money: sum(round.map((r) => r.amount)), key: "round", rows: round.slice(0, 20).map((r) => r._row),
    why: `${(frac * 100).toFixed(1)}% of payments are exact multiples of 1,000. Round numbers rarely arise from genuine invoices at this rate — a screen for estimated/fabricated amounts.`,
    evidence: round.slice(0, 8).map((r) => `row ${r._row}: ${r.vendor} ${round2(r.amount)}`) })];
}

function detVendorOutlier(recs) {
  const out = [];
  const byV = new Map();
  for (const r of recs) { if (!isFinite(r.amount) || !r.vkey) continue; if (!byV.has(r.vkey)) byV.set(r.vkey, []); byV.get(r.vkey).push(r); }
  for (const [vk, grp] of byV) {
    if (grp.length < 5) continue;
    const med = median(grp.map((r) => r.amount));
    if (!isFinite(med) || med <= 0) continue;
    for (const r of grp) {
      if (r.amount > med * 10 && r.amount > 5000) {
        out.push(finding({ rule: "vendor-amount-outlier", title: "Payment far above vendor's norm", severity: "low",
          soundness: "heuristic", money: r.amount, vendor: r.vendor, key: vk + "|" + r._row, rows: [r._row],
          why: `This payment (${round2(r.amount)}) is over 10x the vendor's median payment (${round2(med)}).`,
          evidence: [`row ${r._row}: ${r.vendor} ${round2(r.amount)} ${r.date} (median ${round2(med)})`] }));
      }
    }
  }
  return out;
}

function detWeekend(recs) {
  const wk = recs.filter((r) => r.day != null && isWeekend(r.day) && isFinite(r.amount));
  if (!wk.length) return [];
  return [finding({ rule: "weekend-payment", title: `${wk.length} payment(s) dated on a weekend`, severity: "info",
    soundness: "heuristic", money: sum(wk.map((r) => r.amount)), key: "weekend", rows: wk.slice(0, 30).map((r) => r._row),
    why: "Payments dated Saturday/Sunday can indicate out-of-process disbursement. Informational — confirm against your payment calendar.",
    evidence: wk.slice(0, 8).map((r) => `row ${r._row}: ${r.vendor} ${round2(r.amount)} ${r.date}`) })];
}

function detLoneApprover(recs) {
  // payments where initiator === approver (no segregation of duties), on larger amounts
  const same = recs.filter((r) => r.approver && r.initiator && norm(r.approver) === norm(r.initiator) && isFinite(r.amount) && r.amount >= 5000);
  if (!same.length) return [];
  return [finding({ rule: "segregation-of-duties", title: "Same person initiated and approved", severity: "medium",
    soundness: "precise", money: sum(same.map((r) => r.amount)), key: "sod", rows: same.slice(0, 30).map((r) => r._row),
    why: "The initiator and approver are the same identity on payments >= 5,000 — a segregation-of-duties failure and a classic single-point fraud enabler.",
    evidence: same.slice(0, 8).map((r) => `row ${r._row}: ${r.vendor} ${round2(r.amount)} by ${r.initiator}`) })];
}

// ------------------------------- fusion detections (cyber x financial) -------------------------------

const BANK_CHANGE = new Set(["vendor_bank_change", "bank_change", "iban_change", "bank_account_change", "payee_change"]);
const MAILBOX_RISK = new Set(["mailbox_rule_added", "mailbox_forwarding", "forwarding_rule", "inbox_rule"]);
const ACCESS_RISK = new Set(["login_new_geo", "impossible_travel", "new_device", "mfa_enrolled", "oauth_grant", "suspicious_login"]);
const EXPORT_RISK = new Set(["vendor_list_export", "data_export", "dlp_export", "mass_download"]);

function paymentsForVendorAfter(recs, vkey, day, windowDays) {
  return recs.filter((r) => r.vkey === vkey && isFinite(r.amount) && r.day != null && day != null && r.day >= day && r.day - day <= windowDays);
}

function detFusion(recs, events) {
  const out = [];
  for (const ev of events) {
    if (ev.day == null) continue;
    // BEC payment redirect: bank-change or mailbox-rule for a vendor, then a payment to that vendor
    if (BANK_CHANGE.has(ev.type) || MAILBOX_RISK.has(ev.type)) {
      if (!ev.vkey) continue;
      const pays = paymentsForVendorAfter(recs, ev.vkey, ev.day, 30);
      if (pays.length) {
        const money = sum(pays.map((p) => p.amount));
        out.push(finding({ rule: "fusion-bec-payment-redirect", title: "BEC payment-redirect chain", severity: money >= 25000 ? "critical" : "high",
          soundness: "heuristic", money, vendor: ev.vendor, key: "bec|" + ev.vkey + "|" + ev._row, rows: pays.map((p) => p._row),
          why: `A ${ev.type.replace(/_/g, " ")} for ${ev.vendor || "a vendor"} (${ev.date}) was followed within 30 days by ${pays.length} payment(s) to that vendor. Neither the email layer nor the ERP raises this alone — the fused chain does.`,
          evidence: [`access row ${ev._row}: ${ev.type} ${ev.vendor} ${ev.date} ${ev.detail}`.trim()]
            .concat(pays.slice(0, 6).map((p) => `payment row ${p._row}: ${round2(p.amount)} ${p.date}`)) }));
      }
    }
    // Account-takeover disbursement: risky access for an actor who then approves/initiates a payment
    if (ACCESS_RISK.has(ev.type) && ev.akey) {
      const pays = recs.filter((r) => isFinite(r.amount) && r.day != null && r.day >= ev.day && r.day - ev.day <= 2 &&
        (norm(r.approver) === ev.akey || norm(r.initiator) === ev.akey));
      if (pays.length) {
        const money = sum(pays.map((p) => p.amount));
        out.push(finding({ rule: "fusion-ato-disbursement", title: "Account-takeover disbursement chain", severity: money >= 25000 ? "critical" : "high",
          soundness: "heuristic", money, vendor: "", key: "ato|" + ev.akey + "|" + ev._row, rows: pays.map((p) => p._row),
          why: `A ${ev.type.replace(/_/g, " ")} for ${ev.actor} (${ev.date}) was followed within 48h by ${pays.length} payment(s) that same identity approved or initiated.`,
          evidence: [`access row ${ev._row}: ${ev.type} ${ev.actor} ${ev.date}`]
            .concat(pays.slice(0, 6).map((p) => `payment row ${p._row}: ${p.vendor} ${round2(p.amount)} ${p.date}`)) }));
      }
    }
    // Insider export then new vendor paid
    if (EXPORT_RISK.has(ev.type)) {
      const pays = recs.filter((r) => isFinite(r.amount) && r.day != null && r.day >= ev.day && r.day - ev.day <= 90);
      // "new vendor" = vendor whose first appearance in the dataset is on/after the export day
      const firstDay = new Map();
      for (const r of recs) { if (r.day != null && r.vkey) { const f = firstDay.get(r.vkey); if (f == null || r.day < f) firstDay.set(r.vkey, r.day); } }
      const newPays = pays.filter((r) => r.vkey && firstDay.get(r.vkey) >= ev.day);
      if (newPays.length) {
        const money = sum(newPays.map((p) => p.amount));
        out.push(finding({ rule: "fusion-insider-export-newvendor", title: "Data-export then new-vendor payment", severity: "high",
          soundness: "heuristic", money, vendor: "", key: "exp|" + ev._row, rows: newPays.map((p) => p._row),
          why: `A ${ev.type.replace(/_/g, " ")} by ${ev.actor || "an insider"} (${ev.date}) preceded payment(s) to vendor(s) first seen after that export, within 90 days.`,
          evidence: [`access row ${ev._row}: ${ev.type} ${ev.actor} ${ev.date}`]
            .concat(newPays.slice(0, 6).map((p) => `payment row ${p._row}: ${p.vendor} ${round2(p.amount)} ${p.date}`)) }));
      }
    }
  }
  return out;
}

// ------------------------------- orchestration -------------------------------

export function analyze(paymentsCSV, accessCSV) {
  const { records, warnings, map } = loadPayments(paymentsCSV || "");
  let events = [], accessWarn = [];
  if (accessCSV && accessCSV.trim()) { const a = loadAccessEvents(accessCSV); events = a.events; accessWarn = a.warnings; }

  let findings = [];
  findings = findings.concat(detDuplicatePayments(records));
  findings = findings.concat(detBenford(records));
  findings = findings.concat(detUnderThreshold(records));
  findings = findings.concat(detRoundNumber(records));
  findings = findings.concat(detVendorOutlier(records));
  findings = findings.concat(detWeekend(records));
  findings = findings.concat(detLoneApprover(records));
  if (events.length) findings = findings.concat(detFusion(records, events));

  // deterministic ordering: severity desc, money desc, rule, fingerprint
  findings.sort((a, b) =>
    (SEV_RANK[b.severity] - SEV_RANK[a.severity]) || (b.money - a.money) ||
    (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0) || (a.id < b.id ? -1 : 1));

  const amts = records.map((r) => r.amount).filter(isFinite);
  const summary = {
    payments: records.length,
    accessEvents: events.length,
    totalValue: round2(sum(amts)),
    vendors: new Set(records.map((r) => r.vkey).filter(Boolean)).size,
    dateRange: (() => { const ds = records.map((r) => r.day).filter((d) => d != null); return ds.length ? [dayToISO(Math.min(...ds)), dayToISO(Math.max(...ds))] : null; })(),
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    moneyAtRisk: 0,
    fusionChains: findings.filter((f) => f.rule.startsWith("fusion-")).length,
  };
  for (const f of findings) { summary.counts[f.severity]++; if (SEV_RANK[f.severity] >= 2) summary.moneyAtRisk += f.money; }
  summary.moneyAtRisk = round2(summary.moneyAtRisk);

  return { findings, summary, warnings: warnings.concat(accessWarn), map };
}

// ------------------------------- self-test (determinism + correctness) -------------------------------

// Runs on tiny in-code fixtures. These fixtures are the engine's OWN test data — they are
// never presented to the user as findings about their data. Returns {pass, results}.
export function selfTest() {
  const results = [];
  const check = (name, cond) => results.push({ name, pass: !!cond });

  const pay = [
    "date,vendor,amount,invoice,approver,initiator",
    "2026-01-05,Acme Supply,10000,INV-100,alice,bob",
    "2026-01-06,Acme Supply,10000,INV-100,alice,bob",     // exact duplicate
    "2026-01-10,Globex,9500,INV-201,carol,carol",          // lone approver + under-threshold-ish
    "2026-01-11,Globex,9400,INV-202,carol,carol",
    "2026-01-12,Globex,9300,INV-203,carol,carol",
    "2026-01-20,Initech,250000,INV-9,dave,erin",           // ATO target
  ].join("\n");
  const access = [
    "date,actor,type,vendor,detail",
    "2026-01-19,dave,login_new_geo,,sign-in from new ASN",   // -> ATO disbursement on 2026-01-20
    "2026-01-02,,vendor_bank_change,Acme Supply,IBAN updated", // -> BEC redirect (payments on 01-05/01-06)
  ].join("\n");

  const r1 = analyze(pay, access);
  const r2 = analyze(pay, access);
  check("duplicate-payment detected", r1.findings.some((f) => f.rule === "duplicate-payment"));
  check("segregation-of-duties detected", r1.findings.some((f) => f.rule === "segregation-of-duties"));
  check("fusion BEC chain detected", r1.findings.some((f) => f.rule === "fusion-bec-payment-redirect"));
  check("fusion ATO chain detected", r1.findings.some((f) => f.rule === "fusion-ato-disbursement"));
  check("deterministic: identical findings on repeat", JSON.stringify(r1.findings) === JSON.stringify(r2.findings));
  check("parseAmount handles ($1,234.50)", parseAmount("($1,234.50)") === -1234.5);
  check("parseDay ISO == US", parseDay("2026-01-05") === parseDay("1/5/2026"));
  check("empty input is safe", analyze("", "").findings.length === 0);

  const pass = results.every((r) => r.pass);
  return { pass, results };
}
