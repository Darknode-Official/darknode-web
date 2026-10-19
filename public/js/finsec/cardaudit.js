// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Card Audit (cardaudit): Deck tool UI. Drop corporate card feeds (American Express, Brex, Ramp),
// expense report exports (Expensify, SAP Concur) or a mapped generic CSV, plus an optional HR
// roster and policy-limit table; the engine screens them in a Worker. Runs entirely in the
// browser. The only request is the same-origin holiday reference file /data/ref/us-holidays.json.
// No native dialogs; toasts only.
//
//   renderCardAudit(main) -> void

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, COLUMNS, ROSTER_COLUMNS, POLICY_COLUMNS, BUILTIN_MCC, DETECTIONS, detectFile, parseInput, parseMccList,
  findingsToCsv, followupToCsv, recoveryToCsv, summaryText, exampleDataset, fmtCents, csvCell,
} from "./cardaudit-engine.js?v=20261017c";

const ENGINE = engineUrl("./cardaudit-engine.js?v=20261017c", import.meta);
const P = "crd";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const CONF_RANK = { confirmed: 3, likely: 2, review: 1 };
const ROLE_COLS = { transactions: COLUMNS, roster: ROSTER_COLUMNS, policy: POLICY_COLUMNS };
const KEY_LABEL = {
  date: "Date", employee: "Employee / cardholder", employee_id: "Employee ID", card_last4: "Card (last 4)", merchant: "Merchant", mcc: "MCC", amount: "Amount",
  currency: "Currency", receipt: "Receipt", approver: "Approver", report_id: "Report ID", category: "Category", memo: "Memo", city: "City", country: "Country",
  reimbursable: "Reimbursable (yes/no)", payment_type: "Payment type", name: "Name", email: "Email", department: "Department", title: "Title", manager_id: "Manager ID",
  hire_date: "Hire date", termination_date: "Termination date", status: "Status", limit_per_txn: "Limit per transaction", limit_per_day: "Limit per day",
};

const CSS = `
  .crd-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .crd-root *{box-sizing:border-box}
  .crd-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .crd-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .crd-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .crd-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:110ch;overflow-wrap:anywhere}
  .crd-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .crd-card h2{font-size:.95rem;margin:0 0 10px}
  .crd-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .crd-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .crd-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer;max-width:100%;white-space:normal;text-align:left}
  .crd-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .crd-btn.sm{padding:4px 9px;font-size:.76rem}
  .crd-btn:disabled{opacity:.5;cursor:default}
  .crd-files{display:flex;flex-direction:column;gap:6px;margin-top:12px}
  .crd-file{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;font-size:.82rem;min-width:0}
  .crd-file b{overflow-wrap:anywhere;min-width:0}
  .crd-file select,.crd-map select{font:inherit;font-size:.78rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:3px 6px;background:var(--card,#fff);color:var(--tx,#1a2230);max-width:100%}
  .crd-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085)}
  .crd-conf.high{color:#1b7f4d;border-color:#1b7f4d}.crd-conf.medium{color:#8a6d00;border-color:#8a6d00}.crd-conf.low{color:#b00020;border-color:#b00020}
  .crd-map{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:12px 14px;margin-top:10px;min-width:0}
  .crd-map h3{font-size:.86rem;margin:0 0 4px;overflow-wrap:anywhere}
  .crd-ctl{display:flex;flex-wrap:wrap;gap:14px 20px;align-items:flex-start;margin-top:8px}
  .crd-field{display:flex;flex-direction:column;gap:4px;min-width:0;flex:1 1 170px}
  .crd-field.wide{flex:1 1 100%}
  .crd-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .crd-field input,.crd-field select,.crd-field textarea{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%}
  .crd-field textarea{min-height:78px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}
  .crd-field small{font-size:.74rem;color:var(--mut,#667085);line-height:1.4}
  .crd-check{display:flex;gap:8px;align-items:center;font-size:.84rem}
  .crd-check input{width:auto}
  .crd-ref{font-size:.78rem;color:var(--mut,#667085);margin-top:10px;overflow-wrap:anywhere}
  .crd-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .crd-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:130px;flex:1 1 130px;min-width:0}
  .crd-kpi b{display:block;font-size:1.25rem;overflow-wrap:anywhere}
  .crd-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .crd-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .crd-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .crd-plabel{font-size:.74rem;color:var(--mut,#667085);margin-top:4px;display:none}
  .crd-tabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;border-bottom:1px solid var(--line,#e6e8ee);padding-bottom:8px}
  .crd-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid transparent;background:none;color:var(--mut,#667085);padding:6px 12px;border-radius:8px;cursor:pointer}
  .crd-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#d7dbe3);background:var(--bg,#f7f8fb)}
  .crd-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .crd-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:640px}
  .crd-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .crd-list th.on{color:var(--tx,#1a2230)}
  .crd-list th.on::after{content:" \\2193";font-size:.7rem}
  .crd-list th.on.asc::after{content:" \\2191"}
  .crd-list td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word}
  .crd-list tr[data-i]{cursor:pointer}
  .crd-list tr[data-i]:hover,.crd-list tr.sel{background:var(--bg,#f7f8fb)}
  .crd-nw{white-space:nowrap}
  .crd-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .crd-pill.critical{background:#7a0012}.crd-pill.high{background:#b00020}.crd-pill.medium{background:#b58100}.crd-pill.low{background:#2552c6}.crd-pill.info{background:#667085}
  .crd-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085)}
  .crd-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .crd-drawer{margin-top:12px;display:none;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--bg,#f7f8fb);min-width:0}
  .crd-drawer h3{margin:0;font-size:1rem;overflow-wrap:anywhere}
  .crd-drawer p{margin:6px 0;overflow-wrap:anywhere}
  .crd-drawer .crd-list{background:var(--card,#fff);margin-top:10px}
  .crd-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:10px;padding-left:18px}
  .crd-skip li{margin:2px 0;overflow-wrap:anywhere}
  .crd-chart{width:100%;max-width:900px;height:auto;display:block}
  .crd-legend{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:.78rem;color:var(--mut,#667085);margin:6px 0 10px}
  .crd-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
  .crd-mcc table{min-width:420px}
  .crd-mcc summary{cursor:pointer;font-weight:600;font-size:.86rem;margin-top:10px}
  @media (max-width:560px){.crd-field{flex:1 1 100%}.crd-card{padding:14px}.crd-kpi{flex:1 1 140px}}
`;

const kpi = (v, l) => '<div class="' + P + '-kpi"><b>' + esc(v == null ? "-" : v) + "</b><span>" + esc(l) + "</span></div>";
const pill = (s) => (s ? '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>" : "");
const chips = (cs) => (cs || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("");
const money = (m, cur) => { const keys = Object.keys(m || {}); if (!keys.length) return "0.00"; const c = cur && m[cur] != null ? cur : keys[0]; return fmtCents(m[c]) + " " + (c || "") + (keys.length > 1 ? " +" + (keys.length - 1) + " cur." : ""); };

const sortRows = (rows, key, dir, rank) => rows.slice().sort((a, b) => {
  const x = rank ? (rank[a[key]] ?? -1) : a[key], y = rank ? (rank[b[key]] ?? -1) : b[key];
  const r = typeof x === "number" && typeof y === "number" ? x - y : cmp(String(x == null ? "" : x).toLowerCase(), String(y == null ? "" : y).toLowerCase());
  return dir === "asc" ? r : -r;
});

/** Sortable table: cols = [{key, label, render?, rank?, sortKey?}]. */
function table(cols, rows, sort, onSort, rowKey, limit) {
  const col = cols.find((c) => c.key === sort.key) || {};
  const sorted = sortRows(rows, col.sortKey || sort.key, sort.dir, col.rank);
  const shown = limit ? sorted.slice(0, limit) : sorted;
  const el = document.createElement("div");
  el.className = P + "-list";
  el.innerHTML = "<table><thead><tr>" + cols.map((c) => '<th data-k="' + esc(c.key) + '" class="' + (sort.key === c.key ? "on " + sort.dir : "") + '">' + esc(c.label) + "</th>").join("") + "</tr></thead><tbody>" +
    shown.map((r) => '<tr data-i="' + esc(rowKey(r)) + '">' + cols.map((c) => "<td>" + (c.render ? c.render(r) : esc(r[c.key] == null ? "" : r[c.key])) + "</td>").join("") + "</tr>").join("") + "</tbody></table>";
  el.querySelectorAll("th").forEach((th) => th.addEventListener("click", () => { const k = th.dataset.k; onSort({ key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" }); }));
  return el;
}

function evidenceTable(rows) {
  if (!rows || !rows.length) return '<p class="' + P + '-note">No evidence rows.</p>';
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => '<td class="' + (k === "date" || k === "amount" || k === "card" ? P + "-nw" : "") + '">' + esc(r[k] == null ? "" : r[k]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

function monthlySvg(rows, currency) {
  const data = rows.filter((r) => r.currency === currency);
  if (!data.length) return '<p class="' + P + '-note">No monthly data.</p>';
  const W = 900, H = 260, L = 70, B = 34, T = 16, R = 10;
  const max = Math.max(1, ...data.map((r) => r.totalCents));
  const gw = (W - L - R) / data.length, bw = Math.max(6, Math.min(48, gw - 10));
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const ticks = [0, max / 2, max];
  let s = '<svg class="' + P + '-chart" viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Monthly spend and flagged spend">';
  for (const t of ticks) s += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + y(t) + '" y2="' + y(t) + '" stroke="#e6e8ee"/><text x="' + (L - 6) + '" y="' + (y(t) + 4) + '" text-anchor="end" font-size="11" fill="#667085">' + esc(fmtCents(Math.round(t)).replace(/\.\d\d$/, "")) + "</text>";
  data.forEach((r, i) => {
    const x = L + i * gw + (gw - bw) / 2;
    s += '<rect x="' + x + '" y="' + y(r.totalCents) + '" width="' + bw + '" height="' + Math.max(0, H - B - y(r.totalCents)) + '" fill="#9db4ea" rx="3"><title>' + esc(r.month + ": " + r.total + " " + currency + ", " + r.txns + " transactions") + "</title></rect>";
    if (r.flaggedCents > 0) s += '<rect x="' + x + '" y="' + y(r.flaggedCents) + '" width="' + bw + '" height="' + Math.max(0, H - B - y(r.flaggedCents)) + '" fill="#b00020" rx="3"><title>' + esc(r.month + " flagged: " + r.flagged + " " + currency + ", " + r.flaggedTxns + " transactions") + "</title></rect>";
    if (data.length <= 24 || i % Math.ceil(data.length / 24) === 0) s += '<text x="' + (x + bw / 2) + '" y="' + (H - 12) + '" text-anchor="middle" font-size="11" fill="#1a2230">' + esc(r.month) + "</text>";
  });
  s += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + (H - B) + '" y2="' + (H - B) + '" stroke="#98a2b3"/></svg>';
  return '<div class="' + P + '-legend"><span><i style="background:#9db4ea"></i>Spend (' + esc(currency || "currency unstated") + ')</span><span><i style="background:#b00020"></i>Flagged spend</span></div>' + s;
}

/** Mount the tool into main. */
export function renderCardAudit(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  const num = (id, label, v, help, ph) => '<div class="' + P + '-field"><label for="' + P + "-o-" + id + '">' + label + '</label><input id="' + P + "-o-" + id + '" type="number" min="0" step="any" value="' + (v == null ? "" : esc(v)) + '"' + (ph ? ' placeholder="' + esc(ph) + '"' : "") + "><small>" + help + "</small></div>";
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Card Audit</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Screens corporate card transactions and expense reports for split purchases, duplicate receipts, prohibited merchants, leaver spend, self-approval and the other ACFE expense-reimbursement and card-misuse patterns, so finance can review them. Results are screens, not conclusions. Runs entirely in your browser. Nothing is uploaded. The only request is this site\'s holiday reference file (/data/ref/us-holidays.json).</p>',
    '<div class="', P, '-card"><h2>1. Files</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-note">Card feeds: American Express activity CSV, Brex, Ramp. Expense reports: Expensify, SAP Concur. Any other CSV or JSON is mapped below. Add an HR roster (employee_id, name, email, department, title, manager_id, hire_date, termination_date, status) for leaver and approval checks, and optionally a policy table (category, limit_per_txn, limit_per_day, currency). Zip and gzip archives are unpacked locally.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div>',
    '<div id="', P, '-map"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button><button class="', P, '-btn" id="', P, '-clear" disabled>Clear files</button><span class="', P, '-note" id="', P, '-count"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-plabel" id="', P, '-plabel"></div></div>',
    '<div class="', P, '-card"><h2>2. Thresholds</h2><div class="', P, '-ctl">',
    num("limit", "Card transaction limit", DEFAULTS.cardTxnLimit, "Your single-transaction limit, in the card currency. Blank skips the split check.", "e.g. 2500"),
    num("splitHours", "Split window (hours)", DEFAULTS.splitHours, "Same cardholder and merchant within this many hours."),
    num("receipt", "Receipt required over", DEFAULTS.receiptRequiredOver, "Items above this amount need a receipt."),
    num("spikeZ", "Spike robust z-score", DEFAULTS.spikeZ, "Monthly spend versus the employee's own other months."),
    num("spikeRatio", "Spike minimum multiple", DEFAULTS.spikeMinRatio, "The month must also be this multiple of the median month."),
    num("minHist", "Months of history", DEFAULTS.minHistoryMonths, "Minimum other months before a spike is tested."),
    num("roundMin", "Round-number minimum sample", DEFAULTS.roundMinTxns, "Transactions per employee before the round-number test runs."),
    num("roundZ", "Round-number z-score", DEFAULTS.roundZ, "Share of whole amounts versus the rest of the fleet."),
    num("weekendMin", "Weekend / holiday items", DEFAULTS.weekendMinTxns, "Non-travel items per employee before reporting."),
    num("consec", "Consecutive weekends", DEFAULTS.consecutiveWeekends, "Same merchant this many weekends in a row."),
    num("homeMeals", "Home-city meals", DEFAULTS.homeMealsMin, "Meals in the roster city on non-travel days."),
    num("grace", "Termination grace (days)", DEFAULTS.terminationGraceDays, "Days after termination still accepted."),
    "</div></div>",
    '<div class="', P, '-card"><h2>3. Merchant category policy</h2><div class="', P, '-ctl">',
    '<div class="', P, '-field wide"><label for="', P, '-o-mcc">Prohibited MCCs (your list)</label><textarea id="', P, '-o-mcc" placeholder="7995 Gambling" spellcheck="false"></textarea><small>One 4-digit MCC or range per line (for example 6010-6011), an optional label after it, # for comments. Matches here are reported as high severity.</small><div class="', P, '-note" id="', P, '-mccnote"></div></div>',
    '<div class="', P, '-field wide"><label class="', P, '-check"><input id="', P, '-o-builtin" type="checkbox"', DEFAULTS.useBuiltinMcc ? " checked" : "", '> Use the built-in review list</label><small>Codes that often fall outside card policy. Reported for review, not as breaches. Rows from files without an MCC column (American Express, SAP Concur) are not checked.</small></div>',
    "</div>",
    '<details class="', P, '-mcc"><summary>Built-in review list (', BUILTIN_MCC.length, ' codes, read-only)</summary><div class="', P, '-list" style="margin-top:8px"><table><thead><tr><th>MCC</th><th>Description (ISO 18245)</th><th>Reported as</th></tr></thead><tbody>',
    BUILTIN_MCC.map((b) => "<tr><td>" + esc(b.mcc) + "</td><td>" + esc(b.label) + "</td><td>" + pill(b.severity) + "</td></tr>").join(""),
    "</tbody></table></div></details>",
    '<div class="', P, '-ref" id="', P, '-holidays">Holiday reference data: loading.</div></div>',
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card" id="', P, '-results" style="display:none"><div class="', P, '-tabs" id="', P, '-tabs"></div><div id="', P, '-pane"></div><div class="', P, '-drawer" id="', P, '-drawer"></div><ul class="', P, '-skip" id="', P, '-skipped"></ul></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, running = false, tab = "findings", selected = "", holidays = null;
  const sorts = { findings: { key: "severity", dir: "desc" }, employees: { key: "riskScore", dir: "desc" }, merchants: { key: "flags", dir: "desc" }, monthly: { key: "month", dir: "asc" } };

  // ---- holiday reference file (same origin) ----
  fetch("/data/ref/us-holidays.json").then((r) => (r.ok ? r.json() : null)).then((j) => {
    if (j && Array.isArray(j.data)) {
      holidays = j;
      $("holidays").textContent = "US federal holidays: reference data " + (j.version || "") + " (updated " + (j.updated || "") + ", " + j.data.length + " dates), verify with counsel. Used for the weekend and holiday check.";
    } else $("holidays").textContent = "Holiday reference data could not be loaded; the holiday part of the weekend check will be skipped.";
  }).catch(() => { $("holidays").textContent = "Holiday reference data could not be loaded; the holiday part of the weekend check will be skipped."; });

  // ---- MCC list live validation ----
  $("o-mcc").addEventListener("input", () => {
    const r = parseMccList($("o-mcc").value);
    $("mccnote").textContent = r.entries.length || r.errors.length ? r.entries.length + " entr" + (r.entries.length === 1 ? "y" : "ies") + " read" + (r.errors.length ? "; not understood: " + r.errors.slice(0, 4).map((e) => "line " + e.line).join(", ") : "") : "";
  });

  // ---- files ----
  const datasetName = () => (isExample ? "synthetic example" : files.map((f) => f.name).join(", "));
  function redetect(f) {
    const d = detectFile({ name: f.name, text: f.big ? f.sample : f.text, role: f.role, columns: f.columns });
    Object.assign(f, { format: d.format, label: d.label, confidence: d.confidence, confidenceLabel: d.confidenceLabel, headers: d.headers, map: d.map, missing: d.missing || [], role: d.role });
    if (!f.big) { const p = parseInput([{ name: f.name, text: f.text, role: f.role, columns: f.columns }]); const m = p.files[0]; f.records = m ? m.records : 0; f.rejected = m ? m.rejected : 0; }
  }
  function addFile(name, text, role) {
    const big = text.length > 2 * 1024 * 1024;
    const f = { name, text, big, sample: big ? sampleOf(text) : "", role: role || "", columns: {}, records: big ? null : 0, rejected: 0 };
    redetect(f);
    if (f.format === "empty") { toast("Empty file: " + name, "warning"); return false; }
    const i = files.findIndex((x) => x.name === name);
    if (i >= 0) files[i] = f; else files.push(f);
    return true;
  }
  function sampleOf(text) { const head = text.slice(0, 262144); const t = head.trimStart()[0]; if (t === "{" || t === "[") return text; const nl = head.lastIndexOf("\n"); return nl > 0 ? head.slice(0, nl) : head; }

  function renderFiles() {
    const box = $("files");
    box.innerHTML = files.map((f, i) =>
      '<div class="' + P + '-file"><b>' + esc(f.name) + "</b><span>" + esc(f.label) + '</span><span class="' + P + "-conf " + esc(f.confidenceLabel) + '">' + esc(f.confidenceLabel) + " confidence</span>" +
      "<span>" + (f.records == null ? "records counted during analysis" : f.records + " records" + (f.rejected ? ", " + f.rejected + " unreadable" : "")) + "</span>" +
      '<label class="' + P + '-check">Role <select data-role="' + i + '">' + ["transactions", "roster", "policy"].map((r) => '<option value="' + r + '"' + (f.role === r ? " selected" : "") + ">" + r + "</option>").join("") + "</select></label>" +
      '<button class="' + P + '-btn sm" data-rm="' + i + '" type="button">Remove</button></div>').join("");
    box.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { files.splice(Number(b.dataset.rm), 1); isExample = false; renderFiles(); }));
    box.querySelectorAll("[data-role]").forEach((s) => s.addEventListener("change", () => { const f = files[Number(s.dataset.role)]; f.role = s.value; f.columns = {}; redetect(f); renderFiles(); }));
    const tx = files.filter((f) => f.role === "transactions");
    $("count").textContent = files.length ? files.length + " file" + (files.length === 1 ? "" : "s") + (isExample ? " (synthetic example)" : "") + (tx.length ? "" : ". Add at least one transaction file.") : "";
    $("run").disabled = !tx.length || running;
    $("clear").disabled = !files.length;
    renderMapping();
  }

  function renderMapping() {
    const need = files.map((f, i) => ({ f, i })).filter(({ f }) => f.confidenceLabel !== "high");
    const box = $("map");
    if (!need.length) { box.innerHTML = ""; return; }
    box.innerHTML = need.map(({ f, i }) => {
      const spec = ROLE_COLS[f.role] || COLUMNS;
      return '<div class="' + P + '-map"><h3>Column mapping: ' + esc(f.name) + '</h3><p class="' + P + '-note">' + (f.format === "unknown" ? "Not a known layout." : esc(f.label) + ", " + esc(f.confidenceLabel) + " confidence.") +
        " Pick the column for each field; leave a field as (not present) and the checks that need it are skipped with a reason.</p><div class=\"" + P + '-ctl">' +
        Object.keys(spec).map((k) => '<div class="' + P + '-field"><label>' + esc(KEY_LABEL[k] || k) + '</label><select data-f="' + i + '" data-k="' + esc(k) + '"><option value="">(not present)</option>' +
          f.headers.filter((h) => h !== "").map((h) => '<option value="' + esc(h) + '"' + (f.map[k] === h ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>").join("") + "</div></div>";
    }).join("");
    box.querySelectorAll("select[data-k]").forEach((sel) => sel.addEventListener("change", () => {
      const f = files[Number(sel.dataset.f)];
      f.columns[sel.dataset.k] = sel.value;
      redetect(f);
      const scroll = window.scrollY; renderFiles(); window.scrollTo(0, scroll);
    }));
  }

  mountDropzone($("drop"), {
    maxBytes: 256 * 1024 * 1024, maxFiles: 50, unpack: true, multiple: true,
    label: "Drop card, expense, roster or policy files here, paste, or browse",
    onFiles: async (list) => {
      if (isExample) { files = []; isExample = false; }
      let added = 0;
      for (const f of list) if (addFile(f.name, await f.text())) added++;
      if (added) toast("Added " + added + " file" + (added === 1 ? "" : "s"), "success");
      renderFiles();
    },
  });
  $("clear").addEventListener("click", () => { files = []; isExample = false; renderFiles(); });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    files = []; isExample = true;
    for (const f of ex.files) addFile(f.name, f.text, f.role);
    if (!$("o-limit").value && ex.suggestedOpts.cardTxnLimit) $("o-limit").value = ex.suggestedOpts.cardTxnLimit;
    renderFiles();
    toast("Synthetic example loaded (Brex, SAP Concur, roster, policy). Card limit set to " + ex.suggestedOpts.cardTxnLimit + " for the split check. Click Analyze.", "info");
  });

  // ---- options ----
  const opts = () => {
    const v = (id, d) => { const s = $("o-" + id).value.trim(); const n = Number(s); return s !== "" && Number.isFinite(n) && n >= 0 ? n : d; };
    const lim = $("o-limit").value.trim();
    return {
      cardTxnLimit: lim === "" ? null : lim, splitHours: v("splitHours", DEFAULTS.splitHours), receiptRequiredOver: v("receipt", DEFAULTS.receiptRequiredOver),
      spikeZ: v("spikeZ", DEFAULTS.spikeZ), spikeMinRatio: v("spikeRatio", DEFAULTS.spikeMinRatio), minHistoryMonths: v("minHist", DEFAULTS.minHistoryMonths),
      roundMinTxns: v("roundMin", DEFAULTS.roundMinTxns), roundZ: v("roundZ", DEFAULTS.roundZ), weekendMinTxns: v("weekendMin", DEFAULTS.weekendMinTxns),
      consecutiveWeekends: v("consec", DEFAULTS.consecutiveWeekends), homeMealsMin: v("homeMeals", DEFAULTS.homeMealsMin), terminationGraceDays: v("grace", DEFAULTS.terminationGraceDays),
      useBuiltinMcc: $("o-builtin").checked, mccList: $("o-mcc").value, holidays: holidays ? holidays.data : null,
    };
  };

  async function run() {
    if (!files.length || running) return;
    running = true;
    const prog = $("prog"), bar = prog.firstElementChild, pl = $("plabel");
    prog.style.display = "block"; pl.style.display = "block"; bar.style.width = "0%"; pl.textContent = "starting"; $("run").disabled = true;
    try {
      result = await runInWorker(ENGINE, "analyze", [{ files: files.map((f) => ({ name: f.name, text: f.text, role: f.role, columns: f.columns })) }, opts()], {
        timeoutMs: 600000,
        onProgress: (i, n, label) => { bar.style.width = (n ? Math.min(100, Math.round((i / n) * 100)) : 50) + "%"; pl.textContent = (label || "working") + (n > 1 ? " " + i + " of about " + n + " lines" : ""); },
      });
      for (const mf of result.meta.files) { const f = files.find((x) => x.name === mf.name); if (f) { f.records = mf.records; f.rejected = mf.rejected; } }
      selected = ""; $("drawer").style.display = "none";
      render();
      toast(result.summary.transactions + " transactions screened, " + result.findings.length + " findings", "success");
    } catch (e) {
      toast("Analysis failed: " + ((e && e.message) || e), "error");
    } finally {
      running = false;
      prog.style.display = "none"; pl.style.display = "none"; renderFiles();
    }
  }
  $("run").addEventListener("click", run);

  // ---- results ----
  function render() {
    const r = result, s = r.summary, pc = s.primaryCurrency;
    $("kpis").innerHTML = kpi(s.transactions, "transactions") + kpi(money(s.totalSpend, pc), "total spend") + kpi(s.flaggedEmployees + " of " + s.employees, "flagged employees") +
      kpi(money(s.duplicateAmount, pc), "potential duplicates") + kpi(money(s.postTerminationSpend, pc), "post-termination spend") + kpi(s.findings, "findings");
    $("results").style.display = "";
    $("skipped").innerHTML = r.skipped.length ? "<li><b>Skipped or limited checks</b></li>" + r.skipped.map((k) => "<li>" + esc(k.check) + ": " + esc(k.reason) + "</li>").join("") : "";
    const tabs = [["findings", "Findings (" + r.findings.length + ")"], ["employees", "Employees (" + r.tables.employees.length + ")"], ["merchants", "Merchants (" + r.tables.merchants.length + ")"], ["monthly", "Monthly"]];
    $("tabs").innerHTML = tabs.map(([k, l]) => '<button type="button" class="' + P + "-tab" + (tab === k ? " on" : "") + '" data-tab="' + k + '">' + esc(l) + "</button>").join("");
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; selected = ""; $("drawer").style.display = "none"; render(); }));
    drawPane();
    renderExports();
  }

  const FIND_COLS = [
    { key: "severity", label: "Severity", rank: SEV_RANK, render: (f) => pill(f.severity) },
    { key: "title", label: "Finding", render: (f) => "<b>" + esc(f.title) + '</b><div class="' + P + '-note">' + esc(f.category) + "</div>" },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
    { key: "controls", label: "Controls", render: (f) => chips(f.controls) },
    { key: "evidenceCount", label: "Evidence" },
  ];
  const EMP_COLS = [
    { key: "riskScore", label: "Risk" }, { key: "employee", label: "Employee" }, { key: "department", label: "Department" }, { key: "manager", label: "Manager" },
    { key: "txns", label: "Txns" }, { key: "total", label: "Total", sortKey: "totalCents", render: (e) => '<span class="' + P + '-nw">' + esc(e.total) + "</span>" },
    { key: "flaggedTxns", label: "Flagged txns" }, { key: "findings", label: "Findings" }, { key: "status", label: "Status" },
  ];
  const MER_COLS = [
    { key: "merchant", label: "Merchant" }, { key: "mcc", label: "MCC", render: (m) => esc(m.mcc) + (m.mccLabel ? '<div class="' + P + '-note">' + esc(m.mccLabel) + "</div>" : "") },
    { key: "txns", label: "Txns" }, { key: "employees", label: "Employees" }, { key: "total", label: "Total", sortKey: "totalCents", render: (m) => '<span class="' + P + '-nw">' + esc(m.total) + "</span>" }, { key: "flags", label: "Flagged txns" },
  ];
  const MON_COLS = [{ key: "month", label: "Month" }, { key: "currency", label: "Currency" }, { key: "txns", label: "Txns" }, { key: "employees", label: "Employees" },
    { key: "total", label: "Total", sortKey: "totalCents" }, { key: "flaggedTxns", label: "Flagged txns" }, { key: "flagged", label: "Flagged amount", sortKey: "flaggedCents" }];

  function drawPane() {
    const pane = $("pane"), r = result;
    pane.innerHTML = "";
    if (tab === "findings") {
      if (!r.findings.length) { pane.innerHTML = '<div class="' + P + '-empty">No findings for the current thresholds.</div>'; return; }
      const rows = r.findings.map((f, i) => ({ ...f, i: String(i) }));
      const t = table(FIND_COLS, rows, sorts.findings, (s) => { sorts.findings = s; drawPane(); }, (f) => f.i);
      t.querySelectorAll("tr[data-i]").forEach((tr) => { if (tr.dataset.i === selected) tr.classList.add("sel"); tr.addEventListener("click", () => { selected = tr.dataset.i; drawPane(); showFinding(r.findings[Number(selected)]); }); });
      pane.appendChild(t);
      pane.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">Click a finding for its evidence. Detections: ' + DETECTIONS.map((d) => esc(d.title) + " (needs " + esc(d.needs) + ")").join("; ") + ".</p>");
      return;
    }
    if (tab === "employees") {
      const rows = r.tables.employees;
      if (!rows.length) { pane.innerHTML = '<div class="' + P + '-empty">No employees.</div>'; return; }
      const t = table(EMP_COLS, rows, sorts.employees, (s) => { sorts.employees = s; drawPane(); }, (e) => e.key, 1000);
      t.querySelectorAll("tr[data-i]").forEach((tr) => { if (tr.dataset.i === selected) tr.classList.add("sel"); tr.addEventListener("click", () => { selected = tr.dataset.i; drawPane(); showEmployee(rows.find((e) => e.key === selected)); }); });
      pane.appendChild(t);
      pane.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">' + (rows.length > 1000 ? "Showing 1000 of " + rows.length + " in the current sort. " : "") + "Risk = weighted count of findings (critical 40, high 25, medium 12, low 5), capped at 100. Click an employee for their findings.</p>");
      return;
    }
    if (tab === "merchants") {
      const rows = r.tables.merchants;
      if (!rows.length) { pane.innerHTML = '<div class="' + P + '-empty">No merchants.</div>'; return; }
      pane.appendChild(table(MER_COLS, rows, sorts.merchants, (s) => { sorts.merchants = s; drawPane(); }, (m) => m.key, 1000));
      if (rows.length > 1000) pane.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">Showing 1000 of ' + rows.length + " in the current sort.</p>");
      return;
    }
    if (tab === "monthly") {
      pane.innerHTML = monthlySvg(r.tables.monthly, r.summary.primaryCurrency);
      pane.appendChild(table(MON_COLS, r.tables.monthly, sorts.monthly, (s) => { sorts.monthly = s; drawPane(); }, (m) => m.month + m.currency));
      pane.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">Chart shows the most common currency (' + esc(r.summary.primaryCurrency || "unstated") + "); amounts are never converted between currencies.</p>");
    }
  }

  function closeBtn() { return '<button class="' + P + '-btn sm" data-close type="button">Close</button>'; }
  function wireClose(d) { d.querySelector("[data-close]").addEventListener("click", () => { d.style.display = "none"; selected = ""; drawPane(); }); d.scrollIntoView({ block: "nearest", behavior: "smooth" }); }

  function showFinding(f) {
    const d = $("drawer");
    d.style.display = "block";
    d.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + pill(f.severity) + " " + esc(f.title) + "</h3>" + closeBtn() + "</div>" +
      "<p>" + esc(f.description) + "</p><p><b>Recommendation:</b> " + esc(f.recommendation) + "</p><p><b>Confidence:</b> " + esc(f.confidence) + " &middot; <b>Employees:</b> " + esc((f.employees || []).join(", ")) + "</p>" +
      "<p>" + chips(f.controls) + "</p><p><b>Evidence</b> (" + f.evidence.length + " of " + f.evidenceCount + (f.evidenceCount > f.evidence.length ? "; the first 50 are kept" : "") + ")</p>" + evidenceTable(f.evidence) +
      '<div class="' + P + '-row"><button class="' + P + '-btn sm" data-ev type="button">Export evidence CSV</button></div>';
    wireClose(d);
    d.querySelector("[data-ev]").addEventListener("click", () => {
      const rows = f.evidence || [], keys = [];
      for (const x of rows) for (const k of Object.keys(x)) if (!keys.includes(k)) keys.push(k);
      download(TOOL_ID + "-evidence-" + fileStamp() + ".csv", [keys.join(","), ...rows.map((x) => keys.map((k) => csvCell(x[k])).join(","))].join("\n") + "\n", "text/csv");
    });
  }

  function showEmployee(e) {
    const d = $("drawer");
    if (!e) { d.style.display = "none"; return; }
    const fs = result.findings.map((f, i) => ({ f, i })).filter(({ f }) => (f.employees || []).includes(e.employee));
    d.style.display = "block";
    d.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + esc(e.employee) + (e.employeeId ? " (" + esc(e.employeeId) + ")" : "") + "</h3>" + closeBtn() + "</div>" +
      "<p>" + esc([e.department, e.manager ? "manager " + e.manager : "", e.status].filter(Boolean).join(" · ")) + "</p><p>" + e.txns + " transactions, " + esc(e.total) + ", risk " + e.riskScore + "</p>" +
      (fs.length ? '<div class="' + P + '-list"><table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>' + fs.map(({ f, i }) => '<tr data-fi="' + i + '" style="cursor:pointer"><td>' + pill(f.severity) + "</td><td>" + esc(f.title) + "</td><td>" + f.evidenceCount + "</td></tr>").join("") + "</tbody></table></div>" : '<p class="' + P + '-note">No findings for this employee.</p>');
    wireClose(d);
    d.querySelectorAll("tr[data-fi]").forEach((tr) => tr.addEventListener("click", () => { tab = "findings"; selected = tr.dataset.fi; render(); showFinding(result.findings[Number(selected)]); }));
  }

  // ---- exports + graph ----
  function renderExports() {
    const r = result, ex = $("exports"), stamp = fileStamp();
    const b = (x, l) => '<button class="' + P + '-btn" data-x="' + x + '">' + l + "</button>";
    ex.innerHTML = b("find", "Findings CSV") + b("json", "JSON") + b("txt", "Summary TXT") + b("follow", "Employee follow-up CSV") + b("recovery", "Duplicate recovery CSV");
    const on = (x, fn) => ex.querySelector('[data-x="' + x + '"]').addEventListener("click", fn);
    on("find", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    on("json", () => download(TOOL_ID + "-" + stamp + ".json", toJson({ ...r, summaryStats: summarize(r.findings) }), "application/json"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r), "text/plain"));
    on("follow", () => download(TOOL_ID + "-followup-" + stamp + ".csv", followupToCsv(r.tables.followup), "text/csv"));
    on("recovery", () => { if (!r.tables.recovery.length) { toast("No duplicate groups to recover", "info"); return; } download(TOOL_ID + "-recovery-" + stamp + ".csv", recoveryToCsv(r.tables.recovery), "text/csv"); });
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: datasetName() });
  }

  renderFiles();
}
