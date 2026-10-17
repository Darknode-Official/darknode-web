// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Payroll Integrity (payrollguard): Deck tool UI. Drop the payroll register, the HR roster,
// the direct-deposit change log and (optionally) timesheets together; each file is
// classified by its headers (role editable, mapping panel when confidence is not high),
// then the engine (payrollguard-engine.js, pure) runs in a Worker. Runs entirely in the
// browser; nothing is uploaded. No native dialogs; toasts only.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import { DEFAULTS, TOOL_ID, FIELD_LABELS, parseInput, findingsToCsv, worklistCsv, bankChangesCsv, summaryText, formatCents, exampleDataset } from "./payrollguard-engine.js?v=20261016n";

const ENGINE = engineUrl("./payrollguard-engine.js?v=20261016n", import.meta);
const P = "pay";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (n) => (n == null || n === "" ? "-" : Number(n).toLocaleString());
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0, none: -1 };
const ROLE_LABEL = { register: "Payroll register", roster: "HR roster", bank: "Bank / direct-deposit changes", timesheet: "Timesheets", ignore: "Ignore this file", unknown: "Unrecognised" };
const VENDOR_LABEL = { adp: "ADP Workforce Now", gusto: "Gusto", workday: "Workday", paychex: "Paychex", generic: "Generic", "adp-audit": "ADP change audit (long form)", "workday-bp": "Workday business process audit", "gusto-history": "Bank-account change history" };
const ROLES = ["register", "roster", "bank", "timesheet", "ignore"];
const MAP_FIELDS = {
  register: ["employeeId", "name", "payDate", "periodStart", "periodEnd", "gross", "net", "tax", "fit", "deductions", "regHours", "otHours", "hours", "bankAccount", "bankLast4", "routing", "paymentType", "department"],
  roster: ["employeeId", "name", "ssn", "address", "postal", "phone", "email", "department", "managerId", "hireDate", "termDate", "status", "payType", "salary", "hourlyRate"],
  bank: ["employeeId", "name", "changedAt", "changedBy", "newAccount", "newRouting", "oldLast4", "channel", "ip", "field", "oldValue", "newValue", "process"],
  timesheet: ["employeeId", "name", "date", "hours", "approvedBy", "project"],
};
const THRESHOLDS = [
  ["bankChangeDays", "Bank-change window (days)", "A deposit change this many days or fewer before the next pay date is screened."],
  ["spikeZ", "Pay spike robust z", "Median / MAD z-score above which a period's gross is a spike."],
  ["spikeMinPct", "Spike minimum excess (%)", "A spike must also exceed the employee's median gross by this much."],
  ["minPeriods", "Minimum pay periods", "Periods an employee needs before the spike test runs."],
  ["maxOvertime", "Max overtime (h / week)", "Overtime hours per week-equivalent of the pay period."],
  ["maxWeeklyHours", "Implausible hours (h / week)", "Total paid hours per week above this are flagged."],
  ["campaignMin", "Campaign size (employees)", "Distinct employees changing to one routing number inside the window."],
  ["campaignWindowDays", "Campaign window (days)", "Span for the same-routing campaign check."],
  ["salaryTolerancePct", "Salary tolerance (%)", "Salaried gross may exceed salary / periods per year by this much."],
  ["finalPayDays", "Final-pay grace (days)", "Used only without period dates: pay this soon after termination is a plausible final check."],
];

const CSS = `
  .pay-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .pay-root *{box-sizing:border-box}
  .pay-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .pay-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .pay-hd h2{font-size:1.05rem;margin:0}
  .pay-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .pay-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:95ch;overflow-wrap:anywhere}
  .pay-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;max-width:100%}
  .pay-card h2{font-size:.95rem;margin:0 0 8px}
  .pay-help{font-size:.78rem;color:var(--mut,#667085);margin:2px 0 8px;overflow-wrap:anywhere}
  .pay-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .pay-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .pay-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .pay-btn.on{border-color:#2552c6;color:#2552c6}
  .pay-btn:disabled{opacity:.5;cursor:default}
  .pay-ctl{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:14px 20px}
  .pay-field{display:flex;flex-direction:column;gap:4px;min-width:0}
  .pay-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .pay-field input{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:130px;max-width:100%}
  .pay-field small{font-size:.74rem;color:var(--mut,#667085);overflow-wrap:anywhere}
  .pay-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}
  .pay-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .pay-kpi b{display:block;font-size:1.3rem;overflow-wrap:anywhere}
  .pay-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .pay-kpi.bad b{color:#b00020}
  .pay-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .pay-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .pay-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0}
  .pay-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%;background:var(--card,#fff)}
  .pay-list table{width:100%;border-collapse:collapse;font-size:.84rem;min-width:600px}
  .pay-list th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .pay-list th[data-sort]{cursor:pointer}
  .pay-list th[data-sort].asc::after{content:" \\2191"}.pay-list th[data-sort].desc::after{content:" \\2193"}
  .pay-list td{padding:9px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word}
  .pay-list td.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
  .pay-list tr[data-i]{cursor:pointer}
  .pay-list tr[data-i]:hover,.pay-list tr.sel{background:var(--bg,#f7f8fb)}
  .pay-list select{min-width:170px;font:inherit;font-size:.8rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:4px 6px;max-width:100%}
  .pay-pill{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .pay-pill.critical{background:#7a0012}.pay-pill.high{background:#b00020}.pay-pill.medium{background:#b58100}.pay-pill.low{background:#2552c6}.pay-pill.info,.pay-pill.none{background:#667085}
  .pay-pill.conf-high{background:#1f7a3a}.pay-pill.conf-medium{background:#b58100}.pay-pill.conf-low{background:#b00020}
  .pay-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);overflow-wrap:anywhere}
  .pay-flag{display:inline-block;font-size:.72rem;border:1px solid #b00020;color:#b00020;border-radius:6px;padding:0 6px;margin:1px 4px 1px 0}
  .pay-conf{font-size:.76rem;text-transform:capitalize}
  .pay-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .pay-drawer{margin-top:14px;display:none}
  .pay-drawer .pay-list{max-height:380px}
  .pay-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px;overflow-wrap:anywhere}
  .pay-search{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:360px}
  .pay-map{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px 14px;margin-top:8px}
  .pay-map label{display:block;font-size:.7rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.04em}
  .pay-map select{width:100%;min-width:0}
  .pay-chart{width:100%;height:auto;display:block}
  .pay-chart .bar{fill:#2552c6}
  .pay-chart .bar:hover{fill:#173b99}
  .pay-chart text{fill:var(--mut,#667085);font-size:11px}
  .pay-chart .axis{stroke:var(--line,#e6e8ee)}
  @media (max-width:520px){.pay-field input{width:100%}.pay-list table{min-width:0}}
`;

function kpi(v, l, bad) { return '<div class="' + P + "-kpi" + (bad ? " bad" : "") + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>"; }
function pill(cls, text) { return '<span class="' + P + "-pill " + esc(cls) + '">' + esc(text) + "</span>"; }
function evidenceTable(rows) {
  if (!rows || !rows.length) return '<div class="' + P + '-empty">No evidence rows.</div>';
  const cols = [];
  for (const r of rows) for (const k of Object.keys(r || {})) if (!cols.includes(k)) cols.push(k);
  const cell = (v) => (v == null ? "" : Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v));
  return "<table><thead><tr>" + cols.map((c) => "<th>" + esc(c.replace(/_/g, " ")) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + cols.map((c) => "<td>" + esc(cell(r[c])) + "</td>").join("") + "</tr>").join("") + "</tbody></table>";
}

/** Mount the tool into main. */
export function renderPayrollGuard(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Payroll Integrity</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Screens your payroll register against the HR roster, the direct-deposit change log and timesheets for ghost employees, falsified wages, shared bank details and payroll-diversion bank changes just before payday. Results are patterns to review, not conclusions. SSNs and account numbers are shown as last 4 only. Runs entirely in your browser. Nothing is uploaded; nothing is fetched live.</p>',
    '<div class="', P, '-card"><div id="', P, '-drop"></div>',
    '<p class="', P, '-help">Accepted: ADP Workforce Now payroll register, Gusto payroll journal, Paychex payroll journal, Workday pay results or a generic register CSV; an HR roster (Workday, BambooHR, Rippling or generic); a direct-deposit change log (ADP change audit, Workday business process audit, Gusto bank history or generic); timesheets (optional). Zip and gzip archives are unpacked.</p>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button>',
    '<button class="', P, '-btn" id="', P, '-clear" disabled>Clear files</button><span id="', P, '-count" class="', P, '-skip"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div></div>',
    '<div class="', P, '-card" id="', P, '-files-card" style="display:none"><h2>Files</h2><p class="', P, '-help">Each file is classified by its headers. Correct the role if a detection is wrong; files below high confidence show a column-mapping panel.</p><div id="', P, '-files"></div></div>',
    '<div class="', P, '-card"><h2>Thresholds</h2><div class="', P, '-ctl">',
    THRESHOLDS.map(([k, l, h]) => '<div class="' + P + '-field"><label for="' + P + "-opt-" + k + '">' + esc(l) + '</label><input id="' + P + "-opt-" + k + '" data-opt="' + k + '" type="number" min="0" step="any" value="' + esc(DEFAULTS[k]) + '"><small>' + esc(h) + " Default " + esc(DEFAULTS[k]) + ".</small></div>").join(""),
    "</div></div>",
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-tabs" id="', P, '-tabs" style="display:none"><button class="', P, '-btn on" data-tab="findings">Findings</button><button class="', P, '-btn" data-tab="employees">Employees</button><button class="', P, '-btn" data-tab="bank">Bank changes</button><button class="', P, '-btn" data-tab="shared">Shared identifiers</button><button class="', P, '-btn" data-tab="periods">Periods</button></div>',
    '<div id="', P, '-view"><div class="', P, '-list"><div class="', P, '-empty">No analysis yet. Drop files or load the synthetic example.</div></div></div>',
    '<div class="', P, '-skip" id="', P, '-skipped"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, tab = "findings", sort = { key: "severity", dir: "desc" }, search = "";

  function setFiles(list, example = false) {
    files = list; isExample = example;
    const rows = files.reduce((n, f) => n + f.rowCount, 0);
    $("count").textContent = files.length ? files.length + " file(s), " + num(rows) + " rows" : "";
    $("run").disabled = !files.length; $("clear").disabled = !files.length;
    renderFiles();
  }

  function renderFiles() {
    $("files-card").style.display = files.length ? "" : "none";
    const box = $("files");
    if (!files.length) { box.innerHTML = ""; return; }
    box.innerHTML = '<div class="' + P + '-list"><table><thead><tr><th>File</th><th>Rows</th><th>Role</th><th>Detected as</th><th>Confidence</th></tr></thead><tbody>' +
      files.map((f, i) => "<tr><td>" + esc(f.name) + '</td><td class="num">' + num(f.rowCount) + '</td><td><select data-kind="' + i + '" aria-label="File role">' +
        ROLES.concat(f.kind === "unknown" ? ["unknown"] : []).map((k) => '<option value="' + k + '"' + (f.kind === k ? " selected" : "") + ">" + esc(ROLE_LABEL[k]) + "</option>").join("") +
        "</select></td><td>" + esc(f.kind === "unknown" ? "unrecognised headers" : (VENDOR_LABEL[f.vendor] || f.vendor) + " " + (ROLE_LABEL[f.kind] || "").toLowerCase()) + "</td><td>" + pill("conf-" + f.confidence, f.confidence) + "</td></tr>" +
        (f.confidence !== "high" && MAP_FIELDS[f.kind] ? '<tr><td colspan="5"><div class="' + P + '-help">Column mapping for ' + esc(f.name) + '. Auto picks the header by alias; override where wrong. A check whose column is unmapped is skipped, never guessed.</div><div class="' + P + '-map">' +
          MAP_FIELDS[f.kind].map((k) => '<div><label>' + esc(FIELD_LABELS[k] || k) + '</label><select data-map="' + i + '" data-key="' + k + '"><option value="">(auto)</option>' +
            f.headers.map((h) => '<option value="' + esc(h) + '"' + ((f.columns || {})[k] === h ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>").join("") + "</div></td></tr>" : "")).join("") +
      "</tbody></table></div>";
    box.querySelectorAll("[data-kind]").forEach((el) => el.addEventListener("change", () => {
      const f = files[Number(el.dataset.kind)]; f.kind = el.value; f.confidence = "medium"; f.columns = {}; renderFiles();
    }));
    box.querySelectorAll("[data-map]").forEach((el) => el.addEventListener("change", () => {
      const f = files[Number(el.dataset.map)]; f.columns = f.columns || {};
      if (el.value) f.columns[el.dataset.key] = el.value; else delete f.columns[el.dataset.key];
    }));
  }

  mountDropzone($("drop"), {
    maxBytes: 256 * 1024 * 1024, maxFiles: 50, multiple: true, unpack: true,
    label: "Drop the payroll register, HR roster, bank-change log and timesheets here, paste, or browse",
    onFiles: async (dropped) => {
      const inputs = [];
      for (const f of dropped) inputs.push({ name: f.name, text: await f.text() });
      const parsed = parseInput(inputs);
      const good = parsed.files.filter((f) => f.rowCount);
      if (!good.length) { toast("No rows found in the dropped file(s)", "error"); return; }
      for (const s of parsed.skipped) if (s.check === "parse") toast(s.reason, "warning");
      const merged = isExample ? [] : files.filter((f) => !good.some((g) => g.name === f.name));
      setFiles(merged.concat(good), false);
      toast("Loaded " + good.length + " file(s): " + good.map((f) => ROLE_LABEL[f.kind] || f.kind).join(", "));
    },
  });

  $("clear").addEventListener("click", () => setFiles([], false));
  $("example").addEventListener("click", () => {
    const parsed = parseInput(exampleDataset().files);
    setFiles(parsed.files, true);
    toast("Synthetic example loaded (Gusto journal, roster, bank-change log). Its SSNs use the never-issued 9xx area, so the SSN rule fires on every row by design. Press Analyze.");
  });

  function opts() {
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (el.value !== "" && Number.isFinite(n)) o[el.dataset.opt] = n; });
    return o;
  }

  $("run").addEventListener("click", async () => {
    const prog = $("prog"), bar = prog.firstElementChild;
    prog.style.display = "block"; bar.style.width = "0%"; $("run").disabled = true;
    try {
      const payload = files.map((f) => ({ name: f.name, kind: f.kind, vendor: f.vendor, confidence: f.confidence, headers: f.headers, rows: f.rows, rowCount: f.rowCount, columns: f.columns || {} }));
      result = await runInWorker(ENGINE, "analyze", [{ files: payload }, opts()], {
        onProgress: (i, n) => { bar.style.width = (n ? Math.round((i / n) * 100) : 0) + "%"; },
      });
      tab = "findings"; sort = { key: "severity", dir: "desc" }; search = "";
      render(result);
      toast(result.findings.length + " finding(s) across " + result.summary.employeesPaid + " paid employee(s)", result.findings.some((f) => f.severity === "critical") ? "warning" : "success");
    } catch (e) {
      toast("Analysis failed: " + ((e && e.message) || e), "error");
    } finally {
      prog.style.display = "none"; $("run").disabled = !files.length;
    }
  });

  const money = (c, cur) => formatCents(c) + (cur && !/^mixed/.test(cur) ? " " + cur : "");

  function render(r) {
    const s = r.summary, cur = s.currency;
    $("kpis").innerHTML = kpi(num(s.employeesPaid), "employees paid") + kpi(money(s.grossCents, cur), "gross") + kpi(money(s.netCents, cur), "net") +
      kpi(num(s.ghostCandidates), "ghost candidates", s.ghostCandidates > 0) + kpi(num(s.sharedBankAccounts), "shared bank accounts", s.sharedBankAccounts > 0) +
      kpi(num(s.bankChangesBeforePayday) + " / " + num(s.bankChanges), "bank changes before payday", s.bankChangesBeforePayday > 0) +
      kpi(num(r.findings.length), "findings", (s.bySeverity.critical || 0) > 0) + kpi(money(s.amountAtRiskCents, cur), "net pay on flagged rows");
    $("skipped").innerHTML = r.skipped.length ? "<b>Skipped checks</b> (missing files or columns, never guessed): " + r.skipped.map((x) => esc(x.check) + " - " + esc(x.reason)).join("; ") : "";
    const ex = $("exports");
    ex.innerHTML = '<button class="' + P + '-btn" data-x="csv">Findings CSV</button><button class="' + P + '-btn" data-x="json">Full JSON</button><button class="' + P + '-btn" data-x="txt">Summary TXT</button>' +
      '<button class="' + P + '-btn" data-x="work">Investigation worklist CSV</button><button class="' + P + '-btn" data-x="bank">Bank-change review CSV</button>';
    const stamp = fileStamp();
    ex.querySelector('[data-x="csv"]').addEventListener("click", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    ex.querySelector('[data-x="json"]').addEventListener("click", () => download(TOOL_ID + "-" + stamp + ".json", toJson(r), "application/json"));
    ex.querySelector('[data-x="txt"]').addEventListener("click", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r) + "\nSummary: " + JSON.stringify(summarize(r.findings)) + "\n", "text/plain"));
    ex.querySelector('[data-x="work"]').addEventListener("click", () => download(TOOL_ID + "-worklist-" + stamp + ".csv", worklistCsv(r), "text/csv"));
    ex.querySelector('[data-x="bank"]').addEventListener("click", () => download(TOOL_ID + "-bank-changes-" + stamp + ".csv", bankChangesCsv(r), "text/csv"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: files.map((f) => f.name).join(", ") });
    const tabs = $("tabs"); tabs.style.display = "";
    tabs.querySelectorAll("[data-tab]").forEach((b) => { b.onclick = () => { tab = b.dataset.tab; search = ""; renderView(r); }; });
    $("drawer").style.display = "none";
    renderView(r);
  }

  function renderView(r) {
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.classList.toggle("on", b.dataset.tab === tab));
    const v = $("view");
    if (tab === "findings") renderFindings(r, v);
    else if (tab === "employees") renderEmployees(r, v);
    else if (tab === "bank") renderBank(r, v);
    else if (tab === "shared") renderShared(r, v);
    else renderPeriods(r, v);
  }

  function sortable(ths, onSort) {
    ths.forEach((th) => {
      const k = th.dataset.sort; if (!k) return;
      th.classList.toggle("asc", sort.key === k && sort.dir === "asc"); th.classList.toggle("desc", sort.key === k && sort.dir === "desc");
      th.addEventListener("click", () => { sort = { key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" }; onSort(); });
    });
  }
  const by = (get) => (a, b) => { const x = get(a), y = get(b); const c = x < y ? -1 : x > y ? 1 : 0; return sort.dir === "asc" ? c : -c; };
  const empty = (msg) => '<div class="' + P + '-list"><div class="' + P + '-empty">' + esc(msg) + "</div></div>";

  function renderFindings(r, v) {
    if (!r.findings.length) { v.innerHTML = empty("No findings for the current thresholds and files."); return; }
    const g = { severity: (f) => SEV_RANK[f.severity] || 0, title: (f) => f.title.toLowerCase(), confidence: (f) => f.confidence, category: (f) => f.category, evidence: (f) => f.evidenceCount || 0, risk: (f) => f.amountAtRiskCents || 0 };
    const key = g[sort.key] ? sort.key : "severity";
    const list = r.findings.map((f, i) => ({ f, i })).sort((a, b) => by((x) => g[key](x.f))(a, b) || SEV_RANK[b.f.severity] - SEV_RANK[a.f.severity]);
    v.innerHTML = '<div class="' + P + '-list"><table><thead><tr><th data-sort="severity">Severity</th><th data-sort="title">Finding</th><th data-sort="category">Category</th><th data-sort="confidence">Confidence</th><th>Controls</th><th data-sort="evidence">Evidence</th><th data-sort="risk">At risk</th></tr></thead><tbody>' +
      list.map(({ f, i }) => '<tr data-i="' + i + '"><td>' + pill(f.severity, f.severity) + "</td><td><b>" + esc(f.title) + "</b><div>" + esc(f.description) + "</div></td><td>" + esc(f.category) + '</td><td class="' + P + '-conf">' + esc(f.confidence) + "</td><td>" +
        (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + '</td><td class="num">' + num(f.evidenceCount) + '</td><td class="num">' + (f.amountAtRiskCents ? esc(formatCents(f.amountAtRiskCents)) : "-") + "</td></tr>").join("") + "</tbody></table></div>";
    sortable(v.querySelectorAll("th[data-sort]"), () => renderFindings(r, v));
    v.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => {
      v.querySelectorAll("tr.sel").forEach((x) => x.classList.remove("sel")); tr.classList.add("sel");
      const f = r.findings[Number(tr.dataset.i)];
      const d = $("drawer"); d.style.display = "block";
      d.innerHTML = '<div class="' + P + '-card"><div class="' + P + '-hd"><h2>' + esc(f.title) + "</h2>" + pill(f.severity, f.severity) + '<span class="' + P + '-conf">' + esc(f.confidence) + '</span></div><p class="' + P + '-help">' + esc(f.description) + "</p><p><b>Recommendation.</b> " + esc(f.recommendation) + "</p><div>" +
        (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + '</div><p class="' + P + '-help">Evidence: ' + num(f.evidenceCount) + " row(s)" + (f.evidenceCount > (f.evidence || []).length ? ", first " + (f.evidence || []).length + " shown" : "") +
        (f.amountAtRiskCents ? ". Amount at risk: " + esc(formatCents(f.amountAtRiskCents)) : "") + '</p><div class="' + P + '-list">' + evidenceTable(f.evidence) + "</div></div>";
      d.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }));
  }

  function searchBox(v, count, total, noun, rerender) {
    v.insertAdjacentHTML("afterbegin", '<div class="' + P + '-row" style="margin:0 0 10px"><input class="' + P + '-search" id="' + P + '-search" type="search" placeholder="Search" value="' + esc(search) + '"><span class="' + P + '-skip">' + num(count) + " of " + num(total) + " " + noun + "</span></div>");
    const inp = v.querySelector("#" + P + "-search");
    inp.addEventListener("input", () => { search = inp.value; const pos = inp.selectionStart; rerender(); const n = v.querySelector("#" + P + "-search"); n.focus(); try { n.setSelectionRange(pos, pos); } catch (_) {} });
  }

  function renderEmployees(r, v) {
    const all = r.tables.employees || [];
    const q = search.toLowerCase();
    const rows = all.filter((e) => !q || [e.employee, e.department, e.manager, e.status, ...e.flags].join(" ").toLowerCase().includes(q));
    const g = { employee: (e) => e.employee.toLowerCase(), department: (e) => e.department, periods: (e) => e.periods, gross: (e) => e.grossCents, net: (e) => e.netCents, risk: (e) => SEV_RANK[e.risk], atRisk: (e) => e.amountAtRiskCents, flags: (e) => e.flags.length };
    rows.sort(by(g[sort.key] || g.risk));
    v.innerHTML = '<div class="' + P + '-list"><table><thead><tr><th data-sort="employee">Employee</th><th data-sort="department">Department</th><th>Manager</th><th>Status</th><th data-sort="periods">Periods</th><th data-sort="gross">Gross</th><th data-sort="net">Net</th><th data-sort="flags">Flags</th><th data-sort="risk">Risk</th><th data-sort="atRisk">At risk</th></tr></thead><tbody>' +
      (rows.length ? rows.map((e) => "<tr><td><b>" + esc(e.employee) + "</b></td><td>" + esc(e.department || "-") + "</td><td>" + esc(e.manager || "-") + "</td><td>" + esc(e.status) + '</td><td class="num">' + num(e.periods) + '</td><td class="num">' + esc(formatCents(e.grossCents)) + '</td><td class="num">' + esc(formatCents(e.netCents)) + "</td><td>" +
        e.flags.map((f) => '<span class="' + P + '-flag">' + esc(f) + "</span>").join("") + "</td><td>" + pill(e.risk, e.risk) + '</td><td class="num">' + (e.amountAtRiskCents ? esc(formatCents(e.amountAtRiskCents)) : "-") + "</td></tr>").join("")
        : '<tr><td colspan="10" class="' + P + '-empty">No employees match.</td></tr>') + "</tbody></table></div>";
    searchBox(v, rows.length, all.length, "employees", () => renderEmployees(r, v));
    sortable(v.querySelectorAll("th[data-sort]"), () => renderEmployees(r, v));
  }

  function renderBank(r, v) {
    const all = r.tables.bankChanges || [];
    if (!all.length) { v.innerHTML = empty("No bank-change log loaded."); return; }
    const q = search.toLowerCase();
    const rows = all.filter((b) => !q || [b.employee, b.changed_by, b.channel, b.ip, b.routing, ...b.flags].join(" ").toLowerCase().includes(q));
    const yn = (x) => (x == null ? "unknown" : x ? "yes" : "no");
    v.innerHTML = '<p class="' + P + '-help">Each deposit change with the days to the next pay date. Accounts show last 4 only; routing numbers are public bank identifiers.</p><div class="' + P + '-list"><table><thead><tr><th>Employee</th><th>Changed at</th><th>Changed by</th><th>Channel</th><th>IP</th><th>Old</th><th>New account</th><th>Routing valid</th><th>Next pay</th><th>Days</th><th>Paid to new</th><th>Flags</th></tr></thead><tbody>' +
      rows.map((b) => "<tr><td><b>" + esc(b.employee) + "</b></td><td>" + esc(b.changed_at) + "</td><td>" + esc(b.changed_by || "-") + "</td><td>" + esc(b.channel || "-") + "</td><td>" + esc(b.ip || "-") + "</td><td>" + esc(b.old_account || "-") + "</td><td>" + esc(b.new_account || "-") + "</td><td>" + esc(yn(b.routing_valid)) + "</td><td>" + esc(b.next_pay_date || "-") +
        '</td><td class="num">' + (b.days_to_payday == null ? "-" : esc(b.days_to_payday)) + "</td><td>" + esc(yn(b.paid_to_new_account)) + "</td><td>" + b.flags.map((f) => '<span class="' + P + '-flag">' + esc(f) + "</span>").join("") + "</td></tr>").join("") + "</tbody></table></div>";
    searchBox(v, rows.length, all.length, "changes", () => renderBank(r, v));
  }

  function renderShared(r, v) {
    const rows = r.tables.shared || [];
    if (!rows.length) { v.innerHTML = empty("No identifiers shared between employees."); return; }
    v.innerHTML = '<p class="' + P + '-help">Bank accounts, SSN / national ids, addresses, phones and emails held by more than one employee. Shared addresses are common for families and housemates; treat them as context.</p><div class="' + P + '-list"><table><thead><tr><th>Type</th><th>Identifier</th><th>Employees</th><th>Count</th><th>Severity</th><th>Note</th></tr></thead><tbody>' +
      rows.map((s) => "<tr><td>" + esc(s.type) + "</td><td>" + esc(s.identifier) + "</td><td>" + esc(s.employees.join(", ")) + '</td><td class="num">' + num(s.count) + "</td><td>" + pill(s.severity, s.severity) + "</td><td>" + esc(s.note || "") + "</td></tr>").join("") + "</tbody></table></div>";
  }

  function renderPeriods(r, v) {
    const rows = r.tables.periods || [];
    if (!rows.length) { v.innerHTML = empty("No pay dates in the register."); return; }
    const W = Math.max(320, rows.length * 56), H = 220, padL = 8, padB = 34, padT = 22;
    const max = Math.max(...rows.map((p) => p.grossCents), 1);
    const slot = (W - padL * 2) / rows.length, bw = Math.max(6, Math.min(36, slot - 2));
    const bars = rows.map((p, i) => {
      const h = Math.max(1, Math.round(((H - padB - padT) * p.grossCents) / max));
      const x = padL + i * slot + (slot - bw) / 2, y = H - padB - h;
      const rr = Math.min(4, bw / 2, h);
      const d = "M" + x + "," + (H - padB) + "V" + (y + rr) + "Q" + x + "," + y + " " + (x + rr) + "," + y + "H" + (x + bw - rr) + "Q" + (x + bw) + "," + y + " " + (x + bw) + "," + (y + rr) + "V" + (H - padB) + "Z";
      const tip = p.payDate + ": gross " + formatCents(p.grossCents) + ", net " + formatCents(p.netCents) + ", " + p.headcount + " paid, " + p.flaggedEmployees + " flagged";
      return '<path class="bar" d="' + d + '"><title>' + esc(tip) + "</title></path>" +
        (rows.length <= 16 || i % Math.ceil(rows.length / 16) === 0 ? '<text x="' + (x + bw / 2) + '" y="' + (H - padB + 14) + '" text-anchor="middle">' + esc(p.payDate.slice(5)) + "</text>" : "") +
        (p.flaggedEmployees ? '<text x="' + (x + bw / 2) + '" y="' + (y - 5) + '" text-anchor="middle">' + p.flaggedEmployees + " flagged</text>" : "");
    }).join("");
    v.innerHTML = '<div class="' + P + '-card"><h2>Gross pay per pay date</h2><p class="' + P + '-help">Hover a bar for gross, net, headcount and flagged employees. Labels above bars count employees with a flagged payment on that date.</p>' +
      '<div style="overflow-x:auto"><svg class="' + P + '-chart" viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Gross pay per pay date" style="min-width:' + Math.min(W, 320) + 'px;max-width:' + Math.max(W, 640) + 'px">' +
      '<line class="axis" x1="0" x2="' + W + '" y1="' + (H - padB) + '" y2="' + (H - padB) + '"></line>' + bars + "</svg></div></div>" +
      '<div class="' + P + '-list"><table><thead><tr><th>Pay date</th><th>Headcount</th><th>Payments</th><th>Gross</th><th>Net</th><th>Flagged employees</th></tr></thead><tbody>' +
      rows.map((p) => "<tr><td>" + esc(p.payDate) + '</td><td class="num">' + num(p.headcount) + '</td><td class="num">' + num(p.payments) + '</td><td class="num">' + esc(formatCents(p.grossCents)) + '</td><td class="num">' + esc(formatCents(p.netCents)) + '</td><td class="num">' + num(p.flaggedEmployees) + "</td></tr>").join("") + "</tbody></table></div>";
  }
}

