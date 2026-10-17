// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// AP Forensics (apforensics): Deck tool UI. Drop the AP ledger, the vendor master and
// (optionally) the employee roster; the engine runs forensic screens inside a Worker.
// Runs entirely in the browser; the only request is the same-origin US federal holiday
// reference file. No native dialogs; toasts only.
//
//   renderApForensics(main) -> void

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, COLUMNS, COLUMN_LABEL, FORMATS, ROLE_LABEL, SEV_RANK,
  detectFile, resolveColumns, findingsToCsv, recoveryToCsv, vendorsToCsv, summaryText, exampleDataset, fmtMoney,
} from "./apforensics-engine.js?v=20261016l";

const ENGINE = engineUrl("./apforensics-engine.js?v=20261016l", import.meta);
const P = "apf";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const CONF_RANK = { confirmed: 3, likely: 2, review: 1 };
const fmtSize = (n) => (n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB");

const CSS = `
  .apf-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .apf-root *{box-sizing:border-box}
  .apf-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .apf-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .apf-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .apf-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:95ch}
  .apf-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .apf-card h2{font-size:.95rem;margin:0 0 10px}
  .apf-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .apf-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .apf-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .apf-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .apf-btn.sm{padding:4px 9px;font-size:.76rem}
  .apf-btn:disabled{opacity:.5;cursor:default}
  .apf-files{display:flex;flex-direction:column;gap:6px;margin-top:12px}
  .apf-file{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;font-size:.82rem;min-width:0}
  .apf-file b{overflow-wrap:anywhere;min-width:0}
  .apf-file label{display:flex;gap:6px;align-items:center;flex-wrap:wrap;min-width:0;max-width:100%}
  .apf-file select{font:inherit;font-size:.78rem;max-width:100%;min-width:0;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:3px 6px;background:var(--card,#fff);color:var(--tx,#1a2230)}
  .apf-muted{color:var(--mut,#667085)}
  .apf-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085);white-space:nowrap}
  .apf-conf.high{color:#1b7f4d;border-color:#1b7f4d}.apf-conf.medium{color:#8a6d00;border-color:#8a6d00}.apf-conf.low{color:#b00020;border-color:#b00020}
  .apf-ctl{display:flex;flex-wrap:wrap;gap:14px 20px;align-items:flex-start}
  .apf-field{display:flex;flex-direction:column;gap:4px;min-width:0;flex:1 1 170px}
  .apf-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .apf-field input,.apf-field select{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%}
  .apf-field small{font-size:.74rem;color:var(--mut,#667085);line-height:1.4}
  .apf-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .apf-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:120px;flex:1 1 120px}
  .apf-kpi b{display:block;font-size:1.25rem;overflow-wrap:anywhere}
  .apf-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .apf-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .apf-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .apf-plabel{font-size:.74rem;color:var(--mut,#667085);margin-top:4px;display:none;overflow-wrap:anywhere}
  .apf-tabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;border-bottom:1px solid var(--line,#e6e8ee);padding-bottom:8px}
  .apf-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid transparent;background:none;color:var(--mut,#667085);padding:6px 12px;border-radius:8px;cursor:pointer}
  .apf-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#d7dbe3);background:var(--bg,#f7f8fb)}
  .apf-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .apf-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:640px}
  .apf-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .apf-list th.on{color:var(--tx,#1a2230)}
  .apf-list th.on::after{content:" \\2193";font-size:.7rem}
  .apf-list th.on.asc::after{content:" \\2191"}
  .apf-list td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word}
  .apf-list tr[data-i]{cursor:pointer}
  .apf-list tr[data-i]:hover,.apf-list tr.sel{background:var(--bg,#f7f8fb)}
  .apf-nw{white-space:nowrap}
  .apf-num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
  .apf-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .apf-pill.critical{background:#7a0012}.apf-pill.high{background:#b00020}.apf-pill.medium{background:#b58100}.apf-pill.low{background:#2552c6}.apf-pill.info{background:#667085}
  .apf-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);overflow-wrap:anywhere}
  .apf-risk{font-weight:700}.apf-risk.hi{color:#b00020}.apf-risk.mid{color:#8a6d00}.apf-risk.lo{color:#1b7f4d}
  .apf-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .apf-drawer{margin-top:12px;display:none;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--bg,#f7f8fb);min-width:0}
  .apf-drawer h3{margin:0 0 6px;font-size:1rem;overflow-wrap:anywhere}
  .apf-drawer p{margin:6px 0;overflow-wrap:anywhere}
  .apf-drawer .apf-list{background:var(--card,#fff);margin-top:10px}
  .apf-drawer .apf-list table{min-width:480px}
  .apf-skip{font-size:.78rem;color:var(--mut,#667085);margin:8px 0 0;padding-left:18px}
  .apf-skip li{margin:2px 0;overflow-wrap:anywhere}
  .apf-filters{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:flex-end;margin-bottom:10px}
  .apf-filters .apf-field{flex:0 1 220px}
  .apf-svg{width:100%;height:auto;display:block}
  .apf-svg text{font:11px system-ui,sans-serif;fill:var(--tx,#1a2230)}
  .apf-svg .m{fill:var(--mut,#667085)}
  .apf-legend{display:flex;flex-wrap:wrap;gap:12px;font-size:.76rem;color:var(--mut,#667085);margin-top:8px}
  .apf-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
  .apf-heat td.h{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums;font-size:.76rem}
  @media (max-width:560px){.apf-field,.apf-filters .apf-field{flex:1 1 100%}.apf-card{padding:14px}.apf-kpi{flex:1 1 calc(50% - 10px)}}
`;

const kpi = (v, l) => '<div class="' + P + '-kpi"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const pill = (s) => '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>";
const riskCls = (n) => (n >= 40 ? "hi" : n >= 15 ? "mid" : "lo");
const sortBy = (rows, key, dir, rank) => rows.slice().sort((a, b) => {
  const x = rank ? (rank[a[key]] ?? -1) : a[key], y = rank ? (rank[b[key]] ?? -1) : b[key];
  const r = typeof x === "number" && typeof y === "number" ? x - y : cmp(String(x == null ? "" : x).toLowerCase(), String(y == null ? "" : y).toLowerCase());
  return dir === "asc" ? r : -r;
});

/** Sortable table: cols = [{key, label, render?, rank?, cls?}]. */
function table(cols, rows, sort, onSort, rowKey) {
  const head = cols.map((c) => '<th data-k="' + esc(c.key) + '" class="' + (sort.key === c.key ? "on " + sort.dir : "") + '">' + esc(c.label) + "</th>").join("");
  const sorted = sortBy(rows, sort.key, sort.dir, (cols.find((c) => c.key === sort.key) || {}).rank);
  const body = sorted.map((r) => "<tr" + (rowKey ? ' data-i="' + esc(rowKey(r)) + '"' : "") + ">" + cols.map((c) => "<td" + (c.cls ? ' class="' + P + "-" + c.cls + '"' : "") + ">" + (c.render ? c.render(r) : esc(r[c.key] == null ? "" : r[c.key])) + "</td>").join("") + "</tr>").join("");
  const el = document.createElement("div");
  el.className = P + "-list";
  el.innerHTML = "<table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table>";
  el.querySelectorAll("th").forEach((th) => th.addEventListener("click", () => { const k = th.dataset.k; onSort({ key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" }); }));
  return el;
}

/** Plain table: columns are the union of keys. */
function plainTable(rows) {
  if (!rows || !rows.length) return '<p class="' + P + '-note">No rows.</p>';
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
  const cell = (v) => (v === true ? "yes" : v === false ? "no" : v == null ? "" : Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v));
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => "<td>" + esc(cell(r[k])) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

const THRESHOLDS = [
  ["approvalThreshold", "Approval threshold", "Your approval limit in the ledger currency. Blank skips the split-invoice and under-threshold checks.", "e.g. 10000", "any"],
  ["dupWindowDays", "Duplicate window (days)", "Near-match duplicates must be within this many days.", "", "1"],
  ["splitDays", "Split window (days)", "Invoices from one vendor this close together are tested as a split.", "", "1"],
  ["newVendorDays", "New-vendor window (days)", "First payment sooner than this after the vendor was created.", "", "1"],
  ["spikeZ", "Spend spike z-score", "Robust z (median / MAD) of a vendor's monthly spend.", "", "0.5"],
  ["minVendorInvoices", "Minimum invoices per vendor", "For the round-amount and sequential-invoice tests.", "", "1"],
  ["benfordMin", "Benford minimum (first digit)", "Fewer amounts than this and the test is refused.", "", "50"],
  ["benfordMinFT", "Benford minimum (first two digits)", "The first-two-digit test needs a larger sample.", "", "100"],
];

/** Mount the tool into main. */
export function renderApForensics(main) {
  if (!document.getElementById(P + "-css")) { const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st); }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>AP Forensics</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Forensic screens over your accounts payable ledger, vendor master and employee roster: duplicate payments, duplicate and shell-pattern vendors, vendor/employee matches, split invoices, Benford, segregation of duties and spend spikes. Results are patterns for an accountant or internal auditor to review, not conclusions. Runs entirely in your browser. Nothing is uploaded. The only request is the US federal holiday reference on this site (<span id="', P, '-holhdr">loading</span>); nothing is fetched live.</p>',
    '<div class="', P, '-card"><h2>1. Exports</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-note">Ledger: QuickBooks Online Transaction List by Vendor or Bill Payment List, Xero bills or Payable Invoice Detail, NetSuite vendor payments, SAP FBL1N, Sage Intacct AP payments or any CSV you map. Vendor master: QuickBooks Vendor Contact List, SAP vendor master or mapped. Employees: Workday, BambooHR or any roster you map. Bank account numbers and tax ids are hashed in memory and shown as the last four characters only.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div><div id="', P, '-map"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Run screens</button><button class="', P, '-btn" id="', P, '-clear" disabled>Clear files</button><span class="', P, '-note" id="', P, '-count"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-plabel" id="', P, '-plabel"></div></div>',
    '<div class="', P, '-card"><h2>2. Thresholds</h2><div class="', P, '-ctl" id="', P, '-thr"></div></div>',
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card" id="', P, '-results" style="display:none"><div class="', P, '-tabs" id="', P, '-tabs"></div><div id="', P, '-pane"></div><div class="', P, '-drawer" id="', P, '-drawer"></div><ul class="', P, '-skip" id="', P, '-skipped"></ul></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, running = false, holidays = null;
  let tab = "findings", sel = null;
  const sorts = { findings: { key: "severity", dir: "desc" }, duplicates: { key: "atRiskCents", dir: "desc" }, vendors: { key: "risk", dir: "desc" } };
  const filters = { vq: "", flag: "", mq: "", bv: "" };
  const columnMap = {};

  $("thr").innerHTML = THRESHOLDS.map(([k, label, help, ph, step]) => '<div class="' + P + '-field"><label for="' + P + "-o-" + k + '">' + esc(label) + '</label><input id="' + P + "-o-" + k + '" data-opt="' + k + '" type="number" min="0" step="' + step + '"' +
    (DEFAULTS[k] == null ? ' placeholder="' + esc(ph) + '"' : ' value="' + DEFAULTS[k] + '"') + "><small>" + esc(help) + (DEFAULTS[k] == null ? " Default blank." : " Default " + DEFAULTS[k] + ".") + "</small></div>").join("") +
    '<div class="' + P + '-field"><label for="' + P + '-o-dateOrder">Slash dates</label><select id="' + P + '-o-dateOrder"><option value="auto">Auto (month first unless the first part is over 12)</option><option value="mdy">Month / day / year</option><option value="dmy">Day / month / year</option></select><small>How 03/04/2026 is read. ISO and dotted SAP dates are unambiguous.</small></div>';

  fetch("/data/ref/us-holidays.json").then((r) => (r.ok ? r.json() : null)).then((j) => {
    if (!j || !Array.isArray(j.data)) throw new Error("bad file");
    holidays = j;
    $("holhdr").textContent = "reference data " + (j.version || j.updated || "") + ", verify with counsel";
  }).catch(() => { $("holhdr").textContent = "holiday reference unavailable: the holiday check will be skipped"; });

  const datasetName = () => (isExample ? "synthetic example" : files.map((f) => f.name).join(", "));
  const fmtOptions = Object.entries(FORMATS).map(([k, f]) => [k, f.label, f.role]);
  const effFormat = (f) => {
    const fmt = f.treatAs || f.det.format;
    return FORMATS[fmt] && FORMATS[fmt].role === f.role ? fmt : "generic-" + f.role;
  };

  function renderFiles() {
    const box = $("files");
    box.innerHTML = files.map((f, i) => {
      const ef = effFormat(f);
      return '<div class="' + P + '-file"><b>' + esc(f.name) + '</b><span class="' + P + '-muted">' + esc(fmtSize(f.size)) + "</span>" +
        '<span class="' + P + "-conf " + esc(f.treatAs ? "high" : f.det.confidence) + '">' + esc(f.treatAs ? "confirmed" : f.det.confidence + " confidence") + "</span>" +
        '<span class="' + P + '-muted">' + esc((FORMATS[ef] || {}).label || ef) + "</span>" +
        '<label class="' + P + '-muted">role <select data-role="' + i + '">' + Object.entries(ROLE_LABEL).map(([k, l]) => '<option value="' + k + '"' + (f.role === k ? " selected" : "") + ">" + esc(l) + "</option>").join("") + "</select></label>" +
        '<label class="' + P + '-muted">format <select data-as="' + i + '"><option value="">' + esc("detected") + "</option>" +
        fmtOptions.filter((o) => o[2] === f.role).map(([k, l]) => '<option value="' + esc(k) + '"' + (f.treatAs === k ? " selected" : "") + ">" + esc(l) + "</option>").join("") + "</select></label>" +
        '<button class="' + P + '-btn sm" data-rm="' + i + '" type="button">Remove</button></div>';
    }).join("");
    box.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { files.splice(Number(b.dataset.rm), 1); isExample = false; renderFiles(); }));
    box.querySelectorAll("[data-as]").forEach((s) => s.addEventListener("change", () => { files[Number(s.dataset.as)].treatAs = s.value; renderFiles(); }));
    box.querySelectorAll("[data-role]").forEach((s) => s.addEventListener("change", () => { const f = files[Number(s.dataset.role)]; f.role = s.value; if (f.treatAs && FORMATS[f.treatAs].role !== f.role) f.treatAs = ""; renderFiles(); }));
    const roles = files.map((f) => f.role);
    $("count").textContent = files.length ? files.length + " file" + (files.length === 1 ? "" : "s") + (isExample ? " (synthetic example)" : "") + (roles.includes("ledger") ? "" : " - add an AP ledger export") : "";
    $("run").disabled = !files.length || running;
    $("clear").disabled = !files.length;
    renderMapping();
  }

  function renderMapping() {
    const need = files.filter((f) => !f.treatAs && (f.det.confidence !== "high" || effFormat(f).startsWith("generic-") || f.role !== f.det.role));
    const box = $("map");
    if (!need.length) { box.innerHTML = ""; return; }
    box.innerHTML = need.map((f) => {
      const ef = effFormat(f);
      const generic = ef.startsWith("generic-");
      const cm = columnMap[f.name] || (columnMap[f.name] = {});
      const spec = COLUMNS[f.role];
      const auto = resolveColumns(ef, f.role, f.det.headers, null);
      return '<div class="' + P + '-card" style="margin:12px 0 0"><h2>Column mapping: ' + esc(f.name) + '</h2><p class="' + P + '-note">' +
        (generic ? "This layout was not recognised as a " + esc(ROLE_LABEL[f.role].toLowerCase()) + " export. Map the columns to read; a check whose column is not mapped is skipped and listed, never guessed."
          : "Detected as " + esc(FORMATS[ef].label) + " with " + esc(f.det.confidence) + " confidence. Confirm it under format, or map the columns below.") + "</p>" +
        '<div class="' + P + '-ctl" style="margin-top:10px">' + Object.keys(spec).map((k) => '<div class="' + P + '-field"><label>' + esc(COLUMN_LABEL[k] || k) + '</label><select data-file="' + esc(f.name) + '" data-col="' + esc(k) + '"><option value="">(not present)</option>' +
          f.det.headers.filter((h) => h).map((h) => '<option value="' + esc(h) + '"' + (cm[k] === h || (cm[k] === undefined && auto[k] === h) ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>").join("") + "</div></div>";
    }).join("");
    box.querySelectorAll("[data-col]").forEach((s) => {
      const cm = columnMap[s.dataset.file];
      s.addEventListener("change", () => { cm[s.dataset.col] = s.value; });
    });
  }

  function addFile(name, text, size) {
    const det = detectFile({ name, text });
    if (det.format === "empty") { toast(name + " is empty", "warning"); return false; }
    if (det.format === "unsupported-json") { toast(name + ": export the report as CSV", "warning"); return false; }
    const entry = { name, text, size: size || text.length, det, role: det.role, treatAs: "" };
    const i = files.findIndex((x) => x.name === name);
    if (i >= 0) files[i] = entry; else files.push(entry);
    return true;
  }

  mountDropzone($("drop"), {
    maxBytes: 256 * 1024 * 1024, maxFiles: 50, unpack: true, multiple: true,
    label: "Drop ledger, vendor master and roster exports (CSV / zip), paste, or browse",
    onFiles: async (list) => {
      let added = 0;
      for (const f of list) if (addFile(f.name, await f.text(), f.size)) added++;
      if (added) { if (isExample) files = files.filter((f) => !/synthetic/.test(f.name)); isExample = false; toast("Loaded " + added + " file" + (added === 1 ? "" : "s"), "success"); }
      renderFiles();
    },
  });

  $("clear").addEventListener("click", () => { files = []; isExample = false; renderFiles(); });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    files = []; isExample = true;
    for (const f of ex.files) addFile(f.name, f.text);
    const thr = $("o-approvalThreshold");
    if (!thr.value) thr.value = ex.opts.approvalThreshold;
    renderFiles();
    toast("Synthetic example loaded (approval threshold set to " + ex.opts.approvalThreshold + "). Click Run screens.", "info");
  });

  const opts = () => {
    const o = { roles: {}, treatAs: {}, columns: {}, holidays, dateOrder: $("o-dateOrder").value };
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (el.value.trim() !== "" && Number.isFinite(n) && n >= 0) o[el.dataset.opt] = n; });
    if ($("o-approvalThreshold").value.trim() === "") o.approvalThreshold = null;
    for (const f of files) {
      o.roles[f.name] = f.role;
      if (f.treatAs) o.treatAs[f.name] = f.treatAs;
      const cm = columnMap[f.name];
      if (cm && Object.keys(cm).length && !f.treatAs) o.columns[f.name] = { ...cm };
    }
    return o;
  };

  $("run").addEventListener("click", async () => {
    if (!files.length || running) return;
    running = true;
    const prog = $("prog"), bar = prog.firstElementChild, pl = $("plabel");
    prog.style.display = "block"; pl.style.display = "block"; bar.style.width = "0%"; pl.textContent = "starting"; $("run").disabled = true;
    try {
      result = await runInWorker(ENGINE, "analyze", [files.map((f) => ({ name: f.name, text: f.text })), opts()], {
        timeoutMs: 600000,
        onProgress: (i, n, label) => { bar.style.width = (n ? Math.min(100, Math.round((i / n) * 100)) : 0) + "%"; if (label) pl.textContent = label; },
      });
      sel = null;
      render();
      toast(result.summary.rows + " ledger rows, " + result.findings.length + " finding" + (result.findings.length === 1 ? "" : "s"), "success");
    } catch (e) {
      toast("Analysis failed: " + ((e && e.message) || e), "error");
    } finally {
      running = false; prog.style.display = "none"; pl.style.display = "none"; $("run").disabled = !files.length;
    }
  });

  function render() {
    const s = result.summary;
    $("kpis").innerHTML = kpi(s.payments, "payments") + kpi(s.totalPaid, "total paid") + kpi(s.potentialDuplicate, "potential duplicates") +
      kpi(s.flaggedVendors + " / " + s.vendors, "flagged vendors") + kpi(s.vendorEmployeeMatches, "vendor-employee matches") + kpi(s.findings, "findings");
    $("results").style.display = "";
    $("skipped").innerHTML = (s.totalBasis.length ? "<li><b>Total paid basis:</b> " + esc(s.totalBasis.join("; ")) + "</li>" : "") +
      (result.skipped.length ? "<li><b>Skipped or limited checks</b></li>" + result.skipped.map((k) => "<li>" + esc(k.check) + ": " + esc(k.reason) + "</li>").join("") : "");
    renderTabs(); renderExports();
  }

  function renderTabs() {
    const t = result.tables;
    const tabs = [["findings", "Findings (" + result.findings.length + ")"], ["duplicates", "Duplicates (" + t.duplicates.length + ")"], ["vendors", "Vendors (" + t.vendors.length + ")"], ["benford", "Benford"], ["monthly", "Monthly"]];
    $("tabs").innerHTML = tabs.map(([k, l]) => '<button type="button" class="' + P + "-tab" + (tab === k ? " on" : "") + '" data-tab="' + k + '">' + esc(l) + "</button>").join("");
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; sel = null; $("drawer").style.display = "none"; renderTabs(); }));
    ({ findings: drawFindings, duplicates: drawDuplicates, vendors: drawVendors, benford: drawBenford, monthly: drawMonthly })[tab]();
  }

  function drawer(title, html) {
    const dr = $("drawer");
    dr.style.display = "block";
    dr.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + title + '</h3><button class="' + P + '-btn sm" data-close type="button">Close</button></div>' + html;
    dr.querySelector("[data-close]").addEventListener("click", () => { dr.style.display = "none"; sel = null; renderTabs(); });
    dr.scrollIntoView({ block: "nearest", behavior: "smooth" });
    return dr;
  }

  const FIND_COLS = [
    { key: "severity", label: "Severity", rank: SEV_RANK, render: (f) => pill(f.severity) },
    { key: "title", label: "Finding", render: (f) => "<b>" + esc(f.title) + "</b><div>" + esc(f.description) + "</div>" },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
    { key: "controls", label: "Controls", render: (f) => (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") },
    { key: "evidenceCount", label: "Evidence", cls: "num" },
  ];
  function drawFindings() {
    const box = $("pane"); box.innerHTML = "";
    if (!result.findings.length) { box.innerHTML = '<div class="' + P + '-empty">No findings for the current thresholds. See the skipped checks below for anything that could not run.</div>'; return; }
    const rows = result.findings.map((f, i) => ({ ...f, i }));
    const t = table(FIND_COLS, rows, sorts.findings, (s) => { sorts.findings = s; drawFindings(); }, (f) => f.i);
    t.querySelectorAll("tr[data-i]").forEach((tr) => { if (sel === "f" + tr.dataset.i) tr.classList.add("sel"); tr.addEventListener("click", () => { sel = "f" + tr.dataset.i; drawFindings(); showFinding(result.findings[Number(tr.dataset.i)]); }); });
    box.appendChild(t);
  }
  function showFinding(f) {
    const dr = drawer(pill(f.severity) + " " + esc(f.title),
      "<p>" + esc(f.description) + "</p><p><b>Recommendation:</b> " + esc(f.recommendation) + "</p><p><b>Confidence:</b> " + esc(f.confidence) + " | <b>Category:</b> " + esc(f.category) + "</p>" +
      "<p>" + (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</p>" +
      "<p><b>Evidence</b> (" + f.evidence.length + " of " + f.evidenceCount + (f.evidence.length < f.evidenceCount ? "; the first 50 are kept" : "") + ")</p>" + plainTable(f.evidence) +
      '<div class="' + P + '-row"><button class="' + P + '-btn sm" data-ev type="button">Export evidence CSV</button></div>');
    dr.querySelector("[data-ev]").addEventListener("click", () => {
      const keys = []; for (const r of f.evidence) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
      const q = (v) => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
      download(TOOL_ID + "-" + f.check + "-evidence-" + fileStamp() + ".csv", [keys.join(","), ...f.evidence.map((r) => keys.map((k) => q(r[k])).join(","))].join("\n") + "\n", "text/csv");
    });
  }

  const KIND_LABEL = { exact: "exact", transposed: "transposed digits", "one-edit": "one character apart", "cross-vendor": "two vendor records" };
  const DUP_COLS = [
    { key: "kind", label: "Match", render: (d) => esc(KIND_LABEL[d.kind] || d.kind) },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
    { key: "vendor", label: "Vendor", render: (d) => esc(d.vendor) + (d.vendorB ? '<div class="' + P + '-muted">and ' + esc(d.vendorB) + "</div>" : "") },
    { key: "invoice", label: "Invoices", render: (d) => esc(d.invoice) + " / " + esc(d.invoiceB) },
    { key: "paymentDateB", label: "Dates", render: (d) => '<span class="' + P + '-nw">' + esc(d.paymentDate) + "</span> / " + '<span class="' + P + '-nw">' + esc(d.paymentDateB) + "</span>" },
    { key: "amountCents", label: "Amount", cls: "num", render: (d) => esc(d.amount) },
    { key: "atRiskCents", label: "At risk", cls: "num", render: (d) => esc(d.atRiskCents ? fmtMoney(d.atRiskCents, d.currency) : "-") },
  ];
  function drawDuplicates() {
    const box = $("pane"); box.innerHTML = "";
    const t0 = result.tables.duplicates;
    if (!t0.length) { box.innerHTML = '<div class="' + P + '-empty">No duplicate or near-duplicate payments found.</div>'; return; }
    const rows = t0.map((d, i) => ({ ...d, i }));
    const t = table(DUP_COLS, rows, sorts.duplicates, (s) => { sorts.duplicates = s; drawDuplicates(); }, (d) => d.i);
    t.querySelectorAll("tr[data-i]").forEach((tr) => { if (sel === "d" + tr.dataset.i) tr.classList.add("sel"); tr.addEventListener("click", () => { sel = "d" + tr.dataset.i; drawDuplicates(); showDup(t0[Number(tr.dataset.i)]); }); });
    box.appendChild(t);
    const n = document.createElement("p"); n.className = P + "-note";
    n.textContent = "At risk counts the later payment of each exact or likely pair (" + result.summary.potentialDuplicate + " in total). One-character-apart pairs are listed for review but not counted.";
    box.appendChild(n);
  }
  function showDup(d) {
    const side = [["Vendor", d.vendor, d.vendorB || d.vendor], ["Invoice", d.invoice, d.invoiceB], ["Invoice date", d.invoiceDate, d.invoiceDateB], ["Payment date", d.paymentDate, d.paymentDateB],
      ["Amount", d.amount, d.amount], ["Payment / document ref", d.ref, d.refB], ["Source row", d.lineA, d.lineB]];
    drawer(esc(KIND_LABEL[d.kind] || d.kind) + " match", "<p>" + esc(d.reason) + "</p>" + '<div class="' + P + '-list"><table><thead><tr><th>Field</th><th>First</th><th>Second</th></tr></thead><tbody>' +
      side.map(([k, a, b]) => "<tr><td><b>" + esc(k) + "</b></td><td>" + esc(a) + "</td><td>" + esc(b) + "</td></tr>").join("") + "</tbody></table></div>");
  }

  const VEN_COLS = [
    { key: "vendor", label: "Vendor", render: (v) => "<b>" + esc(v.vendor) + "</b>" + (v.vendorId ? '<div class="' + P + '-muted">' + esc(v.vendorId) + "</div>" : "") + (v.inMaster ? "" : ' <span class="' + P + '-chip">not in master</span>') },
    { key: "invoices", label: "Invoices", cls: "num" },
    { key: "payments", label: "Payments", cls: "num" },
    { key: "totalCents", label: "Total paid", cls: "num", render: (v) => esc(v.total) },
    { key: "first", label: "First / last", render: (v) => '<span class="' + P + '-nw">' + esc(v.first || "-") + "</span> / " + '<span class="' + P + '-nw">' + esc(v.last || "-") + "</span>" },
    { key: "flagCount", label: "Flags", render: (v) => v.flags.map((f) => '<span class="' + P + '-chip">' + esc(f) + "</span>").join("") || "-" },
    { key: "risk", label: "Risk", cls: "num", render: (v) => '<span class="' + P + "-risk " + riskCls(v.risk) + '">' + v.risk + "</span>" },
  ];
  function drawVendors() {
    const t0 = result.tables.vendors;
    const flags = [...new Set(t0.flatMap((v) => v.flags))].sort();
    $("pane").innerHTML = '<div class="' + P + '-filters"><div class="' + P + '-field"><label for="' + P + '-f-vq">Search</label><input id="' + P + '-f-vq" type="search" placeholder="vendor or id" value="' + esc(filters.vq) + '"></div>' +
      '<div class="' + P + '-field"><label for="' + P + '-f-flag">Flag</label><select id="' + P + '-f-flag"><option value="">All vendors</option><option value="*"' + (filters.flag === "*" ? " selected" : "") + ">Any flag</option>" +
      flags.map((f) => '<option value="' + esc(f) + '"' + (filters.flag === f ? " selected" : "") + ">" + esc(f) + "</option>").join("") + '</select></div></div><div id="' + P + '-vlist"></div>';
    const draw = () => {
      const q = filters.vq.trim().toLowerCase();
      const rows = t0.map((v, i) => ({ ...v, i, flagCount: v.flags.length })).filter((v) => (!q || (v.vendor + " " + v.vendorId).toLowerCase().includes(q)) &&
        (!filters.flag || (filters.flag === "*" ? v.flags.length : v.flags.includes(filters.flag))));
      const box = $("vlist"); box.innerHTML = "";
      if (!rows.length) { box.innerHTML = '<div class="' + P + '-empty">No vendors match.</div>'; return; }
      const shown = rows.length > 2000 ? sortBy(rows, sorts.vendors.key, sorts.vendors.dir).slice(0, 2000) : rows;
      const t = table(VEN_COLS, shown, sorts.vendors, (s) => { sorts.vendors = s; draw(); }, (v) => v.i);
      t.querySelectorAll("tr[data-i]").forEach((tr) => { if (sel === "v" + tr.dataset.i) tr.classList.add("sel"); tr.addEventListener("click", () => { sel = "v" + tr.dataset.i; draw(); showVendor(t0[Number(tr.dataset.i)]); }); });
      box.appendChild(t);
      const n = document.createElement("p"); n.className = P + "-note";
      n.textContent = rows.length + " of " + t0.length + " vendors" + (shown.length < rows.length ? " (first 2000 shown; export the vendor risk CSV for all)" : "") + ". Risk is a weighted count of flags (0-100) for ordering review, not a probability.";
      box.appendChild(n);
    };
    $("f-vq").addEventListener("input", (e) => { filters.vq = e.target.value; draw(); });
    $("f-flag").addEventListener("change", (e) => { filters.flag = e.target.value; draw(); });
    draw();
  }
  function showVendor(v) {
    const related = result.findings.filter((f) => (f.assets || []).some((a) => a.type === "VENDOR" && a.name === v.vendor));
    const m = result.tables.monthly.rows.find((r) => r.key === v.key);
    const months = result.tables.monthly.months;
    const mrows = m ? months.map((mo, i) => ({ month: mo, amount: fmtMoney(m.totals[i], m.currency) })).filter((_, i) => m.totals[i]) : [];
    drawer(esc(v.vendor) + ' <span class="' + P + "-risk " + riskCls(v.risk) + '">risk ' + v.risk + "</span>",
      "<p>" + esc([v.vendorId && "id " + v.vendorId, v.taxIdLast4 && "tax id " + v.taxIdLast4, v.invoices + " invoices", v.payments + " payments", "total " + v.total].filter(Boolean).join(" | ")) + "</p>" +
      "<p><b>Findings</b></p>" + plainTable(related.map((f) => ({ severity: f.severity, finding: f.title, confidence: f.confidence }))) +
      "<p><b>Spend by invoice month</b></p>" + plainTable(mrows));
  }

  function drawBenford() {
    const b = result.tables.benford;
    const vend = result.tables.benfordVendors;
    const pane = $("pane");
    const opts2 = '<div class="' + P + '-filters"><div class="' + P + '-field"><label for="' + P + '-f-bv">Population</label><select id="' + P + '-f-bv"><option value="">Whole ledger</option>' +
      vend.map((v, i) => '<option value="' + i + '"' + (filters.bv === String(i) ? " selected" : "") + ">" + esc(v.vendor + " (" + v.n + ")") + "</option>").join("") + "</select><small>Vendors appear here once they reach the first-digit minimum.</small></div></div>";
    const t = filters.bv !== "" && vend[Number(filters.bv)] ? vend[Number(filters.bv)] : b;
    if (!t) { pane.innerHTML = opts2 + '<div class="' + P + '-empty">Benford test refused: too few amounts for a meaningful test (see skipped checks).</div>'; bindBv(); return; }
    const rows = t.rows, W = 760, H = 220, padL = 34, padB = 26, top = 10;
    const max = Math.max(...rows.map((r) => Math.max(r.observed, r.expected))) || 1;
    const bw = (W - padL - 8) / rows.length;
    const y = (v) => top + (H - top - padB) * (1 - v / max);
    const bars = rows.map((r, i) => {
      const x = padL + i * bw;
      const showLabel = rows.length <= 9 || Number(r.digits) % 10 === 0;
      return '<rect x="' + (x + bw * 0.12).toFixed(1) + '" y="' + y(r.observed).toFixed(1) + '" width="' + (bw * 0.76).toFixed(1) + '" height="' + (H - padB - y(r.observed)).toFixed(1) + '" fill="#2552c6"><title>' + esc(r.digits + ": observed " + r.observed + "% (" + r.count + "), expected " + r.expected + "%") + "</title></rect>" +
        (showLabel ? '<text class="m" x="' + (x + bw / 2).toFixed(1) + '" y="' + (H - 8) + '" text-anchor="middle">' + esc(r.digits) + "</text>" : "");
    }).join("");
    const line = rows.map((r, i) => (i ? "L" : "M") + (padL + i * bw + bw / 2).toFixed(1) + " " + y(r.expected).toFixed(1)).join(" ");
    const ticks = [0, max / 2, max].map((v) => '<text class="m" x="' + (padL - 4) + '" y="' + (y(v) + 4).toFixed(1) + '" text-anchor="end">' + v.toFixed(1) + "</text>").join("");
    pane.innerHTML = opts2 + '<svg class="' + P + '-svg" viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Benford observed versus expected">' + ticks + bars + '<path d="' + line + '" fill="none" stroke="#b58100" stroke-width="2"/></svg>' +
      '<div class="' + P + '-legend"><span><i style="background:#2552c6"></i>observed %</span><span><i style="background:#b58100"></i>expected % (Benford)</span></div>' +
      '<p class="' + P + '-note">' + esc((t.test === "firstTwo" ? "First-two-digit" : "First-digit") + " test over " + t.n + " amounts. MAD " + t.mad + " (" + t.conformity + ", Nigrini ranges); chi-square " + t.chi2 + " vs " + t.critical + " critical at 0.05 (df " + t.df + "). " +
        (t.nonconforming ? "Flagged: both tests reject conformity." : "Not flagged: a finding needs both the chi-square test and MAD to reject conformity.") + " A screen, not evidence.") + "</p>";
    bindBv();
  }
  function bindBv() { const s = $("f-bv"); if (s) s.addEventListener("change", () => { filters.bv = s.value; drawBenford(); }); }

  function drawMonthly() {
    const mt = result.tables.monthly;
    const pane = $("pane");
    if (!mt.rows.length) { pane.innerHTML = '<div class="' + P + '-empty">No dated invoices to chart.</div>'; return; }
    pane.innerHTML = '<div class="' + P + '-filters"><div class="' + P + '-field"><label for="' + P + '-f-mq">Search</label><input id="' + P + '-f-mq" type="search" placeholder="vendor" value="' + esc(filters.mq) + '"></div></div><div id="' + P + '-mlist"></div>';
    const draw = () => {
      const q = filters.mq.trim().toLowerCase();
      const rows = mt.rows.filter((r) => !q || r.vendor.toLowerCase().includes(q)).slice(0, 60);
      const box = $("mlist");
      if (!rows.length) { box.innerHTML = '<div class="' + P + '-empty">No vendors match.</div>'; return; }
      const cell = (c, max) => { const a = max ? Math.min(0.85, c / max) : 0; return '<td class="h" style="background:rgba(37,82,198,' + a.toFixed(2) + ");color:" + (a > 0.5 ? "#fff" : "inherit") + '">' + (c ? esc(fmtMoney(c).replace(/\.\d\d$/, "")) : "") + "</td>"; };
      box.innerHTML = '<div class="' + P + "-list " + P + '-heat"><table style="min-width:' + (220 + mt.months.length * 74) + 'px"><thead><tr><th>Vendor</th>' + mt.months.map((m) => "<th>" + esc(m) + "</th>").join("") + "<th>Total</th></tr></thead><tbody>" +
        rows.map((r) => { const max = Math.max(...r.totals); return "<tr><td><b>" + esc(r.vendor) + "</b>" + (r.flagged ? ' <span class="' + P + '-chip">flagged</span>' : "") + (r.currency ? ' <span class="' + P + '-muted">' + esc(r.currency) + "</span>" : "") + "</td>" + r.totals.map((c) => cell(c, max)).join("") + '<td class="h"><b>' + esc(fmtMoney(r.totalCents)) + "</b></td></tr>"; }).join("") +
        "</tbody></table></div>" + '<p class="' + P + '-note">Spend by invoice month, shaded per vendor row. Flagged vendors first, then by total; up to 60 rows shown (' + mt.rows.length + " vendors). Scroll the table sideways for older months.</p>";
    };
    $("f-mq").addEventListener("input", (e) => { filters.mq = e.target.value; draw(); });
    draw();
  }

  function renderExports() {
    const ex = $("exports"), r = result, stamp = fileStamp();
    ex.innerHTML = ["csv:Findings CSV", "json:JSON", "txt:Summary TXT", "rec:Duplicate recovery worksheet CSV", "ven:Vendor risk CSV"]
      .map((x) => { const [k, l] = x.split(":"); return '<button class="' + P + '-btn" data-x="' + k + '">' + esc(l) + "</button>"; }).join("");
    const on = (k, fn) => ex.querySelector('[data-x="' + k + '"]').addEventListener("click", fn);
    on("csv", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    on("json", () => download(TOOL_ID + "-" + stamp + ".json", toJson({ ...r, summaryStats: summarize(r.findings) }), "application/json"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r), "text/plain"));
    on("rec", () => { if (!r.tables.duplicates.length) { toast("No duplicate pairs to recover", "info"); return; } download(TOOL_ID + "-recovery-" + stamp + ".csv", recoveryToCsv(r.tables.duplicates), "text/csv"); });
    on("ven", () => download(TOOL_ID + "-vendors-" + stamp + ".csv", vendorsToCsv(r.tables.vendors), "text/csv"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: datasetName() });
  }

  renderFiles();
}
