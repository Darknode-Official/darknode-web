// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Cloud Spend Anomaly (cloudspend): Deck tool UI. Load AWS CUR / CUR 2.0 / Cost Explorer,
// Azure cost details and GCP billing exports, optionally a Cloud Audit Log Hunter JSON
// export for correlation, and find spend anomalies that signal abuse or runaway cost.
// Runs entirely in the browser; the engine executes in a Worker via ../ingest/worker.js.
// No native dialogs; toasts only.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, MAP_KEYS, MAP_LABEL, SEV_RANK, CONF_RANK, PROVIDER_LABEL,
  detectFile, findingsToCsv, timelineToCsv, resourcesToCsv, accountsToCsv, summaryText, exampleDataset,
} from "./cloudspend-engine.js?v=20261016o";

const ENGINE = engineUrl("./cloudspend-engine.js?v=20261016o", import.meta);
const P = "csa";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const fmtBytes = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? Math.round(n / 1024) + " KB" : n + " B");
const fmtNum = (n) => Number(n || 0).toLocaleString("en-US");
/** Integer cents -> "12,345.67 USD"; never converts currencies. */
const money = (c, cur) => {
  if (c == null) return "";
  const v = Math.round(Number(c) || 0), a = Math.abs(v);
  return (v < 0 ? "-" : "") + String(Math.floor(a / 100)).replace(/\B(?=(\d{3})+(?!\d))/g, ",") + "." + String(a % 100).padStart(2, "0") + (cur ? " " + cur : "");
};
const confClass = (c) => (c >= 0.8 ? "high" : c >= 0.5 ? "medium" : "low");

const CSS = `
  .csa-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .csa-root *{box-sizing:border-box}
  .csa-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .csa-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .csa-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .csa-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:95ch}
  .csa-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .csa-card h2{font-size:.95rem;margin:0 0 10px}
  .csa-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .csa-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .csa-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .csa-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .csa-btn.sm{padding:4px 9px;font-size:.76rem}
  .csa-btn:disabled{opacity:.5;cursor:default}
  .csa-two{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:14px}
  @media (max-width:900px){.csa-two{grid-template-columns:minmax(0,1fr)}}
  .csa-files{display:flex;flex-direction:column;gap:6px;margin-top:12px}
  .csa-file{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;font-size:.82rem;min-width:0}
  .csa-file b{overflow-wrap:anywhere;min-width:0}
  .csa-mut{color:var(--mut,#667085)}
  .csa-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085);white-space:nowrap}
  .csa-conf.high{color:#1b7f4d;border-color:#1b7f4d}.csa-conf.medium{color:#8a6d00;border-color:#8a6d00}.csa-conf.low{color:#b00020;border-color:#b00020}
  .csa-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
  .csa-grp{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 12px;min-width:0}
  .csa-grp h4{margin:0 0 8px;font-size:.76rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut,#667085)}
  .csa-fields{display:flex;flex-wrap:wrap;gap:10px 14px}
  .csa-field{display:flex;flex-direction:column;gap:3px;min-width:0;flex:1 1 150px}
  .csa-field label{font-size:.76rem;font-weight:600;color:var(--tx,#1a2230)}
  .csa-field input,.csa-field select{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:6px 9px;width:100%;max-width:100%}
  .csa-field small{font-size:.72rem;color:var(--mut,#667085);line-height:1.35}
  .csa-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .csa-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:120px;flex:1 1 130px}
  .csa-kpi b{display:block;font-size:1.25rem;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}
  .csa-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .csa-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .csa-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .csa-plabel{font-size:.74rem;color:var(--mut,#667085);margin-top:4px;display:none;overflow-wrap:anywhere}
  .csa-tabs{display:flex;flex-wrap:wrap;gap:6px;border-bottom:1px solid var(--line,#e6e8ee);margin-bottom:12px}
  .csa-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid transparent;border-bottom:none;background:none;color:var(--mut,#667085);padding:7px 12px;border-radius:8px 8px 0 0;cursor:pointer;margin-bottom:-1px}
  .csa-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#e6e8ee);background:var(--card,#fff)}
  .csa-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .csa-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:640px}
  .csa-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .csa-list th.on{color:var(--tx,#1a2230)}
  .csa-list th.on::after{content:" \\2193";font-size:.7rem}
  .csa-list th.on.asc::after{content:" \\2191"}
  .csa-list td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word}
  .csa-list tr[data-i]{cursor:pointer}
  .csa-list tr[data-i]:hover,.csa-list tr.sel{background:var(--bg,#f7f8fb)}
  .csa-nw{white-space:nowrap;font-variant-numeric:tabular-nums}
  .csa-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .csa-pill.critical{background:#7a0012}.csa-pill.high{background:#b00020}.csa-pill.medium{background:#b58100}.csa-pill.low{background:#2552c6}.csa-pill.info{background:#667085}
  .csa-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .csa-chip.hot{color:#b00020;border-color:#b00020}
  .csa-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .csa-drawer{margin-top:12px;display:none;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--bg,#f7f8fb);min-width:0}
  .csa-drawer h3{margin:0;font-size:1rem;overflow-wrap:anywhere}
  .csa-drawer p{margin:6px 0;overflow-wrap:anywhere}
  .csa-drawer .csa-list{background:var(--card,#fff);margin-top:8px}
  .csa-drawer .csa-list table{min-width:0}
  .csa-drawer .csa-list td,.csa-drawer .csa-list th{white-space:nowrap}
  .csa-skip{font-size:.78rem;color:var(--mut,#667085);margin:8px 0 0;padding-left:18px}
  .csa-skip li{margin:2px 0;overflow-wrap:anywhere}
  .csa-filters{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:flex-end;margin-bottom:10px}
  .csa-filters .csa-field{flex:0 1 200px}
  .csa-chart{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px;background:var(--card,#fff);color:var(--tx,#1a2230)}
  .csa-chart svg{display:block;width:100%;height:240px}
  .csa-axis{display:flex;justify-content:space-between;gap:8px;font-size:.72rem;color:var(--mut,#667085);margin-top:4px;flex-wrap:wrap}
  .csa-legend{display:flex;gap:14px;flex-wrap:wrap;font-size:.74rem;color:var(--mut,#667085);margin-top:6px}
  .csa-sw{display:inline-block;width:12px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
  @media (max-width:560px){.csa-field,.csa-filters .csa-field{flex:1 1 100%}.csa-card{padding:14px}.csa-grid{grid-template-columns:1fr}}
`;

const kpi = (v, l) => '<div class="' + P + '-kpi"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const pill = (s) => (s ? '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>" : "");
const sortBy = (rows, key, dir, rank) => rows.slice().sort((a, b) => {
  const x = rank ? (rank[a[key]] ?? -1) : a[key], y = rank ? (rank[b[key]] ?? -1) : b[key];
  const r = typeof x === "number" && typeof y === "number" ? x - y : cmp(String(x == null ? "" : x).toLowerCase(), String(y == null ? "" : y).toLowerCase());
  return dir === "asc" ? r : -r;
});

/** Sortable table: cols = [{key, label, render?, rank?}]. */
function table(cols, rows, sort, onSort, rowKey) {
  const head = cols.map((c) => '<th data-k="' + esc(c.key) + '" class="' + (sort.key === c.key ? "on " + sort.dir : "") + '">' + esc(c.label) + "</th>").join("");
  const sorted = sortBy(rows, sort.key, sort.dir, (cols.find((c) => c.key === sort.key) || {}).rank);
  const body = sorted.map((r) => "<tr" + (rowKey ? ' data-i="' + esc(rowKey(r)) + '"' : "") + ">" + cols.map((c) => "<td>" + (c.render ? c.render(r) : esc(r[c.key] == null ? "" : Array.isArray(r[c.key]) ? r[c.key].join(", ") : r[c.key])) + "</td>").join("") + "</tr>").join("");
  const el = document.createElement("div");
  el.className = P + "-list";
  el.innerHTML = "<table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table>";
  el.querySelectorAll("th").forEach((th) => th.addEventListener("click", () => {
    const k = th.dataset.k;
    onSort({ key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" });
  }));
  return el;
}

/** Plain table of evidence rows (union of keys, money columns formatted). */
function rowsTable(rows, cur) {
  if (!rows || !rows.length) return '<p class="' + P + '-note">No rows.</p>';
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k) && r[k] !== "" && r[k] != null) keys.push(k);
  const show = (k, v) => (/Cents$/.test(k) && typeof v === "number" ? money(v, cur) : Array.isArray(v) ? v.join(", ") : v);
  const lab = (k) => k.replace(/Cents$/, "").replace(/([A-Z])/g, " $1").toLowerCase();
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(lab(k)) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => "<td>" + esc(show(k, r[k]) == null ? "" : show(k, r[k])) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

/** Daily spend line with a baseline band (median to median + z * spread). No library. */
function chartSvg(points, marks) {
  const n = points.length, W = 1000, H = 240, pad = 6;
  let max = 1;
  for (const p of points) { max = Math.max(max, p[1] || 0, p[3] || 0); }
  const x = (i) => (n <= 1 ? W / 2 : (i / (n - 1)) * W).toFixed(1);
  const y = (v) => (H - pad - ((v || 0) / max) * (H - 2 * pad)).toFixed(1);
  let band = "", segs = [], cur = [];
  for (let i = 0; i < n; i++) { if (points[i][2] != null) cur.push(i); else if (cur.length) { segs.push(cur); cur = []; } }
  if (cur.length) segs.push(cur);
  for (const s of segs) {
    const up = s.map((i) => x(i) + "," + y(points[i][3])).join(" ");
    const dn = s.slice().reverse().map((i) => x(i) + "," + y(points[i][2])).join(" ");
    band += '<polygon points="' + up + " " + dn + '" fill="#2552c6" fill-opacity=".14" stroke="none"></polygon>';
    band += '<polyline points="' + s.map((i) => x(i) + "," + y(points[i][2])).join(" ") + '" fill="none" stroke="#2552c6" stroke-dasharray="6 4" stroke-width="1.2" vector-effect="non-scaling-stroke"></polyline>';
  }
  const line = '<polyline points="' + points.map((p, i) => x(i) + "," + y(p[1])).join(" ") + '" fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke"></polyline>';
  const mk = points.map((p, i) => (marks.has(p[0]) ? '<line x1="' + x(i) + '" x2="' + x(i) + '" y1="0" y2="' + H + '" stroke="#b00020" stroke-width="2" stroke-opacity=".55" vector-effect="non-scaling-stroke"><title>' + esc(p[0]) + "</title></line>" : "")).join("");
  const tips = points.map((p, i) => '<rect x="' + (Number(x(i)) - W / Math.max(n, 1) / 2).toFixed(1) + '" y="0" width="' + (W / Math.max(n, 1)).toFixed(1) + '" height="' + H + '" fill="transparent"><title>' + esc(p[0] + ": " + money(p[1]) + (p[2] != null ? " (baseline median " + money(p[2]) + ", band top " + money(p[3]) + ")" : " (no baseline yet)")) + "</title></rect>").join("");
  return '<svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" role="img" aria-label="Daily spend with baseline band">' +
    '<line x1="0" y1="' + (H - pad) + '" x2="' + W + '" y2="' + (H - pad) + '" stroke="#d7dbe3" stroke-width="1" vector-effect="non-scaling-stroke"></line>' + band + mk + line + tips + "</svg>";
}

const GROUPS = [
  { title: "Baseline", fields: [
    ["baselineDays", "Baseline window (days)", "Trailing days used for the median and spread.", 1],
    ["minHistoryDays", "Minimum history (days)", "Days needed before a day is tested; shorter series are skipped with a reason.", 1],
    ["spikeZ", "Spike threshold (robust z)", "Median / MAD z-score a day must exceed.", 1],
  ] },
  { title: "Amounts (in the file's currency)", fields: [
    ["minIncrease", "Minimum increase", "A spike must add at least this over the baseline median. Blank = 0.", 100],
    ["minSpreadCents", "Minimum spread", "Floor for the robust spread so flat or zero baselines do not turn cents into alerts.", 100],
    ["dormantDailyCents", "Dormant: baseline average per day at most", "", 100],
    ["dormantWakeCents", "Dormant: wake-up day at least", "", 100],
  ] },
  { title: "Other checks", fields: [
    ["newFamilyShare", "New compute family: share of baseline day (%)", "Peak day of a new non-GPU family vs the account's median day.", 0.01],
    ["minNewResources", "New resource ids per day at least", "Resource churn check.", 1],
    ["correlationHours", "Correlation window (+/- hours)", "Join to Cloud Audit Log Hunter findings.", 1],
  ] },
];

function thresholdsHtml() {
  const f = ([k, label, help, scale]) => {
    const d = DEFAULTS[k];
    const shown = d == null ? "" : scale === 100 ? (d / 100).toFixed(2) : scale === 0.01 ? Math.round(d * 100) : d;
    return '<div class="' + P + '-field"><label for="' + P + "-o-" + k + '">' + esc(label) + '</label><input id="' + P + "-o-" + k + '" data-opt="' + k + '" data-scale="' + scale + '" type="number" min="0" step="any" value="' + esc(shown) + '"' + (d == null ? ' placeholder="blank = 0"' : "") + "><small>Default " + esc(shown === "" ? "blank" : shown) + (help ? ". " + esc(help) : "") + "</small></div>";
  };
  return '<div class="' + P + '-grid">' + GROUPS.map((g) => '<div class="' + P + '-grp"><h4>' + esc(g.title) + '</h4><div class="' + P + '-fields">' + g.fields.map(f).join("") + "</div></div>").join("") + "</div>";
}

/** Mount the tool into main. */
export function renderCloudSpend(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Cloud Spend Anomaly</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Find cost anomalies in cloud billing data that point to abuse (crypto-mining on new GPU capacity, stolen credentials spinning up resources in unwatched regions or dormant accounts, data leaving through egress) or runaway spend, and join them to cloud audit findings. Robust median / MAD statistics, mapped to MITRE ATT&amp;CK T1496, T1578.002, T1535, T1537 and T1530. Runs entirely in your browser. Nothing is uploaded and nothing is fetched.</p>',
    '<div class="', P, '-two">',
    '<div class="', P, '-card"><h2>1. Billing exports</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-note">Accepted: AWS Cost and Usage Report (legacy lineItem/ columns and CUR 2.0 line_item_ columns, .csv or .csv.gz), AWS Cost Explorer CSV downloads (either layout), Azure Cost Management cost details CSV, GCP billing export to BigQuery as CSV or JSON, GCP console cost table CSV. Drop many files or a zip at once. Currencies are kept apart, never converted.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div><div id="', P, '-map"></div></div>',
    '<div class="', P, '-card"><h2>2. Correlate (optional)</h2><div id="', P, '-ctdrop"></div>',
    '<p class="', P, '-note">The JSON export of this site\'s Cloud Audit Log Hunter. Anomalies are joined to its findings by account / subscription / project, region (where both state one) and time window; both sides get their severity raised with a "correlated with" evidence row.</p>',
    '<div class="', P, '-files" id="', P, '-ctfiles"></div></div>',
    "</div>",
    '<div class="', P, '-card"><h2>3. Thresholds</h2>', thresholdsHtml(),
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" type="button" disabled>Analyze</button><button class="', P, '-btn" id="', P, '-clear" type="button" disabled>Clear files</button><span class="', P, '-note" id="', P, '-count"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-plabel" id="', P, '-plabel"></div></div>',
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card" id="', P, '-results" style="display:none"><div class="', P, '-tabs" id="', P, '-tabs"></div><div id="', P, '-pane"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div><ul class="', P, '-skip" id="', P, '-skipped"></ul></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example" type="button">Load example (synthetic)</button><span class="', P, '-note">60 days of a fictional 3-account CUR plus a small audit-log export.</span></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], ctFiles = [], result = null, isExample = false, running = false;
  let tab = "findings", selFinding = -1, chartKey = "";
  const sorts = { findings: { key: "severity", dir: "desc" }, accounts: { key: "findings", dir: "desc" }, regions: { key: "isNew", dir: "desc" }, families: { key: "gpu", dir: "desc" }, services: { key: "totalCents", dir: "desc" } };
  let ffilter = { sev: "", cat: "", q: "" };
  const mappings = {}, providers = {};
  const datasetName = () => (isExample ? "synthetic example" : files.map((f) => f.name).join(", ").slice(0, 200));

  function renderFiles() {
    const parsedOf = (f) => (result ? (result.meta.files || []).find((x) => x.name === f.name) : null);
    const row = (f, i, kind) => {
      const d = f.det, ps = parsedOf(f);
      return '<div class="' + P + '-file"><b>' + esc(f.name) + '</b><span class="' + P + '-mut">' + esc(fmtBytes(d.bytes)) + (f.fromArchive ? ", from archive" : "") + "</span>" +
        "<span>" + esc((PROVIDER_LABEL[d.provider] ? PROVIDER_LABEL[d.provider] + " - " : "") + d.label) + "</span>" +
        '<span class="' + P + "-conf " + confClass(d.confidence) + '">' + confClass(d.confidence) + " confidence</span>" +
        (ps && ps.kind === "billing" ? '<span class="' + P + '-mut">' + fmtNum(ps.used) + " of " + fmtNum(ps.rows) + " rows used" + (ps.excluded ? " (" + fmtNum(ps.excluded) + " excluded: " + esc(Object.keys(ps.excludedReasons).slice(0, 2).join("; ")) + ")" : "") + (ps.firstDate ? ", " + esc(ps.firstDate + " to " + ps.lastDate) : "") + (ps.currencies.length ? ", " + esc(ps.currencies.join(" / ")) : "") + "</span>" : "") +
        '<button class="' + P + '-btn sm" data-rm="' + kind + i + '" type="button">Remove</button></div>';
    };
    $("files").innerHTML = files.map((f, i) => row(f, i, "b")).join("");
    $("ctfiles").innerHTML = ctFiles.length ? ctFiles.map((f, i) => row(f, i, "c")).join("") : '<p class="' + P + '-note">No audit export loaded; correlation is off.</p>';
    main.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => {
      const k = b.dataset.rm, i = Number(k.slice(1));
      if (k[0] === "b") files.splice(i, 1); else ctFiles.splice(i, 1);
      isExample = false; renderFiles();
    }));
    const bytes = files.concat(ctFiles).reduce((n, f) => n + f.det.bytes, 0);
    $("count").textContent = files.length ? files.length + " billing file" + (files.length === 1 ? "" : "s") + (ctFiles.length ? " + " + ctFiles.length + " audit export" : "") + ", " + fmtBytes(bytes) + (isExample ? " (synthetic example)" : "") : "";
    $("run").disabled = !files.length || running;
    $("clear").disabled = !files.length && !ctFiles.length;
    renderMapping();
  }

  function renderMapping() {
    const lowc = files.filter((f) => f.det.confidence < 0.8 && !/^aws-ce/.test(f.det.format));
    const box = $("map");
    if (!lowc.length) { box.innerHTML = ""; return; }
    box.innerHTML = lowc.map((f, fi) => {
      const m = mappings[f.name] || (mappings[f.name] = {});
      const sel = (k) => {
        const cur = m[k] !== undefined ? m[k] : f.det.cols[k] || "";
        return '<div class="' + P + '-field"><label for="' + P + "-map-" + fi + "-" + k + '">' + esc(MAP_LABEL[k]) + '</label><select id="' + P + "-map-" + fi + "-" + k + '" data-f="' + esc(f.name) + '" data-col="' + k + '"><option value="">(not present)</option>' +
          f.det.headers.map((h) => '<option value="' + esc(h) + '"' + (cur === h ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>";
      };
      return '<div class="' + P + '-grp" style="margin-top:12px"><h4>Column mapping: ' + esc(f.name) + '</h4><p class="' + P + '-note">The layout was not recognised with high confidence. Usage date, account and cost are required; checks whose column is not mapped are skipped and listed, never guessed.</p>' +
        '<div class="' + P + '-fields" style="margin-top:8px">' +
        (f.det.provider === "other" ? '<div class="' + P + '-field"><label for="' + P + "-prov-" + fi + '">Provider</label><select id="' + P + "-prov-" + fi + '" data-prov="' + esc(f.name) + '">' + ["other", "aws", "azure", "gcp"].map((p) => '<option value="' + p + '"' + ((providers[f.name] || "other") === p ? " selected" : "") + ">" + esc(p === "other" ? "Not stated (match all patterns)" : PROVIDER_LABEL[p]) + "</option>").join("") + "</select><small>Decides which GPU / egress / serverless patterns apply.</small></div>" : "") +
        MAP_KEYS.map(sel).join("") + "</div></div>";
    }).join("");
    box.querySelectorAll("[data-col]").forEach((s) => s.addEventListener("change", () => { (mappings[s.dataset.f] = mappings[s.dataset.f] || {})[s.dataset.col] = s.value; }));
    box.querySelectorAll("[data-prov]").forEach((s) => s.addEventListener("change", () => { providers[s.dataset.prov] = s.value; }));
  }

  function addFile(name, text, fromArchive, target) {
    const det = detectFile(name, text);
    if (det.kind === "empty") { toast(name + " is empty", "warning"); return false; }
    if (det.kind === "unknown") { toast(name + " is not a recognised billing export or audit export", "warning"); return false; }
    const entry = { name, text, det, fromArchive: !!fromArchive };
    const list = det.kind === "cloudtrail" ? ctFiles : files;
    if (target === "ct" && det.kind !== "cloudtrail") { toast(name + " is not a Cloud Audit Log Hunter export (meta.tool \"cloudtrail\"); added as a billing file", "warning"); }
    const idx = list.findIndex((x) => x.name === name);
    if (idx >= 0) list[idx] = entry; else list.push(entry);
    return true;
  }
  const onFiles = (target) => async (list, info) => {
    let added = 0;
    if (isExample) { files = []; ctFiles = []; isExample = false; }
    for (const f of list) { try { if (addFile(f.name, await f.text(), f.fromArchive, target)) added++; } catch (e) { toast("Could not read " + f.name + ": " + ((e && e.message) || e), "error"); } }
    const sk = (info && info.skipped) || [];
    if (sk.length) toast(sk.length + " file" + (sk.length === 1 ? "" : "s") + " skipped: " + sk.slice(0, 3).map((s) => s.name + " (" + s.reason + ")").join("; "), "warning");
    if (added) toast("Loaded " + added + " file" + (added === 1 ? "" : "s"), "success");
    result = null; renderFiles();
  };
  mountDropzone($("drop"), { maxBytes: 256 * 1024 * 1024, maxFiles: 50, multiple: true, unpack: true, label: "Drop billing exports or a zip here, paste, or browse", onFiles: onFiles("billing") });
  mountDropzone($("ctdrop"), { maxBytes: 256 * 1024 * 1024, maxFiles: 10, multiple: true, unpack: true, label: "Drop a Cloud Audit Log Hunter JSON export", onFiles: onFiles("ct") });

  $("clear").addEventListener("click", () => { files = []; ctFiles = []; isExample = false; result = null; renderFiles(); });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    files = []; ctFiles = []; isExample = true; result = null;
    for (const f of ex.files) addFile(f.name, f.text, false);
    renderFiles();
    toast("Synthetic example loaded. Click Analyze.", "info");
  });

  const opts = () => {
    const o = { mappings: {}, providers: { ...providers } };
    for (const [n, m] of Object.entries(mappings)) { o.mappings[n] = {}; for (const [k, v] of Object.entries(m)) o.mappings[n][k] = v; }
    main.querySelectorAll("[data-opt]").forEach((el) => {
      if (el.value.trim() === "") return;
      const n = Number(el.value), sc = Number(el.dataset.scale);
      if (Number.isFinite(n) && n >= 0) o[el.dataset.opt] = sc === 100 ? Math.round(n * 100) : sc === 0.01 ? n / 100 : n;
    });
    return o;
  };

  $("run").addEventListener("click", async () => {
    if (!files.length || running) return;
    running = true;
    const prog = $("prog"), bar = prog.firstElementChild, pl = $("plabel");
    prog.style.display = "block"; pl.style.display = "block"; bar.style.width = "0%"; pl.textContent = "starting the worker"; $("run").disabled = true;
    const t0 = performance.now();
    try {
      result = await runInWorker(ENGINE, "analyze", [files.concat(ctFiles).map((f) => ({ name: f.name, text: f.text })), opts()], {
        timeoutMs: 15 * 60 * 1000,
        onProgress: (i, n, label) => { bar.style.width = (n ? Math.min(100, Math.round((i / n) * 100)) : 0) + "%"; pl.textContent = label || ""; },
      });
      selFinding = -1; ffilter = { sev: "", cat: "", q: "" }; chartKey = "";
      render(result);
      toast(result.findings.length + " finding" + (result.findings.length === 1 ? "" : "s") + " from " + fmtNum(result.summary.rows) + " billing rows (" + ((performance.now() - t0) / 1000).toFixed(1) + " s)", "success");
    } catch (e) {
      toast("Analysis failed: " + ((e && e.message) || e), "error");
    } finally {
      running = false;
      prog.style.display = "none"; pl.style.display = "none"; $("run").disabled = !files.length;
    }
  });

  function render(r) {
    const s = r.summary;
    $("kpis").innerHTML = kpi(fmtNum(s.accounts), "accounts") + kpi(s.days ? s.days + " days" : "-", "days covered") +
      kpi(s.totals.map((t) => money(t.cents, t.currency)).join(" / ") || "-", "total spend") + kpi(s.anomalies, "anomalies") +
      kpi(s.gpuAlerts + " / " + s.newRegionAlerts, "GPU / new-region alerts") + kpi(ctFiles.length ? s.correlated : "off", "correlated");
    $("skipped").innerHTML = r.skipped.length ? "<li><b>Skipped or limited checks</b></li>" + r.skipped.map((k) => "<li>" + esc(k.check) + ": " + esc(k.reason) + "</li>").join("") : "";
    $("results").style.display = "";
    $("drawer").style.display = "none";
    renderFiles();
    renderTabs(r);
    renderExports(r);
  }

  function renderTabs(r) {
    const t = r.tables;
    const tabs = [["findings", "Findings (" + r.findings.length + ")"], ["daily", "Daily"], ["accounts", "Accounts (" + t.accounts.length + ")"], ["services", "Services (" + t.services.length + ")"], ["regions", "Regions (" + t.regions.length + ")"], ["families", "Families (" + t.families.length + ")"]];
    $("tabs").innerHTML = tabs.map(([k, l]) => '<button type="button" class="' + P + "-tab" + (tab === k ? " on" : "") + '" data-tab="' + k + '">' + esc(l) + "</button>").join("");
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; $("drawer").style.display = "none"; selFinding = -1; renderTabs(r); }));
    const pane = $("pane");
    pane.innerHTML = "";
    const tbl = (name, cols, rows, empty) => pane.appendChild(rows.length ? table(cols, rows, sorts[name], (s) => { sorts[name] = s; renderTabs(r); }) : emptyEl(empty));
    if (tab === "findings") drawFindings(r);
    else if (tab === "daily") drawDaily(r);
    else if (tab === "accounts") tbl("accounts", ACCT_COLS, t.accounts, "No accounts.");
    else if (tab === "services") tbl("services", SVC_COLS, t.services, "No services.");
    else if (tab === "regions") tbl("regions", REG_COLS, t.regions, "No region column in the input; the new-region check was skipped.");
    else if (tab === "families") tbl("families", FAM_COLS, t.families, "No instance types, meters or machine-type SKUs in the input.");
  }
  const emptyEl = (t) => { const d = document.createElement("div"); d.className = P + "-empty"; d.textContent = t; return d; };
  const acctCell = (x) => "<b>" + esc(x.account) + "</b>" + (x.accountName ? '<div class="' + P + '-mut">' + esc(x.accountName) + "</div>" : "") + '<div class="' + P + '-mut">' + esc(PROVIDER_LABEL[x.provider] || x.provider) + "</div>";
  const m = (k) => (x) => '<span class="' + P + '-nw">' + esc(money(x[k], x.currency)) + "</span>";
  const yes = (k, l) => (x) => (x[k] ? '<span class="' + P + '-chip hot">' + esc(l) + "</span>" : "");

  const FIND_COLS = [
    { key: "severity", label: "Severity", rank: SEV_RANK, render: (f) => pill(f.severity) },
    { key: "title", label: "Finding", render: (f) => "<b>" + esc(f.title) + "</b>" + (f.correlated.length ? ' <span class="' + P + '-chip hot">correlated</span>' : "") },
    { key: "windowStart", label: "Window", render: (f) => '<span class="' + P + '-nw">' + esc(f.windowStart) + (f.windowEnd && f.windowEnd !== f.windowStart ? "<br>" + esc(f.windowEnd) : "") + "</span>" },
    { key: "increaseCents", label: "Increase", render: m("increaseCents") },
    { key: "z", label: "z", render: (f) => (f.z == null ? "-" : esc(f.z >= 999 ? ">999" : f.z)) },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
    { key: "controls", label: "Controls", render: (f) => f.controls.slice(0, 4).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + (f.controls.length > 4 ? '<span class="' + P + '-chip">+' + (f.controls.length - 4) + "</span>" : "") },
    { key: "evidenceCount", label: "Evidence" },
  ];
  const ACCT_COLS = [
    { key: "account", label: "Account", render: acctCell }, { key: "currency", label: "Currency" },
    { key: "baselinePerDayCents", label: "Baseline / day", render: m("baselinePerDayCents") }, { key: "last7Cents", label: "Last 7 days", render: m("last7Cents") },
    { key: "totalCents", label: "Total", render: m("totalCents") }, { key: "maxZ", label: "Max z" }, { key: "findings", label: "Findings" },
    { key: "flags", label: "Flags", render: (x) => x.flags.map((f) => '<span class="' + P + '-chip hot">' + esc(f) + "</span>").join("") },
    { key: "days", label: "Days" }, { key: "status", label: "Status" },
  ];
  const SVC_COLS = [
    { key: "service", label: "Service", render: (x) => "<b>" + esc(x.service) + "</b>" }, { key: "account", label: "Account" }, { key: "currency", label: "Currency" },
    { key: "baselinePerDayCents", label: "Baseline / day", render: m("baselinePerDayCents") }, { key: "last7Cents", label: "Last 7 days", render: m("last7Cents") },
    { key: "totalCents", label: "Total", render: m("totalCents") }, { key: "maxZ", label: "Max z" }, { key: "flags", label: "Flags" },
  ];
  const REG_COLS = [
    { key: "region", label: "Region", render: (x) => "<b>" + esc(x.region) + "</b>" }, { key: "isNew", label: "New", render: yes("isNew", "new") },
    { key: "account", label: "Account" }, { key: "currency", label: "Currency" }, { key: "totalCents", label: "Total", render: m("totalCents") },
    { key: "computeCents", label: "Compute", render: m("computeCents") }, { key: "firstSeen", label: "First" }, { key: "lastSeen", label: "Last" },
  ];
  const FAM_COLS = [
    { key: "family", label: "Family", render: (x) => "<b>" + esc(x.family) + "</b>" }, { key: "gpu", label: "GPU", render: yes("gpu", "GPU") }, { key: "isNew", label: "New", render: yes("isNew", "new") },
    { key: "account", label: "Account" }, { key: "currency", label: "Currency" }, { key: "totalCents", label: "Total", render: m("totalCents") },
    { key: "firstSeen", label: "First" }, { key: "lastSeen", label: "Last" },
  ];

  function drawFindings(r) {
    const pane = $("pane");
    if (!r.findings.length) { pane.appendChild(emptyEl("No anomalies for the current thresholds. Check the skipped list below for checks that could not run.")); return; }
    const cats = [...new Set(r.findings.map((f) => f.category))].sort();
    const fl = document.createElement("div");
    fl.className = P + "-filters";
    fl.innerHTML = '<div class="' + P + '-field"><label for="' + P + '-fs">Severity</label><select id="' + P + '-fs" data-ff="sev"><option value="">All</option>' + ["critical", "high", "medium", "low", "info"].map((s) => '<option value="' + s + '"' + (ffilter.sev === s ? " selected" : "") + ">" + s + "</option>").join("") + "</select></div>" +
      '<div class="' + P + '-field"><label for="' + P + '-fc">Check</label><select id="' + P + '-fc" data-ff="cat"><option value="">All</option>' + cats.map((c) => '<option value="' + esc(c) + '"' + (ffilter.cat === c ? " selected" : "") + ">" + esc(c) + "</option>").join("") + "</select></div>" +
      '<div class="' + P + '-field"><label for="' + P + '-fq">Search</label><input id="' + P + '-fq" data-ff="q" type="search" placeholder="account, region, service" value="' + esc(ffilter.q) + '"></div>';
    pane.appendChild(fl);
    const box = document.createElement("div");
    pane.appendChild(box);
    const draw = () => {
      const q = ffilter.q.trim().toLowerCase();
      const rows = r.findings.map((f, i) => ({ ...f, i })).filter((f) => (!ffilter.sev || f.severity === ffilter.sev) && (!ffilter.cat || f.category === ffilter.cat) &&
        (!q || [f.title, f.account, f.accountName, f.scope, f.regions.join(" ")].some((v) => String(v || "").toLowerCase().includes(q))));
      box.innerHTML = "";
      if (!rows.length) { box.appendChild(emptyEl("No findings match the filters.")); return; }
      const t = table(FIND_COLS, rows, sorts.findings, (s) => { sorts.findings = s; draw(); }, (f) => f.i);
      t.querySelectorAll("tr[data-i]").forEach((tr) => { if (Number(tr.dataset.i) === selFinding) tr.classList.add("sel"); tr.addEventListener("click", () => { selFinding = Number(tr.dataset.i); draw(); showFinding(r, r.findings[selFinding]); }); });
      box.appendChild(t);
    };
    fl.querySelectorAll("[data-ff]").forEach((el) => el.addEventListener("input", () => { ffilter[el.dataset.ff] = el.value; draw(); }));
    draw();
  }

  function showFinding(r, f) {
    const d = $("drawer");
    if (!f) { d.style.display = "none"; return; }
    d.style.display = "block";
    const seriesKey = f.provider + "|" + f.account + "|" + f.currency;
    d.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + pill(f.severity) + " " + esc(f.title) + '</h3><button class="' + P + '-btn sm" data-close type="button">Close</button></div>' +
      "<p>" + esc(f.description) + "</p><p><b>Recommendation:</b> " + esc(f.recommendation) + "</p>" +
      "<p><b>Confidence:</b> " + esc(f.confidence) + " &middot; <b>Account:</b> " + esc(f.account + (f.accountName ? " (" + f.accountName + ")" : "")) + " &middot; <b>Window:</b> " + esc(f.windowStart + (f.windowEnd !== f.windowStart ? " to " + f.windowEnd : "")) +
      " &middot; <b>Baseline/day:</b> " + esc(money(f.baselinePerDayCents, f.currency)) + " &middot; <b>Observed:</b> " + esc(money(f.observedCents, f.currency)) + " &middot; <b>Increase:</b> " + esc(money(f.increaseCents, f.currency)) + (f.z != null ? " &middot; <b>z:</b> " + esc(f.z) : "") + "</p>" +
      "<p>" + f.controls.map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</p>" +
      (f.correlated.length ? "<p><b>Correlated with:</b> " + f.correlated.map((c) => esc(c.title + " (" + c.severity + ")")).join("; ") + "</p>" : "") +
      (f.days && f.days.length ? "<p><b>Day by day</b></p>" + rowsTable(f.days, f.currency) : "") +
      "<p><b>Evidence</b> (" + f.evidence.length + " of " + f.evidenceCount + " rows" + (f.category === "correlated-audit" ? "" : "; top resources by cost") + ")</p>" + rowsTable(f.evidence, f.currency) +
      '<div class="' + P + '-row"><button class="' + P + '-btn sm" data-ev type="button">Export evidence CSV</button>' + (r.tables.series.some((s) => s.provider + "|" + s.account + "|" + s.currency === seriesKey) ? '<button class="' + P + '-btn sm" data-chart type="button">Show on daily chart</button>' : "") + "</div>";
    d.querySelector("[data-close]").addEventListener("click", () => { d.style.display = "none"; selFinding = -1; renderTabs(r); });
    d.querySelector("[data-ev]").addEventListener("click", () => {
      const keys = []; for (const e of f.evidence) for (const k of Object.keys(e)) if (!keys.includes(k)) keys.push(k);
      const q = (v) => { let s = v == null ? "" : String(v); if (/^[=+@\t\r]/.test(s) || /^-[^\d]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
      download(TOOL_ID + "-evidence-" + fileStamp() + ".csv", [keys.join(","), ...f.evidence.map((e) => keys.map((k) => q(e[k])).join(","))].join("\n") + "\n", "text/csv");
    });
    const ch = d.querySelector("[data-chart]");
    if (ch) ch.addEventListener("click", () => { chartKey = seriesKey; tab = "daily"; renderTabs(r); });
    d.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  function drawDaily(r) {
    const pane = $("pane");
    const series = r.tables.series;
    if (!series.length) { pane.appendChild(emptyEl("No daily data.")); return; }
    const keyOf = (s) => s.provider + "|" + s.account + "|" + s.currency;
    const flagged = new Set(r.findings.map((f) => f.provider + "|" + f.account + "|" + f.currency));
    const opts2 = series.slice().sort((a, b) => Number(flagged.has(keyOf(b))) - Number(flagged.has(keyOf(a))) || cmp(keyOf(a), keyOf(b)));
    if (!chartKey || !series.some((s) => keyOf(s) === chartKey)) chartKey = keyOf(opts2[0]);
    const s = series.find((x) => keyOf(x) === chartKey);
    const marks = new Set(r.tables.timeline.filter((t) => t.provider + "|" + t.account + "|" + t.currency === chartKey).map((t) => t.date));
    const max = s.points.reduce((mx, p) => Math.max(mx, p[1] || 0, p[3] || 0), 0);
    const el = document.createElement("div");
    el.innerHTML = '<div class="' + P + '-filters"><div class="' + P + '-field" style="flex:1 1 320px"><label for="' + P + '-acct">Account series</label><select id="' + P + '-acct">' +
      opts2.map((x) => '<option value="' + esc(keyOf(x)) + '"' + (keyOf(x) === chartKey ? " selected" : "") + ">" + esc((flagged.has(keyOf(x)) ? "[anomaly] " : "") + (PROVIDER_LABEL[x.provider] || x.provider) + " " + x.account + (x.accountName ? " (" + x.accountName + ")" : "") + " - " + x.currency) + "</option>").join("") + "</select></div></div>" +
      '<div class="' + P + '-chart">' + chartSvg(s.points, marks) + '<div class="' + P + '-axis"><span>' + esc(s.points[0][0]) + "</span><span>peak " + esc(money(max, s.currency)) + " per day</span><span>" + esc(s.points[s.points.length - 1][0]) + "</span></div>" +
      '<div class="' + P + '-legend"><span><i class="' + P + '-sw" style="background:currentColor"></i>daily spend</span><span><i class="' + P + '-sw" style="background:#2552c6;opacity:.35"></i>baseline band (median to median + ' + esc(r.meta.options.spikeZ) + " x robust spread)</span><span><i class=\"" + P + '-sw" style="background:#b00020"></i>anomaly days</span><span>UTC days; hover for values; no band before ' + esc(r.meta.options.minHistoryDays) + " days of history</span></div></div>";
    pane.appendChild(el);
    el.querySelector("#" + P + "-acct").addEventListener("change", (e) => { chartKey = e.target.value; renderTabs(r); });
    const daily = r.tables.daily;
    if (daily.length) {
      const h = document.createElement("p"); h.className = P + "-note"; h.innerHTML = "<b>All accounts per day</b> (one row per date and currency; currencies are never summed together)"; pane.appendChild(h);
      pane.appendChild(table([{ key: "date", label: "Date" }, { key: "currency", label: "Currency" }, { key: "totalCents", label: "Total", render: m("totalCents") }, { key: "awsCents", label: "AWS", render: m("awsCents") }, { key: "azureCents", label: "Azure", render: m("azureCents") }, { key: "gcpCents", label: "GCP", render: m("gcpCents") }, { key: "otherCents", label: "Other", render: m("otherCents") }],
        daily, { key: "date", dir: "desc" }, () => {}));
    }
  }

  function renderExports(r) {
    const ex = $("exports");
    ex.innerHTML = ["csv:Findings CSV", "json:JSON", "txt:Summary TXT", "tl:Anomaly timeline CSV", "res:Top resources CSV", "acct:Accounts CSV"].map((x) => { const [k, l] = x.split(":"); return '<button class="' + P + '-btn" type="button" data-x="' + k + '">' + l + "</button>"; }).join("");
    const stamp = fileStamp();
    const on = (k, fn) => ex.querySelector('[data-x="' + k + '"]').addEventListener("click", fn);
    on("csv", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    on("json", () => download(TOOL_ID + "-" + stamp + ".json", toJson({ ...r, summaryStats: summarize(r.findings) }), "application/json"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r), "text/plain"));
    on("tl", () => download(TOOL_ID + "-timeline-" + stamp + ".csv", timelineToCsv(r.tables.timeline), "text/csv"));
    on("res", () => download(TOOL_ID + "-top-resources-" + stamp + ".csv", resourcesToCsv(r.findings), "text/csv"));
    on("acct", () => download(TOOL_ID + "-accounts-" + stamp + ".csv", accountsToCsv(r.tables.accounts), "text/csv"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: datasetName() });
  }

  renderFiles();
}
