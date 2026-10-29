// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Vulnerability Import & SLA (vulnimport): Deck tool UI. Drop scanner exports (Nessus, Tenable,
// Qualys, Greenbone/OpenVAS, Rapid7, Trivy, Grype, Snyk, SARIF, Defender, generic CSV) and an
// optional baseline; the engine builds one register in a Worker. KEV / EPSS / EOL come from the
// same-origin mirrors under /data/feeds; the only live request is the optional, user-clicked
// EPSS lookup at api.first.org for CVEs missing from the mirror. No native dialogs.
//
//   renderVulnImport(main) -> void

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, COLUMNS, FORMATS, DETECTIONS, SEV_RANK, parseInput, findingsToCsv, registerToCsv, assetsToCsv, remediationToCsv,
  cveListText, summaryText, graphItems, exampleDataset, csvCell, SSVC_OPTIONS, SSVC_GUIDANCE, ssvcDecide, ssvcInputs,
} from "./vulnimport-engine.js?v=20261028c";

const ENGINE = engineUrl("./vulnimport-engine.js?v=20261028c", import.meta);
const P = "vim";
const EPSS_API = "https://api.first.org/data/v1/epss";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const CONF_RANK = { confirmed: 3, likely: 2, review: 1 };
const PRI_RANK = { P1: 4, P2: 3, P3: 2, P4: 1, "": 0 };
const REG_LIMIT = 500;
const SERIES = [["new", "New", "#2a78d6"], ["stillOpen", "Still open", "#eb6834"], ["fixed", "Fixed", "#1baf7a"], ["reopened", "Reopened", "#eda100"], ["notRescanned", "Not rescanned", "#e87ba4"]];

const CSS = `
  .vim-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .vim-root *{box-sizing:border-box}
  .vim-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .vim-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .vim-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .vim-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:100ch}
  .vim-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .vim-card h2{font-size:.95rem;margin:0 0 10px}
  .vim-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .vim-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .vim-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer;max-width:100%;white-space:normal;text-align:left}
  .vim-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .vim-btn.sm{padding:4px 9px;font-size:.76rem}
  .vim-btn:disabled{opacity:.5;cursor:default}
  .vim-files{display:flex;flex-direction:column;gap:6px;margin-top:12px}
  .vim-file{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;font-size:.82rem;min-width:0}
  .vim-file b{overflow-wrap:anywhere;min-width:0}
  .vim-file select{font:inherit;font-size:.78rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:3px 6px;background:var(--card,#fff);color:var(--tx,#1a2230)}
  .vim-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085)}
  .vim-conf.high{color:#1b7f4d;border-color:#1b7f4d}.vim-conf.medium{color:#8a6d00;border-color:#8a6d00}.vim-conf.low{color:#b00020;border-color:#b00020}
  .vim-ctl{display:flex;flex-wrap:wrap;gap:14px 20px;align-items:flex-start}
  .vim-field{display:flex;flex-direction:column;gap:4px;min-width:0;flex:1 1 150px}
  .vim-field.wide{flex:1 1 100%}
  .vim-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .vim-field input,.vim-field select,.vim-field textarea{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%}
  .vim-field input[type=checkbox]{width:auto}
  .vim-field textarea{min-height:64px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}
  .vim-field small{font-size:.74rem;color:var(--mut,#667085);line-height:1.4}
  .vim-check{display:flex;gap:8px;align-items:center;font-size:.84rem}
  .vim-feeds{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
  .vim-feed{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 12px;font-size:.82rem;min-width:0;overflow-wrap:anywhere}
  .vim-feed b{display:block}
  .vim-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .vim-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:110px;flex:1 1 110px}
  .vim-kpi b{display:block;font-size:1.3rem}
  .vim-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .vim-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .vim-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .vim-plabel{font-size:.74rem;color:var(--mut,#667085);margin-top:4px;display:none}
  .vim-tabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;border-bottom:1px solid var(--line,#e6e8ee);padding-bottom:8px}
  .vim-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid transparent;background:none;color:var(--mut,#667085);padding:6px 12px;border-radius:8px;cursor:pointer}
  .vim-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#d7dbe3);background:var(--bg,#f7f8fb)}
  .vim-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .vim-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:680px}
  .vim-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .vim-list th.on{color:var(--tx,#1a2230)}
  .vim-list th.on::after{content:" \\2193";font-size:.7rem}
  .vim-list th.on.asc::after{content:" \\2191"}
  .vim-nw{white-space:nowrap}
  .vim-list td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word;word-break:normal}
  .vim-list tr[data-i]{cursor:pointer}
  .vim-list tr[data-i]:hover,.vim-list tr.sel{background:var(--bg,#f7f8fb)}
  .vim-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .vim-list tbody>tr:has(>td>.vim-pill:is(.P4,.low))>td:first-child{box-shadow:inset 4px 0 0 #2f7d9e}.vim-list tbody>tr:has(>td>.vim-pill:is(.P3,.medium))>td:first-child{box-shadow:inset 4px 0 0 #b58100}.vim-list tbody>tr:has(>td>.vim-pill:is(.P2,.high))>td:first-child{box-shadow:inset 4px 0 0 #d9480f}.vim-list tbody>tr:has(>td>.vim-pill:is(.P1,.critical))>td:first-child{box-shadow:inset 4px 0 0 #b00020}
  .vim-pill.critical,.vim-pill.P1{background:#7a0012}.vim-pill.high,.vim-pill.P2{background:#b00020}.vim-pill.medium,.vim-pill.P3{background:#b58100}.vim-pill.low,.vim-pill.P4{background:#2552c6}.vim-pill.info{background:#667085}
  .vim-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .vim-chip.kev{color:#7a0012;border-color:#7a0012;font-weight:700}
  .vim-chip.od{color:#b00020;border-color:#b00020}
  .vim-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .vim-drawer{margin-top:12px;display:none;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--bg,#f7f8fb);min-width:0}
  .vim-drawer h3{margin:0 0 6px;font-size:1rem;overflow-wrap:anywhere}
  .vim-drawer p{margin:6px 0;overflow-wrap:anywhere}
  .vim-drawer pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.76rem;background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 10px;max-height:240px;overflow:auto;margin:6px 0}
  .vim-drawer .vim-list{background:var(--card,#fff);margin-top:10px}
  .vim-drawer .vim-list table{min-width:520px}
  .vim-dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;font-size:.82rem;margin:8px 0}
  .vim-dl dt{color:var(--mut,#667085)}.vim-dl dd{margin:0;overflow-wrap:anywhere;min-width:0}
  .vim-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px;padding-left:18px}
  .vim-skip li{margin:2px 0;overflow-wrap:anywhere}
  .vim-filters{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:flex-end;margin-bottom:10px}
  .vim-filters .vim-field{flex:0 1 160px}
  .vim-chart{width:100%;max-width:820px;height:auto;display:block}
  .vim-legend{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:.78rem;color:var(--mut,#667085);margin:6px 0 10px}
  .vim-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
  .vim-matrix ol{margin:6px 0 0;padding-left:20px;font-size:.82rem}
  .vim-matrix summary{cursor:pointer;font-weight:600;font-size:.9rem}
  .vim-ssvc{border:1px solid var(--line,#d7dbe3);border-radius:10px;padding:10px 12px;margin:10px 0}
  .vim-ssvc h4{margin:0 0 6px;font-size:.86rem}
  .vim-ssvc-q{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin:6px 0;font-size:.8rem}
  .vim-ssvc-q>span{min-width:150px;color:var(--mut,#667085)}
  .vim-ssvc-q small{flex-basis:100%;color:var(--mut,#667085)}
  .vim-ssvc-q button{appearance:none;font:inherit;font-size:.78rem;border:1px solid var(--line,#d7dbe3);background:none;color:inherit;padding:3px 10px;border-radius:999px;cursor:pointer}
  .vim-ssvc-q button.on{background:var(--acc,#2552c6);border-color:var(--acc,#2552c6);color:#fff}
  .vim-ssvc-r{margin-top:8px;font-size:.84rem}.vim-ssvc-r b{font-size:.95rem}
  .vim-ssvc-r b.act{color:#b00020}.vim-ssvc-r b.attend{color:#b35c00}.vim-ssvc-r b.trackstar{color:#2552c6}
  @media (max-width:560px){.vim-field,.vim-filters .vim-field{flex:1 1 100%}.vim-dl{grid-template-columns:1fr}.vim-card{padding:14px}}
`;

const kpi = (v, l, c) => '<div class="' + P + '-kpi' + (c ? " " + c : "") + '"><b>' + esc(v == null ? "-" : v) + "</b><span>" + esc(l) + "</span></div>";
const pill = (s) => (s ? '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>" : "");
const confClass = (c) => (c >= 0.8 ? "high" : c >= 0.5 ? "medium" : "low");
const yn = (v) => (v === true ? "yes" : v === false ? "no" : "");
const sortBy = (rows, key, dir, rank) => rows.slice().sort((a, b) => {
  const x = rank ? (rank[a[key]] ?? -1) : a[key], y = rank ? (rank[b[key]] ?? -1) : b[key];
  const r = typeof x === "number" && typeof y === "number" ? x - y : typeof x === "boolean" || typeof y === "boolean" ? Number(!!x) - Number(!!y) : cmp(String(x == null ? "" : x).toLowerCase(), String(y == null ? "" : y).toLowerCase());
  return dir === "asc" ? r : -r;
});

/** Sortable table: cols = [{key, label, render?, rank?}]. */
function table(cols, rows, sort, onSort, rowKey, limit) {
  const sorted = sortBy(rows, sort.key, sort.dir, (cols.find((c) => c.key === sort.key) || {}).rank);
  const shown = limit ? sorted.slice(0, limit) : sorted;
  const el = document.createElement("div");
  el.className = P + "-list dn-scrollbox";
  el.innerHTML = "<table><thead><tr>" + cols.map((c) => '<th data-k="' + esc(c.key) + '" class="' + (sort.key === c.key ? "on " + sort.dir : "") + '">' + esc(c.label) + "</th>").join("") + "</tr></thead><tbody>" +
    shown.map((r) => '<tr data-i="' + esc(rowKey(r)) + '">' + cols.map((c) => "<td>" + (c.render ? c.render(r) : esc(r[c.key] == null ? "" : r[c.key])) + "</td>").join("") + "</tr>").join("") + "</tbody></table>";
  el.querySelectorAll("th").forEach((th) => th.addEventListener("click", () => { const k = th.dataset.k; onSort({ key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" }); }));
  return el;
}

/** Plain table for evidence rows: columns are the union of keys. */
function evidenceTable(rows) {
  if (!rows || !rows.length) return '<p class="' + P + '-note">No evidence rows.</p>';
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
  const cell = (k, v) => (k === "severity" || k === "priority" ? pill(v) : esc(v === true ? "yes" : v === false ? "no" : v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v)));
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => "<td>" + cell(k, r[k]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

function burndownSvg(rows) {
  const sevs = rows.filter((r) => r.severity !== "total");
  const series = SERIES.filter(([k]) => sevs.some((r) => r[k] != null));
  const max = Math.max(1, ...sevs.flatMap((r) => series.map(([k]) => r[k] || 0)));
  const W = 820, H = 260, L = 40, B = 34, T = 14, gw = (W - L - 10) / sevs.length, bw = Math.min(26, (gw - 16) / series.length - 2);
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const ticks = [0, Math.ceil(max / 2), max].filter((v, i, a) => a.indexOf(v) === i);
  let s = '<svg class="' + P + '-chart" viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Burn-down by severity">';
  for (const t of ticks) s += '<line x1="' + L + '" x2="' + (W - 10) + '" y1="' + y(t) + '" y2="' + y(t) + '" stroke="#e6e8ee" stroke-width="1"/><text x="' + (L - 6) + '" y="' + (y(t) + 4) + '" text-anchor="end" font-size="11" fill="#667085">' + t + "</text>";
  sevs.forEach((r, i) => {
    const gx = L + i * gw + (gw - series.length * (bw + 2)) / 2;
    series.forEach(([k, label, color], j) => {
      const v = r[k] || 0, x = gx + j * (bw + 2), top = y(v), h = Math.max(0, H - B - top);
      if (v > 0) s += '<path d="M' + x + "," + (H - B) + "V" + (top + Math.min(4, h)) + "q0,-4 4,-4h" + (bw - 8) + "q4,0 4,4V" + (H - B) + 'Z" fill="' + color + '"><title>' + esc(r.severity + ", " + label + ": " + v) + "</title></path>";
      if (v > 0) s += '<text x="' + (x + bw / 2) + '" y="' + (top - 4) + '" text-anchor="middle" font-size="10" fill="#1a2230">' + v + "</text>";
    });
    s += '<text x="' + (L + i * gw + gw / 2) + '" y="' + (H - 12) + '" text-anchor="middle" font-size="12" fill="#1a2230">' + esc(r.severity) + "</text>";
  });
  s += '<line x1="' + L + '" x2="' + (W - 10) + '" y1="' + (H - B) + '" y2="' + (H - B) + '" stroke="#98a2b3" stroke-width="1"/></svg>';
  const legend = '<div class="' + P + '-legend">' + series.map(([, label, color]) => "<span><i style=\"background:" + color + '"></i>' + esc(label) + "</span>").join("") + "</div>";
  return legend + s;
}

function policyHtml() {
  const d = DEFAULTS, sla = d.sla;
  const num = (id, label, v, help, step = 1) => '<div class="' + P + '-field"><label for="' + P + "-o-" + id + '">' + label + '</label><input id="' + P + "-o-" + id + '" type="number" min="0" step="' + step + '" value="' + v + '"><small>' + help + "</small></div>";
  return '<div class="' + P + '-ctl">' +
    num("p1", "P1 SLA (days)", sla.P1, "Default internal policy.") + num("p2", "P2 SLA (days)", sla.P2, "Default internal policy.") +
    num("p3", "P3 SLA (days)", sla.P3, "Default internal policy.") + num("p4", "P4 SLA (days)", sla.P4, "Default internal policy.") +
    num("pci", "PCI critical/high (days)", sla.pciCriticalHighDays, "PCI DSS 4.0.1 6.3.3 asks for one month; 0 = off, 30 = on.") +
    num("kevnet", "Internet-facing KEV (days)", sla.kevInternetDays, "CISA BOD 22-01 two-week clock; 0 = off.") +
    '<div class="' + P + '-field"><label>KEV due date</label><span class="' + P + '-check"><input id="' + P + '-o-kevdue" type="checkbox"' + (sla.kevCatalogDue ? " checked" : "") + '> use the catalog due date</span><small>BOD 22-01: remediate KEV entries by the date CISA sets.</small></div>' +
    num("epssHigh", "EPSS for P1", d.epssHigh, "With CVSS 7 or more.", 0.01) + num("epssMed", "EPSS for P2", d.epssMedium, "At or above this.", 0.01) +
    num("many", "Criticals per asset", d.manyCriticals, "Open criticals before an asset is reported.") + num("old", "Old after (days)", d.oldDays, "Open longer than this is reported.") +
    num("disagree", "Severity gap", d.disagreeSteps, "Scanner disagreement, in severity levels.") +
    '<div class="' + P + '-field"><label for="' + P + '-o-now">Reference date</label><input id="' + P + '-o-now" type="date"><small>Blank = newest date in the data.</small></div>' +
    '<div class="' + P + '-field"><label>Informational items</label><span class="' + P + '-check"><input id="' + P + '-o-info" type="checkbox"> keep in register</span><small>Severity 0 / Log items are dropped by default.</small></div>' +
    '<div class="' + P + '-field wide"><label for="' + P + '-o-net">Internet-facing assets</label><textarea id="' + P + '-o-net" placeholder="one per line" spellcheck="false"></textarea><small>One host name, IP or IPv4 CIDR per line, or a single regular expression (for example ^dmz-). Used by the priority matrix and the BOD 22-01 clock.</small></div>' +
    "</div>" +
    '<details class="' + P + '-matrix" style="margin-top:12px"><summary>How priority is assigned</summary><ol>' +
    "<li>In CISA KEV: P1.</li><li>EPSS at or above the P1 threshold and CVSS 7 or more: P1.</li><li>CVSS 9 or more and the asset is internet-facing or an exploit is available: P1.</li>" +
    "<li>CVSS 7 or more, or EPSS at or above the P2 threshold: P2.</li><li>CVSS 4 or more: P3.</li><li>Otherwise P4.</li></ol>" +
    '<p class="' + P + '-note">CVSS is the v3 base score (computed from the vector when only a vector is exported), else v2. Without any score the scanner severity stands in (critical 9, high 7, medium 4, low 0.1) and the register says so. Due date = first seen + the bucket SLA, or the earliest applicable of the PCI, KEV catalog and internet-facing KEV clocks. First seen comes from the scanner, else the scan date, else the baseline when the baseline saw it earlier.</p>' +
    '<p class="' + P + '-note">Detections: ' + DETECTIONS.map((d2) => esc(d2.title) + " (needs " + esc(d2.needs) + ")").join("; ") + ".</p></details>";
}

/** Mount the tool into main. */
export function renderVulnImport(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Vulnerability Import &amp; SLA</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">One vulnerability register from every scanner export: de-duplicated per asset and CVE, enriched with CISA KEV and FIRST EPSS, prioritised, measured against SLA policy and compared with last period. Runs entirely in your browser. Nothing is uploaded. KEV, EPSS and end-of-life data are mirrored, dated copies served by this site; the only live request is the optional Fetch live EPSS button, which queries api.first.org.</p>',
    '<div class="', P, '-card"><h2>1. Imports</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-note">Accepted: Nessus .nessus, Tenable / Nessus CSV, Tenable vulnerability export CSV, Qualys CSV and XML, Greenbone / OpenVAS XML and CSV, Rapid7 InsightVM CSV, Trivy, Grype, Snyk and SARIF JSON, Defender Vulnerability Management CSV (weaknesses, per device, advanced hunting), any CSV with an asset and CVE column, and this tool\'s own JSON export as the baseline. Zip and gzip archives are unpacked locally.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div>',
    '<div id="', P, '-map"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button><button class="', P, '-btn" id="', P, '-clear" disabled>Clear files</button><span class="', P, '-note" id="', P, '-count"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-plabel" id="', P, '-plabel"></div></div>',
    '<div class="', P, '-card"><h2>2. Enrichment</h2><div class="', P, '-feeds" id="', P, '-feeds"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-live" disabled>Fetch live EPSS for CVEs not in the mirror</button><span class="', P, '-note" id="', P, '-livenote">Off until you click. Sends only CVE ids to api.first.org, at most 100 per request.</span></div></div>',
    '<div class="', P, '-card"><h2>3. Policy</h2>', policyHtml(), "</div>",
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card" id="', P, '-results" style="display:none"><div class="', P, '-tabs" id="', P, '-tabs"></div><div id="', P, '-pane"></div><div class="', P, '-drawer" id="', P, '-drawer"></div><ul class="', P, '-skip" id="', P, '-skipped"></ul></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, running = false, tab = "register";
  const feeds = { kev: null, epss: null, eol: null };
  let epssLive = null, epssLiveAt = "";
  const columnMap = {};
  const sorts = { register: { key: "priority", dir: "desc" }, assets: { key: "maxPriority", dir: "desc" }, cves: { key: "priority", dir: "desc" }, findings: { key: "severity", dir: "desc" } };
  let filters = { q: "", priority: "", scanner: "", status: "", kev: false, overdue: false };
  let selected = "";
  const ssvcPick = new Map(); // register row key -> SSVC answers the analyst chose (this session only)

  // ---- feeds (same-origin mirrors, loaded on mount) ----
  function renderFeeds() {
    const f = (label, feed, extra) => '<div class="' + P + '-feed"><b>' + label + "</b>" + (feed ? "mirrored " + esc(String(feed.updated || "").slice(0, 10)) + ", " + esc(feed.count || (feed.data || []).length) + " " + extra : "not loaded") + "</div>";
    $("feeds").innerHTML = f("CISA KEV", feeds.kev, "entries") + f("FIRST EPSS", feeds.epss, "CVEs (top scores + every KEV CVE)") + f("End-of-life (endoflife.date)", feeds.eol, "products") +
      '<div class="' + P + '-feed"><b>EPSS live</b>' + (epssLiveAt ? "fetched live " + esc(epssLiveAt) + ", " + Object.keys(epssLive || {}).length + " CVEs" : "not fetched") + "</div>";
  }
  for (const [k, file] of [["kev", "cisa-kev-index"], ["epss", "epss-top"], ["eol", "eol-products"]]) {
    fetch("/data/feeds/" + file + ".json").then((r) => (r.ok ? r.json() : null)).then((j) => { if (j) { feeds[k] = j; renderFeeds(); } }).catch(() => {});
  }
  renderFeeds();

  // ---- files ----
  const totalRecords = () => files.reduce((n, f) => n + f.records, 0);
  const datasetName = () => (isExample ? "synthetic example" : files.map((f) => f.name).join(", "));

  function renderFiles() {
    const box = $("files");
    box.innerHTML = files.map((f, i) =>
      '<div class="' + P + '-file"><b>' + esc(f.name) + "</b><span>" + esc(f.label) + "</span>" +
      '<span class="' + P + "-conf " + confClass(f.confidence) + '">' + confClass(f.confidence) + " confidence</span><span>" + f.records + " records</span>" +
      '<label class="' + P + '-check">Role <select data-role="' + i + '"><option value="current"' + (f.role === "current" ? " selected" : "") + '>current</option><option value="baseline"' + (f.role === "baseline" ? " selected" : "") + ">baseline</option></select></label>" +
      '<button class="' + P + '-btn sm" data-rm="' + i + '" type="button">Remove</button>' + (f.notes && f.notes.length ? '<span class="' + P + '-note">' + esc(f.notes.join("; ")) + "</span>" : "") + "</div>").join("");
    box.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { files.splice(Number(b.dataset.rm), 1); isExample = false; renderFiles(); }));
    box.querySelectorAll("[data-role]").forEach((s) => s.addEventListener("change", () => { files[Number(s.dataset.role)].role = s.value; renderFiles(); }));
    const nb = files.filter((f) => f.role === "baseline").length;
    $("count").textContent = files.length ? files.length + " file" + (files.length === 1 ? "" : "s") + ", " + totalRecords() + " records" + (nb ? ", " + nb + " baseline" : "") + (isExample ? " (synthetic example)" : "") : "";
    $("run").disabled = !files.length || running || !files.some((f) => f.role === "current");
    $("clear").disabled = !files.length;
    renderMapping();
  }

  function renderMapping() {
    const generic = files.filter((f) => f.format === "generic");
    const box = $("map");
    if (!generic.length) { box.innerHTML = ""; return; }
    const headers = [...new Set(generic.flatMap((f) => f.headers))];
    const norm = (h) => String(h).toLowerCase().replace(/[^a-z0-9]/g, "");
    box.innerHTML = '<div class="' + P + '-card" style="margin:12px 0 0"><h2>Column mapping</h2><p class="' + P + '-note">' + esc(generic.map((f) => f.name).join(", ")) + ": not a known scanner layout. Map at least the asset and a CVE or title column, then re-add the file or click Analyze.</p>" +
      '<div class="' + P + '-ctl">' + Object.keys(COLUMNS).map((k) => '<div class="' + P + '-field"><label>' + esc(k.replace("_", " ")) + '</label><select data-col="' + esc(k) + '"><option value="">(not present)</option>' +
        headers.map((h) => '<option value="' + esc(h) + '"' + (columnMap[k] === h || (!columnMap[k] && COLUMNS[k].some((a) => norm(a) === norm(h))) ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>").join("") + "</div></div>";
    box.querySelectorAll("[data-col]").forEach((sel) => {
      if (sel.value) columnMap[sel.dataset.col] = sel.value;
      sel.addEventListener("change", () => { if (sel.value) columnMap[sel.dataset.col] = sel.value; else delete columnMap[sel.dataset.col]; reparseGeneric(); });
    });
  }
  function reparseGeneric() {
    for (const f of files) if (f.format === "generic") { const p = parseInput([{ name: f.name, text: f.text }], { columns: columnMap }); const pf = p.files[0]; if (pf) { f.records = pf.records; f.notes = pf.notes; } }
    const box = $("files"); if (box) { const keep = $("map").innerHTML; renderFiles(); if (!$("map").innerHTML) $("map").innerHTML = keep; }
  }

  function addFile(name, text, role) {
    // Detection is cheap (header / first element); full parsing happens in the worker.
    const big = text.length > 2 * 1024 * 1024;
    const p = parseInput([{ name, text: big ? sampleOf(text) : text, role }], { columns: columnMap });
    const f = p.files[0];
    if (!f || f.format === "unknown") { toast("Not a recognised scanner export: " + name, "warning"); return false; }
    const entry = { name, text, role: f.role, format: f.format, label: f.label, confidence: f.confidence, headers: f.headers || [], records: big ? 0 : f.records, notes: big ? ["large file: records are counted during analysis"] : f.notes };
    const idx = files.findIndex((x) => x.name === name);
    if (idx >= 0) files[idx] = entry; else files.push(entry);
    return true;
  }
  // For a quick format check of a large file: the head, cut at the last complete line.
  function sampleOf(text) { const head = text.slice(0, 262144); const t = head.trimStart()[0]; if (t === "{" || t === "[") return text; const nl = head.lastIndexOf("\n"); return nl > 0 ? head.slice(0, nl) : head; }

  mountDropzone($("drop"), {
    maxBytes: 256 * 1024 * 1024, maxFiles: 500, unpack: true, multiple: true,
    label: "Drop scanner exports here, paste, or browse",
    onFiles: async (list) => {
      let added = 0;
      for (const f of list) { if (addFile(f.name, await f.text())) added++; }
      if (added) { if (isExample) { files = files.filter((f) => !f.name.startsWith("example-")); } isExample = false; toast("Added " + added + " file" + (added === 1 ? "" : "s"), "success"); }
      renderFiles();
    },
  });
  $("clear").addEventListener("click", () => { files = []; isExample = false; renderFiles(); });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    files = []; isExample = true; epssLive = null; epssLiveAt = "";
    for (const f of ex.files) addFile(f.name, f.text, f.role);
    renderFiles(); renderFeeds();
    toast("Synthetic example loaded: " + files.length + " files incl. a baseline. Click Analyze.", "info");
  });

  // ---- options ----
  const val = (id) => Number($("o-" + id).value);
  const opts = () => {
    const nn = (id, d) => (Number.isFinite(val(id)) && val(id) >= 0 ? val(id) : d);
    const o = {
      columns: { ...columnMap }, includeInfo: $("o-info").checked, internetFacing: $("o-net").value.trim(),
      epssHigh: nn("epssHigh", DEFAULTS.epssHigh), epssMedium: nn("epssMed", DEFAULTS.epssMedium), manyCriticals: nn("many", DEFAULTS.manyCriticals), oldDays: nn("old", DEFAULTS.oldDays), disagreeSteps: nn("disagree", DEFAULTS.disagreeSteps),
      sla: { P1: nn("p1", 15), P2: nn("p2", 30), P3: nn("p3", 90), P4: nn("p4", 180), pciCriticalHighDays: nn("pci", 0), kevInternetDays: nn("kevnet", 14), kevCatalogDue: $("o-kevdue").checked },
      kev: feeds.kev, epss: feeds.epss, eol: feeds.eol, epssLive, epssLiveAt,
    };
    const now = $("o-now").value.trim(); if (now) o.now = now + "T23:59:59Z";
    return o;
  };

  async function run() {
    if (!files.length || running) return;
    running = true;
    const prog = $("prog"), bar = prog.firstElementChild, pl = $("plabel");
    prog.style.display = "block"; pl.style.display = "block"; bar.style.width = "0%"; pl.textContent = "starting"; $("run").disabled = true;
    try {
      result = await runInWorker(ENGINE, "analyze", [files.map((f) => ({ name: f.name, text: f.text, role: f.role })), opts()], {
        timeoutMs: 600000,
        onProgress: (i, n, label) => { bar.style.width = (n ? Math.min(100, Math.round((i / n) * 100)) : 50) + "%"; if (label) pl.textContent = label + (n ? "" : " " + i); },
      });
      for (const mf of result.meta.files) { const f = files.find((x) => x.name === mf.name); if (f) f.records = mf.records; }
      renderFiles();
      selected = ""; $("drawer").style.display = "none";
      render();
      toast(result.summary.vulns + " vulnerabilities on " + result.summary.assets + " assets, " + result.findings.length + " findings", "success");
    } catch (e) {
      toast("Analysis failed: " + ((e && e.message) || e), "error");
    } finally {
      running = false;
      prog.style.display = "none"; pl.style.display = "none"; renderFiles();
    }
  }
  $("run").addEventListener("click", run);

  // ---- live EPSS (only on click) ----
  $("live").addEventListener("click", async () => {
    const missing = result ? result.summary.missingEpss : [];
    if (!missing.length) return;
    $("live").disabled = true;
    const got = { ...(epssLive || {}) };
    try {
      for (let i = 0; i < missing.length; i += 100) {
        $("livenote").textContent = "Querying api.first.org: " + Math.min(i + 100, missing.length) + " of " + missing.length;
        const r = await fetch(EPSS_API + "?cve=" + encodeURIComponent(missing.slice(i, i + 100).join(",")), { headers: { Accept: "application/json" } });
        if (!r.ok) throw new Error("api.first.org returned HTTP " + r.status);
        const j = await r.json();
        for (const e of j.data || []) got[String(e.cve).toUpperCase()] = { epss: Number(e.epss), percentile: Number(e.percentile) };
      }
      epssLive = got; epssLiveAt = new Date().toISOString().replace(/\.\d+Z$/, "Z");
      const n = missing.filter((c) => got[c]).length;
      $("livenote").textContent = "Fetched live " + epssLiveAt + " from api.first.org: scores for " + n + " of " + missing.length + " CVEs (FIRST has no score for the rest).";
      renderFeeds();
      await run();
    } catch (e) {
      $("livenote").textContent = "Live EPSS failed: " + ((e && e.message) || e);
      toast("Live EPSS failed: " + ((e && e.message) || e), "error");
      $("live").disabled = false;
    }
  });

  // ---- results ----
  function render() {
    const r = result, s = r.summary;
    $("kpis").innerHTML = kpi(s.assets, "assets") + kpi(s.open, "open vulns") + kpi(s.uniqueCves, "unique CVEs") + kpi(s.kev, "KEV", s.kev ? "kpi-critical" : "") + kpi(s.P1, "P1", s.P1 ? "kpi-critical" : "") + kpi(s.overdue, "overdue", s.overdue ? "kpi-high" : "") +
      kpi(s.fixed, s.baseline ? "fixed since baseline" : "fixed (scanner)") + kpi(s.meanTimeToRemediate == null ? "-" : s.meanTimeToRemediate + " d", "MTTR (n=" + s.mttrSamples + ")");
    const live = $("live");
    live.disabled = !s.missingEpss.length;
    live.textContent = s.missingEpss.length ? "Fetch live EPSS for " + s.missingEpss.length + " CVE" + (s.missingEpss.length === 1 ? "" : "s") + " not in the mirror" : "All CVEs have an EPSS score";
    $("results").style.display = "";
    $("skipped").innerHTML = r.skipped.length ? "<li><b>Skipped or limited checks</b></li>" + r.skipped.map((k) => "<li>" + esc(k.check) + ": " + esc(k.reason) + "</li>").join("") : "";
    const tabs = [["register", "Register (" + r.tables.vulns.length + ")"], ["assets", "Assets (" + r.tables.assets.length + ")"], ["cves", "CVEs (" + r.tables.cves.length + ")"], ["sla", "SLA"], ["burndown", "Burn-down"], ["findings", "Findings (" + r.findings.length + ")"]];
    $("tabs").innerHTML = tabs.map(([k, l]) => '<button type="button" class="' + P + "-tab" + (tab === k ? " on" : "") + '" data-tab="' + k + '">' + esc(l) + "</button>").join("");
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; $("drawer").style.display = "none"; selected = ""; render(); }));
    drawPane();
    renderExports();
  }

  function drawPane() {
    const pane = $("pane");
    pane.innerHTML = "";
    if (tab === "register") return drawRegister(pane);
    if (tab === "assets") return drawSimple(pane, "assets", ASSET_COLS, result.tables.assets, (a) => a.key, (k) => { filters = { ...filters, q: result.tables.assets.find((a) => a.key === k).name }; tab = "register"; render(); });
    if (tab === "cves") return drawSimple(pane, "cves", CVE_COLS, result.tables.cves, (c) => c.cve, (k) => { filters = { ...filters, q: k }; tab = "register"; render(); });
    if (tab === "sla") { pane.appendChild(staticTable(SLA_COLS, result.tables.sla)); pane.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">Open items per priority bucket. Within = has a due date that has not passed; no date = the export has no first-seen or scan date.</p>'); return; }
    if (tab === "burndown") {
      const bd = result.tables.burndown;
      pane.innerHTML = '<p class="' + P + '-note">' + (result.summary.baseline ? "Compared with the baseline import. Fixed = open in the baseline and absent from (or fixed in) a rescanned asset; not rescanned = the asset itself is missing, so the item is not counted as fixed." : "No baseline: counts come from the scanners' own status fields. Load last period's JSON export (or mark a file as baseline) to see new versus fixed.") + "</p>" + burndownSvg(bd);
      pane.appendChild(staticTable(BD_COLS, bd));
      return;
    }
    if (tab === "findings") return drawFindings(pane);
  }

  const REG_COLS = [
    { key: "priority", label: "Priority", rank: PRI_RANK, render: (r) => pill(r.priority) },
    { key: "assetName", label: "Asset", render: (r) => esc(r.assetName) + (r.internetFacing ? ' <span class="' + P + '-chip">internet</span>' : "") },
    { key: "cve", label: "CVE / ID", render: (r) => '<span class="' + P + '-nw">' + esc(r.cve || r.vulnKey) + "</span>" + (r.kev ? ' <span class="' + P + '-chip kev">KEV</span>' : "") },
    { key: "title", label: "Title" },
    { key: "cvss", label: "CVSS" },
    { key: "epss", label: "EPSS", render: (r) => (r.epss == null ? "-" : esc(r.epss) + (r.epssSource === "live" ? ' <span class="' + P + '-chip">live</span>' : "")) },
    { key: "kev", label: "KEV", render: (r) => (r.kev ? "yes" : "") },
    { key: "scanners", label: "Scanner" },
    { key: "firstSeen", label: "First seen", render: (r) => '<span class="' + P + '-nw">' + esc(r.firstSeen || "") + "</span>" },
    { key: "due", label: "Due", render: (r) => '<span class="' + P + '-nw">' + esc(r.due || "") + "</span>" },
    { key: "daysOverdue", label: "Overdue", render: (r) => (r.overdue ? '<span class="' + P + '-chip od">' + r.daysOverdue + " d</span>" : "") },
    { key: "status", label: "Status", render: (r) => esc(r.status) + (r.change ? '<div class="' + P + '-note" style="margin:0">' + esc(r.change) + "</div>" : "") },
  ];
  const ASSET_COLS = [
    { key: "maxPriority", label: "Max priority", rank: PRI_RANK, render: (a) => pill(a.maxPriority) },
    { key: "name", label: "Asset" }, { key: "kind", label: "Kind" }, { key: "os", label: "OS" }, { key: "open", label: "Open" },
    { key: "critical", label: "Critical" }, { key: "high", label: "High" }, { key: "medium", label: "Medium" }, { key: "low", label: "Low" },
    { key: "kev", label: "KEV" }, { key: "overdue", label: "Overdue" }, { key: "scanners", label: "Scanners" },
  ];
  const CVE_COLS = [
    { key: "priority", label: "Priority", rank: PRI_RANK, render: (c) => pill(c.priority) },
    { key: "cve", label: "CVE", render: (c) => '<span class="' + P + '-nw">' + esc(c.cve) + "</span>" + (c.kev ? ' <span class="' + P + '-chip kev">KEV</span>' : "") + (c.ransomware ? ' <span class="' + P + '-chip kev">ransomware</span>' : "") },
    { key: "title", label: "Title" }, { key: "assets", label: "Assets" }, { key: "maxCvss", label: "Max CVSS" },
    { key: "epss", label: "EPSS", render: (c) => (c.epss == null ? "-" : esc(c.epss)) }, { key: "kevDue", label: "KEV due" },
    { key: "fixAvailable", label: "Fix", render: (c) => (c.fixAvailable ? "yes" : "no") }, { key: "overdue", label: "Overdue" }, { key: "scanners", label: "Scanners" },
  ];
  const SLA_COLS = [{ key: "bucket", label: "Bucket", render: (b) => pill(b.bucket) }, { key: "days", label: "SLA days" }, { key: "total", label: "Open" }, { key: "within", label: "Within" }, { key: "overdue", label: "Overdue" }, { key: "noDate", label: "No date" }, { key: "medianDaysOpen", label: "Median days open" }, { key: "fixed", label: "Fixed" }, { key: "fixedWithinSla", label: "Fixed within SLA" }];
  const BD_COLS = [{ key: "severity", label: "Severity" }, ...SERIES.map(([k, l]) => ({ key: k, label: l }))];

  function staticTable(cols, rows) {
    const el = document.createElement("div");
    el.className = P + "-list dn-scrollbox";
    el.innerHTML = "<table><thead><tr>" + cols.map((c) => "<th>" + esc(c.label) + "</th>").join("") + "</tr></thead><tbody>" +
      rows.map((r) => "<tr>" + cols.map((c) => "<td>" + (c.render ? c.render(r) : esc(r[c.key] == null ? "-" : r[c.key])) + "</td>").join("") + "</tr>").join("") + "</tbody></table>";
    return el;
  }
  function drawSimple(pane, name, cols, rows, keyOf, onPick) {
    if (!rows.length) { pane.innerHTML = '<div class="' + P + '-empty">Nothing to show.</div>'; return; }
    const t = table(cols, rows, sorts[name], (s) => { sorts[name] = s; drawPane(); }, keyOf);
    t.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => onPick(tr.dataset.i)));
    pane.appendChild(t);
    pane.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">Click a row to filter the register to it.</p>');
  }

  function drawRegister(pane) {
    const r = result;
    const scanners = [...new Set(r.tables.vulns.flatMap((v) => v.scanners.split("; ")))].sort(cmp);
    const sel = (id, label, options) => '<div class="' + P + '-field"><label for="' + P + "-f-" + id + '">' + label + '</label><select id="' + P + "-f-" + id + '" data-f="' + id + '"><option value="">All</option>' + options.map((o) => '<option value="' + esc(o) + '"' + (filters[id] === o ? " selected" : "") + ">" + esc(o) + "</option>").join("") + "</select></div>";
    const bar = document.createElement("div");
    bar.className = P + "-filters";
    bar.innerHTML = '<div class="' + P + '-field"><label for="' + P + '-f-q">Search</label><input id="' + P + '-f-q" data-f="q" type="search" placeholder="asset, CVE, title" value="' + esc(filters.q) + '"></div>' +
      sel("priority", "Priority", ["P1", "P2", "P3", "P4"]) + sel("scanner", "Scanner", scanners) + sel("status", "Status", ["open", "reopened", "fixed", "unknown"]) +
      '<label class="' + P + '-check"><input type="checkbox" data-f="kev"' + (filters.kev ? " checked" : "") + "> KEV only</label>" +
      '<label class="' + P + '-check"><input type="checkbox" data-f="overdue"' + (filters.overdue ? " checked" : "") + "> Overdue only</label>";
    pane.appendChild(bar);
    const box = document.createElement("div");
    pane.appendChild(box);
    const draw = () => {
      const q = filters.q.trim().toLowerCase();
      const rows = r.tables.vulns.filter((v) => (!filters.priority || v.priority === filters.priority) && (!filters.scanner || v.scanners.split("; ").includes(filters.scanner)) &&
        (!filters.status || v.status === filters.status) && (!filters.kev || v.kev) && (!filters.overdue || v.overdue) &&
        (!q || [v.assetName, v.ip, v.fqdn, v.cve, v.vulnKey, v.title, v.package].some((x) => String(x || "").toLowerCase().includes(q))));
      box.innerHTML = "";
      if (!rows.length) { box.innerHTML = '<div class="' + P + '-empty">No vulnerabilities match the filters.</div>'; return; }
      const t = table(REG_COLS, rows, sorts.register, (s) => { sorts.register = s; draw(); }, (v) => v.key, REG_LIMIT);
      t.querySelectorAll("tr[data-i]").forEach((tr) => { if (tr.dataset.i === selected) tr.classList.add("sel"); tr.addEventListener("click", () => { selected = tr.dataset.i; draw(); showVuln(r.tables.vulns.find((v) => v.key === selected)); }); });
      box.appendChild(t);
      box.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">' + (rows.length > REG_LIMIT ? "Showing the first " + REG_LIMIT + " of " + rows.length + " in the current sort; narrow the filters or export the register CSV for all rows." : rows.length + " of " + r.tables.vulns.length + " rows.") + " Click a row for the evidence.</p>");
    };
    bar.querySelectorAll("[data-f]").forEach((el) => el.addEventListener(el.type === "checkbox" ? "change" : "input", () => { filters[el.dataset.f] = el.type === "checkbox" ? el.checked : el.value; draw(); }));
    draw();
  }

  function closeBtn() { return '<button class="' + P + '-btn sm" data-close type="button">Close</button>'; }
  function wireClose(d) { d.querySelector("[data-close]").addEventListener("click", () => { d.style.display = "none"; selected = ""; drawPane(); }); d.scrollIntoView({ block: "nearest", behavior: "smooth" }); }

  function showVuln(v) {
    const d = $("drawer");
    if (!v) { d.style.display = "none"; return; }
    const dl = [["Asset", v.assetName + (v.ip && v.ip !== v.assetName ? " (" + v.ip + ")" : "")], ["Kind / OS", v.kind + (v.os ? ", " + v.os : "")], ["CVE / ID", v.cve || v.vulnKey], ["All CVEs", v.cves], ["Scanner IDs", v.pluginId],
      ["Severity", v.severity + (v.severityScanner ? " (scanners: " + v.severityScanner + ")" : "")], ["CVSS", v.cvss == null ? "-" : v.cvss + " (" + v.cvssSource + ")" + (v.cvssVector ? " " + v.cvssVector : "")],
      ["EPSS", v.epss == null ? "not in mirror" : v.epss + " (percentile " + v.epssPercentile + ", " + v.epssSource + ")"], ["KEV", v.kev ? "yes, added " + v.kevDateAdded + ", due " + v.kevDue + (v.ransomware ? ", known ransomware use" : "") : "no"],
      ["Priority", v.priority + ": " + v.priorityReason], ["Internet-facing", yn(v.internetFacing) || "no"], ["Exploit available", yn(v.exploit) || "not reported"],
      ["First seen", v.firstSeen + (v.firstSeenBasis ? " (" + v.firstSeenBasis + ")" : "")], ["Last seen", v.lastSeen], ["Due", v.due ? v.due + " (" + v.dueBasis + ")" : v.dueBasis], ["Overdue", v.overdue ? v.daysOverdue + " days" : "no"],
      ["Status", v.status + (v.change ? " (" + v.change + " vs baseline)" : "")], ["Port / protocol", [v.port, v.protocol].filter(Boolean).join("/")], ["Package", [v.package, v.installed].filter(Boolean).join(" ")], ["Fixed version", v.fixedVersion],
      ["Published", v.published], ["Exposed devices", v.exposedDevices]].filter(([, x]) => x !== "" && x != null);
    d.style.display = "block";
    d.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + pill(v.priority) + " " + esc(v.title) + "</h3>" + closeBtn() + "</div>" +
      '<dl class="' + P + '-dl">' + dl.map(([k, x]) => "<dt>" + esc(k) + "</dt><dd>" + esc(x) + "</dd>").join("") + "</dl>" +
      (v.solution ? "<p><b>Solution</b></p><pre>" + esc(v.solution) + "</pre>" : "") + (v.output ? "<p><b>Scanner output</b></p><pre>" + esc(v.output) + "</pre>" : "") +
      (v.references ? "<p><b>References</b></p><pre>" + esc(v.references) + "</pre>" : "") +
      '<div class="' + P + '-ssvc" id="' + P + '-ssvc"></div>';
    drawSsvc(d.querySelector("#" + P + "-ssvc"), v);
    wireClose(d);
  }

  // SSVC second opinion: answers the row supports are pre-selected (with their basis); mission
  // prevalence is the analyst's call, so no decision shows until it is chosen.
  function drawSsvc(box, v) {
    const auto = ssvcInputs(v);
    const pick = ssvcPick.get(v.key) || { exploitation: auto.exploitation, impact: auto.impact, automatable: auto.automatable, prevalence: "" };
    const Q = [["exploitation", "Exploitation"], ["impact", "Technical impact"], ["automatable", "Automatable"], ["prevalence", "Mission prevalence"]];
    const dec = ssvcDecide(pick.exploitation, pick.impact, pick.automatable, pick.prevalence);
    const cls = { Act: "act", Attend: "attend", "Track*": "trackstar", Track: "track" };
    box.innerHTML = "<h4>SSVC decision (CISA)</h4>" + Q.map(([k, label]) => '<div class="' + P + '-ssvc-q"><span>' + esc(label) + "</span>" +
      SSVC_OPTIONS[k].map(([val, l]) => '<button type="button" data-k="' + k + '" data-v="' + val + '"' + (pick[k] === val ? ' class="on"' : "") + ">" + esc(l) + "</button>").join("") +
      (auto.basis[k] ? "<small>From the import: " + esc(auto.basis[k]) + "</small>" : k === "prevalence" ? "<small>How central the affected asset is to your mission. Your call.</small>" : "<small>Not derivable from this record; choose one.</small>") + "</div>").join("") +
      '<div class="' + P + '-ssvc-r">' + (dec ? '<b class="' + cls[dec] + '">' + esc(dec) + "</b>: " + esc(SSVC_GUIDANCE[dec]) + " The P1-P4 priority above is unchanged." : "Answer all four to see the SSVC decision.") + "</div>";
    box.querySelectorAll("button[data-k]").forEach((b) => b.addEventListener("click", () => { ssvcPick.set(v.key, { ...pick, [b.dataset.k]: b.dataset.v }); drawSsvc(box, v); }));
  }

  const FIND_COLS = [
    { key: "severity", label: "Severity", rank: SEV_RANK, render: (f) => pill(f.severity) },
    { key: "title", label: "Finding", render: (f) => "<b>" + esc(f.title) + "</b><div>" + esc(f.description) + "</div>" },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
    { key: "controls", label: "Controls", render: (f) => (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") },
    { key: "evidenceCount", label: "Evidence" },
  ];
  function drawFindings(pane) {
    const r = result;
    if (!r.findings.length) { pane.innerHTML = '<div class="' + P + '-empty">No findings for the current policy.</div>'; return; }
    const rows = r.findings.map((f, i) => ({ ...f, i }));
    const t = table(FIND_COLS, rows, sorts.findings, (s) => { sorts.findings = s; drawPane(); }, (f) => f.i);
    t.querySelectorAll("tr[data-i]").forEach((tr) => { if (tr.dataset.i === selected) tr.classList.add("sel"); tr.addEventListener("click", () => { selected = tr.dataset.i; drawPane(); showFinding(r.findings[Number(selected)]); }); });
    pane.appendChild(t);
  }
  function showFinding(f) {
    const d = $("drawer");
    const det = DETECTIONS.find((x) => x.id === f.check || "overdue_" + x.id === f.check);
    d.style.display = "block";
    d.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + pill(f.severity) + " " + esc(f.title) + "</h3>" + closeBtn() + "</div>" +
      "<p>" + esc(f.description) + "</p><p><b>Recommendation:</b> " + esc(f.recommendation) + "</p>" +
      "<p><b>Confidence:</b> " + esc(f.confidence) + (det ? " &middot; <b>Needs:</b> " + esc(det.needs) : "") + "</p>" +
      "<p>" + (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</p>" +
      "<p><b>Evidence</b> (" + (f.evidence || []).length + " of " + f.evidenceCount + ")</p>" + evidenceTable(f.evidence) +
      '<div class="' + P + '-row"><button class="' + P + '-btn sm" data-ev type="button">Export evidence CSV</button></div>';
    wireClose(d);
    d.querySelector("[data-ev]").addEventListener("click", () => {
      const rows = f.evidence || [], keys = [];
      for (const x of rows) for (const k of Object.keys(x)) if (!keys.includes(k)) keys.push(k);
      download(TOOL_ID + "-evidence-" + fileStamp() + ".csv", [keys.join(","), ...rows.map((x) => keys.map((k) => csvCell(x[k])).join(","))].join("\n"), "text/csv");
    });
  }

  // ---- exports + graph ----
  function renderExports() {
    const r = result, ex = $("exports"), stamp = fileStamp();
    const b = (x, l) => '<button class="' + P + '-btn" data-x="' + x + '">' + l + "</button>";
    ex.innerHTML = b("reg", "Register CSV") + b("assets", "Assets CSV") + b("plan", "Remediation plan CSV") + b("find", "Findings CSV") + b("json", "JSON (baseline for next time)") + b("txt", "Summary TXT") + b("cves", "CVE list TXT") + b("graph", "Add assets and CVEs to Security Graph");
    const on = (x, fn) => ex.querySelector('[data-x="' + x + '"]').addEventListener("click", fn);
    on("reg", () => download(TOOL_ID + "-register-" + stamp + ".csv", registerToCsv(r.tables.vulns), "text/csv"));
    on("assets", () => download(TOOL_ID + "-assets-" + stamp + ".csv", assetsToCsv(r.tables.assets), "text/csv"));
    on("plan", () => download(TOOL_ID + "-remediation-" + stamp + ".csv", remediationToCsv(r.tables.remediation), "text/csv"));
    on("find", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    on("json", () => download(TOOL_ID + "-" + stamp + ".json", toJson({ ...r, summaryStats: summarize(r.findings) }), "application/json"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r), "text/plain"));
    on("cves", () => download(TOOL_ID + "-cves-" + stamp + ".txt", cveListText(r), "text/plain"));
    const gbtn = ex.querySelector('[data-x="graph"]');
    if (isExample) { gbtn.disabled = true; gbtn.title = "Sample data is not written to the Security Graph"; }
    gbtn.addEventListener("click", async () => {
      if (isExample) return;
      gbtn.disabled = true;
      try {
        const gb = await import("/js/graph-bridge.js");
        const { items, links } = graphItems(r);
        const res = gb.sendToGraph(TOOL_ID, items, undefined, true);
        const byKey = new Map((res.entities || []).map((e) => [e.type + ":" + String(e.name).toLowerCase(), e]));
        gb.batchGraph(() => { for (const l of links) { const a = byKey.get(l.from.toLowerCase().replace(/^[a-z_]+:/, (m) => m.toUpperCase())), c = byKey.get(l.to.toLowerCase().replace(/^[a-z_]+:/, (m) => m.toUpperCase())); if (a && c) gb.linkEntities(a.id, c.id, l.rel); } });
        gbtn.textContent = "Added to graph";
        toast("Security Graph: " + (res.created || 0) + " added, " + (res.updated || 0) + " updated", "success");
      } catch (e) { gbtn.disabled = false; toast((e && e.message) || "Couldn't reach the Security Graph", "error"); }
    });
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: datasetName() });
  }

  renderFiles();
}
