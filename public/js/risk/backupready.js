// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Backup Readiness (backupready): Deck tool UI. Load Veeam, AWS Backup, Azure Backup,
// generic job-log, restore-test and asset exports and prove (or disprove) that each
// asset can be recovered from ransomware. The engine runs in a Worker via
// ../ingest/worker.js; the Security Graph is read locally for asset picking and
// related-control findings. No native dialogs; toasts only.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import { wsKey } from "../core/register.js";
import {
  DEFAULTS, TOOL_ID, KINDS, MAP_LABEL, SEV_RANK, CONF_RANK, WEIGHT_KEYS,
  detectFile, findingsToCsv, recoveryToCsv, readinessReport, summaryText, exampleDataset,
} from "./backupready-engine.js?v=20261016t";

const ENGINE = engineUrl("./backupready-engine.js?v=20261016t", import.meta);
const P = "bkr";
const MAP_STORE = "dn_backupready_assetmap";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const fmtBytes = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? Math.round(n / 1024) + " KB" : n + " B");
const confClass = (c) => (c >= 0.8 ? "high" : c >= 0.5 ? "medium" : "low");

const RELATED = [
  { id: "caaudit", label: "Conditional Access Audit", why: "MFA and Conditional Access on administrator and backup-console sign-ins (stolen admin credentials are how backups get deleted)." },
  { id: "privaudit", label: "Privileged Access Audit", why: "Backup administrator and other privileged accounts: standing access, stale admins, shared accounts." },
  { id: "fleetcomply", label: "Endpoint Fleet Compliance", why: "EDR present and healthy on backup servers, proxies and repositories." },
  { id: "fwaudit", label: "Firewall Audit", why: "Network segmentation: backup infrastructure reachable only from where it must be." },
];

const CSS = `
  .bkr-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .bkr-root *{box-sizing:border-box}
  .bkr-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .bkr-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .bkr-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .bkr-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:110ch}
  .bkr-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .bkr-card h2{font-size:.95rem;margin:0 0 10px}
  .bkr-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .bkr-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .bkr-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .bkr-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .bkr-btn.sm{padding:4px 9px;font-size:.76rem}
  .bkr-btn:disabled{opacity:.5;cursor:default}
  .bkr-two{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:14px}
  @media (max-width:900px){.bkr-two{grid-template-columns:minmax(0,1fr)}}
  .bkr-files{display:flex;flex-direction:column;gap:6px;margin-top:12px}
  .bkr-file{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;font-size:.82rem;min-width:0}
  .bkr-file b{overflow-wrap:anywhere;min-width:0}
  .bkr-mut{color:var(--mut,#667085)}
  .bkr-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085);white-space:nowrap}
  .bkr-conf.high{color:#1b7f4d;border-color:#1b7f4d}.bkr-conf.medium{color:#8a6d00;border-color:#8a6d00}.bkr-conf.low{color:#b00020;border-color:#b00020}
  .bkr-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
  .bkr-grp{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 12px;min-width:0}
  .bkr-grp h4{margin:0 0 8px;font-size:.76rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut,#667085)}
  .bkr-fields{display:flex;flex-wrap:wrap;gap:10px 14px}
  .bkr-field{display:flex;flex-direction:column;gap:3px;min-width:0;flex:1 1 140px}
  .bkr-field label{font-size:.76rem;font-weight:600;color:var(--tx,#1a2230)}
  .bkr-field input,.bkr-field select{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:6px 9px;width:100%;max-width:100%}
  .bkr-field small{font-size:.72rem;color:var(--mut,#667085);line-height:1.35}
  .bkr-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .bkr-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:120px;flex:1 1 130px}
  .bkr-kpi b{display:block;font-size:1.25rem;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}
  .bkr-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .bkr-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .bkr-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .bkr-plabel{font-size:.74rem;color:var(--mut,#667085);margin-top:4px;display:none;overflow-wrap:anywhere}
  .bkr-tabs{display:flex;flex-wrap:wrap;gap:6px;border-bottom:1px solid var(--line,#e6e8ee);margin-bottom:12px}
  .bkr-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid transparent;border-bottom:none;background:none;color:var(--mut,#667085);padding:7px 12px;border-radius:8px 8px 0 0;cursor:pointer;margin-bottom:-1px;white-space:nowrap}
  .bkr-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#e6e8ee);background:var(--card,#fff)}
  .bkr-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .bkr-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:640px}
  .bkr-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .bkr-list th.on{color:var(--tx,#1a2230)}
  .bkr-list th.on::after{content:" \\2193";font-size:.7rem}
  .bkr-list th.on.asc::after{content:" \\2191"}
  .bkr-list td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word}
  .bkr-list tr[data-i]{cursor:pointer}
  .bkr-list tr[data-i]:hover,.bkr-list tr.sel{background:var(--bg,#f7f8fb)}
  .bkr-nw{white-space:nowrap;font-variant-numeric:tabular-nums}
  .bkr-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .bkr-pill.critical{background:#7a0012}.bkr-pill.high{background:#b00020}.bkr-pill.medium{background:#b58100}.bkr-pill.low{background:#2552c6}.bkr-pill.info{background:#667085}
  .bkr-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .bkr-st{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em;padding:1px 7px;border-radius:6px;border:1px solid var(--line,#d7dbe3);white-space:nowrap}
  .bkr-st.yes{color:#1b7f4d;border-color:#1b7f4d}.bkr-st.no{color:#b00020;border-color:#b00020}.bkr-st.partial{color:#8a6d00;border-color:#8a6d00}.bkr-st.unknown{color:var(--mut,#667085)}
  .bkr-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .bkr-drawer{margin-top:12px;display:none;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--bg,#f7f8fb);min-width:0}
  .bkr-drawer h3{margin:0;font-size:1rem;overflow-wrap:anywhere}
  .bkr-drawer p{margin:6px 0;overflow-wrap:anywhere}
  .bkr-drawer .bkr-list{background:var(--card,#fff);margin-top:8px}
  .bkr-drawer .bkr-list table{min-width:0}
  .bkr-drawer .bkr-list td,.bkr-drawer .bkr-list th{white-space:nowrap}
  .bkr-skip{font-size:.78rem;color:var(--mut,#667085);margin:8px 0 0;padding-left:18px}
  .bkr-skip li{margin:2px 0;overflow-wrap:anywhere}
  .bkr-filters{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:flex-end;margin-bottom:10px}
  .bkr-filters .bkr-field{flex:0 1 200px}
  .bkr-chart{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px;background:var(--card,#fff);color:var(--tx,#1a2230);margin-bottom:12px}
  .bkr-chart svg{display:block;width:100%;height:200px}
  .bkr-axis{display:flex;justify-content:space-between;gap:8px;font-size:.72rem;color:var(--mut,#667085);margin-top:4px;flex-wrap:wrap}
  .bkr-legend{display:flex;gap:14px;flex-wrap:wrap;font-size:.74rem;color:var(--mut,#667085);margin-top:6px}
  .bkr-sw{display:inline-block;width:12px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
  .bkr-pick{max-height:260px;overflow:auto;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:6px 10px;margin-top:8px}
  .bkr-pick label{display:flex;gap:8px;align-items:flex-start;font-size:.82rem;padding:3px 0;overflow-wrap:anywhere}
  .bkr-rel{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
  .bkr-rel .bkr-grp p{margin:4px 0;font-size:.82rem;overflow-wrap:anywhere}
  .bkr-rel a{color:#2552c6;font-weight:600}
  .bkr-match{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:8px 14px;align-items:center}
  @media (max-width:560px){.bkr-field,.bkr-filters .bkr-field{flex:1 1 100%}.bkr-card{padding:14px}.bkr-grid{grid-template-columns:1fr}.bkr-match{grid-template-columns:1fr}}
`;

const kpi = (v, l) => '<div class="' + P + '-kpi"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const pill = (s) => (s ? '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>" : "");
const st = (v) => '<span class="' + P + "-st " + esc(v || "unknown") + '">' + esc(v || "unknown") + "</span>";
const CRIT_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const sortBy = (rows, key, dir, rank) => rows.slice().sort((a, b) => {
  const x = rank ? (rank[a[key]] ?? -1) : a[key], y = rank ? (rank[b[key]] ?? -1) : b[key];
  const r = typeof x === "number" && typeof y === "number" ? x - y : cmp(String(x == null ? "" : x).toLowerCase(), String(y == null ? "" : y).toLowerCase());
  return dir === "asc" ? r : -r;
});

/** Sortable table: cols = [{key, label, render?, rank?}]. */
function table(cols, rows, sort, onSort, rowKey) {
  const head = cols.map((c) => '<th data-k="' + esc(c.key) + '" class="' + (sort.key === c.key ? "on " + sort.dir : "") + '">' + esc(c.label) + "</th>").join("");
  const sorted = sortBy(rows, sort.key, sort.dir, (cols.find((c) => c.key === sort.key) || {}).rank);
  const body = sorted.map((r) => "<tr" + (rowKey ? ' data-i="' + esc(rowKey(r)) + '"' : "") + ">" + cols.map((c) => "<td>" + (c.render ? c.render(r) : esc(r[c.key] == null ? "" : r[c.key])) + "</td>").join("") + "</tr>").join("");
  const el = document.createElement("div");
  el.className = P + "-list";
  el.innerHTML = "<table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table>";
  el.querySelectorAll("th").forEach((th) => th.addEventListener("click", () => {
    const k = th.dataset.k;
    onSort({ key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" });
  }));
  return el;
}

/** Plain table of evidence rows (union of keys). */
function rowsTable(rows) {
  if (!rows || !rows.length) return '<p class="' + P + '-note">No rows.</p>';
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k) && r[k] !== "" && r[k] != null) keys.push(k);
  const lab = (k) => k.replace(/([A-Z])/g, " $1").toLowerCase();
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(lab(k)) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => "<td>" + esc(r[k] == null ? "" : r[k]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

/** Stacked daily bars: success / warning / failed runs. No library. */
function chartSvg(days) {
  const n = days.length, W = 1000, H = 200, pad = 4;
  let max = 1;
  for (const d of days) max = Math.max(max, d.success + d.warning + d.failed);
  const bw = W / Math.max(n, 1);
  const y = (v) => ((v / max) * (H - 2 * pad));
  let out = "";
  days.forEach((d, i) => {
    const x = (i * bw + bw * 0.12).toFixed(1), w = Math.max(bw * 0.76, 1).toFixed(1);
    let base = H - pad;
    for (const [k, col] of [["success", "#1b7f4d"], ["warning", "#b58100"], ["failed", "#b00020"]]) {
      if (!d[k]) continue;
      const h = y(d[k]);
      base -= h;
      out += '<rect x="' + x + '" y="' + base.toFixed(1) + '" width="' + w + '" height="' + h.toFixed(1) + '" fill="' + col + '"></rect>';
    }
    out += '<rect x="' + (i * bw).toFixed(1) + '" y="0" width="' + bw.toFixed(1) + '" height="' + H + '" fill="transparent"><title>' + esc(d.date + ": " + d.success + " success, " + d.warning + " warning, " + d.failed + " failed") + "</title></rect>";
  });
  return '<svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" role="img" aria-label="Daily backup runs by result">' +
    '<line x1="0" y1="' + (H - pad) + '" x2="' + W + '" y2="' + (H - pad) + '" stroke="#d7dbe3" stroke-width="1" vector-effect="non-scaling-stroke"></line>' + out + "</svg>";
}

const POLICY = [
  { title: "RPO by criticality (hours)", note: "Policy defaults; an rpo_hours value in the asset list overrides them. Edit to match your business impact analysis.", fields: [["rpoCritical", "Critical"], ["rpoHigh", "High"], ["rpoMedium", "Medium"], ["rpoLow", "Low"]] },
  { title: "RTO by criticality (hours)", note: "Compared with tested restore durations; rto_hours in the asset list or rto_minutes_target in the test log override them.", fields: [["rtoCritical", "Critical"], ["rtoHigh", "High"], ["rtoMedium", "Medium"], ["rtoLow", "Low"]] },
  { title: "Job health", note: "", fields: [["maxConsecutiveFailures", "Consecutive failures at least"], ["minSuccessRate", "Minimum success rate (%)"], ["successWindowDays", "Success-rate window (days)"], ["warningDays", "Warnings ignored longer than (days)"]] },
  { title: "Restore tests and retention", note: "Blank retention fields skip the check. The dwell window is your own planning figure; no industry number is assumed.", fields: [["restoreTestDays", "Restore test window (days)"], ["minRetentionDays", "Minimum retention (days)"], ["dwellDays", "Ransomware dwell window (days)"]] },
  { title: "Readiness score weights", note: "Per asset: pass = full weight, partial = half, fail or unknown = 0; score = weighted share of 100.", fields: WEIGHT_KEYS.map(([, k, l]) => [k, l]) },
];

function policyHtml() {
  const f = ([k, label]) => {
    const d = DEFAULTS[k];
    return '<div class="' + P + '-field"><label for="' + P + "-o-" + k + '">' + esc(label) + '</label><input id="' + P + "-o-" + k + '" data-opt="' + k + '" type="number" min="0" step="any" value="' + esc(d == null ? "" : d) + '"' + (d == null ? ' placeholder="blank = skip"' : "") + "><small>Default " + esc(d == null ? "blank" : d) + "</small></div>";
  };
  return '<div class="' + P + '-grid">' + POLICY.map((g) => '<div class="' + P + '-grp"><h4>' + esc(g.title) + "</h4>" + (g.note ? '<p class="' + P + '-note" style="margin:0 0 8px">' + esc(g.note) + "</p>" : "") + '<div class="' + P + '-fields">' + g.fields.map(f).join("") + "</div></div>").join("") +
    '<div class="' + P + '-grp"><h4>As of</h4><div class="' + P + '-fields"><div class="' + P + '-field"><label for="' + P + '-o-now">As-of date and time (UTC)</label><input id="' + P + '-o-now" type="text" placeholder="2026-10-15T12:00Z"><small>Blank = the newest timestamp in the data. RPO ages and test windows are measured from here.</small></div></div></div></div>';
}

function loadMap() { try { const v = JSON.parse(localStorage.getItem(wsKey(MAP_STORE)) || "{}"); return v && typeof v === "object" ? v : {}; } catch (_) { return {}; } }
function saveMap(m) { try { localStorage.setItem(wsKey(MAP_STORE), JSON.stringify(m)); } catch (_) {} }

/** Mount the tool into main. */
export function renderBackupReady(main) {
  if (!document.getElementById(P + "-css")) {
    const st0 = document.createElement("style"); st0.id = P + "-css"; st0.textContent = CSS; document.head.appendChild(st0);
  }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Backup Readiness</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Prove whether each system can be recovered from ransomware: backed up, inside its RPO, healthy jobs, an immutable copy, a copy in another account or region (or offline), a tested restore inside RTO, and 3-2-1-1-0, with a readiness score you can see the weights of. Mapped to CISA #StopRansomware, NIST CSF 2.0 PR.DS-11, NIST SP 800-53 CP-9 / CP-10, CIS Controls v8 11 and ISO 27001 A.8.13. Runs entirely in your browser. Nothing is uploaded and nothing is fetched; the Security Graph is read from this browser.</p>',
    '<div class="', P, '-two">',
    '<div class="', P, '-card"><h2>1. Backup, restore-test and asset exports</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-note">Accepted: Veeam B&amp;R Get-VBRBackupSession, Get-VBRRestorePoint and Get-VBRBackupRepository exported with Export-Csv; AWS Backup CLI JSON (list-backup-jobs, list-copy-jobs, list-restore-jobs, list-backup-vaults / describe-backup-vault, list-protected-resources, list-recovery-points-by-backup-vault); Azure Backup center jobs and backup instances CSV and vault JSON (az backup vault show); a generic job log (system, job, status, start, end, target, target_type, target_account, target_region, immutable, offline, encrypted, retention_days) for Acronis, Datto, Rubrik, Cohesity, Commvault, Druva and others; a restore-test log (system, tested_at, result, duration_minutes, rto_minutes_target, ...); an asset list (name, type, criticality, owner, rpo_hours, rto_hours, environment). Drop many files or a zip.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div><div id="', P, '-map"></div></div>',
    '<div class="', P, '-card"><h2>2. Assets from the Security Graph (optional)</h2>',
    '<p class="', P, '-note">Pick ASSET entities already in your graph instead of, or in addition to, an asset list file. Criticality, rpo_hours and rto_hours are read from the entity data when present; otherwise the medium policy applies.</p>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-gload" type="button">Load assets from the graph</button><span class="', P, '-note" id="', P, '-gcount"></span></div>',
    '<div id="', P, '-gpick"></div></div>',
    "</div>",
    '<div class="', P, '-card"><h2>3. Policy</h2>', policyHtml(),
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" type="button" disabled>Analyze</button><button class="', P, '-btn" id="', P, '-clear" type="button" disabled>Clear files</button><span class="', P, '-note" id="', P, '-count"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-plabel" id="', P, '-plabel"></div></div>',
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card" id="', P, '-matchcard" style="display:none"><h2>Asset matching</h2><div id="', P, '-match"></div></div>',
    '<div class="', P, '-card" id="', P, '-results" style="display:none"><div class="', P, '-tabs" id="', P, '-tabs"></div><div id="', P, '-pane"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div><ul class="', P, '-skip" id="', P, '-skipped"></ul></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example" type="button">Load example (synthetic)</button><span class="', P, '-note">Two fictional AWS accounts (backup, copy and vault JSON), a Veeam session CSV, a restore-test log and 12 assets.</span></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, running = false;
  let tab = "findings", selFinding = -1;
  let graphAssets = [], graphSel = new Set();
  let assetMap = loadMap();
  const mappings = {};
  const sorts = { findings: { key: "severity", dir: "desc" }, recovery: { key: "criticality", dir: "desc" }, jobs: { key: "rate", dir: "asc" }, restores: { key: "testedAt", dir: "desc" }, rule: { key: "criticality", dir: "desc" }, locations: { key: "name", dir: "asc" } };
  let ffilter = { sev: "", cat: "", q: "" };
  const datasetName = () => (isExample ? "synthetic example" : files.map((f) => f.name).join(", ").slice(0, 200));

  function renderFiles() {
    $("files").innerHTML = files.map((f, i) => {
      const d = f.det;
      return '<div class="' + P + '-file"><b>' + esc(f.name) + '</b><span class="' + P + '-mut">' + esc(fmtBytes(d.bytes)) + (f.fromArchive ? ", from archive" : "") + "</span>" +
        "<span>" + esc(mappings[f.name] && mappings[f.name].kind ? KINDS[mappings[f.name].kind].label + " (chosen)" : d.label) + "</span>" +
        '<span class="' + P + "-conf " + confClass(d.confidence) + '">' + confClass(d.confidence) + " confidence</span>" +
        '<span class="' + P + '-mut">' + esc(d.rows.length) + " record" + (d.rows.length === 1 ? "" : "s") + "</span>" +
        '<button class="' + P + '-btn sm" data-rm="' + i + '" type="button">Remove</button></div>';
    }).join("");
    main.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { files.splice(Number(b.dataset.rm), 1); isExample = false; renderFiles(); }));
    const bytes = files.reduce((n, f) => n + f.det.bytes, 0);
    $("count").textContent = files.length ? files.length + " file" + (files.length === 1 ? "" : "s") + ", " + fmtBytes(bytes) + (isExample ? " (synthetic example)" : "") + (graphSel.size ? " + " + graphSel.size + " graph asset" + (graphSel.size === 1 ? "" : "s") : "") : "";
    $("run").disabled = (!files.length && !graphSel.size) || running;
    $("clear").disabled = !files.length;
    renderMapping();
  }

  function renderMapping() {
    const lowc = files.filter((f) => f.det.format === "csv" && (f.det.confidence < 0.8 || f.det.kind === "unknown"));
    const box = $("map");
    if (!lowc.length) { box.innerHTML = ""; return; }
    box.innerHTML = lowc.map((f, fi) => {
      const m = mappings[f.name] || (mappings[f.name] = { cols: {} });
      const kind = m.kind || (KINDS[f.det.kind] ? f.det.kind : "generic-jobs");
      const spec = KINDS[kind];
      const sel = (k) => {
        const cur = m.cols[k] !== undefined ? m.cols[k] : (kind === f.det.kind ? f.det.cols[k] : "") || "";
        const req = spec.required.includes(k);
        return '<div class="' + P + '-field"><label for="' + P + "-map-" + fi + "-" + k + '">' + esc(MAP_LABEL[k] || k) + (req ? " (required)" : "") + '</label><select id="' + P + "-map-" + fi + "-" + k + '" data-f="' + esc(f.name) + '" data-col="' + k + '"><option value="">(not present)</option>' +
          f.det.headers.map((h) => '<option value="' + esc(h) + '"' + (cur === h ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>";
      };
      return '<div class="' + P + '-grp" style="margin-top:12px"><h4>Column mapping: ' + esc(f.name) + '</h4><p class="' + P + '-note">The layout was not recognised with high confidence. Pick what the file is and map its columns; checks whose column is not mapped are skipped and listed, never guessed.</p>' +
        '<div class="' + P + '-fields" style="margin-top:8px"><div class="' + P + '-field" style="flex:1 1 100%"><label for="' + P + "-kind-" + fi + '">File contains</label><select id="' + P + "-kind-" + fi + '" data-kind="' + esc(f.name) + '">' +
        Object.keys(KINDS).map((k) => '<option value="' + k + '"' + (k === kind ? " selected" : "") + ">" + esc(KINDS[k].label) + "</option>").join("") + "</select></div>" +
        Object.keys(spec.cols).map(sel).join("") + "</div></div>";
    }).join("");
    box.querySelectorAll("[data-col]").forEach((s) => s.addEventListener("change", () => { const m = mappings[s.dataset.f]; if (!m.kind) m.kind = currentKind(s.dataset.f); m.cols[s.dataset.col] = s.value; }));
    box.querySelectorAll("[data-kind]").forEach((s) => s.addEventListener("change", () => { mappings[s.dataset.kind] = { kind: s.value, cols: {} }; renderMapping(); }));
  }
  const currentKind = (name) => { const f = files.find((x) => x.name === name); return mappings[name] && mappings[name].kind || (f && KINDS[f.det.kind] ? f.det.kind : "generic-jobs"); };

  function addFile(name, text, fromArchive) {
    const det = detectFile(name, text);
    if (det.kind === "empty") { toast(name + " is empty", "warning"); return false; }
    if (det.kind === "unknown" && det.format !== "csv") { toast(name + " is not a recognised backup, restore-test or asset export", "warning"); return false; }
    const entry = { name, text, det, fromArchive: !!fromArchive };
    const idx = files.findIndex((x) => x.name === name);
    if (idx >= 0) files[idx] = entry; else files.push(entry);
    return true;
  }
  mountDropzone($("drop"), {
    maxBytes: 256 * 1024 * 1024, maxFiles: 50, multiple: true, unpack: true, label: "Drop exports or a zip here, paste, or browse",
    onFiles: async (list, info) => {
      let added = 0;
      if (isExample) { files = []; isExample = false; $("o-now").value = ""; }
      for (const f of list) { try { if (addFile(f.name, await f.text(), f.fromArchive)) added++; } catch (e) { toast("Could not read " + f.name + ": " + ((e && e.message) || e), "error"); } }
      const sk = (info && info.skipped) || [];
      if (sk.length) toast(sk.length + " file" + (sk.length === 1 ? "" : "s") + " skipped: " + sk.slice(0, 3).map((s) => s.name + " (" + s.reason + ")").join("; "), "warning");
      if (added) toast("Loaded " + added + " file" + (added === 1 ? "" : "s"), "success");
      result = null; renderFiles();
    },
  });

  $("clear").addEventListener("click", () => { if (isExample) $("o-now").value = ""; files = []; isExample = false; result = null; renderFiles(); });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    files = []; isExample = true; result = null;
    for (const f of ex.files) addFile(f.name, f.text, false);
    $("o-now").value = ex.now;
    renderFiles();
    toast("Synthetic example loaded (as of " + ex.now + "). Click Analyze.", "info");
  });

  // ---- Security Graph assets ---------------------------------------------------
  $("gload").addEventListener("click", async () => {
    try {
      const sg = await import("/js/security-graph.js");
      graphAssets = (sg.listEntities({ type: "ASSET" }) || []).filter((e) => !(e.tags || []).includes("sample"))
        .map((e) => { const d = e.data || {}; return { id: e.id, name: e.name, criticality: d.criticality || d.tier || "", type: d.type || d.assetType || "", owner: d.owner || "", rpoHours: d.rpoHours ?? d.rpo_hours ?? null, rtoHours: d.rtoHours ?? d.rto_hours ?? null, environment: d.environment || "" }; })
        .sort((a, b) => cmp(String(a.name).toLowerCase(), String(b.name).toLowerCase()));
      renderGraphPick();
      $("gcount").textContent = graphAssets.length + " ASSET entit" + (graphAssets.length === 1 ? "y" : "ies") + " in the graph (sample data excluded)";
    } catch (e) { toast("Could not read the Security Graph: " + ((e && e.message) || e), "error"); }
  });
  function renderGraphPick() {
    const box = $("gpick");
    if (!graphAssets.length) { box.innerHTML = '<p class="' + P + '-note">No ASSET entities in the graph.</p>'; return; }
    box.innerHTML = '<div class="' + P + '-row" style="margin-top:6px"><button class="' + P + '-btn sm" data-ga="all" type="button">Select all</button><button class="' + P + '-btn sm" data-ga="none" type="button">Select none</button></div><div class="' + P + '-pick">' +
      graphAssets.slice(0, 2000).map((a, i) => '<label><input type="checkbox" data-g="' + i + '"' + (graphSel.has(a.id) ? " checked" : "") + "><span>" + esc(a.name) + (a.criticality ? ' <span class="' + P + '-mut">(' + esc(a.criticality) + ")</span>" : "") + "</span></label>").join("") + "</div>";
    box.querySelectorAll("[data-g]").forEach((c) => c.addEventListener("change", () => { const a = graphAssets[Number(c.dataset.g)]; if (c.checked) graphSel.add(a.id); else graphSel.delete(a.id); renderFiles(); }));
    box.querySelectorAll("[data-ga]").forEach((b) => b.addEventListener("click", () => { graphSel = b.dataset.ga === "all" ? new Set(graphAssets.map((a) => a.id)) : new Set(); renderGraphPick(); renderFiles(); }));
  }

  const opts = () => {
    const o = { mappings: {}, assetMap: { ...assetMap } };
    for (const [n, m] of Object.entries(mappings)) if (m.kind || Object.keys(m.cols).length) o.mappings[n] = { kind: m.kind || currentKind(n), cols: { ...m.cols } };
    main.querySelectorAll("[data-opt]").forEach((el) => {
      const k = el.dataset.opt;
      if (el.value.trim() === "") { if (DEFAULTS[k] == null) o[k] = null; return; }
      const n = Number(el.value);
      if (Number.isFinite(n) && n >= 0) o[k] = n;
    });
    const nowv = $("o-now").value.trim();
    if (nowv) o.now = nowv;
    return o;
  };

  async function run() {
    if ((!files.length && !graphSel.size) || running) return;
    running = true;
    const prog = $("prog"), bar = prog.firstElementChild, pl = $("plabel");
    prog.style.display = "block"; pl.style.display = "block"; bar.style.width = "0%"; pl.textContent = "starting the worker"; $("run").disabled = true;
    const t0 = performance.now();
    try {
      const ds = { files: files.map((f) => ({ name: f.name, text: f.text })), assets: graphAssets.filter((a) => graphSel.has(a.id)) };
      result = await runInWorker(ENGINE, "analyze", [ds, opts()], {
        timeoutMs: 15 * 60 * 1000,
        onProgress: (i, n, label) => { bar.style.width = (n ? Math.min(100, Math.round((i / n) * 100)) : 0) + "%"; pl.textContent = label || ""; },
      });
      selFinding = -1; ffilter = { sev: "", cat: "", q: "" };
      render(result);
      toast(result.findings.length + " finding" + (result.findings.length === 1 ? "" : "s") + " across " + result.summary.assets + " assets (" + ((performance.now() - t0) / 1000).toFixed(1) + " s)", "success");
    } catch (e) {
      toast("Analysis failed: " + ((e && e.message) || e), "error");
    } finally {
      running = false;
      prog.style.display = "none"; pl.style.display = "none"; $("run").disabled = !files.length && !graphSel.size;
    }
  }
  $("run").addEventListener("click", run);

  function render(r) {
    const s = r.summary;
    $("kpis").innerHTML = kpi(s.assets, s.assetListGiven ? "assets" : "assets (backup objects)") + kpi(s.protected, "protected") + kpi(s.rpoBreaches, "RPO breaches") +
      kpi(s.immutableCriticalPct == null ? "n/a" : s.immutableCriticalPct + "%", "immutable coverage of critical") + kpi(s.restoreTestsInWindow, "restore tests in window") +
      kpi(s.readiness == null ? "n/a" : s.readiness + " / 100", "readiness score") + kpi(s.asOf ? s.asOf.slice(0, 16).replace("T", " ") : "n/a", "as of (UTC)");
    $("skipped").innerHTML = r.skipped.length ? "<li><b>Skipped or limited checks</b></li>" + r.skipped.map((k) => "<li>" + esc(k.check) + ": " + esc(k.reason) + "</li>").join("") : "";
    $("results").style.display = "";
    $("drawer").style.display = "none";
    renderMatch(r);
    renderTabs(r);
    renderExports(r);
  }

  // ---- asset matching ----------------------------------------------------------
  function renderMatch(r) {
    const card = $("matchcard"), box = $("match");
    if (!r.summary.assetListGiven) { card.style.display = "none"; return; }
    card.style.display = "";
    const um = r.tables.unmatchedAssets, uo = r.tables.unmatchedSystems;
    const systems = r.tables.systems.slice().sort((a, b) => cmp(a.name.toLowerCase(), b.name.toLowerCase()));
    const manual = Object.entries(assetMap).filter(([, v]) => Array.isArray(v) && v.length);
    box.innerHTML = '<p class="' + P + '-note">Assets match backup objects by normalized name, AWS resource id or Name tag, Azure instance name, Veeam VM or job name. ' + um.length + " asset(s) without a backup object; " + uo.length + " backup object(s) without an asset. Manual matches are kept in this browser for the current workspace.</p>" +
      (um.length ? '<div class="' + P + '-match" style="margin-top:10px">' + um.map((a, i) => '<div><b>' + esc(a.asset) + '</b> <span class="' + P + '-mut">(' + esc(a.criticality) + ')</span></div><div class="' + P + '-field"><label for="' + P + "-mm-" + i + '">Backup object</label><select id="' + P + "-mm-" + i + '" data-ma="' + esc(a.asset) + '"><option value="">(no backup object)</option>' +
        systems.map((s) => '<option value="' + esc(s.key) + '">' + esc((s.arn || s.name) + (s.assets ? " [" + s.assets + "]" : "") + " - " + s.sources) + "</option>").join("") + "</select></div>").join("") + "</div>" : "") +
      (uo.length ? '<p class="' + P + '-note" style="margin-top:10px"><b>Backup objects without an asset:</b> ' + uo.map((o) => esc(o.name)).join(", ") + "</p>" : "") +
      (manual.length ? '<p class="' + P + '-note" style="margin-top:10px"><b>Manual matches:</b> ' + manual.map(([k, v]) => esc(k + " -> " + v.join(", "))).join("; ") + "</p>" : "") +
      '<div class="' + P + '-row">' + (um.length ? '<button class="' + P + '-btn pri sm" id="' + P + '-mapply" type="button">Save matches and re-run</button>' : "") + (manual.length ? '<button class="' + P + '-btn sm" id="' + P + '-mclear" type="button">Clear manual matches</button>' : "") + "</div>";
    const ap = $("mapply");
    if (ap) ap.addEventListener("click", () => {
      let n = 0;
      box.querySelectorAll("[data-ma]").forEach((s) => { if (s.value) { assetMap[s.dataset.ma] = [s.value]; n++; } });
      saveMap(assetMap);
      if (!n) { toast("No matches selected", "warning"); return; }
      run();
    });
    const cl = $("mclear");
    if (cl) cl.addEventListener("click", async () => {
      const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Clear manual matches?", "All manual asset-to-backup matches for this workspace are removed. Name matches are not affected.", { danger: true, submitText: "Clear" }) : true;
      if (!ok) return;
      assetMap = {}; saveMap(assetMap); run();
    });
  }

  // ---- tabs ----------------------------------------------------------------------
  function renderTabs(r) {
    const t = r.tables;
    const tabs = [["findings", "Findings (" + r.findings.length + ")"], ["recovery", "Assets (" + t.recovery.length + ")"], ["jobs", "Jobs (" + t.jobs.length + ")"], ["restores", "Restore tests (" + t.restores.length + ")"], ["rule", "3-2-1-1-0"], ["locations", "Vaults and repositories (" + t.locations.length + ")"], ["related", "Related controls"]];
    $("tabs").innerHTML = tabs.map(([k, l]) => '<button type="button" class="' + P + "-tab" + (tab === k ? " on" : "") + '" data-tab="' + k + '">' + esc(l) + "</button>").join("");
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; $("drawer").style.display = "none"; selFinding = -1; renderTabs(r); }));
    const pane = $("pane");
    pane.innerHTML = "";
    const tbl = (name, cols, rows, empty, note) => {
      if (note) { const p = document.createElement("p"); p.className = P + "-note"; p.style.margin = "0 0 8px"; p.innerHTML = note; pane.appendChild(p); }
      pane.appendChild(rows.length ? table(cols, rows, sorts[name], (s) => { sorts[name] = s; renderTabs(r); }) : emptyEl(empty));
    };
    if (tab === "findings") drawFindings(r);
    else if (tab === "recovery") tbl("recovery", REC_COLS, t.recovery, "No assets.", "Recovery confidence per asset. Score weights: " + esc(t.weights.map((w) => w.label + " " + w.weight).join(", ")) + ". Unknown means the loaded exports do not show it either way, and scores 0.");
    else if (tab === "jobs") drawJobs(r);
    else if (tab === "restores") tbl("restores", RES_COLS, t.restores, "No restore tests or restore jobs loaded.", "From the restore-test log, AWS Backup restore jobs (mapped to the source through the recovery point) and Azure restore jobs. Duration is restore time only.");
    else if (tab === "rule") tbl("rule", RULE_COLS, t.rule, "No assets.", "3 copies (production counts as one), 2 media types, 1 offsite (other account or region, or offline), 1 immutable or offline, 0 errors on the latest restore verification. Unknown = not shown in the loaded data.");
    else if (tab === "locations") tbl("locations", LOC_COLS, t.locations, "No backup vaults, repositories or targets in the data.");
    else if (tab === "related") drawRelated();
  }
  const emptyEl = (t) => { const d = document.createElement("div"); d.className = P + "-empty"; d.textContent = t; return d; };

  const FIND_COLS = [
    { key: "severity", label: "Severity", rank: SEV_RANK, render: (f) => pill(f.severity) },
    { key: "title", label: "Finding", render: (f) => "<b>" + esc(f.title) + "</b>" + (f.subject ? '<div class="' + P + '-mut">' + esc(f.subject) + "</div>" : "") },
    { key: "category", label: "Check" },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
    { key: "controls", label: "Controls", render: (f) => f.controls.slice(0, 4).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + (f.controls.length > 4 ? '<span class="' + P + '-chip">+' + (f.controls.length - 4) + "</span>" : "") },
    { key: "evidenceCount", label: "Evidence" },
  ];
  const REC_COLS = [
    { key: "asset", label: "Asset", render: (x) => "<b>" + esc(x.asset) + "</b>" + (x.objects ? '<div class="' + P + '-mut">' + esc(x.objects.length > 90 ? x.objects.slice(0, 90) + "..." : x.objects) + (x.matched === "manual" ? " (manual)" : "") + "</div>" : '<div class="' + P + '-mut">no backup object</div>') },
    { key: "criticality", label: "Criticality", rank: CRIT_RANK },
    { key: "lastGood", label: "Last good backup", render: (x) => '<span class="' + P + '-nw">' + esc(x.lastGood ? x.lastGood.slice(0, 16).replace("T", " ") : "none") + "</span>" + (x.ageHours != null ? '<div class="' + P + '-mut">' + esc(x.ageHours) + " h old</div>" : "") },
    { key: "rpoMet", label: "RPO met", render: (x) => st(x.rpoMet) + '<div class="' + P + '-mut">RPO ' + esc(x.rpoHours) + " h</div>" },
    { key: "copies", label: "Copies" },
    { key: "immutable", label: "Immutable", render: (x) => st(x.immutable) },
    { key: "offsite", label: "Offsite", render: (x) => st(x.offsite) },
    { key: "lastTest", label: "Last restore test", render: (x) => (x.lastTest ? '<span class="' + P + '-nw">' + esc(x.lastTest.slice(0, 10)) + "</span> " + st(x.lastTestResult === "pass" ? "yes" : "no").replace(/>(yes|no)</, ">" + esc(x.lastTestResult) + "<") : st(x.restoreTested)) },
    { key: "rtoMet", label: "RTO met", render: (x) => st(x.rtoMet) },
    { key: "score", label: "Score", render: (x) => "<b>" + esc(x.score) + "</b>" },
  ];
  const RES_COLS = [
    { key: "system", label: "System" }, { key: "asset", label: "Asset" },
    { key: "testedAt", label: "Tested", render: (x) => '<span class="' + P + '-nw">' + esc(x.testedAt.slice(0, 16).replace("T", " ")) + "</span>" },
    { key: "result", label: "Result", render: (x) => st(x.result === "pass" ? "yes" : x.result === "partial" ? "partial" : "no").replace(/>(yes|no|partial)</, ">" + esc(x.result) + "<") },
    { key: "durationMin", label: "Duration (min)" }, { key: "rtoMin", label: "RTO (min)" }, { key: "pointAgeHours", label: "Point age (h)" },
    { key: "source", label: "Source" }, { key: "notes", label: "Notes" },
  ];
  const RULE_COLS = [
    { key: "asset", label: "Asset", render: (x) => "<b>" + esc(x.asset) + "</b>" + (x.locations ? '<div class="' + P + '-mut">' + esc(x.locations) + "</div>" : "") },
    { key: "criticality", label: "Criticality", rank: CRIT_RANK },
    { key: "copies", label: "3 copies", render: (x) => st(x.copiesMet) + ' <span class="' + P + '-mut">' + esc(x.copies) + "</span>" },
    { key: "media", label: "2 media", render: (x) => st(x.media) + (x.mediaTypes ? ' <span class="' + P + '-mut">' + esc(x.mediaTypes) + "</span>" : "") },
    { key: "offsite", label: "1 offsite", render: (x) => st(x.offsite) },
    { key: "immutableOrOffline", label: "1 immutable / offline", render: (x) => st(x.immutableOrOffline) },
    { key: "zeroErrors", label: "0 errors", render: (x) => st(x.zeroErrors) },
  ];
  const LOC_COLS = [
    { key: "name", label: "Vault / repository", render: (x) => "<b>" + esc(x.name) + '</b><div class="' + P + '-mut">' + esc(x.kind) + "</div>" },
    { key: "account", label: "Account" }, { key: "region", label: "Region" }, { key: "targetType", label: "Media" },
    { key: "immutable", label: "Immutable", render: (x) => st(x.immutable) + (x.immutMode ? ' <span class="' + P + '-mut">' + esc(x.immutMode) + "</span>" : "") },
    { key: "deletionProtection", label: "Deletion protection", render: (x) => st(x.deletionProtection) },
    { key: "encrypted", label: "Encrypted", render: (x) => st(x.encrypted) },
    { key: "propertiesLoaded", label: "Properties loaded" }, { key: "objects", label: "Objects" },
  ];
  const JOB_COLS = [
    { key: "job", label: "Job", render: (x) => "<b>" + esc(x.job) + "</b>" + (x.assets ? '<div class="' + P + '-mut">' + esc(x.assets) + "</div>" : "") },
    { key: "kind", label: "Kind" }, { key: "windowRuns", label: "Runs in window" },
    { key: "rate", label: "Success %", render: (x) => esc(x.rate == null ? "-" : x.rate) },
    { key: "failed", label: "Failed" }, { key: "warning", label: "Warning" }, { key: "streak", label: "Failures in a row" },
    { key: "lastStatus", label: "Last", render: (x) => esc(x.lastStatus || "") + '<div class="' + P + '-mut ' + P + '-nw">' + esc(x.lastTime ? x.lastTime.slice(0, 16).replace("T", " ") : "") + "</div>" },
  ];

  function drawFindings(r) {
    const pane = $("pane");
    if (!r.findings.length) { pane.appendChild(emptyEl("No findings for the current policy. Check the skipped list below for checks that could not run.")); return; }
    const cats = [...new Set(r.findings.map((f) => f.category))].sort();
    const fl = document.createElement("div");
    fl.className = P + "-filters";
    fl.innerHTML = '<div class="' + P + '-field"><label for="' + P + '-fs">Severity</label><select id="' + P + '-fs" data-ff="sev"><option value="">All</option>' + ["critical", "high", "medium", "low", "info"].map((s) => '<option value="' + s + '"' + (ffilter.sev === s ? " selected" : "") + ">" + s + "</option>").join("") + "</select></div>" +
      '<div class="' + P + '-field"><label for="' + P + '-fc">Check</label><select id="' + P + '-fc" data-ff="cat"><option value="">All</option>' + cats.map((c) => '<option value="' + esc(c) + '"' + (ffilter.cat === c ? " selected" : "") + ">" + esc(c) + "</option>").join("") + "</select></div>" +
      '<div class="' + P + '-field"><label for="' + P + '-fq">Search</label><input id="' + P + '-fq" data-ff="q" type="search" placeholder="asset, vault, job" value="' + esc(ffilter.q) + '"></div>';
    pane.appendChild(fl);
    const box = document.createElement("div");
    pane.appendChild(box);
    const draw = () => {
      const q = ffilter.q.trim().toLowerCase();
      const rows = r.findings.map((f, i) => ({ ...f, i })).filter((f) => (!ffilter.sev || f.severity === ffilter.sev) && (!ffilter.cat || f.category === ffilter.cat) &&
        (!q || [f.title, f.subject, f.description].some((v) => String(v || "").toLowerCase().includes(q))));
      box.innerHTML = "";
      if (!rows.length) { box.appendChild(emptyEl("No findings match the filters.")); return; }
      const t = table(FIND_COLS, rows, sorts.findings, (s) => { sorts.findings = s; draw(); }, (f) => f.i);
      t.querySelectorAll("tr[data-i]").forEach((tr) => { if (Number(tr.dataset.i) === selFinding) tr.classList.add("sel"); tr.addEventListener("click", () => { selFinding = Number(tr.dataset.i); draw(); showFinding(r.findings[selFinding]); }); });
      box.appendChild(t);
    };
    fl.querySelectorAll("[data-ff]").forEach((el) => el.addEventListener("input", () => { ffilter[el.dataset.ff] = el.value; draw(); }));
    draw();
  }

  function showFinding(f) {
    const d = $("drawer");
    if (!f) { d.style.display = "none"; return; }
    d.style.display = "block";
    d.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + pill(f.severity) + " " + esc(f.title) + '</h3><button class="' + P + '-btn sm" data-close type="button">Close</button></div>' +
      "<p>" + esc(f.description) + "</p><p><b>Recommendation:</b> " + esc(f.recommendation) + "</p>" +
      "<p><b>Confidence:</b> " + esc(f.confidence) + " &middot; <b>Check:</b> " + esc(f.category) + (f.assets.length ? " &middot; <b>Assets:</b> " + esc(f.assets.map((a) => a.name).join(", ")) : "") + "</p>" +
      "<p>" + f.controls.map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</p>" +
      "<p><b>Evidence</b> (" + f.evidence.length + " of " + f.evidenceCount + " rows)</p>" + rowsTable(f.evidence) +
      '<div class="' + P + '-row"><button class="' + P + '-btn sm" data-ev type="button">Export evidence CSV</button></div>';
    d.querySelector("[data-close]").addEventListener("click", () => { d.style.display = "none"; selFinding = -1; renderTabs(result); });
    d.querySelector("[data-ev]").addEventListener("click", () => {
      const keys = []; for (const e of f.evidence) for (const k of Object.keys(e)) if (!keys.includes(k)) keys.push(k);
      const q = (v) => { let s = v == null ? "" : String(v); if (/^[=+@\t\r]/.test(s) || /^-[^\d]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
      download(TOOL_ID + "-evidence-" + fileStamp() + ".csv", [keys.join(","), ...f.evidence.map((e) => keys.map((k) => q(e[k])).join(","))].join("\n") + "\n", "text/csv");
    });
    d.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  function drawJobs(r) {
    const pane = $("pane"), days = r.tables.daily;
    if (days.length) {
      const el = document.createElement("div");
      el.className = P + "-chart";
      el.innerHTML = chartSvg(days) + '<div class="' + P + '-axis"><span>' + esc(days[0].date) + "</span><span>" + esc(days.reduce((n, d) => n + d.success + d.warning + d.failed, 0)) + " runs</span><span>" + esc(days[days.length - 1].date) + "</span></div>" +
        '<div class="' + P + '-legend"><span><i class="' + P + '-sw" style="background:#1b7f4d"></i>success</span><span><i class="' + P + '-sw" style="background:#b58100"></i>warning</span><span><i class="' + P + '-sw" style="background:#b00020"></i>failed</span><span>UTC days, all jobs; hover a day for counts</span></div>';
      pane.appendChild(el);
    }
    pane.appendChild(r.tables.jobs.length ? table(JOB_COLS, r.tables.jobs, sorts.jobs, (s) => { sorts.jobs = s; renderTabs(r); }) : emptyEl("No job run history in the data."));
  }

  async function drawRelated() {
    const pane = $("pane");
    const box = document.createElement("div");
    box.innerHTML = '<p class="' + P + '-note" style="margin:0 0 8px">Controls that decide whether an attacker can reach the backups. Read from Security Graph findings written by these tools in this workspace (sample data excluded). This tab does not change the score.</p><div class="' + P + '-rel" id="' + P + '-rel">Reading the Security Graph...</div>';
    pane.appendChild(box);
    let all = [];
    try { const sg = await import("/js/security-graph.js"); all = (sg.listEntities({ type: "FINDING" }) || []).filter((e) => !(e.tags || []).includes("sample")); }
    catch (e) { const el = box.querySelector("#" + P + "-rel"); if (el) el.textContent = "Could not read the Security Graph: " + ((e && e.message) || e); return; }
    const el = box.querySelector("#" + P + "-rel");
    if (!el) return;
    const q = location.search || "";
    el.innerHTML = RELATED.map((t) => {
      const fs = all.filter((e) => (e.data && e.data.tool === t.id) || (e.tags || []).includes(t.id)).filter((e) => !/resolved|closed/.test(e.status || ""));
      fs.sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || cmp(String(a.name), String(b.name)));
      const hi = fs.filter((e) => e.severity === "critical" || e.severity === "high").length;
      const backupRel = fs.filter((e) => /backup|veeam|vault|recovery|restore/i.test(e.name + " " + ((e.data && e.data.description) || ""))).length;
      const link = '<a href="/' + esc(t.id) + esc(q) + '">Open ' + esc(t.label) + "</a>";
      return '<div class="' + P + '-grp"><h4>' + esc(t.label) + "</h4><p>" + esc(t.why) + "</p>" +
        (fs.length ? "<p>" + st(hi ? "no" : "partial").replace(/>(no|partial)</, ">" + esc(fs.length) + " open<") + " " + esc(hi + " critical/high" + (backupRel ? ", " + backupRel + " mention backup" : "")) + "</p><ul class=\"" + P + '-skip" style="padding-left:16px">' + fs.slice(0, 5).map((e) => "<li>" + pill(e.severity) + " " + esc(String(e.name).replace(/\s*\([a-z0-9]+:[^)]*\)\s*$/i, "")) + "</li>").join("") + "</ul>"
          : "<p>" + st("unknown").replace(">unknown<", ">not assessed<") + " no findings from this tool in the graph - run " + esc(t.label) + ".</p>") +
        "<p>" + link + "</p></div>";
    }).join("");
  }

  function renderExports(r) {
    const ex = $("exports");
    ex.innerHTML = ["csv:Findings CSV", "json:JSON", "txt:Summary TXT", "rec:Recovery confidence CSV", "rep:Readiness report TXT"].map((x) => { const [k, l] = x.split(":"); return '<button class="' + P + '-btn" type="button" data-x="' + k + '">' + l + "</button>"; }).join("");
    const stamp = fileStamp();
    const on = (k, fn) => ex.querySelector('[data-x="' + k + '"]').addEventListener("click", fn);
    on("csv", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    on("json", () => download(TOOL_ID + "-" + stamp + ".json", toJson({ ...r, summaryStats: summarize(r.findings) }), "application/json"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r), "text/plain"));
    on("rec", () => download(TOOL_ID + "-recovery-confidence-" + stamp + ".csv", recoveryToCsv(r.tables.recovery), "text/csv"));
    on("rep", () => download(TOOL_ID + "-readiness-report-" + stamp + ".txt", readinessReport(r), "text/plain"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: datasetName() });
  }

  renderFiles();
}
