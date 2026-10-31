// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Cloud Audit Log Hunter (cloudtrail): Deck tool UI. Drop AWS CloudTrail, Azure Activity Log,
// GCP Cloud Audit Log and Microsoft 365 Unified Audit Log exports (zip / gz unpacked locally);
// the engine normalises them and runs every rule inside a Worker. The only network request is
// the optional same-origin mirrored feed /data/feeds/malicious-ips.json. No native dialogs.
//
//   renderCloudTrail(main) -> void

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, COLUMNS, RULES, PLATFORM_LABEL, SEV_RANK, CONF_RANK, detectFile,
  findingsToCsv, iocsToCsv, principalsToCsv, ipsToCsv, timelineToCsv, queriesText, summaryText, exampleDataset,
} from "./cloudtrail-engine.js?v=20261029c";

const ENGINE = engineUrl("./cloudtrail-engine.js?v=20261029c", import.meta);
const P = "ctl";
const FEED_URL = "/data/feeds/malicious-ips.json";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const fmtBytes = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? Math.round(n / 1024) + " KB" : n + " B");
const fmtNum = (n) => Number(n || 0).toLocaleString("en-US");

const CSS = `
  .ctl-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .ctl-root *{box-sizing:border-box}
  .ctl-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .ctl-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .ctl-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .ctl-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:95ch}
  .ctl-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .ctl-card h2{font-size:.95rem;margin:0 0 10px}
  .ctl-card h3{font-size:.8rem;margin:14px 0 8px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#667085)}
  .ctl-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .ctl-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .ctl-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .ctl-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .ctl-btn.sm{padding:4px 9px;font-size:.76rem}
  .ctl-btn:disabled{opacity:.5;cursor:default}
  .ctl-files{display:flex;flex-direction:column;gap:6px;margin-top:12px}
  .ctl-file{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;font-size:.82rem;min-width:0}
  .ctl-file b{overflow-wrap:anywhere;min-width:0}
  .ctl-mut{color:var(--mut,#667085)}
  .ctl-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085);white-space:nowrap}
  .ctl-conf.high{color:#1b7f4d;border-color:#1b7f4d}.ctl-conf.medium{color:#8a6d00;border-color:#8a6d00}.ctl-conf.low{color:#b00020;border-color:#b00020}
  .ctl-plat{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
  .ctl-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
  .ctl-grp{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 12px;min-width:0}
  .ctl-grp h4{margin:0 0 8px;font-size:.76rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut,#667085)}
  .ctl-fields{display:flex;flex-wrap:wrap;gap:10px 14px}
  .ctl-field{display:flex;flex-direction:column;gap:3px;min-width:0;flex:1 1 140px}
  .ctl-field.wide{flex:1 1 100%}
  .ctl-field label{font-size:.76rem;font-weight:600;color:var(--tx,#1a2230)}
  .ctl-field input,.ctl-field select,.ctl-field textarea{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:6px 9px;width:100%;max-width:100%}
  .ctl-field textarea{min-height:64px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem}
  .ctl-field small{font-size:.72rem;color:var(--mut,#667085);line-height:1.35}
  .ctl-check{display:flex;gap:8px;align-items:flex-start;font-size:.84rem;min-width:0}
  .ctl-check input{margin-top:3px;flex:none}
  .ctl-check span{min-width:0;overflow-wrap:anywhere}
  .ctl-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .ctl-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:120px;flex:1 1 120px}
  .ctl-kpi b{display:block;font-size:1.3rem;overflow-wrap:anywhere}
  .ctl-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .ctl-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .ctl-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .ctl-plabel{font-size:.74rem;color:var(--mut,#667085);margin-top:4px;display:none;overflow-wrap:anywhere}
  .ctl-tabs{display:flex;flex-wrap:wrap;gap:6px;border-bottom:1px solid var(--line,#e6e8ee);margin-bottom:12px}
  .ctl-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid transparent;border-bottom:none;background:none;color:var(--mut,#667085);padding:7px 12px;border-radius:8px 8px 0 0;cursor:pointer;margin-bottom:-1px}
  .ctl-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#e6e8ee);background:var(--card,#fff)}
  .ctl-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .ctl-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:640px}
  .ctl-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .ctl-list th.on{color:var(--tx,#1a2230)}
  .ctl-list th.on::after{content:" \\2193";font-size:.7rem}
  .ctl-list th.on.asc::after{content:" \\2191"}
  .ctl-nw{white-space:nowrap}
  .ctl-list td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word;word-break:normal}
  .ctl-list tr[data-i]{cursor:pointer}
  .ctl-list tr[data-i]:hover,.ctl-list tr.sel{background:var(--bg,#f7f8fb)}
  .ctl-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .ctl-pill.critical{background:#7a0012}.ctl-pill.high{background:#b00020}.ctl-pill.medium{background:#b58100}.ctl-pill.low{background:#2552c6}.ctl-pill.info{background:#667085}
  .ctl-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .ctl-chip.fired{color:#b00020;border-color:#b00020}.ctl-chip.skipped{color:#8a6d00;border-color:#8a6d00}.ctl-chip.silent{color:#1b7f4d;border-color:#1b7f4d}
  .ctl-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .ctl-drawer{margin-top:12px;display:none;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--bg,#f7f8fb);min-width:0}
  .ctl-drawer h3{margin:0;font-size:1rem;text-transform:none;letter-spacing:0;color:var(--tx,#1a2230);overflow-wrap:anywhere}
  .ctl-drawer p{margin:6px 0;overflow-wrap:anywhere}
  .ctl-drawer .ctl-list{background:var(--card,#fff);margin-top:10px}
  .ctl-drawer pre{margin:10px 0 0;max-height:360px;overflow:auto;font-size:12px;background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:10px 12px;white-space:pre-wrap;overflow-wrap:anywhere}
  .ctl-skip{font-size:.78rem;color:var(--mut,#667085);margin:8px 0 0;padding-left:18px}
  .ctl-skip li{margin:2px 0;overflow-wrap:anywhere}
  .ctl-filters{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:flex-end;margin-bottom:10px}
  .ctl-filters .ctl-field{flex:0 1 180px}
  .ctl-tl{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px;background:var(--card,#fff)}
  .ctl-tl svg{display:block;width:100%;height:180px}
  .ctl-tlx{display:flex;justify-content:space-between;gap:8px;font-size:.72rem;color:var(--mut,#667085);margin-top:4px;flex-wrap:wrap}
  .ctl-legend{display:flex;gap:14px;flex-wrap:wrap;font-size:.74rem;color:var(--mut,#667085);margin-top:6px}
  .ctl-sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
  @media (max-width:560px){.ctl-field,.ctl-filters .ctl-field{flex:1 1 100%}.ctl-card{padding:14px}.ctl-grid{grid-template-columns:1fr}}
`;

const kpi = (v, l) => '<div class="' + P + '-kpi"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const pill = (s) => (s ? '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>" : "");
const confClass = (c) => (c >= 0.8 ? "high" : c >= 0.5 ? "medium" : "low");
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

const EV_COLS = ["time", "platform", "principal", "principalType", "action", "service", "status", "error", "ip", "region", "account", "target", "ua"];
function evidenceTable(rows) {
  if (!rows || !rows.length) return '<p class="' + P + '-note">No evidence rows.</p>';
  const keys = EV_COLS.filter((k) => rows.some((r) => r[k] !== "" && r[k] != null));
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r, i) => '<tr data-i="' + i + '" title="Show the raw record">' + keys.map((k) => "<td>" + esc(r[k] == null ? "" : r[k]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

/** Per-bucket SVG bar chart, no library. Grey = all events, red = events inside a finding. */
function timelineSvg(tl) {
  const n = tl.length, W = Math.max(n * 4, 400), H = 160;
  let max = 1;
  for (const b of tl) if (b.events > max) max = b.events;
  const bw = W / n, gap = bw > 3 ? 1 : 0;
  const bars = tl.map((b, k) => {
    const h = (b.events / max) * (H - 6), hf = (b.flagged / max) * (H - 6), x = (k * bw).toFixed(2), w = Math.max(0.6, bw - gap).toFixed(2);
    return "<g><title>" + esc(b.t + ": " + b.events + " events, " + b.failures + " failed, " + b.flagged + " in findings") + "</title>" +
      (b.events ? '<rect x="' + x + '" y="' + (H - h).toFixed(2) + '" width="' + w + '" height="' + h.toFixed(2) + '" fill="#9aa3b2"></rect>' : "") +
      (b.flagged ? '<rect x="' + x + '" y="' + (H - hf).toFixed(2) + '" width="' + w + '" height="' + hf.toFixed(2) + '" fill="#b00020"></rect>' : "") + "</g>";
  }).join("");
  return '<svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" role="img" aria-label="Events per bucket">' +
    '<line x1="0" y1="' + (H - 0.5) + '" x2="' + W + '" y2="' + (H - 0.5) + '" stroke="#d7dbe3" stroke-width="1"></line>' + bars + "</svg>";
}

const GROUPS = [
  { title: "Identity", fields: [
    ["consoleFailN", "Sign-in failures per IP", "Console / UserLoginFailed failures from one IP that make a burst."],
    ["consoleFailWindowMin", "Sign-in failure window (min)", ""],
    ["failureBurstN", "Denied or failed calls per principal", "AccessDenied, Failed, PERMISSION_DENIED."],
    ["failureBurstWindowMin", "Denied-call window (min)", ""],
    ["travelKmh", "Impossible-travel speed (km/h)", "Only used when IP locations are supplied below."],
  ] },
  { title: "Logging and baseline", fields: [
    ["baselineMinEvents", "Events before first-seen applies", "A principal or account needs this many earlier events before a new region, service or tool counts as new."],
  ] },
  { title: "Data access", fields: [
    ["secretsBurstN", "Secret reads per principal", "GetSecretValue, GetParameter, Key Vault SecretGet."],
    ["secretsBurstWindowMin", "Secret-read window (min)", ""],
    ["downloadBurstN", "M365 file downloads per user", ""],
    ["downloadBurstWindowMin", "Download window (min)", ""],
    ["mailAccessBurstN", "MailItemsAccessed per identity", ""],
    ["mailAccessBurstWindowMin", "Mail-access window (min)", ""],
    ["purgeBurstN", "Mail deletions per identity", "HardDelete, SoftDelete, MoveToDeletedItems."],
    ["purgeBurstWindowMin", "Deletion window (min)", ""],
    ["storageListBurstN", "GCS list / get per principal", "Needs Data Access audit logs."],
    ["storageListBurstWindowMin", "GCS window (min)", ""],
  ] },
  { title: "Recon", fields: [
    ["reconBurstN", "Discovery calls per principal", "Describe*, List*, GetCallerIdentity ..."],
    ["reconBurstWindowMin", "Discovery window (min)", ""],
  ] },
];

function thresholdsHtml() {
  const f = (k, label, help) => '<div class="' + P + '-field"><label for="' + P + "-o-" + k + '">' + esc(label) + '</label><input id="' + P + "-o-" + k + '" data-opt="' + k + '" type="number" min="1" step="1" value="' + esc(DEFAULTS[k]) + '"><small>Default ' + esc(DEFAULTS[k]) + (help ? ". " + esc(help) : "") + "</small></div>";
  const ah = DEFAULTS.afterHours;
  return '<div class="' + P + '-grid">' + GROUPS.map((g) => '<div class="' + P + '-grp"><h4>' + esc(g.title) + '</h4><div class="' + P + '-fields">' + g.fields.map((x) => f(x[0], x[1], x[2])).join("") +
    (g.title === "Identity" ? '<div class="' + P + '-field wide"><label for="' + P + '-trusted">Trusted AWS accounts</label><input id="' + P + '-trusted" type="text" placeholder="12-digit ids" autocomplete="off" spellcheck="false"><small>Comma separated. Cross-account AssumeRole, trust policies and snapshot shares from these are not reported. Blank = every foreign account is listed for review.</small></div>' +
      '<div class="' + P + '-field wide"><label for="' + P + '-admin">Admin name pattern</label><input id="' + P + '-admin" type="text" value="' + esc(DEFAULTS.adminNamePattern) + '" spellcheck="false"><small>Regular expression; after-hours changes by matching names are rated medium.</small></div>' +
      '<div class="' + P + '-field wide"><label class="' + P + '-check"><input type="checkbox" id="' + P + '-ah"' + (ah.enabled ? " checked" : "") + '><span>Flag admin changes after hours</span></label></div>' +
      '<div class="' + P + '-field"><label for="' + P + '-ahs">After hours start (hour)</label><input id="' + P + '-ahs" type="number" min="0" max="23" value="' + ah.start + '"><small>Default ' + ah.start + ":00</small></div>" +
      '<div class="' + P + '-field"><label for="' + P + '-ahe">After hours end (hour)</label><input id="' + P + '-ahe" type="number" min="0" max="23" value="' + ah.end + '"><small>Default ' + ah.end + ":00</small></div>" +
      '<div class="' + P + '-field"><label for="' + P + '-aho">UTC offset (hours)</label><input id="' + P + '-aho" type="number" min="-12" max="14" step="0.5" value="' + ah.utcOffset + '"><small>Default 0 (UTC)</small></div>' +
      '<div class="' + P + '-field"><label class="' + P + '-check"><input type="checkbox" id="' + P + '-ahw"' + (ah.weekends ? " checked" : "") + '><span>Weekends count as after hours</span></label></div>' : "") +
    "</div></div>").join("") + "</div>";
}

/** Mount the tool into main. */
export function renderCloudTrail(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Cloud Audit Logs</h1></div>',
    '<p class="', P, '-sub">Hunt AWS CloudTrail, Azure Activity Log, GCP Cloud Audit Logs and the Microsoft 365 Unified Audit Log for what attackers do with cloud credentials: logging stopped, keys minted, policies opened to the world, roles granted, mail forwarded, secrets and data pulled in bursts. ', RULES.length, ' rules mapped to MITRE ATT&amp;CK and CIS / NIST / SCuBA controls. Runs entirely in your browser. Nothing is uploaded. The only request is the optional malicious-IP list at ', FEED_URL, ', a same-origin copy that is mirrored and dated, not live.</p>',
    '<div class="', P, '-card"><h2>1. Audit log exports</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-note">Accepted: CloudTrail {"Records":[...]} files (also .json.gz), CloudTrail NDJSON and Athena / Lake CSV; Azure Activity Log JSON and the Log Analytics AzureActivity CSV; GCP LogEntry NDJSON or JSON array; Microsoft 365 Search-UnifiedAuditLog | Export-Csv, Purview audit CSV and AuditData JSON. Drop many files or a zip at once.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div>',
    '<div id="', P, '-map"></div>',
    '<div class="', P, '-plat" id="', P, '-plat"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" type="button" disabled>Hunt</button><button class="', P, '-btn" id="', P, '-clear" type="button" disabled>Clear files</button><span class="', P, '-note" id="', P, '-count"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-plabel" id="', P, '-plabel"></div></div>',
    '<div class="', P, '-card"><h2>2. Thresholds</h2>', thresholdsHtml(), "</div>",
    '<div class="', P, '-card"><h2>3. Threat intel and location (optional)</h2>',
    '<label class="', P, '-check"><input type="checkbox" id="', P, '-feed"><span>Use the mirrored malicious-IP feed (', FEED_URL, ')</span></label>',
    '<p class="', P, '-note" id="', P, '-feedinfo">Off. Turning it on loads a dated same-origin copy; it is not a live lookup.</p>',
    '<div class="', P, '-fields" style="margin-top:12px">',
    '<div class="', P, '-field wide"><label for="', P, '-ownips">Your own bad IPs</label><textarea id="', P, '-ownips" placeholder="one IP per line" spellcheck="false"></textarea><small>Joined with the feed when it is on, used alone when it is off.</small></div>',
    '<div class="', P, '-field wide"><label for="', P, '-geo">IP locations for impossible travel</label><textarea id="', P, '-geo" placeholder="ip,lat,lon,country" spellcheck="false"></textarea><small>One line per IP, from your GeoIP export. Without it the impossible-travel rule is skipped, never guessed.</small></div>',
    "</div></div>",
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card" id="', P, '-results" style="display:none"><div class="', P, '-tabs" id="', P, '-tabs"></div><div id="', P, '-pane"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div><ul class="', P, '-skip" id="', P, '-skipped"></ul></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example" type="button">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, running = false, feed = null;
  let tab = "findings", selFinding = -1;
  const sorts = { findings: { key: "severity", dir: "desc" }, principals: { key: "risk", dir: "desc" }, ips: { key: "findings", dir: "desc" }, rules: { key: "status", dir: "asc" } };
  let ffilter = { sev: "", platform: "", q: "" };
  const columnMap = {};

  const datasetName = () => (isExample ? "synthetic example" : files.map((f) => f.name).join(", ").slice(0, 200));

  function renderFiles() {
    const box = $("files");
    box.innerHTML = files.map((f, i) => {
      const d = f.det;
      const parsed = result ? (result.meta.files || []).find((x) => x.name === f.name) : null;
      return '<div class="' + P + '-file"><b>' + esc(f.name) + '</b><span class="' + P + '-mut">' + esc(fmtBytes(d.bytes)) + (f.fromArchive ? ", from archive" : "") + "</span>" +
        "<span>" + esc(PLATFORM_LABEL[d.platform] || d.platform) + " &middot; " + esc(d.layout || d.format) + "</span>" +
        '<span class="' + P + "-conf " + confClass(d.confidence) + '">' + esc(confClass(d.confidence)) + " confidence</span>" +
        (parsed ? '<span class="' + P + '-mut">' + fmtNum(parsed.records) + " records parsed</span>" : "") +
        '<button class="' + P + '-btn sm" data-rm="' + i + '" type="button">Remove</button></div>';
    }).join("");
    box.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { files.splice(Number(b.dataset.rm), 1); isExample = false; renderFiles(); }));
    const bytes = files.reduce((n, f) => n + f.det.bytes, 0);
    $("count").textContent = files.length ? files.length + " file" + (files.length === 1 ? "" : "s") + ", " + fmtBytes(bytes) + (isExample ? " (synthetic example)" : "") : "";
    $("run").disabled = !files.length || running;
    $("clear").disabled = !files.length;
    renderMapping();
  }

  function renderMapping() {
    const low = files.filter((f) => f.det.confidence < 0.8);
    const box = $("map");
    if (!low.length) { box.innerHTML = ""; return; }
    const headers = [...new Set(low.flatMap((f) => f.det.headers || []))];
    const labels = { timestamp: "Timestamp", principal: "Principal / user", action: "Action / operation", service: "Service", ip: "Source IP", status: "Status / error", region: "Region", account: "Account / subscription", target: "Target resource", userAgent: "User agent" };
    const norm = (h) => String(h).toLowerCase().replace(/[^a-z0-9]/g, "");
    box.innerHTML = '<div class="' + P + '-card" style="margin:12px 0 0"><h2>Column mapping</h2><p class="' + P + '-note">' + esc(low.map((f) => f.name).join(", ")) + ": the layout was not recognised with high confidence, so it is read as a generic audit table. Timestamp, principal and action are required; rules that need an unmapped field are skipped and listed.</p>" +
      '<div class="' + P + '-fields" style="margin-top:10px">' + Object.keys(COLUMNS).map((k) => '<div class="' + P + '-field"><label for="' + P + "-col-" + k + '">' + esc(labels[k] || k) + '</label><select id="' + P + "-col-" + k + '" data-col="' + esc(k) + '"><option value="">(not present)</option>' +
        headers.map((h) => '<option value="' + esc(h) + '"' + (columnMap[k] === h || (!columnMap[k] && COLUMNS[k].some((a) => norm(a) === norm(h))) ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>").join("") + "</div></div>";
    box.querySelectorAll("[data-col]").forEach((sel) => { if (sel.value) columnMap[sel.dataset.col] = sel.value; sel.addEventListener("change", () => { if (sel.value) columnMap[sel.dataset.col] = sel.value; else delete columnMap[sel.dataset.col]; }); });
  }

  function addFile(name, text, fromArchive) {
    const det = detectFile(name, text);
    if (det.format === "empty") { toast(name + " is empty", "warning"); return false; }
    const entry = { name, text, det, fromArchive: !!fromArchive };
    const idx = files.findIndex((x) => x.name === name);
    if (idx >= 0) files[idx] = entry; else files.push(entry);
    return true;
  }

  mountDropzone($("drop"), {
    maxBytes: 256 * 1024 * 1024, maxFiles: 500, multiple: true, unpack: true,
    label: "Drop audit log exports or a zip here, paste, or browse",
    onFiles: async (list, info) => {
      let added = 0;
      if (isExample) { files = []; isExample = false; }
      for (const f of list) { try { if (addFile(f.name, await f.text(), f.fromArchive)) added++; } catch (e) { toast("Could not read " + f.name + ": " + ((e && e.message) || e), "error"); } }
      const sk = (info && info.skipped) || [];
      if (sk.length) toast(sk.length + " file" + (sk.length === 1 ? "" : "s") + " skipped: " + sk.slice(0, 3).map((s) => s.name + " (" + s.reason + ")").join("; "), "warning");
      if (added) toast("Loaded " + added + " file" + (added === 1 ? "" : "s"), "success");
      result = null; $("plat").innerHTML = "";
      renderFiles();
    },
  });

  $("clear").addEventListener("click", () => { files = []; isExample = false; result = null; $("plat").innerHTML = ""; renderFiles(); });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    files = []; isExample = true; result = null; $("plat").innerHTML = "";
    for (const f of ex.files) addFile(f.name, f.text, false);
    renderFiles();
    toast("Synthetic example loaded: " + files.length + " files. Click Hunt.", "info");
  });

  $("feed").addEventListener("change", async () => {
    const on = $("feed").checked, info = $("feedinfo");
    if (!on) { info.textContent = "Off. Turning it on loads a dated same-origin copy; it is not a live lookup."; return; }
    if (feed) { info.textContent = "Mirrored " + String(feed.updated || "").slice(0, 10) + ": " + fmtNum((feed.data || []).length) + " IPs from " + (feed.source || "the mirror") + "."; return; }
    info.textContent = "Loading the mirrored list...";
    try {
      const res = await fetch(FEED_URL, { cache: "no-cache" });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const j = await res.json();
      if (!j || !Array.isArray(j.data)) throw new Error("unexpected feed shape");
      feed = j;
      info.textContent = "Mirrored " + String(j.updated || "").slice(0, 10) + ": " + fmtNum(j.data.length) + " IPs from " + (j.source || "the mirror") + ".";
    } catch (e) {
      $("feed").checked = false;
      info.textContent = "The mirrored list could not be loaded (" + ((e && e.message) || e) + "). The rule stays skipped unless you paste your own IPs.";
      toast("Malicious-IP mirror unavailable", "warning");
    }
  });

  const opts = () => {
    const o = { columns: { ...columnMap } };
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (Number.isFinite(n) && n > 0) o[el.dataset.opt] = n; });
    o.trustedAccounts = $("trusted").value.split(/[\s,;]+/).map((s) => s.trim()).filter((s) => /^\d{12}$/.test(s));
    const pat = $("admin").value.trim(); if (pat) o.adminNamePattern = pat;
    const num = (id, d) => { const n = Number($(id).value); return Number.isFinite(n) ? n : d; };
    o.afterHours = { enabled: $("ah").checked, start: num("ahs", DEFAULTS.afterHours.start), end: num("ahe", DEFAULTS.afterHours.end), utcOffset: num("aho", 0), weekends: $("ahw").checked };
    const own = $("ownips").value.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean).map((ip) => ({ ip, source: "your list" }));
    const fromFeed = $("feed").checked && feed ? feed.data : [];
    if (own.length || $("feed").checked && feed) o.maliciousIps = fromFeed.concat(own);
    const geo = {};
    for (const line of $("geo").value.split(/\r?\n/)) {
      const p = line.split(",").map((s) => s.trim());
      if (p.length >= 3 && p[0] && Number.isFinite(Number(p[1])) && Number.isFinite(Number(p[2])) && p[1] !== "" && p[2] !== "") geo[p[0]] = { lat: Number(p[1]), lon: Number(p[2]), country: p[3] || "" };
    }
    if (Object.keys(geo).length) o.geo = geo;
    if (isExample) o.now = exampleDataset().now;
    return o;
  };

  $("run").addEventListener("click", async () => {
    if (!files.length || running) return;
    running = true;
    const prog = $("prog"), bar = prog.firstElementChild, pl = $("plabel");
    prog.style.display = "block"; pl.style.display = "block"; bar.style.width = "0%"; pl.textContent = "starting the worker"; $("run").disabled = true;
    const t0 = performance.now();
    try {
      result = await runInWorker(ENGINE, "analyze", [files.map((f) => ({ name: f.name, text: f.text })), opts()], {
        timeoutMs: 15 * 60 * 1000,
        onProgress: (i, n, label) => {
          bar.style.width = (n ? Math.min(100, Math.round((i / n) * 100)) : 0) + "%";
          const m = /(\d+)\s*(?:records|\/)/.exec(label || "");
          const secs = (performance.now() - t0) / 1000;
          const rate = m && secs > 0.2 ? " - " + fmtNum(Math.round(Number(m[1]) / secs)) + " events/s" : "";
          pl.textContent = (label || "") + rate;
        },
      });
      selFinding = -1; ffilter = { sev: "", platform: "", q: "" };
      render(result);
      const secs = (performance.now() - t0) / 1000;
      toast(result.findings.length + " finding" + (result.findings.length === 1 ? "" : "s") + " in " + fmtNum(result.summary.events) + " events (" + secs.toFixed(1) + " s)", "success");
    } catch (e) {
      toast("Analysis failed: " + ((e && e.message) || e), "error");
    } finally {
      running = false;
      prog.style.display = "none"; pl.style.display = "none"; $("run").disabled = !files.length;
    }
  });

  function render(r) {
    const s = r.summary;
    const span = s.events ? (s.spanHours >= 48 ? (s.spanHours / 24).toFixed(1) + " days" : s.spanHours + " h") : "-";
    $("kpis").innerHTML = kpi(fmtNum(s.events), "events") + kpi(fmtNum(s.principals), "principals") + kpi(fmtNum(s.ips), "source IPs") +
      kpi(s.critical + " / " + s.high, "critical / high") + kpi(s.findings, "findings") + kpi(span, "time span");
    $("plat").innerHTML = Object.keys(s.platforms).map((p) => '<span class="' + P + '-chip">' + esc(PLATFORM_LABEL[p] || p) + ": " + fmtNum(s.platforms[p]) + " events</span>").join("") +
      (s.firstTs ? '<span class="' + P + '-chip">' + esc(s.firstTs + " to " + s.lastTs) + "</span>" : "");
    $("skipped").innerHTML = r.skipped.length ? "<li><b>Skipped or limited checks</b></li>" + r.skipped.map((k) => "<li>" + esc(k.check) + ": " + esc(k.reason) + "</li>").join("") : "";
    $("results").style.display = "";
    renderFiles();
    renderTabs(r);
    renderExports(r);
  }

  function renderTabs(r) {
    const tabs = [["findings", "Findings (" + r.findings.length + ")"], ["principals", "Principals (" + r.tables.principals.length + ")"], ["ips", "IPs (" + r.tables.ips.length + ")"], ["timeline", "Timeline"], ["rules", "Rules (" + r.summary.rulesFired + " fired / " + r.tables.rules.length + ")"]];
    $("tabs").innerHTML = tabs.map(([k, l]) => '<button type="button" class="' + P + "-tab" + (tab === k ? " on" : "") + '" data-tab="' + k + '">' + esc(l) + "</button>").join("");
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; $("drawer").style.display = "none"; selFinding = -1; renderTabs(r); }));
    const pane = $("pane");
    pane.innerHTML = "";
    if (tab === "findings") drawFindings(r);
    else if (tab === "principals") pane.appendChild(r.tables.principals.length ? table(PRIN_COLS, r.tables.principals, sorts.principals, (s) => { sorts.principals = s; renderTabs(r); }) : emptyEl("No principals."));
    else if (tab === "ips") pane.appendChild(r.tables.ips.length ? table(IP_COLS, r.tables.ips, sorts.ips, (s) => { sorts.ips = s; renderTabs(r); }) : emptyEl("No source IP addresses in this input."));
    else if (tab === "timeline") drawTimeline(r);
    else if (tab === "rules") pane.appendChild(table(RULE_COLS, r.tables.rules, sorts.rules, (s) => { sorts.rules = s; renderTabs(r); }));
  }
  const emptyEl = (t) => { const d = document.createElement("div"); d.className = P + "-empty"; d.textContent = t; return d; };

  const FIND_COLS = [
    { key: "severity", label: "Severity", rank: SEV_RANK, render: (f) => pill(f.severity) },
    { key: "title", label: "Finding", render: (f) => "<b>" + esc(f.title) + "</b>" + (f.note ? '<div class="' + P + '-mut">' + esc(f.note) + "</div>" : "") },
    { key: "platform", label: "Platform", render: (f) => esc(PLATFORM_LABEL[f.platform] || f.platform) },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
    { key: "controls", label: "Controls", render: (f) => f.controls.slice(0, 4).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + (f.controls.length > 4 ? '<span class="' + P + '-chip">+' + (f.controls.length - 4) + "</span>" : "") },
    { key: "evidenceCount", label: "Events" },
    { key: "firstSeen", label: "First seen", render: (f) => '<span class="' + P + '-nw">' + esc(f.firstSeen) + "</span>" },
  ];
  const PRIN_COLS = [
    { key: "principal", label: "Principal", render: (p) => "<b>" + esc(p.principal) + "</b>" },
    { key: "platform", label: "Platform" }, { key: "type", label: "Type" }, { key: "account", label: "Account" },
    { key: "risk", label: "Risk" }, { key: "maxSeverity", label: "Worst", rank: SEV_RANK, render: (p) => pill(p.maxSeverity) || "-" },
    { key: "events", label: "Events" }, { key: "failures", label: "Failed" }, { key: "ips", label: "IPs" }, { key: "services", label: "Services" },
    { key: "first", label: "First" }, { key: "last", label: "Last" }, { key: "flags", label: "Rules hit" },
  ];
  const IP_COLS = [
    { key: "ip", label: "IP", render: (x) => "<b>" + esc(x.ip) + "</b>" + (x.private ? ' <span class="' + P + '-chip">private</span>' : "") },
    { key: "malicious", label: "Feed", render: (x) => (x.malicious ? '<span class="' + P + '-chip fired">' + esc(x.malicious) + "</span>" : "-") },
    { key: "country", label: "Country" }, { key: "maxSeverity", label: "Worst", rank: SEV_RANK, render: (x) => pill(x.maxSeverity) || "-" },
    { key: "events", label: "Events" }, { key: "failures", label: "Failed" }, { key: "principals", label: "Principals" }, { key: "platforms", label: "Platforms" },
    { key: "first", label: "First" }, { key: "last", label: "Last" }, { key: "flags", label: "Rules hit" },
  ];
  const STATUS_RANK = { fired: 0, skipped: 1, silent: 2, "n/a": 3 };
  const RULE_COLS = [
    { key: "status", label: "Status", rank: STATUS_RANK, render: (x) => '<span class="' + P + "-chip " + esc(x.status === "n/a" ? "" : x.status) + '">' + esc(x.status) + "</span>" },
    { key: "id", label: "Rule", render: (x) => "<b>" + esc(x.title) + '</b><div class="' + P + '-mut">' + esc(x.id) + "</div>" },
    { key: "platform", label: "Platform", render: (x) => esc(x.platform === "any" ? "cross-platform" : PLATFORM_LABEL[x.platform] || x.platform) },
    { key: "severity", label: "Base severity", rank: SEV_RANK, render: (x) => pill(x.severity) },
    { key: "mitre", label: "MITRE" }, { key: "hits", label: "Findings" }, { key: "events", label: "Events" },
    { key: "reason", label: "Why not run" },
  ];

  function drawFindings(r) {
    const pane = $("pane");
    if (!r.findings.length) { pane.appendChild(emptyEl("No findings for the current thresholds. The Rules tab shows which rules ran and which were skipped.")); return; }
    const plats = [...new Set(r.findings.map((f) => f.platform))].sort();
    const fl = document.createElement("div");
    fl.className = P + "-filters";
    fl.innerHTML = '<div class="' + P + '-field"><label for="' + P + '-fs">Severity</label><select id="' + P + '-fs" data-ff="sev"><option value="">All</option>' + ["critical", "high", "medium", "low", "info"].map((s) => '<option value="' + s + '"' + (ffilter.sev === s ? " selected" : "") + ">" + s + "</option>").join("") + "</select></div>" +
      '<div class="' + P + '-field"><label for="' + P + '-fp">Platform</label><select id="' + P + '-fp" data-ff="platform"><option value="">All</option>' + plats.map((p) => '<option value="' + esc(p) + '"' + (ffilter.platform === p ? " selected" : "") + ">" + esc(PLATFORM_LABEL[p] || p) + "</option>").join("") + "</select></div>" +
      '<div class="' + P + '-field"><label for="' + P + '-fq">Search</label><input id="' + P + '-fq" data-ff="q" type="search" placeholder="principal, IP, rule" value="' + esc(ffilter.q) + '"></div>';
    pane.appendChild(fl);
    const box = document.createElement("div");
    pane.appendChild(box);
    const draw = () => {
      const q = ffilter.q.trim().toLowerCase();
      const rows = r.findings.map((f, i) => ({ ...f, i })).filter((f) => (!ffilter.sev || f.severity === ffilter.sev) && (!ffilter.platform || f.platform === ffilter.platform) &&
        (!q || [f.title, f.ruleId, f.note, f.principals.join(" "), f.ips.join(" ")].some((v) => String(v || "").toLowerCase().includes(q))));
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
    d.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + pill(f.severity) + " " + esc(f.title) + '</h3><button class="' + P + '-btn sm" data-close type="button">Close</button></div>' +
      "<p>" + esc(f.description) + "</p><p><b>Recommendation:</b> " + esc(f.recommendation) + "</p>" +
      "<p><b>Confidence:</b> " + esc(f.confidence) + " &middot; <b>Rule:</b> " + esc(f.ruleId) + " &middot; <b>Window:</b> " + esc(f.firstSeen + " to " + f.lastSeen) + "</p>" +
      "<p>" + f.controls.map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</p>" +
      (f.assets.length ? "<p><b>Assets:</b> " + f.assets.map((a) => esc(a.type + " " + a.name)).join(", ") + "</p>" : "") +
      "<p><b>Evidence</b> (" + f.evidence.length + " of " + f.evidenceCount + " events; click a row for the raw record)</p>" + evidenceTable(f.evidence) +
      '<pre id="' + P + '-raw" hidden></pre>' +
      '<div class="' + P + '-row"><button class="' + P + '-btn sm" data-ev type="button">Export evidence CSV</button></div>';
    d.querySelector("[data-close]").addEventListener("click", () => { d.style.display = "none"; selFinding = -1; renderTabs(r); });
    const raw = d.querySelector("#" + P + "-raw");
    d.querySelectorAll(".ctl-list tr[data-i]").forEach((tr) => tr.addEventListener("click", () => {
      d.querySelectorAll(".ctl-list tr.sel").forEach((x) => x.classList.remove("sel"));
      tr.classList.add("sel");
      const ev = f.evidence[Number(tr.dataset.i)];
      const src = ev && ev.raw >= 0 ? r.rawRecords[ev.raw] : undefined;
      let txt = "Raw record not retained (over the raw-record memory budget); the normalised fields above are complete.";
      if (src !== undefined) { try { txt = JSON.stringify(JSON.parse(src), null, 2); } catch (_) { txt = String(src); } }
      raw.hidden = false; raw.textContent = txt;
    }));
    d.querySelector("[data-ev]").addEventListener("click", () => {
      const q = (v) => '"' + String(v == null ? "" : v).replace(/^(?=[=+@\t\r]|-(?!\d+(?:\.\d+)?$))/, "'").replace(/"/g, '""') + '"';
      download(TOOL_ID + "-evidence-" + fileStamp() + ".csv", [EV_COLS.join(","), ...f.evidence.map((e) => EV_COLS.map((k) => q(e[k])).join(","))].join("\n") + "\n", "text/csv");
    });
    d.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  function drawTimeline(r) {
    const pane = $("pane");
    const tl = r.tables.timeline;
    if (!tl.length) { pane.appendChild(emptyEl("No timestamps.")); return; }
    const max = tl.reduce((m, b) => Math.max(m, b.events), 0);
    const flagged = tl.filter((b) => b.flagged);
    const el = document.createElement("div");
    el.innerHTML = '<div class="' + P + '-tl">' + timelineSvg(tl) + '<div class="' + P + '-tlx"><span>' + esc(tl[0].t) + "</span><span>peak " + fmtNum(max) + " events per " + esc(r.summary.timelineUnit) + "</span><span>" + esc(tl[tl.length - 1].t) + "</span></div>" +
      '<div class="' + P + '-legend"><span><i class="' + P + '-sw" style="background:#9aa3b2"></i>all events</span><span><i class="' + P + '-sw" style="background:#b00020"></i>events inside a finding</span><span>' + tl.length + " buckets of one " + esc(r.summary.timelineUnit) + " (UTC); hover a bar for counts</span></div></div>" +
      (flagged.length ? '<h3 class="' + P + '-note" style="margin-top:12px"><b>Buckets with flagged activity</b></h3>' : "");
    pane.appendChild(el);
    if (flagged.length) pane.appendChild(table([{ key: "t", label: "Bucket start (UTC)" }, { key: "events", label: "Events" }, { key: "failures", label: "Failed" }, { key: "flagged", label: "In findings" }], flagged, { key: "t", dir: "asc" }, () => {}));
  }

  function renderExports(r) {
    const ex = $("exports");
    ex.innerHTML = ["csv:Findings CSV", "json:JSON", "txt:Summary TXT", "ioc:IOC CSV", "prin:Principals CSV", "ips:IPs CSV", "tl:Timeline CSV", "q:Hunt queries TXT"].map((x) => { const [k, l] = x.split(":"); return '<button class="' + P + '-btn" type="button" data-x="' + k + '">' + l + "</button>"; }).join("");
    const stamp = fileStamp();
    const on = (k, fn) => ex.querySelector('[data-x="' + k + '"]').addEventListener("click", fn);
    on("csv", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    on("json", () => download(TOOL_ID + "-" + stamp + ".json", toJson({ ...r, rawRecords: undefined, summaryStats: summarize(r.findings) }), "application/json"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r), "text/plain"));
    on("ioc", () => { if (!r.iocs.length) { toast("No IOCs: nothing high or critical was found", "info"); return; } download(TOOL_ID + "-iocs-" + stamp + ".csv", iocsToCsv(r.iocs), "text/csv"); });
    on("prin", () => download(TOOL_ID + "-principals-" + stamp + ".csv", principalsToCsv(r.tables.principals), "text/csv"));
    on("ips", () => download(TOOL_ID + "-ips-" + stamp + ".csv", ipsToCsv(r.tables.ips), "text/csv"));
    on("tl", () => download(TOOL_ID + "-timeline-" + stamp + ".csv", timelineToCsv(r.tables.timeline), "text/csv"));
    on("q", () => download(TOOL_ID + "-queries-" + stamp + ".txt", queriesText(r, opts()), "text/plain"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: datasetName() });
  }

  renderFiles();
}
