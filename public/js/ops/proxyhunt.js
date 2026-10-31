// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Web Gateway Hunt (proxyhunt): Deck tool UI. Drop secure web gateway / proxy logs (Zscaler,
// Squid, Palo Alto, Netskope, Umbrella, Cloudflare Gateway, generic CSV; zip / gz unpacked
// locally); the engine runs in a Worker. The only network request is the optional same-origin
// mirrored feed /data/feeds/malicious-ips.json. No native dialogs; toasts only.
//
//   renderProxyHunt(main) -> void

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, COLUMNS, COLUMN_LABELS, SEV_RANK, CONF_RANK, DEFAULT_INTERNAL_CIDRS, DEV_HOSTS, CATALOG, detectFile,
  findingsToCsv, shadowSaasCsv, tableToCsv, blocklistText, userReportText, summaryText, exampleDataset,
} from "./proxyhunt-engine.js?v=20261030c";

const ENGINE = engineUrl("./proxyhunt-engine.js?v=20261030c", import.meta);
const P = "pxh";
const FEED_URL = "/data/feeds/malicious-ips.json";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const fmtBytes = (n) => { const v = Number(n) || 0; return v >= 1073741824 ? (v / 1073741824).toFixed(2) + " GB" : v >= 1048576 ? (v / 1048576).toFixed(1) + " MB" : v >= 1024 ? Math.round(v / 1024) + " KB" : v + " B"; };
const fmtNum = (n) => Number(n || 0).toLocaleString("en-US");

const CSS = `
  .pxh-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .pxh-root *{box-sizing:border-box}
  .pxh-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .pxh-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .pxh-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .pxh-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:100ch}
  .pxh-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .pxh-card h2{font-size:.95rem;margin:0 0 10px}
  .pxh-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .pxh-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .pxh-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .pxh-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .pxh-btn.sm{padding:4px 9px;font-size:.76rem}
  .pxh-btn:disabled{opacity:.5;cursor:default}
  .pxh-files{display:flex;flex-direction:column;gap:6px;margin-top:12px}
  .pxh-file{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;font-size:.82rem;min-width:0}
  .pxh-file b{overflow-wrap:anywhere;min-width:0}
  .pxh-mut{color:var(--mut,#667085)}
  .pxh-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085);white-space:nowrap}
  .pxh-conf.high{color:#1b7f4d;border-color:#1b7f4d}.pxh-conf.medium{color:#8a6d00;border-color:#8a6d00}.pxh-conf.low{color:#b00020;border-color:#b00020}
  .pxh-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
  .pxh-grp{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 12px;min-width:0}
  .pxh-grp h4{margin:0 0 8px;font-size:.76rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut,#667085)}
  .pxh-fields{display:flex;flex-wrap:wrap;gap:10px 14px}
  .pxh-field{display:flex;flex-direction:column;gap:3px;min-width:0;flex:1 1 140px}
  .pxh-field.wide{flex:1 1 100%}
  .pxh-field label{font-size:.76rem;font-weight:600;color:var(--tx,#1a2230)}
  .pxh-field input,.pxh-field select,.pxh-field textarea{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:6px 9px;width:100%;max-width:100%}
  .pxh-field textarea{min-height:60px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem}
  .pxh-field small{font-size:.72rem;color:var(--mut,#667085);line-height:1.35;overflow-wrap:anywhere}
  .pxh-check{display:flex;gap:8px;align-items:flex-start;font-size:.84rem;min-width:0}
  .pxh-check input{margin-top:3px;flex:none}
  .pxh-check span{min-width:0;overflow-wrap:anywhere}
  .pxh-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .pxh-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:120px;flex:1 1 120px}
  .pxh-kpi b{display:block;font-size:1.3rem;overflow-wrap:anywhere}
  .pxh-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .pxh-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .pxh-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .pxh-plabel{font-size:.74rem;color:var(--mut,#667085);margin-top:4px;display:none;overflow-wrap:anywhere}
  .pxh-tabs{display:flex;flex-wrap:wrap;gap:6px;border-bottom:1px solid var(--line,#e6e8ee);margin-bottom:12px}
  .pxh-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid transparent;border-bottom:none;background:none;color:var(--mut,#667085);padding:7px 12px;border-radius:8px 8px 0 0;cursor:pointer;margin-bottom:-1px}
  .pxh-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#e6e8ee);background:var(--card,#fff)}
  .pxh-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .pxh-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:640px}
  .pxh-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .pxh-list th.on{color:var(--tx,#1a2230)}
  .pxh-list th.on::after{content:" \\2193";font-size:.7rem}
  .pxh-list th.on.asc::after{content:" \\2191"}
  .pxh-list td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word;word-break:normal;max-width:420px}
  .pxh-list tr[data-i]{cursor:pointer}
  .pxh-list tr[data-i]:hover,.pxh-list tr.sel{background:var(--bg,#f7f8fb)}
  .pxh-nw{white-space:nowrap}
  .pxh-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .pxh-pill.critical{background:#7a0012}.pxh-pill.high{background:#b00020}.pxh-pill.medium{background:#b58100}.pxh-pill.low{background:#2552c6}.pxh-pill.info{background:#667085}
  .pxh-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .pxh-chip.no{color:#b00020;border-color:#b00020}.pxh-chip.yes{color:#1b7f4d;border-color:#1b7f4d}.pxh-chip.unknown{color:#8a6d00;border-color:#8a6d00}
  .pxh-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .pxh-drawer{margin-top:12px;display:none;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--bg,#f7f8fb);min-width:0}
  .pxh-drawer h3{margin:0;font-size:1rem;overflow-wrap:anywhere}
  .pxh-drawer p{margin:6px 0;overflow-wrap:anywhere}
  .pxh-drawer .pxh-list{background:var(--card,#fff);margin-top:10px}
  .pxh-skip{font-size:.78rem;color:var(--mut,#667085);margin:8px 0 0;padding-left:18px}
  .pxh-skip li{margin:2px 0;overflow-wrap:anywhere}
  .pxh-filters{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:flex-end;margin-bottom:10px}
  .pxh-filters .pxh-field{flex:0 1 180px}
  .pxh-tl{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px;background:var(--card,#fff)}
  .pxh-tl svg{display:block;width:100%;height:200px}
  .pxh-tlx{display:flex;justify-content:space-between;gap:8px;font-size:.72rem;color:var(--mut,#667085);margin-top:4px;flex-wrap:wrap}
  .pxh-legend{display:flex;gap:14px;flex-wrap:wrap;font-size:.74rem;color:var(--mut,#667085);margin-top:6px}
  .pxh-sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
  .pxh-help{font-size:.78rem;color:var(--mut,#667085);margin:10px 0 0}
  .pxh-help summary{cursor:pointer;font-weight:600;color:var(--tx,#1a2230)}
  .pxh-help p{margin:6px 0;overflow-wrap:anywhere}
  @media (max-width:560px){.pxh-field,.pxh-filters .pxh-field{flex:1 1 100%}.pxh-card{padding:14px}.pxh-grid{grid-template-columns:1fr}.pxh-hd h1{font-size:1.4rem}}
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
  const body = sorted.map((r) => "<tr" + (rowKey ? ' data-i="' + esc(rowKey(r)) + '"' : "") + ">" + cols.map((c) => "<td>" + (c.render ? c.render(r) : esc(r[c.key] == null ? "" : r[c.key])) + "</td>").join("") + "</tr>").join("");
  const el = document.createElement("div");
  el.className = P + "-list";
  el.innerHTML = "<table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table>";
  el.querySelectorAll("th").forEach((th) => th.addEventListener("click", () => { const k = th.dataset.k; onSort({ key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" }); }));
  return el;
}

function evidenceTable(rows) {
  if (!rows || !rows.length) return '<p class="' + P + '-note">No evidence rows.</p>';
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k) && rows.some((x) => x[k] !== "" && x[k] != null)) keys.push(k);
  const cell = (k, v) => (/^bytes/.test(k) && typeof v === "number" ? fmtBytes(v) : v == null ? "" : String(v));
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => "<td>" + esc(cell(k, r[k])) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

/** Daily up / down bytes as grouped bars (no library). */
function timelineSvg(days) {
  const n = days.length, W = Math.max(n * 18, 400), H = 180;
  let max = 1;
  for (const d of days) max = Math.max(max, d.bytesOut, d.bytesIn + d.bytesUnknown);
  const bw = W / n;
  const bars = days.map((d, k) => {
    const x = k * bw, w = Math.max(1, bw / 2 - 1);
    const hu = (d.bytesOut / max) * (H - 6), hd = ((d.bytesIn + d.bytesUnknown) / max) * (H - 6);
    return "<g><title>" + esc(d.day + ": sent " + fmtBytes(d.bytesOut) + ", received " + fmtBytes(d.bytesIn) + (d.bytesUnknown ? ", direction unknown " + fmtBytes(d.bytesUnknown) : "") + ", " + d.requests + " requests, " + d.blocked + " blocked") + "</title>" +
      '<rect x="' + (x + 1).toFixed(2) + '" y="' + (H - hu).toFixed(2) + '" width="' + w.toFixed(2) + '" height="' + hu.toFixed(2) + '" fill="#b00020"></rect>' +
      '<rect x="' + (x + 1 + w).toFixed(2) + '" y="' + (H - hd).toFixed(2) + '" width="' + w.toFixed(2) + '" height="' + hd.toFixed(2) + '" fill="#9aa3b2"></rect></g>';
  }).join("");
  return '<svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" role="img" aria-label="Bytes per day">' +
    '<line x1="0" y1="' + (H - 0.5) + '" x2="' + W + '" y2="' + (H - 0.5) + '" stroke="#d7dbe3" stroke-width="1"></line>' + bars + "</svg>";
}

const GROUPS = [
  { title: "Upload exfiltration", fields: [
    ["uploadMb", "Upload per user per day (MB)", "To unsanctioned storage, transfer, paste, webmail or AI."],
    ["uploadZ", "Robust z above the user's own days", "z = 0.6745 x (day - median) / MAD over the user's other days."],
    ["zMinMb", "Minimum upload for the z rule (MB)", ""],
    ["baselineDays", "Baseline days before z applies", ""],
    ["uploadWrites", "POST/PUT per day when bytes are not logged", ""],
    ["offHoursMb", "Off-hours upload per day (MB)", ""],
  ] },
  { title: "Apps and destinations", fields: [
    ["aiUploadMb", "Upload to one AI service (MB)", "Per user over the log period."],
    ["newAppDays", "New app window (days)", "Relative to the last log entry."],
    ["uncatUploadMb", "Upload to uncategorized / rare host (MB)", ""],
    ["rareUsers", "Rare host: at most this many users", ""],
    ["tunnelMinutes", "CONNECT tunnel duration (min)", "Squid native logs."],
    ["tunnelMb", "CONNECT tunnel volume (MB)", ""],
  ] },
  { title: "Clients and policy", fields: [
    ["blockedPerHour", "Blocked requests per user per hour", ""],
    ["blockedHosts", "... across at least this many hosts", ""],
    ["scriptedMin", "Scripted user-agent requests", "curl, python-requests, Go-http-client, PowerShell, wget, Java ..."],
    ["emptyUaMin", "Empty user-agent requests", ""],
  ] },
];

/** Mount the tool into main. */
export function renderProxyHunt(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  const numField = (k, label, help, extra) => '<div class="' + P + '-field"><label for="' + P + "-o-" + k + '">' + esc(label) + '</label><input id="' + P + "-o-" + k + '" data-opt="' + k + '" type="number" ' + (extra || 'min="0" step="any"') + ' value="' + esc(DEFAULTS[k]) + '"><small>Default ' + esc(DEFAULTS[k]) + (help ? ". " + esc(help) : "") + "</small></div>";
  const area = (id, label, ph, help) => '<div class="' + P + '-field wide"><label for="' + P + "-" + id + '">' + esc(label) + '</label><textarea id="' + P + "-" + id + '" placeholder="' + esc(ph) + '" spellcheck="false"></textarea><small>' + esc(help) + "</small></div>";
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Proxy Logs</h1></div>',
    '<p class="', P, '-sub">Find data leaving the company through the web gateway: uploads to personal storage, file transfer, paste sites, webmail and AI chat services; a shadow-SaaS inventory with user counts; anonymizers, remote-access tools, tunnels, direct-to-IP downloads and scripted clients. ', CATALOG.length, ' catalogued app domains. Runs entirely in your browser. Nothing is uploaded. The only request is the optional malicious-IP list at ', FEED_URL, ', a same-origin copy that is mirrored and dated, not live.</p>',
    '<div class="', P, '-card"><h2>1. Gateway and proxy logs</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-note">Accepted: Zscaler NSS web (LEEF, CEF, Splunk key=value, CSV), Squid access.log (native), Palo Alto URL Filtering and Traffic CSV exports or URL Filtering syslog, Netskope web transactions CSV, Cisco Umbrella proxy CSV, Cloudflare Gateway HTTP Logpush (JSON / NDJSON), or any CSV with ts, user, src_ip, dst_host, url, method, status, bytes_out, bytes_in, category, app, action, user_agent. Many files or a zip at once; up to 512 MB per file. Large logs are streamed and summarised per user, app and host, so memory stays near the size of the text itself.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div>',
    '<div id="', P, '-map"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" type="button" disabled>Hunt</button><button class="', P, '-btn" id="', P, '-cancel" type="button" hidden>Cancel</button><button class="', P, '-btn" id="', P, '-clear" type="button" disabled>Clear files</button><span class="', P, '-note" id="', P, '-count"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-plabel" id="', P, '-plabel"></div></div>',
    '<div class="', P, '-card"><h2>2. Your environment</h2><div class="', P, '-fields">',
    area("sanctioned", "Sanctioned apps", "one domain or app per line", "Blank = nothing sanctioned. Example lines: dropbox.com, Google Drive, test-darknode.sharepoint.com. Mixed services (Google Drive, Box, Gmail, Gist) show sanctioned = unknown until listed."),
    area("own", "Own domains", "one per line", "Excluded from exfiltration and scripted-client checks. The first label also marks your SharePoint / OneDrive tenant as corporate."),
    area("allow", "Allow-listed hosts", "one per line", "Destinations scripts may reach (partner APIs, build servers)."),
    area("internal", "Internal CIDRs", "one per line", "Blank = " + DEFAULT_INTERNAL_CIDRS.join(", ") + "."),
    area("servers", "Server CIDRs", "one per line", "Sources treated as servers: tunnels and remote-access tools from here are high. Requests with no authenticated user also count as non-user sources."),
    '<div class="', P, '-field"><label for="', P, '-o-businessStart">Business day starts (hour)</label><input id="', P, '-o-businessStart" data-opt="businessStart" type="number" min="0" max="23" value="', DEFAULTS.businessStart, '"><small>Default ', DEFAULTS.businessStart, ':00</small></div>',
    '<div class="', P, '-field"><label for="', P, '-o-businessEnd">Business day ends (hour)</label><input id="', P, '-o-businessEnd" data-opt="businessEnd" type="number" min="1" max="24" value="', DEFAULTS.businessEnd, '"><small>Default ', DEFAULTS.businessEnd, ':00</small></div>',
    '<div class="', P, '-field"><label for="', P, '-o-utcOffset">Time zone (hours from UTC)</label><input id="', P, '-o-utcOffset" data-opt="utcOffset" type="number" min="-12" max="14" step="0.5" value="', DEFAULTS.utcOffset, '"><small>Default 0. Also sets the day boundary for per-day totals.</small></div>',
    '<div class="', P, '-field wide"><label class="', P, '-check"><input type="checkbox" id="', P, '-wk" checked><span>Weekends count as outside business hours</span></label>',
    '<label class="', P, '-check"><input type="checkbox" id="', P, '-dev" checked><span>Ignore package registries and update hosts for scripted clients (', DEV_HOSTS.length, ' hosts such as pypi.org, registry.npmjs.org, github.com)</span></label></div>',
    "</div></div>",
    '<div class="', P, '-card"><h2>3. Thresholds</h2><div class="', P, '-grid">', GROUPS.map((g) => '<div class="' + P + '-grp"><h4>' + esc(g.title) + '</h4><div class="' + P + '-fields">' + g.fields.map((x) => numField(x[0], x[1], x[2])).join("") + "</div></div>").join(""), "</div>",
    '<details class="', P, '-help"><summary>How the statistics work</summary><p>Per user and business day, bytes sent to unsanctioned personal storage, file transfer, paste, webmail and AI services are summed. A day is flagged when it reaches the absolute threshold, or when its robust z-score against the same user\'s other active days is above the z threshold: z = 0.6745 x (x - median) / MAD, falling back to (x - median) / (1.2533 x mean absolute deviation) when MAD is 0. The z rule needs the minimum baseline days and the minimum upload, and leaves AI services to the AI check. Every finding states the sample size and thresholds used.</p><p>Squid native logs record one byte count per request (the reply size; for CONNECT tunnels, both directions together), so they cannot measure uploads; those lines count POST/PUT requests instead and feed the long-tunnel check.</p></details></div>',
    '<div class="', P, '-card"><h2>4. Threat intel (optional)</h2>',
    '<label class="', P, '-check"><input type="checkbox" id="', P, '-feed"><span>Use the mirrored malicious-IP feed (', FEED_URL, ')</span></label>',
    '<p class="', P, '-note" id="', P, '-feedinfo">Off. Turning it on loads a dated same-origin copy; it is not a live lookup.</p>',
    '<div class="', P, '-fields" style="margin-top:10px">', area("ownips", "Your own bad IPs", "one IP per line", "Joined with the feed when it is on, used alone when it is off."), "</div></div>",
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card" id="', P, '-results" style="display:none"><div class="', P, '-tabs" id="', P, '-tabs"></div><div id="', P, '-pane"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div><ul class="', P, '-skip" id="', P, '-skipped"></ul></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example" type="button">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, running = null, feed = null, tab = "findings", selFinding = -1;
  const sorts = { findings: { key: "severity", dir: "desc" }, users: { key: "risk", dir: "desc" }, apps: { key: "users", dir: "desc" }, dest: { key: "bytesOut", dir: "desc" } };
  let ffilter = { sev: "", q: "" };
  const columnMap = {};
  const datasetName = () => (isExample ? "synthetic example" : files.map((f) => f.name).join(", ").slice(0, 200));

  function renderFiles() {
    $("files").innerHTML = files.map((f, i) => {
      const d = f.det;
      const parsed = result ? (result.meta.files || []).find((x) => x.name === f.name) : null;
      return '<div class="' + P + '-file"><b>' + esc(f.name) + '</b><span class="' + P + '-mut">' + esc(fmtBytes(d.bytes)) + (f.fromArchive ? ", from archive" : "") + "</span><span>" + esc(d.label) + "</span>" +
        '<span class="' + P + "-conf " + confClass(d.confidence) + '">' + confClass(d.confidence) + " confidence</span>" +
        (parsed ? '<span class="' + P + '-mut">' + fmtNum(parsed.records) + " records" + (parsed.unparsed ? ", " + fmtNum(parsed.unparsed) + " unparsed" : "") + "</span>" : "") +
        '<button class="' + P + '-btn sm" data-rm="' + i + '" type="button">Remove</button></div>';
    }).join("");
    $("files").querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { files.splice(Number(b.dataset.rm), 1); isExample = false; renderFiles(); }));
    const bytes = files.reduce((n, f) => n + f.det.bytes, 0);
    $("count").textContent = files.length ? files.length + " file" + (files.length === 1 ? "" : "s") + ", " + fmtBytes(bytes) + (isExample ? " (synthetic example)" : "") : "";
    $("run").disabled = !files.length || !!running;
    $("clear").disabled = !files.length;
    renderMapping();
  }

  function renderMapping() {
    const low = files.filter((f) => f.det.confidence < 0.8 && f.det.headers && f.det.headers.length && !/^col\d+$/.test(f.det.headers[0] || ""));
    const box = $("map");
    if (!low.length) { box.innerHTML = ""; return; }
    const headers = [...new Set(low.flatMap((f) => f.det.headers))];
    box.innerHTML = '<div class="' + P + '-card" style="margin:12px 0 0"><h2>Column mapping</h2><p class="' + P + '-note">' + esc(low.map((f) => f.name + " (" + f.det.label + ")").join(", ")) + ": the layout was not recognised with high confidence. Check the columns below; checks that need an unmapped column are skipped and listed, never guessed. For a Squid custom logformat, map %&gt;st to Bytes sent and %&lt;st to Bytes received.</p>" +
      '<div class="' + P + '-fields" style="margin-top:10px">' + Object.keys(COLUMNS).map((k) => {
        const auto = (low[0].det.cols || {})[k];
        return '<div class="' + P + '-field"><label for="' + P + "-col-" + k + '">' + esc(COLUMN_LABELS[k] || k) + '</label><select id="' + P + "-col-" + k + '" data-col="' + esc(k) + '"><option value="">(not present)</option>' +
          headers.map((h) => '<option value="' + esc(h) + '"' + ((columnMap[k] || auto) === h ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>";
      }).join("") + "</div></div>";
    box.querySelectorAll("[data-col]").forEach((sel) => { if (sel.value) columnMap[sel.dataset.col] = sel.value; sel.addEventListener("change", () => { if (sel.value) columnMap[sel.dataset.col] = sel.value; else delete columnMap[sel.dataset.col]; }); });
  }

  function addFile(name, text, fromArchive) {
    const det = detectFile(name, text);
    if (det.format === "empty") { toast(name + " is empty", "warning"); return false; }
    if (det.format === "unknown") toast(name + ": format not recognised; it will be listed as skipped", "warning");
    const entry = { name, text, det, fromArchive: !!fromArchive };
    const idx = files.findIndex((x) => x.name === name);
    if (idx >= 0) files[idx] = entry; else files.push(entry);
    return true;
  }

  mountDropzone($("drop"), {
    maxBytes: 512 * 1024 * 1024, maxFiles: 100, multiple: true, unpack: true,
    label: "Drop gateway or proxy logs (or a zip / gz) here, paste, or browse",
    onFiles: async (list) => {
      let added = 0;
      if (isExample) { files = []; isExample = false; }
      for (const f of list) { try { if (addFile(f.name, await f.text(), f.fromArchive)) added++; } catch (e) { toast("Could not read " + f.name + ": " + ((e && e.message) || e), "error"); } }
      if (added) toast("Loaded " + added + " file" + (added === 1 ? "" : "s"), "success");
      result = null;
      renderFiles();
    },
  });

  $("clear").addEventListener("click", () => { files = []; isExample = false; result = null; renderFiles(); });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    files = []; isExample = true; result = null;
    for (const f of ex.files) addFile(f.name, f.text, false);
    renderFiles();
    toast("Synthetic example loaded: Zscaler LEEF and Squid logs. Click Hunt.", "info");
  });

  $("feed").addEventListener("change", async () => {
    const info = $("feedinfo");
    if (!$("feed").checked) { info.textContent = "Off. Turning it on loads a dated same-origin copy; it is not a live lookup."; return; }
    const show = (j) => { info.textContent = "Mirrored " + String(j.updated || "").slice(0, 10) + ": " + fmtNum(j.data.length) + " IPs from " + (j.source || "the mirror") + "."; };
    if (feed) { show(feed); return; }
    info.textContent = "Loading the mirrored list...";
    try {
      const res = await fetch(FEED_URL, { cache: "no-cache" });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const j = await res.json();
      if (!j || !Array.isArray(j.data)) throw new Error("unexpected feed shape");
      feed = j; show(j);
    } catch (e) {
      $("feed").checked = false;
      info.textContent = "The mirrored list could not be loaded (" + ((e && e.message) || e) + "). The check stays skipped unless you paste your own IPs.";
      toast("Malicious-IP mirror unavailable", "warning");
    }
  });

  const opts = () => {
    const o = { columns: { ...columnMap } };
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (el.value !== "" && Number.isFinite(n)) o[el.dataset.opt] = n; });
    o.sanctioned = $("sanctioned").value; o.ownDomains = $("own").value; o.allowHosts = $("allow").value;
    o.internalCidrs = $("internal").value; o.serverCidrs = $("servers").value;
    o.weekendOffHours = $("wk").checked; o.ignoreDevHosts = $("dev").checked;
    const own = $("ownips").value.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean).map((ip) => ({ ip, source: "your list" }));
    if (own.length || ($("feed").checked && feed)) o.maliciousIps = ($("feed").checked && feed ? feed.data : []).concat(own);
    return o;
  };

  $("cancel").addEventListener("click", () => { if (running) running.cancel(); });
  $("run").addEventListener("click", async () => {
    if (!files.length || running) return;
    const prog = $("prog"), bar = prog.firstElementChild, pl = $("plabel");
    prog.style.display = "block"; pl.style.display = "block"; bar.style.width = "0%"; pl.textContent = "starting the worker";
    $("run").disabled = true; $("cancel").hidden = false;
    const t0 = performance.now();
    try {
      running = runInWorker(ENGINE, "analyze", [files.map((f) => ({ name: f.name, text: f.text })), opts()], {
        timeoutMs: 30 * 60 * 1000,
        onProgress: (i, n, label) => { bar.style.width = (n ? Math.min(100, Math.round((i / n) * 100)) : 0) + "%"; pl.textContent = label || ""; },
      });
      result = await running;
      selFinding = -1; ffilter = { sev: "", q: "" }; tab = "findings";
      render(result);
      toast(result.findings.length + " finding" + (result.findings.length === 1 ? "" : "s") + " in " + fmtNum(result.summary.requests) + " requests (" + ((performance.now() - t0) / 1000).toFixed(1) + " s)", "success");
    } catch (e) {
      const m = (e && e.message) || String(e);
      toast(m === "cancelled" ? "Analysis cancelled" : "Analysis failed: " + m, m === "cancelled" ? "info" : "error");
    } finally {
      running = null;
      prog.style.display = "none"; pl.style.display = "none"; $("cancel").hidden = true; $("run").disabled = !files.length;
    }
  });

  function render(r) {
    const s = r.summary;
    $("kpis").innerHTML = kpi(fmtNum(s.requests), "requests") + kpi(fmtNum(s.users), "users") + kpi(fmtNum(s.apps), "apps discovered") +
      kpi(fmtNum(s.unsanctionedApps), "unsanctioned apps") + kpi(fmtNum(s.exfilCandidates), "upload exfil candidates") + kpi(fmtNum(s.aiServices), "AI services used") +
      kpi((s.bySeverity.critical + s.bySeverity.high) + " / " + s.findings, "high / all findings");
    $("skipped").innerHTML = r.skipped.length ? "<li><b>Skipped or limited checks</b></li>" + r.skipped.map((k) => "<li>" + esc(k.check) + ": " + esc(k.reason) + "</li>").join("") : "";
    $("results").style.display = "";
    renderFiles(); renderTabs(r); renderExports(r);
  }

  const emptyEl = (t) => { const d = document.createElement("div"); d.className = P + "-empty"; d.textContent = t; return d; };
  function renderTabs(r) {
    const t = r.tables;
    const tabs = [["findings", "Findings (" + r.findings.length + ")"], ["users", "Users (" + t.users.length + ")"], ["apps", "Apps / shadow SaaS (" + t.apps.length + ")"], ["dest", "Destinations (" + t.destinations.length + ")"], ["timeline", "Timeline"]];
    $("tabs").innerHTML = tabs.map(([k, l]) => '<button type="button" class="' + P + "-tab" + (tab === k ? " on" : "") + '" data-tab="' + k + '">' + esc(l) + "</button>").join("");
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; $("drawer").style.display = "none"; selFinding = -1; renderTabs(r); }));
    const pane = $("pane"); pane.innerHTML = "";
    if (tab === "findings") drawFindings(r);
    else if (tab === "users") pane.appendChild(t.users.length ? table(USER_COLS, t.users, sorts.users, (s) => { sorts.users = s; renderTabs(r); }) : emptyEl("No users."));
    else if (tab === "apps") pane.appendChild(t.apps.length ? table(APP_COLS, t.apps, sorts.apps, (s) => { sorts.apps = s; renderTabs(r); }) : emptyEl("No catalogued apps in this log."));
    else if (tab === "dest") pane.appendChild(t.destinations.length ? table(DEST_COLS, t.destinations, sorts.dest, (s) => { sorts.dest = s; renderTabs(r); }) : emptyEl("No destination hosts in this log."));
    else drawTimeline(r);
  }

  const bytesCol = (key, label) => ({ key, label, render: (x) => '<span class="' + P + '-nw">' + esc(fmtBytes(x[key])) + "</span>" });
  const FIND_COLS = [
    { key: "severity", label: "Severity", rank: SEV_RANK, render: (f) => pill(f.severity) },
    { key: "title", label: "Finding", render: (f) => "<b>" + esc(f.title) + '</b><div class="' + P + '-mut">' + esc(f.category) + "</div>" },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
    { key: "controls", label: "Controls", render: (f) => f.controls.slice(0, 4).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + (f.controls.length > 4 ? '<span class="' + P + '-chip">+' + (f.controls.length - 4) + "</span>" : "") },
    { key: "evidenceCount", label: "Evidence" },
  ];
  const USER_COLS = [
    { key: "user", label: "User / source", render: (u) => "<b>" + esc(u.user) + "</b>" + (u.server ? ' <span class="' + P + '-chip">non-user source</span>' : "") },
    { key: "risk", label: "Risk" }, { key: "worst", label: "Worst", rank: SEV_RANK, render: (u) => pill(u.worst) || "-" },
    { key: "requests", label: "Requests" }, bytesCol("bytesOut", "Sent"), bytesCol("bytesIn", "Received"), { key: "uploads", label: "Uploads" },
    { key: "blocked", label: "Blocked" }, { key: "apps", label: "Apps" }, { key: "riskyApps", label: "Unsanctioned" }, { key: "flags", label: "Rules hit" },
  ];
  const APP_COLS = [
    { key: "app", label: "App", render: (a) => "<b>" + esc(a.app) + "</b>" + (a.isNew ? ' <span class="' + P + '-chip unknown">new</span>' : "") + '<div class="' + P + '-mut">' + esc(a.domains) + "</div>" },
    { key: "category", label: "Category" }, { key: "sanctioned", label: "Sanctioned", render: (a) => '<span class="' + P + "-chip " + esc(a.sanctioned) + '">' + esc(a.sanctioned) + "</span>" + (a.instance ? '<div class="' + P + '-mut">' + esc(a.instance) + "</div>" : "") },
    { key: "users", label: "Users" }, { key: "requests", label: "Requests" }, { key: "uploads", label: "Uploads" }, bytesCol("bytesOut", "Sent"), bytesCol("bytesIn", "Received"),
    { key: "first", label: "First seen", render: (a) => '<span class="' + P + '-nw">' + esc(a.first) + "</span>" }, { key: "last", label: "Last seen", render: (a) => '<span class="' + P + '-nw">' + esc(a.last) + "</span>" },
  ];
  const DEST_COLS = [
    { key: "host", label: "Host", render: (h) => "<b>" + esc(h.host) + "</b>" + (h.malicious ? ' <span class="' + P + '-chip no">listed IP</span>' : "") },
    { key: "app", label: "App" }, { key: "category", label: "Gateway category" }, { key: "requests", label: "Requests" }, { key: "users", label: "Users" },
    bytesCol("bytesOut", "Sent"), bytesCol("bytesIn", "Received"), bytesCol("bytesUnknown", "Unknown dir."), { key: "blocked", label: "Blocked" },
    { key: "last", label: "Last seen", render: (h) => '<span class="' + P + '-nw">' + esc(h.last) + "</span>" },
  ];

  function drawFindings(r) {
    const pane = $("pane");
    if (!r.findings.length) { pane.appendChild(emptyEl("No findings for the current thresholds. Skipped checks are listed below.")); return; }
    const fl = document.createElement("div");
    fl.className = P + "-filters";
    fl.innerHTML = '<div class="' + P + '-field"><label for="' + P + '-fs">Severity</label><select id="' + P + '-fs" data-ff="sev"><option value="">All</option>' + ["critical", "high", "medium", "low", "info"].map((s) => '<option value="' + s + '"' + (ffilter.sev === s ? " selected" : "") + ">" + s + "</option>").join("") + "</select></div>" +
      '<div class="' + P + '-field"><label for="' + P + '-fq">Search</label><input id="' + P + '-fq" data-ff="q" type="search" placeholder="user, host, app" value="' + esc(ffilter.q) + '"></div>';
    pane.appendChild(fl);
    const box = document.createElement("div"); pane.appendChild(box);
    const draw = () => {
      const q = ffilter.q.trim().toLowerCase();
      const rows = r.findings.map((f, i) => ({ ...f, i })).filter((f) => (!ffilter.sev || f.severity === ffilter.sev) && (!q || [f.title, f.entity, f.description].some((v) => String(v || "").toLowerCase().includes(q))));
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
    d.style.display = "block";
    d.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + pill(f.severity) + " " + esc(f.title) + '</h3><button class="' + P + '-btn sm" data-close type="button">Close</button></div>' +
      "<p>" + esc(f.description) + "</p><p><b>Recommendation:</b> " + esc(f.recommendation) + "</p>" +
      "<p><b>Confidence:</b> " + esc(f.confidence) + " &middot; <b>Rule:</b> " + esc(f.rule) + (f.firstSeen ? " &middot; <b>Window:</b> " + esc(f.firstSeen + (f.lastSeen ? " to " + f.lastSeen : "")) : "") + "</p>" +
      "<p>" + f.controls.map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</p>" +
      (f.assets.length ? "<p><b>Assets:</b> " + f.assets.map((a) => esc(a.type + " " + a.name)).join(", ") + "</p>" : "") +
      "<p><b>Evidence</b> (" + f.evidence.length + " of " + f.evidenceCount + ")</p>" + evidenceTable(f.evidence) +
      '<div class="' + P + '-row"><button class="' + P + '-btn sm" data-ev type="button">Export evidence CSV</button></div>';
    d.querySelector("[data-close]").addEventListener("click", () => { d.style.display = "none"; selFinding = -1; renderTabs(r); });
    d.querySelector("[data-ev]").addEventListener("click", () => {
      const keys = [...new Set(f.evidence.flatMap((e) => Object.keys(e)))];
      const q = (v) => '"' + String(v == null ? "" : v).replace(/^(?=[=+@\t\r]|-(?!\d+(?:\.\d+)?$))/, "'").replace(/"/g, '""') + '"';
      download(TOOL_ID + "-evidence-" + fileStamp() + ".csv", [keys.join(","), ...f.evidence.map((e) => keys.map((k) => q(e[k])).join(","))].join("\n") + "\n", "text/csv");
    });
    d.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  function drawTimeline(r) {
    const pane = $("pane");
    const days = r.tables.daily.filter((x) => x.day !== "unknown");
    if (!days.length) { pane.appendChild(emptyEl("No timestamps.")); return; }
    const el = document.createElement("div");
    el.innerHTML = '<div class="' + P + '-tl">' + timelineSvg(days) + '<div class="' + P + '-tlx"><span>' + esc(days[0].day) + "</span><span>" + esc(days[days.length - 1].day) + "</span></div>" +
      '<div class="' + P + '-legend"><span><i class="' + P + '-sw" style="background:#b00020"></i>bytes sent (upload)</span><span><i class="' + P + '-sw" style="background:#9aa3b2"></i>bytes received + direction unknown</span><span>one pair of bars per business day (UTC' + (r.meta.settings.utcOffset >= 0 ? "+" : "") + r.meta.settings.utcOffset + "); hover for totals</span></div></div>";
    pane.appendChild(el);
    pane.appendChild(table([{ key: "day", label: "Day" }, { key: "requests", label: "Requests" }, { key: "users", label: "Users" }, bytesCol("bytesOut", "Sent"), bytesCol("bytesIn", "Received"), bytesCol("bytesUnknown", "Unknown dir."), { key: "blocked", label: "Blocked" }], days, { key: "day", dir: "asc" }, () => {}));
  }

  function renderExports(r) {
    const ex = $("exports");
    ex.innerHTML = ["csv:Findings CSV", "json:JSON", "txt:Summary TXT", "saas:Shadow-SaaS inventory CSV", "users:Per-user report TXT", "block:Blocklist TXT", "ucsv:Users CSV", "dcsv:Destinations CSV"].map((x) => { const [k, l] = x.split(":"); return '<button class="' + P + '-btn" type="button" data-x="' + k + '">' + l + "</button>"; }).join("");
    const stamp = fileStamp();
    const on = (k, fn) => ex.querySelector('[data-x="' + k + '"]').addEventListener("click", fn);
    on("csv", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    on("json", () => download(TOOL_ID + "-" + stamp + ".json", toJson({ ...r, summaryStats: summarize(r.findings) }), "application/json"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r), "text/plain"));
    on("saas", () => download(TOOL_ID + "-shadow-saas-" + stamp + ".csv", shadowSaasCsv(r.tables.apps), "text/csv"));
    on("users", () => download(TOOL_ID + "-users-report-" + stamp + ".txt", userReportText(r), "text/plain"));
    on("block", () => { const t = blocklistText(r.findings); if (t.split("\n").filter((l) => l && !l.startsWith("#")).length === 0) { toast("No confirmed or likely destinations to block", "info"); return; } download(TOOL_ID + "-blocklist-" + stamp + ".txt", t, "text/plain"); });
    on("ucsv", () => download(TOOL_ID + "-users-" + stamp + ".csv", tableToCsv("users", r.tables.users), "text/csv"));
    on("dcsv", () => download(TOOL_ID + "-destinations-" + stamp + ".csv", tableToCsv("destinations", r.tables.destinations), "text/csv"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: datasetName() });
  }

  renderFiles();
}
