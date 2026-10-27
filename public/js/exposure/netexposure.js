// Network Scan Diff (netexposure): Deck tool UI. Drop nmap (XML / -oG), masscan (JSON / XML), naabu,
// Nessus (.nessus) and Shodan exports, plus an optional Firewall Rule Audit JSON export. The engine
// runs in a Worker via ../ingest/worker.js; the end-of-life data is the same-origin, dated mirror at
// /data/feeds/eol-products.json. Nothing is fetched live. No native dialogs; toasts only.
//
//   renderNetExposure(main) -> void

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import {
  DEFAULTS, DEFAULT_INTERNAL, TOOL_ID, COLUMNS, RULES, SEV_RANK, parseInput, findingsToCsv, inventoryToCsv, changesToCsv,
  firewallTicketText, summaryText, exampleDataset,
} from "./netexposure-engine.js?v=20261026b";

const ENGINE = engineUrl("./netexposure-engine.js?v=20261026b", import.meta);
const P = "nxp";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const CONF_RANK = { confirmed: 3, likely: 2, review: 1 };
const EOL_RANK = { eol: 3, approaching: 2, unknown: 1, supported: 0 };
const TABLE_LIMIT = 500;

const CSS = `
  .nxp-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .nxp-root *{box-sizing:border-box}
  .nxp-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .nxp-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .nxp-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .nxp-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:100ch}
  .nxp-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .nxp-card h2{font-size:.95rem;margin:0 0 10px}
  .nxp-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .nxp-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .nxp-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer;max-width:100%;white-space:normal;text-align:left}
  .nxp-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .nxp-btn.sm{padding:4px 9px;font-size:.76rem}
  .nxp-btn:disabled{opacity:.5;cursor:default}
  .nxp-files{display:flex;flex-direction:column;gap:8px;margin-top:12px}
  .nxp-file{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 12px;font-size:.82rem;min-width:0}
  .nxp-file-hd{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center}
  .nxp-file-hd b{overflow-wrap:anywhere;min-width:0}
  .nxp-file .nxp-ctl{margin-top:8px}
  .nxp-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085)}
  .nxp-conf.high{color:#1b7f4d;border-color:#1b7f4d}.nxp-conf.medium{color:#8a6d00;border-color:#8a6d00}.nxp-conf.low{color:#b00020;border-color:#b00020}
  .nxp-ctl{display:flex;flex-wrap:wrap;gap:12px 18px;align-items:flex-start}
  .nxp-field{display:flex;flex-direction:column;gap:4px;min-width:0;flex:1 1 150px}
  .nxp-field.wide{flex:1 1 100%}
  .nxp-field.half{flex:1 1 280px}
  .nxp-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .nxp-field input,.nxp-field select,.nxp-field textarea{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%}
  .nxp-field input[type=checkbox]{width:auto}
  .nxp-field textarea{min-height:70px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}
  .nxp-field small{font-size:.74rem;color:var(--mut,#667085);line-height:1.4;overflow-wrap:anywhere}
  .nxp-check{display:flex;gap:8px;align-items:center;font-size:.84rem}
  .nxp-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .nxp-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:110px;flex:1 1 110px}
  .nxp-kpi b{display:block;font-size:1.3rem}
  .nxp-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .nxp-kpi.alert b{color:#b00020}
  .nxp-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .nxp-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .nxp-plabel{font-size:.74rem;color:var(--mut,#667085);margin-top:4px;display:none;overflow-wrap:anywhere}
  .nxp-tabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;border-bottom:1px solid var(--line,#e6e8ee);padding-bottom:8px}
  .nxp-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid transparent;background:none;color:var(--mut,#667085);padding:6px 12px;border-radius:8px;cursor:pointer}
  .nxp-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#d7dbe3);background:var(--bg,#f7f8fb)}
  .nxp-filters{display:flex;flex-wrap:wrap;gap:10px 16px;align-items:flex-end;margin-bottom:10px}
  .nxp-filters .nxp-field{flex:0 1 200px}
  .nxp-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .nxp-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:640px}
  .nxp-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .nxp-list th.on{color:var(--tx,#1a2230)}
  .nxp-list th.on::after{content:" \\2193";font-size:.7rem}
  .nxp-list th.on.asc::after{content:" \\2191"}
  .nxp-list td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word;word-break:normal}
  .nxp-list tr[data-i]{cursor:pointer}
  .nxp-list tr[data-i]:hover,.nxp-list tr.sel{background:var(--bg,#f7f8fb)}
  .nxp-nw{white-space:nowrap}
  .nxp-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem}
  .nxp-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .nxp-pill.critical{background:#7a0012}.nxp-pill.high{background:#b00020}.nxp-pill.medium{background:#b58100}.nxp-pill.low{background:#2552c6}.nxp-pill.info{background:#667085}
  .nxp-pill.eol{background:#b00020}.nxp-pill.approaching{background:#b58100}.nxp-pill.supported{background:#1b7f4d}.nxp-pill.unknown{background:#667085}
  .nxp-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .nxp-chip.ext{color:#b00020;border-color:#b00020;font-weight:700}
  .nxp-chip.ok{color:#1b7f4d;border-color:#1b7f4d}
  .nxp-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .nxp-drawer{margin-top:12px;display:none;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--bg,#f7f8fb);min-width:0}
  .nxp-drawer h3{margin:0 0 6px;font-size:1rem;overflow-wrap:anywhere}
  .nxp-drawer h4{margin:14px 0 4px;font-size:.86rem;overflow-wrap:anywhere}
  .nxp-drawer p{margin:6px 0;overflow-wrap:anywhere}
  .nxp-drawer pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.76rem;background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 10px;max-height:260px;overflow:auto;margin:6px 0}
  .nxp-drawer .nxp-list{background:var(--card,#fff);margin-top:8px}
  .nxp-drawer .nxp-list table{min-width:520px}
  .nxp-dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;font-size:.82rem;margin:8px 0}
  .nxp-dl dt{color:var(--mut,#667085)}.nxp-dl dd{margin:0;overflow-wrap:anywhere;min-width:0}
  .nxp-skip{font-size:.78rem;color:var(--mut,#667085);margin:10px 0 0;padding-left:18px}
  .nxp-skip li{overflow-wrap:anywhere}
  .nxp-rules summary{cursor:pointer;font-weight:600;font-size:.9rem}
  .nxp-rules .nxp-list table{min-width:600px}
  @media (max-width:560px){.nxp-field,.nxp-field.half,.nxp-filters .nxp-field{flex:1 1 100%}.nxp-dl{grid-template-columns:1fr}.nxp-card{padding:14px}.nxp-hd h1{font-size:1.4rem}}
`;

const kpi = (v, l, alert) => '<div class="' + P + "-kpi" + (alert ? " alert" : "") + '"><b>' + esc(v == null ? "-" : v) + "</b><span>" + esc(l) + "</span></div>";
const pill = (s) => (s ? '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>" : "");
const confClass = (c) => (c >= 0.8 ? "high" : c >= 0.5 ? "medium" : "low");
const zoneChip = (z) => (z === "external" ? '<span class="' + P + '-chip ext">external</span>' : z ? '<span class="' + P + '-chip">' + esc(z) + "</span>" : "");
const ipNum = (ip) => { const m = String(ip || "").match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/); return m ? ((+m[1] * 256 + +m[2]) * 256 + +m[3]) * 256 + +m[4] : null; };
const sortBy = (rows, key, dir, rank) => rows.slice().sort((a, b) => {
  const x = rank ? (rank[a[key]] ?? -1) : a[key], y = rank ? (rank[b[key]] ?? -1) : b[key];
  let r;
  if (key === "ip" && ipNum(x) != null && ipNum(y) != null) r = ipNum(x) - ipNum(y);
  else if (typeof x === "number" && typeof y === "number") r = x - y;
  else if (typeof x === "boolean" || typeof y === "boolean") r = Number(!!x) - Number(!!y);
  else r = cmp(String(x == null ? "" : x).toLowerCase(), String(y == null ? "" : y).toLowerCase());
  return dir === "asc" ? r : -r;
});

/** Sortable table: cols = [{key, label, render?, rank?}]. */
function table(cols, rows, sort, onSort, rowKey, limit) {
  const sorted = sortBy(rows, sort.key, sort.dir, (cols.find((c) => c.key === sort.key) || {}).rank);
  const shown = limit ? sorted.slice(0, limit) : sorted;
  const el = document.createElement("div");
  el.className = P + "-list";
  el.innerHTML = "<table><thead><tr>" + cols.map((c) => '<th data-k="' + esc(c.key) + '" class="' + (sort.key === c.key ? "on " + sort.dir : "") + '">' + esc(c.label) + "</th>").join("") + "</tr></thead><tbody>" +
    shown.map((r) => "<tr" + (rowKey ? ' data-i="' + esc(rowKey(r)) + '"' : "") + ">" + cols.map((c) => "<td>" + (c.render ? c.render(r) : esc(r[c.key] == null ? "" : r[c.key])) + "</td>").join("") + "</tr>").join("") + "</tbody></table>";
  el.querySelectorAll("th").forEach((th) => th.addEventListener("click", () => { const k = th.dataset.k; onSort({ key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" }); }));
  return el;
}

/** Plain table for evidence rows: columns are the union of keys. */
function evidenceTable(rows) {
  if (!rows || !rows.length) return '<p class="' + P + '-note">No evidence rows.</p>';
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
  const cell = (k, v) => (k === "severity" ? pill(v) : esc(v === true ? "yes" : v === false ? "no" : v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v)));
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => "<td>" + cell(k, r[k]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}
const csvCell = (v) => { const s = v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v); return /[",\n\r]/.test(s) || /^[=+\-@]/.test(s) ? '"' + (/^[=+\-@]/.test(s) ? "'" : "") + s.replace(/"/g, '""') + '"' : s; };

function settingsHtml() {
  const d = DEFAULTS;
  const num = (id, label, v, help, min = 0) => '<div class="' + P + '-field"><label for="' + P + "-o-" + id + '">' + label + '</label><input id="' + P + "-o-" + id + '" type="number" min="' + min + '" step="1" value="' + esc(v) + '"><small>' + help + "</small></div>";
  return '<div class="' + P + '-ctl">' +
    '<div class="' + P + '-field half"><label for="' + P + '-o-cidrs">Internal networks</label><textarea id="' + P + '-o-cidrs" placeholder="blank = defaults" spellcheck="false"></textarea><small>One CIDR per line. Blank uses ' + esc(DEFAULT_INTERNAL.join(", ")) + ". Anything else counts as internet-facing, unless the scan is marked as run from outside, which makes every address in it external.</small></div>" +
    '<div class="' + P + '-field half"><label for="' + P + '-o-allow">Approved exposures (allow-list)</label><textarea id="' + P + '-o-allow" placeholder="host:port reason" spellcheck="false"></textarea><small>One per line: address or CIDR, port (or *), optional /tcp or /udp, then the reason. Examples: 198.51.100.7:443 public web; *:22 bastions; 10.0.0.0/8:445/tcp file servers. Allow-listed services stay in the inventory with the reason but raise no finding.</small></div>' +
    num("cert", "Certificate warning (days)", d.certWarnDays, "Report certificates that expire within this many days.", 1) +
    num("eolw", "End-of-life warning (days)", d.eolWarnDays, "Report releases that reach end of life within this many days.", 1) +
    num("rsa", "Minimum RSA / DSA key (bits)", d.minRsaBits, "NIST SP 800-131A: 2048.", 512) +
    '<div class="' + P + '-field"><label for="' + P + '-o-now">Reference date</label><input id="' + P + '-o-now" type="date"><small>Blank = the newest scan time. Used for certificate expiry and end of life.</small></div>' +
    '<div class="' + P + '-field"><label>Internal exposure</label><span class="' + P + '-check"><input id="' + P + '-o-int" type="checkbox"' + (d.reportInternal ? " checked" : "") + '> report risky internal services</span><small>Off = only internet-facing exposures raise risk findings.</small></div>' +
    "</div>" +
    '<details class="' + P + '-rules" style="margin-top:12px"><summary>Risk rule table (' + RULES.length + " rules)</summary>" +
    '<p class="' + P + '-note">Severity when the service is reachable from the internet and when it is only reachable internally ("-" = not reported internally). Matched on the port, the service name nmap / the scanner reported, the product banner or the HTTP title; a well-known port with a different identified service does not match.</p>' +
    '<div class="' + P + '-list"><table><thead><tr><th>Service</th><th>Ports</th><th>External</th><th>Internal</th><th>Why</th></tr></thead><tbody>' +
    RULES.map((r) => "<tr><td><b>" + esc(r.label) + "</b></td><td>" + esc((r.ports || []).join(", ") + (r.proto !== "tcp" ? " (" + r.proto + ")" : "")) + "</td><td>" + pill(r.ext) + "</td><td>" + (r.int ? pill(r.int) : "-") + "</td><td>" + esc(r.why) + "</td></tr>").join("") +
    "</tbody></table></div></details>";
}
/** Mount the tool into main. */
export function renderNetExposure(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Network Scan Diff</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Turns port-scan exports into an exposure inventory: risky services reachable from the internet or inside, end-of-life software, certificate, TLS, SSH, SMB and RDP weaknesses, and what changed between scans. Runs entirely in your browser. Nothing is uploaded and nothing is fetched live; end-of-life dates come from a mirrored, dated copy of endoflife.date served by this site.</p>',
    '<div class="', P, '-card"><h2>1. Scan exports</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-note">Accepted: nmap XML (-oX, including NSE script output) and grepable (-oG), masscan JSON (-oJ) and XML (-oX), naabu JSON lines (-json), Nessus .nessus v2 (ports and services only; use Vulnerability Import for its vulnerabilities), Shodan NDJSON (shodan download / parse) or host JSON, any CSV with an IP and a port column, and optionally a Firewall Rule Audit JSON export for the segmentation check. Zip and gzip archives are unpacked locally. Up to 100 files, 512 MB each; very large files are parsed in the worker.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div>',
    '<div id="', P, '-map"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button><button class="', P, '-btn" id="', P, '-clear" disabled>Clear files</button><span class="', P, '-note" id="', P, '-count"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-plabel" id="', P, '-plabel"></div></div>',
    '<div class="', P, '-card"><h2>2. Settings</h2>', settingsHtml(), '<p class="', P, '-note" id="', P, '-feed">End-of-life feed: loading.</p></div>',
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card" id="', P, '-results" style="display:none"><div class="', P, '-tabs" id="', P, '-tabs"></div><div id="', P, '-pane"></div><div class="', P, '-drawer" id="', P, '-drawer"></div><ul class="', P, '-skip" id="', P, '-skipped"></ul></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, running = false, tab = "findings", selected = "";
  let eolFeed = null;
  const columnMap = {};
  const sorts = { findings: { key: "severity", dir: "desc" }, hosts: { key: "riskScore", dir: "desc" }, services: { key: "severity", dir: "desc" }, ports: { key: "hosts", dir: "desc" }, certs: { key: "daysLeft", dir: "asc" }, changes: { key: "severity", dir: "desc" }, eol: { key: "status", dir: "desc" } };
  const filters = { q: "", zone: "", type: "", risky: false, serviceView: "inventory" };

  // ---- end-of-life mirror (same origin, loaded on mount) ----
  const renderFeed = () => { $("feed").textContent = eolFeed ? "End-of-life feed: endoflife.date, mirrored " + String(eolFeed.updated || "").slice(0, 10) + ", " + (eolFeed.count || (eolFeed.data || []).length) + " products." : "End-of-life feed: not loaded, so end-of-life checks are skipped."; };
  fetch("/data/feeds/eol-products.json").then((r) => (r.ok ? r.json() : null)).then((j) => { if (j && Array.isArray(j.data)) eolFeed = j; renderFeed(); }).catch(() => renderFeed());

  // ---- files and the scans panel ----
  const datasetName = () => (isExample ? "synthetic example" : files.map((f) => f.name).join(", "));
  const scanFiles = () => files.filter((f) => f.format !== "fwaudit");

  function renderFiles() {
    const box = $("files");
    box.innerHTML = files.map((f, i) => {
      const isFw = f.format === "fwaudit";
      return '<div class="' + P + '-file"><div class="' + P + '-file-hd"><b>' + esc(f.name) + "</b><span>" + esc(f.label) + "</span>" +
        '<span class="' + P + "-conf " + confClass(f.confidence) + '">' + confClass(f.confidence) + " confidence</span><span>" + (isFw ? f.records + " firewall rules" : f.hosts + " hosts, " + f.records + " ports") + "</span>" +
        (f.time ? '<span class="' + P + '-nw">' + esc(f.time.replace("T", " ").replace(/:\d\dZ$/, " UTC")) + "</span>" : "") +
        '<button class="' + P + '-btn sm" data-rm="' + i + '" type="button">Remove</button></div>' +
        (isFw ? '<p class="' + P + '-note">Used only for the segmentation check against scans marked as run from outside.</p>' :
          '<div class="' + P + '-ctl">' +
          '<div class="' + P + '-field"><label for="' + P + "-s-label-" + i + '">Scan label</label><input id="' + P + "-s-label-" + i + '" data-s="label" data-f="' + i + '" value="' + esc(f.scan.label) + '" placeholder="file name"><small>Files with the same label form one scan.</small></div>' +
          '<div class="' + P + '-field"><label for="' + P + "-s-order-" + i + '">Order</label><input id="' + P + "-s-order-" + i + '" data-s="order" data-f="' + i + '" type="number" min="1" step="1" value="' + esc(f.scan.order) + '" placeholder="by time"><small>Blank = by scan time.</small></div>' +
          '<div class="' + P + '-field"><label for="' + P + "-s-ports-" + i + '">Ports scanned</label><input id="' + P + "-s-ports-" + i + '" data-s="ports" data-f="' + i + '" value="' + esc(f.scan.ports) + '" placeholder="e.g. 1-65535" spellcheck="false"><small>' + (f.portsScanned ? "Recorded in the file: " + f.portsScanned + " ports." : "Not recorded in the file. Enter the range so closed ports can be told apart from unscanned ones.") + "</small></div>" +
          '<div class="' + P + '-field"><label>Vantage point</label><span class="' + P + '-check"><input type="checkbox" data-s="external" data-f="' + i + '"' + (f.scan.external ? " checked" : "") + "> scanned from outside</span><small>Everything this scan reached counts as internet-facing.</small></div>" +
          "</div>") +
        (f.notes && f.notes.length ? '<p class="' + P + '-note">' + esc(f.notes.join("; ")) + "</p>" : "") + "</div>";
    }).join("");
    box.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { files.splice(Number(b.dataset.rm), 1); if (!files.length) isExample = false; renderFiles(); }));
    box.querySelectorAll("[data-s]").forEach((el) => el.addEventListener(el.type === "checkbox" ? "change" : "input", () => {
      const f = files[Number(el.dataset.f)];
      f.scan[el.dataset.s] = el.type === "checkbox" ? el.checked : el.value;
    }));
    const n = scanFiles().length;
    $("count").textContent = files.length ? n + " scan file" + (n === 1 ? "" : "s") + (files.length > n ? " + firewall export" : "") + ", " + scanFiles().reduce((s, f) => s + f.records, 0) + " ports" + (isExample ? " (synthetic example)" : "") : "";
    $("run").disabled = !n || running;
    $("clear").disabled = !files.length;
    renderMapping();
  }

  function renderMapping() {
    const generic = files.filter((f) => f.format === "csv" && f.confidence < 0.8);
    const box = $("map");
    if (!generic.length) { box.innerHTML = ""; return; }
    const headers = [...new Set(generic.flatMap((f) => f.headers))];
    const norm = (h) => String(h).toLowerCase().replace(/[^a-z0-9]/g, "");
    box.innerHTML = '<div class="' + P + '-card" style="margin:12px 0 0"><h2>Column mapping</h2><p class="' + P + '-note">' + esc(generic.map((f) => f.name).join(", ")) + ": the IP and port columns were not recognised. Map at least IP and port.</p>" +
      '<div class="' + P + '-ctl">' + Object.keys(COLUMNS).map((k) => '<div class="' + P + '-field"><label for="' + P + "-c-" + k + '">' + esc(k) + '</label><select id="' + P + "-c-" + k + '" data-col="' + esc(k) + '"><option value="">(not present)</option>' +
        headers.map((h) => '<option value="' + esc(h) + '"' + (columnMap[k] === h || (!columnMap[k] && (COLUMNS[k] || []).some((a) => norm(a) === norm(h))) ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>").join("") + "</div></div>";
    box.querySelectorAll("[data-col]").forEach((sel) => {
      if (sel.value) columnMap[sel.dataset.col] = sel.value;
      sel.addEventListener("change", () => { if (sel.value) columnMap[sel.dataset.col] = sel.value; else delete columnMap[sel.dataset.col]; reparseCsv(); });
    });
  }
  function reparseCsv() {
    for (const f of files) if (f.format === "csv") { const pf = parseInput([{ name: f.name, text: f.text }], { columns: columnMap }).files[0]; if (pf) { f.records = pf.records; f.hosts = pf.hosts; f.notes = pf.notes; } }
    const keep = $("map").innerHTML;
    renderFiles();
    if (!$("map").innerHTML) $("map").innerHTML = keep;
  }

  // For a quick format check of a large file: the head, cut at the last complete line / element.
  function sampleOf(text) { const head = text.slice(0, 262144); const t = head.trimStart()[0]; if (t === "[" ) return text; const nl = head.lastIndexOf("\n"); return nl > 0 ? head.slice(0, nl) : head; }
  function addFile(name, text, scan) {
    const big = text.length > 4 * 1024 * 1024;
    const pf = parseInput([{ name, text: big ? sampleOf(text) : text }], { columns: columnMap }).files[0];
    if (!pf || pf.format === "unknown") { toast("Not a recognised scan export: " + name, "warning"); return false; }
    const entry = { name, text, format: pf.format, label: pf.label, confidence: pf.confidence, headers: pf.headers || [], records: big ? 0 : pf.records, hosts: big ? 0 : pf.hosts, time: pf.time || "",
      portsScanned: pf.portsScanned || null, notes: big ? ["large file: counts are filled in during analysis"].concat(pf.notes || []) : pf.notes || [],
      scan: { label: (scan && scan.label) || "", order: scan && scan.order != null ? String(scan.order) : "", ports: (scan && scan.ports) || "", external: scan && scan.external != null ? !!scan.external : !!pf.external } };
    const idx = files.findIndex((x) => x.name === name);
    if (idx >= 0) files[idx] = entry; else files.push(entry);
    return true;
  }

  mountDropzone($("drop"), {
    maxBytes: 512 * 1024 * 1024, maxFiles: 100, unpack: true, multiple: true,
    label: "Drop scan exports here, paste, or browse",
    onFiles: async (list) => {
      if (isExample) { files = []; isExample = false; $("o-allow").value = ""; }
      let added = 0;
      for (const f of list) { if (addFile(f.name, await f.text())) added++; }
      if (added) toast("Added " + added + " file" + (added === 1 ? "" : "s"), "success");
      renderFiles();
    },
  });
  $("clear").addEventListener("click", () => { files = []; isExample = false; result = null; $("results").style.display = "none"; $("kpis").innerHTML = ""; $("exports").innerHTML = ""; renderFiles(); });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    files = []; isExample = true;
    for (const f of ex.files) addFile(f.name, f.text, ex.scans[f.name]);
    $("o-allow").value = ex.allowList || "";
    renderFiles();
    toast("Synthetic example loaded: two internal weekly scans and one external scan. Click Analyze.", "info");
  });

  // ---- options ----
  const opts = () => {
    const num = (id, d, min) => { const v = Number($("o-" + id).value); return Number.isFinite(v) && v >= min ? v : d; };
    const scans = {};
    for (const f of scanFiles()) {
      const s = {};
      if (f.scan.label.trim()) s.label = f.scan.label.trim();
      if (String(f.scan.order).trim() && Number.isFinite(Number(f.scan.order))) s.order = Number(f.scan.order);
      if (f.scan.ports.trim()) s.ports = f.scan.ports.trim();
      s.external = !!f.scan.external;
      scans[f.name] = s;
    }
    const o = {
      internalCidrs: $("o-cidrs").value.trim(), allowList: $("o-allow").value, certWarnDays: num("cert", DEFAULTS.certWarnDays, 1), eolWarnDays: num("eolw", DEFAULTS.eolWarnDays, 1),
      minRsaBits: num("rsa", DEFAULTS.minRsaBits, 512), reportInternal: $("o-int").checked, columns: { ...columnMap }, scans, eol: eolFeed,
    };
    const now = $("o-now").value.trim(); if (now) o.now = now + "T12:00:00Z";
    return o;
  };

  async function run() {
    if (!scanFiles().length || running) return;
    running = true;
    const prog = $("prog"), bar = prog.firstElementChild, pl = $("plabel");
    prog.style.display = "block"; pl.style.display = "block"; bar.style.width = "0%"; pl.textContent = "starting"; $("run").disabled = true;
    try {
      result = await runInWorker(ENGINE, "analyze", [files.map((f) => ({ name: f.name, text: f.text })), opts()], {
        timeoutMs: 600000,
        onProgress: (i, n, label) => { bar.style.width = (n ? Math.min(100, Math.round((i / n) * 100)) : 50) + "%"; if (label) pl.textContent = label + (n ? "" : " " + i); },
      });
      for (const mf of result.meta.files) { const f = files.find((x) => x.name === mf.name); if (f) { f.records = mf.records; f.hosts = mf.hosts; } }
      selected = ""; $("drawer").style.display = "none";
      render();
      const s = result.summary;
      toast(s.hosts + " hosts, " + s.openPorts + " open ports, " + result.findings.length + " findings", "success");
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
    const r = result, s = r.summary;
    $("kpis").innerHTML = kpi(s.hosts, "hosts up") + kpi(s.openPorts, "open ports") + kpi(s.externalPorts, "internet-facing ports") +
      kpi(s.riskyExternal, "risky exposures (external)", s.riskyExternal > 0) + kpi(s.riskyInternal, "risky internal") + kpi(s.eolServices, "end-of-life services", s.eolServices > 0) +
      kpi(s.certIssues, "certificate issues") + kpi(s.newSinceLast, "new since last scan", s.newSinceLast > 0) + kpi(s.scans, "scans");
    $("results").style.display = "";
    $("skipped").innerHTML = r.skipped.length ? "<li><b>Skipped or limited checks</b></li>" + r.skipped.map((k) => "<li>" + esc(k.check) + ": " + esc(k.reason) + "</li>").join("") : "";
    const tabs = [["findings", "Findings (" + r.findings.length + ")"], ["hosts", "Hosts (" + r.tables.hosts.length + ")"], ["services", "Services (" + r.tables.exposures.length + ")"],
      ["certs", "Certificates (" + r.tables.certificates.length + ")"], ["changes", "Changes (" + r.tables.changes.length + ")"], ["eol", "End of life (" + r.tables.eol.filter((e) => e.status !== "supported").length + ")"]];
    $("tabs").innerHTML = tabs.map(([k, l]) => '<button type="button" class="' + P + "-tab" + (tab === k ? " on" : "") + '" data-tab="' + k + '">' + esc(l) + "</button>").join("");
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; closeDrawer(); render(); }));
    drawPane();
    renderExports();
  }

  function drawPane() {
    const pane = $("pane");
    pane.innerHTML = "";
    if (tab === "findings") return drawFindings(pane);
    if (tab === "hosts") return drawHosts(pane);
    if (tab === "services") return drawServices(pane);
    if (tab === "certs") return drawSimple(pane, "certs", CERT_COLS, result.tables.certificates, (c) => c.ip + "|" + c.port, (k) => showService(k.split("|")[0], Number(k.split("|")[1])), "Sorted by days left. Click a row for the full scanner output.");
    if (tab === "changes") return drawChanges(pane);
    if (tab === "eol") return drawSimple(pane, "eol", EOL_COLS, result.tables.eol, (e) => e.ip + "|" + e.port + "|" + e.slug, (k) => showService(k.split("|")[0], Number(k.split("|")[1])),
      "Matched against endoflife.date (mirrored " + esc(String(result.summary.eolFeedUpdated || "").slice(0, 10) || "not loaded") + "). OpenSSH has no endoflife.date entry, so it is mapped to the Debian / Ubuntu release its package suffix names; plain upstream versions are not guessed. Banners can lag distribution back-ports.");
  }

  // Column sets
  const FIND_COLS = [
    { key: "severity", label: "Severity", rank: SEV_RANK, render: (f) => pill(f.severity) },
    { key: "title", label: "Finding", render: (f) => "<b>" + esc(f.title) + "</b><div>" + esc(f.description) + "</div>" },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
    { key: "category", label: "Category" },
    { key: "controls", label: "Controls", render: (f) => (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") },
    { key: "evidenceCount", label: "Evidence" },
  ];
  const HOST_COLS = [
    { key: "riskScore", label: "Risk" },
    { key: "ip", label: "IP", render: (h) => '<span class="' + P + '-nw">' + esc(h.ip) + "</span>" + (h.current ? "" : ' <span class="' + P + '-chip">not seen in latest</span>') },
    { key: "hostnames", label: "Names" },
    { key: "zone", label: "Zone", render: (h) => zoneChip(h.zone) },
    { key: "openPorts", label: "Open" },
    { key: "ports", label: "Ports", render: (h) => '<span class="' + P + '-mono">' + esc(h.ports) + "</span>" },
    { key: "os", label: "OS" },
    { key: "flags", label: "Issues" },
    { key: "lastScan", label: "Last scan" },
  ];
  const SVC_COLS = [
    { key: "severity", label: "Risk", rank: SEV_RANK, render: (e) => pill(e.severity) + (e.allowListed ? ' <span class="' + P + '-chip ok">approved</span>' : "") },
    { key: "ip", label: "IP", render: (e) => '<span class="' + P + '-nw">' + esc(e.ip) + "</span>" },
    { key: "port", label: "Port", render: (e) => '<span class="' + P + '-nw">' + esc(e.port + "/" + e.proto) + "</span>" },
    { key: "zone", label: "Zone", render: (e) => zoneChip(e.zone) },
    { key: "service", label: "Service" },
    { key: "product", label: "Product", render: (e) => esc([e.product, e.version].filter(Boolean).join(" ")) },
    { key: "ruleLabel", label: "Rule" },
    { key: "tls", label: "TLS" },
    { key: "hostnames", label: "Names" },
    { key: "firstSeen", label: "First seen" },
  ];
  const PORT_COLS = [
    { key: "port", label: "Port", render: (s) => '<span class="' + P + '-nw">' + esc(s.port + "/" + s.proto) + "</span>" },
    { key: "service", label: "Service" },
    { key: "product", label: "Product", render: (s) => esc([s.product, s.version].filter(Boolean).join(" ")) },
    { key: "hosts", label: "Hosts" }, { key: "external", label: "External" }, { key: "risk", label: "Rule" },
    { key: "ips", label: "Addresses", render: (s) => '<span class="' + P + '-mono">' + esc(s.ips) + "</span>" },
  ];
  const CERT_COLS = [
    { key: "daysLeft", label: "Days left", render: (c) => esc(c.daysLeft == null ? "-" : c.daysLeft) },
    { key: "ip", label: "Endpoint", render: (c) => '<span class="' + P + '-nw">' + esc(c.ip + ":" + c.port) + "</span>" },
    { key: "zone", label: "Zone", render: (c) => zoneChip(c.zone) },
    { key: "subject", label: "Subject" }, { key: "issuer", label: "Issuer" },
    { key: "notAfter", label: "Expires", render: (c) => '<span class="' + P + '-nw">' + esc(c.notAfter) + "</span>" },
    { key: "key", label: "Key" }, { key: "sigAlg", label: "Signature" },
    { key: "issues", label: "Issues", render: (c) => (c.issues ? '<b>' + esc(c.issues) + "</b>" : '<span class="' + P + '-chip ok">none</span>') },
  ];
  const CHG_COLS = [
    { key: "severity", label: "Severity", rank: SEV_RANK, render: (c) => pill(c.severity) },
    { key: "type", label: "Change" },
    { key: "ip", label: "Where", render: (c) => '<span class="' + P + '-nw">' + esc(c.ip ? c.ip + (c.port ? ":" + c.port + "/" + c.proto : "") : "scan") + "</span>" },
    { key: "zone", label: "Zone", render: (c) => zoneChip(c.zone) },
    { key: "before", label: "Before" }, { key: "after", label: "After" }, { key: "detail", label: "Detail" },
    { key: "toScan", label: "Scans", render: (c) => esc(c.fromScan + " to " + c.toScan) },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
  ];
  const EOL_COLS = [
    { key: "status", label: "Status", rank: EOL_RANK, render: (e) => pill(e.status) },
    { key: "ip", label: "Endpoint", render: (e) => '<span class="' + P + '-nw">' + esc(e.ip + ":" + e.port) + "</span>" },
    { key: "zone", label: "Zone", render: (e) => zoneChip(e.zone) },
    { key: "product", label: "Seen as" },
    { key: "slug", label: "Release", render: (e) => esc(e.slug + " " + e.cycle) },
    { key: "eol", label: "End of life", render: (e) => '<span class="' + P + '-nw">' + esc(e.eol) + "</span>" },
    { key: "extendedSupport", label: "Extended support" },
    { key: "latest", label: "Latest in cycle" },
    { key: "source", label: "Identified from" },
  ];

  function drawSimple(pane, name, cols, rows, keyOf, onPick, note) {
    if (!rows.length) { pane.innerHTML = '<div class="' + P + '-empty">Nothing to show.</div>'; return; }
    const t = table(cols, rows, sorts[name], (s) => { sorts[name] = s; drawPane(); }, keyOf, TABLE_LIMIT);
    t.querySelectorAll("tr[data-i]").forEach((tr) => { if (tr.dataset.i === selected) tr.classList.add("sel"); tr.addEventListener("click", () => { selected = tr.dataset.i; onPick(tr.dataset.i); markSel(pane); }); });
    pane.appendChild(t);
    pane.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">' + (rows.length > TABLE_LIMIT ? "Showing " + TABLE_LIMIT + " of " + rows.length + " rows in the current sort; the CSV exports have all rows. " : "") + (note || "") + "</p>");
  }
  const markSel = (pane) => pane.querySelectorAll("tr[data-i]").forEach((tr) => tr.classList.toggle("sel", tr.dataset.i === selected));

  function filterBar(pane, items, onChange) {
    const bar = document.createElement("div");
    bar.className = P + "-filters";
    bar.innerHTML = items.join("");
    pane.appendChild(bar);
    bar.querySelectorAll("[data-flt]").forEach((el) => el.addEventListener(el.type === "checkbox" ? "change" : "input", () => { filters[el.dataset.flt] = el.type === "checkbox" ? el.checked : el.value; onChange(); }));
    const box = document.createElement("div");
    pane.appendChild(box);
    return box;
  }
  const searchField = () => '<div class="' + P + '-field"><label for="' + P + '-f-q">Search</label><input id="' + P + '-f-q" data-flt="q" type="search" placeholder="IP, name, product" value="' + esc(filters.q) + '"></div>';
  const selectField = (id, label, options) => '<div class="' + P + '-field"><label for="' + P + "-f-" + id + '">' + label + '</label><select id="' + P + "-f-" + id + '" data-flt="' + id + '"><option value="">All</option>' + options.map((o) => '<option value="' + esc(o) + '"' + (filters[id] === o ? " selected" : "") + ">" + esc(o) + "</option>").join("") + "</select></div>";
  const matchQ = (vals) => { const q = filters.q.trim().toLowerCase(); return !q || vals.some((x) => String(x == null ? "" : x).toLowerCase().includes(q)); };

  function drawFindings(pane) {
    const r = result;
    if (!r.findings.length) { pane.innerHTML = '<div class="' + P + '-empty">No findings. Every open service is either low risk or approved.</div>'; return; }
    const rows = r.findings.map((f, i) => ({ ...f, i }));
    const t = table(FIND_COLS, rows, sorts.findings, (s) => { sorts.findings = s; drawPane(); }, (f) => f.i);
    t.querySelectorAll("tr[data-i]").forEach((tr) => { if (tr.dataset.i === selected) tr.classList.add("sel"); tr.addEventListener("click", () => { selected = tr.dataset.i; markSel(pane); showFinding(r.findings[Number(selected)]); }); });
    pane.appendChild(t);
    pane.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">Click a finding for its evidence table and the raw scanner output behind it.</p>');
  }

  function drawHosts(pane) {
    const r = result;
    const box = filterBar(pane, [searchField(), selectField("zone", "Zone", ["external", "internal"])], () => draw());
    const draw = () => {
      const rows = r.tables.hosts.filter((h) => (!filters.zone || h.zone === filters.zone) && matchQ([h.ip, h.hostnames, h.os, h.ports, h.flags]));
      box.innerHTML = "";
      if (!rows.length) { box.innerHTML = '<div class="' + P + '-empty">No hosts match.</div>'; return; }
      const t = table(HOST_COLS, rows, sorts.hosts, (s) => { sorts.hosts = s; draw(); }, (h) => h.ip, TABLE_LIMIT);
      t.querySelectorAll("tr[data-i]").forEach((tr) => { if (tr.dataset.i === selected) tr.classList.add("sel"); tr.addEventListener("click", () => { selected = tr.dataset.i; markSel(box); showHost(selected); }); });
      box.appendChild(t);
      box.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">Risk = 40 per critical, 20 per high, 8 per medium and 3 per low issue on the host, capped at 100. ' + rows.length + " of " + r.tables.hosts.length + " hosts.</p>");
    };
    draw();
  }

  function drawServices(pane) {
    const r = result;
    const box = filterBar(pane, [searchField(), selectField("zone", "Zone", ["external", "internal"]),
      '<label class="' + P + '-check"><input type="checkbox" data-flt="risky"' + (filters.risky ? " checked" : "") + "> risky only</label>",
      selectField("serviceView", "View", ["by port"]).replace('<option value="">All</option>', '<option value="">per address</option>')], () => draw());
    const draw = () => {
      box.innerHTML = "";
      if (filters.serviceView === "by port") {
        const rows = r.tables.services.filter((s) => (!filters.risky || s.risk) && (!filters.zone || (filters.zone === "external" ? s.external > 0 : s.hosts > s.external)) && matchQ([s.port, s.service, s.product, s.version, s.ips]));
        if (!rows.length) { box.innerHTML = '<div class="' + P + '-empty">No services match.</div>'; return; }
        box.appendChild(table(PORT_COLS, rows, sorts.ports, (s) => { sorts.ports = s; draw(); }, null, TABLE_LIMIT));
        return;
      }
      const rows = r.tables.exposures.filter((e) => (!filters.risky || e.rule) && (!filters.zone || e.zone === filters.zone) && matchQ([e.ip, e.hostnames, e.port, e.service, e.product, e.version, e.ruleLabel]));
      if (!rows.length) { box.innerHTML = '<div class="' + P + '-empty">No services match.</div>'; return; }
      const t = table(SVC_COLS, rows, sorts.services, (s) => { sorts.services = s; draw(); }, (e) => e.ip + "|" + e.port + "|" + e.proto, TABLE_LIMIT);
      t.querySelectorAll("tr[data-i]").forEach((tr) => { if (tr.dataset.i === selected) tr.classList.add("sel"); tr.addEventListener("click", () => { selected = tr.dataset.i; markSel(box); const [ip, port, proto] = selected.split("|"); showService(ip, Number(port), proto); }); });
      box.appendChild(t);
      box.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">Current state: each port as of the latest scan that saw the host and covered the port. ' + rows.length + " of " + r.tables.exposures.length + " open ports. Click a row for the raw scanner output.</p>");
    };
    draw();
  }

  function drawChanges(pane) {
    const r = result;
    pane.insertAdjacentHTML("beforeend", "<h4 style=\"margin:0 0 6px;font-size:.86rem\">Scan timeline</h4>");
    const tl = document.createElement("div");
    tl.className = P + "-list";
    tl.innerHTML = "<table><thead><tr><th>#</th><th>Scan</th><th>Time</th><th>Scanner</th><th>Vantage</th><th>Hosts up</th><th>Open ports</th><th>Ports scanned</th><th>Targets</th></tr></thead><tbody>" +
      r.tables.scans.map((s) => "<tr><td>" + esc(s.order) + "</td><td><b>" + esc(s.label) + '</b><div class="' + P + '-note" style="margin:0">' + esc(s.files) + "</div></td><td class=\"" + P + '-nw">' + esc(String(s.time || "").replace("T", " ").replace(/:\d\dZ$/, "")) + "</td><td>" + esc(s.scanner) + "</td><td>" + (s.external ? zoneChip("external") : "inside") + "</td><td>" + esc(s.hostsUp) + "</td><td>" + esc(s.openPorts) + "</td><td>" + esc(s.portsScanned || "unknown") + (s.portsSource ? '<div class="' + P + '-note" style="margin:0">' + esc(s.portsSource) + "</div>" : "") + "</td><td>" + esc(s.targets || "unknown") + "</td></tr>").join("") + "</tbody></table>";
    pane.appendChild(tl);
    pane.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">Each scan is compared with the latest earlier scan that shares hosts or targets with it. A port that is missing is called closed only when the newer scan covered that port; otherwise it is "not rescanned" (outside the range) or "not seen" (range unknown). A host outside the newer scan\'s targets is "not rescanned", not gone.</p><h4 style="margin:14px 0 6px;font-size:.86rem">Changes</h4>');
    const types = [...new Set(r.tables.changes.map((c) => c.type))].sort(cmp);
    const box = filterBar(pane, [searchField(), selectField("type", "Change", types), selectField("zone", "Zone", ["external", "internal"])], () => draw());
    const draw = () => {
      const rows = r.tables.changes.map((c, i) => ({ ...c, i })).filter((c) => (!filters.type || c.type === filters.type) && (!filters.zone || c.zone === filters.zone) && matchQ([c.ip, c.port, c.before, c.after, c.detail]));
      box.innerHTML = "";
      if (!rows.length) { box.innerHTML = '<div class="' + P + '-empty">' + (r.tables.changes.length ? "No changes match." : r.tables.scans.length < 2 ? "Load at least two scans of the same scope to see changes." : "No changes between the scans.") + "</div>"; return; }
      const t = table(CHG_COLS, rows, sorts.changes, (s) => { sorts.changes = s; draw(); }, (c) => c.i, TABLE_LIMIT);
      t.querySelectorAll("tr[data-i]").forEach((tr) => { const c = r.tables.changes[Number(tr.dataset.i)]; if (!c.ip || !c.port) { tr.style.cursor = "default"; return; } tr.addEventListener("click", () => { selected = tr.dataset.i; markSel(box); showService(c.ip, Number(c.port), c.proto); }); });
      box.appendChild(t);
    };
    draw();
  }

  // ---- drawer ----
  const closeBtn = () => '<button class="' + P + '-btn sm" data-close type="button">Close</button>';
  function closeDrawer() { const d = $("drawer"); d.style.display = "none"; d.innerHTML = ""; selected = ""; }
  function openDrawer(html) {
    const d = $("drawer");
    d.style.display = "block";
    d.innerHTML = html;
    d.querySelector("[data-close]").addEventListener("click", () => { closeDrawer(); drawPane(); });
    d.scrollIntoView({ block: "nearest", behavior: "smooth" });
    return d;
  }
  /** Raw scanner output for one port: service fields, banners, NSE / plugin output, host scripts. */
  function rawHtml(raw, withHost = true) {
    if (!raw) return '<p class="' + P + '-note">No raw record (the port is not open in the current state).</p>';
    const dl = [["Scan", raw.scan], ["State", raw.state + (raw.reason ? " (" + raw.reason + ")" : "")], ["Service", raw.service], ["Product", [raw.product, raw.version, raw.extrainfo ? "(" + raw.extrainfo + ")" : ""].filter(Boolean).join(" ")], ["CPE", raw.cpe]].filter(([, v]) => v);
    let h = "<h4>" + esc(raw.ip + ":" + raw.port + "/" + raw.proto) + "</h4><dl class=\"" + P + '-dl">' + dl.map(([k, v]) => "<dt>" + esc(k) + "</dt><dd>" + esc(v) + "</dd>").join("") + "</dl>";
    for (const [k, v] of Object.entries(raw.banners || {})) if (v) h += "<p><b>Banner: " + esc(k) + "</b></p><pre>" + esc(v) + "</pre>";
    for (const [k, v] of Object.entries(raw.scripts || {})) h += "<p><b>" + esc(k) + "</b></p><pre>" + esc(String(v).replace(/^\n/, "") || "(empty output)") + "</pre>";
    if (withHost) for (const [k, v] of Object.entries(raw.hostScripts || {})) h += "<p><b>host script: " + esc(k) + "</b></p><pre>" + esc(String(v).replace(/^\n/, "")) + "</pre>";
    if (!Object.keys(raw.scripts || {}).length && !Object.values(raw.banners || {}).some(Boolean)) h += '<p class="' + P + '-note">The scanner recorded no script output or banner for this port.</p>';
    return h;
  }
  const rawFor = (ip, port, proto) => result.tables.raw.find((x) => x.ip === ip && x.port === port && (!proto || x.proto === proto));

  function showFinding(f) {
    const eps = [];
    for (const e of f.evidence || []) if (e.ip && e.port) { const k = e.ip + "|" + e.port + "|" + (e.proto || ""); if (!eps.some((x) => x.k === k)) eps.push({ k, ip: e.ip, port: Number(e.port), proto: e.proto }); }
    const raws = eps.slice(0, 8).map((x) => rawFor(x.ip, x.port, x.proto)).filter(Boolean);
    const d = openDrawer('<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + pill(f.severity) + " " + esc(f.title) + "</h3>" + closeBtn() + "</div>" +
      "<p>" + esc(f.description) + "</p><p><b>Recommendation:</b> " + esc(f.recommendation) + "</p>" +
      "<p><b>Confidence:</b> " + esc(f.confidence) + " &middot; <b>Category:</b> " + esc(f.category) + "</p>" +
      "<p>" + (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</p>" +
      "<p><b>Evidence</b> (" + (f.evidence || []).length + " of " + f.evidenceCount + ")</p>" + evidenceTable(f.evidence) +
      '<div class="' + P + '-row"><button class="' + P + '-btn sm" data-ev type="button">Export evidence CSV</button></div>' +
      (raws.length ? "<h4>Raw scanner output" + (eps.length > raws.length ? " (first " + raws.length + " of " + eps.length + " endpoints)" : "") + "</h4>" + raws.map((x) => rawHtml(x, false)).join("") : ""));
    d.querySelector("[data-ev]").addEventListener("click", () => {
      const rows = f.evidence || [], keys = [];
      for (const x of rows) for (const k of Object.keys(x)) if (!keys.includes(k)) keys.push(k);
      download(TOOL_ID + "-evidence-" + fileStamp() + ".csv", [keys.join(","), ...rows.map((x) => keys.map((k) => csvCell(x[k])).join(","))].join("\n"), "text/csv");
    });
  }
  function showHost(ip) {
    const h = result.tables.hosts.find((x) => x.ip === ip);
    if (!h) return;
    const raws = result.tables.raw.filter((x) => x.ip === ip);
    const hostScripts = raws[0] ? raws[0].hostScripts || {} : {};
    const related = result.findings.filter((f) => (f.evidence || []).some((e) => e.ip === ip));
    const chg = result.tables.changes.filter((c) => c.ip === ip);
    openDrawer('<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + esc(ip) + (h.hostnames ? " (" + esc(h.hostnames) + ")" : "") + "</h3>" + closeBtn() + "</div>" +
      '<dl class="' + P + '-dl"><dt>Zone</dt><dd>' + esc(h.zone) + "</dd><dt>Risk score</dt><dd>" + esc(h.riskScore) + "</dd><dt>OS</dt><dd>" + esc(h.os || "not identified") + "</dd><dt>Open ports</dt><dd>" + esc(h.ports || "none in the current state") + "</dd><dt>Issues</dt><dd>" + esc(h.flags || "none") + "</dd><dt>Last scan</dt><dd>" + esc(h.lastScan) + "</dd></dl>" +
      (related.length ? "<h4>Findings</h4><p>" + related.map((f) => pill(f.severity) + " " + esc(f.title)).join("<br>") + "</p>" : "") +
      (chg.length ? "<h4>Changes</h4>" + evidenceTable(chg.map((c) => ({ type: c.type, port: c.port ? c.port + "/" + c.proto : "", before: c.before, after: c.after, scans: c.fromScan + " to " + c.toScan }))) : "") +
      Object.entries(hostScripts).map(([k, v]) => "<p><b>host script: " + esc(k) + "</b></p><pre>" + esc(String(v).replace(/^\n/, "")) + "</pre>").join("") +
      raws.map((x) => rawHtml(x, false)).join(""));
  }
  function showService(ip, port, proto) {
    const raw = rawFor(ip, port, proto);
    const e = result.tables.exposures.find((x) => x.ip === ip && x.port === port && (!proto || x.proto === proto));
    const related = result.findings.filter((f) => (f.evidence || []).some((v) => v.ip === ip && Number(v.port) === port));
    openDrawer('<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + esc(ip + ":" + port + (proto ? "/" + proto : "")) + (e && e.hostnames ? " (" + esc(e.hostnames) + ")" : "") + "</h3>" + closeBtn() + "</div>" +
      (e ? '<dl class="' + P + '-dl"><dt>Zone</dt><dd>' + esc(e.zone) + "</dd><dt>Rule</dt><dd>" + esc(e.ruleLabel || "none") + (e.severity ? " (" + esc(e.severity) + ")" : "") + "</dd>" + (e.allowListed ? "<dt>Approved</dt><dd>" + esc(e.allowListed) + "</dd>" : "") + "<dt>First seen</dt><dd>" + esc(e.firstSeen) + "</dd><dt>Last seen</dt><dd>" + esc(e.lastSeen) + "</dd></dl>" : "") +
      (related.length ? "<h4>Findings</h4><p>" + related.map((f) => pill(f.severity) + " " + esc(f.title)).join("<br>") + "</p>" : "") + rawHtml(raw));
  }

  // ---- exports + graph ----
  function renderExports() {
    const r = result, ex = $("exports"), stamp = fileStamp();
    const b = (x, l) => '<button class="' + P + '-btn" data-x="' + x + '">' + l + "</button>";
    ex.innerHTML = b("find", "Findings CSV") + b("json", "JSON") + b("txt", "Summary TXT") + b("inv", "Inventory CSV") + b("chg", "Changes CSV") + b("fw", "Firewall change requests TXT");
    const on = (x, fn) => ex.querySelector('[data-x="' + x + '"]').addEventListener("click", fn);
    on("find", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    on("json", () => download(TOOL_ID + "-" + stamp + ".json", toJson({ ...r, summaryStats: summarize(r.findings) }), "application/json"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r), "text/plain"));
    on("inv", () => download(TOOL_ID + "-inventory-" + stamp + ".csv", inventoryToCsv(r), "text/csv"));
    on("chg", () => download(TOOL_ID + "-changes-" + stamp + ".csv", changesToCsv(r), "text/csv"));
    on("fw", () => download(TOOL_ID + "-firewall-requests-" + stamp + ".txt", firewallTicketText(r), "text/plain"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: datasetName() });
  }

  renderFiles();
}
