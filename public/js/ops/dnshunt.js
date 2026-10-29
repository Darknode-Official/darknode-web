// DNS Hunt (dnshunt): Deck tool UI. Drop DNS resolver query logs (Zeek, BIND, Windows DNS
// debug, dnsmasq / Pi-hole, Unbound, Route 53 Resolver, Umbrella, generic CSV; zip / gz
// unpacked locally); the engine runs in a Worker. The only network request is the optional
// same-origin mirrored feed /data/feeds/malicious-ips.json. No native dialogs; toasts only.
//
//   renderDnsHunt(main) -> void

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, COLUMNS, HIGH_CARDINALITY_DEFAULTS, ENCRYPTED_DNS_HOSTS, DOH_CANARY, detectFormat,
  findingsToCsv, tableToCsv, blocklistText, summaryText, exampleDataset,
} from "./dnshunt-engine.js?v=20261026b";

const ENGINE = engineUrl("./dnshunt-engine.js?v=20261026b", import.meta);
const P = "dnh";
const FEED_URL = "/data/feeds/malicious-ips.json";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const fmtBytes = (n) => { const v = Number(n) || 0; return v >= 1073741824 ? (v / 1073741824).toFixed(2) + " GB" : v >= 1048576 ? (v / 1048576).toFixed(1) + " MB" : v >= 1024 ? Math.round(v / 1024) + " KB" : v + " B"; };
const fmtNum = (n) => Number(n || 0).toLocaleString("en-US");
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const CONF_RANK = { confirmed: 2, likely: 1, review: 0 };
const COLUMN_LABELS = { timestamp: "Timestamp", client: "Client IP", query: "Query name (required)", qtype: "Query type", rcode: "Response code", answers: "Answers (resolved IPs)", server: "Resolver / server IP", user: "User" };

const CSS = `
  .dnh-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .dnh-root *{box-sizing:border-box}
  .dnh-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .dnh-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .dnh-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .dnh-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:100ch}
  .dnh-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .dnh-card h2{font-size:.95rem;margin:0 0 10px}
  .dnh-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .dnh-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .dnh-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .dnh-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .dnh-btn.sm{padding:4px 9px;font-size:.76rem}
  .dnh-btn:disabled{opacity:.5;cursor:default}
  .dnh-files{display:flex;flex-direction:column;gap:6px;margin-top:12px}
  .dnh-file{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;font-size:.82rem;min-width:0}
  .dnh-file b{overflow-wrap:anywhere;min-width:0}
  .dnh-mut{color:var(--mut,#667085)}
  .dnh-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085);white-space:nowrap}
  .dnh-conf.high{color:#1b7f4d;border-color:#1b7f4d}.dnh-conf.medium{color:#8a6d00;border-color:#8a6d00}.dnh-conf.low{color:#b00020;border-color:#b00020}
  .dnh-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
  .dnh-grp{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 12px;min-width:0}
  .dnh-grp h4{margin:0 0 8px;font-size:.76rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut,#667085)}
  .dnh-fields{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,200px),1fr));gap:10px 14px;align-items:start}
  .dnh-field{display:flex;flex-direction:column;gap:3px;min-width:0;flex:1 1 140px}
  .dnh-field.wide{flex:1 1 100%;grid-column:1/-1}
  .dnh-field label{font-size:.76rem;font-weight:600;color:var(--tx,#1a2230)}
  .dnh-field input,.dnh-field select,.dnh-field textarea{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:6px 9px;width:100%;max-width:100%}
  .dnh-field textarea{min-height:60px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem}
  .dnh-field small{font-size:.72rem;color:var(--mut,#667085);line-height:1.35;overflow-wrap:anywhere}
  .dnh-check{display:flex;gap:8px;align-items:flex-start;font-size:.84rem;min-width:0}
  .dnh-check input{margin-top:3px;flex:none}
  .dnh-check span{min-width:0;overflow-wrap:anywhere}
  .dnh-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .dnh-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:120px;flex:1 1 120px}
  .dnh-kpi b{display:block;font-size:1.3rem;overflow-wrap:anywhere}
  .dnh-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .dnh-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .dnh-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .dnh-plabel{font-size:.74rem;color:var(--mut,#667085);margin-top:4px;display:none;overflow-wrap:anywhere}
  .dnh-tabs{display:flex;flex-wrap:wrap;gap:6px;border-bottom:1px solid var(--line,#e6e8ee);margin-bottom:12px}
  .dnh-tab{appearance:none;font:inherit;white-space:nowrap;font-size:.84rem;font-weight:600;border:1px solid transparent;border-bottom:none;background:none;color:var(--mut,#667085);padding:7px 12px;border-radius:8px 8px 0 0;cursor:pointer;margin-bottom:-1px}
  .dnh-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#e6e8ee);background:var(--card,#fff)}
  .dnh-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .dnh-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:640px}
  .dnh-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .dnh-list th.on{color:var(--tx,#1a2230)}
  .dnh-list th.on::after{content:" \\2193";font-size:.7rem}
  .dnh-list th.on.asc::after{content:" \\2191"}
  .dnh-list td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word;word-break:normal;max-width:420px}
  .dnh-list td.dnh-dom{overflow-wrap:anywhere}
  .dnh-list tr[data-i]{cursor:pointer}
  .dnh-list tr[data-i]:hover,.dnh-list tr.sel{background:var(--bg,#f7f8fb)}
  .dnh-nw{white-space:nowrap}
  .dnh-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .dnh-pill.critical{background:#7a0012}.dnh-pill.high{background:#b00020}.dnh-pill.medium{background:#b58100}.dnh-pill.low{background:#2552c6}.dnh-pill.info{background:#667085}
  .dnh-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .dnh-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .dnh-drawer{margin-top:12px;display:none;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--bg,#f7f8fb);min-width:0}
  .dnh-drawer h3{margin:0;font-size:1rem;overflow-wrap:anywhere}
  .dnh-drawer p{margin:6px 0;overflow-wrap:anywhere}
  .dnh-drawer .dnh-list{background:var(--card,#fff);margin-top:10px}
  .dnh-skip{font-size:.78rem;color:var(--mut,#667085);margin:8px 0 0;padding-left:18px}
  .dnh-skip li{margin:2px 0;overflow-wrap:anywhere}
  .dnh-filters{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:flex-end;margin-bottom:10px}
  .dnh-filters .dnh-field{flex:0 1 180px}
  .dnh-help{font-size:.78rem;color:var(--mut,#667085);margin:10px 0 0}
  .dnh-help summary{cursor:pointer;font-weight:600;color:var(--tx,#1a2230)}
  .dnh-help p{margin:6px 0;overflow-wrap:anywhere}
  @media (max-width:560px){.dnh-field,.dnh-filters .dnh-field{flex:1 1 100%}.dnh-card{padding:14px}.dnh-grid{grid-template-columns:1fr}.dnh-hd h1{font-size:1.4rem}}
`;

const kpi = (v, l) => '<div class="' + P + '-kpi"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const pill = (s) => (s ? '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>" : "");
const sortBy = (rows, key, dir, rank) => rows.slice().sort((a, b) => {
  const x = rank ? (rank[a[key]] ?? -1) : a[key], y = rank ? (rank[b[key]] ?? -1) : b[key];
  const r = typeof x === "number" && typeof y === "number" ? x - y : cmp(String(x == null ? "" : x).toLowerCase(), String(y == null ? "" : y).toLowerCase());
  return dir === "asc" ? r : -r;
});
const LABELS = {
  domain: "Domain", queries: "Queries", clients: "Clients", resolved: "Resolved", nxdomain: "NXDOMAIN", score: "DGA score", traits: "Traits", entropy: "Entropy",
  uniqueSubdomains: "Unique subdomains", meanLength: "Mean length", encodedShare: "Encoded share", txtNullShare: "TXT/NULL share", longestLabel: "Longest label", signals: "Signals",
  client: "Client", medianIntervalSec: "Median interval (s)", cv: "CV", spanHours: "Span (h)", answers: "Answers", share: "NX share", domains: "Domains",
  unicode: "Unicode", resembles: "Resembles", kind: "Kind", firstSeen: "First seen", lastSeen: "Last seen", dgaLike: "DGA-like", lookalike: "Lookalike",
  users: "Users", host: "Host", resolvers: "Resolvers", ip: "IP",
};
const NOWRAP = new Set(["firstSeen", "lastSeen", "time", "client", "ip"]);

/** Sortable table: cols = [{key, label, render?, rank?}]. */
function table(cols, rows, sort, onSort, rowKey) {
  const head = cols.map((c) => '<th data-k="' + esc(c.key) + '" class="' + (sort.key === c.key ? "on " + sort.dir : "") + '">' + esc(c.label) + "</th>").join("");
  const sorted = sortBy(rows, sort.key, sort.dir, (cols.find((c) => c.key === sort.key) || {}).rank);
  const body = sorted.map((r) => "<tr" + (rowKey ? ' data-i="' + esc(rowKey(r)) + '"' : "") + ">" + cols.map((c) => "<td" + (c.cls ? ' class="' + c.cls + '"' : "") + ">" + (c.render ? c.render(r) : esc(r[c.key] == null ? "" : r[c.key])) + "</td>").join("") + "</tr>").join("");
  const el = document.createElement("div");
  el.className = P + "-list";
  el.innerHTML = "<table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table>";
  el.querySelectorAll("th").forEach((th) => th.addEventListener("click", () => { const k = th.dataset.k; onSort({ key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" }); }));
  return el;
}

/** Columns derived from row keys, with date and IP cells kept on one line. */
function autoCols(rows) {
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
  return keys.map((k) => ({
    key: k, label: LABELS[k] || k, cls: k === "domain" || k === "host" || k === "unicode" ? P + "-dom" : "",
    render: NOWRAP.has(k) ? (r) => '<span class="' + P + '-nw">' + esc(r[k]) + "</span>" : null,
  }));
}

function evidenceTable(rows) {
  if (!rows || !rows.length) return '<p class="' + P + '-note">No evidence rows.</p>';
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k) && rows.some((x) => x[k] !== "" && x[k] != null)) keys.push(k);
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => "<td" + (k === "query" || k === "domain" ? ' class="' + P + '-dom"' : "") + ">" + (NOWRAP.has(k) ? '<span class="' + P + '-nw">' + esc(r[k]) + "</span>" : esc(r[k] == null ? "" : String(r[k]))) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

const GROUPS = [
  { title: "Generated names (DGA)", fields: [
    ["dgaMinLength", "Shortest label scored", "Characters in the registrable label."],
    ["dgaScoreMin", "DGA traits needed (of 6)", "See How the scoring works."],
    ["dgaClientMin", "Failed DGA-like names per client", "Distinct NXDOMAIN names before a client is reported."],
  ] },
  { title: "Tunnelling", fields: [
    ["tunnelMinSubdomains", "Unique subdomains under one domain", ""],
    ["tunnelAvgLen", "Mean query length (chars)", ""],
    ["tunnelEncodedRatio", "Encoded-looking label share (0-1)", "Hex, base32 or long high-entropy labels."],
  ] },
  { title: "Beaconing", fields: [
    ["beaconMinEvents", "Minimum queries per client and domain", ""],
    ["beaconMaxCv", "Max coefficient of variation", "Standard deviation / mean of the intervals."],
    ["beaconMinIntervalSec", "Shortest interval (s)", ""],
    ["beaconMaxIntervalSec", "Longest interval (s)", ""],
    ["beaconPopularShare", "Common domain: share of clients (0-1)", "Domains this widely used are not scored."],
  ] },
  { title: "Failures and new domains", fields: [
    ["nxMin", "NXDOMAIN answers per client", ""],
    ["nxRatio", "NXDOMAIN share per client (0-1)", ""],
    ["baselineDays", "Baseline days for new domains", "Domains first seen after these days of the log are new."],
  ] },
];

/** Mount the tool into main. */
export function renderDnsHunt(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  const numField = (k, label, help) => '<div class="' + P + '-field"><label for="' + P + "-o-" + k + '">' + esc(label) + '</label><input id="' + P + "-o-" + k + '" data-opt="' + k + '" type="number" min="0" step="any" value="' + esc(DEFAULTS[k]) + '"><small>Default ' + esc(DEFAULTS[k]) + (help ? ". " + esc(help) : "") + "</small></div>";
  const area = (id, label, ph, help) => '<div class="' + P + '-field wide"><label for="' + P + "-" + id + '">' + esc(label) + '</label><textarea id="' + P + "-" + id + '" placeholder="' + esc(ph) + '" spellcheck="false"></textarea><small>' + esc(help) + "</small></div>";
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>DNS Logs</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Hunt through resolver query logs for algorithmically generated names, DNS tunnelling, periodic beaconing, NXDOMAIN storms, lookalikes of your own domains, newly observed domains, and clients that send DNS around the company resolver. Runs entirely in your browser. Nothing is uploaded. The only request is the optional malicious-IP list at ', FEED_URL, ', a same-origin copy that is mirrored and dated, not live.</p>',
    '<div class="', P, '-card"><h2>1. DNS logs</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-note">Accepted: Zeek dns.log (TSV or JSON), BIND query log, Windows DNS Server debug log (dns.log), dnsmasq / Pi-hole log, Unbound with log-queries or log-replies, Route 53 Resolver query logs (JSON lines), Cisco Umbrella DNS logs (CSV, with or without header), or any CSV with a query-name column. Many files or a zip at once; up to 512 MB per file. Logs are streamed and folded into per-domain and per-client summaries, so memory stays close to the size of the text.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div>',
    '<div id="', P, '-map"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" type="button" disabled>Hunt</button><button class="', P, '-btn" id="', P, '-cancel" type="button" hidden>Cancel</button><button class="', P, '-btn" id="', P, '-clear" type="button" disabled>Clear files</button><span class="', P, '-note" id="', P, '-count"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-plabel" id="', P, '-plabel"></div></div>',
    '<div class="', P, '-card"><h2>2. Your environment</h2><div class="', P, '-fields">',
    area("own", "Your domains", "one per line", "Used to find lookalikes of your names (homoglyphs, one- or two-letter edits, other TLDs, IDN) and excluded from the other checks."),
    area("allow", "Allow-listed domains", "one per line", "Never reported (suffix match). Built in for tunnelling and beaconing only: " + HIGH_CARDINALITY_DEFAULTS.join(", ") + "."),
    area("known", "Baseline domains (optional)", "one per line", "Domains seen in an earlier period. When filled, anything not on it counts as newly observed; otherwise the first baseline days of the log are used."),
    area("resolvers", "Approved resolvers", "one IP per line", "Blank = any internal address counts as an approved resolver. Needs a log with the server address (Zeek id.resp_h or a mapped column)."),
    area("internal", "Internal CIDRs", "one per line", "Blank = 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, fc00::/7, fe80::/10, ::1."),
    '<div class="', P, '-field"><label for="', P, '-o-assumeYear">Year for logs without one</label><input id="', P, '-o-assumeYear" data-opt="assumeYear" type="number" min="2000" max="2100" placeholder="this year"><small>dnsmasq and syslog lines omit the year. Blank = this year.</small></div>',
    "</div></div>",
    '<div class="', P, '-card"><h2>3. Thresholds</h2><div class="', P, '-grid">', GROUPS.map((g) => '<div class="' + P + '-grp"><h4>' + esc(g.title) + '</h4><div class="' + P + '-fields">' + g.fields.map((x) => numField(x[0], x[1], x[2])).join("") + "</div></div>").join(""), "</div>",
    '<details class="', P, '-help"><summary>How the scoring works</summary>',
    "<p><b>DGA traits.</b> Only the left-most label of the registrable domain is scored (so CDN host names under a known domain are not). One point each for: Shannon entropy H = -&Sigma; p log2 p of at least 3.3 bits per character; under 45% of letter pairs among the 200 most common English pairs; under 25% vowels; a run of 5 or more consonants; 15-60% digits mixed into 5 or more letters; and 16 or more characters. A name with at least the traits-needed setting counts as DGA-like. A client is reported when it gets NXDOMAIN for at least the set number of distinct DGA-like names.</p>",
    "<p><b>Tunnelling.</b> Per registrable domain: unique subdomains, mean query length, share of encoded-looking labels (hex or base32 of 16+ characters, or 24+ characters with entropy of at least 3.8), share of TXT/NULL queries and the longest label (50+). A domain over the unique-subdomain threshold with two or more of these signals is reported as possible tunnelling.</p>",
    "<p><b>Beaconing.</b> Per client and domain, the gaps between queries (under 1 s merged as retries) are trimmed by 10% at each end; the coefficient of variation is standard deviation / mean. Steady gaps (CV at or below the setting) over at least an hour and within the interval range are reported with the sample size. Domains used by a large share of clients are skipped as common services.</p>",
    "<p><b>Encrypted DNS.</b> Lookups of ", ENCRYPTED_DNS_HOSTS.length, " public DoH/DoT endpoints and the Firefox canary ", DOH_CANARY, " are reported, because after those lookups DNS can leave without passing this resolver.</p></details></div>",
    '<div class="', P, '-card"><h2>4. Threat intel (optional)</h2>',
    '<label class="', P, '-check"><input type="checkbox" id="', P, '-feed"><span>Use the mirrored malicious-IP feed (', FEED_URL, ') to check answers</span></label>',
    '<p class="', P, '-note" id="', P, '-feedinfo">Off. Turning it on loads a dated same-origin copy; it is not a live lookup. Needs a log that records answers (Zeek, Route 53, dnsmasq, or a mapped column).</p>',
    '<div class="', P, '-fields" style="margin-top:10px">', area("ownips", "Your own bad IPs", "one IP per line", "Joined with the feed when it is on, used alone when it is off."), "</div></div>",
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card" id="', P, '-results" style="display:none"><div class="', P, '-tabs" id="', P, '-tabs"></div><div id="', P, '-pane"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div><ul class="', P, '-skip" id="', P, '-skipped"></ul></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example" type="button">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, exampleOpts = null, running = null, feed = null, tab = "findings", selFinding = -1;
  const sorts = {};
  let ffilter = { sev: "", q: "" };
  const columnMap = {};
  const datasetName = () => (isExample ? "synthetic example" : files.map((f) => f.name).join(", ").slice(0, 200));
  const needsMap = (f) => (f.det.format === "csv" || f.det.format === "json") && f.det.confidence !== "high" && f.det.headers && f.det.headers.length;

  function renderFiles() {
    $("files").innerHTML = files.map((f, i) => {
      const d = f.det;
      const parsed = result ? (result.tables.files || []).find((x) => x.name === f.name) : null;
      return '<div class="' + P + '-file"><b>' + esc(f.name) + '</b><span class="' + P + '-mut">' + esc(fmtBytes(f.text.length)) + (f.fromArchive ? ", from archive" : "") + "</span><span>" + esc(d.label) + "</span>" +
        '<span class="' + P + "-conf " + esc(d.confidence) + '">' + esc(d.confidence) + " confidence</span>" +
        (parsed ? '<span class="' + P + '-mut">' + fmtNum(parsed.events) + " events</span>" : "") +
        '<button class="' + P + '-btn sm" data-rm="' + i + '" type="button">Remove</button></div>';
    }).join("");
    $("files").querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { files.splice(Number(b.dataset.rm), 1); isExample = false; renderFiles(); }));
    const bytes = files.reduce((n, f) => n + f.text.length, 0);
    $("count").textContent = files.length ? files.length + " file" + (files.length === 1 ? "" : "s") + ", " + fmtBytes(bytes) + (isExample ? " (synthetic example)" : "") : "";
    $("run").disabled = !files.length || !!running;
    $("clear").disabled = !files.length;
    renderMapping();
  }

  function renderMapping() {
    const low = files.filter(needsMap);
    const box = $("map");
    if (!low.length) { box.innerHTML = ""; return; }
    const headers = [...new Set(low.flatMap((f) => f.det.headers))];
    box.innerHTML = '<div class="' + P + '-card" style="margin:12px 0 0"><h2>Column mapping</h2><p class="' + P + '-note">' + esc(low.map((f) => f.name + " (" + f.det.label + ")").join(", ")) + ": the layout was not recognised with high confidence. Check the columns below; checks that need an unmapped column are skipped and listed, never guessed.</p>" +
      '<div class="' + P + '-fields" style="margin-top:10px">' + Object.keys(COLUMNS).map((k) => {
        const auto = (low[0].det.mapping || {})[k];
        return '<div class="' + P + '-field"><label for="' + P + "-col-" + k + '">' + esc(COLUMN_LABELS[k] || k) + '</label><select id="' + P + "-col-" + k + '" data-col="' + esc(k) + '"><option value="">(not present)</option>' +
          headers.map((h) => '<option value="' + esc(h) + '"' + ((columnMap[k] || auto) === h ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>";
      }).join("") + "</div></div>";
    box.querySelectorAll("[data-col]").forEach((sel) => { if (sel.value) columnMap[sel.dataset.col] = sel.value; sel.addEventListener("change", () => { if (sel.value) columnMap[sel.dataset.col] = sel.value; else delete columnMap[sel.dataset.col]; }); });
  }

  function addFile(name, text, fromArchive) {
    if (!String(text).trim()) { toast(name + " is empty", "warning"); return false; }
    const det = detectFormat(text, name);
    if (det.format === "unknown") toast(name + ": format not recognised; it will be listed as skipped", "warning");
    const entry = { name, text, det, fromArchive: !!fromArchive };
    const idx = files.findIndex((x) => x.name === name);
    if (idx >= 0) files[idx] = entry; else files.push(entry);
    return true;
  }

  mountDropzone($("drop"), {
    maxBytes: 512 * 1024 * 1024, maxFiles: 100, multiple: true, unpack: true,
    label: "Drop DNS logs (or a zip / gz) here, paste, or browse",
    onFiles: async (list) => {
      let added = 0;
      if (isExample) { files = []; isExample = false; exampleOpts = null; }
      for (const f of list) { try { if (addFile(f.name, await f.text(), f.fromArchive)) added++; } catch (e) { toast("Could not read " + f.name + ": " + ((e && e.message) || e), "error"); } }
      if (added) toast("Loaded " + added + " file" + (added === 1 ? "" : "s"), "success");
      result = null;
      renderFiles();
    },
  });

  $("clear").addEventListener("click", () => { files = []; isExample = false; exampleOpts = null; result = null; renderFiles(); });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    files = []; isExample = true; exampleOpts = ex.opts; result = null;
    for (const f of ex.files) addFile(f.name, f.text, false);
    renderFiles();
    toast("Synthetic example loaded: a Zeek dns.log and a BIND query log. Click Hunt.", "info");
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
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (el.value !== "" && Number.isFinite(n)) o[el.dataset.opt] = n; });
    if (!o.assumeYear) o.assumeYear = new Date().getUTCFullYear();
    o.ownDomains = $("own").value; o.allowDomains = $("allow").value; o.knownDomains = $("known").value;
    o.approvedResolvers = $("resolvers").value; o.internalCidrs = $("internal").value;
    const own = $("ownips").value.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
    const fromFeed = $("feed").checked && feed ? feed.data.map((x) => x.ip) : [];
    if (own.length || fromFeed.length) { o.maliciousIps = fromFeed.concat(own); o.feedUpdated = fromFeed.length ? String(feed.updated || "").slice(0, 10) : "your list"; }
    if (isExample && exampleOpts) {
      if (!o.ownDomains.trim()) o.ownDomains = exampleOpts.ownDomains;
      if (!o.maliciousIps) { o.maliciousIps = exampleOpts.maliciousIps; o.feedUpdated = exampleOpts.feedUpdated; }
    }
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
      const payload = files.map((f) => (needsMap(f) || f.det.format === "csv" || f.det.format === "json" ? { name: f.name, text: f.text, mapping: { ...(f.det.mapping || {}), ...columnMap } } : { name: f.name, text: f.text }));
      running = runInWorker(ENGINE, "analyze", [{ files: payload }, opts()], {
        timeoutMs: 30 * 60 * 1000,
        onProgress: (i, n, label) => { bar.style.width = (n ? Math.min(100, Math.round((i / n) * 100)) : 0) + "%"; pl.textContent = label || ""; },
      });
      result = await running;
      selFinding = -1; ffilter = { sev: "", q: "" }; tab = "findings";
      render(result);
      toast(result.findings.length + " finding" + (result.findings.length === 1 ? "" : "s") + " in " + fmtNum(result.summary.events) + " events (" + ((performance.now() - t0) / 1000).toFixed(1) + " s)", "success");
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
    const sev = s.bySeverity;
    $("kpis").innerHTML = kpi(fmtNum(s.events), "events") + kpi(fmtNum(s.clients), "clients") + kpi(fmtNum(s.domains), "registrable domains") +
      kpi(fmtNum(s.dgaDomains), "DGA-like domains") + kpi(fmtNum(s.tunnelCandidates), "tunnel candidates") + kpi(fmtNum(s.beacons), "beaconing pairs") +
      kpi(((sev.critical || 0) + (sev.high || 0)) + " / " + s.findings, "high / all findings");
    $("skipped").innerHTML = r.skipped.length ? "<li><b>Skipped or limited checks</b></li>" + r.skipped.map((k) => "<li>" + esc(k.check) + ": " + esc(k.reason) + "</li>").join("") : "";
    $("results").style.display = "";
    renderFiles(); renderTabs(r); renderExports(r);
  }

  const emptyEl = (t) => { const d = document.createElement("div"); d.className = P + "-empty"; d.textContent = t; return d; };
  const TABS = [
    ["findings", "Findings"], ["dga", "DGA-like"], ["tunnel", "Tunnelling"], ["beacons", "Beaconing"], ["lookalikes", "Lookalikes"],
    ["newDomains", "New domains"], ["nxClients", "NXDOMAIN"], ["encryptedDns", "Encrypted DNS"], ["externalResolvers", "Resolvers"], ["clients", "Clients"], ["topDomains", "Top domains"],
  ];
  const EMPTY = {
    dga: "No DGA-like names at the current thresholds.", tunnel: "No domain reached the unique-subdomain threshold.", beacons: "No periodic client/domain pairs.",
    lookalikes: "No lookalikes (enter your domains in settings).", newDomains: "No newly observed domains (or the check was skipped; see below).",
    nxClients: "No NXDOMAIN storms.", encryptedDns: "No public encrypted-DNS endpoints were looked up.", externalResolvers: "No queries to unapproved resolvers (or no server field).",
    clients: "No clients.", topDomains: "No domains.",
  };
  function renderTabs(r) {
    const t = r.tables;
    $("tabs").innerHTML = TABS.map(([k, l]) => '<button type="button" class="' + P + "-tab" + (tab === k ? " on" : "") + '" data-tab="' + k + '">' + esc(l) + " (" + (k === "findings" ? r.findings.length : (t[k] || []).length) + ")</button>").join("");
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; $("drawer").style.display = "none"; selFinding = -1; renderTabs(r); }));
    const pane = $("pane"); pane.innerHTML = "";
    if (tab === "findings") { drawFindings(r); return; }
    const rows = t[tab] || [];
    if (!rows.length) { pane.appendChild(emptyEl(EMPTY[tab] || "Nothing to show.")); return; }
    const cols = autoCols(rows);
    if (!sorts[tab]) sorts[tab] = { key: cols.find((c) => c.key === "queries") ? "queries" : cols[0].key, dir: "desc" };
    pane.appendChild(table(cols, rows, sorts[tab], (s) => { sorts[tab] = s; renderTabs(r); }));
    const b = document.createElement("div");
    b.className = P + "-row";
    b.innerHTML = '<button class="' + P + '-btn sm" type="button">Export this table (CSV)</button>';
    b.firstElementChild.addEventListener("click", () => download(TOOL_ID + "-" + tab + "-" + fileStamp() + ".csv", tableToCsv(rows), "text/csv"));
    pane.appendChild(b);
  }

  const FIND_COLS = [
    { key: "severity", label: "Severity", rank: SEV_RANK, render: (f) => pill(f.severity) },
    { key: "title", label: "Finding", render: (f) => "<b>" + esc(f.title) + '</b><div class="' + P + '-mut" style="overflow-wrap:anywhere">' + esc((f.assets || []).slice(0, 2).map((a) => a.name).join(", ")) + "</div>" },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
    { key: "controls", label: "Controls", render: (f) => f.controls.slice(0, 3).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + (f.controls.length > 3 ? '<span class="' + P + '-chip">+' + (f.controls.length - 3) + "</span>" : "") },
    { key: "evidenceCount", label: "Evidence" },
  ];

  function drawFindings(r) {
    const pane = $("pane");
    if (!r.findings.length) { pane.appendChild(emptyEl("No findings for the current thresholds. Skipped checks are listed below.")); return; }
    if (!sorts.findings) sorts.findings = { key: "severity", dir: "desc" };
    const fl = document.createElement("div");
    fl.className = P + "-filters";
    fl.innerHTML = '<div class="' + P + '-field"><label for="' + P + '-fs">Severity</label><select id="' + P + '-fs" data-ff="sev"><option value="">All</option>' + ["critical", "high", "medium", "low", "info"].map((s) => '<option value="' + s + '"' + (ffilter.sev === s ? " selected" : "") + ">" + s + "</option>").join("") + "</select></div>" +
      '<div class="' + P + '-field"><label for="' + P + '-fq">Search</label><input id="' + P + '-fq" data-ff="q" type="search" placeholder="client, domain" value="' + esc(ffilter.q) + '"></div>';
    pane.appendChild(fl);
    const box = document.createElement("div"); pane.appendChild(box);
    const draw = () => {
      const q = ffilter.q.trim().toLowerCase();
      const rows = r.findings.map((f, i) => ({ ...f, i })).filter((f) => (!ffilter.sev || f.severity === ffilter.sev) && (!q || [f.title, f.description, ...(f.assets || []).map((a) => a.name)].some((v) => String(v || "").toLowerCase().includes(q))));
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
      "<p><b>Confidence:</b> " + esc(f.confidence) + " &middot; <b>Category:</b> " + esc(f.category) + "</p>" +
      "<p>" + f.controls.map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</p>" +
      (f.assets.length ? "<p><b>Assets:</b> " + f.assets.map((a) => esc(a.type + " " + a.name)).join(", ") + "</p>" : "") +
      "<p><b>Evidence</b> (" + f.evidence.length + " of " + f.evidenceCount + ")</p>" + evidenceTable(f.evidence) +
      '<div class="' + P + '-row"><button class="' + P + '-btn sm" data-ev type="button">Export evidence CSV</button></div>';
    d.querySelector("[data-close]").addEventListener("click", () => { d.style.display = "none"; selFinding = -1; renderTabs(r); });
    d.querySelector("[data-ev]").addEventListener("click", () => download(TOOL_ID + "-evidence-" + fileStamp() + ".csv", tableToCsv(f.evidence), "text/csv"));
    d.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  function renderExports(r) {
    const ex = $("exports");
    ex.innerHTML = ["csv:Findings CSV", "json:JSON", "txt:Summary TXT", "block:Blocklist TXT", "dga:DGA-like CSV", "new:New domains CSV"].map((x) => { const [k, l] = x.split(":"); return '<button class="' + P + '-btn" type="button" data-x="' + k + '">' + l + "</button>"; }).join("");
    const stamp = fileStamp();
    const on = (k, fn) => ex.querySelector('[data-x="' + k + '"]').addEventListener("click", fn);
    on("csv", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    on("json", () => download(TOOL_ID + "-" + stamp + ".json", toJson({ ...r, summaryStats: summarize(r.findings) }), "application/json"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r), "text/plain"));
    on("block", () => { const t = blocklistText(r.findings); if (t.split("\n").filter((l) => l && !l.startsWith("#")).length === 0) { toast("No likely or confirmed domains to block", "info"); return; } download(TOOL_ID + "-blocklist-" + stamp + ".txt", t, "text/plain"); });
    on("dga", () => download(TOOL_ID + "-dga-" + stamp + ".csv", tableToCsv(r.tables.dga), "text/csv"));
    on("new", () => download(TOOL_ID + "-new-domains-" + stamp + ".csv", tableToCsv(r.tables.newDomains), "text/csv"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: datasetName() });
  }

  renderFiles();
}
