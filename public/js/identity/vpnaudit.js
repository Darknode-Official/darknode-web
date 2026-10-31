// Remote Access Audit (vpnaudit): Deck tool UI. Drop VPN / ZTNA logs (FortiGate,
// GlobalProtect, Cisco ASA / AnyConnect, OpenVPN, Cloudflare Access, Zscaler ZPA, Azure
// P2S or a generic CSV) plus an optional HR roster, account mapping and service-account
// list. Each file is classified by its content (editable, with a column-mapping panel
// when the detection is not certain); the engine (vpnaudit-engine.js, pure) runs in a
// Worker and reports leavers connecting, brute force and spraying, impossible travel,
// missing MFA, outdated clients, shared accounts and unusual sessions.
// Runs entirely in the browser; the only fetch is the same-origin mirrored malicious-IP
// feed. No native dialogs; toasts only.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, PRODUCTS, PRODUCT_LABEL, FORMAT_LABEL, DEFAULT_INTERNAL_CIDRS, parseInput, columnSpec,
  findingsToCsv, revocationCsv, blocklistText, userReportText, summaryText, exampleDataset,
} from "./vpnaudit-engine.js?v=20261029e";

const ENGINE = engineUrl("./vpnaudit-engine.js?v=20261029e", import.meta);
const FEED_URL = "/data/feeds/malicious-ips.json";
const P = "vpa";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (n) => (n == null || n === "" ? "-" : Number(n).toLocaleString());
const dt = (s) => (s ? String(s).slice(0, 16).replace("T", " ") : "-");
const bytes = (n) => (n == null ? "-" : n >= 1073741824 ? (n / 1073741824).toFixed(2) + " GB" : n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B");
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const FORMATS = Object.keys(FORMAT_LABEL).filter((f) => f !== "unknown");
const kindOf = (format) => (format === "roster" || format === "mapping" || format === "service" ? format : format === "unknown" || format === "ignore" ? "unknown" : "log");

const NUM_FIELDS = [
  ["failThreshold", "Brute-force failures", "Failed logins for one user before a success that count as brute force."],
  ["bfWindowMin", "Brute-force window (min)", "Minutes before the success in which the failures are counted."],
  ["sprayUsers", "Spraying users", "Distinct users failing from one source IP that count as spraying."],
  ["sprayWindowMin", "Spraying window (min)", "Minutes in which those users must fail."],
  ["maxKmh", "Impossible travel (km/h)", "Speed between two accesses above which travel is impossible."],
  ["minTravelKm", "Ignore hops under (km)", "IP geolocation jitter; shorter hops are never travel."],
  ["concurrentMinKm", "Concurrent distance (km)", "Overlapping sessions at least this far apart."],
  ["sharedDevices", "Shared: devices at once", "Distinct devices connected at the same time."],
  ["sharedIps", "Shared: source IPs", "Distinct public IPs for one account inside the window below."],
  ["sharedWindowMin", "Shared window (min)", "Window for the source-IP count."],
  ["maxSessionHours", "Long session (hours)", "Sessions longer than this are reported."],
  ["dormantDays", "Dormant (days)", "Gap after which a returning account counts as reactivated."],
  ["baselineDays", "Baseline (days)", "First days of the log that form each user's normal countries, networks and hours."],
  ["minBaselineEvents", "Baseline accesses", "Accesses needed in the baseline before a user is judged."],
  ["bytesZ", "Transfer robust z", "Modified z-score on bytes sent to the user (per user)."],
  ["bytesOutGb", "Transfer absolute (GB)", "Any single session above this is reported."],
  ["minBytesSamples", "Transfer samples", "Sessions with byte counts needed before the z-score is used."],
  ["minZGb", "Transfer z floor (GB)", "The z-score only flags sessions above this size."],
  ["businessStart", "Business start (hour)", "Start of business hours, 0-23, in the business time zone."],
  ["businessEnd", "Business end (hour)", "End of business hours, 1-24."],
];

const CSS = `
  .vpa-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .vpa-root *{box-sizing:border-box}
  .vpa-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .vpa-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .vpa-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .vpa-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:90ch}
  .vpa-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;max-width:100%}
  .vpa-card h2{font-size:.95rem;margin:0 0 8px;letter-spacing:.01em}
  .vpa-grid2{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:14px}
  .vpa-help{font-size:.78rem;color:var(--mut,#667085);margin:2px 0 8px;overflow-wrap:anywhere}
  .vpa-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .vpa-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .vpa-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .vpa-btn.on{border-color:#2552c6;color:#2552c6}
  .vpa-btn:disabled{opacity:.5;cursor:default}
  .vpa-ctl{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,230px),1fr));gap:14px 20px;align-items:start}
  .vpa-field{display:flex;flex-direction:column;gap:4px;min-width:0;max-width:100%}
  /* a label that wraps to two lines must not push its input below its neighbours': each field's label, input and help share the row tracks */
  .vpa-ctl>.vpa-field{display:grid;grid-row:span 3;grid-template-rows:subgrid;row-gap:4px;align-content:start}.vpa-ctl>.vpa-field>label{align-self:end}
  .vpa-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .vpa-field input,.vpa-field select,.vpa-field textarea,.vpa-in{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;max-width:100%}
  .vpa-field input[type=number]{width:130px}
  .vpa-field input.mid{width:200px}
  .vpa-field textarea{width:280px;min-height:78px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}
  .vpa-field small{font-size:.74rem;color:var(--mut,#667085);max-width:30ch;overflow-wrap:anywhere}
  .vpa-check{display:flex;gap:8px;align-items:center;font-size:.84rem}
  .vpa-sec{margin-top:16px;padding-top:12px;border-top:1px solid var(--line,#eef0f4)}
  .vpa-sec h3{font-size:.8rem;margin:0 0 8px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#667085)}
  .vpa-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}
  .vpa-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .vpa-kpi b{display:block;font-size:1.3rem;overflow-wrap:anywhere}
  .vpa-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .vpa-kpi.bad b{color:#b00020}
  .vpa-prog{margin-top:10px;display:none}
  .vpa-prog .bar{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden}
  .vpa-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .vpa-prog span{display:block;font-size:.74rem;color:var(--mut,#667085);margin-top:4px;overflow-wrap:anywhere}
  .vpa-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0}
  .vpa-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%;background:var(--card,#fff)}
  .vpa-list table{width:100%;border-collapse:collapse;font-size:.84rem;min-width:560px}
  .vpa-list th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .vpa-list th[data-sort]{cursor:pointer}
  .vpa-list th[data-sort].asc::after{content:" \\2191"}.vpa-list th[data-sort].desc::after{content:" \\2193"}
  .vpa-list td{padding:9px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word}
  .vpa-list tr[data-i],.vpa-list tr[data-u]{cursor:pointer}
  .vpa-list tr[data-i]:hover,.vpa-list tr[data-u]:hover,.vpa-list tr.sel{background:var(--bg,#f7f8fb)}
  .vpa-list select,.vpa-list input{min-width:150px;font:inherit;font-size:.8rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:4px 6px;max-width:100%}
  .vpa-pill{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .vpa-pill.critical{background:#7a0012}.vpa-pill.high{background:#b00020}.vpa-pill.medium{background:#b58100}.vpa-pill.low{background:#2552c6}.vpa-pill.info{background:#667085}
  .vpa-pill.conf-high{background:#1f7a3a}.vpa-pill.conf-medium{background:#b58100}.vpa-pill.conf-low{background:#b00020}
  .vpa-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .vpa-conf{font-size:.76rem;text-transform:capitalize}
  .vpa-flag{display:inline-block;font-size:.72rem;border:1px solid #b00020;color:#b00020;border-radius:6px;padding:0 6px;margin:1px 4px 1px 0}
  .vpa-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .vpa-drawer{margin-top:14px;display:none}
  .vpa-drawer .vpa-list{max-height:380px}
  .vpa-drawer table{min-width:0}
  .vpa-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px;overflow-wrap:anywhere}
  .vpa-search{width:100%;max-width:360px}
  .vpa-map{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px 14px;margin-top:8px}
  .vpa-map label{display:block;font-size:.7rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.04em}
  .vpa-map select{width:100%}
  .vpa-tl{border:1px solid var(--line,#e6e8ee);border-radius:12px;background:var(--card,#fff);padding:10px;margin-bottom:12px;overflow:hidden}
  .vpa-tl svg{display:block;width:100%;height:auto}
  .vpa-tl .ax{stroke:var(--line,#d7dbe3)}
  .vpa-tl text{fill:var(--mut,#667085);font-size:11px;font-family:inherit}
  .vpa-legend{display:flex;gap:14px;flex-wrap:wrap;font-size:.74rem;color:var(--mut,#667085);margin-top:6px}
  .vpa-legend i{display:inline-block;width:12px;height:8px;border-radius:2px;margin-right:5px;vertical-align:middle}
  @media (max-width:820px){.vpa-grid2{grid-template-columns:minmax(0,1fr)}}
  @media (max-width:520px){.vpa-field input[type=number],.vpa-field input.mid,.vpa-field textarea{width:100%}.vpa-field{width:100%}.vpa-field small{max-width:none}.vpa-list table{min-width:0}}
`;

function kpi(v, l, bad) { return '<div class="' + P + '-kpi' + (bad ? " bad" : "") + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>"; }
function pill(cls, text) { return '<span class="' + P + "-pill " + esc(cls) + '">' + esc(text) + "</span>"; }

function evidenceTable(rows) {
  if (!rows || !rows.length) return '<div class="' + P + '-empty">No evidence rows.</div>';
  const cols = [];
  for (const r of rows) for (const k of Object.keys(r || {})) if (!cols.includes(k)) cols.push(k);
  const cell = (v) => (v == null ? "" : Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v));
  return "<table><thead><tr>" + cols.map((c) => "<th>" + esc(c) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + cols.map((c) => "<td>" + esc(cell(r[c])) + "</td>").join("") + "</tr>").join("") + "</tbody></table>";
}

function numField(key, label, help) {
  return '<div class="' + P + '-field"><label for="' + P + "-opt-" + key + '">' + esc(label) + '</label><input id="' + P + "-opt-" + key + '" data-opt="' + esc(key) + '" type="number" min="0" step="any" value="' + esc(DEFAULTS[key]) + '"><small>' + esc(help) + "</small></div>";
}
function textField(id, label, help, placeholder, cls) {
  return '<div class="' + P + '-field"><label for="' + P + "-" + id + '">' + esc(label) + '</label><input id="' + P + "-" + id + '" class="' + (cls || "mid") + '" type="text" placeholder="' + esc(placeholder) + '"><small>' + esc(help) + "</small></div>";
}
function areaField(id, label, help, placeholder) {
  return '<div class="' + P + '-field"><label for="' + P + "-" + id + '">' + esc(label) + '</label><textarea id="' + P + "-" + id + '" placeholder="' + esc(placeholder) + '"></textarea><small>' + esc(help) + "</small></div>";
}
const listOf = (v) => String(v || "").split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean);

/** Mount the tool into main. */
export function renderVpnAudit(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>VPN & Remote Access</h1></div>',
    '<p class="', P, '-sub">Audit who connected to your VPN or zero-trust access and how: leavers still connecting, brute force and password spraying followed by a success, impossible travel and concurrent distant sessions, missing MFA, outdated clients, shared accounts, long, off-hours and dormant sessions, and large transfers. Every finding links to the log lines behind it. Runs entirely in your browser; nothing is uploaded. Travel uses only the coordinates your logs carry (no geolocation lookups); checks whose data is missing are listed as skipped, never guessed.</p>',
    '<div class="', P, '-grid2">',
    '<div class="', P, '-card"><h2>Remote-access logs</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-help">FortiGate VPN event logs (key=value), Palo Alto GlobalProtect log CSV or syslog, Cisco ASA / AnyConnect syslog, OpenVPN server log and status file, Cloudflare Access request logs (Logpush JSON or CSV), Zscaler ZPA user status logs, Azure VPN Gateway P2S diagnostic logs, or any CSV with a time, user and source IP. Formats are detected from the content. Zip and gz archives are unpacked.</p></div>',
    '<div class="', P, '-card"><h2>Roster and mappings</h2><div id="', P, '-drop2"></div>',
    '<p class="', P, '-help">Optional. HR roster (email, username, status, termination date), a username-to-email mapping, and a service-account list (one name per line). Needed for the leaver and not-on-roster checks.</p></div>',
    "</div>",
    '<div class="', P, '-card"><div class="', P, '-row" style="margin-top:0"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button>',
    '<button class="', P, '-btn" id="', P, '-clear" disabled>Clear files</button><span id="', P, '-count" class="', P, '-skip" style="margin-top:0"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><div class="bar"><i></i></div><span></span></div>',
    '<p class="', P, '-help" id="', P, '-feed" style="margin-top:10px">Malicious-IP feed: checking ', esc(FEED_URL), "...</p></div>",
    '<div class="', P, '-card" id="', P, '-files-card" style="display:none"><h2>Files</h2><p class="', P, '-help">Each file is classified by its content. Correct the format if a detection is wrong; tabular files with less than high confidence show a column-mapping panel.</p><div id="', P, '-files"></div></div>',
    '<div class="', P, '-card"><h2>Settings</h2>',
    '<div class="', P, '-ctl">', NUM_FIELDS.map(([k, l, h]) => numField(k, l, h)).join(""), "</div>",
    '<div class="', P, '-sec"><h3>Time</h3><div class="', P, '-ctl">',
    '<div class="', P, '-field"><label class="', P, '-check"><input type="checkbox" id="', P, '-weekend"', DEFAULTS.weekendOffHours ? " checked" : "", '> Weekends are off-hours</label></div>',
    textField("tz", "Business time zone", "IANA name (Europe/London) or a fixed offset (UTC+05:30). Blank = UTC. Used for business hours and termination days.", "UTC"),
    textField("logtz", "Log time zone", "Zone for log timestamps that carry none. Blank = UTC.", "UTC"),
    '<div class="', P, '-field"><label for="', P, '-year">Syslog year</label><input id="', P, '-year" type="number" min="2000" max="2100" placeholder="from data"><small>For syslog lines without a year. Blank = the latest year found in the files.</small></div>',
    "</div></div>",
    '<div class="', P, '-sec"><h3>Accounts and networks</h3><div class="', P, '-ctl">',
    areaField("svc", "Service accounts", "One per line; * wildcards allowed. Excluded from the people checks.", "svc-*\nscanner01"),
    areaField("allow", "Allow-listed source IPs", "IPs or CIDRs (your offices, scanners). Never reported as spraying or new networks.", "203.0.113.0/24"),
    areaField("internal", "Internal ranges", "CIDRs treated as internal. Blank = RFC 1918, CGNAT, loopback, link-local.", DEFAULT_INTERNAL_CIDRS.slice(0, 3).join("\n")),
    "</div></div>",
    '<div class="', P, '-sec"><h3>Minimum client versions</h3><p class="', P, '-help">Enter your minimum supported version per client. Left blank, the outdated-client check is skipped for that product; no version is assumed.</p><div class="', P, '-ctl">',
    PRODUCTS.map((p) => '<div class="' + P + '-field"><label for="' + P + "-ver-" + p + '">' + esc(PRODUCT_LABEL[p]) + '</label><input id="' + P + "-ver-" + p + '" data-ver="' + p + '" class="mid" type="text" placeholder="e.g. 5.1.2"></div>').join(""),
    "</div></div>",
    '<p class="', P, '-help" style="margin-top:12px">Memory: files are read fully into browser memory, then parsed in a background Worker. Several hundred MB of logs needs a few GB of free memory; the sessions table keeps the first ', num(DEFAULTS.maxSessionRows), " rows (findings always cover every session).</p>",
    "</div>",
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-tabs" id="', P, '-tabs" style="display:none"><button class="', P, '-btn on" data-tab="findings">Findings</button><button class="', P, '-btn" data-tab="users">Users</button><button class="', P, '-btn" data-tab="sources">Sources</button><button class="', P, '-btn" data-tab="sessions">Sessions</button><button class="', P, '-btn" data-tab="countries">Countries</button></div>',
    '<div id="', P, '-view"><div class="', P, '-list"><div class="', P, '-empty">No analysis yet. Drop logs or load the synthetic example.</div></div></div>',
    '<div class="', P, '-skip" id="', P, '-skipped"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, tab = "findings", sort = { key: "severity", dir: "desc" }, search = "", selUser = "";

  // ---------------------------------------------------------------- feed (same-origin mirror)
  let feed = null;
  const feedReady = (async () => {
    try {
      const res = await fetch(FEED_URL, { cache: "no-cache" });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const j = await res.json();
      const ips = (Array.isArray(j.data) ? j.data : Array.isArray(j) ? j : []).map((d) => (typeof d === "string" ? d : d && d.ip)).filter(Boolean);
      feed = { ips, updated: j.updated || null, source: j.source || "" };
      $("feed").textContent = "Malicious-IP feed: " + num(ips.length) + " addresses from " + (feed.source || "the mirrored feed") + ", mirrored same-origin, updated " + dt(feed.updated) + " UTC. Matches are leads, not proof.";
    } catch (e) {
      feed = null;
      $("feed").textContent = "Malicious-IP feed not available (" + (e && e.message || e) + "); the feed check will be listed as skipped.";
    }
  })();

  // ---------------------------------------------------------------- files
  function setFiles(list, example = false) {
    files = list; isExample = example;
    const lines = files.reduce((n, f) => n + (f.lines || 0), 0);
    $("count").textContent = files.length ? files.length + " file(s), " + num(lines) + " lines" : "";
    $("run").disabled = !files.some((f) => f.kind === "log"); $("clear").disabled = !files.length;
    renderFiles();
  }

  function renderFiles() {
    const card = $("files-card"); card.style.display = files.length ? "" : "none";
    const box = $("files");
    if (!files.length) { box.innerHTML = ""; return; }
    box.innerHTML = '<div class="' + P + '-list"><table><thead><tr><th>File</th><th>Lines</th><th>Format</th><th>Confidence</th></tr></thead><tbody>' +
      files.map((f, i) => {
        const spec = f.confidence !== "high" && f.headers && f.headers.length ? columnSpec(f.format) : null;
        return "<tr><td>" + esc(f.name) + "</td><td>" + num(f.lines) + '</td><td><select data-fmt="' + i + '" aria-label="Format of ' + esc(f.name) + '">' +
          FORMATS.concat(f.format === "unknown" ? ["unknown"] : []).concat(["ignore"]).map((k) => '<option value="' + k + '"' + (f.format === k ? " selected" : "") + ">" + esc(k === "ignore" ? "Ignore this file" : FORMAT_LABEL[k]) + "</option>").join("") +
          "</select></td><td>" + pill("conf-" + (f.format === "ignore" ? "medium" : f.confidence), f.format === "ignore" ? "ignored" : f.confidence) + "</td></tr>" +
          (spec ? '<tr><td colspan="4"><div class="' + P + '-help">Column mapping for ' + esc(f.name) + ' (detected automatically; override where wrong)</div><div class="' + P + '-map">' +
            Object.keys(spec).map((k) => "<div><label>" + esc(k.replace(/_/g, " ")) + '</label><select data-map="' + i + '" data-key="' + esc(k) + '"><option value="">(auto)</option>' +
              f.headers.map((h) => '<option value="' + esc(h) + '"' + ((f.columns || {})[k] === h ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>").join("") + "</div></td></tr>" : "");
      }).join("") + "</tbody></table></div>";
    box.querySelectorAll("[data-fmt]").forEach((el) => el.addEventListener("change", () => {
      const f = files[Number(el.dataset.fmt)]; f.format = el.value; f.kind = kindOf(el.value); f.confidence = "medium"; f.columns = {};
      setFiles(files, isExample);
    }));
    box.querySelectorAll("[data-map]").forEach((el) => el.addEventListener("change", () => {
      const f = files[Number(el.dataset.map)]; f.columns = f.columns || {};
      if (el.value) f.columns[el.dataset.key] = el.value; else delete f.columns[el.dataset.key];
    }));
  }

  async function addFiles(dropped, skippedDz, rosterZone) {
    for (const s of (skippedDz || [])) toast(s.name + " skipped: " + s.reason, "warning");
    const inputs = [];
    for (const f of dropped) inputs.push({ name: f.name, text: await f.text() });
    if (!inputs.length) return;
    const parsed = parseInput(inputs, { parse: false });
    const got = parsed.files.filter((f) => f.text.trim());
    if (rosterZone) {
      for (const f of got) if (f.kind === "log" || f.kind === "unknown") Object.assign(f, { format: /service/i.test(f.name) ? "service" : "roster", kind: /service/i.test(f.name) ? "service" : "roster", confidence: "medium" });
    }
    if (!got.length) { toast("The dropped file(s) are empty", "error"); return; }
    for (const f of got) if (f.format === "unknown") toast(f.name + ": format not recognised; choose one in the Files panel", "warning");
    const merged = isExample ? [] : files.filter((f) => !got.some((g) => g.name === f.name));
    setFiles(merged.concat(got).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)), false);
    toast("Loaded " + got.length + " file(s): " + got.map((f) => FORMAT_LABEL[f.format] || f.format).join(", "));
  }

  mountDropzone($("drop"), {
    maxBytes: 512 * 1024 * 1024, maxFiles: 100, unpack: true, multiple: true,
    label: "Drop VPN / ZTNA logs here (or a zip of them), paste, or browse",
    onFiles: (dropped, info) => addFiles(dropped, info && info.skipped, false),
  });
  mountDropzone($("drop2"), {
    maxBytes: 64 * 1024 * 1024, maxFiles: 10, unpack: true, multiple: true,
    label: "Drop the HR roster, account mapping or service-account list",
    onFiles: (dropped, info) => addFiles(dropped, info && info.skipped, true),
  });

  $("clear").addEventListener("click", () => { setFiles([], false); });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    setFiles(parseInput(ex.files, { parse: false }).files, true);
    toast("Synthetic example loaded: " + ex.files.length + " files (documentation-range IPs, test.darknode.ai people). Press Analyze.");
  });

  function opts() {
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (el.value !== "" && Number.isFinite(n)) o[el.dataset.opt] = n; });
    o.weekendOffHours = $("weekend").checked;
    o.timeZone = $("tz").value.trim() || "UTC";
    o.logTimeZone = $("logtz").value.trim() || "UTC";
    const y = Number($("year").value); o.syslogYear = $("year").value && Number.isFinite(y) ? y : null;
    o.serviceAccounts = listOf($("svc").value);
    o.allowIps = listOf($("allow").value);
    o.internalCidrs = listOf($("internal").value);
    o.minClientVersions = {};
    main.querySelectorAll("[data-ver]").forEach((el) => { if (el.value.trim()) o.minClientVersions[el.dataset.ver] = el.value.trim(); });
    if (feed && feed.ips.length) { o.feedIps = feed.ips; o.feedUpdated = feed.updated ? String(feed.updated).slice(0, 10) : null; }
    return o;
  }

  $("run").addEventListener("click", async () => {
    const prog = $("prog"), bar = prog.querySelector("i"), lbl = prog.querySelector("span");
    prog.style.display = "block"; bar.style.width = "0%"; lbl.textContent = "Starting"; $("run").disabled = true;
    try {
      await feedReady;
      const payload = files.filter((f) => f.format !== "ignore" && f.kind !== "unknown").map((f) => ({
        name: f.name, text: f.text, format: f.format, kind: f.kind, confidence: f.confidence, headers: f.headers, container: f.container, columns: f.columns || {}, lines: f.lines,
      }));
      result = await runInWorker(ENGINE, "analyze", [{ files: payload }, opts()], {
        onProgress: (i, n, label) => { bar.style.width = (n ? Math.round(i / n * 100) : 0) + "%"; if (label) lbl.textContent = label; },
      });
      tab = "findings"; sort = { key: "severity", dir: "desc" }; search = ""; selUser = "";
      render(result);
      const s = result.summary;
      toast(result.findings.length + " finding(s) across " + num(s.sessions) + " sessions and " + num(s.users) + " users", (s.bySeverity.critical || 0) > 0 ? "warning" : "success");
    } catch (e) {
      toast("Analysis failed: " + (e && e.message || e), "error");
    } finally {
      prog.style.display = "none"; $("run").disabled = !files.some((f) => f.kind === "log");
    }
  });

  // ---------------------------------------------------------------- results
  function render(r) {
    const s = r.summary;
    $("kpis").innerHTML = kpi(num(s.sessions), "sessions") + kpi(num(s.users), "users") + kpi(num(s.leaversConnecting), "leavers connecting", s.leaversConnecting > 0) +
      kpi(num(s.bruteForceSuccesses), "brute-force successes", s.bruteForceSuccesses > 0) + kpi(num(s.impossibleTravel), "impossible travel", s.impossibleTravel > 0) +
      kpi(num(s.noMfaUsers), "no-MFA users", s.noMfaUsers > 0) + kpi(num(s.sprayIps), "spraying sources", s.sprayIps > 0) +
      kpi(num(r.findings.length), "findings") + kpi((s.bySeverity.critical || 0) + " / " + (s.bySeverity.high || 0), "critical / high", (s.bySeverity.critical || 0) > 0);
    $("skipped").innerHTML = (r.skipped.length ? "<b>Skipped checks</b> (data not in these logs, never guessed): " + r.skipped.map((x) => esc(x.check) + " - " + esc(x.reason)).join("; ") : "All checks ran.") +
      (s.firstSeen ? "<br>Log span " + esc(dt(s.firstSeen)) + " to " + esc(dt(s.lastSeen)) + " UTC (" + esc(s.spanDays) + " days). Baseline until " + esc(dt(r.meta.baselineEnd)) + ". Business hours in " + esc(r.meta.timeZone) + "; zone-less log times read as " + esc(r.meta.logTimeZone) + "." : "");
    const ex = $("exports");
    ex.innerHTML = '<button class="' + P + '-btn" data-x="csv">Findings CSV</button><button class="' + P + '-btn" data-x="json">Full JSON</button><button class="' + P + '-btn" data-x="txt">Summary TXT</button>' +
      '<button class="' + P + '-btn" data-x="rev">Revocation list CSV</button><button class="' + P + '-btn" data-x="users">User activity TXT</button><button class="' + P + '-btn" data-x="block">IP blocklist TXT</button>';
    const stamp = fileStamp();
    const on = (k, fn) => ex.querySelector('[data-x="' + k + '"]').addEventListener("click", fn);
    on("csv", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    on("json", () => download(TOOL_ID + "-" + stamp + ".json", toJson(r), "application/json"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r) + "\nBy confidence: " + JSON.stringify(summarize(r.findings).byConfidence || {}) + "\n", "text/plain"));
    on("rev", () => { if (!r.tables.revocation.length) toast("No leavers or shared accounts to revoke", "info"); download(TOOL_ID + "-revocation-" + stamp + ".csv", revocationCsv(r), "text/csv"); });
    on("users", () => download(TOOL_ID + "-user-activity-" + stamp + ".txt", userReportText(r), "text/plain"));
    on("block", () => { if (!r.tables.blocklist.length) toast("No spraying sources or feed matches to block", "info"); download(TOOL_ID + "-ip-blocklist-" + stamp + ".txt", blocklistText(r), "text/plain"); });
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: files.map((f) => f.name).join(", ") });
    const tabs = $("tabs"); tabs.style.display = "";
    tabs.querySelectorAll("[data-tab]").forEach((b) => { b.onclick = () => { tab = b.dataset.tab; sort = defaultSort(tab); search = ""; renderView(r); }; });
    $("drawer").style.display = "none";
    renderView(r);
  }

  function defaultSort(t) {
    return { findings: { key: "severity", dir: "desc" }, users: { key: "risk", dir: "desc" }, sources: { key: "failures", dir: "desc" }, sessions: { key: "start", dir: "asc" }, countries: { key: "users", dir: "desc" } }[t];
  }

  function renderView(r) {
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.classList.toggle("on", b.dataset.tab === tab));
    const v = $("view");
    if (tab !== "findings") $("drawer").style.display = "none";
    if (tab === "findings") renderFindings(r, v);
    else if (tab === "users") renderUsers(r, v);
    else if (tab === "sources") renderSources(r, v);
    else if (tab === "sessions") renderSessions(r, v);
    else renderCountries(r, v);
  }

  function sortable(ths, onSort) {
    ths.forEach((th) => {
      const k = th.dataset.sort; if (!k) return;
      th.classList.toggle("asc", sort.key === k && sort.dir === "asc"); th.classList.toggle("desc", sort.key === k && sort.dir === "desc");
      th.addEventListener("click", () => { sort = { key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" }; onSort(); });
    });
  }
  const by = (get) => (a, b) => { const x = get(a), y = get(b); const c = x < y ? -1 : x > y ? 1 : 0; return sort.dir === "asc" ? c : -c; };
  const val = (row, k) => { const x = row[k]; return Array.isArray(x) ? x.length : typeof x === "boolean" ? Number(x) : x == null ? "" : typeof x === "string" ? x.toLowerCase() : x; };

  function searchBox(v, count, total, noun, rerender) {
    v.insertAdjacentHTML("afterbegin", '<div class="' + P + '-row" style="margin:0 0 10px"><input class="' + P + "-in " + P + '-search" id="' + P + '-search" type="search" placeholder="Search ' + esc(noun) + '" value="' + esc(search) + '"><span class="' + P + '-skip" style="margin-top:0">' + num(count) + " of " + num(total) + " " + esc(noun) + "</span></div>");
    const inp = v.querySelector("#" + P + "-search");
    inp.addEventListener("input", () => { search = inp.value; const pos = inp.selectionStart; rerender(); const n = v.querySelector("#" + P + "-search"); n.focus(); try { n.setSelectionRange(pos, pos); } catch (_) {} });
  }

  function renderFindings(r, v) {
    if (!r.findings.length) { v.innerHTML = '<div class="' + P + '-list"><div class="' + P + '-empty">No findings for the current thresholds and files.</div></div>'; return; }
    const CONF = { confirmed: 3, likely: 2, review: 1 };
    const getters = { severity: (f) => SEV_RANK[f.severity] || 0, title: (f) => f.title.toLowerCase(), confidence: (f) => CONF[f.confidence] || 0, category: (f) => f.category, evidence: (f) => f.evidenceCount || 0 };
    const g = getters[sort.key] || getters.severity;
    const list = r.findings.map((f, i) => ({ f, i })).sort((a, b) => by((x) => g(x.f))(a, b) || (SEV_RANK[b.f.severity] - SEV_RANK[a.f.severity]) || a.i - b.i);
    v.innerHTML = '<div class="' + P + '-list"><table><thead><tr><th data-sort="severity">Severity</th><th data-sort="title">Finding</th><th data-sort="category">Category</th><th data-sort="confidence">Confidence</th><th>Controls</th><th data-sort="evidence">Evidence</th></tr></thead><tbody>' +
      list.map(({ f, i }) => '<tr data-i="' + i + '"><td>' + pill(f.severity, f.severity) + "</td><td><b>" + esc(f.title) + "</b><div>" + esc(f.description) + "</div></td><td>" + esc(f.category.replace(/_/g, " ")) + '</td><td class="' + P + '-conf">' + esc(f.confidence) + "</td><td>" +
        (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</td><td>" + num(f.evidenceCount) + "</td></tr>").join("") + "</tbody></table></div>";
    sortable(v.querySelectorAll("th[data-sort]"), () => renderFindings(r, v));
    v.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => {
      v.querySelectorAll("tr.sel").forEach((x) => x.classList.remove("sel")); tr.classList.add("sel");
      openDrawer(r.findings[Number(tr.dataset.i)]);
    }));
  }

  function openDrawer(f) {
    const d = $("drawer"); d.style.display = "block";
    const users = (f.assets || []).filter((a) => a.type === "IDENTITY").map((a) => a.name).filter(Boolean);
    d.innerHTML = '<div class="' + P + '-card"><div class="' + P + '-hd"><h2 style="margin:0">' + esc(f.title) + "</h2>" + pill(f.severity, f.severity) + '<span class="' + P + '-conf">' + esc(f.confidence) + '</span></div><p class="' + P + '-help">' + esc(f.description) + "</p><p><b>Recommendation.</b> " + esc(f.recommendation) + "</p><div>" +
      (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + '</div><p class="' + P + '-help">Evidence: ' + num(f.evidenceCount) + " row(s)" + (f.evidenceCount > (f.evidence || []).length ? ", first " + (f.evidence || []).length + " shown" : "") + "</p>" +
      '<div class="' + P + '-list">' + evidenceTable(f.evidence) + "</div>" +
      (users.length === 1 && result && result.tables.users.some((u) => u.user === users[0]) ? '<div class="' + P + '-row"><button class="' + P + '-btn" id="' + P + '-goto">Show sessions of ' + esc(users[0]) + "</button></div>" : "") + "</div>";
    const go = d.querySelector("#" + P + "-goto");
    if (go) go.addEventListener("click", () => { selUser = users[0]; tab = "sessions"; sort = defaultSort("sessions"); search = ""; renderView(result); $("view").scrollIntoView({ behavior: "smooth", block: "start" }); });
    d.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function renderUsers(r, v) {
    const all = r.tables.users || [];
    const q = search.toLowerCase();
    const rows = all.filter((u) => !q || [u.user, u.name, u.department, u.rosterStatus, u.lastIp, ...(u.countries || []), ...(u.flags || [])].join(" ").toLowerCase().includes(q));
    rows.sort(by((u) => val(u, sort.key)));
    v.innerHTML = '<div class="' + P + '-list"><table><thead><tr><th data-sort="user">User</th><th data-sort="rosterStatus">Roster</th><th data-sort="sessions">Sessions</th><th data-sort="hours">Hours</th><th data-sort="successes">OK</th><th data-sort="failures">Fail</th><th data-sort="ips">IPs</th><th data-sort="devices">Devices</th><th>Countries</th><th data-sort="lastSeen">Last seen</th><th data-sort="risk">Risk</th><th>Flags</th></tr></thead><tbody>' +
      (rows.length ? rows.map((u) => '<tr data-u="' + esc(u.user) + '"><td><b>' + esc(u.user) + "</b>" + (u.name ? '<div class="' + P + '-help" style="margin:0">' + esc(u.name) + (u.department ? " - " + esc(u.department) : "") + "</div>" : "") + "</td><td>" + esc(u.rosterStatus) + (u.termination ? '<div class="' + P + '-help" style="margin:0">terminated ' + esc(u.termination) + "</div>" : "") + (u.matchBasis ? '<div class="' + P + '-help" style="margin:0">by ' + esc(u.matchBasis) + "</div>" : "") +
        "</td><td>" + num(u.sessions) + "</td><td>" + num(u.hours) + "</td><td>" + num(u.successes) + "</td><td>" + num(u.failures) + "</td><td>" + num(u.ips) + "</td><td>" + num(u.devices) + "</td><td>" + esc((u.countries || []).join(" ") || "-") + "</td><td>" + esc(dt(u.lastSeen)) + (u.lastIp ? '<div class="' + P + '-help" style="margin:0">' + esc(u.lastIp) + "</div>" : "") + "</td><td>" + num(u.risk) + "</td><td>" +
        (u.flags || []).map((f) => '<span class="' + P + '-flag">' + esc(f) + "</span>").join("") + "</td></tr>").join("") : '<tr><td colspan="12" class="' + P + '-empty">No users match.</td></tr>') + "</tbody></table></div>";
    searchBox(v, rows.length, all.length, "users", () => renderUsers(r, v));
    sortable(v.querySelectorAll("th[data-sort]"), () => renderUsers(r, v));
    v.querySelectorAll("tr[data-u]").forEach((tr) => tr.addEventListener("click", () => { selUser = tr.dataset.u; tab = "sessions"; sort = defaultSort("sessions"); search = ""; renderView(r); }));
  }

  function renderSources(r, v) {
    const all = r.tables.sources || [];
    const q = search.toLowerCase();
    const rows = all.filter((s) => !q || [s.ip, ...(s.countries || []), s.feed ? "feed" : "", s.spraying ? "spraying" : "", s.internal ? "internal" : ""].join(" ").toLowerCase().includes(q));
    rows.sort(by((s) => val(s, sort.key)));
    v.innerHTML = '<div class="' + P + '-list"><table><thead><tr><th data-sort="ip">Source IP</th><th data-sort="users">Users</th><th data-sort="successes">Successes</th><th data-sort="failures">Failures</th><th>Countries</th><th data-sort="firstSeen">First seen</th><th data-sort="lastSeen">Last seen</th><th>Notes</th></tr></thead><tbody>' +
      (rows.length ? rows.map((s) => "<tr><td><b>" + esc(s.ip) + "</b></td><td>" + num(s.users) + "</td><td>" + num(s.successes) + "</td><td>" + num(s.failures) + "</td><td>" + esc((s.countries || []).join(" ") || "-") + "</td><td>" + esc(dt(s.firstSeen)) + "</td><td>" + esc(dt(s.lastSeen)) + "</td><td>" +
        (s.spraying ? '<span class="' + P + '-flag">spraying</span>' : "") + (s.feed ? '<span class="' + P + '-flag">feed match</span>' : "") + (s.internal ? '<span class="' + P + '-chip">internal</span>' : "") + (s.allowListed ? '<span class="' + P + '-chip">allow-listed</span>' : "") + "</td></tr>").join("") : '<tr><td colspan="8" class="' + P + '-empty">No sources match.</td></tr>') + "</tbody></table></div>" +
      (r.meta.sourcesTruncated ? '<p class="' + P + '-skip">Showing the first 5,000 sources; the JSON export has the same cap. Findings cover every source.</p>' : "");
    searchBox(v, rows.length, all.length, "sources", () => renderSources(r, v));
    sortable(v.querySelectorAll("th[data-sort]"), () => renderSources(r, v));
  }

  function renderCountries(r, v) {
    const rows = (r.tables.countries || []).slice();
    if (!rows.length) { v.innerHTML = '<div class="' + P + '-list"><div class="' + P + '-empty">These logs carry no country field, so no country breakdown is possible.</div></div>'; return; }
    rows.sort(by((c) => val(c, sort.key)));
    v.innerHTML = '<p class="' + P + '-help">Countries as recorded in the logs themselves (no geolocation lookups).</p><div class="' + P + '-list"><table><thead><tr><th data-sort="country">Country</th><th data-sort="users">Users</th><th data-sort="sessions">Sessions</th><th data-sort="successes">Successes</th><th data-sort="failures">Failures</th><th data-sort="ips">Source IPs</th></tr></thead><tbody>' +
      rows.map((c) => "<tr><td><b>" + esc(c.country) + "</b></td><td>" + num(c.users) + "</td><td>" + num(c.sessions) + "</td><td>" + num(c.successes) + "</td><td>" + num(c.failures) + "</td><td>" + num(c.ips) + "</td></tr>").join("") + "</tbody></table></div>";
    sortable(v.querySelectorAll("th[data-sort]"), () => renderCountries(r, v));
  }

  function renderSessions(r, v) {
    const users = [...new Set((r.tables.sessions || []).map((s) => s.user))].sort();
    if (!users.length) { v.innerHTML = '<div class="' + P + '-list"><div class="' + P + '-empty">No sessions could be reconstructed from these logs (authentication events only).</div></div>'; return; }
    if (!users.includes(selUser)) {
      const risky = (r.tables.users || []).slice().sort((a, b) => b.risk - a.risk || (a.user < b.user ? -1 : 1)).find((u) => users.includes(u.user));
      selUser = risky ? risky.user : users[0];
    }
    const mine = r.tables.sessions.filter((s) => s.user === selUser);
    const rows = mine.slice().sort(by((s) => val(s, sort.key)));
    v.innerHTML = '<div class="' + P + '-row" style="margin:0 0 10px"><div class="' + P + '-field"><label for="' + P + '-user">User</label><select id="' + P + '-user" class="' + P + '-in">' +
      users.map((u) => '<option value="' + esc(u) + '"' + (u === selUser ? " selected" : "") + ">" + esc(u) + "</option>").join("") + '</select></div><span class="' + P + '-skip">' + num(mine.length) + " session(s)" + (r.meta.sessionsTruncated ? "; table capped at " + num(r.meta.options.maxSessionRows) + " rows overall" : "") + "</span></div>" +
      timeline(r, mine) +
      '<div class="' + P + '-list"><table><thead><tr><th data-sort="start">Start</th><th data-sort="end">End</th><th data-sort="hours">Hours</th><th data-sort="ip">Source IP</th><th data-sort="country">Country</th><th data-sort="device">Device</th><th data-sort="version">Client</th><th data-sort="bytesOut">To user</th><th data-sort="bytesIn">From user</th><th data-sort="file">Source</th></tr></thead><tbody>' +
      rows.map((s) => "<tr><td>" + esc(dt(s.start)) + (s.inferredStart ? '<div class="' + P + '-help" style="margin:0">inferred from duration</div>' : "") + "</td><td>" + (s.open ? '<span class="' + P + '-chip">open</span>' : esc(dt(s.end))) + "</td><td>" + (s.hours == null ? "-" : num(s.hours)) + "</td><td>" + esc(s.ip || "-") + "</td><td>" + esc(s.country || "-") + "</td><td>" + esc(s.device || "-") + "</td><td>" + esc([s.client, s.version].filter(Boolean).join(" ") || "-") +
        "</td><td>" + esc(bytes(s.bytesOut)) + "</td><td>" + esc(bytes(s.bytesIn)) + "</td><td>" + esc(s.file || "") + (s.line ? ":" + esc(s.line) : "") + "</td></tr>").join("") + "</tbody></table></div>";
    v.querySelector("#" + P + "-user").addEventListener("change", (e) => { selUser = e.target.value; renderSessions(r, v); });
    sortable(v.querySelectorAll("th[data-sort]"), () => renderSessions(r, v));
  }

  // SVG timeline of one user's sessions across the whole log span; overlapping sessions get separate lanes.
  function timeline(r, sessions) {
    const t0 = Date.parse(r.summary.firstSeen), t1 = Date.parse(r.summary.lastSeen);
    if (!Number.isFinite(t0) || !Number.isFinite(t1) || !sessions.length) return "";
    const span = Math.max(t1 - t0, 3600000);
    const W = 1000, L = 10, R = 10, laneH = 16, top = 8;
    const x = (t) => L + ((t - t0) / span) * (W - L - R);
    const maxH = Number(r.meta.options.maxSessionHours) || 24;
    const items = sessions.map((s) => {
      const a = Date.parse(s.start);
      const b = s.end ? Date.parse(s.end) : s.hours != null ? a + s.hours * 3600000 : t1;
      return { s, a, b: Math.max(b, a) };
    }).filter((it) => Number.isFinite(it.a)).sort((p, q) => p.a - q.a);
    const lanes = [];
    for (const it of items) {
      let k = lanes.findIndex((end) => end <= it.a);
      if (k < 0) { k = lanes.length; lanes.push(0); }
      lanes[k] = it.b; it.lane = k;
    }
    const nl = Math.min(lanes.length, 12);
    const H = top + nl * laneH + 28;
    const ticks = [];
    const days = span / 86400000;
    const step = days > 60 ? 7 : days > 20 ? 2 : 1;
    const d0 = new Date(t0); d0.setUTCHours(0, 0, 0, 0);
    for (let t = d0.getTime(); t <= t1; t += step * 86400000) if (t >= t0) ticks.push(t);
    const thin = ticks.length > 16 ? Math.ceil(ticks.length / 16) : 1;
    const bars = items.filter((it) => it.lane < nl).map((it) => {
      const color = it.s.open ? "#b58100" : it.s.hours != null && it.s.hours > maxH ? "#b00020" : "#2552c6";
      const w = Math.max(2, x(it.b) - x(it.a));
      return '<rect x="' + x(it.a).toFixed(1) + '" y="' + (top + it.lane * laneH) + '" width="' + w.toFixed(1) + '" height="' + (laneH - 5) + '" rx="2" fill="' + color + '"><title>' + esc(dt(it.s.start) + " - " + (it.s.open ? "open" : dt(it.s.end)) + ", " + (it.s.hours == null ? "?" : it.s.hours) + " h, " + (it.s.ip || "no IP") + (it.s.country ? " " + it.s.country : "") + (it.s.device ? ", " + it.s.device : "")) + "</title></rect>";
    }).join("");
    const axisY = top + nl * laneH + 4;
    const tickSvg = ticks.filter((_, i) => i % thin === 0).map((t) => '<line class="ax" x1="' + x(t).toFixed(1) + '" x2="' + x(t).toFixed(1) + '" y1="' + top + '" y2="' + axisY + '" stroke-dasharray="2 3"/><text x="' + x(t).toFixed(1) + '" y="' + (axisY + 15) + '" text-anchor="middle">' + esc(new Date(t).toISOString().slice(5, 10)) + "</text>").join("");
    return '<div class="' + P + '-tl"><svg viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Session timeline for ' + esc(selUser) + '">' + tickSvg + '<line class="ax" x1="' + L + '" x2="' + (W - R) + '" y1="' + axisY + '" y2="' + axisY + '"/>' + bars + "</svg>" +
      '<div class="' + P + '-legend"><span><i style="background:#2552c6"></i>session</span><span><i style="background:#b00020"></i>over ' + esc(maxH) + ' h</span><span><i style="background:#b58100"></i>still open at end of log</span><span>Dates in UTC; hover a bar for details' + (lanes.length > nl ? "; " + (lanes.length - nl) + " more overlapping lane(s) not drawn" : "") + "</span></div></div>";
  }
}
