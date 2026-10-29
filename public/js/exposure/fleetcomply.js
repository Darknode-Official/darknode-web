// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Endpoint Fleet Compliance (fleetcomply): Deck tool UI. Drop every endpoint inventory
// (Intune, Jamf, CrowdStrike, Defender, Google, Entra / Okta / AD, software inventories and
// Darknode Workstation Audit fleet records); the engine reconciles them into one device
// register and checks each device against the baseline inside a Worker. Runs entirely in
// the browser; the only request is the same-origin EOL mirror. No native dialogs.
//
//   renderFleetComply(main) -> void

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, COLUMNS, FORMATS, KIND_LABEL, WEIGHTS, DETECTIONS, SEV_RANK,
  detectFile, findingsToCsv, devicesToCsv, softwareToCsv, worklistToCsv, coverageToCsv, summaryText, exampleDataset,
} from "./fleetcomply-engine.js?v=20261026b";

const ENGINE = engineUrl("./fleetcomply-engine.js?v=20261026b", import.meta);
const P = "flt";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const CONF_RANK = { confirmed: 3, likely: 2, review: 1 };
const EOL_RANK = { eol: 3, soon: 2, unknown: 1, supported: 0 };
const fmtSize = (n) => (n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB");
const yn = (v) => (v === true ? "yes" : v === false ? "no" : "-");

const CSS = `
  .flt-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .flt-root *{box-sizing:border-box}
  .flt-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .flt-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .flt-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .flt-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:95ch}
  .flt-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .flt-card h2{font-size:.95rem;margin:0 0 10px}
  .flt-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .flt-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .flt-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .flt-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .flt-btn.sm{padding:4px 9px;font-size:.76rem}
  .flt-btn:disabled{opacity:.5;cursor:default}
  .flt-files{display:flex;flex-direction:column;gap:6px;margin-top:12px}
  .flt-file{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;font-size:.82rem;min-width:0}
  .flt-file b{overflow-wrap:anywhere;min-width:0}
  .flt-file select{font:inherit;font-size:.78rem;max-width:100%;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:3px 6px;background:var(--card,#fff);color:var(--tx,#1a2230)}
  .flt-muted{color:var(--mut,#667085)}
  .flt-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085)}
  .flt-conf.high{color:#1b7f4d;border-color:#1b7f4d}.flt-conf.medium{color:#8a6d00;border-color:#8a6d00}.flt-conf.low{color:#b00020;border-color:#b00020}
  .flt-ctl{display:flex;flex-wrap:wrap;gap:14px 20px;align-items:flex-start}
  .flt-field{display:flex;flex-direction:column;gap:4px;min-width:0;flex:1 1 170px}
  .flt-field.wide{flex:1 1 300px}
  .flt-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .flt-field input,.flt-field select,.flt-field textarea{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%}
  .flt-field textarea{min-height:84px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}
  .flt-field small{font-size:.74rem;color:var(--mut,#667085);line-height:1.4}
  .flt-wgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px 14px;margin-top:10px}
  .flt-wgrid label{display:flex;justify-content:space-between;gap:8px;align-items:center;font-size:.78rem;min-width:0}
  .flt-wgrid span{overflow-wrap:anywhere;min-width:0}
  .flt-wgrid input{width:64px;font:inherit;font-size:.8rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:3px 6px;background:var(--card,#fff);color:var(--tx,#1a2230)}
  .flt-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .flt-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:110px;flex:1 1 110px}
  .flt-kpi b{display:block;font-size:1.3rem}
  .flt-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .flt-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .flt-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .flt-plabel{font-size:.74rem;color:var(--mut,#667085);margin-top:4px;display:none;overflow-wrap:anywhere}
  .flt-tabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;border-bottom:1px solid var(--line,#e6e8ee);padding-bottom:8px}
  .flt-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid transparent;background:none;color:var(--mut,#667085);padding:6px 12px;border-radius:8px;cursor:pointer}
  .flt-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#d7dbe3);background:var(--bg,#f7f8fb)}
  .flt-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .flt-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:640px}
  .flt-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .flt-nw{white-space:nowrap}
  .flt-list th.on{color:var(--tx,#1a2230)}
  .flt-list th.on::after{content:" \\2193";font-size:.7rem}
  .flt-list th.on.asc::after{content:" \\2191"}
  .flt-list td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word}
  .flt-list tr[data-i]{cursor:pointer}
  .flt-list tr[data-i]:hover,.flt-list tr.sel{background:var(--bg,#f7f8fb)}
  .flt-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .flt-pill.critical,.flt-pill.eol,.flt-pill.fail{background:#7a0012}.flt-pill.high{background:#b00020}.flt-pill.medium,.flt-pill.soon{background:#b58100}.flt-pill.low{background:#2552c6}.flt-pill.info,.flt-pill.unknown,.flt-pill.nodata{background:#667085}.flt-pill.supported,.flt-pill.pass{background:#1b7f4d}
  .flt-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .flt-score{font-weight:700}.flt-score.bad{color:#b00020}.flt-score.mid{color:#8a6d00}.flt-score.good{color:#1b7f4d}
  .flt-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .flt-drawer{margin-top:12px;display:none;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--bg,#f7f8fb);min-width:0}
  .flt-drawer h3{margin:0 0 6px;font-size:1rem;overflow-wrap:anywhere}
  .flt-drawer p{margin:6px 0}
  .flt-drawer .flt-list{background:var(--card,#fff);margin-top:10px}
  .flt-drawer .flt-list table{min-width:480px}
  .flt-skip{font-size:.78rem;color:var(--mut,#667085);margin:8px 0 0;padding-left:18px}
  .flt-skip li{margin:2px 0;overflow-wrap:anywhere}
  .flt-filters{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:flex-end;margin-bottom:10px}
  .flt-filters .flt-field{flex:0 1 180px}
  .flt-svg{width:100%;height:auto;display:block}
  .flt-svg text{font:12px system-ui,sans-serif;fill:var(--tx,#1a2230)}
  .flt-svg .m{fill:var(--mut,#667085)}
  .flt-legend{display:flex;flex-wrap:wrap;gap:12px;font-size:.76rem;color:var(--mut,#667085);margin-top:8px}
  .flt-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
  .flt-dist{display:flex;flex-wrap:wrap;gap:6px;font-size:.76rem;margin-top:6px}
  @media (max-width:560px){.flt-field,.flt-field.wide,.flt-filters .flt-field{flex:1 1 100%}.flt-card{padding:14px}.flt-kpi{flex:1 1 calc(50% - 10px)}}
`;

const kpi = (v, l) => '<div class="' + P + '-kpi"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const pill = (s, label) => '<span class="' + P + "-pill " + esc(s) + '">' + esc(label || s) + "</span>";
const scoreCls = (n) => (n < 50 ? "bad" : n < 80 ? "mid" : "good");
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

/** Plain table: columns are the union of keys. */
function plainTable(rows) {
  if (!rows || !rows.length) return '<p class="' + P + '-note">No rows.</p>';
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
  const cell = (v) => (v === true ? "yes" : v === false ? "no" : v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => "<td>" + esc(cell(r[k])) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

const THRESHOLDS = [
  ["edrStaleDays", "EDR silent after (days)", "Sensor not seen for longer than this while MDM still sees the device."],
  ["staleDays", "Stale device after (days)", "No check-in in any source for longer than this."],
  ["lostDays", "Possibly lost after (days)", "Stale this long with an enabled directory account is rated high."],
  ["eolSoonDays", "EOL warning window (days)", "Operating systems reaching end of life within this window."],
  ["patchAgeBuilds", "Allowed releases behind", "Distinct newer OS releases seen in your fleet before a device is flagged."],
  ["sensorMinorLag", "EDR sensor minor versions behind", "Compared with the most common sensor version in the fleet."],
  ["maxLocalAdmins", "Maximum local admin accounts", "More admin accounts than this on one device is flagged."],
];
const WEIGHT_LABEL = {
  encryption: "No disk encryption", edr_missing: "EDR missing", edr_unhealthy: "EDR unhealthy", edr_stale: "EDR silent", sensor_behind: "Sensor version behind",
  os_eol: "End-of-life OS", os_eol_soon: "OS EOL soon", app_eol: "EOL browser/runtime", patch_behind: "Patch level behind", stale: "Stale device", stale_enabled: "Lost, still enabled",
  local_admin: "User is local admin", many_admins: "Too many admins", firewall: "Firewall off", gatekeeper_sip: "Gatekeeper/SIP off", jailbroken: "Jailbroken",
  screen_lock: "Screen lock failing", secure_boot: "Secure Boot off", recovery_lock: "No Recovery Lock", activation_lock: "No Activation Lock", guest_account: "Guest account on",
  noncompliant: "Non-compliant", unmanaged: "Unmanaged", blocklist: "Blocklisted software", remote_access: "Remote-access tool",
};

/** Mount the tool into main. */
export function renderFleetComply(main) {
  if (!document.getElementById(P + "-css")) { const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st); }
  const fmtOptions = Object.entries(FORMATS).map(([k, f]) => [k, f.label]);
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Devices</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Reconcile every endpoint inventory you have (Intune, Jamf, CrowdStrike, Defender, Google, Entra / Okta / Active Directory, software inventories and Darknode Workstation Audit fleet records) into one device register, then check each device for disk encryption, a healthy EDR sensor, end-of-life OS and browsers, patch level, check-in age, local admins, firewall and unauthorized software. Runs entirely in your browser. Nothing is uploaded. End-of-life dates come from the endoflife.date mirror on this site (<span id="', P, '-eolhdr">mirror not loaded yet</span>); nothing is fetched live.</p>',
    '<div class="', P, '-card"><h2>1. Inventories</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-note">Drop several exports at once, or a zip of them. Devices are matched by serial number, then hostname (domain stripped), then Intune / Entra device id, then MAC address.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div><div id="', P, '-map"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze fleet</button><button class="', P, '-btn" id="', P, '-clear" disabled>Clear files</button><span class="', P, '-note" id="', P, '-count"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-plabel" id="', P, '-plabel"></div></div>',
    '<div class="', P, '-card"><h2>2. Baseline</h2><div class="', P, '-ctl" id="', P, '-thr"></div>',
    '<details style="margin-top:12px"><summary class="', P, '-note" style="cursor:pointer">Device score weights (points subtracted from 100 per failed check)</summary><div class="', P, '-wgrid" id="', P, '-weights"></div></details></div>',
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card" id="', P, '-results" style="display:none"><div class="', P, '-tabs" id="', P, '-tabs"></div><div id="', P, '-pane"></div><div class="', P, '-drawer" id="', P, '-drawer"></div><ul class="', P, '-skip" id="', P, '-skipped"></ul></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, running = false, eolFeed = null, exampleNow = null;
  let tab = "devices", sel = null;
  const sorts = { devices: { key: "score", dir: "asc" }, software: { key: "devices", dir: "desc" }, findings: { key: "severity", dir: "desc" } };
  const filters = { q: "", source: "", family: "", check: "", sq: "" };
  const columnMap = {};

  // Baseline panel
  $("thr").innerHTML = THRESHOLDS.map(([k, label, help]) => '<div class="' + P + '-field"><label for="' + P + "-o-" + k + '">' + esc(label) + '</label><input id="' + P + "-o-" + k + '" data-opt="' + k + '" type="number" min="0" step="1" value="' + DEFAULTS[k] + '"><small>' + esc(help) + " Default " + DEFAULTS[k] + ".</small></div>").join("") +
    '<div class="' + P + '-field"><label for="' + P + '-o-ed">Windows servicing track</label><select id="' + P + '-o-ed"><option value="w">Home / Pro (shorter support)</option><option value="e">Enterprise / Education</option></select><small>Used when the OS string does not name the edition.</small></div>' +
    '<div class="' + P + '-field"><label for="' + P + '-o-now">Reference date</label><input id="' + P + '-o-now" type="date"><small>Blank = newest timestamp in the data.</small></div>' +
    '<div class="' + P + '-field wide"><label for="' + P + '-o-block">Blocklist</label><textarea id="' + P + '-o-block" placeholder="one name or /regex/ per line" spellcheck="false"></textarea><small>Matched against software titles from the inventories; matches are high severity.</small></div>' +
    '<div class="' + P + '-field wide"><label for="' + P + '-o-allow">Allowlist</label><textarea id="' + P + '-o-allow" placeholder="one name or /regex/ per line" spellcheck="false"></textarea><small>Approved remote-access tools. The built-in review list covers AnyDesk, TeamViewer, RustDesk, ngrok, Tailscale, LogMeIn, Chrome Remote Desktop, uTorrent, Tor Browser and VNC servers.</small></div>';
  $("weights").innerHTML = Object.keys(WEIGHTS).map((k) => '<label><span>' + esc(WEIGHT_LABEL[k] || k) + '</span><input type="number" min="0" max="100" step="1" data-w="' + k + '" value="' + WEIGHTS[k] + '"></label>').join("");

  fetch("/data/feeds/eol-products.json").then((r) => (r.ok ? r.json() : null)).then((j) => {
    if (!j || !Array.isArray(j.data)) throw new Error("bad feed");
    eolFeed = j; $("eolhdr").textContent = "mirrored " + String(j.updated || "").slice(0, 10) + ", " + j.data.length + " products";
  }).catch(() => { $("eolhdr").textContent = "mirror unavailable: end-of-life checks will be skipped"; });

  const datasetName = () => (isExample ? "synthetic example" : files.map((f) => f.name).join(", "));

  function renderFiles() {
    const box = $("files");
    box.innerHTML = files.map((f, i) => '<div class="' + P + '-file"><b>' + esc(f.name) + '</b><span class="' + P + '-muted">' + esc(fmtSize(f.size)) + "</span>" +
      '<span class="' + P + "-conf " + esc(f.det.confidence) + '">' + esc(f.det.confidence) + " confidence</span>" +
      '<span class="' + P + '-muted">' + esc(KIND_LABEL[(FORMATS[f.treatAs || f.det.format] || {}).kind] || "unrecognised") + "</span>" +
      '<label class="' + P + '-muted">treat as <select data-as="' + i + '"><option value="">' + esc("detected: " + ((FORMATS[f.det.format] || {}).label || f.det.format)) + "</option>" +
      fmtOptions.map(([k, l]) => '<option value="' + esc(k) + '"' + (f.treatAs === k ? " selected" : "") + ">" + esc(l) + "</option>").join("") + "</select></label>" +
      '<button class="' + P + '-btn sm" data-rm="' + i + '" type="button">Remove</button></div>').join("");
    box.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { files.splice(Number(b.dataset.rm), 1); isExample = false; renderFiles(); }));
    box.querySelectorAll("[data-as]").forEach((s) => s.addEventListener("change", () => { files[Number(s.dataset.as)].treatAs = s.value; renderFiles(); }));
    $("count").textContent = files.length ? files.length + " file" + (files.length === 1 ? "" : "s") + (isExample ? " (synthetic example)" : "") : "";
    $("run").disabled = !files.length || running;
    $("clear").disabled = !files.length;
    renderMapping();
  }

  function renderMapping() {
    const need = files.filter((f) => (f.treatAs || f.det.format) === "generic" || (f.det.confidence !== "high" && !f.treatAs && FORMATS[f.det.format] && FORMATS[f.det.format].headers));
    const box = $("map");
    if (!need.length) { box.innerHTML = ""; return; }
    box.innerHTML = need.map((f) => {
      const cm = columnMap[f.name] || (columnMap[f.name] = {});
      const norm = (h) => String(h).toLowerCase().replace(/[^a-z0-9]/g, "");
      return '<div class="' + P + '-card" style="margin:12px 0 0"><h2>Column mapping: ' + esc(f.name) + '</h2><p class="' + P + '-note">' +
        ((f.treatAs || f.det.format) === "generic" ? "This layout was not recognised. Map the columns the engine should read; unmapped columns disable the checks that need them." : "Detected as " + esc(FORMATS[f.det.format].label) + " with " + esc(f.det.confidence) + " confidence. Confirm it with 'treat as', or choose Generic and map the columns.") + "</p>" +
        ((f.treatAs || f.det.format) === "generic" ? '<div class="' + P + '-ctl">' + Object.keys(COLUMNS).map((k) => '<div class="' + P + '-field"><label>' + esc(k) + '</label><select data-file="' + esc(f.name) + '" data-col="' + esc(k) + '"><option value="">(not present)</option>' +
          f.det.headers.map((h) => '<option value="' + esc(h) + '"' + (cm[k] === h || (!cm[k] && COLUMNS[k].some((a) => norm(a) === norm(h))) ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>").join("") + "</div>" : "") + "</div>";
    }).join("");
    box.querySelectorAll("[data-col]").forEach((s) => {
      const cm = columnMap[s.dataset.file];
      if (s.value) cm[s.dataset.col] = s.value;
      s.addEventListener("change", () => { if (s.value) cm[s.dataset.col] = s.value; else delete cm[s.dataset.col]; });
    });
  }

  function addFile(name, text, size) {
    const det = detectFile({ name, text });
    if (det.format === "empty") { toast(name + " is empty", "warning"); return false; }
    const entry = { name, text, size: size || text.length, det, treatAs: "" };
    const i = files.findIndex((x) => x.name === name);
    if (i >= 0) files[i] = entry; else files.push(entry);
    return true;
  }

  mountDropzone($("drop"), {
    maxBytes: 256 * 1024 * 1024, maxFiles: 500, unpack: true, multiple: true,
    label: "Drop inventory exports (CSV / JSON / zip), paste, or browse",
    onFiles: async (list, info) => {
      let added = 0;
      for (const f of list) if (addFile(f.name, await f.text(), f.size)) added++;
      if (added) { isExample = false; exampleNow = null; toast("Loaded " + added + " file" + (added === 1 ? "" : "s"), "success"); }
      if (info && info.skipped && info.skipped.length) toast(info.skipped.length + " file(s) skipped: " + info.skipped.slice(0, 2).map((s) => s.name + " (" + s.reason + ")").join(", "), "warning");
      renderFiles();
    },
  });

  $("clear").addEventListener("click", () => { files = []; isExample = false; exampleNow = null; renderFiles(); });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    files = []; isExample = true; exampleNow = ex.now;
    for (const f of ex.files) addFile(f.name, f.text);
    renderFiles();
    toast("Synthetic example loaded: " + files.length + " files. Click Analyze fleet.", "info");
  });

  const opts = () => {
    const o = { eol: eolFeed, treatAs: {}, columns: {}, weights: {} };
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (el.value !== "" && Number.isFinite(n) && n >= 0) o[el.dataset.opt] = n; });
    main.querySelectorAll("[data-w]").forEach((el) => { const n = Number(el.value); if (el.value !== "" && Number.isFinite(n) && n >= 0) o.weights[el.dataset.w] = n; });
    o.windowsEdition = $("o-ed").value;
    const now = $("o-now").value.trim(); if (now) o.now = now + "T23:59:59Z"; else if (isExample && exampleNow) o.now = exampleNow;
    o.blocklist = $("o-block").value; o.allowlist = $("o-allow").value;
    for (const f of files) { if (f.treatAs) o.treatAs[f.name] = f.treatAs; if (columnMap[f.name] && Object.keys(columnMap[f.name]).length) o.columns[f.name] = { ...columnMap[f.name] }; }
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
        onProgress: (i, n, label) => { bar.style.width = (n ? Math.round((i / n) * 100) : 0) + "%"; if (label) pl.textContent = label; },
      });
      sel = null;
      render();
      toast(result.summary.devices + " devices, " + result.findings.length + " finding" + (result.findings.length === 1 ? "" : "s"), "success");
    } catch (e) {
      toast("Analysis failed: " + ((e && e.message) || e), "error");
    } finally {
      running = false; prog.style.display = "none"; pl.style.display = "none"; $("run").disabled = !files.length;
    }
  });

  function render() {
    const s = result.summary;
    $("kpis").innerHTML = kpi(s.devices, "devices") + kpi(s.sources, "sources") + kpi(s.fleetScore == null ? "-" : s.fleetScore, "fleet score") + kpi(s.unencrypted, "unencrypted") +
      kpi(s.edrMissing, "EDR missing") + kpi(s.eolOs, "EOL OS") + kpi(s.stale, "stale") + kpi(s.localAdmins, "local admins") + kpi(s.findings, "findings");
    $("results").style.display = "";
    $("skipped").innerHTML = result.skipped.length ? "<li><b>Skipped or limited checks</b></li>" + result.skipped.map((k) => "<li>" + esc(k.check) + ": " + esc(k.reason) + "</li>").join("") : "";
    renderTabs(); renderExports();
  }

  function renderTabs() {
    const t = result.tables;
    const tabs = [["devices", "Devices (" + t.devices.length + ")"], ["software", "Software (" + t.software.length + ")"], ["coverage", "Coverage"], ["os", "OS (" + t.os.length + ")"], ["findings", "Findings (" + result.findings.length + ")"], ["sources", "Sources (" + t.sources.length + ")"]];
    $("tabs").innerHTML = tabs.map(([k, l]) => '<button type="button" class="' + P + "-tab" + (tab === k ? " on" : "") + '" data-tab="' + k + '">' + esc(l) + "</button>").join("");
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; sel = null; $("drawer").style.display = "none"; renderTabs(); }));
    ({ devices: drawDevices, software: drawSoftware, coverage: drawCoverage, os: drawOs, findings: drawFindings, sources: drawSources })[tab]();
  }

  const sel3 = (id, label, options, value) => '<div class="' + P + '-field"><label for="' + P + "-f-" + id + '">' + esc(label) + '</label><select id="' + P + "-f-" + id + '" data-f="' + id + '"><option value="">All</option>' +
    options.map((o) => '<option value="' + esc(o[0]) + '"' + (value === o[0] ? " selected" : "") + ">" + esc(o[1]) + "</option>").join("") + "</select></div>";

  const DEV_COLS = [
    { key: "name", label: "Device", render: (d) => "<b>" + esc(d.name || d.serial) + "</b>" + (d.laptop ? ' <span class="' + P + '-chip">laptop</span>' : "") + (d.serial ? '<div class="' + P + '-muted">' + esc(d.serial) + "</div>" : "") },
    { key: "user", label: "User" },
    { key: "os", label: "OS", render: (d) => esc([d.os, d.osVersion].filter(Boolean).join(" ")) },
    { key: "eolStatus", label: "Support", rank: EOL_RANK, render: (d) => pill(d.eolStatus, d.eolStatus === "unknown" ? "unmapped" : d.eolStatus) + (d.eolDate ? '<div class="' + P + '-muted">' + esc(d.eolDate) + "</div>" : "") },
    { key: "encrypted", label: "Encrypted", render: (d) => esc(yn(d.encrypted)) },
    { key: "edr", label: "EDR", render: (d) => esc(d.edr) + (d.edrHealth && d.edrHealth !== "ok" ? '<div class="' + P + '-muted">' + esc(d.edrHealth) + "</div>" : "") },
    { key: "lastSeen", label: "Last seen", render: (d) => `<span class="flt-nw">${esc(d.lastSeen ? d.lastSeen.slice(0, 10) : "-")}</span>` },
    { key: "sources", label: "Sources", render: (d) => d.sources.map((s) => '<span class="' + P + '-chip">' + esc(s) + "</span>").join("") },
    { key: "score", label: "Score", render: (d) => '<span class="' + P + "-score " + scoreCls(d.score) + '">' + d.score + "</span>" },
    { key: "flagCount", label: "Failed checks", render: (d) => esc(d.flags.map((f) => WEIGHT_LABEL[f] || f).join(", ") || "-") },
  ];

  function drawDevices() {
    const t = result.tables.devices;
    const fams = [...new Set(t.map((d) => d.family || "unknown"))].sort();
    const srcs = [...new Set(t.flatMap((d) => d.sources))].sort();
    const checks = [...new Set(t.flatMap((d) => d.flags))].sort();
    const dist = result.summary.distribution;
    $("pane").innerHTML = '<div class="' + P + '-dist">Score distribution: ' + Object.keys(dist).map((k) => '<span class="' + P + '-chip">' + esc(k) + ": " + dist[k] + "</span>").join("") + '</div><div class="' + P + '-filters" style="margin-top:10px">' +
      '<div class="' + P + '-field"><label for="' + P + '-f-q">Search</label><input id="' + P + '-f-q" data-f="q" type="search" placeholder="name, serial, user" value="' + esc(filters.q) + '"></div>' +
      sel3("source", "Source", srcs.map((s) => [s, (FORMATS[s] || {}).label || s]), filters.source) + sel3("family", "OS family", fams.map((f) => [f, f]), filters.family) +
      sel3("check", "Failing check", checks.map((c) => [c, WEIGHT_LABEL[c] || c]), filters.check) + '</div><div id="' + P + '-dlist"></div>';
    $("pane").querySelectorAll("[data-f]").forEach((el) => el.addEventListener("input", () => { filters[el.dataset.f] = el.value; drawDeviceList(); }));
    drawDeviceList();
  }

  function drawDeviceList() {
    const q = filters.q.trim().toLowerCase();
    const rows = result.tables.devices.map((d, i) => ({ ...d, i, flagCount: d.flags.length })).filter((d) => (!filters.source || d.sources.includes(filters.source)) && (!filters.family || (d.family || "unknown") === filters.family) &&
      (!filters.check || d.flags.includes(filters.check)) && (!q || [d.name, d.serial, d.user, d.model].some((v) => String(v || "").toLowerCase().includes(q))));
    const box = $("dlist");
    box.innerHTML = "";
    if (!rows.length) { box.innerHTML = '<div class="' + P + '-empty">No devices match the filters.</div>'; return; }
    const shown = rows.length > 2000 ? sortBy(rows, sorts.devices.key, sorts.devices.dir).slice(0, 2000) : rows;
    const t = table(DEV_COLS, shown, sorts.devices, (s) => { sorts.devices = s; drawDeviceList(); }, (d) => d.i);
    t.querySelectorAll("tr[data-i]").forEach((tr) => { if (sel === "d" + tr.dataset.i) tr.classList.add("sel"); tr.addEventListener("click", () => { sel = "d" + tr.dataset.i; drawDeviceList(); showDevice(result.tables.devices[Number(tr.dataset.i)]); }); });
    box.appendChild(t);
    const n = document.createElement("p"); n.className = P + "-note";
    n.textContent = rows.length + " of " + result.tables.devices.length + " devices" + (shown.length < rows.length ? " (first 2000 shown; narrow the filters or export the register)" : "") + ". Click a device for every source record side by side.";
    box.appendChild(n);
  }

  function showDevice(d) {
    const dr = $("drawer");
    if (!d) { dr.style.display = "none"; return; }
    const base = [
      ["Disk encryption", d.encrypted === true ? "pass" : d.encrypted === false ? "fail" : "nodata", d.checks.encryption],
      ["EDR sensor", d.flags.some((f) => /^edr/.test(f)) ? "fail" : d.edr === "present" ? "pass" : "nodata", [].concat(d.checks.edr_missing || [], d.checks.edr_unhealthy || [], d.checks.edr_stale || [])],
      ["OS support", d.eolStatus === "eol" ? "fail" : d.eolStatus === "soon" ? "soon" : d.eolStatus === "supported" ? "pass" : "nodata", [d.eolCycle, d.eolDate].filter(Boolean)],
      ["Patch level", d.flags.includes("patch_behind") ? "fail" : "nodata", d.checks.patch_behind],
      ["Check-in age", d.flags.includes("stale") || d.flags.includes("stale_enabled") ? "fail" : d.lastSeen ? "pass" : "nodata", [].concat(d.checks.stale || [], d.checks.stale_enabled || [])],
      ["Local admin", d.localAdmin === true || d.flags.includes("many_admins") ? "fail" : d.localAdmin === false ? "pass" : "nodata", [].concat(d.checks.local_admin || [], d.checks.many_admins || [])],
      ["Host firewall", d.firewall === true ? "pass" : d.firewall === false ? "fail" : "nodata", d.checks.firewall],
      ["Compliance", d.compliance === "compliant" ? "pass" : d.compliance ? "fail" : "nodata", d.compliance ? [d.compliance] : []],
    ];
    const covered = new Set(["encryption", "edr_missing", "edr_unhealthy", "edr_stale", "os_eol", "os_eol_soon", "patch_behind", "stale", "stale_enabled", "local_admin", "many_admins", "firewall", "noncompliant"]);
    for (const f of d.flags) if (!covered.has(f)) base.push([WEIGHT_LABEL[f] || f, "fail", d.checks[f]]);
    const checksHtml = '<div class="' + P + '-list"><table><thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead><tbody>' +
      base.map(([n, st, det]) => "<tr><td>" + esc(n) + "</td><td>" + pill(st, st === "nodata" ? "no data" : st) + "</td><td>" + esc((det || []).join("; ")) + "</td></tr>").join("") + "</tbody></table></div>";
    // Source records side by side: one column per record, one row per field
    const recs = d.records;
    const fields = [];
    for (const r of recs) for (const k of Object.keys(r.row || {})) if (!fields.includes(k)) fields.push(k);
    const cell = (v) => (v === true ? "yes" : v === false ? "no" : v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));
    const side = '<div class="' + P + '-list"><table><thead><tr><th>Field</th>' + recs.map((r) => "<th>" + esc((FORMATS[r.format] || {}).label || r.format) + "</th>").join("") + "</tr></thead><tbody>" +
      fields.map((k) => "<tr><td><b>" + esc(k) + "</b></td>" + recs.map((r) => "<td>" + esc(cell(r.row ? r.row[k] : "")) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
    dr.style.display = "block";
    dr.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + esc(d.name || d.serial) + ' <span class="' + P + "-score " + scoreCls(d.score) + '">score ' + d.score + '</span></h3><button class="' + P + '-btn sm" data-close type="button">Close</button></div>' +
      "<p>" + esc([d.user, d.model, [d.os, d.osVersion].join(" "), d.serial ? "serial " + d.serial : "", d.software ? d.software + " software titles" : ""].filter(Boolean).join(" | ")) + "</p>" +
      "<p><b>Baseline</b></p>" + checksHtml + "<p><b>Source records (" + recs.length + ")</b></p>" + side;
    dr.querySelector("[data-close]").addEventListener("click", () => { dr.style.display = "none"; sel = null; if (tab === "devices") drawDeviceList(); });
    dr.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  const SW_COLS = [
    { key: "name", label: "Software", render: (s) => "<b>" + esc(s.name) + "</b>" + (s.blocklisted ? ' <span class="' + P + '-pill high">blocklisted</span>' : "") + (s.remoteAccess ? ' <span class="' + P + '-chip">remote access: ' + esc(s.remoteAccess) + "</span>" : "") },
    { key: "version", label: "Version" }, { key: "publisher", label: "Publisher" }, { key: "devices", label: "Devices" },
    { key: "eol", label: "Support", rank: EOL_RANK, render: (s) => (s.eol ? pill(s.eol) + (s.eolDate ? ' <span class="' + P + '-muted">' + esc(s.eolDate) + "</span>" : "") : '<span class="' + P + '-muted">not tracked</span>') },
  ];
  function drawSoftware() {
    const t = result.tables.software;
    if (!t.length) { $("pane").innerHTML = '<div class="' + P + '-empty">No software inventory loaded (Intune Discovered apps, SCCM, Lansweeper, Kandji or Jamf applications).</div>'; return; }
    $("pane").innerHTML = '<div class="' + P + '-filters"><div class="' + P + '-field"><label for="' + P + '-f-sq">Search</label><input id="' + P + '-f-sq" type="search" placeholder="title or publisher" value="' + esc(filters.sq) + '"></div></div><div id="' + P + '-slist"></div>';
    const draw = () => {
      const q = filters.sq.trim().toLowerCase();
      const rows = t.filter((s) => !q || (s.name + " " + s.publisher).toLowerCase().includes(q));
      const box = $("slist"); box.innerHTML = "";
      box.appendChild(table(SW_COLS, rows.slice(0, 3000), sorts.software, (s) => { sorts.software = s; draw(); }, null));
      const n = document.createElement("p"); n.className = P + "-note"; n.textContent = rows.length + " title/version pairs" + (rows.length > 3000 ? " (first 3000 shown)" : "") + ". Support status is tracked for Chrome, Firefox, Python, Node.js, Temurin and Office from the EOL mirror."; box.appendChild(n);
    };
    $("f-sq").addEventListener("input", (e) => { filters.sq = e.target.value; draw(); });
    draw();
  }

  function drawCoverage() {
    const c = result.tables.coverage;
    if (!c.length) { $("pane").innerHTML = '<div class="' + P + '-empty">Coverage needs at least two device inventories of different kinds (MDM, EDR, directory, Workstation Audit).</div>'; return; }
    const kinds = [...new Set(c.map((x) => x.from))];
    const get = (a, b) => c.find((x) => x.from === a && x.to === b);
    $("pane").innerHTML = '<p class="' + P + '-note">Rows: where the device was seen. Columns: the inventory it is missing from. Click a cell to list the devices.</p><div class="' + P + '-list"><table style="min-width:420px"><thead><tr><th>Seen in \\ missing from</th>' + kinds.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
      kinds.map((a) => "<tr><td><b>" + esc(a) + "</b></td>" + kinds.map((b) => { if (a === b) return '<td class="' + P + '-muted">-</td>'; const x = get(a, b); return x ? '<td data-cov="' + esc(a + "|" + b) + '" style="cursor:pointer"><b>' + x.missing + '</b> <span class="' + P + '-muted">of ' + x.inFrom + "</span></td>" : "<td></td>"; }).join("") + "</tr>").join("") + "</tbody></table></div>";
    $("pane").querySelectorAll("[data-cov]").forEach((td) => td.addEventListener("click", () => {
      const [a, b] = td.dataset.cov.split("|"); const x = get(a, b);
      const dr = $("drawer"); dr.style.display = "block";
      dr.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>In ' + esc(a) + " but not in " + esc(b) + " (" + x.missing + ')</h3><button class="' + P + '-btn sm" data-close type="button">Close</button></div>' + plainTable(x.devices.map((n) => ({ device: n })));
      dr.querySelector("[data-close]").addEventListener("click", () => { dr.style.display = "none"; });
    }));
  }

  function drawOs() {
    const t = result.tables.os.slice().sort((a, b) => b.devices - a.devices || cmp(a.version, b.version));
    if (!t.length) { $("pane").innerHTML = '<div class="' + P + '-empty">No operating systems reported.</div>'; return; }
    const max = Math.max(...t.map((x) => x.devices)), rowH = 26, labelW = 190, W = 760, barW = W - labelW - 170;
    const color = { eol: "#7a0012", soon: "#b58100", supported: "#1b7f4d", unknown: "#98a2b3" };
    const svg = '<svg class="' + P + '-svg" viewBox="0 0 ' + W + " " + (t.length * rowH + 8) + '" role="img" aria-label="Devices per OS version">' + t.map((x, i) => {
      const y = i * rowH + 4, w = Math.max(2, Math.round((x.devices / max) * barW));
      const mark = x.eolStatus === "eol" ? "EOL " + (x.eol || "") : x.eolStatus === "soon" ? "EOL " + x.eol : x.eolStatus === "supported" ? (x.eol ? "supported to " + x.eol : "supported") : "not mapped";
      return '<text x="0" y="' + (y + 16) + '">' + esc(x.version.length > 26 ? x.version.slice(0, 25) + "." : x.version) + "</text>" +
        '<rect x="' + labelW + '" y="' + (y + 3) + '" width="' + w + '" height="16" rx="3" fill="' + color[x.eolStatus || "unknown"] + '"><title>' + esc(x.version + ": " + x.devices + " devices, " + mark) + "</title></rect>" +
        '<text x="' + (labelW + w + 6) + '" y="' + (y + 16) + '">' + x.devices + '</text><text class="m" x="' + (labelW + w + 34) + '" y="' + (y + 16) + '">' + esc(mark) + "</text>";
    }).join("") + "</svg>";
    $("pane").innerHTML = svg + '<div class="' + P + '-legend">' + [["eol", "end of life"], ["soon", "EOL within window"], ["supported", "supported"], ["unknown", "not mapped (see skipped)"]].map(([k, l]) => '<span><i style="background:' + color[k] + '"></i>' + esc(l) + "</span>").join("") + "</div>" +
      '<p class="' + P + '-note">' + (result.summary.eolUpdated ? "End-of-life dates: endoflife.date, mirrored " + esc(result.summary.eolUpdated.slice(0, 10)) + "." : "EOL mirror not loaded: support status unknown.") + "</p>";
  }

  const FIND_COLS = [
    { key: "severity", label: "Severity", rank: SEV_RANK, render: (f) => pill(f.severity) },
    { key: "title", label: "Finding", render: (f) => "<b>" + esc(f.title) + "</b><div>" + esc(f.description) + "</div>" },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
    { key: "controls", label: "Controls", render: (f) => (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") },
    { key: "evidenceCount", label: "Devices" },
  ];
  function drawFindings() {
    const box = $("pane"); box.innerHTML = "";
    if (!result.findings.length) { box.innerHTML = '<div class="' + P + '-empty">No findings for the current baseline.</div>'; return; }
    const rows = result.findings.map((f, i) => ({ ...f, i }));
    const t = table(FIND_COLS, rows, sorts.findings, (s) => { sorts.findings = s; drawFindings(); }, (f) => f.i);
    t.querySelectorAll("tr[data-i]").forEach((tr) => { if (sel === "f" + tr.dataset.i) tr.classList.add("sel"); tr.addEventListener("click", () => { sel = "f" + tr.dataset.i; drawFindings(); showFinding(result.findings[Number(tr.dataset.i)]); }); });
    box.appendChild(t);
  }
  function showFinding(f) {
    const dr = $("drawer");
    const det = DETECTIONS.find((x) => x.id === f.check);
    dr.style.display = "block";
    dr.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + pill(f.severity) + " " + esc(f.title) + '</h3><button class="' + P + '-btn sm" data-close type="button">Close</button></div>' +
      "<p>" + esc(f.description) + "</p><p><b>Recommendation:</b> " + esc(f.recommendation) + "</p><p><b>Confidence:</b> " + esc(f.confidence) + (det ? " | <b>Needs:</b> " + esc(det.needs) : "") + "</p>" +
      "<p>" + (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</p>" +
      "<p><b>Evidence</b> (" + f.evidence.length + " of " + f.evidenceCount + ")</p>" + plainTable(f.evidence) +
      '<div class="' + P + '-row"><button class="' + P + '-btn sm" data-ev type="button">Export evidence CSV</button></div>';
    dr.querySelector("[data-close]").addEventListener("click", () => { dr.style.display = "none"; sel = null; if (tab === "findings") drawFindings(); });
    dr.querySelector("[data-ev]").addEventListener("click", () => {
      const keys = []; for (const r of f.evidence) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
      const q = (v) => '"' + String(v == null ? "" : v).replace(/^(?=[=+@\t\r]|-(?!\d+(?:\.\d+)?$))/, "'").replace(/"/g, '""') + '"';
      download(TOOL_ID + "-" + f.check + "-evidence-" + fileStamp() + ".csv", [keys.join(","), ...f.evidence.map((r) => keys.map((k) => q(r[k])).join(","))].join("\n"), "text/csv");
    });
    dr.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  function drawSources() {
    const t = result.tables.sources.map((s) => ({ file: s.name, format: s.label, kind: KIND_LABEL[s.kind] || s.kind, confidence: s.confidence, rows: s.rows, records: s.kind === "software" ? s.software : s.devices, matched: s.matched, unmatched: s.unmatched }));
    $("pane").innerHTML = '<p class="' + P + '-note">Matched = records joined to a device seen in at least one other file (software rows: joined to a known device).</p>' + plainTable(t);
  }

  function renderExports() {
    const ex = $("exports"), r = result, stamp = fileStamp();
    ex.innerHTML = ["csv:Findings CSV", "json:JSON", "txt:Summary TXT", "dev:Device register CSV", "sw:Software inventory CSV", "work:Remediation worklist CSV", "cov:Coverage CSV"]
      .map((x) => { const [k, l] = x.split(":"); return '<button class="' + P + '-btn" data-x="' + k + '">' + esc(l) + "</button>"; }).join("");
    const on = (k, fn) => ex.querySelector('[data-x="' + k + '"]').addEventListener("click", fn);
    on("csv", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    on("json", () => download(TOOL_ID + "-" + stamp + ".json", toJson({ ...r, summaryStats: summarize(r.findings) }), "application/json"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r), "text/plain"));
    on("dev", () => download(TOOL_ID + "-devices-" + stamp + ".csv", devicesToCsv(r.tables.devices), "text/csv"));
    on("sw", () => { if (!r.tables.software.length) { toast("No software inventory was loaded", "info"); return; } download(TOOL_ID + "-software-" + stamp + ".csv", softwareToCsv(r.tables.software), "text/csv"); });
    on("work", () => { if (!r.tables.worklist.length) { toast("Nothing to remediate", "info"); return; } download(TOOL_ID + "-worklist-" + stamp + ".csv", worklistToCsv(r.tables.worklist), "text/csv"); });
    on("cov", () => download(TOOL_ID + "-coverage-" + stamp + ".csv", coverageToCsv(r.tables.coverage), "text/csv"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: datasetName() });
  }

  renderFiles();
}
