// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// OAuth App Governance (oauthgov): Deck tool UI. Drop the OAuth / enterprise-app exports
// from Microsoft Entra, Google Workspace, Okta, Slack and GitHub; the engine builds one
// app inventory, classifies every scope and runs the detections inside a Worker.
// Runs entirely in the browser; nothing is uploaded or fetched. No native dialogs.
//
//   renderOauthGov(main) -> void

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, COLUMNS, FORMATS, SOURCE_LABEL, SCOPE_RISK, SCOPE_CLASSES, RISK_RANK, DETECTIONS,
  parseInput, findingsToCsv, appsToCsv, revokeToCsv, summaryText, exampleDataset,
} from "./oauthgov-engine.js?v=20261026b";

const ENGINE = engineUrl("./oauthgov-engine.js?v=20261026b", import.meta);
const P = "oag";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const CONF_RANK = { confirmed: 3, likely: 2, review: 1 };

const CSS = `
  .oag-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .oag-root *{box-sizing:border-box}
  .oag-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .oag-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .oag-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .oag-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:90ch}
  .oag-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .oag-card h2{font-size:.95rem;margin:0 0 10px;letter-spacing:.01em}
  .oag-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .oag-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .oag-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .oag-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .oag-btn.sm{padding:4px 9px;font-size:.76rem}
  .oag-btn:disabled{opacity:.5;cursor:default}
  .oag-files{display:flex;flex-direction:column;gap:6px;margin-top:12px}
  .oag-file{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;font-size:.82rem;min-width:0}
  .oag-file b{overflow-wrap:anywhere}
  .oag-file .oag-fmt{color:var(--mut,#667085)}
  .oag-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085)}
  .oag-conf.high{color:#1b7f4d;border-color:#1b7f4d}.oag-conf.medium{color:#8a6d00;border-color:#8a6d00}.oag-conf.low{color:#b00020;border-color:#b00020}
  .oag-ctl{display:flex;flex-wrap:wrap;gap:14px 20px;align-items:flex-start}
  .oag-field{display:flex;flex-direction:column;gap:4px;min-width:0;flex:1 1 180px}
  .oag-field.wide{flex:1 1 100%}
  .oag-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .oag-field input,.oag-field select,.oag-field textarea{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%}
  .oag-field textarea{min-height:84px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}
  .oag-field small{font-size:.74rem;color:var(--mut,#667085);line-height:1.4}
  .oag-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .oag-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:120px;flex:1 1 120px}
  .oag-kpi b{display:block;font-size:1.3rem}
  .oag-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .oag-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .oag-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .oag-plabel{font-size:.74rem;color:var(--mut,#667085);margin-top:4px;display:none}
  .oag-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .oag-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:640px}
  .oag-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .oag-list th.on{color:var(--tx,#1a2230)}
  .oag-list th.on::after{content:" \\2193";font-size:.7rem}
  .oag-list th.on.asc::after{content:" \\2191"}
  .oag-list td{padding:9px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word}
  .oag-list tr[data-i]{cursor:pointer}
  .oag-list tr[data-i]:hover,.oag-list tr.sel{background:var(--bg,#f7f8fb)}
  .oag-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .oag-pill.critical{background:#7a0012}.oag-pill.high{background:#b00020}.oag-pill.medium{background:#b58100}.oag-pill.low{background:#2552c6}.oag-pill.info{background:#667085}
  .oag-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .oag-chip.cls{color:var(--tx,#1a2230)}
  .oag-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .oag-drawer{margin-top:12px;display:none;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--bg,#f7f8fb)}
  .oag-drawer h3{margin:0 0 6px;font-size:1rem}
  .oag-drawer p{margin:6px 0}
  .oag-drawer .oag-list{background:var(--card,#fff);margin-top:10px}
  .oag-drawer .oag-list table{min-width:480px}
  .oag-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px}
  .oag-skip li{margin:2px 0;overflow-wrap:anywhere}
  .oag-filters{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:flex-end;margin-bottom:10px}
  .oag-filters .oag-field{flex:0 1 170px}
  .oag-legend summary{cursor:pointer;font-weight:600;font-size:.9rem}
  .oag-lgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px;margin-top:12px}
  .oag-lcls{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 12px;min-width:0}
  .oag-lcls h4{margin:0 0 6px;font-size:.78rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#667085)}
  .oag-lcls ul{list-style:none;margin:0;padding:0;font-size:.76rem}
  .oag-lcls li{display:flex;gap:6px;align-items:baseline;padding:2px 0;min-width:0}
  .oag-lcls li code{font-size:.72rem;overflow-wrap:anywhere;min-width:0}
  .oag-dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;font-size:.82rem;margin:8px 0}
  .oag-dl dt{color:var(--mut,#667085)}.oag-dl dd{margin:0;overflow-wrap:anywhere}
  .oag-ok{color:#1b7f4d;font-weight:600}
  @media (max-width:560px){.oag-field{flex:1 1 100%}.oag-filters .oag-field{flex:1 1 100%}.oag-dl{grid-template-columns:1fr}.oag-card{padding:14px}}
`;

const kpi = (v, l) => '<div class="' + P + '-kpi"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const pill = (s) => '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>";
const confClass = (c) => (c >= 0.8 ? "high" : c >= 0.5 ? "medium" : "low");
const confLabel = (c) => (c >= 0.8 ? "high" : c >= 0.5 ? "medium" : "low") + " confidence";
const fmtLabel = (f) => (FORMATS[f] || FORMATS.generic).label;
const sortBy = (rows, key, dir, rank) => rows.slice().sort((a, b) => {
  const x = rank ? (rank[a[key]] ?? -1) : a[key], y = rank ? (rank[b[key]] ?? -1) : b[key];
  const r = typeof x === "number" && typeof y === "number" ? x - y : cmp(String(x == null ? "" : x).toLowerCase(), String(y == null ? "" : y).toLowerCase());
  return dir === "asc" ? r : -r;
});

/** Sortable table: cols = [{key, label, render?, rank?}]. */
function table(cols, rows, sort, onSort, rowKey) {
  const head = cols.map((c) => '<th data-k="' + esc(c.key) + '" class="' + (sort.key === c.key ? "on " + sort.dir : "") + '">' + esc(c.label) + "</th>").join("");
  const sorted = sortBy(rows, sort.key, sort.dir, (cols.find((c) => c.key === sort.key) || {}).rank);
  const body = sorted.map((r) => "<tr data-i=\"" + esc(rowKey(r)) + "\">" + cols.map((c) => "<td>" + (c.render ? c.render(r) : esc(r[c.key] == null ? "" : r[c.key])) + "</td>").join("") + "</tr>").join("");
  const el = document.createElement("div");
  el.className = P + "-list";
  el.innerHTML = "<table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table>";
  el.querySelectorAll("th").forEach((th) => th.addEventListener("click", () => {
    const k = th.dataset.k;
    onSort({ key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" });
  }));
  return el;
}

/** Plain table for evidence rows: columns are the union of keys. */
function evidenceTable(rows) {
  if (!rows || !rows.length) return '<p class="' + P + '-note">No evidence rows.</p>';
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
  const cell = (v) => (v === true ? "yes" : v === false ? "no" : v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => "<td>" + (k === "risk" || k === "maxRisk" || k === "severity" ? (r[k] ? pill(r[k]) : "") : esc(cell(r[k]))) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

function legendHtml() {
  const groups = Object.fromEntries(SCOPE_CLASSES.map((c) => [c, []]));
  for (const [scope, e] of Object.entries(SCOPE_RISK)) (groups[e.class] || (groups[e.class] = [])).push({ scope, ...e });
  const n = Object.keys(SCOPE_RISK).length;
  const cards = SCOPE_CLASSES.map((c) => {
    const list = groups[c].sort((a, b) => RISK_RANK[b.risk] - RISK_RANK[a.risk] || cmp(a.scope.toLowerCase(), b.scope.toLowerCase()));
    return '<div class="' + P + '-lcls"><h4>' + esc(c) + " (" + list.length + ")</h4><ul>" +
      list.map((s) => "<li>" + pill(s.risk) + "<code title=\"" + esc(s.reason) + "\">" + esc(s.scope.replace("https://www.googleapis.com/auth/", "google: ")) + "</code></li>").join("") + "</ul></div>";
  }).join("");
  return '<details class="' + P + '-legend"><summary>Scope risk legend: ' + n + " scopes in " + SCOPE_CLASSES.length + " classes</summary>" +
    '<p class="' + P + '-note">Risk is the delegated meaning. Application (app-only) permissions are rated one level higher because they run without a signed-in user. Scopes outside this table are rated medium with review confidence; Slack scopes the vendor marks sensitive are rated high.</p>' +
    '<div class="' + P + '-lgrid">' + cards + "</div></details>";
}

function settingsHtml() {
  return '<div class="' + P + '-ctl">' +
    '<div class="' + P + '-field"><label for="' + P + '-unused">Unused after (days)</label><input id="' + P + '-unused" type="number" min="0" step="1" value="' + DEFAULTS.unusedDays + '"><small>Broad-scope apps not used for longer than this are reported.</small></div>' +
    '<div class="' + P + '-field"><label for="' + P + '-tenant">Your Entra tenant ID (optional)</label><input id="' + P + '-tenant" type="text" placeholder="tenant GUID" autocomplete="off" spellcheck="false"><small>Apps owned by your own tenant are not reported as unverified publishers.</small></div>' +
    '<div class="' + P + '-field"><label for="' + P + '-now">Reference date (optional)</label><input id="' + P + '-now" type="date"><small>Blank = the latest timestamp found in the data.</small></div>' +
    '<div class="' + P + '-field wide"><label for="' + P + '-sanctioned">Sanctioned apps</label><textarea id="' + P + '-sanctioned" placeholder="one app name or client id per line" spellcheck="false"></textarea><small>Apps not on this list that hold mail, file, directory, chat, code or admin access form the shadow-SaaS finding.</small></div>' +
    "</div>";
}

/** Mount the tool into main. */
export function renderOauthGov(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>OAuth Apps</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Inventory every third-party and enterprise app that holds OAuth access to company data across Microsoft Entra, Google Workspace, Okta, Slack and GitHub; classify scopes by risk, separate user consent from admin consent, flag unverified publishers, dormant broad-scope grants and lookalike names, and derive the shadow-SaaS inventory. Runs entirely in your browser. Nothing is uploaded and nothing is fetched.</p>',
    '<div class="', P, '-card"><h2>1. Exports</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-note">Accepted: Entra servicePrincipals / oauth2PermissionGrants / appRoleAssignments JSON, Enterprise applications CSV, service principal sign-in CSV; Google third-party app access CSV and tokens.list JSON; Okta apps JSON/CSV; Slack Manage apps CSV and admin.apps.approved.list JSON; GitHub installations JSON and third-party access CSV. Drop several at once; zip archives are unpacked locally.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div>',
    '<div id="', P, '-map"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button><button class="', P, '-btn" id="', P, '-clear" disabled>Clear files</button><span class="', P, '-note" id="', P, '-count"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-plabel" id="', P, '-plabel"></div></div>',
    '<div class="', P, '-card"><h2>2. Settings</h2>', settingsHtml(), "</div>",
    '<div class="', P, '-card">', legendHtml(), "</div>",
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card" id="', P, '-invcard" style="display:none"><h2>App inventory</h2><div class="', P, '-filters" id="', P, '-filters"></div><div id="', P, '-inv"></div><div class="', P, '-drawer" id="', P, '-appdrawer"></div></div>',
    '<div class="', P, '-card"><h2>Findings</h2><div id="', P, '-list"><div class="', P, '-empty">No analysis yet. Drop exports above, or load the synthetic example below.</div></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div><ul class="', P, '-skip" id="', P, '-skipped"></ul></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, running = false;
  let fSort = { key: "severity", dir: "desc" }, aSort = { key: "maxRisk", dir: "desc" };
  let filters = { source: "", risk: "", consent: "", q: "" };
  let selFinding = -1, selApp = "";
  const columnMap = {};

  const totalRows = () => files.reduce((n, f) => n + f.rows, 0);
  const datasetName = () => (isExample ? "synthetic example" : files.map((f) => f.name).join(", "));

  function renderFiles() {
    const box = $("files");
    box.innerHTML = files.map((f, i) =>
      '<div class="' + P + '-file"><b>' + esc(f.name) + '</b><span class="' + P + '-fmt">' + esc(fmtLabel(f.format)) + "</span>" +
      '<span class="' + P + "-conf " + confClass(f.confidence) + '">' + esc(confLabel(f.confidence)) + "</span><span>" + f.rows + " records</span>" +
      '<button class="' + P + '-btn sm" data-rm="' + i + '" type="button">Remove</button></div>').join("");
    box.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { files.splice(Number(b.dataset.rm), 1); isExample = false; renderFiles(); }));
    $("count").textContent = files.length ? files.length + " file" + (files.length === 1 ? "" : "s") + ", " + totalRows() + " records" + (isExample ? " (synthetic example)" : "") : "";
    $("run").disabled = !files.length || running;
    $("clear").disabled = !files.length;
    renderMapping();
  }

  function renderMapping() {
    const generic = files.filter((f) => f.format === "generic" || f.confidence < 0.8);
    const box = $("map");
    if (!generic.length) { box.innerHTML = ""; return; }
    const headers = [...new Set(generic.flatMap((f) => f.headers))];
    const keys = Object.keys(COLUMNS);
    box.innerHTML = '<div class="' + P + '-card" style="margin:12px 0 0"><h2>Column mapping</h2><p class="' + P + '-note">' + generic.map((f) => f.name).join(", ") + ": the layout was not recognised with high confidence. Map the columns the engine should read; unmapped columns disable the checks that need them.</p>" +
      '<div class="' + P + '-ctl">' + keys.map((k) => '<div class="' + P + '-field"><label>' + esc(k) + '</label><select data-col="' + esc(k) + '"><option value="">(not present)</option>' +
        headers.map((h) => '<option value="' + esc(h) + '"' + (columnMap[k] === h || (!columnMap[k] && COLUMNS[k].some((a) => a.toLowerCase().replace(/[^a-z0-9]/g, "") === h.toLowerCase().replace(/[^a-z0-9]/g, ""))) ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>").join("") + "</div></div>";
    box.querySelectorAll("[data-col]").forEach((sel) => { if (sel.value) columnMap[sel.dataset.col] = sel.value; sel.addEventListener("change", () => { if (sel.value) columnMap[sel.dataset.col] = sel.value; else delete columnMap[sel.dataset.col]; }); });
  }

  function addFile(name, text) {
    const p = parseInput({ name, text });
    const f = p.files[0];
    if (!f) { toast("No records recognised in " + name, "warning"); return false; }
    const idx = files.findIndex((x) => x.name === name);
    const entry = { name, text, format: f.format, confidence: f.confidence, headers: f.headers, rows: f.rows };
    if (idx >= 0) files[idx] = entry; else files.push(entry);
    return true;
  }

  mountDropzone($("drop"), {
    maxBytes: 100 * 1024 * 1024, maxFiles: 20, multiple: true,
    label: "Drop one or more exports here, paste, or browse",
    onFiles: async (list) => {
      let added = 0;
      for (const f of list) { if (addFile(f.name, await f.text())) added++; }
      if (added) { isExample = false; toast("Loaded " + added + " file" + (added === 1 ? "" : "s")); }
      renderFiles();
    },
  });

  $("clear").addEventListener("click", () => { files = []; isExample = false; renderFiles(); });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    files = []; isExample = true;
    for (const f of ex.files) addFile(f.name, f.text);
    renderFiles();
    toast("Synthetic example loaded: " + files.length + " files. Click Analyze.", "info");
  });

  const opts = () => {
    const o = { columns: { ...columnMap } };
    const d = Number($("unused").value); if (Number.isFinite(d) && d >= 0) o.unusedDays = d;
    o.tenantId = $("tenant").value.trim();
    const now = $("now").value.trim(); if (now) o.now = now + "T23:59:59Z";
    o.sanctioned = $("sanctioned").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    return o;
  };

  $("run").addEventListener("click", async () => {
    if (!files.length || running) return;
    running = true;
    const prog = $("prog"), bar = prog.firstElementChild, pl = $("plabel");
    prog.style.display = "block"; pl.style.display = "block"; bar.style.width = "0%"; pl.textContent = "starting"; $("run").disabled = true;
    try {
      result = await runInWorker(ENGINE, "analyzeFiles", [files.map((f) => ({ name: f.name, text: f.text })), opts()], {
        onProgress: (i, n, label) => { bar.style.width = (n ? Math.round((i / n) * 100) : 0) + "%"; if (label) pl.textContent = label; },
      });
      selFinding = -1; selApp = ""; filters = { source: "", risk: "", consent: "", q: "" };
      render(result);
      toast(result.findings.length + " finding" + (result.findings.length === 1 ? "" : "s") + " across " + result.summary.apps + " apps", "success");
    } catch (e) {
      toast("Analysis failed: " + ((e && e.message) || e), "error");
    } finally {
      running = false;
      prog.style.display = "none"; pl.style.display = "none"; $("run").disabled = !files.length;
    }
  });

  function render(r) {
    const s = r.summary;
    $("kpis").innerHTML = kpi(s.apps, "apps") + kpi(s.highRiskApps, "high-risk apps") + kpi(s.userConsentedHighRisk, "user-consented high-risk") +
      kpi(s.unverifiedPublishers, "unverified publishers") + kpi(s.unusedBroad, "unused broad-scope") + kpi(s.unsanctioned, "unsanctioned") + kpi(r.findings.length, "findings");
    $("skipped").innerHTML = r.skipped.length ? "<li><b>Skipped or limited checks</b></li>" + r.skipped.map((k) => "<li>" + esc(k.check) + ": " + esc(k.reason) + "</li>").join("") : "";
    renderInventory(r);
    renderFindings(r);
    renderExports(r);
  }

  const APP_COLS = [
    { key: "app", label: "App", render: (a) => "<b>" + esc(a.app || a.appId) + "</b>" + (a.sanctioned ? ' <span class="' + P + '-chip">sanctioned</span>' : "") + (a.firstParty ? ' <span class="' + P + '-chip">first-party</span>' : "") + (a.enabled === false ? ' <span class="' + P + '-chip">disabled</span>' : "") },
    { key: "source", label: "Source", render: (a) => esc(SOURCE_LABEL[a.source] || a.source) },
    { key: "publisher", label: "Publisher", render: (a) => esc(a.publisher || "-") + (a.publisherVerified === true ? ' <span class="' + P + '-ok">verified</span>' : a.publisherVerified === false ? ' <span class="' + P + '-chip">unverified</span>' : "") },
    { key: "maxRisk", label: "Max risk", rank: RISK_RANK, render: (a) => pill(a.maxRisk) },
    { key: "scopeClasses", label: "Classes", render: (a) => (a.scopeClasses ? a.scopeClasses.split(" ").map((c) => '<span class="' + P + '-chip cls">' + esc(c) + "</span>").join("") : "-") },
    { key: "scopes", label: "Scopes" },
    { key: "consent", label: "Consent" },
    { key: "users", label: "Users" },
    { key: "lastUsed", label: "Last used", render: (a) => esc(a.lastUsed ? a.lastUsed.slice(0, 10) : "-") },
    { key: "findings", label: "Flags", render: (a) => esc([a.findings, a.flags].filter(Boolean).join(" ").split(" ").filter(Boolean).join(", ") || "-") },
  ];

  function renderInventory(r) {
    const card = $("invcard");
    card.style.display = r.tables.apps.length ? "" : "none";
    if (!r.tables.apps.length) return;
    const sources = [...new Set(r.tables.apps.map((a) => a.source))].sort();
    const sel = (id, label, options, value) => '<div class="' + P + '-field"><label for="' + P + "-f-" + id + '">' + label + '</label><select id="' + P + "-f-" + id + '" data-f="' + id + '"><option value="">All</option>' +
      options.map((o) => '<option value="' + esc(o[0]) + '"' + (value === o[0] ? " selected" : "") + ">" + esc(o[1]) + "</option>").join("") + "</select></div>";
    $("filters").innerHTML = sel("source", "Source", sources.map((x) => [x, SOURCE_LABEL[x] || x]), filters.source) +
      sel("risk", "Max risk", ["critical", "high", "medium", "low", "info"].map((x) => [x, x]), filters.risk) +
      sel("consent", "Consent", ["user", "mixed", "admin", "unknown"].map((x) => [x, x]), filters.consent) +
      '<div class="' + P + '-field"><label for="' + P + '-f-q">Search</label><input id="' + P + '-f-q" data-f="q" type="search" placeholder="name, id, publisher" value="' + esc(filters.q) + '"></div>';
    $("filters").querySelectorAll("[data-f]").forEach((el) => el.addEventListener("input", () => { filters[el.dataset.f] = el.value; drawInventory(r); }));
    drawInventory(r);
  }

  function drawInventory(r) {
    const q = filters.q.trim().toLowerCase();
    const rows = r.tables.apps.filter((a) => (!filters.source || a.source === filters.source) && (!filters.risk || a.maxRisk === filters.risk) && (!filters.consent || a.consent === filters.consent) &&
      (!q || [a.app, a.appId, a.publisher, a.objectId].some((v) => String(v || "").toLowerCase().includes(q))));
    const box = $("inv");
    box.innerHTML = "";
    if (!rows.length) { box.innerHTML = '<div class="' + P + '-empty">No apps match the filters.</div>'; return; }
    const t = table(APP_COLS, rows, aSort, (s) => { aSort = s; drawInventory(r); }, (a) => a.key);
    t.querySelectorAll("tr[data-i]").forEach((tr) => { if (tr.dataset.i === selApp) tr.classList.add("sel"); tr.addEventListener("click", () => { selApp = tr.dataset.i; drawInventory(r); showApp(r, selApp); }); });
    box.appendChild(t);
    const note = document.createElement("p"); note.className = P + "-note"; note.textContent = rows.length + " of " + r.tables.apps.length + " apps. Click a row for its scopes and grants.";
    box.appendChild(note);
  }

  function showApp(r, key) {
    const a = r.tables.apps.find((x) => x.key === key);
    const d = $("appdrawer");
    if (!a) { d.style.display = "none"; return; }
    const scopes = r.tables.scopes.filter((s) => s.key === key).map((s) => ({ scope: s.scope, kind: s.kind, risk: s.risk, class: s.class, reason: s.reason, grantIds: s.grantIds }));
    const dl = [["Source", SOURCE_LABEL[a.source] || a.source], ["App / client id", a.appId || "-"], ["Object id", a.objectId || "-"], ["Publisher", (a.publisher || "-") + (a.publisherVerified === true ? " (verified)" : a.publisherVerified === false ? " (unverified)" : "")],
      ["Consent", a.consent + (a.users ? ", " + a.users + " user" + (a.users === 1 ? "" : "s") : "")], ["Consenting users", a.consentingUsers || "-"], ["Enabled", a.enabled === null ? "unknown" : a.enabled ? "yes" : "no"],
      ["First seen", a.firstSeen || "-"], ["Last used", a.lastUsed || "-"], ["Grants", String(a.grants)], ["Sanctioned", a.sanctioned ? "yes" : "no"], ["Flags", [a.findings, a.flags].filter(Boolean).join(" ") || "-"], ["Notes", a.notes || "-"]];
    d.style.display = "block";
    d.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + esc(a.app || a.appId) + " " + pill(a.maxRisk) + '</h3><button class="' + P + '-btn sm" data-close type="button">Close</button></div>' +
      '<dl class="' + P + '-dl">' + dl.map(([k, v]) => "<dt>" + esc(k) + "</dt><dd>" + esc(v) + "</dd>").join("") + "</dl>" +
      "<p><b>Scopes (" + scopes.length + ")</b></p>" + evidenceTable(scopes);
    d.querySelector("[data-close]").addEventListener("click", () => { d.style.display = "none"; selApp = ""; drawInventory(r); });
  }

  const FIND_COLS = [
    { key: "severity", label: "Severity", rank: RISK_RANK, render: (f) => pill(f.severity) },
    { key: "title", label: "Finding", render: (f) => "<b>" + esc(f.title) + "</b><div>" + esc(f.description) + "</div>" },
    { key: "asset", label: "App", render: (f) => esc(f.asset || "-") },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
    { key: "controls", label: "Controls", render: (f) => (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") },
    { key: "evidenceCount", label: "Evidence" },
  ];

  function renderFindings(r) {
    const box = $("list");
    box.innerHTML = "";
    if (!r.findings.length) { box.innerHTML = '<div class="' + P + '-empty">No findings for the current settings.</div>'; $("drawer").style.display = "none"; return; }
    const rows = r.findings.map((f, i) => ({ ...f, i, asset: f.assets && f.assets[0] ? f.assets[0].name : "", evidenceCount: f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length }));
    const t = table(FIND_COLS, rows, fSort, (s) => { fSort = s; renderFindings(r); }, (f) => f.i);
    t.querySelectorAll("tr[data-i]").forEach((tr) => { if (Number(tr.dataset.i) === selFinding) tr.classList.add("sel"); tr.addEventListener("click", () => { selFinding = Number(tr.dataset.i); renderFindings(r); showFinding(r.findings[selFinding]); }); });
    box.appendChild(t);
  }

  function showFinding(f) {
    const d = $("drawer");
    if (!f) { d.style.display = "none"; return; }
    const det = DETECTIONS.find((x) => x.id === f.check);
    d.style.display = "block";
    d.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + pill(f.severity) + " " + esc(f.title) + '</h3><button class="' + P + '-btn sm" data-close type="button">Close</button></div>' +
      "<p>" + esc(f.description) + "</p><p><b>Recommendation:</b> " + esc(f.recommendation) + "</p>" +
      "<p><b>Confidence:</b> " + esc(f.confidence) + (det ? " &middot; <b>Needs:</b> " + esc(det.needs) : "") + "</p>" +
      "<p>" + (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</p>" +
      ((f.assets || []).length ? "<p><b>Assets:</b> " + f.assets.map((a) => esc(a.type + " " + a.name)).join(", ") + "</p>" : "") +
      "<p><b>Evidence</b> (" + (f.evidence || []).length + " of " + (f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length) + ")</p>" + evidenceTable(f.evidence) +
      '<div class="' + P + '-row"><button class="' + P + '-btn sm" data-ev type="button">Export evidence CSV</button></div>';
    d.querySelector("[data-close]").addEventListener("click", () => { d.style.display = "none"; selFinding = -1; if (result) renderFindings(result); });
    d.querySelector("[data-ev]").addEventListener("click", () => {
      const rows = f.evidence || [];
      const keys = []; for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
      const q = (v) => '"' + String(v == null ? "" : typeof v === "object" ? JSON.stringify(v) : v).replace(/^(?=[=+@\t\r]|-(?!\d+(?:\.\d+)?$))/, "'").replace(/"/g, '""') + '"';
      download(TOOL_ID + "-evidence-" + fileStamp() + ".csv", [keys.join(","), ...rows.map((r) => keys.map((k) => q(r[k])).join(","))].join("\n"), "text/csv");
    });
    d.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  function renderExports(r) {
    const ex = $("exports");
    ex.innerHTML = '<button class="' + P + '-btn" data-x="csv">Findings CSV</button><button class="' + P + '-btn" data-x="json">JSON</button><button class="' + P + '-btn" data-x="txt">Summary TXT</button>' +
      '<button class="' + P + '-btn" data-x="apps">App inventory CSV</button><button class="' + P + '-btn" data-x="revoke">Revoke list CSV</button>';
    const stamp = fileStamp();
    ex.querySelector('[data-x="csv"]').addEventListener("click", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    ex.querySelector('[data-x="json"]').addEventListener("click", () => download(TOOL_ID + "-" + stamp + ".json", toJson({ ...r, summaryStats: summarize(r.findings) }), "application/json"));
    ex.querySelector('[data-x="txt"]').addEventListener("click", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r), "text/plain"));
    ex.querySelector('[data-x="apps"]').addEventListener("click", () => download(TOOL_ID + "-apps-" + stamp + ".csv", appsToCsv(r.tables.apps), "text/csv"));
    ex.querySelector('[data-x="revoke"]').addEventListener("click", () => {
      if (!r.tables.revoke.length) { toast("No apps to revoke: nothing was flagged", "info"); return; }
      download(TOOL_ID + "-revoke-" + stamp + ".csv", revokeToCsv(r.tables.revoke), "text/csv");
    });
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: datasetName() });
  }

  renderFiles();
}
