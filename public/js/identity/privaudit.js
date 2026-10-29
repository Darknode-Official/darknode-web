// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Privileged Access Audit (privaudit): Deck tool UI. Drop Entra / AWS / GCP / Okta /
// GitHub exports; the engine runs in a Worker (../ingest/worker.js). Everything stays
// in the browser. No native dialogs; toasts only.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import { DEFAULTS, TOOL_ID, COLUMNS, SOURCES, SEVERITY_RANK, parseInput, findingsToCsv, principalsToCsv, attestationText, exampleDataset } from "./privaudit-engine.js?v=20261026b";

const ENGINE = engineUrl("./privaudit-engine.js?v=20261026b", import.meta);
const P = "prv";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const CSS = `
  .prv-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);min-width:0}
  .prv-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .prv-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .prv-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .prv-sub{color:var(--mut,#667085);margin:8px 0 14px}
  .prv-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .prv-card h2{font-size:.78rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut,#667085);margin:0 0 10px;font-weight:700}
  .prv-help{font-size:.78rem;color:var(--mut,#667085);margin:4px 0 0;overflow-wrap:anywhere}
  .prv-drop{border:1.5px dashed var(--line,#d7dbe3);border-radius:10px;padding:22px;text-align:center;color:var(--mut,#667085);background:var(--bg,#fbfcfe)}
  .prv-files{list-style:none;margin:12px 0 0;padding:0;display:flex;flex-direction:column;gap:6px}
  .prv-files li{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;font-size:.84rem;min-width:0}
  .prv-files li b{overflow-wrap:anywhere}
  .prv-files .x{margin-left:auto;appearance:none;font:inherit;font-size:.74rem;border:1px solid var(--line,#d7dbe3);background:transparent;color:var(--mut,#667085);border-radius:6px;padding:2px 8px;cursor:pointer}
  .prv-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .prv-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .prv-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .prv-btn:disabled{opacity:.5;cursor:default}
  .prv-ctl{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px 16px}
  .prv-field{display:flex;flex-direction:column;gap:4px;min-width:0}
  /* a label that wraps to two lines must not push its input below its neighbours': each field's label, input and help share the row tracks */
  .prv-ctl>.prv-field{display:grid;grid-row:span 3;grid-template-rows:subgrid;row-gap:4px;align-content:start}.prv-ctl>.prv-field>label{align-self:end}
  .prv-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .prv-field input,.prv-field select{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;box-sizing:border-box;min-width:0}
  .prv-field small{font-size:.72rem;color:var(--mut,#667085);overflow-wrap:anywhere}
  .prv-map{border-top:1px solid var(--line,#eef0f4);padding-top:10px;margin-top:10px}
  .prv-map:first-of-type{border-top:0;padding-top:0;margin-top:0}
  .prv-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin:14px 0}
  .prv-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .prv-kpi b{display:block;font-size:1.3rem;overflow-wrap:anywhere}
  .prv-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .prv-kpi.crit b{color:#7a0012}.prv-kpi.high b{color:#b00020}
  .prv-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .prv-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .prv-tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
  .prv-tools input{font:inherit;font-size:.84rem;border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:6px 10px;background:var(--card,#fff);color:var(--tx,#1a2230);min-width:0;flex:1 1 160px;max-width:320px}
  .prv-tools .n{font-size:.78rem;color:var(--mut,#667085)}
  .prv-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .prv-list table{width:100%;border-collapse:collapse;font-size:.84rem;min-width:560px}
  .prv-list th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .prv-list th.on::after{content:" \\2193";opacity:.7}.prv-list th.on.asc::after{content:" \\2191"}
  .prv-list td{padding:9px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word}
  .prv-list tr[data-i]{cursor:pointer}
  .prv-list tr[data-i]:hover,.prv-list tr.sel{background:var(--bg,#f7f8fb)}
  .prv-pill{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .prv-pill.critical{background:#7a0012}.prv-pill.high{background:#b00020}.prv-pill.medium{background:#b58100}.prv-pill.low{background:#2552c6}.prv-pill.info{background:#667085}
  .prv-pill.confirmed{background:#1f6f43}.prv-pill.likely{background:#2552c6}.prv-pill.review{background:#8a6d00}
  .prv-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .prv-chip.flag{color:#7a0012;border-color:#e3b9c0}
  .prv-mfa-no{color:#b00020;font-weight:700}.prv-mfa-yes{color:#1f6f43;font-weight:700}
  .prv-empty{padding:26px;text-align:center;color:var(--mut,#667085)}
  .prv-drawer{display:none}
  .prv-drawer .prv-list table{min-width:420px}
  .prv-src{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:#2552c6}
  .prv-conf{font-size:.74rem;color:var(--mut,#667085)}
  .prv-conf.lo{color:#b58100;font-weight:700}
  .prv-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px}
  .prv-skip ul{margin:4px 0 0;padding-left:18px}
  .prv-inline{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  .prv-inline input{font:inherit;font-size:.84rem;border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;background:var(--card,#fff);color:var(--tx,#1a2230);flex:1 1 180px;max-width:320px;min-width:0}
  @media (max-width:520px){.prv-card{padding:12px}.prv-list table{min-width:0}.prv-list th,.prv-list td{padding:7px 8px}}
`;

const THRESHOLDS = [
  ["staleDays", "Stale after (days)", "Privileged principal with no sign-in or credential use for longer than this."],
  ["maxGlobalAdmins", "Max Global Admins", "CIS M365 1.1.3: fewer than five standing Global Administrators."],
  ["minGlobalAdmins", "Min Global Admins", "Below this the tenant has a lockout risk (SCuBA MS.AAD.7.1)."],
  ["rootUsedDays", "Root use window (days)", "AWS root password used within this window is reported."],
  ["keyRotationDays", "Key rotation (days)", "CIS AWS 1.14: access keys rotated at least this often."],
  ["unusedDays", "Unused credentials (days)", "CIS AWS 1.12: passwords and keys idle longer than this."],
  ["maxSuperAdmins", "Max Okta super admins", "SUPER_ADMIN holders above this count are reported."],
  ["maxOrgOwners", "Max GitHub owners", "Organization owners above this count are reported."],
];

const kpi = (v, l, cls) => '<div class="' + P + '-kpi' + (cls ? " " + cls : "") + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const pill = (v) => '<span class="' + P + "-pill " + esc(v) + '">' + esc(v) + "</span>";
const label = (v) => (v == null ? "" : v);
const confLabel = (c) => (c >= 0.9 ? "high" : c >= 0.6 ? "medium" : c > 0 ? "low" : "none");

/** Mount the tool into main. */
export function renderPrivAudit(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  const fields = THRESHOLDS.map(([k, l, h]) =>
    '<div class="' + P + '-field"><label for="' + P + "-opt-" + k + '">' + esc(l) + '</label><input id="' + P + "-opt-" + k + '" data-opt="' + k + '" type="number" min="0" step="1" value="' + esc(DEFAULTS[k]) + '"><small>' + esc(h) + "</small></div>").join("") +
    '<div class="' + P + '-field"><label for="' + P + '-opt-trustedAccounts">Trusted AWS accounts</label><input id="' + P + '-opt-trustedAccounts" data-opt="trustedAccounts" type="text" placeholder="123456789012, ..."><small>Account ids allowed to assume roles cross-account; others are reported for review.</small></div>' +
    '<div class="' + P + '-field"><label for="' + P + '-opt-now">Reference date</label><input id="' + P + '-opt-now" data-opt="now" type="date"><small>Blank uses the newest timestamp in the data, so results stay repeatable.</small></div>';

  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Privileged Access</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Standing, stale and over-broad administrator access across Microsoft Entra, AWS IAM, GCP, Okta and GitHub exports. Runs entirely in your browser. Nothing is uploaded and nothing is fetched live.</p>',
    '<div class="', P, '-card"><h2>Inputs</h2><div class="', P, '-drop" id="', P, '-drop"></div>',
    '<p class="', P, '-help">Accepted: Entra "Download assignments" CSV or Graph roleAssignments / roleEligibilityScheduleInstances JSON; AWS credential report CSV; aws iam get-account-authorization-details JSON; gcloud projects get-iam-policy JSON; Okta administrators CSV or role JSON; GitHub organization people CSV or members JSON. Drop any combination; each file is detected on its own.</p>',
    '<ul class="', P, '-files" id="', P, '-files"></ul>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button><span class="', P, '-help" id="', P, '-count"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div></div>',
    '<div class="', P, '-card" id="', P, '-mapcard" style="display:none"><h2>Column mapping</h2><p class="', P, '-help">Detection confidence is not high for the files below. Pick the export type and, for CSV files, the columns to use, then apply.</p><div id="', P, '-maps"></div><div class="', P, '-row"><button class="', P, '-btn" id="', P, '-applymap">Apply mapping</button></div></div>',
    '<div class="', P, '-card"><h2>Thresholds</h2><div class="', P, '-ctl">', fields, "</div></div>",
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card" id="', P, '-pcard" style="display:none"><h2>Privileged principal inventory</h2><div class="', P, '-tools"><input id="', P, '-pfilter" type="search" placeholder="Filter principals"><label class="', P, '-n"><input type="checkbox" id="', P, '-ponly" checked style="flex:0 0 auto;width:auto;margin-right:6px">privileged only</label><span class="', P, '-n" id="', P, '-pcount"></span></div><div class="', P, '-list" id="', P, '-plist"></div></div>',
    '<div class="', P, '-card" id="', P, '-fcard" style="display:none"><h2>Findings</h2><div class="', P, '-list" id="', P, '-list"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div>',
    '<div class="', P, '-skip" id="', P, '-skipped"></div></div>',
    '<div class="', P, '-card" id="', P, '-xcard" style="display:none"><h2>Exports</h2>',
    '<div class="', P, '-inline"><input id="', P, '-reviewer" type="text" placeholder="Reviewer name" autocomplete="off"><span class="', P, '-help">Recorded in the attestation together with the export time.</span></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  const state = { files: [], parsed: null, result: null, isExample: false, mapping: { source: {}, columns: {} }, fsort: { key: "severity", asc: false }, psort: { key: "source", asc: true }, sel: -1 };

  // ---------------------------------------------------------------- intake --
  function reparse() {
    state.parsed = state.files.length ? parseInput(state.files, state.mapping) : null;
    renderFiles();
    $("run").disabled = !(state.parsed && state.parsed.rows.length);
    $("count").textContent = state.parsed ? state.parsed.rows.length + " record(s) from " + state.parsed.files.length + " file(s)" + (state.isExample ? " (synthetic example)" : "") : "";
  }
  function addFiles(list, example = false) {
    if (!example && state.isExample) { state.files = []; state.isExample = false; }
    state.isExample = example;
    for (const f of list) { state.files = state.files.filter((x) => x.name !== f.name); state.files.push(f); }
    state.mapping = { source: {}, columns: {} };
    reparse();
  }
  function renderFiles() {
    const ul = $("files");
    if (!state.parsed) { ul.innerHTML = ""; $("mapcard").style.display = "none"; return; }
    ul.innerHTML = state.parsed.files.map((f) => {
      const c = confLabel(f.confidence);
      return "<li><b>" + esc(f.name) + '</b><span class="' + P + '-src">' + esc(SOURCES[f.source] || "not recognised") + '</span><span class="' + P + "-conf" + (c === "high" ? "" : " lo") + '">confidence ' + c + "</span><span>" + f.rows + " record(s)</span>" + (f.note ? '<span class="' + P + '-conf lo">' + esc(f.note) + "</span>" : "") + '<button class="x" data-rm="' + esc(f.name) + '">Remove</button></li>';
    }).join("") + state.parsed.skipped.map((s) => '<li><b>' + esc(s.file) + '</b><span class="' + P + '-conf lo">' + esc(s.reason) + "</span></li>").join("");
    ul.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { state.files = state.files.filter((x) => x.name !== b.dataset.rm); if (!state.files.length) state.isExample = false; reparse(); }));
    renderMapping();
  }
  function renderMapping() {
    const need = state.parsed.files.filter((f) => f.confidence < 0.9);
    $("mapcard").style.display = need.length ? "" : "none";
    if (!need.length) return;
    $("maps").innerHTML = need.map((f) => {
      const src = state.mapping.source[f.name] || f.source;
      const opts = ['<option value="unknown"' + (src === "unknown" ? " selected" : "") + ">Not recognised</option>"].concat(Object.keys(SOURCES).map((k) => '<option value="' + k + '"' + (k === src ? " selected" : "") + ">" + esc(SOURCES[k]) + "</option>")).join("");
      const spec = f.format === "csv" || f.format === "tsv" ? COLUMNS[src] : null;
      const cols = spec ? Object.keys(spec).map((k) => {
        const cur = (f.columns && f.columns[k]) || "";
        return '<div class="' + P + '-field"><label>' + esc(k) + '</label><select data-col="' + esc(k) + '"><option value="">(none)</option>' + f.headers.map((h) => '<option value="' + esc(h) + '"' + (h === cur ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>";
      }).join("") : "";
      return '<div class="' + P + '-map" data-file="' + esc(f.name) + '"><div class="' + P + '-ctl"><div class="' + P + '-field"><label>' + esc(f.name) + ' - export type</label><select data-src>' + opts + "</select></div>" + cols + "</div></div>";
    }).join("");
    $("maps").querySelectorAll("[data-src]").forEach((sel) => sel.addEventListener("change", () => { state.mapping.source[sel.closest("[data-file]").dataset.file] = sel.value; state.parsed = parseInput(state.files, state.mapping); renderMapping(); }));
  }
  $("applymap").addEventListener("click", () => {
    $("maps").querySelectorAll("[data-file]").forEach((box) => {
      const name = box.dataset.file, src = box.querySelector("[data-src]").value;
      state.mapping.source[name] = src;
      const cols = {};
      box.querySelectorAll("[data-col]").forEach((s) => { if (s.value) cols[s.dataset.col] = s.value; });
      if (Object.keys(cols).length) state.mapping.columns[src] = { ...(state.mapping.columns[src] || {}), ...cols };
    });
    reparse();
    toast("Mapping applied", "success");
  });

  mountDropzone($("drop"), {
    maxBytes: 50 * 1024 * 1024, maxFiles: 12, multiple: true,
    label: "Drop one or more exports here, paste, or browse",
    onFiles: async (files, info) => {
      const got = [];
      for (const f of files) { try { got.push({ name: f.name, text: await f.text() }); } catch (_) { toast("Could not read " + f.name, "error"); } }
      if (info && info.skipped) for (const s of info.skipped) toast(s.name + ": " + s.reason, "warning");
      if (!got.length) return;
      addFiles(got);
      const rec = state.parsed.files.filter((f) => got.some((g) => g.name === f.name));
      const bad = rec.filter((f) => f.source === "unknown");
      toast(rec.length - bad.length + " file(s) recognised" + (bad.length ? ", " + bad.length + " need mapping" : ""), bad.length ? "warning" : "success");
    },
  });

  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    state.files = [];
    addFiles(ex.files, true);
    toast("Synthetic example loaded. Not real data; it is never written to the Security Graph.", "info");
  });

  // -------------------------------------------------------------- analyze --
  const opts = () => {
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => {
      const k = el.dataset.opt;
      if (k === "trustedAccounts") { if (el.value.trim()) o[k] = el.value.trim(); return; }
      if (k === "now") { if (el.value) o[k] = el.value + "T23:59:59Z"; return; }
      const n = Number(el.value); if (Number.isFinite(n) && el.value !== "") o[k] = n;
    });
    return o;
  };

  $("run").addEventListener("click", async () => {
    if (!state.parsed) return;
    const prog = $("prog"), bar = prog.firstElementChild;
    prog.style.display = "block"; bar.style.width = "0%"; $("run").disabled = true;
    try {
      state.result = await runInWorker(ENGINE, "analyze", [{ rows: state.parsed.rows, skipped: state.parsed.skipped }, opts()], {
        onProgress: (i, n) => { bar.style.width = (n ? Math.round(i / n * 100) : 0) + "%"; },
      });
      state.sel = -1;
      render(state.result);
      toast(state.result.findings.length + " finding(s), " + state.result.tables.principals.length + " principal(s)", "success");
    } catch (e) {
      toast("Analysis failed: " + (e && e.message || e), "error");
    } finally {
      prog.style.display = "none"; $("run").disabled = !(state.parsed && state.parsed.rows.length);
    }
  });

  // --------------------------------------------------------------- render --
  function render(r) {
    const s = r.summary;
    $("kpis").innerHTML = kpi(s.principals, "principals") + kpi(s.privileged, "privileged") + kpi(s.findings, "findings") +
      kpi(s.bySeverity.critical || 0, "critical", "crit") + kpi(s.bySeverity.high || 0, "high", "high") + kpi(s.noMfa, "privileged, no MFA") +
      (s.jitRatio != null ? kpi(Math.round(s.jitRatio * 100) + "%", "PIM eligible (JIT)") + kpi(s.globalAdmins, "global admins") : "") +
      kpi(s.now ? s.now.slice(0, 10) : "none", "reference date");
    $("pcard").style.display = ""; $("fcard").style.display = ""; $("xcard").style.display = "";
    renderPrincipals(r);
    renderFindings(r);
    $("drawer").style.display = "none";
    $("skipped").innerHTML = r.skipped.length ? "Checks not run (" + r.skipped.length + "):<ul>" + r.skipped.map((k) => "<li><b>" + esc(k.check) + "</b>: " + esc(k.reason) + "</li>").join("") + "</ul>" : "";
    renderExports(r);
  }

  const PCOLS = [["source", "Source"], ["principal", "Principal"], ["type", "Type"], ["roles", "Role(s)"], ["assignmentType", "Assignment"], ["lastUsed", "Last used"], ["mfa", "MFA"], ["flags", "Flags"]];
  function renderPrincipals(r) {
    const q = $("pfilter").value.trim().toLowerCase(), only = $("ponly").checked;
    let rows = r.tables.principals.filter((p) => (!only || p.privileged) && (!q || [p.principal, p.name, p.source, p.roles.join(" "), p.flags.join(" "), p.type].join(" ").toLowerCase().includes(q)));
    const { key, asc } = state.psort;
    const val = (p) => { const v = p[key]; return Array.isArray(v) ? v.join(" ").toLowerCase() : v == null ? "" : String(v).toLowerCase(); };
    rows = rows.slice().sort((a, b) => { const x = val(a), y = val(b); return (x < y ? -1 : x > y ? 1 : 0) * (asc ? 1 : -1) || a.principal.localeCompare(b.principal); });
    $("pcount").textContent = rows.length + " of " + r.tables.principals.length;
    const list = $("plist");
    if (!rows.length) { list.innerHTML = '<div class="' + P + '-empty">No principals match.</div>'; return; }
    list.innerHTML = "<table><thead><tr>" + PCOLS.map(([k, l]) => '<th data-k="' + k + '" class="' + (key === k ? "on" + (asc ? " asc" : "") : "") + '">' + l + "</th>").join("") + "</tr></thead><tbody>" +
      rows.slice(0, 2000).map((p) => "<tr><td>" + esc(SOURCES[p.source] ? p.source : p.source) + "</td><td><b>" + esc(p.principal) + "</b>" + (p.name && p.name !== p.principal ? "<div>" + esc(p.name) + "</div>" : "") + "</td><td>" + esc(p.type) + "</td><td>" + (p.roles.length ? p.roles.map((x) => '<span class="' + P + '-chip">' + esc(x) + "</span>").join("") : '<span class="' + P + '-conf">' + (p.privileged ? "" : "not privileged") + "</span>") + "</td><td>" + esc(label(p.assignmentType)) + "</td><td>" + esc(p.lastUsed ? p.lastUsed.slice(0, 10) : "") + "</td><td>" + (p.mfa === true ? '<span class="' + P + '-mfa-yes">yes</span>' : p.mfa === false ? '<span class="' + P + '-mfa-no">no</span>' : "") + "</td><td>" + p.flags.map((x) => '<span class="' + P + '-chip flag">' + esc(x) + "</span>").join("") + "</td></tr>").join("") + "</tbody></table>";
    list.querySelectorAll("th[data-k]").forEach((th) => th.addEventListener("click", () => { const k = th.dataset.k; if (state.psort.key === k) state.psort.asc = !state.psort.asc; else state.psort = { key: k, asc: true }; renderPrincipals(r); }));
  }
  $("pfilter").addEventListener("input", () => state.result && renderPrincipals(state.result));
  $("ponly").addEventListener("change", () => state.result && renderPrincipals(state.result));

  const FCOLS = [["severity", "Severity"], ["title", "Finding"], ["confidence", "Confidence"], ["controls", "Controls"], ["evidenceCount", "Evidence"]];
  const CONF_RANK = { confirmed: 3, likely: 2, review: 1 };
  function renderFindings(r) {
    const list = $("list");
    if (!r.findings.length) { list.innerHTML = '<div class="' + P + '-empty">No findings for the current inputs and thresholds.</div>'; return; }
    const { key, asc } = state.fsort;
    const val = (f) => key === "severity" ? SEVERITY_RANK[f.severity] : key === "confidence" ? CONF_RANK[f.confidence] || 0 : key === "evidenceCount" ? f.evidenceCount : key === "controls" ? (f.controls || []).map((c) => c.framework + c.id).join(" ").toLowerCase() : String(f[key] || "").toLowerCase();
    const order = r.findings.map((f, i) => i).sort((a, b) => { const x = val(r.findings[a]), y = val(r.findings[b]); return (x < y ? -1 : x > y ? 1 : 0) * (asc ? 1 : -1) || SEVERITY_RANK[r.findings[b].severity] - SEVERITY_RANK[r.findings[a].severity]; });
    list.innerHTML = "<table><thead><tr>" + FCOLS.map(([k, l]) => '<th data-k="' + k + '" class="' + (key === k ? "on" + (asc ? " asc" : "") : "") + '">' + l + "</th>").join("") + "</tr></thead><tbody>" +
      order.map((i) => { const f = r.findings[i]; return '<tr data-i="' + i + '"' + (state.sel === i ? ' class="sel"' : "") + "><td>" + pill(f.severity) + "</td><td><b>" + esc(f.title) + "</b><div>" + esc(f.description) + "</div></td><td>" + pill(f.confidence) + "</td><td>" + (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</td><td>" + f.evidenceCount + "</td></tr>"; }).join("") + "</tbody></table>";
    list.querySelectorAll("th[data-k]").forEach((th) => th.addEventListener("click", () => { const k = th.dataset.k; if (state.fsort.key === k) state.fsort.asc = !state.fsort.asc; else state.fsort = { key: k, asc: k === "title" || k === "controls" }; renderFindings(r); }));
    list.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => { state.sel = Number(tr.dataset.i); renderFindings(r); renderDrawer(r.findings[state.sel]); }));
  }

  function renderDrawer(f) {
    const d = $("drawer"); d.style.display = "block";
    const ev = f.evidence || [];
    const keys = [];
    for (const row of ev) for (const k of Object.keys(row)) if (!keys.includes(k)) keys.push(k);
    const table = ev.length ? '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
      ev.map((row) => "<tr>" + keys.map((k) => "<td>" + esc(row[k] == null ? "" : typeof row[k] === "object" ? JSON.stringify(row[k]) : row[k]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>" : '<div class="' + P + '-empty">No evidence rows.</div>';
    d.innerHTML = '<div class="' + P + '-card" style="margin:12px 0 0"><div class="' + P + '-inline" style="margin-bottom:8px">' + pill(f.severity) + pill(f.confidence) + '<span class="' + P + '-chip">' + esc(f.category) + "</span></div><b>" + esc(f.title) + "</b><p>" + esc(f.description) + '</p><p><b>Recommendation.</b> ' + esc(f.recommendation) + '</p><p class="' + P + '-help">Controls: ' + (f.controls || []).map((c) => esc(c.framework + " " + c.id)).join("; ") + "</p>" +
      '<p class="' + P + '-help">Evidence: ' + ev.length + " of " + f.evidenceCount + " row(s) shown" + (f.assets && f.assets.length ? "; identities: " + f.assets.map((a) => esc(a.name)).join(", ") : "") + "</p>" + table + "</div>";
    d.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function renderExports(r) {
    const ex = $("exports");
    const dataset = state.isExample ? "synthetic example" : state.files.map((f) => f.name).join(", ");
    ex.innerHTML = ['csv|Findings CSV', 'json|Full JSON', 'txt|Summary TXT', 'inv|Principal inventory CSV', 'att|Attestation TXT'].map((x) => { const [k, l] = x.split("|"); return '<button class="' + P + '-btn" data-x="' + k + '">' + l + "</button>"; }).join("");
    const stamp = () => fileStamp();
    ex.querySelector('[data-x="csv"]').addEventListener("click", () => download(TOOL_ID + "-findings-" + stamp() + ".csv", findingsToCsv(r.findings), "text/csv"));
    ex.querySelector('[data-x="json"]').addEventListener("click", () => download(TOOL_ID + "-" + stamp() + ".json", toJson({ ...r, dataset, exportedAt: new Date().toISOString() }), "application/json"));
    ex.querySelector('[data-x="txt"]').addEventListener("click", () => download(TOOL_ID + "-summary-" + stamp() + ".txt", summaryText(r, dataset), "text/plain"));
    ex.querySelector('[data-x="inv"]').addEventListener("click", () => download(TOOL_ID + "-principals-" + stamp() + ".csv", principalsToCsv(r.tables.principals), "text/csv"));
    ex.querySelector('[data-x="att"]').addEventListener("click", () => {
      const reviewer = $("reviewer").value.trim();
      if (!reviewer) { toast("Enter the reviewer name first; the attestation records who reviewed.", "warning"); $("reviewer").focus(); return; }
      download(TOOL_ID + "-attestation-" + stamp() + ".txt", attestationText(r, { reviewer, date: new Date().toISOString(), dataset }), "text/plain");
    });
    attachSinkButton(ex, () => ({ findings: r.findings, sample: state.isExample }), TOOL_ID, { dataset });
  }

  function summaryText(r, dataset) {
    const sum = summarize(r.findings);
    return ["Privileged Access Audit summary", "Dataset: " + dataset, "Sources: " + (r.meta.sources.map((x) => SOURCES[x] || x).join("; ") || "none"), "Reference date: " + (r.meta.now || "none"),
      "Principals: " + r.summary.principals + " (" + r.summary.privileged + " privileged)", "Findings: " + sum.total + " (critical " + sum.bySeverity.critical + ", high " + sum.bySeverity.high + ", medium " + sum.bySeverity.medium + ", low " + sum.bySeverity.low + ")",
      r.summary.jitRatio != null ? "Entra PIM eligible: " + r.summary.eligible + " of " + (r.summary.eligible + r.summary.standing) + " assignments" : "", ""]
      .concat(r.findings.map((f) => "- [" + f.severity + "/" + f.confidence + "] " + f.title + " (" + f.evidenceCount + ") - " + f.recommendation))
      .concat(r.skipped.length ? ["", "Checks not run:"].concat(r.skipped.map((k) => "- " + k.check + ": " + k.reason)) : []).join("\n");
  }
}
