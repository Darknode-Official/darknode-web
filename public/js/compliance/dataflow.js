// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Data Inventory & Processing Register (dataflow): Deck tool UI. Two team-shareable
// registers (core/register.js): processing activities (mirrored to the Security Graph
// as CONTROL entities, one per Art. 30 record) and a DSAR log (CASE entities). All
// scoring is in the pure engine (dataflow-engine.js, run in a Worker). The only
// fetch is this site's own /data/ref/eu-adequacy.json. No native dialogs.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { openRegister, wsKey } from "../core/register.js";
import { download, toJson, fileStamp, toIcs } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, VERSION, THRESHOLD_LABELS, ROLES, LEGAL_BASES, ART9_CONDITIONS, SUBJECTS, CATEGORIES, DPIA_CRITERIA, DPIA_STATUSES, MECHANISMS, DSAR_TYPES, REGIMES,
  COUNTRIES, COLUMNS, COLUMN_LABELS, DSAR_COLUMNS, DSAR_COLUMN_LABELS, ACTIVITY_SCHEMA, DSAR_SCHEMA,
  parseInput, analyze, findingsToCsv, exampleDataset, normalizeActivity, validateActivity, normalizeDsar, validateDsar, screenDpia, suggestCategories,
  csvToActivities, csvToDsars, autoMapActivities, autoMapDsars, ropaCsv, dsarCsv, dpiaMemo, icsEvents, summaryText, categoryLabel, subjectLabel, label, dsarDue,
} from "./dataflow-engine.js?v=20261016zc";

const ENGINE = engineUrl("./dataflow-engine.js?v=20261016zc", import.meta);
const P = "dfr";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CONF_RANK = { confirmed: 0, likely: 1, review: 2 };
const ST_C = { overdue: "#b00020", "at risk": "#b58100", late: "#c0501b", open: "#2552c6", "on time": "#1b7f4d", gap: "#b00020", review: "#b58100", ok: "#1b7f4d" };
const today = () => new Date().toISOString().slice(0, 10);

const CSS = `
  .dfr-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .dfr-root *{box-sizing:border-box}
  .dfr-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .dfr-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .dfr-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--mut,#667085);border:1px solid var(--line,#e6e8ee);padding:2px 9px;border-radius:999px}
  .dfr-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:120ch;overflow-wrap:anywhere}
  .dfr-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .dfr-card h2{font-size:1.02rem;margin:0 0 4px}
  .dfr-card h3{font-size:.8rem;margin:14px 0 6px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#667085)}
  .dfr-row{display:flex;flex-wrap:wrap;gap:8px 10px;align-items:center;margin-top:10px}
  .dfr-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:7px 13px;border-radius:8px;cursor:pointer}
  .dfr-btn:hover{border-color:var(--mut,#667085)}
  .dfr-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .dfr-btn.dang{color:#b00020}
  .dfr-btn:disabled{opacity:.5;cursor:default}
  .dfr-tabs{display:flex;flex-wrap:wrap;gap:4px;border-bottom:1px solid var(--line,#e6e8ee);margin-bottom:12px}
  .dfr-tab{appearance:none;font:inherit;font-size:.86rem;font-weight:600;background:none;border:1px solid transparent;border-bottom:none;color:var(--mut,#667085);padding:7px 13px;border-radius:8px 8px 0 0;cursor:pointer;margin-bottom:-1px}
  .dfr-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#e6e8ee);background:var(--card,#fff)}
  .dfr-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px 16px}
  .dfr-field{display:flex;flex-direction:column;gap:3px;min-width:0}
  .dfr-field.wide{grid-column:1/-1}
  .dfr-field>label,.dfr-lbl{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .dfr-root input[type=text],.dfr-root input[type=number],.dfr-root input[type=date],.dfr-root select,.dfr-root textarea{font:inherit;font-size:.86rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%;min-width:0}
  .dfr-root textarea{min-height:64px;resize:vertical}
  .dfr-help{font-size:.75rem;color:var(--mut,#667085);margin:0;overflow-wrap:anywhere}
  .dfr-help.bad{color:#b00020}
  .dfr-checks{display:flex;flex-wrap:wrap;gap:6px}
  .dfr-chk{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line,#d7dbe3);border-radius:999px;padding:4px 11px;font-size:.8rem;cursor:pointer;user-select:none;background:var(--card,#fff);max-width:100%;overflow-wrap:anywhere}
  .dfr-chk input{margin:0;flex:none}
  .dfr-chk.sp{border-color:#b58100}
  .dfr-tbl{border:1px solid var(--line,#e6e8ee);border-radius:10px;overflow:auto;max-width:100%}
  .dfr-tbl table{width:100%;border-collapse:collapse;font-size:.84rem}
  .dfr-tbl th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 10px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .dfr-tbl th[data-sort]{cursor:pointer;user-select:none}
  .dfr-tbl th.sorted::after{content:" \\2193"}
  .dfr-tbl th.sorted.asc::after{content:" \\2191"}
  .dfr-tbl td{padding:8px 10px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .dfr-tbl tr.dfr-click{cursor:pointer}
  .dfr-tbl tr.dfr-click:hover td{background:var(--bg,#f7f8fb)}
  .dfr-tbl tr.sel td{background:var(--bg,#f2f4f8)}
  .dfr-tbl td input,.dfr-tbl td select{padding:4px 6px;font-size:.8rem;min-width:90px}
  .dfr-pill{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .dfr-pill.critical{background:#7a0012}.dfr-pill.high{background:#b00020}.dfr-pill.medium{background:#b58100}.dfr-pill.low{background:#2552c6}.dfr-pill.info{background:#667085}
  .dfr-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .dfr-mut{color:var(--mut,#667085);font-size:.78rem}
  .dfr-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin:0 0 14px}
  .dfr-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .dfr-kpi b{display:block;font-size:1.3rem;line-height:1.25}
  .dfr-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .dfr-kpi.alert b{color:#b00020}
  .dfr-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin:0 0 6px;display:none}
  .dfr-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .dfr-status{font-size:.8rem;color:var(--mut,#667085);margin-bottom:10px;overflow-wrap:anywhere}
  .dfr-note{border:1px solid var(--line,#e6e8ee);border-left:4px solid #b58100;border-radius:8px;padding:8px 12px;margin:0 0 12px;background:var(--card,#fff);font-size:.84rem;overflow-wrap:anywhere}
  .dfr-dl{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;margin:6px 0;font-size:.84rem}
  .dfr-dl dt{color:var(--mut,#667085)}
  .dfr-dl dd{margin:0;overflow-wrap:anywhere}
  .dfr-cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
  .dfr-empty{padding:22px;text-align:center;color:var(--mut,#667085)}
  .dfr-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px;overflow-wrap:anywhere}
  .dfr-drawer{display:none}
  .dfr-hide{display:none}
  .dfr-root details summary{cursor:pointer;font-size:.82rem;color:var(--mut,#667085);margin-top:8px}
  .dfr-crit{list-style:none;padding:0;margin:6px 0;font-size:.84rem}
  .dfr-crit li{padding:3px 0;border-bottom:1px solid var(--line,#eef0f4);overflow-wrap:anywhere}
  .dfr-crit b{display:inline-block;min-width:22px;color:#b00020}
  @media(max-width:600px){.dfr-card{padding:12px}.dfr-dl{grid-template-columns:1fr}.dfr-dl dt{margin-top:6px}}
`;

const kpi = (v, l, alert) => '<div class="' + P + "-kpi" + (alert ? " alert" : "") + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const field = (id, lbl, input, help, wide) => '<div class="' + P + "-field" + (wide ? " wide" : "") + '"><label for="' + P + "-" + id + '">' + esc(lbl) + "</label>" + input + (help ? '<p class="' + P + '-help">' + esc(help) + "</p>" : "") + "</div>";
const sel = (id, list, blank) => '<select id="' + P + "-" + id + '">' + (blank != null ? '<option value="">' + esc(blank) + "</option>" : "") + list.map((x) => '<option value="' + esc(x.id) + '">' + esc(x.label) + "</option>").join("") + "</select>";
const checks = (id, list, cls) => '<div class="' + P + '-checks" id="' + P + "-" + id + '">' + list.map((x) => '<label class="' + P + "-chk" + (cls ? " " + cls : "") + '"><input type="checkbox" value="' + esc(x.id) + '">' + esc(x.label) + "</label>").join("") + "</div>";
const sevPill = (s) => '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>";
const stPill = (s) => '<span class="' + P + '-pill" style="background:' + (ST_C[s] || "#667085") + '">' + esc(s) + "</span>";
const chips = (ctl) => (ctl || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("");

function objTable(rows) {
  if (!rows || !rows.length) return '<div class="' + P + '-empty">No rows.</div>';
  const keys = [...new Set(rows.flatMap((r) => Object.keys(r || {})))];
  return '<div class="' + P + '-tbl"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => "<td>" + esc(r[k] != null && typeof r[k] === "object" ? JSON.stringify(r[k]) : r[k]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

/** Mount the tool into main. */
export function renderDataFlow(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  const thrKeys = Object.keys(THRESHOLD_LABELS);
  const general = CATEGORIES.filter((c) => !c.special && !c.criminal);
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Data Inventory &amp; Processing Register</h1><span class="', P, '-tag">GDPR Art. 30</span></div>',
    '<p class="', P, '-sub">Record of processing activities, DPIA screening (WP248 rev.01), international transfers, retention and DSAR deadlines. Runs entirely in your browser. Nothing is uploaded. ',
    'The only fetch is this site\'s own adequacy reference file (/data/ref/eu-adequacy.json); there are no live lookups. Saved activities are mirrored into the Security Graph as CONTROL entities and DSARs as CASE entities, so a team workspace shares one register. ',
    'This tool helps you keep records and find gaps. It does not make you compliant and is not legal advice: verify with counsel.</p>',
    '<div id="', P, '-exnote"></div>',
    '<div class="', P, '-tabs" id="', P, '-maintabs">',
    ["acts|Activities", "dsar|DSAR log", "import|Import", "settings|Settings"].map((s) => { const [k, l] = s.split("|"); return '<button class="' + P + "-tab" + (k === "acts" ? " on" : "") + '" data-tab="' + k + '" type="button">' + l + "</button>"; }).join(""),
    "</div>",

    '<div data-pane="acts">',
    '<div class="', P, '-card"><h2>Processing activities</h2><p class="', P, '-help">One row per processing activity (Art. 30). Click a row for its detail, DPIA screening and memo.</p>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-new" type="button">New activity</button><button class="', P, '-btn" id="', P, '-example" type="button">Load example (synthetic)</button></div>',
    '<div class="', P, '-tbl" style="margin-top:10px" id="', P, '-alist"></div></div>',
    '<div class="', P, "-card ", P, '-hide" id="', P, '-detail"></div>',
    '<div class="', P, "-card ", P, '-hide" id="', P, '-form"></div>',
    "</div>",

    '<div data-pane="dsar" class="', P, '-hide">',
    '<div class="', P, '-card"><h2>DSAR log</h2><p class="', P, '-help" id="', P, '-dsarhelp"></p>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-dnew" type="button">New request</button></div>',
    '<div class="', P, '-tbl" style="margin-top:10px" id="', P, '-dlist"></div></div>',
    '<div class="', P, "-card ", P, '-hide" id="', P, '-dform"></div>',
    "</div>",

    '<div data-pane="import" class="', P, '-hide"><div class="', P, '-card"><h2>Import</h2><p class="', P, '-help">Drop a register JSON exported from this tool, a processing-activities CSV (for example the ICO documentation template saved as CSV, or this tool\'s ROPA export), or a DSAR log CSV. Nothing is saved until you press Import.</p>',
    '<div style="margin-top:10px" id="', P, '-drop"></div><div id="', P, '-detected"></div><div id="', P, '-mapping"></div></div></div>',

    '<div data-pane="settings" class="', P, '-hide"><div class="', P, '-card"><h2>Settings</h2><p class="', P, '-help">Saved in this browser for the current workspace.</p>',
    '<h3>Organisation (Art. 30(1)(a) / 30(2)(a))</h3><div class="', P, '-grid">',
    field("o-name", "Organisation name", '<input type="text" id="' + P + '-o-name" placeholder="Legal name">'),
    field("o-contact", "Contact details", '<input type="text" id="' + P + '-o-contact" placeholder="Email, address">'),
    field("o-dpo", "Data protection officer", '<input type="text" id="' + P + '-o-dpo" placeholder="Name or mailbox">', "Where one is appointed (Art. 37)."),
    field("o-representative", "EU or UK representative", '<input type="text" id="' + P + '-o-representative" placeholder="If applicable">', "Art. 27, for organisations outside the EU or UK."),
    '</div><h3>Rules</h3><div class="', P, '-grid">',
    field("s-regime", "Law", sel("s-regime", REGIMES), "Which regime's transfer rules and article references to apply."),
    field("s-clock", "DSAR clock starts", '<select id="' + P + '-s-clock"><option value="receipt">On receipt of the request</option><option value="identity">When identity is verified (if recorded)</option></select>', "EDPB Guidelines 01/2022 count from receipt; the ICO lets the clock start once identity is confirmed. Verify with counsel."),
    field("s-roll", "Weekend deadlines", '<select id="' + P + '-s-roll"><option value="1">Move to the next Monday</option><option value="0">Keep the calendar date</option></select>', "Public holidays are not modelled."),
    "</div><h3>Thresholds</h3><div class=\"", P, '-grid">',
    thrKeys.map((k) => field("opt-" + k, THRESHOLD_LABELS[k][0], '<input type="number" min="1" step="1" id="' + P + "-opt-" + k + '" data-opt="' + k + '" value="' + DEFAULTS[k] + '">', THRESHOLD_LABELS[k][1] + " Default " + DEFAULTS[k] + ".")).join(""),
    '</div><div class="', P, '-row"><button class="', P, '-btn" id="', P, '-sreset" type="button">Reset rules and thresholds</button></div></div></div>',

    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-status" id="', P, '-status"></div>',
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card"><h2>Findings</h2><div class="', P, '-tbl" id="', P, '-flist"><div class="', P, '-empty">No activities analysed yet.</div></div><div class="', P, '-skip" id="', P, '-skipped"></div></div>',
    '<div class="', P, "-card ", P, '-drawer" id="', P, '-drawer"></div>',
    '<div class="', P, '-card"><h2>Exports</h2><div class="', P, '-row" id="', P, '-exports" style="margin-top:4px"></div></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  const reg = openRegister(TOOL_ID, "CONTROL", { schema: ACTIVITY_SCHEMA });
  const dreg = openRegister(TOOL_ID + "-dsar", "CASE", { schema: DSAR_SCHEMA });
  const SET_KEY = () => wsKey("dfr_settings");
  let settings = loadSettings();
  let example = null, result = null, selId = null, editing = null, dEditing = null, adequacy = null, adequacyErr = "";
  let aSort = { key: "findings", asc: false }, dSort = { key: "received", asc: false }, fSort = { key: "severity", asc: true };
  let seq = 0, timer = 0, imported = null, panelSeq = 0;
  let knownAssets = [], knownVendors = null;

  function loadSettings() {
    let s = {};
    try { s = JSON.parse(localStorage.getItem(SET_KEY()) || "null") || {}; } catch (_) {}
    return { org: { name: "", contact: "", dpo: "", representative: "", ...(s.org || {}) }, regime: s.regime || "eu", clockStart: s.clockStart || "receipt", rollWeekends: s.rollWeekends !== false, thresholds: { ...DEFAULTS, ...(s.thresholds || {}) } };
  }
  function saveSettings() { try { localStorage.setItem(SET_KEY(), JSON.stringify(settings)); } catch (_) {} }
  const activities = () => (example ? example.activities : reg.list());
  const dsars = () => (example ? example.dsars : dreg.list());
  const nowIso = () => (example ? example.now : new Date().toISOString());
  const org = () => (example ? example.org : settings.org);
  const opts = () => ({
    ...settings.thresholds, regime: settings.regime, clockStart: settings.clockStart, rollWeekends: settings.rollWeekends, now: nowIso(), adequacy, org: org(),
    knownVendors: example ? example.knownVendors : knownVendors || undefined,
  });

  // ---- tabs --------------------------------------------------------------------
  $("maintabs").addEventListener("click", (e) => {
    const b = e.target.closest("[data-tab]"); if (!b) return;
    $("maintabs").querySelectorAll("[data-tab]").forEach((x) => x.classList.toggle("on", x === b));
    main.querySelectorAll("[data-pane]").forEach((p) => p.classList.toggle(P + "-hide", p.dataset.pane !== b.dataset.tab));
  });

  // ---- settings ------------------------------------------------------------------
  function fillSettings() {
    for (const k of ["name", "contact", "dpo", "representative"]) $("o-" + k).value = settings.org[k] || "";
    $("s-regime").value = settings.regime; $("s-clock").value = settings.clockStart; $("s-roll").value = settings.rollWeekends ? "1" : "0";
    main.querySelectorAll("[data-opt]").forEach((el) => { el.value = settings.thresholds[el.dataset.opt]; });
  }
  for (const k of ["name", "contact", "dpo", "representative"]) $("o-" + k).addEventListener("input", (e) => { settings.org[k] = e.target.value.trim(); saveSettings(); schedule(); });
  $("s-regime").addEventListener("change", (e) => { settings.regime = e.target.value; saveSettings(); schedule(); });
  $("s-clock").addEventListener("change", (e) => { settings.clockStart = e.target.value; saveSettings(); schedule(); });
  $("s-roll").addEventListener("change", (e) => { settings.rollWeekends = e.target.value === "1"; saveSettings(); schedule(); });
  main.querySelectorAll("[data-opt]").forEach((el) => el.addEventListener("input", () => {
    const n = Number(el.value);
    if (Number.isFinite(n) && n >= 1) { settings.thresholds[el.dataset.opt] = Math.round(n); saveSettings(); schedule(); }
  }));
  $("sreset").addEventListener("click", async () => {
    const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Reset rules and thresholds?", "Law, DSAR clock, weekend handling and every threshold return to the defaults. Organisation details are kept.", { danger: true }) : false;
    if (!ok) return;
    settings = { ...settings, regime: "eu", clockStart: "receipt", rollWeekends: true, thresholds: { ...DEFAULTS } };
    saveSettings(); fillSettings(); schedule();
  });

  // ---- analysis ------------------------------------------------------------------
  function schedule() { clearTimeout(timer); timer = setTimeout(analyzeNow, 150); }
  async function analyzeNow() {
    const my = ++seq;
    const ds = { activities: activities(), dsars: dsars() };
    const prog = $("prog"), bar = prog.firstElementChild;
    if (ds.activities.length + ds.dsars.length > 300) { prog.style.display = "block"; bar.style.width = "5%"; }
    let r = null;
    try {
      r = await runInWorker(ENGINE, "analyze", [ds, opts()], { onProgress: (i, n) => { bar.style.width = (n ? Math.round(i / n * 100) : 0) + "%"; } });
    } catch (_) {
      try { r = analyze(ds, opts()); } catch (err) { toast("Analysis failed: " + (err && err.message || err), "error"); }
    } finally { if (my === seq) prog.style.display = "none"; }
    if (my !== seq || !r) return;
    result = r;
    renderAll();
  }

  function renderAll() {
    const s = result.summary;
    const sum = summarize(result.findings);
    $("kpis").innerHTML = kpi(s.activities, "activities") + kpi(s.specialCategory, "special / criminal data") + kpi(s.dpiaLikely, "DPIA likely needed") +
      kpi(s.dpiaGaps, "DPIA gaps", s.dpiaGaps > 0) + kpi(s.transfersGap, "transfer gaps", s.transfersGap > 0) + kpi(s.reviewsOverdue, "reviews due", s.reviewsOverdue > 0) +
      kpi(s.dsarOpen, "DSARs open") + kpi(s.dsarOverdue, "DSARs overdue", s.dsarOverdue > 0) + kpi(s.dsarAtRisk, "DSARs at risk", s.dsarAtRisk > 0) +
      kpi(s.dsarMedianDays == null ? "-" : s.dsarMedianDays + "d", "median DSAR time") + kpi(sum.bySeverity.high + sum.bySeverity.critical, "high findings", sum.bySeverity.high + sum.bySeverity.critical > 0);
    const ref = result.meta.reference;
    $("status").textContent = (ref ? "Transfers checked against reference data " + ref.version + " (updated " + ref.updated + "), verify with counsel." : "Adequacy reference data " + (adequacyErr ? "failed to load (" + adequacyErr + ")" : "loading") + "; transfers not assessed.") +
      " As of " + result.meta.now + ". " + label(REGIMES, result.meta.regime) + ".";
    $("exnote").innerHTML = example ? '<div class="' + P + '-note"><b>Synthetic example loaded.</b> Larkspur Cloudworks is fictional: eight activities and ten DSARs, people at test.darknode.ai, dated as of ' + esc(example.now.slice(0, 10)) + '. Nothing is saved and the graph button is disabled. <button class="' + P + '-btn" id="' + P + '-exit" type="button">Close example</button></div>' : "";
    if (example) $("exit").addEventListener("click", () => { example = null; selId = null; closeForm(); closeDForm(); schedule(); });
    $("dsarhelp").textContent = "Deadline: one calendar month from " + (settings.clockStart === "identity" ? "identity verification (or receipt when not recorded)" : "receipt") + ", or three months when extended (Art. 12(3)); " +
      (settings.rollWeekends ? "weekend deadlines move to Monday" : "weekend deadlines are kept") + ". Use your ticket reference, never the requester's name or email. Verify deadlines with counsel.";
    renderActList(); renderDsarList(); renderFindings(); renderExports();
    $("skipped").textContent = result.skipped.length ? "Not checked: " + result.skipped.map((x) => x.check + " (" + x.reason + ")").join("; ") : "";
    if (selId) renderDetail();
  }

  // ---- activities list -------------------------------------------------------------
  const ASORT = { activity: (a) => a.activity.toLowerCase(), role: (a) => a.role, legalBasis: (a) => a.legalBasis, dpia: (a) => a.dpiaCriteria, transfers: (a) => a.transfers, nextReview: (a) => a.nextReview || "9999", findings: (a) => a.findings };
  function renderActList() {
    const box = $("alist");
    const list = result.tables.activities.slice();
    if (!list.length) { box.innerHTML = '<div class="' + P + '-empty">No activities yet. Add one, import a ROPA CSV, or load the synthetic example.</div>'; return; }
    const f = ASORT[aSort.key];
    list.sort((a, b) => { const p = f(a), q = f(b); return (p < q ? -1 : p > q ? 1 : 0) * (aSort.asc ? 1 : -1) || a.activity.localeCompare(b.activity); });
    const th = (k, l) => '<th data-sort="' + k + '"' + (aSort.key === k ? ' class="sorted' + (aSort.asc ? " asc" : "") + '"' : "") + ">" + l + "</th>";
    const now = result.meta.now;
    box.innerHTML = "<table><thead><tr>" + th("activity", "Activity") + th("role", "Role") + th("legalBasis", "Lawful basis") + th("dpia", "DPIA screening") + th("transfers", "Transfers") + th("nextReview", "Next review") + th("findings", "Findings") + "</tr></thead><tbody>" +
      list.map((a) => '<tr class="' + P + "-click" + (a.id === selId ? " sel" : "") + '" data-id="' + esc(a.id) + '"><td><b>' + esc(a.activity) + "</b>" + (a.special || a.criminal ? ' <span class="' + P + '-chip">' + (a.special ? "Art. 9" : "") + (a.special && a.criminal ? " + " : "") + (a.criminal ? "Art. 10" : "") + "</span>" : "") + '<div class="' + P + '-mut">' + a.subjects + " subject type(s), " + a.categories + " categories</div></td>" +
        "<td>" + esc(a.role || "-") + "</td><td>" + esc(a.legalBasis || "-") + "</td><td>" + a.dpiaCriteria + "/9" + (a.dpiaLikely ? " <b>likely required</b>" : "") + '<div class="' + P + '-mut">' + esc(a.dpiaStatus || "status not recorded") + "</div></td>" +
        "<td>" + a.transfers + "</td><td" + (a.nextReview && a.nextReview < now ? ' style="color:#b00020;font-weight:700"' : "") + ">" + esc(a.nextReview || "-") + "</td><td>" + a.findings + "</td></tr>").join("") + "</tbody></table>";
    box.querySelectorAll("th[data-sort]").forEach((h) => h.addEventListener("click", () => { const k = h.dataset.sort; aSort = { key: k, asc: aSort.key === k ? !aSort.asc : k === "activity" }; renderActList(); }));
    box.querySelectorAll("tr[data-id]").forEach((tr) => tr.addEventListener("click", () => { selId = tr.dataset.id; closeForm(); renderActList(); renderDetail(); $("detail").scrollIntoView({ behavior: "smooth", block: "nearest" }); }));
  }

  // ---- activity detail ---------------------------------------------------------------
  function findRec(id) { return activities().find((r) => r.id === id) || null; }
  function renderDetail() {
    const box = $("detail");
    const raw = findRec(selId);
    if (!raw) { box.classList.add(P + "-hide"); return; }
    const a = normalizeActivity(raw);
    const scr = screenDpia(a);
    const fs = result.findings.filter((f) => f.id.split(":")[2] === a.id);
    const tr = result.tables.transfers.filter((t) => t.activity === (a.name || "Unnamed activity"));
    const dd = (k, v) => "<dt>" + esc(k) + "</dt><dd>" + (v ? esc(v) : '<span class="' + P + '-mut">not recorded</span>') + "</dd>";
    box.classList.remove(P + "-hide");
    box.innerHTML = '<div class="' + P + '-row" style="margin-top:0;justify-content:space-between"><h2 style="margin:0">' + esc(a.name || "Unnamed") + '</h2><span class="' + P + '-row" style="margin:0">' +
      '<button class="' + P + '-btn" id="' + P + '-dedit" type="button">Edit</button><button class="' + P + '-btn" id="' + P + '-dreview" type="button">Mark reviewed today</button><button class="' + P + '-btn" id="' + P + '-dmemo" type="button">DPIA screening memo</button>' +
      '<button class="' + P + '-btn dang" id="' + P + '-ddel" type="button">Delete</button><button class="' + P + '-btn" id="' + P + '-dclose" type="button">Close</button></span></div>' +
      '<div class="' + P + '-cols"><div><dl class="' + P + '-dl">' + dd("Purpose", a.purpose) + dd("Role", label(ROLES, a.role)) + (a.role === "processor" ? dd("Controller", a.controllerName) : "") + dd("Owner", a.owner) +
      dd("Lawful basis", label(LEGAL_BASES, a.legalBasis)) + (a.legalBasis === "f" ? dd("LIA", a.liaRef) : "") + dd("Data subjects", a.dataSubjects.map(subjectLabel).join(", ")) +
      dd("Data categories", a.dataCategories.map((c) => categoryLabel(c) + (a.categoryUses[c] ? " (" + a.categoryUses[c] + ")" : "")).join("; ")) +
      (a.art9Condition ? dd("Art. 9(2)", label(ART9_CONDITIONS, a.art9Condition)) : "") + (a.criminalBasis ? dd("Art. 10 basis", a.criminalBasis) : "") +
      dd("Systems", a.systems.join(", ")) + dd("Recipients", a.recipients.join(", ")) + dd("Retention", [a.retention, a.retentionTrigger ? "from " + a.retentionTrigger : "", a.oldestRecord ? "oldest record " + a.oldestRecord : ""].filter(Boolean).join(", ")) +
      dd("Security measures", a.securityMeasures) + dd("Last review", a.lastReview) + (a.notes ? dd("Notes", a.notes) : "") + "</dl></div>" +
      "<div><h3>DPIA screening (WP248 rev.01): " + scr.count + " of 9" + (scr.likely ? ", DPIA likely required" : "") + '</h3><ul class="' + P + '-crit">' +
      scr.criteria.map((c) => "<li><b>" + (c.met ? "Yes" : "") + "</b> " + esc(c.label) + (c.met && c.why ? ' <span class="' + P + '-mut">(' + esc(c.why) + ")</span>" : "") + "</li>").join("") + "</ul>" +
      '<p class="' + P + '-help">Status: ' + esc(label(DPIA_STATUSES, a.dpiaStatus) || "not recorded") + (a.dpiaDate ? ", " + esc(a.dpiaDate) : "") + (a.dpiaRef ? ", ref " + esc(a.dpiaRef) : "") + ". Two or more criteria usually mean a DPIA is required (Art. 35); also check your supervisory authority's list. Verify with counsel.</p>" +
      (tr.length ? "<h3>Transfers</h3>" + '<div class="' + P + '-tbl"><table><thead><tr><th>Law</th><th>Destination</th><th>Recipient</th><th>Mechanism</th><th>Status</th></tr></thead><tbody>' +
        tr.map((t) => "<tr><td>" + esc(t.regime) + "</td><td>" + esc(t.destination) + "</td><td>" + esc(t.recipient) + "</td><td>" + esc(t.mechanism) + "</td><td>" + stPill(t.status) + '<div class="' + P + '-mut">' + esc(t.note) + "</div></td></tr>").join("") + "</tbody></table></div>" : "") +
      "</div></div><h3>Findings for this activity (" + fs.length + ")</h3>" + findingsHtml(fs, "af", false);
    $("dclose").addEventListener("click", () => { selId = null; box.classList.add(P + "-hide"); renderActList(); });
    $("dedit").addEventListener("click", () => openForm(raw));
    $("ddel").addEventListener("click", () => deleteAct(raw));
    $("dreview").addEventListener("click", () => {
      if (example) { toast("Close the synthetic example to edit real records.", "warning"); return; }
      reg.upsert({ ...raw, lastReview: today() }); schedule(); toast("Review date set to today", "success");
    });
    $("dmemo").addEventListener("click", () => download(TOOL_ID + "-dpia-" + (a.name || "activity").toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 40) + "-" + fileStamp() + ".txt", dpiaMemo(raw, { now: nowIso(), org: org(), example: !!example }), "text/plain"));
    box.querySelectorAll("tr[data-af]").forEach((r) => r.addEventListener("click", () => openDrawer(fs[Number(r.dataset.af)])));
  }

  // ---- activity form ---------------------------------------------------------------
  function closeForm() { editing = null; $("form").classList.add(P + "-hide"); }
  function openForm(rec) {
    if (example) { toast("Close the synthetic example to add or edit real records.", "warning"); return; }
    editing = rec ? { ...rec } : {};
    const r = normalizeActivity(editing);
    const f = $("form");
    f.classList.remove(P + "-hide");
    const manual = DPIA_CRITERIA.filter((c) => !c.derived);
    f.innerHTML = "<h2>" + (rec ? "Edit activity: " + esc(r.name) : "New processing activity") + '</h2><p class="' + P + '-help">Inputs start empty. Only the name is required; everything left blank is reported as a gap, never guessed.</p>' +
      "<h3>Activity</h3><div class=\"" + P + '-grid">' +
      field("f-name", "Activity name", '<input type="text" id="' + P + '-f-name" placeholder="e.g. Payroll">') +
      field("f-role", "Your role", sel("f-role", ROLES, "Not set"), "Processor records follow Art. 30(2).") +
      field("f-owner", "Owner", '<input type="text" id="' + P + '-f-owner" placeholder="Team or mailbox">') +
      field("f-controllerName", "Controller (processor records)", '<input type="text" id="' + P + '-f-controllerName" placeholder="On whose behalf">') +
      field("f-jointController", "Joint controller", '<input type="text" id="' + P + '-f-jointController" placeholder="If any">') +
      field("f-purpose", "Purpose", '<textarea id="' + P + '-f-purpose" placeholder="Why this data is processed"></textarea>', "", true) +
      "</div><h3>Data subjects</h3>" + checks("f-subjects", SUBJECTS) +
      '<div class="' + P + '-grid" style="margin-top:8px">' + field("f-subjOther", "Other data subjects", '<input type="text" id="' + P + '-f-subjOther" placeholder="Separate with ;">') + "</div>" +
      "<h3>Data categories</h3>" + checks("f-catGen", general) +
      '<p class="' + P + '-lbl" style="margin:10px 0 4px">Special category data (Art. 9) and criminal offence data (Art. 10)</p>' + checks("f-catSp", CATEGORIES.filter((c) => c.special || c.criminal), "sp") +
      '<div class="' + P + '-grid" style="margin-top:8px">' + field("f-catOther", "Other categories", '<input type="text" id="' + P + '-f-catOther" placeholder="Separate with ;">') + "</div>" +
      '<details><summary>Suggest categories from a sample (DLP detectors)</summary><p class="' + P + '-help" style="margin-top:6px">Paste a few rows of real data from the system. It is scanned here with the Data Loss Prevention detectors; values are masked and never saved.</p>' +
      '<textarea id="' + P + '-f-sample" placeholder="Paste sample rows"></textarea><div class="' + P + '-row"><button class="' + P + '-btn" id="' + P + '-f-scan" type="button">Scan sample</button><span id="' + P + '-f-scanout" class="' + P + '-mut"></span></div></details>' +
      '<p class="' + P + '-lbl" style="margin:12px 0 4px">What each category is used for (minimisation)</p><div class="' + P + '-tbl"><table><thead><tr><th>Category</th><th>Used for</th></tr></thead><tbody id="' + P + '-f-uses"></tbody></table></div>' +
      "<h3>Lawful basis</h3><div class=\"" + P + '-grid">' +
      field("f-legalBasis", "Art. 6(1) lawful basis", sel("f-legalBasis", LEGAL_BASES, "Not recorded")) +
      field("f-liaRef", "Legitimate interests assessment", '<input type="text" id="' + P + '-f-liaRef" placeholder="Reference or link">', "Needed when the basis is legitimate interests.") +
      field("f-art9Condition", "Art. 9(2) condition", sel("f-art9Condition", ART9_CONDITIONS, "None recorded"), "Required for special category data.") +
      field("f-criminalBasis", "Art. 10 authorisation", '<input type="text" id="' + P + '-f-criminalBasis" placeholder="Law or condition">', "Required for criminal offence data.") +
      "</div><h3>Systems and recipients</h3><div class=\"" + P + '-grid">' +
      field("f-systems", "Systems", '<textarea id="' + P + '-f-systems" placeholder="One per line"></textarea><select id="' + P + '-f-addsys" aria-label="Add a system from the Security Graph"><option value="">Add an asset from the Security Graph</option></select>', "Where the data lives.") +
      field("f-recipients", "Recipients", '<textarea id="' + P + '-f-recipients" placeholder="One per line, or none"></textarea><select id="' + P + '-f-addven" aria-label="Add a vendor"><option value="">Add a vendor from the register</option></select>', "Processors, other controllers, authorities. Write none if there are none.") +
      "</div><h3>Third-country transfers</h3><div class=\"" + P + '-tbl"><table><thead><tr><th>Destination</th><th>Recipient</th><th>Mechanism</th><th>DPF certified (US)</th><th>TIA done</th><th></th></tr></thead><tbody id="' + P + '-f-tr"></tbody></table></div>' +
      '<datalist id="' + P + '-countries">' + Object.values(COUNTRIES).sort().map((n) => '<option value="' + esc(n) + '">').join("") + '</datalist><datalist id="' + P + '-vendors"></datalist>' +
      '<div class="' + P + '-row"><button class="' + P + '-btn" id="' + P + '-f-addtr" type="button">Add transfer</button></div>' +
      "<h3>Retention and security</h3><div class=\"" + P + '-grid">' +
      field("f-retention", "Retention period", '<input type="text" id="' + P + '-f-retention" placeholder="e.g. 6 years">', "A number and unit (days, weeks, months, years) so the overdue check can run.") +
      field("f-retentionTrigger", "Retention starts at", '<input type="text" id="' + P + '-f-retentionTrigger" placeholder="e.g. end of contract">') +
      field("f-oldestRecord", "Oldest record held", '<input type="date" id="' + P + '-f-oldestRecord">', "Date of the oldest record (or trigger) still held.") +
      field("f-securityMeasures", "Security measures (Art. 32)", '<textarea id="' + P + '-f-securityMeasures" placeholder="Access control, encryption, logging"></textarea>', "", true) +
      "</div><h3>DPIA</h3>" + '<p class="' + P + '-help">Tick the WP248 criteria that apply. Sensitive data and vulnerable data subjects are derived from the categories and subjects above.</p>' + checks("f-crit", manual) +
      '<p class="' + P + '-help" id="' + P + '-f-scr" style="margin-top:6px"></p><div class="' + P + '-grid" style="margin-top:8px">' +
      field("f-dpiaStatus", "DPIA status", sel("f-dpiaStatus", DPIA_STATUSES, "Not recorded")) +
      field("f-dpiaDate", "DPIA date", '<input type="date" id="' + P + '-f-dpiaDate">') +
      field("f-dpiaRef", "DPIA reference", '<input type="text" id="' + P + '-f-dpiaRef" placeholder="Reference or link">') +
      field("f-subjectCount", "Approx. data subjects", '<input type="text" id="' + P + '-f-subjectCount" placeholder="Optional">', "Context for the large-scale criterion; tick it above if it applies.") +
      "</div><h3>Review</h3><div class=\"" + P + '-grid">' +
      field("f-lastReview", "Last review", '<input type="date" id="' + P + '-f-lastReview">') +
      field("f-notes", "Notes", '<textarea id="' + P + '-f-notes" placeholder="Notes"></textarea>', "", true) +
      '</div><p class="' + P + '-help bad" id="' + P + '-f-err"></p>' +
      '<div class="' + P + '-row"><button class="' + P + '-btn pri" id="' + P + '-f-save" type="button">Save activity</button><button class="' + P + '-btn" id="' + P + '-f-cancel" type="button">Cancel</button></div>';
    const set = (id, v) => { $("f-" + id).value = v == null ? "" : v; };
    ["name", "role", "owner", "controllerName", "jointController", "purpose", "legalBasis", "liaRef", "art9Condition", "criminalBasis", "retention", "retentionTrigger", "oldestRecord", "securityMeasures", "dpiaStatus", "dpiaDate", "dpiaRef", "subjectCount", "lastReview", "notes"].forEach((k) => set(k, r[k]));
    set("systems", r.systems.join("\n")); set("recipients", r.recipients.join("\n"));
    const knownS = new Set(SUBJECTS.map((s) => s.id)), knownC = new Set(CATEGORIES.map((c) => c.id));
    $("f-subjects").querySelectorAll("input").forEach((i) => { i.checked = r.dataSubjects.includes(i.value); });
    set("subjOther", r.dataSubjects.filter((s) => !knownS.has(s)).join("; "));
    main.querySelectorAll("#" + P + "-f-catGen input, #" + P + "-f-catSp input").forEach((i) => { i.checked = r.dataCategories.includes(i.value); });
    set("catOther", r.dataCategories.filter((c) => !knownC.has(c)).join("; "));
    $("f-crit").querySelectorAll("input").forEach((i) => { i.checked = r.dpiaCriteria.includes(i.value); });
    const uses = { ...r.categoryUses };
    const renderUses = () => {
      $("f-uses").querySelectorAll("input[data-cat]").forEach((i) => { uses[i.dataset.cat] = i.value; });
      const cats = selectedCats();
      $("f-uses").innerHTML = cats.length ? cats.map((c) => "<tr><td>" + esc(categoryLabel(c)) + '</td><td><input type="text" data-cat="' + esc(c) + '" placeholder="Purpose it serves" aria-label="Use of ' + esc(categoryLabel(c)) + '" value="' + esc(uses[c] || "") + '"></td></tr>').join("") : '<tr><td colspan="2" class="' + P + '-mut">Tick categories above.</td></tr>';
    };
    const renderScr = () => {
      const s = screenDpia(readForm());
      $("f-scr").textContent = "Screening: " + s.count + " of 9 criteria met" + (s.likely ? ", DPIA likely required." : ".") + (s.criteria.filter((c) => c.met && c.source === "derived").length ? " Derived: " + s.criteria.filter((c) => c.met && c.source === "derived").map((c) => c.why).join("; ") + "." : "");
    };
    renderUses(); r.transfers.forEach(trRow); renderScr();
    f.onchange = (e) => { if (e.target.closest("#" + P + "-f-catGen, #" + P + "-f-catSp") || e.target.id === P + "-f-catOther") renderUses(); renderScr(); };
    $("f-addtr").addEventListener("click", () => trRow({}));
    $("f-cancel").addEventListener("click", closeForm);
    $("f-save").addEventListener("click", () => saveForm(uses));
    $("f-scan").addEventListener("click", () => {
      const found = suggestCategories($("f-sample").value);
      if (!found.length) { $("f-scanout").textContent = "No personal-data patterns detected in the sample."; return; }
      for (const s of found) { const i = main.querySelector('#' + P + '-f-catGen input[value="' + s.category + '"]'); if (i) i.checked = true; }
      $("f-scanout").textContent = "Ticked: " + found.map((s) => s.label + " (" + s.count + ", e.g. " + s.examples[0] + ")").join("; ");
      $("f-sample").value = "";
      renderUses(); renderScr();
    });
    $("f-addsys").addEventListener("change", (e) => { if (e.target.value) { appendLine("f-systems", e.target.value); e.target.value = ""; } });
    $("f-addven").addEventListener("change", (e) => { if (e.target.value) { appendLine("f-recipients", e.target.value); e.target.value = ""; } });
    fillPickers();
    f.scrollIntoView({ behavior: "smooth", block: "start" });
    $("f-name").focus();
  }
  function appendLine(id, v) { const t = $(id); const cur = t.value.split("\n").map((x) => x.trim()).filter(Boolean); if (!cur.includes(v)) cur.push(v); t.value = cur.join("\n"); }
  function selectedCats() {
    const ticked = [...main.querySelectorAll("#" + P + "-f-catGen input:checked, #" + P + "-f-catSp input:checked")].map((i) => i.value);
    return ticked.concat(($("f-catOther").value || "").split(";").map((x) => x.trim()).filter(Boolean));
  }
  function trRow(t) {
    const tr = document.createElement("tr");
    const c = t.country && COUNTRIES[t.country] ? COUNTRIES[t.country] : t.country === "EU" ? "EU/EEA" : t.country || "";
    tr.innerHTML = '<td><input type="text" data-k="country" list="' + P + '-countries" placeholder="Country" aria-label="Destination country" value="' + esc(c) + '"></td>' +
      '<td><input type="text" data-k="recipient" list="' + P + '-vendors" placeholder="Recipient" aria-label="Recipient" value="' + esc(t.recipient || "") + '"></td>' +
      '<td><select data-k="mechanism" aria-label="Transfer mechanism"><option value="">Not recorded</option>' + MECHANISMS.map((m) => '<option value="' + m.id + '"' + (m.id === t.mechanism ? " selected" : "") + ">" + esc(m.label) + "</option>").join("") + "</select></td>" +
      '<td><select data-k="dpfCertified" aria-label="DPF certified"><option value="">Unknown</option><option value="yes"' + (t.dpfCertified === "yes" ? " selected" : "") + '>Yes</option><option value="no"' + (t.dpfCertified === "no" ? " selected" : "") + ">No</option></select></td>" +
      '<td><label class="' + P + '-chk"><input type="checkbox" data-k="tia"' + (t.tia ? " checked" : "") + '>yes</label></td><td><button class="' + P + '-btn" type="button">Remove</button></td>';
    tr.querySelector("button").addEventListener("click", () => tr.remove());
    $("f-tr").appendChild(tr);
  }
  async function fillPickers() {
    await loadCandidates();
    const s = $("f-addsys"), v = $("f-addven");
    if (!s || !v) return;
    s.innerHTML = '<option value="">' + (knownAssets.length ? "Add an asset from the Security Graph" : "No ASSET entities in the Security Graph") + "</option>" + knownAssets.map((n) => '<option value="' + esc(n) + '">' + esc(n) + "</option>").join("");
    const vs = knownVendors || [];
    v.innerHTML = '<option value="">' + (vs.length ? "Add a vendor from the register" : "No vendors in the register or graph") + "</option>" + vs.map((n) => '<option value="' + esc(n) + '">' + esc(n) + "</option>").join("");
    $("vendors").innerHTML = vs.map((n) => '<option value="' + esc(n) + '">').join("");
  }
  function readForm() {
    const v = (id) => ($("f-" + id).value || "").trim();
    const subs = [...$("f-subjects").querySelectorAll("input:checked")].map((i) => i.value).concat(v("subjOther").split(";").map((x) => x.trim()).filter(Boolean));
    const transfers = [...$("f-tr").querySelectorAll("tr")].map((tr) => {
      const g = (k) => tr.querySelector('[data-k="' + k + '"]');
      return { country: g("country").value.trim(), recipient: g("recipient").value.trim(), mechanism: g("mechanism").value, dpfCertified: g("dpfCertified").value, tia: g("tia").checked };
    }).filter((t) => t.country || t.recipient);
    return {
      ...editing, name: v("name"), role: v("role"), owner: v("owner"), controllerName: v("controllerName"), jointController: v("jointController"), purpose: v("purpose"),
      dataSubjects: subs, dataCategories: selectedCats(), legalBasis: v("legalBasis"), liaRef: v("liaRef"), art9Condition: v("art9Condition"), criminalBasis: v("criminalBasis"),
      systems: v("systems").split("\n").map((x) => x.trim()).filter(Boolean), recipients: v("recipients").split("\n").map((x) => x.trim()).filter(Boolean), transfers,
      retention: v("retention"), retentionTrigger: v("retentionTrigger"), oldestRecord: v("oldestRecord"), securityMeasures: v("securityMeasures"),
      dpiaCriteria: [...$("f-crit").querySelectorAll("input:checked")].map((i) => i.value), dpiaStatus: v("dpiaStatus"), dpiaDate: v("dpiaDate"), dpiaRef: v("dpiaRef"),
      subjectCount: v("subjectCount"), lastReview: v("lastReview"), notes: v("notes"),
    };
  }
  function saveForm(uses) {
    $("f-uses").querySelectorAll("input[data-cat]").forEach((i) => { uses[i.dataset.cat] = i.value.trim(); });
    const raw = readForm();
    const cats = new Set(raw.dataCategories);
    raw.categoryUses = Object.fromEntries(Object.entries(uses).filter(([k, val]) => cats.has(k) && val));
    const errs = validateActivity(raw);
    $("f-err").textContent = errs.join(" ");
    if (errs.length) return;
    const rec = normalizeActivity(raw);
    if (editing.id) rec.id = editing.id; else delete rec.id;
    if (editing.graphId) rec.graphId = editing.graphId;
    if (editing.createdAt) rec.createdAt = editing.createdAt;
    const saved = reg.upsert(rec);
    selId = saved.id; closeForm(); schedule();
    toast("Activity saved", "success");
  }
  async function deleteAct(rec) {
    if (example) { toast("Close the synthetic example to edit real records.", "warning"); return; }
    const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Delete activity?", "This removes \"" + (rec.name || "Unnamed") + "\" from the register and the Security Graph.", { danger: true }) : false;
    if (!ok) return;
    reg.remove(rec.id); selId = null; $("detail").classList.add(P + "-hide"); schedule();
    toast("Activity deleted", "success");
  }
  async function loadCandidates() {
    const assets = new Set(), vendors = new Set();
    let gotVendors = false;
    try {
      const vr = openRegister("vendorrisk", "VENDOR", {});
      for (const r of vr.list()) if (r && r.legalName) vendors.add(String(r.legalName));
      gotVendors = true;
    } catch (_) {}
    try {
      const sg = await import("/js/security-graph.js");
      for (const e of sg.listEntities({ type: "ASSET" }) || []) if (e && e.name) assets.add(e.name);
      for (const e of sg.listEntities({ type: "VENDOR" }) || []) if (e && e.name) vendors.add(e.name);
      gotVendors = true;
    } catch (_) {}
    knownAssets = [...assets].sort((a, b) => a.localeCompare(b));
    knownVendors = gotVendors ? [...vendors].sort((a, b) => a.localeCompare(b)) : null;
  }

  // ---- DSAR list and form ----------------------------------------------------------
  const DSORT = { reference: (d) => d.reference, type: (d) => d.type, received: (d) => d.received, due: (d) => d.due || "9999", status: (d) => d.status, completed: (d) => d.completed || "9999" };
  function renderDsarList() {
    const box = $("dlist");
    const list = result.tables.dsars.slice();
    if (!list.length) { box.innerHTML = '<div class="' + P + '-empty">No requests logged yet.</div>'; return; }
    const f = DSORT[dSort.key];
    list.sort((a, b) => { const p = f(a), q = f(b); return (p < q ? -1 : p > q ? 1 : 0) * (dSort.asc ? 1 : -1) || a.reference.localeCompare(b.reference); });
    const th = (k, l) => '<th data-sort="' + k + '"' + (dSort.key === k ? ' class="sorted' + (dSort.asc ? " asc" : "") + '"' : "") + ">" + l + "</th>";
    box.innerHTML = "<table><thead><tr>" + th("reference", "Reference") + th("type", "Type") + th("received", "Received") + th("due", "Due") + th("status", "Status") + th("completed", "Completed") + "</tr></thead><tbody>" +
      list.map((d) => '<tr class="' + P + '-click" data-id="' + esc(d.id) + '"><td><b>' + esc(d.reference) + "</b></td><td>" + esc(d.type) + ' <span class="' + P + '-mut">' + esc(d.article) + "</span></td><td>" + esc(d.received) +
        (d.clockStart && d.clockStart !== d.received ? '<div class="' + P + '-mut">clock from ' + esc(d.clockStart) + "</div>" : "") + "</td><td>" + esc(d.due) + (d.extended ? '<div class="' + P + '-mut">extended</div>' : "") + "</td><td>" + stPill(d.status) +
        (d.daysLeft != null ? '<div class="' + P + '-mut">' + (d.daysLeft < 0 ? -d.daysLeft + " day(s) over" : d.daysLeft + " day(s) left") + "</div>" : "") + "</td><td>" + esc(d.completed || "-") +
        (d.daysToComplete != null ? '<div class="' + P + '-mut">' + d.daysToComplete + " day(s)</div>" : "") + "</td></tr>").join("") + "</tbody></table>";
    box.querySelectorAll("th[data-sort]").forEach((h) => h.addEventListener("click", () => { const k = h.dataset.sort; dSort = { key: k, asc: dSort.key === k ? !dSort.asc : true }; renderDsarList(); }));
    box.querySelectorAll("tr[data-id]").forEach((tr) => tr.addEventListener("click", () => openDForm(dsars().find((x) => x.id === tr.dataset.id))));
  }
  function closeDForm() { dEditing = null; $("dform").classList.add(P + "-hide"); }
  function openDForm(rec) {
    if (example) { toast("Close the synthetic example to add or edit real records.", "warning"); return; }
    dEditing = rec ? { ...rec } : {};
    const r = normalizeDsar(dEditing);
    const f = $("dform");
    f.classList.remove(P + "-hide");
    f.innerHTML = "<h2>" + (rec ? "Edit request " + esc(r.ref) : "New request") + '</h2><div class="' + P + '-grid">' +
      field("d-ref", "Reference", '<input type="text" id="' + P + '-d-ref" placeholder="Ticket number">', "Never the requester's name or email.") +
      field("d-type", "Request type", sel("d-type", DSAR_TYPES.map((t) => ({ id: t.id, label: t.label + " (" + t.article.replace("Art.", "Art. ") + ")" })), "Not set")) +
      field("d-received", "Received", '<input type="date" id="' + P + '-d-received">') +
      field("d-identityVerified", "Identity verified", '<input type="date" id="' + P + '-d-identityVerified">') +
      field("d-extensionNotified", "Extension notified", '<input type="date" id="' + P + '-d-extensionNotified">', "When the requester was told, with reasons.") +
      field("d-completed", "Completed", '<input type="date" id="' + P + '-d-completed">') +
      field("d-owner", "Owner", '<input type="text" id="' + P + '-d-owner" placeholder="Handler">') +
      field("d-notes", "Notes", '<textarea id="' + P + '-d-notes" placeholder="No personal data"></textarea>', "", true) +
      '</div><div class="' + P + '-checks" style="margin-top:10px"><label class="' + P + '-chk"><input type="checkbox" id="' + P + '-d-extended">Extension taken (two further months)</label></div>' +
      '<p class="' + P + '-help" id="' + P + '-d-due" style="margin-top:8px"></p><p class="' + P + '-help bad" id="' + P + '-d-err"></p>' +
      '<div class="' + P + '-row"><button class="' + P + '-btn pri" id="' + P + '-d-save" type="button">Save request</button>' + (rec ? '<button class="' + P + '-btn" id="' + P + '-d-done" type="button">Mark completed today</button><button class="' + P + '-btn dang" id="' + P + '-d-del" type="button">Delete</button>' : "") +
      '<button class="' + P + '-btn" id="' + P + '-d-cancel" type="button">Cancel</button></div>';
    for (const k of ["ref", "type", "received", "identityVerified", "extensionNotified", "completed", "owner", "notes"]) $("d-" + k).value = r[k] || "";
    $("d-extended").checked = r.extended;
    const showDue = () => {
      const x = readD(), dd = dsarDue(x, { clockStart: settings.clockStart, rollWeekends: settings.rollWeekends });
      $("d-due").textContent = dd.due ? "Due " + dd.due + (x.extended ? " (extended; one-month mark " + dd.baseDue + ")" : "; with an extension it would be " + dd.extendedDue + ", notified by " + dd.baseDue) + ". Verify with counsel." : "Enter the received date to compute the deadline.";
    };
    f.oninput = showDue; f.onchange = showDue; showDue();
    $("d-cancel").addEventListener("click", closeDForm);
    $("d-save").addEventListener("click", () => saveD());
    if (rec) {
      $("d-done").addEventListener("click", () => { $("d-completed").value = today(); saveD(); });
      $("d-del").addEventListener("click", async () => {
        const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Delete request?", "This removes " + (r.ref || "this request") + " from the DSAR log and the Security Graph.", { danger: true }) : false;
        if (!ok) return;
        dreg.remove(rec.id); closeDForm(); schedule(); toast("Request deleted", "success");
      });
    }
    f.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  function readD() {
    const v = (k) => ($("d-" + k).value || "").trim();
    return { ...dEditing, ref: v("ref"), type: v("type"), received: v("received"), identityVerified: v("identityVerified"), extended: $("d-extended").checked, extensionNotified: v("extensionNotified"), completed: v("completed"), owner: v("owner"), notes: v("notes") };
  }
  function saveD() {
    const raw = readD();
    const errs = validateDsar(raw);
    $("d-err").textContent = errs.join(" ");
    if (errs.length) return;
    const rec = normalizeDsar(raw);
    if (dEditing.id) rec.id = dEditing.id; else delete rec.id;
    if (dEditing.graphId) rec.graphId = dEditing.graphId;
    if (dEditing.createdAt) rec.createdAt = dEditing.createdAt;
    dreg.upsert(rec); closeDForm(); schedule(); toast("Request saved", "success");
  }
  $("new").addEventListener("click", () => { selId = null; $("detail").classList.add(P + "-hide"); openForm(null); });
  $("dnew").addEventListener("click", () => openDForm(null));

  // ---- findings ----------------------------------------------------------------------
  const FSORT = { severity: (f) => SEV_RANK[f.severity], title: (f) => f.title.toLowerCase(), category: (f) => f.category, confidence: (f) => CONF_RANK[f.confidence], evidence: (f) => -(f.evidenceCount || 0) };
  function findingsHtml(list, attr, sortable) {
    if (!list.length) return '<div class="' + P + '-empty">No findings.</div>';
    const th = (k, l) => (sortable ? '<th data-sort="' + k + '"' + (fSort.key === k ? ' class="sorted' + (fSort.asc ? " asc" : "") + '"' : "") + ">" + l + "</th>" : "<th>" + l + "</th>");
    return '<div class="' + P + '-tbl"><table><thead><tr>' + th("severity", "Severity") + th("title", "Finding") + th("category", "Area") + th("confidence", "Confidence") + "<th>Controls</th>" + th("evidence", "Evidence") + "</tr></thead><tbody>" +
      list.map((f, i) => '<tr class="' + P + '-click" data-' + attr + '="' + i + '"><td>' + sevPill(f.severity) + "</td><td><b>" + esc(f.title) + '</b><div class="' + P + '-mut">' + esc(f.description) + "</div></td><td>" + esc(f.category) + "</td><td>" + esc(f.confidence) + "</td><td>" + chips(f.controls) + "</td><td>" + (f.evidenceCount || 0) + "</td></tr>").join("") + "</tbody></table></div>";
  }
  function renderFindings() {
    const box = $("flist");
    const f = FSORT[fSort.key];
    const list = result.findings.slice().sort((a, b) => { const p = f(a), q = f(b); return (p < q ? -1 : p > q ? 1 : 0) * (fSort.asc ? 1 : -1) || SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.id.localeCompare(b.id); });
    box.innerHTML = result.meta.rows ? findingsHtml(list, "f", true) : '<div class="' + P + '-empty">No activities or requests yet.</div>';
    box.querySelectorAll("th[data-sort]").forEach((h) => h.addEventListener("click", () => { const k = h.dataset.sort; fSort = { key: k, asc: fSort.key === k ? !fSort.asc : true }; renderFindings(); }));
    box.querySelectorAll("tr[data-f]").forEach((tr) => tr.addEventListener("click", () => openDrawer(list[Number(tr.dataset.f)])));
  }
  function openDrawer(f) {
    const d = $("drawer");
    if (!f) { d.style.display = "none"; return; }
    d.innerHTML = '<div class="' + P + '-row" style="margin-top:0;justify-content:space-between"><h2 style="margin:0">' + sevPill(f.severity) + " " + esc(f.title) + '</h2><button class="' + P + '-btn" id="' + P + '-fclose" type="button">Close</button></div>' +
      '<dl class="' + P + '-dl"><dt>Confidence</dt><dd>' + esc(f.confidence) + "</dd><dt>Area</dt><dd>" + esc(f.category) + "</dd><dt>What</dt><dd>" + esc(f.description) + "</dd><dt>Do this</dt><dd>" + esc(f.recommendation) + "</dd>" +
      "<dt>Controls</dt><dd>" + chips(f.controls) + "</dd>" + ((f.assets || []).length ? "<dt>Linked</dt><dd>" + esc(f.assets.map((a) => a.type + ": " + a.name).join(", ")) + "</dd>" : "") + "</dl>" +
      "<h3>Evidence (" + (f.evidenceCount || 0) + ")</h3>" + objTable(f.evidence);
    d.style.display = "block";
    $("fclose").addEventListener("click", () => { d.style.display = "none"; });
    d.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  // ---- exports -----------------------------------------------------------------------
  function renderExports() {
    const ex = $("exports");
    const acts = activities(), ds = dsars();
    const st = () => fileStamp();
    ex.innerHTML = ["ropac|ROPA CSV (controller, Art. 30(1))", "ropap|ROPA CSV (processor, Art. 30(2))", "rjson|Register JSON", "dcsv|DSAR log CSV", "fcsv|Findings CSV", "fjson|Findings JSON", "txt|Summary TXT", "memos|All DPIA screening memos", "ics|Deadlines calendar (.ics)"]
      .map((s) => { const [k, l] = s.split("|"); return '<button class="' + P + '-btn" type="button" data-x="' + k + '">' + l + "</button>"; }).join("");
    const on = (k, need, fn) => ex.querySelector('[data-x="' + k + '"]').addEventListener("click", () => { if (!need()) { toast("Nothing to export yet", "warning"); return; } fn(); });
    const hasA = () => acts.length > 0, hasD = () => ds.length > 0, hasAny = () => acts.length + ds.length > 0;
    on("ropac", hasA, () => download(TOOL_ID + "-ropa-controller-" + st() + ".csv", ropaCsv(acts, { variant: "controller", org: org() }), "text/csv"));
    on("ropap", () => acts.some((a) => a.role === "processor"), () => download(TOOL_ID + "-ropa-processor-" + st() + ".csv", ropaCsv(acts, { variant: "processor", org: org() }), "text/csv"));
    on("rjson", hasAny, () => {
      const strip = (r) => { const c = { ...r }; delete c.graphId; return c; };
      download(TOOL_ID + "-register-" + st() + ".json", toJson({ tool: TOOL_ID, version: VERSION, example: !!example, activities: acts.map(strip), dsars: ds.map(strip) }), "application/json");
    });
    on("dcsv", hasD, () => download(TOOL_ID + "-dsar-log-" + st() + ".csv", dsarCsv(ds, result), "text/csv"));
    on("fcsv", hasAny, () => download(TOOL_ID + "-findings-" + st() + ".csv", findingsToCsv(result.findings), "text/csv"));
    on("fjson", hasAny, () => download(TOOL_ID + "-findings-" + st() + ".json", toJson({ summary: result.summary, findings: result.findings, skipped: result.skipped, meta: result.meta }), "application/json"));
    on("txt", hasAny, () => download(TOOL_ID + "-summary-" + st() + ".txt", summaryText(result, { org: org(), example: !!example }), "text/plain"));
    on("memos", hasA, () => download(TOOL_ID + "-dpia-memos-" + st() + ".txt", acts.slice().sort((a, b) => String(a.name).localeCompare(String(b.name))).map((a) => dpiaMemo(a, { now: nowIso(), org: org(), example: !!example })).join("\n" + "-".repeat(72) + "\n\n"), "text/plain"));
    on("ics", hasAny, () => {
      const ev = icsEvents({ activities: acts, dsars: ds }, { now: nowIso(), reviewMonths: settings.thresholds.reviewMonths, dpiaReviewMonths: settings.thresholds.dpiaReviewMonths, clockStart: settings.clockStart, rollWeekends: settings.rollWeekends, example: !!example });
      if (!ev.length) { toast("No deadlines to export", "warning"); return; }
      download(TOOL_ID + "-deadlines-" + st() + ".ics", toIcs(ev), "text/calendar");
    });
    attachSinkButton(ex, () => ({ findings: result ? result.findings : [], sample: !!example }), TOOL_ID, { dataset: example ? "synthetic example" : "processing register" });
    const note = document.createElement("p");
    note.className = P + "-help"; note.style.width = "100%";
    note.textContent = "Saved activities and requests are already mirrored as CONTROL and CASE entities. The graph button adds one FINDING per finding, linked to its ASSET (systems) and VENDOR (recipients) entities.";
    ex.appendChild(note);
  }

  // ---- example -----------------------------------------------------------------------
  $("example").addEventListener("click", () => {
    example = exampleDataset();
    selId = null; closeForm(); closeDForm(); $("detail").classList.add(P + "-hide");
    schedule();
    toast("Loaded synthetic example: Larkspur Cloudworks (fictional)", "info");
  });

  // ---- import ------------------------------------------------------------------------
  mountDropzone($("drop"), {
    maxBytes: 20 << 20, maxFiles: 5, unpack: true, accept: ".json,.csv,.tsv,.txt",
    label: "Drop a register JSON, a ROPA CSV or a DSAR log CSV",
    onFiles: async (files) => {
      const parsed = parseInput(await Promise.all(files.map(async (f) => ({ name: f.name, text: await f.text() }))));
      for (const s of parsed.skipped) toast(s.check + ": " + s.reason, "warning");
      imported = parsed;
      renderImport();
    },
  });
  function renderImport() {
    const p = imported;
    const det = $("detected"), map = $("mapping");
    if (!p || !p.files.length) { det.innerHTML = '<p class="' + P + '-help bad" style="margin-top:8px">Nothing importable found.</p>'; map.innerHTML = ""; return; }
    det.innerHTML = '<div class="' + P + '-tbl" style="margin-top:10px"><table><thead><tr><th>File</th><th>Detected format</th><th>Confidence</th><th>Rows</th></tr></thead><tbody>' +
      p.files.map((f) => "<tr><td>" + esc(f.name) + "</td><td>" + esc(f.format) + "</td><td>" + esc(f.confidence) + "</td><td>" + f.count + "</td></tr>").join("") + "</tbody></table></div>";
    map.innerHTML = "";
    if (p.activities.length || p.dsars.length) {
      const div = document.createElement("div");
      div.className = P + "-row";
      div.innerHTML = '<button class="' + P + '-btn pri" type="button">Import ' + p.activities.length + " activit" + (p.activities.length === 1 ? "y" : "ies") + " and " + p.dsars.length + " request(s)</button><span class=\"" + P + '-mut">Records with an ID already in the register are updated.</span>';
      div.querySelector("button").addEventListener("click", () => {
        if (example) { toast("Close the synthetic example first.", "warning"); return; }
        const a = reg.importJson(p.activities.map((x) => ({ ...x }))), d = dreg.importJson(p.dsars.map((x) => ({ ...x })));
        toast("Imported: " + (a.added + d.added) + " added, " + (a.updated + d.updated) + " updated", "success");
        imported = null; det.innerHTML = ""; map.innerHTML = ""; schedule();
      });
      map.appendChild(div);
    }
    p.files.filter((f) => f.rows).forEach((file) => map.appendChild(mappingPanel(file)));
  }
  function mappingPanel(file) {
    const box = document.createElement("div");
    box.className = P + "-card";
    box.style.marginTop = "12px";
    let kind = file.kind;
    const uid = ++panelSeq;
    let mapping = { ...file.mapping };
    const draw = () => {
      const spec = kind === "dsar" ? DSAR_COLUMNS : COLUMNS, labels = kind === "dsar" ? DSAR_COLUMN_LABELS : COLUMN_LABELS;
      const opt = (k, u) => '<select id="' + P + '-m-' + u + '-' + k + '" data-map="' + k + '" aria-label="' + esc(labels[k] || k) + '"><option value="">Not in file</option>' + file.headers.map((h) => '<option value="' + esc(h) + '"' + (mapping[k] === h ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select>";
      box.innerHTML = "<h3>" + esc(file.name) + (file.confidence === "high" ? "" : ' <span style="color:#b58100">(check the mapping: confidence ' + esc(file.confidence) + ")</span>") + "</h3>" +
        '<div class="' + P + '-grid">' + field("k-" + uid, "This file contains", '<select id="' + P + '-k-' + uid + '" data-kind><option value="activities"' + (kind === "activities" ? " selected" : "") + '>Processing activities</option><option value="dsar"' + (kind === "dsar" ? " selected" : "") + ">DSAR log</option></select>") +
        field("o-" + uid, "Date format", '<select id="' + P + '-o-' + uid + '" data-order><option value="dmy">Day/month/year</option><option value="mdy">Month/day/year</option></select>', file.dateOrder === "ambiguous" ? "Dates in this file could be either order; check before importing." : "Detected: " + (file.dateOrder === "mdy" ? "month/day/year" : "day/month/year") + ". ISO dates are always read correctly.") + "</div>" +
        '<div class="' + P + '-grid" style="margin-top:10px">' + Object.keys(spec).map((k) => field("m-" + uid + "-" + k, labels[k] || k, opt(k, uid))).join("") + "</div>" +
        '<p class="' + P + '-help" style="margin-top:6px">Lists may be separated by ; | or commas. Lawful basis, Art. 9 condition and transfer mechanism are read from text such as "Art 6(1)(f)", "legitimate interests" or "SCCs"; anything unrecognised is left blank, never guessed.</p>' +
        '<div class="' + P + '-row"><button class="' + P + '-btn pri" type="button" data-imp>Import ' + file.rows.length + ' row(s)</button><span class="' + P + '-mut" data-note></span></div>';
      box.querySelector("[data-order]").value = file.dateOrder === "mdy" ? "mdy" : "dmy";
      box.querySelector("[data-kind]").addEventListener("change", (e) => { kind = e.target.value; mapping = { ...(kind === "dsar" ? autoMapDsars(file.headers) : autoMapActivities(file.headers)).mapping }; draw(); });
      box.querySelectorAll("[data-map]").forEach((s) => s.addEventListener("change", () => { if (s.value) mapping[s.dataset.map] = s.value; else delete mapping[s.dataset.map]; }));
      box.querySelector("[data-imp]").addEventListener("click", () => {
        if (example) { toast("Close the synthetic example first.", "warning"); return; }
        const order = box.querySelector("[data-order]").value;
        if (kind === "dsar" && !mapping.received) { toast("Map the received-date column first", "warning"); return; }
        if (kind !== "dsar" && !mapping.name && !mapping.purpose) { toast("Map the activity name or purpose column first", "warning"); return; }
        const { records, skipped } = kind === "dsar" ? csvToDsars(file.rows, mapping, { dateOrder: order }) : csvToActivities(file.rows, mapping, { dateOrder: order });
        const r = kind === "dsar" ? dreg : reg;
        for (const rec of records) r.upsert(rec);
        toast("Imported " + records.length + (kind === "dsar" ? " request(s)" : " activit" + (records.length === 1 ? "y" : "ies")) + (skipped.length ? "; " + skipped.length + " note(s)" : ""), skipped.length ? "warning" : "success");
        box.querySelector("[data-note]").textContent = skipped.map((s) => s.check + ": " + s.reason).join("; ");
        schedule();
      });
    };
    draw();
    return box;
  }

  // ---- boot --------------------------------------------------------------------------
  fillSettings();
  fetch("/data/ref/eu-adequacy.json", { cache: "no-cache" }).then((r) => (r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status))))
    .then((j) => { adequacy = j; schedule(); })
    .catch((e) => { adequacyErr = String(e && e.message || e); schedule(); });
  loadCandidates().then(() => schedule()).catch(() => {});
  reg.subscribe(() => { if (!example) schedule(); });
  dreg.subscribe(() => { if (!example) schedule(); });
  Promise.all([reg.ready, dreg.ready]).then(() => Promise.all([reg.backfill(), dreg.backfill()])).then(() => schedule()).catch(() => {});
  schedule();
}
