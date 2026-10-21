// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Third-Party Risk (vendorrisk): Deck tool UI. A team-shareable vendor register
// (core/register.js, mirrored to the Security Graph as VENDOR entities) combined
// with LIVE external posture checks of each vendor's domains. All fetching lives
// here and runs only when the user presses "Check now" / "Check all"; all parsing
// and grading is in the pure engine (vendorrisk-engine.js, run in a Worker).
// No native dialogs; toasts and window.dnConfirm only.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { openRegister, wsKey } from "../core/register.js";
import { download, toJson, fileStamp, toIcs } from "../core/export.js";
import { dnFetch, dnFetchJSON, proxyConfigured } from "../net.js";
import { fetchCertRows } from "../dataprotect/ct-fetch.js";
import {
  DEFAULTS, TOOL_ID, DEFAULT_POLICY, THRESHOLD_LABELS, DATA_TIERS, DATA_TYPES, SYSTEM_ACCESS, INTEGRATIONS, CRITICALITY, DOC_TYPES, BANDS, CHECKS,
  REGISTER_SCHEMA, COLUMNS, COLUMN_LABELS, parseInput, analyze, findingsToCsv, exampleDataset, normalizeRecord, validateRecord, addHistory,
  gradeDomain, makeSnapshot, addSnapshot, diffSnapshots, registerToCsv, icsEvents, onePager, matchPayees, daysUntil, docLabel, csvToRecords,
  registrableGuess, leakResponse, mergePolicy, cleanDomain,
} from "./vendorrisk-engine.js?v=20261021a";

const ENGINE = engineUrl("./vendorrisk-engine.js?v=20261021a", import.meta);
const P = "tpr";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const lbl = (list, id) => (list.find((x) => x.id === id) || { label: id || "" }).label;
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const BAND_C = { low: "#1b7f4d", medium: "#b58100", high: "#c0501b", critical: "#b00020" };
const GRADE_C = { A: "#1b7f4d", B: "#4c8a2a", C: "#b58100", D: "#c0501b", F: "#b00020", "N/A": "#667085" };
const ST_C = { pass: "#1b7f4d", warn: "#b58100", fail: "#b00020", error: "#6b4fa0", skip: "#667085", info: "#2552c6" };
const LEAK_GAP_MS = 61000;

const CSS = `
  .tpr-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .tpr-root *{box-sizing:border-box}
  .tpr-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .tpr-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .tpr-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--mut,#667085);border:1px solid var(--line,#e6e8ee);padding:2px 9px;border-radius:999px}
  .tpr-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:110ch;overflow-wrap:anywhere}
  .tpr-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .tpr-card h2{font-size:1.02rem;margin:0 0 4px}
  .tpr-card h3{font-size:.8rem;margin:14px 0 6px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#667085)}
  .tpr-row{display:flex;flex-wrap:wrap;gap:8px 10px;align-items:center;margin-top:10px}
  .tpr-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:7px 13px;border-radius:8px;cursor:pointer}
  .tpr-btn:hover{border-color:var(--mut,#667085)}
  .tpr-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .tpr-btn.dang{color:#b00020}
  .tpr-btn:disabled{opacity:.5;cursor:default}
  .tpr-tabs{display:flex;flex-wrap:wrap;gap:4px;border-bottom:1px solid var(--line,#e6e8ee);margin-bottom:12px}
  .tpr-tab{appearance:none;font:inherit;font-size:.86rem;font-weight:600;background:none;border:1px solid transparent;border-bottom:none;color:var(--mut,#667085);padding:7px 13px;border-radius:8px 8px 0 0;cursor:pointer;margin-bottom:-1px}
  .tpr-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#e6e8ee);background:var(--card,#fff)}
  .tpr-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px 16px}
  .tpr-field{display:flex;flex-direction:column;gap:3px;min-width:0}
  .tpr-field.wide{grid-column:1/-1}
  .tpr-field>label,.tpr-lbl{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .tpr-root input[type=text],.tpr-root input[type=number],.tpr-root input[type=date],.tpr-root select,.tpr-root textarea{font:inherit;font-size:.86rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%;min-width:0}
  .tpr-root textarea{min-height:64px;resize:vertical}
  .tpr-help{font-size:.75rem;color:var(--mut,#667085);margin:0;overflow-wrap:anywhere}
  .tpr-help.bad{color:#b00020}
  .tpr-checks{display:flex;flex-wrap:wrap;gap:6px}
  .tpr-chk{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line,#d7dbe3);border-radius:999px;padding:4px 11px;font-size:.8rem;cursor:pointer;user-select:none;background:var(--card,#fff);max-width:100%}
  .tpr-chk input{margin:0}
  .tpr-tbl{border:1px solid var(--line,#e6e8ee);border-radius:10px;overflow:auto;max-width:100%}
  .tpr-tbl table{width:100%;border-collapse:collapse;font-size:.84rem}
  .tpr-tbl th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 10px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .tpr-tbl th[data-sort]{cursor:pointer;user-select:none}
  .tpr-tbl th.sorted::after{content:" \\2193"}
  .tpr-tbl th.sorted.asc::after{content:" \\2191"}
  .tpr-tbl td{padding:8px 10px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .tpr-tbl tr.tpr-click{cursor:pointer}
  .tpr-tbl tr.tpr-click:hover td{background:var(--bg,#f7f8fb)}
  .tpr-tbl tr.sel td{background:var(--bg,#f2f4f8)}
  .tpr-tbl td input,.tpr-tbl td select{padding:4px 6px;font-size:.8rem}
  .tpr-pill{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .tpr-pill.critical{background:#7a0012}.tpr-pill.high{background:#b00020}.tpr-pill.medium{background:#b58100}.tpr-pill.low{background:#2552c6}.tpr-pill.info{background:#667085}
  .tpr-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .tpr-grade{display:inline-block;min-width:26px;text-align:center;font-weight:800;border-radius:6px;padding:0 6px;color:#fff}
  .tpr-band{font-weight:700}
  .tpr-mut{color:var(--mut,#667085);font-size:.78rem}
  .tpr-mono{font-family:ui-monospace,Menlo,monospace;font-size:.78rem;overflow-wrap:anywhere}
  .tpr-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin:0 0 14px}
  .tpr-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .tpr-kpi b{display:block;font-size:1.3rem;line-height:1.25}
  .tpr-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .tpr-kpi.alert b{color:#b00020}
  .tpr-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin:0 0 6px;display:none}
  .tpr-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .tpr-status{font-size:.8rem;color:var(--mut,#667085);margin-bottom:10px;overflow-wrap:anywhere}
  .tpr-note{border:1px solid var(--line,#e6e8ee);border-left:4px solid #b58100;border-radius:8px;padding:8px 12px;margin:0 0 12px;background:var(--card,#fff);font-size:.84rem}
  .tpr-dl{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;margin:6px 0;font-size:.84rem}
  .tpr-dl dt{color:var(--mut,#667085)}
  .tpr-dl dd{margin:0;overflow-wrap:anywhere}
  .tpr-svg{width:100%;height:auto;display:block;border:1px solid var(--line,#e6e8ee);border-radius:8px;background:var(--bg,#f7f8fb)}
  .tpr-cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
  .tpr-empty{padding:22px;text-align:center;color:var(--mut,#667085)}
  .tpr-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px;overflow-wrap:anywhere}
  .tpr-drawer{display:none}
  .tpr-hide{display:none}
  .tpr-root details summary{cursor:pointer;font-size:.82rem;color:var(--mut,#667085);margin-top:8px}
  .tpr-pts td input{width:80px}
  @media(max-width:600px){.tpr-card{padding:12px}.tpr-dl{grid-template-columns:1fr}.tpr-dl dt{margin-top:6px}}
`;

const kpi = (v, l, alert) => '<div class="' + P + "-kpi" + (alert ? " alert" : "") + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const field = (id, label, input, help, wide) => '<div class="' + P + "-field" + (wide ? " wide" : "") + '"><label for="' + P + "-" + id + '">' + esc(label) + "</label>" + input + (help ? '<p class="' + P + '-help">' + esc(help) + "</p>" : "") + "</div>";
const sel = (id, list, blank) => '<select id="' + P + "-" + id + '">' + (blank ? '<option value="">' + esc(blank) + "</option>" : "") + list.map((x) => '<option value="' + esc(x.id) + '">' + esc(x.label) + "</option>").join("") + "</select>";
const checks = (id, list) => '<div class="' + P + '-checks" id="' + P + "-" + id + '">' + list.map((x) => '<label class="' + P + '-chk"><input type="checkbox" value="' + esc(x.id) + '">' + esc(x.label) + "</label>").join("") + "</div>";
const gradePill = (g) => '<span class="' + P + '-grade" style="background:' + (GRADE_C[g] || "#667085") + '">' + esc(g || "N/A") + "</span>";
const bandTxt = (b, s) => (b ? '<span class="' + P + '-band" style="color:' + BAND_C[b] + '">' + esc(s != null ? s + " " : "") + esc(b) + "</span>" : '<span class="' + P + '-mut">-</span>');
const stPill = (s) => '<span class="' + P + '-pill" style="background:' + (ST_C[s] || "#667085") + '">' + esc(s) + "</span>";
const sevPill = (s) => '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>";
const checkLabel = (id) => (CHECKS.find((c) => c.id === id) || { label: id }).label;

/** Generic table of objects (evidence rows). */
function objTable(rows) {
  if (!rows || !rows.length) return '<div class="' + P + '-empty">No rows.</div>';
  const keys = [...new Set(rows.flatMap((r) => Object.keys(r || {})))];
  return '<div class="' + P + '-tbl"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => "<td>" + esc(typeof r[k] === "object" && r[k] !== null ? JSON.stringify(r[k]) : r[k]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

/** Mount the tool into main. */
export function renderVendorRisk(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  const thresholdKeys = Object.keys(THRESHOLD_LABELS);
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Third-Party Risk</h1><span class="', P, '-tag">Vendor register</span></div>',
    '<p class="', P, '-sub">Vendor register with inherent and residual risk, assurance-document expiry and live external posture checks of each vendor\'s domains. Runs entirely in your browser. Nothing is uploaded. ',
    'Live checks run only when you press Check now or Check all, and read: DNS over HTTPS from dns.google and cloudflare-dns.com (direct); certificate transparency from crt.sh and api.certspotter.com; ',
    'the vendor\'s own https://, http://, /.well-known/security.txt and mta-sts. hosts; and registration data from rdap.org (which redirects to the registry), all through the Darknode proxy. ',
    'The optional leak-tracker search queries api.ransomware.live through the same proxy. Saved vendors are mirrored into the Security Graph as VENDOR entities.</p>',
    '<div id="', P, '-exnote"></div>',
    '<div class="', P, '-tabs" id="', P, '-maintabs">',
    ['vendors|Vendors', 'portfolio|Portfolio', 'policy|Policy', 'import|Import'].map((s) => { const [k, l] = s.split("|"); return '<button class="' + P + '-tab' + (k === "vendors" ? " on" : "") + '" data-tab="' + k + '" type="button">' + l + "</button>"; }).join(""),
    "</div>",

    // Vendors pane
    '<div data-pane="vendors">',
    '<div class="', P, '-card"><h2>Vendors</h2><p class="', P, '-help">Saved vendors. In a team workspace every member sees the same register through the Security Graph. Click a vendor for its detail.</p>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-new" type="button">New vendor</button><button class="', P, '-btn" id="', P, '-checkall" type="button">Check all</button>',
    '<button class="', P, '-btn" id="', P, '-example" type="button">Load example (synthetic)</button>',
    '<label class="', P, '-chk"><input type="checkbox" id="', P, '-leakopt">Also search ransomware leak trackers</label></div>',
    '<p class="', P, '-help" style="margin-top:6px">Leak-tracker search is opt-in: it sends the vendor\'s registrable domain to api.ransomware.live (keyless, limited to one query per minute, so checks wait between vendors). Only an exact domain or legal-name match becomes a finding.</p>',
    '<div class="', P, '-tbl" style="margin-top:10px" id="', P, '-vlist"></div></div>',
    '<div class="', P, '-card ', P, '-hide" id="', P, '-detail"></div>',
    '<div class="', P, '-card ', P, '-hide" id="', P, '-form"></div>',
    "</div>",

    // Portfolio pane
    '<div data-pane="portfolio" class="', P, '-hide"><div class="', P, '-card" id="', P, '-portfolio"><div class="', P, '-empty">No vendors yet.</div></div></div>',

    // Policy pane
    '<div data-pane="policy" class="', P, '-hide"><div class="', P, '-card" id="', P, '-policy"></div></div>',

    // Import pane
    '<div data-pane="import" class="', P, '-hide"><div class="', P, '-card"><h2>Import</h2><p class="', P, '-help">Drop a register JSON exported from this tool, or a CSV vendor list (one row per vendor) to bulk-load it. Nothing is saved until you press Import.</p>',
    '<div style="margin-top:10px" id="', P, '-drop"></div><div id="', P, '-detected"></div><div id="', P, '-mapping"></div></div></div>',

    // Thresholds
    '<div class="', P, '-card"><details id="', P, '-thrbox"><summary>Thresholds (', thresholdKeys.length, ')</summary><div class="', P, '-grid" style="margin-top:10px">',
    thresholdKeys.map((k) => field("opt-" + k, THRESHOLD_LABELS[k][0], '<input type="number" min="0" step="1" id="' + P + "-opt-" + k + '" data-opt="' + k + '" value="' + DEFAULTS[k] + '">', THRESHOLD_LABELS[k][1] + " Default " + DEFAULTS[k] + ".")).join(""),
    "</div></details></div>",

    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-status" id="', P, '-status"></div>',
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card"><h2>Findings</h2><div class="', P, '-tbl" id="', P, '-flist"><div class="', P, '-empty">No vendors analysed yet.</div></div><div class="', P, '-skip" id="', P, '-skipped"></div></div>',
    '<div class="', P, '-card ', P, '-drawer" id="', P, '-drawer"></div>',
    '<div class="', P, '-card"><h2>Exports</h2><div class="', P, '-row" id="', P, '-exports" style="margin-top:4px"></div></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  const reg = openRegister(TOOL_ID, "VENDOR", { schema: REGISTER_SCHEMA });
  const POLICY_KEY = () => wsKey("tpr_policy");
  let policy = loadPolicy();
  let example = null; // { records, now } when the synthetic example is loaded
  let result = null, selId = null, detailTab = "profile", vSort = { key: "residual", asc: false }, fSort = { key: "severity", asc: true };
  let editing = null, seq = 0, timer = 0, busy = false, lastLeakAt = 0, csvParsed = null;
  let linkCands = [], graphFindingNames = [];

  function loadPolicy() { try { return mergePolicy(JSON.parse(localStorage.getItem(POLICY_KEY()) || "null") || {}); } catch (_) { return mergePolicy({}); } }
  function savePolicy() { try { localStorage.setItem(POLICY_KEY(), JSON.stringify(policy)); } catch (_) {} }
  const records = () => (example ? example.records : reg.list());
  const nowIso = () => (example ? example.now : new Date().toISOString());
  const opts = () => {
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (Number.isFinite(n) && n >= 0) o[el.dataset.opt] = n; });
    return { ...o, policy, now: nowIso() };
  };
  const graded = (id) => (result ? result.tables.graded.find((g) => g.id === id) : null);

  // ---- tabs -----------------------------------------------------------------------
  $("maintabs").addEventListener("click", (e) => {
    const b = e.target.closest("[data-tab]"); if (!b) return;
    $("maintabs").querySelectorAll("[data-tab]").forEach((x) => x.classList.toggle("on", x === b));
    main.querySelectorAll("[data-pane]").forEach((p) => p.classList.toggle(P + "-hide", p.dataset.pane !== b.dataset.tab));
  });

  // ---- analysis ------------------------------------------------------------------
  function schedule() { clearTimeout(timer); timer = setTimeout(analyzeNow, 150); }
  async function analyzeNow() {
    const my = ++seq;
    const recs = records();
    const prog = $("prog"), bar = prog.firstElementChild;
    if (recs.length > 200) { prog.style.display = "block"; bar.style.width = "5%"; }
    try {
      const r = await runInWorker(ENGINE, "analyze", [{ records: recs }, opts()], { onProgress: (i, n) => { bar.style.width = (n ? Math.round(i / n * 100) : 0) + "%"; } });
      if (my !== seq) return;
      result = r;
    } catch (e) {
      try { if (my === seq) result = analyze({ records: recs }, opts()); } catch (err) { toast("Analysis failed: " + (err && err.message || err), "error"); return; }
    } finally { if (my === seq && !busy) prog.style.display = "none"; }
    renderAll();
  }

  function renderAll() {
    if (!result) return;
    const s = result.summary;
    const sum = summarize(result.findings);
    $("kpis").innerHTML = kpi(s.vendors, "vendors") + kpi(s.critical, "critical vendors") + kpi(s.residualHigh, "high residual", s.residualHigh > 0) +
      kpi(s.docsExpired, "docs expired", s.docsExpired > 0) + kpi(s.docsExpiring, "docs expiring " + (opts().upcomingDays) + "d") + kpi(s.reviewsOverdue, "reviews overdue", s.reviewsOverdue > 0) +
      kpi(s.checked + "/" + s.vendors, "posture checked") + kpi(sum.bySeverity.high + sum.bySeverity.critical, "high findings", sum.bySeverity.high + sum.bySeverity.critical > 0);
    $("exnote").innerHTML = example ? '<div class="' + P + '-note"><b>Synthetic example loaded.</b> Eight fictional vendors on *.test.darknode.ai with precomputed posture snapshots. Nothing is saved, nothing is fetched, and the graph button is disabled. <button class="' + P + '-btn" id="' + P + '-exit" type="button">Close example</button></div>' : "";
    if (example) $("exit").addEventListener("click", () => { example = null; selId = null; closeForm(); schedule(); });
    renderVendorList(); renderFindings(); renderPortfolio(); renderExports();
    $("skipped").textContent = result.skipped.length ? "Not checked: " + result.skipped.map((x) => x.check + " (" + x.reason + ")").join("; ") : "";
    if (selId) renderDetail();
  }

  // ---- vendor list ---------------------------------------------------------------
  const VSORT = {
    legalName: (v) => v.legalName.toLowerCase(), criticality: (v) => BANDS.indexOf(v.criticality), inherent: (v) => v.inherent, residual: (v) => v.residual,
    grade: (v) => (v.postureScore == null ? -1 : v.postureScore), nextReview: (v) => v.nextReview || "0000", docsExpiring: (v) => v.docsExpiring, findings: (v) => v.findings,
  };
  function renderVendorList() {
    const box = $("vlist");
    const list = result.tables.vendors.slice();
    if (!list.length) { box.innerHTML = '<div class="' + P + '-empty">No vendors yet. Add one, import a list, or load the synthetic example.</div>'; return; }
    const f = VSORT[vSort.key];
    list.sort((a, b) => { const p = f(a), q = f(b); return (p < q ? -1 : p > q ? 1 : 0) * (vSort.asc ? 1 : -1) || a.legalName.localeCompare(b.legalName); });
    const th = (k, l) => '<th data-sort="' + k + '"' + (vSort.key === k ? ' class="sorted' + (vSort.asc ? " asc" : "") + '"' : "") + ">" + l + "</th>";
    const now = nowIso();
    box.innerHTML = "<table><thead><tr>" + th("legalName", "Vendor") + th("criticality", "Criticality") + th("inherent", "Inherent") + th("residual", "Residual") + th("grade", "Posture") +
      th("nextReview", "Next review") + th("docsExpiring", "Docs expiring") + th("findings", "Findings") + "</tr></thead><tbody>" +
      list.map((v) => {
        const nd = v.nextReview ? daysUntil(v.nextReview, now) : null;
        return '<tr class="' + P + "-click" + (v.id === selId ? " sel" : "") + '" data-id="' + esc(v.id) + '"><td><b>' + esc(v.legalName) + '</b><div class="' + P + '-mut">' + esc(v.domains || "no domain") + "</div></td>" +
          "<td>" + bandTxt(v.criticality) + "</td><td>" + bandTxt(v.inherentBand, v.inherent) + "</td><td>" + bandTxt(v.residualBand, v.residual) + "</td>" +
          "<td>" + gradePill(v.grade) + (v.trend ? ' <span class="' + P + '-mut">' + esc(v.trend) + "</span>" : "") + '<div class="' + P + '-mut">' + esc(v.lastChecked ? v.lastChecked.slice(0, 10) : "never checked") + "</div></td>" +
          "<td" + (nd != null && nd < 0 ? ' style="color:#b00020;font-weight:700"' : "") + ">" + esc(v.nextReview || (v.criticality ? "never reviewed" : "-")) + "</td><td>" + v.docsExpiring + "</td><td>" + v.findings + "</td></tr>";
      }).join("") + "</tbody></table>";
    box.querySelectorAll("th[data-sort]").forEach((h) => h.addEventListener("click", () => { const k = h.dataset.sort; vSort = { key: k, asc: vSort.key === k ? !vSort.asc : k === "legalName" }; renderVendorList(); }));
    box.querySelectorAll("tr[data-id]").forEach((tr) => tr.addEventListener("click", () => { selId = tr.dataset.id; closeForm(); renderVendorList(); renderDetail(); $("detail").scrollIntoView({ behavior: "smooth", block: "nearest" }); }));
  }

  // ---- detail --------------------------------------------------------------------
  function renderDetail() {
    const box = $("detail");
    const rec = records().find((r) => r.id === selId);
    const g = graded(selId);
    if (!rec || !g) { box.classList.add(P + "-hide"); return; }
    box.classList.remove(P + "-hide");
    const r = normalizeRecord(rec);
    const tabs = ["profile|Profile", "assurance|Assurance", "posture|Posture", "changes|Changes", "findings|Findings (" + g.findings.length + ")"];
    box.innerHTML = '<div class="' + P + '-row" style="margin-top:0;justify-content:space-between"><h2 style="margin:0">' + esc(r.legalName) + " " + gradePill(g.posture.grade) + "</h2>" +
      '<div class="' + P + '-row" style="margin-top:0"><button class="' + P + '-btn pri" id="' + P + '-dcheck" type="button">Check now</button><button class="' + P + '-btn" id="' + P + '-dedit" type="button">Edit</button>' +
      '<button class="' + P + '-btn" id="' + P + '-dpager" type="button">One-pager TXT</button><button class="' + P + '-btn dang" id="' + P + '-ddel" type="button">Delete</button><button class="' + P + '-btn" id="' + P + '-dclose" type="button">Close</button></div></div>' +
      '<p class="' + P + '-help">Inherent ' + g.inherent.score + " (" + g.inherent.band + "), assurance credit " + g.credit.pct + "%, residual " + g.residual.score + " (" + g.residual.band + "). " + (r.domains.length ? "Domains: " + esc(r.domains.join(", ")) : "No domains to check.") + "</p>" +
      '<div class="' + P + '-tabs" style="margin-top:10px">' + tabs.map((s) => { const [k, l] = s.split("|"); return '<button class="' + P + "-tab" + (k === detailTab ? " on" : "") + '" data-dt="' + k + '" type="button">' + esc(l) + "</button>"; }).join("") + "</div>" +
      '<div id="' + P + '-dbody"></div>';
    box.querySelectorAll("[data-dt]").forEach((b) => b.addEventListener("click", () => { detailTab = b.dataset.dt; renderDetail(); }));
    $("dclose").addEventListener("click", () => { selId = null; box.classList.add(P + "-hide"); renderVendorList(); });
    $("dedit").addEventListener("click", () => openForm(rec));
    $("dpager").addEventListener("click", () => download(TOOL_ID + "-" + cleanName(r.legalName) + "-" + fileStamp() + ".txt", onePager(r, { ...g, asOf: nowIso().slice(0, 10) }), "text/plain"));
    $("ddel").addEventListener("click", () => deleteVendor(rec));
    $("dcheck").disabled = !!example || !r.domains.length || busy;
    $("dcheck").title = example ? "The synthetic example is offline; its posture is precomputed." : !r.domains.length ? "Add a domain first" : "";
    $("dcheck").addEventListener("click", () => runChecks([rec]));
    $("ddel").disabled = !!example; $("dedit").disabled = !!example;
    const body = $("dbody");
    if (detailTab === "profile") body.innerHTML = profileHtml(r, g);
    else if (detailTab === "assurance") body.innerHTML = assuranceHtml(r);
    else if (detailTab === "posture") body.innerHTML = postureHtml(r, g);
    else if (detailTab === "changes") body.innerHTML = changesHtml(r);
    else body.innerHTML = findingsHtml(g.findings, "df");
    body.querySelectorAll("tr[data-df]").forEach((tr) => tr.addEventListener("click", () => openDrawer(g.findings[Number(tr.dataset.df)])));
  }
  const cleanName = (s) => String(s || "vendor").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40);

  function profileHtml(r, g) {
    const dl = (pairs) => '<dl class="' + P + '-dl">' + pairs.map(([k, v]) => "<dt>" + esc(k) + "</dt><dd>" + esc(v || "-") + "</dd>").join("") + "</dl>";
    return '<div class="' + P + '-cols"><div>' + dl([
      ["Services", r.services], ["Business owner", r.owner], ["Criticality", (r.criticality || "not set") + (r.spof ? " (single point of failure)" : "")],
      ["Data access tier", lbl(DATA_TIERS, r.dataTier)], ["Data types", r.dataTypes.map((t) => lbl(DATA_TYPES, t)).join(", ")], ["System access", lbl(SYSTEM_ACCESS, r.systemAccess)],
      ["Integration", r.integrations.map((t) => lbl(INTEGRATIONS, t)).join(", ")], ["Sends us email", r.sendsMail ? "yes" : "no"], ["Regions of processing", r.regions], ["Sub-processors", r.subProcessors],
      ["Contract", "start " + (r.contractStart || "-") + ", renewal " + (r.renewal || "-") + ", notice " + (r.noticeDays === "" ? "-" : r.noticeDays + " days")],
      ["Reviews", "last " + (r.lastReview || "never") + "; next " + (g.nextReview.date || "-") + " (" + g.nextReview.source + ")"],
      ["Questionnaire score", r.questionnaireScore === "" ? "" : String(r.questionnaireScore)],
      ["Linked payee", r.payeeLink ? r.payeeLink.name + " (" + (r.payeeLink.source === "payee" ? "Payee Control" : "Security Graph") + ")" : ""],
      ["Linked findings", r.linkedFindings.join("; ")], ["Exit plan", r.exitPlan], ["Notes", r.notes],
    ]) + "</div><div>" +
      "<h3>Inherent risk: " + g.inherent.score + "/100 (" + esc(g.inherent.band) + ")</h3>" +
      '<div class="' + P + '-tbl"><table><thead><tr><th>Factor</th><th>Value</th><th>Points</th></tr></thead><tbody>' +
      g.inherent.parts.map((p) => "<tr><td>" + esc(p.factor) + "</td><td>" + esc(p.value) + (p.note ? ' <span class="' + P + '-mut">' + esc(p.note) + "</span>" : "") + "</td><td>" + p.points + "</td></tr>").join("") +
      "<tr><td>Criticality multiplier</td><td>" + esc(g.inherent.criticality) + "</td><td>x " + g.inherent.multiplier + "</td></tr></tbody></table></div>" +
      '<p class="' + P + '-help">' + g.inherent.base + " x " + g.inherent.multiplier + " = " + g.inherent.raw + " of a table maximum " + g.inherent.max + ", scaled to 100. Edit the points on the Policy tab.</p>" +
      "<h3>Assurance credit: " + g.credit.pct + "%" + (g.credit.uncapped > g.credit.cap ? " (capped at " + g.credit.cap + ")" : "") + "</h3>" +
      (g.credit.parts.length ? "<ul>" + g.credit.parts.map((p) => "<li>" + esc(p.item) + ": " + p.credit + "%</li>").join("") + "</ul>" : '<p class="' + P + '-help">No current assurance documents earn credit.</p>') +
      "<h3>Residual risk: " + g.residual.score + "/100 (" + esc(g.residual.band) + ")</h3><p class=\"" + P + '-mono">' + esc(g.residual.formula) + "</p>" +
      "<h3>History</h3>" + (r.history.length ? '<ul class="' + P + '-mut">' + r.history.slice().reverse().map((h) => "<li>" + esc(String(h.at).slice(0, 16).replace("T", " ")) + " - " + esc(h.what) + "</li>").join("") + "</ul>" : '<p class="' + P + '-help">No history.</p>') +
      "</div></div>";
  }

  function assuranceHtml(r) {
    if (!r.docs.length) return '<div class="' + P + '-empty">No assurance documents on file. Edit the vendor to add them.</div>';
    const now = nowIso();
    return '<div class="' + P + '-tbl"><table><thead><tr><th>Document</th><th>Issued</th><th>Period end</th><th>Expires</th><th>Countdown</th><th>Scope</th><th>Exceptions</th></tr></thead><tbody>' +
      r.docs.slice().sort((a, b) => String(a.expires || "9999").localeCompare(String(b.expires || "9999"))).map((d) => {
        const days = d.expires ? daysUntil(d.expires, now) : null;
        const c = days == null ? "" : days < 0 ? "#b00020" : days <= opts().docExpiringDays ? "#b58100" : "";
        return "<tr><td><b>" + esc(docLabel(d.type)) + "</b></td><td>" + esc(d.issued || "-") + "</td><td>" + esc(d.periodEnd || "-") + "</td><td>" + esc(d.expires || "-") + "</td>" +
          '<td style="font-weight:700' + (c ? ";color:" + c : "") + '">' + (days == null ? '<span class="' + P + '-mut">no expiry</span>' : days < 0 ? "expired " + -days + " d ago" : days + " days") + "</td>" +
          "<td>" + esc(d.scope || "-") + "</td><td>" + (d.exceptions ? '<b style="color:#b58100">yes</b> ' + esc(d.exceptionsText) : "no") + "</td></tr>";
      }).join("") + "</tbody></table></div>";
  }

  function sparkline(snaps) {
    const pts = snaps.filter((s) => s.score != null);
    if (pts.length < 2) return '<p class="' + P + '-help">The grade history line appears after two checks.</p>';
    const W = 600, H = 120, L = 30, R = 590, T = 12, B = 96;
    const x = (i) => L + (R - L) * (pts.length === 1 ? 0.5 : i / (pts.length - 1));
    const y = (s) => B - (B - T) * s / 100;
    const line = pts.map((s, i) => x(i).toFixed(1) + "," + y(s.score).toFixed(1)).join(" ");
    return '<svg class="' + P + '-svg" viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Posture score history, ' + pts.length + ' checks">' +
      [0, 50, 100].map((v) => '<line x1="' + L + '" x2="' + R + '" y1="' + y(v) + '" y2="' + y(v) + '" stroke="currentColor" stroke-opacity=".12"/><text x="4" y="' + (y(v) + 4) + '" font-size="11" fill="currentColor" fill-opacity=".6">' + v + "</text>").join("") +
      '<polyline points="' + line + '" fill="none" stroke="#2552c6" stroke-width="2"/>' +
      pts.map((s, i) => '<circle cx="' + x(i) + '" cy="' + y(s.score) + '" r="4" fill="' + (GRADE_C[s.grade] || "#667085") + '"><title>' + esc(String(s.at).slice(0, 16).replace("T", " ") + ": " + s.grade + " (" + s.score + ")") + "</title></circle>" +
        '<text x="' + x(i) + '" y="' + (H - 6) + '" font-size="10" text-anchor="middle" fill="currentColor" fill-opacity=".6">' + esc(String(s.at).slice(5, 10)) + "</text>").join("") + "</svg>";
  }

  function postureHtml(r, g) {
    const snaps = r.posture || [];
    const latest = snaps[snaps.length - 1];
    if (!latest) return '<div class="' + P + '-empty">' + (r.domains.length ? "Never checked. Press Check now to run the live checks." : "Add a domain to this vendor to run posture checks.") + "</div>";
    const doms = [...new Set(latest.results.map((x) => x.domain))];
    return '<p class="' + P + '-help">Last checked ' + esc(String(latest.at).slice(0, 16).replace("T", " ")) + " UTC. Grade " + esc(latest.grade) + (latest.score != null ? " (" + latest.score + "/100)" : "") +
      ". Network errors are shown as error and do not count toward the grade. DKIM cannot be checked without the vendor's selectors.</p>" +
      doms.map((d) => {
        const ds = g.posture.domains.find((x) => x.domain === d);
        return "<h3>" + esc(d) + " " + (ds ? gradePill(ds.grade) + " " + (ds.score != null ? ds.score : "") : "") + "</h3>" +
          '<div class="' + P + '-tbl"><table><thead><tr><th>Check</th><th>Result</th><th>Evidence</th></tr></thead><tbody>' +
          latest.results.filter((x) => x.domain === d).map((x) => "<tr><td>" + esc(checkLabel(x.check)) + "</td><td>" + stPill(x.status) + '</td><td class="' + P + '-mono">' + esc(x.evidence || "") + "</td></tr>").join("") + "</tbody></table></div>";
      }).join("") + "<h3>Grade history</h3>" + sparkline(snaps) + (snaps.some((s) => s.compacted) ? '<p class="' + P + '-help">Older snapshots keep only their grade or statuses so the record stays within the Security Graph size limit.</p>' : "");
  }

  function changesHtml(r) {
    const snaps = r.posture || [];
    if (snaps.length < 2) return '<div class="' + P + '-empty">Changes appear after the second posture check.</div>';
    const d = diffSnapshots(snaps[snaps.length - 2], snaps[snaps.length - 1]);
    const sect = (title, rows) => "<h3>" + esc(title) + " (" + rows.length + ")</h3>" + (rows.length ? '<div class="' + P + '-tbl"><table><thead><tr><th>Domain</th><th>Check</th><th>Was</th><th>Now</th><th>Evidence</th></tr></thead><tbody>' +
      rows.map((x) => "<tr><td>" + esc(x.domain) + "</td><td>" + esc(checkLabel(x.check)) + "</td><td>" + stPill(x.from) + "</td><td>" + stPill(x.to) + '</td><td class="' + P + '-mono">' + esc(x.evidence) + "</td></tr>").join("") + "</tbody></table></div>" : '<p class="' + P + '-help">None.</p>');
    return '<p class="' + P + '-help">Comparing ' + esc(String(d.from).slice(0, 16).replace("T", " ")) + " to " + esc(String(d.to).slice(0, 16).replace("T", " ")) + " UTC. Grade " + gradePill(d.gradeFrom) + " to " + gradePill(d.gradeTo) +
      (d.gradeDrop > 0 ? ' <b style="color:#b00020">down ' + d.gradeDrop + " letter(s)</b>" : d.gradeDrop < 0 ? ' <b style="color:#1b7f4d">up ' + -d.gradeDrop + " letter(s)</b>" : " (same letter)") + ".</p>" +
      sect("New failures", d.newFailures) + sect("Worsened", d.worsened) + sect("Fixed", d.fixed) + sect("Improved", d.improved) + sect("Could not be checked this time", d.unreachable) + (d.added.length ? sect("Newly checked", d.added) : "");
  }

  // ---- findings ------------------------------------------------------------------
  const FSORT = {
    severity: (f) => SEV_RANK[f.severity], vendor: (f) => ((f.assets || [])[0] || {}).name || "", title: (f) => f.title, confidence: (f) => f.confidence, evidence: (f) => f.evidenceCount || 0,
  };
  function findingsHtml(list, attr, sortable) {
    if (!list.length) return '<div class="' + P + '-empty">No findings.</div>';
    const th = (k, l) => (sortable ? '<th data-sort="' + k + '"' + (fSort.key === k ? ' class="sorted' + (fSort.asc ? " asc" : "") + '"' : "") + ">" + l + "</th>" : "<th>" + l + "</th>");
    return '<div class="' + P + '-tbl"><table><thead><tr>' + th("severity", "Severity") + th("vendor", "Vendor") + th("title", "Finding") + th("confidence", "Confidence") + "<th>Controls</th>" + th("evidence", "Evidence") + "</tr></thead><tbody>" +
      list.map((f, i) => '<tr class="' + P + '-click" data-' + attr + '="' + i + '"><td>' + sevPill(f.severity) + "</td><td>" + esc(((f.assets || [])[0] || {}).name || "") + "</td><td><b>" + esc(f.title) + '</b><div class="' + P + '-mut">' + esc(f.description) + "</div></td><td>" + esc(f.confidence) + "</td><td>" +
        (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</td><td>" + (f.evidenceCount || 0) + "</td></tr>").join("") + "</tbody></table></div>";
  }
  function renderFindings() {
    const box = $("flist");
    const f = FSORT[fSort.key];
    const list = result.findings.slice().sort((a, b) => { const p = f(a), q = f(b); return (p < q ? -1 : p > q ? 1 : 0) * (fSort.asc ? 1 : -1) || SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.id.localeCompare(b.id); });
    box.innerHTML = result.tables.vendors.length ? findingsHtml(list, "f", true) : '<div class="' + P + '-empty">No vendors analysed yet.</div>';
    box.querySelectorAll("th[data-sort]").forEach((h) => h.addEventListener("click", () => { const k = h.dataset.sort; fSort = { key: k, asc: fSort.key === k ? !fSort.asc : true }; renderFindings(); }));
    box.querySelectorAll("tr[data-f]").forEach((tr) => tr.addEventListener("click", () => openDrawer(list[Number(tr.dataset.f)])));
  }
  function openDrawer(f) {
    const d = $("drawer");
    if (!f) { d.style.display = "none"; return; }
    d.innerHTML = '<div class="' + P + '-row" style="margin-top:0;justify-content:space-between"><h2 style="margin:0">' + sevPill(f.severity) + " " + esc(f.title) + '</h2><button class="' + P + '-btn" id="' + P + '-fclose" type="button">Close</button></div>' +
      '<dl class="' + P + '-dl"><dt>Vendor</dt><dd>' + esc((f.assets || []).map((a) => a.type + ": " + a.name).join(", ")) + "</dd><dt>Confidence</dt><dd>" + esc(f.confidence) + "</dd><dt>Category</dt><dd>" + esc(f.category) + "</dd>" +
      "<dt>What</dt><dd>" + esc(f.description) + "</dd><dt>Do this</dt><dd>" + esc(f.recommendation) + "</dd><dt>Controls</dt><dd>" + (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</dd></dl>" +
      "<h3>Evidence (" + (f.evidenceCount || 0) + ")</h3>" + objTable(f.evidence);
    d.style.display = "block";
    $("fclose").addEventListener("click", () => { d.style.display = "none"; });
    d.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  // ---- portfolio -----------------------------------------------------------------
  function renderPortfolio() {
    const box = $("portfolio");
    const t = result.tables;
    if (!t.vendors.length) { box.innerHTML = '<div class="' + P + '-empty">No vendors yet.</div>'; return; }
    const W = 520, cell = 100, L = 110, T = 30, H = T + cell * 4 + 30;
    const max = Math.max(1, ...BANDS.flatMap((c) => BANDS.map((b) => t.grid[c][b])));
    let svg = '<svg class="' + P + '-svg" viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Vendor count by criticality and residual risk band">';
    BANDS.forEach((b, j) => { svg += '<text x="' + (L + j * cell + cell / 2) + '" y="' + (T - 10) + '" font-size="13" text-anchor="middle" fill="currentColor" fill-opacity=".7">' + b + "</text>"; });
    BANDS.slice().reverse().forEach((c, i) => {
      svg += '<text x="' + (L - 10) + '" y="' + (T + i * cell + cell / 2 + 4) + '" font-size="13" text-anchor="end" fill="currentColor" fill-opacity=".7">' + c + "</text>";
      BANDS.forEach((b, j) => {
        const n = t.grid[c][b];
        svg += '<rect x="' + (L + j * cell + 2) + '" y="' + (T + i * cell + 2) + '" width="' + (cell - 4) + '" height="' + (cell - 4) + '" rx="6" fill="' + BAND_C[b] + '" fill-opacity="' + (n ? (0.15 + 0.6 * n / max).toFixed(2) : 0.04) + '" stroke="currentColor" stroke-opacity=".1"><title>' + c + " criticality, " + b + " residual: " + n + "</title></rect>" +
          '<text x="' + (L + j * cell + cell / 2) + '" y="' + (T + i * cell + cell / 2 + 8) + '" font-size="24" font-weight="700" text-anchor="middle" fill="currentColor">' + n + "</text>";
      });
    });
    svg += '<text x="' + (L + cell * 2) + '" y="' + (H - 6) + '" font-size="12" text-anchor="middle" fill="currentColor" fill-opacity=".6">residual risk band</text></svg>';
    box.innerHTML = '<h2>Portfolio</h2><div class="' + P + '-cols"><div><h3>Criticality (rows) by residual risk (columns)</h3><div style="max-width:560px">' + svg + "</div></div>" +
      "<div><h3>Documents expiring within " + opts().upcomingDays + " days or expired (" + t.expiring.length + ")</h3>" + objTable(t.expiring) +
      "<h3>Overdue reviews (" + t.overdue.length + ")</h3>" + objTable(t.overdue) + "<h3>Worst posture (" + t.worst.length + ")</h3>" + objTable(t.worst) + "</div></div>";
  }

  // ---- policy --------------------------------------------------------------------
  function renderPolicy() {
    const box = $("policy");
    const P2 = policy.points;
    const inp = (path, v, step) => '<input type="number" step="' + (step || 1) + '" min="0" data-pol="' + path + '" value="' + esc(v) + '" aria-label="' + esc(path) + '">';
    const rowsOf = (title, obj, list, path) => list.map((x, i) => "<tr><td>" + (i ? "" : "<b>" + esc(title) + "</b>") + "</td><td>" + esc(x.label) + "</td><td>" + inp(path + "." + x.id, obj[x.id], path.endsWith("Multiplier") ? 0.1 : 1) + "</td></tr>").join("");
    box.innerHTML = "<h2>Policy</h2><p class=\"" + P + '-help">Every number used for scoring is here and editable. Saved in this browser for the current workspace. Inherent = (data tier + data types (capped) + system access + integrations + single point of failure) x criticality multiplier, scaled to 0-100 by the table maximum. Residual = inherent x (1 - assurance credit) + posture adjustment.</p>' +
      '<div class="' + P + '-cols"><div><h3>Review frequency by criticality (months)</h3><div class="' + P + '-tbl ' + P + '-pts"><table><tbody>' +
      CRITICALITY.map((c) => "<tr><td>" + esc(c.label) + "</td><td>" + inp("reviewMonths." + c.id, policy.reviewMonths[c.id]) + "</td></tr>").join("") + "</tbody></table></div>" +
      "<h3>Assurance credit (% off inherent)</h3><div class=\"" + P + "-tbl " + P + '-pts"><table><tbody>' +
      [["soc2t2", "Current SOC 2 Type II"], ["soc2t1", "Current SOC 2 Type I (no Type II)"], ["iso27001", "Valid ISO 27001 certificate"], ["pentest", "Pentest within fresh window"], ["questionnaire", "Questionnaire within fresh window (x score/100)"], ["insurance", "Cyber insurance in force"], ["requiredContract", "Each required DPA / BAA / AOC on file"], ["cap", "Maximum total credit"]]
        .map(([k, l]) => "<tr><td>" + esc(l) + "</td><td>" + inp("credit." + k, policy.credit[k]) + "</td></tr>").join("") + "</tbody></table></div>" +
      "<h3>Posture adjustment (residual points by grade)</h3><div class=\"" + P + "-tbl " + P + '-pts"><table><tbody>' +
      ["A", "B", "C", "D", "F"].map((k) => "<tr><td>Grade " + k + "</td><td>" + '<input type="number" step="1" data-pol="posture.' + k + '" value="' + esc(policy.posture[k]) + '" aria-label="posture ' + k + '">' + "</td></tr>").join("") + "</tbody></table></div>" +
      "<h3>Band thresholds (score at or above)</h3><div class=\"" + P + "-tbl " + P + '-pts"><table><tbody>' +
      ["medium", "high", "critical"].map((k) => "<tr><td>" + k + "</td><td>" + inp("bands." + k, policy.bands[k]) + "</td></tr>").join("") + "</tbody></table></div></div>" +
      "<div><h3>Inherent risk points</h3><div class=\"" + P + "-tbl " + P + '-pts"><table><thead><tr><th>Factor</th><th>Value</th><th>Points</th></tr></thead><tbody>' +
      rowsOf("Data access tier", P2.dataTier, DATA_TIERS, "points.dataTier") + rowsOf("Data types (each)", P2.dataTypes, DATA_TYPES, "points.dataTypes") +
      "<tr><td></td><td>Data types cap</td><td>" + inp("points.dataTypeCap", P2.dataTypeCap) + "</td></tr>" +
      rowsOf("System access", P2.systemAccess, SYSTEM_ACCESS, "points.systemAccess") + rowsOf("Integration (each)", P2.integrations, INTEGRATIONS, "points.integrations") +
      "<tr><td><b>Single point of failure</b></td><td>yes</td><td>" + inp("points.spof", P2.spof) + "</td></tr>" +
      rowsOf("Criticality multiplier", P2.criticalityMultiplier, CRITICALITY, "points.criticalityMultiplier") + "</tbody></table></div></div></div>" +
      '<div class="' + P + '-row"><button class="' + P + '-btn" id="' + P + '-polreset" type="button">Reset to defaults</button><button class="' + P + '-btn" id="' + P + '-poljson" type="button">Export policy JSON</button></div>';
    box.querySelectorAll("[data-pol]").forEach((el) => el.addEventListener("change", () => {
      const n = Number(el.value);
      if (!Number.isFinite(n)) { toast("Enter a number", "warning"); return; }
      const path = el.dataset.pol.split(".");
      let o = policy;
      for (let i = 0; i < path.length - 1; i++) o = o[path[i]];
      o[path[path.length - 1]] = n;
      savePolicy(); schedule();
    }));
    $("polreset").addEventListener("click", async () => {
      const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Reset policy?", "Every review frequency, point and credit returns to the shipped defaults.", { danger: true }) : false;
      if (!ok) return;
      policy = mergePolicy(JSON.parse(JSON.stringify(DEFAULT_POLICY))); savePolicy(); renderPolicy(); schedule();
    });
    $("poljson").addEventListener("click", () => download(TOOL_ID + "-policy-" + fileStamp() + ".json", toJson(policy), "application/json"));
  }

  // ---- form ----------------------------------------------------------------------
  function closeForm() { editing = null; $("form").classList.add(P + "-hide"); }
  function openForm(rec) {
    if (example) { toast("Close the synthetic example to add or edit real vendors.", "warning"); return; }
    editing = rec ? normalizeRecord(rec) : normalizeRecord({});
    const f = $("form");
    f.classList.remove(P + "-hide");
    f.innerHTML = "<h2>" + (rec ? "Edit vendor: " + esc(editing.legalName) : "New vendor") + "</h2><p class=\"" + P + '-help">Inputs start empty. Only the legal name is required.</p>' +
      "<h3>Vendor</h3><div class=\"" + P + '-grid">' +
      field("f-legalName", "Legal name", '<input type="text" id="' + P + '-f-legalName" placeholder="Legal entity name">', "As on the contract.") +
      field("f-domains", "Domains (1-10)", '<textarea id="' + P + '-f-domains" placeholder="one per line"></textarea>', "The vendor's own domains: website, mail and app hosts. These are checked live.") +
      field("f-services", "Services provided", '<input type="text" id="' + P + '-f-services" placeholder="What they do for you">') +
      field("f-owner", "Business owner", '<input type="text" id="' + P + '-f-owner" placeholder="Name or team">', "Internal owner of the relationship.") +
      field("f-regions", "Country / regions of processing", '<input type="text" id="' + P + '-f-regions" placeholder="e.g. US, EU">') +
      field("f-subProcessors", "Sub-processors", '<input type="text" id="' + P + '-f-subProcessors" placeholder="Free text">') +
      "</div><h3>Data and access</h3><div class=\"" + P + '-grid">' +
      field("f-dataTier", "Data access tier", sel("f-dataTier", DATA_TIERS, "Not set"), "Restricted means regulated data (PII, PHI, PCI, financial).") +
      field("f-systemAccess", "System access", sel("f-systemAccess", SYSTEM_ACCESS, "Not set")) +
      field("f-criticality", "Criticality", sel("f-criticality", CRITICALITY, "Not set"), "Sets the review frequency and the risk multiplier.") +
      "</div>" +
      '<p class="' + P + '-lbl" style="margin:10px 0 4px">Data types</p>' + checks("f-dataTypes", DATA_TYPES) +
      '<p class="' + P + '-lbl" style="margin:10px 0 4px">Integration</p>' + checks("f-integrations", INTEGRATIONS) +
      '<div class="' + P + '-checks" style="margin-top:10px"><label class="' + P + '-chk"><input type="checkbox" id="' + P + '-f-spof">Single point of failure</label><label class="' + P + '-chk"><input type="checkbox" id="' + P + '-f-sendsMail">Vendor emails us (invoices, notices)</label></div>' +
      '<p class="' + P + '-help">"Vendor emails us" turns on the DMARC finding: spoofed vendor mail is a common route for invoice and bank-change fraud.</p>' +
      "<h3>Assurance documents</h3><div class=\"" + P + '-tbl"><table><thead><tr><th>Type</th><th>Issued</th><th>Period end</th><th>Expires</th><th>Scope note</th><th>Exceptions</th><th></th></tr></thead><tbody id="' + P + '-f-docs"></tbody></table></div>' +
      '<div class="' + P + '-row"><button class="' + P + '-btn" id="' + P + '-f-adddoc" type="button">Add document</button></div>' +
      "<h3>Contract and review</h3><div class=\"" + P + '-grid">' +
      field("f-contractStart", "Contract start", '<input type="date" id="' + P + '-f-contractStart">') +
      field("f-renewal", "Renewal date", '<input type="date" id="' + P + '-f-renewal">') +
      field("f-noticeDays", "Termination notice (days)", '<input type="number" min="0" id="' + P + '-f-noticeDays" placeholder="Days">') +
      field("f-lastReview", "Last review", '<input type="date" id="' + P + '-f-lastReview">') +
      field("f-nextReview", "Next review (override)", '<input type="date" id="' + P + '-f-nextReview">', "Leave empty to use the policy frequency for the criticality.") +
      field("f-questionnaireScore", "Questionnaire score (0-100)", '<input type="number" min="0" max="100" id="' + P + '-f-questionnaireScore" placeholder="Optional">') +
      "</div><h3>Links and notes</h3><div class=\"" + P + '-grid">' +
      field("f-payee", "Linked Payee Control vendor", '<select id="' + P + '-f-payee"><option value="">None</option></select>', "From Payee Control (this browser) and VENDOR entities in the Security Graph.") +
      field("f-linkedFindings", "Linked findings", '<input type="text" id="' + P + '-f-linkedFindings" list="' + P + '-fnames" placeholder="Finding names; separate with ;"><datalist id="' + P + '-fnames"></datalist>', "Pick from Security Graph findings or type a reference.") +
      field("f-exitPlan", "Exit plan", '<textarea id="' + P + '-f-exitPlan" placeholder="How you would leave"></textarea>', "Expected for critical vendors.", true) +
      field("f-notes", "Notes", '<textarea id="' + P + '-f-notes" placeholder="Notes"></textarea>', "", true) +
      "</div>" + '<p class="' + P + '-help bad" id="' + P + '-f-err"></p>' +
      '<div class="' + P + '-row"><button class="' + P + '-btn pri" id="' + P + '-f-save" type="button">Save vendor</button><button class="' + P + '-btn" id="' + P + '-f-cancel" type="button">Cancel</button></div>';
    const set = (id, v) => { $("f-" + id).value = v == null ? "" : v; };
    const r = editing;
    ["legalName", "services", "owner", "regions", "subProcessors", "dataTier", "systemAccess", "criticality", "contractStart", "renewal", "noticeDays", "lastReview", "nextReview", "questionnaireScore", "exitPlan", "notes"].forEach((k) => set(k, r[k]));
    set("domains", r.domains.join("\n")); set("linkedFindings", r.linkedFindings.join("; "));
    $("f-spof").checked = r.spof; $("f-sendsMail").checked = r.sendsMail;
    $("f-dataTypes").querySelectorAll("input").forEach((i) => { i.checked = r.dataTypes.includes(i.value); });
    $("f-integrations").querySelectorAll("input").forEach((i) => { i.checked = r.integrations.includes(i.value); });
    r.docs.forEach(docRow);
    $("f-adddoc").addEventListener("click", () => docRow({}));
    $("f-cancel").addEventListener("click", closeForm);
    $("f-save").addEventListener("click", saveForm);
    fillLinks();
    f.scrollIntoView({ behavior: "smooth", block: "start" });
    $("f-legalName").focus();
  }
  function docRow(d) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td><select data-k="type" aria-label="Document type">' + DOC_TYPES.map((x) => '<option value="' + x.id + '"' + (x.id === d.type ? " selected" : "") + ">" + esc(x.label) + "</option>").join("") + "</select></td>" +
      ["issued", "periodEnd", "expires"].map((k) => '<td><input type="date" data-k="' + k + '" aria-label="' + k + '" value="' + esc(d[k] || "") + '"></td>').join("") +
      '<td><input type="text" data-k="scope" placeholder="Scope" aria-label="Scope note" value="' + esc(d.scope || "") + '"></td>' +
      '<td><label class="' + P + '-chk"><input type="checkbox" data-k="exceptions"' + (d.exceptions ? " checked" : "") + '>yes</label><input type="text" data-k="exceptionsText" placeholder="Detail" aria-label="Exceptions detail" value="' + esc(d.exceptionsText || "") + '" style="margin-top:4px"></td>' +
      '<td><button class="' + P + '-btn" type="button">Remove</button></td>';
    tr.dataset.id = d.id || "";
    tr.querySelector("button").addEventListener("click", () => tr.remove());
    $("f-docs").appendChild(tr);
  }
  async function fillLinks() {
    await loadLinkCandidates();
    const s = $("f-payee");
    if (!s || !editing) return;
    const cur = editing.payeeLink;
    const suggested = new Set(matchPayees(editing.legalName, linkCands).map((c) => c.source + ":" + c.id));
    s.innerHTML = '<option value="">None</option>' + linkCands.map((c) => '<option value="' + esc(c.source + ":" + c.id) + '"' + (cur && cur.source === c.source && String(cur.id) === String(c.id) ? " selected" : "") + ">" +
      esc(c.name + " (" + (c.source === "payee" ? "Payee Control" : "Security Graph") + ")" + (suggested.has(c.source + ":" + c.id) ? " - name match" : "")) + "</option>").join("");
    $("fnames").innerHTML = graphFindingNames.map((n) => '<option value="' + esc(n) + '">').join("");
  }
  async function loadLinkCandidates() {
    const out = [];
    try {
      const uid = (window.__dnUid || "anon");
      const payees = JSON.parse(localStorage.getItem("dn_payees_" + uid) || "[]");
      for (const p of Array.isArray(payees) ? payees : []) if (p && p.name) out.push({ source: "payee", id: String(p.id), name: String(p.name) });
    } catch (_) {}
    try {
      const sg = await import("/js/security-graph.js");
      for (const e of sg.listEntities({ type: "VENDOR" }) || []) if (e && e.source !== TOOL_ID && e.name) out.push({ source: "graph", id: e.id, name: e.name });
      graphFindingNames = (sg.listEntities({ type: "FINDING", limit: 300 }) || []).map((e) => e.name).filter(Boolean);
    } catch (_) {}
    linkCands = out.sort((a, b) => (a.name + a.source).localeCompare(b.name + b.source));
  }
  function readForm() {
    const v = (id) => ($("f-" + id).value || "").trim();
    const docs = [...$("f-docs").querySelectorAll("tr")].map((tr, i) => {
      const g = (k) => tr.querySelector('[data-k="' + k + '"]');
      return { id: tr.dataset.id || "d" + Date.now().toString(36) + i, type: g("type").value, issued: g("issued").value, periodEnd: g("periodEnd").value, expires: g("expires").value, scope: g("scope").value.trim(), exceptions: g("exceptions").checked, exceptionsText: g("exceptionsText").value.trim() };
    });
    const pv = v("payee");
    const link = pv ? linkCands.find((c) => c.source + ":" + c.id === pv) : null;
    return {
      ...editing, legalName: v("legalName"), domains: v("domains").split(/[\s,;]+/).filter(Boolean), services: v("services"), owner: v("owner"), regions: v("regions"), subProcessors: v("subProcessors"),
      dataTier: v("dataTier"), systemAccess: v("systemAccess"), criticality: v("criticality"),
      dataTypes: [...$("f-dataTypes").querySelectorAll("input:checked")].map((i) => i.value), integrations: [...$("f-integrations").querySelectorAll("input:checked")].map((i) => i.value),
      spof: $("f-spof").checked, sendsMail: $("f-sendsMail").checked, docs,
      contractStart: v("contractStart"), renewal: v("renewal"), noticeDays: v("noticeDays"), lastReview: v("lastReview"), nextReview: v("nextReview"), questionnaireScore: v("questionnaireScore"),
      payeeLink: link ? { source: link.source, id: link.id, name: link.name } : (pv && editing.payeeLink ? editing.payeeLink : null),
      linkedFindings: v("linkedFindings").split(";").map((x) => x.trim()).filter(Boolean), exitPlan: v("exitPlan"), notes: v("notes"),
    };
  }
  function saveForm() {
    const raw = readForm();
    const errs = validateRecord(raw);
    $("f-err").textContent = errs.join(" ");
    if (errs.length) return;
    const isNew = !editing.id;
    let rec = normalizeRecord(raw);
    if (isNew) rec = addHistory(rec, new Date().toISOString(), "Created");
    else {
      const before = normalizeRecord(reg.get(editing.id) || {});
      const changed = ["legalName", "domains", "services", "owner", "dataTier", "dataTypes", "systemAccess", "integrations", "criticality", "spof", "sendsMail", "docs", "contractStart", "renewal", "noticeDays", "lastReview", "nextReview", "questionnaireScore", "payeeLink", "linkedFindings", "exitPlan", "notes", "regions", "subProcessors"]
        .filter((k) => JSON.stringify(before[k]) !== JSON.stringify(rec[k]));
      if (changed.length) rec = addHistory(rec, new Date().toISOString(), "Edited: " + changed.join(", "));
    }
    const saved = reg.upsert(rec);
    selId = saved.id; closeForm(); schedule();
    toast("Vendor saved", "success");
  }
  async function deleteVendor(rec) {
    const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Delete vendor?", "This removes \"" + (rec.legalName || "Unnamed") + "\", its documents and posture history from the register and the Security Graph.", { danger: true }) : false;
    if (!ok) return;
    reg.remove(rec.id); selId = null; $("detail").classList.add(P + "-hide"); schedule();
    toast("Vendor deleted", "success");
  }

  // ---- live checks ---------------------------------------------------------------
  async function fetchT(url, init, ms) {
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), ms || 8000);
    try { return await fetch(url, { ...(init || {}), signal: ctrl.signal }); } finally { clearTimeout(t); }
  }
  async function doh(name, type) {
    let last = "";
    for (const base of ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]) {
      try {
        const res = await fetchT(base + "?name=" + encodeURIComponent(name) + "&type=" + type, { headers: { Accept: "application/dns-json" } }, 8000);
        if (res.ok) return await res.json();
        last = new URL(base).host + " HTTP " + res.status;
      } catch (e) { last = new URL(base).host + ": " + (e && e.name === "AbortError" ? "timeout" : (e && e.message) || e); }
    }
    return { error: "DNS over HTTPS failed (" + last + ")" };
  }
  const viaProxy = async (fn) => { try { return await fn(); } catch (e) { return { error: String((e && e.message) || e) }; } };
  async function collectDomain(domain) {
    const apex = registrableGuess(domain);
    const proxyOk = proxyConfigured();
    const noProxy = { error: "The Darknode proxy is not configured, so this check cannot run." };
    const [mx, txt, dmarc, mtasts, tlsrpt, ds, caa0, ns, https, http, cert, securityTxt, rdap] = await Promise.all([
      doh(domain, "MX"), doh(domain, "TXT"), doh("_dmarc." + domain, "TXT"), doh("_mta-sts." + domain, "TXT"), doh("_smtp._tls." + domain, "TXT"),
      doh(apex, "DS"), doh(domain, "CAA"), doh(apex, "NS"),
      proxyOk ? viaProxy(() => dnFetch("https://" + domain, { timeout: 14000 })) : noProxy,
      proxyOk ? viaProxy(() => dnFetch("http://" + domain, { timeout: 12000 })) : noProxy,
      proxyOk ? fetchCertRows(domain).then((rows) => ({ rows })).catch((e) => ({ error: String(e && e.message || e) })) : noProxy,
      proxyOk ? viaProxy(() => dnFetch("https://" + domain + "/.well-known/security.txt", { raw: true, timeout: 12000 })) : noProxy,
      proxyOk ? viaProxy(async () => ({ json: await dnFetchJSON("https://rdap.org/domain/" + encodeURIComponent(apex), { timeout: 15000 }) })) : noProxy,
    ]);
    let caa = caa0;
    if (!caa.error && apex !== domain && !(caa.Answer || []).some((a) => a.type === 257)) caa = await doh(apex, "CAA");
    let mtastsPolicy;
    if (!mtasts.error && (mtasts.Answer || []).some((a) => /v=STSv1/i.test(String(a.data)))) {
      mtastsPolicy = proxyOk ? await viaProxy(() => dnFetch("https://mta-sts." + domain + "/.well-known/mta-sts.txt", { raw: true, timeout: 12000 })) : noProxy;
    }
    return { domain, apex, mx, txt, dmarc, mtasts, mtastsPolicy, tlsrpt, ds, caa, ns, https: https.error ? https : { status: https.status, headers: https.headers, finalUrl: https.finalUrl || https.url },
      http: http.error ? http : { status: http.status, finalUrl: http.finalUrl || http.url }, cert, securityTxt: securityTxt.error ? securityTxt : { status: securityTxt.status, body: securityTxt.body }, rdap };
  }
  async function leakFor(domain, status) {
    const kw = registrableGuess(domain);
    if (!proxyConfigured()) return { error: "The Darknode proxy is not configured." };
    const wait = lastLeakAt + LEAK_GAP_MS - Date.now();
    if (wait > 0) { status("waiting " + Math.ceil(wait / 1000) + " s for the ransomware.live rate limit"); await sleep(wait); }
    lastLeakAt = Date.now();
    try { return leakResponse(await dnFetchJSON("https://api.ransomware.live/v2/searchvictims/" + encodeURIComponent(kw), { timeout: 20000 }), kw); }
    catch (e) { return { error: "ransomware.live: " + String((e && e.message) || e) }; }
  }
  async function checkVendor(rec, status) {
    const r = normalizeRecord(rec);
    const leakOpt = $("leakopt").checked;
    const at = new Date().toISOString();
    const all = [];
    for (let i = 0; i < r.domains.length; i++) {
      const d = r.domains[i];
      status(r.legalName + ": " + d);
      const raw = await collectDomain(d);
      if (leakOpt) raw.leak = await leakFor(d, (m) => status(r.legalName + ": " + m));
      all.push(...gradeDomain(raw, { now: at, legalName: r.legalName, certWarnDays: opts().certWarnDays, domainWarnDays: opts().domainWarnDays }));
      if (i < r.domains.length - 1) await sleep(400);
    }
    const snap = makeSnapshot(all, at);
    const cur = reg.get(rec.id) || rec;
    let next = addSnapshot(cur, snap, { cap: DEFAULTS.snapshotCap });
    const prev = (cur.posture || [])[(cur.posture || []).length - 1];
    next = addHistory(next, at, "Posture check: grade " + snap.grade + (snap.score != null ? " (" + snap.score + ")" : "") + (prev ? ", was " + prev.grade : "") + "; " + all.filter((x) => x.status === "error").length + " check(s) errored");
    reg.upsert(next);
    return snap;
  }
  async function runChecks(list) {
    if (busy) { toast("A check is already running", "warning"); return; }
    if (example) { toast("The synthetic example is offline; close it to check real vendors.", "warning"); return; }
    const todo = list.filter((r) => normalizeRecord(r).domains.length);
    if (!todo.length) { toast("No vendors with domains to check", "warning"); return; }
    if (!proxyConfigured()) toast("Proxy not configured: only the DNS checks can run; the rest will show as error.", "warning");
    busy = true; $("checkall").disabled = true;
    const prog = $("prog"), bar = prog.firstElementChild;
    prog.style.display = "block"; bar.style.width = "0%";
    let done = 0, i = 0;
    const lines = new Map();
    const show = () => { $("status").textContent = "Checking " + done + " of " + todo.length + " vendor(s). " + [...lines.values()].join(" | "); };
    const workers = Array.from({ length: Math.min(3, todo.length) }, async (_, w) => {
      while (i < todo.length) {
        const rec = todo[i++];
        try { await checkVendor(rec, (m) => { lines.set(w, m); show(); }); }
        catch (e) { toast(rec.legalName + ": check failed: " + ((e && e.message) || e), "error"); }
        done++; lines.delete(w); bar.style.width = Math.round(done / todo.length * 100) + "%"; show();
        if (i < todo.length) await sleep(750);
      }
    });
    await Promise.all(workers);
    busy = false; $("checkall").disabled = false; prog.style.display = "none";
    $("status").textContent = "Checked " + done + " vendor(s) at " + new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC.";
    toast("Posture checked for " + done + " vendor(s)", "success");
    schedule();
  }

  // ---- buttons -------------------------------------------------------------------
  $("new").addEventListener("click", () => { selId = null; $("detail").classList.add(P + "-hide"); openForm(null); });
  $("checkall").addEventListener("click", () => runChecks(reg.list()));
  $("example").addEventListener("click", () => {
    const ex = exampleDataset(7, new Date().toISOString());
    example = { records: ex.records, now: ex.now };
    selId = ex.records[0].id; detailTab = "posture"; closeForm(); schedule();
    toast("Loaded synthetic example: 8 fictional vendors, no network calls", "info");
  });
  main.querySelectorAll("[data-opt]").forEach((el) => el.addEventListener("input", schedule));

  function renderExports() {
    const ex = $("exports");
    const recs = records();
    const stamp = () => fileStamp();
    ex.innerHTML = ["rcsv|Register CSV", "rjson|Register JSON", "fcsv|Findings CSV", "txt|Summary TXT", "ics|Renewal and review calendar (.ics)"]
      .map((s) => { const [k, l] = s.split("|"); return '<button class="' + P + '-btn" type="button" data-x="' + k + '">' + l + "</button>"; }).join("");
    const on = (k, fn) => ex.querySelector('[data-x="' + k + '"]').addEventListener("click", () => { if (!recs.length) { toast("No vendors to export", "warning"); return; } fn(); });
    on("rcsv", () => download(TOOL_ID + "-register-" + stamp() + ".csv", registerToCsv(recs, result.tables.graded), "text/csv"));
    on("rjson", () => download(TOOL_ID + "-register-" + stamp() + ".json", example ? toJson(recs) : reg.exportJson(), "application/json"));
    on("fcsv", () => download(TOOL_ID + "-findings-" + stamp() + ".csv", findingsToCsv(result.findings), "text/csv"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp() + ".txt", summaryText(), "text/plain"));
    on("ics", () => {
      const ev = icsEvents(recs, { now: nowIso(), policy });
      if (!ev.length) { toast("No renewal, review or expiry dates to export", "warning"); return; }
      download(TOOL_ID + "-calendar-" + stamp() + ".ics", toIcs(ev), "text/calendar");
    });
    attachSinkButton(ex, () => ({ findings: result ? result.findings : [], sample: !!example }), TOOL_ID, { dataset: example ? "synthetic example" : "vendor register" });
    const note = document.createElement("p");
    note.className = P + "-help"; note.style.width = "100%";
    note.textContent = "Saved vendors are already mirrored as VENDOR entities. The graph button adds one FINDING per finding, linked to its VENDOR and DOMAIN entities.";
    ex.appendChild(note);
  }
  function summaryText() {
    const s = result.summary;
    const L = ["Third-Party Risk summary", "As of " + nowIso().slice(0, 16).replace("T", " ") + " UTC" + (example ? " (SYNTHETIC EXAMPLE)" : ""), "",
      "Vendors: " + s.vendors + " (critical " + s.critical + ")", "High or critical residual risk: " + s.residualHigh, "Documents expired: " + s.docsExpired + "; expiring in " + opts().upcomingDays + " days: " + s.docsExpiring,
      "Reviews overdue: " + s.reviewsOverdue, "Posture checked: " + s.checked + " of " + s.vendors, "", "VENDORS (residual, highest first)"];
    for (const v of result.tables.vendors.slice().sort((a, b) => b.residual - a.residual || a.legalName.localeCompare(b.legalName))) L.push("  " + v.legalName + ": inherent " + v.inherent + ", residual " + v.residual + " (" + v.residualBand + "), posture " + v.grade + (v.trend ? " " + v.trend : "") + ", next review " + (v.nextReview || "-"));
    L.push("", "FINDINGS (" + result.findings.length + ")");
    for (const f of result.findings) L.push("  [" + f.severity.toUpperCase() + "] " + f.title + " - " + (((f.assets || [])[0] || {}).name || ""));
    if (result.skipped.length) L.push("", "NOT CHECKED", ...result.skipped.map((x) => "  " + x.check + ": " + x.reason));
    return L.join("\n") + "\n";
  }

  // ---- import --------------------------------------------------------------------
  mountDropzone($("drop"), {
    maxBytes: 20 << 20, maxFiles: 5, unpack: true, accept: ".json,.csv,.tsv,.txt",
    label: "Drop a register JSON or a vendor list CSV",
    onFiles: async (files) => {
      const parsed = parseInput(await Promise.all(files.map(async (f) => ({ name: f.name, text: await f.text() }))));
      for (const s of parsed.skipped) toast(s.check + ": " + s.reason, "warning");
      csvParsed = parsed;
      renderImport();
    },
  });
  function renderImport() {
    const p = csvParsed;
    const det = $("detected"), map = $("mapping");
    if (!p || !p.files.length) { det.innerHTML = '<p class="' + P + '-help bad" style="margin-top:8px">Nothing importable found.</p>'; map.innerHTML = ""; return; }
    det.innerHTML = '<div class="' + P + '-tbl" style="margin-top:10px"><table><thead><tr><th>File</th><th>Detected format</th><th>Confidence</th><th>Rows</th></tr></thead><tbody>' +
      p.files.map((f) => "<tr><td>" + esc(f.name) + "</td><td>" + esc(f.format) + "</td><td>" + esc(f.confidence) + "</td><td>" + f.count + "</td></tr>").join("") + "</tbody></table></div>";
    if (p.format === "vendorrisk-register") {
      map.innerHTML = '<div class="' + P + '-row"><button class="' + P + '-btn pri" id="' + P + '-imp" type="button">Import ' + p.records.length + " vendor(s)</button><span class=\"" + P + '-mut">Records with an ID already in the register are updated.</span></div>';
      $("imp").addEventListener("click", () => {
        if (example) { toast("Close the synthetic example first.", "warning"); return; }
        const r = reg.importJson(p.records.map((x) => ({ ...x })));
        toast("Imported: " + r.added + " added, " + r.updated + " updated" + (r.rejected ? ", " + r.rejected + " rejected" : ""), "success");
        csvParsed = null; det.innerHTML = ""; map.innerHTML = ""; schedule();
      });
      return;
    }
    const opt = (k) => '<select data-map="' + k + '" aria-label="' + esc(COLUMN_LABELS[k] || k) + '"><option value="">Not in file</option>' + p.headers.map((h) => '<option value="' + esc(h) + '"' + (p.mapping[k] === h ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select>";
    map.innerHTML = "<h3>Column mapping" + (p.confidence === "high" ? "" : ' <span style="color:#b58100">(check the mapping: confidence ' + esc(p.confidence) + ")</span>") + "</h3>" +
      '<div class="' + P + '-grid">' + Object.keys(COLUMNS).map((k) => field("map-" + k, COLUMN_LABELS[k] || k, opt(k))).join("") + "</div>" +
      '<p class="' + P + '-help" style="margin-top:6px">Lists (domains, data types, integration) may be separated by ; , or |. Dates as YYYY-MM-DD or M/D/YYYY. Unknown values are left blank, never guessed.</p>' +
      '<div class="' + P + '-row"><button class="' + P + '-btn pri" id="' + P + '-imp" type="button">Import ' + p.rows.length + ' row(s)</button><span class="' + P + '-mut" id="' + P + '-impnote"></span></div>';
    $("imp").addEventListener("click", () => {
      if (example) { toast("Close the synthetic example first.", "warning"); return; }
      const mapping = {};
      map.querySelectorAll("[data-map]").forEach((s) => { if (s.value) mapping[s.dataset.map] = s.value; });
      if (!mapping.legalName) { toast("Map the legal name column first", "warning"); return; }
      const { records: recs, skipped } = csvToRecords(p.rows, mapping);
      const at = new Date().toISOString();
      for (const r of recs) reg.upsert(addHistory(r, at, "Imported from CSV"));
      toast("Imported " + recs.length + " vendor(s)" + (skipped.length ? "; " + skipped.length + " note(s)" : ""), skipped.length ? "warning" : "success");
      $("impnote").textContent = skipped.map((s) => s.check + ": " + s.reason).join("; ");
      schedule();
    });
  }

  // ---- boot ----------------------------------------------------------------------
  renderPolicy();
  reg.subscribe(() => { if (!example) schedule(); });
  reg.ready.then(() => reg.backfill()).then(() => schedule()).catch(() => {});
  schedule();
}
