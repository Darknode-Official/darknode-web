// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Control Evidence (evidence): Deck tool UI. A year-round evidence program for
// SOC 2, ISO 27001, PCI DSS, CIS v8 and NIST CSF 2.0. Controls in scope live in a
// team-shareable register (core/register.js) mirrored into the Security Graph as
// CONTROL entities. Evidence files are hashed in the browser (crypto.subtle) and
// never uploaded or stored; only name, size, type and SHA-256 are kept. The pure
// engine (evidence-engine.js) runs in a Worker. No native dialogs.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { openRegister, wsKey, isTeam } from "../core/register.js";
import { download, toJson, fileStamp, toIcs, zipFiles } from "../core/export.js";
import {
  DEFAULTS, DEFAULT_LABELS, TOOL_ID, FRAMEWORKS, FREQUENCIES, FREQ_LABEL, STATUSES, STATUS_LABEL, SOC2_CATEGORIES, PCI_LEVELS,
  COLUMNS, REGISTER_SCHEMA, TOOL_EVIDENCE_MAP, MAX_HASH_BYTES,
  parseInput, importRows, findingsToCsv, summaryText, exampleDataset, scopedRows, bulkCreate, assignOwners, normalizeRecord,
  mergeRecords, addHistory, refsLabel, fwLabel, sha256Hex, icsEvents, buildPackage, registerCsv, suggestionEvidence,
  toDay, addMonths, addDays, catalogsHaveCrosswalk, normControlId,
} from "./evidence-engine.js?v=20261017c";

const ENGINE = engineUrl("./evidence-engine.js?v=20261017c", import.meta);
const P = "evd";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtBytes = (n) => (n == null || n === "" ? "" : n >= 1 << 30 ? (n / (1 << 30)).toFixed(2) + " GB" : n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + " MB" : n >= 1024 ? Math.round(n / 1024) + " KB" : n + " B");
const todayIso = () => new Date().toISOString().slice(0, 10);
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const PROGRAM_KEY = "evd_program";
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const CSS = `
  .evd-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .evd-root *{box-sizing:border-box}
  .evd-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .evd-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .evd-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--mut,#667085);border:1px solid var(--line,#e6e8ee);padding:2px 9px;border-radius:999px}
  .evd-sub{color:var(--mut,#667085);margin:8px 0 4px;max-width:100ch;overflow-wrap:anywhere}
  .evd-honest{border:1px solid var(--line,#e6e8ee);border-left:4px solid #2552c6;border-radius:8px;padding:9px 14px;margin:8px 0 12px;background:var(--card,#fff);font-weight:600;overflow-wrap:anywhere}
  .evd-exbar{border:1px solid var(--line,#e6e8ee);border-left:4px solid #b58100;border-radius:8px;padding:9px 14px;margin:0 0 12px;background:var(--card,#fff);display:none}
  .evd-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .evd-card h2{font-size:1.02rem;margin:0 0 4px}
  .evd-card h3{font-size:.8rem;margin:16px 0 6px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#667085)}
  .evd-row{display:flex;flex-wrap:wrap;gap:8px 10px;align-items:center;margin-top:10px}
  .evd-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:7px 13px;border-radius:8px;cursor:pointer;max-width:100%}
  .evd-btn:hover{border-color:var(--mut,#667085)}
  .evd-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .evd-btn.dang{color:#b00020}
  .evd-btn.sm{font-size:.76rem;padding:4px 9px}
  .evd-btn:disabled{opacity:.5;cursor:default}
  .evd-tabs{display:flex;flex-wrap:wrap;gap:4px;border-bottom:1px solid var(--line,#e6e8ee);margin:0 0 14px}
  .evd-tab{appearance:none;font:inherit;font-size:.86rem;font-weight:600;background:none;border:1px solid transparent;border-bottom:none;color:var(--mut,#667085);padding:8px 14px;border-radius:8px 8px 0 0;cursor:pointer;margin-bottom:-1px}
  .evd-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#e6e8ee);background:var(--card,#fff)}
  .evd-tab b{font-weight:700;margin-left:4px;color:#2552c6}
  .evd-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px 16px}
  .evd-field{display:flex;flex-direction:column;gap:3px;min-width:0}
  .evd-field.wide{grid-column:1/-1}
  .evd-field>label,.evd-lbl{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .evd-root input[type=text],.evd-root input[type=email],.evd-root input[type=url],.evd-root input[type=number],.evd-root input[type=date],.evd-root input[type=search],.evd-root select,.evd-root textarea{font:inherit;font-size:.86rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%;min-width:0}
  .evd-root textarea{min-height:64px;resize:vertical}
  .evd-help{font-size:.75rem;color:var(--mut,#667085);margin:0;overflow-wrap:anywhere}
  .evd-checks{display:flex;flex-wrap:wrap;gap:6px}
  .evd-chk{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line,#d7dbe3);border-radius:999px;padding:4px 11px;font-size:.8rem;cursor:pointer;user-select:none;background:var(--card,#fff);max-width:100%;overflow-wrap:anywhere}
  .evd-chk input{margin:0}
  .evd-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin:0 0 14px}
  .evd-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .evd-kpi b{display:block;font-size:1.3rem;line-height:1.25;overflow-wrap:anywhere}
  .evd-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .evd-kpi.alert b{color:#b00020}
  .evd-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin:0 0 12px;display:none}
  .evd-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .evd-bars{display:flex;flex-direction:column;gap:10px}
  .evd-bar{display:grid;grid-template-columns:minmax(90px,140px) 1fr minmax(60px,auto);gap:10px;align-items:center}
  .evd-bar .trk{height:16px;border:1px solid var(--line,#e6e8ee);border-radius:4px;background:var(--bg,#f7f8fb);overflow:hidden;display:flex}
  .evd-bar .trk i{display:block;height:100%}
  .evd-bar .rd{background:#1b7f4d}.evd-bar .ex{background:#b58100}
  .evd-bar small{color:var(--mut,#667085);font-size:.74rem;grid-column:2/-1;margin-top:-6px}
  .evd-legend{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:.76rem;color:var(--mut,#667085);margin-top:8px}
  .evd-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
  .evd-tbl{border:1px solid var(--line,#e6e8ee);border-radius:10px;overflow:auto;max-width:100%}
  .evd-tbl table{width:100%;border-collapse:collapse;font-size:.84rem}
  .evd-tbl th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 10px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .evd-tbl th[data-sort]{cursor:pointer;user-select:none}
  .evd-tbl th.sorted::after{content:" \\2193"}
  .evd-tbl th.sorted.asc::after{content:" \\2191"}
  .evd-tbl td{padding:8px 10px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .evd-tbl tr.evd-click{cursor:pointer}
  .evd-tbl tr.evd-click:hover td{background:var(--bg,#f7f8fb)}
  .evd-tbl tr.sel td{background:var(--bg,#f2f4f8)}
  .evd-pill{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .evd-pill.critical{background:#7a0012}.evd-pill.high{background:#b00020}.evd-pill.medium{background:#b58100}.evd-pill.low{background:#2552c6}.evd-pill.info{background:#667085}
  .evd-st{display:inline-block;font-size:.72rem;font-weight:700;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 7px;white-space:nowrap}
  .evd-st.accepted{border-color:#1b7f4d;color:#1b7f4d}.evd-st.collected{border-color:#2552c6;color:#2552c6}.evd-st.collecting{border-color:#b58100;color:#8a6d00}.evd-st.exception{border-color:#b00020;color:#b00020}
  .evd-chip{display:inline-block;font-size:.72rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .evd-chip.fw{color:var(--tx,#1a2230);font-weight:600}
  .evd-due.over{color:#b00020;font-weight:700}.evd-due.soon{color:#8a6d00;font-weight:700}
  .evd-mut{color:var(--mut,#667085);font-size:.78rem}
  .evd-mono{font-family:ui-monospace,Menlo,monospace;font-size:.76rem;overflow-wrap:anywhere;word-break:break-all}
  .evd-empty{padding:22px;text-align:center;color:var(--mut,#667085)}
  .evd-filters{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px 12px;margin-bottom:10px}
  .evd-drawer{display:none;border:1px solid var(--line,#e6e8ee);border-left:4px solid #2552c6;border-radius:12px;background:var(--card,#fff);padding:16px 18px;margin:14px 0}
  .evd-drawer h2{font-size:1.08rem;margin:0 0 4px;overflow-wrap:anywhere}
  .evd-drop{border:1.5px dashed var(--line,#cdd3de);border-radius:10px;padding:18px 14px;text-align:center;color:var(--mut,#667085);background:var(--bg,#fbfcfe);cursor:pointer;overflow-wrap:anywhere}
  .evd-drop.over{border-color:#2552c6}
  .evd-hash{margin-top:8px;font-size:.8rem}
  .evd-hash .trk{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:4px}
  .evd-hash .trk i{display:block;height:100%;width:0;background:#2552c6}
  .evd-hist{list-style:none;margin:0;padding:0;max-height:220px;overflow:auto;font-size:.8rem}
  .evd-hist li{padding:4px 0;border-bottom:1px solid var(--line,#eef0f4);overflow-wrap:anywhere}
  .evd-cal{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));border-top:1px solid var(--line,#e6e8ee);border-left:1px solid var(--line,#e6e8ee)}
  .evd-cal>div{border-right:1px solid var(--line,#e6e8ee);border-bottom:1px solid var(--line,#e6e8ee);min-height:84px;padding:4px 5px;min-width:0;overflow:hidden}
  .evd-cal .hd{min-height:0;font-size:.7rem;font-weight:700;text-transform:uppercase;color:var(--mut,#667085);background:var(--bg,#f7f8fb);text-align:center}
  .evd-cal .out{background:var(--bg,#f7f8fb);opacity:.55}
  .evd-cal .today{outline:2px solid #2552c6;outline-offset:-2px}
  .evd-cal .dn{font-size:.72rem;color:var(--mut,#667085)}
  .evd-cal .it{display:block;font-size:.7rem;line-height:1.3;border-left:3px solid #2552c6;padding:1px 4px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer;background:var(--card,#fff)}
  .evd-cal .it.overdue{border-left-color:#b00020;color:#b00020}
  .evd-cal .cnt{display:none;font-size:.72rem;font-weight:700;color:#2552c6}
  .evd-calnav{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}
  .evd-calnav b{font-size:1rem;min-width:140px}
  .evd-dl{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;margin:6px 0;font-size:.84rem}
  .evd-dl dt{color:var(--mut,#667085)}
  .evd-dl dd{margin:0;overflow-wrap:anywhere}
  .evd-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px;overflow-wrap:anywhere}
  .evd-root details summary{cursor:pointer;font-size:.84rem;font-weight:600;margin:4px 0}
  .evd-root a{color:#2552c6;overflow-wrap:anywhere}
  .evd-lic{font-size:.76rem;color:var(--mut,#667085);margin:2px 0 8px;overflow-wrap:anywhere}
  .evd-scope{max-height:420px}
  .evd-scope input[type=text]{padding:4px 8px;font-size:.8rem}
  @media(max-width:600px){.evd-card,.evd-drawer{padding:12px}.evd-dl{grid-template-columns:1fr}.evd-dl dt{margin-top:6px}
    .evd-cal>div{min-height:46px;padding:2px}.evd-cal .it{display:none}.evd-cal .cnt{display:block}.evd-bar{grid-template-columns:1fr auto}.evd-bar .trk{grid-column:1/-1;grid-row:2}.evd-bar small{grid-column:1/-1;margin-top:0}}
`;

const kpi = (v, l, alert) => '<div class="' + P + "-kpi" + (alert ? " alert" : "") + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const field = (id, label, input, help, wide) => '<div class="' + P + "-field" + (wide ? " wide" : "") + '"><label for="' + P + "-" + id + '">' + esc(label) + "</label>" + input + (help ? '<p class="' + P + '-help">' + esc(help) + "</p>" : "") + "</div>";
const opts = (list, sel) => list.map(([v, l]) => '<option value="' + esc(v) + '"' + (v === sel ? " selected" : "") + ">" + esc(l) + "</option>").join("");
const chips = (refs) => (refs || []).map((r) => '<span class="' + P + '-chip fw">' + esc(fwLabel(r.fw) + " " + r.id) + "</span>").join("");
const stPill = (s) => '<span class="' + P + "-st " + esc(s) + '">' + esc(STATUS_LABEL[s] || s) + "</span>";

/** Mount the tool into main. */
export function renderEvidence(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Control Evidence</h1><span class="', P, '-tag">Evidence calendar</span></div>',
    '<p class="', P, '-sub">Which control needs which evidence, who owns it, when it is due, what was collected, readiness per framework and an auditor package, for SOC 2, ISO 27001, PCI DSS, CIS v8 and NIST CSF 2.0.</p>',
    '<div class="', P, '-honest">Runs entirely in your browser. Nothing is uploaded. Evidence files are hashed in your browser and never uploaded; only name, size and SHA-256 are kept. Control catalogs are read from this site (/data/controls).</div>',
    '<div class="', P, '-exbar" id="', P, '-exbar"></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div>',
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-tabs" role="tablist" id="', P, '-tabs"></div>',
    '<div id="', P, '-pane"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div>',
    '<div class="', P, '-card"><h2>Export and share</h2><p class="', P, '-help">Register exports include every saved control. The calendar covers the configured horizon. The Security Graph receives the findings above (overdue evidence, missing owners, missing evidence, expired exceptions).</p>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button><span class="', P, '-mut" id="', P, '-team"></span></div></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  const reg = openRegister(TOOL_ID, "CONTROL", { schema: REGISTER_SCHEMA });
  const S = {
    tab: "overview", catalogs: null, catErr: "", example: null, result: null, graph: null, graphErr: "",
    program: loadProgram(), thresholds: { ...DEFAULTS }, sort: {}, filter: { fw: "", status: "", owner: "", q: "", due: "" },
    openId: null, findingSel: null, calMonth: null, scopePreview: null, importParsed: null, runSeq: 0,
  };
  $("team").textContent = isTeam() ? "Team workspace: every member sees the same register through the Security Graph." : "Personal workspace. Switch to a team workspace to share this register.";

  const records = () => (S.example ? S.example.records : reg.list().map(normalizeRecord));
  const nowIso = () => (S.example ? S.example.now : todayIso());
  const who = () => { try { const u = window.firebase && window.firebase.auth && window.firebase.auth().currentUser; return (u && u.email) || ""; } catch (_) { return ""; } };

  function loadProgram() {
    try { const v = JSON.parse(localStorage.getItem(wsKey(PROGRAM_KEY)) || "null"); if (v && typeof v === "object") return v; } catch (_) {}
    return { org: "", frameworks: [], soc2Categories: [], cisIG: 1, pciLevels: ["sub", "req"], pciLabel: "" };
  }
  function saveProgram() { try { localStorage.setItem(wsKey(PROGRAM_KEY), JSON.stringify(S.program)); } catch (_) {} }

  // ---- catalogs + graph ---------------------------------------------------
  async function loadCatalogs() {
    const out = {};
    const errs = [];
    await Promise.all(FRAMEWORKS.map(async (f) => {
      try { const r = await fetch("/data/controls/" + f.key + ".json", { cache: "no-cache" }); if (!r.ok) throw new Error("HTTP " + r.status); out[f.key] = await r.json(); }
      catch (e) { errs.push(f.label + ": " + (e && e.message || e)); }
    }));
    S.catalogs = out; S.catErr = errs.join("; ");
  }
  async function loadGraph() {
    try {
      const sg = await import("/js/security-graph.js");
      const list = sg.listEntities({ type: ["FINDING", "CONTROL", "ASSET"] }) || [];
      S.graph = list.map((e) => ({
        id: e.id, type: e.type, name: e.name, source: e.source || "", severity: e.severity || "", tags: e.tags || [], createdAt: e.createdAt || "", updatedAt: e.updatedAt || "",
        data: { _toolSource: e.data && e.data._toolSource, tool: e.data && e.data.tool, _simulated: e.data && e.data._simulated },
      }));
      S.graphErr = "";
    } catch (e) { S.graph = []; S.graphErr = "Security Graph could not be read: " + (e && e.message || e); }
  }

  // ---- analysis -----------------------------------------------------------
  let timer = null;
  function refresh(delay = 60) { clearTimeout(timer); timer = setTimeout(runAnalysis, delay); }
  async function runAnalysis() {
    const seq = ++S.runSeq;
    const prog = $("prog"), bar = prog.firstElementChild;
    const recs = records();
    const showProg = recs.length > 400;
    if (showProg) { prog.style.display = "block"; bar.style.width = "0%"; }
    try {
      const graphRuns = S.example ? S.example.graphRuns : S.graph || [];
      const r = await runInWorker(ENGINE, "analyze", [{ records: recs, catalogs: S.catalogs || {}, graphRuns }, { ...S.thresholds, now: nowIso() }], {
        onProgress: (i, n) => { bar.style.width = (n ? Math.round((i / n) * 100) : 0) + "%"; },
      });
      if (seq !== S.runSeq) return;
      S.result = r;
      renderAll();
    } catch (e) {
      toast("Analysis failed: " + (e && e.message || e), "error");
    } finally { if (showProg) prog.style.display = "none"; }
  }

  // ---- record writes ------------------------------------------------------
  function saveRec(rec) {
    rec = normalizeRecord(rec);
    if (S.example) {
      const i = S.example.records.findIndex((r) => r.id === rec.id);
      if (i >= 0) S.example.records[i] = rec; else S.example.records.push(rec);
      return rec;
    }
    return reg.upsert(rec);
  }
  function removeRec(id) {
    if (S.example) { S.example.records = S.example.records.filter((r) => r.id !== id); return; }
    reg.remove(id);
  }
  const getRec = (id) => records().find((r) => r.id === id) || null;

  // ---- top-level render ---------------------------------------------------
  const TABS = [["overview", "Overview"], ["controls", "Controls"], ["calendar", "Calendar"], ["suggestions", "Suggestions"], ["setup", "Setup"], ["package", "Package"]];
  function renderAll() {
    const r = S.result;
    const s = r ? r.summary : null;
    $("kpis").innerHTML = s ? [
      kpi(s.inScope, "In scope"), kpi(s.ready, "Collected and current"), kpi(s.overdue, "Overdue", s.overdue > 0), kpi(s.dueSoon, "Due in " + S.thresholds.dueSoonDays + " days"),
      kpi(s.exceptions, "Exceptions", s.exceptionsExpired > 0), kpi(s.noOwner, "No owner"), kpi(s.evidenceItems, "Evidence items"),
    ].join("") : "";
    const sugg = r ? r.suggestions.length : 0;
    $("tabs").innerHTML = TABS.map(([k, l]) => '<button class="' + P + "-tab" + (S.tab === k ? " on" : "") + '" role="tab" data-tab="' + k + '">' + esc(l) + (k === "suggestions" && sugg ? "<b>" + sugg + "</b>" : "") + "</button>").join("");
    $("exbar").style.display = S.example ? "block" : "none";
    if (S.example) {
      $("exbar").innerHTML = "<b>Synthetic example: " + esc(S.example.org) + ".</b> Not saved. Dates are relative to " + esc(S.example.now) + '. <span class="' + P + '-row" style="display:inline-flex;margin:0 0 0 6px"><button class="' + P + '-btn sm" data-act="ex-save">Save example to register</button><button class="' + P + '-btn sm" data-act="ex-close">Close example</button></span>';
    }
    renderExports();
    const pane = $("pane");
    if (S.tab === "overview") pane.innerHTML = paneOverview();
    else if (S.tab === "controls") pane.innerHTML = paneControls();
    else if (S.tab === "calendar") pane.innerHTML = paneCalendar();
    else if (S.tab === "suggestions") pane.innerHTML = paneSuggestions();
    else if (S.tab === "setup") { pane.innerHTML = paneSetup(); mountImport(); }
    else if (S.tab === "package") pane.innerHTML = panePackage();
    if (S.openId && !getRec(S.openId)) S.openId = null;
    renderDrawer();
  }

  function renderExports() {
    const ex = $("exports");
    ex.innerHTML = ["reg-csv:Register CSV", "reg-json:Register JSON", "find-csv:Findings CSV", "txt:Summary TXT", "ics:Calendar .ics", "zip:Auditor package (.zip)", "full-json:Analysis JSON"]
      .map((x) => { const [k, l] = x.split(":"); return '<button class="' + P + '-btn" data-act="x-' + k + '">' + esc(l) + "</button>"; }).join("");
    const r = S.result;
    attachSinkButton(ex, () => ({ findings: r ? r.findings : [], sample: !!S.example }), TOOL_ID, { dataset: S.example ? S.example.label : "Control Evidence register" });
  }

  // ---- table helper -------------------------------------------------------
  function sortRows(rows, key, cols) {
    const st = S.sort[key];
    if (!st) return rows;
    const col = cols.find((c) => c.k === st.k);
    const val = col && col.sv ? col.sv : (x) => x[st.k];
    return rows.slice().sort((a, b) => { const va = val(a), vb = val(b); const c = typeof va === "number" && typeof vb === "number" ? va - vb : cmp(String(va ?? ""), String(vb ?? "")); return st.asc ? c : -c; });
  }
  function table(key, cols, rows, { rowAttr, empty } = {}) {
    if (!rows.length) return '<div class="' + P + '-tbl"><div class="' + P + '-empty">' + esc(empty || "Nothing to show.") + "</div></div>";
    const st = S.sort[key] || {};
    const sorted = sortRows(rows, key, cols);
    return '<div class="' + P + '-tbl"><table><thead><tr>' + cols.map((c) => "<th" + (c.nosort ? "" : ' data-sort="' + esc(key) + '" data-k="' + esc(c.k) + '"') + (st.k === c.k ? ' class="sorted' + (st.asc ? " asc" : "") + '"' : "") + ">" + esc(c.l) + "</th>").join("") + "</tr></thead><tbody>" +
      sorted.map((r) => "<tr" + (rowAttr ? rowAttr(r) : "") + ">" + cols.map((c) => "<td>" + (c.h ? c.h(r) : esc(r[c.k])) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
  }
  const dueCell = (r) => {
    if (!r.nextDue) return '<span class="' + P + '-mut">' + (r.frequency === "on-event" ? "on event" : "not set") + "</span>";
    const cls = r.daysOverdue > 0 ? " over" : r.nextDue <= addDays(S.result.summary.now, S.thresholds.dueSoonDays) ? " soon" : "";
    return '<span class="' + P + "-due" + cls + '">' + esc(r.nextDue) + "</span>" + (r.daysOverdue > 0 ? '<div class="' + P + '-mut">' + r.daysOverdue + " d overdue</div>" : "") + (r.dueSource === "override" ? '<div class="' + P + '-mut">override</div>' : "");
  };

  // ---- Overview -----------------------------------------------------------
  function paneOverview() {
    const r = S.result;
    if (!r) return '<div class="' + P + '-card"><div class="' + P + '-empty">Loading.</div></div>';
    if (!r.summary.inScope) {
      return '<div class="' + P + '-card"><h2>No controls in scope yet</h2><p class="' + P + '-help">Open Setup to pick frameworks and create one record per control from the catalogs, import an existing evidence spreadsheet, or load the synthetic example.</p><div class="' + P + '-row"><button class="' + P + '-btn pri" data-tab="setup">Open Setup</button></div></div>';
    }
    const bars = r.tables.readiness.map((x) => {
      const rp = (x.ready / x.inScope) * 100, ep = (x.exceptions / x.inScope) * 100;
      return '<div class="' + P + '-bar"><b>' + esc(x.label) + '</b><div class="trk" role="img" aria-label="' + esc(x.label + " " + x.pct + "% ready") + '"><i class="rd" style="width:' + rp.toFixed(1) + '%"></i><i class="ex" style="width:' + ep.toFixed(1) + '%"></i></div><b>' + x.pct.toFixed(1) + "%</b>" +
        "<small>" + x.ready + " of " + x.inScope + " ready, " + x.exceptions + " exception(s), " + x.overdue + " overdue</small></div>";
    }).join("");
    const fcols = [
      { k: "severity", l: "Severity", sv: (f) => SEV_RANK[f.severity] || 0, h: (f) => '<span class="' + P + "-pill " + esc(f.severity) + '">' + esc(f.severity) + "</span>" },
      { k: "title", l: "Finding", h: (f) => "<b>" + esc(f.title) + '</b><div class="' + P + '-mut">' + esc(f.description) + "</div>" },
      { k: "confidence", l: "Confidence" },
      { k: "controls", l: "Controls", nosort: true, h: (f) => (f.controls || []).slice(0, 6).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + ((f.controls || []).length > 6 ? '<span class="' + P + '-mut">+' + (f.controls.length - 6) + "</span>" : "") },
      { k: "evidenceCount", l: "Evidence", sv: (f) => f.evidenceCount || 0, h: (f) => esc(f.evidenceCount ?? (f.evidence || []).length) },
    ];
    const fr = r.findings.map((f, i) => ({ ...f, _i: i }));
    const cov = table("cov", [
      { k: "label", l: "Framework" }, { k: "domain", l: "Domain" }, { k: "inScope", l: "In scope" }, { k: "ready", l: "Ready" },
      { k: "pct", l: "Ready %", h: (x) => x.pct.toFixed(1) + "%" },
    ], r.tables.coverageByDomain);
    const soon = table("soon", [
      { k: "nextDue", l: "Due" }, { k: "refsText", l: "Controls", h: (x) => chips(x.refs) }, { k: "title", l: "Title" }, { k: "owner", l: "Owner", h: (x) => esc(x.owner || "(none)") },
    ], r.tables.dueSoon, { rowAttr: (x) => ' class="' + P + '-click" data-open="' + esc(x.id) + '"', empty: "Nothing due in the window." });
    const exp = table("exp", [
      { k: "expires", l: "Expires" }, { k: "refsText", l: "Controls" }, { k: "reason", l: "Reason" }, { k: "approvedBy", l: "Approved by" },
    ], r.tables.exceptionsExpiring.concat(r.tables.exceptionsExpired.map((x) => ({ ...x, expires: x.expires + " (expired)" }))), { rowAttr: (x) => ' class="' + P + '-click" data-open="' + esc(x.id) + '"', empty: "No exceptions expiring or expired." });
    const thr = Object.keys(DEFAULT_LABELS).map((k) => field("t-" + k, DEFAULT_LABELS[k][0], '<input type="number" min="0" id="' + P + "-t-" + k + '" data-thr="' + k + '" value="' + esc(S.thresholds[k]) + '">', DEFAULT_LABELS[k][1] + " Default " + DEFAULTS[k] + ".")).join("") +
      field("t-continuousPeriod", "Continuous controls: fresh sample every", '<select id="' + P + '-t-continuousPeriod" data-thr="continuousPeriod">' + opts([["daily", "Day"], ["weekly", "Week"], ["monthly", "Month"], ["quarterly", "Quarter"]], S.thresholds.continuousPeriod) + "</select>", "Continuous controls have no natural period; this sets how fresh their sample evidence must be. Default month.");
    const skipped = r.skipped.length ? '<div class="' + P + '-skip">Not run: ' + r.skipped.map((x) => esc(x.check + " (" + x.reason + ")")).join("; ") + "</div>" : "";
    const unknown = r.tables.unknownRefs.length ? '<div class="' + P + '-skip">Control ids not found in the loaded catalogs: ' + r.tables.unknownRefs.map((x) => esc(x.unknown)).join("; ") + "</div>" : "";
    return [
      '<div class="', P, '-card"><h2>Readiness per framework</h2><p class="', P, '-help">Ready = status collected or accepted by auditor AND the newest evidence is inside its current period. Exceptions are shown separately and do not count as ready. As of ', esc(r.summary.now), ".</p>",
      '<div class="', P, '-bars" style="margin-top:10px">', bars, "</div>",
      '<div class="', P, '-legend"><span><i style="background:#1b7f4d"></i>ready</span><span><i style="background:#b58100"></i>exception</span><span><i style="background:var(--bg,#f7f8fb);border:1px solid var(--line,#e6e8ee)"></i>not ready</span></div>', skipped, unknown, "</div>",
      '<div class="', P, '-card"><h2>Findings</h2><p class="', P, '-help">Click a finding for its evidence rows.</p>',
      table("find", fcols, fr, { rowAttr: (f) => ' class="' + P + "-click" + (S.findingSel === f._i ? " sel" : "") + '" data-finding="' + f._i + '"', empty: "No findings: nothing overdue, every control has an owner and evidence, no expired exceptions." }),
      '<div id="', P, '-fdrawer">', findingDrawer(), "</div></div>",
      '<div class="', P, '-card"><h2>Due in the next ', esc(S.thresholds.dueSoonDays), " days</h2>", soon, "<h3>Exceptions expiring or expired</h3>", exp, "</div>",
      '<div class="', P, '-card"><h2>Coverage by domain</h2>', cov, "</div>",
      '<div class="', P, '-card"><details><summary>Thresholds</summary><div class="', P, '-grid" style="margin-top:10px">', thr, '</div><div class="', P, '-row"><button class="', P, '-btn" data-act="thr-reset">Reset to defaults</button></div></details></div>',
    ].join("");
  }
  function findingDrawer() {
    const r = S.result;
    if (!r || S.findingSel == null || !r.findings[S.findingSel]) return "";
    const f = r.findings[S.findingSel];
    const ev = f.evidence || [];
    const keys = Array.from(new Set(ev.flatMap((e) => Object.keys(e))));
    return '<div class="' + P + '-drawer" style="display:block"><h2>' + esc(f.title) + '</h2><p class="' + P + '-help">' + esc(f.recommendation) + "</p>" +
      '<div class="' + P + '-row" style="margin-bottom:8px">' + (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</div>" +
      (ev.length ? '<div class="' + P + '-tbl"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" + ev.map((e) => "<tr>" + keys.map((k) => "<td>" + esc(e[k]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>" : "") +
      ((f.evidenceCount || 0) > ev.length ? '<p class="' + P + '-help">Showing ' + ev.length + " of " + f.evidenceCount + " rows.</p>" : "") + "</div>";
  }

  // ---- Controls -----------------------------------------------------------
  function paneControls() {
    const r = S.result;
    if (!r) return "";
    const F = S.filter;
    const owners = Array.from(new Set(r.tables.controls.map((x) => x.owner).filter(Boolean))).sort();
    let rows = r.tables.controls;
    if (F.fw) rows = rows.filter((x) => x.refs.some((y) => y.fw === F.fw));
    if (F.status) rows = rows.filter((x) => x.status === F.status);
    if (F.owner === "__none") rows = rows.filter((x) => !x.owner); else if (F.owner) rows = rows.filter((x) => x.owner === F.owner);
    if (F.due === "overdue") rows = rows.filter((x) => x.daysOverdue > 0 && !x.exception);
    else if (F.due === "soon") rows = r.tables.dueSoon.filter((x) => rows.includes(x));
    else if (F.due === "noev") rows = rows.filter((x) => !x.evidenceCount);
    else if (F.due === "stale") rows = rows.filter((x) => x.last && !x.current);
    if (F.q) { const q = F.q.toLowerCase(); rows = rows.filter((x) => (x.refsText + " " + x.title + " " + x.domain + " " + x.owner).toLowerCase().includes(q)); }
    const fws = FRAMEWORKS.filter((f) => r.tables.controls.some((x) => x.refs.some((y) => y.fw === f.key)));
    const cols = [
      { k: "refsText", l: "Controls", h: (x) => chips(x.refs) },
      { k: "title", l: "Title", h: (x) => esc(x.title) + (x.domain ? '<div class="' + P + '-mut">' + esc(x.domain) + "</div>" : "") },
      { k: "owner", l: "Owner", h: (x) => (x.owner ? esc(x.owner) : '<span class="' + P + '-mut">none</span>') },
      { k: "frequency", l: "Frequency", h: (x) => esc(FREQ_LABEL[x.frequency]) },
      { k: "nextDue", l: "Next due", h: dueCell },
      { k: "status", l: "Status", h: (x) => stPill(x.status) + (x.exception ? '<div class="' + P + '-mut">exception to ' + esc(x.exception.expires || "no expiry") + "</div>" : "") },
      { k: "evidenceCount", l: "Evidence", h: (x) => esc(x.evidenceCount) + (x.last ? '<div class="' + P + '-mut">last ' + esc(x.last) + (x.current ? "" : ", stale") + "</div>" : "") },
    ];
    return [
      '<div class="', P, '-card"><div class="', P, '-filters">',
      '<select data-filter="fw" aria-label="Framework"><option value="">All frameworks</option>', opts(fws.map((f) => [f.key, f.label]), F.fw), "</select>",
      '<select data-filter="status" aria-label="Status"><option value="">All statuses</option>', opts(STATUSES.map((s) => [s, STATUS_LABEL[s]]), F.status), "</select>",
      '<select data-filter="owner" aria-label="Owner"><option value="">All owners</option><option value="__none"', F.owner === "__none" ? " selected" : "", ">No owner</option>", opts(owners.map((o) => [o, o]), F.owner), "</select>",
      '<select data-filter="due" aria-label="Due"><option value="">Any due state</option>', opts([["overdue", "Overdue"], ["soon", "Due soon"], ["stale", "Stale evidence"], ["noev", "No evidence"]], F.due), "</select>",
      '<input type="search" data-filter="q" placeholder="Search" aria-label="Search controls" value="', esc(F.q), '">',
      "</div>",
      '<p class="', P, '-help">', rows.length, " of ", r.tables.controls.length, " in-scope controls. Click a row to open its evidence, exceptions and history.", r.tables.exclusions.length ? " " + r.tables.exclusions.length + " control(s) are out of scope (see Package)." : "", "</p>",
      '<div style="margin-top:8px">', table("ctl", cols, rows, { rowAttr: (x) => ' class="' + P + "-click" + (S.openId === x.id ? " sel" : "") + '" data-open="' + esc(x.id) + '"', empty: "No controls match the filters." }), "</div></div>",
    ].join("");
  }

  // ---- Control drawer -----------------------------------------------------
  function renderDrawer() {
    const d = $("drawer");
    const rec = S.openId ? getRec(S.openId) : null;
    if (!rec) { d.style.display = "none"; d.innerHTML = ""; return; }
    const row = (S.result && S.result.tables.controls.find((x) => x.id === rec.id)) || {};
    const cat = rec.refs.map((ref) => S.catalogs && S.catalogs[ref.fw] && (S.catalogs[ref.fw].data || []).find((x) => x.id === ref.id)).filter(Boolean);
    const hints = Array.from(new Set(cat.flatMap((c) => c.evidenceHints || []).concat(rec.evidenceHints || [])));
    const evRows = rec.evidence.map((e, i) => ({ ...e, _i: i }));
    const evTable = evRows.length ? '<div class="' + P + '-tbl"><table><thead><tr><th>Name</th><th>Kind</th><th>SHA-256</th><th>Size</th><th>Collected</th><th>By</th><th>Note / link</th><th></th></tr></thead><tbody>' +
      evRows.map((e) => "<tr><td>" + esc(e.name) + "</td><td>" + esc(e.kind || "file") + (e.kind === "tool run" ? '<div class="' + P + '-mut">' + esc(e.findingCount) + " finding(s)</div>" : "") + '</td><td class="' + P + '-mono">' + (e.sha256 ? esc(e.sha256) : '<span class="' + P + '-mut">none</span>') + "</td><td>" + esc(fmtBytes(e.size)) + "</td><td>" + esc(e.collectedAt) + "</td><td>" + esc(e.collectedBy) + "</td><td>" + esc(e.note) +
        (e.link ? '<div><a href="' + esc(safeUrl(e.link)) + '" target="_blank" rel="noopener noreferrer">' + esc(e.link) + "</a></div>" : "") + '</td><td><button class="' + P + '-btn sm dang" data-act="ev-del" data-i="' + e._i + '">Remove</button></td></tr>').join("") + "</tbody></table></div>"
      : '<p class="' + P + '-help">No evidence yet.</p>';
    const excs = rec.exceptions.length ? '<div class="' + P + '-tbl"><table><thead><tr><th>Reason</th><th>Approved by</th><th>Expires</th><th></th></tr></thead><tbody>' + rec.exceptions.map((x, i) => "<tr><td>" + esc(x.reason) + "</td><td>" + esc(x.approvedBy) + "</td><td>" + esc(x.expires || "no expiry") + (toDay(x.expires) && toDay(x.expires) < nowIso() ? ' <span class="' + P + '-due over">expired</span>' : "") + '</td><td><button class="' + P + '-btn sm dang" data-act="exc-del" data-i="' + i + '">Remove</button></td></tr>').join("") + "</tbody></table></div>" : '<p class="' + P + '-help">No exceptions.</p>';
    const fwOpts = FRAMEWORKS.filter((f) => S.catalogs && S.catalogs[f.key]).map((f) => [f.key, f.label]);
    const hist = rec.history.slice().reverse().map((h) => "<li><b>" + esc(String(h.at).slice(0, 16).replace("T", " ")) + "</b> " + esc(h.action) + (h.by ? ' <span class="' + P + '-mut">' + esc(h.by) + "</span>" : "") + "</li>").join("");
    d.style.display = "block";
    d.innerHTML = [
      '<div class="', P, '-row" style="margin-top:0;justify-content:space-between"><div style="min-width:0"><h2>', esc(rec.title || refsLabel(rec.refs)), "</h2>", chips(rec.refs), rec.domain ? ' <span class="' + P + '-mut">' + esc(rec.domain) + "</span>" : "", "</div>",
      '<button class="', P, '-btn sm" data-act="drawer-close">Close</button></div>',
      '<dl class="', P, '-dl"><dt>Next due</dt><dd>', row.nextDue ? esc(row.nextDue) + (row.dueSource === "override" ? " (override)" : row.dueSource === "first" ? " (first collection after scoping)" : " (last collected " + esc(row.last) + " + " + esc(FREQ_LABEL[rec.frequency].toLowerCase()) + ")") : rec.frequency === "on-event" ? "on event (no fixed date)" : "not set", "</dd>",
      "<dt>Evidence current</dt><dd>", row.current ? "yes, period ends " + esc(row.periodEnd || "") : row.last ? "no, stale since " + esc(row.nextDue || "") : "no evidence yet", "</dd>",
      rec.assessment ? "<dt>Assessment</dt><dd>" + esc(rec.assessment) + "</dd>" : "",
      hints.length ? "<dt>Evidence hints</dt><dd>" + hints.map(esc).join("; ") + "</dd>" : "", "</dl>",
      "<h3>Control</h3><div class=\"", P, '-grid">',
      field("d-owner", "Owner", '<input type="email" id="' + P + '-d-owner" placeholder="owner@company" value="' + esc(rec.owner) + '">', "Accountable for collecting the evidence."),
      field("d-freq", "Frequency", '<select id="' + P + '-d-freq">' + opts(FREQUENCIES.map((f) => [f, FREQ_LABEL[f]]), rec.frequency) + "</select>", "Next due = last collected + frequency (month end clamps)."),
      field("d-status", "Status", '<select id="' + P + '-d-status">' + opts(STATUSES.map((s) => [s, STATUS_LABEL[s]]), rec.status) + "</select>"),
      field("d-due", "Due date override", '<input type="date" id="' + P + '-d-due" value="' + esc(rec.dueOverride) + '">', "Leave empty to compute it."),
      field("d-notes", "Notes", '<textarea id="' + P + '-d-notes">' + esc(rec.notes) + "</textarea>", "", true),
      "</div>",
      '<div class="', P, '-row"><button class="', P, '-btn pri" data-act="rec-save">Save control</button><button class="', P, '-btn" data-act="rec-out">Mark out of scope</button><button class="', P, '-btn dang" data-act="rec-del">Delete from register</button></div>',
      "<h3>Evidence</h3>", evTable,
      '<div class="', P, '-grid" style="margin-top:10px">',
      field("e-by", "Collected by", '<input type="email" id="' + P + '-e-by" placeholder="name@company" value="' + esc(who() || rec.owner) + '">'),
      field("e-at", "Collected on", '<input type="date" id="' + P + '-e-at" value="' + esc(nowIso()) + '">', "The date the evidence was produced or pulled."),
      field("e-note", "Note", '<input type="text" id="' + P + '-e-note" placeholder="Optional">'),
      "</div>",
      '<div class="', P, '-drop" id="', P, '-evdrop" tabindex="0" role="button" aria-label="Attach evidence files">Drop evidence files here or click to choose. Each file is hashed (SHA-256) in this browser and then discarded; it is not uploaded or stored. Up to 512 MB per file: the browser hashing API needs the whole file in memory and has no streaming mode.<input type="file" multiple id="', P, '-evfile" style="display:none"></div>',
      '<div id="', P, '-hashes"></div>',
      '<div class="', P, '-grid" style="margin-top:10px">',
      field("l-name", "Evidence link name", '<input type="text" id="' + P + '-l-name" placeholder="e.g. Q3 access review ticket">'),
      field("l-url", "Link URL", '<input type="url" id="' + P + '-l-url" placeholder="https://">', "For evidence held in another system."),
      '</div><div class="', P, '-row"><button class="', P, '-btn" data-act="link-add">Add link evidence</button></div>',
      "<h3>Exceptions</h3>", excs,
      '<div class="', P, '-grid" style="margin-top:10px">',
      field("x-reason", "Reason", '<input type="text" id="' + P + '-x-reason" placeholder="Why the control cannot operate">'),
      field("x-by", "Approved by", '<input type="email" id="' + P + '-x-by" placeholder="approver@company">'),
      field("x-exp", "Expires", '<input type="date" id="' + P + '-x-exp">', "Empty means no expiry (not recommended)."),
      '</div><div class="', P, '-row"><button class="', P, '-btn" data-act="exc-add">Add exception</button></div>',
      "<h3>Link another framework control</h3>",
      '<p class="', P, '-help">', S.catalogs && catalogsHaveCrosswalk(S.catalogs) ? "The catalogs carry mappings; you can still link by hand." : "The loaded catalogs carry no cross-framework mapping, so links are made by hand. One record can satisfy several framework ids; if a separate record exists for the id you link, the two are merged.", "</p>",
      '<div class="', P, '-grid">',
      field("k-fw", "Framework", '<select id="' + P + '-k-fw">' + opts(fwOpts, fwOpts[0] && fwOpts[0][0]) + "</select>"),
      field("k-id", "Control id", '<input type="text" id="' + P + '-k-id" list="' + P + '-k-list" placeholder="e.g. 5.18" autocomplete="off"><datalist id="' + P + '-k-list"></datalist>'),
      '</div><div class="', P, '-row"><button class="', P, '-btn" data-act="link-ref">Link control</button>',
      rec.refs.length > 1 ? rec.refs.map((x, i) => '<button class="' + P + '-btn sm" data-act="unlink" data-i="' + i + '">Unlink ' + esc(fwLabel(x.fw) + " " + x.id) + "</button>").join("") : "", "</div>",
      "<h3>History</h3>", hist ? '<ul class="' + P + '-hist">' + hist + "</ul>" : '<p class="' + P + '-help">No history.</p>',
    ].join("");
    fillIdList();
    const drop = $("evdrop"), input = $("evfile");
    drop.addEventListener("click", (e) => { if (e.target !== input) input.click(); });
    drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
    drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); attachFiles(Array.from(e.dataTransfer.files || [])); });
    input.addEventListener("change", () => { attachFiles(Array.from(input.files || [])); input.value = ""; });
    $("k-fw").addEventListener("change", fillIdList);
  }
  function fillIdList() {
    const fw = $("k-fw") && $("k-fw").value;
    const dl = $("k-list");
    if (!dl) return;
    const data = (S.catalogs && S.catalogs[fw] && S.catalogs[fw].data) || [];
    dl.innerHTML = data.map((x) => '<option value="' + esc(x.id) + '">' + esc(x.id + " " + x.title) + "</option>").join("");
  }
  const safeUrl = (u) => (/^https?:\/\//i.test(String(u)) ? String(u) : "#");

  async function hashFile(file, onProgress) {
    if (file.size > MAX_HASH_BYTES) throw new Error("over the 512 MB per-file limit");
    const buf = new Uint8Array(file.size);
    let off = 0;
    if (file.stream) {
      const rd = file.stream().getReader();
      for (;;) {
        const { done, value } = await rd.read();
        if (done) break;
        buf.set(value, off); off += value.length;
        onProgress(off / Math.max(1, file.size) * 0.9);
      }
    } else { buf.set(new Uint8Array(await file.arrayBuffer())); }
    onProgress(0.95);
    const h = await sha256Hex(buf);
    onProgress(1);
    return h;
  }
  async function attachFiles(files) {
    const rec = getRec(S.openId);
    if (!rec || !files.length) return;
    const box = $("hashes");
    const by = ($("e-by").value || "").trim(), at = toDay($("e-at").value) || nowIso(), note = ($("e-note").value || "").trim();
    const added = [];
    for (const f of files) {
      const line = document.createElement("div");
      line.className = P + "-hash";
      line.innerHTML = "<span>" + esc(f.name) + " (" + esc(fmtBytes(f.size)) + "): hashing</span><div class=\"trk\"><i></i></div>";
      box.appendChild(line);
      const bar = line.querySelector("i"), lbl = line.querySelector("span");
      try {
        const sha = await hashFile(f, (p) => { bar.style.width = Math.round(p * 100) + "%"; });
        added.push({ kind: "file", name: f.name, size: f.size, type: f.type || "", sha256: sha, collectedAt: at, collectedBy: by, note, link: "" });
        lbl.innerHTML = esc(f.name) + ': <span class="' + P + '-mono">' + esc(sha) + "</span>";
      } catch (e) {
        lbl.textContent = f.name + ": not attached (" + (e && e.message || e) + ")";
        bar.style.background = "#b00020"; bar.style.width = "100%";
      }
    }
    if (!added.length) return;
    const cur = normalizeRecord(getRec(S.openId));
    for (const a of added) {
      if (cur.evidence.some((e) => e.sha256 && e.sha256 === a.sha256)) { toast(a.name + " is already attached (same SHA-256)", "warning"); continue; }
      cur.evidence.push(a);
      addHistory(cur, new Date().toISOString(), "Evidence attached: " + a.name + " sha256 " + a.sha256.slice(0, 16) + "...", by);
    }
    if (cur.status === "not-started" || cur.status === "collecting") cur.status = "collected";
    saveRec(cur);
    toast(added.length + " file(s) hashed and recorded" + (S.example ? " (example, not saved)" : ""), "success");
    refresh(0);
  }

  // ---- Calendar -----------------------------------------------------------
  function paneCalendar() {
    const r = S.result;
    if (!r) return "";
    const now = r.summary.now;
    const ym = S.calMonth || now.slice(0, 7);
    const [y, m] = ym.split("-").map(Number);
    const first = ym + "-01";
    const startDow = (new Date(Date.UTC(y, m - 1, 1)).getUTCDay() + 6) % 7; // Monday first
    const days = new Date(Date.UTC(y, m, 0)).getUTCDate();
    const items = r.tables.calendar;
    const byDay = new Map();
    for (const it of items) { if (!byDay.has(it.date)) byDay.set(it.date, []); byDay.get(it.date).push(it); }
    const cells = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((d) => '<div class="hd">' + d + "</div>");
    const gridStart = addDays(first, -startDow);
    const total = Math.ceil((startDow + days) / 7) * 7;
    for (let i = 0; i < total; i++) {
      const d = addDays(gridStart, i);
      const its = byDay.get(d) || [];
      cells.push('<div class="' + (d.slice(0, 7) !== ym ? "out" : "") + (d === now ? " today" : "") + '"><div class="dn">' + Number(d.slice(8)) + "</div>" +
        (its.length ? '<span class="cnt">' + its.length + "</span>" : "") +
        its.slice(0, 4).map((x) => '<span class="it ' + (x.kind === "overdue" ? "overdue" : "") + '" data-open="' + esc(x.recordId) + '" title="' + esc(x.refsText + ": " + x.title) + '">' + esc(x.refsText) + "</span>").join("") +
        (its.length > 4 ? '<span class="' + P + '-mut">+' + (its.length - 4) + "</span>" : "") + "</div>");
    }
    const monthName = new Date(Date.UTC(y, m - 1, 1)).toLocaleString("en-US", { month: "long", year: "numeric", timeZone: "UTC" });
    const inMonth = items.filter((x) => x.date.slice(0, 7) === ym);
    const overdue = items.filter((x) => x.kind === "overdue");
    return [
      '<div class="', P, '-card"><div class="', P, '-calnav"><button class="', P, '-btn sm" data-act="cal-prev">Previous</button><b>', esc(monthName), '</b><button class="', P, '-btn sm" data-act="cal-next">Next</button><button class="', P, '-btn sm" data-act="cal-today">This month</button><button class="', P, '-btn sm" data-act="x-ics">Export .ics</button></div>',
      '<p class="', P, '-help">Due dates for the next ', esc(S.thresholds.calendarMonths), " months, projected from each control's frequency. Overdue items sit on their original due date. Daily controls appear as weekly checkpoints. Items under an active exception are left out.</p>",
      '<div class="', P, '-cal" style="margin-top:10px">', cells.join(""), "</div></div>",
      '<div class="', P, '-card"><h2>', esc(monthName), "</h2>",
      table("calm", [{ k: "date", l: "Date" }, { k: "kind", l: "Kind" }, { k: "refsText", l: "Controls" }, { k: "title", l: "Title" }, { k: "owner", l: "Owner", h: (x) => esc(x.owner || "(none)") }], inMonth,
        { rowAttr: (x) => ' class="' + P + '-click" data-open="' + esc(x.recordId) + '"', empty: "Nothing due this month." }),
      overdue.length ? "<h3>Overdue (" + overdue.length + ")</h3>" + table("calo", [{ k: "date", l: "Was due" }, { k: "refsText", l: "Controls" }, { k: "title", l: "Title" }, { k: "owner", l: "Owner", h: (x) => esc(x.owner || "(none)") }], overdue, { rowAttr: (x) => ' class="' + P + '-click" data-open="' + esc(x.recordId) + '"' }) : "",
      "</div>",
    ].join("");
  }

  // ---- Suggestions --------------------------------------------------------
  function paneSuggestions() {
    const r = S.result;
    if (!r) return "";
    const src = S.example ? "synthetic tool runs bundled with the example" : "Security Graph in this browser (FINDING, CONTROL and ASSET entities written by Deck tools; sample data ignored)";
    const tools = Object.entries(TOOL_EVIDENCE_MAP).map(([k, v]) => "<tr><td>" + esc(v.label) + '</td><td class="' + P + '-mono">' + esc(k) + "</td><td>" + Object.entries(v.refs).map(([fw, ids]) => ids.map((id) => '<span class="' + P + '-chip">' + esc(fwLabel(fw) + " " + id) + "</span>").join("")).join("") + "</td></tr>").join("");
    return [
      '<div class="', P, '-card"><h2>Evidence suggested from tool runs</h2><p class="', P, '-help">Source: ', esc(src), ". A tool run is every entity a Deck tool wrote on one day. Accepting a suggestion attaches it as a \"tool run\" evidence item (tool, run date, finding count) to that control. Nothing is attached automatically.</p>",
      S.graphErr ? '<div class="' + P + '-skip">' + esc(S.graphErr) + "</div>" : "",
      '<div class="', P, '-row"><button class="', P, '-btn" data-act="graph-reload"', S.example ? " disabled" : "", ">Re-read Security Graph</button></div>",
      '<div style="margin-top:10px">',
      table("sug", [
        { k: "runDate", l: "Run date" }, { k: "toolLabel", l: "Tool" }, { k: "findingCount", l: "Findings" },
        { k: "refsText", l: "Control", h: (x) => chips(x.refs) }, { k: "title", l: "Title" },
        { k: "key", l: "", nosort: true, h: (x) => '<button class="' + P + '-btn sm pri" data-act="sug-accept" data-key="' + esc(x.key) + '">Accept</button>' },
      ], r.suggestions, { empty: "No suggestions: no tool runs in the Security Graph match an in-scope control, or they are already attached." }),
      "</div></div>",
      '<div class="', P, '-card"><details><summary>Mapping used (tool to control ids)</summary><p class="', P, '-help">A small explicit table; every id exists in the shipped catalogs. A tool run is a candidate, not proof: review it before accepting.</p><div class="', P, '-tbl"><table><thead><tr><th>Tool</th><th>Source id</th><th>Controls</th></tr></thead><tbody>', tools, "</tbody></table></div></details></div>",
    ].join("");
  }

  // ---- Setup --------------------------------------------------------------
  function paneSetup() {
    const pg = S.program;
    const cats = S.catalogs || {};
    const fwChecks = FRAMEWORKS.map((f) => {
      const c = cats[f.key];
      return '<div style="margin-bottom:6px"><label class="' + P + '-chk"><input type="checkbox" data-pg-fw="' + f.key + '"' + ((pg.frameworks || []).includes(f.key) ? " checked" : "") + (c ? "" : " disabled") + ">" + esc(f.label) + "</label> " +
        (c ? '<span class="' + P + '-mut">' + esc(c.version) + ", catalog updated " + esc(c.updated) + ", " + (c.data || []).length + " entries</span>" : '<span class="' + P + '-mut">catalog not loaded</span>') + "</div>";
    }).join("");
    const socCats = SOC2_CATEGORIES.map((c) => '<label class="' + P + '-chk"><input type="checkbox" data-pg-soc="' + c.key + '"' + (c.required || (pg.soc2Categories || []).includes(c.key) ? " checked" : "") + (c.required ? " disabled" : "") + ">" + esc(c.label) + "</label>").join("");
    const pciLv = PCI_LEVELS.map((c) => '<label class="' + P + '-chk"><input type="checkbox" data-pg-pci="' + c.key + '"' + ((pg.pciLevels || ["sub", "req"]).includes(c.key) ? " checked" : "") + ">" + esc(c.label) + "</label>").join("");
    const lic = FRAMEWORKS.filter((f) => cats[f.key]).map((f) => '<div class="' + P + '-lic"><b>' + esc(f.label) + "</b> (" + esc(cats[f.key].version) + "): " + esc(cats[f.key].license) + ' <a href="' + esc(safeUrl(cats[f.key].sourceUrl)) + '" target="_blank" rel="noopener noreferrer">source</a>. ' + esc(cats[f.key].notes || "") + "</div>").join("");
    const domains = Array.from(new Set(records().filter((r) => r.scope !== "out").map((r) => r.domain).filter(Boolean))).sort();
    const ownerRows = domains.map((d, i) => '<div class="' + P + '-field"><label for="' + P + "-own-" + i + '">' + esc(d) + '</label><input type="email" id="' + P + "-own-" + i + '" data-own="' + esc(d) + '" placeholder="owner@company"></div>').join("");
    return [
      '<div class="', P, '-card"><h2>Program scope</h2><p class="', P, '-help">Pick frameworks and options, preview the controls, exclude any with a reason, then create one record per control. Existing records are kept, never overwritten.</p>',
      S.catErr ? '<div class="' + P + '-skip">Catalogs not loaded: ' + esc(S.catErr) + "</div>" : "",
      '<div class="', P, '-grid" style="margin-top:10px">', field("pg-org", "Organisation", '<input type="text" id="' + P + '-pg-org" placeholder="Company name" value="' + esc(pg.org) + '">', "Printed on the auditor package."), "</div>",
      "<h3>Frameworks</h3>", fwChecks,
      "<h3>SOC 2 categories</h3><div class=\"", P, '-checks">', socCats, '</div><p class="', P, '-help" style="margin-top:4px">Security (the Common Criteria) is always in scope.</p>',
      "<h3>CIS Controls implementation group</h3><div class=\"", P, '-grid">', field("pg-ig", "Implementation group", '<select id="' + P + '-pg-ig">' + opts([["1", "IG1"], ["2", "IG2 (includes IG1)"], ["3", "IG3 (all safeguards)"]], String(pg.cisIG || 1)) + "</select>"), "</div>",
      "<h3>PCI DSS</h3><div class=\"", P, '-checks">', pciLv, "</div>",
      '<div class="', P, '-grid" style="margin-top:8px">', field("pg-pci", "Assessment type", '<input type="text" id="' + P + '-pg-pci" placeholder="e.g. SAQ D or ROC" value="' + esc(pg.pciLabel) + '">', "Free label, stored on each PCI record. Pick the requirement rows that apply to your SAQ by excluding the rest below."), "</div>",
      '<div class="', P, '-row"><button class="', P, '-btn pri" data-act="scope-preview">Preview scope</button></div>',
      '<div id="', P, '-scopeprev">', scopePreviewHtml(), "</div></div>",
      '<div class="', P, '-card"><h2>Owners by domain</h2><p class="', P, '-help">Assign an owner to every control in a domain in one step. Controls that already have an owner keep it unless you tick overwrite.</p>',
      domains.length ? '<div class="' + P + '-grid" style="margin-top:10px">' + ownerRows + '</div><div class="' + P + '-row"><label class="' + P + '-chk"><input type="checkbox" id="' + P + '-own-over">Overwrite existing owners</label><button class="' + P + '-btn pri" data-act="owners-apply">Apply owners</button></div>' : '<p class="' + P + '-help">No controls in scope yet.</p>',
      "</div>",
      '<div class="', P, '-card"><h2>Import</h2><p class="', P, '-help">Drop a register JSON exported from this tool, or migrate an existing evidence spreadsheet (CSV): one row per control or per evidence item, with at least a framework and a control id column.</p>',
      '<div id="', P, '-impdrop" style="margin-top:8px"></div><div id="', P, '-imp">', importPanelHtml(), "</div></div>",
      '<div class="', P, '-card"><h2>Catalog licences</h2>', lic || '<p class="' + P + '-help">Catalogs not loaded.</p>', "</div>",
    ].join("");
  }
  function scopeFromForm() {
    const pg = { ...S.program };
    const v = (id) => { const el = $(id); return el ? el.value : ""; };
    pg.org = v("pg-org").trim();
    pg.frameworks = Array.from(main.querySelectorAll("[data-pg-fw]:checked")).map((e) => e.dataset.pgFw);
    pg.soc2Categories = Array.from(main.querySelectorAll("[data-pg-soc]:checked")).map((e) => e.dataset.pgSoc).filter((k) => k !== "security");
    pg.cisIG = Number(v("pg-ig")) || 1;
    pg.pciLevels = Array.from(main.querySelectorAll("[data-pg-pci]:checked")).map((e) => e.dataset.pgPci);
    pg.pciLabel = v("pg-pci").trim();
    S.program = pg; saveProgram();
    return pg;
  }
  function scopePreviewHtml() {
    const sp = S.scopePreview;
    if (!sp) return "";
    const have = new Set(records().flatMap((r) => r.refs.map((x) => x.fw + ":" + x.id)));
    const rows = sp.rows.map(({ fw, row }) => ({ fw, id: row.id, title: row.title, domain: row.domain, freq: row.defaultFrequency, key: fw + ":" + row.id, exists: have.has(fw + ":" + row.id) }));
    const fresh = rows.filter((x) => !x.exists).length;
    return '<h3>Preview: ' + rows.length + " controls, " + fresh + " new</h3>" +
      '<div class="' + P + '-tbl ' + P + '-scope"><table><thead><tr><th>Include</th><th>Control</th><th>Title</th><th>Frequency</th><th>Exclusion reason</th></tr></thead><tbody>' +
      rows.map((x) => "<tr><td>" + (x.exists ? '<span class="' + P + '-mut">exists</span>' : '<input type="checkbox" data-inc="' + esc(x.key) + '" checked aria-label="Include ' + esc(x.key) + '">') + '</td><td><span class="' + P + '-chip fw">' + esc(fwLabel(x.fw) + " " + x.id) + "</span></td><td>" + esc(x.title) + '<div class="' + P + '-mut">' + esc(x.domain) + "</div></td><td>" + esc(x.freq) + "</td><td>" + (x.exists ? "" : '<input type="text" data-why="' + esc(x.key) + '" placeholder="Reason if excluded">') + "</td></tr>").join("") +
      "</tbody></table></div>" +
      '<div class="' + P + '-row"><button class="' + P + '-btn pri" data-act="scope-create"' + (fresh ? "" : " disabled") + ">Create records</button><span class=\"" + P + '-mut">Unticked controls are recorded as out of scope with the reason given, and listed in the auditor package.</span></div>';
  }
  function importPanelHtml() {
    const ip = S.importParsed;
    if (!ip) return "";
    if (ip.format === "evidence-register") return '<p class="' + P + '-help">' + esc(ip.name) + ": Control Evidence register JSON, " + ip.rows.length + ' record(s), confidence high.</p><div class="' + P + '-row"><button class="' + P + '-btn pri" data-act="imp-json">Import ' + ip.rows.length + " record(s)</button></div>";
    if (!ip.rows.length) return '<p class="' + P + '-help">' + esc(ip.name) + ": no rows found (" + esc(ip.format) + ").</p>";
    const sel = (k) => '<select data-map="' + k + '"><option value="">(not mapped)</option>' + opts(ip.headers.map((h) => [h, h]), ip.mapping[k] || "") + "</select>";
    const labels = { framework: "Framework", controlId: "Control id", title: "Title", domain: "Domain", owner: "Owner", frequency: "Frequency", lastCollected: "Last collected", nextDue: "Next due", status: "Status", evidence: "Evidence name", sha256: "SHA-256", notes: "Notes" };
    return '<p class="' + P + '-help">' + esc(ip.name) + ": " + esc(ip.format.toUpperCase()) + ", " + ip.rows.length + " row(s), mapping confidence <b>" + esc(ip.confidence) + "</b>.</p>" +
      (ip.confidence !== "high" ? '<p class="' + P + '-help">Check the mapping below before importing.</p>' : "") +
      '<details' + (ip.confidence !== "high" ? " open" : "") + '><summary>Column mapping</summary><div class="' + P + '-grid" style="margin-top:8px">' +
      Object.keys(COLUMNS).map((k) => '<div class="' + P + '-field"><label>' + esc(labels[k] || k) + "</label>" + sel(k) + "</div>").join("") +
      '<div class="' + P + '-field"><label>Framework when not in a column</label><select data-map-default><option value="">(none)</option>' + opts(FRAMEWORKS.map((f) => [f.key, f.label])) + "</select></div></div></details>" +
      '<div class="' + P + '-row"><button class="' + P + '-btn pri" data-act="imp-csv">Import spreadsheet</button></div>' + (ip.report || "");
  }
  function mountImport() {
    const el = $("impdrop");
    if (!el) return;
    mountDropzone(el, {
      maxBytes: 20 * 1024 * 1024, maxFiles: 1, accept: ".json,.csv,.tsv,.txt", label: "Drop a register JSON or an evidence spreadsheet CSV",
      onFiles: async (files) => {
        const f = files[0]; if (!f) return;
        const p = parseInput([{ name: f.name, text: await f.text() }]);
        S.importParsed = { ...p, name: f.name };
        $("imp").innerHTML = importPanelHtml();
      },
    });
  }

  // ---- Package ------------------------------------------------------------
  function panePackage() {
    const r = S.result;
    const ex = r ? r.tables.exclusions : [];
    return [
      '<div class="', P, '-card"><h2>Auditor package</h2><p class="', P, '-help">A .zip with README.txt, index.csv (controls by evidence: name, SHA-256, size, collected date and collector), exceptions.csv, exclusions.csv and readiness.txt. The evidence files themselves are not included because they are never stored: the auditor asks the control owner for each file and matches it to index.csv by its SHA-256. README.txt explains how to verify a hash.</p>',
      '<div class="', P, '-row"><button class="', P, '-btn pri" data-act="x-zip">Build auditor package (.zip)</button><button class="', P, '-btn" data-act="pkg-preview">Preview readiness.txt</button></div>',
      '<div id="', P, '-pkgprev"></div></div>',
      '<div class="', P, '-card"><h2>Out of scope (', ex.length, ")</h2>",
      table("excl", [{ k: "refsText", l: "Control" }, { k: "title", l: "Title" }, { k: "reason", l: "Reason", h: (x) => "out of scope: " + esc(x.reason) }, { k: "id", l: "", nosort: true, h: (x) => '<button class="' + P + '-btn sm" data-act="scope-in" data-id="' + esc(x.id) + '">Bring into scope</button>' }], ex, { empty: "Nothing excluded." }),
      "</div>",
    ].join("");
  }
  const pkgFiles = () => buildPackage(records(), { ...S.thresholds, now: nowIso(), catalogs: S.catalogs, org: S.example ? S.example.org : S.program.org, scopeNote: scopeNote() });
  function scopeNote() {
    const pg = S.example ? S.example.scope : S.program;
    const parts = (pg.frameworks || []).map((k) => fwLabel(k) + (k === "soc2" ? " (" + ["Security"].concat((pg.soc2Categories || []).map((c) => (SOC2_CATEGORIES.find((x) => x.key === c) || {}).label || c)).join(", ") + ")" : k === "cisv8" ? " IG" + (pg.cisIG || 1) : k === "pci4" && pg.pciLabel ? " (" + pg.pciLabel + ")" : ""));
    return parts.join("; ");
  }

  // ---- events -------------------------------------------------------------
  main.addEventListener("click", async (e) => {
    const t = e.target.closest("[data-tab],[data-act],[data-sort],[data-open],[data-finding]");
    if (!t || !main.contains(t)) return;
    if (t.dataset.tab) { S.tab = t.dataset.tab; renderAll(); return; }
    if (t.dataset.sort) {
      const k = t.dataset.sort, c = t.dataset.k, cur = S.sort[k];
      S.sort[k] = cur && cur.k === c ? { k: c, asc: !cur.asc } : { k: c, asc: true };
      renderAll(); return;
    }
    if (t.dataset.finding != null && !t.dataset.act) {
      S.findingSel = Number(t.dataset.finding);
      main.querySelectorAll("tr[data-finding]").forEach((tr) => tr.classList.toggle("sel", Number(tr.dataset.finding) === S.findingSel));
      $("fdrawer").innerHTML = findingDrawer(); return;
    }
    if (t.dataset.open && !t.dataset.act) { S.openId = t.dataset.open; renderDrawer(); $("drawer").scrollIntoView({ behavior: "smooth", block: "start" }); return; }
    const act = t.dataset.act;
    try { await onAct(act, t); } catch (err) { toast(String(err && err.message || err), "error"); }
  });
  main.addEventListener("input", (e) => {
    const t = e.target;
    if (t.dataset.filter) {
      S.filter[t.dataset.filter] = t.value;
      if (t.dataset.filter === "q") { clearTimeout(t._tm); t._tm = setTimeout(() => { const pos = t.selectionStart; renderAll(); const q = main.querySelector('[data-filter="q"]'); if (q) { q.focus(); try { q.setSelectionRange(pos, pos); } catch (_) {} } }, 200); }
      else renderAll();
    }
  });
  main.addEventListener("change", (e) => {
    const t = e.target;
    if (t.dataset.thr) {
      const k = t.dataset.thr;
      if (k === "continuousPeriod") S.thresholds[k] = t.value;
      else { const n = Number(t.value); if (Number.isFinite(n) && n >= 0) S.thresholds[k] = n; }
      refresh(150);
    }
  });

  async function onAct(act, t) {
    const now = new Date().toISOString();
    const me = who();
    if (act === "drawer-close") { S.openId = null; renderDrawer(); return; }
    if (act === "thr-reset") { S.thresholds = { ...DEFAULTS }; refresh(0); return; }
    if (act === "cal-prev" || act === "cal-next" || act === "cal-today") {
      const base = (S.calMonth || S.result.summary.now.slice(0, 7)) + "-01";
      S.calMonth = act === "cal-today" ? null : addMonths(base, act === "cal-prev" ? -1 : 1).slice(0, 7);
      renderAll(); return;
    }
    if (act === "ex-close") { S.example = null; S.openId = null; refresh(0); return; }
    if (act === "ex-save") {
      const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Save the synthetic example?", "This writes " + S.example.records.length + " synthetic controls into your register" + (isTeam() ? " and the team's Security Graph" : "") + ". You can delete them later.", { submitText: "Save" }) : false;
      if (!ok) return;
      for (const r of S.example.records) reg.upsert({ ...r, notes: (r.notes ? r.notes + "\n" : "") + "Synthetic example record (Test Org)." });
      S.example = null; toast("Example saved to the register", "success"); refresh(0); return;
    }
    if (act === "graph-reload") { await loadGraph(); refresh(0); toast("Security Graph re-read", "info"); return; }
    if (act === "sug-accept") {
      const s = S.result.suggestions.find((x) => x.key === t.dataset.key);
      const rec = s && getRec(s.recordId);
      if (!rec) return;
      const cur = normalizeRecord(rec);
      const item = suggestionEvidence(s, { now, by: me });
      cur.evidence.push(item);
      addHistory(cur, now, "Accepted tool-run evidence: " + item.name + " (" + s.findingCount + " finding(s))", me);
      if (cur.status === "not-started" || cur.status === "collecting") cur.status = "collected";
      saveRec(cur); toast("Attached to " + refsLabel(cur.refs), "success"); refresh(0); return;
    }

    // drawer actions
    const rec = S.openId ? normalizeRecord(getRec(S.openId) || {}) : null;
    if (act === "rec-save" && rec) {
      const before = JSON.stringify([rec.owner, rec.frequency, rec.status, rec.dueOverride, rec.notes]);
      rec.owner = $("d-owner").value.trim(); rec.frequency = $("d-freq").value; rec.status = $("d-status").value;
      rec.dueOverride = toDay($("d-due").value) || ""; rec.notes = $("d-notes").value;
      if (JSON.stringify([rec.owner, rec.frequency, rec.status, rec.dueOverride, rec.notes]) !== before) addHistory(rec, now, "Updated: owner " + (rec.owner || "none") + ", " + FREQ_LABEL[rec.frequency] + ", " + STATUS_LABEL[rec.status] + (rec.dueOverride ? ", due override " + rec.dueOverride : ""), me);
      saveRec(rec); toast("Saved" + (S.example ? " (example, not persisted)" : ""), "success"); refresh(0); return;
    }
    if (act === "rec-out" && rec) {
      const why = typeof window.dnPrompt === "function" ? await window.dnPrompt("Reason this control is out of scope", { placeholder: "e.g. no cardholder data on this system" }) : null;
      if (!why || !why.trim()) return;
      rec.scope = "out"; rec.outReason = why.trim(); addHistory(rec, now, "Scoped out: " + rec.outReason, me);
      saveRec(rec); S.openId = null; refresh(0); return;
    }
    if (act === "scope-in") {
      const r = normalizeRecord(getRec(t.dataset.id) || {});
      if (!r.id) return;
      r.scope = "in"; addHistory(r, now, "Brought back into scope (was: " + r.outReason + ")", me); r.outReason = "";
      saveRec(r); refresh(0); return;
    }
    if (act === "rec-del" && rec) {
      const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Delete control?", "This removes " + refsLabel(rec.refs) + " and its evidence records from the register" + (S.example ? " (example only)" : " and the Security Graph") + ". Use Mark out of scope to keep an audit trail instead.", { danger: true, submitText: "Delete" }) : false;
      if (!ok) return;
      removeRec(rec.id); S.openId = null; refresh(0); return;
    }
    if (act === "ev-del" && rec) {
      const i = Number(t.dataset.i), ev = rec.evidence[i];
      if (!ev) return;
      const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Remove evidence item?", "Removes the record of " + ev.name + (ev.sha256 ? " (" + ev.sha256.slice(0, 16) + "...)" : "") + ". The removal is kept in the history.", { danger: true, submitText: "Remove" }) : false;
      if (!ok) return;
      rec.evidence.splice(i, 1); addHistory(rec, now, "Evidence removed: " + ev.name + (ev.sha256 ? " sha256 " + ev.sha256 : ""), me);
      saveRec(rec); refresh(0); return;
    }
    if (act === "link-add" && rec) {
      const name = $("l-name").value.trim(), url = $("l-url").value.trim();
      if (!name || !/^https?:\/\//i.test(url)) { toast("Give the link a name and an http(s) URL", "warning"); return; }
      rec.evidence.push({ kind: "link", name, link: url, sha256: "", size: null, type: "", collectedAt: toDay($("e-at").value) || nowIso(), collectedBy: $("e-by").value.trim(), note: $("e-note").value.trim() });
      addHistory(rec, now, "Link evidence added: " + name, me);
      if (rec.status === "not-started" || rec.status === "collecting") rec.status = "collected";
      saveRec(rec); refresh(0); return;
    }
    if (act === "exc-add" && rec) {
      const reason = $("x-reason").value.trim(), approvedBy = $("x-by").value.trim(), expires = toDay($("x-exp").value) || "";
      if (!reason || !approvedBy) { toast("An exception needs a reason and an approver", "warning"); return; }
      rec.exceptions.push({ reason, approvedBy, expires, addedAt: now });
      rec.status = "exception";
      addHistory(rec, now, "Exception added, approved by " + approvedBy + (expires ? ", expires " + expires : ", no expiry"), me);
      saveRec(rec); refresh(0); return;
    }
    if (act === "exc-del" && rec) {
      const i = Number(t.dataset.i), x = rec.exceptions[i];
      if (!x) return;
      rec.exceptions.splice(i, 1); addHistory(rec, now, "Exception removed: " + x.reason, me);
      saveRec(rec); refresh(0); return;
    }
    if (act === "link-ref" && rec) {
      const fw = $("k-fw").value, id = normControlId(fw, $("k-id").value);
      if (!fw || !id) { toast("Pick a framework and a control id", "warning"); return; }
      const inCat = S.catalogs && S.catalogs[fw] && (S.catalogs[fw].data || []).some((x) => x.id === id);
      if (!inCat) { toast(fwLabel(fw) + " " + id + " is not in the catalog", "warning"); return; }
      if (rec.refs.some((x) => x.fw === fw && x.id === id)) { toast("Already linked", "info"); return; }
      const other = records().find((r) => r.id !== rec.id && r.refs.some((x) => x.fw === fw && x.id === id));
      if (other) {
        const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Merge records?", fwLabel(fw) + " " + id + " already has its own record (" + (other.evidence || []).length + " evidence item(s)). Linking merges it into this one: refs, evidence, exceptions and history are combined and the other record is removed.", { submitText: "Merge" }) : false;
        if (!ok) return;
        const merged = mergeRecords(rec, other, now);
        saveRec(merged); removeRec(other.id);
      } else {
        rec.refs.push({ fw, id }); addHistory(rec, now, "Linked " + fwLabel(fw) + " " + id + " (manual crosswalk)", me);
        saveRec(rec);
      }
      refresh(0); return;
    }
    if (act === "unlink" && rec) {
      const i = Number(t.dataset.i), x = rec.refs[i];
      if (!x || rec.refs.length < 2) return;
      rec.refs.splice(i, 1); addHistory(rec, now, "Unlinked " + fwLabel(x.fw) + " " + x.id, me);
      saveRec(rec); refresh(0); return;
    }

    // setup
    if (act === "scope-preview") {
      const pg = scopeFromForm();
      if (!pg.frameworks.length) { toast("Pick at least one framework", "warning"); return; }
      S.scopePreview = { rows: scopedRows(S.catalogs || {}, pg) };
      $("scopeprev").innerHTML = scopePreviewHtml(); return;
    }
    if (act === "scope-create") {
      const pg = scopeFromForm();
      const exclusions = {};
      main.querySelectorAll("[data-inc]").forEach((c) => { if (!c.checked) { const w = main.querySelector('[data-why="' + window.CSS.escape(c.dataset.inc) + '"]'); exclusions[c.dataset.inc] = (w && w.value.trim()) || "excluded"; } });
      const out = bulkCreate(S.catalogs || {}, { ...pg, exclusions }, { existing: records(), now, by: me });
      const all = out.records.concat(out.excluded);
      if (!all.length) { toast("Nothing new to create", "info"); return; }
      if (S.example) { S.example = null; toast("Closed the example first; records go to your register", "info"); }
      for (const r of all) reg.upsert(r);
      S.scopePreview = null;
      toast(out.records.length + " control(s) created, " + out.excluded.length + " recorded out of scope, " + out.kept + " kept", "success");
      S.tab = "controls"; refresh(0); return;
    }
    if (act === "owners-apply") {
      const map = {};
      main.querySelectorAll("[data-own]").forEach((i) => { if (i.value.trim()) map[i.dataset.own] = i.value.trim(); });
      if (!Object.keys(map).length) { toast("Enter at least one owner", "warning"); return; }
      const changed = assignOwners(records().filter((r) => r.scope !== "out"), map, { overwrite: $("own-over").checked, now, by: me });
      for (const r of changed) saveRec(r);
      toast(changed.length + " control(s) updated", "success"); refresh(0); return;
    }
    if (act === "imp-json") {
      if (S.example) S.example = null;
      const r = reg.importJson(S.importParsed.rows.map(normalizeRecord));
      toast(r.added + " added, " + r.updated + " updated" + (r.rejected ? ", " + r.rejected + " rejected" : ""), "success");
      S.importParsed = null; refresh(0); return;
    }
    if (act === "imp-csv") {
      const mapping = {};
      main.querySelectorAll("[data-map]").forEach((s) => { if (s.value) mapping[s.dataset.map] = s.value; });
      const def = (main.querySelector("[data-map-default]") || {}).value || "";
      if (!mapping.controlId || (!mapping.framework && !def)) { toast("Map a control id column and a framework (column or default)", "warning"); return; }
      const res = importRows(S.importParsed.rows, mapping, { catalogs: S.catalogs, now, by: me, defaultFramework: def });
      const existing = records();
      let added = 0, merged = 0;
      if (S.example) S.example = null;
      for (const r of res.records) {
        const other = existing.find((x) => x.refs.some((y) => y.fw === r.refs[0].fw && y.id === r.refs[0].id));
        if (other) { const m = normalizeRecord(other); m.evidence = m.evidence.concat(r.evidence); addHistory(m, now, "Evidence rows imported from spreadsheet", me); reg.upsert(m); merged++; }
        else { reg.upsert(r); added++; }
      }
      S.importParsed.report = '<div class="' + P + '-skip">' + added + " new control(s), " + merged + " merged into existing records. " +
        (res.skipped.length ? "Skipped rows: " + res.skipped.slice(0, 20).map((x) => "row " + x.row + " (" + esc(x.reason) + ")").join("; ") + (res.skipped.length > 20 ? "; ..." : "") + ". " : "") +
        (res.warnings.length ? "Warnings: " + res.warnings.slice(0, 20).map((x) => "row " + x.row + " (" + esc(x.reason) + ")").join("; ") + (res.warnings.length > 20 ? "; ..." : "") : "") + "</div>";
      toast(added + " control(s) imported, " + merged + " merged", "success");
      refresh(0); return;
    }

    // package + exports
    if (act === "pkg-preview") {
      const f = pkgFiles().find((x) => x.name === "readiness.txt");
      $("pkgprev").innerHTML = '<pre class="' + P + '-mono" style="white-space:pre-wrap;background:var(--bg,#f7f8fb);border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:10px 12px;margin-top:10px;max-height:360px;overflow:auto">' + esc(f.text) + "</pre>"; return;
    }
    const stamp = fileStamp();
    if (act === "x-zip") {
      const files = pkgFiles();
      const zip = await zipFiles(files.map((f) => ({ ...f, name: "auditor-package/" + f.name })));
      download(TOOL_ID + "-auditor-package-" + stamp + ".zip", new Blob([zip], { type: "application/zip" }));
      toast("Auditor package built: " + files.length + " files, no evidence files (matched by hash)", "success"); return;
    }
    if (act === "x-reg-csv") { download(TOOL_ID + "-register-" + stamp + ".csv", registerCsv(records()), "text/csv"); return; }
    if (act === "x-reg-json") { download(TOOL_ID + "-register-" + stamp + ".json", S.example ? toJson(S.example.records) : reg.exportJson(), "application/json"); return; }
    if (act === "x-find-csv") { download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(S.result ? S.result.findings : []), "text/csv"); return; }
    if (act === "x-txt") { if (S.result) download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(S.result), "text/plain"); return; }
    if (act === "x-full-json") { if (S.result) download(TOOL_ID + "-analysis-" + stamp + ".json", toJson({ ...S.result, summaryStats: summarize(S.result.findings) }), "application/json"); return; }
    if (act === "x-ics") {
      const ev = icsEvents(records(), { ...S.thresholds, now: nowIso() });
      if (!ev.length) { toast("Nothing due in the calendar horizon", "info"); return; }
      download(TOOL_ID + "-calendar-" + stamp + ".ics", toIcs(ev, { prodId: "-//Darknode//Control Evidence//EN" }), "text/calendar");
      toast(ev.length + " calendar entries exported", "success"); return;
    }
  }

  $("example").addEventListener("click", () => {
    S.example = exampleDataset(7, { now: todayIso(), catalogs: S.catalogs });
    S.openId = null; S.tab = "overview"; S.calMonth = null;
    toast("Synthetic example loaded (not saved)", "info");
    refresh(0);
  });

  reg.subscribe(() => { if (!S.example) refresh(200); });
  (async () => {
    await loadCatalogs();
    await loadGraph();
    reg.ready.then(() => reg.backfill()).then((n) => { if (n) refresh(0); }).catch(() => {});
    refresh(0);
  })();
}
