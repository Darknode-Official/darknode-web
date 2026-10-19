// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Awareness & Phishing-Test Analytics (awareness): Deck tool UI. Drop phishing
// simulation exports (GoPhish, KnowBe4, Microsoft Defender Attack Simulation
// Training, Proofpoint), LMS training files and an HR roster; the engine
// (awareness-engine.js) runs in a Worker. Per-person campaign outcomes for people
// who clicked can be saved to a team-shareable history register so later
// imports count repeat clicks across campaigns. Runs entirely in the browser;
// nothing is fetched. No native dialogs; toasts and dnConfirm only.
//
//   renderAwareness(main) -> void

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { attachSinkButton } from "../core/sink.js";
import { openRegister } from "../core/register.js";
import { download, toJson, fileStamp } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, KINDS, MODE_KEYS, KEY_LABELS, REGISTER_SCHEMA, parseInput, remapFile, normEmail, mergeHistory,
  findingsToCsv, repeatClickersCsv, departmentScorecardCsv, remedialAssignmentsCsv, summaryText, exampleParsed,
} from "./awareness-engine.js?v=20261017c";

const ENGINE = engineUrl("./awareness-engine.js?v=20261017c", import.meta);
const P = "awr";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const CONF_RANK = { confirmed: 3, likely: 2, review: 1 };
const num = (n) => (n == null ? "" : Number(n).toLocaleString());
const rateTxt = (r) => (r && r.den ? r.pct.toFixed(1) + "% (" + num(r.num) + "/" + num(r.den) + ")" : "n/a");
const minTxt = (m) => (m == null ? "n/a" : m < 120 ? m + " min" : (Math.round(m / 6) / 10) + " h");

const CSS = `
  .awr-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .awr-root *{box-sizing:border-box}
  .awr-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .awr-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .awr-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--mut,#667085);border:1px solid var(--line,#e6e8ee);padding:2px 9px;border-radius:999px}
  .awr-sub{color:var(--mut,#667085);margin:8px 0 6px;max-width:90ch}
  .awr-note{border:1px solid var(--line,#e6e8ee);border-left:3px solid var(--mut,#667085);border-radius:8px;padding:10px 14px;font-size:.84rem;margin:10px 0 14px;background:var(--card,#fff)}
  .awr-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .awr-card h3{font-size:.98rem;margin:0 0 8px}
  .awr-help{color:var(--mut,#667085);font-size:.8rem;margin:4px 0 8px;overflow-wrap:anywhere}
  .awr-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:10px}
  .awr-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:7px 13px;border-radius:8px;cursor:pointer}
  .awr-btn:hover{border-color:var(--mut,#667085)}
  .awr-btn.pri{background:var(--tx,#1a2230);border-color:var(--tx,#1a2230);color:var(--card,#fff)}
  .awr-btn.sm{font-size:.76rem;padding:4px 9px}
  .awr-btn:disabled{opacity:.5;cursor:default}
  .awr-opts{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px 16px}
  .awr-field{display:flex;flex-direction:column;gap:3px;min-width:0}
  .awr-field.wide{grid-column:1/-1}
  .awr-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .awr-field .awr-help{margin:2px 0 0;font-size:.74rem}
  .awr-root input[type=text],.awr-root input[type=number],.awr-root input[type=date],.awr-root select{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:6px 9px;width:100%;max-width:100%;min-width:0}
  .awr-files{width:100%;border-collapse:collapse;font-size:.83rem}
  .awr-files td,.awr-files th{padding:7px 8px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;text-align:left;overflow-wrap:anywhere}
  .awr-files th{font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .awr-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;border:1px solid var(--line,#d7dbe3);border-radius:999px;padding:1px 8px;white-space:nowrap}
  .awr-conf.high{color:#1b7f4d;border-color:#1b7f4d}.awr-conf.medium{color:#8a6d00;border-color:#8a6d00}.awr-conf.low{color:#b00020;border-color:#b00020}.awr-conf.user{color:var(--tx,#1a2230)}
  .awr-map{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:8px 12px;padding:10px;border:1px dashed var(--line,#d7dbe3);border-radius:8px;margin:4px 0 6px}
  .awr-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin:0 0 14px}
  .awr-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .awr-kpi b{display:block;font-size:1.3rem;line-height:1.25;font-variant-numeric:tabular-nums}
  .awr-kpi small{display:block;font-size:.72rem;color:var(--mut,#667085)}
  .awr-kpi span{font-size:.7rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .awr-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .awr-prog i{display:block;height:100%;width:0;background:var(--tx,#1a2230);transition:width .15s}
  .awr-tbl{border:1px solid var(--line,#e6e8ee);border-radius:10px;overflow:auto;max-width:100%}
  .awr-tbl table{width:100%;border-collapse:collapse;font-size:.83rem}
  .awr-tbl th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 10px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .awr-tbl th.awr-s{cursor:pointer;user-select:none}
  .awr-tbl td{padding:8px 10px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .awr-tbl td.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
  .awr-tbl tr[data-i]{cursor:pointer}
  .awr-tbl tr[data-i]:hover td,.awr-tbl tr.on td{background:var(--bg,#f7f8fb)}
  .awr-pill{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .awr-pill.critical{background:#7a0012}.awr-pill.high{background:#b00020}.awr-pill.medium{background:#9a6b00}.awr-pill.low{background:#2552c6}.awr-pill.info{background:#667085}
  .awr-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .awr-empty{padding:22px;text-align:center;color:var(--mut,#667085)}
  .awr-dim{color:var(--mut,#667085)}
  .awr-drawer{margin-top:12px;border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:14px;background:var(--card,#fff)}
  .awr-skip{font-size:.78rem;color:var(--mut,#667085);margin:8px 0 0;padding-left:18px}
  .awr-warn{font-size:.8rem;color:#8a6d00;margin:6px 0 0}
  .awr-chart{width:100%;height:auto;display:block;max-width:900px}
  .awr-chart text{font-size:11px;fill:var(--mut,#667085)}
  .awr-chart .g{stroke:var(--line,#e6e8ee);stroke-width:1}
  .awr-chart .lc{stroke:#b00020;fill:none;stroke-width:2}.awr-chart .pc{fill:#b00020}
  .awr-chart .lr{stroke:#1b7f4d;fill:none;stroke-width:2;stroke-dasharray:6 4}.awr-chart .pr{fill:#1b7f4d}
  .awr-chart .lb{stroke:var(--mut,#667085);stroke-width:1;stroke-dasharray:2 3}
  .awr-legend{display:flex;gap:16px;flex-wrap:wrap;font-size:.78rem;color:var(--mut,#667085);margin:4px 0 8px}
  .awr-legend i{display:inline-block;width:18px;height:0;border-top:2px solid #b00020;vertical-align:middle;margin-right:6px}
  .awr-legend i.r{border-top:2px dashed #1b7f4d}
  .awr-legend i.b{border-top:1px dotted var(--mut,#667085)}
  .awr-grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,460px),1fr));gap:14px}
`;

function kpi(v, label, sub) { return '<div class="' + P + '-kpi"><b>' + esc(v) + "</b>" + (sub ? "<small>" + esc(sub) + "</small>" : "") + "<span>" + esc(label) + "</span></div>"; }

function table(cols, rows, empty) {
  if (!rows.length) return '<div class="' + P + '-empty">' + esc(empty || "Nothing to show.") + "</div>";
  return '<div class="' + P + '-tbl"><table><thead><tr>' + cols.map((c) => "<th>" + esc(c.label) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + cols.map((c) => '<td class="' + (c.n ? "n" : "") + '">' + (c.html ? c.html(r) : esc(c.get ? c.get(r) : r[c.key])) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

const OPT_FIELDS = [
  { key: "minGroupSize", label: "Smallest group shown", type: "number", help: "Breakdown groups with fewer people are hidden so individuals cannot be singled out." },
  { key: "repeatClickMin", label: "Campaigns clicked for follow-up", type: "number", help: "Clicked in at least this many campaigns (imports plus saved history)." },
  { key: "remedialDays", label: "Remedial window (days)", type: "number", help: "Training assigned or completed within this many days after a click." },
  { key: "remedialCourse", label: "Remedial course contains", type: "text", ph: "Any course", help: "Optional text the course name must contain." },
  { key: "minTrendSample", label: "Min delivered for trend", type: "number", help: "Campaigns with fewer delivered emails are left out of trend flags." },
  { key: "baselineClickRate", label: "Your baseline click rate (%)", type: "number", ph: "Optional", help: "Your own earlier figure. No industry benchmark is assumed." },
  { key: "reportTargetRate", label: "Report-rate target (%)", type: "number", ph: "Optional", help: "Flag when the overall report rate is below it." },
  { key: "now", label: "Reference date", type: "date", help: "Used for overdue and tenure. Blank = newest date in the data." },
  { key: "highRiskKeywords", label: "High-risk title keywords", type: "text", wide: true, help: "Comma-separated. Matched as whole words against job titles, in addition to roster privileged / finance / exec flags." },
];

/** Mount the tool into main. */
export function renderAwareness(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  const optHtml = OPT_FIELDS.map((f) => '<div class="' + P + "-field" + (f.wide ? " wide" : "") + '"><label for="' + P + "-o-" + f.key + '">' + esc(f.label) + "</label>" +
    '<input id="' + P + "-o-" + f.key + '" data-opt="' + f.key + '" type="' + f.type + '"' + (f.ph ? ' placeholder="' + esc(f.ph) + '"' : "") + ' value="' + esc(DEFAULTS[f.key]) + '">' +
    '<div class="' + P + '-help">' + esc(f.help) + (DEFAULTS[f.key] !== "" && f.type === "number" ? " Default " + esc(DEFAULTS[f.key]) + "." : "") + "</div></div>").join("");

  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Awareness &amp; Phishing-Test Analytics</h1><span class="', P, '-tag">Compliance</span></div>',
    '<p class="', P, '-sub">Click, credential-entry and report rates per campaign with their denominators, privacy-safe breakdowns, people who need follow-up training, overdue and remedial training, and trends. Runs entirely in your browser. Nothing is uploaded and nothing is fetched.</p>',
    '<div class="', P, '-note"><b>People data is sensitive.</b> Use these results to target training, not to discipline anyone. Small groups are suppressed, and people who clicked in several campaigns are listed as needing follow-up training. Message bodies are never read or stored.</div>',
    '<div class="', P, '-card"><h3>1. Exports</h3>',
    '<div class="', P, '-help">Drop several files at once: GoPhish results or raw events CSV (or API JSON), KnowBe4 recipients JSON or CSV, Microsoft Defender Attack Simulation (Graph JSON or CSV), Proofpoint CSV, an LMS training CSV (user, course, assigned, due, completed) and an HR roster (email, department, title, manager, hire date, privileged / finance / exec flags). A saved history JSON from this tool imports into the history.</div>',
    '<div id="', P, '-drop"></div>',
    '<div id="', P, '-files"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button><button class="', P, '-btn" id="', P, '-clear">Clear files</button><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button><span class="', P, '-dim" id="', P, '-status"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div></div>',
    '<div class="', P, '-card"><h3>2. Thresholds</h3><div class="', P, '-opts">', optHtml, "</div></div>",
    '<div id="', P, '-out"></div>',
    '<div class="', P, '-card" id="', P, '-hist"></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], isExample = false, result = null, exampleNow = "";
  const reg = openRegister(TOOL_ID, "IDENTITY", { schema: REGISTER_SCHEMA });
  reg.ready.then(() => renderHistory()).catch(() => {});
  const unsub = reg.subscribe(() => renderHistory());
  const obs = new MutationObserver(() => { if (!main.querySelector("." + P + "-root")) { unsub(); obs.disconnect(); } });
  try { obs.observe(main, { childList: true }); } catch (_) {}

  // ---------------------------------------------------------------- inputs
  mountDropzone($("drop"), {
    maxBytes: 60 * 1024 * 1024, maxFiles: 50, accept: ".csv,.tsv,.json,.txt,.zip,.gz",
    label: "Drop exports here, paste, or browse",
    onFiles: async (list) => {
      if (isExample) { files = []; isExample = false; exampleNow = ""; }
      const texts = [];
      for (const f of list) { try { texts.push({ name: f.name, text: await f.text() }); } catch (_) { toast("Could not read " + f.name, "error"); } }
      const parsed = parseInput(texts).files;
      for (const f of parsed) {
        if (f.kind === "history") { await importHistory(f.rows, f.name); continue; }
        if (!f.rows.length) { toast("No rows found in " + f.name, "warning"); continue; }
        files.push(f);
      }
      renderFiles();
    },
  });

  async function importHistory(rows, name) {
    if (isExample) return;
    const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Import awareness history?", name + " holds " + rows.length + " people. Their campaign outcomes will be merged into the history register" + " (and shared with your team when a team workspace is active).", { submitText: "Import" }) : false;
    if (!ok) return;
    try { const r = reg.importJson(rows.map((x) => ({ ...x, id: normEmail(x.email), email: normEmail(x.email) }))); toast("History: " + r.added + " added, " + r.updated + " updated", "success"); renderHistory(); }
    catch (e) { toast("History import failed: " + (e && e.message || e), "error"); }
  }

  $("example").addEventListener("click", () => {
    const ex = exampleParsed();
    files = ex.parsed.files; isExample = true; exampleNow = ex.now;
    const nowEl = main.querySelector('[data-opt="now"]'); if (nowEl) nowEl.value = ex.now.slice(0, 10);
    renderFiles();
    toast("Synthetic example loaded: 6 campaigns, 60 fictional people. It is never saved to the history.", "info");
  });
  $("clear").addEventListener("click", () => { files = []; isExample = false; result = null; $("out").innerHTML = ""; renderFiles(); });

  function renderFiles() {
    const box = $("files");
    $("run").disabled = !files.length;
    $("status").textContent = files.length ? files.length + " file(s)" + (isExample ? ", synthetic example" : "") : "";
    if (!files.length) { box.innerHTML = ""; return; }
    const kindOpts = (cur) => Object.entries(KINDS).filter(([k]) => k !== "history").map(([k, v]) => '<option value="' + k + '"' + (k === cur ? " selected" : "") + ">" + esc(v.label) + "</option>").join("");
    box.innerHTML = '<div class="' + P + '-tbl" style="margin-top:12px"><table class="' + P + '-files"><thead><tr><th>File</th><th>Detected format</th><th>Confidence</th><th>Rows</th><th>Campaign name</th><th></th></tr></thead><tbody>' +
      files.map((f, i) => {
        const showMap = f._showMap != null ? f._showMap : (f.confidence !== "high" || (f.missing || []).length > 0);
        const mode = f.mode;
        const map = showMap && mode ? '<tr><td colspan="6"><div class="' + P + '-help">Map the columns of ' + esc(f.name) + ". Required: " + esc(((mode === "outcome" ? ["email", "clicked"] : mode === "status" ? ["email", "status"] : mode === "events" ? ["email", "message"] : mode === "training" ? ["email", "course"] : ["email"])).map((k) => KEY_LABELS[k]).join(", ")) + '. Checks whose columns are left empty are skipped.</div><div class="' + P + '-map">' +
          MODE_KEYS[mode].map((k) => '<div class="' + P + '-field"><label>' + esc(KEY_LABELS[k] || k) + '</label><select data-map="' + i + '" data-key="' + k + '"><option value="">(not in file)</option>' +
            (f.headers || []).map((h) => '<option value="' + esc(h) + '"' + ((f.mapping || {})[k] === h ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>").join("") + "</div></td></tr>" : "";
        return "<tr><td>" + esc(f.name) + (f.missing && f.missing.length ? '<div class="' + P + '-warn">Missing: ' + esc(f.missing.map((k) => KEY_LABELS[k] || k).join(", ")) + "</div>" : "") + "</td>" +
          '<td><select data-kind="' + i + '">' + kindOpts(f.kind) + "</select></td>" +
          '<td><span class="' + P + "-conf " + esc(f.confidence) + '">' + esc(f.confidence === "user" ? "set by you" : f.confidence) + "</span></td>" +
          '<td class="n">' + num(f.rows.length) + "</td>" +
          "<td>" + (f.role === "outcome" ? '<input type="text" data-camp="' + i + '" value="' + esc(f.campaign || "") + '" placeholder="From file">' : '<span class="' + P + '-dim">n/a</span>') + "</td>" +
          '<td><button class="' + P + '-btn sm" data-tog="' + i + '">' + (showMap ? "Hide columns" : "Columns") + '</button> <button class="' + P + '-btn sm" data-rm="' + i + '">Remove</button></td></tr>' + map;
      }).join("") + "</tbody></table></div>" +
      '<div class="' + P + '-help">Campaign name: blank uses the campaign column or the file name. Give two files the same name (for example GoPhish results and raw events of one campaign) to merge them.</div>';
    box.querySelectorAll("[data-kind]").forEach((el) => el.addEventListener("change", () => { const i = +el.dataset.kind; files[i] = { ...remapFile(files[i], el.value, null), _showMap: true }; renderFiles(); }));
    box.querySelectorAll("[data-map]").forEach((el) => el.addEventListener("change", () => {
      const i = +el.dataset.map, f = files[i];
      const mapping = { ...(f.mapping || {}) };
      if (el.value) mapping[el.dataset.key] = el.value; else delete mapping[el.dataset.key];
      files[i] = { ...remapFile(f, f.kind, mapping), _showMap: true };
      renderFiles();
    }));
    box.querySelectorAll("[data-camp]").forEach((el) => el.addEventListener("input", () => { files[+el.dataset.camp].campaign = el.value; }));
    box.querySelectorAll("[data-tog]").forEach((el) => el.addEventListener("click", () => { const f = files[+el.dataset.tog]; const cur = f._showMap != null ? f._showMap : (f.confidence !== "high" || (f.missing || []).length > 0); f._showMap = !cur; renderFiles(); }));
    box.querySelectorAll("[data-rm]").forEach((el) => el.addEventListener("click", () => { files.splice(+el.dataset.rm, 1); if (!files.length) isExample = false; renderFiles(); }));
  }

  const opts = () => {
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => {
      const k = el.dataset.opt;
      if (el.type === "number") { if (el.value === "") o[k] = DEFAULTS[k] === "" ? "" : DEFAULTS[k]; else { const n = Number(el.value); if (Number.isFinite(n)) o[k] = n; } }
      else if (k === "now") o.now = el.value ? el.value + "T00:00:00Z" : "";
      else o[k] = el.value;
    });
    return o;
  };

  const historyList = () => reg.list().map((r) => { const c = { ...r }; delete c.graphId; return c; });

  // ---------------------------------------------------------------- run
  $("run").addEventListener("click", async () => {
    const prog = $("prog"), bar = prog.firstElementChild;
    prog.style.display = "block"; bar.style.width = "0%"; $("run").disabled = true;
    const payload = { files: files.map((f) => ({ name: f.name, kind: f.kind, role: f.role, mode: f.mode, mapping: f.mapping, campaign: f.campaign || "", rows: f.rows })), history: isExample ? [] : historyList() };
    try {
      result = await runInWorker(ENGINE, "analyze", [payload, opts()], { onProgress: (i, n) => { bar.style.width = (n ? Math.round(i / n * 100) : 0) + "%"; } });
      renderResult(result);
      toast(result.findings.length + " finding(s)", "success");
    } catch (e) {
      toast("Analysis failed: " + (e && e.message || e), "error");
    } finally {
      prog.style.display = "none"; $("run").disabled = !files.length;
    }
  });

  // ---------------------------------------------------------------- results
  function renderResult(r) {
    const s = r.summary, t = r.tables;
    const out = $("out");
    out.innerHTML = [
      r.meta.warnings.length ? '<div class="' + P + '-card"><div class="' + P + '-warn">' + r.meta.warnings.map(esc).join("<br>") + "</div></div>" : "",
      '<div class="', P, '-kpis">',
      kpi(num(s.campaigns), "Campaigns", num(s.people) + " people"), kpi(num(s.delivered), "Delivered emails"),
      kpi(s.clickRate.den ? s.clickRate.pct.toFixed(1) + "%" : "n/a", "Click rate", num(s.clickRate.num) + " of " + num(s.clickRate.den)),
      kpi(s.submitRate.den ? s.submitRate.pct.toFixed(1) + "%" : "n/a", "Entered credentials", num(s.submitRate.num) + " of " + num(s.submitRate.den)),
      kpi(s.reportRate.den ? s.reportRate.pct.toFixed(1) + "%" : "n/a", "Report rate", num(s.reportRate.num) + " of " + num(s.reportRate.den)),
      kpi(s.reportBeforeClick.den ? s.reportBeforeClick.pct.toFixed(1) + "%" : "n/a", "Reported before clicking", num(s.reportBeforeClick.num) + " of " + num(s.reportBeforeClick.den)),
      kpi(minTxt(s.medianMinutesToClick), "Median time to click", "n=" + num(t.overall.clickTimeSample)),
      kpi(minTxt(s.medianMinutesToReport), "Median time to report", "n=" + num(t.overall.reportTimeSample)),
      kpi(num(s.needsFollowUp), "Need follow-up training"),
      "</div>",
      '<div class="', P, '-card"><h3>Findings</h3><div id="', P, '-ftbl"></div><div id="', P, '-drawer"></div>',
      r.skipped.length ? '<div class="' + P + '-help" style="margin-top:10px">Skipped checks (columns or files missing; nothing is guessed):</div><ul class="' + P + '-skip">' + r.skipped.map((k) => "<li><b>" + esc(k.check) + "</b>: " + esc(k.reason) + "</li>").join("") + "</ul>" : "",
      '<div class="', P, '-row" id="', P, '-exports"></div></div>',
      '<div class="', P, '-card"><h3>Campaigns and trend</h3>', chart(t.campaigns, opts().baselineClickRate), trendHtml(t.trend),
      table([
        { label: "Date", key: "date" }, { label: "Campaign", key: "campaign" }, { label: "Delivered", key: "delivered", n: 1 },
        { label: "Opened", get: (c) => (c.hasOpen ? rateTxt(c.opened) : "n/a") }, { label: "Clicked", get: (c) => rateTxt(c.clicked) }, { label: "Entered credentials", get: (c) => rateTxt(c.submitted) },
        { label: "Reported", get: (c) => (c.hasReport ? rateTxt(c.reported) : "n/a") }, { label: "Reported before click", get: (c) => (c.hasReport ? rateTxt(c.reportBeforeClick) : "n/a") },
        { label: "Median to click", get: (c) => minTxt(c.medianMinutesToClick) + (c.clickTimeSample ? " (n=" + c.clickTimeSample + ")" : "") },
        { label: "Median to report", get: (c) => minTxt(c.medianMinutesToReport) + (c.reportTimeSample ? " (n=" + c.reportTimeSample + ")" : "") },
        { label: "First click", get: (c) => minTxt(c.minutesToFirstClick) }, { label: "First report", get: (c) => minTxt(c.minutesToFirstReport) },
      ], t.campaigns, "No phishing results loaded."),
      '<div class="', P, '-help">Rates use delivered emails as the denominator. Times are from delivery; "first click" and "first report" are from the campaign\'s first delivery.</div></div>',
      '<div class="', P, '-grid2">',
      '<div class="', P, '-card"><h3>Breakdowns</h3>', breakdownSelect(t.breakdowns), '<div id="', P, '-bd"></div><div class="', P, '-help">', esc(t.suppressionNote || ""), "</div></div>",
      '<div class="', P, '-card"><h3>Training completion by department</h3>',
      t.trainingByDept ? table([{ label: "Department", key: "group" }, { label: "People", get: (x) => (x.suppressed ? "suppressed" : num(x.people)), n: 1 }, { label: "Assignments", get: (x) => (x.suppressed ? "" : num(x.assigned)), n: 1 }, { label: "Completed", get: (x) => (x.suppressed ? "" : rateTxt(x.completion)) }, { label: "Overdue", get: (x) => (x.suppressed ? "" : num(x.overdue)), n: 1 }], t.trainingByDept)
        : '<div class="' + P + '-empty">Needs an LMS training file and a roster with a department column.</div>',
      "</div>",
      "</div>",
      '<div class="', P, '-card"><h3>Needs follow-up training</h3><div class="', P, '-help">People who clicked in at least ', esc(r.meta.options.repeatClickMin), " campaigns, counting this import and the saved history. Offer short, supportive follow-up training.</div>",
      table([{ label: "Email", key: "email" }, { label: "Department", key: "department" }, { label: "Title", key: "title" }, { label: "Campaigns seen", key: "campaignsSeen", n: 1 }, { label: "Clicked", key: "campaignsClicked", n: 1 }, { label: "Entered credentials", key: "campaignsSubmitted", n: 1 }, { label: "Reported", key: "campaignsReported", n: 1 }, { label: "Last click", key: "lastClick" }, { label: "High-risk role", key: "highRisk" }], t.repeatClickers || [], "Nobody meets the follow-up threshold."),
      "</div>",
    ].join("");
    renderFindings(r);
    renderExports(r);
    const sel = $("bdsel");
    if (sel) { sel.addEventListener("change", () => renderBreakdown(t, sel.value)); renderBreakdown(t, sel.value); }
    else $("bd").innerHTML = '<div class="' + P + '-empty">Needs an HR roster or a title column.</div>';
    renderHistory();
  }

  function breakdownSelect(b) {
    const dims = Object.keys(b || {});
    if (!dims.length) return "";
    const lbl = { department: "Department", title: "Role / title", tenure: "Tenure", manager: "Manager" };
    return '<div class="' + P + '-field" style="max-width:260px;margin-bottom:8px"><label for="' + P + '-bdsel">Group by</label><select id="' + P + '-bdsel">' + dims.map((d) => '<option value="' + d + '">' + esc(lbl[d] || d) + "</option>").join("") + "</select></div>";
  }

  function renderBreakdown(t, dim) {
    const rows = (t.breakdowns || {})[dim] || [];
    $("bd").innerHTML = table([
      { label: "Group", key: "group" }, { label: "People", get: (x) => (x.suppressed ? "suppressed" : num(x.people)), n: 1 }, { label: "Delivered", get: (x) => (x.suppressed ? "" : num(x.delivered)), n: 1 },
      { label: "Clicked", get: (x) => (x.suppressed ? "" : rateTxt(x.clicked)) }, { label: "Entered credentials", get: (x) => (x.suppressed ? "" : rateTxt(x.submitted)) }, { label: "Reported", get: (x) => (x.suppressed ? "" : rateTxt(x.reported)) },
    ], rows);
  }

  function trendHtml(tr) {
    if (!tr || !tr.flags || !tr.flags.length) return '<div class="' + P + '-help">Trend flags need two dated campaigns with at least ' + esc(tr ? tr.minSample : DEFAULTS.minTrendSample) + " delivered emails each.</div>";
    return '<div class="' + P + '-help">First vs latest campaign with at least ' + esc(tr.minSample) + " delivered emails (two-proportion test, |z| of 1.96 or more counts as a change): " +
      tr.flags.map((f) => "<b>" + esc(f.metric) + "</b> " + esc(f.fromRate) + " to " + esc(f.toRate) + ", " + esc(f.direction) + " (z=" + esc(f.z) + ")").join("; ") + ". Lure difficulty differs between campaigns.</div>";
  }

  function chart(camps, baseline) {
    const list = (camps || []).filter((c) => c.delivered);
    if (list.length < 2) return "";
    const W = 720, H = 230, L = 40, R = 14, T = 14, B = 40;
    const vals = list.flatMap((c) => [c.clicked.pct || 0, c.hasReport ? c.reported.pct || 0 : 0]);
    const base = baseline === "" || baseline == null ? null : Number(baseline);
    if (base != null && Number.isFinite(base)) vals.push(base);
    const max = Math.max(10, Math.ceil(Math.max(...vals) / 10) * 10);
    const x = (i) => L + (list.length === 1 ? 0 : (i * (W - L - R)) / (list.length - 1));
    const y = (v) => T + (H - T - B) * (1 - v / max);
    let g = "";
    for (let k = 0; k <= 4; k++) { const v = (max * k) / 4; g += '<line class="g" x1="' + L + '" x2="' + (W - R) + '" y1="' + y(v) + '" y2="' + y(v) + '"/><text x="' + (L - 6) + '" y="' + (y(v) + 4) + '" text-anchor="end">' + Math.round(v) + "%</text>"; }
    const pts = (fn) => list.map((c, i) => (fn(c) == null ? null : x(i) + "," + y(fn(c)))).filter(Boolean).join(" ");
    const clickPts = pts((c) => c.clicked.pct), repPts = pts((c) => (c.hasReport ? c.reported.pct : null));
    const dots = list.map((c, i) => '<circle class="pc" cx="' + x(i) + '" cy="' + y(c.clicked.pct || 0) + '" r="3.5"><title>' + esc(c.campaign + ": clicked " + rateTxt(c.clicked)) + "</title></circle>" +
      (c.hasReport ? '<circle class="pr" cx="' + x(i) + '" cy="' + y(c.reported.pct || 0) + '" r="3.5"><title>' + esc(c.campaign + ": reported " + rateTxt(c.reported)) + "</title></circle>" : "") +
      '<text x="' + x(i) + '" y="' + (H - B + 16) + '" text-anchor="middle">' + esc(c.date ? c.date.slice(2) : "undated") + '</text><text x="' + x(i) + '" y="' + (H - B + 30) + '" text-anchor="middle">n=' + c.delivered + "</text>").join("");
    const bl = base != null && Number.isFinite(base) ? '<line class="lb" x1="' + L + '" x2="' + (W - R) + '" y1="' + y(base) + '" y2="' + y(base) + '"/>' : "";
    return '<div class="' + P + '-legend"><span><i></i>Click rate</span><span><i class="r"></i>Report rate</span>' + (bl ? '<span><i class="b"></i>Your baseline</span>' : "") + "</div>" +
      '<svg class="' + P + '-chart" viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Click and report rate per campaign">' + g + bl +
      (clickPts ? '<polyline class="lc" points="' + clickPts + '"/>' : "") + (repPts ? '<polyline class="lr" points="' + repPts + '"/>' : "") + dots + "</svg>";
  }

  const fState = { key: "severity", asc: false, open: -1 };
  function renderFindings(r) {
    const box = $("ftbl");
    if (!r.findings.length) { box.innerHTML = '<div class="' + P + '-empty">No findings for the current thresholds.</div>'; $("drawer").innerHTML = ""; return; }
    const keyOf = { severity: (f) => SEV_RANK[f.severity], title: (f) => f.title, confidence: (f) => CONF_RANK[f.confidence] || 0, category: (f) => f.category, evidence: (f) => f.evidenceCount };
    const idx = r.findings.map((f, i) => i).sort((a, b) => {
      const fa = r.findings[a], fb = r.findings[b];
      return cmp(keyOf[fState.key](fa), keyOf[fState.key](fb)) * (fState.asc ? 1 : -1) || SEV_RANK[fb.severity] - SEV_RANK[fa.severity] || a - b;
    });
    const th = (k, l) => '<th class="' + P + '-s" data-sort="' + k + '">' + l + (fState.key === k ? (fState.asc ? " &#8593;" : " &#8595;") : "") + "</th>";
    box.innerHTML = '<div class="' + P + '-tbl"><table><thead><tr>' + th("severity", "Severity") + th("title", "Finding") + th("category", "Category") + th("confidence", "Confidence") + "<th>Controls</th>" + th("evidence", "Evidence") + "</tr></thead><tbody>" +
      idx.map((i) => { const f = r.findings[i]; return '<tr data-i="' + i + '"' + (fState.open === i ? ' class="on"' : "") + '><td><span class="' + P + "-pill " + esc(f.severity) + '">' + esc(f.severity) + "</span></td><td><b>" + esc(f.title) + '</b><div class="' + P + '-dim">' + esc(f.description) + "</div></td><td>" + esc(f.category) + "</td><td>" + esc(f.confidence) + "</td><td>" +
        (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + '</td><td class="n">' + num(f.evidenceCount) + "</td></tr>"; }).join("") + "</tbody></table></div>";
    box.querySelectorAll("th[data-sort]").forEach((h) => h.addEventListener("click", () => { const k = h.dataset.sort; if (fState.key === k) fState.asc = !fState.asc; else { fState.key = k; fState.asc = k === "title" || k === "category"; } renderFindings(r); }));
    box.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => { const i = +tr.dataset.i; fState.open = fState.open === i ? -1 : i; renderFindings(r); }));
    renderDrawer(r);
  }

  function renderDrawer(r) {
    const d = $("drawer");
    const f = r.findings[fState.open];
    if (!f) { d.innerHTML = ""; return; }
    const ev = f.evidence || [];
    const cols = [...new Set(ev.flatMap((e) => Object.keys(e)))];
    const cell = (v) => (v && typeof v === "object" ? (v.den != null ? rateTxt(v) : JSON.stringify(v)) : typeof v === "boolean" ? (v ? "yes" : "no") : v);
    d.innerHTML = '<div class="' + P + '-drawer"><b>' + esc(f.title) + '</b><p class="' + P + '-help" style="font-size:.84rem">' + esc(f.description) + "</p><p><b>Recommendation.</b> " + esc(f.recommendation) + "</p>" +
      '<div class="' + P + '-help">Evidence: ' + (ev.length < f.evidenceCount ? "first " + ev.length + " of " + num(f.evidenceCount) + " rows (the full list is in the exports)" : num(ev.length) + " row(s)") + "</div>" +
      table(cols.map((c) => ({ label: c.replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase(), get: (e) => cell(e[c]) })), ev) + "</div>";
  }

  function renderExports(r) {
    const ex = $("exports");
    ex.innerHTML = '<button class="' + P + '-btn" data-x="csv">Findings CSV</button><button class="' + P + '-btn" data-x="json">Findings JSON</button><button class="' + P + '-btn" data-x="txt">Summary TXT</button>' +
      '<button class="' + P + '-btn" data-x="rep">Follow-up list CSV</button><button class="' + P + '-btn" data-x="dept">Department scorecard CSV</button>' +
      '<span class="' + P + '-field" style="min-width:200px;flex:1 1 200px;max-width:320px"><input type="text" id="' + P + '-course" placeholder="Course name" aria-label="Remedial course name"></span><button class="' + P + '-btn" data-x="rem">Remedial assignments CSV</button>';
    const stamp = () => TOOL_ID + "-" + fileStamp();
    const on = (x, fn) => ex.querySelector('[data-x="' + x + '"]').addEventListener("click", fn);
    on("csv", () => download(stamp() + "-findings.csv", findingsToCsv(r.findings), "text/csv"));
    on("json", () => download(stamp() + ".json", toJson(r), "application/json"));
    on("txt", () => download(stamp() + "-summary.txt", summaryText(r), "text/plain"));
    on("rep", () => download(stamp() + "-follow-up.csv", repeatClickersCsv(r), "text/csv"));
    on("dept", () => download(stamp() + "-department-scorecard.csv", departmentScorecardCsv(r), "text/csv"));
    on("rem", () => {
      const course = $("course").value.trim();
      if (!course) { toast("Type the course name to assign first.", "warning"); $("course").focus(); return; }
      download(stamp() + "-remedial-assignments.csv", remedialAssignmentsCsv(r, course), "text/csv");
    });
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: isExample ? "synthetic example" : files.map((f) => f.name).join(", ") });
  }

  // ---------------------------------------------------------------- history register
  function renderHistory() {
    const box = $("hist");
    if (!box) return;
    let list = [];
    try { list = reg.list(); } catch (_) {}
    const pc = result && result.tables ? result.tables.personCampaigns || [] : [];
    box.innerHTML = '<h3>History</h3><div class="' + P + '-help">Saved per-person campaign outcomes (campaign name, date, clicked, entered credentials, reported) for people who clicked, keyed by email, so later imports count repeat clicks across campaigns. No message content is stored. In a team workspace the history is shared with your team.</div>' +
      '<div class="' + P + '-row"><span><b>' + num(list.length) + "</b> people in history</span>" +
      '<button class="' + P + '-btn pri" id="' + P + '-hsave"' + (!pc.length || isExample ? " disabled" : "") + ">Save this import to history" + (pc.length ? " (" + num(new Set(pc.map((x) => x.email)).size) + " people)" : "") + "</button>" +
      '<button class="' + P + '-btn" id="' + P + '-hcsv"' + (list.length ? "" : " disabled") + ">Export CSV</button><button class=\"" + P + '-btn" id="' + P + '-hjson"' + (list.length ? "" : " disabled") + ">Export JSON</button>" +
      '<button class="' + P + '-btn" id="' + P + '-hclr"' + (list.length ? "" : " disabled") + ">Clear history</button></div>" +
      (isExample ? '<div class="' + P + '-help">The synthetic example is never saved to the history.</div>' : "") +
      '<div class="' + P + '-help">To import a saved history JSON, drop it on the exports area above.</div>';
    const b = (id) => box.querySelector("#" + P + "-" + id);
    b("hsave").addEventListener("click", async () => {
      if (isExample || !pc.length) return;
      const recs = mergeHistory(historyList(), pc);
      const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Save to history?", "Store campaign outcomes for " + recs.length + " people who clicked. Run Analyze again afterwards to include them in repeat-click counts.", { submitText: "Save" }) : false;
      if (!ok) return;
      for (const rec of recs) reg.upsert(rec);
      toast("Saved " + recs.length + " people to history", "success");
      renderHistory();
    });
    b("hcsv").addEventListener("click", () => download(TOOL_ID + "-history-" + fileStamp() + ".csv", reg.exportCsv(), "text/csv"));
    b("hjson").addEventListener("click", () => download(TOOL_ID + "-history-" + fileStamp() + ".json", reg.exportJson(), "application/json"));
    b("hclr").addEventListener("click", async () => {
      const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Clear awareness history?", "This removes " + list.length + " people and their saved campaign outcomes from the history and the Security Graph. Export it first if you may need it.", { danger: true, submitText: "Clear" }) : false;
      if (!ok) return;
      for (const rec of reg.list()) reg.remove(rec.id);
      toast("History cleared", "success");
      renderHistory();
    });
  }
  renderHistory();
}
