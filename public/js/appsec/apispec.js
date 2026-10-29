// API Security Review (apispec): Deck tool UI. Runs entirely in the browser; the engine
// executes in a Worker via ../ingest/worker.js. No native dialogs; toasts only.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import { DEFAULTS, DEFAULT_LABELS, TOOL_ID, SEVERITIES, OWASP_API_2023, parseInput, findingsToCsv, inventoryToCsv, toSarif, toTxt, exampleDataset } from "./apispec-engine.js?v=20261028c";

const ENGINE = engineUrl("./apispec-engine.js?v=20261028c", import.meta);
const P = "api";
const MAX_FILES = 50, MAX_BYTES = 50 * 1024 * 1024;
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtN = (n) => Number(n || 0).toLocaleString("en-US");
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CONF_ORDER = { confirmed: 0, likely: 1, review: 2 };
const owaspNum = (s) => Number(String(s || "").replace(/^API(\d+).*/, "$1")) || 99;
const HELP = {
  minSeverity: "Findings below this level are hidden and counted.",
  boundStrings: "API4: request strings without maxLength.",
  boundIntegers: "API4: request integers without maximum.",
  boundArrays: "API4: request arrays without maxItems.",
  adminPathPattern: "Path segments that mark admin or internal endpoints.",
  nonProdHostPattern: "Host labels that mark non-production servers.",
  objectIdPattern: "Path parameters treated as object ids for BOLA review.",
  maxRefDepth: "Deeper schemas are not walked (1 to 200).",
};

const CSS = `
  .api-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .api-root *{box-sizing:border-box}
  .api-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .api-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .api-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .api-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:100ch}
  .api-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .api-card h2{font-size:1rem;margin:0 0 10px}
  .api-note{font-size:.8rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .api-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .api-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .api-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .api-btn.sm{padding:4px 10px;font-size:.78rem}
  .api-btn:disabled{opacity:.5;cursor:default}
  .api-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:14px}
  .api-set{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,230px),1fr));gap:12px 18px}
  .api-field{display:flex;flex-direction:column;gap:4px;min-width:0}
  .api-field label{font-size:.76rem;font-weight:700;color:var(--mut,#667085)}
  .api-field input[type=text],.api-field input[type=number],.api-field select{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%}
  .api-field .api-chk{display:flex;gap:8px;align-items:center;font-size:.84rem;font-weight:600;color:var(--tx,#1a2230)}
  .api-field small{font-size:.74rem;color:var(--mut,#667085);overflow-wrap:anywhere}
  .api-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin:14px 0}
  .api-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .api-kpi b{display:block;font-size:1.3rem}
  .api-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .api-kpi.critical b{color:#7a0012}.api-kpi.high b{color:#b00020}.api-kpi.medium b{color:#946a00}
  .api-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .api-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .api-tbl{border:1px solid var(--line,#e6e8ee);border-radius:10px;overflow:auto;max-width:100%}
  .api-tbl table{width:100%;border-collapse:collapse;font-size:.83rem}
  .api-tbl th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .api-tbl th[data-sort]{cursor:pointer}
  .api-tbl th[data-sort]:hover{color:var(--tx,#1a2230)}
  .api-tbl td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word;word-break:normal}
  .api-tbl tr.api-click{cursor:pointer}
  .api-tbl tr.api-click:hover,.api-tbl tr.api-open{background:var(--bg,#f7f8fb)}
  .api-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.8rem;overflow-wrap:anywhere}
  .api-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .api-pill.critical{background:#7a0012}.api-pill.high{background:#b00020}.api-pill.medium{background:#946a00}.api-pill.low{background:#2552c6}.api-pill.info{background:#667085}
  .api-m{display:inline-block;font-size:.7rem;font-weight:700;padding:1px 6px;border-radius:5px;border:1px solid var(--line,#d7dbe3);white-space:nowrap}
  .api-chip{display:inline-block;font-size:.68rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .api-conf{font-size:.76rem;font-weight:600}
  .api-conf.review{color:var(--mut,#667085)}
  .api-empty{padding:24px;text-align:center;color:var(--mut,#667085)}
  .api-tabs{display:flex;flex-wrap:wrap;gap:6px;border-bottom:1px solid var(--line,#e6e8ee);margin:6px 0 12px}
  .api-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;background:none;border:0;border-bottom:2px solid transparent;color:var(--mut,#667085);padding:8px 10px;cursor:pointer}
  .api-tab.on{color:var(--tx,#1a2230);border-bottom-color:#2552c6}
  .api-detail{padding:12px 14px;background:var(--bg,#f7f8fb)}
  .api-detail p{margin:0 0 8px}
  .api-lbl{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);margin:10px 0 4px}
  .api-sel{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
  .api-sel input,.api-sel select{font:inherit;font-size:.82rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:6px 9px;max-width:100%}
  .api-bad{color:#b00020}
  .api-bar{height:8px;border-radius:4px;background:#2552c6;min-width:2px}
  .api-tbl > table{min-width:560px}
  @media (max-width:520px){.api-card{padding:12px}.api-hd h1{font-size:1.4rem}}
`;

function kpi(v, l, cls = "") { return '<div class="' + P + '-kpi ' + cls + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>"; }
const pill = (s) => '<span class="' + P + '-pill ' + esc(s) + '">' + esc(s) + "</span>";
const chips = (cs) => (cs || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework === "OWASP API Security Top 10 2023" ? "OWASP " + c.id : c.framework === "NIST SSDF (SP 800-218)" ? "SSDF " + c.id : c.framework === "CWE" ? c.id : c.framework + " " + c.id) + "</span>").join("");

/** Mount the tool into main. */
export function renderApiSpec(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = `<div class="${P}-root">
    <div class="${P}-hd"><h1>API Security Review</h1><span class="${P}-tag">Deck</span></div>
    <p class="${P}-sub">Reviews OpenAPI 3.0 / 3.1 and Swagger 2.0 (JSON or YAML), Postman collections (v2.1) and GraphQL schemas (SDL or introspection JSON) against the OWASP API Security Top 10 2023. Runs entirely in your browser. Nothing is uploaded and nothing is fetched live; external $ref files are listed, not downloaded.</p>
    <div class="${P}-card">
      <div id="${P}-drop"></div>
      <div class="${P}-row">
        <button class="${P}-btn" id="${P}-example" type="button">Load example (synthetic)</button>
        <button class="${P}-btn" id="${P}-clear" type="button" disabled>Clear files</button>
        <button class="${P}-btn pri" id="${P}-run" type="button" disabled>Review</button>
      </div>
      <p class="${P}-note">Drop one or more definitions (.yaml, .json, .graphql) or a .zip. Postman: Export the collection as v2.1. GraphQL: the SDL file or the JSON result of the introspection query.</p>
      <div class="${P}-prog" id="${P}-prog"><i></i></div>
    </div>
    <div class="${P}-grid">
      <div class="${P}-card"><h2>Files</h2><div id="${P}-files"><div class="${P}-empty">No files yet.</div></div></div>
      <div class="${P}-card"><h2>Settings</h2><div class="${P}-set" id="${P}-set"></div>
        <div class="${P}-row"><button class="${P}-btn sm" id="${P}-reset" type="button">Reset to defaults</button></div></div>
    </div>
    <div id="${P}-out"></div>
  </div>`;

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  const state = { files: new Map(), isExample: false, result: null, tab: "findings", sort: { key: "severity", dir: 1 }, open: null, fq: "", fowasp: "", esort: { key: "path", dir: 1 } };

  /* ---------- settings ---------- */
  function renderSettings(vals) {
    $("set").innerHTML = Object.keys(DEFAULTS).map((k) => {
      const v = vals[k], id = P + "-opt-" + k, lbl = esc(DEFAULT_LABELS[k] || k), help = '<small>' + esc(HELP[k] || "") + " Default: " + esc(DEFAULTS[k]) + "</small>";
      if (k === "minSeverity") return `<div class="${P}-field"><label for="${id}">${lbl}</label><select id="${id}" data-opt="${k}">${SEVERITIES.slice().reverse().map((s) => `<option value="${s}"${s === v ? " selected" : ""}>${s}</option>`).join("")}</select>${help}</div>`;
      if (typeof DEFAULTS[k] === "boolean") return `<div class="${P}-field"><label class="${P}-chk"><input type="checkbox" id="${id}" data-opt="${k}"${v ? " checked" : ""}> ${lbl}</label>${help}</div>`;
      if (typeof DEFAULTS[k] === "number") return `<div class="${P}-field"><label for="${id}">${lbl}</label><input type="number" min="1" max="200" id="${id}" data-opt="${k}" value="${esc(v)}">${help}</div>`;
      return `<div class="${P}-field"><label for="${id}">${lbl}</label><input type="text" id="${id}" data-opt="${k}" value="${esc(v)}" spellcheck="false">${help}</div>`;
    }).join("");
  }
  renderSettings(DEFAULTS);
  $("reset").addEventListener("click", () => renderSettings(DEFAULTS));
  const opts = () => {
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => {
      const k = el.dataset.opt;
      if (typeof DEFAULTS[k] === "boolean") o[k] = el.checked;
      else if (typeof DEFAULTS[k] === "number") { const n = Number(el.value); o[k] = Number.isFinite(n) && n > 0 ? n : DEFAULTS[k]; }
      else o[k] = String(el.value).trim() || DEFAULTS[k];
    });
    return o;
  };

  /* ---------- files ---------- */
  async function addFiles(list, skippedIn = []) {
    if (state.isExample) { state.files.clear(); state.isExample = false; }
    const skipped = skippedIn.slice();
    let added = 0;
    for (const f of list) {
      if (state.files.size >= MAX_FILES) { skipped.push({ name: f.name, reason: "over " + MAX_FILES + " files" }); continue; }
      let text = "";
      try { text = await f.text(); } catch (_) { skipped.push({ name: f.name, reason: "unreadable" }); continue; }
      const det = parseInput([{ name: f.name, text }]).rows[0];
      state.files.set(f.name, { name: f.name, text, det, archive: f.fromArchive || "" });
      added++;
    }
    state.result = null;
    renderFiles(skipped); renderOut();
    if (added) toast("Added " + added + " file" + (added === 1 ? "" : "s"), "info");
    if (skipped.length) toast(skipped.length + " file(s) skipped", "warning");
  }
  mountDropzone($("drop"), {
    maxBytes: MAX_BYTES, maxFiles: MAX_FILES, unpack: true, multiple: true,
    label: "Drop API definitions here, paste, or browse",
    onFiles: (files, { skipped }) => addFiles(files, (skipped || []).map((s) => ({ name: s.name, reason: s.reason }))),
    onError: (e) => toast(String((e && e.message) || e), "error"),
  });
  $("example").addEventListener("click", () => {
    state.files.clear();
    for (const f of exampleDataset().files) state.files.set(f.name, { name: f.name, text: f.text, det: parseInput([f]).rows[0], archive: "" });
    state.isExample = true; state.result = null;
    renderFiles([]); renderOut();
    toast("Loaded the synthetic example (fictional Payments API)", "info");
  });
  $("clear").addEventListener("click", () => { state.files.clear(); state.isExample = false; state.result = null; renderFiles([]); renderOut(); });

  function renderFiles(skipped) {
    const host = $("files");
    $("run").disabled = !state.files.size;
    $("clear").disabled = !state.files.size;
    if (!state.files.size) { host.innerHTML = `<div class="${P}-empty">No files yet.</div>`; return; }
    const res = state.result ? new Map(state.result.tables.files.map((r) => [r.name, r])) : new Map();
    const rows = [...state.files.values()].sort((a, b) => (a.name < b.name ? -1 : 1));
    host.innerHTML = `${state.isExample ? `<p class="${P}-note" style="margin:0 0 8px">Synthetic example: a fictional API, not real data.</p>` : ""}<div class="${P}-tbl"><table><thead><tr><th>File</th><th>Detected format</th><th>Confidence</th><th>Endpoints</th><th>Notes</th></tr></thead><tbody>${rows.map((f) => {
      const r = res.get(f.name);
      const bad = f.det.error || f.det.format === "unknown" || f.det.format === "empty";
      const note = f.det.error || f.det.reason || (f.det.confidence !== "high" && !bad ? "Read as " + f.det.label + "; check the result." : "");
      return `<tr><td class="${P}-mono">${esc(f.name)}${f.archive ? `<div class="${P}-note">from ${esc(f.archive)}</div>` : ""}</td><td>${esc(f.det.label)}</td><td>${esc(f.det.confidence)}</td><td>${r ? fmtN(r.endpoints) : "-"}</td><td class="${bad ? P + "-bad" : ""}">${esc(note)}${r && r.title ? `<div>${esc(r.title + (r.version ? " " + r.version : ""))}</div>` : ""}</td></tr>`;
    }).join("")}</tbody></table></div><p class="${P}-note">Structured definitions are read by their own keys, so no column mapping is needed. A file that is not recognised is listed under Not evaluated and never guessed.</p>${skipped && skipped.length ? `<p class="${P}-note ${P}-bad">Skipped: ${skipped.slice(0, 10).map((s) => esc(s.name + " (" + s.reason + ")")).join(", ")}</p>` : ""}`;
  }

  /* ---------- run ---------- */
  $("run").addEventListener("click", async () => {
    const prog = $("prog"), bar = prog.firstElementChild;
    prog.style.display = "block"; bar.style.width = "0%"; $("run").disabled = true;
    const files = [...state.files.values()].map((f) => ({ name: f.name, text: f.text }));
    try {
      state.result = await runInWorker(ENGINE, "analyze", [files, opts()], {
        timeoutMs: 300000,
        onProgress: (i, n) => { bar.style.width = (n ? Math.round((i / n) * 100) : 0) + "%"; },
      });
      state.open = null;
      renderFiles([]); renderOut();
      toast(state.result.findings.length + " finding(s) across " + state.result.summary.endpoints + " endpoint(s)", state.result.findings.length ? "warning" : "success");
    } catch (e) {
      toast("Review failed: " + ((e && e.message) || e), "error");
    } finally {
      prog.style.display = "none"; $("run").disabled = !state.files.size;
    }
  });

  /* ---------- results ---------- */
  function renderOut() {
    const out = $("out"), r = state.result;
    if (!r) { out.innerHTML = state.files.size ? `<div class="${P}-card ${P}-empty">Ready. Press Review.</div>` : ""; return; }
    const s = r.summary;
    out.innerHTML = `<div class="${P}-kpis">
        ${kpi(fmtN(s.files), "files")}${kpi(fmtN(s.endpoints), "endpoints")}${kpi(fmtN(s.unauthenticated), "no documented auth")}${kpi(fmtN(s.findings), "findings")}
        ${SEVERITIES.map((k) => kpi(fmtN(s.bySeverity[k]), k, k)).join("")}
      </div>
      ${state.isExample ? `<p class="${P}-note" style="margin:-4px 0 12px">Synthetic example: these findings come from a fictional API, not your systems.</p>` : ""}
      <div class="${P}-card">
        <div class="${P}-row" style="margin-top:0" id="${P}-exports">
          <button class="${P}-btn" type="button" data-x="csv">Findings CSV</button>
          <button class="${P}-btn" type="button" data-x="sarif">SARIF</button>
          <button class="${P}-btn" type="button" data-x="inv">Endpoint inventory CSV</button>
          <button class="${P}-btn" type="button" data-x="json">JSON</button>
          <button class="${P}-btn" type="button" data-x="txt">Summary TXT</button>
        </div>
        ${s.filteredOut ? `<p class="${P}-note">${fmtN(s.filteredOut)} finding(s) below the severity threshold are hidden.</p>` : ""}
        <div class="${P}-tabs" role="tablist">${[["findings", "Findings (" + r.findings.length + ")"], ["endpoints", "Endpoints (" + r.tables.endpoints.length + ")"], ["owasp", "OWASP Top 10"], ["skipped", "Not evaluated (" + r.skipped.length + ")"]].map(([k, l]) => `<button type="button" role="tab" class="${P}-tab${state.tab === k ? " on" : ""}" data-tab="${k}">${esc(l)}</button>`).join("")}</div>
        <div id="${P}-tabbody"></div>
      </div>`;
    const ex = $("exports");
    const stamp = () => TOOL_ID + "-" + fileStamp();
    ex.querySelector('[data-x="csv"]').addEventListener("click", () => download(stamp() + "-findings.csv", findingsToCsv(r.findings), "text/csv"));
    ex.querySelector('[data-x="sarif"]').addEventListener("click", () => download(stamp() + ".sarif", toJson(toSarif(r)), "application/sarif+json"));
    ex.querySelector('[data-x="inv"]').addEventListener("click", () => download(stamp() + "-endpoints.csv", inventoryToCsv(r.tables.endpoints), "text/csv"));
    ex.querySelector('[data-x="json"]').addEventListener("click", () => download(stamp() + ".json", toJson(r), "application/json"));
    ex.querySelector('[data-x="txt"]').addEventListener("click", () => download(stamp() + "-summary.txt", toTxt(r) + "\nGraph summary: " + JSON.stringify(summarize(r.findings)) + "\n", "text/plain"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: state.isExample }), TOOL_ID, { dataset: state.isExample ? "synthetic example" : [...state.files.keys()].slice(0, 3).join(", ") + (state.files.size > 3 ? " +" + (state.files.size - 3) : "") });
    out.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.tab; renderOut(); }));
    renderTab();
  }

  function renderTab() {
    const host = $("tabbody"), r = state.result;
    if (state.tab === "findings") return renderFindings(host, r);
    if (state.tab === "endpoints") return renderEndpoints(host, r);
    if (state.tab === "owasp") {
      const max = Math.max(1, ...r.tables.owasp.map((x) => x.findings));
      host.innerHTML = `<div class="${P}-tbl"><table><thead><tr><th>Category</th><th>Findings</th><th style="width:40%"></th></tr></thead><tbody>${r.tables.owasp.map((x) => `<tr class="${P}-click" data-ow="${esc(x.id)}"><td><b>${esc(x.id)}</b> ${esc(x.name)}</td><td>${fmtN(x.findings)}</td><td>${x.findings ? `<div class="${P}-bar" style="width:${Math.round((x.findings / max) * 100)}%"></div>` : ""}</td></tr>`).join("")}</tbody></table></div>
        <p class="${P}-note">Counts come from static checks of the definitions only. API6 (business flows) and API10 (unsafe consumption) depend mostly on runtime behaviour, so a zero there is not a clean bill of health.</p>`;
      host.querySelectorAll("[data-ow]").forEach((tr) => tr.addEventListener("click", () => { state.fowasp = tr.dataset.ow; state.tab = "findings"; renderOut(); }));
      return;
    }
    host.innerHTML = r.skipped.length ? `<p class="${P}-note" style="margin:0 0 8px">Checks or files that could not be evaluated. Nothing here is guessed.</p><div class="${P}-tbl"><table><thead><tr><th>Check</th><th>Reason</th></tr></thead><tbody>${r.skipped.map((x) => `<tr><td class="${P}-mono">${esc(x.check)}</td><td>${esc(x.reason)}</td></tr>`).join("")}</tbody></table></div>` : `<div class="${P}-empty">Every applicable check ran.</div>`;
  }

  const SORTS = {
    severity: (a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity],
    finding: (a, b) => (a.title < b.title ? -1 : a.title > b.title ? 1 : 0),
    operation: (a, b) => (a.operation < b.operation ? -1 : a.operation > b.operation ? 1 : 0),
    owasp: (a, b) => owaspNum(a.owasp) - owaspNum(b.owasp),
    confidence: (a, b) => CONF_ORDER[a.confidence] - CONF_ORDER[b.confidence],
    evidence: (a, b) => a.evidenceCount - b.evidenceCount,
  };
  function renderFindings(host, r) {
    let list = r.findings.map((f, i) => ({ f, i }));
    if (state.fowasp) list = list.filter(({ f }) => f.owasp === state.fowasp);
    if (state.fq) { const q = state.fq.toLowerCase(); list = list.filter(({ f }) => (f.ruleId + " " + f.title + " " + f.operation + " " + f.file + " " + f.pointer).toLowerCase().includes(q)); }
    const c = SORTS[state.sort.key] || SORTS.severity;
    list.sort((a, b) => c(a.f, b.f) * state.sort.dir || a.i - b.i);
    const shown = list.slice(0, 500);
    const th = (k, l) => `<th data-sort="${k}">${l}${state.sort.key === k ? (state.sort.dir > 0 ? " (asc)" : " (desc)") : ""}</th>`;
    host.innerHTML = `<div class="${P}-sel">
        <select id="${P}-fow" aria-label="OWASP category"><option value="">All OWASP categories</option>${Object.keys(OWASP_API_2023).map((k) => `<option value="${k}:2023"${state.fowasp === k + ":2023" ? " selected" : ""}>${k} ${esc(OWASP_API_2023[k])}</option>`).join("")}</select>
        <input id="${P}-fq" type="search" placeholder="Filter findings" value="${esc(state.fq)}">
      </div>
      ${r.findings.length ? `<div class="${P}-tbl"><table><thead><tr>${th("severity", "Severity")}${th("finding", "Finding")}${th("operation", "Operation")}${th("owasp", "OWASP")}${th("confidence", "Confidence")}<th>Controls</th>${th("evidence", "Evidence")}</tr></thead><tbody>${shown.map(({ f, i }) => `<tr class="${P}-click${state.open === i ? " " + P + "-open" : ""}" data-i="${i}">
          <td>${pill(f.severity)}</td><td><b>${esc(f.title)}</b><div class="${P}-note" style="margin:0">${esc(f.file)}:${f.line}</div></td><td class="${P}-mono">${esc(f.operation || "(definition)")}</td><td>${esc(f.owasp)}</td>
          <td><span class="${P}-conf ${esc(f.confidence)}">${esc(f.confidence)}</span></td><td>${chips(f.controls)}</td><td>${f.evidenceCount}</td></tr>${state.open === i ? `<tr><td colspan="7" class="${P}-detail">${detail(f)}</td></tr>` : ""}`).join("")}</tbody></table></div>
        ${list.length > shown.length ? `<p class="${P}-note">Showing ${shown.length} of ${fmtN(list.length)}; the exports have all.</p>` : ""}${!list.length ? `<div class="${P}-empty">No findings match the filter.</div>` : ""}`
      : `<div class="${P}-empty">No findings at this severity threshold. Check Not evaluated for anything that could not be read.</div>`}`;
    host.querySelector("#" + P + "-fow").addEventListener("change", (e) => { state.fowasp = e.target.value; renderTab(); });
    const fq = host.querySelector("#" + P + "-fq");
    fq.addEventListener("input", (e) => { state.fq = e.target.value; const pos = e.target.selectionStart; renderTab(); const n = $("fq"); if (n) { n.focus(); try { n.setSelectionRange(pos, pos); } catch (_) {} } });
    host.querySelectorAll("th[data-sort]").forEach((t) => t.addEventListener("click", () => { const k = t.dataset.sort; state.sort = { key: k, dir: state.sort.key === k ? -state.sort.dir : 1 }; renderTab(); }));
    host.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", (e) => { if (e.target.closest("[data-tester]")) return; const i = Number(tr.dataset.i); state.open = state.open === i ? null : i; renderTab(); }));
    host.querySelectorAll("[data-tester]").forEach((b) => b.addEventListener("click", (e) => { e.stopPropagation(); openTester(b.dataset.method, b.dataset.tester); }));
  }

  function detail(f) {
    const method = (f.operation || "").split(" ")[0];
    const tester = f.url && /^(GET|PUT|POST|DELETE|PATCH|HEAD|OPTIONS)$/.test(method)
      ? `<div class="${P}-row" style="margin-top:4px"><button type="button" class="${P}-btn sm" data-tester="${esc(f.url)}" data-method="${esc(method)}">Open in API Tester</button><span class="${P}-note" style="margin:0">Copies ${esc(method)} ${esc(f.url)} and opens the API Tester. Nothing is sent until you press Send there.</span></div>` : "";
    return `<p>${esc(f.description)}</p>
      <div class="${P}-lbl">Recommended fix</div><p>${esc(f.recommendation)}</p>
      <div class="${P}-lbl">Location</div><p class="${P}-mono">${esc(f.file)}:${f.line}${f.pointer ? " " + esc(f.pointer) : ""}</p>
      <div class="${P}-lbl">Evidence (${f.evidence.length === f.evidenceCount ? f.evidenceCount : "showing " + f.evidence.length + " of " + f.evidenceCount}; secret values are masked)</div>
      <div class="${P}-tbl"><table><thead><tr><th>Line</th><th>Operation</th><th>Field</th><th>Detail</th><th>JSON pointer</th></tr></thead><tbody>${f.evidence.map((e) => `<tr><td>${esc(e.line)}</td><td class="${P}-mono">${esc(e.operation || "-")}</td><td class="${P}-mono">${esc(e.field)}</td><td>${esc(e.detail)}</td><td class="${P}-mono">${esc(e.pointer || "-")}</td></tr>`).join("")}</tbody></table></div>
      <div class="${P}-lbl">References</div><div>${chips(f.controls)}</div>${tester}`;
  }

  function renderEndpoints(host, r) {
    const rows = r.tables.endpoints.slice();
    const k = state.esort.key, d = state.esort.dir;
    rows.sort((a, b) => (k === "findings" ? a.findings - b.findings : String(a[k]).localeCompare(String(b[k]))) * d || a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
    const th = (key, l) => `<th data-esort="${key}">${l}${k === key ? (d > 0 ? " (asc)" : " (desc)") : ""}</th>`;
    host.innerHTML = rows.length ? `<div class="${P}-tbl"><table><thead><tr>${th("method", "Method")}${th("path", "Path")}${th("auth", "Auth")}${th("findings", "Findings")}${th("file", "File")}</tr></thead><tbody>${rows.slice(0, 2000).map((e) => `<tr class="${P}-click" data-op="${esc(e.operation)}"><td><span class="${P}-m">${esc(e.method)}</span>${e.deprecated ? ` <span class="${P}-chip">deprecated</span>` : ""}</td><td class="${P}-mono">${esc(e.path)}</td><td class="${e.auth === "none" ? P + "-bad" : ""}">${esc(e.auth)}</td><td>${e.findings}</td><td class="${P}-mono">${esc(e.file)}:${e.line}</td></tr>`).join("")}</tbody></table></div>${rows.length > 2000 ? `<p class="${P}-note">Showing 2000 of ${fmtN(rows.length)}; the inventory CSV has all.</p>` : ""}<p class="${P}-note">Click an endpoint to see its findings.</p>` : `<div class="${P}-empty">No endpoints were found.</div>`;
    host.querySelectorAll("th[data-esort]").forEach((t) => t.addEventListener("click", () => { const key = t.dataset.esort; state.esort = { key, dir: state.esort.key === key ? -state.esort.dir : 1 }; renderTab(); }));
    host.querySelectorAll("tr[data-op]").forEach((tr) => tr.addEventListener("click", () => { state.fq = tr.dataset.op; state.fowasp = ""; state.tab = "findings"; renderOut(); }));
  }

  async function openTester(method, url) {
    const line = method + " " + url;
    let copied = false;
    try { if (navigator.clipboard) { await navigator.clipboard.writeText(line); copied = true; } } catch (_) {}
    toast(copied ? "Copied " + line + ". Paste it into the API Tester." : "Open the API Tester and enter " + line, "info");
    try { if (typeof window.dnNavigate === "function" && window.dnNavigate("apitester")) return; } catch (_) {}
    window.location.href = "/apitester";
  }
}
