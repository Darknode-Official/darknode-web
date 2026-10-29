// License Compliance (licenseaudit): Deck tool UI. Parsing for the file list runs on the main
// thread; analysis runs in a Worker via ../ingest/worker.js. The only network use is the
// optional "Resolve unknown licenses" lookup, which the user starts. No native dialogs.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import { dnFetch, proxyConfigured } from "../net.js";
import {
  DEFAULTS, TOOL_ID, CONTEXTS, CATEGORY_LABEL, SEVERITIES, COLUMNS, parseInput, findingsToCsv, inventoryToCsv, toNotice, toSpdx, toTxt,
  exampleDataset, resolutionPlan, extractResolvedLicense,
} from "./licenseaudit-engine.js?v=20261029a";

const ENGINE = engineUrl("./licenseaudit-engine.js?v=20261029a", import.meta);
const P = "lic";
const MAX_FILES = 50, MAX_BYTES = 64 * 1024 * 1024, RESOLVE_LIMIT = 200, RESOLVE_GAP_MS = 350;
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtN = (n) => Number(n || 0).toLocaleString("en-US");
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CONF_ORDER = { confirmed: 0, likely: 1, review: 2 };
const CAT_ORDER = { "network-copyleft": 0, proprietary: 1, "strong-copyleft": 2, unknown: 3, "weak-copyleft": 4, permissive: 5, "public-domain": 6 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const cacheGet = (k) => { try { const v = sessionStorage.getItem("lic-res:" + k); return v ? JSON.parse(v) : null; } catch (_) { return null; } };
const cacheSet = (k, v) => { try { sessionStorage.setItem("lic-res:" + k, JSON.stringify(v)); } catch (_) {} };

const CSS = `
  .lic-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .lic-root *{box-sizing:border-box}
  .lic-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .lic-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .lic-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .lic-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:100ch;overflow-wrap:anywhere}
  .lic-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .lic-card h2{font-size:1rem;margin:0 0 10px}
  .lic-note{font-size:.8rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .lic-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .lic-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .lic-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .lic-btn.sm{padding:4px 10px;font-size:.78rem}
  .lic-btn:disabled{opacity:.5;cursor:default}
  .lic-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:14px 18px}
  .lic-field{display:flex;flex-direction:column;gap:4px;min-width:0}
  .lic-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .lic-field input,.lic-field select,.lic-field textarea{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;min-width:0}
  .lic-field textarea{min-height:64px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.8rem}
  .lic-help{font-size:.74rem;color:var(--mut,#667085);line-height:1.4;overflow-wrap:anywhere}
  .lic-check{display:flex;gap:8px;align-items:flex-start;font-size:.84rem}
  .lic-check input{margin-top:4px;flex:none}
  .lic-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(118px,1fr));gap:10px;margin:14px 0}
  .lic-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .lic-kpi b{display:block;font-size:1.3rem}
  .lic-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .lic-kpi.critical b{color:#7a0012}.lic-kpi.high b{color:#b00020}.lic-kpi.medium b{color:#946a00}
  .lic-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .lic-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .lic-proglbl{font-size:.78rem;color:var(--mut,#667085);margin-top:4px;display:none}
  .lic-tbl{border:1px solid var(--line,#e6e8ee);border-radius:10px;overflow:auto;max-width:100%}
  .lic-tbl table{width:100%;border-collapse:collapse;font-size:.83rem}
  .lic-tbl th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .lic-tbl th[data-sort]{cursor:pointer}
  .lic-tbl th[data-sort]:hover{color:var(--tx,#1a2230)}
  .lic-tbl td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word;word-break:normal}
  .lic-tbl tr.lic-click{cursor:pointer}
  .lic-tbl tr.lic-click:hover,.lic-tbl tr.lic-open{background:var(--bg,#f7f8fb)}
  .lic-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.8rem;overflow-wrap:anywhere}
  .lic-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .lic-pill.critical{background:#7a0012}.lic-pill.high{background:#b00020}.lic-pill.medium{background:#946a00}.lic-pill.low{background:#2552c6}.lic-pill.info{background:#667085}
  .lic-cat{display:inline-block;font-size:.7rem;font-weight:600;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;white-space:nowrap}
  .lic-cat.network-copyleft,.lic-cat.proprietary{color:#b00020;border-color:#b00020}
  .lic-cat.strong-copyleft{color:#a33a00;border-color:#a33a00}
  .lic-cat.weak-copyleft,.lic-cat.unknown{color:#946a00;border-color:#946a00}
  .lic-cat.permissive,.lic-cat.public-domain{color:#1d6b3a;border-color:#1d6b3a}
  .lic-chip{display:inline-block;font-size:.68rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);overflow-wrap:anywhere}
  .lic-conf{font-size:.76rem;font-weight:600}
  .lic-conf.review{color:var(--mut,#667085)}
  .lic-empty{padding:24px;text-align:center;color:var(--mut,#667085)}
  .lic-root .lic-tabs{display:flex;flex-wrap:wrap !important;overflow:visible !important;gap:6px;border-bottom:1px solid var(--line,#e6e8ee);margin:6px 0 12px}
  .lic-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;background:none;border:0;border-bottom:2px solid transparent;color:var(--mut,#667085);padding:8px 10px;cursor:pointer}
  .lic-tab.on{color:var(--tx,#1a2230);border-bottom-color:#2552c6}
  .lic-detail{padding:12px 14px;background:var(--bg,#f7f8fb)}
  .lic-detail p{margin:0 0 8px;overflow-wrap:anywhere}
  .lic-lbl{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);margin:10px 0 4px}
  .lic-ev{max-height:360px}
  .lic-ev table{font-size:.78rem}
  .lic-ev td{min-width:90px}
  .lic-sel{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
  .lic-sel input,.lic-sel select{font:inherit;font-size:.82rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:6px 9px;max-width:100%;min-width:0}
  .lic-map{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,180px),1fr));gap:10px;margin-top:8px}
  .lic-bad{color:#b00020}
  .lic-warn{border-left:3px solid #946a00;padding:6px 10px;background:var(--bg,#f7f8fb);border-radius:6px;font-size:.8rem;margin-top:10px;overflow-wrap:anywhere}
  @media (max-width:520px){.lic-card{padding:12px}.lic-hd h1{font-size:1.4rem}}
`;

function kpi(v, l, cls = "") { return '<div class="' + P + '-kpi ' + cls + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>"; }
const pill = (s) => '<span class="' + P + '-pill ' + esc(s) + '">' + esc(s) + "</span>";
const cat = (c) => '<span class="' + P + '-cat ' + esc(c) + '">' + esc(CATEGORY_LABEL[c] || c) + "</span>";
const splitList = (s) => String(s || "").split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);

/** Mount the tool into main. */
export function renderLicenseAudit(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = `<div class="${P}-root">
    <div class="${P}-hd"><h1>Licenses</h1><span class="${P}-tag">Deck</span></div>
    <p class="${P}-sub">Builds a license inventory from lockfiles and CycloneDX or SPDX SBOMs, parses every SPDX expression, and checks copyleft obligations for how you distribute, known incompatibilities and your own allow, review and deny lists. Runs entirely in your browser. Nothing is uploaded. The optional Resolve unknown licenses step sends only package names and versions, through the Darknode fetch proxy, to registry.npmjs.org, pypi.org, crates.io and api.clearlydefined.io.</p>
    <div class="${P}-card">
      <div id="${P}-drop"></div>
      <div class="${P}-row">
        <button class="${P}-btn" id="${P}-example" type="button">Load example (synthetic)</button>
        <button class="${P}-btn" id="${P}-clear" type="button" disabled>Clear files</button>
        <button class="${P}-btn pri" id="${P}-run" type="button" disabled>Analyze</button>
      </div>
      <p class="${P}-note">Accepts package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt, Pipfile.lock, poetry.lock, go.sum, go.mod, Cargo.lock, Gemfile.lock, composer.lock, pom.xml, package.json (project license), CycloneDX 1.4-1.6 JSON or XML, SPDX 2.3 JSON or tag-value, license-checker and pip-licenses reports, and CSV inventories. Load several at once; packages are merged and SBOM licenses win over lockfile fields.</p>
      <div class="${P}-prog" id="${P}-prog"><i></i></div><div class="${P}-proglbl" id="${P}-proglbl"></div>
    </div>
    <div class="${P}-card"><h2>Files</h2><div id="${P}-files"><div class="${P}-empty">No files yet.</div></div></div>
    <div class="${P}-card"><h2>Policy and distribution</h2>
      <div class="${P}-grid">
        <div class="${P}-field"><label for="${P}-ctx">How the software is distributed</label>
          <select id="${P}-ctx">${Object.entries(CONTEXTS).map(([k, v]) => `<option value="${k}"${k === DEFAULTS.context ? " selected" : ""}>${esc(v)}</option>`).join("")}</select>
          <span class="${P}-help">Decides which copyleft obligations are triggered. Default: shipped binary.</span></div>
        <div class="${P}-field"><label for="${P}-proj">Your product's license</label>
          <input id="${P}-proj" type="text" placeholder="SPDX id" autocomplete="off" spellcheck="false">
          <span class="${P}-help">Leave blank to use the license in the SBOM metadata or package.json. Used for incompatibility checks against GPL-family projects.</span></div>
        <div class="${P}-field"><label>&nbsp;</label>
          <label class="${P}-check" style="text-transform:none;letter-spacing:0;font-weight:400;color:inherit;font-size:.84rem"><input type="checkbox" id="${P}-dev"${DEFAULTS.includeDev ? " checked" : ""}> Include development-only packages in obligation checks</label>
          <span class="${P}-help">Off by default: dev dependencies are not distributed with the product.</span></div>
      </div>
      <div class="${P}-grid" style="margin-top:14px">
        <div class="${P}-field"><label for="${P}-allow">Allow list</label><textarea id="${P}-allow" placeholder="MIT" spellcheck="false"></textarea>
          <span class="${P}-help">One per line or comma separated: SPDX ids, globs such as GPL-*, or a category (permissive, public-domain, weak-copyleft, strong-copyleft, network-copyleft, proprietary, unknown). If set, licenses on no list are reported.</span></div>
        <div class="${P}-field"><label for="${P}-review">Review list</label><textarea id="${P}-review" placeholder="weak-copyleft" spellcheck="false"></textarea>
          <span class="${P}-help">Licenses that need a recorded review before use.</span></div>
        <div class="${P}-field"><label for="${P}-deny">Deny list</label><textarea id="${P}-deny" placeholder="AGPL-*" spellcheck="false"></textarea>
          <span class="${P}-help">Deny beats review beats allow. Where a package offers a choice (OR), a denied option is avoided if another is allowed.</span></div>
      </div>
    </div>
    <div id="${P}-out"></div>
  </div>`;

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  const state = { files: new Map(), mapping: {}, parsed: null, isExample: false, result: null, resolved: {}, resolving: false, cancel: false, tab: "findings", sort: { key: "severity", dir: 1 }, open: null, fq: "", isort: { key: "category", dir: 1 }, iq: "", icat: "" };

  /* ---------- files ---------- */
  function reparse() {
    const list = [...state.files.values()].map((f) => ({ name: f.name, text: f.text }));
    state.parsed = list.length ? parseInput(list, { mapping: state.mapping }) : null;
  }
  async function addFiles(list, skippedIn = []) {
    if (state.isExample) { state.files.clear(); state.isExample = false; state.resolved = {}; }
    let added = 0;
    const skipped = skippedIn.slice();
    for (const f of list) {
      if (state.files.size >= MAX_FILES) { skipped.push({ name: f.name, reason: "over " + MAX_FILES + " files" }); continue; }
      let text = "";
      try { text = await f.text(); } catch (_) { skipped.push({ name: f.name, reason: "unreadable" }); continue; }
      state.files.set(f.name, { name: f.name, text, archive: f.fromArchive || "" });
      added++;
    }
    state.result = null;
    reparse(); renderFiles(skipped); renderOut();
    if (added) toast("Added " + added + " file" + (added === 1 ? "" : "s"), "info");
    if (skipped.length) toast(skipped.length + " file(s) skipped", "warning");
  }
  mountDropzone($("drop"), {
    maxBytes: MAX_BYTES, maxFiles: MAX_FILES, unpack: true, multiple: true,
    label: "Drop lockfiles, SBOMs or license reports here, paste, or browse",
    onFiles: (files, { skipped } = {}) => addFiles(files, (skipped || []).map((s) => ({ name: s.name, reason: s.reason }))),
    onError: (e) => toast(String((e && e.message) || e), "error"),
  });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    state.files.clear(); state.mapping = {}; state.resolved = {};
    for (const f of ex.files) state.files.set(f.name, { name: f.name, text: f.text, archive: "" });
    state.isExample = true; state.result = null;
    reparse(); renderFiles([]); renderOut();
    toast("Loaded the synthetic example", "info");
  });
  $("clear").addEventListener("click", () => { state.files.clear(); state.mapping = {}; state.resolved = {}; state.isExample = false; state.result = null; reparse(); renderFiles([]); renderOut(); });

  function renderFiles(skipped) {
    const host = $("files");
    $("run").disabled = !state.files.size;
    $("clear").disabled = !state.files.size;
    if (!state.parsed || !state.parsed.files.length) {
      host.innerHTML = `<div class="${P}-empty">No files yet.</div>${skipped && skipped.length ? `<p class="${P}-note ${P}-bad">Skipped: ${skipped.map((s) => esc(s.name + " (" + s.reason + ")")).join(", ")}</p>` : ""}`;
      return;
    }
    const fl = state.parsed.files;
    const needMap = fl.filter((f) => (f.format === "license-csv" || f.format === "license-json") && f.headers && f.headers.length);
    host.innerHTML = `${state.isExample ? `<p class="${P}-note" style="margin:0 0 10px">Synthetic example: a fictional app, not real data. Package names and their licenses are the real ones; the vendored components are invented.</p>` : ""}
      <div class="${P}-tbl"><table><thead><tr><th>File</th><th>Detected format</th><th>Confidence</th><th>Packages</th><th>Notes</th></tr></thead><tbody>${fl.map((f) => `<tr>
        <td class="${P}-mono">${esc(f.name)}${state.files.get(f.name) && state.files.get(f.name).archive ? `<div class="${P}-note">from ${esc(state.files.get(f.name).archive)}</div>` : ""}</td>
        <td>${esc(f.label)}${f.specVersion ? ` <span class="${P}-chip">${esc(f.specVersion)}</span>` : ""}${f.project && (f.project.name || f.project.license) ? `<div class="${P}-note">project ${esc(f.project.name || "")}${f.project.license ? " (" + esc(f.project.license) + ")" : ""}</div>` : ""}</td>
        <td><span class="${P}-conf ${f.confidence === "high" ? "" : "review"}">${esc(f.confidence)}</span></td>
        <td>${fmtN(f.components.length)}${f.hasGraph ? `<div class="${P}-note">dependency paths</div>` : ""}</td>
        <td>${f.issues.map((i) => `<div class="${P}-note" style="margin:0">${esc(i)}</div>`).join("")}</td></tr>`).join("")}</tbody></table></div>
      ${needMap.map((f) => mappingPanel(f)).join("")}
      ${skipped && skipped.length ? `<p class="${P}-note ${P}-bad">Skipped: ${skipped.slice(0, 10).map((s) => esc(s.name + " (" + s.reason + ")")).join(", ")}</p>` : ""}`;
    host.querySelectorAll("[data-map]").forEach((sel) => sel.addEventListener("change", () => {
      const file = sel.dataset.file, key = sel.dataset.map;
      state.mapping[file] = Object.assign({}, state.mapping[file] || {}, { [key]: sel.value || undefined });
      state.result = null; reparse(); renderFiles([]); renderOut();
    }));
  }
  function mappingPanel(f) {
    const cur = Object.assign({}, f.columns || {}, state.mapping[f.name] || {});
    const show = f.confidence !== "high" || state.mapping[f.name];
    if (!show) return "";
    const labels = { name: "Package name", version: "Version", license: "License", ecosystem: "Ecosystem (optional)", purl: "Package URL (optional)" };
    return `<div class="${P}-warn"><b>Column mapping for ${esc(f.name)}</b>: the headers were not all recognised. Pick which column holds each field.
      <div class="${P}-map">${Object.keys(COLUMNS).map((k) => `<div class="${P}-field"><label for="${P}-map-${esc(f.name)}-${k}">${labels[k]}</label>
        <select id="${P}-map-${esc(f.name)}-${k}" data-map="${k}" data-file="${esc(f.name)}"><option value="">(none)</option>${f.headers.map((h) => `<option value="${esc(h)}"${cur[k] === h ? " selected" : ""}>${esc(h)}</option>`).join("")}</select></div>`).join("")}</div></div>`;
  }

  /* ---------- run ---------- */
  const opts = () => ({
    context: $("ctx").value, projectLicense: $("proj").value.trim(), includeDev: $("dev").checked,
    allow: splitList($("allow").value), review: splitList($("review").value), deny: splitList($("deny").value), resolved: state.resolved,
  });
  async function analyzeNow(quiet) {
    if (!state.parsed) return;
    const prog = $("prog"), bar = prog.firstElementChild, lbl = $("proglbl");
    prog.style.display = "block"; lbl.style.display = "block"; bar.style.width = "0%"; lbl.textContent = "Analysing";
    $("run").disabled = true;
    try {
      state.result = await runInWorker(ENGINE, "analyze", [state.parsed, opts()], {
        timeoutMs: 300000,
        onProgress: (i, n, l) => { bar.style.width = (n ? Math.round((i / n) * 100) : 0) + "%"; lbl.textContent = (l === "merge" ? "Merging packages " : l === "done" ? "Done " : "Evaluating licenses ") + fmtN(i) + " / " + fmtN(n); },
      });
      state.open = null;
      renderOut();
      if (!quiet) toast(state.result.findings.length + " finding(s) across " + fmtN(state.result.summary.components) + " package(s)", state.result.findings.length ? "warning" : "success");
    } catch (e) {
      toast("Analysis failed: " + ((e && e.message) || e), "error");
    } finally {
      prog.style.display = "none"; lbl.style.display = "none"; $("run").disabled = !state.files.size;
    }
  }
  $("run").addEventListener("click", () => analyzeNow(false));

  /* ---------- live resolution ---------- */
  async function resolveUnknown() {
    const r = state.result;
    if (!r || state.resolving) return;
    if (state.isExample) { toast("The synthetic example never makes live lookups.", "info"); return; }
    if (!proxyConfigured()) { toast("Live lookups need the Darknode fetch proxy, which is not configured here.", "error"); return; }
    const plan = resolutionPlan(r.tables.unresolved, { limit: RESOLVE_LIMIT });
    if (!plan.length) { toast("No unresolved packages with a supported ecosystem.", "info"); return; }
    state.resolving = true; state.cancel = false;
    const errors = {}; let found = 0, notFound = 0, done = 0, last = 0;
    const status = () => { const el = $("resstat"); if (el) el.textContent = "Looked up " + done + " / " + plan.length + ": " + found + " found, " + notFound + " with no license on record" + (Object.keys(errors).length ? ", errors: " + Object.entries(errors).map(([h, n]) => h + " " + n).join(", ") : ""); };
    renderOut(); status();
    for (const item of plan) {
      if (state.cancel) break;
      let hit = null;
      for (const u of item.urls) {
        const cached = cacheGet(u.url);
        if (cached) { if (cached.license) { hit = { ...cached, host: u.host }; break; } continue; }
        const wait = last + RESOLVE_GAP_MS - Date.now();
        if (wait > 0) await sleep(wait);
        last = Date.now();
        try {
          const res = await dnFetch(u.url, { raw: true, timeout: 15000, ua: "darknode-licenseaudit (https://darknode.ai)" });
          if (res.status === 404) { cacheSet(u.url, { none: true }); continue; }
          if (res.status !== 200) { errors[u.host] = (errors[u.host] || 0) + 1; continue; }
          let json = null; try { json = JSON.parse(res.body); } catch (_) { errors[u.host] = (errors[u.host] || 0) + 1; continue; }
          const got = extractResolvedLicense(u.kind, json);
          cacheSet(u.url, got ? { license: got.license, detail: got.detail } : { none: true });
          if (got) { hit = { license: got.license, detail: got.detail, host: u.host }; break; }
        } catch (_) { errors[u.host] = (errors[u.host] || 0) + 1; }
      }
      done++;
      if (hit) { found++; state.resolved[item.key] = { license: hit.license, host: hit.host, at: new Date().toISOString() }; } else notFound++;
      status();
    }
    state.resolving = false;
    const summary = "Resolved " + found + " of " + done + " package(s)" + (Object.keys(errors).length ? "; some lookups failed and were left unknown" : "");
    toast(summary, found ? "success" : "warning");
    await analyzeNow(true);
    const el = $("resstat"); if (el) el.textContent = summary + (Object.keys(errors).length ? " (errors: " + Object.entries(errors).map(([h, n]) => h + " " + n).join(", ") + ")" : "") + ". Registry values are labelled in the inventory.";
  }

  /* ---------- results ---------- */
  function renderOut() {
    const out = $("out");
    const r = state.result;
    if (!r) { out.innerHTML = state.files.size ? `<div class="${P}-card ${P}-empty">Ready. Press Analyze.</div>` : ""; return; }
    const s = r.summary;
    const nUnres = r.tables.unresolved.length;
    out.innerHTML = `<div class="${P}-kpis">
        ${kpi(fmtN(s.components), "packages")}${kpi(fmtN(s.licenses), "licenses")}${kpi(fmtN(s.copyleft), "copyleft")}${kpi(fmtN(s.unknown), "unknown", s.unknown ? "medium" : "")}
        ${kpi(fmtN(s.policyHits), "policy hits", s.policyHits ? "high" : "")}${kpi(fmtN(s.findings), "findings")}
        ${SEVERITIES.map((k) => kpi(fmtN(s.bySeverity[k]), k, k)).join("")}
      </div>
      ${state.isExample ? `<p class="${P}-note" style="margin:-4px 0 12px">Synthetic example: findings come from the labelled demo files, not your software.</p>` : ""}
      <div class="${P}-card">
        <div class="${P}-row" style="margin-top:0" id="${P}-exports">
          <button class="${P}-btn" type="button" data-x="csv">Findings CSV</button>
          <button class="${P}-btn" type="button" data-x="json">JSON</button>
          <button class="${P}-btn" type="button" data-x="txt">Summary TXT</button>
          <button class="${P}-btn" type="button" data-x="notice">NOTICE file</button>
          <button class="${P}-btn" type="button" data-x="spdx">SPDX 2.3 JSON</button>
          <button class="${P}-btn" type="button" data-x="inv">Inventory CSV</button>
        </div>
        <p class="${P}-note">${esc(s.contextLabel)}. Project: ${esc(s.project.name || "(unnamed)")}, license ${esc(s.project.license || "not set")}${s.project.source ? " from " + esc(s.project.source) : ""}. ${fmtN(s.inScope)} package(s) in scope${s.devExcluded ? ", " + fmtN(s.devExcluded) + " development-only excluded" : ""}${s.resolvedLive ? ", " + fmtN(s.resolvedLive) + " license(s) from live lookups" : ""}.</p>
        ${nUnres || state.resolving ? `<div class="${P}-row"><button class="${P}-btn" type="button" id="${P}-resolve"${state.resolving || state.isExample ? " disabled" : ""}>Resolve unknown licenses (${fmtN(Math.min(nUnres, RESOLVE_LIMIT))})</button>${state.resolving ? `<button class="${P}-btn sm" type="button" id="${P}-cancel">Stop</button>` : ""}<span class="${P}-note" id="${P}-resstat" style="margin:0">${state.isExample ? "Disabled for the synthetic example." : nUnres > RESOLVE_LIMIT ? "First " + RESOLVE_LIMIT + " per click." : ""}</span></div>` : ""}
        <div class="${P}-tabs" role="tablist">${[["findings", "Findings (" + r.findings.length + ")"], ["inventory", "Inventory (" + r.tables.inventory.length + ")"], ["licenses", "Licenses (" + r.tables.licenses.length + ")"], ["skipped", "Not evaluated (" + r.skipped.length + ")"]].map(([k, l]) => `<button type="button" role="tab" class="${P}-tab${state.tab === k ? " on" : ""}" data-tab="${k}">${esc(l)}</button>`).join("")}</div>
        <div id="${P}-tabbody"></div>
      </div>`;
    const ex = $("exports");
    const stamp = () => TOOL_ID + "-" + fileStamp();
    ex.querySelector('[data-x="csv"]').addEventListener("click", () => download(stamp() + "-findings.csv", findingsToCsv(r.findings), "text/csv"));
    ex.querySelector('[data-x="json"]').addEventListener("click", () => download(stamp() + ".json", toJson(r), "application/json"));
    ex.querySelector('[data-x="txt"]').addEventListener("click", () => download(stamp() + "-summary.txt", toTxt(r) + "\nGraph summary: " + JSON.stringify(summarize(r.findings)) + "\n", "text/plain"));
    ex.querySelector('[data-x="notice"]').addEventListener("click", () => download(stamp() + "-NOTICE.txt", toNotice(r), "text/plain"));
    ex.querySelector('[data-x="spdx"]').addEventListener("click", () => download(stamp() + ".spdx.json", toJson(toSpdx(r, { now: new Date().toISOString() })), "application/spdx+json"));
    ex.querySelector('[data-x="inv"]').addEventListener("click", () => download(stamp() + "-inventory.csv", inventoryToCsv(r), "text/csv"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: state.isExample }), TOOL_ID, { dataset: state.isExample ? "synthetic example" : [...state.files.keys()].slice(0, 3).join(", ") + (state.files.size > 3 ? " +" + (state.files.size - 3) : "") });
    const rb = $("resolve"); if (rb) rb.addEventListener("click", resolveUnknown);
    const cb = $("cancel"); if (cb) cb.addEventListener("click", () => { state.cancel = true; cb.disabled = true; });
    out.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.tab; renderOut(); }));
    renderTab();
  }

  function renderTab() {
    const host = $("tabbody"), r = state.result;
    if (state.tab === "findings") return renderFindings(host, r);
    if (state.tab === "inventory") return renderInventory(host, r);
    if (state.tab === "licenses") {
      host.innerHTML = r.tables.licenses.length ? `<div class="${P}-tbl"><table><thead><tr><th>License</th><th>Category</th><th>OSI approved</th><th>Packages</th><th>In scope</th><th>Examples</th></tr></thead><tbody>${r.tables.licenses.map((x) => `<tr><td class="${P}-mono">${esc(x.license)}</td><td>${cat(x.category)}</td><td>${esc(x.osi)}</td><td>${fmtN(x.packages)}</td><td>${fmtN(x.inScope)}</td><td class="${P}-mono">${esc(x.names.slice(0, 6).join(", "))}${x.names.length > 6 ? " +" + (x.packages - 6) : ""}</td></tr>`).join("")}</tbody></table></div>` : `<div class="${P}-empty">No packages.</div>`;
      return;
    }
    const issues = r.tables.files.flatMap((f) => f.issues.map((i) => ({ check: "input:" + f.name, reason: i })));
    const rows = r.skipped.concat(issues);
    host.innerHTML = rows.length ? `<p class="${P}-note" style="margin:0 0 8px">Checks that could not run, and limits of each input. Missing data is never guessed.</p><div class="${P}-tbl"><table><thead><tr><th>Check</th><th>Reason</th></tr></thead><tbody>${rows.map((x) => `<tr><td class="${P}-mono">${esc(x.check)}</td><td>${esc(x.reason)}</td></tr>`).join("")}</tbody></table></div>` : `<div class="${P}-empty">Every check ran.</div>`;
  }

  const SORTS = {
    severity: (a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity],
    title: (a, b) => (a.title < b.title ? -1 : a.title > b.title ? 1 : 0),
    category: (a, b) => (a.category < b.category ? -1 : a.category > b.category ? 1 : 0),
    confidence: (a, b) => CONF_ORDER[a.confidence] - CONF_ORDER[b.confidence],
    evidence: (a, b) => a.evidenceCount - b.evidenceCount,
  };
  function renderFindings(host, r) {
    let list = r.findings.map((f, i) => ({ f, i }));
    if (state.fq) { const q = state.fq.toLowerCase(); list = list.filter(({ f }) => (f.title + " " + f.ruleId + " " + f.evidence.map((e) => e.package).join(" ")).toLowerCase().includes(q)); }
    const cmpF = SORTS[state.sort.key] || SORTS.severity;
    list.sort((a, b) => cmpF(a.f, b.f) * state.sort.dir || a.i - b.i);
    const th = (k, l) => `<th data-sort="${k}">${l}${state.sort.key === k ? (state.sort.dir > 0 ? " (asc)" : " (desc)") : ""}</th>`;
    host.innerHTML = `<div class="${P}-sel"><input id="${P}-fq" type="search" placeholder="Filter findings" value="${esc(state.fq)}" aria-label="Filter findings"></div>
      ${r.findings.length ? `<div class="${P}-tbl"><table><thead><tr>${th("severity", "Severity")}${th("title", "Finding")}${th("category", "Type")}${th("confidence", "Confidence")}<th>Controls</th>${th("evidence", "Packages")}</tr></thead><tbody>${list.map(({ f, i }) => `<tr class="${P}-click${state.open === i ? " " + P + "-open" : ""}" data-i="${i}">
          <td>${pill(f.severity)}</td><td><b>${esc(f.title)}</b><div class="${P}-note" style="margin:2px 0 0">${esc(f.ruleId)}</div></td><td>${esc(f.category)}</td>
          <td><span class="${P}-conf ${esc(f.confidence)}">${esc(f.confidence)}</span></td><td>${f.controls.map((c) => `<span class="${P}-chip">${esc(c.framework + " " + c.id)}</span>`).join("")}</td><td>${fmtN(f.evidenceCount)}</td></tr>${state.open === i ? `<tr><td colspan="6" class="${P}-detail">${detail(f)}</td></tr>` : ""}`).join("")}</tbody></table></div>
        ${!list.length ? `<div class="${P}-empty">No findings match the filter.</div>` : ""}`
      : `<div class="${P}-empty">No findings for this policy and distribution context. The Inventory and Licenses tabs show what was found.</div>`}`;
    const fq = host.querySelector("#" + P + "-fq");
    fq.addEventListener("input", (e) => { state.fq = e.target.value; const pos = e.target.selectionStart; renderTab(); const n = $("fq"); if (n) { n.focus(); try { n.setSelectionRange(pos, pos); } catch (_) {} } });
    host.querySelectorAll("th[data-sort]").forEach((t) => t.addEventListener("click", () => { const k = t.dataset.sort; state.sort = { key: k, dir: state.sort.key === k ? -state.sort.dir : 1 }; renderTab(); }));
    host.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => { const i = Number(tr.dataset.i); state.open = state.open === i ? null : i; renderTab(); }));
  }

  const EV_LABEL = { package: "Package", version: "Version", ecosystem: "Ecosystem", license: "License", chosen: "Used under", category: "Category", source: "Source file", path: "Dependency path" };
  function detail(f) {
    const keys = [...new Set(f.evidence.flatMap((e) => Object.keys(e)))].filter((k) => f.evidence.some((e) => e[k] !== "" && e[k] != null));
    return `<p>${esc(f.description)}</p>
      <div class="${P}-lbl">Recommended action</div><p>${esc(f.recommendation)}</p>
      <div class="${P}-lbl">Evidence (${f.evidence.length === f.evidenceCount ? fmtN(f.evidenceCount) : "showing " + f.evidence.length + " of " + fmtN(f.evidenceCount)} package${f.evidenceCount === 1 ? "" : "s"})</div>
      <div class="${P}-tbl ${P}-ev"><table><thead><tr>${keys.map((k) => `<th>${esc(EV_LABEL[k] || k.replace(/([A-Z])/g, " $1").toLowerCase())}</th>`).join("")}</tr></thead><tbody>${f.evidence.map((e) => `<tr>${keys.map((k) => `<td class="${k === "package" || k === "path" || k === "license" || k === "chosen" ? P + "-mono" : ""}">${k === "category" ? cat(e[k]) : esc(e[k])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>
      <div class="${P}-lbl">References</div><div>${f.controls.map((c) => `<span class="${P}-chip">${esc(c.framework + " " + c.id)}</span>`).join("")}</div>`;
  }

  const ISORTS = {
    package: (a, b) => (a.package < b.package ? -1 : a.package > b.package ? 1 : 0),
    license: (a, b) => (a.license < b.license ? -1 : a.license > b.license ? 1 : 0),
    category: (a, b) => CAT_ORDER[a.category] - CAT_ORDER[b.category],
    source: (a, b) => (a.licenseSource < b.licenseSource ? -1 : a.licenseSource > b.licenseSource ? 1 : 0),
  };
  function renderInventory(host, r) {
    let rows = r.tables.inventory.map((x, i) => ({ x, i }));
    if (state.icat) rows = rows.filter(({ x }) => x.category === state.icat);
    if (state.iq) { const q = state.iq.toLowerCase(); rows = rows.filter(({ x }) => (x.package + " " + x.license + " " + x.path).toLowerCase().includes(q)); }
    const cmp = ISORTS[state.isort.key] || ISORTS.category;
    rows.sort((a, b) => cmp(a.x, b.x) * state.isort.dir || ISORTS.package(a.x, b.x) || a.i - b.i);
    const shown = rows.slice(0, 1000);
    const th = (k, l) => `<th data-isort="${k}">${l}${state.isort.key === k ? (state.isort.dir > 0 ? " (asc)" : " (desc)") : ""}</th>`;
    const cats = [...new Set(r.tables.inventory.map((x) => x.category))].sort((a, b) => CAT_ORDER[a] - CAT_ORDER[b]);
    host.innerHTML = `<div class="${P}-sel">
        <select id="${P}-icat" aria-label="Category"><option value="">All categories</option>${cats.map((c) => `<option value="${esc(c)}"${state.icat === c ? " selected" : ""}>${esc(CATEGORY_LABEL[c] || c)} (${r.summary.byCategory[c]})</option>`).join("")}</select>
        <input id="${P}-iq" type="search" placeholder="Filter packages" value="${esc(state.iq)}" aria-label="Filter packages">
      </div>
      <div class="${P}-tbl"><table><thead><tr>${th("package", "Package")}${th("license", "License")}${th("category", "Category")}<th>Policy</th>${th("source", "Source")}<th>Path</th></tr></thead><tbody>${shown.map(({ x }) => `<tr>
        <td class="${P}-mono">${esc(x.package)}<div class="${P}-note" style="margin:0">${esc(x.version)}${x.ecosystem ? " - " + esc(x.ecosystem) : ""}${x.dev === "yes" ? " - dev" : ""}</div></td>
        <td class="${P}-mono">${esc(x.license || "(none)")}${x.chosen && x.chosen !== x.license ? `<div class="${P}-note" style="margin:0">used under ${esc(x.chosen)}</div>` : ""}${x.declared && x.concluded && x.declared !== x.concluded && x.concluded !== "NOASSERTION" ? `<div class="${P}-note" style="margin:0">declared ${esc(x.declared)}</div>` : ""}</td>
        <td>${cat(x.category)}</td><td>${esc(x.policy || "-")}</td>
        <td>${esc(x.licenseSource === "resolved" ? "live: " + x.resolvedFrom : x.licenseSource)}</td>
        <td class="${P}-mono">${esc(x.path || "")}</td></tr>`).join("")}</tbody></table></div>
      ${rows.length > shown.length ? `<p class="${P}-note">Showing ${shown.length} of ${fmtN(rows.length)}; the inventory CSV has all.</p>` : ""}${!rows.length ? `<div class="${P}-empty">No packages match.</div>` : ""}`;
    host.querySelector("#" + P + "-icat").addEventListener("change", (e) => { state.icat = e.target.value; renderTab(); });
    const iq = host.querySelector("#" + P + "-iq");
    iq.addEventListener("input", (e) => { state.iq = e.target.value; const pos = e.target.selectionStart; renderTab(); const n = $("iq"); if (n) { n.focus(); try { n.setSelectionRange(pos, pos); } catch (_) {} } });
    host.querySelectorAll("th[data-isort]").forEach((t) => t.addEventListener("click", () => { const k = t.dataset.isort; state.isort = { key: k, dir: state.isort.key === k ? -state.isort.dir : 1 }; renderTab(); }));
  }
}
