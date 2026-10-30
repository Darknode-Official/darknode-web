// IaC Scanner (iacscan): Deck tool UI. Runs entirely in the browser; the engine
// executes in a Worker via ../ingest/worker.js. No native dialogs; toasts only.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import { DEFAULTS, TOOL_ID, RULES, PLATFORM_LABEL, SEVERITIES, classify, findingsToCsv, toSarif, toTxt, exampleDataset } from "./iacscan-engine.js?v=20261029c";

const ENGINE = engineUrl("./iacscan-engine.js?v=20261029c", import.meta);
const P = "iac";
const MAX_FILES = 500, MAX_BYTES = 256 * 1024 * 1024;
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtN = (n) => Number(n || 0).toLocaleString("en-US");
const fmtB = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? Math.round(n / 1024) + " KB" : n + " B");
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CONF_ORDER = { confirmed: 0, likely: 1, review: 2 };
const KIND_LABEL = {
  terraform: "Terraform HCL", tfplan: "Terraform plan JSON", tfstate: "Terraform state", tfvars: "Terraform variables", cloudformation: "CloudFormation",
  kubernetes: "Kubernetes manifest", dockerfile: "Dockerfile", compose: "Docker Compose", arm: "Azure ARM template", "github-actions": "GitHub Actions workflow",
  bicep: "Bicep (unsupported)", "helm-values": "Helm values (not scannable alone)", "helm-template": "Helm template (unrendered)", "helm-chart": "Helm chart metadata",
  "arm-parameters": "ARM parameters", json: "Other JSON", yaml: "Other YAML", text: "Other text", empty: "Empty", binary: "Binary",
};
const SCANNABLE_KINDS = new Set(["terraform", "tfplan", "tfstate", "cloudformation", "kubernetes", "dockerfile", "compose", "arm", "github-actions"]);

const CSS = `
  .iac-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .iac-root *{box-sizing:border-box}
  .iac-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .iac-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .iac-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .iac-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:90ch}
  .iac-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .iac-card h2{font-size:1rem;margin:0 0 10px}
  .iac-note{font-size:.8rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .iac-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .iac-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .iac-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .iac-btn.sm{padding:4px 10px;font-size:.78rem}
  .iac-btn:disabled{opacity:.5;cursor:default}
  .iac-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr));gap:14px}
  .iac-field{display:flex;flex-direction:column;gap:4px;min-width:0}
  .iac-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .iac-field input,.iac-field select{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:280px}
  .iac-ctl{display:flex;flex-wrap:wrap;gap:12px 18px;align-items:flex-end}
  .iac-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin:14px 0}
  .iac-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .iac-kpi b{display:block;font-size:1.3rem}
  .iac-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .iac-kpi.critical b{color:#7a0012}.iac-kpi.high b{color:#b00020}.iac-kpi.medium b{color:#946a00}
  .iac-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .iac-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .iac-proglbl{font-size:.78rem;color:var(--mut,#667085);margin-top:4px;display:none}
  .iac-tbl{border:1px solid var(--line,#e6e8ee);border-radius:10px;overflow:auto;max-width:100%}
  .iac-tbl table{width:100%;border-collapse:collapse;font-size:.83rem}
  .iac-tbl th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .iac-tbl th[data-sort]{cursor:pointer}
  .iac-tbl th[data-sort]:hover{color:var(--tx,#1a2230)}
  .iac-tbl td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word;word-break:normal}
  .iac-tbl tr.iac-click{cursor:pointer}
  .iac-tbl tr.iac-click:hover,.iac-tbl tr.iac-open{background:var(--bg,#f7f8fb)}
  .iac-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.8rem;overflow-wrap:anywhere}
  .iac-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .iac-pill.critical{background:#7a0012}.iac-pill.high{background:#b00020}.iac-pill.medium{background:#946a00}.iac-pill.low{background:#2552c6}.iac-pill.info{background:#667085}
  .iac-chip{display:inline-block;font-size:.68rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .iac-conf{font-size:.76rem;font-weight:600}
  .iac-conf.review{color:var(--mut,#667085)}
  .iac-empty{padding:24px;text-align:center;color:var(--mut,#667085)}
  .iac-tabs{display:flex;flex-wrap:wrap;gap:6px;border-bottom:1px solid var(--line,#e6e8ee);margin:6px 0 12px}
  .iac-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;background:none;border:0;border-bottom:2px solid transparent;color:var(--mut,#667085);padding:8px 10px;cursor:pointer}
  .iac-tab.on{color:var(--tx,#1a2230);border-bottom-color:#2552c6}
  .iac-detail{padding:12px 14px;background:var(--bg,#f7f8fb)}
  .iac-detail p{margin:0 0 8px}
  .iac-lbl{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);margin:10px 0 4px}
  .iac-code{border:1px solid var(--line,#e6e8ee);border-radius:8px;background:var(--card,#fff);overflow:auto;max-height:340px}
  .iac-code table{border-collapse:collapse;width:100%}
  .iac-code td{padding:3px 10px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top}
  .iac-code td.ln{color:var(--mut,#667085);text-align:right;user-select:none;width:1%;white-space:nowrap;border-right:1px solid var(--line,#e6e8ee)}
  .iac-code td.src{white-space:pre-wrap;word-break:break-all}
  .iac-files{display:grid;grid-template-columns:minmax(0,1fr);gap:10px}
  .iac-fgrp{min-width:0}
  .iac-fgrp h3{font-size:.86rem;margin:0 0 6px}
  .iac-rules{max-height:420px;overflow:auto;border:1px solid var(--line,#e6e8ee);border-radius:10px}
  .iac-rule{display:flex;gap:8px;align-items:flex-start;padding:6px 10px;border-bottom:1px solid var(--line,#eef0f4);font-size:.8rem}
  .iac-rule input{margin-top:3px;flex:none}
  .iac-rule span{min-width:0;overflow-wrap:anywhere}
  .iac-plat{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
  .iac-bad{color:#b00020}
  .iac-sel{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
  .iac-sel input,.iac-sel select{font:inherit;font-size:.82rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:6px 9px;max-width:100%}
  @media (max-width:520px){.iac-card{padding:12px}.iac-hd h1{font-size:1.4rem}.iac-grid{grid-template-columns:1fr}}
`;

function kpi(v, l, cls = "") { return '<div class="' + P + '-kpi ' + cls + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>"; }
const pill = (s) => '<span class="' + P + '-pill ' + esc(s) + '">' + esc(s) + "</span>";

/** Mount the tool into main. */
export function renderIacScan(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = `<div class="${P}-root">
    <div class="${P}-hd"><h1>Infrastructure as Code</h1><span class="${P}-tag">Deck</span></div>
    <p class="${P}-sub">Checks Terraform (HCL, plan JSON, state), CloudFormation, Kubernetes and Helm-rendered manifests, Dockerfiles, Docker Compose, Azure ARM and GitHub Actions workflows against ${RULES.length} rules mapped to CIS benchmarks, NIST 800-53 and MITRE ATT&amp;CK, and sweeps every file for hard-coded secrets. Runs entirely in your browser. Nothing is uploaded and nothing is fetched live.</p>
    <div class="${P}-card">
      <div id="${P}-drop"></div>
      <div class="${P}-row">
        <button class="${P}-btn" id="${P}-folder" type="button">Choose a folder</button>
        <input type="file" id="${P}-folderin" webkitdirectory multiple hidden>
        <button class="${P}-btn" id="${P}-example" type="button">Load example (synthetic)</button>
        <button class="${P}-btn" id="${P}-clear" type="button" disabled>Clear files</button>
        <button class="${P}-btn pri" id="${P}-run" type="button" disabled>Scan</button>
      </div>
      <p class="${P}-note">Drop files, a folder or a .zip of the repository (up to ${MAX_FILES} files, 256 MB). Render Helm charts with <span class="${P}-mono">helm template</span> and Terraform plans with <span class="${P}-mono">terraform show -json tfplan</span> first.</p>
      <div class="${P}-prog" id="${P}-prog"><i></i></div><div class="${P}-proglbl" id="${P}-proglbl"></div>
    </div>
    <div class="${P}-grid">
      <div class="${P}-card"><h2>Files</h2><div id="${P}-files"><div class="${P}-empty">No files yet.</div></div></div>
      <div class="${P}-card"><h2>Rule set</h2>
        <div class="${P}-ctl">
          <div class="${P}-field"><label for="${P}-minsev">Lowest severity to report</label><select id="${P}-minsev">${SEVERITIES.slice().reverse().map((s) => `<option value="${s}"${s === DEFAULTS.minSeverity ? " selected" : ""}>${s}</option>`).join("")}</select></div>
          <div class="${P}-field"><label for="${P}-rq">Find rules</label><input id="${P}-rq" type="search" placeholder="id, title or platform"></div>
        </div>
        <p class="${P}-note">Untick a rule to switch it off for the next scan. Nothing is saved.</p>
        <div class="${P}-plat" id="${P}-plat"></div>
        <div class="${P}-row" style="margin:0 0 8px"><button class="${P}-btn sm" id="${P}-rall" type="button">Enable shown</button><button class="${P}-btn sm" id="${P}-rnone" type="button">Disable shown</button><span class="${P}-note" id="${P}-rcount" style="margin:0"></span></div>
        <div class="${P}-rules" id="${P}-rules"></div>
      </div>
    </div>
    <div id="${P}-out"></div>
  </div>`;

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  const state = { files: new Map(), off: new Set(), ruleQ: "", isExample: false, result: null, tab: "findings", sort: { key: "severity", dir: 1 }, open: null, fq: "", fplat: "" };

  /* ---------- files ---------- */
  async function addFiles(list, skippedIn = []) {
    if (state.isExample) { state.files.clear(); state.isExample = false; }
    let added = 0;
    const skipped = skippedIn.slice();
    for (const f of list) {
      if (/(^|\/)(\.git|node_modules|\.terraform)\//.test(f.name)) { skipped.push({ name: f.name, reason: "vendored or VCS directory" }); continue; } // before reading: a repo can hold tens of thousands of these
      if (state.files.size >= MAX_FILES) { skipped.push({ name: f.name, reason: "over " + MAX_FILES + " files" }); continue; }
      let text = "";
      try { text = await f.text(); } catch (e) { skipped.push({ name: f.name, reason: "unreadable" }); continue; }
      state.files.set(f.name, { name: f.name, text, size: text.length, archive: f.fromArchive || "", cls: classify(f.name, text) });
      added++;
    }
    state.result = null;
    renderFiles(skipped);
    renderOut();
    if (added) toast("Added " + added + " file" + (added === 1 ? "" : "s"), "info");
    if (skipped.length) toast(skipped.length + " file(s) skipped", "warning");
  }

  mountDropzone($("drop"), {
    maxBytes: MAX_BYTES, maxFiles: MAX_FILES, unpack: true, multiple: true,
    label: "Drop IaC files, a folder or a .zip here, paste, or browse",
    onFiles: (files, { skipped }) => addFiles(files, (skipped || []).map((s) => ({ name: s.name, reason: s.reason }))),
    onError: (e) => toast(String((e && e.message) || e), "error"),
  });
  $("folder").addEventListener("click", () => $("folderin").click());
  $("folderin").addEventListener("change", (e) => {
    const list = [...(e.target.files || [])].filter((f) => f.size <= MAX_BYTES).map((f) => ({ name: f.webkitRelativePath || f.name, text: () => f.text() }));
    e.target.value = "";
    addFiles(list);
  });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    state.files.clear();
    for (const f of ex.files) state.files.set(f.name, { name: f.name, text: f.text, size: f.text.length, archive: "", cls: classify(f.name, f.text) });
    state.isExample = true; state.result = null;
    renderFiles([]); renderOut();
    toast("Loaded the synthetic example repository", "info");
  });
  $("clear").addEventListener("click", () => { state.files.clear(); state.isExample = false; state.result = null; renderFiles([]); renderOut(); });

  function renderFiles(skipped) {
    const host = $("files");
    $("run").disabled = !state.files.size;
    $("clear").disabled = !state.files.size;
    if (!state.files.size) { host.innerHTML = `<div class="${P}-empty">No files yet.</div>`; return; }
    const byFile = state.result ? new Map(state.result.tables.files.map((f) => [f.name, f])) : new Map();
    const groups = new Map();
    for (const f of [...state.files.values()].sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const k = (byFile.get(f.name) || {}).kind || f.cls.kind;
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(f);
    }
    const order = [...groups.keys()].sort((a, b) => (SCANNABLE_KINDS.has(b) - SCANNABLE_KINDS.has(a)) || (a < b ? -1 : 1));
    const total = [...state.files.values()].reduce((a, f) => a + f.size, 0);
    host.innerHTML = `<p class="${P}-note" style="margin:0 0 10px">${fmtN(state.files.size)} file(s), ${fmtB(total)}${state.isExample ? " - synthetic example, not real infrastructure" : ""}</p><div class="${P}-files">${order.map((k) => {
      const fs = groups.get(k);
      return `<div class="${P}-fgrp"><h3>${esc(KIND_LABEL[k] || k)} <span class="${P}-chip">${fs.length}</span>${SCANNABLE_KINDS.has(k) ? "" : ` <span class="${P}-chip">secrets scan only</span>`}</h3><div class="${P}-tbl"><table><thead><tr><th>File</th><th>Confidence</th><th>Notes</th></tr></thead><tbody>${fs.slice(0, 200).map((f) => {
        const r = byFile.get(f.name);
        const notes = [r ? fmtN(r.resources) + " resource(s)" : "", ...(r ? r.skipped : []), SCANNABLE_KINDS.has(k) ? "" : f.cls.reason].filter(Boolean);
        return `<tr><td class="${P}-mono">${esc(f.name)}${f.archive ? `<div class="${P}-note">from ${esc(f.archive)}</div>` : ""}</td><td>${esc((r || f.cls).confidence)}</td><td>${notes.map((n) => `<div${r && r.skipped.includes(n) ? ` class="${P}-bad"` : ""}>${esc(n)}</div>`).join("")}</td></tr>`;
      }).join("")}</tbody></table></div>${fs.length > 200 ? `<p class="${P}-note">Showing 200 of ${fs.length}.</p>` : ""}</div>`;
    }).join("")}</div>${skipped && skipped.length ? `<p class="${P}-note ${P}-bad">Skipped: ${skipped.slice(0, 10).map((s) => esc(s.name + " (" + s.reason + ")")).join(", ")}${skipped.length > 10 ? " and " + (skipped.length - 10) + " more" : ""}</p>` : ""}`;
  }

  /* ---------- rule set ---------- */
  const shownRules = () => {
    const q = state.ruleQ.toLowerCase();
    return RULES.filter((r) => !q || r.id.toLowerCase().includes(q) || r.title.toLowerCase().includes(q) || r.kind.includes(q) || (PLATFORM_LABEL[r.kind] || "").toLowerCase().includes(q));
  };
  function renderRules() {
    const counts = {};
    for (const r of RULES) { counts[r.kind] = counts[r.kind] || { all: 0, on: 0 }; counts[r.kind].all++; if (!state.off.has(r.id)) counts[r.kind].on++; }
    $("plat").innerHTML = Object.entries(counts).map(([k, v]) => `<button type="button" class="${P}-btn sm" data-plat="${esc(k)}">${esc(PLATFORM_LABEL[k] || k)} ${v.on}/${v.all}</button>`).join("");
    const list = shownRules();
    $("rcount").textContent = list.length + " shown, " + (RULES.length - state.off.size) + " of " + RULES.length + " enabled";
    $("rules").innerHTML = list.map((r) => `<label class="${P}-rule"><input type="checkbox" data-rule="${esc(r.id)}"${state.off.has(r.id) ? "" : " checked"}><span>${pill(r.severity)} <b class="${P}-mono">${esc(r.id)}</b> ${esc(r.title)}</span></label>`).join("") || `<div class="${P}-empty">No rules match.</div>`;
  }
  $("rules").addEventListener("change", (e) => { const id = e.target && e.target.dataset && e.target.dataset.rule; if (!id) return; if (e.target.checked) state.off.delete(id); else state.off.add(id); renderRules(); });
  $("rq").addEventListener("input", (e) => { state.ruleQ = e.target.value.trim(); renderRules(); });
  $("plat").addEventListener("click", (e) => { const b = e.target.closest("[data-plat]"); if (!b) return; $("rq").value = b.dataset.plat; state.ruleQ = b.dataset.plat; renderRules(); });
  $("rall").addEventListener("click", () => { for (const r of shownRules()) state.off.delete(r.id); renderRules(); });
  $("rnone").addEventListener("click", () => { for (const r of shownRules()) state.off.add(r.id); renderRules(); });
  renderRules();

  /* ---------- run ---------- */
  $("run").addEventListener("click", async () => {
    const prog = $("prog"), bar = prog.firstElementChild, lbl = $("proglbl");
    prog.style.display = "block"; lbl.style.display = "block"; bar.style.width = "0%"; lbl.textContent = "Parsing files";
    $("run").disabled = true;
    const files = [...state.files.values()].map((f) => ({ name: f.name, text: f.text }));
    const opts = { ignoreRules: [...state.off].sort(), minSeverity: $("minsev").value };
    try {
      state.result = await runInWorker(ENGINE, "analyze", [files, opts], {
        timeoutMs: 600000,
        onProgress: (i, n, l) => { bar.style.width = (n ? Math.round((i / n) * 100) : 0) + "%"; lbl.textContent = (l === "secrets" ? "Secrets sweep " : l === "done" ? "Done " : "Checking resources ") + fmtN(i) + " / " + fmtN(n); },
      });
      state.open = null;
      renderFiles([]);
      renderOut();
      toast(state.result.findings.length + " finding(s) across " + state.result.summary.resources + " resource(s)", state.result.findings.length ? "warning" : "success");
    } catch (e) {
      toast("Scan failed: " + ((e && e.message) || e), "error");
    } finally {
      prog.style.display = "none"; lbl.style.display = "none"; $("run").disabled = !state.files.size;
    }
  });

  /* ---------- results ---------- */
  function renderOut() {
    const out = $("out");
    const r = state.result;
    if (!r) { out.innerHTML = state.files.size ? `<div class="${P}-card ${P}-empty">Ready. Press Scan.</div>` : ""; return; }
    const s = r.summary;
    const plats = Object.entries(s.byPlatform).filter(([, v]) => v.resources || v.findings);
    out.innerHTML = `<div class="${P}-kpis">
        ${kpi(fmtN(s.files), "files")}${kpi(fmtN(s.resources), "resources")}${kpi(fmtN(s.findings), "findings")}
        ${SEVERITIES.map((k) => kpi(fmtN(s.bySeverity[k]), k, k)).join("")}${kpi(plats.length, "platforms")}
      </div>
      ${state.isExample ? `<p class="${P}-note" style="margin:-4px 0 12px">Synthetic example: these findings come from the labelled demo repository, not your infrastructure.</p>` : ""}
      <div class="${P}-card">
        <div class="${P}-row" style="margin-top:0" id="${P}-exports">
          <button class="${P}-btn" type="button" data-x="csv">Findings CSV</button>
          <button class="${P}-btn" type="button" data-x="sarif">SARIF</button>
          <button class="${P}-btn" type="button" data-x="json">JSON</button>
          <button class="${P}-btn" type="button" data-x="txt">Summary TXT</button>
        </div>
        <p class="${P}-note">${plats.map(([k, v]) => esc((PLATFORM_LABEL[k] || k) + ": " + v.resources + " resources, " + v.findings + " findings")).join(" | ")}${s.filteredOut ? " | " + s.filteredOut + " finding(s) below the severity threshold hidden" : ""}</p>
        <div class="${P}-tabs" role="tablist">${[["findings", "Findings (" + r.findings.length + ")"], ["resources", "Resources (" + r.tables.resources.length + ")"], ["rules", "Rules"], ["skipped", "Not evaluated (" + r.skipped.length + ")"]].map(([k, l]) => `<button type="button" role="tab" class="${P}-tab${state.tab === k ? " on" : ""}" data-tab="${k}">${esc(l)}</button>`).join("")}</div>
        <div id="${P}-tabbody"></div>
      </div>`;
    const ex = $("exports");
    const stamp = () => TOOL_ID + "-" + fileStamp();
    ex.querySelector('[data-x="csv"]').addEventListener("click", () => download(stamp() + "-findings.csv", findingsToCsv(r.findings), "text/csv"));
    ex.querySelector('[data-x="sarif"]').addEventListener("click", () => download(stamp() + ".sarif", toJson(toSarif(r)), "application/sarif+json"));
    ex.querySelector('[data-x="json"]').addEventListener("click", () => download(stamp() + ".json", toJson(r), "application/json"));
    ex.querySelector('[data-x="txt"]').addEventListener("click", () => download(stamp() + "-summary.txt", toTxt(r) + "\nGraph summary: " + JSON.stringify(summarize(r.findings)) + "\n", "text/plain"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: state.isExample }), TOOL_ID, { dataset: state.isExample ? "synthetic example" : [...state.files.keys()].slice(0, 3).join(", ") + (state.files.size > 3 ? " +" + (state.files.size - 3) : "") });
    out.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.tab; renderOut(); }));
    renderTab();
  }

  function renderTab() {
    const host = $("tabbody"), r = state.result;
    if (state.tab === "findings") return renderFindings(host, r);
    if (state.tab === "resources") {
      const rows = r.tables.resources.slice().sort((a, b) => b.hits - a.hits || (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
      host.innerHTML = rows.length ? `<div class="${P}-tbl"><table><thead><tr><th>Resource</th><th>Type</th><th>Platform</th><th>File:line</th><th>Findings</th><th>Rules hit</th></tr></thead><tbody>${rows.slice(0, 1000).map((x) => `<tr><td class="${P}-mono">${esc(x.id)}</td><td class="${P}-mono">${esc(x.type)}</td><td>${esc(PLATFORM_LABEL[x.platform] || x.platform)}</td><td class="${P}-mono">${esc(x.file)}:${x.line}</td><td>${x.hits}</td><td>${x.rules.map((id) => `<span class="${P}-chip">${esc(id)}</span>`).join("")}</td></tr>`).join("")}</tbody></table></div>${rows.length > 1000 ? `<p class="${P}-note">Showing 1000 of ${fmtN(rows.length)}; the JSON export has all.</p>` : ""}` : `<div class="${P}-empty">No resources were parsed.</div>`;
      return;
    }
    if (state.tab === "rules") {
      const rows = r.tables.rules.slice().sort((a, b) => b.hits - a.hits || SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || (a.id < b.id ? -1 : 1));
      host.innerHTML = `<div class="${P}-tbl"><table><thead><tr><th>Rule</th><th>Severity</th><th>Platform</th><th>Hits</th><th>Not evaluated</th><th>References</th></tr></thead><tbody>${rows.map((x) => `<tr><td><b class="${P}-mono">${esc(x.id)}</b> ${esc(x.title)}${x.enabled ? "" : ` <span class="${P}-chip">off</span>`}${x.belowThreshold ? ` <span class="${P}-chip">below threshold</span>` : ""}</td><td>${pill(x.severity)}</td><td>${esc(PLATFORM_LABEL[x.platform] || x.platform)}</td><td>${x.hits}</td><td>${x.unresolved || ""}</td><td class="${P}-note" style="margin:0">${esc(x.frameworks)}</td></tr>`).join("")}</tbody></table></div>`;
      return;
    }
    host.innerHTML = r.skipped.length ? `<p class="${P}-note" style="margin:0 0 8px">Checks that could not run on this input. Values written as variables, references or intrinsic functions are never guessed.</p><div class="${P}-tbl"><table><thead><tr><th>Check</th><th>Reason</th></tr></thead><tbody>${r.skipped.map((x) => `<tr><td class="${P}-mono">${esc(x.check)}</td><td>${esc(x.reason)}</td></tr>`).join("")}</tbody></table></div>` : `<div class="${P}-empty">Every applicable check ran.</div>`;
  }

  const SORTS = {
    severity: (a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity],
    rule: (a, b) => (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0),
    resource: (a, b) => (a.resource < b.resource ? -1 : a.resource > b.resource ? 1 : 0),
    file: (a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line),
    confidence: (a, b) => CONF_ORDER[a.confidence] - CONF_ORDER[b.confidence],
    evidence: (a, b) => a.evidenceCount - b.evidenceCount,
  };
  function renderFindings(host, r) {
    const plats = [...new Set(r.findings.map((f) => f.platform))].sort();
    let list = r.findings.map((f, i) => ({ f, i }));
    if (state.fplat) list = list.filter(({ f }) => f.platform === state.fplat);
    if (state.fq) { const q = state.fq.toLowerCase(); list = list.filter(({ f }) => (f.ruleId + " " + f.title + " " + f.resource + " " + f.file).toLowerCase().includes(q)); }
    const cmpF = SORTS[state.sort.key] || SORTS.severity;
    list.sort((a, b) => cmpF(a.f, b.f) * state.sort.dir || a.i - b.i);
    const shown = list.slice(0, 500);
    const th = (k, l) => `<th data-sort="${k}">${l}${state.sort.key === k ? (state.sort.dir > 0 ? " (asc)" : " (desc)") : ""}</th>`;
    host.innerHTML = `<div class="${P}-sel">
        <select id="${P}-fplat" aria-label="Platform"><option value="">All platforms</option>${plats.map((p) => `<option value="${esc(p)}"${state.fplat === p ? " selected" : ""}>${esc(PLATFORM_LABEL[p] || p)}</option>`).join("")}</select>
        <input id="${P}-fq" type="search" placeholder="Filter findings" value="${esc(state.fq)}">
      </div>
      ${r.findings.length ? `<div class="${P}-tbl"><table><thead><tr>${th("severity", "Severity")}${th("rule", "Rule")}${th("resource", "Resource")}${th("file", "File:line")}${th("confidence", "Confidence")}<th>Controls</th>${th("evidence", "Evidence")}</tr></thead><tbody>${shown.map(({ f, i }) => `<tr class="${P}-click${state.open === i ? " " + P + "-open" : ""}" data-i="${i}">
          <td>${pill(f.severity)}</td><td><b class="${P}-mono">${esc(f.ruleId)}</b><div>${esc(f.title)}</div></td><td class="${P}-mono">${esc(f.resource)}</td><td class="${P}-mono">${esc(f.file)}:${f.line}</td>
          <td><span class="${P}-conf ${esc(f.confidence)}">${esc(f.confidence)}</span></td><td>${f.controls.map((c) => `<span class="${P}-chip">${esc(c.framework + " " + c.id)}</span>`).join("")}</td><td>${f.evidenceCount}</td></tr>${state.open === i ? `<tr><td colspan="7" class="${P}-detail">${detail(f)}</td></tr>` : ""}`).join("")}</tbody></table></div>
        ${list.length > shown.length ? `<p class="${P}-note">Showing ${shown.length} of ${fmtN(list.length)}; the CSV, SARIF and JSON exports have all.</p>` : ""}${!list.length ? `<div class="${P}-empty">No findings match the filter.</div>` : ""}`
      : `<div class="${P}-empty">No findings at this severity threshold. The Rules and Not evaluated tabs show what ran.</div>`}`;
    host.querySelector("#" + P + "-fplat").addEventListener("change", (e) => { state.fplat = e.target.value; renderTab(); });
    const fq = host.querySelector("#" + P + "-fq");
    fq.addEventListener("input", (e) => { state.fq = e.target.value; const pos = e.target.selectionStart; renderTab(); const n = $("fq"); if (n) { n.focus(); try { n.setSelectionRange(pos, pos); } catch (_) {} } });
    host.querySelectorAll("th[data-sort]").forEach((t) => t.addEventListener("click", () => { const k = t.dataset.sort; state.sort = { key: k, dir: state.sort.key === k ? -state.sort.dir : 1 }; renderTab(); }));
    host.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => { const i = Number(tr.dataset.i); state.open = state.open === i ? null : i; renderTab(); }));
  }

  function detail(f) {
    return `<p>${esc(f.description)}</p>
      <div class="${P}-lbl">Recommended fix</div><p>${esc(f.recommendation)}</p>
      <div class="${P}-lbl">Evidence (${f.evidence.length === f.evidenceCount ? f.evidenceCount : "showing " + f.evidence.length + " of " + f.evidenceCount} location${f.evidenceCount === 1 ? "" : "s"}; secret values are masked)</div>
      <div class="${P}-code"><table><tbody>${f.evidence.map((e) => `<tr><td class="ln ${P}-mono">${esc(e.file)}:${e.line}</td><td class="src ${P}-mono">${esc(e.snippet)}</td></tr><tr><td class="ln"></td><td class="${P}-note" style="margin:0">${esc(e.detail)}</td></tr>`).join("")}</tbody></table></div>
      <div class="${P}-lbl">References</div><div>${f.controls.map((c) => `<span class="${P}-chip">${esc(c.framework + " " + c.id)}</span>`).join("")}</div>`;
  }
}
