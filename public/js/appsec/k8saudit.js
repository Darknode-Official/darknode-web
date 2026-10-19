// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Kubernetes Audit (k8saudit): Deck tool UI. Drop a live cluster dump
// (`kubectl get ... -A -o json|yaml`, zip accepted), kube-bench JSON, `kubectl get
// --raw /version` and optional `kubectl auth can-i --list` output; the engine walks
// the RBAC graph, pod security, namespace isolation and exposure chains inside a
// Worker. Runs entirely in the browser; the only fetch is the same-origin mirrored
// end-of-life feed. No native dialogs.
//
//   renderK8sAudit(main) -> void

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, DETECTIONS, SEV_RANK,
  findingsToCsv, workloadsToCsv, rbacMatrixCsv, remediationYaml, summaryText, exampleDataset,
} from "./k8saudit-engine.js?v=20261016k";

const ENGINE = engineUrl("./k8saudit-engine.js?v=20261016k", import.meta);
const P = "kub";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const CONF_RANK = { confirmed: 3, likely: 2, review: 1 };
const KIND_LABEL = { k8s: "Kubernetes objects", "kube-bench": "kube-bench JSON", version: "/version JSON", "can-i": "auth can-i --list", unknown: "not recognised" };

const CSS = `
  .kub-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .kub-root *{box-sizing:border-box}
  .kub-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .kub-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .kub-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .kub-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:100ch;overflow-wrap:anywhere}
  .kub-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .kub-card h2{font-size:.95rem;margin:0 0 10px}
  .kub-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .kub-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .kub-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .kub-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .kub-btn:disabled{opacity:.5;cursor:default}
  .kub-files{display:flex;flex-direction:column;gap:6px;margin-top:12px}
  .kub-file{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;font-size:.82rem;min-width:0}
  .kub-file b{overflow-wrap:anywhere;min-width:0}
  .kub-file .kub-fmt{color:var(--mut,#667085);overflow-wrap:anywhere;min-width:0}
  .kub-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085);white-space:nowrap}
  .kub-conf.high{color:#1b7f4d;border-color:#1b7f4d}.kub-conf.low{color:#b00020;border-color:#b00020}
  .kub-kinds{display:flex;flex-wrap:wrap;gap:4px 6px;margin-top:10px}
  .kub-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .kub-ctl{display:flex;flex-wrap:wrap;gap:14px 20px;align-items:flex-start}
  .kub-field{display:flex;flex-direction:column;gap:4px;min-width:0;flex:1 1 200px}
  .kub-field.wide{flex:1 1 100%}
  .kub-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .kub-field input[type=text],.kub-field input[type=number],.kub-field textarea{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%}
  .kub-field textarea{min-height:70px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}
  .kub-field small{font-size:.74rem;color:var(--mut,#667085);line-height:1.4;overflow-wrap:anywhere}
  .kub-check{display:flex;gap:8px;align-items:flex-start;font-size:.84rem;flex:1 1 280px;min-width:0}
  .kub-check input{margin-top:4px;flex:0 0 auto}
  .kub-check span{min-width:0;overflow-wrap:anywhere}
  .kub-check small{display:block;font-size:.74rem;color:var(--mut,#667085)}
  .kub-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .kub-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .kub-plabel{font-size:.74rem;color:var(--mut,#667085);margin-top:4px;display:none}
  .kub-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .kub-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:120px;flex:1 1 120px}
  .kub-kpi b{display:block;font-size:1.3rem}
  .kub-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .kub-kpi.sev-critical b{color:#7a0012}.kub-kpi.sev-high b{color:#b00020}.kub-kpi.sev-medium b{color:#8a6d00}
  .kub-tabs{display:flex;flex-wrap:wrap;gap:6px;margin:4px 0 12px;border-bottom:1px solid var(--line,#e6e8ee)}
  .kub-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid transparent;border-bottom:none;background:none;color:var(--mut,#667085);padding:8px 12px;border-radius:8px 8px 0 0;cursor:pointer;margin-bottom:-1px}
  .kub-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#e6e8ee);background:var(--card,#fff)}
  .kub-filters{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:flex-end;margin-bottom:10px}
  .kub-filters .kub-field{flex:0 1 220px}
  .kub-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%;max-height:640px}
  .kub-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:640px}
  .kub-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none;position:sticky;top:0;z-index:1}
  .kub-list th.on{color:var(--tx,#1a2230)}
  .kub-list th.on::after{content:" \\2193";font-size:.7rem}
  .kub-list th.on.asc::after{content:" \\2191"}
  .kub-list td{padding:9px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word;word-break:normal}
  .kub-list td.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.76rem;overflow-wrap:anywhere}
  .kub-list tr[data-i]{cursor:pointer}
  .kub-list tr[data-i]:hover,.kub-list tr.sel{background:var(--bg,#f7f8fb)}
  .kub-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .kub-pill.critical{background:#7a0012}.kub-pill.high{background:#b00020}.kub-pill.medium{background:#b58100}.kub-pill.low{background:#2552c6}.kub-pill.info{background:#667085}
  .kub-yes{color:#b00020;font-weight:700}
  .kub-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .kub-drawer{margin-top:12px;display:none;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--bg,#f7f8fb);min-width:0}
  .kub-drawer h3{margin:0 0 6px;font-size:1rem;overflow-wrap:anywhere}
  .kub-drawer p{margin:6px 0;overflow-wrap:anywhere}
  .kub-drawer .kub-list{background:var(--card,#fff);margin-top:10px;max-height:360px}
  .kub-drawer .kub-list table{min-width:480px}
  .kub-drawer pre{margin:8px 0 0;max-height:300px;overflow:auto;font-size:12px;line-height:1.45;background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:10px 12px;white-space:pre}
  .kub-dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;font-size:.82rem;margin:8px 0}
  .kub-dl dt{color:var(--mut,#667085)}.kub-dl dd{margin:0;overflow-wrap:anywhere;min-width:0}
  .kub-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px}
  .kub-skip ul{margin:4px 0 0;padding-left:18px}
  .kub-skip li{margin:2px 0;overflow-wrap:anywhere}
  .kub-how summary{cursor:pointer;font-weight:600;font-size:.9rem}
  .kub-how pre{margin:8px 0 0;overflow:auto;font-size:12px;background:var(--bg,#f7f8fb);border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:10px 12px;white-space:pre-wrap;overflow-wrap:anywhere}
  @media (max-width:560px){.kub-field,.kub-filters .kub-field{flex:1 1 100%}.kub-dl{grid-template-columns:1fr}.kub-card{padding:14px}.kub-kpi{min-width:100px}}
`;

const kpi = (v, l, cls) => '<div class="' + P + "-kpi" + (cls ? " " + cls : "") + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const pill = (s) => (s ? '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>" : "");
const yes = (v) => (v === "yes" ? '<span class="' + P + '-yes">yes</span>' : esc(v));
const sortRows = (rows, key, dir, rank) => rows.slice().sort((a, b) => {
  const x = rank ? (rank[a[key]] ?? -1) : a[key], y = rank ? (rank[b[key]] ?? -1) : b[key];
  const r = typeof x === "number" && typeof y === "number" ? x - y : cmp(String(x == null ? "" : x).toLowerCase(), String(y == null ? "" : y).toLowerCase());
  return dir === "asc" ? r : -r;
});

/** Sortable table: cols = [{key,label,render?,rank?,mono?}]. */
function table(cols, rows, sort, onSort, onRow) {
  const el = document.createElement("div");
  el.className = P + "-list";
  if (!rows.length) { el.innerHTML = '<div class="' + P + '-empty">Nothing to show.</div>'; return el; }
  const sorted = sort.key ? sortRows(rows, sort.key, sort.dir, (cols.find((c) => c.key === sort.key) || {}).rank) : rows;
  el.innerHTML = "<table><thead><tr>" + cols.map((c) => '<th data-k="' + esc(c.key) + '" class="' + (sort.key === c.key ? "on " + sort.dir : "") + '">' + esc(c.label) + "</th>").join("") + "</tr></thead><tbody>" +
    sorted.map((r, i) => "<tr" + (onRow ? ' data-i="' + i + '"' : "") + ">" + cols.map((c) => "<td" + (c.mono ? ' class="mono"' : "") + ">" + (c.render ? c.render(r) : esc(r[c.key] == null ? "" : r[c.key])) + "</td>").join("") + "</tr>").join("") + "</tbody></table>";
  el.querySelectorAll("th").forEach((th) => th.addEventListener("click", () => { const k = th.dataset.k; onSort({ key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" }); }));
  if (onRow) el.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => {
    el.querySelectorAll("tr.sel").forEach((x) => x.classList.remove("sel")); tr.classList.add("sel"); onRow(sorted[Number(tr.dataset.i)]);
  }));
  return el;
}

function evidenceTable(rows) {
  if (!rows || !rows.length) return '<p class="' + P + '-note">No evidence rows.</p>';
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
  const cell = (v) => (v === true ? "yes" : v === false ? "no" : v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => "<td>" + esc(cell(r[k])) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

const HOWTO = [
  "# Cluster state (read-only; Secret values are discarded by this tool at parse time)",
  "kubectl get ns,sa,roles,rolebindings,clusterroles,clusterrolebindings,netpol,ing,secrets,configmaps,pv,nodes -A -o json > rbac-net.json",
  "kubectl get pods,deploy,sts,ds,rs,jobs,cronjobs,svc -A -o json > workloads.json",
  "kubectl get events -A -o json > events.json",
  "kubectl get --raw /version > version.json",
  "# CIS benchmark (optional)",
  "kube-bench run --json > kube-bench.json",
  "# Spot checks per subject (optional; the file name names the subject)",
  "kubectl auth can-i --list --as=test@darknode.ai > can-i-test@darknode.ai.txt",
].join("\n");

/** Mount the tool into main. */
export function renderK8sAudit(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Kubernetes Audit</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Audit a live cluster from a kubectl dump: RBAC effective permissions (incl. aggregated ClusterRoles), pod security, namespace isolation, exposure chains, secrets hygiene, kube-bench results and version end-of-life. Runs entirely in your browser. Nothing is uploaded. End-of-life dates come from the same-origin endoflife.date mirror (<span id="', P, '-eol">mirrored, date shown after the first run</span>); Secret values are dropped as each file is parsed.</p>',
    '<div class="', P, '-card"><h2>1. Cluster dump</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-note">kubectl JSON or YAML (List or multi-document), kube-bench JSON, /version JSON and auth can-i --list text. Several files or one .zip.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div><div class="', P, '-kinds" id="', P, '-kinds"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button><button class="', P, '-btn" id="', P, '-clear" disabled>Clear files</button><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-plabel" id="', P, '-plabel"></div>',
    '<details class="', P, '-how" style="margin-top:12px"><summary>How to collect the inputs</summary><pre>', esc(HOWTO), "</pre></details></div>",
    '<div class="', P, '-card"><h2>2. Settings</h2><div class="', P, '-ctl">',
    '<div class="', P, '-field"><label for="', P, '-cluster">Cluster name</label><input type="text" id="', P, '-cluster" placeholder="prod-eu-1"><small>Names the cluster asset in the Security Graph. Default: cluster.</small></div>',
    '<div class="', P, '-field"><label for="', P, '-now">Reference date</label><input type="text" id="', P, '-now" placeholder="YYYY-MM-DD"><small>For end-of-life checks. Default: newest timestamp in the dump.</small></div>',
    '<div class="', P, '-field wide"><label for="', P, '-regs">Allowed image registries</label><textarea id="', P, '-regs" placeholder="one per line"></textarea><small>Registry host or host/path prefix, e.g. registry.test.darknode.ai. Blank: registries in use are listed for review instead of flagged.</small></div>',
    '<div class="', P, '-field"><label for="', P, '-shared">Shared secret threshold</label><input type="number" min="2" id="', P, '-shared" value="', DEFAULTS.sharedSecretWorkloads, '"><small>Workloads mounting one Secret before it is reported. Default ', DEFAULTS.sharedSecretWorkloads, '.</small></div>',
    '<div class="', P, '-field"><label for="', P, '-events">Repeated event count</label><input type="number" min="1" id="', P, '-events" value="', DEFAULTS.eventRepeatCount, '"><small>BackOff / Failed occurrences before an event is listed. Default ', DEFAULTS.eventRepeatCount, '.</small></div>',
    '<div class="', P, '-field"><label for="', P, '-skew">Kubelet skew (minor versions)</label><input type="number" min="0" id="', P, '-skew" value="', DEFAULTS.kubeletSkewMinors, '"><small>Kubelets further behind the API server are reported. Default ', DEFAULTS.kubeletSkewMinors, '.</small></div>',
    '<label class="', P, '-check"><input type="checkbox" id="', P, '-authcrit" checked><span>Treat cluster-admin for system:authenticated / unauthenticated as critical<small>Off: reported as high.</small></span></label>',
    '<label class="', P, '-check"><input type="checkbox" id="', P, '-complete"><span>The dump includes every kind<small>A kind missing from the dump then means none exist (for example no NetworkPolicies). Off: checks that need a missing kind are skipped and listed.</small></span></label>',
    "</div></div>",
    '<div id="', P, '-out"></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], fileMeta = null, result = null, isExample = false, exampleEol = null, eolFeed = null;
  let tab = "findings", sorts = {}, query = "", sevFilter = "", selFinding = null;

  const renderFiles = () => {
    $("run").disabled = !files.length; $("clear").disabled = !files.length;
    const meta = fileMeta ? fileMeta.files : [];
    $("files").innerHTML = files.map((f, i) => {
      const m = meta[i] || { kind: "pending", confidence: 0, objects: 0 };
      const reason = fileMeta ? (fileMeta.skipped.find((s) => s.file === f.name) || {}).reason : "";
      return '<div class="' + P + '-file"><b>' + esc(f.name) + '</b><span class="' + P + '-fmt">' + esc(m.kind === "pending" ? "detecting" : KIND_LABEL[m.kind] || m.kind) + (m.objects ? " (" + m.objects + " " + (m.kind === "kube-bench" ? "control groups" : m.kind === "can-i" ? "rules" : "objects") + ")" : "") + "</span>" +
        (m.kind !== "pending" ? '<span class="' + P + "-conf " + (m.confidence >= 0.8 ? "high" : "low") + '">' + (m.confidence >= 0.8 ? "high confidence" : "not recognised") + "</span>" : "") +
        (reason ? '<span class="' + P + '-fmt">' + esc(reason) + "</span>" : "") + "</div>";
    }).join("");
    const kinds = fileMeta ? fileMeta.stats.kinds || {} : {};
    $("kinds").innerHTML = Object.keys(kinds).length ? Object.entries(kinds).map(([k, v]) => '<span class="' + P + '-chip">' + esc(k) + " " + v + "</span>").join("") +
      (fileMeta.stats.duplicates ? '<span class="' + P + '-chip">' + fileMeta.stats.duplicates + " duplicates merged</span>" : "") : "";
  };
  const describe = async () => {
    fileMeta = null; renderFiles();
    if (!files.length) return;
    try { fileMeta = await runInWorker(ENGINE, "describeFiles", [files.map((f) => ({ name: f.name, text: f.text }))]); }
    catch (e) { toast("Could not read the files: " + ((e && e.message) || e), "error"); }
    renderFiles();
  };

  mountDropzone($("drop"), {
    maxBytes: 256 * 1024 * 1024, maxFiles: 500, unpack: true, multiple: true,
    label: "Drop kubectl dumps, kube-bench JSON or a .zip here, paste, or browse",
    onFiles: async (list) => {
      if (isExample) { files = []; isExample = false; exampleEol = null; }
      for (const f of list) { const text = await f.text(); const i = files.findIndex((x) => x.name === f.name); if (i >= 0) files[i] = { name: f.name, text }; else files.push({ name: f.name, text }); }
      toast("Loaded " + list.length + " file" + (list.length === 1 ? "" : "s"));
      await describe();
    },
  });
  $("clear").addEventListener("click", () => { files = []; fileMeta = null; isExample = false; exampleEol = null; result = null; $("out").innerHTML = ""; renderFiles(); });
  $("example").addEventListener("click", async () => {
    const ex = exampleDataset();
    files = ex.files.map((f) => ({ ...f })); isExample = true; exampleEol = ex.eol;
    toast("Synthetic example loaded (not real data)");
    await describe();
  });

  const loadEol = async () => {
    if (eolFeed) return eolFeed;
    try {
      const r = await fetch("/data/feeds/eol-products.json", { cache: "no-cache" });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      const entry = (j.data || []).find((p) => p.product === "kubernetes");
      eolFeed = entry ? { ...entry, updated: j.updated } : null;
      $("eol").textContent = eolFeed ? "mirrored " + String(j.updated).slice(0, 10) : "mirror has no kubernetes entry";
    } catch (e) { $("eol").textContent = "mirror unavailable: end-of-life check skipped"; eolFeed = null; }
    return eolFeed;
  };

  const opts = () => {
    const n = (id, d) => { const v = Number($(id).value); return Number.isFinite(v) && v >= 0 ? v : d; };
    const now = $("now").value.trim();
    return {
      clusterName: $("cluster").value.trim() || "cluster",
      allowedRegistries: $("regs").value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean),
      authenticatedCritical: $("authcrit").checked, assumeComplete: $("complete").checked,
      sharedSecretWorkloads: Math.max(2, n("shared", DEFAULTS.sharedSecretWorkloads)), eventRepeatCount: Math.max(1, n("events", DEFAULTS.eventRepeatCount)), kubeletSkewMinors: n("skew", DEFAULTS.kubeletSkewMinors),
      now: /^\d{4}-\d\d-\d\d/.test(now) ? now : null,
    };
  };

  $("run").addEventListener("click", async () => {
    if (!files.length) return;
    const prog = $("prog"), bar = prog.firstElementChild, pl = $("plabel");
    prog.style.display = "block"; pl.style.display = "block"; bar.style.width = "0%"; pl.textContent = "starting"; $("run").disabled = true;
    try {
      const o = opts();
      o.eol = isExample ? exampleEol : await loadEol();
      if (isExample) $("eol").textContent = "synthetic end-of-life data for the example";
      result = await runInWorker(ENGINE, "analyze", [files.map((f) => ({ name: f.name, text: f.text })), o], {
        timeoutMs: 600000,
        onProgress: (i, n, label) => { bar.style.width = (n ? Math.round((i / n) * 100) : 0) + "%"; if (label) pl.textContent = label; },
      });
      selFinding = null; query = ""; sevFilter = "";
      render();
      toast(result.findings.length + " finding" + (result.findings.length === 1 ? "" : "s") + " across " + result.summary.workloads + " workloads", "success");
    } catch (e) {
      toast("Analysis failed: " + ((e && e.message) || e), "error");
    } finally {
      prog.style.display = "none"; pl.style.display = "none"; $("run").disabled = !files.length;
    }
  });

  function render() {
    const r = result, s = r.summary, out = $("out");
    const sum = summarize(r.findings);
    out.innerHTML = "";
    const kp = document.createElement("div"); kp.className = P + "-kpis";
    kp.innerHTML = kpi(s.namespaces, "namespaces") + kpi(s.workloads, "workloads") + kpi(s.privilegedNonSystem, "privileged (non-system)") + kpi(s.clusterAdminSubjects, "cluster-admin subjects") +
      kpi(s.namespacesWithoutNetpol == null ? "n/a" : s.namespacesWithoutNetpol, "namespaces without netpol") + kpi(s.externallyExposed, "externally exposed") +
      ["critical", "high", "medium", "low", "info"].map((k) => kpi(sum.bySeverity[k] || 0, k, "sev-" + k)).join("");
    out.appendChild(kp);
    if (r.skipped.length) {
      const sk = document.createElement("div"); sk.className = P + "-card " + P + "-skip";
      sk.innerHTML = "<b>Skipped checks (" + r.skipped.length + ")</b><ul>" + r.skipped.map((k) => "<li>" + esc(k.check) + (k.file ? " [" + esc(k.file) + "]" : "") + ": " + esc(k.reason) + "</li>").join("") + "</ul>";
      out.appendChild(sk);
    }
    const ex = document.createElement("div"); ex.className = P + "-row"; ex.style.marginBottom = "12px";
    const stamp = () => TOOL_ID + "-" + fileStamp();
    const btns = [["Findings CSV", () => download(stamp() + "-findings.csv", findingsToCsv(r.findings), "text/csv")], ["JSON", () => download(stamp() + ".json", toJson(r), "application/json")],
      ["Summary TXT", () => download(stamp() + "-summary.txt", summaryText(r), "text/plain")], ["RBAC matrix CSV", () => download(stamp() + "-rbac.csv", rbacMatrixCsv(r.tables.subjects), "text/csv")],
      ["Workloads CSV", () => download(stamp() + "-workloads.csv", workloadsToCsv(r.tables.workloads), "text/csv")], ["Remediation YAML", () => download(stamp() + "-remediation.yaml", remediationYaml(r), "application/yaml")]];
    for (const [label, fn] of btns) { const b = document.createElement("button"); b.className = P + "-btn"; b.textContent = label; b.addEventListener("click", fn); ex.appendChild(b); }
    attachSinkButton(ex, () => ({ findings: graphFindings(r), sample: isExample }), TOOL_ID, { dataset: r.meta.cluster });
    out.appendChild(ex);
    const card = document.createElement("div"); card.className = P + "-card";
    const tabs = [["findings", "Findings", r.findings.length], ["workloads", "Workloads", r.tables.workloads.length], ["rbac", "RBAC", r.tables.subjects.length], ["namespaces", "Namespaces", r.tables.namespaces.length], ["images", "Images", r.tables.images.length], ["exposure", "Exposure", r.tables.exposure.length]];
    const tb = document.createElement("div"); tb.className = P + "-tabs"; tb.setAttribute("role", "tablist");
    tb.innerHTML = tabs.map(([k, l, n]) => '<button class="' + P + "-tab" + (tab === k ? " on" : "") + '" role="tab" data-t="' + k + '">' + esc(l) + " (" + n + ")</button>").join("");
    tb.querySelectorAll("button").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.t; render(); }));
    card.appendChild(tb);
    const body = document.createElement("div"); card.appendChild(body);
    out.appendChild(card);
    renderTab(body);
  }

  /** Findings for the graph: cluster asset kept; workload assets carry k8s-workload data. */
  function graphFindings(r) { return r.findings.map(({ check, namespaces, path, yaml, ...f }) => ({ ...f, tags: (f.tags || []).concat([check]) })); }

  function filterBar(body, onChange, withSev) {
    const fb = document.createElement("div"); fb.className = P + "-filters";
    fb.innerHTML = '<div class="' + P + '-field"><label for="' + P + '-q">Filter</label><input type="text" id="' + P + '-q" placeholder="text" value="' + esc(query) + '"></div>' +
      (withSev ? '<div class="' + P + '-field"><label for="' + P + '-sev">Severity</label><select id="' + P + '-sev" style="font:inherit;font-size:.84rem;padding:7px 10px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--card,#fff);color:var(--tx,#1a2230)"><option value="">all</option>' +
        ["critical", "high", "medium", "low", "info"].map((x) => '<option value="' + x + '"' + (sevFilter === x ? " selected" : "") + ">" + x + "</option>").join("") + "</select></div>" : "");
    body.appendChild(fb);
    const qi = fb.querySelector("#" + P + "-q");
    qi.addEventListener("input", () => { query = qi.value; onChange(); });
    if (withSev) fb.querySelector("#" + P + "-sev").addEventListener("change", (e) => { sevFilter = e.target.value; onChange(); });
  }
  const match = (row) => !query || JSON.stringify(row).toLowerCase().includes(query.toLowerCase());

  function renderTab(body) {
    const r = result;
    const holder = document.createElement("div");
    const sort = sorts[tab] || (sorts[tab] = tab === "findings" ? { key: "severity", dir: "desc" } : { key: "", dir: "desc" });
    const redraw = () => { holder.innerHTML = ""; draw(); };
    filterBar(body, redraw, tab === "findings");
    body.appendChild(holder);
    const drawer = document.createElement("div"); drawer.className = P + "-drawer"; body.appendChild(drawer);
    const resort = (sv) => { sorts[tab] = sv; renderTab(clear(body)); };
    function draw() {
      if (tab === "findings") {
        const rows = r.findings.filter((f) => (!sevFilter || f.severity === sevFilter) && match({ t: f.title, d: f.description, c: f.check }));
        holder.appendChild(table([
          { key: "severity", label: "Severity", rank: SEV_RANK, render: (f) => pill(f.severity) },
          { key: "title", label: "Finding", render: (f) => "<b>" + esc(f.title) + '</b><div class="' + P + '-note">' + esc(f.category) + " / " + esc(f.check) + "</div>" },
          { key: "confidence", label: "Confidence", rank: CONF_RANK },
          { key: "controls", label: "Controls", render: (f) => f.controls.slice(0, 4).map((c) => '<span class="' + P + '-chip">' + esc(c.framework.replace("CIS Kubernetes Benchmark", "CIS K8s").replace("NSA/CISA Kubernetes Hardening Guide v1.2", "NSA/CISA") + " " + c.id) + "</span>").join("") + (f.controls.length > 4 ? '<span class="' + P + '-chip">+' + (f.controls.length - 4) + "</span>" : "") },
          { key: "evidenceCount", label: "Evidence" },
        ], rows, sort, resort, (f) => showFinding(drawer, f)));
        if (selFinding) { const f = r.findings.find((x) => x.id === selFinding); if (f) showFinding(drawer, f); }
      } else if (tab === "workloads") {
        holder.appendChild(table([
          { key: "namespace", label: "Namespace" }, { key: "kind", label: "Kind" }, { key: "name", label: "Name" }, { key: "replicas", label: "Replicas" },
          { key: "images", label: "Images", mono: true }, { key: "serviceAccount", label: "Service account" },
          { key: "privileged", label: "Privileged", render: (w) => yes(w.privileged) + (w.system === "yes" && w.privileged === "yes" ? ' <span class="' + P + '-note">system</span>' : "") },
          { key: "hostNetwork", label: "Host network", render: (w) => yes(w.hostNetwork) }, { key: "runAsRoot", label: "Root", render: (w) => yes(w.runAsRoot) },
          { key: "policyCoverage", label: "NetworkPolicy" }, { key: "exposure", label: "Exposure", render: (w) => esc(w.exposure) + (w.exposedVia ? '<div class="' + P + '-note">' + esc(w.exposedVia) + "</div>" : "") },
          { key: "saPermissions", label: "SA rights" }, { key: "findings", label: "Findings" },
        ], r.tables.workloads.filter(match), sort, resort));
      } else if (tab === "rbac") {
        holder.appendChild(table([
          { key: "kind", label: "Kind" }, { key: "name", label: "Subject", render: (s) => "<b>" + esc(s.name) + "</b>" }, { key: "namespace", label: "Namespace" },
          { key: "clusterAdmin", label: "cluster-admin", render: (s) => yes(s.clusterAdmin) }, { key: "scope", label: "Scope" },
          { key: "dangerous", label: "Dangerous rights", render: (s) => s.dangerous ? s.dangerous.split("; ").map((d) => '<span class="' + P + '-chip">' + esc(d) + "</span>").join("") : "" },
          { key: "roles", label: "Roles", mono: true }, { key: "source", label: "Source" },
        ], r.tables.subjects.filter(match), sort, resort));
      } else if (tab === "namespaces") {
        holder.appendChild(table([
          { key: "namespace", label: "Namespace" }, { key: "workloads", label: "Workloads" }, { key: "networkPolicies", label: "NetworkPolicies" },
          { key: "defaultDenyIngress", label: "Deny ingress" }, { key: "defaultDenyEgress", label: "Deny egress" }, { key: "psaEnforce", label: "PSA enforce" },
          { key: "psaWarn", label: "PSA warn" }, { key: "psaAudit", label: "PSA audit" }, { key: "findings", label: "Findings" },
        ], r.tables.namespaces.filter(match), sort, resort));
      } else if (tab === "images") {
        holder.appendChild(table([
          { key: "image", label: "Image", mono: true }, { key: "registry", label: "Registry" }, { key: "tag", label: "Tag" }, { key: "tagPolicy", label: "Tag policy" },
          { key: "allowed", label: "Allowed" }, { key: "workloads", label: "Workloads" }, { key: "usedBy", label: "Used by", mono: true },
        ], r.tables.images.filter(match), sort, resort));
      } else {
        holder.appendChild(table([
          { key: "severity", label: "Risk", rank: SEV_RANK, render: (e) => pill(e.severity) }, { key: "namespace", label: "Namespace" }, { key: "service", label: "Service" },
          { key: "type", label: "Type" }, { key: "ports", label: "Ports" }, { key: "ingress", label: "Ingress" }, { key: "workload", label: "Workload" }, { key: "risks", label: "Risk chain" },
        ], r.tables.exposure.filter(match), sort, resort));
      }
    }
    draw();
  }
  const clear = (el) => { el.innerHTML = ""; return el; };

  function showFinding(drawer, f) {
    selFinding = f.id;
    drawer.style.display = "block";
    const det = DETECTIONS.find((d) => d.check === f.check);
    drawer.innerHTML = "<h3>" + esc(f.title) + "</h3><div>" + pill(f.severity) + ' <span class="' + P + '-chip">' + esc(f.confidence) + '</span> <span class="' + P + '-chip">' + esc(f.category) + "</span></div>" +
      "<p>" + esc(f.description) + "</p><p><b>Recommendation:</b> " + esc(f.recommendation) + "</p>" +
      '<dl class="' + P + '-dl"><dt>Controls</dt><dd>' + f.controls.map((c) => esc(c.framework + " " + c.id)).join("; ") + "</dd>" +
      (f.path ? "<dt>Object path</dt><dd><code>" + esc(f.path) + "</code></dd>" : "") +
      "<dt>Affected</dt><dd>" + esc(f.assets.filter((a) => a.data && a.data.kind !== "k8s-cluster" || a.type === "IDENTITY").map((a) => a.name).join(", ") || "cluster") + "</dd>" +
      "<dt>Evidence</dt><dd>" + f.evidenceCount + " row" + (f.evidenceCount === 1 ? "" : "s") + (f.evidenceCount > f.evidence.length ? " (first " + f.evidence.length + " shown)" : "") + "</dd>" +
      (det ? "<dt>Check</dt><dd>" + esc(det.check) + "</dd>" : "") + "</dl>" +
      (f.yaml ? "<b>Offending snippet</b> <span class=\"" + P + "-note\">(re-serialised; credential values redacted)</span><pre>" + esc(f.yaml) + "</pre>" : "") +
      evidenceTable(f.evidence);
  }

  renderFiles();
}
