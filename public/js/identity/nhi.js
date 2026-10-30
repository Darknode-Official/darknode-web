// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Non-Human Identity Lifecycle (nhi): Deck tool UI. Drop AWS / Entra / GCP / Okta /
// Kubernetes / GitHub credential exports; the pure engine (nhi-engine.js) runs in a
// Worker and returns the credential inventory, findings and a rotation calendar.
// Everything stays in the browser; nothing is fetched. No native dialogs; toasts only.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp, toIcs } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, COLUMNS, parseInput, findingsToCsv, credentialsToCsv, calendarToCsv, calendarToEvents, exampleDataset,
} from "./nhi-engine.js?v=20261029e";

const ENGINE = engineUrl("./nhi-engine.js?v=20261029e", import.meta);
const P = "nhi";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const day = (v) => (v == null ? "" : v === "never" ? "never" : String(v).slice(0, 10));
const num = (n) => (n == null ? "" : Number(n).toLocaleString());

const CSS = `
  .nhi-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .nhi-root *{box-sizing:border-box}
  .nhi-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .nhi-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .nhi-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .nhi-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:90ch}
  .nhi-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;max-width:100%}
  .nhi-card h2{font-size:.78rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--mut,#667085);margin:0 0 10px}
  .nhi-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .nhi-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .nhi-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .nhi-btn.sm{padding:4px 9px;font-size:.76rem}
  .nhi-btn:disabled{opacity:.5;cursor:default}
  .nhi-files{display:flex;flex-direction:column;gap:8px;margin-top:12px}
  .nhi-filerow{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;font-size:.84rem}
  .nhi-filerow b{overflow-wrap:anywhere}
  .nhi-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .nhi-conf.hi{background:#1b7f4b}.nhi-conf.mid{background:#b58100}.nhi-conf.lo{background:#b00020}
  .nhi-map{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;margin-top:10px}
  .nhi-ctl{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:14px 20px;align-items:start}
  .nhi-field{display:flex;flex-direction:column;gap:4px;min-width:0}
  /* a label that wraps to two lines must not push its input below its neighbours': each field's label, input and help share the row tracks */
  .nhi-ctl>.nhi-field{display:grid;grid-row:span 3;grid-template-rows:subgrid;row-gap:4px;align-content:start}.nhi-ctl>.nhi-field>label{align-self:end}
  .nhi-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .nhi-field input,.nhi-field select,.nhi-field textarea{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%}
  .nhi-field textarea{min-height:58px;resize:vertical}
  .nhi-help{font-size:.72rem;color:var(--mut,#667085);line-height:1.4;overflow-wrap:anywhere}
  .nhi-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin:14px 0}
  .nhi-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .nhi-kpi b{display:block;font-size:1.3rem;overflow-wrap:anywhere}
  .nhi-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .nhi-kpi.warn b{color:#b00020}
  .nhi-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .nhi-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .nhi-filters{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;margin-bottom:10px}
  .nhi-filters select,.nhi-filters input{font:inherit;font-size:.82rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:6px 9px;max-width:100%}
  .nhi-filters input{flex:1 1 160px;min-width:0}
  .nhi-count{font-size:.76rem;color:var(--mut,#667085)}
  .nhi-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .nhi-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:640px}
  .nhi-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .nhi-list th.on::after{content:" \\25BE";}
  .nhi-list th.on.asc::after{content:" \\25B4";}
  .nhi-list td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word}
  .nhi-list tr[data-i]{cursor:pointer}
  .nhi-list tr[data-i]:hover{background:var(--bg,#f7f8fb)}
  .nhi-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .nhi-pill.critical{background:#7a0012}.nhi-pill.high{background:#b00020}.nhi-pill.medium{background:#b58100}.nhi-pill.low{background:#2552c6}.nhi-pill.info{background:#667085}
  .nhi-st{display:inline-block;font-size:.7rem;font-weight:700;padding:1px 7px;border-radius:6px;border:1px solid var(--line,#d7dbe3);white-space:nowrap}
  .nhi-st.expired,.nhi-st.never-used{color:#7a0012;border-color:#7a0012}.nhi-st.overdue,.nhi-st.expiring{color:#b00020;border-color:#b00020}.nhi-st.unused{color:#b58100;border-color:#b58100}.nhi-st.ok{color:#1b7f4b;border-color:#1b7f4b}
  .nhi-chip{display:inline-block;font-size:.68rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .nhi-flag{display:inline-block;font-size:.66rem;background:var(--bg,#f7f8fb);border:1px solid var(--line,#e6e8ee);border-radius:4px;padding:0 5px;margin:1px 3px 1px 0;white-space:nowrap}
  .nhi-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .nhi-drawer{margin-top:14px;display:none}
  .nhi-drawer .nhi-list{max-height:360px}
  .nhi-cal{display:flex;flex-direction:column;gap:10px}
  .nhi-month{border:1px solid var(--line,#e6e8ee);border-radius:10px;overflow:hidden}
  .nhi-month h3{margin:0;font-size:.8rem;font-weight:700;padding:8px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap}
  .nhi-month.over h3{color:#b00020}
  .nhi-ev{display:grid;grid-template-columns:92px 84px minmax(0,1fr);gap:8px;padding:7px 12px;border-bottom:1px solid var(--line,#eef0f4);font-size:.82rem;align-items:baseline}
  .nhi-ev:last-child{border-bottom:0}
  .nhi-ev .d{color:var(--mut,#667085);white-space:nowrap}
  .nhi-ev .w{overflow-wrap:anywhere}
  .nhi-ev .w small{color:var(--mut,#667085)}
  @media (max-width:480px){.nhi-ev{grid-template-columns:92px minmax(0,1fr)}.nhi-ev .a{grid-column:2}.nhi-ev .w{grid-column:1/-1}}
  .nhi-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px;overflow-wrap:anywhere}
  .nhi-sect{margin-top:18px}
`;

const LOGICAL = { principal: "Principal", credential: "Credential id", kind: "Kind", created: "Created", lastUsed: "Last used", expires: "Expires", owner: "Owner", source: "Source", status: "Status" };
const STATUS_ORDER = ["expired", "expiring", "overdue", "never-used", "unused", "ok", "managed", "inactive", "unknown"];
const INV_COLS = [["source", "Source"], ["principal", "Principal"], ["kind", "Kind"], ["credential", "Credential"], ["created", "Created"], ["lastUsed", "Last used"], ["expires", "Expires"], ["ageDays", "Age (d)"], ["status", "Status"], ["owner", "Owner"], ["score", "Score"], ["flags", "Flags"]];

function kpi(v, l, warn) { return '<div class="' + P + '-kpi' + (warn ? " warn" : "") + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>"; }
const confClass = (c) => (c >= 0.85 ? "hi" : c >= 0.5 ? "mid" : "lo");
const confLabel = (c) => (c >= 0.85 ? "high" : c >= 0.5 ? "medium" : "low") + " confidence";

function table(rows, cols, { sort, onSort, rowAttr } = {}) {
  if (!rows.length) return '<div class="' + P + '-empty">Nothing to show.</div>';
  const th = cols.map(([k, l]) => '<th data-k="' + esc(k) + '" class="' + (sort && sort.key === k ? "on" + (sort.asc ? " asc" : "") : "") + '">' + esc(l) + "</th>").join("");
  const td = (r, k, i) => {
    const v = r[k];
    if (k === "severity") return '<span class="' + P + "-pill " + esc(v) + '">' + esc(v) + "</span>";
    if (k === "status") return '<span class="' + P + "-st " + esc(v) + '">' + esc(v) + "</span>";
    if (k === "flags") return (v || []).map((f) => '<span class="' + P + '-flag">' + esc(f) + "</span>").join("");
    if (k === "controls") return (v || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("");
    if (k === "title") return "<b>" + esc(v) + "</b><div>" + esc(r.description) + "</div>";
    if (/^(created|lastUsed|expires)$/.test(k)) return esc(day(v) || (k === "lastUsed" && r.usageKnown === false ? "" : k === "lastUsed" ? "never" : ""));
    if (Array.isArray(v)) return esc(v.join("; "));
    return esc(v == null ? "" : typeof v === "object" ? JSON.stringify(v) : v);
  };
  return "<table><thead><tr>" + th + "</tr></thead><tbody>" + rows.map((r, i) => "<tr" + (rowAttr ? rowAttr(r, i) : "") + ">" + cols.map(([k]) => "<td>" + td(r, k, i) + "</td>").join("") + "</tr>").join("") + "</tbody></table>";
}

function sortRows(rows, sort) {
  if (!sort || !sort.key) return rows;
  const k = sort.key, dir = sort.asc ? 1 : -1;
  const sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return rows.slice().sort((a, b) => {
    let x = a[k], y = b[k];
    if (k === "severity") { x = sevRank[x]; y = sevRank[y]; }
    if (k === "status") { x = STATUS_ORDER.indexOf(x); y = STATUS_ORDER.indexOf(y); }
    if (Array.isArray(x)) x = x.length; if (Array.isArray(y)) y = y.length;
    if (x == null && y == null) return 0; if (x == null) return 1; if (y == null) return -1;
    if (typeof x === "number" && typeof y === "number") return (x - y) * dir;
    return String(x).localeCompare(String(y)) * dir;
  });
}

/** Mount the tool into main. */
export function renderNhi(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Service Accounts</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Inventory every machine credential (access keys, client secrets, certificates, API tokens, service-account keys and tokens) across AWS, Entra, GCP, Okta, Kubernetes and GitHub; score each by age, last use, expiry, ownership and scope; get a rotation calendar. Runs entirely in your browser. Nothing is uploaded and nothing is fetched.</p>',
    '<div class="', P, '-card"><div id="', P, '-drop"></div>',
    '<p class="', P, '-help" style="margin:8px 0 0">Accepted: AWS IAM credential report CSV; Entra <code>GET /applications</code> or <code>Get-MgApplication</code> JSON, portal App registrations CSV, <code>/servicePrincipals</code> JSON; <code>gcloud iam service-accounts keys list</code> and <code>service-accounts list</code> JSON; Okta API tokens CSV or <code>/api/v1/api-tokens</code> JSON; <code>kubectl get serviceaccounts | secrets | clusterrolebindings -o json</code>; <code>gh api orgs/{org}/installations</code> and deploy keys JSON. Any other CSV/JSON with principal and date columns can be mapped by hand.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button>',
    '<button class="', P, '-btn" id="', P, '-clear" disabled>Clear files</button>',
    '<button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button><span id="', P, '-file" class="', P, '-skip"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div></div>',
    '<div class="', P, '-card"><h2>Thresholds</h2><div class="', P, '-ctl">',
    field("maxKeyAgeDays", "Max key age (days)", DEFAULTS.maxKeyAgeDays, "Active secret older than this is overdue for rotation (CIS AWS 1.14, CIS GCP 1.7)."),
    field("unusedDays", "Unused threshold (days)", DEFAULTS.unusedDays, "No use for this long, or never used after this age, is stale (CIS AWS 1.12)."),
    field("expiryWarnDays", "Expiry warning windows (days)", DEFAULTS.expiryWarnDays.join(", "), "Comma-separated, ascending; first window is high, then medium, then low.", "text"),
    field("maxCertDays", "Max certificate validity (days)", DEFAULTS.maxCertDays, "Certificates valid longer than this are flagged (CA/B Forum 398-day limit)."),
    field("now", "Reference date", "", "Leave blank to use the latest timestamp in the data.", "date"),
    '<div class="', P, '-field"><label for="', P, '-opt-departed">Departed users</label><textarea id="', P, '-opt-departed" placeholder="One per line"></textarea><span class="', P, '-help">Names or emails of leavers; Okta tokens they created are flagged.</span></div>',
    "</div></div>",
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-sect" id="', P, '-inv"></div>',
    '<div class="', P, '-sect" id="', P, '-fnd"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div>',
    '<div class="', P, '-sect" id="', P, '-cal"></div>',
    '<div class="', P, '-skip" id="', P, '-skipped"></div>',
    "</div>",
  ].join("");

  function field(k, label, val, help, type) {
    return '<div class="' + P + '-field"><label for="' + P + "-opt-" + k + '">' + esc(label) + '</label><input id="' + P + "-opt-" + k + '" data-opt="' + esc(k) + '" type="' + (type || "number") + '" value="' + esc(val) + '"' + (type ? "" : ' min="1" step="1"') + '><span class="' + P + '-help">' + esc(help) + "</span></div>";
  }

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], parsed = null, result = null, isExample = false;
  const mapping = Object.create(null); // keyed by file name: a file named __proto__ must not reach Object.prototype
  let invSort = { key: "score", asc: false }, fndSort = { key: "severity", asc: true }, invFilter = { source: "", status: "", q: "" }, invShowAll = false;

  const reparse = () => {
    parsed = files.length ? parseInput(files, { mapping }) : null;
    renderFiles();
    $("run").disabled = !parsed || !parsed.rows.length;
    $("clear").disabled = !files.length;
    $("file").textContent = parsed ? parsed.rows.length + " record(s) across " + files.length + " file(s)" : "";
  };

  function renderFiles() {
    const box = $("files");
    if (!parsed) { box.innerHTML = ""; return; }
    box.innerHTML = parsed.files.map((f, i) => {
      const generic = f.source === "generic";
      const mapPanel = generic || f.confidence < 0.85 ? mapPanelHtml(f, i) : "";
      return '<div class="' + P + '-filerow" data-f="' + i + '"><b>' + esc(f.name) + "</b><span>" + esc(f.label) + '</span><span class="' + P + "-conf " + confClass(f.confidence) + '">' + esc(confLabel(f.confidence)) + "</span><span>" + esc(f.records) + ' record(s)</span><button class="' + P + '-btn sm" data-rm="' + i + '">Remove</button>' + mapPanel + "</div>";
    }).join("");
    box.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { const f = files[Number(b.dataset.rm)]; files.splice(Number(b.dataset.rm), 1); if (f) delete mapping[f.name]; isExample = false; reparse(); }));
    box.querySelectorAll("select[data-map]").forEach((sel) => sel.addEventListener("change", () => {
      const [fname, key] = sel.dataset.map.split("\u0000");
      mapping[fname] = mapping[fname] || {};
      if (sel.value) mapping[fname][key] = sel.value; else delete mapping[fname][key];
      reparse();
    }));
  }

  function mapPanelHtml(f, i) {
    if (!f.headers || !f.headers.length) return '<div class="' + P + '-help" style="flex-basis:100%">' + (f.source === "none" ? "This file could not be read as CSV or JSON." : "No column headers found.") + "</div>";
    const cur = Object.assign({}, f.mapping || {}, mapping[f.name] || {});
    return '<div style="flex-basis:100%"><div class="' + P + '-help">' + (f.source === "generic" ? "Not a recognised vendor export. Map the columns to use it:" : "Detected with reduced confidence; override the column mapping if needed:") + '</div><div class="' + P + '-map">' +
      Object.entries(LOGICAL).map(([k, l]) => '<div class="' + P + '-field"><label>' + esc(l) + '</label><select data-map="' + esc(f.name) + "\u0000" + k + '"><option value="">(none)</option>' +
        f.headers.map((h) => '<option value="' + esc(h) + '"' + (cur[k] === h ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>").join("") + "</div></div>";
  }

  mountDropzone($("drop"), {
    maxBytes: 64 * 1024 * 1024, maxFiles: 24, label: "Drop credential exports here (several at once), paste, or browse",
    onFiles: async (list) => {
      let added = 0;
      for (const f of list) {
        const text = await f.text();
        if (!text.trim()) { toast(f.name + " is empty", "warning"); continue; }
        const idx = files.findIndex((x) => x.name === f.name);
        if (idx >= 0) files[idx] = { name: f.name, text }; else files.push({ name: f.name, text });
        added++;
      }
      if (!added) return;
      isExample = false;
      reparse();
      const bad = parsed.files.filter((x) => x.source === "none");
      toast(parsed.rows.length + " record(s) from " + files.length + " file(s)" + (bad.length ? "; " + bad.length + " unreadable" : ""), bad.length ? "warning" : "success");
    },
  });

  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    files = ex.files.map((f) => ({ name: f.name, text: f.text }));
    for (const k of Object.keys(mapping)) delete mapping[k];
    isExample = true;
    reparse();
    toast("Synthetic example loaded: " + ex.label, "info");
  });
  $("clear").addEventListener("click", () => { files = []; for (const k of Object.keys(mapping)) delete mapping[k]; isExample = false; reparse(); });

  const opts = () => {
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => {
      const k = el.dataset.opt, v = String(el.value || "").trim();
      if (!v) return;
      if (k === "expiryWarnDays") o[k] = v.split(/[,\s;]+/).map(Number).filter((n) => Number.isFinite(n) && n > 0);
      else if (k === "now") o.now = v + "T23:59:59Z";
      else { const n = Number(v); if (Number.isFinite(n) && n > 0) o[k] = n; }
    });
    const dep = String($("opt-departed").value || "").split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean);
    if (dep.length) o.departed = dep;
    return o;
  };

  $("run").addEventListener("click", async () => {
    if (!parsed) return;
    const prog = $("prog"), bar = prog.firstElementChild;
    prog.style.display = "block"; bar.style.width = "0%"; $("run").disabled = true;
    try {
      result = await runInWorker(ENGINE, "analyze", [parsed, opts()], {
        onProgress: (i, n) => { bar.style.width = (n ? Math.round(i / n * 100) : 0) + "%"; },
      });
      invShowAll = false; invFilter = { source: "", status: "", q: "" };
      render(result);
      toast(result.findings.length + " finding(s) across " + result.summary.credentials + " credential(s)", "success");
    } catch (e) {
      toast("Analysis failed: " + (e && e.message || e), "error");
    } finally {
      prog.style.display = "none"; $("run").disabled = !parsed || !parsed.rows.length;
    }
  });

  function render(r) {
    const s = r.summary, sum = summarize(r.findings);
    $("kpis").innerHTML = kpi(num(s.credentials), "credentials") + kpi(num(s.principals), "principals") + kpi(num(s.ownerless), "ownerless", s.ownerless > 0) +
      kpi(num(s.expired), "expired", s.expired > 0) + kpi(num(s.expiringSoon), "expiring <= " + r.meta.options.expiryWarnDays[0] + "d", s.expiringSoon > 0) + kpi(num(s.overdue), "rotation overdue", s.overdue > 0) +
      kpi(num(s.neverUsed + s.unused), "never / unused", s.neverUsed + s.unused > 0) + kpi(num(r.findings.length), "findings") +
      kpi(num(sum.bySeverity.critical + sum.bySeverity.high), "critical + high", sum.bySeverity.critical + sum.bySeverity.high > 0) +
      kpi(s.nextExpiry ? s.nextExpiry.date : "none", "next expiry") + kpi(r.meta.now ? r.meta.now.slice(0, 10) : "n/a", "reference date (" + r.meta.nowSource + ")");
    $("skipped").textContent = r.skipped.length ? "Skipped: " + r.skipped.map((x) => x.check + " (" + x.reason + ")").join("; ") : "";

    const ex = $("exports");
    ex.innerHTML = [["csv", "Findings CSV"], ["inv", "Inventory CSV"], ["json", "JSON"], ["txt", "Summary TXT"], ["ics", "Calendar .ics"], ["calcsv", "Calendar CSV"]]
      .map(([k, l]) => '<button class="' + P + '-btn" data-x="' + k + '">' + l + "</button>").join("");
    const stamp = fileStamp();
    ex.querySelector('[data-x="csv"]').addEventListener("click", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    ex.querySelector('[data-x="inv"]').addEventListener("click", () => download(TOOL_ID + "-inventory-" + stamp + ".csv", credentialsToCsv(r.tables.credentials), "text/csv"));
    ex.querySelector('[data-x="json"]').addEventListener("click", () => download(TOOL_ID + "-" + stamp + ".json", toJson(r), "application/json"));
    ex.querySelector('[data-x="txt"]').addEventListener("click", () => download(TOOL_ID + "-" + stamp + ".txt", summaryText(r), "text/plain"));
    ex.querySelector('[data-x="ics"]').addEventListener("click", () => download(TOOL_ID + "-rotation-" + stamp + ".ics", toIcs(calendarToEvents(r.tables.calendar, r.meta.now)), "text/calendar"));
    ex.querySelector('[data-x="calcsv"]').addEventListener("click", () => download(TOOL_ID + "-rotation-" + stamp + ".csv", calendarToCsv(r.tables.calendar), "text/csv"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: files.map((f) => f.name).join(", ") });

    renderInventory(r); renderFindings(r); renderCalendar(r);
    $("drawer").style.display = "none";
  }

  function renderInventory(r) {
    const all = r.tables.credentials;
    const sources = [...new Set(all.map((c) => c.source))].sort(), statuses = STATUS_ORDER.filter((s) => all.some((c) => c.status === s));
    const q = invFilter.q.toLowerCase();
    const rows = sortRows(all.filter((c) => (!invFilter.source || c.source === invFilter.source) && (!invFilter.status || c.status === invFilter.status) &&
      (!q || [c.principal, c.credential, c.owner, c.kind, c.scope, (c.flags || []).join(" ")].join(" ").toLowerCase().includes(q))), invSort);
    const shown = invShowAll ? rows : rows.slice(0, 300);
    const box = $("inv");
    box.innerHTML = '<div class="' + P + '-card"><h2>Credential inventory</h2><div class="' + P + '-filters">' +
      '<select data-f="source"><option value="">All sources</option>' + sources.map((s) => '<option value="' + esc(s) + '"' + (invFilter.source === s ? " selected" : "") + ">" + esc(s) + "</option>").join("") + "</select>" +
      '<select data-f="status"><option value="">All statuses</option>' + statuses.map((s) => '<option value="' + esc(s) + '"' + (invFilter.status === s ? " selected" : "") + ">" + esc(s) + "</option>").join("") + "</select>" +
      '<input data-f="q" type="search" placeholder="Search" value="' + esc(invFilter.q) + '">' +
      '<span class="' + P + '-count">' + rows.length + " of " + all.length + (shown.length < rows.length ? " (showing " + shown.length + ")" : "") + "</span></div>" +
      '<div class="' + P + '-list">' + table(shown, INV_COLS, { sort: invSort }) + "</div>" +
      (shown.length < rows.length ? '<div class="' + P + '-row"><button class="' + P + '-btn" data-more>Show all ' + rows.length + "</button></div>" : "") + "</div>";
    box.querySelectorAll("[data-f]").forEach((el) => el.addEventListener(el.tagName === "INPUT" ? "input" : "change", () => { invFilter[el.dataset.f] = el.value; renderInventory(r); if (el.dataset.f === "q") { const i = box.querySelector('[data-f="q"]'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }));
    box.querySelectorAll("th[data-k]").forEach((th) => th.addEventListener("click", () => { const k = th.dataset.k; invSort = { key: k, asc: invSort.key === k ? !invSort.asc : k !== "score" }; renderInventory(r); }));
    const more = box.querySelector("[data-more]"); if (more) more.addEventListener("click", () => { invShowAll = true; renderInventory(r); });
  }

  const FND_COLS = [["severity", "Severity"], ["title", "Finding"], ["confidence", "Confidence"], ["category", "Category"], ["controls", "Controls"], ["evidenceCount", "Evidence"]];
  function renderFindings(r) {
    const box = $("fnd");
    const rows = sortRows(r.findings, fndSort);
    box.innerHTML = '<div class="' + P + '-card"><h2>Findings</h2><div class="' + P + '-list">' +
      (rows.length ? table(rows, FND_COLS, { sort: fndSort, rowAttr: (f) => ' data-i="' + r.findings.indexOf(f) + '"' }) : '<div class="' + P + '-empty">No findings for the current thresholds.</div>') + "</div></div>";
    box.querySelectorAll("th[data-k]").forEach((th) => th.addEventListener("click", () => { const k = th.dataset.k; fndSort = { key: k, asc: fndSort.key === k ? !fndSort.asc : true }; renderFindings(r); }));
    box.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => openDrawer(r.findings[Number(tr.dataset.i)])));
  }

  function openDrawer(f) {
    const d = $("drawer"); d.style.display = "block";
    const cols = [["source", "Source"], ["principal", "Principal"], ["kind", "Kind"], ["credential", "Credential"], ["created", "Created"], ["lastUsed", "Last used"], ["expires", "Expires"], ["ageDays", "Age (d)"], ["expiresInDays", "Expires in (d)"], ["status", "Status"], ["owner", "Owner"], ["scope", "Scope"]];
    const present = cols.filter(([k]) => (f.evidence || []).some((e) => e[k] != null && e[k] !== ""));
    d.innerHTML = '<div class="' + P + '-card"><div class="' + P + '-row" style="margin:0 0 8px;justify-content:space-between"><div><span class="' + P + "-pill " + esc(f.severity) + '">' + esc(f.severity) + "</span> <b>" + esc(f.title) + '</b></div><button class="' + P + '-btn sm" data-close>Close</button></div>' +
      "<p>" + esc(f.description) + "</p><p><b>Recommendation:</b> " + esc(f.recommendation) + "</p><p>" + (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</p>" +
      '<div class="' + P + '-count" style="margin-bottom:6px">Evidence: ' + esc(f.evidenceCount) + " row(s)" + (f.evidenceCount > (f.evidence || []).length ? " (first " + f.evidence.length + " shown; the full set is in the inventory and JSON export)" : "") + "</div>" +
      '<div class="' + P + '-list">' + table(f.evidence || [], present.length ? present : cols) + "</div></div>";
    d.querySelector("[data-close]").addEventListener("click", () => { d.style.display = "none"; });
    d.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function renderCalendar(r) {
    const box = $("cal");
    const cal = r.tables.calendar;
    if (!cal.length) { box.innerHTML = '<div class="' + P + '-card"><h2>Rotation calendar</h2><div class="' + P + '-empty">No dated credentials to schedule.</div></div>'; return; }
    const now = (r.meta.now || "").slice(0, 7);
    const groups = new Map();
    for (const e of cal) {
      const key = e.daysFromNow < 0 ? "overdue" : e.date.slice(0, 7);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(e);
    }
    const label = (k) => (k === "overdue" ? "Overdue" : new Date(k + "-01T00:00:00Z").toLocaleDateString(undefined, { month: "long", year: "numeric", timeZone: "UTC" }) + (k === now ? " (this month)" : ""));
    box.innerHTML = '<div class="' + P + '-card"><h2>Rotation calendar</h2><p class="' + P + '-help" style="margin:0 0 10px">"rotate by" = created + ' + esc(r.meta.options.maxKeyAgeDays) + ' days; "expires" = the credential\'s own end date; "review" = a portal status with no date. Export as .ics to put every entry in a shared calendar.</p><div class="' + P + '-cal">' +
      [...groups.entries()].map(([k, list]) => '<div class="' + P + "-month" + (k === "overdue" ? " over" : "") + '"><h3><span>' + esc(label(k)) + "</span><span>" + list.length + " item(s)</span></h3>" +
        list.map((e) => '<div class="' + P + '-ev"><span class="d">' + esc(e.date) + '</span><span class="a"><span class="' + P + '-st ' + (e.action === "expires" ? "expiring" : e.action === "rotate by" ? "overdue" : "unknown") + '">' + esc(e.action) + '</span></span><span class="w">' + esc(e.principal) + " - " + esc(e.credential) + " <small>" + esc(e.source + " / " + e.kind + " / " + (e.owner || "unassigned")) + "</small></span></div>").join("") + "</div>").join("") + "</div></div>";
  }

  function summaryText(r) {
    const s = r.summary;
    return ["Non-Human Identity Lifecycle summary", "Reference date: " + (r.meta.now || "n/a") + " (" + r.meta.nowSource + ")", "Files: " + r.meta.files.map((f) => f.name + " [" + f.format + "]").join(", "),
      "Credentials: " + s.credentials + "  Principals: " + s.principals + "  Ownerless: " + s.ownerless, "Expired: " + s.expired + "  Expiring soon: " + s.expiringSoon + "  Rotation overdue: " + s.overdue + "  Never used: " + s.neverUsed + "  Unused: " + s.unused,
      "By source: " + JSON.stringify(s.bySource), "By status: " + JSON.stringify(s.byStatus), "Findings: " + r.findings.length + " " + JSON.stringify(s.bySeverity), ""]
      .concat(r.findings.map((f) => "- [" + f.severity + "/" + f.confidence + "] " + f.title + " (" + f.evidenceCount + ") - " + f.recommendation))
      .concat(["", "Rotation calendar (" + r.tables.calendar.length + "):"], r.tables.calendar.map((e) => "  " + e.date + "  " + e.action.padEnd(9) + " " + e.principal + " - " + e.credential + " [" + e.source + "]"))
      .concat(r.skipped.length ? ["", "Skipped: " + r.skipped.map((x) => x.check + " (" + x.reason + ")").join("; ")] : []).join("\n");
  }
}
