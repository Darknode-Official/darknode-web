// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Lifecycle & Offboarding Verifier (jml): Deck tool UI. Drop an HR roster, the IdP
// user export and every SaaS user list together; each file is classified by its
// headers (editable), then the engine (jml-engine.js, pure) runs in a Worker and
// reports leavers still active, time-to-disable against the SLA, movers with
// stale access, joiner gaps, orphan SaaS accounts and licence waste.
// Runs entirely in the browser; nothing is uploaded. No native dialogs; toasts only.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import { DEFAULTS, TOOL_ID, KINDS, parseInput, findingsToCsv, worklistCsv, slaCsv, exampleDataset } from "./jml-engine.js?v=20261017c";

const ENGINE = engineUrl("./jml-engine.js?v=20261017c", import.meta);
const P = "jml";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (n) => (n == null || n === "" ? "-" : Number(n).toLocaleString());
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const KIND_LABEL = { hr: "HR roster", "hr-changes": "HR changes (movers)", idp: "IdP users", saas: "SaaS user list", devices: "Device inventory", ignore: "Ignore this file", unknown: "Unrecognised" };
const MAP_FIELDS = {
  hr: ["employeeId", "name", "email", "hireDate", "termDate", "status", "dept", "manager"],
  "hr-changes": ["employeeId", "email", "effectiveDate", "changeType", "fromDept", "toDept"],
  idp: ["email", "upn", "name", "enabled", "lastSignIn", "created", "dept", "statusChanged", "groups"],
  saas: ["email", "login", "name", "status", "lastLogin", "licensed", "role"],
  devices: ["user", "device", "lastCheckin"],
};
const FIELD_LABEL = {
  employeeId: "Employee id", name: "Name", email: "Email", upn: "Login / UPN", login: "Login", hireDate: "Hire date", termDate: "Termination date", status: "Status", dept: "Department", manager: "Manager",
  effectiveDate: "Effective date", changeType: "Change type", fromDept: "From department", toDept: "To department", enabled: "Enabled / status", lastSignIn: "Last sign-in", created: "Created", statusChanged: "Status changed / disabled at",
  groups: "Groups", lastLogin: "Last login", licensed: "Licence", role: "Role / type", user: "User", device: "Device", lastCheckin: "Last check-in",
};

const CSS = `
  .jml-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .jml-root *{box-sizing:border-box}
  .jml-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .jml-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .jml-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .jml-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:90ch}
  .jml-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;max-width:100%}
  .jml-card h2{font-size:.95rem;margin:0 0 8px;letter-spacing:.01em}
  .jml-help{font-size:.78rem;color:var(--mut,#667085);margin:2px 0 8px;overflow-wrap:anywhere}
  .jml-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .jml-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .jml-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .jml-btn.on{border-color:#2552c6;color:#2552c6}
  .jml-btn:disabled{opacity:.5;cursor:default}
  .jml-ctl{display:flex;flex-wrap:wrap;gap:14px 20px;align-items:flex-end}
  .jml-field{display:flex;flex-direction:column;gap:4px;min-width:0;max-width:100%}
  .jml-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .jml-field input,.jml-field select,.jml-in{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;max-width:100%}
  .jml-field input[type=number]{width:120px}
  .jml-field input[type=date]{width:170px}
  .jml-field input.wide{width:320px;max-width:100%}
  .jml-field small{font-size:.74rem;color:var(--mut,#667085);max-width:34ch;overflow-wrap:anywhere}
  .jml-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}
  .jml-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .jml-kpi b{display:block;font-size:1.3rem;overflow-wrap:anywhere}
  .jml-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .jml-kpi.bad b{color:#b00020}
  .jml-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .jml-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .jml-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0}
  .jml-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%;background:var(--card,#fff)}
  .jml-list table{width:100%;border-collapse:collapse;font-size:.84rem;min-width:560px}
  .jml-list th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .jml-list th[data-sort]{cursor:pointer}
  .jml-list th[data-sort].asc::after{content:" \\2191"}.jml-list th[data-sort].desc::after{content:" \\2193"}
  .jml-list td{padding:9px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word}
  .jml-list tr[data-i]{cursor:pointer}
  .jml-list tr[data-i]:hover,.jml-list tr.sel{background:var(--bg,#f7f8fb)}
  .jml-list select,.jml-list input{min-width:150px;font:inherit;font-size:.8rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:4px 6px;max-width:100%}
  .jml-pill{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .jml-pill.critical{background:#7a0012}.jml-pill.high{background:#b00020}.jml-pill.medium{background:#b58100}.jml-pill.low{background:#2552c6}.jml-pill.info{background:#667085}
  .jml-pill.conf-high{background:#1f7a3a}.jml-pill.conf-medium{background:#b58100}.jml-pill.conf-low{background:#b00020}
  .jml-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .jml-conf{font-size:.76rem;text-transform:capitalize}
  .jml-flag{display:inline-block;font-size:.72rem;border:1px solid #b00020;color:#b00020;border-radius:6px;padding:0 6px;margin:1px 4px 1px 0}
  .jml-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .jml-drawer{margin-top:14px;display:none}
  .jml-drawer .jml-list{max-height:380px}
  .jml-drawer table{min-width:0}
  .jml-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px;overflow-wrap:anywhere}
  .jml-search{width:100%;max-width:360px}
  .jml-map{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px 14px;margin-top:8px}
  .jml-map label{display:block;font-size:.7rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.04em}
  .jml-map select{width:100%}
  .jml-sec{margin-top:12px}
  @media (max-width:520px){.jml-field input[type=number],.jml-field input[type=date],.jml-field input.wide{width:100%}.jml-list table{min-width:0}}
`;

function kpi(v, l, bad) { return '<div class="' + P + '-kpi' + (bad ? " bad" : "") + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>"; }
function pill(cls, text) { return '<span class="' + P + "-pill " + esc(cls) + '">' + esc(text) + "</span>"; }

function evidenceTable(rows) {
  if (!rows || !rows.length) return '<div class="' + P + '-empty">No evidence rows.</div>';
  const cols = [];
  for (const r of rows) for (const k of Object.keys(r || {})) if (!cols.includes(k)) cols.push(k);
  const cell = (v) => (v == null ? "" : Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v));
  return "<table><thead><tr>" + cols.map((c) => "<th>" + esc(c) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + cols.map((c) => "<td>" + esc(cell(r[c])) + "</td>").join("") + "</tr>").join("") + "</tbody></table>";
}

/** Mount the tool into main. */
export function renderJml(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Lifecycle &amp; Offboarding Verifier</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Drop your HR roster, the IdP user export and every SaaS user list together. Joiners, movers and leavers are verified across all of them: leavers still enabled or signed in, time-to-disable against your SLA, movers with old-department access, joiner gaps, orphan SaaS accounts and paid licences held by people who left. Runs entirely in your browser. Nothing is uploaded; nothing is fetched live.</p>',
    '<div class="', P, '-card"><div id="', P, '-drop"></div>',
    '<p class="', P, '-help">Accepted: Workday / BambooHR / Gusto / Rippling rosters and change reports; Entra (Get-MgUser CSV or JSON), Okta users JSON, Google Workspace users CSV; Slack, GitHub, Microsoft 365 active users, Zoom, Salesforce, Atlassian, Zendesk or any CSV with an email and a status column; Intune or Jamf device inventories. Zip archives are unpacked.</p>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button>',
    '<button class="', P, '-btn" id="', P, '-clear" disabled>Clear files</button><span id="', P, '-count" class="', P, '-skip"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div></div>',
    '<div class="', P, '-card" id="', P, '-files-card" style="display:none"><h2>Files</h2><p class="', P, '-help">Each file is classified by its headers. Correct the kind or the app name if a detection is wrong; files with less than high confidence show a column-mapping panel.</p><div id="', P, '-files"></div></div>',
    '<div class="', P, '-card" id="', P, '-costs-card" style="display:none"><h2>Licence cost per seat (monthly)</h2><p class="', P, '-help">Optional. Entered per app, used only to price the licences held by leavers and never-used accounts. Left blank, the tool reports seat counts and never estimates a price.</p><div class="', P, '-ctl" id="', P, '-costs"></div></div>',
    '<div class="', P, '-card"><h2>Thresholds</h2><div class="', P, '-ctl">',
    field("disableSlaHours", "Disable SLA (hours)", DEFAULTS.disableSlaHours, "Hours allowed between the HR termination date and the IdP disable."),
    field("moverGraceDays", "Mover grace (days)", DEFAULTS.moverGraceDays, "Days after a transfer during which old-department access is tolerated."),
    field("joinerLeadDays", "Joiner lead (days)", DEFAULTS.joinerLeadDays, "Days before the hire date an IdP account may already exist."),
    '<div class="', P, '-field"><label for="', P, '-now">As-of date</label><input id="', P, '-now" type="date"><small>Blank = latest timestamp in the data.</small></div>',
    '<div class="', P, '-field"><label for="', P, '-allow">Allowed external domains</label><input id="', P, '-allow" class="wide" type="text" placeholder="Comma-separated domains"><small>Comma-separated. Accounts on these domains are expected and not reported as external.</small></div>',
    "</div></div>",
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-tabs" id="', P, '-tabs" style="display:none"><button class="', P, '-btn on" data-tab="findings">Findings</button><button class="', P, '-btn" data-tab="people">People</button><button class="', P, '-btn" data-tab="apps">Apps</button><button class="', P, '-btn" data-tab="sla">Time to disable</button></div>',
    '<div id="', P, '-view"><div class="', P, '-list"><div class="', P, '-empty">No analysis yet. Drop files or load the synthetic example.</div></div></div>',
    '<div class="', P, '-skip" id="', P, '-skipped"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, tab = "findings", sort = { key: "severity", dir: "desc" }, search = "";

  // ---------------------------------------------------------------- files
  function setFiles(list, example = false) {
    files = list; isExample = example;
    const rows = files.reduce((n, f) => n + f.rowCount, 0);
    $("count").textContent = files.length ? files.length + " file(s), " + num(rows) + " rows" : "";
    $("run").disabled = !files.length; $("clear").disabled = !files.length;
    renderFiles(); renderCosts();
  }

  function renderFiles() {
    const card = $("files-card"); card.style.display = files.length ? "" : "none";
    const box = $("files");
    if (!files.length) { box.innerHTML = ""; return; }
    box.innerHTML = '<div class="' + P + '-list"><table><thead><tr><th>File</th><th>Rows</th><th>Kind</th><th>App</th><th>Detected as</th><th>Confidence</th></tr></thead><tbody>' +
      files.map((f, i) => "<tr><td>" + esc(f.name) + '</td><td>' + num(f.rowCount) + '</td><td><select data-kind="' + i + '">' +
        KINDS.concat(f.kind === "unknown" ? ["unknown"] : []).map((k) => '<option value="' + k + '"' + (f.kind === k ? " selected" : "") + ">" + esc(KIND_LABEL[k]) + "</option>").join("") +
        '</select></td><td>' + (f.kind === "saas" ? '<input data-app="' + i + '" type="text" value="' + esc(f.app || "") + '" placeholder="App name">' : esc(f.app || "")) +
        "</td><td>" + esc(f.vendor && f.vendor !== "generic" ? f.vendor : (f.kind === "unknown" ? "unrecognised headers" : "generic " + (KIND_LABEL[f.kind] || "").toLowerCase())) +
        "</td><td>" + pill("conf-" + f.confidence, f.confidence) + "</td></tr>" +
        (f.confidence !== "high" && MAP_FIELDS[f.kind] ? '<tr><td colspan="6"><div class="' + P + '-help">Column mapping for ' + esc(f.name) + ' (headers detected automatically; override where wrong)</div><div class="' + P + '-map">' +
          MAP_FIELDS[f.kind].map((k) => '<div><label>' + esc(FIELD_LABEL[k] || k) + '</label><select data-map="' + i + '" data-key="' + k + '"><option value="">(auto)</option>' +
            f.headers.map((h) => '<option value="' + esc(h) + '"' + ((f.columns || {})[k] === h ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>").join("") + "</div></td></tr>" : "")).join("") +
      "</tbody></table></div>";
    box.querySelectorAll("[data-kind]").forEach((el) => el.addEventListener("change", () => {
      const f = files[Number(el.dataset.kind)]; f.kind = el.value; f.confidence = "medium"; f.columns = {};
      if (f.kind === "saas" && !f.app) f.app = f.name.replace(/\.[a-z0-9]+$/i, "");
      renderFiles(); renderCosts();
    }));
    box.querySelectorAll("[data-app]").forEach((el) => el.addEventListener("change", () => { files[Number(el.dataset.app)].app = el.value.trim() || "SaaS app"; renderCosts(); }));
    box.querySelectorAll("[data-map]").forEach((el) => el.addEventListener("change", () => {
      const f = files[Number(el.dataset.map)]; f.columns = f.columns || {};
      if (el.value) f.columns[el.dataset.key] = el.value; else delete f.columns[el.dataset.key];
    }));
  }

  function renderCosts() {
    const apps = [...new Set(files.filter((f) => f.kind === "saas").map((f) => f.app || "SaaS app"))].sort();
    const card = $("costs-card"); card.style.display = apps.length ? "" : "none";
    const prev = costs();
    $("costs").innerHTML = apps.map((a) => '<div class="' + P + '-field"><label>' + esc(a) + '</label><input data-cost="' + esc(a) + '" type="number" min="0" step="0.01" placeholder="optional" value="' + (prev[a] != null ? esc(prev[a]) : "") + '"></div>').join("");
  }
  function costs() {
    const out = {};
    main.querySelectorAll("[data-cost]").forEach((el) => { const n = Number(el.value); if (el.value !== "" && Number.isFinite(n) && n > 0) out[el.dataset.cost] = n; });
    return out;
  }

  mountDropzone($("drop"), {
    maxBytes: 50 * 1024 * 1024, maxFiles: 25, multiple: true,
    label: "Drop every export here (HR roster, IdP users, SaaS user lists, devices), paste, or browse",
    onFiles: async (dropped) => {
      const inputs = [];
      for (const f of dropped) inputs.push({ name: f.name, text: await f.text() });
      const parsed = parseInput(inputs);
      const good = parsed.files.filter((f) => f.rowCount);
      if (!good.length) { toast("No rows found in the dropped file(s)", "error"); return; }
      for (const s of parsed.skipped) if (s.check === "parse") toast(s.reason, "warning");
      const merged = isExample ? [] : files.filter((f) => !good.some((g) => g.name === f.name));
      setFiles(merged.concat(good), false);
      toast("Loaded " + good.length + " file(s): " + good.map((f) => KIND_LABEL[f.kind] + (f.app ? " (" + f.app + ")" : "")).join(", "));
    },
  });

  $("clear").addEventListener("click", () => { setFiles([], false); });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    const parsed = parseInput(ex.files);
    setFiles(parsed.files, true);
    toast("Synthetic example loaded: " + parsed.files.length + " files. Press Analyze.");
  });

  function opts() {
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (el.value !== "" && Number.isFinite(n)) o[el.dataset.opt] = n; });
    const nowV = $("now").value; if (nowV) o.now = nowV + "T23:59:59Z";
    o.allowDomains = $("allow").value.split(/[,\s;]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
    o.licenseCostMonthly = costs();
    return o;
  }

  $("run").addEventListener("click", async () => {
    const prog = $("prog"), bar = prog.firstElementChild;
    prog.style.display = "block"; bar.style.width = "0%"; $("run").disabled = true;
    try {
      const payload = files.map((f) => ({ name: f.name, kind: f.kind, vendor: f.vendor, app: f.app, confidence: f.confidence, headers: f.headers, rows: f.rows, rowCount: f.rowCount, text: f.text, isJson: f.isJson, columns: f.columns || {} }));
      result = await runInWorker(ENGINE, "analyze", [{ files: payload }, opts()], {
        onProgress: (i, n) => { bar.style.width = (n ? Math.round(i / n * 100) : 0) + "%"; },
      });
      tab = "findings"; sort = { key: "severity", dir: "desc" }; search = "";
      render(result);
      toast(result.findings.length + " finding(s) across " + result.summary.people + " people and " + result.summary.apps + " app(s)", result.findings.some((f) => f.severity === "critical") ? "warning" : "success");
    } catch (e) {
      toast("Analysis failed: " + (e && e.message || e), "error");
    } finally {
      prog.style.display = "none"; $("run").disabled = !files.length;
    }
  });

  // ---------------------------------------------------------------- results
  function render(r) {
    const s = r.summary;
    $("kpis").innerHTML = kpi(num(s.people), "people in HR") + kpi(num(s.leavers), "leavers") + kpi(num(s.leaversStillActive), "leavers still active", s.leaversStillActive > 0) +
      kpi(num(s.appsWithLeakage) + " / " + num(s.apps), "apps with leakage", s.appsWithLeakage > 0) + kpi(s.medianHoursToDisable == null ? "n/a" : num(s.medianHoursToDisable) + " h", "median time to disable") +
      kpi(num(s.orphans), "orphan SaaS accounts", s.orphans > 0) + kpi(s.licenseWasteMonthly != null ? num(s.licenseWasteMonthly) + " / mo (" + num(s.licenseWasteSeats) + " seats)" : num(s.licenseWasteSeats) + " seats", "licence waste") +
      kpi(num(r.findings.length), "findings") + kpi((s.bySeverity.critical || 0) + " / " + (s.bySeverity.high || 0), "critical / high", (s.bySeverity.critical || 0) > 0);
    $("skipped").innerHTML = r.skipped.length ? "<b>Skipped checks</b> (missing columns or files, never guessed): " + r.skipped.map((x) => esc(x.check) + " - " + esc(x.reason)).join("; ") : "";
    const ex = $("exports");
    ex.innerHTML = '<button class="' + P + '-btn" data-x="csv">Findings CSV</button><button class="' + P + '-btn" data-x="json">Full JSON</button><button class="' + P + '-btn" data-x="txt">Summary TXT</button>' +
      '<button class="' + P + '-btn" data-x="work">Offboarding worklist CSV</button><button class="' + P + '-btn" data-x="sla">SLA report CSV</button>';
    const stamp = fileStamp();
    ex.querySelector('[data-x="csv"]').addEventListener("click", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    ex.querySelector('[data-x="json"]').addEventListener("click", () => download(TOOL_ID + "-" + stamp + ".json", toJson(r), "application/json"));
    ex.querySelector('[data-x="txt"]').addEventListener("click", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r), "text/plain"));
    ex.querySelector('[data-x="work"]').addEventListener("click", () => download(TOOL_ID + "-offboarding-worklist-" + stamp + ".csv", worklistCsv(r), "text/csv"));
    ex.querySelector('[data-x="sla"]').addEventListener("click", () => download(TOOL_ID + "-sla-report-" + stamp + ".csv", slaCsv(r), "text/csv"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: files.map((f) => f.name).join(", ") });
    const tabs = $("tabs"); tabs.style.display = "";
    tabs.querySelectorAll("[data-tab]").forEach((b) => { b.onclick = () => { tab = b.dataset.tab; renderView(r); }; });
    $("drawer").style.display = "none";
    renderView(r);
  }

  function renderView(r) {
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.classList.toggle("on", b.dataset.tab === tab));
    const v = $("view");
    if (tab === "findings") renderFindings(r, v);
    else if (tab === "people") renderPeople(r, v);
    else if (tab === "apps") renderApps(r, v);
    else renderSla(r, v);
  }

  function sortable(ths, onSort) {
    ths.forEach((th) => {
      const k = th.dataset.sort; if (!k) return;
      th.classList.toggle("asc", sort.key === k && sort.dir === "asc"); th.classList.toggle("desc", sort.key === k && sort.dir === "desc");
      th.addEventListener("click", () => { sort = { key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" }; onSort(); });
    });
  }
  const by = (get) => (a, b) => { const x = get(a), y = get(b); const c = x < y ? -1 : x > y ? 1 : 0; return sort.dir === "asc" ? c : -c; };

  function renderFindings(r, v) {
    if (!r.findings.length) { v.innerHTML = '<div class="' + P + '-list"><div class="' + P + '-empty">No findings for the current thresholds and files.</div></div>'; return; }
    const getters = { severity: (f) => SEV_RANK[f.severity] || 0, title: (f) => f.title.toLowerCase(), confidence: (f) => f.confidence, category: (f) => f.category, evidence: (f) => f.evidenceCount || 0 };
    const list = r.findings.map((f, i) => ({ f, i })).sort((a, b) => by((x) => getters[sort.key] ? getters[sort.key](x.f) : 0)(a, b) || (SEV_RANK[b.f.severity] - SEV_RANK[a.f.severity]));
    v.innerHTML = '<div class="' + P + '-list"><table><thead><tr><th data-sort="severity">Severity</th><th data-sort="title">Finding</th><th data-sort="category">Category</th><th data-sort="confidence">Confidence</th><th>Controls</th><th data-sort="evidence">Evidence</th></tr></thead><tbody>' +
      list.map(({ f, i }) => '<tr data-i="' + i + '"><td>' + pill(f.severity, f.severity) + "</td><td><b>" + esc(f.title) + "</b><div>" + esc(f.description) + '</div></td><td>' + esc(f.category) + '</td><td class="' + P + '-conf">' + esc(f.confidence) + "</td><td>" +
        (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</td><td>" + num(f.evidenceCount) + "</td></tr>").join("") + "</tbody></table></div>";
    sortable(v.querySelectorAll("th[data-sort]"), () => renderFindings(r, v));
    v.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => {
      v.querySelectorAll("tr.sel").forEach((x) => x.classList.remove("sel")); tr.classList.add("sel");
      const f = r.findings[Number(tr.dataset.i)];
      const d = $("drawer"); d.style.display = "block";
      d.innerHTML = '<div class="' + P + '-card"><div class="' + P + '-hd"><h2 style="margin:0">' + esc(f.title) + "</h2>" + pill(f.severity, f.severity) + '<span class="' + P + '-conf">' + esc(f.confidence) + '</span></div><p class="' + P + '-help">' + esc(f.description) + "</p><p><b>Recommendation.</b> " + esc(f.recommendation) + "</p><div>" +
        (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + '</div><p class="' + P + '-help">Evidence: ' + num(f.evidenceCount) + " row(s)" + (f.evidenceCount > (f.evidence || []).length ? ", first " + (f.evidence || []).length + " shown" : "") + '</p><div class="' + P + '-list">' + evidenceTable(f.evidence) + "</div></div>";
      d.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }));
  }

  function renderPeople(r, v) {
    const all = r.tables.people || [];
    const q = search.toLowerCase();
    const rows = all.filter((p) => !q || [p.person, p.email, p.employeeId, p.department, p.hrStatus, p.idpStatus, ...(p.flags || []), ...(p.apps || []).map((a) => a.app)].join(" ").toLowerCase().includes(q));
    const getters = { person: (p) => p.person.toLowerCase(), hrStatus: (p) => p.hrStatus, hireDate: (p) => p.hireDate || "", termDate: (p) => p.termDate || "", idpStatus: (p) => p.idpStatus, lastSignIn: (p) => p.lastSignIn || "", apps: (p) => p.apps.length, flags: (p) => p.flags.length };
    const sk = getters[sort.key] ? sort.key : "person";
    rows.sort(by(getters[sk]));
    v.innerHTML = '<div class="' + P + '-row" style="margin:0 0 10px"><input class="' + P + "-in " + P + '-search" id="' + P + '-search" type="search" placeholder="Search people" value="' + esc(search) + '"><span class="' + P + '-skip">' + num(rows.length) + " of " + num(all.length) + " people</span></div>" +
      '<div class="' + P + '-list"><table><thead><tr><th data-sort="person">Person</th><th data-sort="hrStatus">HR status</th><th data-sort="hireDate">Hired</th><th data-sort="termDate">Terminated</th><th data-sort="idpStatus">IdP</th><th data-sort="lastSignIn">Last sign-in</th><th data-sort="apps">Apps</th><th>Devices</th><th data-sort="flags">Flags</th></tr></thead><tbody>' +
      (rows.length ? rows.map((p) => "<tr><td><b>" + esc(p.person) + "</b><div class=\"" + P + "-help\" style=\"margin:0\">" + esc(p.email || p.employeeId) + (p.department ? " - " + esc(p.department) : "") + "</div></td><td>" + esc(p.hrStatus) + "</td><td>" + esc(p.hireDate || "-") + "</td><td>" + esc(p.termDate || "-") + "</td><td>" + esc(p.idpStatus || "-") + "</td><td>" + esc(p.lastSignIn || "-") + "</td><td>" +
        (p.apps.length ? p.apps.map((a) => '<span class="' + P + '-chip">' + esc(a.app + ": " + a.status + (a.licensed === true ? ", licensed" : "")) + "</span>").join("") : "-") + "</td><td>" + (p.devices.length ? esc(p.devices.join(", ")) : "-") + "</td><td>" +
        (p.flags.length ? p.flags.map((f) => '<span class="' + P + '-flag">' + esc(f) + "</span>").join("") : "") + "</td></tr>").join("") : '<tr><td colspan="9" class="' + P + '-empty">No people match.</td></tr>') + "</tbody></table></div>";
    sortable(v.querySelectorAll("th[data-sort]"), () => renderPeople(r, v));
    const inp = v.querySelector("#" + P + "-search");
    inp.addEventListener("input", () => { search = inp.value; const pos = inp.selectionStart; renderPeople(r, v); const n = v.querySelector("#" + P + "-search"); n.focus(); try { n.setSelectionRange(pos, pos); } catch (_) {} });
  }

  function renderApps(r, v) {
    const rows = r.tables.apps || [];
    if (!rows.length) { v.innerHTML = '<div class="' + P + '-list"><div class="' + P + '-empty">No SaaS user lists were loaded.</div></div>'; return; }
    v.innerHTML = '<div class="' + P + '-list"><table><thead><tr><th>App</th><th>Source file</th><th>Accounts</th><th>Active</th><th>Active leavers</th><th>Orphans</th><th>External</th><th>Licensed waste</th><th>Monthly waste</th></tr></thead><tbody>' +
      rows.map((a) => "<tr><td><b>" + esc(a.app) + "</b></td><td>" + esc(a.file) + "</td><td>" + num(a.total) + "</td><td>" + num(a.active) + "</td><td>" + (a.activeLeavers ? '<span class="' + P + '-flag">' + num(a.activeLeavers) + "</span>" : "0") + "</td><td>" + num(a.orphans) + "</td><td>" + num(a.external) + "</td><td>" + num(a.licensedWaste) + "</td><td>" + (a.monthlyWaste == null ? "enter a cost" : num(a.monthlyWaste)) + "</td></tr>").join("") + "</tbody></table></div>";
  }

  function renderSla(r, v) {
    const rows = r.tables.sla || [];
    if (!rows.length) { v.innerHTML = '<div class="' + P + '-list"><div class="' + P + '-empty">No leavers with an IdP account to measure.</div></div>'; return; }
    v.innerHTML = '<p class="' + P + '-help">Hours from the HR termination date to the IdP disable (Okta statusChanged, Entra deletedDateTime). Leavers still enabled count the hours up to the as-of date. SLA: ' + esc(r.meta.options.disableSlaHours) + " h.</p>" +
      '<div class="' + P + '-list"><table><thead><tr><th>Leaver</th><th>Terminated</th><th>Disabled at</th><th>Hours</th><th>Breach</th><th>Status</th><th>IdP</th></tr></thead><tbody>' +
      rows.map((s) => "<tr><td>" + esc(s.leaver) + "</td><td>" + esc((s.terminated || "").slice(0, 16).replace("T", " ")) + "</td><td>" + esc(s.disabledAt ? s.disabledAt.slice(0, 16).replace("T", " ") : "-") + "</td><td>" + (s.hours == null ? "-" : num(s.hours)) + "</td><td>" + (s.breach == null ? "-" : s.breach ? '<span class="' + P + '-flag">yes</span>' : "no") + "</td><td>" + esc(s.status) + "</td><td>" + esc(s.idp) + "</td></tr>").join("") + "</tbody></table></div>";
  }

  function summaryText(r) {
    const s = r.summary, sum = summarize(r.findings);
    return ["Lifecycle & Offboarding Verifier - summary", "As of: " + r.meta.now, "Files: " + (r.tables.files || []).map((f) => f.file + " [" + f.kind + (f.app ? " " + f.app : "") + "]").join(", "),
      "People in HR: " + s.people + "  Leavers: " + s.leavers + "  Leavers still active: " + s.leaversStillActive, "Apps: " + s.apps + "  Apps with leakage: " + s.appsWithLeakage,
      "Median hours to disable: " + (s.medianHoursToDisable == null ? "n/a" : s.medianHoursToDisable) + "  SLA breaches: " + s.slaBreaches,
      "Orphan SaaS accounts: " + s.orphans + "  External accounts: " + s.external, "Licence waste: " + s.licenseWasteSeats + " seats" + (s.licenseWasteMonthly != null ? " (" + s.licenseWasteMonthly + " / month at entered prices)" : ""),
      "Findings: " + sum.total + "  by severity: " + JSON.stringify(sum.bySeverity) + "  by confidence: " + JSON.stringify(sum.byConfidence), "",
      ...r.findings.map((f) => "- [" + f.severity + " / " + f.confidence + "] " + f.title + " (" + f.evidenceCount + " evidence) - " + f.recommendation),
      "", r.skipped.length ? "Skipped checks: " + r.skipped.map((x) => x.check + " (" + x.reason + ")").join("; ") : "All checks ran.",
    ].join("\n");
  }
}

function field(key, label, value, help) {
  return '<div class="' + P + '-field"><label for="' + P + "-opt-" + key + '">' + esc(label) + '</label><input id="' + P + "-opt-" + key + '" data-opt="' + esc(key) + '" type="number" min="0" value="' + esc(value) + '"><small>' + esc(help) + "</small></div>";
}
