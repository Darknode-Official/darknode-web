// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Access Review — periodic user-access review (SOX ITGC, ISO 27001 A.5.18,
// SOC 2 CC6) done in the browser: an HR roster is reconciled against a
// directory / IdP export (Entra ID, Google Workspace, Okta, Active Directory or a
// generic CSV). The engine (access-review-engine.js) is pure and tested; this
// file is the review packet UI: KPIs, findings, the full reconciliation table
// with per-row reviewer decisions (kept in localStorage, keyed by a hash of the
// two inputs), and CSV / JSON / attestation exports.
//
// Large exports run in a module Worker so a 50k-row tenant does not freeze the
// tab; the reconciliation table is virtualised.
//
//   renderAccessReview(main) -> void

import {
  parseHR, parseDirectory, analyze, datasetHash, exampleData,
  toReviewCSV, toFindingsCSV, toReviewJSON, attestationText, summarizeDecisions,
  DEFAULT_OPTIONS, DECISIONS, SEVERITY_RANK, FINDING_TYPES,
} from "/js/identity/access-review-engine.js?v=20261013m";

const ENGINE_URL = new URL("./access-review-engine.js?v=20261013m", import.meta.url).href;

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.showToast || (() => {}))(m); } catch (_) {} };
const confirmDlg = (title, desc, opts) => (typeof window.dnConfirm === "function" ? window.dnConfirm(title, desc, opts) : Promise.resolve(true));
const fmtDate = (t) => (t == null ? "never" : new Date(t).toISOString().slice(0, 10));
const num = (n) => Number(n || 0).toLocaleString();

let injected = false;
function injectStyle() {
  if (injected || document.getElementById("acr-css")) { injected = true; return; }
  injected = true;
  const st = document.createElement("style"); st.id = "acr-css";
  st.textContent = `
  .acr{font-size:14px;line-height:1.5;color:var(--txt,#1a2230)}
  .acr .acr-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .acr h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .acr .acr-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--mut,#667085);border:1px solid var(--line,#e6e8ee);padding:2px 9px;border-radius:999px}
  .acr .acr-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:80ch}
  .acr .acr-note{border:1px solid var(--line,#e6e8ee);border-left:3px solid var(--mut,#667085);border-radius:8px;padding:11px 14px;font-size:.84rem;margin-bottom:16px;background:var(--card,#fff)}
  .acr .acr-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px}
  .acr h3{font-size:.95rem;margin:0 0 6px}
  .acr .acr-help{color:var(--mut,#667085);font-size:.8rem;margin:0 0 8px;overflow-wrap:anywhere}
  .acr .acr-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  @media(max-width:900px){.acr .acr-grid{grid-template-columns:1fr}}
  .acr textarea{width:100%;min-height:170px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;line-height:1.5;padding:10px 12px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--card,#fff);color:var(--txt,#1a2230);box-sizing:border-box}
  .acr input[type=text],.acr input[type=number],.acr select{font:inherit;font-size:.86rem;padding:6px 9px;border:1px solid var(--line,#d7dbe3);border-radius:7px;background:var(--card,#fff);color:var(--txt,#1a2230);box-sizing:border-box}
  .acr input[type=number]{width:84px}
  .acr .acr-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:10px}
  .acr .acr-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--txt,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .acr .acr-btn:hover{border-color:var(--mut,#667085)}
  .acr .acr-btn.pri{background:var(--acc,#1a2230);border-color:var(--acc,#1a2230);color:#fff}
  .acr .acr-btn:disabled{opacity:.55;cursor:default}
  .acr .acr-file{font-size:.78rem;color:var(--mut,#667085)}
  .acr .acr-opts{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px 14px;margin-top:8px}
  .acr .acr-opt label{display:block;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#667085);font-weight:700;margin-bottom:3px}
  .acr .acr-opt .acr-help{margin:3px 0 0;font-size:.74rem}
  .acr .acr-opt.wide{grid-column:span 2}
  .acr .acr-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin:0 0 14px}
  .acr .acr-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px}
  .acr .acr-kpi b{display:block;font-size:1.45rem;line-height:1.2;font-variant-numeric:tabular-nums}
  .acr .acr-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .acr .acr-cov{display:flex;flex-wrap:wrap;gap:6px 10px;font-size:.78rem;margin-top:6px}
  .acr .acr-cov span{border:1px solid var(--line,#e6e8ee);border-radius:6px;padding:1px 8px}
  .acr .acr-cov span.miss{color:var(--mut,#667085);text-decoration:line-through}
  .acr .acr-warn{font-size:.8rem;color:#8a6d00;margin-top:6px}
  .acr .acr-sev-critical{color:#b00020;font-weight:700}
  .acr .acr-sev-high{color:#c0501b;font-weight:700}
  .acr .acr-sev-medium{color:#8a6d00;font-weight:700}
  .acr .acr-sev-low{color:var(--mut,#667085);font-weight:700}
  .acr .acr-sev-info{color:var(--mut,#667085);font-weight:600}
  .acr .acr-good{color:#1b7f4d}
  .acr .acr-tbl{border:1px solid var(--line,#e6e8ee);border-radius:10px;overflow:auto}
  .acr table{width:100%;border-collapse:collapse;font-size:.84rem}
  .acr th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 10px;background:var(--card,#fff);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;position:sticky;top:0;z-index:1}
  .acr th.sortable{cursor:pointer;user-select:none}
  .acr th.sorted::after{content:" \\2193";opacity:.7}
  .acr th.sorted.asc::after{content:" \\2191"}
  .acr td{padding:7px 10px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .acr .acr-f{cursor:pointer}
  .acr .acr-f:hover td{background:var(--bg,#f7f8fb)}
  .acr .acr-fd td{background:var(--bg,#f9fafb);font-size:.82rem}
  .acr .acr-ev{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;margin:6px 0}
  .acr .acr-ev dt{color:var(--mut,#667085)}
  .acr .acr-ev dd{margin:0}
  .acr .acr-ctl{font-size:.76rem;color:var(--mut,#667085)}
  .acr .acr-ctl code{font-family:ui-monospace,Menlo,monospace;font-size:.74rem;border:1px solid var(--line,#e6e8ee);border-radius:4px;padding:0 5px;margin-right:4px}
  .acr .acr-mono{font-family:ui-monospace,Menlo,monospace;font-size:.8rem}
  .acr .acr-dim{color:var(--mut,#667085)}
  .acr .acr-empty{padding:26px;text-align:center;color:var(--mut,#667085)}
  .acr .acr-vhead table{table-layout:fixed}
  .acr .acr-vscroll{max-height:560px;overflow:auto;position:relative;border-top:0}
  .acr .acr-vscroll table{table-layout:fixed;position:absolute;left:0;top:0;width:100%}
  .acr .acr-vscroll td{height:46px;padding:4px 10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;vertical-align:middle}
  .acr .acr-vscroll select{width:100%;padding:4px 6px;font-size:.8rem}
  .acr .acr-vscroll input[type=text]{width:100%;padding:4px 7px;font-size:.8rem}
  .acr .acr-disp-Disable{color:#b00020;font-weight:700}
  .acr .acr-disp-Investigate{color:#c0501b;font-weight:700}
  .acr .acr-disp-Confirm{color:#8a6d00;font-weight:700}
  .acr .acr-disp-Keep{color:#1b7f4d;font-weight:700}
  .acr .acr-sum{font-size:.82rem;color:var(--mut,#667085);margin-top:8px}
  .acr pre.acr-att{white-space:pre-wrap;font-family:ui-monospace,Menlo,monospace;font-size:.78rem;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:12px;background:var(--card,#fff);max-height:320px;overflow:auto;margin:10px 0}
  .acr .acr-spin{display:inline-block;width:14px;height:14px;border:2px solid var(--line,#d7dbe3);border-top-color:var(--txt,#1a2230);border-radius:50%;animation:acrSpin .7s linear infinite;vertical-align:-2px;margin-right:6px}
  @keyframes acrSpin{to{transform:rotate(360deg)}}
  .acr .acr-cnt{font-size:.76rem;color:var(--mut,#667085);margin-left:auto}
  `;
  document.head.appendChild(st);
}

function download(name, text, type) {
  const b = new Blob([text], { type: type || "text/plain" });
  const u = URL.createObjectURL(b); const a = document.createElement("a");
  a.href = u; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(u), 1000);
}

// Run parse + analyze in a module Worker; fall back to the main thread when
// module workers are unavailable. The worker strips raw rows before posting.
function runAnalysis(hrText, dirText, opts) {
  const sync = () => {
    const hr = parseHR(hrText, opts); const dir = parseDirectory(dirText, opts);
    const r = analyze(hr, dir, opts);
    return { result: r, hr: { coverage: hr.coverage, rowCount: hr.rowCount }, dir: { source: dir.source, coverage: dir.coverage, rowCount: dir.rowCount, format: dir.format } };
  };
  if (typeof Worker === "undefined" || typeof Blob === "undefined") return Promise.resolve(sync());
  return new Promise((resolve) => {
    let w = null, done = false;
    const fallback = () => { if (done) return; done = true; try { w && w.terminate(); } catch (_) {} resolve(sync()); };
    try {
      const code = `import { parseHR, parseDirectory, analyze } from ${JSON.stringify(ENGINE_URL)};
self.onmessage = (e) => {
  try {
    const { hrText, dirText, opts } = e.data;
    const hr = parseHR(hrText, opts); const dir = parseDirectory(dirText, opts);
    const r = analyze(hr, dir, opts);
    for (const row of r.rows) { row.account.raw = undefined; if (row.employee) row.employee.raw = undefined; }
    for (const e2 of r.hrNoAccount) e2.raw = undefined;
    self.postMessage({ ok: true, result: r, hr: { coverage: hr.coverage, rowCount: hr.rowCount }, dir: { source: dir.source, coverage: dir.coverage, rowCount: dir.rowCount, format: dir.format } });
  } catch (err) { self.postMessage({ ok: false, error: String(err && err.message || err) }); }
};`;
      const url = URL.createObjectURL(new Blob([code], { type: "text/javascript" }));
      w = new Worker(url, { type: "module" });
      w.onmessage = (e) => { if (done) return; done = true; URL.revokeObjectURL(url); w.terminate(); if (e.data.ok) resolve(e.data); else resolve({ error: e.data.error }); };
      w.onerror = () => { URL.revokeObjectURL(url); fallback(); };
      w.postMessage({ hrText, dirText, opts });
    } catch (_) { fallback(); }
  });
}

export function renderAccessReview(main) {
  injectStyle();
  main.innerHTML = `
  <div class="acr">
    <div class="acr-hd"><h1>Access Review</h1><span class="acr-tag">Identity</span></div>
    <div class="acr-sub">Reconcile an HR roster against a directory or IdP export to run the periodic user-access review that SOX,
      ISO 27001 (A.5.18) and SOC 2 ask for. Every account gets a disposition, a reviewer decision and a note; the result exports
      as a review packet (CSV, JSON, attestation). Both files stay in your browser.</div>

    <div class="acr-note"><b>What this does and does not do.</b> It compares two exports you provide and applies fixed rules
      (leaver still enabled, orphan account, stale, admin without MFA, guest past window, duplicate, password hygiene).
      It does not connect to your IdP and does not change anything. Fuzzy name matches are shown for confirmation, never merged
      silently. The reviewer owns every Keep or Disable decision.</div>

    <div class="acr-grid">
      <div class="acr-card">
        <h3>HR roster (CSV)</h3>
        <p class="acr-help">From Workday, BambooHR, SAP, a payroll export or a spreadsheet. Needed: a name or email column.
          Useful: employee id, employment status, termination date.</p>
        <textarea id="acrHr" placeholder="Paste roster CSV" spellcheck="false"></textarea>
        <div class="acr-row">
          <label class="acr-btn">Load file<input type="file" id="acrHrFile" accept=".csv,.tsv,.txt,text/csv" hidden></label>
          <span class="acr-file" id="acrHrName"></span>
        </div>
      </div>
      <div class="acr-card">
        <h3>Directory or IdP export (CSV or JSON)</h3>
        <p class="acr-help">Entra ID users export, Google Workspace user list, Okta users (CSV or API JSON), or an Active
          Directory Get-ADUser export. The source is detected from the headers.</p>
        <textarea id="acrDir" placeholder="Paste directory export" spellcheck="false"></textarea>
        <div class="acr-row">
          <label class="acr-btn">Load file<input type="file" id="acrDirFile" accept=".csv,.tsv,.txt,.json,text/csv,application/json" hidden></label>
          <span class="acr-file" id="acrDirName"></span>
        </div>
      </div>
    </div>

    <div class="acr-card">
      <h3>Review parameters</h3>
      <div class="acr-opts">
        <div class="acr-opt"><label for="acrGrace">Leaver grace (days)</label><input type="number" id="acrGrace" min="0" value="${DEFAULT_OPTIONS.graceDays}"><p class="acr-help">Days after the HR end date before an enabled account is a finding.</p></div>
        <div class="acr-opt"><label for="acrStale">Dormancy (days)</label><input type="number" id="acrStale" min="1" value="${DEFAULT_OPTIONS.staleDays}"><p class="acr-help">No sign-in for this long is stale. CIS 5.3 uses 45.</p></div>
        <div class="acr-opt"><label for="acrGuest">Guest window (days)</label><input type="number" id="acrGuest" min="1" value="${DEFAULT_OPTIONS.guestDays}"><p class="acr-help">Guests older than this need sponsor re-approval.</p></div>
        <div class="acr-opt"><label for="acrAdminN">Max admins</label><input type="number" id="acrAdminN" min="1" value="${DEFAULT_OPTIONS.adminMaxCount}"><p class="acr-help">Standing admin accounts above this count are flagged.</p></div>
        <div class="acr-opt"><label for="acrAdminP">Max admins (%)</label><input type="number" id="acrAdminP" min="1" max="100" value="${DEFAULT_OPTIONS.adminMaxPct}"><p class="acr-help">Share of enabled members; applied from 20 users up.</p></div>
        <div class="acr-opt"><label for="acrPwd">Password age (days)</label><input type="number" id="acrPwd" min="30" value="${DEFAULT_OPTIONS.pwdAgeDays}"><p class="acr-help">Only used when the export has pwdLastSet.</p></div>
        <div class="acr-opt wide"><label for="acrAlias">Alias domains</label><input type="text" id="acrAlias" placeholder="Comma-separated domains" style="width:100%"><p class="acr-help">Comma-separated domains treated as the same organisation when matching emails. Plus-tags are always stripped.</p></div>
      </div>
      <div class="acr-row">
        <button class="acr-btn pri" id="acrRun">Run review</button>
        <button class="acr-btn" id="acrExample">Load example (synthetic data)</button>
        <button class="acr-btn" id="acrClear">Clear</button>
        <span class="acr-file" id="acrStatus"></span>
      </div>
    </div>

    <div id="acrOut"></div>
  </div>`;

  const $ = (id) => main.querySelector("#" + id);
  const hrTA = $("acrHr"), dirTA = $("acrDir"), out = $("acrOut");

  function wireFile(inputId, ta, nameId) {
    $(inputId).addEventListener("change", (e) => {
      const f = e.target.files && e.target.files[0]; if (!f) return;
      const fr = new FileReader();
      fr.onload = () => { ta.value = String(fr.result || ""); $(nameId).textContent = `${f.name} (${(f.size / 1024).toFixed(0)} KB)`; };
      fr.onerror = () => toast("Could not read file");
      fr.readAsText(f);
    });
  }
  wireFile("acrHrFile", hrTA, "acrHrName");
  wireFile("acrDirFile", dirTA, "acrDirName");

  $("acrExample").addEventListener("click", () => {
    const ex = exampleData();
    hrTA.value = ex.hr; dirTA.value = ex.dir;
    $("acrHrName").textContent = "synthetic example"; $("acrDirName").textContent = "synthetic example (Entra ID shape)";
    toast("Synthetic example loaded. Run review to see the packet.");
  });
  $("acrClear").addEventListener("click", () => {
    hrTA.value = ""; dirTA.value = ""; $("acrHrName").textContent = ""; $("acrDirName").textContent = ""; out.innerHTML = ""; $("acrStatus").textContent = "";
  });
  $("acrRun").addEventListener("click", run);

  function readOpts() {
    const n = (id, d) => { const v = parseInt($(id).value, 10); return Number.isFinite(v) && v >= 0 ? v : d; };
    return {
      graceDays: n("acrGrace", DEFAULT_OPTIONS.graceDays), staleDays: n("acrStale", DEFAULT_OPTIONS.staleDays),
      guestDays: n("acrGuest", DEFAULT_OPTIONS.guestDays), adminMaxCount: n("acrAdminN", DEFAULT_OPTIONS.adminMaxCount),
      adminMaxPct: n("acrAdminP", DEFAULT_OPTIONS.adminMaxPct), pwdAgeDays: n("acrPwd", DEFAULT_OPTIONS.pwdAgeDays),
      aliasDomains: $("acrAlias").value.split(/[,\s]+/).map((s) => s.trim().toLowerCase()).filter(Boolean),
      now: Date.now(),
    };
  }

  // ---- state for the current packet ----
  let state = null; // { result, hash, decisions, meta }

  const lsKey = (hash) => "acr:decisions:" + hash;
  function loadDecisions(hash) { try { const d = JSON.parse(localStorage.getItem(lsKey(hash)) || "{}"); return d && typeof d === "object" ? d : {}; } catch (_) { return {}; } }
  let saveTimer = null;
  function saveDecisions() {
    if (!state) return;
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => { try { localStorage.setItem(lsKey(state.hash), JSON.stringify(state.decisions)); } catch (_) { toast("Could not save decisions locally (storage blocked)."); } }, 250);
  }

  async function run() {
    const hrText = hrTA.value, dirText = dirTA.value;
    if (!hrText.trim() || !dirText.trim()) { out.innerHTML = `<div class="acr-card acr-empty">Both inputs are needed: the HR roster and the directory export.</div>`; return; }
    const btn = $("acrRun"); btn.disabled = true;
    $("acrStatus").innerHTML = `<span class="acr-spin"></span>Reconciling`;
    out.innerHTML = "";
    const opts = readOpts();
    const t0 = performance.now();
    let res;
    try { res = await runAnalysis(hrText, dirText, opts); }
    catch (e) { res = { error: String((e && e.message) || e) }; }
    btn.disabled = false;
    if (!res || res.error) {
      $("acrStatus").textContent = "";
      out.innerHTML = `<div class="acr-card acr-empty">Could not parse the inputs.<br><span class="acr-help">${esc(res ? res.error : "unknown error")}</span></div>`;
      return;
    }
    const hash = datasetHash(hrText, dirText);
    const decisions = loadDecisions(hash);
    const restored = Object.keys(decisions).length;
    state = { result: res.result, hash, decisions, meta: { reviewer: "", date: new Date().toISOString().slice(0, 10) }, dirInfo: res.dir, hrInfo: res.hr };
    $("acrStatus").textContent = `${num(res.result.rows.length)} accounts, ${num(res.hr.rowCount)} roster rows, ${Math.round(performance.now() - t0)} ms`;
    if (restored) toast(`Restored ${restored} decision(s) saved earlier for this exact dataset.`);
    renderPacket();
  }

  // ---------------------------------------------------------------- packet
  function renderPacket() {
    const { result: r, dirInfo, hrInfo } = state;
    const k = r.kpis;
    const covPill = (label, on) => `<span class="${on ? "" : "miss"}">${esc(label)}</span>`;
    const dcov = dirInfo.coverage, hcov = hrInfo.coverage;
    const sourceName = { entra: "Microsoft Entra ID", google: "Google Workspace", okta: "Okta", ad: "Active Directory", generic: "generic CSV" }[dirInfo.source] || dirInfo.source;
    out.innerHTML = `
      <div class="acr-card">
        <h3>Inputs recognised</h3>
        <div class="acr-help">Directory: <b>${esc(sourceName)}</b> (${esc(dirInfo.format)}, ${num(dirInfo.rowCount)} rows). Attributes available (struck through = missing, the related checks are skipped):</div>
        <div class="acr-cov">${covPill("email", dcov.email)}${covPill("enabled", dcov.enabled)}${covPill("user type", dcov.type)}${covPill("admin roles", dcov.admin)}${covPill("MFA", dcov.mfa)}${covPill("last sign-in", dcov.lastSignIn)}${covPill("created", dcov.created)}${covPill("employee id", dcov.employeeId)}${covPill("pwdLastSet", dcov.pwdLastSet)}${covPill("password never expires", dcov.pwdNeverExpires)}</div>
        <div class="acr-help" style="margin-top:8px">HR roster: ${num(hrInfo.rowCount)} rows.</div>
        <div class="acr-cov">${covPill("employee id", hcov.employeeId)}${covPill("name", hcov.name)}${covPill("email", hcov.email)}${covPill("status", hcov.status)}${covPill("end date", hcov.endDate)}${covPill("start date", hcov.startDate)}${covPill("department", hcov.dept)}</div>
        ${r.warnings.length ? `<div class="acr-warn">${r.warnings.map(esc).join("<br>")}</div>` : ""}
      </div>

      <div class="acr-kpis">
        ${kpi(k.accounts, "Accounts")}
        ${kpi(k.enabled, "Enabled")}
        ${kpi(k.matched, "Matched to roster")}
        ${kpi(k.fuzzy, "Name-only matches", k.fuzzy ? "acr-sev-medium" : "")}
        ${kpi(k.leaversEnabled, "Leavers enabled", k.leaversEnabled ? "acr-sev-critical" : "acr-good")}
        ${kpi(k.orphans, "Not on roster", k.orphans ? "acr-sev-high" : "acr-good")}
        ${kpi(k.admins, "Admins")}
        ${kpi(k.adminsNoMfa, "Admins without MFA", k.adminsNoMfa ? "acr-sev-critical" : (dcov.mfa ? "acr-good" : ""))}
        ${kpi(k.stale, "Stale", k.stale ? "acr-sev-medium" : (dcov.lastSignIn ? "acr-good" : ""))}
        ${kpi(k.guests, "Guests enabled")}
        ${kpi(k.hrNoAccount, "Employees without account")}
        ${kpi(k.bySeverity.critical, "Critical findings", k.bySeverity.critical ? "acr-sev-critical" : "acr-good")}
      </div>

      <div class="acr-card" id="acrFindCard">
        <div class="acr-row" style="margin:0 0 8px">
          <h3 style="margin:0">Findings <span class="acr-dim">(${num(r.findings.length)})</span></h3>
          <select id="acrFSev"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
          <select id="acrFType"><option value="">All types</option>${Object.keys(FINDING_TYPES).map((t) => `<option value="${t}">${esc(FINDING_TYPES[t].title)}</option>`).join("")}</select>
          <button class="acr-btn" id="acrFExp">Export findings (CSV)</button>
          <span class="acr-cnt" id="acrFCnt"></span>
        </div>
        <p class="acr-help">Click a row for evidence, the recommended action and control references. Confidence drops to "low" when a finding depends on a name-only match or on an assumed enabled state.</p>
        <div class="acr-tbl" id="acrFTbl"></div>
        <div class="acr-row" id="acrFMore"></div>
      </div>

      <div class="acr-card" id="acrRecCard">
        <div class="acr-row" style="margin:0 0 8px">
          <h3 style="margin:0">Reconciliation <span class="acr-dim">(${num(r.rows.length)} accounts)</span></h3>
          <input type="text" id="acrRQ" placeholder="Search account or name" style="min-width:200px">
          <select id="acrRDisp"><option value="">All dispositions</option><option>Disable</option><option>Investigate</option><option>Confirm match</option><option>Keep</option></select>
          <label style="font-size:.82rem"><input type="checkbox" id="acrRUnd"> undecided only</label>
          <button class="acr-btn" id="acrAccept">Accept suggestions for undecided</button>
          <button class="acr-btn" id="acrReset">Clear decisions</button>
          <span class="acr-cnt" id="acrRCnt"></span>
        </div>
        <p class="acr-help">Suggested disposition comes from the findings. Set the reviewer decision and a note per account; they are saved in this browser for this exact dataset (hash <span class="acr-mono">${esc(state.hash)}</span>).</p>
        <div class="acr-tbl acr-vhead" id="acrRHead"></div>
        <div class="acr-tbl acr-vscroll" id="acrRScroll"><div class="acr-vspace"></div><table><tbody></tbody></table></div>
        <div class="acr-sum" id="acrRSum"></div>
      </div>

      <div class="acr-card">
        <h3>Sign-off</h3>
        <p class="acr-help">Type the reviewer name, then export the packet. The attestation records counts, parameters and the dataset hash so an auditor can tie it to the exports.</p>
        <div class="acr-row" style="margin-top:0">
          <input type="text" id="acrReviewer" placeholder="Reviewer name" style="min-width:220px">
          <input type="text" id="acrDate" value="${esc(state.meta.date)}" style="width:130px" placeholder="YYYY-MM-DD">
          <input type="text" id="acrScope" placeholder="Scope (optional)" style="min-width:220px">
        </div>
        <p class="acr-help" style="margin-top:6px">Scope example: "Q3 FY26 Entra ID production tenant, all enabled users".</p>
        <pre class="acr-att" id="acrAtt"></pre>
        <div class="acr-row" style="margin-top:0">
          <button class="acr-btn pri" id="acrExpCsv">Export reconciliation (CSV)</button>
          <button class="acr-btn" id="acrExpJson">Export packet (JSON)</button>
          <button class="acr-btn" id="acrExpTxt">Export attestation (TXT)</button>
        </div>
      </div>`;

    // findings
    const fState = { sev: "", type: "", sort: "severity", asc: false, shown: 200, open: new Set() };
    $("acrFSev").addEventListener("change", (e) => { fState.sev = e.target.value; fState.shown = 200; renderFindings(); });
    $("acrFType").addEventListener("change", (e) => { fState.type = e.target.value; fState.shown = 200; renderFindings(); });
    $("acrFExp").addEventListener("click", () => download("access-review-findings.csv", toFindingsCSV(r), "text/csv"));
    function filteredFindings() {
      let list = r.findings.filter((f) => (!fState.sev || f.severity === fState.sev) && (!fState.type || f.type === fState.type));
      const dir = fState.asc ? 1 : -1;
      const keyOf = { severity: (f) => SEVERITY_RANK[f.severity], type: (f) => f.title, account: (f) => (f.account ? f.account.id : ""), confidence: (f) => ({ high: 3, medium: 2, low: 1 }[f.confidence] || 0), hr: (f) => (f.employee ? f.employee.status : "") }[fState.sort];
      list.sort((a, b) => { const x = keyOf(a), y = keyOf(b); return (x < y ? -1 : x > y ? 1 : 0) * dir || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]; });
      return list;
    }
    function renderFindings() {
      const list = filteredFindings();
      $("acrFCnt").textContent = `${num(list.length)} shown`;
      if (!list.length) { $("acrFTbl").innerHTML = `<div class="acr-empty">No findings match.</div>`; $("acrFMore").innerHTML = ""; return; }
      const th = (key, label) => `<th class="sortable ${fState.sort === key ? "sorted " + (fState.asc ? "asc" : "") : ""}" data-sort="${key}">${label}</th>`;
      const rows = list.slice(0, fState.shown).map((f) => {
        const open = fState.open.has(f.id);
        return `<tr class="acr-f" data-id="${esc(f.id)}">
          <td class="acr-sev-${f.severity}">${f.severity}</td>
          <td>${esc(f.title)}</td>
          <td class="acr-mono">${f.account ? esc(f.account.id) : '<span class="acr-dim">aggregate</span>'}</td>
          <td>${f.employee ? esc(f.employee.name || f.employee.employeeId) + ` <span class="acr-dim">(${esc(f.employee.status)})</span>` : '<span class="acr-dim">none</span>'}</td>
          <td>${esc(f.confidence)}</td>
        </tr>${open ? `<tr class="acr-fd"><td colspan="5">
          <div>${esc(f.explanation)}</div>
          <dl class="acr-ev">${f.evidence.map((e) => `<dt>${esc(e.label)}</dt><dd>${esc(e.value)}</dd>`).join("")}</dl>
          <div><b>Recommended action.</b> ${esc(f.action)}</div>
          <div class="acr-ctl" style="margin-top:6px">${f.controls.map((c) => `<code>${esc(c)}</code>`).join("")}</div>
        </td></tr>` : ""}`;
      }).join("");
      $("acrFTbl").innerHTML = `<table><thead><tr>${th("severity", "Severity")}${th("type", "Finding")}${th("account", "Account")}${th("hr", "HR match")}${th("confidence", "Confidence")}</tr></thead><tbody>${rows}</tbody></table>`;
      $("acrFMore").innerHTML = list.length > fState.shown ? `<button class="acr-btn" id="acrFShow">Show ${num(Math.min(200, list.length - fState.shown))} more</button><span class="acr-cnt">${num(fState.shown)} of ${num(list.length)}</span>` : "";
      const more = $("acrFShow"); if (more) more.addEventListener("click", () => { fState.shown += 200; renderFindings(); });
      $("acrFTbl").querySelectorAll("th.sortable").forEach((h) => h.addEventListener("click", () => {
        const key = h.dataset.sort; if (fState.sort === key) fState.asc = !fState.asc; else { fState.sort = key; fState.asc = key !== "severity" && key !== "confidence"; }
        renderFindings();
      }));
      $("acrFTbl").querySelectorAll("tr.acr-f").forEach((tr) => tr.addEventListener("click", () => {
        const id = tr.dataset.id; if (fState.open.has(id)) fState.open.delete(id); else fState.open.add(id); renderFindings();
      }));
    }
    renderFindings();

    // reconciliation (virtualised)
    const rState = { q: "", disp: "", undecided: false, list: r.rows };
    const ROW_H = 46;
    const scroll = $("acrRScroll"), space = scroll.querySelector(".acr-vspace"), tbl = scroll.querySelector("table"), tbody = tbl.querySelector("tbody");
    const COLS = `<colgroup><col style="width:22%"><col style="width:14%"><col style="width:7%"><col style="width:15%"><col style="width:12%"><col style="width:12%"><col style="width:18%"></colgroup>`;
    $("acrRHead").innerHTML = `<table>${COLS}<thead><tr><th>Account</th><th>Name</th><th>State</th><th>HR match</th><th>Suggested</th><th>Decision</th><th>Note</th></tr></thead></table>`;
    tbl.insertAdjacentHTML("afterbegin", COLS);
    function applyFilter() {
      const q = rState.q.toLowerCase();
      rState.list = r.rows.filter((row) => {
        if (rState.disp && row.disposition !== rState.disp) return false;
        if (rState.undecided && state.decisions[row.key] && state.decisions[row.key].decision) return false;
        if (q && !(row.account.id.toLowerCase().includes(q) || (row.account.name || "").toLowerCase().includes(q) || (row.employee && (row.employee.name || "").toLowerCase().includes(q)))) return false;
        return true;
      });
      space.style.height = (rState.list.length * ROW_H) + "px";
      $("acrRCnt").textContent = `${num(rState.list.length)} shown`;
      scroll.scrollTop = 0;
      renderWindow();
    }
    function rowHtml(row) {
      const a = row.account, e = row.employee, d = state.decisions[row.key] || {};
      const st = a.enabled === false ? '<span class="acr-dim">disabled</span>' : a.enabled == null ? '<span class="acr-dim">unknown</span>' : "enabled";
      const extra = [a.type !== "member" ? a.type + (a.typeSource === "heuristic" ? "?" : "") : "", a.isAdmin ? "admin" : "", a.mfa === false ? "no MFA" : ""].filter(Boolean).join(", ");
      const hr = e ? `${esc(e.name || e.employeeId)} <span class="acr-dim">${esc(e.status)}${row.matchMethod === "fuzzy" ? ", name-only" : ""}</span>` : '<span class="acr-dim">none</span>';
      const sevTitle = row.findings.length ? ` title="${esc(row.findings.join(", "))}"` : "";
      return `<tr data-key="${esc(row.key)}">
        <td class="acr-mono" title="${esc(a.id)}">${esc(a.id)}</td>
        <td title="${esc(a.name)}">${esc(a.name)}${extra ? ` <span class="acr-dim">(${esc(extra)})</span>` : ""}</td>
        <td>${st}</td>
        <td>${hr}</td>
        <td class="acr-disp-${row.disposition.split(" ")[0]}"${sevTitle}>${esc(row.disposition)}${row.maxSeverity ? ` <span class="acr-dim">${row.maxSeverity}</span>` : ""}</td>
        <td><select data-act="decision"><option value="">Undecided</option>${DECISIONS.map((x) => `<option${d.decision === x ? " selected" : ""}>${x}</option>`).join("")}</select></td>
        <td><input type="text" data-act="note" value="${esc(d.note || "")}" placeholder="Note"></td>
      </tr>`;
    }
    let lastStart = -1, lastEnd = -1;
    function renderWindow(force) {
      const list = rState.list;
      const start = Math.max(0, Math.floor(scroll.scrollTop / ROW_H) - 5);
      const end = Math.min(list.length, Math.ceil((scroll.scrollTop + scroll.clientHeight) / ROW_H) + 5);
      if (!force && start === lastStart && end === lastEnd) return;
      lastStart = start; lastEnd = end;
      if (!list.length) { tbody.innerHTML = `<tr><td colspan="7" class="acr-empty">No accounts match.</td></tr>`; tbl.style.transform = ""; return; }
      let html = "";
      for (let i = start; i < end; i++) html += rowHtml(list[i]);
      tbody.innerHTML = html;
      tbl.style.transform = `translateY(${start * ROW_H}px)`;
    }
    scroll.addEventListener("scroll", () => renderWindow(false));
    scroll.addEventListener("change", (e) => {
      const t = e.target; if (!t || !t.dataset || !t.dataset.act) return;
      const tr = t.closest("tr"); if (!tr) return;
      setDecision(tr.dataset.key, t.dataset.act, t.value);
    });
    scroll.addEventListener("input", (e) => {
      const t = e.target; if (!t || t.dataset.act !== "note") return;
      const tr = t.closest("tr"); if (!tr) return;
      setDecision(tr.dataset.key, "note", t.value);
    });
    function setDecision(key, field, value) {
      const d = state.decisions[key] || (state.decisions[key] = {});
      if (field === "decision") { if (value) d.decision = value; else delete d.decision; }
      else d.note = value;
      d.at = Date.now();
      if (!d.decision && !d.note) delete state.decisions[key];
      saveDecisions(); updateSummary();
    }
    $("acrRQ").addEventListener("input", (e) => { rState.q = e.target.value; applyFilter(); });
    $("acrRDisp").addEventListener("change", (e) => { rState.disp = e.target.value; applyFilter(); });
    $("acrRUnd").addEventListener("change", (e) => { rState.undecided = e.target.checked; applyFilter(); });
    $("acrAccept").addEventListener("click", async () => {
      const und = r.rows.filter((row) => !(state.decisions[row.key] && state.decisions[row.key].decision));
      if (!und.length) { toast("Every account already has a decision."); return; }
      const ok = await confirmDlg("Accept suggested dispositions", `Set the reviewer decision to the suggested disposition for ${num(und.length)} undecided account(s)? Name-only matches become "Match confirmed" only if you confirm them individually; they are skipped here.`, { submitText: "Accept" });
      if (!ok) return;
      let n = 0;
      for (const row of und) {
        if (row.disposition === "Confirm match") continue;
        const d = state.decisions[row.key] || (state.decisions[row.key] = {});
        d.decision = row.disposition; d.at = Date.now(); n++;
      }
      saveDecisions(); renderWindow(true); updateSummary(); toast(`${num(n)} decision(s) set.`);
    });
    $("acrReset").addEventListener("click", async () => {
      const ok = await confirmDlg("Clear all decisions", "Remove every reviewer decision and note for this dataset from this browser? This cannot be undone.", { danger: true, submitText: "Clear" });
      if (!ok) return;
      state.decisions = {}; try { localStorage.removeItem(lsKey(state.hash)); } catch (_) {}
      renderWindow(true); updateSummary(); toast("Decisions cleared.");
    });

    // sign-off
    const meta = () => ({ reviewer: $("acrReviewer").value.trim(), date: $("acrDate").value.trim(), scope: $("acrScope").value.trim(), hash: state.hash });
    function updateSummary() {
      const c = summarizeDecisions(r, state.decisions);
      $("acrRSum").textContent = `Decisions: Keep ${num(c.Keep)}, Disable ${num(c.Disable)}, Investigate ${num(c.Investigate)}, Match confirmed ${num(c["Match confirmed"])}, Not a match ${num(c["Not a match"])}, undecided ${num(c.undecided)}.`;
      $("acrAtt").textContent = attestationText(r, state.decisions, meta());
    }
    ["acrReviewer", "acrDate", "acrScope"].forEach((id) => $(id).addEventListener("input", updateSummary));
    const needReviewer = () => { if (!meta().reviewer) { toast("Type the reviewer name before exporting."); $("acrReviewer").focus(); return false; } return true; };
    const stamp = () => (meta().date || new Date().toISOString().slice(0, 10)).replace(/[^0-9-]/g, "");
    $("acrExpCsv").addEventListener("click", () => { if (!needReviewer()) return; download(`access-review-${stamp()}.csv`, toReviewCSV(r, state.decisions), "text/csv"); });
    $("acrExpJson").addEventListener("click", () => { if (!needReviewer()) return; download(`access-review-${stamp()}.json`, JSON.stringify(toReviewJSON(r, state.decisions, meta()), null, 2), "application/json"); });
    $("acrExpTxt").addEventListener("click", () => { if (!needReviewer()) return; download(`access-review-attestation-${stamp()}.txt`, attestationText(r, state.decisions, meta()), "text/plain"); });

    applyFilter();
    updateSummary();
  }

  function kpi(v, label, cls) { return `<div class="acr-kpi"><b class="${cls || ""}">${num(v)}</b><span>${esc(label)}</span></div>`; }
}
