// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Sign-in Forensics. Load an identity-provider sign-in log export (Microsoft Entra ID,
// Google Workspace Login audit, Okta System Log) and find account-compromise patterns:
// password spraying, brute force, failures-then-success, impossible travel, new
// country, legacy authentication, admins without MFA, after-hours administration,
// concurrent distant sessions, hosting/VPN networks and provider risk flags.
//
// Everything runs in the browser: the file is parsed in slices on the main thread
// (yielding between slices so 100k-row exports do not freeze the page) and no row
// leaves the page. The engine (signin-forensics-engine.js) is pure and unit-tested.
//
//   renderSigninForensics(main) -> void

import {
  createParser, correlateOktaMfa, analyze, userTimeline, findingsToCsv, evidenceToCsv, summaryText, sourceName, iso, DEFAULTS, DETECTIONS,
} from "/js/identity/signin-forensics-engine.js?v=20261013m";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m, kind) => { try { (window.showToast || (() => {}))(m, kind); } catch (_) {} };
const confirmAsync = async (title, desc) => {
  try { if (typeof window.dnConfirm === "function") return await window.dnConfirm(title, desc, { submitText: "Replace" }); } catch (_) {}
  return true;
};

// Severity is conveyed with text colour only (ink theme). Never a background.
const SEV = {
  critical: { label: "Critical", c: "#b00020" },
  high:     { label: "High",     c: "#c0501b" },
  medium:   { label: "Medium",   c: "#8a6d00" },
  low:      { label: "Low",      c: "var(--mut,#64748b)" },
  good:     { label: "Good",     c: "#1b7f4d" },
};
const scoreColor = (n) => n >= 80 ? SEV.critical.c : n >= 50 ? SEV.high.c : n >= 20 ? SEV.medium.c : n > 0 ? SEV.low.c : SEV.good.c;

let injected = false;
function injectStyle() {
  if (injected || document.getElementById("sif-css")) { injected = true; return; }
  injected = true;
  const st = document.createElement("style"); st.id = "sif-css";
  st.textContent = `
  .sif{font-size:14px;line-height:1.5;color:var(--txt,#0f172a)}
  .sif .sif-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .sif h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .sif .sif-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--mut,#64748b);border:1px solid var(--line,#e6e8ee);padding:2px 9px;border-radius:999px}
  .sif .sif-sub{color:var(--mut,#64748b);margin:8px 0 14px;max-width:80ch}
  .sif .sif-scope{border:1px solid var(--line,#e6e8ee);border-left:3px solid var(--acc,#2563eb);border-radius:8px;padding:10px 14px;font-size:.84rem;margin-bottom:16px;background:var(--card,#fff)}
  .sif .sif-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px}
  .sif h3{font-size:.95rem;margin:0 0 6px}
  .sif .sif-note{color:var(--mut,#64748b);font-size:.82rem;margin:0 0 10px;overflow-wrap:anywhere}
  .sif textarea{width:100%;min-height:160px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;line-height:1.5;padding:10px 12px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--card,#fff);color:var(--txt,#0f172a);box-sizing:border-box}
  .sif .sif-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:10px}
  .sif .sif-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--txt,#0f172a);padding:8px 14px;border-radius:8px;cursor:pointer}
  .sif .sif-btn:hover{border-color:var(--mut,#9aa6bd)}
  .sif .sif-btn.pri{background:var(--acc,#2563eb);border-color:var(--acc,#2563eb);color:#fff}
  .sif .sif-btn:disabled{opacity:.55;cursor:default}
  .sif select,.sif input[type=number]{font:inherit;font-size:.84rem;border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:6px 8px;background:var(--card,#fff);color:var(--txt,#0f172a)}
  .sif input[type=number]{width:84px}
  .sif input[type=text]{font:inherit;font-size:.84rem;border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:6px 10px;background:var(--card,#fff);color:var(--txt,#0f172a);min-width:200px}
  .sif .sif-file{font-size:.8rem;color:var(--mut,#64748b)}
  .sif .sif-prog{font-size:.8rem;color:var(--mut,#64748b);min-height:1.2em;margin-top:8px;font-variant-numeric:tabular-nums}
  .sif details.sif-set{border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:0;margin-bottom:14px;background:var(--card,#fff)}
  .sif details.sif-set summary{cursor:pointer;padding:12px 18px;font-weight:600;font-size:.9rem}
  .sif .sif-setbody{padding:4px 18px 16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px 22px}
  .sif .sif-setgrp h4{margin:0 0 6px;font-size:.78rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#64748b)}
  .sif .sif-field{display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:.83rem;margin:4px 0}
  .sif .sif-field span{color:var(--txt,#0f172a)}
  .sif .sif-field small{color:var(--mut,#64748b)}
  .sif .sif-kpis{display:flex;gap:14px;flex-wrap:wrap;margin:0 0 14px}
  .sif .sif-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:118px}
  .sif .sif-kpi b{display:block;font-size:1.45rem;line-height:1.2;font-variant-numeric:tabular-nums;color:var(--c,var(--txt,#0f172a))}
  .sif .sif-kpi span{font-size:.72rem;color:var(--mut,#64748b);text-transform:uppercase;letter-spacing:.05em}
  .sif .sif-src{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 12px;font-size:.84rem}
  .sif .sif-badge{font-size:.74rem;font-weight:700;letter-spacing:.04em;border:1px solid var(--line,#e6e8ee);border-radius:999px;padding:2px 10px;color:var(--txt,#0f172a)}
  .sif .sif-score{display:flex;gap:22px;align-items:flex-start;flex-wrap:wrap}
  .sif .sif-scoren{font-size:2.6rem;font-weight:700;line-height:1;font-variant-numeric:tabular-nums;color:var(--c,var(--txt,#0f172a))}
  .sif .sif-scorel{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut,#64748b);margin-top:4px}
  .sif .sif-sevs{display:flex;gap:14px;flex-wrap:wrap;font-size:.84rem;margin-top:6px}
  .sif .sif-sevs b{font-variant-numeric:tabular-nums}
  .sif .sif-sev{font-weight:700;color:var(--c,var(--txt,#0f172a));white-space:nowrap}
  .sif .sif-sev-critical{color:#b00020}.sif .sif-sev-high{color:#c0501b}.sif .sif-sev-medium{color:#8a6d00}.sif .sif-sev-low{color:var(--mut,#64748b)}.sif .sif-good{color:#1b7f4d}
  .sif .sif-tbl{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;background:var(--card,#fff)}
  .sif table{width:100%;border-collapse:collapse;font-size:.84rem}
  .sif th{text-align:left;font-size:.71rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#64748b);font-weight:700;padding:9px 12px;border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .sif td{padding:9px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .sif tr:last-child td{border-bottom:0}
  .sif .sif-findtbl > table{table-layout:fixed;min-width:820px}
  .sif .sif-findtbl .sif-ev table{table-layout:auto;min-width:0;width:max-content;min-width:100%}
  .sif .sif-findtbl th:nth-child(1){width:84px}.sif .sif-findtbl th:nth-child(2){width:96px}.sif .sif-findtbl th:nth-child(3){width:220px}.sif .sif-findtbl th:nth-child(4){width:240px}
  .sif .sif-nowrap{white-space:nowrap}
  .sif .sif-users > table{table-layout:fixed;min-width:420px}
  .sif .sif-cov > table{min-width:560px}
  .sif .sif-users th:nth-child(2){width:64px}.sif .sif-users th:nth-child(3){width:76px}.sif .sif-users th:nth-child(4){width:92px}
  .sif .sif-users td:first-child{word-break:break-all}
  .sif .sif-reason{white-space:normal;min-width:240px;max-width:36ch}
  .sif tr.sif-click{cursor:pointer}
  .sif tr.sif-click:hover td{background:var(--card2,#f8fafc)}
  .sif tr.sif-open td{background:var(--card2,#f8fafc)}
  .sif .sif-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}
  .sif .sif-tech{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.76rem;color:var(--mut,#64748b);white-space:nowrap}
  .sif .sif-detail{padding:12px 14px 14px;border-bottom:1px solid var(--line,#eef0f4)}
  .sif .sif-detail p{margin:0 0 8px;max-width:95ch}
  .sif .sif-detail .sif-lbl{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#64748b);font-weight:700;margin:10px 0 4px}
  .sif .sif-ev{border:1px solid var(--line,#e6e8ee);border-radius:8px;overflow:auto;max-height:360px}
  .sif .sif-ev table{font-size:.78rem}
  .sif .sif-ev td,.sif .sif-ev th{padding:5px 9px;white-space:nowrap}
  .sif .sif-ok{color:#1b7f4d;font-weight:600}.sif .sif-bad{color:#b00020;font-weight:600}
  .sif .sif-skip{color:var(--mut,#64748b)}
  .sif .sif-sec{display:flex;align-items:baseline;justify-content:space-between;gap:10px;flex-wrap:wrap;margin:18px 0 8px}
  .sif .sif-sec h2{font-size:1.05rem;margin:0}
  .sif .sif-filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .sif .sif-empty{padding:24px;text-align:center;color:var(--mut,#64748b)}
  .sif .sif-tl{margin-top:10px}
  .sif .sif-flag{font-size:.74rem;color:#c0501b;font-weight:600}
  .sif .sif-two{display:grid;grid-template-columns:minmax(300px,2fr) minmax(0,3fr);gap:14px}
  .sif .sif-two > *{min-width:0}
  @media(max-width:900px){.sif .sif-two{grid-template-columns:minmax(0,1fr)}}
  .sif .sif-spin{display:inline-block;width:13px;height:13px;border:2px solid var(--line,#d7dbe3);border-top-color:var(--acc,#2563eb);border-radius:50%;animation:sifSpin .7s linear infinite;vertical-align:-2px;margin-right:6px}
  @keyframes sifSpin{to{transform:rotate(360deg)}}
  `;
  document.head.appendChild(st);
}

function download(name, text, type) {
  const b = new Blob([text], { type: type || "text/plain" });
  const u = URL.createObjectURL(b); const a = document.createElement("a");
  a.href = u; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(u), 1000);
}
const yieldFrame = () => new Promise((res) => (typeof requestIdleCallback === "function" ? requestIdleCallback(() => res(), { timeout: 50 }) : setTimeout(res, 0)));
const fmtTs = (t) => iso(t).replace("T", " ").replace("Z", "");
const fmtN = (n) => Number(n || 0).toLocaleString();

const UTC_OFFSETS = [-720, -660, -600, -540, -480, -420, -360, -300, -240, -210, -180, -120, -60, 0, 60, 120, 180, 210, 240, 270, 300, 330, 345, 360, 390, 420, 480, 540, 570, 600, 630, 660, 720, 765, 780, 840];
const offLabel = (m) => { const s = m < 0 ? "-" : "+"; const a = Math.abs(m); return `UTC${s}${String(Math.floor(a / 60)).padStart(2, "0")}:${String(a % 60).padStart(2, "0")}`; };

export function renderSigninForensics(main) {
  injectStyle();
  main.innerHTML = `
  <div class="sif">
    <div class="sif-hd"><h1>Sign-in Forensics</h1><span class="sif-tag">Identity</span></div>
    <div class="sif-sub">Load a sign-in log export from Microsoft Entra ID, Google Workspace or Okta and find account-compromise
      patterns: password spraying, brute force, failures followed by a success, impossible travel, legacy authentication,
      administrators without MFA and more. The file is parsed and analysed in your browser; no row is uploaded.</div>

    <div class="sif-scope"><b>What you get.</b> Deterministic detections over the export you provide, each tied to a MITRE ATT&amp;CK
      technique with the evidence rows and the threshold that fired. The tool makes no geolocation, reputation or threat-intelligence
      lookups: a detection that needs a column your export lacks is skipped and listed as skipped with the reason, never estimated.</div>

    <div class="sif-card">
      <h3>Sign-in log export</h3>
      <p class="sif-note">Supported: Entra ID sign-in logs (CSV from the portal, or JSON from Microsoft Graph), Google Workspace
        Login audit log (CSV), Okta System Log (JSON array or NDJSON), and any CSV with timestamp, user, IP and outcome columns.
        Column names are matched case-insensitively with common synonyms. Up to a few hundred thousand rows; large files load from the file picker.</p>
      <textarea id="sifIn" placeholder="Paste the export here" spellcheck="false"></textarea>
      <div class="sif-row">
        <button class="sif-btn pri" id="sifRun">Analyse</button>
        <label class="sif-btn">Load file<input type="file" id="sifFile" accept=".csv,.json,.ndjson,.txt,text/csv,application/json" hidden></label>
        <span class="sif-file" id="sifFileName"></span>
        <select id="sifExample" aria-label="Example dataset">
          <option value="">Load example...</option>
          <option value="entra">Entra ID sign-in CSV (synthetic)</option>
          <option value="google">Google Workspace Login audit CSV (synthetic)</option>
          <option value="okta">Okta System Log JSON (synthetic)</option>
        </select>
        <button class="sif-btn" id="sifClear">Clear</button>
      </div>
      <div class="sif-prog" id="sifProg"></div>
    </div>

    <details class="sif-set" id="sifSettings">
      <summary>Detection settings (defaults shown; changes apply on the next Analyse)</summary>
      <div class="sif-setbody">
        <div class="sif-setgrp"><h4>Password spraying</h4>
          <label class="sif-field"><span>Distinct users from one source</span><input type="number" id="o_sprayUsers" min="2" value="${DEFAULTS.sprayUsers}"></label>
          <label class="sif-field"><span>Window <small>(minutes)</small></span><input type="number" id="o_sprayWindowMin" min="1" value="${DEFAULTS.sprayWindowMin}"></label></div>
        <div class="sif-setgrp"><h4>Brute force</h4>
          <label class="sif-field"><span>Failures on one account</span><input type="number" id="o_bruteFailures" min="2" value="${DEFAULTS.bruteFailures}"></label>
          <label class="sif-field"><span>Window <small>(minutes)</small></span><input type="number" id="o_bruteWindowMin" min="1" value="${DEFAULTS.bruteWindowMin}"></label></div>
        <div class="sif-setgrp"><h4>Failures then success</h4>
          <label class="sif-field"><span>Prior failures from same source</span><input type="number" id="o_stuffFailures" min="1" value="${DEFAULTS.stuffFailures}"></label>
          <label class="sif-field"><span>Look-back <small>(minutes)</small></span><input type="number" id="o_stuffWindowMin" min="1" value="${DEFAULTS.stuffWindowMin}"></label></div>
        <div class="sif-setgrp"><h4>Impossible travel</h4>
          <label class="sif-field"><span>Implied speed above <small>(km/h)</small></span><input type="number" id="o_travelSpeedKmh" min="100" value="${DEFAULTS.travelSpeedKmh}"></label>
          <label class="sif-field"><span>Ignore distances under <small>(km)</small></span><input type="number" id="o_travelMinKm" min="0" value="${DEFAULTS.travelMinKm}"></label></div>
        <div class="sif-setgrp"><h4>New country</h4>
          <label class="sif-field"><span>History required before flagging <small>(days)</small></span><input type="number" id="o_newCountryMinDays" min="1" value="${DEFAULTS.newCountryMinDays}"></label></div>
        <div class="sif-setgrp"><h4>Concurrent sessions</h4>
          <label class="sif-field"><span>Window <small>(minutes)</small></span><input type="number" id="o_concurrentWindowMin" min="1" value="${DEFAULTS.concurrentWindowMin}"></label>
          <label class="sif-field"><span>Minimum distance <small>(km)</small></span><input type="number" id="o_concurrentMinKm" min="0" value="${DEFAULTS.concurrentMinKm}"></label></div>
        <div class="sif-setgrp"><h4>Business hours (admin activity)</h4>
          <label class="sif-field"><span>Start hour</span><input type="number" id="o_bizStartHour" min="0" max="23" value="${DEFAULTS.bizStartHour}"></label>
          <label class="sif-field"><span>End hour</span><input type="number" id="o_bizEndHour" min="1" max="24" value="${DEFAULTS.bizEndHour}"></label>
          <label class="sif-field"><span>Organisation time zone</span><select id="o_utcOffsetMin">${UTC_OFFSETS.map((m) => `<option value="${m}"${m === 0 ? " selected" : ""}>${offLabel(m)}</option>`).join("")}</select></label>
          <label class="sif-field"><span>Weekends count as after hours</span><input type="checkbox" id="o_weekendIsAfterHours" checked></label></div>
      </div>
    </details>

    <div id="sifOut"></div>
  </div>`;

  const $ = (id) => main.querySelector("#" + id);
  const inTA = $("sifIn"), out = $("sifOut"), prog = $("sifProg");
  const state = { text: null, parsed: null, records: null, result: null, openKey: null, user: null, sevFilter: "", userFilter: "" };

  $("sifFile").addEventListener("change", (e) => {
    const f = e.target.files && e.target.files[0]; if (!f) return;
    const fr = new FileReader();
    fr.onload = () => { inTA.value = String(fr.result || ""); $("sifFileName").textContent = `${f.name} (${(f.size / 1024).toFixed(0)} KB)`; prog.textContent = "File loaded. Press Analyse."; };
    fr.onerror = () => toast("Could not read the file", "error");
    fr.readAsText(f);
    e.target.value = "";
  });
  $("sifExample").addEventListener("change", async (e) => {
    const v = e.target.value; e.target.value = "";
    if (!v) return;
    if (inTA.value.trim() && !(await confirmAsync("Replace the current input?", "The example dataset will replace what is in the text area."))) return;
    inTA.value = v === "entra" ? exampleEntra() : v === "google" ? exampleGoogle() : exampleOkta();
    $("sifFileName").textContent = "synthetic example";
    prog.textContent = "Example loaded (synthetic data, format-faithful). Press Analyse.";
  });
  $("sifClear").addEventListener("click", () => { inTA.value = ""; $("sifFileName").textContent = ""; prog.textContent = ""; out.innerHTML = ""; Object.assign(state, { text: null, parsed: null, records: null, result: null, openKey: null, user: null }); });
  $("sifRun").addEventListener("click", run);
  inTA.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(); });

  function readOptions() {
    const o = {};
    for (const k of Object.keys(DEFAULTS)) {
      const el = $("o_" + k); if (!el) continue;
      if (el.type === "checkbox") o[k] = el.checked;
      else { const n = Number(el.value); o[k] = Number.isFinite(n) ? n : DEFAULTS[k]; }
    }
    if (o.bizEndHour <= o.bizStartHour) { o.bizEndHour = DEFAULTS.bizEndHour; o.bizStartHour = DEFAULTS.bizStartHour; toast("Business hours end must be after start; defaults used."); }
    return o;
  }

  let running = false;
  async function run() {
    if (running) return;
    const text = inTA.value;
    if (!text.trim()) { out.innerHTML = `<div class="sif-card sif-empty">Paste or load a sign-in log export first.</div>`; return; }
    running = true; $("sifRun").disabled = true;
    try {
      if (state.text !== text || !state.records) {
        state.text = text; state.records = null; state.result = null;
        let p;
        try { p = createParser(text); }
        catch (e) { out.innerHTML = `<div class="sif-card sif-empty">Could not read the input.<br><span class="sif-note">${esc(e && e.message || e)}</span></div>`; prog.textContent = ""; return; }
        if (p.source === "unknown") {
          out.innerHTML = `<div class="sif-card sif-empty">This does not look like a sign-in log export.<br><span class="sif-note">Columns found: ${esc(p.headers.slice(0, 20).join(", ") || "(none)")}. A timestamp, a user and an outcome/status column are the minimum.</span></div>`;
          prog.textContent = ""; return;
        }
        const records = [];
        let t0 = performance.now(), lastPaint = t0;
        prog.innerHTML = `<span class="sif-spin"></span>Parsing...`;
        while (!p.done()) {
          const chunk = p.next(3000);
          for (let i = 0; i < chunk.length; i++) records.push(chunk[i]);
          const now = performance.now();
          if (now - lastPaint > 80) {
            lastPaint = now;
            prog.innerHTML = `<span class="sif-spin"></span>Parsed ${fmtN(p.stats.total)}${p.total ? ` of about ${fmtN(p.total)}` : ""} rows (${fmtN(p.stats.kept)} authentication events kept)`;
            await yieldFrame();
          }
        }
        if (p.source === "okta") correlateOktaMfa(records);
        state.parsed = p; state.records = records;
        prog.textContent = `Parsed ${fmtN(p.stats.total)} rows in ${((performance.now() - t0) / 1000).toFixed(1)} s.`;
      }
      prog.innerHTML = `<span class="sif-spin"></span>Running detections...`;
      await yieldFrame();
      const t1 = performance.now();
      const opts = readOptions();
      state.result = analyze(state.records, opts, { columns: state.parsed.columns, source: state.parsed.source });
      state.openKey = null; state.user = state.result.users[0] ? state.result.users[0].user : null;
      const st = state.parsed.stats;
      prog.textContent = `${fmtN(st.total)} rows read; ${fmtN(st.kept)} authentication events analysed in ${((performance.now() - t1) / 1000).toFixed(1)} s`
        + (st.nonAuth || st.badTs || st.noUser ? ` (dropped: ${fmtN(st.nonAuth)} non-authentication events, ${fmtN(st.badTs)} without a readable timestamp, ${fmtN(st.noUser)} without a user).` : ".");
      renderResults();
    } finally { running = false; $("sifRun").disabled = false; }
  }

  // ----- results -----------------------------------------------------------
  function renderResults() {
    const r = state.result, p = state.parsed, k = r.kpis, s = r.score;
    const ran = r.coverage.filter((c) => c.ran).length;
    out.innerHTML = `
      <div class="sif-src">
        <span class="sif-badge">Source detected: ${esc(sourceName(r.source))}</span>
        <span class="sif-badge">${esc(p.format.toUpperCase())}</span>
        <span class="sif-note" style="margin:0">Detections run: ${ran} of ${r.coverage.length}. ${k.spanStart ? `Span ${esc(fmtTs(k.spanStart))} to ${esc(fmtTs(k.spanEnd))} UTC (${k.spanDays} days).` : ""}</span>
      </div>
      <div class="sif-kpis">
        <div class="sif-kpi"><b>${fmtN(k.records)}</b><span>Auth events</span></div>
        <div class="sif-kpi"><b>${fmtN(k.successes)}</b><span>Successes</span></div>
        <div class="sif-kpi"><b style="--c:${k.failures ? SEV.high.c : "inherit"}">${fmtN(k.failures)}</b><span>Failures</span></div>
        <div class="sif-kpi"><b>${fmtN(k.users)}</b><span>Users</span></div>
        <div class="sif-kpi"><b>${fmtN(k.ips)}</b><span>Source IPs</span></div>
        <div class="sif-kpi"><b>${k.countries ? fmtN(k.countries) : "n/a"}</b><span>Countries</span></div>
        <div class="sif-kpi"><b style="--c:${r.findings.length ? SEV.high.c : SEV.good.c}">${fmtN(r.findings.length)}</b><span>Findings</span></div>
      </div>

      <div class="sif-two">
        <div class="sif-card">
          <h3>Overall risk</h3>
          <div class="sif-score">
            <div><div class="sif-scoren" style="--c:${scoreColor(s.overall)}">${s.overall}</div><div class="sif-scorel">${esc(s.label)}</div></div>
            <div class="sif-sevs">
              <span class="sif-sev-critical"><b>${s.severities.critical}</b> critical</span>
              <span class="sif-sev-high"><b>${s.severities.high}</b> high</span>
              <span class="sif-sev-medium"><b>${s.severities.medium}</b> medium</span>
              <span class="sif-sev-low"><b>${s.severities.low}</b> low</span>
            </div>
          </div>
          <p class="sif-note" style="margin-top:10px">${esc(s.explanation)}</p>
          <div class="sif-row">
            <button class="sif-btn" id="sifExpCsv">Export findings (CSV)</button>
            <button class="sif-btn" id="sifExpEv">Export evidence rows (CSV)</button>
            <button class="sif-btn" id="sifExpJson">Export JSON</button>
            <button class="sif-btn" id="sifCopy">Copy summary</button>
          </div>
        </div>
        <div class="sif-card">
          <h3>Coverage: detections run and skipped</h3>
          <p class="sif-note">A skipped detection means the export does not carry what it needs. The reason is stated; nothing is inferred to fill the gap.</p>
          <div class="sif-tbl sif-cov"><table>
            <thead><tr><th>Detection</th><th>Technique</th><th>Status</th><th>Findings</th></tr></thead>
            <tbody>${r.coverage.map((c) => `<tr><td>${esc(c.name)}${c.reason ? `<div class="sif-note" style="margin:2px 0 0">${esc(c.reason)}</div>` : ""}${c.note ? `<div class="sif-note" style="margin:2px 0 0">${esc(c.note)}</div>` : ""}</td><td class="sif-tech">${esc(c.technique)}</td><td class="sif-nowrap">${c.ran ? `<span class="sif-ok">Ran</span>` : `<span class="sif-skip">Skipped</span>`}</td><td>${c.ran ? c.findings : ""}</td></tr>`).join("")}</tbody>
          </table></div>
          ${p.columns.mfaNote ? `<p class="sif-note" style="margin:10px 0 0">${esc(p.columns.mfaNote)}</p>` : ""}
          ${!p.columns.role ? `<p class="sif-note" style="margin:10px 0 0">No role column in this export: administrators are identified by username pattern or by signing into an administrative console, and those findings are rated medium confidence.</p>` : ""}
        </div>
      </div>

      <div class="sif-sec"><h2>Findings</h2>
        <div class="sif-filters">
          <select id="sifSev"><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
          <input type="text" id="sifUserQ" placeholder="Filter by user or IP">
        </div></div>
      <div id="sifFindings"></div>

      <div class="sif-sec"><h2>Accounts</h2><span class="sif-note" style="margin:0">Select an account to see its timeline with the rows each finding cites.</span></div>
      <div class="sif-two">
        <div id="sifUsers"></div>
        <div id="sifTimeline"></div>
      </div>`;

    $("sifExpCsv").addEventListener("click", () => download("signin-forensics-findings.csv", findingsToCsv(r.findings), "text/csv"));
    $("sifExpEv").addEventListener("click", () => download("signin-forensics-evidence.csv", evidenceToCsv(r.findings), "text/csv"));
    $("sifExpJson").addEventListener("click", () => download("signin-forensics.json", JSON.stringify({ generated: new Date().toISOString(), source: r.source, kpis: r.kpis, score: r.score, options: r.options, coverage: r.coverage, findings: r.findings, users: r.users }, null, 2), "application/json"));
    $("sifCopy").addEventListener("click", async () => {
      const txt = summaryText(r);
      try { await navigator.clipboard.writeText(txt); toast("Summary copied"); }
      catch (_) { download("signin-forensics-summary.txt", txt); toast("Clipboard unavailable; summary downloaded instead"); }
    });
    $("sifSev").value = state.sevFilter; $("sifUserQ").value = state.userFilter;
    $("sifSev").addEventListener("change", (e) => { state.sevFilter = e.target.value; renderFindings(); });
    $("sifUserQ").addEventListener("input", (e) => { state.userFilter = e.target.value.trim().toLowerCase(); renderFindings(); });
    renderFindings(); renderUsers(); renderTimeline();
  }

  function renderFindings() {
    const r = state.result; const host = $("sifFindings");
    let list = r.findings;
    if (state.sevFilter) list = list.filter((f) => f.severity === state.sevFilter);
    if (state.userFilter) list = list.filter((f) => (f.user || "").toLowerCase().includes(state.userFilter) || (f.ip || "").toLowerCase().includes(state.userFilter) || f.title.toLowerCase().includes(state.userFilter));
    if (!list.length) { host.innerHTML = `<div class="sif-card sif-empty">${r.findings.length ? "No findings match the filter." : "No findings. The coverage panel lists which detections ran on this export."}</div>`; return; }
    const shown = list.slice(0, 500);
    host.innerHTML = `<div class="sif-tbl sif-findtbl"><table>
      <thead><tr><th>Severity</th><th>Confidence</th><th>Detection</th><th>Account / source</th><th>Finding</th></tr></thead>
      <tbody>${shown.map((f) => `<tr class="sif-click${state.openKey === f.key ? " sif-open" : ""}" data-key="${esc(f.key)}">
        <td><span class="sif-sev sif-sev-${f.severity}">${SEV[f.severity].label}</span></td>
        <td>${esc(f.confidence)}</td>
        <td>${esc(f.name)}<div class="sif-tech">${esc(f.technique)}</div></td>
        <td class="sif-mono">${esc(f.user || "")}${f.user && f.ip ? "<br>" : ""}${esc(f.ip || "")}</td>
        <td>${esc(f.title)}</td></tr>${state.openKey === f.key ? `<tr><td colspan="5" class="sif-detail">${detailHtml(f)}</td></tr>` : ""}`).join("")}</tbody>
    </table></div>${list.length > shown.length ? `<p class="sif-note" style="margin-top:8px">Showing ${shown.length} of ${fmtN(list.length)} findings. Use the filters or the CSV export for the full list.</p>` : ""}`;
    host.querySelectorAll("tr.sif-click").forEach((tr) => tr.addEventListener("click", () => {
      const key = tr.getAttribute("data-key");
      state.openKey = state.openKey === key ? null : key;
      const f = r.findings.find((x) => x.key === key);
      if (f && f.user && state.openKey) { state.user = f.user; renderUsers(); renderTimeline(); }
      renderFindings();
    }));
  }

  function detailHtml(f) {
    const cols = ["Time (UTC)", "User", "IP", "Outcome", "Application", "Client", "MFA", "Location", "Failure reason", "Note"];
    const shown = f.evidence;
    return `<p>${esc(f.description)}</p>
      <div class="sif-lbl">ATT&amp;CK</div><p class="sif-mono">${esc(f.technique)} ${esc(f.techniqueName)}</p>
      <div class="sif-lbl">Recommended action</div><p>${esc(f.action)}</p>
      <div class="sif-lbl">Evidence (${shown.length === f.evidenceTotal ? fmtN(f.evidenceTotal) : `showing ${shown.length} of ${fmtN(f.evidenceTotal)}`} rows; the evidence CSV export includes the same rows)</div>
      <div class="sif-ev"><table><thead><tr>${cols.map((c) => `<th>${c}</th>`).join("")}</tr></thead>
      <tbody>${shown.map((e) => `<tr><td>${esc(fmtTs(e.ts))}</td><td>${esc(e.user)}</td><td>${esc(e.ip || "")}</td><td>${e.success ? `<span class="sif-ok">success</span>` : `<span class="sif-bad">failure</span>`}</td><td>${esc(e.app || "")}</td><td>${esc(e.clientApp || "")}</td><td>${e.mfa === null ? "" : e.mfa ? "yes" : "no"}</td><td>${esc([e.city, e.country].filter(Boolean).join(", "))}</td><td>${esc(e.failureReason || "")}</td><td>${esc(e.note || "")}</td></tr>`).join("")}</tbody></table></div>`;
  }

  function renderUsers() {
    const r = state.result; const host = $("sifUsers");
    const list = r.users.slice(0, 300);
    host.innerHTML = `<div class="sif-tbl sif-users"><table>
      <thead><tr><th>Account</th><th>Score</th><th>Found</th><th>OK/fail</th></tr></thead>
      <tbody>${list.map((u) => `<tr class="sif-click${state.user === u.user ? " sif-open" : ""}" data-user="${esc(u.user)}">
        <td class="sif-mono">${esc(u.user)}${u.isAdmin ? `<div class="sif-note" style="margin:0">admin (${esc(u.adminBasis || "hint")})</div>` : ""}</td>
        <td><b style="color:${scoreColor(u.score)}">${u.score}</b></td>
        <td>${u.findings.length}</td>
        <td class="sif-mono">${fmtN(u.successes)} / ${fmtN(u.failures)}</td></tr>`).join("")}</tbody></table></div>
      ${r.users.length > list.length ? `<p class="sif-note" style="margin-top:8px">Showing the ${list.length} highest-scoring of ${fmtN(r.users.length)} accounts.</p>` : ""}`;
    host.querySelectorAll("tr.sif-click").forEach((tr) => tr.addEventListener("click", () => { state.user = tr.getAttribute("data-user"); renderUsers(); renderTimeline(); }));
  }

  function renderTimeline() {
    const host = $("sifTimeline"); const r = state.result;
    if (!state.user) { host.innerHTML = `<div class="sif-card sif-empty">Select an account.</div>`; return; }
    const rows = userTimeline(r, state.records, state.user);
    const u = r.users.find((x) => x.user === state.user);
    const shown = rows.slice(0, 2000);
    const names = new Map(r.findings.map((f) => [f.key, f.name]));
    host.innerHTML = `<div class="sif-card" style="margin:0">
      <h3 class="sif-mono">${esc(state.user)}</h3>
      <p class="sif-note">${fmtN(rows.length)} authentication events, ${fmtN(u ? u.successes : 0)} successes and ${fmtN(u ? u.failures : 0)} failures from ${u ? u.ips : 0} IP${u && u.ips === 1 ? "" : "s"}${u && u.countries.length ? ` in ${esc(u.countries.join(", "))}` : ""}. Rows cited by a finding are marked.</p>
      <div class="sif-ev" style="max-height:480px"><table><thead><tr><th>Time (UTC)</th><th>Outcome</th><th>IP</th><th>Location</th><th>Application</th><th>Client</th><th>MFA</th><th>Cited by</th></tr></thead>
      <tbody>${shown.map((e) => `<tr><td>${esc(fmtTs(e.ts))}</td><td class="${e.failureReason ? "sif-reason" : ""}">${e.success ? `<span class="sif-ok">success</span>` : `<span class="sif-bad">failure</span>${e.failureReason ? `<div class="sif-note" style="margin:0">${esc(e.failureReason)}</div>` : ""}`}</td><td>${esc(e.ip || "")}</td><td>${esc([e.city, e.country].filter(Boolean).join(", "))}</td><td>${esc(e.app || "")}</td><td>${esc(e.clientApp || "")}</td><td>${e.mfa === null ? "" : e.mfa ? "yes" : "no"}</td><td>${e.flags.length ? `<span class="sif-flag">${esc([...new Set(e.flags.map((k) => names.get(k) || k))].join("; "))}</span>` : ""}</td></tr>`).join("")}</tbody></table></div>
      ${rows.length > shown.length ? `<p class="sif-note" style="margin-top:8px">Showing the first ${shown.length} of ${fmtN(rows.length)} events.</p>` : ""}
    </div>`;
  }
}

// ---------------------------------------------------------------------------
// Synthetic example datasets. Deterministic (seeded) so the same example always
// loads; shaped exactly like the real exports, with the patterns the detections
// look for planted on a quiet baseline. Every number the UI shows still comes
// from running the detections on this text.
// ---------------------------------------------------------------------------
function rng(seed) { let s = seed >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; }; }
const q = (s) => `"${String(s == null ? "" : s).replace(/"/g, '""')}"`;
const Z = (t) => new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z");
const MIN = 60000, DAY = 86400000;
const EX_T0 = Date.UTC(2026, 8, 21, 8, 0, 0); // Mon 2026-09-21 08:00Z
const STAFF = Array.from({ length: 12 }, (_, i) => "user" + String(i + 1).padStart(2, "0"));
const HOME = { ip: "86.43.10.", city: "Dublin", country: "IE", lat: 53.35, lon: -6.26 };

function exampleEntra() {
  const H = ["Date (UTC)", "Request ID", "User", "Username", "User ID", "Application", "Status", "IP address", "Location", "City", "State/province", "Country/Region", "Client app", "Authentication requirement", "Multifactor authentication result", "Conditional Access", "Failure reason", "Browser", "Operating System", "Device ID", "Risk state", "Latitude", "Longitude"];
  const R = rng(7); const rows = []; let n = 0;
  const push = (o) => rows.push({ ts: o.ts, user: `${o.u}@test.darknode.ai`, app: o.app || "Office 365 Exchange Online", ok: o.ok !== false, ip: o.ip, city: o.city, state: o.state || "", country: o.country, client: o.client || "Browser", mfa: o.mfa === undefined ? true : o.mfa, reason: o.reason || "", browser: o.browser || "Edge 130.0.0", os: o.os || "Windows 11", risk: o.risk || "none", lat: o.lat, lon: o.lon });
  // Baseline: 14 working days, each person signs in 2-4 times from the office range, MFA satisfied.
  for (let d = 0; d < 20; d++) {
    const dayTs = EX_T0 + d * DAY; const dow = new Date(dayTs).getUTCDay(); if (dow === 0 || dow === 6) continue;
    for (const u of STAFF) { if (u === "user11" && d >= 17) continue; /* travelling, see pattern 7 */ const k = 2 + Math.floor(R() * 3); for (let i = 0; i < k; i++) push({ ts: dayTs + Math.floor(R() * 9 * 60) * MIN, u, ip: HOME.ip + (20 + Math.floor(R() * 6)), city: HOME.city, country: HOME.country, lat: HOME.lat, lon: HOME.lon, app: R() < 0.6 ? "Office 365 Exchange Online" : "Microsoft Teams" }); }
    // the IT admin uses the portal daily, with MFA
    push({ ts: dayTs + 60 * MIN, u: "it-admin", app: "Azure Portal", ip: HOME.ip + "21", city: HOME.city, country: HOME.country, lat: HOME.lat, lon: HOME.lon, mfa: true });
  }
  // Pattern 1: password spray from one address across 14 accounts, 2 min apart, day 3 early morning
  STAFF.concat(["it-admin", "svc-backup"]).forEach((u, i) => push({ ts: EX_T0 + 2 * DAY + (-4 * 60 + i * 2) * MIN, u, ok: false, ip: "185.220.101.34", city: "Bucharest", country: "RO", lat: 44.43, lon: 26.1, mfa: null, reason: "Error validating credentials due to invalid username or password.", browser: "Chrome 118.0.0", os: "Linux" }));
  // Pattern 2: the spray source then succeeds against user04 after 7 more failures (no MFA registered)
  for (let i = 0; i < 7; i++) push({ ts: EX_T0 + 2 * DAY + (-3 * 60 + i) * MIN, u: "user04", ok: false, ip: "185.220.101.34", city: "Bucharest", country: "RO", lat: 44.43, lon: 26.1, mfa: null, reason: "Error validating credentials due to invalid username or password." });
  push({ ts: EX_T0 + 2 * DAY + (-3 * 60 + 9) * MIN, u: "user04", ok: true, ip: "185.220.101.34", city: "Bucharest", country: "RO", lat: 44.43, lon: 26.1, mfa: false, risk: "atRisk", browser: "Chrome 118.0.0", os: "Linux" });
  // Pattern 3: brute force on svc-backup, 26 failures in 20 min, day 5
  for (let i = 0; i < 26; i++) push({ ts: EX_T0 + 4 * DAY + (14 * 60 + Math.floor(i * 0.77)) * MIN, u: "svc-backup", ok: false, ip: "45.142.212.61", city: "Amsterdam", country: "NL", lat: 52.37, lon: 4.9, mfa: null, reason: "Error validating credentials due to invalid username or password.", browser: "Python Requests 2.31", os: "Linux" });
  // Pattern 4: impossible travel for user07: Dublin 09:10, Singapore 09:55 same day (day 8)
  push({ ts: EX_T0 + 7 * DAY + 70 * MIN, u: "user07", ip: HOME.ip + "22", city: HOME.city, country: HOME.country, lat: HOME.lat, lon: HOME.lon });
  push({ ts: EX_T0 + 7 * DAY + 115 * MIN, u: "user07", ip: "118.189.5.77", city: "Singapore", country: "SG", lat: 1.35, lon: 103.82, mfa: true, browser: "Safari 17.0", os: "iOS 17" });
  // Pattern 5: legacy IMAP for user08 every morning (a mail client with basic auth)
  for (let d = 0; d < 20; d++) { const dayTs = EX_T0 + d * DAY; const dow = new Date(dayTs).getUTCDay(); if (dow === 0 || dow === 6) continue; push({ ts: dayTs + 15 * MIN, u: "user08", ip: HOME.ip + "24", city: HOME.city, country: HOME.country, lat: HOME.lat, lon: HOME.lon, client: "IMAP4", mfa: false, browser: "", os: "" }); }
  // Pattern 6: it-admin signs into the portal without MFA at 02:30 on a Saturday (day 6) from a hotel in Lisbon
  push({ ts: EX_T0 + 5 * DAY + (-5 * 60 - 30) * MIN, u: "it-admin", app: "Azure Portal", ip: "148.63.80.12", city: "Lisbon", country: "PT", lat: 38.72, lon: -9.14, mfa: false });
  // Pattern 7: new country for user11 on days 18-19 (after > 7 days of history), MFA satisfied: a business trip
  for (const d of [17, 18]) { push({ ts: EX_T0 + d * DAY + 3 * 60 * MIN, u: "user11", ip: "203.0.113.200", city: "Tokyo", country: "JP", lat: 35.68, lon: 139.69, mfa: true }); push({ ts: EX_T0 + d * DAY + 5 * 60 * MIN, u: "user11", ip: "203.0.113.200", city: "Tokyo", country: "JP", lat: 35.68, lon: 139.69, mfa: true }); }
  rows.sort((a, b) => a.ts - b.ts);
  const lines = [H.map(q).join(",")];
  for (const r of rows) {
    n++;
    const rec = { "Date (UTC)": Z(r.ts), "Request ID": `3f1c${String(n).padStart(6, "0")}-00e2-4a1b-9c3e-${String(n * 7919).padStart(12, "0")}`, "User": r.user.split("@")[0].replace(/[.-]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()), "Username": r.user,
      "User ID": `9a8b${String(n % 97).padStart(4, "0")}-0000-4000-8000-${String(n % 13).padStart(12, "0")}`, "Application": r.app, "Status": r.ok ? "Success" : "Failure", "IP address": r.ip, "Location": `${r.city}, ${r.country}`, "City": r.city, "State/province": r.state, "Country/Region": r.country,
      "Client app": r.client, "Authentication requirement": r.mfa === null ? "" : r.mfa ? "multiFactorAuthentication" : "singleFactorAuthentication", "Multifactor authentication result": r.mfa ? "MFA requirement satisfied by claim in the token" : "", "Conditional Access": r.ok ? "success" : "notApplied",
      "Failure reason": r.reason, "Browser": r.browser, "Operating System": r.os, "Device ID": "", "Risk state": r.risk, "Latitude": r.lat, "Longitude": r.lon };
    lines.push(H.map((h) => q(rec[h] == null ? "" : rec[h])).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}

function exampleGoogle() {
  const H = ["Date", "Event Name", "Event Description", "User", "IP Address", "Login Type", "Is Suspicious", "Login Challenge Method", "Is Second Factor", "Login Failure Type"];
  const R = rng(11); const rows = [];
  const push = (ts, ev, u, ip, extra = {}) => rows.push({ ts, ev, u: `${u}@test.darknode.ai`, ip, type: extra.type || "google_password", susp: !!extra.susp, mfa: extra.mfa !== false, fail: extra.fail || "" });
  for (let d = 0; d < 12; d++) {
    const dayTs = EX_T0 + d * DAY; const dow = new Date(dayTs).getUTCDay(); if (dow === 0 || dow === 6) continue;
    for (const u of STAFF.slice(0, 9)) { push(dayTs + Math.floor(R() * 8 * 60) * MIN, "login_success", u, "198.51.100." + (10 + Math.floor(R() * 4))); if (R() < 0.3) push(dayTs + 9 * 60 * MIN, "logout", u, "198.51.100.11"); }
  }
  // spray across 11 users from one IP in 25 minutes
  STAFF.slice(0, 11).forEach((u, i) => push(EX_T0 + 3 * DAY + (-3 * 60 + i * 2) * MIN, "login_failure", u, "102.129.145.9", { fail: "login_failure_invalid_password", mfa: false }));
  // brute force on user05 then success; Google marks the success suspicious
  for (let i = 0; i < 22; i++) push(EX_T0 + 6 * DAY + (-2 * 60 + i) * MIN, "login_failure", "user05", "41.77.9.130", { fail: "login_failure_invalid_password", mfa: false });
  push(EX_T0 + 6 * DAY + (-2 * 60 + 24) * MIN, "suspicious_login", "user05", "41.77.9.130", { susp: true, mfa: false });
  // legacy: user02 uses an Exchange ActiveSync client daily (less secure app)
  for (let d = 0; d < 12; d++) { const dayTs = EX_T0 + d * DAY; const dow = new Date(dayTs).getUTCDay(); if (dow === 0 || dow === 6) continue; push(dayTs + 20 * MIN, "login_success", "user02", "198.51.100.12", { type: "exchange", mfa: false }); }
  // admin account without second factor
  push(EX_T0 + 2 * DAY + 2 * 60 * MIN, "login_success", "gsuite-admin", "198.51.100.10", { mfa: false });
  push(EX_T0 + 8 * DAY + 2 * 60 * MIN, "login_success", "gsuite-admin", "198.51.100.10", { mfa: false });
  rows.sort((a, b) => a.ts - b.ts);
  const lines = [H.join(",")];
  for (const r of rows) {
    const desc = r.ev === "login_success" ? `${r.u} logged in` : r.ev === "login_failure" ? `${r.u} failed to log in` : r.ev === "logout" ? `${r.u} logged out` : `${r.u} logged in from a suspicious location`;
    lines.push([Z(r.ts), r.ev, q(desc), r.u, r.ip, r.type, r.susp ? "TRUE" : "FALSE", "", r.ev === "login_success" || r.ev === "suspicious_login" ? (r.mfa ? "TRUE" : "FALSE") : "", r.fail].join(","));
  }
  return lines.join("\n") + "\n";
}

function exampleOkta() {
  const R = rng(5); const events = [];
  const geo = { dublin: { city: "Dublin", country: "Ireland", lat: 53.3331, lon: -6.2489, isp: "eircom limited", asn: 5466 }, nyc: { city: "New York", country: "United States", lat: 40.7128, lon: -74.006, isp: "Verizon Business", asn: 701 },
    frankfurt: { city: "Frankfurt am Main", country: "Germany", lat: 50.1109, lon: 8.6821, isp: "DigitalOcean, LLC", asn: 14061 }, tor: { city: "Zurich", country: "Switzerland", lat: 47.3769, lon: 8.5417, isp: "Zwiebelfreunde e.V.", asn: 60729, proxy: true } };
  let seq = 0;
  const ev = (ts, type, u, ip, g, ok, extra = {}) => events.push({
    uuid: `0f2e${String(++seq).padStart(4, "0")}-6d1a-11f1-9b3c-${String(seq * 104729).padStart(12, "0")}`, published: new Date(ts).toISOString(), eventType: type, version: "0", severity: ok ? "INFO" : "WARN",
    legacyEventType: type === "user.session.start" ? (ok ? "core.user_auth.login_success" : "core.user_auth.login_failed") : null,
    displayMessage: type === "user.session.start" ? "User login to Okta" : type === "user.authentication.auth_via_mfa" ? "Authentication of user via MFA" : type === "user.session.access_admin_app" ? "User accessing Okta admin app" : "User single sign on to app",
    actor: { id: `00u${u.replace(/\W/g, "").slice(0, 10)}`, type: "User", alternateId: `${u}@test.darknode.ai`, displayName: u.replace(/\./g, " "), detailEntry: null },
    client: { userAgent: { rawUserAgent: extra.ua || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36", os: "Windows 10", browser: "CHROME" }, zone: "null", device: "Computer", id: null, ipAddress: ip,
      geographicalContext: { city: g.city, state: null, country: g.country, postalCode: null, geolocation: { lat: g.lat, lon: g.lon } } },
    outcome: { result: ok ? "SUCCESS" : "FAILURE", reason: ok ? null : (extra.reason || "INVALID_CREDENTIALS") },
    target: extra.app ? [{ id: "0oa1b2c3", type: "AppInstance", alternateId: extra.app, displayName: extra.app, detailEntry: { signOnModeType: "SAML_2_0" } }] : null,
    transaction: { type: "WEB", id: `tx${seq}` }, debugContext: { debugData: { requestUri: "/api/v1/authn", threatSuspected: extra.threat ? "true" : "false" } },
    authenticationContext: { authenticationProvider: null, credentialProvider: null, credentialType: type === "user.authentication.auth_via_mfa" ? "OTP" : "PASSWORD", issuer: null, interface: null, authenticationStep: 0, externalSessionId: `102${u.length}${seq}` },
    securityContext: { asNumber: g.asn, asOrg: g.isp, isp: g.isp, domain: g.isp.split(" ")[0].toLowerCase() + ".net", isProxy: !!g.proxy },
  });
  // Baseline: 7 staff over 10 working days, password then Okta Verify push within a minute.
  for (let d = 0; d < 14; d++) {
    const dayTs = EX_T0 + d * DAY; const dow = new Date(dayTs).getUTCDay(); if (dow === 0 || dow === 6) continue;
    for (const u of STAFF.slice(0, 7)) {
      const t = dayTs + Math.floor(R() * 7 * 60) * MIN; const ip = "86.43.10." + (30 + Math.floor(R() * 5));
      ev(t, "user.session.start", u, ip, geo.dublin, true); ev(t + 40000, "user.authentication.auth_via_mfa", u, ip, geo.dublin, true);
      if (R() < 0.5) ev(t + 90000, "user.authentication.sso", u, ip, geo.dublin, true, { app: R() < 0.5 ? "Salesforce" : "Slack" });
    }
  }
  // okta-admin: admin console without MFA, from a DigitalOcean host
  for (const d of [1, 4, 8]) { const t = EX_T0 + d * DAY + 3 * 60 * MIN; ev(t, "user.session.start", "okta.admin", "164.92.200.14", geo.frankfurt, true); ev(t + 20000, "user.session.access_admin_app", "okta.admin", "164.92.200.14", geo.frankfurt, true); }
  // Password spray from a Tor exit (securityContext.isProxy = true) across 12 users, then a success for user06 without MFA
  STAFF.forEach((u, i) => ev(EX_T0 + 5 * DAY + (-2 * 60 + i * 3) * MIN, "user.session.start", u, "185.220.101.52", geo.tor, false, { reason: "INVALID_CREDENTIALS", ua: "python-requests/2.31.0" }));
  for (let i = 0; i < 6; i++) ev(EX_T0 + 5 * DAY + (-80 + i) * MIN, "user.session.start", "user06", "185.220.101.52", geo.tor, false, { reason: "INVALID_CREDENTIALS", ua: "python-requests/2.31.0" });
  ev(EX_T0 + 5 * DAY + -72 * MIN, "user.session.start", "user06", "185.220.101.52", geo.tor, true, { threat: true, ua: "python-requests/2.31.0" });
  // Impossible travel for user03: Dublin then New York 35 minutes later, both with MFA
  const t2 = EX_T0 + 9 * DAY + 2 * 60 * MIN;
  ev(t2, "user.session.start", "user03", "86.43.10.31", geo.dublin, true); ev(t2 + 30000, "user.authentication.auth_via_mfa", "user03", "86.43.10.31", geo.dublin, true);
  ev(t2 + 35 * MIN, "user.session.start", "user03", "72.229.28.185", geo.nyc, true); ev(t2 + 35 * MIN + 30000, "user.authentication.auth_via_mfa", "user03", "72.229.28.185", geo.nyc, true);
  events.sort((a, b) => a.published.localeCompare(b.published));
  return JSON.stringify(events, null, 2);
}
