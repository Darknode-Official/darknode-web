// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Breach Clock (breachclock): Deck tool UI. An incident-facts form feeds the pure
// engine (breachclock-engine.js, run in a Worker), which returns every breach
// notification obligation that may apply with its deadline to the hour. Incidents
// live in a team-shareable register (core/register.js) mirrored into the Security
// Graph as INCIDENT entities. Runs entirely in the browser; the only network reads
// are this site's own reference files under /data/ref. No native dialogs.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { openRegister } from "../core/register.js";
import { download, toJson, fileStamp, toIcs } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, SECTORS, DATA_TYPES, COUNTRIES, EU_STATES, VERIFY_LINE, REGISTER_SCHEMA, INCIDENT_STATUSES,
  parseInput, parseCounts, analyze, findingsToCsv, checklistToCsv, icsEvents, exportBundle, summaryText, draftNotice,
  exampleDataset, snapshot, isValidTz, fmtDur,
} from "./breachclock-engine.js?v=20261017c";

const ENGINE = engineUrl("./breachclock-engine.js?v=20261017c", import.meta);
const P = "bnc";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const escD = (s) => esc(s).replace(/\d{4}-\d{2}-\d{2}/g, '<span class="bnc-nw">$&</span>');
const num = (n) => Number(n || 0).toLocaleString("en-US");
const STATUS_LABEL = { "not-started": "Not started", drafted: "Drafted", sent: "Sent", "not-required": "Not required" };
const URG_COLOR = { overdue: "#b00020", "due-24h": "#c0501b", "due-72h": "#b58100", later: "#2552c6", done: "#1b7f4d" };
const URG_LABEL = { overdue: "Overdue", "due-24h": "Under 24 h", "due-72h": "Under 72 h", later: "Later", done: "Done" };

const CSS = `
  .bnc-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .bnc-root *{box-sizing:border-box}
  .bnc-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .bnc-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .bnc-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--mut,#667085);border:1px solid var(--line,#e6e8ee);padding:2px 9px;border-radius:999px}
  .bnc-sub{color:var(--mut,#667085);margin:8px 0 6px;max-width:90ch;overflow-wrap:anywhere}
  .bnc-legal{border:1px solid var(--line,#e6e8ee);border-left:4px solid #b00020;border-radius:8px;padding:10px 14px;margin:8px 0 14px;font-weight:700;background:var(--card,#fff)}
  .bnc-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .bnc-card h2{font-size:1.02rem;margin:0 0 4px}
  .bnc-card h3{font-size:.88rem;margin:14px 0 6px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#667085)}
  .bnc-row{display:flex;flex-wrap:wrap;gap:8px 10px;align-items:center;margin-top:10px}
  .bnc-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:7px 13px;border-radius:8px;cursor:pointer}
  .bnc-btn:hover{border-color:var(--mut,#667085)}
  .bnc-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .bnc-btn.dang{color:#b00020}
  .bnc-btn:disabled{opacity:.5;cursor:default}
  .bnc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px 16px}
  .bnc-field{display:flex;flex-direction:column;gap:3px;min-width:0}
  .bnc-field.wide{grid-column:1/-1}
  .bnc-field>label,.bnc-lbl{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .bnc-root input[type=text],.bnc-root input[type=number],.bnc-root input[type=datetime-local],.bnc-root select,.bnc-root textarea{font:inherit;font-size:.86rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%;min-width:0}
  .bnc-root textarea{min-height:70px;resize:vertical;font-family:ui-monospace,Menlo,monospace;font-size:12.5px}
  .bnc-help{font-size:.75rem;color:var(--mut,#667085);margin:0;overflow-wrap:anywhere}
  .bnc-help.bad{color:#b00020}
  .bnc-chips{display:flex;flex-wrap:wrap;gap:6px}
  .bnc-chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line,#d7dbe3);border-radius:999px;padding:4px 11px;font-size:.8rem;cursor:pointer;user-select:none;background:var(--card,#fff);max-width:100%;overflow-wrap:anywhere}
  .bnc-chip input{margin:0}
  .bnc-chip.on{border-color:#2552c6;color:#2552c6;font-weight:600}
  .bnc-checks{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:4px 14px}
  .bnc-checks label{display:flex;gap:7px;align-items:flex-start;font-size:.84rem;cursor:pointer}
  .bnc-checks input{margin-top:3px}
  .bnc-jt{width:100%;border-collapse:collapse}
  .bnc-jt td{padding:3px 4px;vertical-align:top}
  .bnc-jt td:last-child{width:1%;white-space:nowrap}
  .bnc-jt td:nth-child(2){width:32%}
  .bnc-tbl{border:1px solid var(--line,#e6e8ee);border-radius:10px;overflow:auto;max-width:100%}
  .bnc-tbl table{width:100%;border-collapse:collapse;font-size:.84rem}
  .bnc-tbl th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 10px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .bnc-tbl th[data-sort]{cursor:pointer;user-select:none}
  .bnc-tbl th.sorted::after{content:" \\2193"}
  .bnc-tbl th.sorted.asc::after{content:" \\2191"}
  .bnc-tbl td{padding:8px 10px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .bnc-tbl tr.bnc-click{cursor:pointer}
  .bnc-tbl tr.bnc-click:hover td{background:var(--bg,#f7f8fb)}
  .bnc-tbl tr.sel td{background:var(--bg,#f2f4f8)}
  .bnc-tbl tr.dim td{opacity:.6}
  #bnc-obl table{min-width:760px}
  .bnc-tbl select{width:auto;min-width:118px;padding:4px 6px;font-size:.8rem}
  .bnc-pill{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .bnc-pill.likely{background:#b00020}.bnc-pill.possible{background:#b58100}.bnc-pill.not-indicated{background:#667085}
  .bnc-pill.critical{background:#7a0012}.bnc-pill.high{background:#b00020}.bnc-pill.medium{background:#b58100}
  .bnc-conf{font-size:.72rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;color:var(--mut,#667085);white-space:nowrap}
  .bnc-conf.verify{border-color:#b58100;color:#8a6d00;font-weight:700}
  .bnc-left{font-weight:700;white-space:nowrap}
  .bnc-mut{color:var(--mut,#667085);font-size:.78rem}
  .bnc-mono{font-family:ui-monospace,Menlo,monospace;font-size:.78rem}
  .bnc-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin:0 0 14px}
  .bnc-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .bnc-kpi b{display:block;font-size:1.3rem;line-height:1.25;overflow-wrap:anywhere}
  .bnc-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .bnc-kpi.alert b{color:#b00020}
  .bnc-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin:0 0 12px;display:none}
  .bnc-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .bnc-miss{border:1px solid var(--line,#e6e8ee);border-left:4px solid #b58100;border-radius:8px;padding:10px 14px;margin-bottom:14px;background:var(--card,#fff)}
  .bnc-miss ul,.bnc-drawer ul{margin:6px 0 0;padding-left:18px}
  .bnc-miss li,.bnc-drawer li{margin:2px 0;overflow-wrap:anywhere}
  .bnc-svg{width:100%;height:auto;display:block;border:1px solid var(--line,#e6e8ee);border-radius:8px;background:var(--bg,#f7f8fb)}
  .bnc-legend{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:.76rem;color:var(--mut,#667085);margin-top:6px}
  .bnc-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
  .bnc-drawer{display:none}
  .bnc-nw{white-space:nowrap}
  .bnc-drawer pre{white-space:pre-wrap;overflow-wrap:anywhere;font-family:ui-monospace,Menlo,monospace;font-size:12px;background:var(--bg,#f7f8fb);border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:10px 12px;max-height:360px;overflow:auto;margin:6px 0}
  .bnc-dl{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;margin:6px 0;font-size:.84rem}
  .bnc-dl dt{color:var(--mut,#667085)}
  .bnc-dl dd{margin:0;overflow-wrap:anywhere}
  .bnc-empty{padding:22px;text-align:center;color:var(--mut,#667085)}
  .bnc-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px;overflow-wrap:anywhere}
  .bnc-saved{font-size:.78rem;color:var(--mut,#667085)}
  .bnc-root details summary{cursor:pointer;font-size:.82rem;color:var(--mut,#667085);margin-top:8px}
  .bnc-root a{color:#2552c6;overflow-wrap:anywhere}
  @media(max-width:600px){.bnc-card{padding:12px}.bnc-dl{grid-template-columns:1fr}.bnc-dl dt{margin-top:6px}}
`;

const kpi = (v, l, alert) => '<div class="' + P + "-kpi" + (alert ? " alert" : "") + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const field = (id, label, input, help, wide) => '<div class="' + P + "-field" + (wide ? " wide" : "") + '"><label for="' + P + "-" + id + '">' + esc(label) + "</label>" + input + (help ? '<p class="' + P + '-help" id="' + P + "-" + id + '-help">' + esc(help) + "</p>" : "") + "</div>";
const select = (id, opts, extra) => '<select id="' + P + "-" + id + '"' + (extra || "") + ">" + opts.map(([v, l]) => '<option value="' + esc(v) + '">' + esc(l) + "</option>").join("") + "</select>";
const dt = (id) => '<input type="datetime-local" id="' + P + "-" + id + '">';

/** Mount the tool into main. */
export function renderBreachClock(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  const localTz = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (_) { return ""; } })();
  const zones = (() => { try { return Intl.supportedValuesOf("timeZone"); } catch (_) { return ["UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles", "Europe/London", "Europe/Dublin", "Europe/Berlin", "Europe/Paris", "Asia/Kolkata", "Australia/Sydney"]; } })();

  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Breach Clock</h1><span class="', P, '-tag">Breach notification</span></div>',
    '<p class="', P, '-sub">Works out which breach notification obligations may apply to an incident, each deadline to the hour, and who must be told. Runs entirely in your browser. Nothing is uploaded. Reference data is read from this site only (/data/ref): <span id="', P, '-refv">loading</span>.</p>',
    '<div class="', P, '-legal">', esc(VERIFY_LINE), "</div>",

    // Incident register
    '<div class="', P, '-card"><h2>Incidents</h2><p class="', P, '-help">Saved incidents. In a team workspace every member sees the same list through the Security Graph.</p>',
    '<div class="', P, '-tbl" style="margin-top:8px" id="', P, '-reglist"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-new">New incident</button><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button>',
    '<button class="', P, '-btn" id="', P, '-regcsv">Export register CSV</button></div>',
    '<div style="margin-top:12px" id="', P, '-drop"></div>',
    '<p class="', P, '-help" style="margin-top:6px">Import a Breach Clock obligations JSON exported earlier, or a jurisdiction,count CSV to fill the table below.</p></div>',

    // Facts form
    '<div class="', P, '-card" id="', P, '-form"><h2 id="', P, '-formtitle">New incident</h2><p class="', P, '-help">Fill in what you know. Missing facts are listed with the results; nothing is assumed.</p>',
    "<h3>Incident</h3><div class=\"", P, '-grid">',
    field("title", "Incident title", '<input type="text" id="' + P + '-title" placeholder="Short name">', "Used in the register, calendar and notice drafts."),
    field("status", "Incident status", select("status", INCIDENT_STATUSES.map((s) => [s, s[0].toUpperCase() + s.slice(1)])), "Open, notified (notices sent) or closed."),
    field("tz", "Time zone", '<input type="text" id="' + P + '-tz" list="' + P + '-tzlist" placeholder="e.g. America/Chicago" autocomplete="off"><datalist id="' + P + '-tzlist">' + zones.map((z) => '<option value="' + esc(z) + '">').join("") + "</datalist>",
      "IANA zone the times below are in. Empty means UTC." + (localTz ? " Your browser: " + localTz + "." : "")),
    "</div>",
    localTz ? '<div class="' + P + '-row" style="margin-top:6px"><button class="' + P + '-btn" id="' + P + '-mytz" type="button">Use ' + esc(localTz) + "</button></div>" : "",

    "<h3>Organisation sector</h3>",
    '<div class="', P, '-chips" id="', P, '-sectors">', SECTORS.map((s) => '<label class="' + P + '-chip"><input type="checkbox" value="' + esc(s.id) + '">' + esc(s.label) + "</label>").join(""), "</div>",
    '<p class="', P, '-help" style="margin-top:4px">Pick every one that fits. Each decides which regimes are checked.</p>',
    '<div class="', P, '-grid" style="margin-top:10px">',
    field("ms", "EU member state", select("ms", [["", "Not set"]].concat(Object.values(EU_STATES).sort().map((n) => [n, n]))), "Names the supervisory authority (GDPR) and the CSIRT (NIS2)."),
    field("nis2sig", "NIS2 significant incident", select("nis2sig", [["unknown", "Not yet decided"], ["yes", "Yes, significant"], ["no", "No, not significant"]]), "Art. 23(3): severe disruption or financial loss, or considerable damage to others."),
    "</div>",

    "<h3>Data involved</h3>",
    '<div class="', P, '-checks" id="', P, '-types">', DATA_TYPES.map((t) => '<label><input type="checkbox" value="' + esc(t.id) + '"><span>' + esc(t.label) + "</span></label>").join(""), "</div>",
    '<div class="', P, '-grid" style="margin-top:10px">',
    field("enc", "Encrypted, key not compromised", select("enc", [["unknown", "Unknown"], ["yes", "Yes"], ["no", "No"]]), "Yes only if the data was encrypted and the key was not also exposed."),
    field("harm", "Risk to individuals", select("harm", [["unknown", "Not yet assessed"], ["unlikely", "Unlikely to cause harm"], ["risk", "Risk of harm"], ["high", "High risk / serious harm"]]), "Your documented harm assessment; GDPR, PIPEDA and the Australian scheme turn on it."),
    "</div>",

    "<h3>Affected individuals</h3>",
    '<div class="', P, '-grid">',
    field("total", "Total affected", '<input type="number" min="0" step="1" id="' + P + '-total" placeholder="Count">', "Leave empty to use the sum of the table."),
    "</div>",
    '<p class="', P, '-lbl" style="margin:10px 0 4px">Per US state or country</p>',
    '<datalist id="', P, '-jlist"></datalist>',
    '<table class="', P, '-jt"><tbody id="', P, '-jrows"></tbody></table>',
    '<p class="', P, '-help">US states by name or code (CA = California). Countries by full name (Canada, Germany, India).</p>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-jadd" type="button">Add row</button></div>',
    '<div class="', P, '-field" style="margin-top:8px"><label for="', P, '-jpaste">Paste rows</label><textarea id="', P, '-jpaste" placeholder="California,1200"></textarea>',
    '<p class="', P, '-help">One jurisdiction,count per line (comma, tab or semicolon). A header row is ignored.</p></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-jpastebtn" type="button">Add pasted rows</button></div>',

    "<h3>Timeline</h3><div class=\"", P, '-grid">',
    field("occ", "Incident occurred", dt("occ"), "Optional. Best estimate of when it started."),
    field("disc", "Discovered", dt("disc"), "When you first learned of it. Most clocks start here."),
    field("det", "Determined / confirmed breach", dt("det"), "When you confirmed it is a breach. NYDFS, PIPEDA and some states start here."),
    field("mat", "Determined material (SEC)", dt("mat"), "Starts the four-business-day Form 8-K clock."),
    field("ransom", "Extortion payment made", dt("ransom"), "Only if paid. NYDFS 24-hour and 30-day notices."),
    "</div>",

    "<h3>Law enforcement</h3>",
    '<div class="', P, '-checks"><label><input type="checkbox" id="', P, '-le"><span>Law enforcement asked us to delay notice</span></label>',
    '<label><input type="checkbox" id="', P, '-leag"><span>Written US Attorney General determination (SEC Item 1.05(c))</span></label></div>',
    '<div class="', P, '-grid" style="margin-top:8px">',
    field("lefrom", "Delay starts", dt("lefrom"), "Empty means from each clock's trigger."),
    field("leuntil", "Delay ends", dt("leuntil"), "Needed to compute paused deadlines."),
    "</div>",

    "<h3>Notes</h3>",
    '<div class="', P, '-field"><label for="', P, '-notes">Incident notes</label><textarea id="', P, '-notes" placeholder="Notes"></textarea><p class="', P, '-help">Saved with the incident and shared in team workspaces.</p></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-save" type="button">Save incident</button><button class="', P, '-btn dang" id="', P, '-del" type="button">Delete incident</button><span class="', P, '-saved" id="', P, '-savedmsg"></span></div>',
    "</div>",

    // Thresholds
    '<div class="', P, '-card"><h2>Alert windows</h2><div class="', P, '-grid">',
    field("opt-dueSoonHours", "Due-soon window (hours)", '<input type="number" min="1" id="' + P + '-opt-dueSoonHours" data-opt="dueSoonHours" value="' + DEFAULTS.dueSoonHours + '">', "Default " + DEFAULTS.dueSoonHours + ". Deadlines inside it become medium findings."),
    field("opt-urgentHours", "Urgent window (hours)", '<input type="number" min="1" id="' + P + '-opt-urgentHours" data-opt="urgentHours" value="' + DEFAULTS.urgentHours + '">', "Default " + DEFAULTS.urgentHours + ". Deadlines inside it become high findings; overdue is critical."),
    "</div></div>",

    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div>',
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div id="', P, '-missing"></div>',
    '<div class="', P, '-card"><h2>Countdown</h2><div id="', P, '-timeline"><div class="', P, '-empty">Enter the discovery time to see deadlines.</div></div></div>',
    '<div class="', P, '-card"><h2>Obligations</h2>',
    '<div class="', P, '-row" style="margin:0 0 8px"><label class="', P, '-chip"><input type="checkbox" id="', P, '-shownot">Show not indicated</label><span class="', P, '-mut">Click a row for the reasons, conditions, source and a notice template.</span></div>',
    '<div class="', P, '-tbl" id="', P, '-obl"><div class="', P, '-empty">No assessment yet.</div></div>',
    '<div class="', P, '-skip" id="', P, '-skipped"></div></div>',
    '<div class="', P, '-card ', P, '-drawer" id="', P, '-drawer"></div>',
    '<div class="', P, '-card"><h2>Exports</h2><div class="', P, '-row" id="', P, '-exports" style="margin-top:4px"></div></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  const root = main.querySelector("." + P + "-root");
  const reg = openRegister(TOOL_ID, "INCIDENT", { schema: REGISTER_SCHEMA });
  let refs = { breachLaws: null, holidays: null };
  let record = blankRecord();
  let result = null, isExample = false, selId = null, sort = { key: null, asc: true }, seq = 0, timer = 0, saveTimer = 0;

  function blankRecord() { return { title: "", status: "open", facts: {}, statuses: {}, notes: "" }; }
  const opts = () => {
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (Number.isFinite(n) && n > 0) o[el.dataset.opt] = n; });
    return { ...o, breachLaws: refs.breachLaws, holidays: refs.holidays, now: new Date().toISOString() };
  };

  // ---- reference data ----------------------------------------------------------
  Promise.all(["/data/ref/us-breach-laws.json", "/data/ref/us-holidays.json"].map((u) => fetch(u).then((r) => (r.ok ? r.json() : null)).catch(() => null)))
    .then(([laws, hol]) => {
      refs = { breachLaws: laws, holidays: hol };
      const v = [];
      v.push(laws ? "US breach laws " + (laws.version || "") + " (updated " + (laws.updated || "?") + ")" : "US breach laws not loaded");
      v.push(hol ? "US federal holidays " + (hol.version || "") : "US federal holidays not loaded");
      $("refv").textContent = "reference data " + v.join(", ") + "; verify with counsel";
      fillJurisdictionList();
      renderRegister();
      assessNow();
    });

  function fillJurisdictionList() {
    const st = refs.breachLaws && Array.isArray(refs.breachLaws.data) ? refs.breachLaws.data.map((x) => x.jurisdiction) : [];
    $("jlist").innerHTML = st.concat(Object.values(COUNTRIES)).sort().map((n) => '<option value="' + esc(n) + '">').join("");
  }

  // ---- facts form ---------------------------------------------------------------
  function jRow(j, c) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td><input type="text" list="' + P + '-jlist" placeholder="State or country" aria-label="Jurisdiction" value="' + esc(j || "") + '"></td>' +
      '<td><input type="number" min="0" step="1" placeholder="Count" aria-label="Affected in this jurisdiction" value="' + esc(c == null ? "" : c) + '"></td>' +
      '<td><button class="' + P + '-btn" type="button" aria-label="Remove row">Remove</button></td>';
    tr.querySelector("button").addEventListener("click", () => { tr.remove(); changed(); });
    $("jrows").appendChild(tr);
  }

  function readForm() {
    const v = (id) => ($(id).value || "").trim();
    const counts = [...$("jrows").querySelectorAll("tr")].map((tr) => { const [a, b] = tr.querySelectorAll("input"); return { jurisdiction: a.value.trim(), count: b.value.trim() }; })
      .filter((r) => r.jurisdiction || r.count);
    const facts = {
      title: v("title"),
      sectors: [...$("sectors").querySelectorAll("input:checked")].map((i) => i.value),
      memberState: v("ms"), nis2Significant: v("nis2sig"),
      dataTypes: [...$("types").querySelectorAll("input:checked")].map((i) => i.value),
      encrypted: v("enc"), harm: v("harm"), total: v("total"), counts,
      timeZone: v("tz"), occurredAt: v("occ"), discoveredAt: v("disc"), determinedAt: v("det"), materialityAt: v("mat"), ransomPaidAt: v("ransom"),
      leDelay: { requested: $("le").checked, from: v("lefrom"), until: v("leuntil"), agDetermination: $("leag").checked },
    };
    record = { ...record, title: facts.title, status: v("status") || "open", facts, notes: $("notes").value };
    return record;
  }

  function writeForm(rec) {
    const f = rec.facts || {};
    const set = (id, val) => { $(id).value = val == null ? "" : val; };
    set("title", rec.title || f.title || ""); set("status", rec.status || "open"); set("tz", f.timeZone || "");
    set("ms", f.memberState || ""); set("nis2sig", f.nis2Significant || "unknown"); set("enc", f.encrypted || "unknown"); set("harm", f.harm || "unknown");
    set("total", f.total == null ? "" : f.total); set("occ", f.occurredAt); set("disc", f.discoveredAt); set("det", f.determinedAt); set("mat", f.materialityAt); set("ransom", f.ransomPaidAt);
    const le = f.leDelay || {};
    $("le").checked = !!le.requested; $("leag").checked = !!le.agDetermination; set("lefrom", le.from); set("leuntil", le.until);
    set("notes", rec.notes || "");
    $("sectors").querySelectorAll("input").forEach((i) => { i.checked = (f.sectors || []).includes(i.value); i.parentElement.classList.toggle("on", i.checked); });
    $("types").querySelectorAll("input").forEach((i) => { i.checked = (f.dataTypes || []).includes(i.value); });
    $("jrows").innerHTML = "";
    for (const r of f.counts || []) jRow(r.jurisdiction, r.count);
    if (!(f.counts || []).length) jRow("", null);
    $("formtitle").textContent = rec.id ? "Incident: " + (rec.title || "Untitled") : isExample ? "Example incident (synthetic, not saved)" : "New incident";
    $("del").disabled = !rec.id;
    $("save").disabled = isExample;
    $("savedmsg").textContent = isExample ? "Synthetic example: not saved to the register or the Security Graph." : rec.updatedAt ? "Saved " + rec.updatedAt.slice(0, 16).replace("T", " ") + " UTC" : "";
    tzHelp();
  }

  function tzHelp() {
    const z = $("tz").value.trim(), h = $("tz-help");
    if (z && !isValidTz(z)) { h.textContent = "Not a recognised IANA time zone; times are read as UTC."; h.classList.add("bad"); }
    else { h.textContent = "IANA zone the times below are in. Empty means UTC." + (localTz ? " Your browser: " + localTz + "." : ""); h.classList.remove("bad"); }
  }

  function changed() {
    readForm();
    tzHelp();
    clearTimeout(timer);
    timer = setTimeout(assessNow, 250);
    if (record.id && !isExample) { clearTimeout(saveTimer); saveTimer = setTimeout(() => save(true), 1200); }
  }

  $("form").addEventListener("input", (e) => { if (e.target.closest("#" + P + "-jpaste")) return; changed(); });
  $("form").addEventListener("change", (e) => {
    if (e.target.closest("#" + P + "-sectors")) e.target.parentElement.classList.toggle("on", e.target.checked);
    if (e.target.closest("#" + P + "-jpaste")) return;
    changed();
  });
  main.querySelectorAll("[data-opt]").forEach((el) => el.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(assessNow, 250); }));
  if ($("mytz")) $("mytz").addEventListener("click", () => { $("tz").value = localTz; changed(); });
  $("jadd").addEventListener("click", () => jRow("", null));
  $("jpastebtn").addEventListener("click", () => {
    const r = parseCounts($("jpaste").value);
    if (!r.rows.length) { toast("No jurisdiction,count rows found", "warning"); return; }
    addCounts(r.rows);
    $("jpaste").value = "";
    toast("Added " + r.rows.length + " row(s)" + (r.skipped.length ? "; skipped " + r.skipped.length + " (line " + r.skipped.map((s) => s.line).join(", ") + ")" : ""), r.skipped.length ? "warning" : "success");
  });

  function addCounts(rows) {
    [...$("jrows").querySelectorAll("tr")].forEach((tr) => { const [a, b] = tr.querySelectorAll("input"); if (!a.value.trim() && !b.value.trim()) tr.remove(); });
    for (const r of rows) jRow(r.jurisdiction, r.count);
    changed();
  }

  // ---- register ----------------------------------------------------------------
  function renderRegister() {
    const list = reg.list();
    const box = $("reglist");
    if (!list.length) { box.innerHTML = '<div class="' + P + '-empty">No saved incidents yet. Fill in the form and save it.</div>'; return; }
    const o = opts();
    const rows = list.map((r) => {
      let a = null;
      try { a = analyze(r, o).assessment; } catch (_) {}
      return { r, a };
    }).sort((x, y) => String(y.r.updatedAt || "").localeCompare(String(x.r.updatedAt || "")));
    box.innerHTML = "<table><thead><tr><th>Incident</th><th>Status</th><th>Next deadline</th><th>Overdue</th><th>Obligations</th><th>Updated</th></tr></thead><tbody>" +
      rows.map(({ r, a }) => '<tr class="' + P + "-click" + (r.id === record.id ? " sel" : "") + '" data-id="' + esc(r.id) + '"><td><b>' + esc(r.title || "Untitled") + "</b></td><td>" + esc(r.status || "open") + "</td><td>" +
        (a && a.nextDeadline ? escD(a.nextDeadline.deadlineLocal) + '<div class="' + P + '-mut">' + esc(a.nextDeadline.recipient) + "</div>" : '<span class="' + P + '-mut">none fixed</span>') + "</td><td" + (a && a.counts.overdue ? ' style="color:#b00020;font-weight:700"' : "") + ">" + (a ? a.counts.overdue : "") + "</td><td>" +
        (a ? a.counts.likely + a.counts.possible : "") + '</td><td class="' + P + '-mut">' + esc(String(r.updatedAt || "").slice(0, 16).replace("T", " ")) + "</td></tr>").join("") + "</tbody></table>";
    box.querySelectorAll("tr[data-id]").forEach((tr) => tr.addEventListener("click", () => {
      const r = reg.get(tr.dataset.id);
      if (!r) return;
      isExample = false; selId = null; record = { ...r }; writeForm(record); renderRegister(); assessNow();
      $("form").scrollIntoView({ behavior: "smooth", block: "start" });
    }));
  }
  reg.subscribe(() => renderRegister());
  reg.ready.then(() => reg.backfill()).then(() => renderRegister()).catch(() => {});

  function save(quiet) {
    if (isExample) { if (!quiet) toast("The synthetic example is not saved. Start a new incident for real data.", "warning"); return; }
    readForm();
    if (!record.title) { if (!quiet) toast("Give the incident a title first", "warning"); $("title").focus(); return; }
    const a = result && result.assessment;
    const rec = a ? snapshot(record, a) : record;
    const saved = reg.upsert(rec);
    record = { ...saved };
    $("savedmsg").textContent = "Saved " + saved.updatedAt.slice(0, 16).replace("T", " ") + " UTC";
    $("formtitle").textContent = "Incident: " + saved.title;
    $("del").disabled = false;
    renderRegister();
    if (!quiet) toast("Incident saved", "success");
  }
  $("save").addEventListener("click", () => save(false));
  $("del").addEventListener("click", async () => {
    if (!record.id) return;
    const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Delete incident?", "This removes \"" + (record.title || "Untitled") + "\" and its obligation statuses from the register and the Security Graph.", { danger: true }) : false;
    if (!ok) return;
    reg.remove(record.id);
    record = blankRecord(); isExample = false; selId = null;
    writeForm(record); renderRegister(); assessNow();
    toast("Incident deleted", "success");
  });
  $("new").addEventListener("click", () => {
    record = blankRecord(); isExample = false; selId = null;
    writeForm(record); renderRegister(); assessNow();
    $("title").focus();
  });
  $("example").addEventListener("click", () => {
    const ex = exampleDataset(7, new Date().toISOString());
    isExample = true; selId = null;
    record = { ...ex.record, id: undefined };
    delete record.id;
    writeForm(record); renderRegister(); assessNow();
    toast("Loaded synthetic example", "info");
  });
  $("regcsv").addEventListener("click", () => {
    if (!reg.count()) { toast("No saved incidents to export", "warning"); return; }
    download(TOOL_ID + "-register-" + fileStamp() + ".csv", reg.exportCsv(), "text/csv");
  });

  mountDropzone($("drop"), {
    maxBytes: 8 << 20, maxFiles: 5, unpack: true, accept: ".json,.csv,.txt,.tsv",
    label: "Drop an exported incident JSON or a jurisdiction CSV",
    onFiles: async (files) => {
      const parsed = parseInput(await Promise.all(files.map(async (f) => ({ name: f.name, text: await f.text() }))));
      for (const s of parsed.skipped) toast(s.check + ": " + s.reason, "warning");
      if (parsed.format === "breachclock-incident") {
        const inc = parsed.rows[0];
        isExample = false; selId = null;
        record = { title: inc.title || (inc.facts && inc.facts.title) || "", status: inc.status || "open", facts: inc.facts || {}, statuses: inc.statuses || {}, notes: inc.notes || "" };
        if (inc.id && reg.get(inc.id)) record.id = inc.id;
        writeForm(record); assessNow();
        toast("Imported incident" + (record.id ? " (matches a saved incident; Save to update it)" : "; Save to add it to the register"), "success");
      } else if (parsed.format === "jurisdiction-counts") {
        addCounts(parsed.rows.map((r) => ({ jurisdiction: r.jurisdiction, count: r.count })));
        toast("Added " + parsed.rows.length + " jurisdiction row(s)", "success");
      } else toast("Nothing importable found", "error");
    },
  });

  // ---- assessment ----------------------------------------------------------------
  async function assessNow() {
    readForm();
    const my = ++seq;
    const prog = $("prog"), bar = prog.firstElementChild;
    prog.style.display = "block"; bar.style.width = "30%";
    try {
      const r = await runInWorker(ENGINE, "analyze", [record, opts()], { onProgress: (i, n) => { bar.style.width = (n ? Math.round(i / n * 100) : 0) + "%"; } });
      if (my !== seq) return;
      result = r;
      render();
    } catch (e) {
      try { if (my === seq) { result = analyze(record, opts()); render(); } } catch (err) { toast("Assessment failed: " + (err && err.message || err), "error"); }
    } finally { if (my === seq) prog.style.display = "none"; }
  }

  // Live countdown: recompute time left every 30 s on the main thread (pure, fast).
  const tick = setInterval(() => {
    if (!root.isConnected) { clearInterval(tick); return; }
    if (!result) return;
    try { result = analyze(record, opts()); render(true); } catch (_) {}
  }, 30000);

  function urgencyOf(ob) { return ob.status === "sent" || ob.status === "not-required" ? "done" : ob.urgency; }
  function leftText(ob) {
    if (ob.status === "sent") return "Sent";
    if (ob.status === "not-required") return "Not required";
    if (ob.timeLeftHours == null) return ob.deadline ? "" : "No fixed deadline";
    return ob.timeLeftHours < 0 ? "Overdue " + fmtDur(-ob.timeLeftHours) : fmtDur(ob.timeLeftHours);
  }

  function render(fromTick) {
    const a = result.assessment;
    const sum = summarize(result.findings);
    const next = a.nextDeadline;
    $("kpis").innerHTML = kpi(a.counts.likely, "likely") + kpi(a.counts.possible, "possible") + kpi(a.counts.notIndicated, "not indicated") +
      kpi(a.counts.overdue, "overdue", a.counts.overdue > 0) + kpi(a.counts.due24h, "due under 24 h", a.counts.due24h > 0) + kpi(sum.total, "findings") +
      kpi(next ? fmtDur((Date.parse(next.deadline) - Date.parse(a.now)) / 3600000) : "none", "to next deadline");
    $("missing").innerHTML = a.missing.length ? '<div class="' + P + '-miss"><b>Facts still needed (' + a.missing.length + ")</b><ul>" + a.missing.map((m) => "<li><b>" + esc(m.label) + ":</b> " + esc(m.why) + "</li>").join("") + "</ul></div>" : "";
    renderTimeline(a);
    renderTable(a);
    const sk = a.skipped.map((s) => s.check + " (" + s.reason + ")").concat(a.notes);
    $("skipped").textContent = sk.length ? "Not assessed / notes: " + sk.join("; ") : "";
    if (!fromTick) renderExports(a);
    if (selId) openDrawer(selId, true);
  }

  function renderTimeline(a) {
    const box = $("timeline");
    const items = a.obligations.filter((o) => o.applies !== "not-indicated" && o.deadline);
    if (!items.length) { box.innerHTML = '<div class="' + P + '-empty">' + (a.missing.some((m) => m.field === "discoveredAt") ? "Enter the discovery time to see deadlines." : "No obligation with a fixed deadline is indicated. See the table for duties without one.") + "</div>"; return; }
    items.sort((x, y) => (x.deadline < y.deadline ? -1 : x.deadline > y.deadline ? 1 : 0));
    const now = Date.parse(a.now);
    const starts = items.map((o) => (o.triggerTime ? Date.parse(o.triggerTime) : now));
    let t0 = Math.min(now, ...starts), t1 = Math.max(now, ...items.map((o) => Date.parse(o.deadline)));
    const span = Math.max(t1 - t0, 3600000); t0 -= span * 0.02; t1 += span * 0.04;
    const W = 1000, L = 300, R = 980, rowH = 30, top = 34, H = top + items.length * rowH + 12;
    const x = (t) => L + (R - L) * (t - t0) / (t1 - t0);
    const d = (t) => new Date(t).toISOString().slice(5, 10);
    const ticks = [];
    for (let i = 0; i <= 4; i++) { const t = t0 + (t1 - t0) * i / 4; ticks.push('<line x1="' + x(t) + '" x2="' + x(t) + '" y1="' + (top - 6) + '" y2="' + (H - 8) + '" stroke="currentColor" stroke-opacity=".12"/><text x="' + x(t) + '" y="' + (top - 12) + '" font-size="13" text-anchor="middle" fill="currentColor" fill-opacity=".6">' + d(t) + "</text>"); }
    const rows = items.map((o, i) => {
      const y = top + i * rowH + rowH / 2;
      const s = o.triggerTime ? Date.parse(o.triggerTime) : now, e = Date.parse(o.deadline);
      const c = URG_COLOR[urgencyOf(o)] || "#667085";
      const lab = (o.regime + ": " + o.recipient);
      return '<g data-id="' + esc(o.id) + '" style="cursor:pointer"><title>' + esc(lab + " - due " + o.deadlineLocal + " - " + leftText(o)) + "</title>" +
        '<text x="8" y="' + (y + 4) + '" font-size="13" fill="currentColor">' + esc(lab.length > 40 ? lab.slice(0, 39) + "..." : lab) + "</text>" +
        '<rect x="' + Math.min(x(s), x(e)) + '" y="' + (y - 6) + '" width="' + Math.max(2, Math.abs(x(e) - x(s))) + '" height="12" rx="3" fill="' + c + '" fill-opacity=".28"/>' +
        '<circle cx="' + x(e) + '" cy="' + y + '" r="6" fill="' + c + '"/></g>';
    }).join("");
    const nowLine = '<line x1="' + x(now) + '" x2="' + x(now) + '" y1="' + (top - 6) + '" y2="' + (H - 6) + '" stroke="#b00020" stroke-width="2"/><text x="' + x(now) + '" y="' + (H - 0) + '" font-size="12" text-anchor="middle" fill="#b00020">now</text>';
    box.innerHTML = '<svg class="' + P + '-svg" viewBox="0 0 ' + W + " " + (H + 6) + '" role="img" aria-label="Deadline timeline, ' + items.length + ' deadlines; text list below">' + ticks.join("") + rows + nowLine + "</svg>" +
      '<div class="' + P + '-legend">' + Object.keys(URG_COLOR).map((k) => '<span><i style="background:' + URG_COLOR[k] + '"></i>' + URG_LABEL[k] + "</span>").join("") + "<span>Bars run from each clock's trigger to its deadline. Times in " + esc(a.timeZone) + ".</span></div>" +
      "<details><summary>Timeline as text</summary><ol>" + items.map((o) => "<li>" + esc(o.deadlineLocal) + " (" + esc(o.deadline.slice(0, 16).replace("T", " ")) + " UTC): " + esc(o.regime) + " to " + esc(o.recipient) + " - " + esc(leftText(o)) + " [" + esc(o.applies) + "]</li>").join("") + "</ol></details>";
    box.querySelectorAll("g[data-id]").forEach((g) => g.addEventListener("click", () => openDrawer(g.dataset.id)));
  }

  const SORTERS = {
    regime: (o) => o.regime + " " + o.recipient, recipient: (o) => o.recipient,
    deadline: (o) => o.deadline || "9999", left: (o) => (o.timeLeftHours == null ? 1e12 : o.timeLeftHours),
    applies: (o) => ({ likely: 0, possible: 1, "not-indicated": 2 }[o.applies]), confidence: (o) => o.confidence, status: (o) => o.status,
  };

  function renderTable(a) {
    const box = $("obl");
    let list = a.obligations.filter((o) => $("shownot").checked || o.applies !== "not-indicated");
    if (!list.length) { box.innerHTML = '<div class="' + P + '-empty">' + (a.obligations.length ? "Only not-indicated obligations; tick Show not indicated." : "No regimes in scope yet. Pick a sector or add affected jurisdictions.") + "</div>"; return; }
    if (sort.key) {
      const f = SORTERS[sort.key];
      list = list.slice().sort((x, y) => { const p = f(x), q = f(y); return (p < q ? -1 : p > q ? 1 : 0) * (sort.asc ? 1 : -1); });
    }
    const th = (k, l) => '<th data-sort="' + k + '"' + (sort.key === k ? ' class="sorted' + (sort.asc ? " asc" : "") + '"' : "") + ">" + l + "</th>";
    box.innerHTML = "<table><thead><tr>" + th("regime", "Regime") + th("recipient", "Recipient") + th("deadline", "Deadline") + th("left", "Time left") + th("applies", "Applies") + th("confidence", "Confidence") + th("status", "Status") + "</tr></thead><tbody>" +
      list.map((o) => {
        const u = urgencyOf(o);
        return '<tr class="' + P + "-click" + (o.id === selId ? " sel" : "") + (o.applies === "not-indicated" ? " dim" : "") + '" data-id="' + esc(o.id) + '"><td><b>' + esc(o.regime) + '</b><div class="' + P + '-mut">' + esc(o.citation) + "</div></td><td>" + esc(o.recipient) + "</td><td>" +
          (o.deadline ? escD(o.deadlineLocal) + '<div class="' + P + '-mut ' + P + '-mono">' + escD(o.deadline.slice(0, 16).replace("T", " ")) + " UTC</div>" + (o.deadlineEt ? '<div class="' + P + '-mut">' + esc(o.deadlineEt) + "</div>" : "") : '<span class="' + P + '-mut">' + esc(o.clock) + "</span>") + "</td>" +
          '<td><span class="' + P + '-left" style="color:' + (URG_COLOR[u] || "inherit") + '">' + esc(leftText(o)) + "</span></td>" +
          '<td><span class="' + P + "-pill " + esc(o.applies) + '">' + esc(o.applies.replace("-", " ")) + "</span></td>" +
          '<td><span class="' + P + "-conf " + esc(o.confidence) + '">' + esc(o.confidence) + "</span></td>" +
          '<td><select data-st="' + esc(o.id) + '" aria-label="Status">' + Object.entries(STATUS_LABEL).map(([k, l]) => '<option value="' + k + '"' + (o.status === k ? " selected" : "") + ">" + l + "</option>").join("") + "</select>" +
          (o.statusAt ? '<div class="' + P + '-mut">' + esc(String(o.statusAt).slice(0, 16).replace("T", " ")) + "</div>" : "") + "</td></tr>";
      }).join("") + "</tbody></table>";
    box.querySelectorAll("th[data-sort]").forEach((h) => h.addEventListener("click", () => { const k = h.dataset.sort; sort = { key: k, asc: sort.key === k ? !sort.asc : true }; renderTable(a); }));
    box.querySelectorAll("select[data-st]").forEach((s) => {
      s.addEventListener("click", (e) => e.stopPropagation());
      s.addEventListener("change", () => setStatus(s.dataset.st, { state: s.value }));
    });
    box.querySelectorAll("tr[data-id]").forEach((tr) => tr.addEventListener("click", () => openDrawer(tr.dataset.id)));
  }
  $("shownot").addEventListener("change", () => result && renderTable(result.assessment));

  function setStatus(id, patch) {
    const prev = (record.statuses || {})[id] || {};
    const next = { ...prev, ...patch };
    if (patch.state === "sent" && !prev.at) next.at = new Date().toISOString();
    if (patch.state && patch.state !== "sent" && patch.state !== "not-required") delete next.at;
    if (patch.state && patch.state !== "not-required") delete next.reason;
    record.statuses = { ...(record.statuses || {}), [id]: next };
    if (next.state === "not-started" && !next.at && !next.reason) delete record.statuses[id];
    assessNow();
    if (record.id && !isExample) { clearTimeout(saveTimer); saveTimer = setTimeout(() => save(true), 600); }
  }

  function openDrawer(id, keep) {
    const ob = result && result.assessment.obligations.find((o) => o.id === id);
    const d = $("drawer");
    if (!ob) { d.style.display = "none"; selId = null; return; }
    selId = id;
    const st = (record.statuses || {})[id] || {};
    const localInput = (iso) => { if (!iso) return ""; const t = new Date(iso); if (isNaN(t)) return ""; const p = (n) => String(n).padStart(2, "0"); return t.getFullYear() + "-" + p(t.getMonth() + 1) + "-" + p(t.getDate()) + "T" + p(t.getHours()) + ":" + p(t.getMinutes()); };
    d.innerHTML = '<div class="' + P + '-row" style="margin-top:0;justify-content:space-between"><h2 style="margin:0">' + esc(ob.regime) + ": " + esc(ob.recipient) + '</h2><button class="' + P + '-btn" id="' + P + '-dclose" type="button">Close</button></div>' +
      '<p class="' + P + '-help">' + esc(VERIFY_LINE) + "</p>" +
      '<dl class="' + P + '-dl"><dt>Applies</dt><dd><span class="' + P + "-pill " + esc(ob.applies) + '">' + esc(ob.applies) + "</span> (" + esc(ob.confidence) + ")</dd>" +
      "<dt>Citation</dt><dd>" + esc(ob.citation) + (ob.sourceUrl ? ' - <a href="' + esc(ob.sourceUrl) + '" target="_blank" rel="noopener noreferrer">open source</a>' : "") + "</dd>" +
      "<dt>Trigger</dt><dd>" + esc(ob.trigger) + (ob.triggerLocal ? " - " + esc(ob.triggerLocal) : "") + "</dd>" +
      "<dt>Clock</dt><dd>" + esc(ob.clock) + " (" + esc(ob.deadlineKind) + ")</dd>" +
      "<dt>Deadline</dt><dd>" + (ob.deadline ? esc(ob.deadlineLocal) + " / " + esc(ob.deadline) + (ob.deadlineEt ? " / " + esc(ob.deadlineEt) : "") + " - " + esc(leftText(ob)) : "No fixed deadline: " + esc(ob.clock)) + "</dd>" +
      (ob.lawEnforcementDelay ? "<dt>Delay</dt><dd>Paused " + esc(ob.lawEnforcementDelay.pausedHours) + " h for law enforcement</dd>" : "") + "</dl>" +
      "<h3>Why</h3><ul>" + ob.why.map((w) => "<li>" + esc(w) + "</li>").join("") + "</ul>" +
      (ob.conditions.length ? "<h3>Conditions and exceptions</h3><ul>" + ob.conditions.map((w) => "<li>" + esc(w) + "</li>").join("") + "</ul>" : "") +
      "<h3>Status</h3><div class=\"" + P + '-grid">' +
      field("dst", "Status", '<select id="' + P + '-dst">' + Object.entries(STATUS_LABEL).map(([k, l]) => '<option value="' + k + '"' + (ob.status === k ? " selected" : "") + ">" + l + "</option>").join("") + "</select>", "Sent removes it from findings and the calendar.") +
      field("dat", "Sent at", '<input type="datetime-local" id="' + P + '-dat" value="' + esc(localInput(st.at)) + '">', "Your local time. Recorded when you mark it sent.") +
      field("dreason", "Reason not required", '<input type="text" id="' + P + '-dreason" placeholder="Reason" value="' + esc(st.reason || "") + '">', "Record counsel's reasoning when an obligation does not apply.") +
      "</div>" +
      "<h3>Notice template</h3><pre id=\"" + P + '-draft">' + esc(draftNotice(ob, record.facts)) + "</pre>" +
      '<div class="' + P + '-row"><button class="' + P + '-btn" id="' + P + '-copy" type="button">Copy template</button><button class="' + P + '-btn" id="' + P + '-dltxt" type="button">Download template</button></div>';
    d.style.display = "block";
    $("dclose").addEventListener("click", () => { d.style.display = "none"; selId = null; renderTable(result.assessment); });
    $("dst").addEventListener("change", (e) => setStatus(id, { state: e.target.value }));
    $("dat").addEventListener("change", (e) => { const v = e.target.value; setStatus(id, { at: v ? new Date(v).toISOString() : undefined }); });
    $("dreason").addEventListener("change", (e) => setStatus(id, { reason: e.target.value.trim() || undefined }));
    $("copy").addEventListener("click", () => {
      const txt = $("draft").textContent;
      (navigator.clipboard ? navigator.clipboard.writeText(txt) : Promise.reject()).then(() => toast("Template copied", "success"), () => toast("Copy failed; select the text instead", "error"));
    });
    $("dltxt").addEventListener("click", () => download(TOOL_ID + "-notice-" + id + "-" + fileStamp() + ".txt", draftNotice(ob, record.facts), "text/plain"));
    if (!keep) { renderTable(result.assessment); d.scrollIntoView({ behavior: "smooth", block: "nearest" }); }
  }

  function renderExports(a) {
    const ex = $("exports");
    const title = record.title || "incident";
    const stamp = () => fileStamp();
    ex.innerHTML = ['ics|Calendar (.ics)', 'check|Checklist CSV', 'json|Obligations JSON', 'txt|Summary TXT', 'fcsv|Findings CSV'].map((s) => { const [k, l] = s.split("|"); return '<button class="' + P + '-btn" type="button" data-x="' + k + '">' + l + "</button>"; }).join("");
    const on = (k, fn) => ex.querySelector('[data-x="' + k + '"]').addEventListener("click", fn);
    on("ics", () => {
      const ev = icsEvents(result.assessment, title);
      if (!ev.length) { toast("No open fixed deadlines to export", "warning"); return; }
      download(TOOL_ID + "-deadlines-" + stamp() + ".ics", toIcs(ev), "text/calendar");
    });
    on("check", () => download(TOOL_ID + "-checklist-" + stamp() + ".csv", checklistToCsv(result.assessment.checklist), "text/csv"));
    on("json", () => download(TOOL_ID + "-obligations-" + stamp() + ".json", toJson(exportBundle(record, result.assessment)), "application/json"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp() + ".txt", summaryText(result.assessment, title), "text/plain"));
    on("fcsv", () => download(TOOL_ID + "-findings-" + stamp() + ".csv", findingsToCsv(result.findings), "text/csv"));
    attachSinkButton(ex, () => ({ findings: result ? result.findings : [], sample: isExample }), TOOL_ID, { dataset: title });
    const note = document.createElement("p");
    note.className = P + "-help"; note.style.width = "100%";
    note.textContent = "Saving an incident mirrors it into the Security Graph as an INCIDENT; the graph button adds one FINDING per obligation that is overdue or due inside the alert window. " + VERIFY_LINE;
    ex.appendChild(note);
  }

  writeForm(record);
  renderRegister();
}
