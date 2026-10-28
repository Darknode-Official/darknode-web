// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Risk Register (riskreg): Deck tool UI. A team-shared register of risks with an
// Open FAIR-style Monte Carlo of the ranges each owner enters (engine runs in a
// Worker via ../ingest/worker.js). Risks live in core/register.js mirrored to the
// Security Graph as FINDING entities (category "risk", tag risk-register); org
// settings live in a one-record companion register. Runs entirely in the
// browser; the only reads are this site's control catalogs (/data/controls) and
// the local Security Graph. No native dialogs.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { openRegister } from "../core/register.js";
import { download, toJson, fileStamp, toIcs } from "../core/export.js";
import {
  TOOL_ID, CATEGORIES, STATUSES, TREATMENTS, CANON_HEADERS, MODEL_NOTE, REGISTER_SCHEMA, SETTINGS_SCHEMA, SETTINGS_ID, MAX_ITERATIONS,
  parseInput, rowsToRecords, analyze, normalizeRecord, normalizeSettings, validateRisk, withHistory, snapshotOf,
  registerToCsv, registerToJson, lecToCsv, reviewEvents, boardSummary, findingsToCsv, exampleDataset, bandsValid, parseNum,
} from "./riskreg-engine.js?v=20261028a";

const ENGINE = engineUrl("./riskreg-engine.js?v=20261028a", import.meta);
const P = "rsk";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const lsGet = (k) => { try { return localStorage.getItem(k); } catch (_) { return null; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch (_) {} };
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const CATALOGS = [["iso27001", "ISO 27001"], ["soc2", "SOC 2"], ["nistcsf2", "NIST CSF 2.0"], ["cisv8", "CIS v8"], ["pci4", "PCI DSS 4"]];
const STATUS_LABEL = { identified: "Identified", assessed: "Assessed", treating: "Treating", accepted: "Accepted", closed: "Closed" };

function money(v, cur) {
  if (v == null || !Number.isFinite(Number(v))) return "-";
  try { return new Intl.NumberFormat("en-US", { style: "currency", currency: cur || "USD", maximumFractionDigits: 0 }).format(v); } catch (_) { return (cur ? cur + " " : "") + Math.round(v).toLocaleString("en-US"); }
}
function compact(v) {
  const a = Math.abs(v);
  if (a >= 1e9) return +(v / 1e9).toPrecision(3) + "B";
  if (a >= 1e6) return +(v / 1e6).toPrecision(3) + "M";
  if (a >= 1e3) return +(v / 1e3).toPrecision(3) + "k";
  return String(+Number(v).toPrecision(3));
}
const pct = (v) => (v == null ? "-" : (Math.round(v * 1000) / 10) + "%");

const CSS = `
  .rsk-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .rsk-root *{box-sizing:border-box}
  .rsk-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .rsk-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .rsk-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--mut,#667085);border:1px solid var(--line,#e6e8ee);padding:2px 9px;border-radius:999px}
  .rsk-sub{color:var(--mut,#667085);margin:8px 0 6px;max-width:100ch;overflow-wrap:anywhere}
  .rsk-model{border:1px solid var(--line,#e6e8ee);border-left:4px solid #b58100;border-radius:8px;padding:9px 14px;margin:8px 0 14px;font-weight:700;background:var(--card,#fff);overflow-wrap:anywhere}
  .rsk-banner{border:1px solid var(--line,#e6e8ee);border-left:4px solid #2552c6;border-radius:8px;padding:9px 14px;margin:0 0 14px;background:var(--card,#fff);display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center}
  .rsk-tabs{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 14px;border-bottom:1px solid var(--line,#e6e8ee)}
  .rsk-tab{appearance:none;font:inherit;font-size:.88rem;font-weight:600;border:1px solid transparent;border-bottom:none;background:none;color:var(--mut,#667085);padding:8px 14px;border-radius:8px 8px 0 0;cursor:pointer;margin-bottom:-1px}
  .rsk-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#e6e8ee);background:var(--card,#fff)}
  .rsk-pane{display:none}.rsk-pane.on{display:block}
  .rsk-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .rsk-card h2{font-size:1.02rem;margin:0 0 4px}
  .rsk-card h3{font-size:.8rem;margin:16px 0 8px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut,#667085);border-top:1px solid var(--line,#eef0f4);padding-top:12px}
  .rsk-card h3:first-of-type{border-top:none;padding-top:0;margin-top:8px}
  .rsk-row{display:flex;flex-wrap:wrap;gap:8px 10px;align-items:center;margin-top:10px}
  .rsk-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:7px 13px;border-radius:8px;cursor:pointer}
  .rsk-btn:hover{border-color:var(--mut,#667085)}
  .rsk-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .rsk-btn.dang{color:#b00020}
  .rsk-btn.sm{font-size:.76rem;padding:4px 9px}
  .rsk-btn:disabled{opacity:.5;cursor:default}
  .rsk-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px 16px}
  .rsk-field{display:flex;flex-direction:column;gap:3px;min-width:0}
  .rsk-field.wide{grid-column:1/-1}
  .rsk-field>label,.rsk-lbl{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .rsk-root input[type=text],.rsk-root input[type=number],.rsk-root input[type=date],.rsk-root select,.rsk-root textarea{font:inherit;font-size:.86rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%;min-width:0}
  .rsk-root textarea{min-height:64px;resize:vertical}
  .rsk-root input.bad{border-color:#b00020}
  .rsk-r3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:6px}
  .rsk-help{font-size:.75rem;color:var(--mut,#667085);margin:0;overflow-wrap:anywhere}
  .rsk-err{font-size:.75rem;color:#b00020;margin:0;overflow-wrap:anywhere;font-weight:600}
  .rsk-err:empty{display:none}
  .rsk-radio{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:.86rem}
  .rsk-radio label{display:flex;gap:6px;align-items:center;cursor:pointer}
  .rsk-chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
  .rsk-chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line,#d7dbe3);border-radius:999px;padding:2px 4px 2px 10px;font-size:.78rem;max-width:100%;overflow-wrap:anywhere;background:var(--card,#fff)}
  .rsk-chip button{appearance:none;border:none;background:none;color:var(--mut,#667085);cursor:pointer;font:inherit;font-weight:700;padding:0 6px}
  .rsk-pick{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:6px}
  .rsk-tbl{border:1px solid var(--line,#e6e8ee);border-radius:10px;overflow:auto;max-width:100%}
  .rsk-tbl table{width:100%;border-collapse:collapse;font-size:.84rem}
  .rsk-tbl th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 10px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .rsk-tbl th[data-sort]{cursor:pointer;user-select:none}
  .rsk-tbl th.sorted::after{content:" \\2193"}
  .rsk-tbl th.sorted.asc::after{content:" \\2191"}
  .rsk-tbl td{padding:8px 10px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .rsk-tbl td.num,.rsk-tbl th.num{text-align:right;white-space:nowrap}
  .rsk-tbl tr.rsk-click{cursor:pointer}
  .rsk-tbl tr.rsk-click:hover td{background:var(--bg,#f7f8fb)}
  .rsk-tbl tr.sel td{background:var(--bg,#f2f4f8)}
  #rsk-reglist table{min-width:820px}
  #rsk-reglist td,#rsk-findings td{overflow-wrap:break-word}
  #rsk-findings table{min-width:680px}
  .rsk-pill{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .rsk-pill.critical{background:#7a0012}.rsk-pill.high,.rsk-pill.over{background:#b00020}.rsk-pill.medium{background:#b58100}.rsk-pill.low{background:#2552c6}.rsk-pill.ok{background:#1b7f4d}.rsk-pill.na{background:#98a2b3}
  .rsk-conf{font-size:.72rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;color:var(--mut,#667085);white-space:nowrap}
  .rsk-ctl{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085)}
  .rsk-mut{color:var(--mut,#667085);font-size:.78rem}
  .rsk-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin:0 0 14px}
  .rsk-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .rsk-kpi b{display:block;font-size:1.25rem;line-height:1.25;overflow-wrap:anywhere}
  .rsk-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .rsk-kpi.alert b{color:#b00020}
  .rsk-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin:0 0 12px;display:none}
  .rsk-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .rsk-svg{width:100%;height:auto;display:block;border:1px solid var(--line,#e6e8ee);border-radius:8px;background:var(--bg,#f7f8fb)}
  .rsk-cap{font-size:.75rem;color:var(--mut,#667085);margin:4px 0 0;font-style:italic}
  .rsk-legend{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:.76rem;color:var(--mut,#667085);margin-top:6px}
  .rsk-legend .sw{display:inline-block;width:16px;height:0;border-top:3px solid;margin-right:5px;vertical-align:middle}
  .rsk-charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:14px}
  .rsk-bars{display:flex;flex-direction:column;gap:6px}
  .rsk-bar{display:grid;grid-template-columns:minmax(0,38%) minmax(0,1fr) auto;gap:8px;align-items:center;font-size:.8rem}
  .rsk-bar span:first-child{overflow-wrap:anywhere}
  .rsk-bar div{height:12px;background:var(--line,#e6e8ee);border-radius:3px;overflow:hidden}
  .rsk-bar div i{display:block;height:100%;background:#2552c6}
  .rsk-heat{display:grid;grid-template-columns:auto repeat(5,minmax(0,1fr));gap:4px;align-items:stretch;max-width:640px}
  .rsk-heat .ax{font-size:.68rem;color:var(--mut,#667085);display:flex;align-items:center;justify-content:center;text-align:center;padding:2px;overflow-wrap:anywhere}
  .rsk-cell{appearance:none;font:inherit;font-weight:700;font-size:1rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;min-height:48px;cursor:pointer;color:#1a2230}
  .rsk-cell:disabled{cursor:default;font-weight:400;color:#98a2b3}
  .rsk-cell.on{outline:3px solid #2552c6;outline-offset:1px}
  .rsk-drawer{display:none}
  .rsk-dl{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;margin:6px 0;font-size:.84rem}
  .rsk-dl dt{color:var(--mut,#667085)}
  .rsk-dl dd{margin:0;overflow-wrap:anywhere}
  .rsk-empty{padding:22px;text-align:center;color:var(--mut,#667085)}
  .rsk-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px;overflow-wrap:anywhere}
  .rsk-files{font-size:.8rem;margin-top:8px;display:flex;flex-direction:column;gap:3px}
  .rsk-map{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px 12px;margin-top:8px}
  .rsk-root details summary{cursor:pointer;font-size:.82rem;color:var(--mut,#667085);margin-top:8px}
  .rsk-badge{font-size:.68rem;border:1px solid #b58100;color:#8a6d00;border-radius:6px;padding:0 6px;margin-left:6px;white-space:nowrap;font-weight:700}
  @media(max-width:600px){.rsk-card{padding:12px}.rsk-dl{grid-template-columns:1fr}.rsk-dl dt{margin-top:6px}.rsk-tab{padding:7px 10px}}
`;

const kpi = (v, l, alert) => '<div class="' + P + "-kpi" + (alert ? " alert" : "") + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const field = (id, label, input, help, wide) => '<div class="' + P + "-field" + (wide ? " wide" : "") + '"><label for="' + P + "-f-" + id + '">' + esc(label) + "</label>" + input + (help ? '<p class="' + P + '-help">' + esc(help) + "</p>" : "") + '<p class="' + P + '-err" id="' + P + "-e-" + id + '"></p></div>';
const txt = (id, ph, extra) => '<input type="text" id="' + P + "-f-" + id + '" placeholder="' + esc(ph || "") + '"' + (extra || "") + ">";
const sel = (id, opts) => '<select id="' + P + "-f-" + id + '">' + opts.map(([v, l]) => '<option value="' + esc(v) + '">' + esc(l) + "</option>").join("") + "</select>";
function range(key, label, help, wide) {
  const inp = (p, ph) => '<input type="text" inputmode="decimal" data-r="' + key + '" data-p="' + p + '" aria-label="' + esc(label + " " + ph) + '" placeholder="' + ph + '">';
  return '<div class="' + P + "-field" + (wide ? " wide" : "") + '" data-rf="' + key + '"><label>' + esc(label) + '</label><div class="' + P + '-r3">' + inp("min", "Min") + inp("ml", "Likely") + inp("max", "Max") + "</div>" +
    (help ? '<p class="' + P + '-help">' + esc(help) + "</p>" : "") + '<p class="' + P + '-err" id="' + P + "-e-" + key + '"></p></div>';
}

/** Mount the tool into main. */
export function renderRiskRegister(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Risk Register</h1><span class="', P, '-tag">Risk</span></div>',
    '<p class="', P, '-sub">Team risk register with an Open FAIR-style Monte Carlo of the frequency and loss ranges each owner enters: annualized loss exposure, loss-exceedance curves, what treatments buy and which reviews are overdue. Runs entirely in your browser. Nothing is uploaded. It reads only this site\'s control catalogs (/data/controls) and your Security Graph. In a team workspace every member sees the same register.</p>',
    '<div class="', P, '-model">', esc(MODEL_NOTE), ' The figures come only from the ranges in this register; no industry benchmarks or default losses are used.</div>',
    '<div id="', P, '-exbanner"></div>',
    '<div class="', P, '-tabs" role="tablist">',
    ['register', 'risk', 'portfolio', 'settings'].map((t) => '<button class="' + P + '-tab" role="tab" data-tab="' + t + '">' + { register: "Register", risk: "Risk", portfolio: "Portfolio", settings: "Settings" }[t] + "</button>").join(""),
    "</div>",
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div>',

    // ---- Register pane
    '<div class="', P, '-pane" data-pane="register">',
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card"><h2>Risks</h2><p class="', P, '-help">Click a risk to edit it and see its results. Click a column to sort.</p>',
    '<div id="', P, '-filter" class="', P, '-row" style="display:none"></div>',
    '<div class="', P, '-tbl" style="margin-top:8px" id="', P, '-reglist"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-new">New risk</button><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button><button class="', P, '-btn" id="', P, '-rerun">Re-run simulation</button></div>',
    '<p class="', P, '-skip" id="', P, '-meta"></p></div>',

    '<div class="', P, '-card"><h2>Import</h2><p class="', P, '-help">Drop a JSON export from this tool, or a CSV from an existing risk spreadsheet (a mapping panel opens for its columns).</p>',
    '<div style="margin-top:8px" id="', P, '-drop"></div><div class="', P, '-files" id="', P, '-files"></div><div id="', P, '-mapping"></div></div>',

    '<div class="', P, '-card"><h2>Findings</h2><p class="', P, '-help">Generated from the register: over appetite, overdue reviews, missing owners, accepted-above-appetite without a note, stale assessments.</p>',
    '<div class="', P, '-tbl" style="margin-top:8px" id="', P, '-findings"><div class="', P, '-empty">No analysis yet.</div></div>',
    '<div class="', P, '-skip" id="', P, '-skipped"></div>',
    '<div class="', P, '-drawer ', P, '-card" id="', P, '-fdrawer" style="margin-top:12px"></div></div>',

    '<div class="', P, '-card"><h2>Exports</h2><div class="', P, '-row" id="', P, '-exports">',
    '<button class="', P, '-btn" data-x="regcsv">Register CSV</button><button class="', P, '-btn" data-x="regjson">Register JSON</button>',
    '<button class="', P, '-btn" data-x="board">Board summary TXT</button><button class="', P, '-btn" data-x="lec">LEC points CSV</button>',
    '<button class="', P, '-btn" data-x="ics">Review dates .ics</button><button class="', P, '-btn" data-x="fcsv">Findings CSV</button><button class="', P, '-btn" data-x="fjson">Findings JSON</button>',
    "</div></div>",
    "</div>",

    // ---- Risk pane
    '<div class="', P, '-pane" data-pane="risk">',
    '<div class="', P, '-card" id="', P, '-form"><h2 id="', P, '-formtitle">New risk</h2><p class="', P, '-help">Enter ranges you can defend: min, most likely, max. Shorthands like 250k or 1.2M are accepted.</p>',
    '<h3>Scenario</h3><div class="', P, '-grid">',
    field("title", "Title", txt("title", "Ransomware on file servers"), "", true),
    field("scenario", "Scenario", '<textarea id="' + P + '-f-scenario" placeholder="Threat, asset, effect"></textarea>', "Threat community + asset + effect, for example: ransomware operator encrypts file servers.", true),
    field("category", "Category", sel("category", CATEGORIES.map((c) => [c, c[0].toUpperCase() + c.slice(1)]))),
    field("owner", "Owner", txt("owner", "name@company")),
    field("status", "Status", sel("status", STATUSES.map((s) => [s, STATUS_LABEL[s]]))),
    field("currency", "Currency", txt("currency", "USD", ' maxlength="3"'), "ISO 4217 code. Portfolios only sum risks in the same currency."),
    "</div>",
    '<h3>Assets</h3><div class="', P, '-grid">',
    field("assets", "Assets (free text)", txt("assets", "File servers; NAS"), "Separate with semicolons.", true),
    '<div class="', P, '-field wide"><label for="', P, '-f-assetpick">From Security Graph</label><div class="', P, '-pick"><select id="', P, '-f-assetpick"></select><button class="', P, '-btn sm" type="button" id="', P, '-addasset">Add</button></div><p class="', P, '-help" id="', P, '-assethelp">Assets, identities and vendors already in your graph.</p><div class="', P, '-chips" id="', P, '-assetchips"></div></div>',
    "</div>",
    '<h3>Loss event frequency</h3>',
    '<div class="', P, '-radio" role="radiogroup"><label><input type="radio" name="', P, '-fm" value="lef" checked> Loss events per year</label><label><input type="radio" name="', P, '-fm" value="tef"> Threat events per year x vulnerability</label></div>',
    '<div class="', P, '-grid" style="margin-top:10px">',
    '<div data-mode="lef" class="', P, '-field wide">', range("lef", "Loss events per year", "How often this loss happens per year. 0.1 = once in ten years."), "</div>",
    '<div data-mode="tef" class="', P, '-field wide" style="display:none"><div class="', P, '-grid">', range("tef", "Threat events per year", "Attempts or contacts per year."), range("vuln", "Vulnerability (0 to 1)", "Probability an attempt becomes a loss event. 0.15 or 15% both work."), "</div></div>",
    "</div>",
    '<h3>Loss magnitude (per event)</h3><div class="', P, '-grid">',
    range("plm", "Primary loss", "Direct cost per event: response, downtime, replacement, fraud.", true),
    field("slp", "Secondary loss probability", '<input type="text" inputmode="decimal" id="' + P + '-f-slp" placeholder="0.3">', "Chance an event also brings fines, lawsuits or lost customers (0 to 1)."),
    range("slm", "Secondary loss", "Cost when secondary loss happens.", true),
    "</div>",
    '<h3>Controls in place</h3><div class="', P, '-grid">',
    field("controls", "Controls (free text)", '<textarea id="' + P + '-f-controls" placeholder="EDR, nightly backups"></textarea>', "", true),
    '<div class="', P, '-field wide"><label for="', P, '-f-ctlq">Control references</label><div class="', P, '-pick"><input type="text" id="', P, '-f-ctlq" list="', P, '-ctllist" placeholder="Search controls"><button class="', P, '-btn sm" type="button" id="', P, '-addctl">Add</button></div><datalist id="', P, '-ctllist"></datalist><p class="', P, '-help" id="', P, '-ctlhelp">Loading control catalogs.</p><div class="', P, '-chips" id="', P, '-ctlchips"></div></div>',
    "</div>",
    '<h3>Treatment</h3><div class="', P, '-grid">',
    field("treatment", "Treatment", sel("treatment", [["", "Not decided"], ...TREATMENTS.map((t) => [t, t[0].toUpperCase() + t.slice(1)])])),
    field("treatmentCost", "Treatment cost per year", '<input type="text" inputmode="decimal" id="' + P + '-f-treatmentCost" placeholder="120k">', "Annual cost of the treatment, same currency."),
    '<div class="', P, '-field wide"><label class="', P, '-radio"><input type="checkbox" id="', P, '-f-residualInEffect"> Treatment is implemented (use residual ranges as current exposure)</label><p class="', P, '-help">Leave unticked while the treatment is only planned.</p></div>',
    '<div class="', P, '-field wide"><span class="', P, '-lbl">Expected residual after treatment</span><p class="', P, '-help">Fill only what the treatment changes; blank ranges keep the inherent values.</p></div>',
    '<div data-mode="lef" class="', P, '-field wide">', range("res_lef", "Residual loss events per year", ""), "</div>",
    '<div data-mode="tef" class="', P, '-field wide" style="display:none"><div class="', P, '-grid">', range("res_tef", "Residual threat events per year", ""), range("res_vuln", "Residual vulnerability (0 to 1)", ""), "</div></div>",
    range("res_plm", "Residual primary loss", "", true),
    field("res_slp", "Residual secondary loss probability", '<input type="text" inputmode="decimal" id="' + P + '-f-res_slp" placeholder="0.1">', ""),
    range("res_slm", "Residual secondary loss", "", true),
    field("acceptanceNote", "Acceptance note", '<textarea id="' + P + '-f-acceptanceNote" placeholder="Who accepted, why, until when"></textarea>', "Required when the treatment is accept and the risk is above appetite.", true),
    "</div>",
    '<h3>Linked findings and review</h3><div class="', P, '-grid">',
    '<div class="', P, '-field wide"><label for="', P, '-f-findpick">Linked findings</label><div class="', P, '-pick"><select id="', P, '-f-findpick"></select><button class="', P, '-btn sm" type="button" id="', P, '-addfind">Link</button></div><p class="', P, '-help" id="', P, '-findhelp">Findings already in your Security Graph.</p><div class="', P, '-chips" id="', P, '-findchips"></div></div>',
    field("reviewDate", "Next review", '<input type="date" id="' + P + '-f-reviewDate">'),
    field("lastReviewed", "Last reviewed", '<input type="date" id="' + P + '-f-lastReviewed">'),
    field("notes", "Notes", '<textarea id="' + P + '-f-notes" placeholder="Context, sources for the ranges"></textarea>', "", true),
    field("by", "Changed by", txt("by", "you@company"), "Recorded in this risk's history. Remembered in this browser only."),
    "</div>",
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-save">Save risk</button><button class="', P, '-btn" id="', P, '-analyze">Analyze</button><button class="', P, '-btn" id="', P, '-hist">History</button><button class="', P, '-btn dang" id="', P, '-del" disabled>Delete</button><span class="', P, '-mut" id="', P, '-savedmsg"></span></div>',
    '<div class="', P, '-drawer" id="', P, '-histdrawer" style="margin-top:12px"></div>',
    "</div>",
    '<div class="', P, '-card" id="', P, '-results"><h2>Results</h2><div class="', P, '-empty">Analyze the risk to see its results.</div></div>',
    "</div>",

    // ---- Portfolio pane
    '<div class="', P, '-pane" data-pane="portfolio"><div id="', P, '-portfolio"><div class="', P, '-card ', P, '-empty">No analysis yet.</div></div></div>',

    // ---- Settings pane
    '<div class="', P, '-pane" data-pane="settings"><div class="', P, '-card"><h2>Settings</h2><p class="', P, '-help">Organization-wide. Shared with the team through the Security Graph. No money figures are pre-filled: set your own appetite and bands.</p>',
    '<div id="', P, '-setnote"></div>',
    '<h3>Risk appetite</h3><div class="', P, '-grid">',
    field("s-currency", "Currency", '<input type="text" id="' + P + '-f-s-currency" maxlength="3" placeholder="USD">', "Currency of the appetite and magnitude bands; default for new risks."),
    field("s-appetiteAmount", "Appetite (annual loss)", '<input type="text" inputmode="decimal" id="' + P + '-f-s-appetiteAmount" placeholder="2M">', "A risk exceeds appetite when this percentile of its annual loss is above the amount."),
    field("s-appetitePercentile", "At percentile", sel("s-appetitePercentile", [[50, "P50"], [80, "P80"], [90, "P90"], [95, "P95"], [99, "P99"]])),
    field("s-staleDays", "Stale after (days)", '<input type="number" min="1" id="' + P + '-f-s-staleDays">', "Last review older than this is reported."),
    "</div>",
    '<h3>Heatmap bands</h3><p class="', P, '-help">Four ascending edges make five bands. Likelihood uses simulated events per year; impact uses simulated loss per event.</p><div class="', P, '-grid">',
    field("s-freqBands", "Frequency band edges (events per year)", txt("s-freqBands", "0.05, 0.2, 1, 5"), "Example format only; enter your own."),
    field("s-magBands", "Magnitude band edges (loss per event)", txt("s-magBands", "50k, 250k, 1M, 5M"), "Example format only; enter your own."),
    "</div>",
    '<h3>Simulation</h3><div class="', P, '-grid">',
    field("s-iterations", "Iterations", '<input type="number" min="100" max="' + MAX_ITERATIONS + '" step="1000" id="' + P + '-f-s-iterations">', "Default 10,000; max 100,000."),
    field("s-seed", "Seed", '<input type="number" min="0" id="' + P + '-f-s-seed">', "Same seed and ranges give the same numbers."),
    "</div>",
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-ssave">Save settings</button><span class="', P, '-mut" id="', P, '-ssaved"></span></div>',
    "</div></div>",
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  const F = (id) => main.querySelector("#" + P + "-f-" + id);
  const reg = openRegister(TOOL_ID, "FINDING", { schema: REGISTER_SCHEMA });
  const sreg = openRegister(TOOL_ID + "-settings", "REPORT", { schema: SETTINGS_SCHEMA });

  let example = null; // { records, settings, org } while the synthetic example is shown
  let result = null, seq = 0, timer = 0;
  let form = blank();
  let riskRow = null; // per-risk analysis row of the form
  let regSort = { key: "ale", asc: false }, fSort = { key: "sev", asc: false };
  let heatFilter = null; // { label, ids:Set }
  let graphLists = { assets: [], findings: [], controls: [] };
  let catalogs = [];
  let csvState = null;

  const settings = () => normalizeSettings(example ? example.settings : (sreg.get(SETTINGS_ID) || {}));
  const records = () => (example ? example.records : reg.list());
  function blank() { return normalizeRecord({ status: "identified", category: "cyber", currency: settings0().currency }); }
  function settings0() { try { return normalizeSettings(sreg.get(SETTINGS_ID) || {}); } catch (_) { return normalizeSettings({}); } }

  // ---- tabs ------------------------------------------------------------------
  function tab(name) {
    main.querySelectorAll("." + P + "-tab").forEach((b) => b.classList.toggle("on", b.dataset.tab === name));
    main.querySelectorAll("." + P + "-pane").forEach((p) => p.classList.toggle("on", p.dataset.pane === name));
    lsSet("rsk_tab", name);
  }
  main.querySelectorAll("." + P + "-tab").forEach((b) => b.addEventListener("click", () => tab(b.dataset.tab)));
  tab(["register", "risk", "portfolio", "settings"].includes(lsGet("rsk_tab")) ? lsGet("rsk_tab") : "register");

  // ---- reference data: control catalogs + Security Graph -----------------------
  Promise.all(CATALOGS.map(([k]) => fetch("/data/controls/" + k + ".json").then((r) => (r.ok ? r.json() : null)).catch(() => null))).then((docs) => {
    catalogs = docs.map((d, i) => (d ? { key: CATALOGS[i][0], label: CATALOGS[i][1], version: d.version, updated: d.updated, data: d.data || [] } : null)).filter(Boolean);
    fillControlList();
    $("ctlhelp").textContent = catalogs.length ? "Catalogs: " + catalogs.map((c) => c.label + " (" + (c.version || "") + ", updated " + (c.updated || "?") + ")").join("; ") + ". Graph CONTROL entities are listed too." : "Control catalogs could not be loaded; free text still works.";
  });
  function fillControlList() {
    const opts = [];
    for (const c of catalogs) for (const d of c.data) opts.push('<option value="' + esc(c.key + ":" + d.id) + '">' + esc(c.label + " " + d.id + " " + d.title) + "</option>");
    for (const e of graphLists.controls) opts.push('<option value="' + esc("graph:" + e.id) + '">' + esc("Graph control: " + e.name) + "</option>");
    $("ctllist").innerHTML = opts.join("");
  }
  async function loadGraph() {
    try {
      const sg = await import("/js/security-graph.js");
      const L = (t) => { try { return sg.listEntities({ type: t }) || []; } catch (_) { return []; } };
      graphLists = {
        assets: L(["ASSET", "IDENTITY", "VENDOR"]).map((e) => ({ id: e.id, type: e.type, name: e.name })).sort((a, b) => (a.type + a.name).localeCompare(b.type + b.name)),
        findings: L("FINDING").filter((e) => e.source !== TOOL_ID).map((e) => ({ id: e.id, name: e.name, severity: e.severity })).sort((a, b) => String(a.name).localeCompare(String(b.name))).slice(0, 2000),
        controls: L("CONTROL").map((e) => ({ id: e.id, name: e.name })).sort((a, b) => String(a.name).localeCompare(String(b.name))),
      };
    } catch (_) { graphLists = { assets: [], findings: [], controls: [] }; }
    const a = graphLists.assets;
    $("f-assetpick").innerHTML = a.length ? ["ASSET", "IDENTITY", "VENDOR"].map((t) => { const g = a.filter((x) => x.type === t); return g.length ? '<optgroup label="' + t + '">' + g.map((x) => '<option value="' + esc(x.id) + '">' + esc(x.name) + "</option>").join("") + "</optgroup>" : ""; }).join("") : '<option value="">No graph assets yet</option>';
    $("f-findpick").innerHTML = graphLists.findings.length ? graphLists.findings.map((x) => '<option value="' + esc(x.id) + '">' + esc((x.severity ? "[" + x.severity + "] " : "") + x.name) + "</option>").join("") : '<option value="">No graph findings yet</option>';
    $("addasset").disabled = !a.length; $("addfind").disabled = !graphLists.findings.length;
    fillControlList(); renderChips();
  }
  loadGraph();
  document.addEventListener("secgraph:sync", () => { if (main.isConnected) loadGraph(); });

  // ---- form ------------------------------------------------------------------
  const fm = () => (main.querySelector('input[name="' + P + '-fm"]:checked') || {}).value || "lef";
  function setMode(m) {
    main.querySelectorAll('input[name="' + P + '-fm"]').forEach((r) => { r.checked = r.value === m; });
    main.querySelectorAll("#" + P + "-form [data-mode]").forEach((el) => { el.style.display = el.dataset.mode === m ? "" : "none"; });
  }
  main.querySelectorAll('input[name="' + P + '-fm"]').forEach((r) => r.addEventListener("change", () => { setMode(fm()); validateLive(); }));
  const rangeOf = (key) => { const o = {}; main.querySelectorAll('[data-r="' + key + '"]').forEach((el) => { o[el.dataset.p] = el.value.trim(); }); return { min: parseNum(o.min), ml: parseNum(o.ml), max: parseNum(o.max) }; };
  const setRange = (key, r) => { main.querySelectorAll('[data-r="' + key + '"]').forEach((el) => { const v = r && r[el.dataset.p]; el.value = v == null ? "" : String(v); }); };
  const prob = (v) => { const n = parseNum(v); return n != null && n > 1 && n <= 100 ? n / 100 : n; };

  function readForm() {
    const m = fm();
    const vuln = rangeOf("vuln"), rv = rangeOf("res_vuln");
    for (const r of [vuln, rv]) for (const k of ["min", "ml", "max"]) if (r[k] != null && r[k] > 1 && r[k] <= 100) r[k] /= 100;
    form = normalizeRecord({
      ...form,
      title: F("title").value, scenario: F("scenario").value, category: F("category").value, owner: F("owner").value, status: F("status").value,
      currency: F("currency").value || settings().currency, assets: F("assets").value, freqMode: m,
      lef: m === "lef" ? rangeOf("lef") : {}, tef: m === "tef" ? rangeOf("tef") : {}, vuln: m === "tef" ? vuln : {},
      plm: rangeOf("plm"), slp: prob(F("slp").value), slm: rangeOf("slm"),
      controls: F("controls").value, treatment: F("treatment").value, treatmentCost: F("treatmentCost").value,
      residualInEffect: F("residualInEffect").checked,
      residual: { freqMode: m, lef: m === "lef" ? rangeOf("res_lef") : {}, tef: m === "tef" ? rangeOf("res_tef") : {}, vuln: m === "tef" ? rv : {}, plm: rangeOf("res_plm"), slp: prob(F("res_slp").value), slm: rangeOf("res_slm") },
      acceptanceNote: F("acceptanceNote").value, reviewDate: F("reviewDate").value, lastReviewed: F("lastReviewed").value, notes: F("notes").value,
    });
    return form;
  }
  function writeForm(r) {
    form = normalizeRecord(r);
    for (const k of ["title", "scenario", "category", "owner", "status", "currency", "assets", "controls", "treatment", "acceptanceNote", "reviewDate", "lastReviewed", "notes"]) F(k).value = form[k] == null ? "" : form[k];
    F("treatmentCost").value = form.treatmentCost == null ? "" : form.treatmentCost;
    F("slp").value = form.slp == null ? "" : form.slp;
    F("res_slp").value = form.residual.slp == null ? "" : form.residual.slp;
    F("residualInEffect").checked = !!form.residualInEffect;
    setMode(form.freqMode);
    for (const k of ["lef", "tef", "vuln", "plm", "slm"]) { setRange(k, form[k]); setRange("res_" + k, form.residual[k]); }
    F("by").value = lsGet("rsk_by") || "";
    $("formtitle").textContent = form.id ? "Risk: " + (form.title || "Untitled") : "New risk";
    $("del").disabled = !form.id || !!example;
    $("savedmsg").textContent = form.updatedAt ? "Saved " + String(form.updatedAt).slice(0, 16).replace("T", " ") + " UTC" : "";
    $("histdrawer").style.display = "none";
    renderChips(); validateLive();
  }
  function renderChips() {
    const chip = (label, kind, i) => '<span class="' + P + '-chip">' + esc(label) + '<button type="button" aria-label="Remove" data-rm="' + kind + '" data-i="' + i + '">x</button></span>';
    $("assetchips").innerHTML = form.assetRefs.map((a, i) => chip(a.type + ": " + a.name, "asset", i)).join("");
    $("ctlchips").innerHTML = form.controlRefs.map((c, i) => chip(controlLabel(c), "ctl", i)).join("");
    $("findchips").innerHTML = form.linkedFindings.map((id, i) => { const f = graphLists.findings.find((x) => x.id === id); return chip(f ? f.name : id, "find", i); }).join("");
    main.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => {
      const i = Number(b.dataset.i);
      if (b.dataset.rm === "asset") form.assetRefs.splice(i, 1); else if (b.dataset.rm === "ctl") form.controlRefs.splice(i, 1); else form.linkedFindings.splice(i, 1);
      renderChips();
    }));
  }
  function controlLabel(ref) {
    const [k, ...rest] = String(ref).split(":"); const id = rest.join(":");
    if (k === "graph") { const e = graphLists.controls.find((x) => x.id === id); return e ? e.name : ref; }
    const c = catalogs.find((x) => x.key === k); const d = c && c.data.find((x) => x.id === id);
    return c ? c.label + " " + id + (d ? " " + d.title : "") : ref;
  }
  $("addasset").addEventListener("click", () => {
    const e = graphLists.assets.find((x) => x.id === F("assetpick").value);
    if (!e) return;
    if (!form.assetRefs.some((a) => a.id === e.id)) form.assetRefs.push({ id: e.id, type: e.type, name: e.name });
    renderChips();
  });
  $("addfind").addEventListener("click", () => {
    const id = F("findpick").value;
    if (id && !form.linkedFindings.includes(id)) form.linkedFindings.push(id);
    renderChips();
  });
  $("addctl").addEventListener("click", () => {
    const v = F("ctlq").value.trim();
    if (!v) return;
    const known = /^[a-z0-9]+:/.test(v) && (v.startsWith("graph:") || catalogs.some((c) => v.startsWith(c.key + ":")));
    if (!known) { toast("Pick a control from the list (type to search)", "warning"); return; }
    if (!form.controlRefs.includes(v)) form.controlRefs.push(v);
    F("ctlq").value = ""; renderChips();
  });

  function validateLive() {
    const r = readForm();
    main.querySelectorAll("#" + P + "-form ." + P + "-err").forEach((e) => { e.textContent = ""; });
    main.querySelectorAll("#" + P + "-form input.bad").forEach((e) => e.classList.remove("bad"));
    const errs = validateRisk(r);
    for (const e of errs) {
      const el = $("e-" + e.field);
      if (el) el.textContent = el.textContent ? el.textContent + " " + e.message : e.message;
      main.querySelectorAll('[data-r="' + e.field + '"]').forEach((x) => x.classList.add("bad"));
      const inp = F(e.field); if (inp) inp.classList.add("bad");
    }
    return errs;
  }
  let vt = 0;
  $("form").addEventListener("input", (ev) => {
    if (ev.target === F("by")) { lsSet("rsk_by", F("by").value.trim()); return; }
    if (ev.target === F("ctlq")) return;
    clearTimeout(vt); vt = setTimeout(validateLive, 250);
  });
  $("form").addEventListener("change", (ev) => { if (ev.target.tagName === "SELECT" || ev.target.type === "checkbox" || ev.target.type === "date") validateLive(); });

  // ---- analysis ------------------------------------------------------------------
  const baseOpts = () => ({ ...settings(), now: example ? example.now : new Date().toISOString() });
  function schedule() { clearTimeout(timer); timer = setTimeout(runAll, 120); }
  async function runAll() {
    const my = ++seq;
    const list = records();
    const prog = $("prog"), bar = prog.firstElementChild;
    prog.style.display = "block"; bar.style.width = "2%";
    try {
      const r = await runInWorker(ENGINE, "analyze", [{ records: list }, baseOpts()], { onProgress: (i, n) => { if (my === seq) bar.style.width = (n ? Math.round(i / n * 100) : 0) + "%"; } });
      if (my !== seq) return;
      result = r;
    } catch (e) {
      if (my !== seq) return;
      try { result = analyze({ records: list }, baseOpts()); } catch (err) { toast("Analysis failed: " + (err && err.message || err), "error"); }
    } finally { if (my === seq) prog.style.display = "none"; }
    renderAll();
  }
  async function analyzeForm() {
    const r = readForm();
    const errs = validateLive();
    if (errs.length) { riskRow = null; renderResults(errs); return null; }
    const rec = { ...r, id: r.id || "draft" };
    try {
      const out = await runInWorker(ENGINE, "analyze", [{ records: [rec] }, baseOpts()]);
      riskRow = out.tables.risks[0];
    } catch (_) { riskRow = analyze({ records: [rec] }, baseOpts()).tables.risks[0]; }
    renderResults();
    return riskRow;
  }
  $("analyze").addEventListener("click", () => analyzeForm());
  $("rerun").addEventListener("click", () => runAll());

  // ---- register list --------------------------------------------------------------
  function rowsForList() {
    const byId = new Map(((result && result.tables.risks) || []).map((r) => [r.id, r]));
    return records().map((rec, i) => ({ rec, r: byId.get(rec.id || "#" + i) || null }));
  }
  const sortVal = {
    title: (x) => String(x.rec.title || "").toLowerCase(), owner: (x) => String(x.rec.owner || "").toLowerCase(), status: (x) => STATUSES.indexOf(x.rec.status),
    ale: (x) => (x.r && x.r.valid ? x.r.currentStats.mean : -1), p50: (x) => (x.r && x.r.valid ? x.r.currentStats.p50 : -1), p90: (x) => (x.r && x.r.valid ? x.r.currentStats.p90 : -1),
    app: (x) => (x.r && x.r.appetite ? (x.r.appetite.exceeds ? 2 : x.r.appetite.exceeds === false ? 1 : 0) : 0), review: (x) => x.rec.reviewDate || "9999",
  };
  function renderRegister() {
    const box = $("reglist");
    let rows = rowsForList();
    const fl = $("filter");
    if (heatFilter) {
      rows = rows.filter((x) => heatFilter.ids.has(x.rec.id));
      fl.style.display = ""; fl.innerHTML = '<span class="' + P + '-mut">Filtered by heatmap cell: ' + esc(heatFilter.label) + " (" + rows.length + ")</span><button class=\"" + P + '-btn sm" id="' + P + '-clearf">Clear filter</button>';
      $("clearf").addEventListener("click", () => { heatFilter = null; renderRegister(); renderPortfolio(); });
    } else { fl.style.display = "none"; fl.innerHTML = ""; }
    if (!rows.length) { box.innerHTML = '<div class="' + P + '-empty">' + (heatFilter ? "No risks in this cell." : "No risks yet. Add one with New risk, import a spreadsheet, or load the synthetic example.") + "</div>"; return; }
    const f = sortVal[regSort.key] || sortVal.ale;
    rows.sort((a, b) => { const x = f(a), y = f(b); return (x < y ? -1 : x > y ? 1 : 0) * (regSort.asc ? 1 : -1) || String(a.rec.title).localeCompare(String(b.rec.title)); });
    const today = new Date().toISOString().slice(0, 10);
    const th = (k, l, num) => '<th data-sort="' + k + '" class="' + (num ? "num " : "") + (regSort.key === k ? "sorted" + (regSort.asc ? " asc" : "") : "") + '">' + l + "</th>";
    box.innerHTML = "<table><thead><tr>" + th("title", "Risk") + th("owner", "Owner") + th("status", "Status") + th("ale", "ALE (mean)", 1) + th("p50", "P50", 1) + th("p90", "P90", 1) + th("app", "Appetite") + th("review", "Review due") + "</tr></thead><tbody>" +
      rows.map(({ rec, r }) => {
        const v = r && r.valid, cur = r && r.currency;
        const app = !r || !r.appetite ? '<span class="' + P + '-pill na">not set</span>' : r.appetite.exceeds ? '<span class="' + P + '-pill over">Over</span>' : r.appetite.exceeds === false ? '<span class="' + P + '-pill ok">Within</span>' : '<span class="' + P + '-pill na">other ccy</span>';
        const overdue = rec.reviewDate && rec.status !== "closed" && rec.reviewDate < (example ? example.now.slice(0, 10) : today);
        return '<tr class="' + P + "-click" + (rec.id && rec.id === form.id ? " sel" : "") + '" data-id="' + esc(rec.id || "") + '"><td><b>' + esc(rec.title || "Untitled") + "</b>" + (r && !r.valid ? '<span class="' + P + '-badge">needs ranges</span>' : "") +
          '<div class="' + P + '-mut">' + esc(rec.category) + (rec.treatment ? " / " + esc(rec.treatment) : "") + "</div></td><td>" + (rec.owner ? esc(rec.owner) : '<span style="color:#b00020">none</span>') + "</td><td>" + esc(STATUS_LABEL[rec.status] || rec.status) + "</td>" +
          '<td class="num">' + (v ? esc(money(r.currentStats.mean, cur)) : "-") + '</td><td class="num">' + (v ? esc(money(r.currentStats.p50, cur)) : "-") + '</td><td class="num">' + (v ? esc(money(r.currentStats.p90, cur)) : "-") + "</td><td>" + (v ? app : "-") + "</td>" +
          "<td" + (overdue ? ' style="color:#b00020;font-weight:700"' : "") + ">" + esc(rec.reviewDate || "-") + (overdue ? " (overdue)" : "") + "</td></tr>";
      }).join("") + "</tbody></table>";
    box.querySelectorAll("th[data-sort]").forEach((h) => h.addEventListener("click", () => { const k = h.dataset.sort; regSort = { key: k, asc: regSort.key === k ? !regSort.asc : ["title", "owner", "review"].includes(k) }; renderRegister(); }));
    box.querySelectorAll("tr[data-id]").forEach((tr) => tr.addEventListener("click", () => openRisk(tr.dataset.id)));
  }
  function openRisk(id) {
    const rec = records().find((r) => r.id === id);
    if (!rec) return;
    writeForm(rec); tab("risk"); renderRegister();
    riskRow = (result && result.tables.risks.find((r) => r.id === id)) || null;
    if (riskRow && riskRow.valid) renderResults(); else analyzeForm();
    $("form").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ---- results panel (one risk) ------------------------------------------------
  function statsTable(r) {
    const cols = [["Inherent", r.inherent]].concat(r.residual ? [["Residual", r.residual]] : []);
    const cur = r.currency;
    const line = (l, f) => "<tr><td>" + l + "</td>" + cols.map(([, s]) => '<td class="num">' + f(s) + "</td>").join("") + "</tr>";
    return '<div class="' + P + '-tbl" style="max-width:720px"><table><thead><tr><th>Annual loss</th>' + cols.map(([n]) => '<th class="num">' + n + (r.current === n.toLowerCase() ? " (current)" : "") + "</th>").join("") + "</tr></thead><tbody>" +
      line("ALE (mean)", (s) => esc(money(s.mean, cur))) + ["p10", "p50", "p90", "p95", "p99"].map((k) => line(k.toUpperCase(), (s) => esc(money(s[k], cur)))).join("") +
      line("Max simulated", (s) => esc(money(s.max, cur))) + line("P(at least one loss event)", (s) => pct(s.pAny)) + line("Mean loss events per year", (s) => esc(s.meanEvents)) + line("Mean loss per event", (s) => esc(money(s.meanLossPerEvent, cur))) +
      "</tbody></table></div>";
  }
  function renderResults(errs) {
    const box = $("results");
    if (errs && errs.length) { box.innerHTML = "<h2>Results</h2><p class=\"" + P + '-help">Fix the highlighted fields to run the model:</p><ul>' + errs.map((e) => "<li>" + esc(e.message) + "</li>").join("") + "</ul>"; return; }
    const r = riskRow;
    if (!r || !r.valid) { box.innerHTML = '<h2>Results</h2><div class="' + P + '-empty">Analyze the risk to see its results.</div>'; return; }
    const S = settings(), cur = r.currency, e = r.treatmentEcon;
    const app = r.appetite;
    box.innerHTML = "<h2>Results: " + esc(r.title || "Untitled") + "</h2>" +
      '<p class="' + P + '-help">' + esc(MODEL_NOTE) + " " + esc(S.iterations.toLocaleString("en-US")) + " iterations, seed " + esc(S.seed) + ". Current exposure uses the " + esc(r.current) + " ranges.</p>" +
      '<div class="' + P + '-kpis" style="margin-top:10px">' + kpi(money(r.currentStats.mean, cur), "ALE (mean)") + kpi(money(r.currentStats.p90, cur), "P90 annual loss") + kpi(pct(r.currentStats.pAny), "P(loss event in a year)") +
      (app ? kpi(app.exceeds == null ? "other currency" : app.exceeds ? "Over appetite" : "Within", "Appetite P" + app.percentile + " " + money(app.amount, S.currency), app.exceeds) : kpi("not set", "Appetite")) +
      (e ? kpi(e.roi == null ? "n/a" : Math.round(e.roi * 100) + "%", "Treatment ROI") : "") + "</div>" +
      statsTable(r) +
      (e ? '<h3 style="font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut,#667085);margin:14px 0 6px">What the treatment buys</h3><dl class="' + P + '-dl"><dt>ALE reduction</dt><dd>' + esc(money(e.aleReduction, cur)) + " per year (" + pct(e.mitigationRatio) + ")</dd><dt>P90 reduction</dt><dd>" + esc(money(e.p90Reduction, cur)) + "</dd><dt>Treatment cost</dt><dd>" + esc(e.cost == null ? "not entered" : money(e.cost, cur) + " per year") + "</dd><dt>Net benefit</dt><dd>" + esc(e.netBenefit == null ? "n/a" : money(e.netBenefit, cur)) + "</dd>" +
        "<dt>ROI</dt><dd>" + (e.roi == null ? "n/a (enter a cost)" : esc(Math.round(e.roi * 100) + "%") + " = (ALE inherent - ALE residual - cost) / cost") + "</dd><dt>ROSI</dt><dd>" + (e.rosi == null ? "n/a" : esc(Math.round(e.rosi * 100) + "%") + " = (ALE x mitigation ratio - cost) / cost; equal to ROI when the mitigation ratio comes from the simulated residual") + "</dd></dl>" : "") +
      '<div class="' + P + '-charts" style="margin-top:14px"><div><span class="' + P + '-lbl">Loss exceedance curve</span>' + lecSvg(r.lec, [{ k: "inherent", label: "Inherent", color: "#2552c6" }].concat(r.residual ? [{ k: "residual", label: "Residual", color: "#1b7f4d", dash: "6 4" }] : []), app && app.exceeds != null ? app : null, cur) + "</div>" +
      '<div><span class="' + P + '-lbl">Annual loss histogram (' + esc(r.current) + ")</span>" + histSvg(r.histogram, cur) + "</div></div>";
  }

  // ---- SVG charts ------------------------------------------------------------------
  function lecSvg(points, series, appetite, cur) {
    if (!points || !points.length) return '<div class="' + P + '-empty">No losses in the simulation.</div>';
    const W = 640, H = 290, L = 56, Rr = 14, T = 14, B = 44;
    const xs = points.map((p) => p.x);
    const lx0 = Math.log10(xs[0]), lx1 = Math.log10(xs[xs.length - 1]);
    let ymax = 0; for (const s of series) for (const p of points) if (p[s.k] != null) ymax = Math.max(ymax, p[s.k]);
    if (appetite) ymax = Math.max(ymax, 1 - appetite.percentile / 100);
    ymax = Math.min(1, Math.max(0.05, Math.ceil(ymax * 20) / 20));
    const X = (x) => L + (W - L - Rr) * ((Math.log10(x) - lx0) / ((lx1 - lx0) || 1));
    const Y = (y) => T + (H - T - B) * (1 - y / ymax);
    let g = '<svg class="' + P + '-svg" viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Loss exceedance curve">';
    for (let i = 0; i <= 4; i++) { const y = ymax * i / 4; g += '<line x1="' + L + '" x2="' + (W - Rr) + '" y1="' + Y(y) + '" y2="' + Y(y) + '" stroke="#d7dbe3" stroke-width="1"/><text x="' + (L - 6) + '" y="' + (Y(y) + 4) + '" font-size="11" text-anchor="end" fill="#667085">' + (Math.round(y * 1000) / 10) + "%</text>"; }
    for (let e = Math.ceil(lx0); e <= Math.floor(lx1); e++) { const x = X(Math.pow(10, e)); g += '<line x1="' + x + '" x2="' + x + '" y1="' + T + '" y2="' + (H - B) + '" stroke="#e6e8ee"/><text x="' + x + '" y="' + (H - B + 16) + '" font-size="11" text-anchor="middle" fill="#667085">' + esc(compact(Math.pow(10, e))) + "</text>"; }
    if (Math.floor(lx1) - Math.ceil(lx0) < 1) for (const x of [xs[0], xs[xs.length - 1]]) g += '<text x="' + X(x) + '" y="' + (H - B + 16) + '" font-size="11" text-anchor="middle" fill="#667085">' + esc(compact(x)) + "</text>";
    g += '<text x="' + ((L + W - Rr) / 2) + '" y="' + (H - 8) + '" font-size="11" text-anchor="middle" fill="#667085">Annual loss (' + esc(cur || "") + ", log scale)</text>";
    for (const s of series) {
      const d = points.filter((p) => p[s.k] != null).map((p, i) => (i ? "L" : "M") + X(p.x).toFixed(1) + " " + Y(p[s.k]).toFixed(1)).join(" ");
      g += '<path d="' + d + '" fill="none" stroke="' + s.color + '" stroke-width="2.2"' + (s.dash ? ' stroke-dasharray="' + s.dash + '"' : "") + "/>";
    }
    if (appetite && appetite.amount > 0) {
      const ax = Math.log10(appetite.amount);
      const ay = 1 - appetite.percentile / 100;
      if (ax >= lx0 && ax <= lx1) g += '<line x1="' + X(appetite.amount) + '" x2="' + X(appetite.amount) + '" y1="' + T + '" y2="' + (H - B) + '" stroke="#b00020" stroke-dasharray="4 3" stroke-width="1.5"/>';
      if (ay <= ymax) g += '<line x1="' + L + '" x2="' + (W - Rr) + '" y1="' + Y(ay) + '" y2="' + Y(ay) + '" stroke="#b00020" stroke-dasharray="2 3" stroke-width="1"/>';
      if (ax >= lx0 && ax <= lx1 && ay <= ymax) g += '<circle cx="' + X(appetite.amount) + '" cy="' + Y(ay) + '" r="4" fill="#b00020"/>';
    }
    g += "</svg>";
    const leg = series.map((s) => '<span><span class="sw" style="border-top-color:' + s.color + (s.dash ? ';border-top-style:dashed' : '') + '"></span>' + esc(s.label) + "</span>").join("") + (appetite ? '<span><span class="sw" style="border-top-color:#b00020;border-top-style:dashed"></span>Appetite ' + esc(money(appetite.amount, cur)) + " at P" + esc(appetite.percentile) + "</span>" : "");
    return g + '<div class="' + P + '-legend">' + leg + '</div><p class="' + P + '-cap">Probability that annual loss exceeds each amount. ' + esc(MODEL_NOTE) + "</p>";
  }
  function histSvg(h, cur) {
    if (!h || !h.counts || !h.counts.length) return '<div class="' + P + '-empty">No losses in the simulation' + (h ? " (" + esc(h.zero) + " zero-loss years)" : "") + ".</div>";
    const W = 640, H = 290, L = 48, Rr = 14, T = 14, B = 44;
    const max = Math.max(...h.counts, 1), n = h.counts.length, bw = (W - L - Rr) / n;
    let g = '<svg class="' + P + '-svg" viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Annual loss histogram">';
    for (let i = 0; i <= 4; i++) { const y = T + (H - T - B) * (1 - i / 4); g += '<line x1="' + L + '" x2="' + (W - Rr) + '" y1="' + y + '" y2="' + y + '" stroke="#e6e8ee"/><text x="' + (L - 6) + '" y="' + (y + 4) + '" font-size="11" text-anchor="end" fill="#667085">' + Math.round(max * i / 4) + "</text>"; }
    h.counts.forEach((c, i) => { const bh = (H - T - B) * c / max; g += '<rect x="' + (L + i * bw + 1).toFixed(1) + '" y="' + (H - B - bh).toFixed(1) + '" width="' + Math.max(1, bw - 2).toFixed(1) + '" height="' + bh.toFixed(1) + '" fill="#2552c6"/>'; });
    for (const i of [0, Math.floor(n / 2), n]) g += '<text x="' + (L + i * bw) + '" y="' + (H - B + 16) + '" font-size="11" text-anchor="' + (i === n ? "end" : i ? "middle" : "start") + '" fill="#667085">' + esc(compact(h.edges[i])) + "</text>";
    g += '<text x="' + ((L + W - Rr) / 2) + '" y="' + (H - 8) + '" font-size="11" text-anchor="middle" fill="#667085">Annual loss (' + esc(cur || "") + "), years with a loss, up to P99</text></svg>";
    return g + '<p class="' + P + '-cap">Zero-loss years: ' + esc(h.zero.toLocaleString("en-US")) + "; above P99: " + esc(h.over.toLocaleString("en-US")) + ". " + esc(MODEL_NOTE) + "</p>";
  }

  // ---- portfolio pane -----------------------------------------------------------
  function renderPortfolio() {
    const box = $("portfolio");
    if (!result) { box.innerHTML = '<div class="' + P + '-card ' + P + '-empty">No analysis yet.</div>'; return; }
    const S = result.meta.settings;
    const ps = result.tables.portfolios;
    let h = "";
    if (!ps.length) h += '<div class="' + P + '-card ' + P + '-empty">No open risks with complete ranges to aggregate.</div>';
    if (ps.length > 1) h += '<div class="' + P + '-banner">Risks use ' + ps.length + " currencies, so there is one portfolio per currency. Amounts in different currencies are never added together.</div>";
    for (const p of ps) {
      const app = p.appetite || null;
      h += '<div class="' + P + '-card"><h2>Portfolio (' + esc(p.currency) + ", " + p.risks + " open risk" + (p.risks === 1 ? "" : "s") + ")</h2>" +
        '<p class="' + P + '-help">Sum of every open risk\'s simulated annual loss in each iteration, assuming the risks are independent (correlated risks would fatten the tail). ' + esc(MODEL_NOTE) + "</p>" +
        '<div class="' + P + '-kpis" style="margin-top:10px">' + kpi(money(p.current.mean, p.currency), "Portfolio ALE (mean)") + kpi(money(p.current.p50, p.currency), "P50") + kpi(money(p.current.p90, p.currency), "P90") + kpi(money(p.current.p99, p.currency), "P99") +
        (app ? kpi(app.exceeds ? "Exceeds" : "Within", "Appetite P" + app.percentile + " " + money(app.amount, p.currency), app.exceeds) : "") + "</div>" +
        '<div class="' + P + '-charts"><div><span class="' + P + '-lbl">Aggregate loss exceedance curve</span>' + lecSvg(p.lec, [{ k: "inherent", label: "Inherent (no treatments)", color: "#98a2b3", dash: "6 4" }, { k: "current", label: "Current", color: "#2552c6" }], app, p.currency) + "</div>" +
        '<div><span class="' + P + '-lbl">Top contributors (share of portfolio ALE)</span><div class="' + P + '-bars" style="margin-top:8px">' +
        p.topContributors.map((c) => '<div class="' + P + '-bar"><span>' + esc(c.title) + '</span><div><i style="width:' + Math.max(1, Math.round(c.share * 100)) + '%"></i></div><span class="' + P + '-mut">' + esc(money(c.ale, p.currency)) + " (" + pct(c.share) + ")</span></div>").join("") +
        '</div><p class="' + P + '-cap">' + esc(MODEL_NOTE) + "</p></div></div></div>";
    }
    const hm = result.tables.heatmap;
    h += '<div class="' + P + '-card"><h2>Heatmap</h2>';
    if (!hm.ready) h += '<div class="' + P + '-empty">Set bands in Settings. ' + esc(hm.reason) + '</div><div class="' + P + '-row" style="justify-content:center"><button class="' + P + '-btn" id="' + P + '-gosettings">Open Settings</button></div>';
    else {
      h += '<p class="' + P + '-help">Qualitative view derived from the simulation: rows are frequency bands (simulated events per year), columns are magnitude bands (simulated loss per event, ' + esc(hm.currency) + "). Click a cell to filter the register.</p>";
      const fe = hm.freqBands, me = hm.magBands;
      const lab = (e, i, f) => (i === 0 ? "< " + f(e[0]) : i === 4 ? ">= " + f(e[3]) : f(e[i - 1]) + " to " + f(e[i]));
      const color = (f, m) => { const s = f + m; return ["#dff1e6", "#e9f4d9", "#f6f1cf", "#fbe5c8", "#f9d3c4", "#f5c0bb", "#efa9a6", "#e98f8f", "#e07a7a"][s]; };
      h += '<div class="' + P + '-heat" style="margin-top:10px">';
      for (let f = 4; f >= 0; f--) {
        h += '<div class="ax">' + esc(lab(fe, f, (x) => String(x))) + "/yr</div>";
        for (let m = 0; m < 5; m++) {
          const ids = hm.cells[f][m];
          const on = heatFilter && heatFilter.key === f + ":" + m;
          h += '<button class="' + P + "-cell" + (on ? " on" : "") + '" data-f="' + f + '" data-m="' + m + '" style="background:' + color(f, m) + '"' + (ids.length ? "" : " disabled") + ' aria-label="' + ids.length + ' risks">' + (ids.length || "") + "</button>";
        }
      }
      h += '<div class="ax"></div>' + [0, 1, 2, 3, 4].map((m) => '<div class="ax">' + esc(lab(me, m, compact)) + "</div>").join("") + "</div>";
      if (hm.excluded.length) h += '<p class="' + P + '-skip">Not on the heatmap (other currency): ' + esc(hm.excluded.map((x) => x.title).join(", ")) + "</p>";
    }
    h += "</div>";
    box.innerHTML = h;
    const gs = $("gosettings"); if (gs) gs.addEventListener("click", () => tab("settings"));
    box.querySelectorAll("." + P + "-cell[data-f]").forEach((b) => b.addEventListener("click", () => {
      const f = Number(b.dataset.f), m = Number(b.dataset.m);
      heatFilter = { key: f + ":" + m, label: "frequency band " + (f + 1) + ", magnitude band " + (m + 1), ids: new Set(hm.cells[f][m]) };
      renderRegister(); renderPortfolio(); tab("register");
    }));
  }

  // ---- findings ----------------------------------------------------------------------
  const fSortVal = { sev: (f) => SEV_RANK[f.severity] || 0, title: (f) => f.title.toLowerCase(), conf: (f) => f.confidence, cat: (f) => f.category, ev: (f) => f.evidenceCount || 0 };
  function renderFindings() {
    const box = $("findings");
    $("skipped").textContent = result && result.skipped.length ? "Not checked: " + result.skipped.map((s) => s.check.replace(/_/g, " ") + " (" + s.reason + ")").join("; ") : "";
    if (!result || !result.findings.length) { box.innerHTML = '<div class="' + P + '-empty">' + (result ? "No findings." : "No analysis yet.") + "</div>"; return; }
    const list = result.findings.slice();
    const f = fSortVal[fSort.key];
    list.sort((a, b) => { const x = f(a), y = f(b); return (x < y ? -1 : x > y ? 1 : 0) * (fSort.asc ? 1 : -1) || a.title.localeCompare(b.title); });
    const th = (k, l) => '<th data-sort="' + k + '" class="' + (fSort.key === k ? "sorted" + (fSort.asc ? " asc" : "") : "") + '">' + l + "</th>";
    box.innerHTML = "<table><thead><tr>" + th("sev", "Severity") + th("title", "Finding") + th("conf", "Confidence") + "<th>Controls</th>" + th("ev", "Evidence") + "</tr></thead><tbody>" +
      list.map((x) => '<tr class="' + P + '-click" data-fid="' + esc(x.id) + '"><td><span class="' + P + "-pill " + esc(x.severity) + '">' + esc(x.severity) + "</span></td><td><b>" + esc(x.title) + '</b><div class="' + P + '-mut">' + esc(x.description) + '</div></td><td><span class="' + P + '-conf">' + esc(x.confidence) + "</span></td><td>" +
        x.controls.map((c) => '<span class="' + P + '-ctl">' + esc(c.framework + " " + c.id) + "</span>").join("") + '</td><td class="num">' + esc(x.evidenceCount || 0) + "</td></tr>").join("") + "</tbody></table>";
    box.querySelectorAll("th[data-sort]").forEach((h) => h.addEventListener("click", () => { const k = h.dataset.sort; fSort = { key: k, asc: fSort.key === k ? !fSort.asc : k === "title" }; renderFindings(); }));
    box.querySelectorAll("tr[data-fid]").forEach((tr) => tr.addEventListener("click", () => {
      const x = result.findings.find((y) => y.id === tr.dataset.fid);
      if (!x) return;
      const d = $("fdrawer"); d.style.display = "block";
      const cols = Object.keys(x.evidence[0] || {});
      d.innerHTML = "<h2>" + esc(x.title) + '</h2><dl class="' + P + '-dl"><dt>Severity</dt><dd>' + esc(x.severity) + " (" + esc(x.confidence) + ")</dd><dt>What</dt><dd>" + esc(x.description) + "</dd><dt>Do this</dt><dd>" + esc(x.recommendation) + "</dd><dt>Controls</dt><dd>" + esc(x.controls.map((c) => c.framework + " " + c.id).join("; ")) + "</dd>" +
        (x.assets.length ? "<dt>Assets</dt><dd>" + esc(x.assets.map((a) => a.type + ": " + a.name).join("; ")) + "</dd>" : "") + "</dl>" +
        '<div class="' + P + '-tbl"><table><thead><tr>' + cols.map((c) => "<th>" + esc(c) + "</th>").join("") + "</tr></thead><tbody>" + x.evidence.map((row) => "<tr>" + cols.map((c) => "<td>" + esc(typeof row[c] === "number" ? row[c].toLocaleString("en-US") : row[c]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>" +
        '<div class="' + P + '-row"><button class="' + P + '-btn sm" id="' + P + '-openrisk">Open risk</button><button class="' + P + '-btn sm" id="' + P + '-closed">Close</button></div>';
      $("closed").addEventListener("click", () => { d.style.display = "none"; });
      $("openrisk").addEventListener("click", () => openRisk(x.evidence[0] && x.evidence[0].id));
    }));
  }

  // ---- KPIs, meta ----------------------------------------------------------------------
  function renderKpis() {
    const s = result && result.summary;
    if (!s) { $("kpis").innerHTML = ""; return; }
    const sum = summarize(result.findings);
    $("kpis").innerHTML = kpi(s.risks, "risks") +
      result.tables.portfolios.map((p) => kpi(money(p.current.mean, p.currency), "portfolio ALE " + p.currency)).join("") +
      kpi(s.overAppetite, "over appetite", s.overAppetite > 0) + kpi(s.overdueReviews, "overdue reviews", s.overdueReviews > 0) + kpi(s.noOwner, "no owner", s.noOwner > 0) +
      kpi(sum.total, "findings") + (s.invalid ? kpi(s.invalid, "need ranges", true) : "");
    $("meta").textContent = "Simulation: " + result.meta.iterations.toLocaleString("en-US") + " iterations, seed " + result.meta.seed + ". " + result.meta.model;
  }
  let updateSink = () => {};
  function renderAll() {
    renderKpis(); renderRegister(); renderFindings(); renderPortfolio(); updateSink();
    if (form.id && result) { const r = result.tables.risks.find((x) => x.id === form.id); if (r && r.valid) { riskRow = r; renderResults(); } }
  }

  // ---- example banner ----------------------------------------------------------------
  function renderBanner() {
    const b = $("exbanner");
    if (!example) { b.innerHTML = ""; return; }
    b.innerHTML = '<div class="' + P + '-banner"><b>Showing ' + esc(example.label) + ".</b><span>Nothing here is saved. Saving a risk copies it into your register. Example settings (appetite and bands) are synthetic too.</span><button class=\"" + P + '-btn sm" id="' + P + '-exitex">Back to my register</button></div>';
    $("exitex").addEventListener("click", () => { example = null; heatFilter = null; renderBanner(); writeForm(blank()); riskRow = null; renderResults(); writeSettings(); schedule(); });
  }
  $("example").addEventListener("click", () => {
    example = exampleDataset(1, new Date().toISOString());
    heatFilter = null; renderBanner(); writeSettings(); writeForm(blank()); riskRow = null; renderResults(); tab("register"); schedule();
    toast("Loaded synthetic example (not saved)", "info");
  });

  // ---- save / delete / new / history ---------------------------------------------------
  $("new").addEventListener("click", () => { writeForm(blank()); riskRow = null; renderResults(); tab("risk"); F("title").focus(); });
  $("save").addEventListener("click", async () => {
    const r = readForm();
    if (!r.title) { toast("Give the risk a title first", "warning"); F("title").focus(); return; }
    const errs = validateLive();
    const at = new Date().toISOString();
    const by = F("by").value.trim();
    let row = null;
    if (!errs.length) row = await analyzeForm();
    const fromExample = !!example && !!r.id && r.id.startsWith("testorg-");
    const prev = !fromExample && r.id ? reg.get(r.id) : null;
    const rec = { ...r };
    if (fromExample) { delete rec.id; rec.history = []; }
    rec.snapshot = row ? snapshotOf(row, at) : null;
    const saved = reg.upsert(withHistory(prev, rec, { at, by }));
    if (example) { example = null; renderBanner(); writeSettings(); }
    writeForm(saved);
    toast(errs.length ? "Saved. Complete the ranges to include it in the analysis." : "Risk saved", errs.length ? "warning" : "success");
    schedule();
  });
  $("del").addEventListener("click", async () => {
    if (!form.id || example) return;
    const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Delete risk?", "This removes \"" + (form.title || "Untitled") + "\" and its history from the register and the Security Graph.", { danger: true }) : false;
    if (!ok) return;
    reg.remove(form.id);
    writeForm(blank()); riskRow = null; renderResults(); schedule();
    toast("Risk deleted", "success");
  });
  $("hist").addEventListener("click", () => {
    const d = $("histdrawer");
    if (d.style.display === "block") { d.style.display = "none"; return; }
    const h = (form.history || []).slice().reverse();
    d.style.display = "block";
    d.innerHTML = '<span class="' + P + '-lbl">History (last 50 saves)</span>' + (h.length ? '<div class="' + P + '-tbl" style="margin-top:6px"><table><thead><tr><th>When (UTC)</th><th>By</th><th>Change</th></tr></thead><tbody>' +
      h.map((x) => "<tr><td>" + esc(String(x.at || "").slice(0, 16).replace("T", " ")) + "</td><td>" + esc(x.by || "-") + "</td><td>" + esc(x.change) + "</td></tr>").join("") + "</tbody></table></div>" : '<div class="' + P + '-empty">No saves yet.</div>');
  });

  // ---- settings ---------------------------------------------------------------------
  function writeSettings() {
    const s = settings();
    F("s-currency").value = s.currency; F("s-appetiteAmount").value = s.appetiteAmount == null ? "" : s.appetiteAmount;
    F("s-appetitePercentile").value = String(s.appetitePercentile); F("s-staleDays").value = s.staleDays;
    F("s-freqBands").value = s.freqBands.join(", "); F("s-magBands").value = s.magBands.join(", ");
    F("s-iterations").value = s.iterations; F("s-seed").value = s.seed;
    $("ssave").disabled = !!example;
    $("setnote").innerHTML = example ? '<div class="' + P + '-banner">Showing the synthetic example\'s settings. Go back to your register to edit your own.</div>' : "";
    const st = sreg.get(SETTINGS_ID);
    $("ssaved").textContent = st && st.updatedAt ? "Saved " + String(st.updatedAt).slice(0, 16).replace("T", " ") + " UTC" : "Not saved yet";
  }
  $("ssave").addEventListener("click", () => {
    if (example) return;
    const raw = {
      currency: F("s-currency").value, appetiteAmount: F("s-appetiteAmount").value, appetitePercentile: Number(F("s-appetitePercentile").value),
      staleDays: Number(F("s-staleDays").value), freqBands: F("s-freqBands").value, magBands: F("s-magBands").value,
      iterations: Number(F("s-iterations").value), seed: Number(F("s-seed").value),
    };
    const s = normalizeSettings(raw);
    if (!/^[A-Z]{3}$/.test(s.currency)) { toast("Currency must be a 3-letter code", "error"); return; }
    for (const [k, l] of [["freqBands", "Frequency"], ["magBands", "Magnitude"]]) if (s[k].length && !bandsValid(s[k])) { toast(l + " bands need 4 ascending numbers", "error"); return; }
    if (F("s-appetiteAmount").value.trim() && s.appetiteAmount == null) { toast("Appetite amount is not a number", "error"); return; }
    sreg.upsert({ id: SETTINGS_ID, ...s });
    writeSettings(); toast("Settings saved", "success"); schedule();
  });

  // ---- exports ------------------------------------------------------------------------
  const stamp = () => fileStamp();
  $("exports").addEventListener("click", (ev) => {
    const x = ev.target.closest("[data-x]"); if (!x) return;
    const list = records();
    const need = (cond, msg) => { if (!cond) toast(msg, "warning"); return cond; };
    switch (x.dataset.x) {
      case "regcsv": if (need(list.length, "No risks to export")) download(TOOL_ID + "-register-" + stamp() + ".csv", registerToCsv(list), "text/csv"); break;
      case "regjson": if (need(list.length, "No risks to export")) download(TOOL_ID + "-register-" + stamp() + ".json", registerToJson(list, settings()), "application/json"); break;
      case "board": if (need(result, "Run the analysis first")) download(TOOL_ID + "-board-summary-" + stamp() + ".txt", boardSummary(result, { org: example ? example.org : "", now: new Date().toISOString() }), "text/plain"); break;
      case "lec": if (need(result && result.summary.simulated, "No simulated risks")) download(TOOL_ID + "-lec-" + stamp() + ".csv", lecToCsv(result), "text/csv"); break;
      case "ics": { const ev2 = reviewEvents(list, { stamp: new Date().toISOString() }); if (need(ev2.length, "No open risks with a review date")) download(TOOL_ID + "-reviews-" + stamp() + ".ics", toIcs(ev2), "text/calendar"); break; }
      case "fcsv": if (need(result, "Run the analysis first")) download(TOOL_ID + "-findings-" + stamp() + ".csv", findingsToCsv(result.findings), "text/csv"); break;
      case "fjson": if (need(result, "Run the analysis first")) download(TOOL_ID + "-findings-" + stamp() + ".json", toJson({ meta: result.meta, summary: result.summary, findings: result.findings, skipped: result.skipped }), "application/json"); break;
    }
  });
  updateSink = attachSinkButton($("exports"), () => ({ findings: (result && result.findings) || [], sample: !!example }), TOOL_ID, { dataset: "risk register" });

  // ---- import ---------------------------------------------------------------------------
  mountDropzone($("drop"), {
    maxBytes: 20 << 20, maxFiles: 10, unpack: true, accept: ".json,.csv,.tsv,.txt",
    label: "Drop a register JSON or a risk spreadsheet CSV",
    onFiles: async (files) => {
      const parsed = parseInput(await Promise.all(files.map(async (f) => ({ name: f.name, text: await f.text() }))));
      $("files").innerHTML = parsed.files.map((f) => "<div><b>" + esc(f.name) + "</b>: " + esc(f.format) + (f.count != null ? ", " + f.count + " row(s)" : "") + ', confidence <span class="' + P + '-conf">' + esc(f.confidence) + "</span></div>").join("") +
        parsed.skipped.map((s) => '<div class="' + P + '-mut">' + esc(s.reason) + "</div>").join("");
      if (parsed.records.length) {
        csvState = null;
        const m = $("mapping");
        m.innerHTML = '<div class="' + P + '-row"><span>' + parsed.records.length + " risk(s) ready to import" + (parsed.settings ? " (file also carries settings)" : "") + '.</span><button class="' + P + '-btn pri" id="' + P + '-impjson">Import into register</button>' +
          (parsed.settings ? '<label class="' + P + '-radio"><input type="checkbox" id="' + P + '-impset"> Also replace settings</label>' : "") + "</div>";
        $("impjson").addEventListener("click", () => {
          const at = new Date().toISOString();
          const recs = parsed.records.map((r) => withHistory(r.id ? reg.get(r.id) : null, r, { at, by: "JSON import" }));
          const out = reg.importJson(recs);
          if (parsed.settings && $("impset") && $("impset").checked) sreg.upsert({ id: SETTINGS_ID, ...normalizeSettings(parsed.settings) });
          leaveExample(); m.innerHTML = ""; $("files").innerHTML = "";
          toast(out.added + " added, " + out.updated + " updated", "success"); schedule();
        });
      } else if (parsed.rows.length) {
        csvState = { rows: parsed.rows, headers: parsed.headers, mapping: { ...parsed.mapping }, confidence: parsed.confidence };
        renderMapping();
      } else $("mapping").innerHTML = "";
    },
  });
  function leaveExample() { if (example) { example = null; renderBanner(); writeSettings(); } }
  function renderMapping() {
    const s = csvState, m = $("mapping");
    const opts = (k) => '<option value="">(not mapped)</option>' + s.headers.map((h) => '<option value="' + esc(h) + '"' + (s.mapping[k] === h ? " selected" : "") + ">" + esc(h) + "</option>").join("");
    const keyLabel = (k) => k.replace(/^res_/, "residual ").replace(/^lef/, "loss events/yr").replace(/^tef/, "threat events/yr").replace(/^vuln/, "vulnerability").replace(/^plm/, "primary loss").replace(/^slm/, "secondary loss").replace(/^slp/, "secondary probability").replace(/_/g, " ");
    const mapped = Object.keys(s.mapping).length;
    m.innerHTML = '<details' + (s.confidence === "high" ? "" : " open") + "><summary>Column mapping (" + mapped + " of " + CANON_HEADERS.length + " fields mapped, confidence " + esc(s.confidence) + ")</summary>" +
      '<p class="' + P + '-help">Title, primary loss (min, likely, max) and a frequency range are needed to simulate. Unmapped risks still import and show as "needs ranges".</p>' +
      '<div class="' + P + '-map">' + CANON_HEADERS.map((k) => '<div class="' + P + '-field"><label>' + esc(keyLabel(k)) + '</label><select data-map="' + k + '">' + opts(k) + "</select></div>").join("") + "</div></details>" +
      '<div class="' + P + '-row"><div class="' + P + '-field" style="width:140px"><label for="' + P + '-impcur">Currency if blank</label><input type="text" id="' + P + '-impcur" maxlength="3" value="' + esc(settings0().currency) + '"></div>' +
      '<button class="' + P + '-btn pri" id="' + P + '-impcsv">Import ' + s.rows.length + " row(s)</button></div>";
    m.querySelectorAll("[data-map]").forEach((el) => el.addEventListener("change", () => { if (el.value) s.mapping[el.dataset.map] = el.value; else delete s.mapping[el.dataset.map]; }));
    $("impcsv").addEventListener("click", () => {
      if (!s.mapping.title) { toast("Map the title column first", "error"); return; }
      const cur = ($("impcur").value || "").trim().toUpperCase();
      const recs = rowsToRecords(s.rows, s.mapping, { currency: cur, idPrefix: "imp-" + Date.now().toString(36) });
      if (!recs.length) { toast("No rows with a title", "error"); return; }
      const at = new Date().toISOString();
      let added = 0, updated = 0, incomplete = 0;
      for (const r of recs) {
        const prev = s.mapping.id && r.id ? reg.get(r.id) : null;
        if (validateRisk(r).length) incomplete++;
        reg.upsert(withHistory(prev, r, { at, by: "CSV import" }));
        prev ? updated++ : added++;
      }
      leaveExample(); csvState = null; m.innerHTML = ""; $("files").innerHTML = "";
      toast(added + " added, " + updated + " updated" + (incomplete ? ", " + incomplete + " need ranges" : ""), incomplete ? "warning" : "success");
      schedule();
    });
  }

  // ---- boot ----------------------------------------------------------------------------
  writeSettings(); writeForm(blank());
  reg.subscribe(() => { if (!example) schedule(); });
  sreg.subscribe(() => { if (!example) { writeSettings(); schedule(); } });
  Promise.all([reg.ready, sreg.ready]).then(() => Promise.all([reg.backfill(), sreg.backfill()])).then(() => { writeSettings(); schedule(); }).catch(() => schedule());
  schedule();
}
