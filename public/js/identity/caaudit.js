// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Conditional Access Audit (caaudit): Deck tool UI. Loads Entra CA policies JSON,
// Entra registration CSV, Okta policies JSON and Google 2SV CSV (any subset), runs
// the pure engine in a Worker and shows findings, the policy coverage matrix and
// the per-user registration table. Runs entirely in the browser; nothing is uploaded.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import { findColumn } from "../ingest/parse.js";
import {
  DEFAULTS, TOOL_ID, COLUMNS, KINDS, KIND_LABELS, parseInput, findingsToCsv, policyMatrixCsv,
  noPhishingResistantCsv, exampleDataset, MATRIX_COLS,
} from "./caaudit-engine.js?v=20261017c";

const ENGINE = engineUrl("./caaudit-engine.js?v=20261017c", import.meta);
const P = "caa";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CONF_RANK = { confirmed: 0, likely: 1, review: 2 };

const OPT_LABELS = {
  breakGlassMax: ["Break-glass accounts allowed", "Named users excluded from an MFA or block policy before it is flagged"],
  oktaMaxSessionHours: ["Okta max session lifetime (hours)", "maxSessionLifetimeMinutes above this is a weak session"],
  oktaMaxIdleMinutes: ["Okta max idle timeout (minutes)", "maxSessionIdleMinutes above this is a weak session"],
  maxFactorLifetimeHours: ["Max re-authentication interval (hours)", "Okta factor lifetime or Entra sign-in frequency above this is flagged (NIST AAL2: 12 h)"],
  evidenceRows: ["Evidence rows per finding", "Rows kept in each finding; the full count is always reported"],
};

const MATRIX_LABELS = {
  source: "Source", policy: "Policy", state: "State", includedUsers: "Users", includedGroups: "Groups", includedRoles: "Roles",
  excludedUsers: "Excluded users", excludedGroups: "Excluded groups", excludedRoles: "Excluded roles", apps: "Apps", excludedApps: "Excluded apps",
  clientApps: "Client apps", platforms: "Platforms", locations: "Locations", risk: "Risk", grant: "Grant", session: "Session",
};

const CSS = `
  .caa-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);min-width:0}
  .caa-root *{box-sizing:border-box}
  .caa-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .caa-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em;overflow-wrap:anywhere}
  .caa-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .caa-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:90ch}
  .caa-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .caa-card h2{font-size:.95rem;margin:0 0 10px;letter-spacing:.01em}
  .caa-card h2 small{font-weight:400;color:var(--mut,#667085);margin-left:8px}
  .caa-drop{border:1.5px dashed var(--line,#d7dbe3);border-radius:10px;padding:22px 14px;text-align:center;color:var(--mut,#667085);background:var(--bg,#fbfcfe)}
  .caa-drop.over,.caa-drop.dn-dz-over{border-color:#2552c6;background:var(--acc-soft,rgba(37,82,198,.06))}
  .caa-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px;min-width:0}
  .caa-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer;max-width:100%;overflow-wrap:anywhere}
  .caa-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .caa-btn.sm{font-size:.76rem;padding:4px 10px}
  .caa-btn:disabled{opacity:.5;cursor:default}
  .caa-files{display:flex;flex-direction:column;gap:8px;margin-top:12px}
  .caa-file{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:6px 12px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:8px 12px;background:var(--bg,#f7f8fb)}
  .caa-file b{overflow-wrap:anywhere}
  .caa-file .caa-meta{font-size:.76rem;color:var(--mut,#667085);overflow-wrap:anywhere}
  .caa-file select{font:inherit;font-size:.78rem;max-width:100%}
  .caa-conf{display:inline-block;font-size:.68rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085);white-space:nowrap}
  .caa-conf.high{border-color:#1a7f4b;color:#1a7f4b}.caa-conf.medium{border-color:#b58100;color:#b58100}.caa-conf.low{border-color:#b00020;color:#b00020}
  .caa-ctl{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px 18px}
  .caa-field{display:flex;flex-direction:column;gap:4px;min-width:0}
  .caa-field label{font-size:.74rem;font-weight:700;color:var(--tx,#1a2230)}
  .caa-field input,.caa-field select{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%}
  .caa-field small{font-size:.72rem;color:var(--mut,#667085);line-height:1.35;overflow-wrap:anywhere}
  .caa-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin:14px 0}
  .caa-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .caa-kpi b{display:block;font-size:1.3rem;overflow-wrap:anywhere}
  .caa-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .caa-kpi.critical b{color:#7a0012}.caa-kpi.high b{color:#b00020}.caa-kpi.medium b{color:#b58100}
  .caa-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .caa-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .caa-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%;background:var(--card,#fff)}
  .caa-list table{width:100%;border-collapse:collapse;font-size:.84rem;min-width:640px}
  .caa-list th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .caa-list th[data-k]{cursor:pointer;user-select:none}
  .caa-list th[data-k].on{color:var(--tx,#1a2230)}
  .caa-list td{padding:9px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:break-word}
  .caa-list tr[data-i]{cursor:pointer}
  .caa-list tr[data-i]:hover,.caa-list tr[data-i].sel{background:var(--bg,#f7f8fb)}
  .caa-list .caa-desc{color:var(--mut,#667085);font-size:.8rem;margin-top:2px}
  .caa-pill{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .caa-pill.critical{background:#7a0012}.caa-pill.high{background:#b00020}.caa-pill.medium{background:#b58100}.caa-pill.low{background:#2552c6}.caa-pill.info{background:#667085}
  .caa-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .caa-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .caa-drawer{margin-top:14px;display:none}
  .caa-drawer .caa-dh{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;flex-wrap:wrap}
  .caa-drawer p{margin:6px 0}
  .caa-ev{margin-top:10px;border:1px solid var(--line,#e6e8ee);border-radius:8px;overflow:auto;max-height:420px}
  .caa-ev table{border-collapse:collapse;font-size:.78rem;min-width:100%;width:max-content}
  .caa-ev th{position:sticky;top:0;background:var(--bg,#f7f8fb);text-align:left;padding:6px 10px;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .caa-ev td{padding:5px 10px;border-bottom:1px solid var(--line,#eef0f4);max-width:360px;overflow-wrap:anywhere;vertical-align:top}
  .caa-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px;overflow-wrap:anywhere}
  .caa-skip ul{margin:4px 0 0;padding-left:18px}
  .caa-sec{margin-top:14px}
  .caa-sec summary{cursor:pointer;font-weight:700;font-size:.92rem;padding:4px 0}
  .caa-sec summary small{font-weight:400;color:var(--mut,#667085);margin-left:8px}
  .caa-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0}
  .caa-ok{color:#1a7f4b;font-weight:600}.caa-bad{color:#b00020;font-weight:600}
  @media (max-width:560px){.caa-card{padding:12px}.caa-file{grid-template-columns:minmax(0,1fr)}.caa-hd h1{font-size:1.35rem}}
`;

const kpi = (v, l, cls) => '<div class="' + P + '-kpi ' + (cls || "") + '"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>";
const yn = (v) => (v === true || v === "true" ? "yes" : v === false || v === "false" ? "no" : v == null ? "" : String(v));
const confPill = (c) => '<span class="' + P + "-conf " + esc(c) + '">' + esc(c) + "</span>";

/** Mount the tool into main. */
export function renderCaAudit(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  const fields = Object.entries(DEFAULTS).map(([k, v]) => {
    const [label, help] = OPT_LABELS[k] || [k, ""];
    return '<div class="' + P + '-field"><label for="' + P + "-opt-" + k + '">' + esc(label) + '</label><input id="' + P + "-opt-" + k + '" data-opt="' + esc(k) + '" type="number" min="0" step="1" value="' + esc(v) + '"><small>' + esc(help) + " (default " + esc(v) + ")</small></div>";
  }).join("");

  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Conditional Access Audit</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Audits Microsoft Entra Conditional Access policies and registration details, Okta sign-on and enrollment policies and Google Workspace 2-Step Verification reports for MFA gaps, legacy authentication, over-broad exclusions, weak sessions and administrators without phishing-resistant methods. Runs entirely in your browser. Nothing is uploaded and nothing is fetched live.</p>',
    '<div class="', P, '-card"><h2>Inputs<small>any subset; each file is detected automatically</small></h2><div class="', P, '-drop" id="', P, '-drop"></div>',
    '<div class="', P, '-files" id="', P, '-files"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button><button class="', P, '-btn" id="', P, '-clear" disabled>Clear</button><span id="', P, '-count" class="', P, '-skip"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div></div>',
    '<div class="', P, '-card" id="', P, '-mapcard" style="display:none"><h2>Column mapping<small>detection confidence was not high; confirm the columns</small></h2><div id="', P, '-map"></div></div>',
    '<div class="', P, '-card"><h2>Thresholds</h2><div class="', P, '-ctl">', fields, "</div></div>",
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-row" id="', P, '-exports" style="margin:0 0 12px"></div>',
    '<div class="', P, '-list" id="', P, '-list"><div class="', P, '-empty">No analysis yet. Drop one or more exports above, or load the synthetic example.</div></div>',
    '<div class="', P, '-skip" id="', P, '-skipped"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div>',
    '<div id="', P, '-tables"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [];           // [{name, text}]
  let dataset = null;       // parseInput(files)
  let result = null;
  let isExample = false;
  const kindOverride = {};  // name -> kind
  const columnMap = { registration: {}, google: {} };
  let sortKey = "severity", sortDir = 1;

  const refreshDataset = () => {
    dataset = files.length ? parseInput(files) : null;
    renderFiles();
    renderMapping();
    const n = dataset ? dataset.rows.length : 0;
    $("count").textContent = files.length ? files.length + " file" + (files.length === 1 ? "" : "s") + ", " + n.toLocaleString() + " record" + (n === 1 ? "" : "s") : "";
    $("run").disabled = !n;
    $("clear").disabled = !files.length;
  };

  function renderFiles() {
    const host = $("files");
    if (!dataset) { host.innerHTML = ""; return; }
    host.innerHTML = dataset.sources.map((s) => {
      const kind = kindOverride[s.name] || s.kind;
      const opts = Object.keys(KIND_LABELS).map((k) => '<option value="' + k + '"' + (k === kind ? " selected" : "") + ">" + esc(KIND_LABELS[k]) + "</option>").join("");
      return '<div class="' + P + '-file"><div><b>' + esc(s.name) + '</b><div class="' + P + '-meta">' + esc(s.format.toUpperCase()) + " · " + s.rows.length.toLocaleString() + " record" + (s.rows.length === 1 ? "" : "s") + (s.headers.length ? " · " + s.headers.length + " fields" : "") +
        " · detected: " + esc(KIND_LABELS[s.kind] || s.kind) + " " + confPill(s.kindConfidence) + (s.skipped.length ? " · " + esc(s.skipped.map((x) => x.reason).join("; ")) : "") + "</div></div>" +
        '<label class="' + P + '-meta">Treat as <select data-src="' + esc(s.name) + '">' + opts + "</select></label></div>";
    }).join("");
    host.querySelectorAll("select[data-src]").forEach((sel) => sel.addEventListener("change", () => {
      kindOverride[sel.dataset.src] = sel.value;
      renderMapping();
    }));
  }

  function effectiveKind(s) { return kindOverride[s.name] || s.kind; }

  function renderMapping() {
    const card = $("mapcard"), host = $("map");
    if (!dataset) { card.style.display = "none"; host.innerHTML = ""; return; }
    const need = dataset.sources.filter((s) => {
      const k = effectiveKind(s);
      return (k === KINDS.ENTRA_REG || k === KINDS.GOOGLE) && (s.kindConfidence !== "high" || kindOverride[s.name]);
    });
    if (!need.length) { card.style.display = "none"; host.innerHTML = ""; return; }
    card.style.display = "";
    host.innerHTML = need.map((s) => {
      const k = effectiveKind(s), group = k === KINDS.GOOGLE ? "google" : "registration", spec = COLUMNS[group];
      const opt = (sel) => '<option value=""' + (!sel ? " selected" : "") + ">(not present)</option>" + s.headers.map((h) => '<option value="' + esc(h) + '"' + (h === sel ? " selected" : "") + ">" + esc(h) + "</option>").join("");
      return "<p class=\"" + P + "-note\" style=\"margin:0 0 8px\"><b>" + esc(s.name) + "</b> as " + esc(KIND_LABELS[k]) + "</p><div class=\"" + P + "-ctl\" style=\"margin-bottom:12px\">" +
        Object.keys(spec).map((col) => {
          const cur = columnMap[group][col] || findColumn(s.headers, spec[col]) || "";
          return '<div class="' + P + '-field"><label>' + esc(spec[col][0]) + '</label><select data-group="' + group + '" data-col="' + col + '">' + opt(cur) + "</select></div>";
        }).join("") + "</div>";
    }).join("");
    host.querySelectorAll("select[data-group]").forEach((sel) => sel.addEventListener("change", () => {
      if (sel.value) columnMap[sel.dataset.group][sel.dataset.col] = sel.value; else delete columnMap[sel.dataset.group][sel.dataset.col];
    }));
  }

  mountDropzone($("drop"), {
    maxBytes: 100 * 1024 * 1024,
    maxFiles: 25,
    multiple: true,
    label: "Drop Entra / Okta / Google exports here, paste, or browse",
    onFiles: async (list) => {
      let added = 0;
      for (const f of list) {
        let text = "";
        try { text = await f.text(); } catch (_) { toast("Could not read " + f.name, "error"); continue; }
        if (!text.trim()) { toast(f.name + " is empty", "warning"); continue; }
        const i = files.findIndex((x) => x.name === f.name);
        if (i >= 0) files[i] = { name: f.name, text }; else files.push({ name: f.name, text });
        added++;
      }
      if (!added) return;
      isExample = false;
      refreshDataset();
      const bad = dataset.sources.filter((s) => s.kind === KINDS.UNKNOWN && s.rows.length);
      if (bad.length) toast(bad.length + " file" + (bad.length === 1 ? "" : "s") + " not recognised; choose the export type under the file", "warning");
      else toast("Loaded " + added + " file" + (added === 1 ? "" : "s"), "success");
    },
  });

  $("clear").addEventListener("click", () => {
    files = []; dataset = null; result = null; isExample = false;
    for (const k of Object.keys(kindOverride)) delete kindOverride[k];
    columnMap.registration = {}; columnMap.google = {};
    refreshDataset();
    $("kpis").innerHTML = ""; $("exports").innerHTML = ""; $("skipped").innerHTML = ""; $("drawer").style.display = "none"; $("tables").innerHTML = "";
    $("list").innerHTML = '<div class="' + P + '-empty">No analysis yet. Drop one or more exports above, or load the synthetic example.</div>';
  });

  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    files = ex.files.map((f) => ({ name: f.name, text: f.text }));
    isExample = true;
    for (const k of Object.keys(kindOverride)) delete kindOverride[k];
    refreshDataset();
    toast("Synthetic example loaded (seeded, not real data). Click Analyze.", "info");
  });

  const opts = () => {
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (Number.isFinite(n) && n >= 0) o[el.dataset.opt] = n; });
    o.columnMap = { registration: { ...columnMap.registration }, google: { ...columnMap.google } };
    o.kindOverride = { ...kindOverride };
    return o;
  };

  $("run").addEventListener("click", async () => {
    if (!dataset) return;
    const prog = $("prog"), bar = prog.firstElementChild;
    prog.style.display = "block"; bar.style.width = "0%"; $("run").disabled = true;
    try {
      result = await runInWorker(ENGINE, "analyze", [dataset, opts()], {
        onProgress: (i, n) => { bar.style.width = (n ? Math.round(i / n * 100) : 100) + "%"; },
      });
      render(result);
      toast(result.findings.length + " finding" + (result.findings.length === 1 ? "" : "s") + " across " + result.meta.sources + " file" + (result.meta.sources === 1 ? "" : "s"), "success");
    } catch (e) {
      toast("Analysis failed: " + (e && e.message || e), "error");
    } finally {
      prog.style.display = "none"; $("run").disabled = !dataset;
    }
  });

  function sortedFindings(r) {
    const list = r.findings.map((f, i) => ({ f, i }));
    const key = sortKey;
    list.sort((a, b) => {
      let x, y;
      if (key === "severity") { x = SEV_RANK[a.f.severity]; y = SEV_RANK[b.f.severity]; }
      else if (key === "confidence") { x = CONF_RANK[a.f.confidence] ?? 9; y = CONF_RANK[b.f.confidence] ?? 9; }
      else if (key === "evidence") { x = a.f.evidenceCount; y = b.f.evidenceCount; }
      else if (key === "controls") { x = (a.f.controls || []).length; y = (b.f.controls || []).length; }
      else { x = a.f.title.toLowerCase(); y = b.f.title.toLowerCase(); }
      const c = x < y ? -1 : x > y ? 1 : 0;
      return (c || a.i - b.i) * (c ? sortDir : 1);
    });
    return list;
  }

  function render(r) {
    const sum = summarize(r.findings);
    const s = r.summary;
    let k = kpi(r.meta.sources, "files") + kpi(r.findings.length, "findings");
    for (const sev of ["critical", "high", "medium", "low"]) k += kpi(sum.bySeverity[sev] || 0, sev, sev);
    if (s.entra) k += kpi(s.entra.enabled + "/" + s.entra.policies, "Entra policies on") + kpi(s.entra.mfaAllUsers ? "yes" : "no", "all-users MFA") + kpi(s.entra.legacyBlocked ? "yes" : "no", "legacy blocked");
    if (s.registration) k += kpi(s.registration.mfaRegistered + "/" + s.registration.users, "MFA registered") + kpi(s.registration.adminsPhishingResistant + "/" + s.registration.admins, "admins phishing-resistant");
    if (s.okta) k += kpi(s.okta.rules + " in " + s.okta.policies, "Okta rules") + kpi(s.okta.mfaEveryoneRules ? "yes" : "no", "Okta factor for everyone");
    if (s.google) k += kpi(s.google.enrolled + "/" + s.google.active, "2SV enrolled") + kpi(s.google.enforced + "/" + s.google.active, "2SV enforced");
    $("kpis").innerHTML = k;

    $("skipped").innerHTML = r.skipped.length
      ? "<b>Not checked</b> (" + r.skipped.length + "):<ul>" + r.skipped.map((x) => "<li>" + esc(x.check) + " - " + esc(x.reason) + "</li>").join("") + "</ul>"
      : "";

    const ex = $("exports");
    ex.innerHTML = ['csv|Findings CSV', 'json|Full JSON', 'txt|Summary TXT', 'matrix|Policy coverage matrix CSV', 'nopr|Users without phishing-resistant MFA CSV']
      .map((x) => { const [id, label] = x.split("|"); return '<button class="' + P + '-btn" data-x="' + id + '">' + label + "</button>"; }).join("");
    const stamp = TOOL_ID + "-" + fileStamp();
    ex.querySelector('[data-x="csv"]').addEventListener("click", () => download(stamp + "-findings.csv", findingsToCsv(r.findings), "text/csv"));
    ex.querySelector('[data-x="json"]').addEventListener("click", () => download(stamp + ".json", toJson(r), "application/json"));
    ex.querySelector('[data-x="txt"]').addEventListener("click", () => download(stamp + "-summary.txt", summaryText(r, sum), "text/plain"));
    const mx = ex.querySelector('[data-x="matrix"]'); mx.disabled = !r.tables.policies.length;
    mx.addEventListener("click", () => download(stamp + "-policy-matrix.csv", policyMatrixCsv(r.tables.policies), "text/csv"));
    const np = ex.querySelector('[data-x="nopr"]'); np.disabled = !r.tables.registrations.length;
    np.addEventListener("click", () => download(stamp + "-no-phishing-resistant-mfa.csv", noPhishingResistantCsv(r.tables.registrations), "text/csv"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: files.map((f) => f.name).join(", ") });

    renderList(r);
    renderTables(r);
    $("drawer").style.display = "none";
  }

  function renderList(r) {
    const list = $("list");
    if (!r.findings.length) { list.innerHTML = '<div class="' + P + '-empty">No findings for the loaded exports and current thresholds.</div>'; return; }
    const th = (key, label) => '<th data-k="' + key + '" class="' + (sortKey === key ? "on" : "") + '">' + label + (sortKey === key ? (sortDir === 1 ? " ▴" : " ▾") : "") + "</th>";
    list.innerHTML = "<table><thead><tr>" + th("severity", "Severity") + th("title", "Finding") + th("confidence", "Confidence") + th("controls", "Controls") + th("evidence", "Evidence") + "</tr></thead><tbody>" +
      sortedFindings(r).map(({ f, i }) => '<tr data-i="' + i + '"><td><span class="' + P + "-pill " + esc(f.severity) + '">' + esc(f.severity) + "</span></td><td><b>" + esc(f.title) + '</b><div class="' + P + '-desc">' + esc(f.description) + "</div></td><td>" + esc(f.confidence) + "</td><td>" +
        (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</td><td>" + (f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length) + (f.assets && f.assets.length ? '<div class="' + P + '-desc">' + f.assets.length + " asset" + (f.assets.length === 1 ? "" : "s") + "</div>" : "") + "</td></tr>").join("") + "</tbody></table>";
    list.querySelectorAll("th[data-k]").forEach((h) => h.addEventListener("click", () => {
      if (sortKey === h.dataset.k) sortDir = -sortDir; else { sortKey = h.dataset.k; sortDir = 1; }
      renderList(r);
    }));
    list.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => {
      list.querySelectorAll("tr.sel").forEach((x) => x.classList.remove("sel")); tr.classList.add("sel");
      openDrawer(r.findings[Number(tr.dataset.i)]);
    }));
  }

  function evidenceTable(rows, labels) {
    if (!rows || !rows.length) return '<p class="' + P + '-note">No row-level evidence; this is a tenant-wide absence check.</p>';
    const cols = []; for (const row of rows) for (const k of Object.keys(row)) if (!cols.includes(k)) cols.push(k);
    return '<div class="' + P + '-ev"><table><thead><tr>' + cols.map((c) => "<th>" + esc(labels && labels[c] || c) + "</th>").join("") + "</tr></thead><tbody>" +
      rows.map((row) => "<tr>" + cols.map((c) => "<td>" + esc(typeof row[c] === "boolean" ? yn(row[c]) : row[c]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
  }

  function openDrawer(f) {
    const d = $("drawer"); d.style.display = "block";
    const shown = (f.evidence || []).length, total = f.evidenceCount != null ? f.evidenceCount : shown;
    d.innerHTML = '<div class="' + P + '-card"><div class="' + P + '-dh"><div><span class="' + P + "-pill " + esc(f.severity) + '">' + esc(f.severity) + "</span> <b>" + esc(f.title) + "</b></div>" +
      '<button class="' + P + '-btn sm" data-close>Close</button></div>' +
      "<p>" + esc(f.description) + "</p><p><b>Recommendation.</b> " + esc(f.recommendation) + "</p>" +
      "<p>" + (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + " <span class=\"" + P + "-chip\">confidence: " + esc(f.confidence) + "</span></p>" +
      (f.assets && f.assets.length ? '<p class="' + P + '-note">Affected: ' + f.assets.slice(0, 40).map((a) => esc(a.type.toLowerCase() + " " + a.name)).join(", ") + (f.assets.length > 40 ? " and " + (f.assets.length - 40) + " more" : "") + "</p>" : "") +
      "<h2 style=\"margin-top:12px\">Evidence<small>" + (total > shown ? "showing " + shown + " of " + total + " rows; the CSV exports carry the full set" : total + " row" + (total === 1 ? "" : "s")) + "</small></h2>" +
      evidenceTable(f.evidence, MATRIX_LABELS) + "</div>";
    d.querySelector("[data-close]").addEventListener("click", () => { d.style.display = "none"; });
    d.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function renderTables(r) {
    const host = $("tables");
    const parts = [];
    if (r.tables.policies.length) {
      const cols = MATRIX_COLS.filter((c) => r.tables.policies.some((row) => String(row[c] ?? "") !== ""));
      parts.push('<details class="' + P + '-sec" open><summary>Policy coverage matrix<small>' + r.tables.policies.length + " row" + (r.tables.policies.length === 1 ? "" : "s") + "</small></summary>" +
        '<div class="' + P + '-ev" style="max-height:520px"><table><thead><tr>' + cols.map((c) => "<th>" + esc(MATRIX_LABELS[c] || c) + "</th>").join("") + "</tr></thead><tbody>" +
        r.tables.policies.map((row) => "<tr>" + cols.map((c) => "<td" + (c === "state" ? ' class="' + (/^enabled|active/.test(String(row[c])) ? P + "-ok" : P + "-bad") + '"' : "") + ">" + esc(row[c]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div></details>");
    }
    if (r.tables.registrations.length) {
      const rows = r.tables.registrations;
      parts.push('<details class="' + P + '-sec"><summary>MFA registration by user<small>' + rows.length + " user" + (rows.length === 1 ? "" : "s") + "</small></summary>" +
        '<div class="' + P + '-ev" style="max-height:520px"><table><thead><tr><th>User</th><th>Name</th><th>Admin</th><th>MFA registered</th><th>MFA capable</th><th>Passwordless</th><th>Phishing-resistant</th><th>Methods</th><th>Default method</th></tr></thead><tbody>' +
        rows.map((u) => "<tr><td>" + esc(u.upn) + "</td><td>" + esc(u.displayName) + "</td><td>" + yn(u.isAdmin) + "</td><td class=\"" + (u.mfaRegistered === false ? P + "-bad" : "") + "\">" + yn(u.mfaRegistered) + "</td><td>" + yn(u.mfaCapable) + "</td><td>" + yn(u.passwordless) + "</td><td class=\"" + (u.phishingResistant ? P + "-ok" : u.isAdmin ? P + "-bad" : "") + "\">" + yn(u.phishingResistant) + "</td><td>" + esc(u.methods) + "</td><td>" + esc(u.defaultMethod) + "</td></tr>").join("") + "</tbody></table></div></details>");
    }
    if (r.tables.googleUsers.length) {
      const rows = r.tables.googleUsers;
      parts.push('<details class="' + P + '-sec"><summary>Google Workspace 2-Step Verification by user<small>' + rows.length + " user" + (rows.length === 1 ? "" : "s") + "</small></summary>" +
        '<div class="' + P + '-ev" style="max-height:520px"><table><thead><tr><th>Email</th><th>Name</th><th>Admin</th><th>Enrolled</th><th>Enforced</th><th>Suspended</th><th>Last login</th></tr></thead><tbody>' +
        rows.map((u) => "<tr><td>" + esc(u.email) + "</td><td>" + esc(u.name) + "</td><td>" + esc(u.adminStatus || yn(u.admin)) + "</td><td class=\"" + (u.enrolled === false && !u.suspended ? P + "-bad" : u.enrolled ? P + "-ok" : "") + "\">" + yn(u.enrolled) + "</td><td>" + yn(u.enforced) + "</td><td>" + yn(u.suspended) + "</td><td>" + esc(u.lastLogin) + "</td></tr>").join("") + "</tbody></table></div></details>");
    }
    if (r.tables.oktaEnrollment.length) {
      const rows = r.tables.oktaEnrollment;
      parts.push('<details class="' + P + '-sec"><summary>Okta authenticator enrollment<small>' + rows.length + " authenticator" + (rows.length === 1 ? "" : "s") + "</small></summary>" +
        '<div class="' + P + '-ev"><table><thead><tr><th>Policy</th><th>Status</th><th>Authenticator</th><th>Enrollment</th></tr></thead><tbody>' +
        rows.map((e) => "<tr><td>" + esc(e.policy) + "</td><td>" + esc(e.status) + "</td><td>" + esc(e.authenticator) + "</td><td class=\"" + (e.enrollment === "REQUIRED" ? P + "-ok" : "") + "\">" + esc(e.enrollment) + "</td></tr>").join("") + "</tbody></table></div></details>");
    }
    host.innerHTML = parts.join("");
  }

  function summaryText(r, sum) {
    const s = r.summary;
    const lines = ["Conditional Access Audit summary", "Tool: " + TOOL_ID + " " + r.meta.version, "Files: " + r.meta.sources + (isExample ? " (synthetic example)" : ""), "Records: " + r.meta.rows,
      "Findings: " + r.findings.length + " (critical " + (sum.bySeverity.critical || 0) + ", high " + (sum.bySeverity.high || 0) + ", medium " + (sum.bySeverity.medium || 0) + ", low " + (sum.bySeverity.low || 0) + ")", ""];
    for (const src of s.sources) lines.push("Source: " + src.name + " -> " + (KIND_LABELS[src.kind] || src.kind) + ", " + src.rows + " records");
    if (s.entra) lines.push("", "Entra: " + s.entra.policies + " policies (" + s.entra.enabled + " enabled, " + s.entra.reportOnly + " report-only, " + s.entra.disabled + " disabled); all-users MFA enforced: " + (s.entra.mfaAllUsers ? "yes" : "no") + "; legacy auth blocked for all: " + (s.entra.legacyBlocked ? "yes" : "no"));
    if (s.registration) lines.push("Registration: " + s.registration.users + " users, " + s.registration.mfaRegistered + " MFA registered, " + s.registration.notRegistered + " not registered; admins " + s.registration.admins + ", phishing-resistant admins " + s.registration.adminsPhishingResistant);
    if (s.okta) lines.push("Okta: " + s.okta.policies + " policies, " + s.okta.rules + " rules; factor required for everyone: " + (s.okta.mfaEveryoneRules ? "yes" : "no"));
    if (s.google) lines.push("Google: " + s.google.active + " active users, " + s.google.enrolled + " enrolled in 2SV, " + s.google.enforced + " enforced; admins " + s.google.admins);
    lines.push("", "Findings:");
    for (const f of r.findings) lines.push("- [" + f.severity + "/" + f.confidence + "] " + f.title + " (" + (f.controls || []).map((c) => c.framework + " " + c.id).join(", ") + ")", "    " + f.recommendation);
    if (r.skipped.length) { lines.push("", "Not checked:"); for (const x of r.skipped) lines.push("- " + x.check + ": " + x.reason); }
    return lines.join("\n") + "\n";
  }

  refreshDataset();
}
