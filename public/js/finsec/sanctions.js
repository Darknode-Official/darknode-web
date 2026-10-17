// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Sanctions Screening — screen payees, vendors and counterparties against the
// official US Treasury OFAC SDN list (names + aliases). The list is mirrored into
// the site and refreshed daily (scripts/refresh-feeds.mjs); matching runs entirely
// in your browser and the names you screen are never uploaded.
//
//   renderSanctions(main) -> void
//
// Honesty (shown in the UI): watchlist name matching is a SCREENING AID, not a
// compliance determination. Hits must be verified against the official source,
// and blocking / reporting decisions are a human + legal responsibility.

import { buildIndex, screenBatch, screenBatchAsync, selfTest } from "/js/finsec/sanctions-engine.js?v=20261014d";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.showToast || (() => {}))(m); } catch (_) {} };
const AUDIT_KEY = "dn_sanctions_audit_v1";
const DISPOSITIONS = ["pending", "cleared", "escalate", "confirmed"];
const DISP_LABEL = { pending: "Pending review", cleared: "Cleared", escalate: "Escalate", confirmed: "Confirmed" };

// The official OFAC SDN list (names + aliases) is mirrored into the site and
// refreshed daily by scripts/refresh-feeds.mjs (GitHub Actions). Loading it
// same-origin is fast and reliable; the upstream OFAC host blocks edge fetches.
const LIST_URL = "/data/feeds/ofac-sdn.json";

const BAND = {
  exact:    { label: "Exact",    c: "#b00020" },
  strong:   { label: "Strong",   c: "#d9480f" },
  possible: { label: "Possible", c: "#b58100" },
  weak:     { label: "Weak",     c: "#2b6cb0" },
  clear:    { label: "Clear",    c: "#2f9e56" },
};

let injected = false;
function injectStyle() {
  if (injected) return; injected = true;
  const st = document.createElement("style"); st.id = "sanc-css";
  st.textContent = `
  .sanc{width:100%;font-size:14px;line-height:1.5}
  .sanc .snc-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .sanc h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .sanc .snc-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .sanc .snc-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:70ch}
  .sanc .snc-warn{background:var(--acc-soft,rgba(181,129,0,.08));border:1px solid var(--line,#e6e8ee);border-left:3px solid #b58100;border-radius:8px;padding:11px 14px;color:var(--tx,#1a2230);font-size:.84rem;margin-bottom:16px}
  .sanc .snc-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px}
  .sanc h3{font-size:.95rem;margin:0 0 6px}
  .sanc .snc-note{color:var(--mut,#667085);font-size:.82rem;margin:0 0 10px;overflow-wrap:anywhere}
  .sanc textarea{width:100%;min-height:150px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;line-height:1.55;padding:10px 12px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--bg,#fbfcfe);color:var(--tx,#1a2230);box-sizing:border-box}
  .sanc .snc-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:10px}
  .sanc .snc-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .sanc .snc-btn:hover{border-color:#9aa6bd}
  .sanc .snc-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .sanc .snc-btn.pri:hover{background:#1c42a6}
  .sanc .snc-btn:disabled{opacity:.55;cursor:default}
  .sanc .snc-file{font-size:.8rem;color:var(--mut,#667085)}
  .sanc .snc-stat{display:flex;gap:18px;flex-wrap:wrap;margin:14px 0}
  .sanc .snc-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:120px}
  .sanc .snc-kpi b{display:block;font-size:1.5rem;line-height:1.2}
  .sanc .snc-kpi span{font-size:.74rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .sanc .snc-list{margin-top:14px;border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:hidden}
  .sanc table{width:100%;border-collapse:collapse;font-size:.86rem}
  .sanc th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 14px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee)}
  .sanc td{padding:10px 14px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .sanc tr:last-child td{border-bottom:0}
  .sanc .snc-pill{display:inline-block;font-size:.7rem;font-weight:700;color:#fff;padding:2px 8px;border-radius:999px;white-space:nowrap}
  .sanc .snc-hit{background:var(--bg,#fdf6f6)}
  .sanc .snc-match{margin:2px 0;padding:0}
  .sanc .snc-match b{font-weight:600}
  .sanc .snc-prog{font-size:.72rem;color:var(--mut,#667085)}
  .sanc .snc-score{font-variant-numeric:tabular-nums;font-weight:700}
  .sanc .snc-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .sanc .snc-meta{font-size:.78rem;color:var(--mut,#667085);margin-top:8px}
  .sanc .snc-selftest .ok{color:#2f9e56;font-weight:600}
  .sanc .snc-selftest .bad{color:#b00020;font-weight:600}
  .sanc .snc-spin{display:inline-block;width:14px;height:14px;border:2px solid var(--line,#d7dbe3);border-top-color:#2552c6;border-radius:50%;animation:scSpin .7s linear infinite;vertical-align:-2px;margin-right:6px}
  @keyframes scSpin{to{transform:rotate(360deg)}}
  .sanc .snc-ctl{display:flex;flex-wrap:wrap;gap:14px 20px;align-items:flex-end;margin-top:12px;padding-top:12px;border-top:1px solid var(--line,#eef0f4)}
  .sanc .snc-field{display:flex;flex-direction:column;gap:4px;min-width:0}
  .sanc .snc-field > label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .sanc .snc-field .snc-hint{font-size:.72rem;color:var(--mut,#667085);font-weight:400;text-transform:none;letter-spacing:0}
  .sanc input[type=number],.sanc input[type=text],.sanc select{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;box-sizing:border-box}
  .sanc input[type=number]{width:92px}
  .sanc input[type=range]{width:150px;accent-color:#2552c6;vertical-align:middle}
  .sanc .snc-rng{display:flex;align-items:center;gap:8px}
  .sanc .snc-rng b{font-variant-numeric:tabular-nums;min-width:2ch;text-align:right}
  .sanc select{min-width:140px}
  .sanc input[type=text].snc-prog-in{width:170px}
  .sanc .snc-second{font-size:.72rem;color:var(--mut,#667085);margin-top:3px;display:flex;flex-wrap:wrap;gap:3px 10px}
  .sanc .snc-second span{white-space:nowrap}
  .sanc .snc-disp{font-size:.78rem;padding:5px 8px}
  .sanc .snc-disp[data-d=cleared]{border-color:#2f9e56;color:#2f9e56}
  .sanc .snc-disp[data-d=escalate]{border-color:#d9480f;color:#d9480f}
  .sanc .snc-disp[data-d=confirmed]{border-color:#b00020;color:#b00020}
  .sanc .snc-audit{margin-top:18px;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--card,#fff)}
  .sanc .snc-audit h3{margin:0 0 4px}
  .sanc .snc-audit table{margin-top:10px}
  .sanc .snc-audit .snc-prog{font-variant-numeric:tabular-nums}
  @media(max-width:640px){.sanc th.snc-hide,.sanc td.snc-hide{display:none}}
  `;
  document.head.appendChild(st);
}

function download(name, text, mime) {
  const b = new Blob([text], { type: mime || "text/csv" });
  const u = URL.createObjectURL(b); const a = document.createElement("a");
  a.href = u; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(u), 1000);
}

// -------------------- screening audit log (localStorage, per browser) --------------------
// Regulators expect proof a screen ran: who, when, which list version, and the analyst's
// disposition of each hit. Stored locally only — like everything else here, nothing leaves
// the browser. This is a record of the screen, not a compliance determination.
function auditLoad() {
  try { const v = JSON.parse(localStorage.getItem(AUDIT_KEY) || "[]"); return Array.isArray(v) ? v : []; }
  catch (_) { return []; }
}
function auditSave(list) {
  try { localStorage.setItem(AUDIT_KEY, JSON.stringify(list.slice(-200))); return true; }
  catch (_) { return false; }
}
function auditUpsert(rec) {
  const list = auditLoad();
  const i = list.findIndex((r) => r.id === rec.id);
  if (i >= 0) list[i] = rec; else list.push(rec);
  auditSave(list);
}
function auditClear() { try { localStorage.removeItem(AUDIT_KEY); } catch (_) {} }

function auditToCsv(list) {
  const q = (s) => `"${String(s == null ? "" : s).replace(/"/g, '""')}"`;
  const lines = ["screen_id,screened_at,analyst,list_source,list_updated,list_entries,min_score,result_limit,entity_type,program_filter,names_screened,to_review,strong_exact,name,disposition"];
  for (const rec of list) {
    const base = [q(rec.id), q(rec.screenedAt), q(rec.analyst), q(rec.listSource), q(rec.listUpdated),
      rec.listEntries, rec.params.minScore, rec.params.limit, q(rec.params.type), q(rec.params.program),
      rec.totals.screened, rec.totals.review, rec.totals.strong];
    const disp = rec.dispositions || {};
    const names = Object.keys(disp);
    if (!names.length) { lines.push(base.concat([q(""), q("")]).join(",")); continue; }
    for (const nm of names) lines.push(base.concat([q(nm), q(disp[nm])]).join(","));
  }
  return lines.join("\n") + "\n";
}

// module cache: the parsed list is large (~19k entries); keep it for the session.
let _index = null, _meta = null, _loading = null;

async function ensureList() {
  if (_index) return { index: _index, meta: _meta };
  if (_loading) return _loading;
  _loading = (async () => {
    const res = await fetch(LIST_URL, { cache: "default" });
    if (!res.ok) throw new Error("HTTP " + res.status + " loading the sanctions list.");
    const feed = await res.json();
    const entries = feed && Array.isArray(feed.data) ? feed.data : null;
    if (!entries || !entries.length) throw new Error("The sanctions list is empty.");
    _index = buildIndex(entries);
    _meta = { count: entries.length, source: feed.source || "OFAC SDN", updated: feed.updated ? new Date(feed.updated) : null };
    _loading = null;
    return { index: _index, meta: _meta };
  })();
  try { return await _loading; } catch (e) { _loading = null; throw e; }
}

// Split pasted/loaded text into name rows. One name per line; if a line looks like
// CSV, take the first non-numeric column (so a payments export can be screened too).
function parseNames(text) {
  const out = [];
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    let name = line;
    if (line.includes(",")) {
      const cols = line.split(",").map((c) => c.trim().replace(/^"|"$/g, ""));
      // header row? skip if it looks like column names
      if (out.length === 0 && /\b(name|vendor|payee|party|counterparty|beneficiary)\b/i.test(line) && cols.length > 1) {
        continue;
      }
      name = cols.find((c) => c && !/^[\d.,$()-]+$/.test(c)) || cols[0];
    }
    if (name) out.push(name);
  }
  return out;
}

export function renderSanctions(main) {
  injectStyle();
  main.innerHTML = `
  <div class="sanc">
    <div class="snc-hd"><h1>Sanctions Screening</h1><span class="snc-tag">Financial Security</span></div>
    <div class="snc-sub">Screen payees, vendors and counterparties against the official US Treasury <b>OFAC SDN</b> list
      (primary names and aliases), refreshed daily. Matching runs in your browser and the names you screen are
      never uploaded.</div>

    <div class="snc-warn"><b>A screening aid, not a determination.</b> Name matching flags parties to review against the
      official source; a hit is <b>not</b> proof a party is sanctioned, and common names cause false positives by design.
      This screen does not cover the OFAC 50% ownership rule, licences, or non-SDN lists. Blocking, rejecting and
      reporting decisions are yours and your compliance/legal team's.</div>

    <div class="snc-card">
      <h3>Names to screen</h3>
      <p class="snc-note">One name per line. You can also paste a CSV or payments export — the first text column of each
        row is screened, so a vendor or payments list works as-is.</p>
      <textarea id="scIn" placeholder="One name per line"></textarea>
      <div class="snc-ctl">
        <div class="snc-field">
          <label for="scMin">Match threshold <span class="snc-hint">min score to flag</span></label>
          <div class="snc-rng"><input type="range" id="scMin" min="60" max="100" step="1" value="80"><b id="scMinV">80</b></div>
        </div>
        <div class="snc-field">
          <label for="scLimit">Matches per name</label>
          <input type="number" id="scLimit" min="1" max="50" step="1" value="5">
        </div>
        <div class="snc-field">
          <label for="scType">Entity type</label>
          <select id="scType">
            <option value="all">All types</option>
            <option value="individual">Individuals</option>
            <option value="entity">Entities</option>
            <option value="vessel">Vessels</option>
            <option value="aircraft">Aircraft</option>
          </select>
        </div>
        <div class="snc-field">
          <label for="scProg">Program <span class="snc-hint">optional</span></label>
          <input type="text" id="scProg" class="snc-prog-in" placeholder="e.g. RUSSIA" maxlength="40">
        </div>
        <div class="snc-field">
          <label for="scWho">Analyst <span class="snc-hint">for the record</span></label>
          <input type="text" id="scWho" placeholder="your name / id" maxlength="60">
        </div>
      </div>
      <div class="snc-row">
        <button class="snc-btn pri" id="scRun">Screen names</button>
        <label class="snc-btn">Load file<input type="file" id="scFile" accept=".csv,.txt,text/csv" hidden></label>
        <span class="snc-file" id="scFileName"></span>
        <button class="snc-btn" id="scSample">Load example</button>
        <button class="snc-btn" id="scClear">Clear</button>
        <button class="snc-btn" id="scTest">Self-test</button>
        <span class="snc-selftest" id="scTestOut"></span>
      </div>
      <div class="snc-meta" id="scListMeta"></div>
    </div>

    <div id="scOut"></div>
    <div id="scAudit"></div>
  </div>`;

  const $ = (id) => main.querySelector("#" + id);
  const inTA = $("scIn");
  let currentAudit = null; // the audit record for the most recent screen in this view

  $("scMin").addEventListener("input", () => { $("scMinV").textContent = $("scMin").value; });

  $("scFile").addEventListener("change", (e) => {
    const f = e.target.files && e.target.files[0]; if (!f) return;
    const fr = new FileReader();
    fr.onload = () => { inTA.value = String(fr.result || ""); $("scFileName").textContent = f.name; };
    fr.onerror = () => toast("Could not read file");
    fr.readAsText(f);
  });
  $("scSample").addEventListener("click", () => {
    inTA.value = ["Darknode Test Shipping LLC", "Vladimir Putin", "Bank Melli Iran", "Darknode Test Trading Ltd", "Nicolas Maduro", "Test User"].join("\n");
    $("scFileName").textContent = "";
  });
  $("scClear").addEventListener("click", () => { inTA.value = ""; $("scFileName").textContent = ""; $("scOut").innerHTML = ""; currentAudit = null; });
  $("scTest").addEventListener("click", () => {
    const { pass, results } = selfTest();
    $("scTestOut").innerHTML = pass
      ? `<span class="ok">Self-test passed</span> — ${results.length}/${results.length} checks`
      : `<span class="bad">Self-test failed</span> — ${results.filter((r) => !r.pass).map((r) => r.name).join(", ")}`;
  });

  $("scRun").addEventListener("click", run);
  inTA.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(); });

  function readParams() {
    const minScore = Math.max(60, Math.min(100, parseInt($("scMin").value, 10) || 80));
    const limit = Math.max(1, Math.min(50, parseInt($("scLimit").value, 10) || 5));
    const type = $("scType").value || "all";
    const program = ($("scProg").value || "").trim();
    return { minScore, limit, type, program };
  }

  async function run() {
    const names = parseNames(inTA.value);
    const out = $("scOut");
    if (!names.length) { out.innerHTML = `<div class="snc-card snc-empty">Enter at least one name to screen.</div>`; return; }
    const btn = $("scRun"); btn.disabled = true;
    out.innerHTML = `<div class="snc-card"><span class="snc-spin"></span>Loading the OFAC list…</div>`;
    let index, meta;
    try { ({ index, meta } = await ensureList()); }
    catch (e) {
      btn.disabled = false;
      out.innerHTML = `<div class="snc-card snc-empty">Could not load the OFAC list.<br><span class="snc-note">${esc((e && e.message) || e)}</span></div>`;
      return;
    }
    $("scListMeta").textContent = `${meta.source} loaded: ${meta.count.toLocaleString()} entries` + (meta.updated ? ` · refreshed ${meta.updated.toLocaleDateString()}` : "");
    const p = readParams();
    const opts = { minScore: p.minScore, limit: p.limit, types: p.type, program: p.program };
    // Chunked + yielding so a long name list against ~19k entries never freezes the UI.
    const rows = await screenBatchAsync(names, index, opts, (done, tot) => {
      out.innerHTML = `<div class="snc-card"><span class="snc-spin"></span>Screening ${done.toLocaleString()} / ${tot.toLocaleString()} name(s)…</div>`;
    });
    btn.disabled = false;

    const hits = rows.filter((r) => r.hit);
    const strong = hits.filter((r) => r.topBand === "exact" || r.topBand === "strong").length;
    // Audit record: proof a screen ran, with the list version it ran against.
    currentAudit = {
      id: "SCR-" + Date.now().toString(36).toUpperCase(),
      screenedAt: new Date().toISOString(),
      analyst: ($("scWho").value || "").trim(),
      listSource: meta.source || "OFAC SDN",
      listUpdated: meta.updated ? meta.updated.toISOString() : "",
      listEntries: meta.count,
      params: p,
      totals: { screened: names.length, review: hits.length, strong },
      dispositions: {}, // name -> disposition; hits default to "pending"
    };
    for (const r of hits) currentAudit.dispositions[r.name] = "pending";
    auditUpsert(currentAudit);

    renderResults(out, rows, names.length);
    renderAudit();
  }

  function renderResults(out, rows, total) {
    const hits = rows.filter((r) => r.hit);
    const strong = hits.filter((r) => r.topBand === "exact" || r.topBand === "strong").length;
    out.innerHTML = `
      <div class="snc-stat">
        <div class="snc-kpi"><b>${total}</b><span>Screened</span></div>
        <div class="snc-kpi"><b style="color:${hits.length ? "#d9480f" : "#2f9e56"}">${hits.length}</b><span>To review</span></div>
        <div class="snc-kpi"><b style="color:${strong ? "#b00020" : "var(--tx,#1a2230)"}">${strong}</b><span>Strong / exact</span></div>
        <div class="snc-kpi"><b style="color:#2f9e56">${total - hits.length}</b><span>Clear</span></div>
      </div>
      <div class="snc-meta">Screen <b>${esc(currentAudit ? currentAudit.id : "")}</b> recorded. Disposition each hit below — it is saved to the audit log in this browser.</div>
      <div class="snc-row" style="margin:6px 0 4px">
        <button class="snc-btn" id="scExp">Export results (CSV)</button>
      </div>
      <div class="snc-list"><table>
        <thead><tr><th>Name screened</th><th>Result</th><th>Best match</th><th class="snc-hide">Program / identifiers</th><th>Score</th><th>Disposition</th></tr></thead>
        <tbody>${rows.map(rowHtml).join("")}</tbody>
      </table></div>`;
    out.querySelector("#scExp").addEventListener("click", () => download("sanctions-screening.csv", toCsv(rows)));
    out.querySelectorAll("select.snc-disp").forEach((sel) => {
      sel.addEventListener("change", () => {
        if (!currentAudit) return;
        currentAudit.dispositions[sel.dataset.name] = sel.value;
        sel.setAttribute("data-d", sel.value);
        auditUpsert(currentAudit);
        renderAudit();
      });
    });
  }

  function dispSelect(name) {
    const cur = (currentAudit && currentAudit.dispositions[name]) || "pending";
    const opts = DISPOSITIONS.map((d) => `<option value="${d}"${d === cur ? " selected" : ""}>${DISP_LABEL[d]}</option>`).join("");
    return `<select class="snc-btn snc-disp" data-d="${esc(cur)}" data-name="${esc(name)}">${opts}</select>`;
  }

  function rowHtml(r) {
    const b = BAND[r.hit ? r.topBand : "clear"];
    const top = r.matches[0];
    const extra = r.matches.length > 1 ? `<div class="snc-prog">+${r.matches.length - 1} more match${r.matches.length - 1 === 1 ? "" : "es"}</div>` : "";
    // Secondary identifiers to disambiguate common names — shown only when present.
    const sec = top ? [
      top.type ? `<span>type: ${esc(entityLabel(top.type))}</span>` : "",
      top.dob ? `<span>DOB: ${esc(top.dob)}</span>` : "",
      top.nationality ? `<span>nat: ${esc(top.nationality)}</span>` : "",
    ].filter(Boolean).join("") : "";
    return `<tr class="${r.hit ? "snc-hit" : ""}">
      <td><b>${esc(r.name)}</b></td>
      <td><span class="snc-pill" style="background:${b.c}">${b.label}</span></td>
      <td>${top ? `<div class="snc-match"><b>${esc(top.name)}</b></div>${top.matchedName !== top.name ? `<div class="snc-prog">matched alias: ${esc(top.matchedName)}</div>` : ""}${extra}` : `<span class="snc-note">—</span>`}</td>
      <td class="snc-hide">${top ? `<span class="snc-prog">${esc(top.program || "—")}</span>${sec ? `<div class="snc-second">${sec}</div>` : ""}` : ""}</td>
      <td class="snc-score" style="color:${b.c}">${r.hit ? r.topScore : ""}</td>
      <td>${r.hit ? dispSelect(r.name) : `<span class="snc-note">—</span>`}</td>
    </tr>`;
  }

  function renderAudit() {
    const host = $("scAudit");
    if (!host) return;
    const log = auditLoad();
    if (!log.length) { host.innerHTML = ""; return; }
    const recent = log.slice(-10).reverse();
    const rowsHtml = recent.map((rec) => {
      const d = rec.dispositions || {};
      const conf = Object.values(d).filter((x) => x === "confirmed").length;
      const esc8 = (rec.listUpdated || "").slice(0, 10);
      return `<tr>
        <td><b>${esc(rec.id)}</b><div class="snc-prog">${esc((rec.screenedAt || "").replace("T", " ").slice(0, 16))}</div></td>
        <td>${esc(rec.analyst || "—")}</td>
        <td class="snc-hide"><span class="snc-prog">${esc(rec.listSource || "")}${esc8 ? " · " + esc8 : ""} · ${Number(rec.listEntries || 0).toLocaleString()}</span></td>
        <td class="snc-hide"><span class="snc-prog">min ${rec.params.minScore}${rec.params.type && rec.params.type !== "all" ? " · " + esc(rec.params.type) : ""}${rec.params.program ? " · prog " + esc(rec.params.program) : ""}</span></td>
        <td><span class="snc-prog">${rec.totals.screened} screened · ${rec.totals.review} to review${conf ? " · " + conf + " confirmed" : ""}</span></td>
      </tr>`;
    }).join("");
    host.innerHTML = `
      <div class="snc-audit">
        <h3>Screening audit log</h3>
        <p class="snc-note">A local record (this browser only) that a screen ran — who, when, the list version, and your disposition of each hit.
          It is evidence a screen was performed, <b>not</b> a compliance determination.</p>
        <div class="snc-row" style="margin:0">
          <button class="snc-btn" id="scAudCsv">Export audit (CSV)</button>
          <button class="snc-btn" id="scAudJson">Export audit (JSON)</button>
          <button class="snc-btn" id="scAudClear">Clear log</button>
        </div>
        <div class="snc-list"><table>
          <thead><tr><th>Screen</th><th>Analyst</th><th class="snc-hide">List version</th><th class="snc-hide">Parameters</th><th>Outcome</th></tr></thead>
          <tbody>${rowsHtml}</tbody>
        </table></div>
      </div>`;
    host.querySelector("#scAudCsv").addEventListener("click", () => download("sanctions-audit-log.csv", auditToCsv(auditLoad())));
    host.querySelector("#scAudJson").addEventListener("click", () => download("sanctions-audit-log.json", JSON.stringify(auditLoad(), null, 2), "application/json"));
    host.querySelector("#scAudClear").addEventListener("click", async () => {
      const yes = await window.dnConfirm("Clear audit log", "Delete every screening record stored in this browser? This cannot be undone.", { danger: true, submitText: "Clear" });
      if (!yes) return;
      auditClear(); currentAudit = null; renderAudit(); toast("Audit log cleared");
    });
  }

  function toCsv(rows) {
    const q = (s) => `"${String(s == null ? "" : s).replace(/"/g, '""')}"`;
    const lines = ["name_screened,result,score,disposition,best_match,matched_name,program,type,dob,nationality,sdn_uid"];
    for (const r of rows) {
      const t = r.matches[0];
      const disp = (currentAudit && currentAudit.dispositions[r.name]) || (r.hit ? "pending" : "clear");
      lines.push([q(r.name), q(r.hit ? r.topBand : "clear"), r.hit ? r.topScore : 0, q(disp),
        q(t ? t.name : ""), q(t ? t.matchedName : ""), q(t ? t.program : ""), q(t ? t.type : ""),
        q(t ? t.dob : ""), q(t ? t.nationality : ""), q(t ? t.uid : "")].join(","));
    }
    return lines.join("\n") + "\n";
  }

  renderAudit();
}

// Friendly entity-type label for display. Blank OFAC type means an entity.
function entityLabel(t) {
  const s = String(t == null ? "" : t).trim().toLowerCase();
  if (!s) return "entity";
  return s;
}
