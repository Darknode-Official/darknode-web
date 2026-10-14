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

import { buildIndex, screenName, screenBatch, selfTest } from "/js/finsec/sanctions-engine.js?v=20261013m";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.showToast || (() => {}))(m); } catch (_) {} };

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
  .sanc{max-width:1100px;margin:0 auto;font-size:14px;line-height:1.5}
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
  @media(max-width:640px){.sanc th.snc-hide,.sanc td.snc-hide{display:none}}
  `;
  document.head.appendChild(st);
}

function download(name, text) {
  const b = new Blob([text], { type: "text/csv" });
  const u = URL.createObjectURL(b); const a = document.createElement("a");
  a.href = u; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(u), 1000);
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
      <textarea id="scIn" placeholder="Acme Shipping LLC&#10;Vladimir Putin&#10;Bank Melli Iran"></textarea>
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
  </div>`;

  const $ = (id) => main.querySelector("#" + id);
  const inTA = $("scIn");

  $("scFile").addEventListener("change", (e) => {
    const f = e.target.files && e.target.files[0]; if (!f) return;
    const fr = new FileReader();
    fr.onload = () => { inTA.value = String(fr.result || ""); $("scFileName").textContent = f.name; };
    fr.onerror = () => toast("Could not read file");
    fr.readAsText(f);
  });
  $("scSample").addEventListener("click", () => {
    inTA.value = ["Acme Shipping LLC", "Vladimir Putin", "Bank Melli Iran", "Global Widgets Inc", "Nicolas Maduro", "Jane Doe"].join("\n");
    $("scFileName").textContent = "";
  });
  $("scClear").addEventListener("click", () => { inTA.value = ""; $("scFileName").textContent = ""; $("scOut").innerHTML = ""; });
  $("scTest").addEventListener("click", () => {
    const { pass, results } = selfTest();
    $("scTestOut").innerHTML = pass
      ? `<span class="ok">Self-test passed</span> — ${results.length}/${results.length} checks`
      : `<span class="bad">Self-test failed</span> — ${results.filter((r) => !r.pass).map((r) => r.name).join(", ")}`;
  });

  $("scRun").addEventListener("click", run);
  inTA.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(); });

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
    const rows = screenBatch(names, index, { minScore: 80, limit: 5 });
    btn.disabled = false;
    renderResults(out, rows, names.length);
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
      <div class="snc-row" style="margin:0 0 4px">
        <button class="snc-btn" id="scExp">Export results (CSV)</button>
      </div>
      <div class="snc-list"><table>
        <thead><tr><th>Name screened</th><th>Result</th><th>Best match</th><th class="snc-hide">Program</th><th>Score</th></tr></thead>
        <tbody>${rows.map(rowHtml).join("")}</tbody>
      </table></div>`;
    out.querySelector("#scExp").addEventListener("click", () => download("sanctions-screening.csv", toCsv(rows)));
  }

  function rowHtml(r) {
    const b = BAND[r.hit ? r.topBand : "clear"];
    const top = r.matches[0];
    const extra = r.matches.length > 1 ? `<div class="snc-prog">+${r.matches.length - 1} more match${r.matches.length - 1 === 1 ? "" : "es"}</div>` : "";
    return `<tr class="${r.hit ? "snc-hit" : ""}">
      <td><b>${esc(r.name)}</b></td>
      <td><span class="snc-pill" style="background:${b.c}">${b.label}</span></td>
      <td>${top ? `<div class="snc-match"><b>${esc(top.name)}</b></div>${top.matchedName !== top.name ? `<div class="snc-prog">matched alias: ${esc(top.matchedName)}</div>` : ""}${extra}` : `<span class="snc-note">—</span>`}</td>
      <td class="snc-hide">${top ? `<span class="snc-prog">${esc(top.program || "—")}${top.type ? " · " + esc(top.type) : ""}</span>` : ""}</td>
      <td class="snc-score" style="color:${b.c}">${r.hit ? r.topScore : ""}</td>
    </tr>`;
  }

  function toCsv(rows) {
    const q = (s) => `"${String(s == null ? "" : s).replace(/"/g, '""')}"`;
    const lines = ["name_screened,result,score,best_match,matched_name,program,type,sdn_uid"];
    for (const r of rows) {
      const t = r.matches[0];
      lines.push([q(r.name), q(r.hit ? r.topBand : "clear"), r.hit ? r.topScore : 0,
        q(t ? t.name : ""), q(t ? t.matchedName : ""), q(t ? t.program : ""), q(t ? t.type : ""), q(t ? t.uid : "")].join(","));
    }
    return lines.join("\n") + "\n";
  }
}
