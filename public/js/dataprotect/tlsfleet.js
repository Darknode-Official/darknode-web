// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Certificate & TLS Fleet Monitor — paste a list of domains and watch their TLS
// certificates: issuer, validity window and days-to-expiry (live from certificate
// transparency logs via the Darknode proxy), plus whether HSTS is served. Keeps a
// persistent watchlist in this browser and flags certificates nearing expiry.
// Pure parsing/banding lives in tls-engine.js (tested).
//
//   renderTlsFleet(main) -> void

import { parseDomains, buildEntry, summarizeFleet, BANDS } from "/js/dataprotect/tls-engine.js?v=20261013i";
import { fetchCertRows } from "/js/dataprotect/ct-fetch.js?v=20261013i";
import { dnFetch } from "/js/net.js";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.showToast || (() => {}))(m); } catch (_) {} };

function lsKey() { let uid = "anon"; try { uid = window.__dnUid || "anon"; } catch (_) {} return "dn_tlswatch_" + uid; }
function load() { try { const r = JSON.parse(localStorage.getItem(lsKey()) || "{}"); return r && typeof r === "object" ? r : {}; } catch (_) { return {}; } }
function save(s) { try { localStorage.setItem(lsKey(), JSON.stringify(s)); } catch (_) { toast("Could not save the watchlist locally (storage blocked)."); } }

let injected = false;
function injectStyle() {
  if (injected) return; injected = true;
  const st = document.createElement("style"); st.id = "tlsf-css";
  st.textContent = `
  .tlsf{width:100%;font-size:14px;line-height:1.5}
  .tlsf .tlsf-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .tlsf h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .tlsf .tlsf-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .tlsf .tlsf-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:74ch}
  .tlsf .tlsf-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:16px}
  .tlsf textarea{width:100%;font:inherit;font-size:.84rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;padding:10px 12px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--bg,#fbfcfe);color:var(--tx,#1a2230);box-sizing:border-box;min-height:84px;resize:vertical}
  .tlsf .tlsf-row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:12px}
  .tlsf .tlsf-hint{color:var(--mut,#667085);font-size:.78rem;margin:8px 2px 0}
  .tlsf .tlsf-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .tlsf .tlsf-btn:hover{border-color:#9aa6bd}
  .tlsf .tlsf-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .tlsf .tlsf-btn.pri:hover{background:#1c42a6}
  .tlsf .tlsf-btn.sm{padding:5px 10px;font-size:.78rem}
  .tlsf .tlsf-btn:disabled{opacity:.55;cursor:default}
  .tlsf .tlsf-kpis{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
  .tlsf .tlsf-kpi{flex:1;min-width:110px;border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 12px;text-align:center}
  .tlsf .tlsf-kpi b{display:block;font-size:1.5rem;font-weight:800;line-height:1.1}
  .tlsf .tlsf-kpi span{font-size:.74rem;color:var(--mut,#667085)}
  .tlsf .tlsf-alert{background:var(--acc-soft,rgba(217,72,15,.08));border:1px solid var(--line,#e6e8ee);border-left:3px solid #d9480f;border-radius:8px;padding:10px 14px;color:var(--tx,#1a2230);font-size:.84rem;margin-bottom:14px;font-weight:600}
  .tlsf .tlsf-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:hidden}
  .tlsf table{width:100%;border-collapse:collapse;font-size:.84rem}
  .tlsf th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee)}
  .tlsf td{padding:9px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:middle;overflow-wrap:anywhere}
  .tlsf tr:last-child td{border-bottom:0}
  .tlsf .tlsf-dom{font-weight:600}
  .tlsf .tlsf-pill{display:inline-block;font-size:.68rem;font-weight:700;color:#fff;padding:2px 9px;border-radius:999px;white-space:nowrap}
  .tlsf .tlsf-days{font-weight:700}
  .tlsf .tlsf-x{cursor:pointer;color:var(--mut,#98a2b3);font-weight:700;border:0;background:none;font-size:1rem;padding:2px 6px}
  .tlsf .tlsf-x:hover{color:#b00020}
  .tlsf .tlsf-sp{display:inline-block;width:13px;height:13px;border:2px solid rgba(37,82,198,.3);border-top-color:#2552c6;border-radius:50%;animation:tlsfSpin .7s linear infinite;vertical-align:-2px}
  @keyframes tlsfSpin{to{transform:rotate(360deg)}}
  .tlsf .tlsf-empty{text-align:center;color:var(--mut,#667085);padding:24px 12px}
  .tlsf .tlsf-warn{color:var(--mut,#667085);font-size:.78rem;margin-top:12px}
  `;
  document.head.appendChild(st);
}

export function renderTlsFleet(main) {
  injectStyle();
  main.innerHTML = `
  <div class="tlsf">
    <div class="tlsf-hd"><h1>Certificate &amp; TLS Fleet Monitor</h1><span class="tlsf-tag">TLS</span></div>
    <p class="tlsf-sub">Track certificate expiry across every domain you own. Paste a list; each domain's newest certificate is read live from certificate transparency logs, and the watchlist is kept in this browser.</p>
    <div class="tlsf-card">
      <textarea id="tlsfIn" placeholder="One domain per line" spellcheck="false"></textarea>
      <div class="tlsf-row">
        <button class="tlsf-btn pri" id="tlsfAdd">Add &amp; check</button>
        <button class="tlsf-btn" id="tlsfCheck">Check all</button>
        <button class="tlsf-btn" id="tlsfCsv">Export CSV</button>
        <button class="tlsf-btn" id="tlsfClear">Clear watchlist</button>
        <span class="tlsf-hint" id="tlsfStat" style="margin:0"></span>
      </div>
      <p class="tlsf-hint">Reads certificate transparency (crt.sh) and the HSTS header through the Darknode proxy. It observes issued certificates and headers; it does not negotiate TLS, so cipher/protocol versions are not inspected here.</p>
    </div>
    <div id="tlsfOut"></div>
  </div>`;

  const $ = (s) => main.querySelector(s);
  const out = $("#tlsfOut"), statEl = $("#tlsfStat");
  let store = load(); // { domains:[], entries:{domain:entry}, updated }
  if (!Array.isArray(store.domains)) store.domains = [];
  if (!store.entries || typeof store.entries !== "object") store.entries = {};

  const render = () => {
    const entries = store.domains.map((d) => store.entries[d] || { domain: d, pending: true, band: BANDS.unknown });
    if (!store.domains.length) {
      out.innerHTML = `<div class="tlsf-card"><div class="tlsf-empty">No domains yet. Paste a list above and choose <b>Add &amp; check</b>.</div></div>`;
      return;
    }
    const sum = summarizeFleet(entries.filter((e) => !e.pending));
    const pending = entries.filter((e) => e.pending).length;
    const kpi = (n, l, c) => `<div class="tlsf-kpi"><b style="color:${c}">${n}</b><span>${l}</span></div>`;
    const alertBanner = sum.alerting
      ? `<div class="tlsf-alert">${sum.alerting} certificate${sum.alerting === 1 ? "" : "s"} need attention — ${sum.counts.expired} expired, ${sum.counts.urgent} within 14 days, ${sum.counts.soon} within 30 days.</div>`
      : "";
    // keep display order worst-first from summarize, then append pending/unknown
    const display = entries.slice().sort((a, b) => ((b.band || BANDS.unknown).rank - (a.band || BANDS.unknown).rank) || ((a.daysLeft ?? 1e9) - (b.daysLeft ?? 1e9)));
    const rows = display.map((e) => {
      const b = e.band || BANDS.unknown;
      const days = e.pending ? `<span class="tlsf-sp"></span>` : (e.daysLeft == null ? "—" : `<span class="tlsf-days" style="color:${b.c}">${e.daysLeft}</span>`);
      const exp = e.pending ? "checking…" : (e.notAfter ? esc(String(e.notAfter).slice(0, 10)) : "—");
      const pill = e.pending ? `<span class="tlsf-pill" style="background:#8a93a6">…</span>` : `<span class="tlsf-pill" style="background:${b.c}">${b.label}</span>`;
      const hsts = e.pending ? "" : (e.hsts === true ? "yes" : e.hsts === false ? "no" : "—");
      return `<tr>
        <td class="tlsf-dom">${esc(e.domain)}</td>
        <td>${pill}</td>
        <td>${days}</td>
        <td>${exp}</td>
        <td>${e.pending ? "" : esc(e.issuer || "—")}</td>
        <td>${hsts}</td>
        <td style="text-align:right"><button class="tlsf-x" data-rm="${esc(e.domain)}" title="Remove" aria-label="Remove ${esc(e.domain)}">&times;</button></td>
      </tr>`;
    }).join("");
    out.innerHTML = `
      ${alertBanner}
      <div class="tlsf-kpis">
        ${kpi(sum.total + pending, "domains", "var(--tx,#1a2230)")}
        ${kpi(sum.counts.expired, "expired", BANDS.expired.c)}
        ${kpi(sum.counts.urgent, "< 14 days", BANDS.urgent.c)}
        ${kpi(sum.counts.soon, "< 30 days", BANDS.soon.c)}
        ${kpi(sum.soonest == null ? "—" : sum.soonest, "soonest (days)", sum.soonest != null && sum.soonest < 30 ? BANDS.soon.c : "var(--tx,#1a2230)")}
      </div>
      <div class="tlsf-card" style="padding:0;overflow:hidden">
        <div class="tlsf-list"><table>
          <thead><tr><th>Domain</th><th>Status</th><th>Days left</th><th>Expires</th><th>Issuer</th><th>HSTS</th><th></th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>
      </div>`;
    out.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => {
      const d = b.getAttribute("data-rm");
      store.domains = store.domains.filter((x) => x !== d);
      delete store.entries[d]; save(store); render();
    }));
  };

  async function fetchCrt(domain) {
    return fetchCertRows(domain);
  }
  async function fetchHsts(domain) {
    try {
      const r = await dnFetch("https://" + domain, { timeout: 12000 });
      const h = r.headers || {};
      for (const k in h) if (k.toLowerCase() === "strict-transport-security") return true;
      return false;
    } catch (_) { return null; }
  }

  async function checkOne(domain) {
    store.entries[domain] = { domain, pending: true, band: BANDS.unknown };
    try {
      const [rows, hsts] = await Promise.all([fetchCrt(domain).catch(() => []), fetchHsts(domain)]);
      const e = buildEntry(domain, rows);
      e.hsts = hsts;
      store.entries[domain] = e;
    } catch (_) {
      store.entries[domain] = { domain, ok: false, band: BANDS.unknown, daysLeft: null, issuer: "", notAfter: "", hsts: null, checked: Date.now(), error: true };
    }
  }

  // Limited-concurrency fleet check with live re-render.
  async function checkMany(list, limit = 4) {
    if (!list.length) return;
    statEl.innerHTML = `<span class="tlsf-sp"></span> checking ${list.length} domain${list.length === 1 ? "" : "s"}…`;
    [$("#tlsfAdd"), $("#tlsfCheck")].forEach((b) => b.disabled = true);
    let i = 0, done = 0;
    const worker = async () => {
      while (i < list.length) {
        const d = list[i++];
        await checkOne(d); done++;
        store.updated = Date.now(); save(store); render();
        statEl.innerHTML = `<span class="tlsf-sp"></span> checked ${done}/${list.length}…`;
      }
    };
    await Promise.all(Array.from({ length: Math.min(limit, list.length) }, worker));
    [$("#tlsfAdd"), $("#tlsfCheck")].forEach((b) => b.disabled = false);
    statEl.textContent = `Checked ${list.length} · last updated ${new Date().toLocaleTimeString()}`;
  }

  $("#tlsfAdd").addEventListener("click", () => {
    const added = parseDomains($("#tlsfIn").value);
    if (!added.length) { toast("Enter one or more valid domains."); return; }
    const fresh = [];
    for (const d of added) if (!store.domains.includes(d)) { store.domains.push(d); fresh.push(d); }
    save(store); $("#tlsfIn").value = ""; render();
    checkMany(fresh.length ? fresh : added);
  });
  $("#tlsfCheck").addEventListener("click", () => checkMany(store.domains.slice()));
  $("#tlsfClear").addEventListener("click", async () => {
    if (!store.domains.length) return;
    const ok = await (window.dnConfirm ? window.dnConfirm("Clear the entire certificate watchlist?") : Promise.resolve(true));
    if (!ok) return;
    store = { domains: [], entries: {}, updated: Date.now() }; save(store); render();
  });
  $("#tlsfCsv").addEventListener("click", () => {
    if (!store.domains.length) { toast("Nothing to export yet."); return; }
    const head = "domain,status,days_left,expires,issuer,hsts\n";
    const body = store.domains.map((d) => {
      const e = store.entries[d] || {};
      return [d, (e.band && e.band.level) || "unknown", e.daysLeft == null ? "" : e.daysLeft, e.notAfter || "", (e.issuer || "").replace(/,/g, " "), e.hsts === true ? "yes" : e.hsts === false ? "no" : ""].join(",");
    }).join("\n");
    try {
      const blob = new Blob([head + body], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = "tls-fleet.csv";
      document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
    } catch (_) { toast("Download blocked by the browser"); }
  });

  render();
  // auto-refresh entries older than 6 hours on open
  const stale = store.domains.filter((d) => { const e = store.entries[d]; return !e || !e.checked || (Date.now() - e.checked > 6 * 3600 * 1000); });
  if (stale.length) checkMany(stale);
}

export default renderTlsFleet;
