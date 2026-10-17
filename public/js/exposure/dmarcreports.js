// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// DMARC Reports (dmarcreports): Deck tool UI. Drop DMARC aggregate (RUA) reports
// as .xml / .xml.gz / .zip (hundreds at once, nested archives unpacked locally),
// parsedmarc CSV or ARF forensic reports; the engine parses and analyzes them in
// a Worker. Runs entirely in the browser. The only network use is the opt-in
// "Look up sources" button: DNS-over-HTTPS to dns.google and cloudflare-dns.com
// for PTR names and the domain's current DMARC / SPF / DKIM records.
// No native dialogs; toasts only.
//
//   renderDmarcReports(main) -> void

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { unpackAll } from "../ingest/unpack.js";
import { decodeText } from "../ingest/parse.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp, zipFiles } from "../core/export.js";
import {
  DEFAULTS, TOOL_ID, COLUMNS, ESP_TABLE, FORWARDER_TABLE, PSL_SUBSET, DETECTIONS, detectFile, ptrName,
  findingsToCsv, sourcesToCsv, fixListText, planText, summaryText, exampleDataset, csvCell,
} from "./dmarcreports-engine.js?v=20261016u";

const ENGINE = engineUrl("./dmarcreports-engine.js?v=20261016u", import.meta);
const P = "dmr";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const CONF_RANK = { confirmed: 3, likely: 2, review: 1 };
const KEY_LABEL = {
  source_ip: "Source IP", count: "Message count", header_from: "Header From domain", envelope_from: "Envelope From", envelope_to: "Envelope To", disposition: "Disposition",
  dkim_eval: "DKIM aligned (reporter)", spf_eval: "SPF aligned (reporter)", dkim_domains: "DKIM domains", dkim_selectors: "DKIM selectors", dkim_results: "DKIM results",
  spf_domains: "SPF domains", spf_scopes: "SPF scopes", spf_results: "SPF results", reasons: "Override reasons", org_name: "Reporter org", report_id: "Report ID",
  begin: "Begin date", end: "End date", policy_domain: "Policy domain", p: "Policy p", sp: "Policy sp", pct: "Policy pct", adkim: "adkim", aspf: "aspf",
};
const PTR_CAP = 250;

// Session cache for DoH answers (cleared on reload).
const DNS_CACHE = new Map();

const CSS = `
  .dmr-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box}
  .dmr-root *{box-sizing:border-box}
  .dmr-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .dmr-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .dmr-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .dmr-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:120ch;overflow-wrap:anywhere}
  .dmr-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .dmr-card h2{font-size:.95rem;margin:0 0 10px}
  .dmr-card h3{font-size:.88rem;margin:12px 0 6px;overflow-wrap:anywhere}
  .dmr-note{font-size:.78rem;color:var(--mut,#667085);margin:6px 0 0;overflow-wrap:anywhere}
  .dmr-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .dmr-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer;max-width:100%;white-space:normal;text-align:left}
  .dmr-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .dmr-btn.sm{padding:4px 9px;font-size:.76rem}
  .dmr-btn:disabled{opacity:.5;cursor:default}
  .dmr-fmts{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
  .dmr-fmt{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:7px 12px;font-size:.82rem;min-width:0;max-width:100%}
  .dmr-fmt b{overflow-wrap:anywhere}
  .dmr-conf{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:1px 7px;border-radius:999px;border:1px solid var(--line,#d7dbe3);color:var(--mut,#667085)}
  .dmr-conf.high{color:#1b7f4d;border-color:#1b7f4d}.dmr-conf.medium{color:#8a6d00;border-color:#8a6d00}.dmr-conf.low{color:#b00020;border-color:#b00020}
  .dmr-map{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:12px 14px;margin-top:10px;min-width:0}
  .dmr-map h3{margin-top:0}
  .dmr-map select{font:inherit;font-size:.78rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:4px 6px;background:var(--card,#fff);color:var(--tx,#1a2230);width:100%;max-width:100%}
  .dmr-ctl{display:flex;flex-wrap:wrap;gap:14px 20px;align-items:flex-start;margin-top:8px}
  .dmr-field{display:flex;flex-direction:column;gap:4px;min-width:0;flex:1 1 170px}
  .dmr-field.wide{flex:1 1 100%}
  .dmr-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .dmr-field input,.dmr-field textarea{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:100%;max-width:100%}
  .dmr-field textarea{min-height:64px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}
  .dmr-field small{font-size:.74rem;color:var(--mut,#667085);line-height:1.4}
  .dmr-det summary{cursor:pointer;font-weight:600;font-size:.86rem;margin-top:10px}
  .dmr-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .dmr-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;flex:1 1 140px;min-width:0}
  .dmr-kpi b{display:block;font-size:1.25rem;overflow-wrap:anywhere}
  .dmr-kpi span{display:block;font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em;overflow-wrap:anywhere}
  .dmr-tab{max-width:100%;white-space:normal}
  .dmr-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .dmr-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .dmr-plabel{font-size:.74rem;color:var(--mut,#667085);margin-top:4px;display:none}
  .dmr-tabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;border-bottom:1px solid var(--line,#e6e8ee);padding-bottom:8px}
  .dmr-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid transparent;background:none;color:var(--mut,#667085);padding:6px 12px;border-radius:8px;cursor:pointer}
  .dmr-tab.on{color:var(--tx,#1a2230);border-color:var(--line,#d7dbe3);background:var(--bg,#f7f8fb)}
  .dmr-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-width:100%}
  .dmr-list table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:640px}
  .dmr-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .dmr-list th.on{color:var(--tx,#1a2230)}
  .dmr-list th.on::after{content:" \\2193";font-size:.7rem}
  .dmr-list th.on.asc::after{content:" \\2191"}
  .dmr-list td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .dmr-list tr[data-i]{cursor:pointer}
  .dmr-list tr[data-i]:hover,.dmr-list tr.sel{background:var(--bg,#f7f8fb)}
  .dmr-nw{white-space:nowrap}
  .dmr-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .dmr-pill.critical{background:#7a0012}.dmr-pill.high{background:#b00020}.dmr-pill.medium{background:#b58100}.dmr-pill.low{background:#2552c6}.dmr-pill.info{background:#667085}
  .dmr-kind{display:inline-block;font-size:.7rem;font-weight:700;padding:1px 7px;border-radius:6px;border:1px solid var(--line,#d7dbe3);white-space:nowrap}
  .dmr-kind.esp{color:#2552c6;border-color:#2552c6}.dmr-kind.unknown{color:#b00020;border-color:#b00020}.dmr-kind.forwarder{color:#8a6d00;border-color:#8a6d00}.dmr-kind.authenticated{color:#1b7f4d;border-color:#1b7f4d}
  .dmr-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085)}
  .dmr-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .dmr-drawer{margin-top:12px;display:none;border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:14px 16px;background:var(--bg,#f7f8fb);min-width:0}
  .dmr-drawer h3{margin:0;font-size:1rem;overflow-wrap:anywhere}
  .dmr-drawer p{margin:6px 0;overflow-wrap:anywhere}
  .dmr-drawer .dmr-list{background:var(--card,#fff);margin-top:10px}
  .dmr-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:10px;padding-left:18px}
  .dmr-skip li{margin:2px 0;overflow-wrap:anywhere}
  .dmr-chart{width:100%;height:auto;display:block}
  .dmr-legend{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:.78rem;color:var(--mut,#667085);margin:6px 0 10px}
  .dmr-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
  .dmr-stages{list-style:none;margin:8px 0;padding:0;display:flex;flex-wrap:wrap;gap:6px}
  .dmr-stages li{font-size:.76rem;border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:4px 9px;color:var(--mut,#667085)}
  .dmr-stages li.done{color:#1b7f4d;border-color:#1b7f4d}.dmr-stages li.current{color:#fff;background:#2552c6;border-color:#2552c6}
  .dmr-stages li.ready{color:#1b7f4d;border-color:#1b7f4d;border-style:dashed}.dmr-stages li.blocked{color:#b00020;border-color:#b00020;border-style:dashed}
  .dmr-plan{border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:12px 14px;margin-bottom:12px;min-width:0}
  .dmr-plan ul{margin:6px 0;padding-left:18px}
  .dmr-plan li{overflow-wrap:anywhere}
  .dmr-kv{display:grid;grid-template-columns:minmax(110px,180px) 1fr;gap:4px 12px;font-size:.82rem;margin-top:8px}
  .dmr-kv dt{color:var(--mut,#667085)}
  .dmr-kv dd{margin:0;overflow-wrap:anywhere}
  @media (max-width:560px){.dmr-field{flex:1 1 100%}.dmr-card{padding:14px}.dmr-kv{grid-template-columns:1fr}}
`;

const kpi = (v, l) => '<div class="' + P + '-kpi"><b>' + esc(v == null || v === "" ? "-" : v) + "</b><span>" + esc(l) + "</span></div>";
const pill = (s) => (s ? '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>" : "");
const kindTag = (k) => '<span class="' + P + "-kind " + esc(k) + '">' + esc({ esp: "service", unknown: "unknown", forwarder: "forwarding", authenticated: "authenticated" }[k] || k) + "</span>";
const chips = (cs) => (cs || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("");
const pctTxt = (v) => (v == null ? "" : v + "%");

const sortRows = (rows, key, dir, rank) => rows.slice().sort((a, b) => {
  const x = rank ? (rank[a[key]] ?? -1) : a[key], y = rank ? (rank[b[key]] ?? -1) : b[key];
  const r = typeof x === "number" && typeof y === "number" ? x - y : cmp(String(x == null ? "" : x).toLowerCase(), String(y == null ? "" : y).toLowerCase());
  return dir === "asc" ? r : -r;
});

/** Sortable table: cols = [{key, label, render?, rank?}]. */
function table(cols, rows, sort, onSort, rowKey, limit) {
  const col = cols.find((c) => c.key === sort.key) || {};
  const sorted = sortRows(rows, sort.key, sort.dir, col.rank);
  const shown = limit ? sorted.slice(0, limit) : sorted;
  const el = document.createElement("div");
  el.className = P + "-list";
  el.innerHTML = "<table><thead><tr>" + cols.map((c) => '<th data-k="' + esc(c.key) + '" class="' + (sort.key === c.key ? "on " + sort.dir : "") + '">' + esc(c.label) + "</th>").join("") + "</tr></thead><tbody>" +
    shown.map((r) => '<tr data-i="' + esc(rowKey(r)) + '">' + cols.map((c) => "<td>" + (c.render ? c.render(r) : esc(r[c.key] == null ? "" : r[c.key])) + "</td>").join("") + "</tr>").join("") + "</tbody></table>";
  el.querySelectorAll("th").forEach((th) => th.addEventListener("click", () => { const k = th.dataset.k; onSort({ key: k, dir: sort.key === k && sort.dir === "desc" ? "asc" : "desc" }); }));
  return el;
}

function evidenceTable(rows) {
  if (!rows || !rows.length) return '<p class="' + P + '-note">No evidence rows.</p>';
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => '<td class="' + (k === "source_ip" || k === "date" || k === "first" || k === "last" ? P + "-nw" : "") + '">' + esc(r[k] == null ? "" : r[k]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}

function dailySvg(rows) {
  const data = rows.filter((r) => r.date !== "(no date)");
  if (!data.length) return '<p class="' + P + '-note">No dated reports.</p>';
  const W = 900, H = 260, L = 56, B = 34, T = 14, R = 10;
  const max = Math.max(1, ...data.map((r) => r.pass + r.fail));
  const gw = (W - L - R) / data.length, bw = Math.max(3, Math.min(40, gw - 4));
  const y = (v) => T + (H - T - B) * (1 - v / max);
  let s = '<svg class="' + P + '-chart" viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Messages per day passing and failing DMARC">';
  for (const t of [0, Math.round(max / 2), max]) s += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + y(t) + '" y2="' + y(t) + '" stroke="#e6e8ee"/><text x="' + (L - 6) + '" y="' + (y(t) + 4) + '" text-anchor="end" font-size="11" fill="#667085">' + t + "</text>";
  const every = Math.ceil(data.length / 16);
  data.forEach((r, i) => {
    const x = L + i * gw + (gw - bw) / 2;
    const tip = esc(r.date + ": " + r.pass + " pass, " + r.fail + " fail (" + r.passPct + "% pass)");
    s += '<rect x="' + x.toFixed(1) + '" y="' + y(r.pass).toFixed(1) + '" width="' + bw.toFixed(1) + '" height="' + Math.max(0, H - B - y(r.pass)).toFixed(1) + '" fill="#3a7d5c"><title>' + tip + "</title></rect>";
    if (r.fail > 0) s += '<rect x="' + x.toFixed(1) + '" y="' + y(r.pass + r.fail).toFixed(1) + '" width="' + bw.toFixed(1) + '" height="' + Math.max(0, y(r.pass) - y(r.pass + r.fail)).toFixed(1) + '" fill="#b00020"><title>' + tip + "</title></rect>";
    if (i % every === 0) s += '<text x="' + (x + bw / 2).toFixed(1) + '" y="' + (H - 12) + '" text-anchor="middle" font-size="11" fill="#1a2230">' + esc(r.date.slice(5)) + "</text>";
  });
  s += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + (H - B) + '" y2="' + (H - B) + '" stroke="#98a2b3"/></svg>';
  return '<div class="' + P + '-legend"><span><i style="background:#3a7d5c"></i>DMARC pass</span><span><i style="background:#b00020"></i>DMARC fail</span><span>Each report is counted on the day its date range begins (UTC).</span></div>' + s;
}

// ---- DNS over HTTPS (opt-in live lookups) ----
const DOH = [
  (n, t) => "https://dns.google/resolve?name=" + encodeURIComponent(n) + "&type=" + t,
  (n, t) => "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(n) + "&type=" + t,
];
function doh(name, type) {
  const key = type + ":" + name.toLowerCase();
  if (DNS_CACHE.has(key)) return DNS_CACHE.get(key);
  const want = type === "TXT" ? 16 : 12;
  const p = (async () => {
    let lastErr = "";
    for (const u of DOH) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 8000);
      try {
        const res = await fetch(u(name, type), { headers: { Accept: "application/dns-json" }, signal: ctrl.signal });
        if (!res.ok) { lastErr = "HTTP " + res.status; continue; }
        const j = await res.json();
        if (j.Status === 3) return { answers: [] }; // NXDOMAIN
        if (j.Status !== 0) { lastErr = "DNS status " + j.Status; continue; }
        const ans = (j.Answer || []).filter((a) => a.type === want).map((a) => String(a.data || ""));
        return { answers: type === "TXT" ? ans.map((d) => d.replace(/^"|"$/g, "").replace(/"\s*"/g, "")) : ans.map((d) => d.replace(/\.$/, "")) };
      } catch (e) { lastErr = e && e.name === "AbortError" ? "timeout" : String((e && e.message) || e); }
      finally { clearTimeout(timer); }
    }
    DNS_CACHE.delete(key); // do not cache failures
    return { error: lastErr || "lookup failed" };
  })();
  DNS_CACHE.set(key, p);
  return p;
}
async function pool(items, n, fn, onStep) {
  let i = 0, done = 0;
  const worker = async () => { while (i < items.length) { const k = i++; await fn(items[k]); done++; if (onStep) onStep(done, items.length); } };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
}

async function gzipBytes(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Mount the tool into main. */
export function renderDmarcReports(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  const num = (id, label, v, help) => '<div class="' + P + '-field"><label for="' + P + "-o-" + id + '">' + label + '</label><input id="' + P + "-o-" + id + '" type="number" min="0" step="any" value="' + esc(v) + '"><small>' + help + "</small></div>";
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>DMARC Reports</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Turns DMARC aggregate reports into who sends mail as your domains, which legitimate services are not aligned, how much spoofing there is, and a staged path to p=reject. Alignment is recomputed from each report\'s auth_results. Runs entirely in your browser. Nothing is uploaded. Only the optional Look up sources button makes requests: DNS-over-HTTPS to dns.google and cloudflare-dns.com for PTR names and your current DMARC, SPF and DKIM records.</p>',
    '<div class="', P, '-card"><h2>1. Reports</h2><div id="', P, '-drop"></div>',
    '<p class="', P, '-note">Aggregate (RUA) reports as .xml, .xml.gz or .zip, as Google, Microsoft, Yahoo and others send them, in the RFC 7489 or DMARCbis schema; drop hundreds at once or a folder, archives inside archives are unpacked. Also reads the parsedmarc aggregate CSV and ARF forensic (RUF) reports. Duplicate reports (same reporter and report_id) are counted once.</p>',
    '<div class="', P, '-fmts" id="', P, '-fmts"></div>',
    '<div id="', P, '-map"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button><button class="', P, '-btn" id="', P, '-clear" disabled>Clear files</button><span class="', P, '-note" id="', P, '-count"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-plabel" id="', P, '-plabel"></div>',
    '<div id="', P, '-filesum"></div></div>',
    '<div class="', P, '-card"><h2>2. Thresholds</h2><div class="', P, '-ctl">',
    num("noneDays", "Days at p=none before advice", DEFAULTS.noneDays, "Report p=none once the reports span more than this many days."),
    num("spoofMin", "Spoofing volume for high", DEFAULTS.spoofMin, "Failing messages from unknown sources above this are high severity."),
    num("readyPassRate", "Pass rate to advance (%)", DEFAULTS.readyPassRate, "Legitimate-looking mail must pass DMARC at this rate before the next stage."),
    num("senderMinMessages", "Failing messages per sender", DEFAULTS.senderMinMessages, "A known service is reported, and blocks the plan, from this many failing messages."),
    num("minObserveDays", "Days to observe each stage", DEFAULTS.minObserveDays, "Reports needed at the current policy before advancing."),
    num("pctStuckDays", "Days at pct below 100", DEFAULTS.pctStuckDays, "Report partial enforcement held longer than this."),
    '<div class="', P, '-field wide"><label for="', P, '-o-known">Your sending domains (optional)</label><textarea id="', P, '-o-known" placeholder="mail.yourdomain" spellcheck="false"></textarea><small>One From domain per line. Spoofed subdomains not in this list are called out by name.</small></div>',
    "</div>",
    '<details class="', P, '-det"><summary>Sending-service table (', ESP_TABLE.length, ' services, read-only)</summary><p class="', P, '-note">Sources are classified only from report data: DKIM d= domains, SPF / envelope (return-path) domains and well-known DKIM selectors. IP ownership is never guessed. A match on a selector alone is shown with review confidence.</p><div class="', P, '-list" style="margin-top:8px"><table><thead><tr><th>Service</th><th>DKIM d= domains</th><th>Return-path domains</th><th>Selectors</th><th>SPF include</th></tr></thead><tbody>',
    ESP_TABLE.map((e) => "<tr><td>" + esc(e.name) + "</td><td>" + esc(e.dkim.join(", ")) + "</td><td>" + esc(e.spf.join(", ")) + "</td><td>" + esc([...e.selectors, e.id === "hubspot" ? "hs1-*, hs2-*" : "", e.selectorPattern ? "<timestamp>pm" : ""].filter(Boolean).join(", ")) + "</td><td>" + esc(e.include ? "include:" + e.include : "(see service docs)") + "</td></tr>").join(""),
    FORWARDER_TABLE.map((f) => "<tr><td>" + esc(f.name) + "</td><td colspan=\"2\">" + esc(f.domains.join(", ")) + "</td><td></td><td>forwarding, not a sender</td></tr>").join(""),
    "</tbody></table></div></details>",
    '<p class="', P, '-note">Organizational domains for relaxed alignment use an embedded subset of the Public Suffix List (', PSL_SUBSET.length, ' common multi-label suffixes such as co.uk, com.au, co.jp). It is a subset: a domain under an unlisted suffix may be grouped one label too high.</p></div>',
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-card" id="', P, '-results" style="display:none">',
    '<div class="', P, '-row" style="margin:0 0 12px"><button class="', P, '-btn" id="', P, '-lookup">Look up sources</button><span class="', P, '-note" id="', P, '-livenote">Optional: PTR names for up to ', PTR_CAP, ' source IPs and the current DMARC, SPF (with includes) and DKIM records, via dns.google and cloudflare-dns.com. Four queries at a time; answers are cached for this session.</span></div>',
    '<div class="', P, '-tabs" id="', P, '-tabs"></div><div id="', P, '-pane"></div><div class="', P, '-drawer" id="', P, '-drawer"></div><ul class="', P, '-skip" id="', P, '-skipped"></ul></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let files = [], result = null, isExample = false, running = false, tab = "findings", selected = "", live = null;
  const sorts = {
    findings: { key: "severity", dir: "desc" }, sources: { key: "messages", dir: "desc" }, senders: { key: "messages", dir: "desc" },
    domains: { key: "messages", dir: "desc" }, daily: { key: "date", dir: "asc" }, forensic: { key: "file", dir: "asc" },
  };

  // ---- files ----
  const datasetName = () => (isExample ? "synthetic example" : files.length === 1 ? files[0].name : files.length + " DMARC report files");
  function addFile(name, text) {
    const det = detectFile({ name, text });
    const f = { name, text, det, columns: {} };
    const i = files.findIndex((x) => x.name === name);
    if (i >= 0) files[i] = f; else files.push(f);
  }
  function redetect(f) {
    const det = detectFile({ name: f.name, text: f.text });
    for (const [k, v] of Object.entries(f.columns)) { if (v) det.map[k] = v; else delete det.map[k]; }
    det.missing = ["source_ip", "count", "header_from"].filter((k) => !det.map[k]);
    f.det = det;
  }

  function renderFiles() {
    const groups = new Map();
    for (const f of files) {
      const k = f.det.label + "|" + f.det.confidenceLabel;
      const g = groups.get(k) || { label: f.det.label, conf: f.det.confidenceLabel, n: 0, names: [] };
      g.n++; if (g.names.length < 3) g.names.push(f.name);
      groups.set(k, g);
    }
    $("fmts").innerHTML = [...groups.values()].sort((a, b) => b.n - a.n || cmp(a.label, b.label)).map((g) =>
      '<div class="' + P + '-fmt"><b>' + g.n + " file" + (g.n === 1 ? "" : "s") + "</b><span>" + esc(g.label) + '</span><span class="' + P + "-conf " + esc(g.conf) + '">' + esc(g.conf) + " confidence</span>" +
      (g.conf !== "high" ? '<span class="' + P + '-note">' + esc(g.names.join(", ")) + (g.n > 3 ? " and " + (g.n - 3) + " more" : "") + "</span>" : "") + "</div>").join("");
    const usable = files.filter((f) => f.det.format !== "unknown" && f.det.format !== "empty");
    $("count").textContent = files.length ? files.length + " file" + (files.length === 1 ? "" : "s") + (isExample ? " (synthetic example)" : "") + (usable.length ? "" : ". None look like DMARC reports.") : "";
    $("run").disabled = !usable.length || running;
    $("clear").disabled = !files.length;
    renderMapping();
  }

  function renderMapping() {
    const need = files.map((f, i) => ({ f, i })).filter(({ f }) => f.det.format === "csv");
    const box = $("map");
    if (!need.length) { box.innerHTML = ""; return; }
    box.innerHTML = need.slice(0, 10).map(({ f, i }) => '<div class="' + P + '-map"><h3>Column mapping: ' + esc(f.name) + '</h3><p class="' + P + '-note">' + esc(f.det.label) + ", " + esc(f.det.confidenceLabel) + " confidence." +
      (f.det.missing.length ? " Required and not found: " + esc(f.det.missing.map((k) => KEY_LABEL[k] || k).join(", ")) + "." : "") + " Fields left as (not present) disable the checks that need them.</p><div class=\"" + P + '-ctl">' +
      Object.keys(COLUMNS).map((k) => '<div class="' + P + '-field"><label>' + esc(KEY_LABEL[k] || k) + '</label><select data-f="' + i + '" data-k="' + esc(k) + '"><option value="">(not present)</option>' +
        f.det.headers.filter((h) => h !== "").map((h) => '<option value="' + esc(h) + '"' + (f.det.map[k] === h ? " selected" : "") + ">" + esc(h) + "</option>").join("") + "</select></div>").join("") + "</div></div>").join("") +
      (need.length > 10 ? '<p class="' + P + '-note">' + (need.length - 10) + " more CSV files use the automatic mapping.</p>" : "");
    box.querySelectorAll("select[data-k]").forEach((sel) => sel.addEventListener("change", () => {
      const f = files[Number(sel.dataset.f)];
      f.columns[sel.dataset.k] = sel.value;
      redetect(f);
      const scroll = window.scrollY; renderFiles(); window.scrollTo(0, scroll);
    }));
  }

  mountDropzone($("drop"), {
    maxBytes: 256 * 1024 * 1024, maxFiles: 5000, unpack: true, multiple: true,
    label: "Drop DMARC report files, .zip or .gz archives, or a folder here, paste, or browse",
    onFiles: async (list, { skipped }) => {
      if (isExample) { files = []; isExample = false; resetResults(); }
      for (const f of list) addFile(f.name, await f.text());
      if (list.length) toast("Added " + list.length + " file" + (list.length === 1 ? "" : "s") + (skipped && skipped.length ? ", " + skipped.length + " skipped" : ""), "success");
      renderFiles();
    },
  });
  $("clear").addEventListener("click", () => { files = []; isExample = false; resetResults(); renderFiles(); });

  // Synthetic example: packaged as a real .zip (with .xml.gz members) and opened through the same unpack path.
  $("example").addEventListener("click", async () => {
    try {
      const ex = exampleDataset();
      const enc = new TextEncoder();
      const members = [];
      for (const f of ex.files) {
        if (f.pack === "gz") members.push({ name: f.name + ".gz", bytes: await gzipBytes(enc.encode(f.text)), date: new Date(Date.UTC(2026, 9, 3)) });
        else members.push({ name: f.name, text: f.text, date: new Date(Date.UTC(2026, 9, 3)) });
      }
      const zip = await zipFiles(members);
      const { entries, skipped } = await unpackAll(zip, { name: "larkspur-dmarc-example.zip", maxEntries: 5000 });
      files = []; isExample = true; live = null; resetResults();
      for (const e of entries) addFile(e.name, decodeText(e.bytes));
      renderFiles();
      toast("Synthetic example: " + entries.length + " files unpacked from a .zip (" + members.filter((m) => m.bytes).length + " were .xml.gz)" + (skipped.length ? ", " + skipped.length + " skipped" : "") + ". Click Analyze.", "info");
    } catch (e) { toast("Could not build the example: " + ((e && e.message) || e), "error"); }
  });

  // ---- options ----
  const opts = () => {
    const v = (id) => { const s = $("o-" + id).value.trim(); const n = Number(s); return s !== "" && Number.isFinite(n) && n >= 0 ? n : DEFAULTS[id]; };
    const o = {};
    for (const k of ["noneDays", "spoofMin", "readyPassRate", "senderMinMessages", "minObserveDays", "pctStuckDays"]) o[k] = v(k);
    o.knownDomains = $("o-known").value;
    if (live && !isExample) o.live = live;
    return o;
  };

  function resetResults() {
    result = null; live = null; selected = "";
    $("results").style.display = "none"; $("kpis").innerHTML = ""; $("exports").innerHTML = ""; $("filesum").innerHTML = ""; $("drawer").style.display = "none";
  }

  async function run(label) {
    if (!files.length || running) return;
    running = true;
    const prog = $("prog"), bar = prog.firstElementChild, pl = $("plabel");
    prog.style.display = "block"; pl.style.display = "block"; bar.style.width = "0%"; pl.textContent = label || "starting"; $("run").disabled = true;
    try {
      result = await runInWorker(ENGINE, "analyze", [{ files: files.map((f) => ({ name: f.name, text: f.text, columns: f.columns })) }, opts()], {
        timeoutMs: 600000,
        onProgress: (i, n, l) => { bar.style.width = (n ? Math.min(100, Math.round((i / n) * 100)) : 50) + "%"; pl.textContent = (l || "working") + (n > 1 ? " " + i + " of " + n : ""); },
      });
      selected = ""; $("drawer").style.display = "none";
      render();
      toast(result.summary.reports + " reports, " + result.summary.messages + " messages, " + result.findings.length + " findings", "success");
    } catch (e) {
      toast("Analysis failed: " + ((e && e.message) || e), "error");
    } finally {
      running = false;
      prog.style.display = "none"; pl.style.display = "none"; renderFiles();
    }
  }
  $("run").addEventListener("click", () => run());

  // ---- live lookups ----
  $("lookup").addEventListener("click", async () => {
    if (!result || running) return;
    if (isExample) { toast("The synthetic example uses documentation addresses and test domains; live lookups are off for it.", "info"); return; }
    const btn = $("lookup"); btn.disabled = true;
    const note = $("livenote");
    try {
      const checkedAt = new Date().toISOString();
      const L = { checkedAt, ptr: {}, domains: {} };
      const ips = result.tables.sources.slice().sort((a, b) => b.messages - a.messages).map((s) => s.ip).filter((ip, i, a) => a.indexOf(ip) === i && ptrName(ip)).slice(0, PTR_CAP);
      const pds = [...new Set(result.tables.plan.map((p) => p.domain).filter(Boolean))].sort();
      for (const d of pds) L.domains[d] = { checkedAt, dkim: {} };
      const step = (label) => (done, n) => { note.textContent = label + " " + done + " of " + n; };
      await pool(ips, 4, async (ip) => { const r = await doh(ptrName(ip), "PTR"); L.ptr[ip] = r.error ? { error: r.error } : r.answers; }, step("PTR lookups"));
      await pool(pds, 4, async (d) => {
        const dm = await doh("_dmarc." + d, "TXT");
        L.domains[d].dmarc = dm.error ? { error: dm.error } : { txt: dm.answers };
        const root = await doh(d, "TXT");
        if (root.error) { L.domains[d].spf = { error: root.error }; return; }
        const includes = {}, queue = [], seen = new Set([d]);
        const enqueue = (txts) => { const rec = (txts || []).find((t) => /^v=spf1\b/i.test(t)); if (!rec) return; for (const tok of rec.split(/\s+/)) { const m = tok.replace(/^[-~?+]/, "").match(/^(?:include:|redirect=)(.+)$/i); if (m && !seen.has(m[1].toLowerCase())) { seen.add(m[1].toLowerCase()); queue.push(m[1].toLowerCase()); } } };
        enqueue(root.answers);
        let q = 0;
        while (queue.length && q < 40) { const name = queue.shift(); q++; const r = await doh(name, "TXT"); if (!r.error) { includes[name] = r.answers; enqueue(r.answers); } }
        L.domains[d].spf = { txt: root.answers, includes };
      }, step("Domain lookups"));
      const sels = (result.tables.selectorsSeen || []).filter((s) => L.domains[s.domain]);
      await pool(sels, 4, async (s) => { const r = await doh(s.selector + "._domainkey." + s.domain, "TXT"); L.domains[s.domain].dkim[s.selector] = r.error ? { error: r.error } : { txt: r.answers }; }, step("DKIM selector lookups"));
      live = L;
      const failed = Object.values(L.ptr).filter((x) => x && x.error).length;
      note.textContent = "Looked up " + checkedAt.replace("T", " ").slice(0, 19) + " UTC: " + ips.length + " PTR (" + failed + " failed), " + pds.length + " domain(s), " + sels.length + " DKIM selector(s)." + (result.tables.sources.length > PTR_CAP ? " PTR limited to the " + PTR_CAP + " busiest sources." : "");
      await run("re-analyzing with live results");
    } catch (e) {
      toast("Lookup failed: " + ((e && e.message) || e), "error");
    } finally { btn.disabled = false; }
  });

  // ---- results ----
  function render() {
    const r = result, s = r.summary;
    $("kpis").innerHTML = kpi(s.reports, "reports") + kpi(s.messages, "messages") + kpi(s.dmarcPassPct + "%", "DMARC pass") + kpi(s.failing, "failing messages") +
      kpi(s.unknownSources, "unknown sources") + kpi(s.currentPolicy || "-", "current policy" + (s.primaryDomain ? " (" + s.primaryDomain + ")" : ""));
    $("results").style.display = "";
    $("lookup").disabled = isExample;
    if (isExample) $("livenote").textContent = "Live lookups are off for the synthetic example (documentation addresses and test domains).";
    $("skipped").innerHTML = r.skipped.length ? "<li><b>Skipped or limited checks</b></li>" + r.skipped.slice(0, 60).map((k) => "<li>" + esc(k.check) + ": " + esc(k.reason) + "</li>").join("") + (r.skipped.length > 60 ? "<li>and " + (r.skipped.length - 60) + " more (see the JSON export)</li>" : "") : "";
    renderFileSummary();
    const tabs = [["findings", "Findings (" + r.findings.length + ")"], ["sources", "Sources (" + r.tables.sources.length + ")"], ["senders", "Senders (" + r.tables.senders.length + ")"], ["domains", "Domains (" + r.tables.domains.length + ")"], ["daily", "Daily"], ["plan", "Progression plan"]];
    if (r.tables.forensic.length) tabs.push(["forensic", "Forensic (" + r.tables.forensic.length + ")"]);
    $("tabs").innerHTML = tabs.map(([k, l]) => '<button type="button" class="' + P + "-tab" + (tab === k ? " on" : "") + '" data-tab="' + k + '">' + esc(l) + "</button>").join("");
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; selected = ""; $("drawer").style.display = "none"; render(); }));
    if (!tabs.some(([k]) => k === tab)) tab = "findings";
    drawPane();
    renderExports();
  }

  function renderFileSummary() {
    const r = result, s = r.summary, fl = r.tables.files;
    const bad = fl.filter((f) => f.error || (f.duplicate && !f.reports));
    const recRej = fl.reduce((n, f) => n + (f.rejected || 0), 0);
    $("filesum").innerHTML = '<h3>Files read</h3><dl class="' + P + '-kv"><dt>Files</dt><dd>' + s.files + "</dd><dt>Aggregate reports parsed</dt><dd>" + s.reports + "</dd><dt>Duplicates removed</dt><dd>" + s.duplicates +
      "</dd><dt>Forensic reports</dt><dd>" + s.forensic + "</dd><dt>Skipped files</dt><dd>" + bad.length + "</dd><dt>Unreadable records</dt><dd>" + recRej + "</dd><dt>Date range</dt><dd>" + esc(s.from && s.to ? s.from + " to " + s.to : "-") +
      "</dd><dt>Reporters</dt><dd>" + esc(r.tables.reporters.map((x) => x.org + " (" + x.reports + ")").join(", ") || "-") + "</dd></dl>" +
      (bad.length ? '<details class="' + P + '-det"><summary>Skipped files (' + bad.length + ')</summary><ul class="' + P + '-skip">' + bad.slice(0, 200).map((f) => "<li>" + esc(f.name) + ": " + esc(f.error || "duplicate of " + f.duplicateOf) + "</li>").join("") + (bad.length > 200 ? "<li>and " + (bad.length - 200) + " more</li>" : "") + "</ul></details>" : "") +
      (r.tables.reporters.length ? '<details class="' + P + '-det"><summary>Reporters (' + r.tables.reporters.length + ')</summary><div class="' + P + '-list" style="margin-top:8px"><table><thead><tr><th>Reporter</th><th>Email</th><th>Reports</th><th>Messages</th><th>From</th><th>To</th><th>Schema</th></tr></thead><tbody>' +
        r.tables.reporters.map((x) => "<tr><td>" + esc(x.org) + "</td><td>" + esc(x.email) + "</td><td>" + x.reports + "</td><td>" + x.messages + '</td><td class="' + P + '-nw">' + esc(x.first) + '</td><td class="' + P + '-nw">' + esc(x.last) + "</td><td>" + esc(x.schemas) + "</td></tr>").join("") + "</tbody></table></div></details>" : "");
  }

  const FIND_COLS = [
    { key: "severity", label: "Severity", rank: SEV_RANK, render: (f) => pill(f.severity) },
    { key: "title", label: "Finding", render: (f) => "<b>" + esc(f.title) + '</b><div class="' + P + '-note">' + esc(f.category) + "</div>" },
    { key: "confidence", label: "Confidence", rank: CONF_RANK },
    { key: "controls", label: "Controls", render: (f) => chips(f.controls) },
    { key: "evidenceCount", label: "Evidence" },
  ];
  const srcCols = (withPtr) => [
    { key: "ip", label: "Source IP", render: (s) => '<span class="' + P + '-nw">' + esc(s.ip) + "</span>" },
    ...(withPtr ? [{ key: "ptr", label: "PTR" }] : []),
    { key: "headerFrom", label: "From domain" }, { key: "messages", label: "Messages" },
    { key: "dmarcPassPct", label: "DMARC pass", render: (s) => pctTxt(s.dmarcPassPct) }, { key: "dkimAlignedPct", label: "DKIM aligned", render: (s) => pctTxt(s.dkimAlignedPct) }, { key: "spfAlignedPct", label: "SPF aligned", render: (s) => pctTxt(s.spfAlignedPct) },
    { key: "classification", label: "Classification", render: (s) => kindTag(s.kind) + " " + esc(s.classification) },
    { key: "envelopeDomains", label: "Envelope from" }, { key: "dkimDomains", label: "DKIM d= / selector" },
  ];
  const SEND_COLS = [
    { key: "kind", label: "Type", render: (s) => kindTag(s.kind) }, { key: "sender", label: "Sender" }, { key: "sources", label: "Source IPs" }, { key: "messages", label: "Messages" }, { key: "failing", label: "Failing" },
    { key: "dmarcPassPct", label: "DMARC pass", render: (s) => pctTxt(s.dmarcPassPct) }, { key: "dkimAlignedPct", label: "DKIM aligned", render: (s) => pctTxt(s.dkimAlignedPct) }, { key: "spfAlignedPct", label: "SPF aligned", render: (s) => pctTxt(s.spfAlignedPct) },
    { key: "domains", label: "From domains" }, { key: "classifiedVia", label: "Classified by", render: (s) => esc(s.classifiedVia) + (s.selectorOnly ? ' <span class="' + P + '-chip">selector only</span>' : "") },
  ];
  const DOM_COLS = [
    { key: "domain", label: "From domain", render: (d) => esc(d.domain) + (d.isSubdomain ? ' <span class="' + P + '-chip">subdomain</span>' : "") }, { key: "messages", label: "Messages" }, { key: "passPct", label: "DMARC pass", render: (d) => pctTxt(d.passPct) },
    { key: "fail", label: "Failing" }, { key: "policies", label: "Policies seen" }, { key: "reporters", label: "Reporters" }, { key: "sources", label: "Source IPs" },
  ];
  const DAY_COLS = [{ key: "date", label: "Date (UTC)" }, { key: "messages", label: "Messages" }, { key: "pass", label: "Pass" }, { key: "fail", label: "Fail" }, { key: "passPct", label: "Pass %", render: (d) => pctTxt(d.passPct) }];
  const FOR_COLS = [{ key: "file", label: "File" }, { key: "feedbackType", label: "Feedback type" }, { key: "authFailure", label: "Auth failure" }, { key: "sourceIp", label: "Source IP" }, { key: "reportedDomain", label: "Reported domain" }, { key: "originalMailFrom", label: "Original mail from" }, { key: "arrivalDate", label: "Arrival date" }, { key: "deliveryResult", label: "Delivery result" }];

  function drawPane() {
    const pane = $("pane"), r = result;
    pane.innerHTML = "";
    const pick = (t) => { t.querySelectorAll("tr[data-i]").forEach((tr) => { if (tr.dataset.i === selected) tr.classList.add("sel"); }); return t; };
    if (tab === "findings") {
      if (!r.findings.length) { pane.innerHTML = '<div class="' + P + '-empty">No findings for the current thresholds.</div>'; return; }
      const rows = r.findings.map((f, i) => ({ ...f, i: String(i) }));
      const t = pick(table(FIND_COLS, rows, sorts.findings, (s) => { sorts.findings = s; drawPane(); }, (f) => f.i));
      t.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => { selected = tr.dataset.i; drawPane(); showFinding(r.findings[Number(selected)]); }));
      pane.appendChild(t);
      pane.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">Click a finding for its evidence. Detections: ' + DETECTIONS.map((d) => esc(d.title) + " (needs " + esc(d.needs) + ")").join("; ") + ".</p>");
      return;
    }
    if (tab === "sources") {
      const rows = r.tables.sources;
      if (!rows.length) { pane.innerHTML = '<div class="' + P + '-empty">No sources.</div>'; return; }
      const withPtr = rows.some((s) => s.ptr !== undefined);
      const t = pick(table(srcCols(withPtr), rows, sorts.sources, (s) => { sorts.sources = s; drawPane(); }, (s) => s.key, 1000));
      t.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => { selected = tr.dataset.i; drawPane(); showRecord("Source " + selected.split("|")[1], rows.find((s) => s.key === selected)); }));
      pane.appendChild(t);
      pane.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">' + (rows.length > 1000 ? "Showing 1000 of " + rows.length + " in the current sort. " : "") + "One row per From domain and source IP. Alignment is recomputed from auth_results with the published adkim / aspf. " + (withPtr ? "PTR names come from the live lookup." : "PTR names appear after Look up sources.") + "</p>");
      return;
    }
    if (tab === "senders") {
      const rows = r.tables.senders;
      if (!rows.length) { pane.innerHTML = '<div class="' + P + '-empty">No senders.</div>'; return; }
      const t = pick(table(SEND_COLS, rows, sorts.senders, (s) => { sorts.senders = s; drawPane(); }, (s) => s.key));
      t.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => { selected = tr.dataset.i; drawPane(); showSender(rows.find((s) => s.key === selected)); }));
      pane.appendChild(t);
      pane.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">Service = matched in the sending-service table; authenticated = passes DMARC as your domain but the service is not identified; forwarding = forwarder or mailing list; unknown = no aligned pass and no known service. Click a sender for its sources.</p>');
      return;
    }
    if (tab === "domains") {
      pane.appendChild(table(DOM_COLS, r.tables.domains, sorts.domains, (s) => { sorts.domains = s; drawPane(); }, (d) => d.domain));
      return;
    }
    if (tab === "daily") {
      pane.innerHTML = dailySvg(r.tables.daily);
      pane.appendChild(table(DAY_COLS, r.tables.daily, sorts.daily, (s) => { sorts.daily = s; drawPane(); }, (d) => d.date));
      return;
    }
    if (tab === "forensic") {
      pane.appendChild(table(FOR_COLS, r.tables.forensic, sorts.forensic, (s) => { sorts.forensic = s; drawPane(); }, (f) => f.file));
      pane.insertAdjacentHTML("beforeend", '<p class="' + P + '-note">Key ARF headers (RFC 5965 / RFC 6591) from forensic reports. Message bodies are not shown.</p>');
      return;
    }
    if (tab === "plan") {
      const plans = r.tables.plan;
      if (!plans.length) { pane.innerHTML = '<div class="' + P + '-empty">No policy data.</div>'; return; }
      pane.innerHTML = '<p class="' + P + '-note" style="margin:0 0 10px">Rules (deterministic): advance one stage when the reports cover at least the observation days at the current stage, legitimate-looking mail passes DMARC at or above the threshold, and no known or authenticated sender still fails above the per-sender minimum. Estimates apply the next stage\'s pct to the failing mail in the report window.</p>' +
        plans.map((p) => '<div class="' + P + '-plan"><h3 style="margin-top:0">' + esc(p.domain) + "</h3>" +
          '<ol class="' + P + '-stages">' + p.stages.map((s) => '<li class="' + (s.status === "done" ? "done" : s.status === "current" ? "current" : s.status === "next: ready" ? "ready" : s.status === "next: blocked" ? "blocked" : "") + '">' + esc(s.label) + (s.status.startsWith("next") ? " (" + esc(s.status.slice(6)) + ")" : "") + "</li>").join("") + "</ol>" +
          '<dl class="' + P + '-kv"><dt>Current</dt><dd>' + esc(p.current.label + (p.current.sp ? " sp=" + p.current.sp : "")) + "</dd><dt>Reports at current</dt><dd>" + p.daysAtCurrent + " day(s), " + esc(p.since) + " to " + esc(p.until) + "</dd><dt>Legitimate-looking mail</dt><dd>" + p.legitMessages + " messages, " + p.legitPassPct + "% pass</dd>" +
          (p.next ? "<dt>Next stage</dt><dd><b>" + esc(p.next.label) + "</b>: " + (p.ready ? "ready" : "blocked") + "</dd>" : "") +
          (p.estimate ? "<dt>Estimated effect</dt><dd>" + p.estimate.legitimate + " legitimate-looking, " + p.estimate.forwarded + " forwarded and " + p.estimate.unknown + " unknown-source messages over the " + p.estimate.windowDays + "-day window would get " + esc(p.estimate.action) + " (about " + p.estimate.perDayLegitimate + " legitimate and " + p.estimate.perDayUnknown + " unknown per day)</dd>" : "") + "</dl>" +
          (p.reasons.length ? "<ul>" + p.reasons.map((x) => "<li>" + esc(x) + "</li>").join("") + "</ul>" : "") +
          (p.blockers.length ? '<div class="' + P + '-list" style="margin-top:8px"><table><thead><tr><th>Blocking sender</th><th>Failing</th><th>From domains</th><th>Fix</th></tr></thead><tbody>' + p.blockers.map((b) => "<tr><td>" + kindTag(b.kind) + " " + esc(b.sender) + "</td><td>" + b.failing + "</td><td>" + esc(b.domains) + "</td><td>" + esc(b.fix) + "</td></tr>").join("") + "</tbody></table></div>" : "") +
          (p.notes.length ? "<ul>" + p.notes.map((x) => '<li class="' + P + '-note">' + esc(x) + "</li>").join("") + "</ul>" : "") + "</div>").join("");
    }
  }

  function closeBtn() { return '<button class="' + P + '-btn sm" data-close type="button">Close</button>'; }
  function wireClose(d) { d.querySelector("[data-close]").addEventListener("click", () => { d.style.display = "none"; selected = ""; drawPane(); }); d.scrollIntoView({ block: "nearest", behavior: "smooth" }); }

  function showFinding(f) {
    const d = $("drawer");
    d.style.display = "block";
    d.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + pill(f.severity) + " " + esc(f.title) + "</h3>" + closeBtn() + "</div>" +
      "<p>" + esc(f.description) + "</p><p><b>Recommendation:</b> " + esc(f.recommendation) + "</p><p><b>Confidence:</b> " + esc(f.confidence) + (f.assets.length ? " &middot; <b>Assets:</b> " + esc(f.assets.slice(0, 12).map((a) => a.name).join(", ")) + (f.assets.length > 12 ? " +" + (f.assets.length - 12) : "") : "") + "</p>" +
      "<p>" + chips(f.controls) + "</p><p><b>Evidence</b> (" + f.evidence.length + " of " + f.evidenceCount + (f.evidenceCount > f.evidence.length ? "; the first 50 are kept" : "") + ")</p>" + evidenceTable(f.evidence) +
      '<div class="' + P + '-row"><button class="' + P + '-btn sm" data-ev type="button">Export evidence CSV</button></div>';
    wireClose(d);
    d.querySelector("[data-ev]").addEventListener("click", () => {
      const rows = f.evidence || [], keys = [];
      for (const x of rows) for (const k of Object.keys(x)) if (!keys.includes(k)) keys.push(k);
      download(TOOL_ID + "-evidence-" + fileStamp() + ".csv", [keys.join(","), ...rows.map((x) => keys.map((k) => csvCell(x[k])).join(","))].join("\n") + "\n", "text/csv");
    });
  }

  function showRecord(title, rec) {
    const d = $("drawer");
    if (!rec) { d.style.display = "none"; return; }
    const skip = new Set(["key"]);
    d.style.display = "block";
    d.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + esc(title) + "</h3>" + closeBtn() + '</div><div class="' + P + '-list"><table><tbody>' +
      Object.entries(rec).filter(([k]) => !skip.has(k)).map(([k, v]) => "<tr><th style=\"cursor:default\">" + esc(k) + "</th><td>" + esc(v) + "</td></tr>").join("") + "</tbody></table></div>";
    wireClose(d);
  }

  function showSender(s) {
    const d = $("drawer");
    if (!s) { d.style.display = "none"; return; }
    const list = result.tables.sources.filter((x) => x.kind + ":" + x.serviceId === s.key);
    const fix = result.tables.fixes.filter((f) => f.sender === s.sender);
    d.style.display = "block";
    d.innerHTML = '<div class="' + P + '-row" style="margin:0;justify-content:space-between"><h3>' + kindTag(s.kind) + " " + esc(s.sender) + "</h3>" + closeBtn() + "</div><p>" + s.messages + " messages from " + s.sources + " source IP(s); " + s.failing + " fail DMARC. " + (s.spfInclude ? "SPF include for this service: include:" + esc(s.spfInclude) + "." : "") + "</p>" +
      fix.map((f) => "<p><b>DKIM fix for " + esc(f.domain) + ":</b> " + esc(f.dkim) + "</p><p><b>Return-path:</b> " + esc(f.spf) + "</p>").join("") +
      evidenceTable(list.slice(0, 200).map((x) => ({ source_ip: x.ip, ...(x.ptr !== undefined ? { ptr: x.ptr } : {}), header_from: x.headerFrom, messages: x.messages, failing: x.fail, dmarc_pass: x.dmarcPassPct + "%", envelope_from: x.envelopeDomains, dkim: x.dkimDomains })));
    wireClose(d);
  }

  // ---- exports + graph ----
  function renderExports() {
    const r = result, ex = $("exports"), stamp = fileStamp();
    const b = (x, l) => '<button class="' + P + '-btn" data-x="' + x + '">' + l + "</button>";
    ex.innerHTML = b("find", "Findings CSV") + b("json", "JSON") + b("txt", "Summary TXT") + b("src", "Sources CSV") + b("fix", "SPF / DKIM fix list TXT") + b("plan", "Progression plan TXT");
    const on = (x, fn) => ex.querySelector('[data-x="' + x + '"]').addEventListener("click", fn);
    on("find", () => download(TOOL_ID + "-findings-" + stamp + ".csv", findingsToCsv(r.findings), "text/csv"));
    on("json", () => download(TOOL_ID + "-" + stamp + ".json", toJson({ ...r, summaryStats: summarize(r.findings), live: live || null }), "application/json"));
    on("txt", () => download(TOOL_ID + "-summary-" + stamp + ".txt", summaryText(r), "text/plain"));
    on("src", () => download(TOOL_ID + "-sources-" + stamp + ".csv", sourcesToCsv(r.tables.sources), "text/csv"));
    on("fix", () => download(TOOL_ID + "-fixes-" + stamp + ".txt", fixListText(r), "text/plain"));
    on("plan", () => download(TOOL_ID + "-plan-" + stamp + ".txt", planText(r), "text/plain"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: datasetName() });
  }

  renderFiles();
}
