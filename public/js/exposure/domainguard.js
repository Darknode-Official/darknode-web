// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Domain Guard (domainguard): Deck tool UI. Checks every owned domain live over
// DNS-over-HTTPS (dns.google, cloudflare-dns.com fallback), RDAP (rdap.org via the
// site's fetch proxy), certificate transparency (crt.sh / certspotter via ct-fetch),
// MTA-STS policy files and the hostnames the user supplied (via the proxy). All
// fetching lives here; grading is the pure engine running in a Worker. Results are
// timestamped and the compact snapshot is kept per workspace so the next run shows
// what changed. No native dialogs; toasts only.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import { wsKey } from "../core/register.js";
import {
  DEFAULTS, LIMITS, TOOL_ID, TAKEOVER_FINGERPRINTS, parseInput, parseDomainList, findingsToCsv, exampleDataset,
  planDomainQueries, spfIncludeTargets, txtStrings, rrData, dohStatus, normName, generateLookalikes, registrableDomain,
  matchTakeoverProvider, cnameChain, snapshotOf, dnsFixList, lookalikesToCsv, summaryText, isDomainName,
} from "./domainguard-engine.js?v=20261017c";

const ENGINE = engineUrl("./domainguard-engine.js?v=20261017c", import.meta);
const P = "dmg";
const RUNS_KEY = "dn_domainguard_runs";
const DRAFT_KEY = "dn_domainguard_draft";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t || "info"); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CHECK_COLS = [["ns", "NS"], ["mx", "MX"], ["spf", "SPF"], ["dmarc", "DMARC"], ["parked", "Parked"], ["mtasts", "MTA-STS"], ["tlsrpt", "TLS-RPT"], ["dnssec", "DNSSEC"], ["caa", "CAA"], ["wildcard", "Wildcard"], ["expiry", "Expiry"], ["lock", "Lock"], ["cert", "Cert"], ["soa", "SOA"], ["bimi", "BIMI"]];

const CSS = `
  .dmg-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230);box-sizing:border-box;min-width:0}
  .dmg-root *{box-sizing:border-box}
  .dmg-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .dmg-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .dmg-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--mut,#667085);border:1px solid var(--line,#e6e8ee);padding:2px 9px;border-radius:999px}
  .dmg-sub{color:var(--mut,#667085);margin:8px 0 6px;overflow-wrap:anywhere}
  .dmg-honest{border:1px solid var(--line,#e6e8ee);border-left:3px solid var(--mut,#667085);border-radius:8px;padding:10px 14px;font-size:.82rem;margin:8px 0 14px;background:var(--card,#fff);overflow-wrap:anywhere}
  .dmg-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px;min-width:0}
  .dmg-card h3{font-size:.95rem;margin:0 0 6px}
  .dmg-help{color:var(--mut,#667085);font-size:.78rem;margin:4px 0 0;overflow-wrap:anywhere}
  .dmg-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:14px}
  .dmg-root textarea{width:100%;min-height:150px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;line-height:1.5;padding:10px 12px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--card,#fff);color:var(--tx,#1a2230)}
  .dmg-root input[type=text],.dmg-root input[type=number],.dmg-root select{font:inherit;font-size:.85rem;padding:6px 9px;border:1px solid var(--line,#d7dbe3);border-radius:7px;background:var(--card,#fff);color:var(--tx,#1a2230);max-width:100%}
  .dmg-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .dmg-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .dmg-btn:hover{border-color:var(--mut,#667085)}
  .dmg-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .dmg-btn:disabled{opacity:.5;cursor:default}
  .dmg-opts{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,200px),1fr));gap:12px 16px}
  .dmg-opt label{display:block;font-size:.74rem;font-weight:700;color:var(--mut,#667085);margin-bottom:3px}
  .dmg-opt input{width:100%}
  .dmg-files{display:flex;flex-direction:column;gap:4px;margin-top:10px;font-size:.8rem}
  .dmg-file{display:flex;flex-wrap:wrap;gap:6px 12px;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:6px 10px;overflow-wrap:anywhere}
  .dmg-conf{font-weight:700;text-transform:uppercase;font-size:.7rem;letter-spacing:.04em}
  .dmg-conf.high{color:#1b7f4d}.dmg-conf.medium{color:#8a6d00}.dmg-conf.low{color:#b00020}
  .dmg-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,150px),1fr));gap:10px;margin:0 0 14px}
  .dmg-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px;min-width:0}
  .dmg-kpi b{display:block;font-size:1.35rem;line-height:1.2;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
  .dmg-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .dmg-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:12px;display:none}
  .dmg-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .dmg-status{font-size:.8rem;color:var(--mut,#667085);margin-top:6px;overflow-wrap:anywhere}
  .dmg-tabs{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 10px;border-bottom:1px solid var(--line,#e6e8ee);padding-bottom:8px}
  .dmg-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid transparent;background:none;color:var(--mut,#667085);padding:6px 12px;border-radius:7px;cursor:pointer}
  .dmg-tab.on{border-color:var(--line,#d7dbe3);color:var(--tx,#1a2230);background:var(--card,#fff)}
  .dmg-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto;max-height:640px;background:var(--card,#fff)}
  .dmg-list table{width:100%;border-collapse:collapse;font-size:.83rem}
  .dmg-list th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 10px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;position:sticky;top:0;z-index:1}
  .dmg-list th[data-k]{cursor:pointer;user-select:none}
  .dmg-list td{padding:8px 10px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere;min-width:60px}
  .dmg-list td.wide{min-width:220px}
  .dmg-list tr[data-i]{cursor:pointer}
  .dmg-list tr[data-i]:hover td{background:var(--bg,#f7f8fb)}
  .dmg-pill{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .dmg-pill.critical{background:#7a0012}.dmg-pill.high{background:#b00020}.dmg-pill.medium{background:#b58100}.dmg-pill.low{background:#2552c6}.dmg-pill.info{background:#667085}
  .dmg-chip{display:inline-block;font-size:.68rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085);white-space:nowrap}
  .dmg-st{display:inline-block;font-size:.68rem;font-weight:700;border-radius:5px;padding:1px 6px;border:1px solid var(--line,#d7dbe3);white-space:nowrap}
  .dmg-st.pass{color:#1b7f4d;border-color:#1b7f4d}.dmg-st.fail{color:#b00020;border-color:#b00020}.dmg-st.warn{color:#8a6d00;border-color:#b58100}
  .dmg-st.error{color:#7a0012;border-style:dashed}.dmg-st.info,.dmg-st.na,.dmg-st.unchecked{color:var(--mut,#667085)}
  .dmg-grade{display:inline-block;min-width:28px;text-align:center;font-weight:800;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px}
  .dmg-grade.A{color:#1b7f4d;border-color:#1b7f4d}.dmg-grade.B{color:#2552c6;border-color:#2552c6}.dmg-grade.C,.dmg-grade.D{color:#8a6d00;border-color:#b58100}.dmg-grade.F{color:#b00020;border-color:#b00020}
  .dmg-empty{padding:24px;text-align:center;color:var(--mut,#667085)}
  .dmg-drawer{margin-top:14px;display:none}
  .dmg-drawer .dmg-card{border-width:1px 1px 1px 3px}
  .dmg-drawer pre{margin:6px 0 0;max-height:300px;overflow:auto;font-size:12px;background:var(--bg,#f7f8fb);border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:10px 12px;white-space:pre-wrap;overflow-wrap:anywhere}
  .dmg-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px;overflow-wrap:anywhere}
  .dmg-flags td{vertical-align:middle}
  .dmg-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
  .dmg-filters{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;margin-bottom:10px;font-size:.82rem}
  .dmg-x{float:right}
  @media (max-width:600px){.dmg-card{padding:12px}.dmg-hd h1{font-size:1.4rem}}
`;

const store = {
  get(k, d) { try { const v = localStorage.getItem(wsKey(k)); return v ? JSON.parse(v) : d; } catch (_) { return d; } },
  set(k, v) { try { localStorage.setItem(wsKey(k), JSON.stringify(v)); return true; } catch (_) { return false; } },
};

function kpi(v, l) { return '<div class="' + P + '-kpi"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>"; }
function st(s) { return '<span class="' + P + "-st " + esc(s || "na") + '">' + esc(s || "-") + "</span>"; }
function pill(s) { return '<span class="' + P + "-pill " + esc(s) + '">' + esc(s) + "</span>"; }
function rowsTable(rows, cols) {
  if (!rows || !rows.length) return '<div class="' + P + '-empty">No rows.</div>';
  const keys = cols || [...new Set(rows.flatMap((r) => Object.keys(r)))];
  return '<div class="' + P + '-list"><table><thead><tr>' + keys.map((k) => "<th>" + esc(k) + "</th>").join("") + "</tr></thead><tbody>" +
    rows.map((r) => "<tr>" + keys.map((k) => '<td class="' + P + '-mono">' + esc(typeof r[k] === "object" && r[k] != null ? JSON.stringify(r[k]) : r[k]) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>";
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function randLabel() {
  try { const a = new Uint8Array(5); crypto.getRandomValues(a); return "dmg-" + Array.from(a, (b) => b.toString(16).padStart(2, "0")).join(""); } catch (_) { return "dmg-" + Math.random().toString(16).slice(2, 12); }
}

// ---- live fetchers (UI side; engine stays pure) ---------------------------
const DOH = {
  google: (n, t) => "https://dns.google/resolve?name=" + encodeURIComponent(n) + "&type=" + t,
  cloudflare: (n, t) => "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(n) + "&type=" + t,
};
async function dohOnce(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const res = await fetch(url, { headers: { Accept: "application/dns-json" }, signal: ctrl.signal });
    if (!res.ok) throw new Error("HTTP " + res.status);
    return await res.json();
  } finally { clearTimeout(timer); }
}
/** DoH query: preferred resolver first, then the other one. Failure -> { error }. */
async function doh(name, type, prefer) {
  const order = prefer === "cloudflare" ? ["cloudflare"] : prefer === "google" ? ["google"] : ["google", "cloudflare"];
  let last = "";
  for (const r of order) {
    try { const j = await dohOnce(DOH[r](name, type)); j._via = r === "google" ? "dns.google" : "cloudflare-dns.com"; return j; } catch (e) { last = (r === "google" ? "dns.google" : "cloudflare-dns.com") + ": " + ((e && e.message) || e); }
  }
  return { error: last || "DoH failed" };
}

let netMod = null, ctMod = null;
async function net() { if (!netMod) netMod = await import("/js/net.js"); return netMod; }
async function ct() { if (!ctMod) ctMod = await import("../dataprotect/ct-fetch.js"); return ctMod; }
async function proxyGet(url, timeout = 8000) {
  try {
    const n = await net();
    if (!n.proxyConfigured()) return { error: "fetch proxy not configured" };
    const r = await n.dnFetch(url, { raw: true, timeout });
    return { status: r.status, body: String(r.body || "").slice(0, 20000), finalUrl: r.finalUrl || url };
  } catch (e) { return { error: String((e && e.message) || e) }; }
}
async function rdap(domain) {
  try {
    const n = await net();
    if (!n.proxyConfigured()) return { error: "fetch proxy not configured" };
    const r = await n.dnFetch("https://rdap.org/domain/" + encodeURIComponent(domain), { raw: true, timeout: 12000 });
    if (r.status === 404) return { error: "RDAP: domain not found or TLD has no RDAP service (HTTP 404)" };
    try { return JSON.parse(r.body); } catch (_) { return { error: "RDAP did not return JSON (HTTP " + r.status + ")" }; }
  } catch (e) { return { error: String((e && e.message) || e) }; }
}

/** Mount the tool into main. */
export function renderDomainGuard(main) {
  if (!document.getElementById(P + "-css")) {
    const s = document.createElement("style"); s.id = P + "-css"; s.textContent = CSS; document.head.appendChild(s);
  }
  const optFields = [
    ["expiryWarnDays", "Expiry warning (days)", "Registration expiring sooner is high severity."],
    ["expiryCriticalDays", "Expiry critical (days)", "Sooner than this, or expired, is critical."],
    ["certWarnDays", "Certificate warning (days)", "Newest CT certificate expiring sooner is medium."],
    ["newlyRegisteredDays", "Newly registered lookalike (days)", "Lookalikes created more recently count as new."],
    ["maxCandidates", "Lookalike candidates per domain", "Default 300, up to " + LIMITS.maxCandidates + ". Each costs 1 to 4 lookups."],
    ["concurrency", "Parallel lanes", "Default 4 (1 to 8)."],
    ["spacingMs", "Pause between requests (ms)", "Per lane; keeps the run polite to resolvers."],
  ];
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Domain Guard</h1><span class="', P, '-tag">Domain Portfolio Guard</span></div>',
    '<p class="', P, '-sub">Checks every domain you own - main, regional, marketing, parked, acquired - for what lets attackers spoof your mail, take over subdomains, hijack an expiring registration or register a lookalike.</p>',
    '<div class="', P, '-honest">Runs in your browser. Files you drop are parsed locally and never uploaded. Live checks send the domain and host names you enter to: dns.google and cloudflare-dns.com (DNS-over-HTTPS, direct); rdap.org, crt.sh and api.certspotter.com (certificate transparency), mta-sts.&lt;your domain&gt; and the hostnames you supply (HTTP takeover fingerprints) - all through the Darknode fetch proxy. Load example makes no network calls.</div>',
    '<div class="', P, '-grid">',
    '<div class="', P, '-card"><h3>Owned domains</h3><textarea id="', P, '-domains" spellcheck="false" placeholder="one domain per line"></textarea>',
    '<p class="', P, '-help">Optional flag after a domain: <b>mail</b> (sends mail) or <b>parked</b> (no mail). CSV with a domain column also works. Unicode names are converted to Punycode.</p>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-graph">Import DOMAIN entities from Security Graph</button></div></div>',
    '<div class="', P, '-card"><h3>Known hostnames (optional)</h3><textarea id="', P, '-hosts" spellcheck="false" placeholder="one hostname per line"></textarea>',
    '<p class="', P, '-help">Subdomains to test for dangling records. Zone exports dropped below add their A/AAAA/CNAME/alias owners automatically. HTTP fingerprints are fetched only for hostnames you supply.</p></div>',
    "</div>",
    '<div class="', P, '-card"><h3>Import files</h3><div id="', P, '-drop"></div>',
    '<p class="', P, '-help">Domain lists (TXT/CSV) and DNS zone exports: BIND zone files (also Cloudflare\'s export), Route 53 <span class="', P, '-mono">list-resource-record-sets</span> JSON, Azure <span class="', P, '-mono">az network dns record-set list</span> JSON. Several files at once; .zip/.gz unpacked.</p>',
    '<div class="', P, '-files" id="', P, '-files"></div><div id="', P, '-map"></div></div>',
    '<div class="', P, '-card"><h3>Settings</h3>',
    '<div class="', P, '-opt" style="margin-bottom:12px"><label for="', P, '-kw">Brand keywords</label><input type="text" id="', P, '-kw" placeholder="e.g. product names" style="width:100%"><p class="', P, '-help">Comma separated. Combined with login, secure, support, billing, pay, hr, portal, sso, mail when generating lookalikes.</p></div>',
    '<div class="', P, '-opts">',
    optFields.map(([k, l, h]) => '<div class="' + P + '-opt"><label for="' + P + "-o-" + k + '">' + esc(l) + '</label><input type="number" min="0" id="' + P + "-o-" + k + '" data-opt="' + k + '" value="' + esc(DEFAULTS[k]) + '"><p class="' + P + '-help">' + esc(h) + " Default " + esc(DEFAULTS[k]) + ".</p></div>").join(""),
    "</div>",
    '<h3 style="margin-top:14px">Per-domain options</h3><p class="', P, '-help">Mail role "auto" uses MX and SPF. Lookalike checks are opt-in per domain because each one costs hundreds of DNS queries.</p>',
    '<div class="', P, '-list" id="', P, '-flags" style="max-height:320px;margin-top:8px"></div></div>',
    '<div class="', P, '-card"><div class="', P, '-row" style="margin-top:0">',
    '<button class="', P, '-btn pri" id="', P, '-run">Run checks</button>',
    '<button class="', P, '-btn" id="', P, '-cancel" disabled>Cancel</button>',
    '<button class="', P, '-btn" id="', P, '-regrade" disabled>Re-grade with current settings</button>',
    '<button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button>',
    '<button class="', P, '-btn" id="', P, '-clear">Clear</button></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div><div class="', P, '-status" id="', P, '-status"></div></div>',
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-tabs" id="', P, '-tabs"></div>',
    '<div id="', P, '-panel"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div>',
    '<div class="', P, '-skip" id="', P, '-skipped"></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let zoneFiles = []; // [{ name, format, confidence, records, origin, domains }]
  let zoneHosts = []; // from zone exports
  let zoneDomains = []; // { domain, sendsMail, parked } from files
  const flags = new Map(); // domain -> { role: auto|mail|parked, look: bool }
  let observations = {}, hostObs = {}, lookalikes = {}, autoHosts = [];
  let result = null, isExample = false, previous = null, exampleData = null;
  let running = false, cancelled = false, tab = "findings", sortKey = "severity", sortDir = 1, lookFilter = { owner: "", status: "registered" };

  // ---- draft persistence (per viewer, per workspace)
  const draft = store.get(DRAFT_KEY, null);
  if (draft) {
    $("domains").value = draft.domains || ""; $("hosts").value = draft.hosts || ""; $("kw").value = draft.kw || "";
    for (const [d, f] of Object.entries(draft.flags || {})) flags.set(d, f);
  }
  const saveDraft = () => { if (!isExample) store.set(DRAFT_KEY, { domains: $("domains").value, hosts: $("hosts").value, kw: $("kw").value, flags: Object.fromEntries(flags) }); };

  // ---- inputs -> dataset
  function domainSpecs() {
    const list = parseDomainList($("domains").value).domains;
    const m = new Map();
    for (const d of [...zoneDomains, ...list]) {
      const prev = m.get(d.domain);
      m.set(d.domain, prev ? { ...prev, sendsMail: d.sendsMail != null ? d.sendsMail : prev.sendsMail, parked: prev.parked || d.parked } : { ...d });
    }
    const out = [];
    for (const d of [...m.values()].sort((a, b) => (a.domain < b.domain ? -1 : 1)).slice(0, LIMITS.maxDomains)) {
      const f = flags.get(d.domain);
      const role = f && f.role && f.role !== "auto" ? f.role : null;
      out.push({ domain: d.domain, sendsMail: role === "mail" ? true : role === "parked" ? false : d.sendsMail, parked: role === "parked" ? true : role === "mail" ? false : d.parked });
    }
    return out;
  }
  function hostList() {
    const typed = $("hosts").value.split(/[\r\n,]+/).map((s) => normName(s.replace(/^[a-z]+:\/\//i, "").split("/")[0])).filter((h) => isDomainName(h));
    const m = new Map();
    for (const h of zoneHosts) m.set(h.host, { ...h });
    for (const h of typed) if (!m.has(h)) m.set(h, { host: h, types: [], target: null, source: "list" });
    return [...m.values()].sort((a, b) => (a.host < b.host ? -1 : 1));
  }
  const keywords = () => $("kw").value.split(/[,\s]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
  const opts = () => {
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (el.value !== "" && Number.isFinite(n)) o[el.dataset.opt] = n; });
    o.maxCandidates = Math.max(1, Math.min(LIMITS.maxCandidates, o.maxCandidates || DEFAULTS.maxCandidates));
    o.concurrency = Math.max(1, Math.min(8, o.concurrency || DEFAULTS.concurrency));
    o.spacingMs = Math.max(0, Math.min(5000, o.spacingMs == null ? DEFAULTS.spacingMs : o.spacingMs));
    return o;
  };

  function renderFlags() {
    const specs = domainSpecs();
    const box = $("flags");
    if (!specs.length) { box.innerHTML = '<div class="' + P + '-empty">Add domains above to set per-domain options.</div>'; return; }
    box.innerHTML = '<table class="' + P + '-flags"><thead><tr><th>Domain</th><th>Mail role</th><th>Check lookalikes</th><th>Last checked</th></tr></thead><tbody>' +
      specs.map((s) => {
        const f = flags.get(s.domain) || { role: "auto", look: false };
        const auto = s.parked ? "auto (listed parked)" : s.sendsMail ? "auto (listed mail)" : "auto";
        const at = observations[s.domain] && observations[s.domain].at;
        return '<tr><td class="' + P + '-mono">' + esc(s.domain) + '</td><td><select data-role="' + esc(s.domain) + '"><option value="auto"' + (f.role === "auto" || !f.role ? " selected" : "") + ">" + esc(auto) + '</option><option value="mail"' + (f.role === "mail" ? " selected" : "") + '>sends mail</option><option value="parked"' + (f.role === "parked" ? " selected" : "") + '>parked (no mail)</option></select></td><td><label><input type="checkbox" data-look="' + esc(s.domain) + '"' + (f.look ? " checked" : "") + "> check</label></td><td>" + esc(at ? at.replace("T", " ").slice(0, 16) + " UTC" : "-") + "</td></tr>";
      }).join("") + "</tbody></table>";
    box.querySelectorAll("[data-role]").forEach((el) => el.addEventListener("change", () => { const d = el.dataset.role; flags.set(d, { ...(flags.get(d) || { look: false }), role: el.value }); saveDraft(); }));
    box.querySelectorAll("[data-look]").forEach((el) => el.addEventListener("change", () => { const d = el.dataset.look; flags.set(d, { ...(flags.get(d) || { role: "auto" }), look: el.checked }); saveDraft(); }));
  }
  let flagTimer = 0;
  const onInput = () => { if (isExample) leaveExample(); clearTimeout(flagTimer); flagTimer = setTimeout(() => { renderFlags(); saveDraft(); }, 300); };
  $("domains").addEventListener("input", onInput);
  $("hosts").addEventListener("input", onInput);
  $("kw").addEventListener("input", () => saveDraft());

  function leaveExample() {
    isExample = false; exampleData = null; observations = {}; hostObs = {}; lookalikes = {}; previous = null; autoHosts = [];
    $("run").disabled = false; $("status").textContent = "Example cleared; live results will be fetched on Run checks.";
  }

  // ---- file import
  function renderFiles() {
    $("files").innerHTML = zoneFiles.map((f) => '<div class="' + P + '-file"><b>' + esc(f.name) + "</b><span>" + esc(f.format) + '</span><span class="' + P + "-conf " + esc(f.confidence) + '">' + esc(f.confidence) + " confidence</span><span>" +
      (f.records ? esc(f.records) + " records" + (f.origin ? " (zone " + esc(f.origin) + ")" : "") : esc(f.domains) + " domains") + "</span></div>").join("");
  }
  mountDropzone($("drop"), {
    maxBytes: 64 * 1024 * 1024, maxFiles: 50, unpack: true,
    label: "Drop domain lists or DNS zone exports, paste, or browse",
    onFiles: async (files) => {
      if (!files.length) return;
      if (isExample) leaveExample();
      const list = [];
      for (const f of files) list.push({ name: f.name, text: await f.text() });
      const parsed = parseInput(list);
      const map = $("map"); map.innerHTML = "";
      for (const fi of parsed.files) {
        zoneFiles = zoneFiles.filter((z) => z.name !== fi.name).concat([fi]);
        if (fi.needsMapping) {
          const f = list.find((x) => x.name === fi.name);
          map.innerHTML += '<div class="' + P + '-row"><span>' + esc(fi.name) + ': choose the column that holds the domain</span><select data-map="' + esc(fi.name) + '">' + (fi.headers || parsed.headers).map((h) => "<option>" + esc(h) + "</option>").join("") + '</select><button class="' + P + '-btn" data-apply="' + esc(fi.name) + '">Use column</button></div>';
          setTimeout(() => {
            const b = map.querySelector('[data-apply="' + window.CSS.escape(fi.name) + '"]');
            if (b) b.addEventListener("click", () => {
              const col = map.querySelector('[data-map="' + window.CSS.escape(fi.name) + '"]').value;
              const dl = parseDomainList(f.text, { domain: col });
              zoneDomains = zoneDomains.concat(dl.domains);
              fi.domains = dl.domains.length; fi.confidence = "medium"; renderFiles(); renderFlags();
              toast(dl.domains.length + " domains from column " + col, "success");
              b.closest("." + P + "-row").remove();
            });
          }, 0);
        }
      }
      zoneDomains = zoneDomains.concat(parsed.domains);
      const hm = new Map(zoneHosts.map((h) => [h.host, h]));
      for (const h of parsed.hosts) hm.set(h.host, h);
      zoneHosts = [...hm.values()];
      renderFiles(); renderFlags();
      for (const s of parsed.skipped.slice(0, 3)) toast(s.reason, "warning");
      toast(parsed.domains.length + " domain(s), " + parsed.hosts.length + " hostname(s) from " + list.length + " file(s)", "success");
    },
  });

  $("graph").addEventListener("click", async () => {
    try {
      const sg = await import("/js/security-graph.js");
      const ents = (sg.listEntities({ type: "DOMAIN" }) || []).filter((e) => !(e.tags || []).includes("sample"));
      const names = [...new Set(ents.map((e) => normName(e.name)).filter((n) => isDomainName(n)))].sort();
      if (!names.length) { toast("No DOMAIN entities in the Security Graph", "info"); return; }
      const have = new Set(parseDomainList($("domains").value).domains.map((d) => d.domain));
      const add = names.filter((n) => !have.has(n));
      $("domains").value = ($("domains").value.trim() ? $("domains").value.trim() + "\n" : "") + add.join("\n");
      onInput();
      toast(add.length + " domain(s) imported from the Security Graph", "success");
    } catch (e) { toast("Could not read the Security Graph: " + ((e && e.message) || e), "error"); }
  });

  // ---- live run
  async function pool(tasks, lanes, onDone) {
    let i = 0;
    const lane = async () => { while (!cancelled && i < tasks.length) { const t = tasks[i++]; try { await t(); } catch (_) {} onDone(); } };
    await Promise.all(Array.from({ length: Math.min(lanes, tasks.length) }, lane));
  }
  async function fetchDomain(d, o) {
    const pause = () => sleep(o.spacingMs);
    const wild = randLabel() + "." + d;
    const dns = {};
    for (const q of planDomainQueries(d, wild)) {
      if (cancelled) return;
      dns[q.key] = await doh(q.name, q.type, q.resolver);
      await pause();
    }
    const nsHosts = {};
    for (const h of rrData(dns.NS, "NS").map(normName).sort().slice(0, 8)) { if (cancelled) return; nsHosts[h] = await doh(h, "A"); await pause(); }
    // Nested SPF includes (breadth-first, capped): each include is one TXT lookup.
    const spf = {};
    const root = txtStrings(dns.TXT).find((t) => /^v=spf1(\s|$)/i.test(t));
    const queue = root ? spfIncludeTargets(root) : [];
    let budget = 25;
    while (queue.length && budget-- > 0 && !cancelled) {
      const t = queue.shift();
      if (spf[t]) continue;
      spf[t] = await doh(t, "TXT");
      await pause();
      const rec = txtStrings(spf[t]).find((x) => /^v=spf1(\s|$)/i.test(x));
      if (rec) for (const n of spfIncludeTargets(rec)) if (!spf[n] && !queue.includes(n)) queue.push(n);
    }
    let mtaStsPolicy;
    if (txtStrings(dns.MTASTS).some((t) => /^v=stsv1/i.test(t))) { mtaStsPolicy = await proxyGet("https://mta-sts." + d + "/.well-known/mta-sts.txt"); await pause(); }
    const rd = await rdap(registrableDomain(d));
    await pause();
    let cert;
    try { const m = await ct(); cert = { rows: await m.fetchCertRows(d) }; } catch (e) { cert = { error: String((e && e.message) || e) }; }
    observations[d] = { at: new Date().toISOString(), dns, wildcardName: wild, nsHosts, spf, mtaStsPolicy, rdap: rd, cert };
  }
  async function fetchHost(h, o) {
    const A = await doh(h.host, "A");
    await sleep(o.spacingMs);
    const rec = { A, at: new Date().toISOString() };
    const live = cnameChain(A);
    const prov = matchTakeoverProvider(live.target || h.target);
    if (prov && prov.http.length && h.source !== "auto" && dohStatus(A) === "ok") {
      let r = await proxyGet("https://" + h.host + "/", 6000);
      if (r.error) r = await proxyGet("http://" + h.host + "/", 6000);
      rec.http = r;
      await sleep(o.spacingMs);
    }
    hostObs[h.host] = rec;
  }
  async function fetchCandidate(owner, cand, o, rdapLeft) {
    const r = { NS: await doh(cand, "NS") };
    await sleep(o.spacingMs);
    if (dohStatus(r.NS) !== "nxdomain" && !cancelled) {
      r.A = await doh(cand, "A"); await sleep(o.spacingMs);
      r.MX = await doh(cand, "MX"); await sleep(o.spacingMs);
      const registered = dohStatus(r.NS) === "ok" && (rrData(r.NS, "NS").length || rrData(r.A, "A").length || rrData(r.MX, "MX").length);
      if (registered && rdapLeft.n-- > 0) { r.rdap = await rdap(cand); await sleep(o.spacingMs); }
    }
    lookalikes[owner].results[cand] = r;
  }

  async function runLive() {
    const specs = domainSpecs();
    if (!specs.length) { toast("Add at least one domain", "warning"); return; }
    const o = opts();
    const hosts = hostList();
    // DNS-only probe of www.<domain> for each owned domain (no HTTP for auto hosts).
    const allHosts = [...hosts];
    const known = new Set(hosts.map((h) => h.host));
    autoHosts = specs.filter((s) => !known.has("www." + s.domain)).map((s) => ({ host: "www." + s.domain, types: [], target: null, source: "auto" }));
    allHosts.push(...autoHosts);
    const lookOwners = specs.filter((s) => (flags.get(s.domain) || {}).look).map((s) => s.domain);
    const tasks = [];
    const owned = new Set(specs.map((s) => s.domain));
    let candCount = 0;
    for (const s of specs) tasks.push(() => fetchDomain(s.domain, o));
    for (const h of allHosts.slice(0, LIMITS.maxHosts)) tasks.push(() => fetchHost(h, o));
    const rdapLeft = { n: 150 };
    for (const owner of lookOwners) {
      lookalikes[owner] = { at: new Date().toISOString(), results: {} };
      for (const c of generateLookalikes(owner, { keywords: keywords(), max: o.maxCandidates })) {
        if (owned.has(c.domain)) continue;
        candCount++;
        tasks.push(() => fetchCandidate(owner, c.domain, o, rdapLeft));
      }
    }
    previous = (store.get(RUNS_KEY, []) || []).slice(-1)[0] || null;
    running = true; cancelled = false;
    $("run").disabled = true; $("cancel").disabled = false; $("regrade").disabled = true; $("example").disabled = true;
    const prog = $("prog"), bar = prog.firstElementChild;
    prog.style.display = "block"; bar.style.width = "0%";
    let done = 0;
    const label = specs.length + " domain(s), " + allHosts.length + " hostname(s)" + (candCount ? ", " + candCount + " lookalike candidate(s)" : "");
    $("status").textContent = "Checking " + label + "...";
    const started = Date.now();
    await pool(tasks, o.concurrency, () => {
      done++;
      bar.style.width = Math.round((done / tasks.length) * 100) + "%";
      if (done % 3 === 0 || done === tasks.length) $("status").textContent = "Checked " + done + " of " + tasks.length + " items (" + label + ") - " + Math.round((Date.now() - started) / 1000) + "s";
    });
    running = false;
    $("cancel").disabled = true; $("example").disabled = false;
    if (cancelled) { $("status").textContent = "Cancelled after " + done + " of " + tasks.length + " items. Partial results are graded below; unchecked items are listed as skipped."; toast("Run cancelled", "warning"); }
    await grade(true);
    $("run").disabled = false; $("regrade").disabled = false;
    prog.style.display = "none";
    renderFlags();
  }

  async function grade(storeRun) {
    const o = opts();
    const dataset = isExample && exampleData
      ? { ...exampleData.dataset, keywords: keywords().length ? keywords() : exampleData.dataset.keywords }
      : { domains: domainSpecs(), hosts: hostList().concat(autoHosts.filter((h) => hostObs[h.host])), keywords: keywords(), observations, hostObs, lookalikes, previous };
    const run = { ...o };
    if (isExample) run.now = exampleData.now;
    else run.now = new Date().toISOString();
    try {
      result = await runInWorker(ENGINE, "analyze", [dataset, run], { onProgress: () => {} });
    } catch (e) { toast("Grading failed: " + ((e && e.message) || e), "error"); return; }
    if (storeRun && !isExample && !cancelled) {
      const runs = (store.get(RUNS_KEY, []) || []).concat([snapshotOf(result)]).slice(-12);
      if (!store.set(RUNS_KEY, runs)) toast("Could not store this run in browser storage; changes will not be tracked", "warning");
    }
    if (!isExample && !cancelled) $("status").textContent = "Done at " + result.meta.now.replace("T", " ").slice(0, 19) + " UTC. " + result.summary.findings + " finding(s)." + (result.meta.previousAt ? " Compared with the run at " + result.meta.previousAt.replace("T", " ").slice(0, 16) + " UTC." : "");
    render();
  }

  $("run").addEventListener("click", () => { if (!running) runLive(); });
  $("cancel").addEventListener("click", () => { cancelled = true; $("cancel").disabled = true; $("status").textContent = "Cancelling after in-flight requests..."; });
  $("regrade").addEventListener("click", () => grade(false));
  $("example").addEventListener("click", async () => {
    exampleData = exampleDataset();
    isExample = true;
    $("domains").value = exampleData.domainsText; $("hosts").value = ""; $("kw").value = "";
    const parsed = parseInput([exampleData.zoneFile]);
    zoneFiles = parsed.files; zoneHosts = parsed.hosts; zoneDomains = [];
    flags.clear(); flags.set("darknode.test.darknode.ai", { role: "auto", look: true });
    observations = exampleData.dataset.observations; hostObs = exampleData.dataset.hostObs; lookalikes = exampleData.dataset.lookalikes; previous = exampleData.dataset.previous;
    renderFiles(); renderFlags();
    $("run").disabled = true; $("regrade").disabled = false;
    $("status").textContent = "Synthetic example: 6 domains under test.darknode.ai with precomputed DNS, RDAP and CT answers (reference date " + exampleData.now.slice(0, 10) + "). No network calls are made; edit the domain list to leave the example.";
    await grade(false);
    toast("Synthetic example loaded", "info");
  });
  $("clear").addEventListener("click", async () => {
    const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Clear inputs and results?", "Stored run history for this workspace is kept.") : true;
    if (!ok) return;
    $("domains").value = ""; $("hosts").value = ""; $("kw").value = "";
    zoneFiles = []; zoneHosts = []; zoneDomains = []; flags.clear(); result = null;
    leaveExample(); $("status").textContent = ""; saveDraft();
    renderFiles(); renderFlags(); $("kpis").innerHTML = ""; $("tabs").innerHTML = ""; $("panel").innerHTML = ""; $("exports").innerHTML = ""; $("skipped").textContent = ""; $("drawer").style.display = "none"; $("regrade").disabled = true;
  });

  // ---- results
  function render() {
    const r = result;
    if (!r) return;
    const s = r.summary;
    const grades = ["A", "B", "C", "D", "F"].map((g) => g + " " + (s.grades[g] || 0)).join(" / ");
    $("kpis").innerHTML = kpi(s.domains + (s.checked !== s.domains ? " (" + s.checked + " checked)" : ""), "domains") + kpi(grades, "grades A/B/C/D/F") +
      kpi(s.expiring30, "expiring < " + r.meta.thresholds.expiryWarnDays + "d") + kpi(s.dmarcEnforcingPct == null ? "n/a" : s.dmarcEnforcingPct + "%", "DMARC enforcing") +
      kpi(s.takeoverCandidates, "takeover candidates") + kpi(s.lookalikesRegistered + " / " + s.lookalikesChecked, "lookalikes registered / checked") +
      kpi(s.findings, "findings") + kpi((s.bySeverity.critical || 0) + " / " + (s.bySeverity.high || 0), "critical / high");
    const tabs = [["findings", "Findings (" + r.findings.length + ")"], ["domains", "Domains"], ["mail", "Mail auth"], ["subdomains", "Subdomains (" + r.tables.subdomains.length + ")"], ["lookalikes", "Lookalikes (" + s.lookalikesRegistered + ")"], ["changes", "Changes (" + r.tables.changes.length + ")"], ["fingerprints", "Takeover fingerprints"]];
    $("tabs").innerHTML = tabs.map(([k, l]) => '<button class="' + P + "-tab" + (tab === k ? " on" : "") + '" data-tab="' + k + '">' + esc(l) + "</button>").join("");
    $("tabs").querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; $("drawer").style.display = "none"; render(); }));
    $("skipped").textContent = r.skipped.length ? "Skipped or limited: " + r.skipped.map((k) => k.check + " (" + k.reason + ")").join("; ") : "";
    renderPanel();
    renderExports();
  }

  function renderExports() {
    const r = result, ex = $("exports");
    ex.innerHTML = ["csv:Findings CSV", "json:Full results JSON", "txt:Summary TXT", "fix:DNS fix list TXT", "look:Lookalikes CSV"].map((x) => { const [k, l] = x.split(":"); return '<button class="' + P + '-btn" data-x="' + k + '">' + l + "</button>"; }).join("");
    const stamp = () => TOOL_ID + "-" + fileStamp();
    ex.querySelector('[data-x="csv"]').addEventListener("click", () => download(stamp() + "-findings.csv", findingsToCsv(r.findings), "text/csv"));
    ex.querySelector('[data-x="json"]').addEventListener("click", () => download(stamp() + ".json", toJson({ ...r, sample: isExample }), "application/json"));
    ex.querySelector('[data-x="txt"]').addEventListener("click", () => download(stamp() + "-summary.txt", summaryText(r) + "\n\nSeverity totals: " + JSON.stringify(summarize(r.findings).bySeverity) + (isExample ? "\n\nSYNTHETIC EXAMPLE - not real data." : ""), "text/plain"));
    ex.querySelector('[data-x="fix"]').addEventListener("click", () => download(stamp() + "-dns-fixes.txt", dnsFixList(r), "text/plain"));
    ex.querySelector('[data-x="look"]').addEventListener("click", () => download(stamp() + "-lookalikes.csv", lookalikesToCsv(r.tables.lookalikes), "text/csv"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: isExample ? "synthetic example" : "domain portfolio " + (r.meta.now || "").slice(0, 10) });
  }

  function bindRows(panel, rows, onPick) {
    panel.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => onPick(rows[Number(tr.dataset.i)])));
  }
  function drawer(title, html) {
    const d = $("drawer");
    d.style.display = "block";
    d.innerHTML = '<div class="' + P + '-card"><button class="' + P + "-btn " + P + '-x" id="' + P + '-dx">Close</button><h3>' + esc(title) + "</h3>" + html + "</div>";
    $("dx").addEventListener("click", () => { d.style.display = "none"; });
    d.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  function renderPanel() {
    const r = result, panel = $("panel");
    if (tab === "findings") {
      const keyFns = { severity: (f) => SEV_ORDER[f.severity], title: (f) => f.title, confidence: (f) => f.confidence, category: (f) => f.category, evidence: (f) => -(f.evidenceCount || 0) };
      const list = r.findings.slice().sort((a, b) => { const x = keyFns[sortKey](a), y = keyFns[sortKey](b); return (x < y ? -1 : x > y ? 1 : 0) * sortDir; });
      if (!list.length) { panel.innerHTML = '<div class="' + P + '-list"><div class="' + P + '-empty">No findings. ' + (r.summary.checked ? "Every graded check passed or was informational." : "Run checks to fetch live results.") + "</div></div>"; return; }
      const th = (k, l) => '<th data-k="' + k + '">' + l + (sortKey === k ? (sortDir > 0 ? " (asc)" : " (desc)") : "") + "</th>";
      panel.innerHTML = '<div class="' + P + '-list"><table><thead><tr>' + th("severity", "Severity") + th("title", "Finding") + th("confidence", "Confidence") + th("category", "Category") + "<th>Controls</th>" + th("evidence", "Evidence") + "</tr></thead><tbody>" +
        list.map((f, i) => '<tr data-i="' + i + '"><td>' + pill(f.severity) + '</td><td class="wide"><b>' + esc(f.title) + "</b><div>" + esc(f.description) + "</div></td><td>" + esc(f.confidence) + "</td><td>" + esc(f.category) + "</td><td>" +
          f.controls.map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</td><td>" + esc(f.evidenceCount) + "</td></tr>").join("") + "</tbody></table></div>";
      panel.querySelectorAll("th[data-k]").forEach((h) => h.addEventListener("click", () => { const k = h.dataset.k; sortDir = sortKey === k ? -sortDir : 1; sortKey = k; renderPanel(); }));
      bindRows(panel, list, (f) => drawer(f.title, '<p>' + pill(f.severity) + " " + esc(f.confidence) + " - " + esc(f.description) + "</p><p><b>Fix:</b> " + esc(f.recommendation) + "</p><p>" + f.controls.map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</p>" +
        "<p class=\"" + P + "-help\">Showing " + f.evidence.length + " of " + f.evidenceCount + " evidence row(s).</p>" + rowsTable(f.evidence)));
      return;
    }
    if (tab === "domains") {
      const rows = r.tables.domains;
      panel.innerHTML = '<div class="' + P + '-list"><table><thead><tr><th>Domain</th><th>Grade</th><th>Role</th>' + CHECK_COLS.map(([, l]) => "<th>" + l + "</th>").join("") + "<th>Errors</th></tr></thead><tbody>" +
        rows.map((d, i) => '<tr data-i="' + i + '"><td class="' + P + '-mono">' + esc(d.domain) + '</td><td><span class="' + P + "-grade " + esc(d.grade) + '">' + esc(d.grade) + "</span></td><td>" + esc(d.roleLabel || d.role) + "</td>" +
          CHECK_COLS.map(([k]) => "<td>" + st(d.checks[k] ? d.checks[k].status : "unchecked") + "</td>").join("") + "<td>" + esc(d.errors || 0) + "</td></tr>").join("") + "</tbody></table></div>" +
        '<p class="' + P + '-help">Click a domain for every check, its detail and the raw DNS answers. Network errors are shown as "error" and never counted as a pass or a fail. Grade: 100 minus severity points of the domain\'s own findings (critical 40, high 25, medium 12, low 5), A 90+, B 80+, C 65+, D 50+.</p>';
      bindRows(panel, rows, (d) => {
        const ob = observations[d.domain];
        const raw = ob && ob.dns ? Object.entries(ob.dns).map(([k, j]) => ({ query: k, name: j && j.Question && j.Question[0] ? j.Question[0].name : "", status: dohStatus(j), AD: j && j.AD ? "yes" : "", via: j && j._via ? j._via : "", answers: j && j.error ? j.error : (j && j.Answer ? j.Answer.map((a) => a.data).join(" | ") : "") })) : [];
        const checks = Object.entries(d.checks).map(([k, c]) => ({ check: k, status: c.status, detail: c.detail }));
        drawer(d.domain + " - grade " + d.grade, rowsTable(checks, ["check", "status", "detail"]) + (d.rdap ? '<h3 style="margin-top:12px">Registration (RDAP)</h3>' + rowsTable([{ registrar: d.rdap.registrar, created: d.rdap.created, expires: d.rdap.expires, daysLeft: d.rdap.daysLeft, status: (d.rdap.statuses || []).join(", ") }]) : "") +
          '<h3 style="margin-top:12px">Raw DNS answers</h3>' + (raw.length ? rowsTable(raw, ["query", "name", "status", "AD", "via", "answers"]) : '<p class="' + P + '-help">No live answers stored for this domain.</p>') +
          (ob && ob.mtaStsPolicy ? '<h3 style="margin-top:12px">MTA-STS policy</h3><pre>' + esc(ob.mtaStsPolicy.error || ("HTTP " + (ob.mtaStsPolicy.status || "") + "\n" + ob.mtaStsPolicy.body)) + "</pre>" : "") +
          (ob && ob.spf && Object.keys(ob.spf).length ? '<h3 style="margin-top:12px">SPF include lookups</h3>' + rowsTable(Object.entries(ob.spf).sort().map(([k, j]) => ({ include: k, status: dohStatus(j), txt: txtStrings(j).join(" | ") }))) : ""));
      });
      return;
    }
    if (tab === "mail") {
      const rows = r.tables.domains.map((d) => ({ domain: d.domain, role: d.roleLabel || d.role, MX: d.mail ? (d.mail.nullMx ? "null MX" : d.mail.mx) : "", SPF: d.mail ? d.mail.spf : "", "SPF all": d.mail ? d.mail.spfAll : "", "SPF lookups": d.mail && d.mail.spfLookups != null ? d.mail.spfLookups + (d.mail.spfComplete ? "" : "+") : "", DMARC: d.mail ? d.mail.dmarc : "", policy: d.mail ? d.mail.dmarcPolicy : "", pct: d.mail && d.mail.dmarcPct != null ? d.mail.dmarcPct : "", "MTA-STS": d.mail ? d.mail.mtaStsMode : "", "TLS-RPT": d.mail ? (d.mail.tlsRpt ? "yes" : "no") : "", BIMI: d.mail ? (d.mail.bimi ? "yes" : "no") : "" }));
      panel.innerHTML = rowsTable(rows) + '<p class="' + P + '-help">SPF lookups count include, a, mx, ptr, exists and redirect across nested includes (RFC 7208 limit 10); a trailing + means some includes could not be resolved, so the true count is at least that. DKIM cannot be verified without knowing your selectors and is not graded.</p>';
      return;
    }
    if (tab === "subdomains") {
      const rows = r.tables.subdomains.slice().sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9) || (a.host < b.host ? -1 : 1));
      if (!rows.length) { panel.innerHTML = '<div class="' + P + '-list"><div class="' + P + '-empty">No hostnames. Drop a zone export or list hostnames above.</div></div>'; return; }
      panel.innerHTML = '<div class="' + P + '-list"><table><thead><tr><th>Severity</th><th>Host</th><th>Source</th><th>Target</th><th>Provider</th><th>Live</th><th>Verdict</th></tr></thead><tbody>' +
        rows.map((h, i) => '<tr data-i="' + i + '"><td>' + (h.severity ? pill(h.severity) : "-") + '</td><td class="' + P + '-mono">' + esc(h.host) + "</td><td>" + esc(h.source) + '</td><td class="' + P + '-mono">' + esc(h.target) + "</td><td>" + esc(h.provider ? h.provider + " (" + h.providerStatus + ")" : "") + "</td><td>" + st(h.liveStatus) + '</td><td class="wide">' + esc(h.verdict) + (h.signal ? "<div>" + esc(h.signal) + "</div>" : "") + "</td></tr>").join("") + "</tbody></table></div>" +
        '<p class="' + P + '-help">Dangling A/AAAA records pointing into cloud IP ranges are not checked: whether an IP still belongs to you cannot be verified from outside. www.&lt;domain&gt; is probed over DNS only. HTTP fingerprints are fetched only for hostnames you supplied.</p>';
      bindRows(panel, rows, (h) => {
        const ob = hostObs[h.host] || {};
        drawer(h.host, rowsTable([{ verdict: h.verdict, signal: h.signal, target: h.target, provider: h.provider, providerStatus: h.providerStatus, zoneTypes: h.zoneTypes, zoneTarget: h.zoneTarget }]) +
          '<h3 style="margin-top:12px">Raw DNS answer (A)</h3><pre>' + esc(ob.A ? JSON.stringify(ob.A, null, 2) : "not fetched") + "</pre>" +
          (ob.http ? '<h3 style="margin-top:12px">HTTP response (first 2,000 characters)</h3><pre>' + esc(ob.http.error || ("HTTP " + ob.http.status + "\n" + String(ob.http.body || "").slice(0, 2000))) + "</pre>" : ""));
      });
      return;
    }
    if (tab === "lookalikes") {
      const all = r.tables.lookalikes;
      const owners = [...new Set(all.map((l) => l.owner))].sort();
      if (!owners.length) { panel.innerHTML = '<div class="' + P + '-list"><div class="' + P + '-empty">No lookalike checks yet. Tick "Check lookalikes" for a domain in Settings, then Run checks.</div></div>'; return; }
      const list = all.filter((l) => (!lookFilter.owner || l.owner === lookFilter.owner) && (lookFilter.status === "all" || l.status === lookFilter.status));
      const shown = list.slice(0, 500);
      panel.innerHTML = '<div class="' + P + '-filters"><label>Domain <select id="' + P + '-lo"><option value="">all</option>' + owners.map((o) => "<option" + (o === lookFilter.owner ? " selected" : "") + ">" + esc(o) + "</option>").join("") + '</select></label><label>Status <select id="' + P + '-ls">' +
        ["registered", "unregistered", "error", "unchecked", "owned", "all"].map((s) => "<option" + (s === lookFilter.status ? " selected" : "") + ">" + s + "</option>").join("") + "</select></label><span>" + list.length + " candidate(s)" + (list.length > 500 ? ", first 500 shown (export CSV for all)" : "") + "</span></div>" +
        (shown.length ? '<div class="' + P + '-list"><table><thead><tr><th>Lookalike</th><th>Kind</th><th>Status</th><th>MX</th><th>Web</th><th>Created</th><th>Registrar</th><th>Of</th></tr></thead><tbody>' +
          shown.map((l, i) => '<tr data-i="' + i + '"><td class="' + P + '-mono">' + esc(l.display) + (l.display !== l.domain ? "<div>" + esc(l.domain) + "</div>" : "") + "</td><td>" + esc(l.kind) + "</td><td>" + st(l.status === "registered" ? "fail" : l.status === "unregistered" ? "pass" : l.status === "error" ? "error" : "na") + " " + esc(l.status) + "</td><td>" + (l.mx ? "yes" : "") + "</td><td>" + (l.web ? "yes" : "") + "</td><td>" + esc(l.created ? l.created.slice(0, 10) + (l.ageDays != null ? " (" + l.ageDays + "d)" : "") : "") + (l.newlyRegistered ? " <b>new</b>" : "") + "</td><td>" + esc(l.registrar) + '</td><td class="' + P + '-mono">' + esc(l.owner) + "</td></tr>").join("") + "</tbody></table></div>"
          : '<div class="' + P + '-list"><div class="' + P + '-empty">No candidates with this status.</div></div>') +
        '<p class="' + P + '-help">Registered = the name has NS, A or MX records (NXDOMAIN means it does not resolve and is most likely unregistered). Creation dates come from RDAP (first 150 registered candidates per run). "owned" = also in your own domain list (a defensive registration).</p>';
      $("lo").addEventListener("change", (e) => { lookFilter.owner = e.target.value; renderPanel(); });
      $("ls").addEventListener("change", (e) => { lookFilter.status = e.target.value; renderPanel(); });
      bindRows(panel, shown, (l) => {
        const ob = (lookalikes[l.owner] && lookalikes[l.owner].results[l.domain]) || null;
        drawer(l.display, rowsTable([{ lookalike: l.domain, unicode: l.display, kind: l.kind, status: l.status, mx: l.mxHosts, addresses: l.addrs, created: l.created, registrar: l.registrar }]) +
          (ob ? '<h3 style="margin-top:12px">Raw answers</h3>' + rowsTable(["NS", "A", "MX"].filter((k) => ob[k]).map((k) => ({ query: k, status: dohStatus(ob[k]), answers: ob[k].error || (ob[k].Answer || []).map((a) => a.data).join(" | ") })), ["query", "status", "answers"]) : ""));
      });
      return;
    }
    if (tab === "changes") {
      const rows = r.tables.changes;
      panel.innerHTML = (r.meta.previousAt ? '<p class="' + P + '-help">Compared with the run at ' + esc(r.meta.previousAt.replace("T", " ").slice(0, 16)) + " UTC" + (isExample ? " (synthetic)" : "") + ".</p>" : '<p class="' + P + '-help">No previous run stored for this workspace yet; the next run will be compared with this one.</p>') +
        (rows.length ? rowsTable(rows, ["kind", "domain", "check", "from", "to"]) : '<div class="' + P + '-list"><div class="' + P + '-empty">No changes.</div></div>');
      return;
    }
    if (tab === "fingerprints") {
      panel.innerHTML = rowsTable(TAKEOVER_FINGERPRINTS.map((f) => ({ provider: f.provider, "CNAME pattern": f.cname.join("  "), status: f.status, "NXDOMAIN signal": f.nxdomain ? "yes" : "no", "HTTP fingerprint": f.http.join(" | ") }))) +
        '<p class="' + P + '-help">Provider classification follows public knowledge of the can-i-take-over-xyz project at the time this table was written; where uncertain it is marked "edge case". Providers change their rules, so confirm before relying on a verdict. Severity: fingerprint matched on a "vulnerable" provider = critical; NXDOMAIN to a cloud service or a matched "edge case" provider = high; NXDOMAIN to an unknown target = medium.</p>';
    }
  }

  renderFlags();
}
