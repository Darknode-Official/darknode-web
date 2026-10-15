// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// External Posture Scorecard — one domain, run live checks (HTTPS + redirect,
// security headers, SPF/DMARC, security.txt, certificate transparency) and roll
// them into one executive posture grade with a per-category breakdown and a
// remediation list. Scoring is pure and tested (posture-engine.js); this module
// performs the real network I/O through the Darknode proxy and public DoH.
//
//   renderPosture(main) -> void

import { scorePosture, newestCert } from "/js/dataprotect/posture-engine.js?v=20261014d";
import { fetchCertRows } from "/js/dataprotect/ct-fetch.js?v=20261013i";
import { dnFetch } from "/js/net.js";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.showToast || (() => {}))(m); } catch (_) {} };

const GRADE_C = { A: "#2f9e56", B: "#4c9a2a", C: "#b58100", D: "#d9480f", F: "#b00020", "N/A": "#667085" };
const ST = {
  pass: { c: "#2f9e56", t: "Pass" }, warn: { c: "#b58100", t: "Warn" },
  fail: { c: "#b00020", t: "Fail" }, info: { c: "#2f7d9e", t: "Info" }, na: { c: "#8a93a6", t: "N/A" },
};

let injected = false;
function injectStyle() {
  if (injected) return; injected = true;
  const st = document.createElement("style"); st.id = "ps-css";
  st.textContent = `
  .ps{width:100%;font-size:14px;line-height:1.5}
  .ps .ps-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .ps h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .ps .ps-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .ps .ps-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:74ch}
  .ps .ps-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:16px}
  .ps .ps-form{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .ps input{flex:1;min-width:220px;font:inherit;font-size:.9rem;padding:9px 12px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--bg,#fbfcfe);color:var(--tx,#1a2230);box-sizing:border-box}
  .ps .ps-btn{appearance:none;font:inherit;font-size:.86rem;font-weight:600;border:1px solid #2552c6;background:#2552c6;color:#fff;padding:9px 18px;border-radius:8px;cursor:pointer}
  .ps .ps-btn:hover{background:#1c42a6}
  .ps .ps-btn:disabled{opacity:.55;cursor:default}
  .ps .ps-hint{color:var(--mut,#667085);font-size:.78rem;margin:8px 2px 0}
  .ps .ps-score{display:flex;align-items:center;gap:22px;flex-wrap:wrap}
  .ps .ps-ring{width:92px;height:92px;border-radius:50%;display:grid;place-items:center;flex:0 0 auto;background:conic-gradient(var(--g) calc(var(--p)*1%),var(--line,#e9ecf3) 0)}
  .ps .ps-ring .in{width:72px;height:72px;border-radius:50%;background:var(--card,#fff);display:grid;place-items:center;font-size:1.7rem;font-weight:800}
  .ps .ps-gw{min-width:200px}
  .ps .ps-gw .g{font-size:1.1rem;font-weight:700}
  .ps .ps-chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
  .ps .ps-chip{font-size:.8rem;font-weight:600;padding:3px 10px;border:1px solid var(--line,#e6e8ee);border-radius:999px}
  .ps .ps-cat{border:1px solid var(--line,#e6e8ee);border-radius:12px;margin-bottom:12px;overflow:hidden}
  .ps .ps-cat>h3{display:flex;align-items:center;gap:10px;font-size:.92rem;margin:0;padding:12px 16px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee)}
  .ps .ps-cat>h3 .sc{margin-left:auto;font-size:.8rem;color:var(--mut,#667085);font-weight:600}
  .ps .ps-check{display:flex;gap:12px;padding:11px 16px;border-bottom:1px solid var(--line,#eef0f4)}
  .ps .ps-check:last-child{border-bottom:0}
  .ps .ps-pill{flex:0 0 auto;align-self:flex-start;font-size:.68rem;font-weight:700;color:#fff;padding:2px 8px;border-radius:999px;min-width:40px;text-align:center}
  .ps .ps-cn{font-weight:600}
  .ps .ps-cd{color:var(--tx,#1a2230);font-size:.86rem}
  .ps .ps-ca{color:var(--mut,#667085);font-size:.8rem;margin-top:2px}
  .ps .ps-actions li{margin:5px 0}
  .ps .ps-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
  .ps .ps-btn.sm{background:var(--card,#fff);color:var(--tx,#1a2230);border-color:var(--line,#d7dbe3);font-size:.8rem;padding:6px 12px}
  .ps .ps-btn.sm:hover{background:var(--bg,#f7f8fb)}
  .ps .ps-spin{display:inline-block;width:15px;height:15px;border:2px solid rgba(37,82,198,.3);border-top-color:#2552c6;border-radius:50%;animation:psSpin .7s linear infinite;vertical-align:-3px;margin-right:7px}
  @keyframes psSpin{to{transform:rotate(360deg)}}
  .ps .ps-warn{background:var(--acc-soft,rgba(181,129,0,.08));border:1px solid var(--line,#e6e8ee);border-left:3px solid #b58100;border-radius:8px;padding:10px 14px;color:var(--tx,#1a2230);font-size:.82rem;margin-top:10px}
  `;
  document.head.appendChild(st);
}

function cleanDomain(raw) {
  let d = String(raw || "").trim();
  d = d.replace(/^[a-z]+:\/\//i, "").replace(/\/.*$/, "").replace(/:\d+$/, "").replace(/^www\./i, "");
  return d.toLowerCase();
}
const validDomain = (d) => /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(d);

// Public DoH TXT (Cloudflare, Google fallback). Returns array of TXT strings.
async function dohTXT(name) {
  const decode = (j) => ((j && j.Answer) || []).filter((a) => a.type === 16 || a.type === "TXT")
    .map((a) => String(a.data || "").replace(/^"|"$/g, "").replace(/"\s*"/g, ""));
  const urls = [
    "https://cloudflare-dns.com/dns-query?type=TXT&name=" + encodeURIComponent(name),
    "https://dns.google/resolve?type=TXT&name=" + encodeURIComponent(name),
  ];
  for (const u of urls) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 8000);
      const res = await fetch(u, { headers: { Accept: "application/dns-json" }, signal: ctrl.signal });
      clearTimeout(t);
      if (res.ok) return decode(await res.json());
    } catch (_) {}
  }
  return [];
}

async function fetchCert(domain) {
  const rows = await fetchCertRows(domain);
  return rows.length ? newestCert(rows) : null;
}

async function fetchSecurityTxt(domain) {
  for (const path of ["/.well-known/security.txt", "/security.txt"]) {
    try {
      const r = await dnFetch("https://" + domain + path, { raw: true, timeout: 12000 });
      if (r.status === 200 && /contact\s*:/i.test(r.body || "")) return { present: true };
    } catch (_) {}
  }
  return { present: false };
}

// Common DKIM selectors used by major mail providers / ESPs. We can only probe
// well-known names over DoH — a miss is NOT proof that DKIM is absent (selectors
// are arbitrary), which the engine reports honestly as "unknown".
const DKIM_SELECTORS = [
  "google", "default", "selector1", "selector2", "k1", "k2", "k3",
  "dkim", "mail", "s1", "s2", "mandrill", "mxvault", "zoho", "fm1",
  "fm2", "fm3", "protonmail", "scph0920", "pm", "amazonses", "sig1",
];
async function probeDkim(domain) {
  const out = await Promise.all(DKIM_SELECTORS.map(async (selector) => {
    try {
      const txts = await dohTXT(selector + "._domainkey." + domain);
      const present = txts.some((t) => /v\s*=\s*dkim1|(^|;)\s*k\s*=|(^|;)\s*p\s*=/i.test(String(t)));
      return { selector, present };
    } catch (_) { return { selector, present: false }; }
  }));
  return out;
}

// MTA-STS: the _mta-sts TXT record plus the policy file served from the
// mta-sts.<domain> host (/.well-known/mta-sts.txt).
async function fetchMtaSts(domain) {
  const txts = await dohTXT("_mta-sts." + domain);
  let policy = null;
  if (txts.some((t) => /^v=stsv1\b/i.test(String(t).trim()))) {
    try {
      const r = await dnFetch("https://mta-sts." + domain + "/.well-known/mta-sts.txt", { raw: true, timeout: 12000 });
      if (r.status === 200 && /mode\s*:/i.test(r.body || "")) policy = r.body;
    } catch (_) {}
  }
  return { txts, policy };
}

export function renderPosture(main) {
  injectStyle();
  main.innerHTML = `
  <div class="ps">
    <div class="ps-hd"><h1>External Posture Scorecard</h1><span class="ps-tag">POSTURE</span></div>
    <p class="ps-sub">Enter a domain to run live transport, header, email-authentication, certificate and disclosure checks, rolled into one executive posture grade with prioritised fixes.</p>
    <div class="ps-card">
      <div class="ps-form">
        <input id="psIn" type="text" placeholder="example.com" autocomplete="off" spellcheck="false" />
        <button class="ps-btn" id="psRun">Run scorecard</button>
      </div>
      <p class="ps-hint">Checks run live against the public internet through the Darknode proxy and public DNS. Only publicly observable signals are read; no intrusive scanning.</p>
    </div>
    <div id="psOut"></div>
  </div>`;

  const inp = main.querySelector("#psIn");
  const btn = main.querySelector("#psRun");
  const out = main.querySelector("#psOut");

  const run = async () => {
    const domain = cleanDomain(inp.value);
    if (!validDomain(domain)) { toast("Enter a valid domain, e.g. example.com"); return; }
    btn.disabled = true;
    out.innerHTML = `<div class="ps-card"><span class="ps-spin"></span>Running live checks against <b>${esc(domain)}</b>…</div>`;

    const [httpsP, httpP, spfP, dmarcP, certP, stxtP, dkimP, mtaP, tlsRptP] = await Promise.allSettled([
      dnFetch("https://" + domain, { timeout: 14000 }),
      dnFetch("http://" + domain, { timeout: 12000 }),
      dohTXT(domain),
      dohTXT("_dmarc." + domain),
      fetchCert(domain),
      fetchSecurityTxt(domain),
      probeDkim(domain),
      fetchMtaSts(domain),
      dohTXT("_smtp._tls." + domain),
    ]);
    const val = (p) => (p.status === "fulfilled" ? p.value : null);
    const https = val(httpsP), http = val(httpP);

    if (!https && !http) {
      out.innerHTML = `<div class="ps-card"><b>Could not reach ${esc(domain)}.</b><p class="ps-hint">The host did not respond over HTTP or HTTPS. Check the domain and try again.</p></div>`;
      btn.disabled = false; return;
    }

    const headers = (https && https.headers) || (http && http.headers) || {};
    const httpReached = !!http;
    const httpFinal = http ? (http.finalUrl || http.url || "") : "";
    const httpsFinal = https ? (https.finalUrl || https.url || "") : "";
    const input = {
      domain,
      requestedUrl: httpReached ? "http://" + domain : "https://" + domain,
      // Grade HTTPS on whether the HTTPS endpoint actually responded, and the
      // redirect separately on where the HTTP endpoint ended up.
      httpsOk: !!https,
      httpTested: httpReached,
      httpRedirectsToHttps: httpReached ? /^https:/i.test(httpFinal) : false,
      finalUrl: httpsFinal || httpFinal,
      headers,
      // Set-Cookie flags come straight off the real response headers (the proxy
      // preserves them); the engine folds cookie security into the headers score.
      spfTxts: val(spfP) || [], dmarcTxts: val(dmarcP) || [],
      dkimSelectors: val(dkimP) || [],
      mtaStsTxts: (val(mtaP) && val(mtaP).txts) || [], mtaStsPolicy: (val(mtaP) && val(mtaP).policy) || null,
      tlsRptTxts: val(tlsRptP) || [],
      cert: val(certP), securityTxt: val(stxtP) || { present: false },
      now: Date.now(),
    };
    renderReport(out, scorePosture(input), run);
    btn.disabled = false;
  };

  btn.addEventListener("click", run);
  inp.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
  inp.focus();
}

function renderReport(out, res, rerun) {
  const gc = GRADE_C[res.grade] || "#667085";
  const cats = res.categories.map((cat) => {
    const checks = cat.checks.map((c) => `
      <div class="ps-check">
        <span class="ps-pill" style="background:${ST[c.status].c}">${ST[c.status].t}</span>
        <div><div class="ps-cn">${esc(c.name)}</div><div class="ps-cd">${esc(c.detail)}</div>${c.advice ? `<div class="ps-ca">${esc(c.advice)}</div>` : ""}</div>
      </div>`).join("");
    return `<div class="ps-cat"><h3>${esc(cat.label)}<span class="sc">${cat.score == null ? "not assessed" : cat.score + " / 100"} · weight ${cat.weight}%</span></h3>${checks}</div>`;
  }).join("");

  const actions = res.topActions.length
    ? `<div class="ps-card"><h3 style="margin:0 0 8px;font-size:.95rem">Top actions</h3><ol class="ps-actions">${res.topActions.map((a) => `<li><b>${esc(a.category)} — ${esc(a.name)}.</b> ${esc(a.advice || "Address this finding.")}</li>`).join("")}</ol></div>`
    : `<div class="ps-card" style="color:#2f9e56;font-weight:600">No failing or warning checks — strong external posture.</div>`;

  out.innerHTML = `
  <div class="ps-card">
    <div class="ps-score">
      <div class="ps-ring" style="--g:${gc};--p:${res.score == null ? 0 : res.score}"><div class="in" style="color:${gc}">${res.grade}</div></div>
      <div class="ps-gw">
        <div class="g">${esc(res.domain)}</div>
        <div class="ps-hint" style="margin-top:2px">Posture score ${res.score == null ? "n/a" : res.score + " / 100"}</div>
        <div class="ps-chips">
          <span class="ps-chip" style="color:#2f9e56">${res.counts.pass} pass</span>
          <span class="ps-chip" style="color:#b58100">${res.counts.warn} warn</span>
          <span class="ps-chip" style="color:#b00020">${res.counts.fail} fail</span>
        </div>
      </div>
    </div>
    <div class="ps-warn">This scorecard reads publicly observable signals (headers, DNS, certificate transparency, security.txt). It is an external indicator, not a penetration test or an audit.</div>
    <div class="ps-row"><button class="ps-btn sm" id="psJson">Export report (JSON)</button></div>
  </div>
  ${actions}
  ${cats}`;

  out.querySelector("#psJson").addEventListener("click", () => {
    const report = { generated: new Date().toISOString(), tool: "Darknode External Posture Scorecard", domain: res.domain, grade: res.grade, score: res.score, counts: res.counts, categories: res.categories, topActions: res.topActions };
    try {
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = "posture-" + res.domain + ".json";
      document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
    } catch (_) { toast("Download blocked by the browser"); }
  });
}

export default renderPosture;
