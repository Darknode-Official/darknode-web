// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Phishing & URL Triage — paste a URL or a raw email (with headers) and get a
// risk read-out: live redirect unfurling, domain age, lookalike/homograph and
// obfuscation detection, email authentication alignment (SPF/DKIM/DMARC) and
// IOC extraction. Heuristics are pure and tested (phish-engine.js); live lookups
// (redirect chain, RDAP registration date, DNS) run through the proxy / DoH.
//
//   renderPhish(main) -> void

import {
  analyzeUrl, triageEmail, extractIOCs, parseEmailHeaders, registrableDomain, lookalike,
  defangText, refangText, buildTriageReport,
} from "/js/dataprotect/phish-engine.js?v=20261019f";
import { dnFetch, dnFetchJSON } from "/js/net.js";
import { attachSinkButton } from "../core/sink.js";
import { phishUrlFindings, phishEmailFindings } from "/js/dataprotect/dp-sink.js";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.showToast || (() => {}))(m); } catch (_) {} };

const SEVC = { critical: "#b00020", high: "#d9480f", medium: "#b58100", low: "#2f7d9e", info: "#2f9e56" };

let injected = false;
function injectStyle() {
  if (injected) return; injected = true;
  const st = document.createElement("style"); st.id = "phx-css";
  st.textContent = `
  .phx{width:100%;font-size:14px;line-height:1.5}
  .phx .phx-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .phx h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .phx .phx-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .phx .phx-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:74ch}
  .phx .phx-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:16px}
  .phx textarea{width:100%;font:inherit;font-size:.82rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;padding:11px 13px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--bg,#fbfcfe);color:var(--tx,#1a2230);box-sizing:border-box;min-height:120px;resize:vertical}
  .phx .phx-row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:12px}
  .phx .phx-hint{color:var(--mut,#667085);font-size:.78rem;margin:8px 2px 0}
  .phx .phx-seg{display:inline-flex;border:1px solid var(--line,#d7dbe3);border-radius:8px;overflow:hidden}
  .phx .phx-seg button{appearance:none;font:inherit;font-size:.8rem;font-weight:600;border:0;background:var(--card,#fff);color:var(--mut,#667085);padding:7px 14px;cursor:pointer;border-right:1px solid var(--line,#d7dbe3)}
  .phx .phx-seg button:last-child{border-right:0}
  .phx .phx-seg button.on{background:#2552c6;color:#fff}
  .phx .phx-btn{appearance:none;font:inherit;font-size:.86rem;font-weight:600;border:1px solid #2552c6;background:#2552c6;color:#fff;padding:9px 18px;border-radius:8px;cursor:pointer}
  .phx .phx-btn:hover{background:#1c42a6}
  .phx .phx-btn:disabled{opacity:.55;cursor:default}
  .phx .phx-btn.sm{background:var(--card,#fff);color:var(--tx,#1a2230);border-color:var(--line,#d7dbe3);font-size:.78rem;padding:5px 11px}
  .phx .phx-btn.sm:hover{background:var(--bg,#f7f8fb)}
  .phx .phx-verd{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
  .phx .phx-vdot{width:14px;height:14px;border-radius:50%;background:var(--c)}
  .phx .phx-vlabel{font-size:1.15rem;font-weight:700}
  .phx h3{font-size:.92rem;margin:0 0 10px}
  .phx .phx-reasons li{margin:5px 0}
  .phx .phx-sev{display:inline-block;font-size:.66rem;font-weight:700;color:#fff;padding:1px 7px;border-radius:999px;margin-right:6px;vertical-align:1px}
  .phx .phx-kv{display:grid;grid-template-columns:140px 1fr;gap:4px 12px;font-size:.84rem}
  .phx .phx-kv dt{color:var(--mut,#667085);font-weight:600}
  .phx .phx-kv dd{margin:0;overflow-wrap:anywhere}
  .phx .phx-hops{list-style:none;padding:0;margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}
  .phx .phx-hops li{padding:5px 0;border-bottom:1px dashed var(--line,#eef0f4);overflow-wrap:anywhere}
  .phx .phx-hops li:last-child{border-bottom:0}
  .phx .phx-chip{display:inline-block;font-size:.72rem;font-weight:600;padding:2px 9px;border-radius:999px;border:1px solid var(--line,#e6e8ee);margin:2px 4px 2px 0}
  .phx .phx-urlrow{border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 12px;margin-bottom:8px}
  .phx .phx-urlrow .u{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;overflow-wrap:anywhere;font-weight:600}
  .phx .phx-iocs code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.76rem;background:var(--bg,#f2f4f8);padding:1px 5px;border-radius:5px;margin:2px 4px 2px 0;display:inline-block;overflow-wrap:anywhere}
  .phx .phx-sp{display:inline-block;width:14px;height:14px;border:2px solid rgba(37,82,198,.3);border-top-color:#2552c6;border-radius:50%;animation:phxSpin .7s linear infinite;vertical-align:-2px;margin-right:7px}
  @keyframes phxSpin{to{transform:rotate(360deg)}}
  .phx .phx-fang pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;white-space:pre-wrap;overflow-wrap:anywhere;margin:0;max-height:320px;overflow:auto}
  .phx .phx-acts{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
  .phx .phx-warn{background:var(--acc-soft,rgba(181,129,0,.08));border:1px solid var(--line,#e6e8ee);border-left:3px solid #b58100;border-radius:8px;padding:10px 14px;color:var(--tx,#1a2230);font-size:.82rem;margin-top:12px}
  `;
  document.head.appendChild(st);
}

let MODE = "auto";
const SAMPLE_URL = "http://paypal.com.account-verify.ru/login?id=1";

export function renderPhish(main) {
  injectStyle();
  MODE = "auto"; // match the segmented control, which always renders with Auto-detect active
  main.innerHTML = `
  <div class="phx">
    <div class="phx-hd"><h1>Phishing &amp; URL Triage</h1><span class="phx-tag">TRIAGE</span></div>
    <p class="phx-sub">Paste a suspicious link or a full email (with headers). Links are unfurled live, domains checked for age and lookalikes, and email authentication is verified — with a plain-language risk read-out.</p>
    <div class="phx-card">
      <div class="phx-row" style="margin:0 0 10px">
        <span class="phx-seg" id="phxSeg">
          <button data-m="auto" class="on">Auto-detect</button>
          <button data-m="url">URL</button>
          <button data-m="email">Email</button>
        </span>
      </div>
      <textarea id="phxIn" placeholder="Paste a URL, or the full source of an email including its headers (From, Received, Authentication-Results, …)." spellcheck="false"></textarea>
      <div class="phx-row">
        <button class="phx-btn" id="phxRun">Analyze</button>
        <button class="phx-btn sm" id="phxSample">Load example</button>
        <button class="phx-btn sm" id="phxClear">Clear</button>
        <button class="phx-btn sm" id="phxDefang" title="Make every URL, IP, domain and email in the box safe to share">Defang</button>
        <button class="phx-btn sm" id="phxRefang" title="Turn hxxp / [.] / [@] back into live indicators">Refang</button>
      </div>
      <p class="phx-hint">Links are fetched server-side through the Darknode proxy (your browser never loads them). Reputation uses observable signals — redirects, registration date, DNS, lookalikes — not a malware verdict.</p>
    </div>
    <div id="phxFang"></div>
    <div id="phxOut"></div>
  </div>`;

  const $ = (s) => main.querySelector(s);
  const inp = $("#phxIn"), out = $("#phxOut");

  $("#phxSeg").addEventListener("click", (e) => {
    const b = e.target.closest("[data-m]"); if (!b) return;
    MODE = b.getAttribute("data-m");
    $("#phxSeg").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
  });
  $("#phxSample").addEventListener("click", () => { inp.value = SAMPLE_URL; run(); });
  $("#phxClear").addEventListener("click", () => { inp.value = ""; out.innerHTML = ""; $("#phxFang").innerHTML = ""; LAST = null; inp.focus(); });
  const fang = (fn, title) => {
    const text = inp.value; if (!text.trim()) { toast("Paste text to " + title.toLowerCase() + "."); return; }
    const res = fn(text);
    $("#phxFang").innerHTML = `<div class="phx-card phx-fang"><h3>${title}</h3><pre id="phxFangOut">${esc(res)}</pre><div class="phx-acts"><button class="phx-btn sm" id="phxFangCopy">Copy</button><button class="phx-btn sm" id="phxFangClose">Close</button></div></div>`;
    $("#phxFangCopy").addEventListener("click", () => copyText(res));
    $("#phxFangClose").addEventListener("click", () => { $("#phxFang").innerHTML = ""; });
  };
  $("#phxDefang").addEventListener("click", () => fang(defangText, "Defanged"));
  $("#phxRefang").addEventListener("click", () => fang(refangText, "Refanged"));
  out.addEventListener("click", (e) => {
    if (e.target.closest("#phxIocCopy") && LAST) copyText(defangText(iocLines(LAST.iocs)));
    if (e.target.closest("#phxReport") && LAST) exportReport(LAST);
  });
  $("#phxRun").addEventListener("click", run);

  function detectMode(text) {
    if (MODE !== "auto") return MODE;
    if (parseEmailHeaders(text).hasHeaders || /^\s*received\s*:/im.test(text)) return "email";
    return "url";
  }

  async function run() {
    const text = inp.value.trim();
    if (!text) { toast("Paste a URL or an email to analyze."); return; }
    const mode = detectMode(text);
    LAST = null;
    out.innerHTML = `<div class="phx-card"><span class="phx-sp"></span>Analyzing…</div>`;
    if (mode === "email") await runEmail(out, text);
    else await runUrl(out, text);
  }

  inp.focus();
}

// ---- defang + report export ----------------------------------------------

// The last completed triage, kept only so its report / IOCs can be exported.
let LAST = null;

function copyText(t) {
  try { navigator.clipboard.writeText(t).then(() => toast("Copied"), () => toast("Copy failed: select the text and copy it manually.")); }
  catch (_) { toast("Copy failed: select the text and copy it manually."); }
}

function iocLines(iocs) {
  return [["URLs", iocs.urls], ["Domains", iocs.domains], ["IPs", iocs.ips], ["Emails", iocs.emails], ["Hashes", iocs.hashes]]
    .filter(([, a]) => a && a.length).map(([k, a]) => k + ":\n" + a.join("\n")).join("\n\n");
}

async function exportReport(t) {
  let extra = {};
  if (window.dnModal) {
    const r = await window.dnModal({
      title: "Export triage report",
      desc: "Optional: add what was done and any notes. Every indicator in the report is defanged.",
      fields: [{ label: "Actions taken", type: "textarea", rows: 3, placeholder: "e.g. reported to IT, message deleted" }, { label: "Notes", type: "textarea", rows: 3, placeholder: "Anything else worth recording" }],
      submitText: "Download",
    });
    if (!r) return;
    extra = { actions: r[0], notes: r[1] };
  }
  const text = buildTriageReport({ ...t, generated: new Date().toISOString() }, extra);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  a.download = "phishing-triage-" + new Date().toISOString().slice(0, 10) + ".txt";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

const exportBar = () => `<div class="phx-acts"><button class="phx-btn sm" id="phxReport">Export report</button><button class="phx-btn sm" id="phxIocCopy">Copy defanged IOCs</button></div>`;

// ---- live helpers ---------------------------------------------------------

async function unfurl(url) {
  try {
    const r = await dnFetch(url, { timeout: 14000, redirect: "manual" });
    // worker returns redirectChain when following; with manual we read Location hops ourselves
    return { ok: true, status: r.status, finalUrl: r.finalUrl || r.url || url, chain: r.redirectChain || [] };
  } catch (e) {
    // fall back to a followed fetch to at least learn the final URL
    try { const r = await dnFetch(url, { timeout: 14000 }); return { ok: true, status: r.status, finalUrl: r.finalUrl || r.url || url, chain: r.redirectChain || [] }; }
    catch (e2) { return { ok: false, error: (e2 && e2.message) || "unreachable" }; }
  }
}

async function domainAge(domain) {
  try {
    const j = await dnFetchJSON("https://rdap.org/domain/" + encodeURIComponent(domain), { timeout: 12000 });
    const ev = (j && j.events) || [];
    const reg = ev.find((e) => /registration/i.test(e.eventAction || ""));
    if (!reg || !reg.eventDate) return { ok: true, date: null };
    const t = new Date(reg.eventDate).getTime();
    return { ok: true, date: reg.eventDate, days: isNaN(t) ? null : Math.floor((Date.now() - t) / 86400000) };
  } catch (_) { return { ok: false }; }
}

async function dnsA(domain) {
  try {
    const r = await fetch("https://cloudflare-dns.com/dns-query?type=A&name=" + encodeURIComponent(domain), { headers: { Accept: "application/dns-json" } });
    const j = await r.json();
    const ans = (j.Answer || []).filter((a) => a.type === 1).map((a) => a.data);
    return { ok: true, resolves: ans.length > 0, addrs: ans };
  } catch (_) { return { ok: false }; }
}

// ---- URL mode -------------------------------------------------------------

async function runUrl(out, text) {
  const m = text.match(/\bhttps?:\/\/\S+/i);
  const url = m ? m[0].replace(/[.,;]+$/, "") : text.split(/\s+/)[0];
  const a = analyzeUrl(url);
  const iocs = extractIOCs(text);

  out.innerHTML = `
    <div class="phx-card" id="phxHead"></div>
    <div class="phx-card"><h3>Link</h3>
      <dl class="phx-kv">
        <dt>Target</dt><dd style="font-family:ui-monospace,monospace">${esc(a.input)}</dd>
        <dt>Host</dt><dd>${esc(a.host || "—")}</dd>
        <dt>Registered domain</dt><dd>${esc(a.registrable || "—")} <span id="phxAge" class="phx-chip"><span class="phx-sp" style="width:11px;height:11px"></span> age…</span> <span id="phxDns" class="phx-chip"><span class="phx-sp" style="width:11px;height:11px"></span> dns…</span></dd>
        <dt>Scheme</dt><dd>${esc(a.scheme || "—")}</dd>
      </dl>
    </div>
    <div class="phx-card" id="phxReasons"></div>
    <div class="phx-card" id="phxUnfurl"><h3>Redirect chain</h3><div><span class="phx-sp"></span> unfurling…</div></div>
    ${iocsCard(iocs)}
    <div class="phx-warn">Risk is inferred from observable signals (redirects, registration date, DNS, lookalike heuristics). It is not a malware verdict — when in doubt, do not click.</div>`;

  renderReasons(out.querySelector("#phxReasons"), a.reasons, a.severity, "This link");

  // live enrichment in parallel
  const [age, dns, unf] = await Promise.all([
    a.registrable ? domainAge(a.registrable) : Promise.resolve({ ok: false }),
    a.host ? dnsA(a.host) : Promise.resolve({ ok: false }),
    /^https?:/i.test(a.input) || /^https?:/i.test(url) ? unfurl(/^https?:/i.test(url) ? url : "http://" + url) : Promise.resolve({ ok: false, error: "not an http(s) URL" }),
  ]);

  // age chip + maybe extra reason
  const ageEl = out.querySelector("#phxAge");
  let extra = [];
  if (age.ok && age.days != null) {
    ageEl.textContent = `registered ${age.days} day${age.days === 1 ? "" : "s"} ago`;
    if (age.days < 30) { ageEl.style.background = "#fdecec"; ageEl.style.color = "#b00020"; extra.push({ w: 4, t: `Domain was registered only ${age.days} day(s) ago — very common for phishing.` }); }
    else if (age.days < 90) { ageEl.style.color = "#b58100"; extra.push({ w: 2, t: `Domain is relatively new (${age.days} days).` }); }
  } else { ageEl.textContent = "age unknown"; }

  const dnsEl = out.querySelector("#phxDns");
  if (dns.ok) dnsEl.textContent = dns.resolves ? `resolves (${dns.addrs.length} A)` : "does not resolve";
  else dnsEl.textContent = "dns unknown";

  // unfurl
  const unfEl = out.querySelector("#phxUnfurl");
  if (unf.ok) {
    const hops = (unf.chain && unf.chain.length ? unf.chain : [a.input]).concat(unf.finalUrl && unf.finalUrl !== a.input ? [unf.finalUrl] : []);
    const uniqHops = Array.from(new Set(hops.filter(Boolean)));
    const finalA = analyzeUrl(unf.finalUrl || url);
    unfEl.innerHTML = `<h3>Redirect chain (HTTP ${esc(String(unf.status || "?"))})</h3>
      <ul class="phx-hops">${uniqHops.map((h) => `<li>${esc(h)}</li>`).join("")}</ul>
      ${finalA.registrable && a.registrable && finalA.registrable !== a.registrable ? `<p class="phx-hint">Final destination domain <b>${esc(finalA.registrable)}</b> differs from the link you were shown (<b>${esc(a.registrable)}</b>).</p>` : ""}`;
    if (finalA.registrable && a.registrable && finalA.registrable !== a.registrable) extra.push({ w: 3, t: `Redirects to a different domain: ${finalA.registrable}.` });
    for (const r of finalA.reasons) if (!a.reasons.some((x) => x.t === r.t)) extra.push({ w: r.w, t: "Final URL: " + r.t });
  } else {
    unfEl.innerHTML = `<h3>Redirect chain</h3><p class="phx-hint">Could not fetch the link (${esc(unf.error || "unreachable")}). This can mean the page is down, blocking servers, or cloaking.</p>`;
  }

  // recompute headline with enrichment
  const allReasons = a.reasons.concat(extra);
  if (extra.length) renderReasons(out.querySelector("#phxReasons"), allReasons, sevFromWeight(sumW(allReasons)), "This link");
  renderUrlHead(out.querySelector("#phxHead"), a.host || url, sevFromWeight(sumW(allReasons)));
  const vlabel = { critical: "High risk", high: "Suspicious", medium: "Treat with caution", low: "Low risk", info: "Low risk on observable signals" }[sevFromWeight(sumW(allReasons))];
  LAST = { mode: "url", verdict: vlabel, input: a.input, host: a.host, registrable: a.registrable, age: out.querySelector("#phxAge").textContent, dns: out.querySelector("#phxDns").textContent,
    chain: unf.ok ? Array.from(new Set((unf.chain && unf.chain.length ? unf.chain : [a.input]).concat(unf.finalUrl ? [unf.finalUrl] : []).filter(Boolean))) : [], reasons: allReasons, iocs };
  out.querySelector("#phxHead").insertAdjacentHTML("beforeend", exportBar());
  const finalReg = unf.ok ? analyzeUrl(unf.finalUrl || url).registrable : "";
  const urlFindings = phishUrlFindings({ input: a.input, host: a.host, registrable: a.registrable, finalUrl: unf.ok ? unf.finalUrl : "", finalRegistrable: finalReg, severity: sevFromWeight(sumW(allReasons)), reasons: allReasons });
  attachSinkButton(out.querySelector("#phxHead"), () => ({ findings: urlFindings, sample: text === SAMPLE_URL }), "phishtriage", { dataset: "link triage" });
}

function iocsCard(iocs) {
  const parts = [];
  const add = (label, arr) => { if (arr && arr.length) parts.push(`<div style="margin-bottom:6px"><b style="font-size:.8rem">${label}</b><br>${arr.slice(0, 40).map((x) => `<code>${esc(x)}</code>`).join("")}</div>`); };
  add("URLs", iocs.urls); add("Domains", iocs.domains); add("IPs", iocs.ips); add("Emails", iocs.emails); add("Hashes", iocs.hashes);
  if (!parts.length) return "";
  return `<div class="phx-card phx-iocs"><h3>Indicators (IOCs)</h3>${parts.join("")}</div>`;
}

function renderUrlHead(el, label, severity) {
  const vmap = { critical: ["High risk", "#b00020"], high: ["Suspicious", "#d9480f"], medium: ["Treat with caution", "#b58100"], low: ["Low risk", "#2f7d9e"], info: ["Low risk on observable signals", "#2f9e56"] };
  const [t, c] = vmap[severity] || vmap.info;
  el.innerHTML = `<div class="phx-verd"><span class="phx-vdot" style="--c:${c}"></span><span class="phx-vlabel" style="color:${c}">${t}</span><span class="phx-hint" style="margin:0 0 0 auto">${esc(label)}</span></div>`;
}

function renderReasons(el, reasons, severity, subject) {
  const pos = reasons.filter((r) => r.w > 0).sort((a, b) => b.w - a.w);
  if (!pos.length) { el.innerHTML = `<h3>Signals</h3><p style="color:#2f9e56;font-weight:600">No suspicious signals detected on ${esc(subject.toLowerCase())}.</p>`; return; }
  el.innerHTML = `<h3>Signals (${pos.length})</h3><ul class="phx-reasons">${pos.map((r) => {
    const s = r.w >= 4 ? "high" : r.w >= 2 ? "medium" : "low";
    return `<li><span class="phx-sev" style="background:${SEVC[s]}">${s}</span>${esc(r.t)}</li>`;
  }).join("")}</ul>`;
}

function sumW(rs) { return rs.reduce((a, r) => a + Math.max(0, r.w), 0); }
function sevFromWeight(w) { return w >= 7 ? "critical" : w >= 4 ? "high" : w >= 2 ? "medium" : w >= 1 ? "low" : "info"; }

// ---- email mode -----------------------------------------------------------

async function runEmail(out, text) {
  const r = triageEmail(text);
  const v = r.verdict;
  out.innerHTML = `
    <div class="phx-card">
      <div class="phx-verd"><span class="phx-vdot" style="--c:${v.c}"></span><span class="phx-vlabel" style="color:${v.c}">${esc(v.label)}</span></div>
    </div>
    <div class="phx-card"><h3>Message</h3>
      <dl class="phx-kv">
        <dt>From</dt><dd>${esc(r.from || "—")}</dd>
        <dt>From domain</dt><dd>${esc(r.fromReg || "—")} <span id="phxEmAge" class="phx-chip"><span class="phx-sp" style="width:11px;height:11px"></span> age…</span></dd>
        <dt>Return-Path</dt><dd>${esc(r.returnPath || "—")}</dd>
        <dt>Reply-To</dt><dd>${esc(r.replyTo || "—")}</dd>
        <dt>Subject</dt><dd>${esc(r.subject || "—")}</dd>
        <dt>Authentication</dt><dd>${authChip("SPF", r.auth.spf)} ${authChip("DKIM", r.auth.dkim)} ${authChip("DMARC", r.auth.dmarc)}</dd>
      </dl>
    </div>
    <div class="phx-card" id="phxEmReasons"></div>
    ${r.urlAnalyses.length ? `<div class="phx-card"><h3>Links in the message (${r.urlAnalyses.length})</h3>${r.urlAnalyses.slice(0, 25).map(urlRow).join("")}</div>` : ""}
    ${iocsCard(r.iocs)}
    <div class="phx-warn">Authentication results are read from the message's own Authentication-Results header (added by the receiving mail server). This is a triage aid, not a guarantee the message is safe or malicious.</div>`;

  renderReasons(out.querySelector("#phxEmReasons"), r.findings, "info", "this message");
  LAST = { mode: "email", verdict: v.label, from: r.from, fromReg: r.fromReg, returnPath: r.returnPath, replyTo: r.replyTo, subject: r.subject, auth: r.auth, links: r.urlAnalyses, reasons: r.findings, iocs: r.iocs };
  out.querySelector(".phx-card").insertAdjacentHTML("beforeend", exportBar());
  const toHdr = (parseEmailHeaders(text).headers.to || [])[0] || "";
  attachSinkButton(out.querySelector(".phx-card"), () => ({ findings: phishEmailFindings(r, { to: toHdr }) }), "phishtriage", { dataset: "email triage" });

  const ageEl = out.querySelector("#phxEmAge");
  if (r.fromReg) {
    const age = await domainAge(r.fromReg);
    if (age.ok && age.days != null) {
      ageEl.textContent = `registered ${age.days} day${age.days === 1 ? "" : "s"} ago`;
      if (age.days < 30) { ageEl.style.background = "#fdecec"; ageEl.style.color = "#b00020"; }
    } else ageEl.textContent = "age unknown";
    if (LAST && LAST.mode === "email") LAST.age = ageEl.textContent;
  } else { ageEl.textContent = "unknown"; }
}

function authChip(label, val) {
  const c = val === "pass" ? "#2f9e56" : (val === "fail" || val === "softfail") ? "#b00020" : "#8a93a6";
  return `<span class="phx-chip" style="color:${c};border-color:${c}44">${label}: ${esc(val || "none")}</span>`;
}

function urlRow(a) {
  const c = SEVC[a.severity] || SEVC.info;
  const top = a.reasons.filter((x) => x.w > 0).slice(0, 2).map((x) => esc(x.t)).join(" ");
  return `<div class="phx-urlrow"><div class="u" style="color:${c}">${esc(a.input)}</div>${top ? `<div class="phx-hint" style="margin-top:3px">${top}</div>` : `<div class="phx-hint" style="margin-top:3px">No suspicious signals.</div>`}</div>`;
}

export default renderPhish;
