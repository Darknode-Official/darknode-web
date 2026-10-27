// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Native Link & Email Check: phish-engine verdicts for a pasted link or a full email
// source. Enterprise mode ("queue") keeps a triage log of everything reported.

import { analyzeUrl, triageEmail, defangText, refangText, buildTriageReport } from "/js/dataprotect/phish-engine.js?v=20261026a";
import { phishUrlFindings, phishEmailFindings } from "/js/dataprotect/dp-sink.js";
import { attachSinkButton } from "/js/core/sink.js";
import { esc, toast, SEV, sevPill, recordRun, readList, writeList, ago, download } from "./ui.js";

const URL_VERDICT = {
  critical: ["Dangerous: do not open", "#b00020"], high: ["Likely phishing", "#d9480f"],
  medium: ["Suspicious", "#b58100"], low: ["Minor concerns", "#2f7d9e"], info: ["No red flags found", "#2f9e56"],
};
const lvl = (sev) => (sev === "critical" || sev === "high" ? "bad" : sev === "medium" ? "warn" : "good");
const emailSev = (v) => ({ "high-risk": "critical", suspicious: "high", caution: "medium" }[v.level] || "info");

export function mount(el, { space, mode }) {
  const queue = mode === "queue";
  el.innerHTML = `
    <div class="ns-card"><h2>${queue ? "Phishing triage" : "Is this link or email safe?"}</h2>
      <p class="ns-sub">${queue
        ? "Triage what employees report. Paste a suspicious link or the full email source (headers included) for a verdict, the reasons behind it and the indicators to block. Every verdict lands in the triage log below."
        : "Paste a link you were sent, or the full source of an email (in most mail apps: Show original). You get a plain verdict and the reasons. Nothing is opened or clicked."}</p>
      <div class="ns-seg" id="nsPhMode"><button data-m="url" class="on">Link</button><button data-m="email">Email source</button></div>
      <textarea class="ns-ta" id="nsPhIn" aria-label="Link to check" style="margin-top:10px;min-height:90px" placeholder="Paste a link" spellcheck="false"></textarea>
      <div class="ns-row"><button class="ns-btn" id="nsPhGo">Check it</button></div>
      <p class="ns-help">Analysis runs in your browser on the text you paste. The link is never visited.</p></div>
    <div id="nsPhOut"></div>${queue ? `<div class="ns-card"><h2>Triage log<span class="r"><button class="ns-btn ghost sm" id="nsPhExp">Export</button></span></h2><div id="nsPhLog"></div></div>` : ""}`;
  const ta = el.querySelector("#nsPhIn"), out = el.querySelector("#nsPhOut");
  let m = "url";
  el.querySelectorAll("#nsPhMode button").forEach((b) => b.onclick = () => {
    m = b.dataset.m; el.querySelectorAll("#nsPhMode button").forEach((x) => x.classList.toggle("on", x === b));
    ta.placeholder = m === "url" ? "Paste a link" : "Paste the full email source, headers included"; ta.style.minHeight = m === "url" ? "90px" : "200px";
  });

  const log = (entry) => {
    if (!queue) return;
    const list = readList(space, "triage"); list.unshift(entry); writeList(space, "triage", list.slice(0, 300)); paintLog();
  };
  const paintLog = () => {
    const box = el.querySelector("#nsPhLog"); if (!box) return;
    const list = readList(space, "triage");
    box.innerHTML = list.length ? `<ul class="ns-list">${list.slice(0, 50).map((e) => `<li><span class="ns-dot" style="--c:${(SEV[e.sev] || SEV.info).c}"></span><span><b>${esc(e.verdict)}</b> &middot; <span class="ns-mono">${esc(e.subject)}</span></span><span class="t">${esc(e.kind)} &middot; ${ago(e.at)}</span></li>`).join("")}</ul>`
      : `<div class="ns-empty">Nothing triaged yet.</div>`;
  };
  paintLog();
  const exp = el.querySelector("#nsPhExp"); if (exp) exp.onclick = () => download("phishing-triage-log.json", JSON.stringify(readList(space, "triage"), null, 2));

  el.querySelector("#nsPhGo").onclick = () => {
    const raw = ta.value.trim(); if (!raw) { toast(m === "url" ? "Paste a link first" : "Paste the email source first"); return; }
    if (m === "url") {
      // the link may sit inside a pasted sentence ("Click here https://..."): analyse the link, not the first word
      const toks = raw.split(/\s+/).map((t) => t.replace(/^[<("']+|[>)"',;.]+$/g, ""));
      const u = analyzeUrl(toks.find((t) => /^(?:[a-z][a-z0-9+.-]*:\/\/|hxxps?:)/i.test(t)) || toks.find((t) => /[a-z0-9-]\.[a-z]{2,}/i.test(refangText(t))) || toks[0]);
      const [label, c] = URL_VERDICT[u.severity] || URL_VERDICT.info;
      out.innerHTML = `<div class="ns-card" style="border-left:6px solid ${c}">
        <div style="font-size:12px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:${c}">Verdict</div>
        <div style="font-size:24px;font-weight:800;color:${c};margin:2px 0 6px">${esc(label)}</div>
        <div class="ns-mono">${esc(defangText(u.input))}</div>
        <div style="margin-top:6px;font-size:13px">Real destination domain: <b>${esc(u.registrable || u.host || "unknown")}</b></div>
        ${u.reasons.length ? `<ul style="margin:12px 0 0;padding-left:18px">${u.reasons.map((r) => `<li style="margin:4px 0">${esc(r.t)}</li>`).join("")}</ul>` : `<p class="ns-help">None of the checks fired: no lookalike brand, raw IP, punycode, risky TLD, embedded credentials or shortener. A clean result is not a guarantee; if the message was unexpected, verify with the sender another way.</p>`}
        <div class="ns-row" data-act></div></div>`;
      attachSinkButton(out.querySelector("[data-act]"), () => ({ findings: phishUrlFindings(u) }), "phishtriage", { dataset: "link triage" });
      recordRun(space, { tool: "phish", target: u.registrable || u.host || "link", summary: label, level: lvl(u.severity) });
      log({ at: Date.now(), kind: "Link", subject: defangText(u.host || raw.slice(0, 80)), verdict: label, sev: u.severity });
      return;
    }
    const t = triageEmail(raw), sev = emailSev(t.verdict);
    const io = t.iocs || {};
    out.innerHTML = `<div class="ns-card" style="border-left:6px solid ${t.verdict.c}">
      <div style="font-size:12px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:${t.verdict.c}">Verdict</div>
      <div style="font-size:24px;font-weight:800;color:${t.verdict.c};margin:2px 0 8px">${esc(t.verdict.label)}</div>
      <table class="ns-tbl"><tbody>
        <tr><td style="width:150px;color:var(--ns-mut)">From</td><td>${esc(t.from || "-")}</td></tr>
        <tr><td style="color:var(--ns-mut)">Subject</td><td>${esc(t.subject || "-")}</td></tr>
        <tr><td style="color:var(--ns-mut)">SPF / DKIM / DMARC</td><td>${esc((t.auth.spf || "none") + " / " + (t.auth.dkim || "none") + " / " + (t.auth.dmarc || "none"))}</td></tr>
        ${t.replyTo ? `<tr><td style="color:var(--ns-mut)">Reply-To</td><td>${esc(t.replyTo)}</td></tr>` : ""}
      </tbody></table>
      <h2 style="font-size:15px;margin:14px 0 4px">Why</h2>
      <ul style="margin:0;padding-left:18px">${t.findings.map((f) => `<li style="margin:4px 0">${esc(f.t)}</li>`).join("") || "<li>No warning signs in the headers or links.</li>"}</ul>
      ${t.urlAnalyses.length ? `<h2 style="font-size:15px;margin:14px 0 6px">Links in the message (${t.urlAnalyses.length})</h2><div class="ns-scroll"><table class="ns-tbl"><tbody>${t.urlAnalyses.map((u) => `<tr><td style="width:90px">${sevPill(u.severity)}</td><td class="mono">${esc(defangText(u.input))}</td></tr>`).join("")}</tbody></table></div>` : ""}
      ${queue && (io.domains || []).length ? `<h2 style="font-size:15px;margin:14px 0 6px">Indicators to block</h2><div class="ns-mono">${esc(defangText([].concat(io.domains || [], io.ips || []).join("\n"))).replace(/\n/g, "<br>")}</div>` : ""}
      <div class="ns-row" data-act>${queue ? `<button class="ns-btn ghost sm" data-rep>Download report</button>` : ""}</div></div>`;
    const rep = out.querySelector("[data-rep]");
    if (rep) rep.onclick = () => download("phishing-triage.txt", buildTriageReport(t), "text/plain");
    attachSinkButton(out.querySelector("[data-act]"), () => ({ findings: phishEmailFindings(t) }), "phishtriage", { dataset: "email triage" });
    recordRun(space, { tool: "phish", target: t.fromReg || t.fromDomain || "email", summary: t.verdict.label, level: lvl(sev) });
    log({ at: Date.now(), kind: "Email", subject: t.subject || t.from || "(no subject)", verdict: t.verdict.label, sev });
  };
  // a link handed over from search: check it in Link mode
  return { run: (link) => { el.querySelector('#nsPhMode button[data-m="url"]').click(); ta.value = link; el.querySelector("#nsPhGo").click(); } };
}
