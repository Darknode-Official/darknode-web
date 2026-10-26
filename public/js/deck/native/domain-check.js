// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Native Domain Check: live transport, header, email-auth, certificate and disclosure
// checks graded by posture-engine. Personal = one domain; Enterprise = a saved
// portfolio graded side by side (mode "portfolio").

import { scorePosture } from "/js/dataprotect/posture-engine.js?v=20261019i";
import { collectPosture, cleanDomain, validDomain } from "/js/dataprotect/posture-collect.js?v=20261025g";
import { postureFindings } from "/js/dataprotect/dp-sink.js";
import { attachSinkButton } from "/js/core/sink.js";
import { esc, toast, GRADE_C, recordRun, readList, writeList, pool, download } from "./ui.js";
import { parseDomains } from "/js/dataprotect/tls-engine.js";

const ST = { pass: ["#2f9e56", "Pass"], warn: ["#b58100", "Warn"], fail: ["#b00020", "Fail"], info: ["#2f7d9e", "Info"], na: ["#8a93a6", "N/A"] };
const level = (res) => (res.grade === "A" || res.grade === "B" ? "good" : res.grade === "C" ? "warn" : "bad");

async function grade(domain) {
  const input = await collectPosture(domain);
  return input ? scorePosture(input) : null;
}

function reportHTML(res, { personal }) {
  const gc = GRADE_C[res.grade] || "#667085";
  const cats = res.categories.map((cat) => {
    const sc = cat.score == null ? "not assessed" : cat.score + " / 100";
    const col = cat.score == null ? "var(--ns-mut)" : cat.score >= 80 ? "#2f9e56" : cat.score >= 50 ? "#b58100" : "#b00020";
    return `<div class="ns-cat"><h3>${esc(cat.label)}<span class="s" style="color:${col}">${sc}</span></h3>${cat.checks.map((c) => `
      <div class="ns-check ${c.status}"><span class="ns-pill" style="background:${(ST[c.status] || ST.na)[0]}">${(ST[c.status] || ST.na)[1]}</span>
      <div><div class="n">${esc(c.name)}</div><div class="d">${esc(c.detail)}</div>${c.advice && c.status !== "pass" ? `<div class="a">${esc(c.advice)}</div>` : ""}</div></div>`).join("")}</div>`;
  }).join("");
  const fixes = res.topActions.length
    ? `<ol style="margin:6px 0 0;padding-left:20px">${res.topActions.map((a) => `<li style="margin:5px 0"><b>${esc(a.name)}</b> <span style="color:var(--ns-mut)">(${esc(a.category)})</span>. ${esc(a.advice || "")}</li>`).join("")}</ol>`
    : `<p style="color:#2f9e56;font-weight:700;margin:6px 0 0">Nothing failing or warning. ${personal ? "Your" : "This"} domain has a strong external posture.</p>`;
  return `
  <div class="ns-card">
    <div class="ns-score">
      <div class="ns-ring" style="--g:${gc};--p:${res.score == null ? 0 : res.score}"><div class="in">${esc(res.grade)}</div></div>
      <div style="flex:1;min-width:220px">
        <div style="font-size:18px;font-weight:800">${esc(res.domain)}</div>
        <div style="color:var(--ns-mut);font-size:13px">Score ${res.score == null ? "n/a" : res.score + " / 100"} &middot; ${res.counts.fail} failing &middot; ${res.counts.warn} warnings &middot; ${res.counts.pass} passing</div>
        <div class="ns-row" data-act></div>
      </div>
    </div>
    <h2 style="font-size:15px;margin:16px 0 0">${personal ? "What to fix first" : "Priority remediation"}</h2>${fixes}
    <div class="ns-note">Reads only publicly observable signals (HTTP headers, DNS, certificate transparency, security.txt). An external indicator, not a penetration test or audit.</div>
  </div>${cats}`;
}

function wireReport(box, res) {
  const act = box.querySelector("[data-act]");
  const j = document.createElement("button"); j.className = "ns-btn ghost sm"; j.textContent = "Export JSON";
  j.onclick = () => download("domain-check-" + res.domain + ".json", JSON.stringify(res, null, 2));
  act.appendChild(j);
  attachSinkButton(act, () => ({ findings: postureFindings(res) }), "posture", { dataset: "posture " + res.domain });
}

export function mount(el, { space, mode }) {
  const personal = mode !== "portfolio";
  if (personal) {
    el.innerHTML = `
      <div class="ns-card"><h2>Check your domain</h2>
        <p class="ns-sub">Grades the website and email setup of a domain you own: HTTPS, security headers, SPF / DKIM / DMARC, certificate health and a security contact. Takes about 10 seconds.</p>
        <div class="ns-form"><input class="ns-in" id="nsDcIn" aria-label="Domain to check" placeholder="yourdomain.com" autocomplete="off" spellcheck="false"><button class="ns-btn" id="nsDcGo">Check domain</button></div>
        <p class="ns-help">Only public signals are read. Nothing intrusive is sent to the site.</p></div>
      <div id="nsDcOut"></div>`;
    const inp = el.querySelector("#nsDcIn"), btn = el.querySelector("#nsDcGo"), out = el.querySelector("#nsDcOut");
    const last = readList(space, "domain")[0];
    if (last) inp.value = last;
    const run = async () => {
      const d = cleanDomain(inp.value);
      if (!validDomain(d)) { toast("Enter a domain like yourdomain.com"); return; }
      writeList(space, "domain", [d]);
      btn.disabled = true; out.innerHTML = `<div class="ns-card"><span class="ns-spin"></span>Running live checks against <b>${esc(d)}</b>...</div>`;
      let why = "";
      const res = await grade(d).catch((e) => { why = (e && e.message) || ""; return null; });
      btn.disabled = false;
      if (!res) { out.innerHTML = `<div class="ns-card"><b>Could not reach ${esc(d)}.</b><p class="ns-help">${esc(why || "It did not answer over HTTP or HTTPS.")} Check the spelling and try again.</p></div>`; return; }
      out.innerHTML = reportHTML(res, { personal: true }); wireReport(out, res);
      recordRun(space, { tool: "domain", target: d, summary: "Grade " + res.grade + " (" + res.counts.fail + " failing)", level: level(res), score: res.score, grade: res.grade });
    };
    btn.onclick = run; inp.onkeydown = (e) => { if (e.key === "Enter") run(); };
    return { run: (d) => { inp.value = d; run(); } };
  }

  el.innerHTML = `
    <div class="ns-card"><h2>Domain portfolio<span class="r" id="nsPfCount"></span></h2>
      <p class="ns-sub">Grade every public domain the organization owns in one pass and rank them by risk. The list is saved in this browser so you can re-run it.</p>
      <textarea class="ns-ta" id="nsPfIn" style="min-height:96px" placeholder="One domain per line" spellcheck="false"></textarea>
      <div class="ns-row"><button class="ns-btn" id="nsPfGo">Grade portfolio</button><button class="ns-btn ghost" id="nsPfCsv" disabled>Export CSV</button><span class="ns-help" id="nsPfSt" style="margin:0"></span></div>
      <p class="ns-help">Up to 50 domains, 3 at a time. Only public signals are read.</p></div>
    <div id="nsPfOut"></div><div id="nsPfDet"></div>`;
  const ta = el.querySelector("#nsPfIn"), go = el.querySelector("#nsPfGo"), csv = el.querySelector("#nsPfCsv"), st = el.querySelector("#nsPfSt"), out = el.querySelector("#nsPfOut"), det = el.querySelector("#nsPfDet");
  ta.value = readList(space, "domains").join("\n");
  const cnt = () => { const n = parseDomains(ta.value).length; el.querySelector("#nsPfCount").textContent = n ? n + " domain" + (n === 1 ? "" : "s") : ""; };
  ta.oninput = cnt; cnt();
  let results = [];
  const table = () => {
    const rows = results.filter(Boolean).slice().sort((a, b) => (a.res ? a.res.score ?? 101 : -1) - (b.res ? b.res.score ?? 101 : -1));
    out.innerHTML = `<div class="ns-card"><h2>Ranked by risk<span class="r">worst first</span></h2><div class="ns-scroll"><table class="ns-tbl">
      <thead><tr><th>Grade</th><th>Domain</th><th>Score</th><th>Failing</th><th>Warnings</th><th>Top issue</th><th></th></tr></thead><tbody>
      ${rows.map((r) => r.res ? `<tr><td><span class="ns-grade" style="background:${GRADE_C[r.res.grade] || "#667085"}">${esc(r.res.grade)}</span></td><td><b>${esc(r.domain)}</b></td><td>${r.res.score ?? "n/a"}</td><td style="color:#b00020;font-weight:700">${r.res.counts.fail}</td><td style="color:#b58100;font-weight:700">${r.res.counts.warn}</td><td>${esc(r.res.topActions[0] ? r.res.topActions[0].name : "None")}</td><td><button class="ns-btn ghost sm" data-d="${esc(r.domain)}">Details</button></td></tr>`
        : `<tr><td><span class="ns-grade" style="background:#8a93a6">?</span></td><td><b>${esc(r.domain)}</b></td><td colspan="5" style="color:var(--ns-mut)">${r.pending ? '<span class="ns-spin"></span>Checking...' : "Unreachable over HTTP and HTTPS"}</td></tr>`).join("")}
      </tbody></table></div></div>`;
    out.querySelectorAll("[data-d]").forEach((b) => b.onclick = () => {
      const r = results.find((x) => x && x.domain === b.dataset.d); if (!r || !r.res) return;
      det.innerHTML = reportHTML(r.res, { personal: false }); wireReport(det, r.res); det.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };
  go.onclick = async () => {
    const list = parseDomains(ta.value).slice(0, 50);
    if (!list.length) { toast("Add at least one domain"); return; }
    writeList(space, "domains", list); det.innerHTML = "";
    go.disabled = true; csv.disabled = true;
    results = list.map((domain) => ({ domain, pending: true })); table();
    let done = 0;
    await pool(list, 3, (d) => grade(d).catch(() => null), (res, i) => {
      results[i] = { domain: list[i], res }; done++; st.textContent = done + " / " + list.length + " checked"; table();
    });
    go.disabled = false; csv.disabled = false;
    const graded = results.filter((r) => r.res), bad = graded.filter((r) => level(r.res) === "bad").length;
    const avg = graded.length ? Math.round(graded.reduce((a, r) => a + (r.res.score || 0), 0) / graded.length) : null;
    recordRun(space, { tool: "portfolio", target: list.length + " domains", summary: (avg == null ? "No domain reachable" : "Average score " + avg) + ", " + bad + " graded D or F", level: bad ? "bad" : graded.some((r) => level(r.res) === "warn") ? "warn" : "good", score: avg, counts: { domains: list.length, bad } });
    for (const r of graded) recordRun(space, { tool: "domain", target: r.domain, summary: "Grade " + r.res.grade + " (" + r.res.counts.fail + " failing)", level: level(r.res), score: r.res.score, grade: r.res.grade });
  };
  csv.onclick = () => {
    const q = (v) => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
    const lines = [["domain", "grade", "score", "failing", "warnings", "top_issue"].join(",")].concat(results.filter(Boolean).map((r) => r.res
      ? [r.domain, r.res.grade, r.res.score, r.res.counts.fail, r.res.counts.warn, r.res.topActions[0] ? r.res.topActions[0].name : ""].map(q).join(",")
      : [r.domain, "", "", "", "", "unreachable"].map(q).join(",")));
    download("domain-portfolio.csv", lines.join("\n"), "text/csv");
  };
}
