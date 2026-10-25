// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Native Deck spaces: a Personal space for individuals and an Enterprise space for
// organizations. Each has its own home and tool set, rendered directly in the Deck
// (no console pages in iframes). Home screens summarise only runs made in that
// space, kept in this browser by ui.js recordRun().

import { esc, ago, injectStyle, readRuns, clearRuns } from "./native/ui.js";

const V = "?v=20261025b";
const TOOLS = {
  domain: () => import("./native/domain-check.js" + V),
  certs: () => import("./native/cert-watch.js" + V),
  phish: () => import("./native/phish-check.js" + V),
  secrets: () => import("./native/secret-scan.js" + V),
  data: () => import("./native/data-scan.js" + V),
};

export const SPACES = {
  personal: {
    kicker: "Personal space", title: "Your security, without the jargon",
    blurb: "Check the things an individual or a small site owner actually runs: your domain and email setup, your certificates, the links and emails you receive, your code and what you paste into other apps.",
    hero: "linear-gradient(120deg,#1f4fd1 0%,#3a7bff 55%,#14b8a6 100%)",
    tabs: [
      { id: "home", label: "Home" },
      { id: "domain", label: "My domain", mod: "domain", mode: "single", c: "#2552c6", desc: "Grade your website and email setup: HTTPS, headers, SPF, DKIM, DMARC." },
      { id: "phish", label: "Link & email check", mod: "phish", mode: "single", c: "#d9480f", desc: "Paste a link or an email you got. Get a plain verdict and the reasons." },
      { id: "secrets", label: "Code secrets", mod: "secrets", mode: "single", c: "#b00020", desc: "Find keys and passwords in your project before you push it." },
      { id: "data", label: "Safe to share?", mod: "data", mode: "single", c: "#7c3aed", desc: "Check text for personal data and credentials; get a redacted copy." },
      { id: "certs", label: "Certificates", mod: "certs", mode: "single", c: "#2f9e56", desc: "See when your site's certificates expire, before visitors get warnings." },
    ],
    steps: [["domain", "Check your domain"], ["certs", "Add your domains to certificate watch"], ["secrets", "Scan a project for secrets"], ["data", "Check something before you share it"]],
  },
  enterprise: {
    kicker: "Organization space", title: "Organization security command",
    blurb: "Grade the whole public estate, keep every certificate ahead of expiry, triage what employees report, sweep repositories for credentials and review data before it leaves.",
    hero: "linear-gradient(120deg,#111827 0%,#1e293b 50%,#2552c6 100%)",
    tabs: [
      { id: "home", label: "Command" },
      { id: "portfolio", label: "Domain portfolio", mod: "domain", mode: "portfolio", c: "#2552c6", desc: "Grade every public domain at once and rank them by risk." },
      { id: "certs", label: "Certificate fleet", mod: "certs", mode: "fleet", c: "#2f9e56", desc: "Expiry across all hostnames, from certificate-transparency logs." },
      { id: "phish", label: "Phishing triage", mod: "phish", mode: "queue", c: "#d9480f", desc: "Verdicts on reported links and emails, with a triage log and IOCs." },
      { id: "secrets", label: "Repository sweep", mod: "secrets", mode: "repo", c: "#b00020", desc: "Credentials and risky code across a whole repository, locally." },
      { id: "data", label: "Data-loss review", mod: "data", mode: "dlp", c: "#7c3aed", desc: "Find regulated data in documents and exports; produce redacted copies." },
    ],
    steps: [["portfolio", "Grade the domain portfolio"], ["certs", "Load the certificate fleet"], ["phish", "Triage a reported message"], ["secrets", "Sweep a repository"], ["data", "Review an export for regulated data"]],
  },
};
// tab id -> run.tool recorded by the tool modules
const RUN_TOOL = { domain: "domain", portfolio: "portfolio", certs: "certs", phish: "phish", secrets: "secrets", data: "data" };
const LVL_C = { good: "#2f9e56", warn: "#b58100", bad: "#b00020" };

function homeHTML(id, S) {
  const runs = readRuns(id);
  const tools = S.tabs.filter((t) => t.mod);
  const by = (tool) => runs.filter((r) => r.tool === tool);
  const kpi = (v, l, c) => `<div class="ns-kpi" style="--c:${c}"><div class="v">${v}</div><div class="l">${esc(l)}</div></div>`;
  let kpis;
  if (id === "personal") {
    const dom = by("domain")[0], cert = by("certs")[0], sec = by("secrets")[0];
    const phish = by("phish"), risky = phish.filter((r) => r.level === "bad").length;
    kpis = kpi(dom ? esc(dom.grade || "-") : "-", dom ? "Domain grade: " + dom.target : "Domain not checked yet", dom ? LVL_C[dom.level] : "#8a93a6")
      + kpi(cert ? (cert.counts && (cert.counts.expired + cert.counts.urgent + cert.counts.soon)) || 0 : "-", cert ? "Certificates expiring within 30 days" : "Certificates not checked", cert ? LVL_C[cert.level] : "#8a93a6")
      + kpi(sec ? (sec.counts && sec.counts.secrets) || 0 : "-", sec ? "Secrets in last code scan" : "Code not scanned yet", sec ? LVL_C[sec.level] : "#8a93a6")
      + kpi(phish.length, "Links and emails checked" + (risky ? ", " + risky + " flagged" : ""), risky ? "#b00020" : "#2552c6");
  } else {
    const doms = by("domain"), graded = doms.filter((r) => r.score != null);
    const avg = graded.length ? Math.round(graded.reduce((a, r) => a + r.score, 0) / graded.length) : null;
    const weak = doms.filter((r) => r.level === "bad").length;
    const cert = by("certs")[0], phish = by("phish"), secrets = by("secrets")[0], data = by("data");
    kpis = kpi(avg == null ? "-" : avg, graded.length ? "Avg domain score, " + graded.length + " graded" : "No domains graded", avg == null ? "#8a93a6" : avg >= 80 ? "#2f9e56" : avg >= 60 ? "#b58100" : "#b00020")
      + kpi(weak, "Domains graded D or F", weak ? "#b00020" : "#2f9e56")
      + kpi(cert ? (cert.counts && (cert.counts.expired + cert.counts.urgent + cert.counts.soon)) || 0 : "-", cert ? "Certificates expiring within 30 days" : "Fleet not loaded", cert ? LVL_C[cert.level] : "#8a93a6")
      + kpi(phish.length + data.length + (secrets ? 1 : 0), "Triage and reviews completed", "#2552c6");
  }
  const attention = runs.filter((r) => r.level === "bad").slice(0, 8);
  const steps = S.steps.map(([tab, label]) => { const done = by(RUN_TOOL[tab]).length > 0; return `<li class="${done ? "done" : ""}"><span>${esc(label)}</span><button class="ns-btn ${done ? "ghost " : ""}sm" data-go="${tab}">${done ? "Run again" : "Start"}</button></li>`; }).join("");
  return `
    <div class="ns-kpis">${kpis}</div>
    <div class="ns-two">
      <div>
        <div class="ns-card"><h2>${id === "personal" ? "Needs your attention" : "Open risk"}<span class="r">${attention.length ? attention.length + " item" + (attention.length === 1 ? "" : "s") : ""}</span></h2>
          ${attention.length ? `<ul class="ns-list">${attention.map((r) => `<li><span class="ns-dot" style="--c:${LVL_C[r.level]}"></span><span><b>${esc(r.target)}</b> &middot; ${esc(r.summary)}</span><span class="t">${ago(r.at)}</span></li>`).join("")}</ul>`
            : `<div class="ns-empty">${runs.length ? "Nothing high-risk in your recent checks." : "Run a check below and anything risky shows up here."}</div>`}</div>
        <div class="ns-grid">${tools.map((t) => `<button class="ns-tile" style="--c:${t.c}" data-go="${t.id}"><b>${esc(t.label)}</b><span>${esc(t.desc)}</span><em>${by(RUN_TOOL[t.id]).length ? "Last run " + ago(by(RUN_TOOL[t.id])[0].at) : "Open"}</em></button>`).join("")}</div>
      </div>
      <div>
        <div class="ns-card"><h2>${id === "personal" ? "Get set up" : "Coverage"}</h2><ol class="ns-steps">${steps}</ol></div>
        <div class="ns-card"><h2>Recent checks<span class="r">${runs.length ? `<button class="ns-btn ghost sm" data-clear>Clear</button>` : ""}</span></h2>
          ${runs.length ? `<ul class="ns-list">${runs.slice(0, 10).map((r) => `<li><span class="ns-dot" style="--c:${LVL_C[r.level] || "#8a93a6"}"></span><span><b>${esc(r.target)}</b><br><span style="color:var(--ns-mut)">${esc(r.summary)}</span></span><span class="t">${ago(r.at)}</span></li>`).join("")}</ul>` : `<div class="ns-empty">No checks yet.</div>`}
          <p class="ns-help">History is kept in this browser only.</p></div>
      </div>
    </div>`;
}

// Mount (once) or refresh a space into `el`. ctx: { confirm(msg) -> Promise<bool> }.
export function mountSpace(el, id, ctx = {}) {
  const S = SPACES[id]; if (!S) return;
  injectStyle();
  const LS = "dn_space_" + id + "_tab";
  if (!el._ns) {
    el.innerHTML = `<div class="ns">
      <div class="ns-hero" style="--ns-hero:${S.hero}"><div class="k">${esc(S.kicker)}</div><h1>${esc(S.title)}</h1><p>${esc(S.blurb)}</p></div>
      <nav class="ns-tabs" role="tablist">${S.tabs.map((t) => `<button class="ns-tab" role="tab" data-tab="${t.id}">${esc(t.label)}</button>`).join("")}</nav>
      ${S.tabs.map((t) => `<section data-pane="${t.id}" hidden></section>`).join("")}</div>`;
    const st = { cur: "home", mounted: new Set() };
    el._ns = st;
    const show = async (tab) => {
      const t = S.tabs.find((x) => x.id === tab) || S.tabs[0];
      st.cur = t.id; try { localStorage.setItem(LS, t.id); } catch (_) {}
      el.querySelectorAll(".ns-tab").forEach((b) => { const on = b.dataset.tab === t.id; b.classList.toggle("on", on); b.setAttribute("aria-selected", String(on)); });
      el.querySelectorAll("[data-pane]").forEach((p) => { p.hidden = p.dataset.pane !== t.id; });
      const pane = el.querySelector(`[data-pane="${t.id}"]`);
      if (t.id === "home") { pane.innerHTML = homeHTML(id, S); return; }
      if (st.mounted.has(t.id)) return;
      st.mounted.add(t.id);
      pane.innerHTML = `<div class="ns-card"><span class="ns-spin"></span>Loading...</div>`;
      try { (await TOOLS[t.mod]()).mount(pane, { space: id, mode: t.mode }); }
      catch (e) { st.mounted.delete(t.id); pane.innerHTML = `<div class="ns-card"><b>This tool failed to load.</b><p class="ns-help">${esc((e && e.message) || e)}</p></div>`; }
    };
    st.show = show;
    el.addEventListener("click", async (e) => {
      const tb = e.target.closest("[data-tab]"); if (tb) { show(tb.dataset.tab); return; }
      const g = e.target.closest("[data-go]"); if (g) { show(g.dataset.go); el.scrollIntoView({ block: "start" }); return; }
      if (e.target.closest("[data-clear]")) {
        const ok = ctx.confirm ? await ctx.confirm("Clear the check history for this space? Saved domain lists are kept.") : true;
        if (ok) { clearRuns(id); show("home"); }
      }
    });
    // Keep the home screen live when a tool records a run.
    window.addEventListener("dn-space-run", (e) => { if (e.detail && e.detail.space === id && st.cur === "home" && el.isConnected) show("home"); });
    let saved = "home"; try { saved = localStorage.getItem(LS) || "home"; } catch (_) {}
    show(saved);
    return;
  }
  if (el._ns.cur === "home") el._ns.show("home");
}
