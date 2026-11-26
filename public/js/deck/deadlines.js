// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Deadlines scene and the Overview's Deadlines block. The clocks are created and alerted on the
// server, per workspace, by the MonitorDO (worker/monitor.js): certificate expiry from the
// certificate monitors (the Free watch too), and, only with the workspace's opt-ins, the Cyber
// Resilience Act Article 14 reporting clocks and CISA BOD 22-01 due dates from the known-exploited
// CVE monitor. The clock maths and the early-warning facts come from core/deadlines.js, the same
// file the server uses. Darknode tracks the clocks and prepares facts; it does not decide whether
// a law applies and does not submit anything.
import { monitorApi as api, monitoringAvailable } from "./monitor-client.js";
import { CRA, BOD2201, DISCLAIMER, MAX_SHIPPED, stateOf, fmtLeft, utc, stepsOf, sourceOf, craFacts, stateNames, sortDeadlines } from "../core/deadlines.js?v=1";

const S = { ctx: null, el: null, data: null, mons: null, seq: 0, open: new Set(), facts: "", pick: "", showClosed: false, graph: null };
const B = { data: null, at: 0, seq: 0 }; // the Overview block's cache: the Overview re-renders often
const E = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m, t) => { try { S.ctx && S.ctx.toast && S.ctx.toast(m, t); } catch (_) {} };
const isFree = (ctx) => !!(ctx && ctx.tier === "free");
// the Free watch lives in the caller's own workspace, so on Free every request goes there
const call = (body, ctx = S.ctx) => api(body, { personal: isFree(ctx) });
const KIND = { "cra-exploited": "Cyber Resilience Act", "cert-expiry": "Certificate", "kev-due": "BOD 22-01" };
const STATE = { overdue: "Overdue", open: "Open", waiting: "Not started", done: "Done", dismissed: "Dismissed" };
const local = (ms) => (ms ? new Date(ms).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "");

function injectStyle() {
  if (document.getElementById("ddl-css")) return;
  const st = document.createElement("style"); st.id = "ddl-css";
  st.textContent = `
.ddl-sub{color:#5a6680;font-size:12.5px;margin:-2px 0 14px;line-height:1.5}
.ddl-card{border:1px solid rgba(23,33,56,.12);border-radius:10px;margin:0 0 10px;background:#fff}
.ddl-card.over{border-color:rgba(198,40,40,.45)}
.ddl-case{padding:12px 14px 4px;border-bottom:1px solid rgba(23,33,56,.08)}
.ddl-case h3{margin:0;font-size:13.5px;font-weight:650;color:#141c2e}
.ddl-case p{margin:3px 0 8px;font-size:12px;color:#5a6680;line-height:1.5}
.ddl-row{display:flex;align-items:center;gap:8px 12px;flex-wrap:wrap;padding:10px 14px}
.ddl-row+.ddl-row{border-top:1px dashed rgba(23,33,56,.1)}
.ddl-row>.ddl-pill{min-width:80px;text-align:center;box-sizing:border-box}
.ddl-pill{font-size:10.5px;font-weight:700;border-radius:20px;padding:1px 8px;background:rgba(23,33,56,.07);color:#45506a;white-space:nowrap}
.ddl-pill.over{background:rgba(198,40,40,.1);color:#c62828}
.ddl-pill.done{background:rgba(18,168,95,.1);color:#0e7a46}
.ddl-t{flex:1 1 300px;min-width:0}
.ddl-t b{display:block;font-size:13px;font-weight:650;color:#141c2e;overflow-wrap:anywhere}
.ddl-t span{font-size:12px;color:#5a6680}
.ddl-left{font-size:13px;font-weight:700;color:#141c2e;font-variant-numeric:tabular-nums;white-space:nowrap}
.ddl-left.over{color:#c62828}
.ddl-acts{display:flex;gap:6px;flex-wrap:wrap}
.ddl-btn{appearance:none;border:1px solid rgba(23,33,56,.16);background:#fff;border-radius:7px;font:inherit;font-size:12px;font-weight:600;color:#2a3450;padding:4px 10px;cursor:pointer}
.ddl-btn:hover{border-color:var(--dk-acc,#2552c6);color:var(--dk-acc,#2552c6)}
.ddl-btn.pri{background:var(--dk-acc,#2552c6);border-color:var(--dk-acc,#2552c6);color:#fff}
.ddl-btn:disabled{opacity:.55;cursor:default}
.ddl-more{padding:0 14px 12px;font-size:12.5px;color:#45506a;line-height:1.55}
.ddl-more ol{margin:4px 0 8px;padding-left:20px}
.ddl-more blockquote{margin:6px 0;padding:6px 10px;border-left:3px solid rgba(23,33,56,.18);color:#45506a;font-size:12px}
.ddl-more a,.ddl-note a{color:var(--dk-acc,#2552c6)}
.ddl-edit{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px 14px;padding:10px 14px 12px;border-top:1px solid rgba(23,33,56,.08);background:rgba(23,33,56,.02)}
.ddl-f label{display:block;font-size:12px;font-weight:600;color:#2a3450;margin:0 0 3px}
.ddl-f input,.ddl-f textarea{width:100%;font:inherit;font-size:13px;border:1px solid rgba(23,33,56,.18);border-radius:7px;padding:6px 9px;box-sizing:border-box;background:#fff}
.ddl-f textarea{min-height:54px;resize:vertical}
.ddl-f .now{font-size:12px;color:#141c2e;margin:0 0 4px}
.ddl-f .hint{font-size:11.5px;color:#5a6680;margin:3px 0 0;line-height:1.45}
.ddl-f .rowb{display:flex;gap:6px;margin-top:6px;flex-wrap:wrap}
.ddl-facts{margin:0 14px 12px;border:1px solid rgba(37,82,198,.25);border-radius:8px;background:rgba(37,82,198,.03);padding:10px 12px}
.ddl-facts table{width:100%;border-collapse:collapse;font-size:12.5px}
.ddl-facts td{vertical-align:top;overflow-wrap:anywhere}
.ddl-facts td:first-child{width:38%;color:#5a6680;font-weight:600}
.ddl-facts .hd{display:flex;align-items:center;gap:8px;margin:0 0 6px;font-size:12.5px;font-weight:650;color:#141c2e}
.ddl-facts .hd .ddl-btn{margin-left:auto}
.ddl-panel{margin:18px 0 0;border:1px solid rgba(23,33,56,.12);border-radius:10px;padding:12px 14px}
.ddl-panel h2{font-size:14px;margin:0 0 6px}
.ddl-check{display:flex;gap:9px;align-items:flex-start;font-size:13px;color:#141c2e;margin:8px 0;line-height:1.45}
.ddl-check input{margin-top:3px}
.ddl-check small{display:block;color:#5a6680;font-size:12px}
.ddl-note{font-size:12px;color:#45506a;line-height:1.55;margin:8px 0 0}
.ddl-warn{font-size:12.5px;color:#7a4a00;background:rgba(245,146,11,.1);border-radius:8px;padding:9px 12px;line-height:1.5;margin:8px 0 0}
.ddl-picklist{max-height:230px;overflow:auto;border:1px solid rgba(23,33,56,.12);border-radius:8px;margin:6px 0 0}
.ddl-picklist label{display:flex;gap:8px;align-items:center;padding:6px 10px;font-size:12.5px;border-top:1px dashed rgba(23,33,56,.08);overflow-wrap:anywhere}
.ddl-picklist label:first-child{border-top:0}
.ddl-picklist small{color:#5a6680;margin-left:auto;white-space:nowrap}
.ddl-pickbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px}
.ddl-pickbar input{flex:1 1 200px;font:inherit;font-size:13px;border:1px solid rgba(23,33,56,.18);border-radius:7px;padding:6px 9px}
.ddl-off{font-size:12.5px;color:#7a4a00;background:rgba(245,146,11,.1);border-radius:8px;padding:11px 13px;line-height:1.5}
.ddl-ov .ddl-row{padding:8px 0}
.ddl-ov .ddl-row+.ddl-row{border-top:1px dashed rgba(23,33,56,.1)}
@media (max-width:640px){.ddl-row{gap:6px 10px}.ddl-row>.ddl-pill{min-width:0}.ddl-acts{width:100%}.ddl-facts td{display:block;width:auto}.ddl-facts table td:first-child{width:auto;padding-bottom:0!important;border-bottom:0!important}.ddl-facts table td+td{padding-top:2px!important}}
`;
  document.head.appendChild(st);
}

// keep every visible countdown current (one timer for the scene and the Overview block)
let timer = 0;
function tick() {
  const t = Date.now();
  document.querySelectorAll("[data-dl-due]").forEach((x) => {
    const due = Number(x.dataset.dlDue); if (!due) return;
    x.textContent = fmtLeft(due - t); x.classList.toggle("over", due <= t);
  });
}
const startTick = () => { if (!timer) timer = setInterval(tick, 30000); };
const leftHtml = (d, now) => d.dueAt && (d.status === "open") ? `<span class="ddl-left${d.dueAt <= now ? " over" : ""}" data-dl-due="${d.dueAt}">${E(fmtLeft(d.dueAt - now))}</span>` : "";
const pill = (st) => `<span class="ddl-pill${st === "overdue" ? " over" : st === "done" ? " done" : ""}">${E(STATE[st] || st)}</span>`;

// ---- the scene ----------------------------------------------------------------------------------

export function mountDeadlines(el, ctx) {
  injectStyle(); startTick();
  S.ctx = ctx || S.ctx; S.el = el; S.facts = "";
  el.innerHTML = `
    <div class="dk-ovhead"><div><h1>Deadlines</h1><p>The clocks your findings start, soonest first: certificate expiry, and with your opt-ins the Cyber Resilience Act's reporting clocks and CISA BOD 22-01 due dates. Each one lists its steps; you are alerted when it starts and when a quarter of its time is left.</p></div></div>
    <div class="dk-ovp" id="dlBody"><div class="dk-loading"><span class="sp"></span>Loading deadlines…</div></div>`;
  load();
}

async function load() {
  const box = S.el && S.el.querySelector("#dlBody"); if (!box) return;
  const my = ++S.seq;
  if (!monitoringAvailable()) { box.innerHTML = `<div class="ddl-off">Deadlines need the cloud proxy, which this build has not configured.</div>`; return; }
  // guest / Test Mode: the clocks come from server-side monitors, which need an account
  if (S.ctx && S.ctx.noAccount) {
    box.innerHTML = `<div class="ddl-warn">Deadlines come from monitors, which run on Darknode's servers for an account. Create a free account and watch a domain, and its certificate expiry is tracked here. <button class="ddl-btn pri" id="dlSignup">Create a free account</button></div>`;
    box.querySelector("#dlSignup").onclick = () => S.ctx.signup && S.ctx.signup();
    return;
  }
  try {
    const [data, mons] = await Promise.all([call({ op: "deadlines" }), call({ op: "list" }).catch(() => null)]);
    if (my !== S.seq) return;
    S.data = data; S.mons = mons && mons.monitors; B.at = 0; // the Overview block reloads next time
    paint();
  } catch (e) {
    if (my !== S.seq) return;
    box.innerHTML = `<div class="ddl-off">${E(e.message || String(e))}</div>`;
  }
}

function rowHtml(d, now) {
  const st = stateOf(d, now), open = S.open.has(d.id), src = sourceOf(d);
  const sub = d.kind === "cra-exploited" ? (d.dueAt ? "Due " + utc(d.dueAt) + " (" + local(d.dueAt) + " your time)" : "Starts when you mark the fix or mitigation available")
    : d.kind === "cert-expiry" ? "Expires " + utc(d.dueAt) + " · watched since " + utc(d.startedAt)
      : "KEV due date " + utc(d.dueAt).slice(0, 10) + " (end of day, UTC)";
  const closed = d.status !== "open";
  return `<div class="ddl-row" data-id="${E(d.id)}">
      ${pill(st)}
      <div class="ddl-t"><b>${E(d.kind === "cra-exploited" ? ({ early: "Early warning (24 hours)", notify: "Vulnerability notification (72 hours)", final: "Final report (14 days after the fix)" }[d.clock] || d.title) : d.title)}</b><span>${E(KIND[d.kind] || d.kind)} · ${E(sub)}${closed && d.reason ? " · " + E(STATE[d.status]) + ": " + E(d.reason) : ""}</span></div>
      ${leftHtml(d, now)}
      <span class="ddl-acts">
        <button class="ddl-btn" data-act="steps" aria-expanded="${open}">${open ? "Hide steps" : "Steps"}</button>
        ${closed ? `<button class="ddl-btn" data-act="reopen">Reopen</button>` : `<button class="ddl-btn" data-act="done">Mark done</button><button class="ddl-btn" data-act="dismiss">Dismiss</button>`}
      </span>
    </div>
    ${open ? `<div class="ddl-more"><ol>${stepsOf(d).map((s) => `<li>${E(s)}</li>`).join("")}</ol>${src ? `${src.quote ? `<blockquote>"${E(src.quote)}"</blockquote>` : ""}Source: <a href="${E(src.url)}" target="_blank" rel="noopener">${E(src.label)}</a>` : ""}</div>` : ""}`;
}

function caseHtml(c, list, now) {
  const over = list.some((d) => stateOf(d, now) === "overdue");
  const aware = utc(c.awareAt) + (c.awareAt !== c.alertedAt ? " (you corrected it; Darknode alerted " + utc(c.alertedAt) + ")" : " (when Darknode alerted)");
  const states = stateNames(c.memberStates);
  const factsOpen = S.facts === c.cve;
  const f = factsOpen ? craFacts(c, {}, now) : null;
  return `<div class="ddl-card${over ? " over" : ""}" data-case="${E(c.cve)}">
    <div class="ddl-case"><h3>${E(c.cve)} in ${E((c.assets || []).join(", "))}</h3>
      <p>Known exploited: added to the CISA KEV catalogue${c.kevDateAdded ? " on " + E(c.kevDateAdded) : ""}. Became aware ${E(aware)}. <a href="${E(CRA.source.url)}" target="_blank" rel="noopener">Article 14(2)</a>: early warning within 24 hours and vulnerability notification within 72 hours of becoming aware, final report within 14 days after a fix or mitigation is available.</p>
      <div class="ddl-acts" style="margin:0 0 8px"><button class="ddl-btn pri" data-act="facts">${factsOpen ? "Hide facts" : "Copy early-warning facts"}</button><button class="ddl-btn" data-act="edit">Edit case</button></div>
    </div>
    ${f ? `<div class="ddl-facts"><div class="hd">Early-warning facts<button class="ddl-btn" data-act="copy">Copy</button></div><table>${f.rows.map(([l, v]) => `<tr><td>${E(l)}</td><td>${/^https:\/\//.test(v) ? `<a href="${E(v)}" target="_blank" rel="noopener">${E(v)}</a>` : E(v)}</td></tr>`).join("")}</table><p class="ddl-note">${E(CRA.where)} ${E(DISCLAIMER)}</p></div>` : ""}
    ${S.open.has("edit:" + c.cve) ? `<div class="ddl-edit">
      <div class="ddl-f"><label for="dlAw-${E(c.cve)}">Became aware</label><div class="now">${E(utc(c.awareAt))}</div><input id="dlAw-${E(c.cve)}" type="datetime-local" data-f="aware"><p class="hint">Correct it if you knew earlier or later. Your local time.</p></div>
      <div class="ddl-f"><label for="dlFx-${E(c.cve)}">Fix or mitigation available</label><div class="now">${c.fixAt ? E(utc(c.fixAt)) : "Not marked yet"}</div><input id="dlFx-${E(c.cve)}" type="datetime-local" data-f="fix"><p class="hint">Leave empty to use now. This starts the 14-day final report clock.</p><div class="rowb"><button class="ddl-btn" data-act="fix">Mark fix available</button>${c.fixAt ? '<button class="ddl-btn" data-act="unfix">Clear</button>' : ""}</div></div>
      <div class="ddl-f"><label for="dlMs-${E(c.cve)}">Member States</label><div class="now">${states.length ? E(states.join(", ")) : "Not entered yet"}</div><input id="dlMs-${E(c.cve)}" data-f="states" placeholder="DE, FR, NL" value="${E((c.memberStates || []).join(", "))}" autocomplete="off" spellcheck="false"><p class="hint">Where the product is made available: EU country names or two-letter codes, separated by commas.</p></div>
      <div class="ddl-f"><label for="dlMe-${E(c.cve)}">Measures known</label><div class="now">${c.measures ? "Entered" : "Not entered yet"}</div><textarea id="dlMe-${E(c.cve)}" data-f="measures" placeholder="The update or workaround">${E(c.measures || "")}</textarea><p class="hint">Corrective or mitigating measures: what has been done and what users can do.</p></div>
      <div class="ddl-f"><div class="rowb"><button class="ddl-btn pri" data-act="save">Save case</button></div></div>
    </div>` : ""}
    ${list.map((d) => rowHtml(d, now)).join("")}
  </div>`;
}

function paint() {
  const box = S.el && S.el.querySelector("#dlBody"); if (!box || !S.data) return;
  const now = Date.now(), free = isFree(S.ctx);
  const all = sortDeadlines(S.data.deadlines || [], now);
  const cases = new Map((S.data.cases || []).map((c) => [c.cve, c]));
  const live = all.filter((d) => d.status === "open"), closed = all.filter((d) => d.status !== "open");
  // a CRA case is one card with its three clocks, placed where its soonest open clock sorts
  const blocks = [], seen = new Set();
  for (const d of live) {
    if (d.kind === "cra-exploited" && d.group) {
      if (seen.has(d.group)) continue;
      seen.add(d.group);
      const c = cases.get(d.subject && d.subject.value);
      const list = all.filter((x) => x.group === d.group);
      if (c) { blocks.push(caseHtml(c, list, now)); continue; }
    }
    blocks.push(`<div class="ddl-card${stateOf(d, now) === "overdue" ? " over" : ""}">${rowHtml(d, now)}</div>`);
  }
  const overdue = live.filter((d) => stateOf(d, now) === "overdue").length, waiting = live.filter((d) => stateOf(d, now) === "waiting").length;
  const running = live.length - waiting;
  box.innerHTML = `
    <p class="ddl-sub">${live.length ? `${running} open${overdue ? `, <b style="color:#c62828">${overdue} overdue</b>` : ""}${waiting ? `, ${waiting} not started yet` : ""}.` : "No open deadlines."} Times are in UTC, as the clocks run on the server.</p>
    ${blocks.join("") || `<div class="dk-nempty">Nothing is due. A certificate your monitors see expiring shows up here${free ? "" : ", and so do the reporting clocks you opt in to below"}.</div>`}
    ${closed.length ? `<div class="ddl-panel"><h2>Closed <button class="ddl-btn" id="dlClosedT" style="margin-left:6px">${S.showClosed ? "Hide" : "Show " + closed.length}</button></h2>${S.showClosed ? closed.map((d) => `<div class="ddl-card">${rowHtml(d, now)}</div>`).join("") : ""}</div>` : ""}
    ${settingsHtml(free)}`;
  wire(box);
}

// ---- opt-ins and the assets shipped in a product ----------------------------------------------------

function settingsHtml(free) {
  const s = (S.data && S.data.settings) || { cra: false, bod2201: false, shipped: [] };
  const kev = (S.mons || []).some((m) => m.type === "kev-epss" && !m.paused);
  const dis = free ? " disabled" : "";
  const shipped = s.shipped || [];
  const ents = S.graph ? S.graph.filter((e) => !S.pick || e.name.toLowerCase().includes(S.pick.toLowerCase())).slice(0, 300) : null;
  const isOn = (e) => shipped.some((x) => (x.id && x.id === e.id) || (x.name.toLowerCase() === e.name.toLowerCase() && (!x.type || x.type === e.type)));
  return `<div class="ddl-panel" id="dlSettings">
    <h2>Opt-ins</h2>
    <p class="ddl-note" style="margin-top:0">Nothing is assumed. Darknode starts these clocks only when you say they apply to you.</p>
    <label class="ddl-check"><input type="checkbox" id="dlCra"${s.cra ? " checked" : ""}${dis}><span>We make products with digital elements sold in the EU (Cyber Resilience Act)<small>A known-exploited CVE in an asset you mark below as shipped in a product starts the Article 14 clocks: early warning in 24 hours, notification in 72 hours, final report 14 days after the fix. ${E(CRA.applies)}</small></span></label>
    <label class="ddl-check"><input type="checkbox" id="dlBod"${s.bod2201 ? " checked" : ""}${dis}><span>We follow CISA BOD 22-01<small>Each known-exploited CVE in your inventory gets the KEV catalogue's due date. <a href="${E(BOD2201.source.url)}" target="_blank" rel="noopener">The directive</a>.</small></span></label>
    ${free ? `<div class="ddl-warn">Both clocks come from the known-exploited CVE monitor, which is part of Pro. Certificate deadlines from your Free watch are tracked here already. <button class="ddl-btn" id="dlPlans">See Plans</button></div>`
      : (s.cra || s.bod2201) && !kev ? `<div class="ddl-warn">Add a KEV/EPSS watch under Monitors: the clocks start from its new matches. <button class="ddl-btn" id="dlMon">Open Monitors</button></div>` : ""}
    <h2 style="margin-top:14px">Shipped in a product</h2>
    <p class="ddl-note" style="margin-top:0">Mark the assets and components that go into a product you sell. They come from your Security Graph, including components imported from an SBOM (CycloneDX) or a scanner under API &amp; Ingest. ${shipped.length ? shipped.length + " marked." : "None marked yet."}</p>
    ${ents === null ? `<div class="ddl-pickbar"><button class="ddl-btn" id="dlPickLoad">Choose assets</button></div>`
      : `<div class="ddl-pickbar"><input id="dlPickQ" placeholder="Filter by name" aria-label="Filter assets by name" value="${E(S.pick)}" autocomplete="off" spellcheck="false"><button class="ddl-btn pri" id="dlPickSave">Save</button></div>
        <div class="ddl-picklist" id="dlPickList">${ents.length ? ents.map((e) => `<label><input type="checkbox" data-pid="${E(e.id)}"${isOn(e) ? " checked" : ""}><span>${E(e.name)}</span><small>${E(e.type === "SOFTWARE" ? "Software" : "Asset")}</small></label>`).join("") : `<label>No assets or software in the Security Graph${S.pick ? " match that filter" : " yet"}.</label>`}</div>`}
    <p class="ddl-note">${E(DISCLAIMER)} Source: <a href="${E(CRA.source.url)}" target="_blank" rel="noopener">${E(CRA.source.label)}</a>.</p>
  </div>`;
}

async function loadGraph() {
  try {
    const g = await import("/js/security-graph.js"); // singleton: never version
    const P = await import("/js/core/posture.js"); // the same module instance deck-ui.js loads
    S.graph = g.listEntities({ type: ["ASSET", "SOFTWARE"] }).filter((e) => e && e.name && !P.isSimulated(e) && !String(e.source || "").startsWith("monitor:"))
      .map((e) => ({ id: e.id, type: e.type, name: String(e.name) })).sort((a, b) => a.name.localeCompare(b.name));
  } catch (_) { S.graph = []; }
  paint();
}

async function saveSettings(patch) {
  const cur = (S.data && S.data.settings) || {};
  try {
    const r = await call({ op: "dlSettings", settings: { cra: !!cur.cra, bod2201: !!cur.bod2201, shipped: cur.shipped || [], ...patch } });
    S.data.settings = r.settings; B.at = 0;
    toast("Saved", "success");
  } catch (e) { toast(e.message || "Could not save", "error"); }
  paint();
}

// ---- actions --------------------------------------------------------------------------------------

function wire(box) {
  const $ = (s) => box.querySelector(s);
  box.querySelectorAll(".ddl-row").forEach((row) => row.querySelector(".ddl-acts").onclick = (e) => {
    const b = e.target.closest("[data-act]"); if (!b) return;
    const id = row.dataset.id, act = b.dataset.act;
    if (act === "steps") { S.open.has(id) ? S.open.delete(id) : S.open.add(id); paint(); }
    else if (act === "done" || act === "dismiss") closeOne(id, act === "done" ? "done" : "dismissed");
    else if (act === "reopen") change({ op: "dlReopen", id }, "Reopened");
  });
  box.querySelectorAll("[data-case]").forEach((card) => card.querySelectorAll(".ddl-case [data-act], .ddl-facts [data-act], .ddl-edit [data-act]").forEach((b) => b.onclick = () => caseAct(card, card.dataset.case, b.dataset.act)));
  const ct = $("#dlClosedT"); if (ct) ct.onclick = () => { S.showClosed = !S.showClosed; paint(); };
  const cra = $("#dlCra"), bod = $("#dlBod");
  if (cra) cra.onchange = () => saveSettings({ cra: cra.checked });
  if (bod) bod.onchange = () => saveSettings({ bod2201: bod.checked });
  const plans = $("#dlPlans"); if (plans) plans.onclick = () => S.ctx && S.ctx.go && S.ctx.go("plans");
  const mon = $("#dlMon"); if (mon) mon.onclick = () => S.ctx && S.ctx.go && S.ctx.go("monitors");
  const pl = $("#dlPickLoad"); if (pl) pl.onclick = loadGraph;
  const q = $("#dlPickQ");
  if (q) q.oninput = () => { S.pick = q.value; const pos = q.selectionStart; paintPick(); const n = S.el.querySelector("#dlPickQ"); if (n) { n.focus(); try { n.setSelectionRange(pos, pos); } catch (_) {} } };
  const ps = $("#dlPickSave");
  if (ps) ps.onclick = () => {
    const cur = ((S.data && S.data.settings) || {}).shipped || [];
    const shown = new Map((S.graph || []).map((e) => [e.id, e]));
    const boxes = [...box.querySelectorAll("#dlPickList [data-pid]")];
    const visible = new Set(boxes.map((x) => x.dataset.pid));
    // entries not shown under the current filter are kept as they were
    const keep = cur.filter((x) => !(x.id && visible.has(x.id)) && ![...visible].some((id) => shown.get(id) && shown.get(id).name.toLowerCase() === x.name.toLowerCase()));
    const add = boxes.filter((x) => x.checked).map((x) => shown.get(x.dataset.pid)).filter(Boolean).map((e) => ({ id: e.id, type: e.type, name: e.name }));
    const next = [...keep, ...add];
    if (next.length > MAX_SHIPPED) { toast("At most " + MAX_SHIPPED + " assets can be marked as shipped.", "error"); return; }
    saveSettings({ shipped: next });
  };
}
function paintPick() { paint(); }

async function change(body, ok) {
  try { await call(body); B.at = 0; if (ok) toast(ok, "success"); await load(); }
  catch (e) { toast(e.message || "Could not save", "error"); }
}

async function closeOne(id, status) {
  if (!window.dnPrompt) { toast("This needs the in-app dialog, which did not load. Reload the page.", "error"); return; }
  const reason = await window.dnPrompt(status === "done" ? "Mark done" : "Dismiss deadline", {
    desc: status === "done" ? "Say what was done, for example the submission reference. It is kept with the deadline." : "Say why it does not apply. It is kept with the deadline.",
    placeholder: status === "done" ? "Reference or note" : "Reason", textarea: true, submitText: status === "done" ? "Mark done" : "Dismiss",
  });
  if (reason == null) return;
  if (!String(reason).trim()) { toast("A reason is needed.", "error"); return; }
  change({ op: "dlClose", id, status, reason }, status === "done" ? "Marked done" : "Dismissed");
}

const fromLocal = (v) => { const t = v ? new Date(v).getTime() : NaN; return Number.isFinite(t) ? t : null; };

async function caseAct(card, cve, act) {
  const c = ((S.data && S.data.cases) || []).find((x) => x.cve === cve); if (!c) return;
  if (act === "facts") { S.facts = S.facts === cve ? "" : cve; paint(); return; }
  if (act === "edit") { const k = "edit:" + cve; S.open.has(k) ? S.open.delete(k) : S.open.add(k); paint(); return; }
  if (act === "copy") {
    const text = craFacts(c, {}, Date.now()).text;
    try { await navigator.clipboard.writeText(text); toast("Facts copied", "success"); }
    catch (_) { toast("Copy was blocked by the browser. Select the table and copy it instead.", "error"); }
    return;
  }
  const f = (n) => card.querySelector(`[data-f="${n}"]`);
  if (act === "fix") { const v = f("fix") && f("fix").value; const t = v ? fromLocal(v) : Date.now(); if (t == null) { toast("Enter a valid date and time.", "error"); return; } return change({ op: "dlCase", cve, patch: { fixAt: t } }, "Fix marked available: the 14-day clock started"); }
  if (act === "unfix") return change({ op: "dlCase", cve, patch: { fixAt: null } }, "Cleared");
  if (act === "save") {
    const patch = { memberStates: f("states") ? f("states").value : "", measures: f("measures") ? f("measures").value : "" };
    const aw = f("aware") && f("aware").value;
    if (aw) { const t = fromLocal(aw); if (t == null) { toast("Enter a valid date and time.", "error"); return; } patch.awareAt = t; }
    return change({ op: "dlCase", cve, patch }, "Case saved");
  }
}

// ---- the Overview block -----------------------------------------------------------------------------

// Fills `el` (a .dk-ovp panel) with the soonest open deadlines, or hides it when there are none.
export async function mountDeadlineBlock(el, ctx) {
  if (!el) return;
  injectStyle(); startTick();
  const draw = (data) => {
    const now = Date.now();
    const open = sortDeadlines((data && data.deadlines) || [], now).filter((d) => d.status === "open" && d.dueAt);
    if (!open.length || !el.isConnected) { el.hidden = true; return; }
    el.hidden = false;
    el.classList.add("ddl-ov");
    const over = open.filter((d) => d.dueAt <= now).length;
    el.innerHTML = `<h2 data-explain="panel.deadlines">Deadlines${over ? ` <span class="ddl-pill over">${over} overdue</span>` : ""} <span class="mo" role="button" tabindex="0" data-dl-go="1">All deadlines</span></h2>
      ${open.slice(0, 5).map((d) => `<div class="ddl-row">${pill(stateOf(d, now))}<div class="ddl-t"><b>${E(d.title)}</b><span>${E(KIND[d.kind] || d.kind)} · due ${E(utc(d.dueAt))}</span></div>${leftHtml(d, now)}</div>`).join("")}
      ${open.length > 5 ? `<div class="ddl-note">${open.length - 5} more under Deadlines.</div>` : ""}`;
    const go = el.querySelector("[data-dl-go]");
    if (go) { const nav = () => ctx && ctx.go && ctx.go("deadlines"); go.onclick = nav; go.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); nav(); } }; }
  };
  if (!monitoringAvailable()) { el.hidden = true; return; }
  let wid = "me";
  if (!isFree(ctx)) try { wid = (await import("/js/security-graph.js")).activeWorkspaceId() || "me"; } catch (_) {} // singleton: never version
  if (B.data && B.wid === wid && Date.now() - B.at < 60000) { draw(B.data); return; }
  const my = ++B.seq;
  try {
    const data = await call({ op: "deadlines" }, ctx);
    if (my !== B.seq) return;
    B.data = data; B.at = Date.now(); B.wid = wid;
    draw(data);
  } catch (_) { el.hidden = true; }
}
