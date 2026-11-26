// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// The Deck's first five minutes: the overview's first block while a workspace has run no
// scan yet. It runs the same live domain check as the landing (check/domain-check.js),
// shows the real result before any setup, saves it the way the space tools do (a run in
// the Personal history, which ticks "Run your first scan", and findings through the sink
// kit), and offers the free Deck tool that digs into each failing check.
//
// The domain comes from, in order: a /check/<domain> link, the landing's "Fix in the
// Deck" (localStorage dn_first_domain, cleared once it has run), or the user. The sign-up
// email's domain is only offered as a one-click chip, never typed into the field, and
// never for a free-mail provider or a Test Mode / guest identity.
//
// Once a check has run, "Watch this domain" sets up the Free plan's one-domain watch: a
// certificate-expiry and an email/DNS monitor on that domain, checked once a day, alerting by
// email to the account's own verified address (the Worker takes the address from the sign-in
// token and enforces the one-domain limit, worker/free-watch.js).

import { runDomainCheck, normalizeDomain, workDomainFromEmail, domainCheckFindings, domainCheckHeld, runLevel } from "/js/check/domain-check.js?v=1";
import { renderResult, renderPending, escapeHtml as esc } from "/js/check/check-view.js?v=1";
import { recordRun } from "/js/deck/native/ui.js"; // same URL deck-ui and the space tools import

export const FIRST_DOMAIN_KEY = "dn_first_domain";

export function storedFirstDomain() {
  try { return localStorage.getItem(FIRST_DOMAIN_KEY) || ""; } catch (_) { return ""; }
}
function clearStored() { try { localStorage.removeItem(FIRST_DOMAIN_KEY); } catch (_) {} }

// The Deck gets a trimmed user ({uid, displayName, email, photoURL}), so a Test Mode / app
// guest session is told by the shared test address and its random per-session uid prefix.
const isTestIdentity = (u) => !!(u && (u.isAnonymous || u.email === "test@darknode.ai" || /^(test|app-guest)-/.test(u.uid || "")
  || (u.providerData || []).some((p) => p && p.providerId === "test")));

// Survives overview re-renders for this page load: the block is redrawn into each new slot.
const S = { domain: "", res: null, running: false, saved: null, error: "", seq: 0, slot: null, ctx: null, watch: null };

function toolLabel(id) {
  const c = S.ctx;
  if (!c || (c.isLocked && c.isLocked("tool:" + id))) return "";
  return (c.toolName && c.toolName(id)) || "";
}

function paint() {
  const slot = S.slot;
  if (!slot || !slot.isConnected) return;
  const out = slot.querySelector(".dk-fr-out"), msg = slot.querySelector(".dk-fr-msg"), saved = slot.querySelector(".dk-fr-saved");
  const btn = slot.querySelector(".dk-fr-form button[type=submit]");
  if (btn) { btn.disabled = S.running; btn.textContent = S.running ? "Checking…" : "Check domain"; }
  slot.querySelectorAll(".dk-fr-chip").forEach((b) => { b.disabled = S.running; });
  msg.textContent = S.error; msg.hidden = !S.error;
  if (S.res) {
    out.hidden = false;
    out.innerHTML = S.res.checks && S.res.checks.length ? renderResult(S.res, { running: S.running, toolLabel: S.running ? null : toolLabel }) : renderPending(S.res.domain);
  } else { out.hidden = true; out.innerHTML = ""; }
  saved.hidden = !S.saved;
  if (S.saved) saved.innerHTML = savedHtml(S.saved);
  const watch = slot.querySelector(".dk-fr-watch");
  const showWatch = !!(S.res && S.res.checks && S.res.checks.length && !S.running);
  watch.hidden = !showWatch;
  watch.classList.toggle("err", !!(showWatch && S.watch && S.watch.domain === S.res.domain && S.watch.state === "error"));
  if (showWatch) watch.innerHTML = watchHtml();
}

// ---- "Watch this domain" -------------------------------------------------------------------
const WATCH_TYPES = ["cert-expiry", "email-posture"];
const DAY = 86400000;
const isFree = () => { const t = S.ctx && S.ctx.tier; return !t || t === "free"; };
const hostsOf = (m) => ((m && m.config && m.config.domains) || []).map((d) => normalizeDomain(d)).filter(Boolean);
const goBtn = (act, label) => `<button type="button" class="dk-tibtn" data-fr-go="${act}">${label}</button>`;

function watchHtml() {
  const d = S.res.domain, w = S.watch && S.watch.domain === d ? S.watch : null;
  if (!w || w.state === "busy") {
    const busy = !!w;
    return `<div class="dk-fr-wtx"><b>Watch ${esc(d)}</b><br>Get an email when its certificate is close to expiry, or when an email or DNS record (SPF, DMARC, MX, CAA) is removed or weakened. Checked once a day${isFree() ? ". The Free plan watches one domain" : ""}.</div>
      <div class="dk-fr-wbtns"><button type="button" class="dk-tibtn on" data-fr-watch="1"${busy ? " disabled" : ""}>${busy ? "Setting up…" : "Watch this domain"}</button></div>`;
  }
  if (w.state === "on") {
    const where = w.to ? `Alerts go by email to <b>${esc(w.to)}</b>, at most 5 emails a day.` : w.emailAll ? "Alerts go by email to your account address, at most 5 emails a day." : "Alerts go to the channels set on each monitor.";
    const head = w.paused ? `The watch on ${esc(d)} is turned off.` : (w.already ? "Already watching " : "Watching ") + esc(d) + ".";
    const body = w.paused ? "Turn it back on under Monitors to check its certificate and email/DNS records once a day."
      : `Its certificate (expiry within 21 days) and its email/DNS records (SPF, DMARC, MX, CAA) are checked once a day. ${where} Turn the watch off any time under Monitors.`;
    return `<div class="dk-fr-wtx"><b>${head}</b> ${body}</div><div class="dk-fr-wbtns">${goBtn("monitors", "Open Monitors")}</div>`;
  }
  if (w.state === "conflict") {
    return `<div class="dk-fr-wtx"><b>Your Free plan already watches ${esc(w.other)}.</b> The Free plan watches one domain. To watch ${esc(d)} instead, delete the watch on ${esc(w.other)} under Monitors, or request an upgrade under Plans.</div>
      <div class="dk-fr-wbtns">${goBtn("monitors", "Open Monitors")}${goBtn("plans", "See Plans")}</div>`;
  }
  return `<div class="dk-fr-wtx">${esc(w.msg)}</div><div class="dk-fr-wbtns">${w.plan ? goBtn("plans", "See Plans") : '<button type="button" class="dk-tibtn" data-fr-watch="1">Try again</button>'}</div>`;
}

async function watchDomain() {
  const domain = S.res && S.res.domain;
  if (!domain || S.running || (S.watch && S.watch.domain === domain && S.watch.state === "busy")) return;
  const free = isFree();
  const set = (w) => { if (S.res && S.res.domain === domain) { S.watch = { domain, ...w }; paint(); } };
  set({ state: "busy" });
  try {
    const { monitorApi } = await import("/js/deck/monitor-client.js?v=1");
    // the Free watch lives in the caller's own workspace, whichever one is active
    const opts = { personal: free };
    const mons = ((await monitorApi({ op: "list" }, opts)) || {}).monitors || [];
    if (free) {
      const other = [...new Set(mons.flatMap(hostsOf))].filter((h) => h !== domain);
      if (other.length) return set({ state: "conflict", other: other[0] });
    }
    const mine = mons.filter((m) => WATCH_TYPES.includes(m.type) && hostsOf(m).includes(domain));
    const made = [];
    for (const type of WATCH_TYPES) {
      if (mine.some((m) => m.type === type)) continue;
      const monitor = { name: (type === "cert-expiry" ? "Certificate: " : "Email and DNS: ") + domain, type, config: type === "cert-expiry" ? { domains: [domain], warnDays: 21 } : { domains: [domain] }, intervalMs: DAY, channels: [{ type: "email" }] };
      const r = await monitorApi({ op: "upsert", monitor }, opts);
      if (r && r.monitor) made.push(r.monitor);
    }
    const all = mine.concat(made);
    const mail = all.flatMap((m) => m.channels || []).find((c) => c.type === "email" && c.mine && c.to);
    set({ state: "on", already: !made.length, paused: all.some((m) => m.paused), to: mail ? mail.to : "", emailAll: all.every((m) => (m.channels || []).some((c) => c.type === "email")) });
  } catch (e) {
    const msg = (e && e.message) || "The watch could not be set up. Try again.";
    set({ state: "error", plan: !!(e && e.plan), msg: !(e && e.status) && /^Sign in/.test(msg) ? "Sign in with your own account to watch a domain. Alerts go to its verified email address." : msg });
  }
}

function savedHtml(sv) {
  const c = S.ctx || {};
  const where = c.isLocked && !c.isLocked("scene:findings") ? { act: "findings", label: "Open findings" }
    : c.isLocked && !c.isLocked("tool:secgraph") ? { act: "secgraph", label: "Open the Security Graph" } : null;
  const text = !sv.ok ? "The result is shown above, but it could not be saved to this workspace."
    : sv.findings ? `<b>Saved to this workspace.</b> ${sv.findings} finding${sv.findings === 1 ? "" : "s"} recorded for ${esc(sv.domain)}, each linked to the tool that fixes it.`
      : `<b>Saved to this workspace.</b> No failing or warning checks on ${esc(sv.domain)}.`;
  return `<span>${text}</span>${sv.ok && sv.findings && where ? `<button type="button" class="dk-tibtn" data-fr-go="${where.act}">${where.label}</button>` : ""}`;
}

async function save(res, seq) {
  const findings = domainCheckFindings(res);
  const failing = res.checks.filter((c) => c.status === "fail").length;
  // a run in the Personal history: "Run your first scan" reads it, and My domain lists it
  try { recordRun("personal", { tool: "domain", target: res.domain, summary: "Grade " + res.grade + " (" + failing + " failing)", level: runLevel(res), score: res.score, grade: res.grade }); } catch (_) {}
  let out = null;
  try {
    const sink = await import("/js/core/sink.js");
    out = await sink.publishFindings("domaincheck", findings, { dataset: "domaincheck " + res.domain, held: domainCheckHeld(res), quiet: true });
  } catch (_) { out = null; }
  if (seq !== S.seq) return;
  S.saved = { ok: !!out, findings: findings.length, domain: res.domain };
  paint();
  if (S.ctx && S.ctx.onSaved) { try { S.ctx.onSaved(); } catch (_) {} }
}

async function run(raw) {
  const domain = normalizeDomain(raw);
  if (!domain) {
    S.error = String(raw || "").trim() ? "That is not a domain name. Enter one like example.com." : "Enter a domain, like example.com.";
    paint();
    return;
  }
  const seq = ++S.seq;
  Object.assign(S, { domain, res: { domain, checks: [] }, running: true, saved: null, error: "" });
  paint();
  try {
    const res = await runDomainCheck(domain, { onProgress: (r) => { if (seq === S.seq) { S.res = r; paint(); } } });
    if (seq !== S.seq) return;
    Object.assign(S, { res, running: false });
    paint();
    await save(res, seq);
  } catch (e) {
    if (seq !== S.seq) return;
    Object.assign(S, { res: null, running: false, error: (e && e.message) || "The check failed. Try again." });
    paint();
  }
}

/**
 * Draw the block into `slot` (an empty element at the top of the overview).
 * ctx = { user, tier, pending, isLocked(key), toolName(id), openTool(id), go(scene), onSaved() }
 */
export function mountFirstRun(slot, ctx) {
  S.slot = slot; S.ctx = ctx;
  const chip = isTestIdentity(ctx.user) ? "" : workDomainFromEmail(ctx.user && ctx.user.email);
  slot.innerHTML = `<div class="dk-fr" role="region" aria-label="Check your domain">
    <div class="dk-fr-h"><b>Start with your domain</b><p>See where you stand before setting anything up: email authentication, HTTPS, security headers, DNS hardening and security.txt, read live from public records.</p></div>
    <form class="dk-actform dk-fr-form" novalidate><input type="text" placeholder="example.com" aria-label="Domain to check" autocomplete="off" autocapitalize="off" spellcheck="false"><button class="dk-tibtn on" type="submit">Check domain</button></form>
    ${chip ? `<div class="dk-fr-chips"><span>From your sign-up email:</span><button type="button" class="dk-fr-chip" data-fr-domain="${esc(chip)}">Check ${esc(chip)}</button></div>` : ""}
    <p class="dk-fr-help">Use a domain you own or manage. The result is saved to this workspace, with each issue as a finding.</p>
    <p class="dk-fr-msg" role="alert" hidden></p>
    <div class="dk-fr-out" aria-live="polite" hidden></div>
    <div class="dk-fr-saved" hidden></div>
    <div class="dk-fr-watch" aria-live="polite" hidden></div>
  </div>`;
  const form = slot.querySelector(".dk-fr-form"), input = form.querySelector("input");
  form.addEventListener("submit", (e) => { e.preventDefault(); if (!S.running) { run(input.value); input.value = ""; } });
  slot.addEventListener("click", (e) => {
    const t = e.target.closest("button");
    if (!t || !slot.contains(t)) return;
    if (t.dataset.frDomain && !S.running) run(t.dataset.frDomain);
    else if (t.dataset.dmcTool && S.ctx.openTool) S.ctx.openTool(t.dataset.dmcTool);
    else if (t.dataset.frWatch) watchDomain();
    else if (t.dataset.frGo === "secgraph" && S.ctx.openTool) S.ctx.openTool("secgraph");
    else if (t.dataset.frGo && S.ctx.go) S.ctx.go(t.dataset.frGo);
  });
  paint();
  // a /check/<domain> link or the landing's hand-off runs at once; the hand-off key is
  // cleared as soon as it is used, so it never re-runs on a later visit
  const stored = storedFirstDomain();
  const pending = normalizeDomain(ctx.pending || stored);
  if (stored) clearStored();
  if (pending && !S.running && pending !== (S.res && S.res.domain)) run(pending);
}
