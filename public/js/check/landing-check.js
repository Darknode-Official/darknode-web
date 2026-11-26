// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Signed-out domain check: the landing hero form and the shareable /check/<domain> page.
// Both run check/domain-check.js live in the visitor's browser. Nothing is stored and no
// account is needed; the only thing kept is the domain in localStorage (dn_first_domain)
// when the visitor chooses to continue in the Deck, so the Deck can run it on first open.

import { renderResult, renderPending } from "/js/check/check-view.js?v=1";

const loadCheck = () => import("/js/check/domain-check.js?v=1");
const CHECK_PATH = /^\/check\/([^/]+)\/?$/;
export const shareUrl = (domain) => location.origin + "/check/" + encodeURIComponent(domain);

// The domain in a /check/<domain> path, or null on any other path.
export function checkPathDomain(pathname) {
  const m = CHECK_PATH.exec(String(pathname || ""));
  if (!m) return null;
  try { return decodeURIComponent(m[1]); } catch (_) { return m[1]; }
}

function setNoindex() {
  let robots = document.querySelector('meta[name="robots"]');
  if (!robots) { robots = document.createElement("meta"); robots.name = "robots"; document.head.appendChild(robots); }
  robots.content = "noindex";
  const canon = document.querySelector('link[rel="canonical"]'); if (canon) canon.remove(); // a noindex page names no canonical
}

async function copyLink(btn, domain) {
  const url = shareUrl(domain);
  const label = btn.textContent;
  try {
    await navigator.clipboard.writeText(url);
    btn.textContent = "Link copied";
  } catch (_) {
    // no clipboard permission: show the link selected so it can be copied by hand
    let box = btn.parentElement.querySelector(".dmc-linkbox");
    if (!box) { box = document.createElement("input"); box.className = "dmc-linkbox"; box.readOnly = true; box.setAttribute("aria-label", "Link to this result"); btn.insertAdjacentElement("afterend", box); }
    box.value = url; box.focus(); box.select();
    btn.textContent = "Copy the link";
  }
  setTimeout(() => { btn.textContent = label; }, 2200);
}

// The bar under a finished result: share it, and continue in the Deck. The wording never
// promises monitoring (monitors are a Pro feature); it says what the free account does.
function actionsBar(res, actions) {
  const bar = document.createElement("div");
  bar.className = "dmc-next";
  const open = res.checks.filter((c) => c.status === "fail" || c.status === "warn").length;
  bar.innerHTML = `<div class="dmc-next-copy"><b>${open ? "Fix these in the Deck, free account" : "Save this result in the Deck, free account"}</b>
      <span>${open ? "The Deck saves each issue as a finding and opens the tool that fixes it." : "The Deck saves this check to your workspace so you have a baseline."} This domain is checked again when you first open it.</span></div>
    <div class="dmc-next-btns"><button type="button" class="btn lg dmc-cta">${open ? "Fix in the Deck" : "Save in the Deck"}</button><button type="button" class="btn lg ghost dmc-copy">Copy link</button></div>`;
  bar.querySelector(".dmc-cta").addEventListener("click", () => {
    try { localStorage.setItem("dn_first_domain", res.domain); } catch (_) {}
    if (actions && actions.onGetStarted) actions.onGetStarted();
  });
  bar.querySelector(".dmc-copy").addEventListener("click", (e) => copyLink(e.currentTarget, res.domain));
  return bar;
}

// Run one check into `out`, rendering progressively. Returns the final result or null.
let runSeq = 0;
async function runInto(out, raw, { actions, msg, button, onStart }) {
  const seq = ++runSeq;
  const say = (t) => { if (msg) { msg.textContent = t || ""; msg.hidden = !t; } };
  say("");
  const mod = await loadCheck().catch(() => null);
  if (seq !== runSeq) return null;
  if (!mod) { say("The checker did not load. Check your connection and try again."); return null; }
  const domain = mod.normalizeDomain(raw);
  if (!domain) { say(String(raw || "").trim() ? "That is not a domain name. Enter one like example.com." : "Enter a domain, like example.com."); return null; }
  out.hidden = false;
  out.innerHTML = renderPending(domain); // darknode-ignore: renderPending escapes every value it interpolates (check-view.js esc); the domain is validated by normalizeDomain first
  if (onStart) onStart();
  const prevLabel = button ? button.textContent : "";
  if (button) { button.disabled = true; button.textContent = "Checking…"; }
  try {
    const res = await mod.runDomainCheck(domain, { onProgress: (r) => { if (seq === runSeq) out.innerHTML = renderResult(r, { running: true }); } });
    if (seq !== runSeq) return null;
    out.innerHTML = renderResult(res); // darknode-ignore: renderResult escapes every value, including DNS and header text from the checked domain (check-view.js esc)
    out.firstElementChild.appendChild(actionsBar(res, actions));
    return res;
  } catch (e) {
    if (seq !== runSeq) return null;
    out.innerHTML = ""; out.hidden = true;
    say((e && e.message) || "The check failed. Try again.");
    return null;
  } finally {
    if (button && seq === runSeq) { button.disabled = false; button.textContent = prevLabel; }
  }
}

function wireForm(form, out, actions, onDone) {
  const input = form.querySelector("input");
  const button = form.querySelector("button[type=submit]");
  const msg = form.querySelector(".dmc-msg");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    // bring the result into view when it starts below the fold (the hero on a phone)
    const onStart = () => { const r = out.getBoundingClientRect(); if (r.top > window.innerHeight * 0.6 || r.top < 0) out.scrollIntoView({ behavior: "smooth", block: "start" }); };
    const res = await runInto(out, input.value, { actions, msg, button, onStart });
    if (res && onDone) onDone(res);
  });
}

// The /check/<domain> page: replaces the landing sections, like the other public pages.
function mountCheckPage(view, actions, raw) {
  view.querySelectorAll(".section, .hero, .cta-final").forEach((sec) => { sec.hidden = true; });
  setNoindex();
  const page = document.createElement("section");
  page.className = "section dn-checkpage";
  page.innerHTML = `<div class="wrap">
    <div class="dedicated-page-header dn-pubbar"><a class="dedicated-back" href="/"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> Back to home</a><span class="dn-pubnote">Free to use, no account needed.</span><button class="btn sm" type="button">Sign in for the full platform</button></div>
    <h1 class="dmc-ph">Domain check</h1>
    <p class="dmc-psub">Run live in your browser when this page opened, from public DNS records, HTTP responses and certificate logs. Nothing about it is stored, so the link always shows the current state.</p>
    <div class="dmc-out" id="dmcOut"></div>
    <form class="dmc-form dmc-form-page" id="dmcForm" novalidate>
      <label class="dmc-lbl" for="dmcIn">Check another domain</label>
      <div class="dmc-field"><input id="dmcIn" type="text" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="example.com" aria-describedby="dmcHelp"><button class="btn lg" type="submit">Check domain</button></div>
      <p class="dmc-help" id="dmcHelp">Reads public DNS records, HTTP headers and certificate logs only. Use a domain you own or are allowed to assess.</p>
      <p class="dmc-msg" role="alert" hidden></p>
    </form>
  </div>`;
  page.querySelector(".dedicated-back").addEventListener("click", (e) => { e.preventDefault(); window.location.href = "/"; });
  page.querySelector(".dn-pubbar .btn").addEventListener("click", () => actions && actions.onSignIn && actions.onSignIn());
  view.prepend(page);
  const out = page.querySelector("#dmcOut");
  const form = page.querySelector("#dmcForm");
  const show = (res) => {
    // the address bar always names the domain on screen, so a copied URL shares this result
    try { const p = "/check/" + encodeURIComponent(res.domain); if (location.pathname !== p) history.replaceState(history.state, "", p); } catch (_) {}
    document.title = "Domain check: " + res.domain + " — Darknode";
  };
  wireForm(form, out, actions, (res) => { show(res); form.querySelector("input").value = ""; });
  document.title = "Domain check — Darknode";
  window.scrollTo(0, 0);
  runInto(out, raw, { actions, msg: form.querySelector(".dmc-msg") }).then((res) => { if (res) show(res); });
}

/** Wire the hero form, or build the /check/<domain> page when the path is one. */
export function mountLandingCheck(view, actions) {
  const raw = checkPathDomain(location.pathname);
  if (raw != null) return mountCheckPage(view, actions, raw);
  const form = view.querySelector(".hero #dmcForm");
  const out = view.querySelector(".hero #dmcOut");
  if (form && out) wireForm(form, out, actions);
}

