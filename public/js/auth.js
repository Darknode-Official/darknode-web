// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","sentinel-b4194.web.app","sentinel-b4194-6173e.web.app","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d}))throw document.body.innerHTML="",new Error("unlicensed")}());
import { auth, db, googleProvider, githubProvider, OWNER_EMAIL } from "/js/firebase.js";
import { collection as fbCollection, addDoc as fbAddDoc, serverTimestamp as fbServerTimestamp } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";
import {
  onAuthStateChanged, signInWithRedirect, getRedirectResult, signOut,
  createUserWithEmailAndPassword, signInWithEmailAndPassword,
  sendEmailVerification, sendPasswordResetEmail, reload,
  setPersistence, browserLocalPersistence
} from "https://www.gstatic.com/firebasejs/12.17.0/firebase-auth.js";
import {
  doc, getDoc, setDoc, serverTimestamp
} from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";
let MORE = [], CATALOG = [], CATEGORIES = [];
import("/js/toolkit.js").then(m => { MORE = m.MORE; CATALOG = m.CATALOG; CATEGORIES = m.CATEGORIES; });
import { startTour, tourDone } from "/js/tour.js";
let _landing = null;
async function loadLanding() { if (!_landing) _landing = await import("/js/landing.js"); return _landing; }
import {
  renderThreat, renderCheats, renderLearn, homeWidgetsHTML, wireHome, COUNTS,
  CHEATS, RESOURCES,
} from "/js/cyber.js";
let _learnHub = null;
async function loadLearnHub() { if (!_learnHub) { _learnHub = await import("/js/learn-hub.js"); } return _learnHub; }
import { emailConfigured, sendCode, sendLoginAlert, genCode, hashCode, deviceInfo } from "/js/notify.js";
import { initSaved } from "/js/saved.js";
import("/js/shell-bridge.js").then(m => {
  window.shellIsConnected = m.shellIsConnected;
  window.shellConnect = m.shellConnect;
  window.shellStatus = m.shellStatus;
  window.shellExec = m.shellExec;
});

if (window.__boot) window.__boot.set(40);

const _errSeen = new Set();
function _logError(data) {
  const key = data.message + (data.source || '') + (data.line || '');
  if (_errSeen.has(key) || _errSeen.size >= 20) return;
  _errSeen.add(key);
  fbAddDoc(fbCollection(db, "errors"), {
    ...data, email: auth.currentUser?.email || "anonymous",
    uid: auth.currentUser?.uid || "", ts: fbServerTimestamp(),
  }).catch(() => {});
}
if (window.__errorQueue) { window.__errorQueue.splice(0).forEach(e => _logError(e)); window.__errorQueue = null; }
window.addEventListener("error", (ev) => {
  _logError({ message: String(ev.message || ""), source: ev.filename || "", line: ev.lineno, col: ev.colno, stack: ev.error?.stack?.slice(0, 2000) || "", url: location.href, ua: navigator.userAgent, clientTs: Date.now() });
});
window.addEventListener("unhandledrejection", (ev) => {
  const r = ev.reason || {};
  _logError({ message: r.message || String(r), source: "unhandledrejection", stack: r.stack?.slice(0, 2000) || "", url: location.href, ua: navigator.userAgent, clientTs: Date.now() });
});

const userSlot = document.getElementById("user-slot");
const view = document.getElementById("view");
let appShow = null;   // set by renderApp so the command palette can navigate
const _bootStart = performance.now();
function dismissBoot() {
  if (window.__boot) window.__boot.set(100);
  const b = document.getElementById("bootscreen"); if (!b) return;
  const elapsed = performance.now() - _bootStart;
  const delay = Math.max(0, 2200 - elapsed);
  setTimeout(() => {
    const inner = b.querySelector(".boot-inner"); if (inner) inner.classList.add("exit");
    setTimeout(() => { b.style.opacity = "0"; }, 150);
    setTimeout(() => b.remove(), 650);
  }, delay);
}
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const errText = (e) => {
  const map = {
    "auth/invalid-credential": "Wrong email or password.",
    "auth/wrong-password": "Wrong email or password.",
    "auth/user-not-found": "No account with that email.",
    "auth/email-already-in-use": "That email already has an account — try signing in.",
    "auth/weak-password": "Password must be at least 6 characters.",
    "auth/invalid-email": "That doesn't look like a valid email.",
    "auth/popup-closed-by-user": "Sign-in was cancelled.",
    "auth/operation-not-allowed": "This sign-in method isn't enabled in Firebase yet.",
    "auth/too-many-requests": "Too many attempts — wait a bit and retry.",
    "auth/account-exists-with-different-credential": "That email is already registered with a different sign-in method — use that one.",
  };
  return map[e?.code] || e?.message || String(e);
};

async function ensureUserDoc(user) {
  try {
    await setDoc(doc(db, "users", user.uid), {
      email: user.email, name: user.displayName || "", lastSeen: serverTimestamp(),
    }, { merge: true });
  } catch (_) { /* rules/offline - non-fatal */ }
}

// ---------- views ----------
function openFeedback(user) {
  const old = document.getElementById("fbModal"); if (old) old.remove();
  const wrap = document.createElement("div");
  wrap.id = "fbModal"; wrap.className = "fb-modal";
  wrap.innerHTML = `
    <div class="fb-box">
      <div class="fb-h">Send feedback / report a bug</div>
      <div class="fb-types" id="fbTypes">
        <button class="fb-type on" data-t="bug">Bug</button>
        <button class="fb-type" data-t="feedback">Feedback</button>
        <button class="fb-type" data-t="idea">Idea</button>
      </div>
      <textarea id="fbMsg" class="tk-in" rows="5" placeholder="What happened, or what would you like to see? The more detail the better."></textarea>
      <div class="fb-foot"><span class="fb-status" id="fbStatus"></span><span style="flex:1"></span><button class="btn ghost" id="fbCancel">Cancel</button><button class="btn" id="fbSend">Send</button></div>
    </div>`;
  document.body.appendChild(wrap);
  const q = (s) => wrap.querySelector(s);
  let type = "bug";
  q("#fbTypes").onclick = (e) => { const b = e.target.closest("[data-t]"); if (!b) return; type = b.dataset.t; q("#fbTypes").querySelectorAll(".fb-type").forEach((x) => x.classList.toggle("on", x === b)); };
  const close = () => wrap.remove();
  q("#fbCancel").onclick = close;
  wrap.onclick = (e) => { if (e.target === wrap) close(); };
  q("#fbSend").onclick = async () => {
    const msg = q("#fbMsg").value.trim();
    if (!msg) { q("#fbStatus").textContent = "please write a message first"; return; }
    q("#fbSend").disabled = true; q("#fbStatus").textContent = "sending…";
    try {
      await fbAddDoc(fbCollection(db, "feedback"), {
        type, message: msg.slice(0, 4000),
        email: (user && user.email) || "anonymous", uid: (user && user.uid) || "",
        ts: fbServerTimestamp(), userAgent: navigator.userAgent, url: location.href, resolved: false,
      });
      q("#fbStatus").textContent = "Sent — thank you!";
      setTimeout(close, 900);
    } catch (err) { q("#fbSend").disabled = false; q("#fbStatus").textContent = "failed: " + err.message; }
  };
  q("#fbMsg").focus();
}

function showLanding() {
  dismissBoot();
  document.body.classList.remove("app");
  document.body.classList.add("landing");
  userSlot.innerHTML = `<a class="nav-link" id="nav-signin">Sign in</a><button class="btn" id="nav-start">Get Started</button>`;
  document.getElementById("nav-signin").onclick = () => renderAuth("signin");
  document.getElementById("nav-start").onclick = () => renderAuth("signup");
  loadLanding().then(m => m.renderLanding(view, {
    onGetStarted: () => renderAuth("signup"),
    onSignIn: () => renderAuth("signin"),
  }));
}

function renderAuth(mode = "signin") {
  document.body.classList.remove("landing", "app");
  userSlot.innerHTML = "";
  const isSignup = mode === "signup";
  view.innerHTML = `
    <section class="card auth-card">
      <a class="auth-back" id="authBack">&larr; Back</a>
      <div class="auth-logo"><img src="/logo-light.svg" alt=""></div>
      <h1>${isSignup ? "Create your account" : "Welcome back"}</h1>
      <p class="muted">${isSignup ? "Set up your Darknode console in seconds." : "Sign in to your Darknode console."}</p>
      <button class="btn google" id="google">Continue with Google</button>
      <button class="btn github" id="github">Continue with GitHub</button>
      <div class="or"><span></span>or<span></span></div>
      <form id="pwform" autocomplete="on">
        <input type="email" id="email" placeholder="Email" autocomplete="email" required>
        <input type="password" id="password" placeholder="Password (6+ chars)" autocomplete="${isSignup ? "new-password" : "current-password"}" required>
        <button class="btn" type="submit">${isSignup ? "Create account" : "Sign in"}</button>
      </form>
      <div class="auth-links">
        ${isSignup
          ? `<a id="toSignin">Have an account? Sign in</a>`
          : `<a id="toSignup">Create account</a><a id="forgot">Forgot password?</a>`}
      </div>
      <p id="err" class="auth-err"></p>
    </section>`;

  const err = (m) => { document.getElementById("err").textContent = m; };
  document.getElementById("google").onclick = async () => {
    err("");
    try { try { sessionStorage.setItem("sw_fresh_signin", "1"); } catch (_) {} await signInWithRedirect(auth, googleProvider); }
    catch (e) { try { sessionStorage.removeItem("sw_fresh_signin"); } catch (_) {} err(errText(e)); }
  };
  document.getElementById("github").onclick = async () => {
    err("");
    try { try { sessionStorage.setItem("sw_fresh_signin", "1"); } catch (_) {} await signInWithRedirect(auth, githubProvider); }
    catch (e) { try { sessionStorage.removeItem("sw_fresh_signin"); } catch (_) {} err(errText(e)); }
  };
  document.getElementById("pwform").onsubmit = async (ev) => {
    ev.preventDefault(); err("");
    const email = document.getElementById("email").value.trim();
    const pw = document.getElementById("password").value;
    try {
      if (isSignup) {
        const cred = await createUserWithEmailAndPassword(auth, email, pw);
        if (emailConfigured()) {
          const code = genCode();
          await setDoc(doc(db, "users", cred.user.uid), { email, codeVerified: false, pendingCodeHash: await hashCode(code), pendingCodeExp: Date.now() + 10 * 60 * 1000 }, { merge: true });
          const r = await sendCode(email, code, "");
          if (!r.ok) { await sendEmailVerification(cred.user); }
        } else {
          await sendEmailVerification(cred.user);
        }
      } else {
        try { sessionStorage.setItem("sw_fresh_signin", "1"); } catch (_) {}
        await signInWithEmailAndPassword(auth, email, pw);
      }
    } catch (e) { try { sessionStorage.removeItem("sw_fresh_signin"); } catch (_) {} err(errText(e)); }
  };
  const on = (id, fn) => { const el = document.getElementById(id); if (el) el.onclick = fn; };
  on("authBack", showLanding);
  on("toSignup", () => renderAuth("signup"));
  on("toSignin", () => renderAuth("signin"));
  on("forgot", async () => {
    const email = document.getElementById("email").value.trim();
    if (!email) return err("Enter your email above first, then click Forgot password.");
    try { await sendPasswordResetEmail(auth, email); err(""); document.getElementById("err").className = "auth-ok"; document.getElementById("err").textContent = "Password reset email sent — check your inbox."; }
    catch (e) { err(errText(e)); }
  });
}

function renderVerify(user) {
  dismissBoot();
  document.body.classList.remove("landing", "app");
  userSlot.innerHTML = `<button class="btn ghost" id="signout">Sign out</button>`;
  document.getElementById("signout").onclick = () => signOut(auth);
  view.innerHTML = `
    <section class="card auth-card">
      <h1>Verify your email</h1>
      <p class="muted">We sent a verification link to <strong>${esc(user.email)}</strong>. Open it, then click Reload.</p>
      <button class="btn" id="reload">I've verified — reload</button>
      <button class="btn ghost" id="resend">Resend email</button>
      <p id="err" class="auth-err"></p>
    </section>`;
  document.getElementById("reload").onclick = async () => {
    await reload(user);
    if (user.emailVerified) location.reload();
    else document.getElementById("err").textContent = "Still not verified — check the link in your email.";
  };
  document.getElementById("resend").onclick = async () => {
    try { await sendEmailVerification(user); document.getElementById("err").className = "auth-ok"; document.getElementById("err").textContent = "Sent again."; }
    catch (e) { document.getElementById("err").textContent = errText(e); }
  };
}

// Email-code verification (used when EmailJS is configured).
function renderCodeVerify(user) {
  dismissBoot();
  document.body.classList.remove("landing", "app");
  userSlot.innerHTML = `<button class="btn ghost" id="signout">Sign out</button>`;
  document.getElementById("signout").onclick = () => signOut(auth);
  view.innerHTML = `
    <section class="card auth-card">
      <div class="auth-logo"><img src="/logo-light.svg" alt=""></div>
      <h1>Enter your code</h1>
      <p class="muted">We emailed a 6-digit code to <strong>${esc(user.email)}</strong>. Enter it to finish signing up.</p>
      <input id="code" inputmode="numeric" maxlength="6" placeholder="123456" autocomplete="one-time-code" style="text-align:center;letter-spacing:.4em;font-size:1.3rem">
      <button class="btn" id="verify">Verify</button>
      <button class="btn ghost" id="resend">Resend code</button>
      <p id="err" class="auth-err"></p>`;
  const setMsg = (m, ok) => { const e = document.getElementById("err"); e.textContent = m; e.className = ok ? "auth-ok" : "auth-err"; };
  const resendBtn = document.getElementById("resend");
  let cd = 0, timer = null;
  const startCooldown = (sec) => { cd = sec; resendBtn.disabled = true; clearInterval(timer); timer = setInterval(() => { cd--; if (cd <= 0) { clearInterval(timer); resendBtn.disabled = false; resendBtn.textContent = "Resend code"; } else resendBtn.textContent = "Resend in " + cd + "s"; }, 1000); };
  startCooldown(45); // a code was just sent at sign-up
  document.getElementById("verify").onclick = async () => {
    const code = (document.getElementById("code").value || "").trim();
    try {
      const snap = await getDoc(doc(db, "users", user.uid));
      const d = snap.exists() ? snap.data() : {};
      if (!d.pendingCodeHash || (d.pendingCodeExp && Date.now() > d.pendingCodeExp)) return setMsg("Code expired — tap Resend for a new one.");
      if ((await hashCode(code)) !== d.pendingCodeHash) return setMsg("Incorrect code.");
      await setDoc(doc(db, "users", user.uid), { codeVerified: true, pendingCodeHash: null, pendingCodeExp: null }, { merge: true });
      location.reload();
    } catch (e) { setMsg(errText(e)); }
  };
  resendBtn.onclick = async () => {
    startCooldown(45);
    try {
      const code = genCode();
      await setDoc(doc(db, "users", user.uid), { pendingCodeHash: await hashCode(code), pendingCodeExp: Date.now() + 10 * 60 * 1000 }, { merge: true });
      const r = await sendCode(user.email, code, user.displayName);
      setMsg(r.ok ? "New code sent." : "Couldn't send: " + r.error, r.ok);
    } catch (e) { setMsg(errText(e)); }
  };
}

// New-device sign-in: record it (for the admin log) and, if EmailJS is set up, email an alert.
async function checkLoginDevice(user) {
  try {
    const dev = deviceInfo();
    const ref = doc(db, "users", user.uid);
    const snap = await getDoc(ref);
    const data = snap.exists() ? snap.data() : {};
    const known = data.devices || [];
    if (known.includes(dev.id)) return;
    if (emailConfigured()) await sendLoginAlert(user.email, { name: user.displayName || user.email, time: new Date().toLocaleString(), device: dev.label });
    const logins = (data.logins || []).slice(-9);
    logins.push({ device: dev.label, ts: Date.now() });
    await setDoc(ref, { devices: [...known, dev.id], logins }, { merge: true });
  } catch (_) { /* non-fatal */ }
}

// ---------- appearance ----------
const ACCENTS = ["#00d4ff", "#7c5cff", "#22c55e", "#f59e0b", "#ef4444", "#ec4899"];
function applyAccent(c) {
  document.documentElement.style.setProperty("--acc", c);
  try { localStorage.setItem("sw_accent", c); } catch (_) {}
}
(function () { let a = null; try { a = localStorage.getItem("sw_accent"); } catch (_) {} if (a) applyAccent(a); })();
function applyTheme(m) { document.documentElement.setAttribute("data-theme", m); try { localStorage.setItem("sw_theme", m); } catch (_) {} }
(function () { let t = "dark"; try { t = localStorage.getItem("sw_theme") || "dark"; } catch (_) {} applyTheme(t); })();
function crtOn() { try { return localStorage.getItem("sw_crt") === "1"; } catch (_) { return false; } }
function applyCrt(on) { document.documentElement.classList.toggle("crt", on); try { localStorage.setItem("sw_crt", on ? "1" : "0"); } catch (_) {} }
applyCrt(crtOn());

const LOGO_VARIANTS = {
  "outer-radius": {
    label: "Outer radius",
    svg: '<path d="M10,22 A12,12 0 0 1 22,10 H42 V42 H10 Z" fill="none" stroke="currentColor" stroke-width="6" stroke-linejoin="miter"/><path d="M58,10 H78 A12,12 0 0 1 90,22 V42 H58 Z" fill="none" stroke="currentColor" stroke-width="6" stroke-linejoin="miter"/><path d="M10,58 H42 V90 H22 A12,12 0 0 1 10,78 Z" fill="none" stroke="currentColor" stroke-width="6" stroke-linejoin="miter"/><path d="M58,58 H90 V78 A12,12 0 0 1 78,90 H58 Z" fill="#E09A2B"/>',
  },
  "nested-accent": {
    label: "Nested accent",
    svg: '<rect x="10" y="10" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="58" y="10" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="10" y="58" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="58" y="58" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="66.96" y="66.96" width="14.08" height="14.08" rx="3.5" fill="#E09A2B"/>',
  },
  "thin": {
    label: "Thin",
    svg: '<rect x="10" y="10" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="58" y="10" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="10" y="58" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="58" y="58" width="32" height="32" rx="7" fill="#E09A2B"/>',
  },
  "solid": {
    label: "Solid",
    svg: '<rect x="9" y="9" width="36" height="36" rx="8" fill="currentColor"/><rect x="55" y="9" width="36" height="36" rx="8" fill="currentColor"/><rect x="9" y="55" width="36" height="36" rx="8" fill="currentColor"/><rect x="55" y="55" width="36" height="36" rx="8" fill="#E09A2B"/>',
  },
  "missing": {
    label: "Missing cell",
    svg: '<rect x="10" y="10" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="58" y="10" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="10" y="58" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/>',
  },
};
function logoSvg(key) { const v = LOGO_VARIANTS[key]; if (!v) return ""; return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">${v.svg}</svg>`; }
function logoFavSvg(key) {
  const v = LOGO_VARIANTS[key]; if (!v) return "";
  const style = '<style>*{--c:#101722}@media(prefers-color-scheme:dark){*{--c:#F2F5F9}}</style>';
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">${style}${v.svg.replace(/currentColor/g, "var(--c)")}</svg>`;
}
function applyLogo(key) {
  if (!LOGO_VARIANTS[key]) return;
  try { localStorage.setItem("sw_logo", key); } catch (_) {}
  const mark = document.querySelector(".brand-mark");
  if (mark) { mark.src = "data:image/svg+xml," + encodeURIComponent(logoSvg(key).replace(/currentColor/g, "#F2F5F9")); }
  let fav = document.querySelector('link[rel="icon"]');
  if (!fav) { fav = document.createElement("link"); fav.rel = "icon"; document.head.appendChild(fav); }
  fav.href = "data:image/svg+xml," + encodeURIComponent(logoFavSvg(key));
}
(function () { let l = null; try { l = localStorage.getItem("sw_logo"); } catch (_) {} if (l && LOGO_VARIANTS[l]) applyLogo(l); })();

// ---------- app sections ----------
function _dashDateTime() {
  const now = new Date();
  const opts = { weekday: "long", year: "numeric", month: "long", day: "numeric" };
  const date = now.toLocaleDateString(undefined, opts);
  const time = now.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return { date, time };
}

function _dashRecentActivity() {
  const KEY = "dn_recent_activity";
  let items;
  try { items = JSON.parse(localStorage.getItem(KEY)); } catch (_) {}
  if (!Array.isArray(items) || items.length === 0) {
    // Seed with placeholder entries so the section isn't empty on first load
    items = [
      { text: "Scanned 10.10.14.7", ts: Date.now() - 3600000 },
      { text: "Queried CVE-2024-1234", ts: Date.now() - 7200000 },
      { text: "Generated report", ts: Date.now() - 18000000 },
    ];
    try { localStorage.setItem(KEY, JSON.stringify(items)); } catch (_) {}
  }
  return items.slice(0, 8);
}

function _dashSessionStats() {
  let sessions = 0, aiConvos = 0, toolsUsed = 0;
  try { sessions = parseInt(localStorage.getItem("dn_stat_sessions") || "0", 10) || 0; } catch (_) {}
  try { aiConvos = parseInt(localStorage.getItem("dn_stat_ai_convos") || "0", 10) || 0; } catch (_) {}
  try { toolsUsed = parseInt(localStorage.getItem("dn_stat_tools_used") || "0", 10) || 0; } catch (_) {}
  // Bump session count on each home render (deduplicated per page load)
  if (!window._dnSessionCounted) {
    window._dnSessionCounted = true;
    sessions++;
    try { localStorage.setItem("dn_stat_sessions", String(sessions)); } catch (_) {}
  }
  return { sessions, aiConvos, toolsUsed };
}

function renderContact(main) {
  main.innerHTML = `
    <h1 class="pg-h1">Contact</h1>
    <p class="muted pg-sub">Get in touch with the Darknode team.</p>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;max-width:800px">
      <div class="panel">
        <h2 class="pg-h2" style="margin:0 0 16px">Send a Message</h2>
        <form id="contactForm">
          <div style="display:flex;flex-direction:column;gap:12px">
            <div>
              <label style="font-size:.82rem;color:var(--mut);display:block;margin-bottom:4px">Name</label>
              <input class="tk-f" type="text" id="cfName" placeholder="Your name" required style="width:100%">
            </div>
            <div>
              <label style="font-size:.82rem;color:var(--mut);display:block;margin-bottom:4px">Email</label>
              <input class="tk-f" type="email" id="cfEmail" placeholder="you@example.com" required style="width:100%">
            </div>
            <div>
              <label style="font-size:.82rem;color:var(--mut);display:block;margin-bottom:4px">Subject</label>
              <select class="tk-f" id="cfSubject" style="width:100%">
                <option>General Inquiry</option>
                <option>Bug Report</option>
                <option>Feature Request</option>
                <option>Partnership</option>
                <option>Security Issue</option>
                <option>Billing</option>
                <option>Other</option>
              </select>
            </div>
            <div>
              <label style="font-size:.82rem;color:var(--mut);display:block;margin-bottom:4px">Message</label>
              <textarea class="tk-in" id="cfMessage" rows="6" placeholder="How can we help?" required></textarea>
            </div>
            <button class="btn lg" type="submit" id="cfSubmit" style="margin-top:4px">Send Message</button>
            <p id="cfStatus" style="font-size:.82rem;margin:0"></p>
          </div>
        </form>
        <p class="muted" style="font-size:.72rem;margin-top:12px">Powered by Web3Forms. We typically respond within 24 hours.</p>
      </div>
      <div>
        <div class="panel" style="margin-bottom:16px">
          <h2 class="pg-h2" style="margin:0 0 12px">Other Ways to Reach Us</h2>
          <div style="display:flex;flex-direction:column;gap:12px;font-size:.88rem">
            <div><span class="muted">Email</span><br><strong>contact@darknode.ai</strong></div>
            <div><span class="muted">GitHub</span><br><a href="https://github.com/cashzombs-stack" target="_blank" rel="noopener" style="color:var(--acc)">github.com/cashzombs-stack</a></div>
            <div><span class="muted">Response Time</span><br><strong>Within 24 hours</strong></div>
          </div>
        </div>
        <div class="panel">
          <h2 class="pg-h2" style="margin:0 0 12px">Report a Security Issue</h2>
          <p class="muted" style="font-size:.84rem;margin:0 0 8px">Found a vulnerability? Please disclose responsibly.</p>
          <p style="font-size:.84rem;margin:0">Email <strong>security@darknode.ai</strong> with details. Do not open a public issue.</p>
        </div>
      </div>
    </div>`;
  document.getElementById("contactForm").onsubmit = async (e) => {
    e.preventDefault();
    const btn = document.getElementById("cfSubmit");
    const status = document.getElementById("cfStatus");
    const name = document.getElementById("cfName").value.trim();
    const email = document.getElementById("cfEmail").value.trim();
    const subject = document.getElementById("cfSubject").value;
    const message = document.getElementById("cfMessage").value.trim();
    if (!name || !email || !message) { status.textContent = "Please fill in all fields."; status.style.color = "var(--bad,red)"; return; }
    btn.disabled = true; btn.textContent = "Sending..."; status.textContent = "";
    try {
      const res = await fetch("https://api.web3forms.com/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ access_key: "f64b2617-cee3-4a87-b94c-fb667baab7cc", name, email, subject, message, from_name: "Darknode Contact Form" })
      });
      const data = await res.json();
      if (data.success) {
        status.textContent = "Message sent! We'll get back to you within 24 hours.";
        status.style.color = "var(--ok,#3fb950)";
        document.getElementById("cfName").value = "";
        document.getElementById("cfEmail").value = "";
        document.getElementById("cfMessage").value = "";
        btn.textContent = "Sent!";
      } else {
        status.textContent = "Failed to send. Try emailing contact@darknode.ai directly.";
        status.style.color = "var(--bad,red)";
        btn.disabled = false; btn.textContent = "Send Message";
      }
    } catch (err) {
      status.textContent = "Network error. Try emailing contact@darknode.ai directly.";
      status.style.color = "var(--bad,red)";
      btn.disabled = false; btn.textContent = "Send Message";
    }
  };
}

function renderHome(main, user, isOwner, show) {
  const name = user.displayName ? user.displayName.split(" ")[0] : "";
  const browsers = CATALOG.filter((t) => t.kind === "browser").length;
  const stat = (n, l, s) => `<div class="stat"><div class="stat-n">${n}</div><div class="stat-l">${l}</div>${s ? `<div class="stat-s">${s}</div>` : ""}</div>`;
  const qa = (sec, more, title, desc) => `<button class="qa" data-sec="${sec}" data-more="${more}"><div class="qa-title">${title}</div><div class="qa-desc">${desc}</div></button>`;
  const dt = _dashDateTime();
  const recentItems = _dashRecentActivity();
  const sStats = _dashSessionStats();

  const timeAgo = (ts) => {
    const diff = Date.now() - ts;
    if (diff < 60000) return "just now";
    if (diff < 3600000) return Math.floor(diff / 60000) + "m ago";
    if (diff < 86400000) return Math.floor(diff / 3600000) + "h ago";
    return Math.floor(diff / 86400000) + "d ago";
  };

  main.innerHTML = `
    <div class="dash-hero">
      <div class="dash-hero-top">
        <div class="eyebrow">SECURITY CONSOLE</div>
        <div class="dash-meta">
          <span class="dash-status"><span class="dash-status-dot"></span>All systems operational</span>
          <span class="dash-clock" id="dashClock">${esc(dt.date)} -- ${esc(dt.time)}</span>
        </div>
      </div>
      <h1 class="pg-h1">Welcome back${name ? ", " + esc(name) : ""}</h1>
      <p class="muted pg-sub">Tools, threat intel, cheat sheets, local AI and setup guides &mdash; your whole workflow in one place.</p>
      <div class="hero-actions">
        <button class="btn" data-sec="tools">Browse tools</button>
        <button class="btn ghost" data-sec="cheats">Cheat sheets</button>
        <button class="btn ghost" data-sec="threat">Threat intel</button>
      </div>
    </div>
    <div class="stat-row">
      ${stat(CATALOG.length, "tools", browsers + " run in-browser")}
      ${stat(COUNTS.cheats, "cheat sheets")}
      ${stat(COUNTS.cves, "tracked CVEs")}
      ${stat(COUNTS.resources, "resources")}
      ${stat(CATEGORIES.length, "categories")}
      ${stat(59, "AI modules", "Ollama + cloud")}
      ${stat("571K+", "lines of code", "CLI + web")}
    </div>
    <h2 class="pg-h2">Jump in</h2>
    <div class="qa-grid">
      ${qa("ai", "", "AI assistant", "Chat with your local Ollama &mdash; unrestricted security &amp; coding help.")}
      ${qa("payloads", "", "Payload library", "Copy-ready SQLi, XSS, LFI, SSTI, SSRF and more.")}
      ${qa("snippets", "", "Code snippets", "Everyday one-liners for bash, Python, JS, git, docker, SQL.")}
      ${qa("utils", "", "Utilities", "Run tools in your browser &mdash; encode, hash, decode JWTs, gen shells.")}
      ${qa("tools", "", "Browse tools", "Search and use the catalog &mdash; encoders, hashes, payloads and more.")}
      ${qa("cheats", "", "Cheat sheets", "Copy-paste one-liners for recon, shells, privesc and cracking.")}
      ${qa("threat", "", "Threat intel", "Notable CVEs and a common-ports attack-surface reference.")}
      ${qa("learn", "", "Learn", "Curated hubs: HackTricks, OWASP, PayloadsAllTheThings and more.")}
      ${qa("setup", "aicoding", "Local AI coding", "Run Ollama models on your machine, in the terminal or a browser UI.")}
      ${qa("setup", "toolkit", "Prebuilt toolkit", "Install the whole CLI toolkit + SSH in one command.")}
      ${qa("webshell", "", "Web Shell", "Access a terminal in your browser &mdash; run commands, pull AI models.")}
      ${qa("report", "", "Report Generator", "Generate professional pentest reports from your findings.")}
    </div>
    <div class="dash-extras">
      <div class="dash-extra-col">
        <div class="panel dash-activity-panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Recent activity</h2></div>
          <div class="dash-timeline" id="dashTimeline">
            ${recentItems.map((item) => `<div class="dash-tl-item"><span class="dash-tl-dot"></span><span class="dash-tl-text">${esc(item.text)}</span><span class="dash-tl-time muted">${timeAgo(item.ts)}</span></div>`).join("")}
          </div>
        </div>
      </div>
      <div class="dash-extra-col">
        <div class="panel dash-qstats-panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Quick stats</h2></div>
          <div class="dash-qstats">
            <div class="dash-qs-item"><div class="dash-qs-n">${sStats.sessions}</div><div class="dash-qs-l">Total sessions</div></div>
            <div class="dash-qs-item"><div class="dash-qs-n">${sStats.aiConvos}</div><div class="dash-qs-l">AI conversations</div></div>
            <div class="dash-qs-item"><div class="dash-qs-n">${sStats.toolsUsed}</div><div class="dash-qs-l">Tools used</div></div>
          </div>
        </div>
      </div>
    </div>
    ${isOwner ? `<div class="admin-card"><strong>Owner controls</strong><p class="muted">You're the owner &mdash; admin features live under Admin in the sidebar.</p></div>` : ""}
    ${homeWidgetsHTML()}`;
  main.addEventListener("click", (e) => { const b = e.target.closest("[data-sec]"); if (b) show(b.dataset.sec, b.dataset.more || ""); });
  wireHome(main, show);

  // Live clock update
  const clockEl = main.querySelector("#dashClock");
  if (clockEl) {
    const tickClock = () => {
      const d = _dashDateTime();
      clockEl.textContent = d.date + " -- " + d.time;
    };
    const clockTimer = setInterval(tickClock, 30000);
    // Clean up when the element is removed from DOM
    const obs = new MutationObserver(() => { if (!document.contains(clockEl)) { clearInterval(clockTimer); obs.disconnect(); } });
    obs.observe(document.body, { childList: true, subtree: true });
  }
}

function renderSetup(main, openTo) {
  main.innerHTML = `
    <h1 class="pg-h1">Local setup</h1>
    <p class="muted pg-sub">A website can't run these &mdash; spin them up on your own machine with one copy-paste.</p>
    ${MORE.map((m) => `<div class="card" id="setup-${m.id}"><h3>${esc(m.name)}</h3><p class="muted">${esc(m.desc)}</p>
      <div class="dl-cmd-row"><code class="dl-cmd cmd-block">${esc(m.body)}</code><button class="dl-copy" data-copy="${m.id}">copy</button></div></div>`).join("")}`;
  main.onclick = (e) => {
    const b = e.target.closest("[data-copy]"); if (!b) return;
    const m = MORE.find((x) => x.id === b.dataset.copy);
    navigator.clipboard?.writeText(m.body).then(() => { b.textContent = "copied"; setTimeout(() => (b.textContent = "copy"), 1200); });
  };
  if (openTo) { const el = main.querySelector("#setup-" + openTo); if (el) el.scrollIntoView({ behavior: "smooth", block: "center" }); }
}

function renderSettingsPage(main, user, isOwner) {
  const providers = user.providerData.map((p) => p.providerId.replace(".com", "")).join(", ") || "password";
  const created = user.metadata?.creationTime ? new Date(user.metadata.creationTime).toLocaleDateString() : "—";
  const row = (k, v) => `<div class="set-row"><span class="muted">${k}</span><span>${v}</span></div>`;
  const SET_TABS = [["account", "Account"], ["appearance", "Appearance"], ["security", "Security"], ["apikeys", "API Keys"], ["nexus", "Nexus CLI"], ["about", "About"]];
  const curLogo = (() => { try { return localStorage.getItem("sw_logo") || "nested-accent"; } catch (_) { return "nested-accent"; } })();
  const panels = {
    account: `<h2 class="set-panel-h">Account</h2>
      ${row("Name", esc(user.displayName || "—"))}
      ${row("Email", esc(user.email) + (isOwner ? ' <span class="owner-badge">OWNER</span>' : ""))}
      ${row("Signed in via", esc(providers))}
      ${row("Member since", esc(created))}
      ${row("User ID", '<span class="mono">' + esc(user.uid) + "</span>")}`,
    appearance: `<h2 class="set-panel-h">Appearance</h2>
      <div class="set-row"><span class="muted">Theme</span>
        <span class="seg" id="sw-theme"><button data-t="dark">Dark</button><button data-t="light">Light</button></span></div>
      <div class="set-row"><span class="muted">Accent color</span>
        <span class="swatches" id="sw-acc">${ACCENTS.map((c) => `<button class="swatch" style="background:${c}" data-c="${c}" title="${c}"></button>`).join("")}</span></div>
      <div class="set-row"><span class="muted">Logo</span>
        <span class="logo-picks" id="sw-logo">${Object.entries(LOGO_VARIANTS).map(([k, v]) => `<button class="logo-pick${k === curLogo ? " on" : ""}" data-logo="${k}" title="${v.label}"><svg viewBox="0 0 100 100" width="28" height="28">${v.svg.replace(/currentColor/g, "#F2F5F9")}</svg></button>`).join("")}</span></div>
      <div class="set-row"><span class="muted">CRT scanlines</span>
        <span class="seg" id="sw-crt"><button data-crt="1">On</button><button data-crt="0">Off</button></span></div>
      <div class="set-row"><span class="muted">Shell mode</span>
        <span class="seg" id="sw-shell"><button data-shell="education">Education</button><button data-shell="real">Real Terminal</button></span></div>
      <p class="muted" style="font-size:.72rem;margin-top:4px">Education mode uses a simulated filesystem. Real Terminal connects to a local agent on your machine via WebSocket.</p>`,
    security: `<h2 class="set-panel-h">Security</h2>
      <div class="set-btns" style="margin-top:8px">
        <button class="btn ghost" id="set-pw">Change password</button>
        <button class="btn ghost" id="set-tour">Replay walkthrough</button>
        <button class="btn danger" id="set-out">Log out</button>
      </div>`,
    apikeys: `<h2 class="set-panel-h">API Keys</h2>
      <p class="muted" style="font-size:.84rem;margin-bottom:16px">Add your own API keys to enable live threat intelligence lookups. Keys are stored locally in your browser — never sent to our servers.</p>
      <div id="set-apikeys-form" style="display:flex;flex-direction:column;gap:12px;max-width:500px">
        <div class="set-row" style="flex-direction:column;align-items:stretch;gap:4px"><span class="muted">AbuseIPDB</span><input class="tk-f" id="ak-abuseipdb" type="password" placeholder="Your AbuseIPDB API key" autocomplete="off" spellcheck="false" style="width:100%"><span class="muted" style="font-size:.72rem">Free at <a href="https://www.abuseipdb.com/account/api" target="_blank" rel="noopener" style="color:var(--acc)">abuseipdb.com</a> — IP reputation checks</span></div>
        <div class="set-row" style="flex-direction:column;align-items:stretch;gap:4px"><span class="muted">VirusTotal</span><input class="tk-f" id="ak-virustotal" type="password" placeholder="Your VirusTotal API key" autocomplete="off" spellcheck="false" style="width:100%"><span class="muted" style="font-size:.72rem">Free at <a href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noopener" style="color:var(--acc)">virustotal.com</a> — file/URL/IP analysis</span></div>
        <div class="set-row" style="flex-direction:column;align-items:stretch;gap:4px"><span class="muted">Shodan</span><input class="tk-f" id="ak-shodan" type="password" placeholder="Your Shodan API key" autocomplete="off" spellcheck="false" style="width:100%"><span class="muted" style="font-size:.72rem">Free at <a href="https://account.shodan.io" target="_blank" rel="noopener" style="color:var(--acc)">shodan.io</a> — internet-wide scanning data</span></div>
        <div class="set-row" style="flex-direction:column;align-items:stretch;gap:4px"><span class="muted">AlienVault OTX</span><input class="tk-f" id="ak-otx" type="password" placeholder="Your OTX API key" autocomplete="off" spellcheck="false" style="width:100%"><span class="muted" style="font-size:.72rem">Free at <a href="https://otx.alienvault.com/accounts/signup" target="_blank" rel="noopener" style="color:var(--acc)">otx.alienvault.com</a> — threat intelligence pulses</span></div>
        <div style="display:flex;gap:8px;margin-top:4px">
          <button class="btn" id="ak-save">Save Keys</button>
          <button class="btn ghost" id="ak-clear">Clear All</button>
          <span id="ak-status" style="font-size:.82rem;align-self:center"></span>
        </div>
      </div>`,
    nexus: `<h2 class="set-panel-h">Nexus CLI</h2>
      <p class="muted">Sign in to the Nexus terminal agent with this code. In Nexus, run <span class="mono">/login</span> and paste it.</p>
      <div class="set-row"><span class="muted">Your code</span>
        <span class="nexus-code-row">
          <input id="nexus-code" class="mono" type="password" readonly value="${esc(user.refreshToken || "")}" autocomplete="off" spellcheck="false">
          <button class="btn ghost" id="nexus-reveal" type="button">Reveal</button>
          <button class="btn ghost" id="nexus-copy" type="button">Copy</button>
        </span></div>
      <p class="muted" style="font-size:.75rem">Treat this like a password. Changing your password revokes it.</p>`,
    about: `<h2 class="set-panel-h">About</h2>
      <p class="muted">Darknode -- your security workspace. In-browser tools plus install commands for everything that runs on your machine.</p>
      <p class="muted" style="font-size:.75rem">Version 1.0</p>`,
  };
  main.innerHTML = `
    <h1 class="pg-h1">Settings</h1>
    <div class="set-layout">
      <nav class="set-nav">${SET_TABS.map(([k, l]) => `<button class="set-tab${k === "account" ? " active" : ""}" data-stab="${k}">${l}</button>`).join("")}</nav>
      <div class="set-panel" id="set-panel">${panels.account}</div>
    </div>`;
  let curTab = "account";
  function showSetTab(tab) {
    curTab = tab;
    const panel = main.querySelector("#set-panel"); if (!panel) return;
    panel.innerHTML = panels[tab] || "";
    main.querySelectorAll(".set-tab").forEach(b => b.classList.toggle("active", b.dataset.stab === tab));
    wireSetPanel();
  }
  function wireSetPanel() {
    const acc = main.querySelector("#sw-acc");
    if (acc) acc.onclick = (e) => { const b = e.target.closest(".swatch"); if (b) applyAccent(b.dataset.c); };
    const logoSeg = main.querySelector("#sw-logo");
    if (logoSeg) logoSeg.onclick = (e) => { const b = e.target.closest(".logo-pick"); if (!b) return; applyLogo(b.dataset.logo); logoSeg.querySelectorAll(".logo-pick").forEach((x) => x.classList.toggle("on", x === b)); };
    const themeSeg = main.querySelector("#sw-theme");
    if (themeSeg) { const curTheme = document.documentElement.getAttribute("data-theme") || "dark"; themeSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.t === curTheme)); themeSeg.onclick = (e) => { const b = e.target.closest("button[data-t]"); if (!b) return; applyTheme(b.dataset.t); themeSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); }; }
    const crtSeg = main.querySelector("#sw-crt");
    if (crtSeg) { crtSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", (b.dataset.crt === "1") === crtOn())); crtSeg.onclick = (e) => { const b = e.target.closest("button[data-crt]"); if (!b) return; applyCrt(b.dataset.crt === "1"); crtSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); }; }
    const shellSeg = main.querySelector("#sw-shell");
    if (shellSeg) { const curShell = (() => { try { return localStorage.getItem("dn_shell_mode") || "education"; } catch (_) { return "education"; } })(); shellSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.shell === curShell)); shellSeg.onclick = (e) => { const b = e.target.closest("button[data-shell]"); if (!b) return; try { localStorage.setItem("dn_shell_mode", b.dataset.shell); } catch (_) {} shellSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); }; }
    const akSave = main.querySelector("#ak-save");
    if (akSave) {
      const akFields = [["abuseipdb", "#ak-abuseipdb"], ["virustotal", "#ak-virustotal"], ["shodan", "#ak-shodan"], ["otx", "#ak-otx"]];
      try {
        const keys = JSON.parse(localStorage.getItem("dn_api_keys") || "{}");
        akFields.forEach(([svc, sel]) => { const el = main.querySelector(sel); if (el && keys[svc]) el.value = keys[svc]; });
      } catch (_) {}
      akSave.onclick = () => {
        try {
          const keys = JSON.parse(localStorage.getItem("dn_api_keys") || "{}");
          akFields.forEach(([svc, sel]) => { const el = main.querySelector(sel); if (el) { const v = el.value.trim(); if (v) keys[svc] = v; else delete keys[svc]; } });
          localStorage.setItem("dn_api_keys", JSON.stringify(keys));
          const st = main.querySelector("#ak-status"); if (st) { st.textContent = "Keys saved."; st.style.color = "var(--ok,#3fb950)"; setTimeout(() => { st.textContent = ""; }, 2000); }
        } catch (e) { const st = main.querySelector("#ak-status"); if (st) { st.textContent = "Error: " + e.message; st.style.color = "var(--bad,red)"; } }
      };
    }
    const akClear = main.querySelector("#ak-clear");
    if (akClear) {
      akClear.onclick = () => {
        try { localStorage.removeItem("dn_api_keys"); } catch (_) {}
        const inputs = main.querySelectorAll("#set-apikeys-form input"); inputs.forEach((el) => { el.value = ""; });
        const st = main.querySelector("#ak-status"); if (st) { st.textContent = "All keys cleared."; st.style.color = "var(--ok,#3fb950)"; setTimeout(() => { st.textContent = ""; }, 2000); }
      };
    }
    const out = main.querySelector("#set-out"); if (out) out.onclick = () => signOut(auth);
    const tour = main.querySelector("#set-tour"); if (tour) tour.onclick = () => startTour(tourSteps(isOwner));
    const pwBtn = main.querySelector("#set-pw");
    if (pwBtn) pwBtn.onclick = async () => { try { await sendPasswordResetEmail(auth, user.email); alert("Password reset link sent to " + user.email); } catch (e) { alert(errText(e)); } };
    const codeInput = main.querySelector("#nexus-code");
    if (codeInput) {
      if (!codeInput.value) { user.getIdToken().then(() => { codeInput.value = user.refreshToken || ""; }).catch(() => {}); }
      const rev = main.querySelector("#nexus-reveal"); if (rev) rev.onclick = (e) => { const hidden = codeInput.type === "password"; codeInput.type = hidden ? "text" : "password"; e.target.textContent = hidden ? "Hide" : "Reveal"; };
      const cp = main.querySelector("#nexus-copy"); if (cp) cp.onclick = async (e) => { try { await navigator.clipboard.writeText(codeInput.value); } catch (_) { const t = codeInput.type; codeInput.type = "text"; codeInput.select(); try { document.execCommand("copy"); } catch (__) {} codeInput.type = t; } const b = e.target, o = b.textContent; b.textContent = "Copied"; setTimeout(() => { b.textContent = o; }, 1200); };
    }
  }
  main.querySelector(".set-nav").onclick = (e) => { const b = e.target.closest(".set-tab"); if (b) showSetTab(b.dataset.stab); };
  wireSetPanel();
}

// Gamer "ACCESS GRANTED" neon-portal transition, played once on a FRESH sign-in
// (never on a session-restore page load). Renders the app under the overlay
// mid-animation so it's ready as the portal clears. Falls straight through when
// the visitor prefers reduced motion.
function playAccessGranted(name, cb) {
  try {
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion:reduce)").matches) { cb(); return; }
  } catch (_) {}
  const safe = String(name || "").replace(/[<>&"']/g, "").slice(0, 24);
  const o = document.createElement("div");
  o.id = "xfer";
  o.innerHTML = '<div class="xgrid"></div><div class="xring"></div><div class="xring b"></div>'
    + '<div class="xmsg"><div class="xgranted">Welcome Operator</div><div class="xwho">'
    + (safe ? safe : "Access Granted") + '</div></div><div class="xflash"></div>';
  document.body.appendChild(o);
  let ran = false; const go = () => { if (ran) return; ran = true; try { cb(); } catch (_) {} };
  setTimeout(go, 720);                    // build the app beneath the portal
  setTimeout(() => { try { o.remove(); } catch (_) {} }, 1800); // remove after it fades
}

function renderApp(user) {
  dismissBoot();
  document.body.classList.remove("landing");
  document.body.classList.add("app");
  const isOwner = user.email === OWNER_EMAIL;
  const avatar = user.photoURL
    ? `<img class="p-avatar" src="${esc(user.photoURL)}" alt="">`
    : `<span class="p-avatar p-initials">${esc((user.email || "?")[0].toUpperCase())}</span>`;
  const name = user.displayName || user.email;

  view.innerHTML = `
    <div class="app-shell">
      <aside class="sidebar" id="sidebar" role="complementary" aria-label="Main navigation">
        <div class="side-brand">Darknode</div>
        <nav class="side-nav" role="navigation" aria-label="Application sections">
          <button class="side-item" data-sec="home">Dashboard</button>

          <div class="side-group side-collapse" data-open="1">Command Centers</div>
          <button class="side-item" data-sec="prometheus">PROMETHEUS</button>
          <button class="side-item" data-sec="sentineleye">SENTINEL EYE</button>
          <button class="side-item" data-sec="hydra">HYDRA Engine</button>
          <button class="side-item" data-sec="aegis">AEGIS Ops Center</button>
          <button class="side-item" data-sec="vanguard">VANGUARD</button>
          <button class="side-item" data-sec="secdash">Security Dashboard</button>

          <div class="side-group side-collapse">Offensive Security</div>
          <button class="side-item" data-sec="payloads">Payload Generator</button>
          <button class="side-item" data-sec="exploitdb">Exploit Database</button>
          <button class="side-item" data-sec="exploitdev">Exploit Writer</button>
          <button class="side-item" data-sec="packetcraft">Packet Crafter</button>
          <button class="side-item" data-sec="webshell">Web Shell</button>
          <button class="side-item" data-sec="cracklab">Password Cracking</button>
          <button class="side-item" data-sec="attacksim">Attack Simulator</button>
          <button class="side-item" data-sec="firewall">Firewall Builder</button>
          <button class="side-item" data-sec="wirelesslab">Wireless Pentest Lab</button>
          <button class="side-item" data-sec="pentestconsole">Pentest Console</button>

          <div class="side-group side-collapse">Reconnaissance</div>
          <button class="side-item" data-sec="addressintel">Address Intelligence</button>
          <button class="side-item" data-sec="tools">Scanner Suite</button>
          <button class="side-item" data-sec="osint">OSINT Dashboard</button>
          <button class="side-item" data-sec="subdomains">Subdomain Finder</button>
          <button class="side-item" data-sec="dns">DNS Toolkit</button>
          <button class="side-item" data-sec="netmap">Network Mapper</button>
          <button class="side-item" data-sec="attacksurf">Attack Surface Mapper</button>
          <button class="side-item" data-sec="ghdb">Google Dorks</button>
          <button class="side-item" data-sec="apitester">API Tester</button>
          <button class="side-item" data-sec="apiscan">API Security Scanner</button>
          <button class="side-item" data-sec="wayback">Wayback Recon</button>
          <button class="side-item" data-sec="favicon">Favicon Hasher</button>

          <div class="side-group side-collapse">Analysis &amp; Forensics</div>
          <button class="side-item" data-sec="binanalyze">Binary Analyzer</button>
          <button class="side-item" data-sec="loganalyze">Log Analyzer</button>
          <button class="side-item" data-sec="memforensics">Memory Forensics</button>
          <button class="side-item" data-sec="ftimeline">Forensic Timeline</button>
          <button class="side-item" data-sec="malclass">Malware Classifier</button>
          <button class="side-item" data-sec="sandbox">Malware Sandbox</button>
          <button class="side-item" data-sec="phishing">Phishing Analyzer</button>
          <button class="side-item" data-sec="stego">Steganography</button>
          <button class="side-item" data-sec="reveng">Reverse Engineering</button>

          <div class="side-group side-collapse">Defense &amp; Response</div>
          <button class="side-item" data-sec="adversary">Adversary Mind</button>
          <button class="side-item" data-sec="breachsim">Breach Simulator</button>
          <button class="side-item" data-sec="huntlab">Threat Hunt Lab</button>
          <button class="side-item" data-sec="purpleteam">Purple Team Ops</button>
          <button class="side-item" data-sec="deception">Deception Architect</button>
          <button class="side-item" data-sec="incidents">Incident Tracker</button>
          <button class="side-item" data-sec="threatmodel">Threat Modeler</button>
          <button class="side-item" data-sec="containers">Container Security</button>
          <button class="side-item" data-sec="mobilesec">Mobile Security Lab</button>

          <div class="side-group side-collapse">Intelligence &amp; Compliance</div>
          <button class="side-item" data-sec="threat">Threat Intelligence</button>
          <button class="side-item" data-sec="ipreputation">IP Reputation</button>
          <button class="side-item" data-sec="darkwebosint">Dark Web OSINT</button>
          <button class="side-item" data-sec="vulnprio">Vuln Prioritizer</button>
          <button class="side-item" data-sec="compliance">Compliance Checker</button>
          <button class="side-item" data-sec="zerotrust">Zero Trust Designer</button>
          <button class="side-item" data-sec="supplychain">Supply Chain Analyzer</button>
          <button class="side-item" data-sec="socialeng">Social Engineering Sim</button>

          <div class="side-group side-collapse">Tools &amp; Utilities</div>
          <button class="side-item" data-sec="credaudit">Credential Auditor</button>
          <button class="side-item" data-sec="jwtanalyzer">JWT Analyzer</button>
          <button class="side-item" data-sec="cspevaluator">CSP Evaluator</button>
          <button class="side-item" data-sec="urldissect">URL Dissector</button>
          <button class="side-item" data-sec="encoding">Encoding Toolkit</button>
          <button class="side-item" data-sec="cryptotools">Crypto Toolkit</button>
          <button class="side-item" data-sec="regexlab">Regex Lab</button>
          <button class="side-item" data-sec="cheats">Cheat Sheets</button>
          <button class="side-item" data-sec="utils">Utilities</button>

          <div class="side-group side-collapse">AI &amp; Automation</div>
          <button class="side-item" data-sec="ai">AI Assistant</button>
          <button class="side-item" data-sec="coder">Nexus Agent</button>
          <button class="side-item" data-sec="engines">Security Engines</button>
          <button class="side-item" data-sec="report">Report Generator</button>

          <div class="side-group side-collapse">Learning</div>
          <button class="side-item" data-sec="learn">Learn Hub</button>
          <button class="side-item" data-sec="cyberrange">Cyber Range</button>
          <button class="side-item" data-sec="training">Training Labs</button>
          <button class="side-item" data-sec="secquiz">Security Training</button>
          <button class="side-item" data-sec="refs">References</button>
          <button class="side-item" data-sec="snippets">Code Snippets</button>
          <button class="side-item" data-sec="targets">Practice Targets</button>
          <button class="side-item" data-sec="vms">Vulnerable VMs</button>
          <button class="side-item" data-sec="vmlab">VM Lab</button>

          <div class="side-group side-collapse">Platform</div>
          <button class="side-item" data-sec="arsenal">External Resources</button>
          <button class="side-item" data-sec="downloads">Darknode OS</button>
          <button class="side-item" data-sec="dlguide">Download Guide</button>
          <button class="side-item" data-sec="setup">Local Setup</button>
          <button class="side-item" data-sec="privatecloud">Private Cloud</button>
          <button class="side-item" data-sec="github">GitHub</button>
          <button class="side-item" data-sec="api">API</button>
          <button class="side-item" data-sec="docs">Documentation</button>
          <button class="side-item" data-sec="gmail">Gmail</button>

          ${isOwner ? `<div class="side-group side-collapse">Admin</div><button class="side-item" data-sec="admin">Admin Console</button>` : ""}
        </nav>
        <div class="side-foot">${avatar}<div class="side-user"><div class="su-name">${esc(name)}</div><div class="su-mail muted">${esc(user.email)}</div></div></div>
      </aside>
      <main class="app-main" id="app-main" role="main"><div id="crumbs" class="crumbs" aria-label="Breadcrumb" role="navigation"></div><div id="app-content"></div>
        <footer class="app-foot">
          <div class="app-foot-row">
            <span class="app-foot-brand">Darknode</span><span class="app-foot-ver">v2.29</span>
            <nav class="app-foot-links">
              <a data-foot="docs">Docs</a><a data-foot="terms">Terms</a><a data-foot="privacy">Privacy</a><a data-foot="aup">Acceptable Use</a><a data-foot="license">License</a><a data-foot="downloads">Downloads</a>
            </nav>
          </div>
          <div class="app-foot-fine">Use only on systems you own or are authorized to test.</div>
        </footer>
      </main>
    </div>`;

  const main = document.getElementById("app-content");
  const labelOf = (s) => { const b = view.querySelector('.side-item[data-sec="' + s + '"]'); return b ? b.textContent.trim() : s.charAt(0).toUpperCase() + s.slice(1); };
  let trail = [], curSec = "home";
  function renderCrumbs(sec) {
    const i = trail.indexOf(sec);
    if (i >= 0) trail = trail.slice(0, i + 1); else trail.push(sec);
    if (trail.length > 5) trail = trail.slice(-5);
    const cr = document.getElementById("crumbs"); if (!cr) return;
    cr.innerHTML = trail.map((s, idx) => `<button class="crumb${idx === trail.length - 1 ? " cur" : ""}" data-crumb="${esc(s)}">${esc(labelOf(s))}</button>`).join('<span class="crumb-sep">›</span>');
  }
  // URL path <-> section mapping
  const secToPath = (s) => s === "home" ? "/" : "/" + s.replace(/([A-Z])/g, "-$1").toLowerCase();
  const pathToSec = (p) => {
    if (!p || p === "/") return "home";
    const s = p.replace(/^\//, "").replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    return s || "home";
  };

  let _prevCleanup = null;
  function show(sec, more, skipPush) {
    if (_prevCleanup) { try { _prevCleanup(); } catch (_) {} _prevCleanup = null; }
    curSec = sec; renderCrumbs(sec);
    // Update browser URL
    const path = secToPath(sec);
    if (!skipPush && path !== location.pathname) {
      history.pushState({ sec }, "", path);
    }
    view.querySelectorAll(".side-item").forEach((x) => x.classList.toggle("active", x.dataset.sec === sec));
    if (sec === "tools") { main.innerHTML = `<h1 class="pg-h1">Tools</h1><p class="muted pg-sub">Search the catalog and expand any tool.</p><div id="tools"></div>`; import("/js/tools.js").then(m => m.renderTools(document.getElementById("tools"))); }
    else if (sec === "utils") { import("/js/utils.js").then(m => m.renderUtils(main)); }
    else if (sec === "ai") { import("/js/webai.js").then(m => m.renderAI(main)); }
    else if (sec === "payloads") { import("/js/labs.js").then(m => m.renderPayloads(main)); }
    else if (sec === "targets") { import("/js/labs.js").then(m => m.renderTargets(main)); }
    else if (sec === "ghdb") { import("/js/ghdb.js").then(m => m.renderGHDB(main)); }
    else if (sec === "exploitdb") { import("/js/exploitdb.js").then(m => m.renderExploitDB(main)); }
    else if (sec === "vms") { import("/js/vms.js").then(m => m.renderVMs(main)); }
    else if (sec === "webshell") { import("/js/webshell.js").then(m => m.renderWebshell(main)); }
    else if (sec === "vmlab") { import("/js/vmlab.js").then(m => m.renderVMLab(main)); }
    else if (sec === "privatecloud") { import("/js/privatecloud.js").then(m => m.renderPrivateCloud(main)); }
    else if (sec === "saved") { import("/js/saved.js").then(m => m.renderSaved(main, show)); }
    else if (sec === "report") { import("/js/report.js").then(m => m.renderReport(main)); }
    else if (sec === "snippets") { import("/js/labs.js").then(m => m.renderSnippets(main)); }
    else if (sec === "refs") { import("/js/labs.js").then(m => m.renderRefs(main)); }
    else if (sec === "arsenal") { import("/js/arsenal.js").then(m => m.renderArsenal(main)); }
    else if (sec === "engines") { import("/js/arsenal.js").then(m => m.renderEngines(main)); }
    else if (sec === "packetcraft") { import("/js/packet-crafter.js").then(m => m.renderPacketCrafter(main)); }
    else if (sec === "binanalyze") { import("/js/binary-analyzer.js").then(m => m.renderBinaryAnalyzer(main)); }
    else if (sec === "netmap") { import("/js/network-mapper.js").then(m => m.renderNetworkMapper(main)); }
    else if (sec === "loganalyze") { import("/js/log-analyzer.js").then(m => m.renderLogAnalyzer(main)); }
    else if (sec === "credaudit") { import("/js/credential-auditor.js").then(m => m.renderCredentialAuditor(main)); }
    else if (sec === "memforensics") { import("/js/memory-forensics.js").then(m => m.renderMemoryForensics(main)); }
    else if (sec === "stego") { import("/js/steganography.js").then(m => m.renderSteganography(main)); }
    else if (sec === "regexlab") { import("/js/regex-lab.js").then(m => m.renderRegexLab(main)); }
    else if (sec === "encoding") { import("/js/encoding-suite.js").then(m => m.renderEncodingSuite(main)); }
    else if (sec === "threatmodel") { import("/js/threat-modeler.js").then(m => m.renderThreatModeler(main)); }
    else if (sec === "osint") { import("/js/osint-dashboard.js").then(m => m.renderOSINTDashboard(main)); }
    else if (sec === "addressintel") { import("/js/address-intel.js").then(m => m.renderAddressIntel(main)); }
    else if (sec === "incidents") { import("/js/incident-tracker.js").then(m => m.renderIncidentTracker(main)); }
    else if (sec === "firewall") { import("/js/firewall-builder.js").then(m => m.renderFirewallBuilder(main)); }
    else if (sec === "apitester") { import("/js/api-tester.js").then(m => m.renderAPITester(main)); }
    else if (sec === "sandbox") { import("/js/malware-sandbox.js").then(m => m.renderMalwareSandbox(main)); }
    else if (sec === "compliance") { import("/js/compliance-checker.js").then(m => m.renderComplianceChecker(main)); }
    else if (sec === "attacksim") { import("/js/attack-simulator.js").then(m => m.renderAttackSimulator(main)); }
    else if (sec === "dns") { import("/js/dns-toolkit.js").then(m => m.renderDNSToolkit(main)); }
    else if (sec === "subdomains") { import("/js/subdomain-finder.js").then(m => m.renderSubdomainFinder(main)); }
    else if (sec === "mobilesec") { import("/js/mobile-security-lab.js").then(m => m.renderMobileSecurityLab(main)); }
    else if (sec === "apiscan") { import("/js/api-security-scanner.js").then(m => m.renderAPISecurityScanner(main)); }
    else if (sec === "wirelesslab") { import("/js/wireless-lab.js").then(m => m.renderWirelessLab(main)); }
    else if (sec === "pentestconsole") { import("/js/pentest-console.js").then(m => m.renderPentestConsole(main)); }
    else if (sec === "reveng") { import("/js/reverse-engineering.js").then(m => m.renderReverseEngineering(main)); }
    else if (sec === "darkwebosint") { import("/js/darkweb-osint.js").then(m => m.renderDarkwebOsint(main)); }
    else if (sec === "cyberrange") { import("/js/cyber-range.js").then(m => m.renderCyberRange(main)); }
    else if (sec === "prometheus") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading PROMETHEUS...</p>"; const _s=sec; import("/js/prometheus-web.js").then(m => { if(curSec!==_s)return; m.renderPrometheus(main); _prevCleanup = m.cleanupPrometheus; }); }
    else if (sec === "sentineleye") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading SENTINEL EYE...</p>"; if(!document.querySelector('script[src="/js/threat-api.js"]')){var s1=document.createElement("script");s1.src="/js/threat-api.js";document.head.appendChild(s1)}if(!document.querySelector('script[src="/js/threat-map.js"]')){var s2=document.createElement("script");s2.src="/js/threat-map.js";document.head.appendChild(s2)} const _s=sec; import("/js/sentinel-eye.js").then(m => { if(curSec!==_s)return; m.renderSentinelEye(main); _prevCleanup = m.cleanupSentinelEye; }); }
    else if (sec === "exploitdev") { import("/js/exploit-writer.js").then(m => m.renderExploitWriter(main)); }
    else if (sec === "secdash") { import("/js/security-dashboard.js").then(m => m.renderSecurityDashboard(main)); }
    else if (sec === "phishing") { import("/js/phishing-analyzer.js").then(m => m.renderPhishingAnalyzer(main)); }
    else if (sec === "containers") { import("/js/container-security.js").then(m => m.renderContainerSecurity(main)); }
    else if (sec === "cracklab") { import("/js/password-cracking-lab.js").then(m => m.renderPasswordCrackingLab(main)); }
    else if (sec === "hydra") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading HYDRA...</p>"; import("/js/hydra-engine.js").then(m => m.renderHydra(main)); }
    else if (sec === "aegis") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading AEGIS...</p>"; import("/js/aegis-web.js").then(m => m.renderAegis(main)); }
    else if (sec === "vanguard") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading VANGUARD...</p>"; import("/js/vanguard.js").then(m => m.renderVanguard(main)); }
    else if (sec === "jwtanalyzer") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading JWT Analyzer...</p>"; import("/js/jwt-analyzer.js").then(m => m.renderJwtAnalyzer(main)); }
    else if (sec === "cspevaluator") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading CSP Evaluator...</p>"; import("/js/csp-evaluator.js").then(m => m.renderCspEvaluator(main)); }
    else if (sec === "wayback") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Wayback Recon...</p>"; import("/js/wayback-recon.js").then(m => m.renderWaybackRecon(main)); }
    else if (sec === "urldissect") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading URL Dissector...</p>"; import("/js/url-dissector.js").then(m => m.renderUrlDissector(main)); }
    else if (sec === "favicon") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Favicon Hasher...</p>"; import("/js/favicon-hasher.js").then(m => m.renderFaviconHasher(main)); }
    else if (sec === "adversary") { import("/js/adversary-ai.js").then(m => m.renderAdversaryAI(main)); }
    else if (sec === "breachsim") { import("/js/breach-simulator.js").then(m => m.renderBreachSimulator(main)); }
    else if (sec === "huntlab") { import("/js/threat-hunt-lab.js").then(m => m.renderThreatHuntLab(main)); }
    else if (sec === "attacksurf") { import("/js/attack-surface-mapper.js").then(m => m.renderAttackSurfaceMapper(main)); }
    else if (sec === "deception") { import("/js/deception-architect.js").then(m => m.renderDeceptionArchitect(main)); }
    else if (sec === "purpleteam") { import("/js/purple-team-ops.js").then(m => m.renderPurpleTeamOps(main)); }
    else if (sec === "malclass") { import("/js/malware-classifier.js").then(m => m.renderMalwareClassifier(main)); }
    else if (sec === "zerotrust") { import("/js/zero-trust-designer.js").then(m => m.renderZeroTrustDesigner(main)); }
    else if (sec === "vulnprio") { import("/js/vulnerability-prioritizer.js").then(m => m.renderVulnPrioritizer(main)); }
    else if (sec === "secquiz") { import("/js/security-awareness-quiz.js").then(m => m.renderSecurityQuiz(main)); }
    else if (sec === "supplychain") { import("/js/supply-chain-analyzer.js").then(m => m.renderSupplyChainAnalyzer(main)); }
    else if (sec === "cryptotools") { import("/js/crypto-tools.js").then(m => m.renderCryptoTools(main)); }
    else if (sec === "ftimeline") { import("/js/forensic-timeline.js").then(m => m.renderForensicTimeline(main)); }
    else if (sec === "socialeng") { import("/js/social-engineering-sim.js").then(m => m.renderSocialEngSim(main)); }
    else if (sec === "training") { import("/js/arsenal.js").then(m => m.renderTraining(main)); }
    else if (sec === "apikeys") { import("/js/labs.js").then(m => m.renderApiKeys(main)); }
    else if (sec === "cheats") renderCheats(main);
    else if (sec === "threat") renderThreat(main);
    else if (sec === "ipreputation") { import("/js/ip-reputation.js").then(m => m.renderIPReputation(main)); }
    else if (sec === "learn") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Learn Hub...</p>"; loadLearnHub().then(m => m.renderLearnHub(main)); }
    else if (sec === "github") { import("/js/github.js").then(m => m.renderGitHub(main)); }
    else if (sec === "gmail") { import("/js/gmail.js").then(m => m.renderGmail(main)); }
    else if (sec === "coder") { import("/js/coder.js").then(m => m.renderCliCoder(main)); }
    else if (sec === "downloads") { import("/js/getapp.js").then(m => m.renderDownloads(main)); }
    else if (sec === "dlguide") { import("/js/getapp.js").then(m => m.renderDownloadDocs(main)); }
    else if (sec === "api") { import("/js/api.js").then(m => m.renderAPI(main, user)); }
    else if (sec === "docs") { import("/js/docs.js").then(m => m.renderDocs(main)); }
    else if (sec === "setup") renderSetup(main, more);
    else if (sec === "settings") renderSettingsPage(main, user, isOwner);
    else if (sec === "admin") { import("/js/admin.js").then(m => m.renderAdmin(main, user)); }
    else if (sec === "contact") renderContact(main);
    else renderHome(main, user, isOwner, show);
    if (more === undefined) { try { localStorage.setItem("sw_last_sec", sec); } catch (_) {} }
    main.scrollTop = 0;
  }
  // Handle browser back/forward
  window.addEventListener("popstate", (e) => {
    const sec = (e.state && e.state.sec) || pathToSec(location.pathname);
    show(sec, undefined, true);
  });

  view.querySelector(".side-nav").onclick = (e) => {
    const b = e.target.closest(".side-item");
    if (b) { show(b.dataset.sec); closeSidebar(); return; }
    const g = e.target.closest(".side-collapse");
    if (g) {
      const isOpen = g.dataset.open === "1";
      g.dataset.open = isOpen ? "0" : "1";
      let el = g.nextElementSibling;
      while (el && !el.classList.contains("side-group")) {
        if (isOpen) {
          el.style.overflow = "hidden";
          el.style.maxHeight = el.scrollHeight + "px";
          el.offsetHeight;
          el.style.maxHeight = "0";
          el.style.opacity = "0";
          el.style.padding = "0 10px 0 12px";
          setTimeout((() => { const e = el; return () => { e.style.display = "none"; }; })(), 150);
        } else {
          el.style.display = "";
          el.style.overflow = "hidden";
          el.style.maxHeight = "0";
          el.style.opacity = "0";
          el.offsetHeight;
          el.style.transition = "max-height .15s ease, opacity .15s ease, padding .15s ease";
          el.style.maxHeight = el.scrollHeight + "px";
          el.style.opacity = "1";
          el.style.padding = "";
          setTimeout((() => { const e = el; return () => { e.style.maxHeight = ""; e.style.overflow = ""; e.style.transition = ""; }; })(), 160);
        }
        el = el.nextElementSibling;
      }
    }
  };
  // Handle data-sec clicks anywhere in the view (dashboard cards, hero buttons, etc.)
  view.addEventListener("click", (e) => {
    const sec = e.target.closest("[data-sec]");
    if (sec && !sec.closest(".side-nav")) { show(sec.dataset.sec); }
  });

  // Initialize collapsed groups (data-open not set = collapsed)
  view.querySelectorAll(".side-collapse").forEach((g) => {
    if (g.dataset.open !== "1") {
      let el = g.nextElementSibling;
      while (el && !el.classList.contains("side-group")) {
        el.style.display = "none";
        el = el.nextElementSibling;
      }
    }
  });
  // Hamburger toggle for mobile sidebar
  const hamburger = document.getElementById("hamburger");
  const sidebar = document.getElementById("sidebar");
  if (hamburger) {
    hamburger.hidden = false;
    hamburger.onclick = () => {
      const open = sidebar.classList.toggle("open");
      hamburger.classList.toggle("active", open);
      hamburger.setAttribute("aria-expanded", String(open));
    };
  }
  function closeSidebar() { if (sidebar) { sidebar.classList.remove("open"); if (hamburger) { hamburger.classList.remove("active"); hamburger.setAttribute("aria-expanded", "false"); } } }

  userSlot.innerHTML = `
    <button class="cmdk-btn" id="cmdkBtn" title="Search (Ctrl+K)"><span>Search</span><kbd>Ctrl K</kbd></button>
    <div class="tb-item">
      <button class="icon-btn" id="moreBtn" title="More" aria-label="More">&#8943;</button>
      <div class="menu" id="moreMenu" hidden>
        ${MORE.map((m) => `<button class="menu-item col" data-more="${m.id}"><strong>${esc(m.name)}</strong><span class="menu-sub">${esc(m.desc)}</span></button>`).join("")}
      </div>
    </div>
    <div class="tb-item">
      <button class="profile-btn" id="profileBtn">${avatar}<span class="p-email">${esc(user.email)}</span></button>
      <div class="menu" id="profileMenu" hidden>
        <div class="menu-prof">${avatar}<div style="min-width:0"><div class="su-name">${esc(name)}</div><div class="su-mail muted">${esc(user.email)}${isOwner ? ' <span class="owner-badge">OWNER</span>' : ""}</div></div></div>
        <button class="menu-item" data-nav="settings">Settings</button>
        <button class="menu-item" data-nav="apikeys">API keys</button>
        <button class="menu-item" data-nav="saved">Saved Items</button>
        <button class="menu-item" data-a="theme">Toggle light / dark</button>
        <div class="menu-div"></div>
        <button class="menu-item" data-a="tour">Replay walkthrough</button>
        <button class="menu-item" data-nav="contact">Contact / Feedback</button>
        <div class="menu-div"></div>
        <button class="menu-item" data-a="logout">Log out</button>
      </div>
    </div>`;
  const profileMenu = document.getElementById("profileMenu");
  const moreMenu = document.getElementById("moreMenu");
  const closeMenus = () => { if (profileMenu) profileMenu.hidden = true; if (moreMenu) moreMenu.hidden = true; };
  const profileBtn = document.getElementById("profileBtn");
  const moreBtn = document.getElementById("moreBtn");
  if (profileBtn) profileBtn.onclick = (e) => { e.stopPropagation(); const h = profileMenu.hidden; closeMenus(); profileMenu.hidden = !h; };
  if (moreBtn) moreBtn.onclick = (e) => { e.stopPropagation(); const h = moreMenu.hidden; closeMenus(); moreMenu.hidden = !h; };
  document.addEventListener("click", closeMenus);
  if (profileMenu) profileMenu.onclick = (e) => {
    const nb = e.target.closest("[data-nav]"), lb = e.target.closest("[data-a]"); if (!nb && !lb) return;
    closeMenus();
    if (nb) return show(nb.dataset.nav);
    const a = lb.dataset.a;
    if (a === "logout") signOut(auth);
    else if (a === "theme") { const cur = document.documentElement.getAttribute("data-theme") || "dark"; applyTheme(cur === "dark" ? "light" : "dark"); }
    else if (a === "tour") startTour(tourSteps(isOwner));
    else if (a === "feedback") openFeedback(user);
  };
  if (moreMenu) moreMenu.onclick = (e) => { const b = e.target.closest("[data-more]"); if (!b) return; closeMenus(); show("setup", b.dataset.more); };
  const cmdkBtn = document.getElementById("cmdkBtn");
  if (cmdkBtn) cmdkBtn.onclick = openPalette;

  view.querySelectorAll("[data-foot]").forEach((a) => a.addEventListener("click", () => {
    const f = a.dataset.foot;
    if (f === "downloads") return show("downloads");
    show("docs");
    if (f !== "docs") setTimeout(() => { const t = document.getElementById("doc-" + f); if (t) t.scrollIntoView({ behavior: "smooth", block: "start" }); }, 60);
  }));

  appShow = show;
  initSaved(user);

  // ---- breadcrumb navigation ----
  document.getElementById("crumbs").onclick = (e) => { const b = e.target.closest("[data-crumb]"); if (b) show(b.dataset.crumb); };

  // ---- save the exact frame (Ctrl+S) so you resume where you left off ----
  const FRAME = "sw_frame";
  const toast = (msg, ms) => { const t = document.createElement("div"); t.className = "toast"; t.textContent = msg; document.body.appendChild(t); requestAnimationFrame(() => t.classList.add("in")); setTimeout(() => { t.classList.remove("in"); setTimeout(() => t.remove(), 300); }, ms || 2600); };
  const editableFields = () => [...main.querySelectorAll("input,textarea,select")].filter((el) => el.id && el.type !== "password" && el.type !== "file");
  const hasTyped = () => editableFields().some((el) => (el.tagName !== "SELECT") && el.value && el.value.trim());
  function saveFrame() {
    const fields = {}; editableFields().forEach((el) => { if (el.value) fields[el.id] = el.value; });
    try { localStorage.setItem(FRAME, JSON.stringify({ sec: curSec, fields, ts: Date.now() })); } catch (_) {}
    toast("Frame saved — you'll resume right here.");
  }
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && (e.key === "s" || e.key === "S") && document.body.classList.contains("app")) { e.preventDefault(); saveFrame(); }
  });
  // gentle exit-intent hint (once per session) + native unsaved-changes guard
  let exitHinted = false;
  document.addEventListener("mouseout", (e) => { if (e.clientY <= 0 && !exitHinted && hasTyped()) { exitHinted = true; toast("Leaving? Press Ctrl+S to save this exact frame so you resume right here.", 5000); } });
  window.addEventListener("beforeunload", (e) => { if (hasTyped()) { e.preventDefault(); e.returnValue = ""; } });

  // ---- restore last frame (section + typed text), else last section ----
  let frame = null; try { frame = JSON.parse(localStorage.getItem(FRAME)); } catch (_) {}
  let lastSec; try { lastSec = localStorage.getItem("sw_last_sec"); } catch (_) {}
  const pathSec = location.pathname !== "/" ? pathToSec(location.pathname) : null;
  const HEAVY = new Set(["sentineleye","prometheus","hydra","aegis","vanguard"]);
  const startSec = pathSec || (frame && frame.sec) || lastSec || "home";
  const okSec = startSec && startSec !== "setup" && (startSec !== "admin" || isOwner) && !HEAVY.has(startSec);
  show(okSec ? startSec : "home");
  if (frame && frame.fields && frame.sec === startSec) {
    setTimeout(() => { Object.entries(frame.fields).forEach(([id, v]) => { const el = main.querySelector("#" + (window.CSS && CSS.escape ? CSS.escape(id) : id)); if (el && v != null) { el.value = v; el.dispatchEvent(new Event("input", { bubbles: true })); el.dispatchEvent(new Event("change", { bubbles: true })); } }); }, 120);
  }
  if (!tourDone()) setTimeout(() => startTour(tourSteps(isOwner)), 450);
}

// ---- command palette (Ctrl/Cmd+K) ----
// Subsequence fuzzy score: -1 if `needle` isn't a subsequence of `hay`, else a
// score rewarding contiguous runs, word-boundary hits, and early matches.
function fuzzyScore(hay, needle) {
  hay = hay.toLowerCase(); needle = needle.toLowerCase();
  if (!needle) return 0;
  let hi = 0, score = 0, streak = 0;
  for (const ch of needle) {
    const idx = hay.indexOf(ch, hi);
    if (idx < 0) return -1;
    if (idx === 0 || /[\s·.\-\/&]/.test(hay[idx - 1] || "")) score += 4;
    if (idx === hi) { streak++; score += streak; } else streak = 0;
    score += 1; hi = idx + 1;
  }
  return score + Math.max(0, 12 - hi);
}
const paletteRecents = () => { try { return JSON.parse(localStorage.getItem("sw_recent")) || []; } catch (_) { return []; } };
function pushRecent(id) { let r = paletteRecents().filter((x) => x !== id); r.unshift(id); r = r.slice(0, 6); try { localStorage.setItem("sw_recent", JSON.stringify(r)); } catch (_) {} }

function openPalette() {
  if (document.getElementById("cmdk")) return;
  const sections = [["home", "Home"], ["ai", "AI assistant"], ["tools", "Tools"], ["saved", "Saved"], ["utils", "Utilities"], ["payloads", "Payloads"], ["exploitdb", "Exploit & vuln databases"], ["ghdb", "Google dorks"], ["targets", "Practice targets"], ["vms", "Vulnerable VMs"], ["threat", "Threat intel"], ["cheats", "Cheat sheets"], ["snippets", "Code snippets"], ["refs", "References"], ["arsenal", "Arsenal"], ["training", "Training"], ["github", "GitHub"], ["gmail", "Gmail"], ["privatecloud", "Private Cloud Generator"], ["report", "Report generator"], ["learn", "Learn"], ["setup", "Local setup"], ["coder", "Nexus"], ["downloads", "Get the app"], ["dlguide", "Download guide"], ["api", "API"], ["docs", "Documentation"], ["apikeys", "API keys"], ["settings", "Settings"], ["admin", "Admin"], ["vanguard", "VANGUARD"], ["jwtanalyzer", "JWT Analyzer"], ["cspevaluator", "CSP Evaluator"], ["wayback", "Wayback Recon"], ["urldissect", "URL Dissector"], ["favicon", "Favicon Hasher"]];
  const items = [
    ...sections.map(([s, n]) => ({ type: "section", id: s, name: n, desc: "Go to " + n })),
    ...CATALOG.map((t) => ({ type: "tool", id: t.id, name: t.name, desc: t.cat + " · " + t.desc })),
    ...CHEATS.map((c) => ({ type: "section", id: "cheats", name: c.name + " cheat sheet", desc: "Cheat sheet · " + c.cat })),
    ...RESOURCES.map((r) => ({ type: "link", id: r.url, name: r.name, desc: "Resource · " + r.tag })),
  ];
  const ov = document.createElement("div");
  ov.id = "cmdk"; ov.className = "cmdk";
  ov.innerHTML = `<div class="cmdk-box"><input class="cmdk-input" id="cmdk-in" placeholder="Search sections, tools, cheat sheets, resources…" autocomplete="off" spellcheck="false"><div class="cmdk-list" id="cmdk-list"></div><div class="cmdk-foot"><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>↵</kbd> open</span><span><kbd>esc</kbd> close</span></div></div>`;
  document.body.appendChild(ov);
  const inp = ov.querySelector("#cmdk-in"), list = ov.querySelector("#cmdk-list");
  const BADGE = { section: "go", tool: "tool", link: "link" };
  let sel = 0, filtered = items, recentMode = false;
  const close = () => ov.remove();
  function render(q) {
    const t = q.trim();
    if (!t) {
      const rec = paletteRecents().map((id) => items.find((x) => x.type === "section" && x.id === id)).filter(Boolean);
      const recIds = new Set(rec.map((x) => x.id));
      filtered = [...rec, ...items.filter((x) => !(x.type === "section" && recIds.has(x.id)))].slice(0, 80);
      recentMode = rec.length;
    } else {
      filtered = items.map((x) => ({ x, s: fuzzyScore(x.name + " " + x.desc, t) })).filter((o) => o.s >= 0).sort((a, b) => b.s - a.s).slice(0, 60).map((o) => o.x);
      recentMode = 0;
    }
    if (sel >= filtered.length) sel = 0;
    list.innerHTML = filtered.map((x, i) => {
      const hdr = (i === 0 && recentMode) ? `<div class="cmdk-group">Recent</div>` : (i === recentMode && recentMode) ? `<div class="cmdk-group">All</div>` : "";
      return `${hdr}<div class="cmdk-item${i === sel ? " sel" : ""}" data-i="${i}"><span class="cmdk-badge ${x.type}">${BADGE[x.type]}</span><span class="cmdk-name">${esc(x.name)}</span><span class="cmdk-desc">${esc(x.desc)}</span></div>`;
    }).join("") || `<div class="cmdk-empty">No results</div>`;
    const a = list.querySelector(".cmdk-item.sel"); if (a) a.scrollIntoView({ block: "nearest" });
  }
  function run(i) {
    const x = filtered[i]; if (!x) return; close();
    if (x.type === "link") { window.open(x.id, "_blank", "noopener"); return; }
    if (x.type === "section") { pushRecent(x.id); appShow && appShow(x.id); return; }
    appShow && appShow("tools");
    setTimeout(() => { const it = document.querySelector(`.tk-item[data-id="${x.id}"]`); if (it) { if (!it.classList.contains("open")) it.querySelector(".tk-head").click(); it.scrollIntoView({ block: "center" }); } }, 70);
  }
  inp.oninput = () => { sel = 0; render(inp.value); };
  inp.onkeydown = (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(sel + 1, filtered.length - 1); render(inp.value); }
    else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(sel - 1, 0); render(inp.value); }
    else if (e.key === "Enter") { e.preventDefault(); run(sel); }
    else if (e.key === "Escape") { close(); }
  };
  list.onclick = (e) => { const it = e.target.closest(".cmdk-item[data-i]"); if (it) run(+it.dataset.i); };
  ov.onclick = (e) => { if (e.target === ov) close(); };
  render(""); inp.focus();
}
document.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
    if (!document.body.classList.contains("app")) return;
    e.preventDefault();
    const ex = document.getElementById("cmdk"); if (ex) ex.remove(); else openPalette();
  }
});

function tourSteps(isOwner) {
  const steps = [
    { title: "Welcome to Darknode", text: "A quick tour of the console. You can skip anytime." },
    { sel: ".side-nav", title: "Navigate", text: "Move between Home, Tools, Local setup, and Settings here." },
    { sel: ".qa-grid", title: "Quick actions", text: "Jump straight into browsing tools or setting up local AI." },
    { sel: "#moreBtn", title: "The … menu", text: "Spin up the full local toolkit + SSH, or a local AI coding setup with Ollama." },
    { sel: "#profileBtn", title: "Your profile", text: "Navigation, settings, change password, and log out live here." },
  ];
  if (isOwner) steps.push({ sel: ".admin-card", title: "Owner controls", text: "Admin-only features live here — just for you." });
  steps.push({ title: "You're set", text: "That's it. Replay this anytime with the 'Replay walkthrough' button." });
  return steps;
}

// Whitelist enforcement: if the owner turned it on, only allow-listed emails may use the site.
async function accessAllowed(user) {
  if (user.email === OWNER_EMAIL) return true;
  try {
    const { getWhitelist } = await import("/js/admin.js");
    const wl = await getWhitelist();
    if (wl && wl.enforce) {
      const list = (wl.emails || []).map((e) => e.toLowerCase());
      return list.includes((user.email || "").toLowerCase());
    }
  } catch (_) { /* if we can't read, don't lock anyone out */ }
  return true;
}

// Site-wide announcement banner (published from Admin).
async function loadAnnouncement() {
  const el = document.getElementById("announcement");
  if (!el) return;
  try {
    const snap = await getDoc(doc(db, "announcements", "current"));
    const d = snap.exists() ? snap.data() : null;
    if (d && d.active && d.text) {
      el.textContent = d.text;
      el.classList.toggle("banner-info", d.type !== "warn");
      el.hidden = false;
    } else { el.hidden = true; }
  } catch (_) { el.hidden = true; }
}

// ---------- boot ----------
setPersistence(auth, browserLocalPersistence).catch(() => {});
getRedirectResult(auth).then((result) => {
  if (result && result.user) {
    try { sessionStorage.setItem("sw_fresh_signin", "1"); } catch (_) {}
  }
}).catch(() => {});
onAuthStateChanged(auth, async (user) => {
  if (window.__boot) window.__boot.set(70);
  // license verification
  const _hn = [0x64,0x61,0x72,0x6b,0x6e,0x6f,0x64,0x65,0x2e,0x61,0x69].map(c=>String.fromCharCode(c)).join("");
  if(location.hostname!==_hn&&location.hostname!=="www."+_hn&&location.hostname!=="localhost"&&location.hostname!=="127.0.0.1"){document.body.innerHTML="";return}
  let fresh = false; try { fresh = sessionStorage.getItem("sw_fresh_signin") === "1"; if (fresh) sessionStorage.removeItem("sw_fresh_signin"); } catch (_) {}
  if (!user) { showLanding(); return; }
  // Email/password users must verify — a 6-digit code when EmailJS is configured, else the Firebase link.
  const providerEmailPw = user.providerData.some((p) => p.providerId === "password");
  if (providerEmailPw) {
    if (emailConfigured()) {
      const udoc = await getDoc(doc(db, "users", user.uid)).catch(() => null);
      if (!(udoc && udoc.exists() && udoc.data().codeVerified)) { renderCodeVerify(user); return; }
    } else if (!user.emailVerified) { renderVerify(user); return; }
  }
  if (!(await accessAllowed(user))) {
    alert("Access restricted — your email isn't on the allow-list. Contact the owner.");
    await signOut(auth); return;
  }
  await ensureUserDoc(user);
  checkLoginDevice(user);

  // TOS acceptance check — must agree before using the platform
  const udoc = await getDoc(doc(db, "users", user.uid)).catch(() => null);
  const tosAccepted = udoc && udoc.exists() && udoc.data().tosAccepted;
  if (!tosAccepted) {
    view.innerHTML = `
      <div style="max-width:640px;margin:60px auto;padding:24px;font-family:var(--font-body,system-ui)">
        <h1 style="font-size:1.6rem;margin-bottom:8px">Terms of Service</h1>
        <p style="color:var(--mut,#888);margin-bottom:20px">Please read and accept before continuing.</p>
        <div style="background:var(--card,#1a1a1a);border:1px solid var(--line,#333);padding:20px;max-height:400px;overflow-y:auto;font-size:.85rem;line-height:1.7;margin-bottom:20px;border-radius:4px" id="tosBox">
          <h3>Darknode Terms of Service</h3>
          <p><strong>Last updated:</strong> September 11, 2026</p>
          <p>By using Darknode ("the Platform"), including darknode.ai, Darknode CLI, Nexus AI agent, Darknode OS, and all associated tools, you agree to these terms.</p>

          <h4>1. Ethical Use Only</h4>
          <p>Darknode is built for <strong>ethical hacking, authorized penetration testing, cybersecurity education, and legitimate security research</strong>. All tools, intelligence data, exploit references, payloads, and operational platforms (including AEGIS, PROMETHEUS, HYDRA, and all CLI/VM tools) are designed to help security professionals protect systems — not attack them illegally.</p>
          <p><strong>You MUST have explicit written authorization before testing any system, network, or application you do not own.</strong> This includes but is not limited to: penetration tests, vulnerability scans, social engineering assessments, wireless audits, and red team engagements. Unauthorized access to computer systems is a criminal offense under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws worldwide.</p>

          <h4>2. No Liability — Complete Indemnification</h4>
          <p><strong>Darknode, its creators, owners, contributors, affiliates, and partners are NOT liable for any damages, losses, legal consequences, criminal charges, civil actions, fines, penalties, or harm of any kind</strong> resulting from your use or misuse of the Platform, its tools, scripts, AI agents, operating system, exploit databases, payload libraries, intelligence data, or any other component. This includes but is not limited to:</p>
          <ul>
            <li>Unauthorized access to systems, networks, or data</li>
            <li>Data loss, corruption, theft, or exposure</li>
            <li>Criminal prosecution or legal action taken against you</li>
            <li>Damage to hardware, software, infrastructure, or third-party systems</li>
            <li>Consequences of AI-generated code, commands, exploits, or recommendations</li>
            <li>Actions taken by the Nexus AI agent, AEGIS, PROMETHEUS, or any automated tool</li>
            <li>Financial losses, business disruption, or reputational harm</li>
            <li>Use of real CVE data, exploit code, or vulnerability information provided by the platform</li>
          </ul>
          <p><strong>You use everything entirely at your own risk.</strong> The Platform is provided "as-is" with absolutely no warranties, express or implied. By using Darknode, you agree to indemnify and hold harmless Darknode and its team from any claims arising from your use of the platform.</p>

          <h4>3. Real Security Data</h4>
          <p>Darknode provides real-world security intelligence including CVE databases, exploit references, MITRE ATT&amp;CK mappings, APT group profiles, vulnerability data, and penetration testing methodologies. This information is sourced from publicly available databases and is provided for <strong>defensive security, education, and authorized testing purposes only</strong>. Darknode does not create exploits — it references publicly known vulnerabilities to help defenders understand and mitigate threats.</p>

          <h4>4. BYOK (Bring Your Own Key)</h4>
          <p>AI features require your own API keys. Darknode does not execute AI on its hosted servers. You are solely responsible for your API usage, costs, and any actions taken by AI agents operating with your keys.</p>

          <h4>5. User Responsibility</h4>
          <p><strong>You are solely and entirely responsible for:</strong></p>
          <ul>
            <li>Obtaining proper written authorization before any security testing</li>
            <li>Complying with all applicable local, state, national, and international laws</li>
            <li>Any code, payloads, exploits, or tools you generate, modify, or execute</li>
            <li>Securing your own API keys, credentials, and sensitive data</li>
            <li>Understanding the legal implications of your actions in your jurisdiction</li>
            <li>Any damage caused to systems, networks, or data during authorized testing</li>
          </ul>

          <h4>6. Prohibited Activities</h4>
          <p>You agree NOT to use Darknode for:</p>
          <ul>
            <li>Attacking systems without explicit written authorization</li>
            <li>Creating, distributing, or deploying malware for malicious purposes</li>
            <li>Conducting denial-of-service attacks against unauthorized targets</li>
            <li>Stealing, selling, or exposing personal data or credentials</li>
            <li>Any activity that violates applicable cybercrime laws</li>
          </ul>
          <p>Violation of these terms may result in immediate account termination and reporting to appropriate authorities.</p>

          <h4>7. Educational Purpose</h4>
          <p>Darknode is fundamentally a cybersecurity <strong>education and training platform</strong>. Tools, labs, simulations, and resources exist to train the next generation of ethical hackers, penetration testers, incident responders, and security engineers. We do not endorse, encourage, or condone any illegal activity whatsoever.</p>

          <h4>8. Data</h4>
          <p>We store minimal user data (email, display name, login timestamps) in Firebase. We do not sell or share your data. You can request deletion by emailing contact@darknode.ai.</p>

          <h4>9. Changes</h4>
          <p>We may update these terms. Continued use after changes constitutes acceptance.</p>

          <p style="margin-top:20px"><strong>By clicking "I Agree" below, you acknowledge that you have read, understood, and agree to be bound by these terms.</strong></p>
        </div>
        <div style="display:flex;gap:12px;align-items:center">
          <button class="btn lg" id="tosAgree" style="min-width:140px">I Agree</button>
          <button class="btn lg ghost" id="tosDecline">Decline &amp; Sign Out</button>
        </div>
      </div>`;
    document.getElementById("tosAgree").onclick = async () => {
      await setDoc(doc(db, "users", user.uid), { tosAccepted: true, tosAcceptedAt: serverTimestamp() }, { merge: true });
      const enter = () => { renderApp(user); loadAnnouncement(); };
      if (fresh) playAccessGranted(user.displayName || ((user.email || "").split("@")[0]), enter);
      else enter();
    };
    document.getElementById("tosDecline").onclick = async () => {
      await signOut(auth);
    };
    return;
  }

  // Fresh sign-in (flag captured up top)? Play the gamer "Access Granted" portal,
  // then reveal the app. A session-restore page load has no flag → boots straight in.
  const enter = () => { renderApp(user); loadAnnouncement(); };
  if (fresh) playAccessGranted(user.displayName || ((user.email || "").split("@")[0]), enter);
  else enter();
});
