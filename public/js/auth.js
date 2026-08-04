// Multi-user auth for Sentinel Web (Firebase). Google sign-in + email/password
// signup with email verification + password reset. Owner (OWNER_EMAIL) is admin.
import { auth, db, googleProvider, githubProvider, OWNER_EMAIL } from "/js/firebase.js";
import {
  onAuthStateChanged, signInWithPopup, signOut,
  createUserWithEmailAndPassword, signInWithEmailAndPassword,
  sendEmailVerification, sendPasswordResetEmail, reload,
  setPersistence, browserLocalPersistence
} from "https://www.gstatic.com/firebasejs/12.17.0/firebase-auth.js";
import {
  doc, setDoc, serverTimestamp
} from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";
import { renderTools } from "/js/tools.js";
import { MORE, CATALOG, CATEGORIES } from "/js/toolkit.js";
import { startTour, tourDone } from "/js/tour.js";
import { renderLanding } from "/js/landing.js";

const userSlot = document.getElementById("user-slot");
const view = document.getElementById("view");
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
function showLanding() {
  document.body.classList.remove("app");
  document.body.classList.add("landing");
  userSlot.innerHTML = `<a class="nav-link" id="nav-signin">Sign in</a><button class="btn" id="nav-start">Get Started</button>`;
  document.getElementById("nav-signin").onclick = () => renderAuth("signin");
  document.getElementById("nav-start").onclick = () => renderAuth("signup");
  renderLanding(view, {
    onGetStarted: () => renderAuth("signup"),
    onSignIn: () => renderAuth("signin"),
  });
}

function renderAuth(mode = "signin") {
  document.body.classList.remove("landing", "app");
  userSlot.innerHTML = "";
  const isSignup = mode === "signup";
  view.innerHTML = `
    <section class="card auth-card">
      <a class="auth-back" id="authBack">&larr; Back</a>
      <h1>Sentinel</h1>
      <p class="muted">${isSignup ? "Create an account." : "Sign in to continue."}</p>
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
    try { await signInWithPopup(auth, googleProvider); }
    catch (e) { err(errText(e)); }
  };
  document.getElementById("github").onclick = async () => {
    err("");
    try { await signInWithPopup(auth, githubProvider); }
    catch (e) { err(errText(e)); }
  };
  document.getElementById("pwform").onsubmit = async (ev) => {
    ev.preventDefault(); err("");
    const email = document.getElementById("email").value.trim();
    const pw = document.getElementById("password").value;
    try {
      if (isSignup) {
        const cred = await createUserWithEmailAndPassword(auth, email, pw);
        await sendEmailVerification(cred.user);
      } else {
        await signInWithEmailAndPassword(auth, email, pw);
      }
    } catch (e) { err(errText(e)); }
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

// ---------- appearance ----------
const ACCENTS = ["#00d4ff", "#7c5cff", "#22c55e", "#f59e0b", "#ef4444", "#ec4899"];
function applyAccent(c) {
  document.documentElement.style.setProperty("--acc", c);
  try { localStorage.setItem("sw_accent", c); } catch (_) {}
}
(function () { let a = null; try { a = localStorage.getItem("sw_accent"); } catch (_) {} if (a) applyAccent(a); })();

// ---------- app sections ----------
function renderHome(main, user, isOwner, show) {
  const name = user.displayName ? user.displayName.split(" ")[0] : "";
  const browsers = CATALOG.filter((t) => t.kind === "browser").length;
  const stat = (n, l) => `<div class="stat"><div class="stat-n">${n}</div><div class="stat-l">${l}</div></div>`;
  const qa = (sec, more, title, desc) => `<button class="qa" data-sec="${sec}" data-more="${more}"><div class="qa-title">${title}</div><div class="qa-desc">${desc}</div></button>`;
  main.innerHTML = `
    <div class="dash-hero">
      <div class="eyebrow">DASHBOARD</div>
      <h1 class="pg-h1">Welcome back${name ? ", " + esc(name) : ""}</h1>
      <p class="muted pg-sub">Your security tools, local AI, and setup guides &mdash; all in one console.</p>
    </div>
    <div class="stat-row">${stat(CATALOG.length, "tools")}${stat(browsers, "run in-browser")}${stat(CATEGORIES.length, "categories")}</div>
    <h2 class="pg-h2">Jump in</h2>
    <div class="qa-grid">
      ${qa("tools", "", "Browse tools", "Search and use the catalog &mdash; encoders, hashes, payloads and more.")}
      ${qa("setup", "aicoding", "Local AI coding", "Run Ollama models on your machine, in the terminal or a browser UI.")}
      ${qa("setup", "toolkit", "Prebuilt toolkit", "Install the whole CLI toolkit + SSH in one command.")}
      ${qa("settings", "", "Settings", "Account, appearance, and security.")}
    </div>
    ${isOwner ? `<div class="admin-card"><strong>Owner controls</strong><p class="muted">You're the owner &mdash; admin features live under Admin in the sidebar.</p></div>` : ""}`;
  main.querySelector(".qa-grid").onclick = (e) => { const b = e.target.closest(".qa"); if (b) show(b.dataset.sec, b.dataset.more || ""); };
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
  main.innerHTML = `
    <h1 class="pg-h1">Settings</h1>
    <div class="set-card"><div class="set-lbl">Account</div>
      ${row("Name", esc(user.displayName || "—"))}
      ${row("Email", esc(user.email) + (isOwner ? ' <span class="owner-badge">OWNER</span>' : ""))}
      ${row("Signed in via", esc(providers))}
      ${row("Member since", esc(created))}
      ${row("User ID", '<span class="mono">' + esc(user.uid) + "</span>")}
    </div>
    <div class="set-card"><div class="set-lbl">Appearance</div>
      <div class="set-row"><span class="muted">Accent color</span>
        <span class="swatches" id="sw-acc">${ACCENTS.map((c) => `<button class="swatch" style="background:${c}" data-c="${c}" title="${c}"></button>`).join("")}</span></div>
    </div>
    <div class="set-card"><div class="set-lbl">Security</div>
      <div class="set-btns">
        <button class="btn ghost" id="set-pw">Change password</button>
        <button class="btn ghost" id="set-tour">Replay walkthrough</button>
        <button class="btn danger" id="set-out">Log out</button>
      </div>
    </div>
    <div class="set-card"><div class="set-lbl">About</div>
      <p class="muted">Sentinel &mdash; your security workspace. In-browser tools plus install commands for everything that runs on your machine.</p>
      <p class="muted" style="font-size:.75rem">Version 1.0</p>
    </div>`;
  main.querySelector("#sw-acc").onclick = (e) => { const b = e.target.closest(".swatch"); if (b) applyAccent(b.dataset.c); };
  main.querySelector("#set-out").onclick = () => signOut(auth);
  main.querySelector("#set-tour").onclick = () => startTour(tourSteps(isOwner));
  main.querySelector("#set-pw").onclick = async () => {
    try { await sendPasswordResetEmail(auth, user.email); alert("Password reset link sent to " + user.email); }
    catch (e) { alert(errText(e)); }
  };
}

function renderAdmin(main, user) {
  main.innerHTML = `
    <h1 class="pg-h1">Admin</h1>
    <p class="muted pg-sub">Owner-only &mdash; ${esc(user.email)}</p>
    <div class="card"><h3>User management</h3><p class="muted">View and manage signed-up users. Wired to your Firestore &mdash; expandable.</p></div>
    <div class="card"><h3>Announcements</h3><p class="muted">Post a banner shown to everyone.</p></div>`;
}

function renderApp(user) {
  document.body.classList.remove("landing");
  document.body.classList.add("app");
  const isOwner = user.email === OWNER_EMAIL;
  const avatar = user.photoURL
    ? `<img class="p-avatar" src="${esc(user.photoURL)}" alt="">`
    : `<span class="p-avatar p-initials">${esc((user.email || "?")[0].toUpperCase())}</span>`;
  const name = user.displayName || user.email;

  view.innerHTML = `
    <div class="app-shell">
      <aside class="sidebar">
        <div class="side-brand">Sentinel</div>
        <nav class="side-nav">
          <button class="side-item" data-sec="home">Home</button>
          <button class="side-item" data-sec="tools">Tools</button>
          <button class="side-item" data-sec="setup">Local setup</button>
          <button class="side-item" data-sec="settings">Settings</button>
          ${isOwner ? `<button class="side-item" data-sec="admin">Admin</button>` : ""}
        </nav>
        <div class="side-foot">${avatar}<div class="side-user"><div class="su-name">${esc(name)}</div><div class="su-mail muted">${esc(user.email)}</div></div></div>
      </aside>
      <main class="app-main" id="app-main"></main>
    </div>`;

  const main = document.getElementById("app-main");
  function show(sec, more) {
    view.querySelectorAll(".side-item").forEach((x) => x.classList.toggle("active", x.dataset.sec === sec));
    if (sec === "tools") { main.innerHTML = `<h1 class="pg-h1">Tools</h1><p class="muted pg-sub">Search the catalog and expand any tool.</p><div id="tools"></div>`; renderTools(document.getElementById("tools")); }
    else if (sec === "setup") renderSetup(main, more);
    else if (sec === "settings") renderSettingsPage(main, user, isOwner);
    else if (sec === "admin") renderAdmin(main, user);
    else renderHome(main, user, isOwner, show);
    main.scrollTop = 0;
  }
  view.querySelector(".side-nav").onclick = (e) => { const b = e.target.closest(".side-item"); if (b) show(b.dataset.sec); };

  userSlot.innerHTML = `
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
        <button class="menu-item" data-nav="home">Home</button>
        <button class="menu-item" data-nav="tools">Tools</button>
        <button class="menu-item" data-nav="setup">Local setup</button>
        <button class="menu-item" data-nav="settings">Settings</button>
        ${isOwner ? `<button class="menu-item" data-nav="admin">Admin</button>` : ""}
        <div class="menu-div"></div>
        <button class="menu-item" data-a="logout">Log out</button>
      </div>
    </div>`;
  const profileMenu = document.getElementById("profileMenu");
  const moreMenu = document.getElementById("moreMenu");
  const closeMenus = () => { profileMenu.hidden = true; moreMenu.hidden = true; };
  document.getElementById("profileBtn").onclick = (e) => { e.stopPropagation(); const h = profileMenu.hidden; closeMenus(); profileMenu.hidden = !h; };
  document.getElementById("moreBtn").onclick = (e) => { e.stopPropagation(); const h = moreMenu.hidden; closeMenus(); moreMenu.hidden = !h; };
  document.addEventListener("click", closeMenus);
  profileMenu.onclick = (e) => {
    const nb = e.target.closest("[data-nav]"), lb = e.target.closest("[data-a]"); if (!nb && !lb) return;
    closeMenus(); if (lb) signOut(auth); else show(nb.dataset.nav);
  };
  moreMenu.onclick = (e) => { const b = e.target.closest("[data-more]"); if (!b) return; closeMenus(); show("setup", b.dataset.more); };

  show("home");
  if (!tourDone()) setTimeout(() => startTour(tourSteps(isOwner)), 450);
}

function tourSteps(isOwner) {
  const steps = [
    { title: "Welcome to Sentinel", text: "A quick tour of the console. You can skip anytime." },
    { sel: ".side-nav", title: "Navigate", text: "Move between Home, Tools, Local setup, and Settings here." },
    { sel: ".qa-grid", title: "Quick actions", text: "Jump straight into browsing tools or setting up local AI." },
    { sel: "#moreBtn", title: "The … menu", text: "Spin up the full local toolkit + SSH, or a local AI coding setup with Ollama." },
    { sel: "#profileBtn", title: "Your profile", text: "Navigation, settings, change password, and log out live here." },
  ];
  if (isOwner) steps.push({ sel: ".admin-card", title: "Owner controls", text: "Admin-only features live here — just for you." });
  steps.push({ title: "You're set", text: "That's it. Replay this anytime with the 'Replay walkthrough' button." });
  return steps;
}

// ---------- boot ----------
setPersistence(auth, browserLocalPersistence).catch(() => {});
onAuthStateChanged(auth, async (user) => {
  if (!user) { showLanding(); return; }
  // Google accounts are already verified; email/password users must verify.
  const providerEmailPw = user.providerData.some((p) => p.providerId === "password");
  if (providerEmailPw && !user.emailVerified) { renderVerify(user); return; }
  await ensureUserDoc(user);
  renderApp(user);
});
