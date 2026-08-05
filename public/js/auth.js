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
  doc, getDoc, setDoc, serverTimestamp
} from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";
import { renderTools } from "/js/tools.js";
import { MORE, CATALOG, CATEGORIES } from "/js/toolkit.js";
import { startTour, tourDone } from "/js/tour.js";
import { renderLanding } from "/js/landing.js";
import {
  renderThreat, renderCheats, renderLearn, homeWidgetsHTML, wireHome, COUNTS,
  CHEATS, RESOURCES,
} from "/js/cyber.js";
import { renderAdmin, getWhitelist } from "/js/admin.js";

const userSlot = document.getElementById("user-slot");
const view = document.getElementById("view");
let appShow = null;   // set by renderApp so the command palette can navigate
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
function applyTheme(m) { document.documentElement.setAttribute("data-theme", m); try { localStorage.setItem("sw_theme", m); } catch (_) {} }
(function () { let t = "dark"; try { t = localStorage.getItem("sw_theme") || "dark"; } catch (_) {} applyTheme(t); })();

// ---------- app sections ----------
function renderHome(main, user, isOwner, show) {
  const name = user.displayName ? user.displayName.split(" ")[0] : "";
  const browsers = CATALOG.filter((t) => t.kind === "browser").length;
  const stat = (n, l, s) => `<div class="stat"><div class="stat-n">${n}</div><div class="stat-l">${l}</div>${s ? `<div class="stat-s">${s}</div>` : ""}</div>`;
  const qa = (sec, more, title, desc) => `<button class="qa" data-sec="${sec}" data-more="${more}"><div class="qa-title">${title}</div><div class="qa-desc">${desc}</div></button>`;
  main.innerHTML = `
    <div class="dash-hero">
      <div class="eyebrow">SECURITY CONSOLE</div>
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
    </div>
    <h2 class="pg-h2">Jump in</h2>
    <div class="qa-grid">
      ${qa("tools", "", "Browse tools", "Search and use the catalog &mdash; encoders, hashes, payloads and more.")}
      ${qa("cheats", "", "Cheat sheets", "Copy-paste one-liners for recon, shells, privesc and cracking.")}
      ${qa("threat", "", "Threat intel", "Notable CVEs and a common-ports attack-surface reference.")}
      ${qa("learn", "", "Learn", "Curated hubs: HackTricks, OWASP, PayloadsAllTheThings and more.")}
      ${qa("setup", "aicoding", "Local AI coding", "Run Ollama models on your machine, in the terminal or a browser UI.")}
      ${qa("setup", "toolkit", "Prebuilt toolkit", "Install the whole CLI toolkit + SSH in one command.")}
    </div>
    ${isOwner ? `<div class="admin-card"><strong>Owner controls</strong><p class="muted">You're the owner &mdash; admin features live under Admin in the sidebar.</p></div>` : ""}
    ${homeWidgetsHTML()}`;
  main.addEventListener("click", (e) => { const b = e.target.closest("[data-sec]"); if (b) show(b.dataset.sec, b.dataset.more || ""); });
  wireHome(main, show);
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
      <div class="set-row"><span class="muted">Theme</span>
        <span class="seg" id="sw-theme"><button data-t="dark">Dark</button><button data-t="light">Light</button></span></div>
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
  const themeSeg = main.querySelector("#sw-theme");
  const curTheme = document.documentElement.getAttribute("data-theme") || "dark";
  themeSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.t === curTheme));
  themeSeg.onclick = (e) => { const b = e.target.closest("button[data-t]"); if (!b) return; applyTheme(b.dataset.t); themeSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); };
  main.querySelector("#set-out").onclick = () => signOut(auth);
  main.querySelector("#set-tour").onclick = () => startTour(tourSteps(isOwner));
  main.querySelector("#set-pw").onclick = async () => {
    try { await sendPasswordResetEmail(auth, user.email); alert("Password reset link sent to " + user.email); }
    catch (e) { alert(errText(e)); }
  };
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
          <div class="side-group">Workspace</div>
          <button class="side-item" data-sec="home">Home</button>
          <button class="side-item" data-sec="tools">Tools</button>
          <div class="side-group">Knowledge</div>
          <button class="side-item" data-sec="cheats">Cheat sheets</button>
          <button class="side-item" data-sec="threat">Threat intel</button>
          <button class="side-item" data-sec="learn">Learn</button>
          <div class="side-group">System</div>
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
    else if (sec === "cheats") renderCheats(main);
    else if (sec === "threat") renderThreat(main);
    else if (sec === "learn") renderLearn(main);
    else if (sec === "setup") renderSetup(main, more);
    else if (sec === "settings") renderSettingsPage(main, user, isOwner);
    else if (sec === "admin") renderAdmin(main, user);
    else renderHome(main, user, isOwner, show);
    main.scrollTop = 0;
  }
  view.querySelector(".side-nav").onclick = (e) => { const b = e.target.closest(".side-item"); if (b) show(b.dataset.sec); };

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
        <button class="menu-item" data-nav="home">Home</button>
        <button class="menu-item" data-nav="tools">Tools</button>
        <button class="menu-item" data-nav="cheats">Cheat sheets</button>
        <button class="menu-item" data-nav="threat">Threat intel</button>
        <button class="menu-item" data-nav="learn">Learn</button>
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
  document.getElementById("cmdkBtn").onclick = openPalette;

  appShow = show;
  show("home");
  if (!tourDone()) setTimeout(() => startTour(tourSteps(isOwner)), 450);
}

// ---- command palette (Ctrl/Cmd+K) ----
function openPalette() {
  if (document.getElementById("cmdk")) return;
  const sections = [["home", "Home"], ["tools", "Tools"], ["cheats", "Cheat sheets"], ["threat", "Threat intel"], ["learn", "Learn"], ["setup", "Local setup"], ["settings", "Settings"], ["admin", "Admin"]];
  const items = [
    ...sections.map(([s, n]) => ({ type: "section", id: s, name: n, desc: "Go to " + n })),
    ...CATALOG.map((t) => ({ type: "tool", id: t.id, name: t.name, desc: t.cat + " · " + t.desc })),
    ...CHEATS.map((c) => ({ type: "section", id: "cheats", name: c.name + " cheat sheet", desc: "Cheat sheet · " + c.cat })),
    ...RESOURCES.map((r) => ({ type: "link", id: r.url, name: r.name, desc: "Resource · " + r.tag })),
  ];
  const ov = document.createElement("div");
  ov.id = "cmdk"; ov.className = "cmdk";
  ov.innerHTML = `<div class="cmdk-box"><input class="cmdk-input" id="cmdk-in" placeholder="Search tools and sections..." autocomplete="off" spellcheck="false"><div class="cmdk-list" id="cmdk-list"></div></div>`;
  document.body.appendChild(ov);
  const inp = ov.querySelector("#cmdk-in"), list = ov.querySelector("#cmdk-list");
  let sel = 0, filtered = items;
  const close = () => ov.remove();
  function render(q) {
    const t = q.toLowerCase().trim();
    filtered = (t ? items.filter((x) => (x.name + " " + x.desc).toLowerCase().includes(t)) : items).slice(0, 60);
    if (sel >= filtered.length) sel = 0;
    list.innerHTML = filtered.map((x, i) => `<div class="cmdk-item${i === sel ? " sel" : ""}" data-i="${i}"><span class="cmdk-name">${esc(x.name)}</span><span class="cmdk-desc">${esc(x.desc)}</span></div>`).join("") || `<div class="cmdk-empty">No results</div>`;
    const a = list.querySelector(".cmdk-item.sel"); if (a) a.scrollIntoView({ block: "nearest" });
  }
  function run(i) {
    const x = filtered[i]; if (!x) return; close();
    if (x.type === "link") { window.open(x.id, "_blank", "noopener"); return; }
    if (x.type === "section") { appShow && appShow(x.id); return; }
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

// Whitelist enforcement: if the owner turned it on, only allow-listed emails may use the site.
async function accessAllowed(user) {
  if (user.email === OWNER_EMAIL) return true;
  try {
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
onAuthStateChanged(auth, async (user) => {
  if (!user) { showLanding(); return; }
  // Google accounts are already verified; email/password users must verify.
  const providerEmailPw = user.providerData.some((p) => p.providerId === "password");
  if (providerEmailPw && !user.emailVerified) { renderVerify(user); return; }
  if (!(await accessAllowed(user))) {
    alert("Access restricted — your email isn't on the allow-list. Contact the owner.");
    await signOut(auth); return;
  }
  await ensureUserDoc(user);
  renderApp(user);
  loadAnnouncement();
});
