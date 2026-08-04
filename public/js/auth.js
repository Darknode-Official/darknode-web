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
import { MORE } from "/js/toolkit.js";
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
  document.body.classList.remove("landing");
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
  document.body.classList.remove("landing");
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

// Simple dismissable modal overlay.
function showModal(titleTxt, html) {
  const ov = document.createElement("div");
  ov.className = "tk-modal";
  ov.innerHTML = `<div class="tk-modal-box"><div class="tk-modal-hd"><span>${esc(titleTxt)}</span>
    <button class="btn ghost sm" data-close>Close</button></div><div class="tk-modal-body">${html}</div></div>`;
  ov.addEventListener("click", (e) => { if (e.target === ov || e.target.closest("[data-close]")) ov.remove(); });
  document.body.appendChild(ov);
  return ov;
}

function openMore(m) {
  const ov = showModal(m.name, `<p class="muted">${esc(m.desc)}</p>
    <div class="dl-cmd-row"><code class="dl-cmd cmd-block">${esc(m.body)}</code><button class="dl-copy" data-copy>copy</button></div>`);
  ov.querySelector("[data-copy]").onclick = (e) =>
    navigator.clipboard?.writeText(m.body).then(() => { e.target.textContent = "copied"; setTimeout(() => (e.target.textContent = "copy"), 1200); });
}

function openSettings(user, isOwner) {
  const providers = user.providerData.map((p) => p.providerId.replace(".com", "")).join(", ") || "password";
  const ov = showModal("Settings", `
    <div class="set-block"><div class="set-lbl">Account</div>
      <div>${esc(user.email)}${isOwner ? ' <span class="owner-badge">OWNER</span>' : ""}</div>
      <div class="muted" style="font-size:.78rem">Signed in via ${esc(providers)}</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:14px">
      <button class="btn ghost" data-s="changepw">Change password</button>
      <button class="btn ghost" data-s="tour">Replay walkthrough</button>
      <button class="btn danger" data-s="logout">Log out</button>
    </div>`);
  ov.querySelector('[data-s="logout"]').onclick = () => signOut(auth);
  ov.querySelector('[data-s="tour"]').onclick = () => { ov.remove(); startTour(tourSteps(isOwner)); };
  ov.querySelector('[data-s="changepw"]').onclick = async () => {
    try { await sendPasswordResetEmail(auth, user.email); alert("Password reset link sent to " + user.email); }
    catch (e) { alert(errText(e)); }
  };
}

function renderApp(user) {
  document.body.classList.remove("landing");
  const isOwner = user.email === OWNER_EMAIL;
  const avatar = user.photoURL
    ? `<img class="p-avatar" src="${esc(user.photoURL)}" alt="">`
    : `<span class="p-avatar p-initials">${esc((user.email || "?")[0].toUpperCase())}</span>`;

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
        <div class="menu-hd">${esc(user.email)}${isOwner ? ' <span class="owner-badge">OWNER</span>' : ""}</div>
        <button class="menu-item" data-a="settings">Settings</button>
        <button class="menu-item" data-a="logout">Log out</button>
      </div>
    </div>`;

  const profileMenu = document.getElementById("profileMenu");
  const moreMenu = document.getElementById("moreMenu");
  const closeMenus = () => { profileMenu.hidden = true; moreMenu.hidden = true; };
  document.getElementById("profileBtn").onclick = (e) => { e.stopPropagation(); const h = profileMenu.hidden; closeMenus(); profileMenu.hidden = !h; };
  document.getElementById("moreBtn").onclick = (e) => { e.stopPropagation(); const h = moreMenu.hidden; closeMenus(); moreMenu.hidden = !h; };
  document.addEventListener("click", closeMenus);
  profileMenu.onclick = (e) => { const b = e.target.closest("[data-a]"); if (!b) return; closeMenus(); b.dataset.a === "logout" ? signOut(auth) : openSettings(user, isOwner); };
  moreMenu.onclick = (e) => { const b = e.target.closest("[data-more]"); if (!b) return; closeMenus(); openMore(MORE.find((m) => m.id === b.dataset.more)); };

  view.innerHTML = `
    <section class="card">
      <h1>Welcome${user.displayName ? ", " + esc(user.displayName) : ""}</h1>
      <p class="muted">Signed in as ${esc(user.email)}.</p>
      ${isOwner ? `<div class="admin-card"><strong>Owner controls</strong><p class="muted">Admin-only features live here (user management, announcements). Wired to your account.</p></div>` : ""}
    </section>
    <section class="card" id="tools-section">
      <h2>Tools</h2>
      <p class="muted">Search the catalog and expand any tool. Browser tools run right here; the rest show their install command.</p>
      <div id="tools"></div>
    </section>`;
  renderTools(document.getElementById("tools"));
  if (!tourDone()) setTimeout(() => startTour(tourSteps(isOwner)), 450);
}

function tourSteps(isOwner) {
  const steps = [
    { title: "Welcome to Sentinel", text: "A quick tour of the place. You can skip anytime." },
    { sel: "#tools-section", title: "Your tools", text: "Search the catalog and click a tool to expand it. Browser tools (Base64, hashes, reverse-shell, subnet calc...) run right here; server tools reveal their install command." },
    { sel: "#moreBtn", title: "The … menu", text: "Spin up the full local toolkit + SSH, or a local AI coding setup with Ollama, from here." },
    { sel: "#profileBtn", title: "Your profile", text: "Settings, change password, and log out live here." },
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
