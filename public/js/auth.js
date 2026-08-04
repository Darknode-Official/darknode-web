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
import { renderDownloads } from "/js/downloads.js";
import { renderTools } from "/js/tools.js";
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

function renderApp(user) {
  document.body.classList.remove("landing");
  const isOwner = user.email === OWNER_EMAIL;
  userSlot.innerHTML = `
    <span class="muted" style="font-size:.85rem">${esc(user.email)}${isOwner ? ' <span class="owner-badge">OWNER</span>' : ""}</span>
    <button class="btn ghost" id="signout" style="margin-left:10px">Sign out</button>`;
  document.getElementById("signout").onclick = () => signOut(auth);

  view.innerHTML = `
    <section class="card">
      <h1>Welcome${user.displayName ? ", " + esc(user.displayName) : ""}</h1>
      <p class="muted">Signed in as ${esc(user.email)}.</p>
      ${isOwner ? `<div class="admin-card"><strong>Owner controls</strong><p class="muted">Admin-only features live here (user management, announcements). Wired to your account.</p></div>` : ""}
      <p style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn ghost" id="changepw">Change password (email me a reset link)</button>
        <button class="btn ghost" id="replayTour">Replay walkthrough</button>
      </p>
    </section>
    <section class="card" id="tools-section">
      <h2>Tools</h2>
      <p class="muted">Click a tool to get its install command.</p>
      <div id="tools"></div>
    </section>
    <section class="card" id="downloads-section">
      <h2>Downloads</h2>
      <p class="muted">Commands to install everything &mdash; pick your OS.</p>
      <div id="downloads"></div>
    </section>`;
  document.getElementById("changepw").onclick = async () => {
    try { await sendPasswordResetEmail(auth, user.email); alert("Password reset link sent to " + user.email); }
    catch (e) { alert(errText(e)); }
  };
  document.getElementById("replayTour").onclick = () => startTour(tourSteps(isOwner));
  renderDownloads(document.getElementById("downloads"));
  renderTools(document.getElementById("tools"));
  if (!tourDone()) setTimeout(() => startTour(tourSteps(isOwner)), 450);
}

function tourSteps(isOwner) {
  const steps = [
    { title: "Welcome to Sentinel", text: "A quick tour of the place. You can skip anytime." },
    { sel: "#tools-section", title: "Your tools", text: "Every tool you can use. Click one that isn't installed to jump straight to its command." },
    { sel: ".os-tabs", title: "Your OS", text: "Pick Linux, macOS, or Windows and the commands update to match." },
    { sel: "#downloads-section .dl-card", title: "Install it", text: "Copy the command, run it in your terminal, then hit 'mark installed'." },
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
