// Google sign-in (works on localhost once the Google provider is enabled in the
// Firebase console). Minimal for now: sign in, show the user, sign out.
// Full role/whitelist/routing logic comes in the build.
import { auth, googleProvider, OWNER_EMAIL } from "/js/firebase.js";
import {
  onAuthStateChanged, signInWithPopup, signOut,
  setPersistence, browserLocalPersistence
} from "https://www.gstatic.com/firebasejs/12.17.0/firebase-auth.js";

const userSlot = document.getElementById("user-slot");
const view = document.getElementById("view");

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
));

function renderSignedOut() {
  userSlot.innerHTML = "";
  view.innerHTML = `
    <section class="card" style="max-width:420px;margin:48px auto;text-align:center">
      <h1>Sentinel</h1>
      <p class="muted">Sign in to continue.</p>
      <button class="btn" id="signin">Sign in with Google</button>
      <p id="err" style="color:var(--bad);margin-top:12px;font-size:.85rem"></p>
    </section>`;
  document.getElementById("signin").onclick = async () => {
    const err = document.getElementById("err");
    err.textContent = "";
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (e) {
      err.textContent = `${e.code || "error"}: ${e.message || e}`;
      // Most common on first run: auth/operation-not-allowed  -> enable the Google
      // provider in Firebase Console -> Authentication -> Sign-in method.
    }
  };
}

function renderSignedIn(user) {
  const isOwner = user.email === OWNER_EMAIL;
  userSlot.innerHTML = `
    <span class="muted" style="font-size:.85rem">${esc(user.email)}${isOwner ? " (owner)" : ""}</span>
    <button class="btn ghost" id="signout" style="margin-left:10px">Sign out</button>`;
  document.getElementById("signout").onclick = () => signOut(auth);
  view.innerHTML = `
    <section class="card" style="max-width:520px;margin:24px auto">
      <h1>Signed in</h1>
      <p>Welcome, <strong>${esc(user.displayName || user.email)}</strong>.</p>
      <p class="muted">Email: ${esc(user.email)}</p>
      <p class="muted">UID: ${esc(user.uid)}</p>
      <p class="muted">Role: ${isOwner ? "owner" : "signed in (whitelist &amp; tools come later)"}</p>
    </section>`;
}

setPersistence(auth, browserLocalPersistence).catch(() => {});
onAuthStateChanged(auth, (user) => {
  if (user) renderSignedIn(user);
  else renderSignedOut();
});
