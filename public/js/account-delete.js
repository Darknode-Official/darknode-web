// Self-service account deletion (Deck Settings > Data, and the older settings page). The
// Worker's POST /api/account/delete removes every server record and then the sign-in
// (worker/account-delete.js); this side confirms, re-checks the sign-in when it is older
// than 5 minutes, and clears this account's data from the browser afterwards.
import { auth, googleProvider, githubProvider } from "/js/firebase.js?v=20261021a";
import { reauthenticateWithPopup, reauthenticateWithCredential, EmailAuthProvider, signOut } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-auth.js";

const proxyBase = () => { try { return String(window.DARKNODE_PROXY_URL || "").replace(/\/api\/chat$/, ""); } catch (_) { return ""; } };
const modal = (o) => (typeof window.dnModal === "function" ? window.dnModal(o) : Promise.resolve(null));

async function callDelete(user, fresh) {
  const r = await fetch(proxyBase() + "/api/account/delete", {
    method: "POST",
    headers: { Authorization: "Bearer " + (await user.getIdToken(fresh)), "Content-Type": "application/json" },
    body: JSON.stringify({ confirm: "DELETE" }),
  });
  let body = {}; try { body = await r.json(); } catch (_) {}
  return { ok: r.ok, status: r.status, body };
}

// Sign in again with the account's own method. -> true when it worked.
async function reauth(user) {
  const ids = (user.providerData || []).map((p) => p.providerId);
  try {
    if (ids.includes("google.com")) { await reauthenticateWithPopup(user, googleProvider); return true; }
    if (ids.includes("github.com")) { await reauthenticateWithPopup(user, githubProvider); return true; }
    if (ids.includes("password") && user.email) {
      const v = await modal({ title: "Confirm it's you", desc: "Enter the password for " + user.email + ".", fields: [{ inputType: "password", placeholder: "Password" }], submitText: "Continue" });
      if (!v || !v[0]) return false;
      await reauthenticateWithCredential(user, EmailAuthProvider.credential(user.email, v[0]));
      return true;
    }
  } catch (_) {}
  return false;
}

// Remove this account's data from this browser only: keys named with its uid, its saved
// API keys, and its local security-graph snapshots. Other accounts on a shared browser keep theirs.
async function clearLocal(uid) {
  try { if (window.dnKeys && window.dnKeys.clearForUid) window.dnKeys.clearForUid(uid); } catch (_) {}
  try {
    const rm = [];
    for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (k && k.includes(uid)) rm.push(k); }
    rm.forEach((k) => localStorage.removeItem(k));
    localStorage.removeItem("dn_active_ws");
  } catch (_) {}
  try {
    await new Promise((resolve) => {
      const req = indexedDB.open("dn-secgraph", 1);
      req.onerror = req.onblocked = () => resolve();
      req.onupgradeneeded = () => { try { req.result.createObjectStore("snap"); } catch (_) {} };
      req.onsuccess = () => {
        try {
          const db = req.result, tx = db.transaction("snap", "readwrite"), st = tx.objectStore("snap");
          const kr = st.getAllKeys();
          kr.onsuccess = () => { (kr.result || []).filter((k) => String(k).includes(uid)).forEach((k) => st.delete(k)); };
          tx.oncomplete = tx.onerror = tx.onabort = () => { db.close(); resolve(); };
        } catch (_) { resolve(); }
      };
    });
  } catch (_) {}
}

export async function deleteAccount({ toast = () => {} } = {}) {
  const user = auth.currentUser;
  if (!user) { toast("Sign in first.", "error"); return false; }
  if (!proxyBase()) { toast("Account deletion needs the cloud proxy, which this build has not configured.", "error"); return false; }
  const v = await modal({
    title: "Delete your Darknode account?",
    desc: "This permanently deletes the account " + (user.email || "") + " and everything stored with it: your security graph, monitors and domain watch, API keys, settings and notifications, and any team workspace you hold alone. Team workspaces you joined keep their own data. This cannot be undone. Type DELETE to confirm.",
    fields: [{ placeholder: "DELETE" }],
    submitText: "Delete account", danger: true,
  });
  if (!v) return false;
  if (String(v[0] || "").trim() !== "DELETE") { toast("Type DELETE in capitals to confirm.", "error"); return false; }
  let r;
  try {
    r = await callDelete(user, false);
    if (r.status === 401 && r.body.reauth) {
      if (!(await reauth(user))) { toast("Couldn't confirm it's you. Sign out, sign in again, then delete within 5 minutes.", "error"); return false; }
      r = await callDelete(user, true);
    }
  } catch (_) { toast("Couldn't reach Darknode. Check your connection and try again.", "error"); return false; }
  if (r.status === 409) { await modal({ title: "Remove the other members first", desc: r.body.error, submitText: "OK", cancelText: "Close" }); return false; }
  if (!r.ok) { toast(r.body.error || "Deletion failed (HTTP " + r.status + "). Try again.", "error"); return false; }
  const uid = user.uid;
  await clearLocal(uid);
  await modal({ title: "Your account is deleted", desc: "Your Darknode account and its data are gone. You can sign up again at any time with a new account.", submitText: "OK", cancelText: "Close" });
  try { await signOut(auth); } catch (_) {}
  try { location.replace("/"); } catch (_) {}
  return true;
}
