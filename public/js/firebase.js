// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Firebase init for Darknode Web.
// The apiKey here is NOT a secret (it only identifies the project); real protection
// comes from the Firestore/Storage Security Rules in ../firebase/.
if(!/^(darknode\.ai|www\.darknode\.ai|sentinel-b4194\.web\.app|sentinel-b4194-6173e\.web\.app|darknode-web-[a-z0-9]+\.onrender\.com|localhost|127\.0\.0\.1)$/.test(location.hostname)){throw new Error("unlicensed")}

import { initializeApp } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-app.js";
import { getAuth, GoogleAuthProvider, GithubAuthProvider } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-auth.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";
// No Storage SDK: nothing in public/js uses it, and it was a whole extra module on the boot path.

const _authDomain = (location.hostname === "darknode.ai" || location.hostname === "www.darknode.ai")
  ? "darknode.ai" : "sentinel-b4194.firebaseapp.com";
export const firebaseConfig = {
  apiKey: "AIzaSyD3CJO7PLQdRvPOWDqehSlRwEeA5odCTDE",
  authDomain: _authDomain,
  projectId: "sentinel-b4194",
  storageBucket: "sentinel-b4194.firebasestorage.app",
  messagingSenderId: "153127828172",
  appId: "1:153127828172:web:94f864818f562c10cfa069",
  measurementId: "G-8QR8V3DLQX",
};

// The single super-admin is identified by a Firebase custom claim (`admin: true`),
// set out-of-band by scripts/set-admin.mjs — never by a hardcoded email in the
// shipped bundle. The Security Rules enforce it via request.auth.token.admin, and
// the client reads it from the signed ID token (which the client cannot forge).
export async function isAdminUser(user) {
  if (!user || typeof user.getIdTokenResult !== "function") return false;
  try {
    const res = await user.getIdTokenResult();
    return !!(res && res.claims && res.claims.admin === true);
  } catch (_) { return false; }
}

// PUBLIC Google OAuth client id (safe to commit — a client id is not a secret).
// This is a "Web application" client (JavaScript origins: https://darknode.ai and
// https://www.darknode.ai). It drives the in-page Google Identity Services FedCM / One Tap
// bubble in auth.js (google.accounts.id). The returned ID token is exchanged for a Firebase
// session via signInWithCredential. (The matching client SECRET is never used in the browser.)
export const GOOGLE_CLIENT_ID = "153127828172-806br8tvkb773hbo931incl0t8ipr0p0.apps.googleusercontent.com";

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
export const googleProvider = new GoogleAuthProvider();
export const githubProvider = new GithubAuthProvider();
