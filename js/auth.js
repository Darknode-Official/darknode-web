// Auth + app entry. Resolves the signed-in user's role and renders the right view.
// This is a scaffold stub - the full logic is built in the ultraplan pass.
import { auth, db, OWNER_EMAIL, googleProvider } from "/js/firebase.js";
import {
  onAuthStateChanged, signInWithPopup, signOut
} from "https://www.gstatic.com/firebasejs/12.17.0/firebase-auth.js";

// Role resolution plan (implemented in the build):
//  1. onAuthStateChanged -> if signed out, show the "Sign in with Google" button.
//  2. On sign-in, upsert users/{uid} = { email, name, status:'pending' } (first time).
//  3. Read users/{uid}.status: 'owner' (email == OWNER_EMAIL), 'allowed', or 'pending'.
//  4. Subscribe to settings/session_epoch; if it advances past the client's epoch, signOut()
//     (this is the "log out everyone but me" mechanism).
//  5. Route: owner/allowed -> tools hub; pending -> pending-access view.
//
// Enforcement is NOT here - the Security Rules (../firebase) gate all reads/writes so a
// tampered client cannot reach gated data or downloads.

export function isOwner(user){ return !!user && user.email === OWNER_EMAIL; }

onAuthStateChanged(auth, (user) => {
  console.log("[sentinel] auth state:", user ? user.email : "signed out");
  // TODO(build): render sign-in button, resolve role, load the view.
});

export { signInWithPopup, signOut, auth, googleProvider };
