// Firebase init for Sentinel Web.
// Get firebaseConfig from: Firebase Console -> Project settings -> Your apps -> Web app (</>).
// The apiKey here is NOT a secret (it only identifies the project); real protection
// comes from the Firestore/Storage Security Rules in ../firebase/.

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
import { getAuth, GoogleAuthProvider } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";
import { getStorage } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-storage.js";

export const firebaseConfig = {
  apiKey: "REPLACE_ME",
  authDomain: "REPLACE_ME.firebaseapp.com",
  projectId: "REPLACE_ME",
  storageBucket: "REPLACE_ME.appspot.com",
  messagingSenderId: "REPLACE_ME",
  appId: "REPLACE_ME",
};

// The single super-admin. Enforced in the Security Rules via request.auth.token.email.
export const OWNER_EMAIL = "cashzombs@gmail.com";

// PUBLIC Google OAuth client id (safe to commit).
// NOTE: this is a "Desktop app" client. Browser sign-in needs a "Web application" client.
// With Firebase Auth you normally do NOT use this directly - Firebase manages its own
// web OAuth client when you enable the Google provider. Kept here for reference / in case
// you switch to Google Identity Services directly.
export const GOOGLE_CLIENT_ID = "206219019752-er2rsbl36m32ct8f2gn2i46tbovvn7j1.apps.googleusercontent.com";

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);
export const googleProvider = new GoogleAuthProvider();
