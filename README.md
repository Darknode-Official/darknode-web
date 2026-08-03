# Sentinel Web

Google-login hacking-tools portal. **Static frontend on Netlify + Firebase backend**
(Auth, Firestore, Storage, Security Rules). No server code to deploy.

Owner / super-admin: `cashzombs@gmail.com` (fixed in `js/firebase.js` and both `.rules` files).

## Layout
```
index.html              app shell
css/                    styles
js/
  firebase.js           Firebase config + init  <-- fill firebaseConfig
  auth.js               Google sign-in, role resolve, forced-signout watcher
  admin.js              Account Settings (whitelist / announcements / logout-all)
  ssh-wizard.js         OpenSSH guide + ssh-command generator
  tools/index.js        client-side utilities (encoders, reverse-shell, ...)
views/                  home, downloads, ssh-setup, pending-access, account-settings
firebase/               Security Rules (deploy to Firebase, NOT to Netlify)
  firestore.rules
  storage.rules
netlify.toml            static hosting config
```

## Access model
Anyone can sign in with Google. A user's `users/{uid}.status` is one of:
- `owner`  - email == `cashzombs@gmail.com` (enforced by rules via `request.auth.token.email`)
- `allowed` - on the whitelist (only the owner can set this)
- `pending` - default; sees the "Access pending" screen and can request access

All gating is enforced by the **Security Rules**, not the browser, so a tampered client
cannot reach gated data or downloads.

## Setup (once)
1. **Firebase Console** -> create a project.
2. **Build -> Authentication** -> enable the **Google** sign-in provider.
3. **Authentication -> Settings -> Authorized domains** -> add your Netlify URL
   (e.g. `your-site.netlify.app`).
4. **Firestore Database** -> create (production mode) -> paste `firebase/firestore.rules`.
5. **Storage** -> get started -> paste `firebase/storage.rules`.
6. **Project settings -> Your apps -> Web app (</>)** -> copy the config into
   `js/firebase.js` (`firebaseConfig`).
7. Deploy: drag this folder into **Netlify** (or `netlify deploy`).

Note on the OAuth client ID in `js/firebase.js` (`GOOGLE_CLIENT_ID`): the value provided
is a **Desktop app** client from Google Cloud. Firebase Auth does **not** use it - it
manages its own web OAuth client when you enable the Google provider. Browser sign-in via
raw Google Identity Services would need a **Web application** client instead. The ID is
public and harmless to keep; it is not what powers Firebase login.

## "Log out everyone but me"
Owner bumps `settings/session_epoch`; every other client's watcher signs it out. Removing a
user from the whitelist hard-blocks their data/downloads immediately via the rules. Truly
revoking live tokens would need one optional Firebase Cloud Function (Admin SDK).
