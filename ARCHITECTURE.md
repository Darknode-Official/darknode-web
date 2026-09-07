# Architecture

Sentinel Web is the marketing site **and** the full web console for *Sentinel —
Terminal Edition*. Signed-out visitors get a landing page with app/CLI downloads;
signed-in users get a single-page console with a browser tool arsenal, payload /
dork / exploit-DB libraries, threat intel and cheat sheets, a private local-Ollama
assistant, a report generator, a docker-compose "private cloud" generator, the
Nexus showcase, docs, and gated downloads. Aimed at authorized pentesters and
security learners.

There is **no build step**: `public/index.html` loads a single ES-module entry
(`js/auth.js`) which imports ~26 page controllers. State lives in Firebase
(Auth + Firestore + Storage) and `localStorage`.

> **Note:** the README describes an older/aspirational layout (`ssh-wizard.js`,
> `views/`, a pending/allowed/owner model) that no longer matches the tree. This
> document reflects the **actual code** — a single-page app driven by `auth.js`.

## Hosting & backend

- **Firebase Hosting.** `firebase.json` publishes `public/` to Firebase Hosting
  with security headers (`X-Frame-Options: DENY`, `nosniff`, `no-referrer`) and
  an SPA fallback (all routes → `/index.html`). Domain: darknode.ai (Porkbun).
  Large installers are **not** committed — they live on **GitHub Releases**
  (`SpartanKing18/sentinel-web`, tag `sentinel`);
  `public/downloads/` is a git-ignored placeholder.
- **Firebase backend.** `.firebaserc` pins project `sentinel-b4194`; `firebase.json`
  deploys hosting, Firestore rules, and Storage rules.
  Auth = Google + GitHub OAuth + email/password with verification. The single
  super-admin (`OWNER_EMAIL = cashzombs@gmail.com`) is hard-coded in the rules and
  in `js/firebase.js`; owner status is evaluated client-side but **enforced
  server-side** by the rules.

## Module tree

```
public/
  index.html            app shell: boot splash, topbar, announcement banner,
                        <main id="view">; loads js/auth.js as the ONLY entry
  css/styles.css        all styling (1130 lines) — dark/light theme
  arsenal.sh            curl|bash installer: turns Debian/Ubuntu/Kali into a
                        Kali+BlackArch toolset (idempotent, category-selectable)
  js/
    firebase.js          [adapter] Firebase init/config; exports auth/db/storage/
                         providers/OWNER_EMAIL
    auth.js              [core]    app entry + SPA router. Auth flow, email/code
                         verify, whitelist gate, show(sec) dispatcher, Ctrl-K
                         palette, feedback modal, announcements, profile menu.
                         Imports every page controller.
    admin.js             [adapter] owner-only console: user stats, allow-list
                         (settings/whitelist), announcements. Exports getWhitelist()
    saved.js             [adapter] saved workspace (bookmarks + notes): Firestore
                         users/{uid}.workspace when signed in, else localStorage
    target.js            [shared]  one recon target (domain/IP) in localStorage +
                         change events; consumed by cyber/ghdb/exploitdb
    toolkit.js           [shared]  tool catalog data + browser-tool engine
                         (base64/url/hex/rot13…); feeds tools.js + palette
    notify.js            [shared]  EmailJS client-side email (verification codes +
                         login alerts); falls back to Firebase email link
    tour.js              [shared]  game-style guided walkthrough overlay
    utils.js             in-browser utilities: hashing, hash-ID, entropy, encoders
    landing.js           signed-out marketing landing (edition cards, downloads)
    cyber.js             threat intel: CVE feed, cheat sheets, ports, learning
    tools.js             renders the searchable tools catalog from toolkit.js
    labs.js              reference libraries: payloads, snippets, api-keys, refs
    ghdb.js              Google Hacking Database — dorks scoped to the target
    exploitdb.js         pivot search across Exploit-DB / NVD / CISA KEV / Shodan
    vms.js               directory of vulnerable VMs + hypervisors
    privatecloud.js      Private Cloud Generator — docker-compose + .env + README
    report.js            findings collector → Markdown pentest report export
    arsenal.js           curated directories of external tools/platforms/training
    github.js            client-side GitHub integration (profile/repos/activity)
    coder.js             Nexus showcase — markets `sentinel nexus` (does not run it)
    getapp.js            "Get the app" — live GitHub-Releases assets, sizes, tiers
    downloads.js         per-OS install commands for dev tools/runtimes
    webai.js             local Ollama assistant (127.0.0.1:11434), streaming chat
    docs.js              documentation hub — Nexus command reference + policy pages
firebase/
  firestore.rules       per-user users/{uid} ownership; owner-only settings/
                        announcements; feedback create-any / read-owner
  storage.rules         /downloads/** gated to owner + status=='allowed'; else deny
  firestore.indexes.json  empty (no composite indexes)
firebase.json           Firebase Hosting + Firestore + Storage rules config
.firebaserc             default Firebase project sentinel-b4194
```

## App & data flow

```
index.html
   └─ loads js/auth.js  (the only <script type=module>)
         │
         ▼
   onAuthStateChanged
         │  (email/password?) → verify via notify.js 6-digit code, else Firebase link
         ▼
   accessAllowed()  ── reads settings/whitelist via admin.js.getWhitelist()
         ▼
   ensureUserDoc()  ── writes users/{uid}
         ▼
   renderApp()  ── builds the sidebar (Workspace / Offense / Develop / Resources /
                   System) and a show(sec) dispatcher that maps each data-sec to a
                   controller's render*() function.
```

- **Backend adapters** (`firebase.js`, `auth.js`, `admin.js`, `saved.js`) are the
  only files that talk to Firebase. All reads/writes are enforced by
  `firestore.rules` / `storage.rules`.
- **Page controllers** each export a `render*()` that paints `#view`.
- **Shared utilities** (`target.js`, `toolkit.js`, `notify.js`, `tour.js`) have no
  page of their own and are consumed by the controllers.
- `auth.js` (~744 lines) is the hub — ~17% of all JS. The next tier (`cyber`,
  `labs`, `admin`, `utils`, `landing`, `toolkit`) are the content-heavy modules;
  `target.js` / `firebase.js` / `vms.js` are the thin leaves.

## Relationship to sentinel-cli

This repo runs no AI agent. `coder.js` and `docs.js` **showcase and document**
`sentinel nexus`, and `getapp.js` / `landing.js` link to the CLI binary. The actual
Nexus runtime — the multi-engine, policy-gated agent — lives entirely in the
sibling **[sentinel-cli](https://github.com/SpartanKing18/sentinel-cli)** repo and
ships as a download from GitHub Releases. Both share a private, on-device AI stance:
web `webai.js` and the CLI's `lib/nexus/ollama.js` both target a local Ollama at
`127.0.0.1:11434` so nothing has to leave the machine.
