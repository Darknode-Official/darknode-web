# Architecture

**Darknode Web** is the marketing site **and** the full web console for
[darknode.ai](https://darknode.ai). Signed-out visitors get a landing page with
app/CLI/OS downloads; signed-in users get a single-page console: a browser tool
arsenal (192 tool platforms + 900+ Toolbox mini-tools), payload / dork /
exploit-DB libraries, threat intel and cheat sheets, a built-in AI assistant
(hosted free tier or local Ollama), a report generator, a Private-Cloud
compose generator, the Nexus showcase, docs, and download pages. Aimed at
authorized pentesters and security learners.

There is **no build step**: `public/index.html` loads a single ES-module entry
(`js/auth.js`) which lazily imports the page controllers. `public/js` holds
**216** modules (≈461K lines of JS; ≈488K lines across `public/`). State lives
in Firebase (Auth + Firestore) and `localStorage`.

> **README and this document agree.** (Earlier revisions of each described an
> aspirational Cloudflare Pages + Fly.io stack and a product called "Sentinel";
> both are corrected. The live project is Firebase-hosted and branded Darknode.)

## Hosting & backend

- **Firebase Hosting.** `firebase.json` publishes `public/` with a strict
  security header set — **CSP**, **HSTS** (`max-age=31536000; includeSubDomains;
  preload`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy`, and `Permissions-Policy` — plus an SPA fallback (all routes
  → `/index.html`) and a `/api/chat` rewrite to the `chat` Function. Domain:
  darknode.ai. `.firebaserc` pins project **`sentinel-b4194`** (the original
  project id; renaming a live Firebase project would require a full auth/data
  migration, so the legacy id is kept and documented rather than changed).
  Two hosting targets exist (`sentinel-b4194`, `sentinel-b4194-6173e`).
- **Serverless AI proxy.** Model keys for the free tier live **server-side**,
  never in the browser:
  - `functions/index.js` — the `chat` Function (Gemini + fallbacks), with a
    server-enforced Darknode persona, an **origin allow-list**, and a per-IP
    **rate limit**. Also hosts `pair`, the Nexus CLI pairing-code exchange.
  - `worker/worker.js` — a Cloudflare Worker (`darknode-proxy`) serving
    `/api/chat` + `/api/smart`, same origin/rate gating.
  - `js/webai.js` — the in-browser assistant; can target the hosted proxy or a
    **local Ollama** at `127.0.0.1:11434` so nothing leaves the machine.
- **Auth & data.** Firebase Auth (Google + GitHub OAuth + email/password with
  verification) and Cloud Firestore. Per-user isolation is enforced by
  `firebase/firestore.rules` (each user owns `users/{uid}`; the one super-admin
  `OWNER_EMAIL` is checked via `request.auth.token.email`). The client uses **no
  Firebase Storage** (`js/firebase.js` omits the Storage SDK); installer
  downloads live on **GitHub Releases**, and `firebase/storage.rules` remains as
  a deny-by-default backstop.
- **Per-user credentials.** `js/user-keys.js` (`window.dnKeys`) namespaces every
  browser-stored credential by uid (`dnk:<uid>:*`) so two accounts on one
  browser can never read each other's keys; no-account sessions get a random
  per-session uid.

## Module map (high level)

216 modules is too many to list; they group as:

```
public/
  index.html            app shell; loads js/auth.js as the ONLY entry <script>
  css/styles.css        core stylesheet (~9.6K lines); pro-theme.css adds the skin
  js/
    firebase.js         [adapter] Firebase init/config; exports auth/db/providers/OWNER_EMAIL
    user-keys.js        [core]    window.dnKeys — per-uid credential isolation
    auth.js             [core]    app entry + SPA router (~2.5K lines): auth flow,
                                  email/code verify, access gate, show(sec) dispatch,
                                  Ctrl-K palette, feedback modal, announcements, profile,
                                  Settings (incl. Nexus pairing-code generator)
    admin.js            [adapter] owner-only console (user stats, allow-list, announcements)
    api.js              [adapter] the user's Darknode API key (Firestore users/{uid}.apiKey)
    saved.js            [adapter] saved workspace (Firestore or localStorage)
    toolkit.js          [data]    the 192-entry tool CATALOG + browser-tool engine
    tools-manifest.js   [data]    902 Toolbox mini-tool ids/names/cats (generated)
    tools/*.js          [tools]   mini-tool implementations + plain-English help
    webai.js            [feature] AI assistant (hosted proxy or local Ollama)
    <~200 more>         page controllers + flagship tool apps (phantom, oracle, citadel,
                        spectre, navarch, crucible, sentinel-eye globe, …), data libs,
                        threat-intel, console nav, toasts, modals, core/ spine
firebase/
  firestore.rules       per-user users/{uid}; owner-only settings/announcements;
                        feedback create-any; pairings create-own / server-consumed
  storage.rules         deny-by-default (client uses no Storage)
functions/index.js      chat (AI proxy) + pair (CLI pairing exchange)
worker/worker.js        Cloudflare Worker AI proxy (/api/chat, /api/smart)
firebase.json           Hosting + headers + Functions + Firestore/Storage rules
.firebaserc             Firebase project sentinel-b4194
```

## App & data flow

```
index.html
   └─ loads js/user-keys.js then js/auth.js (the only module entry)
         │
         ▼
   onAuthStateChanged → sets window.__dnUid (per-uid key scope)
         │  (email/password?) → verify via notify.js code, else Firebase link
         ▼
   access gate → ensureUserDoc() writes users/{uid}
         ▼
   renderApp() → builds the sidebar + a show(sec) dispatcher mapping each
                 data-sec to a controller's render*() that paints #view
```

- **Backend adapters** (`firebase.js`, `auth.js`, `admin.js`, `api.js`,
  `saved.js`) are the only files that talk to Firebase; every read/write is
  enforced by the Security Rules, not by client JS.
- **AI requests** go to the server-side proxy (keys never shipped) or to local
  Ollama.
- **Page controllers** each export a `render*()`; **shared data/util modules**
  (`toolkit.js`, `target.js`, `notify.js`, …) back them.

## Relationship to the CLI / Nexus

This repo runs **no** AI agent. `coder.js` / `docs.js` showcase and document the
**`darknode` / `nexus`** CLI, and the download pages (`getapp.js`, `landing.js`)
link to its binaries. The agent runtime — the multi-engine, policy-gated Nexus
(49 modules) — lives in the sibling **nexus** engine and the **darknode-cli**
product shell, published to GitHub Releases under the **Darknode-Official** org.
Both share a local-first stance: the web `webai.js` and the CLI's Ollama client
target `127.0.0.1:11434` so work can stay on-device.
