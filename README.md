# Darknode — Web

**[darknode.ai](https://darknode.ai)** — a browser-based cybersecurity platform:
192 security tool platforms and 900+ in-browser utilities, threat intelligence,
CTF/lab content, a built-in AI assistant, and install paths for the desktop app,
CLI, and OS that run deeper work on your own machine.

This repository is the **website** — a static single-page app plus a thin
serverless backend. The desktop app, the CLI/Nexus agent, and the OS live in
their own repositories (see [Ecosystem](#ecosystem)).

## Stack (what actually runs)

- **Hosting:** Firebase Hosting (project `sentinel-b4194`), serving `public/`
  as a no-build-step SPA. Custom domain `darknode.ai`.
- **Auth & data:** Firebase Authentication (Google, GitHub, email/password) and
  Cloud Firestore, both scoped per-user by Security Rules in `firebase/`.
- **AI proxy:** a Cloudflare Worker (`worker/`) and a Firebase Function
  (`functions/`, the `chat` endpoint) that hold the free-tier model keys
  server-side; the browser never sees them. A local **Ollama** option
  (`127.0.0.1:11434`) keeps AI fully on-device when the user runs it.
- **No build step** today: `public/index.html` loads one ES-module entry
  (`js/auth.js`) that lazily pulls in the page controllers.

> There is **no** Cloudflare Pages deployment and **no** Fly.io API server for
> the website. (A separate `darknode-api` repo exists for ecosystem licensing;
> the website does not depend on it.)

## Scale (measured, not marketing)

- `public/` ≈ **488K lines** of first-party source (≈461K JS), across **216**
  JS modules — excludes third-party libraries.
- **192** tool platforms (`CATALOG` in `js/toolkit.js`) + **902** Toolbox
  mini-tools across 16 categories (`js/tools-manifest.js`).
- "Zero cloud dependency" does **not** apply to the website — it relies on
  Firebase Auth/Firestore and external threat-intel APIs. The *local-first AI*
  claim (Ollama) is the accurate version of that idea.

## Develop

```bash
npm install            # dev/test tooling only (the site itself has no build)
npm test               # zero-dep test runner: node test/run.mjs
npx serve public/      # serve the static site locally
```

## Deploy

```bash
firebase deploy --only hosting      # the static site
firebase deploy --only functions    # the AI chat / pairing functions
firebase deploy --only firestore:rules,storage:rules
# the Cloudflare Worker proxy deploys separately:  cd worker && npx wrangler deploy
```

## Ecosystem

| Repo | What it is |
|---|---|
| **darknode-web** (this) | The website + serverless backend |
| **darknode-app** | Electron desktop workstation (native scanners, terminals, VMs, AI) |
| **nexus** / **darknode-cli** | The Nexus AI agent engine (49 modules) and the `darknode`/`nexus` CLI that ships it |
| **darknode-os** / **darknode-os-distro** | A from-scratch x86 kernel, and a cloud-init-provisioned security workstation image |
| **darknode-api** | Standalone licensing/telemetry API (not used by the website) |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the module tree and data flow.

## Security

Report vulnerabilities via [SECURITY.md](SECURITY.md).

## License

See [LICENSE](LICENSE). Unauthorized reproduction is prohibited.
