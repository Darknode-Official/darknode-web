# Ship checklist: adding or changing a feature or tool

Run this every time a feature, tool, plan change, install change or removal lands, before
asking to deploy. Skip a step only when it truly doesn't apply, and say which were skipped.

## 0. Classify the change (decides which steps apply)

| Change | Steps |
|---|---|
| New web tool or Deck tool | 1, 2, 3, 4, 7, 8 |
| New Deck space or scene | 1 (explain), 2, 3, 4, 7, 8 |
| Plan / pricing / gating change | 2, 3, 5, 7, 8 |
| Data handling, AI, network or storage change | 3, 4, 5, 7, 8 |
| Install / download / release change | 6, 2, 7, 8 |
| Tool or feature removed | 1 (unregister), 2, 3, 4, 5 if mentioned, 7, 8 |
| Nexus / CLI command change | 6, 2, 7 |

## 1. Register it (the app must actually reach it)

- **Console route:** `public/js/auth.js`, the `sec === "x"` dispatch (lazy `import("/js/...js?v=...")`).
- **Console catalog:** `public/js/tools-manifest.js` (TOOL_CATS) and `public/js/console-nav.js` (NAV groups; RETIRED set for removals). Mobile: `public/js/mobile-nav.js`.
- **Deck sidebar:** `public/js/deck-ui.js` NAV_DEF entry, plus **plan tier**: PLAN_GROUP / PLAN_ITEM (anything not listed is Free).
- **Deck native space tool:** `public/js/deck/spaces.js` (TOOLS + the space's `tabs`); console tools surfaced in a space go in a gallery list (e.g. WEB_TOOLS).
- **Hover help (test-enforced):** `public/js/ui/explain.js` needs `tool.<id>` or `scene.<id>`, or a HELP entry in `section-help-a.js` / `section-help-b.js`.
- **Section intro:** `public/js/section-help.js` if the tool has a console page.
- **Findings:** if it produces findings, wire `core/sink.js` attachSinkButton so they reach the Security Graph.
- **Removal:** take it out of every place above, plus pins and saved state that might point at it (fall back cleanly, as with the retired Finance view).

## 2. Docs and in-product copy

- `public/js/docs.js`: Getting Started (if it changes what a product does), FAQ, Changelog (current line), Nexus CMD_GROUPS (Nexus commands), Security tab (if safety-relevant). Bump `UPDATED`.
- `public/js/landing.js`: feature/bento cards, FAQ answers, pricing plan feature lists, footer links.
- `public/index.html`: JSON-LD (`featureList`, descriptions), meta description if the headline offer changed.
- `public/sitemap.xml` for any new public page; `public/robots.txt` only if crawl rules change.
- `public/js/darknode-chat.js` system prompt (the in-house assistant's description of the platform and its counts).
- `public/humans.txt` for large releases.

## 3. Legal: TOS, Privacy, Acceptable Use

The binding TOS is in `public/js/auth.js` (the `tosBox` block). `public/js/docs.js` Terms / Privacy / AUP tabs mirror it; keep them in sync.

Update when the change touches any of:
- **What data is collected, stored, or sent somewhere** (new proxy route, new third-party API, new Firestore field, new localStorage of user content) → TOS "Data & Privacy" + docs Privacy.
- **AI behavior** (new provider, prompts leaving the browser, stored conversations) → TOS "AI Features" + docs Terms.
- **Plans, prices, or what a plan includes** → TOS "Plans and Feature Availability" / "Paid Plans & Pricing".
- **A tool that sends traffic to third-party targets** (scanners, fuzzers, testers) → TOS "Prohibited Activities" + docs AUP should name it.
- **A new product or surface** → TOS opening paragraph list of products.
- **A removed capability** → delete its clauses (no stale disclaimers).

**If the change is material, bump `TOS_VERSION` in auth.js** and rewrite the "What changed" list. Everyone who accepted the old version then re-accepts. Wording-only fixes don't need a bump. Keep sections sequentially numbered and cross-references ("Section N") correct. The one sanctioned emoji in the sign-off stays; no others.

## 4. Honesty sweep (no false claims)

Every claim must be true of what ships. Check against the code, not memory:
- Counts (tools, utilities, commands, engines): grep and fix every surface together:
  `grep -rnE "[0-9]{2,4}\+? (security )?(tools|utilities|commands|engines)" public --include=*.js --include=*.html | grep -v vendor`
  How to count (as of 2026-10-29: 140 tools, 780 quick utilities, stated as "140+ tools plus 780 quick utilities"):
  tools = console NAV secs without the `tool-` prefix, minus pages (docs, downloads, dlguide, setup, education, toolbox, beta, api, coder, learn, refs, cheats, snippets, targets), plus Deck NAV_DEF `"tool"` ids not in the console NAV. Quick utilities = console NAV secs with the `tool-` prefix. Nexus modules = files in darknode-cli `lib/nexus/*.js` (88 as of 2026-10-29), the Nexus the site actually installs.
- "Never leaves your machine / never proxied / not stored" claims vs the real data path (`worker/worker.js`, net.js dnFetch, Firestore writes).
- "Coming soon", "priority support", customer or usage claims: only if real.
- No simulated features presented as real; no prefilled inputs; no emojis; no native dialogs; placeholders short with a helper line; example emails `test@darknode.ai`, no real company or person names.
- Site scope is cybersecurity for businesses and individuals; no finance, GRC paperwork or hiring features.

## 5. Plans

- Gating lives in `deck-ui.js` PLAN_GROUP / PLAN_ITEM; tiers in `public/js/core/entitlements.js`.
- Tools above a plan are **hidden**, never badged or upsold.
- Keep three descriptions matching the gating: landing pricing cards, landing FAQ "How do paid plans work?", docs FAQ "Which tools do I get on my plan?".
- Firestore rules must keep `tier` unwritable by users (`firebase/firestore.rules`).

## 6. Install, download and release surfaces

Install commands appear in several places and must agree:
- `public/js/getapp.js` (`PUBLISHED` flags: desktopApp, cliBinaries, npm), `public/js/coder.js` (release URLs), `public/js/docs.js` Getting Started, `public/js/landing.js`, `public/js/api.js` (self-hosted API setup).
- npm is suspended: commands use `git clone` and carry the `NPM_SUSPENDED` marker. To revert: flip `PUBLISHED.npm` and grep `NPM_SUSPENDED`.
- Download links must match the actual GitHub release asset names (build workflows in the darknode-cli / darknode-app repos).
- Nexus / CLI commands: source of truth is darknode-cli `lib/cli/reference.js`; regenerate `command-ref.json` with `node scripts/export-command-ref.js`, then update the web docs.js CMD_GROUPS and the CLI `docs/NEXUS-COMMANDS.md`.
- Find every surface: `grep -rn "git clone https://github.com/Darknode-Official\|NPM_SUSPENDED\|releases/download" public --include=*.js --include=*.html`

## 7. Verify

- `npm test` (all green). Add unit tests for any pure logic; update tests for removals.
- `node --check` every edited JS file.
- Browser check (Playwright): unregister the service worker and clear caches first. Test as a **non-owner Free user** (Test Mode, or a harness with `isOwner:false`), at desktop width and **390px mobile**. The tool opens, does the real thing, and there are no new console errors (Google One Tap localhost errors are pre-existing).
- If hidden by plan: confirm it's absent below the tier and present at it (owner Settings, "Preview as plan").
- Remove harness files and screenshots before committing.

## 8. Cache-busters, commit, deploy

- **No manual bumps.** `firebase deploy` runs `scripts/build.mjs` first (predeploy) and uploads `dist/`: every `?v=` specifier gets a hash of the target file plus everything it imports, and `sw.js` gets `CACHE = 'darknode-<build hash>'` and precaches what index.html loads first. The `?v=` values in `public/` are placeholders; leave them as they are.
- A new import of a cache-busted module needs some `?v=` (any value, e.g. `?v=1`) so the build versions it. Modules that build paths at runtime declare `const V = "?v=..."`; the build gives it the build hash.
- **Never** add `?v=` to singleton modules: security-graph.js, context-bar.js, core/bus.js.
- Check locally with `node scripts/build.mjs` (writes `dist/`, fails on a `?v=` specifier pointing at a missing file) and serve `dist/` to test the release build.
- Commit on a feature branch; no Claude or co-author trailer; no backticks inside `git commit -m "..."`. Push only to `origin`, never `def`.
- **Ask before merging to main and before deploying.** Deploy: `npx firebase deploy --only hosting` (both sites). The `chat` function warning is harmless. Worker changes need a separate `cd worker && npx wrangler deploy --env=""` (production; try `--env staging` first, which publishes darknode-proxy-staging); Firestore rules changes need `scripts/set-admin.mjs` run first.
- Before production, check the release build on a preview channel: open a PR (the Preview workflow comments the URL once the FIREBASE_SERVICE_ACCOUNT secret is set) or run `npx firebase hosting:channel:deploy <name> --only sentinel-b4194 --expires 7d`.
- After deploy, compare `/build.json` on both sites with the build hash `scripts/build.mjs` printed, and curl a changed file.

## 9. Report

Tell the user what changed on each surface (registry, docs, legal, install, plans), what was verified and how, anything skipped and why, and whether a TOS re-acceptance was triggered.
