# Secret Exposure & Backend Leak Scanner — master plan

**Status:** PLAN ONLY (not built). 2026-10-13.
**Working name:** LEAKPROBE (route `leakprobe`).
**One line:** Point it at a web property you own; it proves whether a real secret
(your Gemini API key, any token) is reachable from the browser, and whether the
backend that holds it leaks it through responses, errors, CORS or debug routes.

This exists because of a concrete need: confirm the Darknode Gemini key is
**server-side only in the Cloudflare worker** and never shipped to, echoed to, or
reachable from the client. It generalises to any site/key the owner controls.

---

## 1. Goals and non-goals

**Goals**
1. **Client-exposure proof.** Given a site, fetch everything a browser would load
   (HTML, every `<script>`, inline scripts, imported ES modules, source maps,
   JSON/config, service worker, wasm text) and detect secrets in them — so you can
   answer "is my Gemini key in the bundle?" with evidence (file + line + match).
2. **Backend-leak proof.** Observe the real requests the app makes to its backend
   (the Cloudflare worker, `/api/*`) and inspect **request and response** headers,
   bodies and error pages for secrets, env dumps and stack traces. Answer "does the
   backend ever hand the key back?"
3. **Key-placement verdict.** For a specific secret the owner pastes (e.g. the
   Gemini key), classify **where** it lives: client bundle (critical), network
   traffic from the client (critical), backend response (critical), or *nowhere
   client-reachable* (good — "safe in Cloudflare").
4. **Backend hygiene checks.** Probe the backend for the common ways a key escapes:
   verbose errors, debug/health/env routes, permissive CORS that lets any origin
   read authed responses, cache headers that store secret responses, and reflected
   input.
5. **Actionable report.** Executive verdict + evidence + exact remediation + export.

**Non-goals / hard limits (honesty + safety)**
- **Authorized targets only.** It scans properties the user owns/controls. A typed
  consent gate ("I own or am authorized to test this") is required before any
  active probe, mirroring the site's AUP. No mass/third-party scanning.
- **Never exfiltrate.** Matches are masked in the UI by default; the full secret is
  shown only on an explicit per-row reveal and never leaves the browser/worker.
- **Never validate a key by spending it.** The tool must not call the provider's
  paid API with a found key to "prove" it works. Liveness is inferred from
  *placement*, not from charging the owner's account. (Optional, off-by-default,
  owner-only: a provider's dedicated *key-info* endpoint where one exists and is
  free — see §6; default is placement-only.)
- **Not a guarantee.** "No exposure found" means the detectors (patterns + entropy
  + the owner's own secret strings) found nothing in what was fetched — not a proof
  of absolute safety. Said plainly in the UI.

---

## 2. Threat model — how a key like the Gemini one leaks

The scanner is organised around the real escape paths, and tests each:

| # | Escape path | What the scanner does |
|---|---|---|
| 1 | Hard-coded in client JS/HTML | Fetch + scan every client asset (see §4) |
| 2 | Left in a **source map** (`.map`) that ships to prod | Discover `//# sourceMappingURL`, fetch the map, scan `sourcesContent` |
| 3 | Baked into the **service worker** or a precache manifest | Fetch `sw.js` + any `?v=`/manifest it references, scan |
| 4 | Sent **from the browser** to a third party (key in a request the client makes) | Dynamic capture of outbound requests (§5); flag any request whose headers/query/body carry a secret |
| 5 | **Echoed by the backend** in a response body | Capture `/api/*` responses; scan bodies |
| 6 | Leaked in a **backend error / stack trace** | Send malformed/oversized/odd requests; scan error output for secrets, file paths, env |
| 7 | Exposed by a **debug/health/env route** | Probe a wordlist of common routes (`/debug`, `/env`, `/.env`, `/config`, `/status?verbose`, `/__env`, `/cdn-cgi/...`) |
| 8 | Readable cross-origin via **permissive CORS** | Check `Access-Control-Allow-Origin: *` combined with credentialed/authed responses |
| 9 | Stored in a **shared cache/CDN** | Check `Cache-Control`/`Age`/`CF-Cache-Status` on authed or secret-bearing responses |
| 10 | Reflected input (key pasted into a URL echoed back) | Reflection check on probe inputs |
| 11 | In **git/CI artifacts** served by the site | Probe `/.git/config`, `/.git/HEAD`, sourcemaps, `/package.json`, `/.env*` |

For the Darknode/Cloudflare case specifically, the "pass" state is: the Gemini key
appears in **none** of 1–5, 9; the worker's `/api/chat` and `/api/smart` responses
and error paths (6) never contain it; there is **no** debug/env route (7); and CORS
(8) does not let an arbitrary origin read authed worker responses.

---

## 3. Architecture

Everything runs **client-side in the browser**, using the existing Darknode proxy
(`net.js` → worker `/api/fetch`) for cross-origin fetches, exactly like the other
data-protection tools. No new server component is required for v1.

```
leakprobe.js (UI)
 ├─ crawl orchestrator ............ discovers + fetches assets via dnFetch
 ├─ dynamic capture ............... drives a same-origin probe iframe / fetch log
 ├─ backend prober ................ worker hygiene checks (CORS, errors, routes)
 └─ report renderer

leakprobe-engine.js (PURE, tested)
 ├─ reuse: dlp-engine.scan() ...... all secret/PII detectors already built
 ├─ assetGraph(html) .............. parse out <script src>, modules, sourceMappingURL, sw, links
 ├─ parseSourceMap(json) .......... extract sourcesContent for scanning
 ├─ classifyPlacement(secret, hits) location verdict for a specific owner secret
 ├─ gradeCors(headers, origin) .... CORS exposure verdict
 ├─ gradeErrorLeak(body) .......... secrets/paths/stack in an error response
 ├─ scoreExposure(findings) ....... exec verdict (safe / exposed / critical)
 └─ selfTest()
```

**Reuse (do not rebuild):**
- `dlp-engine.js` — the entire secret/PII detector catalogue + entropy sweep is the
  matching core. LEAKPROBE adds *where it was found* and *the owner's own secret*.
- `net.js` `dnFetch`/`dnFetchJSON` — all cross-origin fetches (CSP already allows the
  worker; the worker fetches server-side so target CORS is irrelevant).
- `phish-engine.registrableDomain` / IOC helpers — scope checks.
- `posture-engine` — fold the header hygiene (CORS/cache) into or beside LEAKPROBE
  rather than duplicating.

---

## 4. Static client-exposure scan (phase A)

1. **Seed**: owner enters a URL (default `https://darknode.ai`). Consent gate first.
2. **Fetch the document** via `dnFetch(url,{raw:true})`.
3. **Build the asset graph** (`assetGraph`):
   - every `<script src>` (same-origin + cross-origin), inline `<script>`,
   - ES module graph: follow `import ... from` one or two hops (bounded),
   - `<link rel=modulepreload/preload/stylesheet>`, `importmap`,
   - `//# sourceMappingURL=` on each script → the `.map`,
   - `sw.js` (+ any precache list / `?v=` asset list it names),
   - `/manifest.json`, `/config*.js`, `/env*.js`, well-known config paths.
4. **Fetch each asset** through the proxy, bounded (max N files, max M bytes each,
   concurrency-limited like the TLS fleet monitor).
5. **Scan each** with `dlp-engine.scan()` **plus** the owner's pasted secret(s)
   as exact-match needles (so a specific Gemini key is caught even if it doesn't
   fit a generic pattern). Record `{assetUrl, line, col, kind, masked}`.
6. **Source maps**: parse `sourcesContent`, scan each original source; a secret in a
   `.map` is a critical finding (the original source with the secret shipped).
7. Gemini-specific: Google API keys match `AIza[0-9A-Za-z\-_]{35}` (already a DLP
   detector), so a leaked Gemini key in any asset is caught automatically; the
   owner's exact key as a needle covers rotated/edge cases.

Output of phase A answers: **"Is my key in anything the browser downloads?"**

---

## 5. Dynamic backend-request capture (phase B)

Goal: see the **actual** requests the app makes and whether any carries/returns a
secret. Two complementary, honest mechanisms (no undisclosed interception):

- **B1 — same-origin probe harness (preferred, darknode.ai itself).** Load the
  target in a controlled same-origin context with `fetch`/`XMLHttpRequest`
  instrumented *before* app code runs (a tiny injected shim that logs method, URL,
  request headers/body, response status/headers/body to an in-page buffer). Only
  possible for the owner's own origin (same-origin policy) — which is exactly the
  Darknode use case. Each captured pair is scanned with `dlp-engine.scan()` + the
  owner needle. Flags: a secret in an **outbound request** (client is sending the
  key — critical) or in a **response body/headers** (backend echoing — critical).
- **B2 — direct endpoint replay (any backend).** Owner lists the backend endpoints
  (e.g. `/api/chat`, `/api/smart`, `/api/fetch`). The tool replays representative
  calls through the proxy and scans responses + headers. Covers backends not loaded
  in a page.

Darknode "pass": `/api/chat` and `/api/smart` responses contain only model output,
never `AIza...`; no request the client makes includes the key (the worker injects
it server-side).

---

## 6. Backend hygiene probes (phase C)

Deterministic, bounded, owner-consented probes against the backend origin:

1. **Error leakage** — send malformed JSON, wrong method, huge body, missing params;
   scan the error response for secrets, absolute file paths, stack frames, framework
   banners, and env fragments (`gradeErrorLeak`).
2. **Debug/env routes** — a *small, safe* wordlist (`/.env`, `/.git/HEAD`,
   `/debug`, `/__env`, `/config.json`, `/status?debug=1`, `/health?verbose=1`,
   `/cdn-cgi/trace`); report any that return 200 with config/secret-shaped content.
3. **CORS** — read `Access-Control-Allow-Origin` / `-Credentials`; flag `*` with
   credentials, or reflection of an arbitrary `Origin`, on any authed/secret route
   (`gradeCors`).
4. **Caching of secrets** — if a secret-bearing or authed response carries a public
   `Cache-Control`/CDN cache hit, flag it (CDN could serve it to others).
5. **Method/verb exposure** — `TRACE`, `OPTIONS` verbosity.
6. **(Optional, off by default, owner-only) provider key-info** — for providers that
   expose a *free, non-charging* key-metadata endpoint, allow the owner to check a
   key's scope/restrictions. **Never** a generate/completion call. For Google AI
   this is deliberately conservative: default is placement-only; document the risk
   that any liveness call may incur usage, and keep it disabled unless the owner
   explicitly opts in per run.

Rate-limited, capped number of requests, long gaps, abortable — never a stress test.

---

## 7. Key-placement verdict (the headline)

For each owner secret (e.g. the Gemini key), combine findings into one verdict:

- **CRITICAL — client-exposed**: found in a client asset (phase A) or an outbound
  client request (B1). Anyone can read it. Rotate now.
- **CRITICAL — backend-leaked**: not in the client, but a backend response/error
  returns it (B/C). Rotate + fix the backend.
- **WARNING — reachable config**: found in a config/debug route or a source map.
- **PASS — server-side only**: appears in *nothing* the scanner could reach from the
  client or from the backend's observable responses → "as far as observable, the key
  is kept server-side (e.g. in the Cloudflare worker's env) and not exposed."

Always with the honest caveat (§1): a PASS is "no exposure observed", not a proof.

---

## 8. UI (`leakprobe.js`, prefix `.lp-`)

- **Consent gate** (typed authorization) before any active probe.
- **Inputs**: target URL; backend origin/endpoints (auto-filled from the site's
  `window.DARKNODE_PROXY_URL` when scanning Darknode); optional owner secrets to
  track (pasted, masked immediately, kept only in memory).
- **Run phases** with live progress (assets fetched, requests captured, probes run).
- **Report**: top verdict card per tracked secret; sections for Client assets,
  Backend traffic, Backend hygiene; evidence rows (asset/endpoint, location, masked
  match, reveal-on-click); remediation per finding; JSON/Markdown export.
- Follows the established data-protection tool look (light cards, blue accent,
  honest banners), no emojis, no native dialogs (`dnModal`/`dnConfirm`/`showToast`).

---

## 9. Safety, ethics, data handling

- Authorized-use gate + AUP link; refuse obvious third-party targets by default.
- Secrets masked by default; reveal is local only; nothing persisted to disk or sent
  anywhere except through the owner's own proxy to the owner's own target.
- No provider spend (§1). No destructive/high-volume probing (§6).
- All fetches through the existing proxy; no new secrets introduced.

---

## 10. Testing

- `leakprobe-engine.js` pure unit tests (`test/security/leakprobe.test.mjs`):
  `assetGraph` extraction (script/module/sourcemap/sw discovery), `parseSourceMap`,
  `classifyPlacement` (each verdict), `gradeCors`, `gradeErrorLeak`, `scoreExposure`,
  plus the owner-needle path through `dlp-engine.scan`.
- Live validation against darknode.ai (the real goal): confirm the Gemini key is in
  no asset and no worker response → PASS; deliberately point at a fixture that *does*
  embed a dummy `AIza...` key → CRITICAL.
- `selfTest()` in-engine, mirrored in the suite, like every other engine.

---

## 11. Rollout

1. Build `leakprobe-engine.js` + tests (pure, reuses dlp-engine).
2. Build `leakprobe.js` UI, phase A (static) first — immediately answers the Gemini
   question for darknode.ai.
3. Add phase C (backend hygiene) — composes with `posture-engine`.
4. Add phase B (dynamic capture) — B2 (replay) first, then B1 (same-origin shim).
5. Register: Deck (Compliance & Trust or Exposure), console-nav (defense),
   auth route + blurb, explainer. Cache-busters + SW bump. Ask before deploy.

**Deliverable for the owner's immediate question:** after phases A + C, LEAKPROBE
scans darknode.ai's bundle + worker and returns, with evidence, whether the Gemini
key is client-reachable or kept server-side in Cloudflare.
```
