# Proposal: Code Protection & Anti-Replication

**Status:** Approved (strategy) — 2026-10-04. Execution scheduled for ship time.
**Owner:** Darknode core
**Scope:** website (`darknode-web`), desktop app (`darknode-app`), Nexus/CLI (`nexus`, `darknode-cli`), OS distro (`darknode-os-distro`).

## Problem

Darknode's source is public on GitHub. Not everyone honors the license; people
clone the work, and increasingly they hand a repo to an AI and ask for a
"modified copy." We want replication to be *expensive and legally exposed*, not
a five-minute fork — without wrecking our own maintainability or performance.

## The one hard truth

**Anything shipped to a client can be read.** Minification and obfuscation raise
the cost of copying; they do not prevent it, and a capable AI can partially
reverse them. Therefore:

1. The only *true* protection is **not shipping the valuable logic** — move it
   server-side behind authenticated APIs. What the client never receives cannot
   be copied.
2. For everything that must ship, **obfuscation + watermarking + legal** turns a
   cheap clone into an expensive, traceable, infringing one.

We also explicitly reject **hand-writing convoluted source**. It rots, breeds
bugs, slows us down, and is *easier* to untangle than tool-generated output.
Source stays clean; the *artifact* gets hardened at build time.

## Threat model (who we're raising the bar against)

| Adversary | Goal | Our lever |
|---|---|---|
| Casual forker | `git clone`, rebrand, redeploy | Server-side crown jewels + obfuscated build (nothing useful in the public static files) |
| AI-assisted cloner | "recreate/modify this repo" | Server-side logic absent from source; obfuscated bundles resist clean extraction |
| Credential/asset lifter | reuse our keys/endpoints | Already addressed: per-user key isolation, origin allow-list + rate limit, auth'd APIs |
| Leaker of a licensed build | redistribute our binary | Per-build invisible **watermark** → trace the source of a leak |

## Strategy — four layers

### Layer 1 — Server-side crown jewels (strongest)
Move only the genuinely proprietary compute behind authenticated endpoints on
`darknode-api`; leave simple/offline tools client-side so they stay instant.

Candidates to relocate (confirm per-tool during execution):
- Flagship tool **engines** (the analysis/scoring logic, not the UI): e.g. the
  hash/JWT/crypto analysis cores, detection and correlation engines, OSINT
  enrichment.
- **AI orchestration**: the server-enforced persona + routing already live in
  `functions/index.js`; consolidate the prompt/strategy there so a client can't
  read or strip it.
- **Scoring / ranking / heuristics** that represent our "secret sauce."

Pattern: client sends inputs → auth'd endpoint runs the engine → returns results.
The client keeps rendering + UX; the IP stays on the server. Keep a graceful
degraded path for offline/no-account use where it makes sense (clearly weaker).

### Layer 2 — Ship-time obfuscation build (web + app)
Introduce a build step. **Source stays readable; the deploy artifact is hardened.**

- **Web (`darknode-web`)** — currently *no* build step. Add one:
  - Bundle the ES-module graph (esbuild — fast, zero-config-ish) into a small
    number of chunks.
  - Obfuscate with `javascript-obfuscator` (control-flow flattening, dead-code
    injection, string array + rotation/encoding, identifier mangling, self-
    defending, debug-protection). Tune to keep runtime overhead acceptable.
  - `firebase deploy` serves `dist/`, **not** `public/js/*` raw source. CI builds;
    raw source is never what's hosted.
  - Keep sourcemaps **private** (for our own error triage), never deployed.
- **Desktop app (`darknode-app`)** — obfuscate the renderer bundle the same way
  via electron-builder's prepackage hook; consider `bytenode` to ship V8
  bytecode for the hottest proprietary modules.

### Layer 3 — Anti-tamper & watermarking
- **Domain/license lock** — already present (`public/js/auth.js:2305`). Harden it:
  move the check behind the obfuscator's self-defending pass so it can't be
  trivially commented out; have it *fail closed* and verify against a signed
  license token, not just `location.hostname`.
- **Integrity checks** — the app verifies its own bundle hash / an SRI manifest
  and refuses to run if modified.
- **Per-build invisible watermark** — stamp each licensed build with an
  identifier encoded in benign-looking constants / string-array ordering, so a
  leaked copy traces back to its source. (Design the encoding so removing it
  requires understanding the obfuscated output — raising cost again.)

### Layer 4 — Legal & hygiene
- Consistent **license header** banner injected at build time into every shipped
  bundle (copyright, license URL, "unauthorized reproduction prohibited").
- Keep the chosen GitHub license explicit and strong; document a DMCA process.
- Resolve the public **tool-count / LOC inconsistencies** (164+ vs 200+ vs 192;
  "592K+" vs measured ~385K) so our own public numbers are credible.

### The OS distro (`darknode-os-distro`)
A Linux distro is mostly packaging of third-party, licensed components — little
to "protect" there and much we're legally bound to keep open. Focus protection
on **our** additions: the preloaded Darknode platform build (ship the obfuscated
web/app build, not source), custom branding/theme assets, and any proprietary
scripts. Don't fight the parts the upstream licenses require to stay open.

## Sequencing (important)

Obfuscation is a **ship-time** concern. We do **not** weave it into source while
tools are still being actively upgraded — that would fight daily development.

1. **Now → Section work:** finish the "make each tool more advanced" batch on
   clean source. In parallel, as each flagship engine is upgraded, build it so the
   engine can live server-side (Layer 1) rather than inline.
2. **Pre-deploy phase:** stand up the build pipeline (Layer 2), wire the
   watermark + hardened license lock (Layer 3), add the license banner (Layer 4).
3. **Deploy:** first production deploy serves the hardened build. (Held until the
   user approves a deploy — see the no-auto-deploy rule.)

## Explicit non-goals
- Not claiming the client becomes "uncopyable." We're raising cost + adding
  traceability + legal exposure.
- Not obfuscating by hand. Not degrading perf/UX beyond a tuned budget.
- Not breaking offline/no-account use of the lightweight tools.

## Risks & mitigations
- **Obfuscation breaks runtime** → gate the build behind the existing test suite
  (688 tests) running against the *built* artifact in CI, not just source.
- **Debuggability loss** → keep private sourcemaps; keep a `dev` build that is
  unobfuscated for local work.
- **Server latency/cost for Layer 1** → only crown jewels move; cache
  deterministic results; keep the client responsive with optimistic UI.
