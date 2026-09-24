# Darknode — Expansion Plan

> Toward a materially larger, genuinely functional platform. This is a
> feature-driven engineering plan, **not** a line-count quota. Every line added
> must be real, tested, non-duplicated source that makes the product do more or
> do it better. We divide the work by **systems**, not by arbitrary line targets.

Last updated: 2026-09-24

---

## 0. Ground rules (non-negotiable)

1. **No filler, no metric-gaming.** No generated dashboards nobody uses, no
   copy-pasted variants, no dead code padding a counter. If reaching a round
   number would require filler, we stop short and say so.
2. **Keep the product working.** No clean-room rewrite. Every change ships behind
   the existing, functioning SPA. Migrations are incremental and reversible.
3. **Measure honestly.** `npm run loc` (`scripts/loc.sh`) is the ruler. It counts
   project-owned source only — excludes `node_modules`, vendored/minified libs,
   build output, source maps, and lockfiles — and reports by category so growth
   is legible and cannot be gamed by dumping vendor code.
4. **Test what we build.** New systems ship with `test/` coverage. `npm test`
   must stay green.
5. **Platform constraints stand:** no emojis in UI (text labels); no native
   `prompt/alert/confirm` (use `window.dnModal/dnConfirm/dnPrompt` + aiModal); no
   network calls in tool features (in-memory data only); full-width but never
   touching pixel edges; bump `?v=` cache-busters on changed imported JS/CSS and
   `sw.js` `CACHE` when `sw.js` changes; never fabricate metrics/data; never
   implement AI jailbreak/safety-flag stripping.

---

## 1. Baseline (measured, not estimated)

At the start of this program (`scripts/loc.sh`):

| Category            | Lines (approx) |
|---------------------|----------------|
| App JS (public/js)  | ~166,400       |
| Reference data      | ~193,500       |
| CSS                 | ~24,100        |
| HTML                | ~690           |
| JSON/schema         | ~8,150         |
| Backend (functions) | ~67            |
| Firebase config     | ~168           |
| Docs                | ~1,390         |
| **TOTAL**           | **~394,800**   |

The honest read: a large, real, feature-rich codebase whose single biggest
segment is reference data (threat catalogs, technique libraries, etc.). Reaching
a materially higher, *meaningful* total is a multi-session engineering program of
building real subsystems — not a single pass.

---

## 2. Audit findings (what to fix / what to build on)

From the architecture audit of the actual source (not old docs):

- **No shared spine.** ~65+ hand-rolled `localStorage` keys with three competing
  prefix conventions; every module re-implements `try { JSON.parse } catch`.
  There is no event bus, no typed store, no route registry, no normalized
  tool-result shape. → **Phase 1 builds this spine.**
- **Routing is a 156-branch `if/else`** in `auth.js#show()`. Invisible to the
  sidebar, search, breadcrumbs, and the AI. → registry (built) → incremental
  adoption.
- **Entity model exists but is unvalidated.** `security-graph.js` has 25
  `ENTITY_TYPES` and a relationship graph, but nothing describes or validates the
  per-type `data` payload. → `core/entities.js` (built).
- **`investigation.js` relationship bug** (~L434–441): writes a phantom
  `dn_sg_relationships` key with wrong field names (`sourceId/targetId` vs the
  graph's `fromId/toId`). → fix in Phase 1 during graph migration.
- **Backend is orphaned.** A single `chat` HTTP function (AI proxy) exists in
  `functions/index.js` but is not wired in `firebase.json`. Client-side AI keys
  are exposed. → **Phase 0 security hardening** (key rotation is the owner's
  action; wiring + auth is ours).
- **Native dialogs still linger** in several modules (admin, case-manager,
  graph-bridge, investigation, cve-search). → migrate opportunistically.

---

## 3. Phases

Each phase lists concrete deliverables. A phase is "done" when its code is
merged, tested (`npm test` green), and — for UI — verified in-browser.

### Phase 0 — Security hardening *(flagged; does not break the working AI path)*
- [ ] Owner: rotate exposed provider keys in their dashboards.
- [ ] Move secrets to Firebase Secrets; wire + authenticate the `chat` function
      proxy in `firebase.json`.
- [ ] Route client AI through the proxy (behind a flag; keep the working path
      until the proxy is verified).

### Phase 1 — Core spine *(in progress)*
- [x] `core/bus.js` — typed event bus (sticky replay, handler isolation). **+tests**
- [x] `core/store.js` — namespaced, versioned KV store with migrations. **+tests**
- [x] `core/entities.js` — entity schemas + validation + relationship rules. **+tests**
- [x] `core/result.js` — normalized ToolResult. **+tests**
- [x] `core/registry.js` — data-driven route/tool registry. **+tests**
- [x] Test harness + runner + honest LOC accounting.
- [ ] `core/context.js` — active-context model (case/investigation) on the bus.
- [ ] Migrate `security-graph.js` persistence onto `store`; fix the
      `investigation.js` relationship bug against the real graph API.
- [ ] Seed the registry from a real route manifest; let the sidebar + a global
      search read from it (dispatch stays as-is until parity is proven).

### Phase 2 — Tool platform lifecycle
- [ ] A tool base/contract (`describe`, `run → ToolResult`, `render`), a results
      feed that consumes `ToolResult`, run history in `store`, and export.
- [ ] Migrate a first cohort of tools onto the contract; wire their results to
      the graph via validated entities.

### Phase 3 — Domain subsystems (the bulk of meaningful growth)
- [ ] Deepen real analytical subsystems (detection engineering, IR case
      management, threat-intel correlation, asset/vuln management) with genuine
      logic, data models, and tests — not UI shells.

### Phase 4 — AI structured context + function-calling
- [ ] Replace the coarse context string with a structured builder that reads the
      registry, active context, and recent `ToolResult`s; expose safe,
      read-only "functions" the AI can call to query in-app state.

### Phase 5 — Cross-cutting
- [ ] Global search, performance passes, accessibility, observability/config,
      admin, fixtures, docs, and broadened test coverage.

---

## 4. Honesty checkpoint

If genuine, useful systems level off well before any round number, that is the
correct place to stop — and this document will say so plainly rather than
manufacture the difference. Growth is reported per commit via `npm run loc`.
