# Darknode Connect — Account-Linking Provider Integration Plan

**Status:** Research + design proposal (not yet implemented)
**Date:** 2026-10-10
**Scope:** Let a Darknode user *connect* an external provider (AI model services and
cybersecurity platforms) by **linking their account** — the "Connect your account"
pattern, like Claude connecting to Figma — rather than pasting an API key.

> **TL;DR up front.** True "connect your account, no key" linking is only available
> for a *subset* of providers, and it comes in two flavours: **(a)** classic OAuth 2.0
> account-linking (GitHub, Hugging Face, Google, and — via a PKCE variant that still
> ends in an API key — OpenRouter), and **(b)** MCP remote servers that use OAuth 2.1
> + PKCE under the hood (how Claude ⇄ Figma actually works). The big consumer chat
> subscriptions (ChatGPT Plus, Claude Pro/Max, the Gemini app) **cannot** be driven by
> a third-party website through any official path — Anthropic explicitly bans it and
> OpenAI/Google give no consumer-subscription API. Most security platforms
> (VirusTotal, Shodan, Censys, GreyNoise, etc.) are **API-key-only** with no OAuth.

---

## 1. How Claude ⇄ Figma actually connects

### 1.1 It is MCP, not a bespoke integration

Claude connects to Figma through the **Model Context Protocol (MCP)**. Figma runs a
**remote MCP server** at `https://mcp.figma.com/mcp` (HTTP/streamable transport). Claude
(Claude Code, Claude Desktop, and claude.ai "Connectors" / "Custom integrations") acts
as an **MCP client**. In Claude Code the connection is added with:

```
claude mcp add --transport http figma https://mcp.figma.com/mcp
```

then authorized by running `/mcp`, selecting **figma → Authenticate**, and clicking
**Allow Access** in the browser. No Figma personal access token (PAT) is pasted and no
Figma desktop app is required — the hosted endpoint is reached directly over the
internet and the handshake is an OAuth browser flow. (Figma restricts which clients may
connect to clients listed in its MCP Catalog.)

The hosted remote server is distinct from Figma's **local/desktop** MCP server at
`http://127.0.0.1:3845/mcp`, which needs no PAT but requires a Dev/Full seat and the
desktop app running.

### 1.2 What the Figma MCP server exposes (tools)

The MCP server exposes **tools** (callable functions) and resources rather than a REST
surface. The official Figma server's tool set includes, among others:

- `get_design_context`, `get_screenshot`, `get_metadata`, `get_variable_defs` — read a
  design/node into structured context (design-to-code).
- `get_code_connect_map` / `add_code_connect_map` — bridge design components to code.
- `create_new_file`, `use_figma`, `generate_figma_design`, `upload_assets` — write
  designs into Figma (code-to-design).
- `get_figjam` / `generate_diagram` — FigJam content.

The client discovers these at runtime via the MCP `tools/list` call after the transport
is authorized.

### 1.3 The exact OAuth 2.1 flow MCP uses

The MCP **Authorization** spec (draft) layers a *selected subset* of OAuth 2.1 on top of
the HTTP transport. Authorization is OPTIONAL for MCP generally, but HTTP transports
SHOULD conform. Roles map directly to OAuth 2.1:

- **MCP server** = OAuth 2.1 **resource server** (e.g. `mcp.figma.com`).
- **MCP client** = OAuth 2.1 **client** (Claude).
- **Authorization server** = issues tokens (may be co-hosted or separate; Figma's own
  identity provider).

The complete flow (from the spec's sequence diagram):

1. **Unauthenticated probe.** Client sends an MCP request with no token. Server replies
   `401 Unauthorized` with a `WWW-Authenticate: Bearer resource_metadata="…", scope="…"`
   header.
2. **Protected Resource Metadata (RFC 9728).** Client fetches
   `https://<server>/.well-known/oauth-protected-resource`. This is **MUST** on both
   sides. It names the authorization server(s).
3. **Authorization Server Metadata.** Client fetches the AS metadata via **RFC 8414**
   (`/.well-known/oauth-authorization-server`) *or* OpenID Connect Discovery
   (`/.well-known/openid-configuration`). Clients MUST support both.
4. **Client registration** — one of three, in priority order:
   - **Client ID Metadata Documents (CIMD)** — client uses an HTTPS URL as its
     `client_id`; the AS fetches metadata from that URL. This is the new **SHOULD** and
     the preferred mechanism.
   - **Pre-registration** — a `client_id` agreed out of band.
   - **Dynamic Client Registration (RFC 7591, DCR)** — `POST /register`. Now **MAY** /
     deprecated, retained for backwards compatibility. (Many existing remote MCP servers
     still rely on DCR today.)
5. **PKCE authorization request.** Client generates PKCE parameters (`code_verifier` +
   `code_challenge`, `S256`), records the expected `issuer` + `state`, includes the
   **`resource` parameter** (RFC 8707, the canonical MCP server URI, **MUST**), applies
   the scope-selection strategy (least privilege; use scopes from the `WWW-Authenticate`
   challenge), and opens the browser to the AS authorization URL.
6. **User authorizes** in the browser; AS redirects to the client callback with
   `code` + `iss`.
7. **Issuer validation (RFC 9207).** Client validates the returned `iss` against the
   recorded issuer before using the code (mix-up-attack defence).
8. **Token exchange.** Client `POST`s the `code` + `code_verifier` + `resource` to the
   token endpoint; receives an **access token** and optionally a **refresh token**.
9. **Authenticated MCP calls.** Every subsequent HTTP request carries
   `Authorization: Bearer <access-token>`. Tokens MUST NOT go in the query string. The
   server validates the token's **audience** is itself (RFC 8707) — tokens for other
   resources MUST be rejected.

**Scopes.** Servers advertise required scopes in the `WWW-Authenticate` challenge and in
`scopes_supported`. Clients request least privilege; on a `403 insufficient_scope` they
perform a **step-up** flow, re-authorizing with the *union* of old and newly-required
scopes.

**Refresh.** Clients wanting refresh tokens SHOULD include `refresh_token` in
`grant_types` and MAY add `offline_access` to scope when the AS supports it; refresh
tokens MUST be kept confidential; the AS retains discretion to issue them or not.

> This is the literal answer to "connect like Claude ⇄ Figma": **be an MCP client that
> speaks OAuth 2.1 + PKCE + RFC 9728/8414 discovery against a remote MCP server the user
> authorizes in their browser.**

---

## 2. OAuth account-linking in general ("Connect your account")

The classic pattern (what GitHub/Hugging Face/Google expose, and what MCP specializes)
is **OAuth 2.0 Authorization Code flow with PKCE**:

1. User clicks **Connect <provider>** in Darknode.
2. Darknode (server-side broker) generates `state` (CSRF/correlation) and PKCE
   `code_verifier`/`code_challenge`, stores them keyed to the Darknode user + a short TTL,
   and redirects the browser to the provider's **authorization endpoint** with
   `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`,
   `code_challenge`, `code_challenge_method=S256`.
3. User logs in to the **provider** and consents to the requested **scopes**.
4. Provider redirects back to Darknode's **registered redirect URI** with `code` + the
   same `state`.
5. Broker verifies `state`, then exchanges `code` (+ `code_verifier` + `client_secret`
   for confidential clients) at the provider's **token endpoint** for an **access token**
   and **refresh token**.
6. Broker **encrypts and stores** the tokens server-side, associated with the Darknode
   user. The browser never sees them.
7. On expiry, broker uses the **refresh token** to mint a new access token.
8. **Disconnect** = delete stored tokens and (where supported) call the provider's
   **revocation endpoint** (RFC 7009).

**What a website needs server-side to do this safely:**

- A confidential **backend** to hold `client_secret` and do the token exchange (a static
  SPA alone cannot — secrets would leak to the browser). ✓ Darknode has the Cloudflare
  Worker.
- **Redirect-URI allowlist** registered with each provider (exact match).
- **`state`** (opaque, single-use, bound to the session) and **PKCE** for CSRF /
  code-interception defence.
- **Encrypted token storage at rest**, per user, with refresh + revocation.
- **Scope minimization** — request only what each feature needs.

---

## 3. Reality check per provider

### 3.1 AI model providers

| Provider | Account-link without API key? | Mechanism | Blunt verdict |
|---|---|---|---|
| **Anthropic / Claude** | **No** | — | Anthropic's Claude Code legal/compliance page states OAuth sign-in is for Claude Code and Anthropic's own apps only, and that products/3rd-party tools **must use API-key auth** via the Console. Anthropic **does not permit** third-party apps to offer Claude.ai login or to route requests through Free/Pro/Max credentials, and **does not register client IDs** for third parties. Enforced server-side (the "OpenClaw ban", Jan 2026). → **API key only.** |
| **OpenAI / ChatGPT** | **No** | — | No consumer-subscription API; a ChatGPT Plus/Pro account cannot be driven by a third-party site. The Platform API uses **API keys** (project keys). → **API key only.** |
| **Google / Gemini** | **Partial** | OAuth to the *developer* API, not the consumer app | Google's docs: the easiest auth is an **API key** (AI Studio); **OAuth 2.0** exists for the Generative Language API for stricter access control, but it authorizes the *developer/Cloud* API, **not** the consumer Gemini app subscription. → **OAuth possible for the dev API; consumer Gemini app: no.** |
| **Perplexity** | **No** | — | API-key-only (`pplx-…` keys). Consumer Perplexity Pro is not exposed. → **API key only.** |
| **Mistral** | **No** | — | API-key-only (La Plateforme keys). Darknode already proxies Mistral with a server key. → **API key only.** |
| **xAI (Grok)** | **No** | — | API-key-only. → **API key only.** |
| **DeepSeek** | **No** | — | API-key-only. → **API key only.** |
| **Cohere** | **No** | — | API-key-only. → **API key only.** |
| **Together AI** | **No** | — | API-key-only. → **API key only.** |
| **OpenRouter** | **Yes (PKCE)** ✅ | **OAuth PKCE** that mints a user-owned key | Genuinely supports "connect your account": sends the user to `openrouter.ai/auth`, returns a **user-controlled API key** scoped to *their* OpenRouter credits/subscription. See §3.3. → **Account-link via PKCE.** |
| **Hugging Face** | **Yes** ✅ | **OAuth 2.0 / OIDC** ("Sign in with Hugging Face") | Standard OAuth; scopes include `openid`, `profile`, `email`, `read-repos`, `read-billing`, `read-memberships`, `gated-repos`, `write-discussions`, with `orgIds` for org access. Acts on the user's HF account. → **Account-link via OAuth.** |
| **GitHub** | **Yes** ✅ | **OAuth App / GitHub App** (Authorization Code, PKCE supported) | The canonical account-link. OAuth App or GitHub App, Authorization Code flow, fine-grained scopes, refresh tokens (GitHub Apps / opt-in). → **Account-link via OAuth.** |

> **The hard truth for the marquee chatbots:** ChatGPT Plus and Claude Pro/Max are
> consumer *chat* subscriptions. There is **no official API** that lets a third-party
> website spend those subscriptions on the user's behalf, and Anthropic actively blocks
> it. Any "connect your ChatGPT/Claude subscription" feature would require scraping or
> unofficial token reuse — against ToS, breakable at any time, and a security/legal
> liability. **Do not build it.** The honest offering is: connect **OpenRouter** (one
> account → many models incl. GPT/Claude/Gemini via OpenRouter credits), or paste an API
> key for the direct providers.

### 3.2 Security / threat-intel platforms

| Platform | OAuth account-link? | Auth model | Verdict |
|---|---|---|---|
| **VirusTotal** | No | `x-apikey` header (personal key from account menu); v3 API | **API key only.** Free capped ~500/day; ToS restricts business workflows. |
| **Shodan** | No | Account **API key** (query param / header) | **API key only.** |
| **Censys** | No | HTTP **Basic auth** (API ID + secret) / token | **API key/secret only.** |
| **GreyNoise** | No | **API key** header | **API key only.** |
| **AbuseIPDB** | No | **API key** (`Key` header), v2 API | **API key only.** |
| **urlscan.io** | No | **API key** (`API-Key` header) | **API key only.** |
| **SecurityTrails** | No | **API key** (`APIKEY` header) | **API key only.** |
| **IPinfo** | No | **Access token** (Bearer / `?token=`) | **Token only.** |
| **Pulsedive** | No | **API key** (`key` param) | **API key only.** |
| **Hybrid Analysis** | No | **API key** (`api-key` header) | **API key only.** |

> **None** of the target security platforms offer OAuth account-linking as of this
> research. They are all static API key / token. So for these, "connect your account"
> reduces to **securely storing a key the user pastes once** (encrypted, server-side) —
> which is still a UX win over re-pasting, but it is *not* account-OAuth. Be honest in
> the UI: label these "Add API key" / "Store key", not "Connect account".

---

## 3.3 OpenRouter OAuth PKCE — exact flow (the AI MVP)

OpenRouter is the one AI provider with a real browser account-link, so it anchors the
MVP. The flow mints a **user-owned OpenRouter API key** (billed to *their* credits), not
a shared Darknode key:

**Step 1 — send user to auth URL:**

```
https://openrouter.ai/auth?callback_url=<DARKNODE_CALLBACK>&code_challenge=<CHALLENGE>&code_challenge_method=S256
```

Optional params: `key_label` (prefill key name, e.g. `Darknode · <user>`),
`workspace_id` / `required_workspace_id` (UUID), `state` (returned unchanged — **use it
for CSRF**). Headless mode: omit `callback_url`, keep `code_challenge` (required then);
the page displays the code for the user to copy.

**Step 2 — exchange code for key:**

```
POST https://openrouter.ai/api/v1/auth/keys
Content-Type: application/json
{ "code": "<CODE>", "code_verifier": "<VERIFIER>", "code_challenge_method": "S256" }
```

Response contains `key` — a **user-controlled API key**. Codes are **single-use** and
expire **10 minutes** after issuance.

**Step 3 — use + store:** store `key` encrypted server-side; call
`https://openrouter.ai/api/v1/chat/completions` with `Authorization: Bearer <key>`.

**Errors:** `400` invalid `code_challenge_method` (mismatch between steps); `403`
invalid code/verifier or expired code; `405` wrong method.

> Note: OpenRouter has no documented param to force a `$0` spend limit via this flow, so
> the minted key can spend the user's credits — surface that clearly at consent.

---

## 4. The plan for Darknode

Darknode = static SPA on Firebase Hosting + a Cloudflare Worker backend
(`worker/worker.js`, "darknode-proxy") already used as the AI proxy, with provider keys
in Worker secrets and an `ALLOWED_ORIGINS` CORS allowlist. We extend the Worker into a
**"Darknode Connect" OAuth broker + MCP client**, keeping all secrets server-side.

### 4.1 Architecture overview

```
Browser (SPA)                 Cloudflare Worker (darknode-proxy)            Provider / MCP server
───────────                   ──────────────────────────────────            ─────────────────────
[Connect <provider>] ───────▶ GET  /connect/:provider/start
                               │  mint state+PKCE, store in KV (TTL)
                               │  302 ─────────────────────────────────────▶ provider authorize URL
                                                                                (user logs in + consents)
                              GET  /connect/:provider/callback?code&state ◀── 302 redirect
                               │  verify state, exchange code→tokens
                               │  encrypt + store tokens (D1/KV) per user
                               │  302 back to SPA  ────────────────────────▶ SPA shows "Connected"
[use a tool] ───────────────▶ POST /connect/:provider/call  (or /api/chat)
                               │  load+decrypt token, refresh if needed
                               │  proxy request ──────────────────────────▶ provider REST / MCP server
[Disconnect] ───────────────▶ POST /connect/:provider/revoke
                               │  revoke at provider + delete stored tokens
```

### 4.2 Broker endpoints (new Worker routes)

All under the Worker, authenticated as a **Darknode user** (Firebase ID token in
`Authorization` header, verified by the Worker — reuse the existing auth/admin check
pattern):

- **`GET /connect/:provider/start`**
  - Verify the Darknode user (Firebase ID token).
  - Generate `state` (random, bound to user+provider, single-use) and, where needed,
    PKCE `code_verifier`/`code_challenge` (S256).
  - Persist `{state → {user_id, provider, code_verifier, created_at}}` in **KV** with a
    short TTL (e.g. 10 min).
  - `302` to the provider's authorization URL with the allow-listed `redirect_uri`,
    minimal `scope`, `state`, `code_challenge`.

- **`GET /connect/:provider/callback`**
  - Read `code`, `state` (+ `iss` where provided). Look up and **delete** the stored
    `state` (single-use); reject on mismatch/expiry.
  - Validate `iss` against expected issuer (RFC 9207) for MCP/OIDC providers.
  - `POST` to the token endpoint: `code` + `code_verifier` (+ `client_secret` from Worker
    env for confidential clients) → access/refresh tokens (or, for OpenRouter, the minted
    `key`).
  - **Encrypt** tokens (§4.5) and store in **D1** keyed by `(user_id, provider)`.
  - `302` back to the SPA connect page with a success flag (no token in the URL).

- **`POST /connect/:provider/call`** (proxy)
  - Load + decrypt the token for `(user, provider)`; refresh if expired.
  - For REST providers (OpenRouter chat, HF, GitHub, security APIs) forward the request
    server-side and stream/return the response (reuse existing SSE plumbing for chat).
  - Never return the token to the browser.

- **`GET /connect/status`** — list which providers the current user has connected (+ scopes,
  expiry), for rendering the UI. Returns metadata only, never tokens.

- **`POST /connect/:provider/revoke`** — call the provider revocation endpoint (RFC 7009)
  where supported; delete the stored tokens; return new status.

### 4.3 MCP-client support (connect "like Claude ⇄ Figma", literally)

For providers/tools exposed as **remote MCP servers**, the Worker becomes an **MCP
client**:

- **`POST /connect/mcp/add`** — user supplies (or picks from a Darknode catalog) a remote
  MCP server URL. Worker probes it (unauthenticated MCP request → expects `401` +
  `WWW-Authenticate`), fetches **Protected Resource Metadata** (RFC 9728), then **AS
  metadata** (RFC 8414 / OIDC discovery).
- **Client registration** — prefer **CIMD** (host a client-metadata JSON at a stable
  Darknode HTTPS URL used as `client_id`); fall back to **DCR** (`POST /register`) for
  servers that still require it; else a pre-registered `client_id` in Worker env.
- **OAuth 2.1 + PKCE** via the same `/connect/.../start` + `/callback` broker, additionally
  sending the **`resource`** parameter (canonical MCP server URI, RFC 8707) and validating
  token **audience**.
- **`POST /connect/mcp/:id/call`** — the Worker proxies MCP JSON-RPC (`tools/list`,
  `tools/call`, etc.) to the remote server with `Authorization: Bearer <token>`, refreshing
  tokens as needed, and returns tool results to the SPA. Darknode's AI (webai.js / the
  darknode persona) can then be given these tools as callable functions — turning a
  connected MCP server into live capabilities inside Darknode, exactly the Claude ⇄ Figma
  model.

This path is what makes Darknode able to say "connect your account like Claude connects to
Figma" and have it be *true* for any provider that ships a remote MCP server.

### 4.4 Per-provider capability matrix → Darknode behavior

| Provider | account-OAuth? | MCP? | API-key-only? | Darknode behavior |
|---|:--:|:--:|:--:|---|
| OpenRouter | ✅ (PKCE→key) | — | — | **Connect account** → minted user key → use across many models (GPT/Claude/Gemini via their credits). **MVP.** |
| Hugging Face | ✅ | — | — | **Connect account** → OIDC token → Inference/repos on user's HF account. **MVP.** |
| GitHub | ✅ | (GitHub ships an MCP server too) | — | **Connect account** → repo/code tools, and/or GitHub MCP. **MVP.** |
| Google / Gemini | ✅ (dev API only) | — | — | **Connect Google (dev API)** → OAuth for Generative Language API. Consumer Gemini app: **not available.** |
| Anthropic / Claude | ❌ | (Anthropic runs Claude *Connectors* as MCP client, not server for others) | key | **Add API key** only; consumer sub **not connectable** — say so. |
| OpenAI / ChatGPT | ❌ | — | key | **Add API key** only; ChatGPT sub **not connectable** — say so. |
| Perplexity / Mistral / xAI / DeepSeek / Cohere / Together | ❌ | — | key | **Add API key** (stored encrypted). |
| Any remote **MCP server** (Figma-style, incl. 3rd-party security MCPs) | ✅ (OAuth 2.1+PKCE) | ✅ | — | **Connect account** via MCP client (§4.3). |
| VirusTotal / Shodan / Censys / GreyNoise / AbuseIPDB / urlscan / SecurityTrails / IPinfo / Pulsedive / Hybrid Analysis | ❌ | — | key | **Add API key / token** (stored encrypted); label "Add key", *not* "Connect account". |

### 4.5 Security requirements

- **Secrets stay in the Worker.** `client_secret`s and any shared keys live in Worker
  **env/secrets** (`wrangler secret put …`), never in SPA bundles or client JS. The
  browser only ever sees "connected / not connected" status.
- **Token encryption at rest.** Encrypt stored tokens with AES-GCM using a key from Worker
  env (WebCrypto `crypto.subtle`); store ciphertext + IV in **D1** (relational, per-user
  rows) — KV only for short-lived `state`/PKCE. Never store plaintext tokens.
- **CSRF / state.** `state` is random, single-use, bound to `(user, provider)`, TTL ≤10 min,
  deleted on callback. PKCE (S256) everywhere it is supported (mandatory for OpenRouter and
  all MCP flows).
- **Issuer + audience validation.** Validate `iss` (RFC 9207) on MCP/OIDC callbacks;
  validate token **audience** = the intended resource (RFC 8707) before use.
- **Redirect-URI allowlist.** Register exact Darknode callback URIs with each provider; the
  Worker only accepts its own registered callbacks. Reject open redirects.
- **Origin allowlist.** Keep/extend the existing `ALLOWED_ORIGINS` CORS gate so only
  Darknode origins can invoke the broker from a browser.
- **Scope minimization.** Request the least scope per feature; use step-up for more.
- **Revocation + expiry.** Support disconnect (revoke + delete), and auto-refresh with
  backoff; surface expiry in status.
- **Per-user isolation.** Rows keyed to the Firebase UID; one user can never read another's
  tokens; admin/owner custom-claim gating consistent with existing rules.
- **Spend transparency.** For OpenRouter (user-billed key) and any paid provider, show at
  consent that calls spend the user's credits.

### 4.6 Data model (D1 sketch)

```sql
CREATE TABLE connections (
  user_id      TEXT NOT NULL,        -- Firebase UID
  provider     TEXT NOT NULL,        -- 'openrouter' | 'huggingface' | 'github' | 'mcp:<id>' ...
  kind         TEXT NOT NULL,        -- 'oauth' | 'oauth_pkce' | 'mcp' | 'apikey'
  enc_access   BLOB,                 -- AES-GCM ciphertext
  enc_refresh  BLOB,
  iv           BLOB,
  scopes       TEXT,
  resource     TEXT,                 -- MCP canonical URI (RFC 8707)
  issuer       TEXT,
  expires_at   INTEGER,
  created_at   INTEGER,
  updated_at   INTEGER,
  PRIMARY KEY (user_id, provider)
);
-- short-lived PKCE/state lives in KV with TTL, not here.
```

### 4.7 Phased build order

- **Phase 0 — groundwork.** Add D1 + KV bindings to `wrangler.toml`; AES-GCM helpers;
  Firebase-ID-token verification in the Worker; `connections` schema; `/connect/status`.
- **Phase 1 — MVP (genuinely doable account-links):**
  1. **OpenRouter OAuth PKCE** (§3.3) — biggest payoff: one connect → many models on the
     user's own credits. Reuses the existing `openrouter` chat path, swapping the shared
     `OPENROUTER_KEY` for the user's minted key.
  2. **Hugging Face OAuth/OIDC** — "Sign in with Hugging Face", `openid profile` + read
     scopes.
  3. **GitHub OAuth** — repo/code tooling.
  - Ship the SPA "Connections" page (connect / status / disconnect), no native dialogs
    (use `dnModal`/`dnConfirm`), no emojis, honest labels.
- **Phase 2 — API-key vault (honest non-OAuth):** encrypted "Add key" storage for the
  direct AI providers (Mistral, Perplexity, xAI, DeepSeek, Cohere, Together) and the
  security platforms (VirusTotal, Shodan, Censys, GreyNoise, AbuseIPDB, urlscan,
  SecurityTrails, IPinfo, Pulsedive, Hybrid Analysis). Same encrypted store, labeled "Add
  API key", not "Connect account".
- **Phase 3 — MCP client / connectors (the real "like Claude ⇄ Figma"):** implement the
  MCP client broker (§4.3) with RFC 9728/8414 discovery, CIMD-first registration, PKCE +
  `resource`, and a tool-proxy that feeds connected MCP tools into Darknode AI. Seed a
  curated MCP catalog (start with Figma + GitHub's MCP servers to prove it, then security
  MCP servers as they appear).
- **Phase 4 — Google/Gemini dev-API OAuth** (optional) — only the Generative Language API,
  clearly separated from the (impossible) consumer Gemini app.

### 4.8 Honestly impossible / out of scope (do not build)

- **ChatGPT Plus/Pro** subscription driven by Darknode — no official API; would require ToS
  violation.
- **Claude Pro/Max** subscription driven by Darknode — **explicitly banned** by Anthropic
  and enforced server-side; API key via Console is the only compliant path.
- **Consumer Gemini app** subscription — no API; only the developer Generative Language API
  is reachable.
- **OAuth for the security platforms** — none offer it today; API keys only.

---

## Sources

- MCP Authorization specification (draft): https://modelcontextprotocol.io/specification/draft/basic/authorization
- MCP authorization overview (Authgear): https://www.authgear.com/post/mcp-authentication/
- Remote MCP OAuth 2.1 / DCR / PRM (Medium): https://medium.com/@yagmur.sahin/remote-mcp-in-the-real-world-oauth-2-1-9d149de6e475
- MCP auth spec deep-dive (Descope): https://www.descope.com/blog/post/mcp-auth-spec
- OAuth on MCP implementation guide (Permit.io): https://www.permit.io/blog/oauth-on-mcp
- MCP + DCR (Medium): https://medium.com/@dipakkrdas/mcp-oauth-dcr-dynamic-client-registration-ebeb4dd5a34d
- Figma remote MCP server + Claude Code setup (write-up): https://mehmetbaykar.com/posts/how-to-integrate-figma-mcp-in-claude-and-opencode/
- Figma remote MCP OAuth-only (Figma forum): https://forum.figma.com/suggest-a-feature-11/remote-figma-mcp-server-let-a-static-token-authenticate-as-an-alternative-to-oauth-57343
- Figma MCP guide (Seamgen): https://www.seamgen.com/blog/figma-mcp-complete-guide-to-design-to-code-automation
- Claude Code remote Figma MCP OAuth issue: https://github.com/anthropics/claude-code/issues/55943
- OpenRouter OAuth PKCE docs (official): https://openrouter.ai/docs/use-cases/oauth-pkce
- Anthropic Claude Code legal & compliance (OAuth vs API key policy): https://code.claude.com/docs/en/legal-and-compliance
- Anthropic "OpenClaw ban" background (MindStudio): https://www.mindstudio.ai/blog/anthropic-openclaw-ban-oauth-authentication
- Anthropic bans subscription auth in 3rd-party tools (AlternativeTo): https://alternativeto.net/news/2026/2/anthropic-officially-bans-using-subscription-authentication-for-third-party-claude-use
- Anthropic OAuth FAQ (Moltis): https://docs.moltis.org/anthropic-oauth.html
- Hugging Face "Sign in with Hugging Face" OAuth docs: https://huggingface.co/docs/hub/main/en/oauth
- Hugging Face OAuth connector scopes (Logto): https://docs.logto.io/integrations/huggingface
- Gemini API OAuth quickstart (Google): https://ai.google.dev/gemini-api/docs/oauth
- Gemini API key auth (Google): https://ai.google.dev/gemini-api/docs/api-key
- VirusTotal authentication docs: https://docs.virustotal.com/reference/authentication
- Security APIs overview (DEV): https://dev.to/0012303/20-free-security-apis-every-developer-should-know-about-2026-1e6
- OSINT API automation (Shodan/VT/Censys): https://openosint.tech/blog/osint-api-automation.html
- Public security APIs list: https://github.com/jaegeral/security-apis
- AbuseIPDB connector (Swimlane): https://docs.swimlane.com/connectors/abuseipdb
- RFC 9728 OAuth 2.0 Protected Resource Metadata: https://datatracker.ietf.org/doc/html/rfc9728
- RFC 8414 OAuth 2.0 Authorization Server Metadata: https://datatracker.ietf.org/doc/html/rfc8414
- RFC 7591 OAuth 2.0 Dynamic Client Registration: https://datatracker.ietf.org/doc/html/rfc7591
- RFC 8707 Resource Indicators for OAuth 2.0: https://www.rfc-editor.org/rfc/rfc8707.html
- RFC 9207 OAuth 2.0 Authorization Server Issuer Identification: https://datatracker.ietf.org/doc/html/rfc9207
- RFC 7009 OAuth 2.0 Token Revocation: https://datatracker.ietf.org/doc/html/rfc7009
