// Darknode AI proxy — Cloudflare Worker.
//
// Same contract as the Firebase function it replaces: the SPA POSTs
//   { provider, model, messages, cite? }  to  <worker>/api/chat
// and gets back OpenAI-style SSE:
//   data: {"choices":[{"delta":{"content":"..."}}]}\n\n ... data: [DONE]
// so the client keeps its single parser. Provider keys live in Worker secrets
// (npx wrangler secret put NAME) and never reach the browser.
//
// Web access: Darknode AI can read the live web. When the last user message
// contains URLs, the Worker fetches those pages (public hosts only, manual
// redirects, 8s timeout, 2MB cap) and inlines their text. On the Gemini path it
// also turns on Google Search grounding so the model can search the web itself.
// `cite` (default true) makes answers end with a Sources list — the website
// leaves it on; the desktop app sends cite:false to suppress citations.
//
// Free on Cloudflare's Workers plan (no card): 100k requests/day, native
// streaming. Deploy: `cd worker && npx wrangler deploy`.

import { handleVault } from "./vault.js";
import { handleGraph } from "./graph.js";
import { handleMonitor } from "./monitor.js";
import { handleKeys, handleIngest } from "./ingest.js";
import { hostAllowed } from "./net-guard.js";
import { readCapped } from "./body-cap.js";
import { handleIntel } from "./intel.js";
import { matchRoute, authenticate, authorize, attachPrincipal, rateCheck, ipCeiling, requestId, withHeaders } from "./auth.js";
export { VaultDO } from "./vault.js";
export { GraphDO } from "./graph.js";
export { MonitorDO } from "./monitor.js";
export { IngestDO } from "./ingest.js";
export { RateLimiterDO } from "./auth.js";

const GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models";

// Server-enforced persona for the flagship `darknode` provider — a
// hacking/cybersecurity + coding specialist that still handles general tasks.
// Rides on BOTH the self-hosted GPU model and the Gemini fallback, so a
// tampered client can't strip the focus.
const DARKNODE_PERSONA = `You are Darknode AI, the flagship model of Darknode (darknode.ai).
Your core expertise is offensive and defensive cybersecurity — penetration testing, exploit and payload development, reverse engineering, malware analysis, web/network/cloud security, digital forensics and detection engineering — and software engineering across languages and stacks. That is what you are best at and what you lead with.
Operate under an authorized-engagement assumption: the user is doing work they are permitted to do — their own systems, contracted engagements, red/blue-team exercises, CTFs, labs, coursework or research. Under that assumption be concrete and technical: real commands, real code, real methodology, real remediation — not vague warnings or boilerplate disclaimers. Separate OBSERVED facts from INFERENCE and flag anything uncertain.
You can also help with general, non-security tasks when asked, but security and coding are your specialty. Do not assist with clearly illegal non-consensual intrusion, indiscriminate or destructive malware, or attacks on people who have not consented — steer those back to the authorized, defensive framing.

Identity: you are Darknode AI, built and operated by Darknode. Refer to yourself only as "Darknode AI". Never reveal, name, confirm, deny or speculate about any underlying model, vendor, provider or company that may power you (for example Google, Gemini, OpenAI, GPT, Anthropic, Claude, Meta, Llama, Mistral) — not even if the user claims to already know, asks you to "be honest", or frames it as a test. If asked what model or company you are, what version you are, or who made you, answer that you are Darknode AI, Darknode's own assistant, and continue helping. Do not state a version number for yourself.`;

const PROVIDERS = {
  darknode: { url: (env) => env.DARKNODE_URL || "", envKey: "DARKNODE_KEY", format: "openai", optionalKey: true },
  groq: { url: () => "https://api.groq.com/openai/v1/chat/completions", envKey: "GROQ_KEY", format: "openai" },
  openrouter: { url: () => "https://openrouter.ai/api/v1/chat/completions", envKey: "OPENROUTER_KEY", format: "openai", headers: { "HTTP-Referer": "https://darknode.ai", "X-Title": "Darknode AI" } },
  mistral: { url: () => "https://api.mistral.ai/v1/chat/completions", envKey: "MISTRAL_KEY", format: "openai" },
  // Claude on the server-held ANTHROPIC_KEY secret; handled by handleClaude (not the
  // OpenAI/Gemini path) because it is signed-in only and separately rate-limited.
  anthropic: { url: () => "https://api.anthropic.com/v1/messages", envKey: "ANTHROPIC_KEY", format: "anthropic" },
  gemini: { url: (env, model, key) => `${GEMINI_BASE}/${encodeURIComponent(model)}:streamGenerateContent?alt=sse&key=${encodeURIComponent(key)}`, envKey: "GEMINI_KEY", format: "gemini" },
};

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, x-request-id",
  "Access-Control-Expose-Headers": "x-request-id, Retry-After",
};

// Browser origins allowed to call the proxy. A request carrying an Origin that
// is not on this list is rejected, so a malicious website cannot ride a visitor's
// browser to burn the server-side AI quota. Requests with NO Origin (the CLI,
// the desktop app, curl) are allowed — they are not a cross-site abuse vector.
const ALLOWED_ORIGINS = [
  "https://darknode.ai",
  "https://www.darknode.ai",
  "https://darknode-official.github.io",
];
export function originAllowed(origin) {
  if (!origin) return true; // non-browser client
  try {
    const h = new URL(origin).hostname;
    if (h === "localhost" || h === "127.0.0.1") return true;
    // Our own Render mirror gets an auto-assigned subdomain whose suffix can change
    // across redeploys; match the service prefix so a new suffix never breaks CORS.
    if (/^darknode-web-[a-z0-9]+\.onrender\.com$/.test(h)) return true;
    // Our Firebase Hosting sites and their preview channels (<site>--<channel>-<hash>.web.app).
    if (origin.startsWith("https://") && /^sentinel-b4194(-6173e)?(--[a-z0-9-]+)?\.web\.app$/.test(h)) return true;
    return ALLOWED_ORIGINS.includes(origin);
  } catch (_) { return false; }
}

const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...CORS } });

function applyPersona(messages, persona) {
  const arr = Array.isArray(messages) ? messages.map((m) => ({ ...m })) : [];
  const sys = arr.find((m) => m.role === "system");
  if (sys) sys.content = persona + "\n\n" + (sys.content || "");
  else arr.unshift({ role: "system", content: persona });
  return arr;
}

// Tell the model whether to surface source URLs. Website => cite; app => don't.
function applyCiteDirective(messages, cite) {
  const line = cite
    ? "When you use information from fetched web pages or web search, cite the source URLs inline so the reader can verify them."
    : "Use any fetched page content or web results to answer, but answer directly and concisely: do not include a sources list, cite URLs, or mention that you searched the web or read a page.";
  const arr = Array.isArray(messages) ? messages.map((m) => ({ ...m })) : [];
  const sys = arr.find((m) => m.role === "system");
  if (sys) sys.content = (sys.content || "") + "\n\n" + line;
  else arr.unshift({ role: "system", content: line });
  return arr;
}

// Google Search grounding roughly doubles time-to-first-token, so we only turn it
// on when the latest user message actually looks time-sensitive — anything whose
// answer depends on current/recent facts the model's training can't be trusted for
// (a specific CVE id, "latest/newest/today/this year", prices, releases, news).
// Explicit URLs are already handled by enrichWithWeb, so they don't count here.
// Env override: GEMINI_SEARCH="1" forces grounding on, "0" forces it off.
const SEARCH_HINTS = /\b(latest|newest|most recent|today|tonight|yesterday|this (week|month|year)|right now|current(ly)?|as of|up[- ]?to[- ]?date|breaking|news|just (announced|released|launched|dropped)|release[ds]?|changelog|price[sd]?|cost|in stock|who won|happening|trending|20(2[6-9]|[3-9]\d))\b|\bCVE-\d{4}-\d{3,}\b/i;
function wantsWebSearch(messages) {
  const arr = Array.isArray(messages) ? messages : [];
  for (let i = arr.length - 1; i >= 0; i--) {
    const m = arr[i];
    if (m && m.role === "user") {
      const txt = typeof m.content === "string" ? m.content
        : Array.isArray(m.content) ? m.content.map((p) => (p && p.text) || "").join(" ") : "";
      return SEARCH_HINTS.test(txt);
    }
  }
  return false;
}
function geminiSearchOn(env, messages) {
  const forced = env && env.GEMINI_SEARCH;
  if (forced === "1") return true;
  if (forced === "0") return false;
  return wantsWebSearch(messages);
}

// ---- Web access (SSRF-guarded URL fetching) --------------------------------
// hostAllowed / ipv4Private live in ./net-guard.js so monitor alert delivery
// (worker/notify.js) reuses the exact same SSRF guard.

function htmlToText(html) {
  let s = String(html || "");
  s = s.replace(/<!--[\s\S]*?-->/g, " ");
  s = s.replace(/<(script|style|noscript|svg|head|nav|footer)\b[\s\S]*?<\/\1>/gi, " ");
  s = s.replace(/<\/(p|div|li|h[1-6]|tr|br|section|article|ul|ol)>/gi, "\n");
  s = s.replace(/<br\s*\/?>/gi, "\n");
  s = s.replace(/<[^>]+>/g, " ");
  s = s.replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">").replace(/&quot;/gi, '"').replace(/&#39;/gi, "'");
  s = s.replace(/[ \t\f\v]+/g, " ").replace(/\n{3,}/g, "\n\n").trim();
  return s;
}

function extractUrls(text) {
  const m = String(text || "").match(/https?:\/\/[^\s<>"'`)\]}]+/gi) || [];
  const out = [];
  for (let u of m) { u = u.replace(/[.,;:!?)\]}>'"]+$/, ""); if (u && out.indexOf(u) < 0) out.push(u); }
  return out;
}

async function safeFetchUrl(rawUrl) {
  let current = rawUrl;
  for (let hop = 0; hop < 4; hop++) {
    let u; try { u = new URL(current); } catch (_) { return { url: rawUrl, error: "invalid URL" }; }
    if (!hostAllowed(u)) return { url: rawUrl, error: "blocked (non-public host)" };
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), 8000);
    let res;
    try {
      res = await fetch(u.href, {
        redirect: "manual",
        signal: ctrl.signal,
        headers: { "User-Agent": "DarknodeAI/1.0 (+https://darknode.ai)", "Accept": "text/html,application/xhtml+xml,text/plain,application/json,*/*" },
      });
    } catch (e) { clearTimeout(to); return { url: rawUrl, error: String((e && e.message) || e) }; }
    clearTimeout(to);
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (loc) { try { current = new URL(loc, u.href).href; continue; } catch (_) { return { url: u.href, error: "bad redirect" }; } }
    }
    if (!res.ok) return { url: u.href, error: "HTTP " + res.status };
    const ct = (res.headers.get("content-type") || "").toLowerCase();
    if (ct && !/text\/html|text\/plain|application\/(json|xml|xhtml)/.test(ct)) return { url: u.href, error: "unsupported content-type" };
    let raw = "", bytes = 0;
    const reader = res.body.getReader(), dec = new TextDecoder();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.length; raw += dec.decode(value, { stream: true });
      if (bytes > 2_000_000) { try { await reader.cancel(); } catch (_) {} break; }
    }
    const text = /json|xml/.test(ct) ? raw.slice(0, 6000) : htmlToText(raw).slice(0, 6000);
    return { url: u.href, text: text || "(no readable text)" };
  }
  return { url: rawUrl, error: "too many redirects" };
}

// Generic SSRF-guarded fetch proxy for the browser tools (recon/OSINT/HTTP
// inspection). Unlike safeFetchUrl (tuned for AI text enrichment) this preserves
// the REAL response status + headers so tools like header-analyzer, http-probe
// and tech-fingerprint can inspect them. Everything reaching here has already
// cleared the origin allow-list and per-IP rate limit in the router.
async function handleFetch(request) {
  const u0 = new URL(request.url);
  let target = u0.searchParams.get("url");
  let raw = u0.searchParams.get("raw") === "1";
  let follow = u0.searchParams.get("redirect") !== "manual";
  let method = "GET";
  // Optional opt-in User-Agent override. Default stays DarknodeRecon so existing
  // callers (header-analyzer, http-probe, tech-fingerprint) are unaffected; some
  // public sites (e.g. Ahmia) deflect bot UAs with a 302, so a caller may request
  // a browser-like UA. Capped in length; never trusted beyond a header value.
  let ua = u0.searchParams.get("ua") || "";
  // Optional opt-in body size cap (bytes). Default is unchanged (200 KB sliced,
  // 1 MB read ceiling) so existing callers behave identically; a caller that
  // genuinely needs a large JSON feed (e.g. the full CISA KEV catalog, ~1.8 MB)
  // may request more, clamped to 4 MB.
  let maxBytes = parseInt(u0.searchParams.get("max") || "", 10);
  // Optional opt-in upstream timeout (seconds) for slow keyless sources (crt.sh often
  // needs 15-20 s); default stays 10 s, clamped to 28 s.
  let waitS = parseInt(u0.searchParams.get("t") || "", 10);
  // Optional Origin request header, for CORS checks (does the site echo a foreign
  // origin?). Server-side, so no cookies ride along; only "null" or scheme://host[:port].
  let origin = u0.searchParams.get("origin") || "";
  if (request.method === "POST") {
    // Cap the request body BEFORE parsing — this control body is tiny ({url,...}),
    // so 64 KB is generous and stops an unbounded JSON parse (every other route
    // caps first). Oversize is rejected; a malformed small body is ignored as before.
    const txt = await readCapped(request, 65536);
    if (txt === null) return json({ error: "Request body too large." }, 413);
    try {
      const b = JSON.parse(txt || "{}");
      if (b && b.url) target = b.url;
      if (b && b.raw) raw = true;
      if (b && b.redirect === "manual") follow = false;
      if (b && b.method) method = String(b.method).toUpperCase();
      if (b && b.ua) ua = String(b.ua);
      if (b && b.max) maxBytes = parseInt(b.max, 10);
      if (b && b.t) waitS = parseInt(b.t, 10);
      if (b && b.origin) origin = String(b.origin);
    } catch (_) {}
  }
  const cap = Math.min(Math.max(Number.isFinite(maxBytes) ? maxBytes : 200000, 1), 4000000);
  const readCap = Math.max(cap, 1000000);
  const waitMs = Math.min(Math.max(Number.isFinite(waitS) ? waitS : 10, 1), 28) * 1000;
  if (!target) return json({ error: "Missing url parameter" }, 400);
  if (!["GET", "HEAD", "POST"].includes(method)) method = "GET";
  ua = ua ? ua.slice(0, 256).replace(/[\r\n]/g, "") : "";
  const reqHeaders = ua
    ? { "User-Agent": ua, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.9" }
    : { "User-Agent": "DarknodeRecon/1.0 (+https://darknode.ai)", "Accept": "*/*" };
  if (origin.length <= 256 && /^(null|https?:\/\/[a-z0-9.-]+(:\d{1,5})?)$/i.test(origin)) reqHeaders.Origin = origin;
  let current = target;
  const chain = [];
  for (let hop = 0; hop < 5; hop++) {
    let u; try { u = new URL(current); } catch (_) { return json({ error: "invalid URL" }, 400); }
    if (!hostAllowed(u)) return json({ error: "blocked (non-public or reserved host)" }, 403);
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), waitMs);
    let res;
    try {
      res = await fetch(u.href, { method, redirect: "manual", signal: ctrl.signal, headers: reqHeaders });
    } catch (e) { clearTimeout(to); return json({ error: String((e && e.message) || e) }, 502); }
    clearTimeout(to);
    const headers = {}; for (const [k, v] of res.headers) headers[k] = v;
    if (res.status >= 300 && res.status < 400 && follow) {
      const loc = res.headers.get("location");
      if (loc) { chain.push({ url: u.href, status: res.status, location: loc }); try { current = new URL(loc, u.href).href; continue; } catch (_) {} }
    }
    const ct = (res.headers.get("content-type") || "").toLowerCase();
    let body = "", bytes = 0, truncated = false;
    try {
      const reader = res.body && res.body.getReader(); const dec = new TextDecoder();
      if (reader) for (;;) {
        const { done, value } = await reader.read(); if (done) break;
        bytes += value.length; body += dec.decode(value, { stream: true });
        if (bytes > readCap) { truncated = true; try { await reader.cancel(); } catch (_) {} break; }
      }
    } catch (_) {}
    const full = raw || /json|xml|javascript|text|csv/.test(ct) ? body : htmlToText(body);
    // A body cut to `cap` is truncated too, not only one cut at the read ceiling.
    if (full.length > cap) truncated = true;
    const text = full.slice(0, cap);
    return json({ url: u.href, finalUrl: u.href, status: res.status, statusText: res.statusText || "", contentType: ct, headers, redirectChain: chain, body: text, bytes, truncated });
  }
  return json({ error: "too many redirects" }, 502);
}

async function enrichWithWeb(messages) {
  const arr = Array.isArray(messages) ? messages : [];
  let idx = -1;
  for (let i = arr.length - 1; i >= 0; i--) { if (arr[i].role === "user") { idx = i; break; } }
  if (idx < 0) return { messages, sources: [] };
  const text = String(arr[idx].content || "");
  const urls = extractUrls(text).slice(0, 3);
  if (!urls.length) return { messages, sources: [] };
  const results = await Promise.all(urls.map(safeFetchUrl));
  const blocks = results.filter(Boolean).map((r) => (r.text ? `Source: ${r.url}\n${r.text}` : `Source: ${r.url}\n[could not fetch: ${r.error}]`));
  if (!blocks.length) return { messages, sources: [] };
  const ctx = `\n\n<web_context note="Live page content fetched for you. Use it to answer the question.">\n${blocks.join("\n\n---\n\n")}\n</web_context>`;
  const copy = arr.map((m, i) => (i === idx ? { ...m, content: text + ctx } : m));
  return { messages: copy, sources: results.filter((r) => r && r.text).map((r) => r.url) };
}

// ---- Upstream calls + streaming --------------------------------------------

function toOpenAiBody(model, messages) {
  const msgs = (messages || []).map((m) => {
    if (m.images && m.images.length) {
      return { role: m.role, content: [
        ...m.images.map((b) => ({ type: "image_url", image_url: { url: "data:image/png;base64," + b } })),
        { type: "text", text: m.content || "Describe this image." },
      ] };
    }
    return { role: m.role, content: m.content };
  });
  return { model, messages: msgs, stream: true };
}

function toGeminiBody(messages, useSearch, thinkingBudget) {
  const sys = (messages || []).find((m) => m.role === "system");
  const contents = (messages || []).filter((m) => m.role !== "system").map((m) => {
    const parts = [];
    if (m.images && m.images.length) m.images.forEach((b) => parts.push({ inlineData: { mimeType: "image/png", data: b } }));
    parts.push({ text: m.content || "Describe this image." });
    return { role: m.role === "assistant" ? "model" : "user", parts };
  });
  const body = { contents };
  if (sys && sys.content) body.systemInstruction = { parts: [{ text: sys.content }] };
  if (useSearch) body.tools = [{ google_search: {} }];
  // Newer Gemini Flash models run a "thinking" pass by default that adds several
  // seconds before the first token — too slow for conversational chat. A budget of
  // 0 turns it off; a negative budget means "omit this and let the model decide".
  if (typeof thinkingBudget === "number" && thinkingBudget >= 0) {
    body.generationConfig = { thinkingConfig: { thinkingBudget } };
  }
  return body;
}

const sseChunk = (text) => "data: " + JSON.stringify({ choices: [{ delta: { content: text } }] }) + "\n\n";
const SSE_HEADERS = { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive", ...CORS };

// One upstream call. For Gemini, tries with Google Search grounding first and
// transparently retries without it if the key/tier rejects the tool (400/403),
// and retries transient 429/503 a couple of times.
// model id -> time until which it is skipped after hanging (per isolate, best effort)
const STALLED = new Map();

async function callUpstream(cfg, env, model, messages, key, opts = {}) {
  const isGemini = cfg.format === "gemini";
  const url = cfg.url(env, model, key);
  const headers = { "Content-Type": "application/json" };
  if (!isGemini && key) headers["Authorization"] = "Bearer " + key;
  if (cfg.headers) Object.assign(headers, cfg.headers);
  let search = isGemini && opts.search !== false;
  // Keep chat snappy: disable Gemini's default "thinking" pass (seconds of latency
  // before the first token) for plain replies. Grounded answers keep thinking since
  // recency questions benefit from it. Owner can override with GEMINI_THINKING_BUDGET
  // (a token budget; a negative value restores the model's own dynamic thinking).
  const envBudget = env && env.GEMINI_THINKING_BUDGET != null && env.GEMINI_THINKING_BUDGET !== ""
    ? parseInt(env.GEMINI_THINKING_BUDGET, 10) : 0;
  let budget = Number.isFinite(envBudget) ? envBudget : 0;
  if (search) budget = -1;
  const build = () => JSON.stringify(isGemini ? toGeminiBody(messages, search, budget) : toOpenAiBody(model, messages));
  let upstream;
  for (let attempt = 0; attempt < 3; attempt++) {
    // A model that never answers (seen with gemini-flash-latest: no headers for 100s+, so
    // Cloudflare cut the chat at 524) must not hang the chat: give up on headers after 12s
    // and report 504, which the caller treats like an overloaded model and falls back.
    const ac = new AbortController(), to = setTimeout(() => ac.abort(), 12000);
    try { upstream = await fetch(url, { method: "POST", headers, body: build(), signal: ac.signal }); }
    catch (e) { if (!ac.signal.aborted) throw e; upstream = new Response(JSON.stringify({ error: { message: "the model did not answer in time" } }), { status: 504 }); }
    finally { clearTimeout(to); }
    if (upstream.status === 504) break;
    // Google Search grounding is a paid-tier feature: free keys reject it with
    // 400/403 or 429 (RESOURCE_EXHAUSTED). Drop the tool and retry plain so the
    // answer still comes back; it activates automatically on a grounding-capable key.
    if (!upstream.ok && search && (upstream.status === 400 || upstream.status === 403 || upstream.status === 429)) { search = false; continue; }
    // A model that doesn't accept thinkingConfig rejects with 400; drop it and retry.
    if (!upstream.ok && isGemini && budget >= 0 && upstream.status === 400) { budget = -1; continue; }
    const retriable = upstream.status === 429 || upstream.status === 503;
    if (upstream.ok || !retriable) break;
    await new Promise((r) => setTimeout(r, 700 * (attempt + 1)));
  }
  return { upstream, isGemini };
}

// Normalize any upstream (OpenAI passthrough or Gemini) to OpenAI SSE, collect
// Gemini grounding sources, strip the upstream [DONE], then emit an optional
// Sources footer (when cite) and a single terminal [DONE].
function streamBack(upstream, isGemini, opts = {}) {
  const fmt = opts.format || (isGemini ? "gemini" : "openai");
  const passthrough = fmt === "openai";
  const reader = upstream.body.getReader();
  const dec = new TextDecoder();
  const enc = new TextEncoder();
  let buf = "";
  const sources = new Set();
  const cite = !!opts.cite;
  const fetched = opts.fetchedSources || [];
  const emitFooter = (controller) => {
    if (cite) {
      const all = [];
      fetched.concat([...sources]).forEach((u) => { if (u && all.indexOf(u) < 0) all.push(u); });
      if (all.length) controller.enqueue(enc.encode(sseChunk("\n\nSources:\n" + all.slice(0, 8).map((u) => "- " + u).join("\n"))));
    }
    controller.enqueue(enc.encode("data: [DONE]\n\n"));
  };
  const stream = new ReadableStream({
    async pull(ctrl) {
      // A chunk can carry no text (Anthropic's message_start, pings, Gemini keep-alives).
      // Returning from pull without enqueueing stalls the stream for good, so keep
      // reading until something was emitted or the upstream ended.
      let n = 0;
      const controller = { enqueue: (x) => { n++; ctrl.enqueue(x); }, close: () => ctrl.close() };
      while (n === 0) {
        const { done, value } = await reader.read();
        if (done) {
          if (passthrough && buf.trim() && buf.trim() !== "data: [DONE]") controller.enqueue(enc.encode(buf));
          emitFooter(controller); controller.close(); return;
        }
        buf += dec.decode(value, { stream: true });
        let nl;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          const t = line.trim();
          if (!t.startsWith("data:")) { if (passthrough) controller.enqueue(enc.encode(line + "\n")); continue; }
          const payload = t.slice(t.indexOf(":") + 1).trim();
          if (payload === "[DONE]") continue; // we emit our own terminal DONE after the footer
          if (fmt === "anthropic") {
            // Messages API SSE: only text deltas reach the reader; thinking and tool
            // blocks, pings and usage events are dropped.
            try {
              const j = JSON.parse(payload);
              if (j.type === "content_block_delta" && j.delta && j.delta.type === "text_delta" && j.delta.text) controller.enqueue(enc.encode(sseChunk(j.delta.text)));
              else if (j.type === "error") controller.enqueue(enc.encode(sseChunk("\n\n[Claude error: " + String((j.error && j.error.message) || "stream failed").slice(0, 200) + "]")));
              // A refusal ends the message with stop_reason "refusal" and no text block,
              // which would otherwise reach the user as a blank answer. Surface it.
              else if (j.type === "message_delta" && j.delta && j.delta.stop_reason === "refusal") controller.enqueue(enc.encode(sseChunk("This request was declined. Claude won't help with this one as written — try rephrasing toward the defensive, detection, or authorized-lab angle, or switch to another model.")));
            } catch (_) { /* partial */ }
          } else if (fmt === "gemini") {
            try {
              const j = JSON.parse(payload);
              const cand = j.candidates && j.candidates[0];
              const parts = cand && cand.content && cand.content.parts;
              if (parts) parts.forEach((p) => { if (p.text) controller.enqueue(enc.encode(sseChunk(p.text))); });
              const ch = cand && cand.groundingMetadata && cand.groundingMetadata.groundingChunks;
              if (Array.isArray(ch)) ch.forEach((c) => { const u = c && c.web && c.web.uri; if (u) sources.add(u); });
            } catch (_) { /* keep-alive / partial */ }
          } else {
            controller.enqueue(enc.encode(line + "\n"));
          }
        }
      }
    },
    cancel() { try { reader.cancel(); } catch (_) {} },
  });
  return new Response(stream, { headers: SSE_HEADERS });
}

// Claude models on the owner's Anthropic key. The key is a Worker secret
// (`wrangler secret put ANTHROPIC_KEY`): it is never in the repo, never sent to a
// browser, and only this function reads it. Because every call spends real credits:
// signed-in users only (admins only when CLAUDE_ACCESS="admin"), a per-user limit of
// CLAUDE_PER_MIN calls a minute, an allow-listed model set, and capped input/output.
// Upstream error bodies are not forwarded (they can describe the account).
export const CLAUDE_MODELS = new Set(["claude-fable-5-1", "claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"]);
const CLAUDE_PER_MIN = 6, CLAUDE_MAX_INPUT_CHARS = 120000, CLAUDE_MAX_TOKENS = 4096;

// OpenAI-style messages -> { system, messages } for the Messages API: system turns are
// joined, roles other than user/assistant dropped, same-role neighbours merged, and
// the conversation starts on a user turn.
export function toClaudeBody(model, messages) {
  const sys = [], out = [];
  for (const m of Array.isArray(messages) ? messages : []) {
    const text = typeof (m && m.content) === "string" ? m.content : Array.isArray(m && m.content) ? m.content.map((p) => (p && typeof p.text === "string" ? p.text : "")).join("") : "";
    if (!text) continue;
    if (m.role === "system") { sys.push(text); continue; }
    if (m.role !== "user" && m.role !== "assistant") continue;
    const last = out[out.length - 1];
    if (last && last.role === m.role) last.content += "\n\n" + text; else out.push({ role: m.role, content: text });
  }
  while (out.length && out[0].role !== "user") out.shift();
  const body = { model, max_tokens: CLAUDE_MAX_TOKENS, stream: true, messages: out };
  if (sys.length) body.system = sys.join("\n\n");
  return body;
}

// Prompt caching (Anthropic). Place two cache breakpoints: one at the end of the
// system block (the stable prefix, which also carries any tool instructions injected
// client-side) and one at the end of the conversation. The API caches each marked
// prefix for 5 minutes; a later request whose prefix matches is billed for the cached
// span at ~10% of fresh input and skips re-encoding it, which is the common case in a
// chat (same system every turn; each follow-up resends the whole history) and when a
// large file or long conversation is attached. Breakpoints below the model's minimum
// cacheable length are silently ignored by the API, so this is a no-op on short chats
// rather than an error. Render order is tools -> system -> messages, so these two are
// the natural prefix boundaries; max 4 breakpoints per request (we use 2).
export function withPromptCache(body) {
  const EPHEMERAL = { type: "ephemeral" };
  const b = { ...body };
  if (typeof b.system === "string" && b.system) b.system = [{ type: "text", text: b.system, cache_control: EPHEMERAL }];
  const msgs = Array.isArray(b.messages) ? b.messages.slice() : [];
  if (msgs.length) {
    const last = { ...msgs[msgs.length - 1] };
    const blocks = typeof last.content === "string" ? [{ type: "text", text: last.content }]
      : Array.isArray(last.content) ? last.content.map((x) => ({ ...x })) : null;
    if (blocks && blocks.length) {
      blocks[blocks.length - 1] = { ...blocks[blocks.length - 1], cache_control: EPHEMERAL };
      last.content = blocks;
      msgs[msgs.length - 1] = last;
      b.messages = msgs;
    }
  }
  return b;
}

// Exported for tests: the Messages API SSE -> the reader's OpenAI-style SSE.
export const claudeStream = (upstream, opts = {}) => streamBack(upstream, false, { ...opts, format: "anthropic" });

async function handleClaude(request, env, model, msgs, opts) {
  if (!env.ANTHROPIC_KEY) return json({ error: "Claude is not configured on this deployment." }, 503);
  if (!CLAUDE_MODELS.has(model)) return json({ error: "Unknown Claude model." }, 400);
  const a = await authenticate(request, env);
  if (a.error) return json({ error: a.error }, a.status);
  const p = a.principal;
  if (p.kind !== "user") return json({ error: "Sign in to use Claude models." }, 401);
  if (env.CLAUDE_ACCESS === "admin" && !(p.claims && p.claims.admin === true)) return json({ error: "Claude models are limited to administrators on this deployment." }, 403);
  const wait = await rateCheck(env, { kind: "user", uid: "claude:" + p.uid }, "", undefined, CLAUDE_PER_MIN);
  if (wait) return withHeaders(json({ error: "Claude limit reached (" + CLAUDE_PER_MIN + " messages a minute). Try again shortly." }, 429), { "Retry-After": String(wait) });
  const plain = toClaudeBody(model, msgs);
  if (!plain.messages.length) return json({ error: "Missing messages" }, 400);
  if (JSON.stringify(plain).length > CLAUDE_MAX_INPUT_CHARS) return json({ error: "Conversation too long for Claude here. Start a new chat." }, 413);
  const body = withPromptCache(plain);
  let upstream;
  const ac = new AbortController(), to = setTimeout(() => ac.abort(), 30000);
  try {
    upstream = await fetch(PROVIDERS.anthropic.url(), {
      method: "POST", signal: ac.signal, body: JSON.stringify(body),
      headers: { "Content-Type": "application/json", "x-api-key": env.ANTHROPIC_KEY, "anthropic-version": env.ANTHROPIC_VERSION || "2023-06-01" },
    });
  } catch (_) { return json({ error: ac.signal.aborted ? "Claude did not answer in time." : "Could not reach Claude." }, 504); }
  finally { clearTimeout(to); }
  if (!upstream.ok || !upstream.body) {
    const st = upstream.status;
    const msg = st === 429 ? "Claude is busy or out of credits. Try again later." : st === 529 ? "Claude is overloaded. Try again shortly." : st === 401 || st === 403 ? "Claude is temporarily unavailable." : "Claude request failed (" + st + ").";
    return json({ error: msg }, st === 401 || st === 403 ? 503 : st >= 400 && st < 600 ? st : 502);
  }
  return claudeStream(upstream, opts);
}

// Flagship Darknode: self-hosted GPU model while DARKNODE_URL is set; the moment
// it's unreachable (GPU run finished/off) fall back to Gemini with the persona
// and web-search grounding.
async function handleDarknode(cfg, env, model, messages, opts) {
  const msgs = applyPersona(messages, DARKNODE_PERSONA);
  if (env.DARKNODE_URL) {
    try {
      const { upstream, isGemini } = await callUpstream(cfg, env, model, msgs, env.DARKNODE_KEY);
      if (upstream.ok && upstream.body) return streamBack(upstream, isGemini, opts);
    } catch (_) { /* fall through to Gemini */ }
  }
  const gKey = env.GEMINI_KEY || env.GEMINI_KEY_2;
  if (!gKey) return json({ error: "Darknode GPU model is offline and no Gemini fallback key is configured (set GEMINI_KEY)." }, 503);
  const gModel = env.GEMINI_FALLBACK_MODEL || "gemini-3.5-flash";
  let { upstream, isGemini } = await callUpstream(PROVIDERS.gemini, env, gModel, msgs, gKey, { search: geminiSearchOn(env, msgs) });
  if (!upstream.ok && [401, 403, 429].includes(upstream.status) && env.GEMINI_KEY_2 && gKey !== env.GEMINI_KEY_2) {
    try { ({ upstream, isGemini } = await callUpstream(PROVIDERS.gemini, env, gModel, msgs, env.GEMINI_KEY_2, { search: geminiSearchOn(env, msgs) })); } catch (_) {}
  }
  if (!upstream.ok) { const t = await upstream.text().catch(() => ""); return json({ error: "Gemini fallback " + upstream.status + ": " + t.slice(0, 300) }, upstream.status); }
  if (!upstream.body) return json({ error: "No upstream body" }, 502);
  return streamBack(upstream, isGemini, opts);
}

// ---- Smart mode for the DI tab (/api/smart) --------------------------------
// The site's own key (SMART_KEY secret, falling back to GEMINI_KEY) stays here on
// the server and never reaches the browser. The planner prompt is fixed server
// side, so this route only ever plans DI requests or writes an answer/code; it
// is not a general-purpose proxy. Non-streaming JSON: { steps, answer }.
const SMART_SYS = `You are Smart mode, the language front-end of DI, a deterministic computation engine on the Darknode website. Refer to yourself only as "Smart mode"; do not name any underlying model, vendor or company.

The engine can: evaluate arithmetic and math expressions (variables, functions, factorial, percentages); convert units; convert number bases and roman numerals; convert colors; solve linear and quadratic equations; do number theory (prime test, gcd/lcm, factorize, nth prime, nth fibonacci); compute statistics over a list; transform text (case, slug, counts, extract emails/urls/numbers, reverse, palindromes); build and test regular expressions; run JSON path queries; do date math; encode/hash (base64, hex, url, rot13, morse, md5, sha1, sha256); spell-check text; look up country capitals, chemical elements and physical constants; truth tables, set operations, matrices, sequences and combinatorics; geometry and interest formulas.

Understand the user's request however it is phrased or misspelled, using the earlier conversation for context. Reply with STRICT JSON and nothing else:
{"steps": [<engine command strings>], "answer": <string or null>}

Rules:
- CODE: whenever the user asks for code of any kind (a function, class, script, program, app, game, website, query, config, a fix, a refactor, a code review or an explanation of code), put the COMPLETE, correct, runnable code in "answer" as markdown: one or two short sentences, then fenced code blocks with a language tag (e.g. \`\`\`python). No placeholders, no "TODO", no "rest of the code here": write all of it. Use the language the user asked for (default: Python). Set "steps" to [].
- COMPUTATION: put every part the engine can compute into "steps", one short normalized command each (e.g. "convert 5 km to miles", "solve x^2 - 5x + 6 = 0", "reverse: hello world", "capital of japan"). A later step may say "it" for the previous result (e.g. ["15% of 240", "multiply it by 3", "is it prime"]). For a math word problem a step is ONLY the arithmetic ("45+62+58").
- EVERYTHING ELSE (explanations, advice, writing, general knowledge): answer it in "answer", concise, correct and friendly, in markdown. If everything is covered by steps, "answer" is null.
- Output JSON only: no code fences around the JSON, no extra prose.`;

async function handleSmart(request, env) {
  // Try the dedicated Smart key first, then the shared Gemini key, so one valid
  // Google key keeps Smart mode working even when SMART_KEY is stale or unset.
  const keys = [...new Set([env.SMART_KEY, env.GEMINI_KEY, env.GEMINI_KEY_2].filter(Boolean))];
  if (!keys.length) return json({ error: "Smart mode is not configured on the server." }, 503);
  let body;
  // Cap the body before parsing (input is sliced to 6 KB + up to 6 history turns);
  // 256 KB is ample and matches the monitor route, so an unbounded parse can't run.
  const smartTxt = await readCapped(request, 262144);
  if (smartTxt === null) return json({ error: "Request body too large." }, 413);
  try { body = JSON.parse(smartTxt || "{}"); } catch (_) { return json({ error: "Invalid JSON body" }, 400); }
  const input = String((body && body.input) || "").slice(0, 6000).trim();
  if (!input) return json({ error: "Empty request" }, 400);
  const contents = [];
  for (const h of (Array.isArray(body.history) ? body.history : []).slice(-6)) {
    if (!h || !h.q) continue;
    contents.push({ role: "user", parts: [{ text: String(h.q).slice(0, 2000) }] });
    contents.push({ role: "model", parts: [{ text: String(h.a || "(answered)").slice(0, 600) }] });
  }
  contents.push({ role: "user", parts: [{ text: input }] });
  const req = { systemInstruction: { parts: [{ text: SMART_SYS }] }, contents, generationConfig: { temperature: 0.2, responseMimeType: "application/json", maxOutputTokens: 8192 } };
  // Primary model, then fallbacks when one is overloaded, missing or unreachable.
  // Overload (503) and quota (429) are per model, so move down the chain on either.
  const models = [...new Set([env.SMART_MODEL || "gemini-3.5-flash", "gemini-flash-latest",
    env.SMART_FALLBACK_MODEL || "gemini-flash-lite-latest", "gemini-3.1-flash-lite"])];
  let r = null, last = null;
  // Walk keys x models: a per-model fault (404 retired / 429 quota / 503 overload)
  // moves to the next model; a bad key (401/403) moves to the next key; a 400 is a
  // request fault no retry can fix, so stop.
  outer:
  for (const key of keys) {
    for (const model of models) {
      try { r = await fetch(`${GEMINI_BASE}/${encodeURIComponent(model)}:generateContent`, { method: "POST", headers: { "Content-Type": "application/json", "x-goog-api-key": key }, body: JSON.stringify(req) }); }
      catch (_) { r = null; continue; }
      last = r;
      if (r.ok || r.status === 400) break outer;
      if (r.status === 401 || r.status === 403) break;
    }
  }
  r = r || last;
  if (!r) return json({ error: "Smart mode could not be reached. Try again in a moment." }, 502);
  if (r.status === 429) return json({ error: "Smart mode is busy right now. Wait a few seconds and try again." }, 429);
  if (!r.ok) return json({ error: "Smart mode had a problem (" + r.status + "). Try again, or turn Smart mode off." }, 502);
  let j; try { j = await r.json(); } catch (_) { return json({ error: "Smart mode returned an unreadable response." }, 502); }
  const parts = (((j.candidates || [])[0] || {}).content || {}).parts || [];
  const text = parts.filter((p) => !p.thought).map((p) => p.text || "").join("").trim();
  if (!text) return json({ error: "Smart mode returned an empty response. Try rephrasing." }, 502);
  let parsed = null;
  try { parsed = JSON.parse(text.replace(/^```(?:json)?/i, "").replace(/```$/, "").trim()); } catch (_) {}
  if (!parsed || typeof parsed !== "object") return json({ steps: [], answer: text });
  const steps = Array.isArray(parsed.steps) ? parsed.steps.filter((x) => typeof x === "string" && x.trim()).map((x) => x.trim()).slice(0, 12) : [];
  return json({ steps, answer: typeof parsed.answer === "string" && parsed.answer.trim() ? parsed.answer : null });
}

export default {
  // A handler that throws (e.g. a JSON body of `null` on /api/intel) must not become
  // Cloudflare's HTML 1101 page with no CORS headers: answer JSON 500, no stack.
  // Every response carries x-request-id so a client report can be matched to logs.
  async fetch(request, env) {
    const rid = requestId(request);
    let res;
    try { res = await route(request, env, rid); } catch (_) { res = json({ error: "Internal error." }, 500); }
    return withHeaders(res, { "x-request-id": rid });
  },
};

// GET /api/v1/health — liveness for uptime checks. Reports which bindings exist,
// never which secrets are set.
function handleHealth(env) {
  return json({
    ok: true, service: "darknode-proxy", api: "v1", time: new Date().toISOString(),
    uptimeSec: Math.floor((Date.now() - STARTED) / 1000),
    bindings: { vault: !!env.VAULT, graph: !!env.GRAPH, monitor: !!env.MONITOR, ingest: !!env.INGEST, rate: !!env.RATE },
  });
}

// POST /api/v1/client-errors — the app reports uncaught errors here; they land in
// the Worker log (wrangler tail / Logpush) tagged with the request id. Fields are
// clipped and nothing is echoed back.
async function handleClientError(request, rid) {
  const raw = await readCapped(request, 8 * 1024);
  if (raw === null) return json({ error: "Request too large." }, 413);
  let b;
  try { b = JSON.parse(raw); } catch (_) { return json({ error: "Invalid JSON body" }, 400); }
  if (!b || typeof b !== "object") return json({ error: "Invalid JSON body" }, 400);
  const clip = (v, n) => (typeof v === "string" ? v.slice(0, n) : typeof v === "number" && isFinite(v) ? v : undefined);
  console.error(JSON.stringify({
    type: "client-error", rid, message: clip(b.message, 500), source: clip(b.source, 300), line: clip(b.line, 10), col: clip(b.col, 10),
    stack: clip(b.stack, 2000), page: clip(b.page, 300), release: clip(b.release, 40), ua: clip(request.headers.get("user-agent"), 200),
  }));
  return new Response(null, { status: 204, headers: CORS });
}

// Set on the first request: Workers return 0 from Date.now() at module load.
let STARTED = 0;

async function route(request, env, rid) {
    if (!STARTED) STARTED = Date.now();
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
    // Reject disallowed browser origins before anything else, so a hostile page
    // cannot ride a visitor's browser to spend the server-side keys.
    const origin = request.headers.get("Origin");
    if (!originAllowed(origin)) return json({ error: "Origin not allowed" }, 403);
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const limited = (wait) => withHeaders(json({ error: "Rate limit exceeded — slow down and retry shortly." }, 429), { "Retry-After": String(wait) });
    // The route table (auth.js) declares what each path needs; enforce it here.
    const { pathname } = new URL(request.url);
    const hit = matchRoute(pathname, request.method);
    if (hit.status === 404) return json({ error: "Not found" }, 404);
    if (hit.status === 405) return withHeaders(json({ error: hit.allow.join(" or ") + " only" }, 405), { Allow: hit.allow.join(", ") });
    const { route: r, rest } = hit;
    let wait = r.auth === "none" ? 0 : ipCeiling(ip);
    if (wait) return limited(wait);
    let principal = { kind: "anonymous" };
    if (r.auth !== "none") {
      const a = await authenticate(request, env);
      if (a.error) return json({ error: a.error }, a.status);
      principal = a.principal;
      const deny = authorize(r, principal);
      if (deny) return json({ error: deny.error }, deny.status);
      attachPrincipal(request, principal);
    }
    wait = await rateCheck(env, principal, ip);
    if (wait) return limited(wait);
    switch (r.id) {
      case "health": return handleHealth(env);
      case "client-errors": return handleClientError(request, rid);
      case "fetch": return handleFetch(request);
      case "smart": return handleSmart(request, env);
      case "intel": return handleIntel(request, json);
      case "vault": return handleVault(request, env, rest, json);
      case "graph": return handleGraph(request, env, rest, json);
      case "monitor": return handleMonitor(request, env, rest, json);
      case "keys": return handleKeys(request, env, rest, json);
      case "ingest": return handleIngest(request, env, rest, json, "ingest");
      case "findings": return handleIngest(request, env, rest, json, "findings");
    }
    // r.id === "chat" (POST only, enforced by the table)
    let body;
    try {
      const raw = await readCapped(request, 1024 * 1024);
      if (raw === null) return json({ error: "Request too large." }, 413); // parity with the other routes' body caps
      body = JSON.parse(raw);
    } catch (_) { return json({ error: "Invalid JSON body" }, 400); }
    const { provider, model, messages } = body || {};
    if (!provider || !model || !messages) return json({ error: "Missing provider, model, or messages" }, 400);

    const cfg = Object.prototype.hasOwnProperty.call(PROVIDERS, provider) ? PROVIDERS[provider] : null;
    if (!cfg) return json({ error: "Unknown provider: " + provider }, 400);

    // Citations default ON (website); the desktop app sends cite:false.
    const cite = !(body && body.cite === false);

    try {
      // Live web access for every provider: fetch any URLs in the last user
      // message, then tell the model whether to cite what it used.
      let msgs = messages, fetchedSources = [];
      try { const e = await enrichWithWeb(messages); msgs = e.messages; fetchedSources = e.sources; } catch (_) { msgs = messages; }
      msgs = applyCiteDirective(msgs, cite);
      const opts = { cite, fetchedSources };

      if (provider === "darknode") return await handleDarknode(cfg, env, model, msgs, opts);
      if (provider === "anthropic") return await handleClaude(request, env, model, msgs, opts);
      // Gemini chat falls back to SMART_KEY the same way /api/smart does, so one valid
      // Google key powers both routes and the two secrets never have to stay in sync.
      let key = env[cfg.envKey] || (provider === "gemini" ? env.SMART_KEY || env.GEMINI_KEY_2 : undefined);
      if (!key && !cfg.optionalKey) return json({ error: "Server key not configured for " + provider }, 500);
      // Google Search grounding roughly doubles time-to-first-token, so turn it on
      // only when the question actually looks time-sensitive (see geminiSearchOn):
      // fast for the common case, grounded when recency matters. GEMINI_SEARCH="1"
      // forces it on, "0" off.
      const search = provider === "gemini" && geminiSearchOn(env, msgs);
      // A model that just hung (504 below) is skipped for a few minutes in this isolate,
      // so only the first chat after it stalls pays the 12s wait.
      let { upstream, isGemini } = provider === "gemini" && (STALLED.get(model) || 0) > Date.now()
        ? { upstream: new Response("{}", { status: 504 }), isGemini: true }
        : await callUpstream(cfg, env, model, msgs, key, { search });
      if (provider === "gemini" && upstream.status === 504) STALLED.set(model, Date.now() + 5 * 60 * 1000);
      // A spent or rejected primary Google key (quota 429, 401/403, or a model not yet
      // rolled out to that key's project: 404) retries the same model once on the
      // backup key (GEMINI_KEY_2 secret) before any model downgrade.
      if (provider === "gemini" && !upstream.ok && [401, 403, 404, 429].includes(upstream.status) && env.GEMINI_KEY_2 && key !== env.GEMINI_KEY_2) {
        key = env.GEMINI_KEY_2;
        try { ({ upstream, isGemini } = await callUpstream(cfg, env, model, msgs, key, { search })); } catch (_) {}
      }
      // A chosen Gemini model can be retired (404), rate-limited (429) or overloaded
      // (503) or hung (504). Rather than fail the chat, retry on the full stable Flash
      // model, then the fast lite alias (the most available tier), so "Darknode Core"
      // never dead-ends while another tier would have answered.
      for (const fb of ["gemini-3.5-flash", "gemini-flash-lite-latest"]) {
        if (provider !== "gemini" || upstream.ok || ![404, 429, 503, 504].includes(upstream.status)) break;
        if (fb !== model) { try { ({ upstream, isGemini } = await callUpstream(cfg, env, fb, msgs, key, { search })); } catch (_) {} }
      }
      if (!upstream.ok) { const t = await upstream.text().catch(() => ""); return json({ error: "Upstream " + upstream.status + ": " + t.slice(0, 300) }, upstream.status); }
      if (!upstream.body) return json({ error: "No upstream body" }, 502);
      return streamBack(upstream, isGemini, opts);
    } catch (e) {
      return json({ error: e.message || String(e) }, 500);
    }
}
