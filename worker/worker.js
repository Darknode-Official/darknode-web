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

const GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models";

// Server-enforced persona for the flagship `darknode` provider — a
// hacking/cybersecurity + coding specialist that still handles general tasks.
// Rides on BOTH the self-hosted GPU model and the Gemini fallback, so a
// tampered client can't strip the focus.
const DARKNODE_PERSONA = `You are Darknode AI, the flagship model of Darknode (darknode.ai).
Your core expertise is offensive and defensive cybersecurity — penetration testing, exploit and payload development, reverse engineering, malware analysis, web/network/cloud security, digital forensics and detection engineering — and software engineering across languages and stacks. That is what you are best at and what you lead with.
Operate under an authorized-engagement assumption: the user is doing work they are permitted to do — their own systems, contracted engagements, red/blue-team exercises, CTFs, labs, coursework or research. Under that assumption be concrete and technical: real commands, real code, real methodology, real remediation — not vague warnings or boilerplate disclaimers. Separate OBSERVED facts from INFERENCE and flag anything uncertain.
You can also help with general, non-security tasks when asked, but security and coding are your specialty. Do not assist with clearly illegal non-consensual intrusion, indiscriminate or destructive malware, or attacks on people who have not consented — steer those back to the authorized, defensive framing.`;

const PROVIDERS = {
  darknode: { url: (env) => env.DARKNODE_URL || "", envKey: "DARKNODE_KEY", format: "openai", optionalKey: true },
  groq: { url: () => "https://api.groq.com/openai/v1/chat/completions", envKey: "GROQ_KEY", format: "openai" },
  openrouter: { url: () => "https://openrouter.ai/api/v1/chat/completions", envKey: "OPENROUTER_KEY", format: "openai", headers: { "HTTP-Referer": "https://darknode.ai", "X-Title": "Darknode AI" } },
  mistral: { url: () => "https://api.mistral.ai/v1/chat/completions", envKey: "MISTRAL_KEY", format: "openai" },
  gemini: { url: (env, model, key) => `${GEMINI_BASE}/${encodeURIComponent(model)}:streamGenerateContent?alt=sse&key=${encodeURIComponent(key)}`, envKey: "GEMINI_KEY", format: "gemini" },
};

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

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

// ---- Web access (SSRF-guarded URL fetching) --------------------------------
// Cloudflare Workers run on the edge and can't reach a private network, and
// there's no `dns`/`net` module, so the guard is hostname/IP-literal based:
// reject localhost, .local/.internal, and private/reserved IP literals.

function ipv4Private(host) {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const p = m.slice(1).map(Number);
  if (p.some((n) => n > 255)) return true;
  if (p[0] === 0 || p[0] === 10 || p[0] === 127) return true;
  if (p[0] === 169 && p[1] === 254) return true;          // link-local + cloud metadata
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
  if (p[0] >= 224) return true;                            // multicast / reserved
  return false;
}

function hostAllowed(u) {
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  const h = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!h || h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".localhost")) return false;
  if (ipv4Private(h)) return false;
  if (h.includes(":")) { // IPv6 literal
    if (h === "::1" || h === "::") return false;
    if (h.startsWith("fe80") || h.startsWith("fc") || h.startsWith("fd")) return false;
    if (h.startsWith("::ffff:") && ipv4Private(h.slice(7))) return false;
  }
  return true;
}

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

function toGeminiBody(messages, useSearch) {
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
  return body;
}

const sseChunk = (text) => "data: " + JSON.stringify({ choices: [{ delta: { content: text } }] }) + "\n\n";
const SSE_HEADERS = { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive", ...CORS };

// One upstream call. For Gemini, tries with Google Search grounding first and
// transparently retries without it if the key/tier rejects the tool (400/403),
// and retries transient 429/503 a couple of times.
async function callUpstream(cfg, env, model, messages, key, opts = {}) {
  const isGemini = cfg.format === "gemini";
  const url = cfg.url(env, model, key);
  const headers = { "Content-Type": "application/json" };
  if (!isGemini && key) headers["Authorization"] = "Bearer " + key;
  if (cfg.headers) Object.assign(headers, cfg.headers);
  let search = isGemini && opts.search !== false;
  const build = () => JSON.stringify(isGemini ? toGeminiBody(messages, search) : toOpenAiBody(model, messages));
  let upstream;
  for (let attempt = 0; attempt < 3; attempt++) {
    upstream = await fetch(url, { method: "POST", headers, body: build() });
    // Google Search grounding is a paid-tier feature: free keys reject it with
    // 400/403 or 429 (RESOURCE_EXHAUSTED). Drop the tool and retry plain so the
    // answer still comes back; it activates automatically on a grounding-capable key.
    if (!upstream.ok && search && (upstream.status === 400 || upstream.status === 403 || upstream.status === 429)) { search = false; continue; }
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
    async pull(controller) {
      const { done, value } = await reader.read();
      if (done) {
        if (!isGemini && buf.trim() && buf.trim() !== "data: [DONE]") controller.enqueue(enc.encode(buf));
        emitFooter(controller); controller.close(); return;
      }
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        const t = line.trim();
        if (!t.startsWith("data:")) { if (!isGemini) controller.enqueue(enc.encode(line + "\n")); continue; }
        const payload = t.slice(t.indexOf(":") + 1).trim();
        if (payload === "[DONE]") continue; // we emit our own terminal DONE after the footer
        if (isGemini) {
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
    },
    cancel() { try { reader.cancel(); } catch (_) {} },
  });
  return new Response(stream, { headers: SSE_HEADERS });
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
  if (!env.GEMINI_KEY) return json({ error: "Darknode GPU model is offline and no Gemini fallback key is configured (set GEMINI_KEY)." }, 503);
  const gModel = env.GEMINI_FALLBACK_MODEL || "gemini-flash-latest";
  const { upstream, isGemini } = await callUpstream(PROVIDERS.gemini, env, gModel, msgs, env.GEMINI_KEY, { search: env.GEMINI_SEARCH !== "0" });
  if (!upstream.ok) { const t = await upstream.text().catch(() => ""); return json({ error: "Gemini fallback " + upstream.status + ": " + t.slice(0, 300) }, upstream.status); }
  if (!upstream.body) return json({ error: "No upstream body" }, 502);
  return streamBack(upstream, isGemini, opts);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
    const { pathname } = new URL(request.url);
    if (pathname !== "/api/chat") return json({ error: "Not found" }, 404);
    if (request.method !== "POST") return json({ error: "POST only" }, 405);

    let body;
    try { body = await request.json(); } catch (_) { return json({ error: "Invalid JSON body" }, 400); }
    const { provider, model, messages } = body || {};
    if (!provider || !model || !messages) return json({ error: "Missing provider, model, or messages" }, 400);

    const cfg = PROVIDERS[provider];
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
      const key = env[cfg.envKey];
      if (!key && !cfg.optionalKey) return json({ error: "Server key not configured for " + provider }, 500);
      const { upstream, isGemini } = await callUpstream(cfg, env, model, msgs, key, { search: provider === "gemini" && env.GEMINI_SEARCH !== "0" });
      if (!upstream.ok) { const t = await upstream.text().catch(() => ""); return json({ error: "Upstream " + upstream.status + ": " + t.slice(0, 300) }, upstream.status); }
      if (!upstream.body) return json({ error: "No upstream body" }, 502);
      return streamBack(upstream, isGemini, opts);
    } catch (e) {
      return json({ error: e.message || String(e) }, 500);
    }
  },
};
