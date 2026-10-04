// Darknode AI proxy — keeps provider API keys server-side.
//
// The web app is a static SPA, so any key shipped to the browser is public.
// This Cloud Function is the ONLY place the free-tier keys live: the client
// POSTs {provider, model, messages} to /api/chat (same-origin hosting rewrite)
// and the function injects the server key, calls the upstream provider, and
// streams the answer back. Keys never reach the browser.
//
// Keys are read from the function environment (functions/.env for local +
// deploy; upgrade to Secret Manager with `firebase functions:secrets:set` for
// production). The client falls back to a user's own BYOK key (called directly)
// only when they've entered one in Settings.
//
// Web access: Darknode AI can read live web pages. When a request's last user
// message contains URLs, the server fetches those pages (SSRF-guarded, public
// hosts only — the same public-only scope a browser AI has) and feeds their
// text to the model. On the Gemini path it also enables Google Search grounding
// so the model can search the web on its own. The client sends `cite:false` to
// suppress source citations (the desktop app does this); the website leaves it
// on, so answers there end with a Sources list.
//
// Every provider is normalized to OpenAI-style SSE on the way out
//   data: {"choices":[{"delta":{"content":"..."}}]}\n\n ... data: [DONE]
// so the client has a single parser regardless of upstream format.

const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const dns = require("dns").promises;
const net = require("net");

if (!admin.apps.length) admin.initializeApp();

const GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models";

// Server-enforced persona for the flagship `darknode` provider. It rides on
// BOTH the self-hosted GPU model and the Gemini fallback, so Darknode always
// leads with hacking/cybersecurity + coding regardless of what system prompt
// the client sends (a tampered client can't strip it). It can still help with
// general tasks — security and code are just its declared strengths.
const DARKNODE_PERSONA = `You are Darknode AI, the flagship model of Darknode (darknode.ai).
Your core expertise is offensive and defensive cybersecurity — penetration testing, exploit and payload development, reverse engineering, malware analysis, web/network/cloud security, digital forensics and detection engineering — and software engineering across languages and stacks. That is what you are best at and what you lead with.
Operate under an authorized-engagement assumption: the user is doing work they are permitted to do — their own systems, contracted engagements, red/blue-team exercises, CTFs, labs, coursework or research. Under that assumption be concrete and technical: real commands, real code, real methodology, real remediation — not vague warnings or boilerplate disclaimers. Separate OBSERVED facts from INFERENCE and flag anything uncertain.
You can also help with general, non-security tasks when asked, but security and coding are your specialty. Do not assist with clearly illegal non-consensual intrusion, indiscriminate or destructive malware, or attacks on people who have not consented — steer those back to the authorized, defensive framing.`;

// Return a copy of the messages with the persona prepended to (or merged into)
// the system message, so it always takes effect server-side.
function applyPersona(messages, persona) {
  const arr = Array.isArray(messages) ? messages.map((m) => ({ ...m })) : [];
  const sys = arr.find((m) => m.role === "system");
  if (sys) sys.content = persona + "\n\n" + (sys.content || "");
  else arr.unshift({ role: "system", content: persona });
  return arr;
}

// Append a citation directive to the system message so the model knows whether
// to surface source URLs. Website => cite; desktop app => never cite.
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

// Is an IP literal in a private / loopback / link-local / reserved range?
function isPrivateIp(ip) {
  ip = String(ip || "").toLowerCase();
  if (net.isIPv4(ip)) {
    const p = ip.split(".").map(Number);
    if (p[0] === 0 || p[0] === 10 || p[0] === 127) return true;
    if (p[0] === 169 && p[1] === 254) return true;          // link-local + cloud metadata 169.254.169.254
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
    if (p[0] >= 224) return true;                            // multicast / reserved
    return false;
  }
  if (ip === "::1" || ip === "::") return true;
  if (ip.startsWith("::ffff:")) return isPrivateIp(ip.slice(7)); // v4-mapped
  if (ip.startsWith("fe80") || ip.startsWith("fc") || ip.startsWith("fd")) return true; // link-local + unique-local
  return false;
}

// Resolve a URL's host and confirm every resolved address is a public one.
async function hostAllowed(u) {
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  const host = u.hostname.toLowerCase();
  if (!host || host === "localhost" || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".localhost")) return false;
  let ips = [];
  if (net.isIP(host)) ips = [host];
  else { try { ips = (await dns.lookup(host, { all: true })).map((r) => r.address); } catch (_) { return false; } }
  return ips.length > 0 && !ips.some(isPrivateIp);
}

// Very small HTML -> readable-text reducer (no deps).
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

// Pull the URLs out of a chunk of text (strip trailing punctuation, dedupe).
function extractUrls(text) {
  const m = String(text || "").match(/https?:\/\/[^\s<>"'`)\]}]+/gi) || [];
  const out = [];
  for (let u of m) { u = u.replace(/[.,;:!?)\]}>'"]+$/, ""); if (u && out.indexOf(u) < 0) out.push(u); }
  return out;
}

// Fetch one URL safely: only public hosts, manual redirects (re-checked each
// hop to defeat DNS-rebinding / redirect SSRF), 8s timeout, ~2MB body cap.
async function safeFetchUrl(rawUrl) {
  let current = rawUrl;
  for (let hop = 0; hop < 4; hop++) {
    let u; try { u = new URL(current); } catch (_) { return { url: rawUrl, error: "invalid URL" }; }
    if (!(await hostAllowed(u))) return { url: rawUrl, error: "blocked (non-public or unresolvable host)" };
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
    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      try { current = new URL(res.headers.get("location"), u.href).href; continue; } catch (_) { return { url: u.href, error: "bad redirect" }; }
    }
    if (!res.ok) return { url: u.href, error: "HTTP " + res.status };
    const ct = (res.headers.get("content-type") || "").toLowerCase();
    if (ct && !/text\/html|text\/plain|application\/(json|xml|xhtml)/.test(ct)) return { url: u.href, error: "unsupported content-type (" + ct.split(";")[0] + ")" };
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

// If the last user turn contains URLs, fetch them and inline their content so
// the model can answer from the live pages. Returns the (possibly rewritten)
// messages plus the list of source URLs actually fetched.
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

// ---- Providers -------------------------------------------------------------

const PROVIDERS = {
  // Darknode's own model. Points at a self-hosted OpenAI-compatible endpoint
  // (Ollama /v1, vLLM, or SGLang) set via DARKNODE_URL. Key optional — a
  // self-hosted box may need none. This is the platform's flagship model.
  darknode: {
    url: () => process.env.DARKNODE_URL || "http://127.0.0.1:11434/v1/chat/completions",
    env: "DARKNODE_KEY",
    format: "openai",
    optionalKey: true,
  },
  groq: { url: () => "https://api.groq.com/openai/v1/chat/completions", env: "GROQ_KEY", format: "openai" },
  openrouter: {
    url: () => "https://openrouter.ai/api/v1/chat/completions",
    env: "OPENROUTER_KEY",
    format: "openai",
    headers: { "HTTP-Referer": "https://darknode.ai", "X-Title": "Darknode AI" },
  },
  mistral: { url: () => "https://api.mistral.ai/v1/chat/completions", env: "MISTRAL_KEY", format: "openai" },
  gemini: {
    url: (model, key) => `${GEMINI_BASE}/${encodeURIComponent(model)}:streamGenerateContent?alt=sse&key=${encodeURIComponent(key)}`,
    env: "GEMINI_KEY",
    format: "gemini",
  },
};

// Translate the app's message array into an OpenAI chat payload (text + images).
function toOpenAiBody(model, messages) {
  const msgs = (messages || []).map((m) => {
    if (m.images && m.images.length) {
      return {
        role: m.role,
        content: [
          ...m.images.map((b) => ({ type: "image_url", image_url: { url: "data:image/png;base64," + b } })),
          { type: "text", text: m.content || "Describe this image." },
        ],
      };
    }
    return { role: m.role, content: m.content };
  });
  return { model, messages: msgs, stream: true };
}

// Translate the app's message array into a Gemini generateContent payload.
// When `useSearch` is set, attach the Google Search tool so Gemini can browse
// the live web (grounding) on its own.
function toGeminiBody(messages, useSearch) {
  const sys = (messages || []).find((m) => m.role === "system");
  const contents = (messages || [])
    .filter((m) => m.role !== "system")
    .map((m) => {
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

function sseChunk(text) {
  return "data: " + JSON.stringify({ choices: [{ delta: { content: text } }] }) + "\n\n";
}

// Pump an OpenAI-format upstream SSE through, line by line, dropping its
// terminal [DONE] (streamBack emits the single [DONE] after any Sources footer).
async function pipeOpenAi(upstream, res) {
  const reader = upstream.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      const t = line.trim();
      if (t === "data: [DONE]" || t === "data:[DONE]") continue;
      res.write(line + "\n");
    }
  }
  if (buf.trim() && buf.trim() !== "data: [DONE]") res.write(buf);
  return [];
}

// Read a Gemini SSE stream, re-emit it as OpenAI-format chunks, and collect the
// grounding source URLs so a Sources footer can be added.
async function pipeGemini(upstream, res) {
  const reader = upstream.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  const sources = new Set();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line.startsWith("data:")) continue;
      const payload = line.slice(line.indexOf(":") + 1).trim();
      if (!payload || payload === "[DONE]") continue;
      try {
        const j = JSON.parse(payload);
        const cand = j.candidates && j.candidates[0];
        const parts = cand && cand.content && cand.content.parts;
        if (parts) parts.forEach((p) => { if (p.text) res.write(sseChunk(p.text)); });
        const chunks = cand && cand.groundingMetadata && cand.groundingMetadata.groundingChunks;
        if (Array.isArray(chunks)) chunks.forEach((c) => { const u = c && c.web && c.web.uri; if (u) sources.add(u); });
      } catch (_) { /* ignore keep-alive / partial lines */ }
    }
  }
  return [...sources];
}

// One upstream call (with a couple of retries for Gemini's 429/503 under load).
// For Gemini, tries with Google Search grounding first and transparently retries
// without it if the key/tier rejects the tool (400/403), so answers never fail
// just because grounding isn't available.
async function callUpstream(cfg, model, messages, key, opts = {}) {
  const isGemini = cfg.format === "gemini";
  const url = cfg.url(model, key);
  const headers = { "Content-Type": "application/json" };
  if (!isGemini && key) headers["Authorization"] = "Bearer " + key; // Gemini keys the URL instead; self-hosted may need none
  if (cfg.headers) Object.assign(headers, cfg.headers);
  let search = isGemini && opts.search !== false;
  const build = () => (isGemini ? toGeminiBody(messages, search) : toOpenAiBody(model, messages));
  let upstream;
  for (let attempt = 0; attempt < 3; attempt++) {
    upstream = await fetch(url, { method: "POST", headers, body: JSON.stringify(build()) });
    // Grounding is paid-tier: free keys reject it with 400/403/429. Drop the tool and retry plain.
    if (!upstream.ok && search && (upstream.status === 400 || upstream.status === 403 || upstream.status === 429)) { search = false; continue; }
    const retriable = upstream.status === 429 || upstream.status === 503;
    if (upstream.ok || !retriable) break;
    await new Promise((r) => setTimeout(r, 700 * (attempt + 1)));
  }
  return { upstream, isGemini };
}

// Stream a successful upstream response back as OpenAI-style SSE, then (when the
// client wants citations) a Sources footer built from fetched + grounded URLs.
async function streamBack(res, upstream, isGemini, opts = {}) {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  const grounded = isGemini ? await pipeGemini(upstream, res) : await pipeOpenAi(upstream, res);
  if (opts.cite) {
    const all = [];
    (opts.fetchedSources || []).concat(grounded || []).forEach((u) => { if (u && all.indexOf(u) < 0) all.push(u); });
    if (all.length) res.write(sseChunk("\n\nSources:\n" + all.slice(0, 8).map((u) => "- " + u).join("\n")));
  }
  res.write("data: [DONE]\n\n");
  res.end();
}

// Flagship Darknode routing: use the self-hosted GPU model while it's up
// (DARKNODE_URL set), and the moment that endpoint is gone — GPU run finished
// or shut down — fall back to Gemini wearing the Darknode persona, so the
// "Darknode AI" model keeps working and stays security+coding focused.
async function handleDarknode(cfg, model, messages, res, opts) {
  const msgs = applyPersona(messages, DARKNODE_PERSONA);
  // 1) Real self-hosted endpoint first, but only if a URL is actually set
  //    (the localhost default is never reachable from the deployed function).
  if (process.env.DARKNODE_URL) {
    try {
      const { upstream, isGemini } = await callUpstream(cfg, model, msgs, process.env[cfg.env]);
      if (upstream.ok && upstream.body) { await streamBack(res, upstream, isGemini, opts); return; }
    } catch (_) { /* GPU endpoint down -> fall through to Gemini */ }
  }
  // 2) Gemini fallback (persona-wrapped, with web search grounding).
  const gKey = process.env.GEMINI_KEY;
  if (!gKey) { res.status(503).json({ error: "Darknode GPU model is offline and no Gemini fallback key is configured (set GEMINI_KEY)." }); return; }
  const gModel = process.env.GEMINI_FALLBACK_MODEL || "gemini-flash-latest";
  const { upstream, isGemini } = await callUpstream(PROVIDERS.gemini, gModel, msgs, gKey);
  if (!upstream.ok) { const t = await upstream.text().catch(() => ""); res.status(upstream.status).json({ error: "Gemini fallback " + upstream.status + ": " + t.slice(0, 300) }); return; }
  if (!upstream.body) { res.status(502).json({ error: "No upstream body" }); return; }
  await streamBack(res, upstream, isGemini, opts);
}

// Browser origins allowed to call the proxy; a request carrying a different
// Origin is rejected so a malicious site cannot ride a visitor's browser to
// spend the server-side AI quota. No Origin (CLI/desktop app/curl) is allowed.
const CHAT_ALLOWED_ORIGINS = [
  "https://darknode.ai",
  "https://www.darknode.ai",
  "https://darknode-official.github.io",
  "https://darknode-web-e1s2.onrender.com",
];
function chatOriginAllowed(origin) {
  if (!origin) return true;
  try { const h = new URL(origin).hostname; if (h === "localhost" || h === "127.0.0.1") return true; return CHAT_ALLOWED_ORIGINS.includes(origin); } catch (_) { return false; }
}
const _chatRlWindow = 60000, _chatRlMax = 40, _chatRlHits = new Map();
function chatRateLimited(ip) {
  const now = Date.now(); let arr = _chatRlHits.get(ip); if (!arr) { arr = []; _chatRlHits.set(ip, arr); }
  while (arr.length && now - arr[0] > _chatRlWindow) arr.shift();
  if (arr.length >= _chatRlMax) return true; arr.push(now);
  if (_chatRlHits.size > 5000) { for (const [k, v] of _chatRlHits) { if (!v.length || now - v[v.length - 1] > _chatRlWindow) _chatRlHits.delete(k); } }
  return false;
}

exports.chat = onRequest({ cors: true, region: "us-central1", timeoutSeconds: 120, memory: "512MiB" }, async (req, res) => {
  if (req.method !== "POST") { res.status(405).send("POST only"); return; }
  const _origin = req.get && req.get("origin");
  if (!chatOriginAllowed(_origin)) { res.status(403).json({ error: "Origin not allowed" }); return; }
  const _ip = (req.get && (req.get("x-forwarded-for") || "").split(",")[0].trim()) || req.ip || "unknown";
  if (chatRateLimited(_ip)) { res.status(429).json({ error: "Rate limit exceeded — slow down and retry shortly." }); return; }

  const { provider, model, messages } = req.body || {};
  if (!provider || !model || !messages) { res.status(400).json({ error: "Missing provider, model, or messages" }); return; }

  const cfg = PROVIDERS[provider];
  if (!cfg) { res.status(400).json({ error: "Unknown provider: " + provider }); return; }

  // Citations default ON (website); the desktop app sends cite:false.
  const cite = !(req.body && req.body.cite === false);

  try {
    // Give every provider live web access: fetch any URLs in the last user
    // message, then tell the model whether to cite what it used.
    let msgs = messages, fetchedSources = [];
    try { const e = await enrichWithWeb(messages); msgs = e.messages; fetchedSources = e.sources; } catch (_) { msgs = messages; }
    msgs = applyCiteDirective(msgs, cite);
    const streamOpts = { cite, fetchedSources };

    // Flagship model has its own GPU-then-Gemini fallback path.
    if (provider === "darknode") { await handleDarknode(cfg, model, msgs, res, streamOpts); return; }

    const key = process.env[cfg.env];
    if (!key && !cfg.optionalKey) { res.status(500).json({ error: "Server key not configured for " + provider }); return; }

    const { upstream, isGemini } = await callUpstream(cfg, model, msgs, key, { search: provider === "gemini" });
    if (!upstream.ok) {
      const errText = await upstream.text().catch(() => "");
      res.status(upstream.status).json({ error: "Upstream " + upstream.status + ": " + errText.slice(0, 300) });
      return;
    }
    if (!upstream.body) { res.status(502).json({ error: "No upstream body" }); return; }
    await streamBack(res, upstream, isGemini, streamOpts);
  } catch (e) {
    if (!res.headersSent) res.status(500).json({ error: e.message });
    else res.end();
  }
});

// ---------------------------------------------------------------------------
// Nexus CLI pairing exchange. The website writes a one-time, 5-minute code to
// Firestore `pairings/{code}` carrying the user's uid/email/name and their
// REVOCABLE Darknode API key (never the Firebase refresh token). The CLI POSTs
// the code here; we look it up with the Admin SDK (clients cannot read the
// collection), delete it immediately (single-use, even on failure), check the
// expiry, and return the account identity + API key. Origin-gated + rate-limited
// like /chat; the CLI sends no Origin, which is allowed.
// ---------------------------------------------------------------------------
function normalizePairCode(raw) {
  return String(raw || "").replace(/[^A-Za-z0-9]/g, "").toUpperCase();
}
exports.pair = onRequest({ cors: true, region: "us-central1", timeoutSeconds: 20, memory: "256MiB" }, async (req, res) => {
  if (req.method !== "POST") { res.status(405).json({ error: "POST only" }); return; }
  const _origin = req.get && req.get("origin");
  if (!chatOriginAllowed(_origin)) { res.status(403).json({ error: "Origin not allowed" }); return; }
  const _ip = (req.get && (req.get("x-forwarded-for") || "").split(",")[0].trim()) || req.ip || "unknown";
  if (chatRateLimited(_ip)) { res.status(429).json({ error: "Rate limit exceeded — slow down and retry shortly." }); return; }

  const code = normalizePairCode((req.body || {}).code);
  if (!code || code.length < 8 || code.length > 64) { res.status(400).json({ error: "Invalid code" }); return; }

  const ref = admin.firestore().collection("pairings").doc(code);
  let snap;
  try { snap = await ref.get(); } catch (e) { res.status(500).json({ error: "Lookup failed" }); return; }
  if (!snap.exists) { res.status(404).json({ error: "Invalid or expired code — generate a fresh one on the website (Settings → Nexus CLI)." }); return; }
  const d = snap.data() || {};
  // Single-use: consume the code regardless of whether it turns out valid.
  try { await ref.delete(); } catch (_) {}
  if (d.expiresAt && Date.now() > Number(d.expiresAt)) { res.status(410).json({ error: "Code expired — generate a fresh one on the website." }); return; }
  if (!d.uid || !d.apiKey) { res.status(410).json({ error: "Code is no longer valid — generate a fresh one." }); return; }
  res.status(200).json({ uid: d.uid, email: d.email || "", name: d.name || "", apiKey: d.apiKey });
});
