// Darknode AI proxy — Cloudflare Worker.
//
// Same contract as the Firebase function it replaces: the SPA POSTs
//   { provider, model, messages }  to  <worker>/api/chat
// and gets back OpenAI-style SSE:
//   data: {"choices":[{"delta":{"content":"..."}}]}\n\n ... data: [DONE]
// so the client keeps its single parser. Provider keys live in Worker secrets
// (npx wrangler secret put NAME) and never reach the browser.
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

function toGeminiBody(messages) {
  const sys = (messages || []).find((m) => m.role === "system");
  const contents = (messages || []).filter((m) => m.role !== "system").map((m) => {
    const parts = [];
    if (m.images && m.images.length) m.images.forEach((b) => parts.push({ inlineData: { mimeType: "image/png", data: b } }));
    parts.push({ text: m.content || "Describe this image." });
    return { role: m.role === "assistant" ? "model" : "user", parts };
  });
  const body = { contents };
  if (sys && sys.content) body.systemInstruction = { parts: [{ text: sys.content }] };
  return body;
}

const sseChunk = (text) => "data: " + JSON.stringify({ choices: [{ delta: { content: text } }] }) + "\n\n";
const SSE_HEADERS = { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive", ...CORS };

// Re-emit a Gemini SSE stream as OpenAI-format SSE.
function geminiToOpenAiStream(upstream) {
  const reader = upstream.body.getReader();
  const dec = new TextDecoder();
  const enc = new TextEncoder();
  let buf = "";
  return new ReadableStream({
    async pull(controller) {
      const { done, value } = await reader.read();
      if (done) { controller.enqueue(enc.encode("data: [DONE]\n\n")); controller.close(); return; }
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line.startsWith("data: ")) continue;
        const payload = line.slice(6);
        if (payload === "[DONE]") continue;
        try {
          const j = JSON.parse(payload);
          const parts = j.candidates && j.candidates[0] && j.candidates[0].content && j.candidates[0].content.parts;
          if (parts) parts.forEach((p) => { if (p.text) controller.enqueue(enc.encode(sseChunk(p.text))); });
        } catch (_) { /* keep-alive / partial */ }
      }
    },
    cancel() { try { reader.cancel(); } catch (_) {} },
  });
}

// One upstream call, retrying Gemini's transient 429/503 a couple of times.
async function callUpstream(cfg, env, model, messages, key) {
  const isGemini = cfg.format === "gemini";
  const url = cfg.url(env, model, key);
  const headers = { "Content-Type": "application/json" };
  if (!isGemini && key) headers["Authorization"] = "Bearer " + key;
  if (cfg.headers) Object.assign(headers, cfg.headers);
  const body = JSON.stringify(isGemini ? toGeminiBody(messages) : toOpenAiBody(model, messages));
  let upstream;
  for (let attempt = 0; ; attempt++) {
    upstream = await fetch(url, { method: "POST", headers, body });
    const retriable = upstream.status === 429 || upstream.status === 503;
    if (upstream.ok || !retriable || attempt >= 2) break;
    await new Promise((r) => setTimeout(r, 700 * (attempt + 1)));
  }
  return { upstream, isGemini };
}

function streamBack(upstream, isGemini) {
  const body = isGemini ? geminiToOpenAiStream(upstream) : upstream.body;
  return new Response(body, { headers: SSE_HEADERS });
}

// Flagship Darknode: self-hosted GPU model while DARKNODE_URL is set; the moment
// it's unreachable (GPU run finished/off) fall back to Gemini with the persona.
async function handleDarknode(cfg, env, model, messages) {
  const msgs = applyPersona(messages, DARKNODE_PERSONA);
  if (env.DARKNODE_URL) {
    try {
      const { upstream, isGemini } = await callUpstream(cfg, env, model, msgs, env.DARKNODE_KEY);
      if (upstream.ok && upstream.body) return streamBack(upstream, isGemini);
    } catch (_) { /* fall through to Gemini */ }
  }
  if (!env.GEMINI_KEY) return json({ error: "Darknode GPU model is offline and no Gemini fallback key is configured (set GEMINI_KEY)." }, 503);
  const gModel = env.GEMINI_FALLBACK_MODEL || "gemini-flash-latest";
  const { upstream, isGemini } = await callUpstream(PROVIDERS.gemini, env, gModel, msgs, env.GEMINI_KEY);
  if (!upstream.ok) { const t = await upstream.text().catch(() => ""); return json({ error: "Gemini fallback " + upstream.status + ": " + t.slice(0, 300) }, upstream.status); }
  if (!upstream.body) return json({ error: "No upstream body" }, 502);
  return streamBack(upstream, isGemini);
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

    try {
      if (provider === "darknode") return await handleDarknode(cfg, env, model, messages);
      const key = env[cfg.envKey];
      if (!key && !cfg.optionalKey) return json({ error: "Server key not configured for " + provider }, 500);
      const { upstream, isGemini } = await callUpstream(cfg, env, model, messages, key);
      if (!upstream.ok) { const t = await upstream.text().catch(() => ""); return json({ error: "Upstream " + upstream.status + ": " + t.slice(0, 300) }, upstream.status); }
      if (!upstream.body) return json({ error: "No upstream body" }, 502);
      return streamBack(upstream, isGemini);
    } catch (e) {
      return json({ error: e.message || String(e) }, 500);
    }
  },
};
