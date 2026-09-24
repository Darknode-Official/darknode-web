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
// Every provider is normalized to OpenAI-style SSE on the way out
//   data: {"choices":[{"delta":{"content":"..."}}]}\n\n ... data: [DONE]
// so the client has a single parser regardless of upstream format.

const { onRequest } = require("firebase-functions/v2/https");

const GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models";

const PROVIDERS = {
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
function toGeminiBody(messages) {
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
  return body;
}

function sseChunk(text) {
  return "data: " + JSON.stringify({ choices: [{ delta: { content: text } }] }) + "\n\n";
}

// Pump an OpenAI-format upstream SSE straight through (it's already our shape).
async function pipeOpenAi(upstream, res) {
  const reader = upstream.body.getReader();
  const dec = new TextDecoder();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    res.write(dec.decode(value, { stream: true }));
  }
  res.write("\n");
}

// Read a Gemini SSE stream and re-emit it as OpenAI-format chunks.
async function pipeGemini(upstream, res) {
  const reader = upstream.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
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
        if (parts) parts.forEach((p) => { if (p.text) res.write(sseChunk(p.text)); });
      } catch (_) { /* ignore keep-alive / partial lines */ }
    }
  }
  res.write("data: [DONE]\n\n");
}

exports.chat = onRequest({ cors: true, region: "us-central1", timeoutSeconds: 120, memory: "256MiB" }, async (req, res) => {
  if (req.method !== "POST") { res.status(405).send("POST only"); return; }

  const { provider, model, messages } = req.body || {};
  if (!provider || !model || !messages) { res.status(400).json({ error: "Missing provider, model, or messages" }); return; }

  const cfg = PROVIDERS[provider];
  if (!cfg) { res.status(400).json({ error: "Unknown provider: " + provider }); return; }

  const key = process.env[cfg.env];
  if (!key) { res.status(500).json({ error: "Server key not configured for " + provider }); return; }

  const isGemini = cfg.format === "gemini";
  const url = cfg.url(model, key);
  const headers = { "Content-Type": "application/json" };
  if (!isGemini) headers["Authorization"] = "Bearer " + key; // Gemini keys the URL instead
  if (cfg.headers) Object.assign(headers, cfg.headers);
  const body = isGemini ? toGeminiBody(messages) : toOpenAiBody(model, messages);

  try {
    // Gemini's free tier can briefly 429/503 under load — retry a couple times.
    let upstream;
    for (let attempt = 0; ; attempt++) {
      upstream = await fetch(url, { method: "POST", headers, body: JSON.stringify(body) });
      const retriable = upstream.status === 429 || upstream.status === 503;
      if (upstream.ok || !retriable || attempt >= 2) break;
      await new Promise((r) => setTimeout(r, 700 * (attempt + 1)));
    }

    if (!upstream.ok) {
      const errText = await upstream.text().catch(() => "");
      res.status(upstream.status).json({ error: "Upstream " + upstream.status + ": " + errText.slice(0, 300) });
      return;
    }
    if (!upstream.body) { res.status(502).json({ error: "No upstream body" }); return; }

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");

    if (isGemini) await pipeGemini(upstream, res);
    else await pipeOpenAi(upstream, res);
    res.end();
  } catch (e) {
    if (!res.headersSent) res.status(500).json({ error: e.message });
    else res.end();
  }
});
