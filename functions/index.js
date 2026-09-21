const { onRequest } = require("firebase-functions/v2/https");

const PROVIDERS = {
  groq: { url: "https://api.groq.com/openai/v1/chat/completions", env: "GROQ_KEY", format: "openai" },
  openrouter: { url: "https://openrouter.ai/api/v1/chat/completions", env: "OPENROUTER_KEY", format: "openai" },
  mistral: { url: "https://api.mistral.ai/v1/chat/completions", env: "MISTRAL_KEY", format: "openai" },
};

exports.chat = onRequest({ cors: true, region: "us-central1", timeoutSeconds: 120, memory: "256MiB" }, async (req, res) => {
  if (req.method !== "POST") { res.status(405).send("POST only"); return; }

  const { provider, model, messages } = req.body;
  if (!provider || !model || !messages) { res.status(400).json({ error: "Missing provider, model, or messages" }); return; }

  const cfg = PROVIDERS[provider];
  if (!cfg) { res.status(400).json({ error: "Unknown provider: " + provider }); return; }

  const key = process.env[cfg.env];
  if (!key) { res.status(500).json({ error: "Server key not configured for " + provider }); return; }

  const headers = { "Content-Type": "application/json", "Authorization": "Bearer " + key };
  if (provider === "openrouter") {
    headers["HTTP-Referer"] = "https://darknode.ai";
    headers["X-Title"] = "Darknode AI";
  }

  try {
    const upstream = await fetch(cfg.url, {
      method: "POST",
      headers,
      body: JSON.stringify({ model, messages, stream: true }),
    });

    if (!upstream.ok) {
      const errText = await upstream.text().catch(() => "");
      res.status(upstream.status).json({ error: "Upstream " + upstream.status + ": " + errText.slice(0, 300) });
      return;
    }

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");

    const reader = upstream.body.getReader();
    const dec = new TextDecoder();

    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(dec.decode(value, { stream: true }));
    }
    res.end();
  } catch (e) {
    if (!res.headersSent) res.status(500).json({ error: e.message });
    else res.end();
  }
});
