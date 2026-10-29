// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Integrations that really run: a key is tested with a live call before the Deck
// calls it connected, and connected security integrations become tools the
// Assistant can use (each call goes through the Worker relay, /api/intel).
import { PROVIDERS, findTool, checkArgs } from "/js/integrations/intel-core.js?v=20261029c";

const CONN_KEY = "dn_deck_connections_v1";
const acct = (k) => { let u = null; try { u = window.__dnUid || null; } catch (_) {} return k + "__" + (!u ? "nouser" : /^(test|app-guest)-/.test(u) ? "guest" : "u_" + u); };
const keyOf = (id) => { try { return String((window.dnKeys && window.dnKeys.get("dn_key_" + id)) || "").trim(); } catch (_) { return ""; } };
function relayUrl() {
  let b = ""; try { b = String(window.DARKNODE_PROXY_URL || "").replace(/\/api\/chat$/, ""); } catch (_) {}
  return b ? b + "/api/intel" : "";
}
async function relay(body, signal) {
  const u = relayUrl(); if (!u) return { ok: false, error: "the Darknode relay is not configured here" };
  // the worker gives up on a provider after 15s; this bounds a relay that never answers
  const ctrl = new AbortController(), to = setTimeout(() => ctrl.abort(), 25000), stop = () => ctrl.abort();
  if (signal) { if (signal.aborted) ctrl.abort(); else signal.addEventListener("abort", stop, { once: true }); }
  let r; try { r = await fetch(u, { method: "POST", signal: ctrl.signal, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); }
  catch (e) { if (signal && signal.aborted) throw e; return { ok: false, error: ctrl.signal.aborted ? "the Darknode relay did not answer in time" : "could not reach the Darknode relay" }; }
  finally { clearTimeout(to); if (signal) signal.removeEventListener("abort", stop); }
  let j = null; try { j = await r.json(); } catch (_) {}
  if (!j) return { ok: false, error: "the relay returned " + r.status };
  if (r.status === 404 && j.error === "Not found") return { ok: false, error: "the Darknode relay does not have integrations yet" };
  return j;
}

// AI providers: a cheap authenticated read (the model list) proves the key.
const AI_TESTS = {
  claude: (k) => ["https://api.anthropic.com/v1/models", { headers: { "x-api-key": k, "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true" } }],
  openai: (k) => ["https://api.openai.com/v1/models", { headers: { Authorization: "Bearer " + k } }],
  gemini: (k) => ["https://generativelanguage.googleapis.com/v1beta/models?key=" + encodeURIComponent(k), {}],
  groq: (k) => ["https://api.groq.com/openai/v1/models", { headers: { Authorization: "Bearer " + k } }],
  openrouter: (k) => ["https://openrouter.ai/api/v1/key", { headers: { Authorization: "Bearer " + k } }],
  mistral: (k) => ["https://api.mistral.ai/v1/models", { headers: { Authorization: "Bearer " + k } }],
  deepseek: (k) => ["https://api.deepseek.com/models", { headers: { Authorization: "Bearer " + k } }],
  together: (k) => ["https://api.together.xyz/v1/models", { headers: { Authorization: "Bearer " + k } }],
  xai: (k) => ["https://api.x.ai/v1/models", { headers: { Authorization: "Bearer " + k } }],
  cohere: (k) => ["https://api.cohere.ai/v1/models", { headers: { Authorization: "Bearer " + k } }],
  fireworks: (k) => ["https://api.fireworks.ai/inference/v1/models", { headers: { Authorization: "Bearer " + k } }],
  cerebras: (k) => ["https://api.cerebras.ai/v1/models", { headers: { Authorization: "Bearer " + k } }],
  huggingface: (k) => ["https://huggingface.co/api/whoami-v2", { headers: { Authorization: "Bearer " + k } }],
  perplexity: (k) => ["https://api.perplexity.ai/chat/completions", { method: "POST", headers: { Authorization: "Bearer " + k, "Content-Type": "application/json" }, body: JSON.stringify({ model: "sonar", max_tokens: 1, messages: [{ role: "user", content: "ok" }] }) }],
};
export const canTest = (id) => !!(AI_TESTS[id] || (PROVIDERS[id] && PROVIDERS[id].test));

// Test a key with a live call. -> { ok: true } | { ok: false, error } | { ok: null, error } (could not check)
export async function testKey(id, key) {
  key = String(key || "").trim();
  if (!key) return { ok: false, error: "enter a key" };
  if (PROVIDERS[id] && PROVIDERS[id].test) {
    const j = await relay({ provider: id, test: true, key });
    if (j.ok) return { ok: true };
    return { ok: j.status ? false : null, error: j.error || "the test failed" };
  }
  const t = AI_TESTS[id]; if (!t) return { ok: null, error: "this provider has no key test" };
  const [url, opts] = t(key), ctrl = new AbortController(), to = setTimeout(() => ctrl.abort(), 15000);
  try {
    const r = await fetch(url, Object.assign({ signal: ctrl.signal }, opts));
    if (r.ok) return { ok: true };
    if (r.status === 401 || r.status === 403) return { ok: false, error: "the provider rejected the key (" + r.status + ")" };
    if (r.status === 429) return { ok: true, note: "valid key, currently rate limited" };
    if (r.status === 402) return { ok: true, note: "valid key, but the account has no credit" };
    return { ok: false, error: "the provider answered " + r.status };
  } catch (_) {
    return { ok: null, error: "could not reach the provider from this browser" };
  } finally { clearTimeout(to); }
}

// Tools the Assistant may use right now: providers connected in the Deck (a
// verified key, or "Linked" for keyless sources).
export function availableTools() {
  let conns = {}; try { conns = JSON.parse(localStorage.getItem(acct(CONN_KEY)) || "{}") || {}; } catch (_) {}
  const out = [];
  for (const [id, p] of Object.entries(PROVIDERS)) {
    const c = conns[id]; if (!c || !c.connected) continue;
    if (p.auth && (!keyOf(id) || !c.verified)) continue;
    for (const t of p.tools) out.push({ provider: id, providerName: p.name, name: t.name, title: t.title, desc: t.desc, args: t.args, keyless: !p.auth });
  }
  return out;
}

// Run one tool call through the relay. -> { ok, data } | { ok: false, error }
export async function runTool(name, rawArgs, signal) {
  const f = findTool(name); if (!f) return { ok: false, error: "unknown tool " + name };
  const c = checkArgs(f.tool, rawArgs); if (c.error) return { ok: false, error: c.error };
  const key = keyOf(f.provider);
  if (f.p.auth && !key) return { ok: false, error: f.p.name + " is not connected" };
  return relay({ provider: f.provider, tool: name, args: c.args, key }, signal);
}
