// Copyright (c) 2026 Darknode-Official. All rights reserved.
// POST /api/intel - relay for the Deck's security integrations. Most intel APIs
// send no CORS headers, so the browser cannot call them itself. The request
// names a provider + tool + arguments; the upstream URL is built from the shared
// table (public/js/integrations/intel-core.js), so this can only reach those
// fixed hosts and paths. The user's key travels with the call, is used for that
// one upstream request, and is never stored or logged.
import { buildRequest, testPassed, statusReason, compact, PROVIDERS } from "../public/js/integrations/intel-core.js";
import { readCapped } from "./body-cap.js";

const MAX_BODY = 8192, MAX_READ = 1500000, WAIT_MS = 15000;

export async function handleIntel(request, json) {
  if (request.method !== "POST") return json({ error: "POST only" }, 405);
  const txt = await readCapped(request, MAX_BODY);
  if (txt === null) return json({ error: "Request body too large." }, 413);
  let b; try { b = JSON.parse(txt || "{}"); } catch (_) { return json({ error: "Body must be JSON." }, 400); }
  const provider = String(b.provider || ""), key = typeof b.key === "string" ? b.key.trim().slice(0, 512) : "";
  if (!Object.prototype.hasOwnProperty.call(PROVIDERS, provider)) return json({ error: "Unknown integration." }, 400);
  const test = !!b.test;
  const r = buildRequest(provider, test ? null : String(b.tool || ""), b.args || {}, key);
  if (r.error) return json({ ok: false, error: r.error }, 400);
  const ctrl = new AbortController(), to = setTimeout(() => ctrl.abort(), WAIT_MS);
  let res;
  try { res = await fetch(r.url, { headers: Object.assign({ "User-Agent": "Darknode-Deck/1.0 (+https://darknode.ai)" }, r.headers), redirect: "follow", signal: ctrl.signal }); }
  catch (e) { clearTimeout(to); return json({ ok: false, status: 0, error: ctrl.signal.aborted ? "the provider did not answer in time" : "could not reach the provider" }); }
  clearTimeout(to);
  let text = "";
  try {
    const reader = res.body.getReader(), dec = new TextDecoder(); let n = 0;
    for (;;) { const { done, value } = await reader.read(); if (done) break; n += value.length; text += dec.decode(value, { stream: true }); if (n > MAX_READ) { try { reader.cancel(); } catch (_) {} break; } }
  } catch (_) {}
  let data = null; try { data = JSON.parse(text); } catch (_) { data = text ? text.slice(0, 2000) : null; }
  const status = res.status;
  if (test) { const ok = testPassed(provider, status, data); return json({ ok, status, error: ok ? undefined : statusReason(status, data) }); }
  const tool = PROVIDERS[provider].tools.find((t) => t.name === b.tool);
  if (status === 404 && tool && tool.found404) return json({ ok: true, status, data: { found: false } });
  if (status < 200 || status >= 300) return json({ ok: false, status, error: statusReason(status, data) });
  return json({ ok: true, status, data: compact(data) });
}
