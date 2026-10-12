// Shared SSRF-guarded network helper for Darknode tools.
//
// Browsers block most cross-origin recon/OSINT requests (CORS), which is why so
// many tools historically faked their output. This routes those requests through
// the Darknode Worker's /api/fetch proxy, which performs the REAL request on the
// edge and returns the real upstream status, headers and body.
//
// Design rule: this helper NEVER fabricates data. If the proxy is unavailable or
// the upstream fails, it THROWS so callers show an honest error — never fake
// results dressed up as live.

function proxyBase() {
  try {
    if (window.DARKNODE_PROXY_URL) return String(window.DARKNODE_PROXY_URL).replace(/\/api\/chat$/, "");
  } catch (_) {}
  return "";
}

export function proxyConfigured() { return !!proxyBase(); }
export function proxyFetchEndpoint() { const b = proxyBase(); return b ? b + "/api/fetch" : ""; }

// dnFetch(url, { raw, redirect:"manual", timeout }) resolves to:
//   { url, finalUrl, status, statusText, contentType, headers, redirectChain, body, truncated }
// `raw:true` returns the body verbatim (no HTML->text); otherwise HTML is reduced
// to readable text while JSON/XML/text pass through.
export async function dnFetch(url, opts = {}) {
  const base = proxyBase();
  if (!base) throw new Error("Live fetch is unavailable — the Darknode proxy is not configured.");
  const qs = new URLSearchParams({ url: String(url) });
  if (opts.raw) qs.set("raw", "1");
  if (opts.redirect === "manual") qs.set("redirect", "manual");
  if (opts.ua) qs.set("ua", String(opts.ua));
  if (opts.max) qs.set("max", String(opts.max));
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeout || 15000);
  let res;
  try {
    res = await fetch(base + "/api/fetch?" + qs.toString(), { signal: ctrl.signal });
  } catch (e) {
    throw new Error("Network error reaching the Darknode proxy: " + ((e && e.message) || e));
  } finally { clearTimeout(timer); }
  let data;
  try { data = await res.json(); } catch (_) { throw new Error("The proxy returned an unreadable response."); }
  if (data && data.error) throw new Error(data.error);
  return data;
}

// Fetch a URL and parse its body as JSON (for keyless public APIs: CISA KEV,
// crt.sh, OSV.dev, ip-api, etc.). Throws on any non-JSON / failure.
export async function dnFetchJSON(url, opts = {}) {
  const r = await dnFetch(url, { ...opts, raw: true });
  try { return JSON.parse(r.body); }
  catch (_) {
    if (r.truncated || (r.bytes && r.body && r.bytes > r.body.length)) throw new Error("The source returned more data than the proxy size limit allows — try a narrower query.");
    throw new Error("Upstream did not return valid JSON" + (r.status && r.status !== 200 ? " (HTTP " + r.status + ")." : "."));
  }
}

try {
  window.dnFetch = dnFetch;
  window.dnFetchJSON = dnFetchJSON;
  window.dnProxyConfigured = proxyConfigured;
} catch (_) {}
