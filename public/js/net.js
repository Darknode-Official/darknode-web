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
  if (opts.origin) qs.set("origin", String(opts.origin));
  if (opts.timeout > 15000) qs.set("t", String(Math.ceil(opts.timeout / 1000) - 2)); // let the worker wait longer upstream, and answer before we give up
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
  // The worker runs on Cloudflare, so a host it cannot reach comes back as Cloudflare's
  // own error page ("error code: 1016", HTTP 530) with Cloudflare's headers. That is
  // not the site answering: callers would grade those headers as the site's.
  const cf = data && data.status >= 400 && /^error code: (1\d{3})\s*$/.exec(String(data.body || ""));
  if (cf) {
    const why = { 1016: "its name does not resolve to an address (DNS lookup failed)", 1001: "its DNS could not be resolved", 1003: "it cannot be reached by bare IP address", 1020: "its firewall blocked the request", 1015: "it rate-limited the request" }[cf[1]];
    throw new Error(new URL(String(url)).hostname + " could not be reached: " + (why || "Cloudflare error " + cf[1]) + ".");
  }
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
