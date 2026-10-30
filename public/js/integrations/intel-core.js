// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Security integrations the Deck can actually call: one table shared by the
// browser (key tests, Assistant tools) and the Cloudflare Worker relay
// (worker/intel.js), so a request can only ever reach a fixed provider host on
// a path built here from validated arguments - never a caller-supplied URL.
// Pure: no DOM, no fetch.

const enc = encodeURIComponent;

// ---- argument types: everything a tool takes is checked before it leaves ----
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
export const ARG_TYPES = {
  ip: { hint: "an IPv4 or IPv6 address", ok: (v) => IPV4.test(v) || (/^[0-9a-f:]{2,39}$/i.test(v) && v.includes(":")) },
  domain: { hint: "a domain name like example.com", ok: (v) => /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(v) },
  hash: { hint: "an MD5, SHA-1 or SHA-256 hash", ok: (v) => /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(v) },
  url: { hint: "a full http(s) URL", ok: (v) => { try { const u = new URL(v); return (u.protocol === "https:" || u.protocol === "http:") && v.length <= 2048; } catch (_) { return false; } } },
  email: { hint: "an email address", ok: (v) => /^[^\s@]{1,64}@([a-z0-9-]+\.)+[a-z]{2,63}$/i.test(v) && v.length <= 254 },
  cve: { hint: "a CVE id like CVE-2024-3400", ok: (v) => /^CVE-\d{4}-\d{4,7}$/i.test(v) },
  query: { hint: "a search query (up to 200 characters)", ok: (v) => v.length >= 1 && v.length <= 200 && !/[\r\n]/.test(v) },
  indicator: { hint: "an IP, domain, URL or hash", ok: (v) => ["ip", "domain", "url", "hash"].some((t) => ARG_TYPES[t].ok(v)) },
};

// VirusTotal addresses a URL by its unpadded base64url form.
function b64url(s) {
  const b = typeof btoa === "function" ? btoa(unescape(enc(s))) : Buffer.from(s, "utf8").toString("base64");
  return b.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// provider -> { name, host, auth, headers, test, tools }
//   auth: { header } key in a header | { query } key as a query param | { bearer: true } | null (keyless)
//   test: the request a "Test key" makes; ok(status, data) decides if the key works
//   tools[]: { name, title, desc, args: { argName: type }, req(args) -> { path, query } }
export const PROVIDERS = {
  virustotal: {
    name: "VirusTotal", host: "www.virustotal.com", auth: { header: "x-apikey" },
    test: { path: "/api/v3/ip_addresses/8.8.8.8" },
    tools: [
      { name: "vt_ip", title: "IP report", desc: "VirusTotal verdicts, reputation, owner and country for an IP address.", args: { ip: "ip" }, req: (a) => ({ path: "/api/v3/ip_addresses/" + enc(a.ip) }) },
      { name: "vt_domain", title: "Domain report", desc: "VirusTotal verdicts, categories, registrar and DNS for a domain.", args: { domain: "domain" }, req: (a) => ({ path: "/api/v3/domains/" + enc(a.domain) }) },
      { name: "vt_file", title: "File hash report", desc: "VirusTotal engine detections and file details for an MD5/SHA-1/SHA-256 hash.", args: { hash: "hash" }, req: (a) => ({ path: "/api/v3/files/" + enc(a.hash) }) },
      { name: "vt_url", title: "URL report", desc: "VirusTotal verdicts for a URL that has been scanned before.", args: { url: "url" }, req: (a) => ({ path: "/api/v3/urls/" + b64url(a.url) }) },
    ],
  },
  shodan: {
    name: "Shodan", host: "api.shodan.io", auth: { query: "key" },
    test: { path: "/api-info" },
    tools: [
      { name: "shodan_host", title: "Host lookup", desc: "Open ports, services, banners, known vulnerabilities and owner Shodan has seen on an IP.", args: { ip: "ip" }, req: (a) => ({ path: "/shodan/host/" + enc(a.ip), query: { minify: "true" } }) },
      { name: "shodan_dns", title: "Domain DNS", desc: "Subdomains and DNS records Shodan knows for a domain.", args: { domain: "domain" }, req: (a) => ({ path: "/dns/domain/" + enc(a.domain) }) },
    ],
  },
  abuseipdb: {
    name: "AbuseIPDB", host: "api.abuseipdb.com", auth: { header: "Key" }, headers: { Accept: "application/json" },
    test: { path: "/api/v2/check", query: { ipAddress: "8.8.8.8" } },
    tools: [
      { name: "abuseipdb_check", title: "IP abuse check", desc: "Abuse confidence score, report count, ISP and usage type for an IP over the last 90 days.", args: { ip: "ip" }, req: (a) => ({ path: "/api/v2/check", query: { ipAddress: a.ip, maxAgeInDays: "90" } }) },
    ],
  },
  greynoise: {
    name: "GreyNoise", host: "api.greynoise.io", auth: { header: "key" }, headers: { Accept: "application/json" },
    test: { path: "/ping" }, // the community lookup ignores the key; /ping checks it
    tools: [
      { name: "greynoise_ip", title: "IP noise check", desc: "Whether an IP is a known mass scanner or a benign service (RIOT), and GreyNoise's classification.", args: { ip: "ip" }, req: (a) => ({ path: "/v3/community/" + enc(a.ip) }), found404: true },
    ],
  },
  otx: {
    name: "AlienVault OTX", host: "otx.alienvault.com", auth: { header: "X-OTX-API-KEY" },
    test: { path: "/api/v1/users/me" },
    tools: [
      { name: "otx_indicator", title: "Indicator pulses", desc: "OTX threat pulses, tags and malware families tied to an IP, domain or file hash.", args: { indicator: "indicator" }, req: (a) => {
        const v = a.indicator, kind = IPV4.test(v) ? "IPv4" : ARG_TYPES.ip.ok(v) ? "IPv6" : ARG_TYPES.hash.ok(v) ? "file" : ARG_TYPES.url.ok(v) ? "url" : "domain";
        return { path: "/api/v1/indicators/" + kind + "/" + enc(v) + "/general" };
      } },
    ],
  },
  urlscan: {
    name: "urlscan.io", host: "urlscan.io", auth: { header: "API-Key" },
    test: { path: "/user/quotas/" },
    tools: [
      { name: "urlscan_search", title: "Scan search", desc: "Past urlscan.io scans matching a query (for example domain:example.com or ip:1.2.3.4): pages, verdicts, screenshots.", args: { query: "query" }, req: (a) => ({ path: "/api/v1/search/", query: { q: a.query, size: "10" } }) },
    ],
  },
  securitytrails: {
    name: "SecurityTrails", host: "api.securitytrails.com", auth: { header: "APIKEY" }, headers: { Accept: "application/json" },
    test: { path: "/v1/ping" },
    tools: [
      { name: "securitytrails_domain", title: "Domain details", desc: "Current DNS records, hosting and Alexa rank for a domain.", args: { domain: "domain" }, req: (a) => ({ path: "/v1/domain/" + enc(a.domain) }) },
      { name: "securitytrails_subdomains", title: "Subdomains", desc: "Subdomains SecurityTrails has seen for a domain.", args: { domain: "domain" }, req: (a) => ({ path: "/v1/domain/" + enc(a.domain) + "/subdomains", query: { children_only: "false" } }) },
    ],
  },
  ipinfo: {
    name: "IPinfo", host: "ipinfo.io", auth: { bearer: true }, headers: { Accept: "application/json" },
    test: { path: "/8.8.8.8" },
    tools: [
      { name: "ipinfo_ip", title: "IP details", desc: "Geolocation, ASN, company and privacy flags (VPN, proxy, hosting) for an IP.", args: { ip: "ip" }, req: (a) => ({ path: "/" + enc(a.ip) }) },
    ],
  },
  hibp: {
    name: "Have I Been Pwned", host: "haveibeenpwned.com", auth: { header: "hibp-api-key" }, headers: { "User-Agent": "Darknode-Deck" },
    test: { path: "/api/v3/subscription/status" },
    tools: [
      { name: "hibp_account", title: "Breached account", desc: "Which known data breaches include an email address.", args: { email: "email" }, req: (a) => ({ path: "/api/v3/breachedaccount/" + enc(a.email), query: { truncateResponse: "false" } }), found404: true },
    ],
  },
  hunter: {
    name: "Hunter", host: "api.hunter.io", auth: { query: "api_key" },
    test: { path: "/v2/account" },
    tools: [
      { name: "hunter_domain", title: "Domain emails", desc: "Public email addresses Hunter has found for a domain and the address pattern it uses.", args: { domain: "domain" }, req: (a) => ({ path: "/v2/domain-search", query: { domain: a.domain, limit: "10" } }) },
      { name: "hunter_verify", title: "Verify email", desc: "Whether an email address is deliverable.", args: { email: "email" }, req: (a) => ({ path: "/v2/email-verifier", query: { email: a.email } }) },
    ],
  },
  pulsedive: {
    name: "Pulsedive", host: "pulsedive.com", auth: { query: "key" },
    test: { path: "/api/info.php", query: { indicator: "pulsedive.com" }, ok: (s, d) => s === 200 && !(d && d.error && /key/i.test(String(d.error))) },
    tools: [
      { name: "pulsedive_indicator", title: "Indicator risk", desc: "Pulsedive risk rating, threats and feeds for an IP, domain or URL.", args: { indicator: "indicator" }, req: (a) => ({ path: "/api/info.php", query: { indicator: a.indicator } }) },
    ],
  },
  hybrid: {
    name: "Hybrid Analysis", host: "www.hybrid-analysis.com", auth: { header: "api-key" }, headers: { "User-Agent": "Falcon Sandbox", Accept: "application/json" },
    test: { path: "/api/v2/key/current" },
    tools: [
      { name: "hybrid_hash", title: "Sandbox reports", desc: "Hybrid Analysis sandbox verdicts and threat scores for a file hash.", args: { hash: "hash" }, req: (a) => ({ path: "/api/v2/search/hash", query: { hash: a.hash } }) },
    ],
  },
  // keyless public sources: "Link to Darknode" turns their tools on
  nvd: {
    name: "NVD", host: "services.nvd.nist.gov", auth: null,
    tools: [
      { name: "nvd_cve", title: "CVE details", desc: "NVD description, CVSS scores, weaknesses and references for a CVE.", args: { cve: "cve" }, req: (a) => ({ path: "/rest/json/cves/2.0", query: { cveId: a.cve.toUpperCase() } }) },
    ],
  },
  circl: {
    name: "CIRCL CVE", host: "cve.circl.lu", auth: null,
    tools: [
      { name: "circl_cve", title: "CVE record", desc: "The CVE record from CIRCL's vulnerability-lookup, including affected products.", args: { cve: "cve" }, req: (a) => ({ path: "/api/cve/" + enc(a.cve.toUpperCase()) }) },
    ],
  },
};

// own keys only: "constructor" or "__proto__" must not resolve to Object.prototype members
const prov = (id) => (Object.prototype.hasOwnProperty.call(PROVIDERS, id) ? PROVIDERS[id] : null);
export const toolsFor = (id) => (prov(id) ? prov(id).tools : []);
export function findTool(name) {
  for (const [pid, p] of Object.entries(PROVIDERS)) { const t = p.tools.find((x) => x.name === name); if (t) return { provider: pid, p, tool: t }; }
  return null;
}

// Check a tool call's arguments; returns { args } (trimmed) or { error }.
export function checkArgs(tool, raw) {
  const args = {};
  for (const [k, type] of Object.entries(tool.args)) {
    const v = String((raw && raw[k]) == null ? "" : raw[k]).trim();
    if (!v) return { error: "missing " + k + " (" + ARG_TYPES[type].hint + ")" };
    if (!ARG_TYPES[type].ok(v)) return { error: k + " must be " + ARG_TYPES[type].hint };
    args[k] = v;
  }
  return { args };
}

// The exact upstream request for a provider call (a tool, or the key test when
// tool is null). Returns { url, headers } - the relay sends nothing else.
export function buildRequest(providerId, toolName, rawArgs, key) {
  const p = prov(providerId);
  if (!p) return { error: "unknown integration" };
  let spec;
  if (toolName) {
    const t = p.tools.find((x) => x.name === toolName);
    if (!t) return { error: "unknown tool" };
    const c = checkArgs(t, rawArgs); if (c.error) return c;
    spec = t.req(c.args);
  } else {
    if (!p.test) return { error: "this integration has no key to test" };
    spec = p.test;
  }
  if (p.auth && !key) return { error: "no API key" };
  const q = Object.assign({}, spec.query || {});
  const headers = Object.assign({}, p.headers || {});
  if (p.auth && p.auth.query) q[p.auth.query] = key;
  if (p.auth && p.auth.header) headers[p.auth.header] = key;
  if (p.auth && p.auth.bearer) headers.Authorization = "Bearer " + key;
  const qs = Object.entries(q).map(([k, v]) => enc(k) + "=" + enc(v)).join("&");
  return { url: "https://" + p.host + spec.path + (qs ? "?" + qs : ""), headers };
}

// Did the key test pass?
export function testPassed(providerId, status, data) {
  const t = (prov(providerId) || {}).test || {};
  return t.ok ? !!t.ok(status, data) : status >= 200 && status < 300;
}

// A plain-language reason for a failed call.
export function statusReason(status, data) {
  const m = data && typeof data === "object" ? data.message || (data.error && data.error.message) || data.error || (data.errors && data.errors[0] && (data.errors[0].detail || data.errors[0].title)) : "";
  const why = typeof m === "string" && m && m.length < 160 ? ": " + m : "";
  return baseReason(status) + why;
}
function baseReason(status) {
  if (status === 401 || status === 403) return "the provider rejected the key (" + status + ")";
  if (status === 429) return "the provider's rate limit or quota is used up (429)";
  if (status === 404) return "not found (404)";
  if (status >= 500) return "the provider had an error (" + status + ")";
  return "the provider answered " + status;
}

// Shrink a provider response to what a model needs: bounded depth, the first
// items of long lists, long strings clipped, and bulky raw fields dropped.
const DROP = new Set(["last_analysis_results", "html", "favicon", "raw", "screenshot", "dom", "data_b64", "certificate", "jarm", "last_https_certificate", "popular_threat_classification_raw"]);
export function compact(v, depth = 0) {
  if (v == null || typeof v === "boolean" || typeof v === "number") return v;
  if (typeof v === "string") return v.length > 400 ? v.slice(0, 400) + "..." : v;
  if (depth >= 5) return Array.isArray(v) ? "[" + v.length + " items]" : "{...}";
  if (Array.isArray(v)) { const out = v.slice(0, 12).map((x) => compact(x, depth + 1)); if (v.length > 12) out.push("... " + (v.length - 12) + " more"); return out; }
  const o = {};
  for (const [k, x] of Object.entries(v)) { if (DROP.has(k)) continue; o[k] = compact(x, depth + 1); }
  return o;
}
