// ============================================================================
// Attack-surface data layer for the Darknode Command Center.
//
// Thin async wrappers over the SSRF-guarded worker proxy (net.js → /api/fetch)
// around authoritative keyless sources: crt.sh (certificate transparency),
// DNS-over-HTTPS (Google + Cloudflare), RDAP (domain + IP registries), Team Cymru
// IP-to-ASN over DNS, and direct HTTP/header/security.txt probing. These
// return NORMALISED DATA only — the Deck renders it. Nothing here is simulated:
// every function performs a real request and throws on failure so the UI shows an
// honest error instead of fabricated results.
// ============================================================================

import { dnFetch, dnFetchJSON } from "/js/net.js";

const clean = (d) => String(d || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^\*\./, "");

// crt.sh certificate transparency → unique subdomains for a registrable domain.
export async function subdomains(domain) {
  const d = clean(domain);
  // crt.sh can return a multi-megabyte JSON for popular domains; request the
  // proxy's large-body cap so the catalogue parses instead of truncating.
  const rows = await dnFetchJSON("https://crt.sh/?q=%25." + encodeURIComponent(d) + "&output=json", { timeout: 30000, max: 4000000 });
  const set = new Set();
  (Array.isArray(rows) ? rows : []).forEach((r) => {
    String(r.name_value || "").split(/\n/).forEach((n) => {
      n = n.trim().toLowerCase().replace(/^\*\./, "");
      if (n && n.endsWith(d) && /^[a-z0-9.\-_]+$/.test(n)) set.add(n);
    });
  });
  return [...set].sort();
}

// DNS-over-HTTPS (Google first, Cloudflare fallback) for one record type.
async function doh(name, type) {
  const parse = (j) => ((j && j.Answer) || []).map((a) => String(a.data || "").replace(/^"|"$/g, "")).filter(Boolean);
  try {
    return parse(await dnFetchJSON("https://dns.google/resolve?name=" + encodeURIComponent(name) + "&type=" + type, { timeout: 15000 }));
  } catch (_) {
    return parse(await dnFetchJSON("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(name) + "&type=" + type, { timeout: 15000 }));
  }
}

// A/AAAA/MX/NS/TXT for a domain. Individual record failures degrade to [].
export async function dns(domain) {
  const d = clean(domain);
  const types = ["A", "AAAA", "MX", "NS", "TXT"];
  const out = {};
  await Promise.all(types.map(async (t) => { try { out[t] = await doh(d, t); } catch (_) { out[t] = []; } }));
  return out;
}

// RDAP registration data (registrar, key dates, nameservers, status).
export async function rdap(domain) {
  const d = clean(domain);
  const j = await dnFetchJSON("https://rdap.org/domain/" + encodeURIComponent(d), { timeout: 20000 });
  const ev = {};
  (j.events || []).forEach((e) => { if (e.eventAction) ev[e.eventAction] = String(e.eventDate || "").slice(0, 10); });
  const registrar = ((j.entities || []).find((e) => (e.roles || []).includes("registrar")) || {});
  const rName = (() => {
    const v = registrar.vcardArray && registrar.vcardArray[1];
    const fn = Array.isArray(v) ? v.find((x) => x[0] === "fn") : null;
    return fn ? fn[3] : (registrar.handle || "—");
  })();
  return {
    handle: j.handle || d,
    registrar: rName,
    registered: ev.registration || "—",
    updated: ev["last changed"] || ev["last update of RDAP database"] || "—",
    expires: ev.expiration || "—",
    status: j.status || [],
    nameservers: (j.nameservers || []).map((n) => String(n.ldhName || "").toLowerCase()).filter(Boolean)
  };
}

// Reverse an IP into its DNS query label (IPv4 octets, or IPv6 nibbles).
function revLabel(ip) {
  if (ip.includes(":")) {
    const [head, tail = ""] = ip.split("::");
    const h = head ? head.split(":") : [], t = tail ? tail.split(":") : [];
    const groups = h.concat(Array(8 - h.length - t.length).fill("0"), t).map((g) => g.padStart(4, "0"));
    return groups.join("").split("").reverse().join(".") + ".origin6.asn.cymru.com";
  }
  return ip.split(".").reverse().join(".") + ".origin.asn.cymru.com";
}
const cymru = (txt) => String(txt || "").split("|").map((s) => s.trim());

// Owning ASN + announced prefix for an IP via Team Cymru's IP-to-ASN DNS service,
// queried as TXT records over DoH — DNS, not a third-party REST API, so no key/quota.
export async function asn(ip) {
  const [o] = await doh(revLabel(ip), "TXT");
  if (!o) throw new Error("No BGP origin found for " + ip);
  const [as, prefix, cc, registry, allocated] = cymru(o);
  const n = as.split(" ")[0];
  const [d] = await doh("AS" + n + ".asn.cymru.com", "TXT").catch(() => []);
  const name = d ? cymru(d)[4] || "" : "";
  return { asn: "AS" + n, name: name || "—", prefix: prefix || "—", country: cc || "", registry: (registry || "").toUpperCase(), allocated: allocated || "" };
}

// Registered netblock for an IP straight from the regional internet registry (RDAP).
export async function netblock(ip) {
  const j = await dnFetchJSON("https://rdap.org/ip/" + encodeURIComponent(ip), { timeout: 20000 });
  const cidr = (j.cidr0_cidrs || []).map((c) => (c.v4prefix || c.v6prefix) + "/" + c.length);
  return {
    name: j.name || "—", handle: j.handle || "",
    range: j.startAddress && j.endAddress ? j.startAddress + " – " + j.endAddress : "",
    cidr: cidr.join(", "), country: j.country || "",
    whois: j.port43 || ""
  };
}

// Direct HTTP probe → status, final URL, server banner, redirect chain, and a
// security-header audit (present/missing) computed from the real response headers.
const SEC_HEADERS = [
  { key: "strict-transport-security", label: "HSTS" },
  { key: "content-security-policy", label: "Content-Security-Policy" },
  { key: "x-frame-options", label: "X-Frame-Options" },
  { key: "x-content-type-options", label: "X-Content-Type-Options" },
  { key: "referrer-policy", label: "Referrer-Policy" },
  { key: "permissions-policy", label: "Permissions-Policy" }
];
export async function httpProbe(domain) {
  const d = clean(domain);
  const r = await dnFetch("https://" + d + "/", { timeout: 20000 });
  const h = {};
  Object.keys(r.headers || {}).forEach((k) => { h[k.toLowerCase()] = r.headers[k]; });
  const secHeaders = SEC_HEADERS.map((s) => ({ label: s.label, present: !!h[s.key], value: h[s.key] || "" }));
  const tech = [];
  if (h["server"]) tech.push({ k: "Server", v: h["server"] });
  if (h["x-powered-by"]) tech.push({ k: "X-Powered-By", v: h["x-powered-by"] });
  if (h["x-aspnet-version"]) tech.push({ k: "ASP.NET", v: h["x-aspnet-version"] });
  if (h["via"]) tech.push({ k: "Via", v: h["via"] });
  if (h["cf-ray"] || /cloudflare/i.test(h["server"] || "")) tech.push({ k: "CDN", v: "Cloudflare" });
  return {
    status: r.status, statusText: r.statusText || "", finalUrl: r.finalUrl || r.url,
    redirects: (r.redirectChain || []).length, secHeaders, tech, server: h["server"] || "—"
  };
}

// security.txt (/.well-known/security.txt) — present + the Contact line if any.
export async function securityTxt(domain) {
  const d = clean(domain);
  const r = await dnFetch("https://" + d + "/.well-known/security.txt", { raw: true, timeout: 15000 });
  const body = String(r.body || "");
  const found = r.status === 200 && /contact\s*:/i.test(body);
  const contact = (body.match(/contact\s*:\s*(.+)/i) || [])[1] || "";
  return { found, status: r.status, contact: contact.trim(), body: found ? body.slice(0, 1200) : "" };
}

// Email authentication from DNS TXT: SPF (domain) + DMARC (_dmarc.domain).
export async function emailAuth(domain) {
  const d = clean(domain);
  const [txt, dmarcTxt] = await Promise.all([
    doh(d, "TXT").catch(() => []),
    doh("_dmarc." + d, "TXT").catch(() => [])
  ]);
  const spf = txt.find((t) => /^v=spf1/i.test(t)) || "";
  const dmarc = dmarcTxt.find((t) => /^v=DMARC1/i.test(t)) || "";
  return {
    spf: { present: !!spf, record: spf },
    dmarc: { present: !!dmarc, record: dmarc, policy: (dmarc.match(/p=([a-z]+)/i) || [])[1] || "" }
  };
}
