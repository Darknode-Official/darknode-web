// posture-collect.js: live data collection for the External Posture Scorecard,
// shared by the console page (posture.js) and the Deck's native spaces. Returns the
// input object scorePosture() grades; throws (with the reason, e.g. the name does not
// resolve) when the host answers neither HTTP nor HTTPS.

import { newestCert } from "/js/dataprotect/posture-engine.js?v=20261029c";
import { fetchCertRows } from "/js/dataprotect/ct-fetch.js?v=20261026a";
import { dnFetch } from "/js/net.js";
import { registrableDomain } from "/js/dataprotect/phish-engine.js?v=20261029e";

export function cleanDomain(raw) {
  let d = String(raw || "").trim();
  // also accept what people paste: you@domain / mailto:, ?query or #hash without a path, a trailing root dot
  d = d.replace(/^mailto:/i, "").replace(/^[a-z]+:\/\//i, "").replace(/[/?#].*$/, "").replace(/^[^@]*@/, "").replace(/:\d+$/, "").replace(/\.$/, "").replace(/^www\./i, "");
  if (/[^\x00-\x7f]/.test(d)) { try { d = new URL("http://" + d).hostname; } catch (_) {} } // international names -> punycode (xn--)
  return d.toLowerCase();
}
export const validDomain = (d) => /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(d);

// Public DoH TXT (Cloudflare, Google fallback). Returns array of TXT strings.
export async function dohTXT(name) {
  const decode = (j) => ((j && j.Answer) || []).filter((a) => a.type === 16 || a.type === "TXT")
    .map((a) => String(a.data || "").replace(/^"|"$/g, "").replace(/"\s*"/g, ""));
  const urls = [
    "https://cloudflare-dns.com/dns-query?type=TXT&name=" + encodeURIComponent(name),
    "https://dns.google/resolve?type=TXT&name=" + encodeURIComponent(name),
  ];
  for (const u of urls) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 8000);
      const res = await fetch(u, { headers: { Accept: "application/dns-json" }, signal: ctrl.signal });
      clearTimeout(t);
      if (res.ok) return decode(await res.json());
    } catch (_) {}
  }
  // neither resolver answered: not the same as "no record", so the engine can say it could not check
  return Object.assign([], { failed: true });
}

// DMARC for a subdomain without its own record falls back to the organizational
// domain's (RFC 7489 6.6.3); .from names that domain when the fallback answered.
async function fetchDmarc(domain) {
  const own = await dohTXT("_dmarc." + domain);
  const org = registrableDomain(domain);
  if (own.some((t) => /^v=dmarc1/i.test(String(t).trim())) || org === domain || own.failed) return own;
  const inherited = await dohTXT("_dmarc." + org);
  return inherited.some((t) => /^v=dmarc1/i.test(String(t).trim())) ? Object.assign(inherited, { from: org }) : inherited.failed ? inherited : own;
}

async function fetchCert(domain) {
  const rows = await fetchCertRows(domain);
  return rows.length ? newestCert(rows) : rows.unreachable ? { unreachable: true } : null;
}

async function fetchSecurityTxt(domain) {
  for (const path of ["/.well-known/security.txt", "/security.txt"]) {
    try {
      const r = await dnFetch("https://" + domain + path, { raw: true, timeout: 12000 });
      // a site that answers every path with its HTML app is not publishing security.txt (RFC 9116: a
      // plain-text "Contact:" field at the start of a line)
      const b = String(r.body || "");
      if (r.status === 200 && !/^\s*</.test(b) && /^contact\s*:/im.test(b)) return { present: true };
    } catch (_) {}
  }
  return { present: false };
}

// Common DKIM selectors used by major mail providers / ESPs. We can only probe
// well-known names over DoH — a miss is NOT proof that DKIM is absent (selectors
// are arbitrary), which the engine reports honestly as "unknown".
const DKIM_SELECTORS = [
  "google", "default", "selector1", "selector2", "k1", "k2", "k3",
  "dkim", "mail", "s1", "s2", "mandrill", "mxvault", "zoho", "fm1",
  "fm2", "fm3", "protonmail", "scph0920", "pm", "amazonses", "sig1",
];
async function probeDkim(domain) {
  const out = await Promise.all(DKIM_SELECTORS.map(async (selector) => {
    try {
      const txts = await dohTXT(selector + "._domainkey." + domain);
      const recs = txts.filter((t) => /v\s*=\s*dkim1|(^|;)\s*k\s*=|(^|;)\s*p\s*=/i.test(String(t)));
      // an empty p= is a revoked key (RFC 6376 3.6.1): it signs nothing
      return { selector, present: recs.length > 0, revoked: recs.length > 0 && recs.every((t) => /(^|;)\s*p\s*=\s*(;|$)/i.test(String(t))) };
    } catch (_) { return { selector, present: false }; }
  }));
  return out;
}

// MTA-STS: the _mta-sts TXT record plus the policy file served from the
// mta-sts.<domain> host (/.well-known/mta-sts.txt).
async function fetchMtaSts(domain) {
  const txts = await dohTXT("_mta-sts." + domain);
  let policy = null;
  if (txts.some((t) => /^v=stsv1\b/i.test(String(t).trim()))) {
    try {
      const r = await dnFetch("https://mta-sts." + domain + "/.well-known/mta-sts.txt", { raw: true, timeout: 12000 });
      if (r.status === 200 && /mode\s*:/i.test(r.body || "")) policy = r.body;
    } catch (_) {}
  }
  return { txts, policy };
}

export async function collectPosture(domain) {
  const [httpsP, httpP, spfP, dmarcP, certP, stxtP, dkimP, mtaP, tlsRptP] = await Promise.allSettled([
    dnFetch("https://" + domain, { timeout: 14000 }),
    dnFetch("http://" + domain, { timeout: 12000 }),
    dohTXT(domain),
    fetchDmarc(domain),
    fetchCert(domain),
    fetchSecurityTxt(domain),
    probeDkim(domain),
    fetchMtaSts(domain),
    dohTXT("_smtp._tls." + domain),
  ]);
  const val = (p) => (p.status === "fulfilled" ? p.value : null);
  const https = val(httpsP), http = val(httpP);

  if (!https && !http) throw new Error(String((httpsP.reason && httpsP.reason.message) || "It did not answer over HTTP or HTTPS."));

  const headers = (https && https.headers) || (http && http.headers) || {};
  const httpReached = !!http;
  const httpFinal = http ? (http.finalUrl || http.url || "") : "";
  const httpsFinal = https ? (https.finalUrl || https.url || "") : "";
  const input = {
    domain,
    requestedUrl: httpReached ? "http://" + domain : "https://" + domain,
    // Grade HTTPS on whether the HTTPS endpoint actually responded, and the
    // redirect separately on where the HTTP endpoint ended up.
    httpsOk: !!https,
    httpTested: httpReached,
    httpRedirectsToHttps: httpReached ? /^https:/i.test(httpFinal) : false,
    finalUrl: httpsFinal || httpFinal,
    headers,
    // Set-Cookie flags come straight off the real response headers (the proxy
    // preserves them); the engine folds cookie security into the headers score.
    spfTxts: val(spfP) || [], dmarcTxts: val(dmarcP) || [], dmarcFrom: (val(dmarcP) && val(dmarcP).from) || null,
    dkimSelectors: val(dkimP) || [],
    mtaStsTxts: (val(mtaP) && val(mtaP).txts) || [], mtaStsPolicy: (val(mtaP) && val(mtaP).policy) || null,
    tlsRptTxts: val(tlsRptP) || [],
    cert: val(certP) && !val(certP).unreachable ? val(certP) : null,
    certUnreachable: certP.status === "rejected" || !!(val(certP) && val(certP).unreachable),
    securityTxt: val(stxtP) || { present: false },
    now: Date.now(),
  };
  return input;
}
