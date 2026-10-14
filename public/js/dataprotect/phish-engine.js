// phish-engine.js — pure, deterministic phishing / URL triage heuristics.
// Parses URLs and raw emails and scores risk from observable signals: redirect
// and obfuscation tricks, lookalike/homograph domains, suspicious TLDs, and
// email authentication alignment (SPF/DKIM/DMARC). Live lookups (redirect
// unfurling, domain age, DNS) are done by the UI and fed in. No network here.
// Tested in test/security/phish.test.mjs.

// ---- small utilities ------------------------------------------------------

export function levenshtein(a, b) {
  a = String(a); b = String(b);
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    let cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

// Common phishing targets (registrable-domain stems).
export const BRANDS = [
  "paypal", "microsoft", "apple", "amazon", "google", "facebook", "instagram",
  "netflix", "linkedin", "dropbox", "docusign", "outlook", "office365", "office",
  "bankofamerica", "chase", "wellsfargo", "citibank", "hsbc", "barclays",
  "coinbase", "binance", "metamask", "whatsapp", "adobe", "dhl", "fedex", "ups",
  "usps", "americanexpress", "amex", "steam", "roblox", "verizon", "att",
];

// Suspicious / abused TLDs (not exhaustive; a weak signal on its own).
export const RISKY_TLDS = new Set([
  "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "country", "click",
  "link", "work", "fit", "gdn", "review", "kim", "loan", "men", "date", "racing",
  "stream", "download", "win", "bid", "party", "science", "cam", "rest", "quest",
]);

// A short list of multi-label public suffixes so eTLD+1 is sane for the common cases.
const TWO_LEVEL = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz",
  "co.jp", "com.br", "com.mx", "co.in", "co.za", "com.sg", "com.hk", "com.tr",
]);

// Known URL-shortener hosts (unfurl recommended).
const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
  "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "lnkd.in", "t.ly",
]);

export function registrableDomain(host) {
  const labels = String(host || "").toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  if (TWO_LEVEL.has(lastTwo)) return labels.slice(-3).join(".");
  return lastTwo;
}

function hasNonAscii(s) { return /[^\x00-\x7F]/.test(String(s)); }

// ---- URL analysis ---------------------------------------------------------

export function analyzeUrl(raw) {
  const out = { input: raw, host: "", scheme: "", reasons: [], severity: "info" };
  let u;
  let s = String(raw || "").trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = "http://" + s; // tolerate scheme-less
  try { u = new URL(s); } catch (_) { out.reasons.push({ w: 3, t: "Unparseable URL." }); out.severity = "medium"; return out; }
  out.scheme = u.protocol.replace(":", "");
  out.host = u.hostname.toLowerCase();
  out.port = u.port;
  out.path = u.pathname + u.search;
  const reg = registrableDomain(out.host);
  out.registrable = reg;

  if (out.scheme === "http") out.reasons.push({ w: 1, t: "Plain HTTP (not encrypted)." });
  if (u.username || u.password) out.reasons.push({ w: 4, t: `Embedded credentials in the URL (userinfo before @). The real host is "${out.host}".` });
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(out.host)) out.reasons.push({ w: 3, t: "The link points at a raw IP address, not a domain." });
  if (out.host.startsWith("xn--") || out.host.includes(".xn--")) out.reasons.push({ w: 4, t: "Punycode host (xn--): possible homograph/lookalike domain." });
  if (hasNonAscii(out.host)) out.reasons.push({ w: 4, t: "Non-ASCII characters in the host: possible homograph attack." });

  const tld = reg.split(".").pop();
  if (RISKY_TLDS.has(tld)) out.reasons.push({ w: 2, t: `Top-level domain .${tld} is frequently abused.` });

  const labels = out.host.split(".");
  if (labels.length >= 5) out.reasons.push({ w: 2, t: `Unusually deep subdomain (${labels.length} labels) — brand names can hide here.` });
  const hyphens = (out.host.match(/-/g) || []).length;
  if (hyphens >= 3) out.reasons.push({ w: 1, t: `Many hyphens in the host (${hyphens}).` });
  if (/\d/.test(reg.split(".")[0]) && /[a-z]/.test(reg.split(".")[0]) && (reg.match(/\d/g) || []).length >= 3) out.reasons.push({ w: 1, t: "Digits mixed into the domain name." });

  if (SHORTENERS.has(out.host)) out.reasons.push({ w: 2, t: "URL shortener — the true destination is hidden until expanded." });

  // brand lookalike / impersonation
  const look = lookalike(out.host);
  if (look.impersonation) out.reasons.push({ w: 4, t: `Brand "${look.brand}" appears in a subdomain but the registered domain is "${reg}".` });
  else if (look.near) out.reasons.push({ w: 3, t: `Domain stem "${look.stem}" is a near-miss (edit distance ${look.distance}) of brand "${look.brand}".` });

  out.severity = sevFromWeight(sumWeight(out.reasons));
  out.lookalike = look;
  return out;
}

function sumWeight(reasons) { return reasons.reduce((a, r) => a + r.w, 0); }
function sevFromWeight(w) { return w >= 7 ? "critical" : w >= 4 ? "high" : w >= 2 ? "medium" : w >= 1 ? "low" : "info"; }

// Lookalike detection against the brand list.
export function lookalike(host) {
  const labels = String(host || "").toLowerCase().split(".");
  const reg = registrableDomain(host);
  const stem = reg.split(".")[0] || "";
  // impersonation: a brand is a label somewhere but NOT the registrable stem
  for (const b of BRANDS) {
    if (labels.includes(b) && stem !== b) return { brand: b, stem, impersonation: true, near: false, distance: 0 };
  }
  // near-miss typosquat on the stem
  let best = null;
  for (const b of BRANDS) {
    if (stem === b) return { brand: b, stem, impersonation: false, near: false, distance: 0, exact: true };
    const d = levenshtein(stem, b);
    if (d > 0 && d <= 2 && Math.abs(stem.length - b.length) <= 2 && (!best || d < best.distance)) best = { brand: b, stem, distance: d };
  }
  if (best) return { ...best, impersonation: false, near: true };
  return { brand: null, stem, impersonation: false, near: false, distance: null };
}

// ---- IOC extraction -------------------------------------------------------

export function extractIOCs(text) {
  text = String(text || "");
  const defang = (s) => s.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".").replace(/\[:\]/g, ":").replace(/\bhxxp/gi, "http");
  const t = defang(text);
  const uniq = (arr) => Array.from(new Set(arr));
  const urls = uniq((t.match(/\bhttps?:\/\/[^\s"'<>)\]]+/gi) || []).map((u) => u.replace(/[.,;]+$/, "")));
  const ips = uniq((t.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || []).filter((ip) => ip.split(".")[0] !== "0"));
  const emails = uniq((t.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || []));
  const hostsFromUrls = urls.map((u) => { try { return new URL(u).hostname.toLowerCase(); } catch (_) { return null; } }).filter(Boolean);
  const bareDomains = uniq((t.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi) || []).map((d) => d.toLowerCase()));
  const domains = uniq(hostsFromUrls.concat(bareDomains).filter((d) => !/\.(png|jpg|jpeg|gif|svg|css|js|json|html|webp)$/i.test(d)));
  const hashes = uniq((t.match(/\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi) || []));
  return { urls, domains, ips, emails, hashes };
}

// ---- email parsing --------------------------------------------------------

// Parse raw RFC822 headers (handles folded continuation lines). Returns a map
// of lowercased header name -> array of values (headers can repeat).
export function parseEmailHeaders(raw) {
  const text = String(raw || "").replace(/\r\n/g, "\n");
  const split = text.indexOf("\n\n");
  const headerBlock = split >= 0 ? text.slice(0, split) : text;
  const body = split >= 0 ? text.slice(split + 2) : "";
  const headers = {};
  const lines = headerBlock.split("\n");
  let cur = null;
  for (const line of lines) {
    if (/^[ \t]/.test(line) && cur) { cur.v += " " + line.trim(); continue; }
    const m = line.match(/^([!-9;-~]+):\s?(.*)$/);
    if (m) { cur = { k: m[1].toLowerCase(), v: m[2] }; (headers[cur.k] = headers[cur.k] || []).push(cur); }
  }
  const out = {};
  for (const k in headers) out[k] = headers[k].map((e) => e.v);
  return { headers: out, body, hasHeaders: !!out["from"] || !!out["received"] || !!out["message-id"] };
}

export function domainOf(addr) {
  const m = String(addr || "").match(/@([^\s>"']+)/);
  return m ? m[1].toLowerCase().replace(/[>)\].,]+$/, "") : "";
}
export function displayName(fromVal) {
  const s = String(fromVal || "").trim();
  const m = s.match(/^"?([^"<]*?)"?\s*<[^>]+>/);
  return (m ? m[1] : "").trim();
}

// Parse an Authentication-Results header value into pass/fail per method.
export function parseAuthResults(val) {
  const s = String(val || "").toLowerCase();
  const pick = (re) => { const m = s.match(re); return m ? m[1] : null; };
  return {
    spf: pick(/\bspf=(\w+)/),
    dkim: pick(/\bdkim=(\w+)/),
    dmarc: pick(/\bdmarc=(\w+)/),
  };
}

// ---- email triage ---------------------------------------------------------

export function triageEmail(raw) {
  const { headers, body, hasHeaders } = parseEmailHeaders(raw);
  const get = (k) => (headers[k] && headers[k][0]) || "";
  const from = get("from");
  const fromDomain = domainOf(from);
  const fromReg = registrableDomain(fromDomain);
  const returnPath = domainOf(get("return-path"));
  const replyTo = domainOf(get("reply-to"));
  const name = displayName(from);
  const auth = parseAuthResults(get("authentication-results"));

  const findings = [];
  const add = (w, t) => findings.push({ w, t });

  if (!hasHeaders) add(0, "No email headers were detected — paste the full message source (including headers) for a complete analysis.");

  // authentication results
  if (auth.dmarc === "fail") add(4, "DMARC failed — the message is not authorised by the From domain's policy.");
  else if (auth.dmarc === "pass") add(-2, "DMARC passed.");
  else if (hasHeaders) add(1, "No DMARC result in Authentication-Results.");
  if (auth.spf === "fail" || auth.spf === "softfail") add(2, `SPF ${auth.spf}.`);
  if (auth.dkim === "fail") add(2, "DKIM signature failed to verify.");

  // alignment
  if (fromReg && returnPath && registrableDomain(returnPath) !== fromReg) add(2, `Return-Path domain (${returnPath}) does not align with From (${fromReg}).`);
  if (fromReg && replyTo && registrableDomain(replyTo) !== fromReg) add(2, `Reply-To domain (${replyTo}) differs from From (${fromReg}) — replies would go elsewhere.`);

  // display-name spoofing
  const nameLook = lookalike(name.toLowerCase().replace(/[^a-z0-9.]/g, ""));
  const brandInName = BRANDS.find((b) => name.toLowerCase().includes(b));
  if (brandInName && fromReg && !fromReg.includes(brandInName)) add(4, `Display name mentions "${brandInName}" but the sending domain is ${fromReg || "unknown"}.`);
  const fromLook = fromReg ? lookalike(fromDomain) : { near: false, impersonation: false };
  if (fromLook.impersonation) add(4, `From domain impersonates brand "${fromLook.brand}" in a subdomain.`);
  else if (fromLook.near) add(3, `From domain is a near-miss of brand "${fromLook.brand}".`);

  // body URLs
  const iocs = extractIOCs(body || raw);
  const urlAnalyses = iocs.urls.slice(0, 25).map(analyzeUrl);
  const riskyUrls = urlAnalyses.filter((u) => u.severity === "high" || u.severity === "critical");
  for (const ru of riskyUrls.slice(0, 5)) add(3, `Risky link: ${ru.host} (${ru.reasons[0] ? ru.reasons[0].t : "suspicious"})`);
  // From-domain mismatch vs links
  const linkRegs = Array.from(new Set(urlAnalyses.map((u) => u.registrable).filter(Boolean)));
  if (fromReg && linkRegs.length && !linkRegs.includes(fromReg) && brandInName) add(2, "None of the links point to the brand's own domain.");

  const weight = findings.reduce((a, f) => a + Math.max(0, f.w), 0);
  return {
    mode: "email",
    from, fromDomain, fromReg, returnPath, replyTo, name, auth,
    subject: get("subject"), messageId: get("message-id"),
    iocs, urlAnalyses,
    findings: findings.sort((a, b) => b.w - a.w),
    verdict: verdictFromWeight(weight, auth),
  };
}

export function verdictFromWeight(weight, auth) {
  if (auth && auth.dmarc === "pass" && weight < 3) return { level: "likely-legitimate", label: "Likely legitimate", c: "#2f9e56" };
  if (weight >= 8) return { level: "high-risk", label: "High risk — likely phishing", c: "#b00020" };
  if (weight >= 4) return { level: "suspicious", label: "Suspicious", c: "#d9480f" };
  if (weight >= 2) return { level: "caution", label: "Treat with caution", c: "#b58100" };
  return { level: "low", label: "Low risk on observable signals", c: "#2f9e56" };
}

export function selfTest() {
  const out = [];
  const T = (n, c) => out.push({ name: n, pass: !!c });

  T("registrable co.uk", registrableDomain("a.b.example.co.uk") === "example.co.uk");
  T("registrable simple", registrableDomain("mail.google.com") === "google.com");
  T("levenshtein", levenshtein("paypal", "paypa1") === 1);

  const a = analyzeUrl("http://paypal.com.secure-login.ru/verify");
  T("impersonation flagged", a.lookalike.impersonation && a.severity !== "info");
  const b = analyzeUrl("https://paypa1.com");
  T("typosquat flagged", b.lookalike.near && b.lookalike.brand === "paypal");
  const c = analyzeUrl("https://github.com/x/y");
  T("benign url low", c.severity === "info" || c.severity === "low");
  const d = analyzeUrl("http://user:pass@198.51.100.9/login");
  T("userinfo + ip flagged", d.reasons.some((r) => /Embedded credentials/.test(r.t)) && d.reasons.some((r) => /raw IP/.test(r.t)));

  const ioc = extractIOCs("reach hxxp://evil[.]com/a and 8.8.8.8 or mail bob@x.com sha256 " + "a".repeat(64));
  T("ioc defang url", ioc.urls.some((u) => u.includes("evil.com")));
  T("ioc ip", ioc.ips.includes("8.8.8.8"));
  T("ioc hash", ioc.hashes.some((h) => h.length === 64));

  const em = triageEmail([
    "From: \"PayPal Service\" <service@paypa1-secure.com>",
    "Return-Path: <bounce@mailer.ru>",
    "Authentication-Results: mx.test; spf=fail; dkim=none; dmarc=fail",
    "Subject: Verify your account",
    "", "Click http://paypal.com.secure.ru/verify now.",
  ].join("\n"));
  T("email high risk", em.verdict.level === "high-risk" || em.verdict.level === "suspicious");
  T("email parsed from", em.fromDomain === "paypa1-secure.com");
  T("email auth parsed", em.auth.dmarc === "fail");

  const legit = triageEmail([
    "From: Billing <billing@example.com>",
    "Return-Path: <billing@example.com>",
    "Authentication-Results: mx.test; spf=pass; dkim=pass; dmarc=pass",
    "Subject: Your receipt", "", "Thanks for your order.",
  ].join("\n"));
  T("legit email passes", legit.verdict.level === "likely-legitimate");

  return { pass: out.every((t) => t.pass), tests: out };
}

export default {
  analyzeUrl, lookalike, extractIOCs, parseEmailHeaders, parseAuthResults,
  triageEmail, registrableDomain, domainOf, displayName, levenshtein,
  verdictFromWeight, BRANDS, RISKY_TLDS, selfTest,
};
