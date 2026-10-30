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

// A curated list of common multi-label public suffixes so eTLD+1 is sane for
// the ccTLDs most often seen in phishing. (Not the full Public Suffix List — the
// goal is sensible registrable-domain extraction without shipping ~200 KB.)
const TWO_LEVEL = new Set([
  // UK
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk", "sch.uk", "nhs.uk", "police.uk",
  // Australia / NZ
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au",
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "geek.nz",
  // Japan / Korea / China / HK / TW / SG / India
  "co.jp", "or.jp", "ne.jp", "go.jp", "ac.jp", "ad.jp", "gr.jp",
  "co.kr", "or.kr", "ne.kr", "go.kr", "re.kr", "pe.kr",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
  "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk", "idv.hk",
  "com.tw", "org.tw", "net.tw", "gov.tw", "edu.tw", "idv.tw",
  "com.sg", "org.sg", "net.sg", "edu.sg", "gov.sg", "per.sg",
  "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "ac.in", "edu.in", "res.in",
  // Latin America
  "com.br", "net.br", "org.br", "gov.br", "edu.br",
  "com.mx", "org.mx", "gob.mx", "edu.mx",
  "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
  "com.co", "net.co", "org.co", "gov.co", "edu.co",
  // Europe
  "co.za", "org.za", "net.za", "gov.za", "ac.za",
  "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
  "com.ua", "net.ua", "org.ua", "gov.ua",
  "com.ru", "net.ru", "org.ru", "gov.ru", "edu.ru",
  "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl",
  "co.il", "org.il", "net.il", "gov.il", "ac.il",
  "com.es", "org.es", "edu.es", "gob.es",
  "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
  "com.my", "net.my", "org.my", "gov.my", "edu.my",
  "co.id", "or.id", "web.id", "go.id", "ac.id",
  "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
  "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
]);

// Known URL-shortener hosts (unfurl recommended).
const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
  "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "lnkd.in", "t.ly",
]);

const isIpHost = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || /^\[[0-9a-f:.]+\]$/i.test(h);

export function registrableDomain(host) {
  if (isIpHost(String(host || ""))) return String(host);
  const labels = String(host || "").toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  if (TWO_LEVEL.has(lastTwo)) return labels.slice(-3).join(".");
  return lastTwo;
}

function hasNonAscii(s) { return /[^\x00-\x7F]/.test(String(s)); }

// RFC 3492 punycode label decoder (xn--... -> Unicode), so a homograph can be
// shown the way a browser or mail client would display it. null when invalid.
function punyDecode(input) {
  const base = 36, tmin = 1, tmax = 26;
  let n = 128, i = 0, bias = 72;
  const out = [], b = Math.max(0, input.lastIndexOf("-"));
  for (let j = 0; j < b; j++) { if (input.charCodeAt(j) >= 0x80) return null; out.push(input.charCodeAt(j)); }
  const adapt = (delta, points, first) => {
    delta = first ? Math.floor(delta / 700) : delta >> 1;
    delta += Math.floor(delta / points);
    let k = 0;
    while (delta > ((base - tmin) * tmax) >> 1) { delta = Math.floor(delta / (base - tmin)); k += base; }
    return k + Math.floor(((base - tmin + 1) * delta) / (delta + 38));
  };
  for (let idx = b > 0 ? b + 1 : 0; idx < input.length;) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      if (idx >= input.length) return null;
      const c = input.charCodeAt(idx++);
      const digit = c >= 48 && c <= 57 ? c - 22 : c >= 97 && c <= 122 ? c - 97 : c >= 65 && c <= 90 ? c - 65 : base;
      if (digit >= base) return null;
      i += digit * w;
      const t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    if (n > 0x10ffff) return null;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

export function toUnicodeHost(host) {
  return String(host || "").split(".").map((l) => (l.startsWith("xn--") ? punyDecode(l.slice(4)) || l : l)).join(".");
}

// Characters that render like Latin letters (Cyrillic/Greek/IPA lookalikes);
// accents are stripped separately. Maps a displayed name to what it reads as.
const CONFUSABLE = {
  "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y", "\u0445": "x",
  "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u0501": "d", "\u04bb": "h", "\u04cf": "l", "\u0261": "g",
  "\u03bf": "o", "\u03b1": "a", "\u03bd": "v", "\u03b9": "i", "\u03ba": "k", "\u03c1": "p", "\u0131": "i", "\u0251": "a",
};
const skeleton = (s) => s.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/./gu, (c) => CONFUSABLE[c] || c);

// Digit-for-letter swaps used in brand typosquats (paypa1, m1crosoft, micr0soft):
// a digit may stand for any of its lookalike letters.
const LEET = { 0: "o", 1: "il", 3: "e", 4: "a", 5: "s", 7: "t" };
const leetIs = (t, b) => t.length === b.length && /\d/.test(t) && [...t].every((c, i) => c === b[i] || (LEET[c] || "").includes(b[i]));
// TLD-looking labels that only appear mid-host to make it read as ending there.
const FAKE_END = new Set(["com", "net", "org", "gov", "edu", "co"]);
const ACCOUNT_WORD = /^(online|login|signin|secure|account|accounts|support|verify|id|auth|help|service|update|billing|wallet|mail)$/;

// ---- URL analysis ---------------------------------------------------------

export function analyzeUrl(raw) {
  const out = { input: raw, host: "", scheme: "", reasons: [], severity: "info" };
  let u;
  let s = refangText(String(raw || "").trim()); // a defanged IOC (hxxps://evil[.]com) is analysed as the link it stands for
  const hadScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s);
  if (!hadScheme) s = "http://" + s; // tolerate scheme-less
  try { u = new URL(s); } catch (_) { out.reasons.push({ w: 3, t: "Unparseable URL." }); out.severity = "medium"; return out; }
  out.scheme = u.protocol.replace(":", "");
  out.host = u.hostname.toLowerCase();
  out.port = u.port;
  out.path = u.pathname + u.search;
  const reg = registrableDomain(out.host);
  out.registrable = reg;

  if (hadScheme && out.scheme === "http") out.reasons.push({ w: 1, t: "Plain HTTP (not encrypted)." });
  if (u.username || u.password) out.reasons.push({ w: 4, t: `Embedded credentials in the URL (userinfo before @). The real host is "${out.host}".` });
  if (isIpHost(out.host)) {
    out.reasons.push({ w: 3, t: "The link points at a raw IP address, not a domain." });
    // URL() normalises 0x7f.1 / 2130706433 / 0177.0.0.1 to dotted form; say so when the link hid it
    const typed = (s.match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?([^/:?#]+)/i) || [])[1];
    if (typed && typed.toLowerCase() !== out.host && !typed.startsWith("[")) out.reasons.push({ w: 3, t: `The IP address is written in a disguised form ("${typed}"); it really is ${out.host}.` });
  }
  if (out.host.startsWith("xn--") || out.host.includes(".xn--")) {
    out.display = toUnicodeHost(out.host);
    // Latin mixed with Cyrillic/Greek in one label is the homograph trick; a name in a
    // single script (bücher.de) is an ordinary international domain
    const mixed = out.display === out.host || out.display.split(".").some((l) => /[a-z]/.test(l) && /[\u0370-\u03ff\u0400-\u04ff\u0500-\u052f]/.test(l));
    out.reasons.push(mixed
      ? { w: 4, t: out.display !== out.host ? `Punycode host (xn--): it displays as "${out.display}", mixing alphabets, a likely homograph/lookalike domain.` : "Punycode host (xn--): possible homograph/lookalike domain." }
      : { w: 1, t: `Punycode host (xn--): an international name that displays as "${out.display}". Fine if that is the site you expect.` });
  }
  if (hasNonAscii(out.host)) out.reasons.push({ w: 4, t: "Non-ASCII characters in the host: possible homograph attack." });

  const tld = reg.split(".").pop();
  if (RISKY_TLDS.has(tld)) out.reasons.push({ w: 2, t: `Top-level domain .${tld} is frequently abused.` });

  const labels = out.host.split(".");
  if (labels.length >= 5) out.reasons.push({ w: 2, t: `Unusually deep subdomain (${labels.length} labels) — brand names can hide here.` });
  const hyphens = (out.host.replace(/(^|\.)xn--/g, "$1").match(/-/g) || []).length;
  if (hyphens >= 3) out.reasons.push({ w: 1, t: `Many hyphens in the host (${hyphens}).` });
  if (/\d/.test(reg.split(".")[0]) && /[a-z]/.test(reg.split(".")[0]) && (reg.match(/\d/g) || []).length >= 3) out.reasons.push({ w: 1, t: "Digits mixed into the domain name." });

  if (SHORTENERS.has(out.host)) out.reasons.push({ w: 2, t: "URL shortener — the true destination is hidden until expanded." });

  // brand lookalike / impersonation
  const look = lookalike(out.host);
  const fakeAt = labels.slice(0, -reg.split(".").length).findIndex((l, i) => i > 0 && FAKE_END.has(l));
  if (fakeAt > 0) out.reasons.push({ w: 2, t: `The address reads as if it ends at "${labels.slice(0, fakeAt + 1).join(".")}", but the real domain is "${reg}".` });
  if (look.homograph) out.reasons.push({ w: 4, t: `Its letters imitate "${look.brand}": "${look.shown}" reads as "${look.reads}".` });
  else if (look.impersonation) out.reasons.push({ w: 4, t: `Brand "${look.brand}" appears in a subdomain but the registered domain is "${reg}".` });
  else if (look.inName) out.reasons.push({ w: 2, t: `The domain "${reg}" has the brand name "${look.brand}" in it but is a different domain from the brand's own; check who owns it.` });
  else if (look.oddTld) out.reasons.push({ w: 3, t: `"${reg}" uses the brand name "${look.brand}" on .${look.oddTld}, which is not where that brand's sites live (they use .com or a country domain); check who owns it.` });
  else if (look.near) out.reasons.push({ w: 3, t: `Domain stem "${look.stem}" is a near-miss (edit distance ${look.distance}) of brand "${look.brand}".` });

  out.severity = sevFromWeight(sumWeight(out.reasons));
  out.lookalike = look;
  return out;
}

function sumWeight(reasons) { return reasons.reduce((a, r) => a + r.w, 0); }
function sevFromWeight(w) { return w >= 7 ? "critical" : w >= 4 ? "high" : w >= 2 ? "medium" : w >= 1 ? "low" : "info"; }

// Lookalike detection against the brand list.
export function lookalike(host) {
  host = String(host || "").toLowerCase();
  // homograph: judge the name the way it is displayed (аpple.com reads as apple.com)
  const shown = toUnicodeHost(host), reads = skeleton(shown);
  if (reads !== host && /^[\x00-\x7f]+$/.test(reads)) {
    const l = asciiLookalike(reads);
    if (l.brand) return { ...l, exact: false, near: !l.impersonation, distance: l.distance || 0, stem: registrableDomain(host).split(".")[0], homograph: true, shown, reads };
  }
  return asciiLookalike(host);
}

function asciiLookalike(host) {
  const labels = host.split(".");
  const reg = registrableDomain(host);
  const stem = reg.split(".")[0] || "";
  // a brand's own domain (outlook.office365.com) is not impersonating anyone
  // ...but only on .com/.net/.org or a country domain (amazon.co.uk, paypal.me): the bare brand on a new
  // generic TLD (apple.support, microsoft.online, paypal.xyz) is a standard phishing registration
  if (BRANDS.includes(stem)) {
    const suf = reg.slice(stem.length + 1);
    if (suf && !/^(com|net|org|[a-z]{2}|[a-z]{2,4}\.[a-z]{2})$/.test(suf)) return { brand: stem, stem, impersonation: false, near: true, oddTld: suf, distance: 0, exact: false };
    return { brand: stem, stem, impersonation: false, near: false, distance: 0, exact: true };
  }
  // impersonation: a brand is a subdomain label, a hyphen-part of one (digits swapped
  // back to letters), or brand + account word (microsoftonline, appleid), but the
  // registered domain is not the brand's
  const sub = labels.slice(0, -reg.split(".").length);
  const isBrand = (t, b) => t === b || leetIs(t, b) || (t.startsWith(b) && ACCOUNT_WORD.test(t.slice(b.length)));
  for (const b of BRANDS) {
    if (labels.includes(b) || sub.some((l) => l.split("-").some((t) => isBrand(t, b))))
      return { brand: b, stem, impersonation: true, near: false, distance: 0 };
  }
  // near-miss typosquat on the stem
  let best = null;
  for (const b of BRANDS) {
    // Near-miss only for brands of 5+ chars: a 1-2 edit distance on a 3-4 char brand
    // (ups, att, amex, hsbc) matches ordinary short domains (us.com, art.com, apex.com)
    // and floods false "lookalike" verdicts. Short brands are still caught by the
    // exact-label impersonation check above.
    const d = levenshtein(stem, b);
    if (b.length >= 5 && d > 0 && d <= 2 && Math.abs(stem.length - b.length) <= 2 && (!best || d < best.distance)) best = { brand: b, stem, distance: d };
  }
  if (best) return { ...best, impersonation: false, near: true };
  // the registered name carries the brand as a hyphen-part (paypal-secure.com, m1crosoft-help.com)
  const part = stem.includes("-") && BRANDS.find((b) => stem.split("-").some((t) => t === b || leetIs(t, b)));
  if (part) return { brand: part, stem, impersonation: false, near: true, inName: true, distance: 0 };
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

// ---- defang / refang ------------------------------------------------------

// Undo the common defanging conventions (hxxp, [.], (.), [:], [@], [at]).
export function refangText(text) {
  return String(text || "")
    .replace(/\bhxxp(s?)/gi, (m, s) => (m[0] === "H" ? "HTTP" : "http") + s)
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, ".")
    .replace(/\[:\/\/\]/g, "://").replace(/\[:\]/g, ":")
    .replace(/\[@\]|\[at\]/gi, "@");
}

// Make every URL, email, IP and domain in the text safe to paste into a ticket or chat:
// http -> hxxp, dots in hosts -> [.], @ -> [@]. Idempotent (already-defanged text is
// refanged first), and the rest of the text is left untouched.
const FILE_EXT = /\.(png|jpg|jpeg|gif|svg|css|js|json|html?|webp|txt|pdf|docx?|xlsx?|exe|dll|zip)$/i;
export function defangText(text) {
  const dots = (s) => s.replace(/\./g, "[.]");
  return refangText(text).replace(
    /\bhttps?:\/\/[^\s"'<>)\]]+|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi,
    (m) => {
      if (/^https?:\/\//i.test(m)) {
        const i = m.indexOf("://") + 3, rest = m.slice(i), cut = rest.search(/[\/?#]/), host = cut < 0 ? rest : rest.slice(0, cut);
        return m.slice(0, i).replace(/^http/i, (h) => (h[0] === "H" ? "HXXP" : "hxxp")) + dots(host) + (cut < 0 ? "" : rest.slice(cut));
      }
      if (m.includes("@")) { const at = m.indexOf("@"); return m.slice(0, at) + "[@]" + dots(m.slice(at + 1)); }
      if (FILE_EXT.test(m)) return m;
      return dots(m);
    });
}

// Plain-text incident report for a triaged URL or email, with every indicator
// defanged. `t` is the triage summary the UI already shows; `extra` holds the
// analyst's optional "actions taken" and "notes".
export function buildTriageReport(t, extra = {}) {
  const L = [], line = "=".repeat(48), d = (s) => defangText(String(s == null || s === "" ? "-" : s));
  const sec = (title) => L.push("", "--- " + title.toUpperCase() + " ---");
  L.push(line, "PHISHING TRIAGE REPORT", line, "Generated: " + (t.generated || new Date().toISOString()), "Type: " + (t.mode === "email" ? "Email" : "Link"), "Verdict: " + (t.verdict || "-"));
  if (t.mode === "email") {
    sec("Message");
    L.push("From: " + d(t.from), "From domain: " + d(t.fromReg) + (t.age ? " (" + t.age + ")" : ""), "Return-Path: " + d(t.returnPath), "Reply-To: " + d(t.replyTo), "Subject: " + (t.subject || "-"));
    if (t.auth) L.push("Authentication: SPF " + (t.auth.spf || "none") + ", DKIM " + (t.auth.dkim || "none") + ", DMARC " + (t.auth.dmarc || "none"));
    if (t.links && t.links.length) { sec("Links in the message"); t.links.forEach((u) => L.push("[" + (u.severity || "info") + "] " + d(u.input))); }
  } else {
    sec("Link");
    L.push("Target: " + d(t.input), "Host: " + d(t.host), "Registered domain: " + d(t.registrable) + (t.age ? " (" + t.age + ")" : ""), "DNS: " + (t.dns || "-"));
    if (t.chain && t.chain.length) { sec("Redirect chain"); t.chain.forEach((h, i) => L.push((i + 1) + ". " + d(h))); }
  }
  const sig = (t.reasons || []).filter((r) => r.w > 0);
  sec("Signals (" + sig.length + ")");
  if (sig.length) sig.forEach((r) => L.push("- " + defangText(r.t))); else L.push("No suspicious signals detected.");
  const io = t.iocs || {}, kinds = [["URLs", io.urls], ["Domains", io.domains], ["IPs", io.ips], ["Emails", io.emails], ["Hashes", io.hashes]].filter(([, a]) => a && a.length);
  if (kinds.length) { sec("Indicators (defanged)"); kinds.forEach(([k, a]) => { L.push(k + ":"); a.slice(0, 100).forEach((x) => L.push("  " + d(x))); }); }
  sec("Actions taken"); L.push(String(extra.actions || "").trim() || "-");
  sec("Notes"); L.push(String(extra.notes || "").trim() || "-");
  sec("Recommended next steps");
  ["Block the sender domain and listed URLs at the mail gateway and web proxy", "Search mail logs for other recipients of the same message or links", "Contact any user who clicked; reset credentials that were entered", "Preserve the original message (.eml) as evidence"].forEach((s, i) => L.push((i + 1) + ". " + s));
  L.push("", "Risk is inferred from observable signals; it is not a malware verdict.", line);
  return L.join("\n");
}

// ---- email parsing --------------------------------------------------------

// Parse raw RFC822 headers (handles folded continuation lines). Returns a map
// of lowercased header name -> array of values (headers can repeat).
export function parseEmailHeaders(raw) {
  const text = String(raw || "").replace(/\r\n/g, "\n");
  const split = text.indexOf("\n\n");
  const headerBlock = split >= 0 ? text.slice(0, split) : text;
  const body = split >= 0 ? text.slice(split + 2) : "";
  // Null-proto: header names come verbatim from a hostile email, and the name regex
  // accepts "__proto__"/"constructor". A plain object would make headers["__proto__"]
  // resolve to Object.prototype (truthy), so `|| []` is skipped and `.push` throws,
  // crashing the whole triage on a single crafted header.
  const headers = Object.create(null);
  const lines = headerBlock.split("\n");
  let cur = null;
  for (const line of lines) {
    if (/^[ \t]/.test(line) && cur) { cur.v += " " + line.trim(); continue; }
    const m = line.match(/^([!-9;-~]+):\s?(.*)$/);
    if (m) { cur = { k: m[1].toLowerCase(), v: m[2] }; (headers[cur.k] = headers[cur.k] || []).push(cur); }
  }
  const out = Object.create(null);
  for (const k in headers) out[k] = headers[k].map((e) => e.v);
  return { headers: out, body, hasHeaders: !!out["from"] || !!out["received"] || !!out["message-id"] };
}

export function domainOf(addr) {
  // The real address is the <angle-addr>; a display name can itself hold an address
  // ("service@brand.com" <x@attacker.example>), the classic From spoof.
  const s = String(addr || ""), angle = s.match(/<([^<>]*)>\s*$/);
  const m = (angle ? angle[1] : s).match(/@([^\s>"']+)/);
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
  const nameLc = name.toLowerCase();
  // Whole-word match, not substring: "att" must not fire on "matthew", "ups" on "groups".
  const brandInName = BRANDS.find((b) => new RegExp("\\b" + b.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b").test(nameLc));
  // The domain legitimately belongs to the brand only when its registrable STEM equals the
  // brand. A substring test (`fromReg.includes`) wrongly cleared attacker.com / myamexclone.com.
  const fromStem = (fromReg || "").split(".")[0];
  if (brandInName && fromReg && fromStem !== brandInName) add(4, `Display name mentions "${brandInName}" but the sending domain is ${fromReg || "unknown"}.`);
  const fromLook = fromReg ? lookalike(fromDomain) : { near: false, impersonation: false };
  if (fromLook.impersonation) add(4, `From domain impersonates brand "${fromLook.brand}" in a subdomain.`);
  else if (fromLook.homograph) add(4, `From domain imitates brand "${fromLook.brand}": "${fromLook.shown}" reads as "${fromLook.reads}".`);
  else if (fromLook.inName) add(3, `From domain ${fromReg} has the brand name "${fromLook.brand}" in it but is a different domain from the brand's own.`);
  else if (fromLook.oddTld) add(3, `From domain ${fromReg} uses the brand name "${fromLook.brand}" on .${fromLook.oddTld}, not the brand's own domain.`);
  else if (fromLook.near) add(3, `From domain is a near-miss of brand "${fromLook.brand}".`);
  // replies going to a brand lookalike is the classic BEC / credential-reset setup
  const replyLook = replyTo && registrableDomain(replyTo) !== fromReg ? lookalike(replyTo) : null;
  if (replyLook && (replyLook.impersonation || replyLook.near)) add(3, `Reply-To domain (${replyTo}) imitates brand "${replyLook.brand}".`);

  // body URLs
  const iocs = extractIOCs(body || raw);
  const urlAnalyses = iocs.urls.slice(0, 25).map(analyzeUrl);
  const riskyUrls = urlAnalyses.filter((u) => u.severity === "high" || u.severity === "critical");
  for (const ru of riskyUrls.slice(0, 5)) { const top = ru.reasons.slice().sort((a, b) => b.w - a.w)[0]; add(3, `Risky link: ${ru.host} (${top ? top.t : "suspicious"})`); }
  // From-domain mismatch vs links
  const linkRegs = Array.from(new Set(urlAnalyses.map((u) => u.registrable).filter(Boolean)));
  if (fromReg && linkRegs.length && !linkRegs.includes(fromReg) && brandInName) add(2, "None of the links point to the brand's own domain.");

  const weight = findings.reduce((a, f) => a + Math.max(0, f.w), 0);
  // A domain can pass its OWN DMARC and still be a spoof: a lookalike / typosquat /
  // homograph signal must veto the "likely legitimate" DMARC-pass shortcut, even when
  // the signal's own weight is too low (e.g. a medium-severity link) to lift the score.
  const spoof =
    fromLook.impersonation || fromLook.near || !!(replyLook && (replyLook.impersonation || replyLook.near)) ||
    !!(brandInName && fromReg && !fromReg.includes(brandInName)) ||
    urlAnalyses.some((u) => u.lookalike && (u.lookalike.impersonation || u.lookalike.near) && u.lookalike.brand !== fromStem) || // a brand mailing its own amazon-adsystem.com is not a spoof
    urlAnalyses.some((u) => (u.reasons || []).some((r) => /homograph|Punycode|Non-ASCII/.test(r.t)));
  const verdict = verdictFromWeight(weight, auth, spoof);
  // On a high-risk message the misaligned Reply-To / Return-Path domains are the attacker's
  // too; on anything milder they are usually a mail provider and must not be blocked.
  if (verdict.level === "high-risk") for (const d of [replyTo, returnPath]) {
    const r = d && registrableDomain(d);
    if (r && r !== fromReg && !iocs.domains.includes(r)) iocs.domains.push(r);
  }
  return {
    mode: "email",
    from, fromDomain, fromReg, returnPath, replyTo, name, auth,
    subject: get("subject"), messageId: get("message-id"),
    iocs, urlAnalyses, spoof,
    findings: findings.sort((a, b) => b.w - a.w),
    verdict,
  };
}

export function verdictFromWeight(weight, auth, spoof) {
  if (!spoof && auth && auth.dmarc === "pass" && weight < 3) return { level: "likely-legitimate", label: "Likely legitimate", c: "#2f9e56" };
  if (weight >= 8) return { level: "high-risk", label: "High risk — likely phishing", c: "#b00020" };
  if (weight >= 4) return { level: "suspicious", label: "Suspicious", c: "#d9480f" };
  if (weight >= 2) return { level: "caution", label: "Treat with caution", c: "#b58100" };
  if (spoof) return { level: "caution", label: "Treat with caution — lookalike domain", c: "#b58100" };
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
  verdictFromWeight, BRANDS, RISKY_TLDS, selfTest, defangText, refangText, buildTriageReport,
};
