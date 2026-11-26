// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Domain check: a fast, real external check of one domain, run from the browser. The
// landing hero, the shareable /check/<domain> page and the Deck's first-run block all
// run it. It reuses the engines the Deck tools already use:
//   email-auth.js          SPF, DMARC and DKIM analysis (the Email Security tool)
//   posture-engine.js      HSTS and security-header grading (the External Posture tool)
//   domainguard-engine.js  DoH answer parsing, CAA records, registrable domain
//   security-txt.js        RFC 9116 validation (the security.txt tool)
//   ct-fetch.js            certificate-transparency rows (crt.sh, Cert Spotter fallback)
// DNS goes straight to public DNS-over-HTTPS (Cloudflare, then Google). Web requests go
// through the Darknode fetch proxy (net.js dnFetch), which reads public responses only.
//
// The grade is transparent: every check has a fixed weight (CHECKS, 100 in total) and
// earns all of it on a pass, half on a warn and none on a fail. A check whose source
// could not be read is "error": it is listed and left out of the grade, never counted
// as a pass or a zero. A check that cannot apply (the domain has no website) is "na"
// and is also left out. Below half of the applicable weight graded, the grade is N/A.
// The pure parts (evaluate, gradeChecks, domainCheckFindings) are unit-tested in
// test/check/domain-check.test.mjs with the network injected.

import { analyzeSPF, analyzeDMARC, analyzeDKIM, DEFAULT_SELECTORS } from "../email-auth.js?v=1";
import { gradeTransport, gradeHeaders, letterGrade, newestCert, certDaysLeft } from "../dataprotect/posture-engine.js?v=1";
import { dohStatus, rrData, txtStrings, parseCaaData, parseMx, registrableDomain, toAsciiDomain, isDomainName } from "../exposure/domainguard-engine.js?v=1";
import { validateSecurityTxt } from "../security-txt.js?v=1";

export const GROUPS = [
  { id: "email", label: "Email authentication" },
  { id: "https", label: "HTTPS" },
  { id: "headers", label: "Security headers" },
  { id: "dns", label: "DNS hardening" },
  { id: "disclosure", label: "Vulnerability disclosure" },
];
const GROUP_LABEL = Object.fromEntries(GROUPS.map((g) => [g.id, g.label]));

// id -> weight (points out of 100) and the free Deck tool that digs into it.
export const CHECKS = [
  { id: "spf", group: "email", label: "SPF", weight: 10, tool: "emailauth" },
  { id: "dmarc", group: "email", label: "DMARC policy", weight: 12, tool: "emailauth" },
  { id: "dkim", group: "email", label: "DKIM", weight: 6, tool: "emailauth" },
  { id: "mx", group: "email", label: "Mail servers (MX)", weight: 4, tool: "dns" },
  { id: "https", group: "https", label: "HTTPS", weight: 10, tool: "headeranalyzer" },
  { id: "redirect", group: "https", label: "HTTP to HTTPS redirect", weight: 7, tool: "headeranalyzer" },
  { id: "cert", group: "https", label: "Certificate expiry", weight: 6, tool: "sslinspector" },
  { id: "hsts", group: "headers", label: "HSTS", weight: 8, tool: "headeranalyzer" },
  { id: "csp", group: "headers", label: "Content-Security-Policy", weight: 7, tool: "headeranalyzer" },
  { id: "frame", group: "headers", label: "Frame protection", weight: 4, tool: "headeranalyzer" },
  { id: "nosniff", group: "headers", label: "X-Content-Type-Options", weight: 4, tool: "headeranalyzer" },
  { id: "referrer", group: "headers", label: "Referrer-Policy", weight: 2, tool: "headeranalyzer" },
  { id: "dnssec", group: "dns", label: "DNSSEC", weight: 7, tool: "dns" },
  { id: "caa", group: "dns", label: "CAA records", weight: 7, tool: "dns" },
  { id: "securitytxt", group: "disclosure", label: "security.txt", weight: 6, tool: "securitytxt" },
];

// Share of a check's weight each status earns. error / na / pending are not graded.
export const CREDIT = { pass: 1, warn: 0.5, fail: 0 };

// ---- input -------------------------------------------------------------------------

// What people paste (a URL, you@domain, mailto:, a port, www.) -> a bare ASCII domain,
// or "" when it is not a domain name (an IP address, a single label, junk).
export function normalizeDomain(raw) {
  let d = String(raw == null ? "" : raw).trim().toLowerCase();
  d = d.replace(/^mailto:/, "").replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/[/?#].*$/, "").replace(/^.*@/, "")
    .replace(/\.+$/, "").replace(/:\d+$/, "").replace(/\.+$/, "").replace(/^www\./, "");
  if (/[^\x00-\x7f]/.test(d)) d = toAsciiDomain(d);
  return isDomainName(d) ? d : "";
}

// Free and consumer mail providers: their domain is not the user's company, so the Deck
// does not offer it as "your domain".
const FREE_MAIL = new Set(("gmail.com googlemail.com outlook.com hotmail.com live.com msn.com passport.com yahoo.com ymail.com rocketmail.com "
  + "aol.com aim.com icloud.com me.com mac.com proton.me protonmail.com protonmail.ch pm.me tuta.io tutanota.com tutanota.de tutamail.com "
  + "keemail.me gmx.com gmx.net gmx.de gmx.at gmx.ch web.de mail.com email.com yandex.com yandex.ru ya.ru mail.ru inbox.ru list.ru bk.ru "
  + "zoho.com zohomail.com fastmail.com fastmail.fm hey.com duck.com mailbox.org posteo.de posteo.net hushmail.com lycos.com inbox.com "
  + "qq.com 163.com 126.com yeah.net sina.com sohu.com aliyun.com naver.com daum.net hanmail.net rediffmail.com libero.it virgilio.it "
  + "orange.fr wanadoo.fr free.fr laposte.net sfr.fr t-online.de freenet.de seznam.cz wp.pl o2.pl interia.pl onet.pl btinternet.com "
  + "sky.com virginmedia.com talktalk.net comcast.net verizon.net att.net sbcglobal.net bellsouth.net cox.net charter.net earthlink.net "
  + "juno.com optonline.net rogers.com shaw.ca sympatico.ca bigpond.com optusnet.com.au xtra.co.nz rambler.ru ukr.net abv.bg").split(" "));
const FREE_MAIL_FAMILY = /^(yahoo|hotmail|outlook|live|gmx|yandex|aol|msn)\.[a-z]{2,3}(\.[a-z]{2})?$/;
const RESERVED = /(^|\.)(example\.(com|net|org)|test|example|invalid|localhost|local|internal|lan|home\.arpa)$/;

export function isFreeMail(domain) {
  const d = String(domain || "").toLowerCase();
  return FREE_MAIL.has(d) || FREE_MAIL_FAMILY.test(d);
}

// The sign-up email's domain when it is a company domain worth offering, else "".
export function workDomainFromEmail(email) {
  const m = /@([^@\s]+)$/.exec(String(email || "").trim().toLowerCase());
  if (!m) return "";
  const d = normalizeDomain(m[1]);
  return d && !isFreeMail(d) && !RESERVED.test(d) ? d : "";
}

// ---- transport -----------------------------------------------------------------------

const RESOLVERS = [
  (n, t, cd) => "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(n) + "&type=" + t + (cd ? "&cd=1" : ""),
  (n, t, cd) => "https://dns.google/resolve?name=" + encodeURIComponent(n) + "&type=" + t + (cd ? "&cd=1" : ""),
];

async function getDnsJson(url, ms) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, { headers: { Accept: "application/dns-json" }, signal: ctrl.signal });
    if (!r.ok) throw new Error("HTTP " + r.status);
    return await r.json();
  } finally { clearTimeout(timer); }
}

// One DoH JSON answer ({ Status, AD, Answer }). SERVFAIL / REFUSED are asked of the other
// resolver too; only when neither resolver answers at all does this throw.
export async function dohJSON(name, type, { cd = false } = {}) {
  let failed = null, firstErr = null;
  for (const url of RESOLVERS) {
    try {
      const j = await getDnsJson(url(name, type, cd), 8000);
      if (j && (j.Status === 2 || j.Status === 5)) { failed = j; continue; }
      return j;
    } catch (e) { firstErr = firstErr || e; }
  }
  if (failed) return failed;
  throw new Error("neither public DNS resolver answered" + (firstErr && firstErr.message ? " (" + firstErr.message + ")" : ""));
}

async function defaultFetch(url, opts) {
  const { dnFetch } = await import("/js/net.js");
  return dnFetch(url, opts);
}

// Certificate-transparency rows covering a host (ct-fetch.js: crt.sh, then Cert Spotter), capped
// so a slow log never holds the whole check: past the cap the check is "error", not graded.
export const CERT_TIMEOUT_MS = 15000;
async function defaultCertRows(host) {
  const { fetchCertRows } = await import("/js/dataprotect/ct-fetch.js?v=20261029e");
  return fetchCertRows(host);
}
function withTimeout(p, ms, why) {
  let t;
  return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(why)), ms); })]).finally(() => clearTimeout(t));
}

const msgOf = (e) => String((e && e.message) || e || "unknown error").replace(/\.+$/, "");

// A failure of the proxy itself (or the site refusing the proxy) says nothing about the
// site: that check is "error". Anything else (refused connection, TLS failure, timeout,
// a name that does not resolve) is the site not answering.
const PROXY_ERROR = /darknode proxy|proxy returned|proxy is not configured|proxy size limit|rate limit|origin not allowed|non-public or reserved host|firewall blocked the request|rate-limited the request/i;
export const isProxyError = (e) => PROXY_ERROR.test(msgOf(e));

const settle = (p) => Promise.resolve(p).then((value) => ({ value }), (e) => ({ error: msgOf(e) }));
const settleWeb = (p) => Promise.resolve(p).then((value) => ({ value }), (e) => (isProxyError(e) ? { error: msgOf(e) } : { siteError: msgOf(e) }));

// ---- evaluation (pure) ------------------------------------------------------------------

const PENDING = Object.freeze({ status: "pending", detail: "Checking", fix: "" });
const clip = (s, n) => { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };
const err = (what, why) => ({ status: "error", detail: "Could not read " + what + ": " + why + ".", fix: "" });
const na = (detail) => ({ status: "na", detail, fix: "" });

// a settled DoH lookup -> { j } (an answer, NXDOMAIN included) | { err } | null (still pending)
function dnsRes(r) {
  if (!r) return null;
  if (r.error) return { err: r.error };
  const st = dohStatus(r.value);
  if (st === "ok" || st === "nxdomain") return { j: r.value };
  return { err: "the resolver returned " + st.toUpperCase() };
}

const STATUS = { PASS: "pass", WARN: "warn", FAIL: "fail" };
// A CT timestamp in ms: crt.sh writes zoneless ISO ("2026-01-14T23:59:59"), which is UTC.
const ctTime = (s) => { s = String(s || ""); return Date.parse(/^\d{4}-\d\d-\d\d[T ]\d\d:\d\d(:\d\d(\.\d+)?)?$/.test(s) ? s.replace(" ", "T") + "Z" : s); };
// The fix for a problem email-auth.js reports in a record that exists, keyed on its wording.
const SPF_FIXES = [
  [/SPF records \(v=spf1\) are published/, "Merge them into a single v=spf1 record."],
  [/\+all/, "Replace +all with -all now: +all lets any server on the internet send as this domain."],
  [/10 DNS-lookup|stop at 10/, "Bring the record under 10 DNS lookups: drop include: entries for services you no longer use, or flatten them."],
  [/~all/, "Once every service that sends your mail is listed, change ~all to -all so mail from unlisted servers is rejected."],
  [/\?all/, "Replace ?all with ~all, then -all, so mail from unlisted servers is rejected."],
  [/No explicit 'all'/, "End the record with -all (or ~all while you confirm every sender is listed)."],
  [/'ptr'/, "Remove the ptr mechanism and list sending hosts with ip4:, ip6: or include: instead."],
];
const DMARC_FIXES = [
  [/DMARC records are published/, "Keep exactly one DMARC record at _dmarc."],
  [/missing or invalid 'p='/, "Add a policy tag to the record: p=quarantine or p=reject."],
  [/p=none/, "Read the aggregate (rua) reports, then move to p=quarantine and later p=reject once legitimate mail passes."],
  [/p=quarantine/, "Move to p=reject once your DMARC reports show legitimate mail passing."],
  [/pct=/, "Remove pct= (or set pct=100) so the policy covers all mail."],
  [/No rua= tag/, "Add rua=mailto:<a mailbox you read> to the record to receive daily aggregate reports."],
];
// An email-auth.js analysis -> a check row: its first problem as the detail and the fix for
// that problem; `missingFix` only when there is no record at all.
function fromAnalysis(a, passDetail, missingFix, fixes) {
  const status = STATUS[a.status] || "warn";
  const bad = (a.findings || []).find((f) => f.kind === "bad") || (a.findings || []).find((f) => f.kind === "warn");
  if (status === "pass") return { status, detail: passDetail, fix: "" };
  const known = bad && (fixes || []).find(([re]) => re.test(bad.text));
  const fix = !a.record ? missingFix : known ? known[1] : "Correct the record as described, then run the check again.";
  return { status, detail: bad ? bad.text : passDetail, fix };
}

// Where the web checks read headers from: the HTTPS answer, else the plain-HTTP one.
function headerSource(o) {
  const web = webGate(o);
  if (web) return web;
  const s = o.https, h = o.http;
  if (!s) return PENDING;
  if (s.value) return { headers: s.value.headers || {}, code: s.value.status | 0, secure: !/^http:/i.test(s.value.finalUrl || s.value.url || "") };
  if (s.error) return err("the site over HTTPS", s.error);
  if (!h) return PENDING;
  if (h.value) return { headers: h.value.headers || {}, code: h.value.status | 0, secure: /^https:/i.test(h.value.finalUrl || h.value.url || "") };
  if (h.error) return err("the site over HTTP", h.error);
  return na("The site answers neither HTTPS nor HTTP, so there are no headers to read.");
}

function webGate(o) {
  if (!o.web || o.web === "pending") return PENDING;
  if (o.web === "none") return na(`No website: ${o.domain} and www.${o.domain} have no A or AAAA record.`);
  if (o.web === "error") return err("the address records", o.webErr || "the lookup failed");
  return null;
}

function fromEngine(src, name, pick) {
  if (src.status) return src; // pending / error / na
  const c = pick(src).checks.find((x) => x.name === name);
  if (!c) return err("the headers", "the grader returned no result");
  const note = src.code >= 400 ? ` Graded from an HTTP ${src.code} response.` : "";
  return { status: c.status, detail: c.detail + note, fix: c.advice || "" };
}

const EVAL = {
  spf(o) {
    const r = dnsRes(o.txt);
    if (!r) return PENDING;
    if (r.err) return err("the TXT records", r.err);
    const a = analyzeSPF(txtStrings(r.j));
    return fromAnalysis(a, "Published: " + clip(a.record, 140), "Publish one TXT record at the domain root, such as v=spf1 include:<your mail provider> -all", SPF_FIXES);
  },
  dmarc(o) {
    if (!o.dmarc) return PENDING;
    if (o.dmarc.error) return err("the DMARC record", o.dmarc.error);
    const { txts, from } = o.dmarc.value;
    const a = analyzeDMARC(txts);
    const inherited = from && from !== o.domain ? ` (inherited from ${from})` : "";
    const pol = (/\bp\s*=\s*(\w+)/i.exec(a.record || "") || [])[1];
    const r = fromAnalysis(a, "Enforced: p=" + (pol || "reject") + inherited + ".", `Publish a TXT record at _dmarc.${o.domain}, such as v=DMARC1; p=none; rua=mailto:<a mailbox you read>. Read the reports, then move to p=quarantine and p=reject.`, DMARC_FIXES);
    if (r.status !== "pass" && inherited) r.detail = r.detail.replace(/\.?$/, "") + inherited + ".";
    return r;
  },
  dkim(o) {
    if (!o.dkim) return PENDING;
    if (o.dkim.error) return err("the DKIM selectors", o.dkim.error);
    const list = o.dkim.value || [];
    // a domain whose SPF authorises no sender at all sends no mail, so it signs nothing
    const t = dnsRes(o.txt);
    if (!t) return PENDING;
    const spf = t.j ? txtStrings(t.j).find((x) => /^v=spf1(\s|$)/i.test(x.trim())) : "";
    if (spf && /^v=spf1\s+-all$/i.test(spf.trim())) return na("The domain sends no mail (its SPF is v=spf1 -all), so it needs no DKIM key.");
    if (list.length && list.every((x) => x.error)) return err("the DKIM selectors", "every selector lookup failed");
    const a = analyzeDKIM(list);
    if (a.status === "NOT FOUND") {
      return { status: "warn", detail: `No DKIM key at any of the ${list.length} common selectors tried. A custom selector would not show here, so this is a warning, not a fail.`, fix: "Turn on DKIM signing in your mail provider and publish the key it gives you. If signing is already on, look up the s= selector in a signed message's DKIM-Signature header." };
    }
    const hit = (a.records || [])[0];
    return fromAnalysis(a, `Key published at selector ${hit ? hit.selector : "?"}${a.records.length > 1 ? ` (+${a.records.length - 1} more)` : ""}.`, "Publish a working DKIM key and remove test mode (t=y) or revoked keys.");
  },
  mx(o) {
    const r = dnsRes(o.mx);
    if (!r) return PENDING;
    if (r.err) return err("the MX records", r.err);
    const hosts = parseMx(r.j);
    if (hosts.length === 1 && !hosts[0].host) return { status: "pass", detail: "Null MX (RFC 7505): the domain declares it accepts no mail.", fix: "" };
    const real = hosts.filter((h) => h.host);
    if (real.length) return { status: "pass", detail: `${real.length} mail server${real.length === 1 ? "" : "s"}: ${real.slice(0, 3).map((h) => h.host).join(", ")}${real.length > 3 ? ", …" : ""}.`, fix: "" };
    return { status: "warn", detail: "No MX record. Mail sent to this domain falls back to its address record or bounces.", fix: "Publish MX records for your mail provider, or a null MX (MX 0 .) if the domain takes no mail." };
  },
  https(o) {
    const g = webGate(o);
    if (g) return g;
    const s = o.https;
    if (!s) return PENDING;
    if (s.error) return err("the site over HTTPS", s.error);
    const fix = "Serve the site over TLS with a valid certificate, then redirect HTTP to HTTPS.";
    if (s.siteError) return { status: "fail", detail: `No HTTPS answer from ${o.webHost}: ${s.siteError}.`, fix };
    const code = s.value.status | 0, fin = s.value.finalUrl || s.value.url || "";
    if (code === 525 || code === 526) return { status: "fail", detail: `The TLS handshake failed (HTTP ${code}${code === 526 ? ", invalid certificate" : ""}).`, fix };
    if (/^http:/i.test(fin)) return { status: "warn", detail: `HTTPS answers but sends visitors to plain HTTP (${clip(fin, 80)}).`, fix: "Keep visitors on HTTPS: remove the redirect to http://." };
    return { status: "pass", detail: `${o.webHost} answers over HTTPS${code ? " (HTTP " + code + ")" : ""}.`, fix: "" };
  },
  redirect(o) {
    const g = webGate(o);
    if (g) return g;
    const s = o.https, h = o.http;
    if (!s || !h) return PENDING;
    if (h.error) return err("the site over HTTP", h.error);
    if (h.siteError) {
      if (s.value) return { status: "pass", detail: "Plain HTTP (port 80) does not answer, so nothing is served unencrypted.", fix: "" };
      if (s.error) return err("the site over HTTPS", s.error);
      return na("The site answers neither HTTP nor HTTPS.");
    }
    const fin = h.value.finalUrl || h.value.url || "";
    if (/^https:/i.test(fin)) return { status: "pass", detail: `http:// redirects to ${clip(fin.replace(/^(https:\/\/[^/]+).*$/i, "$1"), 80)}.`, fix: "" };
    return { status: "fail", detail: `http:// serves the site without moving to HTTPS (HTTP ${h.value.status | 0}).`, fix: "Answer every http:// request with a 301 redirect to the same path on https://." };
  },
  cert(o) {
    const g = webGate(o);
    if (g) return g;
    const r = o.cert;
    if (!r) return PENDING;
    if (r.error) return err("the certificate logs", r.error);
    const rows = r.value || [];
    if (rows.unreachable) return err("the certificate logs", "neither crt.sh nor Cert Spotter answered");
    const now = o.now || Date.now();
    const c = newestCert(rows, now);
    const days = c ? certDaysLeft(c.notAfter, now) : null;
    // nothing logged says nothing certain (a private CA, or a name the logs file differently)
    if (days == null) return err("the certificate logs", `no certificate for ${o.webHost} is logged`);
    const tAfter = ctTime(c.notAfter), tBefore = ctTime(c.notBefore);
    const until = isNaN(tAfter) ? String(c.notAfter).slice(0, 10) : new Date(tAfter).toISOString().slice(0, 10);
    const by = c.issuer ? ` (${clip(String(c.issuer).replace(/^.*\bO=("?)([^,"]+)\1.*$/, "$2"), 50)})` : "";
    const fix = "Renew the certificate now, and check that automatic renewal (your ACME client or host's setting) is running.";
    if (days < 0) return { status: "fail", detail: `The newest logged certificate for ${o.webHost}${by} expired on ${until}.`, fix };
    // bands follow the certificate's own lifetime, so 90-day and short-lived certificates renewing on schedule are not flagged
    const life = isNaN(tAfter) || isNaN(tBefore) ? null : (tAfter - tBefore) / 86400000;
    const lifeDays = life && life > 0 ? life : 90;
    const left = days === 0 ? "less than a day" : days === 1 ? "1 day" : days + " days";
    if (days < Math.min(7, lifeDays * 0.1)) return { status: "fail", detail: `The newest logged certificate for ${o.webHost}${by} expires in ${left}, on ${until}.`, fix };
    if (days < Math.min(21, lifeDays * 0.25)) return { status: "warn", detail: `The newest logged certificate for ${o.webHost}${by} expires in ${left}, on ${until}, later than renewal usually happens.`, fix: "Renew the certificate before then, and check that automatic renewal (your ACME client or host's setting) is running." };
    return { status: "pass", detail: `The newest logged certificate for ${o.webHost}${by} is valid until ${until} (${left}).`, fix: "" };
  },
  hsts(o) {
    const src = headerSource(o);
    if (!src.status && !src.secure) return { status: "fail", detail: "The site was only reachable over plain HTTP, and browsers ignore HSTS there.", fix: "Serve the site over HTTPS and send Strict-Transport-Security with max-age of at least 15552000." };
    return fromEngine(src, "HSTS", (x) => gradeTransport({ headers: x.headers, httpsOk: true, httpTested: false }));
  },
  csp: (o) => fromEngine(headerSource(o), "Content-Security-Policy", (x) => gradeHeaders({ headers: x.headers })),
  frame: (o) => fromEngine(headerSource(o), "Clickjacking protection", (x) => gradeHeaders({ headers: x.headers })),
  nosniff: (o) => fromEngine(headerSource(o), "X-Content-Type-Options", (x) => gradeHeaders({ headers: x.headers })),
  referrer: (o) => fromEngine(headerSource(o), "Referrer-Policy", (x) => gradeHeaders({ headers: x.headers })),
  dnssec(o) {
    const a = o.a;
    if (!a) return PENDING;
    if (a.error) return err("the address record", a.error);
    const st = dohStatus(a.value);
    if (st === "servfail") {
      if (!o.bogus) return PENDING;
      if (o.bogus.value && dohStatus(o.bogus.value) === "ok") return { status: "fail", detail: "Validating resolvers refuse to answer, yet the answer comes back with validation off: the DNSSEC signatures are broken.", fix: "Re-sign the zone, or remove the stale DS record at your registrar." };
      return err("the address record", "the resolver returned SERVFAIL");
    }
    if (st !== "ok" && st !== "nxdomain") return err("the address record", "the resolver returned " + st.toUpperCase());
    if (a.value.AD === true) return { status: "pass", detail: "Signed and validated: the resolver set the AD (authenticated data) flag.", fix: "" };
    const d = dnsRes(o.ds);
    if (!d) return PENDING;
    if (d.err) return err(`the DS record at ${o.org}`, d.err);
    if (rrData(d.j, "DS").length) return { status: "warn", detail: `${o.org} publishes a DS record, but this answer did not validate.`, fix: "Check that the zone's DNSKEY matches the DS record at your registrar." };
    return { status: "warn", detail: `Not signed: ${o.org} has no DS record, so DNS answers cannot be authenticated.`, fix: "Turn on DNSSEC at your DNS host, then add the DS record it gives you at your registrar." };
  },
  caa(o) {
    if (!o.caa) return PENDING;
    if (o.caa.error) return err("the CAA records", o.caa.error);
    const { at, recs } = o.caa.value;
    const fix = 'Publish a CAA record naming the certificate authority you use: 0 issue "<your CA\'s domain>".';
    if (!recs.length) return { status: "warn", detail: "No CAA record: any certificate authority may issue certificates for this domain.", fix };
    const issue = recs.filter((r) => r.tag === "issue" || r.tag === "issuewild");
    if (!issue.length) return { status: "warn", detail: `The CAA record at ${at} has no issue tag, so it does not limit which CA may issue.`, fix };
    const cas = [...new Set(issue.map((r) => r.value.split(";")[0].trim() || "none (issuance blocked)"))];
    return { status: "pass", detail: `CAA at ${at} allows: ${clip(cas.join(", "), 120)}.`, fix: "" };
  },
  securitytxt(o) {
    const g = webGate(o);
    if (g) return g;
    const r = o.stxt;
    if (!r) return PENDING;
    if (r.error) return err("security.txt", r.error);
    const fix = "Publish /.well-known/security.txt over HTTPS with Contact: and Expires: fields (RFC 9116).";
    const v = r.value;
    if (!v.found) return { status: "warn", detail: "No security.txt at /.well-known/security.txt, so researchers have no published way to report a vulnerability.", fix };
    const res = validateSecurityTxt(v.body);
    const bad = res.findings.find((f) => f.level === "error");
    if (!res.ok) return { status: "warn", detail: `Found at ${v.path}, but it is not valid: ${clip(bad ? bad.msg : "it did not parse", 140)}`, fix };
    if (v.path !== "/.well-known/security.txt") return { status: "warn", detail: `Found only at ${v.path}. RFC 9116 places it at /.well-known/security.txt.`, fix: "Serve the same file at /.well-known/security.txt." };
    const contact = res.fields.find((f) => /^contact$/i.test(f.name));
    return { status: "pass", detail: `Valid RFC 9116 file${contact ? ` (Contact: ${clip(contact.value, 60)})` : ""}.`, fix: "" };
  },
};

// All checks for the observations so far: a check whose inputs have not arrived is "pending".
export function evaluate(obs) {
  return CHECKS.map((def) => {
    let r;
    try { r = EVAL[def.id](obs); } catch (e) { r = err("the result", msgOf(e)); }
    return { id: def.id, group: def.group, label: def.label, weight: def.weight, tool: def.tool, status: r.status, detail: r.detail, fix: r.fix || "" };
  });
}

// Weighted grade. Sets points on each graded check (null when it is not graded).
export function gradeChecks(checks) {
  let earned = 0, possible = 0, applicable = 0;
  for (const c of checks) {
    c.points = null;
    if (c.status === "na") continue;
    applicable += c.weight;
    if (!Object.prototype.hasOwnProperty.call(CREDIT, c.status)) continue;
    c.points = c.weight * CREDIT[c.status];
    possible += c.weight;
    earned += c.points;
  }
  const covered = applicable > 0 && possible / applicable >= 0.5;
  const score = covered ? Math.round((100 * earned) / possible) : null;
  return { score, grade: covered ? letterGrade(score) : "N/A", earned, possible, applicable };
}

export function summarize(checks) {
  const n = { pass: 0, warn: 0, fail: 0, error: 0, na: 0, pending: 0 };
  for (const c of checks) n[c.status] = (n[c.status] || 0) + 1;
  return n;
}

// ---- collection ----------------------------------------------------------------------------

async function lookupDmarc(doh, domain, org) {
  const has = (txts) => txts.some((t) => /^v\s*=\s*dmarc1\b/i.test(String(t).trim()));
  const read = async (name) => {
    const j = await doh("_dmarc." + name, "TXT");
    const st = dohStatus(j);
    if (st !== "ok" && st !== "nxdomain") throw new Error("the resolver returned " + st.toUpperCase());
    return txtStrings(j);
  };
  const own = await read(domain);
  if (has(own) || org === domain) return { txts: own, from: domain };
  const parent = await read(org); // RFC 7489 6.6.3: the organizational domain's policy covers subdomains
  return has(parent) ? { txts: parent, from: org } : { txts: own, from: domain };
}

async function probeDkim(doh, domain) {
  return Promise.all(DEFAULT_SELECTORS.map(async (selector) => {
    try {
      const j = await doh(selector + "._domainkey." + domain, "TXT");
      const st = dohStatus(j);
      if (st !== "ok" && st !== "nxdomain") return { selector, found: false, record: null, error: st };
      const rec = txtStrings(j).find((t) => /(^|;)\s*(v=DKIM1|k=|p=)/i.test(t));
      return { selector, found: !!rec, record: rec || null };
    } catch (e) { return { selector, found: false, record: null, error: msgOf(e) }; }
  }));
}

// CAA applies from the name itself up to the registrable domain (RFC 8659 3): the first
// name that has a CAA set decides.
async function findCaa(doh, domain, org) {
  const names = [];
  for (let n = domain; n; n = n.slice(n.indexOf(".") + 1)) { names.push(n); if (n === org || n.indexOf(".") < 0) break; }
  for (const n of names) {
    const j = await doh(n, "CAA");
    const st = dohStatus(j);
    if (st !== "ok" && st !== "nxdomain") throw new Error("the resolver returned " + st.toUpperCase());
    const recs = rrData(j, "CAA").map(parseCaaData).filter(Boolean);
    if (recs.length) return { at: n, recs };
  }
  return { at: null, recs: [] };
}

async function fetchSecurityTxt(fetchUrl, host) {
  for (const path of ["/.well-known/security.txt", "/security.txt"]) {
    let r;
    try { r = await fetchUrl("https://" + host + path, { raw: true, max: 32768, timeout: 12000 }); }
    catch (e) { if (isProxyError(e)) throw e; return { found: false }; }
    const body = String((r && r.body) || "");
    // a site that answers every path with its HTML app is not publishing security.txt
    if ((r.status | 0) === 200 && !/^\s*</.test(body) && /^\s*(?:-\s+)?contact\s*:/im.test(body)) return { found: true, path, body };
  }
  return { found: false };
}

const hasAddress = (r) => !!(r && r.value && dohStatus(r.value) === "ok" && (rrData(r.value, "A").length || rrData(r.value, "AAAA").length));
const lookupFailed = (r) => !r || !!r.error || !["ok", "nxdomain"].includes(dohStatus(r.value));

/**
 * Run the check. onProgress(result) fires as each source lands, with pending checks.
 * deps: { doh(name, type, {cd}), fetchUrl(url, opts), certRows(host), now } for tests; defaults are live.
 * @returns {Promise<{domain, webHost, grade, score, earned, possible, checks, counts, ranAt}>}
 */
export async function runDomainCheck(input, { onProgress, doh = dohJSON, fetchUrl = defaultFetch, certRows = defaultCertRows, certTimeoutMs = CERT_TIMEOUT_MS, now } = {}) {
  const domain = normalizeDomain(input);
  if (!domain) throw new Error("Enter a domain name, like example.com.");
  const org = registrableDomain(domain);
  const obs = { domain, org, webHost: domain, web: "pending", now };
  const result = () => {
    const checks = evaluate(obs);
    const g = gradeChecks(checks);
    return { domain, webHost: obs.webHost, grade: g.grade, score: g.score, earned: g.earned, possible: g.possible, checks, counts: summarize(checks), ranAt: Date.now() };
  };
  const emit = () => { if (onProgress) { try { onProgress(result()); } catch (_) {} } };

  const [a, aaaa] = await Promise.all([settle(doh(domain, "A")), settle(doh(domain, "AAAA"))]);
  if (a.value && dohStatus(a.value) === "nxdomain") throw new Error(`${domain} does not exist in public DNS (NXDOMAIN). Check the spelling.`);
  if (a.error && aaaa.error) throw new Error("Public DNS could not be reached (" + a.error + "). Check your connection and try again.");
  obs.a = a;

  const jobs = [];
  const track = (key, p) => jobs.push(p.then((r) => { obs[key] = r; emit(); }));
  if (!a.error && dohStatus(a.value) === "servfail") track("bogus", settle(doh(domain, "A", { cd: true })));
  track("txt", settle(doh(domain, "TXT")));
  track("dmarc", settle(lookupDmarc(doh, domain, org)));
  track("dkim", settle(probeDkim(doh, domain)));
  track("mx", settle(doh(domain, "MX")));
  track("ds", settle(doh(org, "DS")));
  track("caa", settle(findCaa(doh, domain, org)));

  // Web checks: the domain's own address, else www (many sites live only there).
  let web = hasAddress(a) || hasAddress(aaaa) ? "yes" : lookupFailed(a) && lookupFailed(aaaa) ? "error" : "none";
  if (web === "none") {
    const w = await settle(doh("www." + domain, "A"));
    if (hasAddress(w)) { web = "yes"; obs.webHost = "www." + domain; }
  }
  obs.web = web;
  if (web === "error") obs.webErr = a.error || "the resolver returned " + dohStatus(a.value).toUpperCase();
  emit();
  if (web === "yes") {
    track("https", settleWeb(fetchUrl("https://" + obs.webHost + "/", { timeout: 15000 })));
    track("http", settleWeb(fetchUrl("http://" + obs.webHost + "/", { timeout: 15000 })));
    track("stxt", settle(fetchSecurityTxt(fetchUrl, obs.webHost)));
    track("cert", settle(withTimeout(Promise.resolve().then(() => certRows(obs.webHost)), certTimeoutMs, "the certificate logs did not answer within " + Math.round(certTimeoutMs / 1000) + " seconds")));
  }
  await Promise.all(jobs);
  return result();
}

// ---- findings (the Deck sink kit) -----------------------------------------------------------

const HIGH_ON_FAIL = new Set(["https", "cert", "dmarc", "spf"]);
const fid = (domain, id) => `domaincheck|${domain}|${id}`;

// Failing and warning checks -> common Finding shape (core/sink-map.js). Ids are stable,
// so a re-run of the same domain merges into the same findings.
export function domainCheckFindings(res) {
  const domain = String((res && res.domain) || "").trim().toLowerCase();
  if (!domain) return [];
  return (res.checks || []).filter((c) => c.status === "fail" || c.status === "warn").map((c) => ({
    id: fid(domain, c.id),
    title: `${c.label} issue on ${domain}`,
    severity: c.status === "warn" ? "low" : HIGH_ON_FAIL.has(c.id) ? "high" : "medium",
    confidence: c.id === "dkim" && c.status === "warn" ? "review" : "confirmed",
    category: GROUP_LABEL[c.group] || c.group,
    description: c.detail,
    recommendation: c.fix || undefined,
    evidence: [{ check: c.label, status: c.status, detail: c.detail }],
    assets: [{ type: "DOMAIN", name: domain }],
    tags: ["domaincheck", c.status],
  }));
}

// Finding ids this run could not re-check (its source failed): never offered as fixed.
export function domainCheckHeld(res) {
  const domain = String((res && res.domain) || "").trim().toLowerCase();
  if (!domain) return [];
  return (res.checks || []).filter((c) => c.status === "error" || c.status === "pending").map((c) => fid(domain, c.id));
}

// "good" | "warn" | "bad" for the Deck's run history (same rule as the My domain tool).
export const runLevel = (res) => (res.grade === "A" || res.grade === "B" ? "good" : res.grade === "C" || res.score == null ? "warn" : "bad");
