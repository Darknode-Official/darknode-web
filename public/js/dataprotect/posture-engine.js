// posture-engine.js — pure, deterministic external-posture scoring.
// Given the structured results of live checks (HTTP headers + redirect chain,
// DNS TXT records, security.txt presence, certificate transparency data), it
// grades each category and rolls them into one executive posture score.
// All network I/O lives in the UI (posture.js); this module is side-effect-free
// and fully unit-tested (test/security/posture.test.mjs).

const STATUS_SCORE = { pass: 100, warn: 55, info: 100, fail: 0, na: null };

// ---- parsers --------------------------------------------------------------

export function parseHSTS(value) {
  if (!value) return { present: false };
  const v = String(value).toLowerCase();
  const m = v.match(/max-age\s*=\s*(\d+)/);
  return {
    present: true,
    maxAge: m ? parseInt(m[1], 10) : 0,
    includeSub: /includesubdomains/.test(v),
    preload: /preload/.test(v),
  };
}

export function parseSPF(txts) {
  const rec = (txts || []).find((t) => /^v=spf1\b/i.test(String(t).trim()));
  if (!rec) return { present: false };
  const m = String(rec).match(/([-~?+])all\b/i);
  return { present: true, record: rec, qualifier: m ? m[1] : null };
}

export function parseDMARC(txts) {
  const rec = (txts || []).find((t) => /^v=dmarc1\b/i.test(String(t).trim()));
  if (!rec) return { present: false };
  const m = String(rec).match(/\bp\s*=\s*(none|quarantine|reject)\b/i);
  const pct = String(rec).match(/\bpct\s*=\s*(\d+)\b/i);
  return { present: true, record: rec, policy: m ? m[1].toLowerCase() : "none", pct: pct ? parseInt(pct[1], 10) : 100 };
}

// Days until expiry from an ISO/parseable date string (floor, can be negative).
export function certDaysLeft(notAfter, now = Date.now()) {
  if (!notAfter) return null;
  const t = new Date(notAfter).getTime();
  if (isNaN(t)) return null;
  return Math.floor((t - now) / 86400000);
}

// Pick the newest (latest not_after), non-expired-preferred leaf from crt.sh rows.
export function newestCert(rows, now = Date.now()) {
  if (!Array.isArray(rows) || !rows.length) return null;
  const parsed = rows.map((r) => ({
    issuer: r.issuer_name || r.issuer || "",
    notAfter: r.not_after || r.notAfter || "",
    notBefore: r.not_before || r.notBefore || "",
    names: r.name_value || r.common_name || "",
    t: new Date(r.not_after || r.notAfter || 0).getTime() || 0,
  }));
  parsed.sort((a, b) => b.t - a.t);
  return parsed[0];
}

// ---- category graders -----------------------------------------------------
// Each returns { key, label, weight, checks:[{name,status,detail,advice}] }.

function headerLower(headers) {
  const out = {};
  for (const k in (headers || {})) out[k.toLowerCase()] = headers[k];
  return out;
}

export function gradeTransport(input) {
  const h = headerLower(input.headers);
  const checks = [];
  // Whether HTTPS works and whether plain HTTP redirects to it are two distinct
  // signals: a site can serve HTTPS fine yet not redirect its HTTP endpoint.
  // Prefer the explicit flags from the probe; fall back to the finalUrl regex so
  // older callers/tests still behave.
  const httpsOk = input.httpsOk != null ? !!input.httpsOk : /^https:/i.test(input.finalUrl || "");
  const httpTested = input.httpTested != null ? !!input.httpTested : /^http:/i.test(input.requestedUrl || "");
  const httpRedirects = input.httpRedirectsToHttps != null ? !!input.httpRedirectsToHttps : /^https:/i.test(input.finalUrl || "");
  checks.push(httpsOk
    ? { name: "HTTPS", status: "pass", detail: "The site is served over HTTPS." }
    : { name: "HTTPS", status: "fail", detail: "The site did not respond over HTTPS.", advice: "Serve all traffic over TLS and redirect HTTP to HTTPS." });
  if (httpTested) {
    checks.push(httpRedirects
      ? { name: "HTTP to HTTPS redirect", status: "pass", detail: "Plain HTTP redirects to HTTPS." }
      : { name: "HTTP to HTTPS redirect", status: "fail", detail: "Plain HTTP was not redirected to HTTPS.", advice: "Add a 301 redirect from http:// to https://." });
  }
  const hsts = parseHSTS(h["strict-transport-security"]);
  if (!hsts.present) {
    checks.push({ name: "HSTS", status: "fail", detail: "No Strict-Transport-Security header.", advice: "Send HSTS with a max-age of at least 15552000 (180 days)." });
  } else if (hsts.maxAge < 15552000) {
    checks.push({ name: "HSTS", status: "warn", detail: `HSTS present but max-age is ${hsts.maxAge}s (under 180 days).`, advice: "Raise max-age to 15552000 or more and add includeSubDomains." });
  } else {
    checks.push({ name: "HSTS", status: "pass", detail: `HSTS set (max-age ${hsts.maxAge}s${hsts.includeSub ? ", includeSubDomains" : ""}${hsts.preload ? ", preload" : ""}).` });
  }
  return { key: "transport", label: "Transport security", weight: 25, checks };
}

export function gradeHeaders(input) {
  const h = headerLower(input.headers);
  const checks = [];
  const csp = h["content-security-policy"];
  checks.push(csp
    ? { name: "Content-Security-Policy", status: /unsafe-inline|unsafe-eval/i.test(csp) ? "warn" : "pass", detail: /unsafe-inline|unsafe-eval/i.test(csp) ? "CSP present but allows unsafe-inline/unsafe-eval." : "CSP is set.", advice: /unsafe-inline|unsafe-eval/i.test(csp) ? "Remove unsafe-inline/unsafe-eval; use nonces or hashes." : undefined }
    : { name: "Content-Security-Policy", status: "fail", detail: "No Content-Security-Policy header.", advice: "Add a CSP to limit script/style/connect sources." });
  checks.push(/nosniff/i.test(h["x-content-type-options"] || "")
    ? { name: "X-Content-Type-Options", status: "pass", detail: "nosniff is set." }
    : { name: "X-Content-Type-Options", status: "fail", detail: "Missing nosniff.", advice: "Send X-Content-Type-Options: nosniff." });
  const frameOk = h["x-frame-options"] || /frame-ancestors/i.test(csp || "");
  checks.push(frameOk
    ? { name: "Clickjacking protection", status: "pass", detail: "X-Frame-Options or CSP frame-ancestors is set." }
    : { name: "Clickjacking protection", status: "fail", detail: "No X-Frame-Options or frame-ancestors.", advice: "Set frame-ancestors in CSP (or X-Frame-Options: DENY)." });
  checks.push(h["referrer-policy"]
    ? { name: "Referrer-Policy", status: "pass", detail: `Referrer-Policy: ${String(h["referrer-policy"]).slice(0, 40)}.` }
    : { name: "Referrer-Policy", status: "warn", detail: "No Referrer-Policy.", advice: "Add Referrer-Policy: strict-origin-when-cross-origin." });
  checks.push(h["permissions-policy"]
    ? { name: "Permissions-Policy", status: "pass", detail: "Permissions-Policy is set." }
    : { name: "Permissions-Policy", status: "warn", detail: "No Permissions-Policy.", advice: "Restrict powerful features (camera, geolocation, etc.) with Permissions-Policy." });
  const server = h["server"] || h["x-powered-by"];
  if (server && /\d/.test(server)) {
    checks.push({ name: "Version disclosure", status: "warn", detail: `Server banner reveals a version: ${String(server).slice(0, 40)}.`, advice: "Suppress version numbers in Server / X-Powered-By." });
  }
  return { key: "headers", label: "Security headers", weight: 25, checks };
}

export function gradeEmail(input) {
  const checks = [];
  const spf = parseSPF(input.spfTxts);
  if (!spf.present) {
    checks.push({ name: "SPF", status: "fail", detail: "No SPF record.", advice: "Publish an SPF TXT record ending in -all." });
  } else if (spf.qualifier === "-") {
    checks.push({ name: "SPF", status: "pass", detail: "SPF present with a hard fail (-all)." });
  } else {
    checks.push({ name: "SPF", status: "warn", detail: `SPF present but ends in ${spf.qualifier || "?"}all (not -all).`, advice: "Tighten SPF to -all once senders are enumerated." });
  }
  const dmarc = parseDMARC(input.dmarcTxts);
  if (!dmarc.present) {
    checks.push({ name: "DMARC", status: "fail", detail: "No DMARC record.", advice: "Publish _dmarc with p=quarantine or p=reject." });
  } else if (dmarc.policy === "reject") {
    checks.push({ name: "DMARC", status: "pass", detail: "DMARC p=reject (strongest)." });
  } else if (dmarc.policy === "quarantine") {
    checks.push({ name: "DMARC", status: "warn", detail: "DMARC p=quarantine.", advice: "Move to p=reject once reports are clean." });
  } else {
    checks.push({ name: "DMARC", status: "warn", detail: "DMARC p=none (monitor only).", advice: "Enforce with p=quarantine then p=reject." });
  }
  return { key: "email", label: "Email authentication", weight: 20, checks };
}

export function gradeTls(input) {
  const checks = [];
  const cert = input.cert;
  if (!cert) {
    checks.push({ name: "Certificate", status: "na", detail: "No certificate transparency data was available." });
    return { key: "tls", label: "Certificate", weight: 20, checks };
  }
  const days = certDaysLeft(cert.notAfter, input.now);
  if (days == null) {
    checks.push({ name: "Certificate expiry", status: "na", detail: "Certificate expiry could not be read." });
  } else if (days < 0) {
    checks.push({ name: "Certificate expiry", status: "fail", detail: `Newest known certificate expired ${-days} day(s) ago.`, advice: "Renew the certificate immediately." });
  } else if (days < 14) {
    checks.push({ name: "Certificate expiry", status: "fail", detail: `Certificate expires in ${days} day(s).`, advice: "Renew now; automate renewal (ACME)." });
  } else if (days < 30) {
    checks.push({ name: "Certificate expiry", status: "warn", detail: `Certificate expires in ${days} day(s).`, advice: "Renew soon and automate renewal." });
  } else {
    checks.push({ name: "Certificate expiry", status: "pass", detail: `Certificate valid for ${days} more day(s).` });
  }
  checks.push(cert.issuer
    ? { name: "Issuer", status: "info", detail: `Issued by ${String(cert.issuer).replace(/.*?CN\s*=\s*/i, "").slice(0, 60) || cert.issuer}.` }
    : { name: "Issuer", status: "na", detail: "Issuer not available." });
  return { key: "tls", label: "Certificate", weight: 20, checks };
}

export function gradeDisclosure(input) {
  const checks = [];
  checks.push(input.securityTxt && input.securityTxt.present
    ? { name: "security.txt", status: "pass", detail: "A security.txt disclosure policy is published." }
    : { name: "security.txt", status: "warn", detail: "No /.well-known/security.txt.", advice: "Publish security.txt with a contact for vulnerability reports." });
  return { key: "disclosure", label: "Responsible disclosure", weight: 10, checks };
}

// ---- roll-up --------------------------------------------------------------

function categoryScore(cat) {
  let sum = 0, n = 0;
  for (const c of cat.checks) {
    const s = STATUS_SCORE[c.status];
    if (s == null) continue; // info / na do not move the score
    sum += s; n++;
  }
  return n ? Math.round(sum / n) : null;
}

export function letterGrade(score) {
  if (score == null) return "N/A";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

export function scorePosture(input) {
  input = input || {};
  const categories = [
    gradeTransport(input), gradeHeaders(input), gradeEmail(input),
    gradeTls(input), gradeDisclosure(input),
  ].map((cat) => ({ ...cat, score: categoryScore(cat) }));

  let wSum = 0, wScore = 0;
  for (const cat of categories) {
    if (cat.score == null) continue;
    wSum += cat.weight; wScore += cat.weight * cat.score;
  }
  const score = wSum ? Math.round(wScore / wSum) : null;

  const failing = [];
  for (const cat of categories) for (const c of cat.checks) if (c.status === "fail") failing.push({ category: cat.label, name: c.name, advice: c.advice });
  const warnings = [];
  for (const cat of categories) for (const c of cat.checks) if (c.status === "warn") warnings.push({ category: cat.label, name: c.name, advice: c.advice });

  return {
    domain: input.domain || "",
    score, grade: letterGrade(score),
    categories,
    counts: {
      fail: failing.length, warn: warnings.length,
      pass: categories.reduce((a, cat) => a + cat.checks.filter((c) => c.status === "pass").length, 0),
    },
    topActions: failing.concat(warnings).slice(0, 8),
  };
}

// ---- self-test ------------------------------------------------------------

export function selfTest() {
  const out = [];
  const T = (name, cond) => out.push({ name, pass: !!cond });

  T("parseHSTS maxage", parseHSTS("max-age=31536000; includeSubDomains; preload").maxAge === 31536000);
  T("parseSPF hardfail", parseSPF(["v=spf1 include:_spf.google.com -all"]).qualifier === "-");
  T("parseDMARC reject", parseDMARC(["v=DMARC1; p=reject"]).policy === "reject");
  T("certDaysLeft future", certDaysLeft(new Date(Date.now() + 40 * 86400000).toISOString()) >= 39);

  const strong = scorePosture({
    domain: "example.com", requestedUrl: "https://example.com", finalUrl: "https://example.com",
    headers: {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
      "content-security-policy": "default-src 'self'", "x-content-type-options": "nosniff",
      "x-frame-options": "DENY", "referrer-policy": "strict-origin", "permissions-policy": "geolocation=()",
    },
    spfTxts: ["v=spf1 -all"], dmarcTxts: ["v=DMARC1; p=reject"],
    cert: { issuer: "CN=E5", notAfter: new Date(Date.now() + 60 * 86400000).toISOString() },
    securityTxt: { present: true },
  });
  T("strong scores A", strong.grade === "A");

  const weak = scorePosture({
    domain: "weak.test", requestedUrl: "http://weak.test", finalUrl: "http://weak.test",
    headers: {}, spfTxts: [], dmarcTxts: [], cert: null, securityTxt: { present: false },
  });
  T("weak scores F", weak.grade === "F");
  T("weak has fail actions", weak.counts.fail >= 4);

  return { pass: out.every((t) => t.pass), tests: out };
}

export default { scorePosture, parseHSTS, parseSPF, parseDMARC, certDaysLeft, newestCert, letterGrade, selfTest };
