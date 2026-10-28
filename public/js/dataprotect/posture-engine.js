// posture-engine.js — pure, deterministic external-posture scoring.
// Given the structured results of live checks (HTTP headers + redirect chain,
// DNS TXT records, security.txt presence, certificate transparency data), it
// grades each category and rolls them into one executive posture score.
// All network I/O lives in the UI (posture.js); this module is side-effect-free
// and fully unit-tested (test/security/posture.test.mjs).

// info/na are purely descriptive and must NOT move a category score — categoryScore
// skips any check whose score is null (an `info` scored 100 would average in as a
// perfect mark, inflating e.g. a failed-certificate TLS category by a whole grade).
const STATUS_SCORE = { pass: 100, warn: 55, info: null, fail: 0, na: null };

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
  // The `all` MECHANISM token (optionally qualified), not any "<qual>all" substring:
  // a host/include like `mail-all.example.com` must not be mistaken for the policy.
  // A bare `all` means `+all` per RFC 7208 (default qualifier is pass).
  const allTok = String(rec).trim().split(/\s+/).find((t) => /^[-~?+]?all$/i.test(t));
  return { present: true, record: rec, qualifier: allTok ? (/^[-~?+]/.test(allTok) ? allTok[0] : "+") : null };
}

export function parseDMARC(txts) {
  const rec = (txts || []).find((t) => /^v=dmarc1\b/i.test(String(t).trim()));
  if (!rec) return { present: false };
  const s = String(rec);
  const m = s.match(/\bp\s*=\s*(none|quarantine|reject)\b/i);
  const spM = s.match(/\bsp\s*=\s*(none|quarantine|reject)\b/i);
  const pct = s.match(/\bpct\s*=\s*(\d+)\b/i);
  const rua = s.match(/\brua\s*=\s*([^;]+)/i);
  const ruf = s.match(/\bruf\s*=\s*([^;]+)/i);
  const adkim = s.match(/\badkim\s*=\s*([rs])\b/i);
  const aspf = s.match(/\baspf\s*=\s*([rs])\b/i);
  return {
    present: true, record: rec,
    policy: m ? m[1].toLowerCase() : "none",
    sp: spM ? spM[1].toLowerCase() : null,
    pct: pct ? parseInt(pct[1], 10) : 100,
    rua: rua ? rua[1].trim() : null,
    ruf: ruf ? ruf[1].trim() : null,
    adkim: adkim ? adkim[1].toLowerCase() : null,
    aspf: aspf ? aspf[1].toLowerCase() : null,
  };
}

// Count the DNS-lookup-causing mechanisms in an SPF record. RFC 7208 §4.6.4
// caps these at 10; exceeding it is a permerror (SPF stops evaluating).
// include / a / mx / ptr / exists and the redirect modifier each cost a lookup.
export function spfLookupCount(record) {
  if (!record) return 0;
  const toks = String(record).trim().split(/\s+/);
  let n = 0;
  for (const raw of toks) {
    const t = raw.replace(/^[-~?+]/, "").toLowerCase();
    if (/^(include:|a(:|$|\/)|mx(:|$|\/)|ptr(:|$)|exists:|redirect=)/.test(t)) n++;
  }
  return n;
}

// Parse one or more Set-Cookie header values. The proxy collapses multiple
// Set-Cookie headers into one comma-joined string (standard Headers iteration),
// so accept a string or an array and split on commas that start a new cookie
// pair — while leaving the comma inside an Expires date untouched.
export function parseSetCookie(value) {
  if (!value) return [];
  const parts = Array.isArray(value) ? value.slice() : splitCookieHeader(String(value));
  const out = [];
  for (const raw of parts) {
    const str = String(raw).trim();
    if (!str) continue;
    const segs = str.split(";").map((x) => x.trim());
    const nameVal = segs[0] || "";
    const name = nameVal.split("=")[0].trim();
    if (!name) continue;
    const attrs = segs.slice(1).map((x) => x.toLowerCase());
    const ss = segs.slice(1).find((x) => /^samesite\s*=/i.test(x));
    out.push({
      name,
      secure: attrs.includes("secure"),
      httpOnly: attrs.some((x) => x === "httponly"),
      sameSite: ss ? ss.split("=")[1].trim().toLowerCase() : null,
    });
  }
  return out;
}

function splitCookieHeader(s) {
  // Split only on a comma that is followed by a cookie-name token and '=',
  // so "Expires=Wed, 09 Jun 2025 ..." stays in one piece.
  return s.split(/,(?=\s*[A-Za-z0-9!#$%&'*+\-.^_`|~]+\s*=)/);
}

// Is a domain covered by a cert's Subject Alternative Names? name_value from
// crt.sh/certspotter is a newline-joined list that may contain wildcards.
export function certCoversDomain(names, domain) {
  if (!names || !domain) return null; // unknown
  const d = String(domain).toLowerCase().replace(/\.$/, "");
  const list = String(names).split(/[\s,]+/).map((n) => n.trim().toLowerCase().replace(/\.$/, "")).filter(Boolean);
  if (!list.length) return null;
  for (const n of list) {
    if (n === d) return true;
    if (n.startsWith("*.")) {
      const base = n.slice(2);
      // A wildcard covers exactly one label: a.base matches *.base, a.b.base does not.
      if (d.endsWith("." + base) && d.slice(0, d.length - base.length - 1).indexOf(".") === -1) return true;
      if (d === base) return true; // many issuers also list the apex alongside *.
    }
  }
  return false;
}

// Parse an _mta-sts TXT record and (optionally) the fetched policy file body.
export function parseMtaSts(txts, policyBody) {
  const rec = (txts || []).find((t) => /^v=stsv1\b/i.test(String(t).trim()));
  const res = { present: !!rec, record: rec || null, mode: null, maxAge: null };
  if (policyBody) {
    const m = String(policyBody).match(/mode\s*:\s*(enforce|testing|none)/i);
    const ma = String(policyBody).match(/max_age\s*:\s*(\d+)/i);
    if (m) res.mode = m[1].toLowerCase();
    if (ma) res.maxAge = parseInt(ma[1], 10);
  }
  return res;
}

// Days until expiry from an ISO/parseable date string (floor, can be negative).
export function certDaysLeft(notAfter, now = Date.now()) {
  if (!notAfter) return null;
  // crt.sh emits zoneless ISO (e.g. "2026-01-14T23:59:59"). new Date() would read that as
  // LOCAL time, so the day count drifts by the viewer's UTC offset and can cross a band
  // boundary. Parse a zoneless ISO as UTC (matching netexposure-engine's convention); any
  // string carrying a Z/offset or other format falls through to the normal parser.
  const m = String(notAfter).match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?$/);
  const t = m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0)) : new Date(notAfter).getTime();
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
    // CT JSON rarely carries these; pass them through only when a source provides them.
    keySize: r.key_size || r.keySize || null,
    sigAlg: r.signature_algorithm || r.sigAlg || null,
    serial: r.serial_number || null,
    t: new Date(r.not_after || r.notAfter || 0).getTime() || 0,
  }));
  parsed.sort((a, b) => b.t - a.t);
  return parsed[0];
}

// ---- deep CSP grading (shared logic with the standalone CSP Evaluator) -----

export function parseCSP(raw) {
  const directives = {};
  String(raw || "").split(";").forEach((part) => {
    const trimmed = part.trim();
    if (!trimmed) return;
    const tokens = trimmed.split(/\s+/);
    const name = tokens[0].toLowerCase();
    // CSP L3: the FIRST occurrence of a directive wins; later copies are ignored.
    if (!Object.prototype.hasOwnProperty.call(directives, name)) directives[name] = tokens.slice(1);
  });
  return directives;
}

// Deep, Observatory/CSP-Evaluator-style grade for a CSP string. Pure + tested.
export function gradeCSPDeep(raw) {
  if (!raw || !String(raw).trim()) return { present: false, score: null, grade: "N/A", findings: [], directives: {} };
  const dirs = parseCSP(raw);
  let score = 100;
  const findings = [];
  const add = (sev, msg) => findings.push({ sev, msg });
  const ss = (dirs["script-src"] || dirs["default-src"] || []).map((s) => s.toLowerCase());

  if (!dirs["default-src"]) { score -= 15; add("high", "Missing default-src — no fallback policy."); }
  if (ss.indexOf("'unsafe-inline'") >= 0) { score -= 25; add("critical", "script-src allows 'unsafe-inline' — XSS protection nullified."); }
  if (ss.indexOf("'unsafe-eval'") >= 0) { score -= 20; add("critical", "script-src allows 'unsafe-eval' — code injection possible."); }
  if (ss.indexOf("*") >= 0) { score -= 20; add("critical", "script-src allows the * wildcard — any origin can run scripts."); }
  if (ss.indexOf("data:") >= 0) { score -= 15; add("high", "script-src allows data: — XSS via data: URIs."); }
  if (ss.indexOf("https:") >= 0) { score -= 10; add("high", "script-src allows any HTTPS source — too broad."); }
  if (ss.indexOf("http:") >= 0) { score -= 10; add("high", "script-src allows plain http: sources."); }

  if (!dirs["frame-ancestors"]) { score -= 10; add("high", "Missing frame-ancestors — no clickjacking protection."); }
  const objSrc = (dirs["object-src"] || dirs["default-src"] || []).map((s) => s.toLowerCase());
  if (!objSrc.length || objSrc[0] !== "'none'") { score -= 10; add("high", "Missing or permissive object-src — plugin-based XSS possible (set object-src 'none')."); }
  if (!dirs["base-uri"]) { score -= 8; add("medium", "Missing base-uri — <base> tag injection possible."); }
  if (!dirs["form-action"]) { score -= 5; add("medium", "Missing form-action — forms can submit anywhere."); }
  if ((dirs["style-src"] || dirs["default-src"] || []).map((s) => s.toLowerCase()).indexOf("'unsafe-inline'") >= 0) { score -= 5; add("medium", "style-src allows 'unsafe-inline'."); }

  // Broad connect-src = exfiltration path.
  const cs = (dirs["connect-src"] || dirs["default-src"] || []).map((s) => s.toLowerCase());
  if (cs.indexOf("*") >= 0 || cs.indexOf("https:") >= 0) { score -= 5; add("medium", "connect-src is wildcard/https: — broad exfiltration surface."); }
  // strict-dynamic without a nonce/hash is a no-op.
  const hasNonceHash = ss.some((s) => s.indexOf("'nonce-") === 0 || /^'sha(256|384|512)-/.test(s));
  if (ss.indexOf("'strict-dynamic'") >= 0 && !hasNonceHash) { score -= 5; add("high", "strict-dynamic without a nonce/hash is meaningless."); }

  if (dirs["upgrade-insecure-requests"]) score += 3;
  if (dirs["require-trusted-types-for"]) score += 5;

  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  return { present: true, score, grade, findings, directives: dirs };
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
  if (!csp) {
    checks.push({ name: "Content-Security-Policy", status: "fail", detail: "No Content-Security-Policy header.", advice: "Add a CSP to limit script/style/connect sources." });
  } else {
    const g = gradeCSPDeep(csp);
    // A/B pass, C/D warn, F fail — present-but-weak never scores like absent.
    // Map the deep grade to a status, but never let a CSP with a critical flaw
    // (unsafe-inline/unsafe-eval/wildcard in script-src) read as a clean pass.
    const hasCritical = g.findings.some((f) => f.sev === "critical");
    const st = g.grade === "F" ? "fail" : (g.grade === "A" || g.grade === "B") ? (hasCritical ? "warn" : "pass") : "warn";
    const top = g.findings.slice(0, 3).map((f) => f.msg).join(" ");
    checks.push({
      name: "Content-Security-Policy",
      status: st,
      detail: `CSP present — deep grade ${g.grade} (${g.score}/100).${top ? " " + top : ""}`,
      advice: st === "pass" ? undefined : "Tighten the CSP: remove unsafe-inline/unsafe-eval and wildcards; set object-src 'none' and base-uri 'self'; add frame-ancestors.",
    });
  }
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

  // Cross-origin isolation headers (origin-isolation / Spectre hardening).
  const coop = String(h["cross-origin-opener-policy"] || "").toLowerCase();
  checks.push(/same-origin|same-origin-allow-popups/.test(coop)
    ? { name: "Cross-Origin-Opener-Policy", status: "pass", detail: `COOP: ${coop.slice(0, 40)}.` }
    : { name: "Cross-Origin-Opener-Policy", status: "warn", detail: coop ? `COOP is '${coop}', not same-origin.` : "No Cross-Origin-Opener-Policy.", advice: "Set Cross-Origin-Opener-Policy: same-origin to isolate your browsing context." });
  const coep = String(h["cross-origin-embedder-policy"] || "").toLowerCase();
  checks.push(/require-corp|credentialless/.test(coep)
    ? { name: "Cross-Origin-Embedder-Policy", status: "pass", detail: `COEP: ${coep.slice(0, 40)}.` }
    : { name: "Cross-Origin-Embedder-Policy", status: "warn", detail: coep ? `COEP is '${coep}'.` : "No Cross-Origin-Embedder-Policy.", advice: "Set Cross-Origin-Embedder-Policy: require-corp to enable cross-origin isolation." });
  const corp = String(h["cross-origin-resource-policy"] || "").toLowerCase();
  checks.push(/same-origin|same-site|cross-origin/.test(corp)
    ? { name: "Cross-Origin-Resource-Policy", status: "pass", detail: `CORP: ${corp.slice(0, 40)}.` }
    : { name: "Cross-Origin-Resource-Policy", status: "warn", detail: "No Cross-Origin-Resource-Policy.", advice: "Set Cross-Origin-Resource-Policy: same-origin to stop other sites embedding your resources." });

  // Cookie flags on the response (Secure / HttpOnly / SameSite).
  const cookies = parseSetCookie(input.setCookie != null ? input.setCookie : h["set-cookie"]);
  if (cookies.length) {
    const noSecure = cookies.filter((c) => !c.secure).map((c) => c.name);
    const sameSiteNoneInsecure = cookies.filter((c) => c.sameSite === "none" && !c.secure).map((c) => c.name);
    const noHttpOnly = cookies.filter((c) => !c.httpOnly).map((c) => c.name);
    const noSameSite = cookies.filter((c) => !c.sameSite).map((c) => c.name);
    const trunc = (arr) => arr.slice(0, 4).join(", ") + (arr.length > 4 ? ", …" : "");
    if (noSecure.length) {
      checks.push({ name: "Cookie security", status: "fail", detail: `${noSecure.length} of ${cookies.length} cookie(s) lack the Secure flag: ${trunc(noSecure)}.${sameSiteNoneInsecure.length ? " SameSite=None without Secure is rejected by browsers." : ""}`, advice: "Set Secure (and HttpOnly where the cookie is not read by JS, plus SameSite) on every cookie." });
    } else if (noHttpOnly.length || noSameSite.length) {
      const parts = [];
      if (noHttpOnly.length) parts.push(`${noHttpOnly.length} without HttpOnly (${trunc(noHttpOnly)})`);
      if (noSameSite.length) parts.push(`${noSameSite.length} without SameSite (${trunc(noSameSite)})`);
      checks.push({ name: "Cookie security", status: "warn", detail: `All cookies are Secure, but ${parts.join("; ")}.`, advice: "Add HttpOnly to session cookies and SameSite=Lax/Strict to mitigate CSRF." });
    } else {
      checks.push({ name: "Cookie security", status: "pass", detail: `All ${cookies.length} cookie(s) set Secure, HttpOnly and SameSite.` });
    }
  }

  const server = h["server"] || h["x-powered-by"];
  if (server && /\d/.test(server)) {
    checks.push({ name: "Version disclosure", status: "warn", detail: `Server banner reveals a version: ${String(server).slice(0, 40)}.`, advice: "Suppress version numbers in Server / X-Powered-By." });
  }
  return { key: "headers", label: "Security headers", weight: 25, checks };
}

export function gradeEmail(input) {
  const checks = [];
  // a DNS lookup that failed (neither resolver answered) is "could not check", not "no record";
  // holds names the checks that lookup decides, so their earlier findings are not offered as fixed
  const failed = (txts) => !!(txts && txts.failed);
  const spf = parseSPF(input.spfTxts);
  if (failed(input.spfTxts)) {
    checks.push({ name: "SPF", status: "na", detail: "The DNS lookup for SPF failed, so it could not be checked.", holds: ["SPF lookup budget"] });
  } else if (!spf.present) {
    checks.push({ name: "SPF", status: "fail", detail: "No SPF record.", advice: "Publish an SPF TXT record ending in -all." });
  } else if (spf.qualifier === "-") {
    checks.push({ name: "SPF", status: "pass", detail: "SPF present with a hard fail (-all)." });
  } else {
    checks.push({ name: "SPF", status: "warn", detail: `SPF present but ends in ${spf.qualifier || "?"}all (not -all).`, advice: "Tighten SPF to -all once senders are enumerated." });
  }
  // SPF DNS-lookup budget: RFC 7208 caps lookup mechanisms at 10 (permerror).
  // This counts only the record's own mechanisms, not nested includes, so it is
  // a floor — labelled honestly as an estimate.
  if (spf.present) {
    const n = spfLookupCount(spf.record);
    if (n > 10) {
      checks.push({ name: "SPF lookup budget", status: "fail", detail: `SPF uses at least ${n} lookup mechanisms (RFC 7208 limit is 10) — likely permerror.`, advice: "Flatten includes or drop mechanisms to stay at or under 10 DNS lookups." });
    } else if (n >= 8) {
      checks.push({ name: "SPF lookup budget", status: "warn", detail: `SPF already uses ${n} of 10 lookup mechanisms (nested includes may push it over).`, advice: "Audit nested includes; the real total counts those too." });
    } else {
      checks.push({ name: "SPF lookup budget", status: "pass", detail: `SPF uses ${n} direct lookup mechanism(s) (estimate; nested includes not counted).` });
    }
  }
  const dmarc = parseDMARC(input.dmarcTxts);
  if (failed(input.dmarcTxts)) {
    checks.push({ name: "DMARC", status: "na", detail: "The DNS lookup for DMARC failed, so it could not be checked.", holds: ["DMARC coverage (pct)", "DMARC subdomain policy", "DMARC reporting (rua)"] });
  } else if (!dmarc.present) {
    checks.push({ name: "DMARC", status: "fail", detail: "No DMARC record.", advice: "Publish _dmarc with p=quarantine or p=reject." });
  } else {
    // A subdomain with no record of its own is covered by its organizational domain's
    // record (RFC 7489 6.6.3), whose sp= (else p=) is the policy that applies to it.
    const pol = input.dmarcFrom ? dmarc.sp || dmarc.policy : dmarc.policy;
    const via = input.dmarcFrom ? ` (inherited from ${input.dmarcFrom})` : "", tag = input.dmarcFrom && dmarc.sp ? "sp" : "p";
    if (pol === "reject") {
      checks.push({ name: "DMARC", status: "pass", detail: `DMARC ${tag}=reject (strongest)${via}.` });
    } else if (pol === "quarantine") {
      checks.push({ name: "DMARC", status: "warn", detail: `DMARC ${tag}=quarantine${via}.`, advice: "Move to p=reject once reports are clean." });
    } else {
      checks.push({ name: "DMARC", status: "warn", detail: `DMARC ${tag}=none (monitor only)${via}.`, advice: "Enforce with p=quarantine then p=reject." });
    }
    // pct<100 only enforces on a fraction of mail.
    if (dmarc.pct != null && dmarc.pct < 100) {
      checks.push({ name: "DMARC coverage (pct)", status: "warn", detail: `DMARC pct=${dmarc.pct} — the policy applies to only ${dmarc.pct}% of failing mail.`, advice: "Raise pct to 100 once confident." });
    }
    // Subdomain policy: without sp, subdomains inherit p (fine); flag only if weaker.
    if (!input.dmarcFrom && dmarc.sp && dmarc.sp === "none" && dmarc.policy !== "none") {
      checks.push({ name: "DMARC subdomain policy", status: "warn", detail: `sp=none weakens enforcement for subdomains despite p=${dmarc.policy}.`, advice: "Set sp=reject (or drop sp to inherit p)." });
    }
    // Aggregate reporting (rua) is how you actually see SPF/DKIM alignment.
    checks.push(dmarc.rua
      ? { name: "DMARC reporting (rua)", status: "pass", detail: "Aggregate report address (rua) is configured." }
      : { name: "DMARC reporting (rua)", status: "warn", detail: "No rua= aggregate report address.", advice: "Add rua=mailto:dmarc@yourdomain to receive alignment reports." });
  }

  // DKIM: we can only probe common selectors over DoH; absence is NOT proof of
  // no DKIM (selectors are arbitrary), so a miss is reported as unknown (na).
  const dkim = Array.isArray(input.dkimSelectors) ? input.dkimSelectors : [];
  const found = dkim.filter((d) => d && d.present);
  if (found.length) {
    checks.push({ name: "DKIM", status: "pass", detail: `DKIM key published on selector(s): ${found.map((d) => d.selector).slice(0, 6).join(", ")}.` });
  } else if (dkim.length) {
    checks.push({ name: "DKIM", status: "na", detail: `No DKIM key on the ${dkim.length} common selector(s) probed (${dkim.map((d) => d.selector).slice(0, 8).join(", ")}). DKIM may still exist on a custom selector.`, advice: "Confirm your DKIM selector and publish a key if mail is not signed." });
  }

  // MTA-STS: enforces TLS for inbound SMTP.
  const mta = parseMtaSts(input.mtaStsTxts, input.mtaStsPolicy);
  if (failed(input.mtaStsTxts)) {
    checks.push({ name: "MTA-STS", status: "na", detail: "The DNS lookup for MTA-STS failed, so it could not be checked." });
  } else if (!mta.present) {
    checks.push({ name: "MTA-STS", status: "warn", detail: "No _mta-sts TXT record.", advice: "Publish MTA-STS (TXT + /.well-known/mta-sts.txt policy) to require TLS for inbound mail." });
  } else if (mta.mode === "enforce") {
    checks.push({ name: "MTA-STS", status: "pass", detail: "MTA-STS policy present in enforce mode." });
  } else if (mta.mode) {
    checks.push({ name: "MTA-STS", status: "warn", detail: `MTA-STS present but mode=${mta.mode} (not enforce).`, advice: "Move the policy to mode: enforce once validated." });
  } else {
    checks.push({ name: "MTA-STS", status: "warn", detail: "MTA-STS TXT present but the policy file could not be read.", advice: "Serve /.well-known/mta-sts.txt with mode: enforce." });
  }

  // TLS-RPT: SMTP TLS failure reporting.
  const hasTlsRpt = (input.tlsRptTxts || []).some((t) => /^v=tlsrptv1\b/i.test(String(t).trim()));
  checks.push(failed(input.tlsRptTxts) ? { name: "TLS-RPT", status: "na", detail: "The DNS lookup for TLS-RPT failed, so it could not be checked." } : hasTlsRpt
    ? { name: "TLS-RPT", status: "pass", detail: "SMTP TLS reporting (_smtp._tls TXT) is configured." }
    : { name: "TLS-RPT", status: "warn", detail: "No TLS-RPT record.", advice: "Publish _smtp._tls TXT (v=TLSRPTv1; rua=…) to receive SMTP TLS failure reports." });

  return { key: "email", label: "Email authentication", weight: 20, checks };
}

export function gradeTls(input) {
  const checks = [];
  const cert = input.cert;
  if (!cert) {
    checks.push(input.certUnreachable
      ? { name: "Certificate", status: "na", detail: "The certificate-transparency logs did not answer, so the certificate could not be checked.", holds: ["Certificate validity", "Signature algorithm", "Key strength", "Name coverage", "Issuer"] }
      : { name: "Certificate", status: "na", detail: "No certificate transparency data was available." });
    return { key: "tls", label: "Certificate", weight: 20, checks };
  }
  // Honesty: CT shows the newest certificate ISSUED for the domain, which is not
  // guaranteed to be the leaf the server is serving right now. Label it as such.
  const note = " (newest issued certificate from CT logs — not necessarily the served leaf)";
  const days = certDaysLeft(cert.notAfter, input.now);
  if (days == null) {
    checks.push({ name: "Certificate validity", status: "na", detail: "Certificate expiry could not be read." });
  } else if (days < 0) {
    checks.push({ name: "Certificate validity", status: "fail", detail: `Newest issued certificate expired ${-days} day(s) ago${note}. The live leaf may differ.`, advice: "Confirm the served certificate and renew immediately." });
  } else if (days < 14) {
    checks.push({ name: "Certificate validity", status: "fail", detail: `Newest issued certificate expires in ${days} day(s)${note}.`, advice: "Renew now; automate renewal (ACME)." });
  } else if (days < 30) {
    checks.push({ name: "Certificate validity", status: "warn", detail: `Newest issued certificate expires in ${days} day(s)${note}.`, advice: "Renew soon and automate renewal." });
  } else {
    checks.push({ name: "Certificate validity", status: "pass", detail: `Newest issued certificate valid for ${days} more day(s)${note}.` });
  }

  // SAN coverage: does the newest issued cert actually name this domain?
  const covers = certCoversDomain(cert.names, input.domain);
  if (input.domain && cert.names) {
    checks.push(covers
      ? { name: "Name coverage", status: "pass", detail: `The certificate's SANs cover ${input.domain}.` }
      : { name: "Name coverage", status: "warn", detail: `The newest issued certificate's SANs do not appear to cover ${input.domain} (names: ${String(cert.names).split(/[\s,]+/).filter(Boolean).slice(0, 4).join(", ")}).`, advice: "Ensure the served certificate includes this hostname (or a covering wildcard)." });
  }

  // Key size / signature algorithm — only when a CT source supplied them.
  if (cert.keySize) {
    const k = parseInt(cert.keySize, 10);
    checks.push(k && k < 2048
      ? { name: "Key strength", status: "warn", detail: `Public key is ${k}-bit (RSA under 2048-bit is deprecated).`, advice: "Reissue with a 2048-bit+ RSA or an ECDSA P-256 key." }
      : { name: "Key strength", status: "pass", detail: `Public key size: ${cert.keySize}-bit.` });
  }
  if (cert.sigAlg) {
    checks.push(/sha1|md5/i.test(cert.sigAlg)
      ? { name: "Signature algorithm", status: "fail", detail: `Weak signature algorithm: ${cert.sigAlg}.`, advice: "Reissue with SHA-256 or stronger." }
      : { name: "Signature algorithm", status: "pass", detail: `Signature algorithm: ${String(cert.sigAlg).slice(0, 40)}.` });
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
  T("parseSPF all is a token not a substring", parseSPF(["v=spf1 include:mail-all.example.com ?all"]).qualifier === "?");
  T("parseSPF bare all defaults to +", parseSPF(["v=spf1 a all"]).qualifier === "+");
  T("parseDMARC reject", parseDMARC(["v=DMARC1; p=reject"]).policy === "reject");
  T("certDaysLeft future", certDaysLeft(new Date(Date.now() + 40 * 86400000).toISOString()) >= 39);

  const strong = scorePosture({
    domain: "example.com", requestedUrl: "https://example.com", finalUrl: "https://example.com",
    headers: {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
      "content-security-policy": "default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
      "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "strict-origin",
      "permissions-policy": "geolocation=()", "cross-origin-opener-policy": "same-origin",
      "cross-origin-embedder-policy": "require-corp", "cross-origin-resource-policy": "same-origin",
    },
    spfTxts: ["v=spf1 -all"], dmarcTxts: ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
    dkimSelectors: [{ selector: "default", present: true }],
    mtaStsTxts: ["v=STSv1; id=1"], mtaStsPolicy: "version: STSv1\nmode: enforce\nmax_age: 604800",
    tlsRptTxts: ["v=TLSRPTv1; rua=mailto:t@example.com"],
    cert: { issuer: "CN=E5", notAfter: new Date(Date.now() + 60 * 86400000).toISOString(), names: "example.com\nwww.example.com" },
    securityTxt: { present: true },
  });
  T("strong scores A", strong.grade === "A");
  T("spfLookupCount counts mechanisms", spfLookupCount("v=spf1 include:a include:b mx -all") === 3);
  T("parseSetCookie flags", parseSetCookie("id=1; Path=/; Secure; HttpOnly; SameSite=Lax")[0].secure === true);
  T("certCoversDomain wildcard", certCoversDomain("*.example.com", "a.example.com") === true);
  T("gradeCSPDeep penalises unsafe-inline", gradeCSPDeep("script-src 'self' 'unsafe-inline'").score < 90);
  // info/na checks stay neutral: expired cert (fail=0) + non-covering SAN (warn=55) +
  // known issuer (info) must score the TLS category on fail+warn only → round(55/2)=28,
  // NOT (0+55+100)/3=52 (the pre-fix bug where info counted as a perfect 100).
  const badTls = scorePosture({
    domain: "bad.test", requestedUrl: "https://bad.test", finalUrl: "https://bad.test",
    headers: {}, spfTxts: [], dmarcTxts: [],
    cert: { issuer: "CN=E5", notAfter: new Date(Date.now() - 86400000).toISOString(), names: "other.test" },
    securityTxt: { present: false },
  });
  T("info checks stay neutral in TLS score", (badTls.categories.find((c) => c.key === "tls") || {}).score === 28);

  const weak = scorePosture({
    domain: "weak.test", requestedUrl: "http://weak.test", finalUrl: "http://weak.test",
    headers: {}, spfTxts: [], dmarcTxts: [], cert: null, securityTxt: { present: false },
  });
  T("weak scores F", weak.grade === "F");
  T("weak has fail actions", weak.counts.fail >= 4);

  return { pass: out.every((t) => t.pass), tests: out };
}

export default {
  scorePosture, parseHSTS, parseSPF, parseDMARC, certDaysLeft, newestCert, letterGrade, selfTest,
  spfLookupCount, parseSetCookie, certCoversDomain, parseMtaSts, parseCSP, gradeCSPDeep,
};
