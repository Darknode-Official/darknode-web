// External Posture Scorecard engine tests (public/js/dataprotect/posture-engine.js):
// deterministic grading of transport, headers, email auth, TLS and disclosure.

import { test, assert, group } from "../harness.mjs";
import {
  scorePosture, parseHSTS, parseSPF, parseDMARC, certDaysLeft, newestCert, letterGrade, selfTest, gradeTransport,
  spfLookupCount, parseSetCookie, certCoversDomain, parseMtaSts, parseCSP, gradeCSPDeep, gradeHeaders, gradeEmail, gradeTls,
} from "../../public/js/dataprotect/posture-engine.js";
import { postureFindings, postureHeld } from "../../public/js/dataprotect/dp-sink.js";

group("posture: HTTPS vs HTTP-redirect are distinct signals", () => {
  test("working HTTPS with a non-redirecting HTTP endpoint still passes HTTPS", () => {
    const r = gradeTransport({ requestedUrl: "http://x.test", httpsOk: true, httpTested: true, httpRedirectsToHttps: false, finalUrl: "https://x.test", headers: {} });
    assert.equal(r.checks.find((c) => c.name === "HTTPS").status, "pass");
    assert.equal(r.checks.find((c) => c.name === "HTTP to HTTPS redirect").status, "fail");
  });
  test("HTTPS unreachable fails the HTTPS check", () => {
    const r = gradeTransport({ requestedUrl: "https://x.test", httpsOk: false, httpTested: false, finalUrl: "", headers: {} });
    assert.equal(r.checks.find((c) => c.name === "HTTPS").status, "fail");
  });
  test("legacy finalUrl-only callers still grade HTTPS from the URL", () => {
    const r = gradeTransport({ requestedUrl: "https://x.test", finalUrl: "https://x.test", headers: {} });
    assert.equal(r.checks.find((c) => c.name === "HTTPS").status, "pass");
  });
});

group("posture: engine self-test", () => {
  test("all in-engine self-test checks pass", () => {
    const r = selfTest();
    assert.ok(r.pass, "failures: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
});

group("posture: parsers", () => {
  test("parseHSTS reads directives", () => {
    const h = parseHSTS("max-age=63072000; includeSubDomains; preload");
    assert.equal(h.maxAge, 63072000);
    assert.ok(h.includeSub);
    assert.ok(h.preload);
    assert.notOk(parseHSTS("").present);
  });
  test("parseSPF qualifier", () => {
    assert.equal(parseSPF(["v=spf1 mx -all"]).qualifier, "-");
    assert.equal(parseSPF(["v=spf1 mx ~all"]).qualifier, "~");
    assert.notOk(parseSPF(["not spf"]).present);
  });
  test("parseDMARC policy and pct", () => {
    const d = parseDMARC(["v=DMARC1; p=quarantine; pct=50"]);
    assert.equal(d.policy, "quarantine");
    assert.equal(d.pct, 50);
    assert.equal(parseDMARC(["v=DMARC1; p=reject"]).policy, "reject");
    assert.notOk(parseDMARC([]).present);
  });
  test("certDaysLeft", () => {
    const d = certDaysLeft(new Date(Date.now() + 10 * 86400000).toISOString());
    assert.ok(d === 9 || d === 10, "expected 9 or 10, got " + d);
    assert.ok(certDaysLeft(new Date(Date.now() - 5 * 86400000).toISOString()) < 0);
    assert.equal(certDaysLeft(null), null);
  });
  test("newestCert picks latest not_after", () => {
    const rows = [
      { issuer_name: "A", not_after: "2025-01-01T00:00:00Z" },
      { issuer_name: "B", not_after: "2030-01-01T00:00:00Z" },
    ];
    assert.equal(newestCert(rows).issuer, "B");
    assert.equal(newestCert([]), null);
  });
  test("letterGrade bands", () => {
    assert.equal(letterGrade(95), "A");
    assert.equal(letterGrade(82), "B");
    assert.equal(letterGrade(70), "C");
    assert.equal(letterGrade(52), "D");
    assert.equal(letterGrade(20), "F");
    assert.equal(letterGrade(null), "N/A");
  });
});

group("posture: scoring", () => {
  const strongInput = {
    domain: "example.com", requestedUrl: "https://example.com", finalUrl: "https://example.com",
    headers: {
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
      "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
      "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin", "Permissions-Policy": "geolocation=()",
      "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp",
      "Cross-Origin-Resource-Policy": "same-origin",
    },
    spfTxts: ["v=spf1 include:_spf.example.com -all"], dmarcTxts: ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
    dkimSelectors: [{ selector: "google", present: true }],
    mtaStsTxts: ["v=STSv1; id=20260101"], mtaStsPolicy: "version: STSv1\nmode: enforce\nmax_age: 604800",
    tlsRptTxts: ["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"],
    cert: { issuer: "CN=E5, O=Let's Encrypt", notAfter: new Date(Date.now() + 60 * 86400000).toISOString(), names: "example.com\nwww.example.com" },
    securityTxt: { present: true },
  };

  test("strong site grades A with no failures", () => {
    const r = scorePosture(strongInput);
    assert.equal(r.grade, "A");
    assert.equal(r.counts.fail, 0);
  });

  test("weak site grades F with many failures", () => {
    const r = scorePosture({
      domain: "weak.test", requestedUrl: "http://weak.test", finalUrl: "http://weak.test",
      headers: {}, spfTxts: [], dmarcTxts: [], cert: null, securityTxt: { present: false },
    });
    assert.equal(r.grade, "F");
    assert.ok(r.counts.fail >= 4);
    assert.ok(r.topActions.length > 0);
  });

  test("header case-insensitivity", () => {
    const r = scorePosture({ ...strongInput, headers: { "content-security-policy": "default-src 'self'", "x-content-type-options": "nosniff", "strict-transport-security": "max-age=31536000", "x-frame-options": "DENY", "referrer-policy": "no-referrer", "permissions-policy": "camera=()" } });
    const headers = r.categories.find((c) => c.key === "headers");
    assert.ok(headers.checks.every((c) => c.status !== "fail"));
  });

  test("CSP with unsafe-inline warns not passes", () => {
    // Otherwise well-formed CSP whose only flaw is unsafe-inline in script-src:
    // deep grading keeps it out of "pass" because of the critical finding.
    const r = scorePosture({ ...strongInput, headers: { ...strongInput.headers, "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" } });
    const csp = r.categories.find((c) => c.key === "headers").checks.find((c) => c.name === "Content-Security-Policy");
    assert.equal(csp.status, "warn");
  });

  test("missing cert data does not sink the TLS category to 0", () => {
    const r = scorePosture({ ...strongInput, cert: null });
    const tls = r.categories.find((c) => c.key === "tls");
    assert.equal(tls.score, null); // NA, excluded from weighting
    assert.equal(r.grade, "A");
  });

  test("expired cert fails TLS category", () => {
    const r = scorePosture({ ...strongInput, cert: { issuer: "CN=E5", notAfter: new Date(Date.now() - 2 * 86400000).toISOString() } });
    const tls = r.categories.find((c) => c.key === "tls");
    assert.ok(tls.checks.some((c) => c.status === "fail"));
  });

  test("category weights sum to 100", () => {
    const r = scorePosture(strongInput);
    assert.equal(r.categories.reduce((a, c) => a + c.weight, 0), 100);
  });
});

group("posture: deep CSP grading", () => {
  test("parseCSP keeps the first occurrence of a directive", () => {
    const d = parseCSP("default-src 'self'; script-src 'self'; script-src 'unsafe-inline'");
    assert.equal(d["script-src"].join(" "), "'self'");
  });
  test("a locked-down CSP grades A", () => {
    const g = gradeCSPDeep("default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
    assert.equal(g.grade, "A");
  });
  test("unsafe-inline / unsafe-eval are flagged as critical", () => {
    const g = gradeCSPDeep("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'");
    assert.ok(g.findings.some((f) => /unsafe-inline/.test(f.msg) && f.sev === "critical"));
    assert.ok(g.findings.some((f) => /unsafe-eval/.test(f.msg)));
    assert.ok(g.grade === "D" || g.grade === "F");
  });
  test("wildcard script-src and missing object-src/base-uri are caught", () => {
    const g = gradeCSPDeep("default-src 'self'; script-src *");
    assert.ok(g.findings.some((f) => /wildcard/.test(f.msg)));
    assert.ok(g.findings.some((f) => /object-src/.test(f.msg)));
    assert.ok(g.findings.some((f) => /base-uri/.test(f.msg)));
  });
  test("absent CSP reports N/A, not a crash", () => {
    assert.equal(gradeCSPDeep("").grade, "N/A");
    assert.equal(gradeCSPDeep(null).present, false);
  });
  test("a deeply weak CSP header fails the headers category check", () => {
    const r = gradeHeaders({ headers: { "content-security-policy": "default-src *; script-src * 'unsafe-inline'" } });
    const csp = r.checks.find((c) => c.name === "Content-Security-Policy");
    assert.equal(csp.status, "fail");
  });
});

group("posture: cookie flags", () => {
  test("parseSetCookie reads Secure/HttpOnly/SameSite", () => {
    const c = parseSetCookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")[0];
    assert.ok(c.secure && c.httpOnly);
    assert.equal(c.sameSite, "lax");
  });
  test("parseSetCookie splits multiple cookies without breaking on Expires commas", () => {
    const list = parseSetCookie("a=1; Expires=Wed, 09 Jun 2025 10:18:14 GMT; Secure, b=2; HttpOnly");
    assert.equal(list.length, 2);
    assert.equal(list[0].name, "a");
    assert.ok(list[0].secure);
    assert.equal(list[1].name, "b");
    assert.ok(list[1].httpOnly);
  });
  test("a cookie missing Secure fails the headers cookie check", () => {
    const r = gradeHeaders({ headers: { "set-cookie": "sid=abc; Path=/; HttpOnly" } });
    const ck = r.checks.find((c) => c.name === "Cookie security");
    assert.equal(ck.status, "fail");
  });
  test("secure cookie missing HttpOnly/SameSite only warns", () => {
    const r = gradeHeaders({ headers: { "set-cookie": "sid=abc; Secure" } });
    const ck = r.checks.find((c) => c.name === "Cookie security");
    assert.equal(ck.status, "warn");
  });
  test("no Set-Cookie means no cookie check at all", () => {
    const r = gradeHeaders({ headers: {} });
    assert.notOk(r.checks.some((c) => c.name === "Cookie security"));
  });
});

group("posture: cross-origin headers", () => {
  test("COOP/COEP/CORP pass when set correctly", () => {
    const r = gradeHeaders({ headers: { "cross-origin-opener-policy": "same-origin", "cross-origin-embedder-policy": "require-corp", "cross-origin-resource-policy": "same-origin" } });
    for (const name of ["Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy"]) {
      assert.equal(r.checks.find((c) => c.name === name).status, "pass");
    }
  });
  test("missing cross-origin headers warn (not fail)", () => {
    const r = gradeHeaders({ headers: {} });
    for (const name of ["Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy"]) {
      assert.equal(r.checks.find((c) => c.name === name).status, "warn");
    }
  });
});

group("posture: email auth depth", () => {
  test("parseDMARC extracts rua, sp and pct", () => {
    const d = parseDMARC(["v=DMARC1; p=reject; sp=none; pct=25; rua=mailto:a@b.com; adkim=s"]);
    assert.equal(d.rua, "mailto:a@b.com");
    assert.equal(d.sp, "none");
    assert.equal(d.pct, 25);
    assert.equal(d.adkim, "s");
  });
  test("spfLookupCount tallies lookup mechanisms", () => {
    assert.equal(spfLookupCount("v=spf1 include:_spf.google.com a mx -all"), 3);
    assert.equal(spfLookupCount("v=spf1 ip4:1.2.3.4 -all"), 0);
    assert.equal(spfLookupCount("v=spf1 " + Array(11).fill("include:x.com").join(" ") + " -all"), 11);
  });
  test("SPF over the 10-lookup budget fails", () => {
    const r = gradeEmail({ spfTxts: ["v=spf1 " + Array(12).fill("include:x.com").join(" ") + " -all"], dmarcTxts: ["v=DMARC1; p=reject; rua=mailto:a@b.com"] });
    assert.equal(r.checks.find((c) => c.name === "SPF lookup budget").status, "fail");
  });
  test("a subdomain inherits its organizational domain's DMARC, graded on sp= when set", () => {
    const dm = (r) => r.checks.find((c) => c.name === "DMARC");
    const own = gradeEmail({ spfTxts: ["v=spf1 -all"], dmarcTxts: ["v=DMARC1; p=reject; sp=none; rua=mailto:a@b.com"] });
    assert.equal(dm(own).status, "pass");
    assert.ok(own.checks.some((c) => c.name === "DMARC subdomain policy"));      // sp=none weakens subdomains: flagged on the org domain
    const sub = gradeEmail({ spfTxts: ["v=spf1 -all"], dmarcTxts: ["v=DMARC1; p=reject; sp=none; rua=mailto:a@b.com"], dmarcFrom: "example.com" });
    assert.equal(dm(sub).status, "warn");                                         // for the subdomain itself sp=none is the policy
    assert.ok(/sp=none \(monitor only\) \(inherited from example\.com\)/.test(dm(sub).detail), dm(sub).detail);
    assert.notOk(sub.checks.some((c) => c.name === "DMARC subdomain policy"));
    const inh = gradeEmail({ spfTxts: ["v=spf1 -all"], dmarcTxts: ["v=DMARC1; p=reject; rua=mailto:a@b.com"], dmarcFrom: "example.com" });
    assert.equal(dm(inh).status, "pass");                                         // no sp: p applies
  });
  test("DMARC pct<100 and missing rua warn", () => {
    const r = gradeEmail({ spfTxts: ["v=spf1 -all"], dmarcTxts: ["v=DMARC1; p=reject; pct=50"] });
    assert.equal(r.checks.find((c) => c.name === "DMARC coverage (pct)").status, "warn");
    assert.equal(r.checks.find((c) => c.name === "DMARC reporting (rua)").status, "warn");
  });
  test("DKIM found on a probed selector passes; none probed is N/A", () => {
    const found = gradeEmail({ spfTxts: ["v=spf1 -all"], dmarcTxts: ["v=DMARC1; p=reject; rua=mailto:a@b.com"], dkimSelectors: [{ selector: "s1", present: false }, { selector: "s2", present: true }] });
    assert.equal(found.checks.find((c) => c.name === "DKIM").status, "pass");
    const none = gradeEmail({ spfTxts: ["v=spf1 -all"], dmarcTxts: ["v=DMARC1; p=reject; rua=mailto:a@b.com"], dkimSelectors: [{ selector: "s1", present: false }] });
    assert.equal(none.checks.find((c) => c.name === "DKIM").status, "na");
  });
  test("MTA-STS enforce passes; testing warns; absent warns", () => {
    const pass = parseMtaSts(["v=STSv1; id=1"], "version: STSv1\nmode: enforce\nmax_age: 604800");
    assert.equal(pass.mode, "enforce");
    const r = gradeEmail({ spfTxts: ["v=spf1 -all"], dmarcTxts: ["v=DMARC1; p=reject; rua=mailto:a@b.com"], mtaStsTxts: ["v=STSv1; id=1"], mtaStsPolicy: "mode: testing" });
    assert.equal(r.checks.find((c) => c.name === "MTA-STS").status, "warn");
    const absent = gradeEmail({ spfTxts: ["v=spf1 -all"], dmarcTxts: ["v=DMARC1; p=reject; rua=mailto:a@b.com"] });
    assert.equal(absent.checks.find((c) => c.name === "MTA-STS").status, "warn");
  });
  test("TLS-RPT present passes", () => {
    const r = gradeEmail({ spfTxts: ["v=spf1 -all"], dmarcTxts: ["v=DMARC1; p=reject; rua=mailto:a@b.com"], tlsRptTxts: ["v=TLSRPTv1; rua=mailto:t@b.com"] });
    assert.equal(r.checks.find((c) => c.name === "TLS-RPT").status, "pass");
  });
  test("a DNS lookup that failed is could-not-check, not a missing record", () => {
    const fail = () => Object.assign([], { failed: true });
    const r = gradeEmail({ spfTxts: fail(), dmarcTxts: fail(), mtaStsTxts: fail(), tlsRptTxts: fail() });
    for (const n of ["SPF", "DMARC", "MTA-STS", "TLS-RPT"]) assert.equal(r.checks.find((c) => c.name === n).status, "na", n);
    assert.equal(r.checks.filter((c) => c.status === "fail" || c.status === "warn").length, 0);
    const absent = gradeEmail({ spfTxts: [], dmarcTxts: [] });
    assert.equal(absent.checks.find((c) => c.name === "DMARC").status, "fail", "an answered empty lookup is still no record");
  });
  test("a failed lookup holds the last run's findings so they are not offered as fixed", () => {
    const base = { domain: "x.test", requestedUrl: "https://x.test", httpsOk: true, finalUrl: "https://x.test", headers: {}, securityTxt: { present: false } };
    const was = postureFindings(scorePosture({ ...base, spfTxts: ["v=spf1 ~all"], dmarcTxts: ["v=DMARC1; p=none"], cert: { issuer: "CN=R1", notAfter: new Date(Date.now() + 3 * 86400000).toISOString(), names: "x.test" } }));
    const now = scorePosture({ ...base, spfTxts: Object.assign([], { failed: true }), dmarcTxts: Object.assign([], { failed: true }), cert: null, certUnreachable: true });
    const held = new Set(postureHeld(now));
    const lost = was.filter((f) => /^posture\|x\.test\|(email|tls)\|/.test(f.id) && !postureFindings(now).some((g) => g.id === f.id));
    assert.ok(lost.length >= 3, "the run lost its email and certificate findings");
    for (const f of lost) assert.ok(held.has(f.id), f.id);
    assert.deepEqual(postureHeld(scorePosture({ ...base, spfTxts: [], dmarcTxts: [], cert: null })), [], "an answered lookup holds nothing");
  });
});

group("posture: certificate SAN coverage", () => {
  test("certCoversDomain handles exact, wildcard and apex", () => {
    assert.equal(certCoversDomain("example.com\nwww.example.com", "example.com"), true);
    assert.equal(certCoversDomain("*.example.com", "api.example.com"), true);
    assert.equal(certCoversDomain("*.example.com", "a.b.example.com"), false);
    assert.equal(certCoversDomain("other.com", "example.com"), false);
    assert.equal(certCoversDomain(null, "example.com"), null);
  });
  test("a cert that does not cover the domain warns", () => {
    const r = gradeTls({ domain: "example.com", cert: { issuer: "CN=E5", notAfter: new Date(Date.now() + 90 * 86400000).toISOString(), names: "other.com\nwww.other.com" }, now: Date.now() });
    assert.equal(r.checks.find((c) => c.name === "Name coverage").status, "warn");
  });
  test("the validity label is honest about CT-vs-served-leaf", () => {
    const r = gradeTls({ domain: "example.com", cert: { issuer: "CN=E5", notAfter: new Date(Date.now() + 90 * 86400000).toISOString(), names: "example.com" }, now: Date.now() });
    const v = r.checks.find((c) => c.name === "Certificate validity");
    assert.ok(/newest issued certificate/i.test(v.detail));
    assert.ok(/not necessarily the served leaf/i.test(v.detail));
  });
  test("weak SHA-1 signature fails when a CT source supplies it", () => {
    const r = gradeTls({ domain: "example.com", cert: { issuer: "CN=E5", notAfter: new Date(Date.now() + 90 * 86400000).toISOString(), names: "example.com", sigAlg: "sha1WithRSAEncryption" }, now: Date.now() });
    assert.equal(r.checks.find((c) => c.name === "Signature algorithm").status, "fail");
  });

  test("certDaysLeft reads zoneless crt.sh dates as UTC, not viewer-local (no timezone drift)", () => {
    const now = Date.UTC(2026, 0, 1, 0, 0, 0);
    assert.equal(certDaysLeft("2026-01-31T23:59:59", now), certDaysLeft("2026-01-31T23:59:59Z", now));
    assert.equal(certDaysLeft("2026-01-31T23:59:59Z", now), 30);
  });
});
