// External Posture Scorecard engine tests (public/js/dataprotect/posture-engine.js):
// deterministic grading of transport, headers, email auth, TLS and disclosure.

import { test, assert, group } from "../harness.mjs";
import {
  scorePosture, parseHSTS, parseSPF, parseDMARC, certDaysLeft, newestCert, letterGrade, selfTest, gradeTransport,
} from "../../public/js/dataprotect/posture-engine.js";

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
      "Content-Security-Policy": "default-src 'self'",
      "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin", "Permissions-Policy": "geolocation=()",
    },
    spfTxts: ["v=spf1 include:_spf.example.com -all"], dmarcTxts: ["v=DMARC1; p=reject"],
    cert: { issuer: "CN=E5, O=Let's Encrypt", notAfter: new Date(Date.now() + 60 * 86400000).toISOString() },
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
    const r = scorePosture({ ...strongInput, headers: { ...strongInput.headers, "Content-Security-Policy": "default-src 'self' 'unsafe-inline'" } });
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
