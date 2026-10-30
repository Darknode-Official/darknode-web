// Data-protection engine audit: each test pins one reproduced bug (wrong verdict,
// missed real-format item, or quadratic regex on a 50 KB input).

import { test, assert, group } from "../harness.mjs";
import { scan } from "../../public/js/dataprotect/dlp-engine.js";
import { parseDMARC, gradeEmail, gradeHeaders, gradeTls, certDaysLeft } from "../../public/js/dataprotect/posture-engine.js";
import { issuerLabel } from "../../public/js/dataprotect/tls-engine.js";
import { classifyKey, gradeCors, gradeErrorLeak, gradeRouteResponse } from "../../public/js/dataprotect/leakprobe-engine.js";
import { registrableDomain, extractIOCs, defangText, triageEmail } from "../../public/js/dataprotect/phish-engine.js";

const fast = (fn, ms = 300) => { const t0 = Date.now(); fn(); return Date.now() - t0 < ms; };

group("dataprotect audit", () => {
  test("DLP email detector stays linear on a 50 KB run with no @ (was ~2 s, quadratic)", () => {
    assert.ok(fast(() => scan("1-".repeat(25000) + "x", { detectors: ["email"] })));
    assert.deepEqual(scan("mail test@darknode.ai, first.last+tag@sub.example.co.uk.", { detectors: ["email"] }).findings.map((f) => f.value), ["test@darknode.ai", "first.last+tag@sub.example.co.uk"]);
  });

  test("phish IOC extraction and defang stay linear on 50 KB dotted runs (was ~3.5 s)", () => {
    const dots = "1.".repeat(25000);
    assert.ok(fast(() => extractIOCs(dots)));
    assert.ok(fast(() => defangText(dots)));
    assert.ok(fast(() => triageEmail("From: <test@darknode.ai>\n\n" + "a.".repeat(25000))));
    const r = extractIOCs("see sub.example.com and test@darknode.ai");
    assert.deepEqual(r.emails, ["test@darknode.ai"]);
    assert.ok(r.domains.includes("sub.example.com"));
  });

  test("LEAKPROBE stack-path pattern stays linear on a 50 KB path (was ~1.3 s)", () => {
    assert.ok(fast(() => gradeErrorLeak("/a".repeat(25000))));
    assert.ok(gradeErrorLeak("Error at /srv/app/src/routes/api.js:42").signals.some((s) => s.kind === "stack"));
  });

  test("DMARC record with whitespace around = (RFC 7489 ABNF) is read, not reported missing", () => {
    const d = parseDMARC(["v = DMARC1; p=reject; rua=mailto:test@darknode.ai"]);
    assert.ok(d.present);
    assert.equal(d.policy, "reject");
  });

  test("SPF that delegates with redirect= is not described as ending in ?all", () => {
    const c = gradeEmail({ spfTxts: ["v=spf1 redirect=_spf.example.com"] }).checks.find((x) => x.name === "SPF");
    assert.ok(/redirect=_spf\.example\.com/.test(c.detail));
    assert.ok(!/\?all/.test(c.detail));
  });

  test("a version in X-Powered-By is flagged even when Server has none", () => {
    const v = gradeHeaders({ headers: { server: "nginx", "x-powered-by": "PHP/8.1.2" } }).checks.find((c) => c.name === "Version disclosure");
    assert.ok(v && v.status === "warn");
  });

  test("an ECDSA P-256 / P-384 key is not called weak RSA; RSA-1024 and RSA-512 still are", () => {
    const ks = (k) => gradeTls({ cert: { notAfter: "2099-01-01", keySize: k }, domain: "example.com" }).checks.find((c) => c.name === "Key strength").status;
    assert.equal(ks(256), "pass");
    assert.equal(ks(384), "pass");
    assert.equal(ks(1024), "warn");
    assert.equal(ks(512), "warn");
  });

  test("zoneless ISO with fractional seconds is read as UTC like the plain form", () => {
    const now = Date.UTC(2026, 0, 14, 0, 0, 0);
    assert.equal(certDaysLeft("2026-01-14T23:59:59.000", now), certDaysLeft("2026-01-14T23:59:59", now));
    assert.equal(certDaysLeft("2026-01-14T23:59:59.000", now), 0);
  });

  test("issuerLabel keeps a quoted organisation that contains a comma", () => {
    assert.equal(issuerLabel('C=US, O="Example, Inc.", CN=Example CA'), "Example, Inc.");
    assert.equal(issuerLabel("C=US, O=Example Trust, CN=R3"), "Example Trust");
  });

  test("a Stripe restricted live key (rk_live_) is a secret, not a publishable key", () => {
    const c = classifyKey({ id: "stripe-key", value: "rk_live_" + "a1B2".repeat(6), where: "client-asset" });
    assert.equal(c.exposure, "secret");
    assert.ok(c.insecure);
  });

  test("ACAO: null with credentials is not graded as scoped CORS", () => {
    assert.equal(gradeCors({ "Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true" }, "https://test.example").level, "warning");
    assert.equal(gradeCors({ "Access-Control-Allow-Origin": "https://app.example.com" }, "https://test.example").level, "pass");
  });

  test("a served .env with prefixed names (DB_PASSWORD=, SESSION_SECRET=) is a hit", () => {
    assert.ok(gradeRouteResponse("/.env", 200, "NODE_ENV=production\nDB_PASSWORD=changeme\n").hit);
    assert.ok(gradeRouteResponse("/.env", 200, "export SESSION_SECRET=abc\n").hit);
    assert.ok(!gradeRouteResponse("/debug", 200, "status: ok\nuptime: 42\n").hit);
  });

  test("registrableDomain knows common ccTLD second levels (co.th, com.pk, com.ng, co.ke, co.at)", () => {
    for (const [h, r] of [["a.example.co.th", "example.co.th"], ["www.example.com.pk", "example.com.pk"], ["sub.example.com.ng", "example.com.ng"], ["example.co.ke", "example.co.ke"], ["x.example.co.at", "example.co.at"]]) {
      assert.equal(registrableDomain(h), r, h);
    }
    // before: both collapsed to "co.th", so a Reply-To on a stranger's domain looked aligned
    const t = triageEmail("From: <test@mail.example.co.th>\nReply-To: <test@other.co.th>\nSubject: x\n\nhi");
    assert.ok(t.findings.some((f) => /Reply-To domain/.test(f.t)));
  });
});

group("phish-engine: non-web links, posture cleanDomain", () => {
  test("javascript:/data:/file: links get their own verdict, not 'Unparseable URL'", async () => {
    const { analyzeUrl } = await import("../../public/js/dataprotect/phish-engine.js");
    assert.equal(analyzeUrl("javascript:alert(1)").severity, "critical");
    assert.equal(analyzeUrl("data:text/html;base64,PGgxPg==").severity, "high");
    assert.equal(analyzeUrl("file:///etc/passwd").severity, "medium");
    assert.ok(!analyzeUrl("data:text/html,x").reasons.some((r) => /Unparseable/.test(r.t)));
    assert.equal(analyzeUrl("https://example.com/").severity, "info");
  });
  test("cleanDomain keeps the host after the LAST @", async () => {
    const { cleanDomain } = await import("../../public/js/dataprotect/posture-collect.js");
    assert.equal(cleanDomain("https://test@darknode.ai@example.com/"), "example.com");
    assert.equal(cleanDomain("test@darknode.ai"), "darknode.ai");
  });
});
