// Phishing / URL triage engine tests (public/js/dataprotect/phish-engine.js).

import { test, assert, group } from "../harness.mjs";
import {
  analyzeUrl, lookalike, extractIOCs, parseEmailHeaders, parseAuthResults,
  triageEmail, registrableDomain, domainOf, displayName, levenshtein, selfTest,
} from "../../public/js/dataprotect/phish-engine.js";

group("phish: engine self-test", () => {
  test("all in-engine self-test checks pass", () => {
    const r = selfTest();
    assert.ok(r.pass, "failures: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
});

group("phish: domain helpers", () => {
  test("registrableDomain handles multi-level suffixes", () => {
    assert.equal(registrableDomain("a.b.example.co.uk"), "example.co.uk");
    assert.equal(registrableDomain("mail.google.com"), "google.com");
    assert.equal(registrableDomain("example.com"), "example.com");
    assert.equal(registrableDomain("www.naver.co.kr"), "naver.co.kr");
    assert.equal(registrableDomain("shop.alibaba.com.cn"), "alibaba.com.cn");
    assert.equal(registrableDomain("a.b.site.com.br"), "site.com.br");
  });
  test("levenshtein", () => {
    assert.equal(levenshtein("paypal", "paypa1"), 1);
    assert.equal(levenshtein("", "abc"), 3);
  });
  test("domainOf and displayName", () => {
    assert.equal(domainOf('"Bank" <alerts@bank.com>'), "bank.com");
    assert.equal(displayName('"PayPal Service" <x@y.com>'), "PayPal Service");
  });
});

group("phish: URL analysis", () => {
  test("brand-in-subdomain impersonation", () => {
    const a = analyzeUrl("http://paypal.com.secure-login.ru/verify");
    assert.ok(a.lookalike.impersonation);
    assert.equal(a.lookalike.brand, "paypal");
    assert.ok(["high", "critical"].includes(a.severity));
  });
  test("typosquat near-miss", () => {
    const a = analyzeUrl("https://paypa1.com");
    assert.ok(a.lookalike.near);
    assert.equal(a.lookalike.brand, "paypal");
  });
  test("Plain HTTP is only flagged when the user actually typed http://", () => {
    // scheme-less input is auto-prefixed with http:// for parsing — do not flag it
    assert.notOk(analyzeUrl("example.com/login").reasons.some((r) => /Plain HTTP/.test(r.t)));
    // an explicit http:// URL is flagged
    assert.ok(analyzeUrl("http://example.com/login").reasons.some((r) => /Plain HTTP/.test(r.t)));
    // https is never flagged
    assert.notOk(analyzeUrl("https://example.com").reasons.some((r) => /Plain HTTP/.test(r.t)));
  });
  test("userinfo obfuscation + raw IP", () => {
    const a = analyzeUrl("http://support@198.51.100.9/login");
    assert.ok(a.reasons.some((r) => /Embedded credentials/.test(r.t)));
    assert.ok(a.reasons.some((r) => /raw IP/.test(r.t)));
  });
  test("punycode homograph", () => {
    const a = analyzeUrl("https://xn--pypal-4ve.com");
    assert.ok(a.reasons.some((r) => /Punycode/.test(r.t)));
  });
  test("risky TLD", () => {
    const a = analyzeUrl("https://invoice.zip");
    assert.ok(a.reasons.some((r) => /\.zip/.test(r.t)));
  });
  test("benign URL is low/info", () => {
    const a = analyzeUrl("https://github.com/org/repo");
    assert.ok(["info", "low"].includes(a.severity));
    assert.ok(!a.lookalike.impersonation);
  });
  test("unparseable URL", () => {
    const a = analyzeUrl("::::");
    assert.ok(a.reasons.length > 0);
  });
});

group("phish: lookalike", () => {
  test("exact brand is not flagged", () => {
    const l = lookalike("paypal.com");
    assert.ok(l.exact);
    assert.notOk(l.near);
    assert.notOk(l.impersonation);
  });
  test("non-brand is clean", () => {
    const l = lookalike("mycompany.com");
    assert.notOk(l.near);
    assert.notOk(l.impersonation);
  });
});

group("phish: IOC extraction", () => {
  test("defangs and extracts", () => {
    const ioc = extractIOCs("visit hxxps://bad[.]example[.]com/x, ip 203.0.113.7, mail a@b.com, " + "d".repeat(40));
    assert.ok(ioc.urls.some((u) => u.includes("bad.example.com")));
    assert.ok(ioc.ips.includes("203.0.113.7"));
    assert.ok(ioc.emails.includes("a@b.com"));
    assert.ok(ioc.hashes.some((h) => h.length === 40));
  });
  test("ignores asset-like domains", () => {
    const ioc = extractIOCs("logo.png and real.example.org");
    assert.ok(ioc.domains.includes("real.example.org"));
    assert.ok(!ioc.domains.some((d) => d.endsWith(".png")));
  });
});

group("phish: email parsing and triage", () => {
  test("parses folded headers and splits body", () => {
    const { headers, body, hasHeaders } = parseEmailHeaders("From: a@b.com\nSubject: hello\n world\n\nthe body");
    assert.ok(hasHeaders);
    assert.equal(headers.subject[0], "hello world");
    assert.equal(body, "the body");
  });
  test("parseAuthResults", () => {
    const a = parseAuthResults("mx.google.com; spf=pass; dkim=fail (bad sig); dmarc=pass");
    assert.equal(a.spf, "pass");
    assert.equal(a.dkim, "fail");
    assert.equal(a.dmarc, "pass");
  });
  test("phishing email scores high risk", () => {
    const r = triageEmail([
      'From: "PayPal" <service@paypa1-secure.com>',
      "Return-Path: <bounce@mailer.ru>",
      "Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail",
      "Subject: Verify now", "", "Go to http://paypal.com.secure.ru/verify",
    ].join("\n"));
    assert.ok(["suspicious", "high-risk"].includes(r.verdict.level));
    assert.equal(r.fromReg, "paypa1-secure.com");
    assert.ok(r.findings.some((f) => /DMARC failed/.test(f.t)));
  });
  test("aligned, DMARC-passing email is likely legitimate", () => {
    const r = triageEmail([
      "From: Billing <billing@example.com>",
      "Return-Path: <billing@example.com>",
      "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass",
      "Subject: Receipt", "", "Thanks.",
    ].join("\n"));
    assert.equal(r.verdict.level, "likely-legitimate");
  });
  test("DMARC pass does NOT whitewash a message linking to a lookalike domain", () => {
    // The From domain is clean and passes its own DMARC, but the body links to a
    // typosquat of a real brand. A medium-severity lookalike link does not lift the
    // numeric score, so the old `dmarc=pass && weight<3` shortcut wrongly called this
    // "likely legitimate". The spoof veto must prevent that.
    const r = triageEmail([
      "From: Support <support@example.com>",
      "Return-Path: <support@example.com>",
      "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass",
      "Subject: Please confirm", "", "Sign in at https://paypa1.com/login to continue.",
    ].join("\n"));
    assert.equal(r.auth.dmarc, "pass");
    assert.ok(r.spoof, "a lookalike link should set the spoof veto");
    assert.notEqual(r.verdict.level, "likely-legitimate");
  });
  test("display-name brand spoof with mismatched domain flagged", () => {
    const r = triageEmail([
      'From: "Microsoft Account Team" <no-reply@account-security-check.com>',
      "Authentication-Results: mx; dmarc=none", "", "Sign in.",
    ].join("\n"));
    assert.ok(r.findings.some((f) => /Display name mentions/.test(f.t)));
  });
});
