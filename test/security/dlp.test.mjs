// Data Protection (DLP) engine tests (public/js/dataprotect/dlp-engine.js):
// deterministic secret + PII detection, validation gating, redaction.

import { test, assert, group } from "../harness.mjs";
import {
  scan, redact, selfTest, luhnValid, ibanValid, ssnValid, shannonEntropy, cardBrand, maskValue,
} from "../../public/js/dataprotect/dlp-engine.js";

group("dlp: engine self-test", () => {
  test("all in-engine self-test checks pass", () => {
    const r = selfTest();
    assert.ok(r.pass, "failures: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
});

group("dlp: validators", () => {
  test("luhn accepts valid cards, rejects mutated", () => {
    assert.ok(luhnValid("4111111111111111"));
    assert.ok(luhnValid("5500005555555559"));
    assert.ok(luhnValid("378282246310005"));
    assert.notOk(luhnValid("4111111111111112"));
    assert.notOk(luhnValid("1234567890123"));
  });
  test("card brand detection", () => {
    assert.equal(cardBrand("4111111111111111"), "Visa");
    assert.equal(cardBrand("5500005555555559"), "Mastercard");
    assert.equal(cardBrand("378282246310005"), "American Express");
    assert.equal(cardBrand("6011000990139424"), "Discover");
  });
  test("IBAN mod-97", () => {
    assert.ok(ibanValid("DE89370400440532013000"));
    assert.ok(ibanValid("GB82 WEST 1234 5698 7654 32"));
    assert.notOk(ibanValid("GB82 WEST 1234 5698 7654 33"));
    assert.notOk(ibanValid("DE00370400440532013000"));
  });
  test("SSN structural rules", () => {
    assert.ok(ssnValid("123-45-6789"));
    assert.notOk(ssnValid("000-45-6789"));
    assert.notOk(ssnValid("666-45-6789"));
    assert.notOk(ssnValid("900-45-6789"));
    assert.notOk(ssnValid("123-00-6789"));
    assert.notOk(ssnValid("123-45-0000"));
  });
  test("entropy separates prose from tokens", () => {
    assert.ok(shannonEntropy("the quick brown fox jumps") < 4.2);
    assert.ok(shannonEntropy("wJalrXUtnFEMIK7MDENGbPxRfiCYz1a9") > 4.0);
  });
});

group("dlp: detectors", () => {
  test("detects AWS key id and secret", () => {
    const r = scan('key=AKIAIOSFODNN7EXAMPLE secret aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"');
    assert.ok(r.findings.some((f) => f.id === "aws-key"));
    assert.ok(r.findings.some((f) => f.id === "aws-secret"));
  });
  test("detects payment card with brand", () => {
    const c = scan("pay with 4111 1111 1111 1111 please").findings.find((f) => f.id === "credit-card");
    assert.ok(c);
    assert.equal(c.detail, "Visa");
  });
  test("does not flag random 16-digit non-Luhn as card", () => {
    assert.notOk(scan("order 1234567890123456 ref").findings.some((f) => f.id === "credit-card"));
  });
  test("detects private key block once", () => {
    const r = scan("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKxyz\n-----END RSA PRIVATE KEY-----");
    assert.equal(r.findings.filter((f) => f.id === "private-key").length, 1);
    assert.equal(r.bySeverity.critical, 1);
  });
  test("detects github, slack, stripe, jwt tokens", () => {
    const r = scan([
      "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
      "xoxb-fakeexampletoken-notarealslacksecret",
      "sk_live_exampletokenabcd1234",
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36P",
    ].join("\n"));
    for (const id of ["github-token", "slack-token", "stripe-key", "jwt"]) {
      assert.ok(r.findings.some((f) => f.id === id), "missing " + id);
    }
  });
  test("detects DB connection string and masks password", () => {
    const c = scan("DATABASE_URL=postgres://admin:s3cretP@ss@db.internal:5432/app").findings.find((f) => f.id === "conn-string");
    assert.ok(c);
    assert.notOk(c.masked.includes("s3cret"));
  });
  test("ignores placeholder secrets", () => {
    const r = scan('password = "changeme"\napi_key = "your-key-here"\ntoken: "${TOKEN}"');
    assert.notOk(r.findings.some((f) => f.id === "pat-assignment"));
  });
  test("email excludes asset filenames", () => {
    const emails = scan("see logo@2x.png and real user bob@corp.com").findings.filter((f) => f.id === "email").map((f) => f.value);
    assert.ok(emails.includes("bob@corp.com"));
    assert.notOk(emails.some((e) => e.endsWith(".png")));
  });
  test("line and column are reported", () => {
    const f = scan("line one\nline two AKIAIOSFODNN7EXAMPLE here").findings.find((x) => x.id === "aws-key");
    assert.equal(f.line, 2);
    assert.ok(f.col > 1);
  });
  test("high-entropy sweep flags unknown blob, not prose", () => {
    assert.ok(scan("config blob dGhpc0lzQVZlcnlMb25nUmFuZG9tQmFzZTY0VG9rZW5YWVo=").findings.some((f) => f.id === "high-entropy"));
    assert.notOk(scan("the quick brown fox jumps over the lazy dog again and again").findings.some((f) => f.id === "high-entropy"));
  });
  test("detectors filter narrows scan", () => {
    const r = scan("bob@corp.com AKIAIOSFODNN7EXAMPLE", { detectors: ["email"] });
    assert.ok(r.findings.every((f) => f.id === "email"));
  });
});

group("dlp: redaction and summary", () => {
  test("redaction removes every finding value", () => {
    const text = "card 4111 1111 1111 1111 ssn 123-45-6789 key AKIAIOSFODNN7EXAMPLE";
    const red = redact(text, scan(text).findings);
    for (const f of scan(text).findings) assert.notOk(red.includes(f.value), "leaked " + f.id);
    assert.ok(red.includes("[REDACTED:"));
  });
  test("mask redaction keeps tail", () => {
    const m = maskValue("AKIAIOSFODNN7EXAMPLE");
    assert.ok(m.endsWith("MPLE"));
    assert.ok(m.includes("•"));
  });
  test("summary grade reflects worst severity", () => {
    assert.equal(scan("bob@corp.com").grade, "low");
    assert.equal(scan("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789").grade, "critical");
    assert.equal(scan("nothing sensitive here at all").grade, "clean");
  });
});
