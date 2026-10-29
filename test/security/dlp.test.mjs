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
      "sk_" + "live_exampletokenabcd12345678", // real live keys carry 24+ characters after the prefix
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36P", // darknode-ignore: planted fake JWT for the DLP detector test
    ].join("\n"));
    for (const id of ["github-token", "slack-token", "stripe-key", "jwt"]) {
      assert.ok(r.findings.some((f) => f.id === id), "missing " + id);
    }
  });
  test("detects DB connection string and masks password", () => {
    const c = scan("DATABASE_URL=postgres://admin:s3cretP@ss@db.internal:5432/app").findings.find((f) => f.id === "conn-string"); // darknode-ignore: planted fake database URL for the DLP detector test
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
  test("us-phone matches a valid NANP number but not an arbitrary digit run", () => {
    assert.ok(scan("call 415 555 0172 today").findings.some((f) => f.id === "us-phone"));
    assert.ok(scan("call (415) 555-0172 today").findings.some((f) => f.id === "us-phone"));
    // area code starting with 1 is not a valid NANP area code
    assert.notOk(scan("ref 123 456 7890 end").findings.some((f) => f.id === "us-phone"));
    // exchange starting with 0/1 is invalid
    assert.notOk(scan("ref 415 055 0172 end").findings.some((f) => f.id === "us-phone"));
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
  test("high-entropy sweep skips labelled digests but keeps unlabelled or credential-labelled hex", () => {
    const he = (t) => scan(t).findings.some((f) => f.id === "high-entropy");
    const h64 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    for (const t of ["commit 3b54462b9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e", "sha256: " + h64, "image@sha256:" + h64, "MD5 (a.iso) = d41d8cd98f00b204e9800998ecf8427e",
      '"integrity": "sha512-Vq2UZRvn6q3Ylyh6s3U6YUMm3l9+ZL2vhyc1A6Ow2HPdS0ZdYC8pxfCNqx7pLgOU8u+9N8uwW1d8K6x3E7UCQ=="']) assert.notOk(he(t), t);
    for (const t of ["token 3b54462b9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e", "api_key=3b54462b9f1c2d3e4f5a6b7c8d9e0f1a", "password_hash: 5f4dcc3b5aa765d61d8327deb882cf995f4dcc3b"]) assert.ok(he(t), t);
  });
  test("detectors filter narrows scan", () => {
    const r = scan("bob@corp.com AKIAIOSFODNN7EXAMPLE", { detectors: ["email"] });
    assert.ok(r.findings.every((f) => f.id === "email"));
  });
});

group("dlp: new secret detectors", () => {
  const has = (text, id, opts) => scan(text, opts).findings.some((f) => f.id === id);

  test("Azure storage account key — positive and negative", () => {
    const key = "A".repeat(86) + "==";
    assert.ok(has("DefaultEndpointsProtocol=https;AccountKey=" + key + ";", "azure-storage-key"));
    assert.notOk(has("AccountKey=tooShortForARealKey==", "azure-storage-key"));
  });
  test("Azure SAS token — positive and negative", () => {
    assert.ok(has("https://a.blob.core.windows.net/c/b?sv=2021-08-06&sp=r&sig=aB3dEf9GhiJkl012MnO%3D", "azure-sas"));
    // sv date present but no sig param => not a SAS token
    assert.notOk(has("endpoint?sv=2021-08-06&sp=rwl", "azure-sas"));
  });
  test("Azure AD client secret — positive and negative", () => {
    assert.ok(has("CLIENT_SECRET=abc8Q~" + "a".repeat(34), "azure-ad-secret"));
    assert.notOk(has("just a normal sentence with no secret here at all", "azure-ad-secret"));
  });
  test("GitLab PAT — positive and negative", () => {
    assert.ok(has("token=glpat-ABCDEFGHIJ0123456789", "gitlab-pat"));
    assert.notOk(has("token=glpat-short", "gitlab-pat"));
  });
  test("npm token — positive and negative", () => {
    assert.ok(has("//registry.npmjs.org/:_authToken=npm_" + "a".repeat(36), "npm-token"));
    assert.notOk(has("npm_tooshort", "npm-token"));
  });
  test("Hugging Face token — positive and negative", () => {
    assert.ok(has("HF_TOKEN=hf_" + "aB3dE6gH9j".repeat(4), "huggingface-token"));
    assert.notOk(has("hf_short_name", "huggingface-token"));
  });
  test("GCP service-account key — positive and negative", () => {
    const json = '{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\\nMIIBVAIBADANBgkq\\n-----END PRIVATE KEY-----\\n","client_email":"svc@proj.iam.gserviceaccount.com"}';
    assert.ok(has(json, "gcp-service-account"));
    // a private key with no gserviceaccount context is NOT a GCP SA key (falls to private-key)
    assert.notOk(has("-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkq\n-----END PRIVATE KEY-----", "gcp-service-account"));
  });
  test("Heroku API key — positive and negative", () => {
    assert.ok(has("HEROKU_API_KEY=12345678-1234-1234-1234-123456789abc", "heroku-key"));
    // a bare UUID with no heroku context is not flagged as a Heroku key
    assert.notOk(has("request id 12345678-1234-1234-1234-123456789abc done", "heroku-key"));
  });
  test("DigitalOcean token — positive and negative", () => {
    assert.ok(has("DO_TOKEN=dop_v1_" + "a".repeat(64), "digitalocean-token"));
    assert.notOk(has("dop_v1_deadbeef", "digitalocean-token"));
  });
  test("Bearer / Authorization token — positive and negative", () => {
    assert.ok(has("Authorization: Bearer abcDEF123ghiJKL456mnoP", "bearer-auth"));
    assert.notOk(has("Authorization: Bearer short", "bearer-auth"));
    assert.notOk(has("Authorization: Bearer your-token-goes-here", "bearer-auth"));
  });
  test("Mailgun key — positive and negative", () => {
    assert.ok(has("MAILGUN=key-" + "0123456789abcdef".repeat(2), "mailgun-key"));
    assert.notOk(has("key-nothex-value-here", "mailgun-key"));
  });
  test("PlanetScale token — positive and negative", () => {
    assert.ok(has("DATABASE_PASSWORD=pscale_pw_" + "aB3dEf".repeat(6), "planetscale-token"));
    assert.notOk(has("pscale_pw_short", "planetscale-token"));
  });
  test("Slack app-level token — positive and negative", () => {
    assert.ok(has("SLACK_APP_TOKEN=xapp-1-A01234ABCDE-1234567890-abcdef0123456789", "slack-app-token"));
    assert.notOk(has("xapp-notarealapptoken", "slack-app-token"));
  });
});

group("dlp: ipv4 private-IP allowlist", () => {
  const hasIp = (text, opts) => scan(text, opts).findings.some((f) => f.id === "ipv4");

  test("default flags private and public IPs (current behavior)", () => {
    assert.ok(hasIp("internal host 10.1.2.3"));
    assert.ok(hasIp("router 192.168.0.1"));
    assert.ok(hasIp("resolver 8.8.8.8"));
  });
  test("allowlist drops RFC1918, loopback-equivalent and link-local", () => {
    const o = { excludePrivateIp: true };
    assert.notOk(hasIp("internal host 10.1.2.3", o));
    assert.notOk(hasIp("router 192.168.0.1", o));
    assert.notOk(hasIp("nat 172.16.5.9", o));
    assert.notOk(hasIp("apipa 169.254.1.1", o));
  });
  test("allowlist keeps genuine public IPs", () => {
    assert.ok(hasIp("resolver 8.8.8.8", { excludePrivateIp: true }));
    assert.ok(hasIp("edge 203.0.113.42", { excludePrivateIp: true }));
  });
  test("allowlist ignores IPs inside version strings", () => {
    const o = { excludePrivateIp: true };
    assert.notOk(hasIp("running version 11.22.33.44 of the agent", o));
    assert.notOk(hasIp("build 200.100.50.25 shipped", o));
  });
  test("172.x outside the private block is still flagged with allowlist on", () => {
    assert.ok(scan("public 172.32.0.1 host", { excludePrivateIp: true }).findings.some((f) => f.id === "ipv4"));
  });
});

group("dlp: detector toggles and entropy threshold", () => {
  test("opts.detectors filters to only the enabled ids", () => {
    const text = "glpat-ABCDEFGHIJ0123456789 and bob@corp.com and AKIAIOSFODNN7EXAMPLE";
    const r = scan(text, { detectors: ["gitlab-pat", "email"] });
    assert.ok(r.findings.length > 0);
    assert.ok(r.findings.every((f) => f.id === "gitlab-pat" || f.id === "email"));
    assert.notOk(r.findings.some((f) => f.id === "aws-key"));
  });
  test("disabling high-entropy suppresses the sweep", () => {
    const blob = "config dGhpc0lzQVZlcnlMb25nUmFuZG9tQmFzZTY0VG9rZW5YWVo=";
    assert.ok(scan(blob).findings.some((f) => f.id === "high-entropy"));
    assert.notOk(scan(blob, { detectors: ["email"] }).findings.some((f) => f.id === "high-entropy"));
  });
  test("raising the entropy threshold suppresses borderline tokens", () => {
    const blob = "token dGhpc0lzQVZlcnlMb25nUmFuZG9tQmFzZTY0VG9rZW5YWVo=";
    const low = scan(blob, { entropyThreshold: 3.5 }).findings.filter((f) => f.id === "high-entropy").length;
    const high = scan(blob, { entropyThreshold: 5.9 }).findings.filter((f) => f.id === "high-entropy").length;
    assert.ok(low >= 1);
    assert.ok(high < low);
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

  test("a real PAN is still found when extra digits are glued to the greedy match", () => {
    assert.ok(scan("card 4111 1111 1111 1111 end").findings.some((f) => f.id === "credit-card"));      // control: standalone
    assert.ok(scan("pan 4111 1111 1111 1111 999 trailing").findings.some((f) => f.id === "credit-card")); // card + adjacent number
    assert.ok(scan("ref 999 4111 1111 1111 1111 x").findings.some((f) => f.id === "credit-card"));      // number + card
  });

  test("card hits cover only the card: no trailing space, no glued neighbour number", () => {
    const one = (t) => scan(t).findings.find((f) => f.id === "credit-card");
    assert.equal(one("pay 4111 1111 1111 1111 now").value, "4111 1111 1111 1111");
    assert.equal(redact("pay 4111 1111 1111 1111 now", scan("pay 4111 1111 1111 1111 now").findings), "pay [REDACTED:credit-card] now");
    assert.equal(one("pan 4111 1111 1111 1111 999 x").value, "4111 1111 1111 1111");
    assert.equal(one("ref 999 4111 1111 1111 1111 x").value, "4111 1111 1111 1111");
    const t = "card 4111111111111111 999";
    assert.equal(redact(t, scan(t).findings), "card [REDACTED:credit-card] 999");
  });
});
