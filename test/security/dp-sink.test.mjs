// Data-protection -> Security Graph mapper tests (public/js/dataprotect/dp-sink.js):
// posture / tlsfleet publish only failing or warning checks, phishtriage only medium+
// items, severities normalise to the sink scale, keys are stable across re-runs, and
// DLP never writes a matched value into the graph payload.

import { test, assert, group } from "../harness.mjs";
import { postureFindings, tlsFleetFindings, phishUrlFindings, phishEmailFindings, dlpFindings, dlpSample } from "../../public/js/dataprotect/dp-sink.js";
import { scorePosture } from "../../public/js/dataprotect/posture-engine.js";
import { buildEntry } from "../../public/js/dataprotect/tls-engine.js";
import { analyzeUrl, triageEmail } from "../../public/js/dataprotect/phish-engine.js";
import { scan } from "../../public/js/dataprotect/dlp-engine.js";
import { toEntities, findingKey, SEVERITIES } from "../../public/js/core/sink-map.js";

const DAY = 86400000;
const NOW = Date.UTC(2026, 9, 13, 12, 0, 0);
const keys = (tool, fs) => fs.map((f) => findingKey(tool, f)).sort();
const validSev = (fs) => fs.every((f) => SEVERITIES.includes(f.severity));

// ---- posture
const STRONG_HEADERS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
  "content-security-policy": "default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
  "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "strict-origin",
  "permissions-policy": "geolocation=()", "cross-origin-opener-policy": "same-origin",
  "cross-origin-embedder-policy": "require-corp", "cross-origin-resource-policy": "same-origin",
};
const strongInput = () => ({
  domain: "strong.test", requestedUrl: "https://strong.test", finalUrl: "https://strong.test", httpsOk: true,
  headers: STRONG_HEADERS, spfTxts: ["v=spf1 -all"], dmarcTxts: ["v=DMARC1; p=reject; rua=mailto:d@strong.test"],
  dkimSelectors: [{ selector: "default", present: true }],
  mtaStsTxts: ["v=STSv1; id=1"], mtaStsPolicy: "version: STSv1\nmode: enforce\nmax_age: 604800",
  tlsRptTxts: ["v=TLSRPTv1; rua=mailto:t@strong.test"],
  cert: { issuer: "CN=E5", notAfter: new Date(NOW + 60 * DAY).toISOString(), names: "strong.test" },
  securityTxt: { present: true }, now: NOW,
});
const weakInput = () => ({ domain: "weak.test", requestedUrl: "http://weak.test", finalUrl: "http://weak.test", headers: {}, spfTxts: [], dmarcTxts: ["v=DMARC1; p=none"], cert: null, securityTxt: { present: false }, now: NOW });

group("dp-sink: posture", () => {
  test("passes are excluded; a clean domain yields no findings", () => {
    const res = scorePosture(strongInput());
    const all = res.categories.flatMap((c) => c.checks);
    assert.ok(all.some((c) => c.status === "pass"));
    const out = postureFindings(res);
    const failWarn = all.filter((c) => c.status === "fail" || c.status === "warn").length;
    assert.equal(out.length, failWarn);
  });
  test("every fail/warn check becomes a finding on the domain asset", () => {
    const res = scorePosture(weakInput());
    const out = postureFindings(res);
    assert.equal(out.length, res.counts.fail + res.counts.warn);
    assert.ok(out.every((f) => f.assets.length === 1 && f.assets[0].type === "DOMAIN" && f.assets[0].name === "weak.test"));
    assert.ok(!out.some((f) => f.tags.includes("pass")));
  });
  test("severity normalises: warn->low, fail->medium, primary-defence fail->high", () => {
    const out = postureFindings(scorePosture(weakInput()));
    assert.ok(validSev(out));
    assert.equal(out.find((f) => f.title.startsWith("HTTPS issue")).severity, "high");
    assert.equal(out.find((f) => f.title.startsWith("X-Content-Type-Options")).severity, "medium");
    assert.equal(out.find((f) => f.title.startsWith("DMARC issue")).severity, "low"); // p=none is a warn
  });
  test("keys and titles are stable across re-runs, even when a check changes status", () => {
    assert.deepEqual(keys("posture", postureFindings(scorePosture(weakInput()))), keys("posture", postureFindings(scorePosture(weakInput()))));
    const a = postureFindings(scorePosture({ ...weakInput(), dmarcTxts: ["v=DMARC1; p=none"] })).find((f) => f.title.startsWith("DMARC issue"));
    const b = postureFindings(scorePosture({ ...weakInput(), dmarcTxts: [] })).find((f) => f.title.startsWith("DMARC issue"));
    assert.equal(findingKey("posture", a), findingKey("posture", b));
    assert.equal(a.title, b.title);
    assert.ok(a.severity !== b.severity);
  });
});

// ---- tlsfleet
const entry = (domain, days, hsts) => { const e = buildEntry(domain, [{ issuer_name: "C=US, O=Test CA, CN=R1", not_after: new Date(NOW + days * DAY).toISOString() }], NOW); e.hsts = hsts; return e; };

group("dp-sink: tlsfleet", () => {
  test("bands map to severities; OK, unknown and pending entries are excluded", () => {
    const out = tlsFleetFindings([
      entry("expired.test", -2, true), entry("urgent.test", 5, true), entry("soon.test", 20, true),
      entry("watch.test", 45, true), entry("fine.test", 200, true), buildEntry("nodata.test", [], NOW),
      { domain: "pending.test", pending: true },
    ]);
    const by = Object.fromEntries(out.map((f) => [f.assets[0].name, f.severity]));
    assert.deepEqual(by, { "expired.test": "critical", "urgent.test": "high", "soon.test": "medium", "watch.test": "low" });
    assert.ok(validSev(out));
  });
  test("HSTS confirmed absent is a finding; unknown HSTS is not", () => {
    const out = tlsFleetFindings([entry("a.test", 200, false), entry("b.test", 200, null)]);
    assert.equal(out.length, 1);
    assert.equal(out[0].title, "HSTS not served on a.test");
  });
  test("expiry key and title stay stable as the days count down", () => {
    const a = tlsFleetFindings([entry("x.test", 25, true)])[0];
    const b = tlsFleetFindings([entry("x.test", 3, true)])[0];
    assert.equal(findingKey("tlsfleet", a), findingKey("tlsfleet", b));
    assert.equal(a.title, b.title);
    assert.equal(a.severity, "medium"); assert.equal(b.severity, "high");
  });
});

// ---- phishtriage
const EMAIL = [
  "From: \"Support Team\" <alerts@paypal-security-check.test>",
  "To: Test User <test@darknode.ai>",
  "Return-Path: <bounce@bulk-mailer.test>",
  "Reply-To: collect@another-domain.test",
  "Subject: Your account is locked",
  "Message-ID: <abc123@paypal-security-check.test>",
  "Authentication-Results: mx.test; spf=fail; dkim=fail; dmarc=fail",
  "",
  "Verify now: http://paypal.com.account-verify.ru/login?id=1",
].join("\n");
const LEGIT = [
  "From: Team <news@darknode.ai>",
  "To: test@darknode.ai",
  "Subject: Weekly update",
  "Authentication-Results: mx.test; spf=pass; dkim=pass; dmarc=pass",
  "",
  "Hello.",
].join("\n");

group("dp-sink: phishtriage", () => {
  test("risky link becomes one finding on its registered domain", () => {
    const a = analyzeUrl("http://paypal.com.account-verify.ru/login?id=1");
    const out = phishUrlFindings({ ...a, reasons: a.reasons });
    assert.equal(out.length, 1);
    assert.ok(["critical", "high", "medium"].includes(out[0].severity));
    assert.ok(out[0].assets.some((x) => x.type === "DOMAIN" && x.name === a.registrable));
    assert.ok(out[0].evidence.length > 0 && out[0].evidence.every((e) => e.signal || e.finalUrl));
  });
  test("low and info links are not published", () => {
    assert.equal(phishUrlFindings({ input: "https://darknode.ai/", severity: "info", reasons: [] }).length, 0);
    assert.equal(phishUrlFindings({ input: "http://darknode.ai/", severity: "low", reasons: [{ w: 1, t: "Plain HTTP" }] }).length, 0);
  });
  test("suspicious email maps verdict to severity with sender domain and targeted mailbox", () => {
    const t = triageEmail(EMAIL);
    const out = phishEmailFindings(t, { to: "Test User <test@darknode.ai>" });
    assert.equal(out.length, 1);
    assert.equal(out[0].severity, { "high-risk": "critical", suspicious: "high", caution: "medium" }[t.verdict.level]);
    const names = out[0].assets.map((x) => x.type + ":" + x.name);
    assert.ok(names.includes("DOMAIN:" + t.fromReg));
    assert.ok(names.includes("IDENTITY:test@darknode.ai"));
  });
  test("likely-legitimate email yields nothing", () => {
    assert.equal(phishEmailFindings(triageEmail(LEGIT), { to: "test@darknode.ai" }).length, 0);
  });
  test("email key is stable (Message-ID) across re-runs", () => {
    const k = () => keys("phishtriage", phishEmailFindings(triageEmail(EMAIL), { to: "test@darknode.ai" }));
    assert.deepEqual(k(), k());
  });
});

// ---- dlp
const SECRETS = {
  aws: "AKIAZ7QW3RTY5UIO9PLM", // darknode-ignore: planted fake AWS key id for the sink test
  gh: "ghp_q7Wm2Kx9Lp4Rt8Vz1Nc6Hb3Jd5Fs0GyTeUaQi",
  db: "postgres://svc_user:Pw9xQ2vLm7Kt@db.internal.test:5432/ledger", // darknode-ignore: planted fake database URL for the sink test
  card: "4111 1111 1111 1111",
  ssn: "123-45-6789",
  email: "qx.member7@darknode.ai",
};
const DLP_TEXT = [
  "# config",
  `AWS_ACCESS_KEY_ID=${SECRETS.aws}`,
  `token: ${SECRETS.gh}`,
  `DATABASE_URL=${SECRETS.db}`,
  "",
  "/* ===== customers.csv ===== */",
  `card: ${SECRETS.card}   ssn: ${SECRETS.ssn}`,
  `contact: ${SECRETS.email}`,
].join("\n");

group("dp-sink: dlp", () => {
  test("fixture actually detects every planted value", () => {
    const res = scan(DLP_TEXT);
    const vals = res.findings.map((f) => f.value);
    for (const [k, v] of Object.entries(SECRETS)) assert.ok(vals.some((x) => x.includes(v.split(":")[0]) || v.includes(x)), "not detected: " + k);
  });
  test("raw matched values never appear in the graph payload", () => {
    const res = scan(DLP_TEXT);
    const json = JSON.stringify(toEntities("dlp", dlpFindings(res, DLP_TEXT)));
    for (const f of res.findings) {
      assert.ok(!json.includes(f.value), "raw value leaked: " + f.id);
      const v = f.id === "conn-string" ? f.value.replace(/^[a-z+]+:\/\//i, "") : f.value; // the scheme is kept on purpose
      if (v.length >= 12) for (let i = 0; i + 5 <= v.length; i++) {
        const part = v.slice(i, i + 5);
        if (/^[\d ]+$/.test(part)) continue; // digit runs collide with line/col numbers
        assert.ok(!json.includes(part), `5-char slice of ${f.id} leaked: ${part}`);
      }
    }
    assert.ok(!json.includes("Pw9xQ2vLm7Kt") && !json.includes("svc_user"));
  });
  test("masked samples: card keeps last four, other PII keeps nothing, connection strings keep the scheme", () => {
    assert.equal(dlpSample({ id: "credit-card", kind: "pii", value: SECRETS.card, masked: "x" }), "•••• 1111");
    assert.equal(dlpSample({ id: "ssn", kind: "pii", value: SECRETS.ssn, masked: "•••••••6789" }), "•••• (11 chars)");
    assert.equal(dlpSample({ id: "conn-string", kind: "secret", value: SECRETS.db, masked: "y" }), "postgres://••••:••••@••••"); // darknode-ignore: masked fake database URL for the sink test
    assert.equal(dlpSample({ id: "private-key", kind: "secret", value: "-----BEGIN", masked: "[PRIVATE KEY BLOCK]" }), "[PRIVATE KEY BLOCK]");
    assert.equal(dlpSample({ id: "pat-assignment", kind: "secret", value: "short-pass1", masked: "sh•••ss1" }), "•••• (11 chars)");
  });
  test("findings carry type and file location; pasted text gets a fingerprinted location", () => {
    const out = dlpFindings(scan(DLP_TEXT), DLP_TEXT);
    assert.ok(validSev(out));
    const card = out.find((f) => f.tags.includes("credit-card"));
    assert.equal(card.assets[0].name, "customers.csv");
    assert.equal(card.evidence[0].line, 1);
    const aws = out.find((f) => f.tags.includes("aws-key"));
    assert.ok(/^Pasted text [0-9a-z]{1,8}$/.test(aws.assets[0].name), aws.assets[0].name);
    assert.equal(aws.evidence[0].line, 2);
  });
  test("one finding per (type, location) and stable keys on re-scan", () => {
    const text = DLP_TEXT + "\n" + `second: ${SECRETS.email.replace("7", "8")}`;
    const out = dlpFindings(scan(text), text);
    const email = out.filter((f) => f.tags.includes("email"));
    assert.equal(email.length, 1);
    assert.equal(email[0].evidence.length, 2);
    assert.deepEqual(keys("dlp", dlpFindings(scan(DLP_TEXT), DLP_TEXT)), keys("dlp", dlpFindings(scan(DLP_TEXT), DLP_TEXT)));
  });
  test("clean text publishes nothing", () => {
    assert.equal(dlpFindings(scan("nothing sensitive here"), "nothing sensitive here").length, 0);
  });
});
