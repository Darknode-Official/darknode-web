// Email Auth checker parsers (public/js/email-auth.js): SPF and DMARC record analysis.

import { test, assert, group } from "../harness.mjs";
import { analyzeSPF, analyzeDMARC, analyzeDKIM, DEFAULT_SELECTORS } from "../../public/js/email-auth.js";
import fs from "node:fs";

group("email-auth: SPF/DMARC parsers", () => {
  test("one SPF record with -all passes", () => {
    assert.equal(analyzeSPF(["v=spf1 include:_spf.test.darknode.ai -all", "unrelated=1"]).status, "PASS");
  });
  test("two SPF records fail as permerror (RFC 7208 4.5)", () => {
    const r = analyzeSPF(["v=spf1 include:a.test.darknode.ai -all", "v=spf1 ip4:192.0.2.1 -all"]);
    assert.equal(r.status, "FAIL");
    assert.ok(/2 SPF records/.test(r.findings[0].text));
  });
  test("one DMARC record at p=reject passes", () => {
    assert.equal(analyzeDMARC(["v=DMARC1; p=reject; rua=mailto:test@darknode.ai"]).status, "PASS");
  });
  test("two DMARC records fail (RFC 7489 6.6.3)", () => {
    const r = analyzeDMARC(["v=DMARC1; p=reject; rua=mailto:test@darknode.ai", "v=DMARC1; p=none"]);
    assert.equal(r.status, "FAIL");
    assert.ok(/2 DMARC records/.test(r.findings[0].text));
  });
  test("a revoked DKIM key (empty p=) is not also called a published key", () => {
    const r = analyzeDKIM([{ selector: "default", found: true, record: "v=DKIM1; p=", error: null }]);
    assert.equal(r.status, "WARN");
    assert.ok(!r.findings.some((f) => /publishes a DKIM key/.test(f.text)));
    assert.ok(r.findings.some((f) => /revoked/.test(f.text)));
  });
});

group("email-auth: DKIM selector probe", () => {
  test("the default probe covers Resend, Proton, Fastmail and iCloud selectors", () => {
    for (const s of ["resend", "protonmail", "fm1", "sig1", "google", "selector1", "k1"]) assert.ok(DEFAULT_SELECTORS.includes(s), s);
  });
  test("a long not-found list is summarised by count, a short one is listed", () => {
    const miss = (n) => analyzeDKIM(DEFAULT_SELECTORS.slice(0, n).map((selector) => ({ selector, found: false, record: null, error: null }))).findings[0].text;
    assert.ok(/any of the \d+ common selectors/.test(miss(DEFAULT_SELECTORS.length)));
    assert.equal(miss(1), "No DKIM record found for the selector tried (default).");
  });
  test("the card filled after lookup reads its empty message from its own entry", () => {
    const src = fs.readFileSync(new URL("../../public/js/email-auth.js", import.meta.url), "utf8");
    assert.ok(src.includes("recordHtml(key, analysis, (meta[key] || meta).empty)"));
  });
});
