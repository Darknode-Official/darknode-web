// Email Auth checker parsers (public/js/email-auth.js): SPF and DMARC record analysis.

import { test, assert, group } from "../harness.mjs";
import { analyzeSPF, analyzeDMARC, analyzeDKIM } from "../../public/js/email-auth.js";

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
