// Certificate / TLS fleet monitor engine tests (public/js/dataprotect/tls-engine.js).

import { test, assert, group } from "../harness.mjs";
import {
  expiryBand, issuerLabel, parseDomains, buildEntry, summarizeFleet, selfTest,
} from "../../public/js/dataprotect/tls-engine.js";

group("tls-fleet: engine self-test", () => {
  test("all in-engine self-test checks pass", () => {
    const r = selfTest();
    assert.ok(r.pass, "failures: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
});

group("tls-fleet: banding", () => {
  test("expiry bands", () => {
    assert.equal(expiryBand(-3).level, "expired");
    assert.equal(expiryBand(7).level, "urgent");
    assert.equal(expiryBand(25).level, "soon");
    assert.equal(expiryBand(45).level, "watch");
    assert.equal(expiryBand(120).level, "ok");
    assert.equal(expiryBand(null).level, "unknown");
  });
});

group("tls-fleet: parsing", () => {
  test("issuerLabel prefers O then CN", () => {
    assert.equal(issuerLabel("C=US, O=DigiCert Inc, CN=DigiCert TLS RSA"), "DigiCert Inc");
    assert.equal(issuerLabel("CN=R3"), "R3");
    assert.equal(issuerLabel(""), "");
  });
  test("parseDomains cleans, validates and dedupes order-preserving", () => {
    assert.deepEqual(parseDomains("https://Example.com/path\nexample.com\n bad_host \napi.example.com:443, foo.co"),
      ["example.com", "api.example.com", "foo.co"]);
    assert.deepEqual(parseDomains(""), []);
    assert.deepEqual(parseDomains("notadomain localhost"), []);
    assert.deepEqual(parseDomains("münchen.de\ntest@darknode.ai, mailto:test@darknode.ai example.com. https://u:p@b.com:8443/x?y bar.com#x 8.8.8.8"),
      ["xn--mnchen-3ya.de", "darknode.ai", "example.com", "b.com", "bar.com"]);
  });
});

group("tls-fleet: entries and fleet", () => {
  test("buildEntry maps newest cert to a banded entry", () => {
    const rows = [
      { issuer_name: "O=Let's Encrypt, CN=E5", not_after: new Date(Date.now() + 10 * 86400000).toISOString() },
      { issuer_name: "O=Old", not_after: new Date(Date.now() - 100 * 86400000).toISOString() },
    ];
    const e = buildEntry("site.com", rows);
    assert.ok(e.ok);
    assert.equal(e.issuer, "Let's Encrypt");
    assert.equal(e.band.level, "urgent");
    assert.ok(e.daysLeft >= 9 && e.daysLeft <= 10);
  });
  test("buildEntry with no rows is unknown", () => {
    const e = buildEntry("nocert.com", []);
    assert.notOk(e.ok);
    assert.equal(e.band.level, "unknown");
    assert.equal(e.daysLeft, null);
  });
  test("summarizeFleet counts and sorts worst-first", () => {
    const entries = [
      buildEntry("ok.com", [{ issuer_name: "O=LE", not_after: new Date(Date.now() + 300 * 86400000).toISOString() }]),
      buildEntry("exp.com", [{ issuer_name: "O=LE", not_after: new Date(Date.now() - 2 * 86400000).toISOString() }]),
      buildEntry("soon.com", [{ issuer_name: "O=LE", not_after: new Date(Date.now() + 20 * 86400000).toISOString() }]),
    ];
    const s = summarizeFleet(entries);
    assert.equal(s.total, 3);
    assert.equal(s.counts.expired, 1);
    assert.equal(s.counts.soon, 1);
    assert.equal(s.counts.ok, 1);
    assert.equal(s.alerting, 2);
    assert.equal(s.list[0].domain, "exp.com"); // worst first
  });
});

group("tls-fleet: wildcard names copied from a certificate", () => {
  test("*.example.com is checked as example.com and deduped against it; a bare * is not a domain", () => {
    assert.deepEqual(parseDomains("*.wikipedia.org\nwikipedia.org\n*.\n*foo.com\nhttps://*.example.com/x"), ["wikipedia.org", "example.com"]);
  });
});
