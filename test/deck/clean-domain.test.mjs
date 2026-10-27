// The domain box (Deck "Check my domain" and the Posture tool) takes whatever people paste.
// posture-collect.js imports browser-only paths, so its two pure helpers are lifted from source.

import { test, group, assert } from "../harness.mjs";
import { readFileSync } from "node:fs";

const src = readFileSync(new URL("../../public/js/dataprotect/posture-collect.js", import.meta.url), "utf8");
const body = src.slice(src.indexOf("export function cleanDomain"), src.indexOf("\n", src.indexOf("export const validDomain")) + 1).replace(/^export /gm, "");
const { cleanDomain, validDomain } = new Function(body + "; return { cleanDomain, validDomain };")();

group("deck: domain input cleaning", () => {
  test("URLs, emails, ports, query/hash, www and a trailing dot reduce to the domain", () => {
    for (const [raw, want] of [["HTTPS://Example.COM/path?x=1", "example.com"], ["example.com.", "example.com"], ["www.example.com", "example.com"],
      ["test@darknode.ai", "darknode.ai"], ["mailto:test@darknode.ai", "darknode.ai"], ["example.com:8443", "example.com"], ["example.com?x", "example.com"],
      ["example.com#a", "example.com"], ["https://user:pw@example.com:8443/x", "example.com"], [" sub.example.co.uk ", "sub.example.co.uk"]]) {
      assert.equal(cleanDomain(raw), want, raw);
      assert.ok(validDomain(cleanDomain(raw)), raw);
    }
  });
  test("international names become punycode", () => {
    assert.equal(cleanDomain("münchen.de"), "xn--mnchen-3ya.de");
  });
  test("IPs, single labels and malformed names are still rejected", () => {
    for (const raw of ["8.8.8.8", "localhost", "example", "a..b.com"]) assert.notOk(validDomain(cleanDomain(raw)), raw);
  });
});
