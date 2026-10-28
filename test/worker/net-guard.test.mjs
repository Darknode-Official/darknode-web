// Unit tests for worker/net-guard.js — the shared SSRF host guard.
import { test, group, assert } from "../harness.mjs";
import { hostAllowed, ipv4Private, normalizeIpv4 } from "../../worker/net-guard.js";

const allowed = (url) => hostAllowed(new URL(url));

group("net-guard/normalizeIpv4", () => {
  test("decimal, hex and octal encodings all canonicalise to 127.0.0.1", () => {
    assert.equal(normalizeIpv4("2130706433"), "127.0.0.1");   // bare 32-bit
    assert.equal(normalizeIpv4("0x7f000001"), "127.0.0.1");   // hex
    assert.equal(normalizeIpv4("0177.0.0.1"), "127.0.0.1");   // octal first octet
    assert.equal(normalizeIpv4("127.1"), "127.0.0.1");        // short form
    assert.equal(normalizeIpv4("127.0.0.1"), "127.0.0.1");    // already dotted
  });
  test("non-numeric hosts return null (left untouched)", () => {
    assert.equal(normalizeIpv4("example.com"), null);
    assert.equal(normalizeIpv4("a.b.c.d"), null);
    assert.equal(normalizeIpv4(""), null);
  });
  test("out-of-range numeric parts are rejected", () => {
    assert.equal(normalizeIpv4("4294967296"), null);   // > 2^32-1
    assert.equal(normalizeIpv4("256.1.1.1"), null);
  });
});

group("net-guard/hostAllowed", () => {
  test("public hosts are allowed", () => {
    assert.ok(allowed("https://example.com/x"));
    assert.ok(allowed("https://8.8.8.8/"));
    assert.ok(allowed("https://hooks.slack.com/services/T/B/x"));
  });
  test("loopback / private / metadata are blocked in dotted form", () => {
    assert.notOk(allowed("http://127.0.0.1/"));
    assert.notOk(allowed("http://localhost/"));
    assert.notOk(allowed("http://10.0.0.5/"));
    assert.notOk(allowed("http://192.168.1.1/"));
    assert.notOk(allowed("http://169.254.169.254/latest/meta-data/"));
    assert.notOk(allowed("http://[::1]/"));
  });
  test("a private IPv4 address carried in IPv6 is blocked (URL() rewrites ::ffff:a.b.c.d to hex)", () => {
    assert.notOk(allowed("http://[::ffff:169.254.169.254]/")); // becomes [::ffff:a9fe:a9fe]
    assert.notOk(allowed("http://[::ffff:127.0.0.1]/"));
    assert.notOk(allowed("http://[64:ff9b::a9fe:a9fe]/"));       // NAT64
    assert.notOk(allowed("http://[::7f00:1]/"));                 // IPv4-compatible
    assert.notOk(allowed("http://[2002:a9fe:a9fe::]/"));         // 6to4
    assert.ok(allowed("http://[::ffff:8.8.8.8]/"));
    assert.ok(allowed("http://[64:ff9b::808:808]/"));
    assert.ok(allowed("http://[2606:4700::1111]/"));
  });
  test("numeric-encoded private addresses do not bypass the guard", () => {
    assert.notOk(allowed("http://2130706433/"));          // 127.0.0.1
    assert.notOk(allowed("http://0x7f000001/"));           // 127.0.0.1
    assert.notOk(allowed("http://0177.0.0.1/"));           // 127.0.0.1
    assert.notOk(allowed("http://127.1/"));                // 127.0.0.1
    assert.notOk(allowed("http://2852039166/"));           // 169.254.169.254
  });
  test("non-http(s) schemes are blocked", () => {
    assert.notOk(allowed("file:///etc/passwd"));
    assert.notOk(allowed("ftp://example.com/"));
  });
  test("ipv4Private still matches reserved ranges directly", () => {
    assert.ok(ipv4Private("100.64.0.1"));   // CGNAT
    assert.ok(ipv4Private("224.0.0.1"));     // multicast
    assert.notOk(ipv4Private("8.8.8.8"));
  });
});
