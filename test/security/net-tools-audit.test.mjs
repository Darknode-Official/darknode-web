// Network quick tools audited against ground truth (IEEE OUI registry, RFC 1071/1035/3492/4291/8326,
// Python ipaddress). One test per fixed bug.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as NET } from "../../public/js/tools/network.js";
import { TOOLS as NP } from "../../public/js/tools/netproto.js";

const ALL = [...NET, ...NP];
const run = (id, v) => { try { const r = ALL.find((t) => t.id === id).run(v, H); return typeof r === "string" ? r : JSON.stringify(r); } catch (e) { return "THROW " + e.message; } };
const isErr = (s) => s.startsWith('{"error"');

group("network quick tools audit", () => {
  test("OUI table matches the IEEE registry (AC1F6B is Supermicro, E4CE8F/FCFC48 Apple, F8B156 Dell)", () => {
    assert.ok(run("n-mac-vendor", { mac: "ac:1f:6b:00:00:01" }).startsWith("Supermicro"));
    assert.ok(run("n-mac-vendor", { mac: "e4:ce:8f:00:00:01" }).startsWith("Apple"));
    assert.ok(run("n-mac-vendor", { mac: "fc:fc:48:00:00:01" }).startsWith("Apple"));
    assert.ok(run("n-mac-vendor", { mac: "f8:b1:56:00:00:01" }).startsWith("Dell"));
  });
  test("TCP flags decoder reads Wireshark hex (0x012) instead of reporting no flags", () => {
    assert.ok(run("n-tcp-flags", { mode: "Number → Flags", value: "0x012" }).includes("SYN, ACK"));
    assert.ok(isErr(run("n-tcp-flags", { mode: "Number → Flags", value: "18abc" })));
  });
  test("CIDR splitter caps its output instead of exhausting memory", () => {
    const out = run("n-cidr-split", { cidr: "0.0.0.0/0", count: "4294967296" });
    assert.equal(out.split("\n").length, 4097);
    assert.ok(/4294963200 more \/32/.test(out));
  });
  test("IPv6 parser rejects '::' that stands for zero groups (9 groups)", () => {
    assert.ok(isErr(run("n-ptr-name", { ip: "1::2:3:4:5:6:7:8", mode: "IPv6" })));
    assert.ok(run("n-ptr-name", { ip: "1:2:3:4:5:6:7::", mode: "IPv6" }).endsWith("ip6.arpa"));
  });
  test("SPF checker flags a mechanism missing its colon", () => {
    const out = run("n-spf-check", { spf: "v=spf1 include_spf.example.com ip4:192.0.2.1 mx/24 redirect=_spf.example.com -all" });
    assert.ok(out.includes('Unrecognized mechanism: "include_spf.example.com"'));
    assert.ok(out.includes("mx/24 → Pass") && out.includes("redirect=_spf.example.com → Pass"));
  });
  test("User-Agent parser recognizes Edge on Android (EdgA)", () => {
    const ua = "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36 EdgA/120.0";
    assert.ok(run("n-user-agent", { ua }).includes("Browser: Microsoft Edge 120.0"));
  });
});

group("netproto quick tools audit", () => {
  test("DNS message decoder reports a self-referencing compression pointer instead of '<root>'", () => {
    assert.ok(run("np-dns-decode", { hex: "123401000001000000000000c00c00010001" }).includes("could not parse name"));
  });
  test("DNS name decoder errors on pointer loops and cut-off pointers", () => {
    assert.ok(/loop/.test(run("np-dns-name-decode", { hex: "03777777c000" })));
    assert.ok(/cut off/.test(run("np-dns-name-decode", { hex: "03777777c0" })));
    assert.equal(run("np-dns-name-decode", { hex: "03777777 03636f6d 00" }), "www.com");
  });
  test("DNS name encoder and query builder send an IDN as punycode, not truncated UTF-16", () => {
    assert.ok(run("np-dns-name-encode", { name: "münchen.de" }).includes("0e 78 6e 2d 2d 6d 6e 63 68 65 6e 2d 33 79 61 02 64 65 00"));
    assert.ok(run("np-dns-query-build", { name: "bücher.example", type: "A", rd: true }).startsWith("Query: xn--bcher-kva.example"));
  });
  test("IPv4 header checksum covers IHL*4 bytes when a payload is pasted too", () => {
    assert.ok(run("np-ipv4-checksum", { hex: "4500003c1c46400040060000c0a80001c0a800c7 0050 01bb 0000 0001", mode: "Compute" }).startsWith("Checksum: 0x9c5d"));
    assert.ok(run("np-ipv4-checksum", { hex: "4500003c1c4640004006 9c5d c0a80001c0a800c7 0050 01bb 0000 0001", mode: "Verify" }).startsWith("Valid"));
  });
  test("Wireshark filter does not limit DNS or any-protocol ports to TCP", () => {
    assert.equal(run("np-wireshark-filter", { proto: "dns", port: "53" }), "dns && (tcp.port == 53 || udp.port == 53)");
    assert.equal(run("np-wireshark-filter", { proto: "tls", port: "443" }), "tls && tcp.port == 443");
  });
  test("BGP 65535:0 is GRACEFUL_SHUTDOWN (RFC 8326 name)", () => {
    assert.ok(run("np-bgp-community", { val: "65535:0" }).includes("GRACEFUL_SHUTDOWN"));
  });
  test("IPv6 parser rejects a misplaced or malformed embedded IPv4", () => {
    assert.ok(isErr(run("np-ipv6-classify", { addr: "::1.2.3.4x" })));
    assert.ok(isErr(run("np-ipv6-classify", { addr: "1.2.3.4::" })));
    assert.ok(run("np-ipv6-classify", { addr: "::ffff:10.0.0.1" }).includes("-> 10.0.0.1"));
  });
  test("DNS flags decoder reads '81 80' from a hex dump and rejects trailing garbage", () => {
    assert.ok(run("np-dns-flags-decode", { val: "81 80" }).startsWith("Value: 0x8180"));
    assert.ok(isErr(run("np-dns-flags-decode", { val: "81x" })));
  });
  test("SPF checker takes = only after the redirect/exp modifiers", () => {
    const r = run("n-spf-check", { spf: "v=spf1 ip4=1.2.3.4 redirect=_spf.example.com -all" });
    assert.ok(/Unrecognized mechanism: "ip4=1\.2\.3\.4"/.test(r) && /redirect=_spf\.example\.com → Pass/.test(r));
  });
});
