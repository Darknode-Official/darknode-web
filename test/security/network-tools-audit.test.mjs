// Regression tests for the Deck network-tool audit (2026-10-30): packet
// crafter wire bytes, network mapper CIDR/VLSM/nmap/iptables parsing,
// vulnerability DB severity labels, threat-hunt lab helpers.

import { test, assert, group } from "../harness.mjs";
import * as pc from "../../public/js/packet-crafter.js";
import * as nm from "../../public/js/network-mapper.js";
import { VULNS } from "../../public/js/vulnerability-db.js";
import { isRfc1918, decodeB64 } from "../../public/js/threat-hunt-lab.js";

// Independent RFC 1071 check: folding data that already contains its
// checksum must give 0xFFFF.
function fold(bytes) {
  let s = 0;
  for (let i = 0; i < bytes.length; i += 2) s += (bytes[i] << 8) | (bytes[i + 1] || 0);
  while (s > 0xffff) s = (s & 0xffff) + (s >>> 16);
  return s;
}
const quad = (a) => a.split(".").map(Number);
const ETH = { dst: "ff:ff:ff:ff:ff:ff", src: "00:11:22:33:44:55", type: "0800" };
const ip4 = (o) => ({ version: 4, ihl: 5, ttl: 64, protocol: 6, src: "192.0.2.1", dst: "192.0.2.2", id: 1, flags: 2, frag_offset: 0, ...o });
function l4Valid(pkt) {
  const b = pc.buildPacketBytes(pkt), l4 = b.slice(34);
  const pseudo = [...quad(pkt.ipv4.src), ...quad(pkt.ipv4.dst), 0, pkt.ipv4.protocol, l4.length >> 8, l4.length & 255];
  return { b, ipOk: fold(b.slice(14, 34)) === 0xffff, l4Ok: fold(pseudo.concat(l4)) === 0xffff };
}

group("packet-crafter", () => {
  test("TCP with odd-length payload: IP + pseudo-header checksums verify", () => {
    const r = l4Valid({ ethernet: ETH, ipv4: ip4({}), tcp: { src_port: 1, dst_port: 80, seq: 0, ack: 0, offset: 5, flags: 2, window: 512, urg: 0 }, payload: "odd" });
    assert.ok(r.ipOk && r.l4Ok);
  });
  test("UDP with odd-length payload verifies and length field is set", () => {
    const r = l4Valid({ ethernet: ETH, ipv4: ip4({ protocol: 17 }), udp: { src_port: 5, dst_port: 9 }, payload: "x" });
    assert.ok(r.ipOk && r.l4Ok);
    assert.equal((r.b[38] << 8) | r.b[39], 9);
  });
  test("TTL 0 and TCP window 0 are emitted, not replaced by defaults", () => {
    const b = pc.buildPacketBytes({ ethernet: ETH, ipv4: ip4({ ttl: 0 }), tcp: { src_port: 1, dst_port: 2, seq: 0, ack: 0, offset: 5, flags: 0x10, window: 0, urg: 0 } });
    assert.equal(b[14 + 8], 0);
    assert.equal((b[34 + 14] << 8) | b[34 + 15], 0);
  });
  test("DNS qname with trailing dot has a single root label", () => {
    assert.deepEqual(pc.domainToBytes("example.com."), pc.domainToBytes("example.com"));
  });
  test("payload bytes are UTF-8", () => {
    assert.deepEqual(pc.stringToBytes("€"), [0xe2, 0x82, 0xac]);
  });
});

group("network-mapper", () => {
  test("/0 is honoured, not coerced to /24", () => {
    const r = nm.calcSubnet("0.0.0.0/0");
    assert.equal(r.cidr, "0.0.0.0/0");
    assert.equal(r.totalHosts, 4294967294);
  });
  test("/31 and /32 host counts (RFC 3021)", () => {
    assert.equal(nm.calcSubnet("10.0.0.1/31").totalHosts, 2);
    assert.equal(nm.calcSubnet("10.0.0.1/32").firstHost, "10.0.0.1");
  });
  test("invalid address or prefix throws instead of computing garbage", () => {
    assert.throws(() => nm.calcSubnet("300.1.1.1/24"));
    assert.throws(() => nm.calcSubnet("abc"));
    assert.throws(() => nm.calcSubnet("10.0.0.0/33"));
  });
  test("VLSM masks the base network and fits top-of-range blocks", () => {
    const a = nm.vlsmCalc("10.0.0.77/24", [{ name: "a", hosts: 100 }, { name: "b", hosts: 100 }]);
    assert.deepEqual(a.map((r) => r.cidr), ["10.0.0.0/25", "10.0.0.128/25"]);
    assert.equal(nm.vlsmCalc("255.255.255.0/24", [{ name: "a", hosts: 10 }])[0].cidr, "255.255.255.0/28");
  });
  test("nmap -oN with a digit-bearing hostname gets the real IP", () => {
    const h = nm.parseNmapOutput("Nmap scan report for host-1.example.com (10.0.0.1)\n22/tcp open ssh\n");
    assert.equal(h[0].ip, "10.0.0.1");
  });
  test("iptables rules capture -s/-p/--dport and long lines stay linear", () => {
    const r = nm.parseACL("-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT\n-A INPUT -j DROP");
    assert.equal(r[0].src, "10.0.0.0/8");
    assert.equal(r[0].port, 22);
    assert.equal(r[1].action, "deny");
    const t = Date.now();
    nm.parseACL("-A INPUT " + "-s 1 ".repeat(5000));
    assert.ok(Date.now() - t < 500);
  });
});

group("vulnerability-db", () => {
  test("severity matches the CVSS v3 rating of the listed score", () => {
    const band = (c) => (c >= 9 ? "critical" : c >= 7 ? "high" : c >= 4 ? "medium" : "low");
    for (const v of VULNS) assert.equal(v.severity, band(v.cvss), v.cve);
    assert.equal(VULNS.find((v) => v.cve === "CVE-2014-0160").severity, "high");
  });
  test("CVE ids are well formed (4+ digit sequence)", () => {
    for (const v of VULNS) assert.ok(/^CVE-\d{4}-\d{4,}$/.test(v.cve), v.cve);
  });
});

group("threat-hunt-lab", () => {
  test("RFC 1918 classification of 172.x", () => {
    assert.equal(isRfc1918("172.25.1.1"), true);
    assert.equal(isRfc1918("172.2.1.1"), false);
    assert.equal(isRfc1918("172.32.0.1"), false);
  });
  test("base64 decoder handles UTF-16LE (PowerShell -enc) and UTF-8", () => {
    assert.equal(decodeB64(Buffer.from("whoami", "utf16le").toString("base64")), "whoami");
    assert.equal(decodeB64(Buffer.from("café", "utf8").toString("base64")), "café");
  });
});
