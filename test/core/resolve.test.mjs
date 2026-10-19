// Unit tests for public/js/core/resolve.js — the unified-inventory resolution layer.
import { test, group, assert } from "../harness.mjs";
import {
  bareHost, isIpv4, isIpv6, isIp, canonIp, canonIpv6, canonDomain, canonMac,
  hostParts, identityKeys, resolveAssets, resolveIdentities, coverageMatrix,
} from "../../public/js/core/resolve.js";

const E = (id, type, name, data = {}, source = "") => ({ id, type, name, data, source });

group("resolve/host", () => {
  test("bareHost strips scheme, path, query, port and trailing dot", () => {
    assert.equal(bareHost("https://Server01.Corp.local:8443/path?x=1"), "server01.corp.local");
    assert.equal(bareHost("HOST."), "host");
    assert.equal(bareHost("  Box  "), "box");
  });
  test("bareHost unwraps a bracketed IPv6 literal with a port", () => {
    assert.equal(bareHost("[2001:DB8::1]:443"), "2001:db8::1");
  });
  test("bareHost leaves an ipv6 host:colon alone", () => {
    assert.equal(bareHost("fe80::1"), "fe80::1");
  });
  test("hostParts splits an FQDN into short + fqdn", () => {
    const p = hostParts("Server01.corp.local");
    assert.equal(p.kind, "host"); assert.equal(p.short, "server01"); assert.equal(p.fqdn, "server01.corp.local");
  });
  test("hostParts treats a bare name as short-only (no fqdn)", () => {
    const p = hostParts("SERVER01");
    assert.equal(p.short, "server01"); assert.equal(p.fqdn, null);
  });
  test("hostParts recognises an IP as its own kind", () => {
    assert.equal(hostParts("192.168.000.005").kind, "ip");
    assert.equal(hostParts("192.168.000.005").key, "192.168.0.5");
  });
});

group("resolve/ip", () => {
  test("isIpv4 validates octets", () => {
    assert.equal(isIpv4("10.0.0.1"), true);
    assert.equal(isIpv4("256.0.0.1"), false);
    assert.equal(isIpv4("10.0.0"), false);
  });
  test("canonIp strips leading zeros", () => {
    assert.equal(canonIp("010.000.001.005"), "10.0.1.5");
  });
  test("isIpv6 accepts shorthand, rejects junk", () => {
    assert.equal(isIpv6("2001:db8::1"), true);
    assert.equal(isIpv6("::1"), true);
    assert.equal(isIpv6("hello"), false);
    assert.equal(isIpv6("10.0.0.1"), false);
  });
  test("canonIpv6 expands and recompresses to a stable form", () => {
    assert.equal(canonIpv6("2001:0DB8:0000:0000:0000:0000:0000:0001"), "2001:db8::1");
    assert.equal(canonIpv6("2001:db8::1"), "2001:db8::1");
    assert.equal(canonIpv6("::1"), "::1");
    assert.equal(canonIpv6("0:0:0:0:0:0:0:0"), "::");
  });
  test("canonIpv6 is idempotent", () => {
    const a = canonIpv6("2001:0db8:0:0:0:ff00:0042:8329");
    assert.equal(canonIpv6(a), a);
  });
  test("isIp accepts v4 and v6 but not hostnames", () => {
    assert.equal(isIp("10.0.0.1"), true);
    assert.equal(isIp("2001:db8::1"), true);
    assert.equal(isIp("server01.corp.local"), false);
  });
});

group("resolve/domain+mac", () => {
  test("canonDomain lowercases and drops a wildcard prefix", () => {
    assert.equal(canonDomain("*.API.Example.COM"), "api.example.com");
  });
  test("canonMac normalises separators and casing", () => {
    assert.equal(canonMac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff");
    assert.equal(canonMac("aabb.ccdd.eeff"), "aa:bb:cc:dd:ee:ff");
    assert.equal(canonMac("AABBCCDDEEFF"), "aa:bb:cc:dd:ee:ff");
  });
  test("canonMac rejects non-MACs", () => {
    assert.equal(canonMac("not-a-mac"), null);
    assert.equal(canonMac("aa:bb:cc"), null);
  });
});

group("resolve/identity-keys", () => {
  test("identityKeys pulls an email from the name", () => {
    const k = identityKeys("Jane+news@Corp.com");
    assert.equal(k.emailKey, "jane@corp.com");
    assert.equal(k.upnKey, "jane@corp.com");
  });
  test("identityKeys keeps the DOMAIN\\ prefix on samAccountName (unique only per domain)", () => {
    const k = identityKeys("CORP\\jdoe", { samAccountName: "CORP\\jdoe", displayName: "Doe, John" });
    assert.equal(k.samKey, "corp\\jdoe");
    assert.equal(k.nameKey, "john doe");
  });
  test("different domains with the same sAMAccountName do NOT auto-merge", () => {
    const { clusters } = resolveIdentities([
      E("1", "IDENTITY", "CORP\\jane", { samAccountName: "CORP\\jane" }, "accessreview"),
      E("2", "IDENTITY", "OTHER\\jane", { samAccountName: "OTHER\\jane" }, "accessreview"),
    ]);
    assert.equal(clusters.length, 2, "CORP\\jane and OTHER\\jane are two people");
  });
  test("identityKeys prefers data.email over the display name", () => {
    const k = identityKeys("John Doe", { email: "JDOE@corp.com" });
    assert.equal(k.emailKey, "jdoe@corp.com");
    assert.equal(k.nameKey, "john doe");
  });
});

group("resolve/assets", () => {
  const ents = [
    E("1", "ASSET", "SERVER01"),
    E("2", "ASSET", "server01.corp.local", {}, "vulnimport"),
    E("3", "ENDPOINT", "Server01.corp.local", {}, "fleetcomply"),
    E("4", "IP", "010.0.0.5"),
    E("5", "ASSET", "db01.corp.local", {}, "netexposure"),
    E("6", "ASSET", "web.a.com"),
    E("7", "ASSET", "web.b.com"),
    E("8", "ASSET", "web"), // ambiguous short name — two FQDNs share label "web"
  ];
  test("case + FQDN + short-name variants collapse to one host when unambiguous", () => {
    const cl = resolveAssets(ents);
    const server01 = cl.find((c) => c.key === "server01.corp.local");
    assert.ok(server01, "server01 cluster exists");
    assert.deepEqual(server01.members.sort(), ["1", "2", "3"]);
    assert.deepEqual(server01.sources, ["fleetcomply", "unknown", "vulnimport"]);
  });
  test("an ambiguous short name does NOT merge into either FQDN", () => {
    const cl = resolveAssets(ents);
    const web = cl.find((c) => c.members.includes("8"));
    assert.equal(web.members.length, 1, "bare 'web' stays on its own");
    assert.ok(cl.find((c) => c.key === "web.a.com").members.length === 1);
    assert.ok(cl.find((c) => c.key === "web.b.com").members.length === 1);
  });
  test("a shared MAC merges two hosts even with different names", () => {
    const cl = resolveAssets([
      E("a", "ASSET", "laptop-7", { mac: "AA:BB:CC:00:11:22" }),
      E("b", "ENDPOINT", "DESKTOP-XYZ", { macAddress: "aabbcc001122" }),
    ]);
    assert.equal(cl.length, 1);
    assert.deepEqual(cl[0].members.sort(), ["a", "b"]);
    assert.deepEqual(cl[0].macs, ["aa:bb:cc:00:11:22"]);
  });
  test("distinct hosts stay distinct", () => {
    const cl = resolveAssets(ents);
    assert.ok(cl.find((c) => c.key === "db01.corp.local").members.length === 1);
  });
  test("ENDPOINT membership wins the cluster type", () => {
    const cl = resolveAssets(ents);
    assert.equal(cl.find((c) => c.key === "server01.corp.local").type, "ENDPOINT");
  });
});

group("resolve/identities", () => {
  const ents = [
    E("1", "IDENTITY", "jane@corp.com", {}, "signins"),
    E("2", "IDENTITY", "CORP\\jane", { samAccountName: "CORP\\jane", upn: "jane@corp.com" }, "accessreview"),
    E("3", "IDENTITY", "Jane Doe", { displayName: "Jane Doe" }, "jml"), // name-only, must NOT auto-merge
    E("4", "IDENTITY", "bob@corp.com", { displayName: "Jane Doe" }, "caaudit"), // same name, different person
  ];
  test("email and UPN pull two records into one person", () => {
    const { clusters } = resolveIdentities(ents);
    const jane = clusters.find((c) => c.key === "jane@corp.com");
    assert.deepEqual(jane.members.sort(), ["1", "2"]);
  });
  test("a name-only record is NOT auto-merged into the email person", () => {
    const { clusters } = resolveIdentities(ents);
    assert.ok(clusters.find((c) => c.members.length === 1 && c.members[0] === "3"), "name-only Jane stays separate");
  });
  test("same display name across different emails is a suggestion, not a merge", () => {
    const { clusters, suggestions } = resolveIdentities(ents);
    assert.ok(clusters.find((c) => c.key === "bob@corp.com"), "bob stays his own cluster");
    const s = suggestions.find((x) => x.nameKey === "jane doe");
    assert.ok(s && s.clusterKeys.length >= 2, "jane doe flagged across clusters");
  });
});

group("resolve/coverage", () => {
  const cats = [
    { id: "edr", label: "EDR", sources: ["fleetcomply"] },
    { id: "backup", label: "Backup", sources: ["backupready"] },
    { id: "vuln", label: "Vuln scan", sources: ["vulnimport"] },
  ];
  test("coverageMatrix reports hits and gaps per cluster", () => {
    const clusters = resolveAssets([
      E("1", "ASSET", "server01.corp.local", {}, "vulnimport"),
      E("2", "ENDPOINT", "server01.corp.local", {}, "fleetcomply"),
    ]);
    const cov = coverageMatrix(clusters, cats);
    assert.equal(cov.length, 1);
    assert.equal(cov[0].cover.edr, true);
    assert.equal(cov[0].cover.vuln, true);
    assert.equal(cov[0].cover.backup, false);
    assert.deepEqual(cov[0].missing, ["backup"]);
  });
});

group("resolve/determinism", () => {
  test("resolveAssets output is independent of input order", () => {
    const base = [
      E("1", "ASSET", "server01.corp.local", {}, "a"),
      E("2", "ASSET", "SERVER01", {}, "b"),
      E("3", "IP", "10.0.0.5", {}, "c"),
      E("4", "ASSET", "db01", {}, "d"),
    ];
    const a = JSON.stringify(resolveAssets(base));
    const b = JSON.stringify(resolveAssets([...base].reverse()));
    assert.equal(a, b);
  });
  test("resolveIdentities output is independent of input order", () => {
    const base = [
      E("1", "IDENTITY", "jane@corp.com", {}, "a"),
      E("2", "IDENTITY", "jane@corp.com", { displayName: "Jane" }, "b"),
      E("3", "IDENTITY", "bob@corp.com", {}, "c"),
    ];
    const a = JSON.stringify(resolveIdentities(base));
    const b = JSON.stringify(resolveIdentities([...base].reverse()));
    assert.equal(a, b);
  });
});
