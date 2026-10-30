// Regression tests for the ops/infra audit fixes: firewall-audit prototype-key lookups and
// netsh line counting, DNS Hunt own-domain lookalikes and resolver recursion, and
// pentest-register status normalisation. Each test failed on the pre-fix engines.

import { test, assert, group } from "../harness.mjs";
import { portsFromToken, parseCisco, parsePfsenseXml, parseFortigate, parseWindowsNetsh, isAnyAddr } from "../../public/js/infra/firewall-audit-engine.js";
import { analyze, lookalikeOf } from "../../public/js/ops/dnshunt-engine.js";
import { normStatus } from "../../public/js/ops/pentestreg-engine.js";

group("firewall-audit: prototype-key names", () => {
  test("service token 'constructor' is not a port", () => {
    assert.equal(portsFromToken("constructor"), null);
    assert.equal(portsFromToken("toString"), null);
  });

  test("ASA object/object-group/ACL named after Object.prototype members parse without crashing", () => {
    const a = parseCisco("access-list OUT extended permit tcp object constructor any eq 443\naccess-group OUT in interface outside");
    assert.equal(a.rules.length, 1);
    assert.ok(a.rules[0].src.unresolved.includes("constructor"));
    assert.ok(!isAnyAddr(a.rules[0].src));
    const b = parseCisco("access-list OUT extended permit object-group toString any any\naccess-group OUT in interface outside");
    assert.equal(b.rules.length, 1);
    const c = parseCisco("access-list constructor extended permit tcp any any eq 22");
    assert.equal(typeof c.rules[0].name, "string");
  });

  test("pfSense alias named 'constructor' stays unresolved", () => {
    const r = parsePfsenseXml("<pfsense><filter><rule><type>pass</type><interface>wan</interface><protocol>tcp</protocol><source><address>constructor</address></source><destination><any/><port>22</port></destination><descr>x</descr></rule></filter></pfsense>");
    assert.equal(r.rules.length, 1);
    assert.ok(!isAnyAddr(r.rules[0].src));
    assert.ok(r.rules[0].src.unresolved.length > 0);
  });

  const forti = (src, svc) => `config firewall policy
  edit 1
    set srcintf "wan1"
    set dstintf "lan"
    set srcaddr "${src}"
    set dstaddr "all"
    set action accept
    set service "${svc}"
  next
end`;

  test("FortiGate srcaddr 'constructor' is not treated as all", () => {
    const r = parseFortigate(forti("constructor", "HTTPS"));
    assert.equal(r.rules.length, 1);
    assert.ok(!isAnyAddr(r.rules[0].src));
    assert.ok(r.rules[0].src.unresolved.includes("constructor"));
  });

  test("FortiGate service 'toString' does not crash", () => {
    const r = parseFortigate(forti("all", "toString"));
    assert.equal(r.rules.length, 1);
  });
});

group("firewall-audit: netsh line numbers", () => {
  const block = (i) => `Rule Name:                            R${i}\n----------------------------------------------------------------------\nEnabled:                              Yes\nDirection:                            In\nProfiles:                             Domain\nLocalIP:                              Any\nRemoteIP:                             10.0.${i % 250}.0/24\nProtocol:                             TCP\nLocalPort:                            ${1000 + i}\nRemotePort:                           Any\nAction:                               Allow\n\n`;

  test("line numbers point at each rule header", () => {
    const text = "Header line\n\n" + block(0) + block(1) + block(2);
    const r = parseWindowsNetsh(text);
    const L = text.split("\n");
    assert.equal(r.rules.length, 3);
    for (const rule of r.rules) assert.ok(/^Rule Name:/.test(L[rule.lineNo - 1]), "line " + rule.lineNo);
  });

  test("4000-rule export parses in linear time", () => {
    let s = "";
    for (let i = 0; i < 4000; i++) s += block(i);
    const t = Date.now();
    const r = parseWindowsNetsh(s);
    assert.equal(r.rules.length, 4000);
    assert.ok(Date.now() - t < 1000, "took " + (Date.now() - t) + " ms");
  });
});

group("dnshunt: own domains and resolver recursion", () => {
  const T0 = Date.UTC(2026, 9, 6);
  const ev = (i, client, query, server) => ({ ts: T0 + i * 1000, client, query, qtype: "A", rcode: "NOERROR", answers: [], server });

  test("a second own domain is not a lookalike of the first", () => {
    assert.equal(lookalikeOf("example.net", ["example.com", "example.net"]), null);
    const events = [0, 1, 2, 3, 4].map((i) => ev(i, "10.0.0.5", "www.example.net", "10.0.0.2"));
    const r = analyze({ events }, { ownDomains: "example.com\nexample.net" });
    assert.equal(r.findings.filter((f) => f.category === "lookalike").length, 0);
  });

  test("the internal resolver's own recursion is not a bypass; a real bypass still is", () => {
    const events = [];
    for (let i = 0; i < 5; i++) {
      events.push(ev(i, "10.0.0.5", "www.example.org", "10.0.0.2"));
      events.push(ev(i, "10.0.0.2", "www.example.org", "192.0.2.53"));
      events.push(ev(i, "10.0.0.9", "www.example.org", "198.51.100.53"));
    }
    for (const opts of [{}, { approvedResolvers: "10.0.0.2" }]) {
      const r = analyze({ events }, opts);
      const clients = r.tables.externalResolvers.map((x) => x.client);
      assert.ok(!clients.includes("10.0.0.2"), JSON.stringify(opts));
      assert.ok(clients.includes("10.0.0.9"), JSON.stringify(opts));
      assert.equal(r.findings.filter((f) => f.category === "resolver").length, 1);
    }
  });
});

group("pentestreg: status normalisation", () => {
  test("Remediated and Mitigated are closed; remediation in progress is not", () => {
    assert.equal(normStatus("Remediated"), "closed");
    assert.equal(normStatus("Mitigated"), "closed");
    assert.equal(normStatus("Not mitigated"), "open");
    assert.equal(normStatus("Remediation in progress"), "remediation");
    assert.equal(normStatus("Remediating"), "remediation");
  });
});
