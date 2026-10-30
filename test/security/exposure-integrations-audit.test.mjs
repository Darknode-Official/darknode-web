// Exposure + integrations audit regressions (2026-10-30): one test per fix in
// dmarcreports, vulnimport (Grype), fleetcomply, netexposure and intel-core.

import { test, assert, group } from "../harness.mjs";
import { parseInput as dmarcParse, analyze as dmarcAnalyze } from "../../public/js/exposure/dmarcreports-engine.js";
import { parseInput as vulnParse } from "../../public/js/exposure/vulnimport-engine.js";
import { analyze as fleetAnalyze } from "../../public/js/exposure/fleetcomply-engine.js";
import { analyze as netAnalyze } from "../../public/js/exposure/netexposure-engine.js";
import { buildRequest, toolsFor, testPassed, statusReason } from "../../public/js/integrations/intel-core.js";

const dmarc = (begin, authResults) => "<feedback><report_metadata><org_name>example.com</org_name><email>test@darknode.ai</email><report_id>r" + begin + "</report_id><date_range><begin>" + begin + "</begin><end>" + begin + "</end></date_range></report_metadata>" +
  "<policy_published><domain>example.com</domain><p>reject</p></policy_published><record><row><source_ip>192.0.2.1</source_ip><count>4</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>" +
  "<identifiers><header_from>example.com</header_from></identifiers>" + (authResults ? "<auth_results><dkim><domain>example.com</domain><result>pass</result></dkim></auth_results>" : "") + "</record></feedback>";

const nmap = (ip, start) => '<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -6 -p 22,80 ' + ip + '" start="' + start + '" version="7.94"><scaninfo type="syn" protocol="tcp" numservices="2" services="22,80"/>' +
  '<host starttime="' + start + '" endtime="' + (start + 5) + '"><status state="up" reason="echo-reply"/><address addr="' + ip + '" addrtype="ipv6"/><ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6p1" method="probed"/></port></ports></host>' +
  '<runstats><finished time="' + (start + 10) + '"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>';

group("exposure-integrations audit", () => {
  test("dmarcreports: an epoch past year 9999 does not crash analyze", () => {
    const a = dmarcAnalyze(dmarcParse([{ name: "a.xml", text: dmarc("99999999999999", true) }]));
    assert.ok(a && a.summary);
  });

  test("dmarcreports: a record with no auth_results falls back to policy_evaluated", () => {
    const a = dmarcAnalyze(dmarcParse([{ name: "b.xml", text: dmarc("1700000000", false) }]));
    assert.equal(a.summary.messages, 4);
    assert.equal(a.summary.pass, 4);
  });

  test("vulnimport: Grype keeps the CVSS 3.x score next to a 4.0 entry and reads related CVE scores", () => {
    const grype = { source: { type: "image", target: { userInput: "example.com/app:1.0" } }, distro: { name: "debian", version: "12" }, matches: [
      { vulnerability: { id: "CVE-2024-0001", severity: "High", cvss: [{ version: "3.1", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", metrics: { baseScore: 9.8 } }, { version: "4.0", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", metrics: { baseScore: 9.3 } }], fix: { versions: ["1.2.3"] } }, artifact: { name: "libfoo", version: "1.0" } },
      { vulnerability: { id: "GHSA-aaaa-bbbb-cccc", severity: "Medium", cvss: [], fix: { versions: [] } }, relatedVulnerabilities: [{ id: "CVE-2024-0002", cvss: [{ version: "3.1", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", metrics: { baseScore: 5.4 } }] }], artifact: { name: "libbar", version: "2.0" } },
    ] };
    const p = vulnParse([{ name: "grype.json", text: JSON.stringify(grype) }]);
    const score = (k) => p.rows.find((r) => r.vuln.key === k).vuln.cvss3.score;
    assert.equal(score("CVE-2024-0001"), 9.8);
    assert.equal(score("CVE-2024-0002"), 5.4);
  });

  test("fleetcomply: 14.6 and 14.6.0 are the same release", () => {
    const csv = ["hostname,os,os version,serial,last seen", "mac-a,macOS,14.6,SERIALA1,2026-10-01", "mac-b,macOS,14.6.0,SERIALB1,2026-10-01", "mac-c,macOS,14.5,SERIALC1,2026-10-01"].join("\n");
    const r = fleetAnalyze([{ name: "devices.csv", text: csv }], { now: "2026-10-02" });
    const pb = r.findings.filter((f) => f.check === "patch_behind");
    assert.ok(!pb.some((f) => /2 release/.test(f.title + JSON.stringify(f.evidence))));
  });

  test("netexposure: two spellings of one IPv6 address are one host", () => {
    const r = netAnalyze([{ name: "a.xml", text: nmap("2001:db8::1", 1760000000) }, { name: "b.xml", text: nmap("2001:DB8:0:0:0:0:0:1", 1760100000) }], { now: "2025-10-12" });
    assert.deepEqual(r.tables.hosts.map((h) => h.ip), ["2001:db8::1"]);
    assert.equal(r.tables.changes.length, 0);
  });

  test("intel-core: Object.prototype names are not integrations", () => {
    const key = "ab" + "cd" + "1234";
    for (const id of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
      assert.deepEqual(buildRequest(id, "x", {}, key), { error: "unknown integration" });
      assert.deepEqual(toolsFor(id), []);
      assert.equal(testPassed(id, 500, {}), false);
    }
  });

  test("intel-core: a nested {error:{message}} body is shown in the reason", () => {
    assert.equal(statusReason(401, { error: { code: "WrongCredentialsError", message: "Wrong API key" } }), "the provider rejected the key (401): Wrong API key");
    assert.equal(statusReason(429, { error: "quota exceeded" }), "the provider's rate limit or quota is used up (429): quota exceeded");
  });
});
