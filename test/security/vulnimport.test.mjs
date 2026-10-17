// Vulnerability Import & SLA engine tests (public/js/exposure/vulnimport-engine.js).
// One fixture per scanner export in its documented column / element layout, CVSS maths,
// de-duplication across scanners, KEV / EPSS enrichment, the priority matrix, SLA clocks,
// burn-down against a baseline, end-of-life matching, exports, skipped checks and determinism.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, VERSION, DEFAULTS, FORMATS, DETECTIONS, REGISTER_COLS,
  parseInput, analyze, detectFormat, classifyHeaders, computeCvss31, computeCvss2, priorityOf, slaDue, internetMatcher,
  normSeverity, parseTs, xmlElements, osCandidates, findingsToCsv, registerToCsv, assetsToCsv, remediationToCsv, cveListText, summaryText,
  graphItems, exampleDataset, selfTest,
} from "../../public/js/exposure/vulnimport-engine.js";

const DAY = 86400000;
const NOW = "2026-10-15T12:00:00Z";
const f = (name, text, role) => ({ name, text, role });
const parse1 = (name, text) => { const p = parseInput([f(name, text)]); return { p, file: p.files[0], rows: p.rows }; };
const KEV = { updated: "2026-10-15", count: 2, data: [
  { cve: "CVE-2008-4250", vendor: "Microsoft", product: "Windows", name: "Microsoft Windows Server Service RCE", dateAdded: "2026-05-20", dueDate: "2026-06-03", ransomware: "Unknown" },
  { cve: "CVE-2016-3081", vendor: "Apache", product: "Struts", name: "Apache Struts RCE", dateAdded: "2026-10-08", dueDate: "2026-10-11", ransomware: "Known" },
] };
const EPSS = { updated: "2026-10-15", count: 3, data: [
  { cve: "CVE-2021-44228", epss: 0.94, percentile: 0.999 }, { cve: "CVE-2023-48795", epss: 0.61, percentile: 0.98 }, { cve: "CVE-2016-3081", epss: 0.94, percentile: 0.999 },
] };
const EOL = { updated: "2026-10-15", data: [
  { product: "windows-server", cycles: [{ cycle: "2012-r2", eol: "2023-10-10" }, { cycle: "2022", eol: "2031-10-14" }] },
  { product: "ubuntu", cycles: [{ cycle: "18.04", eol: "2023-05-31", extendedSupport: "2028-04-01" }, { cycle: "22.04", eol: "2027-06-01" }] },
] };
const feeds = { kev: KEV, epss: EPSS, eol: EOL, now: NOW };

// ---------------------------------------------------------------------------
// Fixtures in the exact vendor layouts
// ---------------------------------------------------------------------------
const nessusItem = (port, sev, id, name, body) => '<ReportItem port="' + port + '" svc_name="www" protocol="tcp" severity="' + sev + '" pluginID="' + id + '" pluginName="' + name + '" pluginFamily="Misc.">' + body + "</ReportItem>";
const nessusHost = (ip, fqdn, os, items) => '<ReportHost name="' + ip + '"><HostProperties><tag name="HOST_END">Thu Oct 15 02:10:00 2026</tag><tag name="host-ip">' + ip + '</tag><tag name="host-fqdn">' + fqdn +
  '</tag><tag name="operating-system">' + os + "</tag></HostProperties>" + items.join("") + "</ReportHost>";
const NESSUS = '<?xml version="1.0" ?>\n<NessusClientData_v2><Policy><policyName>t</policyName></Policy><Report name="t" xmlns:cm="http://www.nessus.org/cm">' +
  nessusHost("10.0.0.5", "web.test.darknode.ai", "Microsoft Windows Server 2012 R2 Standard", [
    nessusItem(0, 0, 19506, "Nessus Scan Information", "<risk_factor>None</risk_factor>"),
    nessusItem(445, 4, 34477, "MS08-067", "<cve>CVE-2008-4250</cve><cvss_base_score>10.0</cvss_base_score><cvss_vector>CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C</cvss_vector><risk_factor>Critical</risk_factor><exploit_available>true</exploit_available><solution>Apply MS08-067.</solution>"),
    nessusItem(22, 2, 187315, "SSH Terrapin", "<cve>CVE-2023-48795</cve><cvss3_vector>CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N</cvss3_vector><risk_factor>Medium</risk_factor>"),
  ]) + "</Report></NessusClientData_v2>";

const TENABLE_CSV = 'Plugin ID,CVE,CVSS v2.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output\n' +
  '34477,CVE-2008-4250,10.0,Critical,10.0.0.5,tcp,445,MS08-067,Remote code execution,desc,Apply MS08-067.,https://test.darknode.ai/ms08-067,answered\n' +
  '19506,,,None,10.0.0.5,tcp,0,Nessus Scan Information,,,,,\n';

const TENABLE_EXPORT = 'Asset UUID,IP Address,FQDN,Plugin ID,Plugin Name,Severity,CVE,CVSSv3 Base Score,State,First Seen,Last Seen,Last Fixed,Port,Protocol,Solution\n' +
  'a1b2c3d4-0000-4000-8000-000000000001,10.0.0.7,app.test.darknode.ai,97610,Apache Struts 2 RCE,Critical,CVE-2016-3081,8.1,Active,2026-09-01T00:00:00Z,2026-10-14T00:00:00Z,,8080,tcp,Upgrade Struts\n' +
  'a1b2c3d4-0000-4000-8000-000000000001,10.0.0.7,app.test.darknode.ai,134862,Apache Tomcat AJP,High,CVE-2020-1938,9.8,Fixed,2026-03-01T00:00:00Z,2026-06-01T00:00:00Z,2026-06-10T00:00:00Z,8009,tcp,Upgrade Tomcat\n';

const QUALYS_CSV = '"Scan Results","10/15/2026 at 02:00:00 (GMT)"\n"Darknode test","test@darknode.ai"\n' +
  '"IP","DNS","NetBIOS","OS","IP Status","QID","Title","Vuln Status","Type","Severity","Port","Protocol","FQDN","SSL","First Detected","Last Detected","Times Detected","Date Last Fixed","CVE ID","Vendor Reference","Bugtraq ID","CVSS Base","CVSS Temporal","CVSS3 Base","CVSS3 Temporal","Threat","Impact","Solution","Exploitability","Associated Malware","Results","PCI Vuln","Ticket State","Category"\n' +
  '"10.0.0.9","mail.test.darknode.ai","MAIL","Ubuntu 18.04","host scanned, found vuln","38739","Deprecated SSH Cipher","Active","Vuln","3","22","tcp","mail.test.darknode.ai","no","03/01/2025 10:00:00","10/14/2026 10:00:00","40","","CVE-2008-5161","","","2.6","","","","t","i","Disable CBC ciphers","","","cbc","yes","","General"\n' +
  '"10.0.0.9","mail.test.darknode.ai","MAIL","Ubuntu 18.04","host scanned, found vuln","45038","Host Scan Time","","Ig","1","","","mail.test.darknode.ai","no","","","","","","","","","","","","","","","","","","no","","Information gathering"\n';

const QUALYS_XML = '<?xml version="1.0" encoding="UTF-8" ?>\n<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM "x.dtd">\n<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>1</ID><IP>10.0.0.11</IP><DNS><![CDATA[db.test.darknode.ai]]></DNS><OS><![CDATA[CentOS Linux 7.9]]></OS>' +
  '<DETECTION_LIST><DETECTION><QID>105943</QID><TYPE>Confirmed</TYPE><SEVERITY>4</SEVERITY><PORT>5432</PORT><PROTOCOL>tcp</PROTOCOL><STATUS>Active</STATUS><FIRST_FOUND_DATETIME>2026-08-01T00:00:00Z</FIRST_FOUND_DATETIME><LAST_FOUND_DATETIME>2026-10-14T00:00:00Z</LAST_FOUND_DATETIME><RESULTS>PostgreSQL 9.6</RESULTS></DETECTION>' +
  "<DETECTION><QID>6</QID><TYPE>Info</TYPE><SEVERITY>1</SEVERITY><STATUS>Active</STATUS></DETECTION></DETECTION_LIST></HOST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>";

const OPENVAS_XML = '<report id="r1" format_id="a994b278"><report id="r1"><results start="1" max="100">' +
  '<result id="x1"><name>OpenSSL Heartbleed</name><host>10.0.0.13<hostname>tls.test.darknode.ai</hostname></host><port>443/tcp</port>' +
  '<nvt oid="1.3.6.1.4.1.25623.1.0.103936"><type>nvt</type><name>OpenSSL Heartbeat Information Disclosure</name><tags>cvss_base_vector=AV:N/AC:L/Au:N/C:P/I:N/A:N|solution_type=VendorFix|solution=Update OpenSSL</tags>' +
  '<severities score="5.0"><severity type="cvss_base_v2"><value>AV:N/AC:L/Au:N/C:P/I:N/A:N</value></severity></severities><refs><ref type="cve" id="CVE-2014-0160"/><ref type="url" id="https://test.darknode.ai/hb"/></refs></nvt>' +
  "<threat>Medium</threat><severity>5.0</severity><description>vulnerable</description><creation_time>2026-10-01T03:00:00Z</creation_time><modification_time>2026-10-14T03:00:00Z</modification_time></result>" +
  '<result id="x2"><name>OS Detection</name><host>10.0.0.13</host><port>general/tcp</port><nvt oid="1.3.6.1.4.1.25623.1.0.105937"><name>OS Detection Consolidation</name><tags>cvss_base_vector=AV:N/AC:L/Au:N/C:N/I:N/A:N</tags></nvt><threat>Log</threat><severity>0.0</severity></result>' +
  "</results></report></report>";

const GREENBONE_CSV = "IP,Hostname,Port,Port Protocol,CVSS,Severity,QoD,Solution Type,NVT Name,Summary,Specific Result,NVT OID,CVEs,Task ID,Task Name,Timestamp,Result ID,Impact,Solution,Affected Software/OS,Vulnerability Insight,Vulnerability Detection Method,Product Detection Result,BIDs,CERTs,Other References\n" +
  '10.0.0.13,tls.test.darknode.ai,443,tcp,5.0,Medium,98,VendorFix,OpenSSL Heartbeat Information Disclosure,s,vulnerable,1.3.6.1.4.1.25623.1.0.103936,CVE-2014-0160,t1,Weekly,2026-10-14T03:00:00Z,r1,i,Update OpenSSL,OpenSSL 1.0.1f,,,,,,\n';

const RAPID7_CSV = "Asset IP Address,Asset Names,Asset OS Name,Vulnerability ID,Vulnerability Title,Vulnerability CVE IDs,Vulnerability CVSS Score,Vulnerability CVSSv3 Score,Vulnerability Severity Level,Service Port,Service Protocol,Vulnerability Proof,Vulnerability Solution,Vulnerability Published Date,Vulnerability Test Date,Vulnerable Since,Exploit Count,Malware Kit Count\n" +
  '10.0.0.15,files.test.darknode.ai,Microsoft Windows Server 2022,msft-cve-2020-1472,Netlogon Elevation of Privilege,CVE-2020-1472,9.3,10.0,10,445,tcp,proof,Apply update,2020-08-11,2026-10-14,2026-09-20,3,0\n';

const TRIVY = JSON.stringify({ SchemaVersion: 2, ArtifactName: "registry.test.darknode.ai/api:1.4", ArtifactType: "container_image", Metadata: { OS: { Family: "alpine", Name: "3.14.2" } },
  Results: [{ Target: "registry.test.darknode.ai/api:1.4 (alpine 3.14.2)", Class: "os-pkgs", Type: "alpine", Vulnerabilities: [
    { VulnerabilityID: "CVE-2022-37434", PkgName: "zlib", InstalledVersion: "1.2.11-r3", FixedVersion: "1.2.12-r2", Severity: "CRITICAL", Title: "zlib heap overflow", CVSS: { nvd: { V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", V3Score: 9.8 } } },
  ] }, { Target: "app/lib/log4j-core-2.14.1.jar", Class: "lang-pkgs", Type: "jar", Vulnerabilities: [
    { VulnerabilityID: "CVE-2021-44228", PkgName: "org.apache.logging.log4j:log4j-core", InstalledVersion: "2.14.1", FixedVersion: "2.15.0", Severity: "CRITICAL", CVSS: { nvd: { V3Score: 10 } } },
  ] }] });

const GRYPE = JSON.stringify({ matches: [{ vulnerability: { id: "GHSA-jfh8-c2jp-5v3q", severity: "Critical", cvss: [{ version: "3.1", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", metrics: { baseScore: 10 } }], fix: { versions: ["2.15.0"], state: "fixed" } },
  relatedVulnerabilities: [{ id: "CVE-2021-44228" }], artifact: { name: "log4j-core", version: "2.14.1", type: "java-archive", locations: [{ path: "/app/lib/log4j-core-2.14.1.jar" }] } }],
  source: { type: "image", target: { userInput: "registry.test.darknode.ai/api:1.4" } }, distro: { name: "alpine", version: "3.14.2" } });

const snykProject = (name, vulns) => ({ ok: false, projectName: name, packageManager: "npm", vulnerabilities: vulns });
const snykVuln = (id, cve, sev, score, pkg, ver, fix) => ({ id, title: "Prototype Pollution", severity: sev, cvssScore: score, CVSSv3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", identifiers: { CVE: [cve], CWE: ["CWE-1321"] }, packageName: pkg, version: ver, fixedIn: fix, from: ["web@1.0.0", pkg + "@" + ver] });
const SNYK = JSON.stringify(snykProject("web", [snykVuln("SNYK-JS-LODASH-567746", "CVE-2020-8203", "high", 7.4, "lodash", "4.17.15", ["4.17.19"])]));
const SNYK_MULTI = JSON.stringify([snykProject("web", [snykVuln("SNYK-JS-LODASH-567746", "CVE-2020-8203", "high", 7.4, "lodash", "4.17.15", ["4.17.19"])]), snykProject("admin", [snykVuln("SNYK-JS-MINIMIST-559764", "CVE-2020-7598", "medium", 5.6, "minimist", "1.2.0", ["1.2.3"])])]);

const SARIF = JSON.stringify({ version: "2.1.0", $schema: "https://json.schemastore.org/sarif-2.1.0.json", runs: [{ tool: { driver: { name: "Trivy", rules: [
  { id: "CVE-2021-44228", shortDescription: { text: "log4j RCE" }, properties: { "security-severity": "10.0" } }, { id: "DS002", shortDescription: { text: "Image user should not be root" }, properties: { "security-severity": "8.0" } }] } },
  results: [{ ruleId: "CVE-2021-44228", level: "error", message: { text: "Package: log4j-core" }, locations: [{ physicalLocation: { artifactLocation: { uri: "app/lib/log4j-core.jar" } } }] }, { ruleId: "DS002", level: "error", message: { text: "root" } }] }] });

const MDVM_WEAK = "Name,Severity,CVSS,Exposed devices,Published on,Updated on,Threats,Exploit available,Software,Vendor\n" +
  "CVE-2023-4863,Critical,8.8,42,2023-09-12,2026-10-01,Exploit is verified,true,chrome,google\n";
const MDVM_DEVICE = "Device name,Device ID,OS Platform,CVE,Severity,CVSS Score,Software Name,Software Vendor,Software Version,Fixed version?,Recommended security update,First seen,Last seen\n" +
  "laptop-01.test.darknode.ai,d1,Windows11,CVE-2023-4863,Critical,8.8,chrome,google,116.0.5845.96,117.0.5938.132,Update Chrome,2026-09-20,2026-10-14\n";
const MDVM_HUNT = "DeviceId,DeviceName,OSPlatform,OSVersion,OSArchitecture,SoftwareVendor,SoftwareName,SoftwareVersion,CveId,VulnerabilitySeverityLevel,RecommendedSecurityUpdate,RecommendedSecurityUpdateId,CveTags,CveMitigationStatus\n" +
  "d1,laptop-01.test.darknode.ai,Windows11,10.0,x64,google,chrome,116.0.5845.96,CVE-2023-4863,Critical,,,,\n";
const GENERIC = "hostname,cve_id,summary,risk,cvss_score,discovered\nbox1.test.darknode.ai,CVE-2021-41773,Apache path traversal,High,7.5,2026-09-01\n";

// ---------------------------------------------------------------------------
group("vulnimport: format detection and parsers", () => {

test("constants and formats", () => {
  assert.equal(TOOL_ID, "vulnimport");
  assert.ok(VERSION);
  for (const k of ["nessus-xml", "tenable-csv", "tenable-export", "qualys-csv", "qualys-xml", "openvas-xml", "greenbone-csv", "rapid7-csv", "trivy", "grype", "snyk", "sarif", "mdvm-weaknesses", "mdvm-device", "mdvm-hunting", "generic", "baseline"]) assert.ok(FORMATS[k], k);
  assert.ok(DETECTIONS.length >= 10);
});

test("Nessus .nessus XML: hosts, CVEs, CVSS v2 vector prefix, v3 vector computed, info dropped", () => {
  const { file } = parse1("scan.nessus", NESSUS);
  assert.equal(file.format, "nessus-xml");
  const r = analyze([f("scan.nessus", NESSUS)], { now: NOW });
  const ms = r.tables.vulns.find((v) => v.cve === "CVE-2008-4250");
  assert.equal(ms.cvss, 10);
  assert.equal(ms.assetName.toLowerCase().includes("web") || ms.ip === "10.0.0.5", true);
  assert.equal(ms.exploit, true);
  const tp = r.tables.vulns.find((v) => v.cve === "CVE-2023-48795");
  assert.equal(tp.cvss, 5.9);
  assert.notOk(r.tables.vulns.some((v) => v.pluginId === "19506"));
  assert.ok(r.summary.infoExcluded >= 1);
});

test("Tenable / Nessus CSV", () => {
  const { file } = parse1("t.csv", TENABLE_CSV);
  assert.equal(file.format, "tenable-csv");
  const r = analyze([f("t.csv", TENABLE_CSV)], { now: NOW });
  assert.equal(r.tables.vulns.length, 1);
  assert.equal(r.tables.vulns[0].severity, "critical");
});

test("Tenable vulnerability export CSV: state Fixed and lastFixed feed MTTR", () => {
  const { file } = parse1("export.csv", TENABLE_EXPORT);
  assert.equal(file.format, "tenable-export");
  const r = analyze([f("export.csv", TENABLE_EXPORT)], { now: NOW });
  const fixed = r.tables.vulns.find((v) => v.cve === "CVE-2020-1938");
  assert.equal(fixed.status, "fixed");
  assert.equal(r.summary.mttrSamples, 1);
  assert.equal(r.summary.meanTimeToRemediate, 101);
});

test("Qualys CSV with report preamble; Ig type is informational", () => {
  const { file } = parse1("qualys.csv", QUALYS_CSV);
  assert.equal(file.format, "qualys-csv");
  const r = analyze([f("qualys.csv", QUALYS_CSV)], { now: NOW });
  assert.equal(r.tables.vulns.length, 1);
  const v = r.tables.vulns[0];
  assert.equal(v.cve, "CVE-2008-5161");
  // Qualys 3 (serious) is medium on the common scale; the CVSS 2.6 score then sets the register severity.
  assert.ok(/medium/.test(v.severityScanner));
  assert.equal(v.severity, "low");
  assert.equal(v.firstSeen, "2025-03-01");
});

test("Qualys VM detection XML", () => {
  const { file } = parse1("det.xml", QUALYS_XML);
  assert.equal(file.format, "qualys-xml");
  const r = analyze([f("det.xml", QUALYS_XML)], { now: NOW });
  assert.equal(r.tables.vulns.length, 1);
  assert.equal(r.tables.vulns[0].pluginId, "QID 105943");
  assert.equal(r.tables.vulns[0].severity, "high");
});

test("OpenVAS / Greenbone XML: nested report, CVE refs, Log threat excluded", () => {
  const { file } = parse1("report.xml", OPENVAS_XML);
  assert.equal(file.format, "openvas-xml");
  const r = analyze([f("report.xml", OPENVAS_XML)], { now: NOW });
  assert.equal(r.tables.vulns.length, 1);
  assert.equal(r.tables.vulns[0].cve, "CVE-2014-0160");
  assert.equal(r.tables.vulns[0].cvss, 5);
  assert.equal(r.tables.vulns[0].port, "443");
});

test("Greenbone CSV", () => {
  const { file } = parse1("gb.csv", GREENBONE_CSV);
  assert.equal(file.format, "greenbone-csv");
  const r = analyze([f("gb.csv", GREENBONE_CSV)], { now: NOW });
  assert.equal(r.tables.vulns[0].cve, "CVE-2014-0160");
  assert.equal(r.tables.vulns[0].severity, "medium");
});

test("Rapid7 InsightVM CSV: severity scale, exploit count, Vulnerable Since", () => {
  const { file } = parse1("r7.csv", RAPID7_CSV);
  assert.equal(file.format, "rapid7-csv");
  const r = analyze([f("r7.csv", RAPID7_CSV)], { now: NOW });
  const v = r.tables.vulns[0];
  assert.equal(v.severity, "critical");
  assert.equal(v.exploit, true);
  assert.equal(v.cvss, 10);
  assert.equal(v.firstSeen, "2026-09-20");
});

test("Trivy JSON: image asset, package fields, score from CVSS map", () => {
  const { file } = parse1("trivy.json", TRIVY);
  assert.equal(file.format, "trivy");
  const r = analyze([f("trivy.json", TRIVY)], { now: NOW });
  assert.equal(r.tables.vulns.length, 2);
  const z = r.tables.vulns.find((v) => v.cve === "CVE-2022-37434");
  assert.equal(z.kind, "image");
  assert.equal(z.package, "zlib");
  assert.equal(z.fixedVersion, "1.2.12-r2");
  assert.equal(z.cvss, 9.8);
});

test("Grype JSON: GHSA with related CVE becomes the CVE", () => {
  const { file } = parse1("grype.json", GRYPE);
  assert.equal(file.format, "grype");
  const r = analyze([f("grype.json", GRYPE)], { now: NOW });
  assert.equal(r.tables.vulns.length, 1);
  assert.equal(r.tables.vulns[0].cve, "CVE-2021-44228");
  assert.equal(r.tables.vulns[0].fixedVersion, "2.15.0");
});

test("Snyk JSON: single project", () => {
  const { file } = parse1("snyk.json", SNYK);
  assert.equal(file.format, "snyk");
  const r = analyze([f("snyk.json", SNYK)], { now: NOW });
  assert.equal(r.tables.vulns[0].cve, "CVE-2020-8203");
  assert.equal(r.tables.vulns[0].assetName, "web");
});

test("Snyk JSON: multi-project array (snyk test --all-projects)", () => {
  const r = analyze([f("snyk-all.json", SNYK_MULTI)], { now: NOW });
  assert.equal(r.tables.vulns.length, 2);
  assert.equal(r.summary.assets, 2);
});

test("SARIF 2.1.0: CVE rules imported, non-CVE rules reported in notes", () => {
  const { file } = parse1("scan.sarif", SARIF);
  assert.equal(file.format, "sarif");
  assert.equal(file.records, 1);
  assert.ok(file.notes.some((n) => /without a CVE/.test(n)));
  const r = analyze([f("scan.sarif", SARIF)], { now: NOW });
  assert.equal(r.tables.vulns[0].cvss, 10);
});

test("Defender weaknesses CSV: aggregate asset carrying exposed devices", () => {
  const { file } = parse1("weaknesses.csv", MDVM_WEAK);
  assert.equal(file.format, "mdvm-weaknesses");
  const r = analyze([f("weaknesses.csv", MDVM_WEAK)], { now: NOW });
  const v = r.tables.vulns[0];
  assert.equal(v.aggregate, true);
  assert.equal(String(v.exposedDevices), "42");
  assert.equal(v.exploit, true);
});

test("Defender per-device CSV", () => {
  const { file } = parse1("device.csv", MDVM_DEVICE);
  assert.equal(file.format, "mdvm-device");
  const r = analyze([f("device.csv", MDVM_DEVICE)], { now: NOW });
  assert.equal(r.tables.vulns[0].installed, "116.0.5845.96");
  assert.equal(r.tables.vulns[0].fixedVersion, "117.0.5938.132");
});

test("Defender DeviceTvmSoftwareVulnerabilities hunting CSV: no dates, so no due date", () => {
  const { file } = parse1("hunt.csv", MDVM_HUNT);
  assert.equal(file.format, "mdvm-hunting");
  const r = analyze([f("hunt.csv", MDVM_HUNT)], {});
  assert.equal(r.tables.vulns[0].due, "");
  assert.equal(r.tables.sla.find((s) => s.bucket === r.tables.vulns[0].priority).noDate, 1);
});

test("generic CSV: aliases detected, and explicit column mapping wins", () => {
  assert.equal(classifyHeaders(["hostname", "cve_id", "summary"]).format, "generic");
  const r = analyze([f("g.csv", GENERIC)], { now: NOW });
  assert.equal(r.tables.vulns.length, 1);
  assert.equal(r.tables.vulns[0].cve, "CVE-2021-41773");
  const odd = "machine,ident\nbox9,CVE-2021-41773\n";
  const r2 = analyze([f("odd.csv", odd)], { now: NOW, columns: { asset: "machine", cve: "ident" } });
  assert.equal(r2.tables.vulns[0].assetName, "box9");
});

test("unknown content is reported, not guessed", () => {
  assert.equal(detectFormat("<html><body>nope</body></html>").format, "unknown");
  assert.equal(detectFormat('{"hello":1}').format, "unknown");
  const p = parseInput([f("x.json", '{"hello":1}')]);
  assert.equal(p.files[0].format, "unknown");
});

// ---------------------------------------------------------------------------
});
group("vulnimport: CVSS and helpers", () => {

test("CVSS 3.1 known vectors", () => {
  assert.equal(computeCvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(computeCvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10);
  assert.equal(computeCvss31("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"), 5.9);
  assert.equal(computeCvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
  assert.equal(computeCvss31("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"), 1.8);
  assert.equal(computeCvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0);
  assert.equal(computeCvss31("CVSS:3.1/AV:N/AC:L"), null);
});

test("CVSS 2 known vectors", () => {
  assert.equal(computeCvss2("AV:N/AC:L/Au:N/C:C/I:C/A:C"), 10);
  assert.equal(computeCvss2("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"), 7.5);
  assert.equal(computeCvss2("AV:N/AC:L/Au:N/C:P/I:N/A:N"), 5);
  assert.equal(computeCvss2("AV:N/AC:M/Au:N/C:N/I:P/A:N"), 4.3);
  assert.equal(computeCvss2("AV:N"), null);
});

test("severity normalisation per scanner scale", () => {
  assert.equal(normSeverity("4", "nessus"), "critical");
  assert.equal(normSeverity("0", "nessus"), "info");
  assert.equal(normSeverity("5", "qualys"), "critical");
  assert.equal(normSeverity("3", "qualys"), "medium");
  assert.equal(normSeverity("10", "rapid7"), "critical");
  assert.equal(normSeverity("High"), "high");
});

test("timestamp parsing is UTC and accepts scanner formats", () => {
  assert.equal(parseTs("2026-10-15T00:00:00Z"), Date.UTC(2026, 9, 15));
  assert.equal(parseTs("10/15/2026 00:00:00"), Date.UTC(2026, 9, 15));
  assert.equal(parseTs("Thu Oct 15 02:10:00 2026"), Date.UTC(2026, 9, 15, 2, 10));
  assert.equal(parseTs(""), null);
  assert.equal(parseTs("not a date"), null);
});

test("xmlElements: nested same-name elements and the per-element size cap", () => {
  const els = [...xmlElements("<a><report><report>x</report></report><report/></a>", "report")];
  assert.equal(els.length, 2);
  assert.ok(els[0].xml.endsWith("</report></report>"));
  const big = [...xmlElements("<r><HOST>" + "x".repeat(200) + "</HOST><HOST>y</HOST></r>", "HOST", 100)];
  assert.equal(big[0].skip, true);
  assert.equal(big[1].xml, "<HOST>y</HOST>");
});

test("internet-facing matcher: CIDR, names and regex", () => {
  const m = internetMatcher("10.0.0.0/24\nweb.test.darknode.ai");
  assert.ok(m({ ip: "10.0.0.200" }));
  assert.ok(m({ fqdn: "web.test.darknode.ai" }));
  assert.notOk(m({ ip: "10.0.1.1" }));
  assert.ok(internetMatcher("^dmz-")({ name: "dmz-proxy" }));
  assert.notOk(internetMatcher("")({ name: "x" }));
});

test("OS end-of-life candidates", () => {
  assert.deepEqual(osCandidates("Microsoft Windows Server 2012 R2 Standard"), [{ product: "windows-server", cycle: "2012-r2" }]);
  assert.deepEqual(osCandidates("Ubuntu 18.04.6 LTS"), [{ product: "ubuntu", cycle: "18.04" }]);
});

// ---------------------------------------------------------------------------
});
group("vulnimport: priority and SLA", () => {

const O = DEFAULTS;
test("priority: KEV is P1 regardless of score", () => assert.equal(priorityOf({ kev: true, cvss: 2 }, O).priority, "P1"));
test("priority: EPSS 0.30 with CVSS 7 is P1; EPSS 0.29 is P2", () => {
  assert.equal(priorityOf({ epss: 0.3, cvss: 7 }, O).priority, "P1");
  assert.equal(priorityOf({ epss: 0.29, cvss: 7 }, O).priority, "P2");
  assert.equal(priorityOf({ epss: 0.5, cvss: 6.9 }, O).priority, "P2");
});
test("priority: CVSS 9 needs internet-facing or exploit for P1", () => {
  assert.equal(priorityOf({ cvss: 9 }, O).priority, "P2");
  assert.equal(priorityOf({ cvss: 9, internetFacing: true }, O).priority, "P1");
  assert.equal(priorityOf({ cvss: 9, exploit: true }, O).priority, "P1");
  assert.equal(priorityOf({ cvss: 8.9, exploit: true }, O).priority, "P2");
});
test("priority: P3 / P4 boundaries and EPSS 0.10", () => {
  assert.equal(priorityOf({ cvss: 4 }, O).priority, "P3");
  assert.equal(priorityOf({ cvss: 3.9 }, O).priority, "P4");
  assert.equal(priorityOf({ cvss: 3.9, epss: 0.1 }, O).priority, "P2");
  assert.equal(priorityOf({}, O).priority, "P4");
});

test("SLA: internal days, PCI 6.3.3, KEV catalog due, BOD 22-01 internet clock", () => {
  const t0 = Date.UTC(2026, 0, 1);
  assert.equal(slaDue({ firstSeen: t0, priority: "P2", severity: "high" }).due, t0 + 30 * DAY);
  const pci = slaDue({ firstSeen: t0, priority: "P3", severity: "high" }, { ...O.sla, pciCriticalHighDays: 30 });
  assert.equal(pci.due, t0 + 30 * DAY);
  assert.ok(/PCI DSS 6.3.3/.test(pci.basis));
  const kev = slaDue({ firstSeen: t0, priority: "P1", kev: true, kevDue: "2026-01-05" });
  assert.equal(kev.due, Date.UTC(2026, 0, 5));
  const net = slaDue({ firstSeen: t0, priority: "P1", kev: true, internetFacing: true }, { ...O.sla, kevCatalogDue: false });
  assert.equal(net.due, t0 + 14 * DAY);
  assert.equal(slaDue({ firstSeen: null, priority: "P1" }).due, null);
  // A catalog due date already in the past at first sight falls back to the detection clock.
  const old = slaDue({ firstSeen: t0, priority: "P1", kev: true, kevDue: "2021-12-24" });
  assert.equal(old.due, t0 + 15 * DAY);
  assert.ok(/had passed before first seen/.test(old.basis));
});

test("analyze: overdue days measured against opts.now", () => {
  const r = analyze([f("export.csv", TENABLE_EXPORT)], { now: NOW, kev: KEV });
  const v = r.tables.vulns.find((x) => x.cve === "CVE-2016-3081");
  assert.equal(v.kev, true);
  assert.equal(v.priority, "P1");
  assert.equal(v.due, "2026-09-16");
  assert.equal(v.overdue, true);
  assert.equal(v.daysOverdue, 29);
});

// ---------------------------------------------------------------------------
});
group("vulnimport: merge, enrichment, burn-down", () => {

test("dedupe: same host + CVE + port from Nessus XML and Tenable CSV is one row with both files", () => {
  const r = analyze([f("scan.nessus", NESSUS), f("t.csv", TENABLE_CSV)], { now: NOW });
  const rows = r.tables.vulns.filter((v) => v.cve === "CVE-2008-4250");
  assert.equal(rows.length, 1);
  assert.equal(r.summary.assets, 1);
});

test("dedupe: Trivy and Grype on the same image merge log4j into one row with two scanners", () => {
  const r = analyze([f("trivy.json", TRIVY), f("grype.json", GRYPE)], { now: NOW });
  const rows = r.tables.vulns.filter((v) => v.cve === "CVE-2021-44228");
  assert.equal(rows.length, 1);
  assert.ok(/Grype/.test(rows[0].scanners) && /Trivy/.test(rows[0].scanners));
});

test("KEV and EPSS enrichment, with the ransomware flag and missing-EPSS list", () => {
  const r = analyze([f("trivy.json", TRIVY), f("export.csv", TENABLE_EXPORT)], feeds);
  const l = r.tables.vulns.find((v) => v.cve === "CVE-2021-44228");
  assert.equal(l.epss, 0.94);
  assert.equal(l.epssSource, "mirror");
  assert.equal(l.priority, "P1");
  const s = r.tables.vulns.find((v) => v.cve === "CVE-2016-3081");
  assert.equal(s.ransomware, true);
  assert.ok(r.summary.missingEpss.includes("CVE-2022-37434"));
  assert.notOk(r.summary.missingEpss.includes("CVE-2021-44228"));
});

test("live EPSS overrides the mirror and is labelled live", () => {
  const r = analyze([f("trivy.json", TRIVY)], { ...feeds, epssLive: { "CVE-2022-37434": { epss: 0.02, percentile: 0.8 } }, epssLiveAt: "2026-10-15T12:00:00Z" });
  const z = r.tables.vulns.find((v) => v.cve === "CVE-2022-37434");
  assert.equal(z.epss, 0.02);
  assert.equal(z.epssSource, "live");
  assert.equal(r.summary.missingEpss.length, 0);
});

test("no feeds: no KEV claims and the check is reported as skipped", () => {
  const r = analyze([f("scan.nessus", NESSUS)], { now: NOW });
  assert.equal(r.summary.kev, 0);
  assert.ok(r.skipped.some((s) => /kev/i.test(s.check)));
});

test("burn-down against a baseline: new, fixed, still open, not rescanned", () => {
  const base = analyze([f("t.csv", TENABLE_CSV), f("r7.csv", RAPID7_CSV), f("qualys.csv", QUALYS_CSV)], { now: "2026-09-15T00:00:00Z" });
  const baseJson = JSON.stringify(base);
  // This month: web host rescanned with MS08-067 gone but Terrapin present; files host rescanned clean of nothing (same); mail host not rescanned.
  const NESSUS_FIXED = NESSUS.replace(/<ReportItem port="445"[\s\S]*?<\/ReportItem>/, "");
  const r = analyze([f("scan.nessus", NESSUS_FIXED), f("r7.csv", RAPID7_CSV), f("last.json", baseJson, "baseline")], { now: NOW });
  const total = r.tables.burndown.find((b) => b.severity === "total");
  assert.equal(total.fixed, 1);
  assert.equal(total.new, 1);
  assert.equal(total.stillOpen, 1);
  assert.equal(total.notRescanned, 1);
  assert.equal(r.summary.baseline, true);
  assert.ok(r.findings.some((x) => x.check === "disappeared"));
});

test("baseline firstSeen carries forward when it is earlier than the scan date", () => {
  const base = analyze([f("r7.csv", RAPID7_CSV.replace("2026-09-20", "2026-01-02"))], { now: "2026-02-01T00:00:00Z" });
  const r = analyze([f("r7.csv", RAPID7_CSV.replace(",2026-09-20,", ",,")), f("last.json", JSON.stringify(base), "baseline")], { now: NOW });
  assert.equal(r.tables.vulns[0].firstSeen, "2026-01-02");
});

test("reopened status is detected and reported", () => {
  const reopened = QUALYS_CSV.replace('"38739","Deprecated SSH Cipher","Active"', '"38739","Deprecated SSH Cipher","Re-Opened"');
  const r = analyze([f("qualys.csv", reopened)], { now: NOW });
  assert.equal(r.summary.reopened, 1);
  assert.ok(r.findings.some((x) => x.check === "reopened"));
});

// ---------------------------------------------------------------------------
});
group("vulnimport: detections and findings", () => {

test("findings cite real controls and carry evidence", () => {
  const r = analyze([f("export.csv", TENABLE_EXPORT), f("scan.nessus", NESSUS)], feeds);
  const kev = r.findings.find((x) => x.check === "kev");
  assert.ok(kev);
  assert.ok(kev.controls.some((c) => /BOD 22-01/.test(c.framework + " " + c.id)));
  assert.ok(kev.evidence.length >= 1 && kev.evidenceCount >= kev.evidence.length);
  for (const x of r.findings) { assert.ok(x.controls.length, x.check); assert.ok(x.id && x.title && x.recommendation, x.check); }
});

test("end-of-life OS is reported from the EOL mirror; supported OS is not", () => {
  const r = analyze([f("scan.nessus", NESSUS), f("r7.csv", RAPID7_CSV)], feeds);
  const eol = r.findings.filter((x) => x.check === "eol");
  assert.ok(eol.some((x) => /2012/.test(JSON.stringify(x.evidence))));
  assert.notOk(eol.some((x) => /2022/.test(JSON.stringify(x.evidence))));
});

test("many criticals on one asset respects the threshold", () => {
  const rows = Array.from({ length: 3 }, (_, i) => "box1,CVE-2026-" + (10000 + i) + ",t,Critical,9.8,2026-10-01").join("\n");
  const csv = "hostname,cve_id,summary,risk,cvss_score,discovered\n" + rows + "\n";
  assert.ok(analyze([f("g.csv", csv)], { now: NOW, manyCriticals: 3 }).findings.some((x) => x.check === "many_criticals"));
  assert.notOk(analyze([f("g.csv", csv)], { now: NOW, manyCriticals: 4 }).findings.some((x) => x.check === "many_criticals"));
});

test("scanner severity disagreement is reported", () => {
  const t = TENABLE_CSV.replace("10.0,Critical,10.0.0.5", "10.0,Low,10.0.0.5");
  const r = analyze([f("scan.nessus", NESSUS), f("t.csv", t)], { now: NOW });
  assert.ok(r.findings.some((x) => x.check === "disagree"));
});

test("aggregate Defender weaknesses rows are excluded from per-asset checks", () => {
  const r = analyze([f("weaknesses.csv", MDVM_WEAK)], { now: NOW, manyCriticals: 1 });
  assert.notOk(r.findings.some((x) => x.check === "many_criticals"));
});

// ---------------------------------------------------------------------------
});
group("vulnimport: exports, determinism, example", () => {

test("exports: register, assets, remediation, findings CSV headers and text", () => {
  const r = analyze(exampleDataset().files, feeds);
  assert.equal(registerToCsv(r.tables.vulns).split("\n")[0], REGISTER_COLS.join(","));
  assert.ok(assetsToCsv(r.tables.assets).startsWith("name,ip,fqdn"));
  assert.ok(remediationToCsv(r.tables.remediation).startsWith("priority,action"));
  assert.equal(findingsToCsv(r.findings).split("\n")[0], "severity,confidence,category,check,title,description,recommendation,controls,assets,evidenceCount");
  assert.ok(/CVE-\d{4}-\d+/.test(cveListText(r)));
  assert.ok(summaryText(r).length > 100);
  assert.ok(r.tables.remediation.length >= 1);
});

test("CSV export neutralises spreadsheet formulas", () => {
  const evil = "hostname,cve_id,summary,risk\nbox1,CVE-2021-41773,=HYPERLINK(\"x\"),High\n";
  const out = registerToCsv(analyze([f("g.csv", evil)], { now: NOW }).tables.vulns);
  assert.notOk(/,=HYPERLINK/.test(out));
  assert.notOk(/,"=HYPERLINK/.test(out));
  assert.ok(out.includes("\"'=HYPERLINK"));});

test("graph items link VULNERABILITY -affects-> ASSET and skip aggregates", () => {
  const r = analyze([f("scan.nessus", NESSUS), f("weaknesses.csv", MDVM_WEAK)], feeds);
  const g = graphItems(r);
  assert.ok(g.items.some((i) => i.type === "ASSET"));
  assert.ok(g.items.some((i) => i.type === "VULNERABILITY" && i.name === "CVE-2008-4250"));
  assert.notOk(g.items.some((i) => i.type === "ASSET" && /Defender exposed/.test(i.name)));
  assert.ok(g.links.every((l) => l.rel === "affects" && l.from.startsWith("VULNERABILITY:") && l.to.startsWith("ASSET:")));
  assert.ok(graphItems(r, { sample: true }).items.every((i) => i.opts.tags.includes("sample")));
});

test("deterministic: same input and now give identical output", () => {
  const a = JSON.stringify(analyze(exampleDataset().files, feeds));
  const b = JSON.stringify(analyze(exampleDataset().files, feeds));
  assert.equal(a, b);
});

test("example dataset parses every file and includes a baseline", () => {
  const ex = exampleDataset();
  const p = parseInput(ex.files);
  assert.ok(p.files.every((x) => x.format !== "unknown" && x.records > 0));
  assert.ok(p.files.some((x) => x.role === "baseline"));
  assert.ok(ex.files.every((x) => !/example\.com/.test(x.text)));
  const r = analyze(p, feeds);
  assert.ok(r.summary.vulns > 5 && r.findings.length > 3);
});

test("selfTest passes", () => {
  const s = selfTest();
  assert.ok(s.tests.length >= 5);
  assert.ok(s.tests.every((t) => t.pass), JSON.stringify(s.tests.filter((t) => !t.pass)));
});

test("empty input yields an empty, well-formed result", () => {
  const r = analyze([], { now: NOW });
  assert.equal(r.summary.vulns, 0);
  assert.deepEqual(r.findings, []);
  assert.ok(Array.isArray(r.tables.burndown));
});
});
