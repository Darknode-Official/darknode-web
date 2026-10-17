// Network Scan Diff engine tests (public/js/exposure/netexposure-engine.js).
// One fixture per scanner export in its documented layout (nmap -oX with NSE output, nmap -oG,
// masscan -oJ / -oX, naabu -json, Nessus v2, Shodan NDJSON / host JSON, generic CSV), the NSE
// script parsers, the risk table (internal vs external), end-of-life matching, certificate / TLS /
// SSH / SMB / RDP checks, the scan diff with its coverage rules, the allow-list, the conservative
// segmentation check, exports, determinism and the self-test.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, VERSION, DEFAULTS, FORMATS, RULES, SEV_RANK,
  detectFormat, parseInput, analyze, parsePortSpec, parseNmapArgs, parseSshBanner, parseServerHeader, splitProductVersion,
  parseSslCert, parseSslEnumCiphers, parseSsh2EnumAlgos, parseSmbProtocols, parseSmbSigning, parseRdpEnum, parseVulners,
  parseNmapXml, parseNmapGrep, parseMasscanJson, parseNaabu, parseNessus, parseNessusCert, parseShodan, parsePortCsv, parseFwaudit,
  compareVersions, findCycle, eolCandidates, parseAllowList, matchRules, fwDecide, ipCmp,
  findingsToCsv, inventoryToCsv, changesToCsv, firewallTicketText, summaryText, INVENTORY_COLS, CHANGE_COLS,
  exampleDataset, EOL_FIXTURE, selfTest,
} from "../../public/js/exposure/netexposure-engine.js";
import { compileCidrs } from "../../public/js/ops/log-hunter-engine.js";

const f = (name, text) => ({ name, text });
const recs = (scan) => [...scan.hosts.values()].flatMap((h) => [...h.recs.values()]);
const rec = (scan, ip, port, proto = "tcp") => scan.hosts.get(ip)?.recs.get(proto + "/" + port);
const fid = (r, id) => r.findings.find((x) => x.id === id);
const chType = (r, type) => r.tables.changes.filter((c) => c.type === type);

// ---------------------------------------------------------------------------
// Fixtures (vendor layouts; addresses from RFC 5737 / RFC 1918, names under test.darknode.ai)
// ---------------------------------------------------------------------------
const x = (s) => s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\n/g, "&#xa;");
const SSL_CERT_OUT = "Subject: commonName=vpn.test.darknode.ai/organizationName=Test\nSubject Alternative Name: DNS:vpn.test.darknode.ai, DNS:www.test.darknode.ai\nIssuer: commonName=vpn.test.darknode.ai/organizationName=Test\nPublic Key type: rsa\nPublic Key bits: 1024\nSignature Algorithm: sha1WithRSAEncryption\nNot valid before: 2024-01-01T00:00:00\nNot valid after:  2026-09-01T00:00:00\nMD5:   0123 4567 89ab cdef 0123 4567 89ab cdef\nSHA-1: 1111 2222 3333 4444 5555 6666 7777 8888 9999 0000";
const SSL_ENUM_OUT = "\n  TLSv1.0: \n    ciphers: \n      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 1024) - C\n      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 1024) - A\n    compressors: \n      NULL\n    cipher preference: server\n    warnings: \n      64-bit block cipher 3DES vulnerable to SWEET32 attack\n  TLSv1.2: \n    ciphers: \n      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A\n    compressors: \n      NULL\n    cipher preference: server\n  least strength: C";
const SSH_ALGOS_OUT = "\n  kex_algorithms: (3)\n      curve25519-sha256@libssh.org\n      diffie-hellman-group14-sha1\n      diffie-hellman-group1-sha1\n  server_host_key_algorithms: (2)\n      ssh-rsa\n      ssh-dss\n  encryption_algorithms: (3)\n      aes128-ctr\n      aes128-cbc\n      3des-cbc\n  mac_algorithms: (2)\n      hmac-sha2-256\n      hmac-md5\n  compression_algorithms: (2)\n      none\n      zlib@openssh.com";
const SMB_PROTO_OUT = "\n  dialects: \n    NT LM 0.12 (SMBv1) [dangerous, but default]\n    2:0:2\n    2:1:0\n    3:0:0";
const SMB2_SEC_OUT = "\n  3:1:1: \n    Message signing enabled but not required";
const RDP_OUT = "\n  Security layer\n    CredSSP (NLA): SUCCESS\n    CredSSP with Early User Auth: SUCCESS\n    Native RDP: SUCCESS\n    RDSTLS: SUCCESS\n    SSL: SUCCESS\n  RDP Encryption level: Client Compatible\n    40-bit RC4: SUCCESS\n    56-bit RC4: SUCCESS\n    128-bit RC4: SUCCESS\n    FIPS 140-1: SUCCESS\n  RDP Protocol Version:  RDP 10.7 server";
const VULNERS_OUT = "\n  cpe:/a:openbsd:openssh:7.4p1: \n    \tCVE-2023-38408\t9.8\thttps://vulners.com/cve/CVE-2023-38408\n    \tCVE-2016-10012\t7.8\thttps://vulners.com/cve/CVE-2016-10012\n    \tSSV:92579\t7.5\thttps://vulners.com/seebug/SSV:92579\t*EXPLOIT*";

const nmapHost = (ip, name, ports, extra = "") => '<host starttime="1791450000" endtime="1791450100"><status state="up" reason="echo-reply" reason_ttl="63"/>\n<address addr="' + ip + '" addrtype="ipv4"/>\n<hostnames>' + (name ? '<hostname name="' + name + '" type="user"/><hostname name="' + name + '" type="PTR"/>' : "") + "</hostnames>\n<ports>" + ports + "</ports>" + extra + "\n</host>\n";
const nmapPort = (port, state, svc, scripts = "", proto = "tcp") => '<port protocol="' + proto + '" portid="' + port + '"><state state="' + state + '" reason="syn-ack" reason_ttl="63"/>' + svc + scripts + "</port>\n";
const svc = (name, product = "", version = "", extra = "") => '<service name="' + name + '"' + (product ? ' product="' + product + '"' : "") + (version ? ' version="' + version + '"' : "") + ' method="probed" conf="10"' + extra + "/>";
const script = (id, out, tables = "") => '<script id="' + id + '" output="' + x(out) + '">' + tables + "</script>";
const nmapXml = (args, services, hosts, start = 1791450000, up = 1) =>
  '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n<!-- Nmap 7.94SVN scan initiated as: ' + args + " -->\n" +
  '<nmaprun scanner="nmap" args="' + args + '" start="' + start + '" startstr="Thu Oct  8 09:00:00 2026" version="7.94SVN" xmloutputversion="1.05">\n' +
  '<scaninfo type="syn" protocol="tcp" numservices="' + (parsePortSpec(services).tcp.reduce((n, [a, b]) => n + b - a + 1, 0)) + '" services="' + services + '"/>\n<verbose level="0"/>\n<debugging level="0"/>\n' +
  '<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>\n<address addr="198.51.100.250" addrtype="ipv4"/>\n<hostnames>\n</hostnames>\n</hosthint>\n' +
  hosts + '<runstats><finished time="' + (start + 120) + '" timestr="Thu Oct  8 09:02:00 2026" summary="" elapsed="120.00" exit="success"/><hosts up="' + up + '" down="0" total="' + up + '"/>\n</runstats>\n</nmaprun>\n';

const NMAP_EXT = nmapXml("nmap -sS -sV -p 22,443,3389 --script ssl-cert,ssl-enum-ciphers,ssh2-enum-algos,rdp-enum-encryption,vulners -oX ext.xml 198.51.100.0/28", "22,443,3389",
  nmapHost("198.51.100.4", "vpn.test.darknode.ai",
    nmapPort(22, "open", svc("ssh", "OpenSSH", "7.4p1 Debian 10+deb9u7", ' extrainfo="protocol 2.0" ostype="Linux"'), script("ssh2-enum-algos", SSH_ALGOS_OUT) + script("vulners", VULNERS_OUT)) +
    nmapPort(443, "open", svc("http", "nginx", "1.18.0", ' tunnel="ssl"'), script("ssl-cert", SSL_CERT_OUT) + script("ssl-enum-ciphers", SSL_ENUM_OUT)) +
    nmapPort(3389, "open", svc("ms-wbt-server", "Microsoft Terminal Services"), script("rdp-enum-encryption", RDP_OUT))) +
  '<host><status state="down" reason="no-response" reason_ttl="0"/>\n<address addr="198.51.100.9" addrtype="ipv4"/></host>\n');

const NMAP_SMB = nmapXml("nmap -sS -sV -p 1-1024 --script smb-protocols,smb2-security-mode -oX smb.xml 10.30.0.0/24", "1-1024",
  nmapHost("10.30.0.5", "", nmapPort(445, "open", svc("microsoft-ds"))) .replace("</host>", '<hostscript><script id="smb-protocols" output="' + x(SMB_PROTO_OUT) + '"/><script id="smb2-security-mode" output="' + x(SMB2_SEC_OUT) + '"/></hostscript>\n</host>'));

const GNMAP = "# Nmap 7.94 scan initiated Thu Oct  8 09:00:00 2026 as: nmap -sV -p 1-1000 -oG out.gnmap 192.168.10.0/24\n" +
  "# Ports scanned: TCP(1000;1-1000) UDP(0;) SCTP(0;) PROTOCOLS(0;)\n" +
  "Host: 192.168.10.5 (nas.test.darknode.ai)\tStatus: Up\n" +
  "Host: 192.168.10.5 (nas.test.darknode.ai)\tPorts: 21/open/tcp//ftp//vsftpd 3.0.3/, 22/open/tcp//ssh//OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)/, 445/open/tcp//microsoft-ds?///\tIgnored State: closed (997)\n" +
  "Host: 192.168.10.6 ()\tStatus: Down\n" +
  "# Nmap done at Thu Oct  8 09:01:00 2026 -- 256 IP addresses (1 host up) scanned in 60.00 seconds\n";

const MASSCAN_JSON = "[\n" +
  '{   "ip": "203.0.113.20",   "timestamp": "1791450000", "ports": [ {"port": 23, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }\n,\n' +
  '{   "ip": "203.0.113.20",   "timestamp": "1791450002", "ports": [ {"port": 80, "proto": "tcp", "service": {"name": "http.server", "banner": "Apache/2.4.29 (Ubuntu)"} } ] }\n,\n' +
  '{   "ip": "203.0.113.21",   "timestamp": "1791450003", "ports": [ {"port": 22, "proto": "tcp", "service": {"name": "ssh", "banner": "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"} } ] }\n,\n' +
  "]\n";
const MASSCAN_TRUNC = '{ "ip": "203.0.113.30", "timestamp": "1791450000", "ports": [ {"port": 3389, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 117} ] },\n{ "ip": "203.0.113.31", "timestamp": "1791450001", "ports": [ {"port": 445, "proto": "tcp", "status": "open"';
const MASSCAN_XML = '<?xml version="1.0"?>\n<!-- masscan v1.3 scan -->\n<nmaprun scanner="masscan" start="1791450000" version="1.0-BETA"  xmloutputversion="1.03">\n<scaninfo type="syn" protocol="tcp" />\n' +
  '<host endtime="1791450001"><address addr="203.0.113.40" addrtype="ipv4"/><ports><port protocol="tcp" portid="9200"><state state="open" reason="syn-ack" reason_ttl="52"/></port></ports></host>\n<runstats>\n<finished time="1791450100" timestr="2026-10-08 09:01:40" elapsed="100" />\n<hosts up="1" down="0" total="1" />\n</runstats>\n</nmaprun>\n';

const NAABU = '{"host":"api.test.darknode.ai","ip":"203.0.113.50","timestamp":"2026-10-08T10:00:00.000Z","port":6379,"protocol":"tcp","tls":false}\n' +
  '{"host":"203.0.113.51","ip":"203.0.113.51","timestamp":"2026-10-08T10:00:01.000Z","port":{"Port":443,"Protocol":0,"TLS":true}}\n';

const NESSUS_CERT_OUT = "Subject Name: \n\nCommon Name: legacy.test.darknode.ai\n\nIssuer Name: \n\nCommon Name: legacy.test.darknode.ai\n\nSerial Number: 01 \n\nVersion: 3\n\nSignature Algorithm: SHA-1 With RSA Encryption\n\nNot Valid Before: Jan 01 00:00:00 2024 GMT\nNot Valid After: Aug 31 00:00:00 2026 GMT\n\nPublic Key Info:\n\nAlgorithm: RSA Encryption\nKey Length: 1024 bits\n\nFingerprints : \n\nSHA-1 Fingerprint: AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD\n\nExtension: Subject Alternative Name (2.5.29.17)\nCritical: 0\nDNS: legacy.test.darknode.ai\n";
const nItem = (port, svcName, pid, name, out) => '<ReportItem port="' + port + '" svc_name="' + svcName + '" protocol="tcp" severity="0" pluginID="' + pid + '" pluginName="' + name + '" pluginFamily="Service detection">' + (out != null ? "<plugin_output>" + x(out).replace(/&#xa;/g, "\n") + "</plugin_output>" : "") + "</ReportItem>\n";
const NESSUS = '<?xml version="1.0" ?>\n<NessusClientData_v2>\n<Policy><policyName>Basic</policyName><Preferences><ServerPreferences>' +
  "<preference><name>TARGET</name><value>10.40.0.0/24</value></preference><preference><name>port_range</name><value>1-1024,3389</value></preference>" +
  '</ServerPreferences></Preferences></Policy>\n<Report name="weekly" xmlns:cm="http://www.nessus.org/cm">\n<ReportHost name="10.40.0.7"><HostProperties>\n<tag name="HOST_END">Thu Oct  8 09:30:00 2026</tag>\n<tag name="host-fqdn">legacy.test.darknode.ai</tag>\n<tag name="host-ip">10.40.0.7</tag>\n<tag name="operating-system">Microsoft Windows Server 2012 R2 Standard</tag>\n<tag name="HOST_START">Thu Oct  8 09:00:00 2026</tag>\n</HostProperties>\n' +
  nItem(0, "general", "19506", "Nessus Scan Information", "Information about this scan") +
  nItem(80, "www", "11219", "Nessus SYN scanner", "Port 80/tcp was found to be open") +
  nItem(80, "www", "10107", "HTTP Server Type and Version", "The remote web server type is :\n\nMicrosoft-IIS/8.5") +
  nItem(443, "www", "56984", "SSL / TLS Versions Supported", "This port supports TLSv1.0/TLSv1.1/TLSv1.2.") +
  nItem(443, "www", "10863", "SSL Certificate Information", NESSUS_CERT_OUT) +
  nItem(3389, "msrdp", "22964", "Service Detection", "A Terminal Services server is running on this port.") +
  nItem(445, "cifs", "96982", "Server Message Block (SMB) Protocol Version 1 Enabled (uncredentialed check)", "The remote host supports SMBv1.") +
  "</ReportHost>\n</Report>\n</NessusClientData_v2>\n";

const SHODAN = '{"ip_str": "203.0.113.60", "port": 9200, "transport": "tcp", "product": "Elastic", "version": "7.10.2", "hostnames": ["search.test.darknode.ai"], "timestamp": "2026-10-07T03:12:45.123456", "_shodan": {"module": "elastic"}, "data": "HTTP/1.1 200 OK\\r\\ncontent-type: application/json", "vulns": {"CVE-2021-22145": {"cvss": 6.5, "verified": false}, "CVE-2021-22144": {"cvss": 6.5, "verified": false}}}\n' +
  '{"ip_str": "203.0.113.61", "port": 443, "transport": "tcp", "hostnames": ["shop.test.darknode.ai"], "timestamp": "2026-10-07T03:13:00.000000", "_shodan": {"module": "https"}, "http": {"server": "nginx/1.18.0", "title": "Shop"}, "data": "HTTP/1.1 200 OK\\r\\nServer: nginx/1.18.0", "ssl": {"versions": ["TLSv1", "-SSLv3", "TLSv1.2"], "cert": {"subject": {"CN": "shop.test.darknode.ai"}, "issuer": {"CN": "Test CA"}, "issued": "20250101000000Z", "expires": "20261101000000Z", "sig_alg": "sha256WithRSAEncryption", "pubkey": {"type": "rsa", "bits": 2048}, "fingerprint": {"sha1": "aabb"}}}}\n';

// ---------------------------------------------------------------------------
group("netexposure: format detection", () => {
  test("module identity", () => {
    assert.equal(TOOL_ID, "netexposure");
    assert.ok(/^\d+\.\d+\.\d+$/.test(VERSION));
    assert.ok(FORMATS["nmap-xml"] && FORMATS["shodan-ndjson"] && FORMATS.fwaudit);
  });
  test("detects every supported export by content, not file name", () => {
    const cases = [[NMAP_EXT, "nmap-xml"], [MASSCAN_XML, "masscan-xml"], [GNMAP, "nmap-grep"], [MASSCAN_JSON, "masscan-json"], [NAABU, "naabu-jsonl"], [NESSUS, "nessus"], [SHODAN, "shodan-ndjson"],
      ['{"tool":"Darknode Firewall Rule Audit","rules":[]}', "fwaudit"], ["ip,port,service\n10.0.0.1,22,ssh\n", "csv"]];
    for (const [text, fmt] of cases) assert.equal(detectFormat(text, "renamed.txt").format, fmt, fmt);
  });
  test("unknown and empty input are not guessed", () => {
    assert.equal(detectFormat("").format, "unknown");
    assert.equal(detectFormat("hello world").format, "unknown");
    assert.equal(detectFormat('{"a":1}').format, "unknown");
    const weak = detectFormat("addr;dienst\n10.0.0.1;ssh\n");
    assert.equal(weak.format, "csv"); assert.ok(weak.confidence < 0.5); assert.deepEqual(weak.headers, ["addr", "dienst"]);
  });
});

group("netexposure: nmap parsers", () => {
  test("nmap XML: hosts, ports, products, down hosts and <hosthint> skipped", () => {
    const s = parseNmapXml(NMAP_EXT, "ext.xml");
    assert.deepEqual([...s.hosts.keys()], ["198.51.100.4"]);
    assert.ok(s.down.has("198.51.100.9"));
    const r = rec(s, "198.51.100.4", 22);
    assert.equal(r.product, "OpenSSH"); assert.equal(r.version, "7.4p1 Debian 10+deb9u7"); assert.equal(r.service, "ssh");
    assert.equal(recs(s).length, 3);
    assert.equal(s.timeMs, 1791450000 * 1000);
  });
  test("nmap XML: coverage comes from scaninfo services", () => {
    const s = parseNmapXml(NMAP_EXT, "ext.xml");
    assert.deepEqual(s.scanned.tcp, [[22, 22], [443, 443], [3389, 3389]]);
    assert.equal(s.scannedSource, "scaninfo");
  });
  test("nmap XML: NSE ssl-cert / ssl-enum-ciphers / ssh2-enum-algos / rdp / vulners are applied", () => {
    const s = parseNmapXml(NMAP_EXT, "ext.xml");
    const tls = rec(s, "198.51.100.4", 443);
    assert.equal(tls.tls.cert.subjectCN, "vpn.test.darknode.ai");
    assert.ok(tls.tls.cert.selfSigned);
    assert.equal(tls.tls.cert.keyBits, 1024);
    assert.ok(tls.tls.versions.includes("TLSv1.0"));
    assert.ok(tls.scripts["ssl-cert"].includes("Not valid after"));
    const ssh = rec(s, "198.51.100.4", 22);
    assert.ok(ssh.vulns.some((v) => v.id === "CVE-2023-38408" && v.score === 9.8));
    assert.ok(ssh.scriptFindings.some((v) => v.key === "ssh-weak-algos"));
    assert.ok(rec(s, "198.51.100.4", 3389).scriptFindings.some((v) => v.key === "rdp-weak-enc"));
  });
  test("nmap XML: host-level SMB scripts attach to port 445", () => {
    const s = parseNmapXml(NMAP_SMB, "smb.xml");
    const keys = rec(s, "10.30.0.5", 445).scriptFindings.map((v) => v.key).sort();
    assert.deepEqual(keys, ["smb-signing-not-required", "smbv1"]);
  });
  test("nmap -oG: ports, versions, PTR names, coverage line and down hosts", () => {
    const s = parseNmapGrep(GNMAP, "out.gnmap");
    assert.deepEqual([...s.hosts.keys()], ["192.168.10.5"]);
    assert.ok(s.down.has("192.168.10.6"));
    const r = rec(s, "192.168.10.5", 22);
    assert.equal(r.product, "OpenSSH"); assert.ok(r.version.startsWith("8.2p1"));
    assert.equal(rec(s, "192.168.10.5", 21).product, "vsftpd");
    assert.ok(rec(s, "192.168.10.5", 445).serviceGuess, "microsoft-ds? is a guess");
    assert.deepEqual(s.scanned.tcp, [[1, 1000]]);
    assert.equal(s.scannedSource, "ports-scanned line");
    assert.equal(s.hosts.get("192.168.10.5").hostnames[0].name, "nas.test.darknode.ai");
  });
  test("parsePortSpec and parseNmapArgs", () => {
    assert.deepEqual(parsePortSpec("22,80-81,U:53,T:443"), { tcp: [[22, 22], [80, 81], [443, 443]], udp: [[53, 53]] });
    assert.equal(parsePortSpec("abc"), null);
    assert.deepEqual(parsePortSpec("-").tcp, [[1, 65535]]);
    const a = parseNmapArgs("nmap -sS -p 1-1024 -oX out.xml 10.0.0.0/24 host.test.darknode.ai");
    assert.deepEqual(a.scanned.tcp, [[1, 1024]]);
    assert.ok(a.targets.text.includes("10.0.0.0/24"));
  });
});
group("netexposure: other scanners", () => {
  test("masscan -oJ with the trailing-comma quirk and banner records", () => {
    const s = parseMasscanJson(MASSCAN_JSON, "m.json");
    assert.deepEqual([...s.hosts.keys()].sort(ipCmp), ["203.0.113.20", "203.0.113.21"]);
    assert.ok(rec(s, "203.0.113.20", 23).serviceGuess, "port-only record is a guess");
    const web = rec(s, "203.0.113.20", 80);
    assert.equal(web.product, "Apache httpd"); assert.equal(web.version, "2.4.29");
    const ssh = rec(s, "203.0.113.21", 22);
    assert.equal(ssh.product, "OpenSSH"); assert.ok(ssh.version.startsWith("7.4p1"));
    assert.equal(s.timeMs, 1791450000 * 1000);
    assert.ok(s.notes.some((n) => /coverage is unknown/.test(n)));
    assert.equal(s.scanned.tcp, null);
  });
  test("masscan -oJ truncated mid-record still yields the complete lines", () => {
    const s = parseMasscanJson(MASSCAN_TRUNC, "m.json");
    assert.ok(rec(s, "203.0.113.30", 3389));
    assert.ok(!s.hosts.has("203.0.113.31"));
  });
  test("masscan -oX is read through the nmap XML parser with unknown coverage", () => {
    const s = parseNmapXml(MASSCAN_XML, "m.xml");
    assert.equal(s.scanner, "masscan");
    assert.ok(rec(s, "203.0.113.40", 9200).serviceGuess);
    assert.equal(s.scanned.tcp, null);
  });
  test("naabu -json: flat and nested port objects, host names, TLS flag", () => {
    const s = parseNaabu(NAABU, "n.jsonl");
    assert.ok(rec(s, "203.0.113.50", 6379));
    assert.equal(s.hosts.get("203.0.113.50").hostnames[0].name, "api.test.darknode.ai");
    const t = rec(s, "203.0.113.51", 443);
    assert.equal(t.tunnel, "ssl");
    assert.equal(s.hosts.get("203.0.113.51").hostnames.length, 0);
  });
  test("Nessus v2: ports and services only, server header, TLS versions, cert and port_range coverage", () => {
    const s = parseNessus(NESSUS, "w.nessus");
    const h = s.hosts.get("10.40.0.7");
    assert.ok(h);
    assert.equal(h.nessusOs, "Microsoft Windows Server 2012 R2 Standard");
    assert.ok(!h.recs.has("tcp/0"), "port 0 items are host-level");
    assert.equal(rec(s, "10.40.0.7", 80).service, "http");
    assert.equal(rec(s, "10.40.0.7", 80).product, "Microsoft IIS httpd");
    assert.deepEqual(rec(s, "10.40.0.7", 443).tls.versions, ["TLSv1.0", "TLSv1.1", "TLSv1.2"]);
    assert.equal(rec(s, "10.40.0.7", 443).tls.cert.subjectCN, "legacy.test.darknode.ai");
    assert.equal(rec(s, "10.40.0.7", 3389).service, "ms-wbt-server");
    assert.ok(rec(s, "10.40.0.7", 445).scriptFindings.some((v) => v.key === "smbv1"));
    assert.deepEqual(s.scanned.tcp, [[1, 1024], [3389, 3389]]);
    assert.ok(s.targets.text.includes("10.40.0.0/24"));
  });
  test("Nessus 10863 certificate block", () => {
    const c = parseNessusCert(NESSUS_CERT_OUT);
    assert.equal(c.subjectCN, "legacy.test.darknode.ai"); assert.equal(c.issuerCN, "legacy.test.darknode.ai");
    assert.ok(c.selfSigned); assert.equal(c.keyBits, 1024); assert.ok(/SHA-1/i.test(c.sigAlg));
    assert.equal(c.notAfter.slice(0, 10), "2026-08-31");
    assert.deepEqual(c.sans, ["legacy.test.darknode.ai"]);
    assert.equal(parseNessusCert("nothing useful"), null);
  });
  test("Shodan NDJSON: banners, TLS, certificate, CVEs kept as reported (not re-scored)", () => {
    const s = parseShodan(SHODAN, "s.json");
    assert.ok(s.defaultExternal);
    const es = rec(s, "203.0.113.60", 9200);
    assert.equal(es.product, "Elastic");
    assert.deepEqual(es.vulns.map((v) => [v.id, v.score, v.source]), [["CVE-2021-22144", 6.5, "Shodan"], ["CVE-2021-22145", 6.5, "Shodan"]]);
    const web = rec(s, "203.0.113.61", 443);
    assert.deepEqual(web.tls.versions, ["TLSv1.0", "TLSv1.2"], "negated -SSLv3 dropped, TLSv1 normalised");
    assert.equal(web.tls.cert.notAfter.slice(0, 10), "2026-11-01");
    assert.equal(web.banners.title, "Shop");
  });
  test("Shodan host JSON ({ ip_str, data: [...] })", () => {
    const host = JSON.stringify({ ip_str: "203.0.113.70", hostnames: ["h.test.darknode.ai"], data: [{ port: 22, transport: "tcp", data: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n", _shodan: { module: "ssh" } }, { port: 3389, transport: "tcp", _shodan: { module: "rdp" } }] }, null, 2);
    assert.equal(detectFormat(host).format, "shodan-host");
    const s = parseShodan(host, "h.json");
    assert.equal(rec(s, "203.0.113.70", 22).product, "OpenSSH");
    assert.ok(rec(s, "203.0.113.70", 3389));
  });
  test("CSV port list with automatic and user-mapped columns", () => {
    const auto = parsePortCsv("IP Address,Port,Protocol,Service\n10.50.0.1,3389,tcp,ms-wbt-server\n10.50.0.1,53/udp,,domain\nbad,22,tcp,ssh\n", "p.csv");
    assert.ok(rec(auto, "10.50.0.1", 3389));
    assert.ok(rec(auto, "10.50.0.1", 53, "udp"));
    assert.equal(auto.hosts.size, 1);
    const mapped = parsePortCsv("addr;dienstport\n10.50.0.2;23\n", "p.csv", { ip: "addr", port: "dienstport" });
    assert.ok(rec(mapped, "10.50.0.2", 23));
    const unmapped = parsePortCsv("addr;dienstport\n10.50.0.2;23\n", "p.csv");
    assert.equal(unmapped.hosts.size, 0);
    assert.ok(unmapped.notes.some((n) => /map them/.test(n)));
  });
  test("parseInput lists every file with format, records and notes", () => {
    const p = parseInput([f("a.xml", NMAP_EXT), f("b.json", MASSCAN_JSON), f("c.txt", "nothing")]);
    assert.equal(p.format, "multi");
    assert.deepEqual(p.files.map((x) => x.format), ["nmap-xml", "masscan-json", "unknown"]);
    assert.equal(p.files[0].records, 3);
    assert.equal(p.files[0].portsScanned, 3);
    assert.equal(p.files[1].portsScanned, null);
    assert.ok(p.skipped.some((s) => /c\.txt/.test(s.reason)));
    assert.equal(p.rows.length, 6);
  });
});

group("netexposure: NSE and banner parsers", () => {
  test("ssl-cert text output", () => {
    const c = parseSslCert(SSL_CERT_OUT);
    assert.equal(c.subjectCN, "vpn.test.darknode.ai");
    assert.deepEqual(c.sans, ["vpn.test.darknode.ai", "www.test.darknode.ai"]);
    assert.equal(c.notAfter.slice(0, 10), "2026-09-01");
    assert.equal(c.sigAlg, "sha1WithRSAEncryption");
    assert.equal(c.sha1, "1111222233334444555566667777888899990000");
    assert.equal(parseSslCert(""), null);
  });
  test("ssl-cert structured table output", () => {
    const c = parseSslCert("", { subject: { commonName: "a.test.darknode.ai" }, issuer: { commonName: "Test CA", organizationName: "Test" }, pubkey: { type: "ec", bits: "256" }, sig_algo: "ecdsa-with-SHA256", validity: { notBefore: "2026-01-01T00:00:00", notAfter: "2027-01-01T00:00:00" }, extensions: [{ name: "X509v3 Subject Alternative Name", value: "DNS:a.test.darknode.ai, IP Address:192.0.2.1" }] });
    assert.ok(!c.selfSigned); assert.equal(c.keyType, "ec"); assert.equal(c.keyBits, 256);
    assert.deepEqual(c.sans, ["a.test.darknode.ai"]);
  });
  test("ssl-enum-ciphers: versions, least strength and grade C-or-worse ciphers", () => {
    const r = parseSslEnumCiphers(SSL_ENUM_OUT);
    assert.deepEqual(r.versions, ["TLSv1.0", "TLSv1.2"]);
    assert.equal(r.leastStrength, "C");
    assert.deepEqual(r.weak, [{ version: "TLSv1.0", cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", grade: "C" }]);
  });
  test("ssh2-enum-algos: weak kex, host key, cipher and MAC", () => {
    const r = parseSsh2EnumAlgos(SSH_ALGOS_OUT);
    assert.deepEqual(r.weak, ["kex: diffie-hellman-group1-sha1", "hostkey: ssh-dss", "enc: aes128-cbc", "enc: 3des-cbc", "mac: hmac-md5"]);
    assert.ok(!r.kex.includes("none"), "compression is not mixed into kex");
  });
  test("smb-protocols and smb2-security-mode", () => {
    assert.ok(parseSmbProtocols(SMB_PROTO_OUT).smbv1);
    assert.ok(!parseSmbProtocols("\n  dialects: \n    2:1:0\n    3:1:1").smbv1);
    assert.equal(parseSmbSigning(SMB2_SEC_OUT).signingRequired, false);
    assert.equal(parseSmbSigning("\n  3:1:1: \n    Message signing enabled and required").signingRequired, true);
    assert.equal(parseSmbSigning("").signingRequired, null);
  });
  test("rdp-enum-encryption and vulners", () => {
    assert.deepEqual(parseRdpEnum(RDP_OUT), { nativeRdp: true, nla: true, weakRc4: true });
    assert.deepEqual(parseRdpEnum("\n  Security layer\n    CredSSP (NLA): SUCCESS\n  RDP Protocol Version: RDP 10.7 server"), { nativeRdp: false, nla: true, weakRc4: false });
    assert.deepEqual(parseVulners(VULNERS_OUT).map((v) => v.id), ["CVE-2016-10012", "CVE-2023-38408"], "non-CVE ids (SSV) are dropped");
  });
  test("SSH banner, Server header and nmap product strings", () => {
    assert.deepEqual(parseSshBanner("SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"), { product: "OpenSSH", version: "7.4p1 Debian-10+deb9u7", protocol: "2.0" });
    assert.deepEqual(parseServerHeader("nginx/1.18.0 (Ubuntu)").parts, [{ name: "nginx", version: "1.18.0" }]);
    assert.deepEqual(parseServerHeader("nginx/1.18.0 (Ubuntu)").comments, ["Ubuntu"]);
    assert.equal(splitProductVersion("vsftpd 3.0.3").version, "3.0.3");
  });
});
// A plain nmap XML scan of chosen ports on chosen hosts (all at the same start time unless given).
const simple = (targets, range, hosts, start = 1791450000) => nmapXml("nmap -sS -sV -p " + range + " -oX s.xml " + targets, range,
  hosts.map(([ip, ports]) => nmapHost(ip, "", ports.map(([p, name, product, version]) => nmapPort(p, "open", svc(name, product, version))).join(""))).join(""), start, hosts.length);
const R1 = (rec0) => ({ ip: "198.51.100.1", proto: "tcp", state: "open", service: "", product: "", version: "", serviceGuess: false, banners: {}, scriptFindings: [], ...rec0 });

group("netexposure: risk rules", () => {
  test("rule table is complete and every rule cites controls", () => {
    assert.ok(RULES.length >= 55, "about 60 rules, got " + RULES.length);
    const ids = new Set();
    for (const r of RULES) {
      assert.ok(!ids.has(r.id), "duplicate " + r.id); ids.add(r.id);
      assert.ok(r.ext in SEV_RANK && (r.int == null || r.int in SEV_RANK), r.id);
      assert.ok(r.controls.length > 0 && r.why && r.fix, r.id);
    }
  });
  test("matches by well-known port, by service on a non-standard port, not on plain HTTPS", () => {
    assert.ok(matchRules(R1({ port: 3389, service: "ms-wbt-server" })).some((r) => r.id === "rdp"));
    assert.ok(matchRules(R1({ port: 3389, serviceGuess: true })).some((r) => r.id === "rdp"));
    assert.ok(matchRules(R1({ port: 16379, service: "redis" })).some((r) => r.id === "redis"));
    assert.equal(matchRules(R1({ port: 443, service: "https" })).length, 0);
    assert.equal(matchRules(R1({ port: 3389, service: "http" })).filter((r) => r.id === "rdp").length, 0, "a known non-RDP service on 3389 is not RDP");
  });
  test("external exposure is graded higher than the same service internally", () => {
    const xml = simple("198.51.100.0/28 10.60.0.0/28", "3389", [["10.60.0.2", [[3389, "ms-wbt-server"]]], ["198.51.100.2", [[3389, "ms-wbt-server"]]]]);
    const r = analyze([f("s.xml", xml)]);
    assert.equal(fid(r, "exp-rdp-external").severity, "critical");
    assert.equal(fid(r, "exp-rdp-internal").severity, "low");
    assert.deepEqual(fid(r, "exp-rdp-external").evidence.map((e) => e.ip), ["198.51.100.2"]);
    const off = analyze([f("s.xml", xml)], { reportInternal: false });
    assert.ok(!fid(off, "exp-rdp-internal"));
  });
  test("'scanned from outside' marks every address of that scan as external", () => {
    const xml = simple("10.60.0.0/28", "23", [["10.60.0.3", [[23, "telnet"]]]]);
    const r = analyze([f("s.xml", xml)], { scans: { "s.xml": { external: true } } });
    assert.ok(fid(r, "exp-telnet-external"));
    assert.ok(!fid(r, "exp-telnet-internal"));
  });
  test("custom internal CIDRs replace the RFC 1918 defaults", () => {
    const xml = simple("198.51.100.0/28", "3389", [["198.51.100.2", [[3389, "ms-wbt-server"]]]]);
    const r = analyze([f("s.xml", xml)], { internalCidrs: "198.51.100.0/24" });
    assert.ok(fid(r, "exp-rdp-internal")); assert.ok(!fid(r, "exp-rdp-external"));
  });
  test("allow-list: parsing and suppression with the reason kept", () => {
    const al = parseAllowList("# comment\n198.51.100.2:3389 jump host behind MFA\n*:22/tcp bastions\n10.0.0.0/8:445 file servers\n[2001:db8::5]:443 web\nnot-an-ip:22 x\n198.51.100.3:abc bad");
    assert.deepEqual(al.map((a) => a.spec), ["198.51.100.2:3389", "*:22/tcp", "10.0.0.0/8:445", "[2001:db8::5]:443"]);
    assert.equal(al[0].reason, "jump host behind MFA");
    const xml = simple("198.51.100.0/28", "3389", [["198.51.100.2", [[3389, "ms-wbt-server"]]]]);
    const r = analyze([f("s.xml", xml)], { allowList: "198.51.100.2:3389 jump host behind MFA" });
    assert.ok(!fid(r, "exp-rdp-external"));
    const ex = r.tables.exposures.find((e) => e.port === 3389);
    assert.ok(ex.allowListed); assert.equal(r.summary.allowListed, 1);
  });
});

group("netexposure: end of life", () => {
  test("compareVersions and findCycle", () => {
    assert.equal(compareVersions("1.18.0", "1.24.0"), -1);
    assert.equal(compareVersions("7.4p1", "7.4"), 1);
    assert.equal(compareVersions("2.4.29", "2.4.29"), 0);
    assert.equal(compareVersions("abc", "1"), null);
    const nginx = EOL_FIXTURE.data.find((p) => p.product === "nginx");
    assert.equal(findCycle(nginx, "1.18.0").cycle, "1.18");
    assert.equal(findCycle(nginx, "0.9"), null);
    assert.equal(findCycle({ cycles: [{ cycle: "2" }, { cycle: "2.426" }] }, "2.426.3", 2).cycle, "2.426");
  });
  test("candidates: OpenSSH distro suffixes, IIS -> Windows Server, Server header", () => {
    const deb = eolCandidates(R1({ product: "OpenSSH", version: "7.4p1 Debian 10+deb9u7" }));
    assert.deepEqual(deb.map((c) => [c.slug, c.cycle]), [["debian", "9"]]);
    const ub = eolCandidates(R1({ product: "OpenSSH", version: "7.6p1 Ubuntu 4ubuntu0.7", extrainfo: "Ubuntu Linux; protocol 2.0" }));
    assert.deepEqual(ub.map((c) => [c.slug, c.cycle]), [["ubuntu", "18.04"]]);
    assert.deepEqual(eolCandidates(R1({ product: "OpenSSH", version: "9.6p1" })), [], "plain OpenSSH is not guessed");
    const iis = eolCandidates(R1({ product: "Microsoft IIS httpd", version: "8.5" }));
    assert.ok(iis.some((c) => c.slug === "windows-server" && c.cycle === "2012-r2"));
    const hdr = eolCandidates(R1({ banners: { server: "Apache/2.4.6 (CentOS) PHP/5.4.16" } }));
    assert.deepEqual(hdr.map((c) => c.slug).sort(), ["apache-http-server", "centos", "php"]);
  });
  test("EOL findings from the feed; extended support lowers the severity; skipped without a feed", () => {
    const xml = simple("198.51.100.0/28", "22,6379", [["198.51.100.5", [[22, "ssh", "OpenSSH", "7.4p1 Debian 10+deb9u7"], [6379, "redis", "Redis key-value store", "5.0.7"]]]]);
    const r = analyze([f("s.xml", xml)], { eol: EOL_FIXTURE });
    const redis = fid(r, "eol-redis-5.0-eol"), deb = fid(r, "eol-debian-9-eol");
    assert.ok(redis && deb);
    assert.ok(SEV_RANK[deb.severity] < SEV_RANK[redis.severity], "Debian 9 has extended LTS");
    assert.ok(r.tables.eol.some((e) => e.slug === "redis" && e.status === "eol"));
    const none = analyze([f("s.xml", xml)]);
    assert.ok(!none.findings.some((x) => x.id.startsWith("eol-")));
    assert.ok(none.skipped.some((s) => s.check === "end-of-life"));
  });
});

group("netexposure: certificates, TLS, SSH, SMB, RDP", () => {
  const r = analyze([f("ext.xml", NMAP_EXT), f("smb.xml", NMAP_SMB)], { now: "2026-10-08T00:00:00Z" });
  test("certificate checks: expired, self-signed external, weak key, SHA-1", () => {
    for (const id of ["cfg-cert-expired", "cfg-cert-self-signed", "cfg-cert-weak-key"]) assert.ok(fid(r, id), id);
    assert.ok(!fid(r, "cfg-cert-sha1"), "a self-signature is not judged by its hash");
    const ca = analyze([f("ext.xml", NMAP_EXT.replace("Issuer: commonName=vpn.test.darknode.ai", "Issuer: commonName=Test CA"))], { now: "2026-08-15T00:00:00Z" });
    assert.ok(fid(ca, "cfg-cert-sha1")); assert.ok(!fid(ca, "cfg-cert-self-signed"));
    const row = r.tables.certificates.find((c) => c.ip === "198.51.100.4");
    assert.ok(/expired/.test(row.issues) && /self-signed/.test(row.issues) && /RSA 1024/.test(row.issues));
  });
  test("expiring soon and host-name mismatch use the reference date and user-supplied names", () => {
    const soon = analyze([f("ext.xml", NMAP_EXT)], { now: "2026-08-15T00:00:00Z" });
    assert.ok(fid(soon, "cfg-cert-expiring")); assert.ok(!fid(soon, "cfg-cert-expired"));
    const mm = analyze([f("ext.xml", NMAP_EXT.replace(/vpn\.test\.darknode\.ai" type="user"/, 'other.test.darknode.ai" type="user"'))], { now: "2026-08-15T00:00:00Z" });
    assert.ok(fid(mm, "cfg-cert-mismatch"));
    assert.ok(!fid(soon, "cfg-cert-mismatch"));
  });
  test("legacy TLS and weak cipher grades", () => {
    assert.ok(fid(r, "cfg-tls-legacy"));
    assert.ok(fid(r, "cfg-tls-weak-ciphers").evidence.some((e) => /3DES/.test(JSON.stringify(e))));
  });
  test("weak SSH algorithms, SMBv1, SMB signing, RDP without NLA and weak RC4", () => {
    for (const id of ["cfg-ssh-weak", "cfg-smbv1", "cfg-smb-signing", "cfg-rdp-nla", "cfg-rdp-rc4"]) assert.ok(fid(r, id), id);
    assert.equal(fid(r, "cfg-smbv1").evidence[0].ip, "10.30.0.5");
  });
  test("scanner-reported CVEs are labelled as reported, with the score as given", () => {
    const c = r.findings.find((x) => x.id.startsWith("cve-198.51.100.4"));
    assert.ok(c); assert.equal(c.confidence, "review");
    assert.ok(c.evidence.every((e) => /reported by scanner/.test(e.source)));
    assert.equal(c.evidence.find((e) => e.cve === "CVE-2023-38408").reportedScore, 9.8);
    const sh = analyze([f("s.json", SHODAN)]);
    const es = sh.findings.find((x) => x.id.startsWith("cve-203.0.113.60"));
    assert.ok(/reported by Shodan/.test(es.description));
  });
});
group("netexposure: scan diff and coverage", () => {
  const T1 = 1790845200, T2 = 1791450000; // 2026-10-01, 2026-10-08
  const week1 = simple("10.70.0.0/28", "1-10000", [["10.70.0.2", [[22, "ssh", "OpenSSH", "8.9p1"], [80, "http", "nginx", "1.24.0"]]], ["10.70.0.3", [[443, "https"]]]], T1);
  test("risky port opened is reported as a change finding; versions and new hosts tracked", () => {
    const week2 = simple("10.70.0.0/28", "1-10000", [["10.70.0.2", [[22, "ssh", "OpenSSH", "8.9p1"], [80, "http", "nginx", "1.22.1"], [2375, "docker", "Docker", "24.0.7"]]], ["10.70.0.3", [[443, "https"]]], ["10.70.0.4", [[22, "ssh"]]]], T2);
    const r = analyze([f("w2.xml", week2), f("w1.xml", week1)]);
    assert.deepEqual(r.tables.scans.map((s) => s.label), ["w1.xml", "w2.xml"], "ordered by scan time, not file name");
    const op = chType(r, "port-opened");
    assert.equal(op.length, 1); assert.equal(op[0].port, 2375); assert.ok(op[0].risky);
    assert.ok(fid(r, "chg-port-opened-risky"));
    assert.equal(chType(r, "version-downgrade")[0].before, "nginx 1.24.0");
    assert.ok(fid(r, "chg-version-downgrade"));
    assert.equal(chType(r, "new-host")[0].ip, "10.70.0.4");
    assert.equal(r.summary.newSinceLast, 2);
  });
  test("a newly opened risky port on an external address is high", () => {
    const a = simple("198.51.100.0/28", "1-10000", [["198.51.100.7", [[443, "https"]]]], T1);
    const b = simple("198.51.100.0/28", "1-10000", [["198.51.100.7", [[443, "https"], [6379, "redis", "Redis key-value store", "7.2.4"]]]], T2);
    const r = analyze([f("a.xml", a), f("b.xml", b)]);
    assert.ok(SEV_RANK[chType(r, "port-opened")[0].severity] >= SEV_RANK.high);
    assert.ok(SEV_RANK[fid(r, "chg-port-opened-risky").severity] >= SEV_RANK.high);
    const inside = analyze([f("a.xml", a.replace(/198\.51\.100\./g, "10.80.0.")), f("b.xml", b.replace(/198\.51\.100\./g, "10.80.0."))]);
    assert.ok(SEV_RANK[chType(inside, "port-opened")[0].severity] <= SEV_RANK.medium, "internal opening is capped at medium");
  });
  test("a port is closed only when the newer scan covered it", () => {
    const narrow = simple("10.70.0.0/28", "22,443", [["10.70.0.2", [[22, "ssh", "OpenSSH", "8.9p1"]]], ["10.70.0.3", []]], T2);
    const r = analyze([f("w1.xml", week1), f("w2.xml", narrow)]);
    assert.ok(chType(r, "port-closed").some((c) => c.ip === "10.70.0.3" && c.port === 443));
    const nr = chType(r, "port-not-rescanned");
    assert.deepEqual(nr.map((c) => c.port), [80], "port 80 was outside 22,443");
    assert.ok(fid(r, "chg-coverage-reduced"));
    assert.ok(r.tables.exposures.some((s) => s.ip === "10.70.0.2" && s.port === 80), "an unscanned port stays in the inventory");
    assert.ok(!r.tables.exposures.some((s) => s.ip === "10.70.0.3" && s.port === 443), "a scanned and closed port leaves the inventory");
  });
  test("unknown coverage (masscan, naabu) never reports a closed port", () => {
    const a = '[\n{ "ip": "203.0.113.80", "timestamp": "1790845200", "ports": [ {"port": 22, "proto": "tcp", "status": "open"} ] },\n{ "ip": "203.0.113.80", "timestamp": "1790845200", "ports": [ {"port": 3389, "proto": "tcp", "status": "open"} ] }\n]';
    const b = '[\n{ "ip": "203.0.113.80", "timestamp": "1791450000", "ports": [ {"port": 22, "proto": "tcp", "status": "open"} ] }\n]';
    const r = analyze([f("a.json", a), f("b.json", b)]);
    assert.equal(chType(r, "port-closed").length, 0);
    assert.equal(chType(r, "port-not-seen")[0].port, 3389);
    assert.ok(r.tables.exposures.some((s) => s.port === 3389), "still listed until a covering scan shows it closed");
    const covered = analyze([f("a.json", a), f("b.json", b)], { scans: { "b.json": { ports: "1-65535" } } });
    assert.equal(chType(covered, "port-closed")[0].port, 3389);
  });
  test("host disappeared vs outside the newer scan's targets", () => {
    const gone = simple("10.70.0.0/28", "1-10000", [["10.70.0.2", [[22, "ssh", "OpenSSH", "8.9p1"], [80, "http", "nginx", "1.24.0"]]]], T2);
    const r = analyze([f("w1.xml", week1), f("w2.xml", gone)]);
    assert.equal(chType(r, "host-disappeared")[0].ip, "10.70.0.3");
    const other = simple("10.70.0.2", "1-10000", [["10.70.0.2", [[22, "ssh", "OpenSSH", "8.9p1"], [80, "http", "nginx", "1.24.0"]]]], T2);
    const r2 = analyze([f("w1.xml", week1), f("w2.xml", other)]);
    assert.equal(chType(r2, "host-disappeared").length, 0);
    assert.equal(chType(r2, "host-not-rescanned")[0].ip, "10.70.0.3");
    assert.ok(r2.tables.exposures.some((s) => s.ip === "10.70.0.3"), "not rescanned is not closed");
  });
  test("scans panel: labels merge files into one scan and order overrides time", () => {
    const r = analyze([f("w1.xml", week1), f("w2.xml", simple("10.70.0.0/28", "1-10000", [["10.70.0.2", [[22, "ssh"]]]], T2))], { scans: { "w1.xml": { label: "Later", order: 2 }, "w2.xml": { label: "Earlier", order: 1 } } });
    assert.deepEqual(r.tables.scans.map((s) => s.label), ["Earlier", "Later"]);
    const m = analyze([f("a.xml", week1), f("b.json", MASSCAN_JSON)], { scans: { "a.xml": { label: "Week 41" }, "b.json": { label: "Week 41" } } });
    assert.equal(m.tables.scans.length, 1);
    assert.ok(/a\.xml/.test(m.tables.scans[0].files) && /b\.json/.test(m.tables.scans[0].files));
    assert.ok(m.skipped.some((s) => s.check === "scan-diff"));
  });
});

group("netexposure: segmentation (Firewall Rule Audit export)", () => {
  const FW = JSON.stringify({ tool: "Darknode Firewall Rule Audit", format: "iptables", rules: [
    { idx: 1, scope: "INPUT", action: "allow", direction: "in", proto: "tcp", src: "10.0.0.0/8", dst: "any", dstPorts: "22", enabled: true },
    { idx: 2, scope: "INPUT", action: "deny", direction: "in", proto: "tcp", src: "any", dst: "198.51.100.2/32", dstPorts: "3389", enabled: true },
    { idx: 3, scope: "INPUT", action: "allow", direction: "in", proto: "tcp", src: "any", dst: "198.51.100.3/32", dstPorts: "443", enabled: true },
    { idx: 4, scope: "INPUT", action: "deny", direction: "in", proto: "any", src: "any", dst: "any", dstPorts: "any", enabled: true },
  ] });
  const cidrs = compileCidrs(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
  test("fwDecide: explicit deny, allow, and an inconclusive catch-all", () => {
    const fw = parseFwaudit(FW);
    assert.equal(fwDecide(fw, "198.51.100.2", 3389, "tcp", cidrs).decision, "deny");
    assert.equal(fwDecide(fw, "198.51.100.3", 443, "tcp", cidrs).decision, "allow");
    assert.equal(fwDecide(fw, "198.51.100.9", 23, "tcp", cidrs).decision, null, "catch-all deny is not specific enough");
    assert.equal(fwDecide(fw, "198.51.100.2", 22, "tcp", cidrs).decision, null, "internal-only allow is skipped, then catch-all");
  });
  test("fwDecide: unresolved objects and partial sources stay undecided", () => {
    const fw = parseFwaudit(JSON.stringify({ tool: "Darknode Firewall Rule Audit", rules: [{ idx: 1, scope: "outside_in", action: "deny", proto: "tcp", src: "203.0.113.0/24", dst: "198.51.100.2/32", dstPorts: "3389" }, { idx: 2, scope: "outside_in", action: "deny", proto: "tcp", src: "any", dst: "WEB-SERVERS", dstPorts: "3389" }] }));
    assert.equal(fwDecide(fw, "198.51.100.2", 3389, "tcp", cidrs).decision, null);
  });
  test("drift finding only for scans marked as run from outside", () => {
    const xml = simple("198.51.100.0/28", "3389", [["198.51.100.2", [[3389, "ms-wbt-server"]]]]);
    const inside = analyze([f("s.xml", xml), f("fw.json", FW)]);
    assert.ok(!fid(inside, "seg-drift"));
    assert.ok(inside.skipped.some((s) => s.check === "segmentation" && /outside/.test(s.reason)));
    const outside = analyze([f("s.xml", xml), f("fw.json", FW)], { scans: { "s.xml": { external: true } } });
    const d = fid(outside, "seg-drift");
    assert.ok(d); assert.equal(d.confidence, "review"); assert.equal(d.evidence[0].rule, "#2");
    assert.ok(analyze([f("s.xml", xml)]).skipped.some((s) => s.check === "segmentation"));
  });
});

group("netexposure: results, exports, example and invariants", () => {
  const ex = exampleDataset();
  const opts = { scans: ex.scans, eol: EOL_FIXTURE, allowList: ex.allowList };
  const r = analyze(ex.files, opts);
  test("every finding has the required shape and cites controls", () => {
    assert.ok(r.findings.length > 10);
    for (const x of r.findings) {
      assert.ok(x.id && x.title && x.description && x.recommendation, x.id);
      assert.ok(x.severity in SEV_RANK, x.id);
      assert.ok(["confirmed", "likely", "review"].includes(x.confidence), x.id);
      assert.ok(Array.isArray(x.controls) && x.controls.length > 0, x.id);
      for (const c of x.controls) assert.ok(/^(CIS Controls v8|CIS Microsoft Windows Server Benchmark|PCI DSS 4\.0|NIST SP 800-(53|52 Rev\. 2|131A Rev\. 2)|IETF RFC|CISA BOD|MITRE ATT&CK( for ICS)?)$/.test(c.framework) && c.id, x.id + ": " + JSON.stringify(c));
      assert.ok(x.evidence.length <= 50 && x.evidenceCount >= x.evidence.length, x.id);
    }
    const sorted = r.findings.map((x) => SEV_RANK[x.severity]);
    assert.deepEqual(sorted, sorted.slice().sort((a, b) => b - a), "sorted by severity");
  });
  test("findings CSV header and row count", () => {
    const csv = findingsToCsv(r.findings).split(/\r?\n/).filter(Boolean);
    assert.equal(csv[0], "severity,confidence,category,title,description,recommendation,controls,assets,evidenceCount");
    assert.equal(csv.length, r.findings.length + 1);
  });
  test("inventory and changes CSV use the documented columns", () => {
    assert.equal(inventoryToCsv(r).split(/\r?\n/)[0], INVENTORY_COLS.join(","));
    assert.equal(changesToCsv(r).split(/\r?\n/)[0], CHANGE_COLS.join(","));
    assert.equal(changesToCsv(r).split(/\r?\n/).filter(Boolean).length, r.tables.changes.length + 1);
  });
  test("firewall ticket lists risky, non-allow-listed exposures, external first", () => {
    const t = firewallTicketText(r);
    assert.ok(/^Firewall change requests/.test(t));
    assert.ok(t.indexOf("203.0.113.5") < t.indexOf("10.20.0.60"));
    assert.ok(!/10\.20\.0\.10 .*TCP\/3389/.test(t), "allow-listed RDP on the DC is not ticketed");
    assert.ok(/Network Scan Diff/.test(summaryText(r)));
  });
  test("example uses documentation / RFC 1918 addresses and test.darknode.ai names only", () => {
    const all = ex.files.map((x) => x.text).join("\n");
    const addrs = all.match(/(?<![\w.:/-])\d{1,3}(?:\.\d{1,3}){3}(?![\w.-])/g) || [];
    assert.ok(addrs.length > 10);
    for (const ip of addrs) assert.ok(/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|203\.0\.113\.|198\.51\.100\.|192\.0\.2\.|0\.0\.0\.0$|255\.)/.test(ip), ip);
    for (const host of all.match(/(?<![@/\w.-])[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:ai|com|net|org|local)\b/g) || []) assert.ok(/test\.darknode\.ai$/.test(host), host);
  });
  test("deterministic, and no input fields leak into a second run", () => {
    assert.deepEqual(analyze(ex.files, opts), analyze(ex.files, opts));
    assert.deepEqual(analyze(ex.files.slice().reverse(), opts).findings, r.findings, "file order does not matter");
  });
  test("progress callback and empty input", () => {
    let calls = 0;
    analyze(ex.files, opts, { progress: () => { calls++; } });
    assert.ok(calls >= 3);
    const e = analyze([]);
    assert.equal(e.findings.length, 0); assert.equal(e.summary.hosts, 0);
    assert.ok(e.skipped.some((s) => s.check === "all"));
    assert.equal(parseInput("").rows.length, 0);
  });
  test("defaults ship empty settings and the in-engine self-test passes", () => {
    assert.equal(DEFAULTS.internalCidrs, ""); assert.equal(DEFAULTS.allowList, "");
    const st = selfTest();
    assert.ok(st.pass, st.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
});
