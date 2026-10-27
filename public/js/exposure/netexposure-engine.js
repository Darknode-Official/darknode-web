// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Network Scan Diff (netexposure), pure engine. Turns the organisation's own network scan output
// (nmap -oX / -oG, masscan -oJ / -oX, naabu JSON lines, Nessus .nessus v2, Shodan NDJSON / host
// JSON, or a mapped port-list CSV) into an exposure inventory, flags risky exposed services,
// end-of-life software (against the mirrored endoflife.date feed passed in as opts.eol), weak
// certificates / TLS / SSH / SMB settings read from NSE script output, and diffs scan to scan so
// new exposure is caught the day it appears. Optional: a Firewall Rule Audit JSON export is used
// for a conservative "documented as blocked but observed open" check.
//
// Pure: no DOM, no network, no clock (opts.now or the newest scan time is the reference date).
// Deterministic: the same input produces byte-identical JSON. Runs in a Worker and in node tests.

import { iterCsv, findColumn, xmlLite } from "../ingest/parse.js";
import { isIp, ipToInt, parseCidr, compileCidrs, isInternalIp } from "../ops/log-hunter-engine.js";

export const TOOL_ID = "netexposure";
export const VERSION = "1.0.0";

export const FORMATS = {
  "nmap-xml": "nmap XML (-oX)",
  "nmap-grep": "nmap grepable (-oG)",
  "masscan-json": "masscan JSON (-oJ)",
  "masscan-xml": "masscan XML (-oX)",
  "naabu-jsonl": "naabu JSON lines",
  nessus: "Nessus .nessus v2",
  "shodan-ndjson": "Shodan export (NDJSON)",
  "shodan-host": "Shodan host JSON",
  fwaudit: "Firewall Rule Audit export (JSON)",
  csv: "Port list CSV (mapped columns)",
  unknown: "Not recognised",
};

/** Column aliases for a generic port-list CSV (any tool that writes one row per host and port). */
export const COLUMNS = {
  ip: ["ip", "ip address", "ipaddress", "address", "host ip", "addr", "ip_str", "target"],
  port: ["port", "portid", "port number", "dport", "dst port"],
  proto: ["protocol", "proto", "transport"],
  state: ["state", "status", "port state"],
  service: ["service", "service name", "svc_name", "svc", "name"],
  product: ["product", "software", "application"],
  version: ["version", "product version"],
  hostname: ["hostname", "host", "fqdn", "dns name", "dns"],
  timestamp: ["timestamp", "time", "date", "scan time", "last seen"],
};

/** Settings; the UI renders these with real labels. */
export const DEFAULTS = {
  internalCidrs: "", // blank = DEFAULT_INTERNAL
  allowList: "", // one per line: host[:port[/proto]] reason
  certWarnDays: 30, // certificate expiring within this many days
  eolWarnDays: 90, // end of life within this many days is reported as approaching
  minRsaBits: 2048, // RSA / DSA keys below this are weak
  reportInternal: true, // report risky services seen only on internal addresses
  now: "", // reference date (ISO); blank = newest scan time
};

/** RFC 1918 + RFC 4193 + loopback + link-local. */
export const DEFAULT_INTERNAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "::1/128", "fe80::/10"];

export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEV_WEIGHT = { critical: 40, high: 20, medium: 8, low: 3, info: 0 }; // host risk score, capped at 100
const DAY = 86400000;
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const uniq = (arr) => [...new Set((arr || []).filter((x) => x !== "" && x != null))].sort(cmp);
const down1 = (s) => ({ critical: "high", high: "medium", medium: "low", low: "info", info: "info" })[s];
const clip = (s, n = 4000) => { const t = String(s == null ? "" : s); return t.length > n ? t.slice(0, n) + " [truncated]" : t; };
const isoOf = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString().replace(/\.000Z$/, "Z") : "");
const dayOf = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 10) : "");

/** Compare two IP strings numerically (v4 before v6); falls back to string order. */
export function ipCmp(a, b) {
  const x = ipToInt(a), y = ipToInt(b);
  if (!x || !y) return cmp(String(a), String(b));
  if (x.v !== y.v) return x.v - y.v;
  return x.n < y.n ? -1 : x.n > y.n ? 1 : 0;
}

// ---------------------------------------------------------------------------
// Standards (cited only where the mapping is certain)
// ---------------------------------------------------------------------------
const C = (framework, id) => ({ framework, id });
const CTL = {
  cis11: C("CIS Controls v8", "1.1"), cis22: C("CIS Controls v8", "2.2"), cis310: C("CIS Controls v8", "3.10"),
  cis44: C("CIS Controls v8", "4.4"), cis46: C("CIS Controls v8", "4.6"), cis48: C("CIS Controls v8", "4.8"),
  cis122: C("CIS Controls v8", "12.2"), cis134: C("CIS Controls v8", "13.4"),
  pci125: C("PCI DSS 4.0", "1.2.5"), pci126: C("PCI DSS 4.0", "1.2.6"), pci141: C("PCI DSS 4.0", "1.4.1"), pci142: C("PCI DSS 4.0", "1.4.2"),
  pci224: C("PCI DSS 4.0", "2.2.4"), pci225: C("PCI DSS 4.0", "2.2.5"), pci227: C("PCI DSS 4.0", "2.2.7"), pci421: C("PCI DSS 4.0", "4.2.1"),
  pci633: C("PCI DSS 4.0", "6.3.3"), pci1131: C("PCI DSS 4.0", "11.3.1"), pci1132: C("PCI DSS 4.0", "11.3.2"),
  cm6: C("NIST SP 800-53", "CM-6"), cm7: C("NIST SP 800-53", "CM-7"), cm8: C("NIST SP 800-53", "CM-8"), sc7: C("NIST SP 800-53", "SC-7"),
  sc8: C("NIST SP 800-53", "SC-8"), sc13: C("NIST SP 800-53", "SC-13"), sc17: C("NIST SP 800-53", "SC-17"), sa22: C("NIST SP 800-53", "SA-22"),
  si2: C("NIST SP 800-53", "SI-2"), ac17: C("NIST SP 800-53", "AC-17"),
  rfc8996: C("IETF RFC", "8996 (TLS 1.0 and 1.1 deprecated)"), rfc7568: C("IETF RFC", "7568 (SSLv3 deprecated)"),
  rfc9142: C("IETF RFC", "9142 (SSH key exchange recommendations)"), rfc8758: C("IETF RFC", "8758 (RC4 deprecated in SSH)"),
  rfc6125: C("IETF RFC", "6125 (service identity in certificates)"), sp80052: C("NIST SP 800-52 Rev. 2", "3.1 (protocol versions)"),
  sp800131: C("NIST SP 800-131A Rev. 2", "key lengths and SHA-1 signatures"),
  bod2302: C("CISA BOD", "23-02 (internet-exposed management interfaces)"),
  winSign: C("CIS Microsoft Windows Server Benchmark", "Microsoft network server: Digitally sign communications (always)"),
  winSmb1: C("CIS Microsoft Windows Server Benchmark", "Configure SMB v1 server: Disabled"),
};
const att = (id) => C("MITRE ATT&CK", id);
const ics = (id) => C("MITRE ATT&CK for ICS", id);
const EXPO = [CTL.cis44, CTL.cis134, CTL.pci141, CTL.pci142, CTL.cm7, CTL.sc7];
const CLEAR = [CTL.cis310, CTL.pci227, CTL.sc8];

// ---------------------------------------------------------------------------
// Risk rule table. Each rule: ports + protocol, nmap service names (svc), optional product / title
// patterns, or a script finding key. ext = severity when the address is external (not in the
// internal CIDRs, or the scan is marked "scanned from outside"); int = severity on an internal
// segment (null = inventory only, no finding). A rule matches an open port when
//   - the service name matches svc (on any port), or
//   - the port is in ports and the service is unknown / tcpwrapped / a guess, or
//   - the product or HTTP title matches product / title, or
//   - the scan produced the named script finding.
// ---------------------------------------------------------------------------
function R(id, label, proto, ports, svc, ext, int, why, fix, controls, extra) {
  return { id, label, proto, ports, svc: svc ? new RegExp(svc, "i") : null, ext, int, why, fix, controls, ...(extra || {}) };
}
const ICS_FIX = "Remove the device from any internet-reachable path; place it behind an industrial DMZ and allow only named engineering stations through a firewall that understands the protocol.";
const DB_FIX = "Bind the database to private interfaces, allow only the application servers through the firewall, and require authentication with per-application accounts.";
export const RULES = [
  R("rdp", "RDP", "tcp", [3389], "^(ms-wbt-server|rdp)$", "critical", "low", "Remote Desktop is a leading initial-access vector: password spraying, credential stuffing and pre-auth bugs such as BlueKeep (CVE-2019-0708).", "Do not expose RDP directly. Put it behind a VPN or an RD Gateway with MFA, enforce Network Level Authentication, and restrict the source addresses.", [...EXPO, CTL.ac17, att("T1133"), att("T1021.001")]),
  R("smb", "SMB", "tcp", [445], "^(microsoft-ds|smb|cifs)$", "critical", null, "SMB reachable from outside exposes file shares, NTLM authentication and wormable bugs such as EternalBlue (MS17-010).", "Block TCP 445 at the perimeter. Inside, allow SMB only between clients and the file servers and domain controllers that need it.", [...EXPO, att("T1021.002"), att("T1210")]),
  R("netbios-ssn", "NetBIOS session", "tcp", [139], "^netbios-ssn$", "high", null, "NetBIOS session service carries legacy SMB and leaks host and domain names.", "Block TCP 139 at the perimeter and disable NetBIOS over TCP/IP where it is not needed.", [...EXPO, att("T1021.002")]),
  R("netbios-ns", "NetBIOS name / datagram", "udp", [137, 138], "^netbios-(ns|dgm)$", "high", null, "NetBIOS name service answers leak host, domain and logged-on user names and enable spoofing.", "Block UDP 137-138 at the perimeter; disable NetBIOS over TCP/IP.", [...EXPO, att("T1557.001")]),
  R("telnet", "Telnet", "tcp", [23], "^telnet$", "critical", "high", "Telnet sends credentials and sessions in clear text and is a favourite of IoT botnets.", "Disable Telnet and use SSH. If a device only speaks Telnet, isolate it on a management VLAN reachable from a jump host.", [...EXPO, ...CLEAR, CTL.pci225, att("T1040"), att("T1110")]),
  R("ftp", "FTP", "tcp", [21], "^ftp$", "medium", "low", "FTP sends credentials and data in clear text.", "Replace with SFTP or FTPS; if FTP must stay, restrict the source addresses.", [...EXPO, ...CLEAR, CTL.pci225, att("T1040")], { supersededBy: "ftp-anon" }),
  R("ftp-anon", "Anonymous FTP", "tcp", [], null, "high", "medium", "The server accepts anonymous logins (nmap ftp-anon), so anyone can list and possibly write files.", "Disable anonymous login, or confine it to a read-only directory with no sensitive content.", [...EXPO, CTL.cm6, att("T1078")], { script: "ftp-anon" }),
  R("tftp", "TFTP", "udp", [69], "^tftp$", "high", "medium", "TFTP has no authentication; exposed TFTP servers leak device configurations and boot images.", "Restrict TFTP to the provisioning network and the devices that need it.", [...EXPO, ...CLEAR]),
  R("vnc", "VNC", "tcp", [5900, 5901, 5902, 5903], "^vnc", "critical", "medium", "VNC often runs with weak or no passwords and gives full desktop control.", "Remove internet exposure; tunnel VNC through SSH or a VPN and require strong authentication.", [...EXPO, CTL.ac17, att("T1021.005"), att("T1133")]),
  R("x11", "X11", "tcp", [6000], "^x11$", "high", "medium", "An open X server lets anyone capture the screen and keystrokes.", "Disable TCP listening for X (-nolisten tcp) and use SSH X forwarding.", [...EXPO]),
  R("snmp", "SNMP", "udp", [161], "^snmp$", "high", "low", "SNMP v1/v2c uses clear-text community strings and leaks configuration, routes and interfaces.", "Use SNMPv3 with authentication and privacy; restrict SNMP to the monitoring hosts.", [...EXPO, ...CLEAR], { supersededBy: "snmp-community" }),
  R("snmp-community", "SNMP answering a community string", "udp", [], null, "critical", "medium", "The agent answered nmap's SNMP queries (nmap uses the community 'public' unless snmpcommunity was set), so its data is readable with a guessable community.", "Change or remove default communities, move to SNMPv3, and restrict SNMP to the monitoring hosts.", [...EXPO, CTL.cm6, CTL.pci224], { script: "snmp-community" }),
  R("ipmi", "IPMI", "udp", [623], "^(asf-rmcp|ipmi)", "critical", "medium", "IPMI 2.0 leaks password hashes (RAKP) and controls the server hardware.", "Put BMC interfaces on an isolated management network; never route IPMI to the internet.", [...EXPO, CTL.bod2302]),
  R("rservices", "rsh / rlogin / rexec", "tcp", [512, 513, 514], "^(exec|login|shell|rexec|rlogin|rsh)$", "critical", "high", "The Berkeley r-services trust host addresses and send credentials in clear text.", "Disable the r-services and use SSH.", [...EXPO, ...CLEAR, CTL.pci225]),
  R("ldap", "LDAP / Global Catalog", "tcp", [389, 636, 3268, 3269], "^(ldap|ldapssl|globalcatldap|globalcatldapssl)$", "high", null, "Directory services exposed to the internet invite password spraying and leak directory data.", "Do not expose LDAP to the internet; publish identity through a federation service instead.", [...EXPO, att("T1133")]),
  R("ldap-anon", "LDAP anonymous query", "tcp", [], null, "high", "medium", "nmap ldap-search returned directory entries without credentials.", "Disable anonymous binds beyond the rootDSE and require authenticated, signed LDAP.", [...EXPO, CTL.cm6], { script: "ldap-anon" }),
  R("mssql", "Microsoft SQL Server", "tcp", [1433], "^ms-sql-s$", "high", null, "Database listeners on the internet are brute-forced and exploited directly.", DB_FIX, [...EXPO, att("T1190")]),
  R("mssql-browser", "SQL Server Browser", "udp", [1434], "^ms-sql-m$", "medium", null, "The SQL Browser service enumerates instances and has been used for amplification.", "Block UDP 1434 at the perimeter; disable the Browser service if instances use fixed ports.", [...EXPO]),
  R("mysql", "MySQL / MariaDB", "tcp", [3306], "^mysql$", "high", null, "Database listeners on the internet are brute-forced and exploited directly.", DB_FIX, [...EXPO, att("T1190")]),
  R("postgresql", "PostgreSQL", "tcp", [5432], "^postgresql$", "high", null, "Database listeners on the internet are brute-forced and exploited directly.", DB_FIX, [...EXPO, att("T1190")]),
  R("oracle", "Oracle TNS listener", "tcp", [1521], "^oracle(-tns)?$", "high", null, "Database listeners on the internet are brute-forced and exploited directly.", DB_FIX, [...EXPO, att("T1190")]),
  R("mongodb", "MongoDB", "tcp", [27017, 27018, 27019], "^mongod(b)?$", "critical", "medium", "MongoDB instances without authentication are wiped and ransomed at scale.", DB_FIX + " Enable access control (security.authorization).", [...EXPO, att("T1190")], { product: /mongodb/i }),
  R("redis", "Redis", "tcp", [6379], "^redis$", "critical", "medium", "Redis has no authentication by default; an exposed instance can be abused to write files and run code.", "Bind Redis to localhost or a private interface, enable protected-mode and ACLs/requirepass, and firewall the port.", [...EXPO, att("T1190")], { product: /redis/i }),
  R("memcached", "Memcached", "any", [11211], "^memcache(d)?$", "critical", "low", "Memcached has no authentication and UDP memcached was used for record DDoS amplification.", "Disable UDP (-U 0), bind to private interfaces and firewall the port.", [...EXPO, att("T1498.002")]),
  R("elasticsearch", "Elasticsearch", "tcp", [9200, 9300], "^(elasticsearch|wap-wsp|vrace)$", "critical", "medium", "Exposed Elasticsearch clusters are a leading source of mass data leaks.", "Enable security (TLS + authentication), bind to private interfaces and firewall 9200/9300.", [...EXPO, att("T1190")], { product: /elasticsearch/i }),
  R("couchdb", "CouchDB", "tcp", [5984], "^couchdb$", "high", "low", "CouchDB admin party / unauthenticated APIs leak or allow modification of data.", DB_FIX, [...EXPO, att("T1190")], { product: /couchdb/i }),
  R("cassandra", "Cassandra", "tcp", [9042, 9160], "^cassandra$", "high", "low", "Cassandra ships with authentication disabled by default.", DB_FIX + " Enable PasswordAuthenticator.", [...EXPO, att("T1190")]),
  R("kibana", "Kibana", "tcp", [5601], "^(kibana|esmagent)$", "high", "low", "Kibana exposes the data in Elasticsearch and has had remote code execution bugs.", "Put Kibana behind SSO and a reverse proxy; do not expose it directly.", [...EXPO, att("T1190")], { product: /kibana/i, title: /kibana/i }),
  R("docker", "Docker Engine API (no TLS)", "tcp", [2375], "^docker$", "critical", "high", "The unauthenticated Docker API is equivalent to root on the host and is mass-exploited for cryptomining.", "Never expose 2375. Use the local socket, or TLS client certificates on 2376 restricted to admin hosts.", [...EXPO, att("T1610"), att("T1190")], { product: /docker/i }),
  R("docker-tls", "Docker Engine API (TLS)", "tcp", [2376], "^(docker-s|docker)$", "high", "low", "The Docker API should be reachable only from administration hosts even with TLS.", "Restrict 2376 to administration hosts and verify client-certificate authentication is enforced.", [...EXPO, att("T1610")]),
  R("k8s-api", "Kubernetes API server", "tcp", [6443], "^(sun-sr-https|kubernetes)$", "medium", null, "An internet-reachable API server is exposed to credential and RBAC attacks.", "Restrict the API server to authorised networks or a private endpoint; disable anonymous auth.", [...EXPO, att("T1609")]),
  R("kubelet", "Kubelet API", "tcp", [10250], null, "critical", "medium", "An exposed kubelet with anonymous auth allows running commands in any pod on the node.", "Firewall 10250 to the control plane only; set --anonymous-auth=false and authorization-mode=Webhook.", [...EXPO, att("T1609")]),
  R("kubelet-ro", "Kubelet read-only API", "tcp", [10255], null, "high", "medium", "The read-only kubelet port leaks pod specs, environment and secrets references without authentication.", "Disable the read-only port (--read-only-port=0).", [...EXPO]),
  R("etcd", "etcd", "tcp", [2379, 2380], "^etcd", "critical", "high", "etcd holds every Kubernetes secret; an exposed etcd is a full cluster compromise.", "Restrict etcd to the control plane and require mutual TLS.", [...EXPO, att("T1552")]),
  R("jenkins", "Jenkins", "tcp", [], null, "high", "low", "Jenkins runs code by design; exposed instances are hit with credential and plugin exploits (several in CISA KEV).", "Put Jenkins behind SSO / VPN, disable anonymous read and keep it patched.", [...EXPO, att("T1190")], { title: /\[jenkins\]|jenkins/i, product: /jenkins/i }),
  R("grafana", "Grafana", "tcp", [], null, "medium", null, "Exposed Grafana invites login attacks and has had path-traversal bugs (CVE-2021-43798, in CISA KEV).", "Put Grafana behind SSO or a VPN and keep it patched.", [...EXPO, att("T1190")], { title: /grafana/i, product: /grafana/i }),
  R("prometheus", "Prometheus", "tcp", [], null, "high", "low", "Prometheus has no authentication by default and leaks internal hostnames, versions and metrics.", "Restrict Prometheus to the monitoring network or front it with authentication.", [...EXPO], { title: /prometheus/i, product: /prometheus/i }),
  R("rabbitmq-mgmt", "RabbitMQ management", "tcp", [15672], null, "high", "low", "The RabbitMQ management UI is often left with default guest credentials.", "Restrict the management port and remove default accounts.", [...EXPO], { title: /rabbitmq/i, product: /rabbitmq/i }),
  R("amqp", "AMQP broker", "tcp", [5672], "^amqp$", "medium", null, "Message brokers on the internet are exposed to credential attacks and data leaks.", "Restrict the broker to application networks and require TLS.", [...EXPO]),
  R("zookeeper", "ZooKeeper", "tcp", [2181], "^(zookeeper|eforward)$", "high", "low", "ZooKeeper allows unauthenticated reads of cluster configuration by default.", "Firewall ZooKeeper to cluster members and enable SASL authentication.", [...EXPO]),
  R("kafka", "Kafka", "tcp", [9092], "^(kafka|xmlipcregsvc)$", "high", "low", "Kafka listeners without SASL/TLS let anyone produce or consume messages.", "Restrict Kafka to application networks and enable SASL + TLS listeners.", [...EXPO]),
  R("hadoop", "Hadoop NameNode / YARN", "tcp", [50070, 9870], null, "critical", "medium", "Unauthenticated YARN ResourceManager APIs are mass-exploited to run code; NameNode UIs expose the file system.", "Restrict Hadoop web UIs and REST APIs to the cluster network and enable Kerberos.", [...EXPO, att("T1190")], { title: /hadoop|namenode|all applications/i }),
  R("smtp-relay", "SMTP open relay", "tcp", [], null, "critical", "medium", "nmap smtp-open-relay delivered test messages for unauthenticated senders to outside recipients; spammers will abuse it.", "Restrict relaying to authenticated users and internal networks.", [...EXPO, CTL.cm6], { script: "smtp-open-relay" }),
  R("dns-open-resolver", "Open DNS resolver", "udp", [], null, "high", null, "The server answers recursive queries for anyone (nmap dns-recursion) and can be used for amplification attacks.", "Allow recursion only for your own networks.", [...EXPO, CTL.cm6, att("T1498.002")], { script: "dns-recursion" }),
  R("ntp-monlist", "NTP monlist", "udp", [], null, "high", "low", "NTP monlist answers (nmap ntp-monlist) amplify traffic about 200x and leak client addresses.", "Upgrade ntpd and disable monlist (disable monitor / restrict noquery).", [...EXPO, CTL.cm6, att("T1498.002")], { script: "ntp-monlist" }),
  R("ssdp", "SSDP / UPnP", "udp", [1900], "^(upnp|ssdp)$", "high", null, "SSDP is abused for reflection DDoS and exposes UPnP device control.", "Block UDP 1900 at the perimeter and disable UPnP on edge devices.", [...EXPO, att("T1498.002")]),
  R("mqtt", "MQTT", "tcp", [1883], "^mqtt$", "high", "low", "Plain MQTT brokers often allow anonymous publish/subscribe to device topics.", "Require authentication and TLS (8883); restrict the broker to device networks.", [...EXPO, ...CLEAR]),
  R("mqtt-tls", "MQTT over TLS", "tcp", [8883], "^(secure-mqtt|mqtts)$", "medium", null, "Internet-reachable brokers need strong authentication and topic ACLs.", "Restrict the source addresses and require client authentication.", [...EXPO]),
  R("modbus", "Modbus/TCP", "tcp", [502], "^(modbus|mbap)$", "critical", "medium", "Modbus has no authentication; anyone who reaches it can read and write process values.", ICS_FIX, [...EXPO, ics("T0883"), ics("T0886")]),
  R("s7", "Siemens S7 (ISO-TSAP)", "tcp", [102], "^iso-tsap$", "critical", "medium", "S7comm lets anyone who reaches the PLC read and change its program and state.", ICS_FIX, [...EXPO, ics("T0883"), ics("T0886")]),
  R("bacnet", "BACnet", "udp", [47808], "^bacnet$", "critical", "medium", "BACnet controls building systems without authentication.", ICS_FIX, [...EXPO, ics("T0883")]),
  R("dnp3", "DNP3", "tcp", [20000], "^(dnp|dnp3)$", "critical", "medium", "DNP3 outstations exposed to the internet can be commanded without authentication (unless Secure Authentication is used).", ICS_FIX, [...EXPO, ics("T0883"), ics("T0886")]),
  R("enip", "EtherNet/IP", "tcp", [44818], "^(ethernetip-2|enip)$", "critical", "medium", "EtherNet/IP (CIP) devices exposed to the internet can be enumerated and commanded.", ICS_FIX, [...EXPO, ics("T0883")]),
  R("vpn-portal", "VPN / remote-access portal", "tcp", [], null, "info", "info", "Remote-access gateways (Citrix NetScaler, Fortinet, Pulse/Ivanti, GlobalProtect) are among the most exploited products in CISA KEV; this host belongs on the patch-watch list.", "Track vendor advisories for this product and patch within days; confirm MFA and that the management interface is not exposed.", [CTL.cis11, CTL.cm8, CTL.si2, att("T1133")], { title: /citrix gateway|netscaler|fortigate|fortinet|fortios|sslvpn|pulse connect secure|ivanti connect secure|globalprotect/i, product: /fortigate|fortinet|netscaler|citrix|pulse secure|ivanti|globalprotect|pan-os/i }),
  R("bmc", "Server management controller (iLO / iDRAC)", "tcp", [], null, "critical", "low", "Out-of-band controllers give hardware-level control of the server and have had critical authentication bypasses.", "Move BMCs to an isolated management network reachable only from a jump host.", [...EXPO, CTL.bod2302], { title: /\bilo\b|integrated lights-out|idrac/i, product: /\bilo\b|idrac/i }),
  R("vmware-mgmt", "VMware vCenter / ESXi management", "tcp", [], null, "critical", "low", "vCenter and ESXi management interfaces are prime ransomware targets with several KEV-listed bugs.", "Restrict vCenter/ESXi management to an admin network; never expose it to the internet.", [...EXPO, CTL.bod2302, att("T1190")], { title: /vsphere|vcenter|vmware esxi|id_vc_welcome/i, product: /vmware (esxi|vcenter|authentication daemon)/i }),
  R("rpc-nfs", "RPCbind / NFS", "tcp", [111, 2049], "^(rpcbind|nfs)$", "high", null, "RPCbind and NFS expose file systems and have been used for amplification.", "Block 111 and 2049 at the perimeter; export NFS only to named clients.", [...EXPO]),
  R("winrm", "WinRM", "tcp", [5985, 5986], "^(wsman|wsmans)$", "high", null, "WinRM gives remote PowerShell; exposed endpoints are brute-forced.", "Restrict WinRM to administration hosts.", [...EXPO, CTL.ac17, att("T1021.006")]),
  R("ssh", "SSH", "tcp", [22], "^ssh$", "low", null, "Internet-facing SSH is constantly brute-forced; exposure is acceptable only with keys-only authentication and a reason.", "Restrict the source addresses or require a VPN / bastion; disable password authentication.", [...EXPO, CTL.ac17, att("T1021.004"), att("T1133")]),
  R("msrpc", "Microsoft RPC endpoint mapper", "tcp", [135], "^msrpc$", "high", null, "RPC exposed to the internet enables enumeration and has had wormable bugs.", "Block TCP 135 and the dynamic RPC range at the perimeter.", [...EXPO, att("T1210")]),
  R("rsync", "rsync daemon", "tcp", [873], "^rsync$", "high", "low", "rsync modules are frequently readable without authentication.", "Require authentication on every module and restrict the source addresses.", [...EXPO]),
  R("jetdirect", "Printer raw port (JetDirect)", "tcp", [9100], "^jetdirect$", "medium", null, "Raw printer ports accept print jobs and PJL commands from anyone who can reach them.", "Block 9100 at the perimeter.", [...EXPO]),
  R("solr", "Apache Solr admin", "tcp", [8983], null, "high", "low", "Solr admin APIs have had remote code execution bugs and expose indexed data.", "Restrict Solr to application servers and enable authentication.", [...EXPO, att("T1190")], { title: /solr admin/i, product: /solr/i }),
  R("webmin", "Webmin", "tcp", [10000], null, "high", "low", "Webmin is a root-level web administration panel with a history of pre-auth bugs.", "Restrict Webmin to administration hosts or remove it.", [...EXPO, CTL.bod2302], { title: /webmin/i, product: /miniserv|webmin/i }),
  R("smart-install", "Cisco Smart Install", "tcp", [4786], "^smart-install$", "critical", "medium", "Smart Install lets anyone who reaches it read and replace switch configurations (CISA alert TA18-106A).", "Disable Smart Install (no vstack) and block TCP 4786.", [...EXPO, att("T1190")]),
  R("pptp", "PPTP VPN", "tcp", [1723], "^pptp$", "medium", null, "PPTP relies on MS-CHAPv2, which is broken.", "Replace PPTP with IKEv2/IPsec or a TLS VPN.", [...EXPO, CTL.sc13]),
  R("influxdb", "InfluxDB", "tcp", [8086], null, "high", "low", "InfluxDB 1.x ships with authentication disabled.", DB_FIX, [...EXPO], { product: /influxdb/i, title: /influxdb/i }),
  R("consul", "Consul", "tcp", [8500], null, "high", "low", "An open Consul agent API allows registering services that run scripts.", "Enable ACLs and restrict the HTTP API.", [...EXPO], { product: /consul/i, title: /consul/i }),
];
const RULE_BY_ID = Object.fromEntries(RULES.map((r) => [r.id, r]));
const GENERIC_SVC = /^(|unknown|tcpwrapped)$/;

// ---------------------------------------------------------------------------
// Small parsing helpers
// ---------------------------------------------------------------------------
function attrs(s) {
  const o = {};
  const re = /([A-Za-z_][\w:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  let m;
  while ((m = re.exec(s))) o[m[1]] = decodeEnt(m[2] !== undefined ? m[2] : m[3]);
  return o;
}
function decodeEnt(s) {
  return String(s).replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (m, e) => {
    const k = e.toLowerCase();
    if (k === "amp") return "&"; if (k === "lt") return "<"; if (k === "gt") return ">"; if (k === "quot") return '"'; if (k === "apos") return "'";
    const cp = k[1] === "x" ? parseInt(k.slice(2), 16) : parseInt(k.slice(1), 10);
    return Number.isFinite(cp) ? String.fromCodePoint(cp) : "";
  });
}
function* lines(text) {
  const s = String(text || "");
  let i = 0;
  while (i < s.length) {
    let j = s.indexOf("\n", i);
    if (j < 0) j = s.length;
    yield s.slice(i, j).replace(/\r$/, "");
    i = j + 1;
  }
}
const kids = (n, tag) => (n && n.children ? n.children.filter((c) => c.tag === tag) : []);
const kid = (n, tag) => (n && n.children ? n.children.find((c) => c.tag === tag) || null : null);

/** Parse a port list ("1,3-4,22", "-", "T:22,U:53") into { tcp, udp } ranges ([lo,hi] arrays) or null. */
export function parsePortSpec(spec, defaultProto = "tcp") {
  const out = { tcp: [], udp: [] };
  let s = String(spec || "").trim();
  if (!s) return null;
  if (s === "-") { out[defaultProto] = [[1, 65535]]; return out; }
  let cur = defaultProto;
  for (let tok of s.split(",")) {
    tok = tok.trim();
    const m = tok.match(/^([TUS]):(.*)$/i);
    if (m) { cur = m[1].toUpperCase() === "U" ? "udp" : m[1].toUpperCase() === "T" ? "tcp" : "sctp"; tok = m[2]; }
    if (!tok || cur === "sctp") continue;
    const r = tok.match(/^(\d*)-(\d*)$/);
    if (r) { const lo = r[1] ? Number(r[1]) : 1, hi = r[2] ? Number(r[2]) : 65535; if (lo <= hi && hi <= 65535) out[cur].push([lo, hi]); continue; }
    if (/^\d+$/.test(tok)) { const p = Number(tok); if (p <= 65535) out[cur].push([p, p]); continue; }
    return null; // named ports or anything unexpected: coverage unknown
  }
  return out;
}
const portCount = (ranges) => (ranges ? ranges.reduce((n, r) => n + (r[1] - r[0] + 1), 0) : null);
const inRanges = (ranges, p) => ranges.some((r) => p >= r[0] && p <= r[1]);

// nmap target specs: CIDR, single address, IPv4 octet ranges (10.0.0-2.1-50, 10.0.0.*), names.
function parseTargetTok(tok) {
  const t = String(tok || "").trim();
  if (!t) return null;
  if (/^[\d.]+\/\d+$/.test(t) || (t.includes(":") && /^[0-9a-f:.]+(\/\d+)?$/i.test(t))) { const c = parseCidr(t); return c ? { kind: "cidr", c } : { kind: "name", name: t }; }
  if (/^[\d*,\-]+\.[\d*,\-]+\.[\d*,\-]+\.[\d*,\-]+$/.test(t)) {
    const sets = t.split(".").map((o) => o.split(",").map((part) => (part === "*" ? [0, 255] : part.includes("-") ? part.split("-").map((x, i) => (x === "" ? (i ? 255 : 0) : Number(x))) : [Number(part), Number(part)])));
    if (sets.every((s) => s.every((r) => r[0] <= r[1] && r[1] <= 255))) return { kind: "octets", sets };
  }
  return { kind: "name", name: t.toLowerCase() };
}
function targetHas(tgt, ip) {
  if (tgt.kind === "cidr") { const p = ipToInt(ip); return !!p && p.v === tgt.c.v && (p.n & tgt.c.mask) === tgt.c.net; }
  if (tgt.kind === "octets") { const o = String(ip).split("."); return o.length === 4 && o.every((x, i) => tgt.sets[i].some((r) => Number(x) >= r[0] && Number(x) <= r[1])); }
  return false;
}
function makeTargets(tokens, excludes) {
  const list = (tokens || []).map(parseTargetTok).filter(Boolean);
  if (!list.length) return null;
  return { list, excludes: (excludes || []).map(parseTargetTok).filter(Boolean), names: list.filter((t) => t.kind === "name").map((t) => t.name), text: tokens.join(" ") };
}
function targetsHave(targets, ip) {
  if (!targets) return null;
  if (targets.excludes.some((t) => targetHas(t, ip))) return false;
  return targets.list.some((t) => targetHas(t, ip));
}

const NMAP_VAL_OPTS = new Set(["-p", "-oX", "-oN", "-oG", "-oA", "-oS", "-oM", "-iL", "-iR", "--exclude", "--excludefile", "--script", "--script-args", "--script-args-file", "-e", "-S", "-D", "--top-ports", "--port-ratio", "--max-retries", "--host-timeout", "--min-rate", "--max-rate", "--source-port", "-g", "--data-length", "--data", "--data-string", "--ttl", "--dns-servers", "--version-intensity", "--stylesheet", "--scan-delay", "--max-scan-delay", "--min-hostgroup", "--max-hostgroup", "--min-parallelism", "--max-parallelism", "--initial-rtt-timeout", "--max-rtt-timeout", "--min-rtt-timeout", "--mtu", "--proxies", "--datadir", "--servicedb", "--versiondb", "--resume", "--exclude-ports", "--spoof-mac", "-b", "--max-os-tries", "--script-timeout", "-sI", "--ip-options", "--stats-every"]);
/** Read targets and the scanned-port list from an nmap command line. Unknown parts stay null. */
export function parseNmapArgs(args) {
  const toks = String(args || "").trim().split(/\s+/).filter(Boolean);
  if (toks.length && /(^|[\\/])nmap(\.exe)?$/i.test(toks[0])) toks.shift();
  let portSpec = null, top = false, inputList = false, udp = false, tcp = false, fast = false;
  const targets = [], excludes = [];
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (/^-p[^n]/.test(t) && t[1] === "p") { portSpec = t.slice(2); continue; }
    if (t.startsWith("--") && t.includes("=")) {
      const [k, v] = [t.slice(0, t.indexOf("=")), t.slice(t.indexOf("=") + 1)];
      if (k === "--top-ports") top = true; else if (k === "--exclude") excludes.push(...v.split(",")); else if (k === "--excludefile") inputList = true;
      continue;
    }
    if (NMAP_VAL_OPTS.has(t)) {
      const v = toks[++i] || "";
      if (t === "-p") portSpec = v; else if (t === "--top-ports") top = true; else if (t === "-iL" || t === "-iR" || t === "--excludefile") inputList = true; else if (t === "--exclude") excludes.push(...v.split(","));
      continue;
    }
    if (t.startsWith("-")) {
      if (/^-s[A-Z]*U/.test(t)) udp = true;
      if (/^-s[STAWMNFX]/.test(t) || t === "-sV") tcp = true;
      if (t === "-F") fast = true;
      continue;
    }
    targets.push(t);
  }
  if (!udp) tcp = true;
  let scanned = { tcp: null, udp: null };
  if (portSpec && !top && !fast) {
    const ps = parsePortSpec(portSpec, "tcp");
    if (ps) {
      const hasPrefix = /[TU]:/i.test(portSpec);
      scanned = { tcp: tcp ? ps.tcp : null, udp: udp ? (hasPrefix ? ps.udp : ps.tcp) : null };
      if (tcp && !scanned.tcp.length && !hasPrefix) scanned.tcp = null;
    }
  }
  return { targets: inputList ? null : makeTargets(targets, excludes), scanned, udp, tcp };
}

// --- product / banner helpers ---------------------------------------------------
/** "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7" -> { product: "OpenSSH", version: "7.4p1 Debian-10+deb9u7" }. */
export function parseSshBanner(b) {
  const m = String(b || "").match(/SSH-[\d.]+-([^\s_]+)(?:_(\S+))?(?:\s+(.*))?/);
  if (!m) return null;
  return { product: m[1], version: [m[2], m[3]].filter(Boolean).join(" ").trim(), protocol: (String(b).match(/SSH-([\d.]+)-/) || [])[1] || "" };
}
/** Server header -> [{ name, version }] plus the parenthesised comments. */
export function parseServerHeader(h) {
  const s = String(h || "").trim();
  const parts = [], comments = [];
  const re = /([A-Za-z][\w.+\-]*)(?:\/([\w.\-]+))?|\(([^)]*)\)/g;
  let m;
  while ((m = re.exec(s))) { if (m[3] != null) comments.push(m[3]); else parts.push({ name: m[1], version: m[2] || "" }); }
  return { parts, comments };
}
/** Split an nmap "version" column from -oG ("Apache httpd 2.4.41 ((Ubuntu))") into product / version / extrainfo. */
export function splitProductVersion(s) {
  const t = String(s || "").replace(/\|/g, "/").trim();
  if (!t) return { product: "", version: "", extrainfo: "" };
  const pi = t.indexOf(" (");
  const main = pi >= 0 ? t.slice(0, pi) : t;
  let extrainfo = pi >= 0 ? t.slice(pi + 1).trim() : "";
  if (extrainfo.startsWith("(") && extrainfo.endsWith(")")) extrainfo = extrainfo.slice(1, -1);
  const toks = main.split(/\s+/);
  const vi = toks.findIndex((x, i) => i > 0 && /^\d/.test(x));
  if (vi < 0) return { product: main, version: "", extrainfo };
  return { product: toks.slice(0, vi).join(" "), version: toks.slice(vi).join(" "), extrainfo };
}

// --- NSE script parsers (exported for tests) --------------------------------------
function tableObj(node) {
  const ch = (node.children || []).filter((c) => c.tag === "elem" || c.tag === "table");
  if (!ch.some((c) => c.attrs && c.attrs.key != null)) return ch.map((c) => (c.tag === "elem" ? c.text : tableObj(c)));
  const o = {};
  ch.forEach((c, i) => { o[c.attrs.key != null ? c.attrs.key : String(i)] = c.tag === "elem" ? c.text : tableObj(c); });
  return o;
}
const dnStr = (o) => (o && typeof o === "object" ? Object.keys(o).sort(cmp).map((k) => k + "=" + o[k]).join("/") : String(o || ""));
function dnFromText(s) { const o = {}; for (const part of String(s || "").split("/")) { const i = part.indexOf("="); if (i > 0) o[part.slice(0, i).trim()] = part.slice(i + 1).trim(); } return o; }
function certTime(s) {
  const t = String(s || "").trim();
  if (!t) return null;
  let m = t.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/); // Shodan / ASN.1 GeneralizedTime
  if (m) return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  m = t.match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?/); // nmap ISO without zone = UTC
  if (m) return Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
  m = t.match(/^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})/); // "Aug 31 00:00:00 2026 GMT"
  if (m) { const mo = MONTHS[m[1].toLowerCase()]; if (mo != null) return Date.UTC(+m[6], mo, +m[2], +m[3], +m[4], +m[5]); }
  return null;
}
const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
function finishCert(c) {
  c.subject = c.subject || ""; c.issuer = c.issuer || "";
  c.subjectCN = c.subjectCN || (c.subject.match(/(?:^|\/)commonName=([^/]*)/) || c.subject.match(/(?:^|[,/])\s*CN=([^,/]*)/) || [])[1] || "";
  c.issuerCN = c.issuerCN || (c.issuer.match(/(?:^|\/)commonName=([^/]*)/) || c.issuer.match(/(?:^|[,/])\s*CN=([^,/]*)/) || [])[1] || "";
  c.selfSigned = !!c.subject && c.subject.toLowerCase() === c.issuer.toLowerCase();
  c.sans = uniq((c.sans || []).map((x) => String(x).toLowerCase()));
  c.notBeforeMs = certTime(c.notBefore); c.notAfterMs = certTime(c.notAfter);
  c.notBefore = isoOf(c.notBeforeMs) || c.notBefore || ""; c.notAfter = isoOf(c.notAfterMs) || c.notAfter || "";
  c.keyBits = Number(c.keyBits) || null; c.keyType = String(c.keyType || "").toLowerCase(); c.sigAlg = c.sigAlg || ""; c.sha1 = String(c.sha1 || "").replace(/\s+/g, "").toLowerCase();
  return c;
}
/** nmap ssl-cert: structured tables when present, else the text output. */
export function parseSslCert(output, obj) {
  const c = {};
  if (obj && typeof obj === "object" && !Array.isArray(obj) && (obj.subject || obj.validity)) {
    c.subject = dnStr(obj.subject); c.issuer = dnStr(obj.issuer);
    c.subjectCN = obj.subject && obj.subject.commonName || ""; c.issuerCN = obj.issuer && obj.issuer.commonName || "";
    c.keyType = obj.pubkey && obj.pubkey.type || ""; c.keyBits = obj.pubkey && obj.pubkey.bits || "";
    c.sigAlg = obj.sig_algo || ""; c.notBefore = obj.validity && obj.validity.notBefore || ""; c.notAfter = obj.validity && obj.validity.notAfter || "";
    c.sha1 = obj.sha1 || "";
    const ext = Array.isArray(obj.extensions) ? obj.extensions : obj.extensions ? Object.values(obj.extensions) : [];
    const san = ext.find((e) => e && /subject alternative name/i.test(e.name || ""));
    c.sans = san ? String(san.value || "").split(/,\s*/).map((x) => x.replace(/^DNS:/i, "").trim()).filter((x) => x && !/^IP Address:/i.test(x)) : [];
    return finishCert(c);
  }
  const t = String(output || "");
  const g = (re) => ((t.match(re) || [])[1] || "").trim();
  c.subject = g(/^\s*Subject:\s*(.+)$/m); c.issuer = g(/^\s*Issuer:\s*(.+)$/m);
  c.keyType = g(/Public Key type:\s*(\S+)/); c.keyBits = g(/Public Key bits:\s*(\d+)/); c.sigAlg = g(/Signature Algorithm:\s*(\S+)/);
  c.notBefore = g(/Not valid before:\s*(\S+)/); c.notAfter = g(/Not valid after:\s*(\S+)/); c.sha1 = g(/SHA-1:\s*([0-9a-f ]+)/i);
  const san = g(/Subject Alternative Name:\s*(.+)$/m);
  c.sans = san ? san.split(/,\s*/).map((x) => x.replace(/^DNS:/i, "").trim()).filter((x) => x && !/^IP Address:/i.test(x)) : [];
  if (!c.subject && !c.notAfter) return null;
  return finishCert(c);
}
/** nmap ssl-enum-ciphers -> { versions, leastStrength, weak: [{version, cipher, grade}] }. */
export function parseSslEnumCiphers(output) {
  const versions = [], weak = [];
  let cur = "", least = "";
  for (const raw of lines(output)) {
    const l = raw.replace(/^\|_?\s?/, "");
    const v = l.match(/^\s*(SSLv2|SSLv3|TLSv1\.[0-3]):\s*$/);
    if (v) { cur = v[1]; versions.push(cur); continue; }
    const ls = l.match(/least strength:\s*([A-F])/i);
    if (ls) { least = ls[1].toUpperCase(); continue; }
    const c = l.match(/^\s*([A-Z0-9_]+(?:_[A-Z0-9]+)+)\s.*-\s*([A-F])\s*$/);
    if (c && cur && /[C-F]/.test(c[2])) weak.push({ version: cur, cipher: c[1], grade: c[2] });
  }
  return { versions: uniq(versions), leastStrength: least, weak };
}
const WEAK_SSH = { kex: /^(diffie-hellman-group1-sha1|gss-group1-sha1-.*)$/, hostkey: /^ssh-dss$/, enc: /(-cbc$|^arcfour|^3des|^blowfish|^cast128)/, mac: /^(hmac-md5|hmac-md5-96|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-sha1-96)$/ };
/** nmap ssh2-enum-algos -> algorithm lists and the weak ones. */
export function parseSsh2EnumAlgos(output) {
  const out = { kex: [], hostkey: [], enc: [], mac: [], weak: [] };
  const KEYS = { kex_algorithms: "kex", server_host_key_algorithms: "hostkey", encryption_algorithms: "enc", mac_algorithms: "mac", compression_algorithms: null };
  let cur = null;
  for (const raw of lines(output)) {
    const l = raw.replace(/^\|_?\s?/, "");
    const h = l.match(/^\s*([a-z_]+_algorithms):/);
    if (h) { cur = Object.prototype.hasOwnProperty.call(KEYS, h[1]) ? KEYS[h[1]] : null; continue; }
    const a = l.trim();
    if (cur && a && !a.includes(":")) out[cur].push(a);
    else if (cur && /@/.test(a)) out[cur].push(a);
  }
  for (const k of ["kex", "hostkey", "enc", "mac"]) for (const a of out[k]) if (WEAK_SSH[k].test(a)) out.weak.push(k + ": " + a);
  return out;
}
/** smb-protocols -> { dialects, smbv1 }. */
export function parseSmbProtocols(output) {
  const dialects = [];
  for (const raw of lines(output)) { const l = raw.replace(/^\|_?\s?/, "").trim(); if (l && !/^dialects:?$/i.test(l)) dialects.push(l); }
  return { dialects, smbv1: dialects.some((d) => /SMBv1|NT LM 0\.12/i.test(d)) };
}
/** smb2-security-mode / smb-security-mode -> signing required? (null = unknown). */
export function parseSmbSigning(output) {
  const t = String(output || "");
  if (/signing enabled and required|message_signing:\s*required/i.test(t)) return { signingRequired: true };
  if (/not required|message_signing:\s*(disabled|supported)/i.test(t)) return { signingRequired: false };
  return { signingRequired: null };
}
/** rdp-enum-encryption -> { nativeRdp (non-NLA allowed), nla, weakRc4 }. */
export function parseRdpEnum(output) {
  const t = String(output || "");
  return {
    nativeRdp: /Native RDP:\s*SUCCESS/i.test(t) || /RDP Protocol:\s*SUCCESS/i.test(t),
    nla: /CredSSP[^:\n]*:\s*SUCCESS/i.test(t),
    weakRc4: /(40|56)-bit RC4:\s*SUCCESS/i.test(t),
  };
}
/** vulners -> [{ id, score }] (CVE ids only; scores as the script reported them). */
export function parseVulners(output, obj) {
  const seen = new Map();
  const add = (id, score) => { id = String(id || "").toUpperCase(); if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return; const s = Number(score); const prev = seen.get(id); if (!prev || (Number.isFinite(s) && (prev.score == null || s > prev.score))) seen.set(id, { id, score: Number.isFinite(s) ? s : null, exploit: false }); };
  for (const raw of lines(output)) { const m = raw.match(/(CVE-\d{4}-\d{4,})\s+([\d.]+)?/i); if (m) add(m[1], m[2]); }
  if (!seen.size && obj && typeof obj === "object") {
    for (const v of Object.values(obj)) for (const e of Array.isArray(v) ? v : []) if (e && e.id) add(e.id, e.cvss);
  }
  return [...seen.values()].sort((a, b) => cmp(a.id, b.id));
}

// ---------------------------------------------------------------------------
// Normalised records
// ---------------------------------------------------------------------------
const hnames = (host) => uniq(host.hostnames.map((h) => h.name)).join(" ");
function newHost(ip) {
  return { ip, hostnames: [], status: "up", os: "", osAccuracy: null, smbOs: "", nessusOs: "", mac: "", recs: new Map(), hostScripts: {}, pendingHostFindings: [] };
}
function newRec(ip, port, proto) {
  return {
    ip, port, proto: String(proto || "tcp").toLowerCase(), state: "open", reason: "", service: "", serviceGuess: false, product: "", version: "", extrainfo: "", tunnel: "",
    cpe: [], tls: { versions: [], grade: "", weakCiphers: [], cert: null }, banners: { title: "", server: "", poweredBy: "", ssh: "", raw: "" },
    ssh: null, scriptFindings: [], scripts: {}, vulns: [],
  };
}
function addHostname(host, name, type) {
  const n = String(name || "").trim().toLowerCase().replace(/\.$/, "");
  if (!n || isIp(n)) return;
  if (!host.hostnames.some((h) => h.name === n && h.type === type)) host.hostnames.push({ name: n, type: type || "" });
}
function addFinding(rec, key, detail) { if (!rec.scriptFindings.some((f) => f.key === key)) rec.scriptFindings.push({ key, detail: clip(detail, 400) }); }
function setService(rec, name) {
  let n = String(name || "").trim();
  if (n.endsWith("?")) { rec.serviceGuess = true; n = n.slice(0, -1); }
  if (n.startsWith("ssl/")) { rec.tunnel = rec.tunnel || "ssl"; n = n.slice(4); }
  rec.service = n.toLowerCase();
}
function applyServerHeader(rec, value) {
  const v = String(value || "").trim();
  if (!v) return;
  rec.banners.server = clip(v, 300);
  // Banner-only sources (masscan, Nessus 10107, Shodan) get nmap-style product names so version diffs work.
  if (!rec.product) {
    const p = parseServerHeader(v).parts[0];
    if (p) { rec.product = SERVER_PRODUCT[p.name.toLowerCase()] || p.name; rec.version = p.version || ""; }
  }
}
const SERVER_PRODUCT = { apache: "Apache httpd", "microsoft-iis": "Microsoft IIS httpd", nginx: "nginx", lighttpd: "lighttpd", "apache-coyote": "Apache Tomcat" };

/** Apply one NSE script result to a port record. */
function applyScript(rec, id, output, obj) {
  const out = String(output || "");
  rec.scripts[id] = clip(out);
  const lid = id.toLowerCase();
  if (lid === "ssl-cert") { const c = parseSslCert(out, obj); if (c) rec.tls.cert = c; }
  else if (lid === "ssl-enum-ciphers") { const e = parseSslEnumCiphers(out); rec.tls.versions = uniq([...rec.tls.versions, ...e.versions]); rec.tls.grade = e.leastStrength || rec.tls.grade; rec.tls.weakCiphers = e.weak.slice(0, 50); }
  else if (lid === "sslv2") { if (/SSLv2 supported/i.test(out)) rec.tls.versions = uniq([...rec.tls.versions, "SSLv2"]); }
  else if (lid === "http-title") { const t = obj && typeof obj === "object" && obj.title ? obj.title : out.split("\n").map((x) => x.trim()).find(Boolean) || ""; rec.banners.title = clip(t.replace(/^Site doesn't have a title.*$/i, ""), 300); }
  else if (lid === "http-server-header") { applyServerHeader(rec, Array.isArray(obj) && obj.length ? obj.join(" ") : out.trim()); }
  else if (lid === "http-headers") {
    const s = out.match(/^\s*Server:\s*(.+)$/im); if (s && !rec.banners.server) applyServerHeader(rec, s[1]);
    const p = out.match(/^\s*X-Powered-By:\s*(.+)$/im); if (p) rec.banners.poweredBy = clip(p[1].trim(), 200);
  }
  else if (lid === "ssh2-enum-algos") { rec.ssh = parseSsh2EnumAlgos(out); if (rec.ssh.weak.length) addFinding(rec, "ssh-weak-algos", rec.ssh.weak.join(", ")); }
  else if (lid === "sshv1") { if (/supports SSHv1/i.test(out)) addFinding(rec, "ssh-protocol-1", out.trim()); }
  else if (lid === "banner") { rec.banners.raw = clip(out.trim(), 500); const b = parseSshBanner(out); if (b) rec.banners.ssh = out.trim(); }
  else if (lid === "vulners") { for (const v of parseVulners(out, obj)) if (!rec.vulns.some((x) => x.id === v.id)) rec.vulns.push({ ...v, source: "nmap vulners" }); }
  else if (lid === "ftp-anon") { if (/Anonymous FTP login allowed/i.test(out)) addFinding(rec, "ftp-anon", out.split("\n")[0]); }
  else if (lid === "smtp-open-relay") { if (/is an open relay/i.test(out) && !/not an open relay/i.test(out)) addFinding(rec, "smtp-open-relay", out.trim()); }
  else if (lid === "dns-recursion") { if (/Recursion appears to be enabled/i.test(out)) addFinding(rec, "dns-recursion", out.trim()); }
  else if (lid === "ntp-monlist") { if (out.trim() && !/error|failed|no response/i.test(out)) addFinding(rec, "ntp-monlist", out.trim().split("\n")[0]); }
  else if (/^snmp-/.test(lid)) { if (out.trim() && !/^\s*(error|failed)/i.test(out)) addFinding(rec, "snmp-community", id + ": " + out.trim().split("\n")[0]); }
  else if (lid === "ldap-search") { if (/^\s*dn:/im.test(out)) addFinding(rec, "ldap-anon", "ldap-search returned " + (out.match(/^\s*dn:/gim) || []).length + " entries without credentials"); }
  else if (lid === "rdp-enum-encryption") { const r = parseRdpEnum(out); if (r.nativeRdp) addFinding(rec, "rdp-no-nla", "Native RDP security layer accepted"); if (r.weakRc4) addFinding(rec, "rdp-weak-enc", "40/56-bit RC4 encryption accepted"); }
  else if (lid === "smb-protocols") { const p = parseSmbProtocols(out); if (p.smbv1) addFinding(rec, "smbv1", p.dialects.join(", ")); }
  else if (lid === "smb2-security-mode" || lid === "smb-security-mode") { if (parseSmbSigning(out).signingRequired === false) addFinding(rec, "smb-signing-not-required", out.trim().replace(/\s+/g, " ")); }
}
const HOST_SMB_SCRIPTS = /^(smb-protocols|smb2-security-mode|smb-security-mode|smb-os-discovery|smb-vuln-.*|smb2-capabilities)$/i;

function mergeRec(a, b) {
  const pick = (x, y) => (x ? x : y);
  a.state = a.state === "open" || b.state === "open" ? "open" : pick(a.state, b.state);
  a.reason = pick(a.reason, b.reason);
  if (!a.service || GENERIC_SVC.test(a.service)) { a.service = b.service || a.service; a.serviceGuess = b.serviceGuess; }
  a.product = pick(a.product, b.product); a.version = pick(a.version, b.version); a.extrainfo = pick(a.extrainfo, b.extrainfo); a.tunnel = pick(a.tunnel, b.tunnel);
  a.cpe = uniq([...a.cpe, ...b.cpe]);
  a.tls.versions = uniq([...a.tls.versions, ...b.tls.versions]); a.tls.grade = pick(a.tls.grade, b.tls.grade); a.tls.weakCiphers = a.tls.weakCiphers.length ? a.tls.weakCiphers : b.tls.weakCiphers; a.tls.cert = a.tls.cert || b.tls.cert;
  for (const k of Object.keys(a.banners)) a.banners[k] = pick(a.banners[k], b.banners[k]);
  a.ssh = a.ssh || b.ssh;
  for (const f of b.scriptFindings) addFinding(a, f.key, f.detail);
  for (const [k, v] of Object.entries(b.scripts)) if (!(k in a.scripts)) a.scripts[k] = v;
  for (const v of b.vulns) if (!a.vulns.some((x) => x.id === v.id)) a.vulns.push(v);
  return a;
}
function putRec(host, rec) {
  const key = rec.proto + "/" + rec.port;
  const prev = host.recs.get(key);
  host.recs.set(key, prev ? mergeRec(prev, rec) : rec);
}
function getHost(scan, ip) {
  let h = scan.hosts.get(ip);
  if (!h) { h = newHost(ip); scan.hosts.set(ip, h); }
  return h;
}
function newScan(file, format, scanner) {
  return { file, files: [file], format, scanner, timeMs: null, endMs: null, args: "", version: "", targets: null, scanned: { tcp: null, udp: null }, scannedSource: "", hosts: new Map(), down: new Set(), hostsUpReported: null, notes: [], external: false, defaultExternal: false };
}
const tsMs = (v) => {
  if (v == null || v === "") return null;
  if (/^\d{9,10}$/.test(String(v))) return Number(v) * 1000;
  if (/^\d{12,13}$/.test(String(v))) return Number(v);
  const s = String(v).trim();
  const iso = /[zZ]|[+-]\d{2}:?\d{2}$/.test(s) ? s : s.replace(" ", "T") + "Z";
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
};
const minT = (a, b) => (a == null ? b : b == null ? a : Math.min(a, b));
const maxT = (a, b) => (a == null ? b : b == null ? a : Math.max(a, b));

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------
/** Detect the format of a file from its content (name is only a tie-breaker). */
export function detectFormat(text, name = "") {
  const head = String(text || "").slice(0, 65536).replace(/^﻿/, "");
  const t = head.trimStart();
  const res = (format, confidence) => ({ format, label: FORMATS[format], confidence });
  if (!t) return res("unknown", 0);
  if (/<NessusClientData_v2\b/.test(head)) return res("nessus", 1);
  const nm = head.match(/<nmaprun\b([^>]*)>/);
  if (nm) { const a = attrs(nm[1]); return /masscan/i.test(a.scanner || "") ? res("masscan-xml", 1) : res("nmap-xml", 1); }
  if (/^# Nmap [\d.]+\w* scan initiated .* as: /m.test(head) || /^Host: \S+ \([^)]*\)\t(Status|Ports): /m.test(head)) return res("nmap-grep", 1);
  if (t[0] === "{" || t[0] === "[") {
    if (/"tool"\s*:\s*"Darknode Firewall Rule Audit"/.test(head) || /"tool"\s*:\s*"fwaudit"/.test(head)) return res("fwaudit", 1);
    if (/"ip_str"\s*:/.test(head)) return /^\s*\{\s*"[^"]+"[\s\S]*"data"\s*:\s*\[/.test(head) && !/^\{[^\n]*"ip_str"[^\n]*"port"[^\n]*\}\s*$/m.test(head) ? res("shodan-host", 0.9) : res("shodan-ndjson", 1);
    if (/"ports"\s*:\s*\[\s*\{\s*"port"/.test(head) && /"ip"\s*:/.test(head)) return res("masscan-json", 1);
    if (/"port"\s*:/.test(head) && /"(ip|host)"\s*:/.test(head)) return res("naabu-jsonl", 0.9);
    return res("unknown", 0);
  }
  if (/^[^\n]*[,;\t][^\n]*\n/.test(head)) {
    const first = head.split(/\r?\n/)[0];
    const delim = (first.match(/\t/g) || []).length > (first.match(/,/g) || []).length ? "\t" : first.includes(";") && !first.includes(",") ? ";" : ",";
    const hdr = first.split(delim).map((x) => x.replace(/^"|"$/g, "").trim());
    const ip = findColumn(hdr, COLUMNS.ip), port = findColumn(hdr, COLUMNS.port);
    if (ip && port) return res("csv", 0.7);
    return { ...res("csv", 0.3), headers: hdr };
  }
  return res("unknown", 0);
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------
/** Iterate top-level <tag ...>...</tag> segments without building one giant tree. */
function* segments(text, tag) {
  const open = "<" + tag, close = "</" + tag + ">";
  let i = 0;
  for (;;) {
    let s = text.indexOf(open, i);
    while (s >= 0 && !/[\s>]/.test(text[s + open.length] || "")) s = text.indexOf(open, s + 1);
    if (s < 0) return;
    const e = text.indexOf(close, s);
    if (e < 0) return;
    yield text.slice(s, e + close.length);
    i = e + close.length;
  }
}

/** nmap / masscan XML (-oX). */
export function parseNmapXml(text, file = "nmap.xml", ctx) {
  const s = String(text || "");
  const head = s.slice(0, Math.max(0, s.search(/<host[\s>]/)) || 4096);
  const run = attrs((s.match(/<nmaprun\b([^>]*)>/) || [])[1] || "");
  const masscan = /masscan/i.test(run.scanner || "");
  const scan = newScan(file, masscan ? "masscan-xml" : "nmap-xml", masscan ? "masscan" : "nmap");
  scan.args = run.args || ""; scan.version = run.version || "";
  scan.timeMs = tsMs(run.start);
  if (scan.args) { const a = parseNmapArgs(scan.args); scan.targets = a.targets; scan.scanned = a.scanned; scan.scannedSource = a.scanned.tcp || a.scanned.udp ? "args" : ""; }
  const infos = [...head.matchAll(/<scaninfo\b([^>]*)\/?>/g)].map((m) => attrs(m[1]));
  for (const si of infos) {
    const proto = String(si.protocol || "").toLowerCase();
    if (proto !== "tcp" && proto !== "udp") continue;
    if (si.services) { const ps = parsePortSpec(si.services, proto); if (ps) { scan.scanned[proto] = ps[proto]; scan.scannedSource = "scaninfo"; } }
  }
  const fin = attrs((s.match(/<finished\b([^>]*)\/?>/) || [])[1] || "");
  scan.endMs = tsMs(fin.time);
  const hs = attrs((s.match(/<runstats>[\s\S]*?<hosts\b([^>]*)\/?>/) || [])[1] || "");
  if (hs.up != null) scan.hostsUpReported = Number(hs.up);
  let n = 0;
  for (const seg of segments(s, "host")) {
    if (++n % 1000 === 0) ctx?.progress?.(n, 0, file + ": hosts");
    const h = xmlLite(seg);
    const st = kid(h, "status");
    const addrs = kids(h, "address");
    const a = addrs.find((x) => /ipv[46]/.test(x.attrs.addrtype || "")) || addrs[0];
    if (!a) continue;
    const ip = a.attrs.addr;
    if (st && st.attrs.state && st.attrs.state !== "up") { scan.down.add(ip); continue; }
    const host = getHost(scan, ip);
    const mac = addrs.find((x) => x.attrs.addrtype === "mac");
    if (mac) host.mac = mac.attrs.addr + (mac.attrs.vendor ? " (" + mac.attrs.vendor + ")" : "");
    const hstart = tsMs(h.attrs.starttime), hend = tsMs(h.attrs.endtime);
    if (!scan.timeMs) scan.timeMs = minT(scan.timeMs, hstart || hend);
    scan.endMs = maxT(scan.endMs, hend);
    for (const hn of kids(kid(h, "hostnames"), "hostname")) addHostname(host, hn.attrs.name, hn.attrs.type || "");
    const ports = kid(h, "ports");
    for (const p of kids(ports, "port")) {
      const rec = newRec(ip, Number(p.attrs.portid), p.attrs.protocol);
      const ps = kid(p, "state");
      rec.state = ps ? ps.attrs.state || "" : ""; rec.reason = ps ? ps.attrs.reason || "" : "";
      const sv = kid(p, "service");
      if (sv) {
        setService(rec, sv.attrs.name);
        rec.product = sv.attrs.product || ""; rec.version = sv.attrs.version || ""; rec.extrainfo = sv.attrs.extrainfo || ""; rec.tunnel = sv.attrs.tunnel || rec.tunnel;
        if (sv.attrs.method === "table") rec.serviceGuess = true;
        rec.cpe = uniq(kids(sv, "cpe").map((c) => c.text));
      }
      for (const sc of kids(p, "script")) applyScript(rec, sc.attrs.id || "", sc.attrs.output || "", tableObj(sc));
      if (masscan && rec.state === "open" && !rec.service) rec.serviceGuess = true;
      putRec(host, rec);
    }
    const os = kids(kid(h, "os"), "osmatch").map((m) => ({ name: m.attrs.name || "", acc: Number(m.attrs.accuracy) || 0 })).sort((x, y) => y.acc - x.acc || cmp(x.name, y.name))[0];
    if (os) { host.os = os.name; host.osAccuracy = os.acc; }
    for (const sc of kids(kid(h, "hostscript"), "script")) {
      const id = sc.attrs.id || "", out = sc.attrs.output || "";
      host.hostScripts[id] = clip(out);
      if (id === "smb-os-discovery") { const m = out.match(/^\s*OS:\s*(.+)$/m); host.smbOs = m ? m[1].trim() : host.smbOs; const fq = out.match(/FQDN:\s*(\S+)/); if (fq) addHostname(host, fq[1], "smb"); }
      if (HOST_SMB_SCRIPTS.test(id)) host.pendingHostFindings.push({ id, out, obj: tableObj(sc) });
    }
  }
  if (!scan.timeMs) scan.notes.push("no scan start time in the file");
  return finishHostScripts(scan);
}
// Host-level SMB scripts are attached to the 445 (or 139) port record when one exists.
function finishHostScripts(scan) {
  for (const host of scan.hosts.values()) {
    if (!host.pendingHostFindings.length) continue;
    const target = host.recs.get("tcp/445") || host.recs.get("tcp/139");
    for (const p of host.pendingHostFindings) if (target) applyScript(target, p.id, p.out, p.obj);
    host.pendingHostFindings = [];
  }
  return scan;
}

function parseNmapDate(s) {
  const m = String(s || "").match(/([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})/);
  if (!m) return null;
  const mo = MONTHS[m[1].toLowerCase()];
  return mo == null ? null : Date.UTC(+m[6], mo, +m[2], +m[3], +m[4], +m[5]);
}

/** nmap grepable (-oG). */
export function parseNmapGrep(text, file = "nmap.gnmap", ctx) {
  const scan = newScan(file, "nmap-grep", "nmap");
  let n = 0;
  for (const line of lines(text)) {
    if (++n % 5000 === 0) ctx?.progress?.(n, 0, file + ": lines");
    if (line.startsWith("#")) {
      const init = line.match(/^# Nmap ([\d.]+\w*) scan initiated (.+?) as: (.*)$/);
      if (init) {
        scan.version = init[1]; scan.timeMs = parseNmapDate(init[2]); scan.args = init[3].trim();
        const a = parseNmapArgs(scan.args); scan.targets = a.targets; scan.scanned = a.scanned; scan.scannedSource = a.scanned.tcp || a.scanned.udp ? "args" : "";
      }
      const ps = line.match(/^# Ports scanned:\s*TCP\((\d+);([^)]*)\)\s*UDP\((\d+);([^)]*)\)/);
      if (ps) {
        scan.scanned = { tcp: +ps[1] ? (parsePortSpec(ps[2], "tcp") || {}).tcp || null : [], udp: +ps[3] ? (parsePortSpec(ps[4], "udp") || {}).udp || null : [] };
        scan.scannedSource = "ports-scanned line";
      }
      const done = line.match(/^# Nmap done at (.+?) -- (\d+) IP addresses? \((\d+) hosts? up\)/);
      if (done) { scan.endMs = parseNmapDate(done[1]); scan.hostsUpReported = Number(done[3]); }
      continue;
    }
    const m = line.match(/^Host:\s+(\S+)\s+\(([^)]*)\)\t(.*)$/);
    if (!m) continue;
    const ip = m[1];
    const fields = {};
    for (const f of m[3].split("\t")) { const i = f.indexOf(": "); if (i > 0) fields[f.slice(0, i).trim()] = f.slice(i + 2); }
    if (fields.Status && !/^Up/i.test(fields.Status)) { scan.down.add(ip); continue; }
    const host = getHost(scan, ip);
    if (m[2]) addHostname(host, m[2], "PTR");
    if (fields.OS) host.os = fields.OS.trim();
    if (fields.Ports) {
      for (const ent of fields.Ports.split(/,\s(?=\d+\/)/)) {
        const parts = ent.trim().split("/");
        if (parts.length < 5 || !/^\d+$/.test(parts[0])) continue;
        const rec = newRec(ip, Number(parts[0]), parts[2]);
        rec.state = parts[1]; setService(rec, parts[4]);
        const pv = splitProductVersion(parts[6] || "");
        rec.product = pv.product; rec.version = pv.version; rec.extrainfo = pv.extrainfo;
        putRec(host, rec);
      }
    }
  }
  return scan;
}

function bannerToRec(rec, svc) {
  const name = String(svc.name || "").toLowerCase(), b = String(svc.banner || "");
  if (!b) { if (name && !rec.service) setService(rec, name); return; }
  if (name === "ssh") { const s = parseSshBanner(b); rec.banners.ssh = clip(b.trim(), 300); if (s) { rec.product = rec.product || s.product; rec.version = rec.version || s.version; } if (!rec.service) setService(rec, "ssh"); }
  else if (name === "http") { const sv = b.match(/^Server:\s*(.+)$/im); if (sv) applyServerHeader(rec, sv[1].trim()); const pb = b.match(/^X-Powered-By:\s*(.+)$/im); if (pb) rec.banners.poweredBy = pb[1].trim(); if (!rec.service) setService(rec, "http"); }
  else if (name === "http.server") applyServerHeader(rec, b);
  else if (name === "title") rec.banners.title = clip(b.trim(), 300);
  else if (/^(x509|ssl|vuln)/.test(name)) { /* DER/base64 or masscan vuln probes are not decoded */ }
  else { if (!rec.service) setService(rec, name); rec.banners.raw = rec.banners.raw || clip(b.trim(), 500); }
}

/** masscan -oJ (tolerates the trailing / leading commas older and newer masscan builds write). */
export function parseMasscanJson(text, file = "masscan.json", ctx) {
  const scan = newScan(file, "masscan-json", "masscan");
  let records = null;
  const t = String(text || "").trim();
  try { const j = JSON.parse(t); records = Array.isArray(j) ? j : [j]; } catch (_) {
    try { const j = JSON.parse(t.replace(/,\s*([\]}])/g, "$1")); records = Array.isArray(j) ? j : [j]; } catch (__) { records = null; }
  }
  const take = (o) => {
    if (!o || typeof o !== "object" || !o.ip) return;
    const host = getHost(scan, String(o.ip));
    const ts = tsMs(o.timestamp);
    scan.timeMs = minT(scan.timeMs, ts); scan.endMs = maxT(scan.endMs, ts);
    for (const p of Array.isArray(o.ports) ? o.ports : []) {
      if (!p || p.port == null) continue;
      const rec = newRec(host.ip, Number(p.port), p.proto || "tcp");
      rec.state = p.status || "open"; rec.reason = p.reason || "";
      if (p.service) bannerToRec(rec, p.service); else rec.serviceGuess = true;
      putRec(host, rec);
    }
  };
  if (records) records.forEach(take);
  else {
    let n = 0;
    for (const raw of lines(t)) {
      if (++n % 5000 === 0) ctx?.progress?.(n, 0, file + ": lines");
      const l = raw.trim().replace(/^,\s*/, "").replace(/,\s*$/, "");
      if (!l.startsWith("{")) continue;
      try { take(JSON.parse(l)); } catch (_) { /* partial line */ }
    }
  }
  scan.notes.push("masscan does not record the scanned port list; coverage is unknown unless you enter it");
  return scan;
}

/** naabu -json (one object per line). */
export function parseNaabu(text, file = "naabu.jsonl", ctx) {
  const scan = newScan(file, "naabu-jsonl", "naabu");
  let n = 0;
  for (const raw of lines(text)) {
    if (++n % 5000 === 0) ctx?.progress?.(n, 0, file + ": lines");
    const l = raw.trim();
    if (!l.startsWith("{")) continue;
    let o; try { o = JSON.parse(l); } catch (_) { continue; }
    const ip = o.ip || (isIp(o.host) ? o.host : "");
    if (!ip) continue;
    const portObj = o.port && typeof o.port === "object" ? o.port : null;
    const port = Number(portObj ? portObj.Port : o.port);
    if (!Number.isFinite(port)) continue;
    const host = getHost(scan, ip);
    if (o.host && !isIp(o.host)) addHostname(host, o.host, "user");
    const proto = o.protocol != null ? o.protocol : portObj ? portObj.Protocol : "tcp";
    const rec = newRec(ip, port, typeof proto === "number" ? (proto === 1 ? "udp" : "tcp") : proto || "tcp");
    rec.serviceGuess = true;
    if (o.tls === true || (portObj && portObj.TLS === true)) rec.tunnel = "ssl";
    putRec(host, rec);
    const ts = tsMs(o.timestamp);
    scan.timeMs = minT(scan.timeMs, ts); scan.endMs = maxT(scan.endMs, ts);
  }
  scan.notes.push("naabu output does not record the scanned port list; coverage is unknown unless you enter it");
  return scan;
}

const NESSUS_SVC = { www: "http", cifs: "microsoft-ds", smb: "microsoft-ds", msrdp: "ms-wbt-server", mssql: "ms-sql-s", dns: "domain", "general": "", "unknown": "" };
/** Nessus .nessus v2: ports and services (vulnerabilities belong in Vulnerability Import). */
export function parseNessus(text, file = "scan.nessus", ctx) {
  const s = String(text || "");
  const scan = newScan(file, "nessus", "nessus");
  const pref = (name) => { const m = s.match(new RegExp("<name>" + name + "</name>\\s*<value>([^<]*)</value>")); return m ? decodeEnt(m[1]).trim() : null; };
  const pr = pref("port_range");
  if (pr && !/^default$/i.test(pr)) { const ps = parsePortSpec(/^all$/i.test(pr) ? "1-65535" : pr, "tcp"); if (ps) { scan.scanned.tcp = ps.tcp; scan.scannedSource = "policy port_range"; } }
  else scan.notes.push("policy port_range is 'default' (Nessus' built-in list); port coverage is unknown");
  const tgt = pref("TARGET");
  if (tgt) scan.targets = makeTargets(tgt.split(/[,\s]+/).filter(Boolean), []);
  let n = 0;
  for (const seg of segments(s, "ReportHost")) {
    if (++n % 200 === 0) ctx?.progress?.(n, 0, file + ": hosts");
    const h = xmlLite(seg);
    const tags = {};
    for (const tg of kids(kid(h, "HostProperties"), "tag")) tags[tg.attrs.name] = tg.text;
    const ip = tags["host-ip"] || (isIp(h.attrs.name) ? h.attrs.name : "");
    if (!ip) continue;
    const host = getHost(scan, ip);
    if (tags["host-fqdn"]) addHostname(host, tags["host-fqdn"], "fqdn");
    if (tags["host-rdns"]) addHostname(host, tags["host-rdns"], "PTR");
    if (h.attrs.name && !isIp(h.attrs.name)) addHostname(host, h.attrs.name, "user");
    if (tags["operating-system"]) host.nessusOs = tags["operating-system"].split("\n")[0].trim();
    const st = tsMs(tags.HOST_START_TIMESTAMP) || parseNmapDate(tags.HOST_START);
    const en = tsMs(tags.HOST_END_TIMESTAMP) || parseNmapDate(tags.HOST_END);
    scan.timeMs = minT(scan.timeMs, st); scan.endMs = maxT(scan.endMs, en);
    for (const it of kids(h, "ReportItem")) {
      const port = Number(it.attrs.port);
      if (!port) continue;
      const rec = newRec(ip, port, it.attrs.protocol || "tcp");
      const svc = String(it.attrs.svc_name || "").toLowerCase();
      setService(rec, Object.prototype.hasOwnProperty.call(NESSUS_SVC, svc) ? NESSUS_SVC[svc] : svc);
      const pid = String(it.attrs.pluginID || "");
      const out = (kid(it, "plugin_output") || {}).text || "";
      if (pid === "10107") { const m = out.match(/web server type is\s*:\s*\n+\s*(.+)/i); if (m) applyServerHeader(rec, m[1].trim()); }
      else if (pid === "10267") { const m = out.match(/SSH version\s*:\s*(\S.*)/i); if (m) { rec.banners.ssh = m[1].trim(); const b = parseSshBanner(m[1]); if (b) { rec.product = b.product; rec.version = b.version; } } }
      else if (pid === "10881") { if (/^\s*-\s*1\.(33|5|99)/m.test(out)) addFinding(rec, "ssh-protocol-1", "SSH protocol 1 offered (" + out.replace(/\s+/g, " ").trim() + ")"); }
      else if (pid === "56984") { rec.tls.versions = uniq([...rec.tls.versions, ...(out.match(/SSLv[23]|TLSv1\.[0-3]/g) || [])]); }
      else if (pid === "10863") { const c = parseNessusCert(out); if (c) rec.tls.cert = c; }
      else if (pid === "57608") addFinding(rec, "smb-signing-not-required", "Nessus 57608: SMB signing not required");
      else if (pid === "96982") addFinding(rec, "smbv1", "Nessus 96982: SMBv1 enabled");
      if (["11219", "10335", "34277", "14272", "22964", "10107", "10267", "10881", "56984", "10863"].includes(pid)) rec.scripts["nessus-" + pid] = clip(out || it.attrs.pluginName || "");
      putRec(host, rec);
    }
  }
  return scan;
}
/** Nessus plugin 10863 (SSL Certificate Information) output. */
export function parseNessusCert(out) {
  const t = String(out || "");
  const sect = (name) => { const m = t.match(new RegExp(name + " Name:\\s*\\n([\\s\\S]*?)(?:\\n\\s*\\n[A-Z][a-z]+ [A-Z]?[a-z]*\\s*(?:Name|Number)?\\s*:|$)")); return m ? m[1] : ""; };
  const cnOf = (block) => ((block.match(/Common Name:\s*(.+)/) || [])[1] || "").trim();
  const subj = sect("Subject"), iss = sect("Issuer");
  const c = {
    subjectCN: cnOf(subj), issuerCN: cnOf(iss),
    sigAlg: ((t.match(/Signature Algorithm:\s*(.+)/) || [])[1] || "").trim(),
    notBefore: ((t.match(/Not Valid Before:\s*(.+)/) || [])[1] || "").trim(), notAfter: ((t.match(/Not Valid After:\s*(.+)/) || [])[1] || "").trim(),
    keyType: /RSA/i.test((t.match(/Public Key Info:[\s\S]*?Algorithm:\s*(.+)/) || [])[1] || "") ? "rsa" : ((t.match(/Public Key Info:[\s\S]*?Algorithm:\s*(\S+)/) || [])[1] || ""),
    keyBits: ((t.match(/Key Length:\s*(\d+)/) || [])[1] || ""),
    sha1: ((t.match(/SHA-1 Fingerprint:\s*([0-9A-F: ]+)/i) || [])[1] || "").replace(/[: ]/g, ""),
    sans: (t.match(/DNS:\s*([^\s,]+)/g) || []).map((x) => x.replace(/^DNS:\s*/, "")),
  };
  if (!c.subjectCN && !c.notAfter) return null;
  c.subject = "commonName=" + c.subjectCN; c.issuer = "commonName=" + c.issuerCN;
  if (/^\s*$/.test(iss)) c.issuer = "";
  return finishCert(c);
}

function shodanBanner(scan, o) {
  const ip = String(o.ip_str || "");
  if (!ip || o.port == null) return;
  const host = getHost(scan, ip);
  for (const hn of o.hostnames || []) addHostname(host, hn, "shodan");
  if (o.os && !host.os) host.os = String(o.os);
  const rec = newRec(ip, Number(o.port), o.transport || "tcp");
  const mod = String((o._shodan && o._shodan.module) || "").toLowerCase().replace(/-simple-new$|-\d+$/, "");
  setService(rec, mod === "https" ? "http" : mod);
  if (mod === "https" || (o.ssl && typeof o.ssl === "object")) rec.tunnel = "ssl";
  rec.product = o.product ? String(o.product) : ""; rec.version = o.version ? String(o.version) : "";
  rec.cpe = uniq([...(o.cpe || []), ...(o.cpe23 || [])].map(String));
  const data = String(o.data || "");
  if (data) rec.banners.raw = clip(data.split("\n").slice(0, 8).join("\n"), 500);
  if (/^SSH-\d/.test(data)) {
    rec.banners.ssh = data.split("\n")[0].trim();
    const sb = parseSshBanner(rec.banners.ssh);
    if (sb && !rec.product) { rec.product = sb.product; rec.version = sb.version; }
  }
  if (o.http && typeof o.http === "object") {
    rec.banners.title = clip(o.http.title || "", 300);
    if (o.http.server) applyServerHeader(rec, o.http.server);
  }
  const pb = data.match(/^X-Powered-By:\s*(.+)$/im); if (pb) rec.banners.poweredBy = pb[1].trim();
  if (o.ssl && typeof o.ssl === "object") {
    const vers = (o.ssl.versions || []).filter((v) => !String(v).startsWith("-")).map((v) => (v === "TLSv1" ? "TLSv1.0" : String(v)));
    rec.tls.versions = uniq(vers);
    const ce = o.ssl.cert;
    if (ce && typeof ce === "object") {
      const dn = (x) => (x && typeof x === "object" ? Object.keys(x).sort(cmp).map((k) => k + "=" + x[k]).join("/") : "");
      rec.tls.cert = finishCert({
        subject: dn(ce.subject), issuer: dn(ce.issuer), subjectCN: ce.subject && ce.subject.CN || "", issuerCN: ce.issuer && ce.issuer.CN || "",
        notBefore: ce.issued || "", notAfter: ce.expires || "", sigAlg: ce.sig_alg || "", keyType: ce.pubkey && ce.pubkey.type || "", keyBits: ce.pubkey && ce.pubkey.bits || "",
        sha1: ce.fingerprint && ce.fingerprint.sha1 || "", sans: [],
      });
    }
  }
  if (o.smb && typeof o.smb === "object" && Number(o.smb.smb_version) === 1) addFinding(rec, "smbv1", "Shodan smb_version 1");
  if (o.vulns && typeof o.vulns === "object") {
    for (const [id, v] of Object.entries(o.vulns)) {
      if (!/^CVE-\d{4}-\d{4,}$/i.test(id)) continue;
      rec.vulns.push({ id: id.toUpperCase(), score: v && Number.isFinite(Number(v.cvss)) ? Number(v.cvss) : null, verified: !!(v && v.verified), source: "Shodan" });
    }
    rec.vulns.sort((a, b) => cmp(a.id, b.id));
  }
  rec.scripts["shodan-" + (mod || "banner")] = clip(data);
  putRec(host, rec);
  const ts = tsMs(o.timestamp);
  scan.timeMs = minT(scan.timeMs, ts); scan.endMs = maxT(scan.endMs, ts);
}
/** Shodan `shodan download` / `shodan parse` NDJSON, or a Shodan host JSON ({ ip_str, data: [...] }). */
export function parseShodan(text, file = "shodan.json", ctx) {
  const scan = newScan(file, "shodan-ndjson", "shodan");
  scan.defaultExternal = true;
  const t = String(text || "").trim();
  let whole = null;
  if (t.startsWith("[") || (t.startsWith("{") && !/\}\s*\n\s*\{/.test(t.slice(0, 200000)))) { try { whole = JSON.parse(t); } catch (_) { whole = null; } }
  if (whole) {
    const list = Array.isArray(whole) ? whole : [whole];
    for (const o of list) {
      if (o && Array.isArray(o.data)) { scan.format = "shodan-host"; for (const b of o.data) shodanBanner(scan, { ip_str: o.ip_str, hostnames: o.hostnames, os: o.os, ...b }); }
      else shodanBanner(scan, o);
    }
  } else {
    let n = 0;
    for (const raw of lines(t)) {
      if (++n % 5000 === 0) ctx?.progress?.(n, 0, file + ": lines");
      const l = raw.trim();
      if (!l.startsWith("{")) continue;
      try { shodanBanner(scan, JSON.parse(l)); } catch (_) { /* skip */ }
    }
  }
  scan.notes.push("Shodan crawls from the internet on its own schedule and port list; coverage is unknown and each banner keeps its own timestamp");
  return scan;
}

/** Generic CSV with ip + port columns (column map may be supplied). */
export function parsePortCsv(text, file = "ports.csv", columns = {}) {
  const scan = newScan(file, "csv", "csv");
  let cols = null, n = 0;
  for (const row of iterCsv(String(text || ""))) {
    if (!cols) {
      const hdr = Object.keys(row);
      cols = {};
      for (const [k, al] of Object.entries(COLUMNS)) cols[k] = columns[k] && hdr.includes(columns[k]) ? columns[k] : findColumn(hdr, al);
      if (!cols.ip || !cols.port) { scan.notes.push("needs an IP column and a port column (map them)"); return scan; }
    }
    n++;
    const ip = String(row[cols.ip] || "").trim(), port = Number(String(row[cols.port] || "").replace(/\/.*$/, ""));
    if (!isIp(ip) || !Number.isFinite(port) || port <= 0) continue;
    const host = getHost(scan, ip);
    if (cols.hostname && row[cols.hostname]) addHostname(host, row[cols.hostname], "user");
    const pm = String(row[cols.port]).match(/\/(tcp|udp)/i);
    const rec = newRec(ip, port, (cols.proto && row[cols.proto]) || (pm ? pm[1] : "tcp"));
    rec.state = String((cols.state && row[cols.state]) || "open").toLowerCase();
    if (cols.service) setService(rec, row[cols.service]); else rec.serviceGuess = true;
    if (cols.product) rec.product = String(row[cols.product] || ""); if (cols.version) rec.version = String(row[cols.version] || "");
    putRec(host, rec);
    if (cols.timestamp) { const ts = tsMs(row[cols.timestamp]); scan.timeMs = minT(scan.timeMs, ts); scan.endMs = maxT(scan.endMs, ts); }
  }
  scan.notes.push(n + " rows; port coverage unknown");
  return scan;
}

/** Firewall Rule Audit JSON export -> plain rules (only what the segmentation check needs). */
export function parseFwaudit(text) {
  let j; try { j = JSON.parse(String(text || "")); } catch (_) { return null; }
  if (!j || !Array.isArray(j.rules)) return null;
  return { label: j.label || j.format || "", format: j.format || "", rules: j.rules.map((r, i) => ({ idx: r.idx != null ? r.idx : i + 1, name: r.name || "", scope: r.scope || "", action: r.action || "", direction: r.direction || "any", proto: r.proto || "any", src: String(r.src || "any"), dst: String(r.dst || "any"), dstPorts: String(r.dstPorts || "any"), enabled: r.enabled !== false, state: r.state || null, restricted: !!r.restricted, shadowedBy: r.shadowedBy || null, raw: r.raw || "" })) };
}

// ---------------------------------------------------------------------------
// parseInput: detection + per-file parse (used by the UI for the file list and by analyze)
// ---------------------------------------------------------------------------
function parseOne(f, opts, ctx) {
  const text = String(f.text || "");
  const det = detectFormat(text, f.name);
  const name = f.name || "input";
  let scan = null, fw = null;
  if (det.format === "nmap-xml" || det.format === "masscan-xml") scan = parseNmapXml(text, name, ctx);
  else if (det.format === "nmap-grep") scan = parseNmapGrep(text, name, ctx);
  else if (det.format === "masscan-json") scan = parseMasscanJson(text, name, ctx);
  else if (det.format === "naabu-jsonl") scan = parseNaabu(text, name, ctx);
  else if (det.format === "nessus") scan = parseNessus(text, name, ctx);
  else if (det.format === "shodan-ndjson" || det.format === "shodan-host") scan = parseShodan(text, name, ctx);
  else if (det.format === "csv") scan = parsePortCsv(text, name, (opts && opts.columns) || {});
  else if (det.format === "fwaudit") fw = parseFwaudit(text);
  return { det, scan, fw, name };
}
function recRow(scanLabel, scan, host, rec) {
  return {
    scanId: scanLabel, scanner: scan.scanner, scanTime: isoOf(scan.timeMs), ip: rec.ip, hostnames: host.hostnames.map((h) => h.name), port: rec.port, proto: rec.proto, state: rec.state,
    service: rec.service, product: rec.product, version: rec.version, cpe: rec.cpe,
    tls: { versions: rec.tls.versions, cert: rec.tls.cert ? { subject: rec.tls.cert.subject, issuer: rec.tls.cert.issuer, notAfter: rec.tls.cert.notAfter, selfSigned: rec.tls.cert.selfSigned, sigAlg: rec.tls.cert.sigAlg, keyBits: rec.tls.cert.keyBits } : null },
    banners: { ...rec.banners }, scriptFindings: rec.scriptFindings.map((f) => f.key),
  };
}

/**
 * Parse one or more files. input: text | [{ name, text }]. Returns per-file detection and the
 * normalised rows ({ scanId, scanner, scanTime, ip, hostnames, port, proto, state, service,
 * product, version, cpe, tls, banners, scriptFindings }).
 */
export function parseInput(input, opts = {}) {
  const files = typeof input === "string" ? [{ name: "input", text: input }] : Array.isArray(input) ? input : input && Array.isArray(input.files) ? input.files : [];
  const out = { format: "empty", headers: [], rows: [], skipped: [], files: [] };
  for (const f of files) {
    const { det, scan, fw, name } = parseOne(f, opts);
    const entry = { name, format: det.format, label: det.label, confidence: det.confidence, headers: det.headers || [], hosts: 0, records: 0, time: "", notes: [] };
    if (scan) {
      entry.hosts = scan.hosts.size; entry.time = isoOf(scan.timeMs); entry.notes = scan.notes.slice();
      entry.scanner = scan.scanner; entry.portsScanned = scan.scanned.tcp || scan.scanned.udp ? (portCount(scan.scanned.tcp) || 0) + (portCount(scan.scanned.udp) || 0) : null;
      if (det.format === "csv" && !entry.headers.length) entry.headers = [];
      for (const host of [...scan.hosts.values()].sort((a, b) => ipCmp(a.ip, b.ip))) for (const rec of [...host.recs.values()].sort(recCmp)) { entry.records++; out.rows.push(recRow(name, scan, host, rec)); }
      entry.external = scan.defaultExternal;
    } else if (fw) { entry.records = fw.rules.length; entry.notes.push(fw.rules.length + " firewall rules"); }
    else if (det.format !== "unknown") entry.notes.push("no records");
    else out.skipped.push({ check: "parse", reason: name + ": not a recognised scan export" });
    out.files.push(entry);
  }
  out.format = out.files.length === 1 ? out.files[0].format : out.files.length ? "multi" : "empty";
  out.headers = out.rows.length ? Object.keys(out.rows[0]) : [];
  return out;
}
const recCmp = (a, b) => cmp(a.proto, b.proto) || a.port - b.port;

// ---------------------------------------------------------------------------
// End-of-life matching against the endoflife.date mirror
// ---------------------------------------------------------------------------
// Product names as banners / nmap -sV report them -> endoflife.date slug. minSeg = the number of
// version segments a cycle must match (e.g. Jenkins LTS cycles are "2.xxx").
export const EOL_PRODUCTS = [
  { re: /^apache( httpd)?$/i, slug: "apache-http-server", label: "Apache httpd" },
  { re: /^nginx$/i, slug: "nginx", label: "nginx" },
  { re: /^mysql$/i, slug: "mysql", label: "MySQL" },
  { re: /^mariadb$/i, slug: "mariadb", label: "MariaDB" },
  { re: /^postgresql( db)?$/i, slug: "postgresql", label: "PostgreSQL" },
  { re: /^redis( key-value store)?$/i, slug: "redis", label: "Redis" },
  { re: /^mongodb$/i, slug: "mongodb", label: "MongoDB" },
  { re: /^elasticsearch( rest api)?$/i, slug: "elasticsearch", label: "Elasticsearch" },
  { re: /^kibana$/i, slug: "kibana", label: "Kibana" },
  { re: /^apache tomcat( \/ coyote jsp engine)?$|^tomcat$/i, slug: "tomcat", label: "Apache Tomcat" },
  { re: /^jenkins$/i, slug: "jenkins", label: "Jenkins", minSeg: 2 },
  { re: /^isc bind$/i, slug: "bind-9", label: "ISC BIND" },
  { re: /^exim smtpd$/i, slug: "exim", label: "Exim" },
  { re: /^samba smbd$/i, slug: "samba", label: "Samba" },
  { re: /^vmware esxi/i, slug: "esxi", label: "VMware ESXi" },
  { re: /^vmware vcenter/i, slug: "vcenter", label: "VMware vCenter" },
  { re: /^node\.?js$/i, slug: "nodejs", label: "Node.js" },
  { re: /^grafana$/i, slug: "grafana", label: "Grafana" },
  { re: /^rabbitmq$/i, slug: "rabbitmq", label: "RabbitMQ" },
  { re: /^microsoft sql server/i, slug: "mssqlserver", label: "Microsoft SQL Server" },
  { re: /^openssl$/i, slug: "openssl", label: "OpenSSL" },
  { re: /^php$/i, slug: "php", label: "PHP" },
  { re: /^python$/i, slug: "python", label: "Python" },
  { re: /^haproxy$/i, slug: "haproxy", label: "HAProxy" },
];
// Microsoft IIS ships with one Windows Server release; 10.0 spans 2016-2025 and is not mapped.
const IIS_TO_WINDOWS = { "6.0": "2003-sp2", "7.0": "2008-sp2", "7.5": "2008-r2-sp1", "8.0": "2012", "8.5": "2012-r2" };
// Exchange build major.minor -> release.
const EXCHANGE_BUILD = { "8": "2007", "14": "2010", "15.0": "2013", "15.1": "2016", "15.2": "2019" };
// Upstream OpenSSH version shipped in each Ubuntu LTS release (distro packages keep the upstream number).
const UBUNTU_OPENSSH = { "6.6.1p1": "14.04", "7.2p2": "16.04", "7.6p1": "18.04", "8.2p1": "20.04", "8.9p1": "22.04", "9.6p1": "24.04" };
// Apache httpd version shipped by RHEL / CentOS majors.
const EL_HTTPD = { "2.2.15": "6", "2.4.6": "7", "2.4.37": "8", "2.4.57": "9" };

const verSegs = (v) => { const m = String(v || "").match(/^\d+(?:\.\d+)*/); return m ? m[0].split(".").map(Number) : null; };
/** -1 / 0 / 1, or null when either side has no leading number. Suffixes like "p1" compare after numbers. */
export function compareVersions(a, b) {
  const x = String(a || "").match(/\d+|[a-z]+/gi), y = String(b || "").match(/\d+|[a-z]+/gi);
  if (!x || !y || !/^\d/.test(x[0]) || !/^\d/.test(y[0])) return null;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i], q = y[i];
    if (p == null) return -1; if (q == null) return 1;
    const pn = /^\d+$/.test(p), qn = /^\d+$/.test(q);
    if (pn && qn) { if (+p !== +q) return +p < +q ? -1 : 1; continue; }
    if (pn !== qn) return pn ? 1 : -1;
    if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}
/** Find the release cycle of `version` in a feed product entry (longest numeric prefix match). */
export function findCycle(entry, version, minSeg = 1) {
  if (!entry || !Array.isArray(entry.cycles)) return null;
  const vs = verSegs(version);
  if (!vs) return null;
  let best = null, bestLen = 0;
  for (const c of entry.cycles) {
    const cy = String(c.cycle);
    if (!/^\d+(\.\d+)*$/.test(cy)) continue;
    const cs = cy.split(".").map(Number);
    if (cs.length > vs.length || cs.length < minSeg) continue;
    if (cs.every((n, i) => n === vs[i]) && cs.length > bestLen) { best = c; bestLen = cs.length; }
  }
  return best;
}
function cycleStatus(c, nowMs, warnDays) {
  const ext = c.extendedSupport;
  const extActive = ext === true || (typeof ext === "string" && Date.parse(ext + "T00:00:00Z") > nowMs);
  if (c.eol === true) return { status: "eol", date: "", extActive, ext };
  if (c.eol === false || c.eol == null) return { status: "supported", date: "", extActive, ext };
  const t = Date.parse(String(c.eol) + "T00:00:00Z");
  if (!Number.isFinite(t)) return { status: "unknown", date: String(c.eol), extActive, ext };
  if (t <= nowMs) return { status: "eol", date: String(c.eol), extActive, ext };
  if (t - nowMs <= warnDays * DAY) return { status: "approaching", date: String(c.eol), extActive, ext };
  return { status: "supported", date: String(c.eol), extActive, ext };
}
function windowsCycle(osText) {
  const m = String(osText || "").match(/Windows Server (\d{4})( R2)?/i);
  if (!m) return null;
  const y = m[1], r2 = !!m[2];
  const map = { 2003: "2003-sp2", 2008: r2 ? "2008-r2-sp1" : "2008-sp2", 2012: r2 ? "2012-r2" : "2012", 2016: "2016", 2019: "2019", 2022: "2022", 2025: "2025" };
  return map[y] || null;
}
/** EOL candidates seen on one port record: [{ slug, product, version, cycle?, source, confidence }]. */
export function eolCandidates(rec) {
  const out = [];
  const add = (slug, product, version, source, extra) => out.push({ slug, product, version, source, confidence: "likely", ...(extra || {}) });
  const prod = String(rec.product || "").trim(), ver = String(rec.version || "").trim(), extra = String(rec.extrainfo || "");
  // OpenSSH is not tracked by endoflife.date; the distro suffix pins the OS release that ships it.
  const ssh = /openssh/i.test(prod) ? { product: "OpenSSH", version: ver } : parseSshBanner(rec.banners.ssh);
  if (ssh && /openssh/i.test(ssh.product)) {
    const deb = String(ssh.version).match(/deb(\d+)u\d+/i);
    const up = (String(ssh.version).match(/^[\d.]+p\d+/) || [])[0];
    if (deb) add("debian", "OpenSSH " + ssh.version, deb[1], "OpenSSH package suffix +deb" + deb[1], { cycle: deb[1], os: "Debian " + deb[1] });
    else if (/ubuntu/i.test(ssh.version + " " + extra) && up && UBUNTU_OPENSSH[up]) add("ubuntu", "OpenSSH " + ssh.version, UBUNTU_OPENSSH[up], "Ubuntu ships OpenSSH " + up + " in " + UBUNTU_OPENSSH[up], { cycle: UBUNTU_OPENSSH[up], os: "Ubuntu " + UBUNTU_OPENSSH[up] });
  }
  if (/^Microsoft IIS/i.test(prod)) { const w = IIS_TO_WINDOWS[(ver.match(/^\d+\.\d+/) || [])[0]]; if (w) add("windows-server", "Microsoft IIS " + ver, w, "IIS " + ver + " ships only with Windows Server " + w, { cycle: w }); }
  if (/^Microsoft Exchange/i.test(prod)) { const s = verSegs(ver); if (s) { const k = s[0] === 15 ? "15." + s[1] : String(s[0]); if (EXCHANGE_BUILD[k]) add("msexchange", prod + " " + ver, EXCHANGE_BUILD[k], "Exchange build " + k, { cycle: EXCHANGE_BUILD[k] }); } }
  let pv = ver, pp = prod;
  const maria = ver.match(/^[\d.]+-([\d.]+)-MariaDB/i);
  if (/^mysql$/i.test(prod) && maria) { pp = "MariaDB"; pv = maria[1]; }
  const pyx = (extra.match(/Python ([\d.]+)/) || [])[1];
  if (pyx) add("python", "Python " + pyx, pyx, "service extrainfo");
  if (pp) for (const p of EOL_PRODUCTS) if (p.re.test(pp) && verSegs(pv)) { add(p.slug, p.label + " " + pv, (pv.match(/^\d+(?:\.\d+)*[a-z]?/i) || [])[0], "service version", { minSeg: p.minSeg || 1 }); break; }
  // Server / X-Powered-By headers
  const hdrs = [rec.banners.server, rec.banners.poweredBy].filter(Boolean).join(" ");
  if (hdrs) {
    const { parts, comments } = parseServerHeader(hdrs);
    for (const p of parts) {
      if (!p.version || !verSegs(p.version)) continue;
      const n = p.name.toLowerCase();
      if (n === "apache") { if (!out.some((o) => o.slug === "apache-http-server")) add("apache-http-server", "Apache/" + p.version, p.version, "Server header"); const el = EL_HTTPD[p.version]; const dist = comments.find((c) => /centos|red hat/i.test(c)); if (el && dist) add(/centos/i.test(dist) ? "centos" : "rhel", "Apache/" + p.version + " (" + dist + ")", el, "httpd " + p.version + " is the " + dist + " " + el + " package", { cycle: el }); }
      else if (n === "nginx" && !out.some((o) => o.slug === "nginx")) add("nginx", "nginx/" + p.version, p.version, "Server header");
      else if (n === "php") add("php", "PHP/" + p.version, p.version, "X-Powered-By / Server header");
      else if (n === "openssl") add("openssl", "OpenSSL/" + p.version, p.version, "Server header");
      else if (n === "microsoft-iis") { const w = IIS_TO_WINDOWS[(p.version.match(/^\d+\.\d+/) || [])[0]]; if (w && !out.some((o) => o.slug === "windows-server")) add("windows-server", "Microsoft-IIS/" + p.version, w, "IIS " + p.version + " ships only with Windows Server " + w, { cycle: w }); }
    }
  }
  // de-duplicate by slug + version
  const seen = new Set();
  return out.filter((o) => { const k = o.slug + "|" + (o.cycle || o.version); if (seen.has(k)) return false; seen.add(k); return true; });
}

// ---------------------------------------------------------------------------
// Allow-list and settings
// ---------------------------------------------------------------------------
/** "203.0.113.5:443/tcp reason", "*:22 bastion", "10.0.0.0/8:445 file servers", "[2001:db8::1]:443 web". */
export function parseAllowList(text) {
  const out = [];
  for (const raw of String(text || "").split(/\r?\n/)) {
    const l = raw.trim();
    if (!l || l.startsWith("#")) continue;
    const sp = l.search(/\s/);
    const spec = sp < 0 ? l : l.slice(0, sp), reason = sp < 0 ? "" : l.slice(sp + 1).replace(/^[-:]\s*/, "").trim();
    let host = spec, port = "*", proto = "";
    const v6 = spec.match(/^\[([^\]]+)\](?::(.+))?$/);
    if (v6) { host = v6[1]; port = v6[2] || "*"; }
    else if ((spec.match(/:/g) || []).length === 1) { [host, port] = spec.split(":"); }
    const pm = String(port).match(/^([^/]+)(?:\/(tcp|udp))?$/i);
    if (pm) { port = pm[1]; proto = (pm[2] || "").toLowerCase(); }
    const ports = port === "*" ? null : parsePortSpec(port, "tcp");
    if (port !== "*" && !ports) continue;
    const tgt = host === "*" ? null : parseTargetTok(host);
    if (host !== "*" && (!tgt || tgt.kind === "name")) continue;
    out.push({ spec, host, port, proto, ranges: ports ? ports.tcp : null, tgt, reason: reason || "(no reason given)" });
  }
  return out;
}
function allowFor(list, ip, port, proto) {
  return list.find((a) => (!a.tgt || targetHas(a.tgt, ip)) && (!a.ranges || inRanges(a.ranges, port)) && (!a.proto || a.proto === proto)) || null;
}
function cidrList(text) {
  const toks = Array.isArray(text) ? text : String(text || "").split(/[\s,]+/).filter(Boolean);
  const valid = toks.filter((t) => parseCidr(t));
  return valid.length ? valid : DEFAULT_INTERNAL.slice();
}

// ---------------------------------------------------------------------------
// Rule matching
// ---------------------------------------------------------------------------
/** Risk rules matching one open port record (superseded rules removed). */
export function matchRules(rec) {
  const hits = [];
  const svc = String(rec.service || "").toLowerCase();
  const guess = rec.serviceGuess || GENERIC_SVC.test(svc);
  const title = rec.banners.title || "", product = [rec.product, rec.banners.server].filter(Boolean).join(" ");
  for (const r of RULES) {
    if (r.proto !== "any" && r.proto !== rec.proto) continue;
    let ok = false;
    if (r.script) ok = rec.scriptFindings.some((f) => f.key === r.script);
    else {
      if (r.svc && svc && !GENERIC_SVC.test(svc) && r.svc.test(svc) && (!rec.serviceGuess || r.ports.includes(rec.port))) ok = true;
      if (!ok && r.ports.includes(rec.port) && (guess || (r.svc && r.svc.test(svc)) || (!r.svc && !r.title && !r.product))) ok = true;
      if (!ok && r.ports.includes(rec.port) && !r.svc && (r.title || r.product) && guess) ok = true;
      if (!ok && r.product && product && r.product.test(product)) ok = true;
      if (!ok && r.title && title && r.title.test(title)) ok = true;
    }
    if (ok) hits.push(r);
  }
  return hits.filter((r) => !hits.some((o) => r.supersededBy === o.id));
}

// ---------------------------------------------------------------------------
// Segmentation check against a Firewall Rule Audit export
// ---------------------------------------------------------------------------
function fwAddr(text) {
  const t = String(text || "").trim();
  if (/^any$/i.test(t)) return { any: true, ranges: [], unresolved: false };
  if (/^NOT /i.test(t)) return { any: false, ranges: [], unresolved: true };
  const ranges = [];
  let unresolved = false;
  for (const tok of t.split(/,\s*/)) {
    if (/^any$/i.test(tok)) return { any: true, ranges: [], unresolved: false };
    const rg = tok.match(/^([\d.]+)-([\d.]+)$/);
    if (rg) { const a = ipToInt(rg[1]), b = ipToInt(rg[2]); if (a && b) { ranges.push({ lo: a, hi: b }); continue; } }
    const c = parseCidr(tok);
    if (c) { ranges.push({ cidr: c }); continue; }
    unresolved = true;
  }
  return { any: false, ranges, unresolved };
}
function fwAddrHas(a, ip) {
  if (a.any) return true;
  const p = ipToInt(ip);
  if (!p) return false;
  return a.ranges.some((r) => (r.cidr ? r.cidr.v === p.v && (p.n & r.cidr.mask) === r.cidr.net : r.lo.v === p.v && p.n >= r.lo.n && p.n <= r.hi.n));
}
function fwAddrAllInternal(a, cidrs) {
  if (a.any || a.unresolved || !a.ranges.length) return false;
  return a.ranges.every((r) => (r.cidr ? cidrs.some((c) => c.v === r.cidr.v && (r.cidr.net & c.mask) === c.net && r.cidr.mask >= c.mask) : false));
}
function fwPorts(text) {
  const t = String(text || "").trim();
  if (/^any$/i.test(t)) return { any: true, ranges: [], unresolved: false };
  const ranges = [];
  let unresolved = false;
  for (const tok of t.split(/,\s*/)) { const m = tok.match(/^(\d+)(?:-(\d+))?$/); if (m) ranges.push([+m[1], +(m[2] || m[1])]); else unresolved = true; }
  return { any: false, ranges, unresolved };
}
const fwProtoCovers = (rp, p) => { const r = String(rp || "any").toLowerCase(); return r === "any" || r === "ip" || r === p || (r === "tcp/udp" && (p === "tcp" || p === "udp")); };
/**
 * First-match decision for "an external source reaches ip:port/proto" in each scope of the rule base.
 * Returns { decision: "deny"|"allow"|null, rule, scope, reason }. Conservative: any rule that could
 * match but cannot be evaluated (unresolved objects, extra matchers, partial sources) makes the
 * scope undecided, and only explicit deny rules (named destination and named ports) count.
 */
export function fwDecide(fw, ip, port, proto, cidrs) {
  const scopes = new Map();
  for (const r of fw.rules) { if (!scopes.has(r.scope)) scopes.set(r.scope, []); scopes.get(r.scope).push(r); }
  const results = [];
  for (const [scope, rules] of [...scopes].sort((a, b) => cmp(a[0], b[0]))) {
    let res = { scope, decision: null, rule: null, reason: "no rule matched (default policy not evaluated)" };
    for (const r of rules) {
      if (!r.enabled || !/^(allow|deny|reject)$/.test(r.action) || r.direction === "out") continue;
      if (r.state && !/new/i.test(r.state)) continue;
      if (!fwProtoCovers(r.proto, proto)) continue;
      const dst = fwAddr(r.dst), dp = fwPorts(r.dstPorts), src = fwAddr(r.src);
      const dstHit = fwAddrHas(dst, ip), portHit = dp.any || inRanges(dp.ranges, port);
      if ((!dstHit && dst.unresolved) || (!portHit && dp.unresolved)) { res = { scope, decision: null, rule: r, reason: "rule " + r.idx + " uses objects that cannot be resolved" }; break; }
      if (!dstHit || !portHit) continue;
      if (fwAddrAllInternal(src, cidrs)) continue;
      if (!src.any || r.restricted) { res = { scope, decision: null, rule: r, reason: "rule " + r.idx + " matches only some sources or has extra matchers" }; break; }
      const explicit = !dst.any && !dp.any;
      res = { scope, decision: r.action === "allow" ? "allow" : explicit ? "deny" : null, rule: r, reason: r.action === "allow" ? "rule " + r.idx + " allows" : explicit ? "rule " + r.idx + " explicitly denies this destination and port" : "rule " + r.idx + " is a catch-all deny (not specific enough to conclude)" };
      break;
    }
    results.push(res);
  }
  const allow = results.find((r) => r.decision === "allow");
  const deny = results.find((r) => r.decision === "deny");
  return { decision: allow ? "allow" : deny ? "deny" : null, by: allow || deny || null, results };
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
function normFiles(dataset) {
  if (typeof dataset === "string") return [{ name: "input", text: dataset }];
  if (Array.isArray(dataset)) return dataset.filter((f) => f && typeof f.text === "string");
  if (dataset && Array.isArray(dataset.files)) return dataset.files.filter((f) => f && typeof f.text === "string");
  return [];
}
const hostKeyOrder = (scans) => scans.map((s) => s.id);
const vulnSev = (score) => (score == null ? "low" : score >= 9 ? "high" : score >= 7 ? "medium" : "low");

/**
 * analyze(files, opts, ctx)
 *   files: [{ name, text }] (or { files }) - every scan export plus an optional Firewall Rule Audit JSON
 *   opts:  DEFAULTS + { eol: <eol-products.json>, scans: { [fileName]: { label, order, external, ports } }, columns }
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  const files = normFiles(dataset).slice().sort((a, b) => cmp(String(a.name), String(b.name)));
  const skipped = [], findings = [];
  const cidrStrs = cidrList(o.internalCidrs), cidrs = compileCidrs(cidrStrs);
  const allow = parseAllowList(o.allowList);
  const scanOpts = o.scans || {};
  const fileMeta = [];
  let fw = null;

  // 1. parse every file
  const parsed = [];
  files.forEach((f, i) => {
    ctx?.progress?.(i, files.length, "parsing " + f.name);
    const { det, scan, fw: fwp, name } = parseOne(f, o, ctx);
    fileMeta.push({ name, format: det.format, label: det.label, confidence: det.confidence, records: scan ? [...scan.hosts.values()].reduce((n, h) => n + h.recs.size, 0) : fwp ? fwp.rules.length : 0, hosts: scan ? scan.hosts.size : 0, notes: scan ? scan.notes.slice() : [] });
    if (fwp) { if (fw) skipped.push({ check: "segmentation", reason: "more than one firewall export; using " + fw.name }); else fw = { ...fwp, name }; }
    else if (scan) parsed.push(scan);
    else skipped.push({ check: "parse", reason: name + ": not a recognised scan export" });
  });

  // 2. group into scans (files sharing a label are one scan) and order them
  const groups = new Map();
  for (const sc of parsed) {
    const so = scanOpts[sc.file] || {};
    const label = String(so.label || "").trim() || sc.file;
    if (!groups.has(label)) groups.set(label, { id: label, label, parts: [], order: null, external: null, ports: "" });
    const g = groups.get(label);
    g.parts.push(sc);
    if (so.order != null && so.order !== "" && Number.isFinite(Number(so.order))) g.order = g.order == null ? Number(so.order) : Math.min(g.order, Number(so.order));
    if (so.external != null) g.external = g.external || !!so.external;
    if (so.ports) g.ports = String(so.ports);
  }
  const scans = [];
  for (const g of groups.values()) {
    const base = g.parts[0];
    const s = { id: g.id, label: g.label, files: g.parts.map((p) => p.file).sort(cmp), scanner: uniq(g.parts.map((p) => p.scanner)).join(" + "), format: uniq(g.parts.map((p) => p.format)).join(" + "),
      timeMs: g.parts.reduce((m, p) => minT(m, p.timeMs), null), endMs: g.parts.reduce((m, p) => maxT(m, p.endMs), null), args: uniq(g.parts.map((p) => p.args)).join(" | "),
      hosts: new Map(), down: new Set(), targets: null, scanned: { tcp: null, udp: null }, scannedSource: base.scannedSource, notes: uniq(g.parts.flatMap((p) => p.notes)),
      external: g.external != null ? g.external : g.parts.every((p) => p.defaultExternal), userOrder: g.order };
    // targets: union when every part knows its scope
    if (g.parts.every((p) => p.targets)) s.targets = { list: g.parts.flatMap((p) => p.targets.list), excludes: [], names: g.parts.flatMap((p) => p.targets.names), text: g.parts.map((p) => p.targets.text).join(" | ") };
    for (const proto of ["tcp", "udp"]) if (g.parts.every((p) => p.scanned[proto])) s.scanned[proto] = g.parts.flatMap((p) => p.scanned[proto]);
    if (g.ports) { const ps = parsePortSpec(g.ports, "tcp"); if (ps) { s.scanned = { tcp: ps.tcp.length ? ps.tcp : s.scanned.tcp, udp: ps.udp.length ? ps.udp : s.scanned.udp }; s.scannedSource = "entered by you"; } }
    for (const p of g.parts) {
      for (const ip of p.down) s.down.add(ip);
      for (const [ip, h] of p.hosts) {
        const t = s.hosts.get(ip);
        if (!t) { s.hosts.set(ip, h); continue; }
        for (const hn of h.hostnames) addHostname(t, hn.name, hn.type);
        t.os = t.os || h.os; t.osAccuracy = t.osAccuracy || h.osAccuracy; t.smbOs = t.smbOs || h.smbOs; t.nessusOs = t.nessusOs || h.nessusOs; t.mac = t.mac || h.mac;
        Object.assign(t.hostScripts, h.hostScripts);
        for (const rec of h.recs.values()) putRec(t, rec);
      }
    }
    for (const ip of s.hosts.keys()) s.down.delete(ip);
    scans.push(s);
  }
  scans.sort((a, b) => (a.userOrder != null && b.userOrder != null ? a.userOrder - b.userOrder : 0) || ((a.timeMs ?? Infinity) - (b.timeMs ?? Infinity)) || cmp(a.id, b.id));
  scans.forEach((s, i) => { s.order = i; });
  const nowMs = Number.isFinite(Date.parse(o.now)) ? Date.parse(o.now) : scans.reduce((m, s) => maxT(m, maxT(s.timeMs, s.endMs)), null) ?? (o.eol && Date.parse(o.eol.updated)) ?? 0;
  if (!scans.length) skipped.push({ check: "all", reason: "no scan data in the input" });

  // Coverage helpers
  const hostInScope = (s, ip) => (s.hosts.has(ip) || s.down.has(ip) ? true : s.targets ? targetsHave(s.targets, ip) : null);
  const portScanned = (s, proto, port) => (s.scanned[proto] ? inRanges(s.scanned[proto], port) : null);
  const zoneOf = (s, ip) => (s.external || !isInternalIp(ip, cidrs) ? "external" : "internal");

  // 3. current state per (ip, proto, port): latest scan that saw the host and covered the port
  ctx?.progress?.(0, 1, "building inventory");
  const obs = new Map(); // key -> [{ s, rec }]
  for (const s of scans) for (const [ip, h] of s.hosts) for (const rec of h.recs.values()) {
    const k = ip + "|" + rec.proto + "|" + rec.port;
    if (!obs.has(k)) obs.set(k, []);
    obs.get(k).push({ s, rec, host: h });
  }
  const current = []; // { key, ip, rec, host, scan, zone, firstSeen, lastSeen }
  for (const [k, list] of obs) {
    const opens = list.filter((x) => x.rec.state === "open");
    if (!opens.length) continue;
    const [ip, proto, portS] = k.split("|"); const port = Number(portS);
    let latest = null;
    for (const s of scans) {
      const seen = list.find((x) => x.s === s);
      if (seen) { latest = { s, open: seen.rec.state === "open", item: seen }; continue; }
      if (s.hosts.has(ip) && portScanned(s, proto, port) === true) latest = { s, open: false, item: null };
      else if (s.down.has(ip) || (!s.hosts.has(ip) && hostInScope(s, ip) === true && latest && s.order > latest.s.order)) latest = { s, open: false, item: null, gone: true };
    }
    if (!latest || !latest.open) continue;
    const it = latest.item;
    current.push({ key: k, ip, port, proto, rec: it.rec, host: it.host, scan: latest.s, zone: zoneOf(latest.s, ip), firstSeen: opens[0].s, lastSeen: latest.s });
  }
  current.sort((a, b) => ipCmp(a.ip, b.ip) || recCmp(a, b));

  const issues = new Map(); // ip -> [{ sev, tag }]
  const addIssue = (ip, sev, tag) => { if (!issues.has(ip)) issues.set(ip, []); issues.get(ip).push({ sev, tag }); };
  const hostLabel = (c) => (c.host.hostnames[0] ? c.host.hostnames[0].name : c.ip);
  const assetFor = (c) => [{ type: "ASSET", name: hostLabel(c), data: { ip: c.ip, ports: [], os: hostOs(c.host) } }, { type: "IP", name: c.ip }];
  const evRow = (c, extra) => ({ ip: c.ip, hostname: hnames(c.host), port: c.port, proto: c.proto, zone: c.zone, service: c.rec.service, product: [c.rec.product, c.rec.version].filter(Boolean).join(" "), scan: c.scan.label, ...(extra || {}) });

  // 4. risky exposures
  const exposures = [];
  const ruleGroups = new Map(); // rule|zone -> { rule, zone, sev, rows, assets }
  for (const c of current) {
    const hits = matchRules(c.rec);
    const al = allowFor(allow, c.ip, c.port, c.proto);
    for (const r of hits.length ? hits : [null]) {
      const sev = r ? (c.zone === "external" ? r.ext : r.int) : null;
      exposures.push({ ip: c.ip, hostnames: hnames(c.host), zone: c.zone, port: c.port, proto: c.proto, service: c.rec.service + (c.rec.serviceGuess ? "?" : ""), product: c.rec.product, version: c.rec.version,
        tls: c.rec.tunnel === "ssl" || c.rec.tls.versions.length ? (c.rec.tls.versions.join(" ") || "yes") : "", certNotAfter: c.rec.tls.cert ? c.rec.tls.cert.notAfter.slice(0, 10) : "",
        rule: r ? r.id : "", ruleLabel: r ? r.label : "", severity: sev || "", allowListed: al ? al.reason : "", firstSeen: c.firstSeen.label, lastSeen: c.lastSeen.label, firstSeenTime: isoOf(c.firstSeen.timeMs) });
      if (!r || !sev || al) continue;
      if (c.zone === "internal" && !o.reportInternal) continue;
      const gk = r.id + "|" + c.zone;
      if (!ruleGroups.has(gk)) ruleGroups.set(gk, { rule: r, zone: c.zone, sev, items: [] });
      ruleGroups.get(gk).items.push(c);
      addIssue(c.ip, sev, r.label + (c.zone === "external" ? " (internet)" : ""));
    }
  }
  for (const g of [...ruleGroups.values()]) {
    const r = g.rule, ext = g.zone === "external", n = g.items.length;
    const hostsN = new Set(g.items.map((c) => c.ip)).size;
    findings.push({
      id: "exp-" + r.id + "-" + g.zone,
      title: r.label + (r.script ? "" : ext ? " exposed to the internet" : " reachable on internal networks") + (r.id === "vpn-portal" ? " (patch-watch list)" : ""),
      severity: g.sev, confidence: g.items.every((c) => !c.rec.serviceGuess) ? "confirmed" : "likely", category: ext ? "external exposure" : "internal exposure",
      description: r.why + " Seen on " + n + " port" + (n === 1 ? "" : "s") + " across " + hostsN + " host" + (hostsN === 1 ? "" : "s") + (ext ? " from an external vantage point (address outside the internal ranges, or the scan was marked as run from outside)." : " inside the internal ranges.") + (g.items.some((c) => c.rec.serviceGuess) ? " Some services are identified by port number only (no version detection), so confirm them." : ""),
      recommendation: r.fix, controls: r.controls,
      evidence: g.items.slice(0, 50).map((c) => evRow(c, { firstSeen: c.firstSeen.label, detail: r.script ? (c.rec.scriptFindings.find((f) => f.key === r.script) || {}).detail || "" : c.rec.banners.title || "" })),
      evidenceCount: n, assets: dedupeAssets(g.items.flatMap(assetFor)), tags: [g.zone, r.id],
    });
  }

  // 5. per-port configuration checks: TLS, certificates, SSH, SMB, RDP
  const certRows = [];
  const cfg = new Map(); // check -> { items, ... }
  const pushCfg = (check, c, extra, sev) => { if (!cfg.has(check)) cfg.set(check, { items: [], sev: "info" }); const g = cfg.get(check); g.items.push({ c, extra }); if (SEV_RANK[sev] > SEV_RANK[g.sev]) g.sev = sev; addIssue(c.ip, sev, CFG[check].tag); };
  const certWarnMs = Number(o.certWarnDays) * DAY;
  let anyTlsData = false, anySsh = false, anySmb = false;
  for (const c of current) {
    const ext = c.zone === "external", rec = c.rec;
    const v = rec.tls.versions;
    if (v.length) anyTlsData = true;
    if (v.includes("SSLv2") || v.includes("SSLv3")) pushCfg("tls-ssl", c, { versions: v.join(" ") }, "high");
    if (v.includes("TLSv1.0") || v.includes("TLSv1.1")) pushCfg("tls-legacy", c, { versions: v.join(" ") }, ext ? "medium" : "low");
    if (rec.tls.grade && /[C-F]/.test(rec.tls.grade)) pushCfg("tls-weak-ciphers", c, { grade: rec.tls.grade, ciphers: rec.tls.weakCiphers.slice(0, 6).map((w) => w.version + " " + w.cipher + " (" + w.grade + ")").join("; ") }, rec.tls.grade === "F" ? "high" : ext ? "medium" : "low");
    const cert = rec.tls.cert;
    if (cert) {
      anyTlsData = true;
      const daysLeft = cert.notAfterMs != null ? Math.floor((cert.notAfterMs - nowMs) / DAY) : null;
      const certIssues = [];
      const ce = { subject: cert.subjectCN || cert.subject, issuer: cert.issuerCN || cert.issuer, notAfter: cert.notAfter.slice(0, 10), daysLeft };
      if (daysLeft != null && cert.notAfterMs <= nowMs) { certIssues.push("expired"); pushCfg("cert-expired", c, ce, ext ? "high" : "medium"); }
      else if (daysLeft != null && cert.notAfterMs - nowMs <= certWarnMs) { certIssues.push("expires in " + daysLeft + " d"); pushCfg("cert-expiring", c, ce, ext ? "medium" : "low"); }
      if (cert.selfSigned) { certIssues.push("self-signed"); if (ext) pushCfg("cert-self-signed", c, ce, "medium"); }
      if (cert.keyBits && /^(rsa|dsa)$/.test(cert.keyType || "rsa") && cert.keyBits < Number(o.minRsaBits)) { certIssues.push(cert.keyType.toUpperCase() + " " + cert.keyBits + "-bit"); pushCfg("cert-weak-key", c, { ...ce, key: (cert.keyType || "rsa") + " " + cert.keyBits }, ext ? "high" : "medium"); }
      if (/md5|sha1(?!\d)|sha-1(?!\d)/i.test(cert.sigAlg) && !cert.selfSigned) { certIssues.push(cert.sigAlg); pushCfg("cert-sha1", c, { ...ce, sigAlg: cert.sigAlg }, /md5/i.test(cert.sigAlg) ? "high" : "medium"); }
      // hostname mismatch: only names the user scanned by (nmap "user" names, naabu host, Nessus target name)
      const names = c.host.hostnames.filter((h) => h.type === "user").map((h) => h.name);
      if (names.length) {
        const certNames = uniq([cert.subjectCN.toLowerCase(), ...cert.sans]);
        const bad = names.filter((n) => !certNames.some((cn) => cn === n || (cn.startsWith("*.") && n.endsWith(cn.slice(1)) && n.split(".").length === cn.split(".").length)));
        if (bad.length && certNames.length) { certIssues.push("name mismatch"); pushCfg("cert-mismatch", c, { ...ce, scannedAs: bad.join(" "), certNames: certNames.join(" ") }, ext ? "medium" : "low"); }
      }
      certRows.push({ ip: c.ip, port: c.port, hostnames: hnames(c.host), zone: c.zone, subject: cert.subjectCN || cert.subject, issuer: cert.issuerCN || cert.issuer, notBefore: cert.notBefore.slice(0, 10), notAfter: cert.notAfter.slice(0, 10), daysLeft, selfSigned: cert.selfSigned, sigAlg: cert.sigAlg, key: [cert.keyType, cert.keyBits].filter(Boolean).join(" "), sans: cert.sans.join(" "), sha1: cert.sha1, issues: certIssues.join(", "), scan: c.scan.label });
    }
    const sf = (k) => rec.scriptFindings.find((f) => f.key === k);
    if (rec.ssh) anySsh = true;
    if (sf("ssh-weak-algos")) pushCfg("ssh-weak", c, { algorithms: sf("ssh-weak-algos").detail }, ext ? "medium" : "low");
    if (sf("ssh-protocol-1")) pushCfg("ssh-v1", c, { detail: sf("ssh-protocol-1").detail }, "high");
    if (rec.scripts["smb-protocols"] || rec.scripts["smb2-security-mode"] || rec.scripts["smb-security-mode"] || rec.scripts["nessus-96982"] || sf("smbv1") || sf("smb-signing-not-required")) anySmb = true;
    if (sf("smbv1")) pushCfg("smbv1", c, { detail: sf("smbv1").detail }, ext ? "critical" : "high");
    if (sf("smb-signing-not-required")) pushCfg("smb-signing", c, { detail: sf("smb-signing-not-required").detail }, ext ? "high" : "medium");
    if (sf("rdp-no-nla")) pushCfg("rdp-nla", c, { detail: sf("rdp-no-nla").detail }, ext ? "high" : "medium");
    if (sf("rdp-weak-enc")) pushCfg("rdp-rc4", c, { detail: sf("rdp-weak-enc").detail }, "low");
  }
  for (const [check, g] of [...cfg].sort((a, b) => cmp(a[0], b[0]))) {
    const d = CFG[check], n = g.items.length, ext = g.items.filter((x) => x.c.zone === "external").length;
    findings.push({ id: "cfg-" + check, title: d.title, severity: g.sev, confidence: d.confidence, category: d.category,
      description: d.why + " " + n + " port" + (n === 1 ? "" : "s") + (ext ? " (" + ext + " external)" : "") + ".", recommendation: d.fix, controls: d.controls,
      evidence: g.items.slice(0, 50).map((x) => evRow(x.c, x.extra)), evidenceCount: n, assets: dedupeAssets(g.items.flatMap((x) => assetFor(x.c))), tags: [check] });
  }
  if (!anyTlsData) skipped.push({ check: "tls-and-certificates", reason: "no TLS data in the scans (nmap ssl-cert / ssl-enum-ciphers, Nessus 10863 / 56984 or Shodan ssl)" });
  if (!anySsh && current.some((c) => c.rec.service === "ssh")) skipped.push({ check: "ssh-algorithms", reason: "SSH found but no ssh2-enum-algos output; run nmap --script ssh2-enum-algos" });
  if (!anySmb && current.some((c) => c.port === 445)) skipped.push({ check: "smb-settings", reason: "SMB found but no smb-protocols / smb2-security-mode output (or Nessus 96982 / 57608)" });

  // 6. end of life
  const eolRows = [];
  const eolFeed = o.eol && Array.isArray(o.eol.data) ? o.eol : null;
  const eolBy = eolFeed ? Object.fromEntries(eolFeed.data.map((p) => [p.product, p])) : {};
  if (!eolFeed) skipped.push({ check: "end-of-life", reason: "end-of-life feed not loaded (/data/feeds/eol-products.json)" });
  else {
    const eolItems = [];
    const seenHostOs = new Set();
    const consider = (c, cand) => {
      const entry = eolBy[cand.slug];
      if (!entry) return;
      const cyc = cand.cycle ? entry.cycles.find((x) => String(x.cycle) === String(cand.cycle)) : findCycle(entry, cand.version, cand.minSeg || 1);
      if (!cyc) return;
      const st = cycleStatus(cyc, nowMs, Number(o.eolWarnDays));
      eolRows.push({ ip: c.ip, port: c.port, hostnames: hnames(c.host), zone: c.zone, product: cand.product, slug: cand.slug, cycle: String(cyc.cycle), eol: cyc.eol === true ? "yes (no date)" : cyc.eol === false ? "not set" : String(cyc.eol), status: st.status, extendedSupport: st.extActive ? (st.ext === true ? "available" : "until " + st.ext) : "", latest: cyc.latest || "", source: cand.source, confidence: cand.confidence, scan: c.scan.label });
      if (st.status === "eol" || st.status === "approaching") eolItems.push({ c, cand, cyc, st });
    };
    for (const c of current) for (const cand of eolCandidates(c.rec)) consider(c, cand);
    // host operating system (smb-os-discovery / Nessus) -> attach to the SMB port, or the host's first port
    for (const c of current) {
      if (seenHostOs.has(c.ip)) continue;
      const osText = c.host.smbOs || c.host.nessusOs;
      const w = windowsCycle(osText);
      if (!w) continue;
      const target = current.find((x) => x.ip === c.ip && x.port === 445) || c;
      seenHostOs.add(c.ip);
      consider(target, { slug: "windows-server", product: osText, version: w, cycle: w, source: c.host.smbOs ? "smb-os-discovery" : "Nessus operating-system", confidence: "likely" });
    }
    const eg = new Map();
    for (const x of eolItems) { const k = x.cand.slug + "|" + x.cyc.cycle + "|" + x.st.status; if (!eg.has(k)) eg.set(k, []); eg.get(k).push(x); }
    for (const [k, list] of [...eg].sort((a, b) => cmp(a[0], b[0]))) {
      const x0 = list[0], anyExt = list.some((x) => x.c.zone === "external"), eol = x0.st.status === "eol";
      let sev = eol ? (anyExt ? "high" : "medium") : "low";
      if (eol && x0.st.extActive) sev = down1(sev);
      const name = (eolBy[x0.cand.slug].product || x0.cand.slug) + " " + x0.cyc.cycle;
      for (const x of list) addIssue(x.c.ip, sev, "EOL " + name);
      findings.push({ id: "eol-" + k.replace(/\|/g, "-"), title: (eol ? "End-of-life software: " : "Approaching end of life: ") + name, severity: sev, confidence: "likely", category: "end of life",
        description: name + (eol ? " reached end of life" + (x0.st.date ? " on " + x0.st.date : "") : " reaches end of life on " + x0.st.date) + " (endoflife.date, mirrored " + String(eolFeed.updated || "").slice(0, 10) + "). Identified from " + uniq(list.map((x) => x.cand.source)).join("; ") + " on " + list.length + " port" + (list.length === 1 ? "" : "s") + "." + (x0.st.extActive ? " Extended (paid) support " + (x0.st.ext === true ? "is available" : "runs until " + x0.st.ext) + "; confirm whether you subscribe." : "") + " Banners can lag behind distribution back-ports, so treat the cycle as the signal, not the patch level.",
        recommendation: "Plan an upgrade to a supported release" + (x0.cyc.latest ? " (latest in this cycle: " + x0.cyc.latest + ")" : "") + "; until then restrict exposure and monitor advisories.",
        controls: [CTL.cis22, CTL.sa22, CTL.si2, CTL.pci633],
        evidence: list.slice(0, 50).map((x) => evRow(x.c, { identified: x.cand.product, cycle: String(x.cyc.cycle), eol: x.st.date || "yes", source: x.cand.source })), evidenceCount: list.length,
        assets: dedupeAssets(list.flatMap((x) => assetFor(x.c))), tags: ["eol", x0.cand.slug] });
    }
  }

  // 7. scanner-reported CVEs (nmap vulners / Shodan) - shown as reported, never re-scored
  const vulnRows = [];
  const vulnFindings = [];
  for (const c of current) {
    if (!c.rec.vulns.length) continue;
    const top = c.rec.vulns.reduce((m, v) => (v.score != null && (m == null || v.score > m) ? v.score : m), null);
    for (const v of c.rec.vulns) vulnRows.push({ ip: c.ip, port: c.port, cve: v.id, reportedScore: v.score, source: v.source, verified: v.verified ? "yes" : "" });
    const verified = c.rec.vulns.some((v) => v.verified);
    let sev = vulnSev(top);
    if (c.zone === "internal") sev = down1(sev);
    vulnFindings.push({ id: "cve-" + c.key, title: "Scanner-reported CVEs on " + c.ip + ":" + c.port + "/" + c.proto, severity: sev, confidence: verified ? "likely" : "review", category: "reported vulnerabilities",
      description: c.rec.vulns.length + " CVE" + (c.rec.vulns.length === 1 ? "" : "s") + " reported by " + uniq(c.rec.vulns.map((v) => v.source)).join(" and ") + " for " + ([c.rec.product, c.rec.version].filter(Boolean).join(" ") || c.rec.service) + (top != null ? " (highest score as reported: " + top + ")" : "") + ". These are matched from the version banner by the scanner, not verified exploits; back-ported fixes cause false positives. Import authenticated scan results in Vulnerability Import for the authoritative list.",
      recommendation: "Confirm the installed package version on the host, patch or upgrade, and re-scan.", controls: [CTL.si2, CTL.pci633, CTL.pci1131],
      evidence: c.rec.vulns.slice(0, 50).map((v) => ({ ip: c.ip, port: c.port, cve: v.id, reportedScore: v.score == null ? "" : v.score, source: v.source + " (reported by scanner)", verified: v.verified ? "yes" : "" })), evidenceCount: c.rec.vulns.length,
      assets: dedupeAssets([...assetFor(c), ...c.rec.vulns.slice(0, 40).map((v) => ({ type: "VULNERABILITY", name: v.id, data: { source: v.source + " (reported by scanner)", reportedScore: v.score } }))]), tags: ["reported-by-scanner"] });
    addIssue(c.ip, sev, c.rec.vulns.length + " reported CVEs");
  }
  findings.push(...vulnFindings);

  // 8. scan-to-scan diff (each scan against the latest earlier scan with overlapping scope)
  ctx?.progress?.(0, 1, "comparing scans");
  const changes = [];
  const diffs = [];
  const overlaps = (a, b) => [...b.hosts.keys()].some((ip) => a.hosts.has(ip) || hostInScope(a, ip) === true) || [...a.hosts.keys()].some((ip) => hostInScope(b, ip) === true);
  for (const cur of scans) {
    const prev = [...scans].filter((s) => s.order < cur.order && overlaps(s, cur)).pop();
    if (!prev) continue;
    const d = { from: prev.label, to: cur.label, fromOrder: prev.order, toOrder: cur.order, coverage: [] };
    diffs.push(d);
    const ch = (type, ip, extra, sev, conf) => changes.push({ fromScan: prev.label, toScan: cur.label, toOrder: cur.order, type, ip, port: "", proto: "", before: "", after: "", detail: "", zone: ip ? zoneOf(cur.hosts.has(ip) ? cur : prev, ip) : "", severity: sev, confidence: conf, ...(extra || {}) });
    const prevUp = [...prev.hosts.keys()].sort(ipCmp), curUp = [...cur.hosts.keys()].sort(ipCmp);
    let notRescannedHosts = 0;
    for (const ip of prevUp) {
      if (cur.hosts.has(ip)) continue;
      const sc = hostInScope(cur, ip);
      if (sc === true) ch("host-disappeared", ip, { before: openList(prev.hosts.get(ip)), detail: cur.down.has(ip) ? "host reported down" : "host in scope but did not respond" }, "info", cur.down.has(ip) ? "confirmed" : "likely");
      else if (sc === false) { notRescannedHosts++; ch("host-not-rescanned", ip, { before: openList(prev.hosts.get(ip)), detail: "outside the targets of " + cur.label }, "info", "confirmed"); }
      else ch("host-not-seen", ip, { before: openList(prev.hosts.get(ip)), detail: "scope of " + cur.label + " is unknown" }, "info", "review");
    }
    for (const ip of curUp) {
      if (prev.hosts.has(ip)) continue;
      const sc = hostInScope(prev, ip);
      const z = zoneOf(cur, ip);
      if (sc === false) ch("host-first-in-scope", ip, { after: openList(cur.hosts.get(ip)), detail: "outside the targets of " + prev.label }, "info", "confirmed");
      else ch("new-host", ip, { after: openList(cur.hosts.get(ip)), detail: sc === true ? (prev.down.has(ip) ? "was down in " + prev.label : "in scope of " + prev.label + " but not seen") : "scope of " + prev.label + " unknown" }, z === "external" ? "low" : "info", sc === true ? "likely" : "review");
    }
    for (const ip of curUp) {
      if (!prev.hosts.has(ip)) continue;
      const ph = prev.hosts.get(ip), chh = cur.hosts.get(ip);
      const keys = uniq([...ph.recs.keys(), ...chh.recs.keys()]);
      for (const k of keys) {
        const a = ph.recs.get(k), b = chh.recs.get(k);
        const [proto, portS] = k.split("/"); const port = Number(portS);
        const aOpen = a && a.state === "open", bOpen = b && b.state === "open";
        const z = zoneOf(cur, ip);
        if (bOpen && !aOpen) {
          const scanned = a ? true : portScanned(prev, proto, port);
          const hits = matchRules(b), risky = hits.find((r) => (z === "external" ? r.ext : r.int));
          const rsev = risky ? (z === "external" ? risky.ext : risky.int) : null;
          const al = allowFor(allow, ip, port, proto);
          if (scanned === false) { ch("port-first-observed", ip, { port, proto, after: svcText(b), detail: "port was not in the scan range of " + prev.label }, "info", "confirmed"); continue; }
          let sev = risky ? (z === "external" ? (SEV_RANK[rsev] >= SEV_RANK.high ? rsev : "high") : (SEV_RANK[rsev] >= SEV_RANK.medium ? "medium" : "low")) : z === "external" ? "low" : "info";
          if (al) sev = "info";
          ch("port-opened", ip, { port, proto, before: a ? a.state : "not open", after: svcText(b), detail: (risky ? "risky: " + risky.label : "") + (al ? (risky ? "; " : "") + "allow-listed: " + al.reason : "") + (scanned === null ? (risky || al ? "; " : "") + "port coverage of " + prev.label + " unknown" : ""), risky: risky ? risky.id : "" }, sev, a ? "confirmed" : scanned === true ? "likely" : "review");
        } else if (aOpen && !bOpen) {
          const scanned = b ? true : portScanned(cur, proto, port);
          if (scanned === false) { ch("port-not-rescanned", ip, { port, proto, before: svcText(a), detail: "port was not in the scan range of " + cur.label }, "info", "confirmed"); continue; }
          ch(scanned === null ? "port-not-seen" : "port-closed", ip, { port, proto, before: svcText(a), after: b ? b.state : "not open", detail: scanned === null ? "port coverage of " + cur.label + " unknown; not reported as closed" : "" }, "info", b ? "confirmed" : scanned === true ? "likely" : "review");
        } else if (aOpen && bOpen) {
          const pa = [a.product, a.version].filter(Boolean).join(" "), pb = [b.product, b.version].filter(Boolean).join(" ");
          if (pa && pb && pa !== pb) {
            const same = a.product === b.product, cv = same ? compareVersions(a.version, b.version) : null;
            const type = cv === -1 ? "version-upgrade" : cv === 1 ? "version-downgrade" : same ? "version-change" : "service-change";
            ch(type, ip, { port, proto, before: pa, after: pb }, type === "version-downgrade" ? "medium" : type === "service-change" ? "low" : "info", "likely");
          }
          const ca = a.tls.cert, cb = b.tls.cert;
          if (ca && cb && (ca.sha1 && cb.sha1 ? ca.sha1 !== cb.sha1 : ca.notAfter !== cb.notAfter || ca.subject !== cb.subject)) ch("certificate-changed", ip, { port, proto, before: (ca.subjectCN || ca.subject) + " until " + ca.notAfter.slice(0, 10), after: (cb.subjectCN || cb.subject) + " until " + cb.notAfter.slice(0, 10), detail: cb.selfSigned ? "new certificate is self-signed" : "" }, cb.selfSigned && z === "external" ? "low" : "info", "confirmed");
          else if (!ca && cb) ch("certificate-new", ip, { port, proto, after: (cb.subjectCN || cb.subject) + " until " + cb.notAfter.slice(0, 10) }, "info", "likely");
        }
      }
    }
    // coverage
    for (const proto of ["tcp", "udp"]) {
      const pa = prev.scanned[proto], pb = cur.scanned[proto];
      if (pa && pb && portCount(pb) < portCount(pa)) d.coverage.push(proto.toUpperCase() + " ports scanned dropped from " + portCount(pa) + " to " + portCount(pb));
      else if (pa && !pb && (proto === "tcp" || pa.length)) d.coverage.push(proto.toUpperCase() + " port list of " + cur.label + " is unknown (" + prev.label + " scanned " + portCount(pa) + ")");
    }
    if (notRescannedHosts) d.coverage.push(notRescannedHosts + " host(s) from " + prev.label + " were outside the targets of " + cur.label);
    if (prev.hosts.size && cur.hosts.size < prev.hosts.size * 0.8 && hostInScope(cur, prevUp[0]) !== false) d.coverage.push("hosts up fell from " + prev.hosts.size + " to " + cur.hosts.size);
    if (d.coverage.length) ch("coverage-reduced", "", { detail: d.coverage.join("; ") }, "low", "review");
  }
  changes.sort((a, b) => a.toOrder - b.toOrder || cmp(a.type, b.type) || ipCmp(a.ip || "0.0.0.0", b.ip || "0.0.0.0") || (Number(a.port) || 0) - (Number(b.port) || 0));
  // findings only from each scan's comparison with its predecessor where that scan is the newest of its scope
  const latestTo = new Set(scans.filter((s) => !diffs.some((d) => d.fromOrder === s.order)).map((s) => s.label));
  const recent = changes.filter((c) => latestTo.has(c.toScan));
  const chGroups = [
    ["port-opened", (c) => c.risky && SEV_RANK[c.severity] >= SEV_RANK.medium, "Risky service newly opened since the previous scan", "A port matching the risk table was not open in the previous scan of the same scope and is open now. New exposure is most dangerous the day it appears.", "Confirm the change was approved; if not, close it or restrict the source addresses today, and find out who changed the firewall or host.", [CTL.cis44, CTL.cis134, CTL.pci125, CTL.pci1132, CTL.cm7, CTL.sc7, att("T1190"), att("T1133")]],
    ["port-opened", (c) => !(c.risky && SEV_RANK[c.severity] >= SEV_RANK.medium), "New open ports since the previous scan", "Ports open now that were scanned and not open in the previous scan of the same scope.", "Check each against your approved services list (PCI DSS 1.2.5); close what is not needed.", [CTL.cis11, CTL.cis48, CTL.pci125, CTL.cm7, CTL.cm8]],
    ["new-host", () => true, "New hosts since the previous scan", "Hosts that responded now but not in the previous scan of the same scope.", "Make sure each new host is in the asset inventory and has an owner.", [CTL.cis11, CTL.cm8]],
    ["version-downgrade", () => true, "Service version downgraded", "A service reports an older version than in the previous scan; this can mean a rollback, a rebuilt host from an old image, or a different device answering on the address.", "Confirm why the version went backwards and re-apply missing patches.", [CTL.si2, CTL.cm8, CTL.pci633]],
    ["coverage-reduced", () => true, "Scan coverage reduced", "The newer scan covered fewer hosts or ports than the one before it, so missing services are not reported as closed.", "Re-run the scan with the same targets and port range, or enter the port range in the scans panel when the tool did not record it.", [CTL.pci1131, CTL.pci1132, CTL.cm8]],
  ];
  for (const [type, pred, title, why, fix, controls] of chGroups) {
    const list = recent.filter((c) => c.type === type && pred(c));
    if (!list.length) continue;
    const sev = list.reduce((m, c) => (SEV_RANK[c.severity] > SEV_RANK[m] ? c.severity : m), "info");
    if (sev === "info" && type !== "coverage-reduced" && type !== "new-host") continue;
    findings.push({ id: "chg-" + type + (title.startsWith("Risky") ? "-risky" : ""), title, severity: sev, confidence: list.every((c) => c.confidence === "confirmed") ? "confirmed" : list.some((c) => c.confidence !== "review") ? "likely" : "review", category: "change",
      description: why + " " + list.length + " change" + (list.length === 1 ? "" : "s") + " between " + uniq(list.map((c) => c.fromScan + " and " + c.toScan)).join(", ") + ".", recommendation: fix, controls,
      evidence: list.slice(0, 50).map((c) => ({ ip: c.ip, port: c.port, proto: c.proto, zone: c.zone, before: c.before, after: c.after, detail: c.detail, from: c.fromScan, to: c.toScan, confidence: c.confidence })), evidenceCount: list.length,
      assets: dedupeAssets(list.filter((c) => c.ip).flatMap((c) => [{ type: "IP", name: c.ip }])), tags: ["change"] });
    for (const c of list) if (c.ip && SEV_RANK[c.severity] >= SEV_RANK.low) addIssue(c.ip, c.severity, "new: " + (c.port ? c.port + "/" + c.proto : "host"));
  }
  if (scans.length < 2) skipped.push({ check: "scan-diff", reason: scans.length ? "only one scan loaded; load an earlier scan of the same scope to see changes" : "no scans" });
  else if (!diffs.length) skipped.push({ check: "scan-diff", reason: "no two scans share hosts or targets, so there is nothing to compare" });

  // 9. segmentation check against the Firewall Rule Audit export
  const segRows = [];
  if (!fw) skipped.push({ check: "segmentation", reason: "no Firewall Rule Audit JSON export loaded (optional)" });
  else {
    const extCurrent = current.filter((c) => c.scan.external);
    if (!extCurrent.length) skipped.push({ check: "segmentation", reason: "needs a scan marked as run from outside (scanned from outside); internal scans do not traverse the documented perimeter" });
    else {
      for (const c of extCurrent) {
        const dcs = fwDecide(fw, c.ip, c.port, c.proto, cidrs);
        if (dcs.decision === "deny") segRows.push({ c, rule: dcs.by.rule, scope: dcs.by.scope, reason: dcs.by.reason });
      }
      if (segRows.length) {
        findings.push({ id: "seg-drift", title: "Service open although the documented rule base denies it", severity: "high", confidence: "review", category: "segmentation",
          description: segRows.length + " service(s) answered an external scan although the first matching rule in " + fw.name + " explicitly denies that destination and port. Either the rule is not deployed on the path the scan took, NAT maps the address elsewhere, or the documentation is stale. Only explicit denies (named destination and port, any source, no extra matchers) are used; everything else is left undecided.",
          recommendation: "Compare the running firewall configuration with the exported rule base, confirm the scan path, and close the service or correct the documentation.",
          controls: [CTL.cis44, CTL.cis134, CTL.pci141, CTL.pci142, CTL.sc7],
          evidence: segRows.slice(0, 50).map((x) => evRow(x.c, { rule: "#" + x.rule.idx + (x.rule.name ? " " + x.rule.name : ""), scope: x.scope, ruleText: x.rule.action + " " + x.rule.proto + " " + x.rule.src + " -> " + x.rule.dst + " " + x.rule.dstPorts })), evidenceCount: segRows.length,
          assets: dedupeAssets(segRows.flatMap((x) => assetFor(x.c))), tags: ["segmentation"] });
        for (const x of segRows) addIssue(x.c.ip, "high", "open despite deny rule");
      }
    }
  }

  // 10. tables
  ctx?.progress?.(1, 1, "summarising");
  const hostRows = [];
  const byIp = new Map();
  for (const c of current) { if (!byIp.has(c.ip)) byIp.set(c.ip, []); byIp.get(c.ip).push(c); }
  const allIps = uniq([...byIp.keys(), ...scans.flatMap((s) => [...s.hosts.keys()])]).sort(ipCmp);
  for (const ip of allIps) {
    const list = byIp.get(ip) || [];
    const latestScan = [...scans].reverse().find((s) => s.hosts.has(ip));
    const h = list.length ? list[list.length - 1].host : latestScan.hosts.get(ip);
    const iss = issues.get(ip) || [];
    const score = Math.min(100, iss.reduce((n, x) => n + SEV_WEIGHT[x.sev], 0));
    const zone = list.length ? list[0].zone : zoneOf(latestScan, ip);
    hostRows.push({ ip, hostnames: hnames(h), zone, openPorts: list.length, ports: list.map((c) => c.port + "/" + c.proto).join(" "), os: hostOs(h), riskScore: score, flags: uniq(iss.filter((x) => SEV_RANK[x.sev] >= SEV_RANK.low).map((x) => x.tag)).join("; "), lastScan: latestScan ? latestScan.label : "", current: list.length > 0 });
  }
  hostRows.sort((a, b) => b.riskScore - a.riskScore || ipCmp(a.ip, b.ip));
  // fill ASSET data.ports from the inventory
  const portsByIp = new Map(hostRows.map((h) => [h.ip, h.ports.split(" ").filter(Boolean)]));
  for (const f of findings) for (const a of f.assets || []) if (a.type === "ASSET" && a.data) a.data.ports = portsByIp.get(a.data.ip) || [];
  const svcMap = new Map();
  for (const c of current) {
    const k = c.port + "/" + c.proto + "|" + c.rec.service + "|" + c.rec.product + "|" + c.rec.version;
    if (!svcMap.has(k)) svcMap.set(k, { port: c.port, proto: c.proto, service: c.rec.service, product: c.rec.product, version: c.rec.version, hosts: 0, external: 0, ips: [] });
    const r = svcMap.get(k); r.hosts++; if (c.zone === "external") r.external++; r.ips.push(c.ip);
  }
  const serviceRows = [...svcMap.values()].map((r) => ({ ...r, ips: r.ips.slice(0, 50).join(" "), risk: (matchRules(current.find((c) => c.port === r.port && c.proto === r.proto && c.rec.service === r.service && c.rec.product === r.product && c.rec.version === r.version).rec)[0] || {}).label || "" }))
    .sort((a, b) => a.port - b.port || cmp(a.proto, b.proto) || cmp(a.service, b.service) || cmp(a.product, b.product) || cmp(a.version, b.version));
  const scanRows = scans.map((s) => ({ id: s.id, label: s.label, order: s.order + 1, files: s.files.join(", "), scanner: s.scanner, format: s.format, time: isoOf(s.timeMs), hostsUp: s.hosts.size, openPorts: [...s.hosts.values()].reduce((n, h) => n + [...h.recs.values()].filter((r) => r.state === "open").length, 0),
    portsScanned: s.scanned.tcp || s.scanned.udp ? [s.scanned.tcp ? "TCP " + portCount(s.scanned.tcp) : "", s.scanned.udp ? "UDP " + portCount(s.scanned.udp) : ""].filter(Boolean).join(", ") : "unknown", portsSource: s.scannedSource || "", targets: s.targets ? s.targets.text : "unknown", external: s.external, notes: s.notes.join("; "), args: s.args }));

  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(a.category || "", b.category || "") || cmp(a.title, b.title) || cmp(a.id || "", b.id || ""));
  const extRisky = exposures.filter((e) => e.zone === "external" && e.severity && e.severity !== "info" && !e.allowListed);
  const newSince = recent.filter((c) => c.type === "port-opened" || c.type === "new-host").length;
  const summary = {
    scans: scans.length, hosts: byIp.size, hostsSeen: allIps.length, openPorts: current.length, externalPorts: current.filter((c) => c.zone === "external").length,
    riskyExternal: extRisky.length, riskyInternal: exposures.filter((e) => e.zone === "internal" && e.severity && e.severity !== "info" && !e.allowListed).length, allowListed: exposures.filter((e) => e.allowListed).length,
    eolServices: eolRows.filter((r) => r.status === "eol").length, eolApproaching: eolRows.filter((r) => r.status === "approaching").length,
    certIssues: certRows.filter((r) => r.issues).length, certificates: certRows.length, reportedCves: uniq(vulnRows.map((v) => v.cve)).length,
    newSinceLast: newSince, changes: changes.length, findings: findings.length, bySeverity: countBy(findings, "severity"), referenceDate: isoOf(nowMs), eolFeedUpdated: eolFeed ? String(eolFeed.updated || "") : "",
    internalCidrs: cidrStrs,
  };
  return {
    summary, findings,
    tables: { hosts: hostRows, services: serviceRows, exposures, certificates: certRows.sort((a, b) => (a.daysLeft ?? 1e9) - (b.daysLeft ?? 1e9) || ipCmp(a.ip, b.ip) || a.port - b.port), changes: changes.map(({ toOrder, ...c }) => c), eol: eolRows.sort((a, b) => cmp(a.status, b.status) || ipCmp(a.ip, b.ip) || a.port - b.port || cmp(a.slug, b.slug)), vulns: vulnRows.sort((a, b) => ipCmp(a.ip, b.ip) || a.port - b.port || cmp(a.cve, b.cve)), scans: scanRows, raw: rawRows(current), firewall: fw ? { name: fw.name, rules: fw.rules.length, denied: segRows.length } : null },
    skipped, meta: { tool: TOOL_ID, version: VERSION, files: fileMeta, rows: current.length, scanOrder: hostKeyOrder(scans), allowList: allow.map((a) => ({ spec: a.spec, reason: a.reason })) },
  };
}

function rawRows(current) {
  return current.map((c) => ({ ip: c.ip, port: c.port, proto: c.proto, state: c.rec.state, reason: c.rec.reason, service: c.rec.service, product: c.rec.product, version: c.rec.version, extrainfo: c.rec.extrainfo, cpe: c.rec.cpe.join(" "), banners: Object.fromEntries(Object.entries(c.rec.banners).filter(([, v]) => v)), scripts: c.rec.scripts, hostScripts: c.host.hostScripts, scan: c.scan.label }));
}
function hostOs(h) { return h.smbOs || h.nessusOs || (h.os ? h.os + (h.osAccuracy ? " (" + h.osAccuracy + "% match)" : "") : ""); }
const openList = (h) => (h ? [...h.recs.values()].filter((r) => r.state === "open").sort(recCmp).map((r) => r.port + "/" + r.proto).join(" ") : "");
const svcText = (r) => [r.port + "/" + r.proto, r.service, r.product, r.version].filter(Boolean).join(" ");
function dedupeAssets(list) {
  const m = new Map();
  for (const a of list) { const k = a.type + "|" + a.name; if (!m.has(k)) m.set(k, a); }
  return [...m.values()].sort((a, b) => cmp(a.type, b.type) || cmp(a.name, b.name)).slice(0, 60);
}
function countBy(items, key) {
  const out = {};
  for (const it of items) out[it[key]] = (out[it[key]] || 0) + 1;
  return out;
}

const CFG = {
  "tls-ssl": { tag: "SSLv2/v3", title: "SSLv2 or SSLv3 enabled", category: "tls", confidence: "confirmed", why: "SSL 2.0 and 3.0 are broken (DROWN, POODLE) and prohibited.", fix: "Disable SSLv2 and SSLv3 on the listener; allow TLS 1.2 and 1.3 only.", controls: [CTL.rfc7568, CTL.sp80052, CTL.pci421, CTL.sc8, CTL.sc13] },
  "tls-legacy": { tag: "TLS 1.0/1.1", title: "TLS 1.0 or 1.1 enabled", category: "tls", confidence: "confirmed", why: "TLS 1.0 and 1.1 are deprecated and not accepted for PCI or federal systems.", fix: "Disable TLS 1.0 and 1.1; keep TLS 1.2 with AEAD ciphers and TLS 1.3.", controls: [CTL.rfc8996, CTL.sp80052, CTL.pci421, CTL.sc8, CTL.sc13] },
  "tls-weak-ciphers": { tag: "weak ciphers", title: "Weak TLS cipher suites (ssl-enum-ciphers grade C or worse)", category: "tls", confidence: "confirmed", why: "nmap ssl-enum-ciphers graded at least one offered cipher suite C or worse (for example 3DES, RC4, export or anonymous suites, or small DH groups).", fix: "Remove the weak suites; prefer ECDHE with AES-GCM or ChaCha20-Poly1305.", controls: [CTL.sp80052, CTL.pci421, CTL.sc13] },
  "cert-expired": { tag: "cert expired", title: "Expired certificate", category: "certificate", confidence: "confirmed", why: "Clients reject or warn on expired certificates, which trains users to click through warnings.", fix: "Renew and deploy the certificate; automate renewal (ACME) and monitor expiry.", controls: [CTL.pci421, CTL.sc17, CTL.sc8] },
  "cert-expiring": { tag: "cert expiring", title: "Certificate expiring soon", category: "certificate", confidence: "confirmed", why: "The certificate expires within the warning window.", fix: "Renew before expiry; automate renewal (ACME) and monitor expiry.", controls: [CTL.pci421, CTL.sc17] },
  "cert-self-signed": { tag: "self-signed (internet)", title: "Self-signed certificate on an internet-facing service", category: "certificate", confidence: "confirmed", why: "Clients cannot authenticate a self-signed certificate, which enables interception and teaches users to accept warnings.", fix: "Issue a certificate from a publicly trusted CA (or your enterprise CA for managed clients only).", controls: [CTL.pci421, CTL.sc17] },
  "cert-weak-key": { tag: "weak cert key", title: "Certificate key below the minimum size", category: "certificate", confidence: "confirmed", why: "RSA/DSA keys under 2048 bits are disallowed.", fix: "Re-issue with RSA 2048+ or ECDSA P-256.", controls: [CTL.sp800131, CTL.pci421, CTL.sc13] },
  "cert-sha1": { tag: "SHA-1/MD5 signature", title: "Certificate signed with SHA-1 or MD5", category: "certificate", confidence: "confirmed", why: "SHA-1 and MD5 signatures are collision-prone and no longer trusted by browsers.", fix: "Re-issue the certificate with a SHA-256 (or stronger) signature.", controls: [CTL.sp800131, CTL.pci421, CTL.sc13] },
  "cert-mismatch": { tag: "cert name mismatch", title: "Certificate does not cover the scanned host name", category: "certificate", confidence: "likely", why: "The name used to reach the service is not in the certificate's subject or SAN list, so clients will warn or fail.", fix: "Issue a certificate whose SAN list includes every name clients use.", controls: [CTL.rfc6125, CTL.pci421, CTL.sc17] },
  "ssh-weak": { tag: "weak SSH algorithms", title: "SSH server offers weak algorithms", category: "ssh", confidence: "confirmed", why: "nmap ssh2-enum-algos lists deprecated algorithms (diffie-hellman-group1-sha1, ssh-dss, CBC or RC4 ciphers, MD5 or 96-bit MACs).", fix: "Remove them from KexAlgorithms, HostKeyAlgorithms, Ciphers and MACs in sshd_config.", controls: [CTL.rfc9142, CTL.rfc8758, CTL.cm6, CTL.sc13] },
  "ssh-v1": { tag: "SSH protocol 1", title: "SSH protocol version 1 supported", category: "ssh", confidence: "confirmed", why: "SSH-1 is cryptographically broken.", fix: "Disable protocol 1 (Protocol 2 only) or upgrade the server.", controls: [CTL.cm6, CTL.sc13, CTL.pci227] },
  smbv1: { tag: "SMBv1", title: "SMBv1 enabled", category: "smb", confidence: "confirmed", why: "SMBv1 is the protocol behind EternalBlue / WannaCry and has no modern protections.", fix: "Disable SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false) after confirming no legacy clients need it.", controls: [CTL.winSmb1, CTL.cis48, CTL.cm7, att("T1210")] },
  "smb-signing": { tag: "SMB signing not required", title: "SMB signing not required", category: "smb", confidence: "confirmed", why: "Without required signing, captured NTLM authentication can be relayed to this host.", fix: "Require SMB signing (Microsoft network server: Digitally sign communications (always) = Enabled).", controls: [CTL.winSign, CTL.cm6, att("T1557.001")] },
  "rdp-nla": { tag: "RDP without NLA", title: "RDP accepts connections without Network Level Authentication", category: "rdp", confidence: "confirmed", why: "nmap rdp-enum-encryption negotiated the native RDP security layer, so the logon screen and pre-auth code are reachable without credentials.", fix: "Require NLA (Group Policy: Require user authentication for remote connections by using Network Level Authentication).", controls: [CTL.cm6, CTL.ac17, att("T1021.001")] },
  "rdp-rc4": { tag: "RDP weak encryption", title: "RDP accepts 40/56-bit RC4 encryption", category: "rdp", confidence: "confirmed", why: "Legacy RDP encryption levels use weak RC4 keys.", fix: "Set the RDP encryption level to High / require TLS.", controls: [CTL.cm6, CTL.sc13] },
};

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
const q = (v) => { let s = String(v == null ? "" : v); if (/^[=+@\t\r-]/.test(s) && !/^-\d+(\.\d+)?$/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; }; // a leading = + - @ would run as a spreadsheet formula
const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "assets", "evidenceCount"];
/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const body = (findings || []).map((f) => [f.severity, f.confidence, f.category, f.title, f.description, f.recommendation, (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), (f.assets || []).filter((a) => a.type !== "VULNERABILITY").map((a) => a.name).join(" "), f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length].map(q).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n") + "\n";
}
function rowsToCsv(cols, rows) { return [cols.join(","), ...rows.map((r) => cols.map((c) => q(r[c])).join(","))].join("\n") + "\n"; }
export const INVENTORY_COLS = ["ip", "hostnames", "zone", "port", "proto", "service", "product", "version", "tls", "certNotAfter", "rule", "severity", "allowListed", "firstSeen", "lastSeen"];
/** Exposure inventory: host x port x service x version. */
export function inventoryToCsv(result) { return rowsToCsv(INVENTORY_COLS, (result && result.tables.exposures) || []); }
export const CHANGE_COLS = ["fromScan", "toScan", "type", "ip", "port", "proto", "zone", "before", "after", "detail", "severity", "confidence"];
export function changesToCsv(result) { return rowsToCsv(CHANGE_COLS, (result && result.tables.changes) || []); }
/** One close/restrict request per risky exposure (rule severity medium or worse, not allow-listed). */
export function firewallTicketText(result) {
  const rows = ((result && result.tables.exposures) || []).filter((e) => e.rule && e.severity && SEV_RANK[e.severity] >= SEV_RANK.medium && !e.allowListed)
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || ipCmp(a.ip, b.ip) || a.port - b.port);
  const L = ["Firewall change requests - Network Scan Diff", "Reference date: " + ((result && result.summary.referenceDate) || ""), "Requests: " + rows.length, ""];
  rows.forEach((e, i) => {
    const r = RULE_BY_ID[e.rule];
    L.push((i + 1) + ". [" + e.severity.toUpperCase() + "] " + (e.zone === "external" ? "CLOSE or RESTRICT inbound from the internet" : "RESTRICT on the internal segment") + ": " + e.ip + (e.hostnames ? " (" + e.hostnames + ")" : "") + " " + e.proto.toUpperCase() + "/" + e.port);
    L.push("   Service: " + [r.label, e.service, e.product, e.version].filter(Boolean).join(" | "));
    L.push("   Why: " + r.why);
    L.push("   Requested change: " + r.fix);
    L.push("   First seen in: " + e.firstSeen + "; last seen in: " + e.lastSeen);
    L.push("   References: " + r.controls.map((c) => c.framework + " " + c.id).join("; "));
    L.push("");
  });
  if (!rows.length) L.push("No risky exposures at medium severity or above.");
  return L.join("\n") + "\n";
}
export function summaryText(result) {
  const s = result.summary;
  const L = ["Network Scan Diff summary", "Reference date: " + s.referenceDate, "Scans: " + s.scans + "; hosts with open ports: " + s.hosts + "; open ports: " + s.openPorts + " (" + s.externalPorts + " external)",
    "Risky exposures: " + s.riskyExternal + " external, " + s.riskyInternal + " internal, " + s.allowListed + " allow-listed", "End of life: " + s.eolServices + " (approaching: " + s.eolApproaching + ")" + (s.eolFeedUpdated ? "; feed mirrored " + s.eolFeedUpdated.slice(0, 10) : ""),
    "Certificate issues: " + s.certIssues + " of " + s.certificates + "; scanner-reported CVEs: " + s.reportedCves, "New since last scan: " + s.newSinceLast + "; changes recorded: " + s.changes, "Findings: " + s.findings + " " + JSON.stringify(s.bySeverity), ""];
  for (const f of result.findings) L.push("- [" + f.severity + "/" + f.confidence + "] " + f.title + " (" + (f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length) + ") - " + f.recommendation);
  if (result.skipped.length) { L.push("", "Skipped or limited checks:"); for (const k of result.skipped) L.push("- " + k.check + ": " + k.reason); }
  return L.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example: two nmap XML scans of 10.20.0.0/24 a week apart plus one external scan of
// 203.0.113.0/28 (documentation range). Format-faithful nmap -oX; every value is invented.
// ---------------------------------------------------------------------------
const xa = (s) => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/\n/g, "&#xa;");
function scriptXml(sc) { return '<script id="' + xa(sc.id) + '" output="' + xa(sc.output) + '">' + (sc.xml || "") + "</script>"; }
function nmapXml({ args, start, hosts, services, version = "7.94SVN" }) {
  const startstr = new Date(start * 1000).toUTCString().replace(/^(\w+), (\d+) (\w+) (\d+) ([\d:]+) GMT$/, "$1 $3 $2 $5 $4");
  const out = ['<?xml version="1.0" encoding="UTF-8"?>', "<!DOCTYPE nmaprun>", '<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>',
    "<!-- Nmap " + version + " scan initiated " + startstr + " as: " + xa(args) + " -->",
    '<nmaprun scanner="nmap" args="' + xa(args) + '" start="' + start + '" startstr="' + startstr + '" version="' + version + '" xmloutputversion="1.05">',
    '<scaninfo type="syn" protocol="tcp" numservices="' + portCount(parsePortSpec(services).tcp) + '" services="' + services + '"/>', '<verbose level="0"/>', '<debugging level="0"/>'];
  let t = start;
  for (const h of hosts) {
    t += 3;
    out.push('<host starttime="' + t + '" endtime="' + (t + 40) + '"><status state="up" reason="' + (h.ip.startsWith("10.") ? "arp-response" : "echo-reply") + '" reason_ttl="' + (h.ip.startsWith("10.") ? 0 : 52) + '"/>');
    out.push('<address addr="' + h.ip + '" addrtype="ipv4"/>' + (h.mac ? '<address addr="' + h.mac + '" addrtype="mac" vendor="' + xa(h.vendor || "") + '"/>' : ""));
    out.push("<hostnames>" + (h.names || []).map(([n, ty]) => '<hostname name="' + xa(n) + '" type="' + ty + '"/>').join("") + "</hostnames>");
    out.push('<ports><extraports state="closed" count="' + (portCount(parsePortSpec(services).tcp) - h.ports.length) + '"><extrareasons reason="reset" count="' + (portCount(parsePortSpec(services).tcp) - h.ports.length) + '" proto="tcp"/></extraports>');
    for (const p of h.ports) {
      out.push('<port protocol="' + (p.proto || "tcp") + '" portid="' + p.port + '"><state state="open" reason="syn-ack" reason_ttl="' + (h.ip.startsWith("10.") ? 64 : 52) + '"/>' +
        '<service name="' + xa(p.svc) + '"' + (p.product ? ' product="' + xa(p.product) + '"' : "") + (p.version ? ' version="' + xa(p.version) + '"' : "") + (p.extrainfo ? ' extrainfo="' + xa(p.extrainfo) + '"' : "") + (p.ostype ? ' ostype="' + xa(p.ostype) + '"' : "") + (p.tunnel ? ' tunnel="' + p.tunnel + '"' : "") + ' method="probed" conf="10">' + (p.cpe || []).map((c) => "<cpe>" + c + "</cpe>").join("") + "</service>" +
        (p.scripts || []).map(scriptXml).join("") + "</port>");
    }
    out.push("</ports>");
    if (h.os) out.push('<os><portused state="open" proto="tcp" portid="' + h.ports[0].port + '"/><osmatch name="' + xa(h.os) + '" accuracy="' + (h.osAcc || 96) + '" line="1"><osclass type="general purpose" osfamily="' + (/windows/i.test(h.os) ? "Windows" : "Linux") + '" accuracy="' + (h.osAcc || 96) + '"/></osmatch></os>');
    if (h.hostscripts && h.hostscripts.length) out.push("<hostscript>" + h.hostscripts.map(scriptXml).join("") + "</hostscript>");
    out.push('<times srtt="412" rttvar="187" to="100000"/></host>');
  }
  const end = t + 60;
  out.push('<runstats><finished time="' + end + '" timestr="' + new Date(end * 1000).toUTCString() + '" summary="Nmap done; ' + hosts.length + ' IP addresses up" elapsed="' + (end - start) + '" exit="success"/><hosts up="' + hosts.length + '" down="0" total="' + hosts.length + '"/></runstats>', "</nmaprun>", "");
  return out.join("\n");
}
function certScript(rnd, { cn, issuer, sans, bits = 2048, sig = "sha256WithRSAEncryption", nb, na }) {
  const hex = (n) => Array.from({ length: n }, () => Math.floor(rnd() * 16).toString(16)).join("");
  const md5 = hex(32), sha1 = hex(40);
  const fmt = (h) => h.match(/.{4}/g).join(" ");
  const output = "Subject: commonName=" + cn + (sans ? "\nSubject Alternative Name: " + sans.map((s) => "DNS:" + s).join(", ") : "") + "\nIssuer: commonName=" + issuer + "\nPublic Key type: rsa\nPublic Key bits: " + bits + "\nSignature Algorithm: " + sig + "\nNot valid before: " + nb + "\nNot valid after:  " + na + "\nMD5:   " + fmt(md5) + "\nSHA-1: " + fmt(sha1);
  const xml = '<table key="subject"><elem key="commonName">' + cn + '</elem></table><table key="issuer"><elem key="commonName">' + issuer + "</elem></table>" +
    '<table key="pubkey"><elem key="type">rsa</elem><elem key="bits">' + bits + '</elem><elem key="exponent">65537</elem></table>' +
    (sans ? '<table key="extensions"><table><elem key="name">X509v3 Subject Alternative Name</elem><elem key="value">' + sans.map((s) => "DNS:" + s).join(", ") + "</elem></table></table>" : "") +
    '<elem key="sig_algo">' + sig + '</elem><table key="validity"><elem key="notBefore">' + nb + '</elem><elem key="notAfter">' + na + '</elem></table><elem key="md5">' + md5 + '</elem><elem key="sha1">' + sha1 + "</elem>";
  return { id: "ssl-cert", output: "\n" + output.split("\n").join("\n"), xml };
}
const CIPHERS_WEAK = "\n  TLSv1.0: \n    ciphers: \n      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (secp256r1) - A\n      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C\n    compressors: \n      NULL\n    cipher preference: server\n    warnings: \n      64-bit block cipher 3DES vulnerable to SWEET32 attack\n  TLSv1.2: \n    ciphers: \n      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A\n    compressors: \n      NULL\n    cipher preference: server\n  least strength: C";
const CIPHERS_OK = "\n  TLSv1.2: \n    ciphers: \n      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (secp256r1) - A\n    compressors: \n      NULL\n    cipher preference: client\n  TLSv1.3: \n    ciphers: \n      TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A\n      TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A\n    cipher preference: server\n  least strength: A";
const SSH_ALGOS_WEAK = "\n  kex_algorithms: (5)\n      curve25519-sha256@libssh.org\n      ecdh-sha2-nistp256\n      diffie-hellman-group-exchange-sha256\n      diffie-hellman-group14-sha1\n      diffie-hellman-group1-sha1\n  server_host_key_algorithms: (3)\n      ssh-rsa\n      ecdsa-sha2-nistp256\n      ssh-ed25519\n  encryption_algorithms: (5)\n      chacha20-poly1305@openssh.com\n      aes128-ctr\n      aes256-gcm@openssh.com\n      aes128-cbc\n      3des-cbc\n  mac_algorithms: (4)\n      hmac-sha2-256\n      hmac-sha2-512\n      hmac-sha1\n      hmac-md5\n  compression_algorithms: (2)\n      none\n      zlib@openssh.com";
const SSH_ALGOS_OK = "\n  kex_algorithms: (3)\n      curve25519-sha256\n      curve25519-sha256@libssh.org\n      ecdh-sha2-nistp256\n  server_host_key_algorithms: (3)\n      rsa-sha2-512\n      rsa-sha2-256\n      ssh-ed25519\n  encryption_algorithms: (3)\n      chacha20-poly1305@openssh.com\n      aes128-ctr\n      aes256-gcm@openssh.com\n  mac_algorithms: (2)\n      hmac-sha2-256-etm@openssh.com\n      hmac-sha2-512-etm@openssh.com\n  compression_algorithms: (2)\n      none\n      zlib@openssh.com";
const SMB_V1 = { id: "smb-protocols", output: "\n  dialects: \n    NT LM 0.12 (SMBv1) [dangerous, but default]\n    2:0:2\n    2:1:0\n    3:0:0\n    3:0:2", xml: '<table key="dialects"><elem>NT LM 0.12 (SMBv1) [dangerous, but default]</elem><elem>2:0:2</elem><elem>2:1:0</elem><elem>3:0:0</elem><elem>3:0:2</elem></table>' };
const SMB_V2 = { id: "smb-protocols", output: "\n  dialects: \n    2:0:2\n    2:1:0\n    3:0:0\n    3:0:2\n    3:1:1", xml: '<table key="dialects"><elem>2:0:2</elem><elem>2:1:0</elem><elem>3:0:0</elem><elem>3:0:2</elem><elem>3:1:1</elem></table>' };
const SMB_SIGN_OPT = { id: "smb2-security-mode", output: "\n  3:0:2: \n    Message signing enabled but not required", xml: '<table key="3:0:2"><elem>Message signing enabled but not required</elem></table>' };
const SMB_SIGN_REQ = { id: "smb2-security-mode", output: "\n  3:1:1: \n    Message signing enabled and required", xml: '<table key="3:1:1"><elem>Message signing enabled and required</elem></table>' };
const VULNERS_SSH74 = { id: "vulners", output: "\n  cpe:/a:openbsd:openssh:7.4p1: \n    \tCVE-2023-38408\t9.8\thttps://vulners.com/cve/CVE-2023-38408\n    \tCVE-2020-15778\t7.8\thttps://vulners.com/cve/CVE-2020-15778\n    \tCVE-2021-41617\t7.0\thttps://vulners.com/cve/CVE-2021-41617" };
const RDP_ENUM = { id: "rdp-enum-encryption", output: "\n  Security layer\n    CredSSP (NLA): SUCCESS\n    CredSSP with Early User Auth: SUCCESS\n    Native RDP: SUCCESS\n    RDSTLS: SUCCESS\n    SSL: SUCCESS\n  RDP Encryption level: Client Compatible\n    40-bit RC4: SUCCESS\n    56-bit RC4: SUCCESS\n    128-bit RC4: SUCCESS\n    FIPS 140-1: SUCCESS\n  RDP Protocol Version:  RDP 10.7 server" };

/** Seeded SYNTHETIC dataset: { label, files: [{ name, text }], scans: { [file]: { label, order, external } } }. */
export function exampleDataset(seed = 7) {
  let s = seed >>> 0;
  const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const D = ".corp.test.darknode.ai";
  const cert = (o) => certScript(rnd, o);
  const ssh74 = { port: 22, svc: "ssh", product: "OpenSSH", version: "7.4p1 Debian 10+deb9u7", extrainfo: "protocol 2.0", ostype: "Linux", cpe: ["cpe:/a:openbsd:openssh:7.4p1", "cpe:/o:linux:linux_kernel"], scripts: [{ id: "ssh2-enum-algos", output: SSH_ALGOS_WEAK }, VULNERS_SSH74] };
  const ssh89 = { port: 22, svc: "ssh", product: "OpenSSH", version: "8.9p1 Ubuntu 3ubuntu0.10", extrainfo: "Ubuntu Linux; protocol 2.0", ostype: "Linux", cpe: ["cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:linux:linux_kernel"], scripts: [{ id: "ssh2-enum-algos", output: SSH_ALGOS_OK }] };
  const intranetCert = cert({ cn: "intranet" + D, issuer: "intranet" + D, sans: ["intranet" + D], nb: "2024-08-31T00:00:00", na: "2026-08-31T00:00:00" });
  const dcCert = cert({ cn: "dc01" + D, issuer: "Test Org Issuing CA 01", sans: ["dc01" + D], nb: "2026-03-02T09:12:44", na: "2027-03-02T09:12:44" });
  const internalHosts = (week2) => [
    { ip: "10.20.0.10", names: [["dc01" + D, "PTR"]], os: "Microsoft Windows Server 2019", ports: [
      { port: 53, svc: "domain", product: "Simple DNS Plus" }, { port: 88, svc: "kerberos-sec", product: "Microsoft Windows Kerberos" }, { port: 135, svc: "msrpc", product: "Microsoft Windows RPC", ostype: "Windows" },
      { port: 389, svc: "ldap", product: "Microsoft Windows Active Directory LDAP", extrainfo: "Domain: corp.test.darknode.ai, Site: Default-First-Site-Name" }, { port: 445, svc: "microsoft-ds" },
      { port: 636, svc: "ldapssl", tunnel: "ssl", scripts: [dcCert] }, { port: 3389, svc: "ms-wbt-server", product: "Microsoft Terminal Services", ostype: "Windows" }],
      hostscripts: [SMB_V2, SMB_SIGN_REQ, { id: "smb-os-discovery", output: "\n  OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)\n  Computer name: DC01\n  NetBIOS computer name: DC01\\x00\n  Domain name: corp.test.darknode.ai\n  FQDN: dc01" + D + "\n  System time: 2026-10-01T09:00:12+00:00" }] },
    { ip: "10.20.0.21", names: [["fs01" + D, "PTR"]], os: "Microsoft Windows Server 2012 R2", ports: [
      { port: 135, svc: "msrpc", product: "Microsoft Windows RPC", ostype: "Windows" }, { port: 139, svc: "netbios-ssn", product: "Microsoft Windows netbios-ssn", ostype: "Windows" },
      { port: 445, svc: "microsoft-ds", product: "Microsoft Windows Server 2008 R2 - 2012 microsoft-ds" }, { port: 3389, svc: "ms-wbt-server", product: "Microsoft Terminal Services", ostype: "Windows" }],
      hostscripts: [SMB_V1, SMB_SIGN_OPT, { id: "smb-os-discovery", output: "\n  OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)\n  OS CPE: cpe:/o:microsoft:windows_server_2012::-\n  Computer name: FS01\n  NetBIOS computer name: FS01\\x00\n  Domain name: corp.test.darknode.ai\n  FQDN: fs01" + D + "\n  System time: 2026-10-01T09:00:31+00:00" }] },
    { ip: "10.20.0.30", names: [["app01" + D, "PTR"]], os: "Linux 4.15 - 5.8", ports: [ssh74, { port: 8080, svc: "http", product: "Apache Tomcat", version: "9.0.31", scripts: [{ id: "http-title", output: "Apache Tomcat/9.0.31", xml: '<elem key="title">Apache Tomcat/9.0.31</elem>' }] }] },
    { ip: "10.20.0.40", names: [["intranet" + D, "PTR"]], os: "Linux 5.0 - 5.14", ports: [
      ssh89, { port: 80, svc: "http", product: "nginx", version: week2 ? "1.24.0" : "1.18.0", extrainfo: "Ubuntu", scripts: [{ id: "http-server-header", output: "nginx/" + (week2 ? "1.24.0" : "1.18.0") + " (Ubuntu)", xml: "<elem>nginx/" + (week2 ? "1.24.0" : "1.18.0") + " (Ubuntu)</elem>" }] },
      { port: 443, svc: "http", tunnel: "ssl", product: "nginx", version: week2 ? "1.24.0" : "1.18.0", extrainfo: "Ubuntu", scripts: [intranetCert, { id: "ssl-enum-ciphers", output: CIPHERS_WEAK }, { id: "http-title", output: "Test Org Intranet", xml: '<elem key="title">Test Org Intranet</elem>' }] }] },
    { ip: "10.20.0.50", names: [["db01" + D, "PTR"]], os: "Linux 4.15 - 5.8", ports: [ssh89, { port: 3306, svc: "mysql", product: "MySQL", version: "5.7.33-0ubuntu0.18.04.1" }] },
    { ip: "10.20.0.60", names: [["build01" + D, "PTR"]], os: "Linux 5.0 - 5.14", ports: [ssh89, ...(week2 ? [{ port: 2375, svc: "docker", product: "Docker", version: "24.0.7", extrainfo: "API 1.43", scripts: [{ id: "http-title", output: "Site doesn't have a title (application/json)." }] }] : [])] },
    { ip: "10.20.0.70", names: [["prn-3f" + D, "PTR"]], ports: [{ port: 23, svc: "telnet", product: "HP JetDirect printer telnetd" }, { port: 80, svc: "http", product: "HP-ChaiSOE", version: "1.0" }, { port: 9100, svc: "jetdirect" }] },
    ...(week2 ? [] : [{ ip: "10.20.0.80", names: [["old-kiosk" + D, "PTR"]], os: "Microsoft Windows 10 1607", ports: [{ port: 135, svc: "msrpc", product: "Microsoft Windows RPC" }, { port: 445, svc: "microsoft-ds" }] }]),
    ...(week2 ? [{ ip: "10.20.0.90", names: [["mon01" + D, "PTR"]], os: "Linux 5.0 - 5.14", ports: [ssh89, { port: 3000, svc: "ppp", product: "Grafana http", scripts: [{ id: "http-title", output: "Grafana\nRequested resource was /login", xml: '<elem key="title">Grafana</elem><elem key="redirect_url">/login</elem>' }] }] }] : []),
  ];
  const args = (f) => "nmap -sS -sV -O -p 1-10000 --script ssl-cert,ssl-enum-ciphers,ssh2-enum-algos,smb-protocols,smb2-security-mode,smb-os-discovery,http-title,http-server-header,vulners -oX " + f + " 10.20.0.0/24";
  const t1 = Date.UTC(2026, 9, 1, 9, 0, 0) / 1000, t2 = Date.UTC(2026, 9, 8, 9, 0, 0) / 1000, t3 = Date.UTC(2026, 9, 8, 14, 30, 0) / 1000;
  const vpnCert = cert({ cn: "portal.testorg.test.darknode.ai", issuer: "portal.testorg.test.darknode.ai", nb: "2024-09-14T00:00:00", na: "2026-09-14T00:00:00" });
  const extHosts = [
    { ip: "203.0.113.5", names: [["ts.testorg.test.darknode.ai", "PTR"]], ports: [{ port: 3389, svc: "ms-wbt-server", product: "Microsoft Terminal Services", ostype: "Windows", scripts: [RDP_ENUM] }] },
    { ip: "203.0.113.6", names: [["cache-edge.testorg.test.darknode.ai", "PTR"]], ports: [{ port: 6379, svc: "redis", product: "Redis key-value store", version: "5.0.7" }] },
    { ip: "203.0.113.7", names: [["remote.testorg.test.darknode.ai", "user"]], ports: [{ port: 443, svc: "http", tunnel: "ssl", product: "nginx", scripts: [vpnCert, { id: "ssl-enum-ciphers", output: CIPHERS_OK }, { id: "http-title", output: "Test Org Remote Access", xml: '<elem key="title">Test Org Remote Access</elem>' }] }] },
    { ip: "203.0.113.8", names: [["sftp.testorg.test.darknode.ai", "PTR"]], ports: [{ ...ssh74, scripts: [VULNERS_SSH74] }] },
    { ip: "203.0.113.9", names: [["www.testorg.test.darknode.ai", "PTR"]], ports: [{ port: 80, svc: "http", product: "nginx" }, { port: 443, svc: "http", tunnel: "ssl", product: "nginx", scripts: [cert({ cn: "www.testorg.test.darknode.ai", issuer: "Test CA", sans: ["www.testorg.test.darknode.ai", "testorg.test.darknode.ai"], nb: "2026-07-20T00:00:00", na: "2026-10-28T23:59:59" }), { id: "ssl-enum-ciphers", output: CIPHERS_OK }] }] },
  ];
  const files = [
    { name: "internal-2026-10-01.xml", text: nmapXml({ args: args("internal-2026-10-01.xml"), start: t1, hosts: internalHosts(false), services: "1-10000" }) },
    { name: "internal-2026-10-08.xml", text: nmapXml({ args: args("internal-2026-10-08.xml"), start: t2, hosts: internalHosts(true), services: "1-10000" }) },
    { name: "external-2026-10-08.xml", text: nmapXml({ args: "nmap -Pn -sS -sV -p 22,80,443,3389,6379 --script ssl-cert,ssl-enum-ciphers,rdp-enum-encryption,vulners -oX external-2026-10-08.xml 203.0.113.0/28 remote.testorg.test.darknode.ai", start: t3, hosts: extHosts, services: "22,80,443,3389,6379" }) },
  ];
  return {
    label: "synthetic example (not real data)", files,
    scans: { "internal-2026-10-01.xml": { label: "Internal week 40", order: 1 }, "internal-2026-10-08.xml": { label: "Internal week 41", order: 2 }, "external-2026-10-08.xml": { label: "External perimeter", order: 3, external: true } },
    allowList: "10.20.0.10:3389 domain controller admin access via jump host only",
  };
}
// Small fixture shaped like /data/feeds/eol-products.json, for selfTest and tests only.
export const EOL_FIXTURE = {
  updated: "2026-10-01T00:00:00.000Z", source: "endoflife.date (test fixture)", count: 5, data: [
    { product: "debian", cycles: [{ cycle: "12", eol: "2028-06-30", latest: "12.15", extendedSupport: false }, { cycle: "9", eol: "2022-07-01", latest: "9.13", extendedSupport: "2027-06-30" }] },
    { product: "nginx", cycles: [{ cycle: "1.24", eol: "2024-04-23", latest: "1.24.0" }, { cycle: "1.18", eol: "2021-04-20", latest: "1.18.0" }, { cycle: "1.29", eol: false, latest: "1.29.8" }] },
    { product: "redis", cycles: [{ cycle: "7.4", eol: "2029-12-01", latest: "7.4.11" }, { cycle: "5.0", eol: "2022-04-27", latest: "5.0.14" }] },
    { product: "mysql", cycles: [{ cycle: "8.4", eol: "2032-04-30", latest: "8.4.9" }, { cycle: "5.7", eol: "2023-10-31", latest: "5.7.44" }] },
    { product: "windows-server", cycles: [{ cycle: "2019", eol: "2029-01-09" }, { cycle: "2012-r2", eol: "2023-10-10" }] },
    { product: "tomcat", cycles: [{ cycle: "9.0", eol: "2027-03-31", latest: "9.0.123" }] },
  ],
};

/** Real deterministic checks of the engine. */
export function selfTest() {
  const tests = [];
  const ex = exampleDataset();
  const r = analyze(ex.files, { scans: ex.scans, eol: EOL_FIXTURE, allowList: ex.allowList });
  const has = (id) => r.findings.some((f) => f.id === id);
  tests.push({ name: "external RDP and Redis are critical", pass: r.findings.some((f) => f.id === "exp-rdp-external" && f.severity === "critical") && r.findings.some((f) => f.id === "exp-redis-external" && f.severity === "critical") });
  tests.push({ name: "new Docker API port is caught as a risky change", pass: r.tables.changes.some((c) => c.type === "port-opened" && c.ip === "10.20.0.60" && c.port === 2375 && c.risky === "docker") && has("chg-port-opened-risky") });
  tests.push({ name: "expired self-signed external certificate", pass: has("cfg-cert-expired") && has("cfg-cert-self-signed") });
  tests.push({ name: "SMBv1 and EOL Windows / Debian found", pass: has("cfg-smbv1") && has("eol-windows-server-2012-r2-eol") && has("eol-debian-9-eol") });
  tests.push({ name: "disappeared host recorded, not as closed ports", pass: r.tables.changes.some((c) => c.type === "host-disappeared" && c.ip === "10.20.0.80") && !r.tables.changes.some((c) => c.type === "port-closed" && c.ip === "10.20.0.80") });
  tests.push({ name: "deterministic", pass: JSON.stringify(r) === JSON.stringify(analyze(ex.files, { scans: ex.scans, eol: EOL_FIXTURE, allowList: ex.allowList })) });
  tests.push({ name: "empty input yields no findings", pass: analyze([]).findings.length === 0 });
  return { pass: tests.every((t) => t.pass), tests };
}
