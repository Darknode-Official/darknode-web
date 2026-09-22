// Network Mapper — topology visualization, subnet calculator, attack surface mapper, nmap importer.
// Copyright (c) 2026 Darknode-Official. All rights reserved.
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ─── Service/port database ─────────────────────────────────────────────────
const PORT_DB = {
  21: { name: "FTP", risk: 3, vuln: "Cleartext auth, anonymous access, CVE-2015-3306 ProFTPD" },
  22: { name: "SSH", risk: 1, vuln: "Brute force, CVE-2024-6387 regreSSHion, weak ciphers" },
  23: { name: "Telnet", risk: 4, vuln: "Cleartext everything, no encryption, deprecated" },
  25: { name: "SMTP", risk: 2, vuln: "Open relay, VRFY user enum, STARTTLS stripping" },
  53: { name: "DNS", risk: 2, vuln: "Zone transfer, cache poisoning, amplification, tunneling" },
  80: { name: "HTTP", risk: 2, vuln: "All web vulns (SQLi, XSS, RCE), unencrypted traffic" },
  88: { name: "Kerberos", risk: 2, vuln: "Kerberoasting, AS-REP roasting, golden ticket" },
  110: { name: "POP3", risk: 3, vuln: "Cleartext auth, brute force" },
  111: { name: "RPCbind", risk: 3, vuln: "Service enumeration, NFS exploitation" },
  135: { name: "MS-RPC", risk: 3, vuln: "DCOM exploitation, remote code execution" },
  139: { name: "NetBIOS", risk: 3, vuln: "SMB relay, null sessions, information disclosure" },
  143: { name: "IMAP", risk: 2, vuln: "Cleartext auth, brute force" },
  161: { name: "SNMP", risk: 3, vuln: "Default community strings, information disclosure" },
  389: { name: "LDAP", risk: 3, vuln: "Anonymous bind, credential extraction, injection" },
  443: { name: "HTTPS", risk: 1, vuln: "Web vulns, weak TLS versions, cert issues" },
  445: { name: "SMB", risk: 4, vuln: "EternalBlue (MS17-010), relay attacks, ransomware spread" },
  993: { name: "IMAPS", risk: 1, vuln: "Brute force, weak TLS" },
  1433: { name: "MSSQL", risk: 3, vuln: "xp_cmdshell, default sa password, SQLi" },
  1521: { name: "Oracle", risk: 3, vuln: "TNS poisoning, default credentials, Java deserialization" },
  2049: { name: "NFS", risk: 3, vuln: "Misconfigured exports, no_root_squash" },
  3306: { name: "MySQL", risk: 3, vuln: "UDF exploitation, default credentials, SQLi" },
  3389: { name: "RDP", risk: 3, vuln: "BlueKeep (CVE-2019-0708), brute force, NLA bypass" },
  5432: { name: "PostgreSQL", risk: 2, vuln: "COPY command RCE, weak auth, SQLi" },
  5900: { name: "VNC", risk: 3, vuln: "No/weak auth, brute force, unencrypted" },
  5985: { name: "WinRM", risk: 3, vuln: "Credential stuffing, lateral movement via Evil-WinRM" },
  6379: { name: "Redis", risk: 4, vuln: "Default no auth, SLAVEOF RCE, module loading" },
  8080: { name: "HTTP-Alt", risk: 2, vuln: "Management interfaces, default credentials" },
  8443: { name: "HTTPS-Alt", risk: 1, vuln: "Management panels, web application vulns" },
  9200: { name: "Elasticsearch", risk: 4, vuln: "Default no auth, data exfiltration, RCE" },
  27017: { name: "MongoDB", risk: 4, vuln: "Default no auth, data theft, ransomware" },
};

// ─── OS fingerprints ───────────────────────────────────────────────────────
const OS_ICONS = {
  "linux": { icon: "L", color: "#f39c12" },
  "windows": { icon: "W", color: "#3498db" },
  "macos": { icon: "M", color: "#95a5a6" },
  "cisco": { icon: "C", color: "#2ecc71" },
  "router": { icon: "R", color: "#e74c3c" },
  "firewall": { icon: "F", color: "#e67e22" },
  "switch": { icon: "S", color: "#1abc9c" },
  "printer": { icon: "P", color: "#9b59b6" },
  "camera": { icon: "K", color: "#34495e" },
  "unknown": { icon: "?", color: "#7f8c8d" },
};

// ─── Topology templates ────────────────────────────────────────────────────
const TOPOLOGY_TEMPLATES = {
  "Flat Network": {
    desc: "Single network segment — all hosts on the same subnet. Simple but no segmentation.",
    nodes: [
      { id: "gw", ip: "192.168.1.1", hostname: "gateway", os: "router", ports: [22, 80, 443], x: 400, y: 50 },
      { id: "srv1", ip: "192.168.1.10", hostname: "web-server", os: "linux", ports: [22, 80, 443, 3306], x: 200, y: 200 },
      { id: "srv2", ip: "192.168.1.11", hostname: "db-server", os: "linux", ports: [22, 3306, 5432], x: 400, y: 200 },
      { id: "ws1", ip: "192.168.1.100", hostname: "workstation-1", os: "windows", ports: [135, 139, 445, 3389], x: 100, y: 350 },
      { id: "ws2", ip: "192.168.1.101", hostname: "workstation-2", os: "windows", ports: [135, 139, 445, 3389], x: 300, y: 350 },
      { id: "ws3", ip: "192.168.1.102", hostname: "workstation-3", os: "windows", ports: [135, 139, 445], x: 500, y: 350 },
      { id: "ptr", ip: "192.168.1.200", hostname: "printer", os: "printer", ports: [80, 443, 515, 9100], x: 650, y: 200 },
    ],
    edges: [
      { from: "gw", to: "srv1" }, { from: "gw", to: "srv2" }, { from: "gw", to: "ws1" },
      { from: "gw", to: "ws2" }, { from: "gw", to: "ws3" }, { from: "gw", to: "ptr" },
      { from: "ws1", to: "srv1" }, { from: "ws2", to: "srv1" }, { from: "ws3", to: "srv2" },
    ],
  },
  "DMZ Architecture": {
    desc: "Three-zone network with DMZ between external and internal networks. Industry standard for hosting public services.",
    nodes: [
      { id: "inet", ip: "0.0.0.0", hostname: "Internet", os: "unknown", ports: [], x: 400, y: 30 },
      { id: "fw-ext", ip: "10.0.0.1", hostname: "external-firewall", os: "firewall", ports: [22], x: 400, y: 120 },
      { id: "dmz-web", ip: "10.0.1.10", hostname: "dmz-webserver", os: "linux", ports: [80, 443], x: 200, y: 230 },
      { id: "dmz-mail", ip: "10.0.1.11", hostname: "dmz-mailserver", os: "linux", ports: [25, 143, 993], x: 400, y: 230 },
      { id: "dmz-dns", ip: "10.0.1.12", hostname: "dmz-dns", os: "linux", ports: [53], x: 600, y: 230 },
      { id: "fw-int", ip: "10.0.0.2", hostname: "internal-firewall", os: "firewall", ports: [22], x: 400, y: 330 },
      { id: "dc", ip: "10.0.2.10", hostname: "domain-controller", os: "windows", ports: [53, 88, 135, 389, 445, 636], x: 200, y: 440 },
      { id: "db", ip: "10.0.2.11", hostname: "database-server", os: "linux", ports: [22, 3306, 5432], x: 400, y: 440 },
      { id: "file", ip: "10.0.2.12", hostname: "file-server", os: "windows", ports: [135, 139, 445], x: 600, y: 440 },
    ],
    edges: [
      { from: "inet", to: "fw-ext" },
      { from: "fw-ext", to: "dmz-web" }, { from: "fw-ext", to: "dmz-mail" }, { from: "fw-ext", to: "dmz-dns" },
      { from: "dmz-web", to: "fw-int" }, { from: "dmz-mail", to: "fw-int" },
      { from: "fw-int", to: "dc" }, { from: "fw-int", to: "db" }, { from: "fw-int", to: "file" },
    ],
  },
  "Three-Tier Architecture": {
    desc: "Presentation, application, and data tiers — each on its own network segment with controlled access between tiers.",
    nodes: [
      { id: "lb", ip: "10.0.0.10", hostname: "load-balancer", os: "router", ports: [80, 443], x: 400, y: 50 },
      { id: "web1", ip: "10.0.1.10", hostname: "web-1", os: "linux", ports: [80, 443], x: 250, y: 170 },
      { id: "web2", ip: "10.0.1.11", hostname: "web-2", os: "linux", ports: [80, 443], x: 550, y: 170 },
      { id: "app1", ip: "10.0.2.10", hostname: "app-1", os: "linux", ports: [8080, 8443], x: 250, y: 300 },
      { id: "app2", ip: "10.0.2.11", hostname: "app-2", os: "linux", ports: [8080, 8443], x: 550, y: 300 },
      { id: "db-m", ip: "10.0.3.10", hostname: "db-primary", os: "linux", ports: [3306], x: 300, y: 430 },
      { id: "db-s", ip: "10.0.3.11", hostname: "db-replica", os: "linux", ports: [3306], x: 500, y: 430 },
    ],
    edges: [
      { from: "lb", to: "web1" }, { from: "lb", to: "web2" },
      { from: "web1", to: "app1" }, { from: "web1", to: "app2" },
      { from: "web2", to: "app1" }, { from: "web2", to: "app2" },
      { from: "app1", to: "db-m" }, { from: "app2", to: "db-m" },
      { from: "db-m", to: "db-s" },
    ],
  },
  "Zero Trust Micro-Segmented": {
    desc: "Every workload is isolated with its own security controls. No implicit trust between any segments.",
    nodes: [
      { id: "idp", ip: "10.0.0.5", hostname: "identity-provider", os: "linux", ports: [443], x: 400, y: 50 },
      { id: "proxy", ip: "10.0.0.10", hostname: "zero-trust-proxy", os: "linux", ports: [443], x: 400, y: 150 },
      { id: "seg-a", ip: "10.0.1.0/24", hostname: "segment-a (web)", os: "firewall", ports: [], x: 150, y: 280 },
      { id: "seg-b", ip: "10.0.2.0/24", hostname: "segment-b (api)", os: "firewall", ports: [], x: 400, y: 280 },
      { id: "seg-c", ip: "10.0.3.0/24", hostname: "segment-c (data)", os: "firewall", ports: [], x: 650, y: 280 },
      { id: "w-a1", ip: "10.0.1.10", hostname: "web-app-1", os: "linux", ports: [443], x: 100, y: 400 },
      { id: "w-a2", ip: "10.0.1.11", hostname: "web-app-2", os: "linux", ports: [443], x: 200, y: 400 },
      { id: "w-b1", ip: "10.0.2.10", hostname: "api-svc-1", os: "linux", ports: [8443], x: 350, y: 400 },
      { id: "w-b2", ip: "10.0.2.11", hostname: "api-svc-2", os: "linux", ports: [8443], x: 450, y: 400 },
      { id: "w-c1", ip: "10.0.3.10", hostname: "database", os: "linux", ports: [5432], x: 600, y: 400 },
      { id: "w-c2", ip: "10.0.3.11", hostname: "cache", os: "linux", ports: [6379], x: 700, y: 400 },
    ],
    edges: [
      { from: "idp", to: "proxy" },
      { from: "proxy", to: "seg-a" }, { from: "proxy", to: "seg-b" }, { from: "proxy", to: "seg-c" },
      { from: "seg-a", to: "w-a1" }, { from: "seg-a", to: "w-a2" },
      { from: "seg-b", to: "w-b1" }, { from: "seg-b", to: "w-b2" },
      { from: "seg-c", to: "w-c1" }, { from: "seg-c", to: "w-c2" },
    ],
  },
};

// ─── Attack patterns ───────────────────────────────────────────────────────
const ATTACK_PATTERNS = [
  { name: "ARP Spoofing", zone: "Layer 2", desc: "Poison ARP caches to redirect traffic through attacker's machine for MITM.", req: "Same broadcast domain", mitre: "T1557.002" },
  { name: "VLAN Hopping", zone: "Layer 2", desc: "Switch spoofing or double-tagging to reach other VLANs.", req: "Trunk port access or DTP enabled", mitre: "T1599" },
  { name: "DHCP Starvation + Rogue DHCP", zone: "Layer 2/3", desc: "Exhaust legitimate DHCP pool, then serve malicious DHCP with attacker as gateway.", req: "Same broadcast domain", mitre: "T1557" },
  { name: "DNS Spoofing", zone: "Layer 3/7", desc: "Inject false DNS responses to redirect traffic.", req: "MITM position or vulnerable resolver", mitre: "T1557.004" },
  { name: "LLMNR/NBT-NS Poisoning", zone: "Layer 3", desc: "Respond to local name resolution broadcasts to capture NTLMv2 hashes.", req: "Windows network, same subnet", mitre: "T1557.001" },
  { name: "SMB Relay", zone: "Layer 7", desc: "Relay captured NTLM authentication to other hosts for lateral movement.", req: "SMB signing disabled, captured auth", mitre: "T1557.001" },
  { name: "Pass-the-Hash", zone: "Credential", desc: "Use captured NTLM hash to authenticate without knowing the password.", req: "NTLM hash, target accepting NTLM", mitre: "T1550.002" },
  { name: "Kerberoasting", zone: "Credential", desc: "Request service tickets for SPNs and crack them offline.", req: "Domain user credentials, SPN targets", mitre: "T1558.003" },
  { name: "DCSync", zone: "Credential", desc: "Replicate AD domain controller to extract all password hashes.", req: "Replication privileges (Domain Admin)", mitre: "T1003.006" },
  { name: "PrintNightmare", zone: "Exploit", desc: "Exploit Windows Print Spooler for RCE on domain controllers.", req: "Print Spooler running, CVE-2021-34527", mitre: "T1210" },
  { name: "EternalBlue", zone: "Exploit", desc: "SMBv1 remote code execution (MS17-010).", req: "SMBv1 enabled, unpatched Windows", mitre: "T1210" },
  { name: "BlueKeep", zone: "Exploit", desc: "RDP pre-authentication RCE (CVE-2019-0708).", req: "RDP exposed, unpatched Windows 7/2008R2", mitre: "T1210" },
];

// ─── Protocol flow diagrams ────────────────────────────────────────────────
const PROTOCOL_FLOWS = {
  "TCP 3-Way Handshake": [
    { from: "Client", to: "Server", label: "SYN (seq=x)", desc: "Client initiates connection" },
    { from: "Server", to: "Client", label: "SYN-ACK (seq=y, ack=x+1)", desc: "Server acknowledges and sends its own SYN" },
    { from: "Client", to: "Server", label: "ACK (ack=y+1)", desc: "Client acknowledges — connection established" },
  ],
  "TLS 1.3 Handshake": [
    { from: "Client", to: "Server", label: "ClientHello + KeyShare", desc: "Client sends supported ciphers and key share" },
    { from: "Server", to: "Client", label: "ServerHello + KeyShare + {Encrypted Extensions, Certificate, CertVerify, Finished}", desc: "Server completes handshake in one round trip" },
    { from: "Client", to: "Server", label: "{Finished}", desc: "Client confirms — TLS 1.3 handshake complete (1-RTT)" },
    { from: "Client", to: "Server", label: "[Application Data]", desc: "Encrypted application data flows" },
  ],
  "DNS Resolution": [
    { from: "Client", to: "Recursive Resolver", label: "Query: A example.com", desc: "Client asks its configured DNS resolver" },
    { from: "Recursive Resolver", to: "Root Server", label: "Query: example.com?", desc: "Resolver queries root nameserver" },
    { from: "Root Server", to: "Recursive Resolver", label: "Referral: .com NS", desc: "Root refers to .com TLD servers" },
    { from: "Recursive Resolver", to: "TLD Server", label: "Query: example.com?", desc: "Resolver queries .com TLD server" },
    { from: "TLD Server", to: "Recursive Resolver", label: "Referral: example.com NS", desc: "TLD refers to authoritative nameservers" },
    { from: "Recursive Resolver", to: "Auth Server", label: "Query: A example.com", desc: "Resolver queries authoritative server" },
    { from: "Auth Server", to: "Recursive Resolver", label: "Answer: 93.184.216.34", desc: "Authoritative server provides the answer" },
    { from: "Recursive Resolver", to: "Client", label: "Answer: 93.184.216.34", desc: "Resolver returns cached result to client" },
  ],
  "DHCP (DORA)": [
    { from: "Client", to: "Broadcast", label: "DHCP Discover", desc: "Client broadcasts looking for DHCP servers" },
    { from: "Server", to: "Client", label: "DHCP Offer (10.0.0.50)", desc: "Server offers an IP address" },
    { from: "Client", to: "Broadcast", label: "DHCP Request (10.0.0.50)", desc: "Client requests the offered address" },
    { from: "Server", to: "Client", label: "DHCP ACK", desc: "Server confirms the lease" },
  ],
  "ARP Resolution": [
    { from: "Host A", to: "Broadcast", label: "ARP Request: Who has 10.0.0.1?", desc: "Host broadcasts asking for MAC of target IP" },
    { from: "Host B (10.0.0.1)", to: "Host A", label: "ARP Reply: 10.0.0.1 is at aa:bb:cc:dd:ee:ff", desc: "Target responds with its MAC address" },
  ],
  "Kerberos Authentication": [
    { from: "Client", to: "KDC (AS)", label: "AS-REQ (username)", desc: "Client requests TGT from Authentication Service" },
    { from: "KDC (AS)", to: "Client", label: "AS-REP (TGT encrypted with krbtgt hash)", desc: "KDC issues Ticket Granting Ticket" },
    { from: "Client", to: "KDC (TGS)", label: "TGS-REQ (TGT + SPN)", desc: "Client requests service ticket using TGT" },
    { from: "KDC (TGS)", to: "Client", label: "TGS-REP (Service Ticket)", desc: "KDC issues ticket for the requested service" },
    { from: "Client", to: "Service", label: "AP-REQ (Service Ticket)", desc: "Client presents service ticket to the server" },
    { from: "Service", to: "Client", label: "AP-REP (optional mutual auth)", desc: "Service optionally authenticates itself back" },
  ],
};

// ─── Subnet calculator ────────────────────────────────────────────────────
function calcSubnet(cidr) {
  var parts = cidr.split("/");
  var ip = parts[0];
  var prefix = parseInt(parts[1]) || 24;
  if (prefix < 0 || prefix > 32) prefix = 24;
  var ipNum = ipToNum(ip);
  var mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  var network = (ipNum & mask) >>> 0;
  var broadcast = (network | ~mask) >>> 0;
  var firstHost = prefix >= 31 ? network : (network + 1) >>> 0;
  var lastHost = prefix >= 31 ? broadcast : (broadcast - 1) >>> 0;
  var totalHosts = prefix >= 31 ? (prefix === 32 ? 1 : 2) : Math.pow(2, 32 - prefix) - 2;
  return {
    network: numToIp(network), broadcast: numToIp(broadcast), netmask: numToIp(mask),
    wildcardMask: numToIp((~mask) >>> 0), firstHost: numToIp(firstHost), lastHost: numToIp(lastHost),
    totalHosts: totalHosts, prefix: prefix, cidr: numToIp(network) + "/" + prefix,
    binaryMask: mask.toString(2).padStart(32, "0").match(/.{8}/g).join("."),
  };
}

function ipToNum(ip) {
  var parts = ip.split(".").map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function numToIp(num) {
  return [(num >>> 24) & 0xFF, (num >>> 16) & 0xFF, (num >>> 8) & 0xFF, num & 0xFF].join(".");
}

// ─── VLSM calculator ──────────────────────────────────────────────────────
function vlsmCalc(baseNetwork, subnets) {
  var sorted = subnets.slice().sort(function(a, b) { return b.hosts - a.hosts; });
  var results = [];
  var currentIp = ipToNum(baseNetwork.split("/")[0]);
  var basePrefix = parseInt(baseNetwork.split("/")[1]) || 24;
  var baseEnd = (currentIp + Math.pow(2, 32 - basePrefix)) >>> 0;
  for (var i = 0; i < sorted.length; i++) {
    var needed = sorted[i].hosts + 2;
    var bits = Math.ceil(Math.log2(needed));
    if (bits < 2) bits = 2;
    var prefix = 32 - bits;
    var subnetSize = Math.pow(2, bits);
    var alignment = subnetSize;
    if (currentIp % alignment !== 0) currentIp = (Math.ceil(currentIp / alignment) * alignment) >>> 0;
    if ((currentIp + subnetSize) > baseEnd) { results.push({ name: sorted[i].name, error: "Not enough address space" }); continue; }
    results.push({ name: sorted[i].name, requestedHosts: sorted[i].hosts, network: numToIp(currentIp), prefix: prefix,
      cidr: numToIp(currentIp) + "/" + prefix, broadcast: numToIp((currentIp + subnetSize - 1) >>> 0),
      firstHost: numToIp((currentIp + 1) >>> 0), lastHost: numToIp((currentIp + subnetSize - 2) >>> 0),
      usableHosts: subnetSize - 2, waste: subnetSize - 2 - sorted[i].hosts });
    currentIp = (currentIp + subnetSize) >>> 0;
  }
  return results;
}

// ─── Nmap output parser ───────────────────────────────────────────────────
function parseNmapOutput(text) {
  var hosts = [];
  var grepLines = text.split("\n").filter(function(l) { return l.indexOf("Host:") >= 0 && l.indexOf("Ports:") >= 0; });
  if (grepLines.length) {
    for (var i = 0; i < grepLines.length; i++) {
      var hostMatch = grepLines[i].match(/Host:\s+([\d.]+)\s+\(([^)]*)\)/);
      if (!hostMatch) continue;
      var ports = [];
      var portsMatch = grepLines[i].match(/Ports:\s+(.+?)(?:\t|$)/);
      if (portsMatch) {
        var portEntries = portsMatch[1].split(",");
        for (var p = 0; p < portEntries.length; p++) {
          var pp = portEntries[p].trim().split("/");
          if (pp.length >= 5 && pp[1] === "open") ports.push(parseInt(pp[0]) || 0);
        }
      }
      var osMatch = grepLines[i].match(/OS:\s+(.+?)(?:\t|$)/);
      hosts.push({ ip: hostMatch[1], hostname: hostMatch[2] || "", ports: ports, os: guessOS(osMatch ? osMatch[1] : "", ports) });
    }
    return hosts;
  }
  var blocks = text.split(/Nmap scan report for /);
  for (var b = 1; b < blocks.length; b++) {
    var block = blocks[b];
    var firstLine = block.split("\n")[0];
    var ip2 = "", hostname2 = "";
    var ipMatch = firstLine.match(/([\d.]+)/);
    if (ipMatch) ip2 = ipMatch[1];
    var hnMatch = firstLine.match(/^([^\s(]+)/);
    if (hnMatch && hnMatch[1] !== ip2) hostname2 = hnMatch[1];
    var ports2 = [];
    var portLines = block.split("\n").filter(function(l) { return /^\d+\/tcp\s+open/.test(l.trim()); });
    for (var pl = 0; pl < portLines.length; pl++) { var pn = parseInt(portLines[pl].trim()); if (pn) ports2.push(pn); }
    if (ip2) hosts.push({ ip: ip2, hostname: hostname2, ports: ports2, os: guessOS("", ports2) });
  }
  return hosts;
}

function guessOS(osStr, ports) {
  osStr = (osStr || "").toLowerCase();
  if (osStr.indexOf("windows") >= 0) return "windows";
  if (osStr.indexOf("linux") >= 0) return "linux";
  if (osStr.indexOf("mac") >= 0 || osStr.indexOf("darwin") >= 0) return "macos";
  if (osStr.indexOf("cisco") >= 0) return "cisco";
  if (ports.indexOf(135) >= 0 || ports.indexOf(445) >= 0 || ports.indexOf(3389) >= 0) return "windows";
  if (ports.indexOf(22) >= 0 && ports.indexOf(445) < 0) return "linux";
  return "unknown";
}

// ─── Risk scoring ──────────────────────────────────────────────────────────
function calculateRisk(node) {
  var score = 0, details = [];
  for (var i = 0; i < (node.ports || []).length; i++) {
    var port = node.ports[i], info = PORT_DB[port];
    if (info) { score += info.risk; if (info.risk >= 3) details.push(info.name + " (port " + port + "): " + info.vuln); }
    else score += 1;
  }
  if ((node.ports || []).length > 10) { score += 3; details.push("Large attack surface (" + node.ports.length + " ports)"); }
  var level = score <= 3 ? "low" : (score <= 8 ? "medium" : (score <= 15 ? "high" : "critical"));
  return { score: score, level: level, details: details };
}

function riskColor(level) {
  if (level === "low") return "#2ecc71";
  if (level === "medium") return "#f39c12";
  if (level === "high") return "#e74c3c";
  return "#c0392b";
}

// ─── Firewall rule analyzer ────────────────────────────────────────────────
function parseACL(text) {
  var rules = [];
  var lines = text.split("\n");
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (!line || line.charAt(0) === "#" || line.charAt(0) === "!") continue;
    var m = line.match(/^(permit|deny|allow|drop|reject)\s+(tcp|udp|icmp|ip|any)\s+([\d./]+|any|host\s+[\d.]+)\s+([\d./]+|any|host\s+[\d.]+)(?:\s+(?:eq|port)\s+(\d+))?/i);
    if (m) {
      rules.push({ action: m[1].toLowerCase(), protocol: m[2].toLowerCase(), src: m[3].replace(/host\s+/i, ""), dst: m[4].replace(/host\s+/i, ""), port: m[5] ? parseInt(m[5]) : null, raw: line });
    } else {
      var im = line.match(/-A\s+(\w+).*?(?:-s\s+([\d./]+))?.*?(?:-d\s+([\d./]+))?.*?(?:-p\s+(\w+))?.*?(?:--dport\s+(\d+))?.*?-j\s+(\w+)/i);
      if (im) {
        rules.push({ action: im[6].toLowerCase() === "accept" ? "permit" : "deny", protocol: im[4] || "any", src: im[2] || "any", dst: im[3] || "any", port: im[5] ? parseInt(im[5]) : null, chain: im[1], raw: line });
      }
    }
  }
  return rules;
}

// ─── Canvas-based network diagram ──────────────────────────────────────────
function drawNetwork(canvas, nodes, edges, state) {
  var ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  var ox = state.panX || 0, oy = state.panY || 0, scale = state.zoom || 1;
  ctx.save();
  ctx.translate(ox, oy);
  ctx.scale(scale, scale);

  ctx.strokeStyle = "rgba(150,150,150,0.4)";
  ctx.lineWidth = 1.5;
  for (var e = 0; e < edges.length; e++) {
    var fromNode = nodes.find(function(n) { return n.id === edges[e].from; });
    var toNode = nodes.find(function(n) { return n.id === edges[e].to; });
    if (fromNode && toNode) { ctx.beginPath(); ctx.moveTo(fromNode.x, fromNode.y); ctx.lineTo(toNode.x, toNode.y); ctx.stroke(); }
  }

  for (var n = 0; n < nodes.length; n++) {
    var node = nodes[n], risk = calculateRisk(node), osInfo = OS_ICONS[node.os] || OS_ICONS.unknown;
    var selected = state.selected === node.id, radius = 22;
    ctx.beginPath(); ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
    ctx.fillStyle = selected ? "#fff" : osInfo.color; ctx.fill();
    ctx.lineWidth = selected ? 3 : 2; ctx.strokeStyle = selected ? "#f1c40f" : riskColor(risk.level); ctx.stroke();
    ctx.fillStyle = selected ? osInfo.color : "#fff"; ctx.font = "bold 16px monospace"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillText(osInfo.icon, node.x, node.y);
    ctx.fillStyle = "#ccc"; ctx.font = "11px sans-serif";
    ctx.fillText(node.hostname || node.ip, node.x, node.y + radius + 14);
    ctx.beginPath(); ctx.arc(node.x + radius - 4, node.y - radius + 4, 5, 0, Math.PI * 2);
    ctx.fillStyle = riskColor(risk.level); ctx.fill();
  }
  ctx.restore();
}

// ─── Main render function ──────────────────────────────────────────────────
export function renderNetworkMapper(main) {
  var nodes = [], edges = [], activeTab = "map", selectedNode = null;
  var canvasState = { panX: 20, panY: 20, zoom: 1, dragging: null, panning: false, lastX: 0, lastY: 0 };
  var subnetInput = "192.168.1.0/24";
  var vlsmInput = [{ name: "Servers", hosts: 50 }, { name: "Workstations", hosts: 200 }, { name: "Management", hosts: 10 }];
  var aclInput = "", nmapInput = "", selectedFlow = "TCP 3-Way Handshake";

  function render() {
    var html = '<h1 class="pg-h1">Network Mapper</h1>';
    html += '<p class="muted pg-sub">Topology visualization, subnet calculator, attack surface analysis, and nmap import. All processing runs locally.</p>';
    html += '<div class="tool-intro">';
    html += '<h2>Network Mapper</h2>';
    html += '<p>Visualizes network topology, shows open ports, and maps services across hosts. Great for understanding your network layout.</p>';
    html += '<div class="tool-steps">';
    html += '<div class="tool-step"><span class="step-num">1</span><div class="step-text"><strong>Enter a target or load a demo</strong>Add hosts manually, import nmap output, or load a template</div></div>';
    html += '<div class="tool-step"><span class="step-num">2</span><div class="step-text"><strong>Run the scan</strong>View hosts, ports, and services on the interactive map</div></div>';
    html += '<div class="tool-step"><span class="step-num">3</span><div class="step-text"><strong>Explore the map</strong>Drag nodes to rearrange, click for details, and analyze attack surface</div></div>';
    html += '</div></div>';
    var tabs = [
      { id: "map", label: "Network Map" }, { id: "hosts", label: "Hosts (" + nodes.length + ")" },
      { id: "subnet", label: "Subnet Calc" }, { id: "vlsm", label: "VLSM" },
      { id: "templates", label: "Templates" }, { id: "import", label: "Import Nmap" },
      { id: "attacks", label: "Attack Surface" }, { id: "firewall", label: "Firewall" },
      { id: "flows", label: "Protocol Flows" }, { id: "export", label: "Export" },
    ];
    html += '<div class="pc-tabs">';
    for (var t = 0; t < tabs.length; t++) html += '<button class="pc-tab' + (activeTab === tabs[t].id ? " on" : "") + '" data-tab="' + tabs[t].id + '">' + esc(tabs[t].label) + '</button>';
    html += '</div><div class="pc-body">';

    if (activeTab === "map") html += renderMap();
    else if (activeTab === "hosts") html += renderHosts();
    else if (activeTab === "subnet") html += renderSubnetCalc();
    else if (activeTab === "vlsm") html += renderVLSMTab();
    else if (activeTab === "templates") html += renderTemplatesTab();
    else if (activeTab === "import") html += renderImport();
    else if (activeTab === "attacks") html += renderAttackSurface();
    else if (activeTab === "firewall") html += renderFirewall();
    else if (activeTab === "flows") html += renderFlows();
    else if (activeTab === "export") html += renderExportTab();
    html += '</div>';
    main.innerHTML = html;
    wireEvents();
    if (activeTab === "map") {
      var canvas = main.querySelector("#nm-canvas");
      if (canvas) { canvas.width = canvas.parentElement.clientWidth; canvas.height = 500; canvasState.selected = selectedNode; drawNetwork(canvas, nodes, edges, canvasState); wireCanvas(canvas); }
    }
  }

  function renderMap() {
    var html = '<div class="nm-map-wrap">';
    html += '<div class="nm-map-toolbar"><button class="btn" id="nm-zoom-in">+</button><button class="btn" id="nm-zoom-out">-</button><button class="btn" id="nm-zoom-fit">Fit</button><button class="btn" id="nm-add-host">+ Add Host</button>';
    html += '<span class="muted nm-map-info">' + nodes.length + ' hosts, ' + edges.length + ' connections | Drag to reposition. Scroll to zoom.</span></div>';
    html += '<canvas id="nm-canvas" class="nm-canvas"></canvas>';
    if (selectedNode) {
      var node = nodes.find(function(n) { return n.id === selectedNode; });
      if (node) {
        var risk = calculateRisk(node);
        html += '<div class="nm-detail"><div class="nm-detail-header"><h3>' + esc(node.hostname || node.ip) + '</h3>';
        html += '<span class="nm-risk-badge" style="background:' + riskColor(risk.level) + '">' + risk.level.toUpperCase() + ' (' + risk.score + ')</span>';
        html += '<button class="btn nm-del-btn" id="nm-del-node">Delete</button></div>';
        html += '<div class="nm-detail-grid"><div><strong>IP:</strong> ' + esc(node.ip) + '</div><div><strong>OS:</strong> ' + esc(node.os) + '</div>';
        html += '<div><strong>Ports:</strong> ' + (node.ports || []).map(function(p) { var info = PORT_DB[p]; return p + (info ? " (" + info.name + ")" : ""); }).join(", ") + '</div>';
        if (risk.details.length) { html += '<div class="nm-vulns"><strong>Vulnerabilities:</strong>'; for (var d = 0; d < risk.details.length; d++) html += '<div class="nm-vuln-item">' + esc(risk.details[d]) + '</div>'; html += '</div>'; }
        html += '</div></div>';
      }
    }
    html += '</div>';
    return html;
  }

  function renderHosts() {
    var html = '<div class="nm-hosts"><button class="btn" id="nm-add-host2">+ Add Host</button>';
    if (!nodes.length) { html += '<div class="muted" style="margin:20px 0">No hosts yet. Add manually, import nmap, or load a template.</div>'; }
    else {
      html += '<table class="pc-table"><thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Ports</th><th>Risk</th><th></th></tr></thead><tbody>';
      for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i], risk = calculateRisk(n);
        html += '<tr><td><code>' + esc(n.ip) + '</code></td><td>' + esc(n.hostname) + '</td><td>' + esc(n.os) + '</td><td>' + (n.ports || []).join(", ") + '</td><td style="color:' + riskColor(risk.level) + '">' + risk.level.toUpperCase() + '</td><td><button class="btn nm-del-host" data-id="' + esc(n.id) + '">X</button></td></tr>';
      }
      html += '</tbody></table>';
    }
    html += '</div>';
    return html;
  }

  function renderSubnetCalc() {
    var result = null;
    try { result = calcSubnet(subnetInput); } catch (_) {}
    var html = '<div class="nm-subnet"><h3>Subnet Calculator</h3>';
    html += '<div class="nm-subnet-input"><label class="pc-label">CIDR Notation</label><input class="pc-input" id="nm-cidr" value="' + esc(subnetInput) + '" placeholder="192.168.1.0/24"></div>';
    if (result) {
      html += '<table class="pc-table"><tbody>';
      html += '<tr><td>Network</td><td><code>' + esc(result.network) + '</code></td></tr>';
      html += '<tr><td>Broadcast</td><td><code>' + esc(result.broadcast) + '</code></td></tr>';
      html += '<tr><td>Subnet Mask</td><td><code>' + esc(result.netmask) + '</code></td></tr>';
      html += '<tr><td>Wildcard</td><td><code>' + esc(result.wildcardMask) + '</code></td></tr>';
      html += '<tr><td>Binary Mask</td><td><code>' + esc(result.binaryMask) + '</code></td></tr>';
      html += '<tr><td>First Host</td><td><code>' + esc(result.firstHost) + '</code></td></tr>';
      html += '<tr><td>Last Host</td><td><code>' + esc(result.lastHost) + '</code></td></tr>';
      html += '<tr><td>Usable Hosts</td><td><strong>' + result.totalHosts.toLocaleString() + '</strong></td></tr>';
      html += '</tbody></table>';
      html += '<h4 style="margin-top:20px">Common Subnets</h4><table class="pc-table"><thead><tr><th>CIDR</th><th>Mask</th><th>Hosts</th><th>Use</th></tr></thead><tbody>';
      var common = [
        ["/32","255.255.255.255","1","Host route"],["/31","255.255.255.254","2","Point-to-point"],
        ["/30","255.255.255.252","2","P2P legacy"],["/29","255.255.255.248","6","Small office"],
        ["/28","255.255.255.240","14","Small subnet"],["/27","255.255.255.224","30","Server VLAN"],
        ["/26","255.255.255.192","62","Department"],["/25","255.255.255.128","126","Floor"],
        ["/24","255.255.255.0","254","Standard"],["/22","255.255.252.0","1022","Campus"],
        ["/16","255.255.0.0","65534","Enterprise"],["/8","255.0.0.0","16M+","Massive"],
      ];
      for (var c = 0; c < common.length; c++) html += '<tr><td><code>' + common[c][0] + '</code></td><td><code>' + common[c][1] + '</code></td><td>' + common[c][2] + '</td><td>' + common[c][3] + '</td></tr>';
      html += '</tbody></table>';
    }
    html += '</div>';
    return html;
  }

  function renderVLSMTab() {
    var html = '<div class="nm-vlsm"><h3>VLSM Calculator</h3>';
    html += '<div class="nm-vlsm-input"><label class="pc-label">Base Network</label><input class="pc-input" id="nm-vlsm-base" value="192.168.1.0/24">';
    html += '<h4>Subnets</h4><div id="nm-vlsm-list">';
    for (var i = 0; i < vlsmInput.length; i++) {
      html += '<div class="nm-vlsm-row"><input class="pc-input" value="' + esc(vlsmInput[i].name) + '" data-idx="' + i + '" data-field="name"><input class="pc-input" type="number" value="' + vlsmInput[i].hosts + '" data-idx="' + i + '" data-field="hosts" min="1" style="width:80px"><button class="btn nm-vlsm-del" data-idx="' + i + '">X</button></div>';
    }
    html += '</div><button class="btn" id="nm-vlsm-add">+ Add Subnet</button></div>';
    var results = vlsmCalc("192.168.1.0/24", vlsmInput);
    if (results.length) {
      html += '<table class="pc-table"><thead><tr><th>Name</th><th>Needed</th><th>CIDR</th><th>Usable</th><th>Broadcast</th><th>Waste</th></tr></thead><tbody>';
      for (var r = 0; r < results.length; r++) {
        var res = results[r];
        if (res.error) html += '<tr><td>' + esc(res.name) + '</td><td colspan="5">' + esc(res.error) + '</td></tr>';
        else html += '<tr><td>' + esc(res.name) + '</td><td>' + res.requestedHosts + '</td><td><code>' + esc(res.cidr) + '</code></td><td>' + res.usableHosts + '</td><td><code>' + esc(res.broadcast) + '</code></td><td>' + res.waste + '</td></tr>';
      }
      html += '</tbody></table>';
    }
    html += '</div>';
    return html;
  }

  function renderTemplatesTab() {
    var names = Object.keys(TOPOLOGY_TEMPLATES);
    var html = '<div class="nm-templates"><h3>Topology Templates</h3><div class="pc-tpl-grid">';
    for (var i = 0; i < names.length; i++) {
      var tpl = TOPOLOGY_TEMPLATES[names[i]];
      html += '<div class="pc-tpl-card"><div class="pc-tpl-name">' + esc(names[i]) + '</div><div class="pc-tpl-desc">' + esc(tpl.desc) + '</div><div class="muted">' + tpl.nodes.length + ' hosts, ' + tpl.edges.length + ' edges</div><button class="btn pc-tpl-btn nm-load-tpl" data-tpl="' + esc(names[i]) + '">Load</button></div>';
    }
    html += '</div></div>';
    return html;
  }

  function renderImport() {
    var html = '<div class="nm-import"><h3>Import Nmap Output</h3><p class="muted">Paste nmap -oN or -oG output.</p>';
    html += '<textarea class="pc-textarea" id="nm-nmap-input" rows="12" placeholder="Paste nmap output here...">' + esc(nmapInput) + '</textarea>';
    html += '<button class="btn" id="nm-nmap-parse">Parse &amp; Import</button></div>';
    return html;
  }

  function renderAttackSurface() {
    var html = '<div class="nm-attacks"><h3>Attack Surface Analysis</h3>';
    if (nodes.length) {
      var riskCounts = { low: 0, medium: 0, high: 0, critical: 0 };
      for (var i = 0; i < nodes.length; i++) riskCounts[calculateRisk(nodes[i]).level]++;
      html += '<div class="nm-risk-summary">';
      html += '<div class="nm-risk-card" style="border-color:#2ecc71"><span class="nm-risk-num">' + riskCounts.low + '</span><span class="nm-risk-label">Low</span></div>';
      html += '<div class="nm-risk-card" style="border-color:#f39c12"><span class="nm-risk-num">' + riskCounts.medium + '</span><span class="nm-risk-label">Medium</span></div>';
      html += '<div class="nm-risk-card" style="border-color:#e74c3c"><span class="nm-risk-num">' + riskCounts.high + '</span><span class="nm-risk-label">High</span></div>';
      html += '<div class="nm-risk-card" style="border-color:#c0392b"><span class="nm-risk-num">' + riskCounts.critical + '</span><span class="nm-risk-label">Critical</span></div></div>';
      var highRisk = nodes.map(function(n) { return { node: n, risk: calculateRisk(n) }; }).filter(function(r) { return r.risk.level === "high" || r.risk.level === "critical"; }).sort(function(a, b) { return b.risk.score - a.risk.score; });
      if (highRisk.length) {
        html += '<h4>High/Critical Hosts</h4><table class="pc-table"><thead><tr><th>Host</th><th>IP</th><th>Risk</th><th>Issues</th></tr></thead><tbody>';
        for (var h = 0; h < highRisk.length; h++) {
          var hr = highRisk[h];
          html += '<tr><td>' + esc(hr.node.hostname || hr.node.ip) + '</td><td><code>' + esc(hr.node.ip) + '</code></td><td style="color:' + riskColor(hr.risk.level) + '">' + hr.risk.level.toUpperCase() + '</td><td>' + hr.risk.details.map(function(d) { return '<div class="nm-vuln-item">' + esc(d) + '</div>'; }).join("") + '</td></tr>';
        }
        html += '</tbody></table>';
      }
    } else { html += '<div class="muted">Add hosts to analyze.</div>'; }
    html += '<h4>Common Attack Patterns</h4><table class="pc-table"><thead><tr><th>Attack</th><th>Zone</th><th>Requirements</th><th>MITRE</th></tr></thead><tbody>';
    for (var a = 0; a < ATTACK_PATTERNS.length; a++) {
      var atk = ATTACK_PATTERNS[a];
      html += '<tr><td><strong>' + esc(atk.name) + '</strong></td><td>' + esc(atk.zone) + '</td><td>' + esc(atk.req) + '</td><td><code>' + esc(atk.mitre) + '</code></td></tr>';
    }
    html += '</tbody></table></div>';
    return html;
  }

  function renderFirewall() {
    var html = '<div class="nm-firewall"><h3>Firewall Rule Analyzer</h3><p class="muted">Paste Cisco ACL or iptables rules.</p>';
    html += '<textarea class="pc-textarea" id="nm-acl-input" rows="10" placeholder="permit tcp any 10.0.1.0/24 eq 80\ndeny ip any any">' + esc(aclInput) + '</textarea>';
    html += '<button class="btn" id="nm-acl-parse">Analyze</button>';
    if (aclInput) {
      var rules = parseACL(aclInput);
      if (rules.length) {
        html += '<h4>Parsed (' + rules.length + ')</h4><table class="pc-table"><thead><tr><th>#</th><th>Action</th><th>Proto</th><th>Src</th><th>Dst</th><th>Port</th></tr></thead><tbody>';
        for (var r = 0; r < rules.length; r++) {
          var rule = rules[r], cls = rule.action === "permit" || rule.action === "allow" ? "nm-rule-permit" : "nm-rule-deny";
          html += '<tr class="' + cls + '"><td>' + (r + 1) + '</td><td><strong>' + rule.action.toUpperCase() + '</strong></td><td>' + esc(rule.protocol) + '</td><td><code>' + esc(rule.src) + '</code></td><td><code>' + esc(rule.dst) + '</code></td><td>' + (rule.port || "any") + '</td></tr>';
        }
        html += '</tbody></table>';
        var hasDefaultDeny = rules.length > 0 && (rules[rules.length - 1].action === "deny" || rules[rules.length - 1].action === "drop") && rules[rules.length - 1].src === "any";
        html += '<div class="nm-acl-summary">' + (hasDefaultDeny ? '<span class="pc-ck-ok">Default deny (good)</span>' : '<span class="pc-ck-fail">No default deny!</span>') + '</div>';
      }
    }
    html += '</div>';
    return html;
  }

  function renderFlows() {
    var flowNames = Object.keys(PROTOCOL_FLOWS);
    var html = '<div class="nm-flows"><h3>Protocol Flow Diagrams</h3><div class="nm-flow-tabs">';
    for (var f = 0; f < flowNames.length; f++) html += '<button class="pc-tab' + (selectedFlow === flowNames[f] ? " on" : "") + '" data-flow="' + esc(flowNames[f]) + '">' + esc(flowNames[f]) + '</button>';
    html += '</div><div class="nm-flow-diagram">';
    var flow = PROTOCOL_FLOWS[selectedFlow] || [];
    for (var s = 0; s < flow.length; s++) {
      var step = flow[s], isLeft = s % 2 === 0;
      html += '<div class="nm-flow-step"><div class="nm-flow-from">' + esc(step.from) + '</div>';
      html += '<div class="nm-flow-arrow' + (isLeft ? "" : " nm-flow-arrow-rev") + '"><div class="nm-flow-label">' + esc(step.label) + '</div><div class="nm-flow-line">' + (isLeft ? "&#x2192;" : "&#x2190;") + '</div></div>';
      html += '<div class="nm-flow-to">' + esc(step.to) + '</div><div class="nm-flow-desc">' + esc(step.desc) + '</div></div>';
    }
    html += '</div></div>';
    return html;
  }

  function renderExportTab() {
    var json = JSON.stringify({ nodes: nodes, edges: edges }, null, 2);
    var html = '<div class="nm-export"><h3>Export Topology</h3><pre class="pc-hex" style="max-height:400px;overflow:auto">' + esc(json) + '</pre>';
    html += '<button class="btn" id="nm-copy-json">Copy JSON</button></div>';
    return html;
  }

  function wireEvents() {
    var tabs = main.querySelector(".pc-tabs");
    if (tabs) tabs.onclick = function(e) { var btn = e.target.closest(".pc-tab"); if (btn && btn.dataset.tab) { activeTab = btn.dataset.tab; render(); } };
    var cidrInput = main.querySelector("#nm-cidr");
    if (cidrInput) cidrInput.oninput = function() { subnetInput = cidrInput.value; render(); };
    var tplBtns = main.querySelectorAll(".nm-load-tpl");
    for (var t = 0; t < tplBtns.length; t++) tplBtns[t].onclick = function(e) {
      var tpl = TOPOLOGY_TEMPLATES[e.target.dataset.tpl];
      if (tpl) { nodes = JSON.parse(JSON.stringify(tpl.nodes)); edges = JSON.parse(JSON.stringify(tpl.edges)); activeTab = "map"; render(); }
    };
    var nmapParse = main.querySelector("#nm-nmap-parse");
    if (nmapParse) nmapParse.onclick = function() {
      var ta = main.querySelector("#nm-nmap-input"); if (!ta) return;
      nmapInput = ta.value;
      var parsed = parseNmapOutput(nmapInput);
      if (parsed.length) {
        var cols = Math.ceil(Math.sqrt(parsed.length));
        for (var i = 0; i < parsed.length; i++) {
          if (!nodes.find(function(n) { return n.ip === parsed[i].ip; })) {
            nodes.push({ id: "nmap-" + i + "-" + Date.now(), ip: parsed[i].ip, hostname: parsed[i].hostname || "", os: parsed[i].os, ports: parsed[i].ports, x: 80 + (i % cols) * 150, y: 80 + Math.floor(i / cols) * 120 });
          }
        }
        activeTab = "map"; render();
      }
    };
    var addBtn = main.querySelector("#nm-add-host") || main.querySelector("#nm-add-host2");
    if (addBtn) addBtn.onclick = function() {
      var ip = prompt("IP:", "10.0.0." + (nodes.length + 1)); if (!ip) return;
      var hostname = prompt("Hostname:", "host-" + (nodes.length + 1));
      var os = prompt("OS (linux/windows/router/firewall/switch):", "linux");
      var portsStr = prompt("Ports (comma-sep):", "22,80,443");
      nodes.push({ id: "m-" + Date.now(), ip: ip, hostname: hostname || "", os: os || "unknown", ports: portsStr ? portsStr.split(",").map(function(p) { return parseInt(p.trim()); }).filter(Boolean) : [], x: 100 + Math.random() * 500, y: 100 + Math.random() * 300 });
      render();
    };
    var delNode = main.querySelector("#nm-del-node");
    if (delNode) delNode.onclick = function() { nodes = nodes.filter(function(n) { return n.id !== selectedNode; }); edges = edges.filter(function(e) { return e.from !== selectedNode && e.to !== selectedNode; }); selectedNode = null; render(); };
    var delBtns = main.querySelectorAll(".nm-del-host");
    for (var d = 0; d < delBtns.length; d++) delBtns[d].onclick = function(e) { var id = e.target.dataset.id; nodes = nodes.filter(function(n) { return n.id !== id; }); edges = edges.filter(function(e2) { return e2.from !== id && e2.to !== id; }); render(); };
    var zoomIn = main.querySelector("#nm-zoom-in"), zoomOut = main.querySelector("#nm-zoom-out"), zoomFit = main.querySelector("#nm-zoom-fit");
    if (zoomIn) zoomIn.onclick = function() { canvasState.zoom = Math.min(3, canvasState.zoom * 1.2); var c = main.querySelector("#nm-canvas"); if (c) drawNetwork(c, nodes, edges, canvasState); };
    if (zoomOut) zoomOut.onclick = function() { canvasState.zoom = Math.max(0.3, canvasState.zoom / 1.2); var c = main.querySelector("#nm-canvas"); if (c) drawNetwork(c, nodes, edges, canvasState); };
    if (zoomFit) zoomFit.onclick = function() { canvasState.zoom = 1; canvasState.panX = 20; canvasState.panY = 20; var c = main.querySelector("#nm-canvas"); if (c) drawNetwork(c, nodes, edges, canvasState); };
    var aclParse = main.querySelector("#nm-acl-parse");
    if (aclParse) aclParse.onclick = function() { var ta = main.querySelector("#nm-acl-input"); if (ta) { aclInput = ta.value; render(); } };
    var flowBtns = main.querySelectorAll("[data-flow]");
    for (var fb = 0; fb < flowBtns.length; fb++) flowBtns[fb].onclick = function(e) { selectedFlow = e.target.dataset.flow; render(); };
    var vlsmAdd = main.querySelector("#nm-vlsm-add");
    if (vlsmAdd) vlsmAdd.onclick = function() { vlsmInput.push({ name: "Subnet-" + (vlsmInput.length + 1), hosts: 50 }); render(); };
    var vlsmDels = main.querySelectorAll(".nm-vlsm-del");
    for (var vd = 0; vd < vlsmDels.length; vd++) vlsmDels[vd].onclick = function(e) { vlsmInput.splice(parseInt(e.target.dataset.idx), 1); render(); };
    var copyJson = main.querySelector("#nm-copy-json");
    if (copyJson) copyJson.onclick = function() { navigator.clipboard.writeText(JSON.stringify({ nodes: nodes, edges: edges }, null, 2)).then(function() { copyJson.textContent = "Copied!"; setTimeout(function() { copyJson.textContent = "Copy JSON"; }, 2000); }); };
  }

  function wireCanvas(canvas) {
    canvas.onmousedown = function(e) {
      var rect = canvas.getBoundingClientRect();
      var mx = (e.clientX - rect.left - canvasState.panX) / canvasState.zoom, my = (e.clientY - rect.top - canvasState.panY) / canvasState.zoom;
      var clicked = null;
      for (var i = nodes.length - 1; i >= 0; i--) { var dx = mx - nodes[i].x, dy = my - nodes[i].y; if (dx * dx + dy * dy < 22 * 22) { clicked = nodes[i]; break; } }
      if (clicked) { canvasState.dragging = clicked.id; canvasState.dragOffX = mx - clicked.x; canvasState.dragOffY = my - clicked.y; selectedNode = clicked.id; canvasState.selected = clicked.id; drawNetwork(canvas, nodes, edges, canvasState); render(); }
      else { selectedNode = null; canvasState.selected = null; canvasState.panning = true; canvasState.lastX = e.clientX; canvasState.lastY = e.clientY; drawNetwork(canvas, nodes, edges, canvasState); }
    };
    canvas.onmousemove = function(e) {
      if (canvasState.dragging) { var rect = canvas.getBoundingClientRect(); var mx = (e.clientX - rect.left - canvasState.panX) / canvasState.zoom, my = (e.clientY - rect.top - canvasState.panY) / canvasState.zoom; var node = nodes.find(function(n) { return n.id === canvasState.dragging; }); if (node) { node.x = mx - canvasState.dragOffX; node.y = my - canvasState.dragOffY; drawNetwork(canvas, nodes, edges, canvasState); } }
      else if (canvasState.panning) { canvasState.panX += e.clientX - canvasState.lastX; canvasState.panY += e.clientY - canvasState.lastY; canvasState.lastX = e.clientX; canvasState.lastY = e.clientY; drawNetwork(canvas, nodes, edges, canvasState); }
    };
    canvas.onmouseup = canvas.onmouseleave = function() { canvasState.dragging = null; canvasState.panning = false; };
    canvas.onwheel = function(e) { e.preventDefault(); canvasState.zoom = Math.max(0.3, Math.min(3, canvasState.zoom * (e.deltaY < 0 ? 1.1 : 0.9))); drawNetwork(canvas, nodes, edges, canvasState); };
  }

  render();
}
