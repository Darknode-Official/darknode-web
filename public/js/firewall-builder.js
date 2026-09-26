// Firewall Rule Builder & Analyzer — interactive firewall rule management tool
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const PROTOCOLS = ["TCP", "UDP", "ICMP", "ANY"];
const ACTIONS = ["ACCEPT", "DROP", "REJECT", "LOG"];
const DIRECTIONS = ["INPUT", "OUTPUT", "FORWARD"];
const STATES = ["NEW", "ESTABLISHED", "RELATED", "INVALID"];

const ICMP_TYPES = [
  { type: 0, name: "echo-reply", desc: "Ping reply" },
  { type: 3, name: "destination-unreachable", desc: "Destination unreachable (host/port/network)" },
  { type: 4, name: "source-quench", desc: "Congestion control (deprecated)" },
  { type: 5, name: "redirect", desc: "Route redirect message" },
  { type: 8, name: "echo-request", desc: "Ping request" },
  { type: 11, name: "time-exceeded", desc: "TTL expired in transit or reassembly timeout" },
  { type: 12, name: "parameter-problem", desc: "Malformed packet header" },
  { type: 13, name: "timestamp-request", desc: "Timestamp request" },
  { type: 14, name: "timestamp-reply", desc: "Timestamp reply" },
  { type: 17, name: "address-mask-request", desc: "Subnet mask request (deprecated)" },
  { type: 18, name: "address-mask-reply", desc: "Subnet mask reply (deprecated)" },
];

const BOGON_RANGES = [
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
  "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
  "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
  "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
];

const SCENARIO_TEMPLATES = {
  "Web Server": [
    { src: "0.0.0.0/0", dst: "", port: "80", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow HTTP" },
    { src: "0.0.0.0/0", dst: "", port: "443", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow HTTPS" },
    { src: "", dst: "", port: "", proto: "TCP", action: "ACCEPT", dir: "OUTPUT", log: false, comment: "Allow outbound TCP" },
  ],
  "SSH Hardened": [
    { src: "10.0.0.0/8", dst: "", port: "22", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: true, comment: "Allow SSH from internal" },
    { src: "192.168.0.0/16", dst: "", port: "22", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: true, comment: "Allow SSH from private" },
    { src: "0.0.0.0/0", dst: "", port: "22", proto: "TCP", action: "DROP", dir: "INPUT", log: true, comment: "Drop SSH from all others" },
  ],
  "DNS Server": [
    { src: "0.0.0.0/0", dst: "", port: "53", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow DNS TCP" },
    { src: "0.0.0.0/0", dst: "", port: "53", proto: "UDP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow DNS UDP" },
  ],
  "Mail Server": [
    { src: "0.0.0.0/0", dst: "", port: "25", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow SMTP" },
    { src: "0.0.0.0/0", dst: "", port: "465", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow SMTPS" },
    { src: "0.0.0.0/0", dst: "", port: "587", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow submission" },
    { src: "0.0.0.0/0", dst: "", port: "993", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow IMAPS" },
    { src: "0.0.0.0/0", dst: "", port: "995", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow POP3S" },
  ],
  "Database (MySQL)": [
    { src: "10.0.0.0/8", dst: "", port: "3306", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: true, comment: "Allow MySQL from internal" },
    { src: "0.0.0.0/0", dst: "", port: "3306", proto: "TCP", action: "DROP", dir: "INPUT", log: true, comment: "Drop MySQL from external" },
  ],
  "Database (PostgreSQL)": [
    { src: "10.0.0.0/8", dst: "", port: "5432", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: true, comment: "Allow PostgreSQL from internal" },
    { src: "0.0.0.0/0", dst: "", port: "5432", proto: "TCP", action: "DROP", dir: "INPUT", log: true, comment: "Drop PostgreSQL from external" },
  ],
  "Database (MSSQL)": [
    { src: "10.0.0.0/8", dst: "", port: "1433", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: true, comment: "Allow MSSQL from internal" },
    { src: "0.0.0.0/0", dst: "", port: "1433", proto: "TCP", action: "DROP", dir: "INPUT", log: true, comment: "Drop MSSQL from external" },
  ],
  "VPN (OpenVPN)": [
    { src: "0.0.0.0/0", dst: "", port: "1194", proto: "UDP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow OpenVPN" },
  ],
  "VPN (WireGuard)": [
    { src: "0.0.0.0/0", dst: "", port: "51820", proto: "UDP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow WireGuard" },
  ],
  "Docker Host": [
    { src: "172.17.0.0/16", dst: "", port: "", proto: "ANY", action: "ACCEPT", dir: "FORWARD", log: false, comment: "Allow Docker bridge" },
    { src: "", dst: "172.17.0.0/16", port: "", proto: "ANY", action: "ACCEPT", dir: "FORWARD", log: false, comment: "Allow to Docker bridge" },
  ],
  "Kubernetes": [
    { src: "10.244.0.0/16", dst: "", port: "", proto: "ANY", action: "ACCEPT", dir: "FORWARD", log: false, comment: "Allow pod network" },
    { src: "0.0.0.0/0", dst: "", port: "6443", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: true, comment: "Allow K8s API" },
    { src: "0.0.0.0/0", dst: "", port: "10250", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow kubelet" },
    { src: "0.0.0.0/0", dst: "", port: "30000:32767", proto: "TCP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow NodePort range" },
  ],
  "Ping Only": [
    { src: "0.0.0.0/0", dst: "", port: "", proto: "ICMP", action: "ACCEPT", dir: "INPUT", log: false, comment: "Allow ICMP echo" },
  ],
  "Anti-Spoofing": BOGON_RANGES.map(r => ({
    src: r, dst: "", port: "", proto: "ANY", action: "DROP", dir: "INPUT", log: true, comment: "Drop bogon " + r
  })),
};

const HARDENING_CHECKLIST = [
  { item: "Set default INPUT policy to DROP", category: "Policy" },
  { item: "Set default FORWARD policy to DROP", category: "Policy" },
  { item: "Allow loopback (lo) interface traffic", category: "Essential" },
  { item: "Allow ESTABLISHED,RELATED connections", category: "Essential" },
  { item: "Rate-limit SSH connections (max 3/min per IP)", category: "Hardening" },
  { item: "Drop invalid packets", category: "Hardening" },
  { item: "Block bogon/RFC 1918 on WAN interface", category: "Hardening" },
  { item: "Enable SYN flood protection (SYN cookies)", category: "DDoS" },
  { item: "Limit ICMP rate to prevent ping flood", category: "DDoS" },
  { item: "Drop packets with invalid TCP flags (XMAS, NULL)", category: "Hardening" },
  { item: "Log dropped packets for analysis", category: "Logging" },
  { item: "Limit log rate to prevent log flooding", category: "Logging" },
  { item: "Restrict outbound to required ports only", category: "Egress" },
  { item: "Block outbound SMTP (25) except from mail server", category: "Egress" },
  { item: "Block outbound DNS to non-approved resolvers", category: "Egress" },
  { item: "Enable connection tracking timeout tuning", category: "Performance" },
  { item: "Use REJECT with tcp-reset for TCP, icmp-port-unreachable for UDP", category: "Best Practice" },
  { item: "Separate rules per interface (eth0, wlan0, etc.)", category: "Organization" },
  { item: "Document each rule with comments", category: "Organization" },
  { item: "Review and audit rules quarterly", category: "Maintenance" },
  { item: "Test rules in a staging environment first", category: "Maintenance" },
  { item: "Implement fail2ban for brute force protection", category: "Hardening" },
  { item: "Use nftables over iptables on modern systems", category: "Best Practice" },
  { item: "Disable IPv6 if not in use, or mirror IPv4 rules", category: "Best Practice" },
];

const OUTPUT_FORMATS = ["iptables", "nftables", "pf", "netsh", "cisco-acl", "aws-sg", "azure-nsg", "gcp-fw"];

function ipInCidr(ip, cidr) {
  if (!cidr || !ip) return false;
  var parts = cidr.split("/");
  var mask = parts[1] ? parseInt(parts[1], 10) : 32;
  var cidrParts = parts[0].split(".").map(Number);
  var ipParts = ip.split(".").map(Number);
  if (cidrParts.length !== 4 || ipParts.length !== 4) return false;
  var cidrNum = ((cidrParts[0] << 24) | (cidrParts[1] << 16) | (cidrParts[2] << 8) | cidrParts[3]) >>> 0;
  var ipNum = ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0;
  var maskNum = mask === 0 ? 0 : (0xFFFFFFFF << (32 - mask)) >>> 0;
  return (ipNum & maskNum) === (cidrNum & maskNum);
}

function portInRange(port, rangeStr) {
  if (!rangeStr || !port) return true;
  port = parseInt(port, 10);
  var ranges = rangeStr.split(",");
  for (var i = 0; i < ranges.length; i++) {
    var r = ranges[i].trim();
    if (r.indexOf(":") !== -1 || r.indexOf("-") !== -1) {
      var sep = r.indexOf(":") !== -1 ? ":" : "-";
      var lo = parseInt(r.split(sep)[0], 10);
      var hi = parseInt(r.split(sep)[1], 10);
      if (port >= lo && port <= hi) return true;
    } else {
      if (port === parseInt(r, 10)) return true;
    }
  }
  return false;
}

function ruleToIptables(r) {
  var cmd = "iptables -A " + r.dir;
  if (r.src) cmd += " -s " + r.src;
  if (r.dst) cmd += " -d " + r.dst;
  if (r.proto !== "ANY") cmd += " -p " + r.proto.toLowerCase();
  if (r.port && r.proto !== "ICMP" && r.proto !== "ANY") {
    // A comma-separated port list requires the multiport match; plain --dport
    // only accepts a single port or a lo:hi range.
    if (r.port.indexOf(",") !== -1) cmd += " -m multiport --dports " + r.port.replace(/\s+/g, "");
    else cmd += " --dport " + r.port;
  }
  if (r.states && r.states.length) cmd += " -m conntrack --ctstate " + r.states.join(",");
  if (r.log) cmd += " -j LOG --log-prefix \"FW-" + r.dir + ": \"";
  cmd += " -j " + r.action;
  if (r.comment) cmd += " -m comment --comment \"" + r.comment.replace(/"/g, "'") + "\"";
  return cmd;
}

function ruleToNftables(r) {
  var chain = r.dir.toLowerCase();
  var cmd = "nft add rule inet filter " + chain;
  if (r.src) cmd += " ip saddr " + r.src;
  if (r.dst) cmd += " ip daddr " + r.dst;
  if (r.proto !== "ANY") cmd += " " + r.proto.toLowerCase();
  if (r.port && r.proto !== "ICMP" && r.proto !== "ANY") {
    // nftables expresses a port list as an anonymous set { 80, 443 }.
    if (r.port.indexOf(",") !== -1) cmd += " dport { " + r.port.split(",").map(function(p) { return p.trim(); }).join(", ") + " }";
    else cmd += " dport " + r.port;
  }
  if (r.states && r.states.length) cmd += " ct state " + r.states.join(",").toLowerCase();
  var act = r.action.toLowerCase();
  if (act === "reject") act = "reject";
  if (r.log) cmd += " log prefix \"FW-" + chain + ": \"";
  cmd += " " + act;
  if (r.comment) cmd += " comment \"" + r.comment.replace(/"/g, "'") + "\"";
  return cmd;
}

function ruleToPf(r) {
  var act = r.action === "ACCEPT" ? "pass" : (r.action === "DROP" ? "block drop" : "block return");
  var dir = r.dir === "INPUT" ? "in" : (r.dir === "OUTPUT" ? "out" : "in");
  var cmd = act + " " + dir;
  if (r.log) cmd += " log";
  // pf is last-match-wins by default; these rules are emitted in first-match
  // (iptables) priority order, so each carries `quick` to stop evaluation on
  // the first match. Without it a trailing broad block overrides earlier passes.
  cmd += " quick";
  if (r.proto !== "ANY") cmd += " proto " + r.proto.toLowerCase();
  if (r.src) cmd += " from " + r.src; else cmd += " from any";
  if (r.dst) cmd += " to " + r.dst; else cmd += " to any";
  if (r.port && r.proto !== "ICMP" && r.proto !== "ANY") cmd += " port " + r.port;
  return cmd;
}

function ruleToNetsh(r) {
  var dir = r.dir === "INPUT" ? "in" : "out";
  var act = r.action === "ACCEPT" ? "allow" : "block";
  var cmd = "netsh advfirewall firewall add rule name=\"" + (r.comment || "Rule") + "\"";
  cmd += " dir=" + dir + " action=" + act;
  if (r.proto !== "ANY") cmd += " protocol=" + r.proto.toLowerCase();
  if (r.port && r.proto !== "ICMP") cmd += " localport=" + r.port;
  if (r.src && r.src !== "0.0.0.0/0") cmd += " remoteip=" + r.src;
  cmd += " enable=yes";
  return cmd;
}

function ruleToCiscoACL(r, num) {
  var act = r.action === "ACCEPT" ? "permit" : "deny";
  var proto = r.proto === "ANY" ? "ip" : r.proto.toLowerCase();
  var src = r.src || "any";
  var dst = r.dst || "any";
  if (src !== "any") {
    var sp = src.split("/");
    var mask = sp[1] ? parseInt(sp[1], 10) : 32;
    var wildcard = mask === 0 ? 0xFFFFFFFF : (((1 << (32 - mask)) - 1) >>> 0);
    var w3 = wildcard & 0xFF, w2 = (wildcard >> 8) & 0xFF, w1 = (wildcard >> 16) & 0xFF, w0 = (wildcard >>> 24) & 0xFF;
    src = sp[0] + " " + w0 + "." + w1 + "." + w2 + "." + w3;
  }
  if (dst !== "any") {
    var dp = dst.split("/");
    var dmask = dp[1] ? parseInt(dp[1], 10) : 32;
    var dwildcard = dmask === 0 ? 0xFFFFFFFF : (((1 << (32 - dmask)) - 1) >>> 0);
    var d3 = dwildcard & 0xFF, d2 = (dwildcard >> 8) & 0xFF, d1 = (dwildcard >> 16) & 0xFF, d0 = (dwildcard >>> 24) & 0xFF;
    dst = dp[0] + " " + d0 + "." + d1 + "." + d2 + "." + d3;
  }
  // All ACEs of one numbered ACL must share the same list number; a numbered
  // IOS ACL is a single top-down list, so every entry is "access-list 100 ...".
  var cmd = "access-list 100 " + act + " " + proto + " " + src + " " + dst;
  if (r.port && proto !== "icmp" && proto !== "ip") cmd += " eq " + r.port;
  if (r.log) cmd += " log";
  return cmd;
}

function ruleToAWS(r) {
  var entry = {
    IpProtocol: r.proto === "ANY" ? "-1" : r.proto.toLowerCase(),
    IpRanges: [{ CidrIp: r.src || "0.0.0.0/0" }],
  };
  if (r.port && r.proto !== "ICMP" && r.proto !== "ANY") {
    if (r.port.indexOf(":") !== -1 || r.port.indexOf("-") !== -1) {
      var sep = r.port.indexOf(":") !== -1 ? ":" : "-";
      entry.FromPort = parseInt(r.port.split(sep)[0], 10);
      entry.ToPort = parseInt(r.port.split(sep)[1], 10);
    } else {
      entry.FromPort = parseInt(r.port, 10);
      entry.ToPort = parseInt(r.port, 10);
    }
  }
  if (r.comment) entry.Description = r.comment;
  return entry;
}

function ruleToAzure(r) {
  return {
    name: (r.comment || "rule").replace(/[^a-zA-Z0-9_-]/g, "_"),
    properties: {
      protocol: r.proto === "ANY" ? "*" : r.proto,
      sourceAddressPrefix: r.src || "*",
      destinationAddressPrefix: r.dst || "*",
      destinationPortRange: r.port || "*",
      access: r.action === "ACCEPT" ? "Allow" : "Deny",
      direction: r.dir === "INPUT" ? "Inbound" : "Outbound",
      priority: 100,
    }
  };
}

function ruleToGCP(r) {
  var obj = {
    name: (r.comment || "rule").toLowerCase().replace(/[^a-z0-9-]/g, "-"),
    direction: r.dir === "INPUT" ? "INGRESS" : "EGRESS",
    action: r.action === "ACCEPT" ? "allow" : "deny",
    sourceRanges: r.src ? [r.src] : ["0.0.0.0/0"],
  };
  if (r.proto !== "ANY") {
    var allowed = { IPProtocol: r.proto.toLowerCase() };
    if (r.port) allowed.ports = [r.port];
    obj.allowed = [allowed];
  }
  return obj;
}

function generateOutput(rules, format) {
  var lines = [];
  if (format === "iptables") {
    lines.push("# Generated by Darknode Firewall Builder");
    lines.push("# Flush existing rules");
    lines.push("iptables -F");
    lines.push("iptables -X");
    lines.push("");
    lines.push("# Default policies");
    lines.push("iptables -P INPUT DROP");
    lines.push("iptables -P FORWARD DROP");
    lines.push("iptables -P OUTPUT ACCEPT");
    lines.push("");
    lines.push("# Allow loopback");
    lines.push("iptables -A INPUT -i lo -j ACCEPT");
    lines.push("iptables -A OUTPUT -o lo -j ACCEPT");
    lines.push("");
    lines.push("# Allow established connections");
    lines.push("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
    lines.push("");
    lines.push("# Custom rules");
    for (var i = 0; i < rules.length; i++) lines.push(ruleToIptables(rules[i]));
  } else if (format === "nftables") {
    lines.push("#!/usr/sbin/nft -f");
    lines.push("# Generated by Darknode Firewall Builder");
    lines.push("flush ruleset");
    lines.push("");
    lines.push("table inet filter {");
    lines.push("  chain input {");
    lines.push("    type filter hook input priority 0; policy drop;");
    lines.push("    iif lo accept");
    lines.push("    ct state established,related accept");
    for (var j = 0; j < rules.length; j++) {
      if (rules[j].dir === "INPUT") lines.push("    " + ruleToNftables(rules[j]).replace(/^nft add rule inet filter input /, ""));
    }
    lines.push("  }");
    lines.push("  chain forward {");
    lines.push("    type filter hook forward priority 0; policy drop;");
    for (var k = 0; k < rules.length; k++) {
      if (rules[k].dir === "FORWARD") lines.push("    " + ruleToNftables(rules[k]).replace(/^nft add rule inet filter forward /, ""));
    }
    lines.push("  }");
    lines.push("  chain output {");
    lines.push("    type filter hook output priority 0; policy accept;");
    for (var l = 0; l < rules.length; l++) {
      if (rules[l].dir === "OUTPUT") lines.push("    " + ruleToNftables(rules[l]).replace(/^nft add rule inet filter output /, ""));
    }
    lines.push("  }");
    lines.push("}");
  } else if (format === "pf") {
    lines.push("# Generated by Darknode Firewall Builder");
    lines.push("set skip on lo0");
    lines.push("block all");
    lines.push("pass out all keep state");
    lines.push("");
    for (var m = 0; m < rules.length; m++) lines.push(ruleToPf(rules[m]));
  } else if (format === "netsh") {
    lines.push("REM Generated by Darknode Firewall Builder");
    lines.push("netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound");
    lines.push("");
    for (var n = 0; n < rules.length; n++) lines.push(ruleToNetsh(rules[n]));
  } else if (format === "cisco-acl") {
    lines.push("! Generated by Darknode Firewall Builder");
    for (var o = 0; o < rules.length; o++) lines.push(ruleToCiscoACL(rules[o], o));
    lines.push("access-list 100 deny ip any any log");
  } else if (format === "aws-sg") {
    var inbound = rules.filter(function(r) { return r.dir === "INPUT" && r.action === "ACCEPT"; }).map(ruleToAWS);
    var outbound = rules.filter(function(r) { return r.dir === "OUTPUT" && r.action === "ACCEPT"; }).map(ruleToAWS);
    lines.push(JSON.stringify({ SecurityGroupRules: { IngressRules: inbound, EgressRules: outbound } }, null, 2));
  } else if (format === "azure-nsg") {
    var nsgRules = rules.map(function(r, idx) {
      var ar = ruleToAzure(r);
      ar.properties.priority = 100 + idx * 10;
      return ar;
    });
    lines.push(JSON.stringify({ securityRules: nsgRules }, null, 2));
  } else if (format === "gcp-fw") {
    var gcpRules = rules.map(function(r, idx) {
      var gr = ruleToGCP(r);
      gr.priority = 1000 + idx;
      return gr;
    });
    lines.push(JSON.stringify({ firewallRules: gcpRules }, null, 2));
  }
  return lines.join("\n");
}

function detectConflicts(rules) {
  var conflicts = [];
  for (var i = 0; i < rules.length; i++) {
    for (var j = i + 1; j < rules.length; j++) {
      var a = rules[i], b = rules[j];
      if (a.dir !== b.dir) continue;
      if (a.proto !== "ANY" && b.proto !== "ANY" && a.proto !== b.proto) continue;
      var srcOverlap = !a.src || !b.src || a.src === b.src || a.src === "0.0.0.0/0" || b.src === "0.0.0.0/0";
      var dstOverlap = !a.dst || !b.dst || a.dst === b.dst || a.dst === "0.0.0.0/0" || b.dst === "0.0.0.0/0";
      var portOverlap = !a.port || !b.port || a.port === b.port;
      if (srcOverlap && dstOverlap && portOverlap) {
        if (a.action !== b.action) {
          conflicts.push({ ruleA: i + 1, ruleB: j + 1, type: "conflict", msg: "Rules #" + (i + 1) + " and #" + (j + 1) + " match same traffic with different actions. Rule #" + (i + 1) + " takes precedence." });
        } else {
          var aSpecific = (a.src && a.src !== "0.0.0.0/0" ? 1 : 0) + (a.port ? 1 : 0) + (a.proto !== "ANY" ? 1 : 0);
          var bSpecific = (b.src && b.src !== "0.0.0.0/0" ? 1 : 0) + (b.port ? 1 : 0) + (b.proto !== "ANY" ? 1 : 0);
          if (bSpecific > aSpecific) {
            conflicts.push({ ruleA: i + 1, ruleB: j + 1, type: "shadow", msg: "Rule #" + (j + 1) + " is shadowed by broader rule #" + (i + 1) + " (same action, never reached)." });
          }
        }
      }
    }
  }
  return conflicts;
}

function simulatePacket(rules, pkt) {
  var results = [];
  for (var i = 0; i < rules.length; i++) {
    var r = rules[i];
    if (pkt.dir && r.dir !== pkt.dir) { results.push({ rule: i + 1, match: false, reason: "Direction mismatch" }); continue; }
    if (r.proto !== "ANY" && pkt.proto && r.proto !== pkt.proto.toUpperCase()) { results.push({ rule: i + 1, match: false, reason: "Protocol mismatch" }); continue; }
    if (r.src && r.src !== "0.0.0.0/0" && pkt.srcIp && !ipInCidr(pkt.srcIp, r.src)) { results.push({ rule: i + 1, match: false, reason: "Source IP not in " + r.src }); continue; }
    if (r.dst && r.dst !== "0.0.0.0/0" && pkt.dstIp && !ipInCidr(pkt.dstIp, r.dst)) { results.push({ rule: i + 1, match: false, reason: "Dest IP not in " + r.dst }); continue; }
    if (r.port && pkt.port && !portInRange(pkt.port, r.port)) { results.push({ rule: i + 1, match: false, reason: "Port not in " + r.port }); continue; }
    results.push({ rule: i + 1, match: true, action: r.action, reason: "MATCH - " + r.action + (r.comment ? " (" + r.comment + ")" : "") });
    break;
  }
  if (!results.length || !results[results.length - 1].match) {
    results.push({ rule: "default", match: true, action: "DROP", reason: "Default policy: DROP" });
  }
  return results;
}

function parseIptablesSave(text) {
  var rules = [];
  var lines = text.split("\n");
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (!line || line.charAt(0) === "#" || line.charAt(0) === "*" || line === "COMMIT" || line.charAt(0) === ":") continue;
    if (line.indexOf("-A ") !== 0) continue;
    var r = { src: "", dst: "", port: "", proto: "ANY", action: "ACCEPT", dir: "INPUT", log: false, comment: "", states: [] };
    var tokens = line.split(/\s+/);
    for (var j = 0; j < tokens.length; j++) {
      if (tokens[j] === "-A") r.dir = tokens[++j] || "INPUT";
      else if (tokens[j] === "-s") r.src = tokens[++j] || "";
      else if (tokens[j] === "-d") r.dst = tokens[++j] || "";
      else if (tokens[j] === "-p") r.proto = (tokens[++j] || "").toUpperCase();
      else if (tokens[j] === "--dport") r.port = tokens[++j] || "";
      else if (tokens[j] === "-j") r.action = tokens[++j] || "ACCEPT";
      else if (tokens[j] === "--comment") { j++; r.comment = tokens[j] ? tokens[j].replace(/"/g, "") : ""; }
      else if (tokens[j] === "--ctstate") { r.states = (tokens[++j] || "").split(","); }
    }
    if (r.action === "LOG") r.log = true;
    rules.push(r);
  }
  return rules;
}

export function renderFirewallBuilder(main) {
  var rules = [];
  var selectedFormat = "iptables";

  function renderRuleList() {
    var el = main.querySelector("#fw-rules");
    if (!el) return;
    if (!rules.length) {
      el.innerHTML = '<div style="color:var(--mut);padding:20px;text-align:center">No rules yet. Add rules above or load a template.</div>';
      return;
    }
    var html = '<table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<tr style="border-bottom:1px solid var(--line);color:var(--mut)">' +
      '<th style="padding:6px;text-align:left">#</th>' +
      '<th style="padding:6px;text-align:left">Dir</th>' +
      '<th style="padding:6px;text-align:left">Proto</th>' +
      '<th style="padding:6px;text-align:left">Source</th>' +
      '<th style="padding:6px;text-align:left">Destination</th>' +
      '<th style="padding:6px;text-align:left">Port</th>' +
      '<th style="padding:6px;text-align:left">Action</th>' +
      '<th style="padding:6px;text-align:left">Comment</th>' +
      '<th style="padding:6px;text-align:left">Log</th>' +
      '<th style="padding:6px;text-align:center">Move</th>' +
      '<th style="padding:6px;text-align:center">Del</th></tr>';
    for (var i = 0; i < rules.length; i++) {
      var r = rules[i];
      var actColor = r.action === "ACCEPT" ? "color:#22c55e" : (r.action === "DROP" ? "color:#ef4444" : (r.action === "REJECT" ? "color:#f59e0b" : "color:var(--acc)"));
      html += '<tr style="border-bottom:1px solid var(--line)">' +
        '<td style="padding:6px">' + (i + 1) + '</td>' +
        '<td style="padding:6px">' + esc(r.dir) + '</td>' +
        '<td style="padding:6px">' + esc(r.proto) + '</td>' +
        '<td style="padding:6px;font-family:var(--mono,monospace);font-size:.72rem">' + esc(r.src || "any") + '</td>' +
        '<td style="padding:6px;font-family:var(--mono,monospace);font-size:.72rem">' + esc(r.dst || "any") + '</td>' +
        '<td style="padding:6px;font-family:var(--mono,monospace)">' + esc(r.port || "all") + '</td>' +
        '<td style="padding:6px;font-weight:600;' + actColor + '">' + esc(r.action) + '</td>' +
        '<td style="padding:6px;color:var(--mut);font-size:.72rem">' + esc(r.comment) + '</td>' +
        '<td style="padding:6px">' + (r.log ? "Y" : "-") + '</td>' +
        '<td style="padding:6px;text-align:center">' +
          (i > 0 ? '<button class="btn sm ghost fw-move" data-idx="' + i + '" data-d="-1" style="padding:2px 6px">Up</button>' : '') +
          (i < rules.length - 1 ? '<button class="btn sm ghost fw-move" data-idx="' + i + '" data-d="1" style="padding:2px 6px">Dn</button>' : '') +
        '</td>' +
        '<td style="padding:6px;text-align:center"><button class="btn sm danger fw-del" data-idx="' + i + '" style="padding:2px 8px">X</button></td>' +
        '</tr>';
    }
    html += '</table>';
    el.innerHTML = html;

    el.querySelectorAll(".fw-move").forEach(function(b) {
      b.onclick = function() {
        var idx = parseInt(b.dataset.idx, 10);
        var d = parseInt(b.dataset.d, 10);
        var tmp = rules[idx];
        rules[idx] = rules[idx + d];
        rules[idx + d] = tmp;
        renderRuleList();
      };
    });
    el.querySelectorAll(".fw-del").forEach(function(b) {
      b.onclick = function() {
        rules.splice(parseInt(b.dataset.idx, 10), 1);
        renderRuleList();
      };
    });
  }

  function renderOutput() {
    var el = main.querySelector("#fw-output");
    if (el) el.textContent = generateOutput(rules, selectedFormat);
  }

  function renderConflicts() {
    var el = main.querySelector("#fw-conflicts");
    if (!el) return;
    var c = detectConflicts(rules);
    if (!c.length) {
      el.innerHTML = '<div style="color:#22c55e;padding:8px">No conflicts detected.</div>';
      return;
    }
    el.innerHTML = c.map(function(cf) {
      var color = cf.type === "conflict" ? "#ef4444" : "#f59e0b";
      return '<div style="padding:6px 8px;border-left:3px solid ' + color + ';margin:4px 0;font-size:.8rem;background:var(--card2);border-radius:0 4px 4px 0">' + esc(cf.msg) + '</div>';
    }).join("");
  }

  // Build main UI
  var scenarioOptions = Object.keys(SCENARIO_TEMPLATES).map(function(k) { return '<option value="' + esc(k) + '">' + esc(k) + '</option>'; }).join("");
  var formatOptions = OUTPUT_FORMATS.map(function(f) { return '<option value="' + esc(f) + '"' + (f === selectedFormat ? ' selected' : '') + '>' + esc(f) + '</option>'; }).join("");
  var protoOptions = PROTOCOLS.map(function(p) { return '<option value="' + esc(p) + '">' + esc(p) + '</option>'; }).join("");
  var actionOptions = ACTIONS.map(function(a) { return '<option value="' + esc(a) + '">' + esc(a) + '</option>'; }).join("");
  var dirOptions = DIRECTIONS.map(function(d) { return '<option value="' + esc(d) + '">' + esc(d) + '</option>'; }).join("");

  main.innerHTML =
    '<h1 class="pg-h1">Firewall Builder</h1>' +
    '<p class="muted pg-sub">Build, analyze, and export firewall rules for iptables, nftables, pf, Windows Firewall, Cisco ACL, and cloud platforms.</p>' +

    '<div class="tab-bar" id="fw-tabs">' +
      '<button class="tab active" data-tab="builder">Rule Builder</button>' +
      '<button class="tab" data-tab="templates">Templates</button>' +
      '<button class="tab" data-tab="output">Export</button>' +
      '<button class="tab" data-tab="conflicts">Conflict Detector</button>' +
      '<button class="tab" data-tab="simulate">Packet Simulator</button>' +
      '<button class="tab" data-tab="import">Import</button>' +
      '<button class="tab" data-tab="nat">NAT Rules</button>' +
      '<button class="tab" data-tab="icmp">ICMP Reference</button>' +
      '<button class="tab" data-tab="hardening">Hardening Checklist</button>' +
    '</div>' +

    '<div id="fw-content"></div>';

  var tabBar = main.querySelector("#fw-tabs");
  var content = main.querySelector("#fw-content");

  function renderTab(tabId) {
    tabBar.querySelectorAll(".tab").forEach(function(t) { t.classList.toggle("active", t.dataset.tab === tabId); });

    if (tabId === "builder") {
      content.innerHTML =
        '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px;margin-bottom:12px">' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Direction</label><select class="tk-f" id="fw-dir">' + dirOptions + '</select></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Protocol</label><select class="tk-f" id="fw-proto">' + protoOptions + '</select></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Source IP/CIDR</label><input class="tk-f" id="fw-src" placeholder="0.0.0.0/0"></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Dest IP/CIDR</label><input class="tk-f" id="fw-dst" placeholder="any"></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Port/Range</label><input class="tk-f" id="fw-port" placeholder="80,443"></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Action</label><select class="tk-f" id="fw-action">' + actionOptions + '</select></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Comment</label><input class="tk-f" id="fw-comment" placeholder="Rule description"></div>' +
          '<div style="display:flex;align-items:end;gap:8px"><label style="font-size:.72rem;color:var(--mut);display:flex;align-items:center;gap:4px"><input type="checkbox" id="fw-log"> Log</label></div>' +
        '</div>' +
        '<button class="btn sm" id="fw-add">Add Rule</button>' +
        '<div id="fw-rules" style="margin-top:16px"></div>';

      main.querySelector("#fw-add").onclick = function() {
        rules.push({
          dir: main.querySelector("#fw-dir").value,
          proto: main.querySelector("#fw-proto").value,
          src: main.querySelector("#fw-src").value.trim(),
          dst: main.querySelector("#fw-dst").value.trim(),
          port: main.querySelector("#fw-port").value.trim(),
          action: main.querySelector("#fw-action").value,
          comment: main.querySelector("#fw-comment").value.trim(),
          log: main.querySelector("#fw-log").checked,
          states: [],
        });
        main.querySelector("#fw-src").value = "";
        main.querySelector("#fw-dst").value = "";
        main.querySelector("#fw-port").value = "";
        main.querySelector("#fw-comment").value = "";
        renderRuleList();
      };
      renderRuleList();

    } else if (tabId === "templates") {
      content.innerHTML =
        '<h2 class="pg-h2">Scenario Templates</h2>' +
        '<p class="muted" style="font-size:.82rem">Click a template to load its rules. You can combine multiple templates.</p>' +
        '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;margin-top:12px">' +
          Object.keys(SCENARIO_TEMPLATES).map(function(k) {
            var count = SCENARIO_TEMPLATES[k].length;
            return '<button class="btn sm ghost fw-tpl" data-tpl="' + esc(k) + '" style="text-align:left;padding:10px">' +
              '<div style="font-weight:600">' + esc(k) + '</div>' +
              '<div style="font-size:.72rem;color:var(--mut)">' + count + ' rule' + (count !== 1 ? 's' : '') + '</div>' +
            '</button>';
          }).join("") +
        '</div>' +
        '<div style="margin-top:12px"><button class="btn sm danger" id="fw-clear">Clear All Rules</button></div>';

      content.querySelectorAll(".fw-tpl").forEach(function(b) {
        b.onclick = function() {
          var tpl = SCENARIO_TEMPLATES[b.dataset.tpl];
          if (tpl) {
            for (var i = 0; i < tpl.length; i++) {
              rules.push(Object.assign({}, tpl[i], { states: [] }));
            }
            renderTab("builder");
          }
        };
      });
      var clearBtn = content.querySelector("#fw-clear");
      if (clearBtn) clearBtn.onclick = function() { rules = []; renderTab("builder"); };

    } else if (tabId === "output") {
      content.innerHTML =
        '<div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">' +
          '<label style="font-size:.82rem;color:var(--mut)">Output format:</label>' +
          '<select class="tk-f" id="fw-format" style="max-width:200px">' + formatOptions + '</select>' +
          '<button class="btn sm" id="fw-gen">Generate</button>' +
          '<button class="btn sm ghost" id="fw-copy">Copy</button>' +
        '</div>' +
        '<pre class="tk-out" id="fw-output" style="max-height:500px;overflow:auto"></pre>';

      main.querySelector("#fw-format").onchange = function() { selectedFormat = this.value; };
      main.querySelector("#fw-gen").onclick = function() {
        selectedFormat = main.querySelector("#fw-format").value;
        renderOutput();
      };
      main.querySelector("#fw-copy").onclick = function() {
        var text = main.querySelector("#fw-output").textContent;
        navigator.clipboard.writeText(text).then(function() {
          main.querySelector("#fw-copy").textContent = "Copied";
          setTimeout(function() { main.querySelector("#fw-copy").textContent = "Copy"; }, 1500);
        });
      };
      renderOutput();

    } else if (tabId === "conflicts") {
      content.innerHTML =
        '<h2 class="pg-h2">Rule Conflict Detector</h2>' +
        '<p class="muted" style="font-size:.82rem">Analyzes rules for conflicts (same traffic, different actions) and shadowed rules (more specific rule after a broader one with the same action).</p>' +
        '<div id="fw-conflicts" style="margin-top:12px"></div>';
      renderConflicts();

    } else if (tabId === "simulate") {
      content.innerHTML =
        '<h2 class="pg-h2">Packet Simulator</h2>' +
        '<p class="muted" style="font-size:.82rem">Test which rule matches a given packet.</p>' +
        '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px;margin:12px 0">' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Direction</label><select class="tk-f" id="fw-sim-dir">' + dirOptions + '</select></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Protocol</label><select class="tk-f" id="fw-sim-proto">' + protoOptions + '</select></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Source IP</label><input class="tk-f" id="fw-sim-src" placeholder="192.168.1.100"></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Dest IP</label><input class="tk-f" id="fw-sim-dst" placeholder="10.0.0.5"></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Dest Port</label><input class="tk-f" id="fw-sim-port" placeholder="80"></div>' +
        '</div>' +
        '<button class="btn sm" id="fw-sim-run">Test Packet</button>' +
        '<div id="fw-sim-result" style="margin-top:12px"></div>';

      main.querySelector("#fw-sim-run").onclick = function() {
        var pkt = {
          dir: main.querySelector("#fw-sim-dir").value,
          proto: main.querySelector("#fw-sim-proto").value,
          srcIp: main.querySelector("#fw-sim-src").value.trim(),
          dstIp: main.querySelector("#fw-sim-dst").value.trim(),
          port: main.querySelector("#fw-sim-port").value.trim(),
        };
        var results = simulatePacket(rules, pkt);
        var out = main.querySelector("#fw-sim-result");
        out.innerHTML = results.map(function(r) {
          var bg = r.match ? (r.action === "ACCEPT" ? "rgba(34,197,94,.1)" : "rgba(239,68,68,.1)") : "transparent";
          var border = r.match ? (r.action === "ACCEPT" ? "#22c55e" : "#ef4444") : "var(--line)";
          return '<div style="padding:6px 10px;border-left:3px solid ' + border + ';margin:3px 0;font-size:.8rem;background:' + bg + ';border-radius:0 4px 4px 0">' +
            '<strong>Rule #' + r.rule + ':</strong> ' + esc(r.reason) + '</div>';
        }).join("");
      };

    } else if (tabId === "import") {
      content.innerHTML =
        '<h2 class="pg-h2">Import Rules</h2>' +
        '<p class="muted" style="font-size:.82rem">Paste iptables-save output to import existing rules.</p>' +
        '<textarea class="tk-in" id="fw-import-text" rows="12" placeholder="Paste iptables-save output here..."></textarea>' +
        '<div class="tk-btns"><button class="btn sm" id="fw-import-btn">Import</button></div>' +
        '<div id="fw-import-result" style="margin-top:8px"></div>';

      main.querySelector("#fw-import-btn").onclick = function() {
        var text = main.querySelector("#fw-import-text").value;
        var imported = parseIptablesSave(text);
        if (!imported.length) {
          main.querySelector("#fw-import-result").innerHTML = '<div style="color:#ef4444">No rules found. Make sure you paste iptables-save format (-A chain ... -j TARGET).</div>';
          return;
        }
        for (var i = 0; i < imported.length; i++) rules.push(imported[i]);
        main.querySelector("#fw-import-result").innerHTML = '<div style="color:#22c55e">Imported ' + imported.length + ' rules.</div>';
      };

    } else if (tabId === "nat") {
      content.innerHTML =
        '<h2 class="pg-h2">NAT / Port Forwarding Rules</h2>' +
        '<p class="muted" style="font-size:.82rem">Generate NAT, masquerade, and port forwarding rules.</p>' +
        '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px;margin:12px 0">' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Type</label><select class="tk-f" id="fw-nat-type"><option>MASQUERADE</option><option>SNAT</option><option>DNAT</option><option>Port Forward</option></select></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Interface (out)</label><input class="tk-f" id="fw-nat-iface" placeholder="eth0"></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Source CIDR</label><input class="tk-f" id="fw-nat-src" placeholder="192.168.1.0/24"></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">SNAT IP</label><input class="tk-f" id="fw-nat-snat" placeholder="203.0.113.1"></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Dest IP (DNAT)</label><input class="tk-f" id="fw-nat-dnat" placeholder="10.0.0.5"></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Ext Port</label><input class="tk-f" id="fw-nat-eport" placeholder="8080"></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Int Port</label><input class="tk-f" id="fw-nat-iport" placeholder="80"></div>' +
        '</div>' +
        '<button class="btn sm" id="fw-nat-gen">Generate NAT Rule</button>' +
        '<pre class="tk-out" id="fw-nat-output" style="margin-top:10px"></pre>';

      main.querySelector("#fw-nat-gen").onclick = function() {
        var type = main.querySelector("#fw-nat-type").value;
        var iface = main.querySelector("#fw-nat-iface").value.trim() || "eth0";
        var src = main.querySelector("#fw-nat-src").value.trim();
        var snatIp = main.querySelector("#fw-nat-snat").value.trim();
        var dnatIp = main.querySelector("#fw-nat-dnat").value.trim();
        var eport = main.querySelector("#fw-nat-eport").value.trim();
        var iport = main.querySelector("#fw-nat-iport").value.trim();
        var out = [];
        out.push("# " + type + " rule");
        out.push("echo 1 > /proc/sys/net/ipv4/ip_forward");
        if (type === "MASQUERADE") {
          out.push("iptables -t nat -A POSTROUTING -o " + iface + (src ? " -s " + src : "") + " -j MASQUERADE");
          out.push("iptables -A FORWARD -i " + iface + " -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
          if (src) out.push("iptables -A FORWARD -s " + src + " -o " + iface + " -j ACCEPT");
        } else if (type === "SNAT") {
          out.push("iptables -t nat -A POSTROUTING -o " + iface + (src ? " -s " + src : "") + " -j SNAT --to-source " + (snatIp || "PUBLIC_IP"));
        } else if (type === "DNAT") {
          out.push("iptables -t nat -A PREROUTING -i " + iface + " -p tcp --dport " + (eport || "80") + " -j DNAT --to-destination " + (dnatIp || "INTERNAL_IP") + ":" + (iport || eport || "80"));
          out.push("iptables -A FORWARD -p tcp -d " + (dnatIp || "INTERNAL_IP") + " --dport " + (iport || eport || "80") + " -m conntrack --ctstate NEW -j ACCEPT");
        } else if (type === "Port Forward") {
          out.push("iptables -t nat -A PREROUTING -i " + iface + " -p tcp --dport " + (eport || "8080") + " -j DNAT --to-destination " + (dnatIp || "10.0.0.5") + ":" + (iport || "80"));
          out.push("iptables -t nat -A POSTROUTING -p tcp -d " + (dnatIp || "10.0.0.5") + " --dport " + (iport || "80") + " -j MASQUERADE");
          out.push("iptables -A FORWARD -p tcp -d " + (dnatIp || "10.0.0.5") + " --dport " + (iport || "80") + " -m conntrack --ctstate NEW -j ACCEPT");
        }
        main.querySelector("#fw-nat-output").textContent = out.join("\n");
      };

    } else if (tabId === "icmp") {
      content.innerHTML =
        '<h2 class="pg-h2">ICMP Type Reference</h2>' +
        '<p class="muted" style="font-size:.82rem">ICMP message types commonly used in firewall rules.</p>' +
        '<table style="width:100%;border-collapse:collapse;font-size:.8rem;margin-top:12px">' +
        '<tr style="border-bottom:1px solid var(--line);color:var(--mut)"><th style="padding:6px;text-align:left">Type</th><th style="padding:6px;text-align:left">Name</th><th style="padding:6px;text-align:left">Description</th><th style="padding:6px;text-align:left">iptables flag</th></tr>' +
        ICMP_TYPES.map(function(t) {
          return '<tr style="border-bottom:1px solid var(--line)">' +
            '<td style="padding:6px;font-family:var(--mono,monospace)">' + t.type + '</td>' +
            '<td style="padding:6px;font-weight:500">' + esc(t.name) + '</td>' +
            '<td style="padding:6px;color:var(--mut)">' + esc(t.desc) + '</td>' +
            '<td style="padding:6px;font-family:var(--mono,monospace);font-size:.72rem">--icmp-type ' + t.type + '</td></tr>';
        }).join("") +
        '</table>' +
        '<div style="margin-top:16px">' +
          '<h3 style="font-size:.9rem;margin-bottom:8px">Common ICMP Rules</h3>' +
          '<pre class="tk-out">' +
            '# Allow ping (echo-request and echo-reply)\n' +
            'iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT\n' +
            'iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT\n\n' +
            '# Allow essential ICMP (fragmentation needed, time exceeded)\n' +
            'iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT\n' +
            'iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT\n\n' +
            '# Rate-limit ping to prevent flood\n' +
            'iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT\n' +
            'iptables -A INPUT -p icmp --icmp-type echo-request -j DROP\n\n' +
            '# Block ICMP redirect (potential MITM)\n' +
            'iptables -A INPUT -p icmp --icmp-type redirect -j DROP' +
          '</pre>' +
        '</div>';

    } else if (tabId === "hardening") {
      content.innerHTML =
        '<h2 class="pg-h2">Firewall Hardening Checklist</h2>' +
        '<p class="muted" style="font-size:.82rem">' + HARDENING_CHECKLIST.length + ' items. Check off as you implement each one.</p>' +
        '<div id="fw-checklist" style="margin-top:12px">' +
          HARDENING_CHECKLIST.map(function(c, i) {
            return '<label style="display:flex;align-items:flex-start;gap:8px;padding:8px;border-bottom:1px solid var(--line);font-size:.82rem;cursor:pointer">' +
              '<input type="checkbox" class="fw-check" data-idx="' + i + '" style="margin-top:3px">' +
              '<div><div style="font-weight:500">' + esc(c.item) + '</div>' +
              '<div style="font-size:.72rem;color:var(--mut)">' + esc(c.category) + '</div></div>' +
            '</label>';
          }).join("") +
        '</div>';

      try {
        var saved = JSON.parse(localStorage.getItem("fw_checklist") || "[]");
        content.querySelectorAll(".fw-check").forEach(function(cb) {
          if (saved.indexOf(parseInt(cb.dataset.idx, 10)) !== -1) cb.checked = true;
          cb.onchange = function() {
            var checks = [];
            content.querySelectorAll(".fw-check:checked").forEach(function(c2) { checks.push(parseInt(c2.dataset.idx, 10)); });
            try { localStorage.setItem("fw_checklist", JSON.stringify(checks)); } catch (_) {}
          };
        });
      } catch (_) {}
    }
  }

  tabBar.onclick = function(e) {
    var b = e.target.closest(".tab");
    if (b) renderTab(b.dataset.tab);
  };
  renderTab("builder");
}
