// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Network & IP mini-tools. See _schema.md for the contract.
// Pure client-side: all IPv4/IPv6/MAC math is implemented inline with
// integer/bitwise operations (kept unsigned via >>> 0). No network access.

// ---------------------------------------------------------------------------
// IPv4 helpers
// ---------------------------------------------------------------------------
function parseIPv4(s) {
  if (typeof s !== "string") return null;
  const m = s.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = [m[1], m[2], m[3], m[4]].map(Number);
  if (parts.some((p) => p < 0 || p > 255 || isNaN(p))) return null;
  return parts;
}
const ipToInt = (parts) => ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
const intToIp = (n) => { n = n >>> 0; return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join("."); };
function parseCIDR(s) {
  if (typeof s !== "string") return null;
  const m = s.trim().match(/^(.+)\/(\d{1,2})$/);
  if (!m) return null;
  const ip = parseIPv4(m[1]);
  const bits = parseInt(m[2], 10);
  if (!ip || isNaN(bits) || bits < 0 || bits > 32) return null;
  return { ip, bits, ipInt: ipToInt(ip) };
}
const maskFromBits = (bits) => (bits <= 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0);
function maskToBits(maskInt) {
  let bits = 0, seenZero = false;
  for (let i = 31; i >= 0; i--) {
    const bit = (maskInt >>> i) & 1;
    if (bit === 1) { if (seenZero) return null; bits++; }
    else seenZero = true;
  }
  return bits;
}
function inCidrRange(ipInt, baseStr, bits) {
  const base = ipToInt(parseIPv4(baseStr));
  const mask = maskFromBits(bits);
  return ((ipInt & mask) >>> 0) === ((base & mask) >>> 0);
}
function rangeToCidrs(startInt, endInt) {
  const out = [];
  let start = startInt;
  let guard = 0;
  while (start <= endInt && guard < 4096) {
    guard++;
    let bits = 32;
    for (let b = 0; b <= 32; b++) {
      const blockSize = Math.pow(2, 32 - b);
      if (start % blockSize === 0 && start + blockSize - 1 <= endInt) { bits = b; break; }
    }
    out.push(`${intToIp(start)}/${bits}`);
    start += Math.pow(2, 32 - bits);
  }
  return { blocks: out, truncated: start <= endInt };
}

// ---------------------------------------------------------------------------
// IPv6 helpers
// ---------------------------------------------------------------------------
function parseIPv6(str) {
  if (typeof str !== "string") return null;
  let s = str.trim();
  if (!s) return null;
  const dcCount = (s.match(/::/g) || []).length;
  if (dcCount > 1) return null;
  const v4m = s.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (v4m) {
    const v4 = parseIPv4(v4m[1]);
    if (!v4) return null;
    const hex1 = (((v4[0] << 8) | v4[1]) >>> 0).toString(16);
    const hex2 = (((v4[2] << 8) | v4[3]) >>> 0).toString(16);
    s = s.slice(0, s.length - v4m[1].length) + hex1 + ":" + hex2;
  }
  let groups;
  if (s.includes("::")) {
    const parts = s.split("::");
    if (parts.length !== 2) return null;
    const head = parts[0] ? parts[0].split(":") : [];
    const tail = parts[1] ? parts[1].split(":") : [];
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = [...head, ...new Array(missing).fill("0"), ...tail];
  } else {
    groups = s.split(":");
  }
  if (groups.length !== 8) return null;
  const out = [];
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out;
}
const expandIPv6 = (g) => g.map((x) => x.toString(16).padStart(4, "0")).join(":");
function compressIPv6(g) {
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (g[i] === 0) { if (curStart === -1) curStart = i; curLen++; if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; } }
    else { curStart = -1; curLen = 0; }
  }
  const hex = g.map((x) => x.toString(16));
  if (bestLen < 2) return hex.join(":");
  const before = hex.slice(0, bestStart);
  const after = hex.slice(bestStart + bestLen);
  return before.join(":") + "::" + after.join(":");
}

// ---------------------------------------------------------------------------
// MAC helpers
// ---------------------------------------------------------------------------
function parseMac(str) {
  if (typeof str !== "string") return null;
  const hex = str.trim().replace(/[:\-.\s]/g, "");
  if (!/^[0-9a-fA-F]{12}$/.test(hex)) return null;
  const b = [];
  for (let i = 0; i < 12; i += 2) b.push(parseInt(hex.substr(i, 2), 16));
  return b;
}
function macToEui64Groups(mac) {
  const full = [mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]];
  return [
    (((full[0] << 8) | full[1]) >>> 0).toString(16).padStart(4, "0"),
    (((full[2] << 8) | full[3]) >>> 0).toString(16).padStart(4, "0"),
    (((full[4] << 8) | full[5]) >>> 0).toString(16).padStart(4, "0"),
    (((full[6] << 8) | full[7]) >>> 0).toString(16).padStart(4, "0"),
  ];
}

// ---------------------------------------------------------------------------
// Reference tables
// ---------------------------------------------------------------------------
const OUI = {
  "000C29": "VMware", "005056": "VMware", "000569": "VMware", "001C14": "VMware",
  "080027": "Oracle VirtualBox", "001C42": "Parallels",
  "525400": "QEMU / KVM (virtio)", "00155D": "Microsoft Hyper-V",
  "B827EB": "Raspberry Pi Foundation", "DCA632": "Raspberry Pi Foundation", "E45F01": "Raspberry Pi Foundation",
  "001EC2": "Apple", "28CFE9": "Apple", "3C0754": "Apple", "8863DF": "Apple", "F01898": "Apple", "AC1F6B": "Apple",
  "E4CE8F": "Samsung", "5C0A5B": "Samsung", "002637": "Samsung",
  "CC46D6": "Cisco", "001BD4": "Cisco (Linksys)", "FCFC48": "Cisco",
  "D89EF3": "Dell", "14FEB5": "Dell", "B083FE": "Dell",
  "F8B156": "Hewlett Packard", "3CD92B": "Hewlett Packard",
  "0050BA": "D-Link", "00146C": "Netgear", "A040A0": "Netgear",
  "00E04C": "Realtek",
};
const PORTS = {
  20: "FTP (data)", 21: "FTP (control)", 22: "SSH", 23: "Telnet", 25: "SMTP",
  53: "DNS", 67: "DHCP (server)", 68: "DHCP (client)", 69: "TFTP", 80: "HTTP",
  110: "POP3", 111: "RPCbind", 119: "NNTP", 123: "NTP", 135: "MS RPC",
  137: "NetBIOS Name Service", 138: "NetBIOS Datagram", 139: "NetBIOS Session",
  143: "IMAP", 161: "SNMP", 162: "SNMP Trap", 179: "BGP", 194: "IRC",
  389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
  515: "LPD Printer", 520: "RIP", 587: "SMTP Submission", 631: "IPP",
  636: "LDAPS", 691: "MS Exchange Routing", 860: "iSCSI", 873: "rsync",
  902: "VMware Server", 989: "FTPS (data)", 990: "FTPS (control)", 993: "IMAPS",
  995: "POP3S", 1080: "SOCKS Proxy", 1194: "OpenVPN", 1433: "Microsoft SQL Server",
  1521: "Oracle DB", 1701: "L2TP", 1723: "PPTP", 1812: "RADIUS (auth)",
  1813: "RADIUS (accounting)", 2049: "NFS", 2082: "cPanel", 2083: "cPanel SSL",
  2181: "ZooKeeper", 2375: "Docker API", 2376: "Docker API (TLS)",
  3128: "Squid Proxy", 3268: "LDAP Global Catalog", 3306: "MySQL",
  3389: "RDP", 3690: "Subversion (svn)", 4444: "Metasploit / generic handler",
  5000: "UPnP / dev HTTP", 5060: "SIP", 5061: "SIP (TLS)", 5432: "PostgreSQL",
  5601: "Kibana", 5672: "AMQP", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
  6667: "IRC", 8000: "HTTP alt", 8008: "HTTP alt", 8080: "HTTP proxy / alt",
  8443: "HTTPS alt", 8888: "HTTP alt", 9000: "PHP-FPM", 9092: "Kafka",
  9200: "Elasticsearch", 9418: "Git", 11211: "Memcached", 27017: "MongoDB",
  27018: "MongoDB (shard)", 50000: "SAP",
};
const HTTP_STATUS = {
  100: "Continue", 101: "Switching Protocols", 102: "Processing", 103: "Early Hints",
  200: "OK", 201: "Created", 202: "Accepted", 203: "Non-Authoritative Information",
  204: "No Content", 205: "Reset Content", 206: "Partial Content", 207: "Multi-Status",
  208: "Already Reported", 226: "IM Used",
  300: "Multiple Choices", 301: "Moved Permanently", 302: "Found", 303: "See Other",
  304: "Not Modified", 305: "Use Proxy", 307: "Temporary Redirect", 308: "Permanent Redirect",
  400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
  404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable",
  407: "Proxy Authentication Required", 408: "Request Timeout", 409: "Conflict",
  410: "Gone", 411: "Length Required", 412: "Precondition Failed", 413: "Payload Too Large",
  414: "URI Too Long", 415: "Unsupported Media Type", 416: "Range Not Satisfiable",
  417: "Expectation Failed", 418: "I'm a Teapot", 421: "Misdirected Request",
  422: "Unprocessable Entity", 423: "Locked", 424: "Failed Dependency", 425: "Too Early",
  426: "Upgrade Required", 428: "Precondition Required", 429: "Too Many Requests",
  431: "Request Header Fields Too Large", 451: "Unavailable For Legal Reasons",
  500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
  503: "Service Unavailable", 504: "Gateway Timeout", 505: "HTTP Version Not Supported",
  506: "Variant Also Negotiates", 507: "Insufficient Storage", 508: "Loop Detected",
  510: "Not Extended", 511: "Network Authentication Required",
};
const MIME = {
  html: "text/html", htm: "text/html", css: "text/css", js: "application/javascript",
  mjs: "application/javascript", json: "application/json", xml: "application/xml",
  txt: "text/plain", csv: "text/csv", md: "text/markdown",
  png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif",
  svg: "image/svg+xml", webp: "image/webp", ico: "image/x-icon", bmp: "image/bmp",
  tiff: "image/tiff", avif: "image/avif",
  mp3: "audio/mpeg", wav: "audio/wav", ogg: "audio/ogg", flac: "audio/flac",
  aac: "audio/aac", m4a: "audio/mp4",
  mp4: "video/mp4", webm: "video/webm", avi: "video/x-msvideo", mov: "video/quicktime",
  mkv: "video/x-matroska",
  pdf: "application/pdf", zip: "application/zip", gz: "application/gzip",
  tar: "application/x-tar", rar: "application/vnd.rar", "7z": "application/x-7z-compressed",
  doc: "application/msword",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xls: "application/vnd.ms-excel",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ppt: "application/vnd.ms-powerpoint",
  pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  woff: "font/woff", woff2: "font/woff2", ttf: "font/ttf", otf: "font/otf",
  eot: "application/vnd.ms-fontobject",
  wasm: "application/wasm", exe: "application/x-msdownload", sh: "application/x-sh",
  apk: "application/vnd.android.package-archive",
  yaml: "application/x-yaml", yml: "application/x-yaml", sql: "application/sql",
  bin: "application/octet-stream",
};
const DNS_TYPES = {
  A: "Maps a hostname to an IPv4 address.",
  AAAA: "Maps a hostname to an IPv6 address.",
  CNAME: "Alias of one name to another (canonical name).",
  MX: "Mail exchange server(s) for the domain, with priority.",
  TXT: "Free-form text; used for SPF, DKIM, domain verification.",
  NS: "Authoritative name servers for the domain.",
  SOA: "Start of authority; zone admin, serial, refresh/retry timers.",
  PTR: "Reverse lookup: address to hostname.",
  SRV: "Service location record (priority, weight, port, target host).",
  CAA: "Restricts which CAs may issue certificates for the domain.",
  NAPTR: "Naming Authority Pointer, used in ENUM/SIP routing.",
  DNSKEY: "Public key used in DNSSEC.",
  DS: "Delegation Signer; hashes a child zone's DNSKEY for DNSSEC.",
  RRSIG: "DNSSEC signature over a record set.",
  NSEC: "DNSSEC proof of non-existence (ordered names).",
  NSEC3: "Hashed DNSSEC proof of non-existence.",
  TLSA: "Associates a TLS certificate with a hostname (DANE).",
  SSHFP: "SSH public key fingerprint for host verification.",
  HINFO: "Host information (CPU/OS); rarely used today.",
  LOC: "Geographic location of a host.",
  CERT: "Stores certificates or CRLs.",
  DNAME: "Redirects an entire subtree of the DNS namespace.",
  AFSDB: "AFS database location record.",
  SPF: "Deprecated sender policy framework record (use TXT instead).",
};

export const TOOLS = [
  { id: "n-subnet-calc", name: "IPv4 Subnet Calculator", cat: "network", desc: "Full breakdown of a CIDR block: network, broadcast, mask, host range, usable hosts.", tags: ["subnet", "cidr", "ipv4"],
    inputs: [{ k: "cidr", label: "CIDR", type: "text", placeholder: "10.0.0.0/24" }],
    run(v) {
      if (!v.cidr) return "";
      const c = parseCIDR(v.cidr);
      if (!c) return { error: "Enter a valid CIDR, e.g. 10.0.0.0/24" };
      const { bits, ipInt } = c;
      const mask = maskFromBits(bits);
      const network = (ipInt & mask) >>> 0;
      const broadcast = (network | (~mask >>> 0)) >>> 0;
      const wildcard = (~mask) >>> 0;
      const total = Math.pow(2, 32 - bits);
      let firstHost, lastHost, usable;
      if (bits >= 31) { firstHost = network; lastHost = broadcast; usable = bits === 32 ? 1 : 2; }
      else { firstHost = network + 1; lastHost = broadcast - 1; usable = total - 2; }
      return [
        `CIDR: ${intToIp(network)}/${bits}`,
        `Netmask: ${intToIp(mask)}`,
        `Wildcard: ${intToIp(wildcard)}`,
        `Network: ${intToIp(network)}`,
        `Broadcast: ${intToIp(broadcast)}`,
        `First host: ${intToIp(firstHost)}`,
        `Last host: ${intToIp(lastHost)}`,
        `Usable hosts: ${usable}`,
        `Total addresses: ${total}`,
      ].join("\n");
    } },

  { id: "n-cidr-to-mask", name: "CIDR → Netmask", cat: "network", desc: "Convert a prefix length (/24) to a dotted netmask.", tags: ["cidr", "mask"],
    inputs: [{ k: "bits", label: "CIDR prefix", type: "text", inputType: "number", placeholder: "24" }],
    run(v) { if (v.bits === "" || v.bits == null) return ""; const bits = parseInt(v.bits, 10); if (isNaN(bits) || bits < 0 || bits > 32) return { error: "Prefix must be 0-32." }; return intToIp(maskFromBits(bits)); } },

  { id: "n-mask-to-cidr", name: "Netmask → CIDR", cat: "network", desc: "Convert a dotted netmask to a prefix length.", tags: ["cidr", "mask"],
    inputs: [{ k: "mask", label: "Netmask", type: "text", placeholder: "255.255.255.0" }],
    run(v) { if (!v.mask) return ""; const m = parseIPv4(v.mask); if (!m) return { error: "Enter a valid dotted netmask." }; const bits = maskToBits(ipToInt(m)); if (bits === null) return { error: "Not a contiguous netmask." }; return `/${bits}`; } },

  { id: "n-wildcard-mask", name: "Wildcard Mask", cat: "network", desc: "Derive the wildcard (inverse) mask from a netmask, for ACLs.", tags: ["acl", "cisco", "mask"],
    inputs: [{ k: "mask", label: "Netmask", type: "text", placeholder: "255.255.255.0" }],
    run(v) { if (!v.mask) return ""; const m = parseIPv4(v.mask); if (!m) return { error: "Enter a valid dotted netmask." }; return intToIp((~ipToInt(m)) >>> 0); } },

  { id: "n-ip-to-int", name: "IPv4 → Integer", cat: "network", desc: "Convert a dotted IPv4 address to its unsigned 32-bit integer value.", tags: ["ipv4", "integer"],
    inputs: [{ k: "ip", label: "IPv4 address", type: "text", placeholder: "192.168.1.1" }],
    run(v) { if (!v.ip) return ""; const p = parseIPv4(v.ip); if (!p) return { error: "Enter a valid IPv4 address." }; return String(ipToInt(p)); } },

  { id: "n-int-to-ip", name: "Integer → IPv4", cat: "network", desc: "Convert an unsigned 32-bit integer to a dotted IPv4 address.", tags: ["ipv4", "integer"],
    inputs: [{ k: "int", label: "Integer (0 - 4294967295)", type: "text", inputType: "number", placeholder: "3232235777" }],
    run(v) { if (v.int === "" || v.int == null) return ""; const n = Number(v.int); if (!Number.isInteger(n) || n < 0 || n > 4294967295) return { error: "Enter an integer between 0 and 4294967295." }; return intToIp(n); } },

  { id: "n-ip-class", name: "IPv4 Address Class", cat: "network", desc: "Classify a legacy address class (A/B/C/D/E) from its first octet.", tags: ["classful", "ipv4"],
    inputs: [{ k: "ip", label: "IPv4 address", type: "text", placeholder: "172.16.5.1" }],
    run(v) { if (!v.ip) return ""; const p = parseIPv4(v.ip); if (!p) return { error: "Enter a valid IPv4 address." }; const o = p[0]; if (o < 128) return "Class A (1.0.0.0 - 126.255.255.255)"; if (o < 192) return "Class B (128.0.0.0 - 191.255.255.255)"; if (o < 224) return "Class C (192.0.0.0 - 223.255.255.255)"; if (o < 240) return "Class D — Multicast (224.0.0.0 - 239.255.255.255)"; return "Class E — Reserved/experimental (240.0.0.0 - 255.255.255.255)"; } },

  { id: "n-ip-type", name: "IPv4 Private / Public / Reserved Checker", cat: "network", desc: "Identify whether an IPv4 address is private, loopback, link-local, documentation, multicast, or public.", tags: ["rfc1918", "private", "public"],
    inputs: [{ k: "ip", label: "IPv4 address", type: "text", placeholder: "10.1.2.3" }],
    run(v) {
      if (!v.ip) return "";
      const p = parseIPv4(v.ip); if (!p) return { error: "Enter a valid IPv4 address." };
      const ipInt = ipToInt(p);
      const checks = [
        ["0.0.0.0/8", "This host on this network"], ["10.0.0.0/8", "Private (RFC 1918)"],
        ["100.64.0.0/10", "Shared address space / CGNAT (RFC 6598)"], ["127.0.0.0/8", "Loopback"],
        ["169.254.0.0/16", "Link-local (APIPA)"], ["172.16.0.0/12", "Private (RFC 1918)"],
        ["192.0.0.0/24", "IETF protocol assignments"], ["192.0.2.0/24", "Documentation (TEST-NET-1)"],
        ["192.88.99.0/24", "6to4 relay anycast"], ["192.168.0.0/16", "Private (RFC 1918)"],
        ["198.18.0.0/15", "Benchmarking"], ["198.51.100.0/24", "Documentation (TEST-NET-2)"],
        ["203.0.113.0/24", "Documentation (TEST-NET-3)"], ["224.0.0.0/4", "Multicast"],
        ["240.0.0.0/4", "Reserved for future use"], ["255.255.255.255/32", "Limited broadcast"],
      ];
      for (const [cidr, label] of checks) { const [base, bitsStr] = cidr.split("/"); if (inCidrRange(ipInt, base, parseInt(bitsStr, 10))) return label; }
      return "Public / globally routable";
    } },

  { id: "n-ip-in-cidr", name: "Is IP in CIDR?", cat: "network", desc: "Check whether an IPv4 address falls inside a given CIDR block.", tags: ["cidr", "membership"],
    inputs: [{ k: "ip", label: "IPv4 address", type: "text", placeholder: "10.0.0.5" }, { k: "cidr", label: "CIDR", type: "text", placeholder: "10.0.0.0/24" }],
    run(v) { if (!v.ip || !v.cidr) return ""; const c = parseCIDR(v.cidr); if (!c) return { error: "Enter a valid CIDR." }; const p = parseIPv4(v.ip); if (!p) return { error: "Enter a valid IPv4 address." }; const mask = maskFromBits(c.bits); const inside = ((ipToInt(p) & mask) >>> 0) === ((c.ipInt & mask) >>> 0); return inside ? `Yes — ${v.ip} is inside ${v.cidr}` : `No — ${v.ip} is outside ${v.cidr}`; } },

  { id: "n-cidr-hosts", name: "CIDR Host Counter", cat: "network", desc: "Total addresses and usable hosts for a given prefix length.", tags: ["cidr", "hosts"],
    inputs: [{ k: "bits", label: "CIDR prefix", type: "text", inputType: "number", placeholder: "24" }],
    run(v) { if (v.bits === "" || v.bits == null) return ""; const bits = parseInt(v.bits, 10); if (isNaN(bits) || bits < 0 || bits > 32) return { error: "Prefix must be 0-32." }; const total = Math.pow(2, 32 - bits); const usable = bits >= 31 ? (bits === 32 ? 1 : 2) : total - 2; return `Total addresses: ${total}\nUsable hosts: ${usable}`; } },

  { id: "n-range-to-cidr", name: "IPv4 Range → CIDR Aggregate", cat: "network", desc: "Summarize a start-end IPv4 range into the minimal list of covering CIDR blocks.", tags: ["aggregate", "supernet", "summarize"], button: "Aggregate",
    inputs: [{ k: "start", label: "Start IP", type: "text", placeholder: "10.0.0.0" }, { k: "end", label: "End IP", type: "text", placeholder: "10.0.0.255" }],
    run(v) {
      if (!v.start || !v.end) return "";
      const s = parseIPv4(v.start), e = parseIPv4(v.end);
      if (!s || !e) return { error: "Enter valid start and end IPv4 addresses." };
      const startInt = ipToInt(s), endInt = ipToInt(e);
      if (startInt > endInt) return { error: "Start address must be less than or equal to the end address." };
      const { blocks, truncated } = rangeToCidrs(startInt, endInt);
      return blocks.join("\n") + (truncated ? "\n… (truncated, range too large)" : "");
    } },

  { id: "n-cidr-split", name: "CIDR Splitter", cat: "network", desc: "Split a CIDR block into N equal-sized subnets.", tags: ["subnet", "split"], button: "Split",
    inputs: [{ k: "cidr", label: "CIDR", type: "text", placeholder: "192.168.0.0/24" }, { k: "count", label: "Number of subnets (power of 2)", type: "text", inputType: "number", placeholder: "4" }],
    run(v) {
      if (!v.cidr || !v.count) return "";
      const c = parseCIDR(v.cidr); if (!c) return { error: "Enter a valid CIDR." };
      const n = parseInt(v.count, 10);
      if (!n || n < 2 || (n & (n - 1)) !== 0) return { error: "Number of subnets must be a power of 2 (2, 4, 8, 16, …)." };
      const addBits = Math.log2(n);
      const newBits = c.bits + addBits;
      if (newBits > 32) return { error: "Cannot split that far past /32." };
      const mask = maskFromBits(c.bits);
      const base = (c.ipInt & mask) >>> 0;
      const blockSize = Math.pow(2, 32 - newBits);
      const lines = [];
      for (let i = 0; i < n; i++) lines.push(`${intToIp(base + i * blockSize)}/${newBits}`);
      return lines.join("\n");
    } },

  { id: "n-ipv6-expand", name: "IPv6 Expander", cat: "network", desc: "Expand a compressed IPv6 address to its full 8-group form.", tags: ["ipv6", "expand"],
    inputs: [{ k: "addr", label: "IPv6 address", type: "text", placeholder: "2001:db8::1" }],
    run(v) { if (!v.addr) return ""; const g = parseIPv6(v.addr); if (!g) return { error: "Enter a valid IPv6 address." }; return expandIPv6(g); } },

  { id: "n-ipv6-compress", name: "IPv6 Compressor", cat: "network", desc: "Compress an IPv6 address to its shortest :: form.", tags: ["ipv6", "compress"],
    inputs: [{ k: "addr", label: "IPv6 address", type: "text", placeholder: "2001:0db8:0000:0000:0000:0000:0000:0001" }],
    run(v) { if (!v.addr) return ""; const g = parseIPv6(v.addr); if (!g) return { error: "Enter a valid IPv6 address." }; return compressIPv6(g); } },

  { id: "n-ipv6-eui64", name: "MAC → EUI-64 Interface ID", cat: "network", desc: "Derive the 64-bit modified-EUI-64 interface identifier from a MAC address.", tags: ["ipv6", "eui64", "mac"],
    inputs: [{ k: "mac", label: "MAC address", type: "text", placeholder: "AA:BB:CC:DD:EE:FF" }],
    run(v) { if (!v.mac) return ""; const mac = parseMac(v.mac); if (!mac) return { error: "Enter a valid MAC address." }; const [g1, g2, g3, g4] = macToEui64Groups(mac); return `Interface ID: ${g1}:${g2}:${g3}:${g4}\n(universal/local bit flipped, FFFE inserted per modified EUI-64)`; } },

  { id: "n-mac-format", name: "MAC Address Formatter", cat: "network", desc: "Normalize a MAC address into colon, dash, Cisco-dotted, and bare formats.", tags: ["mac", "normalize"],
    inputs: [{ k: "mac", label: "MAC address (any format)", type: "text", placeholder: "aabb.ccdd.eeff" }],
    run(v) { if (!v.mac) return ""; const mac = parseMac(v.mac); if (!mac) return { error: "Enter a valid 12-hex-digit MAC address." }; const hex = mac.map((b) => b.toString(16).padStart(2, "0")); return [`Colon: ${hex.join(":")}`, `Dash: ${hex.join("-")}`, `Cisco: ${hex[0]}${hex[1]}.${hex[2]}${hex[3]}.${hex[4]}${hex[5]}`, `Bare: ${hex.join("")}`, `Uppercase colon: ${hex.join(":").toUpperCase()}`].join("\n"); } },

  { id: "n-mac-eui64", name: "MAC → EUI-64 Link-Local Address", cat: "network", desc: "Build a full IPv6 address (default fe80::/64) from a MAC using modified EUI-64.", tags: ["ipv6", "link-local", "mac"],
    inputs: [{ k: "mac", label: "MAC address", type: "text", placeholder: "AA:BB:CC:DD:EE:FF" }, { k: "prefix", label: "64-bit prefix", type: "text", value: "fe80::", placeholder: "fe80::" }],
    run(v) {
      if (!v.mac) return "";
      const mac = parseMac(v.mac); if (!mac) return { error: "Enter a valid MAC address." }
      const [g1, g2, g3, g4] = macToEui64Groups(mac);
      let p = String(v.prefix || "fe80::").trim().replace(/:+$/, "");
      return `${p}::${g1}:${g2}:${g3}:${g4}`;
    } },

  { id: "n-mac-vendor", name: "MAC Vendor (OUI) Lookup", cat: "network", desc: "Look up the manufacturer for a MAC's OUI, against a local ~25-entry reference subset.", tags: ["mac", "oui", "vendor"],
    inputs: [{ k: "mac", label: "MAC address", type: "text", placeholder: "00:0C:29:12:34:56" }],
    run(v) { if (!v.mac) return ""; const mac = parseMac(v.mac); if (!mac) return { error: "Enter a valid MAC address." }; const key = mac.slice(0, 3).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase(); const vendor = OUI[key]; return vendor ? `${vendor} (OUI ${key})` : `Not found for OUI ${key} — this is a local subset of ~25 common OUIs, not the full IEEE registry.`; } },

  { id: "n-port-lookup", name: "TCP/UDP Port Lookup", cat: "network", desc: "Look up the well-known service for a port number, from a local reference table.", tags: ["port", "service"],
    inputs: [{ k: "port", label: "Port", type: "text", inputType: "number", placeholder: "443" }],
    run(v) { if (v.port === "" || v.port == null) return ""; const port = parseInt(v.port, 10); if (isNaN(port) || port < 0 || port > 65535) return { error: "Enter a port number 0-65535." }; const svc = PORTS[port]; return svc ? `Port ${port} — ${svc}` : `Port ${port} has no entry in this local table; it may be dynamic/private (49152-65535) or simply unlisted.`; } },

  { id: "n-ports-reference", name: "Common Ports Reference", cat: "network", desc: "Search the local list of common TCP/UDP ports by name or number.", tags: ["port", "reference", "search"],
    inputs: [{ k: "q", label: "Search (name or number, blank = all)", type: "text", placeholder: "sql" }],
    run(v) {
      const q = String(v.q || "").trim().toLowerCase();
      const entries = Object.entries(PORTS).sort((a, b) => Number(a[0]) - Number(b[0]));
      const matches = entries.filter(([port, name]) => !q || port.includes(q) || name.toLowerCase().includes(q));
      if (!matches.length) return { error: "No matching ports found." };
      return matches.map(([port, name]) => `${port} — ${name}`).join("\n");
    } },

  { id: "n-tcp-flags", name: "TCP Flags Decoder", cat: "network", desc: "Decode a TCP flags byte into SYN/ACK/FIN/etc., or encode flag names into a value.", tags: ["tcp", "flags"],
    inputs: [{ k: "mode", label: "Mode", type: "select", opts: ["Number → Flags", "Flags → Number"], value: "Number → Flags" }, { k: "value", label: "Value", type: "text", placeholder: "Number 0-255 or SYN,ACK" }],
    run(v) {
      const FLAGS = [["FIN", 0x01], ["SYN", 0x02], ["RST", 0x04], ["PSH", 0x08], ["ACK", 0x10], ["URG", 0x20], ["ECE", 0x40], ["CWR", 0x80]];
      if (!v.value) return "";
      if (v.mode === "Number → Flags") {
        const n = parseInt(v.value, 10);
        if (isNaN(n) || n < 0 || n > 255) return { error: "Enter a number 0-255." };
        const set = FLAGS.filter(([, bit]) => (n & bit) !== 0).map(([name]) => name);
        return `Flags set: ${set.length ? set.join(", ") : "(none)"}\nBinary: ${n.toString(2).padStart(8, "0")}`;
      }
      const names = String(v.value).toUpperCase().split(/[,\s]+/).filter(Boolean);
      let n = 0; const unknown = [];
      for (const nm of names) { const f = FLAGS.find(([name]) => name === nm); if (f) n |= f[1]; else unknown.push(nm); }
      if (unknown.length) return { error: `Unknown flag(s): ${unknown.join(", ")}` };
      return `Value: ${n} (binary ${n.toString(2).padStart(8, "0")}, hex 0x${n.toString(16).padStart(2, "0")})`;
    } },

  { id: "n-http-status", name: "HTTP Status Code Lookup", cat: "network", desc: "Meaning and class for any HTTP status code, 1xx-5xx.", tags: ["http", "status"],
    inputs: [{ k: "code", label: "Status code", type: "text", inputType: "number", placeholder: "404" }],
    run(v) { if (v.code === "" || v.code == null) return ""; const code = parseInt(v.code, 10); const name = HTTP_STATUS[code]; if (!name) return { error: `Unknown or unlisted status code ${v.code}.` }; const cls = code < 200 ? "Informational" : code < 300 ? "Success" : code < 400 ? "Redirection" : code < 500 ? "Client Error" : "Server Error"; return `${code} ${name} (${cls})`; } },

  { id: "n-http-methods", name: "HTTP Methods Reference", cat: "network", desc: "What each HTTP request method is for.", tags: ["http", "methods", "verbs"],
    inputs: [{ k: "method", label: "Method (blank = all)", type: "select", opts: ["", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"], value: "" }],
    run(v) {
      const M = { GET: "Retrieve a representation of a resource.", HEAD: "Like GET but returns headers only, no body.", POST: "Submit data to be processed, or create a resource.", PUT: "Replace a resource entirely with the supplied payload.", DELETE: "Remove the specified resource.", CONNECT: "Establish a tunnel to the server (used for HTTPS proxying).", OPTIONS: "Describe the communication options for the target resource.", TRACE: "Echo the received request for diagnostic loop-back testing.", PATCH: "Apply a partial modification to a resource." };
      if (v.method && M[v.method]) return `${v.method}: ${M[v.method]}`;
      return Object.entries(M).map(([k, d]) => `${k}: ${d}`).join("\n");
    } },

  { id: "n-mime-type", name: "MIME Type by Extension", cat: "network", desc: "Look up the MIME/content type for a file extension, from a ~50-entry table.", tags: ["mime", "content-type"],
    inputs: [{ k: "ext", label: "Extension", type: "text", placeholder: "svg" }],
    run(v) { if (!v.ext) return ""; const ext = String(v.ext).trim().replace(/^\./, "").toLowerCase(); const mime = MIME[ext]; if (!mime) return { error: `Unknown extension ".${ext}" — not in this local table.` }; return mime; } },

  { id: "n-url-parser", name: "URL Parser", cat: "network", desc: "Break a URL down into scheme, host, port, path, query and fragment.", tags: ["url", "parse"],
    inputs: [{ k: "url", label: "URL", type: "text", placeholder: "https://user:pass@example.com:8443/a/b?x=1&y=2#frag" }],
    run(v) {
      if (!v.url) return "";
      try {
        const u = new URL(v.url);
        const q = [];
        u.searchParams.forEach((val, key) => q.push(`  ${key} = ${val}`));
        return [
          `Scheme: ${u.protocol.replace(":", "")}`,
          `Host: ${u.hostname}`,
          `Port: ${u.port || "(default)"}`,
          `Path: ${u.pathname}`,
          `Query: ${u.search ? u.search.slice(1) : "(none)"}`,
          `Fragment: ${u.hash ? u.hash.slice(1) : "(none)"}`,
          `Username: ${u.username || "(none)"}`,
          `Password: ${u.password ? "(set)" : "(none)"}`,
          q.length ? `Query params:\n${q.join("\n")}` : null,
        ].filter(Boolean).join("\n");
      } catch (e) { return { error: "Enter a valid absolute URL, including scheme (e.g. https://)." }; }
    } },

  { id: "n-query-parser", name: "Query String Parser", cat: "network", desc: "Parse a URL query string into key/value lines.", tags: ["url", "querystring"],
    inputs: [{ k: "qs", label: "Query string", type: "textarea", rows: 3, placeholder: "a=1&b=two&a=3" }],
    run(v) { if (!v.qs) return ""; try { const s = v.qs.trim().replace(/^\?/, ""); const params = new URLSearchParams(s); const lines = []; params.forEach((val, key) => lines.push(`${key} = ${val}`)); return lines.length ? lines.join("\n") : "(no parameters)"; } catch (e) { return { error: "Could not parse query string." }; } } },

  { id: "n-user-agent", name: "User-Agent Parser", cat: "network", desc: "Heuristically identify browser, OS and device type from a User-Agent string.", tags: ["ua", "browser", "os"],
    inputs: [{ k: "ua", label: "User-Agent string", type: "textarea", rows: 3, placeholder: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/120.0 Safari/537.36" }],
    run(v) {
      const ua = String(v.ua || ""); if (!ua) return "";
      let browser = "Unknown", bver = "";
      const tests = [[/Edg\/([\d.]+)/, "Microsoft Edge"], [/OPR\/([\d.]+)/, "Opera"], [/CriOS\/([\d.]+)/, "Chrome (iOS)"], [/FxiOS\/([\d.]+)/, "Firefox (iOS)"], [/Chrome\/([\d.]+)/, "Chrome"], [/Firefox\/([\d.]+)/, "Firefox"], [/Version\/([\d.]+).*Safari/, "Safari"], [/Trident.*rv:([\d.]+)/, "Internet Explorer"], [/MSIE ([\d.]+)/, "Internet Explorer"]];
      for (const [re, name] of tests) { const m = ua.match(re); if (m) { browser = name; bver = m[1]; break; } }
      let os = "Unknown";
      const osTests = [[/Windows NT 10\.0/, "Windows 10/11"], [/Windows NT 6\.3/, "Windows 8.1"], [/Windows NT 6\.2/, "Windows 8"], [/Windows NT 6\.1/, "Windows 7"], [/iPad.*OS ([\d_]+)/, "iPadOS"], [/iPhone OS ([\d_]+)/, "iOS"], [/Mac OS X ([\d_]+)/, "macOS"], [/Android ([\d.]+)/, "Android"], [/CrOS/, "ChromeOS"], [/Linux/, "Linux"]];
      for (const [re, name] of osTests) { if (re.test(ua)) { os = name; break; } }
      const mobile = /Mobi|Android|iPhone|iPad/.test(ua);
      return `Browser: ${browser}${bver ? " " + bver : ""}\nOS: ${os}\nDevice: ${mobile ? "Mobile" : "Desktop"}`;
    } },

  { id: "n-dns-types", name: "DNS Record Type Explainer", cat: "network", desc: "What each DNS record type (A, AAAA, MX, TXT, …) is used for.", tags: ["dns", "records"],
    inputs: [{ k: "type", label: "Record type (blank = all)", type: "text", placeholder: "MX" }],
    run(v) { const t = String(v.type || "").trim().toUpperCase(); if (!t) return Object.entries(DNS_TYPES).map(([k, d]) => `${k}: ${d}`).join("\n"); const d = DNS_TYPES[t]; if (!d) return { error: `Unknown record type "${t}".` }; return `${t}: ${d}`; } },

  { id: "n-ptr-name", name: "Reverse-DNS PTR Name Builder", cat: "network", desc: "Build the in-addr.arpa / ip6.arpa PTR query name for an IPv4 or IPv6 address.", tags: ["dns", "ptr", "reverse"],
    inputs: [{ k: "ip", label: "IP address", type: "text", placeholder: "192.168.1.10" }, { k: "mode", label: "Version", type: "select", opts: ["IPv4", "IPv6"], value: "IPv4" }],
    run(v) {
      if (!v.ip) return "";
      if (v.mode === "IPv6") { const g = parseIPv6(v.ip); if (!g) return { error: "Enter a valid IPv6 address." }; const nibbles = g.map((x) => x.toString(16).padStart(4, "0")).join("").split("").reverse().join("."); return `${nibbles}.ip6.arpa`; }
      const p = parseIPv4(v.ip); if (!p) return { error: "Enter a valid IPv4 address." };
      return `${p.slice().reverse().join(".")}.in-addr.arpa`;
    } },

  { id: "n-cidr-compare", name: "CIDR Contains Summary", cat: "network", desc: "Determine whether one CIDR block contains, equals, or is disjoint from another.", tags: ["cidr", "compare", "contains"],
    inputs: [{ k: "a", label: "CIDR A", type: "text", placeholder: "10.0.0.0/8" }, { k: "b", label: "CIDR B", type: "text", placeholder: "10.1.2.0/24" }],
    run(v) {
      if (!v.a || !v.b) return "";
      const a = parseCIDR(v.a), b = parseCIDR(v.b);
      if (!a) return { error: "Enter a valid CIDR for A." };
      if (!b) return { error: "Enter a valid CIDR for B." };
      const maskA = maskFromBits(a.bits), maskB = maskFromBits(b.bits);
      const netA = (a.ipInt & maskA) >>> 0, netB = (b.ipInt & maskB) >>> 0;
      if (a.bits === b.bits) return netA === netB ? "A and B are the same network." : "A and B do not overlap.";
      if (a.bits < b.bits) return ((netB & maskA) >>> 0) === netA ? `A contains B (A is /${a.bits}, B is /${b.bits}).` : "A and B do not overlap.";
      return ((netA & maskB) >>> 0) === netB ? `B contains A (B is /${b.bits}, A is /${a.bits}).` : "A and B do not overlap.";
    } },

  { id: "n-dig-builder", name: "dig Command Builder", cat: "network", desc: "Build a dig command for a name, record type and optional server (for authorized DNS testing).", tags: ["dns", "dig", "command"],
    inputs: [{ k: "name", label: "Name", type: "text", placeholder: "example.com" }, { k: "type", label: "Record type", type: "select", opts: ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "ANY", "PTR", "SRV"], value: "A" }, { k: "server", label: "Server (optional)", type: "text", placeholder: "8.8.8.8" }],
    run(v) { if (!v.name) return ""; const name = v.name.trim(); const server = (v.server || "").trim(); return `dig ${name} ${v.type || "A"}${server ? ` @${server}` : ""}`; } },

  { id: "n-nslookup-builder", name: "nslookup Command Builder", cat: "network", desc: "Build an nslookup command for a name, record type and optional server.", tags: ["dns", "nslookup", "command"],
    inputs: [{ k: "name", label: "Name", type: "text", placeholder: "example.com" }, { k: "type", label: "Record type", type: "select", opts: ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "PTR", "SRV"], value: "A" }, { k: "server", label: "Server (optional)", type: "text", placeholder: "1.1.1.1" }],
    run(v) { if (!v.name) return ""; const name = v.name.trim(); const server = (v.server || "").trim(); return `nslookup -type=${v.type || "A"} ${name}${server ? ` ${server}` : ""}`; } },

  { id: "n-ping-builder", name: "ping Command Builder", cat: "network", desc: "Build a ping command with count and packet size for the target OS.", tags: ["ping", "icmp", "command"],
    inputs: [{ k: "host", label: "Host or IP", type: "text", placeholder: "example.com" }, { k: "count", label: "Count", type: "text", inputType: "number", value: "4" }, { k: "size", label: "Packet size", type: "text", inputType: "number", value: "56" }, { k: "os", label: "OS", type: "select", opts: ["Linux", "macOS", "Windows"], value: "Linux" }],
    run(v, H) { if (!v.host) return ""; const host = v.host.trim(); const count = H.clampInt(v.count, 1, 1000, 4); const size = H.clampInt(v.size, 1, 65500, 56); if (v.os === "Windows") return `ping -n ${count} -l ${size} ${host}`; return `ping -c ${count} -s ${size} ${host}`; } },

  { id: "n-traceroute-builder", name: "traceroute Command Builder", cat: "network", desc: "Build a traceroute (or tracert) command for the target OS.", tags: ["traceroute", "tracert", "command"],
    inputs: [{ k: "host", label: "Host or IP", type: "text", placeholder: "example.com" }, { k: "os", label: "OS", type: "select", opts: ["Linux", "macOS", "Windows"], value: "Linux" }],
    run(v) { if (!v.host) return ""; const host = v.host.trim(); return v.os === "Windows" ? `tracert ${host}` : `traceroute ${host}`; } },

  { id: "n-nmap-builder", name: "nmap Command Builder", cat: "network", desc: "Build an nmap command for a scan type, ports and NSE scripts, for authorized testing.", tags: ["nmap", "scan", "command"],
    inputs: [{ k: "target", label: "Target (host/IP/CIDR)", type: "text", placeholder: "192.168.1.0/24" }, { k: "scanType", label: "Scan type", type: "select", opts: ["SYN (stealth)", "TCP Connect", "UDP", "Version detection", "OS detection", "Ping scan (no ports)", "Aggressive"], value: "SYN (stealth)" }, { k: "ports", label: "Ports (optional)", type: "text", placeholder: "22,80,443 or 1-1000" }, { k: "scripts", label: "NSE scripts (optional)", type: "text", placeholder: "default,vuln" }, { k: "timing", label: "Fast timing (-T4)", type: "checkbox", value: false }],
    run(v) {
      if (!v.target) return "";
      const flags = { "SYN (stealth)": "-sS", "TCP Connect": "-sT", "UDP": "-sU", "Version detection": "-sV", "OS detection": "-O", "Ping scan (no ports)": "-sn", "Aggressive": "-A" };
      let cmd = `nmap ${flags[v.scanType] || "-sS"}`;
      if (v.ports) cmd += ` -p ${v.ports.trim()}`;
      if (v.scripts) cmd += ` --script ${v.scripts.trim()}`;
      if (v.timing) cmd += " -T4";
      cmd += ` ${v.target.trim()}`;
      return cmd;
    } },

  { id: "n-curl-builder", name: "curl Command Builder", cat: "network", desc: "Build a curl command with method, headers and body.", tags: ["curl", "http", "command"],
    inputs: [{ k: "method", label: "Method", type: "select", opts: ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], value: "GET" }, { k: "url", label: "URL", type: "text", placeholder: "https://api.example.com/v1/items" }, { k: "headers", label: "Headers (one per line, Key: Value)", type: "textarea", rows: 3, placeholder: "Authorization: Bearer TOKEN\nContent-Type: application/json" }, { k: "data", label: "Body data (optional)", type: "textarea", rows: 2, placeholder: '{"key":"value"}' }, { k: "insecure", label: "Insecure (-k, skip TLS verify)", type: "checkbox", value: false }, { k: "verbose", label: "Verbose (-v)", type: "checkbox", value: false }],
    run(v) {
      if (!v.url) return "";
      let cmd = "curl";
      if (v.method && v.method !== "GET") cmd += ` -X ${v.method}`;
      const headers = String(v.headers || "").split("\n").map((s) => s.trim()).filter(Boolean);
      for (const h of headers) cmd += ` -H "${h.replace(/"/g, '\\"')}"`;
      if (v.data) cmd += ` -d '${String(v.data).replace(/'/g, "'\\''")}'`;
      if (v.insecure) cmd += " -k";
      if (v.verbose) cmd += " -v";
      cmd += ` "${v.url.trim()}"`;
      return cmd;
    } },

  { id: "n-wget-builder", name: "wget Command Builder", cat: "network", desc: "Build a wget download command with common options.", tags: ["wget", "http", "command"],
    inputs: [{ k: "url", label: "URL", type: "text", placeholder: "https://example.com/file.tar.gz" }, { k: "output", label: "Output filename (optional)", type: "text", placeholder: "file.tar.gz" }, { k: "continueDl", label: "Resume (-c)", type: "checkbox", value: false }, { k: "quiet", label: "Quiet (-q)", type: "checkbox", value: false }, { k: "ua", label: "Custom User-Agent (optional)", type: "text" }],
    run(v) {
      if (!v.url) return "";
      let cmd = "wget";
      if (v.output) cmd += ` -O ${v.output.trim()}`;
      if (v.continueDl) cmd += " -c";
      if (v.quiet) cmd += " -q";
      if (v.ua) cmd += ` --user-agent="${v.ua.trim()}"`;
      cmd += ` "${v.url.trim()}"`;
      return cmd;
    } },

  { id: "n-netcat-builder", name: "netcat Command Builder", cat: "network", desc: "Build a netcat listener or connect command for authorized testing.", tags: ["netcat", "nc", "command"],
    inputs: [{ k: "mode", label: "Mode", type: "select", opts: ["Listen", "Connect"], value: "Listen" }, { k: "host", label: "Host (connect mode)", type: "text", placeholder: "10.0.0.5" }, { k: "port", label: "Port", type: "text", inputType: "number", placeholder: "4444" }, { k: "udp", label: "UDP (-u)", type: "checkbox", value: false }, { k: "verbose", label: "Verbose (-v)", type: "checkbox", value: false }],
    run(v) {
      if (!v.port) return "";
      let cmd = "nc";
      if (v.verbose) cmd += " -v";
      if (v.udp) cmd += " -u";
      if (v.mode === "Listen") { cmd += ` -l ${v.port.trim()}`; return cmd; }
      if (!v.host) return { error: "Enter a host to connect to." };
      cmd += ` ${v.host.trim()} ${v.port.trim()}`;
      return cmd;
    } },

  { id: "n-tcpdump-builder", name: "tcpdump Filter Builder", cat: "network", desc: "Build a tcpdump command with a host/port/protocol capture filter.", tags: ["tcpdump", "pcap", "command"],
    inputs: [{ k: "iface", label: "Interface (optional)", type: "text", placeholder: "eth0" }, { k: "host", label: "Host (optional)", type: "text", placeholder: "10.0.0.5" }, { k: "port", label: "Port (optional)", type: "text", inputType: "number" }, { k: "proto", label: "Protocol", type: "select", opts: ["any", "tcp", "udp", "icmp"], value: "any" }],
    run(v) {
      if (!v.iface && !v.host && !v.port && (!v.proto || v.proto === "any")) return "";
      let cmd = "tcpdump";
      if (v.iface) cmd += ` -i ${v.iface.trim()}`;
      const filters = [];
      if (v.host) filters.push(`host ${v.host.trim()}`);
      if (v.port) filters.push(`port ${v.port.trim()}`);
      if (v.proto && v.proto !== "any") filters.push(v.proto);
      if (filters.length) cmd += ` '${filters.join(" and ")}'`;
      return cmd;
    } },

  { id: "n-spf-check", name: "SPF Record Syntax Checker", cat: "network", desc: "Parse an SPF TXT record's mechanisms and qualifiers.", tags: ["spf", "dns", "email"],
    inputs: [{ k: "spf", label: "SPF record", type: "textarea", rows: 3, placeholder: "v=spf1 ip4:203.0.113.0/24 include:_spf.example.com ~all" }],
    run(v) {
      const rec = String(v.spf || "").trim();
      if (!rec) return "";
      if (!/^v=spf1\b/i.test(rec)) return { error: 'SPF record must start with "v=spf1".' };
      const tokens = rec.split(/\s+/).slice(1);
      const lines = []; let allSeen = false;
      const qualName = { "+": "Pass", "-": "Fail", "~": "SoftFail", "?": "Neutral" };
      for (const t of tokens) {
        if (/^(\+|-|~|\?)?all$/i.test(t)) { const q = qualName[t[0]] || "Pass"; lines.push(`all → ${q} (catch-all)`); allSeen = true; continue; }
        const m = t.match(/^(\+|-|~|\?)?(ip4|ip6|a|mx|ptr|exists|include|redirect|exp)(:?.*)$/i);
        if (m) { const q = qualName[m[1]] || "Pass"; lines.push(`${m[2]}${m[3] || ""} → ${q}`); }
        else lines.push(`Unrecognized mechanism: "${t}"`);
      }
      if (!allSeen) lines.push('(no "all" mechanism — record does not terminate explicitly)');
      return lines.join("\n");
    } },

  { id: "n-ipv6-ula", name: "IPv6 ULA Prefix Generator", cat: "network", desc: "Generate a random Unique Local Address prefix (fd00::/48) per RFC 4193.", tags: ["ipv6", "ula", "random"], button: "Generate", live: false,
    inputs: [],
    run(v, H) { const rnd = H.randBytes(5); const hex = "fd" + H.toHex(rnd); return `${hex.slice(0, 4)}:${hex.slice(4, 8)}:${hex.slice(8, 12)}::/48`; } },

  { id: "n-ipv4-mapped-ipv6", name: "IPv4 → IPv6 Mapped Address", cat: "network", desc: "Embed an IPv4 address into its IPv4-mapped and IPv4-compatible IPv6 forms.", tags: ["ipv6", "ipv4", "mapped"],
    inputs: [{ k: "ip", label: "IPv4 address", type: "text", placeholder: "203.0.113.5" }],
    run(v) { if (!v.ip) return ""; const p = parseIPv4(v.ip); if (!p) return { error: "Enter a valid IPv4 address." }; const hex = p.map((b) => b.toString(16).padStart(2, "0")).join(""); const g1 = hex.slice(0, 4), g2 = hex.slice(4, 8); return `IPv4-mapped: ::ffff:${g1}:${g2}  (equivalently ::ffff:${v.ip.trim()})\nIPv4-compatible (deprecated): ::${v.ip.trim()}`; } },

  { id: "n-whois-builder", name: "whois Command Builder", cat: "network", desc: "Build a whois lookup command for a domain or IP, with an optional server.", tags: ["whois", "command"],
    inputs: [{ k: "target", label: "Domain or IP", type: "text", placeholder: "example.com" }, { k: "server", label: "Whois server (optional)", type: "text", placeholder: "whois.arin.net" }],
    run(v) { if (!v.target) return ""; const server = (v.server || "").trim(); return `whois${server ? ` -h ${server}` : ""} ${v.target.trim()}`; } },

  { id: "n-ssh-builder", name: "ssh Command Builder", cat: "network", desc: "Build an ssh command with user, port, identity file and options.", tags: ["ssh", "command"],
    inputs: [{ k: "host", label: "Host or IP", type: "text", placeholder: "10.0.0.5" }, { k: "user", label: "User (optional)", type: "text", placeholder: "root" }, { k: "port", label: "Port", type: "text", inputType: "number", value: "22" }, { k: "key", label: "Identity file (optional)", type: "text", placeholder: "~/.ssh/id_ed25519" }, { k: "agentForward", label: "Agent forwarding (-A)", type: "checkbox", value: false }, { k: "verbose", label: "Verbose (-v)", type: "checkbox", value: false }],
    run(v) {
      if (!v.host) return "";
      let cmd = "ssh";
      if (v.verbose) cmd += " -v";
      if (v.port && v.port !== "22") cmd += ` -p ${v.port.trim()}`;
      if (v.key) cmd += ` -i ${v.key.trim()}`;
      if (v.agentForward) cmd += " -A";
      cmd += ` ${v.user ? v.user.trim() + "@" : ""}${v.host.trim()}`;
      return cmd;
    } },

  { id: "n-openssl-builder", name: "openssl s_client Command Builder", cat: "network", desc: "Build an openssl s_client command to inspect a TLS endpoint's certificate.", tags: ["openssl", "tls", "command"],
    inputs: [{ k: "host", label: "Host", type: "text", placeholder: "example.com" }, { k: "port", label: "Port", type: "text", inputType: "number", value: "443" }, { k: "sni", label: "SNI hostname (optional)", type: "text" }, { k: "showCerts", label: "Show full chain (-showcerts)", type: "checkbox", value: false }],
    run(v) {
      if (!v.host) return "";
      const port = (v.port || "443").trim();
      let cmd = `openssl s_client -connect ${v.host.trim()}:${port}`;
      if (v.sni) cmd += ` -servername ${v.sni.trim()}`;
      if (v.showCerts) cmd += " -showcerts";
      return cmd;
    } },
];
