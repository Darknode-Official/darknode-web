// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
// Darknode Packet Analyzer — parse raw hex packets into protocol layers

// ── Protocol Constants ──────────────────────────────────────────────────────

const ETHERTYPES = {
  "0800": "IPv4", "0806": "ARP", "86dd": "IPv6", "8100": "802.1Q VLAN",
  "8847": "MPLS Unicast", "8848": "MPLS Multicast", "0842": "Wake-on-LAN",
  "22f3": "IETF TRILL", "6003": "DECnet Phase IV", "8035": "RARP",
  "809b": "AppleTalk", "80f3": "AARP", "8137": "IPX", "8204": "QNX Qnet",
  "88a8": "802.1ad (QinQ)", "88cc": "LLDP", "88e5": "802.1AE (MACsec)",
  "88f7": "PTP (IEEE 1588)", "8902": "802.1ag (CFM)", "8906": "FCoE",
  "8914": "FCoE Init", "88e1": "HomePlug AV", "9000": "Loopback (config testing)",
};

const IP_PROTOCOLS = {
  1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6 Encapsulation",
  43: "IPv6 Routing", 44: "IPv6 Fragment", 47: "GRE", 50: "ESP", 51: "AH",
  58: "ICMPv6", 59: "IPv6 No Next Header", 60: "IPv6 Destination Options",
  88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP",
};

const TCP_FLAGS = {
  FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08,
  ACK: 0x10, URG: 0x20, ECE: 0x40, CWR: 0x80,
};

const WELL_KNOWN_PORTS = {
  20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
  53: "DNS", 67: "DHCP Server", 68: "DHCP Client", 69: "TFTP", 80: "HTTP",
  88: "Kerberos", 110: "POP3", 119: "NNTP", 123: "NTP", 135: "MS RPC",
  137: "NetBIOS Name", 138: "NetBIOS Datagram", 139: "NetBIOS Session",
  143: "IMAP", 161: "SNMP", 162: "SNMP Trap", 179: "BGP", 194: "IRC",
  389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
  515: "LPD", 520: "RIP", 523: "IBM DB2", 530: "RPC", 543: "Klogin",
  544: "Kshell", 548: "AFP", 554: "RTSP", 587: "SMTP Submission",
  631: "IPP/CUPS", 636: "LDAPS", 873: "rsync", 993: "IMAPS", 995: "POP3S",
  1080: "SOCKS", 1433: "MSSQL", 1434: "MSSQL UDP", 1521: "Oracle",
  1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel SSL",
  2181: "ZooKeeper", 3306: "MySQL", 3389: "RDP", 3690: "SVN",
  4443: "Pharos", 5060: "SIP", 5061: "SIP TLS", 5432: "PostgreSQL",
  5672: "AMQP", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
  6443: "Kubernetes API", 6667: "IRC", 8080: "HTTP Proxy", 8443: "HTTPS Alt",
  8888: "HTTP Alt", 9090: "Prometheus", 9200: "Elasticsearch",
  9300: "Elasticsearch Transport", 11211: "Memcached", 27017: "MongoDB",
  27018: "MongoDB Shard", 50000: "SAP",
};

const DNS_TYPES = {
  1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
  28: "AAAA", 33: "SRV", 35: "NAPTR", 36: "KX", 37: "CERT", 39: "DNAME",
  43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3",
  51: "NSEC3PARAM", 52: "TLSA", 55: "HIP", 59: "CDS", 60: "CDNSKEY",
  61: "OPENPGPKEY", 64: "SVCB", 65: "HTTPS", 99: "SPF", 249: "TKEY",
  250: "TSIG", 251: "IXFR", 252: "AXFR", 255: "ANY", 256: "URI",
  257: "CAA",
};

const DNS_CLASSES = { 1: "IN", 2: "CS", 3: "CH", 4: "HS", 255: "ANY" };

const DNS_RCODES = {
  0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
  5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH",
  10: "NOTZONE", 16: "BADSIG/BADVERS", 17: "BADKEY", 18: "BADTIME",
  19: "BADMODE", 20: "BADNAME", 21: "BADALG", 22: "BADTRUNC",
};

const ICMP_TYPES = {
  0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
  5: "Redirect", 8: "Echo Request", 9: "Router Advertisement",
  10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
  13: "Timestamp Request", 14: "Timestamp Reply", 15: "Info Request",
  16: "Info Reply", 17: "Address Mask Request", 18: "Address Mask Reply",
  30: "Traceroute", 40: "Photuris Security Failure",
};

const ICMP_UNREACH_CODES = {
  0: "Net Unreachable", 1: "Host Unreachable", 2: "Protocol Unreachable",
  3: "Port Unreachable", 4: "Fragmentation Needed (DF set)",
  5: "Source Route Failed", 6: "Destination Network Unknown",
  7: "Destination Host Unknown", 8: "Source Host Isolated",
  9: "Network Administratively Prohibited", 10: "Host Administratively Prohibited",
  11: "Network Unreachable for TOS", 12: "Host Unreachable for TOS",
  13: "Communication Administratively Prohibited",
};

const TLS_CONTENT_TYPES = {
  20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData",
};

const TLS_VERSIONS = {
  "0300": "SSL 3.0", "0301": "TLS 1.0", "0302": "TLS 1.1",
  "0303": "TLS 1.2", "0304": "TLS 1.3",
};

const TLS_HANDSHAKE_TYPES = {
  0: "HelloRequest", 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
  5: "EndOfEarlyData", 8: "EncryptedExtensions", 11: "Certificate",
  12: "ServerKeyExchange", 13: "CertificateRequest", 14: "ServerHelloDone",
  15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished",
};

const TLS_CIPHER_SUITES = {
  "1301": "TLS_AES_128_GCM_SHA256", "1302": "TLS_AES_256_GCM_SHA384",
  "1303": "TLS_CHACHA20_POLY1305_SHA256", "c02b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  "c02c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "c02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  "c030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "cca8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
  "cca9": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "c013": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
  "c014": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "009c": "TLS_RSA_WITH_AES_128_GCM_SHA256",
  "009d": "TLS_RSA_WITH_AES_256_GCM_SHA384", "002f": "TLS_RSA_WITH_AES_128_CBC_SHA",
  "0035": "TLS_RSA_WITH_AES_256_CBC_SHA", "000a": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
  "00ff": "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
};

const TLS_EXTENSIONS = {
  0: "server_name", 1: "max_fragment_length", 5: "status_request",
  10: "supported_groups", 11: "ec_point_formats", 13: "signature_algorithms",
  14: "use_srtp", 15: "heartbeat", 16: "application_layer_protocol_negotiation",
  18: "signed_certificate_timestamp", 21: "padding", 22: "encrypt_then_mac",
  23: "extended_master_secret", 27: "compress_certificate",
  28: "record_size_limit", 35: "session_ticket", 41: "pre_shared_key",
  42: "early_data", 43: "supported_versions", 44: "cookie",
  45: "psk_key_exchange_modes", 47: "certificate_authorities",
  48: "oid_filters", 49: "post_handshake_auth", 50: "signature_algorithms_cert",
  51: "key_share", 65281: "renegotiation_info",
};

const ARP_OPCODES = { 1: "Request", 2: "Reply", 3: "RARP Request", 4: "RARP Reply" };

const DHCP_OPTIONS = {
  1: "Subnet Mask", 3: "Router", 6: "DNS Server", 12: "Hostname",
  15: "Domain Name", 28: "Broadcast Address", 33: "Static Route",
  42: "NTP Server", 43: "Vendor Specific", 44: "NetBIOS Name Server",
  46: "NetBIOS Node Type", 50: "Requested IP", 51: "Lease Time",
  53: "DHCP Message Type", 54: "DHCP Server ID", 55: "Parameter Request List",
  56: "Message", 57: "Max DHCP Message Size", 58: "Renewal Time",
  59: "Rebinding Time", 60: "Vendor Class ID", 61: "Client ID",
  66: "TFTP Server Name", 67: "Bootfile Name", 81: "Client FQDN",
  82: "Relay Agent Info", 119: "Domain Search", 121: "Classless Static Route",
  150: "TFTP Server Address", 252: "WPAD URL",
};

const DHCP_MSG_TYPES = {
  1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
  5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
};

// ── Hex Parsing Utilities ───────────────────────────────────────────────────

function hexToBytes(hex) {
  const clean = hex.replace(/[\s\-:,0x]/g, "").toLowerCase();
  const bytes = [];
  for (let i = 0; i < clean.length; i += 2) {
    const b = parseInt(clean.substr(i, 2), 16);
    if (isNaN(b)) break;
    bytes.push(b);
  }
  return bytes;
}

function bytesToHex(bytes, start, len) {
  return bytes.slice(start, start + len).map(b => b.toString(16).padStart(2, "0")).join("");
}

function bytesToInt(bytes, start, len) {
  let val = 0;
  for (let i = 0; i < len; i++) val = (val << 8) | (bytes[start + i] || 0);
  return val >>> 0;
}

function bytesToIP(bytes, start) {
  return bytes.slice(start, start + 4).join(".");
}

function bytesToIPv6(bytes, start) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(bytesToHex(bytes, start + i, 2));
  }
  return groups.join(":").replace(/(^|:)0{1,3}/g, "$1").replace(/(:0)+:/, "::");
}

function bytesToMAC(bytes, start) {
  return bytes.slice(start, start + 6).map(b => b.toString(16).padStart(2, "0")).join(":");
}

function bytesToASCII(bytes) {
  return bytes.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".").join("");
}

function ipChecksum(bytes, start, len) {
  let sum = 0;
  for (let i = 0; i < len; i += 2) {
    sum += (bytes[start + i] << 8) | (bytes[start + i + 1] || 0);
  }
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return (~sum) & 0xFFFF;
}

function flagsToString(value, flagMap) {
  return Object.entries(flagMap)
    .filter(([, bit]) => value & bit)
    .map(([name]) => name)
    .join(", ") || "None";
}

// ── Protocol Parsers ────────────────────────────────────────────────────────

function parseEthernet(bytes, offset) {
  if (bytes.length < offset + 14) return { error: "Too short for Ethernet header", length: 0 };
  const dst = bytesToMAC(bytes, offset);
  const src = bytesToMAC(bytes, offset + 6);
  let etherType = bytesToHex(bytes, offset + 12, 2);
  let headerLen = 14;
  let vlan = null;
  if (etherType === "8100") {
    const tci = bytesToInt(bytes, offset + 14, 2);
    vlan = { priority: (tci >> 13) & 7, cfi: (tci >> 12) & 1, id: tci & 0xFFF };
    etherType = bytesToHex(bytes, offset + 16, 2);
    headerLen = 18;
  }
  return {
    name: "Ethernet II",
    fields: [
      { name: "Destination MAC", value: dst, offset: offset, length: 6 },
      { name: "Source MAC", value: src, offset: offset + 6, length: 6 },
      ...(vlan ? [
        { name: "VLAN Priority", value: vlan.priority, offset: offset + 14, length: 2 },
        { name: "VLAN CFI", value: vlan.cfi, offset: offset + 14, length: 2 },
        { name: "VLAN ID", value: vlan.id, offset: offset + 14, length: 2 },
      ] : []),
      { name: "EtherType", value: "0x" + etherType + " (" + (ETHERTYPES[etherType] || "Unknown") + ")", offset: offset + (vlan ? 16 : 12), length: 2 },
    ],
    etherType: etherType,
    length: headerLen,
    offset: offset,
  };
}

function parseARP(bytes, offset) {
  if (bytes.length < offset + 28) return { error: "Too short for ARP", length: 0 };
  const hwType = bytesToInt(bytes, offset, 2);
  const protoType = bytesToHex(bytes, offset + 2, 2);
  const hwLen = bytes[offset + 4];
  const protoLen = bytes[offset + 5];
  const opcode = bytesToInt(bytes, offset + 6, 2);
  const senderMAC = bytesToMAC(bytes, offset + 8);
  const senderIP = bytesToIP(bytes, offset + 14);
  const targetMAC = bytesToMAC(bytes, offset + 18);
  const targetIP = bytesToIP(bytes, offset + 24);
  return {
    name: "ARP",
    fields: [
      { name: "Hardware Type", value: hwType + (hwType === 1 ? " (Ethernet)" : ""), offset, length: 2 },
      { name: "Protocol Type", value: "0x" + protoType, offset: offset + 2, length: 2 },
      { name: "Hardware Size", value: hwLen, offset: offset + 4, length: 1 },
      { name: "Protocol Size", value: protoLen, offset: offset + 5, length: 1 },
      { name: "Opcode", value: opcode + " (" + (ARP_OPCODES[opcode] || "Unknown") + ")", offset: offset + 6, length: 2 },
      { name: "Sender MAC", value: senderMAC, offset: offset + 8, length: 6 },
      { name: "Sender IP", value: senderIP, offset: offset + 14, length: 4 },
      { name: "Target MAC", value: targetMAC, offset: offset + 18, length: 6 },
      { name: "Target IP", value: targetIP, offset: offset + 24, length: 4 },
    ],
    length: 28,
    offset,
  };
}

function parseIPv4(bytes, offset) {
  if (bytes.length < offset + 20) return { error: "Too short for IPv4 header", length: 0 };
  const versionIHL = bytes[offset];
  const version = (versionIHL >> 4) & 0xF;
  const ihl = versionIHL & 0xF;
  const headerLen = ihl * 4;
  const dscp = (bytes[offset + 1] >> 2) & 0x3F;
  const ecn = bytes[offset + 1] & 3;
  const totalLength = bytesToInt(bytes, offset + 2, 2);
  const identification = bytesToInt(bytes, offset + 4, 2);
  const flagsFragment = bytesToInt(bytes, offset + 6, 2);
  const flags = (flagsFragment >> 13) & 7;
  const fragmentOffset = flagsFragment & 0x1FFF;
  const ttl = bytes[offset + 8];
  const protocol = bytes[offset + 9];
  const checksum = bytesToInt(bytes, offset + 10, 2);
  const srcIP = bytesToIP(bytes, offset + 12);
  const dstIP = bytesToIP(bytes, offset + 16);
  const flagStr = [];
  if (flags & 4) flagStr.push("Reserved");
  if (flags & 2) flagStr.push("DF");
  if (flags & 1) flagStr.push("MF");
  const computed = ipChecksum(bytes, offset, headerLen);
  const checksumOk = (computed === 0) ? "OK" : "INCORRECT (computed: 0x" + computed.toString(16) + ")";
  const options = [];
  if (headerLen > 20) {
    let optOff = offset + 20;
    while (optOff < offset + headerLen) {
      const type = bytes[optOff];
      if (type === 0) break;
      if (type === 1) { options.push({ name: "NOP", offset: optOff, length: 1 }); optOff++; continue; }
      const optLen = bytes[optOff + 1] || 1;
      const optNames = { 7: "Record Route", 68: "Timestamp", 131: "Loose Source Route", 137: "Strict Source Route", 148: "Router Alert" };
      options.push({ name: optNames[type] || ("Option " + type), offset: optOff, length: optLen, data: bytesToHex(bytes, optOff, optLen) });
      optOff += optLen;
    }
  }
  return {
    name: "IPv4",
    fields: [
      { name: "Version", value: version, offset, length: 1 },
      { name: "IHL", value: ihl + " (" + headerLen + " bytes)", offset, length: 1 },
      { name: "DSCP", value: dscp, offset: offset + 1, length: 1 },
      { name: "ECN", value: ecn, offset: offset + 1, length: 1 },
      { name: "Total Length", value: totalLength + " bytes", offset: offset + 2, length: 2 },
      { name: "Identification", value: "0x" + identification.toString(16).padStart(4, "0") + " (" + identification + ")", offset: offset + 4, length: 2 },
      { name: "Flags", value: "0x" + flags.toString(16) + " (" + (flagStr.join(", ") || "None") + ")", offset: offset + 6, length: 2 },
      { name: "Fragment Offset", value: fragmentOffset, offset: offset + 6, length: 2 },
      { name: "TTL", value: ttl, offset: offset + 8, length: 1 },
      { name: "Protocol", value: protocol + " (" + (IP_PROTOCOLS[protocol] || "Unknown") + ")", offset: offset + 9, length: 1 },
      { name: "Header Checksum", value: "0x" + checksum.toString(16).padStart(4, "0") + " [" + checksumOk + "]", offset: offset + 10, length: 2 },
      { name: "Source IP", value: srcIP, offset: offset + 12, length: 4 },
      { name: "Destination IP", value: dstIP, offset: offset + 16, length: 4 },
      ...options.map(o => ({ name: "Option: " + o.name, value: o.data || "", offset: o.offset, length: o.length })),
    ],
    protocol,
    srcIP,
    dstIP,
    totalLength,
    length: headerLen,
    offset,
  };
}

function parseIPv6(bytes, offset) {
  if (bytes.length < offset + 40) return { error: "Too short for IPv6 header", length: 0 };
  const vtcfl = bytesToInt(bytes, offset, 4);
  const version = (vtcfl >> 28) & 0xF;
  const trafficClass = (vtcfl >> 20) & 0xFF;
  const flowLabel = vtcfl & 0xFFFFF;
  const payloadLength = bytesToInt(bytes, offset + 4, 2);
  const nextHeader = bytes[offset + 6];
  const hopLimit = bytes[offset + 7];
  const srcIP = bytesToIPv6(bytes, offset + 8);
  const dstIP = bytesToIPv6(bytes, offset + 24);
  return {
    name: "IPv6",
    fields: [
      { name: "Version", value: version, offset, length: 4 },
      { name: "Traffic Class", value: "0x" + trafficClass.toString(16).padStart(2, "0"), offset, length: 4 },
      { name: "Flow Label", value: "0x" + flowLabel.toString(16).padStart(5, "0"), offset, length: 4 },
      { name: "Payload Length", value: payloadLength + " bytes", offset: offset + 4, length: 2 },
      { name: "Next Header", value: nextHeader + " (" + (IP_PROTOCOLS[nextHeader] || "Unknown") + ")", offset: offset + 6, length: 1 },
      { name: "Hop Limit", value: hopLimit, offset: offset + 7, length: 1 },
      { name: "Source IP", value: srcIP, offset: offset + 8, length: 16 },
      { name: "Destination IP", value: dstIP, offset: offset + 24, length: 16 },
    ],
    protocol: nextHeader,
    srcIP,
    dstIP,
    payloadLength,
    length: 40,
    offset,
  };
}

function parseTCP(bytes, offset) {
  if (bytes.length < offset + 20) return { error: "Too short for TCP header", length: 0 };
  const srcPort = bytesToInt(bytes, offset, 2);
  const dstPort = bytesToInt(bytes, offset + 2, 2);
  const seq = bytesToInt(bytes, offset + 4, 4);
  const ack = bytesToInt(bytes, offset + 8, 4);
  const dataOffsetFlags = bytesToInt(bytes, offset + 12, 2);
  const dataOffset = ((dataOffsetFlags >> 12) & 0xF) * 4;
  const flags = dataOffsetFlags & 0x1FF;
  const window = bytesToInt(bytes, offset + 14, 2);
  const checksum = bytesToInt(bytes, offset + 16, 2);
  const urgentPtr = bytesToInt(bytes, offset + 18, 2);
  const activeFlags = flagsToString(flags, TCP_FLAGS);
  const options = [];
  if (dataOffset > 20) {
    let optOff = offset + 20;
    while (optOff < offset + dataOffset) {
      const kind = bytes[optOff];
      if (kind === 0) break;
      if (kind === 1) { options.push({ name: "NOP", offset: optOff, length: 1 }); optOff++; continue; }
      const optLen = bytes[optOff + 1] || 1;
      let optName = "Unknown (" + kind + ")";
      let optValue = bytesToHex(bytes, optOff + 2, Math.max(0, optLen - 2));
      if (kind === 2) { optName = "MSS"; optValue = bytesToInt(bytes, optOff + 2, 2) + " bytes"; }
      else if (kind === 3) { optName = "Window Scale"; optValue = "shift " + bytes[optOff + 2] + " (multiply by " + (1 << bytes[optOff + 2]) + ")"; }
      else if (kind === 4) { optName = "SACK Permitted"; optValue = ""; }
      else if (kind === 5) {
        optName = "SACK";
        const blockCount = (optLen - 2) / 8;
        const blocks = [];
        for (let b = 0; b < blockCount; b++) {
          const left = bytesToInt(bytes, optOff + 2 + b * 8, 4);
          const right = bytesToInt(bytes, optOff + 6 + b * 8, 4);
          blocks.push(left + "-" + right);
        }
        optValue = blocks.join(", ");
      }
      else if (kind === 8) {
        optName = "Timestamps";
        const tsval = bytesToInt(bytes, optOff + 2, 4);
        const tsecr = bytesToInt(bytes, optOff + 6, 4);
        optValue = "TSval=" + tsval + " TSecr=" + tsecr;
      }
      else if (kind === 28) { optName = "User Timeout"; }
      else if (kind === 29) { optName = "TCP Authentication"; }
      else if (kind === 30) { optName = "Multipath TCP"; }
      else if (kind === 34) { optName = "TCP Fast Open"; }
      options.push({ name: optName, value: optValue, offset: optOff, length: optLen });
      optOff += optLen;
    }
  }
  const srcService = WELL_KNOWN_PORTS[srcPort] || "";
  const dstService = WELL_KNOWN_PORTS[dstPort] || "";
  return {
    name: "TCP",
    fields: [
      { name: "Source Port", value: srcPort + (srcService ? " (" + srcService + ")" : ""), offset, length: 2 },
      { name: "Destination Port", value: dstPort + (dstService ? " (" + dstService + ")" : ""), offset: offset + 2, length: 2 },
      { name: "Sequence Number", value: seq, offset: offset + 4, length: 4 },
      { name: "Acknowledgment Number", value: ack, offset: offset + 8, length: 4 },
      { name: "Data Offset", value: (dataOffset / 4) + " (" + dataOffset + " bytes)", offset: offset + 12, length: 2 },
      { name: "Flags", value: "0x" + (flags & 0xFF).toString(16).padStart(2, "0") + " (" + activeFlags + ")", offset: offset + 12, length: 2 },
      { name: "Window Size", value: window, offset: offset + 14, length: 2 },
      { name: "Checksum", value: "0x" + checksum.toString(16).padStart(4, "0"), offset: offset + 16, length: 2 },
      { name: "Urgent Pointer", value: urgentPtr, offset: offset + 18, length: 2 },
      ...options.map(o => ({ name: "Option: " + o.name, value: String(o.value), offset: o.offset, length: o.length })),
    ],
    srcPort,
    dstPort,
    length: dataOffset,
    offset,
    flags,
    seq,
    ack,
  };
}

function parseUDP(bytes, offset) {
  if (bytes.length < offset + 8) return { error: "Too short for UDP header", length: 0 };
  const srcPort = bytesToInt(bytes, offset, 2);
  const dstPort = bytesToInt(bytes, offset + 2, 2);
  const udpLength = bytesToInt(bytes, offset + 4, 2);
  const checksum = bytesToInt(bytes, offset + 6, 2);
  const srcService = WELL_KNOWN_PORTS[srcPort] || "";
  const dstService = WELL_KNOWN_PORTS[dstPort] || "";
  return {
    name: "UDP",
    fields: [
      { name: "Source Port", value: srcPort + (srcService ? " (" + srcService + ")" : ""), offset, length: 2 },
      { name: "Destination Port", value: dstPort + (dstService ? " (" + dstService + ")" : ""), offset: offset + 2, length: 2 },
      { name: "Length", value: udpLength + " bytes", offset: offset + 4, length: 2 },
      { name: "Checksum", value: "0x" + checksum.toString(16).padStart(4, "0"), offset: offset + 6, length: 2 },
    ],
    srcPort,
    dstPort,
    length: 8,
    offset,
    payloadLength: udpLength - 8,
  };
}

function parseICMP(bytes, offset) {
  if (bytes.length < offset + 8) return { error: "Too short for ICMP", length: 0 };
  const type = bytes[offset];
  const code = bytes[offset + 1];
  const checksum = bytesToInt(bytes, offset + 2, 2);
  const typeName = ICMP_TYPES[type] || "Unknown";
  let codeDesc = "";
  if (type === 3) codeDesc = ICMP_UNREACH_CODES[code] || "Unknown";
  else if (type === 5) {
    const redirectCodes = { 0: "Redirect for Network", 1: "Redirect for Host", 2: "Redirect for TOS and Network", 3: "Redirect for TOS and Host" };
    codeDesc = redirectCodes[code] || "Unknown";
  }
  else if (type === 11) codeDesc = code === 0 ? "TTL exceeded in transit" : "Fragment reassembly time exceeded";
  const fields = [
    { name: "Type", value: type + " (" + typeName + ")", offset, length: 1 },
    { name: "Code", value: code + (codeDesc ? " (" + codeDesc + ")" : ""), offset: offset + 1, length: 1 },
    { name: "Checksum", value: "0x" + checksum.toString(16).padStart(4, "0"), offset: offset + 2, length: 2 },
  ];
  if (type === 0 || type === 8) {
    fields.push({ name: "Identifier", value: bytesToInt(bytes, offset + 4, 2), offset: offset + 4, length: 2 });
    fields.push({ name: "Sequence Number", value: bytesToInt(bytes, offset + 6, 2), offset: offset + 6, length: 2 });
  } else if (type === 3 && code === 4) {
    fields.push({ name: "Next-Hop MTU", value: bytesToInt(bytes, offset + 6, 2), offset: offset + 6, length: 2 });
  } else if (type === 5) {
    fields.push({ name: "Gateway Address", value: bytesToIP(bytes, offset + 4), offset: offset + 4, length: 4 });
  }
  return { name: "ICMP", fields, length: 8, offset };
}

function parseDNS(bytes, offset, maxLen) {
  if (bytes.length < offset + 12) return { error: "Too short for DNS header", length: 0 };
  const txid = bytesToInt(bytes, offset, 2);
  const flagsWord = bytesToInt(bytes, offset + 2, 2);
  const qr = (flagsWord >> 15) & 1;
  const opcode = (flagsWord >> 11) & 0xF;
  const aa = (flagsWord >> 10) & 1;
  const tc = (flagsWord >> 9) & 1;
  const rd = (flagsWord >> 8) & 1;
  const ra = (flagsWord >> 7) & 1;
  const z = (flagsWord >> 4) & 7;
  const rcode = flagsWord & 0xF;
  const qdcount = bytesToInt(bytes, offset + 4, 2);
  const ancount = bytesToInt(bytes, offset + 6, 2);
  const nscount = bytesToInt(bytes, offset + 8, 2);
  const arcount = bytesToInt(bytes, offset + 10, 2);
  const fields = [
    { name: "Transaction ID", value: "0x" + txid.toString(16).padStart(4, "0"), offset, length: 2 },
    { name: "QR", value: qr ? "1 (Response)" : "0 (Query)", offset: offset + 2, length: 2 },
    { name: "Opcode", value: opcode + " (" + (["Query", "IQuery", "Status", "", "Notify", "Update"][opcode] || "Unknown") + ")", offset: offset + 2, length: 2 },
    { name: "Authoritative (AA)", value: aa, offset: offset + 2, length: 2 },
    { name: "Truncated (TC)", value: tc, offset: offset + 2, length: 2 },
    { name: "Recursion Desired (RD)", value: rd, offset: offset + 2, length: 2 },
    { name: "Recursion Available (RA)", value: ra, offset: offset + 2, length: 2 },
    { name: "Z (Reserved)", value: z, offset: offset + 2, length: 2 },
    { name: "RCODE", value: rcode + " (" + (DNS_RCODES[rcode] || "Unknown") + ")", offset: offset + 2, length: 2 },
    { name: "Questions", value: qdcount, offset: offset + 4, length: 2 },
    { name: "Answer RRs", value: ancount, offset: offset + 6, length: 2 },
    { name: "Authority RRs", value: nscount, offset: offset + 8, length: 2 },
    { name: "Additional RRs", value: arcount, offset: offset + 10, length: 2 },
  ];
  let pos = offset + 12;
  function readName(start) {
    let parts = [], p = start, jumped = false, savedP = 0;
    for (let safety = 0; safety < 128; safety++) {
      if (p >= bytes.length) break;
      const len = bytes[p];
      if (len === 0) { p++; break; }
      if ((len & 0xC0) === 0xC0) {
        if (!jumped) savedP = p + 2;
        p = ((len & 0x3F) << 8) | bytes[p + 1];
        jumped = true;
        continue;
      }
      parts.push(bytes.slice(p + 1, p + 1 + len).map(b => String.fromCharCode(b)).join(""));
      p += 1 + len;
    }
    return { name: parts.join(".") || "(root)", endPos: jumped ? savedP : p };
  }
  for (let q = 0; q < qdcount && pos < bytes.length; q++) {
    const qn = readName(pos);
    pos = qn.endPos;
    const qtype = bytesToInt(bytes, pos, 2);
    const qclass = bytesToInt(bytes, pos + 2, 2);
    fields.push({ name: "Query: " + qn.name, value: (DNS_TYPES[qtype] || "Type " + qtype) + " " + (DNS_CLASSES[qclass] || "Class " + qclass), offset: pos - 1, length: 4 });
    pos += 4;
  }
  function readRR(label) {
    const rn = readName(pos);
    pos = rn.endPos;
    const rtype = bytesToInt(bytes, pos, 2);
    const rclass = bytesToInt(bytes, pos + 2, 2);
    const rttl = bytesToInt(bytes, pos + 4, 4);
    const rdlength = bytesToInt(bytes, pos + 8, 2);
    pos += 10;
    let rdata = bytesToHex(bytes, pos, rdlength);
    if (rtype === 1 && rdlength === 4) rdata = bytesToIP(bytes, pos);
    else if (rtype === 28 && rdlength === 16) rdata = bytesToIPv6(bytes, pos);
    else if (rtype === 5 || rtype === 2 || rtype === 12 || rtype === 39) rdata = readName(pos).name;
    else if (rtype === 15) rdata = "pref=" + bytesToInt(bytes, pos, 2) + " " + readName(pos + 2).name;
    else if (rtype === 16) {
      let txt = "";
      let tp = pos;
      while (tp < pos + rdlength) { const tl = bytes[tp]; txt += bytes.slice(tp + 1, tp + 1 + tl).map(b => String.fromCharCode(b)).join(""); tp += 1 + tl; }
      rdata = '"' + txt + '"';
    }
    fields.push({ name: label + ": " + rn.name, value: (DNS_TYPES[rtype] || "Type " + rtype) + " TTL=" + rttl + " " + rdata, offset: pos, length: rdlength });
    pos += rdlength;
  }
  for (let a = 0; a < ancount && pos < bytes.length; a++) readRR("Answer");
  for (let a = 0; a < nscount && pos < bytes.length; a++) readRR("Authority");
  for (let a = 0; a < arcount && pos < bytes.length; a++) readRR("Additional");
  return { name: "DNS", fields, length: pos - offset, offset };
}

function parseTLS(bytes, offset) {
  if (bytes.length < offset + 5) return { error: "Too short for TLS", length: 0 };
  const contentType = bytes[offset];
  const version = bytesToHex(bytes, offset + 1, 2);
  const tlsLength = bytesToInt(bytes, offset + 3, 2);
  const fields = [
    { name: "Content Type", value: contentType + " (" + (TLS_CONTENT_TYPES[contentType] || "Unknown") + ")", offset, length: 1 },
    { name: "Version", value: "0x" + version + " (" + (TLS_VERSIONS[version] || "Unknown") + ")", offset: offset + 1, length: 2 },
    { name: "Length", value: tlsLength + " bytes", offset: offset + 3, length: 2 },
  ];
  if (contentType === 22 && bytes.length > offset + 5) {
    const hsType = bytes[offset + 5];
    const hsLen = (bytes[offset + 6] << 16) | (bytes[offset + 7] << 8) | bytes[offset + 8];
    fields.push({ name: "Handshake Type", value: hsType + " (" + (TLS_HANDSHAKE_TYPES[hsType] || "Unknown") + ")", offset: offset + 5, length: 1 });
    fields.push({ name: "Handshake Length", value: hsLen + " bytes", offset: offset + 6, length: 3 });
    if (hsType === 1 && bytes.length > offset + 43) {
      const chVersion = bytesToHex(bytes, offset + 9, 2);
      fields.push({ name: "Client Version", value: "0x" + chVersion + " (" + (TLS_VERSIONS[chVersion] || "Unknown") + ")", offset: offset + 9, length: 2 });
      fields.push({ name: "Client Random", value: bytesToHex(bytes, offset + 11, 32), offset: offset + 11, length: 32 });
      const sessIdLen = bytes[offset + 43];
      fields.push({ name: "Session ID Length", value: sessIdLen, offset: offset + 43, length: 1 });
      let cipherOff = offset + 44 + sessIdLen;
      if (cipherOff + 2 <= bytes.length) {
        const cipherLen = bytesToInt(bytes, cipherOff, 2);
        fields.push({ name: "Cipher Suites Length", value: cipherLen + " bytes (" + (cipherLen / 2) + " suites)", offset: cipherOff, length: 2 });
        for (let i = 0; i < cipherLen && i < 40; i += 2) {
          const cs = bytesToHex(bytes, cipherOff + 2 + i, 2);
          fields.push({ name: "Cipher Suite", value: "0x" + cs + " (" + (TLS_CIPHER_SUITES[cs] || "Unknown") + ")", offset: cipherOff + 2 + i, length: 2 });
        }
        let compOff = cipherOff + 2 + cipherLen;
        if (compOff + 1 <= bytes.length) {
          const compLen = bytes[compOff];
          compOff++;
          if (compOff + compLen <= bytes.length && compOff + compLen + 2 <= bytes.length) {
            let extOff = compOff + compLen;
            if (extOff + 2 <= bytes.length) {
              const extTotalLen = bytesToInt(bytes, extOff, 2);
              extOff += 2;
              const extEnd = extOff + extTotalLen;
              while (extOff + 4 <= extEnd && extOff + 4 <= bytes.length) {
                const extType = bytesToInt(bytes, extOff, 2);
                const extLen = bytesToInt(bytes, extOff + 2, 2);
                const extName = TLS_EXTENSIONS[extType] || ("Unknown (" + extType + ")");
                let extValue = extLen + " bytes";
                if (extType === 0 && extLen > 5) {
                  let snOff = extOff + 7;
                  const snLen = bytesToInt(bytes, extOff + 7, 2);
                  snOff += 2;
                  extValue = bytes.slice(snOff, snOff + snLen).map(b => String.fromCharCode(b)).join("");
                }
                if (extType === 16 && extLen > 2) {
                  let alpnOff = extOff + 6;
                  const alpnEnd = extOff + 4 + extLen;
                  const protos = [];
                  while (alpnOff < alpnEnd) {
                    const pLen = bytes[alpnOff];
                    protos.push(bytes.slice(alpnOff + 1, alpnOff + 1 + pLen).map(b => String.fromCharCode(b)).join(""));
                    alpnOff += 1 + pLen;
                  }
                  extValue = protos.join(", ");
                }
                fields.push({ name: "Extension: " + extName, value: extValue, offset: extOff, length: 4 + extLen });
                extOff += 4 + extLen;
              }
            }
          }
        }
      }
    }
    if (hsType === 2 && bytes.length > offset + 43) {
      const shVersion = bytesToHex(bytes, offset + 9, 2);
      fields.push({ name: "Server Version", value: "0x" + shVersion + " (" + (TLS_VERSIONS[shVersion] || "Unknown") + ")", offset: offset + 9, length: 2 });
      fields.push({ name: "Server Random", value: bytesToHex(bytes, offset + 11, 32), offset: offset + 11, length: 32 });
      const sessIdLen = bytes[offset + 43];
      fields.push({ name: "Session ID Length", value: sessIdLen, offset: offset + 43, length: 1 });
      const csOff = offset + 44 + sessIdLen;
      if (csOff + 2 <= bytes.length) {
        const cs = bytesToHex(bytes, csOff, 2);
        fields.push({ name: "Cipher Suite", value: "0x" + cs + " (" + (TLS_CIPHER_SUITES[cs] || "Unknown") + ")", offset: csOff, length: 2 });
      }
    }
  }
  return { name: "TLS", fields, length: 5 + tlsLength, offset };
}

function parseHTTP(bytes, offset) {
  const text = bytes.slice(offset).map(b => String.fromCharCode(b)).join("");
  const headerEnd = text.indexOf("\r\n\r\n");
  if (headerEnd < 0) return { error: "Not HTTP or incomplete", length: 0 };
  const headerText = text.slice(0, headerEnd);
  const lines = headerText.split("\r\n");
  const firstLine = lines[0];
  const isRequest = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s/.test(firstLine);
  const isResponse = /^HTTP\/\d/.test(firstLine);
  if (!isRequest && !isResponse) return { error: "Not HTTP", length: 0 };
  const fields = [{ name: isRequest ? "Request Line" : "Status Line", value: firstLine, offset, length: firstLine.length }];
  for (let i = 1; i < lines.length; i++) {
    const colon = lines[i].indexOf(":");
    if (colon > 0) {
      const hName = lines[i].slice(0, colon).trim();
      const hVal = lines[i].slice(colon + 1).trim();
      fields.push({ name: "Header: " + hName, value: hVal, offset: offset + headerText.indexOf(lines[i]), length: lines[i].length });
    }
  }
  const bodyStart = headerEnd + 4;
  const bodyText = text.slice(bodyStart);
  if (bodyText.length > 0) {
    fields.push({ name: "Body", value: bodyText.slice(0, 500) + (bodyText.length > 500 ? "... (" + bodyText.length + " bytes)" : ""), offset: offset + bodyStart, length: bodyText.length });
  }
  return { name: "HTTP", fields, length: bytes.length - offset, offset };
}

function parseDHCP(bytes, offset) {
  if (bytes.length < offset + 240) return { error: "Too short for DHCP", length: 0 };
  const op = bytes[offset];
  const htype = bytes[offset + 1];
  const hlen = bytes[offset + 2];
  const xid = bytesToHex(bytes, offset + 4, 4);
  const ciaddr = bytesToIP(bytes, offset + 12);
  const yiaddr = bytesToIP(bytes, offset + 16);
  const siaddr = bytesToIP(bytes, offset + 20);
  const giaddr = bytesToIP(bytes, offset + 24);
  const chaddr = bytesToMAC(bytes, offset + 28);
  const fields = [
    { name: "Op", value: op + (op === 1 ? " (Request)" : op === 2 ? " (Reply)" : ""), offset, length: 1 },
    { name: "Hardware Type", value: htype + (htype === 1 ? " (Ethernet)" : ""), offset: offset + 1, length: 1 },
    { name: "Hardware Addr Length", value: hlen, offset: offset + 2, length: 1 },
    { name: "Transaction ID", value: "0x" + xid, offset: offset + 4, length: 4 },
    { name: "Client IP", value: ciaddr, offset: offset + 12, length: 4 },
    { name: "Your IP", value: yiaddr, offset: offset + 16, length: 4 },
    { name: "Server IP", value: siaddr, offset: offset + 20, length: 4 },
    { name: "Gateway IP", value: giaddr, offset: offset + 24, length: 4 },
    { name: "Client MAC", value: chaddr, offset: offset + 28, length: 6 },
  ];
  const magic = bytesToHex(bytes, offset + 236, 4);
  if (magic === "63825363") {
    fields.push({ name: "Magic Cookie", value: "0x63825363 (DHCP)", offset: offset + 236, length: 4 });
    let optOff = offset + 240;
    while (optOff < bytes.length) {
      const optCode = bytes[optOff];
      if (optCode === 255) { fields.push({ name: "Option 255", value: "End", offset: optOff, length: 1 }); break; }
      if (optCode === 0) { optOff++; continue; }
      const optLen = bytes[optOff + 1];
      let optName = DHCP_OPTIONS[optCode] || ("Option " + optCode);
      let optVal = bytesToHex(bytes, optOff + 2, optLen);
      if (optCode === 53) optVal = DHCP_MSG_TYPES[bytes[optOff + 2]] || optVal;
      else if (optCode === 1 || optCode === 50 || optCode === 54 || optCode === 28) optVal = bytesToIP(bytes, optOff + 2);
      else if (optCode === 3 || optCode === 6) {
        const ips = [];
        for (let i = 0; i < optLen; i += 4) ips.push(bytesToIP(bytes, optOff + 2 + i));
        optVal = ips.join(", ");
      }
      else if (optCode === 12 || optCode === 15 || optCode === 60) optVal = bytes.slice(optOff + 2, optOff + 2 + optLen).map(b => String.fromCharCode(b)).join("");
      else if (optCode === 51 || optCode === 58 || optCode === 59) optVal = bytesToInt(bytes, optOff + 2, 4) + " seconds";
      fields.push({ name: "Option: " + optName, value: optVal, offset: optOff, length: 2 + optLen });
      optOff += 2 + optLen;
    }
  }
  return { name: "DHCP", fields, length: bytes.length - offset, offset };
}

// ── Main Packet Dissector ───────────────────────────────────────────────────

function dissectPacket(hex) {
  const bytes = hexToBytes(hex);
  if (bytes.length < 14) return { layers: [], bytes, error: "Packet too short (< 14 bytes)" };
  const layers = [];
  const eth = parseEthernet(bytes, 0);
  if (eth.error) return { layers: [], bytes, error: eth.error };
  layers.push(eth);
  let nextOffset = eth.length;
  if (eth.etherType === "0806") {
    const arp = parseARP(bytes, nextOffset);
    if (!arp.error) layers.push(arp);
    return { layers, bytes };
  }
  let ipProto = -1;
  if (eth.etherType === "0800") {
    const ipv4 = parseIPv4(bytes, nextOffset);
    if (ipv4.error) return { layers, bytes, error: ipv4.error };
    layers.push(ipv4);
    ipProto = ipv4.protocol;
    nextOffset += ipv4.length;
  } else if (eth.etherType === "86dd") {
    const ipv6 = parseIPv6(bytes, nextOffset);
    if (ipv6.error) return { layers, bytes, error: ipv6.error };
    layers.push(ipv6);
    ipProto = ipv6.protocol;
    nextOffset += ipv6.length;
  }
  if (ipProto === 1) {
    const icmp = parseICMP(bytes, nextOffset);
    if (!icmp.error) layers.push(icmp);
  } else if (ipProto === 6) {
    const tcp = parseTCP(bytes, nextOffset);
    if (!tcp.error) {
      layers.push(tcp);
      nextOffset += tcp.length;
      if (nextOffset < bytes.length) {
        const payloadByte = bytes[nextOffset];
        if (payloadByte >= 20 && payloadByte <= 23) {
          const tls = parseTLS(bytes, nextOffset);
          if (!tls.error) layers.push(tls);
        } else if (payloadByte >= 0x41 && payloadByte <= 0x5A) {
          const http = parseHTTP(bytes, nextOffset);
          if (!http.error) layers.push(http);
        }
      }
    }
  } else if (ipProto === 17) {
    const udp = parseUDP(bytes, nextOffset);
    if (!udp.error) {
      layers.push(udp);
      nextOffset += udp.length;
      if (udp.srcPort === 53 || udp.dstPort === 53) {
        const dns = parseDNS(bytes, nextOffset, udp.payloadLength);
        if (!dns.error) layers.push(dns);
      } else if ((udp.srcPort === 67 || udp.srcPort === 68) && (udp.dstPort === 67 || udp.dstPort === 68)) {
        const dhcp = parseDHCP(bytes, nextOffset);
        if (!dhcp.error) layers.push(dhcp);
      }
    }
  }
  return { layers, bytes };
}

// ── Sample Packets ──────────────────────────────────────────────────────────

const SAMPLE_PACKETS = [
  {
    name: "ARP Request",
    description: "Who has 192.168.1.1? Tell 192.168.1.100",
    hex: "ffffffffffff 001122334455 0806 0001 0800 06 04 0001 001122334455 c0a80164 000000000000 c0a80101",
  },
  {
    name: "ARP Reply",
    description: "192.168.1.1 is at aa:bb:cc:dd:ee:ff",
    hex: "001122334455 aabbccddeeff 0806 0001 0800 06 04 0002 aabbccddeeff c0a80101 001122334455 c0a80164",
  },
  {
    name: "ICMP Echo Request",
    description: "Ping 10.0.0.1 → 10.0.0.2",
    hex: "aabbccddeeff 001122334455 0800 4500 003c 1234 0000 4001 b5e6 0a000001 0a000002 0800 4d5a 0001 0001 6162636465666768696a6b6c6d6e6f70",
  },
  {
    name: "DNS Query (A record)",
    description: "Query for example.com",
    hex: "aabbccddeeff 001122334455 0800 4500 003e 5678 0000 4011 0000 0a000001 08080808 c350 0035 002a 0000 abcd 0100 0001 0000 0000 0000 076578616d706c6503636f6d00 0001 0001",
  },
  {
    name: "TCP SYN",
    description: "TCP SYN to port 443 (HTTPS)",
    hex: "aabbccddeeff 001122334455 0800 4500 003c 9abc 4000 4006 0000 0a000001 5db8d822 c0a0 01bb 00000001 00000000 a002 ffff 0000 0000 0204 05b4 0402 080a 00000001 00000000 0103 0307",
  },
  {
    name: "TCP SYN-ACK",
    description: "TCP SYN-ACK response from port 443",
    hex: "001122334455 aabbccddeeff 0800 4500 003c def0 4000 3f06 0000 5db8d822 0a000001 01bb c0a0 00000001 00000002 a012 ffff 0000 0000 0204 05b4 0402 080a 00000001 00000001 0103 0307",
  },
  {
    name: "HTTP GET Request",
    description: "GET / HTTP/1.1 to example.com",
    hex: "aabbccddeeff 001122334455 0800 4500 0082 1234 4000 4006 0000 0a000001 5db8d822 c0a0 0050 00000001 00000001 5018 ffff 0000 0000" +
      Array.from("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Darknode/1.0\r\nAccept: */*\r\n\r\n").map(c => c.charCodeAt(0).toString(16).padStart(2, "0")).join(""),
  },
  {
    name: "TLS ClientHello",
    description: "TLS 1.2 ClientHello with SNI",
    hex: "aabbccddeeff 001122334455 0800 4500 00f0 abcd 4000 4006 0000 0a000001 5db8d822 c0a0 01bb 00000001 00000001 5018 ffff 0000 0000 16 0301 00c1 01 0000bd 0303" +
      "aabbccdd".repeat(8) + "00 0008 1301 1302 c02f c030 0100 0086 0000 0013 0011 00 000e 6578616d706c652e636f6d 000d 0014 0012 0403 0503 0603 0804 0805 0806 0401 0501 0601 002b 0003 02 0303 000a 0006 0004 001d 0017 0033 0026 0024 001d 0020" +
      "1122334455667788".repeat(4),
  },
  {
    name: "UDP DNS Response",
    description: "DNS response for example.com → 93.184.216.34",
    hex: "001122334455 aabbccddeeff 0800 4500 0050 0001 0000 4011 0000 08080808 0a000001 0035 c350 003c 0000 abcd 8180 0001 0001 0000 0000 076578616d706c6503636f6d00 0001 0001 c00c 0001 0001 00005460 0004 5db8d822",
  },
  {
    name: "DHCP Discover",
    description: "DHCP Discover from client",
    hex: "ffffffffffff 001122334455 0800 4500 0148 0000 0000 4011 0000 00000000 ffffffff 0044 0043 0134 0000" +
      "01 01 06 00 3903f326 0000 0000 00000000 00000000 00000000 00000000 001122334455" +
      "00".repeat(10) + "00".repeat(64) + "00".repeat(128) +
      "63825363" +
      "3501 01" +
      "3204 c0a80164" +
      "3304 00015180" +
      "370a 01 03 06 0f 1a 1c 33 3a 3b 77" +
      "ff",
  },
  {
    name: "802.1Q VLAN Tagged",
    description: "VLAN ID 100, ICMP echo inside",
    hex: "aabbccddeeff 001122334455 8100 0064 0800 4500 003c 1234 0000 4001 0000 0a000001 0a000002 0800 4d5a 0001 0001 6162636465666768",
  },
];

// ── UI Rendering ────────────────────────────────────────────────────────────

function formatHexDump(bytes, highlightStart, highlightLen) {
  const rows = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const addr = i.toString(16).padStart(8, "0");
    const hexParts = [];
    const asciiParts = [];
    for (let j = 0; j < 16; j++) {
      const idx = i + j;
      if (idx < bytes.length) {
        const isHighlighted = highlightStart !== undefined && idx >= highlightStart && idx < highlightStart + highlightLen;
        const hexStr = bytes[idx].toString(16).padStart(2, "0");
        const asciiChar = (bytes[idx] >= 32 && bytes[idx] <= 126) ? String.fromCharCode(bytes[idx]) : ".";
        hexParts.push(isHighlighted ? '<span class="pk-hl">' + hexStr + '</span>' : hexStr);
        asciiParts.push(isHighlighted ? '<span class="pk-hl">' + escH(asciiChar) + '</span>' : escH(asciiChar));
      } else {
        hexParts.push("  ");
        asciiParts.push(" ");
      }
      if (j === 7) hexParts.push(" ");
    }
    rows.push('<span class="pk-addr">' + addr + '</span>  ' + hexParts.join(" ") + '  <span class="pk-ascii">' + asciiParts.join("") + '</span>');
  }
  return rows.join("\n");
}

function escH(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }

function renderLayerTree(layers) {
  let html = "";
  for (const layer of layers) {
    html += '<div class="pk-layer">';
    html += '<div class="pk-layer-head" data-offset="' + layer.offset + '" data-len="' + layer.length + '">';
    html += '<span class="pk-arrow">&#9654;</span> <strong>' + escH(layer.name) + '</strong>';
    html += ' <span class="pk-dim">(' + layer.length + ' bytes @ offset ' + layer.offset + ')</span>';
    html += '</div>';
    html += '<div class="pk-fields" hidden>';
    for (const f of layer.fields) {
      html += '<div class="pk-field" data-offset="' + f.offset + '" data-len="' + f.length + '">';
      html += '<span class="pk-fname">' + escH(f.name) + ':</span> ';
      html += '<span class="pk-fval">' + escH(String(f.value)) + '</span>';
      html += '</div>';
    }
    html += '</div></div>';
  }
  return html;
}

function renderSummary(layers) {
  if (!layers.length) return "No layers parsed";
  const parts = layers.map(l => l.name);
  const last = layers[layers.length - 1];
  let info = parts.join(" → ");
  if (last.name === "TCP" && last.flags !== undefined) {
    info += " [" + flagsToString(last.flags, TCP_FLAGS) + "]";
    if (last.srcPort) info += " " + last.srcPort + " → " + last.dstPort;
  }
  if (last.name === "UDP" && last.srcPort) info += " " + last.srcPort + " → " + last.dstPort;
  if (last.name === "DNS") {
    const qField = last.fields.find(f => f.name.startsWith("Query:"));
    if (qField) info += " " + qField.name.replace("Query: ", "");
  }
  if (last.name === "ICMP") {
    const typeF = last.fields.find(f => f.name === "Type");
    if (typeF) info += " " + typeF.value;
  }
  if (last.name === "HTTP") {
    const reqF = last.fields.find(f => f.name === "Request Line" || f.name === "Status Line");
    if (reqF) info += " " + reqF.value;
  }
  return info;
}

export function renderPacketAnalyzer(container) {
  const CSS = `
    <style>
    .pka{font-family:var(--mono,'JetBrains Mono',monospace);color:var(--txt,#e0e6ed);max-width:1200px;margin:0 auto;padding:24px}
    .pka h2{font-family:var(--font-display,system-ui);font-weight:700;font-size:1.4rem;margin:0 0 16px;color:var(--acc,#00d4ff)}
    .pka-tabs{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
    .pka-tab{padding:6px 14px;border-radius:6px;cursor:pointer;font-size:.85rem;border:1px solid var(--border,#1e2a3a);background:var(--bg2,#0d1520);color:var(--mut,#8892a4);transition:all .15s}
    .pka-tab.active{background:var(--acc,#00d4ff);color:#000;border-color:var(--acc)}
    .pka-input{width:100%;min-height:120px;background:var(--bg2,#0d1520);border:1px solid var(--border,#1e2a3a);border-radius:8px;color:var(--txt);font-family:inherit;font-size:.85rem;padding:12px;resize:vertical;margin-bottom:12px}
    .pka-input:focus{outline:none;border-color:var(--acc,#00d4ff)}
    .pka-btn{padding:6px 16px;border-radius:6px;border:none;background:var(--acc,#00d4ff);color:#000;font-weight:600;cursor:pointer;font-size:.85rem;margin-right:8px}
    .pka-btn:hover{opacity:.85}
    .pka-btn.ghost{background:transparent;border:1px solid var(--border,#1e2a3a);color:var(--txt)}
    .pka-samples{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px}
    .pka-sample{font-size:.75rem;padding:4px 10px;border-radius:4px;background:var(--bg2,#0d1520);border:1px solid var(--border,#1e2a3a);cursor:pointer;color:var(--mut)}
    .pka-sample:hover{border-color:var(--acc);color:var(--acc)}
    .pka-summary{padding:8px 12px;background:var(--bg2,#0d1520);border-radius:6px;margin-bottom:16px;font-size:.85rem;color:var(--acc)}
    .pka-split{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    @media(max-width:768px){.pka-split{grid-template-columns:1fr}}
    .pka-hex{background:var(--bg2,#0d1520);border-radius:8px;padding:12px;overflow-x:auto;font-size:.78rem;line-height:1.6;white-space:pre;border:1px solid var(--border,#1e2a3a)}
    .pk-addr{color:var(--mut,#556677)}
    .pk-ascii{color:#7c5cff}
    .pk-hl{background:rgba(0,212,255,.2);color:var(--acc,#00d4ff);border-radius:2px}
    .pka-tree{background:var(--bg2,#0d1520);border-radius:8px;padding:12px;overflow-y:auto;max-height:500px;border:1px solid var(--border,#1e2a3a)}
    .pk-layer{margin-bottom:4px}
    .pk-layer-head{padding:4px 8px;cursor:pointer;border-radius:4px;font-size:.85rem}
    .pk-layer-head:hover{background:rgba(0,212,255,.08)}
    .pk-arrow{display:inline-block;transition:transform .15s;font-size:.7rem;margin-right:4px}
    .pk-layer-head.open .pk-arrow{transform:rotate(90deg)}
    .pk-dim{color:var(--mut,#556677);font-size:.75rem}
    .pk-fields{padding-left:24px}
    .pk-field{padding:2px 8px;font-size:.8rem;cursor:pointer;border-radius:3px}
    .pk-field:hover{background:rgba(0,212,255,.06)}
    .pk-fname{color:var(--mut,#8892a4)}
    .pk-fval{color:var(--txt)}
    .pka-error{color:#ff4444;padding:8px 12px;background:rgba(255,68,68,.08);border-radius:6px;margin-bottom:12px;font-size:.85rem}
    .pka-stats{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;font-size:.8rem;color:var(--mut)}
    .pka-stats span{color:var(--txt)}
    </style>
  `;
  container.innerHTML = CSS + `
    <div class="pka">
      <h2>Packet Analyzer</h2>
      <p style="color:var(--mut);font-size:.9rem;margin-bottom:16px">Paste raw hex bytes to dissect network packets into protocol layers. Supports Ethernet, IPv4/IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS, ARP, DHCP.</p>
      <div class="pka-samples" id="pka-samples"></div>
      <textarea class="pka-input" id="pka-input" placeholder="Paste hex bytes here (e.g. aabbccddeeff 001122334455 0800 4500...)"></textarea>
      <div style="margin-bottom:16px">
        <button class="pka-btn" id="pka-parse">Dissect Packet</button>
        <button class="pka-btn ghost" id="pka-clear">Clear</button>
      </div>
      <div id="pka-error"></div>
      <div id="pka-summary"></div>
      <div id="pka-stats"></div>
      <div class="pka-split">
        <div>
          <div style="font-size:.85rem;font-weight:600;margin-bottom:8px;color:var(--mut)">Hex Dump</div>
          <div class="pka-hex" id="pka-hex"></div>
        </div>
        <div>
          <div style="font-size:.85rem;font-weight:600;margin-bottom:8px;color:var(--mut)">Protocol Tree</div>
          <div class="pka-tree" id="pka-tree"></div>
        </div>
      </div>
    </div>
  `;

  const samplesEl = container.querySelector("#pka-samples");
  const inputEl = container.querySelector("#pka-input");
  const hexEl = container.querySelector("#pka-hex");
  const treeEl = container.querySelector("#pka-tree");
  const summaryEl = container.querySelector("#pka-summary");
  const statsEl = container.querySelector("#pka-stats");
  const errorEl = container.querySelector("#pka-error");

  SAMPLE_PACKETS.forEach((s, i) => {
    const btn = document.createElement("button");
    btn.className = "pka-sample";
    btn.textContent = s.name;
    btn.title = s.description;
    btn.onclick = () => { inputEl.value = s.hex; doParse(); };
    samplesEl.appendChild(btn);
  });

  container.querySelector("#pka-parse").onclick = doParse;
  container.querySelector("#pka-clear").onclick = () => {
    inputEl.value = "";
    hexEl.innerHTML = "";
    treeEl.innerHTML = "";
    summaryEl.innerHTML = "";
    statsEl.innerHTML = "";
    errorEl.innerHTML = "";
  };

  let lastResult = null;

  function doParse() {
    errorEl.innerHTML = "";
    const hex = inputEl.value.trim();
    if (!hex) { errorEl.innerHTML = '<div class="pka-error">Enter hex bytes to parse</div>'; return; }
    const result = dissectPacket(hex);
    lastResult = result;
    if (result.error) errorEl.innerHTML = '<div class="pka-error">' + escH(result.error) + '</div>';
    summaryEl.innerHTML = result.layers.length ? '<div class="pka-summary">' + escH(renderSummary(result.layers)) + '</div>' : "";
    statsEl.innerHTML = '<div class="pka-stats">Total: <span>' + result.bytes.length + ' bytes</span> &nbsp; Layers: <span>' + result.layers.length + '</span></div>';
    hexEl.innerHTML = formatHexDump(result.bytes);
    treeEl.innerHTML = renderLayerTree(result.layers);

    treeEl.querySelectorAll(".pk-layer-head").forEach(head => {
      head.onclick = () => {
        head.classList.toggle("open");
        const fields = head.nextElementSibling;
        fields.hidden = !fields.hidden;
        const off = parseInt(head.dataset.offset);
        const len = parseInt(head.dataset.len);
        hexEl.innerHTML = formatHexDump(result.bytes, off, len);
      };
    });

    treeEl.querySelectorAll(".pk-field").forEach(field => {
      field.onclick = (e) => {
        e.stopPropagation();
        const off = parseInt(field.dataset.offset);
        const len = parseInt(field.dataset.len);
        hexEl.innerHTML = formatHexDump(result.bytes, off, len);
      };
    });
  }
}
