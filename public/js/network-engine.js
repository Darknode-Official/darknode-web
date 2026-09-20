// Darknode Network Engine — packet parsing, PCAP reader, TCP reassembly,
// subnet calculator, DNS parser, TLS analysis, MAC lookup, firewall rules.
// Pure browser JS, no dependencies. All functions are ES module exports.

const TD = new TextDecoder();

// ─── Ethernet Frame Parser ──────────────────────────────────────────────────
export function parseEthernet(data, offset = 0) {
  const dv = new DataView(data.buffer || data, offset);
  const dst = Array.from(new Uint8Array(data.buffer || data, offset, 6), b => b.toString(16).padStart(2,"0")).join(":");
  const src = Array.from(new Uint8Array(data.buffer || data, offset+6, 6), b => b.toString(16).padStart(2,"0")).join(":");
  const etherType = dv.getUint16(12);
  const typeNames = { 0x0800:"IPv4", 0x0806:"ARP", 0x86DD:"IPv6", 0x8100:"802.1Q VLAN" };
  return { dst, src, etherType: `0x${etherType.toString(16).padStart(4,"0")}`, protocol: typeNames[etherType]||"Unknown", payloadOffset: offset+14, headerSize: 14 };
}

// ─── IPv4 Parser ────────────────────────────────────────────────────────────
export function parseIPv4(data, offset = 0) {
  const bytes = new Uint8Array(data.buffer || data, offset);
  const dv = new DataView(data.buffer || data, offset);
  const version = (bytes[0] >> 4) & 0xF;
  const ihl = (bytes[0] & 0xF) * 4;
  const totalLen = dv.getUint16(2);
  const id = dv.getUint16(4);
  const flagsOff = dv.getUint16(6);
  const flags = { DF: !!(flagsOff & 0x4000), MF: !!(flagsOff & 0x2000) };
  const fragOff = (flagsOff & 0x1FFF) * 8;
  const ttl = bytes[8];
  const protocol = bytes[9];
  const checksum = dv.getUint16(10);
  const src = `${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
  const dst = `${bytes[16]}.${bytes[17]}.${bytes[18]}.${bytes[19]}`;
  const protoNames = { 1:"ICMP", 6:"TCP", 17:"UDP", 47:"GRE", 50:"ESP", 51:"AH", 58:"ICMPv6", 89:"OSPF" };
  return { version, headerLen: ihl, totalLen, id, flags, fragOffset: fragOff, ttl, protocol: protoNames[protocol]||protocol, protocolNum: protocol, checksum: `0x${checksum.toString(16)}`, src, dst, payloadOffset: offset+ihl, payloadLen: totalLen-ihl };
}

// ─── TCP Parser ─────────────────────────────────────────────────────────────
export function parseTCP(data, offset = 0) {
  const dv = new DataView(data.buffer || data, offset);
  const srcPort = dv.getUint16(0);
  const dstPort = dv.getUint16(2);
  const seqNum = dv.getUint32(4);
  const ackNum = dv.getUint32(8);
  const dataOffset = ((dv.getUint8(12) >> 4) & 0xF) * 4;
  const flagByte = dv.getUint16(12) & 0x1FF;
  const flags = { FIN:!!(flagByte&1), SYN:!!(flagByte&2), RST:!!(flagByte&4), PSH:!!(flagByte&8), ACK:!!(flagByte&16), URG:!!(flagByte&32), ECE:!!(flagByte&64), CWR:!!(flagByte&128), NS:!!(flagByte&256) };
  const flagStr = Object.entries(flags).filter(([,v])=>v).map(([k])=>k).join(",");
  const window = dv.getUint16(14);
  const checksum = dv.getUint16(16);
  const urgPtr = dv.getUint16(18);
  return { srcPort, dstPort, seqNum, ackNum, headerLen: dataOffset, flags, flagStr, window, checksum: `0x${checksum.toString(16)}`, urgentPtr: urgPtr, payloadOffset: offset+dataOffset };
}

// ─── UDP Parser ─────────────────────────────────────────────────────────────
export function parseUDP(data, offset = 0) {
  const dv = new DataView(data.buffer || data, offset);
  return { srcPort: dv.getUint16(0), dstPort: dv.getUint16(2), length: dv.getUint16(4), checksum: `0x${dv.getUint16(6).toString(16)}`, payloadOffset: offset+8, payloadLen: dv.getUint16(4)-8 };
}

// ─── ICMP Parser ────────────────────────────────────────────────────────────
export function parseICMP(data, offset = 0) {
  const dv = new DataView(data.buffer || data, offset);
  const type = dv.getUint8(0);
  const code = dv.getUint8(1);
  const typeNames = { 0:"Echo Reply", 3:"Destination Unreachable", 4:"Source Quench", 5:"Redirect", 8:"Echo Request", 11:"Time Exceeded", 12:"Parameter Problem", 13:"Timestamp", 14:"Timestamp Reply" };
  return { type, code, checksum: `0x${dv.getUint16(2).toString(16)}`, typeName: typeNames[type]||`Type ${type}`, id: dv.getUint16(4), sequence: dv.getUint16(6) };
}

// ─── DNS Parser ─────────────────────────────────────────────────────────────
const DNS_TYPES = { 1:"A", 2:"NS", 5:"CNAME", 6:"SOA", 12:"PTR", 15:"MX", 16:"TXT", 28:"AAAA", 33:"SRV", 35:"NAPTR", 43:"DS", 46:"RRSIG", 47:"NSEC", 48:"DNSKEY", 52:"TLSA", 65:"HTTPS", 99:"SPF", 255:"ANY", 256:"URI", 257:"CAA" };
const DNS_CLASSES = { 1:"IN", 3:"CH", 4:"HS", 255:"ANY" };

function readDNSName(data, offset, dv) {
  const parts = [];
  let pos = offset, jumped = false, savedPos = 0;
  for (let safety = 0; safety < 128; safety++) {
    const len = dv.getUint8(pos);
    if (len === 0) { pos++; break; }
    if ((len & 0xC0) === 0xC0) {
      if (!jumped) savedPos = pos + 2;
      pos = ((len & 0x3F) << 8) | dv.getUint8(pos+1);
      jumped = true;
      continue;
    }
    parts.push(TD.decode(new Uint8Array(data.buffer || data, pos+1, len)));
    pos += len + 1;
  }
  return { name: parts.join("."), endOffset: jumped ? savedPos : pos };
}

export function parseDNS(data, offset = 0) {
  const bytes = new Uint8Array(data.buffer || data, offset);
  const dv = new DataView(data.buffer || data, offset);
  const id = dv.getUint16(0);
  const flags = dv.getUint16(2);
  const qr = !!(flags & 0x8000);
  const opcode = (flags >> 11) & 0xF;
  const aa = !!(flags & 0x0400);
  const tc = !!(flags & 0x0200);
  const rd = !!(flags & 0x0100);
  const ra = !!(flags & 0x0080);
  const rcode = flags & 0xF;
  const rcodeNames = { 0:"NOERROR", 1:"FORMERR", 2:"SERVFAIL", 3:"NXDOMAIN", 4:"NOTIMP", 5:"REFUSED" };
  const qdCount = dv.getUint16(4);
  const anCount = dv.getUint16(6);
  const nsCount = dv.getUint16(8);
  const arCount = dv.getUint16(10);

  let pos = 12;
  const questions = [];
  for (let i = 0; i < qdCount && pos < bytes.length; i++) {
    const { name, endOffset } = readDNSName(data, offset+pos, dv);
    pos = endOffset - offset;
    const qtype = dv.getUint16(pos); pos += 2;
    const qclass = dv.getUint16(pos); pos += 2;
    questions.push({ name, type: DNS_TYPES[qtype]||qtype, class: DNS_CLASSES[qclass]||qclass });
  }

  function readRecords(count) {
    const records = [];
    for (let i = 0; i < count && pos < bytes.length - 10; i++) {
      const { name, endOffset } = readDNSName(data, offset+pos, dv);
      pos = endOffset - offset;
      const rtype = dv.getUint16(pos); pos += 2;
      const rclass = dv.getUint16(pos); pos += 2;
      const ttl = dv.getUint32(pos); pos += 4;
      const rdlen = dv.getUint16(pos); pos += 2;
      let rdata = "";
      if (rtype === 1 && rdlen === 4) rdata = `${bytes[pos]}.${bytes[pos+1]}.${bytes[pos+2]}.${bytes[pos+3]}`;
      else if (rtype === 28 && rdlen === 16) rdata = Array.from(bytes.slice(pos, pos+16)).map((b,i) => (i%2===0 ? "" : "") + b.toString(16).padStart(2,"0")).join("").replace(/(.{4})/g, "$1:").slice(0,-1);
      else if (rtype === 5 || rtype === 2 || rtype === 12) { rdata = readDNSName(data, offset+pos, dv).name; }
      else if (rtype === 15) { rdata = `${dv.getUint16(pos)} ${readDNSName(data, offset+pos+2, dv).name}`; }
      else if (rtype === 16) { const tlen = bytes[pos]; rdata = TD.decode(bytes.slice(pos+1, pos+1+tlen)); }
      else rdata = `<${rdlen} bytes>`;
      pos += rdlen;
      records.push({ name, type: DNS_TYPES[rtype]||rtype, class: DNS_CLASSES[rclass]||rclass, ttl, rdata });
    }
    return records;
  }

  const answers = readRecords(anCount);
  const authority = readRecords(nsCount);
  const additional = readRecords(arCount);

  return { id, isResponse: qr, opcode, authoritative: aa, truncated: tc, recursionDesired: rd, recursionAvailable: ra, rcode: rcodeNames[rcode]||rcode, questions, answers, authority, additional };
}

// ─── HTTP Parser ────────────────────────────────────────────────────────────
export function parseHTTP(data) {
  const text = typeof data === "string" ? data : TD.decode(data);
  const headerEnd = text.indexOf("\r\n\r\n");
  if (headerEnd < 0) return { error: "No HTTP header/body separator found" };
  const headerBlock = text.substring(0, headerEnd);
  const body = text.substring(headerEnd + 4);
  const lines = headerBlock.split("\r\n");
  const firstLine = lines[0];

  const isRequest = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s/.test(firstLine);
  const result = { raw: headerBlock, body, bodyLength: body.length, headers: {}, cookies: [] };

  if (isRequest) {
    const [method, path, version] = firstLine.split(/\s+/);
    result.type = "request"; result.method = method; result.path = path; result.version = version;
  } else {
    const m = firstLine.match(/^(HTTP\/[\d.]+)\s+(\d+)\s*(.*)/);
    if (m) { result.type = "response"; result.version = m[1]; result.status = parseInt(m[2]); result.statusText = m[3]; }
  }

  for (let i = 1; i < lines.length; i++) {
    const colonIdx = lines[i].indexOf(":");
    if (colonIdx < 0) continue;
    const key = lines[i].substring(0, colonIdx).trim().toLowerCase();
    const val = lines[i].substring(colonIdx + 1).trim();
    result.headers[key] = val;
    if (key === "cookie" || key === "set-cookie") {
      val.split(";").forEach(part => {
        const [k, ...v] = part.trim().split("=");
        if (k) result.cookies.push({ name: k.trim(), value: v.join("=").trim() });
      });
    }
  }
  result.contentType = result.headers["content-type"] || "";
  result.contentLength = parseInt(result.headers["content-length"]) || body.length;
  result.server = result.headers["server"] || "";
  return result;
}

// ─── TLS ClientHello Parser ─────────────────────────────────────────────────
const TLS_CIPHER_SUITES = {
  0x1301:"TLS_AES_128_GCM_SHA256", 0x1302:"TLS_AES_256_GCM_SHA384", 0x1303:"TLS_CHACHA20_POLY1305_SHA256",
  0xC02C:"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xC02B:"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  0xC030:"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xC02F:"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  0xCCA9:"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", 0xCCA8:"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
  0xC027:"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xC028:"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
  0xC013:"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014:"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
  0x009E:"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009F:"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
  0x002F:"TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035:"TLS_RSA_WITH_AES_256_CBC_SHA",
  0x009C:"TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D:"TLS_RSA_WITH_AES_256_GCM_SHA384",
  0x003C:"TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003D:"TLS_RSA_WITH_AES_256_CBC_SHA256",
  0x000A:"TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0004:"TLS_RSA_WITH_RC4_128_MD5",
  0x0005:"TLS_RSA_WITH_RC4_128_SHA", 0x00FF:"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
};

export function parseTLSClientHello(data, offset = 0) {
  const bytes = new Uint8Array(data.buffer || data, offset);
  const dv = new DataView(data.buffer || data, offset);
  if (bytes[0] !== 0x16) return { error: "Not a TLS record (type != Handshake)" };
  const tlsVersion = `${bytes[1]}.${bytes[2]}`;
  const recordLen = dv.getUint16(3);
  if (bytes[5] !== 0x01) return { error: "Not a ClientHello" };
  let pos = 9; // skip record header + handshake header
  const clientVersion = `${bytes[pos]}.${bytes[pos+1]}`; pos += 2;
  pos += 32; // skip random
  const sessIdLen = bytes[pos++];
  pos += sessIdLen;
  const csLen = dv.getUint16(pos); pos += 2;
  const cipherSuites = [];
  for (let i = 0; i < csLen; i += 2) {
    const cs = dv.getUint16(pos + i);
    cipherSuites.push({ id: `0x${cs.toString(16).padStart(4,"0")}`, name: TLS_CIPHER_SUITES[cs]||"Unknown" });
  }
  pos += csLen;
  const compLen = bytes[pos++];
  pos += compLen;

  // Extensions
  let sni = "";
  const extensions = [];
  if (pos + 2 <= bytes.length) {
    const extLen = dv.getUint16(pos); pos += 2;
    const extEnd = pos + extLen;
    while (pos + 4 <= extEnd && pos + 4 <= bytes.length) {
      const extType = dv.getUint16(pos);
      const extDataLen = dv.getUint16(pos + 2);
      const extNames = { 0:"server_name", 5:"status_request", 10:"supported_groups", 11:"ec_point_formats", 13:"signature_algorithms", 16:"ALPN", 23:"extended_master_secret", 43:"supported_versions", 45:"psk_key_exchange_modes", 51:"key_share" };
      extensions.push({ type: extType, name: extNames[extType]||`ext_${extType}`, length: extDataLen });
      if (extType === 0 && extDataLen > 5) {
        const nameLen = dv.getUint16(pos + 7);
        sni = TD.decode(bytes.slice(pos + 9, pos + 9 + nameLen));
      }
      pos += 4 + extDataLen;
    }
  }

  return { type: "ClientHello", tlsRecordVersion: tlsVersion, clientVersion, cipherSuites, sni, extensions, cipherSuiteCount: cipherSuites.length };
}

// ─── Cipher Suite Security Rating ───────────────────────────────────────────
export function rateCipherSuite(name) {
  const n = (name||"").toUpperCase();
  if (/RC4|MD5|DES(?!E)|EXPORT|NULL|ANON/.test(n)) return { rating: "insecure", score: 0, reason: "Broken algorithm" };
  if (/3DES|CBC.*SHA(?!256|384)/.test(n)) return { rating: "weak", score: 30, reason: "Legacy cipher, vulnerable to BEAST/POODLE" };
  if (/RSA_WITH.*CBC/.test(n)) return { rating: "acceptable", score: 50, reason: "No forward secrecy" };
  if (/RSA_WITH.*GCM/.test(n)) return { rating: "acceptable", score: 60, reason: "No forward secrecy, but AEAD" };
  if (/ECDHE.*GCM|ECDHE.*CHACHA20/.test(n)) return { rating: "strong", score: 90, reason: "ECDHE + AEAD" };
  if (/^TLS_AES.*GCM|^TLS_CHACHA20/.test(n)) return { rating: "excellent", score: 100, reason: "TLS 1.3 cipher" };
  if (/ECDHE.*CBC.*SHA256/.test(n)) return { rating: "good", score: 70, reason: "ECDHE but CBC mode" };
  return { rating: "unknown", score: 50, reason: "Unrecognized cipher suite" };
}

// ─── PCAP Parser ────────────────────────────────────────────────────────────
export function parsePCAP(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = dv.getUint32(0);
  let le;
  if (magic === 0xA1B2C3D4) le = false;
  else if (magic === 0xD4C3B2A1) le = true;
  else return { error: "Not a PCAP file" };

  const vMajor = dv.getUint16(4, le);
  const vMinor = dv.getUint16(6, le);
  const snapLen = dv.getUint32(16, le);
  const linkType = dv.getUint32(20, le);

  const packets = [];
  let pos = 24;
  while (pos + 16 <= bytes.length) {
    const tsSec = dv.getUint32(pos, le);
    const tsUsec = dv.getUint32(pos+4, le);
    const inclLen = dv.getUint32(pos+8, le);
    const origLen = dv.getUint32(pos+12, le);
    pos += 16;
    if (pos + inclLen > bytes.length) break;
    const pktData = bytes.slice(pos, pos + inclLen);
    packets.push({ timestamp: tsSec + tsUsec/1e6, capturedLen: inclLen, originalLen: origLen, data: pktData });
    pos += inclLen;
  }

  // Basic stats
  let totalBytes = 0;
  const protocols = {};
  for (const pkt of packets) {
    totalBytes += pkt.capturedLen;
    if (pkt.data.length >= 14) {
      const ethType = (pkt.data[12] << 8) | pkt.data[13];
      const proto = ethType === 0x0800 ? "IPv4" : ethType === 0x0806 ? "ARP" : ethType === 0x86DD ? "IPv6" : `0x${ethType.toString(16)}`;
      protocols[proto] = (protocols[proto]||0) + 1;
    }
  }
  const duration = packets.length > 1 ? packets[packets.length-1].timestamp - packets[0].timestamp : 0;

  return { version: `${vMajor}.${vMinor}`, snapLen, linkType, packetCount: packets.length, totalBytes, duration: Math.round(duration*1000)/1000, protocols, packets: packets.slice(0, 100) };
}

// ─── TCP Stream Reassembly ──────────────────────────────────────────────────
export function reassembleTCPStream(packets) {
  const streams = {};
  for (const pkt of packets) {
    if (!pkt.data || pkt.data.length < 54) continue;
    const ethType = (pkt.data[12] << 8) | pkt.data[13];
    if (ethType !== 0x0800) continue;
    const ipProto = pkt.data[23];
    if (ipProto !== 6) continue;
    const ihl = (pkt.data[14] & 0xF) * 4;
    const ipOff = 14;
    const tcpOff = ipOff + ihl;
    if (tcpOff + 20 > pkt.data.length) continue;
    const dv = new DataView(pkt.data.buffer, pkt.data.byteOffset);
    const srcPort = dv.getUint16(tcpOff);
    const dstPort = dv.getUint16(tcpOff + 2);
    const seqNum = dv.getUint32(tcpOff + 4);
    const tcpHeaderLen = ((pkt.data[tcpOff + 12] >> 4) & 0xF) * 4;
    const payloadOff = tcpOff + tcpHeaderLen;
    const payloadLen = pkt.data.length - payloadOff;
    if (payloadLen <= 0) continue;

    const srcIP = `${pkt.data[26]}.${pkt.data[27]}.${pkt.data[28]}.${pkt.data[29]}`;
    const dstIP = `${pkt.data[30]}.${pkt.data[31]}.${pkt.data[32]}.${pkt.data[33]}`;
    const key = `${srcIP}:${srcPort}->${dstIP}:${dstPort}`;
    if (!streams[key]) streams[key] = { src: `${srcIP}:${srcPort}`, dst: `${dstIP}:${dstPort}`, segments: [], totalBytes: 0 };
    streams[key].segments.push({ seq: seqNum, data: pkt.data.slice(payloadOff), timestamp: pkt.timestamp });
    streams[key].totalBytes += payloadLen;
  }

  for (const key of Object.keys(streams)) {
    streams[key].segments.sort((a, b) => a.seq - b.seq);
    const combined = new Uint8Array(streams[key].totalBytes);
    let pos = 0;
    for (const seg of streams[key].segments) {
      combined.set(seg.data, pos);
      pos += seg.data.length;
    }
    streams[key].reassembled = combined;
    streams[key].text = TD.decode(combined);
  }
  return streams;
}

// ─── Subnet Calculator ──────────────────────────────────────────────────────
function ipToUint32(ip) {
  return ip.split(".").reduce((acc, oct) => (acc << 8) | parseInt(oct), 0) >>> 0;
}
function uint32ToIP(n) {
  return `${(n>>>24)&0xFF}.${(n>>>16)&0xFF}.${(n>>>8)&0xFF}.${n&0xFF}`;
}

export function subnetCalc(cidr) {
  const [ip, bits] = cidr.split("/");
  const prefix = parseInt(bits);
  if (prefix < 0 || prefix > 32) return { error: "Invalid prefix length" };
  const ipNum = ipToUint32(ip);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const network = (ipNum & mask) >>> 0;
  const broadcast = (network | ~mask) >>> 0;
  const first = prefix >= 31 ? network : (network + 1) >>> 0;
  const last = prefix >= 31 ? broadcast : (broadcast - 1) >>> 0;
  const hostCount = prefix >= 31 ? (prefix === 32 ? 1 : 2) : (broadcast - network - 1);
  const wildcard = (~mask) >>> 0;

  return {
    network: uint32ToIP(network), broadcast: uint32ToIP(broadcast),
    firstHost: uint32ToIP(first), lastHost: uint32ToIP(last),
    netmask: uint32ToIP(mask), wildcard: uint32ToIP(wildcard),
    prefix, hostCount, totalAddresses: 2**(32-prefix),
    isPrivate: /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(uint32ToIP(network)),
    class: network < 0x80000000 ? "A" : network < 0xC0000000 ? "B" : network < 0xE0000000 ? "C" : network < 0xF0000000 ? "D" : "E",
  };
}

export function cidrOverlap(cidr1, cidr2) {
  const s1 = subnetCalc(cidr1), s2 = subnetCalc(cidr2);
  const n1 = ipToUint32(s1.network), b1 = ipToUint32(s1.broadcast);
  const n2 = ipToUint32(s2.network), b2 = ipToUint32(s2.broadcast);
  return !(b1 < n2 || b2 < n1);
}

export function ipInSubnet(ip, cidr) {
  const s = subnetCalc(cidr);
  const ipNum = ipToUint32(ip);
  const net = ipToUint32(s.network);
  const bcast = ipToUint32(s.broadcast);
  return ipNum >= net && ipNum <= bcast;
}

// ─── Nmap XML Parser ────────────────────────────────────────────────────────
export function parseNmapXML(xmlText) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, "text/xml");
  const hosts = [];
  for (const hostEl of doc.querySelectorAll("host")) {
    const addr = hostEl.querySelector("address")?.getAttribute("addr") || "";
    const state = hostEl.querySelector("status")?.getAttribute("state") || "";
    const hostname = hostEl.querySelector("hostname")?.getAttribute("name") || "";
    const ports = [];
    for (const portEl of hostEl.querySelectorAll("port")) {
      const portId = portEl.getAttribute("portid");
      const proto = portEl.getAttribute("protocol");
      const portState = portEl.querySelector("state")?.getAttribute("state") || "";
      const service = portEl.querySelector("service")?.getAttribute("name") || "";
      const product = portEl.querySelector("service")?.getAttribute("product") || "";
      const version = portEl.querySelector("service")?.getAttribute("version") || "";
      ports.push({ port: parseInt(portId), protocol: proto, state: portState, service, product, version });
    }
    const os = hostEl.querySelector("osmatch")?.getAttribute("name") || "";
    hosts.push({ address: addr, state, hostname, ports, os, openPorts: ports.filter(p => p.state === "open").length });
  }
  const scanInfo = { scanner: doc.querySelector("nmaprun")?.getAttribute("scanner") || "nmap", args: doc.querySelector("nmaprun")?.getAttribute("args") || "", startTime: doc.querySelector("nmaprun")?.getAttribute("startstr") || "" };
  return { hosts, totalHosts: hosts.length, scanInfo };
}

// ─── MAC Address Vendor Lookup ──────────────────────────────────────────────
const OUI_DB = {
  "00:50:56":"VMware","00:0C:29":"VMware","00:1C:14":"VMware","00:05:69":"VMware",
  "08:00:27":"VirtualBox","0A:00:27":"VirtualBox",
  "00:15:5D":"Hyper-V","00:1D:D8":"Microsoft",
  "00:1A:11":"Google","3C:5A:B4":"Google","F4:F5:E8":"Google",
  "00:17:88":"Philips","3C:E1:A1":"Universal Global Scientific",
  "F8:1A:67":"TP-Link","50:C7:BF":"TP-Link","98:DA:C4":"TP-Link",
  "00:1F:A4":"Shenzhen Gongjin","A4:2B:B0":"TP-Link",
  "B0:BE:76":"TP-Link","C0:25:E9":"TP-Link",
  "00:14:BF":"Cisco","00:1B:0D":"Cisco","00:1E:14":"Cisco","00:24:C4":"Cisco",
  "00:25:45":"Cisco","00:26:0B":"Cisco","00:E0:A3":"Cisco",
  "58:97:BD":"Cisco","70:10:5C":"Cisco","B0:00:B4":"Cisco",
  "00:0A:95":"Apple","00:14:51":"Apple","00:1B:63":"Apple","00:1E:C2":"Apple",
  "00:25:BC":"Apple","3C:15:C2":"Apple","60:03:08":"Apple","A4:5E:60":"Apple",
  "AC:BC:32":"Apple","D0:25:98":"Apple","F0:DB:E2":"Apple",
  "00:1A:A0":"Dell","00:14:22":"Dell","18:03:73":"Dell","B0:83:FE":"Dell",
  "F8:DB:88":"Dell","D4:BE:D9":"Dell",
  "00:1E:68":"Quanta","00:24:E8":"Dell","3C:97:0E":"HP","9C:8E:99":"HP",
  "00:21:5A":"HP","00:25:B3":"HP","A0:D3:C1":"HP","F4:39:09":"HP",
  "00:0D:3A":"Microsoft Azure","00:03:FF":"Microsoft",
  "D8:9E:F3":"Amazon","40:B4:CD":"Amazon","68:54:FD":"Amazon","A0:02:DC":"Amazon",
  "48:2C:6A":"Intel","00:1F:3B":"Intel","68:05:CA":"Intel","A4:34:D9":"Intel",
  "B4:96:91":"Intel","3C:F0:11":"Intel","8C:EC:4B":"Intel",
  "00:13:20":"Intel","00:16:76":"Intel","00:19:D1":"Intel",
  "00:E0:4C":"Realtek","00:0C:43":"Ralink","00:17:9A":"D-Link","1C:7E:E5":"D-Link",
  "2C:56:DC":"ASUSTek","00:1D:60":"ASUSTek","04:92:26":"ASUSTek",
  "00:12:17":"Cisco-Linksys","00:1A:70":"Cisco-Linksys",
  "00:24:B2":"Netgear","20:4E:7F":"Netgear","6C:B0:CE":"Netgear","A4:2B:8C":"Netgear",
  "00:26:F2":"Netgear","30:46:9A":"Netgear","C4:3D:C7":"Netgear",
  "F0:9F:C2":"Ubiquiti","24:A4:3C":"Ubiquiti","78:8A:20":"Ubiquiti","80:2A:A8":"Ubiquiti",
  "00:1E:58":"D-Link","00:26:5A":"D-Link","C8:BE:19":"D-Link",
  "B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi","E4:5F:01":"Raspberry Pi",
  "52:54:00":"QEMU/KVM","DE:AD:BE":"Testing/Debug",
  "00:1C:42":"Parallels","00:16:3E":"Xen","02:42:AC":"Docker",
  "00:0F:20":"Hewlett Packard Enterprise","00:1B:78":"Hewlett Packard Enterprise",
  "28:80:23":"Samsung","00:1E:E1":"Samsung","5C:49:7D":"Samsung","A8:06:00":"Samsung",
  "00:1F:CC":"Samsung","C4:57:6E":"Samsung","F0:25:B7":"Samsung",
  "00:1A:2B":"Ayecom","00:1C:BF":"MediaTek","70:62:B8":"D-Link",
  "00:22:6B":"Cisco-Linksys","E0:91:F5":"Netgear","B4:75:0E":"Belkin",
};

export function lookupMAC(mac) {
  const prefix = mac.toUpperCase().replace(/[:-]/g, ":").substring(0, 8);
  const vendor = OUI_DB[prefix];
  return { mac, prefix, vendor: vendor || "Unknown", isVirtual: /VMware|VirtualBox|Hyper-V|QEMU|KVM|Xen|Docker|Parallels/.test(vendor || "") };
}

// ─── ARP Spoofing Detection ─────────────────────────────────────────────────
export function detectARPSpoofing(arpTable) {
  // arpTable: array of { ip, mac }
  const ipToMac = {};
  const macToIPs = {};
  const anomalies = [];

  for (const entry of arpTable) {
    const ip = entry.ip, mac = entry.mac.toUpperCase();
    if (ipToMac[ip] && ipToMac[ip] !== mac) {
      anomalies.push({ type: "duplicate_ip", ip, macs: [ipToMac[ip], mac], severity: "high", description: `IP ${ip} maps to multiple MACs — possible ARP spoofing` });
    }
    ipToMac[ip] = mac;
    if (!macToIPs[mac]) macToIPs[mac] = [];
    macToIPs[mac].push(ip);
  }

  for (const [mac, ips] of Object.entries(macToIPs)) {
    if (ips.length > 5) {
      anomalies.push({ type: "mac_flooding", mac, ipCount: ips.length, severity: "medium", description: `MAC ${mac} claims ${ips.length} IPs — possible ARP flooding` });
    }
  }

  // Check for gateway impersonation
  const gatewayIPs = arpTable.filter(e => e.ip.endsWith(".1") || e.ip.endsWith(".254"));
  for (const gw of gatewayIPs) {
    const vendor = lookupMAC(gw.mac);
    if (vendor.isVirtual) {
      anomalies.push({ type: "virtual_gateway", ip: gw.ip, mac: gw.mac, vendor: vendor.vendor, severity: "info", description: `Gateway ${gw.ip} has virtual MAC (${vendor.vendor})` });
    }
  }

  return { anomalies, entries: arpTable.length, uniqueIPs: Object.keys(ipToMac).length, uniqueMACs: Object.keys(macToIPs).length };
}

// ─── Firewall Rule Parser ───────────────────────────────────────────────────
export function parseIptablesRules(text) {
  const rules = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("*") || trimmed === "COMMIT") continue;
    if (trimmed.startsWith(":")) {
      const [chain, policy] = trimmed.slice(1).split(/\s+/);
      rules.push({ type: "policy", chain, policy, raw: trimmed });
      continue;
    }
    if (!trimmed.startsWith("-A")) continue;
    const rule = { type: "rule", raw: trimmed };
    const chainMatch = trimmed.match(/-A\s+(\S+)/); if (chainMatch) rule.chain = chainMatch[1];
    const protoMatch = trimmed.match(/-p\s+(\S+)/); if (protoMatch) rule.protocol = protoMatch[1];
    const srcMatch = trimmed.match(/-s\s+(\S+)/); if (srcMatch) rule.source = srcMatch[1];
    const dstMatch = trimmed.match(/-d\s+(\S+)/); if (dstMatch) rule.destination = dstMatch[1];
    const dportMatch = trimmed.match(/--dport\s+(\S+)/); if (dportMatch) rule.dport = dportMatch[1];
    const sportMatch = trimmed.match(/--sport\s+(\S+)/); if (sportMatch) rule.sport = sportMatch[1];
    const actionMatch = trimmed.match(/-j\s+(\S+)/); if (actionMatch) rule.action = actionMatch[1];
    const ifaceMatch = trimmed.match(/-i\s+(\S+)/); if (ifaceMatch) rule.inInterface = ifaceMatch[1];
    const ofaceMatch = trimmed.match(/-o\s+(\S+)/); if (ofaceMatch) rule.outInterface = ofaceMatch[1];
    const stateMatch = trimmed.match(/--state\s+(\S+)/); if (stateMatch) rule.state = stateMatch[1];
    rules.push(rule);
  }
  return { rules, totalRules: rules.filter(r => r.type === "rule").length, chains: [...new Set(rules.map(r => r.chain).filter(Boolean))] };
}

// ─── IP Geolocation ─────────────────────────────────────────────────────────
export async function geolocateIP(ip) {
  try {
    const res = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    return { ip: data.ip, city: data.city, region: data.region, country: data.country_name, countryCode: data.country_code, org: data.org, asn: data.asn, latitude: data.latitude, longitude: data.longitude, timezone: data.timezone, error: data.error ? data.reason : null };
  } catch (e) { return { ip, error: e.message }; }
}

// ─── Port Service Map ───────────────────────────────────────────────────────
const PORT_MAP = {
  20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",67:"dhcp-server",
  68:"dhcp-client",69:"tftp",80:"http",88:"kerberos",110:"pop3",111:"rpcbind",
  119:"nntp",123:"ntp",135:"msrpc",137:"netbios-ns",138:"netbios-dgm",
  139:"netbios-ssn",143:"imap",161:"snmp",162:"snmp-trap",179:"bgp",
  389:"ldap",443:"https",445:"microsoft-ds",464:"kpasswd",465:"smtps",
  500:"isakmp",514:"syslog",515:"printer",520:"rip",523:"ibm-db2",
  587:"submission",631:"ipp",636:"ldaps",873:"rsync",993:"imaps",
  995:"pop3s",1080:"socks",1433:"mssql",1434:"mssql-m",1521:"oracle",
  1723:"pptp",2049:"nfs",2181:"zookeeper",2375:"docker",2376:"docker-tls",
  3306:"mysql",3389:"rdp",3690:"svn",4443:"pharos",4444:"metasploit",
  5060:"sip",5061:"sip-tls",5432:"postgresql",5672:"amqp",5900:"vnc",
  5985:"winrm",5986:"winrm-tls",6379:"redis",6443:"kubernetes-api",
  6667:"irc",7001:"weblogic",8000:"http-alt",8080:"http-proxy",
  8081:"http-alt",8443:"https-alt",8888:"http-alt",9000:"cslistener",
  9090:"zeus-admin",9200:"elasticsearch",9300:"elasticsearch-cluster",
  9418:"git",11211:"memcached",27017:"mongodb",27018:"mongodb",
  5555:"android-adb",1337:"waste",31337:"eleet",
};

export function lookupPort(port) {
  return { port, service: PORT_MAP[port] || "unknown", isWellKnown: port < 1024, isRegistered: port >= 1024 && port < 49152, isDynamic: port >= 49152 };
}
