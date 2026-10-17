// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Network-protocol mini-tools: packet/header decoders from pasted hex, accurate
// protocol reference tables, and link-layer / transport calculators. See _schema.md.
// Complements the "network" category (subnet math, command builders) without duplicating it.

const S = (v) => (v == null ? "" : String(v));

// ---- hex parsing ----
function hexBytes(s) {
  const h = String(s || "").replace(/0x/gi, "").replace(/[\s:.,_-]/g, "");
  if (!h) return { err: "Paste the bytes as hex, e.g. 45 00 00 3c." };
  if (!/^[0-9a-fA-F]+$/.test(h)) return { err: "Input has non-hex characters. Use only 0-9 and a-f." };
  if (h.length % 2) return { err: "Odd number of hex digits — each byte needs two hex characters." };
  const u = new Uint8Array(h.length / 2);
  for (let i = 0; i < u.length; i++) u[i] = parseInt(h.substr(i * 2, 2), 16);
  return u;
}
const u16 = (u, i) => ((u[i] << 8) | u[i + 1]) >>> 0;
const u32 = (u, i) => ((u[i] * 0x1000000) + (u[i + 1] << 16) + (u[i + 2] << 8) + u[i + 3]) >>> 0;
const macOf = (u, i) => Array.from(u.slice(i, i + 6), (b) => b.toString(16).padStart(2, "0")).join(":");
const ip4Of = (u, i) => `${u[i]}.${u[i + 1]}.${u[i + 2]}.${u[i + 3]}`;
const hx = (n, w) => "0x" + (n >>> 0).toString(16).padStart(w || 2, "0");
const bin8 = (n) => (n & 0xff).toString(2).padStart(8, "0");

// ---- IPv6 helpers ----
function v6compress(g) {
  const hexg = g.map((x) => x.toString(16));
  let best = -1, bestLen = 0, i = 0;
  while (i < 8) { if (g[i] === 0) { let j = i; while (j < 8 && g[j] === 0) j++; if (j - i > bestLen) { bestLen = j - i; best = i; } i = j; } else i++; }
  if (bestLen < 2) return hexg.join(":");
  return hexg.slice(0, best).join(":") + "::" + hexg.slice(best + bestLen).join(":");
}
function v6expand(g) { return g.map((x) => x.toString(16).padStart(4, "0")).join(":"); }
function v6Of(u, i) { const g = []; for (let k = 0; k < 8; k++) g.push(u16(u, i + k * 2)); return v6compress(g); }
function parseV6(str) {
  let s = String(str || "").trim().replace(/%.*$/, "");
  if (!s) return null;
  if (s.indexOf("::") !== s.lastIndexOf("::")) return null;
  let head, tail;
  if (s.includes("::")) { const p = s.split("::"); head = p[0] ? p[0].split(":") : []; tail = p[1] ? p[1].split(":") : []; }
  else { head = s.split(":"); tail = []; }
  const expand = (arr) => {
    const out = [];
    for (const p of arr) {
      if (p === "") return null;
      if (p.includes(".")) { const o = p.split("."); if (o.length !== 4) return null; const b = o.map((x) => parseInt(x, 10)); if (b.some((x) => isNaN(x) || x < 0 || x > 255)) return null; out.push((b[0] << 8) | b[1]); out.push((b[2] << 8) | b[3]); }
      else { if (!/^[0-9a-fA-F]{1,4}$/.test(p)) return null; out.push(parseInt(p, 16)); }
    }
    return out;
  };
  const h = expand(head), t = expand(tail);
  if (h === null || t === null) return null;
  const total = h.length + t.length;
  if (s.includes("::")) { if (total > 7) return null; return [...h, ...new Array(8 - total).fill(0), ...t]; }
  if (total !== 8) return null;
  return h;
}

// ---- internet checksum (RFC 1071) ----
function foldSum(bytes, start, end) {
  start = start || 0; end = end == null ? bytes.length : end;
  let sum = 0;
  for (let i = start; i < end; i += 2) { const hi = bytes[i], lo = (i + 1 < end) ? bytes[i + 1] : 0; sum += (hi << 8) | lo; }
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return sum & 0xffff;
}

// ---- reference-table renderer ----
function refTable(map, q, fmt) {
  const entries = Object.entries(map);
  const query = String(q || "").trim().toLowerCase();
  const rows = entries.filter(([k, val]) => !query || k.toLowerCase().includes(query) || String(val).toLowerCase().includes(query));
  if (!rows.length) return { error: "No matching entries." };
  return rows.map(fmt || (([k, val]) => `${k} — ${val}`)).join("\n");
}

// ---- shared protocol maps ----
const IP_PROTOCOLS = { 0: "HOPOPT (IPv6 Hop-by-Hop Options)", 1: "ICMP", 2: "IGMP", 4: "IPv4 (encapsulation)", 6: "TCP", 8: "EGP", 9: "IGP (any private interior gateway)", 17: "UDP", 41: "IPv6 (encapsulation)", 43: "IPv6-Route (Routing header)", 44: "IPv6-Frag (Fragment header)", 46: "RSVP", 47: "GRE", 50: "ESP (Encapsulating Security Payload)", 51: "AH (Authentication Header)", 58: "IPv6-ICMP (ICMPv6)", 59: "IPv6-NoNxt (No Next Header)", 60: "IPv6-Opts (Destination Options)", 88: "EIGRP", 89: "OSPFIGP (OSPF)", 94: "IPIP", 97: "ETHERIP", 103: "PIM", 108: "IPComp", 112: "VRRP", 115: "L2TP", 132: "SCTP", 136: "UDP-Lite", 137: "MPLS-in-IP" };
const DNS_TYPE_CODES = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT", 17: "RP", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC", 33: "SRV", 35: "NAPTR", 37: "CERT", 39: "DNAME", 41: "OPT (EDNS0)", 43: "DS", 44: "SSHFP", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 59: "CDS", 60: "CDNSKEY", 64: "SVCB", 65: "HTTPS", 99: "SPF (obsolete)", 108: "EUI48", 109: "EUI64", 251: "IXFR", 252: "AXFR", 255: "ANY (*)", 256: "URI", 257: "CAA" };
const DNS_TYPE_BY_NAME = Object.fromEntries(Object.entries(DNS_TYPE_CODES).map(([k, v]) => [v.split(" ")[0], Number(k)]));

export const TOOLS = [

  // ================= LINK / NETWORK LAYER DECODERS =================
  { id: "np-ethernet-decode", name: "Ethernet II Frame Decoder", cat: "netproto", desc: "Decode an Ethernet II header from hex: destination MAC, source MAC and EtherType (with 802.1Q VLAN tag if present).", tags: ["ethernet", "frame", "mac", "ethertype"],
    inputs: [{ k: "hex", label: "Frame bytes (hex)", type: "textarea", rows: 3, placeholder: "ffffffffffff 001122334455 0806" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 14) return { error: "Need at least 14 bytes for an Ethernet II header." };
      const dst = macOf(u, 0), src = macOf(u, 6);
      let et = u16(u, 12), off = 14, vlan = "";
      const ET = { 0x0800: "IPv4", 0x0806: "ARP", 0x86dd: "IPv6", 0x8100: "802.1Q VLAN", 0x88a8: "802.1ad QinQ", 0x8847: "MPLS unicast", 0x8864: "PPPoE Session", 0x88cc: "LLDP" };
      if ((et === 0x8100 || et === 0x88a8) && u.length >= 18) {
        const tci = u16(u, 14); vlan = `\nVLAN tag (${hx(et, 4)}): PCP=${(tci >> 13) & 7} DEI=${(tci >> 12) & 1} VID=${tci & 0x0fff}`;
        et = u16(u, 16); off = 18;
      }
      const name = ET[et] || "unknown / IEEE 802.3 length (if <= 0x05DC)";
      return `Destination MAC: ${dst}\nSource MAC:      ${src}${vlan}\nEtherType:       ${hx(et, 4)} (${name})\nPayload starts at byte ${off}.`;
    } },

  { id: "np-vlan-decode", name: "802.1Q VLAN Tag Decoder", cat: "netproto", desc: "Decode an IEEE 802.1Q tag: TPID, Priority (PCP), Drop-Eligible (DEI/CFI) and VLAN ID. Accepts the 4-byte tag or just the 2-byte TCI.", tags: ["vlan", "802.1q", "tag", "pcp"],
    inputs: [{ k: "hex", label: "Tag bytes (hex)", type: "text", placeholder: "8100 0064" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      let tci, tpid = null;
      if (u.length === 4) { tpid = u16(u, 0); tci = u16(u, 2); }
      else if (u.length === 2) { tci = u16(u, 0); }
      else return { error: "Provide 2 bytes (TCI) or 4 bytes (TPID+TCI)." };
      const pcp = (tci >> 13) & 7, dei = (tci >> 12) & 1, vid = tci & 0x0fff;
      const PRI = ["0 Best effort", "1 Background", "2 Excellent effort", "3 Critical apps", "4 Video <100ms", "5 Voice <10ms", "6 Internetwork control", "7 Network control"];
      const special = vid === 0 ? " (priority-tagged, no VLAN)" : vid === 1 ? " (default VLAN on many switches)" : vid === 4095 ? " (reserved)" : "";
      return [tpid !== null ? `TPID: ${hx(tpid, 4)}` : null, `PCP (priority): ${pcp} — ${PRI[pcp]}`, `DEI/CFI: ${dei}`, `VLAN ID: ${vid}${special}`].filter(Boolean).join("\n");
    } },

  { id: "np-arp-decode", name: "ARP Packet Decoder", cat: "netproto", desc: "Decode an ARP packet from hex: hardware/protocol type, opcode, and sender/target MAC and IP addresses.", tags: ["arp", "rarp", "mac", "request", "reply"],
    inputs: [{ k: "hex", label: "ARP bytes (hex)", type: "textarea", rows: 3, placeholder: "0001 0800 06 04 0001 001122334455 c0a80001 000000000000 c0a80002" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 8) return { error: "Need at least 8 bytes (ARP fixed header)." };
      const htype = u16(u, 0), ptype = u16(u, 2), hlen = u[4], plen = u[5], op = u16(u, 6);
      const HT = { 1: "Ethernet", 6: "IEEE 802", 15: "Frame Relay", 16: "ATM", 17: "HDLC", 18: "Fibre Channel", 20: "Serial Line" };
      const OP = { 1: "ARP Request", 2: "ARP Reply", 3: "RARP Request", 4: "RARP Reply", 8: "InARP Request", 9: "InARP Reply" };
      const out = [`Hardware type: ${htype} (${HT[htype] || "?"})`, `Protocol type: ${hx(ptype, 4)} (${ptype === 0x0800 ? "IPv4" : "?"})`, `HW addr len: ${hlen}   Proto addr len: ${plen}`, `Opcode: ${op} (${OP[op] || "?"})`];
      if (htype === 1 && ptype === 0x0800 && hlen === 6 && plen === 4 && u.length >= 28) {
        out.push(`Sender MAC: ${macOf(u, 8)}  Sender IP: ${ip4Of(u, 14)}`);
        out.push(`Target MAC: ${macOf(u, 18)}  Target IP: ${ip4Of(u, 24)}`);
      } else {
        out.push("(Address fields shown only for Ethernet/IPv4 ARP with 28+ bytes.)");
      }
      return out.join("\n");
    } },

  { id: "np-ipv4-decode", name: "IPv4 Header Decoder", cat: "netproto", desc: "Decode an IPv4 header from hex into every field: version, IHL, DSCP/ECN, length, ID, flags, fragment offset, TTL, protocol, checksum and addresses.", tags: ["ipv4", "ip", "header", "decode", "ttl"],
    inputs: [{ k: "hex", label: "IPv4 header bytes (hex)", type: "textarea", rows: 3, placeholder: "4500 003c 1c46 4000 4006 b1e6 c0a80001 c0a800c7" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 20) return { error: "Need at least 20 bytes for an IPv4 header." };
      const ver = u[0] >> 4, ihl = u[0] & 0x0f, hlen = ihl * 4;
      if (ver !== 4) return { error: `First nibble is ${ver}, not 4 — this is not an IPv4 header.` };
      const dscp = u[1] >> 2, ecn = u[1] & 3, total = u16(u, 2), id = u16(u, 4);
      const flagsFrag = u16(u, 6), df = (flagsFrag >> 14) & 1, mf = (flagsFrag >> 13) & 1, frag = (flagsFrag & 0x1fff) * 8;
      const ttl = u[8], proto = u[9], cks = u16(u, 10);
      const ECN = ["Not-ECT", "ECT(1)", "ECT(0)", "CE (congestion)"];
      const calc = (() => { const c = Uint8Array.from(u.slice(0, hlen)); c[10] = 0; c[11] = 0; return (~foldSum(c, 0, hlen)) & 0xffff; })();
      return [
        `Version: ${ver}   IHL: ${ihl} (${hlen} bytes)`,
        `DSCP: ${dscp} (${hx(dscp)})   ECN: ${ecn} (${ECN[ecn]})`,
        `Total length: ${total} bytes`,
        `Identification: ${id} (${hx(id, 4)})`,
        `Flags: DF=${df} MF=${mf}   Fragment offset: ${frag} bytes`,
        `TTL: ${ttl}`,
        `Protocol: ${proto} (${IP_PROTOCOLS[proto] || "?"})`,
        `Header checksum: ${hx(cks, 4)}  (computed ${hx(calc, 4)} ${hlen <= u.length ? (calc === cks ? "— valid" : "— MISMATCH") : ""})`,
        `Source: ${ip4Of(u, 12)}`,
        `Destination: ${ip4Of(u, 16)}`,
        ihl > 5 ? `Options present: ${hlen - 20} bytes` : "No options.",
      ].join("\n");
    } },

  { id: "np-ipv6-decode", name: "IPv6 Header Decoder", cat: "netproto", desc: "Decode a 40-byte IPv6 header from hex: version, traffic class (DSCP/ECN), flow label, payload length, next header and hop limit, plus source and destination.", tags: ["ipv6", "header", "decode", "flow label"],
    inputs: [{ k: "hex", label: "IPv6 header bytes (hex)", type: "textarea", rows: 3, placeholder: "6000 0000 0014 0640 fe80...(40 bytes)" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 40) return { error: "Need 40 bytes for an IPv6 base header." };
      const ver = u[0] >> 4;
      if (ver !== 6) return { error: `First nibble is ${ver}, not 6 — not an IPv6 header.` };
      const tc = ((u[0] & 0x0f) << 4) | (u[1] >> 4);
      const flow = ((u[1] & 0x0f) << 16) | (u[2] << 8) | u[3];
      const plen = u16(u, 4), nh = u[6], hop = u[7];
      return [
        `Version: 6`,
        `Traffic class: ${tc} (DSCP ${tc >> 2}, ECN ${tc & 3})`,
        `Flow label: ${flow} (${hx(flow, 5)})`,
        `Payload length: ${plen} bytes`,
        `Next header: ${nh} (${IP_PROTOCOLS[nh] || "?"})`,
        `Hop limit: ${hop}`,
        `Source: ${v6Of(u, 8)}`,
        `Destination: ${v6Of(u, 24)}`,
      ].join("\n");
    } },

  // ================= TRANSPORT LAYER DECODERS =================
  { id: "np-tcp-decode", name: "TCP Header Decoder", cat: "netproto", desc: "Decode a TCP header from hex: ports, sequence/ack numbers, data offset, every flag bit, window, checksum, urgent pointer and option kinds.", tags: ["tcp", "header", "flags", "seq", "ack"],
    inputs: [{ k: "hex", label: "TCP header bytes (hex)", type: "textarea", rows: 3, placeholder: "0050 01bb 00000001 00000000 5002 2000 917c 0000" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 20) return { error: "Need at least 20 bytes for a TCP header." };
      const sp = u16(u, 0), dp = u16(u, 2), seq = u32(u, 4), ack = u32(u, 8);
      const dataOff = u[12] >> 4, hlen = dataOff * 4;
      const ns = u[12] & 1, fb = u[13];
      const FL = [["CWR", 0x80], ["ECE", 0x40], ["URG", 0x20], ["ACK", 0x10], ["PSH", 0x08], ["RST", 0x04], ["SYN", 0x02], ["FIN", 0x01]];
      const set = FL.filter(([, b]) => fb & b).map(([n]) => n); if (ns) set.unshift("NS");
      const win = u16(u, 14), cks = u16(u, 16), urg = u16(u, 18);
      const out = [
        `Source port: ${sp}   Destination port: ${dp}`,
        `Sequence number: ${seq}`,
        `Acknowledgment number: ${ack}`,
        `Data offset: ${dataOff} (${hlen}-byte header)`,
        `Flags: ${set.length ? set.join(" ") : "(none)"}  [${bin8(fb)}]`,
        `Window: ${win}`,
        `Checksum: ${hx(cks, 4)}   Urgent pointer: ${urg}`,
      ];
      if (dataOff > 5 && u.length >= hlen) {
        const KIND = { 0: "EOL", 1: "NOP", 2: "MSS", 3: "Window Scale", 4: "SACK permitted", 5: "SACK", 8: "Timestamps", 28: "User Timeout", 29: "TCP-AO", 34: "TFO cookie" };
        const opts = []; let p = 20;
        while (p < hlen && p < u.length) { const k = u[p]; if (k === 0) { opts.push("EOL"); break; } if (k === 1) { opts.push("NOP"); p++; continue; } const len = u[p + 1]; if (!len || p + len > hlen) break; let extra = ""; if (k === 2 && len === 4) extra = `=${u16(u, p + 2)}`; if (k === 3 && len === 3) extra = `=${u[p + 2]} (x${1 << u[p + 2]})`; opts.push(`${KIND[k] || "kind " + k}${extra}`); p += len; }
        out.push(`Options: ${opts.join(", ") || "(none parsed)"}`);
      }
      return out.join("\n");
    } },

  { id: "np-udp-decode", name: "UDP Header Decoder", cat: "netproto", desc: "Decode the 8-byte UDP header from hex: source port, destination port, length and checksum.", tags: ["udp", "header", "port", "length"],
    inputs: [{ k: "hex", label: "UDP header bytes (hex)", type: "text", placeholder: "d431 0035 002a 1b2c" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 8) return { error: "Need 8 bytes for a UDP header." };
      const len = u16(u, 4);
      return `Source port: ${u16(u, 0)}\nDestination port: ${u16(u, 2)}\nLength: ${len} bytes (header 8 + data ${len - 8})\nChecksum: ${hx(u16(u, 6), 4)}${u16(u, 6) === 0 ? " (0 = not computed, allowed over IPv4)" : ""}`;
    } },

  { id: "np-icmp-decode", name: "ICMP Message Decoder", cat: "netproto", desc: "Decode an ICMPv4 message from hex: type, code, checksum and the type-specific rest-of-header (echo id/seq, next-hop MTU, pointer).", tags: ["icmp", "ping", "echo", "unreachable"],
    inputs: [{ k: "hex", label: "ICMP bytes (hex)", type: "text", placeholder: "0800 f7ff 0001 0001" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 4) return { error: "Need at least 4 bytes (type, code, checksum)." };
      const t = u[0], c = u[1];
      const TYPE = { 0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench (deprecated)", 5: "Redirect", 8: "Echo Request", 9: "Router Advertisement", 10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem", 13: "Timestamp", 14: "Timestamp Reply", 17: "Address Mask Request", 18: "Address Mask Reply" };
      const out = [`Type: ${t} (${TYPE[t] || "?"})`, `Code: ${c}`, `Checksum: ${hx(u16(u, 2), 4)}`];
      if ((t === 8 || t === 0) && u.length >= 8) out.push(`Identifier: ${u16(u, 4)}   Sequence: ${u16(u, 6)}`);
      else if (t === 3 && c === 4 && u.length >= 8) out.push(`Next-hop MTU: ${u16(u, 6)}`);
      else if (t === 11) out.push(`(Rest unused; followed by the IP header + 8 bytes that expired.)`);
      else if (t === 12 && u.length >= 5) out.push(`Pointer: byte ${u[4]} of the offending header`);
      return out.join("\n");
    } },

  { id: "np-tls-record-decode", name: "TLS Record Header Decoder", cat: "netproto", desc: "Decode a 5-byte TLS/SSL record header from hex: content type, protocol version and record length.", tags: ["tls", "ssl", "record", "handshake"],
    inputs: [{ k: "hex", label: "Record header bytes (hex)", type: "text", placeholder: "16 0303 0040" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 5) return { error: "Need 5 bytes for a TLS record header." };
      const CT = { 20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData", 24: "Heartbeat" };
      const VER = { 0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2 (also TLS 1.3 records)", 0x0304: "TLS 1.3" };
      const ver = u16(u, 1), len = u16(u, 3);
      const out = [`Content type: ${u[0]} (${CT[u[0]] || "?"})`, `Version: ${hx(ver, 4)} (${VER[ver] || "?"})`, `Record length: ${len} bytes`];
      if (u[0] === 22 && u.length >= 6) { const HS = { 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished" }; out.push(`First handshake message type: ${u[5]} (${HS[u[5]] || "?"})`); }
      return out.join("\n");
    } },

  // ================= DNS =================
  { id: "np-dns-decode", name: "DNS Message Decoder", cat: "netproto", desc: "Decode a DNS message from hex: transaction ID, every header flag (QR, Opcode, AA, TC, RD, RA, RCODE), section counts and the question section (with name decompression).", tags: ["dns", "message", "wire", "query", "flags"],
    inputs: [{ k: "hex", label: "DNS message bytes (hex)", type: "textarea", rows: 4, placeholder: "1234 0100 0001 0000 0000 0000 03777777 076578616d706c6503636f6d 00 0001 0001" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 12) return { error: "Need at least 12 bytes for a DNS header." };
      const id = u16(u, 0), fl = u16(u, 2);
      const qr = (fl >> 15) & 1, op = (fl >> 11) & 0xf, aa = (fl >> 10) & 1, tc = (fl >> 9) & 1, rd = (fl >> 8) & 1, ra = (fl >> 7) & 1, z = (fl >> 6) & 1, ad = (fl >> 5) & 1, cd = (fl >> 4) & 1, rc = fl & 0xf;
      const OP = { 0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE", 6: "DSO" };
      const RC = { 0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 9: "NOTAUTH", 16: "BADVERS" };
      const qd = u16(u, 4), an = u16(u, 6), ns = u16(u, 8), ar = u16(u, 10);
      function name(off) {
        let labels = [], jumped = false, pos = off, safety = 0, consumed = 0;
        while (safety++ < 128) {
          if (pos >= u.length) return null;
          const len = u[pos];
          if (len === 0) { if (!jumped) consumed = pos + 1 - off; pos++; break; }
          if ((len & 0xc0) === 0xc0) { if (pos + 1 >= u.length) return null; const ptr = ((len & 0x3f) << 8) | u[pos + 1]; if (!jumped) consumed = pos + 2 - off; jumped = true; pos = ptr; continue; }
          if ((len & 0xc0) !== 0) return null;
          if (pos + 1 + len > u.length) return null;
          let lab = ""; for (let k = 0; k < len; k++) lab += String.fromCharCode(u[pos + 1 + k]);
          labels.push(lab); pos += 1 + len;
        }
        return { name: labels.join(".") || "<root>", consumed };
      }
      const out = [
        `Transaction ID: ${hx(id, 4)}`,
        `${qr ? "Response" : "Query"} (QR=${qr}), Opcode ${op} (${OP[op] || "?"})`,
        `Flags: AA=${aa} TC=${tc} RD=${rd} RA=${ra} AD=${ad} CD=${cd} Z=${z}`,
        `RCODE: ${rc} (${RC[rc] || "?"})`,
        `Counts: QD=${qd} AN=${an} NS=${ns} AR=${ar}`,
      ];
      let p = 12;
      for (let i = 0; i < qd && p < u.length; i++) {
        const n = name(p); if (!n) { out.push("Question: (could not parse name)"); break; }
        p += n.consumed; if (p + 4 > u.length) { out.push(`Question ${i + 1}: ${n.name} (truncated)`); break; }
        const qt = u16(u, p), qc = u16(u, p + 2); p += 4;
        out.push(`Question ${i + 1}: ${n.name}  type ${qt} (${DNS_TYPE_CODES[qt] || "?"})  class ${qc === 1 ? "IN" : qc}`);
      }
      return out.join("\n");
    } },

  { id: "np-dns-flags-decode", name: "DNS Header Flags Decoder", cat: "netproto", desc: "Decode the 16-bit DNS header flags word (the 3rd/4th bytes) into QR, Opcode, AA, TC, RD, RA, AD, CD and RCODE.", tags: ["dns", "flags", "rcode", "opcode"],
    inputs: [{ k: "val", label: "Flags value (hex or decimal)", type: "text", placeholder: "0x8180" }],
    run(v) {
      if (!v.val) return "";
      const s = String(v.val).trim();
      const fl = /^0x/i.test(s) ? parseInt(s, 16) : /^[0-9a-f]{4}$/i.test(s) && !/^\d+$/.test(s) ? parseInt(s, 16) : parseInt(s, 10);
      if (isNaN(fl) || fl < 0 || fl > 0xffff) return { error: "Enter a 16-bit value (0-65535 or 0x0000-0xffff)." };
      const OP = { 0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE", 6: "DSO" };
      const RC = { 0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 9: "NOTAUTH", 16: "BADVERS" };
      const rc = fl & 0xf, op = (fl >> 11) & 0xf;
      return [`Value: ${hx(fl, 4)} (${fl})`, `QR: ${(fl >> 15) & 1} (${(fl >> 15) & 1 ? "response" : "query"})`, `Opcode: ${op} (${OP[op] || "?"})`, `AA (authoritative): ${(fl >> 10) & 1}`, `TC (truncated): ${(fl >> 9) & 1}`, `RD (recursion desired): ${(fl >> 8) & 1}`, `RA (recursion available): ${(fl >> 7) & 1}`, `AD (authentic data): ${(fl >> 5) & 1}`, `CD (checking disabled): ${(fl >> 4) & 1}`, `RCODE: ${rc} (${RC[rc] || "?"})`].join("\n");
    } },

  { id: "np-dns-name-decode", name: "DNS Name Decoder", cat: "netproto", desc: "Decode a length-prefixed DNS name from hex into a dotted domain, handling compression pointers (0xC0) that point within the same bytes.", tags: ["dns", "name", "labels", "compression"],
    inputs: [{ k: "hex", label: "Name bytes (hex, from offset 0)", type: "textarea", rows: 2, placeholder: "03 777777 07 6578616d706c65 03 636f6d 00" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      let labels = [], pos = 0, safety = 0, note = "";
      while (safety++ < 128) {
        if (pos >= u.length) return { error: "Ran off the end — missing a terminating 0x00 byte." };
        const len = u[pos];
        if (len === 0) break;
        if ((len & 0xc0) === 0xc0) { note = `\n(compression pointer 0x${((len & 0x3f) << 8 | (u[pos + 1] || 0)).toString(16)} — resolved only within these bytes)`; const ptr = ((len & 0x3f) << 8) | u[pos + 1]; pos = ptr; continue; }
        if ((len & 0xc0) !== 0) return { error: "Invalid label length bits." };
        if (pos + 1 + len > u.length) return { error: "Label length runs past the data." };
        let lab = ""; for (let k = 0; k < len; k++) lab += String.fromCharCode(u[pos + 1 + k]);
        labels.push(lab); pos += 1 + len;
      }
      return `${labels.join(".") || "<root>"}${note}`;
    } },

  { id: "np-dns-name-encode", name: "DNS Name Encoder", cat: "netproto", desc: "Encode a domain name into DNS wire format: each label prefixed by its length byte, ended with 0x00. Shows the hex bytes.", tags: ["dns", "name", "labels", "wire", "encode"],
    inputs: [{ k: "name", label: "Domain name", type: "text", placeholder: "www.example.com" }],
    run(v) {
      const name = String(v.name || "").trim().replace(/\.$/, "");
      if (!name) return "";
      const labels = name.split(".");
      const bytes = [];
      for (const l of labels) { if (l.length === 0) return { error: "Empty label (two dots in a row)." }; if (l.length > 63) return { error: `Label "${l}" exceeds 63 bytes.` }; bytes.push(l.length); for (let i = 0; i < l.length; i++) bytes.push(l.charCodeAt(i) & 0xff); }
      bytes.push(0);
      if (bytes.length > 255) return { error: "Encoded name exceeds 255 bytes." };
      const hexs = bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ");
      return `Wire bytes (${bytes.length}):\n${hexs}`;
    } },

  { id: "np-dns-query-build", name: "DNS Query Builder", cat: "netproto", desc: "Build a complete DNS query message (header + question) as hex for a given name, record type and recursion flag — ready to send over UDP/53.", tags: ["dns", "query", "wire", "build", "udp"],
    inputs: [
      { k: "name", label: "Domain name", type: "text", placeholder: "example.com" },
      { k: "type", label: "Record type", type: "select", opts: ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "PTR", "SRV", "CAA", "ANY"], value: "A" },
      { k: "rd", label: "Recursion desired", type: "checkbox", value: true },
    ],
    run(v) {
      const name = String(v.name || "").trim().replace(/\.$/, "");
      if (!name) return "";
      const qtype = DNS_TYPE_BY_NAME[v.type] || 1;
      const out = [];
      const push16 = (n) => { out.push((n >> 8) & 0xff, n & 0xff); };
      push16(0x1234); // transaction ID (example)
      push16(v.rd ? 0x0100 : 0x0000); // flags: standard query, RD
      push16(1); push16(0); push16(0); push16(0); // QD=1, AN/NS/AR=0
      for (const l of name.split(".")) { if (!l || l.length > 63) return { error: "Invalid label in name." }; out.push(l.length); for (let i = 0; i < l.length; i++) out.push(l.charCodeAt(i) & 0xff); }
      out.push(0);
      push16(qtype); push16(1); // QTYPE, QCLASS=IN
      const hexs = out.map((b) => b.toString(16).padStart(2, "0")).join(" ");
      return `Query: ${name} ${v.type} IN (${out.length} bytes, ID 0x1234)\n\n${hexs}`;
    } },

  // ================= APP / SERVICE DECODERS =================
  { id: "np-dhcp-decode", name: "DHCP / BOOTP Decoder", cat: "netproto", desc: "Decode the fixed BOOTP/DHCP header from hex (op, hops, xid, client/your/server/gateway IPs, client MAC) plus the magic cookie and first options.", tags: ["dhcp", "bootp", "lease", "options"],
    inputs: [{ k: "hex", label: "DHCP packet bytes (hex)", type: "textarea", rows: 4, placeholder: "01 01 06 00 3903f326 ...(240+ bytes)" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 44) return { error: "Need at least 44 bytes for the BOOTP fixed header." };
      const out = [
        `Op: ${u[0]} (${u[0] === 1 ? "BOOTREQUEST" : u[0] === 2 ? "BOOTREPLY" : "?"})`,
        `HW type: ${u[1]} (${u[1] === 1 ? "Ethernet" : "?"})  HW len: ${u[2]}  Hops: ${u[3]}`,
        `Transaction ID (xid): ${hx(u32(u, 4), 8)}`,
        `Secs: ${u16(u, 8)}  Flags: ${hx(u16(u, 10), 4)}${(u16(u, 10) & 0x8000) ? " (broadcast)" : ""}`,
        `ciaddr (client): ${ip4Of(u, 12)}`,
        `yiaddr (your):   ${ip4Of(u, 16)}`,
        `siaddr (server): ${ip4Of(u, 20)}`,
        `giaddr (gateway):${ip4Of(u, 24)}`,
        `chaddr (client MAC): ${macOf(u, 28)}`,
      ];
      if (u.length >= 240 && u32(u, 236) === 0x63825363) {
        out.push("Magic cookie: 63 82 53 63 (DHCP)");
        const MT = { 1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM" };
        let p = 240; const opts = [];
        while (p < u.length) { const code = u[p]; if (code === 255) { opts.push("255 End"); break; } if (code === 0) { p++; continue; } const len = u[p + 1]; let desc = `option ${code}`; if (code === 53) desc = `53 MessageType=${MT[u[p + 2]] || u[p + 2]}`; else if (code === 1) desc = `1 SubnetMask=${ip4Of(u, p + 2)}`; else if (code === 3) desc = `3 Router=${ip4Of(u, p + 2)}`; else if (code === 51) desc = `51 LeaseTime=${u32(u, p + 2)}s`; else if (code === 54) desc = `54 ServerID=${ip4Of(u, p + 2)}`; opts.push(desc); p += 2 + len; if (opts.length > 12) { opts.push("..."); break; } }
        out.push("Options: " + opts.join(", "));
      } else {
        out.push("(No DHCP magic cookie found at byte 236 — pure BOOTP or truncated.)");
      }
      return out.join("\n");
    } },

  { id: "np-ntp-decode", name: "NTP Packet Decoder", cat: "netproto", desc: "Decode an NTP packet from hex: leap indicator, version, mode, stratum, poll/precision exponents, reference ID and the transmit timestamp.", tags: ["ntp", "time", "stratum", "sntp"],
    inputs: [{ k: "hex", label: "NTP bytes (hex, 48)", type: "textarea", rows: 3, placeholder: "1b 00 00 00 ...(48 bytes)" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 48) return { error: "Need 48 bytes for an NTP packet." };
      const li = u[0] >> 6, vn = (u[0] >> 3) & 7, mode = u[0] & 7, st = u[1];
      const poll = u[2] << 24 >> 24, prec = u[3] << 24 >> 24;
      const LI = ["no warning", "last minute 61s", "last minute 59s", "clock unsynchronized"];
      const MODE = { 0: "reserved", 1: "symmetric active", 2: "symmetric passive", 3: "client", 4: "server", 5: "broadcast", 6: "control", 7: "private" };
      let strat = st === 0 ? "0 (unspecified / kiss-o'-death)" : st === 1 ? "1 (primary reference)" : `${st} (secondary)`;
      const txSec = u32(u, 40);
      const date = txSec ? new Date((txSec - 2208988800) * 1000).toISOString() : "(zero)";
      return [
        `Leap indicator: ${li} (${LI[li]})`,
        `Version: ${vn}   Mode: ${mode} (${MODE[mode]})`,
        `Stratum: ${strat}`,
        `Poll interval: 2^${poll} s   Precision: 2^${prec} s`,
        `Reference ID: ${hx(u32(u, 12), 8)}`,
        `Transmit timestamp: ${txSec} -> ${date}`,
      ].join("\n");
    } },

  { id: "np-stun-decode", name: "STUN Message Decoder", cat: "netproto", desc: "Decode a STUN message header from hex (WebRTC/NAT traversal): message type (method + class), length, magic cookie and transaction ID.", tags: ["stun", "webrtc", "nat", "ice"],
    inputs: [{ k: "hex", label: "STUN bytes (hex)", type: "textarea", rows: 2, placeholder: "0001 0000 2112a442 000102030405060708090a0b" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 20) return { error: "Need 20 bytes for a STUN header." };
      const mt = u16(u, 0);
      if (mt & 0xc000) return { error: "Top two bits are not zero — not a STUN message." };
      const cls = ((mt >> 4) & 1) | ((mt >> 7) & 2);
      const method = (mt & 0x000f) | ((mt & 0x00e0) >> 1) | ((mt & 0x3e00) >> 2);
      const CLS = ["Request", "Indication", "Success Response", "Error Response"];
      const METH = { 1: "Binding", 2: "SharedSecret (deprecated)", 3: "Allocate (TURN)", 4: "Refresh (TURN)", 6: "Send (TURN)", 7: "Data (TURN)", 8: "CreatePermission (TURN)", 9: "ChannelBind (TURN)" };
      const cookie = u32(u, 4);
      const tid = Array.from(u.slice(8, 20), (b) => b.toString(16).padStart(2, "0")).join("");
      return [
        `Message type: ${hx(mt, 4)}`,
        `Method: ${method} (${METH[method] || "?"})`,
        `Class: ${cls} (${CLS[cls]})`,
        `Message length: ${u16(u, 2)} bytes (attributes)`,
        `Magic cookie: ${hx(cookie, 8)} ${cookie === 0x2112a442 ? "(valid)" : "(INVALID — expected 0x2112a442)"}`,
        `Transaction ID: ${tid}`,
      ].join("\n");
    } },

  // ================= TUNNELING / MPLS =================
  { id: "np-vxlan-decode", name: "VXLAN Header Decoder", cat: "netproto", desc: "Decode the 8-byte VXLAN header from hex: flags (I bit) and the 24-bit VXLAN Network Identifier (VNI).", tags: ["vxlan", "overlay", "vni", "tunnel"],
    inputs: [{ k: "hex", label: "VXLAN header bytes (hex)", type: "text", placeholder: "08 000000 001389 00" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 8) return { error: "Need 8 bytes for a VXLAN header." };
      const iBit = (u[0] >> 3) & 1, vni = (u[4] << 16) | (u[5] << 8) | u[6];
      return `Flags byte: ${bin8(u[0])}  (I bit = ${iBit}${iBit ? ", VNI valid" : ", VNI should be ignored"})\nVNI: ${vni} (${hx(vni, 6)})\nReserved byte (last): ${hx(u[7])}`;
    } },

  { id: "np-gre-decode", name: "GRE Header Decoder", cat: "netproto", desc: "Decode a GRE (Generic Routing Encapsulation) header from hex: checksum/key/sequence flags, version and the encapsulated protocol EtherType.", tags: ["gre", "tunnel", "encapsulation"],
    inputs: [{ k: "hex", label: "GRE header bytes (hex)", type: "text", placeholder: "3000 0800 ...(key/seq if set)" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 4) return { error: "Need at least 4 bytes for a GRE header." };
      const C = (u[0] >> 7) & 1, K = (u[0] >> 5) & 1, Sb = (u[0] >> 4) & 1, ver = u[1] & 7;
      const proto = u16(u, 2);
      const P = { 0x0800: "IPv4", 0x86dd: "IPv6", 0x6558: "Transparent Ethernet Bridging (NVGRE)", 0x880b: "PPP" };
      const out = [`Flags: C(checksum)=${C} K(key)=${K} S(seq)=${Sb}`, `Version: ${ver}${ver === 1 ? " (PPTP Enhanced GRE)" : ""}`, `Protocol type: ${hx(proto, 4)} (${P[proto] || "?"})`];
      let off = 4; if (C) { out.push(`Checksum: ${u.length >= off + 2 ? hx(u16(u, off), 4) : "?"}`); off += 4; }
      if (K) { out.push(`Key: ${u.length >= off + 4 ? hx(u32(u, off), 8) : "?"}`); off += 4; }
      if (Sb) { out.push(`Sequence: ${u.length >= off + 4 ? u32(u, off) : "?"}`); }
      return out.join("\n");
    } },

  { id: "np-mpls-decode", name: "MPLS Label Stack Decoder", cat: "netproto", desc: "Decode one or more 4-byte MPLS label stack entries from hex: label value, Traffic Class (EXP), Bottom-of-Stack bit and TTL.", tags: ["mpls", "label", "ttl", "bos"],
    inputs: [{ k: "hex", label: "MPLS entries (hex)", type: "text", placeholder: "00064 0 1 ff  e.g. 00 06 41 ff" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 4 || u.length % 4) return { error: "Each MPLS entry is exactly 4 bytes." };
      const out = [];
      for (let i = 0; i < u.length; i += 4) {
        const label = (u[i] << 12) | (u[i + 1] << 4) | (u[i + 2] >> 4);
        const tc = (u[i + 2] >> 1) & 7, s = u[i + 2] & 1, ttl = u[i + 3];
        let special = label === 0 ? " (IPv4 Explicit NULL)" : label === 2 ? " (IPv6 Explicit NULL)" : label === 3 ? " (Implicit NULL)" : label === 1 ? " (Router Alert)" : "";
        out.push(`Entry ${i / 4 + 1}: Label=${label}${special}  TC/EXP=${tc}  S(bottom)=${s}  TTL=${ttl}`);
      }
      return out.join("\n");
    } },

  { id: "np-esp-decode", name: "IPsec ESP Header Decoder", cat: "netproto", desc: "Decode the IPsec ESP header fields from hex: Security Parameters Index (SPI) and the sequence number (the rest of the payload is encrypted).", tags: ["ipsec", "esp", "spi", "vpn"],
    inputs: [{ k: "hex", label: "ESP header bytes (hex)", type: "text", placeholder: "a1b2c3d4 00000001" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 8) return { error: "Need 8 bytes (SPI + sequence number)." };
      return `SPI: ${hx(u32(u, 0), 8)}\nSequence number: ${u32(u, 4)}\n(Everything after these 8 bytes is the encrypted payload + ICV.)`;
    } },

  { id: "np-pcap-header", name: "pcap Global Header Decoder", cat: "netproto", desc: "Decode a classic .pcap file global header from hex: magic/byte-order, version, snap length and link-layer type.", tags: ["pcap", "capture", "libpcap", "snaplen"],
    inputs: [{ k: "hex", label: "First 24 bytes (hex)", type: "textarea", rows: 2, placeholder: "d4c3b2a1 0200 0400 00000000 00000000 ffff0000 01000000" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 24) return { error: "Need 24 bytes for the pcap global header." };
      const be = u32(u, 0);
      let little, nano = false, magicDesc;
      if (be === 0xa1b2c3d4) { little = false; magicDesc = "big-endian, microsecond"; }
      else if (be === 0xd4c3b2a1) { little = true; magicDesc = "little-endian, microsecond"; }
      else if (be === 0xa1b23c4d) { little = false; nano = true; magicDesc = "big-endian, nanosecond"; }
      else if (be === 0x4d3cb2a1) { little = true; nano = true; magicDesc = "little-endian, nanosecond"; }
      else return { error: `Unknown magic ${hx(be, 8)} — not a classic pcap file.` };
      const rd16 = (i) => little ? (u[i] | (u[i + 1] << 8)) : u16(u, i);
      const rd32 = (i) => little ? ((u[i] | (u[i + 1] << 8) | (u[i + 2] << 16) | (u[i + 3] * 0x1000000)) >>> 0) : u32(u, i);
      const LT = { 0: "NULL/loopback", 1: "Ethernet", 9: "PPP", 101: "Raw IP", 105: "IEEE 802.11 (Wi-Fi)", 113: "Linux cooked (SLL)", 127: "802.11 + radiotap", 228: "Raw IPv4", 229: "Raw IPv6", 276: "Linux cooked v2" };
      const lt = rd32(20);
      return [`Magic: ${hx(be, 8)} (${magicDesc})`, `Version: ${rd16(4)}.${rd16(6)}`, `Snap length: ${rd32(16)} bytes`, `Link-layer type: ${lt} (${LT[lt] || "?"})`, nano ? "Timestamps are in nanoseconds." : "Timestamps are in microseconds."].join("\n");
    } },

  // ================= CHECKSUMS =================
  { id: "np-ipv4-checksum", name: "IPv4 Header Checksum", cat: "netproto", desc: "Compute or verify the IPv4 header checksum (RFC 1071 ones-complement) over a pasted header. Compute zeroes the checksum field first.", tags: ["ipv4", "checksum", "rfc1071"],
    inputs: [{ k: "hex", label: "IPv4 header bytes (hex)", type: "textarea", rows: 2, placeholder: "4500 003c 1c46 4000 4006 0000 c0a80001 c0a800c7" }, { k: "mode", label: "Mode", type: "select", opts: ["Compute", "Verify"], value: "Compute" }],
    run(v) {
      if (!v.hex) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      if (u.length < 20 || u.length % 4) return { error: "An IPv4 header is 20+ bytes in 4-byte words." };
      if (v.mode === "Verify") { const fold = foldSum(u, 0, u.length); return fold === 0xffff ? `Valid: the ones-complement sum folds to 0xFFFF (checksum OK).` : `INVALID: sum folds to ${hx(fold, 4)} (should be 0xFFFF). Stored checksum does not match.`; }
      const c = Uint8Array.from(u); c[10] = 0; c[11] = 0;
      const sum = (~foldSum(c, 0, c.length)) & 0xffff;
      return `Checksum: ${hx(sum, 4)}\nInsert bytes ${(sum >> 8).toString(16).padStart(2, "0")} ${(sum & 0xff).toString(16).padStart(2, "0")} at offset 10-11.`;
    } },

  { id: "np-l4-checksum", name: "TCP/UDP Checksum (pseudo-header)", cat: "netproto", desc: "Compute the TCP or UDP checksum over the IPv4/IPv6 pseudo-header plus the segment. Paste the L4 segment hex and the two IP addresses.", tags: ["tcp", "udp", "checksum", "pseudo-header"],
    inputs: [
      { k: "hex", label: "L4 segment bytes (hex, checksum field ignored)", type: "textarea", rows: 3, placeholder: "0050 01bb 00000001 00000000 5002 2000 0000 0000" },
      { k: "src", label: "Source IP", type: "text", placeholder: "192.0.2.1" },
      { k: "dst", label: "Destination IP", type: "text", placeholder: "192.0.2.2" },
      { k: "proto", label: "Protocol", type: "select", opts: ["TCP", "UDP"], value: "TCP" },
    ],
    run(v) {
      if (!v.hex || !v.src || !v.dst) return "";
      const u = hexBytes(v.hex); if (u.err) return { error: u.err };
      const protoNum = v.proto === "UDP" ? 17 : 6;
      const seg = Uint8Array.from(u);
      const ckOff = v.proto === "UDP" ? 6 : 16;
      if (seg.length < ckOff + 2) return { error: `Segment too short for a ${v.proto} header.` };
      seg[ckOff] = 0; seg[ckOff + 1] = 0;
      const ps = [];
      const isV6 = v.src.includes(":") || v.dst.includes(":");
      if (isV6) {
        const a = parseV6(v.src), b = parseV6(v.dst);
        if (!a || !b) return { error: "Invalid IPv6 address." };
        for (const g of a) { ps.push(g >> 8, g & 0xff); }
        for (const g of b) { ps.push(g >> 8, g & 0xff); }
        const L = seg.length; ps.push((L >>> 24) & 0xff, (L >>> 16) & 0xff, (L >>> 8) & 0xff, L & 0xff);
        ps.push(0, 0, 0, protoNum);
      } else {
        const pa = v.src.split(".").map(Number), pb = v.dst.split(".").map(Number);
        if (pa.length !== 4 || pb.length !== 4 || [...pa, ...pb].some((x) => isNaN(x) || x < 0 || x > 255)) return { error: "Invalid IPv4 address." };
        ps.push(...pa, ...pb, 0, protoNum, (seg.length >> 8) & 0xff, seg.length & 0xff);
      }
      const all = Uint8Array.from([...ps, ...seg]);
      const sum = (~foldSum(all, 0, all.length)) & 0xffff;
      const final = sum === 0 && v.proto === "UDP" ? 0xffff : sum;
      return `${v.proto} checksum: ${hx(final, 4)}\n(pseudo-header ${ps.length} bytes + segment ${seg.length} bytes${isV6 ? ", IPv6" : ", IPv4"})`;
    } },

  // ================= ADDRESS ANALYSIS =================
  { id: "np-ipv6-classify", name: "IPv6 Address Classifier", cat: "netproto", desc: "Classify an IPv6 address: loopback, unspecified, link-local, unique-local (ULA), multicast (with scope), global unicast, IPv4-mapped, documentation, 6to4 or Teredo.", tags: ["ipv6", "classify", "ula", "link-local", "multicast"],
    inputs: [{ k: "addr", label: "IPv6 address", type: "text", placeholder: "fe80::1" }],
    run(v) {
      if (!v.addr) return "";
      const g = parseV6(v.addr); if (!g) return { error: "Enter a valid IPv6 address." };
      const b0 = g[0];
      let type, extra = "";
      const allZeroButLast = g.slice(0, 7).every((x) => x === 0);
      if (allZeroButLast && g[7] === 0) type = "Unspecified (::)";
      else if (allZeroButLast && g[7] === 1) type = "Loopback (::1)";
      else if ((b0 & 0xffc0) === 0xfe80) type = "Link-local unicast (fe80::/10)";
      else if ((b0 & 0xfe00) === 0xfc00) { type = "Unique local (ULA, fc00::/7)"; extra = (b0 & 0x0100) ? "  L bit set (locally assigned, fd00::/8)" : "  L bit clear (fc00::/8, reserved)"; }
      else if ((b0 & 0xff00) === 0xff00) {
        const scopeNib = g[0] & 0xf, flags = (g[0] >> 4) & 0xf;
        const SCOPE = { 1: "interface-local", 2: "link-local", 4: "admin-local", 5: "site-local", 8: "organization-local", 14: "global" };
        type = `Multicast (ff00::/8)`; extra = `  flags=${flags.toString(2).padStart(4, "0")} scope=${scopeNib} (${SCOPE[scopeNib] || "?"})`;
        if (g[5] === 0x0001 && (g[6] >> 8) === 0xff) extra += "\nLooks like a solicited-node multicast (ff02::1:ffXX:XXXX).";
      }
      else if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) type = "IPv4-mapped (::ffff:0:0/96) -> " + `${g[6] >> 8}.${g[6] & 0xff}.${g[7] >> 8}.${g[7] & 0xff}`;
      else if (b0 === 0x2001 && g[1] === 0x0db8) type = "Documentation (2001:db8::/32, RFC 3849)";
      else if (b0 === 0x2001 && g[1] === 0x0000) type = "Teredo (2001:0::/32)";
      else if (b0 === 0x2002) type = "6to4 (2002::/16)";
      else if ((b0 & 0xe000) === 0x2000) type = "Global unicast (2000::/3)";
      else type = "Other / reserved";
      return `${v6expand(g)}\n${v6compress(g)}\nType: ${type}${extra}`;
    } },

  { id: "np-ipv6-solicited-node", name: "IPv6 Solicited-Node Multicast", cat: "netproto", desc: "Build the solicited-node multicast address (ff02::1:ffXX:XXXX) from an IPv6 unicast address — the group Neighbor Discovery listens on.", tags: ["ipv6", "multicast", "ndp", "solicited-node"],
    inputs: [{ k: "addr", label: "IPv6 unicast address", type: "text", placeholder: "fe80::2aa:ff:fe28:9c5a" }],
    run(v) {
      if (!v.addr) return "";
      const g = parseV6(v.addr); if (!g) return { error: "Enter a valid IPv6 address." };
      const last24hi = g[6] & 0xff, last16 = g[7];
      const sn = [0xff02, 0, 0, 0, 0, 0x0001, 0xff00 | last24hi, last16];
      return `Solicited-node: ${v6compress(sn)}\nFull: ${v6expand(sn)}\nMaps to Ethernet MAC: 33:33:ff:${last24hi.toString(16).padStart(2, "0")}:${(last16 >> 8).toString(16).padStart(2, "0")}:${(last16 & 0xff).toString(16).padStart(2, "0")}`;
    } },

  { id: "np-mac-bits", name: "MAC Address Bit Analyzer", cat: "netproto", desc: "Explain a MAC address's low-order bits: the I/G bit (unicast vs multicast), the U/L bit (globally unique vs locally administered) and broadcast detection.", tags: ["mac", "oui", "multicast", "locally administered"],
    inputs: [{ k: "mac", label: "MAC address", type: "text", placeholder: "02:00:00:00:00:01" }],
    run(v) {
      if (!v.mac) return "";
      const h = String(v.mac).replace(/[^0-9a-fA-F]/g, "");
      if (h.length !== 12) return { error: "Enter a 12-hex-digit MAC address." };
      const b = []; for (let i = 0; i < 6; i++) b.push(parseInt(h.substr(i * 2, 2), 16));
      const ig = b[0] & 1, ul = (b[0] >> 1) & 1;
      const broadcast = b.every((x) => x === 0xff);
      return [
        `Address: ${b.map((x) => x.toString(16).padStart(2, "0")).join(":")}`,
        `First octet: ${bin8(b[0])}`,
        `I/G bit (bit 0): ${ig} — ${ig ? "group/multicast (a frame to many)" : "individual/unicast"}`,
        `U/L bit (bit 1): ${ul} — ${ul ? "locally administered (not a real vendor OUI)" : "universally administered (vendor-assigned OUI)"}`,
        broadcast ? "This is the broadcast address ff:ff:ff:ff:ff:ff." : (ig && b[0] === 0x01 && b[1] === 0x00 && b[2] === 0x5e ? "IPv4 multicast MAC (01:00:5e range)." : ig && b[0] === 0x33 && b[1] === 0x33 ? "IPv6 multicast MAC (33:33 range)." : ""),
      ].filter(Boolean).join("\n");
    } },

  { id: "np-multicast-mac", name: "Multicast IP to MAC Mapper", cat: "netproto", desc: "Map an IPv4 or IPv6 multicast address to its Ethernet multicast MAC (IPv4 uses 01:00:5e + low 23 bits; IPv6 uses 33:33 + low 32 bits).", tags: ["multicast", "mac", "igmp", "mld"],
    inputs: [{ k: "addr", label: "Multicast IP", type: "text", placeholder: "239.255.255.250" }],
    run(v) {
      if (!v.addr) return "";
      if (v.addr.includes(":")) {
        const g = parseV6(v.addr); if (!g) return { error: "Enter a valid IPv6 address." };
        if ((g[0] & 0xff00) !== 0xff00) return { error: "Not an IPv6 multicast address (ff00::/8)." };
        const b = [0x33, 0x33, g[6] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff];
        return `Ethernet MAC: ${b.map((x) => x.toString(16).padStart(2, "0")).join(":")}\n(33:33 prefix + low 32 bits of the IPv6 address.)`;
      }
      const p = v.addr.split(".").map(Number);
      if (p.length !== 4 || p.some((x) => isNaN(x) || x < 0 || x > 255)) return { error: "Enter a valid IPv4 address." };
      if (p[0] < 224 || p[0] > 239) return { error: "Not an IPv4 multicast address (224.0.0.0/4)." };
      const low23 = (((p[1] & 0x7f) << 16) | (p[2] << 8) | p[3]);
      const b = [0x01, 0x00, 0x5e, (low23 >> 16) & 0xff, (low23 >> 8) & 0xff, low23 & 0xff];
      return `Ethernet MAC: ${b.map((x) => x.toString(16).padStart(2, "0")).join(":")}\n(01:00:5e prefix + low 23 bits; note 32 IPs share each MAC.)`;
    } },

  // ================= CALCULATORS =================
  { id: "np-asn-convert", name: "ASN asdot / asplain Converter", cat: "netproto", desc: "Convert a 4-byte Autonomous System Number between asplain (a single number) and asdot (high.low) notation, per RFC 5396.", tags: ["asn", "bgp", "asdot", "asplain"],
    inputs: [{ k: "asn", label: "ASN (asplain or asdot)", type: "text", placeholder: "65536 or 1.0" }],
    run(v) {
      const s = String(v.asn || "").trim(); if (!s) return "";
      let plain;
      if (s.includes(".")) { const p = s.split("."); if (p.length !== 2) return { error: "asdot is high.low, e.g. 1.0" }; const hi = parseInt(p[0], 10), lo = parseInt(p[1], 10); if (isNaN(hi) || isNaN(lo) || hi < 0 || hi > 65535 || lo < 0 || lo > 65535) return { error: "Each half must be 0-65535." }; plain = hi * 65536 + lo; }
      else { plain = parseInt(s, 10); if (isNaN(plain) || plain < 0 || plain > 4294967295) return { error: "ASN must be 0-4294967295." }; }
      const hi = Math.floor(plain / 65536), lo = plain % 65536;
      const asdot = hi === 0 ? String(lo) : `${hi}.${lo}`;
      return `asplain: ${plain}\nasdot:   ${asdot}\nasdot+:  ${hi}.${lo}\n${plain <= 65535 ? "(16-bit ASN)" : "(32-bit ASN)"}`;
    } },

  { id: "np-bgp-community", name: "BGP Community Formatter", cat: "netproto", desc: "Convert a BGP standard community between ASN:value and its 32-bit integer form, and recognize well-known communities (NO_EXPORT, NO_ADVERTISE). Also formats large communities.", tags: ["bgp", "community", "no-export", "routing"],
    inputs: [{ k: "val", label: "Community (ASN:value, N:N:N, or 32-bit int)", type: "text", placeholder: "65001:100" }],
    run(v) {
      const s = String(v.val || "").trim(); if (!s) return "";
      const WK = { 0xffffff01: "NO_EXPORT", 0xffffff02: "NO_ADVERTISE", 0xffffff03: "NO_EXPORT_SUBCONFED (LOCAL_AS)", 0xffffff04: "NO_PEER", 0xffff0000: "planned-shut (RFC 8326)", 0xffff029a: "BLACKHOLE" };
      const parts = s.split(":");
      if (parts.length === 3) { const n = parts.map((x) => parseInt(x, 10)); if (n.some((x) => isNaN(x) || x < 0 || x > 4294967295)) return { error: "Large community is three 32-bit numbers ASN:func:param." }; return `Large community: ${n[0]}:${n[1]}:${n[2]} (12 bytes)`; }
      if (parts.length === 2) { const hi = parseInt(parts[0], 10), lo = parseInt(parts[1], 10); if (isNaN(hi) || isNaN(lo) || hi < 0 || hi > 65535 || lo < 0 || lo > 65535) return { error: "Standard community is ASN:value with each 0-65535." }; const n = (hi * 65536 + lo) >>> 0; return `Standard community: ${hi}:${lo}\n32-bit value: ${n} (${hx(n, 8)})${WK[n] ? `\nWell-known: ${WK[n]}` : ""}`; }
      const n = parseInt(s, 10); if (isNaN(n) || n < 0 || n > 4294967295) return { error: "Enter ASN:value, N:N:N, or a 32-bit integer." };
      return `32-bit value: ${n} (${hx(n >>> 0, 8)})\nStandard community: ${Math.floor(n / 65536)}:${n % 65536}${WK[n >>> 0] ? `\nWell-known: ${WK[n >>> 0]}` : ""}`;
    } },

  { id: "np-mtu-mss", name: "MTU / MSS Calculator", cat: "netproto", desc: "Work out the TCP Maximum Segment Size from a link MTU (or back), subtracting the IPv4/IPv6 header and the TCP header plus any options.", tags: ["mtu", "mss", "tcp", "pmtud"],
    inputs: [
      { k: "mtu", label: "Link MTU (bytes)", type: "text", inputType: "number", placeholder: "1500" },
      { k: "ipver", label: "IP version", type: "select", opts: ["IPv4", "IPv6"], value: "IPv4" },
      { k: "tsopt", label: "TCP timestamps option (+12 bytes)", type: "checkbox", value: false },
    ],
    run(v) {
      const mtu = parseInt(v.mtu, 10); if (isNaN(mtu) || mtu < 68) return { error: "Enter an MTU of at least 68 bytes." };
      const iph = v.ipver === "IPv6" ? 40 : 20;
      const tcph = 20 + (v.tsopt ? 12 : 0);
      const mss = mtu - iph - tcph;
      return `MTU: ${mtu}\nIP header: ${iph} (${v.ipver})\nTCP header: ${tcph}${v.tsopt ? " (20 + 12 timestamps)" : ""}\nMSS: ${mss} bytes\n\n(Advertised MSS is MTU minus IP and TCP headers. PMTUD lowers this if a smaller MTU is on the path.)`;
    } },

  { id: "np-ipv4-fragment", name: "IPv4 Fragmentation Calculator", cat: "netproto", desc: "Given a total IP packet size and a path MTU, compute how it fragments: number of fragments, each one's size, fragment offset (in 8-byte units) and More-Fragments flag.", tags: ["ipv4", "fragmentation", "mtu", "offset"],
    inputs: [
      { k: "total", label: "Total IP packet size (bytes, incl. 20-byte header)", type: "text", inputType: "number", placeholder: "4000" },
      { k: "mtu", label: "Path MTU (bytes)", type: "text", inputType: "number", placeholder: "1500" },
    ],
    run(v) {
      const total = parseInt(v.total, 10), mtu = parseInt(v.mtu, 10);
      if (isNaN(total) || total < 21) return { error: "Total size must include the 20-byte header (>= 21)." };
      if (isNaN(mtu) || mtu < 28) return { error: "MTU must be at least 28 (20 header + 8 data)." };
      if (total <= mtu) return `Packet (${total} B) fits in MTU ${mtu} — no fragmentation (DF can be set).`;
      const payload = total - 20;
      const maxData = Math.floor((mtu - 20) / 8) * 8;
      const out = []; let off = 0, n = 0;
      while (off < payload) { const chunk = Math.min(maxData, payload - off); const mf = (off + chunk) < payload ? 1 : 0; out.push(`Frag ${++n}: ${20 + chunk} B total (data ${chunk})  offset=${off / 8} (byte ${off})  MF=${mf}`); off += chunk; if (n > 200) { out.push("..."); break; } }
      return `Payload ${payload} B, max ${maxData} B data/fragment -> ${n} fragments:\n` + out.join("\n");
    } },

  { id: "np-window-scale", name: "TCP Window Scale Calculator", cat: "netproto", desc: "Apply a TCP window scale factor: multiply the 16-bit window field by 2^shift to get the real receive window (and show the maximum).", tags: ["tcp", "window", "scaling", "throughput"],
    inputs: [
      { k: "win", label: "Window field value (0-65535)", type: "text", inputType: "number", placeholder: "8192" },
      { k: "shift", label: "Window scale shift (0-14)", type: "range", min: 0, max: 14, step: 1, value: 7 },
    ],
    run(v) {
      const win = parseInt(v.win, 10), shift = parseInt(v.shift, 10);
      if (isNaN(win) || win < 0 || win > 65535) return { error: "Window value must be 0-65535." };
      if (isNaN(shift) || shift < 0 || shift > 14) return { error: "Shift must be 0-14 (RFC 7323 max)." };
      const real = win * Math.pow(2, shift);
      return `Window field: ${win}\nScale: shift ${shift} (x${Math.pow(2, shift)})\nEffective window: ${real.toLocaleString()} bytes\nMax possible at this shift: ${(65535 * Math.pow(2, shift)).toLocaleString()} bytes`;
    } },

  { id: "np-bandwidth-time", name: "Transfer Time Calculator", cat: "netproto", desc: "Estimate how long it takes to move a given amount of data at a given link rate, accounting for bits-vs-bytes and decimal (Mbps) units.", tags: ["bandwidth", "throughput", "transfer", "time"],
    inputs: [
      { k: "size", label: "Data size", type: "text", inputType: "number", placeholder: "10" },
      { k: "sizeUnit", label: "Size unit", type: "select", opts: ["GB", "MB", "KB", "GiB", "MiB", "Mb", "Gb"], value: "GB" },
      { k: "rate", label: "Link rate", type: "text", inputType: "number", placeholder: "100" },
      { k: "rateUnit", label: "Rate unit", type: "select", opts: ["Mbps", "Gbps", "Kbps", "MB/s", "GB/s"], value: "Mbps" },
    ],
    run(v) {
      const size = parseFloat(v.size), rate = parseFloat(v.rate);
      if (isNaN(size) || size <= 0) return { error: "Enter a positive data size." };
      if (isNaN(rate) || rate <= 0) return { error: "Enter a positive link rate." };
      const SB = { GB: 8e9, MB: 8e6, KB: 8e3, GiB: 8 * 2 ** 30, MiB: 8 * 2 ** 20, Mb: 1e6, Gb: 1e9 };
      const RB = { Mbps: 1e6, Gbps: 1e9, Kbps: 1e3, "MB/s": 8e6, "GB/s": 8e9 };
      const bits = size * SB[v.sizeUnit];
      const bps = rate * RB[v.rateUnit];
      const secs = bits / bps;
      const fmt = (s) => s < 1 ? `${(s * 1000).toFixed(1)} ms` : s < 90 ? `${s.toFixed(2)} s` : s < 5400 ? `${(s / 60).toFixed(2)} min` : `${(s / 3600).toFixed(2)} h`;
      return `Data: ${bits.toLocaleString()} bits\nRate: ${bps.toLocaleString()} bits/s\nIdeal transfer time: ${fmt(secs)}\n\n(Theoretical minimum at 100% efficiency; real transfers are slower due to protocol overhead, latency and loss.)`;
    } },

  { id: "np-propagation-delay", name: "Propagation Delay Calculator", cat: "netproto", desc: "Estimate the one-way and round-trip propagation delay over a distance, using the signal velocity in fiber, copper or free space (radio).", tags: ["latency", "rtt", "propagation", "fiber"],
    inputs: [
      { k: "dist", label: "Distance (km)", type: "text", inputType: "number", placeholder: "1000" },
      { k: "medium", label: "Medium", type: "select", opts: ["Fiber (n~1.47)", "Copper (VF 0.66)", "Free space / radio (c)"], value: "Fiber (n~1.47)" },
    ],
    run(v) {
      const dist = parseFloat(v.dist); if (isNaN(dist) || dist <= 0) return { error: "Enter a positive distance in km." };
      const c = 299792.458; // km/s
      const vel = v.medium.startsWith("Fiber") ? c / 1.4682 : v.medium.startsWith("Copper") ? c * 0.66 : c;
      const oneWay = dist / vel; // seconds
      const ms = (x) => (x * 1000).toFixed(3) + " ms";
      return `Signal velocity: ${Math.round(vel).toLocaleString()} km/s (${v.medium})\nOne-way delay: ${ms(oneWay)}\nRound-trip (RTT): ${ms(oneWay * 2)}\n\n(Propagation only — switching, queuing and serialization add more. Approximate.)`;
    } },

  { id: "np-ntp-timestamp", name: "NTP Timestamp Converter", cat: "netproto", desc: "Convert between a 64-bit NTP timestamp (hex, seconds since 1900) and a human date/time, and back from an ISO date.", tags: ["ntp", "timestamp", "time", "epoch"],
    inputs: [{ k: "val", label: "NTP 64-bit hex, or ISO date", type: "text", placeholder: "e5f20a8e.00000000 or 2024-01-01T00:00:00Z" }],
    run(v) {
      const s = String(v.val || "").trim(); if (!s) return "";
      const NTP_EPOCH = 2208988800; // seconds between 1900 and 1970
      const hexClean = s.replace(/^0x/i, "").replace(/[.\s_]/g, "");
      if (/^[0-9a-fA-F]+$/.test(hexClean) && (hexClean.length === 8 || hexClean.length === 16) && !/[g-su-yG-SU-Y:/]/.test(s.replace(/^0x/i, ""))) {
        const secs = parseInt(hexClean.slice(0, 8), 16);
        const fracHex = hexClean.length === 16 ? hexClean.slice(8) : "00000000";
        const frac = parseInt(fracHex, 16) / 0x100000000;
        const unix = secs - NTP_EPOCH + frac;
        if (unix < -62135596800) return { error: "Timestamp out of range." };
        return `NTP seconds: ${secs}\nFraction: ${frac.toFixed(9)} s\nUnix time: ${unix.toFixed(6)}\nUTC: ${new Date(unix * 1000).toISOString()}`;
      }
      const d = new Date(s);
      if (isNaN(d.getTime())) return { error: "Enter 8/16 hex digits, or an ISO date like 2024-01-01T00:00:00Z." };
      const unix = d.getTime() / 1000;
      const ntpSec = Math.floor(unix + NTP_EPOCH);
      const frac = Math.round((unix + NTP_EPOCH - ntpSec) * 0x100000000) >>> 0;
      return `UTC: ${d.toISOString()}\nNTP seconds: ${ntpSec} (${hx(ntpSec, 8)})\nNTP 64-bit: ${hx(ntpSec, 8).slice(2)}.${frac.toString(16).padStart(8, "0")}`;
    } },

  { id: "np-syslog-pri", name: "Syslog Priority (PRI) Decoder", cat: "netproto", desc: "Decode a syslog PRI value (as in <134>) into its facility and severity, or build the PRI from a facility and severity.", tags: ["syslog", "facility", "severity", "rfc5424"],
    inputs: [
      { k: "mode", label: "Mode", type: "select", opts: ["PRI -> facility+severity", "facility+severity -> PRI"], value: "PRI -> facility+severity" },
      { k: "pri", label: "PRI value (for decode)", type: "text", inputType: "number", placeholder: "134" },
      { k: "facility", label: "Facility (for encode, 0-23)", type: "text", inputType: "number", placeholder: "16" },
      { k: "severity", label: "Severity (for encode, 0-7)", type: "text", inputType: "number", placeholder: "6" },
    ],
    run(v) {
      const FAC = { 0: "kernel", 1: "user", 2: "mail", 3: "daemon", 4: "auth/security", 5: "syslogd", 6: "line printer", 7: "news", 8: "uucp", 9: "clock/cron", 10: "authpriv", 11: "ftp", 12: "ntp", 13: "log audit", 14: "log alert", 15: "clock", 16: "local0", 17: "local1", 18: "local2", 19: "local3", 20: "local4", 21: "local5", 22: "local6", 23: "local7" };
      const SEV = ["0 Emergency", "1 Alert", "2 Critical", "3 Error", "4 Warning", "5 Notice", "6 Informational", "7 Debug"];
      if (v.mode === "facility+severity -> PRI") {
        const f = parseInt(v.facility, 10), s = parseInt(v.severity, 10);
        if (isNaN(f) || f < 0 || f > 23) return { error: "Facility is 0-23." };
        if (isNaN(s) || s < 0 || s > 7) return { error: "Severity is 0-7." };
        return `PRI = facility*8 + severity = ${f}*8 + ${s} = ${f * 8 + s}\nWire: <${f * 8 + s}>`;
      }
      const pri = parseInt(v.pri, 10); if (isNaN(pri) || pri < 0 || pri > 191) return { error: "PRI is 0-191." };
      const f = pri >> 3, s = pri & 7;
      return `PRI ${pri} = <${pri}>\nFacility: ${f} (${FAC[f]})\nSeverity: ${SEV[s]}`;
    } },

  // ================= REFERENCE TABLES =================
  { id: "np-ip-protocols", name: "IP Protocol Number Reference", cat: "netproto", desc: "Look up the IANA IP protocol number carried in the IPv4 Protocol / IPv6 Next Header field (6 TCP, 17 UDP, 1 ICMP, 47 GRE, 50 ESP, ...).", tags: ["ip", "protocol", "iana", "next header"],
    inputs: [{ k: "q", label: "Search number or name (blank = all)", type: "text", placeholder: "gre" }],
    run(v) { return refTable(IP_PROTOCOLS, v.q, ([k, val]) => `${k} — ${val}`); } },

  { id: "np-ethertypes", name: "EtherType Reference", cat: "netproto", desc: "Look up the EtherType in an Ethernet II frame (0x0800 IPv4, 0x0806 ARP, 0x86DD IPv6, 0x8100 VLAN, 0x88CC LLDP, ...).", tags: ["ethernet", "ethertype", "frame"],
    inputs: [{ k: "q", label: "Search hex or name (blank = all)", type: "text", placeholder: "arp" }],
    run(v) {
      const ET = { "0x0800": "IPv4", "0x0806": "ARP", "0x0842": "Wake-on-LAN", "0x22F3": "TRILL", "0x8035": "Reverse ARP (RARP)", "0x809B": "AppleTalk (EtherTalk)", "0x80F3": "AppleTalk ARP (AARP)", "0x8100": "IEEE 802.1Q VLAN tag", "0x86DD": "IPv6", "0x8808": "Ethernet flow control (PAUSE)", "0x8809": "Slow Protocols (LACP)", "0x8847": "MPLS unicast", "0x8848": "MPLS multicast", "0x8863": "PPPoE Discovery", "0x8864": "PPPoE Session", "0x888E": "IEEE 802.1X (EAPOL)", "0x88A8": "IEEE 802.1ad QinQ (S-tag)", "0x88CC": "LLDP", "0x88E5": "IEEE 802.1AE MACsec", "0x88F7": "Precision Time Protocol (PTP)", "0x8906": "Fibre Channel over Ethernet (FCoE)", "0x9000": "Ethernet Configuration Testing (loopback)" };
      return refTable(ET, v.q);
    } },

  { id: "np-icmp-types", name: "ICMPv4 Type / Code Reference", cat: "netproto", desc: "Look up ICMP (IPv4) message types and their codes: Echo, Destination Unreachable (with code meanings), Time Exceeded, Redirect and more.", tags: ["icmp", "ping", "unreachable", "type", "code"],
    inputs: [{ k: "q", label: "Search type number or name (blank = all)", type: "text", placeholder: "unreachable" }],
    run(v) {
      const T = {
        "0": "Echo Reply", "3": "Destination Unreachable — code 0 net, 1 host, 2 protocol, 3 port, 4 fragmentation needed & DF set, 5 source route failed, 6 dest network unknown, 7 dest host unknown, 9/10 admin prohibited, 13 communication admin prohibited",
        "4": "Source Quench (deprecated)", "5": "Redirect — code 0 for network, 1 for host, 2 for ToS+network, 3 for ToS+host",
        "8": "Echo Request (ping)", "9": "Router Advertisement", "10": "Router Solicitation",
        "11": "Time Exceeded — code 0 TTL expired in transit, 1 fragment reassembly time exceeded",
        "12": "Parameter Problem — code 0 pointer indicates error, 1 missing required option, 2 bad length",
        "13": "Timestamp Request", "14": "Timestamp Reply", "17": "Address Mask Request", "18": "Address Mask Reply",
      };
      return refTable(T, v.q);
    } },

  { id: "np-icmpv6-types", name: "ICMPv6 Type / Code Reference", cat: "netproto", desc: "Look up ICMPv6 message types including the Neighbor Discovery messages (Router/Neighbor Solicitation and Advertisement) and MLD.", tags: ["icmpv6", "ndp", "neighbor discovery", "mld"],
    inputs: [{ k: "q", label: "Search type number or name (blank = all)", type: "text", placeholder: "neighbor" }],
    run(v) {
      const T = {
        "1": "Destination Unreachable — code 0 no route, 1 admin prohibited, 2 beyond scope, 3 address unreachable, 4 port unreachable",
        "2": "Packet Too Big (carries the MTU)", "3": "Time Exceeded — code 0 hop limit, 1 fragment reassembly",
        "4": "Parameter Problem — code 0 erroneous header, 1 unrecognized next header, 2 unrecognized option",
        "128": "Echo Request", "129": "Echo Reply", "130": "Multicast Listener Query (MLD)", "131": "Multicast Listener Report (MLDv1)", "132": "Multicast Listener Done",
        "133": "Router Solicitation (NDP)", "134": "Router Advertisement (NDP)", "135": "Neighbor Solicitation (NDP)", "136": "Neighbor Advertisement (NDP)", "137": "Redirect (NDP)", "143": "Multicast Listener Report (MLDv2)",
      };
      return refTable(T, v.q);
    } },

  { id: "np-dns-rcodes", name: "DNS Opcode / RCODE Reference", cat: "netproto", desc: "Look up DNS header opcodes (QUERY, NOTIFY, UPDATE) and response codes / RCODEs (NOERROR, NXDOMAIN, SERVFAIL, REFUSED, including EDNS extended codes).", tags: ["dns", "rcode", "opcode", "nxdomain", "servfail"],
    inputs: [{ k: "q", label: "Search (blank = all)", type: "text", placeholder: "nxdomain" }],
    run(v) {
      const T = {
        "Opcode 0": "QUERY — standard query", "Opcode 1": "IQUERY — inverse query (obsolete)", "Opcode 2": "STATUS — server status request", "Opcode 4": "NOTIFY — zone change notification", "Opcode 5": "UPDATE — dynamic update", "Opcode 6": "DSO — DNS Stateful Operations",
        "RCODE 0": "NOERROR — no error", "RCODE 1": "FORMERR — format error", "RCODE 2": "SERVFAIL — server failure", "RCODE 3": "NXDOMAIN — non-existent domain", "RCODE 4": "NOTIMP — not implemented", "RCODE 5": "REFUSED — query refused", "RCODE 6": "YXDOMAIN — name exists when it should not", "RCODE 7": "YXRRSET — RR set exists when it should not", "RCODE 8": "NXRRSET — RR set does not exist", "RCODE 9": "NOTAUTH — server not authoritative / not authorized", "RCODE 10": "NOTZONE — name not in zone",
        "RCODE 16": "BADVERS / BADSIG — bad EDNS version or TSIG signature", "RCODE 17": "BADKEY — key not recognized", "RCODE 18": "BADTIME — signature out of time window", "RCODE 23": "BADCOOKIE — bad/missing server cookie",
      };
      return refTable(T, v.q);
    } },

  { id: "np-dns-type-codes", name: "DNS Record Type Codes", cat: "netproto", desc: "Numeric DNS resource-record TYPE codes used on the wire (1 A, 28 AAAA, 15 MX, 16 TXT, 257 CAA, 65 HTTPS, ...) — the numbers a packet decoder needs.", tags: ["dns", "type", "code", "rrtype", "wire"],
    inputs: [{ k: "q", label: "Search code or mnemonic (blank = all)", type: "text", placeholder: "aaaa" }],
    run(v) { return refTable(DNS_TYPE_CODES, v.q, ([k, val]) => `${k} — ${val}`); } },

  { id: "np-dhcp-options", name: "DHCP Option Reference", cat: "netproto", desc: "Look up BOOTP/DHCP option codes (1 Subnet Mask, 3 Router, 6 DNS, 51 Lease Time, 53 Message Type, 55 Parameter Request List, ...).", tags: ["dhcp", "bootp", "option", "rfc2132"],
    inputs: [{ k: "q", label: "Search code or name (blank = all)", type: "text", placeholder: "lease" }],
    run(v) {
      const T = { "0": "Pad", "1": "Subnet Mask", "3": "Router (default gateway)", "6": "Domain Name Server", "12": "Host Name", "15": "Domain Name", "26": "Interface MTU", "28": "Broadcast Address", "42": "NTP Servers", "43": "Vendor-Specific Information", "44": "NetBIOS Name Server", "50": "Requested IP Address", "51": "IP Address Lease Time", "53": "DHCP Message Type", "54": "Server Identifier", "55": "Parameter Request List", "56": "Message", "57": "Maximum DHCP Message Size", "58": "Renewal Time (T1)", "59": "Rebinding Time (T2)", "60": "Vendor Class Identifier", "61": "Client Identifier", "66": "TFTP Server Name", "67": "Bootfile Name", "81": "Client FQDN", "82": "Relay Agent Information", "118": "Subnet Selection", "119": "Domain Search List", "121": "Classless Static Route", "255": "End" };
      return refTable(T, v.q);
    } },

  { id: "np-dhcp-message-types", name: "DHCP Message Type Reference", cat: "netproto", desc: "Look up the DHCP message types carried in option 53 (DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, ...).", tags: ["dhcp", "message type", "option 53", "dora"],
    inputs: [{ k: "q", label: "Search number or name (blank = all)", type: "text", placeholder: "discover" }],
    run(v) {
      const T = { "1": "DHCPDISCOVER — client broadcasts to find servers", "2": "DHCPOFFER — server offers an address", "3": "DHCPREQUEST — client requests/renews an offered address", "4": "DHCPDECLINE — client rejects (address already in use)", "5": "DHCPACK — server confirms the lease", "6": "DHCPNAK — server refuses/invalidates", "7": "DHCPRELEASE — client gives up its lease", "8": "DHCPINFORM — client has an IP, wants config only", "9": "DHCPFORCERENEW — server forces a renew", "10": "DHCPLEASEQUERY", "13": "DHCPLEASEACTIVE" };
      return refTable(T, v.q);
    } },

  { id: "np-dhcpv6-message-types", name: "DHCPv6 Message Type Reference", cat: "netproto", desc: "Look up DHCPv6 message types (SOLICIT, ADVERTISE, REQUEST, REPLY, RENEW, RELAY-FORW, ...) — distinct from DHCPv4.", tags: ["dhcpv6", "ipv6", "message type"],
    inputs: [{ k: "q", label: "Search number or name (blank = all)", type: "text", placeholder: "solicit" }],
    run(v) {
      const T = { "1": "SOLICIT", "2": "ADVERTISE", "3": "REQUEST", "4": "CONFIRM", "5": "RENEW", "6": "REBIND", "7": "REPLY", "8": "RELEASE", "9": "DECLINE", "10": "RECONFIGURE", "11": "INFORMATION-REQUEST", "12": "RELAY-FORW", "13": "RELAY-REPL" };
      return refTable(T, v.q);
    } },

  { id: "np-http2-frames", name: "HTTP/2 Frame Type Reference", cat: "netproto", desc: "Look up HTTP/2 frame types (0 DATA, 1 HEADERS, 4 SETTINGS, 6 PING, 7 GOAWAY, 8 WINDOW_UPDATE, ...) from RFC 9113.", tags: ["http2", "frame", "h2"],
    inputs: [{ k: "q", label: "Search number or name (blank = all)", type: "text", placeholder: "settings" }],
    run(v) {
      const T = { "0x0": "DATA — message body", "0x1": "HEADERS — header block (opens a stream)", "0x2": "PRIORITY — stream priority", "0x3": "RST_STREAM — abort a stream", "0x4": "SETTINGS — connection parameters", "0x5": "PUSH_PROMISE — server push announcement", "0x6": "PING — liveness / RTT", "0x7": "GOAWAY — stop creating streams / shut down", "0x8": "WINDOW_UPDATE — flow-control credit", "0x9": "CONTINUATION — more header block fragments" };
      return refTable(T, v.q);
    } },

  { id: "np-http2-settings", name: "HTTP/2 SETTINGS Reference", cat: "netproto", desc: "Look up HTTP/2 SETTINGS parameters (HEADER_TABLE_SIZE, ENABLE_PUSH, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, ...).", tags: ["http2", "settings", "flow control"],
    inputs: [{ k: "q", label: "Search id or name (blank = all)", type: "text", placeholder: "window" }],
    run(v) {
      const T = { "0x1": "HEADER_TABLE_SIZE — HPACK dynamic table size (default 4096)", "0x2": "ENABLE_PUSH — allow server push (default 1)", "0x3": "MAX_CONCURRENT_STREAMS — limit of open streams", "0x4": "INITIAL_WINDOW_SIZE — per-stream flow-control window (default 65535)", "0x5": "MAX_FRAME_SIZE — largest frame payload (default 16384)", "0x6": "MAX_HEADER_LIST_SIZE — advisory header size limit" };
      return refTable(T, v.q);
    } },

  { id: "np-http2-errors", name: "HTTP/2 Error Code Reference", cat: "netproto", desc: "Look up HTTP/2 error codes used in RST_STREAM and GOAWAY (PROTOCOL_ERROR, FLOW_CONTROL_ERROR, REFUSED_STREAM, ENHANCE_YOUR_CALM, ...).", tags: ["http2", "error", "goaway", "rst_stream"],
    inputs: [{ k: "q", label: "Search code or name (blank = all)", type: "text", placeholder: "refused" }],
    run(v) {
      const T = { "0x0": "NO_ERROR — graceful shutdown", "0x1": "PROTOCOL_ERROR", "0x2": "INTERNAL_ERROR", "0x3": "FLOW_CONTROL_ERROR", "0x4": "SETTINGS_TIMEOUT", "0x5": "STREAM_CLOSED", "0x6": "FRAME_SIZE_ERROR", "0x7": "REFUSED_STREAM — not processed, safe to retry", "0x8": "CANCEL", "0x9": "COMPRESSION_ERROR — HPACK state broken", "0xa": "CONNECT_ERROR", "0xb": "ENHANCE_YOUR_CALM — too much load", "0xc": "INADEQUATE_SECURITY", "0xd": "HTTP_1_1_REQUIRED" };
      return refTable(T, v.q);
    } },

  { id: "np-tls-record-types", name: "TLS Record Type Reference", cat: "netproto", desc: "Look up TLS record content types (20 ChangeCipherSpec, 21 Alert, 22 Handshake, 23 ApplicationData, 24 Heartbeat).", tags: ["tls", "record", "content type"],
    inputs: [{ k: "q", label: "Search number or name (blank = all)", type: "text", placeholder: "handshake" }],
    run(v) {
      const T = { "20": "ChangeCipherSpec", "21": "Alert", "22": "Handshake", "23": "ApplicationData", "24": "Heartbeat (RFC 6520)" };
      return refTable(T, v.q);
    } },

  { id: "np-tls-handshake-types", name: "TLS Handshake Type Reference", cat: "netproto", desc: "Look up TLS handshake message types for TLS 1.2 and 1.3 (ClientHello, ServerHello, EncryptedExtensions, Certificate, Finished, KeyUpdate, ...).", tags: ["tls", "handshake", "clienthello"],
    inputs: [{ k: "q", label: "Search number or name (blank = all)", type: "text", placeholder: "clienthello" }],
    run(v) {
      const T = { "0": "hello_request (TLS 1.2)", "1": "client_hello", "2": "server_hello", "3": "hello_verify_request (DTLS)", "4": "new_session_ticket", "5": "end_of_early_data (1.3)", "8": "encrypted_extensions (1.3)", "11": "certificate", "12": "server_key_exchange (1.2)", "13": "certificate_request", "14": "server_hello_done (1.2)", "15": "certificate_verify", "16": "client_key_exchange (1.2)", "20": "finished", "24": "key_update (1.3)", "25": "compressed_certificate", "254": "message_hash (1.3)" };
      return refTable(T, v.q);
    } },

  { id: "np-tls-extensions", name: "TLS Extension Reference", cat: "netproto", desc: "Look up TLS extension types seen in ClientHello/ServerHello (0 server_name/SNI, 10 supported_groups, 13 signature_algorithms, 16 ALPN, 43 supported_versions, 51 key_share, ...).", tags: ["tls", "extension", "sni", "alpn", "key_share"],
    inputs: [{ k: "q", label: "Search number or name (blank = all)", type: "text", placeholder: "sni" }],
    run(v) {
      const T = { "0": "server_name (SNI)", "1": "max_fragment_length", "5": "status_request (OCSP stapling)", "10": "supported_groups (curves)", "11": "ec_point_formats", "13": "signature_algorithms", "14": "use_srtp", "15": "heartbeat", "16": "application_layer_protocol_negotiation (ALPN)", "18": "signed_certificate_timestamp (SCT)", "21": "padding", "22": "encrypt_then_mac", "23": "extended_master_secret", "35": "session_ticket", "41": "pre_shared_key (1.3)", "42": "early_data (1.3)", "43": "supported_versions (1.3)", "44": "cookie", "45": "psk_key_exchange_modes (1.3)", "47": "certificate_authorities", "50": "signature_algorithms_cert", "51": "key_share (1.3)", "65281": "renegotiation_info" };
      return refTable(T, v.q, ([k, val]) => `${k} (${hx(Number(k), Number(k) > 255 ? 4 : 2)}) — ${val}`);
    } },

  { id: "np-tls-alerts", name: "TLS Alert Reference", cat: "netproto", desc: "Look up TLS alert descriptions and what triggers them (close_notify, bad_record_mac, handshake_failure, unknown_ca, protocol_version, ...).", tags: ["tls", "alert", "handshake_failure"],
    inputs: [{ k: "q", label: "Search number or name (blank = all)", type: "text", placeholder: "handshake" }],
    run(v) {
      const T = { "0": "close_notify — clean shutdown", "10": "unexpected_message", "20": "bad_record_mac — decryption/MAC failed", "22": "record_overflow", "40": "handshake_failure — no acceptable parameters", "42": "bad_certificate", "43": "unsupported_certificate", "44": "certificate_revoked", "45": "certificate_expired", "46": "certificate_unknown", "47": "illegal_parameter", "48": "unknown_ca — cannot verify cert chain", "49": "access_denied", "50": "decode_error", "51": "decrypt_error", "70": "protocol_version — version not supported", "71": "insufficient_security", "80": "internal_error", "86": "inappropriate_fallback", "90": "user_canceled", "109": "missing_extension", "110": "unsupported_extension", "112": "unrecognized_name (SNI)", "116": "certificate_required", "120": "no_application_protocol (ALPN)" };
      return refTable(T, v.q);
    } },

  { id: "np-tcp-options", name: "TCP Option Kind Reference", cat: "netproto", desc: "Look up TCP option kinds (0 EOL, 1 NOP, 2 MSS, 3 Window Scale, 4 SACK permitted, 5 SACK, 8 Timestamps, ...).", tags: ["tcp", "option", "mss", "sack", "timestamps"],
    inputs: [{ k: "q", label: "Search kind or name (blank = all)", type: "text", placeholder: "sack" }],
    run(v) {
      const T = { "0": "End of Option List (EOL)", "1": "No-Operation (NOP) — padding/alignment", "2": "Maximum Segment Size (MSS)", "3": "Window Scale", "4": "SACK Permitted", "5": "SACK (selective acknowledgment blocks)", "8": "Timestamps (TSval/TSecr)", "28": "User Timeout", "29": "TCP Authentication Option (TCP-AO)", "34": "TCP Fast Open Cookie" };
      return refTable(T, v.q);
    } },

  { id: "np-tcp-states", name: "TCP Connection State Reference", cat: "netproto", desc: "Explain the TCP state machine states (LISTEN, SYN-SENT, ESTABLISHED, FIN-WAIT-1/2, TIME-WAIT, CLOSE-WAIT, ...) and what each means.", tags: ["tcp", "state", "time-wait", "handshake"],
    inputs: [{ k: "q", label: "Search a state (blank = all)", type: "text", placeholder: "time-wait" }],
    run(v) {
      const T = { "CLOSED": "No connection. The starting and ending point.", "LISTEN": "Server waiting for an incoming SYN.", "SYN-SENT": "Client sent SYN, waiting for SYN-ACK.", "SYN-RECEIVED": "Got a SYN, sent SYN-ACK, waiting for the final ACK.", "ESTABLISHED": "Open connection; data can flow both ways.", "FIN-WAIT-1": "Sent a FIN, waiting for ACK or the peer's FIN.", "FIN-WAIT-2": "Our FIN was ACKed; waiting for the peer's FIN.", "CLOSE-WAIT": "Peer sent FIN; waiting for the local app to close.", "CLOSING": "Both sides sent FIN at the same time.", "LAST-ACK": "Sent our FIN after CLOSE-WAIT; waiting for its ACK.", "TIME-WAIT": "Waiting 2*MSL so old duplicate packets die before reuse." };
      return refTable(T, v.q, ([k, val]) => `${k}: ${val}`);
    } },

  { id: "np-dscp-reference", name: "DSCP / DiffServ Reference", cat: "netproto", desc: "Convert between a DiffServ Code Point name (CS, AF, EF, default) and its 6-bit value, or look up by number. Shows the value and binary.", tags: ["dscp", "diffserv", "qos", "ef", "af"],
    inputs: [{ k: "q", label: "Name (e.g. EF, AF31) or value (0-63), blank = all", type: "text", placeholder: "EF" }],
    run(v) {
      const T = { "CS0 / Default": 0, "CS1": 8, "CS2": 16, "CS3": 24, "CS4": 32, "CS5": 40, "CS6": 48, "CS7": 56, "AF11": 10, "AF12": 12, "AF13": 14, "AF21": 18, "AF22": 20, "AF23": 22, "AF31": 26, "AF32": 28, "AF33": 30, "AF41": 34, "AF42": 36, "AF43": 38, "EF (Expedited Forwarding)": 46, "VA (Voice-Admit)": 44 };
      const q = String(v.q || "").trim();
      if (!q) return Object.entries(T).map(([k, val]) => `${k} = ${val} (${val.toString(2).padStart(6, "0")})`).join("\n");
      const num = parseInt(q, 10);
      if (!isNaN(num) && String(num) === q) { const hit = Object.entries(T).find(([, val]) => val === num); if (num < 0 || num > 63) return { error: "DSCP is 0-63." }; return `Value ${num} (${num.toString(2).padStart(6, "0")})${hit ? ` = ${hit[0]}` : " = (no standard name)"}`; }
      const hit = Object.entries(T).find(([k]) => k.toLowerCase().startsWith(q.toLowerCase()));
      if (!hit) return { error: `No DSCP name matching "${q}".` };
      return `${hit[0]} = ${hit[1]} (${hit[1].toString(2).padStart(6, "0")})`;
    } },

  { id: "np-snmp-oids", name: "SNMP OID Reference", cat: "netproto", desc: "Look up common SNMP / MIB-II object identifiers (sysDescr, sysUpTime, sysName, ifInOctets, ...) with their dotted OIDs.", tags: ["snmp", "oid", "mib", "monitoring"],
    inputs: [{ k: "q", label: "Search name or OID (blank = all)", type: "text", placeholder: "uptime" }],
    run(v) {
      const T = { "sysDescr": "1.3.6.1.2.1.1.1 — system description string", "sysObjectID": "1.3.6.1.2.1.1.2 — vendor object ID", "sysUpTime": "1.3.6.1.2.1.1.3 — time since agent restarted (centiseconds)", "sysContact": "1.3.6.1.2.1.1.4 — admin contact", "sysName": "1.3.6.1.2.1.1.5 — device hostname", "sysLocation": "1.3.6.1.2.1.1.6 — physical location", "sysServices": "1.3.6.1.2.1.1.7 — layers offered", "ifNumber": "1.3.6.1.2.1.2.1 — number of interfaces", "ifDescr": "1.3.6.1.2.1.2.2.1.2 — interface name (per-index)", "ifType": "1.3.6.1.2.1.2.2.1.3 — interface type", "ifSpeed": "1.3.6.1.2.1.2.2.1.5 — interface bits/sec", "ifOperStatus": "1.3.6.1.2.1.2.2.1.8 — up(1)/down(2)/testing(3)", "ifInOctets": "1.3.6.1.2.1.2.2.1.10 — bytes received", "ifOutOctets": "1.3.6.1.2.1.2.2.1.16 — bytes sent", "ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6 — 64-bit bytes received", "hrSystemUptime": "1.3.6.1.2.1.25.1.1 — host system uptime" };
      return refTable(T, v.q, ([k, val]) => `${k}: ${val}`);
    } },

  { id: "np-snmp-pdu-types", name: "SNMP PDU / Version Reference", cat: "netproto", desc: "Look up SNMP protocol versions and PDU types (GetRequest 0xA0, GetNextRequest 0xA1, Response 0xA2, SetRequest 0xA3, Trap/InformRequest, ...).", tags: ["snmp", "pdu", "trap", "getbulk"],
    inputs: [{ k: "q", label: "Search (blank = all)", type: "text", placeholder: "trap" }],
    run(v) {
      const T = { "Version 0": "SNMPv1", "Version 1": "SNMPv2c", "Version 3": "SNMPv3", "PDU 0xA0": "GetRequest", "PDU 0xA1": "GetNextRequest", "PDU 0xA2": "Response (GetResponse)", "PDU 0xA3": "SetRequest", "PDU 0xA4": "Trap (SNMPv1)", "PDU 0xA5": "GetBulkRequest (v2c+)", "PDU 0xA6": "InformRequest", "PDU 0xA7": "SNMPv2-Trap", "PDU 0xA8": "Report (v3)" };
      return refTable(T, v.q);
    } },

  { id: "np-well-known-multicast", name: "Well-Known Multicast Reference", cat: "netproto", desc: "Look up reserved multicast groups for IPv4 (224.0.0.x link-local, mDNS, SSDP) and IPv6 (ff02::1 all-nodes, ff02::2 all-routers, ...).", tags: ["multicast", "mdns", "ssdp", "all-nodes", "ospf"],
    inputs: [{ k: "q", label: "Search address or name (blank = all)", type: "text", placeholder: "mdns" }],
    run(v) {
      const T = { "224.0.0.1": "All Hosts (link-local)", "224.0.0.2": "All Routers (link-local)", "224.0.0.5": "OSPF All Routers", "224.0.0.6": "OSPF Designated Routers", "224.0.0.9": "RIPv2", "224.0.0.13": "PIM", "224.0.0.18": "VRRP", "224.0.0.22": "IGMPv3", "224.0.0.102": "HSRPv2 / GLBP", "224.0.0.251": "mDNS (Bonjour)", "224.0.0.252": "LLMNR", "224.0.1.1": "NTP", "239.255.255.250": "SSDP (UPnP discovery)", "ff02::1": "All Nodes (link-local)", "ff02::2": "All Routers (link-local)", "ff02::5": "OSPFv3 All Routers", "ff02::6": "OSPFv3 Designated Routers", "ff02::9": "RIPng", "ff02::a": "EIGRP", "ff02::d": "PIM", "ff02::16": "MLDv2", "ff02::1:2": "All DHCPv6 relay agents/servers", "ff02::fb": "mDNS (IPv6)", "ff02::1:3": "LLMNR (IPv6)" };
      return refTable(T, v.q);
    } },

  { id: "np-linktype", name: "pcap Link-Layer Type Reference", cat: "netproto", desc: "Look up libpcap/PCAP link-layer header types (LINKTYPE/DLT): 0 NULL, 1 Ethernet, 101 Raw IP, 105 802.11, 113 Linux cooked, 127 radiotap, ...", tags: ["pcap", "linktype", "dlt", "capture"],
    inputs: [{ k: "q", label: "Search number or name (blank = all)", type: "text", placeholder: "ethernet" }],
    run(v) {
      const T = { "0": "NULL / LOOP — BSD loopback (4-byte AF_ family)", "1": "ETHERNET (EN10MB)", "6": "IEEE 802.5 Token Ring", "8": "SLIP", "9": "PPP", "10": "FDDI", "50": "PPP over HDLC (PPP_SERIAL)", "101": "RAW — raw IP, no link header", "104": "C-HDLC (Cisco HDLC)", "105": "IEEE 802.11 (Wi-Fi)", "113": "LINUX_SLL — Linux cooked capture", "127": "IEEE 802.11 + radiotap header", "143": "DOCSIS", "228": "IPV4 — raw IPv4", "229": "IPV6 — raw IPv6", "276": "LINUX_SLL2 — Linux cooked v2" };
      return refTable(T, v.q);
    } },

  { id: "np-radius-codes", name: "RADIUS Code Reference", cat: "netproto", desc: "Look up RADIUS packet codes for AAA (Access-Request 1, Access-Accept 2, Access-Reject 3, Accounting-Request 4, Access-Challenge 11, CoA/Disconnect, ...).", tags: ["radius", "aaa", "authentication", "coa"],
    inputs: [{ k: "q", label: "Search code or name (blank = all)", type: "text", placeholder: "challenge" }],
    run(v) {
      const T = { "1": "Access-Request", "2": "Access-Accept", "3": "Access-Reject", "4": "Accounting-Request", "5": "Accounting-Response", "11": "Access-Challenge", "12": "Status-Server (experimental)", "13": "Status-Client (experimental)", "40": "Disconnect-Request", "41": "Disconnect-ACK", "42": "Disconnect-NAK", "43": "CoA-Request (Change of Authorization)", "44": "CoA-ACK", "45": "CoA-NAK" };
      return refTable(T, v.q);
    } },

  { id: "np-quic-terms", name: "QUIC / HTTP3 Glossary", cat: "netproto", desc: "Explain QUIC and HTTP/3 terms (connection ID, 0-RTT, stream types, packet number spaces, retry, ALPN h3) in plain language.", tags: ["quic", "http3", "h3", "0-rtt"],
    inputs: [{ k: "q", label: "Search a term (blank = all)", type: "text", placeholder: "0-rtt" }],
    run(v) {
      const T = { "QUIC": "A transport over UDP with built-in TLS 1.3 encryption, multiplexed streams, and no head-of-line blocking between streams.", "Connection ID": "An identifier that lets a connection survive IP/port changes (NAT rebinding, Wi-Fi to cellular).", "0-RTT": "Sends application data in the first flight using a cached key from a prior session; replayable, so only for idempotent requests.", "1-RTT": "Normal application data after the handshake completes.", "Stream": "An ordered byte flow; client-initiated bidirectional streams are IDs 0,4,8..., many per connection.", "Packet number spaces": "Initial, Handshake, and Application — each with its own packet numbers and keys.", "Long header": "Used during the handshake (Initial, 0-RTT, Handshake, Retry packets); carries the version.", "Short header": "Used after the handshake for 1-RTT packets; smaller, no version field.", "Retry": "A server response that forces address validation with a token before state is created.", "ALPN h3": "The ALPN identifier that selects HTTP/3 over QUIC.", "QPACK": "HTTP/3's header compression, the successor to HPACK, designed to avoid head-of-line blocking." };
      return refTable(T, v.q, ([k, val]) => `${k}: ${val}`);
    } },

  { id: "np-dns-edns", name: "EDNS0 OPT Explainer", cat: "netproto", desc: "Explain the EDNS0 OPT pseudo-record and optionally decode its 32-bit TTL field (extended RCODE, version, DO bit and flags).", tags: ["dns", "edns", "opt", "dnssec", "do bit"],
    inputs: [{ k: "ttl", label: "OPT TTL field (hex/decimal, optional)", type: "text", placeholder: "0x00008000" }],
    run(v) {
      const base = [
        "EDNS0 adds an OPT pseudo-record (type 41) in the Additional section:",
        "  CLASS field = requestor's max UDP payload size (e.g. 4096).",
        "  TTL field is reused as: ext-RCODE(8) | VERSION(8) | DO flag(1) | Z(15).",
        "  RDATA holds option TLVs (e.g. Cookie, NSID, Client Subnet).",
      ].join("\n");
      if (!v.ttl) return base;
      const s = String(v.ttl).trim();
      const n = /^0x/i.test(s) ? parseInt(s, 16) : parseInt(s, 10);
      if (isNaN(n) || n < 0 || n > 0xffffffff) return { error: "TTL must be a 32-bit value." };
      const extRcode = (n >>> 24) & 0xff, ver = (n >>> 16) & 0xff, doBit = (n >>> 15) & 1, z = n & 0x7fff;
      return `${base}\n\nDecoded TTL ${hx(n >>> 0, 8)}:\n  Extended RCODE (high bits): ${extRcode}\n  EDNS version: ${ver}\n  DO (DNSSEC OK): ${doBit}\n  Z (reserved): ${z}`;
    } },

  // ================= FILTER BUILDER =================
  { id: "np-wireshark-filter", name: "Wireshark Display Filter Builder", cat: "netproto", desc: "Build a Wireshark display-filter expression from host, port, protocol and direction fields (Wireshark syntax, not the tcpdump/BPF capture syntax).", tags: ["wireshark", "display filter", "pcap", "analysis"],
    inputs: [
      { k: "proto", label: "Protocol", type: "select", opts: ["(any)", "tcp", "udp", "icmp", "dns", "http", "tls", "arp"], value: "tcp" },
      { k: "host", label: "Host IP (either direction)", type: "text", placeholder: "192.0.2.10" },
      { k: "src", label: "Source IP", type: "text", placeholder: "" },
      { k: "dst", label: "Destination IP", type: "text", placeholder: "" },
      { k: "port", label: "Port (either direction)", type: "text", inputType: "number", placeholder: "443" },
      { k: "extra", label: "Extra expression (ANDed)", type: "text", placeholder: "tcp.flags.syn == 1" },
    ],
    run(v) {
      const parts = [];
      const ipf = (ip) => ip.includes(":") ? "ipv6" : "ip";
      if (v.proto && v.proto !== "(any)") parts.push(v.proto);
      if (v.host) parts.push(`${ipf(v.host)}.addr == ${v.host.trim()}`);
      if (v.src) parts.push(`${ipf(v.src)}.src == ${v.src.trim()}`);
      if (v.dst) parts.push(`${ipf(v.dst)}.dst == ${v.dst.trim()}`);
      if (v.port !== "" && v.port != null) {
        const p = parseInt(v.port, 10); if (isNaN(p) || p < 0 || p > 65535) return { error: "Port must be 0-65535." };
        const l4 = (v.proto === "udp") ? "udp" : "tcp";
        parts.push(`${l4}.port == ${p}`);
      }
      if (v.extra && v.extra.trim()) parts.push(`(${v.extra.trim()})`);
      if (!parts.length) return { error: "Fill at least one field." };
      return parts.join(" && ");
    } },
];
