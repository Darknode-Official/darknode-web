// Packet Crafter — visual packet builder, protocol analyzer, and export tool.
// Copyright (c) 2026 Darknode-Official. All rights reserved.
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ─── Protocol field definitions ────────────────────────────────────────────
const ETHER_TYPES = [
  { value: "0800", label: "IPv4 (0x0800)" },
  { value: "0806", label: "ARP (0x0806)" },
  { value: "86DD", label: "IPv6 (0x86DD)" },
  { value: "8100", label: "802.1Q VLAN (0x8100)" },
  { value: "8847", label: "MPLS unicast (0x8847)" },
  { value: "88CC", label: "LLDP (0x88CC)" },
  { value: "0842", label: "Wake-on-LAN (0x0842)" },
];

const IP_PROTOCOLS = [
  { value: 1, label: "ICMP (1)" },
  { value: 6, label: "TCP (6)" },
  { value: 17, label: "UDP (17)" },
  { value: 41, label: "IPv6 encap (41)" },
  { value: 47, label: "GRE (47)" },
  { value: 50, label: "ESP (50)" },
  { value: 51, label: "AH (51)" },
  { value: 58, label: "ICMPv6 (58)" },
  { value: 89, label: "OSPF (89)" },
  { value: 132, label: "SCTP (132)" },
];

const TCP_FLAGS = [
  { bit: 0, name: "FIN", desc: "No more data from sender" },
  { bit: 1, name: "SYN", desc: "Synchronize sequence numbers" },
  { bit: 2, name: "RST", desc: "Reset the connection" },
  { bit: 3, name: "PSH", desc: "Push buffered data" },
  { bit: 4, name: "ACK", desc: "Acknowledgment field significant" },
  { bit: 5, name: "URG", desc: "Urgent pointer field significant" },
  { bit: 6, name: "ECE", desc: "ECN-Echo" },
  { bit: 7, name: "CWR", desc: "Congestion Window Reduced" },
  { bit: 8, name: "NS", desc: "ECN nonce concealment" },
];

const ICMP_TYPES = [
  { type: 0, code: 0, label: "Echo Reply" },
  { type: 3, code: 0, label: "Destination Unreachable — Net unreachable" },
  { type: 3, code: 1, label: "Destination Unreachable — Host unreachable" },
  { type: 3, code: 3, label: "Destination Unreachable — Port unreachable" },
  { type: 3, code: 4, label: "Destination Unreachable — Fragmentation needed" },
  { type: 3, code: 13, label: "Destination Unreachable — Admin prohibited" },
  { type: 5, code: 0, label: "Redirect — Network" },
  { type: 5, code: 1, label: "Redirect — Host" },
  { type: 8, code: 0, label: "Echo Request" },
  { type: 11, code: 0, label: "Time Exceeded — TTL expired" },
  { type: 11, code: 1, label: "Time Exceeded — Fragment reassembly" },
  { type: 13, code: 0, label: "Timestamp Request" },
  { type: 14, code: 0, label: "Timestamp Reply" },
  { type: 17, code: 0, label: "Address Mask Request" },
  { type: 18, code: 0, label: "Address Mask Reply" },
];

const ARP_OPCODES = [
  { value: 1, label: "ARP Request (1)" },
  { value: 2, label: "ARP Reply (2)" },
  { value: 3, label: "RARP Request (3)" },
  { value: 4, label: "RARP Reply (4)" },
];

const DNS_QTYPES = [
  { value: 1, label: "A (1)" },
  { value: 2, label: "NS (2)" },
  { value: 5, label: "CNAME (5)" },
  { value: 6, label: "SOA (6)" },
  { value: 12, label: "PTR (12)" },
  { value: 15, label: "MX (15)" },
  { value: 16, label: "TXT (16)" },
  { value: 28, label: "AAAA (28)" },
  { value: 33, label: "SRV (33)" },
  { value: 43, label: "DS (43)" },
  { value: 46, label: "RRSIG (46)" },
  { value: 48, label: "DNSKEY (48)" },
  { value: 252, label: "AXFR (252)" },
  { value: 255, label: "ANY (255)" },
];

const DNS_CLASSES = [
  { value: 1, label: "IN (Internet)" },
  { value: 3, label: "CH (Chaos)" },
  { value: 4, label: "HS (Hesiod)" },
  { value: 255, label: "ANY" },
];

// ─── Protocol field reference database ─────────────────────────────────────
const FIELD_REFERENCE = {
  ethernet: {
    dst_mac: { name: "Destination MAC", bits: 48, desc: "Hardware address of the intended receiver. ff:ff:ff:ff:ff:ff for broadcast.", security: "ARP spoofing can poison the MAC-to-IP mapping. CAM table overflow attacks flood switches with fake MACs." },
    src_mac: { name: "Source MAC", bits: 48, desc: "Hardware address of the sender.", security: "MAC spoofing allows impersonation on the local network. 802.1X port-based authentication mitigates this." },
    ether_type: { name: "EtherType", bits: 16, desc: "Identifies the protocol encapsulated in the payload. 0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6.", security: "Non-standard EtherTypes may indicate tunneling or exfiltration. Monitor for unexpected values." },
  },
  ipv4: {
    version: { name: "Version", bits: 4, desc: "IP version number. Always 4 for IPv4.", security: "Mismatched version can cause parsing errors in some stacks." },
    ihl: { name: "IHL (Header Length)", bits: 4, desc: "Number of 32-bit words in the header. Minimum 5 (20 bytes), maximum 15 (60 bytes).", security: "Manipulated IHL can cause buffer overflows in vulnerable parsers. Values < 5 are invalid." },
    dscp: { name: "DSCP", bits: 6, desc: "Differentiated Services Code Point for QoS marking.", security: "Can be manipulated for traffic priority abuse or to bypass QoS-based filtering." },
    ecn: { name: "ECN", bits: 2, desc: "Explicit Congestion Notification. 00=Not-ECT, 01=ECT(1), 10=ECT(0), 11=CE.", security: "Some firewalls don't properly handle ECN-marked packets, creating bypass opportunities." },
    total_length: { name: "Total Length", bits: 16, desc: "Entire packet size in bytes, including header and data. Max 65535.", security: "Oversized packets can trigger fragmentation-based attacks. Tiny fragments may evade IDS." },
    identification: { name: "Identification", bits: 16, desc: "Uniquely identifies fragments of an original datagram.", security: "Predictable IDs enable idle scanning (Nmap -sI). Can be used for OS fingerprinting." },
    flags: { name: "Flags", bits: 3, desc: "Bit 0: Reserved. Bit 1: Don't Fragment (DF). Bit 2: More Fragments (MF).", security: "The DF bit is used in Path MTU Discovery. Clearing it enables fragmentation attacks." },
    fragment_offset: { name: "Fragment Offset", bits: 13, desc: "Offset of this fragment from the beginning of the original datagram, in 8-byte units.", security: "Overlapping fragments (teardrop attack) can crash vulnerable systems. Tiny offset evasion bypasses firewalls." },
    ttl: { name: "TTL", bits: 8, desc: "Time To Live. Decremented by each router. Packet discarded when TTL reaches 0.", security: "TTL analysis reveals network topology (traceroute). Default TTL varies by OS for fingerprinting (Linux=64, Windows=128, Cisco=255)." },
    protocol: { name: "Protocol", bits: 8, desc: "Identifies the next-level protocol: 1=ICMP, 6=TCP, 17=UDP.", security: "Unusual protocol numbers may indicate tunneling. Protocol 41 (6in4) and 47 (GRE) are common tunnel protocols." },
    header_checksum: { name: "Header Checksum", bits: 16, desc: "One's complement checksum of the IP header only.", security: "Invalid checksums should cause packet drops but some hosts accept them, enabling evasion." },
    src_ip: { name: "Source IP", bits: 32, desc: "IPv4 address of the sender.", security: "IP spoofing is trivial for UDP/ICMP. TCP spoofing requires predicting sequence numbers. BCP38/uRPF filters help." },
    dst_ip: { name: "Destination IP", bits: 32, desc: "IPv4 address of the intended receiver.", security: "RFC 1918 addresses in external traffic indicate misconfiguration or spoofing. Broadcast addresses enable amplification attacks." },
  },
  ipv6: {
    version: { name: "Version", bits: 4, desc: "Always 6 for IPv6.", security: "IPv6 often has less scrutiny than IPv4 in dual-stack networks." },
    traffic_class: { name: "Traffic Class", bits: 8, desc: "Equivalent to IPv4 DSCP+ECN. Used for QoS.", security: "Same QoS abuse potential as IPv4 DSCP." },
    flow_label: { name: "Flow Label", bits: 20, desc: "Labels packets belonging to the same flow for QoS handling.", security: "Can be used for covert channel communication." },
    payload_length: { name: "Payload Length", bits: 16, desc: "Size of the payload in bytes. Does not include the 40-byte fixed header.", security: "Jumbogram extension allows payloads > 65535 bytes." },
    next_header: { name: "Next Header", bits: 8, desc: "Identifies the type of header following the IPv6 header.", security: "Extension header chains can be used to evade firewalls that only inspect the first header." },
    hop_limit: { name: "Hop Limit", bits: 8, desc: "Equivalent to IPv4 TTL. Decremented by each forwarding node.", security: "Same OS fingerprinting implications as IPv4 TTL." },
    src_addr: { name: "Source Address", bits: 128, desc: "128-bit IPv6 address of the sender.", security: "IPv6 EUI-64 addresses leak the MAC address of the host." },
    dst_addr: { name: "Destination Address", bits: 128, desc: "128-bit IPv6 address of the receiver.", security: "Link-local addresses (fe80::) should never appear in routed traffic." },
  },
  tcp: {
    src_port: { name: "Source Port", bits: 16, desc: "Port number of the sending application. Ephemeral ports typically 49152-65535.", security: "Predictable source ports enable DNS cache poisoning. Low source ports may indicate privileged process." },
    dst_port: { name: "Destination Port", bits: 16, desc: "Port number of the receiving application.", security: "Port scanning reveals running services. Well-known ports: 22=SSH, 80=HTTP, 443=HTTPS, 3389=RDP." },
    seq_num: { name: "Sequence Number", bits: 32, desc: "If SYN is set, this is the initial sequence number (ISN). Otherwise, the sequence number of the first data byte.", security: "Predictable ISNs enable TCP session hijacking. Modern OSes use cryptographic ISN generation (RFC 6528)." },
    ack_num: { name: "Acknowledgment Number", bits: 32, desc: "If ACK is set, the value of the next sequence number the sender expects.", security: "ACK scanning (nmap -sA) can map firewall rules." },
    data_offset: { name: "Data Offset", bits: 4, desc: "Number of 32-bit words in the TCP header. Minimum 5 (20 bytes).", security: "Manipulated offsets can cause parsing issues in IDS/IPS." },
    reserved: { name: "Reserved", bits: 3, desc: "Reserved for future use. Should be zero.", security: "Non-zero reserved bits may indicate OS fingerprinting or covert channels." },
    flags: { name: "Flags", bits: 9, desc: "NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN control bits.", security: "Unusual flag combinations (XMAS=FIN+PSH+URG, NULL=none) are used for scanning. RST injection enables session termination attacks." },
    window_size: { name: "Window Size", bits: 16, desc: "Number of bytes the sender is willing to receive.", security: "Window size of 0 (zero-window probe) can be used for slowloris-style attacks. Window scaling factor reveals OS." },
    checksum: { name: "Checksum", bits: 16, desc: "One's complement checksum of the TCP header, data, and pseudo-header.", security: "Some NAT devices recalculate checksums, which can reveal the presence of NAT." },
    urgent_pointer: { name: "Urgent Pointer", bits: 16, desc: "If URG is set, offset of the last urgent data byte.", security: "Urgent data handling varies by OS, enabling fingerprinting. Some IDS miss urgent data." },
  },
  udp: {
    src_port: { name: "Source Port", bits: 16, desc: "Port number of the sending application.", security: "UDP source port spoofing is trivial since there's no handshake. Used in DNS amplification attacks." },
    dst_port: { name: "Destination Port", bits: 16, desc: "Port number of the receiving application.", security: "Common targets: 53=DNS, 67/68=DHCP, 161=SNMP, 123=NTP, 500=IKE, 1900=SSDP." },
    length: { name: "Length", bits: 16, desc: "Length of the UDP header and data in bytes. Minimum 8.", security: "Oversized UDP packets may indicate buffer overflow attempts." },
    checksum: { name: "Checksum", bits: 16, desc: "Optional in IPv4 (0 = disabled), mandatory in IPv6.", security: "Disabled checksums (set to 0) allow data corruption to go undetected." },
  },
  icmp: {
    type: { name: "Type", bits: 8, desc: "ICMP message type. 0=Echo Reply, 3=Destination Unreachable, 8=Echo Request, 11=Time Exceeded.", security: "ICMP can be used for network reconnaissance (ping sweep), covert channels (ICMP tunneling), and DoS (ICMP flood)." },
    code: { name: "Code", bits: 8, desc: "Further specifies the ICMP message type.", security: "Type 3 Code 4 (fragmentation needed) is used in PMTUD attacks." },
    checksum: { name: "Checksum", bits: 16, desc: "One's complement checksum of the ICMP message.", security: "Invalid checksums should be dropped but some hosts don't verify." },
    identifier: { name: "Identifier", bits: 16, desc: "Used to match echo requests with replies.", security: "OS fingerprinting via ICMP ID patterns." },
    sequence: { name: "Sequence Number", bits: 16, desc: "Incremented with each echo request sent.", security: "Sequence number patterns vary by OS implementation." },
  },
  arp: {
    hw_type: { name: "Hardware Type", bits: 16, desc: "Type of hardware address. 1 = Ethernet.", security: "Non-standard hardware types are rare and may indicate malformed packets." },
    proto_type: { name: "Protocol Type", bits: 16, desc: "Protocol address type. 0x0800 = IPv4.", security: "ARP is inherently insecure — no authentication mechanism." },
    hw_len: { name: "Hardware Address Length", bits: 8, desc: "Length of hardware address in bytes. 6 for Ethernet.", security: "Unusual lengths may crash vulnerable ARP implementations." },
    proto_len: { name: "Protocol Address Length", bits: 8, desc: "Length of protocol address in bytes. 4 for IPv4.", security: "Same as hw_len — unusual values may cause issues." },
    opcode: { name: "Opcode", bits: 16, desc: "1=Request, 2=Reply, 3=RARP Request, 4=RARP Reply.", security: "Gratuitous ARP (unsolicited replies) is the basis of ARP spoofing/poisoning attacks." },
    sender_hw: { name: "Sender Hardware Address", bits: 48, desc: "MAC address of the sender.", security: "In ARP spoofing, this is set to the attacker's MAC to redirect traffic." },
    sender_proto: { name: "Sender Protocol Address", bits: 32, desc: "IP address of the sender.", security: "Spoofed to claim another host's IP address in ARP poisoning." },
    target_hw: { name: "Target Hardware Address", bits: 48, desc: "MAC address of the target. 00:00:00:00:00:00 in requests.", security: "In ARP replies, this tells the target which MAC to associate with the IP." },
    target_proto: { name: "Target Protocol Address", bits: 32, desc: "IP address of the target.", security: "The IP being queried. ARP cache entries map this IP to the hardware address." },
  },
  dns: {
    transaction_id: { name: "Transaction ID", bits: 16, desc: "Randomly generated to match requests with responses.", security: "Predictable transaction IDs enable DNS cache poisoning (Kaminsky attack). Must be cryptographically random." },
    flags: { name: "Flags", bits: 16, desc: "QR, Opcode, AA, TC, RD, RA, Z, AD, CD, RCODE fields.", security: "The AD (Authenticated Data) flag indicates DNSSEC validation. TC (Truncated) forces fallback to TCP." },
    qr: { name: "QR (Query/Response)", bits: 1, desc: "0=Query, 1=Response.", security: "Unsolicited responses may be spoofed DNS replies." },
    opcode: { name: "Opcode", bits: 4, desc: "0=Standard query, 1=Inverse query, 2=Server status, 4=Notify, 5=Update.", security: "DNS UPDATE (5) can be used for unauthorized zone modifications if dynamic updates are misconfigured." },
    aa: { name: "AA (Authoritative Answer)", bits: 1, desc: "Set if the responding server is authoritative for the domain.", security: "Spoofed responses may falsely set AA to appear legitimate." },
    tc: { name: "TC (Truncated)", bits: 1, desc: "Set if the response was truncated. Client should retry over TCP.", security: "DNS amplification attacks exploit the TCP fallback mechanism." },
    rd: { name: "RD (Recursion Desired)", bits: 1, desc: "Set by the client to request recursive resolution.", security: "Open recursive resolvers are exploited for DNS amplification attacks. Should be restricted." },
    ra: { name: "RA (Recursion Available)", bits: 1, desc: "Set by the server if recursion is supported.", security: "Indicates the server accepts recursive queries — potential amplification vector." },
    rcode: { name: "RCODE", bits: 4, desc: "Response code. 0=No error, 1=Format error, 2=Server failure, 3=NXDOMAIN, 5=Refused.", security: "NXDOMAIN responses can leak internal hostnames. SERVFAIL may indicate DNSSEC validation failure." },
    qdcount: { name: "Question Count", bits: 16, desc: "Number of questions in the query.", security: "Multiple questions are rarely legitimate and may indicate fuzzing." },
    ancount: { name: "Answer Count", bits: 16, desc: "Number of answer records.", security: "Unusually high answer counts may indicate DNS amplification or poisoning attempts." },
    qname: { name: "Query Name", bits: "variable", desc: "The domain name being queried, encoded as a sequence of labels.", security: "DNS tunneling encodes data in query names. Long or unusual domain names may indicate C2 communication or DGA domains." },
    qtype: { name: "Query Type", bits: 16, desc: "Type of record being requested. 1=A, 28=AAAA, 15=MX, 16=TXT, 255=ANY.", security: "ANY queries amplify responses. TXT records are used for DNS tunneling and C2." },
    qclass: { name: "Query Class", bits: 16, desc: "Class of the query. Usually 1 (IN = Internet).", security: "Non-IN classes are extremely rare and may indicate protocol abuse." },
  },
};

// ─── Packet templates ──────────────────────────────────────────────────────
const TEMPLATES = {
  "TCP SYN Scan": {
    desc: "Single SYN packet to probe a port — the basis of Nmap -sS scanning.",
    ethernet: { dst: "ff:ff:ff:ff:ff:ff", src: "00:11:22:33:44:55", type: "0800" },
    ipv4: { version: 4, ihl: 5, dscp: 0, ecn: 0, ttl: 64, protocol: 6, src: "192.168.1.100", dst: "192.168.1.1", id: 54321, flags: 2, frag_offset: 0 },
    tcp: { src_port: 45678, dst_port: 80, seq: 1000, ack: 0, offset: 5, flags: 0x002, window: 65535, urg: 0 },
  },
  "TCP SYN Flood": {
    desc: "SYN packet with spoofed source — illustrates a SYN flood DoS pattern.",
    ethernet: { dst: "ff:ff:ff:ff:ff:ff", src: "de:ad:be:ef:ca:fe", type: "0800" },
    ipv4: { version: 4, ihl: 5, dscp: 0, ecn: 0, ttl: 128, protocol: 6, src: "10.0.0.1", dst: "203.0.113.50", id: 0, flags: 0, frag_offset: 0 },
    tcp: { src_port: 12345, dst_port: 443, seq: 0, ack: 0, offset: 5, flags: 0x002, window: 1024, urg: 0 },
  },
  "ARP Request": {
    desc: "Standard ARP request — who has this IP? Tell me.",
    ethernet: { dst: "ff:ff:ff:ff:ff:ff", src: "00:11:22:33:44:55", type: "0806" },
    arp: { hw_type: 1, proto_type: 0x0800, hw_len: 6, proto_len: 4, opcode: 1, sender_mac: "00:11:22:33:44:55", sender_ip: "192.168.1.100", target_mac: "00:00:00:00:00:00", target_ip: "192.168.1.1" },
  },
  "ARP Spoof (Gratuitous)": {
    desc: "Gratuitous ARP reply — used in MITM attacks to poison ARP caches.",
    ethernet: { dst: "ff:ff:ff:ff:ff:ff", src: "de:ad:be:ef:ca:fe", type: "0806" },
    arp: { hw_type: 1, proto_type: 0x0800, hw_len: 6, proto_len: 4, opcode: 2, sender_mac: "de:ad:be:ef:ca:fe", sender_ip: "192.168.1.1", target_mac: "ff:ff:ff:ff:ff:ff", target_ip: "192.168.1.1" },
  },
  "DNS Query (A Record)": {
    desc: "Standard DNS query for an A record.",
    ethernet: { dst: "ff:ff:ff:ff:ff:ff", src: "00:11:22:33:44:55", type: "0800" },
    ipv4: { version: 4, ihl: 5, dscp: 0, ecn: 0, ttl: 64, protocol: 17, src: "192.168.1.100", dst: "8.8.8.8", id: 12345, flags: 0, frag_offset: 0 },
    udp: { src_port: 53421, dst_port: 53, length: 0 },
    dns: { id: 0xABCD, qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0, qname: "example.com", qtype: 1, qclass: 1 },
  },
  "ICMP Echo Request (Ping)": {
    desc: "Standard ICMP echo request — the classic ping.",
    ethernet: { dst: "ff:ff:ff:ff:ff:ff", src: "00:11:22:33:44:55", type: "0800" },
    ipv4: { version: 4, ihl: 5, dscp: 0, ecn: 0, ttl: 64, protocol: 1, src: "192.168.1.100", dst: "192.168.1.1", id: 54321, flags: 2, frag_offset: 0 },
    icmp: { type: 8, code: 0, id: 0x1234, seq: 1 },
  },
  "TCP 3-Way Handshake — SYN": {
    desc: "First packet of a TCP three-way handshake.",
    ethernet: { dst: "aa:bb:cc:dd:ee:ff", src: "00:11:22:33:44:55", type: "0800" },
    ipv4: { version: 4, ihl: 5, dscp: 0, ecn: 0, ttl: 64, protocol: 6, src: "10.0.0.5", dst: "10.0.0.10", id: 1, flags: 2, frag_offset: 0 },
    tcp: { src_port: 49152, dst_port: 22, seq: 100, ack: 0, offset: 5, flags: 0x002, window: 65535, urg: 0 },
  },
  "HTTP GET Request": {
    desc: "TCP packet carrying an HTTP GET request payload.",
    ethernet: { dst: "aa:bb:cc:dd:ee:ff", src: "00:11:22:33:44:55", type: "0800" },
    ipv4: { version: 4, ihl: 5, dscp: 0, ecn: 0, ttl: 64, protocol: 6, src: "192.168.1.100", dst: "93.184.216.34", id: 1, flags: 2, frag_offset: 0 },
    tcp: { src_port: 50000, dst_port: 80, seq: 1, ack: 1, offset: 5, flags: 0x018, window: 65535, urg: 0 },
    payload: "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Darknode/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
  },
  "HTTP POST Request": {
    desc: "TCP packet carrying an HTTP POST request with a JSON body.",
    ethernet: { dst: "aa:bb:cc:dd:ee:ff", src: "00:11:22:33:44:55", type: "0800" },
    ipv4: { version: 4, ihl: 5, dscp: 0, ecn: 0, ttl: 64, protocol: 6, src: "192.168.1.100", dst: "93.184.216.34", id: 2, flags: 2, frag_offset: 0 },
    tcp: { src_port: 50001, dst_port: 80, seq: 1, ack: 1, offset: 5, flags: 0x018, window: 65535, urg: 0 },
    payload: 'POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{"key":"value","num":42}',
  },
};

// ─── Attack pattern signatures ─────────────────────────────────────────────
const ATTACK_SIGNATURES = [
  { name: "SYN Scan", check: (p) => p.tcp && (p.tcp.flags & 0x3FF) === 0x002 && p.tcp.ack === 0, severity: "info", desc: "Single SYN without established connection — port scanning technique (Nmap -sS)." },
  { name: "SYN Flood", check: (p) => p.tcp && (p.tcp.flags & 0x3FF) === 0x002 && p.ipv4 && p.ipv4.ttl > 100, severity: "high", desc: "SYN with high TTL and no ACK — possible SYN flood DoS if source is spoofed." },
  { name: "XMAS Scan", check: (p) => p.tcp && (p.tcp.flags & 0x029) === 0x029, severity: "medium", desc: "FIN+PSH+URG flags set — Nmap XMAS scan (-sX). Used to bypass stateless firewalls." },
  { name: "NULL Scan", check: (p) => p.tcp && (p.tcp.flags & 0x03F) === 0, severity: "medium", desc: "No TCP flags set — Nmap NULL scan (-sN). Exploits RFC 793 behavior." },
  { name: "FIN Scan", check: (p) => p.tcp && (p.tcp.flags & 0x03F) === 0x001, severity: "medium", desc: "Only FIN flag set — Nmap FIN scan (-sF). Another stateless firewall bypass." },
  { name: "ARP Spoofing", check: (p) => p.arp && p.arp.opcode === 2 && p.ethernet && p.ethernet.dst === "ff:ff:ff:ff:ff:ff", severity: "high", desc: "Gratuitous ARP reply broadcast — classic MITM attack technique." },
  { name: "Land Attack", check: (p) => p.ipv4 && p.ipv4.src === p.ipv4.dst && p.tcp && p.tcp.src_port === p.tcp.dst_port, severity: "critical", desc: "Source and destination IP+port are identical — Land attack DoS." },
  { name: "Ping of Death", check: (p) => p.icmp && p.ipv4 && p.ipv4.total_length > 65535, severity: "critical", desc: "Oversized ICMP packet — Ping of Death attack." },
  { name: "DNS Zone Transfer", check: (p) => p.dns && p.dns.qtype === 252, severity: "high", desc: "AXFR query — DNS zone transfer attempt. Should be restricted to authorized secondaries." },
  { name: "DNS ANY Query", check: (p) => p.dns && p.dns.qtype === 255, severity: "medium", desc: "ANY query — used in DNS amplification attacks. Many resolvers now refuse these." },
  { name: "Tiny Fragment", check: (p) => p.ipv4 && p.ipv4.frag_offset === 0 && (p.ipv4.flags & 1) === 1 && p.ipv4.total_length < 68, severity: "high", desc: "Very small first fragment — may be attempting to evade firewall/IDS inspection." },
  { name: "Low TTL", check: (p) => p.ipv4 && p.ipv4.ttl <= 1, severity: "info", desc: "TTL of 0 or 1 — traceroute-style probing or misconfiguration." },
  { name: "Source Routing", check: (p) => p.ipv4 && p.ipv4.ihl > 5, severity: "medium", desc: "IP options present (IHL > 5) — may contain source routing which allows path manipulation." },
  { name: "ICMP Redirect", check: (p) => p.icmp && p.icmp.type === 5, severity: "high", desc: "ICMP Redirect — can be used to reroute traffic through an attacker's machine." },
  { name: "TCP RST Injection", check: (p) => p.tcp && (p.tcp.flags & 0x004) === 0x004 && p.tcp.seq > 0, severity: "medium", desc: "TCP RST with non-zero sequence — possible connection termination attack." },
];

// ─── TCP State Machine ─────────────────────────────────────────────────────
const TCP_STATES = [
  { from: "CLOSED", to: "LISTEN", trigger: "passive open", desc: "Server begins listening for connections" },
  { from: "CLOSED", to: "SYN_SENT", trigger: "active open, send SYN", desc: "Client initiates connection" },
  { from: "LISTEN", to: "SYN_RCVD", trigger: "recv SYN, send SYN+ACK", desc: "Server receives client SYN" },
  { from: "LISTEN", to: "SYN_SENT", trigger: "send SYN", desc: "Simultaneous open" },
  { from: "SYN_SENT", to: "ESTABLISHED", trigger: "recv SYN+ACK, send ACK", desc: "Client completes handshake" },
  { from: "SYN_SENT", to: "SYN_RCVD", trigger: "recv SYN, send SYN+ACK", desc: "Simultaneous open" },
  { from: "SYN_SENT", to: "CLOSED", trigger: "timeout", desc: "Connection attempt timed out" },
  { from: "SYN_RCVD", to: "ESTABLISHED", trigger: "recv ACK", desc: "Server completes handshake" },
  { from: "SYN_RCVD", to: "FIN_WAIT_1", trigger: "close, send FIN", desc: "Server closes before established" },
  { from: "ESTABLISHED", to: "FIN_WAIT_1", trigger: "close, send FIN", desc: "Active close initiated" },
  { from: "ESTABLISHED", to: "CLOSE_WAIT", trigger: "recv FIN, send ACK", desc: "Passive close — peer initiated close" },
  { from: "FIN_WAIT_1", to: "FIN_WAIT_2", trigger: "recv ACK", desc: "Our FIN acknowledged" },
  { from: "FIN_WAIT_1", to: "CLOSING", trigger: "recv FIN, send ACK", desc: "Simultaneous close" },
  { from: "FIN_WAIT_1", to: "TIME_WAIT", trigger: "recv FIN+ACK, send ACK", desc: "Fast close — both FIN and ACK received" },
  { from: "FIN_WAIT_2", to: "TIME_WAIT", trigger: "recv FIN, send ACK", desc: "Peer's FIN received" },
  { from: "CLOSING", to: "TIME_WAIT", trigger: "recv ACK", desc: "Our FIN acknowledged after simultaneous close" },
  { from: "CLOSE_WAIT", to: "LAST_ACK", trigger: "close, send FIN", desc: "Application closes after peer's FIN" },
  { from: "LAST_ACK", to: "CLOSED", trigger: "recv ACK", desc: "Final ACK received — connection fully closed" },
  { from: "TIME_WAIT", to: "CLOSED", trigger: "2MSL timeout", desc: "Wait period expires — ensures late segments are discarded" },
];

// ─── Checksum utilities ────────────────────────────────────────────────────
function ipChecksum(headerBytes) {
  let sum = 0;
  for (let i = 0; i < headerBytes.length; i += 2) {
    sum += (headerBytes[i] << 8) | (headerBytes[i + 1] || 0);
  }
  while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
  return (~sum) & 0xFFFF;
}

function tcpChecksum(srcIp, dstIp, tcpHeaderAndData) {
  const pseudo = new Uint8Array(12 + tcpHeaderAndData.length + (tcpHeaderAndData.length % 2));
  const srcParts = srcIp.split(".").map(Number);
  const dstParts = dstIp.split(".").map(Number);
  pseudo[0] = srcParts[0]; pseudo[1] = srcParts[1]; pseudo[2] = srcParts[2]; pseudo[3] = srcParts[3];
  pseudo[4] = dstParts[0]; pseudo[5] = dstParts[1]; pseudo[6] = dstParts[2]; pseudo[7] = dstParts[3];
  pseudo[8] = 0;
  pseudo[9] = 6;
  pseudo[10] = (tcpHeaderAndData.length >> 8) & 0xFF;
  pseudo[11] = tcpHeaderAndData.length & 0xFF;
  pseudo.set(tcpHeaderAndData, 12);
  return ipChecksum(pseudo);
}

function udpChecksum(srcIp, dstIp, udpHeaderAndData) {
  const pseudo = new Uint8Array(12 + udpHeaderAndData.length + (udpHeaderAndData.length % 2));
  const srcParts = srcIp.split(".").map(Number);
  const dstParts = dstIp.split(".").map(Number);
  pseudo[0] = srcParts[0]; pseudo[1] = srcParts[1]; pseudo[2] = srcParts[2]; pseudo[3] = srcParts[3];
  pseudo[4] = dstParts[0]; pseudo[5] = dstParts[1]; pseudo[6] = dstParts[2]; pseudo[7] = dstParts[3];
  pseudo[8] = 0;
  pseudo[9] = 17;
  pseudo[10] = (udpHeaderAndData.length >> 8) & 0xFF;
  pseudo[11] = udpHeaderAndData.length & 0xFF;
  pseudo.set(udpHeaderAndData, 12);
  return ipChecksum(pseudo);
}

// ─── Byte serialization ────────────────────────────────────────────────────
function macToBytes(mac) {
  return mac.split(":").map((h) => parseInt(h, 16) || 0);
}

function ipToBytes(ip) {
  return ip.split(".").map((o) => parseInt(o, 10) || 0);
}

function ipv6ToBytes(addr) {
  const groups = addr.split(":");
  const bytes = [];
  for (const g of groups) {
    const val = parseInt(g, 16) || 0;
    bytes.push((val >> 8) & 0xFF, val & 0xFF);
  }
  while (bytes.length < 16) bytes.push(0);
  return bytes.slice(0, 16);
}

function domainToBytes(domain) {
  const labels = domain.split(".");
  const bytes = [];
  for (const label of labels) {
    bytes.push(label.length);
    for (let i = 0; i < label.length; i++) bytes.push(label.charCodeAt(i));
  }
  bytes.push(0);
  return bytes;
}

function stringToBytes(str) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) bytes.push(str.charCodeAt(i) & 0xFF);
  return bytes;
}

function u16(val) { return [(val >> 8) & 0xFF, val & 0xFF]; }
function u32(val) { return [(val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF]; }

// ─── Packet builder ────────────────────────────────────────────────────────
function buildPacketBytes(pkt) {
  const bytes = [];

  // Ethernet
  if (pkt.ethernet) {
    bytes.push(...macToBytes(pkt.ethernet.dst || "ff:ff:ff:ff:ff:ff"));
    bytes.push(...macToBytes(pkt.ethernet.src || "00:00:00:00:00:00"));
    bytes.push(...u16(parseInt(pkt.ethernet.type || "0800", 16)));
  }

  // ARP
  if (pkt.arp) {
    bytes.push(...u16(pkt.arp.hw_type || 1));
    bytes.push(...u16(pkt.arp.proto_type || 0x0800));
    bytes.push(pkt.arp.hw_len || 6);
    bytes.push(pkt.arp.proto_len || 4);
    bytes.push(...u16(pkt.arp.opcode || 1));
    bytes.push(...macToBytes(pkt.arp.sender_mac || "00:00:00:00:00:00"));
    bytes.push(...ipToBytes(pkt.arp.sender_ip || "0.0.0.0"));
    bytes.push(...macToBytes(pkt.arp.target_mac || "00:00:00:00:00:00"));
    bytes.push(...ipToBytes(pkt.arp.target_ip || "0.0.0.0"));
    return bytes;
  }

  // IPv4
  if (pkt.ipv4) {
    const ipStart = bytes.length;
    const ihl = pkt.ipv4.ihl || 5;
    bytes.push(((pkt.ipv4.version || 4) << 4) | ihl);
    bytes.push(((pkt.ipv4.dscp || 0) << 2) | (pkt.ipv4.ecn || 0));
    bytes.push(0, 0); // total length placeholder
    bytes.push(...u16(pkt.ipv4.id || 0));
    const flagsAndOffset = ((pkt.ipv4.flags || 0) << 13) | (pkt.ipv4.frag_offset || 0);
    bytes.push(...u16(flagsAndOffset));
    bytes.push(pkt.ipv4.ttl || 64);
    bytes.push(pkt.ipv4.protocol || 6);
    bytes.push(0, 0); // checksum placeholder
    bytes.push(...ipToBytes(pkt.ipv4.src || "0.0.0.0"));
    bytes.push(...ipToBytes(pkt.ipv4.dst || "0.0.0.0"));

    // TCP
    if (pkt.tcp) {
      const tcpStart = bytes.length;
      bytes.push(...u16(pkt.tcp.src_port || 0));
      bytes.push(...u16(pkt.tcp.dst_port || 0));
      bytes.push(...u32(pkt.tcp.seq || 0));
      bytes.push(...u32(pkt.tcp.ack || 0));
      const offsetAndFlags = ((pkt.tcp.offset || 5) << 12) | (pkt.tcp.flags || 0);
      bytes.push(...u16(offsetAndFlags));
      bytes.push(...u16(pkt.tcp.window || 65535));
      bytes.push(0, 0); // checksum placeholder
      bytes.push(...u16(pkt.tcp.urg || 0));
      if (pkt.payload) bytes.push(...stringToBytes(pkt.payload));
      // TCP checksum
      const tcpLen = bytes.length - tcpStart;
      const tcpData = new Uint8Array(bytes.slice(tcpStart));
      const cksum = tcpChecksum(pkt.ipv4.src || "0.0.0.0", pkt.ipv4.dst || "0.0.0.0", tcpData);
      bytes[tcpStart + 16] = (cksum >> 8) & 0xFF;
      bytes[tcpStart + 17] = cksum & 0xFF;
    }

    // UDP
    if (pkt.udp) {
      const udpStart = bytes.length;
      bytes.push(...u16(pkt.udp.src_port || 0));
      bytes.push(...u16(pkt.udp.dst_port || 0));
      bytes.push(0, 0); // length placeholder
      bytes.push(0, 0); // checksum placeholder
      if (pkt.dns) {
        bytes.push(...u16(pkt.dns.id || 0));
        const dnsFlags = ((pkt.dns.qr || 0) << 15) | ((pkt.dns.opcode || 0) << 11) |
          ((pkt.dns.aa || 0) << 10) | ((pkt.dns.tc || 0) << 9) | ((pkt.dns.rd || 0) << 8) |
          ((pkt.dns.ra || 0) << 7) | ((pkt.dns.rcode || 0));
        bytes.push(...u16(dnsFlags));
        bytes.push(...u16(1)); // QDCOUNT
        bytes.push(...u16(0)); // ANCOUNT
        bytes.push(...u16(0)); // NSCOUNT
        bytes.push(...u16(0)); // ARCOUNT
        bytes.push(...domainToBytes(pkt.dns.qname || "example.com"));
        bytes.push(...u16(pkt.dns.qtype || 1));
        bytes.push(...u16(pkt.dns.qclass || 1));
      }
      if (pkt.payload && !pkt.dns) bytes.push(...stringToBytes(pkt.payload));
      const udpLen = bytes.length - udpStart;
      bytes[udpStart + 4] = (udpLen >> 8) & 0xFF;
      bytes[udpStart + 5] = udpLen & 0xFF;
      const udpData = new Uint8Array(bytes.slice(udpStart));
      const cksum = udpChecksum(pkt.ipv4.src || "0.0.0.0", pkt.ipv4.dst || "0.0.0.0", udpData);
      bytes[udpStart + 6] = (cksum >> 8) & 0xFF;
      bytes[udpStart + 7] = cksum & 0xFF;
    }

    // ICMP
    if (pkt.icmp) {
      const icmpStart = bytes.length;
      bytes.push(pkt.icmp.type || 0);
      bytes.push(pkt.icmp.code || 0);
      bytes.push(0, 0); // checksum placeholder
      bytes.push(...u16(pkt.icmp.id || 0));
      bytes.push(...u16(pkt.icmp.seq || 0));
      // ICMP data (32 bytes of pattern)
      for (let i = 0; i < 32; i++) bytes.push(0x41 + (i % 26));
      const icmpData = new Uint8Array(bytes.slice(icmpStart));
      const cksum = ipChecksum(icmpData);
      bytes[icmpStart + 2] = (cksum >> 8) & 0xFF;
      bytes[icmpStart + 3] = cksum & 0xFF;
    }

    // Fill in IP total length
    const ipLen = bytes.length - ipStart;
    bytes[ipStart + 2] = (ipLen >> 8) & 0xFF;
    bytes[ipStart + 3] = ipLen & 0xFF;

    // IP checksum (header only)
    const ipHeaderBytes = new Uint8Array(bytes.slice(ipStart, ipStart + ihl * 4));
    const ipCksum = ipChecksum(ipHeaderBytes);
    bytes[ipStart + 10] = (ipCksum >> 8) & 0xFF;
    bytes[ipStart + 11] = ipCksum & 0xFF;
  }

  return bytes;
}

// ─── Hex/binary formatting ─────────────────────────────────────────────────
function hexDump(bytes) {
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const offset = i.toString(16).padStart(8, "0");
    const hex = [];
    const ascii = [];
    for (let j = 0; j < 16; j++) {
      if (i + j < bytes.length) {
        hex.push(bytes[i + j].toString(16).padStart(2, "0"));
        ascii.push(bytes[i + j] >= 32 && bytes[i + j] <= 126 ? String.fromCharCode(bytes[i + j]) : ".");
      } else {
        hex.push("  ");
        ascii.push(" ");
      }
    }
    const hexStr = hex.slice(0, 8).join(" ") + "  " + hex.slice(8).join(" ");
    lines.push(offset + "  " + hexStr + "  |" + ascii.join("") + "|");
  }
  return lines.join("\n");
}

function binaryDump(bytes) {
  const lines = [];
  for (let i = 0; i < bytes.length; i += 4) {
    const offset = i.toString(16).padStart(4, "0");
    const bits = [];
    for (let j = 0; j < 4; j++) {
      if (i + j < bytes.length) {
        bits.push(bytes[i + j].toString(2).padStart(8, "0"));
      }
    }
    lines.push(offset + "  " + bits.join(" "));
  }
  return lines.join("\n");
}

function toHexString(bytes) {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function toCArray(bytes, name) {
  const lines = ["unsigned char " + name + "[] = {"];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    lines.push("  " + chunk.map((b) => "0x" + b.toString(16).padStart(2, "0")).join(", ") + (i + 16 < bytes.length ? "," : ""));
  }
  lines.push("};");
  lines.push("unsigned int " + name + "_len = " + bytes.length + ";");
  return lines.join("\n");
}

function toScapy(pkt) {
  const parts = [];
  if (pkt.ethernet) {
    parts.push('Ether(dst="' + (pkt.ethernet.dst || "ff:ff:ff:ff:ff:ff") + '", src="' + (pkt.ethernet.src || "00:00:00:00:00:00") + '", type=0x' + (pkt.ethernet.type || "0800") + ')');
  }
  if (pkt.arp) {
    parts.push('ARP(op=' + (pkt.arp.opcode || 1) + ', hwsrc="' + (pkt.arp.sender_mac || "00:00:00:00:00:00") + '", psrc="' + (pkt.arp.sender_ip || "0.0.0.0") + '", hwdst="' + (pkt.arp.target_mac || "00:00:00:00:00:00") + '", pdst="' + (pkt.arp.target_ip || "0.0.0.0") + '")');
  }
  if (pkt.ipv4) {
    parts.push('IP(src="' + (pkt.ipv4.src || "0.0.0.0") + '", dst="' + (pkt.ipv4.dst || "0.0.0.0") + '", ttl=' + (pkt.ipv4.ttl || 64) + ', id=' + (pkt.ipv4.id || 0) + ')');
  }
  if (pkt.tcp) {
    const flagStr = [];
    if (pkt.tcp.flags & 0x002) flagStr.push("S");
    if (pkt.tcp.flags & 0x010) flagStr.push("A");
    if (pkt.tcp.flags & 0x001) flagStr.push("F");
    if (pkt.tcp.flags & 0x004) flagStr.push("R");
    if (pkt.tcp.flags & 0x008) flagStr.push("P");
    if (pkt.tcp.flags & 0x020) flagStr.push("U");
    parts.push('TCP(sport=' + (pkt.tcp.src_port || 0) + ', dport=' + (pkt.tcp.dst_port || 0) + ', seq=' + (pkt.tcp.seq || 0) + ', ack=' + (pkt.tcp.ack || 0) + ', flags="' + flagStr.join("") + '", window=' + (pkt.tcp.window || 65535) + ')');
  }
  if (pkt.udp) {
    parts.push('UDP(sport=' + (pkt.udp.src_port || 0) + ', dport=' + (pkt.udp.dst_port || 0) + ')');
  }
  if (pkt.icmp) {
    parts.push('ICMP(type=' + (pkt.icmp.type || 0) + ', code=' + (pkt.icmp.code || 0) + ', id=' + (pkt.icmp.id || 0) + ', seq=' + (pkt.icmp.seq || 0) + ')');
  }
  if (pkt.dns) {
    parts.push('DNS(rd=' + (pkt.dns.rd || 0) + ', qd=DNSQR(qname="' + (pkt.dns.qname || "example.com") + '", qtype=' + (pkt.dns.qtype || 1) + '))');
  }
  if (pkt.payload) {
    parts.push('Raw(load=b"' + pkt.payload.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\r/g, "\\r").replace(/\n/g, "\\n") + '")');
  }
  return "pkt = " + parts.join(" / ") + "\nsend(pkt)";
}

function toRawBytes(bytes) {
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    lines.push(bytes.slice(i, i + 16).map((b) => "\\" + b.toString(8).padStart(3, "0")).join(""));
  }
  return lines.join("\n");
}

// ─── Wireshark filter generator ────────────────────────────────────────────
function wiresharkFilter(pkt) {
  const parts = [];
  if (pkt.ipv4) {
    if (pkt.ipv4.src && pkt.ipv4.src !== "0.0.0.0") parts.push("ip.src == " + pkt.ipv4.src);
    if (pkt.ipv4.dst && pkt.ipv4.dst !== "0.0.0.0") parts.push("ip.dst == " + pkt.ipv4.dst);
    if (pkt.ipv4.protocol) parts.push("ip.proto == " + pkt.ipv4.protocol);
  }
  if (pkt.tcp) {
    if (pkt.tcp.src_port) parts.push("tcp.srcport == " + pkt.tcp.src_port);
    if (pkt.tcp.dst_port) parts.push("tcp.dstport == " + pkt.tcp.dst_port);
    const fnames = [];
    if (pkt.tcp.flags & 0x002) fnames.push("tcp.flags.syn == 1");
    if (pkt.tcp.flags & 0x010) fnames.push("tcp.flags.ack == 1");
    if (pkt.tcp.flags & 0x001) fnames.push("tcp.flags.fin == 1");
    if (pkt.tcp.flags & 0x004) fnames.push("tcp.flags.reset == 1");
    if (fnames.length) parts.push(...fnames);
  }
  if (pkt.udp) {
    if (pkt.udp.src_port) parts.push("udp.srcport == " + pkt.udp.src_port);
    if (pkt.udp.dst_port) parts.push("udp.dstport == " + pkt.udp.dst_port);
  }
  if (pkt.icmp) {
    parts.push("icmp.type == " + (pkt.icmp.type || 0));
    parts.push("icmp.code == " + (pkt.icmp.code || 0));
  }
  if (pkt.dns) {
    parts.push("dns");
    if (pkt.dns.qname) parts.push('dns.qry.name == "' + pkt.dns.qname + '"');
  }
  if (pkt.arp) {
    parts.push("arp");
    if (pkt.arp.opcode) parts.push("arp.opcode == " + pkt.arp.opcode);
  }
  return parts.join(" && ") || "ip";
}

// ─── MTU/Fragmentation calculator ──────────────────────────────────────────
function mtuCalc(totalLen, mtu) {
  const ipHeaderLen = 20;
  const maxPayload = mtu - ipHeaderLen;
  const fragmentPayload = maxPayload & ~7; // must be multiple of 8
  const dataLen = totalLen - ipHeaderLen;
  if (dataLen <= maxPayload) return [{ offset: 0, size: dataLen, mf: false }];
  const frags = [];
  let offset = 0;
  while (offset < dataLen) {
    const remaining = dataLen - offset;
    const size = remaining > fragmentPayload ? fragmentPayload : remaining;
    const mf = offset + size < dataLen;
    frags.push({ offset: offset / 8, size, mf });
    offset += size;
  }
  return frags;
}

// ─── Sequence number analyzer ──────────────────────────────────────────────
function seqAnalysis(isn, dataLen, windowSize) {
  const nextSeq = (isn + dataLen) >>> 0;
  const ackExpected = nextSeq;
  const windowEnd = (isn + windowSize) >>> 0;
  const wrapDistance = 0xFFFFFFFF - isn;
  return {
    isn,
    nextSeq,
    ackExpected,
    windowStart: isn,
    windowEnd,
    wrapDistance,
    willWrap: dataLen > wrapDistance,
    bytesInFlight: dataLen,
  };
}

// ─── HTML builder helpers ──────────────────────────────────────────────────
function selectHTML(id, options, selected, label) {
  let html = '<label class="pc-label">' + esc(label) + '</label>';
  html += '<select id="' + esc(id) + '" class="pc-select">';
  for (const opt of options) {
    const val = opt.value !== undefined ? opt.value : opt;
    const lbl = opt.label || opt;
    html += '<option value="' + esc(String(val)) + '"' + (String(val) === String(selected) ? " selected" : "") + '>' + esc(lbl) + '</option>';
  }
  html += '</select>';
  return html;
}

function inputHTML(id, value, label, type, extra) {
  return '<label class="pc-label">' + esc(label) + '</label>' +
    '<input id="' + esc(id) + '" class="pc-input" type="' + (type || "text") + '" value="' + esc(String(value)) + '"' + (extra || "") + '>';
}

function checkboxHTML(id, checked, label) {
  return '<label class="pc-chk-label"><input type="checkbox" id="' + esc(id) + '"' + (checked ? " checked" : "") + '> ' + esc(label) + '</label>';
}

// ─── Service fingerprint database ──────────────────────────────────────────
const SERVICE_FINGERPRINTS = {
  20: { name: "FTP Data", risk: "medium", desc: "FTP data channel — cleartext file transfer" },
  21: { name: "FTP", risk: "high", desc: "FTP control — credentials sent in cleartext" },
  22: { name: "SSH", risk: "low", desc: "Secure Shell — encrypted remote access" },
  23: { name: "Telnet", risk: "critical", desc: "Telnet — all data including passwords sent in cleartext" },
  25: { name: "SMTP", risk: "medium", desc: "Simple Mail Transfer — email relay, often abused for spam" },
  53: { name: "DNS", risk: "medium", desc: "Domain Name System — can be used for amplification and tunneling" },
  67: { name: "DHCP Server", risk: "medium", desc: "DHCP — rogue DHCP servers enable MITM" },
  68: { name: "DHCP Client", risk: "low", desc: "DHCP client port" },
  69: { name: "TFTP", risk: "high", desc: "Trivial FTP — no authentication, commonly targeted" },
  80: { name: "HTTP", risk: "medium", desc: "Hypertext Transfer Protocol — unencrypted web traffic" },
  88: { name: "Kerberos", risk: "medium", desc: "Kerberos auth — Kerberoasting and AS-REP roasting targets" },
  110: { name: "POP3", risk: "high", desc: "Post Office Protocol — cleartext email retrieval" },
  111: { name: "RPCbind", risk: "high", desc: "RPC port mapper — reveals available RPC services" },
  123: { name: "NTP", risk: "medium", desc: "Network Time Protocol — NTP amplification attacks" },
  135: { name: "MS-RPC", risk: "high", desc: "Microsoft RPC — many Windows exploits target this" },
  137: { name: "NetBIOS NS", risk: "high", desc: "NetBIOS Name Service — information disclosure" },
  138: { name: "NetBIOS DGM", risk: "high", desc: "NetBIOS Datagram — Windows network browsing" },
  139: { name: "NetBIOS SSN", risk: "high", desc: "NetBIOS Session — legacy SMB, many vulnerabilities" },
  143: { name: "IMAP", risk: "medium", desc: "Internet Message Access Protocol — email retrieval" },
  161: { name: "SNMP", risk: "high", desc: "Simple Network Management — default community strings leak system info" },
  162: { name: "SNMP Trap", risk: "medium", desc: "SNMP trap receiver" },
  389: { name: "LDAP", risk: "high", desc: "Lightweight Directory Access Protocol — AD enumeration target" },
  443: { name: "HTTPS", risk: "low", desc: "HTTP over TLS — encrypted web traffic" },
  445: { name: "SMB", risk: "critical", desc: "Server Message Block — EternalBlue, relay attacks, ransomware propagation" },
  464: { name: "Kerberos Change/Set", risk: "medium", desc: "Kerberos password change" },
  500: { name: "IKE", risk: "medium", desc: "Internet Key Exchange — VPN tunnel negotiation" },
  512: { name: "rexec", risk: "critical", desc: "Remote execution — no encryption, deprecated" },
  513: { name: "rlogin", risk: "critical", desc: "Remote login — no encryption, deprecated" },
  514: { name: "RSH/Syslog", risk: "high", desc: "Remote Shell (TCP) / Syslog (UDP) — unencrypted" },
  515: { name: "LPD", risk: "medium", desc: "Line Printer Daemon — printer exploitation" },
  523: { name: "IBM DB2", risk: "high", desc: "IBM DB2 database — default credentials common" },
  543: { name: "Klogin", risk: "high", desc: "Kerberos-encrypted rlogin" },
  544: { name: "Kshell", risk: "high", desc: "Kerberos-encrypted rshell" },
  548: { name: "AFP", risk: "medium", desc: "Apple Filing Protocol" },
  554: { name: "RTSP", risk: "medium", desc: "Real Time Streaming Protocol — camera/media streams" },
  587: { name: "SMTP Submission", risk: "low", desc: "Mail submission with STARTTLS" },
  593: { name: "MS-RPC/HTTP", risk: "high", desc: "RPC over HTTP — Exchange, SharePoint" },
  623: { name: "IPMI", risk: "critical", desc: "Intelligent Platform Management — IPMI cipher 0 allows auth bypass" },
  631: { name: "IPP/CUPS", risk: "medium", desc: "Internet Printing Protocol — printer attacks" },
  636: { name: "LDAPS", risk: "low", desc: "LDAP over TLS" },
  873: { name: "Rsync", risk: "high", desc: "Rsync — unauthenticated file access if misconfigured" },
  993: { name: "IMAPS", risk: "low", desc: "IMAP over TLS" },
  995: { name: "POP3S", risk: "low", desc: "POP3 over TLS" },
  1080: { name: "SOCKS", risk: "high", desc: "SOCKS proxy — can be abused for pivoting" },
  1099: { name: "Java RMI", risk: "critical", desc: "Java Remote Method Invocation — deserialization attacks" },
  1433: { name: "MSSQL", risk: "high", desc: "Microsoft SQL Server — xp_cmdshell RCE" },
  1434: { name: "MSSQL Browser", risk: "high", desc: "MSSQL UDP discovery — information disclosure" },
  1521: { name: "Oracle DB", risk: "high", desc: "Oracle Database TNS Listener" },
  1723: { name: "PPTP", risk: "high", desc: "Point-to-Point Tunneling — weak encryption, deprecated" },
  1883: { name: "MQTT", risk: "high", desc: "Message Queuing Telemetry Transport — IoT, often unauthenticated" },
  2049: { name: "NFS", risk: "high", desc: "Network File System — misconfigured exports leak files" },
  2181: { name: "ZooKeeper", risk: "high", desc: "Apache ZooKeeper — default no authentication" },
  2375: { name: "Docker API", risk: "critical", desc: "Docker Engine API unencrypted — full container/host compromise" },
  2376: { name: "Docker API TLS", risk: "medium", desc: "Docker Engine API with TLS" },
  3306: { name: "MySQL", risk: "high", desc: "MySQL database — UDF for RCE, many known CVEs" },
  3389: { name: "RDP", risk: "high", desc: "Remote Desktop Protocol — BlueKeep, brute force target" },
  4443: { name: "HTTPS Alt", risk: "low", desc: "Alternative HTTPS port" },
  5432: { name: "PostgreSQL", risk: "high", desc: "PostgreSQL database — COPY TO/FROM for file I/O" },
  5672: { name: "AMQP", risk: "medium", desc: "Advanced Message Queuing Protocol — RabbitMQ" },
  5900: { name: "VNC", risk: "high", desc: "Virtual Network Computing — often weak/no authentication" },
  5985: { name: "WinRM HTTP", risk: "high", desc: "Windows Remote Management — lateral movement via Evil-WinRM" },
  5986: { name: "WinRM HTTPS", risk: "medium", desc: "WinRM over HTTPS" },
  6379: { name: "Redis", risk: "critical", desc: "Redis — default no authentication, RCE via SLAVEOF or modules" },
  6443: { name: "Kubernetes API", risk: "critical", desc: "Kubernetes API Server — cluster takeover if exposed" },
  8080: { name: "HTTP Proxy/Alt", risk: "medium", desc: "HTTP alternative — common for proxies, dev servers, management interfaces" },
  8443: { name: "HTTPS Alt", risk: "low", desc: "HTTPS alternative port" },
  8888: { name: "HTTP Alt", risk: "medium", desc: "HTTP alternative — Jupyter notebooks, admin panels" },
  9090: { name: "Prometheus", risk: "medium", desc: "Prometheus metrics — information disclosure if exposed" },
  9200: { name: "Elasticsearch", risk: "critical", desc: "Elasticsearch — default no auth, data exfiltration" },
  9300: { name: "Elasticsearch Transport", risk: "critical", desc: "Elasticsearch inter-node communication" },
  11211: { name: "Memcached", risk: "high", desc: "Memcached — amplification attacks, data exfiltration" },
  27017: { name: "MongoDB", risk: "critical", desc: "MongoDB — default no authentication, massive data breaches" },
  27018: { name: "MongoDB Shard", risk: "critical", desc: "MongoDB shard server" },
  50000: { name: "SAP", risk: "high", desc: "SAP start service — many known vulnerabilities" },
};

// ─── Main render function ──────────────────────────────────────────────────
export function renderPacketCrafter(main) {
  // Current packet state
  let pkt = {
    ethernet: { dst: "ff:ff:ff:ff:ff:ff", src: "00:11:22:33:44:55", type: "0800" },
    ipv4: { version: 4, ihl: 5, dscp: 0, ecn: 0, ttl: 64, protocol: 6, src: "192.168.1.100", dst: "192.168.1.1", id: 54321, flags: 2, frag_offset: 0 },
    tcp: { src_port: 45678, dst_port: 80, seq: 1000, ack: 0, offset: 5, flags: 0x002, window: 65535, urg: 0 },
  };
  let activeTab = "builder";
  let activeRefProto = "ethernet";
  let selectedExport = "hex";

  function getLayerName() {
    if (pkt.arp) return "ARP";
    const proto = pkt.ipv4 ? pkt.ipv4.protocol : 0;
    if (pkt.tcp || proto === 6) return "TCP";
    if (pkt.udp || proto === 17) return "UDP";
    if (pkt.icmp || proto === 1) return "ICMP";
    return "Raw";
  }

  function detectAttacks() {
    const matched = [];
    for (const sig of ATTACK_SIGNATURES) {
      try { if (sig.check(pkt)) matched.push(sig); } catch (_) {}
    }
    return matched;
  }

  function render() {
    const bytes = buildPacketBytes(pkt);
    const attacks = detectAttacks();

    // Tab buttons
    let html = '<div class="pc-wrap">';
    html += '<div class="pc-tabs">';
    var tabs = [
      { id: "builder", label: "Packet Builder" },
      { id: "hexdump", label: "Hex Dump" },
      { id: "binary", label: "Binary View" },
      { id: "reference", label: "Field Reference" },
      { id: "templates", label: "Templates" },
      { id: "export", label: "Export" },
      { id: "checksums", label: "Checksums" },
      { id: "mtu", label: "MTU / Fragment" },
      { id: "seqnum", label: "Seq Analysis" },
      { id: "tcpfsm", label: "TCP States" },
      { id: "wireshark", label: "Wireshark Filter" },
      { id: "attacks", label: "Attack Detection" + (attacks.length ? " (" + attacks.length + ")" : "") },
    ];
    for (var t = 0; t < tabs.length; t++) {
      html += '<button class="pc-tab' + (activeTab === tabs[t].id ? " on" : "") + '" data-tab="' + tabs[t].id + '">' + esc(tabs[t].label) + '</button>';
    }
    html += '</div>';

    // Summary bar
    html += '<div class="pc-summary">';
    html += '<span class="pc-pill">Ethernet</span>';
    if (pkt.arp) html += '<span class="pc-pill">ARP</span>';
    if (pkt.ipv4) html += '<span class="pc-pill">IPv4</span>';
    if (pkt.ipv6) html += '<span class="pc-pill">IPv6</span>';
    if (pkt.tcp) html += '<span class="pc-pill">TCP</span>';
    if (pkt.udp) html += '<span class="pc-pill">UDP</span>';
    if (pkt.icmp) html += '<span class="pc-pill">ICMP</span>';
    if (pkt.dns) html += '<span class="pc-pill">DNS</span>';
    if (pkt.payload) html += '<span class="pc-pill">Payload</span>';
    html += '<span class="pc-size">' + bytes.length + ' bytes</span>';
    if (attacks.length) html += '<span class="pc-warn">' + attacks.length + ' attack pattern' + (attacks.length > 1 ? "s" : "") + ' detected</span>';
    html += '</div>';

    // Tab content
    html += '<div class="pc-body">';

    if (activeTab === "builder") {
      html += renderBuilder();
    } else if (activeTab === "hexdump") {
      html += '<pre class="pc-hex">' + esc(hexDump(bytes)) + '</pre>';
    } else if (activeTab === "binary") {
      html += '<pre class="pc-hex">' + esc(binaryDump(bytes)) + '</pre>';
    } else if (activeTab === "reference") {
      html += renderReference();
    } else if (activeTab === "templates") {
      html += renderTemplates();
    } else if (activeTab === "export") {
      html += renderExport(bytes);
    } else if (activeTab === "checksums") {
      html += renderChecksums(bytes);
    } else if (activeTab === "mtu") {
      html += renderMTU();
    } else if (activeTab === "seqnum") {
      html += renderSeqNum();
    } else if (activeTab === "tcpfsm") {
      html += renderTCPFSM();
    } else if (activeTab === "wireshark") {
      html += renderWireshark();
    } else if (activeTab === "attacks") {
      html += renderAttacks(attacks);
    }

    html += '</div></div>';

    // Only rebuild content area if tab bar already exists, otherwise build full page
    var existing = main.querySelector(".pc-body");
    if (existing && main.querySelector(".pc-tabs")) {
      // Update tab active states
      main.querySelectorAll(".pc-tab").forEach(function(t) { t.classList.toggle("on", t.dataset.tab === activeTab); });
      // Update summary
      var sumEl = main.querySelector(".pc-summary");
      if (sumEl) {
        var sumHtml = '<span class="pc-pill">Ethernet</span>';
        if (pkt.arp) sumHtml += '<span class="pc-pill">ARP</span>';
        if (pkt.ipv4) sumHtml += '<span class="pc-pill">IPv4</span>';
        if (pkt.ipv6) sumHtml += '<span class="pc-pill">IPv6</span>';
        if (pkt.tcp) sumHtml += '<span class="pc-pill">TCP</span>';
        if (pkt.udp) sumHtml += '<span class="pc-pill">UDP</span>';
        if (pkt.icmp) sumHtml += '<span class="pc-pill">ICMP</span>';
        if (pkt.dns) sumHtml += '<span class="pc-pill">DNS</span>';
        if (pkt.payload) sumHtml += '<span class="pc-pill">Payload</span>';
        sumHtml += '<span class="pc-size">' + bytes.length + ' bytes</span>';
        if (attacks.length) sumHtml += '<span class="pc-warn">' + attacks.length + ' attack pattern' + (attacks.length > 1 ? "s" : "") + ' detected</span>';
        sumEl.innerHTML = sumHtml;
      }
      // Only replace content body
      var contentHtml = '';
      if (activeTab === "builder") contentHtml = renderBuilder();
      else if (activeTab === "hexdump") contentHtml = '<pre class="pc-hex">' + esc(hexDump(bytes)) + '</pre>';
      else if (activeTab === "binary") contentHtml = '<pre class="pc-hex">' + esc(binaryDump(bytes)) + '</pre>';
      else if (activeTab === "reference") contentHtml = renderReference();
      else if (activeTab === "templates") contentHtml = renderTemplates();
      else if (activeTab === "export") contentHtml = renderExport(bytes);
      else if (activeTab === "checksums") contentHtml = renderChecksums(bytes);
      else if (activeTab === "mtu") contentHtml = renderMTU();
      else if (activeTab === "seqnum") contentHtml = renderSeqNum();
      else if (activeTab === "tcpfsm") contentHtml = renderTCPFSM();
      else if (activeTab === "wireshark") contentHtml = renderWireshark();
      else if (activeTab === "attacks") contentHtml = renderAttacks(attacks);
      existing.innerHTML = contentHtml;
      wireEvents();
      return;
    }

    main.innerHTML = '<h1 class="pg-h1">Packet Crafter</h1><p class="muted pg-sub">Visual packet builder with protocol analysis, checksums, attack detection, and multi-format export. All computation runs in your browser.</p>' + html;

    // Event handlers
    main.querySelector(".pc-tabs").onclick = function(e) {
      var btn = e.target.closest(".pc-tab");
      if (btn) { activeTab = btn.dataset.tab; render(); }
    };
    wireEvents();
  }

  function renderBuilder() {
    var html = '';

    // ── Ethernet Layer ──
    html += '<div class="pc-layer"><h3 class="pc-lh">Ethernet (Layer 2)</h3><div class="pc-fields">';
    html += inputHTML("pc-eth-dst", pkt.ethernet.dst, "Dst MAC", "text");
    html += inputHTML("pc-eth-src", pkt.ethernet.src, "Src MAC", "text");
    html += selectHTML("pc-eth-type", ETHER_TYPES, pkt.ethernet.type, "EtherType");
    html += '</div></div>';

    var ethType = pkt.ethernet.type;

    // ── ARP ──
    if (ethType === "0806") {
      html += '<div class="pc-layer"><h3 class="pc-lh">ARP</h3><div class="pc-fields">';
      var a = pkt.arp || { hw_type: 1, proto_type: 0x0800, hw_len: 6, proto_len: 4, opcode: 1, sender_mac: "00:11:22:33:44:55", sender_ip: "192.168.1.100", target_mac: "00:00:00:00:00:00", target_ip: "192.168.1.1" };
      html += selectHTML("pc-arp-op", ARP_OPCODES, a.opcode, "Opcode");
      html += inputHTML("pc-arp-smac", a.sender_mac, "Sender MAC", "text");
      html += inputHTML("pc-arp-sip", a.sender_ip, "Sender IP", "text");
      html += inputHTML("pc-arp-tmac", a.target_mac, "Target MAC", "text");
      html += inputHTML("pc-arp-tip", a.target_ip, "Target IP", "text");
      html += '</div></div>';
    }

    // ── IPv4 ──
    if (ethType === "0800" && pkt.ipv4) {
      html += '<div class="pc-layer"><h3 class="pc-lh">IPv4 (Layer 3)</h3><div class="pc-fields">';
      html += inputHTML("pc-ip-src", pkt.ipv4.src, "Source IP", "text");
      html += inputHTML("pc-ip-dst", pkt.ipv4.dst, "Destination IP", "text");
      html += inputHTML("pc-ip-ttl", pkt.ipv4.ttl, "TTL", "number", ' min="0" max="255"');
      html += selectHTML("pc-ip-proto", IP_PROTOCOLS, pkt.ipv4.protocol, "Protocol");
      html += inputHTML("pc-ip-id", pkt.ipv4.id, "Identification", "number", ' min="0" max="65535"');
      html += inputHTML("pc-ip-dscp", pkt.ipv4.dscp, "DSCP", "number", ' min="0" max="63"');
      html += inputHTML("pc-ip-ecn", pkt.ipv4.ecn, "ECN", "number", ' min="0" max="3"');
      html += '<label class="pc-label">IP Flags</label><div class="pc-flag-row">';
      html += checkboxHTML("pc-ip-df", (pkt.ipv4.flags & 2) !== 0, "DF (Don't Fragment)");
      html += checkboxHTML("pc-ip-mf", (pkt.ipv4.flags & 1) !== 0, "MF (More Fragments)");
      html += '</div>';
      html += inputHTML("pc-ip-frag", pkt.ipv4.frag_offset, "Fragment Offset", "number", ' min="0" max="8191"');
      html += '</div></div>';

      var proto = pkt.ipv4.protocol;

      // ── TCP ──
      if (proto === 6) {
        html += '<div class="pc-layer"><h3 class="pc-lh">TCP (Layer 4)</h3><div class="pc-fields">';
        var tcp = pkt.tcp || { src_port: 0, dst_port: 0, seq: 0, ack: 0, offset: 5, flags: 0, window: 65535, urg: 0 };
        html += inputHTML("pc-tcp-sport", tcp.src_port, "Source Port", "number", ' min="0" max="65535"');
        html += inputHTML("pc-tcp-dport", tcp.dst_port, "Destination Port", "number", ' min="0" max="65535"');
        html += inputHTML("pc-tcp-seq", tcp.seq, "Sequence Number", "number", ' min="0" max="4294967295"');
        html += inputHTML("pc-tcp-ack", tcp.ack, "Acknowledgment Number", "number", ' min="0" max="4294967295"');
        html += inputHTML("pc-tcp-win", tcp.window, "Window Size", "number", ' min="0" max="65535"');
        html += inputHTML("pc-tcp-urg", tcp.urg, "Urgent Pointer", "number", ' min="0" max="65535"');
        html += '<label class="pc-label">TCP Flags</label><div class="pc-flag-grid">';
        for (var f = 0; f < TCP_FLAGS.length; f++) {
          var flag = TCP_FLAGS[f];
          html += checkboxHTML("pc-tcp-f-" + flag.name.toLowerCase(), (tcp.flags & (1 << flag.bit)) !== 0, flag.name + " — " + flag.desc);
        }
        html += '</div>';
        html += '</div></div>';
        // Payload
        html += '<div class="pc-layer"><h3 class="pc-lh">Payload (optional)</h3>';
        html += '<textarea id="pc-payload" class="pc-textarea" rows="4" placeholder="Raw payload data (e.g. HTTP request)">' + esc(pkt.payload || "") + '</textarea>';
        html += '</div>';
      }

      // ── UDP ──
      if (proto === 17) {
        html += '<div class="pc-layer"><h3 class="pc-lh">UDP (Layer 4)</h3><div class="pc-fields">';
        var udp = pkt.udp || { src_port: 0, dst_port: 53, length: 0 };
        html += inputHTML("pc-udp-sport", udp.src_port, "Source Port", "number", ' min="0" max="65535"');
        html += inputHTML("pc-udp-dport", udp.dst_port, "Destination Port", "number", ' min="0" max="65535"');
        html += '</div></div>';

        // ── DNS ──
        if (udp.dst_port === 53 || udp.src_port === 53) {
          html += '<div class="pc-layer"><h3 class="pc-lh">DNS</h3><div class="pc-fields">';
          var dns = pkt.dns || { id: 0xABCD, qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0, qname: "example.com", qtype: 1, qclass: 1 };
          html += inputHTML("pc-dns-id", "0x" + (dns.id || 0).toString(16).toUpperCase(), "Transaction ID", "text");
          html += inputHTML("pc-dns-qname", dns.qname, "Query Name", "text");
          html += selectHTML("pc-dns-qtype", DNS_QTYPES, dns.qtype, "Query Type");
          html += selectHTML("pc-dns-qclass", DNS_CLASSES, dns.qclass, "Query Class");
          html += '<label class="pc-label">DNS Flags</label><div class="pc-flag-row">';
          html += checkboxHTML("pc-dns-qr", dns.qr === 1, "QR (Response)");
          html += checkboxHTML("pc-dns-aa", dns.aa === 1, "AA (Authoritative)");
          html += checkboxHTML("pc-dns-tc", dns.tc === 1, "TC (Truncated)");
          html += checkboxHTML("pc-dns-rd", dns.rd === 1, "RD (Recursion Desired)");
          html += checkboxHTML("pc-dns-ra", dns.ra === 1, "RA (Recursion Available)");
          html += '</div>';
          html += '</div></div>';
        } else {
          html += '<div class="pc-layer"><h3 class="pc-lh">Payload (optional)</h3>';
          html += '<textarea id="pc-payload" class="pc-textarea" rows="4" placeholder="Raw UDP payload data">' + esc(pkt.payload || "") + '</textarea>';
          html += '</div>';
        }
      }

      // ── ICMP ──
      if (proto === 1) {
        html += '<div class="pc-layer"><h3 class="pc-lh">ICMP</h3><div class="pc-fields">';
        var icmp = pkt.icmp || { type: 8, code: 0, id: 0x1234, seq: 1 };
        html += selectHTML("pc-icmp-type", ICMP_TYPES.map(function(it) { return { value: it.type + ":" + it.code, label: it.label }; }), icmp.type + ":" + icmp.code, "Type / Code");
        html += inputHTML("pc-icmp-id", icmp.id, "Identifier", "number", ' min="0" max="65535"');
        html += inputHTML("pc-icmp-seq", icmp.seq, "Sequence Number", "number", ' min="0" max="65535"');
        html += '</div></div>';
      }
    }

    return html;
  }

  function renderReference() {
    var protos = Object.keys(FIELD_REFERENCE);
    var html = '<div class="pc-ref-tabs">';
    for (var p = 0; p < protos.length; p++) {
      html += '<button class="pc-tab pc-ref-btn' + (activeRefProto === protos[p] ? " on" : "") + '" data-rp="' + protos[p] + '">' + esc(protos[p].toUpperCase()) + '</button>';
    }
    html += '</div>';
    var fields = FIELD_REFERENCE[activeRefProto] || {};
    html += '<table class="pc-table"><thead><tr><th>Field</th><th>Bits</th><th>Description</th><th>Security Implications</th></tr></thead><tbody>';
    var keys = Object.keys(fields);
    for (var k = 0; k < keys.length; k++) {
      var f = fields[keys[k]];
      html += '<tr><td class="pc-fn">' + esc(f.name) + '</td><td>' + f.bits + '</td><td>' + esc(f.desc) + '</td><td class="pc-sec">' + esc(f.security) + '</td></tr>';
    }
    html += '</tbody></table>';
    return html;
  }

  function renderTemplates() {
    var html = '<div class="pc-tpl-grid">';
    var names = Object.keys(TEMPLATES);
    for (var i = 0; i < names.length; i++) {
      var tpl = TEMPLATES[names[i]];
      html += '<div class="pc-tpl-card" data-tpl="' + esc(names[i]) + '">';
      html += '<div class="pc-tpl-name">' + esc(names[i]) + '</div>';
      html += '<div class="pc-tpl-desc">' + esc(tpl.desc) + '</div>';
      html += '<button class="btn pc-tpl-btn" data-tpl="' + esc(names[i]) + '">Load Template</button>';
      html += '</div>';
    }
    html += '</div>';
    return html;
  }

  function renderExport(bytes) {
    var formats = [
      { id: "hex", label: "Hex String" },
      { id: "carray", label: "C Array" },
      { id: "scapy", label: "Python Scapy" },
      { id: "raw", label: "Raw Bytes (Octal)" },
    ];
    var html = '<div class="pc-exp-tabs">';
    for (var i = 0; i < formats.length; i++) {
      html += '<button class="pc-tab' + (selectedExport === formats[i].id ? " on" : "") + '" data-exp="' + formats[i].id + '">' + esc(formats[i].label) + '</button>';
    }
    html += '</div>';
    var code = "";
    if (selectedExport === "hex") code = toHexString(bytes);
    else if (selectedExport === "carray") code = toCArray(bytes, "packet");
    else if (selectedExport === "scapy") code = toScapy(pkt);
    else if (selectedExport === "raw") code = toRawBytes(bytes);
    html += '<pre class="pc-hex pc-export-code">' + esc(code) + '</pre>';
    html += '<button class="btn" id="pc-copy-export">Copy to Clipboard</button>';
    return html;
  }

  function renderChecksums(bytes) {
    var html = '<div class="pc-ck-grid">';
    if (pkt.ipv4) {
      var ihl = pkt.ipv4.ihl || 5;
      var ethLen = pkt.ethernet ? 14 : 0;
      var ipHeader = bytes.slice(ethLen, ethLen + ihl * 4);
      var zeroed = ipHeader.slice();
      zeroed[10] = 0; zeroed[11] = 0;
      var computed = ipChecksum(new Uint8Array(zeroed));
      var stored = (ipHeader[10] << 8) | ipHeader[11];
      html += '<div class="pc-ck-card">';
      html += '<div class="pc-ck-title">IP Header Checksum</div>';
      html += '<div>Computed: <code>0x' + computed.toString(16).padStart(4, "0").toUpperCase() + '</code></div>';
      html += '<div>Stored: <code>0x' + stored.toString(16).padStart(4, "0").toUpperCase() + '</code></div>';
      html += '<div class="' + (computed === stored ? "pc-ck-ok" : "pc-ck-fail") + '">' + (computed === stored ? "VALID" : "MISMATCH") + '</div>';
      html += '</div>';

      if (pkt.tcp) {
        var tcpStart = ethLen + ihl * 4;
        var tcpData = bytes.slice(tcpStart);
        var tcpZeroed = tcpData.slice();
        tcpZeroed[16] = 0; tcpZeroed[17] = 0;
        var tcpCk = tcpChecksum(pkt.ipv4.src, pkt.ipv4.dst, new Uint8Array(tcpZeroed));
        var tcpStored = (tcpData[16] << 8) | tcpData[17];
        html += '<div class="pc-ck-card">';
        html += '<div class="pc-ck-title">TCP Checksum (with pseudo-header)</div>';
        html += '<div>Computed: <code>0x' + tcpCk.toString(16).padStart(4, "0").toUpperCase() + '</code></div>';
        html += '<div>Stored: <code>0x' + tcpStored.toString(16).padStart(4, "0").toUpperCase() + '</code></div>';
        html += '<div class="' + (tcpCk === tcpStored ? "pc-ck-ok" : "pc-ck-fail") + '">' + (tcpCk === tcpStored ? "VALID" : "MISMATCH") + '</div>';
        html += '<div class="pc-ck-note">Pseudo-header: ' + esc(pkt.ipv4.src) + ' -> ' + esc(pkt.ipv4.dst) + ', Proto=6, TCP Len=' + tcpData.length + '</div>';
        html += '</div>';
      }

      if (pkt.udp) {
        var udpStart = ethLen + ihl * 4;
        var udpData = bytes.slice(udpStart);
        var udpZeroed = udpData.slice();
        udpZeroed[6] = 0; udpZeroed[7] = 0;
        var udpCk = udpChecksum(pkt.ipv4.src, pkt.ipv4.dst, new Uint8Array(udpZeroed));
        var udpStored = (udpData[6] << 8) | udpData[7];
        html += '<div class="pc-ck-card">';
        html += '<div class="pc-ck-title">UDP Checksum (with pseudo-header)</div>';
        html += '<div>Computed: <code>0x' + udpCk.toString(16).padStart(4, "0").toUpperCase() + '</code></div>';
        html += '<div>Stored: <code>0x' + udpStored.toString(16).padStart(4, "0").toUpperCase() + '</code></div>';
        html += '<div class="' + (udpCk === udpStored ? "pc-ck-ok" : "pc-ck-fail") + '">' + (udpCk === udpStored ? "VALID" : "MISMATCH") + '</div>';
        html += '</div>';
      }

      if (pkt.icmp) {
        var icmpStart = ethLen + ihl * 4;
        var icmpData = bytes.slice(icmpStart);
        var icmpZeroed = icmpData.slice();
        icmpZeroed[2] = 0; icmpZeroed[3] = 0;
        var icmpCk = ipChecksum(new Uint8Array(icmpZeroed));
        var icmpStored = (icmpData[2] << 8) | icmpData[3];
        html += '<div class="pc-ck-card">';
        html += '<div class="pc-ck-title">ICMP Checksum</div>';
        html += '<div>Computed: <code>0x' + icmpCk.toString(16).padStart(4, "0").toUpperCase() + '</code></div>';
        html += '<div>Stored: <code>0x' + icmpStored.toString(16).padStart(4, "0").toUpperCase() + '</code></div>';
        html += '<div class="' + (icmpCk === icmpStored ? "pc-ck-ok" : "pc-ck-fail") + '">' + (icmpCk === icmpStored ? "VALID" : "MISMATCH") + '</div>';
        html += '</div>';
      }
    }
    html += '</div>';
    return html;
  }

  function renderMTU() {
    var totalLen = pkt.ipv4 ? (buildPacketBytes(pkt).length - (pkt.ethernet ? 14 : 0)) : 0;
    var mtu = 1500;
    var frags = totalLen ? mtuCalc(totalLen, mtu) : [];
    var html = '<div class="pc-mtu">';
    html += '<h3>MTU / Fragmentation Calculator</h3>';
    html += '<div class="pc-fields">';
    html += inputHTML("pc-mtu-val", mtu, "MTU (bytes)", "number", ' min="68" max="65535"');
    html += '<div class="pc-label">Current packet IP size: <strong>' + totalLen + ' bytes</strong></div>';
    html += '</div>';
    if (totalLen <= mtu) {
      html += '<div class="pc-ck-ok" style="margin:12px 0">No fragmentation needed — packet fits within MTU.</div>';
    } else {
      html += '<div class="pc-ck-fail" style="margin:12px 0">Packet exceeds MTU — ' + frags.length + ' fragments required.</div>';
      html += '<table class="pc-table"><thead><tr><th>#</th><th>Offset (8-byte units)</th><th>Size (bytes)</th><th>MF Flag</th></tr></thead><tbody>';
      for (var i = 0; i < frags.length; i++) {
        html += '<tr><td>' + (i + 1) + '</td><td>' + frags[i].offset + '</td><td>' + frags[i].size + '</td><td>' + (frags[i].mf ? "1 (More)" : "0 (Last)") + '</td></tr>';
      }
      html += '</tbody></table>';
    }
    html += '</div>';
    return html;
  }

  function renderSeqNum() {
    var html = '<div class="pc-seq">';
    html += '<h3>TCP Sequence Number Analysis</h3>';
    if (!pkt.tcp) {
      html += '<div class="muted">Select TCP protocol to analyze sequence numbers.</div>';
    } else {
      var payloadLen = pkt.payload ? pkt.payload.length : 0;
      var analysis = seqAnalysis(pkt.tcp.seq, payloadLen || 1, pkt.tcp.window);
      html += '<table class="pc-table"><tbody>';
      html += '<tr><td>ISN (Initial Sequence Number)</td><td><code>' + analysis.isn + '</code> (0x' + analysis.isn.toString(16).toUpperCase() + ')</td></tr>';
      html += '<tr><td>Next Sequence Number</td><td><code>' + analysis.nextSeq + '</code></td></tr>';
      html += '<tr><td>Expected ACK from peer</td><td><code>' + analysis.ackExpected + '</code></td></tr>';
      html += '<tr><td>Window start</td><td><code>' + analysis.windowStart + '</code></td></tr>';
      html += '<tr><td>Window end</td><td><code>' + analysis.windowEnd + '</code></td></tr>';
      html += '<tr><td>Bytes in flight</td><td><code>' + analysis.bytesInFlight + '</code></td></tr>';
      html += '<tr><td>Distance to wrap</td><td><code>' + analysis.wrapDistance + '</code> bytes</td></tr>';
      html += '<tr><td>Will wrap?</td><td>' + (analysis.willWrap ? '<span class="pc-warn">Yes</span>' : 'No') + '</td></tr>';
      html += '</tbody></table>';
      html += '<div class="pc-seq-note">';
      html += '<strong>ISN Security:</strong> Modern OSes (Linux 4.2+, Windows 10+) use RFC 6528 to generate cryptographically random ISNs. ';
      html += 'Predictable ISNs (incremental, time-based) allow blind TCP session hijacking and IP spoofing attacks. ';
      html += 'Tools like <code>hping3 --seqnum</code> can test ISN predictability.';
      html += '</div>';
    }
    html += '</div>';
    return html;
  }

  function renderTCPFSM() {
    var html = '<div class="pc-fsm">';
    html += '<h3>TCP State Machine</h3>';
    html += '<table class="pc-table"><thead><tr><th>From State</th><th>To State</th><th>Trigger</th><th>Description</th></tr></thead><tbody>';
    for (var i = 0; i < TCP_STATES.length; i++) {
      var s = TCP_STATES[i];
      html += '<tr><td><code>' + esc(s.from) + '</code></td><td><code>' + esc(s.to) + '</code></td><td>' + esc(s.trigger) + '</td><td>' + esc(s.desc) + '</td></tr>';
    }
    html += '</tbody></table>';
    html += '<div class="pc-fsm-note">';
    html += '<strong>Normal 3-way handshake:</strong> CLOSED → SYN_SENT → ESTABLISHED (client) | LISTEN → SYN_RCVD → ESTABLISHED (server)<br>';
    html += '<strong>Normal close:</strong> ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED (active) | ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED (passive)<br>';
    html += '<strong>TIME_WAIT:</strong> Lasts 2×MSL (typically 60-120s). Ensures late segments don\'t corrupt new connections on the same port. SYN floods can exhaust TIME_WAIT slots.';
    html += '</div>';
    html += '</div>';
    return html;
  }

  function renderWireshark() {
    var filter = wiresharkFilter(pkt);
    var html = '<div class="pc-ws">';
    html += '<h3>Wireshark Display Filter</h3>';
    html += '<pre class="pc-hex pc-ws-filter">' + esc(filter) + '</pre>';
    html += '<button class="btn" id="pc-copy-ws">Copy Filter</button>';
    html += '<div class="pc-ws-note">';
    html += '<strong>Usage:</strong> Paste this filter into the Wireshark display filter bar to capture packets matching your crafted packet\'s characteristics. ';
    html += 'Combine with capture filters like <code>host ' + esc(pkt.ipv4 ? pkt.ipv4.dst : "x.x.x.x") + '</code> for targeted captures.';
    html += '</div>';

    // Port lookup
    if (pkt.tcp || pkt.udp) {
      var port = pkt.tcp ? pkt.tcp.dst_port : (pkt.udp ? pkt.udp.dst_port : 0);
      var svc = SERVICE_FINGERPRINTS[port];
      if (svc) {
        html += '<div class="pc-svc">';
        html += '<h4>Service: ' + esc(svc.name) + ' (port ' + port + ')</h4>';
        html += '<div>Risk: <span class="pc-risk-' + svc.risk + '">' + svc.risk.toUpperCase() + '</span></div>';
        html += '<div>' + esc(svc.desc) + '</div>';
        html += '</div>';
      }
    }
    html += '</div>';
    return html;
  }

  function renderAttacks(attacks) {
    var html = '<div class="pc-attacks">';
    html += '<h3>Attack Pattern Detection</h3>';
    if (!attacks.length) {
      html += '<div class="pc-ck-ok">No known attack patterns detected in this packet.</div>';
    } else {
      for (var i = 0; i < attacks.length; i++) {
        var a = attacks[i];
        html += '<div class="pc-atk pc-atk-' + a.severity + '">';
        html += '<div class="pc-atk-name">' + esc(a.name) + ' <span class="pc-atk-sev">' + a.severity.toUpperCase() + '</span></div>';
        html += '<div class="pc-atk-desc">' + esc(a.desc) + '</div>';
        html += '</div>';
      }
    }
    html += '<div class="pc-attacks-note">';
    html += '<strong>Note:</strong> This detector checks the crafted packet against ' + ATTACK_SIGNATURES.length + ' known attack patterns. ';
    html += 'Real IDS/IPS systems like Snort and Suricata use thousands of rules with flow state tracking.';
    html += '</div>';
    html += '</div>';
    return html;
  }

  function wireEvents() {
    // Builder field changes
    var onChange = function() {
      // Ethernet
      var el;
      el = main.querySelector("#pc-eth-dst"); if (el) pkt.ethernet.dst = el.value;
      el = main.querySelector("#pc-eth-src"); if (el) pkt.ethernet.src = el.value;
      el = main.querySelector("#pc-eth-type"); if (el) {
        pkt.ethernet.type = el.value;
        if (el.value === "0806") {
          pkt.arp = pkt.arp || { hw_type: 1, proto_type: 0x0800, hw_len: 6, proto_len: 4, opcode: 1, sender_mac: pkt.ethernet.src, sender_ip: "192.168.1.100", target_mac: "00:00:00:00:00:00", target_ip: "192.168.1.1" };
          delete pkt.ipv4; delete pkt.tcp; delete pkt.udp; delete pkt.icmp; delete pkt.dns;
        } else if (el.value === "0800") {
          delete pkt.arp;
          pkt.ipv4 = pkt.ipv4 || { version: 4, ihl: 5, dscp: 0, ecn: 0, ttl: 64, protocol: 6, src: "192.168.1.100", dst: "192.168.1.1", id: 54321, flags: 2, frag_offset: 0 };
          pkt.tcp = pkt.tcp || { src_port: 45678, dst_port: 80, seq: 1000, ack: 0, offset: 5, flags: 0x002, window: 65535, urg: 0 };
        }
      }

      // ARP
      if (pkt.arp) {
        el = main.querySelector("#pc-arp-op"); if (el) pkt.arp.opcode = parseInt(el.value) || 1;
        el = main.querySelector("#pc-arp-smac"); if (el) pkt.arp.sender_mac = el.value;
        el = main.querySelector("#pc-arp-sip"); if (el) pkt.arp.sender_ip = el.value;
        el = main.querySelector("#pc-arp-tmac"); if (el) pkt.arp.target_mac = el.value;
        el = main.querySelector("#pc-arp-tip"); if (el) pkt.arp.target_ip = el.value;
      }

      // IPv4
      if (pkt.ipv4) {
        el = main.querySelector("#pc-ip-src"); if (el) pkt.ipv4.src = el.value;
        el = main.querySelector("#pc-ip-dst"); if (el) pkt.ipv4.dst = el.value;
        el = main.querySelector("#pc-ip-ttl"); if (el) pkt.ipv4.ttl = parseInt(el.value) || 0;
        el = main.querySelector("#pc-ip-id"); if (el) pkt.ipv4.id = parseInt(el.value) || 0;
        el = main.querySelector("#pc-ip-dscp"); if (el) pkt.ipv4.dscp = parseInt(el.value) || 0;
        el = main.querySelector("#pc-ip-ecn"); if (el) pkt.ipv4.ecn = parseInt(el.value) || 0;
        el = main.querySelector("#pc-ip-frag"); if (el) pkt.ipv4.frag_offset = parseInt(el.value) || 0;
        var df = main.querySelector("#pc-ip-df");
        var mf = main.querySelector("#pc-ip-mf");
        pkt.ipv4.flags = 0;
        if (df && df.checked) pkt.ipv4.flags |= 2;
        if (mf && mf.checked) pkt.ipv4.flags |= 1;

        el = main.querySelector("#pc-ip-proto");
        if (el) {
          var newProto = parseInt(el.value) || 6;
          if (newProto !== pkt.ipv4.protocol) {
            pkt.ipv4.protocol = newProto;
            delete pkt.tcp; delete pkt.udp; delete pkt.icmp; delete pkt.dns; delete pkt.payload;
            if (newProto === 6) pkt.tcp = { src_port: 45678, dst_port: 80, seq: 1000, ack: 0, offset: 5, flags: 0x002, window: 65535, urg: 0 };
            else if (newProto === 17) { pkt.udp = { src_port: 53421, dst_port: 53, length: 0 }; pkt.dns = { id: 0xABCD, qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0, qname: "example.com", qtype: 1, qclass: 1 }; }
            else if (newProto === 1) pkt.icmp = { type: 8, code: 0, id: 0x1234, seq: 1 };
            render();
            return;
          }
        }
      }

      // TCP
      if (pkt.tcp) {
        el = main.querySelector("#pc-tcp-sport"); if (el) pkt.tcp.src_port = parseInt(el.value) || 0;
        el = main.querySelector("#pc-tcp-dport"); if (el) pkt.tcp.dst_port = parseInt(el.value) || 0;
        el = main.querySelector("#pc-tcp-seq"); if (el) pkt.tcp.seq = parseInt(el.value) || 0;
        el = main.querySelector("#pc-tcp-ack"); if (el) pkt.tcp.ack = parseInt(el.value) || 0;
        el = main.querySelector("#pc-tcp-win"); if (el) pkt.tcp.window = parseInt(el.value) || 0;
        el = main.querySelector("#pc-tcp-urg"); if (el) pkt.tcp.urg = parseInt(el.value) || 0;
        var flags = 0;
        for (var f = 0; f < TCP_FLAGS.length; f++) {
          el = main.querySelector("#pc-tcp-f-" + TCP_FLAGS[f].name.toLowerCase());
          if (el && el.checked) flags |= (1 << TCP_FLAGS[f].bit);
        }
        pkt.tcp.flags = flags;
      }

      // UDP
      if (pkt.udp) {
        el = main.querySelector("#pc-udp-sport"); if (el) pkt.udp.src_port = parseInt(el.value) || 0;
        el = main.querySelector("#pc-udp-dport"); if (el) pkt.udp.dst_port = parseInt(el.value) || 0;
      }

      // DNS
      if (pkt.dns) {
        el = main.querySelector("#pc-dns-id"); if (el) pkt.dns.id = parseInt(el.value, 16) || parseInt(el.value) || 0;
        el = main.querySelector("#pc-dns-qname"); if (el) pkt.dns.qname = el.value;
        el = main.querySelector("#pc-dns-qtype"); if (el) pkt.dns.qtype = parseInt(el.value) || 1;
        el = main.querySelector("#pc-dns-qclass"); if (el) pkt.dns.qclass = parseInt(el.value) || 1;
        el = main.querySelector("#pc-dns-qr"); if (el) pkt.dns.qr = el.checked ? 1 : 0;
        el = main.querySelector("#pc-dns-aa"); if (el) pkt.dns.aa = el.checked ? 1 : 0;
        el = main.querySelector("#pc-dns-tc"); if (el) pkt.dns.tc = el.checked ? 1 : 0;
        el = main.querySelector("#pc-dns-rd"); if (el) pkt.dns.rd = el.checked ? 1 : 0;
        el = main.querySelector("#pc-dns-ra"); if (el) pkt.dns.ra = el.checked ? 1 : 0;
      }

      // ICMP
      if (pkt.icmp) {
        el = main.querySelector("#pc-icmp-type");
        if (el) {
          var parts = el.value.split(":");
          pkt.icmp.type = parseInt(parts[0]) || 0;
          pkt.icmp.code = parseInt(parts[1]) || 0;
        }
        el = main.querySelector("#pc-icmp-id"); if (el) pkt.icmp.id = parseInt(el.value) || 0;
        el = main.querySelector("#pc-icmp-seq"); if (el) pkt.icmp.seq = parseInt(el.value) || 0;
      }

      // Payload
      el = main.querySelector("#pc-payload"); if (el) pkt.payload = el.value || undefined;
      if (!pkt.payload) delete pkt.payload;
    };

    // Bind all inputs
    var inputs = main.querySelectorAll(".pc-input, .pc-select, .pc-textarea, .pc-chk-label input");
    for (var i = 0; i < inputs.length; i++) {
      inputs[i].addEventListener("input", onChange);
      inputs[i].addEventListener("change", onChange);
    }

    // Template buttons
    var tplBtns = main.querySelectorAll(".pc-tpl-btn");
    for (var t = 0; t < tplBtns.length; t++) {
      tplBtns[t].addEventListener("click", function(e) {
        var name = e.target.dataset.tpl;
        var tpl = TEMPLATES[name];
        if (tpl) {
          pkt = JSON.parse(JSON.stringify(tpl));
          activeTab = "builder";
          render();
        }
      });
    }

    // Reference protocol tabs
    var refBtns = main.querySelectorAll(".pc-ref-btn");
    for (var r = 0; r < refBtns.length; r++) {
      refBtns[r].addEventListener("click", function(e) {
        activeRefProto = e.target.dataset.rp;
        render();
      });
    }

    // Export format tabs
    var expBtns = main.querySelectorAll("[data-exp]");
    for (var x = 0; x < expBtns.length; x++) {
      expBtns[x].addEventListener("click", function(e) {
        selectedExport = e.target.dataset.exp;
        render();
      });
    }

    // Copy buttons
    var copyExp = main.querySelector("#pc-copy-export");
    if (copyExp) {
      copyExp.addEventListener("click", function() {
        var code = main.querySelector(".pc-export-code");
        if (code) navigator.clipboard.writeText(code.textContent).then(function() { copyExp.textContent = "Copied!"; setTimeout(function() { copyExp.textContent = "Copy to Clipboard"; }, 2000); });
      });
    }
    var copyWs = main.querySelector("#pc-copy-ws");
    if (copyWs) {
      copyWs.addEventListener("click", function() {
        var code = main.querySelector(".pc-ws-filter");
        if (code) navigator.clipboard.writeText(code.textContent).then(function() { copyWs.textContent = "Copied!"; setTimeout(function() { copyWs.textContent = "Copy Filter"; }, 2000); });
      });
    }
  }

  render();
}
