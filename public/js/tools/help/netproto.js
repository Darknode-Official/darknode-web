// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Plain-English help for the netproto.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "np-ethernet-decode": {
    what: "Reads the first bytes of an Ethernet frame (the wrapper every LAN packet travels in) and shows the two hardware (MAC) addresses and the EtherType that says what is inside. Also spots a VLAN tag.",
    when: "You captured a frame in hex (for example from Wireshark's byte view) and want to read its destination, source and payload type.",
    example: { hex: "ffffffffffff 001122334455 0806" },
  },
  "np-vlan-decode": {
    what: "Decodes an IEEE 802.1Q VLAN tag into its parts: the priority, the drop-eligible bit, and the VLAN ID (which numbered virtual LAN the frame belongs to).",
    when: "You have the 4-byte tag (or just the 2-byte TCI) from a trunk-port capture and need to read the VLAN number and priority.",
    example: { hex: "8100 0064" },
  },
  "np-arp-decode": {
    what: "Reads an ARP packet (the messages that match an IP address to a hardware MAC address on a LAN) and shows whether it is a request or reply plus the sender and target addresses.",
    when: "You are analysing LAN traffic or suspected ARP spoofing and want to read who is asking for, or claiming, which IP.",
    example: { hex: "0001 0800 06 04 0001 001122334455 c0000201 000000000000 c0000202" },
  },
  "np-ipv4-decode": {
    what: "Breaks a 20-byte IPv4 header (pasted as hex) into every field: version, length, priority (DSCP/ECN), fragmentation flags, time-to-live, the protocol inside, checksum and the source and destination addresses.",
    when: "You are inspecting a captured packet and want a full, labelled read-out of its IPv4 header instead of counting bytes by hand.",
    example: { hex: "4500 003c 1c46 4000 4006 b1e6 c0000201 c0000202" },
  },
  "np-ipv6-decode": {
    what: "Breaks a 40-byte IPv6 header (pasted as hex) into its fields: traffic class, flow label, payload length, the next-header protocol, hop limit, and the source and destination addresses.",
    when: "You captured an IPv6 packet and want its header fields spelled out, with the addresses shown in short form.",
    example: { hex: "6000000000140640 fe800000000000000000000000000001 fe800000000000000000000000000002" },
  },
  "np-tcp-decode": {
    what: "Breaks a TCP header (pasted as hex) into ports, sequence and acknowledgment numbers, all the flag bits (SYN, ACK, FIN and so on), the window size and any options.",
    when: "You are reading a captured TCP segment and want to see the connection details and which flags are set.",
    example: { hex: "0050 01bb 00000001 00000000 5002 2000 917c 0000" },
  },
  "np-udp-decode": {
    what: "Reads the 8-byte UDP header (pasted as hex) and shows the source port, destination port, length and checksum.",
    when: "You have a captured UDP datagram and want its ports and length without counting bytes.",
    example: { hex: "d431 0035 002a 1b2c" },
  },
  "np-icmp-decode": {
    what: "Reads an ICMP message (the control messages behind ping and 'host unreachable') from hex and names the type and code, plus extra fields like the echo id and sequence.",
    when: "You captured an ICMP packet and want to know whether it is an echo, an unreachable, a time-exceeded, and exactly which code.",
    example: { hex: "0800 f7ff 0001 0001" },
  },
  "np-tls-record-decode": {
    what: "Reads the 5-byte header that starts every TLS record (the encrypted web/transport security layer) and shows the content type, the version, and the record length.",
    when: "You captured the start of a TLS connection and want to tell a handshake from application data and read the version.",
    example: { hex: "16 0303 0040 01" },
  },
  "np-dns-decode": {
    what: "Decodes a DNS message (the question-and-answer format behind domain-name lookups) from hex: the ID, every header flag, the section counts, and the question name and type. It follows name-compression pointers.",
    when: "You captured a DNS query or reply and want to read what was asked and the response code, without a packet analyser.",
    example: { hex: "1234 0100 0001 0000 0000 0000 03 777777 07 6578616d706c65 03 636f6d 00 0001 0001" },
  },
  "np-dns-flags-decode": {
    what: "Takes the 16-bit DNS flags word (the third and fourth bytes of a DNS message) and spells out each bit: query or response, the operation, the authority bits, and the response code.",
    when: "You have just the DNS flags value (for example 0x8180) and want to know what state it describes.",
    example: { val: "0x8180" },
  },
  "np-dns-name-decode": {
    what: "Turns the DNS 'wire' form of a domain name (each part prefixed by its length, ending in a zero byte) back into a readable dotted name. It understands compression pointers within the given bytes.",
    when: "You pulled a name out of a DNS packet in hex and want to read it as example.com.",
    example: { hex: "03 777777 07 6578616d706c65 03 636f6d 00" },
  },
  "np-dns-name-encode": {
    what: "Turns a readable domain name into the DNS wire form: each label prefixed by its length and ended with a zero byte. Shows the resulting hex bytes.",
    when: "You are crafting a DNS packet by hand and need the exact bytes for a name.",
    example: { name: "www.example.com" },
  },
  "np-dns-query-build": {
    what: "Builds a complete DNS query packet (header plus the question) as hex for a name and record type, ready to send over UDP port 53.",
    when: "You want to test a DNS server with a raw query, or learn exactly what a lookup looks like on the wire.",
    example: { name: "example.com", type: "A", rd: true },
  },
  "np-dhcp-decode": {
    what: "Reads the fixed part of a DHCP/BOOTP packet (how devices get an IP address automatically) from hex: the operation, transaction id, the four address fields, the client's MAC, and the first options.",
    when: "You captured DHCP traffic and want to read which address was offered or requested and the key options.",
    example: { hex: "0101060039 03f3260000 00000000000 0c0000201 00000000 00000000 00112233445500000000000000000000" },
  },
  "np-ntp-decode": {
    what: "Reads an NTP time-synchronisation packet from hex: the version and mode, the stratum (how close it is to a reference clock), the poll and precision values, and the transmit time.",
    when: "You captured NTP traffic and want to see the server's stratum and the timestamp it sent.",
    example: { hex: "1b000000000000000000000000000000000000000000000000000000000000000000000000000000e5f20a8e00000000" },
  },
  "np-stun-decode": {
    what: "Reads a STUN message header (the protocol WebRTC and VoIP use to find their public address through NAT) from hex: the method and class, the length, the magic cookie, and the transaction id.",
    when: "You are debugging WebRTC or a VoIP call and captured a STUN packet you want to identify.",
    example: { hex: "0001 0000 2112a442 000102030405060708090a0b" },
  },
  "np-vxlan-decode": {
    what: "Reads the 8-byte VXLAN header (an overlay that tunnels Layer-2 frames across a Layer-3 network, common in data centres) and shows the flags and the 24-bit network identifier (VNI).",
    when: "You captured data-centre overlay traffic and want the VNI that says which virtual network a frame belongs to.",
    example: { hex: "08 000000 001389 00" },
  },
  "np-gre-decode": {
    what: "Reads a GRE tunnel header from hex and shows which optional fields are present (checksum, key, sequence), the version, and what protocol is being tunnelled.",
    when: "You captured GRE tunnel traffic (for example a site-to-site link) and want to read the header and the inner protocol.",
    example: { hex: "0000 0800" },
  },
  "np-mpls-decode": {
    what: "Reads one or more 4-byte MPLS label entries from hex and shows each label number, its traffic class, the bottom-of-stack bit, and its time-to-live.",
    when: "You captured an MPLS-labelled packet in a provider network and want to read the label stack.",
    example: { hex: "00 06 41 ff" },
  },
  "np-esp-decode": {
    what: "Reads the readable part of an IPsec ESP header (the encrypted tunnels used by VPNs) from hex: the Security Parameters Index and the sequence number. The rest of the payload is encrypted.",
    when: "You captured IPsec VPN traffic and want the SPI and sequence number that identify the security association.",
    example: { hex: "a1b2c3d4 00000001" },
  },
  "np-pcap-header": {
    what: "Reads the 24-byte header at the very start of a classic .pcap capture file and shows the byte order, the version, the snapshot length, and the link type (for example Ethernet).",
    when: "You are inspecting a raw capture file and want to confirm its format and link type before parsing packets.",
    example: { hex: "d4c3b2a1 0200 0400 00000000 00000000 ffff0000 01000000" },
  },
  "np-ipv4-checksum": {
    what: "Works out the IPv4 header checksum (the error-detecting number stored in the header) for pasted header bytes, or checks whether an existing one is correct.",
    when: "You are crafting or verifying an IPv4 header and need the checksum value, or want to confirm a captured one is valid.",
    example: { hex: "4500 003c 1c46 4000 4006 0000 c0000201 c0000202", mode: "Compute" },
  },
  "np-l4-checksum": {
    what: "Works out a TCP or UDP checksum, which also covers a small 'pseudo-header' made from the IP addresses. You paste the segment bytes and the two IP addresses.",
    when: "You are hand-building a TCP or UDP packet and need the correct checksum, which depends on the source and destination IPs.",
    example: { hex: "0050 01bb 00000001 00000000 5002 2000 0000 0000", src: "192.0.2.1", dst: "192.0.2.2", proto: "TCP" },
  },
  "np-ipv6-classify": {
    what: "Looks at an IPv6 address and tells you what kind it is: loopback, link-local, unique-local, multicast (with its scope), global, IPv4-mapped, documentation, and so on. Also shows its full and short forms.",
    when: "You see an IPv6 address and want to know whether it is routable on the internet, local to one link, or a special-purpose address.",
    example: { addr: "fe80::1" },
  },
  "np-ipv6-solicited-node": {
    what: "Builds the solicited-node multicast address for an IPv6 address. This is the small group that Neighbor Discovery (IPv6's version of ARP) listens on, and the matching Ethernet MAC.",
    when: "You are studying or debugging IPv6 Neighbor Discovery and need the solicited-node group for a given address.",
    example: { addr: "fe80::2aa:ff:fe28:9c5a" },
  },
  "np-mac-bits": {
    what: "Explains the meaning hidden in the first byte of a MAC (hardware) address: whether it is a one-to-one or a group address, and whether it is a real vendor address or a locally made-up one. Also spots broadcast.",
    when: "You see a MAC address and want to know if it is randomised/locally administered (common on phones) or a genuine vendor address, or if it is multicast.",
    example: { mac: "02:00:00:00:00:01" },
  },
  "np-multicast-mac": {
    what: "Converts an IPv4 or IPv6 multicast address (traffic sent to a group) into the matching Ethernet hardware (MAC) address that switches use to deliver it.",
    when: "You are configuring or debugging multicast and need the Layer-2 MAC that a given group maps to.",
    example: { addr: "239.255.255.250" },
  },
  "np-asn-convert": {
    what: "Converts an Autonomous System Number (the id of a network on the internet's routing system) between its plain number form and the dotted 'high.low' form.",
    when: "You are working with BGP routing and have an ASN in one notation but need the other.",
    example: { asn: "65536" },
  },
  "np-bgp-community": {
    what: "Converts a BGP community tag (a label routers attach to routes to signal policy) between the ASN:value form and its single-number form, and names well-known ones like NO_EXPORT.",
    when: "You are reading or writing BGP routing policy and need a community in a particular format.",
    example: { val: "65001:100" },
  },
  "np-mtu-mss": {
    what: "Works out the TCP Maximum Segment Size, which is how much data fits in one segment, by subtracting the IP and TCP headers from the link's maximum packet size (MTU).",
    when: "You are tuning a link or diagnosing fragmentation and need the right MSS for a given MTU.",
    example: { mtu: "1500", ipver: "IPv4", tsopt: false },
  },
  "np-ipv4-fragment": {
    what: "Shows how a large IP packet is split to fit a smaller maximum packet size (MTU): how many fragments, each one's size, its offset and whether more fragments follow.",
    when: "You are learning or debugging IP fragmentation and want to see exactly how a packet of a given size breaks up.",
    example: { total: "4000", mtu: "1500" },
  },
  "np-window-scale": {
    what: "Applies a TCP window scale factor: it multiplies the small window number in the header by two to the power of the scale shift to give the real receive window in bytes.",
    when: "You are reading a capture with window scaling and want the true window size, or you are estimating throughput.",
    example: { win: "8192", shift: "7" },
  },
  "np-bandwidth-time": {
    what: "Estimates how long it takes to move an amount of data over a link of a given speed, handling the bits-versus-bytes conversion for you.",
    when: "You want a quick idea of how long a transfer or backup should take at a given link rate. It is an ideal minimum, not a real-world figure.",
    example: { size: "10", sizeUnit: "GB", rate: "100", rateUnit: "Mbps" },
  },
  "np-propagation-delay": {
    what: "Estimates the minimum delay for a signal to travel a distance, there and back, based on how fast signals move in fibre, copper or open air.",
    when: "You want the floor on latency a link can have because of distance alone. Real latency is higher once switching and queuing are added.",
    example: { dist: "1000", medium: "Fiber (n~1.47)" },
  },
  "np-ntp-timestamp": {
    what: "Converts an NTP timestamp (the 64-bit time format used in time packets, counted from the year 1900) to a normal date, and converts a date back the other way.",
    when: "You pulled a timestamp out of an NTP packet and want to read it as a human date, or you need the NTP form of a date.",
    example: { val: "0xe5f20a8e" },
  },
  "np-syslog-pri": {
    what: "Decodes the syslog priority number (the value in angle brackets like <134> at the start of a log message) into the facility (which part of the system) and severity (how urgent), or builds it back.",
    when: "You are reading raw syslog messages and want to know which facility and severity a PRI value means.",
    example: { mode: "PRI -> facility+severity", pri: "134" },
  },
  "np-ip-protocols": {
    what: "Looks up the IANA IP protocol number, which is the field inside an IP packet that says what is carried next (6 is TCP, 17 is UDP, 1 is ICMP, and so on).",
    when: "You see a protocol number in an IP header or a firewall rule and want to know what it is.",
    example: { q: "tcp" },
  },
  "np-ethertypes": {
    what: "Looks up an EtherType, the two-byte code in an Ethernet frame that says what protocol is inside (0x0800 is IPv4, 0x0806 is ARP, 0x86DD is IPv6).",
    when: "You see an EtherType value in a capture and want to know the protocol it names.",
    example: { q: "arp" },
  },
  "np-icmp-types": {
    what: "Looks up ICMP (IPv4) message types and their codes, such as the different reasons for a 'Destination Unreachable' message.",
    when: "You see an ICMP type and code in a capture or a firewall log and want their meaning.",
    example: { q: "echo" },
  },
  "np-icmpv6-types": {
    what: "Looks up ICMPv6 message types, including the Neighbor Discovery messages that IPv6 uses in place of ARP, and multicast listener messages.",
    when: "You are reading IPv6 control traffic and want to identify a message type such as Router Advertisement or Neighbor Solicitation.",
    example: { q: "neighbor" },
  },
  "np-dns-rcodes": {
    what: "Looks up DNS operation codes and response codes, such as NXDOMAIN (name does not exist) or SERVFAIL (server failure).",
    when: "You see a DNS response code and want to know what went right or wrong with a lookup.",
    example: { q: "nxdomain" },
  },
  "np-dns-type-codes": {
    what: "Looks up the numeric DNS record type codes used on the wire (1 is A, 28 is AAAA, 15 is MX), the numbers you need when reading a DNS packet by hand.",
    when: "You are decoding a raw DNS message and see a type number you need to turn into a record name.",
    example: { q: "aaaa" },
  },
  "np-dhcp-options": {
    what: "Looks up DHCP option codes, the numbered settings a DHCP server hands out (like subnet mask, router, DNS server, lease time).",
    when: "You are reading a DHCP packet or server config and see an option number you need to identify.",
    example: { q: "lease" },
  },
  "np-dhcp-message-types": {
    what: "Looks up the DHCP message types that drive address assignment: DISCOVER, OFFER, REQUEST, ACK and the rest.",
    when: "You are following the DHCP handshake in a capture and want to name each message.",
    example: { q: "discover" },
  },
  "np-dhcpv6-message-types": {
    what: "Looks up the DHCPv6 message types used to assign IPv6 addresses (SOLICIT, ADVERTISE, REQUEST, REPLY), which differ from the IPv4 ones.",
    when: "You are debugging IPv6 address assignment and want to name a DHCPv6 message.",
    example: { q: "solicit" },
  },
  "np-http2-frames": {
    what: "Looks up HTTP/2 frame types, the building blocks of an HTTP/2 connection (DATA, HEADERS, SETTINGS, PING and so on).",
    when: "You are inspecting an HTTP/2 connection and see a frame type number or name you want explained.",
    example: { q: "settings" },
  },
  "np-http2-settings": {
    what: "Looks up HTTP/2 SETTINGS parameters, the connection options the two sides agree on, such as the maximum number of streams or the flow-control window size.",
    when: "You are reading an HTTP/2 SETTINGS frame and want to know what each parameter controls.",
    example: { q: "window" },
  },
  "np-http2-errors": {
    what: "Looks up HTTP/2 error codes used when a stream or the whole connection is reset, such as REFUSED_STREAM or PROTOCOL_ERROR.",
    when: "You see an HTTP/2 connection or stream being closed with an error code and want its meaning.",
    example: { q: "refused" },
  },
  "np-tls-record-types": {
    what: "Looks up the TLS record content types, the number at the start of each TLS record that says whether it is a handshake, an alert, or application data.",
    when: "You are reading a TLS capture and want to tell what kind of record you are looking at.",
    example: { q: "handshake" },
  },
  "np-tls-handshake-types": {
    what: "Looks up TLS handshake message types for TLS 1.2 and 1.3, such as ClientHello, ServerHello, Certificate and Finished.",
    when: "You are following a TLS handshake in a capture and want to name each message by its type number.",
    example: { q: "hello" },
  },
  "np-tls-extensions": {
    what: "Looks up TLS extension types, the add-ons carried in the Hello messages, such as the server name (SNI), the ALPN protocol list, or key share.",
    when: "You are inspecting a ClientHello or ServerHello and see an extension number you want to identify.",
    example: { q: "sni" },
  },
  "np-tls-alerts": {
    what: "Looks up TLS alert descriptions, the codes a TLS endpoint sends when something is wrong, such as handshake_failure or unknown_ca.",
    when: "You see a TLS connection fail with an alert and want to know what the code means.",
    example: { q: "handshake" },
  },
  "np-tcp-options": {
    what: "Looks up TCP option kinds, the extras that follow the main TCP header, such as Maximum Segment Size, Window Scale, SACK and Timestamps.",
    when: "You are reading TCP options in a capture and see a kind number you want to identify.",
    example: { q: "sack" },
  },
  "np-tcp-states": {
    what: "Explains the TCP connection states, the stages a connection moves through from opening to closing, such as ESTABLISHED, TIME-WAIT and CLOSE-WAIT.",
    when: "You see a state in netstat or a diagram and want to know what the connection is doing in that state.",
    example: { q: "time-wait" },
  },
  "np-dscp-reference": {
    what: "Converts between a DiffServ quality-of-service name (like EF or AF31) and its 6-bit value, or looks one up by number. These mark how a packet should be prioritised.",
    when: "You are configuring or reading quality-of-service markings and need the value for a name, or the name for a value.",
    example: { q: "EF" },
  },
  "np-snmp-oids": {
    what: "Looks up common SNMP object identifiers (the dotted numbers that name a piece of device information), such as the system name or an interface's byte counters.",
    when: "You are polling a device with SNMP and need the OID for a well-known value, or want to identify an OID you see.",
    example: { q: "uptime" },
  },
  "np-snmp-pdu-types": {
    what: "Looks up SNMP versions and the message (PDU) types, such as GetRequest, SetRequest and Trap.",
    when: "You are decoding SNMP traffic and want to name a PDU type or confirm a version number.",
    example: { q: "trap" },
  },
  "np-well-known-multicast": {
    what: "Looks up reserved multicast groups for IPv4 and IPv6, the addresses set aside for jobs like routing protocols, mDNS/Bonjour and UPnP discovery.",
    when: "You see a multicast address in a capture and want to know what service it belongs to.",
    example: { q: "mdns" },
  },
  "np-linktype": {
    what: "Looks up the link-layer type numbers used in capture files (for example 1 for Ethernet, 105 for Wi-Fi), which tell a reader how to parse each packet's start.",
    when: "You opened a capture file and need to know what the link type number means.",
    example: { q: "ethernet" },
  },
  "np-radius-codes": {
    what: "Looks up RADIUS packet codes, used by the login/authentication servers behind Wi-Fi and VPN sign-ins, such as Access-Request and Access-Accept.",
    when: "You are debugging network authentication (AAA) and see a RADIUS code you want to identify.",
    example: { q: "challenge" },
  },
  "np-quic-terms": {
    what: "Explains QUIC and HTTP/3 terms in plain language, such as connection id, 0-RTT, streams and the different packet number spaces.",
    when: "You are learning or debugging QUIC/HTTP3 and want a quick, plain-English definition of a term.",
    example: { q: "0-rtt" },
  },
  "np-dns-edns": {
    what: "Explains the EDNS0 OPT record, the modern extension that lets DNS use larger messages and DNSSEC, and optionally decodes its reused TTL field into the version and the DNSSEC-OK bit.",
    when: "You are studying DNS extensions or reading an OPT record and want to understand its fields.",
    example: { ttl: "0x00008000" },
  },
  "np-wireshark-filter": {
    what: "Builds a Wireshark display-filter expression from simple fields (protocol, host, port, direction). This is the syntax you type in Wireshark's filter bar, which differs from tcpdump's capture filters.",
    when: "You want to narrow a capture in Wireshark to a protocol, host or port and would rather fill in boxes than remember the syntax.",
    example: { proto: "tcp", host: "192.0.2.10", port: "443" },
  },
};
