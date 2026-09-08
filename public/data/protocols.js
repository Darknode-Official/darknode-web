/**
 * protocols.js -- Comprehensive Network Protocol Reference for Security Testing
 *
 * Copyright (c) 2026 Darknode Project
 * All rights reserved.
 *
 * This file provides structured documentation of network protocols, packet
 * structures, Wireshark filters, and Nmap NSE scripts for use in security
 * testing and network analysis workflows.
 *
 * WARNING: These tools and techniques are intended for authorized security
 * testing only. Unauthorized access to computer systems is illegal.
 *
 * Author: SpartanKing18
 * Last updated: 2026-09-07
 */

// ---------------------------------------------------------------------------
// 1. PROTOCOLS -- 80+ network protocols with security-relevant metadata
// ---------------------------------------------------------------------------

export const PROTOCOLS = [
  // ---- Core TCP/IP Stack ----
  {
    name: "IPv4",
    port: null,
    transport: "Network Layer",
    description: "Internet Protocol version 4 -- primary network layer protocol responsible for addressing and routing packets across networks using 32-bit addresses.",
    securityNotes: "No built-in authentication or encryption. Susceptible to spoofing, fragmentation attacks, and man-in-the-middle interception. TTL manipulation can bypass firewalls.",
    commonVulns: [
      "IP spoofing",
      "Fragmentation overlap attacks (teardrop)",
      "Source routing abuse",
      "LAND attack (src == dst)",
      "Ping of Death (oversized ICMP)"
    ],
    testingCommands: [
      "nmap -sn 192.168.1.0/24",
      "hping3 -S -a <spoofed_ip> -p 80 <target>",
      "scapy: send(IP(dst='target', options=[IPOption_LSRR()])/ICMP())"
    ],
    relatedCVEs: ["CVE-1999-0016", "CVE-1999-0015", "CVE-2008-4609"]
  },
  {
    name: "IPv6",
    port: null,
    transport: "Network Layer",
    description: "Internet Protocol version 6 -- successor to IPv4 with 128-bit addresses, simplified header, and mandatory IPsec support capability.",
    securityNotes: "Extension headers can be abused to bypass firewalls and IDS. Router advertisement spoofing enables MITM. Many networks have IPv6 enabled but unmonitored.",
    commonVulns: [
      "Router Advertisement spoofing",
      "Extension header chain abuse",
      "Neighbor Discovery Protocol spoofing",
      "Rogue DHCPv6 server",
      "IPv6 tunnel injection"
    ],
    testingCommands: [
      "nmap -6 <target>",
      "thc-ipv6: alive6 eth0",
      "parasite6 eth0 (ND spoofing)",
      "fake_router6 eth0 <attacker_ip>"
    ],
    relatedCVEs: ["CVE-2020-16898", "CVE-2021-24086", "CVE-2023-23415"]
  },
  {
    name: "TCP",
    port: null,
    transport: "Transport Layer",
    description: "Transmission Control Protocol -- connection-oriented transport protocol providing reliable, ordered, error-checked delivery of data between applications.",
    securityNotes: "Three-way handshake is vulnerable to SYN flood attacks. Sequence number prediction enables session hijacking. RST injection can terminate connections.",
    commonVulns: [
      "SYN flood denial of service",
      "TCP sequence prediction / session hijacking",
      "RST injection / connection reset",
      "TCP timestamp side-channel leaks",
      "Idle scan (zombie scan) for stealth recon"
    ],
    testingCommands: [
      "nmap -sS <target> (SYN scan)",
      "nmap -sT <target> (connect scan)",
      "hping3 --flood -S -p 80 <target>",
      "nmap -sI <zombie> <target> (idle scan)"
    ],
    relatedCVEs: ["CVE-2004-0230", "CVE-2008-4609", "CVE-2019-11477"]
  },
  {
    name: "UDP",
    port: null,
    transport: "Transport Layer",
    description: "User Datagram Protocol -- connectionless transport protocol offering minimal overhead for applications that can tolerate packet loss.",
    securityNotes: "No handshake makes source IP spoofing trivial. UDP amplification attacks leverage services with large response-to-request ratios. Stateless nature complicates firewall filtering.",
    commonVulns: [
      "UDP amplification / reflection DDoS",
      "UDP flood attacks",
      "Source IP spoofing",
      "DNS/NTP/SSDP amplification",
      "UDP port scan evasion"
    ],
    testingCommands: [
      "nmap -sU <target>",
      "nmap -sU --top-ports 100 <target>",
      "hping3 --udp -p 53 <target>",
      "unicornscan -mU <target>:1-65535"
    ],
    relatedCVEs: ["CVE-2013-5211", "CVE-2014-0160"]
  },
  {
    name: "ICMP",
    port: null,
    transport: "Network Layer",
    description: "Internet Control Message Protocol -- used for diagnostic and error reporting in IP networks including ping, traceroute, and destination unreachable messages.",
    securityNotes: "Can be used for covert channels (ICMP tunneling). Smurf attacks use directed broadcast with spoofed source. ICMP redirect messages can alter routing tables.",
    commonVulns: [
      "ICMP tunnel / covert channel",
      "Smurf attack (broadcast amplification)",
      "ICMP redirect routing manipulation",
      "Ping of Death",
      "ICMP-based OS fingerprinting"
    ],
    testingCommands: [
      "ping -c 4 <target>",
      "traceroute <target>",
      "nmap -sn -PE <target> (ICMP echo discovery)",
      "icmpsh (reverse ICMP shell)",
      "ptunnel (ICMP tunnel)"
    ],
    relatedCVEs: ["CVE-1999-0015", "CVE-2004-0790", "CVE-2023-23415"]
  },
  {
    name: "ARP",
    port: null,
    transport: "Data Link Layer",
    description: "Address Resolution Protocol -- maps IPv4 addresses to MAC addresses on local network segments. Fundamental to Ethernet communication.",
    securityNotes: "No authentication mechanism. ARP spoofing/poisoning is trivial on local networks and enables MITM attacks, traffic interception, and denial of service.",
    commonVulns: [
      "ARP spoofing / cache poisoning",
      "ARP flood (CAM table overflow)",
      "Gratuitous ARP abuse",
      "ARP-based MITM",
      "MAC spoofing via ARP manipulation"
    ],
    testingCommands: [
      "arpspoof -i eth0 -t <victim> <gateway>",
      "ettercap -T -q -i eth0 -M arp:remote /<target1>// /<target2>//",
      "bettercap -iface eth0 -eval 'set arp.spoof.targets <target>; arp.spoof on'",
      "arping -c 4 <target>"
    ],
    relatedCVEs: ["CVE-2008-2927", "CVE-2016-6564"]
  },

  // ---- Web Protocols ----
  {
    name: "HTTP",
    port: 80,
    transport: "TCP",
    description: "Hypertext Transfer Protocol -- application layer protocol for distributed, collaborative, hypermedia information systems. Foundation of data communication on the World Wide Web.",
    securityNotes: "Plaintext protocol vulnerable to eavesdropping and modification. No integrity or confidentiality. HTTP request smuggling exploits parsing differences between front/back-end servers.",
    commonVulns: [
      "HTTP request smuggling (CL.TE, TE.CL)",
      "HTTP response splitting / header injection",
      "HTTP verb tampering",
      "Host header injection",
      "HTTP desync attacks",
      "Slow HTTP DoS (Slowloris, R-U-Dead-Yet)"
    ],
    testingCommands: [
      "curl -v http://<target>/",
      "nikto -h http://<target>",
      "dirb http://<target>/",
      "gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt",
      "slowhttptest -c 1000 -H -g -o output -i 10 -r 200 -t GET -u http://<target> -x 24 -p 3"
    ],
    relatedCVEs: ["CVE-2023-25690", "CVE-2023-44487", "CVE-2021-22947"]
  },
  {
    name: "HTTPS",
    port: 443,
    transport: "TCP (TLS)",
    description: "HTTP over TLS -- encrypted version of HTTP using Transport Layer Security to provide confidentiality, integrity, and server authentication.",
    securityNotes: "Security depends on proper TLS configuration. Vulnerable to certificate pinning bypass, TLS downgrade attacks, and misconfigured cipher suites. HSTS preloading recommended.",
    commonVulns: [
      "SSL stripping (via MITM)",
      "TLS downgrade attacks (POODLE, DROWN)",
      "Certificate validation bypass",
      "Weak cipher suite negotiation",
      "CRIME/BREACH compression attacks",
      "Mixed content vulnerabilities"
    ],
    testingCommands: [
      "sslscan <target>:443",
      "testssl.sh <target>",
      "sslyze --regular <target>",
      "nmap --script ssl-enum-ciphers -p 443 <target>",
      "curl -vk https://<target>/"
    ],
    relatedCVEs: ["CVE-2014-3566", "CVE-2016-0800", "CVE-2014-0224", "CVE-2015-0204"]
  },
  {
    name: "HTTP/2",
    port: 443,
    transport: "TCP (TLS)",
    description: "Major revision of HTTP with multiplexed streams, header compression (HPACK), server push, and binary framing for improved performance.",
    securityNotes: "Multiplexing introduces new attack surfaces including stream priority abuse and rapid reset attacks. HPACK compression can leak information. Implementation bugs in frame handling common.",
    commonVulns: [
      "Rapid Reset attack (HTTP/2 DDoS)",
      "Stream multiplexing abuse",
      "HPACK bombing",
      "Header flooding",
      "Settings flood",
      "Ping flood"
    ],
    testingCommands: [
      "curl --http2 -v https://<target>/",
      "h2spec <target>:443",
      "nghttp -v https://<target>/",
      "nmap --script http2-enum -p 443 <target>"
    ],
    relatedCVEs: ["CVE-2023-44487", "CVE-2019-9511", "CVE-2019-9512", "CVE-2019-9513"]
  },
  {
    name: "HTTP/3 (QUIC)",
    port: 443,
    transport: "UDP (QUIC)",
    description: "Third major version of HTTP, built on QUIC transport protocol over UDP. Provides built-in encryption, reduced latency with 0-RTT handshakes, and improved multiplexing.",
    securityNotes: "UDP-based transport may bypass traditional firewalls. 0-RTT replay attacks possible. Connection migration feature introduces new tracking vectors.",
    commonVulns: [
      "0-RTT replay attacks",
      "Connection ID tracking",
      "UDP amplification vectors",
      "Version negotiation downgrade",
      "Firewall bypass via UDP"
    ],
    testingCommands: [
      "curl --http3 https://<target>/",
      "quiche-client https://<target>/",
      "ngtcp2-client <target> 443"
    ],
    relatedCVEs: ["CVE-2021-22903", "CVE-2023-32681"]
  },
  {
    name: "WebSocket",
    port: 80,
    transport: "TCP",
    description: "Full-duplex communication protocol over a single TCP connection, initiated via HTTP upgrade handshake. Enables real-time bidirectional data transfer.",
    securityNotes: "Cross-Site WebSocket Hijacking (CSWSH) if origin validation is missing. No CSRF tokens in upgrade handshake by default. Tunneling through WebSockets can bypass security controls.",
    commonVulns: [
      "Cross-Site WebSocket Hijacking",
      "Missing origin validation",
      "WebSocket message injection",
      "Insecure ws:// (unencrypted) usage",
      "DoS via message flooding"
    ],
    testingCommands: [
      "websocat ws://<target>/ws",
      "wscat -c ws://<target>/ws",
      "Burp Suite WebSocket history tab",
      "nmap --script http-websocket -p 80 <target>"
    ],
    relatedCVEs: ["CVE-2020-27813", "CVE-2021-32640"]
  },
  {
    name: "gRPC",
    port: 50051,
    transport: "TCP (HTTP/2)",
    description: "High-performance RPC framework using Protocol Buffers over HTTP/2. Supports unary, server-streaming, client-streaming, and bidirectional streaming.",
    securityNotes: "Reflection service can expose API schema. Plaintext mode enables traffic interception. Lack of input validation on protobuf messages can cause crashes.",
    commonVulns: [
      "gRPC reflection information disclosure",
      "Protobuf deserialization issues",
      "Missing TLS (plaintext gRPC)",
      "Unauthenticated method access",
      "Large message DoS"
    ],
    testingCommands: [
      "grpcurl -plaintext <target>:50051 list",
      "grpcurl -plaintext <target>:50051 describe",
      "grpc_health_probe -addr=<target>:50051",
      "nmap -p 50051 --script=http2-enum <target>"
    ],
    relatedCVEs: ["CVE-2023-32731", "CVE-2023-33953"]
  },
  {
    name: "GraphQL",
    port: 443,
    transport: "TCP (HTTP/HTTPS)",
    description: "API query language allowing clients to request specific data structures. Typically served over HTTP at a single endpoint.",
    securityNotes: "Introspection queries expose full schema. Nested query attacks cause DoS. Batching enables brute force. Authorization often implemented inconsistently across resolvers.",
    commonVulns: [
      "Introspection information disclosure",
      "Nested query DoS (query depth attack)",
      "Batch query brute forcing",
      "IDOR via relay node IDs",
      "Field suggestion information leak",
      "SQL injection in resolvers"
    ],
    testingCommands: [
      "curl -X POST -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}' http://<target>/graphql",
      "graphql-voyager (visualization)",
      "InQL Burp extension",
      "clairvoyance (schema discovery without introspection)"
    ],
    relatedCVEs: ["CVE-2021-41248", "CVE-2022-37315"]
  },

  // ---- DNS ----
  {
    name: "DNS",
    port: 53,
    transport: "UDP/TCP",
    description: "Domain Name System -- hierarchical distributed naming system translating domain names to IP addresses. Uses UDP for standard queries and TCP for zone transfers and large responses.",
    securityNotes: "Cache poisoning can redirect traffic. Zone transfers may leak internal network info. DNS tunneling exfiltrates data. DNSSEC adoption remains incomplete.",
    commonVulns: [
      "DNS cache poisoning (Kaminsky attack)",
      "DNS amplification DDoS",
      "DNS tunneling / data exfiltration",
      "Zone transfer information disclosure",
      "DNS rebinding attacks",
      "Subdomain takeover"
    ],
    testingCommands: [
      "dig @<dns_server> <domain> ANY",
      "dig @<dns_server> <domain> AXFR (zone transfer)",
      "dnsrecon -d <domain> -t std",
      "dnsenum <domain>",
      "fierce --domain <domain>",
      "nmap --script dns-brute <domain>"
    ],
    relatedCVEs: ["CVE-2008-1447", "CVE-2020-1350", "CVE-2021-20322"]
  },
  {
    name: "DNS over HTTPS (DoH)",
    port: 443,
    transport: "TCP (HTTPS)",
    description: "DNS queries and responses encrypted via HTTPS, preventing eavesdropping and manipulation of DNS traffic by network intermediaries.",
    securityNotes: "Bypasses traditional DNS monitoring and filtering. Can be used as a covert channel. Enterprise visibility into DNS queries is lost without endpoint controls.",
    commonVulns: [
      "Bypass of DNS-based security controls",
      "Covert data exfiltration channel",
      "Enterprise monitoring evasion",
      "DNS-over-HTTPS tunnel abuse"
    ],
    testingCommands: [
      "curl -H 'accept: application/dns-json' 'https://dns.google/resolve?name=<domain>&type=A'",
      "dog <domain> --https @https://cloudflare-dns.com/dns-query",
      "doh-client -s https://dns.google/dns-query -t A <domain>"
    ],
    relatedCVEs: ["CVE-2019-14855"]
  },
  {
    name: "DNS over TLS (DoT)",
    port: 853,
    transport: "TCP (TLS)",
    description: "DNS queries encrypted via TLS on a dedicated port, providing confidentiality while remaining distinguishable from other traffic for network policy enforcement.",
    securityNotes: "Dedicated port (853) makes it easy to identify and block, unlike DoH. Still prevents content inspection of DNS queries by intermediaries.",
    commonVulns: [
      "TLS downgrade to plaintext DNS",
      "Certificate validation bypass",
      "Port-based blocking evasion"
    ],
    testingCommands: [
      "kdig -d @853 +tls <domain>",
      "openssl s_client -connect <resolver>:853"
    ],
    relatedCVEs: []
  },
  {
    name: "mDNS",
    port: 5353,
    transport: "UDP (Multicast)",
    description: "Multicast DNS -- resolves hostnames to IP addresses on small networks without a local name server. Used by Bonjour (Apple) and Avahi (Linux).",
    securityNotes: "No authentication allows spoofing. Information disclosure of network services. Can be abused for reconnaissance on local networks.",
    commonVulns: [
      "mDNS spoofing / poisoning",
      "Service enumeration / reconnaissance",
      "mDNS reflection amplification",
      "Name collision attacks"
    ],
    testingCommands: [
      "avahi-browse -a",
      "mdns-scan",
      "nmap --script dns-service-discovery -p 5353 <target>",
      "responder -I eth0 (mDNS poisoning)"
    ],
    relatedCVEs: ["CVE-2020-12108", "CVE-2017-6519"]
  },

  // ---- Email Protocols ----
  {
    name: "SMTP",
    port: 25,
    transport: "TCP",
    description: "Simple Mail Transfer Protocol -- standard protocol for sending email messages between servers and from clients to servers.",
    securityNotes: "Plaintext by default. VRFY/EXPN commands enumerate users. Open relays enable spam. SPF/DKIM/DMARC essential but often misconfigured.",
    commonVulns: [
      "Open relay abuse",
      "SMTP user enumeration (VRFY/EXPN/RCPT TO)",
      "Email spoofing (missing SPF/DKIM/DMARC)",
      "SMTP injection",
      "STARTTLS stripping",
      "Auth brute force"
    ],
    testingCommands: [
      "nmap -p 25 --script smtp-commands,smtp-enum-users,smtp-open-relay <target>",
      "smtp-user-enum -M VRFY -U users.txt -t <target>",
      "swaks --to victim@domain --from attacker@domain --server <target>",
      "telnet <target> 25"
    ],
    relatedCVEs: ["CVE-2019-10149", "CVE-2020-28018", "CVE-2021-3156"]
  },
  {
    name: "SMTPS",
    port: 465,
    transport: "TCP (TLS)",
    description: "SMTP over implicit TLS -- encrypted email submission using TLS from connection start. Revived as standard in RFC 8314.",
    securityNotes: "Relies on proper TLS configuration. Certificate validation important. Legacy implementations may support weak ciphers.",
    commonVulns: [
      "Weak TLS cipher suites",
      "Certificate validation bypass",
      "Credential brute force",
      "Downgrade to plaintext"
    ],
    testingCommands: [
      "openssl s_client -connect <target>:465",
      "sslscan <target>:465",
      "nmap --script ssl-enum-ciphers -p 465 <target>"
    ],
    relatedCVEs: ["CVE-2014-3566"]
  },
  {
    name: "SMTP Submission",
    port: 587,
    transport: "TCP (STARTTLS)",
    description: "Mail submission port for authenticated clients to submit outbound email. Requires STARTTLS upgrade and authentication before accepting messages.",
    securityNotes: "STARTTLS upgrade can be stripped by MITM. Authentication credentials sent after upgrade. Must enforce TLS before auth.",
    commonVulns: [
      "STARTTLS stripping",
      "Credential interception pre-TLS",
      "Auth brute force",
      "Misconfigured relay after auth"
    ],
    testingCommands: [
      "openssl s_client -starttls smtp -connect <target>:587",
      "swaks --to test@domain --server <target> --port 587 --tls",
      "nmap -p 587 --script smtp-commands <target>"
    ],
    relatedCVEs: ["CVE-2011-0411"]
  },
  {
    name: "POP3",
    port: 110,
    transport: "TCP",
    description: "Post Office Protocol version 3 -- retrieves email from a remote server, typically downloading and deleting messages from the server.",
    securityNotes: "Plaintext authentication by default. Credentials visible on the wire. STLS upgrade available but not always enforced.",
    commonVulns: [
      "Plaintext credential interception",
      "Auth brute force",
      "STLS stripping",
      "Buffer overflow in implementations"
    ],
    testingCommands: [
      "nmap -p 110 --script pop3-capabilities,pop3-brute <target>",
      "telnet <target> 110",
      "hydra -l <user> -P <passlist> <target> pop3"
    ],
    relatedCVEs: ["CVE-2007-1558", "CVE-2014-3566"]
  },
  {
    name: "POP3S",
    port: 995,
    transport: "TCP (TLS)",
    description: "POP3 over implicit TLS -- encrypted email retrieval providing confidentiality for authentication and message content.",
    securityNotes: "Depends on TLS configuration quality. Client certificate auth adds security but is rarely implemented.",
    commonVulns: [
      "Weak TLS ciphers",
      "Auth brute force",
      "Certificate pinning bypass"
    ],
    testingCommands: [
      "openssl s_client -connect <target>:995",
      "sslscan <target>:995",
      "nmap --script ssl-enum-ciphers -p 995 <target>"
    ],
    relatedCVEs: []
  },
  {
    name: "IMAP",
    port: 143,
    transport: "TCP",
    description: "Internet Message Access Protocol -- manages email on a remote server with folder support, search capabilities, and multi-client synchronization.",
    securityNotes: "Plaintext auth by default. STARTTLS available but must be enforced. IMAP IDLE long connections increase interception window.",
    commonVulns: [
      "Plaintext credential interception",
      "STARTTLS stripping",
      "Auth brute force",
      "IMAP injection",
      "Mailbox enumeration"
    ],
    testingCommands: [
      "nmap -p 143 --script imap-capabilities,imap-brute <target>",
      "telnet <target> 143",
      "hydra -l <user> -P <passlist> <target> imap"
    ],
    relatedCVEs: ["CVE-2019-11356", "CVE-2021-33515"]
  },
  {
    name: "IMAPS",
    port: 993,
    transport: "TCP (TLS)",
    description: "IMAP over implicit TLS -- encrypted email management providing confidentiality for all IMAP operations.",
    securityNotes: "TLS configuration quality determines security. Must verify server certificate to prevent MITM.",
    commonVulns: [
      "Weak TLS configuration",
      "Auth brute force over TLS",
      "Certificate validation issues"
    ],
    testingCommands: [
      "openssl s_client -connect <target>:993",
      "sslscan <target>:993",
      "nmap --script ssl-enum-ciphers -p 993 <target>"
    ],
    relatedCVEs: []
  },

  // ---- File Transfer ----
  {
    name: "FTP",
    port: 21,
    transport: "TCP",
    description: "File Transfer Protocol -- standard protocol for transferring files between client and server. Uses separate control (21) and data channels.",
    securityNotes: "Plaintext authentication and data transfer. Anonymous FTP often misconfigured. Active mode opens client-side ports. Bounce attack uses PORT command.",
    commonVulns: [
      "Plaintext credential interception",
      "Anonymous FTP access",
      "FTP bounce attack (port scanning via FTP)",
      "Directory traversal",
      "Writable directories for malware staging",
      "PASV response manipulation"
    ],
    testingCommands: [
      "nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor <target>",
      "hydra -l <user> -P <passlist> <target> ftp",
      "ftp <target>",
      "wget -r ftp://anonymous:anonymous@<target>/"
    ],
    relatedCVEs: ["CVE-2011-2523", "CVE-2015-3306", "CVE-2019-12815"]
  },
  {
    name: "FTPS",
    port: 990,
    transport: "TCP (TLS)",
    description: "FTP over implicit TLS -- file transfer with encryption. Explicit FTPS (AUTH TLS on port 21) is more common in practice.",
    securityNotes: "Data channel encryption must also be negotiated (PROT P). Some clients fall back to plaintext data transfer silently.",
    commonVulns: [
      "Plaintext data channel fallback",
      "Certificate validation bypass",
      "Weak TLS ciphers",
      "CCC command downgrades control channel"
    ],
    testingCommands: [
      "openssl s_client -connect <target>:990",
      "curl --ftp-ssl ftp://<target>/",
      "lftp -e 'set ftp:ssl-force true' <target>"
    ],
    relatedCVEs: ["CVE-2014-3566"]
  },
  {
    name: "SFTP",
    port: 22,
    transport: "TCP (SSH)",
    description: "SSH File Transfer Protocol -- secure file transfer subsystem of SSH providing encrypted file access, transfer, and management.",
    securityNotes: "Inherits SSH security properties. Key management critical. Chroot misconfiguration can allow directory escape.",
    commonVulns: [
      "SSH key management failures",
      "Weak SSH credentials",
      "Chroot escape",
      "Symlink traversal",
      "SFTP-only restriction bypass"
    ],
    testingCommands: [
      "sftp <user>@<target>",
      "nmap -p 22 --script ssh-brute <target>",
      "hydra -l <user> -P <passlist> <target> ssh"
    ],
    relatedCVEs: ["CVE-2018-15473", "CVE-2023-48795"]
  },
  {
    name: "TFTP",
    port: 69,
    transport: "UDP",
    description: "Trivial File Transfer Protocol -- simple lockstep file transfer protocol with no authentication. Used for PXE boot and network device firmware updates.",
    securityNotes: "No authentication or encryption whatsoever. Any network host can read/write files. Often used to exfiltrate configuration files from network devices.",
    commonVulns: [
      "Unauthenticated file access",
      "Configuration file exfiltration",
      "Directory traversal",
      "TFTP-based malware delivery",
      "Network device config theft"
    ],
    testingCommands: [
      "nmap -sU -p 69 --script tftp-enum <target>",
      "tftp <target> -c get /etc/passwd",
      "atftp --get --remote-file /etc/shadow --local-file shadow <target>",
      "msfconsole: use auxiliary/gather/tftp_fetch"
    ],
    relatedCVEs: ["CVE-2015-3633", "CVE-2019-12264"]
  },
  {
    name: "SCP",
    port: 22,
    transport: "TCP (SSH)",
    description: "Secure Copy Protocol -- file transfer using SSH for encryption and authentication. Being deprecated in favor of SFTP.",
    securityNotes: "Inherits SSH security. SCP client-side command injection vulnerability discovered in multiple implementations. Deprecated in OpenSSH 9.0+.",
    commonVulns: [
      "Client-side filename injection",
      "SSH credential attacks",
      "Command injection via filenames"
    ],
    testingCommands: [
      "scp <user>@<target>:/etc/passwd ./passwd",
      "nmap -p 22 --script ssh-auth-methods <target>"
    ],
    relatedCVEs: ["CVE-2019-6111", "CVE-2019-6109"]
  },

  // ---- Remote Access ----
  {
    name: "SSH",
    port: 22,
    transport: "TCP",
    description: "Secure Shell -- cryptographic network protocol for secure remote login, command execution, and tunneling over an unsecured network.",
    securityNotes: "Key exchange algorithm and cipher selection critical. Host key verification prevents MITM. Agent forwarding can be abused. Terrapin attack affects chacha20-poly1305.",
    commonVulns: [
      "Brute force / credential stuffing",
      "Username enumeration (timing)",
      "SSH agent forwarding hijacking",
      "Terrapin prefix truncation attack",
      "Weak key exchange algorithms",
      "Exposed private keys"
    ],
    testingCommands: [
      "nmap -p 22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods <target>",
      "ssh-audit <target>",
      "hydra -l root -P <passlist> <target> ssh",
      "ssh -o StrictHostKeyChecking=no <target>"
    ],
    relatedCVEs: ["CVE-2018-15473", "CVE-2023-48795", "CVE-2024-6387"]
  },
  {
    name: "Telnet",
    port: 23,
    transport: "TCP",
    description: "Telnet protocol -- provides bidirectional interactive text-oriented communication. All data transmitted in plaintext including credentials.",
    securityNotes: "Completely insecure -- all traffic including passwords sent in cleartext. Should never be used on untrusted networks. Still common on legacy systems and IoT devices.",
    commonVulns: [
      "Plaintext credential interception",
      "Session hijacking",
      "Brute force attacks",
      "Default credentials on embedded devices",
      "Environment variable manipulation"
    ],
    testingCommands: [
      "nmap -p 23 --script telnet-brute,telnet-ntlm-info <target>",
      "telnet <target>",
      "hydra -l admin -P <passlist> <target> telnet",
      "msfconsole: use auxiliary/scanner/telnet/telnet_login"
    ],
    relatedCVEs: ["CVE-2020-10188", "CVE-2018-17612"]
  },
  {
    name: "RDP",
    port: 3389,
    transport: "TCP/UDP",
    description: "Remote Desktop Protocol -- Microsoft proprietary protocol providing graphical remote access to Windows systems with encryption and authentication.",
    securityNotes: "BlueKeep and DejaBlue are critical RCE vulnerabilities. Network Level Authentication (NLA) should be enforced. Weak encryption modes still supported for compatibility.",
    commonVulns: [
      "BlueKeep (pre-auth RCE)",
      "Credential brute force",
      "MITM via weak encryption",
      "Session hijacking",
      "Clipboard data theft",
      "Pass-the-Hash via RDP"
    ],
    testingCommands: [
      "nmap -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info <target>",
      "xfreerdp /v:<target> /u:<user> /p:<pass>",
      "hydra -l <user> -P <passlist> <target> rdp",
      "crowbar -b rdp -s <target>/32 -u <user> -C <passlist>"
    ],
    relatedCVEs: ["CVE-2019-0708", "CVE-2019-1181", "CVE-2019-1182", "CVE-2012-0002"]
  },
  {
    name: "VNC",
    port: 5900,
    transport: "TCP",
    description: "Virtual Network Computing -- graphical desktop sharing protocol using the Remote Framebuffer (RFB) protocol. Platform independent.",
    securityNotes: "Many implementations use weak authentication. Encryption often not enabled by default. Password limited to 8 characters in some implementations.",
    commonVulns: [
      "No/weak authentication",
      "Plaintext traffic (no TLS)",
      "Password brute force (8-char limit)",
      "VNC authentication bypass",
      "Screenshot/keylogger via VNC"
    ],
    testingCommands: [
      "nmap -p 5900 --script vnc-info,vnc-brute <target>",
      "vncviewer <target>",
      "hydra -P <passlist> <target> vnc",
      "msfconsole: use auxiliary/scanner/vnc/vnc_login"
    ],
    relatedCVEs: ["CVE-2019-15678", "CVE-2019-15679", "CVE-2006-2369"]
  },

  // ---- Directory Services ----
  {
    name: "LDAP",
    port: 389,
    transport: "TCP",
    description: "Lightweight Directory Access Protocol -- open standard for accessing and maintaining distributed directory information services over an IP network.",
    securityNotes: "Plaintext by default. LDAP injection similar to SQL injection. Anonymous bind may expose directory data. STARTTLS upgrade available but not always enforced.",
    commonVulns: [
      "LDAP injection",
      "Anonymous bind information disclosure",
      "Plaintext credential interception",
      "STARTTLS stripping",
      "Password spraying",
      "LDAP pass-back attack"
    ],
    testingCommands: [
      "nmap -p 389 --script ldap-rootdse,ldap-search <target>",
      "ldapsearch -x -H ldap://<target> -b 'dc=domain,dc=com'",
      "ldapenum -H ldap://<target> -b 'dc=domain,dc=com'",
      "windapsearch -d <domain> --dc <target> --full"
    ],
    relatedCVEs: ["CVE-2017-8563", "CVE-2021-42278", "CVE-2021-42287"]
  },
  {
    name: "LDAPS",
    port: 636,
    transport: "TCP (TLS)",
    description: "LDAP over TLS -- encrypted directory access providing confidentiality for LDAP operations including authentication and data queries.",
    securityNotes: "Certificate validation critical. Channel binding tokens add MITM resistance. LDAP signing should be required.",
    commonVulns: [
      "Certificate validation bypass",
      "LDAP signing not required",
      "Channel binding not enforced",
      "Weak TLS configuration"
    ],
    testingCommands: [
      "openssl s_client -connect <target>:636",
      "ldapsearch -x -H ldaps://<target> -b 'dc=domain,dc=com'",
      "nmap --script ssl-enum-ciphers -p 636 <target>"
    ],
    relatedCVEs: ["CVE-2017-8563"]
  },
  {
    name: "Kerberos",
    port: 88,
    transport: "TCP/UDP",
    description: "Network authentication protocol using tickets issued by a Key Distribution Center (KDC) to prove identity. Core of Active Directory authentication.",
    securityNotes: "Kerberoasting extracts service ticket hashes for offline cracking. AS-REP roasting targets accounts without pre-auth. Golden/Silver tickets provide persistent access.",
    commonVulns: [
      "Kerberoasting (SPN-based hash extraction)",
      "AS-REP roasting",
      "Golden ticket attacks",
      "Silver ticket attacks",
      "Pass-the-ticket",
      "Unconstrained delegation abuse",
      "Diamond ticket attacks"
    ],
    testingCommands: [
      "GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc> -request (Kerberoasting)",
      "GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <dc> (AS-REP roast)",
      "nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='<domain>' <target>",
      "rubeus.exe kerberoast",
      "kerbrute userenum --dc <dc> -d <domain> users.txt"
    ],
    relatedCVEs: ["CVE-2014-6324", "CVE-2020-17049", "CVE-2022-33679"]
  },
  {
    name: "Active Directory (Global Catalog)",
    port: 3268,
    transport: "TCP",
    description: "LDAP access to the Global Catalog -- a partial, read-only replica of all objects in a multi-domain Active Directory forest.",
    securityNotes: "Exposes cross-domain enumeration. Anonymous access may reveal forest structure. Useful for AD reconnaissance.",
    commonVulns: [
      "Cross-domain enumeration",
      "Anonymous bind exposure",
      "Forest trust mapping"
    ],
    testingCommands: [
      "ldapsearch -x -H ldap://<target>:3268 -b 'dc=domain,dc=com'",
      "nmap -p 3268 --script ldap-rootdse <target>"
    ],
    relatedCVEs: ["CVE-2021-42278"]
  },

  // ---- Network Infrastructure ----
  {
    name: "DHCP",
    port: 67,
    transport: "UDP",
    description: "Dynamic Host Configuration Protocol -- automatically assigns IP addresses, subnet masks, gateways, and DNS servers to network clients.",
    securityNotes: "No authentication. Rogue DHCP servers can redirect traffic. DHCP starvation depletes address pool. DHCP snooping is the primary defense.",
    commonVulns: [
      "Rogue DHCP server (MITM)",
      "DHCP starvation / exhaustion",
      "DHCP spoofing",
      "Option injection (DNS, gateway)",
      "DHCP release/decline attacks"
    ],
    testingCommands: [
      "nmap -sU -p 67 --script dhcp-discover <target>",
      "dhcpig (DHCP exhaustion)",
      "yersinia -G (DHCP attacks)",
      "scapy: sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0',dst='255.255.255.255')/UDP(sport=68,dport=67)/BOOTP(chaddr=RandMAC())/DHCP(options=[('message-type','discover'),'end']))"
    ],
    relatedCVEs: ["CVE-2018-1111", "CVE-2019-6470"]
  },
  {
    name: "NTP",
    port: 123,
    transport: "UDP",
    description: "Network Time Protocol -- synchronizes clocks across networked computer systems to within milliseconds of UTC.",
    securityNotes: "Monlist command enables massive amplification attacks. Time manipulation can break Kerberos, certificates, and logging. NTS (NTP over TLS) adds authentication.",
    commonVulns: [
      "NTP amplification DDoS (monlist)",
      "Time manipulation attacks",
      "Kerberos token replay via time skew",
      "Mode 6/7 information disclosure",
      "Unauthenticated time setting"
    ],
    testingCommands: [
      "ntpq -p <target>",
      "nmap -sU -p 123 --script ntp-info,ntp-monlist <target>",
      "ntpdc -n -c monlist <target>",
      "ntpdate -q <target>"
    ],
    relatedCVEs: ["CVE-2013-5211", "CVE-2014-9295", "CVE-2016-9311"]
  },
  {
    name: "SNMP",
    port: 161,
    transport: "UDP",
    description: "Simple Network Management Protocol -- monitors and manages network devices. v1/v2c use community strings, v3 adds authentication and encryption.",
    securityNotes: "v1/v2c community strings sent in plaintext (often 'public'/'private'). Read community exposes system info. Write community enables device reconfiguration. Upgrade to SNMPv3.",
    commonVulns: [
      "Default community strings (public/private)",
      "Community string brute force",
      "Information disclosure (system, interface, route tables)",
      "Device reconfiguration via write access",
      "SNMP-based network mapping"
    ],
    testingCommands: [
      "nmap -sU -p 161 --script snmp-info,snmp-brute,snmp-sysdescr <target>",
      "snmpwalk -v2c -c public <target>",
      "onesixtyone -c community.txt <target>",
      "snmp-check <target>",
      "msfconsole: use auxiliary/scanner/snmp/snmp_enum"
    ],
    relatedCVEs: ["CVE-2017-6742", "CVE-2012-3268"]
  },
  {
    name: "SNMP Trap",
    port: 162,
    transport: "UDP",
    description: "SNMP Trap receiver port -- receives asynchronous notifications from SNMP-managed devices about significant events.",
    securityNotes: "Trap receivers often run with elevated privileges. Spoofed traps can trigger automated responses. Trap data may contain sensitive information.",
    commonVulns: [
      "Trap spoofing",
      "Information disclosure in trap data",
      "Trap-triggered action abuse"
    ],
    testingCommands: [
      "snmptrap -v2c -c public <target> '' 1.3.6.1.4.1.0 1.3.6.1.4.1.0.1 s 'test'",
      "nmap -sU -p 162 <target>"
    ],
    relatedCVEs: []
  },
  {
    name: "Syslog",
    port: 514,
    transport: "UDP/TCP",
    description: "Standard for message logging -- sends event notification messages across IP networks to a central syslog server for storage and analysis.",
    securityNotes: "UDP syslog has no authentication, encryption, or delivery guarantee. Log injection possible. Spoofed log messages can pollute SIEM. Use TLS syslog (RFC 5425).",
    commonVulns: [
      "Log injection / forging",
      "Syslog spoofing",
      "Plaintext log interception",
      "Syslog flood DoS",
      "SIEM evasion via log manipulation"
    ],
    testingCommands: [
      "logger -n <target> -P 514 'test message'",
      "nmap -sU -p 514 <target>",
      "nc -u <target> 514 <<< '<14>Test syslog message'"
    ],
    relatedCVEs: ["CVE-2014-3634", "CVE-2019-17041"]
  },

  // ---- File Sharing ----
  {
    name: "SMB/CIFS",
    port: 445,
    transport: "TCP",
    description: "Server Message Block -- network file sharing protocol used primarily on Windows networks for shared access to files, printers, and serial ports.",
    securityNotes: "EternalBlue (MS17-010) is one of the most exploited vulnerabilities ever. SMBv1 should be disabled. SMB signing prevents relay attacks. Null sessions can expose information.",
    commonVulns: [
      "EternalBlue (MS17-010) remote code execution",
      "SMB relay / NTLM relay",
      "Null session enumeration",
      "SMB share enumeration",
      "Pass-the-hash attacks",
      "PrintNightmare via SMB"
    ],
    testingCommands: [
      "nmap -p 445 --script smb-vuln-ms17-010,smb-enum-shares,smb-enum-users <target>",
      "smbclient -L //<target>/ -N",
      "enum4linux -a <target>",
      "crackmapexec smb <target> -u '' -p '' --shares",
      "smbmap -H <target>"
    ],
    relatedCVEs: ["CVE-2017-0144", "CVE-2020-0796", "CVE-2021-34527", "CVE-2022-24500"]
  },
  {
    name: "NetBIOS",
    port: 139,
    transport: "TCP",
    description: "NetBIOS Session Service -- legacy Windows networking protocol providing name resolution, session service, and datagram distribution.",
    securityNotes: "Exposes Windows machine names, workgroups, and logged-in users. NetBIOS name spoofing (NBNS poisoning) enables MITM. Should be disabled when not needed.",
    commonVulns: [
      "NetBIOS name service poisoning",
      "Network information disclosure",
      "Null session via NetBIOS",
      "NBNS spoofing for credential capture"
    ],
    testingCommands: [
      "nbtscan <target>/24",
      "nmap -sU -p 137 --script nbstat <target>",
      "nmblookup -A <target>",
      "responder -I eth0 (NBNS poisoning)"
    ],
    relatedCVEs: ["CVE-2017-0161"]
  },
  {
    name: "NFS",
    port: 2049,
    transport: "TCP/UDP",
    description: "Network File System -- distributed file system protocol allowing remote hosts to mount filesystems over a network as if they were local.",
    securityNotes: "Authentication based on IP/hostname easily spoofed. Root squashing can be bypassed. Exported with no_root_squash allows privilege escalation. Check showmount output.",
    commonVulns: [
      "Unauthenticated mount access",
      "Root squash bypass",
      "no_root_squash privilege escalation",
      "UID/GID spoofing",
      "NFS share enumeration"
    ],
    testingCommands: [
      "showmount -e <target>",
      "nmap -p 2049 --script nfs-ls,nfs-showmount,nfs-statfs <target>",
      "mount -t nfs <target>:/share /mnt/nfs",
      "rpcinfo -p <target>"
    ],
    relatedCVEs: ["CVE-2014-5207", "CVE-2019-3689"]
  },

  // ---- Database Protocols ----
  {
    name: "MySQL",
    port: 3306,
    transport: "TCP",
    description: "MySQL database server protocol -- provides client-server communication for MySQL/MariaDB relational database management systems.",
    securityNotes: "Authentication bypass vulnerabilities have occurred. Remote root access with blank passwords is common misconfiguration. UDF exploitation for RCE.",
    commonVulns: [
      "Default/blank root password",
      "Authentication bypass",
      "SQL injection (application level)",
      "UDF exploitation for command execution",
      "File read via LOAD DATA INFILE",
      "Privilege escalation via grants"
    ],
    testingCommands: [
      "nmap -p 3306 --script mysql-info,mysql-enum,mysql-brute,mysql-empty-password <target>",
      "mysql -h <target> -u root -p",
      "hydra -l root -P <passlist> <target> mysql",
      "msfconsole: use auxiliary/scanner/mysql/mysql_login"
    ],
    relatedCVEs: ["CVE-2012-2122", "CVE-2016-6662", "CVE-2021-2307"]
  },
  {
    name: "PostgreSQL",
    port: 5432,
    transport: "TCP",
    description: "PostgreSQL database wire protocol -- client-server communication for the PostgreSQL relational database system.",
    securityNotes: "pg_hba.conf controls access. Trust authentication allows passwordless login. COPY TO/FROM can read/write files. Large object functions enable file system access.",
    commonVulns: [
      "Trust authentication misconfiguration",
      "Default credentials (postgres/postgres)",
      "COPY TO/FROM file access",
      "Large object file read/write",
      "SQL injection to RCE via functions",
      "pg_read_file() information disclosure"
    ],
    testingCommands: [
      "nmap -p 5432 --script pgsql-brute <target>",
      "psql -h <target> -U postgres",
      "hydra -l postgres -P <passlist> <target> postgres",
      "pgcli -h <target> -U postgres"
    ],
    relatedCVEs: ["CVE-2019-9193", "CVE-2023-39417", "CVE-2024-0985"]
  },
  {
    name: "MSSQL",
    port: 1433,
    transport: "TCP",
    description: "Microsoft SQL Server protocol (TDS) -- Tabular Data Stream protocol for communication with SQL Server instances.",
    securityNotes: "xp_cmdshell enables OS command execution. sa account with weak password is common. SQL Server Browser on UDP 1434 enumerates instances. Linked servers can pivot.",
    commonVulns: [
      "xp_cmdshell command execution",
      "sa account brute force",
      "SQL injection to RCE",
      "Linked server abuse for pivoting",
      "Instance enumeration via browser",
      "CLR assembly exploitation"
    ],
    testingCommands: [
      "nmap -p 1433 --script ms-sql-info,ms-sql-brute,ms-sql-empty-password <target>",
      "mssqlclient.py <domain>/<user>:<pass>@<target>",
      "sqsh -S <target> -U sa -P <pass>",
      "crackmapexec mssql <target> -u <user> -p <pass> -x 'whoami'"
    ],
    relatedCVEs: ["CVE-2020-0618", "CVE-2019-1068"]
  },
  {
    name: "Oracle DB",
    port: 1521,
    transport: "TCP",
    description: "Oracle TNS Listener -- provides network connectivity to Oracle Database instances using the Transparent Network Substrate protocol.",
    securityNotes: "TNS Listener can be remotely poisoned. Default SIDs and credentials common. ODAT tool provides comprehensive Oracle assessment. Java stored procedures enable RCE.",
    commonVulns: [
      "TNS Listener poisoning",
      "Default SID enumeration (ORCL, XE)",
      "Default credentials (scott/tiger, sys/change_on_install)",
      "Java stored procedure RCE",
      "TNS remote registration",
      "Privilege escalation via UTL_FILE"
    ],
    testingCommands: [
      "nmap -p 1521 --script oracle-tns-version,oracle-sid-brute,oracle-brute <target>",
      "odat all -s <target> -p 1521",
      "tnscmd10g status -h <target>",
      "sqlplus <user>/<pass>@<target>:1521/SID"
    ],
    relatedCVEs: ["CVE-2012-1675", "CVE-2018-3110", "CVE-2020-2883"]
  },
  {
    name: "MongoDB",
    port: 27017,
    transport: "TCP",
    description: "MongoDB wire protocol -- binary protocol for communication with MongoDB NoSQL document database servers.",
    securityNotes: "Historically shipped with no authentication enabled by default. Exposed MongoDB instances have been mass-ransomed. NoSQL injection differs from SQL injection.",
    commonVulns: [
      "No authentication (default pre-3.6)",
      "NoSQL injection",
      "SSRF via MongoDB URI",
      "Exposed management interface",
      "Data exfiltration from unprotected instances",
      "Ransomware via unauthenticated access"
    ],
    testingCommands: [
      "nmap -p 27017 --script mongodb-info,mongodb-databases,mongodb-brute <target>",
      "mongosh --host <target>",
      "mongo <target>:27017 --eval 'db.adminCommand({listDatabases:1})'",
      "msfconsole: use auxiliary/scanner/mongodb/mongodb_login"
    ],
    relatedCVEs: ["CVE-2015-7882", "CVE-2013-1892"]
  },
  {
    name: "Redis",
    port: 6379,
    transport: "TCP",
    description: "Redis serialization protocol (RESP) -- in-memory data structure store used as database, cache, message broker, and streaming engine.",
    securityNotes: "No authentication by default. CONFIG SET allows writing arbitrary files (SSH keys, crontabs, webshells). Lua scripting can execute arbitrary code. Bind to localhost.",
    commonVulns: [
      "Unauthenticated access (no requirepass)",
      "Arbitrary file write via CONFIG SET dir/dbfilename",
      "SSH key injection",
      "Crontab injection for reverse shell",
      "Webshell write via SAVE",
      "Lua sandbox escape (older versions)",
      "SLAVEOF-based replication exploit"
    ],
    testingCommands: [
      "nmap -p 6379 --script redis-info,redis-brute <target>",
      "redis-cli -h <target> INFO",
      "redis-cli -h <target> CONFIG GET *",
      "msfconsole: use auxiliary/scanner/redis/redis_login"
    ],
    relatedCVEs: ["CVE-2015-8080", "CVE-2022-0543", "CVE-2023-28856"]
  },
  {
    name: "Memcached",
    port: 11211,
    transport: "TCP/UDP",
    description: "Memcached binary/text protocol -- distributed memory caching system for speeding up dynamic web applications by caching data in RAM.",
    securityNotes: "No authentication. UDP reflection attacks achieved record-breaking 1.7 Tbps DDoS. Exposed instances leak cached application data including sessions and credentials.",
    commonVulns: [
      "UDP amplification DDoS (1.7 Tbps record)",
      "Unauthenticated data access",
      "Cached credential extraction",
      "Session token theft",
      "Cache poisoning"
    ],
    testingCommands: [
      "nmap -p 11211 --script memcached-info <target>",
      "echo 'stats' | nc <target> 11211",
      "echo 'stats items' | nc <target> 11211",
      "memcstat --servers=<target>"
    ],
    relatedCVEs: ["CVE-2018-1000115", "CVE-2016-8704", "CVE-2016-8705"]
  },
  {
    name: "Elasticsearch",
    port: 9200,
    transport: "TCP (HTTP)",
    description: "Elasticsearch REST API -- distributed search and analytics engine accessed via HTTP/JSON RESTful API.",
    securityNotes: "Historically no authentication by default. X-Pack/Security module adds auth. Exposed instances have been mass-compromised. Groovy/Painless scripting can achieve RCE.",
    commonVulns: [
      "Unauthenticated access",
      "Groovy/Painless script RCE",
      "Data exfiltration from exposed clusters",
      "Index/snapshot enumeration",
      "Kibana SSRF via Elasticsearch",
      "Directory traversal in snapshot API"
    ],
    testingCommands: [
      "curl http://<target>:9200/",
      "curl http://<target>:9200/_cat/indices?v",
      "curl http://<target>:9200/_search?pretty",
      "nmap -p 9200 --script http-elasticsearch-info <target>"
    ],
    relatedCVEs: ["CVE-2015-1427", "CVE-2014-3120", "CVE-2018-17246"]
  },
  {
    name: "CouchDB",
    port: 5984,
    transport: "TCP (HTTP)",
    description: "Apache CouchDB HTTP API -- document-oriented NoSQL database accessed via RESTful HTTP/JSON API with built-in web admin interface (Fauxton).",
    securityNotes: "Admin party mode (no admin account) was the default. REST API fully accessible without auth. Erlang query server can execute OS commands.",
    commonVulns: [
      "Admin party (no authentication)",
      "Remote code execution via Erlang views",
      "Unauthenticated database access",
      "Admin account creation without auth",
      "Data exfiltration"
    ],
    testingCommands: [
      "curl http://<target>:5984/",
      "curl http://<target>:5984/_all_dbs",
      "curl http://<target>:5984/_users/_all_docs",
      "nmap -p 5984 --script couchdb-databases,couchdb-stats <target>"
    ],
    relatedCVEs: ["CVE-2017-12635", "CVE-2017-12636", "CVE-2022-24706"]
  },
  {
    name: "Cassandra",
    port: 9042,
    transport: "TCP",
    description: "Apache Cassandra CQL native protocol -- binary protocol for Cassandra Query Language interaction with Cassandra distributed database.",
    securityNotes: "Authentication disabled by default. JMX management port (7199) often exposed. Inter-node communication unencrypted by default.",
    commonVulns: [
      "No authentication (default AllowAllAuthenticator)",
      "JMX remote access",
      "CQL injection",
      "Inter-node traffic interception",
      "Default credentials"
    ],
    testingCommands: [
      "nmap -p 9042 --script cassandra-info,cassandra-brute <target>",
      "cqlsh <target>",
      "nodetool -h <target> status"
    ],
    relatedCVEs: ["CVE-2020-17516", "CVE-2021-44521"]
  },

  // ---- Message Queue / IoT ----
  {
    name: "RabbitMQ",
    port: 5672,
    transport: "TCP (AMQP)",
    description: "RabbitMQ AMQP broker -- message broker implementing the Advanced Message Queuing Protocol for reliable asynchronous messaging.",
    securityNotes: "Default credentials guest/guest. Management API on port 15672 often exposed. Erlang cookie shared across cluster enables full node access.",
    commonVulns: [
      "Default credentials (guest/guest)",
      "Management API exposure (15672)",
      "Erlang cookie theft for cluster takeover",
      "Message interception",
      "Queue/exchange enumeration"
    ],
    testingCommands: [
      "nmap -p 5672 --script amqp-info <target>",
      "curl -u guest:guest http://<target>:15672/api/overview",
      "rabbitmqadmin -H <target> list queues",
      "msfconsole: use auxiliary/scanner/amqp/amqp_login"
    ],
    relatedCVEs: ["CVE-2019-11281", "CVE-2021-22116"]
  },
  {
    name: "MQTT",
    port: 1883,
    transport: "TCP",
    description: "Message Queuing Telemetry Transport -- lightweight publish-subscribe messaging protocol designed for constrained IoT devices and low-bandwidth networks.",
    securityNotes: "No authentication by default on many brokers. Subscribing to '#' wildcard captures all messages. Used extensively in IoT with poor security practices.",
    commonVulns: [
      "No authentication",
      "Wildcard topic subscription (# captures all)",
      "Plaintext message interception",
      "Malicious message injection",
      "Client ID spoofing",
      "Will message abuse"
    ],
    testingCommands: [
      "mosquitto_sub -h <target> -t '#' -v",
      "mosquitto_pub -h <target> -t 'test/topic' -m 'payload'",
      "nmap -p 1883 --script mqtt-subscribe <target>",
      "mqtt-explorer (GUI tool)"
    ],
    relatedCVEs: ["CVE-2017-7651", "CVE-2023-0809"]
  },
  {
    name: "MQTTS",
    port: 8883,
    transport: "TCP (TLS)",
    description: "MQTT over TLS -- encrypted MQTT communication providing confidentiality and server authentication for IoT messaging.",
    securityNotes: "TLS adds encryption but authentication still must be configured. Certificate-based mutual authentication recommended for IoT deployments.",
    commonVulns: [
      "Weak TLS configuration",
      "Missing client authentication",
      "Self-signed certificate acceptance"
    ],
    testingCommands: [
      "mosquitto_sub -h <target> -p 8883 --cafile ca.crt -t '#' -v",
      "openssl s_client -connect <target>:8883"
    ],
    relatedCVEs: []
  },
  {
    name: "CoAP",
    port: 5683,
    transport: "UDP",
    description: "Constrained Application Protocol -- specialized web transfer protocol for constrained IoT nodes and networks, using UDP with optional DTLS security.",
    securityNotes: "UDP-based and easily spoofable. No security by default. DTLS mode adds encryption but increases overhead on constrained devices.",
    commonVulns: [
      "No authentication (default)",
      "UDP spoofing",
      "CoAP amplification",
      "Resource discovery enumeration",
      "Proxy abuse"
    ],
    testingCommands: [
      "coap-client -m get coap://<target>/.well-known/core",
      "nmap -sU -p 5683 <target>",
      "aiocoap-client coap://<target>/.well-known/core"
    ],
    relatedCVEs: ["CVE-2019-9750"]
  },

  // ---- Multimedia / Streaming ----
  {
    name: "RTSP",
    port: 554,
    transport: "TCP",
    description: "Real Time Streaming Protocol -- controls streaming media servers for establishing and controlling media sessions between endpoints.",
    securityNotes: "Default credentials on IP cameras ubiquitous. Unauthenticated stream access common. Stream URLs often predictable. Used to access security camera feeds.",
    commonVulns: [
      "Default/no credentials on cameras",
      "Unauthenticated stream access",
      "Stream URL enumeration",
      "Buffer overflow in RTSP parsers",
      "RTSP-based reconnaissance of cameras"
    ],
    testingCommands: [
      "nmap -p 554 --script rtsp-methods,rtsp-url-brute <target>",
      "cameradar -t <target>",
      "ffplay rtsp://<target>/stream",
      "vlc rtsp://<user>:<pass>@<target>/stream"
    ],
    relatedCVEs: ["CVE-2017-13228", "CVE-2019-15107"]
  },
  {
    name: "SIP",
    port: 5060,
    transport: "UDP/TCP",
    description: "Session Initiation Protocol -- signaling protocol for initiating, maintaining, and terminating VoIP and multimedia communication sessions.",
    securityNotes: "Extension enumeration reveals valid accounts. SIP INVITE flooding causes DoS. Registration hijacking redirects calls. Toll fraud is a major financial risk.",
    commonVulns: [
      "SIP extension enumeration",
      "Registration hijacking",
      "INVITE flood DoS",
      "Toll fraud (unauthorized calls)",
      "Eavesdropping (RTP interception)",
      "Caller ID spoofing"
    ],
    testingCommands: [
      "svmap <target>",
      "svwar -m INVITE <target>",
      "sipvicious (svmap/svwar/svcrack)",
      "nmap -sU -p 5060 --script sip-methods,sip-enum-users <target>",
      "msfconsole: use auxiliary/scanner/sip/enumerator"
    ],
    relatedCVEs: ["CVE-2019-2location", "CVE-2018-12584"]
  },
  {
    name: "RTP",
    port: null,
    transport: "UDP (dynamic ports)",
    description: "Real-time Transport Protocol -- delivers audio and video over IP networks. Uses dynamic port pairs (even for RTP, odd for RTCP).",
    securityNotes: "No encryption by default. SRTP adds encryption. RTP streams can be intercepted and reconstructed into audio/video recordings.",
    commonVulns: [
      "Plaintext media stream interception",
      "Voice call eavesdropping",
      "RTP injection (inserting audio)",
      "SRTP key management failures"
    ],
    testingCommands: [
      "wireshark: capture and decode RTP streams",
      "rtpbreak -r <pcap_file>",
      "ucsniff (VoIP sniffer)"
    ],
    relatedCVEs: ["CVE-2017-6location"]
  },

  // ---- Routing Protocols ----
  {
    name: "BGP",
    port: 179,
    transport: "TCP",
    description: "Border Gateway Protocol -- inter-autonomous system routing protocol that makes core Internet routing decisions based on network paths, policies, and rule-sets.",
    securityNotes: "BGP hijacking redirects Internet traffic. No built-in authentication in original design. MD5 authentication (TCP option 19) is weak. RPKI adoption improving but incomplete.",
    commonVulns: [
      "BGP hijacking / prefix hijacking",
      "Route leaks",
      "BGP session reset via TCP RST",
      "Peer authentication bypass",
      "AS-path manipulation",
      "BGP MITM via route injection"
    ],
    testingCommands: [
      "nmap -p 179 <target>",
      "bgp-inspect (route analysis)",
      "routeviews.org (BGP looking glass)",
      "bgpstream.com (hijack detection)"
    ],
    relatedCVEs: ["CVE-2004-0230", "CVE-2022-20835"]
  },
  {
    name: "OSPF",
    port: null,
    transport: "IP Protocol 89",
    description: "Open Shortest Path First -- link-state routing protocol for IP networks using Dijkstra's algorithm to find the shortest path between nodes.",
    securityNotes: "OSPF authentication should be mandatory. Rogue router injection can manipulate routing. Passive interface configuration prevents neighbor formation on untrusted segments.",
    commonVulns: [
      "Unauthenticated OSPF neighbor injection",
      "LSA manipulation",
      "Routing table poisoning",
      "Phantom router attacks",
      "MD5 authentication cracking"
    ],
    testingCommands: [
      "loki (OSPF attack framework)",
      "scapy: OSPF hello packet crafting",
      "wireshark: filter ospf"
    ],
    relatedCVEs: ["CVE-2013-0149"]
  },
  {
    name: "VRRP",
    port: null,
    transport: "IP Protocol 112",
    description: "Virtual Router Redundancy Protocol -- provides automatic assignment of available IP routers to participating hosts for first-hop redundancy.",
    securityNotes: "Authentication often plaintext or disabled. Priority manipulation makes attacker the master router. Gateway hijacking enables MITM.",
    commonVulns: [
      "Priority manipulation for master election",
      "Gateway hijacking / MITM",
      "Authentication bypass",
      "VRRP advertisement spoofing"
    ],
    testingCommands: [
      "loki -i eth0 (VRRP spoofing)",
      "yersinia -G (VRRP attacks)",
      "scapy: VRRP packet crafting"
    ],
    relatedCVEs: []
  },

  // ---- Wireless Protocols ----
  {
    name: "WPA2",
    port: null,
    transport: "IEEE 802.11 (Wi-Fi)",
    description: "Wi-Fi Protected Access 2 -- security protocol using AES-CCMP encryption for wireless LANs. Personal mode uses PSK; Enterprise uses 802.1X/RADIUS.",
    securityNotes: "KRACK attack exploits 4-way handshake nonce reuse. PSK mode vulnerable to offline dictionary attacks after capturing handshake. PMKID attack does not require client.",
    commonVulns: [
      "KRACK (Key Reinstallation Attack)",
      "Offline handshake dictionary attack",
      "PMKID-based attack (clientless)",
      "Evil twin / rogue AP",
      "Deauthentication attack (DoS / handshake capture)",
      "WPS PIN brute force"
    ],
    testingCommands: [
      "airmon-ng start wlan0",
      "airodump-ng wlan0mon",
      "aireplay-ng --deauth 10 -a <bssid> wlan0mon",
      "aircrack-ng -w <wordlist> capture.cap",
      "hashcat -m 22000 hash.hc22000 <wordlist>",
      "hcxdumptool -i wlan0mon --enable_status=1 -o capture.pcapng"
    ],
    relatedCVEs: ["CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13080"]
  },
  {
    name: "WPA3",
    port: null,
    transport: "IEEE 802.11 (Wi-Fi)",
    description: "Wi-Fi Protected Access 3 -- latest Wi-Fi security protocol using Simultaneous Authentication of Equals (SAE/Dragonfly) to replace PSK handshake.",
    securityNotes: "Dragonblood attacks exploit implementation flaws in SAE. Transition mode (WPA3/WPA2 mixed) enables downgrade attacks. Side-channel attacks possible on SAE.",
    commonVulns: [
      "Dragonblood side-channel attacks",
      "Transition mode downgrade to WPA2",
      "SAE timing attacks",
      "Denial of service via SAE commit flooding",
      "Group downgrade attacks"
    ],
    testingCommands: [
      "dragonslayer (Dragonblood tool)",
      "dragondrain (SAE DoS)",
      "dragontime (timing attack)",
      "dragonforce (password recovery)"
    ],
    relatedCVEs: ["CVE-2019-9494", "CVE-2019-9495", "CVE-2019-9496", "CVE-2019-9497"]
  },
  {
    name: "Bluetooth",
    port: null,
    transport: "IEEE 802.15.1",
    description: "Bluetooth wireless technology -- short-range wireless standard for exchanging data over short distances from fixed and mobile devices. Includes Classic, LE, and BR/EDR.",
    securityNotes: "BlueBorne enables remote code execution without pairing. KNOB attack weakens encryption key negotiation. BIAS allows impersonation. BLE has minimal security.",
    commonVulns: [
      "BlueBorne (remote RCE without pairing)",
      "KNOB (Key Negotiation of Bluetooth)",
      "BIAS (Bluetooth Impersonation Attack)",
      "Bluejacking / Bluesnarfing",
      "BLE GATT service enumeration",
      "PIN brute force (legacy pairing)"
    ],
    testingCommands: [
      "hciconfig hci0 up",
      "hcitool scan",
      "hcitool lescan",
      "sdptool browse <bt_addr>",
      "gatttool -b <bt_addr> -I (BLE)",
      "bettercap -eval 'ble.recon on'"
    ],
    relatedCVEs: ["CVE-2017-1000251", "CVE-2019-9506", "CVE-2020-10135"]
  },
  {
    name: "ZigBee",
    port: null,
    transport: "IEEE 802.15.4",
    description: "ZigBee wireless mesh networking protocol -- low-power, low-data-rate protocol for IoT devices including home automation, smart energy, and industrial sensing.",
    securityNotes: "Network key often transmitted in plaintext during joining. Default trust center key (ZigBeeAlliance09) widely known. OTA key extraction from firmware common.",
    commonVulns: [
      "Default trust center link key",
      "Network key sniffing during joining",
      "Key extraction from firmware",
      "Replay attacks",
      "Insecure rejoin vulnerability",
      "Frame counter manipulation"
    ],
    testingCommands: [
      "killerbee: zbstumbler (network discovery)",
      "killerbee: zbdump (packet capture)",
      "killerbee: zbreplay (replay attack)",
      "attify-zigbee-framework",
      "wireshark with ZigBee dissector"
    ],
    relatedCVEs: ["CVE-2020-28952"]
  },

  // ---- Industrial / SCADA Protocols ----
  {
    name: "Modbus",
    port: 502,
    transport: "TCP",
    description: "Modbus TCP -- industrial communication protocol for connecting electronic devices in SCADA/ICS environments. Originally serial (RTU/ASCII), adapted for TCP/IP.",
    securityNotes: "Absolutely no authentication or encryption. Any host that can reach port 502 can read/write registers and coils. Critical infrastructure often directly exposed to Internet.",
    commonVulns: [
      "No authentication whatsoever",
      "Register/coil read (process data theft)",
      "Register/coil write (process manipulation)",
      "Function code scanning",
      "Denial of service",
      "PLC stop/start commands"
    ],
    testingCommands: [
      "nmap -p 502 --script modbus-discover <target>",
      "mbtget -a 1 -r 0 -n 100 <target> (read holding registers)",
      "modbus-cli read <target> %MW0 100",
      "msfconsole: use auxiliary/scanner/scada/modbus_findunitid"
    ],
    relatedCVEs: ["CVE-2019-9306", "CVE-2022-0778"]
  },
  {
    name: "DNP3",
    port: 20000,
    transport: "TCP/UDP",
    description: "Distributed Network Protocol 3 -- communication protocol used between components in process automation systems, particularly electric and water utilities.",
    securityNotes: "DNP3 Secure Authentication (SA) adds security but is rarely implemented. Legacy DNP3 has no authentication. Direct physical process impact possible.",
    commonVulns: [
      "No authentication (legacy mode)",
      "Unsolicited response injection",
      "Control relay output block attacks",
      "Cold/warm restart commands",
      "Data link layer manipulation",
      "Fuzzing crashes (common in implementations)"
    ],
    testingCommands: [
      "nmap -p 20000 --script dnp3-info <target>",
      "aegis (DNP3 IDS)",
      "msfconsole: use auxiliary/scanner/scada/dnp3_status_request",
      "wireshark: filter dnp3"
    ],
    relatedCVEs: ["CVE-2013-2804", "CVE-2019-18996"]
  },
  {
    name: "OPC-UA",
    port: 4840,
    transport: "TCP",
    description: "Open Platform Communications Unified Architecture -- machine-to-machine communication protocol for industrial automation with built-in security model.",
    securityNotes: "Supports security modes (None, Sign, SignAndEncrypt) but often deployed with SecurityPolicy None. Certificate management frequently misconfigured.",
    commonVulns: [
      "SecurityPolicy None deployment",
      "Anonymous authentication enabled",
      "Certificate validation bypass",
      "Node enumeration / information disclosure",
      "Write access to process variables",
      "Method call abuse"
    ],
    testingCommands: [
      "nmap -p 4840 --script opcua-info <target>",
      "opcua-commander (GUI browser)",
      "python-opcua: client.connect('opc.tcp://<target>:4840')",
      "UaExpert (GUI client)"
    ],
    relatedCVEs: ["CVE-2022-29862", "CVE-2022-29863", "CVE-2019-8287"]
  },
  {
    name: "BACnet",
    port: 47808,
    transport: "UDP",
    description: "Building Automation and Control Networks -- protocol for building automation including HVAC, lighting, elevator, and fire detection systems.",
    securityNotes: "No authentication in standard BACnet/IP. Any device on the network can read/write BACnet objects. Securing requires network segmentation or BACnet/SC (Secure Connect).",
    commonVulns: [
      "No authentication",
      "Device enumeration",
      "Object value read/write",
      "BACnet routing exploitation",
      "Building system manipulation (HVAC, access control)"
    ],
    testingCommands: [
      "nmap -sU -p 47808 --script bacnet-info <target>",
      "bacnet-stack tools: bacwi (Who-Is), bacrp (Read-Property)",
      "msfconsole: use auxiliary/scanner/scada/bacnet_info_request"
    ],
    relatedCVEs: ["CVE-2019-12480"]
  },
  {
    name: "EtherNet/IP",
    port: 44818,
    transport: "TCP/UDP",
    description: "EtherNet/Industrial Protocol -- industrial network protocol using standard Ethernet for industrial automation applications. Uses CIP (Common Industrial Protocol) at application layer.",
    securityNotes: "No built-in authentication or encryption. Implicit messaging uses UDP multicast. PLC program download/upload typically unauthenticated.",
    commonVulns: [
      "Unauthenticated PLC programming",
      "CIP command injection",
      "Device enumeration",
      "Firmware upload without auth",
      "Process manipulation"
    ],
    testingCommands: [
      "nmap -p 44818 --script enip-info <target>",
      "pycomm3: PLC('target').get_tag_list()",
      "msfconsole: use auxiliary/scanner/scada/ethernetip_info"
    ],
    relatedCVEs: ["CVE-2021-22681", "CVE-2022-1159"]
  },
  {
    name: "S7comm",
    port: 102,
    transport: "TCP (ISO-TSAP)",
    description: "Siemens S7 Communication -- proprietary protocol used by Siemens SIMATIC S7 PLCs for programming, diagnostics, and HMI communication.",
    securityNotes: "No authentication in S7comm. S7comm+ (S7-1500) adds some security but is often disabled. Stuxnet exploited S7 PLCs. PLC Stop/Start commands typically unrestricted.",
    commonVulns: [
      "Unauthenticated PLC Stop/Start",
      "Program download/upload without auth",
      "CPU state manipulation",
      "Memory read/write",
      "Password bypass (S7-300/400)"
    ],
    testingCommands: [
      "nmap -p 102 --script s7-info <target>",
      "plcscan -i <target>",
      "snap7: client.connect('<target>', 0, 1)",
      "msfconsole: use auxiliary/scanner/scada/s7_enumerate"
    ],
    relatedCVEs: ["CVE-2019-13945", "CVE-2020-15782"]
  },

  // ---- VPN / Tunneling ----
  {
    name: "IPsec (IKE)",
    port: 500,
    transport: "UDP",
    description: "Internet Key Exchange -- protocol for establishing Security Associations for IPsec VPN tunnels. IKEv1 uses aggressive/main mode; IKEv2 is more secure.",
    securityNotes: "IKEv1 aggressive mode exposes PSK hash for offline cracking. IKEv2 preferred. Transform enumeration reveals VPN configuration. Weak PSK common.",
    commonVulns: [
      "IKEv1 aggressive mode PSK hash capture",
      "Pre-shared key brute force",
      "Transform enumeration",
      "VPN gateway identification",
      "IKE DDoS amplification"
    ],
    testingCommands: [
      "nmap -sU -p 500 --script ike-version <target>",
      "ike-scan -M --aggressive <target>",
      "ikeforce <target> -e -w wordlist.txt",
      "ike-scan --trans=7/256/1/2 -M <target>"
    ],
    relatedCVEs: ["CVE-2018-5389", "CVE-2016-2379"]
  },
  {
    name: "OpenVPN",
    port: 1194,
    transport: "UDP/TCP",
    description: "OpenVPN -- open-source VPN solution using custom security protocol based on SSL/TLS for key exchange and data encryption.",
    securityNotes: "Certificate-based authentication preferred over PSK. tls-auth/tls-crypt adds HMAC firewall. Configuration file can contain embedded commands.",
    commonVulns: [
      "Weak certificate validation",
      "PSK brute force",
      "Client configuration file injection",
      "Missing tls-auth/tls-crypt",
      "Privilege escalation via configuration directives"
    ],
    testingCommands: [
      "nmap -sU -p 1194 <target>",
      "openvpn --remote <target> --dev tun --ifconfig 10.0.0.2 10.0.0.1",
      "nmap -sV -p 1194 <target>"
    ],
    relatedCVEs: ["CVE-2020-15078", "CVE-2017-7521"]
  },
  {
    name: "WireGuard",
    port: 51820,
    transport: "UDP",
    description: "WireGuard -- modern VPN protocol with minimal attack surface, using state-of-the-art cryptography (ChaCha20, Curve25519, BLAKE2s).",
    securityNotes: "Minimal attack surface by design. No version negotiation or cipher agility. IP leak possible if AllowedIPs misconfigured. Key management is the primary concern.",
    commonVulns: [
      "Key compromise",
      "AllowedIPs misconfiguration (traffic leak)",
      "Endpoint discovery",
      "DNS leak",
      "Missing kill switch"
    ],
    testingCommands: [
      "nmap -sU -p 51820 <target>",
      "wg show (if access to endpoint)"
    ],
    relatedCVEs: ["CVE-2021-46873"]
  },

  // ---- Proxy / Load Balancing ----
  {
    name: "SOCKS5",
    port: 1080,
    transport: "TCP",
    description: "SOCKS version 5 -- proxy protocol supporting both TCP and UDP traffic with optional authentication. Routes network packets between a client and server through a proxy.",
    securityNotes: "Open SOCKS proxies frequently used to anonymize attacks. No traffic encryption. DNS resolution through proxy prevents DNS leaks. Authentication bypass vulnerabilities.",
    commonVulns: [
      "Open proxy abuse",
      "Authentication bypass",
      "Proxy chain anonymization for attacks",
      "DNS leak through SOCKS4",
      "Internal network pivoting"
    ],
    testingCommands: [
      "nmap -p 1080 --script socks-open-proxy <target>",
      "curl --socks5 <target>:1080 http://ifconfig.me",
      "proxychains nmap <internal_target>"
    ],
    relatedCVEs: []
  },
  {
    name: "HTTP Proxy (CONNECT)",
    port: 3128,
    transport: "TCP",
    description: "HTTP proxy using CONNECT method for tunneling. Squid commonly runs on 3128. CONNECT method creates TCP tunnel for arbitrary protocols.",
    securityNotes: "Open proxies enable anonymous browsing and attack relay. CONNECT method can tunnel non-HTTP traffic. SSRF via proxy misconfiguration.",
    commonVulns: [
      "Open proxy relay",
      "CONNECT method tunnel abuse",
      "Cache poisoning",
      "SSRF via proxy",
      "Access control bypass"
    ],
    testingCommands: [
      "nmap -p 3128 --script http-open-proxy <target>",
      "curl -x http://<target>:3128 http://internal-server/",
      "curl -x http://<target>:3128 -X CONNECT internal:22"
    ],
    relatedCVEs: ["CVE-2019-12525", "CVE-2020-15049"]
  },

  // ---- Miscellaneous Protocols ----
  {
    name: "LLMNR",
    port: 5355,
    transport: "UDP",
    description: "Link-Local Multicast Name Resolution -- protocol used in Windows networks for name resolution when DNS fails. Sends multicast queries on the local network.",
    securityNotes: "LLMNR poisoning captures NTLMv2 hashes for offline cracking. Responder tool automates this attack. Should be disabled via Group Policy.",
    commonVulns: [
      "LLMNR poisoning for NTLMv2 hash capture",
      "MITM via name resolution spoofing",
      "Credential relay attacks",
      "WPAD exploitation via LLMNR"
    ],
    testingCommands: [
      "responder -I eth0 -wrf",
      "Inveigh.ps1 (PowerShell responder)",
      "hashcat -m 5600 captured_hash.txt <wordlist>",
      "nmap -sU -p 5355 <target>"
    ],
    relatedCVEs: []
  },
  {
    name: "NBNS (NetBIOS Name Service)",
    port: 137,
    transport: "UDP",
    description: "NetBIOS Name Service -- name registration and resolution service for NetBIOS over TCP/IP networks. Legacy Windows name resolution.",
    securityNotes: "Same poisoning risks as LLMNR. Responder captures NTLM hashes. Should be disabled when not needed. Often exploited together with LLMNR.",
    commonVulns: [
      "NBNS poisoning for hash capture",
      "Name spoofing",
      "NetBIOS information disclosure",
      "NTLM relay via NBNS"
    ],
    testingCommands: [
      "responder -I eth0",
      "nbtscan <target>/24",
      "nmap -sU -p 137 --script nbstat <target>"
    ],
    relatedCVEs: []
  },
  {
    name: "RADIUS",
    port: 1812,
    transport: "UDP",
    description: "Remote Authentication Dial-In User Service -- provides centralized AAA (Authentication, Authorization, Accounting) management for network access.",
    securityNotes: "Shared secret used to encrypt user password. Weak shared secrets enable offline attacks. RADIUS over TLS (RadSec) addresses transport security.",
    commonVulns: [
      "Weak shared secret",
      "Response authenticator forgery",
      "User password decryption via shared secret",
      "Blast-RADIUS attack (MD5 collision)",
      "Dictionary attacks on shared secret"
    ],
    testingCommands: [
      "nmap -sU -p 1812 <target>",
      "radclient <target> auth <shared_secret> <<< 'User-Name=test\\nUser-Password=test'",
      "eapmd5pass -r capture.pcap -w <wordlist>"
    ],
    relatedCVEs: ["CVE-2024-3596"]
  },
  {
    name: "TACACS+",
    port: 49,
    transport: "TCP",
    description: "Terminal Access Controller Access-Control System Plus -- provides centralized AAA for network devices. Cisco-originated, encrypts the full packet body.",
    securityNotes: "Encryption uses MD5-based obfuscation with shared key, not true encryption. Key recovery possible from captured traffic. Separates authentication, authorization, accounting.",
    commonVulns: [
      "Shared key recovery from traffic",
      "MD5 obfuscation weakness",
      "Key brute force",
      "Privilege level manipulation",
      "Command authorization bypass"
    ],
    testingCommands: [
      "nmap -p 49 <target>",
      "loki (TACACS+ tool)",
      "wireshark: filter tacplus",
      "tac_plus decryptor tools"
    ],
    relatedCVEs: ["CVE-2023-20198"]
  },
  {
    name: "PPTP",
    port: 1723,
    transport: "TCP (GRE)",
    description: "Point-to-Point Tunneling Protocol -- VPN protocol using GRE encapsulation and PPP for tunneling. Considered cryptographically broken.",
    securityNotes: "MS-CHAPv2 authentication is cryptographically broken (100% crack rate). Should not be used. PPTP traffic can be decrypted by passive eavesdropper after capturing handshake.",
    commonVulns: [
      "MS-CHAPv2 hash cracking (trivial)",
      "GRE session hijacking",
      "MPPE key recovery",
      "Traffic decryption",
      "Authentication downgrade"
    ],
    testingCommands: [
      "nmap -p 1723 --script pptp-version <target>",
      "thc-pptp-bruter -u <user> -W <wordlist> <target>",
      "chapcrack (MS-CHAPv2 cracking)"
    ],
    relatedCVEs: ["CVE-2012-2975"]
  },
  {
    name: "L2TP",
    port: 1701,
    transport: "UDP",
    description: "Layer 2 Tunneling Protocol -- tunneling protocol used to support VPNs. Typically combined with IPsec for encryption (L2TP/IPsec).",
    securityNotes: "L2TP alone provides no encryption. Must be paired with IPsec. L2TP/IPsec security depends on IPsec configuration. PSK mode vulnerable to offline attacks.",
    commonVulns: [
      "No encryption without IPsec",
      "IPsec PSK brute force",
      "Tunnel endpoint discovery",
      "L2TP session hijacking (without IPsec)"
    ],
    testingCommands: [
      "nmap -sU -p 1701 <target>",
      "ike-scan -M <target> (check IPsec pairing)"
    ],
    relatedCVEs: []
  },
  {
    name: "XMPP",
    port: 5222,
    transport: "TCP",
    description: "Extensible Messaging and Presence Protocol (Jabber) -- open XML-based protocol for real-time messaging, presence information, and contact list maintenance.",
    securityNotes: "STARTTLS upgrade required for security. Server-to-server communication (port 5269) often lacks certificate validation. XML entity expansion attacks possible.",
    commonVulns: [
      "STARTTLS stripping",
      "XML external entity (XXE) injection",
      "User enumeration",
      "Message interception (plaintext)",
      "XEP abuse (file transfer, etc.)"
    ],
    testingCommands: [
      "nmap -p 5222 --script xmpp-info,xmpp-brute <target>",
      "openssl s_client -starttls xmpp -connect <target>:5222"
    ],
    relatedCVEs: ["CVE-2014-3566", "CVE-2022-0217"]
  },
  {
    name: "IRC",
    port: 6667,
    transport: "TCP",
    description: "Internet Relay Chat -- text-based real-time communication protocol. IRC over TLS typically on port 6697. Historically used for botnet C2.",
    securityNotes: "Plaintext protocol. DCC (Direct Client-to-Client) exposes IP addresses. Widely used for botnet command and control. IRC over TLS (6697) adds encryption.",
    commonVulns: [
      "Plaintext credential/message interception",
      "DCC IP address disclosure",
      "Channel takeover",
      "Botnet C2 usage",
      "IRC backdoor exploitation"
    ],
    testingCommands: [
      "nmap -p 6667 --script irc-info,irc-brute <target>",
      "irssi -c <target>",
      "nmap -p 6667 --script irc-unrealircd-backdoor <target>"
    ],
    relatedCVEs: ["CVE-2010-2075"]
  },
  {
    name: "Docker API",
    port: 2375,
    transport: "TCP (HTTP)",
    description: "Docker Engine REST API -- management interface for Docker containers. Port 2375 is unencrypted; 2376 is TLS-encrypted.",
    securityNotes: "Exposed Docker API provides full container and host access. Container escape to host is equivalent to root. Never expose Docker socket to network without TLS and authentication.",
    commonVulns: [
      "Unauthenticated container creation",
      "Host filesystem mount (container escape)",
      "Privileged container for host root",
      "Image poisoning",
      "Container breakout"
    ],
    testingCommands: [
      "curl http://<target>:2375/version",
      "curl http://<target>:2375/containers/json",
      "docker -H tcp://<target>:2375 ps",
      "nmap -p 2375 --script docker-version <target>"
    ],
    relatedCVEs: ["CVE-2019-5736", "CVE-2020-15257"]
  },
  {
    name: "Kubernetes API",
    port: 6443,
    transport: "TCP (HTTPS)",
    description: "Kubernetes API Server -- RESTful interface for managing Kubernetes clusters. Central control plane component.",
    securityNotes: "Anonymous authentication may be enabled. Service account tokens in pods can access API. RBAC misconfiguration is the primary risk. Kubelet API (10250) is another vector.",
    commonVulns: [
      "Anonymous/unauthenticated access",
      "RBAC misconfiguration",
      "Service account token abuse",
      "Privileged pod escape",
      "etcd access (secrets extraction)",
      "Kubelet API exploitation"
    ],
    testingCommands: [
      "curl -k https://<target>:6443/",
      "curl -k https://<target>:6443/api/v1/namespaces",
      "kubectl --server=https://<target>:6443 --insecure-skip-tls-verify get pods",
      "kube-hunter --remote <target>"
    ],
    relatedCVEs: ["CVE-2018-1002105", "CVE-2021-25741", "CVE-2023-5528"]
  },
  {
    name: "etcd",
    port: 2379,
    transport: "TCP (HTTP/gRPC)",
    description: "etcd distributed key-value store -- stores Kubernetes cluster state including secrets, configurations, and service discovery data.",
    securityNotes: "Unauthenticated access exposes all cluster secrets. Kubernetes secrets stored base64-encoded (not encrypted) by default. Client certificate auth should be mandatory.",
    commonVulns: [
      "Unauthenticated access",
      "Kubernetes secret extraction",
      "Cluster state manipulation",
      "Service account token theft",
      "Configuration tampering"
    ],
    testingCommands: [
      "curl http://<target>:2379/v2/keys/?recursive=true",
      "etcdctl --endpoints=http://<target>:2379 get / --prefix",
      "nmap -p 2379 <target>"
    ],
    relatedCVEs: ["CVE-2020-15106", "CVE-2020-15136"]
  },
  {
    name: "WinRM",
    port: 5985,
    transport: "TCP (HTTP)",
    description: "Windows Remote Management -- Microsoft implementation of WS-Management protocol for remote management of Windows machines via HTTP/SOAP.",
    securityNotes: "Port 5985 is HTTP, 5986 is HTTPS. Accepts NTLM and Kerberos authentication. Evil-WinRM provides interactive shell. Pass-the-hash works with WinRM.",
    commonVulns: [
      "Credential brute force",
      "Pass-the-hash authentication",
      "Remote code execution via WinRM",
      "NTLM relay to WinRM",
      "Lateral movement vector"
    ],
    testingCommands: [
      "evil-winrm -i <target> -u <user> -p <pass>",
      "crackmapexec winrm <target> -u <user> -p <pass>",
      "nmap -p 5985 --script http-winrm-brute <target>",
      "Test-WSMan -ComputerName <target> (PowerShell)"
    ],
    relatedCVEs: ["CVE-2021-38647"]
  },
  {
    name: "IPMI",
    port: 623,
    transport: "UDP",
    description: "Intelligent Platform Management Interface -- provides management and monitoring of server hardware independent of the host OS, BIOS, or CPU.",
    securityNotes: "RAKP authentication returns password hashes that can be cracked offline. Cipher 0 bypasses authentication entirely. IPMI 2.0 hash disclosure is a design flaw.",
    commonVulns: [
      "RAKP hash disclosure (by design in IPMI 2.0)",
      "Cipher 0 authentication bypass",
      "Default credentials",
      "Plaintext password storage in BMC",
      "SOL (Serial Over LAN) session hijacking"
    ],
    testingCommands: [
      "nmap -sU -p 623 --script ipmi-version,ipmi-brute,ipmi-cipher-zero <target>",
      "ipmitool -I lanplus -H <target> -U admin -P admin chassis status",
      "msfconsole: use auxiliary/scanner/ipmi/ipmi_dumphashes"
    ],
    relatedCVEs: ["CVE-2013-4786", "CVE-2013-4037"]
  },
  {
    name: "DICOM",
    port: 104,
    transport: "TCP",
    description: "Digital Imaging and Communications in Medicine -- standard for handling, storing, transmitting, and printing medical imaging information.",
    securityNotes: "Often unencrypted and unauthenticated on hospital networks. Exposes patient health information (PHI). AE Title acts as weak shared secret.",
    commonVulns: [
      "Unauthenticated access to medical images",
      "PHI/PII data exposure",
      "C-FIND enumeration of patients",
      "C-MOVE image exfiltration",
      "AE Title enumeration"
    ],
    testingCommands: [
      "nmap -p 104 --script dicom-ping <target>",
      "dcm4che: findscu -c <target>:104",
      "orthanc explorer (DICOM viewer)"
    ],
    relatedCVEs: ["CVE-2019-11687", "CVE-2022-38100"]
  },
  {
    name: "AMQP",
    port: 5672,
    transport: "TCP",
    description: "Advanced Message Queuing Protocol -- open standard application layer protocol for message-oriented middleware with queuing, routing, and pub/sub capabilities.",
    securityNotes: "Authentication and access controls vary by implementation. TLS (AMQPS on 5671) should be enabled. Message content visible without encryption.",
    commonVulns: [
      "Default credentials",
      "Plaintext message interception",
      "Queue/exchange enumeration",
      "Message injection",
      "Consumer impersonation"
    ],
    testingCommands: [
      "nmap -p 5672 --script amqp-info <target>",
      "amqp-tools: amqp-consume -s <target> -e test",
      "python pika library for AMQP testing"
    ],
    relatedCVEs: []
  },
  {
    name: "Rsync",
    port: 873,
    transport: "TCP",
    description: "Rsync file synchronization protocol -- efficiently transfers and synchronizes files between systems using delta encoding.",
    securityNotes: "Anonymous rsync modules may expose sensitive files. No encryption by default (use rsync over SSH). Module listing reveals available shares.",
    commonVulns: [
      "Anonymous module access",
      "Sensitive file exposure",
      "No encryption (plaintext transfer)",
      "Module enumeration",
      "Writable module abuse"
    ],
    testingCommands: [
      "nmap -p 873 --script rsync-list-modules <target>",
      "rsync <target>::",
      "rsync -av <target>::<module> ./loot/",
      "rsync rsync://<target>/"
    ],
    relatedCVEs: ["CVE-2022-29154"]
  },
  {
    name: "LDAP (Active Directory)",
    port: 389,
    transport: "TCP",
    description: "LDAP in Active Directory context -- provides directory services for Windows domain environments including user, group, and computer object management.",
    securityNotes: "LDAP channel binding and signing should be enforced. Anonymous bind may expose AD structure. LDAP referral injection possible. AD CS (Certificate Services) via LDAP is an escalation path.",
    commonVulns: [
      "Anonymous bind enumeration",
      "LDAP signing not enforced",
      "AD CS ESC1-ESC8 abuse via LDAP",
      "Password spraying via LDAP bind",
      "BloodHound data collection"
    ],
    testingCommands: [
      "bloodhound-python -u <user> -p <pass> -d <domain> -dc <dc> -c all",
      "ldapdomaindump -u '<domain>\\<user>' -p <pass> <target>",
      "adidnsdump -u '<domain>\\<user>' -p <pass> <dc>",
      "certipy find -u <user>@<domain> -p <pass> -dc-ip <dc>"
    ],
    relatedCVEs: ["CVE-2021-42278", "CVE-2021-42287", "CVE-2022-26923"]
  },
  {
    name: "RPC (MS-RPC)",
    port: 135,
    transport: "TCP",
    description: "Microsoft Remote Procedure Call endpoint mapper -- locates RPC services running on remote machines. Gateway to numerous Windows services.",
    securityNotes: "Endpoint mapper reveals available RPC services. Many critical Windows exploits target RPC services. PetitPotam, PrintNightmare use RPC interfaces.",
    commonVulns: [
      "RPC service enumeration",
      "PetitPotam (EfsRpcOpenFileRaw)",
      "PrintNightmare (MS-RPRN/MS-PAR)",
      "MS-DCOM exploitation",
      "DCOM lateral movement"
    ],
    testingCommands: [
      "rpcclient -U '' -N <target>",
      "nmap -p 135 --script msrpc-enum <target>",
      "impacket-rpcdump <target>",
      "rpcmap.py <target>"
    ],
    relatedCVEs: ["CVE-2003-0352", "CVE-2021-36942", "CVE-2021-34527"]
  },

  // ---- Additional Protocols ----
  {
    name: "LDAP (Active Directory)",
    port: 389,
    transport: "TCP",
    description: "LDAP in Active Directory context -- provides directory services for Windows domain environments including user, group, and computer object management.",
    securityNotes: "LDAP channel binding and signing should be enforced. Anonymous bind may expose AD structure. LDAP referral injection possible. AD CS (Certificate Services) via LDAP is an escalation path.",
    commonVulns: [
      "Anonymous bind enumeration",
      "LDAP signing not enforced",
      "AD CS ESC1-ESC8 abuse via LDAP",
      "Password spraying via LDAP bind",
      "BloodHound data collection via LDAP"
    ],
    testingCommands: [
      "bloodhound-python -u <user> -p <pass> -d <domain> -dc <dc> -c all",
      "ldapdomaindump -u '<domain>\\<user>' -p <pass> <target>",
      "adidnsdump -u '<domain>\\<user>' -p <pass> <dc>",
      "certipy find -u <user>@<domain> -p <pass> -dc-ip <dc>"
    ],
    relatedCVEs: ["CVE-2021-42278", "CVE-2021-42287", "CVE-2022-26923"]
  },
  {
    name: "STUN",
    port: 3478,
    transport: "UDP/TCP",
    description: "Session Traversal Utilities for NAT -- enables clients behind NAT to discover their public IP and port mapping for peer-to-peer communication.",
    securityNotes: "Information disclosure of NAT topology. Can be abused for DDoS amplification. TURN (relay extension) adds authentication but may be misconfigured.",
    commonVulns: [
      "NAT topology disclosure",
      "STUN amplification",
      "TURN relay abuse for anonymization",
      "TURN credential brute force"
    ],
    testingCommands: [
      "nmap -sU -p 3478 <target>",
      "stun <target>:3478",
      "turnutils_uclient <target>"
    ],
    relatedCVEs: []
  },
  {
    name: "SNTP",
    port: 123,
    transport: "UDP",
    description: "Simple Network Time Protocol -- simplified version of NTP for time synchronization where full NTP precision is not required.",
    securityNotes: "Same vulnerabilities as NTP. Simpler clients may have weaker validation. Time spoofing breaks Kerberos and certificate validation.",
    commonVulns: [
      "Time spoofing attacks",
      "Amplification via monlist",
      "Kerberos ticket validation bypass",
      "Certificate validity manipulation"
    ],
    testingCommands: [
      "nmap -sU -p 123 --script ntp-info <target>",
      "ntpdate -q <target>"
    ],
    relatedCVEs: ["CVE-2013-5211"]
  },
  {
    name: "SSDP",
    port: 1900,
    transport: "UDP (Multicast)",
    description: "Simple Service Discovery Protocol -- discovery protocol for UPnP devices on local networks using HTTP-like multicast messages.",
    securityNotes: "Major amplification attack vector (30x amplification factor). UPnP devices often exposed to Internet. Enables internal network reconnaissance.",
    commonVulns: [
      "SSDP amplification DDoS (30x factor)",
      "UPnP device enumeration",
      "Internal service discovery",
      "UPnP port forwarding manipulation"
    ],
    testingCommands: [
      "nmap -sU -p 1900 --script upnp-info <target>",
      "miranda (UPnP tool)",
      "python -c \"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'M-SEARCH * HTTP/1.1\\r\\nHost:239.255.255.250:1900\\r\\nST:ssdp:all\\r\\nMAN:\\\"ssdp:discover\\\"\\r\\nMX:2\\r\\n\\r\\n',('239.255.255.250',1900))\""
    ],
    relatedCVEs: ["CVE-2020-12695"]
  },
  {
    name: "IGMP",
    port: null,
    transport: "IP Protocol 2",
    description: "Internet Group Management Protocol -- manages multicast group membership between hosts and routers on IPv4 networks.",
    securityNotes: "IGMP spoofing can join/leave multicast groups. Resource exhaustion via excessive group joins. Used in network reconnaissance to discover multicast infrastructure.",
    commonVulns: [
      "Multicast group hijacking",
      "IGMP flooding DoS",
      "Multicast traffic interception",
      "Switch CAM table overflow via multicast"
    ],
    testingCommands: [
      "nmap --script broadcast-igmp-discovery",
      "iperf -s -u -B 239.1.1.1 (multicast receive)",
      "wireshark: filter igmp"
    ],
    relatedCVEs: ["CVE-2009-2631"]
  }
];


// ---------------------------------------------------------------------------
// 2. PACKET_STRUCTURES -- Common packet headers explained field by field
// ---------------------------------------------------------------------------

export const PACKET_STRUCTURES = [
  {
    name: "IPv4 Header",
    protocol: "IPv4",
    minSize: "20 bytes",
    maxSize: "60 bytes",
    fields: [
      { name: "Version", bits: 4, description: "IP version (always 4 for IPv4)" },
      { name: "IHL", bits: 4, description: "Internet Header Length in 32-bit words (min 5, max 15)" },
      { name: "DSCP", bits: 6, description: "Differentiated Services Code Point for QoS classification" },
      { name: "ECN", bits: 2, description: "Explicit Congestion Notification flags" },
      { name: "Total Length", bits: 16, description: "Total packet length in bytes including header and data (max 65535)" },
      { name: "Identification", bits: 16, description: "Fragment identification for reassembly of fragmented packets" },
      { name: "Flags", bits: 3, description: "Bit 0: Reserved. Bit 1: Don't Fragment (DF). Bit 2: More Fragments (MF)" },
      { name: "Fragment Offset", bits: 13, description: "Offset of this fragment relative to original datagram in 8-byte units" },
      { name: "TTL", bits: 8, description: "Time to Live -- decremented by each router, packet discarded at 0" },
      { name: "Protocol", bits: 8, description: "Upper layer protocol number (6=TCP, 17=UDP, 1=ICMP, 89=OSPF)" },
      { name: "Header Checksum", bits: 16, description: "One's complement checksum of header only (not data)" },
      { name: "Source Address", bits: 32, description: "Sender's IPv4 address (can be spoofed)" },
      { name: "Destination Address", bits: 32, description: "Recipient's IPv4 address" },
      { name: "Options", bits: "0-320 (variable)", description: "Optional fields for source routing, record route, timestamps, etc." }
    ]
  },
  {
    name: "IPv6 Header",
    protocol: "IPv6",
    minSize: "40 bytes",
    maxSize: "40 bytes (fixed, extensions follow)",
    fields: [
      { name: "Version", bits: 4, description: "IP version (always 6 for IPv6)" },
      { name: "Traffic Class", bits: 8, description: "Similar to DSCP+ECN in IPv4, QoS and congestion notification" },
      { name: "Flow Label", bits: 20, description: "Labels packets belonging to the same flow for QoS handling" },
      { name: "Payload Length", bits: 16, description: "Length of payload in bytes (excluding 40-byte header)" },
      { name: "Next Header", bits: 8, description: "Type of next header (extension header or upper layer protocol)" },
      { name: "Hop Limit", bits: 8, description: "Equivalent to IPv4 TTL, decremented at each hop" },
      { name: "Source Address", bits: 128, description: "128-bit sender address" },
      { name: "Destination Address", bits: 128, description: "128-bit recipient address" }
    ]
  },
  {
    name: "TCP Header",
    protocol: "TCP",
    minSize: "20 bytes",
    maxSize: "60 bytes",
    fields: [
      { name: "Source Port", bits: 16, description: "Sender's port number (0-65535)" },
      { name: "Destination Port", bits: 16, description: "Recipient's port number identifying the target service" },
      { name: "Sequence Number", bits: 32, description: "Byte offset of first data byte in this segment (ISN during SYN)" },
      { name: "Acknowledgment Number", bits: 32, description: "Next expected byte from the other side (valid when ACK flag set)" },
      { name: "Data Offset", bits: 4, description: "TCP header length in 32-bit words (min 5 = 20 bytes)" },
      { name: "Reserved", bits: 3, description: "Reserved bits, must be zero" },
      { name: "Flags (NS)", bits: 1, description: "ECN-nonce concealment protection" },
      { name: "Flags (CWR)", bits: 1, description: "Congestion Window Reduced -- sender reduced congestion window" },
      { name: "Flags (ECE)", bits: 1, description: "ECN-Echo -- indicates ECN capability or congestion experienced" },
      { name: "Flags (URG)", bits: 1, description: "Urgent pointer field is significant" },
      { name: "Flags (ACK)", bits: 1, description: "Acknowledgment field is significant (set in all but initial SYN)" },
      { name: "Flags (PSH)", bits: 1, description: "Push function -- deliver data to application immediately" },
      { name: "Flags (RST)", bits: 1, description: "Reset the connection -- used for abort and error indication" },
      { name: "Flags (SYN)", bits: 1, description: "Synchronize sequence numbers -- connection establishment" },
      { name: "Flags (FIN)", bits: 1, description: "No more data from sender -- connection teardown" },
      { name: "Window Size", bits: 16, description: "Receive window size in bytes (flow control)" },
      { name: "Checksum", bits: 16, description: "One's complement checksum of header, data, and pseudo-header" },
      { name: "Urgent Pointer", bits: 16, description: "Offset from sequence number of last urgent data byte" },
      { name: "Options", bits: "0-320 (variable)", description: "MSS, Window Scale, SACK, Timestamps, etc." }
    ]
  },
  {
    name: "UDP Header",
    protocol: "UDP",
    minSize: "8 bytes",
    maxSize: "8 bytes",
    fields: [
      { name: "Source Port", bits: 16, description: "Sender's port number (optional, 0 if not used)" },
      { name: "Destination Port", bits: 16, description: "Recipient's port number" },
      { name: "Length", bits: 16, description: "Total datagram length in bytes (header + data, min 8)" },
      { name: "Checksum", bits: 16, description: "Optional in IPv4 (mandatory in IPv6), covers header and data" }
    ]
  },
  {
    name: "ICMP Header",
    protocol: "ICMP",
    minSize: "8 bytes",
    maxSize: "Variable",
    fields: [
      { name: "Type", bits: 8, description: "ICMP message type (0=Echo Reply, 3=Dest Unreachable, 8=Echo Request, 11=Time Exceeded)" },
      { name: "Code", bits: 8, description: "Subtype code providing additional context for the Type field" },
      { name: "Checksum", bits: 16, description: "One's complement checksum of entire ICMP message" },
      { name: "Rest of Header", bits: 32, description: "Type-specific data (e.g., Identifier+Sequence for Echo, MTU for Dest Unreachable)" },
      { name: "Data", bits: "Variable", description: "Payload (Echo: arbitrary data, Error: original datagram header + 8 bytes)" }
    ]
  },
  {
    name: "ARP Packet",
    protocol: "ARP",
    minSize: "28 bytes",
    maxSize: "28 bytes (for IPv4/Ethernet)",
    fields: [
      { name: "Hardware Type", bits: 16, description: "Link layer type (1 = Ethernet)" },
      { name: "Protocol Type", bits: 16, description: "Network layer protocol (0x0800 = IPv4)" },
      { name: "Hardware Address Length", bits: 8, description: "Length of hardware address in bytes (6 for Ethernet MAC)" },
      { name: "Protocol Address Length", bits: 8, description: "Length of protocol address in bytes (4 for IPv4)" },
      { name: "Operation", bits: 16, description: "ARP operation (1=Request, 2=Reply, 3=RARP Request, 4=RARP Reply)" },
      { name: "Sender Hardware Address", bits: 48, description: "MAC address of the sender" },
      { name: "Sender Protocol Address", bits: 32, description: "IPv4 address of the sender" },
      { name: "Target Hardware Address", bits: 48, description: "MAC address of the target (0 in ARP requests)" },
      { name: "Target Protocol Address", bits: 32, description: "IPv4 address of the target being queried" }
    ]
  },
  {
    name: "DNS Header",
    protocol: "DNS",
    minSize: "12 bytes",
    maxSize: "12 bytes (header only, plus variable question/answer sections)",
    fields: [
      { name: "Transaction ID", bits: 16, description: "Random identifier matching queries to responses (predictable values enable poisoning)" },
      { name: "Flags (QR)", bits: 1, description: "Query (0) or Response (1)" },
      { name: "Flags (Opcode)", bits: 4, description: "Query type (0=Standard, 1=Inverse, 2=Status, 4=Notify, 5=Update)" },
      { name: "Flags (AA)", bits: 1, description: "Authoritative Answer -- server is authoritative for the domain" },
      { name: "Flags (TC)", bits: 1, description: "Truncation -- message truncated, retry with TCP" },
      { name: "Flags (RD)", bits: 1, description: "Recursion Desired -- client requests recursive resolution" },
      { name: "Flags (RA)", bits: 1, description: "Recursion Available -- server supports recursive queries" },
      { name: "Flags (Z)", bits: 1, description: "Reserved (must be zero)" },
      { name: "Flags (AD)", bits: 1, description: "Authenticated Data -- DNSSEC validation passed" },
      { name: "Flags (CD)", bits: 1, description: "Checking Disabled -- DNSSEC validation skipped by resolver" },
      { name: "Flags (RCODE)", bits: 4, description: "Response code (0=NoError, 1=FormErr, 2=ServFail, 3=NXDomain, 5=Refused)" },
      { name: "Question Count", bits: 16, description: "Number of questions in the query section" },
      { name: "Answer Count", bits: 16, description: "Number of resource records in the answer section" },
      { name: "Authority Count", bits: 16, description: "Number of resource records in the authority section" },
      { name: "Additional Count", bits: 16, description: "Number of resource records in the additional section" }
    ]
  },
  {
    name: "HTTP Request",
    protocol: "HTTP/1.1",
    minSize: "Variable",
    maxSize: "Variable (typically limited by server configuration)",
    fields: [
      { name: "Request Line", bits: "Variable", description: "Method SP Request-URI SP HTTP-Version CRLF (e.g., 'GET /index.html HTTP/1.1')" },
      { name: "Host Header", bits: "Variable", description: "Mandatory in HTTP/1.1 -- target hostname for virtual hosting" },
      { name: "User-Agent", bits: "Variable", description: "Client software identification string" },
      { name: "Accept", bits: "Variable", description: "Media types the client is willing to receive (content negotiation)" },
      { name: "Accept-Encoding", bits: "Variable", description: "Acceptable compression algorithms (gzip, deflate, br)" },
      { name: "Connection", bits: "Variable", description: "Connection management (keep-alive, close)" },
      { name: "Cookie", bits: "Variable", description: "Session cookies and client-side state" },
      { name: "Authorization", bits: "Variable", description: "Authentication credentials (Basic, Bearer, Digest)" },
      { name: "Content-Type", bits: "Variable", description: "MIME type of request body (for POST/PUT)" },
      { name: "Content-Length", bits: "Variable", description: "Size of request body in bytes" },
      { name: "CRLF", bits: 16, description: "Empty line separating headers from body" },
      { name: "Body", bits: "Variable", description: "Request payload (POST data, file uploads, JSON, etc.)" }
    ]
  },
  {
    name: "TLS Record",
    protocol: "TLS 1.2/1.3",
    minSize: "5 bytes (header)",
    maxSize: "16389 bytes (5 header + 16384 data)",
    fields: [
      { name: "Content Type", bits: 8, description: "Record type: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=Application Data" },
      { name: "Version (Legacy)", bits: 16, description: "TLS version (0x0301=TLS 1.0, 0x0302=1.1, 0x0303=1.2/1.3)" },
      { name: "Length", bits: 16, description: "Length of following record data (max 16384, or 16384+padding for encrypted)" },
      { name: "Record Data", bits: "Variable", description: "Handshake messages, encrypted application data, or alert messages" }
    ]
  },
  {
    name: "TLS ClientHello",
    protocol: "TLS 1.2/1.3",
    minSize: "Variable",
    maxSize: "Variable",
    fields: [
      { name: "Handshake Type", bits: 8, description: "0x01 = ClientHello" },
      { name: "Length", bits: 24, description: "Length of ClientHello message body" },
      { name: "Client Version", bits: 16, description: "Highest TLS version supported (0x0303 for TLS 1.2+)" },
      { name: "Client Random", bits: 256, description: "32 bytes of random data used in key derivation" },
      { name: "Session ID Length", bits: 8, description: "Length of session ID for session resumption (0 if none)" },
      { name: "Session ID", bits: "Variable", description: "Previous session ID for resumption" },
      { name: "Cipher Suites Length", bits: 16, description: "Length of cipher suite list in bytes" },
      { name: "Cipher Suites", bits: "Variable", description: "Ordered list of supported cipher suites (2 bytes each)" },
      { name: "Compression Methods", bits: "Variable", description: "Supported compression (should be null/none only)" },
      { name: "Extensions Length", bits: 16, description: "Length of extensions block" },
      { name: "Extensions", bits: "Variable", description: "SNI, supported_versions, key_share, signature_algorithms, ALPN, etc." }
    ]
  },
  {
    name: "Ethernet Frame",
    protocol: "Ethernet II",
    minSize: "64 bytes (including FCS)",
    maxSize: "1518 bytes (or 9018 for jumbo frames)",
    fields: [
      { name: "Preamble", bits: 56, description: "Alternating 1s and 0s for clock synchronization (10101010 pattern)" },
      { name: "SFD", bits: 8, description: "Start Frame Delimiter (10101011) marks end of preamble" },
      { name: "Destination MAC", bits: 48, description: "Recipient's MAC address (FF:FF:FF:FF:FF:FF for broadcast)" },
      { name: "Source MAC", bits: 48, description: "Sender's MAC address" },
      { name: "EtherType / Length", bits: 16, description: "Protocol identifier (0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6) or frame length" },
      { name: "Payload", bits: "368-12000", description: "Data payload (46-1500 bytes for standard Ethernet)" },
      { name: "FCS", bits: 32, description: "Frame Check Sequence -- CRC-32 error detection" }
    ]
  },
  {
    name: "SMB2 Header",
    protocol: "SMB2/3",
    minSize: "64 bytes",
    maxSize: "64 bytes",
    fields: [
      { name: "Protocol ID", bits: 32, description: "Magic bytes 0xFE534D42 ('\\xFESMB')" },
      { name: "Structure Size", bits: 16, description: "Header structure size (always 64)" },
      { name: "Credit Charge", bits: 16, description: "Number of credits consumed by this request" },
      { name: "Status / Channel Sequence", bits: 32, description: "NT Status code (response) or Channel Sequence (request)" },
      { name: "Command", bits: 16, description: "SMB2 command code (0=Negotiate, 1=SessionSetup, 5=Create, 8=Read, 9=Write)" },
      { name: "Credit Request/Response", bits: 16, description: "Credits requested by client or granted by server" },
      { name: "Flags", bits: 32, description: "SMB2_FLAGS_SERVER_TO_REDIR, SMB2_FLAGS_ASYNC_COMMAND, SMB2_FLAGS_SIGNED, etc." },
      { name: "Next Command", bits: 32, description: "Offset to next command in compound request (0 if last)" },
      { name: "Message ID", bits: 64, description: "Unique message identifier for matching requests to responses" },
      { name: "Process ID", bits: 32, description: "Process identifier (reserved in SMB 3.x)" },
      { name: "Tree ID", bits: 32, description: "Identifies connected share" },
      { name: "Session ID", bits: 64, description: "Identifies authenticated session" },
      { name: "Signature", bits: 128, description: "Message signature for integrity (when signing is enabled)" }
    ]
  },
  {
    name: "LDAP Message (BER)",
    protocol: "LDAP",
    minSize: "Variable",
    maxSize: "Variable",
    fields: [
      { name: "Tag (SEQUENCE)", bits: 8, description: "ASN.1 tag 0x30 indicating SEQUENCE type" },
      { name: "Length", bits: "8-40", description: "BER-encoded length of the message contents" },
      { name: "Message ID", bits: "Variable (INTEGER)", description: "Integer identifying the LDAP operation for matching responses" },
      { name: "Protocol Op", bits: "Variable", description: "LDAP operation: BindRequest(0), SearchRequest(3), ModifyRequest(6), etc." },
      { name: "Controls", bits: "Variable (optional)", description: "Optional sequence of LDAP controls (paging, sort, etc.)" }
    ]
  },
  {
    name: "Kerberos AS-REQ",
    protocol: "Kerberos v5",
    minSize: "Variable",
    maxSize: "Variable",
    fields: [
      { name: "PVNO", bits: "Variable", description: "Protocol version number (5)" },
      { name: "MSG-TYPE", bits: "Variable", description: "Message type (10 = AS-REQ, 12 = TGS-REQ)" },
      { name: "PA-DATA", bits: "Variable", description: "Pre-authentication data (PA-ENC-TIMESTAMP for password, PA-PK-AS-REQ for PKINIT)" },
      { name: "REQ-BODY", bits: "Variable", description: "Request body containing:" },
      { name: "  KDC-Options", bits: 32, description: "Flags: forwardable, renewable, canonicalize, etc." },
      { name: "  CName", bits: "Variable", description: "Client principal name (username)" },
      { name: "  Realm", bits: "Variable", description: "Kerberos realm (domain name)" },
      { name: "  SName", bits: "Variable", description: "Server principal name (krbtgt/<realm> for AS-REQ)" },
      { name: "  Till", bits: "Variable", description: "Requested ticket expiration time" },
      { name: "  Nonce", bits: 32, description: "Random nonce for replay protection" },
      { name: "  EType", bits: "Variable", description: "Requested encryption types in preference order (23=RC4, 17=AES128, 18=AES256)" }
    ]
  },
  {
    name: "SNMP v2c Message",
    protocol: "SNMPv2c",
    minSize: "Variable",
    maxSize: "Variable",
    fields: [
      { name: "SEQUENCE Tag", bits: 8, description: "ASN.1 SEQUENCE (0x30)" },
      { name: "Length", bits: "Variable", description: "BER length of entire SNMP message" },
      { name: "Version", bits: "Variable (INTEGER)", description: "SNMP version (0=v1, 1=v2c, 3=v3)" },
      { name: "Community String", bits: "Variable (OCTET STRING)", description: "Community string for authentication (often 'public' or 'private')" },
      { name: "PDU Type", bits: 8, description: "PDU type tag (0xA0=GetRequest, 0xA1=GetNextRequest, 0xA2=GetResponse, 0xA3=SetRequest, 0xA5=GetBulkRequest, 0xA7=SNMPv2-Trap)" },
      { name: "Request ID", bits: "Variable (INTEGER)", description: "Unique identifier matching request to response" },
      { name: "Error Status", bits: "Variable (INTEGER)", description: "Error indicator (0=noError, 1=tooBig, 2=noSuchName, etc.)" },
      { name: "Error Index", bits: "Variable (INTEGER)", description: "Points to variable binding that caused error" },
      { name: "Variable Bindings", bits: "Variable (SEQUENCE)", description: "List of OID-value pairs being queried or set" }
    ]
  },
  {
    name: "DHCP Message",
    protocol: "DHCP",
    minSize: "236 bytes (+ options)",
    maxSize: "576 bytes (minimum MTU support)",
    fields: [
      { name: "Op", bits: 8, description: "Message op code (1=BOOTREQUEST from client, 2=BOOTREPLY from server)" },
      { name: "HType", bits: 8, description: "Hardware address type (1 = Ethernet)" },
      { name: "HLen", bits: 8, description: "Hardware address length (6 for Ethernet MAC)" },
      { name: "Hops", bits: 8, description: "Relay agent hops (incremented by each relay)" },
      { name: "XID", bits: 32, description: "Transaction ID chosen by client to match requests/responses" },
      { name: "Secs", bits: 16, description: "Seconds elapsed since client began address acquisition" },
      { name: "Flags", bits: 16, description: "Broadcast flag (bit 0) -- client requests broadcast response" },
      { name: "CIAddr", bits: 32, description: "Client IP address (set if client has a valid address)" },
      { name: "YIAddr", bits: 32, description: "Your (client) IP address -- offered/assigned by server" },
      { name: "SIAddr", bits: 32, description: "Next server IP address for bootstrap (TFTP server)" },
      { name: "GIAddr", bits: 32, description: "Relay agent IP address" },
      { name: "CHAddr", bits: 128, description: "Client hardware address (padded to 16 bytes)" },
      { name: "SName", bits: 512, description: "Server host name (64 bytes, null-terminated)" },
      { name: "File", bits: 1024, description: "Boot filename (128 bytes, null-terminated)" },
      { name: "Magic Cookie", bits: 32, description: "0x63825363 marks start of DHCP options" },
      { name: "Options", bits: "Variable", description: "DHCP options: message type(53), subnet mask(1), router(3), DNS(6), lease time(51), etc." }
    ]
  },
  {
    name: "Modbus TCP/IP ADU",
    protocol: "Modbus TCP",
    minSize: "12 bytes",
    maxSize: "260 bytes",
    fields: [
      { name: "Transaction ID", bits: 16, description: "Identification of the transaction (echoed in response)" },
      { name: "Protocol ID", bits: 16, description: "Protocol identifier (0x0000 for Modbus)" },
      { name: "Length", bits: 16, description: "Number of following bytes (Unit ID + PDU)" },
      { name: "Unit ID", bits: 8, description: "Slave/unit identifier (or 0xFF for broadcast)" },
      { name: "Function Code", bits: 8, description: "Modbus function (1=Read Coils, 2=Read Discrete Inputs, 3=Read Holding Registers, 4=Read Input Registers, 5=Write Single Coil, 6=Write Single Register, 15=Write Multiple Coils, 16=Write Multiple Registers)" },
      { name: "Data", bits: "Variable", description: "Function-specific data (starting address, quantity, values)" }
    ]
  },
  {
    name: "MQTT Fixed Header",
    protocol: "MQTT v3.1.1/5.0",
    minSize: "2 bytes",
    maxSize: "5 bytes (fixed header)",
    fields: [
      { name: "Packet Type", bits: 4, description: "Control packet type (1=CONNECT, 2=CONNACK, 3=PUBLISH, 4=PUBACK, 8=SUBSCRIBE, 12=PINGREQ, 14=DISCONNECT)" },
      { name: "Flags", bits: 4, description: "Type-specific flags (DUP, QoS level, RETAIN for PUBLISH)" },
      { name: "Remaining Length", bits: "8-32", description: "Variable-length encoding of remaining packet size (1-4 bytes, max 256MB)" }
    ]
  },
  {
    name: "DNS Resource Record",
    protocol: "DNS",
    minSize: "Variable",
    maxSize: "Variable",
    fields: [
      { name: "NAME", bits: "Variable", description: "Domain name in label format (or pointer via compression, 0xC0xx)" },
      { name: "TYPE", bits: 16, description: "RR type (1=A, 2=NS, 5=CNAME, 6=SOA, 15=MX, 16=TXT, 28=AAAA, 33=SRV, 257=CAA)" },
      { name: "CLASS", bits: 16, description: "DNS class (1=IN for Internet)" },
      { name: "TTL", bits: 32, description: "Time to live in seconds -- how long the record may be cached" },
      { name: "RDLENGTH", bits: 16, description: "Length of RDATA in bytes" },
      { name: "RDATA", bits: "Variable", description: "Resource data (e.g., 4 bytes for A record IPv4 address, variable for TXT)" }
    ]
  },
  {
    name: "RADIUS Access-Request",
    protocol: "RADIUS",
    minSize: "20 bytes",
    maxSize: "4096 bytes",
    fields: [
      { name: "Code", bits: 8, description: "Packet type (1=Access-Request, 2=Access-Accept, 3=Access-Reject, 4=Accounting-Request, 5=Accounting-Response, 11=Access-Challenge)" },
      { name: "Identifier", bits: 8, description: "Unique identifier matching request to response (0-255)" },
      { name: "Length", bits: 16, description: "Total packet length including header and attributes (20-4096 bytes)" },
      { name: "Authenticator", bits: 128, description: "16-byte field: random in requests, MD5(Code+ID+Length+RequestAuth+Attributes+Secret) in responses" },
      { name: "Attributes", bits: "Variable", description: "Type-Length-Value attribute pairs: User-Name(1), User-Password(2), NAS-IP-Address(4), NAS-Port(5), Service-Type(6), Framed-Protocol(7), etc." }
    ]
  }
];


// ---------------------------------------------------------------------------
// 3. WIRESHARK_FILTERS -- 200+ display/capture filters organized by purpose
// ---------------------------------------------------------------------------

export const WIRESHARK_FILTERS = {
  // ---- Protocol-Specific Filters (50+) ----
  protocolSpecific: [
    { filter: "tcp", description: "All TCP traffic" },
    { filter: "udp", description: "All UDP traffic" },
    { filter: "icmp", description: "All ICMP traffic" },
    { filter: "arp", description: "All ARP traffic" },
    { filter: "dns", description: "All DNS traffic" },
    { filter: "http", description: "All HTTP traffic" },
    { filter: "http2", description: "All HTTP/2 traffic" },
    { filter: "tls", description: "All TLS/SSL traffic" },
    { filter: "ssl", description: "All SSL traffic (legacy alias for TLS)" },
    { filter: "ssh", description: "All SSH traffic" },
    { filter: "ftp", description: "All FTP control channel traffic" },
    { filter: "ftp-data", description: "All FTP data channel traffic" },
    { filter: "smtp", description: "All SMTP traffic" },
    { filter: "imap", description: "All IMAP traffic" },
    { filter: "pop", description: "All POP3 traffic" },
    { filter: "smb", description: "All SMB/CIFS traffic" },
    { filter: "smb2", description: "All SMB2/SMB3 traffic" },
    { filter: "ldap", description: "All LDAP traffic" },
    { filter: "kerberos", description: "All Kerberos traffic" },
    { filter: "snmp", description: "All SNMP traffic" },
    { filter: "rdp", description: "All RDP traffic" },
    { filter: "vnc", description: "All VNC/RFB traffic" },
    { filter: "dhcp", description: "All DHCP traffic" },
    { filter: "ntp", description: "All NTP traffic" },
    { filter: "sip", description: "All SIP traffic" },
    { filter: "rtp", description: "All RTP traffic" },
    { filter: "rtsp", description: "All RTSP traffic" },
    { filter: "bgp", description: "All BGP traffic" },
    { filter: "ospf", description: "All OSPF traffic" },
    { filter: "mysql", description: "All MySQL protocol traffic" },
    { filter: "pgsql", description: "All PostgreSQL traffic" },
    { filter: "tds", description: "All TDS (MSSQL) traffic" },
    { filter: "mongo", description: "All MongoDB traffic" },
    { filter: "redis", description: "All Redis protocol traffic (RESP)" },
    { filter: "amqp", description: "All AMQP traffic" },
    { filter: "mqtt", description: "All MQTT traffic" },
    { filter: "coap", description: "All CoAP traffic" },
    { filter: "grpc", description: "All gRPC traffic" },
    { filter: "quic", description: "All QUIC traffic" },
    { filter: "syslog", description: "All Syslog traffic" },
    { filter: "radius", description: "All RADIUS traffic" },
    { filter: "tacplus", description: "All TACACS+ traffic" },
    { filter: "modbus", description: "All Modbus traffic" },
    { filter: "dnp3", description: "All DNP3 traffic" },
    { filter: "opcua", description: "All OPC-UA traffic" },
    { filter: "bacnet", description: "All BACnet traffic" },
    { filter: "s7comm", description: "All Siemens S7comm traffic" },
    { filter: "enip", description: "All EtherNet/IP traffic" },
    { filter: "ipmi", description: "All IPMI traffic" },
    { filter: "dcerpc", description: "All DCE/RPC traffic" },
    { filter: "nbns", description: "All NetBIOS Name Service traffic" },
    { filter: "llmnr", description: "All LLMNR traffic" },
    { filter: "mdns", description: "All mDNS traffic" },
    { filter: "vrrp", description: "All VRRP traffic" },
    { filter: "hsrp", description: "All HSRP traffic" },
    { filter: "igmp", description: "All IGMP traffic" },
    { filter: "stp", description: "All Spanning Tree Protocol traffic" },
    { filter: "lldp", description: "All LLDP (Link Layer Discovery Protocol) traffic" }
  ],

  // ---- Attack Detection Filters (30+) ----
  attackDetection: [
    { filter: "tcp.flags.syn == 1 && tcp.flags.ack == 0", description: "SYN packets only (SYN flood detection)" },
    { filter: "tcp.flags == 0x002 && tcp.window_size <= 1024", description: "SYN packets with small window (scanner signature)" },
    { filter: "tcp.flags.reset == 1", description: "TCP RST packets (connection reset attacks)" },
    { filter: "tcp.flags == 0x029", description: "XMAS scan detection (FIN+PSH+URG)" },
    { filter: "tcp.flags == 0x000", description: "NULL scan detection (no flags set)" },
    { filter: "tcp.flags == 0x001", description: "FIN scan detection (FIN only)" },
    { filter: "arp.duplicate-address-detected", description: "ARP duplicate address (possible spoofing)" },
    { filter: "arp.opcode == 2 && arp.src.hw_mac != <gateway_mac>", description: "ARP replies not from gateway (spoofing detection)" },
    { filter: "dns.qry.type == 255", description: "DNS ANY queries (amplification attack indicator)" },
    { filter: "dns.flags.response == 1 && dns.resp.len > 512", description: "Large DNS responses (amplification)" },
    { filter: "dns.qry.name contains '..' || dns.qry.name contains '\\x00'", description: "Suspicious DNS query content" },
    { filter: "http.request.method == \"CONNECT\"", description: "HTTP CONNECT method (proxy tunneling)" },
    { filter: "http.request.uri contains \"..\"", description: "Directory traversal attempts in HTTP" },
    { filter: "http.request.uri matches \"(\\.\\./){3,}\"", description: "Path traversal (3+ levels up)" },
    { filter: "http.request.uri contains \"cmd.exe\" || http.request.uri contains \"/bin/sh\"", description: "Command injection in URL" },
    { filter: "http.request.uri matches \"(?i)(union|select|insert|update|delete|drop).*(?i)(from|into|table|database)\"", description: "SQL injection patterns in URL" },
    { filter: "http.request.uri contains \"<script\" || http.request.uri contains \"javascript:\"", description: "XSS patterns in URL" },
    { filter: "http.content_type contains \"multipart\" && http.request.method == \"POST\" && http.content_length > 10000000", description: "Large file upload (possible webshell)" },
    { filter: "icmp.type == 3 && icmp.code == 3", description: "ICMP Port Unreachable (port scan responses)" },
    { filter: "icmp.type == 8 && data.len > 100", description: "Large ICMP echo requests (possible tunnel)" },
    { filter: "smb2.cmd == 3 && smb2.tree contains \"IPC$\"", description: "SMB IPC$ tree connect (recon/exploitation)" },
    { filter: "ntlmssp.auth.domain && ntlmssp", description: "NTLM authentication traffic (relay attack surface)" },
    { filter: "kerberos.msg_type == 13", description: "Kerberos TGS-REP (Kerberoasting indicator)" },
    { filter: "kerberos.msg_type == 11 && kerberos.error_code == 6", description: "Kerberos pre-auth failure (password spraying)" },
    { filter: "ldap.bindRequest && !ldap.bindRequest.authentication.simple == \"\"", description: "LDAP bind with credentials" },
    { filter: "rdp.neg.type == 0x01 && rdp.neg.selectedprotocol == 0", description: "RDP without NLA (BlueKeep-vulnerable config)" },
    { filter: "ssh.kex.algorithms contains \"diffie-hellman-group1-sha1\"", description: "SSH weak key exchange algorithm" },
    { filter: "tls.handshake.extensions_server_name", description: "TLS SNI (domain identification in encrypted traffic)" },
    { filter: "tls.record.version < 0x0303", description: "TLS version less than 1.2 (weak)" },
    { filter: "smtp.req.command == \"VRFY\" || smtp.req.command == \"EXPN\"", description: "SMTP user enumeration commands" },
    { filter: "ftp.request.command == \"PASS\" || ftp.request.command == \"USER\"", description: "FTP credentials in transit" },
    { filter: "telnet && data.data contains 50:61:73:73:77:6f:72:64", description: "Telnet password prompt (plaintext auth)" },
    { filter: "wlan.fc.type_subtype == 0x000c", description: "Wi-Fi deauthentication frames (deauth attack)" },
    { filter: "eapol", description: "EAPOL frames (WPA handshake capture)" }
  ],

  // ---- Troubleshooting Filters (30+) ----
  troubleshooting: [
    { filter: "tcp.analysis.retransmission", description: "TCP retransmissions (packet loss indicator)" },
    { filter: "tcp.analysis.fast_retransmission", description: "TCP fast retransmissions (detected via duplicate ACKs)" },
    { filter: "tcp.analysis.duplicate_ack", description: "Duplicate ACKs (packet loss / reordering)" },
    { filter: "tcp.analysis.zero_window", description: "TCP zero window (receiver buffer full)" },
    { filter: "tcp.analysis.window_update", description: "TCP window updates (flow control changes)" },
    { filter: "tcp.analysis.out_of_order", description: "Out-of-order TCP segments" },
    { filter: "tcp.analysis.lost_segment", description: "TCP lost segments detected" },
    { filter: "tcp.analysis.keep_alive", description: "TCP keepalive probes" },
    { filter: "tcp.analysis.reset", description: "Connection resets (RST flag analysis)" },
    { filter: "icmp.type == 3", description: "ICMP Destination Unreachable (routing/firewall issues)" },
    { filter: "icmp.type == 3 && icmp.code == 4", description: "ICMP Fragmentation Needed (MTU issues / PMTUD)" },
    { filter: "icmp.type == 11", description: "ICMP Time Exceeded (TTL expired, routing loops)" },
    { filter: "icmp.type == 5", description: "ICMP Redirect (routing change notification)" },
    { filter: "dns.flags.rcode != 0", description: "DNS error responses (NXDOMAIN, SERVFAIL, etc.)" },
    { filter: "dns.flags.rcode == 2", description: "DNS SERVFAIL responses" },
    { filter: "dns.flags.rcode == 3", description: "DNS NXDOMAIN responses" },
    { filter: "dns.time > 0.5", description: "Slow DNS queries (>500ms response time)" },
    { filter: "http.response.code >= 400", description: "HTTP error responses (4xx and 5xx)" },
    { filter: "http.response.code == 500", description: "HTTP 500 Internal Server Error" },
    { filter: "http.response.code == 502", description: "HTTP 502 Bad Gateway" },
    { filter: "http.response.code == 503", description: "HTTP 503 Service Unavailable" },
    { filter: "http.time > 5", description: "Slow HTTP responses (>5 seconds)" },
    { filter: "tls.alert_message", description: "TLS alert messages (handshake failures, etc.)" },
    { filter: "tls.alert_message.level == 2", description: "TLS fatal alert messages" },
    { filter: "tls.handshake.type == 2 && tls.handshake.extensions.supported_versions == 0x0303", description: "TLS 1.2 ServerHello (version negotiation check)" },
    { filter: "dhcp.option.dhcp == 6", description: "DHCP NAK responses (address assignment failures)" },
    { filter: "ip.checksum_bad.expert || tcp.checksum_bad.expert || udp.checksum_bad.expert", description: "Bad checksums (corruption or offloading)" },
    { filter: "frame.time_delta > 1", description: "Gaps > 1 second between consecutive packets" },
    { filter: "ip.ttl < 5", description: "Very low TTL values (possible routing issues)" },
    { filter: "ip.fragment", description: "IP fragmented packets (MTU or attack)" },
    { filter: "tcp.connection.syn_ack_rtt > 0.5", description: "Slow SYN-ACK response (server overload indicator)" },
    { filter: "smb2.nt_status != 0x00000000", description: "SMB errors (access denied, file not found)" },
    { filter: "ldap.resultCode != 0", description: "LDAP error responses" }
  ],

  // ---- Performance Analysis Filters (20+) ----
  performanceAnalysis: [
    { filter: "tcp.analysis.ack_rtt > 0.2", description: "High TCP round-trip time (>200ms)" },
    { filter: "tcp.analysis.ack_rtt > 1", description: "Very high TCP RTT (>1 second)" },
    { filter: "tcp.window_size_value < 2048", description: "Small TCP window (potential throughput bottleneck)" },
    { filter: "tcp.window_size_scalefactor > 0", description: "TCP connections using window scaling" },
    { filter: "tcp.analysis.bytes_in_flight > 65535", description: "Large data in flight (high bandwidth usage)" },
    { filter: "frame.len > 1500", description: "Jumbo frames or fragmented packets" },
    { filter: "frame.len < 64", description: "Runt frames (possible errors)" },
    { filter: "ip.dsfield.dscp > 0", description: "Packets with QoS markings (DSCP)" },
    { filter: "tcp.options.mss_val < 1460", description: "Non-standard MSS values (tunneling or MTU issues)" },
    { filter: "http.response_number > 0 && http.time > 2", description: "Slow HTTP transactions (>2 seconds)" },
    { filter: "tcp.analysis.window_full", description: "TCP window full events (receiver bottleneck)" },
    { filter: "tcp.len > 0 && tcp.nxtseq == tcp.seq", description: "TCP segments with no new data (possible retransmission)" },
    { filter: "dns.time > 1", description: "DNS queries taking over 1 second" },
    { filter: "smb2.time > 1", description: "Slow SMB2 operations (>1 second)" },
    { filter: "tls.handshake.type == 1 && frame.time_delta_displayed > 0.5", description: "Slow TLS connection initiation" },
    { filter: "tcp.analysis.initial_rtt > 0.1", description: "Initial TCP RTT > 100ms" },
    { filter: "http.content_length > 1048576", description: "HTTP responses over 1MB" },
    { filter: "ip.len > 1400 && ip.flags.mf == 1", description: "Large fragmented IP packets (MTU issues)" },
    { filter: "tcp.options.sack_le", description: "TCP Selective Acknowledgment blocks (loss recovery)" },
    { filter: "tcp.analysis.reused_ports", description: "TCP port reuse (connection pool behavior)" },
    { filter: "frame.time_relative > 60 && tcp.analysis.keep_alive", description: "Long-lived connections with keepalives" },
    { filter: "tcp.reassembled.length > 65535", description: "Large reassembled TCP streams" }
  ],

  // ---- IoT / SCADA Filters (20+) ----
  iotScada: [
    { filter: "modbus", description: "All Modbus TCP traffic" },
    { filter: "modbus.func_code == 1", description: "Modbus Read Coils (function code 1)" },
    { filter: "modbus.func_code == 3", description: "Modbus Read Holding Registers (function code 3)" },
    { filter: "modbus.func_code == 5", description: "Modbus Write Single Coil (function code 5)" },
    { filter: "modbus.func_code == 6", description: "Modbus Write Single Register (function code 6)" },
    { filter: "modbus.func_code == 15", description: "Modbus Write Multiple Coils (function code 15)" },
    { filter: "modbus.func_code == 16", description: "Modbus Write Multiple Registers (function code 16)" },
    { filter: "modbus.func_code >= 128", description: "Modbus exception responses (error conditions)" },
    { filter: "dnp3", description: "All DNP3 traffic" },
    { filter: "dnp3.al.func == 0x01", description: "DNP3 Read requests" },
    { filter: "dnp3.al.func == 0x02", description: "DNP3 Write requests" },
    { filter: "dnp3.al.func == 0x03 || dnp3.al.func == 0x04", description: "DNP3 Select/Operate (control commands)" },
    { filter: "dnp3.al.func == 0x0d", description: "DNP3 Cold Restart command" },
    { filter: "s7comm", description: "All Siemens S7comm traffic" },
    { filter: "s7comm.param.func == 0x04", description: "S7comm Read Variable requests" },
    { filter: "s7comm.param.func == 0x05", description: "S7comm Write Variable requests" },
    { filter: "s7comm.param.func == 0x28", description: "S7comm Setup Communication" },
    { filter: "s7comm.param.func == 0x29", description: "S7comm CPU Stop/Start" },
    { filter: "opcua", description: "All OPC-UA traffic" },
    { filter: "bacnet", description: "All BACnet traffic" },
    { filter: "enip", description: "All EtherNet/IP traffic" },
    { filter: "enip.command == 0x006f", description: "EtherNet/IP SendRRData (explicit messaging)" },
    { filter: "enip.command == 0x0070", description: "EtherNet/IP SendUnitData (connected messaging)" },
    { filter: "mqtt", description: "All MQTT traffic" },
    { filter: "mqtt.msgtype == 3", description: "MQTT PUBLISH messages" },
    { filter: "mqtt.msgtype == 8", description: "MQTT SUBSCRIBE messages" },
    { filter: "mqtt.topic contains \"#\" || mqtt.topic contains \"+\"", description: "MQTT wildcard subscriptions" },
    { filter: "coap", description: "All CoAP traffic" },
    { filter: "coap.code >= 128", description: "CoAP response codes (success/error)" },
    { filter: "zbee_nwk", description: "ZigBee network layer traffic" },
    { filter: "zbee_aps", description: "ZigBee application support layer" }
  ],

  // ---- Wireless Filters (20+) ----
  wireless: [
    { filter: "wlan", description: "All 802.11 wireless frames" },
    { filter: "wlan.fc.type == 0", description: "802.11 management frames" },
    { filter: "wlan.fc.type == 1", description: "802.11 control frames" },
    { filter: "wlan.fc.type == 2", description: "802.11 data frames" },
    { filter: "wlan.fc.type_subtype == 0x0000", description: "Association Request frames" },
    { filter: "wlan.fc.type_subtype == 0x0001", description: "Association Response frames" },
    { filter: "wlan.fc.type_subtype == 0x0004", description: "Probe Request frames (client scanning)" },
    { filter: "wlan.fc.type_subtype == 0x0005", description: "Probe Response frames" },
    { filter: "wlan.fc.type_subtype == 0x0008", description: "Beacon frames (AP advertisement)" },
    { filter: "wlan.fc.type_subtype == 0x000b", description: "Authentication frames" },
    { filter: "wlan.fc.type_subtype == 0x000c", description: "Deauthentication frames (attack indicator)" },
    { filter: "wlan.fc.type_subtype == 0x000a", description: "Disassociation frames" },
    { filter: "wlan.bssid == AA:BB:CC:DD:EE:FF", description: "Traffic for specific access point (replace MAC)" },
    { filter: "wlan.addr == AA:BB:CC:DD:EE:FF", description: "All traffic involving specific wireless device" },
    { filter: "wlan.ssid == \"TargetSSID\"", description: "Frames for specific SSID" },
    { filter: "wlan.rsn.akms.type == 2", description: "WPA2-PSK authentication" },
    { filter: "wlan.rsn.akms.type == 1", description: "WPA2-Enterprise (802.1X) authentication" },
    { filter: "wlan.rsn.akms.type == 8", description: "WPA3-SAE authentication" },
    { filter: "eapol", description: "EAPOL key exchange (WPA/WPA2 4-way handshake)" },
    { filter: "eapol.keydes.type == 2", description: "EAPOL RSN (WPA2) key frames" },
    { filter: "wlan.wep.key", description: "WEP-encrypted frames" },
    { filter: "wlan.fc.protected == 1", description: "Protected (encrypted) wireless frames" },
    { filter: "wlan.fc.retry == 1", description: "Retransmitted wireless frames (poor signal)" },
    { filter: "wlan_radio.signal_dbm < -70", description: "Weak signal frames (below -70 dBm)" },
    { filter: "wlan.tag.number == 48", description: "RSN Information Element (security capabilities)" },
    { filter: "wlan.fc.type_subtype == 0x000d && wlan.fixed.reason_code == 7", description: "Deauth due to leaving BSS (possible forced deauth)" }
  ],

  // ---- Capture Filters (BPF syntax, for capture-time filtering) ----
  captureFilters: [
    { filter: "host 192.168.1.100", description: "Capture: traffic to/from specific host" },
    { filter: "net 192.168.1.0/24", description: "Capture: traffic on specific subnet" },
    { filter: "port 80", description: "Capture: traffic on port 80 (HTTP)" },
    { filter: "port 443", description: "Capture: traffic on port 443 (HTTPS)" },
    { filter: "tcp port 22", description: "Capture: SSH traffic only" },
    { filter: "udp port 53", description: "Capture: DNS traffic only" },
    { filter: "not port 22", description: "Capture: exclude SSH traffic" },
    { filter: "src host 10.0.0.1", description: "Capture: traffic from specific source" },
    { filter: "dst host 10.0.0.1", description: "Capture: traffic to specific destination" },
    { filter: "tcp portrange 1-1024", description: "Capture: well-known TCP ports" },
    { filter: "ether host aa:bb:cc:dd:ee:ff", description: "Capture: traffic involving specific MAC" },
    { filter: "ether broadcast", description: "Capture: broadcast traffic only" },
    { filter: "ip proto 1", description: "Capture: ICMP protocol only" },
    { filter: "greater 1000", description: "Capture: packets larger than 1000 bytes" },
    { filter: "less 100", description: "Capture: packets smaller than 100 bytes" },
    { filter: "tcp[tcpflags] & (tcp-syn) != 0", description: "Capture: TCP SYN flag set" },
    { filter: "tcp[tcpflags] & (tcp-rst) != 0", description: "Capture: TCP RST flag set" },
    { filter: "tcp[13] == 0x02", description: "Capture: SYN-only packets (exact match)" },
    { filter: "tcp[13] == 0x12", description: "Capture: SYN-ACK packets" },
    { filter: "vlan", description: "Capture: VLAN-tagged frames" },
    { filter: "ip multicast", description: "Capture: multicast traffic" },
    { filter: "not arp", description: "Capture: exclude ARP traffic" },
    { filter: "host 192.168.1.100 and port 445", description: "Capture: SMB traffic for specific host" },
    { filter: "src net 10.0.0.0/8 and dst net 172.16.0.0/12", description: "Capture: traffic between two private ranges" }
  ]
};


// ---------------------------------------------------------------------------
// 4. NMAP_SCRIPTS -- 100+ NSE script references
// ---------------------------------------------------------------------------

export const NMAP_SCRIPTS = [
  // ---- Discovery & Enumeration ----
  {
    name: "dns-brute",
    category: "discovery",
    description: "Attempts to enumerate DNS hostnames by brute forcing popular subdomain names against a target domain.",
    usage: "nmap --script dns-brute --script-args dns-brute.domain=<domain>,dns-brute.threads=10 <target>",
    output: "List of discovered subdomains and their resolved IP addresses"
  },
  {
    name: "dns-zone-transfer",
    category: "discovery",
    description: "Requests a zone transfer (AXFR) from a DNS server to retrieve all records for a domain.",
    usage: "nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=<domain> <dns_server>",
    output: "Complete zone file with all DNS records if transfer is permitted"
  },
  {
    name: "dns-srv-enum",
    category: "discovery",
    description: "Enumerates SRV records for common services like LDAP, Kerberos, SIP, and XMPP.",
    usage: "nmap --script dns-srv-enum --script-args dns-srv-enum.domain=<domain> <target>",
    output: "SRV records with service names, ports, and target hosts"
  },
  {
    name: "dns-nsid",
    category: "discovery",
    description: "Retrieves DNS server identity information via the NSID EDNS option.",
    usage: "nmap -sU -p 53 --script dns-nsid <target>",
    output: "DNS server identity string and version information"
  },
  {
    name: "broadcast-dhcp-discover",
    category: "discovery",
    description: "Sends a DHCP DISCOVER broadcast to identify DHCP servers on the local network.",
    usage: "nmap --script broadcast-dhcp-discover",
    output: "DHCP server IP, offered IP range, lease time, DNS, gateway"
  },
  {
    name: "broadcast-dns-service-discovery",
    category: "discovery",
    description: "Discovers services using DNS-SD (mDNS/Bonjour) on the local network.",
    usage: "nmap --script broadcast-dns-service-discovery",
    output: "List of advertised services with names, ports, and TXT records"
  },
  {
    name: "targets-sniffer",
    category: "discovery",
    description: "Sniffs the local network to discover active hosts by passively monitoring traffic.",
    usage: "nmap --script targets-sniffer --script-args targets-sniffer.timeout=30 -sn",
    output: "List of IP addresses observed on the network"
  },
  {
    name: "ip-geolocation-geoplugin",
    category: "discovery",
    description: "Queries the GeoPlugin API to determine geographic location of IP addresses.",
    usage: "nmap --script ip-geolocation-geoplugin <target>",
    output: "Country, region, city, latitude, longitude for target IP"
  },
  {
    name: "whois-domain",
    category: "discovery",
    description: "Queries WHOIS databases for domain registration information.",
    usage: "nmap --script whois-domain --script-args whois.whodb=nofollow <target>",
    output: "Domain registrar, registration/expiry dates, nameservers, registrant info"
  },
  {
    name: "traceroute-geolocation",
    category: "discovery",
    description: "Performs a traceroute and attempts to geolocate each hop.",
    usage: "nmap --traceroute --script traceroute-geolocation <target>",
    output: "Traceroute with geographic coordinates for each hop"
  },

  // ---- HTTP Scripts ----
  {
    name: "http-enum",
    category: "discovery",
    description: "Enumerates common web application directories and files (robots.txt, admin panels, etc.).",
    usage: "nmap -p 80,443 --script http-enum <target>",
    output: "List of discovered directories, files, and interesting paths"
  },
  {
    name: "http-title",
    category: "discovery",
    description: "Shows the title of the default page of a web server.",
    usage: "nmap -p 80,443 --script http-title <target>",
    output: "HTML title tag content from the web server's default page"
  },
  {
    name: "http-headers",
    category: "discovery",
    description: "Performs a HEAD request and displays HTTP response headers.",
    usage: "nmap -p 80,443 --script http-headers <target>",
    output: "All HTTP response headers including server, security headers, cookies"
  },
  {
    name: "http-methods",
    category: "discovery",
    description: "Finds which HTTP methods are supported by the server (GET, POST, PUT, DELETE, OPTIONS, etc.).",
    usage: "nmap -p 80 --script http-methods --script-args http-methods.url-path='/api/' <target>",
    output: "List of supported HTTP methods and potentially risky ones"
  },
  {
    name: "http-robots.txt",
    category: "discovery",
    description: "Retrieves and parses robots.txt to find disallowed paths (potential sensitive directories).",
    usage: "nmap -p 80 --script http-robots.txt <target>",
    output: "Disallowed and allowed paths from robots.txt"
  },
  {
    name: "http-sitemap-generator",
    category: "discovery",
    description: "Spiders a website and generates a directory structure sitemap.",
    usage: "nmap -p 80 --script http-sitemap-generator <target>",
    output: "Hierarchical sitemap of discovered pages and resources"
  },
  {
    name: "http-vhosts",
    category: "discovery",
    description: "Searches for web virtual hosts by sending HTTP requests with different Host headers.",
    usage: "nmap -p 80 --script http-vhosts --script-args http-vhosts.filelist=vhosts.txt <target>",
    output: "Virtual host names that respond differently from the default"
  },
  {
    name: "http-waf-detect",
    category: "discovery",
    description: "Attempts to determine whether a web server is behind a Web Application Firewall.",
    usage: "nmap -p 80 --script http-waf-detect <target>",
    output: "WAF detection result and identified WAF product name if possible"
  },
  {
    name: "http-waf-fingerprint",
    category: "discovery",
    description: "Attempts to fingerprint the specific WAF product protecting a web application.",
    usage: "nmap -p 80 --script http-waf-fingerprint <target>",
    output: "Identified WAF vendor and product"
  },
  {
    name: "http-sql-injection",
    category: "vuln",
    description: "Spiders a web application looking for URLs with query parameters and tests them for SQL injection.",
    usage: "nmap -p 80 --script http-sql-injection <target>",
    output: "List of URLs potentially vulnerable to SQL injection"
  },
  {
    name: "http-xssed",
    category: "vuln",
    description: "Checks xssed.com for known XSS vulnerabilities associated with the target.",
    usage: "nmap -p 80 --script http-xssed <target>",
    output: "Known XSS vulnerabilities from xssed.com database"
  },
  {
    name: "http-shellshock",
    category: "vuln",
    description: "Tests for the Shellshock (CVE-2014-6271) vulnerability in CGI scripts.",
    usage: "nmap -p 80 --script http-shellshock --script-args uri=/cgi-bin/test.cgi <target>",
    output: "Shellshock vulnerability status for specified CGI scripts"
  },
  {
    name: "http-slowloris-check",
    category: "vuln",
    description: "Tests whether a web server is vulnerable to the Slowloris DoS attack.",
    usage: "nmap -p 80 --script http-slowloris-check <target>",
    output: "Vulnerability assessment for Slowloris slow HTTP attack"
  },
  {
    name: "http-cookie-flags",
    category: "safe",
    description: "Examines cookies set by HTTP services and reports missing security flags (httponly, secure).",
    usage: "nmap -p 80 --script http-cookie-flags <target>",
    output: "Cookie names with missing httponly and secure flags"
  },
  {
    name: "http-security-headers",
    category: "safe",
    description: "Checks for the presence of various HTTP security headers.",
    usage: "nmap -p 80 --script http-security-headers <target>",
    output: "Missing security headers (CSP, HSTS, X-Frame-Options, etc.)"
  },
  {
    name: "http-cors",
    category: "safe",
    description: "Tests Cross-Origin Resource Sharing (CORS) configuration of web servers.",
    usage: "nmap -p 80 --script http-cors <target>",
    output: "CORS policy details including allowed origins, methods, headers"
  },
  {
    name: "http-php-version",
    category: "discovery",
    description: "Attempts to discover the PHP version by sending crafted queries.",
    usage: "nmap -p 80 --script http-php-version <target>",
    output: "PHP version information (if exposed)"
  },
  {
    name: "http-wordpress-enum",
    category: "discovery",
    description: "Enumerates WordPress themes, plugins, and users.",
    usage: "nmap -p 80 --script http-wordpress-enum <target>",
    output: "WordPress plugins, themes, and user accounts"
  },
  {
    name: "http-git",
    category: "vuln",
    description: "Checks for an exposed .git repository on a web server.",
    usage: "nmap -p 80 --script http-git <target>",
    output: "Git repository exposure details including remote URLs and branch info"
  },
  {
    name: "http-config-backup",
    category: "vuln",
    description: "Checks for common configuration backup files (web.config.bak, .htaccess.bak, etc.).",
    usage: "nmap -p 80 --script http-config-backup <target>",
    output: "Discovered backup configuration files"
  },

  // ---- SSL/TLS Scripts ----
  {
    name: "ssl-enum-ciphers",
    category: "discovery",
    description: "Lists SSL/TLS cipher suites offered by a server, grading them by strength.",
    usage: "nmap -p 443 --script ssl-enum-ciphers <target>",
    output: "Cipher suites per TLS version with strength grades (A-F)"
  },
  {
    name: "ssl-cert",
    category: "discovery",
    description: "Retrieves and displays the SSL certificate from a server.",
    usage: "nmap -p 443 --script ssl-cert <target>",
    output: "Certificate subject, issuer, validity dates, SANs, key details"
  },
  {
    name: "ssl-date",
    category: "discovery",
    description: "Retrieves the server's time from the TLS handshake timestamp.",
    usage: "nmap -p 443 --script ssl-date <target>",
    output: "Server timestamp and clock skew from your local time"
  },
  {
    name: "ssl-heartbleed",
    category: "vuln",
    description: "Tests for the OpenSSL Heartbleed vulnerability (CVE-2014-0160).",
    usage: "nmap -p 443 --script ssl-heartbleed <target>",
    output: "Heartbleed vulnerability status (VULNERABLE or safe)"
  },
  {
    name: "ssl-poodle",
    category: "vuln",
    description: "Tests for the POODLE vulnerability (SSLv3 CBC padding oracle).",
    usage: "nmap -p 443 --script ssl-poodle <target>",
    output: "POODLE vulnerability status"
  },
  {
    name: "ssl-ccs-injection",
    category: "vuln",
    description: "Tests for the CCS Injection vulnerability (CVE-2014-0224).",
    usage: "nmap -p 443 --script ssl-ccs-injection <target>",
    output: "CCS injection vulnerability status"
  },
  {
    name: "ssl-dh-params",
    category: "vuln",
    description: "Tests for weak Diffie-Hellman key exchange parameters (Logjam, etc.).",
    usage: "nmap -p 443 --script ssl-dh-params <target>",
    output: "DH parameter strength, Logjam vulnerability status"
  },
  {
    name: "ssl-known-key",
    category: "vuln",
    description: "Checks whether the SSL certificate uses a known compromised key (e.g., Debian weak keys).",
    usage: "nmap -p 443 --script ssl-known-key <target>",
    output: "Whether the key matches known compromised key databases"
  },

  // ---- SMB Scripts ----
  {
    name: "smb-enum-shares",
    category: "discovery",
    description: "Enumerates SMB shares on a target and shows access permissions.",
    usage: "nmap -p 445 --script smb-enum-shares <target>",
    output: "Share names, paths, types, comments, and access levels"
  },
  {
    name: "smb-enum-users",
    category: "discovery",
    description: "Enumerates users on a Windows system via SMB.",
    usage: "nmap -p 445 --script smb-enum-users <target>",
    output: "User accounts, RIDs, and account descriptions"
  },
  {
    name: "smb-enum-domains",
    category: "discovery",
    description: "Enumerates domains on a Windows system and retrieves domain policies.",
    usage: "nmap -p 445 --script smb-enum-domains <target>",
    output: "Domain names, password policies, lockout thresholds"
  },
  {
    name: "smb-enum-groups",
    category: "discovery",
    description: "Enumerates local groups and their members on a Windows system.",
    usage: "nmap -p 445 --script smb-enum-groups <target>",
    output: "Group names, RIDs, and member lists"
  },
  {
    name: "smb-os-discovery",
    category: "discovery",
    description: "Discovers OS version, computer name, domain, and workgroup via SMB.",
    usage: "nmap -p 445 --script smb-os-discovery <target>",
    output: "OS version, NetBIOS name, domain/workgroup, system time"
  },
  {
    name: "smb-security-mode",
    category: "discovery",
    description: "Determines the security level of SMB (message signing, authentication).",
    usage: "nmap -p 445 --script smb-security-mode <target>",
    output: "SMB signing status, authentication level, challenge/response mode"
  },
  {
    name: "smb-vuln-ms17-010",
    category: "vuln",
    description: "Tests for the EternalBlue (MS17-010) vulnerability in SMBv1.",
    usage: "nmap -p 445 --script smb-vuln-ms17-010 <target>",
    output: "EternalBlue vulnerability status and affected OS details"
  },
  {
    name: "smb-vuln-ms08-067",
    category: "vuln",
    description: "Tests for the Conficker/MS08-067 vulnerability in the Server service.",
    usage: "nmap -p 445 --script smb-vuln-ms08-067 <target>",
    output: "MS08-067 vulnerability status"
  },
  {
    name: "smb2-security-mode",
    category: "discovery",
    description: "Determines SMB2/SMB3 security mode including message signing requirement.",
    usage: "nmap -p 445 --script smb2-security-mode <target>",
    output: "SMB2 message signing status (enabled/required)"
  },
  {
    name: "smb-protocols",
    category: "discovery",
    description: "Determines which SMB protocol dialects are supported (SMBv1, SMBv2, SMBv3).",
    usage: "nmap -p 445 --script smb-protocols <target>",
    output: "List of supported SMB protocol versions"
  },
  {
    name: "smb-brute",
    category: "brute",
    description: "Brute-force attacks SMB authentication.",
    usage: "nmap -p 445 --script smb-brute --script-args userdb=users.txt,passdb=passwords.txt <target>",
    output: "Valid username/password combinations found"
  },

  // ---- SSH Scripts ----
  {
    name: "ssh2-enum-algos",
    category: "discovery",
    description: "Reports supported algorithms (key exchange, encryption, MAC, compression) for SSH2.",
    usage: "nmap -p 22 --script ssh2-enum-algos <target>",
    output: "Lists of supported KEX, encryption, MAC, and compression algorithms"
  },
  {
    name: "ssh-hostkey",
    category: "discovery",
    description: "Retrieves SSH host keys and fingerprints.",
    usage: "nmap -p 22 --script ssh-hostkey --script-args ssh_hostkey=full <target>",
    output: "Host key types, key data, MD5 and SHA256 fingerprints"
  },
  {
    name: "ssh-auth-methods",
    category: "discovery",
    description: "Lists authentication methods supported by an SSH server.",
    usage: "nmap -p 22 --script ssh-auth-methods <target>",
    output: "Supported auth methods (publickey, password, keyboard-interactive, etc.)"
  },
  {
    name: "ssh-brute",
    category: "brute",
    description: "Brute-force attacks SSH authentication.",
    usage: "nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt <target>",
    output: "Valid SSH credential pairs"
  },
  {
    name: "ssh-publickey-acceptance",
    category: "auth",
    description: "Tests whether specific public keys are accepted for SSH authentication.",
    usage: "nmap -p 22 --script ssh-publickey-acceptance --script-args ssh.publickey=/path/to/key <target>",
    output: "Whether the provided public key is accepted"
  },

  // ---- Database Scripts ----
  {
    name: "mysql-info",
    category: "discovery",
    description: "Retrieves MySQL server version, protocol, and capability flags.",
    usage: "nmap -p 3306 --script mysql-info <target>",
    output: "MySQL version, protocol, server capabilities, connection status"
  },
  {
    name: "mysql-enum",
    category: "discovery",
    description: "Enumerates valid MySQL usernames using authentication bypass technique.",
    usage: "nmap -p 3306 --script mysql-enum <target>",
    output: "Valid MySQL usernames on the server"
  },
  {
    name: "mysql-brute",
    category: "brute",
    description: "Brute-force attacks MySQL authentication.",
    usage: "nmap -p 3306 --script mysql-brute --script-args userdb=users.txt,passdb=pass.txt <target>",
    output: "Valid MySQL credential pairs"
  },
  {
    name: "mysql-empty-password",
    category: "vuln",
    description: "Tests MySQL for accounts with empty passwords.",
    usage: "nmap -p 3306 --script mysql-empty-password <target>",
    output: "MySQL accounts with blank passwords (especially root)"
  },
  {
    name: "mysql-databases",
    category: "discovery",
    description: "Lists databases on a MySQL server (requires valid credentials).",
    usage: "nmap -p 3306 --script mysql-databases --script-args mysqluser=root,mysqlpass='' <target>",
    output: "List of MySQL databases"
  },
  {
    name: "ms-sql-info",
    category: "discovery",
    description: "Retrieves MSSQL server version, instance name, and configuration.",
    usage: "nmap -p 1433 --script ms-sql-info <target>",
    output: "SQL Server version, instance name, TCP port, named pipe"
  },
  {
    name: "ms-sql-brute",
    category: "brute",
    description: "Brute-force attacks MSSQL authentication.",
    usage: "nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=pass.txt <target>",
    output: "Valid MSSQL credential pairs"
  },
  {
    name: "ms-sql-empty-password",
    category: "vuln",
    description: "Tests MSSQL for the sa account with an empty password.",
    usage: "nmap -p 1433 --script ms-sql-empty-password <target>",
    output: "Whether sa or other accounts have blank passwords"
  },
  {
    name: "ms-sql-xp-cmdshell",
    category: "vuln",
    description: "Attempts to execute OS commands via xp_cmdshell on MSSQL.",
    usage: "nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password='',ms-sql-xp-cmdshell.cmd='whoami' <target>",
    output: "Command execution output from the database server"
  },
  {
    name: "pgsql-brute",
    category: "brute",
    description: "Brute-force attacks PostgreSQL authentication.",
    usage: "nmap -p 5432 --script pgsql-brute --script-args userdb=users.txt,passdb=pass.txt <target>",
    output: "Valid PostgreSQL credential pairs"
  },
  {
    name: "mongodb-databases",
    category: "discovery",
    description: "Lists databases on a MongoDB server (if authentication is not required).",
    usage: "nmap -p 27017 --script mongodb-databases <target>",
    output: "Database names and sizes"
  },
  {
    name: "mongodb-info",
    category: "discovery",
    description: "Retrieves MongoDB server information including version and build info.",
    usage: "nmap -p 27017 --script mongodb-info <target>",
    output: "MongoDB version, server status, and configuration details"
  },
  {
    name: "mongodb-brute",
    category: "brute",
    description: "Brute-force attacks MongoDB authentication.",
    usage: "nmap -p 27017 --script mongodb-brute <target>",
    output: "Valid MongoDB credentials"
  },
  {
    name: "redis-info",
    category: "discovery",
    description: "Retrieves Redis server information including version, memory, clients.",
    usage: "nmap -p 6379 --script redis-info <target>",
    output: "Redis version, connected clients, memory usage, keyspace stats"
  },
  {
    name: "redis-brute",
    category: "brute",
    description: "Brute-force attacks Redis authentication.",
    usage: "nmap -p 6379 --script redis-brute <target>",
    output: "Valid Redis passwords"
  },
  {
    name: "cassandra-info",
    category: "discovery",
    description: "Retrieves Cassandra cluster information.",
    usage: "nmap -p 9042 --script cassandra-info <target>",
    output: "Cluster name, partitioner, snitch, and schema versions"
  },
  {
    name: "cassandra-brute",
    category: "brute",
    description: "Brute-force attacks Cassandra authentication.",
    usage: "nmap -p 9042 --script cassandra-brute <target>",
    output: "Valid Cassandra credentials"
  },
  {
    name: "oracle-tns-version",
    category: "discovery",
    description: "Retrieves Oracle TNS Listener version.",
    usage: "nmap -p 1521 --script oracle-tns-version <target>",
    output: "TNS Listener version and protocol information"
  },
  {
    name: "oracle-sid-brute",
    category: "brute",
    description: "Brute-force guesses Oracle SID (System Identifier) names.",
    usage: "nmap -p 1521 --script oracle-sid-brute <target>",
    output: "Valid Oracle SIDs (ORCL, XE, etc.)"
  },

  // ---- SNMP Scripts ----
  {
    name: "snmp-info",
    category: "discovery",
    description: "Retrieves basic SNMP information including system description and contact.",
    usage: "nmap -sU -p 161 --script snmp-info <target>",
    output: "System description, contact, location, uptime, OID"
  },
  {
    name: "snmp-brute",
    category: "brute",
    description: "Brute-forces SNMP community strings.",
    usage: "nmap -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=communities.txt <target>",
    output: "Valid community strings with access level (read/write)"
  },
  {
    name: "snmp-sysdescr",
    category: "discovery",
    description: "Retrieves the system description OID from SNMP-enabled devices.",
    usage: "nmap -sU -p 161 --script snmp-sysdescr <target>",
    output: "System description string (OS, version, hardware info)"
  },
  {
    name: "snmp-interfaces",
    category: "discovery",
    description: "Enumerates network interfaces via SNMP.",
    usage: "nmap -sU -p 161 --script snmp-interfaces <target>",
    output: "Interface names, IPs, MAC addresses, status, speeds"
  },
  {
    name: "snmp-processes",
    category: "discovery",
    description: "Lists running processes via SNMP.",
    usage: "nmap -sU -p 161 --script snmp-processes <target>",
    output: "Running process names, PIDs, and resource usage"
  },
  {
    name: "snmp-netstat",
    category: "discovery",
    description: "Enumerates network connections (like netstat) via SNMP.",
    usage: "nmap -sU -p 161 --script snmp-netstat <target>",
    output: "Active TCP/UDP connections with local/remote addresses and ports"
  },
  {
    name: "snmp-win32-software",
    category: "discovery",
    description: "Enumerates installed software on Windows via SNMP.",
    usage: "nmap -sU -p 161 --script snmp-win32-software <target>",
    output: "Installed software names and versions"
  },
  {
    name: "snmp-win32-users",
    category: "discovery",
    description: "Enumerates Windows user accounts via SNMP.",
    usage: "nmap -sU -p 161 --script snmp-win32-users <target>",
    output: "Windows user account names"
  },

  // ---- LDAP / Kerberos / AD Scripts ----
  {
    name: "ldap-rootdse",
    category: "discovery",
    description: "Retrieves the LDAP Root DSE (Directory Server Agent) information.",
    usage: "nmap -p 389 --script ldap-rootdse <target>",
    output: "Naming contexts, supported controls, LDAP version, server name"
  },
  {
    name: "ldap-search",
    category: "discovery",
    description: "Performs an LDAP search against a directory server.",
    usage: "nmap -p 389 --script ldap-search --script-args ldap.base='dc=domain,dc=com' <target>",
    output: "LDAP directory entries matching the search filter"
  },
  {
    name: "ldap-brute",
    category: "brute",
    description: "Brute-force attacks LDAP authentication.",
    usage: "nmap -p 389 --script ldap-brute --script-args ldap.base='dc=domain,dc=com' <target>",
    output: "Valid LDAP credentials"
  },
  {
    name: "krb5-enum-users",
    category: "discovery",
    description: "Enumerates valid Kerberos usernames by exploiting AS-REQ response differences.",
    usage: "nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='DOMAIN.COM',userdb=users.txt <target>",
    output: "Valid domain usernames confirmed via Kerberos"
  },

  // ---- VoIP Scripts ----
  {
    name: "sip-methods",
    category: "discovery",
    description: "Discovers supported SIP methods (INVITE, REGISTER, OPTIONS, etc.).",
    usage: "nmap -sU -p 5060 --script sip-methods <target>",
    output: "List of supported SIP methods"
  },
  {
    name: "sip-enum-users",
    category: "discovery",
    description: "Enumerates valid SIP user extensions.",
    usage: "nmap -sU -p 5060 --script sip-enum-users <target>",
    output: "Valid SIP extension numbers and user agents"
  },

  // ---- ICS/SCADA Scripts ----
  {
    name: "modbus-discover",
    category: "discovery",
    description: "Identifies Modbus devices and retrieves device identification.",
    usage: "nmap -p 502 --script modbus-discover <target>",
    output: "Modbus device ID, vendor, product name, firmware version"
  },
  {
    name: "s7-info",
    category: "discovery",
    description: "Retrieves Siemens S7 PLC information including module, serial, firmware.",
    usage: "nmap -p 102 --script s7-info <target>",
    output: "PLC module type, serial number, firmware version, plant ID"
  },
  {
    name: "dnp3-info",
    category: "discovery",
    description: "Retrieves DNP3 device information from an outstation.",
    usage: "nmap -p 20000 --script dnp3-info <target>",
    output: "DNP3 device identification and supported function codes"
  },
  {
    name: "enip-info",
    category: "discovery",
    description: "Retrieves EtherNet/IP device information via CIP Identity request.",
    usage: "nmap -p 44818 --script enip-info <target>",
    output: "Device vendor, product name, serial, firmware version"
  },
  {
    name: "bacnet-info",
    category: "discovery",
    description: "Retrieves BACnet device information.",
    usage: "nmap -sU -p 47808 --script bacnet-info <target>",
    output: "BACnet device instance, vendor, model, firmware, application"
  },

  // ---- Network Infrastructure Scripts ----
  {
    name: "nbstat",
    category: "discovery",
    description: "Retrieves NetBIOS name table from a host.",
    usage: "nmap -sU -p 137 --script nbstat <target>",
    output: "NetBIOS names, name types, MAC address, domain/workgroup"
  },
  {
    name: "ntp-info",
    category: "discovery",
    description: "Retrieves NTP server status and configuration variables.",
    usage: "nmap -sU -p 123 --script ntp-info <target>",
    output: "NTP version, reference clock, stratum, precision"
  },
  {
    name: "ntp-monlist",
    category: "vuln",
    description: "Tests for NTP monlist command (amplification attack vector).",
    usage: "nmap -sU -p 123 --script ntp-monlist <target>",
    output: "Recent NTP clients if monlist is enabled (CVE-2013-5211)"
  },
  {
    name: "dhcp-discover",
    category: "discovery",
    description: "Sends a DHCP request to discover DHCP server information.",
    usage: "nmap -sU -p 67 --script dhcp-discover <target>",
    output: "DHCP server IP, offered IP, subnet mask, gateway, DNS, lease time"
  },
  {
    name: "pptp-version",
    category: "discovery",
    description: "Retrieves PPTP VPN server version information.",
    usage: "nmap -p 1723 --script pptp-version <target>",
    output: "PPTP hostname, vendor, firmware version"
  },
  {
    name: "ike-version",
    category: "discovery",
    description: "Identifies IKE version and VPN gateway vendor.",
    usage: "nmap -sU -p 500 --script ike-version <target>",
    output: "IKE version, vendor ID, supported transforms"
  },

  // ---- Vulnerability Detection Scripts ----
  {
    name: "vulners",
    category: "vuln",
    description: "Queries vulners.com vulnerability database for known CVEs based on detected service versions.",
    usage: "nmap -sV --script vulners <target>",
    output: "CVE IDs and CVSS scores for detected service versions"
  },
  {
    name: "vulscan",
    category: "vuln",
    description: "Advanced vulnerability scanner using offline CVE databases (requires vulscan NSE script).",
    usage: "nmap -sV --script vulscan/vulscan.nse <target>",
    output: "Potential vulnerabilities from multiple offline databases"
  },
  {
    name: "smb-vuln-ms12-020",
    category: "vuln",
    description: "Tests for the MS12-020 RDP vulnerability (pre-authentication DoS/RCE).",
    usage: "nmap -p 3389 --script smb-vuln-ms12-020 <target>",
    output: "MS12-020 vulnerability status"
  },
  {
    name: "rdp-enum-encryption",
    category: "discovery",
    description: "Enumerates RDP encryption levels and security protocols.",
    usage: "nmap -p 3389 --script rdp-enum-encryption <target>",
    output: "Supported RDP encryption levels and security layers"
  },
  {
    name: "rdp-ntlm-info",
    category: "discovery",
    description: "Retrieves NTLM authentication information from RDP (domain, hostname, OS version).",
    usage: "nmap -p 3389 --script rdp-ntlm-info <target>",
    output: "Target domain, computer name, DNS name, OS build number"
  },
  {
    name: "ftp-anon",
    category: "auth",
    description: "Tests whether anonymous FTP login is allowed.",
    usage: "nmap -p 21 --script ftp-anon <target>",
    output: "Anonymous FTP access status and root directory listing"
  },
  {
    name: "ftp-bounce",
    category: "vuln",
    description: "Tests whether an FTP server allows bounce scanning (PORT command abuse).",
    usage: "nmap -p 21 --script ftp-bounce <target>",
    output: "FTP bounce scan capability status"
  },
  {
    name: "ftp-vsftpd-backdoor",
    category: "vuln",
    description: "Tests for the vsftpd 2.3.4 backdoor (CVE-2011-2523).",
    usage: "nmap -p 21 --script ftp-vsftpd-backdoor <target>",
    output: "Backdoor exploitation status"
  },
  {
    name: "smtp-commands",
    category: "discovery",
    description: "Enumerates SMTP commands supported by the server.",
    usage: "nmap -p 25 --script smtp-commands <target>",
    output: "Supported SMTP commands (EHLO response)"
  },
  {
    name: "smtp-enum-users",
    category: "discovery",
    description: "Enumerates SMTP users via VRFY, EXPN, and RCPT TO methods.",
    usage: "nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY} <target>",
    output: "Valid email addresses / user accounts"
  },
  {
    name: "smtp-open-relay",
    category: "vuln",
    description: "Tests whether an SMTP server is an open relay.",
    usage: "nmap -p 25 --script smtp-open-relay <target>",
    output: "Open relay test results for various source/dest combinations"
  },
  {
    name: "vnc-info",
    category: "discovery",
    description: "Retrieves VNC server information including protocol version and security types.",
    usage: "nmap -p 5900 --script vnc-info <target>",
    output: "VNC protocol version, security types (None, VNC Auth, TLS)"
  },
  {
    name: "vnc-brute",
    category: "brute",
    description: "Brute-force attacks VNC authentication.",
    usage: "nmap -p 5900 --script vnc-brute <target>",
    output: "Valid VNC passwords"
  },
  {
    name: "ipmi-version",
    category: "discovery",
    description: "Retrieves IPMI version and BMC information.",
    usage: "nmap -sU -p 623 --script ipmi-version <target>",
    output: "IPMI version, firmware version, BMC manufacturer"
  },
  {
    name: "ipmi-cipher-zero",
    category: "vuln",
    description: "Tests for IPMI cipher 0 authentication bypass vulnerability.",
    usage: "nmap -sU -p 623 --script ipmi-cipher-zero <target>",
    output: "Whether IPMI cipher 0 (no auth) is enabled"
  },
  {
    name: "ipmi-brute",
    category: "brute",
    description: "Brute-force attacks IPMI authentication (RAKP).",
    usage: "nmap -sU -p 623 --script ipmi-brute <target>",
    output: "Valid IPMI credentials"
  },
  {
    name: "mqtt-subscribe",
    category: "discovery",
    description: "Subscribes to MQTT topics and displays messages.",
    usage: "nmap -p 1883 --script mqtt-subscribe --script-args mqtt-subscribe.topic='#' <target>",
    output: "MQTT messages from subscribed topics"
  },
  {
    name: "amqp-info",
    category: "discovery",
    description: "Retrieves AMQP (RabbitMQ) server information.",
    usage: "nmap -p 5672 --script amqp-info <target>",
    output: "AMQP product, version, platform, copyright info"
  },
  {
    name: "memcached-info",
    category: "discovery",
    description: "Retrieves memcached server statistics.",
    usage: "nmap -p 11211 --script memcached-info <target>",
    output: "Version, uptime, current items, memory usage, connections"
  },
  {
    name: "rsync-list-modules",
    category: "discovery",
    description: "Lists available rsync modules on a server.",
    usage: "nmap -p 873 --script rsync-list-modules <target>",
    output: "Module names and descriptions"
  },
  {
    name: "docker-version",
    category: "discovery",
    description: "Retrieves Docker engine version information from the Docker API.",
    usage: "nmap -p 2375 --script docker-version <target>",
    output: "Docker version, API version, OS/arch, kernel version"
  },
  {
    name: "couchdb-databases",
    category: "discovery",
    description: "Lists databases on a CouchDB server.",
    usage: "nmap -p 5984 --script couchdb-databases <target>",
    output: "CouchDB database names"
  },
  {
    name: "couchdb-stats",
    category: "discovery",
    description: "Retrieves CouchDB server statistics.",
    usage: "nmap -p 5984 --script couchdb-stats <target>",
    output: "CouchDB request counts, open databases, OS process count"
  },
  {
    name: "rtsp-methods",
    category: "discovery",
    description: "Enumerates RTSP methods supported by the server.",
    usage: "nmap -p 554 --script rtsp-methods <target>",
    output: "Supported RTSP methods (DESCRIBE, SETUP, PLAY, etc.)"
  },
  {
    name: "rtsp-url-brute",
    category: "brute",
    description: "Brute-forces RTSP stream URLs to find accessible camera feeds.",
    usage: "nmap -p 554 --script rtsp-url-brute <target>",
    output: "Valid RTSP stream URLs (camera feeds)"
  },
  {
    name: "dicom-ping",
    category: "discovery",
    description: "Sends a DICOM C-ECHO (ping) to verify DICOM service availability.",
    usage: "nmap -p 104 --script dicom-ping <target>",
    output: "DICOM service availability and AE Title"
  },
  {
    name: "broadcast-listener",
    category: "discovery",
    description: "Listens for broadcast and multicast traffic on the local network.",
    usage: "nmap --script broadcast-listener --script-args broadcast-listener.timeout=30",
    output: "Captured broadcast/multicast packets from network protocols"
  },
  {
    name: "firewalk",
    category: "discovery",
    description: "Discovers firewall rules by sending packets with TTL values that expire at the firewall.",
    usage: "nmap --script firewalk --traceroute <target>",
    output: "Ports allowed/blocked by intermediate firewalls"
  },
  {
    name: "firewall-bypass",
    category: "vuln",
    description: "Tests for FTP-mediated firewall bypass using the FTP bounce technique.",
    usage: "nmap --script firewall-bypass <target>",
    output: "Firewall bypass possibility via FTP or other service"
  }
];


// ---------------------------------------------------------------------------
// 5. PORT_REFERENCE -- Quick-lookup table of well-known ports
// ---------------------------------------------------------------------------

export const PORT_REFERENCE = {
  tcp: {
    20: { service: "FTP Data", risk: "medium", notes: "FTP data channel -- active mode transfers" },
    21: { service: "FTP Control", risk: "high", notes: "Plaintext auth, anonymous access, bounce attacks" },
    22: { service: "SSH / SFTP / SCP", risk: "medium", notes: "Brute force target, key management critical" },
    23: { service: "Telnet", risk: "critical", notes: "Completely plaintext -- never use on untrusted networks" },
    25: { service: "SMTP", risk: "high", notes: "Open relay, user enum, spoofing, STARTTLS strip" },
    49: { service: "TACACS+", risk: "medium", notes: "MD5 obfuscation, key recovery possible" },
    53: { service: "DNS (TCP)", risk: "medium", notes: "Zone transfers, large responses" },
    80: { service: "HTTP", risk: "high", notes: "Plaintext, web vulns, request smuggling" },
    88: { service: "Kerberos", risk: "high", notes: "Kerberoasting, AS-REP roast, golden tickets" },
    102: { service: "S7comm (Siemens PLC)", risk: "critical", notes: "No auth, PLC stop/start, program upload" },
    104: { service: "DICOM", risk: "high", notes: "Medical imaging, PHI exposure, no auth" },
    110: { service: "POP3", risk: "high", notes: "Plaintext credentials" },
    111: { service: "RPCbind", risk: "medium", notes: "RPC service enumeration" },
    135: { service: "MS-RPC", risk: "high", notes: "Endpoint mapper, PetitPotam, PrintNightmare" },
    137: { service: "NetBIOS-NS (UDP also)", risk: "medium", notes: "Name poisoning, NTLM capture" },
    139: { service: "NetBIOS-SSN", risk: "high", notes: "Null sessions, legacy SMB" },
    143: { service: "IMAP", risk: "high", notes: "Plaintext credentials, STARTTLS strip" },
    389: { service: "LDAP", risk: "high", notes: "Injection, anonymous bind, plaintext auth" },
    443: { service: "HTTPS", risk: "medium", notes: "TLS config critical, cipher audit needed" },
    445: { service: "SMB", risk: "critical", notes: "EternalBlue, relay attacks, null sessions" },
    465: { service: "SMTPS", risk: "low", notes: "Implicit TLS email submission" },
    502: { service: "Modbus TCP", risk: "critical", notes: "No authentication whatsoever -- ICS critical" },
    514: { service: "Syslog (TCP)", risk: "medium", notes: "Log injection, plaintext" },
    554: { service: "RTSP", risk: "high", notes: "Camera streams, default creds" },
    587: { service: "SMTP Submission", risk: "medium", notes: "STARTTLS required, auth brute force" },
    623: { service: "IPMI (UDP also)", risk: "critical", notes: "RAKP hash leak, cipher 0 bypass" },
    636: { service: "LDAPS", risk: "low", notes: "Encrypted LDAP, cert validation required" },
    873: { service: "Rsync", risk: "high", notes: "Anonymous modules, no encryption" },
    990: { service: "FTPS", risk: "low", notes: "FTP over implicit TLS" },
    993: { service: "IMAPS", risk: "low", notes: "Encrypted IMAP" },
    995: { service: "POP3S", risk: "low", notes: "Encrypted POP3" },
    1080: { service: "SOCKS Proxy", risk: "high", notes: "Open proxy abuse, pivoting" },
    1433: { service: "MSSQL", risk: "critical", notes: "xp_cmdshell RCE, sa brute force" },
    1521: { service: "Oracle TNS", risk: "high", notes: "TNS poisoning, default SIDs/creds" },
    1701: { service: "L2TP", risk: "medium", notes: "No encryption without IPsec" },
    1723: { service: "PPTP", risk: "critical", notes: "MS-CHAPv2 cryptographically broken" },
    1883: { service: "MQTT", risk: "high", notes: "No auth, wildcard sub, IoT exposure" },
    2049: { service: "NFS", risk: "high", notes: "UID spoofing, no_root_squash escalation" },
    2375: { service: "Docker API", risk: "critical", notes: "Unauth container/host access" },
    2376: { service: "Docker API (TLS)", risk: "medium", notes: "TLS-protected Docker API" },
    2379: { service: "etcd", risk: "critical", notes: "K8s secrets, cluster state" },
    3128: { service: "Squid Proxy", risk: "high", notes: "Open proxy, CONNECT tunneling" },
    3268: { service: "AD Global Catalog", risk: "medium", notes: "Cross-domain enum" },
    3306: { service: "MySQL", risk: "high", notes: "Default root, auth bypass, UDF RCE" },
    3389: { service: "RDP", risk: "critical", notes: "BlueKeep, brute force, pass-the-hash" },
    4840: { service: "OPC-UA", risk: "high", notes: "SecurityPolicy None, anon auth" },
    5060: { service: "SIP", risk: "high", notes: "Extension enum, toll fraud, eavesdropping" },
    5222: { service: "XMPP", risk: "medium", notes: "STARTTLS strip, XXE" },
    5432: { service: "PostgreSQL", risk: "high", notes: "Trust auth, COPY file access" },
    5672: { service: "AMQP / RabbitMQ", risk: "high", notes: "Default guest/guest, Erlang cookie" },
    5900: { service: "VNC", risk: "high", notes: "Weak/no auth, 8-char password limit" },
    5984: { service: "CouchDB", risk: "high", notes: "Admin party, REST API exposure" },
    5985: { service: "WinRM (HTTP)", risk: "high", notes: "Pass-the-hash, lateral movement" },
    5986: { service: "WinRM (HTTPS)", risk: "medium", notes: "Encrypted WinRM" },
    6379: { service: "Redis", risk: "critical", notes: "Unauth access, file write RCE" },
    6443: { service: "Kubernetes API", risk: "critical", notes: "RBAC misconfig, anon access" },
    6667: { service: "IRC", risk: "medium", notes: "Plaintext, botnet C2" },
    8080: { service: "HTTP Alternate / Proxy", risk: "high", notes: "Admin panels, management interfaces" },
    8443: { service: "HTTPS Alternate", risk: "medium", notes: "Management interfaces over TLS" },
    8883: { service: "MQTTS", risk: "low", notes: "MQTT over TLS" },
    9042: { service: "Cassandra CQL", risk: "high", notes: "No auth default, CQL injection" },
    9200: { service: "Elasticsearch", risk: "critical", notes: "Unauth access, script RCE" },
    11211: { service: "Memcached", risk: "critical", notes: "No auth, amplification DDoS" },
    15672: { service: "RabbitMQ Management", risk: "high", notes: "Web UI, default guest/guest" },
    20000: { service: "DNP3", risk: "critical", notes: "No auth in legacy mode, utility SCADA" },
    27017: { service: "MongoDB", risk: "critical", notes: "No auth default, mass ransoming" },
    44818: { service: "EtherNet/IP", risk: "critical", notes: "Unauth PLC programming" },
    47808: { service: "BACnet", risk: "high", notes: "No auth, building automation" },
    50051: { service: "gRPC", risk: "medium", notes: "Reflection disclosure, plaintext mode" }
  },
  udp: {
    53: { service: "DNS", risk: "high", notes: "Amplification, cache poisoning, tunneling" },
    67: { service: "DHCP Server", risk: "high", notes: "Rogue server, starvation, spoofing" },
    68: { service: "DHCP Client", risk: "low", notes: "Client-side DHCP" },
    69: { service: "TFTP", risk: "critical", notes: "Zero authentication, config theft" },
    123: { service: "NTP", risk: "high", notes: "Monlist amplification, time manipulation" },
    137: { service: "NetBIOS-NS", risk: "medium", notes: "Name poisoning, NTLM capture" },
    161: { service: "SNMP", risk: "critical", notes: "Default community strings, full enum" },
    162: { service: "SNMP Trap", risk: "medium", notes: "Trap spoofing, info disclosure" },
    500: { service: "IKE (IPsec)", risk: "high", notes: "Aggressive mode PSK hash capture" },
    514: { service: "Syslog", risk: "medium", notes: "Log forging, no auth/encryption" },
    1194: { service: "OpenVPN", risk: "low", notes: "VPN tunnel endpoint" },
    1701: { service: "L2TP", risk: "medium", notes: "Requires IPsec for security" },
    1812: { service: "RADIUS", risk: "high", notes: "Shared secret weakness, Blast-RADIUS" },
    1813: { service: "RADIUS Accounting", risk: "medium", notes: "Same shared secret issues" },
    4500: { service: "IPsec NAT-T", risk: "medium", notes: "IPsec NAT traversal" },
    5353: { service: "mDNS", risk: "medium", notes: "Spoofing, service enumeration" },
    5355: { service: "LLMNR", risk: "high", notes: "NTLM hash capture, poisoning" },
    5683: { service: "CoAP", risk: "high", notes: "No auth, UDP spoofing, IoT" },
    47808: { service: "BACnet", risk: "high", notes: "Building automation, no auth" },
    51820: { service: "WireGuard", risk: "low", notes: "Modern VPN, minimal attack surface" }
  }
};


// ---------------------------------------------------------------------------
// 6. PROTOCOL_CATEGORIES -- Protocol taxonomy for UI grouping
// ---------------------------------------------------------------------------

export const PROTOCOL_CATEGORIES = [
  {
    name: "Core TCP/IP Stack",
    description: "Foundational Internet protocols for addressing, routing, and transport.",
    protocols: ["IPv4", "IPv6", "TCP", "UDP", "ICMP", "ARP"]
  },
  {
    name: "Web Protocols",
    description: "Protocols for web communication, APIs, and real-time data exchange.",
    protocols: ["HTTP", "HTTPS", "HTTP/2", "HTTP/3 (QUIC)", "WebSocket", "gRPC", "GraphQL"]
  },
  {
    name: "DNS & Name Resolution",
    description: "Domain name resolution and service discovery protocols.",
    protocols: ["DNS", "DNS over HTTPS (DoH)", "DNS over TLS (DoT)", "mDNS", "LLMNR", "NBNS (NetBIOS Name Service)"]
  },
  {
    name: "Email",
    description: "Protocols for sending, receiving, and managing email.",
    protocols: ["SMTP", "SMTPS", "SMTP Submission", "POP3", "POP3S", "IMAP", "IMAPS"]
  },
  {
    name: "File Transfer",
    description: "Protocols for transferring files between systems.",
    protocols: ["FTP", "FTPS", "SFTP", "TFTP", "SCP", "Rsync", "NFS", "SMB/CIFS"]
  },
  {
    name: "Remote Access",
    description: "Protocols for remote system administration and desktop access.",
    protocols: ["SSH", "Telnet", "RDP", "VNC", "WinRM"]
  },
  {
    name: "Directory & Authentication",
    description: "Protocols for directory services, authentication, and authorization.",
    protocols: ["LDAP", "LDAPS", "Kerberos", "RADIUS", "TACACS+", "Active Directory (Global Catalog)"]
  },
  {
    name: "Databases",
    description: "Database server communication protocols.",
    protocols: ["MySQL", "PostgreSQL", "MSSQL", "Oracle DB", "MongoDB", "Redis", "Memcached", "Elasticsearch", "CouchDB", "Cassandra"]
  },
  {
    name: "Message Queues & IoT",
    description: "Messaging protocols for asynchronous communication and IoT devices.",
    protocols: ["RabbitMQ", "MQTT", "MQTTS", "CoAP", "AMQP"]
  },
  {
    name: "VoIP & Multimedia",
    description: "Protocols for voice, video, and real-time streaming.",
    protocols: ["SIP", "RTP", "RTSP"]
  },
  {
    name: "Routing & Network Infrastructure",
    description: "Protocols for network routing, time sync, and monitoring.",
    protocols: ["BGP", "OSPF", "VRRP", "DHCP", "NTP", "SNMP", "SNMP Trap", "Syslog"]
  },
  {
    name: "Wireless",
    description: "Wireless networking and short-range communication protocols.",
    protocols: ["WPA2", "WPA3", "Bluetooth", "ZigBee"]
  },
  {
    name: "Industrial / SCADA",
    description: "Protocols for industrial control systems and building automation.",
    protocols: ["Modbus", "DNP3", "OPC-UA", "BACnet", "EtherNet/IP", "S7comm"]
  },
  {
    name: "VPN & Tunneling",
    description: "Virtual private network and tunneling protocols.",
    protocols: ["IPsec (IKE)", "OpenVPN", "WireGuard", "PPTP", "L2TP", "SOCKS5", "HTTP Proxy (CONNECT)"]
  },
  {
    name: "Container & Orchestration",
    description: "Container management and orchestration platform protocols.",
    protocols: ["Docker API", "Kubernetes API", "etcd"]
  },
  {
    name: "Miscellaneous",
    description: "Chat, hardware management, and other specialized protocols.",
    protocols: ["XMPP", "IRC", "IPMI", "DICOM", "NetBIOS", "RPC (MS-RPC)"]
  }
];


// ---------------------------------------------------------------------------
// 7. COMMON_ATTACK_CHAINS -- Multi-protocol attack scenarios
// ---------------------------------------------------------------------------

export const COMMON_ATTACK_CHAINS = [
  {
    name: "LLMNR/NBNS Poisoning to Domain Admin",
    phases: [
      "1. Run Responder to poison LLMNR/NBNS queries on the local network",
      "2. Capture NTLMv2 hashes from victims attempting to access non-existent shares",
      "3. Crack hashes offline with hashcat (-m 5600) or relay with ntlmrelayx",
      "4. Use captured/cracked credentials for lateral movement via SMB/WinRM",
      "5. Enumerate AD with BloodHound to find path to Domain Admin",
      "6. Kerberoast service accounts or exploit AD CS misconfigurations",
      "7. Obtain Domain Admin via golden ticket, DCSync, or privilege escalation"
    ],
    protocols: ["LLMNR", "NBNS", "SMB/CIFS", "Kerberos", "LDAP", "WinRM"],
    tools: ["Responder", "hashcat", "ntlmrelayx", "BloodHound", "impacket", "CrackMapExec"]
  },
  {
    name: "External to Internal via Exposed Services",
    phases: [
      "1. Enumerate subdomains via DNS brute force and certificate transparency",
      "2. Scan for exposed management interfaces (RDP, SSH, VNC, WinRM, IPMI)",
      "3. Test for default credentials and known CVEs on discovered services",
      "4. Exploit vulnerable service for initial access (e.g., unpatched VPN, RDP)",
      "5. Establish persistence via SSH keys, scheduled tasks, or WMI subscriptions",
      "6. Pivot internally through discovered network segments",
      "7. Target high-value assets (domain controllers, databases, file servers)"
    ],
    protocols: ["DNS", "HTTP", "HTTPS", "SSH", "RDP", "VNC", "IPMI"],
    tools: ["nmap", "masscan", "nuclei", "Metasploit", "Cobalt Strike"]
  },
  {
    name: "ICS/SCADA Compromise",
    phases: [
      "1. Scan for exposed industrial protocols (Modbus 502, S7comm 102, BACnet 47808)",
      "2. Enumerate PLCs, RTUs, and HMIs using protocol-specific discovery",
      "3. Read process variables to understand the control system",
      "4. Identify critical control points (valves, switches, setpoints)",
      "5. Modify register/coil values to manipulate physical processes",
      "6. Optionally: upload modified PLC logic for persistent manipulation"
    ],
    protocols: ["Modbus", "S7comm", "DNP3", "BACnet", "EtherNet/IP", "OPC-UA"],
    tools: ["nmap ICS scripts", "plcscan", "mbtget", "Metasploit ICS modules"]
  },
  {
    name: "Wi-Fi to Internal Network",
    phases: [
      "1. Monitor wireless networks with airmon-ng/airodump-ng",
      "2. Capture WPA2 handshake via deauthentication attack",
      "3. Crack PSK offline with hashcat/aircrack-ng",
      "4. Connect to target network with recovered credentials",
      "5. Perform ARP spoofing for MITM position",
      "6. Capture credentials from HTTP, FTP, Telnet, SMTP traffic",
      "7. Pivot to internal systems using captured credentials"
    ],
    protocols: ["WPA2", "ARP", "DHCP", "DNS", "HTTP", "SMB/CIFS"],
    tools: ["aircrack-ng suite", "hashcat", "bettercap", "Wireshark"]
  },
  {
    name: "Database Pivot Chain",
    phases: [
      "1. Discover database ports via port scan (3306, 5432, 1433, 27017, 6379)",
      "2. Test for default/weak credentials or no authentication",
      "3. Extract sensitive data (credentials, PII, business data)",
      "4. Attempt OS command execution (xp_cmdshell, COPY TO, UDF, CONFIG SET)",
      "5. Write SSH keys or webshells via database file write capabilities",
      "6. Establish reverse shell from database server",
      "7. Pivot to additional network segments accessible from database server"
    ],
    protocols: ["MySQL", "PostgreSQL", "MSSQL", "MongoDB", "Redis"],
    tools: ["nmap", "hydra", "sqlmap", "redis-cli", "mssqlclient.py"]
  },
  {
    name: "DNS-Based Data Exfiltration",
    phases: [
      "1. Set up authoritative DNS server for attacker-controlled domain",
      "2. Encode sensitive data in DNS query labels (base32/hex subdomains)",
      "3. Send DNS queries from compromised host to trigger resolution",
      "4. Collect exfiltrated data from DNS query logs on authoritative server",
      "5. Optionally use DNS-over-HTTPS to bypass DNS monitoring",
      "6. Alternatively use ICMP tunneling or DNS TXT record responses for bidirectional C2"
    ],
    protocols: ["DNS", "DNS over HTTPS (DoH)", "ICMP"],
    tools: ["dnscat2", "iodine", "DNSExfiltrator", "Cobalt Strike DNS beacon"]
  }
];


// ---------------------------------------------------------------------------
// Utility exports
// ---------------------------------------------------------------------------

/**
 * Look up a protocol by name (case-insensitive partial match).
 */
export function findProtocol(query) {
  const q = query.toLowerCase();
  return PROTOCOLS.filter(p => p.name.toLowerCase().includes(q));
}

/**
 * Look up protocols by port number.
 */
export function findByPort(port) {
  return PROTOCOLS.filter(p => p.port === port);
}

/**
 * Look up packet structure by protocol name.
 */
export function findPacketStructure(protocol) {
  const q = protocol.toLowerCase();
  return PACKET_STRUCTURES.filter(p =>
    p.name.toLowerCase().includes(q) || p.protocol.toLowerCase().includes(q)
  );
}

/**
 * Search Wireshark filters across all categories.
 */
export function searchWiresharkFilters(query) {
  const q = query.toLowerCase();
  const results = [];
  for (const [category, filters] of Object.entries(WIRESHARK_FILTERS)) {
    for (const f of filters) {
      if (f.filter.toLowerCase().includes(q) || f.description.toLowerCase().includes(q)) {
        results.push({ ...f, category });
      }
    }
  }
  return results;
}

/**
 * Search Nmap scripts by name, category, or description.
 */
export function searchNmapScripts(query) {
  const q = query.toLowerCase();
  return NMAP_SCRIPTS.filter(s =>
    s.name.toLowerCase().includes(q) ||
    s.category.toLowerCase().includes(q) ||
    s.description.toLowerCase().includes(q)
  );
}

/**
 * Get all Nmap scripts in a specific category.
 */
export function getNmapScriptsByCategory(category) {
  return NMAP_SCRIPTS.filter(s => s.category.toLowerCase() === category.toLowerCase());
}

/**
 * Summary statistics for the reference data.
 */
export const STATS = {
  totalProtocols: PROTOCOLS.length,
  totalPacketStructures: PACKET_STRUCTURES.length,
  totalWiresharkFilters: Object.values(WIRESHARK_FILTERS).reduce((sum, arr) => sum + arr.length, 0),
  totalNmapScripts: NMAP_SCRIPTS.length
};
