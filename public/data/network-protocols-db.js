// Network Protocols Security Reference Database
// Comprehensive protocol reference with ports, attacks, detection, and hardening
// For ethical cybersecurity education and defense

export const NETWORK_PROTOCOLS_DB = [
  {
    name: "TCP (Transmission Control Protocol)",
    port: "N/A (transport layer)",
    layer: "Transport (Layer 4)",
    description: "Connection-oriented, reliable, ordered delivery of byte streams. Uses three-way handshake (SYN, SYN-ACK, ACK) to establish connections. Provides flow control via sliding window, congestion control (slow start, congestion avoidance, fast retransmit, fast recovery), and error detection via checksums.",
    rfc: "RFC 793, RFC 5681, RFC 7323",
    attacks: [
      "SYN Flood: Send massive SYN packets without completing handshake, exhausting server connection table",
      "TCP Reset Attack: Inject RST packets to tear down established connections (requires sequence number prediction)",
      "Session Hijacking: Predict sequence numbers to inject data into established TCP streams",
      "TCP Sequence Prediction: Guess ISN (Initial Sequence Number) to forge packets in a session",
      "Idle Scan (Zombie Scan): Use a third-party idle host IP ID field to scan a target stealthily",
      "FIN/XMAS/NULL Scan: Send packets with unusual flag combinations to fingerprint OS and discover open ports",
      "TCP Window Size Attack: Advertise zero window to stall connection, consuming server resources",
      "Covert Channel: Hide data in TCP header fields (ISN, urgent pointer, timestamp options)",
      "TIME-WAIT Assassination: Send forged RST during TIME-WAIT to free port for reuse",
      "Land Attack: Send packet with source and destination as same address/port to crash vulnerable stacks",
      "Sockstress: Manipulate TCP window size and options to consume kernel memory on target"
    ],
    detection: [
      "Monitor for high volume of half-open connections (SYN without ACK) — SYN flood indicator",
      "Alert on RST packets from unexpected sources or with invalid sequence numbers",
      "Track TCP retransmission rates — sudden spikes may indicate packet injection",
      "IDS signature: alert tcp any any -> any any (flags:S; threshold:type both, track by_dst, count 100, seconds 10;)",
      "Monitor for unusual TCP flag combinations (XMAS: FIN+PSH+URG, NULL: no flags)",
      "Baseline normal connection rates per host and alert on deviations >3 standard deviations",
      "Track ISN predictability with statistical analysis of sequence number increments",
      "Suricata rule: alert tcp any any -> $HOME_NET any (msg:\"Possible SYN flood\"; flags:S,12; threshold:type both, track by_dst, count 500, seconds 10; sid:1000001;)"
    ],
    hardening: [
      "Enable SYN cookies (net.ipv4.tcp_syncookies=1) to handle SYN floods without connection table exhaustion",
      "Reduce SYN-RECV timeout: net.ipv4.tcp_synack_retries=2 (default 5)",
      "Increase SYN backlog: net.ipv4.tcp_max_syn_backlog=65536",
      "Enable TCP timestamps: net.ipv4.tcp_timestamps=1 (helps with PAWS and RTT estimation)",
      "Randomize ISN (default on modern kernels) to prevent sequence prediction",
      "Set net.ipv4.tcp_rfc1337=1 to drop RST packets in TIME-WAIT state",
      "Implement iptables rate limiting: -A INPUT -p tcp --syn -m limit --limit 25/s --limit-burst 50 -j ACCEPT",
      "Use TCP-AO (RFC 5925) or TCP-MD5 (RFC 2385) for BGP session authentication",
      "Disable TCP window scaling if not needed: net.ipv4.tcp_window_scaling=0",
      "Configure appropriate keepalive settings: tcp_keepalive_time=600, tcp_keepalive_intvl=60, tcp_keepalive_probes=5"
    ]
  },
  {
    name: "UDP (User Datagram Protocol)",
    port: "N/A (transport layer)",
    layer: "Transport (Layer 4)",
    description: "Connectionless, unreliable, no guaranteed ordering. Minimal overhead (8-byte header vs TCP's 20+). Used for DNS, DHCP, SNMP, VoIP, streaming, gaming. Supports multicast and broadcast.",
    rfc: "RFC 768",
    attacks: [
      "UDP Flood: Overwhelm target with massive UDP packets to random ports, triggering ICMP port unreachable responses",
      "DNS Amplification: Spoof source IP and send small DNS queries to open resolvers; responses are 50-70x larger",
      "NTP Amplification: Use monlist command (amplification factor ~556x) to flood target with NTP responses",
      "SSDP Amplification: Abuse UPnP SSDP service (port 1900) for ~30x amplification",
      "Memcached Amplification: Exploit memcached UDP (port 11211) for up to 51,000x amplification — largest known",
      "CLDAP Amplification: Abuse Connectionless LDAP (port 389 UDP) for ~56-70x amplification",
      "CharGEN Amplification: Use character generator service (port 19) for reflection attacks",
      "UDP Port Scan: Send empty UDP datagrams; closed ports respond with ICMP unreachable, open ports are silent",
      "Fraggle Attack: Broadcast UDP packets to port 7 (echo) or 19 (chargen) with spoofed source IP",
      "Covert Channel: Exfiltrate data via DNS over UDP queries — hard to detect in normal DNS traffic"
    ],
    detection: [
      "Monitor UDP packet rates per source/destination — baseline and alert on spikes >5x normal",
      "Track ICMP destination unreachable messages — high rates indicate UDP flood or port scan",
      "Alert on UDP traffic to unusual ports or unexpected services",
      "Deep packet inspection for DNS amplification: responses significantly larger than queries",
      "Snort rule: alert udp any any -> $HOME_NET any (msg:\"UDP flood\"; threshold:type both, track by_dst, count 1000, seconds 10; sid:1000002;)",
      "Monitor outbound DNS query volume for data exfiltration over DNS tunnels",
      "Check for monlist queries to NTP servers (deprecated since NTP 4.2.7)",
      "Alert on memcached UDP traffic from external sources"
    ],
    hardening: [
      "Rate limit UDP traffic with iptables: -A INPUT -p udp -m limit --limit 100/s --limit-burst 200 -j ACCEPT",
      "Disable unnecessary UDP services (chargen, echo, discard, daytime)",
      "Block UDP port 19 (chargen), port 7 (echo), port 11211 (memcached) from external",
      "Configure DNS resolvers to not allow recursion from external IPs",
      "Disable NTP monlist: restrict default noquery in ntp.conf",
      "Enable source address validation (BCP38/BCP84) to prevent IP spoofing",
      "Use response rate limiting (RRL) on authoritative DNS servers",
      "Disable SSDP/UPnP on external-facing interfaces",
      "Implement ingress/egress filtering to drop spoofed packets",
      "Use connection tracking (conntrack) to drop UDP responses without matching queries"
    ]
  },
  {
    name: "ICMP (Internet Control Message Protocol)",
    port: "N/A (network layer protocol, IP protocol number 1)",
    layer: "Network (Layer 3)",
    description: "Used for diagnostic and control messages. Key types: Echo Request/Reply (ping), Destination Unreachable, Time Exceeded (traceroute), Redirect, Source Quench (deprecated). Essential for path MTU discovery and network troubleshooting.",
    rfc: "RFC 792, RFC 4443 (ICMPv6)",
    attacks: [
      "Ping of Death: Send oversized ICMP packets (>65535 bytes) that crash vulnerable systems on reassembly",
      "Smurf Attack: Broadcast ICMP echo request with spoofed source IP to amplify traffic against victim",
      "ICMP Flood (Ping Flood): Overwhelm target bandwidth with continuous ICMP echo requests",
      "ICMP Redirect Attack: Send forged redirect messages to reroute traffic through attacker-controlled gateway",
      "ICMP Tunnel: Encapsulate data inside ICMP echo request/reply payloads for covert exfiltration (tools: icmpsh, ptunnel, hans)",
      "ICMP Source Quench: Send fake source quench to slow down target's transmission rate (mostly ignored now)",
      "Traceroute Mapping: Use TTL-exceeded messages to map internal network topology",
      "Inverse Mapping: Send ICMP requests to IP range; non-responsive IPs behind firewalls can be mapped",
      "ICMP Timestamp Attack: Use timestamp request/reply to determine target's system clock for timing attacks",
      "Fragmentation Attack: Send fragmented ICMP packets designed to crash or hang target's IP reassembly"
    ],
    detection: [
      "Monitor ICMP packet sizes — legitimate ping usually ≤64 bytes payload; larger may be tunneling",
      "Alert on high-rate ICMP traffic from single source (>100 packets/sec suggests flood)",
      "Detect ICMP tunnel tools by analyzing payload entropy and patterns in echo request/reply data",
      "Snort rule: alert icmp any any -> $HOME_NET any (msg:\"ICMP flood\"; itype:8; threshold:type both, track by_src, count 100, seconds 10; sid:1000003;)",
      "Monitor for ICMP redirect messages — rarely legitimate in modern networks",
      "Check for ICMP type 13/14 (timestamp) and type 17/18 (address mask) — often used in recon",
      "Alert on ICMP unreachable storms indicating port scanning activity",
      "Track ICMP fragmentation — fragmented ICMP is almost always malicious"
    ],
    hardening: [
      "Rate limit ICMP: iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT",
      "Disable ICMP redirects: net.ipv4.conf.all.accept_redirects=0, net.ipv4.conf.all.send_redirects=0",
      "Disable ICMP timestamp responses: iptables -A INPUT -p icmp --icmp-type timestamp-request -j DROP",
      "Block broadcast ICMP: net.ipv4.icmp_echo_ignore_broadcasts=1",
      "Enable source validation: net.ipv4.conf.all.rp_filter=1",
      "Do NOT disable ICMP entirely — it breaks Path MTU Discovery, causes TCP black holes",
      "Allow ICMP types 3 (destination unreachable) and 11 (time exceeded) for proper network function",
      "Block ICMP type 5 (redirect) at network perimeter",
      "Restrict outbound ICMP to prevent internal recon and exfiltration",
      "Implement BCP38 to prevent ICMP spoofing from your network"
    ]
  },
  {
    name: "DNS (Domain Name System)",
    port: "53 (TCP and UDP)",
    layer: "Application (Layer 7)",
    description: "Hierarchical distributed naming system. Resolves domain names to IP addresses and vice versa. Record types include A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR, CAA, DNSKEY, DS, RRSIG, NSEC/NSEC3. Supports zone transfers (AXFR/IXFR), dynamic updates, and DNSSEC for authenticated responses.",
    rfc: "RFC 1034, RFC 1035, RFC 4033-4035 (DNSSEC), RFC 8484 (DoH), RFC 7858 (DoT)",
    attacks: [
      "DNS Cache Poisoning (Kaminsky Attack): Race condition in DNS resolution to inject forged records into resolver cache",
      "DNS Amplification DDoS: Spoof source IP, send ANY/TXT queries to open resolvers for 28-54x amplification",
      "DNS Tunneling: Encode data in DNS queries/responses (TXT/NULL/CNAME records) to bypass firewalls. Tools: iodine, dnscat2, dns2tcp",
      "DNS Hijacking: Compromise registrar account or DNS server to redirect domain resolution",
      "DNS Rebinding: Rapidly change DNS resolution to bypass same-origin policy and access internal services",
      "NXDOMAIN Attack: Query massive numbers of non-existent subdomains to overwhelm authoritative server",
      "Phantom Domain Attack: Point resolver at unresponsive servers to exhaust resolver resources",
      "Zone Transfer (AXFR) Exploitation: Request full zone transfer from misconfigured DNS server to enumerate all records",
      "DNS Subdomain Takeover: Claim dangling CNAME/NS records pointing to deprovisioned cloud services",
      "Typosquatting: Register misspelled domains to phish users (e.g., goog1e.com, gooogle.com)",
      "DNS Water Torture (Random Subdomain Attack): Query random subdomains to bypass resolver caching and flood authoritative servers",
      "Birthday Attack on DNS: Exploit birthday paradox to increase cache poisoning probability"
    ],
    detection: [
      "Monitor DNS query volume per client — >1000 queries/min suggests tunneling or C2",
      "Analyze DNS TXT record sizes — legitimate TXT records rarely exceed 255 bytes; tunneling uses large TXT",
      "Check for high entropy in queried subdomains — randomized strings suggest DGA (Domain Generation Algorithm)",
      "Alert on AXFR requests from non-secondary DNS servers",
      "Monitor for queries to recently registered domains (<30 days old) — common for phishing and C2",
      "Track NXDOMAIN response ratio — >30% suggests DGA malware or data exfiltration",
      "Suricata rule: alert dns any any -> any any (msg:\"DNS tunneling TXT\"; dns.query; content:\".tunnel.\"; sid:1000004;)",
      "Detect fast-flux networks: domains resolving to many IPs with short TTLs (<300s)",
      "Monitor DNS-over-HTTPS (DoH) connections to known resolvers that bypass local DNS security",
      "Alert on direct DNS queries to external resolvers bypassing internal DNS infrastructure"
    ],
    hardening: [
      "Implement DNSSEC to authenticate DNS responses and prevent cache poisoning",
      "Restrict zone transfers: allow-transfer { trusted-servers; }; in named.conf",
      "Use split-horizon DNS to separate internal and external views",
      "Enable DNS response rate limiting (RRL) on authoritative servers",
      "Configure minimal-responses yes; in BIND to reduce amplification",
      "Disable recursion on authoritative servers: recursion no;",
      "Implement DNS sinkholing for known malicious domains",
      "Force all DNS traffic through internal resolvers — block outbound port 53",
      "Enable DNS logging and forward to SIEM for analysis",
      "Use DNS-over-TLS (DoT, port 853) or DNS-over-HTTPS (DoH) for privacy",
      "Monitor and alert on CAA record violations for certificate issuance",
      "Implement RPZ (Response Policy Zones) for DNS-level threat intelligence",
      "Set maximum cache TTL to limit impact of poisoned records"
    ]
  },
  {
    name: "HTTP (Hypertext Transfer Protocol)",
    port: "80 (TCP)",
    layer: "Application (Layer 7)",
    description: "Stateless request-response protocol for web communication. Methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT. Status codes: 1xx informational, 2xx success, 3xx redirection, 4xx client error, 5xx server error. HTTP/1.1 supports persistent connections, chunked transfer, pipelining. HTTP/2 adds multiplexing, header compression (HPACK), server push, stream prioritization. HTTP/3 runs over QUIC (UDP).",
    rfc: "RFC 7230-7235 (HTTP/1.1), RFC 7540 (HTTP/2), RFC 9114 (HTTP/3)",
    attacks: [
      "SQL Injection: Inject SQL via HTTP parameters to manipulate backend database queries",
      "Cross-Site Scripting (XSS): Inject JavaScript into web pages viewed by other users (reflected, stored, DOM-based)",
      "Cross-Site Request Forgery (CSRF): Force authenticated users to execute unwanted actions via crafted requests",
      "HTTP Request Smuggling: Exploit differences in how front-end and back-end parse Content-Length vs Transfer-Encoding",
      "Server-Side Request Forgery (SSRF): Abuse server to make requests to internal resources (cloud metadata: 169.254.169.254)",
      "HTTP Response Splitting: Inject CRLF (\\r\\n) into headers to add malicious response headers or body",
      "Slowloris: Open many connections and send partial HTTP headers slowly to exhaust server connection pool",
      "RUDY (R-U-Dead-Yet): Send POST requests with extremely slow body to tie up application threads",
      "HTTP Desync Attack: Exploit HTTP/2 to HTTP/1.1 downgrade discrepancies for request smuggling",
      "Host Header Injection: Manipulate Host header for cache poisoning, password reset poisoning, or SSRF",
      "HTTP Parameter Pollution: Submit duplicate parameters to bypass WAF rules or application logic",
      "Verb Tampering: Use unexpected HTTP methods (PUT, DELETE) on endpoints that only check GET/POST",
      "Clickjacking: Frame legitimate site in invisible iframe to capture user clicks",
      "Open Redirect: Abuse URL redirect parameters to send users to malicious sites"
    ],
    detection: [
      "WAF signatures for SQLi: UNION SELECT, OR 1=1, single quotes in parameters, hex-encoded payloads",
      "XSS detection: <script>, javascript:, onerror=, onload=, data:text/html in request parameters",
      "Monitor for HTTP 500 errors — spikes indicate active exploitation attempts",
      "Detect request smuggling: mismatched Content-Length and Transfer-Encoding headers",
      "Alert on requests to internal IP ranges via SSRF (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254)",
      "ModSecurity CRS: SecRule ARGS \"@detectSQLi\" \"id:1,phase:2,deny,status:403\"",
      "Track slow HTTP connections — Slowloris connections have very low data rates over long durations",
      "Monitor HTTP TRACE method usage — should be disabled; used for XST (Cross-Site Tracing) attacks",
      "Check for directory traversal patterns: ../, ....\\, %2e%2e%2f in URLs",
      "Alert on unusual User-Agent strings or missing headers that indicate automated tools"
    ],
    hardening: [
      "Redirect all HTTP to HTTPS (301 redirect on port 80)",
      "Implement Content-Security-Policy header to mitigate XSS and data injection",
      "Set X-Content-Type-Options: nosniff to prevent MIME type sniffing",
      "Enable X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking",
      "Add Strict-Transport-Security header with max-age ≥ 31536000 and includeSubDomains",
      "Configure X-XSS-Protection: 0 (deprecated, rely on CSP instead)",
      "Set Referrer-Policy: strict-origin-when-cross-origin to control referrer leakage",
      "Disable HTTP TRACE method: TraceEnable Off in Apache, or deny in nginx",
      "Implement CSRF tokens on all state-changing requests",
      "Use SameSite=Lax or Strict on session cookies",
      "Set connection timeout and request body limits to mitigate slow HTTP attacks",
      "Deploy WAF (ModSecurity, Cloudflare, AWS WAF) with OWASP CRS ruleset",
      "Normalize HTTP requests before validation to prevent encoding-based bypasses",
      "Implement Permissions-Policy header to restrict browser features (camera, microphone, geolocation)"
    ]
  },
  {
    name: "HTTPS (HTTP Secure / HTTP over TLS)",
    port: "443 (TCP)",
    layer: "Application (Layer 7)",
    description: "HTTP encrypted with TLS. Provides confidentiality, integrity, and server authentication. Uses X.509 certificates for identity verification. Modern deployments use TLS 1.3 with AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305). Certificate transparency (CT) logs provide public audit of issued certificates.",
    rfc: "RFC 8446 (TLS 1.3), RFC 2818 (HTTP over TLS), RFC 6962 (Certificate Transparency)",
    attacks: [
      "SSL Stripping (sslstrip): Downgrade HTTPS to HTTP by intercepting initial HTTP redirect — prevented by HSTS preload",
      "BEAST: CBC mode vulnerability in TLS 1.0 — exploit predictable IV for chosen-plaintext attack",
      "POODLE: Padding oracle in SSLv3 CBC — downgrade attack to extract encrypted data byte by byte",
      "Heartbleed (CVE-2014-0160): OpenSSL bug leaking up to 64KB server memory per request, including private keys",
      "CRIME/BREACH: Exploit TLS/HTTP compression to recover session cookies via chosen-plaintext",
      "ROBOT (Return Of Bleichenbacher's Oracle Threat): RSA key exchange vulnerability for session key recovery",
      "DROWN: Cross-protocol attack using SSLv2 to decrypt TLS sessions sharing the same RSA key",
      "Certificate Spoofing: Use fraudulent or self-signed certificates with user click-through warnings",
      "TLS Downgrade Attack: Force negotiation of weaker cipher suites via ClientHello manipulation",
      "Renegotiation Attack: Inject data during TLS renegotiation to prepend attacker content to authenticated session",
      "Logjam: Exploit weak Diffie-Hellman parameters (512-bit export grade) to break key exchange",
      "FREAK: Force RSA_EXPORT cipher suites for 512-bit RSA key exchange (factored in hours on cloud)",
      "Certificate Transparency Monitoring: Enumerate subdomains by watching CT logs (not attack, but OPSEC risk)"
    ],
    detection: [
      "Monitor certificate transparency logs for unauthorized certificate issuance for your domains",
      "Detect TLS downgrade attempts by tracking negotiated protocol versions and cipher suites",
      "Alert on SSLv2/SSLv3/TLS1.0 connections — should not be accepted",
      "Check for self-signed or expired certificates in monitored connections",
      "Monitor OCSP stapling failures and CRL distribution point availability",
      "Detect SSL stripping: monitor for HTTP traffic on authenticated sessions",
      "Alert on certificates issued by untrusted or unexpected CAs",
      "Track JA3/JA3S fingerprints to identify malicious TLS clients and servers",
      "Monitor for MITM proxies: certificate chain should match expected issuer"
    ],
    hardening: [
      "Use TLS 1.3 only where possible; minimum TLS 1.2 with strong cipher suites",
      "Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1 on all services",
      "Enable HSTS with preload: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
      "Configure OCSP stapling for faster certificate validation without privacy leak",
      "Pin certificates using public key pinning (HPKP deprecated — use CAA records instead)",
      "Publish CAA DNS records to restrict which CAs can issue certificates for your domains",
      "Generate 2048-bit+ RSA keys or P-256/P-384 ECDSA keys",
      "Enable Perfect Forward Secrecy (PFS) with ECDHE key exchange",
      "Use strong cipher suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256",
      "Disable TLS compression to prevent CRIME attacks",
      "Renew certificates before expiration — automate with certbot/ACME",
      "Monitor Certificate Transparency logs for your domains",
      "Configure ssl_prefer_server_ciphers on; in nginx to enforce server cipher preference"
    ]
  },
  {
    name: "FTP (File Transfer Protocol)",
    port: "21 (control), 20 (data — active mode)",
    layer: "Application (Layer 7)",
    description: "Client-server file transfer. Uses separate control and data connections. Active mode: server connects back to client data port. Passive mode: client connects to server data port. Supports anonymous access. Transmits credentials in plaintext. Largely replaced by SFTP/SCP for secure transfers.",
    rfc: "RFC 959, RFC 2228 (FTP Security Extensions), RFC 4217 (FTPS)",
    attacks: [
      "Credential Sniffing: FTP sends USER and PASS in cleartext — trivially captured on the wire",
      "FTP Bounce Attack: Use PORT command to proxy connections through FTP server to scan internal hosts",
      "Anonymous Login Exploitation: Access misconfigured FTP servers with anonymous:anonymous credentials",
      "Directory Traversal: Use ../ sequences in FTP commands to access files outside intended directory",
      "Brute Force: Automated password guessing against FTP login — tools: hydra, medusa, ncrack",
      "MITM Attack: Intercept and modify FTP data in transit (no encryption in plain FTP)",
      "FTP Malware Distribution: Upload malware to writable anonymous FTP directories",
      "Banner Grabbing: Extract FTP server version from welcome banner for targeted exploitation",
      "Passive Mode Data Theft: Intercept data connections in passive mode by predicting ephemeral ports",
      "SITE EXEC Command Injection: Exploit misconfigured FTP servers allowing arbitrary command execution"
    ],
    detection: [
      "Monitor for cleartext credentials on port 21 traffic — no legitimate reason for plain FTP in modern networks",
      "Alert on anonymous FTP login attempts: USER anonymous or USER ftp",
      "Track failed FTP authentication attempts — >5 failures in 60 seconds indicates brute force",
      "Detect FTP bounce attacks: PORT commands specifying IP addresses different from the connected client",
      "Snort rule: alert tcp any any -> any 21 (msg:\"FTP brute force\"; content:\"530 \"; threshold:type both, track by_src, count 5, seconds 60; sid:1000005;)",
      "Monitor for large file transfers or unusual upload activity on FTP servers",
      "Alert on SITE EXEC, SITE CPFR/CPTO commands — often used in exploitation",
      "Track FTP connections from unexpected source IPs or during unusual hours"
    ],
    hardening: [
      "Replace FTP with SFTP (SSH File Transfer Protocol) or SCP wherever possible",
      "If FTP required, use FTPS (FTP over TLS) with explicit TLS (AUTH TLS)",
      "Disable anonymous FTP access unless specifically required",
      "Chroot FTP users to their home directories to prevent directory traversal",
      "Disable FTP PORT command to prevent bounce attacks: -P in vsftpd.conf",
      "Set strong password policies and implement account lockout after failed attempts",
      "Restrict FTP access to specific IP ranges via firewall rules or TCP wrappers",
      "Disable SITE EXEC and other dangerous FTP commands",
      "Set idle timeout and limit concurrent connections per user",
      "Log all FTP activity and forward to SIEM for monitoring",
      "Use passive mode only and restrict passive port range to a defined set"
    ]
  },
  {
    name: "SSH (Secure Shell)",
    port: "22 (TCP)",
    layer: "Application (Layer 7)",
    description: "Encrypted remote shell access, file transfer (SCP/SFTP), and port forwarding. Uses public-key cryptography for authentication and key exchange. Supports local/remote/dynamic port forwarding for tunneling. SSH-2 protocol uses Diffie-Hellman key exchange, server authentication via host keys, and symmetric encryption for session data.",
    rfc: "RFC 4251-4256 (SSH Protocol), RFC 4419 (DH Group Exchange)",
    attacks: [
      "Brute Force/Credential Stuffing: Automated password guessing — SSH is the #1 brute-forced service on the internet",
      "SSH Key Theft: Steal private keys from ~/.ssh/ directory or SSH agent forwarding",
      "SSH Agent Hijacking: Access forwarded SSH agent socket to impersonate user on other systems",
      "SSH Tunneling for Exfiltration: Use SSH -L/-R/-D flags to tunnel data out through allowed SSH connections",
      "MITM Attack: Intercept SSH connection before host key verification — user accepts unknown host key",
      "Terrapin Attack (CVE-2023-48795): Prefix truncation in SSH handshake to downgrade connection security",
      "SSH Banner Grabbing: Extract SSH version (OpenSSH_8.9p1) for version-specific vulnerability targeting",
      "Username Enumeration (CVE-2018-15473): Timing difference in authentication response reveals valid usernames",
      "Private Key Passphrase Cracking: Brute force encrypted SSH private keys offline — tools: ssh2john, john",
      "Control Master Hijacking: Abuse SSH ControlMaster socket to piggyback on existing authenticated sessions"
    ],
    detection: [
      "Monitor failed SSH authentication: >5 failures from single IP in 5 minutes indicates brute force",
      "Alert on SSH connections from unusual geographic locations or unexpected IP ranges",
      "Detect SSH tunneling by monitoring for long-duration SSH sessions with high data transfer",
      "Track SSH key usage — alert on keys used from unexpected source IPs",
      "Suricata rule: alert ssh any any -> $HOME_NET 22 (msg:\"SSH brute force\"; threshold:type both, track by_src, count 5, seconds 300; sid:1000006;)",
      "Monitor for SSH agent forwarding from high-value systems",
      "Alert on SSH connections during non-business hours from admin accounts",
      "Detect reverse SSH tunnels by monitoring outbound SSH connections from servers",
      "Track host key changes — unexpected changes may indicate MITM"
    ],
    hardening: [
      "Disable root login: PermitRootLogin no",
      "Use key-based authentication only: PasswordAuthentication no",
      "Use Ed25519 or ECDSA keys (ssh-keygen -t ed25519) — faster and more secure than RSA",
      "Restrict SSH access to specific users: AllowUsers user1 user2",
      "Change default port (security through obscurity — reduces log noise, not a real defense)",
      "Implement fail2ban or sshguard for automated IP blocking after failed attempts",
      "Disable SSH agent forwarding unless needed: AllowAgentForwarding no",
      "Disable TCP forwarding if not needed: AllowTcpForwarding no",
      "Enable 2FA with PAM module (Google Authenticator, Duo)",
      "Set idle timeout: ClientAliveInterval 300, ClientAliveCountMax 2",
      "Use SSH certificates instead of authorized_keys for centralized key management",
      "Restrict SSH to specific subnets via firewall or ListenAddress directive",
      "Disable X11 forwarding: X11Forwarding no",
      "Use Match blocks for per-user/group restrictions",
      "Enable audit logging: LogLevel VERBOSE"
    ]
  },
  {
    name: "SMTP (Simple Mail Transfer Protocol)",
    port: "25 (relay), 465 (SMTPS — deprecated), 587 (submission with STARTTLS)",
    layer: "Application (Layer 7)",
    description: "Email transmission protocol. Uses EHLO/HELO handshake, MAIL FROM, RCPT TO, DATA commands. Modern extensions: STARTTLS for encryption, AUTH for authentication, PIPELINING, 8BITMIME, DSN. SPF, DKIM, and DMARC provide email authentication and anti-spoofing.",
    rfc: "RFC 5321 (SMTP), RFC 6409 (Submission), RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC)",
    attacks: [
      "Email Spoofing: Forge From header to send email as any address — prevented by SPF/DKIM/DMARC",
      "Open Relay Exploitation: Use misconfigured SMTP server to relay spam/phishing without authentication",
      "SMTP User Enumeration: Use VRFY/EXPN commands or RCPT TO timing to discover valid email addresses",
      "Phishing/Spear-Phishing: Craft targeted emails with malicious links or attachments",
      "SMTP Credential Harvesting: Capture cleartext AUTH PLAIN/LOGIN credentials on unencrypted connections",
      "STARTTLS Stripping: MITM downgrade attack that prevents TLS negotiation on SMTP connections",
      "Email Header Injection: Inject additional headers (BCC, CC) via CRLF in input fields",
      "Mailbox Overflow: Send massive number of emails to fill target mailbox quota",
      "SMTP Smuggling: Exploit differences in how MTAs parse end-of-data sequences",
      "Business Email Compromise (BEC): Impersonate executives to request wire transfers or sensitive data"
    ],
    detection: [
      "Monitor for VRFY and EXPN commands — should be disabled on production servers",
      "Track authentication failure rates per source IP on submission port (587)",
      "Alert on email sent without SPF/DKIM alignment (DMARC failure reports)",
      "Monitor outbound email volume per user — sudden spikes indicate compromised account or spam relay",
      "Check for emails with mismatched envelope sender (MAIL FROM) and header From address",
      "Detect phishing: analyze URLs in email bodies against known malicious domains and URL shorteners",
      "Alert on STARTTLS failures from known-good peers (potential stripping attack)",
      "Monitor for large attachment sends to external domains (potential data exfiltration)"
    ],
    hardening: [
      "Implement SPF: v=spf1 ip4:x.x.x.x include:_spf.google.com -all",
      "Configure DKIM signing with 2048-bit keys for all outbound email",
      "Publish DMARC policy: v=DMARC1; p=reject; rua=mailto:dmarc@domain.com",
      "Require STARTTLS on port 587 for submission: smtpd_tls_security_level=encrypt",
      "Disable VRFY and EXPN commands: disable_vrfy_command=yes (Postfix)",
      "Disable open relay: smtpd_relay_restrictions=permit_mynetworks, permit_sasl_authenticated, reject",
      "Implement rate limiting per sender and per IP address",
      "Use MTA-STS (RFC 8461) to enforce TLS on inbound SMTP connections",
      "Enable DANE (RFC 7672) with TLSA DNS records for certificate validation",
      "Configure anti-spam (SpamAssassin, rspamd) and antivirus (ClamAV) scanning",
      "Implement sender verification with callback verification or SPF check at RCPT TO",
      "Block outbound port 25 from workstations — only mail servers should use port 25",
      "Set message size limits and recipient limits to prevent abuse"
    ]
  },
  {
    name: "SNMP (Simple Network Management Protocol)",
    port: "161 (agent), 162 (trap receiver), UDP",
    layer: "Application (Layer 7)",
    description: "Network device monitoring and management. SNMPv1/v2c use community strings (essentially passwords in cleartext). SNMPv3 adds authentication (MD5/SHA) and encryption (DES/AES). MIB (Management Information Base) defines the data hierarchy. OIDs identify specific data points.",
    rfc: "RFC 3411-3418 (SNMPv3), RFC 1157 (SNMPv1)",
    attacks: [
      "Default Community String: Many devices ship with public (read) and private (read-write) community strings",
      "SNMP Walk: Enumerate entire device configuration, routing tables, ARP cache, interfaces using snmpwalk",
      "Community String Brute Force: Try common strings (public, private, cisco, admin, manager) to gain access",
      "SNMP Write Exploitation: Use write-enabled community string to modify device configs, change routes, or create backdoor accounts",
      "SNMP Amplification DDoS: Send GetBulk requests with spoofed source IP for ~6x amplification",
      "Credential Extraction: SNMP MIBs may contain router configs with passwords (e.g., Cisco running-config via SNMP)",
      "SNMP Trap Injection: Send forged SNMP traps to monitoring systems to create false alerts or suppress real ones",
      "MIB Data Exfiltration: Read sensitive data from custom MIBs (user accounts, interface configs, ARP tables)",
      "SNMPv1/v2c Sniffing: Community strings transmitted in cleartext — trivially captured on the network"
    ],
    detection: [
      "Monitor for SNMP traffic from unexpected sources — only management stations should send SNMP",
      "Alert on snmpwalk or snmpbulkget patterns: rapid succession of GetNext/GetBulk requests",
      "Detect community string brute force: multiple authentication failures from single source",
      "Monitor SNMP SET operations — write operations should be rare and from authorized sources only",
      "Alert on SNMPv1/v2c traffic — should be migrated to SNMPv3",
      "Track SNMP trap sources — unexpected trap senders may indicate injection",
      "Monitor for access to sensitive OIDs (e.g., running-config OID on Cisco: 1.3.6.1.4.1.9.9.96)"
    ],
    hardening: [
      "Migrate all devices to SNMPv3 with authPriv (authentication + encryption)",
      "Use strong, unique community strings — never use public/private defaults",
      "Restrict SNMP access to specific management IPs via ACL",
      "Disable SNMP write access unless absolutely required",
      "Filter SNMP traffic at network perimeter — block UDP 161/162 from external",
      "Use SNMPv3 users with SHA-256 authentication and AES-256 encryption",
      "Remove or restrict access to sensitive MIB branches",
      "Change community strings regularly (treat as passwords)",
      "Disable SNMPv1 and SNMPv2c on all devices",
      "Configure SNMP view to limit accessible OIDs per user/community",
      "Log all SNMP access and forward to SIEM"
    ]
  },
  {
    name: "LDAP (Lightweight Directory Access Protocol)",
    port: "389 (TCP/UDP), 636 (LDAPS over TLS), 3268/3269 (Global Catalog)",
    layer: "Application (Layer 7)",
    description: "Directory service protocol for querying and modifying directory services (Active Directory, OpenLDAP, FreeIPA). Organizes data in tree structure with DNs (Distinguished Names). Supports BIND (authentication), SEARCH, ADD, DELETE, MODIFY operations. SASL provides pluggable authentication (GSSAPI/Kerberos, DIGEST-MD5).",
    rfc: "RFC 4510-4519 (LDAPv3), RFC 4513 (LDAP Authentication)",
    attacks: [
      "LDAP Injection: Inject LDAP filter syntax to bypass authentication or extract data: *)(&, )(cn=*, |(uid=*)",
      "Anonymous Bind Exploitation: Query entire directory tree when anonymous bind is enabled (common misconfiguration)",
      "Credential Sniffing: LDAP simple bind transmits password in cleartext without TLS",
      "LDAP Pass-Back Attack: Modify LDAP server configuration on device (printer, AP) to capture credentials sent to rogue LDAP server",
      "LDAP Enumeration: Extract users, groups, GPOs, computers, trusts from Active Directory via LDAP queries",
      "Null Bind Exploitation: Some LDAP servers allow binding with empty DN and password",
      "CLDAP Amplification: UDP port 389 used for connectionless LDAP — 56-70x amplification factor in DDoS",
      "LDAP Referral Attack: Redirect LDAP client to malicious server via LDAP referral response",
      "Password Spray via LDAP: Try common passwords against all users through LDAP bind attempts",
      "Kerberoasting via LDAP: Enumerate SPN (servicePrincipalName) attributes to find Kerberoastable accounts"
    ],
    detection: [
      "Monitor for anonymous LDAP bind attempts — alert and investigate immediately",
      "Track LDAP query volume per source — enumeration produces many rapid queries",
      "Alert on LDAP queries for sensitive attributes: userPassword, unicodePwd, supplementalCredentials",
      "Detect LDAP injection: monitor for special characters in bind DN and search filters (*, |, &, !)",
      "Monitor for LDAP bind failures — password spray produces many failures across different accounts",
      "Track queries for servicePrincipalName attribute — Kerberoasting indicator",
      "Alert on LDAP connections from non-domain-joined systems or unexpected subnets",
      "Monitor CLDAP (UDP 389) traffic for amplification abuse"
    ],
    hardening: [
      "Require LDAPS (port 636) or STARTTLS on port 389 — disable simple bind over cleartext",
      "Disable anonymous bind: olcDisallows: bind_anon in OpenLDAP",
      "Implement LDAP signing and channel binding (required in modern AD — CVE-2017-8563)",
      "Use SASL/GSSAPI (Kerberos) for authentication instead of simple bind",
      "Restrict LDAP query access with ACLs — limit who can read sensitive attributes",
      "Block CLDAP (UDP 389) from external networks to prevent amplification abuse",
      "Enable LDAP audit logging: dsHeuristics flag on AD, auditlog overlay on OpenLDAP",
      "Limit LDAP search result size: olcSizeLimit and olcTimeLimit in OpenLDAP",
      "Validate and sanitize all input before constructing LDAP queries (prevent injection)",
      "Use service accounts with minimal privileges for application LDAP binds"
    ]
  },
  {
    name: "Kerberos",
    port: "88 (TCP/UDP), 464 (kpasswd)",
    layer: "Application (Layer 7)",
    description: "Network authentication protocol using tickets. Components: KDC (Key Distribution Center) with AS (Authentication Service) and TGS (Ticket Granting Service). Flow: client requests TGT from AS using password hash, then exchanges TGT for service tickets from TGS. Uses symmetric cryptography (AES256-CTS-HMAC-SHA1-96 in modern AD). Provides mutual authentication and SSO within a realm.",
    rfc: "RFC 4120 (Kerberos V5), RFC 6806 (KDC Referrals)",
    attacks: [
      "Kerberoasting: Request service tickets (TGS-REP) for SPNs and crack them offline — the ticket is encrypted with the service account password hash",
      "AS-REP Roasting: Request AS-REP for accounts with pre-authentication disabled (DONT_REQUIRE_PREAUTH) and crack the response offline",
      "Golden Ticket: Forge TGT using compromised krbtgt account hash — grants domain-wide access for ticket lifetime (default 10 hours, renewable 7 days)",
      "Silver Ticket: Forge service ticket using compromised service account hash — access specific service without contacting KDC",
      "Pass-the-Ticket: Steal and reuse Kerberos tickets from memory (mimikatz sekurlsa::tickets)",
      "Overpass-the-Hash: Use NTLM hash to request Kerberos TGT — combine pass-the-hash with Kerberos",
      "Delegation Abuse: Exploit unconstrained/constrained/resource-based constrained delegation to impersonate users",
      "Diamond Ticket: Modify a legitimate TGT by decrypting it with krbtgt hash, changing fields, and re-encrypting — harder to detect than golden ticket",
      "Skeleton Key: Patch LSASS on DC to allow master password for any account alongside legitimate passwords",
      "S4U2Self/S4U2Proxy Abuse: Request tickets on behalf of other users via constrained delegation extensions",
      "Kerberos Bronze Bit (CVE-2020-17049): Bypass constrained delegation restrictions by flipping forwardable flag"
    ],
    detection: [
      "Monitor for TGS-REQ for many SPNs from single user — Kerberoasting indicator (Event ID 4769)",
      "Alert on AS-REQ without pre-authentication data (Event ID 4768 with pre-auth type 0)",
      "Detect golden ticket: TGT with unusual lifetime, missing corresponding AS-REQ, or for non-existent user",
      "Monitor for encryption downgrade: RC4-HMAC (type 23) when AES should be used — Kerberoasting tool default",
      "Track delegation usage: Event ID 4769 with transited services",
      "Alert on Kerberos authentication from unexpected source IPs",
      "Monitor for LSASS process access (Event ID 4663) — credential theft indicator",
      "Detect skeleton key: monitor LSASS for code injection, unusual DLLs loaded",
      "Track krbtgt password age — should be rotated at least every 180 days",
      "Monitor for service ticket requests from machine accounts to other machines — lateral movement indicator"
    ],
    hardening: [
      "Use AES256 encryption for all Kerberos operations — disable RC4 (DES already disabled by default)",
      "Enable Kerberos pre-authentication for all accounts (default — check for exceptions)",
      "Rotate krbtgt password twice (accounts for replication delay) every 180 days or immediately after compromise",
      "Use Group Managed Service Accounts (gMSA) with 240-character random passwords that auto-rotate",
      "Remove unnecessary SPNs from service accounts to reduce Kerberoasting attack surface",
      "Implement Privileged Access Workstations (PAW) for Tier 0 administration",
      "Disable unconstrained delegation — migrate to constrained or resource-based delegation",
      "Enable Protected Users security group for sensitive accounts (disables NTLM, delegation, and RC4)",
      "Configure Kerberos Armoring (FAST) for additional pre-authentication protection",
      "Set maximum ticket lifetime to 10 hours and renewal to 7 days (defaults)",
      "Monitor and restrict delegation rights across the domain",
      "Deploy Credential Guard on Windows 10+ endpoints to protect LSASS"
    ]
  },
  {
    name: "NTP (Network Time Protocol)",
    port: "123 (UDP)",
    layer: "Application (Layer 7)",
    description: "Time synchronization protocol. Hierarchical stratum model: stratum 0 (atomic clocks/GPS), stratum 1 (directly connected to stratum 0), stratum 2-15 (synchronized to lower stratum). Achieves millisecond accuracy over WAN, microsecond over LAN. NTPv4 supports autokey authentication and IPv6.",
    rfc: "RFC 5905 (NTPv4)",
    attacks: [
      "NTP Amplification DDoS: Exploit monlist command (mode 7) for ~556x amplification factor",
      "Time Shifting Attack: Gradually skew target's clock to break certificate validation, TOTP, Kerberos, log correlation",
      "NTP Reflection: Spoof source IP to reflect NTP responses at target",
      "Kiss-of-Death (KoD) Attack: Send forged KoD packets to cause clients to stop querying their time server",
      "NTP Mode 6 Information Disclosure: Query NTP readvar/peers to enumerate internal servers and configuration",
      "Rogue NTP Server: Set up fake NTP server on network to manipulate clients' time synchronization",
      "Replay Attack: Capture and replay NTP packets to prevent clock updates",
      "CVE-2014-9295: Multiple buffer overflows in NTP daemon allowing remote code execution"
    ],
    detection: [
      "Monitor for monlist requests (mode 7, opcode 42) — deprecated and commonly abused",
      "Alert on NTP traffic volume anomalies — amplification produces large response-to-query ratio",
      "Detect NTP mode 6 queries from non-management IPs",
      "Monitor NTP stratum changes on critical systems — sudden changes may indicate manipulation",
      "Track NTP source IPs — clients should only sync from authorized servers",
      "Alert on large clock adjustments (>1 second) — may indicate time manipulation attack"
    ],
    hardening: [
      "Disable monlist: restrict default noquery in ntp.conf (NTP 4.2.7+ removes monlist by default)",
      "Restrict NTP queries: restrict default kod nomodify notrap nopeer noquery",
      "Use authenticated NTP with symmetric key or autokey",
      "Configure specific NTP servers rather than pool: server ntp.ubuntu.com iburst prefer",
      "Block NTP mode 6 and mode 7 queries from external sources",
      "Deploy internal NTP servers synchronized to trusted stratum 1 sources",
      "Enable NTP logging for security monitoring",
      "Use chrony instead of ntpd — better security defaults and faster synchronization",
      "Implement NTS (Network Time Security, RFC 8915) for authenticated and encrypted NTP"
    ]
  },
  {
    name: "BGP (Border Gateway Protocol)",
    port: "179 (TCP)",
    layer: "Application (Layer 7) / Network routing",
    description: "The routing protocol of the internet. Path-vector protocol for exchanging routing information between autonomous systems (ASes). BGPv4 supports CIDR, route aggregation, and communities. Uses TCP for reliable transport. UPDATE messages contain NLRI (Network Layer Reachability Information), path attributes (AS_PATH, NEXT_HOP, LOCAL_PREF, MED), and withdrawn routes.",
    rfc: "RFC 4271 (BGP-4), RFC 7454 (BGP Operations and Security), RFC 8205 (BGPsec)",
    attacks: [
      "BGP Hijacking: Announce more-specific prefixes (longer mask) for victim's IP space to redirect traffic",
      "BGP Route Leak: Accidental or malicious re-advertisement of learned routes to unintended peers",
      "AS Path Prepending Manipulation: Artificially lengthen AS path to manipulate routing decisions",
      "BGP Session Reset: Send TCP RST to tear down BGP session and cause route withdrawal/convergence",
      "BGP MITM: Hijack routes to position attacker in traffic path, then forward to legitimate destination",
      "Prefix De-aggregation Attack: Announce smaller subnets to divert specific traffic",
      "BGP Dampening Abuse: Trigger route flapping on victim prefix to cause dampening penalties",
      "BGP Community Manipulation: Forge communities to influence routing decisions at upstream providers",
      "Sub-prefix Hijack with Interception: Announce /25 of victim's /24, intercept traffic, re-route to real destination"
    ],
    detection: [
      "Monitor BGP routing tables for unexpected origin AS changes (RPKI ROV validation)",
      "Use BGP monitoring services: RIPE RIS, RouteViews, BGPStream for route hijack detection",
      "Alert on new prefix announcements from your AS that don't match registered prefixes",
      "Monitor BGP session state — unexpected down/up transitions may indicate attack",
      "Track AS path changes for critical prefixes — new ASes in path may indicate hijack",
      "Implement RPKI ROA (Route Origin Authorization) and validate inbound routes"
    ],
    hardening: [
      "Implement RPKI with ROA (Route Origin Authorization) for all your prefixes",
      "Enable RPKI Origin Validation (ROV) on all BGP routers to reject invalid origins",
      "Use BGP-MD5 authentication (TCP-MD5, RFC 2385) or TCP-AO (RFC 5925) for session security",
      "Filter inbound routes with prefix lists — only accept expected prefixes from peers",
      "Implement maximum-prefix limits on BGP sessions to prevent route table overflow",
      "Register routing policy in IRR (Internet Routing Registry) and generate filters from it",
      "Use BGP communities to tag and control route propagation",
      "Configure BGP TTL security (GTSM, RFC 5082): neighbor X.X.X.X ttl-security hops 1",
      "Implement BGPsec (RFC 8205) for path validation where supported",
      "Monitor BGP sessions with BFD (Bidirectional Forwarding Detection) for fast failure detection",
      "Use bogon and martian prefix filters to reject private/reserved IP space from external peers"
    ]
  },
  {
    name: "RDP (Remote Desktop Protocol)",
    port: "3389 (TCP/UDP)",
    layer: "Application (Layer 7)",
    description: "Microsoft proprietary remote desktop access protocol. Provides graphical remote access to Windows systems. Supports multiple channels for clipboard, audio, file transfer, printing, USB redirection. Uses TLS for encryption. Network Level Authentication (NLA) requires authentication before establishing full RDP session. Restricted Admin mode prevents credential caching on remote host.",
    rfc: "Microsoft proprietary (MS-RDPBCGR specification)",
    attacks: [
      "BlueKeep (CVE-2019-0708): Pre-authentication RCE in RDP on Windows 7/2008 R2 — wormable, no user interaction",
      "RDP Brute Force: Automated password guessing — RDP is heavily targeted by ransomware groups",
      "RDP Session Hijacking: Use tscon.exe to connect to disconnected sessions without authentication (requires SYSTEM)",
      "RDP MITM: Intercept RDP connection to capture credentials — tool: Seth, Responder",
      "DejaBlue (CVE-2019-1181/1182): Post-authentication RCE affecting Windows 7-10 and Server 2008-2019",
      "Pass-the-Hash via RDP: Use NTLM hash for Restricted Admin mode RDP authentication",
      "RDP Credential Harvesting: Capture credentials from RDP bitmap cache (bcache24.bmc files)",
      "SharpRDP: Execute commands on remote system via RDP virtual channels without GUI",
      "GoldBrute Botnet: Massive RDP brute-force botnet targeting 1.5+ million RDP servers",
      "RDP Reverse Tunnel: Use RDP as reverse tunnel for C2 communication through firewalls",
      "Sticky Keys Backdoor: Replace sethc.exe or utilman.exe with cmd.exe for pre-authentication shell access"
    ],
    detection: [
      "Monitor Event ID 4625 (failed logon) with logon type 10 (RemoteInteractive) for brute force",
      "Alert on successful RDP from unusual IPs or geographic locations (Event ID 4624, type 10)",
      "Track RDP session events: 4778 (reconnect), 4779 (disconnect) for session hijacking",
      "Monitor for tscon.exe execution — session hijacking tool",
      "Detect RDP tunneling: RDP connections from servers that shouldn't be RDP sources",
      "Alert on NLA failures — may indicate MITM or credential stuffing",
      "Monitor for sethc.exe/utilman.exe replacement (Event ID 4663 on system32 directory)",
      "Track RDP bitmap cache files for forensic analysis of past sessions",
      "Alert on RDP connections during non-business hours from admin accounts"
    ],
    hardening: [
      "Enable Network Level Authentication (NLA) — authenticates before session is established",
      "Use RDP Gateway (RD Gateway) instead of exposing RDP directly to internet",
      "Implement MFA for RDP access — DUO, Azure MFA, or smart card authentication",
      "Disable RDP if not needed: fDenyTSConnections=1 in registry",
      "Change default port (reduces automated scanning — not a real security measure)",
      "Use Restricted Admin mode to prevent credential caching on remote host",
      "Enable Remote Credential Guard for SSO without sending credentials to remote host",
      "Implement account lockout policies for RDP authentication",
      "Use Windows Firewall to restrict RDP access to specific IP ranges",
      "Disable clipboard and drive redirection if not needed (reduce data exfiltration risk)",
      "Keep systems patched — BlueKeep and DejaBlue are fully patched",
      "Deploy RDP Defender or fail2ban equivalent for automated blocking",
      "Use Azure Bastion or SSH tunnels instead of direct internet-exposed RDP"
    ]
  },
  {
    name: "SMB (Server Message Block)",
    port: "445 (TCP, direct SMB), 137-139 (NetBIOS over TCP/IP)",
    layer: "Application (Layer 7)",
    description: "Network file sharing protocol for Windows. SMBv1 (deprecated, vulnerable), SMBv2 (Windows Vista+), SMBv3 (Windows 8+, supports encryption). Provides file/printer sharing, named pipes, IPC. NTLM or Kerberos authentication. SMBv3 adds transparent failover, multichannel, and AES-128-CCM/GCM encryption.",
    rfc: "MS-SMB, MS-SMB2 (Microsoft specifications), RFC 1001-1002 (NetBIOS)",
    attacks: [
      "EternalBlue (MS17-010): Buffer overflow in SMBv1 — used by WannaCry and NotPetya ransomware",
      "SMB Relay (NTLM Relay): Capture and relay NTLM authentication to another SMB server — tools: ntlmrelayx, Responder",
      "SMB Signing Not Required: Allows MITM and relay attacks when signing is not enforced",
      "Pass-the-Hash: Use captured NTLM hash to authenticate to SMB shares without knowing password",
      "PsExec/Remote Execution: Use admin shares (ADMIN$, C$, IPC$) for remote command execution",
      "Null Session Enumeration: Access IPC$ share without credentials to enumerate users, shares, policies",
      "SCF File Attack: Plant malicious .scf file in writable share to capture NTLM hashes when users browse",
      "SMBGhost (CVE-2020-0796): RCE in SMBv3.1.1 compression — wormable, affects Windows 10",
      "PrintNightmare (CVE-2021-34527): RCE via Windows Print Spooler accessible through SMB",
      "SMB Brute Force: Automated credential guessing against SMB authentication",
      "Ransomware Propagation: Self-spreading ransomware uses SMB for lateral movement (WannaCry, Ryuk)",
      "Coerced Authentication: Force target to authenticate to attacker-controlled SMB (PetitPotam, PrinterBug)"
    ],
    detection: [
      "Monitor for SMBv1 traffic — should be disabled on all systems (Event ID 2004 in SMBServer log)",
      "Detect NTLM relay: monitor for authentication from unexpected sources with legitimate user credentials",
      "Alert on access to admin shares (ADMIN$, C$, IPC$) from non-admin workstations (Event ID 5140/5145)",
      "Track failed SMB authentication attempts (Event ID 4625 with logon type 3)",
      "Detect PsExec: monitor for service creation (Event ID 7045) naming PSEXESVC or similar",
      "Monitor for null session connections to IPC$ share",
      "Alert on SMB connections to external IPs — SMB should not leave the network",
      "Track SMB signing status across all endpoints — unsigned SMB is relay-vulnerable",
      "Monitor for .scf and .url file creation in shared folders"
    ],
    hardening: [
      "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
      "Require SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature $true",
      "Enable SMBv3 encryption: Set-SmbServerConfiguration -EncryptData $true",
      "Disable null sessions: RestrictNullSessAccess=1 in registry",
      "Remove unnecessary shares and restrict share permissions",
      "Block SMB at network perimeter: deny TCP 445 and TCP 137-139 inbound/outbound",
      "Use SMB access-based enumeration to hide shares users cannot access",
      "Implement LAPS (Local Administrator Password Solution) to prevent pass-the-hash across machines",
      "Enable Extended Protection for Authentication to prevent NTLM relay",
      "Disable NTLM where possible — enforce Kerberos authentication",
      "Configure firewall to prevent SMB lateral movement between workstations",
      "Apply security patches promptly — EternalBlue, SMBGhost, PrintNightmare all have patches",
      "Use Windows Credential Guard to protect NTLM hashes in memory"
    ]
  },
  {
    name: "DHCP (Dynamic Host Configuration Protocol)",
    port: "67 (server, UDP), 68 (client, UDP)",
    layer: "Application (Layer 7)",
    description: "Automatic IP address assignment. DORA process: Discover (broadcast), Offer, Request, Acknowledge. Assigns IP address, subnet mask, default gateway, DNS servers, lease time. DHCP relay agents forward requests across subnets. DHCPv6 (port 546/547) for IPv6 address assignment alongside SLAAC.",
    rfc: "RFC 2131 (DHCPv4), RFC 8415 (DHCPv6)",
    attacks: [
      "DHCP Starvation: Exhaust DHCP address pool by requesting all available IPs with spoofed MAC addresses — tool: DHCPig, Yersinia",
      "Rogue DHCP Server: Set up unauthorized DHCP server to provide malicious gateway/DNS — MITM for entire subnet",
      "DHCP Spoofing: Respond to DHCP requests faster than legitimate server to provide attacker-controlled settings",
      "DHCP Snooping Bypass: Craft DHCP packets that bypass snooping validation on certain switch firmware",
      "DHCP ACK Injection: Inject DHCP ACK in response to legitimate DHCP Request to override settings",
      "DHCP Information Disclosure: Analyze DHCP traffic to discover network topology, DNS domains, and IP ranges",
      "DHCPv6 Starvation: Exhaust DHCPv6 address pool (harder due to larger address space, but possible with prefix delegation)"
    ],
    detection: [
      "Enable DHCP snooping on switches — tracks legitimate DHCP server ports",
      "Monitor for multiple DHCP Discover messages from different MAC addresses from same port",
      "Alert on DHCP Offer from unauthorized server IPs",
      "Track DHCP lease table for unusual churn or rapid assignments",
      "Monitor for MAC address spoofing patterns in DHCP requests",
      "Alert on DHCP Option 3 (gateway) or Option 6 (DNS) pointing to unexpected addresses"
    ],
    hardening: [
      "Enable DHCP snooping on all access switches: ip dhcp snooping (Cisco IOS)",
      "Configure DHCP snooping trust on uplink ports only: ip dhcp snooping trust",
      "Enable Dynamic ARP Inspection (DAI) to validate ARP based on DHCP snooping database",
      "Implement port security to limit MAC addresses per port (prevents DHCP starvation)",
      "Configure IP Source Guard to prevent IP spoofing based on DHCP snooping table",
      "Use DHCP Option 82 (relay agent information) for client identification",
      "Implement DHCP failover between two servers for high availability",
      "Set reasonable lease times (8 hours typical — shorter for guest networks)",
      "Configure DHCP server logging and monitor for anomalies",
      "Use 802.1X port authentication to control network access before DHCP"
    ]
  },
  {
    name: "ARP (Address Resolution Protocol)",
    port: "N/A (Layer 2, EtherType 0x0806)",
    layer: "Data Link (Layer 2)",
    description: "Resolves IPv4 addresses to MAC (hardware) addresses on local network. Stateless protocol — hosts accept ARP replies even without sending a request (gratuitous ARP). ARP cache maps IP to MAC with timeout. No authentication mechanism in the protocol itself.",
    rfc: "RFC 826",
    attacks: [
      "ARP Spoofing/Poisoning: Send gratuitous ARP replies to associate attacker's MAC with gateway IP — MITM all traffic on subnet",
      "ARP Cache Poisoning: Overwrite legitimate ARP cache entries to redirect traffic — tools: arpspoof, ettercap, bettercap",
      "ARP-Based MITM: Position attacker between victim and gateway by poisoning both ARP caches",
      "ARP DoS: Flood network with ARP requests to overwhelm switches and endpoints",
      "ARP Scan: Send ARP requests to all IPs on subnet for fast host discovery (faster than ICMP ping)",
      "VLAN Hopping via ARP: In some configurations, ARP packets can traverse VLAN boundaries",
      "Gratuitous ARP Flooding: Send massive gratuitous ARP to update all hosts' ARP caches simultaneously",
      "ARP Cloning: Clone another host's MAC address to intercept its traffic"
    ],
    detection: [
      "Monitor for multiple IPs resolving to same MAC address — ARP spoofing indicator",
      "Alert on ARP replies from unexpected MAC addresses for gateway IP",
      "Track ARP cache changes on critical systems — unexpected changes indicate poisoning",
      "Deploy arpwatch or XArp to monitor ARP table for suspicious activity",
      "Enable Dynamic ARP Inspection (DAI) on switches — validates ARP against DHCP snooping database",
      "Snort rule: alert arp any any -> any any (msg:\"ARP spoofing\"; arp.opcode:2;)",
      "Monitor for high rate of ARP requests from single source — ARP scan indicator"
    ],
    hardening: [
      "Enable Dynamic ARP Inspection (DAI) on switches: ip arp inspection vlan X",
      "Configure static ARP entries for critical infrastructure (gateway, DNS, DC)",
      "Enable DHCP snooping as prerequisite for DAI",
      "Implement private VLANs to isolate hosts on same subnet",
      "Use 802.1X port authentication to prevent unauthorized devices",
      "Deploy host-based ARP monitoring (arpwatch, XArp)",
      "Consider VPN or IPsec for sensitive communications on shared networks",
      "Segment networks with VLANs to limit ARP broadcast domain size",
      "Use static IP-to-MAC bindings on access switches for critical servers",
      "Enable ARP rate limiting on switch ports to prevent ARP floods"
    ]
  },
  {
    name: "IPsec (Internet Protocol Security)",
    port: "UDP 500 (IKE), UDP 4500 (NAT-T), IP protocol 50 (ESP), IP protocol 51 (AH)",
    layer: "Network (Layer 3)",
    description: "Suite of protocols for securing IP communications. Two modes: Transport (encrypts payload only) and Tunnel (encrypts entire IP packet, adds new IP header — used for VPNs). AH provides authentication/integrity (no encryption). ESP provides encryption + authentication. IKEv1/IKEv2 for Security Association (SA) negotiation and key exchange.",
    rfc: "RFC 4301 (IPsec), RFC 7296 (IKEv2), RFC 4302 (AH), RFC 4303 (ESP)",
    attacks: [
      "IKE Aggressive Mode Attack: Extract PSK hash from aggressive mode exchange — crack offline",
      "ISAKMP Vulnerability Exploitation: Buffer overflows in IKE implementations (CVE-2016-6415 Cisco IKEv1)",
      "VPN Credential Brute Force: Guess VPN pre-shared keys or user credentials",
      "IPsec Downgrade Attack: Force negotiation of weaker encryption (DES, NULL) or authentication algorithms",
      "Replay Attack on IPsec: Replay captured ESP packets — prevented by anti-replay window",
      "Side-Channel on AES-GCM: Timing attacks on certain IPsec AES-GCM implementations",
      "IKEv1 Rekey Timing Attack: Exploit predictable rekey intervals for traffic analysis",
      "Split Tunneling Exploitation: Access corporate resources while routing other traffic through attacker network"
    ],
    detection: [
      "Monitor for IKE aggressive mode negotiations — should be disabled in favor of main mode",
      "Alert on IKE authentication failures — brute force indicator",
      "Track IPsec SA establishment and teardown — unusual patterns indicate issues",
      "Monitor for ESP packets with NULL encryption — misconfiguration or downgrade",
      "Alert on IKE negotiations proposing weak algorithms (DES, MD5, DH group 1/2)",
      "Monitor VPN connection patterns for anomalous timing or data volumes"
    ],
    hardening: [
      "Use IKEv2 instead of IKEv1 — better security, supports EAP, simpler",
      "Use certificate-based authentication instead of pre-shared keys",
      "If PSK required, use strong random keys (32+ characters)",
      "Disable IKE aggressive mode — use main mode only in IKEv1",
      "Configure strong cipher suites: AES-256-GCM, SHA-256/384/512, DH group 14+ (2048-bit) or ECDH",
      "Enable Perfect Forward Secrecy (PFS) for IPsec rekeying",
      "Enable anti-replay protection (default in most implementations)",
      "Configure Dead Peer Detection (DPD) for SA cleanup",
      "Disable split tunneling for VPN clients to ensure all traffic goes through VPN",
      "Implement certificate revocation checking (CRL/OCSP) for IPsec certificates",
      "Set reasonable SA lifetimes: 8 hours for IKE, 1 hour for IPsec"
    ]
  },
  {
    name: "TLS (Transport Layer Security)",
    port: "Varies (wraps other protocols: 443/HTTPS, 993/IMAPS, 995/POP3S, 636/LDAPS, 853/DoT)",
    layer: "Session/Presentation (Layer 5/6)",
    description: "Cryptographic protocol providing confidentiality and integrity for network communications. TLS 1.3 (2018) is current — reduced handshake to 1-RTT (0-RTT with PSK resumption), removed insecure features (RSA key transport, static DH, CBC ciphers, compression), and only supports AEAD ciphers. Handshake: ClientHello → ServerHello → certificate exchange → key exchange → Finished.",
    rfc: "RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2)",
    attacks: [
      "BEAST (TLS 1.0): CBC chosen-plaintext attack exploiting predictable IV",
      "POODLE (SSL 3.0): Padding oracle on CBC mode — can decrypt one byte per 256 requests",
      "CRIME: Exploit TLS-level compression to recover cookies via compression ratio analysis",
      "BREACH: Exploit HTTP-level compression (works even with TLS) — recover secrets from response bodies",
      "Lucky13: Timing attack on CBC MAC verification in TLS 1.0-1.2",
      "Sweet32: Birthday attack on 64-bit block ciphers (3DES, Blowfish) in TLS",
      "Raccoon Attack: Timing vulnerability in DH key exchange (TLS 1.2 and earlier)",
      "ALPACA: Cross-protocol attack exploiting TLS servers sharing certificates across different protocols",
      "TLS Truncation Attack: Inject TCP FIN/RST to prematurely close TLS connection",
      "Bleichenbacher/ROBOT: RSA PKCS#1 v1.5 padding oracle — decrypt or sign with server's private key",
      "Renegotiation Attack (CVE-2009-3555): Inject plaintext into TLS session during renegotiation",
      "0-RTT Replay (TLS 1.3): Replay 0-RTT data in TLS 1.3 — limited to non-mutable requests"
    ],
    detection: [
      "Monitor for SSL/TLS protocol version downgrade attempts in ClientHello",
      "Alert on connections using SSLv3, TLS 1.0, or TLS 1.1 — all deprecated",
      "Track cipher suite negotiation — alert on weak ciphers (RC4, DES, 3DES, NULL, EXPORT)",
      "Detect ALPN confusion: mismatched protocol negotiation across different services",
      "Monitor for certificate chain validation failures",
      "Use JA3/JA3S fingerprints to identify known malicious TLS implementations",
      "Alert on TLS renegotiation attempts — should be disabled or rate-limited",
      "Monitor certificate validity periods — certificates valid >398 days violate BR requirements"
    ],
    hardening: [
      "Use TLS 1.3 where possible; minimum TLS 1.2 with forward-secret cipher suites",
      "TLS 1.3 cipher suites (all forward-secret): TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256",
      "TLS 1.2 recommended suites: ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384",
      "Disable compression at TLS level to prevent CRIME",
      "Use separate certificates per protocol to prevent ALPACA",
      "Enable OCSP stapling for efficient certificate revocation checking",
      "Implement Certificate Transparency monitoring for your domains",
      "Disable TLS renegotiation or limit rate to prevent DoS",
      "Configure 0-RTT replay protection (only allow for idempotent requests)",
      "Use ECDSA certificates (P-256/P-384) for faster handshakes than RSA",
      "Enable session tickets with rotating keys for session resumption",
      "Test configuration with testssl.sh, ssllabs.com, or sslscan"
    ]
  },
  {
    name: "QUIC",
    port: "443 (UDP)",
    layer: "Transport (Layer 4) / Application (Layer 7)",
    description: "Transport protocol built on UDP, designed by Google, standardized as HTTP/3 transport. Integrates TLS 1.3 into transport layer — 0-RTT connection establishment. Multiplexed streams without head-of-line blocking. Connection migration (survives IP changes). Built-in congestion control. Authenticated and encrypted headers.",
    rfc: "RFC 9000 (QUIC), RFC 9001 (QUIC-TLS), RFC 9114 (HTTP/3)",
    attacks: [
      "QUIC Flood: UDP-based DDoS targeting QUIC endpoints — harder to filter than TCP SYN floods",
      "0-RTT Replay: Replay early data in QUIC 0-RTT handshake — similar to TLS 1.3 0-RTT issue",
      "Connection ID Manipulation: Forge connection migration by spoofing connection IDs",
      "Version Negotiation Downgrade: Attempt to force older, vulnerable QUIC versions",
      "Amplification via Initial Packets: QUIC initial packets can be larger than request — anti-amplification limit exists",
      "Ossification Attacks: Exploit middleboxes that incorrectly parse QUIC headers",
      "Path Validation Bypass: Attempt to hijack connection during migration by racing with legitimate endpoint"
    ],
    detection: [
      "Monitor UDP 443 traffic volume — QUIC is indistinguishable from other encrypted UDP at the packet level",
      "Track QUIC version negotiation failures — may indicate downgrade attempts",
      "Alert on high rates of QUIC Initial packets from single source — potential amplification attack",
      "Monitor connection migration events for unusual frequency",
      "Detect QUIC traffic via ALPN inspection in the Initial packet (before encryption)",
      "Track QUIC connection durations and data volumes for anomaly detection"
    ],
    hardening: [
      "Implement QUIC token validation for address verification (Retry mechanism)",
      "Limit 0-RTT data processing to idempotent operations only",
      "Enable address validation tokens to prevent amplification",
      "Configure appropriate connection limits per source IP",
      "Implement rate limiting on QUIC Initial packet processing",
      "Use QUIC version negotiation to enforce minimum version",
      "Deploy QUIC-aware firewalls and DDoS mitigation (Cloudflare, AWS Shield)",
      "Monitor QUIC connection metrics and log anomalies",
      "Disable QUIC if not needed — HTTP/2 over TCP is sufficient for most use cases"
    ]
  },
  {
    name: "SIP (Session Initiation Protocol)",
    port: "5060 (TCP/UDP), 5061 (TLS)",
    layer: "Application (Layer 7)",
    description: "Signaling protocol for VoIP, video conferencing, instant messaging. Request methods: INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS, INFO, SUBSCRIBE, NOTIFY. Uses SDP (Session Description Protocol) for media negotiation. Media typically transmitted via RTP/RTCP on separate ports.",
    rfc: "RFC 3261 (SIP), RFC 3550 (RTP)",
    attacks: [
      "SIP INVITE Flooding: Overwhelm SIP proxy/PBX with INVITE requests to cause DoS",
      "VoIP Eavesdropping: Capture RTP streams to reconstruct voice conversations — tools: Wireshark, VoIPong",
      "SIP Registration Hijacking: Register attacker's device for victim's extension to intercept calls",
      "Toll Fraud: Exploit misconfigured PBX to make international/premium calls at victim's expense",
      "SPIT (Spam over Internet Telephony): Automated mass VoIP calls for advertising or phishing",
      "Caller ID Spoofing: Forge From header in SIP INVITE to display arbitrary caller ID",
      "RTP Injection: Inject audio into ongoing RTP streams — insert fake audio into calls",
      "SIP Brute Force: Guess SIP extension passwords — tools: svwar (SIPVicious), SIPcrack",
      "SRTP Key Recovery: Attack weak SRTP key management to decrypt VoIP traffic",
      "Ooh323 Protocol Abuse: Exploit H.323-to-SIP gateway misconfigurations for toll fraud"
    ],
    detection: [
      "Monitor SIP REGISTER requests — multiple failures indicate brute force",
      "Alert on SIP traffic from unexpected external IPs — SIP should be restricted to known peers",
      "Detect INVITE floods: high rate of INVITE without corresponding ACK/BYE",
      "Monitor call patterns for toll fraud: international calls, premium numbers, unusual hours",
      "Track SIP user agent strings — anomalous agents may indicate attacking tools (SIPVicious)",
      "Alert on RTP traffic to/from unexpected endpoints",
      "Monitor for caller ID manipulation — From header differing from authentication identity"
    ],
    hardening: [
      "Use TLS for SIP signaling (port 5061) — prevent eavesdropping on signaling",
      "Enable SRTP for media encryption — prevent voice call interception",
      "Implement strong SIP authentication with complex passwords",
      "Restrict SIP registration to known IP ranges or use VPN",
      "Configure call rate limiting and concurrent call limits per extension",
      "Disable international calling where not needed — use whitelist for allowed destinations",
      "Implement toll fraud detection: unusual call patterns, premium numbers, high cost",
      "Use SIP ALG (Application Layer Gateway) on firewall for proper NAT traversal",
      "Enable SIP intrusion detection rules (SIPVicious detection signatures)",
      "Segment VoIP traffic on dedicated VLAN with QoS",
      "Disable SIP debug/trace modes in production"
    ]
  },
  {
    name: "VNC (Virtual Network Computing)",
    port: "5900+ (TCP, display :0 = 5900, :1 = 5901, etc.)",
    layer: "Application (Layer 7)",
    description: "Remote framebuffer protocol for graphical desktop sharing. Platform-independent. Uses RFB (Remote Framebuffer) protocol. Authentication: VNC password (DES-encrypted, max 8 chars), or platform authentication. No built-in encryption — traffic is cleartext by default. Variants: RealVNC, TightVNC, UltraVNC, TigerVNC.",
    rfc: "RFB Protocol specification (not an RFC — community standard)",
    attacks: [
      "VNC Authentication Bypass: Exploit vulnerabilities allowing connection without password (CVE-2006-2369)",
      "VNC Password Cracking: DES-encrypted VNC password is limited to 8 characters — cracked quickly",
      "VNC Session Sniffing: Capture unencrypted VNC traffic to reconstruct desktop display",
      "VNC Brute Force: Automated password guessing — limited password space (8 chars max) makes this fast",
      "Keyboard/Mouse Injection: Send input events to active VNC session to control remote system",
      "VNC Screenshot Capture: Connect to authenticated session and capture screen contents",
      "VNC Reverse Connection: Attacker's listening viewer receives connection from victim's VNC server",
      "UltraVNC Heap Overflow (CVE-2019-8262): RCE via malicious VNC client connecting to UltraVNC server"
    ],
    detection: [
      "Monitor for VNC traffic (ports 5900-5910) — should not be exposed to internet",
      "Alert on VNC authentication failures — brute force indicator",
      "Track VNC connections from unexpected source IPs",
      "Detect VNC reverse connections: outbound connections from servers to external VNC viewers",
      "Monitor for RFB protocol handshake on non-standard ports — VNC often runs on alternate ports",
      "Alert on VNC sessions during non-business hours"
    ],
    hardening: [
      "Never expose VNC directly to the internet — use SSH tunnel or VPN",
      "Use SSH tunneling for VNC: ssh -L 5900:localhost:5900 user@server, then connect to localhost:5900",
      "Replace VNC with more secure alternatives where possible (RDP with NLA, SSH X forwarding)",
      "Set strong VNC password (maximum 8 chars — inherent limitation, hence tunnel is essential)",
      "Configure VNC to listen only on localhost: -localhost flag in x11vnc/TigerVNC",
      "Use UltraVNC with encryption plugin or TigerVNC's built-in TLS",
      "Restrict VNC access via firewall to specific management IPs",
      "Disable VNC when not actively in use",
      "Monitor VNC log files for unauthorized access attempts",
      "Use certificate-based TLS with TigerVNC for encrypted connections"
    ]
  },
  {
    name: "NetBIOS (Network Basic Input/Output System)",
    port: "137 (UDP, name service), 138 (UDP, datagram), 139 (TCP, session)",
    layer: "Session (Layer 5)",
    description: "Legacy API and protocol for network communication in Windows environments. Provides name registration, name resolution, and session services. NetBIOS over TCP/IP (NBT) enables NetBIOS on modern networks. Largely superseded by DNS and direct SMB (port 445) but still present for backward compatibility.",
    rfc: "RFC 1001, RFC 1002 (NetBIOS over TCP/IP)",
    attacks: [
      "NetBIOS Name Spoofing: Respond to NBNS (NetBIOS Name Service) queries to redirect connections — tools: Responder, NBNSpoof",
      "NBNS/LLMNR Poisoning: Answer broadcast name queries to capture NTLM hashes — primary initial access technique on internal networks",
      "NetBIOS Enumeration: Use nbtstat, nbtscan to discover hostnames, domains, users, services on network",
      "NetBIOS Null Session: Establish session without credentials to enumerate shares and users",
      "NetBIOS DoS: Flood with registration/conflict packets to disrupt name resolution",
      "WPAD (Web Proxy Auto-Discovery) via NBNS: Poison WPAD name resolution to proxy all HTTP traffic through attacker"
    ],
    detection: [
      "Monitor NBNS query/response traffic — Responder produces responses to all queries",
      "Alert on NBNS responses from unexpected sources — legitimate responses come from the named host",
      "Track WPAD name resolution — should resolve only to legitimate proxy server",
      "Monitor for nbtstat/nbtscan patterns: rapid name queries across subnet",
      "Detect LLMNR/NBNS poisoning: responses from IP that doesn't match the queried name",
      "Alert on NetBIOS session establishment (port 139) from unexpected sources"
    ],
    hardening: [
      "Disable NetBIOS over TCP/IP on all systems where not required",
      "Disable LLMNR: Group Policy > Computer Configuration > Administrative Templates > Network > DNS Client > Turn Off Multicast Name Resolution",
      "Disable NBNS via DHCP scope option: NetBIOS Node Type = P-node (0x2)",
      "Block ports 137-139 at network perimeter and between VLANs",
      "Deploy WPAD via DNS only — configure DNS entry, disable NBNS/LLMNR WPAD resolution",
      "Use Group Policy to disable NetBIOS: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\NetBT\\Parameters\\NodeType = 2",
      "Deploy Responder detection tools (Respounder) on the network",
      "Segment networks to reduce broadcast domain — limits NBNS/LLMNR poisoning scope",
      "Disable WPAD if proxy auto-discovery is not used"
    ]
  },
  {
    name: "OSPF (Open Shortest Path First)",
    port: "IP protocol 89 (not TCP/UDP — directly over IP)",
    layer: "Network (Layer 3)",
    description: "Link-state interior gateway protocol for IP routing within an autonomous system. Uses Dijkstra's SPF algorithm. Supports VLSM, ECMP, route summarization. Areas reduce LSA flooding — Area 0 is backbone. LSA types: Router (1), Network (2), Summary (3), ASBR Summary (4), External (5), NSSA (7). Hello packets on multicast 224.0.0.5/6.",
    rfc: "RFC 2328 (OSPFv2), RFC 5340 (OSPFv3 for IPv6)",
    attacks: [
      "OSPF Router Injection: Introduce rogue router into OSPF area to advertise false routes",
      "LSA Manipulation: Inject forged LSAs to redirect traffic through attacker-controlled router",
      "OSPF Adjacency Disruption: Send modified Hello packets to prevent adjacency formation",
      "MaxAge LSA Attack: Set LSA age to MaxAge (3600s) to force premature LSA flushing",
      "Sequence Number Attack: Increment sequence number in forged LSAs to override legitimate advertisements",
      "Phantom Router: Create ghost router advertisements to create routing loops or blackholes",
      "OSPF Denial of Service: Flood with LSAs to overwhelm router CPU during SPF calculation"
    ],
    detection: [
      "Monitor for OSPF neighbor state changes — unexpected changes may indicate rogue router",
      "Alert on new OSPF routers appearing in routing domain",
      "Track LSA flooding patterns — sudden increase suggests manipulation",
      "Monitor OSPF area membership changes",
      "Alert on OSPF authentication failures — brute force or misconfiguration",
      "Track OSPF route changes for critical prefixes"
    ],
    hardening: [
      "Enable OSPF authentication: MD5 or SHA-256 (ip ospf authentication message-digest)",
      "Use OSPF cryptographic authentication (RFC 5709) with SHA-256",
      "Implement passive interfaces on all non-routing ports: passive-interface default",
      "Configure OSPF stub/NSSA areas to limit external LSA flooding",
      "Set maximum LSA limits per router to prevent LSA flooding DoS",
      "Use OSPF areas to segment routing domain and reduce attack surface",
      "Filter routes with distribute-lists and prefix-lists at area borders",
      "Enable OSPF graceful restart for planned maintenance",
      "Monitor OSPF logs and forward to SIEM for anomaly detection"
    ]
  },
  {
    name: "RIP (Routing Information Protocol)",
    port: "520 (UDP)",
    layer: "Application (Layer 7) / Network routing",
    description: "Distance-vector routing protocol. RIPv1 (classful, broadcast), RIPv2 (classless, multicast 224.0.0.9, authentication). Maximum 15 hops (16 = unreachable). 30-second update interval. Simple but slow convergence and limited scalability. Largely replaced by OSPF and EIGRP in modern networks.",
    rfc: "RFC 2453 (RIPv2)",
    attacks: [
      "Route Injection: Send crafted RIP responses with false routes to redirect traffic",
      "RIP Authentication Bypass: RIPv1 has no authentication; RIPv2 MD5 auth can be brute-forced",
      "Route Poisoning: Advertise routes with metric 16 (infinity) to black-hole traffic",
      "RIP Flooding: Send rapid route updates to overwhelm router processing",
      "RIP Information Disclosure: RIPv1 broadcasts entire routing table to all hosts on subnet",
      "Triggered Update Abuse: Force convergence storms by sending rapid topology changes"
    ],
    detection: [
      "Monitor for RIP traffic from non-router hosts — only routers should send RIP updates",
      "Alert on unexpected route changes in RIP routing table",
      "Track RIP update frequency — updates faster than 30 seconds are suspicious",
      "Monitor for routes with metric approaching 16 (potential poisoning)",
      "Alert on RIP updates from unknown source IPs"
    ],
    hardening: [
      "Migrate to OSPF or IS-IS — RIP has fundamental scalability and security limitations",
      "If RIP required, use RIPv2 with MD5 authentication",
      "Implement passive interfaces on all non-routing ports",
      "Configure route filtering with distribute-lists to limit accepted routes",
      "Set maximum metric and offset-lists to limit impact of route injection",
      "Block UDP 520 at network perimeter",
      "Use key chains with key rotation for RIPv2 authentication",
      "Enable route poisoning with split horizon and triggered updates for faster convergence"
    ]
  },
  {
    name: "GRE (Generic Routing Encapsulation)",
    port: "IP protocol 47 (not TCP/UDP)",
    layer: "Network (Layer 3)",
    description: "Tunneling protocol that encapsulates a wide variety of network layer protocols inside point-to-point connections. Used for VPNs, connecting non-contiguous networks, carrying multicast/IPv6 over IPv4. Adds 4-byte header (24 bytes with optional fields). No encryption — typically combined with IPsec for security.",
    rfc: "RFC 2784 (GRE), RFC 2890 (GRE Key and Sequence Number Extensions)",
    attacks: [
      "GRE Tunnel Pivoting: Use existing GRE tunnels to pivot into isolated network segments",
      "GRE Packet Injection: Inject packets into GRE tunnel to access internal networks",
      "GRE Tunnel Reconnaissance: Discover GRE tunnels to map internal network topology",
      "GRE DoS: Overwhelm tunnel endpoint with high volume of GRE encapsulated packets",
      "GRE Evasion: Encapsulate malicious traffic in GRE to bypass IDS/firewall that doesn't inspect GRE",
      "Double Encapsulation: Stack multiple GRE headers to evade security controls",
      "GRE Key Brute Force: Guess GRE key field (32-bit) to inject traffic into keyed tunnels"
    ],
    detection: [
      "Monitor for unexpected GRE traffic (IP protocol 47) — should only exist between known tunnel endpoints",
      "Inspect GRE tunnel payload with deep packet inspection capable IDS",
      "Alert on new GRE tunnels being established from non-router devices",
      "Track GRE traffic volume for anomalies",
      "Monitor for GRE-encapsulated traffic crossing network perimeter"
    ],
    hardening: [
      "Combine GRE with IPsec for encryption and authentication (GRE over IPsec)",
      "Use GRE key option for basic tunnel authentication (not a substitute for IPsec)",
      "Restrict GRE tunnel endpoints to specific source/destination IPs via ACL",
      "Enable GRE tunnel keepalives for dead peer detection",
      "Implement access lists on tunnel interfaces to filter encapsulated traffic",
      "Block GRE (protocol 47) at perimeter unless specifically required",
      "Use tunnel protection ipsec profile for automatic IPsec encryption of GRE tunnels",
      "Monitor GRE tunnel interface counters for anomalous traffic patterns"
    ]
  },
  {
    name: "IGMP (Internet Group Management Protocol)",
    port: "IP protocol 2",
    layer: "Network (Layer 3)",
    description: "Used by hosts to report multicast group membership to routers. IGMPv1: join only (leave on timeout). IGMPv2: adds explicit leave. IGMPv3: source-specific multicast (SSM). Routers use IGMP to maintain multicast group membership tables and forward multicast traffic only to interested receivers.",
    rfc: "RFC 3376 (IGMPv3), RFC 2236 (IGMPv2)",
    attacks: [
      "IGMP Flooding: Send massive IGMP membership reports to overwhelm switch/router IGMP snooping tables",
      "Multicast Storm: Join all multicast groups to receive all multicast traffic — causes network congestion",
      "IGMP Leave Injection: Send forged leave messages to remove legitimate members from multicast groups",
      "IGMP Source Spoofing: Forge IGMP reports to receive multicast traffic not intended for attacker",
      "Switch CAM Table Overflow via Multicast: Exploit multicast forwarding to flood traffic to all ports"
    ],
    detection: [
      "Monitor IGMP join/leave rates per port — high rates indicate potential abuse",
      "Alert on IGMP traffic from unexpected source IPs",
      "Track multicast group membership changes",
      "Monitor switch CPU utilization — IGMP flooding causes high CPU on L2/L3 switches",
      "Alert on all-groups multicast joins from single host"
    ],
    hardening: [
      "Enable IGMP snooping on all VLANs to limit multicast scope",
      "Configure IGMP snooping querier for each VLAN",
      "Set maximum multicast groups per port to prevent flooding",
      "Enable storm control for multicast traffic on access ports",
      "Implement IGMP filtering to restrict which groups hosts can join",
      "Configure multicast VLAN registration (MVR) for shared multicast sources",
      "Block IGMP at network perimeter unless required for specific applications"
    ]
  },
  {
    name: "RADIUS (Remote Authentication Dial-In User Service)",
    port: "1812 (authentication, UDP), 1813 (accounting, UDP)",
    layer: "Application (Layer 7)",
    description: "AAA (Authentication, Authorization, Accounting) protocol for network access control. Used by 802.1X, VPN, WiFi (WPA2-Enterprise), and network device authentication. Client-server model: NAS (Network Access Server) acts as RADIUS client. Supports PAP, CHAP, MS-CHAPv2, EAP methods. Shared secret for client-server authentication.",
    rfc: "RFC 2865 (RADIUS), RFC 2866 (RADIUS Accounting), RFC 3579 (RADIUS EAP)",
    attacks: [
      "Shared Secret Brute Force: Capture RADIUS packets and brute-force the shared secret offline",
      "RADIUS Packet Replay: Replay Access-Accept packets to bypass authentication",
      "RADIUS Response Forgery: Forge Access-Accept responses to NAS using cracked shared secret",
      "RADIUS Credential Harvesting: Capture PAP passwords transmitted inside RADIUS packets (MD5-encrypted with shared secret)",
      "EAP Downgrade: Force client to negotiate weaker EAP method (EAP-MD5 instead of EAP-TLS)",
      "RADIUS Proxy Manipulation: Exploit RADIUS proxy chains to inject or modify authentication decisions",
      "Blast-RADIUS (CVE-2024-3596): MD5 collision attack allowing response forgery without knowing shared secret"
    ],
    detection: [
      "Monitor RADIUS authentication failures — high rates indicate brute force or credential stuffing",
      "Alert on Access-Accept from unexpected RADIUS server IPs",
      "Track RADIUS accounting for session anomalies (excessive duration, bandwidth, unusual NAS IDs)",
      "Monitor for EAP downgrade: clients using EAP-MD5 or PAP when stronger methods are configured",
      "Alert on RADIUS traffic from non-NAS sources",
      "Monitor shared secret age — should be rotated regularly"
    ],
    hardening: [
      "Use strong, unique shared secrets (32+ random characters) per NAS",
      "Deploy RADIUS over TLS (RadSec, RFC 6614) instead of UDP with shared secrets",
      "Use EAP-TLS with client certificates for strongest authentication",
      "Implement RADIUS server redundancy (primary/secondary) for availability",
      "Restrict RADIUS client IPs via firewall and RADIUS server configuration",
      "Enable RADIUS accounting for audit trail and anomaly detection",
      "Rotate shared secrets regularly (quarterly minimum)",
      "Block RADIUS traffic (UDP 1812/1813) from untrusted networks",
      "Use certificate-based authentication (EAP-TLS/EAP-TTLS) instead of password-based (PAP/CHAP)",
      "Update RADIUS server to patch Blast-RADIUS (CVE-2024-3596) — enforce Message-Authenticator attribute"
    ]
  },
  {
    name: "TACACS+ (Terminal Access Controller Access-Control System Plus)",
    port: "49 (TCP)",
    layer: "Application (Layer 7)",
    description: "Cisco-developed AAA protocol for network device administration. Unlike RADIUS, separates authentication, authorization, and accounting into independent functions. Encrypts entire packet body (RADIUS only encrypts password). Uses TCP for reliable transport. Commonly used for managing routers, switches, and firewalls.",
    rfc: "RFC 8907 (TACACS+), originally Cisco proprietary",
    attacks: [
      "TACACS+ Key Cracking: Capture encrypted packets and brute-force the shared key (XOR-based encryption)",
      "TACACS+ Replay: Replay authentication packets captured from the wire",
      "TACACS+ MITM: Intercept and modify TACACS+ packets using cracked shared key",
      "Session Hijacking: Exploit session ID predictability in some implementations",
      "Authorization Bypass: Exploit misconfigured authorization rules to elevate privileges on network devices"
    ],
    detection: [
      "Monitor TACACS+ authentication failures per source IP",
      "Alert on TACACS+ connections from unexpected source IPs",
      "Track command authorization audit logs for privilege escalation attempts",
      "Monitor for TACACS+ traffic outside of management VLAN",
      "Alert on administrative commands executed during non-business hours"
    ],
    hardening: [
      "Use strong shared keys (32+ random characters) unique per device",
      "Restrict TACACS+ traffic to management VLAN only",
      "Implement per-command authorization on network devices",
      "Log all commands via TACACS+ accounting",
      "Use TACACS+ over IPsec or dedicated management network for encryption",
      "Implement dual-factor authentication through TACACS+ integration with MFA",
      "Configure timeout and lockout policies for failed authentication",
      "Deploy redundant TACACS+ servers for availability",
      "Review and audit authorization profiles regularly"
    ]
  },
  {
    name: "TFTP (Trivial File Transfer Protocol)",
    port: "69 (UDP)",
    layer: "Application (Layer 7)",
    description: "Simple, lockstep file transfer protocol with no authentication, no encryption, no directory listing. Used for PXE boot, network device firmware loading, VoIP phone provisioning. Transfers files in 512-byte blocks with stop-and-wait acknowledgment. Very limited — no security features whatsoever.",
    rfc: "RFC 1350",
    attacks: [
      "Unauthenticated File Access: TFTP has NO authentication — anyone can read/write accessible files",
      "Configuration Theft: Download router/switch configs from TFTP server (often contains passwords)",
      "TFTP Bounce: Use TFTP server as pivot to access files on connected networks",
      "Firmware Replacement: Upload malicious firmware to devices using TFTP for provisioning",
      "Directory Traversal: Access files outside TFTP root with ../../../ path traversal",
      "TFTP Server Discovery: Scan for TFTP servers to find configuration repositories and PXE images"
    ],
    detection: [
      "Monitor all TFTP (UDP 69) traffic — should be tightly controlled",
      "Alert on TFTP traffic from non-provisioning systems",
      "Track TFTP file access logs for configuration file downloads",
      "Monitor for TFTP traffic crossing network segments — should stay within management network",
      "Alert on TFTP PUT operations — writes to TFTP server are almost always suspicious"
    ],
    hardening: [
      "Isolate TFTP to a dedicated management VLAN — never expose to user networks",
      "Replace TFTP with SFTP/SCP wherever possible",
      "Configure TFTP server to serve read-only files only (disable writes)",
      "Restrict TFTP server to specific directory (chroot) — prevent directory traversal",
      "Use ACLs to restrict TFTP access to specific device IPs",
      "Block TFTP (UDP 69) at network perimeter",
      "Use TFTP only for initial device provisioning — switch to SSH/HTTPS management after setup",
      "Monitor and log all TFTP transactions"
    ]
  },
  {
    name: "IMAP (Internet Message Access Protocol)",
    port: "143 (TCP), 993 (IMAPS over TLS)",
    layer: "Application (Layer 7)",
    description: "Email retrieval protocol allowing clients to access and manage mail on server. Unlike POP3, keeps messages on server by default. Supports folders, server-side search, partial message fetch, concurrent access from multiple clients, IDLE for push notifications. IMAP4rev1 is current version.",
    rfc: "RFC 9051 (IMAP4rev2), RFC 3501 (IMAP4rev1)",
    attacks: [
      "IMAP Credential Sniffing: Capture LOGIN credentials on unencrypted port 143",
      "IMAP Brute Force: Automated password guessing against IMAP authentication",
      "IMAP STARTTLS Stripping: MITM downgrade to prevent TLS negotiation",
      "Email Exfiltration: Access mailbox via compromised credentials to steal sensitive data",
      "IMAP Command Injection: Inject IMAP commands through improperly sanitized inputs in webmail",
      "Mailbox Enumeration: Use authentication responses to enumerate valid email addresses",
      "OAuth Token Theft: Steal IMAP OAuth tokens for persistent mailbox access without password"
    ],
    detection: [
      "Monitor for cleartext IMAP traffic (port 143) — should be disabled or migrated to IMAPS",
      "Track IMAP authentication failures for brute force detection",
      "Alert on IMAP connections from unusual IPs or countries",
      "Monitor for large volume email downloads — potential exfiltration",
      "Track IMAP IDLE sessions for unusual duration or activity",
      "Alert on IMAP connections during non-business hours from service accounts"
    ],
    hardening: [
      "Require IMAPS (port 993) or STARTTLS — disable plaintext IMAP on port 143",
      "Implement MFA or app-specific passwords for IMAP access",
      "Use OAuth2 instead of password-based IMAP authentication where supported",
      "Set rate limiting on authentication attempts",
      "Implement account lockout after failed login attempts",
      "Monitor and log all IMAP access for security auditing",
      "Disable IMAP for accounts that only use webmail",
      "Restrict IMAP access to specific IP ranges or VPN"
    ]
  },
  {
    name: "POP3 (Post Office Protocol v3)",
    port: "110 (TCP), 995 (POP3S over TLS)",
    layer: "Application (Layer 7)",
    description: "Simple email retrieval protocol. Downloads messages to client and typically deletes from server. Supports APOP for challenge-response authentication. Limited compared to IMAP — no server-side folders, search, or concurrent access. Still used by some legacy systems and simple email clients.",
    rfc: "RFC 1939 (POP3)",
    attacks: [
      "POP3 Credential Sniffing: USER and PASS commands sent in cleartext on port 110",
      "POP3 Brute Force: Simple username/password makes brute force straightforward",
      "APOP Hash Cracking: Capture APOP MD5 challenge-response and crack offline",
      "POP3 STARTTLS Stripping: MITM to prevent encryption negotiation",
      "Mailbox Theft: Download all messages via compromised credentials — POP3 downloads entire mailbox"
    ],
    detection: [
      "Alert on cleartext POP3 traffic (port 110) — migrate to POP3S",
      "Monitor POP3 authentication failures",
      "Track POP3 connections from unexpected source IPs",
      "Alert on large mailbox downloads during unusual hours"
    ],
    hardening: [
      "Require POP3S (port 995) or STARTTLS — disable plaintext POP3",
      "Migrate to IMAP for better security features and server-side management",
      "Implement rate limiting and account lockout on POP3 authentication",
      "Use strong passwords and consider MFA integration",
      "Restrict POP3 access by IP range",
      "Log all POP3 access and forward to SIEM"
    ]
  },
  {
    name: "Modbus",
    port: "502 (TCP)",
    layer: "Application (Layer 7)",
    description: "Industrial control system (ICS/SCADA) protocol for communication between PLCs, RTUs, and HMIs. Originally serial (Modbus RTU/ASCII), now commonly Modbus/TCP. Function codes: read coils (01), read registers (03), write single coil (05), write single register (06), write multiple registers (16). No authentication or encryption — designed for trusted networks.",
    rfc: "No RFC — Modbus Organization specification",
    attacks: [
      "Modbus Command Injection: Send unauthorized function codes to manipulate PLC outputs (coils, registers)",
      "Modbus Reconnaissance: Read holding/input registers to map industrial process and device configuration",
      "Modbus DoS: Flood Modbus TCP port 502 or send malformed packets to crash PLC",
      "Modbus Replay: Capture and replay legitimate Modbus commands to reproduce actions",
      "Function Code Scanning: Enumerate supported function codes to identify device capabilities",
      "Register Manipulation: Write to holding registers to change setpoints, alarm thresholds, or process parameters",
      "Coil Forcing: Write to coils to toggle digital outputs (open/close valves, start/stop motors)",
      "Modbus MITM: Intercept and modify Modbus traffic between HMI and PLC"
    ],
    detection: [
      "Monitor for Modbus traffic from non-SCADA systems — strict source validation essential",
      "Alert on write function codes (05, 06, 15, 16) from unexpected sources",
      "Track read requests for sensitive registers — enumeration indicator",
      "Monitor for diagnostic function codes (08) — used for device interrogation",
      "Alert on Modbus traffic crossing IT/OT network boundary",
      "Implement Modbus-aware IDS (Snort/Suricata with Modbus preprocessor)"
    ],
    hardening: [
      "Isolate Modbus devices on dedicated OT network — air-gap from IT network where possible",
      "Use Modbus/TCP gateway with access control lists to restrict which IPs can send which function codes",
      "Implement industrial firewall (Tofino, Claroty, Nozomi) with Modbus protocol awareness",
      "Deploy industrial IDS for Modbus anomaly detection",
      "Use VPN or TLS tunnel for Modbus traffic that must traverse untrusted networks",
      "Disable unused Modbus function codes on PLCs",
      "Implement change detection on critical register values",
      "Follow IEC 62443 and NIST SP 800-82 for ICS security guidance",
      "Monitor and log all Modbus transactions",
      "Use Modbus/TCP security extensions where supported by devices"
    ]
  },
  {
    name: "DNP3 (Distributed Network Protocol 3)",
    port: "20000 (TCP/UDP)",
    layer: "Application (Layer 7)",
    description: "SCADA/ICS protocol widely used in electric utilities, water systems, and oil/gas. Supports event-driven reporting, time synchronization, file transfer. More robust than Modbus — supports CRC checks, fragmented messages, and Secure Authentication (SA) in DNP3-SA. Used between SCADA masters and remote outstations.",
    rfc: "IEEE 1815 (DNP3 standard)",
    attacks: [
      "DNP3 Command Injection: Send unauthorized control commands to open/close breakers, change setpoints",
      "DNP3 Spoofing: Forge DNP3 responses to feed false data to SCADA master",
      "DNP3 Replay Attack: Capture and replay legitimate DNP3 control sequences",
      "DNP3 Fragmentation Attack: Exploit fragmented message handling to crash or confuse outstation",
      "DNP3 DoS: Send malformed DNP3 frames to crash or reboot outstations",
      "Unsolicited Response Manipulation: Inject false unsolicited responses to trigger operator actions"
    ],
    detection: [
      "Monitor DNP3 traffic for unauthorized source addresses",
      "Alert on control function codes from non-master stations",
      "Track DNP3 authentication failures (if SA enabled)",
      "Monitor for unusual DNP3 function codes or data patterns",
      "Implement DNP3-aware IDS (Suricata has DNP3 parser)"
    ],
    hardening: [
      "Enable DNP3 Secure Authentication (SA) for mutual authentication",
      "Isolate DNP3 networks on dedicated OT infrastructure",
      "Use TLS or VPN tunnels for DNP3 traffic over untrusted networks",
      "Implement allowlists for DNP3 source and destination addresses",
      "Deploy industrial firewall with DNP3 deep packet inspection",
      "Follow NERC CIP standards for electric utility SCADA security",
      "Monitor and log all DNP3 control operations",
      "Implement bump-in-the-wire encryption devices for legacy DNP3 systems"
    ]
  },
  {
    name: "MQTT (Message Queuing Telemetry Transport)",
    port: "1883 (TCP), 8883 (TLS)",
    layer: "Application (Layer 7)",
    description: "Lightweight publish-subscribe messaging protocol designed for IoT and constrained devices. Topics organized hierarchically (home/livingroom/temperature). QoS levels: 0 (at most once), 1 (at least once), 2 (exactly once). Supports retained messages, last will and testament (LWT), persistent sessions. Broker-based architecture (Mosquitto, HiveMQ, EMQX).",
    rfc: "OASIS MQTT v5.0, OASIS MQTT v3.1.1",
    attacks: [
      "MQTT Credential Brute Force: Default installations often have no authentication",
      "Topic Eavesdropping: Subscribe to # (all topics) to monitor all MQTT messages on broker",
      "MQTT Injection: Publish malicious messages to actuator topics to control IoT devices",
      "Unauthorized Data Access: Subscribe to sensitive topics without proper ACL enforcement",
      "MQTT DoS: Flood broker with connections/publications to overwhelm processing",
      "Retained Message Poisoning: Publish retained messages with malicious payloads that persist",
      "Will Message Abuse: Set malicious will messages that trigger on disconnect",
      "Topic Enumeration: Subscribe to various topic patterns to discover IoT device hierarchy"
    ],
    detection: [
      "Monitor for wildcard subscriptions (# or +) — rarely legitimate in production",
      "Alert on MQTT connections without authentication credentials",
      "Track publication to actuator/control topics from unexpected clients",
      "Monitor MQTT broker connection rates for DoS indicators",
      "Alert on new client IDs connecting to production broker",
      "Track retained message changes on critical topics"
    ],
    hardening: [
      "Enable authentication — never run MQTT broker without username/password or certificates",
      "Use TLS on port 8883 — disable plaintext port 1883 in production",
      "Implement fine-grained ACLs per client — restrict publish/subscribe to needed topics only",
      "Disable anonymous connections: allow_anonymous false in Mosquitto",
      "Use client certificates for mutual TLS authentication",
      "Restrict wildcard subscriptions (#) to monitoring systems only",
      "Implement rate limiting per client on connection and publication",
      "Use separate MQTT brokers for different trust zones",
      "Enable MQTT v5 enhanced authentication for stronger auth flows",
      "Monitor broker logs and forward to SIEM"
    ]
  },
  {
    name: "CoAP (Constrained Application Protocol)",
    port: "5683 (UDP), 5684 (DTLS)",
    layer: "Application (Layer 7)",
    description: "Lightweight RESTful protocol for constrained IoT devices. Similar to HTTP but over UDP with much smaller overhead. Supports GET, PUT, POST, DELETE methods. Uses DTLS for security. Supports observe (push notifications), block-wise transfer (large payloads), and resource discovery (/.well-known/core). Designed for 6LoWPAN and Thread networks.",
    rfc: "RFC 7252 (CoAP), RFC 7641 (Observe), RFC 7959 (Block-Wise Transfer)",
    attacks: [
      "CoAP Amplification: Exploit multicast CoAP requests for DDoS amplification",
      "CoAP Spoofing: Forge CoAP responses (UDP-based, no connection state) to inject false data",
      "Resource Discovery Enumeration: Access /.well-known/core to map all available resources",
      "Unauthorized Resource Manipulation: PUT/POST/DELETE without authentication on misconfigured devices",
      "CoAP Observe Hijacking: Subscribe to observe notifications meant for legitimate clients",
      "Block-Wise Transfer Manipulation: Inject or modify blocks during large transfers"
    ],
    detection: [
      "Monitor for CoAP multicast traffic on 224.0.1.187 — limit to local networks",
      "Alert on CoAP traffic from external sources — IoT protocols should be internal",
      "Track CoAP resource discovery requests (/.well-known/core) from unexpected sources",
      "Monitor for CoAP PUT/DELETE operations on critical resources"
    ],
    hardening: [
      "Enable DTLS for all CoAP communications (port 5684)",
      "Implement CoAP access control — authenticate all clients before resource access",
      "Disable multicast CoAP discovery on production networks",
      "Use OSCORE (RFC 8613) for end-to-end security through proxies",
      "Restrict CoAP traffic to IoT VLAN — block at network perimeter",
      "Implement rate limiting on CoAP endpoints",
      "Use ACE (Authentication and Authorization for Constrained Environments) framework",
      "Monitor CoAP traffic with IoT-aware security tools"
    ]
  },
  {
    name: "WireGuard",
    port: "51820 (UDP, configurable)",
    layer: "Network (Layer 3)",
    description: "Modern VPN protocol designed for simplicity and performance. ~4,000 lines of code (vs ~400,000 for OpenVPN). Uses Noise protocol framework with Curve25519 (key exchange), ChaCha20-Poly1305 (encryption), BLAKE2s (hashing), SipHash24 (hashtable keys). Kernel-level implementation for high performance. Cryptokey routing: associates public keys with allowed IP ranges.",
    rfc: "No RFC — https://www.wireguard.com/protocol/",
    attacks: [
      "Key Compromise: Steal private key from /etc/wireguard/ to impersonate endpoint",
      "Endpoint Discovery: WireGuard responds to valid handshake initiations — can confirm endpoint existence",
      "IP Spoofing within Tunnel: AllowedIPs misconfiguration can allow routing arbitrary traffic through peers",
      "Denial of Service: Flood with handshake initiation packets (CPU-intensive operations)",
      "Side-Channel Timing: Timing attacks on Curve25519 implementation (mitigated in modern kernels)",
      "Configuration Exfiltration: Extract WireGuard config files containing private keys and peer information"
    ],
    detection: [
      "Monitor for WireGuard traffic (UDP, default port 51820) from unexpected sources",
      "Track WireGuard handshake rates — high rates may indicate DoS or scanning",
      "Alert on WireGuard configuration file access (inotify on /etc/wireguard/)",
      "Monitor for new WireGuard interfaces appearing on systems"
    ],
    hardening: [
      "Restrict WireGuard private key file permissions: chmod 600 /etc/wireguard/wg0.conf",
      "Use AllowedIPs to strictly limit which IPs each peer can route",
      "Implement post-quantum key exchange with WireGuard's experimental PQ support",
      "Change default port from 51820 to reduce scanning noise",
      "Use wg-quick with PostUp/PostDown rules for firewall integration",
      "Rotate keys periodically — WireGuard supports seamless key rotation",
      "Implement kill switch: PostUp = iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -j REJECT",
      "Monitor WireGuard handshake latest times to detect peer availability issues",
      "Use MultihopVPN configuration for defense in depth"
    ]
  },
  {
    name: "SNTP/PTP (Simple NTP / Precision Time Protocol)",
    port: "123 (SNTP, UDP), 319/320 (PTP, UDP)",
    layer: "Application (Layer 7)",
    description: "SNTP is a simplified NTP for devices that don't need full NTP complexity. PTP (IEEE 1588) provides sub-microsecond time synchronization using hardware timestamping — critical for financial trading, telecom, and industrial control. PTP uses master-slave hierarchy with Boundary Clocks and Transparent Clocks.",
    rfc: "RFC 4330 (SNTP), IEEE 1588 (PTP)",
    attacks: [
      "PTP Master Spoofing: Impersonate PTP grandmaster to take control of time synchronization",
      "PTP Delay Attack: Selectively delay PTP sync/delay-request messages to skew slave clocks",
      "Best Master Clock Algorithm Manipulation: Influence BMCA to elect attacker-controlled clock as grandmaster",
      "Time Stepping Attack: Introduce sudden large time offsets to disrupt time-sensitive applications",
      "SNTP Spoofing: Respond to SNTP queries with manipulated time to affect less-critical systems"
    ],
    detection: [
      "Monitor for PTP grandmaster changes — unexpected changes indicate spoofing",
      "Track PTP offset and delay metrics — sudden changes suggest manipulation",
      "Alert on new PTP announce messages from unknown sources",
      "Monitor SNTP traffic from non-configured sources"
    ],
    hardening: [
      "Use PTP with 802.1AS (generalized PTP) for automotive and industrial networks",
      "Implement PTP security annex (IEEE 1588-2019) with HMAC authentication",
      "Restrict PTP traffic to dedicated timing VLAN",
      "Use hardware timestamping for accurate PTP — software timestamps are more vulnerable to manipulation",
      "Deploy PTP monitoring to detect grandmaster anomalies",
      "Use redundant PTP grandmasters from independent sources",
      "Configure PTP domain separation to isolate timing zones",
      "Monitor PTP Best Master Clock election for manipulation"
    ]
  }
];

// Total protocols: 32 entries with comprehensive security data
// Categories covered: Transport, Network, Application, Data Link, ICS/SCADA, IoT, VPN, Routing, Email, Authentication
