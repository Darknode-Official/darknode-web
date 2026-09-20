// Copyright (c) 2026 SpartanKing18. All rights reserved.
// DNS Security Reference — record types, attacks, DNSSEC, enumeration, detection

export const DNS_RECORD_TYPES = [
  { type: "A", rfc: "RFC 1035", format: "name TTL IN A IPv4", example: "example.com. 300 IN A 93.184.216.34", description: "Maps hostname to IPv4 address", security: "Verify A records match expected IPs; attackers modify via DNS hijacking or cache poisoning to redirect traffic" },
  { type: "AAAA", rfc: "RFC 3596", format: "name TTL IN AAAA IPv6", example: "example.com. 300 IN AAAA 2606:2800:220:1:248:1893:25c8:1946", description: "Maps hostname to IPv6 address", security: "Dual-stack hosts may have AAAA records pointing to different infrastructure; check both A and AAAA for consistency" },
  { type: "CNAME", rfc: "RFC 1035", format: "name TTL IN CNAME target", example: "www.example.com. 300 IN CNAME example.com.", description: "Canonical name alias — points one name to another", security: "Dangling CNAMEs pointing to deprovisioned services enable subdomain takeover (e.g., old CNAME → deleted S3 bucket)" },
  { type: "MX", rfc: "RFC 1035", format: "name TTL IN MX priority mailserver", example: "example.com. 300 IN MX 10 mail.example.com.", description: "Mail exchange — specifies mail servers for the domain", security: "Verify MX records to detect email hijacking; attackers add rogue MX to intercept mail" },
  { type: "NS", rfc: "RFC 1035", format: "name TTL IN NS nameserver", example: "example.com. 86400 IN NS ns1.example.com.", description: "Authoritative nameserver for the zone", security: "Compromised NS records redirect all DNS resolution; NS takeover gives full domain control" },
  { type: "TXT", rfc: "RFC 1035", format: "name TTL IN TXT \"text\"", example: "example.com. 300 IN TXT \"v=spf1 include:_spf.google.com ~all\"", description: "Arbitrary text — used for SPF, DKIM, DMARC, domain verification", security: "TXT records expose SPF/DMARC policy; misconfigured SPF (+all) allows anyone to spoof email from the domain" },
  { type: "SOA", rfc: "RFC 1035", format: "name TTL IN SOA mname rname serial refresh retry expire minimum", example: "example.com. 86400 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400", description: "Start of Authority — zone metadata, serial number, timing", security: "SOA serial number reveals zone update frequency; RNAME exposes admin email; low TTLs may indicate fast-flux" },
  { type: "PTR", rfc: "RFC 1035", format: "reverse-ip.in-addr.arpa. TTL IN PTR hostname", example: "34.216.184.93.in-addr.arpa. 300 IN PTR example.com.", description: "Reverse DNS — maps IP to hostname", security: "Mismatched forward/reverse DNS is a red flag; PTR records help identify infrastructure ownership" },
  { type: "SRV", rfc: "RFC 2782", format: "service.proto.name TTL IN SRV priority weight port target", example: "_ldap._tcp.example.com. 300 IN SRV 0 100 389 dc1.example.com.", description: "Service locator — specifies host/port for services", security: "SRV records expose internal service topology (LDAP, Kerberos, SIP, XMPP); valuable for recon" },
  { type: "CAA", rfc: "RFC 8659", format: "name TTL IN CAA flags tag value", example: "example.com. 86400 IN CAA 0 issue \"letsencrypt.org\"", description: "Certificate Authority Authorization — restricts which CAs can issue certs", security: "Missing CAA allows any CA to issue certificates; always set CAA to prevent unauthorized certificate issuance" },
  { type: "TLSA", rfc: "RFC 6698", format: "port.proto.name TTL IN TLSA usage selector matching-type cert-data", example: "_443._tcp.example.com. 300 IN TLSA 3 1 1 abcdef...", description: "DANE TLS Authentication — pins certificates in DNS", security: "TLSA with DNSSEC provides certificate pinning at DNS level, preventing CA compromise attacks" },
  { type: "SSHFP", rfc: "RFC 4255", format: "name TTL IN SSHFP algorithm fingerprint-type fingerprint", example: "server.example.com. 300 IN SSHFP 2 1 123456789abcdef...", description: "SSH Fingerprint — publishes SSH host key fingerprints in DNS", security: "With DNSSEC, clients can verify SSH host keys via DNS instead of TOFU (Trust On First Use)" },
  { type: "NAPTR", rfc: "RFC 3403", format: "name TTL IN NAPTR order preference flags service regexp replacement", example: "example.com. 300 IN NAPTR 100 10 \"u\" \"E2U+sip\" \"!^.*$!sip:info@example.com!\" .", description: "Naming Authority Pointer — used in ENUM, SIP, S-NAPTR", security: "NAPTR can redirect VoIP/SIP traffic; verify records for telephony systems" },
  { type: "DNSKEY", rfc: "RFC 4034", format: "name TTL IN DNSKEY flags protocol algorithm public-key", example: "example.com. 86400 IN DNSKEY 257 3 13 base64-key...", description: "DNSSEC public key — Zone Signing Key (256) or Key Signing Key (257)", security: "KSK (flag 257) signs the DNSKEY RRset; ZSK (flag 256) signs all other records; key rollover must be coordinated" },
  { type: "DS", rfc: "RFC 4034", format: "name TTL IN DS key-tag algorithm digest-type digest", example: "example.com. 86400 IN DS 12345 13 2 abcdef...", description: "Delegation Signer — parent zone's hash of child's KSK, establishing chain of trust", security: "DS record in parent zone authenticates the child's DNSKEY; missing DS breaks DNSSEC chain" },
  { type: "RRSIG", rfc: "RFC 4034", format: "name TTL IN RRSIG type-covered algorithm labels original-ttl sig-expiration sig-inception key-tag signer signature", example: "example.com. 300 IN RRSIG A 13 2 300 20260101000000 20250101000000 12345 example.com. base64-sig...", description: "DNSSEC signature over an RRset", security: "Expired RRSIG causes validation failure (SERVFAIL); monitor expiration dates; clock skew can break validation" },
  { type: "NSEC", rfc: "RFC 4034", format: "name TTL IN NSEC next-name type-bitmap", example: "alpha.example.com. 300 IN NSEC beta.example.com. A AAAA RRSIG NSEC", description: "Authenticated denial of existence — proves a name does not exist by listing the next name", security: "NSEC allows zone walking (enumerating all names by following the chain); use NSEC3 to prevent this" },
  { type: "NSEC3", rfc: "RFC 5155", format: "name TTL IN NSEC3 algorithm flags iterations salt next-hashed-name type-bitmap", example: "abc123.example.com. 300 IN NSEC3 1 0 10 aabb def456 A AAAA RRSIG", description: "Hashed authenticated denial — prevents zone enumeration", security: "Low iteration counts are vulnerable to offline dictionary attacks; NSEC3 with opt-out can leave unsigned delegations" },
  { type: "NSEC3PARAM", rfc: "RFC 5155", format: "name TTL IN NSEC3PARAM algorithm flags iterations salt", example: "example.com. 0 IN NSEC3PARAM 1 0 10 aabb", description: "Parameters for NSEC3 hash computation", security: "Published in the zone so resolvers know the NSEC3 parameters; salt should be changed periodically" },
  { type: "HTTPS", rfc: "RFC 9460", format: "name TTL IN HTTPS priority target params", example: "example.com. 300 IN HTTPS 1 . alpn=\"h2,h3\" ipv4hint=93.184.216.34", description: "Service binding for HTTPS — specifies ALPN, ECH, IP hints", security: "HTTPS records enable Encrypted Client Hello (ECH) which hides the SNI, improving privacy; also prevents SSL stripping by advertising HTTPS support in DNS" },
  { type: "SVCB", rfc: "RFC 9460", format: "name TTL IN SVCB priority target params", example: "_dns.example.com. 300 IN SVCB 1 dot.example.com. alpn=\"dot\"", description: "Generic service binding — base type for HTTPS records", security: "SVCB directs clients to specific service endpoints; verify target integrity" },
  { type: "LOC", rfc: "RFC 1876", format: "name TTL IN LOC lat lon alt size", example: "example.com. 300 IN LOC 37 23 30.900 N 122 1 38.649 W 7.00m", description: "Geographic location of a host", security: "LOC records reveal physical infrastructure location; rarely used but valuable for OSINT if present" },
  { type: "HINFO", rfc: "RFC 1035", format: "name TTL IN HINFO cpu os", example: "server.example.com. 300 IN HINFO \"Intel\" \"Linux\"", description: "Host information — CPU and OS", security: "HINFO directly reveals OS and hardware; almost never published anymore due to security concerns" },
  { type: "RP", rfc: "RFC 1183", format: "name TTL IN RP mailbox txt-record", example: "example.com. 300 IN RP admin.example.com. info.example.com.", description: "Responsible Person for the domain", security: "RP records expose administrator contact information; useful for OSINT" },
  { type: "DNAME", rfc: "RFC 6672", format: "name TTL IN DNAME target", example: "legacy.example.com. 300 IN DNAME new.example.com.", description: "Delegation Name — redirects an entire subtree", security: "DNAME can redirect all subdomains; verify DNAME records haven't been maliciously added" },
  { type: "OPENPGPKEY", rfc: "RFC 7929", format: "hash._openpgpkey.domain TTL IN OPENPGPKEY key-data", example: "abc123._openpgpkey.example.com. 300 IN OPENPGPKEY base64-key...", description: "PGP public key published in DNS for email encryption", security: "With DNSSEC, provides authenticated key distribution for email encryption without key servers" },
  { type: "SMIMEA", rfc: "RFC 8162", format: "hash._smimecert.domain TTL IN SMIMEA usage selector matching cert-data", example: "abc._smimecert.example.com. 300 IN SMIMEA 3 0 1 abcdef...", description: "S/MIME certificate association — like TLSA but for email", security: "Enables DNS-based S/MIME certificate discovery and pinning" },
  { type: "URI", rfc: "RFC 7553", format: "name TTL IN URI priority weight target", example: "_http._tcp.example.com. 300 IN URI 10 1 \"https://www.example.com/\"", description: "Uniform Resource Identifier — maps a domain to a URI", security: "URI records can redirect services; verify targets haven't been modified" },
  { type: "CDNSKEY", rfc: "RFC 7344", format: "name TTL IN CDNSKEY flags protocol algorithm key", example: "example.com. 86400 IN CDNSKEY 257 3 13 base64-key...", description: "Child DNSKEY — child zone's proposed DNSKEY for automated key rollover", security: "Used for automated DNSSEC key rollover between parent and child zones; must be validated" },
  { type: "CDS", rfc: "RFC 7344", format: "name TTL IN CDS key-tag algorithm digest-type digest", example: "example.com. 86400 IN CDS 12345 13 2 abcdef...", description: "Child DS — child zone's proposed DS record for parent", security: "Enables automated DS record updates; reduces manual key management errors" },
  { type: "TSIG", rfc: "RFC 8945", format: "key-name algorithm time-signed fudge MAC original-id error other-data", example: "(transaction signature, not stored as RR)", description: "Transaction Signature — authenticates DNS messages (zone transfers, dynamic updates)", security: "TSIG authenticates AXFR/IXFR requests; weak TSIG keys or HMAC-MD5 are vulnerable; use HMAC-SHA256 minimum" },
  { type: "TKEY", rfc: "RFC 2930", format: "key-name algorithm inception expiration mode error key-data", example: "(key establishment, not stored as RR)", description: "Transaction Key — establishes shared secret for TSIG", security: "TKEY negotiates TSIG keys; GSS-TSIG integrates with Kerberos/Active Directory" },
  { type: "DLV", rfc: "RFC 4431", format: "name TTL IN DLV key-tag algorithm digest-type digest", example: "example.com.dlv.isc.org. 86400 IN DLV 12345 13 2 abcdef...", description: "DNSSEC Lookaside Validation — alternative trust anchor (deprecated)", security: "DLV was a workaround before widespread DNSSEC deployment; deprecated since 2017; should not be relied upon" },
  { type: "IPSECKEY", rfc: "RFC 4025", format: "name TTL IN IPSECKEY precedence gateway-type algorithm gateway public-key", example: "host.example.com. 300 IN IPSECKEY 10 2 2 gateway.example.com. base64-key...", description: "IPsec public key for opportunistic encryption", security: "Enables opportunistic IPsec between hosts using DNS-published keys; requires DNSSEC for authentication" },
  { type: "CERT", rfc: "RFC 4398", format: "name TTL IN CERT type key-tag algorithm certificate", example: "example.com. 300 IN CERT PKIX 0 0 base64-cert...", description: "Certificate record — stores X.509 or PGP certificates in DNS", security: "Publishes certificates in DNS; with DNSSEC provides an alternative to traditional CA infrastructure" },
  { type: "AFSDB", rfc: "RFC 1183", format: "name TTL IN AFSDB subtype hostname", example: "example.com. 300 IN AFSDB 1 afs.example.com.", description: "AFS Database — locates AFS cell database servers", security: "Exposes AFS infrastructure; rarely used in modern networks" },
  { type: "APL", rfc: "RFC 3123", format: "name TTL IN APL addressfamily:prefix/prefixlength", example: "example.com. 300 IN APL 1:192.168.0.0/16 !1:192.168.1.0/24", description: "Address Prefix List — specifies address ranges", security: "Can define network boundaries; the negation prefix (!) excludes ranges" },
  { type: "DHCID", rfc: "RFC 4701", format: "name TTL IN DHCID base64-data", example: "host.example.com. 300 IN DHCID base64...", description: "DHCP Identifier — prevents DDNS update conflicts", security: "Links dynamic DNS updates to specific DHCP clients; prevents hostname hijacking in DDNS environments" },
  { type: "CSYNC", rfc: "RFC 7477", format: "name TTL IN CSYNC serial flags type-bitmap", example: "example.com. 86400 IN CSYNC 2024010101 3 A AAAA NS", description: "Child-to-Parent Synchronization — automates glue record updates", security: "Automates NS and address record synchronization between child and parent zones" },
  { type: "ZONEMD", rfc: "RFC 8976", format: "name TTL IN ZONEMD serial scheme hash-algorithm digest", example: "example.com. 86400 IN ZONEMD 2024010101 1 1 abcdef...", description: "Zone Message Digest — integrity hash of the entire zone", security: "Provides zone-level integrity verification; complements DNSSEC by protecting the zone file as a whole" },
  { type: "EUI48", rfc: "RFC 7043", format: "name TTL IN EUI48 address", example: "host.example.com. 300 IN EUI48 00-00-5e-00-53-2a", description: "48-bit Extended Unique Identifier (MAC address)", security: "Publishes MAC addresses in DNS; useful for network inventory but exposes hardware identifiers" },
  { type: "EUI64", rfc: "RFC 7043", format: "name TTL IN EUI64 address", example: "host.example.com. 300 IN EUI64 00-00-5e-ef-10-00-00-2a", description: "64-bit Extended Unique Identifier", security: "EUI-64 can be derived from MAC addresses; privacy concern if published" },
  { type: "WALLET", rfc: "draft", format: "name TTL IN WALLET crypto-type address", example: "donate.example.com. 300 IN WALLET BTC bc1q...", description: "Cryptocurrency wallet address (proposed)", security: "If adopted, verify with DNSSEC to prevent wallet address replacement attacks" },
];

export const DNS_ATTACKS = [
  {
    name: "DNS Cache Poisoning",
    aka: ["Kaminsky Attack", "DNS Spoofing"],
    description: "Attacker injects forged DNS responses into a resolver's cache, causing it to return attacker-controlled IP addresses for legitimate domains. The classic Kaminsky attack exploits the birthday paradox by flooding the resolver with responses for random subdomains.",
    prerequisites: ["Network access to send packets to the resolver", "Knowledge of the resolver's source port (pre-randomization)", "Ability to trigger DNS queries from the target resolver"],
    steps: [
      "Trigger a query from the target resolver for a random subdomain (e.g., random123.example.com)",
      "Flood the resolver with forged responses before the real answer arrives",
      "Include a malicious Authority/Additional section that overwrites the NS or A record for example.com",
      "If the forged response arrives first with the correct transaction ID, the cache is poisoned",
      "All subsequent queries for example.com resolve to the attacker's IP until TTL expires"
    ],
    tools: ["dnsspoof", "Bettercap dns.spoof", "Ettercap dns_spoof", "custom scripts using Scapy"],
    detection: "Monitor for unusual DNS response patterns: multiple answers for same query, responses from unexpected sources, TTL anomalies, cache hit rate drops. DNSSEC validation failures indicate attempted poisoning.",
    prevention: ["Enable DNSSEC validation on resolvers", "Use DNS source port randomization (RFC 5452)", "Enable 0x20 encoding (mixed case query name randomization)", "Use DNS cookies (RFC 7873)", "Deploy DNS over HTTPS/TLS to prevent on-path manipulation", "Use Response Rate Limiting (RRL) on authoritative servers"],
    severity: "critical",
    cve_examples: ["CVE-2008-1447 (Kaminsky)", "CVE-2020-25705 (SAD DNS)", "CVE-2021-20322 (Linux kernel SAD DNS)"]
  },
  {
    name: "DNS Rebinding",
    aka: ["DNS Pinning Bypass"],
    description: "Attacker uses a malicious domain with a very short TTL. First resolution returns the attacker's IP (serving malicious JavaScript), then subsequent resolutions return an internal IP (e.g., 192.168.1.1). The browser's same-origin policy treats both as the same origin, allowing the script to access internal resources.",
    prerequisites: ["Victim must visit attacker-controlled domain", "Attacker controls their domain's authoritative DNS", "Target internal service accessible from victim's network"],
    steps: [
      "Victim visits attacker.com which resolves to attacker's server (1.2.3.4)",
      "Attacker's page loads JavaScript that will make requests to attacker.com",
      "Attacker's DNS server now returns 192.168.1.1 for attacker.com (TTL=0)",
      "Browser re-resolves attacker.com → 192.168.1.1 (internal router/service)",
      "JavaScript requests to attacker.com now hit the internal service",
      "Same-origin policy allows it because the origin (attacker.com) hasn't changed",
      "Attacker exfiltrates internal data back to their server"
    ],
    tools: ["Singularity (DNS rebinding tool)", "rbndr.us (rebinding service)", "whonow", "DNSrebinder", "Tavis Ormandy's rebinder"],
    detection: "Monitor DNS for domains resolving to private IP ranges (RFC 1918). Detect rapid DNS TTL changes. Web application firewalls can check Host headers against expected values.",
    prevention: ["DNS resolvers should refuse to return private IPs for public domains (DNS rebinding protection)", "Validate Host header on all internal services", "Use HTTPS with valid certificates on internal services", "Implement CORS properly on internal APIs", "Network segmentation to limit internal access from workstations"],
    severity: "high",
    cve_examples: ["CVE-2019-18634 (Router DNS rebinding)", "Multiple IoT device vulnerabilities"]
  },
  {
    name: "DNS Tunneling",
    aka: ["DNS Exfiltration", "DNS Covert Channel"],
    description: "Encodes data within DNS queries and responses to bypass firewalls and exfiltrate data. Since most networks allow DNS traffic (port 53), this creates a covert communication channel. Data is typically encoded in subdomain labels (queries) and TXT records (responses).",
    prerequisites: ["Attacker controls an authoritative DNS server for a domain", "Target network allows outbound DNS (port 53) — almost always true", "Client-side tool to encode/decode data"],
    steps: [
      "Attacker registers a domain (e.g., evil.com) and runs a tunneling server as its authoritative NS",
      "On the compromised host, run a DNS tunneling client",
      "To send data OUT: client encodes data as subdomain labels (e.g., base32-encoded-data.evil.com)",
      "Query reaches attacker's NS which decodes the subdomain label → original data",
      "To receive data IN: attacker's NS encodes response data in TXT/CNAME/MX records",
      "Client decodes the DNS response → original data",
      "Full bidirectional communication channel established over DNS"
    ],
    tools: ["iodine (IP-over-DNS)", "dnscat2 (C2 over DNS)", "dns2tcp", "Heyoka", "NSTX", "OzymanDNS", "DNSExfiltrator", "Cobalt Strike DNS beacon"],
    detection: "Unusually long subdomain labels (>30 chars), high volume of TXT queries to single domain, high entropy in query names, unusual query types (NULL, PRIVATE), queries to newly registered domains, DNS query frequency anomalies. Tools: passive DNS monitoring, Zeek dns.log analysis, ML-based detection.",
    prevention: ["Monitor and analyze DNS traffic patterns", "Block direct DNS to external resolvers (force through internal resolvers)", "Implement DNS query logging and analysis", "Use DNS firewalls/RPZ to block known tunneling domains", "Limit DNS response sizes", "Consider blocking TXT queries for non-email domains", "Deploy ML-based DNS anomaly detection"],
    severity: "high",
    cve_examples: []
  },
  {
    name: "DNS Amplification Attack",
    aka: ["DNS Reflection Attack", "DNS DDoS"],
    description: "Attacker sends small DNS queries with a spoofed source IP (the victim's IP) to open DNS resolvers. The resolvers send large responses to the victim, amplifying the traffic by 28-54x. Uses ANY/TXT queries to maximize response size.",
    prerequisites: ["Ability to spoof source IP addresses", "List of open DNS resolvers", "Target IP address"],
    steps: [
      "Attacker identifies open DNS resolvers (Shodan, Censys, masscan)",
      "Craft DNS queries for records with large responses (ANY, TXT with large SPF, DNSSEC-signed zones)",
      "Spoof the source IP to be the victim's IP address",
      "Send thousands of these small queries (~60 bytes each) to many resolvers",
      "Each resolver sends the large response (~3000+ bytes) to the victim",
      "Amplification factor of 28-54x floods the victim's bandwidth"
    ],
    tools: ["hping3", "Scapy", "custom UDP flooding tools"],
    detection: "Monitor for sudden spikes in DNS response traffic from many sources. IDS rules for DNS responses without corresponding queries. Netflow analysis showing asymmetric DNS traffic.",
    prevention: ["Configure resolvers as non-recursive (don't answer queries from the internet)", "Implement BCP38/BCP84 (ingress filtering to prevent IP spoofing)", "Rate limit DNS responses", "Disable ANY query support (RFC 8482)", "Use Response Rate Limiting (RRL) on authoritative servers", "Deploy Anycast for authoritative DNS"],
    severity: "high",
    cve_examples: []
  },
  {
    name: "Subdomain Takeover",
    aka: ["Dangling DNS", "Unclaimed Subdomain"],
    description: "When a subdomain's CNAME points to an external service (S3, GitHub Pages, Heroku, Azure, etc.) that has been deprovisioned, an attacker can claim that service and serve content on the victim's subdomain.",
    prerequisites: ["Target has a CNAME record pointing to an external service", "The external service/resource has been deleted or unclaimed", "The external service allows new registrations for the unclaimed resource"],
    steps: [
      "Enumerate target's subdomains (subfinder, amass, cert transparency)",
      "Check each subdomain for CNAME records pointing to external services",
      "Identify dangling CNAMEs (CNAME target returns NXDOMAIN or service-specific error pages)",
      "Register/claim the resource on the external service (e.g., create the S3 bucket, claim the GitHub Pages repo)",
      "Serve attacker-controlled content on the victim's subdomain",
      "Use for phishing, cookie theft (if parent domain cookies), or credential harvesting"
    ],
    tools: ["subjack", "nuclei (takeover templates)", "can-i-take-over-xyz (database)", "tko-subs", "SubOver", "dnsreaper"],
    detection: "Regular monitoring of DNS records for dangling CNAMEs. Automated scanning with subjack/nuclei. Certificate Transparency log monitoring for unauthorized certificates on subdomains.",
    prevention: ["Remove DNS records when deprovisioning services", "Regular audit of CNAME records", "Use wildcard DNS only when necessary", "Implement a DNS record lifecycle management process", "Monitor Certificate Transparency logs", "Set up alerts for NXDOMAIN responses on owned subdomains"],
    severity: "high",
    cve_examples: []
  },
  {
    name: "DNS Zone Transfer (AXFR)",
    aka: ["AXFR Leak", "Zone Transfer Attack"],
    description: "If a DNS server allows zone transfers to unauthorized hosts, an attacker can download the entire zone file, revealing all hostnames, IP addresses, MX records, and other DNS data for the domain.",
    prerequisites: ["Target DNS server has zone transfer enabled for any source", "Network access to the DNS server on port 53/TCP"],
    steps: [
      "Identify authoritative nameservers: dig NS example.com",
      "Attempt zone transfer: dig AXFR example.com @ns1.example.com",
      "If successful, the entire zone file is returned with all records",
      "Parse results for internal hostnames, IP ranges, mail servers, service records",
      "Use discovered hosts as targets for further enumeration"
    ],
    tools: ["dig (dig AXFR)", "nslookup (ls -d)", "host -l", "dnsrecon -t axfr", "fierce", "dnsenum"],
    detection: "Monitor DNS server logs for AXFR requests from unauthorized IPs. IDS rules for TCP/53 zone transfer attempts.",
    prevention: ["Restrict zone transfers to authorized secondary nameservers only (allow-transfer ACL)", "Use TSIG authentication for zone transfers", "Implement split-horizon DNS (internal/external views)", "Monitor and alert on zone transfer attempts"],
    severity: "medium",
    cve_examples: []
  },
  {
    name: "NXDOMAIN Attack",
    aka: ["DNS Water Torture", "Random Subdomain Attack", "Phantom Domain Attack"],
    description: "Attacker sends massive volumes of queries for non-existent subdomains, overwhelming the authoritative DNS server with NXDOMAIN responses. Unlike amplification, this targets the authoritative server directly.",
    prerequisites: ["Botnet or distributed infrastructure for sending queries", "Target domain name"],
    steps: [
      "Generate random subdomain queries: random1.example.com, random2.example.com, etc.",
      "Send millions of these queries through recursive resolvers",
      "Recursive resolvers forward to authoritative server (cache misses since names are random)",
      "Authoritative server overwhelmed processing NXDOMAIN responses",
      "Legitimate queries for example.com time out or fail"
    ],
    tools: ["Custom scripts", "Botnet infrastructure"],
    detection: "Spike in NXDOMAIN responses from authoritative server. High query rate for non-existent names. Resolver cache hit rate drops significantly.",
    prevention: ["Deploy Anycast DNS infrastructure", "Implement Response Rate Limiting (RRL)", "Use NSEC/NSEC3 aggressive negative caching (RFC 8198)", "Deploy DNS firewall / RPZ", "DDoS mitigation services (Cloudflare, Akamai, AWS Shield)"],
    severity: "high",
    cve_examples: []
  },
  {
    name: "DNS Hijacking",
    aka: ["DNS Redirection", "Router DNS Hijack", "Rogue DNS"],
    description: "Attacker modifies DNS settings (on the router, host, or registrar level) to redirect DNS queries to attacker-controlled servers. All traffic for any domain can then be redirected.",
    prerequisites: ["Access to router admin panel, host /etc/resolv.conf, or domain registrar account"],
    steps: [
      "Compromise router (default credentials, vulnerability) and change DNS settings",
      "Or modify victim's /etc/resolv.conf or Windows DNS settings",
      "Or compromise domain registrar account and change nameservers",
      "All DNS queries from affected hosts/network now go to attacker's DNS server",
      "Attacker returns malicious IPs for any queried domain",
      "Victim's traffic silently redirected to attacker infrastructure"
    ],
    tools: ["RouterSploit (router exploitation)", "DNSchef (fake DNS server)", "Bettercap", "Social engineering for registrar access"],
    detection: "Monitor DNS resolver settings on endpoints. DNSSEC validation failures. Certificate warnings when visiting HTTPS sites. Unexpected DNS server addresses in DHCP leases.",
    prevention: ["Change default router credentials", "Enable DNSSEC validation", "Use DNS over HTTPS/TLS on endpoints", "Enable registrar lock and 2FA on domain accounts", "Monitor DNS configuration via endpoint management", "Use HSTS to prevent downgrade to HTTP after redirect"],
    severity: "critical",
    cve_examples: ["DNSpionage (2018-2019)", "Sea Turtle (2017-2019)"]
  },
  {
    name: "DNS over HTTPS/TLS Bypass",
    aka: ["DoH/DoT Evasion"],
    description: "Malware uses DNS over HTTPS (DoH) or DNS over TLS (DoT) to bypass traditional DNS monitoring. Since queries are encrypted, network security tools cannot inspect them.",
    prerequisites: ["Malware on the endpoint", "Access to public DoH/DoT resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8, etc.)"],
    steps: [
      "Malware sends DNS queries over HTTPS (port 443) to a DoH resolver",
      "Traffic appears as normal HTTPS traffic, blending with web browsing",
      "Traditional DNS monitoring (port 53 inspection) sees nothing",
      "Malware can resolve C2 domains, exfiltrate data via DNS, all encrypted",
      "Even DNS tunneling works over DoH, making detection much harder"
    ],
    tools: ["curl (DoH client)", "cloudflared", "dnscrypt-proxy", "Custom malware with DoH libraries"],
    detection: "Block or monitor connections to known DoH resolver IPs. TLS SNI inspection for DoH endpoints (dns.google, cloudflare-dns.com). Deploy internal DoH resolver and force all DoH traffic through it. Endpoint-level DNS monitoring (EDR).",
    prevention: ["Block known DoH/DoT resolver IPs at the firewall", "Deploy internal DoH/DoT resolver", "Use endpoint DNS monitoring (EDR/XDR)", "Implement TLS inspection for outbound traffic", "Group policy to disable DoH in browsers", "Monitor for connections to DoH resolver hostnames via SNI"],
    severity: "medium",
    cve_examples: []
  },
  {
    name: "IDN Homograph Attack (DNS)",
    aka: ["Punycode Attack", "Unicode Domain Spoofing"],
    description: "Attacker registers an internationalized domain name (IDN) using Unicode characters that look identical to ASCII characters. For example, using Cyrillic 'а' (U+0430) instead of Latin 'a' (U+0061) to create a domain visually identical to a legitimate one.",
    prerequisites: ["A domain registrar that allows IDN registration", "Target domain that can be spoofed with lookalike Unicode characters"],
    steps: [
      "Identify target domain: apple.com",
      "Find Unicode homoglyphs: Cyrillic а=a, е=e, о=o, р=p, с=c, х=x",
      "Register: аррlе.com (xn--80ak6aa92e.com in Punycode) — looks identical to apple.com",
      "Set up phishing site on the homograph domain",
      "Victim sees what appears to be apple.com in the URL bar",
      "Modern browsers show Punycode for mixed-script domains, but single-script IDNs may display as Unicode"
    ],
    tools: ["EvilURL", "homoglyph-generator", "dnstwist", "urlcrazy"],
    detection: "Monitor Certificate Transparency logs for lookalike domains. Use domain monitoring services. Check for Punycode (xn--) domains similar to your brand.",
    prevention: ["Register defensive homograph domains", "Enable IDN display restrictions in browsers", "Certificate Transparency monitoring", "Domain takedown procedures", "User awareness training about checking URLs carefully"],
    severity: "medium",
    cve_examples: ["CVE-2017-5383 (Firefox IDN display)"]
  }
];

export const DNSSEC_REFERENCE = {
  overview: "DNSSEC adds cryptographic signatures to DNS records, creating a chain of trust from the root zone down to individual records. It provides authentication (records came from the authorized source) and integrity (records were not modified in transit), but NOT confidentiality (queries/responses are still plaintext).",
  chain_of_trust: [
    { level: "Root Zone", description: "Root DNSKEY is the trust anchor, hardcoded in resolvers. Signs DS records for TLDs.", key: "Root KSK (RSA 2048, key tag 20326)" },
    { level: "TLD (.com, .org, etc.)", description: "TLD's DNSKEY is authenticated by DS record in root zone. Signs DS records for second-level domains.", key: "TLD KSK + ZSK" },
    { level: "Domain (example.com)", description: "Domain's DNSKEY authenticated by DS record in TLD zone. Signs all records in the zone.", key: "Domain KSK + ZSK" }
  ],
  record_types: [
    { type: "DNSKEY", purpose: "Public keys used to verify RRSIG signatures. Flag 257 = KSK (signs DNSKEY RRset only), Flag 256 = ZSK (signs all other RRsets)." },
    { type: "RRSIG", purpose: "Signature over an RRset. Contains: covered type, algorithm, labels, original TTL, expiration, inception, key tag, signer name, and the signature itself." },
    { type: "DS", purpose: "Delegation Signer — hash of child zone's KSK, published in parent zone. Establishes the chain of trust downward." },
    { type: "NSEC", purpose: "Authenticated denial of existence. Lists the next existing name and the record types at the current name. Allows zone walking." },
    { type: "NSEC3", purpose: "Hashed denial of existence. Uses salted hashes of names instead of plaintext, preventing easy zone enumeration." },
    { type: "NSEC3PARAM", purpose: "Parameters for NSEC3: hash algorithm, flags, iterations, salt. Published in the zone apex." }
  ],
  algorithms: [
    { id: 5, name: "RSASHA1", status: "deprecated", notes: "SHA-1 is broken; do not use for new deployments" },
    { id: 7, name: "RSASHA1-NSEC3-SHA1", status: "deprecated", notes: "Same weakness as algorithm 5" },
    { id: 8, name: "RSASHA256", status: "recommended", notes: "RSA with SHA-256; widely supported; use 2048-bit keys minimum" },
    { id: 10, name: "RSASHA512", status: "acceptable", notes: "RSA with SHA-512; larger signatures, not always necessary" },
    { id: 13, name: "ECDSAP256SHA256", status: "recommended", notes: "ECDSA with P-256 curve; smaller keys and signatures than RSA; good performance" },
    { id: 14, name: "ECDSAP384SHA384", status: "acceptable", notes: "ECDSA with P-384; stronger than P-256 but larger signatures" },
    { id: 15, name: "ED25519", status: "recommended", notes: "EdDSA with Curve25519; smallest signatures, fastest verification; best choice for new deployments" },
    { id: 16, name: "ED448", status: "acceptable", notes: "EdDSA with Curve448; stronger than ED25519 but less widely supported" }
  ],
  validation_process: [
    "Resolver receives a DNS response with RRSIG records",
    "Resolver fetches the DNSKEY for the signing zone",
    "Resolver verifies the RRSIG using the ZSK from the DNSKEY RRset",
    "Resolver verifies the DNSKEY RRset using the KSK (self-signed DNSKEY RRSIG)",
    "Resolver fetches the DS record from the parent zone",
    "Resolver verifies that the DS record matches the hash of the child's KSK",
    "Process repeats up the chain to the root trust anchor",
    "If all signatures verify and none are expired, the response is SECURE (AD flag set)",
    "If validation fails, the response is BOGUS (SERVFAIL returned to client)"
  ],
  common_failures: [
    { issue: "Expired RRSIG", cause: "Zone not re-signed before signature expiration", fix: "Automate zone signing with proper refresh intervals; monitor expiration dates" },
    { issue: "Clock skew", cause: "Resolver's clock is outside the RRSIG validity window", fix: "Ensure NTP synchronization on all DNS servers and resolvers" },
    { issue: "Missing DS in parent", cause: "DS record not published or removed from parent zone", fix: "Verify DS record presence with dig DS example.com @parent-ns; resubmit if missing" },
    { issue: "Algorithm mismatch", cause: "DS record references an algorithm not present in DNSKEY RRset", fix: "Ensure DS algorithm matches the KSK algorithm" },
    { issue: "Key rollover failure", cause: "Old keys removed before new DS propagated to parent", fix: "Follow RFC 7583 key rollover timelines; use double-signing during transition" },
    { issue: "NSEC3 iteration too high", cause: "High iteration count causes resolver timeouts", fix: "Use iteration count of 0-10 per current best practice (was previously higher)" }
  ]
};

export const DNS_ENUMERATION_TOOLS = [
  { tool: "dig", category: "query", commands: [
    { cmd: "dig example.com ANY", desc: "Query all record types (may be blocked per RFC 8482)" },
    { cmd: "dig example.com AXFR @ns1.example.com", desc: "Attempt zone transfer" },
    { cmd: "dig +trace example.com", desc: "Trace delegation chain from root" },
    { cmd: "dig +dnssec example.com", desc: "Query with DNSSEC records" },
    { cmd: "dig +short example.com", desc: "Terse output — IP only" },
    { cmd: "dig -x 93.184.216.34", desc: "Reverse DNS lookup" },
    { cmd: "dig example.com TXT +noall +answer", desc: "Clean TXT record output" },
    { cmd: "dig @8.8.8.8 example.com", desc: "Query specific resolver" },
    { cmd: "dig +nsid @resolver example.com", desc: "Request resolver's NSID (identify anycast node)" },
    { cmd: "dig CH TXT version.bind @ns1.example.com", desc: "Query DNS server version (BIND)" }
  ]},
  { tool: "nslookup", category: "query", commands: [
    { cmd: "nslookup -type=any example.com", desc: "All records" },
    { cmd: "nslookup -type=mx example.com", desc: "Mail servers" },
    { cmd: "nslookup -type=ns example.com", desc: "Nameservers" },
    { cmd: "nslookup -type=soa example.com", desc: "SOA record" }
  ]},
  { tool: "host", category: "query", commands: [
    { cmd: "host -a example.com", desc: "All records" },
    { cmd: "host -t AAAA example.com", desc: "IPv6 records" },
    { cmd: "host -l example.com ns1.example.com", desc: "Zone transfer attempt" }
  ]},
  { tool: "dnsrecon", category: "enumeration", commands: [
    { cmd: "dnsrecon -d example.com -t std", desc: "Standard enumeration (SOA, NS, A, AAAA, MX, TXT)" },
    { cmd: "dnsrecon -d example.com -t axfr", desc: "Zone transfer attempt on all NS" },
    { cmd: "dnsrecon -d example.com -t brt -D subdomains.txt", desc: "Brute force subdomains" },
    { cmd: "dnsrecon -d example.com -t zonewalk", desc: "DNSSEC zone walk via NSEC records" },
    { cmd: "dnsrecon -d example.com -t crt", desc: "Enumerate via Certificate Transparency" },
    { cmd: "dnsrecon -r 192.168.1.0/24", desc: "Reverse DNS scan on IP range" }
  ]},
  { tool: "dnsenum", category: "enumeration", commands: [
    { cmd: "dnsenum example.com", desc: "Full enumeration (NS, MX, AXFR, brute force, whois)" },
    { cmd: "dnsenum --dnsserver 8.8.8.8 -f subdomains.txt example.com", desc: "Custom resolver + wordlist" },
    { cmd: "dnsenum --threads 10 --noreverse example.com", desc: "Fast scan, skip reverse lookups" }
  ]},
  { tool: "fierce", category: "enumeration", commands: [
    { cmd: "fierce --domain example.com", desc: "DNS reconnaissance and subdomain scanning" },
    { cmd: "fierce --domain example.com --subdomains subdomains.txt", desc: "Custom wordlist" },
    { cmd: "fierce --domain example.com --dns-servers 8.8.8.8", desc: "Use specific resolver" }
  ]},
  { tool: "subfinder", category: "subdomain", commands: [
    { cmd: "subfinder -d example.com", desc: "Passive subdomain enumeration (APIs, CT logs, archives)" },
    { cmd: "subfinder -d example.com -silent | httpx", desc: "Find live subdomains" },
    { cmd: "subfinder -dL domains.txt -o subs.txt", desc: "Batch mode with output file" },
    { cmd: "subfinder -d example.com -all -recursive", desc: "All sources + recursive enumeration" }
  ]},
  { tool: "amass", category: "subdomain", commands: [
    { cmd: "amass enum -d example.com", desc: "Subdomain enumeration (passive + active)" },
    { cmd: "amass enum -passive -d example.com", desc: "Passive only (no direct target contact)" },
    { cmd: "amass enum -brute -d example.com -w wordlist.txt", desc: "Include brute forcing" },
    { cmd: "amass intel -whois -d example.com", desc: "Discover related domains via WHOIS" },
    { cmd: "amass viz -d3 -d example.com", desc: "Visualize enumeration results" }
  ]},
  { tool: "massdns", category: "subdomain", commands: [
    { cmd: "massdns -r resolvers.txt -t A -o S subdomains.txt", desc: "High-speed DNS resolution" },
    { cmd: "massdns -r resolvers.txt -t A -o J subdomains.txt", desc: "JSON output" }
  ]},
  { tool: "dnstwist", category: "phishing", commands: [
    { cmd: "dnstwist example.com", desc: "Generate and check lookalike domains (typosquatting)" },
    { cmd: "dnstwist --registered example.com", desc: "Show only registered lookalike domains" },
    { cmd: "dnstwist --format json example.com", desc: "JSON output for automation" },
    { cmd: "dnstwist --whois example.com", desc: "Include WHOIS data for registered domains" }
  ]},
  { tool: "dnsx", category: "resolution", commands: [
    { cmd: "cat subs.txt | dnsx -a -resp", desc: "Resolve A records with responses" },
    { cmd: "cat subs.txt | dnsx -cname -resp", desc: "Find CNAME records" },
    { cmd: "echo example.com | dnsx -recon", desc: "Full reconnaissance" },
    { cmd: "cat ips.txt | dnsx -ptr -resp", desc: "Reverse DNS lookups" }
  ]}
];

export const DNS_MISCONFIGURATIONS = [
  { id: 1, category: "Zone Transfer", issue: "AXFR allowed to any source", risk: "critical", description: "Zone transfer (AXFR) is enabled without IP restrictions, allowing anyone to download the complete zone file and enumerate all DNS records.", remediation: "Restrict allow-transfer to authorized secondary nameserver IPs only. Use TSIG authentication for zone transfers.", check: "dig AXFR example.com @ns1.example.com" },
  { id: 2, category: "Zone Transfer", issue: "IXFR allowed without authentication", risk: "high", description: "Incremental zone transfers accepted without TSIG authentication.", remediation: "Require TSIG for all zone transfers (AXFR and IXFR).", check: "dig IXFR=2024010100 example.com @ns1.example.com" },
  { id: 3, category: "Recursion", issue: "Open resolver (recursion enabled for all)", risk: "critical", description: "DNS server answers recursive queries from any source IP. Can be abused for DNS amplification DDoS attacks.", remediation: "Disable recursion on authoritative servers. On recursive resolvers, restrict to authorized networks only (allow-recursion ACL).", check: "dig @target-ns google.com — if it resolves, recursion is open" },
  { id: 4, category: "DNSSEC", issue: "No DNSSEC signing", risk: "medium", description: "Zone is not signed with DNSSEC, leaving it vulnerable to cache poisoning and response spoofing.", remediation: "Enable DNSSEC signing. Use automated tools like OpenDNSSEC or BIND's inline-signing.", check: "dig +dnssec example.com — no RRSIG records returned" },
  { id: 5, category: "DNSSEC", issue: "Expired RRSIG signatures", risk: "critical", description: "DNSSEC signatures have expired, causing SERVFAIL for validating resolvers. Effectively a self-inflicted outage.", remediation: "Re-sign the zone immediately. Implement automated re-signing with monitoring for expiration.", check: "dig +dnssec example.com — check RRSIG expiration dates" },
  { id: 6, category: "DNSSEC", issue: "Missing DS record in parent zone", risk: "high", description: "Zone is signed but DS record is not published in the parent, breaking the chain of trust.", remediation: "Submit DS record to parent zone (via registrar or EPP).", check: "dig DS example.com @parent-ns" },
  { id: 7, category: "DNSSEC", issue: "NSEC zone walking possible", risk: "low", description: "Zone uses NSEC (not NSEC3), allowing enumeration of all names by following the NSEC chain.", remediation: "Switch to NSEC3 with appropriate salt and iterations. Or use NSEC3 with opt-out for large zones.", check: "dnsrecon -d example.com -t zonewalk" },
  { id: 8, category: "DNSSEC", issue: "Weak DNSSEC algorithm (RSA-SHA1)", risk: "medium", description: "Zone is signed with algorithm 5 or 7 (RSA-SHA1) which uses the broken SHA-1 hash.", remediation: "Roll to algorithm 13 (ECDSA P-256) or 15 (ED25519). Follow RFC 7583 for algorithm rollover.", check: "dig DNSKEY example.com — check algorithm field" },
  { id: 9, category: "SPF", issue: "Missing SPF record", risk: "high", description: "No SPF TXT record, allowing anyone to send email claiming to be from the domain.", remediation: "Add an SPF record: v=spf1 include:_spf.google.com -all (adjust to your mail setup).", check: "dig TXT example.com | grep spf" },
  { id: 10, category: "SPF", issue: "SPF with +all or ?all", risk: "critical", description: "SPF record ends with +all (pass all) or ?all (neutral), effectively not restricting email senders.", remediation: "Use -all (hard fail) or ~all (soft fail). Never use +all.", check: "dig TXT example.com — check SPF mechanism" },
  { id: 11, category: "SPF", issue: "SPF with too many DNS lookups (>10)", risk: "medium", description: "SPF record exceeds the 10 DNS lookup limit (RFC 7208), causing SPF evaluation to fail (permerror).", remediation: "Flatten SPF records to reduce lookup count. Use ip4/ip6 mechanisms instead of include where possible.", check: "Use online SPF checker tools or spf-tools" },
  { id: 12, category: "DMARC", issue: "Missing DMARC record", risk: "high", description: "No DMARC policy, so receiving mail servers don't know how to handle SPF/DKIM failures.", remediation: "Add _dmarc.example.com TXT record: v=DMARC1; p=reject; rua=mailto:dmarc@example.com", check: "dig TXT _dmarc.example.com" },
  { id: 13, category: "DMARC", issue: "DMARC policy set to p=none", risk: "medium", description: "DMARC is in monitoring-only mode and does not instruct receivers to reject spoofed email.", remediation: "After monitoring period, escalate to p=quarantine then p=reject.", check: "dig TXT _dmarc.example.com — check p= value" },
  { id: 14, category: "DKIM", issue: "Missing DKIM records", risk: "medium", description: "No DKIM public key published in DNS, so email signatures cannot be verified.", remediation: "Configure DKIM signing on your mail server and publish the public key as a TXT record.", check: "dig TXT selector._domainkey.example.com" },
  { id: 15, category: "DKIM", issue: "Weak DKIM key (RSA 512/768-bit)", risk: "high", description: "DKIM key is too short to resist brute-force attacks.", remediation: "Use RSA 2048-bit or Ed25519 DKIM keys.", check: "Check DKIM TXT record key length" },
  { id: 16, category: "CAA", issue: "Missing CAA record", risk: "medium", description: "No CAA record, allowing any Certificate Authority to issue certificates for the domain.", remediation: "Add CAA records: example.com. CAA 0 issue \"letsencrypt.org\" (restrict to your CA).", check: "dig CAA example.com" },
  { id: 17, category: "Nameserver", issue: "Single nameserver (no redundancy)", risk: "high", description: "Only one nameserver configured. If it goes down, the entire domain becomes unreachable.", remediation: "Configure at least 2 nameservers, preferably on different networks and in different geographic locations.", check: "dig NS example.com — count results" },
  { id: 18, category: "Nameserver", issue: "All nameservers on same subnet", risk: "medium", description: "All nameservers share the same /24 network, creating a single point of failure.", remediation: "Use nameservers on different networks and with different providers (e.g., one on Route53, one on Cloudflare).", check: "Resolve all NS records and compare IP subnets" },
  { id: 19, category: "Nameserver", issue: "DNS server version disclosed", risk: "low", description: "DNS server responds to version.bind or version.server queries, revealing software and version.", remediation: "Set version string to a generic value: version \"not disclosed\"; in BIND configuration.", check: "dig CH TXT version.bind @ns1.example.com" },
  { id: 20, category: "TTL", issue: "Excessively long TTL on critical records", risk: "low", description: "Very high TTL (>86400) on A/AAAA records makes it slow to respond to incidents or IP changes.", remediation: "Use TTLs of 300-3600 for A/AAAA records. Higher TTLs (86400) are acceptable for NS and MX.", check: "dig example.com — check TTL value" },
  { id: 21, category: "TTL", issue: "Very short TTL (possible fast-flux)", risk: "medium", description: "TTL of 0-60 seconds on A records may indicate fast-flux DNS used by botnets to cycle through IPs rapidly.", remediation: "Investigate domains with very short TTLs. Legitimate CDNs may use short TTLs, but combined with high IP churn it's suspicious.", check: "Monitor for domains with TTL < 60 resolving to many different IPs" },
  { id: 22, category: "Subdomain", issue: "Dangling CNAME (subdomain takeover risk)", risk: "high", description: "CNAME record points to a service that no longer exists (e.g., deleted S3 bucket, deprovisioned Heroku app).", remediation: "Remove the DNS record or re-provision the service. Audit CNAME records regularly.", check: "Resolve CNAMEs and check if targets return NXDOMAIN or service-specific error pages" },
  { id: 23, category: "Subdomain", issue: "Wildcard DNS record", risk: "medium", description: "Wildcard record (*.example.com) causes all non-existent subdomains to resolve, masking potential issues.", remediation: "Use wildcards only when intentional (CDN, email). Remove if not needed. Monitor for abuse.", check: "dig random-nonexistent-name.example.com — if it resolves, wildcard is active" },
  { id: 24, category: "Privacy", issue: "HINFO records published", risk: "low", description: "HINFO records reveal CPU architecture and operating system of hosts.", remediation: "Remove HINFO records. They are rarely used and provide reconnaissance data to attackers.", check: "dig HINFO hostname.example.com" },
  { id: 25, category: "Privacy", issue: "LOC records expose physical location", risk: "low", description: "LOC records reveal geographic coordinates of infrastructure.", remediation: "Remove LOC records unless required for a specific application.", check: "dig LOC example.com" },
  { id: 26, category: "Dynamic DNS", issue: "Unsecured dynamic DNS updates", risk: "critical", description: "DNS server accepts dynamic updates (nsupdate) without TSIG authentication.", remediation: "Require TSIG authentication for all dynamic updates. Restrict update-policy to specific zones and record types.", check: "nsupdate -v then 'update add test.example.com 60 A 1.2.3.4' — should be rejected" },
  { id: 27, category: "Resolver", issue: "No DNSSEC validation on resolver", risk: "medium", description: "Recursive resolver does not validate DNSSEC signatures, accepting potentially poisoned responses.", remediation: "Enable DNSSEC validation: dnssec-validation auto; in BIND or equivalent in other resolvers.", check: "dig +dnssec +cd example.com vs dig +dnssec example.com — compare AD flag" },
  { id: 28, category: "Resolver", issue: "Resolver forwarding to single upstream", risk: "medium", description: "Resolver forwards all queries to a single upstream resolver, creating a single point of failure and trust.", remediation: "Configure multiple forwarders or enable full recursion from root hints.", check: "Check resolver configuration for forwarders list" },
  { id: 29, category: "Email", issue: "MX record points to IP instead of hostname", risk: "low", description: "MX records should point to hostnames, not IP addresses (RFC 2181).", remediation: "Change MX to point to a hostname with a corresponding A record.", check: "dig MX example.com" },
  { id: 30, category: "Email", issue: "No MTA-STS record", risk: "medium", description: "Missing MTA-STS policy, leaving SMTP connections vulnerable to downgrade attacks.", remediation: "Publish _mta-sts.example.com TXT record and host a policy file at https://mta-sts.example.com/.well-known/mta-sts.txt", check: "dig TXT _mta-sts.example.com" },
];

export const DNS_DETECTION_PATTERNS = {
  zeek_rules: [
    { name: "DNS Tunneling Detection", description: "Detect unusually long DNS queries indicative of tunneling", rule: "event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) { if (|query| > 52) { NOTICE([$note=DNS::Tunneling, $msg=fmt(\"Long DNS query: %s\", query), $conn=c]); } }" },
    { name: "High Volume DNS to Single Domain", description: "Alert on excessive queries to one domain", rule: "Track unique queries per domain per time window; alert when count > threshold (e.g., 100 queries in 60 seconds)" },
    { name: "DNS Zone Transfer Attempt", description: "Detect AXFR/IXFR queries", rule: "event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) { if (qtype == 252 || qtype == 251) { NOTICE([$note=DNS::ZoneTransfer, $msg=fmt(\"Zone transfer attempt: %s\", query), $conn=c]); } }" },
    { name: "TXT Record Abuse", description: "Detect high volume of TXT queries (potential data exfiltration)", rule: "Track TXT query frequency; alert when rate exceeds normal baseline" },
    { name: "NXDOMAIN Flood", description: "Detect DNS water torture attacks", rule: "Monitor NXDOMAIN response rate per authoritative domain; alert on spike" },
    { name: "DNS to Non-Standard Port", description: "DNS traffic on ports other than 53", rule: "event connection_established(c: connection) { if (c$id$resp_p != 53/tcp && c$id$resp_p != 53/udp && c$service == \"dns\") NOTICE(...); }" }
  ],
  suricata_rules: [
    { sid: 2100001, rule: "alert dns any any -> any any (msg:\"DNS Zone Transfer Attempt\"; dns.query; content:\"AXFR\"; nocase; sid:2100001; rev:1;)", description: "Detect AXFR zone transfer requests" },
    { sid: 2100002, rule: "alert dns any any -> any any (msg:\"Suspicious Long DNS Query\"; dns.query; content:\"|00|\"; offset:50; sid:2100002; rev:1;)", description: "DNS query over 50 bytes (potential tunneling)" },
    { sid: 2100003, rule: "alert dns any any -> any any (msg:\"DNS Query for TXT Record\"; dns.query; dns.rrtype:16; threshold:type both, track by_src, count 50, seconds 60; sid:2100003; rev:1;)", description: "High rate of TXT queries from single source" },
    { sid: 2100004, rule: "alert dns any any -> any any (msg:\"DNS Query to Known Tunneling Domain\"; dns.query; content:\"tunnel.example.com\"; nocase; sid:2100004; rev:1;)", description: "Query to known DNS tunneling domain" },
    { sid: 2100005, rule: "alert dns any any -> any any (msg:\"High Entropy DNS Query\"; dns.query; pcre:\"/^[a-z0-9]{32,}\\./i\"; sid:2100005; rev:1;)", description: "Detect high-entropy subdomain queries (base32/64 encoded)" },
    { sid: 2100006, rule: "alert dns any any -> any any (msg:\"DNS Response with Private IP\"; dns.answer; content:\"|c0 a8|\"; sid:2100006; rev:1;)", description: "DNS response containing private IP range (192.168.x.x) — potential rebinding" }
  ],
  indicators_of_compromise: [
    { indicator: "Query length > 50 characters", category: "tunneling", confidence: "medium" },
    { indicator: "High entropy in subdomain labels", category: "tunneling", confidence: "high" },
    { indicator: "TXT query volume > 100/minute to single domain", category: "exfiltration", confidence: "high" },
    { indicator: "NULL/PRIVATE record type queries", category: "tunneling", confidence: "high" },
    { indicator: "Queries to newly registered domains (< 7 days)", category: "C2", confidence: "medium" },
    { indicator: "DNS responses with private IP ranges", category: "rebinding", confidence: "high" },
    { indicator: "NXDOMAIN rate > 1000/minute from single source", category: "DDoS", confidence: "high" },
    { indicator: "Consistent periodic DNS queries (beaconing)", category: "C2", confidence: "high" },
    { indicator: "DNS queries to known DGA patterns", category: "malware", confidence: "high" },
    { indicator: "Multiple A record changes in short period (fast-flux)", category: "botnet", confidence: "medium" }
  ]
};

export const DNS_PASSIVE_SOURCES = [
  { name: "SecurityTrails", url: "https://securitytrails.com", description: "Historical DNS data, WHOIS, subdomains", api: true },
  { name: "VirusTotal", url: "https://virustotal.com", description: "DNS resolution history, passive DNS, related domains", api: true },
  { name: "Farsight DNSDB", url: "https://dnsdb.info", description: "Largest passive DNS database, historical lookups", api: true },
  { name: "PassiveTotal (RiskIQ)", url: "https://community.riskiq.com", description: "Passive DNS, WHOIS, SSL certificates, host pairs", api: true },
  { name: "Robtex", url: "https://robtex.com", description: "DNS lookups, IP/AS information, shared DNS", api: false },
  { name: "DNSdumpster", url: "https://dnsdumpster.com", description: "Free domain research, DNS recon, network mapping", api: false },
  { name: "Certificate Transparency Logs", url: "https://crt.sh", description: "All SSL certificates issued for a domain (reveals subdomains)", api: true },
  { name: "Shodan", url: "https://shodan.io", description: "DNS server banners, open resolvers, service discovery", api: true },
  { name: "Censys", url: "https://censys.io", description: "DNS infrastructure scanning, certificate discovery", api: true },
  { name: "BGP Toolkit (Hurricane Electric)", url: "https://bgp.he.net", description: "DNS, WHOIS, BGP, network information", api: false },
  { name: "ViewDNS.info", url: "https://viewdns.info", description: "Reverse IP, DNS propagation, WHOIS, port scanner", api: true },
  { name: "Wayback Machine", url: "https://web.archive.org", description: "Historical website snapshots (may reveal old DNS configurations)", api: true }
];
