// Copyright (c) 2026 Darknode-Official. All rights reserved.
// DNS Toolkit -- DNS analysis, security, and record building.

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const DNS_RECORDS = [
  { type: "A", rfc: "1035", desc: "Maps hostname to IPv4 address", example: "example.com. 300 IN A 93.184.216.34", security: "Verify resolution. Watch for DNS hijacking pointing to malicious IPs. Check with dig/nslookup from multiple resolvers." },
  { type: "AAAA", rfc: "3596", desc: "Maps hostname to IPv6 address", example: "example.com. 300 IN AAAA 2606:2800:220:1:248:1893:25c8:1946", security: "Same risks as A records. Ensure IPv6 firewall rules match IPv4 policies." },
  { type: "CNAME", rfc: "1035", desc: "Canonical name alias -- points one domain to another", example: "www.example.com. 300 IN CNAME example.com.", security: "Dangling CNAMEs enable subdomain takeover. Regularly audit CNAMEs pointing to decommissioned services (S3, Heroku, Azure, GitHub Pages)." },
  { type: "MX", rfc: "1035", desc: "Mail exchange server with priority (lower = higher priority)", example: "example.com. 300 IN MX 10 mail.example.com.", security: "MX records direct email routing. Misconfigured MX can lead to email interception. Always pair with SPF/DKIM/DMARC." },
  { type: "NS", rfc: "1035", desc: "Authoritative nameserver for the zone", example: "example.com. 86400 IN NS ns1.example.com.", security: "NS hijacking redirects all DNS queries. Monitor for unauthorized NS changes. Use registrar lock." },
  { type: "TXT", rfc: "1035", desc: "Arbitrary text -- used for SPF, DKIM, DMARC, domain verification", example: 'example.com. 300 IN TXT "v=spf1 include:_spf.google.com ~all"', security: "Contains critical email security records. SPF prevents spoofing. DKIM proves message integrity. DMARC enforces policy." },
  { type: "SOA", rfc: "1035", desc: "Start of Authority -- zone metadata (serial, refresh, retry, expire, minimum TTL)", example: "example.com. 86400 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400", security: "SOA serial number helps detect unauthorized zone changes. Low TTL minimum can be exploited for rapid DNS changes." },
  { type: "SRV", rfc: "2782", desc: "Service locator -- specifies host and port for services (LDAP, SIP, XMPP)", example: "_sip._tcp.example.com. 300 IN SRV 10 5 5060 sip.example.com.", security: "SRV records expose internal service architecture. Attackers use them to discover LDAP, Kerberos, and other services." },
  { type: "PTR", rfc: "1035", desc: "Pointer record for reverse DNS -- maps IP to hostname", example: "34.216.184.93.in-addr.arpa. 300 IN PTR example.com.", security: "Missing PTR records cause email deliverability issues. Forward-confirmed reverse DNS (FCrDNS) validates IP-hostname relationship." },
  { type: "CAA", rfc: "8659", desc: "Certificate Authority Authorization -- specifies which CAs can issue certs for the domain", example: 'example.com. 86400 IN CAA 0 issue "letsencrypt.org"', security: "Critical security record. Prevents unauthorized certificate issuance. Should be set for all domains. Include iodef for violation notifications." },
  { type: "DNSKEY", rfc: "4034", desc: "DNSSEC public key for zone signing", example: "example.com. 86400 IN DNSKEY 257 3 13 base64...", security: "Part of DNSSEC chain of trust. KSK (flag 257) signs ZSK. ZSK (flag 256) signs zone records." },
  { type: "DS", rfc: "4034", desc: "Delegation Signer -- links parent zone to child zone's DNSKEY for DNSSEC", example: "example.com. 86400 IN DS 12345 13 2 base16hash...", security: "DS record in parent zone validates child's DNSKEY. Missing DS breaks DNSSEC chain. Must be updated on key rotation." },
  { type: "RRSIG", rfc: "4034", desc: "DNSSEC signature over a resource record set", example: "example.com. 300 IN RRSIG A 13 2 300 20250101000000 20240101000000 12345 example.com. base64sig...", security: "Validates record authenticity. Expiry must be monitored -- expired RRSIG causes SERVFAIL for validating resolvers." },
  { type: "NSEC", rfc: "4034", desc: "Next Secure record -- proves non-existence of a name in DNSSEC", example: "example.com. 86400 IN NSEC www.example.com. A AAAA NS SOA TXT", security: "Enables zone walking -- enumerating all records in a zone. NSEC3 (RFC 5155) uses hashed names to prevent this." },
  { type: "NSEC3", rfc: "5155", desc: "Hashed denial of existence for DNSSEC -- prevents zone enumeration", example: "hash.example.com. 86400 IN NSEC3 1 0 10 AABB hash2 A AAAA", security: "Preferred over NSEC to prevent zone walking. Use sufficient iterations and random salt." },
  { type: "TLSA", rfc: "6698", desc: "DANE TLS Authentication -- binds TLS certificate to DNS name", example: "_443._tcp.example.com. 300 IN TLSA 3 1 1 sha256hash...", security: "Pins TLS certificate via DNS (requires DNSSEC). Prevents CA compromise attacks. Alternative to HPKP." },
  { type: "SSHFP", rfc: "4255", desc: "SSH Fingerprint -- publishes SSH host key fingerprint in DNS", example: "host.example.com. 300 IN SSHFP 2 1 sha1fingerprint...", security: "Validates SSH host key via DNSSEC-signed DNS. Prevents SSH MITM attacks on first connection." },
  { type: "NAPTR", rfc: "3403", desc: "Naming Authority Pointer -- used in SIP/ENUM for service discovery", example: "example.com. 300 IN NAPTR 100 10 \"u\" \"E2U+sip\" \"!^.*$!sip:info@example.com!\" .", security: "Reveals telephony and SIP infrastructure. Used in VoIP service discovery." },
  { type: "LOC", rfc: "1876", desc: "Geographic location of a host", example: "example.com. 300 IN LOC 37 46 30.000 N 122 25 10.000 W 0.00m", security: "Reveals physical location of infrastructure. Rarely used, but can leak facility locations." },
  { type: "HINFO", rfc: "1035", desc: "Host information -- CPU and OS type", example: 'example.com. 300 IN HINFO "INTEL-386" "LINUX"', security: "Reveals OS and hardware information to attackers. Deprecated in practice but still queryable." },
  { type: "RP", rfc: "1183", desc: "Responsible Person -- email contact for the domain", example: "example.com. 300 IN RP admin.example.com. .", security: "Can reveal administrator email addresses for social engineering." },
];

const DNS_ATTACKS = [
  { name: "DNS Cache Poisoning (Kaminsky Attack)", desc: "Flood recursive resolver with forged responses to poison its cache, redirecting users to attacker-controlled servers. Kaminsky's 2008 disclosure showed any resolver could be targeted by racing the response with a forged additional-section record.", mitre: "T1584.002", tools: ["dnsspoof", "Ettercap", "bettercap"], prevention: ["Source port randomization (RFC 5452)", "DNSSEC validation", "DNS-over-HTTPS/TLS", "Restrict recursive resolvers to internal clients"], detection: ["Monitor for DNS responses from unexpected sources", "Alert on cache poisoning indicators (unexpected TTL changes)", "DNSSEC validation failures"] },
  { name: "DNS Amplification DDoS", desc: "Send DNS queries with a spoofed source IP (the victim) to open resolvers. The response is much larger than the query (amplification factor 28-54x for ANY queries), flooding the victim with traffic.", mitre: "T1498.002", tools: ["Scapy", "hping3", "custom UDP tools"], prevention: ["Block open resolvers on your network", "Implement BCP38 (ingress filtering)", "Rate limit DNS responses", "Disable ANY query type"], detection: ["Spike in inbound DNS responses", "High volume of DNS traffic from many sources", "UDP flood alerts on firewall"] },
  { name: "DNS Tunneling", desc: "Encode data in DNS queries and responses (using TXT, NULL, or CNAME records) to create a covert communication channel that bypasses most firewalls and content filters.", mitre: "T1071.004", tools: ["iodine", "dnscat2", "DNSExfiltrator", "Cobalt Strike DNS beacon"], prevention: ["DNS monitoring and anomaly detection", "Block direct DNS to external resolvers", "Inspect DNS query patterns for high entropy", "Limit TXT record response sizes"], detection: ["Unusually long DNS queries (>52 chars)", "High volume of DNS queries to single domain", "TXT/NULL record queries to non-standard domains", "High entropy in DNS labels"] },
  { name: "DNS Rebinding", desc: "Serve a web page that initially resolves to attacker's IP, then change DNS to resolve to victim's internal IP (e.g., 192.168.1.1). Browser's same-origin policy treats both as same origin, allowing the page to access internal services.", mitre: "T1557", tools: ["Singularity of Origin", "rbndr.us", "whonow"], prevention: ["DNS pinning in applications", "Validate Host header on web servers", "Network segmentation", "Block external DNS resolving to internal IPs"], detection: ["DNS responses with internal IP addresses from external domains", "Rapid DNS TTL changes", "Multiple A records with public and private IPs"] },
  { name: "Subdomain Takeover", desc: "When a CNAME points to a decommissioned third-party service (S3 bucket, Heroku app, GitHub Pages, Azure, Shopify), an attacker can claim that resource and serve content on the victim's subdomain.", mitre: "T1584.001", tools: ["Subjack", "SubOver", "can-i-take-over-xyz", "nuclei"], prevention: ["Audit and remove dangling CNAMEs", "Monitor subdomain DNS changes", "Use wildcard DNS with caution", "Check CNAME targets before decommissioning services"], detection: ["Regular CNAME audit against known vulnerable services", "Certificate Transparency monitoring", "HTTP response monitoring for unexpected content"] },
  { name: "Zone Transfer (AXFR)", desc: "If a DNS server allows zone transfers to unauthorized clients, an attacker can download the entire zone file, revealing all subdomains, IPs, mail servers, and other records.", mitre: "T1590.002", tools: ["dig AXFR", "dnsrecon", "fierce", "dnsenum"], prevention: ["Restrict AXFR to authorized secondary nameservers only", "Use TSIG authentication for zone transfers", "Firewall port 53 TCP to authorized IPs", "Monitor for unauthorized AXFR attempts"], detection: ["TCP port 53 connections from unauthorized IPs", "Zone transfer log entries", "Large DNS responses (full zone data)"] },
  { name: "NXDOMAIN Attack", desc: "Flood recursive resolver with queries for non-existent domains, overwhelming its cache and upstream authoritative servers. Causes legitimate queries to time out or fail.", mitre: "T1498", tools: ["Custom flooding scripts", "DNS stress tools"], prevention: ["Aggressive negative caching", "Rate limiting per client", "Response Rate Limiting (RRL) on authoritative servers", "NXDOMAIN redirect/sinkhole"], detection: ["Spike in NXDOMAIN responses", "Single source generating many unique queries", "Resolver CPU/memory spike"] },
  { name: "Phantom Domain Attack", desc: "Register domains with nameservers that never respond or respond very slowly. Recursive resolvers waste resources waiting for these responses, degrading performance.", mitre: "T1498", tools: ["Custom slow DNS servers"], prevention: ["Aggressive query timeouts on recursive resolvers", "Limit outstanding queries per domain", "Resolver resource monitoring"], detection: ["High number of pending DNS queries", "Resolver response time degradation", "Queries timing out to specific domains"] },
  { name: "Random Subdomain Attack (Water Torture)", desc: "Query random subdomains of a target domain (abc123.target.com), bypassing cache since each query is unique. Overwhelms the authoritative server for the target domain.", mitre: "T1498", tools: ["Custom query generators"], prevention: ["Rate limiting on authoritative servers", "Anycast DNS distribution", "DNS firewall/scrubbing service", "Response Rate Limiting"], detection: ["Many queries for random subdomains of same domain", "Authoritative server load spike", "NXDOMAIN spike for single parent domain"] },
  { name: "Typosquatting", desc: "Register domains similar to the target (gooogle.com, darkn0de.ai) to catch typos. Serve phishing pages, malware, or ad farms. Often combined with homograph attacks using Unicode characters.", mitre: "T1583.001", tools: ["dnstwist", "URLCrazy", "CatPhish", "Typo generator"], prevention: ["Register common typo domains defensively", "Monitor for typosquat registrations (dnstwist)", "DMARC/DKIM to prevent email spoofing from typosquats", "Browser typo protection extensions"], detection: ["New domain registrations similar to your brand", "Certificate Transparency logs for lookalike domains", "User reports of suspicious sites"] },
  { name: "DNS Hijacking", desc: "Compromise DNS infrastructure (registrar account, authoritative server, or resolver) to redirect DNS queries. Can redirect all traffic for a domain to attacker infrastructure.", mitre: "T1584.002", tools: ["Registrar account compromise", "Router DNS settings modification"], prevention: ["Registrar account MFA and lock", "DNSSEC to detect tampering", "Monitor DNS resolution from external vantage points", "Use registry lock (serverTransferProhibited)"], detection: ["DNS resolution returning unexpected IPs", "DNSSEC validation failures", "Registrar change notifications", "Certificate mismatch alerts"] },
  { name: "BGP Hijacking for DNS", desc: "Announce BGP routes for IP prefixes containing authoritative DNS servers. Traffic to those servers is routed through attacker infrastructure, enabling DNS manipulation at scale.", mitre: "T1557", tools: ["BGP route injection"], prevention: ["RPKI Route Origin Validation", "BGP monitoring services", "Multiple authoritative DNS providers in different ASNs", "DNSSEC (detects tampered responses)"], detection: ["BGP route announcements for DNS server prefixes", "Route path changes for DNS infrastructure", "RPKI invalid announcements"] },
];

const SUBDOMAINS = [
  "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote", "vpn", "gateway",
  "ns1", "ns2", "ns3", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
  "api", "api2", "api3", "rest", "graphql", "ws", "websocket", "grpc",
  "dev", "staging", "stage", "test", "testing", "qa", "uat", "sandbox", "demo",
  "admin", "panel", "dashboard", "console", "manage", "portal", "cp", "cpanel",
  "app", "apps", "mobile", "m", "beta", "alpha", "preview", "canary",
  "blog", "news", "forum", "community", "wiki", "docs", "documentation", "help", "support",
  "shop", "store", "pay", "payment", "billing", "checkout", "cart",
  "cdn", "static", "assets", "media", "images", "img", "files", "upload", "download",
  "db", "database", "mysql", "postgres", "mongo", "redis", "elastic", "elasticsearch", "kibana",
  "ci", "cd", "jenkins", "gitlab", "github", "bitbucket", "build", "deploy", "release",
  "monitor", "grafana", "prometheus", "nagios", "zabbix", "status", "health", "metrics",
  "auth", "login", "sso", "oauth", "identity", "id", "accounts", "signup", "register",
  "git", "svn", "repo", "repository", "code", "src", "source",
  "backup", "bak", "old", "legacy", "archive", "temp", "tmp",
  "internal", "intranet", "corp", "corporate", "office", "hq",
  "proxy", "cache", "lb", "loadbalancer", "edge", "node", "cluster",
  "aws", "azure", "gcp", "cloud", "s3", "bucket",
  "jira", "confluence", "slack", "teams", "zoom",
  "crm", "erp", "hr", "finance",
  "smtp", "pop3", "imap", "exchange", "owa",
  "vpn", "ssl", "secure", "waf",
  "siem", "log", "logs", "syslog", "splunk",
  "k8s", "kubernetes", "docker", "container", "registry",
  "phpmyadmin", "adminer", "pgadmin", "webmin",
  "autodiscover", "autoconfig", "lyncdiscover",
  "ns", "nameserver", "resolver",
  "dev1", "dev2", "test1", "test2", "prod", "production",
  "web", "web1", "web2", "www1", "www2",
  "srv", "server", "host", "node1", "node2",
  "data", "analytics", "bi", "reports", "reporting",
  "chat", "messaging", "notify", "notifications",
  "search", "solr", "sphinx",
  "video", "stream", "live", "rtmp",
  "email", "mailer", "newsletter", "postfix",
  "iot", "mqtt", "sensor",
  "devops", "infra", "infrastructure", "ops",
  "sec", "security", "pentest", "scan",
];

const WHOIS_FIELDS = [
  { field: "Domain Name", desc: "The registered domain name", security: "Verify you are querying the correct domain" },
  { field: "Registry Domain ID", desc: "Unique identifier assigned by the registry", security: "Can be used to track domain across registrar changes" },
  { field: "Registrar WHOIS Server", desc: "The registrar's WHOIS server for detailed information", security: "Query this for complete registration details" },
  { field: "Registrar URL", desc: "Website of the domain registrar", security: "Verify registrar legitimacy" },
  { field: "Updated Date", desc: "Last time the registration was modified", security: "Recent changes may indicate account compromise or transfer" },
  { field: "Creation Date", desc: "When the domain was first registered", security: "New domains (< 30 days) are higher risk for phishing/malware. Domain age is a trust signal." },
  { field: "Registry Expiry Date", desc: "When the registration expires", security: "Expiring domains are targets for registration hijacking" },
  { field: "Registrar", desc: "Company managing the domain registration", security: "Some registrars are preferred by threat actors due to lax policies" },
  { field: "Domain Status", desc: "EPP status codes indicating transfer/update restrictions", security: "clientTransferProhibited prevents unauthorized transfers. serverTransferProhibited is registry-level lock. Missing locks indicate vulnerability." },
  { field: "Name Server", desc: "Authoritative DNS servers for the domain", security: "Changes in nameservers may indicate DNS hijacking" },
  { field: "DNSSEC", desc: "Whether DNSSEC is configured", security: "Unsigned domains are vulnerable to DNS spoofing attacks" },
  { field: "Registrant Organization", desc: "Organization that registered the domain", security: "Privacy services (e.g., WhoisGuard) hide this -- common for both legitimate privacy and malicious intent" },
  { field: "Registrant Country", desc: "Country of the registrant", security: "Cross-reference with expected origin. Unexpected countries may indicate compromise." },
];

const DOH_PROVIDERS = [
  { name: "Cloudflare", url: "https://1.1.1.1/dns-query", ip: "1.1.1.1, 1.0.0.1", privacy: "No logging of identifying data. Purges logs within 24 hours.", features: "Malware blocking (1.1.1.2), Family filter (1.1.1.3)" },
  { name: "Google Public DNS", url: "https://dns.google/dns-query", ip: "8.8.8.8, 8.8.4.4", privacy: "Temporary logs with partial IP. Full logs deleted within 48 hours.", features: "DNSSEC validation, ECS support" },
  { name: "Quad9", url: "https://dns.quad9.net/dns-query", ip: "9.9.9.9, 149.112.112.112", privacy: "No logging of source IP. Swiss privacy jurisdiction.", features: "Threat intelligence blocking, DNSSEC validation" },
  { name: "NextDNS", url: "https://dns.nextdns.io", ip: "Varies per account", privacy: "Configurable logging. Optional zero-log mode.", features: "Custom blocklists, analytics, per-device policies" },
  { name: "AdGuard DNS", url: "https://dns.adguard.com/dns-query", ip: "94.140.14.14, 94.140.15.15", privacy: "Anonymous aggregate statistics only.", features: "Ad blocking, tracker blocking, family protection mode" },
  { name: "Mullvad DNS", url: "https://dns.mullvad.net/dns-query", ip: "194.242.2.2", privacy: "No logging. Swedish jurisdiction.", features: "Ad/tracker blocking, DNSSEC validation" },
];

const DNS_MISCONFIGS = [
  { name: "Open Resolver", desc: "DNS server responds to recursive queries from any source IP on the internet", risk: "Can be abused for DNS amplification DDoS attacks and cache poisoning", fix: "Restrict recursion to internal networks. Set 'allow-recursion' in BIND or equivalent." },
  { name: "Zone Transfer Allowed (AXFR)", desc: "Authoritative server allows zone transfers to any client", risk: "Exposes complete zone data including all subdomains and internal infrastructure", fix: "Restrict AXFR to authorized secondary nameservers. Use TSIG authentication." },
  { name: "Missing CAA Record", desc: "No Certificate Authority Authorization record set", risk: "Any CA can issue certificates for your domain, enabling potential MITM after CA compromise", fix: "Add CAA record specifying authorized CAs: example.com. CAA 0 issue \"letsencrypt.org\"" },
  { name: "Missing SPF Record", desc: "No SPF TXT record to authorize mail senders", risk: "Anyone can send email appearing to come from your domain (spoofing)", fix: "Add SPF record: example.com. TXT \"v=spf1 include:_spf.google.com -all\"" },
  { name: "Missing DMARC Record", desc: "No DMARC policy to enforce email authentication", risk: "Even with SPF/DKIM, no policy enforcement means spoofed emails may still be delivered", fix: "Add DMARC record: _dmarc.example.com. TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@example.com\"" },
  { name: "SPF with ~all (SoftFail)", desc: "SPF record uses ~all instead of -all", risk: "Emails failing SPF may still be delivered (softfail is not enforced by all receivers)", fix: "Change ~all to -all once all legitimate senders are listed" },
  { name: "Wildcard DNS Record", desc: "Wildcard A or CNAME record (*.example.com) resolves all subdomains", risk: "Prevents subdomain takeover detection. Any subdomain resolves, hiding misconfigured services.", fix: "Remove wildcard records. Explicitly define needed subdomains." },
  { name: "Dangling CNAME", desc: "CNAME pointing to a decommissioned service (S3, Heroku, Azure, etc.)", risk: "Subdomain takeover -- attacker claims the decommissioned resource and controls your subdomain", fix: "Remove CNAME records when decommissioning services. Regular CNAME audit." },
  { name: "No DNSSEC", desc: "Domain is not signed with DNSSEC", risk: "DNS responses can be spoofed without detection. Cache poisoning attacks are feasible.", fix: "Enable DNSSEC signing at your DNS provider. Publish DS records in parent zone." },
  { name: "Low TTL on Critical Records", desc: "Very low TTL (< 60s) on A or NS records", risk: "Makes DNS hijacking faster since caches expire quickly. Also increases query load.", fix: "Use reasonable TTLs (300-3600s for A records, 86400 for NS/MX)" },
];

// ---- TABS AND RENDERING ----

var TABS = [
  { id: "records", label: "Record Types", render: renderRecordsTab },
  { id: "spf", label: "SPF Builder", render: renderSPFTab },
  { id: "dkim", label: "DKIM Builder", render: renderDKIMTab },
  { id: "dmarc", label: "DMARC Builder", render: renderDMARCTab },
  { id: "attacks", label: "DNS Attacks", render: renderAttacksTab },
  { id: "subdomains", label: "Subdomain Wordlist", render: renderSubdomainsTab },
  { id: "doh", label: "DoH/DoT Providers", render: renderDoHTab },
  { id: "whois", label: "WHOIS Reference", render: renderWhoisTab },
  { id: "misconfig", label: "Misconfigurations", render: renderMisconfigTab },
];

function renderRecordsTab(container) {
  var html = '<h2 class="pg-h2">DNS Record Types</h2>' +
    '<p class="muted" style="margin-bottom:12px">' + DNS_RECORDS.length + ' DNS record types with descriptions, examples, and security implications.</p>';
  for (var i = 0; i < DNS_RECORDS.length; i++) {
    var r = DNS_RECORDS[i];
    html += '<div class="dns-card">' +
      '<div class="dns-card-header">' +
        '<span class="dns-type">' + esc(r.type) + '</span>' +
        '<span class="dns-rfc">RFC ' + esc(r.rfc) + '</span>' +
      '</div>' +
      '<div class="dns-desc">' + esc(r.desc) + '</div>' +
      '<div class="dns-example"><code>' + esc(r.example) + '</code></div>' +
      '<div class="dns-security"><strong>Security:</strong> ' + esc(r.security) + '</div>' +
    '</div>';
  }
  container.innerHTML = html;
}

function renderSPFTab(container) {
  var html = '<h2 class="pg-h2">SPF Record Builder</h2>' +
    '<p class="muted" style="margin-bottom:12px">Build a Sender Policy Framework record to authorize your email senders and prevent spoofing.</p>' +
    '<div class="dns-builder">' +
      '<div class="dns-field"><label>Domain:</label><input id="spf-domain" class="dns-input" placeholder="example.com" value=""></div>' +
      '<div class="dns-field"><label>Include (third-party senders):</label>' +
        '<div id="spf-includes" class="dns-multi">' +
          '<div class="dns-multi-item"><input class="dns-input spf-include" placeholder="_spf.google.com" value="_spf.google.com"><button class="dns-rm" data-action="rm-spf-include">x</button></div>' +
        '</div>' +
        '<button class="btn sm ghost" id="spf-add-include">+ Add Include</button>' +
      '</div>' +
      '<div class="dns-field"><label>ip4 (allowed IPv4 addresses/ranges):</label>' +
        '<div id="spf-ip4s" class="dns-multi"></div>' +
        '<button class="btn sm ghost" id="spf-add-ip4">+ Add IPv4</button>' +
      '</div>' +
      '<div class="dns-field"><label>ip6 (allowed IPv6 addresses/ranges):</label>' +
        '<div id="spf-ip6s" class="dns-multi"></div>' +
        '<button class="btn sm ghost" id="spf-add-ip6">+ Add IPv6</button>' +
      '</div>' +
      '<div class="dns-field"><label>A record of domain itself sends mail:</label>' +
        '<input type="checkbox" id="spf-a"> Yes' +
      '</div>' +
      '<div class="dns-field"><label>MX records send mail:</label>' +
        '<input type="checkbox" id="spf-mx" checked> Yes' +
      '</div>' +
      '<div class="dns-field"><label>Policy for non-matching senders:</label>' +
        '<select id="spf-all" class="dns-input">' +
          '<option value="-all">-all (Fail -- reject)</option>' +
          '<option value="~all">~all (SoftFail -- mark but deliver)</option>' +
          '<option value="?all">?all (Neutral -- no policy)</option>' +
        '</select>' +
      '</div>' +
      '<button class="btn sm" id="spf-generate">Generate SPF Record</button>' +
      '<div class="dns-output" id="spf-output"></div>' +
    '</div>';
  container.innerHTML = html;

  container.querySelector('#spf-add-include').onclick = function() {
    var div = document.createElement('div'); div.className = 'dns-multi-item';
    div.innerHTML = '<input class="dns-input spf-include" placeholder="include domain"><button class="dns-rm" data-action="rm">x</button>';
    div.querySelector('.dns-rm').onclick = function() { div.remove(); };
    container.querySelector('#spf-includes').appendChild(div);
  };
  container.querySelector('#spf-add-ip4').onclick = function() {
    var div = document.createElement('div'); div.className = 'dns-multi-item';
    div.innerHTML = '<input class="dns-input spf-ip4" placeholder="192.168.1.0/24"><button class="dns-rm">x</button>';
    div.querySelector('.dns-rm').onclick = function() { div.remove(); };
    container.querySelector('#spf-ip4s').appendChild(div);
  };
  container.querySelector('#spf-add-ip6').onclick = function() {
    var div = document.createElement('div'); div.className = 'dns-multi-item';
    div.innerHTML = '<input class="dns-input spf-ip6" placeholder="2001:db8::/32"><button class="dns-rm">x</button>';
    div.querySelector('.dns-rm').onclick = function() { div.remove(); };
    container.querySelector('#spf-ip6s').appendChild(div);
  };
  container.querySelectorAll('.dns-rm').forEach(function(btn) {
    btn.onclick = function() { btn.closest('.dns-multi-item').remove(); };
  });

  container.querySelector('#spf-generate').onclick = function() {
    var parts = ["v=spf1"];
    if (container.querySelector('#spf-a').checked) parts.push("a");
    if (container.querySelector('#spf-mx').checked) parts.push("mx");
    container.querySelectorAll('.spf-include').forEach(function(inp) {
      var v = inp.value.trim(); if (v) parts.push("include:" + v);
    });
    container.querySelectorAll('.spf-ip4').forEach(function(inp) {
      var v = inp.value.trim(); if (v) parts.push("ip4:" + v);
    });
    container.querySelectorAll('.spf-ip6').forEach(function(inp) {
      var v = inp.value.trim(); if (v) parts.push("ip6:" + v);
    });
    parts.push(container.querySelector('#spf-all').value);
    var record = parts.join(" ");
    var domain = container.querySelector('#spf-domain').value.trim() || "example.com";
    container.querySelector('#spf-output').innerHTML =
      '<div class="dns-result-label">TXT Record:</div>' +
      '<code class="dns-result">' + esc(domain) + '. IN TXT "' + esc(record) + '"</code>' +
      '<div class="dns-result-label" style="margin-top:8px">DNS Entry (for your provider):</div>' +
      '<div class="dns-result-detail">Type: TXT | Name: @ | Value: ' + esc(record) + '</div>';
  };
}

function renderDKIMTab(container) {
  var html = '<h2 class="pg-h2">DKIM Record Builder</h2>' +
    '<p class="muted" style="margin-bottom:12px">DomainKeys Identified Mail signs outgoing emails with a cryptographic signature. The public key is published in DNS.</p>' +
    '<div class="dns-builder">' +
      '<div class="dns-field"><label>Selector (e.g., google, default, s1):</label><input id="dkim-selector" class="dns-input" placeholder="google" value="google"></div>' +
      '<div class="dns-field"><label>Domain:</label><input id="dkim-domain" class="dns-input" placeholder="example.com"></div>' +
      '<div class="dns-field"><label>Key type:</label><select id="dkim-keytype" class="dns-input"><option value="rsa">RSA</option><option value="ed25519">Ed25519</option></select></div>' +
      '<div class="dns-field"><label>Public key (base64, from your mail provider):</label><textarea id="dkim-key" class="dns-input" rows="3" placeholder="MIIBIjANBg..."></textarea></div>' +
      '<div class="dns-field"><label>Testing mode:</label><input type="checkbox" id="dkim-testing"> Yes (t=y -- advisory only, don\'t reject failures)</div>' +
      '<button class="btn sm" id="dkim-generate">Generate DKIM Record</button>' +
      '<div class="dns-output" id="dkim-output"></div>' +
    '</div>' +
    '<div class="dns-ref" style="margin-top:16px">' +
      '<h3>DKIM Tags Reference</h3>' +
      '<table class="dns-ref-table"><tr><th>Tag</th><th>Required</th><th>Description</th></tr>' +
      '<tr><td>v</td><td>Yes</td><td>Version (must be DKIM1)</td></tr>' +
      '<tr><td>k</td><td>No</td><td>Key type (rsa or ed25519, default: rsa)</td></tr>' +
      '<tr><td>p</td><td>Yes</td><td>Public key data (base64 encoded)</td></tr>' +
      '<tr><td>t</td><td>No</td><td>Flags: y = testing mode, s = strict (no subdomains)</td></tr>' +
      '<tr><td>s</td><td>No</td><td>Service type (* or email)</td></tr>' +
      '<tr><td>h</td><td>No</td><td>Hash algorithm (sha256)</td></tr>' +
      '<tr><td>n</td><td>No</td><td>Notes (human-readable)</td></tr>' +
      '</table></div>';
  container.innerHTML = html;

  container.querySelector('#dkim-generate').onclick = function() {
    var selector = container.querySelector('#dkim-selector').value.trim() || "default";
    var domain = container.querySelector('#dkim-domain').value.trim() || "example.com";
    var keytype = container.querySelector('#dkim-keytype').value;
    var key = container.querySelector('#dkim-key').value.trim().replace(/\s+/g, '');
    var testing = container.querySelector('#dkim-testing').checked;
    var parts = ["v=DKIM1"];
    if (keytype !== "rsa") parts.push("k=" + keytype);
    if (testing) parts.push("t=y");
    parts.push("p=" + (key || "YOUR_PUBLIC_KEY_HERE"));
    var record = parts.join("; ");
    container.querySelector('#dkim-output').innerHTML =
      '<div class="dns-result-label">TXT Record:</div>' +
      '<code class="dns-result">' + esc(selector) + '._domainkey.' + esc(domain) + '. IN TXT "' + esc(record) + '"</code>' +
      '<div class="dns-result-label" style="margin-top:8px">DNS Entry:</div>' +
      '<div class="dns-result-detail">Type: TXT | Name: ' + esc(selector) + '._domainkey | Value: ' + esc(record) + '</div>';
  };
}

function renderDMARCTab(container) {
  var html = '<h2 class="pg-h2">DMARC Record Builder</h2>' +
    '<p class="muted" style="margin-bottom:12px">DMARC tells receivers what to do with emails that fail SPF and DKIM checks.</p>' +
    '<div class="dns-builder">' +
      '<div class="dns-field"><label>Domain:</label><input id="dmarc-domain" class="dns-input" placeholder="example.com"></div>' +
      '<div class="dns-field"><label>Policy (p):</label><select id="dmarc-policy" class="dns-input">' +
        '<option value="reject">reject -- reject all failing emails</option>' +
        '<option value="quarantine">quarantine -- send to spam</option>' +
        '<option value="none">none -- monitor only (start here)</option></select></div>' +
      '<div class="dns-field"><label>Subdomain policy (sp):</label><select id="dmarc-sp" class="dns-input">' +
        '<option value="">Same as domain policy</option>' +
        '<option value="reject">reject</option>' +
        '<option value="quarantine">quarantine</option>' +
        '<option value="none">none</option></select></div>' +
      '<div class="dns-field"><label>Aggregate report email (rua):</label><input id="dmarc-rua" class="dns-input" placeholder="mailto:dmarc@example.com"></div>' +
      '<div class="dns-field"><label>Forensic report email (ruf):</label><input id="dmarc-ruf" class="dns-input" placeholder="mailto:dmarc-forensic@example.com"></div>' +
      '<div class="dns-field"><label>Percentage of messages to apply policy (pct):</label><input id="dmarc-pct" class="dns-input" type="number" min="1" max="100" value="100"></div>' +
      '<div class="dns-field"><label>SPF alignment (aspf):</label><select id="dmarc-aspf" class="dns-input"><option value="r">Relaxed (default)</option><option value="s">Strict</option></select></div>' +
      '<div class="dns-field"><label>DKIM alignment (adkim):</label><select id="dmarc-adkim" class="dns-input"><option value="r">Relaxed (default)</option><option value="s">Strict</option></select></div>' +
      '<button class="btn sm" id="dmarc-generate">Generate DMARC Record</button>' +
      '<div class="dns-output" id="dmarc-output"></div>' +
    '</div>';
  container.innerHTML = html;

  container.querySelector('#dmarc-generate').onclick = function() {
    var domain = container.querySelector('#dmarc-domain').value.trim() || "example.com";
    var parts = ["v=DMARC1"];
    parts.push("p=" + container.querySelector('#dmarc-policy').value);
    var sp = container.querySelector('#dmarc-sp').value;
    if (sp) parts.push("sp=" + sp);
    var rua = container.querySelector('#dmarc-rua').value.trim();
    if (rua) parts.push("rua=" + rua);
    var ruf = container.querySelector('#dmarc-ruf').value.trim();
    if (ruf) parts.push("ruf=" + ruf);
    var pct = container.querySelector('#dmarc-pct').value;
    if (pct && pct !== "100") parts.push("pct=" + pct);
    var aspf = container.querySelector('#dmarc-aspf').value;
    if (aspf === "s") parts.push("aspf=s");
    var adkim = container.querySelector('#dmarc-adkim').value;
    if (adkim === "s") parts.push("adkim=s");
    var record = parts.join("; ");
    container.querySelector('#dmarc-output').innerHTML =
      '<div class="dns-result-label">TXT Record:</div>' +
      '<code class="dns-result">_dmarc.' + esc(domain) + '. IN TXT "' + esc(record) + '"</code>' +
      '<div class="dns-result-label" style="margin-top:8px">DNS Entry:</div>' +
      '<div class="dns-result-detail">Type: TXT | Name: _dmarc | Value: ' + esc(record) + '</div>';
  };
}

function renderAttacksTab(container) {
  var html = '<h2 class="pg-h2">DNS Attack Reference</h2>' +
    '<p class="muted" style="margin-bottom:12px">' + DNS_ATTACKS.length + ' DNS attack techniques with tools, detection, and prevention.</p>';
  for (var i = 0; i < DNS_ATTACKS.length; i++) {
    var a = DNS_ATTACKS[i];
    html += '<div class="dns-card">' +
      '<div class="dns-card-header"><span class="dns-atk-name">' + esc(a.name) + '</span><span class="dns-mitre">' + esc(a.mitre) + '</span></div>' +
      '<div class="dns-desc">' + esc(a.desc) + '</div>' +
      '<div class="dns-tools"><strong>Tools:</strong> ' + a.tools.map(function(t) { return esc(t); }).join(", ") + '</div>' +
      '<div class="dns-prevention"><strong>Prevention:</strong><ul>' + a.prevention.map(function(p) { return '<li>' + esc(p) + '</li>'; }).join("") + '</ul></div>' +
      '<div class="dns-detection"><strong>Detection:</strong><ul>' + a.detection.map(function(d) { return '<li>' + esc(d) + '</li>'; }).join("") + '</ul></div>' +
    '</div>';
  }
  container.innerHTML = html;
}

function renderSubdomainsTab(container) {
  var html = '<h2 class="pg-h2">Subdomain Enumeration Wordlist</h2>' +
    '<p class="muted" style="margin-bottom:12px">' + SUBDOMAINS.length + ' common subdomains for discovery and enumeration.</p>' +
    '<div class="dns-field"><label>Filter:</label><input id="sub-filter" class="dns-input" placeholder="Search subdomains..."></div>' +
    '<button class="btn sm" id="sub-copy">Copy All to Clipboard</button>' +
    '<pre class="tk-out" id="sub-list" style="margin-top:8px;max-height:400px;overflow-y:auto">' + SUBDOMAINS.join("\n") + '</pre>';
  container.innerHTML = html;

  container.querySelector('#sub-filter').oninput = function() {
    var q = this.value.toLowerCase();
    var filtered = SUBDOMAINS.filter(function(s) { return s.indexOf(q) >= 0; });
    container.querySelector('#sub-list').textContent = filtered.join("\n");
  };
  container.querySelector('#sub-copy').onclick = function() {
    navigator.clipboard.writeText(SUBDOMAINS.join("\n")).then(function() {
      container.querySelector('#sub-copy').textContent = "Copied";
      setTimeout(function() { container.querySelector('#sub-copy').textContent = "Copy All to Clipboard"; }, 2000);
    });
  };
}

function renderDoHTab(container) {
  var html = '<h2 class="pg-h2">DNS over HTTPS / TLS Providers</h2>' +
    '<p class="muted" style="margin-bottom:12px">Encrypted DNS prevents eavesdropping and manipulation of DNS queries by network observers.</p>';
  for (var i = 0; i < DOH_PROVIDERS.length; i++) {
    var p = DOH_PROVIDERS[i];
    html += '<div class="dns-card">' +
      '<div class="dns-card-header"><span class="dns-type">' + esc(p.name) + '</span></div>' +
      '<div class="dns-field-row"><strong>DoH URL:</strong> <code>' + esc(p.url) + '</code></div>' +
      '<div class="dns-field-row"><strong>IP Addresses:</strong> ' + esc(p.ip) + '</div>' +
      '<div class="dns-field-row"><strong>Privacy:</strong> ' + esc(p.privacy) + '</div>' +
      '<div class="dns-field-row"><strong>Features:</strong> ' + esc(p.features) + '</div>' +
    '</div>';
  }
  container.innerHTML = html;
}

function renderWhoisTab(container) {
  var html = '<h2 class="pg-h2">WHOIS Field Reference</h2>' +
    '<p class="muted" style="margin-bottom:12px">Understanding WHOIS output for domain investigation.</p>' +
    '<table class="dns-ref-table"><tr><th>Field</th><th>Description</th><th>Security Relevance</th></tr>';
  for (var i = 0; i < WHOIS_FIELDS.length; i++) {
    var w = WHOIS_FIELDS[i];
    html += '<tr><td>' + esc(w.field) + '</td><td>' + esc(w.desc) + '</td><td>' + esc(w.security) + '</td></tr>';
  }
  html += '</table>';

  html += '<h3 style="margin-top:16px">Domain Age Calculator</h3>' +
    '<div class="dns-field"><label>Registration date:</label><input type="date" id="whois-date" class="dns-input"></div>' +
    '<button class="btn sm" id="whois-calc">Calculate Age</button>' +
    '<div id="whois-result" class="dns-output"></div>';
  container.innerHTML = html;

  container.querySelector('#whois-calc').onclick = function() {
    var d = container.querySelector('#whois-date').value;
    if (!d) return;
    var reg = new Date(d);
    var now = new Date();
    var diff = now - reg;
    var days = Math.floor(diff / 86400000);
    var years = Math.floor(days / 365);
    var rem = days % 365;
    var risk = days < 30 ? "HIGH RISK" : days < 365 ? "Moderate risk" : "Low risk";
    var riskColor = days < 30 ? "#ef4444" : days < 365 ? "#f59e0b" : "#22c55e";
    container.querySelector('#whois-result').innerHTML =
      '<div>Domain age: <strong>' + years + ' years, ' + rem + ' days</strong> (' + days + ' total days)</div>' +
      '<div style="color:' + riskColor + ';font-weight:600;margin-top:4px">' + risk + '</div>';
  };
}

function renderMisconfigTab(container) {
  var html = '<h2 class="pg-h2">Common DNS Misconfigurations</h2>' +
    '<p class="muted" style="margin-bottom:12px">Security issues found in DNS configurations and how to fix them.</p>';
  for (var i = 0; i < DNS_MISCONFIGS.length; i++) {
    var m = DNS_MISCONFIGS[i];
    html += '<div class="dns-card">' +
      '<div class="dns-atk-name">' + esc(m.name) + '</div>' +
      '<div class="dns-desc">' + esc(m.desc) + '</div>' +
      '<div class="dns-risk"><strong>Risk:</strong> ' + esc(m.risk) + '</div>' +
      '<div class="dns-fix"><strong>Fix:</strong> ' + esc(m.fix) + '</div>' +
    '</div>';
  }
  container.innerHTML = html;
}

// ---- STYLES ----

var STYLE = '<style>' +
  '.dns-card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;margin-bottom:8px}' +
  '.dns-card-header{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}' +
  '.dns-type{font-family:var(--mono);font-size:.82rem;font-weight:700;color:var(--acc);background:var(--acc-soft,rgba(0,212,255,.1));padding:2px 10px;border-radius:4px}' +
  '.dns-rfc{font-size:.7rem;color:var(--mut)}' +
  '.dns-atk-name{font-weight:600;font-size:.9rem}' +
  '.dns-mitre{font-family:var(--mono);font-size:.72rem;color:var(--acc)}' +
  '.dns-desc{font-size:.82rem;color:var(--mut);line-height:1.5;margin-bottom:6px}' +
  '.dns-example{background:var(--card2,#111);border:1px solid var(--line);border-radius:4px;padding:6px 10px;margin-bottom:6px;overflow-x:auto}' +
  '.dns-example code{font-size:.75rem;color:var(--acc);white-space:pre}' +
  '.dns-security,.dns-tools,.dns-prevention,.dns-detection,.dns-risk,.dns-fix{font-size:.8rem;line-height:1.5;margin-bottom:4px}' +
  '.dns-security strong,.dns-tools strong,.dns-prevention strong,.dns-detection strong,.dns-risk strong,.dns-fix strong{color:var(--acc)}' +
  '.dns-prevention ul,.dns-detection ul{margin:4px 0 0 16px;padding:0}' +
  '.dns-prevention li,.dns-detection li{margin-bottom:2px}' +
  '.dns-builder{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px}' +
  '.dns-field{margin-bottom:10px}' +
  '.dns-field label{display:block;font-size:.78rem;color:var(--mut);margin-bottom:4px;font-weight:500}' +
  '.dns-input{background:var(--card2,#111);border:1px solid var(--line);color:var(--txt);padding:6px 10px;border-radius:4px;font-size:.8rem;font-family:inherit;width:100%;box-sizing:border-box}' +
  '.dns-input:focus{border-color:var(--acc);outline:none}' +
  'select.dns-input{width:auto;min-width:200px}' +
  '.dns-multi{display:flex;flex-direction:column;gap:4px;margin-bottom:4px}' +
  '.dns-multi-item{display:flex;gap:4px;align-items:center}' +
  '.dns-multi-item .dns-input{flex:1}' +
  '.dns-rm{background:transparent;border:1px solid var(--line);color:var(--mut);width:28px;height:28px;border-radius:4px;cursor:pointer;font-size:.8rem}' +
  '.dns-rm:hover{border-color:var(--bad,#ef4444);color:var(--bad,#ef4444)}' +
  '.dns-output{margin-top:12px;padding:12px;background:var(--card2,#111);border:1px solid var(--line);border-radius:6px}' +
  '.dns-result-label{font-size:.72rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px}' +
  '.dns-result{display:block;font-size:.82rem;color:var(--acc);word-break:break-all}' +
  '.dns-result-detail{font-size:.78rem;color:var(--txt);font-family:var(--mono)}' +
  '.dns-field-row{font-size:.82rem;margin-bottom:4px;line-height:1.4}' +
  '.dns-field-row code{color:var(--acc);font-size:.78rem}' +
  '.dns-ref-table{width:100%;border-collapse:collapse;font-size:.78rem}' +
  '.dns-ref-table th,.dns-ref-table td{padding:6px 8px;border:1px solid var(--line);text-align:left}' +
  '.dns-ref-table th{background:var(--card);font-weight:600}' +
  '.dns-ref-table tr:nth-child(even){background:var(--card)}' +
'</style>';

export function renderDNSToolkit(main) {
  main.innerHTML = STYLE +
    '<h1 class="pg-h1">DNS Toolkit</h1>' +
    '<p class="muted pg-sub">DNS analysis, record building, attack reference, and email security configuration.</p>' +
    '<div class="tool-intro">' +
      '<h2>DNS Toolkit</h2>' +
      '<p>Performs comprehensive DNS lookups on any domain. See all record types, check email security (SPF/DKIM/DMARC), and discover subdomains.</p>' +
      '<div class="tool-steps">' +
        '<div class="tool-step"><span class="step-num">1</span><div class="step-text"><strong>Enter a domain name</strong>Type a domain like example.com to analyze</div></div>' +
        '<div class="tool-step"><span class="step-num">2</span><div class="step-text"><strong>Choose the lookup type</strong>Pick a tab: Records, SPF Builder, DKIM, DMARC, Attacks, or Subdomains</div></div>' +
        '<div class="tool-step"><span class="step-num">3</span><div class="step-text"><strong>View the results</strong>See DNS records, security configs, and recommendations</div></div>' +
      '</div>' +
    '</div>' +
    '<div class="tab-bar" id="dns-tabs" style="flex-wrap:wrap">' +
      TABS.map(function(t, i) { return '<button class="tab' + (i === 0 ? ' active' : '') + '" data-tab="' + t.id + '">' + t.label + '</button>'; }).join('') +
    '</div>' +
    '<div id="dns-content"></div>';

  var tabBar = main.querySelector('#dns-tabs');
  var content = main.querySelector('#dns-content');

  function switchTab(tabId) {
    tabBar.querySelectorAll('.tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === tabId); });
    var tab = TABS.find(function(t) { return t.id === tabId; });
    if (tab) { content.innerHTML = ''; tab.render(content); }
  }

  tabBar.onclick = function(e) {
    var btn = e.target.closest('.tab');
    if (btn) switchTab(btn.dataset.tab);
  };

  switchTab('records');
}
