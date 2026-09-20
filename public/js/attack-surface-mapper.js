// Attack Surface Mapper — See Your Org Like an Attacker Sees It
// Maps an organization's external attack surface from the attacker's perspective.
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// =============================================================================
// DNS RECORD REFERENCE — what each record type reveals to attackers
// =============================================================================
const DNS_RECORDS = [
  { type: 'A', desc: 'Maps hostname to IPv4 address', risk: 'Reveals server IP, enables direct scanning and geolocation', attackUse: 'Port scanning, fingerprinting hosting provider, identifying co-hosted sites via reverse DNS', remediation: 'Use a CDN/proxy (Cloudflare, AWS CloudFront) to hide origin IP' },
  { type: 'AAAA', desc: 'Maps hostname to IPv6 address', risk: 'IPv6 may bypass IPv4-only security controls', attackUse: 'Some WAFs/firewalls only filter IPv4 — IPv6 can be an alternate path', remediation: 'Apply same security controls to IPv6 as IPv4, or disable IPv6 if unused' },
  { type: 'CNAME', desc: 'Canonical name alias to another domain', risk: 'Reveals third-party services, enables subdomain takeover if target is decommissioned', attackUse: 'Identify SaaS providers, find dangling CNAMEs for subdomain takeover', remediation: 'Audit CNAMEs regularly, remove records pointing to decommissioned services' },
  { type: 'MX', desc: 'Mail exchange servers', risk: 'Identifies email infrastructure, enables targeted phishing', attackUse: 'Determine email provider (Google Workspace, O365, on-prem), target mail server vulns', remediation: 'Use cloud email with strong SPF/DKIM/DMARC, don\'t expose on-prem mail servers' },
  { type: 'TXT', desc: 'Arbitrary text records (SPF, DKIM, verification)', risk: 'Leaks SPF includes (reveals email infrastructure), verification tokens reveal services used', attackUse: 'Map all third-party services via verification TXT records (google-site-verification, MS=, atlassian-domain-verification)', remediation: 'Remove old verification records, minimize SPF includes' },
  { type: 'NS', desc: 'Authoritative nameservers', risk: 'Reveals DNS hosting provider, enables DNS-specific attacks', attackUse: 'Target DNS provider for cache poisoning, check for zone transfer (AXFR)', remediation: 'Use reputable DNS hosting with DNSSEC enabled' },
  { type: 'SOA', desc: 'Start of Authority — zone admin info', risk: 'May leak admin email address and zone serial numbering scheme', attackUse: 'Admin email for social engineering, serial numbers reveal update frequency', remediation: 'Use generic admin email (dns-admin@), not personal addresses' },
  { type: 'SRV', desc: 'Service location records', risk: 'Reveals internal services (LDAP, SIP, XMPP, Kerberos)', attackUse: 'Map internal service architecture from external DNS', remediation: 'Don\'t publish internal SRV records in public DNS' },
  { type: 'PTR', desc: 'Reverse DNS — IP to hostname', risk: 'Reveals hostnames and naming conventions', attackUse: 'Map IP ranges to hostnames, discover internal naming scheme (srv-db-01, etc.)', remediation: 'Use generic PTR records that don\'t reveal server roles' },
  { type: 'CAA', desc: 'Certificate Authority Authorization', risk: 'Shows which CAs can issue certs — absence means any CA can', attackUse: 'No CAA = attacker can get a valid cert from any CA for your domain', remediation: 'Set CAA records restricting to your CA (e.g., letsencrypt.org)' },
  { type: 'DMARC', desc: 'Email authentication policy (p=none/quarantine/reject)', risk: 'p=none means spoofed emails are delivered — phishing is trivial', attackUse: 'Check if domain can be spoofed for phishing campaigns', remediation: 'Set DMARC to p=reject with rua/ruf reporting' },
  { type: 'SPF', desc: 'Sender Policy Framework — authorized mail senders', risk: 'Overly permissive SPF (+all, too many includes) enables spoofing', attackUse: 'If SPF is missing or weak, spoof emails from the domain', remediation: 'Strict SPF with -all, minimize includes, use ~all only during testing' },
  { type: 'DKIM', desc: 'DomainKeys Identified Mail — email signing', risk: 'Missing DKIM means email integrity can\'t be verified', attackUse: 'Without DKIM, spoofed emails pass through more filters', remediation: 'Configure DKIM with 2048-bit keys, rotate annually' },
];

// =============================================================================
// TECHNOLOGY FINGERPRINTING — how attackers ID your stack
// =============================================================================
const TECH_FINGERPRINTS = [
  { category: 'HTTP Headers', techniques: [
    { name: 'Server header', desc: 'Server: Apache/2.4.49 reveals exact version', risk: 'high', fix: 'Set ServerTokens Prod (Apache) or server_tokens off (nginx)' },
    { name: 'X-Powered-By', desc: 'X-Powered-By: PHP/7.4.3 reveals language and version', risk: 'high', fix: 'Remove header: Header unset X-Powered-By (Apache) or fastcgi_hide_header (nginx)' },
    { name: 'X-AspNet-Version', desc: 'Reveals .NET framework version', risk: 'medium', fix: 'Set enableVersionHeader="false" in web.config' },
    { name: 'X-Generator', desc: 'Used by CMSs (WordPress, Drupal, Joomla)', risk: 'medium', fix: 'Remove via CMS security plugin or theme functions' },
    { name: 'Set-Cookie names', desc: 'JSESSIONID=Java, PHPSESSID=PHP, ASP.NET_SessionId=.NET, connect.sid=Node/Express, _rails_session=Ruby on Rails', risk: 'medium', fix: 'Rename default session cookies to generic names' },
    { name: 'X-Request-ID format', desc: 'UUID format can identify framework (Heroku, Rails, Express)', risk: 'low', fix: 'Use generic format or remove header' },
  ]},
  { category: 'HTML/DOM Clues', techniques: [
    { name: 'Meta generator tag', desc: '<meta name="generator" content="WordPress 6.4"> in page source', risk: 'high', fix: 'Remove generator meta tag via theme or plugin' },
    { name: 'HTML comments', desc: '<!-- Built with React 18 --> or <!-- Powered by Shopify -->', risk: 'medium', fix: 'Strip HTML comments in production builds' },
    { name: 'CSS/JS file paths', desc: '/wp-content/themes/ (WordPress), /sites/default/files/ (Drupal), /static/js/main.chunk.js (React CRA)', risk: 'medium', fix: 'Rename default paths, use build tool to obfuscate' },
    { name: 'Error pages', desc: 'Default 404/500 pages reveal framework (Tomcat, Django, Rails, Spring)', risk: 'high', fix: 'Custom error pages that don\'t reveal stack info' },
    { name: 'Form hidden fields', desc: '__VIEWSTATE (.NET), csrf_token naming conventions', risk: 'low', fix: 'Rename CSRF tokens to generic names' },
    { name: 'JavaScript globals', desc: 'window.__NEXT_DATA__ (Next.js), window.__NUXT__ (Nuxt), angular.version', risk: 'medium', fix: 'Remove debug globals in production' },
  ]},
  { category: 'URL Patterns', techniques: [
    { name: 'Admin paths', desc: '/wp-admin/ (WordPress), /admin/ (Django), /administrator/ (Joomla), /user/login (Drupal)', risk: 'high', fix: 'Move admin to non-standard path, restrict by IP' },
    { name: 'API patterns', desc: '/api/v1/ (REST), /graphql (GraphQL), /api/jsonws/ (Liferay), /_api/ (SharePoint)', risk: 'medium', fix: 'Rate limit API endpoints, require authentication' },
    { name: 'File extensions', desc: '.php, .asp, .aspx, .jsp, .do, .action reveal server-side language', risk: 'low', fix: 'Use extensionless URLs via URL rewriting' },
    { name: 'Default files', desc: '/robots.txt, /sitemap.xml, /.well-known/, /crossdomain.xml', risk: 'medium', fix: 'Audit robots.txt for sensitive path disclosure' },
  ]},
  { category: 'SSL/TLS', techniques: [
    { name: 'Certificate details', desc: 'Issuer, SANs reveal all subdomains, org name, and infrastructure', risk: 'medium', fix: 'Use wildcard certs instead of listing every subdomain in SANs' },
    { name: 'Cipher suites', desc: 'Supported ciphers reveal server software and configuration age', risk: 'low', fix: 'Use modern cipher suite (Mozilla Intermediate compatibility)' },
    { name: 'TLS version', desc: 'TLS 1.0/1.1 support indicates old, potentially vulnerable server', risk: 'high', fix: 'Disable TLS 1.0 and 1.1, require TLS 1.2+ with TLS 1.3 preferred' },
  ]},
];

// =============================================================================
// SECURITY HEADERS SCORECARD — 15 headers graded
// =============================================================================
const SECURITY_HEADERS = [
  { name: 'Content-Security-Policy', weight: 15, desc: 'Controls which resources the browser can load — the single most effective XSS mitigation', missing: 'No CSP means XSS payloads can load scripts from anywhere', good: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'", bad: "Missing or script-src 'unsafe-inline' 'unsafe-eval' *" },
  { name: 'Strict-Transport-Security', weight: 12, desc: 'Forces HTTPS for all future visits, prevents SSL stripping attacks', missing: 'Users can be downgraded to HTTP via MITM', good: 'max-age=31536000; includeSubDomains; preload', bad: 'Missing or max-age < 6 months' },
  { name: 'X-Content-Type-Options', weight: 8, desc: 'Prevents MIME type sniffing — stops browsers from executing non-script files as scripts', missing: 'Uploaded files could be interpreted as scripts', good: 'nosniff', bad: 'Missing' },
  { name: 'X-Frame-Options', weight: 8, desc: 'Prevents clickjacking by controlling iframe embedding', missing: 'Page can be framed for clickjacking attacks', good: 'DENY or SAMEORIGIN', bad: 'Missing (CSP frame-ancestors is the modern replacement)' },
  { name: 'Referrer-Policy', weight: 6, desc: 'Controls how much URL info is leaked in the Referer header', missing: 'Full URLs (including tokens, session IDs) leak to third parties', good: 'strict-origin-when-cross-origin or no-referrer', bad: 'Missing or unsafe-url' },
  { name: 'Permissions-Policy', weight: 6, desc: 'Restricts browser features (camera, mic, geolocation, payment)', missing: 'Third-party scripts can access device features', good: 'camera=(), microphone=(), geolocation=()', bad: 'Missing' },
  { name: 'Cross-Origin-Opener-Policy', weight: 5, desc: 'Isolates browsing context from cross-origin popups', missing: 'Cross-origin pages can interact with window handles', good: 'same-origin', bad: 'Missing (unsafe-none weakens isolation)' },
  { name: 'Cross-Origin-Resource-Policy', weight: 5, desc: 'Prevents cross-origin reads of resources', missing: 'Resources can be embedded by any origin', good: 'same-origin or same-site', bad: 'Missing' },
  { name: 'Cross-Origin-Embedder-Policy', weight: 4, desc: 'Required for SharedArrayBuffer, prevents Spectre-class attacks', missing: 'Spectre side-channel attacks possible in browser', good: 'require-corp', bad: 'Missing' },
  { name: 'X-XSS-Protection', weight: 3, desc: 'Legacy XSS filter (deprecated in modern browsers, CSP is better)', missing: 'No impact on modern browsers with CSP', good: '0 (disable — the filter itself can introduce vulnerabilities)', bad: '1; mode=block (can leak info)' },
  { name: 'X-DNS-Prefetch-Control', weight: 2, desc: 'Controls DNS prefetching which can leak visited link info', missing: 'Browser may prefetch DNS for all links on page', good: 'off', bad: 'Missing' },
  { name: 'X-Permitted-Cross-Domain-Policies', weight: 2, desc: 'Controls Flash/PDF cross-domain access (legacy but still checked)', missing: 'Flash/Acrobat plugins could make cross-domain requests', good: 'none', bad: 'Missing or master-only' },
  { name: 'Cache-Control', weight: 5, desc: 'Controls caching of sensitive pages', missing: 'Sensitive pages cached in browser/proxy, accessible to next user', good: 'no-store, no-cache, must-revalidate (for sensitive pages)', bad: 'public, max-age=31536000 on login/account pages' },
  { name: 'X-Download-Options', weight: 2, desc: 'Prevents IE from executing downloads in the site context', missing: 'Downloaded files could auto-execute in site security context (IE only)', good: 'noopen', bad: 'Missing' },
  { name: 'Expect-CT', weight: 2, desc: 'Certificate Transparency enforcement (being deprecated in favor of browser defaults)', missing: 'Misissued certificates may not be detected', good: 'max-age=86400, enforce', bad: 'Missing (low impact as browsers now enforce CT by default)' },
];

// =============================================================================
// WAF FINGERPRINTING — how attackers detect your WAF
// =============================================================================
const WAF_SIGNATURES = [
  { name: 'Cloudflare', indicators: ['cf-ray header', 'cf-cache-status header', 'Server: cloudflare', '__cfduid cookie', 'cf-connecting-ip header', 'CAPTCHA page with /cdn-cgi/'], bypass: 'Find origin IP via historical DNS, Censys, Shodan, or email headers (Received: from)' },
  { name: 'AWS WAF', indicators: ['x-amzn-requestid header', 'x-amz-cf-id header (CloudFront)', '403 with "Request blocked" body', 'AWSALB cookie'], bypass: 'Target API Gateway directly, use non-standard HTTP methods, chunk transfer encoding' },
  { name: 'Akamai', indicators: ['X-Akamai-Transformed header', 'AkamaiGHost Server header', 'akamai-x-cache-on header', 'Reference #xx.xx pattern in 403'], bypass: 'Payload fragmentation, Unicode normalization, HTTP parameter pollution' },
  { name: 'Imperva/Incapsula', indicators: ['incap_ses cookie', 'visid_incap cookie', 'X-CDN: Imperva header', 'CAPTCHA with /_Incapsula_Resource/'], bypass: 'Use origin IP directly, time-based bypass (race condition in rule evaluation)' },
  { name: 'F5 BIG-IP ASM', indicators: ['TS cookie prefix', 'BIGipServer cookie', 'X-WA-Info header', 'The requested URL was rejected response'], bypass: 'Encoding tricks (double URL encoding, Unicode), HTTP desync attacks' },
  { name: 'ModSecurity', indicators: ['Mod_Security or NOYB in Server header', 'Reference to OWASP CRS in 403 body', 'Apache/nginx with unusually detailed 403s'], bypass: 'CRS bypass: Content-Type manipulation, multipart boundary confusion, comment injection in SQL' },
  { name: 'Sucuri', indicators: ['X-Sucuri-ID header', 'Sucuri/Cloudproxy in Server', 'sucuri-specific CAPTCHA page'], bypass: 'Find origin IP, use alternative protocols (WebSocket), bypass via API endpoints' },
  { name: 'Barracuda', indicators: ['barra_counter_session cookie', 'barracudanetworks.com references in block page'], bypass: 'HTTP parameter pollution, chunked transfer encoding, case variation' },
  { name: 'Fortinet FortiWeb', indicators: ['FORTIWAFSID cookie', 'Server: FortiWeb', '.fwf file extension in block page'], bypass: 'JSON content-type bypass, double encoding, null byte injection' },
  { name: 'Palo Alto', indicators: ['Block page with "Access has been blocked" and Palo Alto branding', 'X-PAN headers'], bypass: 'SSL/TLS interception gaps, domain fronting, legitimate cloud service abuse' },
];

// =============================================================================
// CLOUD ASSET PATTERNS — discovery techniques
// =============================================================================
const CLOUD_PATTERNS = [
  { provider: 'AWS S3', patterns: ['[company].s3.amazonaws.com', '[company]-backup.s3.amazonaws.com', '[company]-assets.s3.amazonaws.com', '[company]-uploads.s3.amazonaws.com', '[company]-data.s3.amazonaws.com', '[company]-logs.s3.amazonaws.com', '[company]-dev.s3.amazonaws.com', '[company]-staging.s3.amazonaws.com', '[company]-prod.s3.amazonaws.com', '[company]-media.s3.amazonaws.com'], check: 'curl -s https://[bucket].s3.amazonaws.com | grep -c ListBucketResult', risk: 'Public listing exposes all objects, public read exposes data, public write allows defacement' },
  { provider: 'Azure Blob', patterns: ['[company].blob.core.windows.net', '[company]storage.blob.core.windows.net', '[company]data.blob.core.windows.net'], check: 'curl -s "https://[account].blob.core.windows.net/[container]?restype=container&comp=list"', risk: 'Anonymous access to containers exposes data' },
  { provider: 'GCP Storage', patterns: ['storage.googleapis.com/[company]', '[company].storage.googleapis.com'], check: 'curl -s https://storage.googleapis.com/[bucket]', risk: 'allUsers or allAuthenticatedUsers ACL exposes data' },
  { provider: 'Azure Web Apps', patterns: ['[company].azurewebsites.net', '[company]-api.azurewebsites.net'], check: 'Subdomain takeover if CNAME exists but app is deleted', risk: 'Subdomain takeover, exposed Kudu console (/api/scm)' },
  { provider: 'AWS CloudFront', patterns: ['[hash].cloudfront.net'], check: 'curl -I to check X-Amz-Cf-Id header', risk: 'Misconfigured origin may be accessible directly' },
  { provider: 'Heroku', patterns: ['[company].herokuapp.com'], check: 'CNAME to herokuapp.com — takeover if app deleted', risk: 'Subdomain takeover, exposed environment variables' },
  { provider: 'Firebase', patterns: ['[project].firebaseio.com', '[project].web.app', '[project].firebaseapp.com'], check: 'curl -s https://[project].firebaseio.com/.json', risk: 'Misconfigured Firestore/RTDB rules expose all data' },
  { provider: 'GitHub Pages', patterns: ['[org].github.io'], check: 'CNAME to github.io — takeover if repo deleted', risk: 'Subdomain takeover, source code in public repo' },
];

// =============================================================================
// API ENDPOINT DISCOVERY — common paths attackers check
// =============================================================================
const API_DISCOVERY_PATHS = [
  { path: '/api', desc: 'Generic API root' },
  { path: '/api/v1', desc: 'Versioned API' },
  { path: '/api/v2', desc: 'Newer API version' },
  { path: '/swagger.json', desc: 'Swagger/OpenAPI spec (exposes all endpoints)' },
  { path: '/swagger-ui.html', desc: 'Swagger interactive UI' },
  { path: '/api-docs', desc: 'API documentation' },
  { path: '/openapi.json', desc: 'OpenAPI 3.0 spec' },
  { path: '/graphql', desc: 'GraphQL endpoint (try introspection query)' },
  { path: '/graphiql', desc: 'GraphQL interactive IDE' },
  { path: '/.well-known/openid-configuration', desc: 'OpenID Connect discovery' },
  { path: '/oauth/token', desc: 'OAuth2 token endpoint' },
  { path: '/health', desc: 'Health check (may reveal version/env info)' },
  { path: '/healthz', desc: 'Kubernetes health check' },
  { path: '/metrics', desc: 'Prometheus metrics (may expose internal data)' },
  { path: '/actuator', desc: 'Spring Boot Actuator (env, beans, mappings)' },
  { path: '/actuator/env', desc: 'Spring environment variables (may contain secrets)' },
  { path: '/debug', desc: 'Debug endpoints' },
  { path: '/trace', desc: 'Request tracing' },
  { path: '/.env', desc: 'Environment file (secrets, API keys)' },
  { path: '/wp-json/wp/v2/users', desc: 'WordPress REST API user enumeration' },
  { path: '/server-info', desc: 'Server information page' },
  { path: '/server-status', desc: 'Apache server status' },
  { path: '/nginx_status', desc: 'Nginx status page' },
  { path: '/phpinfo.php', desc: 'PHP info page (exposes entire config)' },
  { path: '/elmah.axd', desc: '.NET error log viewer' },
  { path: '/telescope', desc: 'Laravel Telescope debug dashboard' },
  { path: '/_debug_toolbar/', desc: 'Django debug toolbar' },
  { path: '/console', desc: 'Interactive console (Rails, H2 database)' },
  { path: '/adminer.php', desc: 'Database admin tool' },
  { path: '/phpmyadmin', desc: 'phpMyAdmin database admin' },
];

// =============================================================================
// SUBDOMAIN TAKEOVER FINGERPRINTS
// =============================================================================
const TAKEOVER_FINGERPRINTS = [
  { service: 'GitHub Pages', cname: 'github.io', fingerprint: "There isn't a GitHub Pages site here", exploitable: true },
  { service: 'Heroku', cname: 'herokuapp.com', fingerprint: 'No such app', exploitable: true },
  { service: 'AWS S3', cname: 's3.amazonaws.com', fingerprint: 'NoSuchBucket', exploitable: true },
  { service: 'Shopify', cname: 'myshopify.com', fingerprint: 'Sorry, this shop is currently unavailable', exploitable: true },
  { service: 'Tumblr', cname: 'domains.tumblr.com', fingerprint: "There's nothing here", exploitable: true },
  { service: 'WordPress.com', cname: 'wordpress.com', fingerprint: 'Do you want to register', exploitable: true },
  { service: 'Pantheon', cname: 'pantheonsite.io', fingerprint: '404 error unknown site', exploitable: true },
  { service: 'Fastly', cname: 'fastly.net', fingerprint: 'Fastly error: unknown domain', exploitable: true },
  { service: 'Ghost', cname: 'ghost.io', fingerprint: 'The thing you were looking for is no longer here', exploitable: true },
  { service: 'Surge.sh', cname: 'surge.sh', fingerprint: 'project not found', exploitable: true },
  { service: 'Zendesk', cname: 'zendesk.com', fingerprint: 'Help Center Closed', exploitable: false },
  { service: 'Azure', cname: 'azurewebsites.net', fingerprint: 'Error 404 - Web app not found', exploitable: true },
  { service: 'Unbounce', cname: 'unbouncepages.com', fingerprint: 'The requested URL was not found', exploitable: true },
  { service: 'Fly.io', cname: 'fly.dev', fingerprint: '404 Not Found', exploitable: true },
  { service: 'Netlify', cname: 'netlify.app', fingerprint: 'Not Found - Request ID:', exploitable: false },
  { service: 'Vercel', cname: 'vercel.app', fingerprint: 'DEPLOYMENT_NOT_FOUND', exploitable: false },
  { service: 'Cargo Collective', cname: 'cargocollective.com', fingerprint: '404 Not Found', exploitable: true },
  { service: 'HubSpot', cname: 'hs-sites.com', fingerprint: 'Domain not found', exploitable: false },
  { service: 'Intercom', cname: 'custom.intercom.help', fingerprint: 'Uh oh. That page doesn\'t exist', exploitable: false },
];

// =============================================================================
// EMAIL FORMAT DISCOVERY — common patterns
// =============================================================================
const EMAIL_FORMATS = [
  { format: 'first.last@domain.com', example: 'john.smith@company.com', prevalence: '45%' },
  { format: 'firstlast@domain.com', example: 'johnsmith@company.com', prevalence: '15%' },
  { format: 'first@domain.com', example: 'john@company.com', prevalence: '10%' },
  { format: 'flast@domain.com', example: 'jsmith@company.com', prevalence: '12%' },
  { format: 'first_last@domain.com', example: 'john_smith@company.com', prevalence: '8%' },
  { format: 'firstl@domain.com', example: 'johns@company.com', prevalence: '5%' },
  { format: 'f.last@domain.com', example: 'j.smith@company.com', prevalence: '3%' },
  { format: 'last.first@domain.com', example: 'smith.john@company.com', prevalence: '2%' },
];

// =============================================================================
// LIVE DATA HELPERS — query real DNS, certificate, and email records
// =============================================================================
function fetchDNS(domain, type) {
  return fetch('https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=' + type)
    .then(function(r) { return r.json(); })
    .catch(function() { return null; });
}

function fetchCert(domain) {
  return fetch('https://crt.sh/?q=' + encodeURIComponent(domain) + '&output=json&limit=5')
    .then(function(r) { return r.json(); })
    .catch(function() { return null; });
}

// =============================================================================
// ASSESSMENT ENGINE — uses live API data, no simulated results
// =============================================================================
function runAssessment(domain) {
  var d = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');

  return Promise.all([
    fetchDNS(d, 'CAA'),
    fetchDNS(d, 'TXT'),
    fetchDNS('_dmarc.' + d, 'TXT'),
    fetchDNS(d, 'MX'),
    fetchDNS(d, 'NS'),
    fetchDNS(d, 'A'),
    fetchCert(d),
  ]).then(function(responses) {
    var caaData = responses[0];
    var txtData = responses[1];
    var dmarcData = responses[2];
    var mxData = responses[3];
    var nsData = responses[4];
    var aData = responses[5];
    var certData = responses[6];

    var results = {
      domain: d,
      timestamp: new Date().toISOString(),
      categories: {},
      overallScore: 0,
    };

    // ---- DNS Analysis (real data from Google Public DNS) ----
    var dnsFindings = [];
    var dnsScore = 100;

    var caaRecords = (caaData && caaData.Answer) ? caaData.Answer.filter(function(r) { return r.type === 257; }) : [];
    if (caaRecords.length === 0) {
      dnsFindings.push({ severity: 'high', finding: 'CAA record not set — any Certificate Authority can issue certificates for ' + d, recommendation: 'Set CAA records to restrict certificate issuance (e.g., 0 issue "letsencrypt.org")' });
      dnsScore -= 20;
    } else {
      var issuers = caaRecords.map(function(r) { return r.data; }).join(', ');
      dnsFindings.push({ severity: 'low', finding: 'CAA records configured: ' + issuers, recommendation: 'No action needed — certificate issuance is restricted' });
    }

    var dnssecEnabled = (caaData && caaData.AD === true) || (aData && aData.AD === true);
    if (!dnssecEnabled) {
      dnsFindings.push({ severity: 'medium', finding: 'DNSSEC not enabled — DNS responses can be spoofed', recommendation: 'Enable DNSSEC to prevent DNS spoofing and cache poisoning attacks' });
      dnsScore -= 15;
    } else {
      dnsFindings.push({ severity: 'low', finding: 'DNSSEC enabled and validated (AD flag set by resolver)', recommendation: 'No action needed — DNS responses are cryptographically authenticated' });
    }

    var nsRecords = (nsData && nsData.Answer) ? nsData.Answer : [];
    if (nsRecords.length > 0) {
      var nameservers = nsRecords.map(function(r) { return r.data; }).join(', ');
      dnsFindings.push({ severity: 'info', finding: 'Nameservers: ' + nameservers, recommendation: 'Ensure nameserver provider supports DNSSEC and has DDoS protection' });
    } else {
      dnsFindings.push({ severity: 'medium', finding: 'Could not retrieve nameserver records', recommendation: 'Verify NS records are properly configured' });
      dnsScore -= 10;
    }

    var firstNS = nsRecords.length > 0 ? nsRecords[0].data.replace(/\.$/, '') : 'ns1.' + d;
    dnsFindings.push({ severity: 'info', finding: 'Zone transfer (AXFR) testing requires the Pentest Console. Run: dig @' + firstNS + ' ' + d + ' AXFR', recommendation: 'Ensure AXFR is restricted to authorized secondary nameservers only' });

    results.categories.dns = { score: Math.max(0, dnsScore), grade: scoreToGrade(Math.max(0, dnsScore)), findings: dnsFindings };

    // ---- Email Security (real SPF/DMARC/MX from DNS) ----
    var emailFindings = [];
    var emailScore = 100;

    var txtRecords = (txtData && txtData.Answer) ? txtData.Answer : [];
    var spfRecord = null;
    txtRecords.forEach(function(r) {
      var val = r.data || '';
      if (val.indexOf('v=spf1') !== -1) spfRecord = val.replace(/^"|"$/g, '');
    });

    if (!spfRecord) {
      emailFindings.push({ severity: 'critical', finding: 'SPF record MISSING — domain can be freely spoofed for phishing', recommendation: 'Set SPF to v=spf1 include:[your-providers] -all' });
      emailScore -= 30;
    } else if (spfRecord.indexOf('+all') !== -1) {
      emailFindings.push({ severity: 'critical', finding: 'SPF record uses +all — this permits ANY server to send email as ' + d + '. Record: ' + spfRecord, recommendation: 'Change +all to -all immediately' });
      emailScore -= 30;
    } else if (spfRecord.indexOf('~all') !== -1) {
      emailFindings.push({ severity: 'medium', finding: 'SPF record uses ~all (softfail) — spoofed emails may still be delivered. Record: ' + spfRecord, recommendation: 'Change ~all to -all for strict enforcement' });
      emailScore -= 10;
    } else if (spfRecord.indexOf('-all') !== -1) {
      emailFindings.push({ severity: 'low', finding: 'SPF properly configured with -all (hardfail). Record: ' + spfRecord, recommendation: 'No action needed' });
    } else {
      emailFindings.push({ severity: 'medium', finding: 'SPF record found but missing explicit all mechanism. Record: ' + spfRecord, recommendation: 'Add -all to the end of the SPF record' });
      emailScore -= 10;
    }

    var dmarcRecords = (dmarcData && dmarcData.Answer) ? dmarcData.Answer : [];
    var dmarcRecord = null;
    dmarcRecords.forEach(function(r) {
      var val = r.data || '';
      if (val.indexOf('v=DMARC1') !== -1 || val.indexOf('v=dmarc1') !== -1) dmarcRecord = val.replace(/^"|"$/g, '');
    });

    if (!dmarcRecord) {
      emailFindings.push({ severity: 'critical', finding: 'DMARC policy MISSING — no email authentication enforcement for ' + d, recommendation: 'Set DMARC to v=DMARC1; p=reject; rua=mailto:dmarc-reports@' + d });
      emailScore -= 30;
    } else if (dmarcRecord.indexOf('p=none') !== -1) {
      emailFindings.push({ severity: 'high', finding: 'DMARC policy is p=none (monitoring only, not enforcing). Record: ' + dmarcRecord, recommendation: 'Change p=none to p=reject after validating SPF/DKIM alignment' });
      emailScore -= 20;
    } else if (dmarcRecord.indexOf('p=quarantine') !== -1) {
      emailFindings.push({ severity: 'medium', finding: 'DMARC policy is p=quarantine — spoofed emails go to spam, not rejected. Record: ' + dmarcRecord, recommendation: 'Consider upgrading to p=reject for full enforcement' });
      emailScore -= 10;
    } else if (dmarcRecord.indexOf('p=reject') !== -1) {
      emailFindings.push({ severity: 'low', finding: 'DMARC properly configured with p=reject. Record: ' + dmarcRecord, recommendation: 'No action needed — email spoofing is blocked' });
    }

    var mxRecords = (mxData && mxData.Answer) ? mxData.Answer : [];
    if (mxRecords.length > 0) {
      var mxHosts = mxRecords.map(function(r) { return r.data; }).join(', ');
      var provider = 'unknown provider';
      if (mxHosts.indexOf('google') !== -1 || mxHosts.indexOf('aspmx') !== -1) provider = 'Google Workspace';
      else if (mxHosts.indexOf('outlook') !== -1 || mxHosts.indexOf('microsoft') !== -1) provider = 'Microsoft 365';
      else if (mxHosts.indexOf('pphosted') !== -1 || mxHosts.indexOf('proofpoint') !== -1) provider = 'Proofpoint';
      else if (mxHosts.indexOf('mimecast') !== -1) provider = 'Mimecast';
      emailFindings.push({ severity: 'info', finding: 'MX records point to ' + provider + ': ' + mxHosts, recommendation: 'Enable advanced threat protection on your email provider' });
    } else {
      emailFindings.push({ severity: 'info', finding: 'No MX records found — domain may not handle email', recommendation: 'If unused for email, publish null SPF (v=spf1 -all) and DMARC (p=reject)' });
    }

    emailFindings.push({ severity: 'info', finding: 'DKIM verification requires knowing the selector. Run: dig selector1._domainkey.' + d + ' TXT', recommendation: 'Common selectors: google, selector1, selector2, default, k1' });

    results.categories.email = { score: Math.max(0, emailScore), grade: scoreToGrade(Math.max(0, emailScore)), findings: emailFindings };

    // ---- SSL/TLS (real certificate data from CT logs) ----
    var tlsFindings = [];
    var tlsScore = 100;

    var certs = Array.isArray(certData) ? certData : [];
    if (certs.length > 0) {
      var cert = certs[0];
      var issuerRaw = cert.issuer_name || cert.ca_name || 'Unknown CA';
      var cnMatch = issuerRaw.match(/CN=([^,]+)/);
      var issuer = cnMatch ? cnMatch[1] : issuerRaw;
      var notAfter = cert.not_after || '';
      var commonName = cert.common_name || '';

      tlsFindings.push({ severity: 'low', finding: 'Certificate found — issued by ' + issuer + (notAfter ? ', valid until ' + notAfter : ''), recommendation: 'Ensure auto-renewal is configured and certificate is monitored' });

      if (notAfter) {
        var expiryDate = new Date(notAfter.replace(' ', 'T') + 'Z');
        var daysLeft = Math.floor((expiryDate - new Date()) / 86400000);
        if (daysLeft < 0) {
          tlsFindings.push({ severity: 'critical', finding: 'Certificate EXPIRED ' + Math.abs(daysLeft) + ' days ago', recommendation: 'Renew certificate immediately' });
          tlsScore -= 40;
        } else if (daysLeft < 30) {
          tlsFindings.push({ severity: 'high', finding: 'Certificate expires in ' + daysLeft + ' days', recommendation: 'Renew certificate before expiry' });
          tlsScore -= 15;
        }
      }

      tlsFindings.push({ severity: 'info', finding: 'Certificate CN: ' + commonName + '. ' + certs.length + ' certificate(s) found in Certificate Transparency logs.', recommendation: 'Use wildcard certificates to reduce subdomain enumeration via CT logs' });
    } else {
      tlsFindings.push({ severity: 'medium', finding: 'Could not retrieve certificate data from CT logs (crt.sh may be rate-limited, or no certificates issued for this domain)', recommendation: 'Verify TLS config. Run: echo | openssl s_client -connect ' + d + ':443 2>/dev/null | openssl x509 -noout -text' });
      tlsScore -= 15;
    }

    tlsFindings.push({ severity: 'info', finding: 'TLS version and cipher suite testing requires the Pentest Console. Run: nmap --script ssl-enum-ciphers -p 443 ' + d, recommendation: 'Disable TLS 1.0 and 1.1, require TLS 1.2+ with TLS 1.3 preferred' });
    tlsFindings.push({ severity: 'info', finding: 'HSTS header check requires the Pentest Console. Run: curl -sI https://' + d + ' | grep -i strict-transport-security', recommendation: 'Set HSTS with max-age=31536000 includeSubDomains preload' });

    results.categories.tls = { score: Math.max(0, tlsScore), grade: scoreToGrade(Math.max(0, tlsScore)), findings: tlsFindings };

    // ---- Security Headers (cannot check from browser — CORS) ----
    results.categories.headers = {
      score: null,
      grade: '?',
      findings: [
        { severity: 'info', finding: 'Security header analysis cannot be performed from the browser due to CORS restrictions', recommendation: 'Run from the Pentest Console: curl -sI https://' + d + ' | grep -iE "content-security-policy|strict-transport-security|x-content-type|x-frame|referrer-policy|permissions-policy"' },
        { severity: 'info', finding: 'For a comprehensive header audit, run: curl -sI https://' + d, recommendation: 'Compare results against the Security Headers reference tab for recommended values' },
      ],
    };

    // ---- Technology Exposure (requires active scanning) ----
    results.categories.technology = {
      score: null,
      grade: '?',
      findings: [
        { severity: 'info', finding: 'Technology detection requires active scanning. Use the Pentest Console.', recommendation: 'Run: curl -sI https://' + d + ' to check Server, X-Powered-By, and other fingerprinting headers' },
        { severity: 'info', finding: 'CMS detection command: curl -s https://' + d + ' | grep -i "generator\\|wp-content\\|drupal\\|joomla"', recommendation: 'See the Reference tab for a complete list of technology fingerprinting techniques' },
        { severity: 'info', finding: 'WAF detection requires sending test payloads. Use the Pentest Console.', recommendation: 'See the WAF Fingerprinting section in the Reference tab for detection signatures' },
      ],
    };

    // ---- Cloud Exposure (requires Pentest Console) ----
    results.categories.cloud = {
      score: null,
      grade: '?',
      findings: [
        { severity: 'info', finding: 'Cloud asset discovery requires the Pentest Console for bucket enumeration and subdomain takeover testing', recommendation: 'Check S3: curl -s https://' + d.replace(/\./g, '-') + '.s3.amazonaws.com | grep -c ListBucketResult' },
        { severity: 'info', finding: 'Subdomain takeover testing requires CNAME resolution from a non-browser context', recommendation: 'Run: dig CNAME staging.' + d + ' +short — check for dangling CNAMEs pointing to decommissioned services' },
        { severity: 'info', finding: 'See the Cloud Asset Discovery Patterns in the Reference tab for full testing methodology', recommendation: 'Use the Pentest Console to test each cloud provider pattern systematically' },
      ],
    };

    // Calculate overall from categories that have real scores
    var scoredCats = Object.keys(results.categories).filter(function(k) { return results.categories[k].score !== null; });
    if (scoredCats.length > 0) {
      var totalScore = scoredCats.reduce(function(a, k) { return a + results.categories[k].score; }, 0);
      results.overallScore = Math.round(totalScore / scoredCats.length);
    } else {
      results.overallScore = null;
    }
    results.overallGrade = results.overallScore !== null ? scoreToGrade(results.overallScore) : '?';
    results.partialScan = scoredCats.length < Object.keys(results.categories).length;

    return results;
  });
}

function scoreToGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

function gradeColor(grade) {
  const map = { A: '#00e676', B: '#69f0ae', C: '#ffd600', D: '#ff9100', F: '#ff1744' };
  return map[grade] || '#888';
}

function sevColor(sev) {
  const map = { critical: '#ff1744', high: '#ff5252', medium: '#ff9100', low: '#ffd600', info: 'var(--mut)' };
  return map[sev] || 'var(--mut)';
}

// =============================================================================
// MAIN RENDER
// =============================================================================
export function renderAttackSurfaceMapper(main) {
  let results = null;
  let activeTab = 'overview';
  let savedAssessments = [];
  try { savedAssessments = JSON.parse(localStorage.getItem('asm_history') || '[]'); } catch (_) {}

  function render() {
    main.innerHTML =
      '<h1 class="pg-h1">Attack Surface Mapper</h1>' +
      '<p class="muted pg-sub">See your organization like an attacker sees it. Analyze your external attack surface across DNS, email, TLS, headers, technology, and cloud exposure.</p>' +
      '<div style="display:flex;gap:8px;align-items:center;margin-bottom:16px;flex-wrap:wrap">' +
        '<input type="text" id="asm-domain" placeholder="Enter domain (e.g., example.com)" value="" style="background:var(--card);color:var(--txt);border:1px solid var(--line);padding:8px 14px;border-radius:4px;font-size:.85rem;flex:1;min-width:200px;font-family:inherit">' +
        '<button class="btn sm" id="asm-scan">Analyze Attack Surface</button>' +
        '<button class="btn sm ghost" id="asm-history-btn">History (' + savedAssessments.length + ')</button>' +
      '</div>' +
      '<div id="asm-content"></div>';

    main.querySelector('#asm-scan').onclick = function() {
      var domainInput = main.querySelector('#asm-domain');
      var d = domainInput.value.trim();
      if (!d) { domainInput.style.borderColor = '#ff1744'; return; }
      domainInput.style.borderColor = 'var(--line)';
      var scanBtn = main.querySelector('#asm-scan');
      var contentArea = main.querySelector('#asm-content');
      scanBtn.disabled = true;
      scanBtn.textContent = 'Scanning...';
      contentArea.innerHTML = '<div style="text-align:center;padding:40px;color:var(--mut)">' +
        '<div style="font-size:1.2rem;margin-bottom:8px">Querying live DNS, email, and certificate data...</div>' +
        '<div style="font-size:.8rem">Checking CAA, SPF, DMARC, MX, NS, DNSSEC, and CT logs for ' + esc(d) + '</div></div>';
      runAssessment(d).then(function(r) {
        results = r;
        var scoreVal = r.overallScore !== null ? r.overallScore : 0;
        var gradeVal = r.overallGrade || '?';
        savedAssessments.unshift({ domain: r.domain, score: scoreVal, grade: gradeVal, timestamp: r.timestamp });
        if (savedAssessments.length > 20) savedAssessments = savedAssessments.slice(0, 20);
        try { localStorage.setItem('asm_history', JSON.stringify(savedAssessments)); } catch (_) {}
        activeTab = 'overview';
        scanBtn.disabled = false;
        scanBtn.textContent = 'Analyze Attack Surface';
        renderResults();
      }).catch(function(err) {
        contentArea.innerHTML = '<div style="text-align:center;padding:40px;color:#ff1744">' +
          '<div style="font-size:1.2rem;margin-bottom:8px">Scan failed</div>' +
          '<div style="font-size:.8rem;color:var(--mut)">' + esc(String(err)) + '</div></div>';
        scanBtn.disabled = false;
        scanBtn.textContent = 'Analyze Attack Surface';
      });
    };

    main.querySelector('#asm-history-btn').onclick = function() {
      activeTab = 'history';
      renderResults();
    };

    if (results) renderResults();
  }

  function renderResults() {
    var content = main.querySelector('#asm-content');
    if (!content) return;

    if (activeTab === 'history') {
      content.innerHTML = '<h2 class="pg-h2">Assessment History</h2>' +
        (savedAssessments.length === 0 ? '<p class="muted">No assessments saved yet.</p>' :
          '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.8rem">' +
          '<thead><tr style="border-bottom:2px solid var(--line)">' +
          '<th style="padding:8px;text-align:left;color:var(--mut)">Domain</th>' +
          '<th style="padding:8px;text-align:left;color:var(--mut)">Score</th>' +
          '<th style="padding:8px;text-align:left;color:var(--mut)">Grade</th>' +
          '<th style="padding:8px;text-align:left;color:var(--mut)">Date</th>' +
          '</tr></thead><tbody>' +
          savedAssessments.map(function(a) {
            return '<tr style="border-bottom:1px solid var(--line)">' +
              '<td style="padding:8px;font-weight:600">' + esc(a.domain) + '</td>' +
              '<td style="padding:8px">' + a.score + '/100</td>' +
              '<td style="padding:8px;color:' + gradeColor(a.grade) + ';font-weight:700;font-size:1.1rem">' + a.grade + '</td>' +
              '<td style="padding:8px;color:var(--mut)">' + new Date(a.timestamp).toLocaleDateString() + '</td>' +
              '</tr>';
          }).join('') +
          '</tbody></table></div>' +
          '<button class="btn sm ghost" id="asm-clear" style="margin-top:12px">Clear History</button>');
      var clearBtn = content.querySelector('#asm-clear');
      if (clearBtn) clearBtn.onclick = function() { savedAssessments = []; try { localStorage.removeItem('asm_history'); } catch (_) {} renderResults(); };
      return;
    }

    if (!results) { content.innerHTML = ''; return; }

    // Tabs
    var tabs = [
      { id: 'overview', label: 'Overview' },
      { id: 'dns', label: 'DNS' },
      { id: 'email', label: 'Email Security' },
      { id: 'tls', label: 'SSL/TLS' },
      { id: 'headers', label: 'Security Headers' },
      { id: 'technology', label: 'Technology' },
      { id: 'cloud', label: 'Cloud' },
      { id: 'reference', label: 'Reference' },
      { id: 'report', label: 'Report' },
    ];

    var tabHtml = '<div class="tab-bar" style="overflow-x:auto;flex-wrap:nowrap">' +
      tabs.map(function(t) { return '<button class="tab' + (activeTab === t.id ? ' active' : '') + '" data-tab="' + t.id + '">' + esc(t.label) + '</button>'; }).join('') +
      '</div>';

    var bodyHtml = '';

    if (activeTab === 'overview') {
      bodyHtml = renderOverview();
    } else if (activeTab === 'reference') {
      bodyHtml = renderReference();
    } else if (activeTab === 'report') {
      bodyHtml = renderReport();
    } else if (results.categories[activeTab]) {
      bodyHtml = renderCategory(activeTab);
    }

    content.innerHTML = tabHtml + '<div style="margin-top:12px">' + bodyHtml + '</div>';

    content.querySelector('.tab-bar').onclick = function(e) {
      var b = e.target.closest('.tab');
      if (!b) return;
      activeTab = b.dataset.tab;
      renderResults();
    };
  }

  function renderOverview() {
    var r = results;
    var html = '<div style="display:flex;align-items:center;gap:24px;margin-bottom:20px;flex-wrap:wrap">' +
      '<div style="text-align:center">' +
        '<div style="font-size:3rem;font-weight:800;color:' + gradeColor(r.overallGrade) + '">' + r.overallGrade + '</div>' +
        '<div style="font-size:.75rem;color:var(--mut)">Overall Grade</div>' +
        '<div style="font-size:1.1rem;font-weight:600;color:var(--txt);margin-top:4px">' + (r.overallScore !== null ? r.overallScore + '/100' : 'Partial — some checks require Pentest Console') + '</div>' +
      '</div>' +
      '<div style="flex:1;min-width:250px">' +
        '<h2 class="pg-h2" style="margin:0 0 4px">Attack Surface: ' + esc(r.domain) + '</h2>' +
        '<p class="muted" style="margin:0">Assessed ' + new Date(r.timestamp).toLocaleString() + '</p>' +
      '</div>' +
    '</div>';

    // Category scores
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px;margin-bottom:20px">';
    var catNames = { dns: 'DNS Security', email: 'Email Security', tls: 'SSL/TLS', headers: 'HTTP Headers', technology: 'Tech Exposure', cloud: 'Cloud Security' };
    Object.keys(r.categories).forEach(function(key) {
      var cat = r.categories[key];
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px;cursor:pointer" data-tab="' + key + '" class="tab">' +
        '<div style="font-size:1.4rem;font-weight:700;color:' + gradeColor(cat.grade) + '">' + cat.grade + '</div>' +
        '<div style="font-size:.8rem;color:var(--txt);font-weight:500">' + esc(catNames[key] || key) + '</div>' +
        '<div style="font-size:.7rem;color:var(--mut)">' + (cat.score !== null ? cat.score + '/100' : 'Pentest Console') + '</div>' +
        '<div style="height:3px;background:var(--line);border-radius:2px;margin-top:6px"><div style="height:100%;width:' + (cat.score !== null ? cat.score : 0) + '%;background:' + gradeColor(cat.grade) + ';border-radius:2px"></div></div>' +
      '</div>';
    });
    html += '</div>';

    // Critical findings summary
    var allFindings = [];
    Object.keys(r.categories).forEach(function(key) {
      r.categories[key].findings.forEach(function(f) { allFindings.push(Object.assign({}, f, { category: key })); });
    });
    var critical = allFindings.filter(function(f) { return f.severity === 'critical' || f.severity === 'high'; });

    if (critical.length > 0) {
      html += '<h3 style="color:#ff1744;margin:0 0 8px">Critical & High Findings (' + critical.length + ')</h3>';
      critical.forEach(function(f) {
        html += '<div style="background:var(--card);border:1px solid var(--line);border-left:3px solid ' + sevColor(f.severity) + ';border-radius:4px;padding:10px;margin-bottom:6px;font-size:.8rem">' +
          '<div style="display:flex;gap:8px;align-items:center">' +
            '<span style="color:' + sevColor(f.severity) + ';font-weight:700;text-transform:uppercase;font-size:.65rem">' + esc(f.severity) + '</span>' +
            '<span>' + esc(f.finding) + '</span>' +
          '</div>' +
          '<div style="color:var(--mut);font-size:.75rem;margin-top:4px">Fix: ' + esc(f.recommendation) + '</div>' +
        '</div>';
      });
    }

    // Attacker's 30-minute view
    html += '<h3 style="margin:20px 0 8px">What an Attacker Learns in 30 Minutes</h3>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px;font-size:.8rem;line-height:1.7">' +
        '<p>A motivated attacker targeting <strong>' + esc(r.domain) + '</strong> would discover:</p>' +
        '<ul style="margin:8px 0;padding-left:20px">' +
          '<li>Hosting infrastructure and cloud provider via DNS/IP lookup</li>' +
          '<li>Email provider and authentication posture (SPF/DKIM/DMARC)</li>' +
          '<li>Technology stack from HTTP headers, cookies, and HTML source</li>' +
          '<li>Subdomains via Certificate Transparency logs and DNS enumeration</li>' +
          '<li>Security header coverage — what browser protections are active</li>' +
          '<li>WAF presence (or absence) and potential bypass techniques</li>' +
          '<li>Employee names and email format via LinkedIn/public sources</li>' +
          '<li>Cloud assets via naming pattern brute force (S3, Azure Blob)</li>' +
        '</ul>' +
        '<p style="margin:0">Overall assessment: <strong style="color:' + gradeColor(r.overallGrade) + '">' +
          (r.overallScore === null ? 'Partial scan — DNS, email, and TLS checked with live data. Run remaining checks from the Pentest Console for a full assessment.' :
           r.overallScore >= 80 ? 'Well-hardened surface. Attacker would need significant effort.' :
           r.overallScore >= 60 ? 'Moderate exposure. Several findings would accelerate an attack.' :
           r.overallScore >= 40 ? 'Significant exposure. Multiple easy entry points available.' :
           'Critical exposure. Trivial attack surface — immediate remediation needed.') +
        '</strong></p>' +
      '</div>';

    return html;
  }

  function renderCategory(key) {
    var cat = results.categories[key];
    var catNames = { dns: 'DNS Security', email: 'Email Security', tls: 'SSL/TLS', headers: 'HTTP Security Headers', technology: 'Technology Exposure', cloud: 'Cloud Security' };

    var html = '<div style="display:flex;align-items:center;gap:16px;margin-bottom:16px">' +
      '<div style="font-size:2.5rem;font-weight:800;color:' + gradeColor(cat.grade) + '">' + cat.grade + '</div>' +
      '<div>' +
        '<h2 class="pg-h2" style="margin:0">' + esc(catNames[key] || key) + '</h2>' +
        '<div style="font-size:.8rem;color:var(--mut)">Score: ' + (cat.score !== null ? cat.score + '/100' : 'Requires Pentest Console for active scanning') + '</div>' +
      '</div>' +
    '</div>';

    cat.findings.forEach(function(f) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-left:3px solid ' + sevColor(f.severity) + ';border-radius:4px;padding:12px;margin-bottom:8px;font-size:.82rem">' +
        '<div style="display:flex;gap:8px;align-items:center;margin-bottom:4px">' +
          '<span style="color:' + sevColor(f.severity) + ';font-weight:700;text-transform:uppercase;font-size:.65rem;padding:2px 6px;border:1px solid;border-radius:3px">' + esc(f.severity) + '</span>' +
          '<span style="font-weight:500">' + esc(f.finding) + '</span>' +
        '</div>' +
        '<div style="color:var(--mut);font-size:.78rem">Recommendation: ' + esc(f.recommendation) + '</div>' +
      '</div>';
    });

    return html;
  }

  function renderReference() {
    var html = '<h2 class="pg-h2">Attack Surface Reference</h2>';

    // DNS Reference
    html += '<h3 style="margin:16px 0 8px">DNS Records — What They Reveal</h3>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Type</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Purpose</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Attacker Use</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Remediation</th>' +
      '</tr></thead><tbody>' +
      DNS_RECORDS.map(function(r) {
        return '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:6px;font-weight:600;color:var(--acc)">' + esc(r.type) + '</td>' +
          '<td style="padding:6px">' + esc(r.desc) + '</td>' +
          '<td style="padding:6px;color:var(--mut)">' + esc(r.attackUse) + '</td>' +
          '<td style="padding:6px;color:var(--mut)">' + esc(r.remediation) + '</td>' +
          '</tr>';
      }).join('') +
      '</tbody></table></div>';

    // WAF Fingerprinting
    html += '<h3 style="margin:16px 0 8px">WAF Detection Signatures</h3>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:8px">' +
      WAF_SIGNATURES.map(function(w) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:10px;font-size:.78rem">' +
          '<div style="font-weight:600;margin-bottom:4px">' + esc(w.name) + '</div>' +
          '<div style="color:var(--mut);margin-bottom:4px">Indicators: ' + esc(w.indicators.join(', ')) + '</div>' +
          '<div style="color:#ff9100;font-size:.72rem">Bypass: ' + esc(w.bypass) + '</div>' +
        '</div>';
      }).join('') + '</div>';

    // Subdomain Takeover
    html += '<h3 style="margin:16px 0 8px">Subdomain Takeover Fingerprints</h3>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Service</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">CNAME</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Fingerprint</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Exploitable</th>' +
      '</tr></thead><tbody>' +
      TAKEOVER_FINGERPRINTS.map(function(t) {
        return '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:6px;font-weight:500">' + esc(t.service) + '</td>' +
          '<td style="padding:6px;font-family:var(--mono,monospace);font-size:.72rem">' + esc(t.cname) + '</td>' +
          '<td style="padding:6px;color:var(--mut);font-size:.72rem">' + esc(t.fingerprint) + '</td>' +
          '<td style="padding:6px;color:' + (t.exploitable ? '#ff1744' : '#00e676') + ';font-weight:600">' + (t.exploitable ? 'YES' : 'NO') + '</td>' +
          '</tr>';
      }).join('') +
      '</tbody></table></div>';

    // Cloud Patterns
    html += '<h3 style="margin:16px 0 8px">Cloud Asset Discovery Patterns</h3>' +
      CLOUD_PATTERNS.map(function(c) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:10px;margin-bottom:6px;font-size:.78rem">' +
          '<div style="font-weight:600;color:var(--acc);margin-bottom:4px">' + esc(c.provider) + '</div>' +
          '<div style="color:var(--mut);margin-bottom:4px">Patterns: <code style="font-size:.72rem">' + esc(c.patterns.join(', ')) + '</code></div>' +
          '<div style="color:var(--mut)">Check: <code style="font-size:.72rem">' + esc(c.check) + '</code></div>' +
          '<div style="color:#ff9100;font-size:.72rem;margin-top:4px">Risk: ' + esc(c.risk) + '</div>' +
        '</div>';
      }).join('');

    // API Paths
    html += '<h3 style="margin:16px 0 8px">Common API Discovery Paths</h3>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:4px">' +
      API_DISCOVERY_PATHS.map(function(p) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:3px;padding:6px 10px;font-size:.75rem;display:flex;gap:8px">' +
          '<code style="color:var(--acc);white-space:nowrap">' + esc(p.path) + '</code>' +
          '<span style="color:var(--mut)">' + esc(p.desc) + '</span>' +
        '</div>';
      }).join('') + '</div>';

    // Security Headers
    html += '<h3 style="margin:16px 0 8px">HTTP Security Headers Scorecard</h3>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Header</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Weight</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Purpose</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Good Value</th>' +
      '</tr></thead><tbody>' +
      SECURITY_HEADERS.map(function(h) {
        return '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:6px;font-weight:500;white-space:nowrap">' + esc(h.name) + '</td>' +
          '<td style="padding:6px;color:var(--acc)">' + h.weight + '</td>' +
          '<td style="padding:6px;color:var(--mut)">' + esc(h.desc) + '</td>' +
          '<td style="padding:6px"><code style="font-size:.7rem">' + esc(h.good) + '</code></td>' +
          '</tr>';
      }).join('') +
      '</tbody></table></div>';

    // Email Formats
    html += '<h3 style="margin:16px 0 8px">Common Email Address Formats</h3>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Format</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Example</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Prevalence</th>' +
      '</tr></thead><tbody>' +
      EMAIL_FORMATS.map(function(f) {
        return '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:6px;font-family:var(--mono,monospace)">' + esc(f.format) + '</td>' +
          '<td style="padding:6px;color:var(--mut)">' + esc(f.example) + '</td>' +
          '<td style="padding:6px;color:var(--acc)">' + esc(f.prevalence) + '</td>' +
          '</tr>';
      }).join('') +
      '</tbody></table></div>';

    return html;
  }

  function renderReport() {
    if (!results) return '<p class="muted">Run an assessment first.</p>';
    var r = results;
    var allFindings = [];
    Object.keys(r.categories).forEach(function(key) {
      r.categories[key].findings.forEach(function(f) { allFindings.push(Object.assign({}, f, { category: key })); });
    });
    allFindings.sort(function(a, b) {
      var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] || 5) - (order[b.severity] || 5);
    });

    var report = '=== ATTACK SURFACE ASSESSMENT REPORT ===\n';
    report += 'Domain: ' + r.domain + '\n';
    report += 'Date: ' + new Date(r.timestamp).toLocaleString() + '\n';
    report += 'Overall Score: ' + (r.overallScore !== null ? r.overallScore + '/100' : 'Partial (some categories require Pentest Console)') + ' (Grade: ' + r.overallGrade + ')\n\n';

    report += '--- CATEGORY SCORES ---\n';
    var catNames = { dns: 'DNS Security', email: 'Email Security', tls: 'SSL/TLS', headers: 'HTTP Headers', technology: 'Tech Exposure', cloud: 'Cloud Security' };
    Object.keys(r.categories).forEach(function(key) {
      var cat = r.categories[key];
      report += (catNames[key] || key) + ': ' + (cat.score !== null ? cat.score + '/100' : 'N/A (requires Pentest Console)') + ' (' + cat.grade + ')\n';
    });

    report += '\n--- FINDINGS (sorted by severity) ---\n';
    allFindings.forEach(function(f, i) {
      report += '\n[' + (i + 1) + '] [' + f.severity.toUpperCase() + '] ' + f.finding + '\n';
      report += '    Category: ' + f.category + '\n';
      report += '    Fix: ' + f.recommendation + '\n';
    });

    report += '\n--- REMEDIATION PRIORITIES ---\n';
    report += '1. Fix all CRITICAL findings immediately\n';
    report += '2. Address HIGH findings within 7 days\n';
    report += '3. Remediate MEDIUM findings within 30 days\n';
    report += '4. Schedule LOW findings for next maintenance window\n';

    var html = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">' +
      '<h2 class="pg-h2" style="margin:0">Assessment Report</h2>' +
      '<span style="flex:1"></span>' +
      '<button class="btn sm" id="asm-copy">Copy Report</button>' +
    '</div>' +
    '<pre style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px;font-size:.78rem;white-space:pre-wrap;max-height:500px;overflow-y:auto;color:var(--txt);line-height:1.6">' + esc(report) + '</pre>';

    setTimeout(function() {
      var btn = main.querySelector('#asm-copy');
      if (btn) btn.onclick = function() {
        navigator.clipboard.writeText(report).then(function() { btn.textContent = 'Copied!'; setTimeout(function() { btn.textContent = 'Copy Report'; }, 1500); });
      };
    }, 0);

    return html;
  }

  render();
}
