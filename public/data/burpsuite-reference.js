// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Comprehensive Burp Suite Reference — tools, intruder attacks, payloads, workflows

export const BURP_TOOLS = [
  { name: "Proxy", description: "Intercepts HTTP/S traffic between the browser and target. The core of Burp — capture, inspect, and modify requests/responses in real time. Set browser proxy to 127.0.0.1:8080.", features: ["Intercept toggle", "HTTP history", "WebSocket history", "Match and replace rules", "TLS pass-through", "Response modification", "Request drop/forward/send to tools"], shortcuts: { "Forward": "Ctrl+F", "Drop": "Ctrl+D", "Toggle intercept": "Ctrl+T", "Send to Repeater": "Ctrl+R", "Send to Intruder": "Ctrl+I" } },
  { name: "Scanner", description: "Automated vulnerability scanner. Active scanning sends attack payloads; passive scanning analyzes proxy traffic. Detects SQLi, XSS, SSRF, XXE, command injection, path traversal, and hundreds more.", features: ["Passive scanning (on proxy traffic)", "Active scanning (sends payloads)", "Crawl and audit", "JavaScript analysis", "Scan configurations (speed vs coverage)", "Issue definitions with remediation", "Confidence levels: Certain, Firm, Tentative"], scan_types: ["Crawl only", "Audit only", "Crawl and audit"] },
  { name: "Intruder", description: "Automated customized attacks. Define positions in a request template, select an attack type, load payloads, and run. Used for brute forcing, parameter fuzzing, enumeration, and token analysis.", features: ["4 attack types", "30+ payload types", "Payload processing rules", "Grep match/extract", "Resource pool (throttling)", "Follow redirects", "Multiple payload sets"] },
  { name: "Repeater", description: "Manual request modification and resending. Edit any part of a request and see the response immediately. Essential for manual testing and exploit development.", features: ["Multiple tabs", "Request/response side-by-side", "Follow redirects toggle", "HTTP/1 and HTTP/2", "Render HTML response", "Inspector (decoded parameters)", "Send group (parallel)"] },
  { name: "Sequencer", description: "Analyze the quality of randomness in tokens (session IDs, CSRF tokens, password reset tokens). Statistical tests determine if tokens are predictable.", features: ["Live capture from response", "Manual token load", "FIPS tests", "Character-level analysis", "Bit-level analysis", "Overall entropy rating"], tests: ["Monobit", "Block frequency", "Runs", "Long runs", "Spectral", "Cumulative sums", "Approximate entropy", "Serial"] },
  { name: "Decoder", description: "Transform data between encodings. Supports URL, HTML, Base64, hex, octal, binary, gzip, and custom encoding chains.", encodings: ["URL encoding", "HTML encoding", "Base64", "ASCII hex", "Octal", "Binary", "Gzip", "Hash: MD5", "Hash: SHA-1", "Hash: SHA-256", "Hash: SHA-512"] },
  { name: "Comparer", description: "Visual diff of two HTTP requests or responses. Highlights differences word-by-word or byte-by-byte. Useful for identifying subtle response changes.", modes: ["Word-level diff", "Byte-level diff", "Sync scrolling"] },
  { name: "Logger", description: "Comprehensive HTTP logging. Records all requests from every Burp tool with full details. Filterable by tool, status, MIME type, extension, and search terms.", features: ["Filter by tool source", "Capture filter", "Display filter", "Column sorting", "Export"] },
  { name: "Organizer", description: "Store and annotate interesting requests and responses during testing. Create notes, color-code findings, and organize them for reporting.", features: ["Notes per item", "Color coding", "Custom columns", "Sorting", "Export for reports"] },
  { name: "DOM Invader", description: "Browser extension for DOM XSS testing. Inject canaries into sources, track data flow through the DOM, and detect when it reaches dangerous sinks.", features: ["Canary injection", "Source/sink tracking", "Postmessage interception", "Prototype pollution detection", "DOM clobbering detection"] },
  { name: "Collaborator", description: "External service for detecting out-of-band interactions (blind SSRF, blind XSS, blind SQLi, DNS exfiltration). Uses unique subdomains per payload.", interaction_types: ["DNS lookup", "HTTP request", "SMTP connection"], usage: "Insert Collaborator payloads in injection points. If the server makes a request to the payload URL, you get a callback confirming the vulnerability." },
];

export const BURP_INTRUDER_ATTACKS = [
  { type: "Sniper", description: "One payload set, one position at a time. Tests each position with each payload while other positions hold their original value. Best for: testing individual parameters for vulnerabilities.", positions: "single", payload_sets: 1, requests: "positions × payloads", example: "Testing each parameter for SQLi one at a time: ?user=PAYLOAD&pass=original, then ?user=original&pass=PAYLOAD" },
  { type: "Battering Ram", description: "One payload set, all positions simultaneously. Every position gets the same payload at the same time. Best for: testing the same value in multiple places (e.g., username in both a form field and a cookie).", positions: "all simultaneously", payload_sets: 1, requests: "payloads", example: "Testing same credential in multiple fields: ?user=PAYLOAD&email=PAYLOAD&backup_user=PAYLOAD" },
  { type: "Pitchfork", description: "Multiple payload sets, one per position, iterated in parallel. Position 1 gets payload 1 from set 1, position 2 gets payload 1 from set 2, etc. Best for: credential stuffing with known username:password pairs.", positions: "matched parallel", payload_sets: "one per position", requests: "min(set sizes)", example: "Credential stuffing: ?user=admin&pass=admin123, then ?user=root&pass=toor (matched pairs)" },
  { type: "Cluster Bomb", description: "Multiple payload sets, every combination tested. Position 1 gets each payload from set 1 × position 2 gets each payload from set 2. Cartesian product. Best for: brute force with username and password lists.", positions: "all combinations", payload_sets: "one per position", requests: "set1 × set2 × ... × setN", example: "Brute force: tries every username with every password. 100 users × 1000 passwords = 100,000 requests." },
];

export const BURP_PAYLOAD_TYPES = [
  { name: "Simple list", description: "A list of strings to use as payloads. The most common type.", use_case: "Wordlists, known values, specific test strings" },
  { name: "Runtime file", description: "Read payloads from a file at runtime. Better for large wordlists — doesn't load all into memory.", use_case: "Large wordlists (rockyou, SecLists)" },
  { name: "Custom iterator", description: "Generate payloads by combining multiple lists with separators. Creates structured payloads like user@domain or first.last.", use_case: "Email enumeration, username generation" },
  { name: "Character substitution", description: "Take a base string and substitute characters (a→@, s→$, etc.). Generates leet speak variations.", use_case: "Password mutation" },
  { name: "Case modification", description: "Generate case variations of payload strings (upper, lower, proper, inverted).", use_case: "Case-sensitive bypass testing" },
  { name: "Recursive grep", description: "Extract payloads from the previous response using regex. Chain-extract tokens or values across requests.", use_case: "CSRF token extraction, pagination" },
  { name: "Illegal Unicode", description: "Generate illegal Unicode representations of characters for bypass testing.", use_case: "WAF bypass, input validation bypass" },
  { name: "Character blocks", description: "Generate strings of repeated characters at specified lengths. For buffer overflow and length limit testing.", use_case: "Buffer overflow testing, input length limits" },
  { name: "Numbers", description: "Generate sequential or random numbers in a range with configurable step, format, and padding.", use_case: "IDOR testing, ID enumeration, brute force PINs" },
  { name: "Dates", description: "Generate dates in configurable formats within a range.", use_case: "Date-based access control testing" },
  { name: "Brute forcer", description: "Generate all permutations of a character set up to a specified length.", use_case: "Short token brute force, PIN cracking" },
  { name: "Null payloads", description: "Send the request repeatedly with no payload modification. Useful for race conditions and timing analysis.", use_case: "Race condition testing, rate limiting analysis" },
  { name: "Username generator", description: "Generate username formats from a list of names (jsmith, j.smith, john.smith, smithj, etc.).", use_case: "Username enumeration" },
  { name: "ECB block shuffler", description: "Shuffle ECB-encrypted blocks to test for block cipher vulnerabilities.", use_case: "ECB mode detection and exploitation" },
  { name: "Bit flipper", description: "Flip individual bits in the original value. For testing token integrity and MAC bypass.", use_case: "Token manipulation, MAC bypass" },
  { name: "Extension-generated", description: "Generate payloads via a Burp extension.", use_case: "Custom payload generation logic" },
  { name: "Copy other payload", description: "Copy the value from another payload position.", use_case: "Matching values across positions" },
];

export const BURP_PAYLOAD_PROCESSING = [
  { rule: "Add prefix", description: "Add a string before each payload", example: "admin_" },
  { rule: "Add suffix", description: "Add a string after each payload", example: "_test" },
  { rule: "Match/replace", description: "Regex find and replace within each payload" },
  { rule: "Substring", description: "Extract a substring from each payload" },
  { rule: "Reverse substring", description: "Extract from the end of each payload" },
  { rule: "Modify case", description: "Change case (to upper, to lower, invert)" },
  { rule: "Encode", description: "Apply encoding (URL, HTML, Base64, hex, etc.)" },
  { rule: "Decode", description: "Apply decoding (URL, HTML, Base64, hex, etc.)" },
  { rule: "Hash", description: "Hash the payload (MD5, SHA-1, SHA-256, SHA-512)" },
  { rule: "Skip if matches regex", description: "Skip payloads matching a regular expression" },
  { rule: "Invoke Burp extension", description: "Process payload through an extension" },
];

export const BURP_WORKFLOWS = [
  { name: "SQL Injection Testing", steps: ["Proxy → capture request with parameters", "Send to Repeater → test single quotes, UNION, boolean-based manually", "Send to Intruder → set parameter as position", "Load SQLi payload list (SecLists/Fuzzing/SQLi)", "Sniper attack → check response length/status differences", "Grep match for SQL error strings", "Confirm with sqlmap if found"] },
  { name: "XSS Discovery", steps: ["Proxy → identify reflected parameters", "Repeater → inject basic payloads (<script>alert(1)</script>)", "Check response for unencoded reflection", "Intruder → fuzz with XSS polyglot payloads", "DOM Invader → inject canary for DOM XSS", "Check Content-Type and CSP headers", "Test stored XSS via comment/profile fields"] },
  { name: "Authentication Testing", steps: ["Proxy → capture login request", "Intruder → Cluster Bomb with username + password lists", "Grep match for success indicators (redirect, welcome, dashboard)", "Grep extract response length for enumeration", "Test account lockout by sending 20+ requests for one user", "Test password reset flow for token predictability (Sequencer)", "Check session token entropy (Sequencer)"] },
  { name: "IDOR Testing", steps: ["Proxy → identify requests with IDs/UUIDs", "Repeater → change ID to another user's", "Check if unauthorized data is returned", "Intruder → Numbers payload type for ID enumeration", "Test both GET and POST with ID manipulation", "Check horizontal (same role) and vertical (different role) access"] },
  { name: "SSRF Testing", steps: ["Identify URL parameters, webhook URLs, file imports", "Repeater → replace URL with Collaborator payload", "Check for DNS/HTTP interactions in Collaborator", "Test internal IPs: 127.0.0.1, 169.254.169.254 (cloud metadata)", "Test URL scheme bypass: file://, gopher://, dict://", "Test DNS rebinding if IP filtering is present"] },
  { name: "File Upload Testing", steps: ["Proxy → capture upload request", "Repeater → modify Content-Type header", "Test extension bypass: .php5, .phtml, .php.jpg", "Test null byte: shell.php%00.jpg", "Test double extension: shell.php.jpg", "Upload SVG with embedded JavaScript", "Check if uploaded file is accessible and executable"] },
  { name: "JWT Testing", steps: ["Proxy → capture request with JWT", "Decoder → decode JWT header and payload", "Change algorithm to 'none' and remove signature", "Change algorithm from RS256 to HS256 (key confusion)", "Brute force weak HMAC signing keys", "Modify claims (role, user ID, expiry)", "Test with expired token (check if server validates exp)"] },
];

export const BURP_SHORTCUTS = [
  { shortcut: "Ctrl+R", action: "Send to Repeater" },
  { shortcut: "Ctrl+I", action: "Send to Intruder" },
  { shortcut: "Ctrl+Shift+R", action: "Send to Repeater (new tab)" },
  { shortcut: "Ctrl+Shift+I", action: "Send to Intruder (new tab)" },
  { shortcut: "Ctrl+T", action: "Toggle intercept (Proxy)" },
  { shortcut: "Ctrl+F", action: "Forward intercepted request" },
  { shortcut: "Ctrl+D", action: "Drop intercepted request" },
  { shortcut: "Ctrl+Shift+T", action: "Switch Repeater tab" },
  { shortcut: "Ctrl+Space", action: "Send request (Repeater)" },
  { shortcut: "Ctrl+Shift+U", action: "URL encode selection" },
  { shortcut: "Ctrl+Shift+B", action: "Base64 encode selection" },
  { shortcut: "Ctrl+Shift+H", action: "HTML encode selection" },
  { shortcut: "Ctrl+Z", action: "Undo" },
  { shortcut: "Ctrl+Shift+Z", action: "Redo" },
  { shortcut: "Ctrl+F", action: "Find in editor" },
  { shortcut: "Ctrl+G", action: "Go to line" },
  { shortcut: "Ctrl+Plus/Minus", action: "Increase/decrease font size" },
];

export const BURP_MATCH_REPLACE = [
  { type: "Request header", example: "Match: User-Agent: .* → Replace: User-Agent: Googlebot/2.1", use_case: "Spoof user agent" },
  { type: "Request header", example: "Match: ^$ → Replace: X-Forwarded-For: 127.0.0.1", use_case: "Add header to bypass IP restrictions" },
  { type: "Request body", example: "Match: role=user → Replace: role=admin", use_case: "Privilege escalation testing" },
  { type: "Response header", example: "Match: X-Frame-Options: .* → Replace: (empty)", use_case: "Remove clickjacking protection for testing" },
  { type: "Response header", example: "Match: Content-Security-Policy: .* → Replace: (empty)", use_case: "Remove CSP for XSS testing" },
  { type: "Response body", example: "Match: <input type=\"hidden\" → Replace: <input type=\"text\"", use_case: "Reveal hidden form fields" },
  { type: "Response body", example: "Match: disabled=\"disabled\" → Replace: (empty)", use_case: "Enable disabled form fields" },
  { type: "Request first line", example: "Match: HTTP/1.1 → Replace: HTTP/2", use_case: "Force HTTP version" },
];
