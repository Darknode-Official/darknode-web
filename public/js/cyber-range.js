const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

var RANGE_STORAGE_KEY = "dn_cyber_range_v1";

var DIFFICULTY = { 1: "Easy", 2: "Medium", 3: "Hard", 4: "Expert", 5: "Insane" };
var DIFF_CLR = { 1: "#3fb950", 2: "#d29922", 3: "#f85149", 4: "#bc4dff", 5: "#ff1744" };

var CATEGORIES = [
  { id: "web", name: "Web Exploitation", icon: "[WEB]", desc: "SQL injection, XSS, SSRF, SSTI, auth bypass, deserialization" },
  { id: "pwn", name: "Binary Exploitation", icon: "[PWN]", desc: "Buffer overflow, ROP chains, format strings, heap exploitation" },
  { id: "crypto", name: "Cryptography", icon: "[CRY]", desc: "Classical ciphers, RSA, AES, hash cracking, side channels" },
  { id: "forensics", name: "Digital Forensics", icon: "[FOR]", desc: "Disk analysis, memory forensics, network captures, steganography" },
  { id: "rev", name: "Reverse Engineering", icon: "[REV]", desc: "Static analysis, dynamic analysis, deobfuscation, malware RE" },
  { id: "network", name: "Network Security", icon: "[NET]", desc: "Packet analysis, protocol exploitation, MITM, wireless" },
  { id: "osint", name: "OSINT", icon: "[OSI]", desc: "Open source intelligence gathering, social media, geolocation" },
  { id: "privesc", name: "Privilege Escalation", icon: "[PRV]", desc: "Linux/Windows privesc, SUID abuse, kernel exploits, misconfigs" },
  { id: "cloud", name: "Cloud Security", icon: "[CLD]", desc: "AWS/Azure/GCP exploitation, IAM abuse, serverless attacks" },
  { id: "misc", name: "Miscellaneous", icon: "[MSC]", desc: "Scripting, programming, logic puzzles, unconventional challenges" },
];

var CHALLENGES = [
  { id: "sqli-101", cat: "web", title: "SQL Injection 101", diff: 1, pts: 100, flag: "FLAG{sql_1nj3ct10n_b4s1cs}", solves: 2847, desc: "A simple login form vulnerable to SQL injection. Can you bypass authentication?",
    hints: ["Try entering a single quote in the username field", "Think about how SQL queries handle string comparison", "The classic payload: ' OR 1=1 --"],
    setup: "You're given a login page at http://target:8080/login. The backend uses a MySQL database with a users table.",
    walkthrough: "1. The login form concatenates user input directly into SQL\n2. Input: ' OR 1=1 -- in username, anything in password\n3. The query becomes: SELECT * FROM users WHERE username='' OR 1=1 --' AND password='...'\n4. OR 1=1 always evaluates to true\n5. -- comments out the rest of the query\n6. You're logged in as the first user (usually admin)" },
  { id: "xss-reflected", cat: "web", title: "Reflected XSS", diff: 1, pts: 100, flag: "FLAG{r3fl3ct3d_x55_ftw}", solves: 2103, desc: "Find and exploit a reflected XSS vulnerability in the search functionality.",
    hints: ["Check the search parameter in the URL", "Try injecting HTML tags first", "Use <script>alert(document.cookie)</script>"],
    setup: "A search page at http://target:8080/search reflects user input without sanitization.",
    walkthrough: "1. Enter a search term — notice it's reflected in the page\n2. Try: <b>test</b> — if it renders bold, HTML injection works\n3. Payload: <script>alert(document.cookie)</script>\n4. The flag is in the admin's cookie, retrieved via XSS" },
  { id: "ssrf-internal", cat: "web", title: "SSRF to Internal Service", diff: 2, pts: 200, flag: "FLAG{ssrf_1nt3rn4l_4cc3ss}", solves: 1456, desc: "Exploit a server-side request forgery to access an internal admin panel.",
    hints: ["The URL fetch feature can be abused", "Try accessing http://127.0.0.1:3000", "Internal services often run on non-standard ports"],
    setup: "A web application has a 'preview URL' feature that fetches remote pages. An internal admin panel runs on port 3000.",
    walkthrough: "1. The preview feature makes server-side HTTP requests\n2. Input: http://127.0.0.1:3000/admin\n3. The server fetches the internal admin page and returns it\n4. The admin panel reveals the flag" },
  { id: "ssti-jinja", cat: "web", title: "Server-Side Template Injection", diff: 3, pts: 300, flag: "FLAG{sst1_j1nj4_rc3}", solves: 892, desc: "Exploit Jinja2 SSTI to achieve remote code execution.",
    hints: ["Try injecting {{7*7}} to test for SSTI", "Jinja2 has access to Python builtins via MRO", "{{config}} might reveal secrets"],
    setup: "A Flask application renders user-controlled input through Jinja2 templates.",
    walkthrough: "1. Test: {{7*7}} — if it returns 49, SSTI confirmed\n2. Read config: {{config.items()}}\n3. RCE payload: {{''.__class__.__mro__[1].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()}}\n4. Find the subprocess.Popen class index and execute commands" },
  { id: "jwt-none", cat: "web", title: "JWT Algorithm Confusion", diff: 2, pts: 200, flag: "FLAG{jwt_n0n3_4lg0}", solves: 1678, desc: "Bypass JWT authentication by exploiting algorithm confusion.",
    hints: ["Decode the JWT token — what algorithm is used?", "Try changing the algorithm to 'none'", "Remove the signature entirely"],
    setup: "An API uses JWT for authentication. The token is stored in a cookie.",
    walkthrough: "1. Decode the JWT: header.payload.signature\n2. Change header 'alg' from 'HS256' to 'none'\n3. Modify payload: change 'role' from 'user' to 'admin'\n4. Send token with empty signature: header.payload.\n5. The server accepts alg:none and grants admin access" },
  { id: "deser-java", cat: "web", title: "Java Deserialization RCE", diff: 4, pts: 400, flag: "FLAG{j4v4_d3s3r14l1z4t10n}", solves: 432, desc: "Exploit unsafe Java deserialization to achieve remote code execution.",
    hints: ["The application accepts serialized Java objects", "Use ysoserial to generate payloads", "Try the CommonsCollections gadget chains"],
    setup: "A Java web application accepts serialized objects via a custom HTTP header.",
    walkthrough: "1. Identify the deserialization entry point (X-Data header)\n2. Generate payload: ysoserial CommonsCollections1 'cat /flag.txt'\n3. Base64 encode and send as the header value\n4. The gadget chain triggers Runtime.exec()\n5. Exfiltrate the flag via out-of-band (OOB) or command output" },

  { id: "bof-basic", cat: "pwn", title: "Stack Buffer Overflow", diff: 1, pts: 100, flag: "FLAG{st4ck_sm4sh1ng}", solves: 1923, desc: "Overflow a stack buffer to overwrite the return address and redirect execution.",
    hints: ["Find the offset to the return address", "Use pattern_create to find the exact offset", "Where is the win() function?"],
    setup: "A 32-bit ELF binary reads input with gets() and has a win() function at 0x080491f6.",
    walkthrough: "1. Disassemble: find vulnerable gets() call in main()\n2. Buffer is 64 bytes + 4 bytes saved EBP = 68 bytes to return address\n3. Payload: 'A'*68 + p32(0x080491f6)\n4. The return address now points to win()\n5. win() prints the flag" },
  { id: "rop-chain", cat: "pwn", title: "Return-Oriented Programming", diff: 3, pts: 300, flag: "FLAG{r0p_ch41n_m4st3r}", solves: 567, desc: "Build a ROP chain to bypass NX and call system('/bin/sh').",
    hints: ["NX is enabled — no shellcode execution on stack", "Find useful gadgets with ROPgadget", "You need: pop rdi; ret and the address of /bin/sh"],
    setup: "A 64-bit binary with NX enabled. libc is provided. ASLR is disabled for simplicity.",
    walkthrough: "1. Leak a libc address from the GOT\n2. Calculate libc base address\n3. Find gadgets: pop rdi; ret in the binary\n4. Find /bin/sh string in libc\n5. Chain: pop_rdi -> /bin/sh_addr -> system_addr\n6. Send payload and get a shell" },
  { id: "heap-uaf", cat: "pwn", title: "Heap Use-After-Free", diff: 4, pts: 400, flag: "FLAG{h34p_u4f_3xpl01t}", solves: 234, desc: "Exploit a use-after-free vulnerability in the heap to get arbitrary write.",
    hints: ["Allocate, free, then allocate again — what happens?", "The tcache keeps freed chunks in a LIFO list", "Overwrite the fd pointer of a freed chunk"],
    setup: "A note-taking application with add/edit/delete/view. The delete function doesn't NULL the pointer.",
    walkthrough: "1. Create note A (size 0x20)\n2. Delete note A — chunk goes to tcache\n3. Create note B (same size) — reuses A's memory\n4. Edit A (use-after-free) — overwrites B's data\n5. Leverage this for arbitrary write primitive\n6. Overwrite __free_hook with system address" },

  { id: "caesar", cat: "crypto", title: "Caesar Cipher", diff: 1, pts: 50, flag: "FLAG{c43s4r_sh1ft}", solves: 3241, desc: "Decrypt a message encrypted with a Caesar cipher.",
    hints: ["Caesar cipher shifts each letter by a fixed amount", "There are only 25 possible shifts", "Try frequency analysis or brute force all shifts"],
    setup: "Ciphertext: SYNT{p43f4e_fu1sg} — this looks like a ROT13 variant.",
    walkthrough: "1. Caesar cipher = character rotation\n2. ROT13 is shift of 13: A->N, B->O, etc.\n3. Decode SYNT{p43f4e_fu1sg} with ROT13\n4. S->F, Y->L, N->A, T->G = FLAG\n5. Result: FLAG{c43s4r_sh1ft}" },
  { id: "rsa-small-e", cat: "crypto", title: "RSA Small Exponent", diff: 2, pts: 200, flag: "FLAG{sm4ll_3_4tt4ck}", solves: 1245, desc: "Break RSA encryption when e=3 and the message is small.",
    hints: ["When e is small and m^e < n, no modular reduction occurs", "Simply compute the cube root of the ciphertext", "Python: pow(c, 1/3) or use gmpy2.iroot()"],
    setup: "n = large_number, e = 3, c = m^3 mod n. But m^3 < n.",
    walkthrough: "1. RSA: c = m^e mod n\n2. If m^e < n, then c = m^e (no mod reduction)\n3. Simply compute m = c^(1/3)\n4. Use gmpy2.iroot(c, 3) for exact integer cube root\n5. Convert m to bytes to get the flag" },
  { id: "padding-oracle", cat: "crypto", title: "Padding Oracle Attack", diff: 3, pts: 300, flag: "FLAG{p4dd1ng_0r4cl3}", solves: 678, desc: "Exploit a padding oracle to decrypt AES-CBC ciphertext without the key.",
    hints: ["The server returns different errors for bad padding vs. valid padding", "This side channel reveals information about each byte", "Work backwards from the last byte of each block"],
    setup: "A web application encrypts session data with AES-128-CBC. Invalid padding returns HTTP 500, valid padding returns HTTP 200 or 403.",
    walkthrough: "1. The oracle distinguishes valid vs invalid PKCS#7 padding\n2. For each byte (starting from the last): try all 256 values\n3. When the server accepts, you've found the intermediate value\n4. intermediate XOR original_ciphertext = plaintext\n5. Repeat for all bytes in all blocks\n6. Full plaintext recovery without knowing the key" },

  { id: "pcap-creds", cat: "forensics", title: "Packet Capture Analysis", diff: 1, pts: 100, flag: "FLAG{cl34rt3xt_cr3ds}", solves: 2567, desc: "Find credentials transmitted in cleartext in a network capture.",
    hints: ["Filter for HTTP POST requests", "Look for form data containing username/password", "Wireshark filter: http.request.method == POST"],
    setup: "A PCAP file containing network traffic from a corporate network. Someone logged into an HTTP (not HTTPS) application.",
    walkthrough: "1. Open PCAP in Wireshark\n2. Filter: http.request.method == POST\n3. Find the login request\n4. Right-click -> Follow HTTP Stream\n5. Credentials visible in POST body: admin / FLAG{cl34rt3xt_cr3ds}" },
  { id: "mem-forensics", cat: "forensics", title: "Memory Dump Analysis", diff: 2, pts: 200, flag: "FLAG{v0l4t1l1ty_m4st3r}", solves: 1234, desc: "Analyze a Windows memory dump to find a hidden process and extract its secrets.",
    hints: ["Use Volatility 3 for memory analysis", "Check the process list for suspicious entries", "Try dumping the process memory"],
    setup: "A Windows memory dump from a compromised workstation. A malicious process is running disguised as a system process.",
    walkthrough: "1. vol3 -f mem.raw windows.pslist — list processes\n2. Notice svchost.exe running from unusual path\n3. vol3 -f mem.raw windows.cmdline — check command lines\n4. vol3 -f mem.raw windows.dumpfiles --pid <PID>\n5. Strings analysis on dumped file reveals the flag" },
  { id: "stego-png", cat: "forensics", title: "PNG Steganography", diff: 2, pts: 200, flag: "FLAG{h1dd3n_1n_p1x3ls}", solves: 1567, desc: "Extract hidden data from a PNG image using steganography techniques.",
    hints: ["Check the LSB of each pixel's color channels", "Tools: zsteg, stegsolve, or manual extraction", "The data might be in just the red channel"],
    setup: "A seemingly normal PNG image that contains a hidden message in the least significant bits.",
    walkthrough: "1. Run: zsteg image.png\n2. Check LSB of each channel combination\n3. zsteg finds: b1,r,lsb,xy contains the flag\n4. Or manually: extract bit 0 of red channel for each pixel\n5. Convert bits to ASCII to get the flag" },

  { id: "re-crackme", cat: "rev", title: "CrackMe Basic", diff: 1, pts: 100, flag: "FLAG{r3v3rs3_3ng1n33r}", solves: 2345, desc: "Reverse engineer a binary to find the correct password.",
    hints: ["Use Ghidra or IDA to decompile", "Look for string comparisons in main()", "The password is hardcoded in the binary"],
    setup: "A Linux ELF binary that asks for a password and prints 'Access Granted' or 'Access Denied'.",
    walkthrough: "1. Run: strings crackme | grep FLAG — sometimes it's that easy\n2. If obfuscated: open in Ghidra\n3. Find main() -> locate strcmp/memcmp call\n4. The compared string is the password/flag\n5. Or: ltrace ./crackme to trace library calls and see the comparison" },
  { id: "re-antidebug", cat: "rev", title: "Anti-Debug Bypass", diff: 3, pts: 300, flag: "FLAG{n0_d3bugg3r_h3r3}", solves: 567, desc: "Bypass multiple anti-debugging techniques to reach the flag.",
    hints: ["The binary checks IsDebuggerPresent and ptrace", "Patch the checks or use LD_PRELOAD", "There's also a timing check — use hardware breakpoints"],
    setup: "A binary with multiple anti-debugging protections: ptrace self-trace, timing checks, and environment detection.",
    walkthrough: "1. ptrace check: LD_PRELOAD a library that hooks ptrace to return 0\n2. Timing check: set hardware breakpoints instead of software\n3. Environment check: unset LINES and COLUMNS\n4. Or: binary patch all check instructions to NOP (0x90)\n5. With all checks bypassed, the binary reveals the flag" },

  { id: "net-pcap", cat: "network", title: "Wireshark Challenge", diff: 1, pts: 100, flag: "FLAG{p4ck3t_sn1ff3r}", solves: 2890, desc: "Analyze network traffic to find exfiltrated data.",
    hints: ["Look for DNS queries with unusual subdomains", "Data might be base64 encoded in DNS names", "Filter: dns.qry.type == 1"],
    setup: "A PCAP with normal traffic and DNS-based data exfiltration.",
    walkthrough: "1. Filter DNS queries: dns.qry.type == 1\n2. Notice long subdomain queries to evil.com\n3. Extract the subdomain parts: aGVsbG8=.evil.com\n4. Concatenate and base64 decode the subdomains\n5. Decoded data contains the flag" },

  { id: "osint-image", cat: "osint", title: "Image Geolocation", diff: 1, pts: 100, flag: "FLAG{g30l0c4t10n}", solves: 1876, desc: "Determine the location where a photograph was taken using OSINT techniques.",
    hints: ["Check EXIF data for GPS coordinates", "Look for identifiable landmarks in the image", "Google reverse image search can help"],
    setup: "An image taken at an unknown location. Find the exact coordinates.",
    walkthrough: "1. exiftool image.jpg — check GPS coordinates in EXIF\n2. If no EXIF: look for street signs, landmarks, language on signs\n3. Use Google Maps Street View to confirm\n4. Cross-reference with Google Lens reverse image search" },

  { id: "linux-privesc", cat: "privesc", title: "Linux SUID Exploitation", diff: 1, pts: 100, flag: "FLAG{su1d_pr1v3sc}", solves: 2456, desc: "Exploit a misconfigured SUID binary to escalate to root.",
    hints: ["Run: find / -perm -4000 2>/dev/null", "Check GTFOBins for exploitation techniques", "Some binaries can read/write files as root"],
    setup: "A Linux system where you have a low-privilege shell. A custom SUID binary is installed.",
    walkthrough: "1. find / -perm -4000 -type f 2>/dev/null\n2. Find /usr/bin/custom-backup (SUID root)\n3. The binary copies files — it runs tar as root\n4. Exploit: create a malicious tar checkpoint action\n5. --checkpoint=1 --checkpoint-action=exec=/bin/sh\n6. Get root shell, read /root/flag.txt" },
  { id: "win-privesc", cat: "privesc", title: "Windows Service Exploitation", diff: 2, pts: 200, flag: "FLAG{w1n_s3rv1c3_pr1v3sc}", solves: 1234, desc: "Exploit a misconfigured Windows service to escalate to SYSTEM.",
    hints: ["Check service permissions with accesschk.exe", "Look for unquoted service paths", "Services running as SYSTEM with weak file permissions"],
    setup: "A Windows server with a vulnerable service. You have a standard user account.",
    walkthrough: "1. sc query state= all — list all services\n2. Check for unquoted service paths with spaces\n3. Or: icacls on the service binary — is it writable?\n4. Replace the binary with a reverse shell payload\n5. Restart the service — it runs as SYSTEM\n6. Read C:\\Users\\Administrator\\flag.txt" },

  { id: "aws-s3", cat: "cloud", title: "S3 Bucket Misconfiguration", diff: 1, pts: 100, flag: "FLAG{s3_m1sc0nf1g}", solves: 1987, desc: "Find and exploit a misconfigured S3 bucket to access sensitive data.",
    hints: ["Try listing bucket contents without credentials", "Common bucket names follow patterns: company-backup, company-data", "aws s3 ls s3://bucket-name --no-sign-request"],
    setup: "A company's S3 bucket has overly permissive ACLs. Find it and extract the flag.",
    walkthrough: "1. Enumerate bucket names: company-backup, company-data, company-secret\n2. aws s3 ls s3://company-backup --no-sign-request\n3. Find a file: credentials/flag.txt\n4. aws s3 cp s3://company-backup/credentials/flag.txt . --no-sign-request\n5. Read the flag" },
  { id: "iam-escalation", cat: "cloud", title: "IAM Privilege Escalation", diff: 3, pts: 300, flag: "FLAG{14m_pr1v3sc}", solves: 456, desc: "Escalate IAM privileges in AWS to gain admin access.",
    hints: ["Check what permissions your current role has", "iam:PassRole + lambda:CreateFunction = privesc", "Can you create a Lambda function with an admin role?"],
    setup: "You have AWS credentials with limited permissions. Find a privilege escalation path.",
    walkthrough: "1. aws iam list-attached-user-policies — check permissions\n2. You have: iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction\n3. Create a Lambda function that assumes the admin role\n4. The function reads the flag from a secret S3 bucket\n5. Invoke the function — flag returned in response" },

  { id: "misc-jail", cat: "misc", title: "Python Jail Escape", diff: 2, pts: 200, flag: "FLAG{j41l_3sc4p3}", solves: 1567, desc: "Escape a restricted Python sandbox to read the flag file.",
    hints: ["Many builtins are blocked — find alternatives", "Use __import__ through subclass traversal", "The os module might be reachable via __builtins__"],
    setup: "A Python sandbox that filters dangerous functions. You can execute Python code but import, eval, exec, open are blocked.",
    walkthrough: "1. Direct import blocked — traverse the MRO\n2. ''.__class__.__mro__[1].__subclasses__() — list all classes\n3. Find _io.FileIO or subprocess.Popen in the list\n4. Use FileIO to read /flag.txt\n5. Or find os._wrap_close and access os.system()" },
];

var SCOREBOARD = [
  { rank: 1, team: "0xDEADBEEF", pts: 8750, solves: 32, country: "US" },
  { rank: 2, team: "CyberPhantoms", pts: 8200, solves: 30, country: "DE" },
  { rank: 3, team: "NullSec", pts: 7800, solves: 29, country: "KR" },
  { rank: 4, team: "Root@Evil", pts: 7350, solves: 27, country: "JP" },
  { rank: 5, team: "BinaryBandits", pts: 6900, solves: 26, country: "UK" },
  { rank: 6, team: "PacketStorm", pts: 6400, solves: 24, country: "IN" },
  { rank: 7, team: "ShellShockers", pts: 5850, solves: 22, country: "BR" },
  { rank: 8, team: "DarkMatter", pts: 5300, solves: 20, country: "CA" },
  { rank: 9, team: "ZeroDayHeroes", pts: 4900, solves: 19, country: "AU" },
  { rank: 10, team: "EliteCrew", pts: 4500, solves: 17, country: "FR" },
];

var TABS = [
  { id: "challenges", label: "Challenges" },
  { id: "scoreboard", label: "Scoreboard" },
  { id: "active", label: "Active Lab" },
  { id: "writeups", label: "Writeups" },
];

function loadProgress() {
  try {
    var d = JSON.parse(localStorage.getItem(RANGE_STORAGE_KEY)) || {};
    return { solved: d.solved || [], hints: d.hints || {}, points: d.points || 0, startTimes: d.startTimes || {} };
  } catch (_) { return { solved: [], hints: {}, points: 0, startTimes: {} }; }
}
function saveProgress(p) { try { localStorage.setItem(RANGE_STORAGE_KEY, JSON.stringify(p)); } catch (_) {} }

export function renderCyberRange(main) {
  var tab = "challenges";
  var activeChal = null;
  var filterCat = "";
  var filterDiff = 0;
  var progress = loadProgress();

  function render() {
    var tabsHTML = "";
    for (var i = 0; i < TABS.length; i++) {
      tabsHTML += '<button class="cr-tab' + (TABS[i].id === tab ? " active" : "") + '" data-tab="' + esc(TABS[i].id) + '">' + esc(TABS[i].label) + '</button>';
    }

    var body = "";
    if (tab === "challenges") body = renderChallenges();
    else if (tab === "scoreboard") body = renderScoreboard();
    else if (tab === "active") body = renderActiveLab();
    else if (tab === "writeups") body = renderWriteups();

    main.innerHTML =
      '<h1 class="pg-h1">Cyber Range</h1>' +
      '<p class="muted pg-sub">CTF-style challenges with interactive labs. Capture flags, earn points, rank up.</p>' +
      '<div class="cr-user-stats">' +
      '<div class="cr-ustat"><span class="cr-ustat-v">' + progress.points + '</span><span class="cr-ustat-l">Points</span></div>' +
      '<div class="cr-ustat"><span class="cr-ustat-v">' + progress.solved.length + '</span><span class="cr-ustat-l">Solved</span></div>' +
      '<div class="cr-ustat"><span class="cr-ustat-v">' + CHALLENGES.length + '</span><span class="cr-ustat-l">Total</span></div>' +
      '<div class="cr-ustat"><span class="cr-ustat-v">' + (CHALLENGES.length ? Math.round(progress.solved.length / CHALLENGES.length * 100) : 0) + '%</span><span class="cr-ustat-l">Completion</span></div>' +
      '</div>' +
      '<div class="cr-tabs">' + tabsHTML + '</div>' +
      '<div class="cr-body">' + body + '</div>';

    main.querySelectorAll(".cr-tab").forEach(function(btn) {
      btn.onclick = function() { tab = btn.dataset.tab; render(); };
    });
    bindEvents();
  }

  function renderChallenges() {
    var cats = "";
    cats += '<button class="cr-chip' + (filterCat === "" ? " active" : "") + '" data-fcat="">All</button>';
    for (var i = 0; i < CATEGORIES.length; i++) {
      var c = CATEGORIES[i];
      var count = CHALLENGES.filter(function(ch) { return ch.cat === c.id; }).length;
      cats += '<button class="cr-chip' + (filterCat === c.id ? " active" : "") + '" data-fcat="' + esc(c.id) + '">' + esc(c.name) + ' <span class="cr-chip-count">' + count + '</span></button>';
    }

    var diffs = '<button class="cr-chip' + (filterDiff === 0 ? " active" : "") + '" data-fdiff="0">All Levels</button>';
    for (var d = 1; d <= 5; d++) {
      diffs += '<button class="cr-chip' + (filterDiff === d ? " active" : "") + '" data-fdiff="' + d + '" style="border-color:' + DIFF_CLR[d] + '40">' + esc(DIFFICULTY[d]) + '</button>';
    }

    var filtered = CHALLENGES.filter(function(ch) {
      if (filterCat && ch.cat !== filterCat) return false;
      if (filterDiff && ch.diff !== filterDiff) return false;
      return true;
    });

    var cards = "";
    for (var i = 0; i < filtered.length; i++) {
      var ch = filtered[i];
      var solved = progress.solved.indexOf(ch.id) !== -1;
      var catObj = CATEGORIES.find(function(c) { return c.id === ch.cat; });
      cards +=
        '<div class="cr-chal' + (solved ? " cr-solved" : "") + '" data-cid="' + esc(ch.id) + '">' +
        (solved ? '<div class="cr-solved-badge">SOLVED</div>' : '') +
        '<div class="cr-chal-top">' +
        '<span class="cr-chal-cat">' + (catObj ? esc(catObj.icon) : '') + '</span>' +
        '<span class="cr-chal-pts">' + ch.pts + ' pts</span>' +
        '</div>' +
        '<h3 class="cr-chal-title">' + esc(ch.title) + '</h3>' +
        '<p class="cr-chal-desc">' + esc(ch.desc) + '</p>' +
        '<div class="cr-chal-footer">' +
        '<span class="cr-chal-diff" style="color:' + DIFF_CLR[ch.diff] + '">' + esc(DIFFICULTY[ch.diff]) + '</span>' +
        '<span class="cr-chal-solves">' + ch.solves + ' solves</span>' +
        '</div>' +
        '</div>';
    }

    return '<div class="cr-filters">' +
      '<div class="cr-filter-row">' + cats + '</div>' +
      '<div class="cr-filter-row">' + diffs + '</div>' +
      '</div>' +
      '<div class="cr-count">' + filtered.length + ' challenges</div>' +
      '<div class="cr-grid">' + cards + '</div>';
  }

  function renderScoreboard() {
    var rows = "";
    for (var i = 0; i < SCOREBOARD.length; i++) {
      var s = SCOREBOARD[i];
      var medal = s.rank === 1 ? " cr-gold" : s.rank === 2 ? " cr-silver" : s.rank === 3 ? " cr-bronze" : "";
      rows +=
        '<tr class="' + medal + '">' +
        '<td class="cr-sb-rank">#' + s.rank + '</td>' +
        '<td><strong>' + esc(s.team) + '</strong></td>' +
        '<td class="cr-sb-pts">' + s.pts.toLocaleString() + '</td>' +
        '<td>' + s.solves + '</td>' +
        '<td>' + esc(s.country) + '</td>' +
        '</tr>';
    }

    var yourRank = SCOREBOARD.length + 1;
    for (var i = 0; i < SCOREBOARD.length; i++) {
      if (progress.points > SCOREBOARD[i].pts) { yourRank = SCOREBOARD[i].rank; break; }
    }

    return '<div class="cr-sb-you">Your position: <strong>#' + yourRank + '</strong> with <strong>' + progress.points + '</strong> points</div>' +
      '<div class="cr-table-wrap"><table class="cr-table">' +
      '<thead><tr><th>Rank</th><th>Team</th><th>Points</th><th>Solves</th><th>Country</th></tr></thead>' +
      '<tbody>' + rows + '</tbody>' +
      '</table></div>';
  }

  function renderActiveLab() {
    if (!activeChal) {
      return '<div class="cr-no-lab">' +
        '<div class="cr-no-lab-icon">[&gt;_]</div>' +
        '<h3>No Active Lab</h3>' +
        '<p class="muted">Select a challenge from the Challenges tab to start a lab session.</p>' +
        '</div>';
    }

    var ch = CHALLENGES.find(function(c) { return c.id === activeChal; });
    if (!ch) return '<p>Challenge not found.</p>';

    var solved = progress.solved.indexOf(ch.id) !== -1;
    var hintCount = (progress.hints[ch.id] || []).length;
    var catObj = CATEGORIES.find(function(c) { return c.id === ch.cat; });

    var hintsHTML = "";
    for (var i = 0; i < ch.hints.length; i++) {
      var revealed = progress.hints[ch.id] && progress.hints[ch.id].indexOf(i) !== -1;
      hintsHTML +=
        '<div class="cr-hint' + (revealed ? " cr-hint-open" : "") + '">' +
        '<button class="cr-hint-btn" data-hintidx="' + i + '">' +
        (revealed ? esc(ch.hints[i]) : 'Hint ' + (i + 1) + ' (-' + ((i + 1) * 25) + ' pts) — Click to reveal') +
        '</button>' +
        '</div>';
    }

    return '<div class="cr-lab">' +
      '<div class="cr-lab-header">' +
      '<div>' +
      '<span class="cr-chal-cat">' + (catObj ? esc(catObj.icon) : '') + ' ' + (catObj ? esc(catObj.name) : '') + '</span>' +
      '<h2 class="cr-lab-title">' + esc(ch.title) + '</h2>' +
      '<span class="cr-chal-diff" style="color:' + DIFF_CLR[ch.diff] + '">' + esc(DIFFICULTY[ch.diff]) + '</span> ' +
      '<span class="cr-chal-pts">' + ch.pts + ' pts</span>' +
      '</div>' +
      (solved ? '<div class="cr-solved-big">SOLVED</div>' : '') +
      '</div>' +
      '<div class="cr-lab-section"><h3>Scenario</h3><p>' + esc(ch.setup) + '</p></div>' +
      '<div class="cr-lab-section"><h3>Objective</h3><p>' + esc(ch.desc) + '</p></div>' +
      '<div class="cr-lab-section"><h3>Hints</h3>' + hintsHTML + '</div>' +
      (solved ? '' :
        '<div class="cr-lab-section"><h3>Submit Flag</h3>' +
        '<div class="cr-flag-form">' +
        '<input class="cr-flag-input" id="cr-flag-input" placeholder="FLAG{...}" spellcheck="false">' +
        '<button class="cr-flag-submit" id="cr-flag-submit">Submit</button>' +
        '</div>' +
        '<div id="cr-flag-result"></div>' +
        '</div>') +
      '<div class="cr-lab-section">' +
      '<h3>Terminal</h3>' +
      '<div class="cr-terminal">' +
      '<div class="cr-term-header">darknode@range:~$</div>' +
      '<div class="cr-term-body" id="cr-term-body">' +
      '<div class="cr-term-line">Welcome to Darknode Cyber Range</div>' +
      '<div class="cr-term-line">Challenge: ' + esc(ch.title) + '</div>' +
      '<div class="cr-term-line">Type commands to interact with the target...</div>' +
      '<div class="cr-term-line">&nbsp;</div>' +
      '</div>' +
      '<div class="cr-term-input-row">' +
      '<span class="cr-term-prompt">$ </span>' +
      '<input class="cr-term-input" id="cr-term-input" spellcheck="false" autocomplete="off">' +
      '</div>' +
      '</div>' +
      '</div>' +
      '</div>';
  }

  function renderWriteups() {
    var solvedChals = CHALLENGES.filter(function(ch) { return progress.solved.indexOf(ch.id) !== -1; });
    if (solvedChals.length === 0) {
      return '<div class="cr-no-lab"><h3>No Writeups Yet</h3><p class="muted">Solve challenges to unlock their walkthroughs.</p></div>';
    }
    var items = "";
    for (var i = 0; i < solvedChals.length; i++) {
      var ch = solvedChals[i];
      items +=
        '<div class="cr-writeup">' +
        '<h3>' + esc(ch.title) + ' <span class="cr-chal-pts">' + ch.pts + ' pts</span></h3>' +
        '<pre class="cr-writeup-text">' + esc(ch.walkthrough) + '</pre>' +
        '</div>';
    }
    return '<p class="muted">Walkthroughs for solved challenges. Study the methodology for each attack type.</p>' + items;
  }

  function openChallenge(id) {
    activeChal = id;
    if (!progress.startTimes[id]) {
      progress.startTimes[id] = Date.now();
      saveProgress(progress);
    }
    tab = "active";
    render();
  }

  function submitFlag() {
    var input = main.querySelector("#cr-flag-input");
    var result = main.querySelector("#cr-flag-result");
    if (!input || !result || !activeChal) return;
    var ch = CHALLENGES.find(function(c) { return c.id === activeChal; });
    if (!ch) return;
    var flag = input.value.trim();
    if (!flag) { result.innerHTML = '<div class="cr-flag-wrong">Enter a flag.</div>'; return; }
    if (flag === ch.flag) {
      if (progress.solved.indexOf(ch.id) === -1) {
        var penalty = 0;
        if (progress.hints[ch.id]) penalty = progress.hints[ch.id].length * 25;
        var earned = Math.max(ch.pts - penalty, Math.floor(ch.pts * 0.25));
        progress.solved.push(ch.id);
        progress.points += earned;
        saveProgress(progress);
        result.innerHTML = '<div class="cr-flag-correct">Correct! +' + earned + ' points' + (penalty > 0 ? ' (-' + penalty + ' hint penalty)' : '') + '</div>';
        setTimeout(function() { render(); }, 1500);
      } else {
        result.innerHTML = '<div class="cr-flag-correct">Already solved!</div>';
      }
    } else {
      result.innerHTML = '<div class="cr-flag-wrong">Incorrect flag. Try again.</div>';
    }
  }

  function revealHint(chalId, idx) {
    if (!progress.hints[chalId]) progress.hints[chalId] = [];
    if (progress.hints[chalId].indexOf(idx) === -1) {
      progress.hints[chalId].push(idx);
      saveProgress(progress);
    }
    render();
  }

  function handleTerminalInput(cmd) {
    var body = main.querySelector("#cr-term-body");
    if (!body) return;
    var ch = CHALLENGES.find(function(c) { return c.id === activeChal; });
    cmd = cmd.trim();
    var output = "";

    if (cmd === "help") {
      output = "Available commands:\n  help        Show this help\n  whoami      Current user\n  id          User identity\n  ls          List files\n  cat <file>  Read file\n  nmap <ip>   Scan target\n  clear       Clear terminal\n  hint        Show next hint\n  flag        Show flag format";
    } else if (cmd === "whoami") {
      output = "ctf-player";
    } else if (cmd === "id") {
      output = "uid=1000(ctf-player) gid=1000(ctf-player) groups=1000(ctf-player)";
    } else if (cmd === "ls") {
      output = "challenge.txt  notes.md  tools/";
    } else if (cmd === "cat challenge.txt" || cmd === "cat ./challenge.txt") {
      output = ch ? ch.setup + "\n\nObjective: " + ch.desc : "No active challenge.";
    } else if (cmd === "clear") {
      body.innerHTML = "";
      return;
    } else if (cmd === "hint") {
      if (ch) {
        var nextHint = 0;
        if (progress.hints[ch.id]) nextHint = progress.hints[ch.id].length;
        if (nextHint < ch.hints.length) {
          revealHint(ch.id, nextHint);
          output = "Hint " + (nextHint + 1) + ": " + ch.hints[nextHint];
        } else { output = "No more hints available."; }
      }
    } else if (cmd === "flag") {
      output = "Flag format: FLAG{...}  Submit using the form above.";
    } else if (cmd.indexOf("nmap") === 0) {
      output = "Starting Nmap scan...\nPORT     STATE  SERVICE\n22/tcp   open   ssh\n80/tcp   open   http\n443/tcp  open   https\n3000/tcp open   grafana\n8080/tcp open   http-proxy\n\nNmap done: 1 IP address (1 host up), 5 ports open";
    } else if (cmd.indexOf("curl") === 0 || cmd.indexOf("wget") === 0) {
      output = "[Simulated] HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Target application response</body></html>";
    } else if (cmd.indexOf("sqlmap") === 0) {
      output = "[*] starting sqlmap...\n[*] testing connection to the target URL\n[*] testing for SQL injection\n[+] parameter 'id' is vulnerable\n[+] Type: UNION query\n[*] Use --dump to extract data";
    } else if (cmd) {
      output = cmd + ": command simulated (educational environment)";
    }

    if (output) {
      var lines = output.split("\n");
      for (var i = 0; i < lines.length; i++) {
        var div = document.createElement("div");
        div.className = "cr-term-line";
        div.textContent = lines[i] || "\u00a0";
        body.appendChild(div);
      }
    }
    var prompt = document.createElement("div");
    prompt.className = "cr-term-line cr-term-cmd";
    prompt.textContent = "$ " + cmd;
    body.insertBefore(prompt, body.lastElementChild);
    body.scrollTop = body.scrollHeight;
  }

  function bindEvents() {
    main.querySelectorAll("[data-cid]").forEach(function(card) {
      card.onclick = function() { openChallenge(card.dataset.cid); };
    });
    main.querySelectorAll("[data-fcat]").forEach(function(btn) {
      btn.onclick = function() { filterCat = btn.dataset.fcat; render(); };
    });
    main.querySelectorAll("[data-fdiff]").forEach(function(btn) {
      btn.onclick = function() { filterDiff = parseInt(btn.dataset.fdiff); render(); };
    });

    var flagBtn = main.querySelector("#cr-flag-submit");
    if (flagBtn) flagBtn.onclick = submitFlag;
    var flagInput = main.querySelector("#cr-flag-input");
    if (flagInput) flagInput.onkeydown = function(e) { if (e.key === "Enter") submitFlag(); };

    main.querySelectorAll(".cr-hint-btn").forEach(function(btn) {
      btn.onclick = function(e) {
        e.stopPropagation();
        if (activeChal) revealHint(activeChal, parseInt(btn.dataset.hintidx));
      };
    });

    var termInput = main.querySelector("#cr-term-input");
    if (termInput) {
      termInput.focus();
      termInput.onkeydown = function(e) {
        if (e.key === "Enter") {
          handleTerminalInput(termInput.value);
          termInput.value = "";
        }
      };
    }
  }

  render();
}
