// Password cracking reference and practice tool
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const HASH_PATTERNS = [
  { name: "MD5", regex: /^[a-fA-F0-9]{32}$/, hashcat: 0, john: "raw-md5", example: "5d41402abc4b2a76b9719d911017c592", speed: "164 GH/s" },
  { name: "SHA-1", regex: /^[a-fA-F0-9]{40}$/, hashcat: 100, john: "raw-sha1", example: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", speed: "26 GH/s" },
  { name: "SHA-256", regex: /^[a-fA-F0-9]{64}$/, hashcat: 1400, john: "raw-sha256", example: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", speed: "14 GH/s" },
  { name: "SHA-512", regex: /^[a-fA-F0-9]{128}$/, hashcat: 1700, john: "raw-sha512", example: "cf83e1357eefb8bdf1542850d66d8007...(128 hex chars)", speed: "5 GH/s" },
  { name: "NTLM", regex: /^[a-fA-F0-9]{32}$/, hashcat: 1000, john: "nt", example: "a4f49c406510bdcab6824ee7c30fd852", speed: "300 GH/s" },
  { name: "LM", regex: /^[a-fA-F0-9]{32}$/, hashcat: 3000, john: "lm", example: "aad3b435b51404eeaad3b435b51404ee", speed: "500 GH/s" },
  { name: "bcrypt", regex: /^\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53}$/, hashcat: 3200, john: "bcrypt", example: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", speed: "184 kH/s" },
  { name: "scrypt", regex: /^\$scrypt\$/, hashcat: 8900, john: "scrypt", example: "$scrypt$ln=15,r=8,p=1$...", speed: "2.5 kH/s" },
  { name: "argon2", regex: /^\$argon2(i|d|id)\$/, hashcat: null, john: "argon2", example: "$argon2id$v=19$m=65536,t=3,p=4$...", speed: "~100 H/s" },
  { name: "MD5 crypt (md5crypt)", regex: /^\$1\$/, hashcat: 500, john: "md5crypt", example: "$1$salt$hash", speed: "46 MH/s" },
  { name: "SHA-256 crypt", regex: /^\$5\$/, hashcat: 7400, john: "sha256crypt", example: "$5$rounds=5000$salt$hash", speed: "2.6 MH/s" },
  { name: "SHA-512 crypt", regex: /^\$6\$/, hashcat: 1800, john: "sha512crypt", example: "$6$rounds=5000$salt$hash", speed: "1.2 MH/s" },
  { name: "DES crypt", regex: /^[./A-Za-z0-9]{13}$/, hashcat: 1500, john: "descrypt", example: "48T/25RVSmGq2", speed: "9.5 GH/s" },
  { name: "MySQL 4.1+", regex: /^\*[A-F0-9]{40}$/, hashcat: 300, john: "mysql-sha1", example: "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", speed: "26 GH/s" },
  { name: "MySQL 3.x", regex: /^[a-fA-F0-9]{16}$/, hashcat: 200, john: "mysql", example: "606717496665bcba", speed: "400 GH/s" },
  { name: "MSSQL (2012+)", regex: /^0x0200[a-fA-F0-9]+$/, hashcat: 1731, john: "mssql12", example: "0x0200...", speed: "14 GH/s" },
  { name: "Oracle 11g+", regex: /^S:[A-F0-9]{60}$/, hashcat: 112, john: "oracle11", example: "S:380E1E25...", speed: "500 MH/s" },
  { name: "PostgreSQL MD5", regex: /^md5[a-fA-F0-9]{32}$/, hashcat: 12, john: "postgres", example: "md5be86a79bf2043622d58d5453c47d4860", speed: "164 GH/s" },
  { name: "WPA-PBKDF2-PMKID", regex: /^[a-fA-F0-9]{32}\*/, hashcat: 22000, john: "wpapsk", example: "hash*bssid*stmac*essid", speed: "2.4 MH/s" },
  { name: "NetNTLMv1", regex: /^[^:]+::\w+:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$/, hashcat: 5500, john: "netntlm", example: "user::domain:lm:nt:challenge", speed: "100 GH/s" },
  { name: "NetNTLMv2", regex: /^[^:]+::\w+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$/, hashcat: 5600, john: "netntlmv2", example: "user::domain:challenge:nt:blob", speed: "10 GH/s" },
  { name: "Kerberos 5 TGS-REP (Kerberoast)", regex: /^\$krb5tgs\$/, hashcat: 13100, john: "krb5tgs", example: "$krb5tgs$23$*user$realm$spn*$hash", speed: "1.3 GH/s" },
  { name: "Kerberos 5 AS-REP", regex: /^\$krb5asrep\$/, hashcat: 18200, john: "krb5asrep", example: "$krb5asrep$23$user@realm:hash", speed: "1.3 GH/s" },
  { name: "DPAPI masterkey", regex: /^\$DPAPImk\$/, hashcat: 15300, john: "dpapimk", example: "$DPAPImk$2*...", speed: "200 kH/s" },
  { name: "macOS v10.8+ (PBKDF2-SHA512)", regex: /^\$ml\$/, hashcat: 7100, john: "pbkdf2-hmac-sha512", example: "$ml$...", speed: "50 kH/s" },
  { name: "Django PBKDF2-SHA256", regex: /^pbkdf2_sha256\$/, hashcat: 10000, john: "django", example: "pbkdf2_sha256$260000$salt$hash", speed: "500 kH/s" },
  { name: "WordPress (phpass)", regex: /^\$P\$/, hashcat: 400, john: "phpass", example: "$P$B...hash....", speed: "24 MH/s" },
  { name: "Joomla (MD5)", regex: /^[a-fA-F0-9]{32}:[a-zA-Z0-9]{32}$/, hashcat: 11, john: "joomla", example: "hash:salt", speed: "164 GH/s" },
  { name: "Drupal 7 (SHA-512)", regex: /^\$S\$/, hashcat: 7900, john: "drupal7", example: "$S$D...hash....", speed: "300 kH/s" },
  { name: "phpBB3", regex: /^\$H\$/, hashcat: 400, john: "phpass", example: "$H$9...hash....", speed: "24 MH/s" },
];

const WORDLISTS = [
  { name: "rockyou.txt", size: "134 MB", entries: "14.3M", desc: "The classic -- most common real-world passwords from the 2009 RockYou breach. Always your first try.", source: "Included with Kali Linux" },
  { name: "SecLists/Passwords", size: "~500 MB", entries: "Various", desc: "Daniel Miessler's curated collection. Includes common-credentials, default-creds, top-passwords, leaked databases, and more.", source: "github.com/danielmiessler/SecLists" },
  { name: "CrackStation", size: "15 GB (full)", entries: "1.5B", desc: "Massive lookup table. The smaller human-only version (64MB, 63M entries) is more practical for dictionary attacks.", source: "crackstation.net" },
  { name: "Weakpass", size: "Varies", entries: "Up to 30B", desc: "Multiple lists of varying sizes. weakpass_4 is the largest. Good for targeted cracking with hardware.", source: "weakpass.com" },
  { name: "Kaonashi", size: "9.5 GB", entries: "185M", desc: "Large wordlist built from real password breaches. Sorted by frequency.", source: "github.com/kaonashi-passwords" },
  { name: "HIBP Passwords", size: "12 GB", entries: "613M", desc: "Every unique password from Have I Been Pwned breaches. SHA-1 hashes only (k-anonymity model).", source: "haveibeenpwned.com/Passwords" },
  { name: "Custom CeWL lists", size: "Varies", entries: "Varies", desc: "Generated per-target using CeWL (Custom Word List generator). Scrapes target website for words to build org-specific wordlists.", source: "CeWL tool" },
  { name: "CUPP output", size: "Small", entries: "~thousands", desc: "Common User Passwords Profiler. Builds targeted wordlists from personal info (name, birthday, pet, partner).", source: "CUPP tool" },
];

const HASHCAT_RULES = [
  { name: "best64.rule", entries: 64, desc: "The best 64 rules by statistical analysis. Fast and effective for quick wins. Always run this first." },
  { name: "dive.rule", entries: 99068, desc: "Deep dive rules. Much larger, covers many more mutations. Run after best64." },
  { name: "OneRuleToRuleThemAll.rule", entries: 52000, desc: "Community-compiled mega rule. Combination of the best rules from multiple sources." },
  { name: "rockyou-30000.rule", entries: 30000, desc: "Rules generated from rockyou password patterns." },
  { name: "d3ad0ne.rule", entries: 34101, desc: "Comprehensive mutation rules." },
  { name: "T0XlC.rule", entries: 12019, desc: "Balanced coverage-to-speed rule set." },
  { name: "toggles1-5.rule", entries: 31, desc: "Toggle case of characters at positions 1-5. Good for known patterns." },
  { name: "leet.rule", entries: "~100", desc: "Leetspeak substitutions (a->@, e->3, i->1, o->0, s->$, t->7)." },
];

const RULE_SYNTAX = [
  { rule: ":", desc: "Do nothing (passthrough)" },
  { rule: "l", desc: "Lowercase all" },
  { rule: "u", desc: "Uppercase all" },
  { rule: "c", desc: "Capitalize first, lowercase rest" },
  { rule: "C", desc: "Lowercase first, uppercase rest" },
  { rule: "t", desc: "Toggle case of all characters" },
  { rule: "TN", desc: "Toggle case at position N" },
  { rule: "$X", desc: "Append character X" },
  { rule: "^X", desc: "Prepend character X" },
  { rule: "[", desc: "Delete first character" },
  { rule: "]", desc: "Delete last character" },
  { rule: "DN", desc: "Delete character at position N" },
  { rule: "d", desc: "Duplicate entire word" },
  { rule: "r", desc: "Reverse word" },
  { rule: "f", desc: "Reflect (append reversed)" },
  { rule: "{", desc: "Rotate left" },
  { rule: "}", desc: "Rotate right" },
  { rule: "sXY", desc: "Replace all X with Y" },
  { rule: "@X", desc: "Remove all instances of X" },
  { rule: "iNX", desc: "Insert X at position N" },
  { rule: "oNX", desc: "Overwrite at position N with X" },
  { rule: "'N", desc: "Truncate at position N" },
  { rule: "xNM", desc: "Extract M chars starting at N" },
  { rule: "p", desc: "Duplicate word (append copy)" },
  { rule: "q", desc: "Duplicate every character" },
  { rule: "k", desc: "Swap first two characters" },
  { rule: "K", desc: "Swap last two characters" },
  { rule: "*NM", desc: "Swap characters at positions N and M" },
  { rule: "E", desc: "Lowercase first letter, uppercase the rest (title case inverse)" },
];

const ATTACK_MODES = [
  { mode: "-a 0", name: "Dictionary", desc: "Tries each word in a wordlist. With rules (-r), applies mutations to each word. The most common and effective attack mode.", usage: "hashcat -m 1000 hashes.txt rockyou.txt -r best64.rule", time: "Fast with rules, depends on wordlist size" },
  { mode: "-a 1", name: "Combination", desc: "Combines words from two wordlists. Left + Right, e.g., 'password' + '123' = 'password123'. Good for compound passwords.", usage: "hashcat -m 1000 hashes.txt left.txt right.txt", time: "O(n*m) where n and m are wordlist sizes" },
  { mode: "-a 3", name: "Brute-force / Mask", desc: "Tries all combinations matching a pattern (mask). Use charsets: ?l lowercase, ?u uppercase, ?d digit, ?s special, ?a all. Define masks for known patterns.", usage: "hashcat -m 1000 hashes.txt ?u?l?l?l?l?l?d?d", time: "Depends on mask length and charset size" },
  { mode: "-a 6", name: "Hybrid (Wordlist + Mask)", desc: "Appends mask-generated strings to wordlist words. E.g., rockyou.txt + ?d?d?d appends 000-999 to each word.", usage: "hashcat -m 1000 hashes.txt rockyou.txt ?d?d?d?d", time: "wordlist_size * mask_keyspace" },
  { mode: "-a 7", name: "Hybrid (Mask + Wordlist)", desc: "Prepends mask-generated strings to wordlist words. E.g., ?d?d?d + rockyou.txt prepends 000-999.", usage: "hashcat -m 1000 hashes.txt ?d?d?d?d rockyou.txt", time: "mask_keyspace * wordlist_size" },
  { mode: "-a 9", name: "Association", desc: "Uses a wordlist where each line corresponds to a hash. Good when you know the username or hint for each hash.", usage: "hashcat -m 1000 hashes.txt wordlist.txt -a 9", time: "Single pass" },
];

const MASK_CHARSETS = [
  { mask: "?l", chars: "abcdefghijklmnopqrstuvwxyz", count: 26, desc: "Lowercase letters" },
  { mask: "?u", chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", count: 26, desc: "Uppercase letters" },
  { mask: "?d", chars: "0123456789", count: 10, desc: "Digits" },
  { mask: "?s", chars: " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", count: 33, desc: "Special characters" },
  { mask: "?a", chars: "?l?u?d?s combined", count: 95, desc: "All printable ASCII" },
  { mask: "?b", chars: "0x00-0xFF", count: 256, desc: "All bytes (binary)" },
  { mask: "-1 ?l?d", chars: "Custom charset #1", count: 36, desc: "Example: lowercase + digits" },
  { mask: "-2 ?u?d", chars: "Custom charset #2", count: 36, desc: "Example: uppercase + digits" },
];

const PRACTICE_HASHES = [
  { hash: "5d41402abc4b2a76b9719d911017c592", type: "MD5", difficulty: "Easy", hint: "5-letter common English word" },
  { hash: "8cb2237d0679ca88db6464eac60da96345513964", type: "SHA-1", difficulty: "Easy", hint: "Common number sequence" },
  { hash: "e10adc3949ba59abbe56e057f20f883e", type: "MD5", difficulty: "Easy", hint: "6-digit number, very common" },
  { hash: "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", type: "SHA-1", difficulty: "Easy", hint: "Very common 8-char password" },
  { hash: "d8578edf8458ce06fbc5bb76a58c5ca4", type: "MD5", difficulty: "Easy", hint: "A common household animal" },
  { hash: "b1b3773a05c0ed0176787a4f1574ff0075f7521e", type: "SHA-1", difficulty: "Easy", hint: "Computer input device" },
  { hash: "8621ffdbc5698829397d97767ac13db3", type: "MD5", difficulty: "Easy", hint: "Type of fruit" },
  { hash: "7c6a180b36896a65c4c2c6c03b29aff3f3eb296e", type: "SHA-1", difficulty: "Easy", hint: "Common 8-letter word + 1" },
  { hash: "0d107d09f5bbe40cade3de5c71e9e9b7", type: "MD5", difficulty: "Medium", hint: "A word meaning happy" },
  { hash: "e99a18c428cb38d5f260853678922e03", type: "MD5", difficulty: "Easy", hint: "Common 3-word phrase about security" },
  { hash: "21232f297a57a5a743894a0e4a801fc3", type: "MD5", difficulty: "Easy", hint: "The person who manages a system" },
  { hash: "ee11cbb19052e40b07aac0ca060c23ee", type: "MD5", difficulty: "Easy", hint: "Common shorthand for 'you are'" },
  { hash: "d077f244def8a70e5ea758bd8352fcd8", type: "MD5", difficulty: "Easy", hint: "Invisible in the dark" },
  { hash: "3c363836cf4e16666669a25da280a1865c2d2874", type: "SHA-1", difficulty: "Medium", hint: "A greeting" },
  { hash: "098f6bcd4621d373cade4e832627b4f6", type: "MD5", difficulty: "Easy", hint: "Used to verify software" },
  { hash: "5ebe2294ecd0e0f08eab7690d2a6ee69", type: "MD5", difficulty: "Easy", hint: "A hidden word" },
  { hash: "cc03e747a6afbbcbf8be7668acfebee5", type: "MD5", difficulty: "Easy", hint: "The opposite of wrong" },
  { hash: "827ccb0eea8a706c4c34a16891f84e7b", type: "MD5", difficulty: "Easy", hint: "Simple counting" },
  { hash: "fcea920f7412b5da7be0cf42b8c93759", type: "MD5", difficulty: "Easy", hint: "What you do on the internet" },
  { hash: "25d55ad283aa400af464c76d713c07ad", type: "MD5", difficulty: "Easy", hint: "The most overused 8-char password" },
  { hash: "a4f49c406510bdcab6824ee7c30fd852", type: "NTLM", difficulty: "Medium", hint: "Same as MD5 #20 but NTLM format" },
  { hash: "32ed87bdb5fdc5e9cba88547376818d4", type: "NTLM", difficulty: "Medium", hint: "Reptile" },
  { hash: "25b565b8b1cfb8e97e465bcc22a81360b78a07a7", type: "SHA-1", difficulty: "Medium", hint: "Something you drink in the morning" },
  { hash: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", type: "SHA-256", difficulty: "Hard", hint: "3 digits" },
  { hash: "6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090", type: "SHA-256", difficulty: "Hard", hint: "Opposite of goodbye" },
];

const GPU_SPEEDS = [
  { gpu: "RTX 3090", md5: "63 GH/s", sha1: "11 GH/s", sha256: "6.8 GH/s", ntlm: "110 GH/s", bcrypt: "95 kH/s", wpa: "1.1 MH/s" },
  { gpu: "RTX 4090", md5: "164 GH/s", sha1: "26 GH/s", sha256: "14 GH/s", ntlm: "300 GH/s", bcrypt: "184 kH/s", wpa: "2.4 MH/s" },
  { gpu: "RTX 4090 x8", md5: "1.3 TH/s", sha1: "208 GH/s", sha256: "112 GH/s", ntlm: "2.4 TH/s", bcrypt: "1.47 MH/s", wpa: "19 MH/s" },
  { gpu: "A100", md5: "72 GH/s", sha1: "14 GH/s", sha256: "7.2 GH/s", ntlm: "124 GH/s", bcrypt: "105 kH/s", wpa: "1.4 MH/s" },
  { gpu: "H100", md5: "150 GH/s", sha1: "24 GH/s", sha256: "13 GH/s", ntlm: "270 GH/s", bcrypt: "170 kH/s", wpa: "2.2 MH/s" },
];

function renderHashIDTab(container) {
  container.innerHTML =
    '<h2 class="pg-h2">Hash Identifier</h2>' +
    '<p class="muted">Paste a hash to automatically identify its type, hashcat mode, and john format.</p>' +
    '<textarea class="tk-in" id="pcl-hash-input" rows="3" placeholder="Paste a hash here...\ne.g., 5d41402abc4b2a76b9719d911017c592"></textarea>' +
    '<div class="tk-btns"><button class="btn sm" id="pcl-hash-id">Identify Hash</button></div>' +
    '<div id="pcl-hash-out"></div>';

  container.querySelector("#pcl-hash-id").onclick = function() {
    var hash = container.querySelector("#pcl-hash-input").value.trim();
    if (!hash) return;
    var matches = HASH_PATTERNS.filter(function(p) { return p.regex.test(hash); });
    if (!matches.length) {
      container.querySelector("#pcl-hash-out").innerHTML = '<p class="muted" style="margin-top:12px">No matching hash format found. The hash may be truncated or in an unsupported format.</p>';
      return;
    }
    var html = '<div style="margin-top:12px"><div style="font-weight:600;margin-bottom:8px">' + matches.length + ' possible match(es):</div>';
    matches.forEach(function(m) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px;margin:6px 0">' +
        '<div style="font-weight:600;color:var(--acc);font-size:.95rem">' + esc(m.name) + '</div>' +
        '<div style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px;margin-top:6px;font-size:.82rem">' +
          '<span class="muted">Hashcat mode:</span><span>-m ' + (m.hashcat !== null ? m.hashcat : "N/A") + '</span>' +
          '<span class="muted">John format:</span><span>--format=' + esc(m.john) + '</span>' +
          '<span class="muted">RTX 4090 speed:</span><span>' + esc(m.speed) + '</span>' +
        '</div></div>';
    });
    html += '</div>';
    container.querySelector("#pcl-hash-out").innerHTML = html;
  };
}

function renderHashcatRefTab(container) {
  var html = '<h2 class="pg-h2">Hashcat Mode Reference</h2>' +
    '<p class="muted">Complete reference of hashcat -m modes with format, example hash, and RTX 4090 performance.</p>' +
    '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.8rem;margin-top:12px">' +
    '<tr style="border-bottom:2px solid var(--line);text-align:left"><th style="padding:8px">Mode</th><th style="padding:8px">Name</th><th style="padding:8px">John Format</th><th style="padding:8px">Speed (4090)</th></tr>';
  HASH_PATTERNS.forEach(function(p) {
    html += '<tr style="border-bottom:1px solid var(--line)">' +
      '<td style="padding:6px 8px;color:var(--acc);font-weight:600">' + (p.hashcat !== null ? p.hashcat : "N/A") + '</td>' +
      '<td style="padding:6px 8px">' + esc(p.name) + '</td>' +
      '<td style="padding:6px 8px;font-family:var(--font-mono,monospace);font-size:.75rem">' + esc(p.john) + '</td>' +
      '<td style="padding:6px 8px;color:var(--acc)">' + esc(p.speed) + '</td></tr>';
  });
  html += '</table></div>';
  container.innerHTML = html;
}

function renderWordlistTab(container) {
  var html = '<h2 class="pg-h2">Wordlist Reference</h2>' +
    '<p class="muted">Major wordlists for password cracking, with sizes and descriptions.</p>';
  WORDLISTS.forEach(function(w) {
    html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px;margin:8px 0">' +
      '<div style="display:flex;justify-content:space-between;align-items:center">' +
        '<strong style="color:var(--acc)">' + esc(w.name) + '</strong>' +
        '<div style="display:flex;gap:8px;font-size:.75rem"><span class="muted">Size: ' + esc(w.size) + '</span><span class="muted">Entries: ' + esc(w.entries) + '</span></div>' +
      '</div>' +
      '<p style="font-size:.83rem;margin:6px 0 4px">' + esc(w.desc) + '</p>' +
      '<div style="font-size:.75rem;color:var(--mut)">Source: ' + esc(w.source) + '</div></div>';
  });
  container.innerHTML = html;
}

function renderRulesTab(container) {
  var html = '<h2 class="pg-h2">Hashcat Rules Reference</h2>' +
    '<p class="muted">Rules transform wordlist entries to match real password patterns.</p>' +
    '<h3 style="margin:16px 0 8px;font-size:.9rem;color:var(--acc)">Popular Rule Files</h3>';
  HASHCAT_RULES.forEach(function(r) {
    html += '<div style="display:flex;gap:12px;padding:6px 10px;background:var(--card);border-radius:4px;margin:4px 0;font-size:.82rem">' +
      '<code style="color:var(--acc);min-width:220px">' + esc(r.name) + ' <span class="muted">(' + r.entries + ')</span></code>' +
      '<span>' + esc(r.desc) + '</span></div>';
  });
  html += '<h3 style="margin:20px 0 8px;font-size:.9rem;color:var(--acc)">Rule Syntax</h3>';
  html += '<div style="display:grid;grid-template-columns:auto 1fr;gap:2px 16px;font-size:.82rem">';
  RULE_SYNTAX.forEach(function(r) {
    html += '<code style="color:var(--acc);padding:4px 8px;background:var(--card);border-radius:4px;font-weight:600">' + esc(r.rule) + '</code>' +
      '<span style="padding:4px 0">' + esc(r.desc) + '</span>';
  });
  html += '</div>';
  container.innerHTML = html;
}

function renderAttackModesTab(container) {
  var html = '<h2 class="pg-h2">Attack Modes</h2>' +
    '<p class="muted">When to use each hashcat attack mode.</p>';
  ATTACK_MODES.forEach(function(a) {
    html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px;margin:8px 0">' +
      '<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px">' +
        '<code style="color:var(--acc);font-weight:700;font-size:.9rem">' + esc(a.mode) + '</code>' +
        '<strong>' + esc(a.name) + '</strong></div>' +
      '<p style="font-size:.83rem;margin:4px 0">' + esc(a.desc) + '</p>' +
      '<div style="font-family:var(--font-mono,monospace);font-size:.78rem;background:var(--card2,#111);padding:8px;border-radius:4px;margin:6px 0;color:var(--acc)">' + esc(a.usage) + '</div>' +
      '<div style="font-size:.75rem;color:var(--mut)">Time estimate: ' + esc(a.time) + '</div></div>';
  });
  html += '<h3 style="margin:20px 0 8px;font-size:.9rem;color:var(--acc)">Mask Charsets</h3>';
  html += '<div style="display:grid;grid-template-columns:auto auto auto 1fr;gap:2px 12px;font-size:.82rem">';
  html += '<span style="font-weight:600;padding:4px 0">Mask</span><span style="font-weight:600;padding:4px 0">Count</span><span style="font-weight:600;padding:4px 0">Description</span><span></span>';
  MASK_CHARSETS.forEach(function(m) {
    html += '<code style="color:var(--acc);padding:4px 0">' + esc(m.mask) + '</code>' +
      '<span style="padding:4px 0">' + m.count + '</span>' +
      '<span style="padding:4px 0">' + esc(m.desc) + '</span><span></span>';
  });
  html += '</div>';
  container.innerHTML = html;
}

function renderCalcTab(container) {
  container.innerHTML =
    '<h2 class="pg-h2">Time-to-Crack Calculator</h2>' +
    '<p class="muted">Estimate how long it takes to brute-force a password given its length, charset, and hardware.</p>' +
    '<div style="display:grid;gap:8px;max-width:400px;margin:12px 0">' +
      '<label style="font-size:.8rem">Password Length<input class="tk-f" id="pcl-calc-len" type="number" min="1" max="32" value="8"></label>' +
      '<label style="font-size:.8rem">Charset Size<select class="tk-f" id="pcl-calc-charset"><option value="10">Digits only (10)</option><option value="26">Lowercase (26)</option><option value="36">Lower + digits (36)</option><option value="52">Mixed case (52)</option><option value="62">Mixed + digits (62)</option><option value="95" selected>All printable (95)</option></select></label>' +
      '<label style="font-size:.8rem">Hash Type<select class="tk-f" id="pcl-calc-hash"><option value="164000000000">MD5 (164 GH/s)</option><option value="26000000000">SHA-1 (26 GH/s)</option><option value="14000000000">SHA-256 (14 GH/s)</option><option value="300000000000" selected>NTLM (300 GH/s)</option><option value="184000">bcrypt ($2a$10) (184 kH/s)</option><option value="2400000">WPA2 (2.4 MH/s)</option><option value="1200000">SHA-512 crypt (1.2 MH/s)</option></select></label>' +
    '</div>' +
    '<div class="tk-btns"><button class="btn sm" id="pcl-calc-go">Calculate</button></div>' +
    '<pre class="tk-out" id="pcl-calc-out"></pre>';

  container.querySelector("#pcl-calc-go").onclick = function() {
    var len = parseInt(container.querySelector("#pcl-calc-len").value) || 8;
    var charset = parseInt(container.querySelector("#pcl-calc-charset").value);
    var speed = parseFloat(container.querySelector("#pcl-calc-hash").value);
    var keyspace = Math.pow(charset, len);
    var seconds = keyspace / speed;
    var avg = seconds / 2;
    function fmt(s) {
      if (s < 1) return "< 1 second";
      if (s < 60) return Math.round(s) + " seconds";
      if (s < 3600) return Math.round(s/60) + " minutes";
      if (s < 86400) return (s/3600).toFixed(1) + " hours";
      if (s < 86400*365) return (s/86400).toFixed(1) + " days";
      if (s < 86400*365*1000) return (s/(86400*365)).toFixed(1) + " years";
      if (s < 86400*365*1e6) return (s/(86400*365*1000)).toFixed(1) + " thousand years";
      if (s < 86400*365*1e9) return (s/(86400*365*1e6)).toFixed(1) + " million years";
      return (s/(86400*365*1e9)).toFixed(1) + " billion years";
    }
    var out = "=== BRUTE FORCE TIME ESTIMATE ===\n\n" +
      "Password length: " + len + " characters\n" +
      "Charset size: " + charset + " characters\n" +
      "Total keyspace: " + keyspace.toExponential(2) + "\n" +
      "Hardware speed: " + speed.toExponential(2) + " H/s (RTX 4090)\n\n" +
      "Maximum time: " + fmt(seconds) + "\n" +
      "Average time (50%): " + fmt(avg) + "\n\n" +
      "--- SCALING ---\n" +
      "x8 GPUs: " + fmt(avg/8) + "\n" +
      "x64 GPUs: " + fmt(avg/64) + "\n" +
      "x1000 GPUs: " + fmt(avg/1000) + "\n";
    container.querySelector("#pcl-calc-out").textContent = out;
  };
}

function renderPracticeTab(container) {
  var html = '<h2 class="pg-h2">Practice Hashes</h2>' +
    '<p class="muted">' + PRACTICE_HASHES.length + ' hashes to practice cracking. Try with hashcat, john, or online tools. Hints available.</p>';
  html += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.8rem;margin-top:12px">' +
    '<tr style="border-bottom:2px solid var(--line);text-align:left"><th style="padding:8px">#</th><th style="padding:8px">Hash</th><th style="padding:8px">Type</th><th style="padding:8px">Difficulty</th><th style="padding:8px">Hint</th></tr>';
  PRACTICE_HASHES.forEach(function(p, i) {
    var diffCol = p.difficulty === "Easy" ? "#22c55e" : p.difficulty === "Medium" ? "#f59e0b" : "#ef4444";
    html += '<tr style="border-bottom:1px solid var(--line)">' +
      '<td style="padding:6px 8px">' + (i+1) + '</td>' +
      '<td style="padding:6px 8px;font-family:var(--font-mono,monospace);font-size:.72rem;word-break:break-all;max-width:300px">' + esc(p.hash) + '</td>' +
      '<td style="padding:6px 8px">' + esc(p.type) + '</td>' +
      '<td style="padding:6px 8px;color:' + diffCol + '">' + esc(p.difficulty) + '</td>' +
      '<td style="padding:6px 8px;color:var(--mut);font-size:.78rem">' + esc(p.hint) + '</td></tr>';
  });
  html += '</table></div>';
  container.innerHTML = html;
}

function renderHardwareTab(container) {
  var html = '<h2 class="pg-h2">GPU Hashrate Reference</h2>' +
    '<p class="muted">Benchmark speeds for common hash types across different GPUs.</p>';
  html += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.8rem;margin-top:12px">' +
    '<tr style="border-bottom:2px solid var(--line);text-align:left"><th style="padding:8px">GPU</th><th style="padding:8px">MD5</th><th style="padding:8px">SHA-1</th><th style="padding:8px">SHA-256</th><th style="padding:8px">NTLM</th><th style="padding:8px">bcrypt</th><th style="padding:8px">WPA2</th></tr>';
  GPU_SPEEDS.forEach(function(g) {
    html += '<tr style="border-bottom:1px solid var(--line)">' +
      '<td style="padding:6px 8px;font-weight:600;color:var(--acc)">' + esc(g.gpu) + '</td>' +
      '<td style="padding:6px 8px">' + esc(g.md5) + '</td>' +
      '<td style="padding:6px 8px">' + esc(g.sha1) + '</td>' +
      '<td style="padding:6px 8px">' + esc(g.sha256) + '</td>' +
      '<td style="padding:6px 8px">' + esc(g.ntlm) + '</td>' +
      '<td style="padding:6px 8px">' + esc(g.bcrypt) + '</td>' +
      '<td style="padding:6px 8px">' + esc(g.wpa) + '</td></tr>';
  });
  html += '</table></div>';
  html += '<div style="margin-top:16px;padding:12px;background:var(--card);border-radius:6px;font-size:.83rem">' +
    '<strong>Rainbow Tables vs Brute Force</strong>' +
    '<p style="margin:6px 0">Rainbow tables are precomputed hash chains that trade storage for time. A table for MD5 + all 7-char alphanumeric passwords is ~100GB but cracks instantly. However:</p>' +
    '<ul style="margin:4px 0;padding-left:20px">' +
      '<li>Salted hashes defeat rainbow tables entirely (each salt needs its own table)</li>' +
      '<li>bcrypt, scrypt, argon2 are immune by design (salt + slow hashing)</li>' +
      '<li>Modern GPUs have made brute force faster than table lookups for many cases</li>' +
      '<li>Tables only cover a fixed charset and length range</li>' +
    '</ul></div>';
  container.innerHTML = html;
}

const PCL_TABS = [
  { id: "hashid", label: "Hash Identifier", render: renderHashIDTab },
  { id: "hashcat", label: "Hashcat Modes", render: renderHashcatRefTab },
  { id: "wordlists", label: "Wordlists", render: renderWordlistTab },
  { id: "rules", label: "Rules", render: renderRulesTab },
  { id: "attacks", label: "Attack Modes", render: renderAttackModesTab },
  { id: "calc", label: "Time Calculator", render: renderCalcTab },
  { id: "practice", label: "Practice Hashes", render: renderPracticeTab },
  { id: "hardware", label: "GPU Speeds", render: renderHardwareTab },
];

export function renderPasswordCrackingLab(main) {
  main.innerHTML =
    '<h1 class="pg-h1">Password Cracking Lab</h1>' +
    '<p class="muted pg-sub">Hash identification, cracking references, wordlists, rules, and practice challenges.</p>' +
    '<div class="tab-bar" id="pcl-tabs">' +
      PCL_TABS.map(function(t, i) { return '<button class="tab' + (i === 0 ? ' active' : '') + '" data-tab="' + t.id + '">' + t.label + '</button>'; }).join('') +
    '</div>' +
    '<div id="pcl-content" style="margin-top:12px"></div>';

  var tabBar = main.querySelector('#pcl-tabs');
  var content = main.querySelector('#pcl-content');
  function switchTab(tabId) {
    tabBar.querySelectorAll('.tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === tabId); });
    var tab = PCL_TABS.find(function(t) { return t.id === tabId; });
    if (tab) { content.innerHTML = ''; tab.render(content); }
  }
  tabBar.onclick = function(e) { var btn = e.target.closest('.tab'); if (btn) switchTab(btn.dataset.tab); };
  switchTab('hashid');
}
