// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
// Darknode Password Security Toolkit

// ── Common Passwords (top 500 for fast dictionary check) ────────────────────
const COMMON_PASSWORDS = [
  "123456","password","12345678","qwerty","123456789","12345","1234","111111","1234567",
  "dragon","123123","baseball","abc123","football","monkey","letmein","shadow","master",
  "666666","qwertyuiop","123321","mustang","1234567890","michael","654321","superman",
  "1qaz2wsx","7777777","121212","000000","qazwsx","123qwe","killer","trustno1","jordan",
  "jennifer","zxcvbnm","asdfgh","hunter","buster","soccer","harley","batman","andrew",
  "tigger","sunshine","iloveyou","2000","charlie","robert","thomas","hockey","ranger",
  "daniel","starwars","klaster","112233","george","computer","michelle","jessica","pepper",
  "1111","zxcvbn","555555","11111111","131313","freedom","777777","pass","maggie","159753",
  "aaaaaa","ginger","princess","joshua","cheese","amanda","summer","love","ashley","nicole",
  "chelsea","biteme","matthew","access","yankees","987654321","dallas","austin","thunder",
  "taylor","matrix","mobilemail","william","corvette","hello","martin","heather","secret",
  "fucker","merlin","diamond","1234qwer","gfhjkm","hammer","silver","222222","88888888",
  "anthony","justin","test","bailey","q1w2e3r4t5","patrick","internet","scooter","orange",
  "11111","golfer","cookie","richard","samantha","bigdog","guitar","jackson","whatever",
  "mickey","chicken","sparky","snoopy","maverick","phoenix","camaro","peanut","morgan",
  "welcome","falcon","cowboy","ferrari","samsung","andrea","smokey","steelers","joseph",
  "mercedes","dakota","arsenal","eagles","melissa","boomer","booboo","spider","nascar",
  "monster","tigers","yellow","xxxxxx","123123123","gateway","marina","diablo","bulldog",
  "qwer1234","compaq","purple","hardcore","banana","junior","hannah","123654","porsche",
  "lakers","iceman","money","cowboys","987654","london","tennis","999999","ncc1701",
  "coffee","scooby","0000","miller","boston","q1w2e3r4","fuckoff","brandon","yamaha",
  "chester","mother","forever","johnny","edward","333333","oliver","redsox","player",
  "nikita","knight","fender","barney","midnight","please","brandy","badboy","iwantu",
  "slayer","rangers","charles","flower","bigdaddy","rabbit","wizard","jasper","enter",
  "rachel","chris","steven","winner","adidas","victoria","natasha","1q2w3e4r","jasmine",
  "winter","prince","panties","marine","ghbdtn","fishing","cocacola","casper","oscar",
  "tucker","patrick","pumpkin","falcon2","scarface","europa","sammy","runner","johnny5",
  "abcdef","admin","admin123","root","toor","administrator","changeme","default","guest",
  "login","user","test123","temp","temp123","backup","oracle","postgres","mysql","redis",
  "mongodb","ftp","ssh","telnet","vnc","cisco","ubnt","mikrotik","passw0rd","P@ssw0rd",
  "P@ssword1","Welcome1","Qwerty123","Password1","Admin123","Letmein1","Iloveyou1",
];

// ── Passphrase Word List (EFF short wordlist subset — 400 words) ────────────
const WORDLIST = [
  "acid","acorn","acre","acts","afar","affix","aged","agent","agile","aging",
  "agony","ahead","aide","aim","ajar","alarm","album","alert","alias","alibi",
  "alien","align","alike","alive","alley","allot","allow","alloy","almond","along",
  "alpha","also","alter","amino","ample","amuse","angel","anger","angle","ankle",
  "annex","antic","anvil","apart","ape","apex","apple","apply","apron","aqua",
  "arena","argue","arise","armor","army","aroma","array","arrow","arson","art",
  "ash","atlas","atom","attic","audio","audit","augur","aunt","aura","auto",
  "avid","avoid","awake","award","aware","axiom","axis","axle","azure","bacon",
  "badge","badly","bagel","baggy","baked","baker","balmy","ban","candy","basin",
  "batch","bath","baton","blade","blank","blast","blaze","bleak","blend","bless",
  "blimp","blind","bliss","blitz","bloat","block","bloke","blond","blood","bloom",
  "blown","bluff","blunt","blurb","blurt","blush","board","boast","body","bogey",
  "boil","bold","bolt","bond","bonus","book","booth","born","boss","both",
  "boxer","brace","brain","brake","brand","brave","bread","break","breed","brick",
  "bride","brief","brine","bring","brink","brisk","broad","broil","broke","brook",
  "broth","brown","brush","buddy","budge","buggy","build","bulge","bulk","bully",
  "bunch","bunny","burn","burst","cabin","cable","cadet","cage","calm","camel",
  "camp","canal","candy","cape","card","cargo","carol","carry","carve","catch",
  "cause","cedar","chain","chair","chalk","champ","chant","chaos","charm","chart",
  "chase","cheap","check","cheek","cheer","chess","chest","chief","child","chill",
  "chip","choir","choke","chunk","churn","cider","cigar","cinch","circa","city",
  "civic","civil","claim","clamp","clap","clash","clasp","class","clean","clear",
  "clerk","click","cliff","climb","cling","clip","cloak","clock","clone","close",
  "cloth","cloud","clown","club","cluck","clue","clump","clung","coach","coast",
  "cobra","cocoa","code","coil","coin","coke","cold","comet","comic","comma",
  "conch","coral","core","cork","corn","couch","could","count","coup","court",
  "cover","cozy","crack","craft","cramp","crane","crash","crate","crawl","crazy",
  "creak","cream","creek","creep","crest","crew","crimp","crisp","croak","crock",
  "crook","cross","crowd","crown","crude","crush","cubic","cult","cup","curb",
  "curry","curse","curve","cycle","daily","dairy","daisy","dance","dare","dart",
];

// ── Hash Type Identification ────────────────────────────────────────────────
const HASH_TYPES = [
  { name: "MD5", regex: /^[a-f0-9]{32}$/i, length: 32, hashcat: 0, john: "Raw-MD5", example: "5d41402abc4b2a76b9719d911017c592" },
  { name: "SHA-1", regex: /^[a-f0-9]{40}$/i, length: 40, hashcat: 100, john: "Raw-SHA1", example: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" },
  { name: "SHA-224", regex: /^[a-f0-9]{56}$/i, length: 56, hashcat: 1300, john: "Raw-SHA224", example: "ea09ae889d5c051a0086696f06f4d8f19e47c5e4731c34f80e545d69" },
  { name: "SHA-256", regex: /^[a-f0-9]{64}$/i, length: 64, hashcat: 1400, john: "Raw-SHA256", example: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" },
  { name: "SHA-384", regex: /^[a-f0-9]{96}$/i, length: 96, hashcat: 10800, john: "Raw-SHA384", example: "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f" },
  { name: "SHA-512", regex: /^[a-f0-9]{128}$/i, length: 128, hashcat: 1700, john: "Raw-SHA512", example: "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043" },
  { name: "NTLM", regex: /^[a-f0-9]{32}$/i, length: 32, hashcat: 1000, john: "NT", example: "b4b9b02e6f09a9bd760f388b67351e2b" },
  { name: "MySQL 4.1+", regex: /^\*[a-f0-9]{40}$/i, length: 41, hashcat: 300, john: "mysql-sha1", example: "*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29" },
  { name: "bcrypt", regex: /^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$/, length: 60, hashcat: 3200, john: "bcrypt", example: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy" },
  { name: "MD5crypt", regex: /^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$/, length: 34, hashcat: 500, john: "md5crypt", example: "$1$salt$abc123def456ghi789jkl" },
  { name: "SHA-256crypt", regex: /^\$5\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$/, length: null, hashcat: 7400, john: "sha256crypt", example: "$5$rounds=5000$salt$hash..." },
  { name: "SHA-512crypt", regex: /^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$/, length: null, hashcat: 1800, john: "sha512crypt", example: "$6$rounds=5000$salt$hash..." },
  { name: "Argon2id", regex: /^\$argon2id\$/, length: null, hashcat: null, john: "argon2", example: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash" },
  { name: "Argon2i", regex: /^\$argon2i\$/, length: null, hashcat: null, john: "argon2", example: "$argon2i$v=19$m=65536,t=3,p=1$salt$hash" },
  { name: "scrypt", regex: /^\$scrypt\$/, length: null, hashcat: null, john: "scrypt", example: "$scrypt$ln=14,r=8,p=1$salt$hash" },
  { name: "PBKDF2-SHA256", regex: /^pbkdf2_sha256\$|^\$pbkdf2-sha256\$/, length: null, hashcat: 10900, john: "PBKDF2-HMAC-SHA256", example: "pbkdf2_sha256$260000$salt$hash" },
  { name: "DES crypt", regex: /^[./A-Za-z0-9]{13}$/, length: 13, hashcat: 1500, john: "descrypt", example: "rEK1ecacw.7.c" },
  { name: "LM Hash", regex: /^[a-f0-9]{32}$/i, length: 32, hashcat: 3000, john: "LM", example: "aad3b435b51404eeaad3b435b51404ee" },
  { name: "CRC32", regex: /^[a-f0-9]{8}$/i, length: 8, hashcat: null, john: null, example: "3610a686" },
  { name: "Apache APR1", regex: /^\$apr1\$/, length: null, hashcat: 1600, john: "md5apr1", example: "$apr1$salt$hash" },
  { name: "Cisco IOS Type 5", regex: /^\$1\$[./A-Za-z0-9]{4}\$[./A-Za-z0-9]{22}$/, length: null, hashcat: 500, john: "md5crypt", example: "$1$abcd$ef.ghijk.lmnop" },
  { name: "Cisco IOS Type 7", regex: /^[0-9]{2}[0-9a-fA-F]+$/, length: null, hashcat: null, john: null, example: "060506324F41" },
  { name: "Cisco IOS Type 9 (scrypt)", regex: /^\$9\$/, length: null, hashcat: 9300, john: null, example: "$9$salt$hash" },
  { name: "Kerberos 5 TGS-REP (etype 23)", regex: /^\$krb5tgs\$23\$/, length: null, hashcat: 13100, john: "krb5tgs", example: "$krb5tgs$23$*user$realm$..." },
  { name: "Kerberos 5 AS-REP (etype 23)", regex: /^\$krb5asrep\$23\$/, length: null, hashcat: 18200, john: "krb5asrep", example: "$krb5asrep$23$user@domain:..." },
  { name: "NetNTLMv2", regex: /^[a-zA-Z0-9]+::\w+:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$/i, length: null, hashcat: 5600, john: "netntlmv2", example: "user::domain:challenge:hash:blob" },
];

// ── Hashcat Mode Reference ──────────────────────────────────────────────────
const HASHCAT_MODES = [
  { mode: 0, name: "MD5", example: "8743b52063cd84097a65d1633f5c74f5", speed: "~60 GH/s (RTX 4090)" },
  { mode: 10, name: "md5($pass.$salt)", example: "01dfae6e5d4d90d9892622325959afbe:7050461", speed: "~50 GH/s" },
  { mode: 20, name: "md5($salt.$pass)", example: "f0fda58630310a6dd91a7d8f0a4ceda2:4225637426", speed: "~50 GH/s" },
  { mode: 50, name: "HMAC-MD5 (key=$pass)", example: "fc741db0a2968c39d9c2a5cc75b05370:1234", speed: "~8 GH/s" },
  { mode: 100, name: "SHA1", example: "b89eaac7e61417341b710b727768294d0e6a277b", speed: "~20 GH/s" },
  { mode: 110, name: "sha1($pass.$salt)", example: "2fc5a684737ce1bf7b3b239df432416e0dd07c57:2014", speed: "~18 GH/s" },
  { mode: 300, name: "MySQL4.1/MySQL5", example: "*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29", speed: "~10 GH/s" },
  { mode: 400, name: "phpass (WordPress/Drupal)", example: "$P$984478476IagS59wHZvyQMArzfx58u.", speed: "~25 MH/s" },
  { mode: 500, name: "md5crypt / MD5(Unix)", example: "$1$28772684$iEwNOgGugqO9.bIz5sk8k/", speed: "~30 MH/s" },
  { mode: 900, name: "MD4", example: "afe04867ec7a3845145579a95f72eca7", speed: "~80 GH/s" },
  { mode: 1000, name: "NTLM", example: "b4b9b02e6f09a9bd760f388b67351e2b", speed: "~80 GH/s" },
  { mode: 1100, name: "Domain Cached Credentials (DCC)", example: "4dd8965d1d476fa0d026722989a6b772:3060147285011", speed: "~20 GH/s" },
  { mode: 1300, name: "SHA2-224", example: "e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198", speed: "~3 GH/s" },
  { mode: 1400, name: "SHA2-256", example: "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935", speed: "~8 GH/s" },
  { mode: 1500, name: "descrypt (DES Unix)", example: "48c/R8JAv757A", speed: "~3 GH/s" },
  { mode: 1700, name: "SHA2-512", example: "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123aff8602e75e08e3", speed: "~2 GH/s" },
  { mode: 1800, name: "sha512crypt (SHA512 Unix)", example: "$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/", speed: "~300 KH/s" },
  { mode: 2100, name: "Domain Cached Credentials 2 (DCC2)", example: "$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f", speed: "~150 KH/s" },
  { mode: 2500, name: "WPA/WPA2 (PMKID/EAPOL)", example: "WPA*02*...", speed: "~1 MH/s" },
  { mode: 2611, name: "vBulletin < v3.8.5", example: "16780ba78d2d5f02f3202901c1b6d975:568", speed: "~50 GH/s" },
  { mode: 3000, name: "LM", example: "299bd128c1101fd6", speed: "~80 GH/s" },
  { mode: 3100, name: "Oracle H: Type (Oracle 7+)", example: "7A963A529D2E3229:3682427524", speed: "~200 MH/s" },
  { mode: 3200, name: "bcrypt", example: "$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6", speed: "~100 KH/s" },
  { mode: 5500, name: "NetNTLMv1", example: "u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb...", speed: "~50 GH/s" },
  { mode: 5600, name: "NetNTLMv2", example: "admin::N46iSNekpT:08ca45b7d7ea58ee:...", speed: "~5 GH/s" },
  { mode: 7300, name: "IPMI2 RAKP HMAC-SHA1", example: "b]c]12345:...", speed: "~3 GH/s" },
  { mode: 7400, name: "sha256crypt", example: "$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD", speed: "~800 KH/s" },
  { mode: 7500, name: "Kerberos 5 AS-REQ Pre-Auth (etype 23)", example: "$krb5pa$23$*user$realm$...", speed: "~1 GH/s" },
  { mode: 7900, name: "Drupal7", example: "$S$C33783772bRXEx1aCsvY.dqgaaSu76XmVlKrW9Qu8IQlvxHlGzok", speed: "~100 KH/s" },
  { mode: 8900, name: "scrypt", example: "SCRYPT:1024:1:1:...", speed: "~30 KH/s" },
  { mode: 9300, name: "Cisco IOS $9$ (scrypt)", example: "$9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM", speed: "~30 KH/s" },
  { mode: 9400, name: "MS Office 2007", example: "$office$*2007*...", speed: "~500 KH/s" },
  { mode: 9500, name: "MS Office 2010", example: "$office$*2010*...", speed: "~250 KH/s" },
  { mode: 9600, name: "MS Office 2013", example: "$office$*2013*...", speed: "~20 KH/s" },
  { mode: 9700, name: "MS Office <= 2003 ($0/$1, MD5+RC4)", example: "$oldoffice$1*...", speed: "~5 GH/s" },
  { mode: 10300, name: "SAP CODVN H (PWDSALTEDHASH) iSSHA-1", example: "{x-issha, 1024}...", speed: "~1 GH/s" },
  { mode: 10900, name: "PBKDF2-HMAC-SHA256", example: "sha256:1000:MTc3MTA0MDQyNGIy:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt", speed: "~2 MH/s" },
  { mode: 11300, name: "Bitcoin/Litecoin wallet.dat", example: "$bitcoin$96$...", speed: "~3 KH/s" },
  { mode: 11600, name: "7-Zip", example: "$7z$0$19$0$1122$...", speed: "~30 KH/s" },
  { mode: 12500, name: "RAR3-hp", example: "$RAR3$*0*...", speed: "~1 KH/s" },
  { mode: 13000, name: "RAR5", example: "$rar5$16$...", speed: "~100 KH/s" },
  { mode: 13100, name: "Kerberos 5 TGS-REP (etype 23)", example: "$krb5tgs$23$*user$realm$spn*$...", speed: "~500 MH/s" },
  { mode: 13400, name: "KeePass 1/2", example: "$keepass$*2*...", speed: "~500 KH/s" },
  { mode: 15300, name: "DPAPI masterkey file (v1)", example: "$DPAPImk$1*...", speed: "~200 KH/s" },
  { mode: 15900, name: "DPAPI masterkey file (v2)", example: "$DPAPImk$2*...", speed: "~10 KH/s" },
  { mode: 16800, name: "WPA-PMKID-PBKDF2", example: "2582a8281bf9d4308d6f5731d0e61c61*4604ba734d4e*89acf0e761f4*...", speed: "~1 MH/s" },
  { mode: 18200, name: "Kerberos 5 AS-REP (etype 23)", example: "$krb5asrep$23$user@domain:...", speed: "~500 MH/s" },
  { mode: 22000, name: "WPA-PBKDF2-PMKID+EAPOL", example: "WPA*02*...", speed: "~1 MH/s" },
  { mode: 22100, name: "BitLocker", example: "$bitlocker$0$...", speed: "~5 KH/s" },
  { mode: 28100, name: "Windows Hello PIN/Password", example: "$WINHELLO$*SHA512*...", speed: "~50 KH/s" },
];

// ── Password Strength Analysis ──────────────────────────────────────────────

function analyzePassword(pw) {
  if (!pw) return { score: 0, entropy: 0, feedback: ["Enter a password"], level: "none" };
  const feedback = [];
  let charsetSize = 0;
  if (/[a-z]/.test(pw)) charsetSize += 26;
  if (/[A-Z]/.test(pw)) charsetSize += 26;
  if (/[0-9]/.test(pw)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) charsetSize += 33;
  const entropy = Math.round(pw.length * Math.log2(charsetSize || 1) * 100) / 100;
  const isCommon = COMMON_PASSWORDS.includes(pw.toLowerCase());
  if (isCommon) feedback.push("This is in the top 500 most common passwords");
  if (pw.length < 8) feedback.push("Too short — use at least 12 characters");
  else if (pw.length < 12) feedback.push("Consider 12+ characters for better security");
  if (!/[a-z]/.test(pw)) feedback.push("Add lowercase letters");
  if (!/[A-Z]/.test(pw)) feedback.push("Add uppercase letters");
  if (!/[0-9]/.test(pw)) feedback.push("Add numbers");
  if (!/[^a-zA-Z0-9]/.test(pw)) feedback.push("Add special characters (!@#$%^&*)");
  if (/^(.)\1+$/.test(pw)) feedback.push("All identical characters — very weak");
  if (/^(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(pw)) feedback.push("Starts with a common sequence");
  if (/(.)\1{2,}/.test(pw)) feedback.push("Repeated characters reduce effective entropy");
  if (/^[a-zA-Z]+\d{1,4}$/.test(pw)) feedback.push("Word+number pattern is easily guessed");
  if (/^[A-Z][a-z]+\d+[!@#$%^&*]?$/.test(pw)) feedback.push("Capital-word-number-symbol pattern is common");
  const reverseCommon = COMMON_PASSWORDS.some(c => pw.toLowerCase().includes(c) && c.length > 3);
  if (reverseCommon && !isCommon) feedback.push("Contains a common password as a substring");
  let score = 0;
  if (isCommon) score = 0;
  else {
    if (entropy >= 28) score++;
    if (entropy >= 36) score++;
    if (entropy >= 50) score++;
    if (entropy >= 65) score++;
    if (entropy >= 80) score++;
    if (pw.length >= 16) score++;
    if (feedback.length <= 1) score++;
  }
  score = Math.min(score, 5);
  const levels = ["very-weak", "weak", "fair", "good", "strong", "very-strong"];
  const level = levels[Math.min(score, 5)];
  if (!feedback.length) feedback.push("Strong password");
  return { score, entropy, feedback, level, charsetSize, isCommon, length: pw.length };
}

// Uniform random integers in [0, mod) via rejection sampling. A plain
// (uint32 % mod) over-represents the first (2^32 % mod) values; discarding
// draws in that unusable tail removes the modulo bias.
function _unbiasedIndices(count, mod) {
  const out = new Array(count);
  const max = Math.floor(0x100000000 / mod) * mod;
  // getRandomValues rejects buffers over 65536 bytes (16384 uint32s), so
  // refill in bounded chunks rather than allocating one array of `count`.
  const buf = new Uint32Array(Math.min(Math.max(count, 1), 16384));
  let filled = 0;
  while (filled < count) {
    crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length && filled < count; i++) {
      if (buf[i] < max) out[filled++] = buf[i] % mod;
    }
  }
  return out;
}

function generatePassword(length, options) {
  const sets = { lower: "abcdefghijklmnopqrstuvwxyz", upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", digits: "0123456789", symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?" };
  let chars = "";
  if (options.lower !== false) chars += sets.lower;
  if (options.upper !== false) chars += sets.upper;
  if (options.digits !== false) chars += sets.digits;
  if (options.symbols !== false) chars += sets.symbols;
  if (!chars) chars = sets.lower + sets.digits;
  return _unbiasedIndices(length, chars.length).map(i => chars[i]).join("");
}

function generatePassphrase(wordCount, separator) {
  return _unbiasedIndices(wordCount, WORDLIST.length).map(i => WORDLIST[i]).join(separator || "-");
}

function identifyHash(hash) {
  const trimmed = hash.trim();
  const matches = HASH_TYPES.filter(h => h.regex.test(trimmed));
  if (!matches.length) {
    if (/^[a-f0-9]+$/i.test(trimmed)) return [{ name: "Unknown hex hash", length: trimmed.length, hashcat: null, john: null }];
    return [{ name: "Not a recognized hash format", length: trimmed.length, hashcat: null, john: null }];
  }
  return matches;
}

function estimateCrackTime(hashType, charsetSize, length) {
  const speeds = { "MD5": 6e10, "SHA-1": 2e10, "SHA-256": 8e9, "SHA-512": 2e9, "NTLM": 8e10, "bcrypt": 1e5, "scrypt": 3e4, "Argon2id": 1e3, "PBKDF2-SHA256": 2e6, "MD5crypt": 3e7, "SHA-512crypt": 3e5, "DES crypt": 3e9 };
  const speed = speeds[hashType] || 1e9;
  const keyspace = Math.pow(charsetSize, length);
  const seconds = keyspace / speed / 2;
  if (seconds < 1) return "Instant";
  if (seconds < 60) return Math.round(seconds) + " seconds";
  if (seconds < 3600) return Math.round(seconds / 60) + " minutes";
  if (seconds < 86400) return Math.round(seconds / 3600) + " hours";
  if (seconds < 86400 * 365) return Math.round(seconds / 86400) + " days";
  if (seconds < 86400 * 365 * 1000) return Math.round(seconds / (86400 * 365)) + " years";
  if (seconds < 86400 * 365 * 1e6) return Math.round(seconds / (86400 * 365 * 1000)) + " thousand years";
  if (seconds < 86400 * 365 * 1e9) return Math.round(seconds / (86400 * 365 * 1e6)) + " million years";
  return "Billions+ years";
}

// ── Policy Checks ───────────────────────────────────────────────────────────

const POLICIES = {
  "NIST 800-63B": { minLength: 8, maxLength: null, requireUpper: false, requireLower: false, requireDigit: false, requireSpecial: false, blockCommon: true, notes: "Memorized secrets SHALL be at least 8 characters. No composition rules. Must check against breach lists." },
  "PCI DSS 4.0": { minLength: 12, maxLength: null, requireUpper: true, requireLower: true, requireDigit: true, requireSpecial: true, blockCommon: true, notes: "12+ characters with numeric and alphabetic. If system doesn't support 12, minimum 8." },
  "HIPAA": { minLength: 8, maxLength: null, requireUpper: true, requireLower: true, requireDigit: true, requireSpecial: false, blockCommon: true, notes: "No explicit standard — follows NIST guidelines. Covered entities should enforce strong passwords." },
  "CIS Benchmark": { minLength: 14, maxLength: null, requireUpper: true, requireLower: true, requireDigit: true, requireSpecial: true, blockCommon: true, notes: "14+ characters, complexity required, lockout after 5 attempts, 60-day rotation." },
  "OWASP ASVS": { minLength: 12, maxLength: 128, requireUpper: false, requireLower: false, requireDigit: false, requireSpecial: false, blockCommon: true, notes: "12+ chars, no composition rules, must check against 10k+ breached passwords, max length >= 128." },
};

function checkPolicy(pw, policyName) {
  const p = POLICIES[policyName];
  if (!p) return { pass: false, issues: ["Unknown policy"] };
  const issues = [];
  if (pw.length < p.minLength) issues.push("Too short: minimum " + p.minLength + " characters (got " + pw.length + ")");
  if (p.maxLength && pw.length > p.maxLength) issues.push("Too long: maximum " + p.maxLength + " characters");
  if (p.requireUpper && !/[A-Z]/.test(pw)) issues.push("Requires uppercase letter");
  if (p.requireLower && !/[a-z]/.test(pw)) issues.push("Requires lowercase letter");
  if (p.requireDigit && !/[0-9]/.test(pw)) issues.push("Requires digit");
  if (p.requireSpecial && !/[^a-zA-Z0-9]/.test(pw)) issues.push("Requires special character");
  if (p.blockCommon && COMMON_PASSWORDS.includes(pw.toLowerCase())) issues.push("Password is on the common/breached list");
  return { pass: issues.length === 0, issues, notes: p.notes };
}

// ── UI ──────────────────────────────────────────────────────────────────────

function esc(s) { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }

export function renderPasswordTools(container) {
  const CSS = `<style>
  .pwt{font-family:var(--mono,'JetBrains Mono',monospace);color:var(--txt,#e0e6ed);max-width:1100px;margin:0 auto;padding:24px}
  .pwt h2{font-family:var(--font-display,system-ui);font-weight:700;font-size:1.4rem;margin:0 0 16px;color:var(--acc,#00d4ff)}
  .pwt-tabs{display:flex;gap:6px;margin-bottom:20px;flex-wrap:wrap}
  .pwt-tab{padding:6px 14px;border-radius:4px;cursor:pointer;font-size:.85rem;border:1px solid var(--border,#1e2a3a);background:var(--bg2,#0d1520);color:var(--mut,#8892a4)}
  .pwt-tab.active{background:var(--acc,#00d4ff);color:#000;border-color:var(--acc)}
  .pwt-panel{display:none}.pwt-panel.active{display:block}
  .pwt-input{width:100%;padding:10px 12px;background:var(--bg2,#0d1520);border:1px solid var(--border,#1e2a3a);border-radius:6px;color:var(--txt);font-family:inherit;font-size:.9rem;margin-bottom:12px}
  .pwt-input:focus{outline:none;border-color:var(--acc,#00d4ff)}
  .pwt-btn{padding:6px 16px;border-radius:6px;border:none;background:var(--acc,#00d4ff);color:#000;font-weight:600;cursor:pointer;font-size:.85rem;margin-right:8px;margin-bottom:8px}
  .pwt-btn:hover{opacity:.85}
  .pwt-btn.ghost{background:transparent;border:1px solid var(--border,#1e2a3a);color:var(--txt)}
  .pwt-meter{height:8px;border-radius:4px;background:var(--bg2,#0d1520);margin-bottom:8px;overflow:hidden}
  .pwt-fill{height:100%;border-radius:4px;transition:width .3s,background .3s}
  .pwt-result{background:var(--bg2,#0d1520);border-radius:8px;padding:12px;margin-bottom:12px;font-size:.85rem;border:1px solid var(--border,#1e2a3a)}
  .pwt-label{color:var(--mut,#8892a4);font-size:.8rem;margin-bottom:4px}
  .pwt-val{color:var(--txt);font-size:.9rem}
  .pwt-good{color:#22c55e}.pwt-warn{color:#f59e0b}.pwt-bad{color:#ef4444}
  .pwt-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  @media(max-width:768px){.pwt-grid{grid-template-columns:1fr}}
  .pwt-table{width:100%;border-collapse:collapse;font-size:.8rem;margin-bottom:12px}
  .pwt-table th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);color:var(--mut);font-weight:600}
  .pwt-table td{padding:6px 8px;border-bottom:1px solid rgba(255,255,255,.04);color:var(--txt);word-break:break-all}
  .pwt-table tr:hover td{background:rgba(0,212,255,.03)}
  .pwt-opt{display:flex;align-items:center;gap:8px;margin-bottom:8px;font-size:.85rem;color:var(--txt)}
  .pwt-opt input[type=checkbox]{accent-color:var(--acc,#00d4ff)}
  .pwt-opt input[type=range]{flex:1;accent-color:var(--acc)}
  </style>`;

  const tabNames = ["Strength Meter", "Generator", "Hash Identifier", "Hashcat Reference", "Crack Time", "Policy Check"];
  const tabHtml = tabNames.map((n, i) => '<div class="pwt-tab' + (i === 0 ? " active" : "") + '" data-idx="' + i + '">' + n + '</div>').join("");

  container.innerHTML = CSS + '<div class="pwt"><h2>Password Security Toolkit</h2><div class="pwt-tabs">' + tabHtml + '</div><div id="pwt-panels"></div></div>';
  const panelsEl = container.querySelector("#pwt-panels");

  function showTab(idx) {
    container.querySelectorAll(".pwt-tab").forEach((t, i) => t.classList.toggle("active", i === idx));
    const panels = [renderStrengthPanel, renderGeneratorPanel, renderHashIdPanel, renderHashcatPanel, renderCrackTimePanel, renderPolicyPanel];
    panels[idx]();
  }
  container.querySelectorAll(".pwt-tab").forEach(t => t.onclick = () => showTab(parseInt(t.dataset.idx)));

  function renderStrengthPanel() {
    panelsEl.innerHTML = `
      <div class="pwt-panel active">
        <input class="pwt-input" id="pw-str-input" type="text" placeholder="Enter password to analyze..." autocomplete="off">
        <div class="pwt-meter"><div class="pwt-fill" id="pw-str-fill" style="width:0%"></div></div>
        <div id="pw-str-result"></div>
      </div>`;
    const inp = panelsEl.querySelector("#pw-str-input");
    const fill = panelsEl.querySelector("#pw-str-fill");
    const res = panelsEl.querySelector("#pw-str-result");
    inp.oninput = () => {
      const a = analyzePassword(inp.value);
      const pct = (a.score / 5) * 100;
      const colors = ["#ef4444", "#ef4444", "#f59e0b", "#f59e0b", "#22c55e", "#22c55e"];
      fill.style.width = pct + "%";
      fill.style.background = colors[a.score] || "#ef4444";
      res.innerHTML = '<div class="pwt-result"><div class="pwt-grid"><div><div class="pwt-label">Strength</div><div class="pwt-val" style="color:' + colors[a.score] + '">' + esc(a.level.replace(/-/g, " ").toUpperCase()) + '</div></div><div><div class="pwt-label">Entropy</div><div class="pwt-val">' + a.entropy + ' bits</div></div><div><div class="pwt-label">Length</div><div class="pwt-val">' + (a.length || 0) + ' characters</div></div><div><div class="pwt-label">Charset Size</div><div class="pwt-val">' + (a.charsetSize || 0) + ' characters</div></div></div>' +
        '<div style="margin-top:12px"><div class="pwt-label">Feedback</div>' + a.feedback.map(f => '<div style="margin-top:4px;color:' + (f.includes("Strong") ? "#22c55e" : "#f59e0b") + '">• ' + esc(f) + '</div>').join("") +
        (a.isCommon ? '<div style="margin-top:4px;color:#ef4444;font-weight:600">This password appears in common breach lists!</div>' : "") +
        '</div></div>';
    };
  }

  function renderGeneratorPanel() {
    panelsEl.innerHTML = `
      <div class="pwt-panel active">
        <div class="pwt-opt"><label>Length:</label><input type="range" id="pw-gen-len" min="8" max="128" value="20"><span id="pw-gen-len-val">20</span></div>
        <div class="pwt-opt"><input type="checkbox" id="pw-gen-lower" checked> Lowercase (a-z)</div>
        <div class="pwt-opt"><input type="checkbox" id="pw-gen-upper" checked> Uppercase (A-Z)</div>
        <div class="pwt-opt"><input type="checkbox" id="pw-gen-digits" checked> Digits (0-9)</div>
        <div class="pwt-opt"><input type="checkbox" id="pw-gen-symbols" checked> Symbols (!@#$%^&*)</div>
        <button class="pwt-btn" id="pw-gen-go">Generate Password</button>
        <button class="pwt-btn ghost" id="pw-gen-phrase">Generate Passphrase</button>
        <div class="pwt-result" id="pw-gen-result" style="font-size:1.1rem;word-break:break-all;margin-top:12px"></div>
      </div>`;
    const lenRange = panelsEl.querySelector("#pw-gen-len");
    const lenVal = panelsEl.querySelector("#pw-gen-len-val");
    lenRange.oninput = () => lenVal.textContent = lenRange.value;
    panelsEl.querySelector("#pw-gen-go").onclick = () => {
      const pw = generatePassword(parseInt(lenRange.value), {
        lower: panelsEl.querySelector("#pw-gen-lower").checked,
        upper: panelsEl.querySelector("#pw-gen-upper").checked,
        digits: panelsEl.querySelector("#pw-gen-digits").checked,
        symbols: panelsEl.querySelector("#pw-gen-symbols").checked,
      });
      const a = analyzePassword(pw);
      panelsEl.querySelector("#pw-gen-result").innerHTML = '<span style="color:var(--acc)">' + esc(pw) + '</span><div style="margin-top:8px;font-size:.8rem;color:var(--mut)">Entropy: ' + a.entropy + ' bits · ' + a.level.replace(/-/g, " ") + '</div>';
    };
    panelsEl.querySelector("#pw-gen-phrase").onclick = () => {
      const pp = generatePassphrase(5, "-");
      const a = analyzePassword(pp);
      panelsEl.querySelector("#pw-gen-result").innerHTML = '<span style="color:var(--acc)">' + esc(pp) + '</span><div style="margin-top:8px;font-size:.8rem;color:var(--mut)">Entropy: ' + a.entropy + ' bits · ' + a.level.replace(/-/g, " ") + ' · 5-word passphrase</div>';
    };
  }

  function renderHashIdPanel() {
    panelsEl.innerHTML = `
      <div class="pwt-panel active">
        <input class="pwt-input" id="pw-hash-input" placeholder="Paste a hash to identify its type...">
        <button class="pwt-btn" id="pw-hash-go">Identify Hash</button>
        <div id="pw-hash-result"></div>
      </div>`;
    panelsEl.querySelector("#pw-hash-go").onclick = () => {
      const hash = panelsEl.querySelector("#pw-hash-input").value.trim();
      if (!hash) return;
      const matches = identifyHash(hash);
      const res = panelsEl.querySelector("#pw-hash-result");
      res.innerHTML = '<div class="pwt-result"><div class="pwt-label">Possible Hash Types (' + matches.length + ' match' + (matches.length === 1 ? "" : "es") + ')</div>' +
        '<table class="pwt-table"><tr><th>Type</th><th>Hashcat Mode</th><th>John Format</th></tr>' +
        matches.map(m => '<tr><td style="color:var(--acc)">' + esc(m.name) + '</td><td>' + (m.hashcat !== null ? m.hashcat : "—") + '</td><td>' + (m.john || "—") + '</td></tr>').join("") +
        '</table></div>';
    };
  }

  function renderHashcatPanel() {
    panelsEl.innerHTML = `
      <div class="pwt-panel active">
        <input class="pwt-input" id="pw-hc-filter" placeholder="Filter modes... (e.g. bcrypt, NTLM, kerberos)">
        <div id="pw-hc-table"></div>
      </div>`;
    const filterEl = panelsEl.querySelector("#pw-hc-filter");
    const tableEl = panelsEl.querySelector("#pw-hc-table");
    function renderTable(filter) {
      const f = (filter || "").toLowerCase();
      const filtered = f ? HASHCAT_MODES.filter(m => m.name.toLowerCase().includes(f) || String(m.mode).includes(f)) : HASHCAT_MODES;
      tableEl.innerHTML = '<table class="pwt-table"><tr><th>Mode</th><th>Name</th><th>Speed (RTX 4090)</th></tr>' +
        filtered.map(m => '<tr><td>' + m.mode + '</td><td style="color:var(--acc)">' + esc(m.name) + '</td><td style="color:var(--mut)">' + esc(m.speed) + '</td></tr>').join("") +
        '</table>' + '<div style="color:var(--mut);font-size:.75rem">' + filtered.length + ' of ' + HASHCAT_MODES.length + ' modes</div>';
    }
    filterEl.oninput = () => renderTable(filterEl.value);
    renderTable("");
  }

  function renderCrackTimePanel() {
    panelsEl.innerHTML = `
      <div class="pwt-panel active">
        <div class="pwt-grid">
          <div><div class="pwt-label">Hash Type</div><select class="pwt-input" id="pw-ct-hash" style="padding:8px"><option>MD5</option><option>SHA-1</option><option>SHA-256</option><option>SHA-512</option><option>NTLM</option><option>bcrypt</option><option>scrypt</option><option>Argon2id</option><option>PBKDF2-SHA256</option><option>MD5crypt</option><option>SHA-512crypt</option><option>DES crypt</option></select></div>
          <div><div class="pwt-label">Password Length</div><input class="pwt-input" id="pw-ct-len" type="number" min="1" max="64" value="8"></div>
        </div>
        <div class="pwt-label" style="margin-top:8px">Character Set</div>
        <div class="pwt-opt"><input type="checkbox" id="pw-ct-lower" checked> Lowercase (26)</div>
        <div class="pwt-opt"><input type="checkbox" id="pw-ct-upper" checked> Uppercase (26)</div>
        <div class="pwt-opt"><input type="checkbox" id="pw-ct-digit" checked> Digits (10)</div>
        <div class="pwt-opt"><input type="checkbox" id="pw-ct-symbol"> Symbols (33)</div>
        <button class="pwt-btn" id="pw-ct-go">Estimate</button>
        <div id="pw-ct-result"></div>
      </div>`;
    panelsEl.querySelector("#pw-ct-go").onclick = () => {
      let cs = 0;
      if (panelsEl.querySelector("#pw-ct-lower").checked) cs += 26;
      if (panelsEl.querySelector("#pw-ct-upper").checked) cs += 26;
      if (panelsEl.querySelector("#pw-ct-digit").checked) cs += 10;
      if (panelsEl.querySelector("#pw-ct-symbol").checked) cs += 33;
      if (!cs) cs = 26;
      const len = parseInt(panelsEl.querySelector("#pw-ct-len").value) || 8;
      const hashType = panelsEl.querySelector("#pw-ct-hash").value;
      const time = estimateCrackTime(hashType, cs, len);
      const keyspace = Math.pow(cs, len);
      panelsEl.querySelector("#pw-ct-result").innerHTML = '<div class="pwt-result"><div class="pwt-grid"><div><div class="pwt-label">Estimated Crack Time</div><div class="pwt-val" style="font-size:1.1rem;color:var(--acc)">' + esc(time) + '</div></div><div><div class="pwt-label">Keyspace</div><div class="pwt-val">' + (keyspace > 1e15 ? keyspace.toExponential(2) : keyspace.toLocaleString()) + '</div></div></div><div style="margin-top:8px;font-size:.8rem;color:var(--mut)">Assumes RTX 4090 GPU · Average case (50% keyspace) · No rules/masks applied</div></div>';
    };
  }

  function renderPolicyPanel() {
    panelsEl.innerHTML = `
      <div class="pwt-panel active">
        <input class="pwt-input" id="pw-pol-input" placeholder="Enter password to check against policies...">
        <button class="pwt-btn" id="pw-pol-go">Check All Policies</button>
        <div id="pw-pol-result"></div>
      </div>`;
    panelsEl.querySelector("#pw-pol-go").onclick = () => {
      const pw = panelsEl.querySelector("#pw-pol-input").value;
      if (!pw) return;
      let html = '';
      for (const [name, _] of Object.entries(POLICIES)) {
        const r = checkPolicy(pw, name);
        html += '<div class="pwt-result"><div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><span style="font-size:1.2rem">' + (r.pass ? "[OK]" : "[X]") + '</span><strong>' + esc(name) + '</strong><span class="' + (r.pass ? "pwt-good" : "pwt-bad") + '">' + (r.pass ? "PASS" : "FAIL") + '</span></div>' +
          (r.issues.length ? r.issues.map(i => '<div style="color:#f59e0b;font-size:.8rem">• ' + esc(i) + '</div>').join("") : '<div style="color:#22c55e;font-size:.8rem">All requirements met</div>') +
          '<div style="margin-top:6px;font-size:.75rem;color:var(--mut)">' + esc(r.notes) + '</div></div>';
      }
      panelsEl.querySelector("#pw-pol-result").innerHTML = html;
    };
  }

  showTab(0);
}
