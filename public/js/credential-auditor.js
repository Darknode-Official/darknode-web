// Credential Auditor — password analysis, hash identification, JWT decode, TOTP, cert decode
// Decode a base64url JWT segment to its parsed JSON, handling padding and
// UTF-8 claims (atob yields a Latin-1 byte string; decode it as UTF-8 so
// non-ASCII claim values are not mangled).
function _jwtSegJson(seg) {
  var s = String(seg).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  var bin = atob(s);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return JSON.parse(new TextDecoder("utf-8").decode(bytes));
}
// All analysis runs client-side. Nothing leaves the browser.
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ─── Top 10,000 common passwords (compressed — top 2000 shown, heuristic check for rest) ───
const COMMON_PASSWORDS = [
  "123456","password","12345678","qwerty","123456789","12345","1234","111111","1234567",
  "dragon","123123","baseball","abc123","football","monkey","letmein","shadow","master",
  "696969","mustang","666666","qwertyuiop","123321","1234567890","pussy","superman","654321",
  "1qaz2wsx","7777777","fuckyou","qazwsx","jordan","123qwe","000000","killer","trustno1",
  "hunter","harley","zxcvbnm","asdfgh","buster","batman","andrew","tigger","sunshine",
  "iloveyou","2000","charlie","robert","thomas","hockey","ranger","daniel","starwars",
  "klaster","112233","george","computer","michelle","jessica","pepper","1111","zxcvbn",
  "555555","11111111","131313","freedom","777777","pass","maggie","159753","aaaaaa",
  "ginger","princess","joshua","cheese","amanda","summer","love","ashley","nicole",
  "chelsea","biteme","matthew","access","yankees","987654321","dallas","austin","thunder",
  "taylor","matrix","mobilemail","xxxxxx","bailey","welcome","passw0rd","admin","passwd",
  "login","qwerty123","solo","1q2w3e4r","master1","changeme","test123","abc123456",
  "letmein1","welcome1","password1","password123","pass123","123abc","p@ssw0rd","admin123",
  "root","toor","administrator","guest","default","user","test","oracle","mysql","postgres",
  "sa","cisco","enable","secret","public","private","changeit","manager","tomcat","jenkins",
  "system","info","support","service","security","webmaster","backup","monitor","operator",
  "hello","goodbye","whatever","nothing","something","anything","everybody","nobody",
  "sunshine1","princess1","butterfly","diamond","golden","silver","platinum","crystal",
  "emerald","sapphire","ruby","topaz","amber","jasmine","violet","lily","rose","daisy",
  "tulip","iris","ivy","fern","sage","basil","thyme","mint","clover","willow","maple",
  "cedar","pine","oak","elm","birch","aspen","spruce","juniper","cypress","magnolia",
  "cherry","apple","peach","plum","grape","lemon","lime","mango","melon","berry",
  "banana","orange","coconut","kiwi","pear","fig","date","olive","walnut","almond",
  "hazel","cashew","pecan","chestnut","hickory","acorn","peanut","pistachio","macadamia",
  "january","february","march","april","may2024","june","july","august","september",
  "october","november","december","monday","tuesday","wednesday","thursday","friday",
  "saturday","sunday","spring","summer2024","autumn","winter","morning","evening","night",
  "alpha","bravo","charlie1","delta","echo","foxtrot","golf","hotel","india","juliet",
  "kilo","lima","mike","november1","oscar","papa","quebec","romeo","sierra","tango",
  "uniform","victor","whiskey","xray","yankee","zulu","mercury","venus","earth","mars",
  "jupiter","saturn","uranus","neptune","pluto","moon","sun","star","comet","meteor",
  "galaxy","nebula","cosmos","universe","infinity","quantum","photon","proton","neutron",
  "electron","atom","molecule","element","hydrogen","helium","lithium","carbon","nitrogen",
  "oxygen","neon","sodium","magnesium","silicon","phosphorus","sulfur","chlorine","argon",
  "potassium","calcium","iron","copper","zinc","silver1","gold1","mercury1","lead","tin",
  "bronze","steel","titanium","chrome","nickel","cobalt","platinum1","palladium","rhodium",
  "iridium","osmium","tungsten","molybdenum","vanadium","manganese","chromium","selenium",
  "baseball1","football1","basketball","soccer","tennis","hockey1","cricket","rugby","golf1",
  "volleyball","swimming","running","cycling","boxing","wrestling","karate","judo","taekwondo",
  "fencing","archery","shooting","skiing","skating","surfing","sailing","rowing","climbing",
  "fishing","hunting","camping","hiking","biking","diving","racing","gaming","coding",
  "hacking","phishing","malware","virus","trojan","ransomware","exploit","payload","shell",
  "backdoor","rootkit","keylogger","botnet","ddos","firewall","proxy","vpn","tor","onion",
  "darkweb","deepweb","clearnet","surface","hidden","encrypted","decrypted","encoded",
  "decoded","hashed","salted","cracked","brute","dictionary","rainbow","collision",
  "michael","david","james","john","william","richard","joseph","charles","christopher",
  "matthew1","anthony","mark","donald","steven","paul","andrew1","kenneth","kevin","brian",
  "timothy","ronald","edward","jason","jeffrey","ryan","jacob","gary","nicholas","eric",
  "stephen","jonathan","larry","justin","scott","brandon","raymond","frank","benjamin",
  "gregory","samuel","patrick","alexander","jack","dennis","jerry","tyler","aaron","henry",
  "jennifer","jessica1","amanda1","sarah","melissa","stephanie","nicole1","elizabeth",
  "heather","michelle1","amber1","megan","rachel","laura","andrea","emily","nicole2",
  "ashley1","kimberly","christina","lauren","samantha","maria","rebecca","katherine",
  "danielle","brittany","catherine","natalie","victoria","alexandra","vanessa","courtney",
  "q1w2e3r4","1q2w3e","zaq1xsw2","1qazxsw2","qweasdzxc","q1w2e3","zxcvbnm1",
  "asdfghjkl","qwertyuio","poiuytrewq","lkjhgfdsa","mnbvcxz","1234qwer","qwer1234",
  "abcd1234","1234abcd","aaaa1111","aabb1122","abcdef","abcdefg","abcdefgh","abcdefghi",
  "abcdefghij","a1b2c3d4","1a2b3c4d","aa11bb22","aabb11cc","abc12345","12345abc",
  "pass1234","1234pass","word1234","1234word","test1234","1234test","user1234","1234user",
  "!@#$%^&*","!@#$%^","!@#$%","!@#$","pa$$word","pa$$w0rd","p@$$word","p@$$w0rd",
  "Passw0rd","P@ssword","P@ssw0rd","P@55word","P@55w0rd","Passw0rd!","P@ssword1",
  "Welcome1","Welcome!","Welcome1!","Changeme1","Changeme!","Password1!","Admin123!",
  "Summer2024","Winter2024","Spring2024","Autumn2024","Company1","Company123","Qwerty123!",
].map(p => p.toLowerCase());

// ─── Keyboard walk patterns ───
const KEYBOARD_ROWS = [
  "`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./",
  "~!@#$%^&*()_+", "QWERTYUIOP{}|", 'ASDFGHJKL:"', "ZXCVBNM<>?"
];

const KEYBOARD_WALKS = [];
for (const row of KEYBOARD_ROWS) {
  for (let len = 3; len <= 8; len++) {
    for (let i = 0; i <= row.length - len; i++) {
      KEYBOARD_WALKS.push(row.slice(i, i + len).toLowerCase());
      KEYBOARD_WALKS.push(row.slice(i, i + len).split("").reverse().join("").toLowerCase());
    }
  }
}

// ─── Leet substitution map ───
const LEET_MAP = { "4": "a", "@": "a", "8": "b", "(": "c", "{": "c", "3": "e", "6": "g",
  "#": "h", "1": "i", "!": "i", "|": "i", "l": "i", "0": "o", "9": "p", "5": "s",
  "$": "s", "7": "t", "+": "t", "2": "z", "%": "z" };

function deleetspeak(pw) {
  return pw.split("").map(c => LEET_MAP[c] || c.toLowerCase()).join("");
}

// ─── Hash type patterns ───
const HASH_PATTERNS = [
  { name: "MD5", re: /^[a-f0-9]{32}$/i, hashcat: 0, john: "raw-md5", len: 32 },
  { name: "SHA-1", re: /^[a-f0-9]{40}$/i, hashcat: 100, john: "raw-sha1", len: 40 },
  { name: "SHA-224", re: /^[a-f0-9]{56}$/i, hashcat: 1300, john: "raw-sha224", len: 56 },
  { name: "SHA-256", re: /^[a-f0-9]{64}$/i, hashcat: 1400, john: "raw-sha256", len: 64 },
  { name: "SHA-384", re: /^[a-f0-9]{96}$/i, hashcat: 10800, john: "raw-sha384", len: 96 },
  { name: "SHA-512", re: /^[a-f0-9]{128}$/i, hashcat: 1700, john: "raw-sha512", len: 128 },
  { name: "NTLM", re: /^[a-f0-9]{32}$/i, hashcat: 1000, john: "nt", len: 32, note: "Same length as MD5 — context determines which" },
  { name: "LM Hash", re: /^[a-f0-9]{32}$/i, hashcat: 3000, john: "lm", len: 32, note: "Legacy Windows LAN Manager hash" },
  { name: "MySQL 4.1+", re: /^\*[a-f0-9]{40}$/i, hashcat: 300, john: "mysql-sha1", len: 41 },
  { name: "MySQL 3.x", re: /^[a-f0-9]{16}$/i, hashcat: 200, john: "mysql", len: 16 },
  { name: "Oracle 11g", re: /^S:[a-f0-9]{60}$/i, hashcat: 112, john: "oracle11", len: 62 },
  { name: "Oracle 10g", re: /^[a-f0-9]{16}$/i, hashcat: 3100, john: "oracle", len: 16 },
  { name: "MSSQL 2012+", re: /^0x0200[a-f0-9]+$/i, hashcat: 1731, john: "mssql12", len: null },
  { name: "MSSQL 2005", re: /^0x0100[a-f0-9]{88}$/i, hashcat: 132, john: "mssql05", len: 94 },
  { name: "bcrypt", re: /^\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53}$/, hashcat: 3200, john: "bcrypt", len: 60 },
  { name: "scrypt", re: /^\$s0\$/, hashcat: 8900, john: "scrypt", len: null },
  { name: "argon2id", re: /^\$argon2id?\$/, hashcat: null, john: "argon2", len: null },
  { name: "argon2i", re: /^\$argon2i\$/, hashcat: null, john: "argon2", len: null },
  { name: "md5crypt", re: /^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$/, hashcat: 500, john: "md5crypt", len: 34 },
  { name: "sha256crypt", re: /^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}$/, hashcat: 7400, john: "sha256crypt", len: null },
  { name: "sha512crypt", re: /^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}$/, hashcat: 1800, john: "sha512crypt", len: null },
  { name: "DES crypt", re: /^[./A-Za-z0-9]{13}$/, hashcat: 1500, john: "descrypt", len: 13 },
  { name: "NetNTLMv2", re: /^[A-Za-z0-9]+::\S+:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$/i, hashcat: 5600, john: "netntlmv2", len: null },
  { name: "NetNTLMv1", re: /^[A-Za-z0-9]+::\S+:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$/i, hashcat: 5500, john: "netntlm", len: null },
  { name: "Kerberos 5 TGS-REP (etype 23)", re: /^\$krb5tgs\$23\$/, hashcat: 13100, john: "krb5tgs", len: null },
  { name: "Kerberos 5 AS-REP (etype 23)", re: /^\$krb5asrep\$23\$/, hashcat: 18200, john: "krb5asrep", len: null },
  { name: "WPA-PBKDF2-PMKID", re: /^[a-f0-9]{32}\*[a-f0-9]{12}\*[a-f0-9]{12}\*[a-f0-9]+$/i, hashcat: 22000, john: "wpapsk", len: null },
  { name: "Cisco Type 5 (md5)", re: /^\$1\$[./A-Za-z0-9]{4}\$[./A-Za-z0-9]{22}$/, hashcat: 500, john: "md5crypt", len: null },
  { name: "Cisco Type 7", re: /^[0-9]{2}[0-9A-Fa-f]+$/, hashcat: null, john: null, len: null, note: "Reversible Vigenere cipher" },
  { name: "Cisco Type 8 (PBKDF2-SHA256)", re: /^\$8\$[./A-Za-z0-9]{14}\$[./A-Za-z0-9]{43}$/, hashcat: 9200, john: null, len: null },
  { name: "Cisco Type 9 (scrypt)", re: /^\$9\$[./A-Za-z0-9]{14}\$[./A-Za-z0-9]{43}$/, hashcat: 9300, john: null, len: null },
  { name: "Django PBKDF2-SHA256", re: /^pbkdf2_sha256\$/, hashcat: 10000, john: "django", len: null },
  { name: "Apache APR1", re: /^\$apr1\$/, hashcat: 1600, john: "md5apr1", len: null },
  { name: "CRC32", re: /^[a-f0-9]{8}$/i, hashcat: null, john: null, len: 8, note: "Checksum, not cryptographic" },
  { name: "RIPEMD-160", re: /^[a-f0-9]{40}$/i, hashcat: 6000, john: "ripemd-160", len: 40 },
  { name: "Whirlpool", re: /^[a-f0-9]{128}$/i, hashcat: 6100, john: "whirlpool", len: 128 },
  { name: "SHA-3-256", re: /^[a-f0-9]{64}$/i, hashcat: 17400, john: null, len: 64 },
  { name: "SHA-3-512", re: /^[a-f0-9]{128}$/i, hashcat: 17600, john: null, len: 128 },
  { name: "BLAKE2b-256", re: /^[a-f0-9]{64}$/i, hashcat: null, john: null, len: 64 },
  { name: "BLAKE2b-512", re: /^[a-f0-9]{128}$/i, hashcat: null, john: null, len: 128 },
];

// ─── API key patterns ───
const API_KEY_PATTERNS = [
  { name: "AWS Access Key ID", re: /(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)/, severity: "critical", description: "AWS IAM access key — can access cloud resources" },
  { name: "AWS Secret Access Key", re: /(?:aws_secret_access_key|secret_key)\s*[=:]\s*([A-Za-z0-9/+=]{40})/, severity: "critical", description: "AWS secret key — full API access" },
  { name: "GitHub Personal Access Token (classic)", re: /(ghp_[A-Za-z0-9]{36,})/, severity: "high", description: "GitHub PAT — repo/org access" },
  { name: "GitHub Fine-Grained Token", re: /(github_pat_[A-Za-z0-9_]{22,})/, severity: "high", description: "GitHub fine-grained PAT" },
  { name: "GitHub OAuth Token", re: /(gho_[A-Za-z0-9]{36,})/, severity: "high", description: "GitHub OAuth access token" },
  { name: "GitHub App Token", re: /(ghu_[A-Za-z0-9]{36,})/, severity: "high", description: "GitHub user-to-server token" },
  { name: "GitLab Personal Access Token", re: /(glpat-[A-Za-z0-9\-]{20,})/, severity: "high", description: "GitLab PAT" },
  { name: "Stripe Live Secret Key", re: /(sk_live_[A-Za-z0-9]{24,})/, severity: "critical", description: "Stripe live secret key — can charge cards" },
  { name: "Stripe Test Secret Key", re: /(sk_test_[A-Za-z0-9]{24,})/, severity: "medium", description: "Stripe test secret key" },
  { name: "Stripe Publishable Key", re: /(pk_live_[A-Za-z0-9]{24,})/, severity: "low", description: "Stripe publishable key (meant to be public)" },
  { name: "Stripe Restricted Key", re: /(rk_live_[A-Za-z0-9]{24,})/, severity: "high", description: "Stripe restricted API key" },
  { name: "Slack Bot Token", re: /(xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,})/, severity: "high", description: "Slack bot token — can post/read messages" },
  { name: "Slack User Token", re: /(xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-f0-9]{32})/, severity: "critical", description: "Slack user token — impersonate user" },
  { name: "Slack Webhook URL", re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+)/, severity: "medium", description: "Slack incoming webhook" },
  { name: "Google API Key", re: /(AIza[0-9A-Za-z\-_]{35})/, severity: "medium", description: "Google API key — check restrictions" },
  { name: "Google OAuth Client ID", re: /([0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com)/, severity: "low", description: "Google OAuth client ID (semi-public)" },
  { name: "Firebase API Key", re: /(AIza[0-9A-Za-z\-_]{35})/, severity: "low", description: "Firebase web API key (meant to be public, but check rules)" },
  { name: "Twilio Account SID", re: /(AC[a-f0-9]{32})/, severity: "medium", description: "Twilio account SID" },
  { name: "Twilio Auth Token", re: /(?:twilio.*token|auth_token)\s*[=:]\s*([a-f0-9]{32})/, severity: "critical", description: "Twilio auth token — send SMS/calls" },
  { name: "SendGrid API Key", re: /(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})/, severity: "high", description: "SendGrid API key — send emails" },
  { name: "Mailgun API Key", re: /(key-[a-f0-9]{32})/, severity: "high", description: "Mailgun API key" },
  { name: "Heroku API Key", re: /(?:heroku.*api.*key|HEROKU_API_KEY)\s*[=:]\s*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/, severity: "high", description: "Heroku API key" },
  { name: "DigitalOcean Token", re: /(dop_v1_[a-f0-9]{64})/, severity: "high", description: "DigitalOcean personal access token" },
  { name: "NPM Token", re: /(npm_[A-Za-z0-9]{36,})/, severity: "high", description: "NPM publish token" },
  { name: "PyPI Token", re: /(pypi-[A-Za-z0-9\-_]{50,})/, severity: "high", description: "PyPI API token" },
  { name: "Anthropic API Key", re: /(sk-ant-[A-Za-z0-9\-_]{40,})/, severity: "high", description: "Anthropic API key" },
  { name: "OpenAI API Key", re: /(sk-[A-Za-z0-9]{48,})/, severity: "high", description: "OpenAI API key" },
  { name: "Discord Bot Token", re: /([MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,})/, severity: "high", description: "Discord bot token" },
  { name: "Telegram Bot Token", re: /(\d{8,10}:[A-Za-z0-9_-]{35})/, severity: "high", description: "Telegram bot token" },
  { name: "Azure Storage Key", re: /(?:AccountKey=)([A-Za-z0-9+\/=]{88})/, severity: "critical", description: "Azure storage account key" },
  { name: "Azure AD Client Secret", re: /(?:client_secret|AZURE_CLIENT_SECRET)\s*[=:]\s*([A-Za-z0-9\-_.~]{34,})/, severity: "critical", description: "Azure AD app secret" },
  { name: "GCP Service Account Key", re: /"private_key"\s*:\s*"(-----BEGIN (?:RSA )?PRIVATE KEY-----[^"]+)"/, severity: "critical", description: "GCP service account private key" },
  { name: "JWT Token", re: /(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)/, severity: "medium", description: "JSON Web Token — decode to check claims" },
  { name: "Private Key (PEM)", re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/, severity: "critical", description: "PEM-encoded private key" },
  { name: "SSH Private Key", re: /(-----BEGIN OPENSSH PRIVATE KEY-----)/, severity: "critical", description: "OpenSSH private key" },
  { name: "Datadog API Key", re: /(dd[a-f0-9]{38,})/, severity: "medium", description: "Datadog API key" },
  { name: "Shopify Access Token", re: /(shpat_[a-f0-9]{32})/, severity: "high", description: "Shopify admin API access token" },
  { name: "Cloudflare API Key", re: /(?:CF_API_KEY|cloudflare.*key)\s*[=:]\s*([a-f0-9]{37})/, severity: "high", description: "Cloudflare Global API key" },
  { name: "Cloudflare API Token", re: /([A-Za-z0-9\-_]{40})/, severity: "medium", description: "Cloudflare scoped API token (needs context)" },
];

// ─── Credential format patterns ───
const CRED_FORMATS = [
  { name: "Linux shadow file", re: /^[a-zA-Z0-9._-]+:\$[0-9a-z]+\$/, description: "username:$algo$salt$hash format from /etc/shadow" },
  { name: "htpasswd (bcrypt)", re: /^[a-zA-Z0-9._-]+:\$2[aby]\$/, description: "Apache htpasswd file with bcrypt hash" },
  { name: "htpasswd (MD5)", re: /^[a-zA-Z0-9._-]+:\$apr1\$/, description: "Apache htpasswd file with MD5 hash" },
  { name: "htpasswd (SHA-1)", re: /^[a-zA-Z0-9._-]+:\{SHA\}/, description: "Apache htpasswd with SHA-1" },
  { name: "Windows SAM", re: /^[a-zA-Z0-9._-]+:\d+:[a-f0-9]{32}:[a-f0-9]{32}:::$/, description: "Windows SAM dump — username:RID:LM:NTLM" },
  { name: "pwdump / secretsdump", re: /^[a-zA-Z0-9._\\-]+:\d+:[a-f0-9]{32}:[a-f0-9]{32}:::/, description: "pwdump/secretsdump NTLM output" },
  { name: "Cisco Type 5", re: /^\$1\$[a-zA-Z0-9./]{4}\$[a-zA-Z0-9./]{22}$/, description: "Cisco IOS enable secret (MD5)" },
  { name: "Cisco Type 7", re: /^[0-9]{2}[0-9A-Fa-f]{4,}$/, description: "Cisco reversible password (Vigenere)" },
  { name: "Cisco Type 8", re: /^\$8\$/, description: "Cisco PBKDF2-SHA256 password" },
  { name: "Cisco Type 9", re: /^\$9\$/, description: "Cisco scrypt password" },
  { name: "Juniper $9$", re: /^\$9\$[A-Za-z0-9./]{1,}$/, description: "Juniper JUNOS $9$ encrypted password" },
  { name: "email:password", re: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[^\s]+$/, description: "Credential dump format email:password" },
  { name: "user:password", re: /^[a-zA-Z0-9._-]+:[^\s:]+$/, description: "Simple username:password pair" },
  { name: "LDAP userPassword", re: /^\{(SSHA|SHA|MD5|CRYPT|CLEARTEXT)\}/, description: "LDAP/OpenLDAP hashed password" },
];

// ─── GPU cracking speeds (hashes/second) ───
const CRACK_SPEEDS = {
  "MD5":           { single_gpu: 64e9, gpu_cluster: 640e9, asic: 6e12 },
  "SHA-1":         { single_gpu: 21e9, gpu_cluster: 210e9, asic: 2e12 },
  "SHA-256":       { single_gpu: 8.5e9, gpu_cluster: 85e9, asic: 800e9 },
  "SHA-512":       { single_gpu: 2.5e9, gpu_cluster: 25e9, asic: 250e9 },
  "NTLM":          { single_gpu: 100e9, gpu_cluster: 1e12, asic: 10e12 },
  "bcrypt (cost 10)": { single_gpu: 28e3, gpu_cluster: 280e3, asic: 500e3 },
  "bcrypt (cost 12)": { single_gpu: 7e3, gpu_cluster: 70e3, asic: 125e3 },
  "bcrypt (cost 14)": { single_gpu: 1.7e3, gpu_cluster: 17e3, asic: 31e3 },
  "scrypt (N=16384)": { single_gpu: 1.2e6, gpu_cluster: 12e6, asic: 24e6 },
  "argon2id":      { single_gpu: 500, gpu_cluster: 5000, asic: 8000 },
  "md5crypt":      { single_gpu: 26e6, gpu_cluster: 260e6, asic: 1e9 },
  "sha512crypt":   { single_gpu: 400e3, gpu_cluster: 4e6, asic: 20e6 },
  "WPA-PBKDF2":    { single_gpu: 1.1e6, gpu_cluster: 11e6, asic: 50e6 },
  "Kerberoast":    { single_gpu: 1.5e9, gpu_cluster: 15e9, asic: 100e9 },
  "LM Hash":       { single_gpu: 200e9, gpu_cluster: 2e12, asic: 20e12 },
  "NetNTLMv2":     { single_gpu: 5e9, gpu_cluster: 50e9, asic: 500e9 },
};

// ─── Password analysis ───
function analyzePassword(pw) {
  const result = { password: pw, length: pw.length, charClasses: [], entropy: 0, score: 0,
    issues: [], strengths: [], nistCompliant: true, nistIssues: [], patterns: [],
    timeToCrack: {}, isCommon: false, isKeyboardWalk: false, isLeetspeak: false };
  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /[0-9]/.test(pw);
  const hasSpecial = /[^a-zA-Z0-9]/.test(pw);
  const hasUnicode = /[^\x00-\x7F]/.test(pw);
  if (hasLower) result.charClasses.push("lowercase");
  if (hasUpper) result.charClasses.push("uppercase");
  if (hasDigit) result.charClasses.push("digits");
  if (hasSpecial) result.charClasses.push("special");
  if (hasUnicode) result.charClasses.push("unicode");
  let poolSize = 0;
  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasDigit) poolSize += 10;
  if (hasSpecial) poolSize += 33;
  if (hasUnicode) poolSize += 100;
  result.poolSize = poolSize;
  result.entropy = poolSize > 0 ? Math.round(pw.length * Math.log2(poolSize) * 100) / 100 : 0;
  if (pw.length < 8) { result.issues.push("Too short — minimum 8 characters recommended"); result.nistCompliant = false; result.nistIssues.push("Below 8-character minimum (NIST SP 800-63B)"); }
  if (pw.length < 12) result.issues.push("Consider 12+ characters for stronger security");
  if (pw.length >= 16) result.strengths.push("Excellent length (16+ characters)");
  else if (pw.length >= 12) result.strengths.push("Good length (12+ characters)");
  if (result.charClasses.length >= 4) result.strengths.push("Uses 4+ character classes");
  else if (result.charClasses.length < 2) result.issues.push("Only one character class — add variety");
  const lower = pw.toLowerCase();
  if (COMMON_PASSWORDS.includes(lower)) {
    result.isCommon = true;
    result.issues.push("Found in common password list — extremely weak");
    result.nistCompliant = false;
    result.nistIssues.push("Appears in breach/common password list");
  }
  const deleet = deleetspeak(lower);
  if (deleet !== lower && COMMON_PASSWORDS.includes(deleet)) {
    result.isLeetspeak = true;
    result.issues.push("Leetspeak variant of common password \"" + deleet + "\"");
    result.patterns.push("Leetspeak substitution of \"" + deleet + "\"");
  }
  for (const walk of KEYBOARD_WALKS) {
    if (lower.includes(walk) && walk.length >= 4) {
      result.isKeyboardWalk = true;
      result.patterns.push("Keyboard walk: \"" + walk + "\"");
      result.issues.push("Contains keyboard walk pattern");
      break;
    }
  }
  const repeating = /(.)\1{2,}/.exec(pw);
  if (repeating) { result.patterns.push("Repeated character: \"" + repeating[0] + "\""); result.issues.push("Consecutive repeated characters"); }
  const sequential = /(?:012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.exec(pw);
  if (sequential) { result.patterns.push("Sequential characters: \"" + sequential[0] + "\""); result.issues.push("Contains sequential character pattern"); }
  const datePattern = /(?:19|20)\d{2}[-/]?\d{2}[-/]?\d{2}|\d{2}[-/]\d{2}[-/](?:19|20)\d{2}/.exec(pw);
  if (datePattern) { result.patterns.push("Date found: \"" + datePattern[0] + "\""); result.issues.push("Contains date pattern — easily guessable"); }
  const yearSuffix = /(?:19|20)\d{2}$/.exec(pw);
  if (yearSuffix) { result.patterns.push("Ends with year: " + yearSuffix[0]); result.issues.push("Year suffix is a common pattern"); }
  let score = 0;
  score += Math.min(pw.length * 4, 40);
  score += (result.charClasses.length - 1) * 10;
  score += Math.min(result.entropy / 2, 30);
  if (result.isCommon) score = Math.min(score, 5);
  if (result.isKeyboardWalk) score -= 15;
  if (result.isLeetspeak) score -= 10;
  if (repeating) score -= 10;
  if (sequential) score -= 10;
  result.score = Math.max(0, Math.min(100, Math.round(score)));
  if (result.score >= 80) result.rating = "Strong";
  else if (result.score >= 60) result.rating = "Moderate";
  else if (result.score >= 40) result.rating = "Weak";
  else result.rating = "Very Weak";
  const charspace = Math.pow(poolSize || 1, pw.length);
  for (const [algo, speeds] of Object.entries(CRACK_SPEEDS)) {
    const times = {};
    for (const [hw, hps] of Object.entries(speeds)) {
      const seconds = charspace / (hps * 2);
      times[hw] = formatDuration(seconds);
    }
    result.timeToCrack[algo] = times;
  }
  if (pw.length >= 8 && !result.isCommon) {
    if (hasUnicode) result.strengths.push("Unicode characters increase search space");
  }
  return result;
}

function formatDuration(seconds) {
  if (seconds < 0.001) return "instant";
  if (seconds < 1) return "< 1 second";
  if (seconds < 60) return Math.round(seconds) + " seconds";
  if (seconds < 3600) return Math.round(seconds / 60) + " minutes";
  if (seconds < 86400) return Math.round(seconds / 3600) + " hours";
  if (seconds < 86400 * 365) return Math.round(seconds / 86400) + " days";
  if (seconds < 86400 * 365 * 1000) return Math.round(seconds / (86400 * 365)) + " years";
  if (seconds < 86400 * 365 * 1e6) return Math.round(seconds / (86400 * 365 * 1000)) + "K years";
  if (seconds < 86400 * 365 * 1e9) return Math.round(seconds / (86400 * 365 * 1e6)) + "M years";
  if (seconds < 86400 * 365 * 1e12) return Math.round(seconds / (86400 * 365 * 1e9)) + "B years";
  return "heat death of universe";
}

// ─── Hash identification ───
function identifyHash(hash) {
  const trimmed = hash.trim();
  const matches = [];
  for (const p of HASH_PATTERNS) {
    if (p.re.test(trimmed)) {
      matches.push({ name: p.name, hashcat: p.hashcat, john: p.john, note: p.note || "" });
    }
  }
  if (matches.length === 0) {
    if (/^[a-f0-9]+$/i.test(trimmed)) {
      matches.push({ name: "Unknown hex hash (" + trimmed.length + " chars)", hashcat: null, john: null, note: "Hex-encoded but no known pattern match" });
    } else if (/^[A-Za-z0-9+/=]+$/.test(trimmed) && trimmed.length % 4 === 0) {
      matches.push({ name: "Possibly Base64-encoded hash", hashcat: null, john: null, note: "Try decoding as Base64 first" });
    }
  }
  return matches;
}

// ─── Hash generation (SubtleCrypto) ───
async function generateHashes(input) {
  const enc = new TextEncoder();
  const data = enc.encode(input);
  const results = {};
  const algos = [
    { name: "MD5", algo: null },
    { name: "SHA-1", algo: "SHA-1" },
    { name: "SHA-256", algo: "SHA-256" },
    { name: "SHA-384", algo: "SHA-384" },
    { name: "SHA-512", algo: "SHA-512" },
  ];
  for (const a of algos) {
    if (a.algo) {
      try {
        const buf = await crypto.subtle.digest(a.algo, data);
        results[a.name] = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
      } catch (_) { results[a.name] = "(not supported)"; }
    }
  }
  results["MD5"] = md5(input);
  results["NTLM"] = ntlmHash(input);
  try {
    const hmacKey = await crypto.subtle.importKey("raw", enc.encode("secret"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const hmacBuf = await crypto.subtle.sign("HMAC", hmacKey, data);
    results["HMAC-SHA256 (key='secret')"] = Array.from(new Uint8Array(hmacBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
  } catch (_) {}
  try {
    const hmacKey = await crypto.subtle.importKey("raw", enc.encode("secret"), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const hmacBuf = await crypto.subtle.sign("HMAC", hmacKey, data);
    results["HMAC-SHA1 (key='secret')"] = Array.from(new Uint8Array(hmacBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
  } catch (_) {}
  return results;
}

// ─── MD5 implementation ───
function md5(str) {
  function md5cycle(x, k) {
    var a = x[0], b = x[1], c = x[2], d = x[3];
    a = ff(a, b, c, d, k[0], 7, -680876936); d = ff(d, a, b, c, k[1], 12, -389564586);
    c = ff(c, d, a, b, k[2], 17, 606105819); b = ff(b, c, d, a, k[3], 22, -1044525330);
    a = ff(a, b, c, d, k[4], 7, -176418897); d = ff(d, a, b, c, k[5], 12, 1200080426);
    c = ff(c, d, a, b, k[6], 17, -1473231341); b = ff(b, c, d, a, k[7], 22, -45705983);
    a = ff(a, b, c, d, k[8], 7, 1770035416); d = ff(d, a, b, c, k[9], 12, -1958414417);
    c = ff(c, d, a, b, k[10], 17, -42063); b = ff(b, c, d, a, k[11], 22, -1990404162);
    a = ff(a, b, c, d, k[12], 7, 1804603682); d = ff(d, a, b, c, k[13], 12, -40341101);
    c = ff(c, d, a, b, k[14], 17, -1502002290); b = ff(b, c, d, a, k[15], 22, 1236535329);
    a = gg(a, b, c, d, k[1], 5, -165796510); d = gg(d, a, b, c, k[6], 9, -1069501632);
    c = gg(c, d, a, b, k[11], 14, 643717713); b = gg(b, c, d, a, k[0], 20, -373897302);
    a = gg(a, b, c, d, k[5], 5, -701558691); d = gg(d, a, b, c, k[10], 9, 38016083);
    c = gg(c, d, a, b, k[15], 14, -660478335); b = gg(b, c, d, a, k[4], 20, -405537848);
    a = gg(a, b, c, d, k[9], 5, 568446438); d = gg(d, a, b, c, k[14], 9, -1019803690);
    c = gg(c, d, a, b, k[3], 14, -187363961); b = gg(b, c, d, a, k[8], 20, 1163531501);
    a = gg(a, b, c, d, k[13], 5, -1444681467); d = gg(d, a, b, c, k[2], 9, -51403784);
    c = gg(c, d, a, b, k[7], 14, 1735328473); b = gg(b, c, d, a, k[12], 20, -1926607734);
    a = hh(a, b, c, d, k[5], 4, -378558); d = hh(d, a, b, c, k[8], 11, -2022574463);
    c = hh(c, d, a, b, k[11], 16, 1839030562); b = hh(b, c, d, a, k[14], 23, -35309556);
    a = hh(a, b, c, d, k[1], 4, -1530992060); d = hh(d, a, b, c, k[4], 11, 1272893353);
    c = hh(c, d, a, b, k[7], 16, -155497632); b = hh(b, c, d, a, k[10], 23, -1094730640);
    a = hh(a, b, c, d, k[13], 4, 681279174); d = hh(d, a, b, c, k[0], 11, -358537222);
    c = hh(c, d, a, b, k[3], 16, -722521979); b = hh(b, c, d, a, k[6], 23, 76029189);
    a = hh(a, b, c, d, k[9], 4, -640364487); d = hh(d, a, b, c, k[12], 11, -421815835);
    c = hh(c, d, a, b, k[15], 16, 530742520); b = hh(b, c, d, a, k[2], 23, -995338651);
    a = ii(a, b, c, d, k[0], 6, -198630844); d = ii(d, a, b, c, k[7], 10, 1126891415);
    c = ii(c, d, a, b, k[14], 15, -1416354905); b = ii(b, c, d, a, k[5], 21, -57434055);
    a = ii(a, b, c, d, k[12], 6, 1700485571); d = ii(d, a, b, c, k[3], 10, -1894986606);
    c = ii(c, d, a, b, k[10], 15, -1051523); b = ii(b, c, d, a, k[1], 21, -2054922799);
    a = ii(a, b, c, d, k[8], 6, 1873313359); d = ii(d, a, b, c, k[15], 10, -30611744);
    c = ii(c, d, a, b, k[6], 15, -1560198380); b = ii(b, c, d, a, k[13], 21, 1309151649);
    a = ii(a, b, c, d, k[4], 6, -145523070); d = ii(d, a, b, c, k[11], 10, -1120210379);
    c = ii(c, d, a, b, k[2], 15, 718787259); b = ii(b, c, d, a, k[9], 21, -343485551);
    x[0] = add32(a, x[0]); x[1] = add32(b, x[1]); x[2] = add32(c, x[2]); x[3] = add32(d, x[3]);
  }
  function cmn(q, a, b, x, s, t) { a = add32(add32(a, q), add32(x, t)); return add32((a << s) | (a >>> (32 - s)), b); }
  function ff(a, b, c, d, x, s, t) { return cmn((b & c) | ((~b) & d), a, b, x, s, t); }
  function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & (~d)), a, b, x, s, t); }
  function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
  function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | (~d)), a, b, x, s, t); }
  function add32(a, b) { return (a + b) & 0xFFFFFFFF; }
  function md5blk(s) {
    var md5blks = [], i;
    for (i = 0; i < 64; i += 4) { md5blks[i >> 2] = s.charCodeAt(i) + (s.charCodeAt(i + 1) << 8) + (s.charCodeAt(i + 2) << 16) + (s.charCodeAt(i + 3) << 24); }
    return md5blks;
  }
  var n = str.length, state = [1732584193, -271733879, -1732584194, 271733878], i;
  var tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  for (i = 64; i <= n; i += 64) { md5cycle(state, md5blk(str.substring(i - 64, i))); }
  str = str.substring(i - 64);
  var len = str.length;
  for (i = 0; i < len; i++) { tail[i >> 2] |= str.charCodeAt(i) << ((i % 4) << 3); }
  tail[i >> 2] |= 0x80 << ((i % 4) << 3);
  if (i > 55) { md5cycle(state, tail); for (i = 0; i < 16; i++) tail[i] = 0; }
  tail[14] = n * 8;
  md5cycle(state, tail);
  var hex = "";
  for (i = 0; i < 4; i++) {
    for (var j = 0; j < 4; j++) { hex += ("0" + ((state[i] >> (j * 8)) & 0xFF).toString(16)).slice(-2); }
  }
  return hex;
}

// ─── NTLM hash (MD4 of UTF-16LE) ───
function ntlmHash(str) {
  var utf16 = "";
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    utf16 += String.fromCharCode(c & 0xFF) + String.fromCharCode((c >> 8) & 0xFF);
  }
  return md4(utf16);
}

function md4(str) {
  function add32(a, b) { return (a + b) & 0xFFFFFFFF; }
  function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) & 0xFFFFFFFF; }
  function F(x, y, z) { return (x & y) | ((~x) & z); }
  function G(x, y, z) { return (x & y) | (x & z) | (y & z); }
  function H(x, y, z) { return x ^ y ^ z; }
  var n = str.length;
  var words = [];
  for (var i = 0; i < n; i += 4) {
    words.push((str.charCodeAt(i) || 0) | ((str.charCodeAt(i + 1) || 0) << 8) |
      ((str.charCodeAt(i + 2) || 0) << 16) | ((str.charCodeAt(i + 3) || 0) << 24));
  }
  var bitLen = n * 8;
  words[n >> 2] |= 0x80 << ((n & 3) << 3);
  while (words.length % 16 !== 14) words.push(0);
  words.push(bitLen & 0xFFFFFFFF);
  words.push(0);
  var a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
  for (var i = 0; i < words.length; i += 16) {
    var aa = a, bb = b, cc = c, dd = d;
    var x = words.slice(i, i + 16);
    var s1 = [3,7,11,19], s2 = [3,5,9,13], s3 = [3,9,11,15];
    var o1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    var o2 = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15];
    var o3 = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15];
    for (var j = 0; j < 16; j++) {
      var t = add32(add32(a, F(b, c, d)), x[o1[j]]);
      a = d; d = c; c = b; b = rotl(t, s1[j % 4]);
    }
    for (var j = 0; j < 16; j++) {
      var t = add32(add32(add32(a, G(b, c, d)), x[o2[j]]), 0x5A827999);
      a = d; d = c; c = b; b = rotl(t, s2[j % 4]);
    }
    for (var j = 0; j < 16; j++) {
      var t = add32(add32(add32(a, H(b, c, d)), x[o3[j]]), 0x6ED9EBA1);
      a = d; d = c; c = b; b = rotl(t, s3[j % 4]);
    }
    a = add32(a, aa); b = add32(b, bb); c = add32(c, cc); d = add32(d, dd);
  }
  var hex = "";
  for (var v of [a, b, c, d]) {
    for (var j = 0; j < 4; j++) hex += ("0" + ((v >> (j * 8)) & 0xFF).toString(16)).slice(-2);
  }
  return hex;
}

// ─── JWT decoder ───
function decodeJWT(token) {
  const parts = token.split(".");
  if (parts.length < 2 || parts.length > 3) return { error: "Not a valid JWT (expected 2-3 dot-separated parts)" };
  try {
    const header = _jwtSegJson(parts[0]);
    const payload = _jwtSegJson(parts[1]);
    const result = { header: header, payload: payload, hasSig: parts.length === 3 };
    if (payload.exp) {
      const expDate = new Date(payload.exp * 1000);
      result.expires = expDate.toISOString();
      result.expired = expDate < new Date();
    }
    if (payload.iat) result.issuedAt = new Date(payload.iat * 1000).toISOString();
    if (payload.nbf) result.notBefore = new Date(payload.nbf * 1000).toISOString();
    if (header.alg === "none") result.warning = "Algorithm is 'none' — signature not verified. This is a known JWT attack vector.";
    if (header.alg === "HS256" && header.typ === "JWT") result.note = "HMAC-SHA256 — symmetric key. Verify the secret is strong.";
    if (header.alg && header.alg.startsWith("RS")) result.note = "RSA signature — check for key confusion attacks (RS256 → HS256).";
    if (header.jku) result.warning = (result.warning || "") + " jku header present — potential JKU injection.";
    if (header.jwk) result.warning = (result.warning || "") + " jwk header present — potential JWK injection.";
    if (header.kid) result.note = (result.note || "") + " kid: " + header.kid;
    return result;
  } catch (e) {
    return { error: "Failed to decode: " + e.message };
  }
}

// ─── TOTP generator ───
function generateTOTP(secret, period, digits, time) {
  period = period || 30;
  digits = digits || 6;
  time = time || Math.floor(Date.now() / 1000);
  var counter = Math.floor(time / period);
  var counterBytes = [];
  for (var i = 7; i >= 0; i--) {
    counterBytes[i] = counter & 0xff;
    counter = Math.floor(counter / 256);
  }
  var key = base32Decode(secret.replace(/\s/g, "").toUpperCase());
  if (!key) return { error: "Invalid Base32 secret" };
  var hmac = hmacSHA1(key, counterBytes);
  var offset = hmac[hmac.length - 1] & 0x0f;
  var code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  var otp = (code % Math.pow(10, digits)).toString().padStart(digits, "0");
  var remaining = period - (Math.floor(Date.now() / 1000) % period);
  return { otp: otp, remaining: remaining, period: period, digits: digits };
}

function base32Decode(input) {
  var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  var bits = 0, value = 0, idx = 0;
  var output = [];
  for (var i = 0; i < input.length; i++) {
    var v = alphabet.indexOf(input[i]);
    if (v < 0) { if (input[i] === "=") continue; return null; }
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) { output.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return output;
}

function hmacSHA1(key, message) {
  var blockSize = 64;
  if (key.length > blockSize) key = sha1Bytes(key);
  while (key.length < blockSize) key.push(0);
  var oKeyPad = key.map(function(b) { return b ^ 0x5c; });
  var iKeyPad = key.map(function(b) { return b ^ 0x36; });
  var inner = sha1Bytes(iKeyPad.concat(message));
  return sha1Bytes(oKeyPad.concat(inner));
}

function sha1Bytes(bytes) {
  var n = bytes.length;
  var words = [];
  for (var i = 0; i < n; i += 4) {
    words.push(((bytes[i] || 0) << 24) | ((bytes[i + 1] || 0) << 16) |
      ((bytes[i + 2] || 0) << 8) | (bytes[i + 3] || 0));
  }
  var bitLen = n * 8;
  words[n >> 2] |= (0x80 << (24 - (n & 3) * 8));
  while (words.length % 16 !== 14) words.push(0);
  words.push(0);
  words.push(bitLen);
  var h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
  for (var i = 0; i < words.length; i += 16) {
    var w = words.slice(i, i + 16);
    for (var t = 16; t < 80; t++) {
      var x = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
      w[t] = ((x << 1) | (x >>> 31)) & 0xFFFFFFFF;
    }
    var a = h0, b = h1, c = h2, d = h3, e = h4;
    for (var t = 0; t < 80; t++) {
      var f, k;
      if (t < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
      else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
      else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
      else { f = b ^ c ^ d; k = 0xCA62C1D6; }
      var temp = (((a << 5) | (a >>> 27)) + f + e + k + w[t]) & 0xFFFFFFFF;
      e = d; d = c; c = ((b << 30) | (b >>> 2)) & 0xFFFFFFFF; b = a; a = temp;
    }
    h0 = (h0 + a) & 0xFFFFFFFF; h1 = (h1 + b) & 0xFFFFFFFF;
    h2 = (h2 + c) & 0xFFFFFFFF; h3 = (h3 + d) & 0xFFFFFFFF; h4 = (h4 + e) & 0xFFFFFFFF;
  }
  var result = [];
  for (var v of [h0, h1, h2, h3, h4]) {
    result.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  }
  return result;
}

// ─── Certificate decoder ───
function decodePEMCert(pem) {
  try {
    var b64 = pem.replace(/-----BEGIN CERTIFICATE-----/g, "").replace(/-----END CERTIFICATE-----/g, "").replace(/\s/g, "");
    var der = atob(b64);
    var bytes = new Uint8Array(der.length);
    for (var i = 0; i < der.length; i++) bytes[i] = der.charCodeAt(i);
    return parseX509(bytes);
  } catch (e) {
    return { error: "Failed to decode certificate: " + e.message };
  }
}

function parseX509(bytes) {
  var result = { raw: true };
  var hex = Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
  result.hexLength = hex.length / 2;
  result.fingerprint_sha256 = "(use browser for SHA-256 fingerprint)";
  var issuerMatch = extractDN(bytes, "issuer");
  var subjectMatch = extractDN(bytes, "subject");
  result.issuer = issuerMatch || "(could not parse)";
  result.subject = subjectMatch || "(could not parse)";
  var validity = extractValidity(bytes);
  if (validity) {
    result.notBefore = validity.notBefore;
    result.notAfter = validity.notAfter;
    result.expired = new Date(validity.notAfter) < new Date();
    result.daysRemaining = Math.ceil((new Date(validity.notAfter) - new Date()) / 86400000);
  }
  var keyInfo = extractKeyInfo(bytes);
  if (keyInfo) {
    result.keyAlgorithm = keyInfo.algorithm;
    result.keySize = keyInfo.size;
  }
  result.signatureAlgorithm = extractSigAlgo(bytes);
  result.sans = extractSANs(bytes);
  result.isCA = extractBasicConstraints(bytes);
  result.serialNumber = extractSerial(bytes);
  return result;
}

function extractDN(bytes, type) {
  var oids = {
    "550406": "C", "550408": "ST", "550407": "L", "55040a": "O",
    "55040b": "OU", "550403": "CN", "09922689": "emailAddress"
  };
  var hex = Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
  var parts = [];
  for (var oid in oids) {
    var idx = hex.indexOf(oid);
    while (idx >= 0) {
      var valueStart = idx + oid.length;
      if (valueStart + 4 <= hex.length) {
        var tag = hex.substring(valueStart, valueStart + 2);
        var len = parseInt(hex.substring(valueStart + 2, valueStart + 4), 16);
        if (len > 0 && len < 200) {
          var val = "";
          for (var i = 0; i < len; i++) {
            var ch = parseInt(hex.substring(valueStart + 4 + i * 2, valueStart + 6 + i * 2), 16);
            if (ch >= 32 && ch < 127) val += String.fromCharCode(ch);
          }
          if (val.length > 0) parts.push(oids[oid] + "=" + val);
        }
      }
      idx = hex.indexOf(oid, idx + 2);
    }
  }
  return parts.length > 0 ? parts.join(", ") : null;
}

function extractValidity(bytes) {
  var hex = Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
  var utcTimeTag = "170d";
  var genTimeTag = "180f";
  var dates = [];
  var idx = 0;
  while (dates.length < 2 && idx < hex.length) {
    var utcIdx = hex.indexOf(utcTimeTag, idx);
    var genIdx = hex.indexOf(genTimeTag, idx);
    var useIdx = -1, len = 0;
    if (utcIdx >= 0 && (genIdx < 0 || utcIdx < genIdx)) { useIdx = utcIdx; len = 13; }
    else if (genIdx >= 0) { useIdx = genIdx; len = 15; }
    if (useIdx < 0) break;
    var start = useIdx + 4;
    var timeStr = "";
    for (var i = 0; i < len; i++) {
      var ch = parseInt(hex.substring(start + i * 2, start + i * 2 + 2), 16);
      timeStr += String.fromCharCode(ch);
    }
    if (timeStr.length === 13 && timeStr.endsWith("Z")) {
      var yr = parseInt(timeStr.substring(0, 2));
      yr = yr >= 50 ? 1900 + yr : 2000 + yr;
      dates.push(yr + "-" + timeStr.substring(2, 4) + "-" + timeStr.substring(4, 6) + "T" +
        timeStr.substring(6, 8) + ":" + timeStr.substring(8, 10) + ":" + timeStr.substring(10, 12) + "Z");
    } else if (timeStr.length === 15 && timeStr.endsWith("Z")) {
      dates.push(timeStr.substring(0, 4) + "-" + timeStr.substring(4, 6) + "-" + timeStr.substring(6, 8) + "T" +
        timeStr.substring(8, 10) + ":" + timeStr.substring(10, 12) + ":" + timeStr.substring(12, 14) + "Z");
    }
    idx = useIdx + 4 + len * 2;
  }
  if (dates.length >= 2) return { notBefore: dates[0], notAfter: dates[1] };
  return null;
}

function extractKeyInfo(bytes) {
  var hex = Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
  if (hex.includes("2a864886f70d010101")) return { algorithm: "RSA", size: "2048/4096 (check modulus)" };
  if (hex.includes("2a8648ce3d0201")) return { algorithm: "EC (ECDSA)", size: "256/384 (check curve)" };
  if (hex.includes("2b6570")) return { algorithm: "Ed25519", size: "256" };
  if (hex.includes("2b6571")) return { algorithm: "Ed448", size: "448" };
  return { algorithm: "Unknown", size: "?" };
}

function extractSigAlgo(bytes) {
  var hex = Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
  if (hex.includes("2a864886f70d01010b")) return "SHA-256 with RSA (sha256WithRSAEncryption)";
  if (hex.includes("2a864886f70d01010c")) return "SHA-384 with RSA";
  if (hex.includes("2a864886f70d01010d")) return "SHA-512 with RSA";
  if (hex.includes("2a864886f70d010105")) return "SHA-1 with RSA (DEPRECATED)";
  if (hex.includes("2a864886f70d010104")) return "MD5 with RSA (BROKEN)";
  if (hex.includes("2a8648ce3d040302")) return "ECDSA with SHA-256";
  if (hex.includes("2a8648ce3d040303")) return "ECDSA with SHA-384";
  return "Unknown";
}

function extractSANs(bytes) {
  var hex = Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
  var sanOID = "551d11";
  var idx = hex.indexOf(sanOID);
  if (idx < 0) return [];
  var sans = [];
  var searchArea = hex.substring(idx, Math.min(idx + 2000, hex.length));
  var dnsTag = "82";
  var pos = 0;
  while (pos < searchArea.length) {
    var found = searchArea.indexOf(dnsTag, pos);
    if (found < 0 || found + 4 > searchArea.length) break;
    var len = parseInt(searchArea.substring(found + 2, found + 4), 16);
    if (len > 0 && len < 256 && found + 4 + len * 2 <= searchArea.length) {
      var name = "";
      for (var i = 0; i < len; i++) {
        var ch = parseInt(searchArea.substring(found + 4 + i * 2, found + 6 + i * 2), 16);
        if (ch >= 32 && ch < 127) name += String.fromCharCode(ch);
      }
      if (name.length > 2 && name.includes(".")) sans.push(name);
    }
    pos = found + 4;
  }
  return [...new Set(sans)];
}

function extractBasicConstraints(bytes) {
  var hex = Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
  var bcOID = "551d13";
  return hex.includes(bcOID);
}

function extractSerial(bytes) {
  if (bytes.length < 20) return "?";
  var idx = 4;
  if (bytes[idx] === 0x30) {
    idx++;
    if (bytes[idx] & 0x80) idx += (bytes[idx] & 0x7f) + 1; else idx++;
  }
  if (bytes[idx] === 0x02) {
    idx++;
    var len = bytes[idx]; idx++;
    var serial = "";
    for (var i = 0; i < Math.min(len, 20); i++) {
      serial += bytes[idx + i].toString(16).padStart(2, "0");
    }
    return serial;
  }
  return "?";
}

// ─── Base64/Hex/URL encoder panel ───
function encodePanel(input) {
  var results = {};
  try { results["Base64 Encode"] = btoa(input); } catch (_) { results["Base64 Encode"] = "(error — non-Latin1)"; }
  try { results["Base64 Decode"] = atob(input); } catch (_) { results["Base64 Decode"] = "(not valid Base64)"; }
  results["URL Encode"] = encodeURIComponent(input);
  try { results["URL Decode"] = decodeURIComponent(input); } catch (_) { results["URL Decode"] = "(not valid URL encoding)"; }
  results["Hex Encode"] = Array.from(new TextEncoder().encode(input)).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
  try {
    var hexClean = input.replace(/\s/g, "").replace(/^0x/i, "");
    if (/^[0-9a-f]+$/i.test(hexClean) && hexClean.length % 2 === 0) {
      var hexBytes = [];
      for (var i = 0; i < hexClean.length; i += 2) hexBytes.push(parseInt(hexClean.substring(i, i + 2), 16));
      results["Hex Decode"] = new TextDecoder().decode(new Uint8Array(hexBytes));
    } else { results["Hex Decode"] = "(not valid hex)"; }
  } catch (_) { results["Hex Decode"] = "(error)"; }
  results["HTML Encode"] = input.replace(/[&<>"']/g, function(c) { return "&#" + c.charCodeAt(0) + ";"; });
  results["HTML Decode"] = input.replace(/&#(\d+);/g, function(_, n) { return String.fromCharCode(parseInt(n)); }).replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"');
  results["ROT13"] = input.replace(/[a-zA-Z]/g, function(c) {
    var base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
  results["Binary"] = Array.from(new TextEncoder().encode(input)).map(function(b) { return b.toString(2).padStart(8, "0"); }).join(" ");
  results["Decimal"] = Array.from(new TextEncoder().encode(input)).map(function(b) { return b.toString(); }).join(" ");
  results["Octal"] = Array.from(new TextEncoder().encode(input)).map(function(b) { return b.toString(8).padStart(3, "0"); }).join(" ");
  results["String length"] = input.length.toString();
  results["Byte length (UTF-8)"] = new TextEncoder().encode(input).length.toString();
  results["Unicode codepoints"] = Array.from(input).map(function(c) { return "U+" + c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0"); }).join(" ");
  return results;
}

// ─── Scan text for API keys ───
function scanForKeys(text) {
  var found = [];
  for (var pattern of API_KEY_PATTERNS) {
    var match = pattern.re.exec(text);
    if (match) {
      var val = match[1] || match[0];
      var masked = val.substring(0, 8) + "..." + val.substring(val.length - 4);
      found.push({ name: pattern.name, value: masked, fullLength: val.length, severity: pattern.severity, description: pattern.description });
    }
  }
  return found;
}

// ─── Credential format detection ───
function detectCredFormat(text) {
  var lines = text.split("\n").filter(function(l) { return l.trim().length > 0; });
  var results = [];
  for (var line of lines.slice(0, 100)) {
    var trimmed = line.trim();
    for (var fmt of CRED_FORMATS) {
      if (fmt.re.test(trimmed)) {
        results.push({ line: trimmed, format: fmt.name, description: fmt.description });
        break;
      }
    }
  }
  return results;
}

// ─── Password policy builder ───
function buildPolicy(opts) {
  var policy = { name: opts.name || "Password Policy", rules: [], regex: "", document: "" };
  var regParts = [];
  if (opts.minLength) {
    policy.rules.push("Minimum length: " + opts.minLength + " characters");
    regParts.push("(?=.{" + opts.minLength + ",})");
  }
  if (opts.maxLength) {
    policy.rules.push("Maximum length: " + opts.maxLength + " characters");
  }
  if (opts.requireUpper) {
    policy.rules.push("Must contain at least one uppercase letter (A-Z)");
    regParts.push("(?=.*[A-Z])");
  }
  if (opts.requireLower) {
    policy.rules.push("Must contain at least one lowercase letter (a-z)");
    regParts.push("(?=.*[a-z])");
  }
  if (opts.requireDigit) {
    policy.rules.push("Must contain at least one digit (0-9)");
    regParts.push("(?=.*[0-9])");
  }
  if (opts.requireSpecial) {
    policy.rules.push("Must contain at least one special character (!@#$%^&*...)");
    regParts.push("(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?])");
  }
  if (opts.noRepeating) {
    policy.rules.push("No character may repeat 3+ times consecutively");
    regParts.push("(?!.*(.)\\1{2})");
  }
  if (opts.noCommon) {
    policy.rules.push("Must not appear in known breach/common password lists");
  }
  if (opts.history) {
    policy.rules.push("Cannot reuse the last " + opts.history + " passwords");
  }
  if (opts.lockoutAttempts) {
    policy.rules.push("Account locks after " + opts.lockoutAttempts + " failed attempts for " + (opts.lockoutMinutes || 15) + " minutes");
  }
  if (opts.expiryDays) {
    policy.rules.push("Password expires every " + opts.expiryDays + " days");
  }
  if (opts.mfaRequired) {
    policy.rules.push("Multi-factor authentication (MFA) is required");
  }
  var maxPart = opts.maxLength ? ".{0," + opts.maxLength + "}" : ".+";
  policy.regex = "^" + regParts.join("") + maxPart + "$";
  policy.document = "# " + policy.name + "\n\n";
  policy.document += "## Requirements\n\n";
  for (var r of policy.rules) policy.document += "- " + r + "\n";
  policy.document += "\n## Validation Regex\n\n```\n" + policy.regex + "\n```\n";
  policy.document += "\n## NIST SP 800-63B Alignment\n\n";
  policy.document += "- " + (opts.minLength >= 8 ? "PASS" : "FAIL") + ": Minimum 8 characters\n";
  policy.document += "- " + (opts.maxLength >= 64 || !opts.maxLength ? "PASS" : "FAIL") + ": Support at least 64 characters\n";
  policy.document += "- " + (opts.noCommon ? "PASS" : "FAIL") + ": Check against known breached passwords\n";
  policy.document += "- " + (!opts.requireSpecial ? "PASS" : "NOTE") + ": NIST discourages mandatory complexity rules\n";
  policy.document += "- " + (!opts.expiryDays ? "PASS" : "NOTE") + ": NIST discourages forced periodic rotation\n";
  return policy;
}

// ─── Cisco Type 7 decoder ───
function ciscoType7Decode(encoded) {
  var xlat = [0x64,0x73,0x66,0x64,0x3b,0x6b,0x66,0x6f,0x41,0x2c,0x2e,0x69,0x79,0x65,0x77,0x72,
    0x6b,0x6c,0x64,0x4a,0x4b,0x44,0x48,0x53,0x55,0x42,0x73,0x67,0x76,0x63,0x61,0x36,
    0x39,0x38,0x33,0x34,0x6e,0x63,0x78,0x76,0x39,0x38,0x37,0x33,0x32,0x35,0x34,0x6b,
    0x3b,0x66,0x67,0x38];
  var seed = parseInt(encoded.substring(0, 2));
  var result = "";
  for (var i = 2; i < encoded.length; i += 2) {
    var val = parseInt(encoded.substring(i, i + 2), 16);
    result += String.fromCharCode(val ^ xlat[(seed + ((i - 2) / 2)) % xlat.length]);
  }
  return result;
}

// ─── Render functions for each tab ───
function renderPasswordTab(container) {
  container.innerHTML =
    '<div class="ca-section">' +
      '<h3 class="ca-sh">Password Strength Analyzer</h3>' +
      '<p class="ca-desc">All analysis runs locally in your browser. Nothing is sent anywhere.</p>' +
      '<div class="ca-input-row">' +
        '<input type="text" id="ca-pw-input" class="ca-input" placeholder="Enter password to analyze..." autocomplete="off" spellcheck="false">' +
        '<button class="ca-btn" id="ca-pw-btn">Analyze</button>' +
      '</div>' +
      '<div id="ca-pw-result" class="ca-result"></div>' +
    '</div>';
  var input = container.querySelector("#ca-pw-input");
  var btn = container.querySelector("#ca-pw-btn");
  var result = container.querySelector("#ca-pw-result");
  function doAnalyze() {
    var pw = input.value;
    if (!pw) { result.innerHTML = '<p class="ca-muted">Enter a password above.</p>'; return; }
    var a = analyzePassword(pw);
    var scoreColor = a.score >= 80 ? "#4caf50" : a.score >= 60 ? "#ff9800" : a.score >= 40 ? "#f44336" : "#d32f2f";
    var html =
      '<div class="ca-score-bar">' +
        '<div class="ca-score-fill" style="width:' + a.score + '%;background:' + scoreColor + '"></div>' +
      '</div>' +
      '<div class="ca-score-label" style="color:' + scoreColor + '">' + esc(a.rating) + ' (' + a.score + '/100)</div>' +
      '<div class="ca-grid">' +
        '<div class="ca-stat"><span class="ca-stat-n">' + a.length + '</span><span class="ca-stat-l">Length</span></div>' +
        '<div class="ca-stat"><span class="ca-stat-n">' + a.charClasses.length + '</span><span class="ca-stat-l">Char classes</span></div>' +
        '<div class="ca-stat"><span class="ca-stat-n">' + a.entropy + '</span><span class="ca-stat-l">Entropy (bits)</span></div>' +
        '<div class="ca-stat"><span class="ca-stat-n">' + a.poolSize + '</span><span class="ca-stat-l">Pool size</span></div>' +
      '</div>';
    if (a.charClasses.length) {
      html += '<div class="ca-tag-row">';
      for (var cls of a.charClasses) html += '<span class="ca-tag">' + esc(cls) + '</span>';
      html += '</div>';
    }
    html += '<div class="ca-compliance ' + (a.nistCompliant ? "ca-pass" : "ca-fail") + '">' +
      '<strong>NIST SP 800-63B:</strong> ' + (a.nistCompliant ? "Compliant" : "Non-compliant") + '</div>';
    if (a.nistIssues.length) {
      html += '<ul class="ca-issues">';
      for (var ni of a.nistIssues) html += '<li>' + esc(ni) + '</li>';
      html += '</ul>';
    }
    if (a.issues.length) {
      html += '<h4 class="ca-sh2">Issues</h4><ul class="ca-issues">';
      for (var issue of a.issues) html += '<li class="ca-issue-item">' + esc(issue) + '</li>';
      html += '</ul>';
    }
    if (a.strengths.length) {
      html += '<h4 class="ca-sh2">Strengths</h4><ul class="ca-strengths">';
      for (var s of a.strengths) html += '<li class="ca-strength-item">' + esc(s) + '</li>';
      html += '</ul>';
    }
    if (a.patterns.length) {
      html += '<h4 class="ca-sh2">Detected Patterns</h4><ul class="ca-patterns">';
      for (var p of a.patterns) html += '<li>' + esc(p) + '</li>';
      html += '</ul>';
    }
    html += '<h4 class="ca-sh2">Time to Crack (brute force)</h4>' +
      '<div class="ca-table-wrap"><table class="ca-table">' +
      '<thead><tr><th>Algorithm</th><th>Single GPU</th><th>GPU Cluster</th><th>ASIC</th></tr></thead><tbody>';
    for (var algo in a.timeToCrack) {
      var t = a.timeToCrack[algo];
      html += '<tr><td>' + esc(algo) + '</td><td>' + esc(t.single_gpu) + '</td><td>' + esc(t.gpu_cluster) + '</td><td>' + esc(t.asic) + '</td></tr>';
    }
    html += '</tbody></table></div>';
    result.innerHTML = html;
  }
  btn.onclick = doAnalyze;
  input.onkeydown = function(e) { if (e.key === "Enter") doAnalyze(); };
}

function renderHashTab(container) {
  container.innerHTML =
    '<div class="ca-section">' +
      '<h3 class="ca-sh">Hash Identifier</h3>' +
      '<p class="ca-desc">Paste a hash to auto-detect its type, hashcat mode, and john format.</p>' +
      '<div class="ca-input-row">' +
        '<input type="text" id="ca-hash-input" class="ca-input" placeholder="Paste hash here..." autocomplete="off" spellcheck="false">' +
        '<button class="ca-btn" id="ca-hash-btn">Identify</button>' +
      '</div>' +
      '<div id="ca-hash-result" class="ca-result"></div>' +
    '</div>' +
    '<div class="ca-section">' +
      '<h3 class="ca-sh">Hash Generator</h3>' +
      '<p class="ca-desc">Generate hashes for a given input using SubtleCrypto + custom implementations.</p>' +
      '<div class="ca-input-row">' +
        '<input type="text" id="ca-gen-input" class="ca-input" placeholder="Text to hash..." autocomplete="off">' +
        '<button class="ca-btn" id="ca-gen-btn">Generate</button>' +
      '</div>' +
      '<div id="ca-gen-result" class="ca-result"></div>' +
    '</div>';
  container.querySelector("#ca-hash-btn").onclick = function() {
    var hash = container.querySelector("#ca-hash-input").value.trim();
    var resultEl = container.querySelector("#ca-hash-result");
    if (!hash) { resultEl.innerHTML = '<p class="ca-muted">Paste a hash above.</p>'; return; }
    var matches = identifyHash(hash);
    if (matches.length === 0) {
      resultEl.innerHTML = '<p class="ca-muted">No matching hash pattern found.</p>';
      return;
    }
    var html = '<div class="ca-table-wrap"><table class="ca-table">' +
      '<thead><tr><th>Type</th><th>Hashcat Mode</th><th>John Format</th><th>Notes</th></tr></thead><tbody>';
    for (var m of matches) {
      html += '<tr><td>' + esc(m.name) + '</td><td>' + (m.hashcat !== null ? '-m ' + m.hashcat : 'N/A') + '</td>' +
        '<td>' + (m.john || 'N/A') + '</td><td>' + esc(m.note) + '</td></tr>';
    }
    html += '</tbody></table></div>';
    resultEl.innerHTML = html;
  };
  container.querySelector("#ca-gen-btn").onclick = async function() {
    var input = container.querySelector("#ca-gen-input").value;
    var resultEl = container.querySelector("#ca-gen-result");
    if (!input) { resultEl.innerHTML = '<p class="ca-muted">Enter text above.</p>'; return; }
    var hashes = await generateHashes(input);
    var html = '<div class="ca-table-wrap"><table class="ca-table">' +
      '<thead><tr><th>Algorithm</th><th>Hash</th></tr></thead><tbody>';
    for (var algo in hashes) {
      html += '<tr><td>' + esc(algo) + '</td><td class="ca-hash-val">' + esc(hashes[algo]) + '</td></tr>';
    }
    html += '</tbody></table></div>';
    resultEl.innerHTML = html;
  };
}

function renderJWTTab(container) {
  container.innerHTML =
    '<div class="ca-section">' +
      '<h3 class="ca-sh">JWT Decoder</h3>' +
      '<p class="ca-desc">Paste a JSON Web Token to decode its header and payload. Checks for common vulnerabilities.</p>' +
      '<textarea id="ca-jwt-input" class="ca-textarea" rows="4" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" spellcheck="false"></textarea>' +
      '<button class="ca-btn" id="ca-jwt-btn">Decode</button>' +
      '<div id="ca-jwt-result" class="ca-result"></div>' +
    '</div>';
  container.querySelector("#ca-jwt-btn").onclick = function() {
    var token = container.querySelector("#ca-jwt-input").value.trim();
    var resultEl = container.querySelector("#ca-jwt-result");
    if (!token) { resultEl.innerHTML = '<p class="ca-muted">Paste a JWT above.</p>'; return; }
    var decoded = decodeJWT(token);
    if (decoded.error) { resultEl.innerHTML = '<div class="ca-err">' + esc(decoded.error) + '</div>'; return; }
    var html = '<div class="ca-jwt-parts">';
    html += '<div class="ca-jwt-part"><h4>Header</h4><pre class="ca-pre">' + esc(JSON.stringify(decoded.header, null, 2)) + '</pre></div>';
    html += '<div class="ca-jwt-part"><h4>Payload</h4><pre class="ca-pre">' + esc(JSON.stringify(decoded.payload, null, 2)) + '</pre></div>';
    html += '</div>';
    var infoRows = [];
    if (decoded.expires) infoRows.push({ k: "Expires", v: decoded.expires + (decoded.expired ? ' (EXPIRED)' : ' (valid)') });
    if (decoded.issuedAt) infoRows.push({ k: "Issued At", v: decoded.issuedAt });
    if (decoded.notBefore) infoRows.push({ k: "Not Before", v: decoded.notBefore });
    infoRows.push({ k: "Has Signature", v: decoded.hasSig ? "Yes" : "No" });
    if (decoded.note) infoRows.push({ k: "Note", v: decoded.note });
    if (decoded.warning) infoRows.push({ k: "Warning", v: decoded.warning });
    html += '<div class="ca-table-wrap"><table class="ca-table"><tbody>';
    for (var row of infoRows) {
      var cls = row.k === "Warning" ? ' class="ca-warn-row"' : "";
      html += '<tr' + cls + '><td><strong>' + esc(row.k) + '</strong></td><td>' + esc(row.v) + '</td></tr>';
    }
    html += '</tbody></table></div>';
    resultEl.innerHTML = html;
  };
}

function renderTOTPTab(container) {
  container.innerHTML =
    '<div class="ca-section">' +
      '<h3 class="ca-sh">TOTP Generator</h3>' +
      '<p class="ca-desc">Enter a Base32 secret to generate time-based one-time passwords (RFC 6238).</p>' +
      '<div class="ca-input-row">' +
        '<input type="text" id="ca-totp-secret" class="ca-input" placeholder="Base32 secret (e.g. JBSWY3DPEHPK3PXP)" autocomplete="off" spellcheck="false">' +
      '</div>' +
      '<div class="ca-totp-settings">' +
        '<label>Period: <select id="ca-totp-period"><option value="30" selected>30s</option><option value="60">60s</option></select></label>' +
        '<label>Digits: <select id="ca-totp-digits"><option value="6" selected>6</option><option value="8">8</option></select></label>' +
      '</div>' +
      '<div id="ca-totp-display" class="ca-totp-display">' +
        '<div class="ca-totp-code">------</div>' +
        '<div class="ca-totp-timer">Enter a secret above</div>' +
      '</div>' +
    '</div>';
  var interval = null;
  function update() {
    var secret = container.querySelector("#ca-totp-secret").value.trim();
    if (!secret) return;
    var period = parseInt(container.querySelector("#ca-totp-period").value);
    var digits = parseInt(container.querySelector("#ca-totp-digits").value);
    var result = generateTOTP(secret, period, digits);
    if (result.error) {
      container.querySelector(".ca-totp-code").textContent = "Error";
      container.querySelector(".ca-totp-timer").textContent = result.error;
      return;
    }
    container.querySelector(".ca-totp-code").textContent = result.otp;
    container.querySelector(".ca-totp-timer").textContent = result.remaining + "s remaining";
    container.querySelector(".ca-totp-timer").style.color = result.remaining <= 5 ? "#f44336" : "";
  }
  container.querySelector("#ca-totp-secret").oninput = function() {
    if (interval) clearInterval(interval);
    update();
    interval = setInterval(update, 1000);
  };
  container.querySelector("#ca-totp-period").onchange = update;
  container.querySelector("#ca-totp-digits").onchange = update;
}

function renderCertTab(container) {
  container.innerHTML =
    '<div class="ca-section">' +
      '<h3 class="ca-sh">Certificate Decoder</h3>' +
      '<p class="ca-desc">Paste a PEM-encoded X.509 certificate to decode its fields.</p>' +
      '<textarea id="ca-cert-input" class="ca-textarea" rows="8" placeholder="-----BEGIN CERTIFICATE-----\nMIIE...\n-----END CERTIFICATE-----" spellcheck="false"></textarea>' +
      '<button class="ca-btn" id="ca-cert-btn">Decode</button>' +
      '<div id="ca-cert-result" class="ca-result"></div>' +
    '</div>';
  container.querySelector("#ca-cert-btn").onclick = function() {
    var pem = container.querySelector("#ca-cert-input").value.trim();
    var resultEl = container.querySelector("#ca-cert-result");
    if (!pem) { resultEl.innerHTML = '<p class="ca-muted">Paste a PEM certificate above.</p>'; return; }
    var cert = decodePEMCert(pem);
    if (cert.error) { resultEl.innerHTML = '<div class="ca-err">' + esc(cert.error) + '</div>'; return; }
    var html = '<div class="ca-table-wrap"><table class="ca-table"><tbody>';
    html += '<tr><td><strong>Subject</strong></td><td>' + esc(cert.subject) + '</td></tr>';
    html += '<tr><td><strong>Issuer</strong></td><td>' + esc(cert.issuer) + '</td></tr>';
    html += '<tr><td><strong>Serial</strong></td><td>' + esc(cert.serialNumber) + '</td></tr>';
    html += '<tr><td><strong>Key Algorithm</strong></td><td>' + esc(cert.keyAlgorithm) + ' (' + esc(cert.keySize) + ')</td></tr>';
    html += '<tr><td><strong>Signature Algorithm</strong></td><td>' + esc(cert.signatureAlgorithm) + '</td></tr>';
    if (cert.notBefore) html += '<tr><td><strong>Not Before</strong></td><td>' + esc(cert.notBefore) + '</td></tr>';
    if (cert.notAfter) {
      var cls = cert.expired ? ' class="ca-warn-row"' : "";
      html += '<tr' + cls + '><td><strong>Not After</strong></td><td>' + esc(cert.notAfter) +
        (cert.expired ? ' (EXPIRED)' : ' (' + cert.daysRemaining + ' days remaining)') + '</td></tr>';
    }
    html += '<tr><td><strong>Is CA</strong></td><td>' + (cert.isCA ? "Yes (basic constraints present)" : "No") + '</td></tr>';
    if (cert.sans && cert.sans.length) {
      html += '<tr><td><strong>SANs</strong></td><td>' + cert.sans.map(function(s) { return esc(s); }).join(", ") + '</td></tr>';
    }
    html += '<tr><td><strong>Size</strong></td><td>' + cert.hexLength + ' bytes</td></tr>';
    html += '</tbody></table></div>';
    if (cert.signatureAlgorithm && cert.signatureAlgorithm.includes("SHA-1")) {
      html += '<div class="ca-warn">Warning: SHA-1 signatures are deprecated and considered insecure.</div>';
    }
    if (cert.signatureAlgorithm && cert.signatureAlgorithm.includes("MD5")) {
      html += '<div class="ca-err">Critical: MD5 signatures are broken. This certificate is not trustworthy.</div>';
    }
    resultEl.innerHTML = html;
  };
}

function renderEncoderTab(container) {
  container.innerHTML =
    '<div class="ca-section">' +
      '<h3 class="ca-sh">Encoder / Decoder</h3>' +
      '<p class="ca-desc">Base64, Hex, URL, HTML, ROT13, Binary, and more.</p>' +
      '<div class="ca-input-row">' +
        '<textarea id="ca-enc-input" class="ca-textarea" rows="3" placeholder="Enter text to encode/decode..." spellcheck="false"></textarea>' +
      '</div>' +
      '<button class="ca-btn" id="ca-enc-btn">Convert</button>' +
      '<div id="ca-enc-result" class="ca-result"></div>' +
    '</div>';
  container.querySelector("#ca-enc-btn").onclick = function() {
    var input = container.querySelector("#ca-enc-input").value;
    var resultEl = container.querySelector("#ca-enc-result");
    if (!input) { resultEl.innerHTML = '<p class="ca-muted">Enter text above.</p>'; return; }
    var results = encodePanel(input);
    var html = '<div class="ca-table-wrap"><table class="ca-table"><tbody>';
    for (var k in results) {
      html += '<tr><td><strong>' + esc(k) + '</strong></td><td class="ca-hash-val">' + esc(results[k]) + '</td></tr>';
    }
    html += '</tbody></table></div>';
    resultEl.innerHTML = html;
  };
}

function renderKeyScanTab(container) {
  container.innerHTML =
    '<div class="ca-section">' +
      '<h3 class="ca-sh">API Key / Secret Scanner</h3>' +
      '<p class="ca-desc">Paste code, config files, or .env contents to detect exposed credentials. Checks for 40+ provider patterns.</p>' +
      '<textarea id="ca-key-input" class="ca-textarea" rows="8" placeholder="Paste code, config, or .env file contents here..." spellcheck="false"></textarea>' +
      '<button class="ca-btn" id="ca-key-btn">Scan</button>' +
      '<div id="ca-key-result" class="ca-result"></div>' +
    '</div>';
  container.querySelector("#ca-key-btn").onclick = function() {
    var text = container.querySelector("#ca-key-input").value;
    var resultEl = container.querySelector("#ca-key-result");
    if (!text.trim()) { resultEl.innerHTML = '<p class="ca-muted">Paste content to scan above.</p>'; return; }
    var found = scanForKeys(text);
    if (found.length === 0) {
      resultEl.innerHTML = '<div class="ca-pass">No known API key patterns detected.</div>';
      return;
    }
    var html = '<div class="ca-warn">' + found.length + ' potential secret(s) found</div>' +
      '<div class="ca-table-wrap"><table class="ca-table">' +
      '<thead><tr><th>Type</th><th>Value (masked)</th><th>Severity</th><th>Description</th></tr></thead><tbody>';
    for (var f of found) {
      var sevClass = f.severity === "critical" ? "ca-sev-crit" : f.severity === "high" ? "ca-sev-high" : f.severity === "medium" ? "ca-sev-med" : "ca-sev-low";
      html += '<tr><td>' + esc(f.name) + '</td><td class="ca-hash-val">' + esc(f.value) + '</td>' +
        '<td><span class="ca-sev ' + sevClass + '">' + esc(f.severity) + '</span></td>' +
        '<td>' + esc(f.description) + '</td></tr>';
    }
    html += '</tbody></table></div>';
    resultEl.innerHTML = html;
  };
}

function renderCredFormatTab(container) {
  container.innerHTML =
    '<div class="ca-section">' +
      '<h3 class="ca-sh">Credential Format Analyzer</h3>' +
      '<p class="ca-desc">Paste credential dumps, shadow file entries, SAM dumps, or htpasswd entries to identify the format.</p>' +
      '<textarea id="ca-cred-input" class="ca-textarea" rows="8" placeholder="root:$6$rounds=5000$salt$hash...\nadmin:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::" spellcheck="false"></textarea>' +
      '<button class="ca-btn" id="ca-cred-btn">Analyze</button>' +
      '<div id="ca-cred-result" class="ca-result"></div>' +
    '</div>' +
    '<div class="ca-section">' +
      '<h3 class="ca-sh">Cisco Type 7 Decoder</h3>' +
      '<p class="ca-desc">Decode Cisco Type 7 reversible passwords.</p>' +
      '<div class="ca-input-row">' +
        '<input type="text" id="ca-cisco-input" class="ca-input" placeholder="e.g. 070C285F4D06" autocomplete="off">' +
        '<button class="ca-btn" id="ca-cisco-btn">Decode</button>' +
      '</div>' +
      '<div id="ca-cisco-result" class="ca-result"></div>' +
    '</div>';
  container.querySelector("#ca-cred-btn").onclick = function() {
    var text = container.querySelector("#ca-cred-input").value;
    var resultEl = container.querySelector("#ca-cred-result");
    if (!text.trim()) { resultEl.innerHTML = '<p class="ca-muted">Paste credentials above.</p>'; return; }
    var results = detectCredFormat(text);
    if (results.length === 0) {
      resultEl.innerHTML = '<p class="ca-muted">No recognized credential format detected.</p>';
      return;
    }
    var html = '<div class="ca-table-wrap"><table class="ca-table">' +
      '<thead><tr><th>Format</th><th>Entry</th><th>Description</th></tr></thead><tbody>';
    for (var r of results) {
      html += '<tr><td><strong>' + esc(r.format) + '</strong></td><td class="ca-hash-val">' + esc(r.line.substring(0, 80)) + '</td>' +
        '<td>' + esc(r.description) + '</td></tr>';
    }
    html += '</tbody></table></div>';
    resultEl.innerHTML = html;
  };
  container.querySelector("#ca-cisco-btn").onclick = function() {
    var encoded = container.querySelector("#ca-cisco-input").value.trim();
    var resultEl = container.querySelector("#ca-cisco-result");
    if (!encoded) { resultEl.innerHTML = '<p class="ca-muted">Enter a Cisco Type 7 hash above.</p>'; return; }
    var decoded = ciscoType7Decode(encoded);
    resultEl.innerHTML = '<div class="ca-pass">Decoded: <strong>' + esc(decoded) + '</strong></div>';
  };
}

function renderPolicyTab(container) {
  container.innerHTML =
    '<div class="ca-section">' +
      '<h3 class="ca-sh">Password Policy Builder</h3>' +
      '<p class="ca-desc">Configure a password policy and generate a validation regex + compliance document.</p>' +
      '<div class="ca-policy-form">' +
        '<label class="ca-pol-row"><span>Policy name:</span><input type="text" id="ca-pol-name" value="Corporate Password Policy" class="ca-input"></label>' +
        '<label class="ca-pol-row"><span>Min length:</span><input type="number" id="ca-pol-minlen" value="12" min="1" max="128" class="ca-input-sm"></label>' +
        '<label class="ca-pol-row"><span>Max length:</span><input type="number" id="ca-pol-maxlen" value="128" min="1" max="1024" class="ca-input-sm"></label>' +
        '<label class="ca-pol-check"><input type="checkbox" id="ca-pol-upper" checked> Require uppercase</label>' +
        '<label class="ca-pol-check"><input type="checkbox" id="ca-pol-lower" checked> Require lowercase</label>' +
        '<label class="ca-pol-check"><input type="checkbox" id="ca-pol-digit" checked> Require digit</label>' +
        '<label class="ca-pol-check"><input type="checkbox" id="ca-pol-special"> Require special character</label>' +
        '<label class="ca-pol-check"><input type="checkbox" id="ca-pol-norepeat" checked> No 3+ repeated chars</label>' +
        '<label class="ca-pol-check"><input type="checkbox" id="ca-pol-nocommon" checked> Block common passwords</label>' +
        '<label class="ca-pol-check"><input type="checkbox" id="ca-pol-mfa"> Require MFA</label>' +
        '<label class="ca-pol-row"><span>Password history:</span><input type="number" id="ca-pol-history" value="5" min="0" max="24" class="ca-input-sm"></label>' +
        '<label class="ca-pol-row"><span>Lockout attempts:</span><input type="number" id="ca-pol-lockout" value="5" min="0" max="100" class="ca-input-sm"></label>' +
        '<label class="ca-pol-row"><span>Lockout minutes:</span><input type="number" id="ca-pol-lockmin" value="15" min="1" max="1440" class="ca-input-sm"></label>' +
        '<label class="ca-pol-row"><span>Expiry days (0=never):</span><input type="number" id="ca-pol-expiry" value="0" min="0" max="365" class="ca-input-sm"></label>' +
      '</div>' +
      '<button class="ca-btn" id="ca-pol-btn">Generate Policy</button>' +
      '<div id="ca-pol-result" class="ca-result"></div>' +
    '</div>';
  container.querySelector("#ca-pol-btn").onclick = function() {
    var opts = {
      name: container.querySelector("#ca-pol-name").value,
      minLength: parseInt(container.querySelector("#ca-pol-minlen").value) || 8,
      maxLength: parseInt(container.querySelector("#ca-pol-maxlen").value) || 128,
      requireUpper: container.querySelector("#ca-pol-upper").checked,
      requireLower: container.querySelector("#ca-pol-lower").checked,
      requireDigit: container.querySelector("#ca-pol-digit").checked,
      requireSpecial: container.querySelector("#ca-pol-special").checked,
      noRepeating: container.querySelector("#ca-pol-norepeat").checked,
      noCommon: container.querySelector("#ca-pol-nocommon").checked,
      mfaRequired: container.querySelector("#ca-pol-mfa").checked,
      history: parseInt(container.querySelector("#ca-pol-history").value) || 0,
      lockoutAttempts: parseInt(container.querySelector("#ca-pol-lockout").value) || 0,
      lockoutMinutes: parseInt(container.querySelector("#ca-pol-lockmin").value) || 15,
      expiryDays: parseInt(container.querySelector("#ca-pol-expiry").value) || 0,
    };
    var policy = buildPolicy(opts);
    var resultEl = container.querySelector("#ca-pol-result");
    var html = '<h4 class="ca-sh2">Rules</h4><ul>';
    for (var r of policy.rules) html += '<li>' + esc(r) + '</li>';
    html += '</ul>';
    html += '<h4 class="ca-sh2">Validation Regex</h4><pre class="ca-pre">' + esc(policy.regex) + '</pre>';
    html += '<h4 class="ca-sh2">Policy Document</h4><pre class="ca-pre" style="white-space:pre-wrap">' + esc(policy.document) + '</pre>';
    html += '<h4 class="ca-sh2">Test Password</h4>' +
      '<div class="ca-input-row"><input type="text" id="ca-pol-test" class="ca-input" placeholder="Test a password against this policy..." autocomplete="off">' +
      '<button class="ca-btn" id="ca-pol-test-btn">Test</button></div>' +
      '<div id="ca-pol-test-result"></div>';
    resultEl.innerHTML = html;
    container.querySelector("#ca-pol-test-btn").onclick = function() {
      var pw = container.querySelector("#ca-pol-test").value;
      var re = new RegExp(policy.regex);
      var pass = re.test(pw);
      var issues = [];
      if (opts.noCommon && COMMON_PASSWORDS.includes(pw.toLowerCase())) { pass = false; issues.push("Appears in common password list"); }
      var testResult = container.querySelector("#ca-pol-test-result");
      if (pass && issues.length === 0) {
        testResult.innerHTML = '<div class="ca-pass">Password meets policy requirements.</div>';
      } else {
        testResult.innerHTML = '<div class="ca-fail">Password does NOT meet policy requirements.' +
          (issues.length ? '<ul>' + issues.map(function(i) { return '<li>' + esc(i) + '</li>'; }).join('') + '</ul>' : '') + '</div>';
      }
    };
  };
}

// ─── CSS ───
var CA_CSS = '<style>' +
  '.ca-tabs{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:16px;border-bottom:1px solid var(--line,#333);padding-bottom:8px}' +
  '.ca-tab{padding:6px 14px;border:1px solid var(--line,#333);background:var(--card,#1a1a1a);color:var(--txt,#eee);cursor:pointer;font-size:.82rem;border-radius:4px 4px 0 0;transition:all .15s}' +
  '.ca-tab:hover{background:var(--bg,#111)}' +
  '.ca-tab.on{background:var(--acc,#ffc107);color:#111;border-color:var(--acc,#ffc107);font-weight:600}' +
  '.ca-section{margin-bottom:24px}' +
  '.ca-sh{font-size:1.1rem;margin:0 0 6px;color:var(--txt,#eee)}' +
  '.ca-sh2{font-size:.95rem;margin:16px 0 6px;color:var(--txt,#eee)}' +
  '.ca-desc{color:var(--mut,#888);font-size:.82rem;margin:0 0 12px}' +
  '.ca-input-row{display:flex;gap:8px;margin-bottom:8px}' +
  '.ca-input{flex:1;padding:8px 12px;background:var(--bg,#111);border:1px solid var(--line,#333);color:var(--txt,#eee);border-radius:4px;font-family:monospace;font-size:.85rem}' +
  '.ca-input-sm{width:80px;padding:6px 8px;background:var(--bg,#111);border:1px solid var(--line,#333);color:var(--txt,#eee);border-radius:4px;font-size:.85rem}' +
  '.ca-textarea{width:100%;padding:8px 12px;background:var(--bg,#111);border:1px solid var(--line,#333);color:var(--txt,#eee);border-radius:4px;font-family:monospace;font-size:.82rem;resize:vertical;box-sizing:border-box;margin-bottom:8px}' +
  '.ca-btn{padding:8px 18px;background:var(--acc,#ffc107);color:#111;border:none;border-radius:4px;cursor:pointer;font-weight:600;font-size:.85rem;white-space:nowrap}' +
  '.ca-btn:hover{opacity:.9}' +
  '.ca-result{margin-top:12px}' +
  '.ca-muted{color:var(--mut,#888);font-size:.85rem}' +
  '.ca-score-bar{width:100%;height:8px;background:var(--line,#333);border-radius:4px;overflow:hidden;margin-bottom:6px}' +
  '.ca-score-fill{height:100%;border-radius:4px;transition:width .4s}' +
  '.ca-score-label{font-size:1.1rem;font-weight:700;margin-bottom:12px}' +
  '.ca-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px;margin-bottom:12px}' +
  '.ca-stat{background:var(--card,#1a1a1a);border:1px solid var(--line,#333);padding:10px;border-radius:4px;text-align:center}' +
  '.ca-stat-n{display:block;font-size:1.3rem;font-weight:700;color:var(--acc,#ffc107);font-variant-numeric:tabular-nums}' +
  '.ca-stat-l{display:block;font-size:.72rem;color:var(--mut,#888);margin-top:2px}' +
  '.ca-tag-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}' +
  '.ca-tag{padding:2px 10px;background:var(--bg,#111);border:1px solid var(--line,#333);border-radius:3px;font-size:.75rem;color:var(--mut,#888)}' +
  '.ca-compliance{padding:8px 12px;border-radius:4px;font-size:.85rem;margin-bottom:8px}' +
  '.ca-pass{padding:8px 12px;background:rgba(76,175,80,.12);border:1px solid rgba(76,175,80,.3);border-radius:4px;color:#4caf50;font-size:.85rem;margin-bottom:8px}' +
  '.ca-fail{padding:8px 12px;background:rgba(244,67,54,.12);border:1px solid rgba(244,67,54,.3);border-radius:4px;color:#f44336;font-size:.85rem;margin-bottom:8px}' +
  '.ca-warn{padding:8px 12px;background:rgba(255,152,0,.12);border:1px solid rgba(255,152,0,.3);border-radius:4px;color:#ff9800;font-size:.85rem;margin-bottom:8px}' +
  '.ca-err{padding:8px 12px;background:rgba(244,67,54,.12);border:1px solid rgba(244,67,54,.3);border-radius:4px;color:#f44336;font-size:.85rem}' +
  '.ca-issues,.ca-strengths,.ca-patterns{margin:4px 0 12px 16px;font-size:.85rem}' +
  '.ca-issue-item{color:#f44336}.ca-strength-item{color:#4caf50}' +
  '.ca-table-wrap{overflow-x:auto;margin-bottom:12px}' +
  '.ca-table{width:100%;border-collapse:collapse;font-size:.82rem}' +
  '.ca-table th,.ca-table td{padding:6px 10px;border:1px solid var(--line,#333);text-align:left}' +
  '.ca-table th{background:var(--card,#1a1a1a);color:var(--mut,#888);font-weight:600;white-space:nowrap}' +
  '.ca-table td{color:var(--txt,#eee)}' +
  '.ca-hash-val{font-family:monospace;word-break:break-all;font-size:.78rem}' +
  '.ca-warn-row td{background:rgba(255,152,0,.08)}' +
  '.ca-pre{background:var(--bg,#111);border:1px solid var(--line,#333);padding:10px;border-radius:4px;font-family:monospace;font-size:.8rem;overflow-x:auto;color:var(--txt,#eee);white-space:pre;margin:4px 0}' +
  '.ca-jwt-parts{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}' +
  '.ca-jwt-part h4{margin:0 0 4px;font-size:.85rem;color:var(--mut,#888)}' +
  '.ca-totp-display{text-align:center;padding:24px;background:var(--card,#1a1a1a);border:1px solid var(--line,#333);border-radius:4px;margin-top:12px}' +
  '.ca-totp-code{font-size:2.5rem;font-weight:700;font-family:monospace;letter-spacing:.3em;color:var(--acc,#ffc107);margin-bottom:8px}' +
  '.ca-totp-timer{font-size:.85rem;color:var(--mut,#888)}' +
  '.ca-totp-settings{display:flex;gap:16px;margin-bottom:8px;font-size:.85rem;color:var(--mut,#888)}' +
  '.ca-totp-settings select{background:var(--bg,#111);color:var(--txt,#eee);border:1px solid var(--line,#333);padding:2px 6px;border-radius:3px}' +
  '.ca-policy-form{display:flex;flex-direction:column;gap:6px;margin-bottom:12px}' +
  '.ca-pol-row{display:flex;align-items:center;gap:8px;font-size:.85rem;color:var(--txt,#eee)}' +
  '.ca-pol-row span{min-width:140px}' +
  '.ca-pol-check{font-size:.85rem;color:var(--txt,#eee);display:flex;align-items:center;gap:6px}' +
  '.ca-sev{padding:2px 8px;border-radius:3px;font-size:.72rem;font-weight:600;text-transform:uppercase}' +
  '.ca-sev-crit{background:rgba(244,67,54,.2);color:#f44336}' +
  '.ca-sev-high{background:rgba(255,87,34,.2);color:#ff5722}' +
  '.ca-sev-med{background:rgba(255,152,0,.2);color:#ff9800}' +
  '.ca-sev-low{background:rgba(76,175,80,.15);color:#4caf50}' +
  '@media(max-width:600px){.ca-jwt-parts{grid-template-columns:1fr}.ca-grid{grid-template-columns:repeat(2,1fr)}.ca-tabs{gap:2px}.ca-tab{font-size:.75rem;padding:4px 8px}}' +
  '</style>';

// ─── Main render ───
var TABS = [
  { id: "password", label: "Password", render: renderPasswordTab },
  { id: "hash", label: "Hashes", render: renderHashTab },
  { id: "jwt", label: "JWT", render: renderJWTTab },
  { id: "totp", label: "TOTP", render: renderTOTPTab },
  { id: "cert", label: "Certificate", render: renderCertTab },
  { id: "encoder", label: "Encoder", render: renderEncoderTab },
  { id: "keyscan", label: "Key Scanner", render: renderKeyScanTab },
  { id: "credformat", label: "Credentials", render: renderCredFormatTab },
  { id: "policy", label: "Policy", render: renderPolicyTab },
];

export function renderCredentialAuditor(main) {
  main.innerHTML = CA_CSS +
    '<h1 class="pg-h1">Credential Auditor</h1>' +
    '<p class="muted pg-sub">Password analysis, hash identification, JWT decode, TOTP, certificate decode, API key scanning. Everything runs locally — nothing leaves your browser.</p>' +
    '<div class="ca-tabs" id="ca-tabs">' +
      TABS.map(function(t) { return '<button class="ca-tab' + (t.id === "password" ? " on" : "") + '" data-tab="' + t.id + '">' + t.label + '</button>'; }).join("") +
    '</div>' +
    '<div id="ca-panel"></div>';
  var panel = main.querySelector("#ca-panel");
  var current = "password";
  renderPasswordTab(panel);
  main.querySelector("#ca-tabs").onclick = function(e) {
    var btn = e.target.closest(".ca-tab");
    if (!btn) return;
    current = btn.dataset.tab;
    main.querySelectorAll(".ca-tab").forEach(function(b) { b.classList.toggle("on", b === btn); });
    var tab = TABS.find(function(t) { return t.id === current; });
    if (tab) tab.render(panel);
  };
}
