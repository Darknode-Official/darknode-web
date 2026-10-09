// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// ThreatForest — automated attack trees from source code.
//
// Inspired by the research project of the same name (AWS / Black Hat USA 2026,
// "ThreatForest: Automated Attack Trees from Source Code"), rebuilt from scratch
// to be faster and more capable:
//   - FAST: a deterministic client-side static-analysis engine runs instantly in
//     the browser. Weaknesses carry their own CWE/CAPEC/MITRE ATT&CK/STRIDE labels,
//     so mapping is a lookup, not a slow embedding search (the original's weak spot,
//     ~0.29 mapping quality). No server round-trip is needed to get a full result.
//   - POWERFUL: every finding is cross-walked to CWE + CAPEC + ATT&CK + STRIDE, woven
//     into a goal-oriented attack tree, scored for risk, and can be pushed into the
//     Security Graph or exported. An optional one-pass AI deep-dive (Darknode AI) adds
//     prioritised remediation and extra attack paths on top of the deterministic core.
//
// Analysis is heuristic and advisory: it flags patterns that are commonly dangerous.
// Confidence is shown per finding; treat high-confidence sink+source chains first.

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ---- Attack goals: the top level of every tree -----------------------------
const GOALS = {
  rce:     { name: "Execute attacker-controlled code or commands", short: "Remote code execution" },
  sqli:    { name: "Read or tamper with the database", short: "Database compromise" },
  authz:   { name: "Bypass authentication or escalate privilege", short: "Auth bypass / privesc" },
  ssrf:    { name: "Reach internal systems from the server", short: "SSRF / pivot" },
  secret:  { name: "Harvest hardcoded credentials and keys", short: "Credential theft" },
  crypto:  { name: "Defeat weak or misused cryptography", short: "Crypto failure" },
  xss:     { name: "Run script in a victim's session", short: "Cross-site scripting" },
  deser:   { name: "Gain execution via unsafe deserialization", short: "Insecure deserialization" },
  path:    { name: "Read or write arbitrary files", short: "Path traversal / file abuse" },
  memory:  { name: "Corrupt memory to hijack control flow", short: "Memory safety" },
  dos:     { name: "Exhaust resources / denial of service", short: "Denial of service" },
  data:    { name: "Disclose sensitive data", short: "Information disclosure" },
  config:  { name: "Abuse insecure configuration", short: "Misconfiguration" },
  ssjs:    { name: "Server-side request / template abuse", short: "Injection (template/XXE)" },
};

// ---- Weakness knowledge base ------------------------------------------------
// r: pattern (global+multiline). g: goal key. cwe/capec/att/stride: standard refs.
// sev: 1 low .. 5 critical. kind: sink|source|auth|secret|crypto|config|memory.
// fix: one-line remediation. langs: advisory language tags (display only).
const R = (o) => o;
const RULES = [
  // ---- Command / code injection (sinks) ----
  R({ id: "cmd-exec", t: "Shell command execution", g: "rce", kind: "sink", sev: 5,
    r: /\b(?:os\.system|subprocess\.(?:call|run|Popen|check_output)|exec[lv]?p?|popen|system|shell_exec|passthru|proc_open|child_process\.(?:exec|execSync|spawn)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(/g,
    cwe: "CWE-78", capec: "CAPEC-248", att: ["T1059 Command & Scripting Interpreter"], stride: "E", langs: ["py", "js", "php", "java"],
    fix: "Avoid the shell; pass an argument array to a safe exec API and never interpolate user input into a command string." }),
  R({ id: "code-eval", t: "Dynamic code evaluation (eval)", g: "rce", kind: "sink", sev: 5,
    r: /\b(?:eval|Function\s*\(|setTimeout\s*\(\s*["'`]|setInterval\s*\(\s*["'`]|new\s+Function|assert\s*\(|exec\s*\(|execfile|compile\s*\()\s*/g,
    cwe: "CWE-95", capec: "CAPEC-242", att: ["T1059 Command & Scripting Interpreter"], stride: "E", langs: ["js", "py", "php"],
    fix: "Never eval() dynamic strings. Use a parser, a lookup table, or JSON.parse for data." }),
  R({ id: "tmpl-inject", t: "Possible server-side template injection", g: "ssjs", kind: "sink", sev: 4,
    r: /\b(?:render_template_string|Template\s*\(\s*[^)]*\+|Twig|Jinja2?\s*\(|new\s+Handlebars|\{\{.*\+.*\}\})/g,
    cwe: "CWE-1336", capec: "CAPEC-242", att: ["T1059 Command & Scripting Interpreter"], stride: "E", langs: ["py", "php", "js"],
    fix: "Render fixed templates with escaped variables; never build a template body from user input." }),

  // ---- SQL / NoSQL / LDAP injection ----
  R({ id: "sqli-concat", t: "SQL built by string concatenation", g: "sqli", kind: "sink", sev: 5,
    r: /(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^;"'`]*?(?:["'`]\s*\+|\+\s*["'`]|%s|\$\{|f["'])/gi,
    cwe: "CWE-89", capec: "CAPEC-66", att: ["T1190 Exploit Public-Facing Application"], stride: "T", langs: ["py", "js", "php", "java"],
    fix: "Use parameterised queries / prepared statements; never concatenate input into SQL." }),
  R({ id: "sqli-exec", t: "Raw query executed with interpolated input", g: "sqli", kind: "sink", sev: 5,
    r: /\b(?:execute|query|raw|executeQuery|createStatement|mysqli_query|pg_query)\s*\(\s*[^)]*(?:\+|\$\{|%|f["'`])/g,
    cwe: "CWE-89", capec: "CAPEC-7", att: ["T1190 Exploit Public-Facing Application"], stride: "T", langs: ["js", "py", "php"],
    fix: "Bind parameters instead of interpolating into the query text." }),
  R({ id: "nosqli", t: "NoSQL query from unsanitised object", g: "sqli", kind: "sink", sev: 4,
    r: /\.(?:find|findOne|update|remove|deleteOne)\s*\(\s*(?:req\.(?:body|query|params)|\{\s*\$where)/g,
    cwe: "CWE-943", capec: "CAPEC-676", att: ["T1190 Exploit Public-Facing Application"], stride: "T", langs: ["js"],
    fix: "Validate/whitelist query shapes; reject operator keys ($where/$gt) from user input." }),
  R({ id: "ldap-inject", t: "LDAP filter from user input", g: "ssjs", kind: "sink", sev: 4,
    r: /\b(?:search|bind)\s*\([^)]*(?:\+|\$\{)[^)]*(?:cn=|uid=|\(&)/g,
    cwe: "CWE-90", capec: "CAPEC-136", att: ["T1190 Exploit Public-Facing Application"], stride: "T", langs: ["java", "py"],
    fix: "Escape LDAP metacharacters and use parameterised filters." }),

  // ---- Deserialization ----
  R({ id: "deser-pickle", t: "Unsafe deserialization (pickle/yaml/marshal)", g: "deser", kind: "sink", sev: 5,
    r: /\b(?:pickle\.loads?|cPickle\.loads?|yaml\.load\s*\((?![^)]*Loader)|marshal\.loads?|__reduce__)\b/g,
    cwe: "CWE-502", capec: "CAPEC-586", att: ["T1059 Command & Scripting Interpreter"], stride: "E", langs: ["py"],
    fix: "Use yaml.safe_load / JSON; never unpickle untrusted data." }),
  R({ id: "deser-java", t: "Java/PHP object deserialization of untrusted data", g: "deser", kind: "sink", sev: 5,
    r: /\b(?:ObjectInputStream|readObject|XMLDecoder|unserialize|Marshal\.load|JSON\.parse\s*\(\s*[^)]*\)\s*\.\s*__proto__)\b/g,
    cwe: "CWE-502", capec: "CAPEC-586", att: ["T1059 Command & Scripting Interpreter"], stride: "E", langs: ["java", "php", "rb"],
    fix: "Avoid native deserialization of external data; use a strict schema and allow-list classes." }),

  // ---- Path traversal / file ----
  R({ id: "path-trav", t: "File path built from user input", g: "path", kind: "sink", sev: 4,
    r: /\b(?:open|readFile|readFileSync|writeFile|createReadStream|file_get_contents|fopen|sendFile|res\.sendFile|include|require)\s*\(\s*[^)]*(?:req\.|request\.|params|query|body|\+|\$\{|\.\.\/)/g,
    cwe: "CWE-22", capec: "CAPEC-126", att: ["T1083 File and Directory Discovery"], stride: "I", langs: ["js", "py", "php"],
    fix: "Canonicalise and confine paths to an allow-listed base directory; reject '..'." }),
  R({ id: "upload-exec", t: "Uploaded file saved to a web/exec path", g: "rce", kind: "sink", sev: 4,
    r: /\b(?:move_uploaded_file|multer|\.mv\s*\(|save\s*\(\s*[^)]*upload)/g,
    cwe: "CWE-434", capec: "CAPEC-17", att: ["T1105 Ingress Tool Transfer"], stride: "E", langs: ["php", "js"],
    fix: "Store uploads outside the webroot, validate type/extension, and randomise filenames." }),

  // ---- SSRF / open redirect / network ----
  R({ id: "ssrf", t: "Outbound request to a user-controlled URL", g: "ssrf", kind: "sink", sev: 4,
    r: /\b(?:requests\.(?:get|post)|axios\.(?:get|post)|fetch|urllib\.request\.urlopen|http\.get|curl_exec|HttpClient|file_get_contents)\s*\(\s*[^)]*(?:req\.|request\.|params|query|body|\+|\$\{)/g,
    cwe: "CWE-918", capec: "CAPEC-664", att: ["T1090 Proxy", "T1046 Network Service Discovery"], stride: "I", langs: ["py", "js", "php"],
    fix: "Allow-list destination hosts, block internal IP ranges and redirects, resolve+pin DNS." }),
  R({ id: "open-redirect", t: "Open redirect to user-controlled location", g: "config", kind: "sink", sev: 3,
    r: /\b(?:redirect|res\.redirect|header\s*\(\s*["']Location|sendRedirect)\s*\(\s*[^)]*(?:req\.|request\.|params|query|\+|\$\{)/g,
    cwe: "CWE-601", capec: "CAPEC-194", att: ["T1566 Phishing"], stride: "T", langs: ["js", "py", "php", "java"],
    fix: "Redirect only to a server-side allow-list of relative paths." }),

  // ---- XSS / output ----
  R({ id: "dom-xss", t: "Unescaped HTML sink (DOM XSS)", g: "xss", kind: "sink", sev: 4,
    r: /\.(?:innerHTML|outerHTML)\s*=|document\.write\s*\(|\.insertAdjacentHTML\s*\(|dangerouslySetInnerHTML|\$\([^)]*\)\.html\s*\(/g,
    cwe: "CWE-79", capec: "CAPEC-63", att: ["T1059.007 JavaScript"], stride: "T", langs: ["js"],
    fix: "Use textContent / safe templating; sanitise with a vetted library before inserting HTML." }),
  R({ id: "reflect-xss", t: "User input written to the response unescaped", g: "xss", kind: "sink", sev: 4,
    r: /\b(?:res\.(?:send|write|end)|echo|print|printf|out\.print)\s*\(\s*[^)]*(?:req\.|request\.|params|query|body|\$_(?:GET|POST|REQUEST))/g,
    cwe: "CWE-79", capec: "CAPEC-591", att: ["T1059.007 JavaScript"], stride: "T", langs: ["js", "php", "java"],
    fix: "Context-encode all output; enable a strict Content-Security-Policy." }),

  // ---- XXE ----
  R({ id: "xxe", t: "XML parser with external entities enabled", g: "ssjs", kind: "sink", sev: 4,
    r: /\b(?:etree\.parse|DocumentBuilderFactory|SAXParser|libxml_disable_entity_loader\s*\(\s*false|resolveEntities\s*=\s*true|XMLReader)\b/g,
    cwe: "CWE-611", capec: "CAPEC-201", att: ["T1005 Data from Local System"], stride: "I", langs: ["java", "py", "php"],
    fix: "Disable DTDs and external entity resolution on the XML parser." }),

  // ---- Secrets ----
  R({ id: "secret-generic", t: "Hardcoded secret / API key", g: "secret", kind: "secret", sev: 4,
    r: /\b(?:api[_-]?key|secret|passwo?rd|token|access[_-]?key|private[_-]?key|client[_-]?secret)\s*[:=]\s*["'][A-Za-z0-9/_+\-]{12,}["']/gi,
    cwe: "CWE-798", capec: "CAPEC-191", att: ["T1552.001 Credentials In Files"], stride: "I", langs: ["*"],
    fix: "Move secrets to environment variables or a secrets manager; rotate anything committed." }),
  R({ id: "secret-aws", t: "AWS access key id", g: "secret", kind: "secret", sev: 5,
    r: /\bAKIA[0-9A-Z]{16}\b/g,
    cwe: "CWE-798", capec: "CAPEC-191", att: ["T1552.001 Credentials In Files"], stride: "I", langs: ["*"],
    fix: "Revoke the key immediately and use IAM roles / short-lived credentials." }),
  R({ id: "secret-pem", t: "Embedded private key", g: "secret", kind: "secret", sev: 5,
    r: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    cwe: "CWE-798", capec: "CAPEC-191", att: ["T1552.004 Private Keys"], stride: "I", langs: ["*"],
    fix: "Never commit private keys; store in a KMS/HSM and rotate." }),

  // ---- Crypto ----
  R({ id: "weak-hash", t: "Weak hash for security use (MD5/SHA1)", g: "crypto", kind: "crypto", sev: 3,
    r: /\b(?:md5|sha1|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)|hashlib\.(?:md5|sha1))\b/g,
    cwe: "CWE-327", capec: "CAPEC-97", att: ["T1110 Brute Force"], stride: "T", langs: ["*"],
    fix: "Use SHA-256+ for integrity and a slow KDF (bcrypt/scrypt/Argon2) for passwords." }),
  R({ id: "weak-cipher", t: "Broken/weak cipher or ECB mode", g: "crypto", kind: "crypto", sev: 4,
    r: /\b(?:DES|RC4|3DES|Blowfish|Cipher\.getInstance\s*\(\s*["'][^"']*ECB|AES\/ECB|MODE_ECB)\b/g,
    cwe: "CWE-327", capec: "CAPEC-97", att: ["T1600 Weaken Encryption"], stride: "I", langs: ["*"],
    fix: "Use AES-GCM (or ChaCha20-Poly1305) with a random nonce; never ECB or DES/RC4." }),
  R({ id: "weak-random", t: "Insecure randomness for security tokens", g: "crypto", kind: "crypto", sev: 3,
    r: /\b(?:Math\.random|random\.random|rand\s*\(|mt_rand|new\s+Random\s*\()/g,
    cwe: "CWE-338", capec: "CAPEC-112", att: ["T1110 Brute Force"], stride: "S", langs: ["*"],
    fix: "Use a CSPRNG (crypto.randomBytes / secrets / SecureRandom) for tokens and keys." }),
  R({ id: "tls-noverify", t: "TLS certificate verification disabled", g: "crypto", kind: "config", sev: 4,
    r: /\b(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*0|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0)/g,
    cwe: "CWE-295", capec: "CAPEC-94", att: ["T1557 Adversary-in-the-Middle"], stride: "S", langs: ["*"],
    fix: "Never disable certificate validation; fix the trust store instead." }),

  // ---- Auth / session ----
  R({ id: "jwt-none", t: "JWT verification weakened or skipped", g: "authz", kind: "auth", sev: 5,
    r: /\b(?:algorithms?\s*[:=]\s*\[?\s*["']none|verify\s*[:=]\s*False|jwt\.decode\s*\([^)]*verify\s*=\s*False|noVerify)\b/gi,
    cwe: "CWE-347", capec: "CAPEC-115", att: ["T1550.001 Application Access Token"], stride: "S", langs: ["*"],
    fix: "Verify signatures with a fixed algorithm allow-list; reject 'none'." }),
  R({ id: "cookie-insecure", t: "Session cookie missing HttpOnly/Secure", g: "authz", kind: "config", sev: 3,
    r: /\b(?:httpOnly\s*:\s*false|secure\s*:\s*false|setcookie\s*\([^)]*,\s*(?:false)?\s*,\s*false)/g,
    cwe: "CWE-614", capec: "CAPEC-31", att: ["T1539 Steal Web Session Cookie"], stride: "I", langs: ["js", "php"],
    fix: "Set HttpOnly, Secure and SameSite on session cookies." }),
  R({ id: "cors-wild", t: "Wildcard CORS with credentials", g: "config", kind: "config", sev: 3,
    r: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|origin\s*:\s*["']\*["'][^}]*credentials\s*:\s*true/g,
    cwe: "CWE-942", capec: "CAPEC-141", att: ["T1190 Exploit Public-Facing Application"], stride: "I", langs: ["js"],
    fix: "Reflect only allow-listed origins; never combine '*' with credentials." }),
  R({ id: "csrf-missing", t: "State-changing route without CSRF protection", g: "authz", kind: "config", sev: 2,
    r: /\b(?:app|router)\.(?:post|put|delete|patch)\s*\(/g,
    cwe: "CWE-352", capec: "CAPEC-62", att: ["T1204 User Execution"], stride: "T", langs: ["js"],
    fix: "Require anti-CSRF tokens or SameSite cookies on state-changing requests (verify this is handled)." }),

  // ---- Memory safety (C/C++) ----
  R({ id: "unsafe-cstr", t: "Unbounded C string operation", g: "memory", kind: "memory", sev: 5,
    r: /\b(?:strcpy|strcat|gets|sprintf|scanf|vsprintf|memcpy)\s*\(/g,
    cwe: "CWE-120", capec: "CAPEC-100", att: ["T1203 Exploitation for Client Execution"], stride: "E", langs: ["c", "cpp"],
    fix: "Use bounded variants (strncpy/snprintf/fgets) or safer string types; validate lengths." }),
  R({ id: "format-string", t: "Uncontrolled format string", g: "memory", kind: "memory", sev: 4,
    r: /\b(?:printf|fprintf|syslog)\s*\(\s*[A-Za-z_]\w*\s*\)/g,
    cwe: "CWE-134", capec: "CAPEC-67", att: ["T1203 Exploitation for Client Execution"], stride: "E", langs: ["c", "cpp"],
    fix: 'Use a constant format string: printf("%s", var).' }),

  // ---- JS-specific ----
  R({ id: "proto-pollution", t: "Possible prototype pollution", g: "rce", kind: "sink", sev: 3,
    r: /\[(?:req\.[^\]]+|key|prop)\]\s*=|Object\.assign\s*\(\s*\{\}\s*,\s*req\.|merge\s*\(\s*[^,]+,\s*req\./g,
    cwe: "CWE-1321", capec: "CAPEC-77", att: ["T1059.007 JavaScript"], stride: "T", langs: ["js"],
    fix: "Reject __proto__/constructor keys; use Map or a null-prototype object for merges." }),
  R({ id: "regex-dos", t: "Potentially catastrophic regex (ReDoS)", g: "dos", kind: "sink", sev: 2,
    r: /\/\([^)]*[+*]\)[+*]|\(\.\*\)\+|\(\.\+\)\+/g,
    cwe: "CWE-1333", capec: "CAPEC-492", att: ["T1499 Endpoint Denial of Service"], stride: "D", langs: ["js", "py"],
    fix: "Avoid nested quantifiers; bound input length or use a linear-time regex engine." }),

  // ---- Config / logging / debug ----
  R({ id: "debug-on", t: "Debug mode enabled", g: "config", kind: "config", sev: 2,
    r: /\b(?:DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True|NODE_ENV\s*=\s*['"]?development|display_errors\s*=\s*On)/g,
    cwe: "CWE-489", capec: "CAPEC-121", att: ["T1592 Gather Victim Host Information"], stride: "I", langs: ["py", "js", "php"],
    fix: "Disable debug/verbose errors in production." }),
  R({ id: "sensitive-log", t: "Sensitive value written to logs", g: "data", kind: "sink", sev: 2,
    r: /\b(?:console\.log|print|logger?\.(?:info|debug|warn))\s*\([^)]*(?:password|token|secret|api[_-]?key|ssn|credit)/gi,
    cwe: "CWE-532", capec: "CAPEC-215", att: ["T1552.001 Credentials In Files"], stride: "I", langs: ["*"],
    fix: "Redact secrets before logging; keep them out of log sinks entirely." }),

  // ---- Input sources (used to build source -> sink attack paths) ----
  R({ id: "src-http", t: "Untrusted HTTP input", g: "data", kind: "source", sev: 1,
    r: /\b(?:req\.(?:body|query|params|headers|cookies)|request\.(?:args|form|values|json|GET|POST)|\$_(?:GET|POST|REQUEST|COOKIE)|getParameter|ctx\.request)\b/g,
    cwe: "CWE-20", capec: "CAPEC-153", att: ["T1190 Exploit Public-Facing Application"], stride: "T", langs: ["*"],
    fix: "Validate and canonicalise all external input at the boundary (schema/allow-list)." }),
  R({ id: "src-cli", t: "Untrusted CLI/env input", g: "data", kind: "source", sev: 1,
    r: /\b(?:process\.argv|sys\.argv|os\.environ|getenv|process\.env|\$\{?\d)\b/g,
    cwe: "CWE-20", capec: "CAPEC-153", att: ["T1059 Command & Scripting Interpreter"], stride: "T", langs: ["*"],
    fix: "Treat argv/env as untrusted; validate before use." }),
];

// Pre-compile a version of each rule's regex with line tracking done at match time.
// Regexes above are authored global; we clone per-run to reset lastIndex safely.

// ---- Static analysis engine -------------------------------------------------
function detectLangs(code) {
  const langs = new Set();
  if (/\bdef\s+\w+\s*\(|import\s+\w+|print\s*\(|self\./.test(code)) langs.add("Python");
  if (/\b(?:const|let|var|function|=>|require\s*\(|module\.exports|console\.)\b/.test(code)) langs.add("JavaScript");
  if (/<\?php|\$\w+\s*=|echo\s|->/.test(code)) langs.add("PHP");
  if (/\b(?:public|private)\s+(?:static\s+)?(?:class|void|int|String)\b|System\.out/.test(code)) langs.add("Java");
  if (/#include\s*<|->\s*\w+|::\w+|std::/.test(code)) langs.add("C/C++");
  if (/\bfunc\s+\w+\s*\(|package\s+main|fmt\./.test(code)) langs.add("Go");
  if (/\bdef\s+\w+|puts\s|end\b.*\n|require\s+['"]/.test(code) && /\bend\b/.test(code)) langs.add("Ruby");
  return Array.from(langs);
}

function lineOf(code, idx) {
  let n = 1;
  for (let i = 0; i < idx && i < code.length; i++) if (code[i] === "\n") n++;
  return n;
}
function snippet(code, idx, len) {
  const start = code.lastIndexOf("\n", idx) + 1;
  let end = code.indexOf("\n", idx + len);
  if (end < 0) end = code.length;
  return code.slice(start, end).trim().slice(0, 160);
}

function analyze(code) {
  const findings = [];
  const sinks = [], sources = [];
  for (const rule of RULES) {
    const re = new RegExp(rule.r.source, rule.r.flags.includes("g") ? rule.r.flags : rule.r.flags + "g");
    let m, count = 0;
    while ((m = re.exec(code)) && count < 50) {
      count++;
      if (m.index === re.lastIndex) re.lastIndex++; // zero-width guard
      const line = lineOf(code, m.index);
      const f = {
        rid: rule.id, title: rule.t, goal: rule.g, kind: rule.kind, sev: rule.sev,
        cwe: rule.cwe, capec: rule.capec, att: rule.att, stride: rule.stride, fix: rule.fix,
        line, excerpt: snippet(code, m.index, m[0].length), idx: m.index, confidence: "medium",
      };
      if (rule.kind === "source") sources.push(f); else { sinks.push(f); findings.push(f); }
      if (rule.kind === "secret" || rule.kind === "memory") findings[findings.length - 1] && (findings[findings.length - 1].confidence = "high");
    }
  }
  // Taint heuristic: a sink within ~5 lines of a source is a likely exploitable chain.
  for (const f of findings) {
    if (f.kind !== "sink") continue;
    const near = sources.find((s) => Math.abs(s.line - f.line) <= 5);
    if (near) { f.confidence = "high"; f.taint = near.title + " (line " + near.line + ")"; }
  }
  // CSRF rule is noisy: only keep it if there are also input sources (a real app surface).
  const hasSrc = sources.length > 0;
  const kept = findings.filter((f) => f.rid !== "csrf-missing" || hasSrc);
  kept.sort((a, b) => b.sev - a.sev || a.line - b.line);
  return { findings: kept, sources, langs: detectLangs(code), loc: code.split("\n").length };
}

// ---- Attack-tree synthesis --------------------------------------------------
function buildTree(findings) {
  const byGoal = {};
  for (const f of findings) (byGoal[f.goal] = byGoal[f.goal] || []).push(f);
  const branches = Object.keys(byGoal).map((g) => {
    const items = byGoal[g];
    const maxSev = Math.max.apply(null, items.map((i) => i.sev));
    return {
      goal: g, name: (GOALS[g] || { name: g }).name, short: (GOALS[g] || {}).short || g,
      sev: maxSev, leaves: items,
    };
  }).sort((a, b) => b.sev - a.sev);
  return { root: "Compromise the application", branches };
}

// ---- Risk scoring -----------------------------------------------------------
function riskScore(findings) {
  const w = { 5: 28, 4: 15, 3: 7, 2: 3, 1: 1 };
  let raw = 0; const by = { 5: 0, 4: 0, 3: 0, 2: 0, 1: 0 };
  for (const f of findings) { raw += w[f.sev] * (f.confidence === "high" ? 1.25 : 1); by[f.sev]++; }
  const score = Math.min(100, Math.round(raw));
  const grade = score >= 75 ? "F" : score >= 55 ? "D" : score >= 35 ? "C" : score >= 15 ? "B" : score > 0 ? "A" : "A+";
  return { score, grade, by };
}

const SEV_LABEL = { 5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info" };
const sevClass = (s) => "tf-s" + s;

// ---- Samples (instant demo, multi-language) ---------------------------------
const SAMPLES = {
  "Node / Express API": `const express = require('express');\nconst { exec } = require('child_process');\nconst db = require('./db');\nconst app = express();\nconst API_KEY = "sk_live_9f8a7b6c5d4e3f2a1b0c";\n\napp.get('/ping', (req, res) => {\n  // pings a host the user supplies\n  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));\n});\n\napp.get('/user', (req, res) => {\n  const q = "SELECT * FROM users WHERE id = " + req.query.id;\n  db.query(q, (e, rows) => res.send('<b>' + rows[0].name + '</b>'));\n});\n\napp.post('/avatar', (req, res) => {\n  res.sendFile(req.body.path);\n});\n\napp.listen(3000);`,
  "Python / Flask": `import os, pickle, hashlib, yaml\nfrom flask import Flask, request\napp = Flask(__name__)\n\n@app.route('/run')\ndef run():\n    cmd = request.args.get('cmd')\n    return os.system(cmd)\n\n@app.route('/load', methods=['POST'])\ndef load():\n    data = pickle.loads(request.data)   # untrusted\n    return str(data)\n\n@app.route('/hash')\ndef h():\n    return hashlib.md5(request.args['p'].encode()).hexdigest()\n\nif __name__ == '__main__':\n    app.run(debug=True)`,
  "PHP / legacy": `<?php\n$pass = "P@ssw0rd_admin_2024";\n$id = $_GET['id'];\n$res = mysqli_query($conn, "SELECT * FROM accounts WHERE id = $id");\necho "Welcome " . $_GET['name'];\ninclude($_GET['page'] . ".php");\n$data = unserialize($_POST['blob']);\n?>`,
};

// ---- State + rendering ------------------------------------------------------
let _root = null;
let S = null;

function freshState() {
  return { code: "", result: null, tree: null, risk: null, tab: "analyze", ai: "", aiBusy: false, sentGraph: false };
}

const CSS = `
#tf-root{--tf-acc:var(--acc,#6aa6ff);width:100%;color:var(--txt);font-size:.9rem;line-height:1.5}
#tf-root *{box-sizing:border-box}
.tf-head{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:14px}
.tf-mark{font-weight:800;letter-spacing:.14em;font-size:1.05rem;color:var(--txt)}
.tf-mark b{color:var(--tf-acc)}
.tf-badge{font-size:.6rem;font-weight:700;letter-spacing:.08em;padding:3px 7px;border-radius:4px;background:color-mix(in srgb,var(--tf-acc) 18%,transparent);color:var(--tf-acc);border:1px solid color-mix(in srgb,var(--tf-acc) 40%,transparent)}
.tf-tag{font-size:.72rem;color:var(--mut)}
.tf-tabs{display:flex;gap:6px;flex-wrap:wrap;border-bottom:1px solid var(--line);margin-bottom:16px;padding-bottom:8px}
.tf-tab{background:transparent;border:1px solid var(--line);color:var(--mut);padding:7px 14px;border-radius:4px;font:inherit;font-size:.78rem;cursor:pointer;white-space:nowrap;transition:all .15s}
.tf-tab:hover{color:var(--txt);border-color:color-mix(in srgb,var(--tf-acc) 45%,var(--line))}
.tf-tab.on{color:var(--tf-acc);border-color:var(--tf-acc);background:color-mix(in srgb,var(--tf-acc) 10%,transparent);font-weight:600}
.tf-tab:disabled{opacity:.4;cursor:not-allowed}
.tf-panel{min-height:200px}
.tf-ta{width:100%;min-height:260px;background:var(--card,#0e1420);color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:12px;font-family:ui-monospace,"JetBrains Mono",monospace;font-size:.82rem;resize:vertical;spellcheck:false}
.tf-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0}
.tf-btn{background:var(--tf-acc);color:#071018;border:none;padding:9px 16px;border-radius:4px;font:inherit;font-weight:600;font-size:.82rem;cursor:pointer;transition:filter .15s}
.tf-btn:hover{filter:brightness(1.08)}
.tf-btn:disabled{opacity:.5;cursor:not-allowed}
.tf-btn.ghost{background:transparent;color:var(--txt);border:1px solid var(--line)}
.tf-btn.ghost:hover{border-color:var(--tf-acc);color:var(--tf-acc)}
.tf-samples{display:flex;gap:6px;flex-wrap:wrap}
.tf-chip{background:transparent;border:1px solid var(--line);color:var(--mut);padding:5px 11px;border-radius:999px;font:inherit;font-size:.74rem;cursor:pointer}
.tf-chip:hover{border-color:var(--tf-acc);color:var(--tf-acc)}
.tf-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:14px 0}
.tf-kpi{background:var(--card,#0e1420);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.tf-kpi-v{font-size:1.5rem;font-weight:800;line-height:1}
.tf-kpi-l{font-size:.68rem;color:var(--mut);text-transform:uppercase;letter-spacing:.06em;margin-top:5px}
.tf-grade{display:inline-flex;align-items:center;justify-content:center;width:44px;height:44px;border-radius:10px;font-weight:800;font-size:1.3rem}
.tf-note{font-size:.74rem;color:var(--mut);background:color-mix(in srgb,var(--tf-acc) 7%,transparent);border:1px solid var(--line);border-left:3px solid var(--tf-acc);border-radius:4px;padding:9px 12px;margin:10px 0}
.tf-empty{color:var(--mut);text-align:center;padding:40px 0}
.tf-tbl{width:100%;border-collapse:collapse;font-size:.8rem}
.tf-tbl th{text-align:left;color:var(--mut);font-weight:600;font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;padding:8px 10px;border-bottom:1px solid var(--line)}
.tf-tbl td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.tf-tbl tr:hover td{background:color-mix(in srgb,var(--tf-acc) 5%,transparent)}
.tf-pill{display:inline-block;font-size:.66rem;font-weight:700;padding:2px 7px;border-radius:4px;white-space:nowrap}
.tf-s5{background:#3a0d12;color:#ff8a93;border:1px solid #6a1620}
.tf-s4{background:#3a220d;color:#ffb366;border:1px solid #6a3e16}
.tf-s3{background:#3a350d;color:#ffe066;border:1px solid #6a5f16}
.tf-s2{background:#0d2a3a;color:#66c7ff;border:1px solid #16506a}
.tf-s1{background:#1a1f2b;color:#9aa6b8;border:1px solid #2a3344}
.tf-conf{font-size:.66rem;color:var(--mut)}
.tf-code{font-family:ui-monospace,"JetBrains Mono",monospace;font-size:.74rem;color:var(--mut);background:var(--card,#0e1420);padding:2px 5px;border-radius:3px;display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tf-ref{font-size:.68rem;color:var(--mut)}
.tf-ref a,.tf-ref span{color:var(--tf-acc)}
.tf-tree{list-style:none;margin:0;padding:0}
.tf-tree ul{list-style:none;margin:0 0 0 20px;padding:6px 0 0;border-left:1px dashed var(--line)}
.tf-tnode{padding:4px 0}
.tf-tgoal{display:flex;align-items:center;gap:8px;cursor:pointer;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card,#0e1420);margin-bottom:4px}
.tf-tgoal:hover{border-color:var(--tf-acc)}
.tf-tgoal .tf-caret{transition:transform .15s;color:var(--mut)}
.tf-tgoal.col .tf-caret{transform:rotate(-90deg)}
.tf-tleaf{display:flex;align-items:flex-start;gap:8px;padding:6px 10px;margin-left:8px}
.tf-dot{width:8px;height:8px;border-radius:50%;flex:none;margin-top:5px}
.tf-matrix{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
.tf-mcard{background:var(--card,#0e1420);border:1px solid var(--line);border-radius:8px;padding:12px}
.tf-mcard h4{margin:0 0 6px;font-size:.82rem;color:var(--tf-acc)}
.tf-mcard .tf-ref{display:block;margin:3px 0}
.tf-aiout{background:var(--card,#0e1420);border:1px solid var(--line);border-radius:8px;padding:14px;white-space:pre-wrap;font-size:.82rem;min-height:60px}
.tf-sec-h{font-size:.8rem;font-weight:700;color:var(--txt);margin:18px 0 8px;text-transform:uppercase;letter-spacing:.05em}
`;

function shellHTML() {
  return "<style>" + CSS + "</style>" +
    '<div id="tf-root">' +
    '<div class="tf-head"><span class="tf-mark">THREAT<b>FOREST</b></span>' +
    '<span class="tf-badge">CODE &rarr; ATTACK TREES</span>' +
    '<span class="tf-tag">Static analysis &middot; MITRE ATT&amp;CK &middot; CWE &middot; CAPEC &middot; STRIDE</span></div>' +
    '<nav class="tf-tabs" id="tf-tabs"></nav>' +
    '<section class="tf-panel" id="tf-panel"></section>' +
    "</div>";
}

const TABS = [
  { id: "analyze", name: "Analyze" },
  { id: "tree", name: "Attack Tree" },
  { id: "findings", name: "Findings" },
  { id: "attack", name: "ATT&CK / CAPEC" },
  { id: "mitigations", name: "Mitigations" },
  { id: "report", name: "Report" },
];

function renderTabs() {
  const nav = _root && _root.querySelector("#tf-tabs");
  if (!nav) return;
  const hasResult = !!(S.result && S.result.findings.length >= 0 && S.result);
  nav.innerHTML = TABS.map((t) => {
    const needsResult = t.id !== "analyze";
    const dis = needsResult && !S.result ? " disabled" : "";
    return '<button class="tf-tab' + (t.id === S.tab ? " on" : "") + '" data-tab="' + t.id + '"' + dis + ">" + esc(t.name) + "</button>";
  }).join("");
  nav.querySelectorAll(".tf-tab").forEach((b) => { b.onclick = () => { if (b.disabled) return; S.tab = b.dataset.tab; renderTabs(); renderPanel(); }; });
}

function renderPanel() {
  const p = _root && _root.querySelector("#tf-panel");
  if (!p) return;
  if (S.tab === "analyze") return paintAnalyze(p);
  if (!S.result) { p.innerHTML = '<p class="tf-empty">Run an analysis first.</p>'; return; }
  if (S.tab === "tree") return paintTree(p);
  if (S.tab === "findings") return paintFindings(p);
  if (S.tab === "attack") return paintAttack(p);
  if (S.tab === "mitigations") return paintMitigations(p);
  if (S.tab === "report") return paintReport(p);
}

// ---- Analyze tab ----
function paintAnalyze(p) {
  p.innerHTML =
    '<p class="tf-tag" style="margin:0 0 10px">Paste source code (any language, one or many files). Everything is analyzed locally in your browser &mdash; nothing is uploaded unless you run the optional AI deep-dive.</p>' +
    '<div class="tf-samples">Load a sample: ' + Object.keys(SAMPLES).map((k) => '<button class="tf-chip" data-sample="' + esc(k) + '">' + esc(k) + "</button>").join("") + "</div>" +
    '<textarea class="tf-ta" id="tf-code" spellcheck="false" placeholder="// paste code here...">' + esc(S.code) + "</textarea>" +
    '<div class="tf-row">' +
    '<button class="tf-btn" id="tf-run">Build attack tree</button>' +
    '<button class="tf-btn ghost" id="tf-clear">Clear</button>' +
    '<span class="tf-tag" id="tf-stat"></span></div>' +
    (S.result ? summaryHTML() : "");
  p.querySelectorAll("[data-sample]").forEach((b) => b.onclick = () => {
    S.code = SAMPLES[b.dataset.sample] || "";
    const ta = p.querySelector("#tf-code"); if (ta) ta.value = S.code;
  });
  p.querySelector("#tf-clear").onclick = () => { S.code = ""; S.result = null; renderTabs(); paintAnalyze(p); };
  p.querySelector("#tf-run").onclick = () => {
    const ta = p.querySelector("#tf-code"); S.code = ta ? ta.value : "";
    if (!S.code.trim()) { const st = p.querySelector("#tf-stat"); if (st) st.textContent = "Paste some code first."; return; }
    const t0 = performance.now();
    S.result = analyze(S.code);
    S.tree = buildTree(S.result.findings);
    S.risk = riskScore(S.result.findings);
    S.sentGraph = false; S.ai = "";
    const ms = Math.max(1, Math.round(performance.now() - t0));
    renderTabs();
    S.tab = "tree"; renderTabs(); renderPanel();
    // flash the time on the analyze stat is moot now; keep for re-entry
    S._ms = ms;
  };
}

function summaryHTML() {
  const r = S.risk, res = S.result;
  return "" +
    '<div class="tf-kpis">' +
    '<div class="tf-kpi"><div class="tf-kpi-v"><span class="tf-grade ' + sevClass(r.score >= 55 ? 5 : r.score >= 35 ? 4 : r.score >= 15 ? 3 : 2) + '">' + r.grade + "</span></div><div class=\"tf-kpi-l\">Risk grade</div></div>" +
    '<div class="tf-kpi"><div class="tf-kpi-v">' + r.score + '</div><div class="tf-kpi-l">Risk score / 100</div></div>' +
    '<div class="tf-kpi"><div class="tf-kpi-v">' + res.findings.length + '</div><div class="tf-kpi-l">Weaknesses</div></div>' +
    '<div class="tf-kpi"><div class="tf-kpi-v" style="color:#ff8a93">' + (r.by[5] + r.by[4]) + '</div><div class="tf-kpi-l">Critical + High</div></div>' +
    '<div class="tf-kpi"><div class="tf-kpi-v">' + (S.tree ? S.tree.branches.length : 0) + '</div><div class="tf-kpi-l">Attack paths</div></div>' +
    "</div>" +
    '<p class="tf-note">Analyzed ' + res.loc + " lines" + (res.langs.length ? " (" + esc(res.langs.join(", ")) + ")" : "") +
    (S._ms ? " in " + S._ms + " ms" : "") + ". Findings are heuristic and advisory &mdash; verify high-confidence source&rarr;sink chains first.</p>";
}

// ---- Attack tree tab ----
function paintTree(p) {
  if (!S.tree.branches.length) { p.innerHTML = '<p class="tf-empty">No attack paths found. Either the code is clean of the patterns ThreatForest checks, or paste more of it.</p>'; return; }
  const dotColor = { 5: "#ff5d6c", 4: "#ff9f45", 3: "#ffd24a", 2: "#4ab8ff", 1: "#7f8ca0" };
  const branches = S.tree.branches.map((b) => {
    const leaves = b.leaves.map((l) =>
      '<li class="tf-tleaf"><span class="tf-dot" style="background:' + dotColor[l.sev] + '"></span>' +
      "<div><div><b>" + esc(l.title) + '</b> <span class="tf-pill ' + sevClass(l.sev) + '">' + SEV_LABEL[l.sev] + "</span>" +
      (l.taint ? ' <span class="tf-conf">&larr; reachable from ' + esc(l.taint) + "</span>" : "") + "</div>" +
      '<div class="tf-ref">line ' + l.line + " &middot; " + esc(l.cwe) + " &middot; " + esc((l.att[0] || "")) + "</div></div></li>"
    ).join("");
    return '<li class="tf-tnode"><div class="tf-tgoal" data-g="' + esc(b.goal) + '">' +
      '<span class="tf-caret">&#9660;</span><span class="tf-dot" style="background:' + dotColor[b.sev] + '"></span>' +
      "<b>" + esc(b.name) + '</b> <span class="tf-tag">(' + b.leaves.length + ")</span></div><ul>" + leaves + "</ul></li>";
  }).join("");
  p.innerHTML = '<p class="tf-tag" style="margin:0 0 12px"><b>Goal:</b> ' + esc(S.tree.root) + " &mdash; click a path to collapse. Each leaf is a concrete weakness that advances that goal.</p>" +
    '<ul class="tf-tree">' + branches + "</ul>" +
    '<div class="tf-row" style="margin-top:16px"><button class="tf-btn ghost" id="tf-graph"' + (S.sentGraph ? " disabled" : "") + ">" + (S.sentGraph ? "Sent to Security Graph" : "Send to Security Graph") + "</button></div>";
  p.querySelectorAll(".tf-tgoal").forEach((el) => el.onclick = () => {
    el.classList.toggle("col");
    const ul = el.nextElementSibling; if (ul) ul.style.display = el.classList.contains("col") ? "none" : "";
  });
  const gb = p.querySelector("#tf-graph"); if (gb) gb.onclick = () => sendGraph(gb);
}

// ---- Findings tab ----
function paintFindings(p) {
  if (!S.result.findings.length) { p.innerHTML = '<p class="tf-empty">No weaknesses detected.</p>'; return; }
  const rows = S.result.findings.map((f) =>
    "<tr><td><span class=\"tf-pill " + sevClass(f.sev) + '">' + SEV_LABEL[f.sev] + "</span></td>" +
    "<td><b>" + esc(f.title) + '</b><br><span class="tf-conf">confidence: ' + esc(f.confidence) + (f.taint ? " &middot; tainted by " + esc(f.taint) : "") + "</span></td>" +
    "<td>" + f.line + "</td>" +
    '<td><span class="tf-code">' + esc(f.excerpt) + "</span></td>" +
    '<td class="tf-ref">' + esc(f.cwe) + "<br>" + esc(f.capec) + "</td></tr>"
  ).join("");
  p.innerHTML = '<table class="tf-tbl"><thead><tr><th>Severity</th><th>Weakness</th><th>Line</th><th>Evidence</th><th>Refs</th></tr></thead><tbody>' + rows + "</tbody></table>";
}

// ---- ATT&CK / CAPEC tab ----
function paintAttack(p) {
  const tech = {};
  for (const f of S.result.findings) for (const a of f.att) {
    const id = a.split(" ")[0];
    tech[a] = tech[a] || { name: a, id, count: 0, cwes: new Set(), capecs: new Set() };
    tech[a].count++; tech[a].cwes.add(f.cwe); tech[a].capecs.add(f.capec);
  }
  const list = Object.values(tech).sort((a, b) => b.count - a.count);
  if (!list.length) { p.innerHTML = '<p class="tf-empty">No techniques mapped.</p>'; return; }
  const cards = list.map((t) => {
    const tid = t.id.split(".")[0];
    return '<div class="tf-mcard"><h4>' + esc(t.name) + "</h4>" +
      '<div class="tf-ref">Hits: <b>' + t.count + "</b></div>" +
      '<div class="tf-ref">CWE: ' + esc(Array.from(t.cwes).join(", ")) + "</div>" +
      '<div class="tf-ref">CAPEC: ' + esc(Array.from(t.capecs).join(", ")) + "</div>" +
      '<div class="tf-ref"><a href="https://attack.mitre.org/techniques/' + esc(tid.replace(".", "/")) + '/" target="_blank" rel="noopener">MITRE ' + esc(t.id) + " &nearr;</a></div></div>";
  }).join("");
  p.innerHTML = '<p class="tf-tag" style="margin:0 0 12px">' + list.length + " ATT&amp;CK technique(s) mapped deterministically from the detected weaknesses &mdash; no embedding guesswork.</p>" +
    '<div class="tf-matrix">' + cards + "</div>";
}

// ---- Mitigations tab ----
function paintMitigations(p) {
  const seen = {}, groups = [];
  for (const f of S.result.findings) {
    if (seen[f.rid]) continue; seen[f.rid] = 1;
    groups.push(f);
  }
  groups.sort((a, b) => b.sev - a.sev);
  const rows = groups.map((f) =>
    '<div class="tf-mcard" style="margin-bottom:10px"><h4>' + esc(f.title) + ' <span class="tf-pill ' + sevClass(f.sev) + '">' + SEV_LABEL[f.sev] + "</span></h4>" +
    "<div style=\"margin:6px 0\">" + esc(f.fix) + "</div>" +
    '<div class="tf-ref">' + esc(f.cwe) + " &middot; " + esc(f.capec) + " &middot; STRIDE: " + esc(f.stride) + "</div></div>"
  ).join("");
  p.innerHTML = '<p class="tf-sec-h">Prioritised remediation (' + groups.length + " weakness classes)</p>" + rows +
    '<div class="tf-row" style="margin-top:14px">' +
    '<button class="tf-btn" id="tf-ai"' + (S.aiBusy ? " disabled" : "") + ">" + (S.aiBusy ? "Thinking…" : "AI deep-dive & extra attack paths") + "</button>" +
    '<span class="tf-tag">Optional: sends the findings (not your full code) to Darknode AI for a prioritised, context-aware remediation plan.</span></div>' +
    (S.ai ? '<div class="tf-aiout" id="tf-aiout" style="margin-top:12px">' + esc(S.ai) + "</div>" : '<div class="tf-aiout" id="tf-aiout" style="margin-top:12px;display:none"></div>');
  const ab = p.querySelector("#tf-ai"); if (ab) ab.onclick = () => runAI(p);
}

// ---- Report tab ----
function toMarkdown() {
  const r = S.risk, res = S.result;
  let md = "# ThreatForest report\n\n";
  md += "- **Risk grade:** " + r.grade + " (" + r.score + "/100)\n";
  md += "- **Lines analyzed:** " + res.loc + (res.langs.length ? " (" + res.langs.join(", ") + ")" : "") + "\n";
  md += "- **Weaknesses:** " + res.findings.length + " (critical " + r.by[5] + ", high " + r.by[4] + ", medium " + r.by[3] + ", low " + r.by[2] + ")\n\n";
  md += "## Attack tree\n\nGoal: " + S.tree.root + "\n\n";
  for (const b of S.tree.branches) {
    md += "- **" + b.name + "**\n";
    for (const l of b.leaves) md += "  - " + l.title + " (" + SEV_LABEL[l.sev] + ", line " + l.line + ", " + l.cwe + ", " + (l.att[0] || "") + ")\n";
  }
  md += "\n## Findings\n\n| Sev | Weakness | Line | CWE | CAPEC |\n|---|---|---|---|---|\n";
  for (const f of res.findings) md += "| " + SEV_LABEL[f.sev] + " | " + f.title + " | " + f.line + " | " + f.cwe + " | " + f.capec + " |\n";
  md += "\n## Remediation\n\n";
  const seen = {};
  for (const f of res.findings) { if (seen[f.rid]) continue; seen[f.rid] = 1; md += "- **" + f.title + ":** " + f.fix + "\n"; }
  if (S.ai) md += "\n## AI deep-dive\n\n" + S.ai + "\n";
  md += "\n---\n_ThreatForest (Darknode). Heuristic static analysis; verify before acting._\n";
  return md;
}
function paintReport(p) {
  const md = toMarkdown();
  p.innerHTML =
    '<div class="tf-row"><button class="tf-btn" id="tf-copy">Copy Markdown</button>' +
    '<button class="tf-btn ghost" id="tf-json">Download JSON</button>' +
    '<button class="tf-btn ghost" id="tf-md">Download .md</button></div>' +
    '<textarea class="tf-ta" readonly style="min-height:340px">' + esc(md) + "</textarea>";
  p.querySelector("#tf-copy").onclick = () => {
    navigator.clipboard && navigator.clipboard.writeText(md);
    const b = p.querySelector("#tf-copy"); b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy Markdown"), 1200);
  };
  p.querySelector("#tf-json").onclick = () => download("threatforest-report.json", JSON.stringify({ risk: S.risk, result: S.result, tree: S.tree, ai: S.ai }, null, 2), "application/json");
  p.querySelector("#tf-md").onclick = () => download("threatforest-report.md", md, "text/markdown");
}
function download(name, data, type) {
  try {
    const blob = new Blob([data], { type: type });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 100);
  } catch (_) {}
}

// ---- AI deep-dive (optional, one streaming pass via the Darknode proxy) ----
function proxyUrl() { try { if (window.DARKNODE_PROXY_URL) return window.DARKNODE_PROXY_URL; } catch (_) {} return "/api/chat"; }
async function runAI(p) {
  if (S.aiBusy) return;
  S.aiBusy = true; S.ai = ""; paintMitigations(p);
  const out = p.querySelector("#tf-aiout");
  if (out) { out.style.display = ""; out.textContent = ""; }
  const brief = S.result.findings.slice(0, 40).map((f) => "- " + f.title + " (" + SEV_LABEL[f.sev] + ", " + f.cwe + ", line " + f.line + ")").join("\n");
  const sys = "You are a senior application-security engineer. You are given a list of statically-detected weaknesses from a codebase. Produce: (1) the single most urgent fix and why, (2) any additional attack paths that chain these weaknesses together, (3) a short prioritised remediation checklist. Be concrete and terse. Do not repeat the raw list.";
  const user = "Weaknesses found (" + S.result.findings.length + " total, top shown):\n" + brief + "\n\nLanguages: " + (S.result.langs.join(", ") || "unknown") + ".";
  try {
    const r = await fetch(proxyUrl(), {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider: "gemini", model: "gemini-flash-latest", messages: [{ role: "system", content: sys }, { role: "user", content: user }] }),
    });
    if (!r.ok || !r.body) throw new Error("AI service " + r.status);
    const reader = r.body.getReader(), dec = new TextDecoder(); let buf = "";
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      let nl; while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
        if (!line.startsWith("data: ")) continue;
        const pl = line.slice(6); if (pl === "[DONE]") break;
        try { const j = JSON.parse(pl); const d = j.choices && j.choices[0] && j.choices[0].delta; if (d && d.content) { S.ai += d.content; if (out) out.textContent = S.ai; } } catch (_) {}
      }
    }
    if (!S.ai) S.ai = "The AI service returned no content. The deterministic findings above are complete on their own.";
  } catch (e) {
    S.ai = "AI deep-dive unavailable (" + (e && e.message ? e.message : "offline") + "). The deterministic analysis above is complete without it.";
    if (out) { out.style.display = ""; out.textContent = S.ai; }
  }
  S.aiBusy = false;
  const ab = p.querySelector("#tf-ai"); if (ab) { ab.disabled = false; ab.textContent = "AI deep-dive & extra attack paths"; }
}

// ---- Security Graph feed ----
function sendGraph(btn) {
  if (S.sentGraph || !S.result) return;
  btn.disabled = true; btn.textContent = "Sending…";
  import("/js/graph-bridge.js?v=20260923c").then((gb) => {
    try {
      const sevMap = { 5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info" };
      const asset = gb.sendToGraph("ThreatForest", [{
        type: "ASSET", name: "ThreatForest scan (" + (S.result.langs.join("/") || "code") + ")",
        data: { lines: S.result.loc, weaknesses: S.result.findings.length, riskScore: S.risk.score, grade: S.risk.grade, _tool: "threatforest" },
        opts: { tags: ["threatforest", "sast"] },
      }], undefined, true).entities[0];
      gb.batchGraph(() => {
        const findItems = S.result.findings.slice(0, 60).map((f) => ({
          type: "VULNERABILITY", name: f.title + " @ line " + f.line,
          data: { cwe: f.cwe, capec: f.capec, attack: (f.att[0] || ""), stride: f.stride, confidence: f.confidence, evidence: f.excerpt, _goal: f.goal },
          opts: { tags: ["threatforest", f.goal], severity: sevMap[f.sev] },
        }));
        const out = gb.sendToGraph("ThreatForest", findItems, undefined, true);
        if (asset) out.entities.forEach((e) => { if (e) try { gb.linkEntities(asset.id, e.id, "contains"); } catch (_) {} });
        // techniques
        const techNames = {};
        S.result.findings.forEach((f) => f.att.forEach((a) => (techNames[a] = 1)));
        const techItems = Object.keys(techNames).map((a) => ({ type: "TECHNIQUE", name: a, data: { _tool: "threatforest" }, opts: { tags: ["threatforest", "mitre"] } }));
        if (techItems.length) {
          const tout = gb.sendToGraph("ThreatForest", techItems, undefined, true);
          if (asset) tout.entities.forEach((e) => { if (e) try { gb.linkEntities(asset.id, e.id, "related_to"); } catch (_) {} });
        }
      });
      S.sentGraph = true;
      btn.textContent = "Sent to Security Graph";
      if (gb.showGraphToast) gb.showGraphToast("ThreatForest: " + S.result.findings.length + " weaknesses sent to the Security Graph.");
    } catch (e) {
      btn.disabled = false; btn.textContent = "Send to Security Graph";
    }
  }).catch(() => { btn.disabled = false; btn.textContent = "Send to Security Graph"; });
}

// ---- Entry points -----------------------------------------------------------
export function renderThreatforest(main) {
  S = freshState();
  main.innerHTML = shellHTML();
  _root = main.querySelector("#tf-root");
  // retint to the user's accent
  try { const acc = getComputedStyle(document.body).getPropertyValue("--acc"); if (acc && _root) _root.style.setProperty("--tf-acc", acc.trim()); } catch (_) {}
  renderTabs();
  renderPanel();
}
export function cleanupThreatforest() { _root = null; S = null; }
