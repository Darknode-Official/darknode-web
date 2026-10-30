// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// ThreatForest engine — pure, deterministic static-analysis logic (no DOM, no network).
// Imported by public/js/threatforest.js (the UI) and exercised by
// test/security/threatforest.test.mjs. Keeping it browser-free makes it unit-testable
// under plain Node (`node test/run.mjs`).
//
// Analysis is heuristic and advisory: it flags patterns that are commonly dangerous.
// Confidence is shown per finding; treat high-confidence findings first.
//
// Two tiers of evidence, kept honestly distinct:
//   1. CONFIRMED (JavaScript/TypeScript only): the Code Scanner's inter-procedural
//      data-flow (taint) engine is reused here. When it can trace every step of a path
//      from an untrusted source into a sink, that finding is marked `reach` (confirmed
//      reachable) and cites the traced path. This is real reachability, not proximity.
//   2. LEXICAL (all other languages, and categories taint doesn't model): a regex hit
//      whose source->sink relationship is CO-LOCATION only — NOT call-graph reachability.
//      See the co-location heuristic in analyze() below; it is never inflated to a
//      reachability claim.

import { taintScan } from "./codescan/taint-js.js?v=20261029e";

// ---- Attack goals: the top level of every tree -----------------------------
export const GOALS = {
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
export const RULES = [
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

export const SEV_LABEL = { 5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info" };

// Lexical tokens that denote an untrusted input source. Used by the co-location
// heuristic to tell "the untrusted input is used in this very statement" (strong)
// from "a source merely sits a few lines away" (weak).
const SRC_TOKEN = /\b(?:req|request|params|query|body|getParameter)\b|\$_(?:GET|POST|REQUEST|COOKIE)|process\.argv|sys\.argv/;

// ---- Data-flow (taint) confirmation for JS/TS ------------------------------
// The taint engine reports sink kinds (code|cmd|sql|nosql|xss|redirect|path|ssrf|
// regex|module) with a numeric CWE and a traced flow. This maps each kind onto a
// ThreatForest goal and the standard refs the regex rules also carry, so a confirmed
// flow slots into the same attack tree. The CWE/title/fix come from the taint finding.
const SEV_FROM_STR = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const FLOW_MAP = {
  code:     { goal: "rce",    capec: "CAPEC-242", att: ["T1059 Command & Scripting Interpreter"], stride: "E" },
  cmd:      { goal: "rce",    capec: "CAPEC-248", att: ["T1059 Command & Scripting Interpreter"], stride: "E" },
  sql:      { goal: "sqli",   capec: "CAPEC-66",  att: ["T1190 Exploit Public-Facing Application"], stride: "T" },
  nosql:    { goal: "sqli",   capec: "CAPEC-676", att: ["T1190 Exploit Public-Facing Application"], stride: "T" },
  xss:      { goal: "xss",    capec: "CAPEC-63",  att: ["T1059.007 JavaScript"], stride: "T" },
  redirect: { goal: "config", capec: "CAPEC-194", att: ["T1566 Phishing"], stride: "T" },
  path:     { goal: "path",   capec: "CAPEC-126", att: ["T1083 File and Directory Discovery"], stride: "I" },
  ssrf:     { goal: "ssrf",   capec: "CAPEC-664", att: ["T1090 Proxy"], stride: "I" },
  regex:    { goal: "dos",    capec: "CAPEC-492", att: ["T1499 Endpoint Denial of Service"], stride: "D" },
  module:   { goal: "rce",    capec: "CAPEC-175", att: ["T1059 Command & Scripting Interpreter"], stride: "E" },
};
const cweNum = (s) => parseInt(String(s).replace(/\D/g, ""), 10);

// Run the taint engine and turn every CONFIRMED source->sink flow into a finding.
// These are the only findings allowed to claim reachability — each one carries the
// actual traced path. Pure/DOM-free; failures degrade to [] (regex analysis still runs).
export function flowFindings(code) {
  let flows = [];
  try { flows = taintScan(code); } catch (_) { return []; }
  const lines = String(code || "").split("\n");
  const out = [];
  for (const t of flows) {
    const map = FLOW_MAP[t.kind];
    if (!map) continue;
    const flow = Array.isArray(t.flow) ? t.flow : [];
    const src = (flow[0] && flow[0].label ? flow[0].label : "untrusted input").replace(/^untrusted input:\s*/, "");
    const steps = Math.max(1, flow.length - 1);
    out.push({
      rid: "flow." + t.kind, title: t.title, goal: map.goal, kind: "sink",
      sev: SEV_FROM_STR[t.sev] || 3, cwe: "CWE-" + t.cwe, capec: map.capec, att: map.att, stride: map.stride,
      fix: t.fix, line: t.line, excerpt: (lines[t.line - 1] || "").trim().slice(0, 160), idx: 0,
      confidence: "high",
      reach: {
        level: "confirmed", source: src, steps,
        // Honest: the taint engine traced every step, so "reachable" is earned here
        // (unlike the lexical co-location labels, which never make this claim).
        text: "confirmed reachable — data flow traced from " + src + " (" + steps + " step" + (steps === 1 ? "" : "s") + ")",
        flow: flow.map((s) => ({ line: s.line, label: s.label })),
        why: t.why,
      },
    });
  }
  return out;
}

// ---- Static analysis engine -------------------------------------------------
export function detectLangs(code) {
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

export function lineOf(code, idx) {
  let n = 1;
  for (let i = 0; i < idx && i < code.length; i++) if (code[i] === "\n") n++;
  return n;
}
export function snippet(code, idx, len) {
  const start = code.lastIndexOf("\n", idx) + 1;
  let end = code.indexOf("\n", idx + len);
  if (end < 0) end = code.length;
  return code.slice(start, end).trim().slice(0, 160);
}

export function analyze(code) {
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
  // Co-location heuristic — this is LEXICAL co-location, NOT call-graph reachability.
  //  - "input" (strong): the sink's own statement contains an untrusted-input token,
  //    so external data plausibly flows into the sink on that line -> confidence high.
  //  - "near" (weak): a source merely sits within ~5 lines of the sink. Proximity does
  //    not prove data flow, so confidence is NOT inflated; it stays as detected.
  for (const f of findings) {
    if (f.kind !== "sink") continue;
    if (SRC_TOKEN.test(f.excerpt)) {
      f.confidence = "high";
      f.coloc = { level: "input", text: "untrusted input used on this line" };
      continue;
    }
    const near = sources.find((s) => Math.abs(s.line - f.line) <= 5);
    if (near) {
      f.coloc = { level: "near", text: "near untrusted input: " + near.title + " (line " + near.line + ")" };
    }
  }
  // CSRF rule is noisy: only keep it if there are also input sources (a real app surface).
  const hasSrc = sources.length > 0;
  let kept = findings.filter((f) => f.rid !== "csrf-missing" || hasSrc);
  const langs = detectLangs(code);

  // Data-flow confirmation (JS/TS): a traced source->sink path is strictly better than
  // lexical co-location, so it SUPERSEDES a regex sink hit of the same CWE on the same
  // line and is added as a confirmed-reachable node. Regex hits the taint engine did not
  // (or could not) confirm stay exactly as detected — weak, honest "near"/"input" nodes.
  let confirmed = [];
  if (langs.includes("JavaScript")) {
    confirmed = flowFindings(code);
    if (confirmed.length) {
      const drop = new Set();
      for (const c of confirmed) for (const f of kept) {
        if (f.kind === "sink" && f.line === c.line && cweNum(f.cwe) === cweNum(c.cwe)) drop.add(f);
      }
      kept = kept.filter((f) => !drop.has(f)).concat(confirmed);
    }
  }
  kept.sort((a, b) => b.sev - a.sev || a.line - b.line);
  return { findings: kept, sources, langs, loc: code.split("\n").length, confirmed: confirmed.length };
}

// ---- Attack-tree edge weighting (HEURISTIC) ---------------------------------
// Real attack-tree tools rank paths. We attach a rough likelihood `p` (0..1) and an
// effort `cost` (1 easy .. 5 hard) to each leaf so paths can be ordered. This is a
// transparent heuristic derived from severity and evidence strength — a confirmed
// data-flow weighs most, then a same-line input, then mere proximity. It is NOT a
// measured exploit probability; it only orders what to look at first.
export function edgeWeight(f) {
  const base = { 5: 0.55, 4: 0.4, 3: 0.25, 2: 0.12, 1: 0.05 }[f.sev] || 0.1;
  let p = base;
  if (f.reach) p = Math.min(0.95, base + 0.4);                               // taint traced the flow
  else if (f.coloc && f.coloc.level === "input") p = Math.min(0.8, base + 0.2);
  else if (f.coloc && f.coloc.level === "near") p = Math.min(0.6, base + 0.08);
  const cost = f.reach ? Math.max(1, 6 - f.sev) : Math.max(1, 7 - f.sev);    // lower = easier for the attacker
  return { p: Math.round(p * 100) / 100, cost, heuristic: true };
}

// ---- Attack-tree synthesis --------------------------------------------------
export function buildTree(findings) {
  const byGoal = {};
  for (const f of findings) (byGoal[f.goal] = byGoal[f.goal] || []).push(f);
  const branches = Object.keys(byGoal).map((g) => {
    // Within a branch, confirmed-reachable leaves lead, then by severity.
    const items = byGoal[g].slice().sort((a, b) => (b.reach ? 1 : 0) - (a.reach ? 1 : 0) || b.sev - a.sev || a.line - b.line);
    const leaves = items.map((f) => ({ ...f, confirmed: !!f.reach, weight: edgeWeight(f) }));
    const maxSev = Math.max.apply(null, items.map((i) => i.sev));
    // OR-node: any leaf achieves the goal, so the path likelihood is their union (heuristic).
    const p = 1 - leaves.reduce((acc, l) => acc * (1 - l.weight.p), 1);
    const minCost = Math.min.apply(null, leaves.map((l) => l.weight.cost));
    return {
      goal: g, name: (GOALS[g] || { name: g }).name, short: (GOALS[g] || {}).short || g,
      sev: maxSev, confirmed: leaves.some((l) => l.confirmed), leaves,
      weight: { p: Math.round(p * 100) / 100, minCost, heuristic: true },
    };
  // Severity stays the primary order (preserves the documented invariant); a confirmed
  // branch, then a higher heuristic likelihood, break ties.
  }).sort((a, b) => b.sev - a.sev || (b.confirmed ? 1 : 0) - (a.confirmed ? 1 : 0) || b.weight.p - a.weight.p);
  return { root: "Compromise the application", branches };
}

// ---- Risk scoring -----------------------------------------------------------
export function riskScore(findings) {
  const w = { 5: 28, 4: 15, 3: 7, 2: 3, 1: 1 };
  let raw = 0; const by = { 5: 0, 4: 0, 3: 0, 2: 0, 1: 0 };
  // A taint-confirmed flow is the strongest evidence, so it weighs most; a high-confidence
  // lexical hit next; everything else at face value.
  for (const f of findings) { raw += w[f.sev] * (f.reach ? 1.5 : f.confidence === "high" ? 1.25 : 1); by[f.sev]++; }
  const score = Math.min(100, Math.round(raw));
  const grade = score >= 75 ? "F" : score >= 55 ? "D" : score >= 35 ? "C" : score >= 15 ? "B" : score > 0 ? "A" : "A+";
  return { score, grade, by };
}
