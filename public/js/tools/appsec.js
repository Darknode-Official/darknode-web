// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Security & AppSec mini-tools (for authorized testing / defense).
// Pure client-side, dependency-free. See _schema.md. Offensive payload / command
// builders here are for AUTHORIZED penetration testing, CTFs and defense only.

const S = (v) => (v == null ? "" : String(v));

// ---- small shared helpers (module scope) ----
function b64urlBytes(u8) {
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// binary-safe base64 / base32 straight from bytes (H.fromBytes is UTF-8 lossy for binary)
function b64FromBytes(u8, url) {
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  let o = btoa(bin);
  if (url) o = o.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return o;
}
function base32FromBytes(u8) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, val = 0, out = "";
  for (let i = 0; i < u8.length; i++) {
    val = (val << 8) | u8[i];
    bits += 8;
    while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += A[(val << (5 - bits)) & 31];
  return out;
}

// base32 decode -> raw bytes (RFC 4648), for TOTP keys
function base32ToBytes(s) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const t = String(s).toUpperCase().replace(/=+$/, "").replace(/[^A-Z2-7]/g, "");
  let bits = 0, val = 0;
  const out = [];
  for (const c of t) {
    const idx = A.indexOf(c);
    if (idx < 0) continue;
    val = (val << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}

async function hmacBytes(hashName, keyBytes, msgBytes) {
  const k = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: hashName }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, msgBytes);
  return new Uint8Array(sig);
}

// IPv4 <-> integer
function ipToInt(str) {
  const m = String(str).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const o = [+m[1], +m[2], +m[3], +m[4]];
  for (const x of o) if (x > 255) return null;
  return ((o[0] * 16777216) + (o[1] << 16) + (o[2] << 8) + o[3]) >>> 0;
}
function intToIp(n) {
  n = n >>> 0;
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

function humanTime(seconds) {
  if (!isFinite(seconds)) return "effectively forever";
  if (seconds < 1) return "< 1 second";
  const units = [["year", 31557600], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
  for (const [name, s] of units) {
    if (seconds >= s) {
      const v = seconds / s;
      if (v >= 1e6) return `${v.toExponential(2)} ${name}s`;
      return `${(Math.round(v * 10) / 10)} ${name}${v >= 2 ? "s" : ""}`;
    }
  }
  return `${seconds} seconds`;
}

function charsetPool(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[ ]/.test(pw)) pool += 1;
  if (/[^A-Za-z0-9 ]/.test(pw)) pool += 33;
  return pool;
}

function randInt(maxExclusive) {
  const u = new Uint32Array(1);
  crypto.getRandomValues(u);
  return u[0] % maxExclusive;
}
function pick(arr) { return arr[randInt(arr.length)]; }

const PHRASE_WORDS = [
  "apple", "river", "mountain", "silver", "planet", "forest", "candle", "bridge", "meadow", "cactus",
  "orbit", "lantern", "harbor", "willow", "copper", "thunder", "velvet", "canyon", "ember", "glacier",
  "marble", "pepper", "saffron", "timber", "walnut", "zephyr", "anchor", "beacon", "cinder", "dagger",
  "falcon", "granite", "hollow", "ivory", "jungle", "kettle", "ladder", "maple", "nectar", "opal",
  "pebble", "quartz", "raven", "sunset", "tundra", "umber", "violet", "whisper", "yonder", "amber",
  "breeze", "clover", "dune", "echo", "fable", "grove", "haven", "iris", "jade", "koala",
];

export const TOOLS = [

  // 1
  { id: "sx-password-strength", name: "Password Strength Meter", cat: "appsec", desc: "Estimate a password's entropy (bits), give a rating and an offline crack-time estimate.", tags: ["password", "entropy", "strength", "crack time"],
    inputs: [{ k: "pw", label: "Password", type: "text", inputType: "password", placeholder: "correct horse battery" }],
    run(v) {
      const pw = S(v.pw);
      if (!pw) return "";
      const pool = charsetPool(pw);
      const bits = pool > 0 ? pw.length * Math.log2(pool) : 0;
      let rating = "Very weak";
      if (bits >= 128) rating = "Excellent";
      else if (bits >= 80) rating = "Strong";
      else if (bits >= 60) rating = "Good";
      else if (bits >= 40) rating = "Fair";
      else if (bits >= 28) rating = "Weak";
      const guesses = Math.pow(2, bits) / 2;
      const offline = humanTime(guesses / 1e10);
      const online = humanTime(guesses / 1e3);
      return `Length: ${pw.length}\nCharset pool: ${pool} symbols\nEntropy: ${bits.toFixed(1)} bits\nRating: ${rating}\n\nCrack time (offline, 10B guesses/s): ${offline}\nCrack time (online, 1k guesses/s):   ${online}`;
    } },

  // 2
  { id: "sx-password-entropy", name: "Password Entropy Calculator", cat: "appsec", desc: "Compute entropy bits from a chosen length and character-set size.", tags: ["entropy", "password", "bits"],
    inputs: [
      { k: "len", label: "Length", type: "range", min: 1, max: 128, step: 1, value: 16 },
      { k: "charset", label: "Character set", type: "select", opts: [["10", "Digits only (10)"], ["26", "Lowercase (26)"], ["52", "Mixed case (52)"], ["62", "Alphanumeric (62)"], ["95", "All printable ASCII (95)"]], value: "62" },
    ],
    run(v, H) {
      const len = H.clampInt(v.len, 1, 128, 16);
      const pool = H.clampInt(v.charset, 2, 95, 62);
      const bits = len * Math.log2(pool);
      const combos = Math.pow(pool, len);
      return `Length: ${len}\nCharset: ${pool}\nEntropy: ${bits.toFixed(1)} bits\nCombinations: ${combos < 1e15 ? combos.toLocaleString() : combos.toExponential(3)}`;
    } },

  // 3
  { id: "sx-password-generator", name: "Random Password Generator", cat: "appsec", desc: "Generate a cryptographically-random password with selectable character classes.", tags: ["password", "generator", "random"],
    inputs: [
      { k: "len", label: "Length", type: "range", min: 4, max: 128, step: 1, value: 20 },
      { k: "lower", label: "lowercase a-z", type: "checkbox", value: true },
      { k: "upper", label: "UPPERCASE A-Z", type: "checkbox", value: true },
      { k: "digits", label: "digits 0-9", type: "checkbox", value: true },
      { k: "symbols", label: "symbols !@#$%", type: "checkbox", value: true },
    ],
    run(v, H) {
      const len = H.clampInt(v.len, 4, 128, 20);
      let set = "";
      if (v.lower) set += "abcdefghijklmnopqrstuvwxyz";
      if (v.upper) set += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      if (v.digits) set += "0123456789";
      if (v.symbols) set += "!@#$%^&*()-_=+[]{};:,.<>?";
      if (!set) return { error: "Select at least one character class." };
      let out = "";
      for (let i = 0; i < len; i++) out += set[randInt(set.length)];
      return out;
    } },

  // 4
  { id: "sx-passphrase", name: "Passphrase Generator", cat: "appsec", desc: "Build a memorable multi-word passphrase from a built-in word list.", tags: ["passphrase", "diceware", "words"],
    inputs: [
      { k: "n", label: "Number of words", type: "range", min: 2, max: 12, step: 1, value: 4 },
      { k: "sep", label: "Separator", type: "select", opts: ["-", ".", "_", " ", ""], value: "-" },
      { k: "cap", label: "Capitalize each word", type: "checkbox", value: false },
      { k: "num", label: "Append a random number", type: "checkbox", value: true },
    ],
    run(v, H) {
      const n = H.clampInt(v.n, 2, 12, 4);
      const words = [];
      for (let i = 0; i < n; i++) {
        let w = pick(PHRASE_WORDS);
        if (v.cap) w = w[0].toUpperCase() + w.slice(1);
        words.push(w);
      }
      let out = words.join(v.sep == null ? "-" : v.sep);
      if (v.num) out += (v.sep || "") + randInt(100);
      return out;
    } },

  // 5
  { id: "sx-pin-generator", name: "PIN Generator", cat: "appsec", desc: "Generate a random numeric PIN of a chosen length.", tags: ["pin", "otp", "numeric", "random"],
    inputs: [
      { k: "len", label: "Digits", type: "range", min: 3, max: 12, step: 1, value: 6 },
      { k: "count", label: "How many", type: "range", min: 1, max: 20, step: 1, value: 1 },
    ],
    run(v, H) {
      const len = H.clampInt(v.len, 3, 12, 6);
      const count = H.clampInt(v.count, 1, 20, 1);
      const out = [];
      for (let c = 0; c < count; c++) {
        let p = "";
        for (let i = 0; i < len; i++) p += randInt(10);
        out.push(p);
      }
      return out.join("\n");
    } },

  // 7
  { id: "sx-jwt-none", name: "JWT alg:none Forge", cat: "appsec", desc: "Re-encode header+payload as an unsigned alg:none token to test missing signature verification (authorized testing).", tags: ["jwt", "alg none", "bypass"],
    inputs: [
      { k: "header", label: "Header JSON", type: "textarea", rows: 2, value: '{"alg":"none","typ":"JWT"}' },
      { k: "payload", label: "Payload JSON", type: "textarea", rows: 4, value: '{"sub":"admin","role":"admin"}' },
    ],
    run(v, H) {
      if (!v.header || !v.payload) return "";
      let h, p;
      try { h = JSON.parse(v.header); } catch (e) { return { error: "Header is not valid JSON." }; }
      try { p = JSON.parse(v.payload); } catch (e) { return { error: "Payload is not valid JSON." }; }
      if (!h || typeof h !== "object" || Array.isArray(h)) return { error: "Header must be a JSON object." };
      h.alg = h.alg && /none/i.test(h.alg) ? h.alg : "none";
      const h64 = b64urlBytes(H.bytes(JSON.stringify(h)));
      const p64 = b64urlBytes(H.bytes(JSON.stringify(p)));
      return `${h64}.${p64}.\n\n(trailing dot = empty signature; some libraries also accept it with the dot omitted)`;
    } },

  // 8
  { id: "sx-jwt-hs256-sign", name: "JWT HS256 Signer", cat: "appsec", desc: "Build and HS256-sign a JWT from a payload and secret for testing token-handling logic.", tags: ["jwt", "hs256", "hmac", "sign"],
    inputs: [
      { k: "payload", label: "Payload JSON", type: "textarea", rows: 4, value: '{"sub":"1234567890","name":"tester","iat":1700000000}' },
      { k: "secret", label: "Secret", type: "text", inputType: "password", placeholder: "supersecret" },
    ],
    async run(v, H) {
      if (!v.payload || !v.secret) return "";
      let p;
      try { p = JSON.parse(v.payload); } catch (e) { return { error: "Payload is not valid JSON." }; }
      const h64 = b64urlBytes(H.bytes(JSON.stringify({ alg: "HS256", typ: "JWT" })));
      const p64 = b64urlBytes(H.bytes(JSON.stringify(p)));
      const signing = `${h64}.${p64}`;
      const hex = await H.hmac("SHA-256", v.secret, signing);
      const sig = b64urlBytes(H.fromHex(hex));
      return `${signing}.${sig}`;
    } },

  // 10
  { id: "sx-htpasswd", name: "htpasswd Line", cat: "appsec", desc: "Build an Apache htpasswd entry using SHA-1 ({SHA}) or a plaintext variant.", tags: ["htpasswd", "apache", "sha1", "auth"],
    inputs: [
      { k: "user", label: "Username", type: "text", placeholder: "admin" },
      { k: "pass", label: "Password", type: "text", inputType: "password" },
      { k: "mode", label: "Scheme", type: "select", opts: [["sha", "{SHA} (base64 SHA-1)"], ["plain", "Plaintext"]], value: "sha" },
    ],
    async run(v, H) {
      if (!v.user || !v.pass) return "";
      if (v.user.includes(":")) return { error: "Username cannot contain ':'." };
      if (v.mode === "plain") return `${v.user}:${v.pass}`;
      const hex = await H.sha1(v.pass);
      const b64 = b64FromBytes(H.fromHex(hex), false);
      return `${v.user}:{SHA}${b64}`;
    } },

  // 11
  { id: "sx-bcrypt-cost", name: "bcrypt Cost Explainer", cat: "appsec", desc: "Explain a bcrypt cost factor: iterations and a rough hashes/sec estimate.", tags: ["bcrypt", "cost", "kdf", "apr1"],
    inputs: [{ k: "cost", label: "Cost factor", type: "range", min: 4, max: 20, step: 1, value: 12 }],
    run(v, H) {
      const cost = H.clampInt(v.cost, 4, 20, 12);
      const iters = Math.pow(2, cost);
      const baseHps = 1e5; // ~cost-4 baseline on a modern core
      const hps = baseHps / Math.pow(2, cost - 4);
      return `Cost factor: ${cost}\nKey-expansion rounds: 2^${cost} = ${iters.toLocaleString()}\nApprox hashes/sec (single core): ~${hps < 1 ? hps.toExponential(2) : Math.round(hps)}\nTime per hash: ~${(1 / hps).toFixed(4)} s\n\nApache MD5 apr1 uses 1000 iterations and is far weaker — prefer bcrypt (cost >= 12) or argon2id.`;
    } },

  // 14
  { id: "sx-ipv4-to-int", name: "IPv4 to Integer", cat: "appsec", desc: "Convert a dotted-quad IPv4 address to its 32-bit integer (decimal and hex).", tags: ["ipv4", "integer", "convert"],
    inputs: [{ k: "ip", label: "IPv4", type: "text", placeholder: "192.168.0.1" }],
    run(v) {
      if (!v.ip) return "";
      const n = ipToInt(v.ip);
      if (n == null) return { error: "Invalid IPv4 address." };
      return `Decimal: ${n}\nHex: 0x${n.toString(16).padStart(8, "0")}\nBinary: ${n.toString(2).padStart(32, "0").replace(/(.{8})(?=.)/g, "$1.")}`;
    } },

  // 15
  { id: "sx-int-to-ipv4", name: "Integer to IPv4", cat: "appsec", desc: "Convert a 32-bit integer (decimal or 0x-hex) to a dotted-quad IPv4 address.", tags: ["ipv4", "integer", "convert"],
    inputs: [{ k: "n", label: "Integer", type: "text", placeholder: "3232235521 or 0xC0A80001" }],
    run(v) {
      const raw = S(v.n).trim();
      if (!raw) return "";
      let n;
      if (/^0x[0-9a-f]+$/i.test(raw)) n = parseInt(raw, 16);
      else if (/^\d+$/.test(raw)) n = parseInt(raw, 10);
      else return { error: "Enter a decimal or 0x-hex integer." };
      if (!isFinite(n) || n < 0 || n > 4294967295) return { error: "Out of 32-bit range (0 - 4294967295)." };
      return intToIp(n >>> 0);
    } },

  // 16
  { id: "sx-ip-in-cidr", name: "IPv4 in CIDR Check", cat: "appsec", desc: "Test whether an IPv4 address falls within a given CIDR block.", tags: ["cidr", "contains", "match", "network"],
    inputs: [
      { k: "ip", label: "IPv4 address", type: "text", placeholder: "10.0.5.9" },
      { k: "cidr", label: "CIDR block", type: "text", placeholder: "10.0.0.0/16" },
    ],
    run(v) {
      if (!v.ip || !v.cidr) return "";
      const ip = ipToInt(v.ip);
      if (ip == null) return { error: "Invalid IPv4 address." };
      const m = S(v.cidr).trim().match(/^(.+)\/(\d{1,2})$/);
      if (!m) return { error: "CIDR must be IP/prefix." };
      const base = ipToInt(m[1]);
      const pfx = +m[2];
      if (base == null || pfx > 32) return { error: "Invalid CIDR." };
      const mask = pfx === 0 ? 0 : (0xffffffff << (32 - pfx)) >>> 0;
      const inside = ((ip & mask) >>> 0) === ((base & mask) >>> 0);
      return inside ? `YES — ${v.ip} is within ${v.cidr}` : `NO — ${v.ip} is NOT within ${v.cidr}`;
    } },

  // 17
  { id: "sx-mask-prefix", name: "Netmask / Prefix Converter", cat: "appsec", desc: "Convert between a dotted netmask (255.255.255.0) and a prefix length (/24).", tags: ["netmask", "prefix", "subnet"],
    inputs: [{ k: "in", label: "Netmask or /prefix", type: "text", placeholder: "255.255.255.0 or 24" }],
    run(v) {
      const raw = S(v.in).trim().replace(/^\//, "");
      if (!raw) return "";
      if (/^\d{1,2}$/.test(raw)) {
        const pfx = +raw;
        if (pfx > 32) return { error: "Prefix must be 0-32." };
        const mask = pfx === 0 ? 0 : (0xffffffff << (32 - pfx)) >>> 0;
        return `/${pfx}  ->  ${intToIp(mask)}`;
      }
      const n = ipToInt(raw);
      if (n == null) return { error: "Enter a netmask or a prefix length." };
      // count contiguous leading ones
      const bin = n.toString(2).padStart(32, "0");
      if (!/^1*0*$/.test(bin)) return { error: "Not a valid contiguous netmask." };
      return `${intToIp(n)}  ->  /${(bin.match(/^1*/)[0]).length}`;
    } },

  // 18
  { id: "sx-wildcard-mask", name: "Wildcard Mask from Prefix", cat: "appsec", desc: "Produce the inverse (wildcard) mask used by ACLs from a prefix or netmask.", tags: ["wildcard", "acl", "mask", "cisco"],
    inputs: [{ k: "in", label: "Prefix or netmask", type: "text", placeholder: "24 or 255.255.255.0" }],
    run(v) {
      const raw = S(v.in).trim().replace(/^\//, "");
      if (!raw) return "";
      let mask;
      if (/^\d{1,2}$/.test(raw)) {
        const pfx = +raw;
        if (pfx > 32) return { error: "Prefix must be 0-32." };
        mask = pfx === 0 ? 0 : (0xffffffff << (32 - pfx)) >>> 0;
      } else {
        mask = ipToInt(raw);
        if (mask == null) return { error: "Invalid netmask." };
      }
      const wild = (~mask) >>> 0;
      return `Netmask:  ${intToIp(mask)}\nWildcard: ${intToIp(wild)}`;
    } },

  // 20
  { id: "sx-ipv6", name: "IPv6 Expand / Compress", cat: "appsec", desc: "Expand an IPv6 address to full form or compress it to shorthand.", tags: ["ipv6", "expand", "compress"],
    inputs: [
      { k: "addr", label: "IPv6 address", type: "text", placeholder: "2001:db8::1" },
      { k: "mode", label: "Mode", type: "select", opts: ["Expand", "Compress"], value: "Expand" },
    ],
    run(v) {
      let a = S(v.addr).trim();
      if (!a) return "";
      // embedded IPv4 tail (::ffff:192.0.2.1) -> two hex groups
      const m4 = a.match(/^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/);
      if (m4) { const o = m4[2].split(".").map(Number); if (o.some((x) => x > 255)) return { error: "Invalid embedded IPv4 address." }; a = m4[1] + ((o[0] << 8) | o[1]).toString(16) + ":" + ((o[2] << 8) | o[3]).toString(16); }
      if (!/^[0-9a-fA-F:]+$/.test(a) || (a.match(/::/g) || []).length > 1) return { error: "Invalid IPv6 address." };
      let groups;
      if (a.includes("::")) {
        const [l, r] = a.split("::");
        const lp = l ? l.split(":") : [];
        const rp = r ? r.split(":") : [];
        const fill = 8 - lp.length - rp.length;
        if (fill < 1) return { error: "Too many groups." };
        if (lp.includes("") || rp.includes("")) return { error: "Invalid IPv6 address: empty group (stray colon)." };
        groups = lp.concat(Array(fill).fill("0"), rp);
      } else {
        groups = a.split(":");
        if (groups.length !== 8) return { error: "Full IPv6 needs 8 groups." };
        if (groups.includes("")) return { error: "Invalid IPv6 address: empty group (stray colon)." };
      }
      groups = groups.map((g) => g === "" ? "0" : g);
      for (const g of groups) if (g.length > 4) return { error: "Group has more than 4 hex digits." };
      const full = groups.map((g) => g.padStart(4, "0").toLowerCase());
      if (v.mode === "Expand") return full.join(":");
      // compress longest zero run
      const g = full.map((x) => x.replace(/^0+(?=.)/, ""));
      let best = -1, bestLen = 0, run = -1, runLen = 0;
      for (let i = 0; i < 8; i++) {
        if (g[i] === "0") { if (run < 0) run = i; runLen++; if (runLen > bestLen) { bestLen = runLen; best = run; } }
        else { run = -1; runLen = 0; }
      }
      if (bestLen > 1) { const head = g.slice(0, best).join(":"); const tail = g.slice(best + bestLen).join(":"); return head + "::" + tail; }
      return g.join(":");
    } },

  // 22
  { id: "sx-hash-string", name: "Hash a String", cat: "appsec", desc: "Hash text with MD5, SHA-1, SHA-256 or SHA-512.", tags: ["hash", "md5", "sha256", "digest"],
    inputs: [
      { k: "text", label: "Input", type: "textarea", rows: 3 },
      { k: "algo", label: "Algorithm", type: "select", opts: ["MD5", "SHA-1", "SHA-256", "SHA-512"], value: "SHA-256" },
    ],
    async run(v, H) {
      if (!v.text) return "";
      switch (v.algo) {
        case "MD5": return H.md5(v.text);
        case "SHA-1": return await H.sha1(v.text);
        case "SHA-512": return await H.sha512(v.text);
        default: return await H.sha256(v.text);
      }
    } },

  // 23
  { id: "sx-hmac", name: "HMAC Generator", cat: "appsec", desc: "Compute an HMAC over a message with a chosen key and hash algorithm.", tags: ["hmac", "mac", "sign", "sha"],
    inputs: [
      { k: "algo", label: "Hash", type: "select", opts: [["SHA-1", "HMAC-SHA1"], ["SHA-256", "HMAC-SHA256"], ["SHA-384", "HMAC-SHA384"], ["SHA-512", "HMAC-SHA512"]], value: "SHA-256" },
      { k: "key", label: "Key", type: "text", inputType: "password", placeholder: "secret key" },
      { k: "msg", label: "Message", type: "textarea", rows: 3 },
    ],
    async run(v, H) {
      if (!v.key || !v.msg) return "";
      return await H.hmac(v.algo, v.key, v.msg);
    } },

  // 25
  { id: "sx-default-creds", name: "Default Credentials Lookup", cat: "appsec", desc: "Search a built-in list of well-known vendor/device default credentials (for authorized audits).", tags: ["default", "credentials", "vendor", "audit"],
    inputs: [{ k: "q", label: "Search vendor/device", type: "text", placeholder: "cisco, tomcat, router..." }],
    run(v) {
      const list = [
        ["Cisco (IOS)", "cisco", "cisco"], ["Cisco (enable)", "-", "cisco"], ["D-Link router", "admin", "(blank)"],
        ["Netgear router", "admin", "password"], ["Linksys router", "admin", "admin"], ["TP-Link router", "admin", "admin"],
        ["Ubiquiti UniFi", "ubnt", "ubnt"], ["MikroTik RouterOS", "admin", "(blank)"], ["pfSense", "admin", "pfsense"],
        ["Apache Tomcat manager", "tomcat", "tomcat"], ["Apache Tomcat", "admin", "admin"], ["Jenkins", "admin", "admin"],
        ["MySQL", "root", "(blank)"], ["PostgreSQL", "postgres", "postgres"], ["MongoDB", "(none)", "(none - open)"],
        ["Redis", "(none)", "(none - open)"], ["Oracle DB", "system", "manager"], ["MSSQL", "sa", "(blank)"],
        ["Grafana", "admin", "admin"], ["Kibana/Elastic", "elastic", "changeme"], ["RabbitMQ", "guest", "guest"],
        ["phpMyAdmin", "root", "(blank)"], ["Webmin", "admin", "admin"], ["Zabbix", "Admin", "zabbix"],
        ["Nagios", "nagiosadmin", "nagios"], ["Tomcat host-manager", "admin", "changethis"], ["Splunk", "admin", "changeme"],
        ["VMware ESXi", "root", "(set at install)"], ["Raspberry Pi (old)", "pi", "raspberry"], ["Zyxel router", "admin", "1234"],
        ["Axis IP camera", "root", "pass"], ["Hikvision camera", "admin", "12345"],
      ];
      const q = S(v.q).trim().toLowerCase();
      const rows = q ? list.filter((r) => r[0].toLowerCase().includes(q)) : list;
      if (!rows.length) return `No match for "${v.q}". Showing all is possible by clearing the search.`;
      return rows.map((r) => `${r[0].padEnd(26)}  user=${r[1]}  pass=${r[2]}`).join("\n") + "\n\n(For authorized audits only — change all defaults.)";
    } },

  // 26
  { id: "sx-headers-checklist", name: "Security Headers Checklist", cat: "appsec", desc: "Paste raw response headers to see which recommended security headers are missing.", tags: ["headers", "http", "hardening", "csp"],
    inputs: [{ k: "hdr", label: "Raw response headers", type: "textarea", rows: 8, placeholder: "content-type: text/html\nx-frame-options: DENY\n..." }],
    run(v) {
      if (!v.hdr) return "";
      const present = new Set(S(v.hdr).split(/\r?\n/).map((l) => l.split(":")[0].trim().toLowerCase()).filter(Boolean));
      const rec = [
        ["content-security-policy", "Restrict resource origins (XSS/clickjacking defense)"],
        ["strict-transport-security", "Force HTTPS (HSTS)"],
        ["x-content-type-options", "nosniff — stop MIME sniffing"],
        ["x-frame-options", "Clickjacking defense (or use CSP frame-ancestors)"],
        ["referrer-policy", "Limit referrer leakage"],
        ["permissions-policy", "Restrict powerful browser features"],
        ["cross-origin-opener-policy", "Isolate browsing context (COOP)"],
        ["cross-origin-resource-policy", "Restrict cross-origin embedding (CORP)"],
        ["cache-control", "Prevent caching of sensitive responses"],
      ];
      const missing = rec.filter(([h]) => !present.has(h));
      const ok = rec.filter(([h]) => present.has(h)).map(([h]) => h);
      let out = `Present (${ok.length}/${rec.length}): ${ok.join(", ") || "none"}\n\nMISSING:\n`;
      out += missing.length ? missing.map(([h, why]) => `  - ${h}: ${why}`).join("\n") : "  (none — all recommended headers present)";
      return out;
    } },

  // 27
  { id: "sx-tls-versions", name: "TLS Version Explainer", cat: "appsec", desc: "Show the status and guidance for each SSL/TLS protocol version.", tags: ["tls", "ssl", "protocol", "deprecated"],
    inputs: [{ k: "ver", label: "Version", type: "select", opts: ["All", "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"], value: "All" }],
    run(v) {
      const info = {
        "SSLv2": "INSECURE — broken (DROWN). Disable entirely.",
        "SSLv3": "INSECURE — POODLE. Deprecated by RFC 7568. Disable.",
        "TLS 1.0": "DEPRECATED (RFC 8996) — BEAST/weak ciphers. Disable.",
        "TLS 1.1": "DEPRECATED (RFC 8996) — no modern AEAD. Disable.",
        "TLS 1.2": "OK — still widely acceptable if configured with AEAD ciphers + PFS.",
        "TLS 1.3": "RECOMMENDED — modern AEAD only, forward secrecy by default, faster handshake.",
      };
      if (v.ver === "All") return Object.entries(info).map(([k, d]) => `${k.padEnd(9)} ${d}`).join("\n");
      return `${v.ver}: ${info[v.ver] || "unknown"}`;
    } },

  // 28
  { id: "sx-cipher-suite", name: "Cipher Suite Explainer", cat: "appsec", desc: "Parse a TLS_* cipher suite name into key exchange, authentication, encryption and MAC.", tags: ["cipher", "tls", "suite", "aead"],
    inputs: [{ k: "cs", label: "Cipher suite", type: "text", placeholder: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" }],
    run(v) {
      const name = S(v.cs).trim().toUpperCase();
      if (!name) return "";
      if (!name.startsWith("TLS_")) return { error: "Expected an IANA name starting with TLS_." };
      const body = name.slice(4);
      if (!body.includes("_WITH_")) {
        // TLS 1.3 style: TLS_AES_128_GCM_SHA256
        const p = body.split("_");
        const mac = p[p.length - 1];
        return `TLS 1.3 suite\n  Key exchange: negotiated separately (ECDHE / DHE)\n  Cipher: ${p.slice(0, -1).join("_")}\n  Hash (HKDF/PRF): ${mac}`;
      }
      const [kxAuth, rest] = body.split("_WITH_");
      const ka = kxAuth.split("_");
      let kx = ka[0], auth = ka[1] || ka[0];
      const rp = rest.split("_");
      const mac = rp[rp.length - 1];
      const enc = rp.slice(0, -1).join("_");
      const aead = /GCM|CCM|CHACHA20/.test(enc);
      return `Key exchange: ${kx}\nAuthentication: ${auth}\nEncryption: ${enc}${aead ? " (AEAD)" : ""}\nMAC/PRF hash: ${mac}\nForward secrecy: ${/ECDHE|DHE/.test(kx) ? "yes" : "no"}`;
    } },

  // 29
  { id: "sx-hsts-parser", name: "HSTS Header Parser", cat: "appsec", desc: "Parse a Strict-Transport-Security header and flag weak settings.", tags: ["hsts", "header", "tls"],
    inputs: [{ k: "h", label: "HSTS header value", type: "text", placeholder: "max-age=63072000; includeSubDomains; preload" }],
    run(v) {
      let s = S(v.h).trim();
      if (!s) return "";
      s = s.replace(/^strict-transport-security:\s*/i, "");
      // RFC 6797 6.1: directive names are case-insensitive, a value may be a quoted-string
      // (max-age="31536000" was read as missing), and a repeated directive makes the browser
      // ignore the whole header
      const dirs = {}, dup = [];
      for (const part of s.split(";").map((x) => x.trim()).filter(Boolean)) {
        const m = part.match(/^([^=\s]+)\s*(?:=\s*(.*))?$/);
        if (!m) continue;
        const k = m[1].toLowerCase();
        if (Object.hasOwn(dirs, k)) dup.push(m[1]); else dirs[k] = m[2] == null ? "" : m[2].trim().replace(/^"(.*)"$/, "$1");
      }
      const maxAge = /^\d+$/.test(dirs["max-age"] ?? "") ? +dirs["max-age"] : null;
      const sub = Object.hasOwn(dirs, "includesubdomains");
      const preload = Object.hasOwn(dirs, "preload");
      const out = [];
      if (dup.length) out.push(`INVALID: ${dup.join(", ")} appears more than once, so browsers ignore this header entirely (RFC 6797 6.1).\n`);
      out.push(`max-age: ${maxAge == null ? (Object.hasOwn(dirs, "max-age") ? `"${dirs["max-age"]}" (invalid)` : "MISSING (invalid)") : maxAge + " s (" + (maxAge / 86400).toFixed(0) + " days)"}`);
      out.push(`includeSubDomains: ${sub ? "yes" : "no"}`);
      out.push(`preload: ${preload ? "yes" : "no"}`);
      const warn = [];
      if (maxAge == null) warn.push(Object.hasOwn(dirs, "max-age") ? "max-age is not a whole number of seconds — header is invalid." : "No max-age — header is invalid.");
      else if (maxAge === 0) warn.push("max-age=0 tells the browser to forget HSTS for this host (used to turn HSTS off).");
      else if (maxAge < 31536000) warn.push("max-age < 1 year; preload lists require >= 31536000.");
      if (!sub) warn.push("Without includeSubDomains, subdomains are unprotected.");
      if (preload && (!sub || (maxAge || 0) < 31536000)) warn.push("preload requires includeSubDomains + max-age >= 1 year.");
      if (warn.length) out.push("\nWarnings:\n  - " + warn.join("\n  - "));
      return out.join("\n");
    } },

  // 31
  { id: "sx-xss-cheatsheet", name: "XSS Payload Cheatsheet", cat: "appsec", desc: "Context-aware XSS payloads (HTML, attribute, JS, URL) for authorized testing.", tags: ["xss", "payload", "cheatsheet", "context"],
    inputs: [{ k: "ctx", label: "Injection context", type: "select", opts: ["HTML body", "HTML attribute", "JavaScript string", "URL / href"], value: "HTML body" }],
    run(v) {
      const p = {
        "HTML body": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>"],
        "HTML attribute": ["\" onmouseover=alert(1) x=\"", "' onfocus=alert(1) autofocus='", "\"><script>alert(1)</script>", "\" onerror=alert(1) src=x \""],
        "JavaScript string": ["';alert(1);//", "\";alert(1);//", "</script><script>alert(1)</script>", "\\';alert(1);//"],
        "URL / href": ["javascript:alert(1)", "javascript:alert(document.domain)", "data:text/html,<script>alert(1)</script>", "  javascript:alert(1)"],
      };
      return (p[v.ctx] || []).join("\n") + "\n\n(Authorized testing only.)";
    } },

  // 37
  { id: "sx-double-url-encode", name: "Double URL-encode", cat: "appsec", desc: "URL-encode a payload twice (WAF/filter bypass testing).", tags: ["url", "double encode", "bypass"],
    inputs: [{ k: "text", label: "Payload", type: "textarea", rows: 3 }],
    run(v) {
      if (!v.text) return "";
      return encodeURIComponent(encodeURIComponent(v.text));
    } },

  // 39
  { id: "sx-unicode-bypass", name: "Unicode/UTF-8 Bypass Encoder", cat: "appsec", desc: "Encode a payload as JS \\u, HTML entities, percent-UTF-8 or fullwidth homoglyphs.", tags: ["unicode", "utf-8", "bypass", "encode"],
    inputs: [
      { k: "text", label: "Payload", type: "textarea", rows: 3 },
      { k: "mode", label: "Encoding", type: "select", opts: [["ju", "JavaScript \\u escapes"], ["html", "HTML numeric entities"], ["pct", "Percent-encoded UTF-8"], ["fw", "Fullwidth homoglyphs"]], value: "ju" },
    ],
    run(v) {
      const s = S(v.text);
      if (!s) return "";
      const chars = Array.from(s);
      if (v.mode === "ju") return chars.map((c) => { const cp = c.codePointAt(0); return cp > 0xffff ? "\\u{" + cp.toString(16) + "}" : "\\u" + cp.toString(16).padStart(4, "0"); }).join("");
      if (v.mode === "html") return chars.map((c) => "&#" + c.codePointAt(0) + ";").join("");
      if (v.mode === "pct") return Array.from(new TextEncoder().encode(s)).map((b) => "%" + b.toString(16).toUpperCase().padStart(2, "0")).join("");
      // fullwidth: map printable ASCII 0x21-0x7E to 0xFF01-0xFF5E
      return chars.map((c) => { const cp = c.codePointAt(0); return (cp >= 0x21 && cp <= 0x7e) ? String.fromCodePoint(cp - 0x21 + 0xff01) : c; }).join("");
    } },

  // 40
  { id: "sx-hex-escape", name: "Hex-escape a Payload", cat: "appsec", desc: "Escape each byte of a payload as \\xNN, \\u00NN or 0xNN.", tags: ["hex", "escape", "payload"],
    inputs: [
      { k: "text", label: "Payload", type: "textarea", rows: 3 },
      { k: "fmt", label: "Format", type: "select", opts: [["x", "\\xNN"], ["u", "\\u00NN"], ["0x", "0xNN,0xNN"], ["percent", "%NN"]], value: "x" },
    ],
    run(v, H) {
      const s = S(v.text);
      if (!s) return "";
      const bytes = H.bytes(s);
      const hx = (b) => b.toString(16).padStart(2, "0");
      if (v.fmt === "x") return Array.from(bytes, (b) => "\\x" + hx(b)).join("");
      if (v.fmt === "u") return Array.from(bytes, (b) => "\\u00" + hx(b)).join("");
      if (v.fmt === "percent") return Array.from(bytes, (b) => "%" + hx(b).toUpperCase()).join("");
      return Array.from(bytes, (b) => "0x" + hx(b)).join(",");
    } },

  // 41
  { id: "sx-xss-mutator", name: "XSS Filter-Evasion Mutator", cat: "appsec", desc: "Apply case, comment and encoding tricks to an XSS payload to test filters.", tags: ["xss", "evasion", "waf", "mutate"],
    inputs: [
      { k: "text", label: "Payload", type: "text", placeholder: "<script>alert(1)</script>" },
      { k: "trick", label: "Trick", type: "select", opts: [["case", "aLtErNaTiNg case"], ["comment", "Insert HTML comments"], ["nullbyte", "Null-byte in tag"], ["entity", "Entity-encode brackets"], ["nospace", "Slash instead of spaces"]], value: "case" },
    ],
    run(v) {
      const s = S(v.text);
      if (!s) return "";
      switch (v.trick) {
        case "case": return Array.from(s).map((c, i) => i % 2 ? c.toUpperCase() : c.toLowerCase()).join("");
        case "comment": return s.replace(/<(\/?)(\w+)/g, "<$1$2<!---->").replace("<!---->", "");
        case "nullbyte": return s.replace(/<script/gi, "<scri\x00pt");
        case "entity": return s.replace(/</g, "&lt;").replace(/>/g, "&gt;");
        case "nospace": return s.replace(/ /g, "/");
        default: return s;
      }
    } },

  // 42
  { id: "sx-ua-list", name: "User-Agent List", cat: "appsec", desc: "Common browser and scanner User-Agent strings for testing.", tags: ["user-agent", "ua", "scanner", "header"],
    inputs: [{ k: "kind", label: "Kind", type: "select", opts: ["Browsers", "Scanners/Tools", "Bots"], value: "Browsers" }],
    run(v) {
      const data = {
        "Browsers": [
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
          "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
        ],
        "Scanners/Tools": ["sqlmap/1.8", "Nmap Scripting Engine", "Nikto/2.5.0", "curl/8.5.0", "python-requests/2.31.0", "Wfuzz/3.1", "gobuster/3.6", "Burp Suite Professional"],
        "Bots": ["Googlebot/2.1 (+http://www.google.com/bot.html)", "bingbot/2.0", "Mozilla/5.0 (compatible; AhrefsBot/7.0)", "facebookexternalhit/1.1"],
      };
      return (data[v.kind] || []).join("\n");
    } },

  // 43
  { id: "sx-path-wordlist", name: "Secret-path Wordlist", cat: "appsec", desc: "Common sensitive/hidden paths for content discovery on authorized targets.", tags: ["wordlist", "paths", "discovery", "robots"],
    inputs: [{ k: "grp", label: "Group", type: "select", opts: ["Admin/Auth", "Config/Secrets", "Backup/VCS", "API/Debug"], value: "Config/Secrets" }],
    run(v) {
      const data = {
        "Admin/Auth": ["/admin", "/administrator", "/login", "/wp-admin", "/phpmyadmin", "/manager/html", "/console", "/dashboard"],
        "Config/Secrets": ["/.env", "/config.php", "/wp-config.php", "/settings.py", "/.aws/credentials", "/.ssh/id_rsa", "/robots.txt", "/.well-known/security.txt"],
        "Backup/VCS": ["/.git/config", "/.git/HEAD", "/.svn/entries", "/backup.zip", "/db.sql", "/.DS_Store", "/index.php.bak", "/web.config.bak"],
        "API/Debug": ["/api", "/api/v1", "/swagger.json", "/openapi.json", "/graphql", "/actuator/env", "/debug", "/phpinfo.php"],
      };
      return (data[v.grp] || []).join("\n");
    } },

  // 44
  { id: "sx-totp-secret", name: "TOTP Secret Generator", cat: "appsec", desc: "Generate a random Base32 TOTP shared secret of a chosen strength.", tags: ["totp", "2fa", "secret", "base32"],
    inputs: [{ k: "bytes", label: "Entropy", type: "select", opts: [["10", "80-bit (16 chars)"], ["20", "160-bit (32 chars, recommended)"], ["32", "256-bit (52 chars)"]], value: "20" }],
    run(v, H) {
      const n = H.clampInt(v.bytes, 10, 32, 20);
      const secret = base32FromBytes(H.randBytes(n));
      return secret;
    } },

  // 45
  { id: "sx-totp-code", name: "TOTP Code Generator", cat: "appsec", desc: "Compute an RFC 6238 TOTP code from a Base32 secret at the current or a given time.", tags: ["totp", "2fa", "otp", "rfc6238"],
    inputs: [
      { k: "secret", label: "Base32 secret", type: "text", inputType: "password", placeholder: "JBSWY3DPEHPK3PXP" },
      { k: "digits", label: "Digits", type: "select", opts: ["6", "8"], value: "6" },
      { k: "period", label: "Period (s)", type: "select", opts: ["30", "60"], value: "30" },
      { k: "time", label: "Unix time (blank = now)", type: "text", placeholder: "(now)" },
    ],
    async run(v, H) {
      const secret = S(v.secret).trim();
      if (!secret) return "";
      const key = base32ToBytes(secret);
      if (!key.length) return { error: "Invalid Base32 secret." };
      const digits = v.digits === "8" ? 8 : 6;
      const period = v.period === "60" ? 60 : 30;
      const now = S(v.time).trim() ? parseInt(v.time, 10) : Math.floor(Date.now() / 1000);
      if (!isFinite(now)) return { error: "Invalid Unix time." };
      let counter = Math.floor(now / period);
      const msg = new Uint8Array(8);
      for (let i = 7; i >= 0; i--) { msg[i] = counter & 0xff; counter = Math.floor(counter / 256); }
      const hs = await hmacBytes("SHA-1", key, msg);
      const off = hs[hs.length - 1] & 0x0f;
      const bin = ((hs[off] & 0x7f) << 24) | (hs[off + 1] << 16) | (hs[off + 2] << 8) | hs[off + 3];
      const code = (bin % Math.pow(10, digits)).toString().padStart(digits, "0");
      const remain = period - (now % period);
      return `${code}\n\nValid for ~${remain}s (period ${period}s, ${digits} digits)`;
    } },

  // 46
  { id: "sx-otpauth-uri", name: "otpauth:// URI Builder", cat: "appsec", desc: "Build a Google-Authenticator-compatible otpauth:// URI for a TOTP secret.", tags: ["otpauth", "totp", "qr", "2fa"],
    inputs: [
      { k: "issuer", label: "Issuer", type: "text", placeholder: "ACME Corp" },
      { k: "account", label: "Account", type: "text", placeholder: "test@darknode.ai" },
      { k: "secret", label: "Base32 secret", type: "text", inputType: "password" },
      { k: "digits", label: "Digits", type: "select", opts: ["6", "8"], value: "6" },
      { k: "period", label: "Period", type: "select", opts: ["30", "60"], value: "30" },
    ],
    run(v) {
      if (!v.secret || !v.account) return "";
      const secret = S(v.secret).trim().replace(/=+$/, "").replace(/\s+/g, "");
      if (!/^[A-Za-z2-7]+$/.test(secret)) return { error: "Secret must be Base32 (A-Z, 2-7)." };
      const issuer = S(v.issuer).trim();
      const label = issuer ? `${encodeURIComponent(issuer)}:${encodeURIComponent(v.account)}` : encodeURIComponent(v.account);
      const q = [`secret=${secret}`, `algorithm=SHA1`, `digits=${v.digits}`, `period=${v.period}`];
      if (issuer) q.push(`issuer=${encodeURIComponent(issuer)}`);
      return `otpauth://totp/${label}?${q.join("&")}`;
    } },

  // 47
  { id: "sx-api-key", name: "API Key Generator", cat: "appsec", desc: "Generate a random API key with an optional prefix.", tags: ["api key", "token", "generator", "random"],
    inputs: [
      { k: "prefix", label: "Prefix", type: "text", placeholder: "sk_live" },
      { k: "bytes", label: "Random bytes", type: "range", min: 8, max: 48, step: 1, value: 24 },
      { k: "fmt", label: "Format", type: "select", opts: [["b64url", "base64url"], ["hex", "hex"]], value: "b64url" },
    ],
    run(v, H) {
      const n = H.clampInt(v.bytes, 8, 48, 24);
      const rnd = H.randBytes(n);
      const body = v.fmt === "hex" ? H.toHex(rnd) : b64FromBytes(rnd, true);
      const pfx = S(v.prefix).trim();
      return pfx ? `${pfx}_${body}` : body;
    } },

  // 48
  { id: "sx-uuid-token", name: "UUID Token Generator", cat: "appsec", desc: "Generate one or more random v4 UUIDs.", tags: ["uuid", "guid", "token", "v4"],
    inputs: [
      { k: "count", label: "How many", type: "range", min: 1, max: 50, step: 1, value: 1 },
      { k: "upper", label: "Uppercase", type: "checkbox", value: false },
      { k: "braces", label: "Wrap in { }", type: "checkbox", value: false },
    ],
    run(v, H) {
      const count = H.clampInt(v.count, 1, 50, 1);
      const out = [];
      for (let i = 0; i < count; i++) {
        let u = H.uuid();
        if (v.upper) u = u.toUpperCase();
        if (v.braces) u = `{${u}}`;
        out.push(u);
      }
      return out.join("\n");
    } },

  // 49
  { id: "sx-nonce", name: "Nonce / Salt / Token Generator", cat: "appsec", desc: "Generate cryptographically random bytes for a nonce, salt, CSRF token or API secret, in hex, base64 or base64url.", tags: ["nonce", "csp", "iv", "random", "salt", "csrf", "token", "secret"],
    inputs: [
      { k: "bytes", label: "Bytes", type: "range", min: 4, max: 128, step: 1, value: 16 },
      { k: "fmt", label: "Format", type: "select", opts: [["b64", "base64"], ["hex", "hex"], ["b64url", "base64url"]], value: "b64" },
    ],
    run(v, H) {
      const n = H.clampInt(v.bytes, 4, 128, 16);
      const rnd = H.randBytes(n);
      if (v.fmt === "hex") return H.toHex(rnd);
      return b64FromBytes(rnd, v.fmt === "b64url");
    } },

  // 54
  { id: "sx-phonetic", name: "Phonetic Speller (NATO)", cat: "appsec", desc: "Spell a password/token using the NATO phonetic alphabet for safe verbal readout.", tags: ["nato", "phonetic", "spell", "readback"],
    inputs: [{ k: "text", label: "Text", type: "text", placeholder: "Ab3!" }],
    run(v) {
      const s = S(v.text);
      if (!s) return "";
      const nato = { a: "Alfa", b: "Bravo", c: "Charlie", d: "Delta", e: "Echo", f: "Foxtrot", g: "Golf", h: "Hotel", i: "India", j: "Juliett", k: "Kilo", l: "Lima", m: "Mike", n: "November", o: "Oscar", p: "Papa", q: "Quebec", r: "Romeo", s: "Sierra", t: "Tango", u: "Uniform", v: "Victor", w: "Whiskey", x: "Xray", y: "Yankee", z: "Zulu" };
      const digits = { "0": "Zero", "1": "One", "2": "Two", "3": "Three", "4": "Four", "5": "Five", "6": "Six", "7": "Seven", "8": "Eight", "9": "Niner" };
      const sym = { "!": "Exclamation", "@": "At", "#": "Hash", "$": "Dollar", "%": "Percent", "^": "Caret", "&": "Ampersand", "*": "Asterisk", "-": "Dash", "_": "Underscore", "=": "Equals", "+": "Plus", ".": "Dot", " ": "Space" };
      return Array.from(s).map((c) => {
        const lc = c.toLowerCase();
        if (nato[lc]) return (c === c.toUpperCase() && /[a-z]/i.test(c)) ? `${nato[lc]} (CAP)` : `${nato[lc]} (lower)`;
        if (digits[c]) return digits[c];
        return sym[c] || `'${c}'`;
      }).join(" - ");
    } },

  // 55
  { id: "sx-entropy-bytes", name: "Byte Entropy (hex/text)", cat: "appsec", desc: "Compute Shannon entropy over bytes (bits/byte) to gauge randomness of a key or blob.", tags: ["entropy", "randomness", "bytes", "hex"],
    inputs: [
      { k: "data", label: "Data", type: "textarea", rows: 3 },
      { k: "mode", label: "Interpret as", type: "select", opts: ["Text (UTF-8)", "Hex"], value: "Text (UTF-8)" },
    ],
    run(v, H) {
      const raw = S(v.data);
      if (!raw) return "";
      let bytes;
      if (v.mode === "Hex") {
        if (!/^[0-9a-fA-F\s]+$/.test(raw)) return { error: "Hex mode needs hex digits only." };
        bytes = H.fromHex(raw);
      } else bytes = H.bytes(raw);
      if (!bytes.length) return { error: "No bytes to measure." };
      const freq = new Array(256).fill(0);
      for (const b of bytes) freq[b]++;
      let H2 = 0;
      for (const f of freq) if (f) { const p = f / bytes.length; H2 -= p * Math.log2(p); }
      return `Bytes: ${bytes.length}\nShannon entropy: ${H2.toFixed(4)} bits/byte (max 8)\nTotal: ${(H2 * bytes.length).toFixed(1)} bits\nRandomness: ${(H2 / 8 * 100).toFixed(1)}% of ideal`;
    } },

  // 56
  { id: "sx-shannon", name: "Shannon Entropy Calculator", cat: "appsec", desc: "Compute the Shannon entropy of a string over its character symbols, with the frequency table.", tags: ["shannon", "entropy", "text", "frequency"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 3 }],
    run(v) {
      const s = S(v.text);
      if (!s) return "";
      const chars = Array.from(s);
      const freq = new Map();
      for (const c of chars) freq.set(c, (freq.get(c) || 0) + 1);
      let H = 0;
      for (const f of freq.values()) { const p = f / chars.length; H -= p * Math.log2(p); }
      const table = [...freq.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([c, f]) => `  ${JSON.stringify(c)}: ${f} (${(f / chars.length * 100).toFixed(1)}%)`).join("\n");
      return `Symbols: ${chars.length}, unique: ${freq.size}\nEntropy: ${H.toFixed(4)} bits/symbol\nTotal information: ${(H * chars.length).toFixed(1)} bits\n\nTop frequencies:\n${table}`;
    } },

  // 57
  { id: "sx-b64-cred", name: "Base64 Credential Builder", cat: "appsec", desc: "Build a base64(user:pass) blob (e.g. for HTTP Basic auth) and its decode.", tags: ["base64", "credential", "basic auth"],
    inputs: [
      { k: "user", label: "Username", type: "text", placeholder: "admin" },
      { k: "pass", label: "Password", type: "text", inputType: "password" },
      { k: "mode", label: "Direction", type: "select", opts: ["Encode user:pass", "Decode base64"], value: "Encode user:pass" },
      { k: "blob", label: "Base64 or Authorization header (for decode)", type: "text", placeholder: "YWRtaW46cGFzcw==" },
    ],
    run(v, H) {
      if (v.mode === "Decode base64") {
        const blob = S(v.blob).trim().replace(/^Authorization:\s*/i, "").replace(/^Basic\s+/i, "");
        if (!blob) return "";
        let dec;
        try { dec = H.b64decode(blob); } catch (e) { return { error: "Invalid base64." }; }
        const i = dec.indexOf(":");
        return i < 0 ? `${dec}\n\nusername: ${dec}\npassword: (none)` : `${dec}\n\nusername: ${dec.slice(0, i)}\npassword: ${dec.slice(i + 1)}`;
      }
      if (!v.user && !v.pass) return "";
      if (S(v.user).includes(":")) return { error: "Username cannot contain ':'." };
      return H.b64encode(`${S(v.user)}:${S(v.pass)}`);
    } },

  // 58
  { id: "sx-email-obfuscate", name: "Email Obfuscator", cat: "appsec", desc: "Obfuscate an email address to resist scrapers (entities, [at]/[dot], or hex).", tags: ["email", "obfuscate", "anti-scrape", "entities"],
    inputs: [
      { k: "email", label: "Email", type: "text", placeholder: "you@example.com" },
      { k: "mode", label: "Method", type: "select", opts: [["at", "[at] / [dot] words"], ["entity", "HTML numeric entities"], ["hexentity", "HTML hex entities"], ["rot", "ROT13 (reversible)"]], value: "at" },
    ],
    run(v) {
      const e = S(v.email).trim();
      if (!e) return "";
      switch (v.mode) {
        case "at": return e.replace(/@/g, " [at] ").replace(/\./g, " [dot] ");
        case "entity": return Array.from(e).map((c) => "&#" + c.codePointAt(0) + ";").join("");
        case "hexentity": return Array.from(e).map((c) => "&#x" + c.codePointAt(0).toString(16) + ";").join("");
        case "rot": return e.replace(/[a-z]/gi, (c) => String.fromCharCode((c <= "Z" ? 90 : 122) >= (c.charCodeAt(0) + 13) ? c.charCodeAt(0) + 13 : c.charCodeAt(0) - 13));
        default: return e;
      }
    } },

  // 59
  { id: "sx-basic-auth-header", name: "HTTP Basic Auth Header", cat: "appsec", desc: "Build an Authorization: Basic header from a username and password.", tags: ["basic auth", "authorization", "header", "http"],
    inputs: [
      { k: "user", label: "Username", type: "text", placeholder: "admin" },
      { k: "pass", label: "Password", type: "text", inputType: "password" },
    ],
    run(v, H) {
      if (!v.user && !v.pass) return "";
      if (S(v.user).includes(":")) return { error: "Username cannot contain ':'." };
      const token = H.b64encode(`${S(v.user)}:${S(v.pass)}`);
      return `Authorization: Basic ${token}`;
    } },

  // 65
  { id: "sx-luhn", name: "Luhn Validator / Generator", cat: "appsec", desc: "Validate a number's Luhn checksum or generate a valid check digit (test data / cards).", tags: ["luhn", "checksum", "credit card", "validate"],
    inputs: [
      { k: "num", label: "Number", type: "text", placeholder: "4111111111111111" },
      { k: "mode", label: "Mode", type: "select", opts: ["Validate", "Compute check digit"], value: "Validate" },
    ],
    run(v) {
      const digits = S(v.num).replace(/\D/g, "");
      if (!digits) return "";
      const luhn = (d) => { let sum = 0, alt = false; for (let i = d.length - 1; i >= 0; i--) { let n = +d[i]; if (alt) { n *= 2; if (n > 9) n -= 9; } sum += n; alt = !alt; } return sum % 10; };
      if (v.mode === "Validate") {
        const ok = luhn(digits) === 0;
        return `${digits}\nLuhn checksum: ${ok ? "VALID" : "INVALID"}`;
      }
      // compute the digit that makes it valid (treat input as the number without check digit)
      const check = (10 - luhn(digits + "0")) % 10;
      return `Base: ${digits}\nCheck digit: ${check}\nFull: ${digits}${check}`;
    } },

];
