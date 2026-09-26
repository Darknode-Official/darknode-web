// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Hashing, checksum & validation mini-tools. See _schema.md for the contract.

// ---- MD4 (RFC 1320) — needed for NTLM, not exposed by Web Crypto ----
function md4(u8) {
  function rl(n, c) { return (n << c) | (n >>> (32 - c)); }
  function add(a, b) { const l = (a & 0xffff) + (b & 0xffff); return (((a >> 16) + (b >> 16) + (l >> 16)) << 16) | (l & 0xffff); }
  function F(x, y, z) { return (x & y) | (~x & z); }
  function G(x, y, z) { return (x & y) | (x & z) | (y & z); }
  function Hh(x, y, z) { return x ^ y ^ z; }
  function ff(a, b, c, d, x, s) { return rl(add(a, add(F(b, c, d), x)), s); }
  function gg(a, b, c, d, x, s) { return rl(add(a, add(add(G(b, c, d), x), 0x5a827999)), s); }
  function hh(a, b, c, d, x, s) { return rl(add(a, add(add(Hh(b, c, d), x), 0x6ed9eba1)), s); }
  const n = u8.length; const words = [];
  for (let i = 0; i < n; i++) words[i >> 2] = (words[i >> 2] || 0) | (u8[i] << ((i % 4) * 8));
  words[n >> 2] = (words[n >> 2] || 0) | (0x80 << ((n % 4) * 8));
  const bl = n * 8; const len = (((n + 8) >> 6) + 1) * 16;
  words[len - 2] = bl & 0xffffffff; words[len - 1] = Math.floor(bl / 0x100000000);
  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
  for (let i = 0; i < len; i += 16) {
    const oa = a, ob = b, oc = c, od = d; const x = (j) => words[i + j] || 0;
    a = ff(a, b, c, d, x(0), 3); d = ff(d, a, b, c, x(1), 7); c = ff(c, d, a, b, x(2), 11); b = ff(b, c, d, a, x(3), 19);
    a = ff(a, b, c, d, x(4), 3); d = ff(d, a, b, c, x(5), 7); c = ff(c, d, a, b, x(6), 11); b = ff(b, c, d, a, x(7), 19);
    a = ff(a, b, c, d, x(8), 3); d = ff(d, a, b, c, x(9), 7); c = ff(c, d, a, b, x(10), 11); b = ff(b, c, d, a, x(11), 19);
    a = ff(a, b, c, d, x(12), 3); d = ff(d, a, b, c, x(13), 7); c = ff(c, d, a, b, x(14), 11); b = ff(b, c, d, a, x(15), 19);
    a = gg(a, b, c, d, x(0), 3); d = gg(d, a, b, c, x(4), 5); c = gg(c, d, a, b, x(8), 9); b = gg(b, c, d, a, x(12), 13);
    a = gg(a, b, c, d, x(1), 3); d = gg(d, a, b, c, x(5), 5); c = gg(c, d, a, b, x(9), 9); b = gg(b, c, d, a, x(13), 13);
    a = gg(a, b, c, d, x(2), 3); d = gg(d, a, b, c, x(6), 5); c = gg(c, d, a, b, x(10), 9); b = gg(b, c, d, a, x(14), 13);
    a = gg(a, b, c, d, x(3), 3); d = gg(d, a, b, c, x(7), 5); c = gg(c, d, a, b, x(11), 9); b = gg(b, c, d, a, x(15), 13);
    a = hh(a, b, c, d, x(0), 3); d = hh(d, a, b, c, x(8), 9); c = hh(c, d, a, b, x(4), 11); b = hh(b, c, d, a, x(12), 15);
    a = hh(a, b, c, d, x(2), 3); d = hh(d, a, b, c, x(10), 9); c = hh(c, d, a, b, x(6), 11); b = hh(b, c, d, a, x(14), 15);
    a = hh(a, b, c, d, x(1), 3); d = hh(d, a, b, c, x(9), 9); c = hh(c, d, a, b, x(5), 11); b = hh(b, c, d, a, x(13), 15);
    a = hh(a, b, c, d, x(3), 3); d = hh(d, a, b, c, x(11), 9); c = hh(c, d, a, b, x(7), 11); b = hh(b, c, d, a, x(15), 15);
    a = add(a, oa); b = add(b, ob); c = add(c, oc); d = add(d, od);
  }
  const hex = (nn) => { let s = ""; for (let i = 0; i < 4; i++) s += ((nn >> (i * 8)) & 255).toString(16).padStart(2, "0"); return s; };
  return hex(a) + hex(b) + hex(c) + hex(d);
}
const toUTF16LE = (str) => { const buf = new Uint8Array(str.length * 2); for (let i = 0; i < str.length; i++) { const c = str.charCodeAt(i); buf[i * 2] = c & 0xff; buf[i * 2 + 1] = (c >> 8) & 0xff; } return buf; };

// ---- small checksum algorithms (inline, not in _helpers.js) ----
const adler32 = (str, H) => { const MOD = 65521; let a = 1, b = 0; const u = H.bytes(str); for (let i = 0; i < u.length; i++) { a = (a + u[i]) % MOD; b = (b + a) % MOD; } return (((b << 16) | a) >>> 0).toString(16).padStart(8, "0"); };
const crc32c = (str, H) => { const u = H.bytes(str); let c = 0xffffffff; for (let i = 0; i < u.length; i++) { c ^= u[i]; for (let k = 0; k < 8; k++) c = (c & 1) ? (0x82f63b78 ^ (c >>> 1)) : (c >>> 1); } return ((c ^ 0xffffffff) >>> 0).toString(16).padStart(8, "0"); };
const crc16ccitt = (str, H) => { const u = H.bytes(str); let crc = 0xffff; for (let i = 0; i < u.length; i++) { crc ^= (u[i] << 8); for (let j = 0; j < 8; j++) crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff; } return crc.toString(16).padStart(4, "0"); };
const crc8 = (str, H) => { const u = H.bytes(str); let crc = 0; for (let i = 0; i < u.length; i++) { crc ^= u[i]; for (let j = 0; j < 8; j++) crc = (crc & 0x80) ? ((crc << 1) ^ 0x07) & 0xff : (crc << 1) & 0xff; } return crc.toString(16).padStart(2, "0"); };
const fnv1a32 = (str, H) => { let h = 0x811c9dc5; const u = H.bytes(str); for (let i = 0; i < u.length; i++) { h ^= u[i]; h = Math.imul(h, 0x01000193); } return (h >>> 0).toString(16).padStart(8, "0"); };
const fnv1_32 = (str, H) => { let h = 0x811c9dc5; const u = H.bytes(str); for (let i = 0; i < u.length; i++) { h = Math.imul(h, 0x01000193); h ^= u[i]; } return (h >>> 0).toString(16).padStart(8, "0"); };
const djb2 = (str, H) => { let h = 5381; const u = H.bytes(str); for (let i = 0; i < u.length; i++) h = (Math.imul(h, 33) + u[i]) | 0; return (h >>> 0).toString(16).padStart(8, "0"); };
const sdbm = (str, H) => { let h = 0; const u = H.bytes(str); for (let i = 0; i < u.length; i++) h = (u[i] + (h << 6) + (h << 16) - h) | 0; return (h >>> 0).toString(16).padStart(8, "0"); };
function murmur3_32(str, seed, H) {
  const u = H.bytes(str); let h1 = seed >>> 0; const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  const len = u.length; const nblocks = len >> 2;
  for (let i = 0; i < nblocks; i++) {
    let k1 = (u[i * 4] | (u[i * 4 + 1] << 8) | (u[i * 4 + 2] << 16) | (u[i * 4 + 3] << 24));
    k1 = Math.imul(k1, c1); k1 = (k1 << 15) | (k1 >>> 17); k1 = Math.imul(k1, c2);
    h1 ^= k1; h1 = (h1 << 13) | (h1 >>> 19); h1 = (Math.imul(h1, 5) + 0xe6546b64) | 0;
  }
  let k1 = 0; const tail = nblocks * 4;
  switch (len & 3) {
    case 3: k1 ^= u[tail + 2] << 16;
    case 2: k1 ^= u[tail + 1] << 8;
    case 1: k1 ^= u[tail]; k1 = Math.imul(k1, c1); k1 = (k1 << 15) | (k1 >>> 17); k1 = Math.imul(k1, c2); h1 ^= k1;
  }
  h1 ^= len; h1 ^= h1 >>> 16; h1 = Math.imul(h1, 0x85ebca6b); h1 ^= h1 >>> 13; h1 = Math.imul(h1, 0xc2b2ae35); h1 ^= h1 >>> 16;
  return (h1 >>> 0).toString(16).padStart(8, "0");
}
const luhnSum = (digits) => { let sum = 0, alt = false; for (let i = digits.length - 1; i >= 0; i--) { let d = digits.charCodeAt(i) - 48; if (alt) { d *= 2; if (d > 9) d -= 9; } sum += d; alt = !alt; } return sum; };
const gtinCheck = (payload) => { let sum = 0; for (let i = 0; i < payload.length; i++) { const posFromRight = payload.length - i; const w = (posFromRight % 2 === 1) ? 3 : 1; sum += payload[i] * w; } return (10 - (sum % 10)) % 10; };

export const TOOLS = [
  { id: "h-md5", name: "MD5 Hash", cat: "hashing", desc: "Compute the MD5 digest of text (RFC 1321).", tags: ["md5", "digest"],
    run(v, H) { return v.text ? H.md5(v.text) : ""; },
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 6 }] },

  { id: "h-sha1", name: "SHA-1 Hash", cat: "hashing", desc: "Compute the SHA-1 digest of text.", tags: ["sha1", "digest"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 6 }],
    async run(v, H) { return v.text ? await H.sha1(v.text) : ""; } },

  { id: "h-sha256", name: "SHA-256 Hash", cat: "hashing", desc: "Compute the SHA-256 digest of text.", tags: ["sha256", "digest"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 6 }],
    async run(v, H) { return v.text ? await H.sha256(v.text) : ""; } },

  { id: "h-sha384", name: "SHA-384 Hash", cat: "hashing", desc: "Compute the SHA-384 digest of text.", tags: ["sha384", "digest"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 6 }],
    async run(v, H) { return v.text ? await H.sha384(v.text) : ""; } },

  { id: "h-sha512", name: "SHA-512 Hash", cat: "hashing", desc: "Compute the SHA-512 digest of text.", tags: ["sha512", "digest"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 6 }],
    async run(v, H) { return v.text ? await H.sha512(v.text) : ""; } },

  { id: "h-hash-all", name: "Hash All (MD5 / SHA-1 / SHA-256 / …)", cat: "hashing", desc: "Compute several digests of the same input at once.", tags: ["multi", "digest"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 6 }, { k: "extended", label: "Include SHA-384 / SHA-512", type: "checkbox", value: false }],
    async run(v, H) {
      if (!v.text) return "";
      const lines = [`MD5:      ${H.md5(v.text)}`, `SHA-1:    ${await H.sha1(v.text)}`, `SHA-256:  ${await H.sha256(v.text)}`, `CRC32:    ${H.crc32(v.text)}`];
      if (v.extended) { lines.push(`SHA-384:  ${await H.sha384(v.text)}`); lines.push(`SHA-512:  ${await H.sha512(v.text)}`); }
      return lines.join("\n");
    } },

  { id: "h-crc32", name: "CRC32 Checksum", cat: "hashing", desc: "Compute the CRC-32 (IEEE 802.3) checksum of text.", tags: ["crc", "checksum"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 6 }],
    run(v, H) { return v.text ? H.crc32(v.text) : ""; } },

  { id: "h-crc32c", name: "CRC32C (Castagnoli) Checksum", cat: "hashing", desc: "Compute CRC-32C using the Castagnoli polynomial (used by iSCSI, ext4, SCTP).", tags: ["crc", "castagnoli"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 6 }],
    run(v, H) { return v.text ? crc32c(v.text, H) : ""; } },

  { id: "h-crc16", name: "CRC16/CCITT Checksum", cat: "hashing", desc: "Compute the CRC-16/CCITT-FALSE checksum of text.", tags: ["crc", "checksum"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 6 }],
    run(v, H) { return v.text ? crc16ccitt(v.text, H) : ""; } },

  { id: "h-crc8", name: "CRC8 Checksum", cat: "hashing", desc: "Compute a CRC-8 (poly 0x07) checksum of text.", tags: ["crc", "checksum"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 6 }],
    run(v, H) { return v.text ? crc8(v.text, H) : ""; } },

  { id: "h-adler32", name: "Adler-32 Checksum", cat: "hashing", desc: "Compute the Adler-32 checksum used by zlib.", tags: ["adler32", "zlib", "checksum"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 6 }],
    run(v, H) { return v.text ? adler32(v.text, H) : ""; } },

  { id: "h-hmac", name: "HMAC Generator", cat: "hashing", desc: "Compute an HMAC of a message with a secret key using SHA-1/256/384/512.", tags: ["hmac", "mac", "key"],
    inputs: [{ k: "text", label: "Message", type: "textarea", rows: 5 }, { k: "key", label: "Secret key", type: "text", placeholder: "secret" }, { k: "algo", label: "Hash algorithm", type: "select", opts: ["SHA-1", "SHA-256", "SHA-384", "SHA-512"], value: "SHA-256" }],
    async run(v, H) { if (!v.text || !v.key) return ""; try { return await H.hmac(v.algo, v.key, v.text); } catch (e) { return { error: "Could not compute HMAC." }; } } },

  { id: "h-ntlm", name: "NTLM Hash", cat: "hashing", desc: "Compute the NTLM hash (MD4 of the UTF-16LE password) used by Windows/AD.", tags: ["ntlm", "windows", "md4"],
    inputs: [{ k: "text", label: "Password", type: "text", inputType: "password" }],
    run(v) { if (!v.text) return ""; return md4(toUTF16LE(v.text)).toUpperCase(); } },

  { id: "h-fnv1a-32", name: "FNV-1a Hash (32-bit)", cat: "hashing", desc: "Fowler–Noll–Vo 1a variant, 32-bit — fast non-cryptographic hash.", tags: ["fnv", "fnv1a", "non-crypto"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 4 }],
    run(v, H) { return v.text ? fnv1a32(v.text, H) : ""; } },

  { id: "h-fnv1-32", name: "FNV-1 Hash (32-bit)", cat: "hashing", desc: "Fowler–Noll–Vo original variant, 32-bit (multiply-then-xor).", tags: ["fnv", "fnv1", "non-crypto"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 4 }],
    run(v, H) { return v.text ? fnv1_32(v.text, H) : ""; } },

  { id: "h-djb2", name: "DJB2 Hash", cat: "hashing", desc: "Dan Bernstein's classic string hash (h = h*33 + c).", tags: ["djb2", "non-crypto"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 4 }],
    run(v, H) { return v.text ? djb2(v.text, H) : ""; } },

  { id: "h-sdbm", name: "SDBM Hash", cat: "hashing", desc: "The SDBM/gawk string hash function.", tags: ["sdbm", "non-crypto"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 4 }],
    run(v, H) { return v.text ? sdbm(v.text, H) : ""; } },

  { id: "h-murmur3-32", name: "MurmurHash3 (x86, 32-bit)", cat: "hashing", desc: "Compute MurmurHash3 32-bit with an optional seed.", tags: ["murmur", "murmur3", "non-crypto"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 4 }, { k: "seed", label: "Seed", type: "text", inputType: "number", value: "0" }],
    run(v, H) { if (!v.text) return ""; const seed = H.clampInt(v.seed, 0, 0xffffffff, 0); return murmur3_32(v.text, seed, H); } },

  { id: "h-hash-identifier", name: "Hash Type Identifier", cat: "hashing", desc: "Guess the likely algorithm(s) behind a hash string by its length, charset and prefix.", tags: ["identify", "guess"],
    inputs: [{ k: "hash", label: "Hash", type: "text", placeholder: "5f4dcc3b5aa765d61d8327deb882cf99" }],
    run(v) {
      if (!v.hash) return "";
      const h = v.hash.trim();
      const hexRe = /^[a-fA-F0-9]+$/;
      const candidates = [];
      if (/^\$2[abxy]?\$/.test(h)) candidates.push("bcrypt");
      else if (/^\$1\$/.test(h)) candidates.push("MD5 crypt (Unix)");
      else if (/^\$5\$/.test(h)) candidates.push("SHA-256 crypt (Unix)");
      else if (/^\$6\$/.test(h)) candidates.push("SHA-512 crypt (Unix)");
      else if (!hexRe.test(h) && h.length % 4 === 0 && /^[A-Za-z0-9+/]{20,}={0,2}$/.test(h)) candidates.push("Base64-encoded digest");
      if (hexRe.test(h)) {
        switch (h.length) {
          case 8: candidates.push("CRC32 / Adler-32"); break;
          case 16: candidates.push("MySQL323 / Half MD5"); break;
          case 32: candidates.push("MD5 / MD4 / NTLM / LM"); break;
          case 40: candidates.push("SHA-1 / MySQL5 / RIPEMD-160"); break;
          case 56: candidates.push("SHA-224 / SHA3-224"); break;
          case 64: candidates.push("SHA-256 / SHA3-256 / BLAKE2s"); break;
          case 96: candidates.push("SHA-384 / SHA3-384"); break;
          case 128: candidates.push("SHA-512 / SHA3-512 / Whirlpool"); break;
        }
      }
      if (!candidates.length) return { error: "Unrecognized hash format." };
      return `Length: ${h.length} chars\nLikely: ${candidates.join(", ")}`;
    } },

  { id: "h-bcrypt-info", name: "bcrypt Hash Parser", cat: "hashing", desc: "Parse a bcrypt hash ($2a$rounds$salt+hash) into its components.", tags: ["bcrypt", "parse"],
    inputs: [{ k: "hash", label: "bcrypt hash", type: "text", placeholder: "$2a$10$N9qo8uLOickgx2ZMRZoMye..." }],
    run(v) {
      if (!v.hash) return "";
      const m = /^\$(2[abxy]?)\$(\d{2})\$([./A-Za-z0-9]{53})$/.exec(v.hash.trim());
      if (!m) return { error: "Not a valid bcrypt hash ($2a$rounds$53-char-salt+hash)." };
      const [, variant, rounds, rest] = m;
      return `Algorithm: bcrypt (${variant})\nCost factor: ${parseInt(rounds, 10)} (2^${parseInt(rounds, 10)} iterations)\nSalt: ${rest.slice(0, 22)}\nHash: ${rest.slice(22)}`;
    } },

  

  { id: "h-luhn", name: "Luhn Checksum Validator", cat: "hashing", desc: "Validate any number (card, IMEI, etc.) against the Luhn (mod 10) algorithm.", tags: ["luhn", "mod10", "checksum"],
    inputs: [{ k: "number", label: "Number", type: "text", placeholder: "4111111111111111" }],
    run(v) { if (!v.number) return ""; const d = v.number.replace(/[^0-9]/g, ""); if (!d) return { error: "Enter digits." }; const sum = luhnSum(d); return `Digits: ${d}\nLuhn checksum digit: ${sum % 10}\nValid: ${sum % 10 === 0 ? "YES" : "NO"}`; } },

  { id: "h-cc-brand", name: "Credit Card Brand Detector", cat: "hashing", desc: "Detect card brand (Visa/Mastercard/Amex/Discover/…) by IIN prefix and check the Luhn digit.", tags: ["credit card", "iin", "bin"],
    inputs: [{ k: "number", label: "Card number", type: "text", inputType: "text", placeholder: "4111111111111111" }],
    run(v) {
      if (!v.number) return "";
      const d = v.number.replace(/[^0-9]/g, "");
      if (!d) return { error: "Enter a card number." };
      const rules = [["Visa", /^4\d{12}(\d{3})?(\d{3})?$/], ["Mastercard", /^(5[1-5]\d{14}|2(2[2-9]\d{12}|[3-6]\d{13}|7[01]\d{12}|720\d{12}))$/], ["American Express", /^3[47]\d{13}$/], ["Discover", /^6(011\d{12}|5\d{14}|4[4-9]\d{13})$/], ["Diners Club", /^3(0[0-5]\d{11}|[68]\d{12})$/], ["JCB", /^35\d{14}$/], ["UnionPay", /^62\d{14,17}$/]];
      const match = rules.find(([, re]) => re.test(d));
      const valid = luhnSum(d) % 10 === 0;
      return `Number: ${d}\nBrand: ${match ? match[0] : "Unknown"}\nLuhn valid: ${valid ? "YES" : "NO"}`;
    } },

  { id: "h-iban-validate", name: "IBAN Validator", cat: "hashing", desc: "Validate an IBAN using the ISO 7064 mod-97 checksum.", tags: ["iban", "bank", "mod97"],
    inputs: [{ k: "iban", label: "IBAN", type: "text", placeholder: "GB29 NWBK 6016 1331 9268 19" }],
    run(v) {
      if (!v.iban) return "";
      const s = v.iban.replace(/\s+/g, "").toUpperCase();
      if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return { error: "Not a plausible IBAN format." };
      const rearr = s.slice(4) + s.slice(0, 4);
      let expanded = "";
      for (const c of rearr) expanded += /[A-Z]/.test(c) ? (c.charCodeAt(0) - 55).toString() : c;
      let rem = 0;
      for (let i = 0; i < expanded.length; i++) rem = (rem * 10 + (expanded.charCodeAt(i) - 48)) % 97;
      return `IBAN: ${s.match(/.{1,4}/g).join(" ")}\nCountry: ${s.slice(0, 2)}\nCheck digits: ${s.slice(2, 4)}\nMod-97 remainder: ${rem}\nValid: ${rem === 1 ? "YES" : "NO"}`;
    } },

  { id: "h-isbn", name: "ISBN-10 / ISBN-13 Validator", cat: "hashing", desc: "Validate a book ISBN-10 or ISBN-13 checksum.", tags: ["isbn", "book"],
    inputs: [{ k: "isbn", label: "ISBN", type: "text", placeholder: "978-3-16-148410-0" }],
    run(v) {
      if (!v.isbn) return "";
      const s = v.isbn.replace(/[-\s]/g, "").toUpperCase();
      if (s.length === 10) {
        if (!/^\d{9}[\dX]$/.test(s)) return { error: "Not a valid ISBN-10 format." };
        let sum = 0; for (let i = 0; i < 10; i++) sum += (s[i] === "X" ? 10 : s.charCodeAt(i) - 48) * (10 - i);
        return `ISBN-10: ${s}\nValid: ${sum % 11 === 0 ? "YES" : "NO"}`;
      }
      if (s.length === 13) {
        if (!/^\d{13}$/.test(s)) return { error: "Not a valid ISBN-13 format." };
        let sum = 0; for (let i = 0; i < 13; i++) sum += (s.charCodeAt(i) - 48) * (i % 2 === 0 ? 1 : 3);
        return `ISBN-13: ${s}\nValid: ${sum % 10 === 0 ? "YES" : "NO"}`;
      }
      return { error: "ISBN must be 10 or 13 characters (digits, optional trailing X)." };
    } },

  { id: "h-upc-ean", name: "UPC/EAN/GTIN Check Digit", cat: "hashing", desc: "Compute or verify the GS1 check digit for UPC-A, EAN-8, EAN-13 or GTIN-14 codes.", tags: ["upc", "ean", "gtin", "barcode"],
    inputs: [{ k: "digits", label: "Digits", type: "text", placeholder: "036000291452" }, { k: "mode", label: "Mode", type: "select", opts: ["Verify (includes check digit)", "Compute (payload only)"], value: "Verify (includes check digit)" }],
    run(v) {
      if (!v.digits) return "";
      const s = v.digits.replace(/[^0-9]/g, "");
      if (!s) return { error: "Enter digits only (UPC-A, EAN-8, EAN-13, GTIN-14)." };
      const arr = s.split("").map(Number);
      if (v.mode.startsWith("Compute")) { const cd = gtinCheck(arr); return `Payload: ${s}\nCheck digit: ${cd}\nFull code: ${s}${cd}`; }
      if (arr.length < 2) return { error: "Enter the full code including its check digit." };
      const payload = arr.slice(0, -1); const given = arr[arr.length - 1]; const cd = gtinCheck(payload);
      return `Code: ${s}\nExpected check digit: ${cd}\nGiven check digit: ${given}\nValid: ${cd === given ? "YES" : "NO"}`;
    } },

  { id: "h-imei-validate", name: "IMEI Validator", cat: "hashing", desc: "Validate a 15-digit mobile device IMEI via the Luhn algorithm.", tags: ["imei", "mobile", "luhn"],
    inputs: [{ k: "imei", label: "IMEI", type: "text", placeholder: "490154203237518" }],
    run(v) {
      if (!v.imei) return "";
      const s = v.imei.replace(/[^0-9]/g, "");
      if (s.length !== 15) return { error: "IMEI must be 15 digits." };
      const valid = luhnSum(s) % 10 === 0;
      return `IMEI: ${s}\nTAC (device type): ${s.slice(0, 8)}\nSerial: ${s.slice(8, 14)}\nCheck digit: ${s.slice(14)}\nLuhn valid: ${valid ? "YES" : "NO"}`;
    } },

  { id: "h-vin-check", name: "VIN Check Digit Validator", cat: "hashing", desc: "Validate a 17-character vehicle VIN's ISO 3779 check digit (position 9).", tags: ["vin", "vehicle", "iso3779"],
    inputs: [{ k: "vin", label: "VIN", type: "text", placeholder: "1M8GDM9AXKP042788" }],
    run(v) {
      if (!v.vin) return "";
      const s = v.vin.trim().toUpperCase();
      if (s.length !== 17) return { error: "VIN must be 17 characters." };
      if (/[IOQ]/.test(s)) return { error: "VIN cannot contain the letters I, O, or Q." };
      const T = { A: 1, B: 2, C: 3, D: 4, E: 5, F: 6, G: 7, H: 8, J: 1, K: 2, L: 3, M: 4, N: 5, P: 7, R: 9, S: 2, T: 3, U: 4, V: 5, W: 6, X: 7, Y: 8, Z: 9, 0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9 };
      const W = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
      let sum = 0;
      for (let i = 0; i < 17; i++) { const val = T[s[i]]; if (val === undefined) return { error: `Invalid VIN character: ${s[i]}` }; sum += val * W[i]; }
      const rem = sum % 11; const expected = rem === 10 ? "X" : String(rem); const given = s[8];
      return `VIN: ${s}\nWMI: ${s.slice(0, 3)}\nCheck digit (pos 9): given "${given}", expected "${expected}"\nValid: ${given === expected ? "YES" : "NO"}`;
    } },

  { id: "h-verhoeff", name: "Verhoeff Checksum", cat: "hashing", desc: "Compute or verify a Verhoeff check digit (catches all single-digit and adjacent-transposition errors; used by Aadhaar).", tags: ["verhoeff", "checksum"],
    inputs: [{ k: "number", label: "Number", type: "text" }, { k: "mode", label: "Mode", type: "select", opts: ["Verify (includes check digit)", "Compute (payload only)"], value: "Verify (includes check digit)" }],
    run(v) {
      if (!v.number) return "";
      const s = v.number.replace(/[^0-9]/g, "");
      if (!s) return { error: "Enter digits only." };
      const d = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1], [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]];
      const p = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1], [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]];
      const inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];
      if (v.mode.startsWith("Compute")) {
        const digits = s.split("").reverse().map(Number);
        let c = 0; for (let i = 0; i < digits.length; i++) c = d[c][p[(i + 1) % 8][digits[i]]];
        const cd = inv[c];
        return `Payload: ${s}\nCheck digit: ${cd}\nFull number: ${s}${cd}`;
      }
      const digits = s.split("").reverse().map(Number);
      let c = 0; for (let i = 0; i < digits.length; i++) c = d[c][p[i % 8][digits[i]]];
      return `Number: ${s}\nVerhoeff checksum: ${c}\nValid: ${c === 0 ? "YES" : "NO"}`;
    } },

  { id: "h-password-entropy", name: "Password Entropy Estimator", cat: "hashing", desc: "Estimate a password's entropy in bits and a rough offline crack-time.", tags: ["password", "entropy", "strength"],
    inputs: [{ k: "password", label: "Password", type: "text", inputType: "password" }],
    run(v) {
      if (!v.password) return "";
      const pw = v.password; let pool = 0;
      if (/[a-z]/.test(pw)) pool += 26; if (/[A-Z]/.test(pw)) pool += 26; if (/[0-9]/.test(pw)) pool += 10; if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
      const bits = pw.length * Math.log2(pool || 1);
      const seconds = Math.pow(2, bits) / 1e10;
      const fmt = (sec) => { if (sec < 1) return "instant"; const units = [["years", 31536000], ["days", 86400], ["hours", 3600], ["minutes", 60], ["seconds", 1]]; for (const [name, size] of units) if (sec >= size) return `${(sec / size).toLocaleString(undefined, { maximumFractionDigits: 1 })} ${name}`; return `${sec.toFixed(1)} seconds`; };
      return `Length: ${pw.length}\nCharacter pool: ${pool}\nEntropy: ${bits.toFixed(1)} bits\nEst. crack time (10B guesses/sec offline attack): ${fmt(seconds)}`;
    } },

  { id: "h-hibp-prefix", name: "HIBP k-Anonymity Prefix", cat: "hashing", desc: "Compute the SHA-1 hash and k-anonymity prefix/suffix used to check a password against Have I Been Pwned without sending the full hash.", tags: ["hibp", "password", "sha1", "k-anonymity"],
    inputs: [{ k: "password", label: "Password", type: "text", inputType: "password" }],
    async run(v, H) {
      if (!v.password) return "";
      const hash = (await H.sha1(v.password)).toUpperCase();
      return `SHA-1: ${hash}\nk-Anonymity prefix (send this, 5 chars): ${hash.slice(0, 5)}\nSuffix to match locally: ${hash.slice(5)}\n\nQuery GET https://api.pwnedpasswords.com/range/${hash.slice(0, 5)} and look for the suffix above in the response. This tool makes no network calls itself.`;
    } },

  { id: "h-hash-compare", name: "Hash Comparator", cat: "hashing", desc: "Compare two hash strings for an exact (case-insensitive) match.", tags: ["compare", "diff", "verify"],
    inputs: [{ k: "a", label: "Hash A", type: "textarea", rows: 2 }, { k: "b", label: "Hash B", type: "textarea", rows: 2 }],
    run(v) {
      if (!v.a || !v.b) return "";
      const norm = (s) => s.trim().toLowerCase().replace(/\s+/g, "");
      const na = norm(v.a), nb = norm(v.b); const match = na === nb;
      return `Hash A: ${na} (${na.length} chars)\nHash B: ${nb} (${nb.length} chars)\nMatch: ${match ? "YES — identical" : "NO — hashes differ"}`;
    } },

  { id: "h-uuid-validate", name: "UUID Validator", cat: "hashing", desc: "Validate a UUID and identify its version and variant.", tags: ["uuid", "guid"],
    inputs: [{ k: "uuid", label: "UUID", type: "text", placeholder: "550e8400-e29b-41d4-a716-446655440000" }],
    run(v) {
      if (!v.uuid) return "";
      const s = v.uuid.trim().toLowerCase();
      const m = /^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$/.exec(s);
      if (!m) return { error: "Not a valid UUID format (8-4-4-4-12 hex)." };
      const verChar = m[3][0]; const variantChar = m[4][0];
      let variant = "Future (reserved)";
      if (/[89ab]/.test(variantChar)) variant = "RFC 4122 (standard)"; else if (/[0-7]/.test(variantChar)) variant = "NCS (reserved, backward compat)"; else if (/[cd]/.test(variantChar)) variant = "Microsoft (reserved)";
      const names = { 1: "time-based", 2: "DCE security", 3: "name-based (MD5)", 4: "random", 5: "name-based (SHA-1)", 6: "reordered time-based", 7: "Unix timestamp-based", 8: "custom" };
      const isNil = s === "00000000-0000-0000-0000-000000000000";
      return `UUID: ${s}\nVersion: ${verChar} (${names[verChar] || "unknown"})\nVariant: ${variant}\nNil UUID: ${isNil ? "YES" : "NO"}`;
    } },

  { id: "h-ulid-decode", name: "ULID Decoder", cat: "hashing", desc: "Decode a ULID's embedded 48-bit millisecond timestamp and randomness.", tags: ["ulid", "timestamp"],
    inputs: [{ k: "ulid", label: "ULID", type: "text", placeholder: "01ARZ3NDEKTSV4RRFFQ69G5FAV" }],
    run(v) {
      if (!v.ulid) return "";
      const s = v.ulid.trim().toUpperCase();
      if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(s)) return { error: "Not a valid ULID (26 Crockford-base32 characters)." };
      const ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
      let ms = 0; for (const c of s.slice(0, 10)) ms = ms * 32 + ALPHA.indexOf(c);
      if (!Number.isFinite(ms) || ms > 8.64e15) return { error: "Timestamp out of range." };
      return `ULID: ${s}\nTimestamp: ${ms} ms since epoch\nDate (UTC): ${new Date(ms).toISOString()}\nRandomness: ${s.slice(10)}`;
    } },

  { id: "h-simhash", name: "SimHash (Near-Duplicate Fingerprint)", cat: "hashing", desc: "Compute a 32-bit SimHash fingerprint of text for near-duplicate / fuzzy matching.", tags: ["simhash", "fuzzy", "similarity"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v, H) {
      if (!v.text) return "";
      const tokens = v.text.toLowerCase().match(/[a-z0-9]+/g);
      if (!tokens || !tokens.length) return { error: "No tokens found in input." };
      const freq = {}; for (const t of tokens) freq[t] = (freq[t] || 0) + 1;
      const BITS = 32; const vec = new Array(BITS).fill(0);
      for (const tok of Object.keys(freq)) {
        const w = freq[tok]; const h = fnv1a32(tok, H); const hv = parseInt(h, 16);
        for (let b = 0; b < BITS; b++) vec[b] += ((hv >>> b) & 1) ? w : -w;
      }
      let out = 0n; for (let b = 0; b < BITS; b++) if (vec[b] > 0) out |= (1n << BigInt(b));
      return `Tokens: ${tokens.length} (${Object.keys(freq).length} unique)\nSimHash (32-bit): 0x${out.toString(16).padStart(8, "0")}\nCompare two SimHashes' Hamming distance to detect near-duplicate text.`;
    } },
];
