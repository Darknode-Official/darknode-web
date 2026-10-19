// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Shared helpers for the mini-tools registry. Pure, dependency-free, browser-safe.
// Tool run() functions receive this object as their second argument: (vals, H).

const te = new TextEncoder();
const td = new TextDecoder();

// ---- bytes / text ----
const bytes = (s) => te.encode(String(s));
const fromBytes = (u8) => td.decode(u8 instanceof Uint8Array ? u8 : new Uint8Array(u8));
const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => { const s = String(h).replace(/[^0-9a-fA-F]/g, ""); const u = new Uint8Array(s.length >> 1); for (let i = 0; i < u.length; i++) u[i] = parseInt(s.substr(i * 2, 2), 16); return u; };

// ---- base64 (unicode-safe) ----
const b64encode = (s, { url = false } = {}) => { let bin = ""; const u = bytes(s); for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]); let o = btoa(bin); if (url) o = o.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); return o; };
const b64decode = (s, { url = false } = {}) => { let t = String(s).trim(); if (url) t = t.replace(/-/g, "+").replace(/_/g, "/"); t = t.replace(/\s+/g, ""); while (t.length % 4) t += "="; const bin = atob(t); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return fromBytes(u); };

// ---- base32 (RFC 4648) ----
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const base32encode = (s) => { const u = bytes(s); let bits = 0, val = 0, out = ""; for (let i = 0; i < u.length; i++) { val = (val << 8) | u[i]; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) out += B32[(val << (5 - bits)) & 31]; while (out.length % 8) out += "="; return out; };
const base32decode = (s) => { const t = String(s).toUpperCase().replace(/=+$/, "").replace(/\s+/g, ""); let bits = 0, val = 0; const out = []; for (const c of t) { const idx = B32.indexOf(c); if (idx < 0) continue; val = (val << 5) | idx; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } } return fromBytes(new Uint8Array(out)); };

// ---- base58 (Bitcoin alphabet) ----
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const base58encode = (s) => { let u = bytes(s); let zeros = 0; while (zeros < u.length && u[zeros] === 0) zeros++; const digits = [0]; for (let i = zeros; i < u.length; i++) { let carry = u[i]; for (let j = 0; j < digits.length; j++) { carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0; } while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; } } let out = "1".repeat(zeros); for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]]; return zeros === u.length ? "1".repeat(zeros) : out; };

// ---- hashing ----
async function sha(algo, s) { const buf = await crypto.subtle.digest(algo, bytes(s)); return toHex(new Uint8Array(buf)); }
const sha1 = (s) => sha("SHA-1", s);
const sha256 = (s) => sha("SHA-256", s);
const sha384 = (s) => sha("SHA-384", s);
const sha512 = (s) => sha("SHA-512", s);
async function hmac(algo, key, msg) { const k = await crypto.subtle.importKey("raw", bytes(key), { name: "HMAC", hash: algo }, false, ["sign"]); const sig = await crypto.subtle.sign("HMAC", k, bytes(msg)); return toHex(new Uint8Array(sig)); }

// ---- MD5 (sync, RFC 1321) ----
function md5(str) {
  function rl(n, c) { return (n << c) | (n >>> (32 - c)); }
  function add(a, b) { const l = (a & 0xffff) + (b & 0xffff); return (((a >> 16) + (b >> 16) + (l >> 16)) << 16) | (l & 0xffff); }
  function cmn(q, a, b, x, s, t) { return add(rl(add(add(a, q), add(x, t)), s), b); }
  function ff(a, b, c, d, x, s, t) { return cmn((b & c) | (~b & d), a, b, x, s, t); }
  function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & ~d), a, b, x, s, t); }
  function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
  function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | ~d), a, b, x, s, t); }
  const u = bytes(str); const n = u.length; const words = [];
  for (let i = 0; i < n; i++) words[i >> 2] = (words[i >> 2] || 0) | (u[i] << ((i % 4) * 8));
  words[n >> 2] = (words[n >> 2] || 0) | (0x80 << ((n % 4) * 8));
  const bl = n * 8; const len = (((n + 8) >> 6) + 1) * 16; words[len - 2] = bl & 0xffffffff; words[len - 1] = Math.floor(bl / 0x100000000);
  let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
  const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  for (let i = 0; i < len; i += 16) {
    const oa = a, ob = b, oc = c, od = d; const x = (j) => words[i + j] || 0;
    a = ff(a, b, c, d, x(0), S[0], -680876936); d = ff(d, a, b, c, x(1), S[1], -389564586); c = ff(c, d, a, b, x(2), S[2], 606105819); b = ff(b, c, d, a, x(3), S[3], -1044525330);
    a = ff(a, b, c, d, x(4), S[0], -176418897); d = ff(d, a, b, c, x(5), S[1], 1200080426); c = ff(c, d, a, b, x(6), S[2], -1473231341); b = ff(b, c, d, a, x(7), S[3], -45705983);
    a = ff(a, b, c, d, x(8), S[0], 1770035416); d = ff(d, a, b, c, x(9), S[1], -1958414417); c = ff(c, d, a, b, x(10), S[2], -42063); b = ff(b, c, d, a, x(11), S[3], -1990404162);
    a = ff(a, b, c, d, x(12), S[0], 1804603682); d = ff(d, a, b, c, x(13), S[1], -40341101); c = ff(c, d, a, b, x(14), S[2], -1502002290); b = ff(b, c, d, a, x(15), S[3], 1236535329);
    a = gg(a, b, c, d, x(1), S[4], -165796510); d = gg(d, a, b, c, x(6), S[5], -1069501632); c = gg(c, d, a, b, x(11), S[6], 643717713); b = gg(b, c, d, a, x(0), S[7], -373897302);
    a = gg(a, b, c, d, x(5), S[4], -701558691); d = gg(d, a, b, c, x(10), S[5], 38016083); c = gg(c, d, a, b, x(15), S[6], -660478335); b = gg(b, c, d, a, x(4), S[7], -405537848);
    a = gg(a, b, c, d, x(9), S[4], 568446438); d = gg(d, a, b, c, x(14), S[5], -1019803690); c = gg(c, d, a, b, x(3), S[6], -187363961); b = gg(b, c, d, a, x(8), S[7], 1163531501);
    a = gg(a, b, c, d, x(13), S[4], -1444681467); d = gg(d, a, b, c, x(2), S[5], -51403784); c = gg(c, d, a, b, x(7), S[6], 1735328473); b = gg(b, c, d, a, x(12), S[7], -1926607734);
    a = hh(a, b, c, d, x(5), S[8], -378558); d = hh(d, a, b, c, x(8), S[9], -2022574463); c = hh(c, d, a, b, x(11), S[10], 1839030562); b = hh(b, c, d, a, x(14), S[11], -35309556);
    a = hh(a, b, c, d, x(1), S[8], -1530992060); d = hh(d, a, b, c, x(4), S[9], 1272893353); c = hh(c, d, a, b, x(7), S[10], -155497632); b = hh(b, c, d, a, x(10), S[11], -1094730640);
    a = hh(a, b, c, d, x(13), S[8], 681279174); d = hh(d, a, b, c, x(0), S[9], -358537222); c = hh(c, d, a, b, x(3), S[10], -722521979); b = hh(b, c, d, a, x(6), S[11], 76029189);
    a = hh(a, b, c, d, x(9), S[8], -640364487); d = hh(d, a, b, c, x(12), S[9], -421815835); c = hh(c, d, a, b, x(15), S[10], 530742520); b = hh(b, c, d, a, x(2), S[11], -995338651);
    a = ii(a, b, c, d, x(0), S[12], -198630844); d = ii(d, a, b, c, x(7), S[13], 1126891415); c = ii(c, d, a, b, x(14), S[14], -1416354905); b = ii(b, c, d, a, x(5), S[15], -57434055);
    a = ii(a, b, c, d, x(12), S[12], 1700485571); d = ii(d, a, b, c, x(3), S[13], -1894986606); c = ii(c, d, a, b, x(10), S[14], -1051523); b = ii(b, c, d, a, x(1), S[15], -2054922799);
    a = ii(a, b, c, d, x(8), S[12], 1873313359); d = ii(d, a, b, c, x(15), S[13], -30611744); c = ii(c, d, a, b, x(6), S[14], -1560198380); b = ii(b, c, d, a, x(13), S[15], 1309151649);
    a = ii(a, b, c, d, x(4), S[12], -145523070); d = ii(d, a, b, c, x(11), S[13], -1120210379); c = ii(c, d, a, b, x(2), S[14], 718787259); b = ii(b, c, d, a, x(9), S[15], -343485551);
    a = add(a, oa); b = add(b, ob); c = add(c, oc); d = add(d, od);
  }
  const hex = (n) => { let s = ""; for (let i = 0; i < 4; i++) s += ((n >> (i * 8)) & 255).toString(16).padStart(2, "0"); return s; };
  return hex(a) + hex(b) + hex(c) + hex(d);
}

// ---- CRC32 ----
const CRC_TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = (s) => { const u = bytes(s); let c = 0xffffffff; for (let i = 0; i < u.length; i++) c = CRC_TABLE[(c ^ u[i]) & 255] ^ (c >>> 8); return ((c ^ 0xffffffff) >>> 0).toString(16).padStart(8, "0"); };

// ---- misc ----
const randBytes = (n) => { const u = new Uint8Array(n); crypto.getRandomValues(u); return u; };
const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : (() => { const u = randBytes(16); u[6] = (u[6] & 0x0f) | 0x40; u[8] = (u[8] & 0x3f) | 0x80; const h = toHex(u); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`; })());
const clampInt = (v, lo, hi, dflt) => { const n = parseInt(v, 10); if (isNaN(n)) return dflt; return Math.max(lo, Math.min(hi, n)); };
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export const H = {
  te, td, bytes, fromBytes, toHex, fromHex,
  b64encode, b64decode, base32encode, base32decode, base58encode,
  sha, sha1, sha256, sha384, sha512, hmac, md5, crc32,
  randBytes, uuid, clampInt, escapeHtml,
};
