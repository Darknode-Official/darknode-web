// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Shared helpers for the mini-tools registry. Pure, dependency-free, browser-safe.
// Tool run() functions receive this object as their second argument: (vals, H).

const te = new TextEncoder();
const td = new TextDecoder();

// ---- bytes / text ----
const bytes = (s) => te.encode(String(s));
const fromBytes = (u8) => td.decode(u8 instanceof Uint8Array ? u8 : new Uint8Array(u8));
// Decoded bytes as text when they are valid UTF-8, else as hex with a note (a lossy decode would
// turn every non-text byte into U+FFFD and hide the data).
const textOrHex = (u8) => { try { return new TextDecoder("utf-8", { fatal: true }).decode(u8); } catch (_) { return "(not UTF-8 text - " + u8.length + " bytes as hex)\n" + Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join(" "); } };
const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
// strict like netproto's hexBytes: 0x / \x prefixes and separators are fine, other characters or an odd digit count throw
const fromHex = (h) => { const s = String(h).replace(/0x|\\x/gi, "").replace(/[\s:.,_-]/g, ""); if (/[^0-9a-fA-F]/.test(s)) throw new Error("Not valid hex: use 0-9 and a-f only (spaces and colons are fine)."); if (s.length % 2) throw new Error("Hex has an odd number of digits; each byte is two digits."); const u = new Uint8Array(s.length >> 1); for (let i = 0; i < u.length; i++) u[i] = parseInt(s.substr(i * 2, 2), 16); return u; };

// ---- base64 (unicode-safe) ----
const b64encode = (s, { url = false } = {}) => { let bin = ""; const u = bytes(s); for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]); let o = btoa(bin); if (url) o = o.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); return o; };
const b64bytes = (s, { url = false } = {}) => { let t = String(s).trim(); if (url) t = t.replace(/-/g, "+").replace(/_/g, "/"); t = t.replace(/\s+/g, ""); while (t.length % 4) t += "="; const bin = atob(t); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; };
const b64decode = (s, opts) => fromBytes(b64bytes(s, opts));

// ---- base32 (RFC 4648) ----
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const base32encode = (s) => { const u = bytes(s); let bits = 0, val = 0, out = ""; for (let i = 0; i < u.length; i++) { val = (val << 8) | u[i]; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) out += B32[(val << (5 - bits)) & 31]; while (out.length % 8) out += "="; return out; };
const base32bytes = (s) => { const t = String(s).toUpperCase().replace(/=+$/, "").replace(/\s+/g, ""); let bits = 0, val = 0; const out = []; for (const c of t) { const idx = B32.indexOf(c); if (idx < 0) throw new Error("not Base32: " + c); val = (val << 5) | idx; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } } return new Uint8Array(out); };
const base32decode = (s) => fromBytes(base32bytes(s));

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

// HTML character references as an HTML5 parser decodes them in text: the HTML 4 named set
// (plus apos), the legacy names browsers accept without a semicolon (&copy, &amp), numeric
// references with or without ";", 128-159 read as Windows-1252 (&#150; is an en dash), and
// 0 / surrogates / > U+10FFFF as U+FFFD.
const ENT4 = "quot:22 amp:26 lt:3c gt:3e nbsp:a0 iexcl:a1 cent:a2 pound:a3 curren:a4 yen:a5 brvbar:a6 sect:a7 uml:a8 copy:a9 ordf:aa laquo:ab not:ac shy:ad reg:ae macr:af deg:b0 plusmn:b1 sup2:b2 sup3:b3 acute:b4 micro:b5 para:b6 middot:b7 cedil:b8 sup1:b9 ordm:ba raquo:bb frac14:bc frac12:bd frac34:be iquest:bf Agrave:c0 Aacute:c1 Acirc:c2 Atilde:c3 Auml:c4 Aring:c5 AElig:c6 Ccedil:c7 Egrave:c8 Eacute:c9 Ecirc:ca Euml:cb Igrave:cc Iacute:cd Icirc:ce Iuml:cf ETH:d0 Ntilde:d1 Ograve:d2 Oacute:d3 Ocirc:d4 Otilde:d5 Ouml:d6 times:d7 Oslash:d8 Ugrave:d9 Uacute:da Ucirc:db Uuml:dc Yacute:dd THORN:de szlig:df agrave:e0 aacute:e1 acirc:e2 atilde:e3 auml:e4 aring:e5 aelig:e6 ccedil:e7 egrave:e8 eacute:e9 ecirc:ea euml:eb igrave:ec iacute:ed icirc:ee iuml:ef eth:f0 ntilde:f1 ograve:f2 oacute:f3 ocirc:f4 otilde:f5 ouml:f6 divide:f7 oslash:f8 ugrave:f9 uacute:fa ucirc:fb uuml:fc yacute:fd thorn:fe yuml:ff OElig:152 oelig:153 Scaron:160 scaron:161 Yuml:178 fnof:192 circ:2c6 tilde:2dc Alpha:391 Beta:392 Gamma:393 Delta:394 Epsilon:395 Zeta:396 Eta:397 Theta:398 Iota:399 Kappa:39a Lambda:39b Mu:39c Nu:39d Xi:39e Omicron:39f Pi:3a0 Rho:3a1 Sigma:3a3 Tau:3a4 Upsilon:3a5 Phi:3a6 Chi:3a7 Psi:3a8 Omega:3a9 alpha:3b1 beta:3b2 gamma:3b3 delta:3b4 epsilon:3b5 zeta:3b6 eta:3b7 theta:3b8 iota:3b9 kappa:3ba lambda:3bb mu:3bc nu:3bd xi:3be omicron:3bf pi:3c0 rho:3c1 sigmaf:3c2 sigma:3c3 tau:3c4 upsilon:3c5 phi:3c6 chi:3c7 psi:3c8 omega:3c9 thetasym:3d1 upsih:3d2 piv:3d6 ensp:2002 emsp:2003 thinsp:2009 zwnj:200c zwj:200d lrm:200e rlm:200f ndash:2013 mdash:2014 lsquo:2018 rsquo:2019 sbquo:201a ldquo:201c rdquo:201d bdquo:201e dagger:2020 Dagger:2021 bull:2022 hellip:2026 permil:2030 prime:2032 Prime:2033 lsaquo:2039 rsaquo:203a oline:203e frasl:2044 euro:20ac image:2111 weierp:2118 real:211c trade:2122 alefsym:2135 larr:2190 uarr:2191 rarr:2192 darr:2193 harr:2194 crarr:21b5 lArr:21d0 uArr:21d1 rArr:21d2 dArr:21d3 hArr:21d4 forall:2200 part:2202 exist:2203 empty:2205 nabla:2207 isin:2208 notin:2209 ni:220b prod:220f sum:2211 minus:2212 lowast:2217 radic:221a prop:221d infin:221e ang:2220 and:2227 or:2228 cap:2229 cup:222a int:222b there4:2234 sim:223c cong:2245 asymp:2248 ne:2260 equiv:2261 le:2264 ge:2265 sub:2282 sup:2283 nsub:2284 sube:2286 supe:2287 oplus:2295 otimes:2297 perp:22a5 sdot:22c5 lceil:2308 rceil:2309 lfloor:230a rfloor:230b lang:2329 rang:232a loz:25ca spades:2660 clubs:2663 hearts:2665 diams:2666";
const ENT_LEGACY = new Set("AElig AMP Aacute Acirc Agrave Aring Atilde Auml COPY Ccedil ETH Eacute Ecirc Egrave Euml GT Iacute Icirc Igrave Iuml LT Ntilde Oacute Ocirc Ograve Oslash Otilde Ouml QUOT REG THORN Uacute Ucirc Ugrave Uuml Yacute aacute acirc acute aelig agrave amp aring atilde auml brvbar ccedil cedil cent copy curren deg divide eacute ecirc egrave eth euml frac12 frac14 frac34 gt iacute icirc iexcl igrave iquest iuml laquo lt macr micro middot nbsp not ntilde oacute ocirc ograve ordf ordm oslash otilde ouml para plusmn pound quot raquo reg sect shy sup1 sup2 sup3 szlig thorn times uacute ucirc ugrave uml uuml yacute yen yuml".split(" "));
let ENT_MAP = null;
const W1252 = { 128: 0x20ac, 130: 0x201a, 131: 0x192, 132: 0x201e, 133: 0x2026, 134: 0x2020, 135: 0x2021, 136: 0x2c6, 137: 0x2030, 138: 0x160, 139: 0x2039, 140: 0x152, 142: 0x17d, 145: 0x2018, 146: 0x2019, 147: 0x201c, 148: 0x201d, 149: 0x2022, 150: 0x2013, 151: 0x2014, 152: 0x2dc, 153: 0x2122, 154: 0x161, 155: 0x203a, 156: 0x153, 158: 0x17e, 159: 0x178 };
function decodeEntities(text) {
  if (!ENT_MAP) {
    ENT_MAP = new Map(ENT4.split(" ").map((x) => { const [k, cp] = x.split(":"); return [k, String.fromCodePoint(parseInt(cp, 16))]; }));
    ENT_MAP.set("apos", "'").set("lang", "\u27e8").set("rang", "\u27e9"); // HTML5 moved these two
    for (const k of ["AMP", "LT", "GT", "QUOT", "COPY", "REG"]) ENT_MAP.set(k, ENT_MAP.get(k.toLowerCase()));
  }
  return String(text).replace(/&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)/g, (m, e) => {
    if (e[0] === "#") {
      const hex = e[1] === "x" || e[1] === "X";
      const n = parseInt(e.slice(hex ? 2 : 1).replace(/;$/, ""), hex ? 16 : 10);
      if (W1252[n]) return String.fromCodePoint(W1252[n]);
      return n > 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : "\ufffd";
    }
    if (e.endsWith(";") && ENT_MAP.has(e.slice(0, -1))) return ENT_MAP.get(e.slice(0, -1));
    // no exact match: the longest legacy name at the start (&copyright -> (c)right, &notit; -> not-sign + it;)
    for (let x = Math.min(e.length, 6); x >= 2; x--) if (ENT_LEGACY.has(e.slice(0, x))) return ENT_MAP.get(e.slice(0, x)) + e.slice(x);
    return m;
  });
}

export const H = {
  te, td, bytes, fromBytes, toHex, fromHex,
  b64encode, b64decode, b64bytes, base32encode, base32decode, base32bytes, base58encode, textOrHex,
  sha, sha1, sha256, sha384, sha512, hmac, md5, crc32,
  randBytes, uuid, clampInt, escapeHtml, decodeEntities,
};
