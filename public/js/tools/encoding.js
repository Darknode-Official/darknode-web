// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Encoding & decoding mini-tools. See _schema.md for the contract.
const S = (v) => (v == null ? "" : String(v));

// RFC 3492 Punycode decode (ToUnicode). Browsers expose ToASCII via the URL
// API but keep hostnames in xn-- form, so the reverse direction is hand-rolled.
const PUNY = { BASE: 36, TMIN: 1, TMAX: 26, SKEW: 38, DAMP: 700, IBIAS: 72, IN: 128, MAX: 0x7fffffff };
function punyAdapt(delta, n, first) {
  delta = first ? Math.floor(delta / PUNY.DAMP) : delta >> 1;
  delta += Math.floor(delta / n);
  let k = 0;
  for (; delta > ((PUNY.BASE - PUNY.TMIN) * PUNY.TMAX) >> 1; k += PUNY.BASE) delta = Math.floor(delta / (PUNY.BASE - PUNY.TMIN));
  return Math.floor(k + (PUNY.BASE - PUNY.TMIN + 1) * delta / (delta + PUNY.SKEW));
}
function punyBasicToDigit(cp) {
  if (cp >= 0x30 && cp <= 0x39) return cp - 0x30 + 26;
  if (cp >= 0x41 && cp <= 0x5a) return cp - 0x41;
  if (cp >= 0x61 && cp <= 0x7a) return cp - 0x61;
  return PUNY.BASE;
}
function punyDecode(input) {
  const output = [];
  let n = PUNY.IN, i = 0, bias = PUNY.IBIAS;
  let basic = input.lastIndexOf("-");
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) { const c = input.charCodeAt(j); if (c >= 0x80) throw new Error("bad"); output.push(c); }
  let idx = basic > 0 ? basic + 1 : 0;
  while (idx < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = PUNY.BASE; ; k += PUNY.BASE) {
      if (idx >= input.length) throw new Error("bad");
      const digit = punyBasicToDigit(input.charCodeAt(idx++));
      if (digit >= PUNY.BASE || digit > Math.floor((PUNY.MAX - i) / w)) throw new Error("bad");
      i += digit * w;
      const t = k <= bias ? PUNY.TMIN : (k >= bias + PUNY.TMAX ? PUNY.TMAX : k - bias);
      if (digit < t) break;
      w *= (PUNY.BASE - t);
    }
    const out = output.length + 1;
    bias = punyAdapt(i - oldi, out, oldi === 0);
    if (Math.floor(i / out) > PUNY.MAX - n) throw new Error("bad");
    n += Math.floor(i / out);
    i %= out;
    output.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...output);
}
function punyToUnicode(host) {
  return host.split(".").map((l) => /^xn--/i.test(l) ? punyDecode(l.slice(4)) : l).join(".");
}

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

export const TOOLS = [
  { id: "base64", name: "Base64 Encoder / Decoder", cat: "encoding", desc: "Encode or decode Base64, with URL-safe and MIME variants.", tags: ["b64"],
    inputs: [{ k: "text", label: "Text", type: "textarea", placeholder: "Hello, Darknode" }, { k: "mode", label: "Mode", type: "select", opts: ["Encode", "Decode"], value: "Encode" }, { k: "url", label: "URL-safe (base64url)", type: "checkbox" }],
    run(v, H) { if (!v.text) return ""; try { return v.mode === "Encode" ? H.b64encode(v.text, { url: v.url }) : H.textOrHex(H.b64bytes(v.text, { url: v.url || /[-_]/.test(v.text) })); } catch (e) { return { error: "Not valid Base64." }; } } }, // - or _ only occur in base64url

  { id: "base32", name: "Base32 Encoder / Decoder", cat: "encoding", desc: "RFC 4648 Base32 encode/decode.", tags: ["b32"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["Encode", "Decode"], value: "Encode" }],
    run(v, H) { if (!v.text) return ""; try { return v.mode === "Encode" ? H.base32encode(v.text) : H.textOrHex(H.base32bytes(v.text)); } catch (e) { return { error: "Not valid Base32." }; } } },

  { id: "base58", name: "Base58 Encoder", cat: "encoding", desc: "Bitcoin-alphabet Base58 encode (no 0, O, I, l).", tags: ["b58", "bitcoin"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }],
    run(v, H) { return v.text ? H.base58encode(v.text) : ""; } },

  { id: "url-encode", name: "URL Encoder / Decoder", cat: "encoding", desc: "Percent-encode or decode a URL or component.", tags: ["percent", "uri"],
    inputs: [{ k: "text", label: "Text", type: "textarea", placeholder: "a b&c=d" }, { k: "mode", label: "Mode", type: "select", opts: ["Encode", "Decode"], value: "Encode" }, { k: "component", label: "Encode as component (encodeURIComponent)", type: "checkbox", value: true }, { k: "all", label: "Encode every character (filter testing)", type: "checkbox", value: false }],
    run(v) { if (!v.text) return ""; try { if (v.mode === "Encode" && v.all) return Array.from(String(v.text), (c) => { const cp = c.codePointAt(0); return cp < 128 ? "%" + cp.toString(16).toUpperCase().padStart(2, "0") : encodeURIComponent(c); }).join(""); if (v.mode === "Encode") return v.component ? encodeURIComponent(v.text) : encodeURI(v.text); return v.component ? decodeURIComponent(v.text) : decodeURI(v.text); } catch (e) { return { error: "Malformed URL sequence." }; } } },

  { id: "html-entities", name: "HTML Entity Encoder / Decoder", cat: "encoding", desc: "Escape or unescape HTML entities (&lt; &amp; &eacute; &#8212; …) the way a browser decodes them.", tags: ["escape", "xss"],
    inputs: [{ k: "text", label: "Text", type: "textarea", placeholder: "<b>hi</b> & \"you\"" }, { k: "mode", label: "Mode", type: "select", opts: ["Encode", "Decode"], value: "Encode" }],
    run(v) { if (!v.text) return ""; if (v.mode === "Encode") return v.text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); return decodeEntities(v.text);} },

  { id: "hex-text", name: "Hex Encoder / Decoder", cat: "encoding", desc: "Convert text to hex bytes and back.", tags: ["hex", "base16"],
    inputs: [{ k: "text", label: "Text or hex", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["Text → Hex", "Hex → Text"], value: "Text → Hex" }, { k: "sep", label: "Separator (encode)", type: "select", opts: [["", "none"], [" ", "space"], [":", "colon"]], value: "" }],
    run(v, H) { if (!v.text) return ""; if (v.mode === "Text → Hex") { const h = H.toHex(H.bytes(v.text)); return v.sep ? h.match(/.{2}/g).join(v.sep) : h; } try { return H.textOrHex(H.fromHex(v.text)); } catch (e) { return { error: "Not valid hex." }; } } },

  { id: "binary-text", name: "Binary Encoder / Decoder", cat: "encoding", desc: "Text to 8-bit binary and back.", tags: ["binary", "bits"],
    inputs: [{ k: "text", label: "Text or binary", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["Text → Binary", "Binary → Text"], value: "Text → Binary" }],
    run(v, H) { if (!v.text) return ""; if (v.mode === "Text → Binary") return Array.from(H.bytes(v.text), (b) => b.toString(2).padStart(8, "0")).join(" "); const bits = v.text.replace(/[^01]/g, ""); if (bits.length % 8) return { error: "Binary length must be a multiple of 8." }; const u = new Uint8Array(bits.length / 8); for (let i = 0; i < u.length; i++) u[i] = parseInt(bits.substr(i * 8, 8), 2); return H.fromBytes(u); } },

  { id: "rot13", name: "ROT13 / ROT47", cat: "encoding", desc: "Classic letter/ASCII rotation ciphers (self-inverse).", tags: ["cipher", "rot"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }, { k: "mode", label: "Variant", type: "select", opts: ["ROT13", "ROT47"], value: "ROT13" }],
    run(v) { if (!v.text) return ""; if (v.mode === "ROT13") return v.text.replace(/[a-zA-Z]/g, (c) => String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)); return v.text.replace(/[!-~]/g, (c) => String.fromCharCode(33 + ((c.charCodeAt(0) - 33 + 47) % 94))); } },

  { id: "caesar", name: "Caesar Cipher", cat: "encoding", desc: "Shift each letter by N (Caesar / shift cipher).", tags: ["cipher", "shift"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }, { k: "shift", label: "Shift", type: "range", min: 1, max: 25, step: 1, value: 3 }, { k: "mode", label: "Mode", type: "select", opts: ["Encrypt", "Decrypt"], value: "Encrypt" }],
    run(v, H) { if (!v.text) return ""; let s = H.clampInt(v.shift, -25, 25, 3); if (v.mode === "Decrypt") s = -s; return v.text.replace(/[a-z]/gi, (c) => { const base = c <= "Z" ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - base + s + 26) % 26 + base); }); } },

  { id: "atbash", name: "Atbash Cipher", cat: "encoding", desc: "Mirror the alphabet (A↔Z, B↔Y). Self-inverse.", tags: ["cipher"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }],
    run(v) { if (!v.text) return ""; return v.text.replace(/[a-z]/gi, (c) => { const base = c <= "Z" ? 65 : 97; return String.fromCharCode(base + 25 - (c.charCodeAt(0) - base)); }); } },

  { id: "vigenere", name: "Vigenère Cipher", cat: "encoding", desc: "Polyalphabetic cipher with a keyword.", tags: ["cipher", "key"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }, { k: "key", label: "Key", type: "text", placeholder: "LEMON" }, { k: "mode", label: "Mode", type: "select", opts: ["Encrypt", "Decrypt"], value: "Encrypt" }],
    run(v) { if (!v.text) return ""; const key = (v.key || "").replace(/[^a-z]/gi, "").toUpperCase(); if (!key) return { error: "Enter a key (letters only)." }; let ki = 0; return v.text.replace(/[a-z]/gi, (c) => { const base = c <= "Z" ? 65 : 97; let k = key.charCodeAt(ki % key.length) - 65; if (v.mode === "Decrypt") k = -k; ki++; return String.fromCharCode((c.charCodeAt(0) - base + k + 26) % 26 + base); }); } },

  { id: "xor-cipher", name: "XOR Cipher", cat: "encoding", desc: "XOR bytes against a repeating key; output as hex.", tags: ["cipher", "xor"],
    inputs: [{ k: "text", label: "Text or hex", type: "textarea" }, { k: "key", label: "Key", type: "text", placeholder: "secret" }, { k: "mode", label: "Mode", type: "select", opts: ["Text → Hex", "Hex → Text"], value: "Text → Hex" }],
    run(v, H) { if (!v.text || !v.key) return ""; const key = H.bytes(v.key); const data = v.mode === "Text → Hex" ? H.bytes(v.text) : H.fromHex(v.text); const out = new Uint8Array(data.length); for (let i = 0; i < data.length; i++) out[i] = data[i] ^ key[i % key.length]; return v.mode === "Text → Hex" ? H.toHex(out) : H.fromBytes(out); } },

  { id: "morse", name: "Morse Code", cat: "encoding", desc: "Text ↔ Morse code (International).", tags: ["morse"],
    inputs: [{ k: "text", label: "Text or Morse", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["Text → Morse", "Morse → Text"], value: "Text → Morse" }],
    run(v) { const M = { A: ".-", B: "-...", C: "-.-.", D: "-..", E: ".", F: "..-.", G: "--.", H: "....", I: "..", J: ".---", K: "-.-", L: ".-..", M: "--", N: "-.", O: "---", P: ".--.", Q: "--.-", R: ".-.", S: "...", T: "-", U: "..-", V: "...-", W: ".--", X: "-..-", Y: "-.--", Z: "--..", "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.", "/": "-..-.", "@": ".--.-.", "-": "-....-", "(": "-.--.", ")": "-.--.-", ":": "---...", "=": "-...-", "+": ".-.-." }; if (!v.text) return ""; if (v.mode === "Text → Morse") return v.text.toUpperCase().split("").map((c) => c === " " ? "/" : (M[c] || "")).filter(Boolean).join(" "); const R = Object.fromEntries(Object.entries(M).map(([k, x]) => [x, k])); return v.text.trim().split(/\s+/).map((t) => t === "/" ? " " : Object.hasOwn(R, t) ? R[t] : "").join(""); } },

  { id: "unicode-escape", name: "Unicode Escape / Unescape", cat: "encoding", desc: "Convert to \\uXXXX escapes and back.", tags: ["unicode", "\\u"],
    inputs: [{ k: "text", label: "Text", type: "textarea", placeholder: "café résumé naïve" }, { k: "mode", label: "Mode", type: "select", opts: ["Escape", "Unescape"], value: "Escape" }],
    run(v) { if (!v.text) return ""; if (v.mode === "Escape") return Array.from(v.text).map((c) => { const cp = c.codePointAt(0); if (cp > 126 || cp < 32) return cp > 0xffff ? "\\u{" + cp.toString(16) + "}" : "\\u" + cp.toString(16).padStart(4, "0"); return c; }).join(""); try { return v.text.replace(/\\u\{([0-9a-fA-F]+)\}|\\u([0-9a-fA-F]{4})/g, (m, a, b) => String.fromCodePoint(parseInt(a || b, 16))); } catch (e) { return { error: "Bad escape sequence." }; } } },

  { id: "json-string-escape", name: "JSON String Escaper", cat: "encoding", desc: "Escape text into a JSON string literal, or unescape one.", tags: ["json", "escape"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["Escape", "Unescape"], value: "Escape" }],
    run(v) { if (!v.text) return ""; if (v.mode === "Escape") return JSON.stringify(v.text); try { const t = v.text.trim(); return JSON.parse(t[0] === '"' ? t : '"' + t + '"'); } catch (e) { return { error: "Not a valid JSON string." }; } } },

  { id: "leetspeak", name: "Leetspeak Converter", cat: "encoding", desc: "Convert text to and from 1337 5p34k.", tags: ["leet", "1337"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["To leet", "From leet"], value: "To leet" }],
    run(v) { if (!v.text) return ""; const to = { a: "4", e: "3", i: "1", o: "0", s: "5", t: "7", l: "1", g: "9", b: "8" }; if (v.mode === "To leet") return v.text.toLowerCase().replace(/[aeiostlgb]/g, (c) => to[c]); const from = { "4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "9": "g", "8": "b" }; return v.text.replace(/[43105798]/g, (c) => from[c]); } },

  { id: "a1z26", name: "A1Z26 Cipher", cat: "encoding", desc: "Letters to their alphabet position (A=1 … Z=26) and back.", tags: ["cipher", "number"],
    inputs: [{ k: "text", label: "Text or numbers", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["Text → Numbers", "Numbers → Text"], value: "Text → Numbers" }],
    run(v) { if (!v.text) return ""; if (v.mode === "Text → Numbers") return v.text.toLowerCase().replace(/[a-z]+/g, (w) => Array.from(w, (c) => c.charCodeAt(0) - 96).join("-")); const letter = (n) => { const i = parseInt(n, 10); return i >= 1 && i <= 26 ? String.fromCharCode(96 + i) : ""; }; if (!/\d-\d/.test(v.text)) return v.text.trim().split(/[\s,]+/).map(letter).join(""); return v.text.replace(/\d+(?:-\d+)*/g, (run) => run.split("-").map(letter).join("")); } }, // letters joined by -, words keep their spaces; a plain "8 5 12" list still decodes

  { id: "reverse-string", name: "String Reverser", cat: "encoding", desc: "Reverse characters (Unicode-aware).", tags: ["reverse"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }],
    run(v) { return v.text ? Array.from(S(v.text)).reverse().join("") : ""; } },

  { id: "punycode", name: "Punycode (IDN) Converter", cat: "encoding", desc: "Convert internationalized domain names to/from ASCII (xn--).", tags: ["idn", "domain"],
    inputs: [{ k: "text", label: "Domain", type: "text", placeholder: "münchen.de" }, { k: "mode", label: "Mode", type: "select", opts: ["To ASCII", "To Unicode"], value: "To ASCII" }],
    run(v) { if (!v.text) return ""; try { const u = new URL("http://" + v.text.trim()); if (v.mode === "To ASCII") return u.hostname; try { return punyToUnicode(u.hostname); } catch (_) { return u.hostname; } } catch (e) { return { error: "Enter a valid domain name." }; } } },
];
