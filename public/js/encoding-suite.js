// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d}))throw document.body.innerHTML="",new Error("unlicensed")}());

// ============================================================================
// DARKNODE ENCODING SUITE — Comprehensive Encoding/Decoding Toolkit
// Base64, URL, HTML, Hex, Binary, ROT13/47, Caesar, Vigenère, Morse,
// NATO phonetic, Unicode escape, JWT decoder, ASN.1/DER viewer.
// ============================================================================

// ---------------------------------------------------------------------------
// Base64 encode/decode (handles Unicode via UTF-8)
// ---------------------------------------------------------------------------
function b64Encode(str) {
  try { return btoa(unescape(encodeURIComponent(str))); }
  catch (e) { return "Error: " + e.message; }
}
function b64Decode(str) {
  try { return decodeURIComponent(escape(atob(str.trim()))); }
  catch (e) { return "Error: Invalid Base64 — " + e.message; }
}

// ---------------------------------------------------------------------------
// URL encode/decode
// ---------------------------------------------------------------------------
function urlEncode(str) { try { return encodeURIComponent(str); } catch (e) { return "Error: " + e.message; } }
function urlDecode(str) { try { return decodeURIComponent(str); } catch (e) { return "Error: " + e.message; } }
function urlEncodeAll(str) {
  // RFC 3986 percent-encoding operates on UTF-8 bytes, not UTF-16 code units.
  // Iterating str.charCodeAt() emitted "%20AC" for "€" (a single >255 unit) —
  // not valid percent-encoding — and "%E9" for "é" instead of "%C3%A9".
  const bytes = new TextEncoder().encode(str);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += "%" + bytes[i].toString(16).toUpperCase().padStart(2, "0");
  return out;
}
function doubleUrlEncode(str) { return encodeURIComponent(encodeURIComponent(str)); }

// ---------------------------------------------------------------------------
// HTML entity encode/decode
// ---------------------------------------------------------------------------
const HTML_ENTITIES = {
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  "/": "&#x2F;", "`": "&#96;", "=": "&#61;"
};
function htmlEncode(str) {
  return str.replace(/[&<>"'\/`=]/g, ch => HTML_ENTITIES[ch] || ch);
}
function htmlDecode(str) {
  const el = document.createElement("textarea");
  el.innerHTML = str;
  return el.value;
}
function htmlEncodeAll(str) {
  // Iterate by code point (for...of), not by UTF-16 unit: an astral character
  // such as "😀" (U+1F600) must become the single reference &#128512; rather
  // than two lone-surrogate entities &#55357;&#56832;.
  let out = "";
  for (const ch of str) out += "&#" + ch.codePointAt(0) + ";";
  return out;
}
function htmlEncodeHex(str) {
  let out = "";
  for (const ch of str) out += "&#x" + ch.codePointAt(0).toString(16) + ";";
  return out;
}

// ---------------------------------------------------------------------------
// Hex encode/decode
// ---------------------------------------------------------------------------
function hexEncode(str) {
  let out = "";
  for (const b of new TextEncoder().encode(str)) out += b.toString(16).padStart(2, "0");
  return out;
}
function hexDecode(str) {
  const clean = str.replace(/\s+/g, "").replace(/\\x/gi, "").replace(/^0x/i, "");
  if (clean.length % 2 !== 0) return "Error: Odd number of hex characters";
  const bytes = [];
  for (let i = 0; i < clean.length; i += 2) {
    const byte = parseInt(clean.substr(i, 2), 16);
    if (isNaN(byte)) return "Error: Invalid hex character at position " + i;
    bytes.push(byte);
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}
function hexWithSpaces(str) {
  let out = "";
  for (const b of new TextEncoder().encode(str)) out += b.toString(16).padStart(2, "0") + " ";
  return out.trim();
}
function hexWith0x(str) {
  let out = "";
  for (const b of new TextEncoder().encode(str)) out += "\\x" + b.toString(16).padStart(2, "0");
  return out;
}

// ---------------------------------------------------------------------------
// Binary / Octal / Decimal conversion
// ---------------------------------------------------------------------------
function textToBinary(str) {
  return Array.from(new TextEncoder().encode(str)).map(b => b.toString(2).padStart(8, "0")).join(" ");
}
function binaryToText(bin) {
  const tokens = bin.trim().split(/\s+/).filter(Boolean);
  const bytes = [];
  for (const t of tokens) {
    const n = parseInt(t, 2);
    if (isNaN(n)) return "Error: Invalid binary value \"" + t + "\"";
    bytes.push(n & 0xFF);
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}
function textToOctal(str) {
  return Array.from(new TextEncoder().encode(str)).map(b => b.toString(8).padStart(3, "0")).join(" ");
}
function octalToText(oct) {
  const tokens = oct.trim().split(/\s+/).filter(Boolean);
  const bytes = [];
  for (const t of tokens) {
    const n = parseInt(t, 8);
    if (isNaN(n)) return "Error: Invalid octal value \"" + t + "\"";
    bytes.push(n & 0xFF);
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}
function textToDecimal(str) {
  return Array.from(new TextEncoder().encode(str)).map(b => b.toString(10)).join(" ");
}
function decimalToText(dec) {
  const tokens = dec.trim().split(/\s+/).filter(Boolean);
  const bytes = [];
  for (const t of tokens) {
    const n = parseInt(t, 10);
    if (isNaN(n)) return "Error: Invalid decimal value \"" + t + "\"";
    bytes.push(n & 0xFF);
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

// ---------------------------------------------------------------------------
// ROT13 / ROT47
// ---------------------------------------------------------------------------
function rot13(str) {
  return str.replace(/[a-zA-Z]/g, ch => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
  });
}
function rot47(str) {
  return str.replace(/[!-~]/g, ch => {
    return String.fromCharCode(((ch.charCodeAt(0) - 33 + 47) % 94) + 33);
  });
}

// ---------------------------------------------------------------------------
// Caesar cipher (configurable shift)
// ---------------------------------------------------------------------------
function caesarEncrypt(str, shift) {
  shift = ((shift % 26) + 26) % 26;
  return str.replace(/[a-zA-Z]/g, ch => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
  });
}
function caesarDecrypt(str, shift) { return caesarEncrypt(str, 26 - shift); }
function caesarBruteForce(str) {
  const results = [];
  for (let shift = 0; shift < 26; shift++) {
    results.push({ shift, text: caesarDecrypt(str, shift) });
  }
  return results;
}

// ---------------------------------------------------------------------------
// Vigenère cipher
// ---------------------------------------------------------------------------
function vigenereEncrypt(text, key) {
  if (!key) return "Error: Key required";
  key = key.toUpperCase().replace(/[^A-Z]/g, "");
  if (!key) return "Error: Key must contain letters";
  let result = "", ki = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (/[a-zA-Z]/.test(ch)) {
      const base = ch <= "Z" ? 65 : 97;
      const shift = key.charCodeAt(ki % key.length) - 65;
      result += String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
      ki++;
    } else {
      result += ch;
    }
  }
  return result;
}
function vigenereDecrypt(text, key) {
  if (!key) return "Error: Key required";
  key = key.toUpperCase().replace(/[^A-Z]/g, "");
  if (!key) return "Error: Key must contain letters";
  let result = "", ki = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (/[a-zA-Z]/.test(ch)) {
      const base = ch <= "Z" ? 65 : 97;
      const shift = key.charCodeAt(ki % key.length) - 65;
      result += String.fromCharCode(((ch.charCodeAt(0) - base - shift + 26) % 26) + base);
      ki++;
    } else {
      result += ch;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Morse Code
// ---------------------------------------------------------------------------
const MORSE_MAP = {
  "A":".-","B":"-...","C":"-.-.","D":"-..","E":".","F":"..-.","G":"--.","H":"....","I":"..","J":".---",
  "K":"-.-","L":".-..","M":"--","N":"-.","O":"---","P":".--.","Q":"--.-","R":".-.","S":"...","T":"-",
  "U":"..-","V":"...-","W":".--","X":"-..-","Y":"-.--","Z":"--..","0":"-----","1":".----","2":"..---",
  "3":"...--","4":"....-","5":".....","6":"-....","7":"--...","8":"---..","9":"----.",".":" .-.-.-",
  ",":" --..--","?":"..--..","!":"-.-.--","/":" -..-.","(":" -.--.",")":"-.--.-","&":".-...",":":" ---...",
  ";":" -.-.-.","=":" -...-","+":" .-.-.","-":" -....-","_":" ..--.-","\"":".-..-.",
  "$":" ...-..-","@":" .--.-."," ":" / "
};
const MORSE_REV = {};
for (const [k, v] of Object.entries(MORSE_MAP)) MORSE_REV[v.trim()] = k;

function textToMorse(str) {
  return str.toUpperCase().split("").map(ch => MORSE_MAP[ch] || ch).join(" ").replace(/\s+/g, " ");
}
function morseToText(morse) {
  return morse.split(" / ").map(word =>
    word.trim().split(/\s+/).map(code => MORSE_REV[code] || code).join("")
  ).join(" ");
}

// ---------------------------------------------------------------------------
// NATO Phonetic Alphabet
// ---------------------------------------------------------------------------
const NATO_MAP = {
  "A":"Alpha","B":"Bravo","C":"Charlie","D":"Delta","E":"Echo","F":"Foxtrot","G":"Golf","H":"Hotel",
  "I":"India","J":"Juliet","K":"Kilo","L":"Lima","M":"Mike","N":"November","O":"Oscar","P":"Papa",
  "Q":"Quebec","R":"Romeo","S":"Sierra","T":"Tango","U":"Uniform","V":"Victor","W":"Whiskey",
  "X":"X-ray","Y":"Yankee","Z":"Zulu","0":"Zero","1":"One","2":"Two","3":"Three","4":"Four",
  "5":"Five","6":"Six","7":"Seven","8":"Eight","9":"Niner"," ":"[space]",".":"Stop","-":"Dash"
};
function textToNATO(str) {
  return str.toUpperCase().split("").map(ch => NATO_MAP[ch] || ch).join(" ");
}
function natoToText(nato) {
  const rev = {};
  for (const [k, v] of Object.entries(NATO_MAP)) rev[v.toLowerCase()] = k;
  return nato.split(/\s+/).map(w => {
    const lw = w.toLowerCase();
    return rev[lw] || (lw === "[space]" ? " " : w);
  }).join("");
}

// ---------------------------------------------------------------------------
// Unicode escape/unescape
// ---------------------------------------------------------------------------
function unicodeEscape(str) {
  return Array.from(str).map(ch => {
    const code = ch.codePointAt(0);
    if (code > 0xffff) return "\\u{" + code.toString(16) + "}";
    return "\\u" + code.toString(16).padStart(4, "0");
  }).join("");
}
function unicodeUnescape(str) {
  return str.replace(/\\u\{([0-9a-fA-F]+)\}|\\u([0-9a-fA-F]{4})/g, (_, g1, g2) => {
    return String.fromCodePoint(parseInt(g1 || g2, 16));
  });
}
function punycode(str) {
  try {
    const url = new URL("http://" + str);
    return url.hostname;
  } catch (e) { return "Error: " + e.message; }
}

// ---------------------------------------------------------------------------
// JWT Decoder
// ---------------------------------------------------------------------------
function decodeJWT(token) {
  const parts = token.trim().split(".");
  if (parts.length !== 3) return { error: "Invalid JWT: expected 3 parts separated by dots, got " + parts.length };
  function b64urlDecode(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    let text;
    try {
      const bin = atob(s);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      text = new TextDecoder("utf-8").decode(bytes);
    } catch (e) { return null; }
    try { return JSON.parse(text); } catch (e) { return text; }
  }
  const header = b64urlDecode(parts[0]);
  const payload = b64urlDecode(parts[1]);
  const signature = parts[2];
  const claims = {};
  if (payload && typeof payload === "object") {
    if (payload.iat) claims.issuedAt = new Date(payload.iat * 1000).toISOString();
    if (payload.exp) {
      claims.expiresAt = new Date(payload.exp * 1000).toISOString();
      claims.isExpired = Date.now() / 1000 > payload.exp;
    }
    if (payload.nbf) claims.notBefore = new Date(payload.nbf * 1000).toISOString();
    if (payload.iss) claims.issuer = payload.iss;
    if (payload.sub) claims.subject = payload.sub;
    if (payload.aud) claims.audience = payload.aud;
  }
  return {
    header: header,
    payload: payload,
    signature: signature,
    signatureBase64Url: parts[2],
    signatureHex: (function () {
      // Pad to a multiple of 4, not a hardcoded "==": a 32-byte HS256 signature
      // is 43 base64url chars, and 43 + "==" = 45 (≡1 mod 4), which the browser's
      // strict atob() rejects with InvalidCharacterError — throwing out of this
      // object literal and failing the entire JWT decode for most real tokens.
      try {
        let s = parts[2].replace(/-/g, "+").replace(/_/g, "/");
        while (s.length % 4) s += "=";
        const bin = atob(s);
        let hex = "";
        for (let i = 0; i < bin.length; i++) hex += bin.charCodeAt(i).toString(16).padStart(2, "0");
        return hex;
      } catch (e) { return ""; }
    })(),
    claims: claims,
    algorithm: header && header.alg ? header.alg : "unknown",
    type: header && header.typ ? header.typ : "unknown"
  };
}

// ---------------------------------------------------------------------------
// ASN.1/DER Viewer (basic TLV parser)
// ---------------------------------------------------------------------------
const ASN1_TAGS = {
  0x01: "BOOLEAN", 0x02: "INTEGER", 0x03: "BIT STRING", 0x04: "OCTET STRING",
  0x05: "NULL", 0x06: "OBJECT IDENTIFIER", 0x07: "ObjectDescriptor",
  0x08: "EXTERNAL", 0x09: "REAL", 0x0a: "ENUMERATED", 0x0b: "EMBEDDED PDV",
  0x0c: "UTF8String", 0x0d: "RELATIVE-OID", 0x10: "SEQUENCE", 0x11: "SET",
  0x12: "NumericString", 0x13: "PrintableString", 0x14: "T61String",
  0x15: "VideotexString", 0x16: "IA5String", 0x17: "UTCTime",
  0x18: "GeneralizedTime", 0x19: "GraphicString", 0x1a: "VisibleString",
  0x1b: "GeneralString", 0x1c: "UniversalString", 0x1d: "CHARACTER STRING",
  0x1e: "BMPString", 0x30: "SEQUENCE", 0x31: "SET"
};
function parseASN1(hexStr) {
  const bytes = [];
  const clean = hexStr.replace(/\s+/g, "").replace(/^0x/i, "");
  for (let i = 0; i < clean.length; i += 2) {
    bytes.push(parseInt(clean.substr(i, 2), 16));
  }
  const nodes = [];
  function parse(offset, depth) {
    if (offset >= bytes.length) return offset;
    const tag = bytes[offset];
    const tagName = ASN1_TAGS[tag] || (tag & 0x20 ? "CONSTRUCTED [" + (tag & 0x1f) + "]" : "PRIMITIVE [" + (tag & 0x1f) + "]");
    const constructed = !!(tag & 0x20);
    offset++;
    let len = bytes[offset]; offset++;
    if (len & 0x80) {
      const numBytes = len & 0x7f;
      len = 0;
      for (let i = 0; i < numBytes; i++) { len = (len << 8) | bytes[offset]; offset++; }
    }
    const valueBytes = bytes.slice(offset, offset + len);
    const valueHex = valueBytes.map(b => b.toString(16).padStart(2, "0")).join(" ");
    let valueStr = "";
    if (tag === 0x02) {
      let n = 0;
      for (const b of valueBytes) n = (n << 8) | b;
      valueStr = n.toString();
    } else if (tag === 0x13 || tag === 0x16 || tag === 0x0c || tag === 0x1a) {
      valueStr = valueBytes.map(b => String.fromCharCode(b)).join("");
    } else if (tag === 0x06) {
      const oid = [];
      oid.push(Math.floor(valueBytes[0] / 40));
      oid.push(valueBytes[0] % 40);
      let acc = 0;
      for (let i = 1; i < valueBytes.length; i++) {
        acc = (acc << 7) | (valueBytes[i] & 0x7f);
        if (!(valueBytes[i] & 0x80)) { oid.push(acc); acc = 0; }
      }
      valueStr = oid.join(".");
    } else if (tag === 0x17) {
      valueStr = valueBytes.map(b => String.fromCharCode(b)).join("");
    } else if (tag === 0x01) {
      valueStr = valueBytes[0] === 0 ? "FALSE" : "TRUE";
    }
    nodes.push({ depth, tag: "0x" + tag.toString(16).padStart(2, "0"), tagName, length: len, valueHex, valueStr, constructed });
    if (constructed && len > 0) {
      let end = offset + len;
      let childOffset = offset;
      while (childOffset < end) {
        childOffset = parse(childOffset, depth + 1);
      }
    }
    return offset + len;
  }
  try { parse(0, 0); } catch (e) { nodes.push({ depth: 0, tag: "??", tagName: "PARSE ERROR", length: 0, valueHex: "", valueStr: e.message, constructed: false }); }
  return nodes;
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------
const ENC_STYLES = `
  .enc-wrap { font-family: var(--mono, 'JetBrains Mono', monospace); color: var(--txt, #e0e6ed); max-width: 1100px; margin: 0 auto; padding: 24px; }
  .enc-title { font-family: var(--sans, 'Sora', system-ui, sans-serif); font-size: 1.75rem; font-weight: 700; margin-bottom: 8px; background: linear-gradient(135deg, #7c5cff, #00d4ff); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .enc-sub { color: var(--txt-2, #8899aa); font-size: 0.85rem; margin-bottom: 24px; font-family: var(--sans, 'Sora', system-ui, sans-serif); }
  .enc-tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border, #1a2233); margin-bottom: 20px; flex-wrap: wrap; }
  .enc-tab { padding: 8px 14px; cursor: pointer; font-size: 0.78rem; border: none; background: transparent; color: var(--txt-2, #8899aa); border-bottom: 2px solid transparent; transition: all 0.15s; font-family: inherit; }
  .enc-tab:hover { color: var(--txt, #e0e6ed); background: rgba(124,92,255,0.05); }
  .enc-tab.active { color: #7c5cff; border-bottom-color: #7c5cff; }
  .enc-panel { display: none; }
  .enc-panel.active { display: block; }
  .enc-card { background: var(--card, #0d1117); border: 1px solid var(--border, #1a2233); border-radius: 8px; padding: 20px; margin-bottom: 16px; }
  .enc-card h3 { font-size: 1rem; font-weight: 600; margin: 0 0 12px; color: var(--txt, #e0e6ed); font-family: var(--sans, 'Sora', system-ui, sans-serif); }
  .enc-dual { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .enc-label { display: block; font-size: 0.73rem; color: var(--txt-2, #8899aa); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.05em; }
  .enc-input, .enc-textarea { width: 100%; box-sizing: border-box; padding: 10px 12px; background: var(--input-bg, #161b22); border: 1px solid var(--border, #1a2233); border-radius: 6px; color: var(--txt, #e0e6ed); font-family: inherit; font-size: 0.85rem; outline: none; transition: border-color 0.15s; }
  .enc-input:focus, .enc-textarea:focus { border-color: #7c5cff; }
  .enc-textarea { resize: vertical; min-height: 100px; }
  .enc-select { padding: 8px 12px; background: var(--input-bg, #161b22); border: 1px solid var(--border, #1a2233); border-radius: 6px; color: var(--txt, #e0e6ed); font-family: inherit; font-size: 0.85rem; outline: none; cursor: pointer; }
  .enc-btn { padding: 8px 18px; border: none; border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 0.8rem; font-weight: 600; transition: all 0.15s; }
  .enc-btn-primary { background: linear-gradient(135deg, #7c5cff, #5a3fdd); color: #fff; }
  .enc-btn-primary:hover { filter: brightness(1.15); transform: translateY(-1px); }
  .enc-btn-ghost { background: transparent; color: #7c5cff; border: 1px solid rgba(124,92,255,0.3); }
  .enc-btn-ghost:hover { background: rgba(124,92,255,0.1); }
  .enc-output { background: #0a0e16; border: 1px solid var(--border, #1a2233); border-radius: 6px; padding: 12px; font-size: 0.82rem; word-break: break-all; margin-top: 8px; min-height: 36px; position: relative; white-space: pre-wrap; }
  .enc-copy-btn { position: absolute; top: 6px; right: 6px; padding: 4px 10px; font-size: 0.7rem; background: rgba(124,92,255,0.15); color: #7c5cff; border: none; border-radius: 4px; cursor: pointer; font-family: inherit; }
  .enc-copy-btn:hover { background: rgba(124,92,255,0.3); }
  .enc-swap { display: flex; align-items: center; justify-content: center; padding: 8px; }
  .enc-swap-btn { background: none; border: 1px solid var(--border, #1a2233); border-radius: 4px; width: 36px; height: 36px; cursor: pointer; color: var(--txt-2, #8899aa); font-size: 1.1rem; display: flex; align-items: center; justify-content: center; transition: all 0.15s; }
  .enc-swap-btn:hover { border-color: #7c5cff; color: #7c5cff; background: rgba(124,92,255,0.08); }
  .enc-jwt-section { margin-top: 12px; }
  .enc-jwt-header { font-size: 0.75rem; color: var(--txt-2, #8899aa); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px; }
  .enc-jwt-json { background: #0a0e16; border: 1px solid var(--border, #1a2233); border-radius: 6px; padding: 12px; font-size: 0.82rem; white-space: pre-wrap; overflow-x: auto; }
  .enc-asn1-tree { font-size: 0.78rem; line-height: 1.6; }
  .enc-asn1-node { padding-left: 20px; border-left: 1px solid rgba(124,92,255,0.2); margin-left: 8px; }
  .enc-asn1-tag { color: #7c5cff; font-weight: 600; }
  .enc-asn1-name { color: #00d4ff; }
  .enc-asn1-len { color: var(--txt-2, #8899aa); font-size: 0.72rem; }
  .enc-asn1-val { color: #00c853; }
  .enc-caesar-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; margin-top: 12px; }
  .enc-caesar-table th { text-align: left; padding: 6px 10px; background: #0a0e16; color: var(--txt-2, #8899aa); font-weight: 500; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .enc-caesar-table td { padding: 6px 10px; border-bottom: 1px solid rgba(26,34,51,0.3); }
  .enc-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; background: rgba(124,92,255,0.15); color: #7c5cff; }
  .enc-info { font-size: 0.78rem; color: var(--txt-2, #8899aa); margin: 4px 0 12px; }
  @media (max-width: 700px) {
    .enc-dual { grid-template-columns: 1fr; }
    .enc-tabs { gap: 0; }
    .enc-tab { padding: 6px 8px; font-size: 0.7rem; }
  }
`;

// ---------------------------------------------------------------------------
// Helper: build an encode/decode panel pair
// ---------------------------------------------------------------------------
function buildCodecPanel(id, label, encodeFn, decodeFn, opts) {
  opts = opts || {};
  return `
    <div class="enc-card">
      <h3>${label}</h3>
      ${opts.info ? '<div class="enc-info">' + opts.info + '</div>' : ""}
      <div class="enc-dual">
        <div>
          <label class="enc-label">Plain text</label>
          <textarea class="enc-textarea" id="${id}-plain" placeholder="Type text to encode...">${opts.defaultText || ""}</textarea>
        </div>
        <div>
          <label class="enc-label">Encoded</label>
          <textarea class="enc-textarea" id="${id}-encoded" placeholder="Paste encoded text to decode..."></textarea>
        </div>
      </div>
      ${opts.extraControls || ""}
      <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;">
        <button class="enc-btn enc-btn-primary" data-action="encode" data-codec="${id}">Encode →</button>
        <button class="enc-btn enc-btn-ghost" data-action="decode" data-codec="${id}">← Decode</button>
        ${opts.extraButtons || ""}
      </div>
    </div>`;
}

// ---------------------------------------------------------------------------
// UI Renderer
// ---------------------------------------------------------------------------
export function renderEncodingSuite(container) {
  const styleEl = document.createElement("style");
  styleEl.textContent = ENC_STYLES;
  document.head.appendChild(styleEl);

  container.innerHTML = `
    <div class="enc-wrap">
      <div class="enc-title">Encoding Suite</div>
      <div class="enc-sub">Encode, decode, and transform data between formats — entirely in your browser</div>
      <div class="enc-tabs" id="enc-tabs">
        <button class="enc-tab active" data-panel="base64">Base64</button>
        <button class="enc-tab" data-panel="url">URL</button>
        <button class="enc-tab" data-panel="html">HTML</button>
        <button class="enc-tab" data-panel="hex">Hex</button>
        <button class="enc-tab" data-panel="binary">Binary/Oct/Dec</button>
        <button class="enc-tab" data-panel="rot">ROT13/47</button>
        <button class="enc-tab" data-panel="caesar">Caesar</button>
        <button class="enc-tab" data-panel="vigenere">Vigenère</button>
        <button class="enc-tab" data-panel="morse">Morse</button>
        <button class="enc-tab" data-panel="nato">NATO</button>
        <button class="enc-tab" data-panel="unicode">Unicode</button>
        <button class="enc-tab" data-panel="jwt">JWT</button>
        <button class="enc-tab" data-panel="asn1">ASN.1</button>
      </div>

      <div class="enc-panel active" id="epanel-base64">
        ${buildCodecPanel("b64", "Base64 Encoding", null, null, {
          info: "RFC 4648 Base64 encoding. Handles Unicode via UTF-8 encoding."
        })}
      </div>

      <div class="enc-panel" id="epanel-url">
        ${buildCodecPanel("url", "URL Encoding (encodeURIComponent)", null, null, {
          info: "RFC 3986 percent-encoding. Encodes all characters that are not unreserved.",
          extraButtons: '<button class="enc-btn enc-btn-ghost" data-action="urlencode-all" data-codec="url">Encode All Chars</button><button class="enc-btn enc-btn-ghost" data-action="urlencode-double" data-codec="url">Double Encode</button>'
        })}
      </div>

      <div class="enc-panel" id="epanel-html">
        ${buildCodecPanel("html", "HTML Entity Encoding", null, null, {
          info: "Encode special HTML characters as named or numeric entities to prevent XSS.",
          extraButtons: '<button class="enc-btn enc-btn-ghost" data-action="htmlencode-all" data-codec="html">All → Decimal</button><button class="enc-btn enc-btn-ghost" data-action="htmlencode-hex" data-codec="html">All → Hex</button>'
        })}
      </div>

      <div class="enc-panel" id="epanel-hex">
        ${buildCodecPanel("hex", "Hexadecimal Encoding", null, null, {
          info: "Convert text to hex byte representation and back.",
          extraButtons: '<button class="enc-btn enc-btn-ghost" data-action="hex-spaces" data-codec="hex">With Spaces</button><button class="enc-btn enc-btn-ghost" data-action="hex-0x" data-codec="hex">\\x Prefix</button>'
        })}
      </div>

      <div class="enc-panel" id="epanel-binary">
        <div class="enc-card">
          <h3>Binary / Octal / Decimal</h3>
          <div class="enc-info">Convert text to and from binary, octal, or decimal byte representation.</div>
          <label class="enc-label">Input text</label>
          <textarea class="enc-textarea" id="bin-plain" placeholder="Hello"></textarea>
          <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;">
            <button class="enc-btn enc-btn-primary" id="bin-to-bin">→ Binary</button>
            <button class="enc-btn enc-btn-primary" id="bin-to-oct">→ Octal</button>
            <button class="enc-btn enc-btn-primary" id="bin-to-dec">→ Decimal</button>
          </div>
          <div class="enc-output" id="bin-output" style="margin-top:12px;"></div>
          <div style="margin-top:16px;">
            <label class="enc-label">Encoded input (auto-detects binary/octal/decimal)</label>
            <textarea class="enc-textarea" id="bin-encoded" placeholder="01001000 01100101 01101100 01101100 01101111"></textarea>
            <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;">
              <button class="enc-btn enc-btn-ghost" id="bin-from-bin">Binary →</button>
              <button class="enc-btn enc-btn-ghost" id="bin-from-oct">Octal →</button>
              <button class="enc-btn enc-btn-ghost" id="bin-from-dec">Decimal →</button>
            </div>
            <div class="enc-output" id="bin-decode-output" style="margin-top:8px;"></div>
          </div>
        </div>
      </div>

      <div class="enc-panel" id="epanel-rot">
        ${buildCodecPanel("rot13", "ROT13 (letters only)", null, null, {
          info: "Rotate each letter by 13 positions. Applying ROT13 twice returns the original."
        })}
        <div style="margin-top:8px;">
          ${buildCodecPanel("rot47", "ROT47 (all printable ASCII)", null, null, {
            info: "Rotate each printable ASCII character (! through ~) by 47 positions."
          })}
        </div>
      </div>

      <div class="enc-panel" id="epanel-caesar">
        <div class="enc-card">
          <h3>Caesar Cipher</h3>
          <div class="enc-info">Shift each letter by N positions. ROT13 is Caesar with shift=13.</div>
          <label class="enc-label">Text</label>
          <textarea class="enc-textarea" id="caesar-text" placeholder="The quick brown fox jumps over the lazy dog"></textarea>
          <div style="display:flex;gap:12px;align-items:center;margin-top:12px;">
            <label class="enc-label" style="min-width:50px;">Shift</label>
            <input type="range" style="flex:1;accent-color:#7c5cff;" id="caesar-shift" min="0" max="25" value="3">
            <span id="caesar-shift-val" style="min-width:30px;text-align:right;color:#7c5cff;font-weight:600;">3</span>
          </div>
          <div style="display:flex;gap:8px;margin-top:12px;">
            <button class="enc-btn enc-btn-primary" id="caesar-enc">Encrypt</button>
            <button class="enc-btn enc-btn-ghost" id="caesar-dec">Decrypt</button>
            <button class="enc-btn enc-btn-ghost" id="caesar-brute">Brute Force (all 26)</button>
          </div>
          <div class="enc-output" id="caesar-output" style="margin-top:12px;"></div>
        </div>
      </div>

      <div class="enc-panel" id="epanel-vigenere">
        <div class="enc-card">
          <h3>Vigenère Cipher</h3>
          <div class="enc-info">Polyalphabetic substitution cipher using a keyword. Much stronger than Caesar.</div>
          <div class="enc-dual">
            <div>
              <label class="enc-label">Plain / Cipher text</label>
              <textarea class="enc-textarea" id="vig-text" placeholder="ATTACKATDAWN"></textarea>
            </div>
            <div>
              <label class="enc-label">Key (letters only)</label>
              <input class="enc-input" id="vig-key" placeholder="LEMON" value="">
            </div>
          </div>
          <div style="display:flex;gap:8px;margin-top:12px;">
            <button class="enc-btn enc-btn-primary" id="vig-enc">Encrypt</button>
            <button class="enc-btn enc-btn-ghost" id="vig-dec">Decrypt</button>
          </div>
          <div class="enc-output" id="vig-output" style="margin-top:12px;"></div>
        </div>
      </div>

      <div class="enc-panel" id="epanel-morse">
        ${buildCodecPanel("morse", "Morse Code", null, null, {
          info: "International Morse Code. Words separated by \" / \", letters by spaces."
        })}
      </div>

      <div class="enc-panel" id="epanel-nato">
        ${buildCodecPanel("nato", "NATO Phonetic Alphabet", null, null, {
          info: "ICAO/NATO spelling alphabet for unambiguous verbal communication."
        })}
      </div>

      <div class="enc-panel" id="epanel-unicode">
        ${buildCodecPanel("unicode", "Unicode Escape", null, null, {
          info: "Convert characters to \\uXXXX escape sequences and back."
        })}
      </div>

      <div class="enc-panel" id="epanel-jwt">
        <div class="enc-card">
          <h3>JWT Decoder</h3>
          <div class="enc-info">Decode a JSON Web Token to inspect its header, payload, and signature. No verification (needs server-side secret).</div>
          <label class="enc-label">JWT Token</label>
          <textarea class="enc-textarea" id="jwt-input" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"></textarea>
          <button class="enc-btn enc-btn-primary" id="jwt-decode" style="margin-top:12px;">Decode JWT</button>
          <div id="jwt-output"></div>
        </div>
      </div>

      <div class="enc-panel" id="epanel-asn1">
        <div class="enc-card">
          <h3>ASN.1/DER Viewer</h3>
          <div class="enc-info">Parse a DER-encoded hex string and display its ASN.1 TLV (Tag-Length-Value) structure.</div>
          <label class="enc-label">DER Hex</label>
          <textarea class="enc-textarea" id="asn1-input" placeholder="30 13 02 01 05 16 0e 41 6e 79 62 6f 64 79 20 74 68 65 72 65 3f"></textarea>
          <button class="enc-btn enc-btn-primary" id="asn1-parse" style="margin-top:12px;">Parse</button>
          <div id="asn1-output"></div>
        </div>
      </div>
    </div>
  `;

  // --- Tab switching ---
  container.querySelectorAll(".enc-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      container.querySelectorAll(".enc-tab").forEach(t => t.classList.remove("active"));
      container.querySelectorAll(".enc-panel").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      const panel = container.querySelector("#epanel-" + tab.dataset.panel);
      if (panel) panel.classList.add("active");
    });
  });

  // --- Codec dispatch ---
  const codecs = {
    b64:     { encode: b64Encode, decode: b64Decode },
    url:     { encode: urlEncode, decode: urlDecode },
    html:    { encode: htmlEncode, decode: htmlDecode },
    hex:     { encode: hexEncode, decode: hexDecode },
    rot13:   { encode: rot13, decode: rot13 },
    rot47:   { encode: rot47, decode: rot47 },
    morse:   { encode: textToMorse, decode: morseToText },
    nato:    { encode: textToNATO, decode: natoToText },
    unicode: { encode: unicodeEscape, decode: unicodeUnescape }
  };

  container.querySelectorAll("[data-action]").forEach(btn => {
    btn.addEventListener("click", () => {
      const action = btn.dataset.action;
      const codec = btn.dataset.codec;
      const plain = container.querySelector("#" + codec + "-plain");
      const encoded = container.querySelector("#" + codec + "-encoded");
      if (action === "encode" && codecs[codec]) {
        encoded.value = codecs[codec].encode(plain.value);
      } else if (action === "decode" && codecs[codec]) {
        plain.value = codecs[codec].decode(encoded.value);
      } else if (action === "urlencode-all") {
        encoded.value = urlEncodeAll(plain.value);
      } else if (action === "urlencode-double") {
        encoded.value = doubleUrlEncode(plain.value);
      } else if (action === "htmlencode-all") {
        encoded.value = htmlEncodeAll(plain.value);
      } else if (action === "htmlencode-hex") {
        encoded.value = htmlEncodeHex(plain.value);
      } else if (action === "hex-spaces") {
        encoded.value = hexWithSpaces(plain.value);
      } else if (action === "hex-0x") {
        encoded.value = hexWith0x(plain.value);
      }
    });
  });

  // --- Binary panel ---
  container.querySelector("#bin-to-bin").addEventListener("click", () => {
    container.querySelector("#bin-output").textContent = textToBinary(container.querySelector("#bin-plain").value);
  });
  container.querySelector("#bin-to-oct").addEventListener("click", () => {
    container.querySelector("#bin-output").textContent = textToOctal(container.querySelector("#bin-plain").value);
  });
  container.querySelector("#bin-to-dec").addEventListener("click", () => {
    container.querySelector("#bin-output").textContent = textToDecimal(container.querySelector("#bin-plain").value);
  });
  container.querySelector("#bin-from-bin").addEventListener("click", () => {
    container.querySelector("#bin-decode-output").textContent = binaryToText(container.querySelector("#bin-encoded").value);
  });
  container.querySelector("#bin-from-oct").addEventListener("click", () => {
    container.querySelector("#bin-decode-output").textContent = octalToText(container.querySelector("#bin-encoded").value);
  });
  container.querySelector("#bin-from-dec").addEventListener("click", () => {
    container.querySelector("#bin-decode-output").textContent = decimalToText(container.querySelector("#bin-encoded").value);
  });

  // --- Caesar panel ---
  const caesarShift = container.querySelector("#caesar-shift");
  const caesarShiftVal = container.querySelector("#caesar-shift-val");
  caesarShift.addEventListener("input", () => { caesarShiftVal.textContent = caesarShift.value; });
  container.querySelector("#caesar-enc").addEventListener("click", () => {
    const text = container.querySelector("#caesar-text").value;
    const shift = parseInt(caesarShift.value, 10);
    container.querySelector("#caesar-output").textContent = caesarEncrypt(text, shift);
  });
  container.querySelector("#caesar-dec").addEventListener("click", () => {
    const text = container.querySelector("#caesar-text").value;
    const shift = parseInt(caesarShift.value, 10);
    container.querySelector("#caesar-output").textContent = caesarDecrypt(text, shift);
  });
  container.querySelector("#caesar-brute").addEventListener("click", () => {
    const text = container.querySelector("#caesar-text").value;
    const results = caesarBruteForce(text);
    let html = '<table class="enc-caesar-table"><thead><tr><th>Shift</th><th>Result</th></tr></thead><tbody>';
    for (const r of results) {
      html += `<tr><td><span class="enc-badge">${r.shift}</span></td><td>${htmlEncode(r.text)}</td></tr>`;
    }
    html += "</tbody></table>";
    container.querySelector("#caesar-output").innerHTML = html;
  });

  // --- Vigenère panel ---
  container.querySelector("#vig-enc").addEventListener("click", () => {
    const text = container.querySelector("#vig-text").value;
    const key = container.querySelector("#vig-key").value;
    container.querySelector("#vig-output").textContent = vigenereEncrypt(text, key);
  });
  container.querySelector("#vig-dec").addEventListener("click", () => {
    const text = container.querySelector("#vig-text").value;
    const key = container.querySelector("#vig-key").value;
    container.querySelector("#vig-output").textContent = vigenereDecrypt(text, key);
  });

  // --- JWT panel ---
  container.querySelector("#jwt-decode").addEventListener("click", () => {
    const token = container.querySelector("#jwt-input").value;
    const out = container.querySelector("#jwt-output");
    if (!token.trim()) { out.innerHTML = '<div class="enc-output" style="color:#f44336;">Paste a JWT token</div>'; return; }
    const result = decodeJWT(token);
    if (result.error) { out.innerHTML = '<div class="enc-output" style="color:#f44336;">' + result.error + '</div>'; return; }
    let html = '<div style="margin-top:16px;">';
    html += '<div class="enc-jwt-section"><div class="enc-jwt-header" style="color:#f44336;">Header</div><div class="enc-jwt-json" style="border-color:rgba(244,67,54,0.3);">' + JSON.stringify(result.header, null, 2) + '</div></div>';
    html += '<div class="enc-jwt-section" style="margin-top:12px;"><div class="enc-jwt-header" style="color:#7c5cff;">Payload</div><div class="enc-jwt-json" style="border-color:rgba(124,92,255,0.3);">' + JSON.stringify(result.payload, null, 2) + '</div></div>';
    html += '<div class="enc-jwt-section" style="margin-top:12px;"><div class="enc-jwt-header" style="color:#00d4ff;">Signature</div><div class="enc-jwt-json" style="border-color:rgba(0,212,255,0.3);">' + result.signatureBase64Url + '</div></div>';
    if (Object.keys(result.claims).length) {
      html += '<div class="enc-jwt-section" style="margin-top:12px;"><div class="enc-jwt-header">Parsed Claims</div><div class="enc-jwt-json">' + JSON.stringify(result.claims, null, 2) + '</div></div>';
    }
    html += '</div>';
    out.innerHTML = html;
  });

  // --- ASN.1 panel ---
  container.querySelector("#asn1-parse").addEventListener("click", () => {
    const hex = container.querySelector("#asn1-input").value;
    const out = container.querySelector("#asn1-output");
    if (!hex.trim()) { out.innerHTML = '<div class="enc-output" style="color:#f44336;">Paste DER hex data</div>'; return; }
    const nodes = parseASN1(hex);
    let html = '<div class="enc-asn1-tree" style="margin-top:16px;">';
    for (const n of nodes) {
      const indent = "  ".repeat(n.depth);
      html += `<div style="padding-left:${n.depth * 20}px;border-left:${n.depth > 0 ? '1px solid rgba(124,92,255,0.2)' : 'none'};margin-left:${n.depth > 0 ? '8px' : '0'};">`;
      html += `<span class="enc-asn1-tag">${n.tag}</span> `;
      html += `<span class="enc-asn1-name">${n.tagName}</span> `;
      html += `<span class="enc-asn1-len">(${n.length} bytes)</span>`;
      if (n.valueStr) html += ` <span class="enc-asn1-val">= ${htmlEncode(n.valueStr)}</span>`;
      if (n.valueHex && !n.constructed) html += `<div style="font-size:0.72rem;color:var(--txt-2,#667);margin-top:2px;">${n.valueHex}</div>`;
      html += '</div>';
    }
    html += '</div>';
    out.innerHTML = html;
  });
}
