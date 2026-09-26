// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Encoding & decoding mini-tools. See _schema.md for the contract.
const S = (v) => (v == null ? "" : String(v));

export const TOOLS = [
  { id: "base64", name: "Base64 Encoder / Decoder", cat: "encoding", desc: "Encode or decode Base64, with URL-safe and MIME variants.", tags: ["b64"],
    inputs: [{ k: "text", label: "Text", type: "textarea", placeholder: "Hello, Darknode" }, { k: "mode", label: "Mode", type: "select", opts: ["Encode", "Decode"], value: "Encode" }, { k: "url", label: "URL-safe (base64url)", type: "checkbox" }],
    run(v, H) { if (!v.text) return ""; try { return v.mode === "Encode" ? H.b64encode(v.text, { url: v.url }) : H.b64decode(v.text, { url: v.url }); } catch (e) { return { error: "Not valid Base64." }; } } },

  { id: "base32", name: "Base32 Encoder / Decoder", cat: "encoding", desc: "RFC 4648 Base32 encode/decode.", tags: ["b32"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["Encode", "Decode"], value: "Encode" }],
    run(v, H) { if (!v.text) return ""; try { return v.mode === "Encode" ? H.base32encode(v.text) : H.base32decode(v.text); } catch (e) { return { error: "Not valid Base32." }; } } },

  { id: "base58", name: "Base58 Encoder", cat: "encoding", desc: "Bitcoin-alphabet Base58 encode (no 0, O, I, l).", tags: ["b58", "bitcoin"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }],
    run(v, H) { return v.text ? H.base58encode(v.text) : ""; } },

  { id: "url-encode", name: "URL Encoder / Decoder", cat: "encoding", desc: "Percent-encode or decode a URL or component.", tags: ["percent", "uri"],
    inputs: [{ k: "text", label: "Text", type: "textarea", placeholder: "a b&c=d" }, { k: "mode", label: "Mode", type: "select", opts: ["Encode", "Decode"], value: "Encode" }, { k: "component", label: "Encode as component (encodeURIComponent)", type: "checkbox", value: true }],
    run(v) { if (!v.text) return ""; try { if (v.mode === "Encode") return v.component ? encodeURIComponent(v.text) : encodeURI(v.text); return v.component ? decodeURIComponent(v.text) : decodeURI(v.text); } catch (e) { return { error: "Malformed URL sequence." }; } } },

  { id: "html-entities", name: "HTML Entity Encoder / Decoder", cat: "encoding", desc: "Escape or unescape HTML entities (&lt; &amp; …).", tags: ["escape", "xss"],
    inputs: [{ k: "text", label: "Text", type: "textarea", placeholder: "<b>hi</b> & \"you\"" }, { k: "mode", label: "Mode", type: "select", opts: ["Encode", "Decode"], value: "Encode" }],
    run(v) { if (!v.text) return ""; if (v.mode === "Encode") return v.text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); const map = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", "#39": "'", nbsp: " " }; return v.text.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (m, e) => { if (e[0] === "#") { const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return isNaN(n) ? m : String.fromCodePoint(n); } return map[e] != null ? map[e] : m; }); } },

  { id: "hex-text", name: "Hex Encoder / Decoder", cat: "encoding", desc: "Convert text to hex bytes and back.", tags: ["hex", "base16"],
    inputs: [{ k: "text", label: "Text or hex", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["Text → Hex", "Hex → Text"], value: "Text → Hex" }, { k: "sep", label: "Separator (encode)", type: "select", opts: [["", "none"], [" ", "space"], [":", "colon"]], value: "" }],
    run(v, H) { if (!v.text) return ""; if (v.mode === "Text → Hex") { const h = H.toHex(H.bytes(v.text)); return v.sep ? h.match(/.{2}/g).join(v.sep) : h; } try { return H.fromBytes(H.fromHex(v.text)); } catch (e) { return { error: "Not valid hex." }; } } },

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
    run(v) { const M = { A: ".-", B: "-...", C: "-.-.", D: "-..", E: ".", F: "..-.", G: "--.", H: "....", I: "..", J: ".---", K: "-.-", L: ".-..", M: "--", N: "-.", O: "---", P: ".--.", Q: "--.-", R: ".-.", S: "...", T: "-", U: "..-", V: "...-", W: ".--", X: "-..-", Y: "-.--", Z: "--..", "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.", "/": "-..-.", "@": ".--.-.", "-": "-....-", "(": "-.--.", ")": "-.--.-", ":": "---...", "=": "-...-", "+": ".-.-." }; if (!v.text) return ""; if (v.mode === "Text → Morse") return v.text.toUpperCase().split("").map((c) => c === " " ? "/" : (M[c] || "")).filter(Boolean).join(" "); const R = Object.fromEntries(Object.entries(M).map(([k, x]) => [x, k])); return v.text.trim().split(/\s+/).map((t) => t === "/" ? " " : (R[t] || "")).join(""); } },

  { id: "unicode-escape", name: "Unicode Escape / Unescape", cat: "encoding", desc: "Convert to \\uXXXX escapes and back.", tags: ["unicode", "\\u"],
    inputs: [{ k: "text", label: "Text", type: "textarea", placeholder: "café résumé naïve" }, { k: "mode", label: "Mode", type: "select", opts: ["Escape", "Unescape"], value: "Escape" }],
    run(v) { if (!v.text) return ""; if (v.mode === "Escape") return Array.from(v.text).map((c) => { const cp = c.codePointAt(0); if (cp > 126 || cp < 32) return cp > 0xffff ? "\\u{" + cp.toString(16) + "}" : "\\u" + cp.toString(16).padStart(4, "0"); return c; }).join(""); try { return v.text.replace(/\\u\{([0-9a-fA-F]+)\}|\\u([0-9a-fA-F]{4})/g, (m, a, b) => String.fromCodePoint(parseInt(a || b, 16))); } catch (e) { return { error: "Bad escape sequence." }; } } },

  { id: "json-string-escape", name: "JSON String Escaper", cat: "encoding", desc: "Escape text into a JSON string literal, or unescape one.", tags: ["json", "escape"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["Escape", "Unescape"], value: "Escape" }],
    run(v) { if (!v.text) return ""; if (v.mode === "Escape") return JSON.stringify(v.text); try { const t = v.text.trim(); return JSON.parse(t[0] === '"' ? t : '"' + t + '"'); } catch (e) { return { error: "Not a valid JSON string." }; } } },

  { id: "nato", name: "NATO Phonetic Alphabet", cat: "encoding", desc: "Spell text with Alfa, Bravo, Charlie…", tags: ["phonetic", "spell"],
    inputs: [{ k: "text", label: "Text", type: "textarea", placeholder: "SOS" }],
    run(v) { const N = { A: "Alfa", B: "Bravo", C: "Charlie", D: "Delta", E: "Echo", F: "Foxtrot", G: "Golf", H: "Hotel", I: "India", J: "Juliett", K: "Kilo", L: "Lima", M: "Mike", N: "November", O: "Oscar", P: "Papa", Q: "Quebec", R: "Romeo", S: "Sierra", T: "Tango", U: "Uniform", V: "Victor", W: "Whiskey", X: "X-ray", Y: "Yankee", Z: "Zulu" }; if (!v.text) return ""; return v.text.toUpperCase().split("").map((c) => /[0-9]/.test(c) ? c : (N[c] || (c === " " ? "|" : ""))).filter(Boolean).join(" "); } },

  { id: "leetspeak", name: "Leetspeak Converter", cat: "encoding", desc: "Convert text to and from 1337 5p34k.", tags: ["leet", "1337"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["To leet", "From leet"], value: "To leet" }],
    run(v) { if (!v.text) return ""; const to = { a: "4", e: "3", i: "1", o: "0", s: "5", t: "7", l: "1", g: "9", b: "8" }; if (v.mode === "To leet") return v.text.toLowerCase().replace(/[aeiostlgb]/g, (c) => to[c]); const from = { "4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "9": "g", "8": "b" }; return v.text.replace(/[43105798]/g, (c) => from[c]); } },

  { id: "a1z26", name: "A1Z26 Cipher", cat: "encoding", desc: "Letters to their alphabet position (A=1 … Z=26) and back.", tags: ["cipher", "number"],
    inputs: [{ k: "text", label: "Text or numbers", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["Text → Numbers", "Numbers → Text"], value: "Text → Numbers" }],
    run(v) { if (!v.text) return ""; if (v.mode === "Text → Numbers") return v.text.toLowerCase().replace(/[a-z]/g, (c) => (c.charCodeAt(0) - 96) + "-").replace(/-(\s|$)/g, "$1").replace(/-/g, " "); return v.text.trim().split(/[\s,]+/).map((n) => { const i = parseInt(n, 10); return i >= 1 && i <= 26 ? String.fromCharCode(96 + i) : ""; }).join(""); } },

  { id: "reverse-string", name: "String Reverser", cat: "encoding", desc: "Reverse characters (Unicode-aware).", tags: ["reverse"],
    inputs: [{ k: "text", label: "Text", type: "textarea" }],
    run(v) { return v.text ? Array.from(S(v.text)).reverse().join("") : ""; } },

  { id: "punycode", name: "Punycode (IDN) Converter", cat: "encoding", desc: "Convert internationalized domain names to/from ASCII (xn--).", tags: ["idn", "domain"],
    inputs: [{ k: "text", label: "Domain", type: "text", placeholder: "münchen.de" }, { k: "mode", label: "Mode", type: "select", opts: ["To ASCII", "To Unicode"], value: "To ASCII" }],
    run(v) { if (!v.text) return ""; try { const u = new URL("http://" + v.text.trim()); if (v.mode === "To ASCII") return u.hostname; try { return decodeURIComponent(escape(u.hostname)); } catch (_) {} return u.hostname; } catch (e) { return { error: "Enter a valid domain name." }; } } },
];
