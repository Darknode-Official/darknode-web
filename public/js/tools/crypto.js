// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Cryptography & PKI mini-tools: symmetric/asymmetric crypto via WebCrypto, key
// derivation, PEM/ASN.1/X.509 parsing, CTF number-theory and classic cryptanalysis.
// Pure client-side, deterministic (crypto RNG is allowed for generators). See _schema.md.

const S = (v) => (v == null ? "" : String(v));
const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = (typeof crypto !== "undefined" && crypto.subtle) ? crypto.subtle : null;

// ---- bytes / hex / base64 ----
function cleanHex(h) { return S(h).replace(/0x/gi, "").replace(/[^0-9a-fA-F]/g, ""); }
function hexToBytes(h) { h = cleanHex(h); if (h.length % 2) h = "0" + h; const u = new Uint8Array(h.length / 2); for (let i = 0; i < u.length; i++) u[i] = parseInt(h.substr(i * 2, 2), 16); return u; }
function bytesToHex(u) { return Array.from(u, (b) => b.toString(16).padStart(2, "0")).join(""); }
function bytesToB64(u) { let s = ""; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }
function b64urlOf(u) { return bytesToB64(u).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function b64ToBytes(s) { let t = S(s).replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, ""); while (t.length % 4) t += "="; const bin = atob(t); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
function textPreview(u) { try { const s = dec.decode(u); return /�/.test(s) ? null : s; } catch (e) { return null; } }

// ---- BigInt helpers ----
function parseBig(s) {
  s = S(s).trim();
  if (!s) return null;
  try {
    if (/^-?0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^-?\d+$/.test(s)) return BigInt(s);
    if (/^[0-9a-fA-F]+$/.test(s)) return BigInt("0x" + s);
  } catch (e) { return null; }
  return null;
}
function modpow(b, e, m) { if (m === 1n) return 0n; b %= m; if (b < 0n) b += m; let r = 1n; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
function egcd(a, b) { let os = 1n, s = 0n, ot = 0n, t = 1n, orr = a, r = b; while (r !== 0n) { const q = orr / r; [orr, r] = [r, orr - q * r]; [os, s] = [s, os - q * s]; [ot, t] = [t, ot - q * t]; } return [orr, os, ot]; }
function modinv(a, m) { a = ((a % m) + m) % m; const [g, x] = egcd(a, m); if (g !== 1n) return null; return ((x % m) + m) % m; }
function bigAbs(n) { return n < 0n ? -n : n; }
function gcdBig(a, b) { a = bigAbs(a); b = bigAbs(b); while (b) { [a, b] = [b, a % b]; } return a; }
function bigToBytes(n) { if (n < 0n) n = -n; let h = n.toString(16); if (h.length % 2) h = "0" + h; return hexToBytes(h); }
function bytesToBig(u) { let n = 0n; for (const b of u) n = (n << 8n) | BigInt(b); return n; }

// ---- Miller-Rabin ----
function isProbablePrime(n, rounds) {
  if (n < 2n) return false;
  for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) { if (n === p) return true; if (n % p === 0n) return false; }
  let d = n - 1n, r = 0n; while ((d & 1n) === 0n) { d >>= 1n; r++; }
  const bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
  const extra = rounds || 8;
  for (let i = 0; i < extra; i++) bases.push(2n + BigInt(Math.floor(Math.random() * 1e9)) % (n - 3n));
  for (const a of bases) {
    const aa = a % n; if (aa < 2n) continue;
    let x = modpow(aa, d, n);
    if (x === 1n || x === n - 1n) continue;
    let ok = false;
    for (let j = 1n; j < r; j++) { x = (x * x) % n; if (x === n - 1n) { ok = true; break; } }
    if (!ok) return false;
  }
  return true;
}

// ---- GF(2^8) for Shamir / AES field ----
function gfMul(a, b) { let p = 0; for (let i = 0; i < 8; i++) { if (b & 1) p ^= a; const hi = a & 0x80; a = (a << 1) & 0xff; if (hi) a ^= 0x1b; b >>= 1; } return p & 0xff; }
const GF_EXP = new Uint8Array(256), GF_LOG = new Uint8Array(256);
(function () { let x = 1; for (let i = 0; i < 255; i++) { GF_EXP[i] = x; GF_LOG[x] = i; x = gfMul(x, 3); } GF_EXP[255] = GF_EXP[0]; })();
function gfMulT(a, b) { return (a === 0 || b === 0) ? 0 : GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255]; }
function gfDiv(a, b) { if (b === 0) return 0; if (a === 0) return 0; return GF_EXP[((GF_LOG[a] - GF_LOG[b]) % 255 + 255) % 255]; }

// ---- ASN.1 / DER ----
function pemToDer(pem) { const m = S(pem).match(/-----BEGIN [^-]+-----([\s\S]*?)-----END/); const body = (m ? m[1] : pem).replace(/[^A-Za-z0-9+/=]/g, ""); return b64ToBytes(body); }
function pemLabel(pem) { const m = S(pem).match(/-----BEGIN ([^-]+)-----/); return m ? m[1].trim() : null; }
function derToPem(u, label) { const b = bytesToB64(u); const lines = b.match(/.{1,64}/g) || [""]; return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`; }
function anyToBytes(s) { s = S(s).trim(); if (/-----BEGIN/.test(s)) return pemToDer(s); const hx = s.replace(/\s+/g, ""); if (/^[0-9a-fA-F]+$/.test(hx) && hx.length % 2 === 0) return hexToBytes(hx); try { return b64ToBytes(s); } catch (e) { return hexToBytes(hx); } }
function parseASN1(bytes, start, end) {
  const nodes = []; let p = start;
  while (p < end) {
    const tagByte = bytes[p]; const cls = tagByte >> 6; const constructed = !!(tagByte & 0x20); let tagNum = tagByte & 0x1f; let hp = p + 1;
    if (tagNum === 0x1f) { tagNum = 0; let b; do { b = bytes[hp++]; tagNum = (tagNum << 7) | (b & 0x7f); } while (b & 0x80); }
    if (hp > end) throw new Error("truncated header");
    let len = bytes[hp++];
    if (len & 0x80) { const n = len & 0x7f; if (n > 6) throw new Error("length too large"); len = 0; for (let i = 0; i < n; i++) len = len * 256 + bytes[hp++]; }
    const contentStart = hp; const contentEnd = hp + len;
    if (contentEnd > end) throw new Error("length exceeds buffer");
    const node = { tagByte, cls, constructed, tagNum, start: p, headerLen: hp - p, length: len, contentStart, contentEnd, children: null };
    if (constructed) node.children = parseASN1(bytes, contentStart, contentEnd);
    nodes.push(node); p = contentEnd;
  }
  return nodes;
}
function decodeOID(bytes, s, e) {
  const parts = []; let v = 0n; let first = true;
  for (let i = s; i < e; i++) { const b = bytes[i]; v = (v << 7n) | BigInt(b & 0x7f); if (!(b & 0x80)) { if (first) { let a = v / 40n; if (a > 2n) a = 2n; parts.push(a.toString()); parts.push((v - a * 40n).toString()); first = false; } else parts.push(v.toString()); v = 0n; } }
  return parts.join(".");
}
const OID_NAMES = {
  "2.5.4.3": "commonName (CN)", "2.5.4.6": "countryName (C)", "2.5.4.7": "localityName (L)", "2.5.4.8": "stateOrProvinceName (ST)", "2.5.4.9": "streetAddress", "2.5.4.10": "organizationName (O)", "2.5.4.11": "organizationalUnitName (OU)", "2.5.4.5": "serialNumber", "2.5.4.4": "surname", "2.5.4.42": "givenName", "2.5.4.17": "postalCode",
  "1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "domainComponent (DC)", "0.9.2342.19200300.100.1.1": "userId (UID)",
  "1.2.840.113549.1.1.1": "rsaEncryption", "1.2.840.113549.1.1.5": "sha1WithRSAEncryption", "1.2.840.113549.1.1.11": "sha256WithRSAEncryption", "1.2.840.113549.1.1.12": "sha384WithRSAEncryption", "1.2.840.113549.1.1.13": "sha512WithRSAEncryption", "1.2.840.113549.1.1.10": "rsassaPss", "1.2.840.113549.1.1.8": "mgf1",
  "1.2.840.10045.2.1": "ecPublicKey", "1.2.840.10045.3.1.7": "prime256v1 / P-256", "1.3.132.0.34": "secp384r1 / P-384", "1.3.132.0.35": "secp521r1 / P-521", "1.3.132.0.10": "secp256k1",
  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256", "1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.2.840.10045.4.3.4": "ecdsa-with-SHA512", "1.2.840.10045.4.1": "ecdsa-with-SHA1",
  "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448", "1.3.101.110": "X25519", "1.3.101.111": "X448",
  "2.5.29.14": "subjectKeyIdentifier", "2.5.29.15": "keyUsage", "2.5.29.17": "subjectAltName", "2.5.29.18": "issuerAltName", "2.5.29.19": "basicConstraints", "2.5.29.31": "cRLDistributionPoints", "2.5.29.32": "certificatePolicies", "2.5.29.35": "authorityKeyIdentifier", "2.5.29.37": "extKeyUsage",
  "1.3.6.1.5.5.7.1.1": "authorityInfoAccess", "1.3.6.1.5.5.7.48.1": "OCSP", "1.3.6.1.5.5.7.48.2": "caIssuers", "1.3.6.1.5.5.7.3.1": "serverAuth", "1.3.6.1.5.5.7.3.2": "clientAuth", "1.3.6.1.5.5.7.3.3": "codeSigning", "1.3.6.1.5.5.7.3.4": "emailProtection", "1.3.6.1.5.5.7.3.8": "timeStamping", "1.3.6.1.5.5.7.3.9": "OCSPSigning",
  "1.3.6.1.4.1.11129.2.4.2": "signedCertificateTimestampList (CT)",
  "2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512", "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.1.2": "aes128-CBC", "2.16.840.1.101.3.4.1.22": "aes192-CBC", "2.16.840.1.101.3.4.1.42": "aes256-CBC", "2.16.840.1.101.3.4.1.6": "aes128-GCM", "2.16.840.1.101.3.4.1.26": "aes192-GCM", "2.16.840.1.101.3.4.1.46": "aes256-GCM",
  "1.2.840.113549.1.9.14": "extensionRequest", "1.2.840.113549.1.9.7": "challengePassword", "1.2.840.113549.3.7": "des-ede3-cbc", "1.2.840.113549.1.5.13": "pbes2", "1.2.840.113549.1.5.12": "pbkdf2",
};
const DN_SHORT = { "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.9": "STREET", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber", "2.5.4.4": "SN", "2.5.4.42": "GN", "2.5.4.17": "postalCode", "1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID" };

// ---- ChaCha20 (RFC 8439) ----
function rotl32(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
function chachaBlock(key, nonce, counter) {
  // key: 8 u32, nonce: 3 u32, counter: u32
  const s = new Uint32Array(16);
  s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) s[4 + i] = key[i];
  s[12] = counter >>> 0; s[13] = nonce[0]; s[14] = nonce[1]; s[15] = nonce[2];
  const x = s.slice();
  const QR = (a, b, c, d) => {
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 8);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 7);
  };
  for (let i = 0; i < 10; i++) { QR(0, 4, 8, 12); QR(1, 5, 9, 13); QR(2, 6, 10, 14); QR(3, 7, 11, 15); QR(0, 5, 10, 15); QR(1, 6, 11, 12); QR(2, 7, 8, 13); QR(3, 4, 9, 14); }
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) { const w = (x[i] + s[i]) >>> 0; out[i * 4] = w & 0xff; out[i * 4 + 1] = (w >>> 8) & 0xff; out[i * 4 + 2] = (w >>> 16) & 0xff; out[i * 4 + 3] = (w >>> 24) & 0xff; }
  return out;
}
function leU32(u8, o) { return (u8[o] | (u8[o + 1] << 8) | (u8[o + 2] << 16) | (u8[o + 3] << 24)) >>> 0; }
function chacha20(keyBytes, nonceBytes, counter, data) {
  const key = new Uint32Array(8); for (let i = 0; i < 8; i++) key[i] = leU32(keyBytes, i * 4);
  const nonce = new Uint32Array(3); for (let i = 0; i < 3; i++) nonce[i] = leU32(nonceBytes, i * 4);
  const out = new Uint8Array(data.length);
  for (let off = 0; off < data.length; off += 64) {
    const ks = chachaBlock(key, nonce, counter + (off / 64));
    for (let i = 0; i < 64 && off + i < data.length; i++) out[off + i] = data[off + i] ^ ks[i];
  }
  return out;
}

// ---- English scoring for XOR cryptanalysis ----
const ENG_FREQ = { " ": 13, e: 12.7, t: 9.1, a: 8.2, o: 7.5, i: 7, n: 6.7, s: 6.3, h: 6.1, r: 6, d: 4.3, l: 4, c: 2.8, u: 2.8, m: 2.4, w: 2.4, f: 2.2, g: 2, y: 2, p: 1.9, b: 1.5, v: 0.98, k: 0.77, j: 0.15, x: 0.15, q: 0.095, z: 0.074 };
function scoreEnglish(u) { let s = 0; for (const b of u) { if (b === 10 || b === 13 || b === 9) continue; if (b < 32 || b > 126) { s -= 30; continue; } const c = String.fromCharCode(b).toLowerCase(); s += ENG_FREQ[c] || 0.05; } return s; }
function hammingBits(a, b) { let d = 0; const n = Math.min(a.length, b.length); for (let i = 0; i < n; i++) { let x = a[i] ^ b[i]; while (x) { d += x & 1; x >>= 1; } } return d; }

// ---- WebCrypto algorithm helpers ----
function aesName(len) { return { 16: "AES-128", 24: "AES-192", 32: "AES-256" }[len] || null; }
function jwkAlgImport(jwk) {
  if (jwk.kty === "RSA") return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  if (jwk.kty === "EC") return { name: "ECDSA", namedCurve: jwk.crv };
  if (jwk.kty === "OKP") return { name: jwk.crv }; // Ed25519 / X25519
  return null;
}

export const TOOLS = [
  // ================= AES (WebCrypto) =================
  { id: "cr-aes-gcm-encrypt", name: "AES-GCM Encrypt", cat: "crypto", desc: "Authenticated AES-GCM encryption via WebCrypto. Key and IV are hex; output is ciphertext+tag as hex.", tags: ["aes", "gcm", "aead", "encrypt"], live: false, button: "Encrypt",
    inputs: [{ k: "key", label: "Key (hex, 16/24/32 bytes)", type: "text", placeholder: "00112233..." }, { k: "iv", label: "IV / nonce (hex, 12 bytes recommended)", type: "text" }, { k: "pt", label: "Plaintext", type: "textarea", rows: 3 }, { k: "aad", label: "Additional data (hex, optional)", type: "text" }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      const key = hexToBytes(v.key); if (!aesName(key.length)) return { error: "Key must be 16, 24 or 32 bytes of hex." };
      const iv = hexToBytes(v.iv); if (!iv.length) return { error: "IV required (hex)." };
      if (v.pt == null || v.pt === "") return "";
      try {
        const k = await subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]);
        const params = { name: "AES-GCM", iv }; if (v.aad && cleanHex(v.aad)) params.additionalData = hexToBytes(v.aad);
        const ct = new Uint8Array(await subtle.encrypt(params, k, enc.encode(v.pt)));
        const tag = ct.slice(ct.length - 16);
        return `Ciphertext+tag (hex):\n${bytesToHex(ct)}\n\nCiphertext only: ${bytesToHex(ct.slice(0, ct.length - 16))}\nTag (16 bytes): ${bytesToHex(tag)}\nBase64: ${bytesToB64(ct)}`;
      } catch (e) { return { error: "Encrypt failed: " + e.message }; }
    } },
  { id: "cr-aes-gcm-decrypt", name: "AES-GCM Decrypt", cat: "crypto", desc: "Decrypt and verify AES-GCM. Ciphertext (hex) must include the 16-byte tag appended. Fails if the tag is wrong.", tags: ["aes", "gcm", "aead", "decrypt"], live: false, button: "Decrypt",
    inputs: [{ k: "key", label: "Key (hex)", type: "text" }, { k: "iv", label: "IV / nonce (hex)", type: "text" }, { k: "ct", label: "Ciphertext+tag (hex)", type: "textarea", rows: 3 }, { k: "aad", label: "Additional data (hex, optional)", type: "text" }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      const key = hexToBytes(v.key); if (!aesName(key.length)) return { error: "Key must be 16, 24 or 32 bytes of hex." };
      const iv = hexToBytes(v.iv); if (!iv.length) return { error: "IV required." };
      if (!v.ct) return "";
      try {
        const k = await subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]);
        const params = { name: "AES-GCM", iv }; if (v.aad && cleanHex(v.aad)) params.additionalData = hexToBytes(v.aad);
        const pt = new Uint8Array(await subtle.decrypt(params, k, hexToBytes(v.ct)));
        const t = textPreview(pt);
        return `OK — tag verified.\n\nPlaintext${t == null ? " (hex, not UTF-8)" : ""}:\n${t == null ? bytesToHex(pt) : t}`;
      } catch (e) { return { error: "Decrypt/verify failed (wrong key, IV, AAD or tampered data)." }; }
    } },
  { id: "cr-aes-cbc-encrypt", name: "AES-CBC Encrypt (PKCS#7)", cat: "crypto", desc: "AES-CBC encryption with PKCS#7 padding via WebCrypto. Key and 16-byte IV are hex; output hex.", tags: ["aes", "cbc", "encrypt"], live: false, button: "Encrypt",
    inputs: [{ k: "key", label: "Key (hex, 16/24/32 bytes)", type: "text" }, { k: "iv", label: "IV (hex, 16 bytes)", type: "text" }, { k: "pt", label: "Plaintext", type: "textarea", rows: 3 }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      const key = hexToBytes(v.key); if (!aesName(key.length)) return { error: "Key must be 16, 24 or 32 bytes." };
      const iv = hexToBytes(v.iv); if (iv.length !== 16) return { error: "CBC IV must be exactly 16 bytes." };
      if (v.pt == null || v.pt === "") return "";
      try { const k = await subtle.importKey("raw", key, { name: "AES-CBC" }, false, ["encrypt"]); const ct = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, k, enc.encode(v.pt))); return `Ciphertext (hex):\n${bytesToHex(ct)}\n\nBase64: ${bytesToB64(ct)}`; } catch (e) { return { error: "Encrypt failed: " + e.message }; }
    } },
  { id: "cr-aes-cbc-decrypt", name: "AES-CBC Decrypt (PKCS#7)", cat: "crypto", desc: "AES-CBC decryption with PKCS#7 unpadding. Ciphertext is hex; key and IV hex.", tags: ["aes", "cbc", "decrypt"], live: false, button: "Decrypt",
    inputs: [{ k: "key", label: "Key (hex)", type: "text" }, { k: "iv", label: "IV (hex, 16 bytes)", type: "text" }, { k: "ct", label: "Ciphertext (hex)", type: "textarea", rows: 3 }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      const key = hexToBytes(v.key); if (!aesName(key.length)) return { error: "Key must be 16, 24 or 32 bytes." };
      const iv = hexToBytes(v.iv); if (iv.length !== 16) return { error: "CBC IV must be exactly 16 bytes." };
      if (!v.ct) return "";
      try { const k = await subtle.importKey("raw", key, { name: "AES-CBC" }, false, ["decrypt"]); const pt = new Uint8Array(await subtle.decrypt({ name: "AES-CBC", iv }, k, hexToBytes(v.ct))); const t = textPreview(pt); return `Plaintext${t == null ? " (hex)" : ""}:\n${t == null ? bytesToHex(pt) : t}`; } catch (e) { return { error: "Decrypt failed (wrong key/IV or bad padding)." }; }
    } },
  { id: "cr-aes-ctr-encrypt", name: "AES-CTR Encrypt", cat: "crypto", desc: "AES in counter mode (stream). Key and 16-byte initial counter block are hex; output hex. No padding.", tags: ["aes", "ctr", "stream", "encrypt"], live: false, button: "Encrypt",
    inputs: [{ k: "key", label: "Key (hex)", type: "text" }, { k: "ctr", label: "Initial counter block (hex, 16 bytes)", type: "text" }, { k: "bits", label: "Counter bits", type: "select", opts: ["32", "64", "128"], value: "64" }, { k: "pt", label: "Plaintext", type: "textarea", rows: 3 }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      const key = hexToBytes(v.key); if (!aesName(key.length)) return { error: "Key must be 16, 24 or 32 bytes." };
      const ctr = hexToBytes(v.ctr); if (ctr.length !== 16) return { error: "Counter block must be 16 bytes." };
      if (v.pt == null || v.pt === "") return "";
      try { const k = await subtle.importKey("raw", key, { name: "AES-CTR" }, false, ["encrypt"]); const out = new Uint8Array(await subtle.encrypt({ name: "AES-CTR", counter: ctr, length: parseInt(v.bits, 10) }, k, enc.encode(v.pt))); return `Ciphertext (hex):\n${bytesToHex(out)}\n\nBase64: ${bytesToB64(out)}`; } catch (e) { return { error: "Encrypt failed: " + e.message }; }
    } },
  { id: "cr-aes-ctr-decrypt", name: "AES-CTR Decrypt", cat: "crypto", desc: "Decrypt AES-CTR. Because CTR is a stream, this is identical to encryption; ciphertext is hex.", tags: ["aes", "ctr", "stream", "decrypt"], live: false, button: "Decrypt",
    inputs: [{ k: "key", label: "Key (hex)", type: "text" }, { k: "ctr", label: "Initial counter block (hex, 16 bytes)", type: "text" }, { k: "bits", label: "Counter bits", type: "select", opts: ["32", "64", "128"], value: "64" }, { k: "ct", label: "Ciphertext (hex)", type: "textarea", rows: 3 }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      const key = hexToBytes(v.key); if (!aesName(key.length)) return { error: "Key must be 16, 24 or 32 bytes." };
      const ctr = hexToBytes(v.ctr); if (ctr.length !== 16) return { error: "Counter block must be 16 bytes." };
      if (!v.ct) return "";
      try { const k = await subtle.importKey("raw", key, { name: "AES-CTR" }, false, ["decrypt"]); const pt = new Uint8Array(await subtle.decrypt({ name: "AES-CTR", counter: ctr, length: parseInt(v.bits, 10) }, k, hexToBytes(v.ct))); const t = textPreview(pt); return `Plaintext${t == null ? " (hex)" : ""}:\n${t == null ? bytesToHex(pt) : t}`; } catch (e) { return { error: "Decrypt failed: " + e.message }; }
    } },
  { id: "cr-aes-key-gen", name: "AES Key Generator", cat: "crypto", desc: "Generate a cryptographically random AES key (128/192/256-bit) as hex and base64.", tags: ["aes", "key", "generate", "random"], live: false, button: "Generate",
    inputs: [{ k: "bits", label: "Key size", type: "select", opts: ["128", "192", "256"], value: "256" }],
    run(v) { const n = parseInt(v.bits, 10) / 8; const u = new Uint8Array(n); crypto.getRandomValues(u); return `Key (${v.bits}-bit):\nhex    ${bytesToHex(u)}\nbase64 ${bytesToB64(u)}`; } },

  // ================= KDF =================
  { id: "cr-pbkdf2", name: "PBKDF2 Key Derivation", cat: "crypto", desc: "Derive bytes from a password with PBKDF2-HMAC (WebCrypto). Choose hash, iterations and output length.", tags: ["pbkdf2", "kdf", "derive", "password"], live: false, button: "Derive",
    inputs: [{ k: "pw", label: "Password", type: "text" }, { k: "salt", label: "Salt", type: "text", placeholder: "salt" }, { k: "salthex", label: "Salt is hex", type: "checkbox", value: false }, { k: "iter", label: "Iterations", type: "text", inputType: "number", value: "100000" }, { k: "hash", label: "Hash", type: "select", opts: ["SHA-256", "SHA-384", "SHA-512", "SHA-1"], value: "SHA-256" }, { k: "len", label: "Output bits", type: "text", inputType: "number", value: "256" }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      if (!v.pw) return "";
      const iter = parseInt(v.iter, 10) || 0; if (iter < 1) return { error: "Iterations must be >= 1." };
      const len = parseInt(v.len, 10) || 0; if (len < 8 || len % 8) return { error: "Output bits must be a multiple of 8." };
      const salt = v.salthex ? hexToBytes(v.salt) : enc.encode(v.salt || "");
      try { const bk = await subtle.importKey("raw", enc.encode(v.pw), { name: "PBKDF2" }, false, ["deriveBits"]); const bits = new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", salt, iterations: iter, hash: v.hash }, bk, len)); return `Derived (${len}-bit, ${iter} iters, ${v.hash}):\nhex    ${bytesToHex(bits)}\nbase64 ${bytesToB64(bits)}`; } catch (e) { return { error: "Derive failed: " + e.message }; }
    } },
  { id: "cr-hkdf", name: "HKDF Key Derivation", cat: "crypto", desc: "HKDF (extract-and-expand) from input key material via WebCrypto. IKM and salt are hex, info is text.", tags: ["hkdf", "kdf", "derive", "rfc5869"], live: false, button: "Derive",
    inputs: [{ k: "ikm", label: "Input key material (hex)", type: "text" }, { k: "salt", label: "Salt (hex, optional)", type: "text" }, { k: "info", label: "Info / context (text)", type: "text" }, { k: "hash", label: "Hash", type: "select", opts: ["SHA-256", "SHA-384", "SHA-512", "SHA-1"], value: "SHA-256" }, { k: "len", label: "Output bits", type: "text", inputType: "number", value: "256" }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      const ikm = hexToBytes(v.ikm); if (!ikm.length) return "";
      const len = parseInt(v.len, 10) || 0; if (len < 8 || len % 8) return { error: "Output bits must be a multiple of 8." };
      try { const bk = await subtle.importKey("raw", ikm, { name: "HKDF" }, false, ["deriveBits"]); const bits = new Uint8Array(await subtle.deriveBits({ name: "HKDF", salt: hexToBytes(v.salt || ""), info: enc.encode(v.info || ""), hash: v.hash }, bk, len)); return `Derived (${len}-bit, ${v.hash}):\nhex    ${bytesToHex(bits)}\nbase64 ${bytesToB64(bits)}`; } catch (e) { return { error: "Derive failed: " + e.message }; }
    } },
  { id: "cr-kdf-advisor", name: "Password KDF Cost Advisor", cat: "crypto", desc: "OWASP-aligned work-factor guidance for Argon2id, scrypt, bcrypt and PBKDF2 password hashing.", tags: ["argon2", "bcrypt", "scrypt", "pbkdf2", "owasp"], live: true,
    inputs: [{ k: "algo", label: "Algorithm", type: "select", opts: ["Argon2id", "scrypt", "bcrypt", "PBKDF2"], value: "Argon2id" }],
    run(v) {
      const g = {
        "Argon2id": "OWASP minimum configurations (any one):\n  m=19 MiB, t=2, p=1\n  m=12 MiB, t=3, p=1\n  m=7  MiB, t=4, p=1\nPrefer Argon2id for new systems. Raise memory first, then iterations, until one hash takes ~0.5-1s on your hardware.",
        "scrypt": "OWASP minimum configurations (any one):\n  N=2^17 (131072), r=8, p=1  -> ~128 MiB\n  N=2^16 (65536),  r=8, p=2\n  N=2^15 (32768),  r=8, p=3\nMemory cost = 128 * N * r bytes. Use if Argon2 is unavailable.",
        "bcrypt": "Work factor (cost) 10 or higher; many sites now use 12. Each +1 doubles the time.\nNote bcrypt silently truncates passwords beyond 72 bytes; pre-hash long inputs.",
        "PBKDF2": "OWASP iteration minimums:\n  PBKDF2-HMAC-SHA256 : 600,000 iterations\n  PBKDF2-HMAC-SHA512 : 210,000 iterations\n  PBKDF2-HMAC-SHA1   : 1,300,000 iterations\nUse a 128-bit+ random salt per password. PBKDF2 has no memory hardness; prefer Argon2id/scrypt if you can.",
      };
      return `${v.algo} password-hashing guidance\n\n${g[v.algo]}\n\n(Source: OWASP Password Storage Cheat Sheet. Always benchmark on your own hardware and re-check current OWASP numbers.)`;
    } },

  // ================= Asymmetric keygen / sign =================
  { id: "cr-rsa-keygen", name: "RSA Keypair Generator", cat: "crypto", desc: "Generate an RSA keypair and export the public key (SPKI PEM) and private key (PKCS#8 PEM) plus JWKs.", tags: ["rsa", "keypair", "pem", "jwk", "generate"], live: false, button: "Generate",
    inputs: [{ k: "bits", label: "Modulus size", type: "select", opts: ["2048", "3072", "4096"], value: "2048" }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      try {
        const kp = await subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: parseInt(v.bits, 10), publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
        const spki = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));
        const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
        const jwk = await subtle.exportKey("jwk", kp.publicKey);
        return `${derToPem(spki, "PUBLIC KEY")}\n\n${derToPem(pkcs8, "PRIVATE KEY")}\n\nPublic JWK:\n${JSON.stringify({ kty: jwk.kty, n: jwk.n, e: jwk.e }, null, 2)}`;
      } catch (e) { return { error: "Keygen failed: " + e.message }; }
    } },
  { id: "cr-ecdsa-keygen", name: "ECDSA Keypair Generator", cat: "crypto", desc: "Generate an elliptic-curve (P-256/P-384/P-521) keypair and export PEM and JWK.", tags: ["ecdsa", "ec", "keypair", "pem", "jwk"], live: false, button: "Generate",
    inputs: [{ k: "curve", label: "Curve", type: "select", opts: ["P-256", "P-384", "P-521"], value: "P-256" }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      try {
        const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: v.curve }, true, ["sign", "verify"]);
        const spki = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));
        const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
        const jwk = await subtle.exportKey("jwk", kp.publicKey);
        return `Curve ${v.curve}\n\n${derToPem(spki, "PUBLIC KEY")}\n\n${derToPem(pkcs8, "PRIVATE KEY")}\n\nPublic JWK:\n${JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, null, 2)}`;
      } catch (e) { return { error: "Keygen failed: " + e.message }; }
    } },
  { id: "cr-ed25519-keygen", name: "Ed25519 Keypair Generator", cat: "crypto", desc: "Generate an Ed25519 signing keypair and export SPKI/PKCS#8 PEM and JWK.", tags: ["ed25519", "eddsa", "keypair", "pem"], live: false, button: "Generate",
    inputs: [],
    async run() {
      if (!subtle) return { error: "WebCrypto unavailable." };
      try {
        const kp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
        const spki = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));
        const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
        const jwk = await subtle.exportKey("jwk", kp.publicKey);
        return `${derToPem(spki, "PUBLIC KEY")}\n\n${derToPem(pkcs8, "PRIVATE KEY")}\n\nPublic JWK:\n${JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x }, null, 2)}`;
      } catch (e) { return { error: "Ed25519 not supported here: " + e.message }; }
    } },
  { id: "cr-x25519-keygen", name: "X25519 Keypair Generator", cat: "crypto", desc: "Generate an X25519 (ECDH) keypair for key agreement and export PEM and JWK.", tags: ["x25519", "ecdh", "keypair", "curve25519"], live: false, button: "Generate",
    inputs: [],
    async run() {
      if (!subtle) return { error: "WebCrypto unavailable." };
      try {
        const kp = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
        const spki = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));
        const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
        const jwk = await subtle.exportKey("jwk", kp.publicKey);
        return `${derToPem(spki, "PUBLIC KEY")}\n\n${derToPem(pkcs8, "PRIVATE KEY")}\n\nPublic JWK:\n${JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x }, null, 2)}`;
      } catch (e) { return { error: "X25519 not supported here: " + e.message }; }
    } },
  { id: "cr-rsa-sign", name: "RSA Sign", cat: "crypto", desc: "Sign a message with an RSA private key (PKCS#8 PEM) using PKCS#1 v1.5 or PSS. Output signature base64.", tags: ["rsa", "sign", "signature"], live: false, button: "Sign",
    inputs: [{ k: "pem", label: "Private key (PKCS#8 PEM)", type: "textarea", rows: 5 }, { k: "msg", label: "Message", type: "textarea", rows: 2 }, { k: "scheme", label: "Scheme", type: "select", opts: ["PKCS1v1.5", "PSS"], value: "PKCS1v1.5" }, { k: "hash", label: "Hash", type: "select", opts: ["SHA-256", "SHA-384", "SHA-512"], value: "SHA-256" }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      if (!v.pem || v.msg == null) return "";
      const algName = v.scheme === "PSS" ? "RSA-PSS" : "RSASSA-PKCS1-v1_5";
      try {
        const k = await subtle.importKey("pkcs8", pemToDer(v.pem), { name: algName, hash: v.hash }, false, ["sign"]);
        const params = v.scheme === "PSS" ? { name: "RSA-PSS", saltLength: { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 }[v.hash] } : { name: algName };
        const sig = new Uint8Array(await subtle.sign(params, k, enc.encode(v.msg)));
        return `Signature (${v.scheme}, ${v.hash}):\nbase64 ${bytesToB64(sig)}\nhex    ${bytesToHex(sig)}`;
      } catch (e) { return { error: "Sign failed: " + e.message }; }
    } },
  { id: "cr-rsa-verify", name: "RSA Verify", cat: "crypto", desc: "Verify an RSA signature (base64) against a message and an RSA public key (SPKI PEM).", tags: ["rsa", "verify", "signature"], live: false, button: "Verify",
    inputs: [{ k: "pem", label: "Public key (SPKI PEM)", type: "textarea", rows: 5 }, { k: "msg", label: "Message", type: "textarea", rows: 2 }, { k: "sig", label: "Signature (base64)", type: "textarea", rows: 2 }, { k: "scheme", label: "Scheme", type: "select", opts: ["PKCS1v1.5", "PSS"], value: "PKCS1v1.5" }, { k: "hash", label: "Hash", type: "select", opts: ["SHA-256", "SHA-384", "SHA-512"], value: "SHA-256" }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      if (!v.pem || !v.sig || v.msg == null) return "";
      const algName = v.scheme === "PSS" ? "RSA-PSS" : "RSASSA-PKCS1-v1_5";
      try {
        const k = await subtle.importKey("spki", pemToDer(v.pem), { name: algName, hash: v.hash }, false, ["verify"]);
        const params = v.scheme === "PSS" ? { name: "RSA-PSS", saltLength: { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 }[v.hash] } : { name: algName };
        const ok = await subtle.verify(params, k, b64ToBytes(v.sig), enc.encode(v.msg));
        return ok ? "VALID — signature matches." : "INVALID — signature does not match.";
      } catch (e) { return { error: "Verify failed: " + e.message }; }
    } },
  { id: "cr-ecdsa-sign", name: "ECDSA Sign", cat: "crypto", desc: "Sign a message with an EC private key (PKCS#8 PEM). Output is the raw r||s signature as base64/hex.", tags: ["ecdsa", "ec", "sign"], live: false, button: "Sign",
    inputs: [{ k: "pem", label: "Private key (PKCS#8 PEM)", type: "textarea", rows: 4 }, { k: "curve", label: "Curve", type: "select", opts: ["P-256", "P-384", "P-521"], value: "P-256" }, { k: "msg", label: "Message", type: "textarea", rows: 2 }, { k: "hash", label: "Hash", type: "select", opts: ["SHA-256", "SHA-384", "SHA-512"], value: "SHA-256" }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      if (!v.pem || v.msg == null) return "";
      try { const k = await subtle.importKey("pkcs8", pemToDer(v.pem), { name: "ECDSA", namedCurve: v.curve }, false, ["sign"]); const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: v.hash }, k, enc.encode(v.msg))); return `Signature (raw r||s):\nbase64 ${bytesToB64(sig)}\nhex    ${bytesToHex(sig)}`; } catch (e) { return { error: "Sign failed: " + e.message }; }
    } },
  { id: "cr-ecdsa-verify", name: "ECDSA Verify", cat: "crypto", desc: "Verify an ECDSA raw (r||s) signature in base64 against a message and EC public key (SPKI PEM).", tags: ["ecdsa", "ec", "verify"], live: false, button: "Verify",
    inputs: [{ k: "pem", label: "Public key (SPKI PEM)", type: "textarea", rows: 4 }, { k: "curve", label: "Curve", type: "select", opts: ["P-256", "P-384", "P-521"], value: "P-256" }, { k: "msg", label: "Message", type: "textarea", rows: 2 }, { k: "sig", label: "Signature (base64, raw r||s)", type: "textarea", rows: 2 }, { k: "hash", label: "Hash", type: "select", opts: ["SHA-256", "SHA-384", "SHA-512"], value: "SHA-256" }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      if (!v.pem || !v.sig || v.msg == null) return "";
      try { const k = await subtle.importKey("spki", pemToDer(v.pem), { name: "ECDSA", namedCurve: v.curve }, false, ["verify"]); const ok = await subtle.verify({ name: "ECDSA", hash: v.hash }, k, b64ToBytes(v.sig), enc.encode(v.msg)); return ok ? "VALID — signature matches." : "INVALID — signature does not match."; } catch (e) { return { error: "Verify failed: " + e.message }; }
    } },

  // ================= JWK / PEM =================
  { id: "cr-jwk-to-pem", name: "JWK to PEM", cat: "crypto", desc: "Convert an RSA/EC/OKP JWK to PEM (SPKI for public, PKCS#8 for private) via WebCrypto import/export.", tags: ["jwk", "pem", "convert", "key"], live: false, button: "Convert",
    inputs: [{ k: "jwk", label: "JWK (JSON)", type: "textarea", rows: 6 }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      if (!v.jwk) return "";
      let jwk; try { jwk = JSON.parse(v.jwk); } catch (e) { return { error: "Not valid JSON." }; }
      const alg = jwkAlgImport(jwk); if (!alg) return { error: "Unsupported kty (expected RSA, EC or OKP)." };
      const isPriv = !!jwk.d; const usages = alg.name === "X25519" ? (isPriv ? ["deriveBits"] : []) : (isPriv ? ["sign"] : ["verify"]);
      try {
        const k = await subtle.importKey("jwk", jwk, alg, true, usages);
        const fmt = isPriv ? "pkcs8" : "spki"; const der = new Uint8Array(await subtle.exportKey(fmt, k));
        return derToPem(der, isPriv ? "PRIVATE KEY" : "PUBLIC KEY");
      } catch (e) { return { error: "Convert failed: " + e.message }; }
    } },
  { id: "cr-pem-to-jwk", name: "PEM to JWK", cat: "crypto", desc: "Convert an SPKI/PKCS#8 PEM key to a JWK. The algorithm is detected from the key's ASN.1 structure.", tags: ["pem", "jwk", "convert", "key"], live: false, button: "Convert",
    inputs: [{ k: "pem", label: "PEM (PUBLIC KEY or PRIVATE KEY)", type: "textarea", rows: 6 }],
    async run(v) {
      if (!subtle) return { error: "WebCrypto unavailable." };
      if (!v.pem) return "";
      const label = pemLabel(v.pem) || ""; const isPriv = /PRIVATE/.test(label); const der = pemToDer(v.pem);
      // find algorithm OID
      let oid = "";
      try {
        const top = parseASN1(der, 0, der.length)[0];
        const algId = isPriv ? top.children[1] : top.children[0];
        const oidNode = algId.children[0]; oid = decodeOID(der, oidNode.contentStart, oidNode.contentEnd);
      } catch (e) { return { error: "Could not parse key structure." }; }
      let alg, usages;
      if (oid === "1.2.840.113549.1.1.1") { alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }; usages = isPriv ? ["sign"] : ["verify"]; }
      else if (oid === "1.2.840.10045.2.1") {
        // EC: curve from param OID
        let crv = "P-256";
        try { const top = parseASN1(der, 0, der.length)[0]; const algId = isPriv ? top.children[1] : top.children[0]; const paramNode = algId.children[1]; const cOid = decodeOID(der, paramNode.contentStart, paramNode.contentEnd); crv = { "1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521" }[cOid] || "P-256"; } catch (e) {}
        alg = { name: "ECDSA", namedCurve: crv }; usages = isPriv ? ["sign"] : ["verify"];
      } else if (oid === "1.3.101.112") { alg = { name: "Ed25519" }; usages = isPriv ? ["sign"] : ["verify"]; }
      else if (oid === "1.3.101.110") { alg = { name: "X25519" }; usages = isPriv ? ["deriveBits"] : []; }
      else return { error: "Unsupported key algorithm OID " + oid };
      try { const k = await subtle.importKey(isPriv ? "pkcs8" : "spki", der, alg, true, usages); const jwk = await subtle.exportKey("jwk", k); return JSON.stringify(jwk, null, 2); } catch (e) { return { error: "Convert failed: " + e.message }; }
    } },
  { id: "cr-jwk-thumbprint", name: "JWK Thumbprint (RFC 7638)", cat: "crypto", desc: "Compute the SHA-256 JWK thumbprint over the canonical required members, as base64url (the 'kid').", tags: ["jwk", "thumbprint", "rfc7638", "kid"], live: false, button: "Compute",
    inputs: [{ k: "jwk", label: "JWK (JSON)", type: "textarea", rows: 6 }],
    async run(v, H) {
      if (!v.jwk) return "";
      let jwk; try { jwk = JSON.parse(v.jwk); } catch (e) { return { error: "Not valid JSON." }; }
      let obj;
      if (jwk.kty === "RSA") obj = { e: jwk.e, kty: "RSA", n: jwk.n };
      else if (jwk.kty === "EC") obj = { crv: jwk.crv, kty: "EC", x: jwk.x, y: jwk.y };
      else if (jwk.kty === "OKP") obj = { crv: jwk.crv, kty: "OKP", x: jwk.x };
      else if (jwk.kty === "oct") obj = { k: jwk.k, kty: "oct" };
      else return { error: "Unsupported kty." };
      for (const [kk, vv] of Object.entries(obj)) if (vv == null) return { error: `Missing required member "${kk}" for kty ${jwk.kty}.` };
      const canon = JSON.stringify(obj);
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(canon)));
      return `Canonical JSON: ${canon}\n\nThumbprint (base64url): ${b64urlOf(digest)}\nThumbprint (hex):       ${bytesToHex(digest)}`;
    } },

  // ================= PEM / ASN.1 / X.509 =================
  { id: "cr-pem-inspect", name: "PEM Inspector", cat: "crypto", desc: "Identify a PEM block's label, decode its base64 body and report the DER length and leading bytes.", tags: ["pem", "inspect", "der"], live: true,
    inputs: [{ k: "pem", label: "PEM block", type: "textarea", rows: 6 }],
    run(v) {
      if (!v.pem) return "";
      const label = pemLabel(v.pem); if (!label) return { error: "No PEM header found (expected -----BEGIN ...-----)." };
      let der; try { der = pemToDer(v.pem); } catch (e) { return { error: "Base64 body is malformed." }; }
      let kind = "unknown"; try { const n = parseASN1(der, 0, der.length)[0]; kind = n.tagByte === 0x30 ? "SEQUENCE (valid DER top)" : "0x" + n.tagByte.toString(16); } catch (e) { kind = "not parseable as DER"; }
      return `Label:       ${label}\nDER length:  ${der.length} bytes\nTop element: ${kind}\nFirst bytes: ${bytesToHex(der.slice(0, Math.min(16, der.length)))}\n\nTip: use the ASN.1 DER Decoder or X.509 Parser for the full structure.`;
    } },
  { id: "cr-pem-wrap", name: "DER / PEM Converter", cat: "crypto", desc: "Wrap raw DER (hex or base64) into a PEM block with a chosen label, or unwrap a PEM block back to DER hex.", tags: ["der", "pem", "wrap", "convert"], live: true,
    inputs: [{ k: "mode", label: "Direction", type: "select", opts: ["DER to PEM", "PEM to DER"], value: "DER to PEM" }, { k: "label", label: "PEM label (for DER to PEM)", type: "text", value: "CERTIFICATE" }, { k: "data", label: "Input (DER hex/base64, or PEM)", type: "textarea", rows: 5 }],
    run(v) {
      if (!v.data) return "";
      if (v.mode === "DER to PEM") { let der; try { der = anyToBytes(v.data); } catch (e) { return { error: "Input is not valid hex/base64." }; } if (!der.length) return { error: "No bytes decoded." }; return derToPem(der, (v.label || "DATA").toUpperCase()); }
      const label = pemLabel(v.data); if (!label) return { error: "No PEM header found." }; const der = pemToDer(v.data); return `Label: ${label}\nDER (${der.length} bytes) hex:\n${bytesToHex(der)}\n\nBase64:\n${bytesToB64(der)}`;
    } },
  { id: "cr-asn1-decode", name: "ASN.1 DER Decoder", cat: "crypto", desc: "Recursively decode ASN.1 DER (from hex, base64 or PEM) into a readable tag/length/value tree with OID names.", tags: ["asn1", "der", "decode", "tlv"], live: true,
    inputs: [{ k: "data", label: "DER (hex / base64 / PEM)", type: "textarea", rows: 6 }],
    run(v) {
      if (!v.data) return "";
      let bytes; try { bytes = anyToBytes(v.data); } catch (e) { return { error: "Could not read input as hex/base64/PEM." }; }
      if (!bytes.length) return { error: "No bytes to decode." };
      const TAG = { 1: "BOOLEAN", 2: "INTEGER", 3: "BIT STRING", 4: "OCTET STRING", 5: "NULL", 6: "OBJECT IDENTIFIER", 10: "ENUMERATED", 12: "UTF8String", 19: "PrintableString", 20: "T61String", 22: "IA5String", 23: "UTCTime", 24: "GeneralizedTime", 26: "VisibleString", 48: "SEQUENCE", 49: "SET" };
      const lines = [];
      function walk(nodes, depth) {
        for (const n of nodes) {
          const ind = "  ".repeat(depth);
          let name = n.cls === 0 ? (TAG[n.tagByte] || TAG[n.tagNum] || ("tag " + n.tagNum)) : (n.cls === 2 ? `[${n.tagNum}]` : `class${n.cls} tag${n.tagNum}`);
          let extra = "";
          if (!n.constructed) {
            const c = bytes.slice(n.contentStart, n.contentEnd);
            if (n.tagByte === 0x06) extra = decodeOID(bytes, n.contentStart, n.contentEnd) + (OID_NAMES[decodeOID(bytes, n.contentStart, n.contentEnd)] ? " (" + OID_NAMES[decodeOID(bytes, n.contentStart, n.contentEnd)] + ")" : "");
            else if (n.tagByte === 0x02) { const bi = bytesToBig(c); extra = c.length <= 8 ? bi.toString() : "0x" + bytesToHex(c); }
            else if (n.tagByte === 0x01) extra = c[0] ? "TRUE" : "FALSE";
            else if (n.tagByte === 0x05) extra = "";
            else if (n.tagByte === 0x13 || n.tagByte === 0x0c || n.tagByte === 0x16 || n.tagByte === 0x1a) extra = JSON.stringify(dec.decode(c));
            else if (n.tagByte === 0x17 || n.tagByte === 0x18) extra = dec.decode(c);
            else extra = (c.length <= 32 ? bytesToHex(c) : bytesToHex(c.slice(0, 32)) + "...");
          }
          lines.push(`${ind}${name}${n.constructed ? "" : " len=" + n.length}${extra ? "  " + extra : ""}`);
          if (n.children) walk(n.children, depth + 1);
        }
      }
      try { walk(parseASN1(bytes, 0, bytes.length), 0); } catch (e) { return { error: "DER parse error: " + e.message }; }
      return lines.join("\n");
    } },
  { id: "cr-x509-parse", name: "X.509 Certificate Parser", cat: "crypto", desc: "Parse a PEM/DER X.509 certificate: version, serial, issuer, subject, validity, public key, SAN and extensions.", tags: ["x509", "certificate", "ssl", "tls", "parse"], live: false, button: "Parse",
    inputs: [{ k: "pem", label: "Certificate (PEM or DER hex/base64)", type: "textarea", rows: 8 }],
    run(v) {
      if (!v.pem) return "";
      let bytes; try { bytes = anyToBytes(v.pem); } catch (e) { return { error: "Could not read certificate." }; }
      try { return parseCertificate(bytes); } catch (e) { return { error: "Parse failed: " + e.message }; }
    } },
  { id: "cr-csr-parse", name: "CSR (PKCS#10) Parser", cat: "crypto", desc: "Parse a certificate signing request: subject, public-key algorithm/size, signature algorithm and requested SANs.", tags: ["csr", "pkcs10", "certificate", "request", "parse"], live: false, button: "Parse",
    inputs: [{ k: "pem", label: "CSR (PEM or DER hex/base64)", type: "textarea", rows: 8 }],
    run(v) {
      if (!v.pem) return "";
      let bytes; try { bytes = anyToBytes(v.pem); } catch (e) { return { error: "Could not read CSR." }; }
      try { return parseCSR(bytes); } catch (e) { return { error: "Parse failed: " + e.message }; }
    } },
  { id: "cr-cert-fingerprint", name: "Certificate Fingerprint", cat: "crypto", desc: "Compute SHA-256 / SHA-1 fingerprints of an X.509 certificate's DER (the values browsers display).", tags: ["x509", "fingerprint", "thumbprint", "sha256"], live: false, button: "Compute",
    inputs: [{ k: "pem", label: "Certificate (PEM or DER)", type: "textarea", rows: 6 }],
    async run(v) {
      if (!v.pem) return "";
      let der; try { der = anyToBytes(v.pem); } catch (e) { return { error: "Could not read certificate." }; }
      const colon = (h) => h.match(/.{2}/g).join(":").toUpperCase();
      const s256 = new Uint8Array(await crypto.subtle.digest("SHA-256", der));
      const s1 = new Uint8Array(await crypto.subtle.digest("SHA-1", der));
      return `SHA-256:\n${colon(bytesToHex(s256))}\n\nSHA-1:\n${colon(bytesToHex(s1))}`;
    } },
  { id: "cr-oid-lookup", name: "OID Lookup", cat: "crypto", desc: "Look up a cryptography/X.509 object identifier by dotted OID or by name (RSA, ecPublicKey, subjectAltName, ...).", tags: ["oid", "asn1", "x509", "lookup"], live: true,
    inputs: [{ k: "q", label: "OID or name", type: "text", placeholder: "2.5.29.17 or subjectAltName" }],
    run(v) {
      if (!v.q) return "";
      const q = v.q.trim().toLowerCase();
      if (OID_NAMES[v.q.trim()]) return `${v.q.trim()}  =  ${OID_NAMES[v.q.trim()]}`;
      const hits = Object.entries(OID_NAMES).filter(([oid, name]) => oid.includes(q) || name.toLowerCase().includes(q));
      if (!hits.length) return { error: "No match in the built-in table." };
      return hits.slice(0, 20).map(([oid, name]) => `${oid.padEnd(32)} ${name}`).join("\n") + (hits.length > 20 ? `\n... (${hits.length - 20} more)` : "");
    } },
  { id: "cr-key-strength", name: "Key Strength Advisor", cat: "crypto", desc: "Map an RSA/ECC/symmetric/hash size to its approximate security level in bits (NIST SP 800-57) with a verdict.", tags: ["key", "strength", "nist", "security level"], live: true,
    inputs: [{ k: "type", label: "Algorithm", type: "select", opts: ["RSA/DH (modulus bits)", "ECC (curve bits)", "Symmetric (key bits)", "Hash (output bits)"], value: "RSA/DH (modulus bits)" }, { k: "size", label: "Size (bits)", type: "text", inputType: "number", value: "2048" }],
    run(v) {
      const n = parseInt(v.size, 10); if (!n || n < 1) return { error: "Enter a positive bit size." };
      let bits, note;
      if (v.type.startsWith("RSA")) { const tab = [[1024, 80], [2048, 112], [3072, 128], [7680, 192], [15360, 256]]; bits = 0; for (const [m, b] of tab) if (n >= m) bits = b; note = n < 2048 ? "Below 2048-bit is deprecated." : "2048-bit = ~112-bit, acceptable through ~2030; use 3072-bit for 128-bit strength."; }
      else if (v.type.startsWith("ECC")) { bits = Math.floor(n / 2); note = n < 256 ? "Below 256-bit curves are discouraged." : "ECC security level is about half the curve size."; }
      else if (v.type.startsWith("Symmetric")) { bits = n; note = n < 128 ? "Below 128-bit symmetric keys are not recommended." : "Symmetric key strength equals the key length."; }
      else { bits = Math.floor(n / 2); note = "Collision resistance is about half the digest size; preimage resistance is the full size."; }
      const verdict = bits >= 128 ? "STRONG (>=128-bit)" : bits >= 112 ? "ACCEPTABLE near-term (112-bit)" : "WEAK — do not use for new systems";
      return `Algorithm:       ${v.type}\nSize:            ${n} bits\nSecurity level:  ~${bits}-bit\nVerdict:         ${verdict}\n\n${note}\n(Per NIST SP 800-57 Part 1 equivalent-strength guidance.)`;
    } },
  { id: "cr-ec-curve-ref", name: "Elliptic Curve Reference", cat: "crypto", desc: "Key parameters for common curves: field/order size, security level, OID and typical use.", tags: ["ecc", "curve", "p-256", "secp256k1", "curve25519", "reference"], live: true,
    inputs: [{ k: "curve", label: "Curve", type: "select", opts: ["P-256 (secp256r1)", "P-384 (secp384r1)", "P-521 (secp521r1)", "secp256k1", "Curve25519 / Ed25519"], value: "P-256 (secp256r1)" }],
    run(v) {
      const T = {
        "P-256 (secp256r1)": { field: 256, order: 256, sec: 128, oid: "1.2.840.10045.3.1.7", use: "TLS, JWT ES256, general ECDSA/ECDH. NIST prime curve." },
        "P-384 (secp384r1)": { field: 384, order: 384, sec: 192, oid: "1.3.132.0.34", use: "Higher-assurance TLS, JWT ES384. NIST prime curve." },
        "P-521 (secp521r1)": { field: 521, order: 521, sec: 256, oid: "1.3.132.0.35", use: "Top-level NIST curve, JWT ES512." },
        "secp256k1": { field: 256, order: 256, sec: 128, oid: "1.3.132.0.10", use: "Bitcoin/Ethereum ECDSA. Koblitz curve, not a NIST TLS curve." },
        "Curve25519 / Ed25519": { field: 255, order: 253, sec: 128, oid: "1.3.101.112 (Ed25519), 1.3.101.110 (X25519)", use: "Ed25519 signatures, X25519 key exchange. Fast, misuse-resistant." },
      };
      const c = T[v.curve];
      return `${v.curve}\n  Field size:      ${c.field}-bit prime field\n  Subgroup order:  ~${c.order}-bit\n  Security level:  ~${c.sec}-bit\n  OID:             ${c.oid}\n  Typical use:     ${c.use}`;
    } },

  // ================= PKCS#7 / modes / explainers =================
  { id: "cr-pkcs7-pad", name: "PKCS#7 Pad", cat: "crypto", desc: "Apply PKCS#7 (PKCS#5) padding to data up to a block boundary. Input is text or hex; output hex.", tags: ["pkcs7", "pkcs5", "padding", "block"], live: true,
    inputs: [{ k: "data", label: "Data", type: "text" }, { k: "hex", label: "Input is hex", type: "checkbox", value: false }, { k: "block", label: "Block size (bytes)", type: "select", opts: ["8", "16"], value: "16" }],
    run(v) {
      if (v.data == null || v.data === "") return "";
      const block = parseInt(v.block, 10); const d = v.hex ? hexToBytes(v.data) : enc.encode(v.data);
      const pad = block - (d.length % block); const out = new Uint8Array(d.length + pad); out.set(d); for (let i = 0; i < pad; i++) out[d.length + i] = pad;
      return `Padded (${pad} byte${pad > 1 ? "s" : ""} of 0x${pad.toString(16).padStart(2, "0")}):\n${bytesToHex(out)}`;
    } },
  { id: "cr-pkcs7-unpad", name: "PKCS#7 Unpad / Validate", cat: "crypto", desc: "Validate and strip PKCS#7 padding from hex data. Reports whether the padding is well-formed (padding-oracle basics).", tags: ["pkcs7", "unpad", "padding", "oracle"], live: true,
    inputs: [{ k: "data", label: "Data (hex)", type: "text" }, { k: "block", label: "Block size (bytes)", type: "select", opts: ["8", "16"], value: "16" }],
    run(v) {
      if (!v.data) return "";
      const block = parseInt(v.block, 10); const d = hexToBytes(v.data);
      if (!d.length || d.length % block) return { error: `Length ${d.length} is not a multiple of block size ${block}.` };
      const pad = d[d.length - 1];
      if (pad < 1 || pad > block) return { error: `Invalid padding: last byte is 0x${pad.toString(16)} (must be 1..${block}).` };
      for (let i = d.length - pad; i < d.length; i++) if (d[i] !== pad) return { error: `Invalid padding: byte at ${i} is 0x${d[i].toString(16)}, expected 0x${pad.toString(16)}.` };
      const msg = d.slice(0, d.length - pad); const t = textPreview(msg);
      return `Valid padding (${pad} byte${pad > 1 ? "s" : ""} stripped).\nMessage hex: ${bytesToHex(msg)}${t != null ? "\nAs text:     " + t : ""}`;
    } },
  { id: "cr-iv-gen", name: "IV / Nonce Generator", cat: "crypto", desc: "Generate a cryptographically random IV or nonce of a chosen size, as hex and base64.", tags: ["iv", "nonce", "random", "gcm", "generate"], live: false, button: "Generate",
    inputs: [{ k: "size", label: "Size", type: "select", opts: [["12", "12 bytes (AES-GCM / ChaCha20)"], ["16", "16 bytes (AES-CBC / CTR)"], ["8", "8 bytes"], ["24", "24 bytes (XChaCha20)"], ["32", "32 bytes"]], value: "12" }],
    run(v) { const n = parseInt(v.size, 10); const u = new Uint8Array(n); crypto.getRandomValues(u); return `Random ${n}-byte IV/nonce:\nhex    ${bytesToHex(u)}\nbase64 ${bytesToB64(u)}\n\nReminder: a GCM/CTR/ChaCha20 nonce must be unique per key. Never reuse one.`; } },
  { id: "cr-const-time-compare", name: "Constant-Time Compare", cat: "crypto", desc: "Compare two values for equality in constant time (XOR-accumulate) and explains why '===' leaks timing.", tags: ["timing", "compare", "mac", "constant-time"], live: true,
    inputs: [{ k: "a", label: "Value A", type: "text" }, { k: "b", label: "Value B", type: "text" }, { k: "hex", label: "Values are hex", type: "checkbox", value: false }],
    run(v) {
      if (v.a == null || v.b == null || (v.a === "" && v.b === "")) return "";
      const a = v.hex ? hexToBytes(v.a) : enc.encode(v.a); const b = v.hex ? hexToBytes(v.b) : enc.encode(v.b);
      let diff = a.length ^ b.length; const n = Math.max(a.length, b.length);
      for (let i = 0; i < n; i++) diff |= (a[i] || 0) ^ (b[i] || 0);
      return `${diff === 0 ? "EQUAL" : "NOT EQUAL"} (constant-time)\n\nWhy it matters: a normal early-exit comparison (a === b, memcmp) returns faster on the first differing byte, leaking how many leading bytes matched. An attacker can time repeated guesses to recover a MAC or token one byte at a time. Always use a constant-time compare (XOR every byte, OR the results) for secrets, MACs and tokens.`;
    } },
  { id: "cr-block-mode-ref", name: "Block Cipher Mode Reference", cat: "crypto", desc: "What ECB/CBC/CTR/GCM/XTS do, what they need (IV/nonce), and their security pitfalls.", tags: ["ecb", "cbc", "ctr", "gcm", "mode", "reference"], live: true,
    inputs: [{ k: "mode", label: "Mode", type: "select", opts: ["ECB", "CBC", "CTR", "GCM", "XTS"], value: "GCM" }],
    run(v) {
      const M = {
        ECB: "Electronic Codebook: each block encrypted independently.\n  Needs: nothing extra (no IV).\n  DANGER: identical plaintext blocks -> identical ciphertext blocks (the 'ECB penguin'). Leaks structure. Do not use.",
        CBC: "Cipher Block Chaining: each block XORed with the previous ciphertext before encryption.\n  Needs: random, unpredictable 16-byte IV per message.\n  Pitfalls: malleable without a MAC; vulnerable to padding-oracle attacks. Use Encrypt-then-MAC or an AEAD instead.",
        CTR: "Counter: turns the block cipher into a stream by encrypting a counter and XORing.\n  Needs: a unique nonce/counter per message (NEVER reuse with the same key).\n  Pitfalls: no integrity; nonce reuse XORs two plaintexts together. Pair with a MAC.",
        GCM: "Galois/Counter Mode: CTR encryption plus a built-in authentication tag (AEAD).\n  Needs: a unique 96-bit nonce per key; optional associated data (AAD).\n  Pitfalls: nonce reuse is catastrophic (leaks the auth key). Preferred modern mode when nonces can be kept unique.",
        XTS: "XEX-based tweakable mode: designed for disk/sector encryption.\n  Needs: two keys and a sector 'tweak'.\n  Pitfalls: no authentication; only for fixed-size storage blocks, not general messaging.",
      };
      return `AES-${v.mode}\n\n${M[v.mode]}`;
    } },
  { id: "cr-nonce-reuse-explainer", name: "Nonce Reuse Explainer", cat: "crypto", desc: "Explains what breaks when a nonce/IV is reused in CTR, GCM, ChaCha20 or a one-time pad.", tags: ["nonce", "iv", "reuse", "ctr", "gcm", "explainer"], live: true,
    inputs: [{ k: "scheme", label: "Scheme", type: "select", opts: ["AES-CTR", "AES-GCM", "ChaCha20-Poly1305", "One-Time Pad"], value: "AES-GCM" }],
    run(v) {
      const M = {
        "AES-CTR": "CTR keystream depends only on (key, nonce). Reuse the nonce and two messages share a keystream: C1 XOR C2 = P1 XOR P2, revealing the XOR of the plaintexts. With any known/guessable structure the plaintexts fall. No integrity either.",
        "AES-GCM": "Worse than CTR: besides the P1 XOR P2 leak, GCM's authentication uses a polynomial MAC keyed by H. A single nonce reuse lets an attacker solve for the authentication subkey and FORGE arbitrary messages. One repeat is catastrophic.",
        "ChaCha20-Poly1305": "Same shape as GCM: the ChaCha20 keystream repeats (plaintext XOR leak) and the Poly1305 one-time key is reused, enabling tag forgery. Use XChaCha20 (192-bit nonce) or a counter if you cannot guarantee unique 96-bit nonces.",
        "One-Time Pad": "A pad reused across two messages is a 'two-time pad': C1 XOR C2 = P1 XOR P2. Classic crib-dragging recovers both plaintexts. The OTP is only secure if the key is truly random and used exactly once.",
      };
      return `Nonce/IV reuse in ${v.scheme}\n\n${M[v.scheme]}\n\nFix: generate a fresh random nonce per message, or use a deterministic counter you are certain never repeats for a given key.`;
    } },
  { id: "cr-padding-oracle-explainer", name: "Padding Oracle Explainer", cat: "crypto", desc: "How a CBC padding-oracle attack decrypts data without the key, and how to prevent it.", tags: ["padding oracle", "cbc", "attack", "explainer"], live: true,
    inputs: [],
    run() { return "CBC Padding Oracle\n\nSetup: the server decrypts attacker-supplied CBC ciphertext and reveals (directly or via timing/error differences) whether the PKCS#7 padding was valid.\n\nAttack: CBC decryption computes P_i = D(C_i) XOR C_{i-1}. By tampering with the previous block C_{i-1} byte by byte and watching the valid/invalid-padding signal, the attacker learns D(C_i) one byte at a time, then recovers P_i = D(C_i) XOR (real C_{i-1}). No key needed; ~256 queries per byte.\n\nPrevent:\n  - Use an AEAD (AES-GCM, ChaCha20-Poly1305) so ciphertext is authenticated before decryption.\n  - Or Encrypt-then-MAC and verify the MAC in constant time BEFORE decrypting.\n  - Never expose distinct padding/decryption errors or timing to the client."; } },

  // ================= Diffie-Hellman / modular arithmetic =================
  { id: "cr-dh-toy", name: "Diffie-Hellman Calculator", cat: "crypto", desc: "Toy finite-field Diffie-Hellman: from prime p, generator g and two private exponents, compute publics and the shared secret.", tags: ["diffie-hellman", "dh", "key exchange"], live: false, button: "Compute",
    inputs: [{ k: "p", label: "Prime p", type: "text", value: "23" }, { k: "g", label: "Generator g", type: "text", value: "5" }, { k: "a", label: "Alice private a", type: "text", value: "6" }, { k: "b", label: "Bob private b", type: "text", value: "15" }],
    run(v) {
      const p = parseBig(v.p), g = parseBig(v.g), a = parseBig(v.a), b = parseBig(v.b);
      if (p == null || g == null || a == null || b == null) return { error: "All of p, g, a, b must be integers (decimal or 0x hex)." };
      if (p < 2n) return { error: "p must be >= 2." };
      const A = modpow(g, a, p), B = modpow(g, b, p);
      const s1 = modpow(B, a, p), s2 = modpow(A, b, p);
      return `A = g^a mod p = ${A}\nB = g^b mod p = ${B}\n\nShared (B^a mod p) = ${s1}\nShared (A^b mod p) = ${s2}\n${s1 === s2 ? "Match — shared secret established." : "Mismatch (check inputs)."}${isProbablePrime(p, 4) ? "" : "\n\nWarning: p does not look prime; this is a toy calculator only."}`;
    } },
  { id: "cr-modpow", name: "Modular Exponentiation", cat: "crypto", desc: "Compute base^exponent mod modulus with big integers (square-and-multiply). The core of RSA and DH.", tags: ["modpow", "modular", "exponent", "bigint"], live: true,
    inputs: [{ k: "base", label: "Base", type: "text" }, { k: "exp", label: "Exponent", type: "text" }, { k: "mod", label: "Modulus", type: "text" }],
    run(v) {
      const b = parseBig(v.base), e = parseBig(v.exp), m = parseBig(v.mod);
      if (b == null || e == null || m == null) return "";
      if (m < 1n) return { error: "Modulus must be >= 1." };
      if (e < 0n) { const inv = modinv(b, m); if (inv == null) return { error: "Negative exponent needs base invertible mod m, but gcd != 1." }; return `${modpow(inv, -e, m)}`; }
      const r = modpow(b, e, m); return `${r}\n\nhex: 0x${r.toString(16)}`;
    } },
  { id: "cr-modinv", name: "Modular Inverse", cat: "crypto", desc: "Find a^-1 mod m (the x with a*x = 1 mod m) via the extended Euclidean algorithm, or report none exists.", tags: ["modinv", "inverse", "modular", "euclid"], live: true,
    inputs: [{ k: "a", label: "a", type: "text" }, { k: "m", label: "Modulus m", type: "text" }],
    run(v) { const a = parseBig(v.a), m = parseBig(v.m); if (a == null || m == null) return ""; if (m < 2n) return { error: "Modulus must be >= 2." }; const inv = modinv(a, m); if (inv == null) return { error: `No inverse: gcd(a, m) = ${gcdBig(a, m)} != 1.` }; return `${inv}\n\nCheck: ${((a % m + m) % m)} * ${inv} mod ${m} = ${(((a % m + m) % m) * inv) % m}`; } },
  { id: "cr-ext-gcd", name: "Extended Euclidean (Bezout)", cat: "crypto", desc: "Compute gcd(a,b) and integers x,y with a*x + b*y = gcd(a,b).", tags: ["gcd", "bezout", "euclid", "extended"], live: true,
    inputs: [{ k: "a", label: "a", type: "text" }, { k: "b", label: "b", type: "text" }],
    run(v) { const a = parseBig(v.a), b = parseBig(v.b); if (a == null || b == null) return ""; const [g, x, y] = egcd(a, b); return `gcd = ${g}\nx = ${x}\ny = ${y}\n\n${a}*(${x}) + ${b}*(${y}) = ${a * x + b * y}`; } },
  { id: "cr-crt", name: "CRT Solver", cat: "crypto", desc: "Solve a system of congruences x = r_i (mod m_i) with the Chinese Remainder Theorem. Moduli need not be coprime if consistent.", tags: ["crt", "chinese remainder", "congruence"], live: false, button: "Solve",
    inputs: [{ k: "r", label: "Residues (comma-separated)", type: "text", value: "2, 3, 2" }, { k: "m", label: "Moduli (comma-separated)", type: "text", value: "3, 5, 7" }],
    run(v) {
      const rs = S(v.r).split(",").map((x) => parseBig(x)), ms = S(v.m).split(",").map((x) => parseBig(x));
      if (rs.length !== ms.length || rs.some((x) => x == null) || ms.some((x) => x == null)) return { error: "Give the same count of integer residues and moduli." };
      if (ms.some((x) => x < 1n)) return { error: "Moduli must be positive." };
      let x = ((rs[0] % ms[0]) + ms[0]) % ms[0], mod = ms[0];
      for (let i = 1; i < rs.length; i++) {
        const [g, p] = egcd(mod, ms[i]); const r2 = ((rs[i] % ms[i]) + ms[i]) % ms[i];
        if ((r2 - x) % g !== 0n) return { error: `No solution: congruences ${i} and earlier ones are inconsistent.` };
        const lcm = mod / g * ms[i]; const mult = ((r2 - x) / g) * p % (ms[i] / g); x = ((x + mod * mult) % lcm + lcm) % lcm; mod = lcm;
      }
      return `x = ${x}  (mod ${mod})\n\nhex: 0x${x.toString(16)}`;
    } },
  { id: "cr-gf256-mul", name: "GF(2^8) Multiply", cat: "crypto", desc: "Multiply two bytes in the Rijndael finite field GF(2^8) with the AES polynomial 0x11B.", tags: ["gf256", "galois", "aes", "field"], live: true,
    inputs: [{ k: "a", label: "a (hex byte)", type: "text", value: "57" }, { k: "b", label: "b (hex byte)", type: "text", value: "83" }],
    run(v) { const a = parseInt(cleanHex(v.a), 16), b = parseInt(cleanHex(v.b), 16); if (isNaN(a) || isNaN(b) || a > 255 || b > 255) return { error: "Enter two bytes in hex (00..FF)." }; const p = gfMul(a, b); return `0x${a.toString(16).padStart(2, "0")} * 0x${b.toString(16).padStart(2, "0")} = 0x${p.toString(16).padStart(2, "0")} (${p}) in GF(2^8) mod 0x11B`; } },
  { id: "cr-mod-sqrt", name: "Modular Square Root (Tonelli-Shanks)", cat: "crypto", desc: "Find x with x^2 = a (mod p) for an odd prime p, or report that a is a non-residue.", tags: ["sqrt", "tonelli", "shanks", "quadratic residue"], live: false, button: "Solve",
    inputs: [{ k: "a", label: "a", type: "text", value: "5" }, { k: "p", label: "Prime p", type: "text", value: "41" }],
    run(v) {
      const a0 = parseBig(v.a), p = parseBig(v.p); if (a0 == null || p == null) return "";
      if (p < 2n || !isProbablePrime(p, 6)) return { error: "p must be an odd prime." };
      const a = ((a0 % p) + p) % p; if (a === 0n) return "x = 0";
      if (modpow(a, (p - 1n) / 2n, p) !== 1n) return { error: `${a0} is a quadratic non-residue mod ${p} (no square root).` };
      if (p % 4n === 3n) { const x = modpow(a, (p + 1n) / 4n, p); return `x = ${x}  (also ${p - x})`; }
      let q = p - 1n, s = 0n; while ((q & 1n) === 0n) { q >>= 1n; s++; }
      let z = 2n; while (modpow(z, (p - 1n) / 2n, p) !== p - 1n) z++;
      let m = s, c = modpow(z, q, p), t = modpow(a, q, p), r = modpow(a, (q + 1n) / 2n, p);
      while (t !== 1n) { let i = 0n, tt = t; while (tt !== 1n) { tt = (tt * tt) % p; i++; if (i === m) return { error: "Tonelli-Shanks failed." }; } const b = modpow(c, 1n << (m - i - 1n), p); m = i; c = (b * b) % p; t = (t * c) % p; r = (r * b) % p; }
      return `x = ${r}  (also ${p - r})`;
    } },
  { id: "cr-jacobi", name: "Legendre / Jacobi Symbol", cat: "crypto", desc: "Compute the Jacobi symbol (a/n) for odd n>0 (equals the Legendre symbol when n is prime): tells quadratic-residue status.", tags: ["jacobi", "legendre", "quadratic residue", "number theory"], live: true,
    inputs: [{ k: "a", label: "a", type: "text", value: "5" }, { k: "n", label: "n (odd)", type: "text", value: "21" }],
    run(v) {
      let a = parseBig(v.a), n = parseBig(v.n); if (a == null || n == null) return "";
      if (n <= 0n || (n & 1n) === 0n) return { error: "n must be odd and positive." };
      a = ((a % n) + n) % n; let result = 1n;
      while (a !== 0n) { while ((a & 1n) === 0n) { a >>= 1n; const r = n % 8n; if (r === 3n || r === 5n) result = -result; } [a, n] = [n, a]; if (a % 4n === 3n && n % 4n === 3n) result = -result; a %= n; }
      if (n !== 1n) return `(a/n) = 0  (a and n share a factor)`;
      return `(${v.a} / ${v.n}) = ${result}\n${result === 1n ? "Likely a quadratic residue (guaranteed if n is prime)." : "Quadratic non-residue."}`;
    } },

  // ================= RSA CTF =================
  { id: "cr-rsa-factor", name: "RSA Factor (small n)", cat: "crypto", desc: "Factor a small/weak RSA modulus n into p and q using trial division plus Pollard's rho (CTF scale only).", tags: ["rsa", "factor", "pollard", "ctf"], live: false, button: "Factor",
    inputs: [{ k: "n", label: "Modulus n", type: "text" }],
    run(v) {
      let n = parseBig(v.n); if (n == null) return ""; if (n < 2n) return { error: "n must be >= 2." };
      if (isProbablePrime(n, 10)) return { error: "n is prime — not a valid RSA modulus." };
      const factors = [];
      for (const sp of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n]) { while (n % sp === 0n) { factors.push(sp); n /= sp; } }
      function rho(m) {
        if (m % 2n === 0n) return 2n;
        let x = 2n, y = 2n, c = 1n + BigInt(Math.floor(Math.random() * 20)), d = 1n, i = 0;
        const f = (z) => (z * z + c) % m;
        while (d === 1n && i < 2000000) { x = f(x); y = f(f(y)); d = gcdBig(bigAbs(x - y), m); i++; }
        return d === m ? null : d;
      }
      const stack = n > 1n ? [n] : [];
      let guard = 0;
      while (stack.length && guard++ < 200) { const m = stack.pop(); if (m === 1n) continue; if (isProbablePrime(m, 10)) { factors.push(m); continue; } let d = null; for (let a = 0; a < 8 && !d; a++) d = rho(m); if (!d) return { error: "Could not factor within limits — n is too large for this toy factorer." }; stack.push(d, m / d); }
      factors.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      const distinct = factors.length === 2 && factors[0] !== factors[1];
      return `n = ${factors.join(" * ")}\n\n${distinct ? `p = ${factors[0]}\nq = ${factors[1]}` : "Factors: " + factors.join(", ")}`;
    } },
  { id: "cr-rsa-compute-d", name: "RSA Private Exponent (d)", cat: "crypto", desc: "From primes p, q and public exponent e, compute n, phi(n), lambda(n) and the private exponent d.", tags: ["rsa", "private", "d", "totient", "ctf"], live: true,
    inputs: [{ k: "p", label: "p", type: "text" }, { k: "q", label: "q", type: "text" }, { k: "e", label: "e", type: "text", value: "65537" }],
    run(v) {
      const p = parseBig(v.p), q = parseBig(v.q), e = parseBig(v.e); if (p == null || q == null || e == null) return "";
      if (p < 2n || q < 2n) return { error: "p and q must be >= 2." };
      const n = p * q, phi = (p - 1n) * (q - 1n), lam = (p - 1n) / gcdBig(p - 1n, q - 1n) * (q - 1n);
      const d = modinv(e, lam); const dphi = modinv(e, phi);
      if (d == null) return { error: "e is not invertible mod lambda(n): gcd(e, lambda) != 1." };
      return `n       = ${n}\nphi(n)  = ${phi}\nlambda  = ${lam}\nd (mod lambda) = ${d}\nd (mod phi)    = ${dphi}\n\n(Either d works for decryption; libraries use the lambda form.)`;
    } },
  { id: "cr-rsa-decrypt-pq", name: "RSA Decrypt with p,q", cat: "crypto", desc: "Textbook RSA decrypt: given p, q, e and ciphertext c, compute d and recover m = c^d mod n (as integer and text).", tags: ["rsa", "decrypt", "ctf", "textbook"], live: false, button: "Decrypt",
    inputs: [{ k: "p", label: "p", type: "text" }, { k: "q", label: "q", type: "text" }, { k: "e", label: "e", type: "text", value: "65537" }, { k: "c", label: "Ciphertext c", type: "textarea", rows: 2 }],
    run(v) {
      const p = parseBig(v.p), q = parseBig(v.q), e = parseBig(v.e), c = parseBig(v.c); if (p == null || q == null || e == null || c == null) return "";
      const n = p * q, phi = (p - 1n) * (q - 1n); const d = modinv(e, phi); if (d == null) return { error: "gcd(e, phi) != 1." };
      const m = modpow(c, d, n); const bytes = bigToBytes(m); const t = textPreview(bytes);
      return `d = ${d}\nm = ${m}\nm (hex) = 0x${m.toString(16)}\nm (bytes) = ${bytesToHex(bytes)}${t != null ? "\nm (text)  = " + t : ""}`;
    } },
  { id: "cr-rsa-encrypt-toy", name: "RSA Encrypt (textbook)", cat: "crypto", desc: "Textbook (unpadded) RSA: c = m^e mod n. Message may be an integer or short text. For CTFs/teaching only.", tags: ["rsa", "encrypt", "textbook", "ctf"], live: false, button: "Encrypt",
    inputs: [{ k: "n", label: "Modulus n", type: "text" }, { k: "e", label: "e", type: "text", value: "65537" }, { k: "m", label: "Message (integer, or text if 'text' checked)", type: "textarea", rows: 2 }, { k: "astext", label: "Message is text", type: "checkbox", value: false }],
    run(v) {
      const n = parseBig(v.n), e = parseBig(v.e); if (n == null || e == null) return "";
      let m; if (v.astext) { if (!v.m) return ""; m = bytesToBig(enc.encode(v.m)); } else { m = parseBig(v.m); if (m == null) return ""; }
      if (m >= n) return { error: "Message integer must be smaller than n." };
      const c = modpow(m, e, n); return `m = ${m}\nc = ${c}\nc (hex) = 0x${c.toString(16)}\n\n(Unpadded textbook RSA — not secure for real use; use OAEP.)`;
    } },
  { id: "cr-rsa-crt-decrypt", name: "RSA-CRT Decrypt", cat: "crypto", desc: "Decrypt with RSA CRT parameters p, q, dP, dQ, qInv and ciphertext c (as stored in PKCS#1 private keys).", tags: ["rsa", "crt", "decrypt", "pkcs1"], live: false, button: "Decrypt",
    inputs: [{ k: "p", label: "p", type: "text" }, { k: "q", label: "q", type: "text" }, { k: "dp", label: "dP (d mod p-1)", type: "text" }, { k: "dq", label: "dQ (d mod q-1)", type: "text" }, { k: "qinv", label: "qInv (q^-1 mod p)", type: "text" }, { k: "c", label: "Ciphertext c", type: "textarea", rows: 2 }],
    run(v) {
      const p = parseBig(v.p), q = parseBig(v.q), dp = parseBig(v.dp), dq = parseBig(v.dq), qinv = parseBig(v.qinv), c = parseBig(v.c);
      if ([p, q, dp, dq, qinv, c].some((x) => x == null)) return "";
      const m1 = modpow(c, dp, p), m2 = modpow(c, dq, q); let h = (qinv * (((m1 - m2) % p) + p)) % p; const m = m2 + h * q;
      const bytes = bigToBytes(m); const t = textPreview(bytes);
      return `m = ${m}\nm (hex) = 0x${m.toString(16)}${t != null ? "\nm (text) = " + t : ""}`;
    } },
  { id: "cr-ecdsa-nonce-reuse", name: "ECDSA Nonce-Reuse Recovery", cat: "crypto", desc: "Recover the ECDSA nonce k and private key d from two signatures that reused the same nonce (same r).", tags: ["ecdsa", "nonce", "reuse", "recover", "ctf"], live: false, button: "Recover",
    inputs: [{ k: "n", label: "Curve order n", type: "text" }, { k: "r", label: "r (shared)", type: "text" }, { k: "s1", label: "s1", type: "text" }, { k: "s2", label: "s2", type: "text" }, { k: "h1", label: "Hash of msg1 (z1)", type: "text" }, { k: "h2", label: "Hash of msg2 (z2)", type: "text" }],
    run(v) {
      const n = parseBig(v.n), r = parseBig(v.r), s1 = parseBig(v.s1), s2 = parseBig(v.s2), h1 = parseBig(v.h1), h2 = parseBig(v.h2);
      if ([n, r, s1, s2, h1, h2].some((x) => x == null)) return "";
      const sd = (((s1 - s2) % n) + n) % n; if (sd === 0n) return { error: "s1 == s2 mod n; cannot recover (need distinct signatures)." };
      const sdInv = modinv(sd, n); if (sdInv == null) return { error: "s1-s2 not invertible mod n." };
      const k = ((((h1 - h2) % n) + n) % n * sdInv) % n;
      const rInv = modinv(r, n); if (rInv == null) return { error: "r not invertible mod n." };
      const d = (((((s1 * k - h1) % n) + n) % n) * rInv) % n;
      return `Recovered nonce k = ${k}\nRecovered private key d = ${d}\nd (hex) = 0x${d.toString(16)}\n\nReusing a nonce across two ECDSA signatures fully exposes the private key.`;
    } },
  { id: "cr-totient", name: "Euler Totient phi(n)", cat: "crypto", desc: "Factor n (small) and compute Euler's totient phi(n), used to derive RSA private keys.", tags: ["totient", "phi", "euler", "factor", "rsa"], live: false, button: "Compute",
    inputs: [{ k: "n", label: "n", type: "text" }],
    run(v) {
      let n = parseBig(v.n); if (n == null) return ""; if (n < 1n) return { error: "n must be >= 1." }; if (n === 1n) return "phi(1) = 1";
      const orig = n; const fac = new Map();
      function rho(m) { if (m % 2n === 0n) return 2n; let x = 2n, y = 2n, c = 1n + BigInt(Math.floor(Math.random() * 20)), d = 1n, i = 0; const f = (z) => (z * z + c) % m; while (d === 1n && i < 2000000) { x = f(x); y = f(f(y)); d = gcdBig(bigAbs(x - y), m); i++; } return d === m ? null : d; }
      for (const sp of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n]) while (n % sp === 0n) { fac.set(sp, (fac.get(sp) || 0n) + 1n); n /= sp; }
      const stack = n > 1n ? [n] : []; let guard = 0;
      while (stack.length && guard++ < 200) { const m = stack.pop(); if (m === 1n) continue; if (isProbablePrime(m, 10)) { fac.set(m, (fac.get(m) || 0n) + 1n); continue; } let d = null; for (let a = 0; a < 8 && !d; a++) d = rho(m); if (!d) return { error: "Could not factor n within limits." }; stack.push(d, m / d); }
      let phi = 1n; const parts = []; for (const [pf, k] of [...fac.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) { phi *= (pf - 1n) * (pf ** (k - 1n)); parts.push(k === 1n ? `${pf}` : `${pf}^${k}`); }
      return `n = ${orig} = ${parts.join(" * ")}\nphi(n) = ${phi}`;
    } },
  { id: "cr-primality-test", name: "Primality Test", cat: "crypto", desc: "Miller-Rabin probable-primality test for big integers, with deterministic small-prime checks.", tags: ["prime", "miller-rabin", "primality", "bigint"], live: false, button: "Test",
    inputs: [{ k: "n", label: "n", type: "text" }, { k: "rounds", label: "Extra random rounds", type: "range", min: 1, max: 40, step: 1, value: 12 }],
    run(v) { const n = parseBig(v.n); if (n == null) return ""; const rounds = parseInt(v.rounds, 10) || 8; const prime = isProbablePrime(n, rounds); return `${n} is ${prime ? "PROBABLY PRIME" : "COMPOSITE"}${prime ? ` (Miller-Rabin, ${rounds} extra rounds; error < 4^-rounds)` : ""}`; } },
  { id: "cr-random-prime", name: "Random Prime Generator", cat: "crypto", desc: "Generate a random probable prime of a chosen bit length using crypto RNG and Miller-Rabin.", tags: ["prime", "generate", "random", "rsa"], live: false, button: "Generate",
    inputs: [{ k: "bits", label: "Bit length", type: "select", opts: ["16", "32", "64", "128", "256", "512"], value: "128" }],
    run(v) {
      const bits = parseInt(v.bits, 10); const bytes = Math.ceil(bits / 8); let tries = 0;
      while (tries++ < 20000) {
        const u = new Uint8Array(bytes); crypto.getRandomValues(u); let n = bytesToBig(u);
        n |= 1n; n |= (1n << BigInt(bits - 1)); const mask = (1n << BigInt(bits)) - 1n; n &= mask; n |= 1n; n |= (1n << BigInt(bits - 1));
        if (isProbablePrime(n, 10)) return `${bits}-bit probable prime:\n${n}\nhex: 0x${n.toString(16)}`;
      }
      return { error: "Could not find a prime in the attempt budget; try again." };
    } },

  // ================= Classic cryptanalysis =================
  { id: "cr-freq-analysis", name: "Letter Frequency Analysis", cat: "crypto", desc: "Count letter frequencies in text (A-Z, case-insensitive) with percentages, for breaking substitution ciphers.", tags: ["frequency", "analysis", "substitution", "cryptanalysis"], live: true,
    inputs: [{ k: "text", label: "Ciphertext", type: "textarea", rows: 5 }],
    run(v) {
      if (!v.text) return "";
      const counts = {}; let total = 0; for (const ch of v.text.toUpperCase()) if (ch >= "A" && ch <= "Z") { counts[ch] = (counts[ch] || 0) + 1; total++; }
      if (!total) return { error: "No letters found." };
      const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([c, n]) => `${c}  ${String(n).padStart(5)}  ${(n / total * 100).toFixed(2)}%  ${"#".repeat(Math.round(n / total * 100))}`);
      return `Total letters: ${total}\n\n${rows.join("\n")}\n\n(English order is roughly E T A O I N S H R D L U.)`;
    } },
  { id: "cr-ioc", name: "Index of Coincidence", cat: "crypto", desc: "Compute the index of coincidence of text; compares against English (~0.0667) and random (~0.0385).", tags: ["ioc", "index of coincidence", "vigenere", "cryptanalysis"], live: true,
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) {
      if (!v.text) return "";
      const counts = {}; let N = 0; for (const ch of v.text.toUpperCase()) if (ch >= "A" && ch <= "Z") { counts[ch] = (counts[ch] || 0) + 1; N++; }
      if (N < 2) return { error: "Need at least 2 letters." };
      let sum = 0; for (const c in counts) sum += counts[c] * (counts[c] - 1); const ioc = sum / (N * (N - 1));
      const guess = ioc > 0.058 ? "close to English (likely monoalphabetic or plaintext)" : ioc > 0.045 ? "between — possibly a short-key polyalphabetic cipher" : "close to random (likely a long key / polyalphabetic)";
      return `N = ${N}\nIoC = ${ioc.toFixed(4)}\n\nEnglish ~0.0667, uniform random ~0.0385.\nAssessment: ${guess}.`;
    } },
  { id: "cr-kasiski", name: "Kasiski Examination", cat: "crypto", desc: "Find repeated substrings in a Vigenere-style ciphertext and factor the gaps to suggest likely key lengths.", tags: ["kasiski", "vigenere", "key length", "cryptanalysis"], live: false, button: "Analyze",
    inputs: [{ k: "text", label: "Ciphertext", type: "textarea", rows: 5 }, { k: "len", label: "Substring length", type: "select", opts: ["3", "4", "5"], value: "3" }],
    run(v) {
      if (!v.text) return "";
      const s = v.text.toUpperCase().replace(/[^A-Z]/g, ""); const L = parseInt(v.len, 10);
      if (s.length < L * 2) return { error: "Ciphertext too short." };
      const pos = {}; for (let i = 0; i + L <= s.length; i++) { const sub = s.slice(i, i + L); (pos[sub] = pos[sub] || []).push(i); }
      const gaps = []; const reps = [];
      for (const sub in pos) if (pos[sub].length > 1) { for (let i = 1; i < pos[sub].length; i++) gaps.push(pos[sub][i] - pos[sub][0]); reps.push(`${sub} x${pos[sub].length}`); }
      if (!gaps.length) return { error: "No repeated substrings of that length found." };
      const factorCount = {}; for (const g of gaps) for (let f = 2; f <= 20; f++) if (g % f === 0) factorCount[f] = (factorCount[f] || 0) + 1;
      const ranked = Object.entries(factorCount).sort((a, b) => b[1] - a[1]).slice(0, 8);
      return `Repeated ${L}-grams: ${reps.slice(0, 12).join(", ")}${reps.length > 12 ? " ..." : ""}\nGaps: ${gaps.slice(0, 20).join(", ")}${gaps.length > 20 ? " ..." : ""}\n\nMost common gap factors (candidate key lengths):\n${ranked.map(([f, c]) => `  ${f}: appears in ${c} gaps`).join("\n")}`;
    } },
  { id: "cr-vigenere-keylen", name: "Vigenere Key-Length (IoC)", cat: "crypto", desc: "Estimate a Vigenere key length by averaging the index of coincidence of each column for periods 1..20.", tags: ["vigenere", "key length", "ioc", "cryptanalysis"], live: false, button: "Analyze",
    inputs: [{ k: "text", label: "Ciphertext", type: "textarea", rows: 5 }],
    run(v) {
      if (!v.text) return "";
      const s = v.text.toUpperCase().replace(/[^A-Z]/g, ""); if (s.length < 20) return { error: "Need at least 20 letters." };
      const rows = [];
      for (let period = 1; period <= Math.min(20, s.length >> 1); period++) {
        let tot = 0, cols = 0;
        for (let c = 0; c < period; c++) { const counts = {}; let N = 0; for (let i = c; i < s.length; i += period) { counts[s[i]] = (counts[s[i]] || 0) + 1; N++; } if (N < 2) continue; let sum = 0; for (const k in counts) sum += counts[k] * (counts[k] - 1); tot += sum / (N * (N - 1)); cols++; }
        rows.push([period, cols ? tot / cols : 0]);
      }
      const ranked = rows.slice().sort((a, b) => Math.abs(b[1] - 0.0667) < Math.abs(a[1] - 0.0667) ? 1 : -1);
      return `Average IoC per candidate key length (English ~0.0667):\n${rows.map(([p, io]) => `  len ${String(p).padStart(2)}: ${io.toFixed(4)}${Math.abs(io - 0.0667) < 0.012 ? "  <-- likely" : ""}`).join("\n")}\n\nBest guesses: ${ranked.slice(0, 3).map((r) => r[0]).join(", ")}`;
    } },
  { id: "cr-single-byte-xor", name: "Single-Byte XOR Breaker", cat: "crypto", desc: "Brute-force all 256 single-byte XOR keys over a hex/base64 ciphertext and rank candidates by English likeness.", tags: ["xor", "brute force", "cryptopals", "cryptanalysis"], live: false, button: "Break",
    inputs: [{ k: "data", label: "Ciphertext", type: "textarea", rows: 3 }, { k: "fmt", label: "Input format", type: "select", opts: ["hex", "base64"], value: "hex" }],
    run(v) {
      if (!v.data) return "";
      let bytes; try { bytes = v.fmt === "hex" ? hexToBytes(v.data) : b64ToBytes(v.data); } catch (e) { return { error: "Could not decode input." }; }
      if (!bytes.length) return { error: "Empty input." };
      const res = []; for (let k = 0; k < 256; k++) { const out = bytes.map((b) => b ^ k); res.push({ k, score: scoreEnglish(out), text: textPreview(Uint8Array.from(out)) }); }
      res.sort((a, b) => b.score - a.score);
      return res.slice(0, 5).map((r) => `key 0x${r.k.toString(16).padStart(2, "0")} ('${r.k >= 32 && r.k < 127 ? String.fromCharCode(r.k) : "."}') score ${r.score.toFixed(1)}: ${JSON.stringify(r.text == null ? "(binary)" : r.text.slice(0, 80))}`).join("\n");
    } },
  { id: "cr-xor-keylen", name: "Repeating-XOR Key-Length Guess", cat: "crypto", desc: "Rank likely repeating-key XOR key sizes by the normalized Hamming distance between blocks (cryptopals method).", tags: ["xor", "key length", "hamming", "cryptopals"], live: false, button: "Analyze",
    inputs: [{ k: "data", label: "Ciphertext", type: "textarea", rows: 3 }, { k: "fmt", label: "Input format", type: "select", opts: ["hex", "base64"], value: "base64" }, { k: "max", label: "Max key size", type: "range", min: 4, max: 40, step: 1, value: 40 }],
    run(v) {
      if (!v.data) return "";
      let bytes; try { bytes = v.fmt === "hex" ? hexToBytes(v.data) : b64ToBytes(v.data); } catch (e) { return { error: "Could not decode input." }; }
      const maxKs = Math.min(parseInt(v.max, 10), bytes.length >> 2 || 1); const res = [];
      for (let ks = 2; ks <= maxKs; ks++) {
        const blocks = Math.min(6, Math.floor(bytes.length / ks)); if (blocks < 2) continue;
        let tot = 0, pairs = 0; for (let i = 0; i < blocks - 1; i++) for (let j = i + 1; j < blocks; j++) { tot += hammingBits(bytes.slice(i * ks, (i + 1) * ks), bytes.slice(j * ks, (j + 1) * ks)) / ks; pairs++; }
        res.push({ ks, d: tot / pairs });
      }
      if (!res.length) return { error: "Ciphertext too short to analyze." };
      res.sort((a, b) => a.d - b.d);
      return `Candidate key sizes (lower normalized distance = more likely):\n${res.slice(0, 6).map((r) => `  ${String(r.ks).padStart(2)}: ${r.d.toFixed(3)}`).join("\n")}`;
    } },
  { id: "cr-repeating-xor-break", name: "Repeating-Key XOR Breaker", cat: "crypto", desc: "Fully break repeating-key XOR: auto-detect key length, transpose, solve each column, then recover key and plaintext.", tags: ["xor", "vigenere", "break", "cryptopals"], live: false, button: "Break",
    inputs: [{ k: "data", label: "Ciphertext", type: "textarea", rows: 4 }, { k: "fmt", label: "Input format", type: "select", opts: ["hex", "base64"], value: "base64" }, { k: "keylen", label: "Key length (0 = auto)", type: "text", inputType: "number", value: "0" }],
    run(v) {
      if (!v.data) return "";
      let bytes; try { bytes = v.fmt === "hex" ? hexToBytes(v.data) : b64ToBytes(v.data); } catch (e) { return { error: "Could not decode input." }; }
      if (bytes.length < 4) return { error: "Ciphertext too short." };
      let ks = parseInt(v.keylen, 10) || 0;
      if (!ks) { let best = Infinity; for (let k = 2; k <= Math.min(40, bytes.length >> 2); k++) { const blocks = Math.min(6, Math.floor(bytes.length / k)); if (blocks < 2) continue; let tot = 0, pairs = 0; for (let i = 0; i < blocks - 1; i++) for (let j = i + 1; j < blocks; j++) { tot += hammingBits(bytes.slice(i * k, (i + 1) * k), bytes.slice(j * k, (j + 1) * k)) / k; pairs++; } const d = tot / pairs; if (d < best) { best = d; ks = k; } } }
      if (!ks) return { error: "Could not determine key length." };
      const key = new Uint8Array(ks);
      for (let c = 0; c < ks; c++) { const col = []; for (let i = c; i < bytes.length; i += ks) col.push(bytes[i]); let bestK = 0, bestS = -1e9; for (let k = 0; k < 256; k++) { const s = scoreEnglish(col.map((b) => b ^ k)); if (s > bestS) { bestS = s; bestK = k; } } key[c] = bestK; }
      const out = bytes.map((b, i) => b ^ key[i % ks]); const t = textPreview(Uint8Array.from(out));
      return `Key length: ${ks}\nKey (hex): ${bytesToHex(key)}\nKey (text): ${JSON.stringify(textPreview(key) || "(binary)")}\n\nPlaintext:\n${t == null ? bytesToHex(Uint8Array.from(out)) : t}`;
    } },
  { id: "cr-hex-xor", name: "Fixed XOR (hex)", cat: "crypto", desc: "XOR two equal-length hex buffers together and return the hex result (cryptopals fixed-XOR).", tags: ["xor", "hex", "cryptopals"], live: true,
    inputs: [{ k: "a", label: "Buffer A (hex)", type: "text" }, { k: "b", label: "Buffer B (hex)", type: "text" }],
    run(v) { if (!v.a || !v.b) return ""; const a = hexToBytes(v.a), b = hexToBytes(v.b); if (a.length !== b.length) return { error: `Lengths differ (${a.length} vs ${b.length} bytes).` }; const out = a.map((x, i) => x ^ b[i]); return bytesToHex(Uint8Array.from(out)); } },
  { id: "cr-hamming-distance", name: "Hamming Distance (bits)", cat: "crypto", desc: "Count differing bits between two equal-length inputs (text or hex). Used in XOR key-length analysis.", tags: ["hamming", "distance", "bits", "cryptopals"], live: true,
    inputs: [{ k: "a", label: "A", type: "text" }, { k: "b", label: "B", type: "text" }, { k: "hex", label: "Inputs are hex", type: "checkbox", value: false }],
    run(v) { if (v.a == null || v.b == null || (!v.a && !v.b)) return ""; const a = v.hex ? hexToBytes(v.a) : enc.encode(v.a); const b = v.hex ? hexToBytes(v.b) : enc.encode(v.b); if (a.length !== b.length) return { error: `Lengths differ (${a.length} vs ${b.length} bytes).` }; return `Hamming distance: ${hammingBits(a, b)} bits (over ${a.length * 8} bits)`; } },
  { id: "cr-chi-squared", name: "English Chi-Squared Score", cat: "crypto", desc: "Score how closely text's letter distribution matches English using chi-squared; lower is more English-like.", tags: ["chi-squared", "scoring", "english", "cryptanalysis"], live: true,
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) {
      if (!v.text) return "";
      const EXP = { A: 8.2, B: 1.5, C: 2.8, D: 4.3, E: 12.7, F: 2.2, G: 2.0, H: 6.1, I: 7.0, J: 0.15, K: 0.77, L: 4.0, M: 2.4, N: 6.7, O: 7.5, P: 1.9, Q: 0.095, R: 6.0, S: 6.3, T: 9.1, U: 2.8, V: 0.98, W: 2.4, X: 0.15, Y: 2.0, Z: 0.074 };
      const counts = {}; let N = 0; for (const ch of v.text.toUpperCase()) if (ch >= "A" && ch <= "Z") { counts[ch] = (counts[ch] || 0) + 1; N++; }
      if (!N) return { error: "No letters found." };
      let chi = 0; for (const c in EXP) { const e = EXP[c] / 100 * N; const o = counts[c] || 0; chi += (o - e) * (o - e) / e; }
      return `Letters: ${N}\nChi-squared vs English: ${chi.toFixed(2)}\n(Lower = closer to English. Natural English text scores roughly under ~2*alphabet; random text scores much higher.)`;
    } },

  // ================= Shamir Secret Sharing =================
  { id: "cr-shamir-split", name: "Shamir Secret Split", cat: "crypto", desc: "Split a secret into N shares (threshold T) using Shamir Secret Sharing over GF(256). Any T shares reconstruct it.", tags: ["shamir", "sss", "secret sharing", "split"], live: false, button: "Split",
    inputs: [{ k: "secret", label: "Secret (text, or hex if checked)", type: "textarea", rows: 2 }, { k: "hex", label: "Secret is hex", type: "checkbox", value: false }, { k: "n", label: "Number of shares (N)", type: "text", inputType: "number", value: "5" }, { k: "t", label: "Threshold (T)", type: "text", inputType: "number", value: "3" }],
    run(v) {
      if (!v.secret) return "";
      const n = parseInt(v.n, 10), t = parseInt(v.t, 10);
      if (!(t >= 2 && n >= t && n <= 255)) return { error: "Need 2 <= T <= N <= 255." };
      const secret = v.hex ? hexToBytes(v.secret) : enc.encode(v.secret); if (!secret.length) return { error: "Empty secret." };
      const shares = []; for (let x = 1; x <= n; x++) shares.push({ x, y: new Uint8Array(secret.length) });
      for (let bi = 0; bi < secret.length; bi++) {
        const coeff = new Uint8Array(t); coeff[0] = secret[bi]; const rnd = new Uint8Array(t - 1); crypto.getRandomValues(rnd); for (let i = 1; i < t; i++) coeff[i] = rnd[i - 1];
        for (const sh of shares) { let acc = 0; for (let p = t - 1; p >= 0; p--) acc = gfMulT(acc, sh.x) ^ coeff[p]; sh.y[bi] = acc; }
      }
      return `Threshold ${t} of ${n}. Each line is one share (keep them apart):\n\n${shares.map((s) => `${s.x.toString(16).padStart(2, "0")}-${bytesToHex(s.y)}`).join("\n")}\n\n(Format: xx-<hex payload>. Feed any ${t} lines to Shamir Secret Combine.)`;
    } },
  { id: "cr-shamir-combine", name: "Shamir Secret Combine", cat: "crypto", desc: "Reconstruct a Shamir-shared secret from T or more shares (xx-hex format from the split tool).", tags: ["shamir", "sss", "secret sharing", "combine"], live: false, button: "Combine",
    inputs: [{ k: "shares", label: "Shares (one per line, xx-hex)", type: "textarea", rows: 6 }, { k: "ashex", label: "Output as hex", type: "checkbox", value: false }],
    run(v) {
      if (!v.shares) return "";
      const lines = v.shares.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      if (lines.length < 2) return { error: "Provide at least 2 shares." };
      const pts = []; let len = -1;
      for (const l of lines) { const m = l.match(/^([0-9a-fA-F]{1,2})[-:](.+)$/); if (!m) return { error: `Bad share format: ${l}` }; const x = parseInt(m[1], 16); const y = hexToBytes(m[2]); if (len < 0) len = y.length; else if (y.length !== len) return { error: "Shares have differing lengths." }; pts.push({ x, y }); }
      const xs = pts.map((p) => p.x); if (new Set(xs).size !== xs.length) return { error: "Duplicate share indices." };
      const out = new Uint8Array(len);
      for (let bi = 0; bi < len; bi++) {
        let secret = 0;
        for (let i = 0; i < pts.length; i++) { let num = 1, den = 1; for (let j = 0; j < pts.length; j++) if (j !== i) { num = gfMulT(num, pts[j].x); den = gfMulT(den, pts[i].x ^ pts[j].x); } const lagr = gfMulT(pts[i].y[bi], gfDiv(num, den)); secret ^= lagr; }
        out[bi] = secret;
      }
      const t = textPreview(out);
      return v.ashex || t == null ? `Secret (hex): ${bytesToHex(out)}` : `Secret: ${t}`;
    } },

  // ================= ChaCha20 =================
  { id: "cr-chacha20", name: "ChaCha20 Encrypt / Decrypt", cat: "crypto", desc: "RFC 8439 ChaCha20 stream cipher (pure JS). 32-byte key, 12-byte nonce, 32-bit counter. Symmetric: same op both ways.", tags: ["chacha20", "stream", "rfc8439", "encrypt"], live: false, button: "Run",
    inputs: [{ k: "key", label: "Key (hex, 32 bytes)", type: "text" }, { k: "nonce", label: "Nonce (hex, 12 bytes)", type: "text" }, { k: "counter", label: "Initial counter", type: "text", inputType: "number", value: "1" }, { k: "data", label: "Input", type: "textarea", rows: 3 }, { k: "mode", label: "Mode", type: "select", opts: ["Encrypt (text -> hex)", "Decrypt (hex -> text)"], value: "Encrypt (text -> hex)" }],
    run(v) {
      const key = hexToBytes(v.key), nonce = hexToBytes(v.nonce); if (key.length !== 32) return { error: "Key must be 32 bytes of hex." }; if (nonce.length !== 12) return { error: "Nonce must be 12 bytes of hex." };
      if (!v.data) return ""; const counter = parseInt(v.counter, 10) || 0;
      if (v.mode.startsWith("Encrypt")) { const out = chacha20(key, nonce, counter, enc.encode(v.data)); return `Ciphertext (hex):\n${bytesToHex(out)}\n\nBase64: ${bytesToB64(out)}`; }
      const ct = hexToBytes(v.data); const out = chacha20(key, nonce, counter, ct); const t = textPreview(out); return `Plaintext${t == null ? " (hex)" : ""}:\n${t == null ? bytesToHex(out) : t}`;
    } },
  { id: "cr-chacha20-block", name: "ChaCha20 Keystream Block", cat: "crypto", desc: "Generate one 64-byte ChaCha20 keystream block (RFC 8439) from key, nonce and counter, for test-vector checks.", tags: ["chacha20", "keystream", "rfc8439", "block"], live: false, button: "Generate",
    inputs: [{ k: "key", label: "Key (hex, 32 bytes)", type: "text" }, { k: "nonce", label: "Nonce (hex, 12 bytes)", type: "text" }, { k: "counter", label: "Counter", type: "text", inputType: "number", value: "1" }],
    run(v) {
      const kb = hexToBytes(v.key), nb = hexToBytes(v.nonce); if (kb.length !== 32) return { error: "Key must be 32 bytes." }; if (nb.length !== 12) return { error: "Nonce must be 12 bytes." };
      const key = new Uint32Array(8); for (let i = 0; i < 8; i++) key[i] = leU32(kb, i * 4); const nonce = new Uint32Array(3); for (let i = 0; i < 3; i++) nonce[i] = leU32(nb, i * 4);
      const ks = chachaBlock(key, nonce, parseInt(v.counter, 10) || 0);
      return `64-byte keystream block (hex):\n${bytesToHex(ks)}`;
    } },
];

// ---- X.509 / CSR parsers (shared) ----
function readName(bytes, node) {
  const parts = [];
  for (const rdn of node.children || []) for (const atv of rdn.children || []) {
    const oidNode = atv.children[0], valNode = atv.children[1];
    const oid = decodeOID(bytes, oidNode.contentStart, oidNode.contentEnd);
    const name = DN_SHORT[oid] || oid;
    let val; try { val = dec.decode(bytes.slice(valNode.contentStart, valNode.contentEnd)); } catch (e) { val = bytesToHex(bytes.slice(valNode.contentStart, valNode.contentEnd)); }
    parts.push(`${name}=${val}`);
  }
  return parts.join(", ");
}
function asn1Time(bytes, node) {
  const str = dec.decode(bytes.slice(node.contentStart, node.contentEnd)); const utc = node.tagByte === 0x17;
  const m = utc ? str.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?$/) : str.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?$/);
  if (!m) return str; let Y = m[1]; if (utc) { const yy = +Y; Y = String(yy < 50 ? 2000 + yy : 1900 + yy); }
  return `${Y}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6] || "00"} UTC`;
}
function pubKeyInfo(bytes, spki) {
  const algId = spki.children[0]; const oidNode = algId.children[0]; const oid = decodeOID(bytes, oidNode.contentStart, oidNode.contentEnd);
  const algName = OID_NAMES[oid] || oid;
  let detail = "";
  if (oid === "1.2.840.113549.1.1.1") {
    try { const bit = spki.children[1]; const inner = parseASN1(bytes, bit.contentStart + 1, bit.contentEnd)[0]; const modNode = inner.children[0]; let mlen = modNode.length; if (bytes[modNode.contentStart] === 0) mlen--; detail = ` (${mlen * 8}-bit modulus)`; } catch (e) {}
  } else if (oid === "1.2.840.10045.2.1") { try { const p = algId.children[1]; detail = " (" + (OID_NAMES[decodeOID(bytes, p.contentStart, p.contentEnd)] || "curve") + ")"; } catch (e) {} }
  return `${algName}${detail}`;
}
function parseExtensions(bytes, extSeq) {
  const out = [];
  for (const ext of extSeq.children || []) {
    const oidNode = ext.children[0]; const oid = decodeOID(bytes, oidNode.contentStart, oidNode.contentEnd);
    let crit = false, valNode;
    if (ext.children.length === 3) { crit = bytes[ext.children[1].contentStart] !== 0; valNode = ext.children[2]; } else valNode = ext.children[1];
    const name = OID_NAMES[oid] || oid; const label = name + (crit ? " [critical]" : "");
    try {
      if (oid === "2.5.29.17" || oid === "2.5.29.18") {
        const seq = parseASN1(bytes, valNode.contentStart, valNode.contentEnd)[0]; const names = [];
        for (const gn of seq.children || []) { const c = bytes.slice(gn.contentStart, gn.contentEnd); if (gn.tagNum === 2) names.push("DNS:" + dec.decode(c)); else if (gn.tagNum === 1) names.push("email:" + dec.decode(c)); else if (gn.tagNum === 6) names.push("URI:" + dec.decode(c)); else if (gn.tagNum === 7) names.push("IP:" + (c.length === 4 ? Array.from(c).join(".") : bytesToHex(c))); else names.push("[" + gn.tagNum + "]"); }
        out.push(`${label}: ${names.join(", ")}`);
      } else if (oid === "2.5.29.19") {
        const seq = parseASN1(bytes, valNode.contentStart, valNode.contentEnd)[0]; let ca = false, pl = null;
        for (const ch of seq.children || []) { if (ch.tagByte === 0x01) ca = bytes[ch.contentStart] !== 0; if (ch.tagByte === 0x02) pl = bytesToBig(bytes.slice(ch.contentStart, ch.contentEnd)).toString(); }
        out.push(`${label}: CA=${ca}${pl != null ? ", pathlen=" + pl : ""}`);
      } else if (oid === "2.5.29.15") {
        const bit = parseASN1(bytes, valNode.contentStart, valNode.contentEnd)[0]; const unused = bytes[bit.contentStart]; let val = 0; for (let i = bit.contentStart + 1; i < bit.contentEnd; i++) val = (val << 8) | bytes[i]; const total = (bit.length - 1) * 8 - unused;
        const USAGES = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"]; const set = []; const hi = (bit.length - 2) * 8 + 7;
        for (let i = 0; i < USAGES.length; i++) { if (val & (1 << (hi - i))) set.push(USAGES[i]); }
        out.push(`${label}: ${set.join(", ") || "(none decoded)"}`);
      } else if (oid === "2.5.29.37") {
        const seq = parseASN1(bytes, valNode.contentStart, valNode.contentEnd)[0]; const us = (seq.children || []).map((o) => OID_NAMES[decodeOID(bytes, o.contentStart, o.contentEnd)] || decodeOID(bytes, o.contentStart, o.contentEnd));
        out.push(`${label}: ${us.join(", ")}`);
      } else if (oid === "2.5.29.14") {
        const os = parseASN1(bytes, valNode.contentStart, valNode.contentEnd)[0]; out.push(`${label}: ${bytesToHex(bytes.slice(os.contentStart, os.contentEnd))}`);
      } else out.push(`${label}`);
    } catch (e) { out.push(`${label}`); }
  }
  return out;
}
function parseCertificate(bytes) {
  const cert = parseASN1(bytes, 0, bytes.length)[0];
  if (!cert || cert.tagByte !== 0x30 || !cert.children) throw new Error("not a certificate SEQUENCE");
  const tbs = cert.children[0]; const sigAlgTop = cert.children[1];
  let i = 0, version = 1;
  if (tbs.children[0].tagByte === 0xA0) { version = Number(bytesToBig(bytes.slice(tbs.children[0].children[0].contentStart, tbs.children[0].children[0].contentEnd))) + 1; i = 1; }
  const serial = tbs.children[i++]; const sigAlg = tbs.children[i++]; const issuer = tbs.children[i++]; const validity = tbs.children[i++]; const subject = tbs.children[i++]; const spki = tbs.children[i++];
  let extSeq = null; for (; i < tbs.children.length; i++) if (tbs.children[i].tagByte === 0xA3) { extSeq = tbs.children[i].children[0]; break; }
  const serialHex = bytesToHex(bytes.slice(serial.contentStart, serial.contentEnd)).replace(/^00/, "");
  const sigOid = decodeOID(bytes, sigAlgTop.children[0].contentStart, sigAlgTop.children[0].contentEnd);
  const lines = [
    `Version:          v${version}`,
    `Serial:           ${serialHex}`,
    `Signature alg:    ${OID_NAMES[sigOid] || sigOid}`,
    `Issuer:           ${readName(bytes, issuer)}`,
    `Subject:          ${readName(bytes, subject)}`,
    `Not before:       ${asn1Time(bytes, validity.children[0])}`,
    `Not after:        ${asn1Time(bytes, validity.children[1])}`,
    `Public key:       ${pubKeyInfo(bytes, spki)}`,
  ];
  if (extSeq) { lines.push("", "Extensions:"); for (const e of parseExtensions(bytes, extSeq)) lines.push("  " + e); }
  return lines.join("\n");
}
function parseCSR(bytes) {
  const csr = parseASN1(bytes, 0, bytes.length)[0];
  if (!csr || csr.tagByte !== 0x30 || !csr.children) throw new Error("not a CSR SEQUENCE");
  const cri = csr.children[0]; const sigAlg = csr.children[1];
  // cri: version INTEGER, subject Name, SPKI, [0] attributes
  const subject = cri.children[1]; const spki = cri.children[2];
  const sigOid = decodeOID(bytes, sigAlg.children[0].contentStart, sigAlg.children[0].contentEnd);
  const lines = [`Subject:         ${readName(bytes, subject)}`, `Public key:      ${pubKeyInfo(bytes, spki)}`, `Signature alg:   ${OID_NAMES[sigOid] || sigOid}`];
  // attributes [0]
  const attrs = cri.children.find((c) => c.tagByte === 0xA0);
  if (attrs) {
    for (const attr of attrs.children || []) {
      try {
        const aoid = decodeOID(bytes, attr.children[0].contentStart, attr.children[0].contentEnd);
        if (aoid === "1.2.840.113549.1.9.14") {
          const set = attr.children[1]; const extSeq = set.children[0];
          lines.push("", "Requested extensions:"); for (const e of parseExtensions(bytes, extSeq)) lines.push("  " + e);
        } else lines.push(`Attribute:       ${OID_NAMES[aoid] || aoid}`);
      } catch (e) {}
    }
  }
  return lines.join("\n");
}
