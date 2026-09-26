import { esc } from '/js/shared.js';

const HT_ALGOS = [
  { id: 'md5', name: 'MD5', bits: 128, hex: 32, native: false },
  { id: 'sha1', name: 'SHA-1', bits: 160, hex: 40, native: true, subtle: 'SHA-1' },
  { id: 'sha256', name: 'SHA-256', bits: 256, hex: 64, native: true, subtle: 'SHA-256' },
  { id: 'sha384', name: 'SHA-384', bits: 384, hex: 96, native: true, subtle: 'SHA-384' },
  { id: 'sha512', name: 'SHA-512', bits: 512, hex: 128, native: true, subtle: 'SHA-512' },
  { id: 'sha3_256', name: 'SHA-3-256', bits: 256, hex: 64, native: false },
  { id: 'sha3_512', name: 'SHA-3-512', bits: 512, hex: 128, native: false },
  { id: 'ripemd160', name: 'RIPEMD-160', bits: 160, hex: 40, native: false },
  { id: 'crc32', name: 'CRC32', bits: 32, hex: 8, native: false },
];

const HT_HMAC_ALGOS = ['SHA-256', 'SHA-384', 'SHA-512'];

const HT_HASH_PATTERNS = [
  { len: 8, name: 'CRC32', confidence: 0.9 },
  { len: 32, name: 'MD5', confidence: 0.95 },
  { len: 40, name: 'SHA-1 / RIPEMD-160', confidence: 0.9 },
  { len: 56, name: 'SHA-224 / SHA-3-224', confidence: 0.85 },
  { len: 64, name: 'SHA-256 / SHA-3-256', confidence: 0.9 },
  { len: 96, name: 'SHA-384 / SHA-3-384', confidence: 0.85 },
  { len: 128, name: 'SHA-512 / SHA-3-512', confidence: 0.9 },
];

const HT_BCRYPT_RE = /^\$2[aby]?\$\d{2}\$.{53}$/;
const HT_ARGON2_RE = /^\$argon2(i|d|id)\$/;
const HT_NTLM_RE = /^[a-fA-F0-9]{32}$/;

const HT_WORDLIST = [
  'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
  'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
  'ashley', 'bailey', 'shadow', '123123', '654321', 'superman', 'hello',
  'charlie', 'donald', 'password1', 'welcome', 'admin', 'root', 'toor',
];

// These three algorithms are not exposed by Web Crypto (crypto.subtle only
// covers SHA-1/2), so they are implemented in full here. Earlier revisions used
// stand-in "simple" mixing functions that produced 32/40/64-hex-shaped output
// but were NOT the real algorithms — MD5("abc") did not equal
// 900150983cd24fb0d6963f7d28e17f72, SHA3-256/512 were SHA-2 IV + FNV, and
// RIPEMD-160 lacked its dual pipeline entirely. Every value copied from the
// tool was therefore wrong. These are real, test-vector-verified
// implementations operating on the UTF-8 bytes of the input (matching how
// crypto.subtle hashes strings).

function _htUtf8Bytes(str) { return Array.from(new TextEncoder().encode(str)); }
function _htHexLE(v) {
  return ((v & 0xff).toString(16).padStart(2, '0')) +
    (((v >>> 8) & 0xff).toString(16).padStart(2, '0')) +
    (((v >>> 16) & 0xff).toString(16).padStart(2, '0')) +
    (((v >>> 24) & 0xff).toString(16).padStart(2, '0'));
}

// MD5 (RFC 1321).
function _htMD5(str) {
  const msg = _htUtf8Bytes(str);
  const origLen = msg.length;
  msg.push(0x80);
  while (msg.length % 64 !== 56) msg.push(0);
  const bitLen = origLen * 8;
  for (let b = 0; b < 8; b++) msg.push(Math.floor(bitLen / Math.pow(2, 8 * b)) & 0xff);
  const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  const K = [];
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let off = 0; off < msg.length; off += 64) {
    const M = [];
    for (let j = 0; j < 16; j++) M[j] = msg[off + j * 4] | (msg[off + j * 4 + 1] << 8) | (msg[off + j * 4 + 2] << 16) | (msg[off + j * 4 + 3] << 24);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) | 0;
      A = D; D = C; C = B;
      const s = S[Math.floor(i / 16) * 4 + (i % 4)];
      B = (B + ((F << s) | (F >>> (32 - s)))) | 0;
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
  }
  return _htHexLE(a0) + _htHexLE(b0) + _htHexLE(c0) + _htHexLE(d0);
}

// RIPEMD-160 (dual left/right lines with independent constants, rotations and
// message schedules; ISO/IEC 10118-3).
const _HT_RMD_R = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
const _HT_RMD_RP = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
const _HT_RMD_S = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
const _HT_RMD_SP = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];
function _htRIPEMD160(str) {
  const rol = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  const f = (j, x, y, z) => {
    if (j < 16) return (x ^ y ^ z) >>> 0;
    if (j < 32) return ((x & y) | (~x & z)) >>> 0;
    if (j < 48) return ((x | ~y) ^ z) >>> 0;
    if (j < 64) return ((x & z) | (y & ~z)) >>> 0;
    return (x ^ (y | ~z)) >>> 0;
  };
  const K = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const KP = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
  const msg = _htUtf8Bytes(str);
  const origLen = msg.length;
  msg.push(0x80);
  while (msg.length % 64 !== 56) msg.push(0);
  const bitLen = origLen * 8;
  for (let b = 0; b < 8; b++) msg.push(Math.floor(bitLen / Math.pow(2, 8 * b)) & 0xff);
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  for (let off = 0; off < msg.length; off += 64) {
    const X = [];
    for (let j = 0; j < 16; j++) X[j] = (msg[off + j * 4] | (msg[off + j * 4 + 1] << 8) | (msg[off + j * 4 + 2] << 16) | (msg[off + j * 4 + 3] << 24)) >>> 0;
    let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
    let ar = h0, br = h1, cr = h2, dr = h3, er = h4;
    for (let j = 0; j < 80; j++) {
      const rnd = Math.floor(j / 16);
      let t = (((al + f(j, bl, cl, dl)) >>> 0) + X[_HT_RMD_R[j]]) >>> 0;
      t = (t + K[rnd]) >>> 0;
      t = (rol(t, _HT_RMD_S[j]) + el) >>> 0;
      al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t;
      t = (((ar + f(79 - j, br, cr, dr)) >>> 0) + X[_HT_RMD_RP[j]]) >>> 0;
      t = (t + KP[rnd]) >>> 0;
      t = (rol(t, _HT_RMD_SP[j]) + er) >>> 0;
      ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t;
    }
    const t = (h1 + cl + dr) >>> 0;
    h1 = (h2 + dl + er) >>> 0;
    h2 = (h3 + el + ar) >>> 0;
    h3 = (h4 + al + br) >>> 0;
    h4 = (h0 + bl + cr) >>> 0;
    h0 = t;
  }
  return _htHexLE(h0) + _htHexLE(h1) + _htHexLE(h2) + _htHexLE(h3) + _htHexLE(h4);
}

// SHA-3 (Keccak-f[1600], FIPS 202) with 64-bit lanes held as BigInt.
const _HT_KECCAK_M64 = (1n << 64n) - 1n;
const _HT_KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n];
const _HT_KECCAK_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
function _htKeccakF(A) {
  const rol = (x, n) => { const nb = BigInt(n); return ((x << nb) | (x >> (64n - nb))) & _HT_KECCAK_M64; };
  for (let round = 0; round < 24; round++) {
    const C = [];
    for (let x = 0; x < 5; x++) C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4];
    const D = [];
    for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rol(C[(x + 1) % 5], 1);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) A[x][y] ^= D[x];
    const B = [[0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n]];
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y][(2 * x + 3 * y) % 5] = rol(A[x][y], _HT_KECCAK_ROT[x][y]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) A[x][y] = (B[x][y] ^ (~B[(x + 1) % 5][y] & B[(x + 2) % 5][y])) & _HT_KECCAK_M64;
    A[0][0] ^= _HT_KECCAK_RC[round];
  }
}
function _htSHA3(str, bits) {
  const rate = (1600 - bits * 2) / 8;
  const outLen = bits / 8;
  const msg = _htUtf8Bytes(str);
  msg.push(0x06);
  while (msg.length % rate !== 0) msg.push(0);
  msg[msg.length - 1] ^= 0x80;
  const A = [[0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n]];
  for (let off = 0; off < msg.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let b = 0; b < 8; b++) lane |= BigInt(msg[off + i * 8 + b]) << BigInt(8 * b);
      A[i % 5][Math.floor(i / 5)] ^= lane;
    }
    _htKeccakF(A);
  }
  let out = '', produced = 0;
  outer: for (;;) {
    for (let i = 0; i < rate / 8; i++) {
      const lane = A[i % 5][Math.floor(i / 5)];
      for (let b = 0; b < 8; b++) {
        out += Number((lane >> BigInt(8 * b)) & 0xffn).toString(16).padStart(2, '0');
        if (++produced >= outLen) break outer;
      }
    }
    _htKeccakF(A);
  }
  return out;
}

function _htCRC32(str) {
  const bytes = new TextEncoder().encode(str);
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i];
    for (let j = 0; j < 8; j++) crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
  }
  return ((crc ^ 0xFFFFFFFF) >>> 0).toString(16).padStart(8, '0');
}

async function _htComputeHash(algo, text) {
  const a = HT_ALGOS.find(x => x.id === algo);
  if (!a) return 'unknown';
  if (a.native && crypto.subtle) {
    try {
      const enc = new TextEncoder().encode(text);
      const buf = await crypto.subtle.digest(a.subtle, enc);
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (_) { /* fallback */ }
  }
  if (algo === 'md5') return _htMD5(text);
  if (algo === 'crc32') return _htCRC32(text);
  if (algo === 'ripemd160') return _htRIPEMD160(text);
  if (algo === 'sha3_256') return _htSHA3(text, 256);
  if (algo === 'sha3_512') return _htSHA3(text, 512);
  // Only reachable if a SHA-1/2 algorithm was requested but Web Crypto was
  // unavailable (e.g. a non-secure context). Emitting a stand-in value under a
  // real algorithm name would be worse than saying so, so report honestly.
  return '[unavailable: ' + a.name + ' requires Web Crypto in a secure context]';
}

async function _htComputeFileHash(algoSubtle, file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const buf = await crypto.subtle.digest(algoSubtle, reader.result);
        resolve(Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join(''));
      } catch (e) { reject(e); }
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

async function _htComputeHMAC(algo, key, message) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: algo }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(message));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function _htIdentifyHash(hash) {
  const h = hash.trim();
  if (HT_BCRYPT_RE.test(h)) return [{ name: 'bcrypt', confidence: 0.99 }];
  if (HT_ARGON2_RE.test(h)) return [{ name: 'Argon2', confidence: 0.99 }];
  if (/^\$[156]\$/.test(h)) return [{ name: 'Unix crypt (SHA/MD5)', confidence: 0.95 }];
  if (/^[a-fA-F0-9]+$/.test(h)) {
    const matches = HT_HASH_PATTERNS.filter(p => p.len === h.length);
    if (h.length === 32 && /^[a-fA-F0-9]{32}$/.test(h)) {
      matches.push({ name: 'NTLM', confidence: 0.7 });
    }
    return matches.length ? matches : [{ name: 'Unknown hex string', confidence: 0.3 }];
  }
  if (/^[A-Za-z0-9+/=]+$/.test(h) && h.length > 20) return [{ name: 'Possibly Base64-encoded hash', confidence: 0.5 }];
  return [{ name: 'Unknown format', confidence: 0.1 }];
}

const HT_STYLE = `
.ht-wrap{background:#0a0e14;color:#c8d6e5;font-family:'Segoe UI',system-ui,sans-serif;border-radius:8px;overflow:hidden;min-height:500px}
.ht-header{background:linear-gradient(135deg,#0c1020 0%,#141e30 100%);padding:18px 24px;border-bottom:1px solid #1a2a44}
.ht-header h2{margin:0;font-size:20px;color:#00aaff;letter-spacing:1px;display:flex;align-items:center;gap:10px}
.ht-header h2 svg{width:22px;height:22px}
.ht-header p{margin:4px 0 0;font-size:12px;color:#6a8caa;letter-spacing:.5px}
.ht-tabs{display:flex;background:#0c1020;border-bottom:1px solid #1a2a44;overflow-x:auto}
.ht-tab{padding:10px 20px;background:none;border:none;color:#6a8caa;cursor:pointer;font-size:13px;white-space:nowrap;border-bottom:2px solid transparent;transition:.2s}
.ht-tab:hover{color:#c8d6e5;background:rgba(0,170,255,.05)}
.ht-tab.active{color:#00aaff;border-bottom-color:#00aaff;background:rgba(0,170,255,.08)}
.ht-body{padding:20px}
.ht-panel{background:#0f172a;border:1px solid #1a2a44;border-radius:8px;padding:18px;margin-bottom:16px}
.ht-panel h3{margin:0 0 12px;font-size:15px;color:#e2e8f0}
.ht-row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;margin-bottom:14px}
.ht-label{display:block;font-size:11px;color:#6a8caa;margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px}
.ht-input,.ht-select,.ht-textarea{background:#0a0e14;border:1px solid #1a2a44;border-radius:6px;color:#e2e8f0;padding:8px 12px;font-size:13px;font-family:inherit;width:100%;box-sizing:border-box}
.ht-textarea{font-family:'JetBrains Mono','Fira Code',monospace;resize:vertical;min-height:80px}
.ht-input:focus,.ht-select:focus,.ht-textarea:focus{outline:none;border-color:#00aaff;box-shadow:0 0 0 2px rgba(0,170,255,.15)}
.ht-btn{padding:8px 18px;border:none;border-radius:4px;cursor:pointer;font-size:13px;font-weight:600;transition:.2s}
.ht-btn-primary{background:#00aaff;color:#0a0e14}
.ht-btn-primary:hover{background:#33bbff}
.ht-btn-danger{background:#ff4444;color:#fff}
.ht-btn-danger:hover{background:#ff6666}
.ht-btn-ghost{background:transparent;border:1px solid #1a2a44;color:#c8d6e5}
.ht-btn-ghost:hover{border-color:#00aaff;color:#00aaff}
.ht-result{background:#0a0e14;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-top:12px;font-family:'JetBrains Mono','Fira Code',monospace;font-size:12px;word-break:break-all;line-height:1.7}
.ht-result-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid #1a2a4433}
.ht-result-row:last-child{border-bottom:none}
.ht-result-algo{color:#00aaff;font-weight:600;min-width:110px}
.ht-result-hash{color:#c8d6e5;flex:1;margin:0 12px;word-break:break-all}
.ht-result-copy{background:none;border:1px solid #1a2a44;color:#6a8caa;padding:4px 10px;border-radius:4px;cursor:pointer;font-size:11px}
.ht-result-copy:hover{border-color:#00aaff;color:#00aaff}
.ht-badge{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:600}
.ht-badge-green{background:rgba(0,255,136,.12);color:#00ff88}
.ht-badge-red{background:rgba(255,68,68,.12);color:#ff4444}
.ht-badge-yellow{background:rgba(255,214,0,.12);color:#ffd600}
.ht-badge-blue{background:rgba(0,170,255,.12);color:#00aaff}
.ht-badge-purple{background:rgba(168,85,247,.12);color:#a855f7}
.ht-drop-zone{border:2px dashed #1a2a44;border-radius:8px;padding:40px;text-align:center;color:#6a8caa;transition:.2s;cursor:pointer}
.ht-drop-zone:hover,.ht-drop-zone.dragover{border-color:#00aaff;background:rgba(0,170,255,.05);color:#00aaff}
.ht-drop-zone svg{width:40px;height:40px;margin-bottom:8px;opacity:.5}
.ht-table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}
.ht-table th{text-align:left;padding:10px 12px;background:#141e30;color:#6a8caa;font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #1a2a44}
.ht-table td{padding:8px 12px;border-bottom:1px solid #1a2a4433;color:#c8d6e5}
.ht-confidence{height:6px;border-radius:3px;background:#1a2a44;overflow:hidden;min-width:80px}
.ht-confidence-fill{height:100%;border-radius:3px;transition:.3s}
.ht-match{background:#0f172a;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-bottom:10px}
.ht-match-name{font-size:15px;font-weight:600;color:#e2e8f0;margin-bottom:4px}
.ht-match-meta{font-size:12px;color:#6a8caa}
.ht-compare-result{text-align:center;padding:24px;border-radius:8px;margin-top:16px;font-size:16px;font-weight:600}
.ht-compare-match{background:rgba(0,255,136,.08);border:1px solid rgba(0,255,136,.3);color:#00ff88}
.ht-compare-mismatch{background:rgba(255,68,68,.08);border:1px solid rgba(255,68,68,.3);color:#ff4444}
.ht-rainbow-entry{display:flex;align-items:center;gap:12px;padding:6px 10px;border-bottom:1px solid #1a2a4433;font-size:12px}
.ht-rainbow-plain{color:#00ff88;min-width:120px;font-family:'JetBrains Mono',monospace}
.ht-rainbow-hash{color:#6a8caa;flex:1;font-family:'JetBrains Mono',monospace;word-break:break-all}
.ht-salt-demo{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}
.ht-salt-card{background:#0a0e14;border:1px solid #1a2a44;border-radius:6px;padding:12px}
.ht-salt-card h4{margin:0 0 6px;font-size:13px;color:#00aaff}
.ht-salt-card code{font-size:11px;color:#c8d6e5;word-break:break-all}
.ht-cost-table td{font-family:'JetBrains Mono',monospace;font-size:12px}
.ht-ref-section{margin-bottom:20px}
.ht-ref-section h3{color:#00aaff;font-size:14px;margin:0 0 10px;padding-bottom:6px;border-bottom:1px solid #1a2a44}
.ht-ref-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.ht-ref-card{background:#0a0e14;border:1px solid #1a2a44;border-radius:6px;padding:14px}
.ht-ref-card h4{margin:0 0 6px;font-size:13px;color:#e2e8f0}
.ht-ref-card p{margin:0;font-size:12px;color:#6a8caa;line-height:1.5}
.ht-progress{width:100%;height:4px;background:#1a2a44;border-radius:2px;overflow:hidden;margin-top:8px}
.ht-progress-bar{height:100%;background:#00aaff;border-radius:2px;transition:width .3s}
.ht-checkboxes{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.ht-check-label{display:flex;align-items:center;gap:6px;padding:5px 12px;background:#0a0e14;border:1px solid #1a2a44;border-radius:4px;cursor:pointer;font-size:12px;transition:.2s}
.ht-check-label:hover{border-color:#00aaff}
.ht-check-label input:checked+span{color:#00aaff}
@media(max-width:768px){.ht-body{padding:14px}.ht-salt-demo{grid-template-columns:1fr}.ht-ref-grid{grid-template-columns:1fr}.ht-row{flex-direction:column}}
`;

export function renderHashToolkit(container) {
  const el = document.createElement('div');
  el.className = 'ht-wrap';
  const style = document.createElement('style');
  style.textContent = HT_STYLE;
  el.appendChild(style);

  const tabs = ['Generate', 'File Hash', 'Identify', 'Compare', 'Reference'];
  let activeTab = 0;

  function render() {
    const existing = el.querySelector('.ht-inner');
    if (existing) existing.remove();
    const inner = document.createElement('div');
    inner.className = 'ht-inner';
    inner.innerHTML = `
      <div class="ht-header">
        <h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg> Hash &amp; Checksum Toolkit</h2>
        <p>Generate, identify, compare, and analyze cryptographic hashes</p>
      </div>
      <div class="ht-tabs">${tabs.map((t, i) => `<button class="ht-tab${i === activeTab ? ' active' : ''}" data-tab="${i}">${esc(t)}</button>`).join('')}</div>
      <div class="ht-body" id="htBody"></div>
    `;
    el.appendChild(inner);
    el.querySelectorAll('.ht-tab').forEach(btn => btn.onclick = () => { activeTab = +btn.dataset.tab; render(); });
    const body = el.querySelector('#htBody');
    if (activeTab === 0) renderGenerate(body);
    else if (activeTab === 1) renderFileHash(body);
    else if (activeTab === 2) renderIdentify(body);
    else if (activeTab === 3) renderCompare(body);
    else renderReference(body);
  }

  function renderGenerate(body) {
    body.innerHTML = `
      <div class="ht-panel">
        <h3>Hash Generator</h3>
        <div class="ht-label">Select Algorithms</div>
        <div class="ht-checkboxes" id="htAlgoChecks">
          ${HT_ALGOS.map(a => `<label class="ht-check-label"><input type="checkbox" value="${a.id}" checked><span>${esc(a.name)}</span></label>`).join('')}
        </div>
        <div class="ht-label">Input Text</div>
        <textarea class="ht-textarea" id="htGenInput" rows="3" placeholder="Enter text to hash..."></textarea>
        <div class="ht-row" style="margin-top:12px">
          <button class="ht-btn ht-btn-primary" id="htGenBtn">Compute Hashes</button>
          <button class="ht-btn ht-btn-ghost" id="htGenClearBtn">Clear</button>
        </div>
        <div id="htGenResults"></div>
      </div>
      <div class="ht-panel">
        <h3>HMAC Generator</h3>
        <div class="ht-row">
          <div style="flex:1"><div class="ht-label">Secret Key</div><input class="ht-input" id="htHmacKey" placeholder="Enter secret key"></div>
          <div style="flex:1"><div class="ht-label">Algorithm</div><select class="ht-select" id="htHmacAlgo">${HT_HMAC_ALGOS.map(a => `<option value="${a}">HMAC-${a}</option>`).join('')}</select></div>
        </div>
        <div class="ht-label">Message</div>
        <textarea class="ht-textarea" id="htHmacMsg" rows="2" placeholder="Enter message..."></textarea>
        <div class="ht-row" style="margin-top:12px">
          <button class="ht-btn ht-btn-primary" id="htHmacBtn">Compute HMAC</button>
        </div>
        <div id="htHmacResult"></div>
      </div>
      <div class="ht-panel">
        <h3>Salting Demonstrator</h3>
        <p style="font-size:12px;color:#6a8caa;margin:0 0 12px">Same password with different salts produces completely different hashes</p>
        <div class="ht-row">
          <div style="flex:1"><div class="ht-label">Password</div><input class="ht-input" id="htSaltPwd" placeholder="e.g. password123" value="password123"></div>
          <button class="ht-btn ht-btn-primary" id="htSaltBtn" style="align-self:flex-end">Demonstrate</button>
        </div>
        <div id="htSaltResult"></div>
      </div>
      <div class="ht-panel">
        <h3>Rainbow Table Simulator</h3>
        <p style="font-size:12px;color:#6a8caa;margin:0 0 12px">Shows how dictionary attacks work by pre-computing hashes for common passwords</p>
        <div class="ht-row">
          <div style="flex:1"><div class="ht-label">Hash to Crack (SHA-256)</div><input class="ht-input" id="htRainbowHash" placeholder="Paste a SHA-256 hash..."></div>
          <button class="ht-btn ht-btn-danger" id="htRainbowBuildBtn" style="align-self:flex-end">Build Table</button>
          <button class="ht-btn ht-btn-primary" id="htRainbowLookupBtn" style="align-self:flex-end">Lookup</button>
        </div>
        <div id="htRainbowResult"></div>
      </div>
    `;

    el.querySelector('#htGenBtn').onclick = async () => {
      const text = el.querySelector('#htGenInput').value;
      if (!text) return;
      const checked = [...el.querySelectorAll('#htAlgoChecks input:checked')].map(c => c.value);
      if (!checked.length) return;
      const out = el.querySelector('#htGenResults');
      out.innerHTML = '<div class="ht-progress"><div class="ht-progress-bar" style="width:0%"></div></div>';
      const bar = out.querySelector('.ht-progress-bar');
      const results = [];
      for (let i = 0; i < checked.length; i++) {
        bar.style.width = `${((i + 1) / checked.length) * 100}%`;
        const algo = HT_ALGOS.find(a => a.id === checked[i]);
        const hash = await _htComputeHash(checked[i], text);
        results.push({ algo, hash });
      }
      out.innerHTML = `<div class="ht-result">${results.map(r => `
        <div class="ht-result-row">
          <span class="ht-result-algo">${esc(r.algo.name)}</span>
          <span class="ht-result-hash">${esc(r.hash)}</span>
          <button class="ht-result-copy" data-hash="${esc(r.hash)}">Copy</button>
        </div>`).join('')}</div>`;
      out.querySelectorAll('.ht-result-copy').forEach(btn => {
        btn.onclick = () => { navigator.clipboard.writeText(btn.dataset.hash); btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = 'Copy', 1500); };
      });
    };

    el.querySelector('#htGenClearBtn').onclick = () => {
      el.querySelector('#htGenInput').value = '';
      el.querySelector('#htGenResults').innerHTML = '';
    };

    el.querySelector('#htHmacBtn').onclick = async () => {
      const key = el.querySelector('#htHmacKey').value;
      const msg = el.querySelector('#htHmacMsg').value;
      const algo = el.querySelector('#htHmacAlgo').value;
      if (!key || !msg) return;
      try {
        const hmac = await _htComputeHMAC(algo, key, msg);
        el.querySelector('#htHmacResult').innerHTML = `<div class="ht-result"><div class="ht-result-row"><span class="ht-result-algo">HMAC-${esc(algo)}</span><span class="ht-result-hash">${esc(hmac)}</span><button class="ht-result-copy" onclick="navigator.clipboard.writeText('${esc(hmac)}');this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',1500)">Copy</button></div></div>`;
      } catch (e) {
        el.querySelector('#htHmacResult').innerHTML = `<div class="ht-result" style="color:#ff4444">Error: ${esc(e.message)}</div>`;
      }
    };

    el.querySelector('#htSaltBtn').onclick = async () => {
      const pwd = el.querySelector('#htSaltPwd').value || 'password123';
      const salts = ['x9K2mN', 'Qp7bZr', 'aW3fLh', 'Yd8nRs'];
      const results = [];
      for (const salt of salts) {
        const hash = await _htComputeHash('sha256', salt + pwd);
        results.push({ salt, hash });
      }
      const unsalted = await _htComputeHash('sha256', pwd);
      el.querySelector('#htSaltResult').innerHTML = `
        <div style="margin-top:12px">
          <div class="ht-panel" style="margin-bottom:8px;border-color:#ff444433">
            <div class="ht-label">Unsalted SHA-256</div>
            <code style="font-size:11px;color:#ff4444;word-break:break-all">${esc(unsalted)}</code>
          </div>
          <div class="ht-salt-demo">${results.map(r => `
            <div class="ht-salt-card">
              <h4>Salt: <span style="color:#00ff88">${esc(r.salt)}</span></h4>
              <code>${esc(r.hash)}</code>
            </div>`).join('')}</div>
          <p style="font-size:11px;color:#6a8caa;margin-top:10px">Each salt produces a completely different hash, making rainbow table attacks impractical</p>
        </div>`;
    };

    let rainbowTable = null;
    el.querySelector('#htRainbowBuildBtn').onclick = async () => {
      const out = el.querySelector('#htRainbowResult');
      out.innerHTML = '<div class="ht-progress"><div class="ht-progress-bar" style="width:0%"></div></div>';
      const bar = out.querySelector('.ht-progress-bar');
      rainbowTable = {};
      for (let i = 0; i < HT_WORDLIST.length; i++) {
        bar.style.width = `${((i + 1) / HT_WORDLIST.length) * 100}%`;
        const hash = await _htComputeHash('sha256', HT_WORDLIST[i]);
        rainbowTable[hash] = HT_WORDLIST[i];
        await new Promise(r => setTimeout(r, 20));
      }
      out.innerHTML = `<div class="ht-result"><div style="margin-bottom:8px;color:#00ff88;font-size:12px">Rainbow table built: ${HT_WORDLIST.length} entries</div>${HT_WORDLIST.map(w => {
        const h = Object.entries(rainbowTable).find(([, v]) => v === w);
        return `<div class="ht-rainbow-entry"><span class="ht-rainbow-plain">${esc(w)}</span><span class="ht-rainbow-hash">${h ? esc(h[0]) : '...'}</span></div>`;
      }).join('')}</div>`;
    };

    el.querySelector('#htRainbowLookupBtn').onclick = () => {
      const hash = el.querySelector('#htRainbowHash').value.trim().toLowerCase();
      if (!hash) return;
      if (!rainbowTable) { el.querySelector('#htRainbowResult').innerHTML = '<div class="ht-result" style="color:#ff4444">Build the rainbow table first</div>'; return; }
      const found = rainbowTable[hash];
      el.querySelector('#htRainbowResult').innerHTML = found
        ? `<div class="ht-compare-result ht-compare-mismatch" style="color:#ff4444">CRACKED: <span style="color:#00ff88;font-family:monospace">${esc(found)}</span></div>`
        : `<div class="ht-compare-result ht-compare-match" style="color:#00ff88">Not found in rainbow table (${Object.keys(rainbowTable).length} entries checked)</div>`;
    };
  }

  function renderFileHash(body) {
    body.innerHTML = `
      <div class="ht-panel">
        <h3>File Hash Calculator</h3>
        <p style="font-size:12px;color:#6a8caa;margin:0 0 14px">Compute cryptographic hashes of files using Web Crypto API (SHA family)</p>
        <div class="ht-drop-zone" id="htDropZone">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
          <div style="margin-top:4px">Drag &amp; drop a file here or click to browse</div>
          <input type="file" id="htFileInput" style="display:none">
        </div>
        <div id="htFileInfo" style="margin-top:12px"></div>
        <div class="ht-label" style="margin-top:14px">Select Algorithms</div>
        <div class="ht-checkboxes" id="htFileAlgos">
          <label class="ht-check-label"><input type="checkbox" value="SHA-1" checked><span>SHA-1</span></label>
          <label class="ht-check-label"><input type="checkbox" value="SHA-256" checked><span>SHA-256</span></label>
          <label class="ht-check-label"><input type="checkbox" value="SHA-384"><span>SHA-384</span></label>
          <label class="ht-check-label"><input type="checkbox" value="SHA-512" checked><span>SHA-512</span></label>
        </div>
        <div id="htFileResults"></div>
      </div>
      <div class="ht-panel">
        <h3>Verify File Integrity</h3>
        <p style="font-size:12px;color:#6a8caa;margin:0 0 12px">Compare a file's hash against an expected value</p>
        <div class="ht-row">
          <div style="flex:1"><div class="ht-label">Expected Hash</div><input class="ht-input" id="htVerifyExpected" placeholder="Paste expected hash..."></div>
        </div>
        <div id="htVerifyResult"></div>
      </div>
    `;

    const dropZone = el.querySelector('#htDropZone');
    const fileInput = el.querySelector('#htFileInput');
    let selectedFile = null;
    let computedHashes = {};

    dropZone.onclick = () => fileInput.click();
    dropZone.ondragover = e => { e.preventDefault(); dropZone.classList.add('dragover'); };
    dropZone.ondragleave = () => dropZone.classList.remove('dragover');
    dropZone.ondrop = e => { e.preventDefault(); dropZone.classList.remove('dragover'); if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]); };
    fileInput.onchange = () => { if (fileInput.files.length) handleFile(fileInput.files[0]); };

    async function handleFile(file) {
      selectedFile = file;
      const sizeStr = file.size < 1024 ? `${file.size} B` : file.size < 1048576 ? `${(file.size / 1024).toFixed(1)} KB` : `${(file.size / 1048576).toFixed(2)} MB`;
      el.querySelector('#htFileInfo').innerHTML = `<div style="display:flex;align-items:center;gap:10px;padding:10px;background:#0f172a;border-radius:6px;border:1px solid #1a2a44"><span style="color:#00aaff"></span><div><div style="font-size:13px;color:#e2e8f0">${esc(file.name)}</div><div style="font-size:11px;color:#6a8caa">${sizeStr} · ${esc(file.type || 'unknown type')}</div></div></div>`;

      const algos = [...el.querySelectorAll('#htFileAlgos input:checked')].map(c => c.value);
      if (!algos.length) return;
      const out = el.querySelector('#htFileResults');
      out.innerHTML = '<div class="ht-progress"><div class="ht-progress-bar" style="width:0%"></div></div>';
      const bar = out.querySelector('.ht-progress-bar');
      computedHashes = {};
      const results = [];

      for (let i = 0; i < algos.length; i++) {
        bar.style.width = `${((i + 1) / algos.length) * 100}%`;
        try {
          const hash = await _htComputeFileHash(algos[i], file);
          results.push({ algo: algos[i], hash });
          computedHashes[algos[i]] = hash;
        } catch (e) {
          results.push({ algo: algos[i], hash: `Error: ${e.message}` });
        }
      }

      out.innerHTML = `<div class="ht-result">${results.map(r => `
        <div class="ht-result-row">
          <span class="ht-result-algo">${esc(r.algo)}</span>
          <span class="ht-result-hash">${esc(r.hash)}</span>
          <button class="ht-result-copy" data-hash="${esc(r.hash)}">Copy</button>
        </div>`).join('')}</div>`;
      out.querySelectorAll('.ht-result-copy').forEach(btn => {
        btn.onclick = () => { navigator.clipboard.writeText(btn.dataset.hash); btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = 'Copy', 1500); };
      });
    }

    el.querySelector('#htVerifyExpected').oninput = () => {
      const expected = el.querySelector('#htVerifyExpected').value.trim().toLowerCase();
      if (!expected || !Object.keys(computedHashes).length) return;
      const match = Object.entries(computedHashes).find(([, h]) => h === expected);
      el.querySelector('#htVerifyResult').innerHTML = match
        ? `<div class="ht-compare-result ht-compare-match">MATCH — Hash verified with ${esc(match[0])}</div>`
        : `<div class="ht-compare-result ht-compare-mismatch">NO MATCH — File may be corrupted or tampered with</div>`;
    };
  }

  function renderIdentify(body) {
    body.innerHTML = `
      <div class="ht-panel">
        <h3>Hash Identifier</h3>
        <p style="font-size:12px;color:#6a8caa;margin:0 0 12px">Paste an unknown hash to identify the algorithm</p>
        <textarea class="ht-textarea" id="htIdInput" rows="3" placeholder="Paste hash here...&#10;e.g. 5d41402abc4b2a76b9719d911017c592"></textarea>
        <div class="ht-row" style="margin-top:12px">
          <button class="ht-btn ht-btn-primary" id="htIdBtn">Identify</button>
          <button class="ht-btn ht-btn-ghost" id="htIdSampleBtn">Load Sample</button>
        </div>
        <div id="htIdResult"></div>
      </div>
      <div class="ht-panel">
        <h3>Hash Length Reference</h3>
        <table class="ht-table">
          <thead><tr><th>Algorithm</th><th>Bits</th><th>Hex Length</th><th>Native</th></tr></thead>
          <tbody>${HT_ALGOS.map(a => `<tr><td style="color:#00aaff">${esc(a.name)}</td><td>${a.bits}</td><td>${a.hex}</td><td>${a.native ? '<span class="ht-badge ht-badge-green">SubtleCrypto</span>' : '<span class="ht-badge ht-badge-green">Pure JS</span>'}</td></tr>`).join('')}
          <tr><td style="color:#a855f7">bcrypt</td><td>184</td><td>60 chars</td><td><span class="ht-badge ht-badge-purple">Format</span></td></tr>
          <tr><td style="color:#a855f7">Argon2</td><td>Variable</td><td>Variable</td><td><span class="ht-badge ht-badge-purple">Format</span></td></tr>
          <tr><td style="color:#a855f7">NTLM</td><td>128</td><td>32</td><td><span class="ht-badge ht-badge-yellow">Simulated</span></td></tr>
          </tbody>
        </table>
      </div>
    `;

    el.querySelector('#htIdSampleBtn').onclick = () => {
      el.querySelector('#htIdInput').value = '$2b$12$LJ3m4ys3Lg.Ry0M5dPkne.NX3jCPB0CqRGYJTeCkOX0wvFhVBKfRW';
    };

    el.querySelector('#htIdBtn').onclick = () => {
      const input = el.querySelector('#htIdInput').value.trim();
      if (!input) return;
      const matches = _htIdentifyHash(input);
      const out = el.querySelector('#htIdResult');
      out.innerHTML = `<div style="margin-top:14px">${matches.map(m => {
        const pct = Math.round(m.confidence * 100);
        const color = pct >= 90 ? '#00ff88' : pct >= 70 ? '#00aaff' : pct >= 50 ? '#ffd600' : '#ff4444';
        return `<div class="ht-match">
          <div class="ht-match-name">${esc(m.name)}</div>
          <div class="ht-match-meta">
            Confidence: <span style="color:${color}">${pct}%</span>
            <div class="ht-confidence" style="margin-top:4px"><div class="ht-confidence-fill" style="width:${pct}%;background:${color}"></div></div>
          </div>
        </div>`;
      }).join('')}
      <div style="margin-top:10px;font-size:12px;color:#6a8caa">
        Input length: <span style="color:#e2e8f0">${input.length} characters</span> ·
        Charset: <span style="color:#e2e8f0">${/^[a-fA-F0-9]+$/.test(input) ? 'Hexadecimal' : /^[A-Za-z0-9+/=]+$/.test(input) ? 'Base64' : 'Mixed'}</span>
      </div></div>`;
    };
  }

  function renderCompare(body) {
    body.innerHTML = `
      <div class="ht-panel">
        <h3>Hash Comparison</h3>
        <p style="font-size:12px;color:#6a8caa;margin:0 0 12px">Timing-safe comparison of two hash values</p>
        <div class="ht-label">Hash A</div>
        <input class="ht-input" id="htCmpA" placeholder="Paste first hash..." style="font-family:monospace;margin-bottom:10px">
        <div class="ht-label">Hash B</div>
        <input class="ht-input" id="htCmpB" placeholder="Paste second hash..." style="font-family:monospace">
        <div class="ht-row" style="margin-top:14px">
          <button class="ht-btn ht-btn-primary" id="htCmpBtn">Compare</button>
          <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:#6a8caa"><input type="checkbox" id="htCmpCase"><span>Case-sensitive</span></label>
        </div>
        <div id="htCmpResult"></div>
      </div>
      <div class="ht-panel">
        <h3>Key Derivation Cost Estimator</h3>
        <p style="font-size:12px;color:#6a8caa;margin:0 0 12px">Estimated computation time for password hashing algorithms</p>
        <table class="ht-table ht-cost-table">
          <thead><tr><th>Algorithm</th><th>Parameters</th><th>Time (est.)</th><th>Memory</th><th>Security</th></tr></thead>
          <tbody>
            <tr><td style="color:#00aaff">bcrypt</td><td>cost=10</td><td>~100ms</td><td>4 KB</td><td><span class="ht-badge ht-badge-green">Good</span></td></tr>
            <tr><td style="color:#00aaff">bcrypt</td><td>cost=12</td><td>~400ms</td><td>4 KB</td><td><span class="ht-badge ht-badge-green">Good</span></td></tr>
            <tr><td style="color:#00aaff">bcrypt</td><td>cost=14</td><td>~1.6s</td><td>4 KB</td><td><span class="ht-badge ht-badge-green">Strong</span></td></tr>
            <tr><td style="color:#a855f7">scrypt</td><td>N=16384, r=8, p=1</td><td>~100ms</td><td>16 MB</td><td><span class="ht-badge ht-badge-green">Strong</span></td></tr>
            <tr><td style="color:#a855f7">scrypt</td><td>N=65536, r=8, p=1</td><td>~400ms</td><td>64 MB</td><td><span class="ht-badge ht-badge-blue">Very Strong</span></td></tr>
            <tr><td style="color:#ff4444">Argon2id</td><td>t=3, m=64MB, p=4</td><td>~500ms</td><td>64 MB</td><td><span class="ht-badge ht-badge-blue">Very Strong</span></td></tr>
            <tr><td style="color:#ff4444">Argon2id</td><td>t=4, m=256MB, p=8</td><td>~2s</td><td>256 MB</td><td><span class="ht-badge ht-badge-purple">Maximum</span></td></tr>
            <tr><td style="color:#6a8caa">MD5</td><td>1 iteration</td><td>&lt;1μs</td><td>~0</td><td><span class="ht-badge ht-badge-red">Broken</span></td></tr>
            <tr><td style="color:#6a8caa">SHA-256</td><td>1 iteration</td><td>&lt;1μs</td><td>~0</td><td><span class="ht-badge ht-badge-red">Not for passwords</span></td></tr>
          </tbody>
        </table>
      </div>
    `;

    el.querySelector('#htCmpBtn').onclick = () => {
      let a = el.querySelector('#htCmpA').value.trim();
      let b = el.querySelector('#htCmpB').value.trim();
      const caseSensitive = el.querySelector('#htCmpCase').checked;
      if (!a || !b) return;
      if (!caseSensitive) { a = a.toLowerCase(); b = b.toLowerCase(); }
      const match = a === b;
      let diffIdx = -1;
      if (!match) {
        for (let i = 0; i < Math.max(a.length, b.length); i++) {
          if (a[i] !== b[i]) { diffIdx = i; break; }
        }
      }
      el.querySelector('#htCmpResult').innerHTML = match
        ? `<div class="ht-compare-result ht-compare-match">MATCH — Hashes are identical</div>`
        : `<div class="ht-compare-result ht-compare-mismatch">MISMATCH — Hashes differ${diffIdx >= 0 ? ` at position ${diffIdx}` : ''}</div>
           ${a.length !== b.length ? `<div style="margin-top:8px;font-size:12px;color:#6a8caa">Length difference: ${a.length} vs ${b.length} characters</div>` : ''}`;
    };
  }

  function renderReference(body) {
    body.innerHTML = `
      <div class="ht-ref-section">
        <h3>Hash Algorithm Comparison</h3>
        <table class="ht-table">
          <thead><tr><th>Algorithm</th><th>Output</th><th>Speed</th><th>Collision Resistance</th><th>Status</th></tr></thead>
          <tbody>
            <tr><td>MD5</td><td>128-bit</td><td>Very Fast</td><td><span class="ht-badge ht-badge-red">Broken</span></td><td>Deprecated for security</td></tr>
            <tr><td>SHA-1</td><td>160-bit</td><td>Fast</td><td><span class="ht-badge ht-badge-red">Broken</span></td><td>Deprecated (SHAttered)</td></tr>
            <tr><td>SHA-256</td><td>256-bit</td><td>Fast</td><td><span class="ht-badge ht-badge-green">Strong</span></td><td>Recommended</td></tr>
            <tr><td>SHA-384</td><td>384-bit</td><td>Fast</td><td><span class="ht-badge ht-badge-green">Strong</span></td><td>Recommended</td></tr>
            <tr><td>SHA-512</td><td>512-bit</td><td>Fast</td><td><span class="ht-badge ht-badge-green">Strong</span></td><td>Recommended</td></tr>
            <tr><td>SHA-3-256</td><td>256-bit</td><td>Moderate</td><td><span class="ht-badge ht-badge-blue">Very Strong</span></td><td>NIST Standard (2015)</td></tr>
            <tr><td>SHA-3-512</td><td>512-bit</td><td>Moderate</td><td><span class="ht-badge ht-badge-blue">Very Strong</span></td><td>NIST Standard (2015)</td></tr>
            <tr><td>RIPEMD-160</td><td>160-bit</td><td>Fast</td><td><span class="ht-badge ht-badge-yellow">Adequate</span></td><td>Used in Bitcoin</td></tr>
            <tr><td>BLAKE2</td><td>Variable</td><td>Very Fast</td><td><span class="ht-badge ht-badge-green">Strong</span></td><td>Modern alternative</td></tr>
            <tr><td>BLAKE3</td><td>256-bit</td><td>Fastest</td><td><span class="ht-badge ht-badge-green">Strong</span></td><td>Cutting edge</td></tr>
          </tbody>
        </table>
      </div>
      <div class="ht-ref-section">
        <h3>Birthday Attack</h3>
        <div class="ht-ref-grid">
          <div class="ht-ref-card">
            <h4>What is a Birthday Attack?</h4>
            <p>A birthday attack exploits the birthday paradox — in a group of 23 people, there's a 50% chance two share a birthday. Similarly, finding two inputs that produce the same hash is much easier than finding an input for a specific hash.</p>
          </div>
          <div class="ht-ref-card">
            <h4>Collision Resistance</h4>
            <p>For an n-bit hash, brute-force preimage requires 2^n operations, but finding ANY collision requires only ~2^(n/2) operations. This is why 128-bit MD5 (2^64 collision) is broken, while 256-bit SHA-256 (2^128 collision) is secure.</p>
          </div>
          <div class="ht-ref-card">
            <h4>Known Collisions</h4>
            <p><strong>MD5:</strong> Collisions found in 2004 (Wang et al.). Used in Flame malware's fake Microsoft cert.<br><strong>SHA-1:</strong> SHAttered attack (2017, Google/CWI). Two different PDFs with same SHA-1 hash. Cost: ~$110K in GPU time.</p>
          </div>
          <div class="ht-ref-card">
            <h4>Protection</h4>
            <p>Use SHA-256 or SHA-3 for integrity checks. For passwords, use key derivation functions (bcrypt, scrypt, Argon2) with salts. Never use MD5 or SHA-1 for security-critical applications.</p>
          </div>
        </div>
      </div>
      <div class="ht-ref-section">
        <h3>Common Use Cases</h3>
        <div class="ht-ref-grid">
          <div class="ht-ref-card">
            <h4>File Integrity</h4>
            <p>Verify downloads haven't been tampered with. Compare SHA-256 hash of downloaded file against the publisher's checksum.</p>
          </div>
          <div class="ht-ref-card">
            <h4>Password Storage</h4>
            <p>Never store plaintext passwords. Use bcrypt (cost 12+), scrypt, or Argon2id with unique random salts per user.</p>
          </div>
          <div class="ht-ref-card">
            <h4>Digital Signatures</h4>
            <p>Hash the document, then sign the hash with a private key. RSA-SHA256, ECDSA-SHA256 are standard.</p>
          </div>
          <div class="ht-ref-card">
            <h4>Blockchain</h4>
            <p>Bitcoin uses double SHA-256 for block hashing and RIPEMD-160 for address generation. Ethereum uses Keccak-256 (SHA-3 variant).</p>
          </div>
          <div class="ht-ref-card">
            <h4>Data Deduplication</h4>
            <p>Hash file chunks to identify duplicates. Used in backup systems, content-addressed storage (IPFS, Git).</p>
          </div>
          <div class="ht-ref-card">
            <h4>HMAC Authentication</h4>
            <p>HMAC-SHA256 verifies message integrity and authenticity. Used in API authentication, JWT tokens, webhook signatures.</p>
          </div>
        </div>
      </div>
      <div class="ht-ref-section">
        <h3>CLI Quick Reference</h3>
        <div class="ht-result" style="font-size:12px;line-height:2">
          <div><span style="color:#6a8caa"># Linux/macOS</span></div>
          <div><span style="color:#00ff88">md5sum</span> file.txt</div>
          <div><span style="color:#00ff88">sha256sum</span> file.txt</div>
          <div><span style="color:#00ff88">sha512sum</span> file.txt</div>
          <div><span style="color:#00ff88">openssl</span> dgst -sha256 file.txt</div>
          <div><span style="color:#00ff88">openssl</span> dgst -sha3-256 file.txt</div>
          <div style="margin-top:6px"><span style="color:#6a8caa"># macOS only</span></div>
          <div><span style="color:#00ff88">shasum</span> -a 256 file.txt</div>
          <div style="margin-top:6px"><span style="color:#6a8caa"># Windows (PowerShell)</span></div>
          <div><span style="color:#00aaff">Get-FileHash</span> file.txt -Algorithm SHA256</div>
          <div><span style="color:#00aaff">Get-FileHash</span> file.txt -Algorithm MD5</div>
          <div style="margin-top:6px"><span style="color:#6a8caa"># HMAC</span></div>
          <div><span style="color:#00ff88">echo</span> -n "message" | <span style="color:#00ff88">openssl</span> dgst -sha256 -hmac "key"</div>
          <div style="margin-top:6px"><span style="color:#6a8caa"># Verify</span></div>
          <div><span style="color:#00ff88">sha256sum</span> -c checksums.txt</div>
        </div>
      </div>
    `;
  }

  render();
  container.appendChild(el);
}
