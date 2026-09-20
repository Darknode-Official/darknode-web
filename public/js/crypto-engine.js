// Darknode Crypto Engine — pure JS cryptographic primitives and analysis tools
// No external dependencies. Runs in browser. All functions are ES module exports.

const TE = new TextEncoder();
const TD = new TextDecoder();

// ─── MD5 ────────────────────────────────────────────────────────────────────
// RFC 1321 implementation
const MD5_S = [
  7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
  5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
  4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
  6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
];
const MD5_K = new Uint32Array(64);
for (let i = 0; i < 64; i++) MD5_K[i] = Math.floor(2**32 * Math.abs(Math.sin(i + 1))) >>> 0;

function md5_core(msg) {
  const len = msg.length;
  const bitLen = len * 8;
  const padLen = ((56 - (len + 1) % 64) + 64) % 64;
  const buf = new Uint8Array(len + 1 + padLen + 8);
  buf.set(msg);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(buf.length - 8, bitLen >>> 0, true);
  dv.setUint32(buf.length - 4, (bitLen / 2**32) >>> 0, true);

  let a0 = 0x67452301, b0 = 0xEFCDAB89, c0 = 0x98BADCFE, d0 = 0x10325476;
  const M = new Uint32Array(16);

  for (let off = 0; off < buf.length; off += 64) {
    for (let j = 0; j < 16; j++) M[j] = dv.getUint32(off + j * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16)      { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5*i+1) % 16; }
      else if (i < 48) { F = B ^ C ^ D;           g = (3*i+5) % 16; }
      else              { F = C ^ (B | ~D);        g = (7*i) % 16; }
      F = (F + A + MD5_K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + ((F << MD5_S[i]) | (F >>> (32 - MD5_S[i])))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, a0, true); odv.setUint32(4, b0, true);
  odv.setUint32(8, c0, true); odv.setUint32(12, d0, true);
  return out;
}

export function md5(input) {
  const bytes = typeof input === "string" ? TE.encode(input) : input;
  return hex(md5_core(bytes));
}

// ─── SHA-1 ──────────────────────────────────────────────────────────────────
// FIPS 180-4
function sha1_core(msg) {
  const len = msg.length;
  const bitLen = len * 8;
  const padLen = ((55 - len % 64) + 64) % 64;
  const buf = new Uint8Array(len + 1 + padLen + 8);
  buf.set(msg); buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(buf.length - 4, bitLen >>> 0, false);

  let h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0;
  const W = new Uint32Array(80);

  for (let off = 0; off < buf.length; off += 64) {
    for (let j = 0; j < 16; j++) W[j] = dv.getUint32(off + j*4, false);
    for (let j = 16; j < 80; j++) {
      const x = W[j-3] ^ W[j-8] ^ W[j-14] ^ W[j-16];
      W[j] = (x << 1) | (x >>> 31);
    }
    let a=h0, b=h1, c=h2, d=h3, e=h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20)      { f = (b&c)|((~b)&d);  k = 0x5A827999; }
      else if (i < 40) { f = b^c^d;            k = 0x6ED9EBA1; }
      else if (i < 60) { f = (b&c)|(b&d)|(c&d);k = 0x8F1BBCDC; }
      else              { f = b^c^d;            k = 0xCA62C1D6; }
      const t = (((a<<5)|(a>>>27)) + f + e + k + W[i]) >>> 0;
      e = d; d = c; c = ((b<<30)|(b>>>2)) >>> 0; b = a; a = t;
    }
    h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0; h4=(h4+e)>>>0;
  }
  const out = new Uint8Array(20);
  const odv = new DataView(out.buffer);
  [h0,h1,h2,h3,h4].forEach((v,i) => odv.setUint32(i*4, v, false));
  return out;
}

export function sha1(input) {
  const bytes = typeof input === "string" ? TE.encode(input) : input;
  return hex(sha1_core(bytes));
}

// ─── SHA-256 ────────────────────────────────────────────────────────────────
// FIPS 180-4
const SHA256_K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);

function sha256_core(msg) {
  const len = msg.length;
  const bitLen = len * 8;
  const padLen = ((55 - len % 64) + 64) % 64;
  const buf = new Uint8Array(len + 1 + padLen + 8);
  buf.set(msg); buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(buf.length - 4, bitLen >>> 0, false);

  let H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const W = new Uint32Array(64);

  for (let off = 0; off < buf.length; off += 64) {
    for (let j = 0; j < 16; j++) W[j] = dv.getUint32(off + j*4, false);
    for (let j = 16; j < 64; j++) {
      const s0 = ((W[j-15]>>>7)|(W[j-15]<<25)) ^ ((W[j-15]>>>18)|(W[j-15]<<14)) ^ (W[j-15]>>>3);
      const s1 = ((W[j-2]>>>17)|(W[j-2]<<15)) ^ ((W[j-2]>>>19)|(W[j-2]<<13)) ^ (W[j-2]>>>10);
      W[j] = (W[j-16] + s0 + W[j-7] + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA256_K[i] + W[i]) >>> 0;
      const S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  H.forEach((v,i) => odv.setUint32(i*4, v, false));
  return out;
}

export function sha256(input) {
  const bytes = typeof input === "string" ? TE.encode(input) : input;
  return hex(sha256_core(bytes));
}

// ─── SHA-512 ────────────────────────────────────────────────────────────────
// Uses BigInt for 64-bit operations
const SHA512_K = [
  0x428a2f98d728ae22n,0x7137449123ef65cdn,0xb5c0fbcfec4d3b2fn,0xe9b5dba58189abortn ? 0n : 0xe9b5dba58189dbcen,
].length ? [] : []; // placeholder — full table below

const SHA512_K_FULL = [
  0x428a2f98d728ae22n,0x7137449123ef65cdn,0xb5c0fbcfec4d3b2fn,0xe9b5dba58189dbcen,
  0x3956c25bf348b538n,0x59f111f1b605d019n,0x923f82a4af194f9bn,0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n,0x12835b0145706fben,0x243185be4ee4b28cn,0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn,0x80deb1fe3b1696b1n,0x9bdc06a725c71235n,0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n,0xefbe4786384f25e3n,0x0fc19dc68b8cd5b5n,0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n,0x4a7484aa6ea6e483n,0x5cb0a9dcbd41fbd4n,0x76f988da831153b5n,
  0x983e5152ee66dfabn,0xa831c66d2db43210n,0xb00327c898fb213fn,0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n,0xd5a79147930aa725n,0x06ca6351e003826fn,0x142929670a0e6e70n,
  0x27b70a8546d22ffcn,0x2e1b21385c26c926n,0x4d2c6dfc5ac42aedn,0x53380d139d95b3dfn,
  0x650a73548baf63den,0x766a0abb3c77b2a8n,0x81c2c92e47edaee6n,0x92722c851482353bn,
  0xa2bfe8a14cf10364n,0xa81a664bbc423001n,0xc24b8b70d0f89791n,0xc76c51a30654be30n,
  0xd192e819d6ef5218n,0xd69906245565a910n,0xf40e35855771202an,0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n,0x1e376c085141ab53n,0x2748774cdf8eeb99n,0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n,0x4ed8aa4ae3418acbn,0x5b9cca4f7763e373n,0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn,0x78a5636f43172f60n,0x84c87814a1f0ab72n,0x8cc702081a6439ecn,
  0x90befffa23631e28n,0xa4506cebde82bde9n,0xbef9a3f7b2c67915n,0xc67178f2e372532bn,
  0xca273eceea26619cn,0xd186b8c721c0c207n,0xeada7dd6cde0eb1en,0xf57d4f7fee6ed178n,
  0x06f067aa72176fban,0x0a637dc5a2c898a6n,0x113f9804bef90daen,0x1b710b35131c471bn,
  0x28db77f523047d84n,0x32caab7b40c72493n,0x3c9ebe0a15c9bebcn,0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n,0x597f299cfc657e2an,0x5fcb6fab3ad6faecn,0x6c44198c4a475817n
];

const m64 = 0xFFFFFFFFFFFFFFFFn;
function rotr64(x, n) { return ((x >> BigInt(n)) | (x << BigInt(64-n))) & m64; }

function sha512_core(msg) {
  const len = msg.length;
  const bitLen = BigInt(len) * 8n;
  const padLen = ((111 - len % 128) + 128) % 128;
  const buf = new Uint8Array(len + 1 + padLen + 16);
  buf.set(msg); buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  // Write 128-bit length (we only use lower 64 bits)
  const bl = Number(bitLen & 0xFFFFFFFFn);
  const bh = Number((bitLen >> 32n) & 0xFFFFFFFFn);
  dv.setUint32(buf.length - 4, bl, false);
  dv.setUint32(buf.length - 8, bh, false);

  let H = [
    0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
    0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
  ];
  const W = new Array(80);
  const K = SHA512_K_FULL;

  for (let off = 0; off < buf.length; off += 128) {
    for (let j = 0; j < 16; j++) {
      const hi = BigInt(dv.getUint32(off + j*8, false));
      const lo = BigInt(dv.getUint32(off + j*8+4, false));
      W[j] = ((hi << 32n) | lo) & m64;
    }
    for (let j = 16; j < 80; j++) {
      const s0 = rotr64(W[j-15],1) ^ rotr64(W[j-15],8) ^ (W[j-15] >> 7n);
      const s1 = rotr64(W[j-2],19) ^ rotr64(W[j-2],61) ^ (W[j-2] >> 6n);
      W[j] = (W[j-16] + s0 + W[j-7] + s1) & m64;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let i = 0; i < 80; i++) {
      const S1 = rotr64(e,14) ^ rotr64(e,18) ^ rotr64(e,41);
      const ch = (e & f) ^ (~e & m64 & g);
      const t1 = (h + S1 + ch + K[i] + W[i]) & m64;
      const S0 = rotr64(a,28) ^ rotr64(a,34) ^ rotr64(a,39);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) & m64;
      h=g; g=f; f=e; e=(d+t1)&m64; d=c; c=b; b=a; a=(t1+t2)&m64;
    }
    for (let i = 0; i < 8; i++) H[i] = (H[i] + [a,b,c,d,e,f,g,h][i]) & m64;
  }
  const out = new Uint8Array(64);
  const odv = new DataView(out.buffer);
  H.forEach((v,i) => {
    odv.setUint32(i*8, Number((v >> 32n) & 0xFFFFFFFFn), false);
    odv.setUint32(i*8+4, Number(v & 0xFFFFFFFFn), false);
  });
  return out;
}

export function sha512(input) {
  const bytes = typeof input === "string" ? TE.encode(input) : input;
  return hex(sha512_core(bytes));
}

// ─── HMAC ───────────────────────────────────────────────────────────────────
export function hmac(hashFn, key, message) {
  const coreMap = { md5: [md5_core,64], sha1: [sha1_core,64], sha256: [sha256_core,64], sha512: [sha512_core,128] };
  const entry = coreMap[hashFn];
  if (!entry) throw new Error("Unsupported hash: " + hashFn);
  const [coreFn, blockSize] = entry;
  let keyBytes = typeof key === "string" ? TE.encode(key) : key;
  const msgBytes = typeof message === "string" ? TE.encode(message) : message;
  if (keyBytes.length > blockSize) keyBytes = coreFn(keyBytes);
  const paddedKey = new Uint8Array(blockSize);
  paddedKey.set(keyBytes);
  const ipad = new Uint8Array(blockSize); const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) { ipad[i] = paddedKey[i] ^ 0x36; opad[i] = paddedKey[i] ^ 0x5c; }
  const inner = new Uint8Array(blockSize + msgBytes.length);
  inner.set(ipad); inner.set(msgBytes, blockSize);
  const innerHash = coreFn(inner);
  const outer = new Uint8Array(blockSize + innerHash.length);
  outer.set(opad); outer.set(innerHash, blockSize);
  return hex(coreFn(outer));
}

// ─── Hex helper ─────────────────────────────────────────────────────────────
function hex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}
export function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i*2, 2), 16);
  return out;
}
export function bytesToHex(b) { return hex(b); }

// ─── AES ────────────────────────────────────────────────────────────────────
// AES-128 and AES-256, ECB and CBC modes, PKCS7 padding

const AES_SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]);

const AES_INV_SBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) AES_INV_SBOX[AES_SBOX[i]] = i;

const AES_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d];

function aes_subBytes(state) { for (let i = 0; i < 16; i++) state[i] = AES_SBOX[state[i]]; }
function aes_invSubBytes(state) { for (let i = 0; i < 16; i++) state[i] = AES_INV_SBOX[state[i]]; }

function aes_shiftRows(s) {
  let t;
  t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
  t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
  t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
}
function aes_invShiftRows(s) {
  let t;
  t=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
  t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
  t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
}

function gmul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xFF;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

function aes_mixColumns(s) {
  for (let c = 0; c < 4; c++) {
    const i = c*4;
    const a=s[i], b=s[i+1], cc=s[i+2], d=s[i+3];
    s[i]   = gmul(a,2)^gmul(b,3)^cc^d;
    s[i+1] = a^gmul(b,2)^gmul(cc,3)^d;
    s[i+2] = a^b^gmul(cc,2)^gmul(d,3);
    s[i+3] = gmul(a,3)^b^cc^gmul(d,2);
  }
}
function aes_invMixColumns(s) {
  for (let c = 0; c < 4; c++) {
    const i = c*4;
    const a=s[i], b=s[i+1], cc=s[i+2], d=s[i+3];
    s[i]   = gmul(a,14)^gmul(b,11)^gmul(cc,13)^gmul(d,9);
    s[i+1] = gmul(a,9)^gmul(b,14)^gmul(cc,11)^gmul(d,13);
    s[i+2] = gmul(a,13)^gmul(b,9)^gmul(cc,14)^gmul(d,11);
    s[i+3] = gmul(a,11)^gmul(b,13)^gmul(cc,9)^gmul(d,14);
  }
}

function aes_addRoundKey(state, rk, round) {
  for (let i = 0; i < 16; i++) state[i] ^= rk[round*16 + i];
}

function aes_keyExpansion(key) {
  const nk = key.length / 4; // 4 for AES-128, 8 for AES-256
  const nr = nk + 6; // 10 for 128, 14 for 256
  const rk = new Uint8Array((nr+1)*16);
  rk.set(key);
  for (let i = nk; i < (nr+1)*4; i++) {
    let t = rk.slice((i-1)*4, i*4);
    if (i % nk === 0) {
      t = new Uint8Array([AES_SBOX[t[1]], AES_SBOX[t[2]], AES_SBOX[t[3]], AES_SBOX[t[0]]]);
      t[0] ^= AES_RCON[i/nk - 1];
    } else if (nk > 6 && i % nk === 4) {
      t = new Uint8Array([AES_SBOX[t[0]], AES_SBOX[t[1]], AES_SBOX[t[2]], AES_SBOX[t[3]]]);
    }
    for (let j = 0; j < 4; j++) rk[i*4+j] = rk[(i-nk)*4+j] ^ t[j];
  }
  return { rk, nr };
}

function aes_encryptBlock(block, ek) {
  const state = new Uint8Array(block);
  const { rk, nr } = ek;
  aes_addRoundKey(state, rk, 0);
  for (let r = 1; r < nr; r++) {
    aes_subBytes(state); aes_shiftRows(state); aes_mixColumns(state); aes_addRoundKey(state, rk, r);
  }
  aes_subBytes(state); aes_shiftRows(state); aes_addRoundKey(state, rk, nr);
  return state;
}

function aes_decryptBlock(block, ek) {
  const state = new Uint8Array(block);
  const { rk, nr } = ek;
  aes_addRoundKey(state, rk, nr);
  for (let r = nr-1; r > 0; r--) {
    aes_invShiftRows(state); aes_invSubBytes(state); aes_addRoundKey(state, rk, r); aes_invMixColumns(state);
  }
  aes_invShiftRows(state); aes_invSubBytes(state); aes_addRoundKey(state, rk, 0);
  return state;
}

function pkcs7Pad(data) {
  const pad = 16 - (data.length % 16);
  const out = new Uint8Array(data.length + pad);
  out.set(data);
  for (let i = data.length; i < out.length; i++) out[i] = pad;
  return out;
}
function pkcs7Unpad(data) {
  const pad = data[data.length - 1];
  if (pad < 1 || pad > 16) throw new Error("Invalid PKCS7 padding");
  return data.slice(0, data.length - pad);
}

export function aesEncryptECB(plaintext, key) {
  const keyBytes = typeof key === "string" ? TE.encode(key) : key;
  const ptBytes = typeof plaintext === "string" ? TE.encode(plaintext) : plaintext;
  if (keyBytes.length !== 16 && keyBytes.length !== 32) throw new Error("Key must be 16 or 32 bytes");
  const ek = aes_keyExpansion(keyBytes);
  const padded = pkcs7Pad(ptBytes);
  const out = new Uint8Array(padded.length);
  for (let i = 0; i < padded.length; i += 16) {
    out.set(aes_encryptBlock(padded.slice(i, i+16), ek), i);
  }
  return out;
}

export function aesDecryptECB(ciphertext, key) {
  const keyBytes = typeof key === "string" ? TE.encode(key) : key;
  if (keyBytes.length !== 16 && keyBytes.length !== 32) throw new Error("Key must be 16 or 32 bytes");
  const ek = aes_keyExpansion(keyBytes);
  const out = new Uint8Array(ciphertext.length);
  for (let i = 0; i < ciphertext.length; i += 16) {
    out.set(aes_decryptBlock(ciphertext.slice(i, i+16), ek), i);
  }
  return pkcs7Unpad(out);
}

export function aesEncryptCBC(plaintext, key, iv) {
  const keyBytes = typeof key === "string" ? TE.encode(key) : key;
  const ptBytes = typeof plaintext === "string" ? TE.encode(plaintext) : plaintext;
  const ivBytes = typeof iv === "string" ? hexToBytes(iv) : iv;
  if (ivBytes.length !== 16) throw new Error("IV must be 16 bytes");
  const ek = aes_keyExpansion(keyBytes);
  const padded = pkcs7Pad(ptBytes);
  const out = new Uint8Array(padded.length);
  let prev = new Uint8Array(ivBytes);
  for (let i = 0; i < padded.length; i += 16) {
    const block = padded.slice(i, i+16);
    for (let j = 0; j < 16; j++) block[j] ^= prev[j];
    const enc = aes_encryptBlock(block, ek);
    out.set(enc, i);
    prev = enc;
  }
  return out;
}

export function aesDecryptCBC(ciphertext, key, iv) {
  const keyBytes = typeof key === "string" ? TE.encode(key) : key;
  const ivBytes = typeof iv === "string" ? hexToBytes(iv) : iv;
  const ek = aes_keyExpansion(keyBytes);
  const out = new Uint8Array(ciphertext.length);
  let prev = new Uint8Array(ivBytes);
  for (let i = 0; i < ciphertext.length; i += 16) {
    const block = ciphertext.slice(i, i+16);
    const dec = aes_decryptBlock(block, ek);
    for (let j = 0; j < 16; j++) dec[j] ^= prev[j];
    out.set(dec, i);
    prev = block;
  }
  return pkcs7Unpad(out);
}

// ─── XOR Cipher ─────────────────────────────────────────────────────────────
export function xorEncrypt(data, key) {
  const d = typeof data === "string" ? TE.encode(data) : data;
  const k = typeof key === "string" ? TE.encode(key) : key;
  const out = new Uint8Array(d.length);
  for (let i = 0; i < d.length; i++) out[i] = d[i] ^ k[i % k.length];
  return out;
}

export function xorSingleByteBreak(ciphertext) {
  const ct = typeof ciphertext === "string" ? hexToBytes(ciphertext) : ciphertext;
  const engFreq = "etaoinshrdlcumwfgypbvkjxqz";
  let bestScore = -1, bestKey = 0, bestText = "";
  for (let key = 0; key < 256; key++) {
    const plain = new Uint8Array(ct.length);
    for (let i = 0; i < ct.length; i++) plain[i] = ct[i] ^ key;
    let score = 0;
    for (const b of plain) {
      const c = String.fromCharCode(b).toLowerCase();
      const idx = engFreq.indexOf(c);
      if (idx >= 0) score += 26 - idx;
      if (b >= 32 && b < 127) score += 1;
    }
    if (score > bestScore) { bestScore = score; bestKey = key; bestText = TD.decode(plain); }
  }
  return { key: bestKey, keyHex: bestKey.toString(16).padStart(2,"0"), plaintext: bestText, score: bestScore };
}

// ─── Caesar Cipher ──────────────────────────────────────────────────────────
export function caesarEncrypt(text, shift) {
  return text.replace(/[a-zA-Z]/g, c => {
    const base = c < "a" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26 + 26) % 26 + base);
  });
}

export function caesarDecrypt(text, shift) { return caesarEncrypt(text, -shift); }

export function caesarBruteForce(text) {
  return Array.from({length: 26}, (_, i) => ({ shift: i, text: caesarDecrypt(text, i) }));
}

// ─── Vigenere Cipher ────────────────────────────────────────────────────────
export function vigenereEncrypt(text, key) {
  const k = key.toLowerCase();
  let ki = 0;
  return text.replace(/[a-zA-Z]/g, c => {
    const base = c < "a" ? 65 : 97;
    const shift = k.charCodeAt(ki % k.length) - 97;
    ki++;
    return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
  });
}

export function vigenereDecrypt(text, key) {
  const k = key.toLowerCase();
  let ki = 0;
  return text.replace(/[a-zA-Z]/g, c => {
    const base = c < "a" ? 65 : 97;
    const shift = k.charCodeAt(ki % k.length) - 97;
    ki++;
    return String.fromCharCode(((c.charCodeAt(0) - base - shift + 26) % 26) + base);
  });
}

export function kasiskiExamination(ciphertext) {
  const ct = ciphertext.replace(/[^a-zA-Z]/g, "").toLowerCase();
  const distances = [];
  for (let len = 3; len <= 6; len++) {
    for (let i = 0; i < ct.length - len; i++) {
      const tri = ct.substring(i, i + len);
      const next = ct.indexOf(tri, i + len);
      if (next > 0) distances.push(next - i);
    }
  }
  if (!distances.length) return { likelyKeyLengths: [1], distances };
  const gcdAll = (arr) => arr.reduce((a, b) => { while(b){[a,b]=[b,a%b]} return a; });
  const factors = {};
  for (const d of distances) {
    for (let f = 2; f <= Math.min(d, 20); f++) {
      if (d % f === 0) factors[f] = (factors[f] || 0) + 1;
    }
  }
  const sorted = Object.entries(factors).sort((a,b) => b[1] - a[1]).slice(0, 5).map(e => Number(e[0]));
  return { likelyKeyLengths: sorted.length ? sorted : [1], distances };
}

// ─── RSA Math Helpers ───────────────────────────────────────────────────────
export function modpow(base, exp, mod) {
  base = BigInt(base); exp = BigInt(exp); mod = BigInt(mod);
  if (mod === 1n) return 0n;
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

export function modinv(a, m) {
  a = BigInt(a); m = BigInt(m);
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}

export function millerRabin(n, k = 20) {
  n = BigInt(n);
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;
  let d = n - 1n, r = 0n;
  while (d % 2n === 0n) { d /= 2n; r++; }
  for (let i = 0; i < k; i++) {
    const a = 2n + BigInt(Math.floor(Math.random() * Number(n - 4n < 2n**32n ? n - 4n : 2n**32n))) ;
    let x = modpow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let cont = false;
    for (let j = 0n; j < r - 1n; j++) {
      x = modpow(x, 2n, n);
      if (x === n - 1n) { cont = true; break; }
    }
    if (!cont) return false;
  }
  return true;
}

export function generateRSAKeys(bits = 64) {
  function randPrime(b) {
    while (true) {
      let n = BigInt(Math.floor(Math.random() * 2**(b/2))) | 1n;
      n = n | (1n << BigInt(b/2 - 1));
      if (millerRabin(n, 10)) return n;
    }
  }
  const p = randPrime(bits); const q = randPrime(bits);
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  const e = 65537n;
  const d = modinv(e, phi);
  return { publicKey: { n: n.toString(), e: e.toString() }, privateKey: { n: n.toString(), d: d.toString() }, p: p.toString(), q: q.toString() };
}

// ─── Password Strength ─────────────────────────────────────────────────────
const COMMON_PASSWORDS = ["password","123456","12345678","qwerty","abc123","monkey","1234567","letmein","trustno1","dragon","baseball","iloveyou","master","sunshine","ashley","bailey","passw0rd","shadow","123123","654321","superman","qazwsx","michael","football","password1","password123","welcome","admin","login","hello","charlie","donald","starwars","jordan","access","thunder","master1","batman","1qaz2wsx"];

export function passwordStrength(pw) {
  const len = pw.length;
  let charsetSize = 0;
  if (/[a-z]/.test(pw)) charsetSize += 26;
  if (/[A-Z]/.test(pw)) charsetSize += 26;
  if (/[0-9]/.test(pw)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) charsetSize += 33;
  const entropy = len * Math.log2(charsetSize || 1);
  const patterns = [];
  if (/^[a-z]+$/.test(pw)) patterns.push("all lowercase");
  if (/^[0-9]+$/.test(pw)) patterns.push("all digits");
  if (/(.)\1{2,}/.test(pw)) patterns.push("repeated characters");
  if (/^(012|123|234|345|456|567|678|789|abc|bcd|cde|def|qwe|asd|zxc)/i.test(pw)) patterns.push("sequential pattern");
  const isCommon = COMMON_PASSWORDS.includes(pw.toLowerCase());
  if (isCommon) patterns.push("common password");
  let score;
  if (isCommon || entropy < 20) score = "very weak";
  else if (entropy < 36) score = "weak";
  else if (entropy < 60) score = "moderate";
  else if (entropy < 80) score = "strong";
  else score = "very strong";
  const crackTime = Math.pow(2, entropy) / 1e10; // assuming 10 billion guesses/sec
  return { score, entropy: Math.round(entropy * 10) / 10, charsetSize, patterns, isCommon, crackTimeSeconds: crackTime,
    crackTimeHuman: crackTime < 1 ? "instant" : crackTime < 60 ? Math.round(crackTime)+"s" : crackTime < 3600 ? Math.round(crackTime/60)+"m" : crackTime < 86400 ? Math.round(crackTime/3600)+"h" : crackTime < 31536000 ? Math.round(crackTime/86400)+"d" : Math.round(crackTime/31536000)+"y"
  };
}

// ─── Hash Identifier ────────────────────────────────────────────────────────
export function identifyHash(hashStr) {
  const h = hashStr.trim();
  const candidates = [];
  if (/^[a-f0-9]{32}$/i.test(h)) candidates.push("MD5", "NTLM");
  if (/^[a-f0-9]{40}$/i.test(h)) candidates.push("SHA-1", "RIPEMD-160");
  if (/^[a-f0-9]{56}$/i.test(h)) candidates.push("SHA-224", "SHA3-224");
  if (/^[a-f0-9]{64}$/i.test(h)) candidates.push("SHA-256", "SHA3-256", "BLAKE2s");
  if (/^[a-f0-9]{96}$/i.test(h)) candidates.push("SHA-384", "SHA3-384");
  if (/^[a-f0-9]{128}$/i.test(h)) candidates.push("SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool");
  if (/^\$2[ayb]\$\d{2}\$.{53}$/.test(h)) candidates.push("bcrypt");
  if (/^\$6\$/.test(h)) candidates.push("SHA-512 crypt (Unix)");
  if (/^\$5\$/.test(h)) candidates.push("SHA-256 crypt (Unix)");
  if (/^\$1\$/.test(h)) candidates.push("MD5 crypt (Unix)");
  if (/^[a-f0-9]{16}$/i.test(h)) candidates.push("MySQL (old)", "Half MD5", "DES");
  if (/^[a-f0-9]{48}$/i.test(h)) candidates.push("Haval-192", "Tiger-192");
  if (/^pbkdf2/i.test(h)) candidates.push("PBKDF2");
  if (/^scrypt:/i.test(h)) candidates.push("scrypt");
  if (!candidates.length) candidates.push("Unknown");
  return { hash: h, length: h.length, candidates, mostLikely: candidates[0] };
}

// ─── JWT Decoder ────────────────────────────────────────────────────────────
function b64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return atob(s);
}

export function jwtDecode(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT: expected 3 parts, got " + parts.length);
  try {
    const header = JSON.parse(b64urlDecode(parts[0]));
    const payload = JSON.parse(b64urlDecode(parts[1]));
    const sig = parts[2];
    const isExpired = payload.exp ? Date.now() / 1000 > payload.exp : null;
    const issuedAt = payload.iat ? new Date(payload.iat * 1000).toISOString() : null;
    const expiresAt = payload.exp ? new Date(payload.exp * 1000).toISOString() : null;
    return { header, payload, signature: sig, isExpired, issuedAt, expiresAt, algorithm: header.alg || "none",
      algNone: header.alg === "none", claims: Object.keys(payload) };
  } catch (e) { throw new Error("Invalid JWT: " + e.message); }
}

// ─── X.509 Certificate Parser ───────────────────────────────────────────────
export function parseCertificatePEM(pem) {
  const b64 = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s/g, "");
  const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return parseDER(der);
}

function parseDER(der) {
  let pos = 0;
  function readTag() {
    if (pos >= der.length) return null;
    const tag = der[pos++];
    let len = der[pos++];
    if (len & 0x80) {
      const numBytes = len & 0x7f;
      len = 0;
      for (let i = 0; i < numBytes; i++) len = (len << 8) | der[pos++];
    }
    const value = der.slice(pos, pos + len);
    pos += len;
    return { tag, len, value };
  }
  const fields = {};
  try {
    const seq = readTag(); // outer SEQUENCE
    if (!seq) return { error: "Empty certificate" };
    // Try to extract common fields by pattern matching
    const certDER = seq.value;
    // Extract readable strings
    const strings = [];
    for (let i = 0; i < certDER.length - 2; i++) {
      if ((certDER[i] === 0x0C || certDER[i] === 0x13 || certDER[i] === 0x16) && certDER[i+1] < 128) {
        const slen = certDER[i+1];
        if (i + 2 + slen <= certDER.length) {
          const str = TD.decode(certDER.slice(i+2, i+2+slen));
          if (str.length >= 2 && /^[\x20-\x7E]+$/.test(str)) strings.push(str);
        }
      }
    }
    fields.extractedStrings = strings;
    fields.size = der.length;
    // Look for OID patterns for common cert fields
    const oidCN = [0x55, 0x04, 0x03]; // 2.5.4.3 = Common Name
    const oidOrg = [0x55, 0x04, 0x0A]; // 2.5.4.10 = Organization
    const oidCountry = [0x55, 0x04, 0x06]; // 2.5.4.6 = Country
    for (let i = 0; i < certDER.length - 10; i++) {
      if (certDER[i] === 0x06) { // OID tag
        const olen = certDER[i+1];
        if (olen >= 3 && i+2+olen < certDER.length) {
          const oid = certDER.slice(i+2, i+2+olen);
          const nextPos = i + 2 + olen;
          if (nextPos < certDER.length && (certDER[nextPos] === 0x0C || certDER[nextPos] === 0x13 || certDER[nextPos] === 0x16)) {
            const slen = certDER[nextPos+1];
            const sval = TD.decode(certDER.slice(nextPos+2, nextPos+2+slen));
            if (oid[0]===0x55 && oid[1]===0x04 && oid[2]===0x03) fields.commonName = sval;
            if (oid[0]===0x55 && oid[1]===0x04 && oid[2]===0x0A) fields.organization = fields.organization || sval;
            if (oid[0]===0x55 && oid[1]===0x04 && oid[2]===0x06) fields.country = fields.country || sval;
          }
        }
      }
    }
  } catch (e) { fields.error = e.message; }
  return fields;
}

// ─── Encoding Chains ────────────────────────────────────────────────────────
export function base64Encode(input) {
  const bytes = typeof input === "string" ? TE.encode(input) : input;
  return btoa(String.fromCharCode(...bytes));
}
export function base64Decode(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

const B32_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export function base32Encode(input) {
  const bytes = typeof input === "string" ? TE.encode(input) : input;
  let bits = "", out = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  while (bits.length % 5) bits += "0";
  for (let i = 0; i < bits.length; i += 5) out += B32_ALPHA[parseInt(bits.substr(i, 5), 2)];
  while (out.length % 8) out += "=";
  return out;
}
export function base32Decode(b32) {
  let bits = "";
  for (const c of b32.replace(/=+$/, "")) {
    const idx = B32_ALPHA.indexOf(c.toUpperCase());
    if (idx >= 0) bits += idx.toString(2).padStart(5, "0");
  }
  const out = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(bits.substr(i*8, 8), 2);
  return out;
}

export function urlEncode(str) { return encodeURIComponent(str); }
export function urlDecode(str) { return decodeURIComponent(str); }

export function htmlEncode(str) {
  return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
export function htmlDecode(str) {
  return str.replace(/&amp;/g,"&").replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&quot;/g,'"').replace(/&#39;/g,"'");
}

export function unicodeEscape(str) {
  return str.replace(/[^\x20-\x7E]/g, c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}
export function unicodeUnescape(str) {
  return str.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

export function rot13(str) {
  return str.replace(/[a-zA-Z]/g, c => {
    const base = c < "a" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

// ─── Encoding Chain ─────────────────────────────────────────────────────────
export function encodingChain(input, steps) {
  const ops = {
    base64: base64Encode, base64d: s => TD.decode(base64Decode(s)),
    base32: base32Encode, base32d: s => TD.decode(base32Decode(s)),
    hex: s => hex(TE.encode(s)), hexd: s => TD.decode(hexToBytes(s)),
    url: urlEncode, urld: urlDecode,
    html: htmlEncode, htmld: htmlDecode,
    unicode: unicodeEscape, unicoded: unicodeUnescape,
    rot13: rot13, md5, sha1, sha256, sha512,
  };
  let result = input;
  for (const step of steps) {
    const fn = ops[step];
    if (!fn) throw new Error("Unknown encoding step: " + step);
    result = fn(result);
  }
  return result;
}
