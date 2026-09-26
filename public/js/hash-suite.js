// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d}))throw document.body.innerHTML="",new Error("unlicensed")}());

// ============================================================================
// DARKNODE HASH SUITE — Complete Hashing Toolkit
// Pure JavaScript implementations of MD5, SHA-1, SHA-256, SHA-512, HMAC,
// hash identification, file hashing, password entropy, rainbow table
// estimation, and bcrypt/scrypt cost analysis.
// ============================================================================

// ---------------------------------------------------------------------------
// MD5 Implementation (RFC 1321)
// ---------------------------------------------------------------------------
const MD5 = (function () {
  function safeAdd(x, y) {
    const lsw = (x & 0xffff) + (y & 0xffff);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xffff);
  }
  function bitRotateLeft(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
  }
  function md5cmn(q, a, b, x, s, t) {
    return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
  }
  function md5ff(a, b, c, d, x, s, t) {
    return md5cmn((b & c) | (~b & d), a, b, x, s, t);
  }
  function md5gg(a, b, c, d, x, s, t) {
    return md5cmn((b & d) | (c & ~d), a, b, x, s, t);
  }
  function md5hh(a, b, c, d, x, s, t) {
    return md5cmn(b ^ c ^ d, a, b, x, s, t);
  }
  function md5ii(a, b, c, d, x, s, t) {
    return md5cmn(c ^ (b | ~d), a, b, x, s, t);
  }

  function binlMD5(x, len) {
    x[len >> 5] |= 0x80 << (len % 32);
    x[((len + 64) >>> 9 << 4) + 14] = len;
    let a = 1732584193;
    let b = -271733879;
    let c = -1732584194;
    let d = 271733878;
    for (let i = 0; i < x.length; i += 16) {
      const olda = a, oldb = b, oldc = c, oldd = d;
      a = md5ff(a, b, c, d, x[i],      7, -680876936);
      d = md5ff(d, a, b, c, x[i + 1],  12, -389564586);
      c = md5ff(c, d, a, b, x[i + 2],  17, 606105819);
      b = md5ff(b, c, d, a, x[i + 3],  22, -1044525330);
      a = md5ff(a, b, c, d, x[i + 4],  7, -176418897);
      d = md5ff(d, a, b, c, x[i + 5],  12, 1200080426);
      c = md5ff(c, d, a, b, x[i + 6],  17, -1473231341);
      b = md5ff(b, c, d, a, x[i + 7],  22, -45705983);
      a = md5ff(a, b, c, d, x[i + 8],  7, 1770035416);
      d = md5ff(d, a, b, c, x[i + 9],  12, -1958414417);
      c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
      b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
      a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
      d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
      c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
      b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);

      a = md5gg(a, b, c, d, x[i + 1],  5, -165796510);
      d = md5gg(d, a, b, c, x[i + 6],  9, -1069501632);
      c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
      b = md5gg(b, c, d, a, x[i],      20, -373897302);
      a = md5gg(a, b, c, d, x[i + 5],  5, -701558691);
      d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
      c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
      b = md5gg(b, c, d, a, x[i + 4],  20, -405537848);
      a = md5gg(a, b, c, d, x[i + 9],  5, 568446438);
      d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
      c = md5gg(c, d, a, b, x[i + 3],  14, -187363961);
      b = md5gg(b, c, d, a, x[i + 8],  20, 1163531501);
      a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
      d = md5gg(d, a, b, c, x[i + 2],  9, -51403784);
      c = md5gg(c, d, a, b, x[i + 7],  14, 1735328473);
      b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);

      a = md5hh(a, b, c, d, x[i + 5],  4, -378558);
      d = md5hh(d, a, b, c, x[i + 8],  11, -2022574463);
      c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
      b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
      a = md5hh(a, b, c, d, x[i + 1],  4, -1530992060);
      d = md5hh(d, a, b, c, x[i + 4],  11, 1272893353);
      c = md5hh(c, d, a, b, x[i + 7],  16, -155497632);
      b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
      a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
      d = md5hh(d, a, b, c, x[i + 0],  11, -358537222);
      c = md5hh(c, d, a, b, x[i + 3],  16, -722521979);
      b = md5hh(b, c, d, a, x[i + 6],  23, 76029189);
      a = md5hh(a, b, c, d, x[i + 9],  4, -640364487);
      d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
      c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
      b = md5hh(b, c, d, a, x[i + 2],  23, -995338651);

      a = md5ii(a, b, c, d, x[i],      6, -198630844);
      d = md5ii(d, a, b, c, x[i + 7],  10, 1126891415);
      c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
      b = md5ii(b, c, d, a, x[i + 5],  21, -57434055);
      a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
      d = md5ii(d, a, b, c, x[i + 3],  10, -1894986606);
      c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
      b = md5ii(b, c, d, a, x[i + 1],  21, -2054922799);
      a = md5ii(a, b, c, d, x[i + 8],  6, 1873313359);
      d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
      c = md5ii(c, d, a, b, x[i + 6],  15, -1560198380);
      b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
      a = md5ii(a, b, c, d, x[i + 4],  6, -145523070);
      d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
      c = md5ii(c, d, a, b, x[i + 2],  15, 718787259);
      b = md5ii(b, c, d, a, x[i + 9],  21, -343485551);

      a = safeAdd(a, olda);
      b = safeAdd(b, oldb);
      c = safeAdd(c, oldc);
      d = safeAdd(d, oldd);
    }
    return [a, b, c, d];
  }

  function rstrMD5(s) {
    return binl2rstr(binlMD5(rstr2binl(s), s.length * 8));
  }
  function rstr2hex(input) {
    const hexTab = "0123456789abcdef";
    let output = "";
    for (let i = 0; i < input.length; i++) {
      const x = input.charCodeAt(i);
      output += hexTab.charAt((x >>> 4) & 0x0f) + hexTab.charAt(x & 0x0f);
    }
    return output;
  }
  function str2rstrUTF8(input) {
    let output = "";
    for (let i = 0; i < input.length; i++) {
      const c = input.charCodeAt(i);
      if (c < 128) { output += String.fromCharCode(c); }
      else if (c < 2048) {
        output += String.fromCharCode((c >> 6) | 192);
        output += String.fromCharCode((c & 63) | 128);
      } else {
        output += String.fromCharCode((c >> 12) | 224);
        output += String.fromCharCode(((c >> 6) & 63) | 128);
        output += String.fromCharCode((c & 63) | 128);
      }
    }
    return output;
  }
  function rstr2binl(input) {
    const output = new Array(input.length >> 2);
    for (let i = 0; i < output.length; i++) output[i] = 0;
    for (let i = 0; i < input.length * 8; i += 8) {
      output[i >> 5] |= (input.charCodeAt(i / 8) & 0xff) << (i % 32);
    }
    return output;
  }
  function binl2rstr(input) {
    let output = "";
    for (let i = 0; i < input.length * 32; i += 8) {
      output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xff);
    }
    return output;
  }

  function hmacMD5(key, data) {
    let bkey = rstr2binl(str2rstrUTF8(key));
    if (bkey.length > 16) bkey = binlMD5(bkey, key.length * 8);
    const ipad = new Array(16), opad = new Array(16);
    for (let i = 0; i < 16; i++) {
      ipad[i] = bkey[i] ^ 0x36363636;
      opad[i] = bkey[i] ^ 0x5c5c5c5c;
    }
    const d = str2rstrUTF8(data);
    const hash = binlMD5(ipad.concat(rstr2binl(d)), 512 + d.length * 8);
    return binl2rstr(binlMD5(opad.concat(hash), 512 + 128));
  }

  return {
    hash: function (str) { return rstr2hex(rstrMD5(str2rstrUTF8(str))); },
    hmac: function (key, data) { return rstr2hex(hmacMD5(key, data)); }
  };
})();

// ---------------------------------------------------------------------------
// SHA-1 Implementation (FIPS 180-4)
// ---------------------------------------------------------------------------
const SHA1 = (function () {
  function safeAdd(x, y) {
    const lsw = (x & 0xffff) + (y & 0xffff);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xffff);
  }
  function rol(num, cnt) { return (num << cnt) | (num >>> (32 - cnt)); }
  function str2rstrUTF8(input) {
    let output = "";
    for (let i = 0; i < input.length; i++) {
      const c = input.charCodeAt(i);
      if (c < 128) output += String.fromCharCode(c);
      else if (c < 2048) {
        output += String.fromCharCode((c >> 6) | 192);
        output += String.fromCharCode((c & 63) | 128);
      } else {
        output += String.fromCharCode((c >> 12) | 224);
        output += String.fromCharCode(((c >> 6) & 63) | 128);
        output += String.fromCharCode((c & 63) | 128);
      }
    }
    return output;
  }
  function rstr2hex(input) {
    const hex = "0123456789abcdef";
    let out = "";
    for (let i = 0; i < input.length; i++) {
      const x = input.charCodeAt(i);
      out += hex.charAt((x >>> 4) & 0x0f) + hex.charAt(x & 0x0f);
    }
    return out;
  }
  function rstr2binb(input) {
    const output = new Array(input.length >> 2);
    for (let i = 0; i < output.length; i++) output[i] = 0;
    for (let i = 0; i < input.length * 8; i += 8) {
      output[i >> 5] |= (input.charCodeAt(i / 8) & 0xff) << (24 - (i % 32));
    }
    return output;
  }
  function binb2rstr(input) {
    let output = "";
    for (let i = 0; i < input.length * 32; i += 8) {
      output += String.fromCharCode((input[i >> 5] >>> (24 - (i % 32))) & 0xff);
    }
    return output;
  }
  function binbSHA1(x, len) {
    x[len >> 5] |= 0x80 << (24 - (len % 32));
    x[((len + 64 >> 9) << 4) + 15] = len;
    const w = new Array(80);
    let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878, e = -1009589776;
    for (let i = 0; i < x.length; i += 16) {
      const olda = a, oldb = b, oldc = c, oldd = d, olde = e;
      for (let j = 0; j < 80; j++) {
        if (j < 16) w[j] = x[i + j] || 0;
        else w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
        let f, k;
        if (j < 20)      { f = (b & c) | (~b & d); k = 1518500249; }
        else if (j < 40) { f = b ^ c ^ d; k = 1859775393; }
        else if (j < 60) { f = (b & c) | (b & d) | (c & d); k = -1894007588; }
        else              { f = b ^ c ^ d; k = -899497514; }
        const t = safeAdd(safeAdd(rol(a, 5), f), safeAdd(safeAdd(e, w[j]), k));
        e = d; d = c; c = rol(b, 30); b = a; a = t;
      }
      a = safeAdd(a, olda); b = safeAdd(b, oldb);
      c = safeAdd(c, oldc); d = safeAdd(d, oldd); e = safeAdd(e, olde);
    }
    return [a, b, c, d, e];
  }
  function rstrSHA1(s) { return binb2rstr(binbSHA1(rstr2binb(s), s.length * 8)); }

  function hmacSHA1(key, data) {
    let bkey = rstr2binb(str2rstrUTF8(key));
    if (bkey.length > 16) bkey = binbSHA1(bkey, key.length * 8);
    const ipad = new Array(16), opad = new Array(16);
    for (let i = 0; i < 16; i++) {
      ipad[i] = (bkey[i] || 0) ^ 0x36363636;
      opad[i] = (bkey[i] || 0) ^ 0x5c5c5c5c;
    }
    const d = str2rstrUTF8(data);
    const hash = binbSHA1(ipad.concat(rstr2binb(d)), 512 + d.length * 8);
    return binb2rstr(binbSHA1(opad.concat(hash), 512 + 160));
  }

  return {
    hash: function (str) { return rstr2hex(rstrSHA1(str2rstrUTF8(str))); },
    hmac: function (key, data) { return rstr2hex(hmacSHA1(key, data)); }
  };
})();

// ---------------------------------------------------------------------------
// SHA-256 Implementation (FIPS 180-4)
// ---------------------------------------------------------------------------
const SHA256 = (function () {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function safeAdd(x, y) {
    const lsw = (x & 0xffff) + (y & 0xffff);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xffff);
  }
  function S(X, n) { return (X >>> n) | (X << (32 - n)); }
  function R(X, n) { return (X >>> n); }
  function Ch(x, y, z) { return (x & y) ^ (~x & z); }
  function Maj(x, y, z) { return (x & y) ^ (x & z) ^ (y & z); }
  function Sigma0(x) { return S(x, 2) ^ S(x, 13) ^ S(x, 22); }
  function Sigma1(x) { return S(x, 6) ^ S(x, 11) ^ S(x, 25); }
  function Gamma0(x) { return S(x, 7) ^ S(x, 18) ^ R(x, 3); }
  function Gamma1(x) { return S(x, 17) ^ S(x, 19) ^ R(x, 10); }

  function str2rstrUTF8(input) {
    let output = "";
    for (let i = 0; i < input.length; i++) {
      const c = input.charCodeAt(i);
      if (c < 128) output += String.fromCharCode(c);
      else if (c < 2048) {
        output += String.fromCharCode((c >> 6) | 192);
        output += String.fromCharCode((c & 63) | 128);
      } else {
        output += String.fromCharCode((c >> 12) | 224);
        output += String.fromCharCode(((c >> 6) & 63) | 128);
        output += String.fromCharCode((c & 63) | 128);
      }
    }
    return output;
  }
  function rstr2hex(input) {
    const hex = "0123456789abcdef";
    let out = "";
    for (let i = 0; i < input.length; i++) {
      const x = input.charCodeAt(i);
      out += hex.charAt((x >>> 4) & 0x0f) + hex.charAt(x & 0x0f);
    }
    return out;
  }
  function rstr2binb(input) {
    const output = new Array(input.length >> 2);
    for (let i = 0; i < output.length; i++) output[i] = 0;
    for (let i = 0; i < input.length * 8; i += 8) {
      output[i >> 5] |= (input.charCodeAt(i / 8) & 0xff) << (24 - (i % 32));
    }
    return output;
  }
  function binb2rstr(input) {
    let output = "";
    for (let i = 0; i < input.length * 32; i += 8) {
      output += String.fromCharCode((input[i >> 5] >>> (24 - (i % 32))) & 0xff);
    }
    return output;
  }

  function coreSHA256(m, l) {
    m[l >> 5] |= 0x80 << (24 - (l % 32));
    m[((l + 64 >> 9) << 4) + 15] = l;
    const W = new Array(64);
    let a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
    let e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;
    for (let i = 0; i < m.length; i += 16) {
      const aa = a, bb = b, cc = c, dd = d, ee = e, ff = f, gg = g, hh = h;
      for (let j = 0; j < 64; j++) {
        if (j < 16) W[j] = m[i + j] || 0;
        else W[j] = safeAdd(safeAdd(safeAdd(Gamma1(W[j - 2]), W[j - 7]), Gamma0(W[j - 15])), W[j - 16]);
        const T1 = safeAdd(safeAdd(safeAdd(safeAdd(h, Sigma1(e)), Ch(e, f, g)), K[j]), W[j]);
        const T2 = safeAdd(Sigma0(a), Maj(a, b, c));
        h = g; g = f; f = e; e = safeAdd(d, T1);
        d = c; c = b; b = a; a = safeAdd(T1, T2);
      }
      a = safeAdd(a, aa); b = safeAdd(b, bb); c = safeAdd(c, cc); d = safeAdd(d, dd);
      e = safeAdd(e, ee); f = safeAdd(f, ff); g = safeAdd(g, gg); h = safeAdd(h, hh);
    }
    return [a, b, c, d, e, f, g, h];
  }

  function rstrSHA256(s) { return binb2rstr(coreSHA256(rstr2binb(s), s.length * 8)); }

  function hmacSHA256(key, data) {
    let bkey = rstr2binb(str2rstrUTF8(key));
    if (bkey.length > 16) bkey = coreSHA256(bkey, key.length * 8);
    const ipad = new Array(16), opad = new Array(16);
    for (let i = 0; i < 16; i++) {
      ipad[i] = (bkey[i] || 0) ^ 0x36363636;
      opad[i] = (bkey[i] || 0) ^ 0x5c5c5c5c;
    }
    const d = str2rstrUTF8(data);
    const hash = coreSHA256(ipad.concat(rstr2binb(d)), 512 + d.length * 8);
    return binb2rstr(coreSHA256(opad.concat(hash), 512 + 256));
  }

  return {
    hash: function (str) { return rstr2hex(rstrSHA256(str2rstrUTF8(str))); },
    hmac: function (key, data) { return rstr2hex(hmacSHA256(key, data)); }
  };
})();

// ---------------------------------------------------------------------------
// SHA-512 Implementation (FIPS 180-4) — uses BigInt-free 64-bit emulation
// ---------------------------------------------------------------------------
const SHA512 = (function () {
  function Int64(hi, lo) { this.hi = hi | 0; this.lo = lo | 0; }
  Int64.prototype.clone = function () { return new Int64(this.hi, this.lo); };

  const K = [
    new Int64(0x428a2f98, 0xd728ae22), new Int64(0x71374491, 0x23ef65cd),
    new Int64(0xb5c0fbcf, 0xec4d3b2f), new Int64(0xe9b5dba5, 0x8189dbbc),
    new Int64(0x3956c25b, 0xf348b538), new Int64(0x59f111f1, 0xb605d019),
    new Int64(0x923f82a4, 0xaf194f9b), new Int64(0xab1c5ed5, 0xda6d8118),
    new Int64(0xd807aa98, 0xa3030242), new Int64(0x12835b01, 0x45706fbe),
    new Int64(0x243185be, 0x4ee4b28c), new Int64(0x550c7dc3, 0xd5ffb4e2),
    new Int64(0x72be5d74, 0xf27b896f), new Int64(0x80deb1fe, 0x3b1696b1),
    new Int64(0x9bdc06a7, 0x25c71235), new Int64(0xc19bf174, 0xcf692694),
    new Int64(0xe49b69c1, 0x9ef14ad2), new Int64(0xefbe4786, 0x384f25e3),
    new Int64(0x0fc19dc6, 0x8b8cd5b5), new Int64(0x240ca1cc, 0x77ac9c65),
    new Int64(0x2de92c6f, 0x592b0275), new Int64(0x4a7484aa, 0x6ea6e483),
    new Int64(0x5cb0a9dc, 0xbd41fbd4), new Int64(0x76f988da, 0x831153b5),
    new Int64(0x983e5152, 0xee66dfab), new Int64(0xa831c66d, 0x2db43210),
    new Int64(0xb00327c8, 0x98fb213f), new Int64(0xbf597fc7, 0xbeef0ee4),
    new Int64(0xc6e00bf3, 0x3da88fc2), new Int64(0xd5a79147, 0x930aa725),
    new Int64(0x06ca6351, 0xe003826f), new Int64(0x14292967, 0x0a0e6e70),
    new Int64(0x27b70a85, 0x46d22ffc), new Int64(0x2e1b2138, 0x5c26c926),
    new Int64(0x4d2c6dfc, 0x5ac42aed), new Int64(0x53380d13, 0x9d95b3df),
    new Int64(0x650a7354, 0x8baf63de), new Int64(0x766a0abb, 0x3c77b2a8),
    new Int64(0x81c2c92e, 0x47edaee6), new Int64(0x92722c85, 0x1482353b),
    new Int64(0xa2bfe8a1, 0x4cf10364), new Int64(0xa81a664b, 0xbc423001),
    new Int64(0xc24b8b70, 0xd0f89791), new Int64(0xc76c51a3, 0x0654be30),
    new Int64(0xd192e819, 0xd6ef5218), new Int64(0xd6990624, 0x5565a910),
    new Int64(0xf40e3585, 0x5771202a), new Int64(0x106aa070, 0x32bbd1b8),
    new Int64(0x19a4c116, 0xb8d2d0c8), new Int64(0x1e376c08, 0x5141ab53),
    new Int64(0x2748774c, 0xdf8eeb99), new Int64(0x34b0bcb5, 0xe19b48a8),
    new Int64(0x391c0cb3, 0xc5c95a63), new Int64(0x4ed8aa4a, 0xe3418acb),
    new Int64(0x5b9cca4f, 0x7763e373), new Int64(0x682e6ff3, 0xd6b2b8a3),
    new Int64(0x748f82ee, 0x5defb2fc), new Int64(0x78a5636f, 0x43172f60),
    new Int64(0x84c87814, 0xa1f0ab72), new Int64(0x8cc70208, 0x1a6439ec),
    new Int64(0x90befffa, 0x23631e28), new Int64(0xa4506ceb, 0xde82bde9),
    new Int64(0xbef9a3f7, 0xb2c67915), new Int64(0xc67178f2, 0xe372532b),
    new Int64(0xca273ece, 0xea26619c), new Int64(0xd186b8c7, 0x21c0c207),
    new Int64(0xeada7dd6, 0xcde0eb1e), new Int64(0xf57d4f7f, 0xee6ed178),
    new Int64(0x06f067aa, 0x72176fba), new Int64(0x0a637dc5, 0xa2c898a6),
    new Int64(0x113f9804, 0xbef90dae), new Int64(0x1b710b35, 0x131c471b),
    new Int64(0x28db77f5, 0x23047d84), new Int64(0x32caab7b, 0x40c72493),
    new Int64(0x3c9ebe0a, 0x15c9bebc), new Int64(0x431d67c4, 0x9c100d4c),
    new Int64(0x4cc5d4be, 0xcb3e42b6), new Int64(0x597f299c, 0xfc657e2a),
    new Int64(0x5fcb6fab, 0x3ad6faec), new Int64(0x6c44198c, 0x4a475817)
  ];

  function int64add(dst, a, b) {
    // Read every input before writing dst: dst may alias a (e.g. the final
    // int64add(H[i], H[i], ...) accumulation), and writing dst.lo first would
    // corrupt the carry computation.
    const lo = (a.lo >>> 0) + (b.lo >>> 0);
    const hi = (a.hi + b.hi + (lo > 0xffffffff ? 1 : 0)) | 0;
    dst.lo = lo | 0;
    dst.hi = hi;
  }
  function int64add4(dst, a, b, c, d) {
    const lo = (a.lo >>> 0) + (b.lo >>> 0) + (c.lo >>> 0) + (d.lo >>> 0);
    dst.lo = lo | 0;
    dst.hi = (a.hi + b.hi + c.hi + d.hi + Math.floor(lo / 0x100000000)) | 0;
  }
  function int64add5(dst, a, b, c, d, e) {
    const lo = (a.lo >>> 0) + (b.lo >>> 0) + (c.lo >>> 0) + (d.lo >>> 0) + (e.lo >>> 0);
    dst.lo = lo | 0;
    dst.hi = (a.hi + b.hi + c.hi + d.hi + e.hi + Math.floor(lo / 0x100000000)) | 0;
  }
  function int64shr(dst, x, shift) {
    dst.lo = (x.lo >>> shift) | (x.hi << (32 - shift));
    dst.hi = x.hi >>> shift;
  }
  function int64rotr(dst, x, shift) {
    dst.lo = (x.lo >>> shift) | (x.hi << (32 - shift));
    dst.hi = (x.hi >>> shift) | (x.lo << (32 - shift));
  }
  function int64revrrot(dst, x, shift) {
    dst.lo = (x.hi >>> shift) | (x.lo << (32 - shift));
    dst.hi = (x.lo >>> shift) | (x.hi << (32 - shift));
  }

  function str2rstrUTF8(input) {
    let output = "";
    for (let i = 0; i < input.length; i++) {
      const c = input.charCodeAt(i);
      if (c < 128) output += String.fromCharCode(c);
      else if (c < 2048) {
        output += String.fromCharCode((c >> 6) | 192);
        output += String.fromCharCode((c & 63) | 128);
      } else {
        output += String.fromCharCode((c >> 12) | 224);
        output += String.fromCharCode(((c >> 6) & 63) | 128);
        output += String.fromCharCode((c & 63) | 128);
      }
    }
    return output;
  }
  function rstr2hex(input) {
    const hex = "0123456789abcdef";
    let out = "";
    for (let i = 0; i < input.length; i++) {
      const x = input.charCodeAt(i);
      out += hex.charAt((x >>> 4) & 0x0f) + hex.charAt(x & 0x0f);
    }
    return out;
  }

  function coreSHA512(msg, len) {
    // Pad into 32-bit big-endian words. Each 1024-bit block is 32 words; the
    // low 32 bits of the (128-bit) message length go in the final word of the
    // last block, which is where the compression loop reads W[15].lo.
    const lenWordIdx = (((len + 128) >> 10) << 5) + 31;
    const m = new Array(lenWordIdx + 1);
    for (let i = 0; i < m.length; i++) m[i] = 0;
    for (let i = 0; i < len; i += 8) {
      m[i >> 5] |= (msg.charCodeAt(i / 8) & 0xff) << (24 - (i % 32));
    }
    m[len >> 5] |= 0x80 << (24 - (len % 32));
    m[lenWordIdx] = len;

    const W = new Array(80);
    for (let j = 0; j < 80; j++) W[j] = new Int64(0, 0);
    let H = [
      new Int64(0x6a09e667, 0xf3bcc908), new Int64(0xbb67ae85, 0x84caa73b),
      new Int64(0x3c6ef372, 0xfe94f82b), new Int64(0xa54ff53a, 0x5f1d36f1),
      new Int64(0x510e527f, 0xade682d1), new Int64(0x9b05688c, 0x2b3e6c1f),
      new Int64(0x1f83d9ab, 0xfb41bd6b), new Int64(0x5be0cd19, 0x137e2179)
    ];

    const T1 = new Int64(0, 0), T2 = new Int64(0, 0);
    const s0 = new Int64(0, 0), s1 = new Int64(0, 0);
    const ch = new Int64(0, 0), maj = new Int64(0, 0);
    const r1 = new Int64(0, 0), r2 = new Int64(0, 0), r3 = new Int64(0, 0);

    for (let i = 0; i < m.length; i += 32) {
      const a = H[0].clone(), b = H[1].clone(), c = H[2].clone(), d = H[3].clone();
      const e = H[4].clone(), f = H[5].clone(), g = H[6].clone(), h = H[7].clone();
      for (let j = 0; j < 80; j++) {
        if (j < 16) {
          W[j].hi = m[i + 2 * j] || 0;
          W[j].lo = m[i + 2 * j + 1] || 0;
        } else {
          int64rotr(r1, W[j - 2], 19);
          int64revrrot(r2, W[j - 2], 29);
          int64shr(r3, W[j - 2], 6);
          s1.lo = r1.lo ^ r2.lo ^ r3.lo;
          s1.hi = r1.hi ^ r2.hi ^ r3.hi;
          int64rotr(r1, W[j - 15], 1);
          int64rotr(r2, W[j - 15], 8);
          int64shr(r3, W[j - 15], 7);
          s0.lo = r1.lo ^ r2.lo ^ r3.lo;
          s0.hi = r1.hi ^ r2.hi ^ r3.hi;
          int64add4(W[j], s1, W[j - 7], s0, W[j - 16]);
        }
        int64rotr(r1, e, 14);
        int64rotr(r2, e, 18);
        int64revrrot(r3, e, 9);
        s1.lo = r1.lo ^ r2.lo ^ r3.lo;
        s1.hi = r1.hi ^ r2.hi ^ r3.hi;
        ch.lo = (e.lo & f.lo) ^ (~e.lo & g.lo);
        ch.hi = (e.hi & f.hi) ^ (~e.hi & g.hi);
        int64add5(T1, h, s1, ch, K[j], W[j]);
        int64rotr(r1, a, 28);
        int64revrrot(r2, a, 2);
        int64revrrot(r3, a, 7);
        s0.lo = r1.lo ^ r2.lo ^ r3.lo;
        s0.hi = r1.hi ^ r2.hi ^ r3.hi;
        maj.lo = (a.lo & b.lo) ^ (a.lo & c.lo) ^ (b.lo & c.lo);
        maj.hi = (a.hi & b.hi) ^ (a.hi & c.hi) ^ (b.hi & c.hi);
        int64add(T2, s0, maj);
        h.hi = g.hi; h.lo = g.lo;
        g.hi = f.hi; g.lo = f.lo;
        f.hi = e.hi; f.lo = e.lo;
        int64add(e, d, T1);
        d.hi = c.hi; d.lo = c.lo;
        c.hi = b.hi; c.lo = b.lo;
        b.hi = a.hi; b.lo = a.lo;
        int64add(a, T1, T2);
      }
      int64add(H[0], H[0], a); int64add(H[1], H[1], b);
      int64add(H[2], H[2], c); int64add(H[3], H[3], d);
      int64add(H[4], H[4], e); int64add(H[5], H[5], f);
      int64add(H[6], H[6], g); int64add(H[7], H[7], h);
    }
    let out = "";
    for (let i = 0; i < 8; i++) {
      for (let j = 28; j >= 0; j -= 4) out += "0123456789abcdef".charAt((H[i].hi >>> j) & 0xf);
      for (let j = 28; j >= 0; j -= 4) out += "0123456789abcdef".charAt((H[i].lo >>> j) & 0xf);
    }
    return out;
  }

  return {
    hash: function (str) {
      const s = str2rstrUTF8(str);
      return coreSHA512(s, s.length * 8);
    }
  };
})();

// ---------------------------------------------------------------------------
// Hash Identification Engine
// ---------------------------------------------------------------------------
const HASH_TYPES = [
  { name: "MD5",           len: 32,  regex: /^[a-f0-9]{32}$/i,                       category: "Deprecated", bits: 128,  desc: "Message Digest 5 — 128-bit hash. Collision-broken; do not use for security." },
  { name: "SHA-1",         len: 40,  regex: /^[a-f0-9]{40}$/i,                       category: "Deprecated", bits: 160,  desc: "Secure Hash Algorithm 1 — 160-bit. Collision attacks demonstrated; phase out." },
  { name: "SHA-224",       len: 56,  regex: /^[a-f0-9]{56}$/i,                       category: "Current",    bits: 224,  desc: "SHA-2 family, 224-bit truncated variant of SHA-256." },
  { name: "SHA-256",       len: 64,  regex: /^[a-f0-9]{64}$/i,                       category: "Current",    bits: 256,  desc: "SHA-2 family, 256-bit. Industry standard for integrity and digital signatures." },
  { name: "SHA-384",       len: 96,  regex: /^[a-f0-9]{96}$/i,                       category: "Current",    bits: 384,  desc: "SHA-2 family, 384-bit truncated variant of SHA-512." },
  { name: "SHA-512",       len: 128, regex: /^[a-f0-9]{128}$/i,                      category: "Current",    bits: 512,  desc: "SHA-2 family, 512-bit. Recommended for high-security use." },
  { name: "SHA3-256",      len: 64,  regex: /^[a-f0-9]{64}$/i,                       category: "Current",    bits: 256,  desc: "SHA-3 (Keccak), 256-bit. Independent design from SHA-2." },
  { name: "SHA3-512",      len: 128, regex: /^[a-f0-9]{128}$/i,                      category: "Current",    bits: 512,  desc: "SHA-3 (Keccak), 512-bit variant." },
  { name: "RIPEMD-160",    len: 40,  regex: /^[a-f0-9]{40}$/i,                       category: "Legacy",     bits: 160,  desc: "RACE Integrity Primitives, 160-bit. Used in Bitcoin address generation." },
  { name: "BLAKE2b-256",   len: 64,  regex: /^[a-f0-9]{64}$/i,                       category: "Modern",     bits: 256,  desc: "BLAKE2b with 256-bit output. Faster than SHA-256 on modern CPUs." },
  { name: "BLAKE2b-512",   len: 128, regex: /^[a-f0-9]{128}$/i,                      category: "Modern",     bits: 512,  desc: "BLAKE2b with 512-bit output. Default BLAKE2 configuration." },
  { name: "BLAKE3",        len: 64,  regex: /^[a-f0-9]{64}$/i,                       category: "Modern",     bits: 256,  desc: "BLAKE3. Extremely fast, parallelizable. Default 256-bit output." },
  { name: "CRC32",         len: 8,   regex: /^[a-f0-9]{8}$/i,                        category: "Checksum",   bits: 32,   desc: "Cyclic Redundancy Check. Error detection, not cryptographic." },
  { name: "CRC64",         len: 16,  regex: /^[a-f0-9]{16}$/i,                       category: "Checksum",   bits: 64,   desc: "64-bit CRC variant. Error detection for large data." },
  { name: "Adler-32",      len: 8,   regex: /^[a-f0-9]{8}$/i,                        category: "Checksum",   bits: 32,   desc: "Adler-32. Faster than CRC32 but weaker error detection." },
  { name: "MD4",           len: 32,  regex: /^[a-f0-9]{32}$/i,                       category: "Broken",     bits: 128,  desc: "Message Digest 4. Predecessor to MD5; severely broken." },
  { name: "NTLM",         len: 32,  regex: /^[a-f0-9]{32}$/i,                        category: "Windows",    bits: 128,  desc: "Windows NTLM hash (MD4 of UTF-16LE password). Very fast to crack." },
  { name: "MySQL 4.1+",   len: 40,  regex: /^\*[a-f0-9]{40}$/i,                      category: "Database",   bits: 160,  desc: "MySQL password hash. SHA1(SHA1(password)) with * prefix." },
  { name: "bcrypt",        len: null, regex: /^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$/, category: "KDF",       bits: 184,  desc: "Adaptive password hash. Cost factor makes brute-force expensive." },
  { name: "scrypt",        len: null, regex: /^\$s0\$/,                               category: "KDF",        bits: 256,  desc: "Memory-hard password KDF. Resistant to GPU/ASIC attacks." },
  { name: "Argon2",        len: null, regex: /^\$argon2(id?|d)\$/,                    category: "KDF",        bits: 256,  desc: "Winner of Password Hashing Competition. Recommended for new systems." },
  { name: "PBKDF2",        len: null, regex: /^\$pbkdf2/,                             category: "KDF",        bits: null, desc: "Password-Based Key Derivation Function 2. NIST recommended." },
  { name: "Django PBKDF2", len: null, regex: /^pbkdf2_sha256\$/,                      category: "Framework",  bits: 256,  desc: "Django's default password hasher using PBKDF2-SHA256." },
  { name: "Wordpress",     len: null, regex: /^\$P\$[./0-9A-Za-z]{31}$/,              category: "Framework",  bits: 128,  desc: "WordPress/phpBB phpass portable hash." },
  { name: "Unix MD5",      len: null, regex: /^\$1\$[./0-9A-Za-z]{8}\$[./0-9A-Za-z]{22}$/, category: "Unix",  bits: 128, desc: "Unix crypt MD5. 1000 rounds of MD5 with salt." },
  { name: "Unix SHA-256",  len: null, regex: /^\$5\$/,                                category: "Unix",       bits: 256,  desc: "Unix crypt SHA-256. Configurable rounds (default 5000)." },
  { name: "Unix SHA-512",  len: null, regex: /^\$6\$/,                                category: "Unix",       bits: 512,  desc: "Unix crypt SHA-512. Default on modern Linux /etc/shadow." },
  { name: "LM Hash",       len: 32,  regex: /^[a-f0-9]{32}$/i,                       category: "Windows",    bits: 128,  desc: "LAN Manager hash. DES-based; splits password into 7-char halves. Extremely weak." },
  { name: "Whirlpool",     len: 128, regex: /^[a-f0-9]{128}$/i,                      category: "Legacy",     bits: 512,  desc: "512-bit hash based on AES-like block cipher. ISO/IEC 10118-3." },
  { name: "Tiger-192",     len: 48,  regex: /^[a-f0-9]{48}$/i,                       category: "Legacy",     bits: 192,  desc: "192-bit hash optimized for 64-bit platforms." },
  { name: "GOST R 34.11",  len: 64,  regex: /^[a-f0-9]{64}$/i,                       category: "National",   bits: 256,  desc: "Russian cryptographic hash standard (Streebog)." },
  { name: "SM3",           len: 64,  regex: /^[a-f0-9]{64}$/i,                       category: "National",   bits: 256,  desc: "Chinese cryptographic hash standard." },
];

function identifyHash(input) {
  if (!input || typeof input !== "string") return [];
  const trimmed = input.trim();
  const matches = [];
  for (const ht of HASH_TYPES) {
    if (ht.regex.test(trimmed)) {
      matches.push({ ...ht, confidence: ht.len === trimmed.length ? "high" : ht.len === null ? "high" : "medium" });
    }
  }
  if (matches.length > 1) {
    matches.sort((a, b) => (a.confidence === "high" ? 0 : 1) - (b.confidence === "high" ? 0 : 1));
  }
  return matches;
}

// ---------------------------------------------------------------------------
// Password Entropy Calculator
// ---------------------------------------------------------------------------
function calcEntropy(password) {
  if (!password) return { entropy: 0, charset: 0, strength: "none", crackTime: "instant" };
  let charset = 0;
  let hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false, hasExtended = false;
  for (let i = 0; i < password.length; i++) {
    const c = password.charCodeAt(i);
    if (c >= 97 && c <= 122) hasLower = true;
    else if (c >= 65 && c <= 90) hasUpper = true;
    else if (c >= 48 && c <= 57) hasDigit = true;
    else if (c >= 33 && c <= 126) hasSpecial = true;
    else hasExtended = true;
  }
  if (hasLower)    charset += 26;
  if (hasUpper)    charset += 26;
  if (hasDigit)    charset += 10;
  if (hasSpecial)  charset += 33;
  if (hasExtended) charset += 128;
  const entropy = Math.log2(Math.pow(charset, password.length));
  let strength, crackTime;
  const seconds = Math.pow(2, entropy) / 10e9;
  if (entropy < 28)      { strength = "very weak"; crackTime = "< 1 second"; }
  else if (entropy < 36) { strength = "weak"; crackTime = formatTime(seconds); }
  else if (entropy < 60) { strength = "reasonable"; crackTime = formatTime(seconds); }
  else if (entropy < 80) { strength = "strong"; crackTime = formatTime(seconds); }
  else if (entropy < 100){ strength = "very strong"; crackTime = formatTime(seconds); }
  else                    { strength = "excellent"; crackTime = formatTime(seconds); }
  const patterns = [];
  if (/^[a-z]+$/.test(password)) patterns.push("lowercase only — add uppercase, digits, symbols");
  if (/^[A-Z]+$/.test(password)) patterns.push("uppercase only — add lowercase, digits, symbols");
  if (/^[0-9]+$/.test(password)) patterns.push("digits only — extremely weak");
  if (/^(.)\1+$/.test(password)) patterns.push("repeated character — trivially crackable");
  if (/^(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password)) patterns.push("starts with a sequential pattern");
  if (/^(password|123456|qwerty|admin|letmein|welcome|monkey|dragon|master|login)/i.test(password)) patterns.push("common password — will be cracked instantly");
  if (password.length < 8) patterns.push("too short — use at least 12 characters");
  return { entropy: Math.round(entropy * 100) / 100, charset, strength, crackTime, length: password.length, patterns };
}

function formatTime(seconds) {
  if (seconds < 1)              return "< 1 second";
  if (seconds < 60)             return Math.round(seconds) + " seconds";
  if (seconds < 3600)           return Math.round(seconds / 60) + " minutes";
  if (seconds < 86400)          return Math.round(seconds / 3600) + " hours";
  if (seconds < 2592000)        return Math.round(seconds / 86400) + " days";
  if (seconds < 31536000)       return Math.round(seconds / 2592000) + " months";
  if (seconds < 31536000000)    return Math.round(seconds / 31536000) + " years";
  if (seconds < 31536000000000) return Math.round(seconds / 31536000000) + " millennia";
  return "heat death of the universe";
}

// ---------------------------------------------------------------------------
// Rainbow Table Size Estimator
// ---------------------------------------------------------------------------
function estimateRainbowTable(charset, maxLen, hashBits, chainLen, numTables) {
  charset   = charset   || 95;
  maxLen    = maxLen    || 8;
  hashBits  = hashBits || 128;
  chainLen  = chainLen || 10000;
  numTables = numTables || 1;
  let keyspace = 0;
  for (let i = 1; i <= maxLen; i++) keyspace += Math.pow(charset, i);
  const numChains = Math.ceil(keyspace / chainLen);
  const hashBytes = hashBits / 8;
  const endpointBytes = maxLen;
  const chainSize = hashBytes + endpointBytes + 4;
  const tableSize = numChains * chainSize;
  const totalSize = tableSize * numTables;
  const successRate = 1 - Math.pow(1 - 1 / chainLen, chainLen * numTables);
  return {
    keyspace: keyspace,
    keyspaceFormatted: formatNumber(keyspace),
    numChains: numChains,
    chainLength: chainLen,
    singleTableBytes: tableSize,
    singleTableFormatted: formatBytes(tableSize),
    totalBytes: totalSize,
    totalFormatted: formatBytes(totalSize),
    successRate: (successRate * 100).toFixed(2) + "%",
    numTables: numTables,
    charset: charset,
    maxLen: maxLen,
    hashBits: hashBits,
    computeTime: formatTime(keyspace / 1e9)
  };
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(2) + " KB";
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + " MB";
  if (bytes < 1099511627776) return (bytes / 1073741824).toFixed(2) + " GB";
  return (bytes / 1099511627776).toFixed(2) + " TB";
}

function formatNumber(n) {
  if (n < 1e6) return n.toLocaleString();
  if (n < 1e9) return (n / 1e6).toFixed(2) + " million";
  if (n < 1e12) return (n / 1e9).toFixed(2) + " billion";
  if (n < 1e15) return (n / 1e12).toFixed(2) + " trillion";
  if (n < 1e18) return (n / 1e15).toFixed(2) + " quadrillion";
  return n.toExponential(3);
}

// ---------------------------------------------------------------------------
// Bcrypt / Scrypt Cost Calculator
// ---------------------------------------------------------------------------
function bcryptCostEstimate(costFactor) {
  const baseTimeMs = 0.2;
  const iterations = Math.pow(2, costFactor);
  const timeMs = baseTimeMs * iterations;
  const hashesPerSec = 1000 / timeMs;
  const entropyBits = [40, 50, 60, 70, 80];
  const estimates = entropyBits.map(bits => ({
    entropy: bits,
    combinations: Math.pow(2, bits),
    crackTime: formatTime(Math.pow(2, bits) / hashesPerSec),
    crackTimeGPU: formatTime(Math.pow(2, bits) / (hashesPerSec * 1000))
  }));
  return {
    costFactor: costFactor,
    iterations: iterations,
    timePerHash: timeMs < 1000 ? timeMs.toFixed(2) + " ms" : (timeMs / 1000).toFixed(2) + " s",
    hashesPerSecCPU: Math.round(hashesPerSec),
    hashesPerSecGPU: Math.round(hashesPerSec * 1000),
    recommendation: costFactor < 10 ? "Too low — use at least 12" : costFactor < 12 ? "Below recommended minimum" : costFactor <= 14 ? "Good for most applications" : "Very strong but may be slow for interactive login",
    estimates: estimates
  };
}

function scryptCostEstimate(N, r, p) {
  N = N || 16384;
  r = r || 8;
  p = p || 1;
  const memoryBytes = 128 * N * r;
  const cpuCost = 128 * N * r * p;
  const timeEstMs = (N * r * p) / 50000;
  return {
    N: N,
    r: r,
    p: p,
    memory: formatBytes(memoryBytes),
    memoryBytes: memoryBytes,
    cpuCost: formatNumber(cpuCost),
    timePerHash: timeEstMs < 1000 ? timeEstMs.toFixed(1) + " ms" : (timeEstMs / 1000).toFixed(2) + " s",
    recommendation: memoryBytes < 16777216 ? "Below recommended — increase N" : memoryBytes < 67108864 ? "Acceptable for interactive use" : memoryBytes < 268435456 ? "Strong — suitable for file encryption" : "Very strong — may use excessive memory",
    comparison: {
      bcrypt12: "bcrypt cost 12 uses ~4 KB memory",
      currentScrypt: `scrypt(N=${N}, r=${r}, p=${p}) uses ${formatBytes(memoryBytes)} memory`,
      advantage: `scrypt uses ${Math.round(memoryBytes / 4096)}x more memory than bcrypt, making GPU attacks harder`
    }
  };
}

// ---------------------------------------------------------------------------
// HMAC Calculator (wraps MD5, SHA-1, SHA-256)
// ---------------------------------------------------------------------------
function computeHMAC(algorithm, key, message) {
  switch ((algorithm || "").toLowerCase().replace(/[- ]/g, "")) {
    case "md5":    return MD5.hmac(key, message);
    case "sha1":   return SHA1.hmac(key, message);
    case "sha256": return SHA256.hmac(key, message);
    default:       return "Unsupported algorithm: " + algorithm;
  }
}

// ---------------------------------------------------------------------------
// File Hash Calculator (uses FileReader API)
// ---------------------------------------------------------------------------
async function hashFile(file, algorithm, progressCallback) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = function (e) {
      const data = e.target.result;
      let text = "";
      const bytes = new Uint8Array(data);
      for (let i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
      if (progressCallback) progressCallback(50);
      let result;
      switch ((algorithm || "sha256").toLowerCase().replace(/[- ]/g, "")) {
        case "md5":    result = MD5.hash(text); break;
        case "sha1":   result = SHA1.hash(text); break;
        case "sha256": result = SHA256.hash(text); break;
        case "sha512": result = SHA512.hash(text); break;
        default:       result = SHA256.hash(text); break;
      }
      if (progressCallback) progressCallback(100);
      resolve({
        filename: file.name,
        size: file.size,
        sizeFormatted: formatBytes(file.size),
        type: file.type || "unknown",
        algorithm: algorithm || "sha256",
        hash: result,
        timestamp: new Date().toISOString()
      });
    };
    reader.onerror = function () { reject(new Error("Failed to read file")); };
    reader.readAsArrayBuffer(file);
  });
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------
const HASH_STYLES = `
  .hs-wrap { font-family: var(--mono, 'JetBrains Mono', monospace); color: var(--txt, #e0e6ed); max-width: 1100px; margin: 0 auto; padding: 24px; }
  .hs-title { font-family: var(--sans, 'Sora', system-ui, sans-serif); font-size: 1.75rem; font-weight: 700; margin-bottom: 8px; background: linear-gradient(135deg, #00d4ff, #7c5cff); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .hs-subtitle { color: var(--txt-2, #8899aa); font-size: 0.85rem; margin-bottom: 24px; font-family: var(--sans, 'Sora', system-ui, sans-serif); }
  .hs-tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border, #1a2233); margin-bottom: 20px; flex-wrap: wrap; }
  .hs-tab { padding: 8px 16px; cursor: pointer; font-size: 0.8rem; border: none; background: transparent; color: var(--txt-2, #8899aa); border-bottom: 2px solid transparent; transition: all 0.15s; font-family: inherit; }
  .hs-tab:hover { color: var(--txt, #e0e6ed); background: rgba(0,212,255,0.05); }
  .hs-tab.active { color: #00d4ff; border-bottom-color: #00d4ff; }
  .hs-panel { display: none; }
  .hs-panel.active { display: block; }
  .hs-card { background: var(--card, #0d1117); border: 1px solid var(--border, #1a2233); border-radius: 8px; padding: 20px; margin-bottom: 16px; }
  .hs-card h3 { font-size: 1rem; font-weight: 600; margin: 0 0 12px; color: var(--txt, #e0e6ed); font-family: var(--sans, 'Sora', system-ui, sans-serif); }
  .hs-input-group { margin-bottom: 12px; }
  .hs-label { display: block; font-size: 0.75rem; color: var(--txt-2, #8899aa); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.05em; }
  .hs-input, .hs-textarea { width: 100%; box-sizing: border-box; padding: 10px 12px; background: var(--input-bg, #161b22); border: 1px solid var(--border, #1a2233); border-radius: 6px; color: var(--txt, #e0e6ed); font-family: inherit; font-size: 0.85rem; outline: none; transition: border-color 0.15s; }
  .hs-input:focus, .hs-textarea:focus { border-color: #00d4ff; }
  .hs-textarea { resize: vertical; min-height: 80px; }
  .hs-select { padding: 8px 12px; background: var(--input-bg, #161b22); border: 1px solid var(--border, #1a2233); border-radius: 6px; color: var(--txt, #e0e6ed); font-family: inherit; font-size: 0.85rem; outline: none; cursor: pointer; }
  .hs-btn { padding: 8px 18px; border: none; border-radius: 6px; cursor: pointer; font-family: inherit; font-size: 0.8rem; font-weight: 600; transition: all 0.15s; }
  .hs-btn-primary { background: linear-gradient(135deg, #00d4ff, #0090b3); color: #000; }
  .hs-btn-primary:hover { filter: brightness(1.15); transform: translateY(-1px); }
  .hs-btn-ghost { background: transparent; color: #00d4ff; border: 1px solid rgba(0,212,255,0.3); }
  .hs-btn-ghost:hover { background: rgba(0,212,255,0.1); }
  .hs-output { background: #0a0e16; border: 1px solid var(--border, #1a2233); border-radius: 6px; padding: 12px; font-size: 0.82rem; word-break: break-all; margin-top: 8px; min-height: 36px; position: relative; user-select: all; }
  .hs-copy-btn { position: absolute; top: 6px; right: 6px; padding: 4px 10px; font-size: 0.7rem; background: rgba(0,212,255,0.15); color: #00d4ff; border: none; border-radius: 4px; cursor: pointer; font-family: inherit; }
  .hs-copy-btn:hover { background: rgba(0,212,255,0.3); }
  .hs-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }
  .hs-results-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; margin-top: 12px; }
  .hs-results-table th { text-align: left; padding: 8px 12px; background: #0a0e16; border-bottom: 1px solid var(--border, #1a2233); color: var(--txt-2, #8899aa); font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.7rem; }
  .hs-results-table td { padding: 8px 12px; border-bottom: 1px solid rgba(26,34,51,0.5); vertical-align: top; }
  .hs-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }
  .hs-badge-green { background: rgba(0,200,83,0.15); color: #00c853; }
  .hs-badge-yellow { background: rgba(255,183,77,0.15); color: #ffb74d; }
  .hs-badge-red { background: rgba(244,67,54,0.15); color: #f44336; }
  .hs-badge-blue { background: rgba(0,212,255,0.15); color: #00d4ff; }
  .hs-badge-purple { background: rgba(124,92,255,0.15); color: #7c5cff; }
  .hs-meter { height: 8px; background: #161b22; border-radius: 4px; overflow: hidden; margin-top: 6px; }
  .hs-meter-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
  .hs-file-drop { border: 2px dashed var(--border, #1a2233); border-radius: 8px; padding: 40px; text-align: center; color: var(--txt-2, #8899aa); cursor: pointer; transition: all 0.15s; }
  .hs-file-drop:hover, .hs-file-drop.dragover { border-color: #00d4ff; background: rgba(0,212,255,0.05); color: #00d4ff; }
  .hs-file-drop input { display: none; }
  .hs-progress { width: 100%; height: 4px; background: #161b22; border-radius: 2px; margin-top: 8px; overflow: hidden; display: none; }
  .hs-progress.active { display: block; }
  .hs-progress-bar { height: 100%; background: linear-gradient(90deg, #00d4ff, #7c5cff); border-radius: 2px; transition: width 0.3s; width: 0; }
  .hs-compare-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
  .hs-match { color: #00c853; font-weight: 600; }
  .hs-nomatch { color: #f44336; font-weight: 600; }
  .hs-info-row { display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid rgba(26,34,51,0.3); }
  .hs-info-label { color: var(--txt-2, #8899aa); font-size: 0.8rem; }
  .hs-info-value { color: var(--txt, #e0e6ed); font-size: 0.85rem; font-weight: 500; }
  .hs-slider-group { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  .hs-slider { flex: 1; accent-color: #00d4ff; }
  .hs-slider-val { min-width: 40px; text-align: right; font-size: 0.85rem; color: #00d4ff; font-weight: 600; }
  @media (max-width: 700px) {
    .hs-grid { grid-template-columns: 1fr; }
    .hs-compare-row { grid-template-columns: 1fr; }
    .hs-tabs { gap: 0; }
    .hs-tab { padding: 6px 10px; font-size: 0.72rem; }
  }
`;

// ---------------------------------------------------------------------------
// UI Renderer
// ---------------------------------------------------------------------------
export function renderHashSuite(container) {
  const styleEl = document.createElement("style");
  styleEl.textContent = HASH_STYLES;
  document.head.appendChild(styleEl);

  container.innerHTML = `
    <div class="hs-wrap">
      <div class="hs-title">Hash Suite</div>
      <div class="hs-subtitle">Compute, identify, compare, and analyze cryptographic hashes — entirely in your browser</div>

      <div class="hs-tabs" id="hs-tabs">
        <button class="hs-tab active" data-panel="compute">Compute</button>
        <button class="hs-tab" data-panel="identify">Identify</button>
        <button class="hs-tab" data-panel="compare">Compare</button>
        <button class="hs-tab" data-panel="file">File Hash</button>
        <button class="hs-tab" data-panel="hmac">HMAC</button>
        <button class="hs-tab" data-panel="entropy">Password Entropy</button>
        <button class="hs-tab" data-panel="rainbow">Rainbow Table</button>
        <button class="hs-tab" data-panel="cost">KDF Cost</button>
        <button class="hs-tab" data-panel="reference">Reference</button>
      </div>

      <!-- COMPUTE PANEL -->
      <div class="hs-panel active" id="panel-compute">
        <div class="hs-card">
          <h3>Compute Hash</h3>
          <div class="hs-input-group">
            <label class="hs-label">Input Text</label>
            <textarea class="hs-textarea" id="compute-input" placeholder="Type or paste text to hash..."></textarea>
          </div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
            <select class="hs-select" id="compute-algo">
              <option value="md5">MD5</option>
              <option value="sha1">SHA-1</option>
              <option value="sha256" selected>SHA-256</option>
              <option value="sha512">SHA-512</option>
              <option value="all">All algorithms</option>
            </select>
            <select class="hs-select" id="compute-format">
              <option value="hex">Hex (lowercase)</option>
              <option value="HEX">Hex (UPPERCASE)</option>
              <option value="base64">Base64</option>
            </select>
            <button class="hs-btn hs-btn-primary" id="compute-btn">Hash</button>
            <button class="hs-btn hs-btn-ghost" id="compute-clear">Clear</button>
          </div>
          <div id="compute-output"></div>
        </div>
      </div>

      <!-- IDENTIFY PANEL -->
      <div class="hs-panel" id="panel-identify">
        <div class="hs-card">
          <h3>Identify Hash Type</h3>
          <div class="hs-input-group">
            <label class="hs-label">Paste a hash</label>
            <input class="hs-input" id="identify-input" placeholder="e.g. 5d41402abc4b2a76b9719d911017c592">
          </div>
          <button class="hs-btn hs-btn-primary" id="identify-btn">Identify</button>
          <div id="identify-output"></div>
        </div>
      </div>

      <!-- COMPARE PANEL -->
      <div class="hs-panel" id="panel-compare">
        <div class="hs-card">
          <h3>Compare Hashes</h3>
          <p style="font-size:0.8rem;color:var(--txt-2,#8899aa);margin:0 0 12px;">Paste two hashes to check if they match (constant-time comparison).</p>
          <div class="hs-compare-row">
            <div class="hs-input-group">
              <label class="hs-label">Hash A</label>
              <input class="hs-input" id="compare-a" placeholder="First hash...">
            </div>
            <div class="hs-input-group">
              <label class="hs-label">Hash B</label>
              <input class="hs-input" id="compare-b" placeholder="Second hash...">
            </div>
          </div>
          <button class="hs-btn hs-btn-primary" id="compare-btn">Compare</button>
          <div id="compare-output"></div>
        </div>
      </div>

      <!-- FILE HASH PANEL -->
      <div class="hs-panel" id="panel-file">
        <div class="hs-card">
          <h3>File Hash Calculator</h3>
          <div class="hs-file-drop" id="file-drop">
            <div style="font-size:1.2rem;margin-bottom:8px;color:var(--acc);font-family:var(--mono)">[FILE]</div>
            <div>Drag &amp; drop a file here, or <strong>click to browse</strong></div>
            <div style="font-size:0.75rem;margin-top:4px;">All processing happens in your browser — nothing is uploaded</div>
            <input type="file" id="file-input">
          </div>
          <div style="display:flex;gap:8px;margin-top:12px;align-items:center;">
            <select class="hs-select" id="file-algo">
              <option value="md5">MD5</option>
              <option value="sha1">SHA-1</option>
              <option value="sha256" selected>SHA-256</option>
              <option value="sha512">SHA-512</option>
            </select>
          </div>
          <div class="hs-progress" id="file-progress"><div class="hs-progress-bar" id="file-progress-bar"></div></div>
          <div id="file-output"></div>
        </div>
      </div>

      <!-- HMAC PANEL -->
      <div class="hs-panel" id="panel-hmac">
        <div class="hs-card">
          <h3>HMAC Generator</h3>
          <div class="hs-input-group">
            <label class="hs-label">Secret Key</label>
            <input class="hs-input" id="hmac-key" placeholder="Enter secret key..." type="password">
          </div>
          <div class="hs-input-group">
            <label class="hs-label">Message</label>
            <textarea class="hs-textarea" id="hmac-msg" placeholder="Enter message to authenticate..."></textarea>
          </div>
          <div style="display:flex;gap:8px;align-items:center;">
            <select class="hs-select" id="hmac-algo">
              <option value="md5">HMAC-MD5</option>
              <option value="sha1">HMAC-SHA1</option>
              <option value="sha256" selected>HMAC-SHA256</option>
            </select>
            <button class="hs-btn hs-btn-primary" id="hmac-btn">Generate HMAC</button>
          </div>
          <div id="hmac-output"></div>
        </div>
      </div>

      <!-- PASSWORD ENTROPY PANEL -->
      <div class="hs-panel" id="panel-entropy">
        <div class="hs-card">
          <h3>Password Entropy Calculator</h3>
          <div class="hs-input-group">
            <label class="hs-label">Password</label>
            <div style="position:relative;">
              <input class="hs-input" id="entropy-input" placeholder="Type a password to analyze..." type="text" autocomplete="off">
            </div>
          </div>
          <div id="entropy-output"></div>
        </div>
      </div>

      <!-- RAINBOW TABLE PANEL -->
      <div class="hs-panel" id="panel-rainbow">
        <div class="hs-card">
          <h3>Rainbow Table Size Estimator</h3>
          <p style="font-size:0.8rem;color:var(--txt-2,#8899aa);margin:0 0 16px;">Estimate the storage needed for a rainbow table attack on a given keyspace.</p>
          <div class="hs-grid">
            <div>
              <div class="hs-slider-group">
                <label class="hs-label" style="min-width:100px;">Charset size</label>
                <input type="range" class="hs-slider" id="rt-charset" min="10" max="256" value="95">
                <span class="hs-slider-val" id="rt-charset-val">95</span>
              </div>
              <div class="hs-slider-group">
                <label class="hs-label" style="min-width:100px;">Max length</label>
                <input type="range" class="hs-slider" id="rt-maxlen" min="1" max="16" value="8">
                <span class="hs-slider-val" id="rt-maxlen-val">8</span>
              </div>
              <div class="hs-slider-group">
                <label class="hs-label" style="min-width:100px;">Hash bits</label>
                <select class="hs-select" id="rt-hashbits">
                  <option value="128" selected>128 (MD5)</option>
                  <option value="160">160 (SHA-1)</option>
                  <option value="256">256 (SHA-256)</option>
                  <option value="512">512 (SHA-512)</option>
                </select>
              </div>
              <div class="hs-slider-group">
                <label class="hs-label" style="min-width:100px;">Chain length</label>
                <input type="range" class="hs-slider" id="rt-chain" min="100" max="100000" value="10000" step="100">
                <span class="hs-slider-val" id="rt-chain-val">10000</span>
              </div>
              <div class="hs-slider-group">
                <label class="hs-label" style="min-width:100px;">Num tables</label>
                <input type="range" class="hs-slider" id="rt-tables" min="1" max="10" value="1">
                <span class="hs-slider-val" id="rt-tables-val">1</span>
              </div>
            </div>
            <div id="rt-output"></div>
          </div>
        </div>
      </div>

      <!-- KDF COST PANEL -->
      <div class="hs-panel" id="panel-cost">
        <div class="hs-card">
          <h3>KDF Cost Calculator</h3>
          <div class="hs-grid">
            <div>
              <h3 style="font-size:0.9rem;">bcrypt</h3>
              <div class="hs-slider-group">
                <label class="hs-label" style="min-width:100px;">Cost factor</label>
                <input type="range" class="hs-slider" id="bcrypt-cost" min="4" max="20" value="12">
                <span class="hs-slider-val" id="bcrypt-cost-val">12</span>
              </div>
              <div id="bcrypt-output"></div>
            </div>
            <div>
              <h3 style="font-size:0.9rem;">scrypt</h3>
              <div class="hs-slider-group">
                <label class="hs-label" style="min-width:100px;">N (CPU/mem)</label>
                <select class="hs-select" id="scrypt-n">
                  <option value="1024">1024</option>
                  <option value="2048">2048</option>
                  <option value="4096">4096</option>
                  <option value="8192">8192</option>
                  <option value="16384" selected>16384</option>
                  <option value="32768">32768</option>
                  <option value="65536">65536</option>
                  <option value="131072">131072</option>
                  <option value="262144">262144</option>
                  <option value="1048576">1048576</option>
                </select>
              </div>
              <div class="hs-slider-group">
                <label class="hs-label" style="min-width:100px;">r (block)</label>
                <input type="range" class="hs-slider" id="scrypt-r" min="1" max="32" value="8">
                <span class="hs-slider-val" id="scrypt-r-val">8</span>
              </div>
              <div class="hs-slider-group">
                <label class="hs-label" style="min-width:100px;">p (parallel)</label>
                <input type="range" class="hs-slider" id="scrypt-p" min="1" max="16" value="1">
                <span class="hs-slider-val" id="scrypt-p-val">1</span>
              </div>
              <div id="scrypt-output"></div>
            </div>
          </div>
        </div>
      </div>

      <!-- REFERENCE PANEL -->
      <div class="hs-panel" id="panel-reference">
        <div class="hs-card">
          <h3>Hash Algorithm Reference</h3>
          <table class="hs-results-table">
            <thead>
              <tr>
                <th>Algorithm</th>
                <th>Bits</th>
                <th>Hex Length</th>
                <th>Category</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody id="ref-table-body"></tbody>
          </table>
        </div>
        <div class="hs-card" style="margin-top:16px;">
          <h3>Hash Comparison Chart</h3>
          <table class="hs-results-table">
            <thead>
              <tr><th>Property</th><th>MD5</th><th>SHA-1</th><th>SHA-256</th><th>SHA-512</th><th>SHA-3</th><th>BLAKE3</th></tr>
            </thead>
            <tbody>
              <tr><td>Output size</td><td>128 bit</td><td>160 bit</td><td>256 bit</td><td>512 bit</td><td>Variable</td><td>256 bit</td></tr>
              <tr><td>Block size</td><td>512 bit</td><td>512 bit</td><td>512 bit</td><td>1024 bit</td><td>1600 bit</td><td>64 B</td></tr>
              <tr><td>Rounds</td><td>64</td><td>80</td><td>64</td><td>80</td><td>24</td><td>7</td></tr>
              <tr><td>Construction</td><td>M-D</td><td>M-D</td><td>M-D</td><td>M-D</td><td>Sponge</td><td>Merkle tree</td></tr>
              <tr><td>Speed (cpb)</td><td>~5</td><td>~7</td><td>~12</td><td>~8</td><td>~8</td><td>~0.5</td></tr>
              <tr><td>Collision resist.</td><td><span class="hs-badge hs-badge-red">Broken</span></td><td><span class="hs-badge hs-badge-red">Broken</span></td><td><span class="hs-badge hs-badge-green">Secure</span></td><td><span class="hs-badge hs-badge-green">Secure</span></td><td><span class="hs-badge hs-badge-green">Secure</span></td><td><span class="hs-badge hs-badge-green">Secure</span></td></tr>
              <tr><td>Preimage resist.</td><td><span class="hs-badge hs-badge-yellow">Weakened</span></td><td><span class="hs-badge hs-badge-yellow">Weakened</span></td><td><span class="hs-badge hs-badge-green">Secure</span></td><td><span class="hs-badge hs-badge-green">Secure</span></td><td><span class="hs-badge hs-badge-green">Secure</span></td><td><span class="hs-badge hs-badge-green">Secure</span></td></tr>
              <tr><td>Length extension</td><td><span class="hs-badge hs-badge-red">Vulnerable</span></td><td><span class="hs-badge hs-badge-red">Vulnerable</span></td><td><span class="hs-badge hs-badge-red">Vulnerable</span></td><td><span class="hs-badge hs-badge-red">Vulnerable</span></td><td><span class="hs-badge hs-badge-green">Immune</span></td><td><span class="hs-badge hs-badge-green">Immune</span></td></tr>
              <tr><td>Parallelizable</td><td>No</td><td>No</td><td>No</td><td>No</td><td>No</td><td><span class="hs-badge hs-badge-green">Yes</span></td></tr>
              <tr><td>Year</td><td>1992</td><td>1995</td><td>2001</td><td>2001</td><td>2015</td><td>2020</td></tr>
              <tr><td>Standard</td><td>RFC 1321</td><td>FIPS 180-4</td><td>FIPS 180-4</td><td>FIPS 180-4</td><td>FIPS 202</td><td>—</td></tr>
              <tr><td>Use for passwords?</td><td><span class="hs-badge hs-badge-red">Never</span></td><td><span class="hs-badge hs-badge-red">Never</span></td><td><span class="hs-badge hs-badge-red">Never</span></td><td><span class="hs-badge hs-badge-red">Never</span></td><td><span class="hs-badge hs-badge-red">Never</span></td><td><span class="hs-badge hs-badge-red">Never</span></td></tr>
              <tr><td>Recommendation</td><td><span class="hs-badge hs-badge-red">Do not use</span></td><td><span class="hs-badge hs-badge-red">Phase out</span></td><td><span class="hs-badge hs-badge-green">Default choice</span></td><td><span class="hs-badge hs-badge-green">Use for max sec.</span></td><td><span class="hs-badge hs-badge-blue">Good</span></td><td><span class="hs-badge hs-badge-blue">Fastest</span></td></tr>
            </tbody>
          </table>
        </div>
        <div class="hs-card" style="margin-top:16px;">
          <h3>Password Hashing Comparison</h3>
          <table class="hs-results-table">
            <thead>
              <tr><th>Property</th><th>bcrypt</th><th>scrypt</th><th>Argon2id</th><th>PBKDF2</th></tr>
            </thead>
            <tbody>
              <tr><td>Year</td><td>1999</td><td>2009</td><td>2015</td><td>2000</td></tr>
              <tr><td>Memory-hard</td><td>No (4 KB)</td><td><span class="hs-badge hs-badge-green">Yes</span></td><td><span class="hs-badge hs-badge-green">Yes</span></td><td>No</td></tr>
              <tr><td>GPU resistant</td><td><span class="hs-badge hs-badge-yellow">Moderate</span></td><td><span class="hs-badge hs-badge-green">Strong</span></td><td><span class="hs-badge hs-badge-green">Strong</span></td><td><span class="hs-badge hs-badge-red">Weak</span></td></tr>
              <tr><td>ASIC resistant</td><td><span class="hs-badge hs-badge-yellow">Moderate</span></td><td><span class="hs-badge hs-badge-green">Strong</span></td><td><span class="hs-badge hs-badge-green">Strong</span></td><td><span class="hs-badge hs-badge-red">Weak</span></td></tr>
              <tr><td>Side-channel</td><td><span class="hs-badge hs-badge-yellow">Possible</span></td><td><span class="hs-badge hs-badge-yellow">Possible</span></td><td><span class="hs-badge hs-badge-green">Argon2id ok</span></td><td><span class="hs-badge hs-badge-yellow">Possible</span></td></tr>
              <tr><td>Max password</td><td>72 bytes</td><td>Unlimited</td><td>Unlimited</td><td>Unlimited</td></tr>
              <tr><td>Standard</td><td>—</td><td>RFC 7914</td><td>RFC 9106</td><td>RFC 2898</td></tr>
              <tr><td>Recommended cost</td><td>12+</td><td>N=2^15, r=8</td><td>m=64MB, t=3</td><td>600k+ iter</td></tr>
              <tr><td>OWASP verdict</td><td><span class="hs-badge hs-badge-green">OK</span></td><td><span class="hs-badge hs-badge-green">OK</span></td><td><span class="hs-badge hs-badge-green">Preferred</span></td><td><span class="hs-badge hs-badge-green">OK</span></td></tr>
            </tbody>
          </table>
        </div>
        <div class="hs-card" style="margin-top:16px;">
          <h3>Known Hash Attacks Timeline</h3>
          <table class="hs-results-table">
            <thead><tr><th>Year</th><th>Algorithm</th><th>Attack</th><th>Impact</th></tr></thead>
            <tbody>
              <tr><td>1996</td><td>MD4</td><td>Dobbertin collision attack</td><td>Full collision in seconds</td></tr>
              <tr><td>2004</td><td>MD5</td><td>Wang et al. collision</td><td>Collision found in hours on PC</td></tr>
              <tr><td>2005</td><td>SHA-1</td><td>Wang et al. theoretical</td><td>2^63 operations (reduced from 2^80)</td></tr>
              <tr><td>2008</td><td>MD5</td><td>Rogue CA certificate</td><td>Forged SSL certificate using collision</td></tr>
              <tr><td>2009</td><td>MD5</td><td>Flame malware</td><td>Forged Microsoft code-signing certificate</td></tr>
              <tr><td>2012</td><td>SHA-1</td><td>Reduced rounds attack</td><td>73-round collision (out of 80)</td></tr>
              <tr><td>2017</td><td>SHA-1</td><td>SHAttered (Google/CWI)</td><td>First practical collision (6500 CPU-years)</td></tr>
              <tr><td>2019</td><td>SHA-1</td><td>Chosen-prefix collision</td><td>Practical chosen-prefix collision</td></tr>
              <tr><td>2020</td><td>SHA-1</td><td>Shambles attack</td><td>PGP/GnuPG key impersonation demonstrated</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  // --- Tab switching ---
  const tabs = container.querySelectorAll(".hs-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      container.querySelectorAll(".hs-panel").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      const panel = container.querySelector("#panel-" + tab.dataset.panel);
      if (panel) panel.classList.add("active");
    });
  });

  // --- Utility: copy to clipboard ---
  function attachCopy(parentEl) {
    parentEl.querySelectorAll(".hs-copy-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const target = btn.closest(".hs-output");
        if (target) {
          const text = target.textContent.replace("Copy", "").replace("Copied!", "").trim();
          navigator.clipboard.writeText(text).then(() => {
            btn.textContent = "Copied!";
            setTimeout(() => { btn.textContent = "Copy"; }, 1200);
          });
        }
      });
    });
  }

  function hexToBase64(hex) {
    let bytes = "";
    for (let i = 0; i < hex.length; i += 2) {
      bytes += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return btoa(bytes);
  }

  // --- Compute panel ---
  const computeBtn = container.querySelector("#compute-btn");
  const computeClear = container.querySelector("#compute-clear");
  computeBtn.addEventListener("click", () => {
    const input = container.querySelector("#compute-input").value;
    const algo = container.querySelector("#compute-algo").value;
    const fmt = container.querySelector("#compute-format").value;
    const out = container.querySelector("#compute-output");
    if (!input) { out.innerHTML = '<div class="hs-output" style="color:#f44336;">Enter text to hash</div>'; return; }

    function formatHash(hex) {
      if (fmt === "HEX") return hex.toUpperCase();
      if (fmt === "base64") return hexToBase64(hex);
      return hex;
    }

    if (algo === "all") {
      const md5 = formatHash(MD5.hash(input));
      const sha1 = formatHash(SHA1.hash(input));
      const sha256 = formatHash(SHA256.hash(input));
      const sha512 = formatHash(SHA512.hash(input));
      out.innerHTML = `
        <div class="hs-card" style="margin-top:12px;">
          <div class="hs-info-row"><span class="hs-info-label">MD5</span></div>
          <div class="hs-output">${md5}<button class="hs-copy-btn">Copy</button></div>
          <div class="hs-info-row" style="margin-top:12px;"><span class="hs-info-label">SHA-1</span></div>
          <div class="hs-output">${sha1}<button class="hs-copy-btn">Copy</button></div>
          <div class="hs-info-row" style="margin-top:12px;"><span class="hs-info-label">SHA-256</span></div>
          <div class="hs-output">${sha256}<button class="hs-copy-btn">Copy</button></div>
          <div class="hs-info-row" style="margin-top:12px;"><span class="hs-info-label">SHA-512</span></div>
          <div class="hs-output">${sha512}<button class="hs-copy-btn">Copy</button></div>
        </div>`;
    } else {
      let hash;
      switch (algo) {
        case "md5":    hash = formatHash(MD5.hash(input)); break;
        case "sha1":   hash = formatHash(SHA1.hash(input)); break;
        case "sha256": hash = formatHash(SHA256.hash(input)); break;
        case "sha512": hash = formatHash(SHA512.hash(input)); break;
      }
      out.innerHTML = `<div class="hs-output">${hash}<button class="hs-copy-btn">Copy</button></div>`;
    }
    attachCopy(out);
  });
  computeClear.addEventListener("click", () => {
    container.querySelector("#compute-input").value = "";
    container.querySelector("#compute-output").innerHTML = "";
  });

  // --- Identify panel ---
  container.querySelector("#identify-btn").addEventListener("click", () => {
    const input = container.querySelector("#identify-input").value;
    const out = container.querySelector("#identify-output");
    if (!input.trim()) { out.innerHTML = '<div class="hs-output" style="color:#f44336;">Paste a hash to identify</div>'; return; }
    const matches = identifyHash(input);
    if (matches.length === 0) {
      out.innerHTML = '<div class="hs-output" style="color:#ffb74d;">No known hash format matches this input. Length: ' + input.trim().length + ' characters.</div>';
      return;
    }
    let html = `<div style="margin-top:12px;font-size:0.8rem;color:var(--txt-2,#8899aa);">Input length: ${input.trim().length} characters &middot; ${matches.length} possible match${matches.length > 1 ? "es" : ""}</div>`;
    html += '<table class="hs-results-table"><thead><tr><th>Algorithm</th><th>Category</th><th>Bits</th><th>Confidence</th><th>Description</th></tr></thead><tbody>';
    for (const m of matches) {
      const badge = m.confidence === "high" ? "hs-badge-green" : "hs-badge-yellow";
      html += `<tr><td><strong>${m.name}</strong></td><td>${m.category}</td><td>${m.bits || "—"}</td><td><span class="hs-badge ${badge}">${m.confidence}</span></td><td style="font-size:0.75rem;">${m.desc}</td></tr>`;
    }
    html += "</tbody></table>";
    out.innerHTML = html;
  });

  // --- Compare panel ---
  container.querySelector("#compare-btn").addEventListener("click", () => {
    const a = container.querySelector("#compare-a").value.trim().toLowerCase();
    const b = container.querySelector("#compare-b").value.trim().toLowerCase();
    const out = container.querySelector("#compare-output");
    if (!a || !b) { out.innerHTML = '<div class="hs-output" style="color:#f44336;">Enter both hashes</div>'; return; }
    const match = a === b;
    let html = `<div class="hs-output" style="border-color:${match ? "#00c853" : "#f44336"};">`;
    html += match ? '<span class="hs-match">MATCH — Hashes are identical</span>' : '<span class="hs-nomatch">NO MATCH — Hashes differ</span>';
    if (!match && a.length === b.length) {
      let diffCount = 0;
      for (let i = 0; i < a.length; i++) { if (a[i] !== b[i]) diffCount++; }
      html += `<div style="margin-top:8px;font-size:0.8rem;color:var(--txt-2,#8899aa);">Same length (${a.length}). ${diffCount} character${diffCount > 1 ? "s" : ""} differ.</div>`;
    } else if (!match) {
      html += `<div style="margin-top:8px;font-size:0.8rem;color:var(--txt-2,#8899aa);">Hash A: ${a.length} chars, Hash B: ${b.length} chars</div>`;
    }
    html += "</div>";
    out.innerHTML = html;
  });

  // --- File hash panel ---
  const fileDrop = container.querySelector("#file-drop");
  const fileInput = container.querySelector("#file-input");
  fileDrop.addEventListener("click", () => fileInput.click());
  fileDrop.addEventListener("dragover", (e) => { e.preventDefault(); fileDrop.classList.add("dragover"); });
  fileDrop.addEventListener("dragleave", () => fileDrop.classList.remove("dragover"));
  fileDrop.addEventListener("drop", (e) => {
    e.preventDefault();
    fileDrop.classList.remove("dragover");
    if (e.dataTransfer.files.length) processFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener("change", () => { if (fileInput.files.length) processFile(fileInput.files[0]); });

  async function processFile(file) {
    const algo = container.querySelector("#file-algo").value;
    const progress = container.querySelector("#file-progress");
    const progressBar = container.querySelector("#file-progress-bar");
    const out = container.querySelector("#file-output");
    progress.classList.add("active");
    progressBar.style.width = "10%";
    out.innerHTML = '<div class="hs-output">Computing hash...</div>';
    try {
      const result = await hashFile(file, algo, (pct) => { progressBar.style.width = pct + "%"; });
      out.innerHTML = `
        <div class="hs-card" style="margin-top:12px;">
          <div class="hs-info-row"><span class="hs-info-label">File</span><span class="hs-info-value">${result.filename}</span></div>
          <div class="hs-info-row"><span class="hs-info-label">Size</span><span class="hs-info-value">${result.sizeFormatted} (${result.size.toLocaleString()} bytes)</span></div>
          <div class="hs-info-row"><span class="hs-info-label">Type</span><span class="hs-info-value">${result.type}</span></div>
          <div class="hs-info-row"><span class="hs-info-label">Algorithm</span><span class="hs-info-value">${result.algorithm.toUpperCase()}</span></div>
          <div class="hs-info-row"><span class="hs-info-label">Computed</span><span class="hs-info-value">${result.timestamp}</span></div>
          <div class="hs-output" style="margin-top:8px;">${result.hash}<button class="hs-copy-btn">Copy</button></div>
        </div>`;
      attachCopy(out);
    } catch (err) {
      out.innerHTML = '<div class="hs-output" style="color:#f44336;">Error: ' + err.message + '</div>';
    }
    setTimeout(() => { progress.classList.remove("active"); }, 500);
  }

  // --- HMAC panel ---
  container.querySelector("#hmac-btn").addEventListener("click", () => {
    const key = container.querySelector("#hmac-key").value;
    const msg = container.querySelector("#hmac-msg").value;
    const algo = container.querySelector("#hmac-algo").value;
    const out = container.querySelector("#hmac-output");
    if (!key || !msg) { out.innerHTML = '<div class="hs-output" style="color:#f44336;">Enter both key and message</div>'; return; }
    const hmac = computeHMAC(algo, key, msg);
    out.innerHTML = `
      <div class="hs-card" style="margin-top:12px;">
        <div class="hs-info-row"><span class="hs-info-label">Algorithm</span><span class="hs-info-value">HMAC-${algo.toUpperCase()}</span></div>
        <div class="hs-output">${hmac}<button class="hs-copy-btn">Copy</button></div>
      </div>`;
    attachCopy(out);
  });

  // --- Entropy panel (live) ---
  const entropyInput = container.querySelector("#entropy-input");
  function updateEntropy() {
    const pw = entropyInput.value;
    const out = container.querySelector("#entropy-output");
    if (!pw) { out.innerHTML = ""; return; }
    const result = calcEntropy(pw);
    const strengthColors = {
      "none": "#666", "very weak": "#f44336", "weak": "#ff9800",
      "reasonable": "#ffb74d", "strong": "#4caf50", "very strong": "#00c853", "excellent": "#00d4ff"
    };
    const pct = Math.min(100, (result.entropy / 128) * 100);
    let html = `
      <div class="hs-card" style="margin-top:12px;">
        <div class="hs-info-row"><span class="hs-info-label">Entropy</span><span class="hs-info-value">${result.entropy} bits</span></div>
        <div class="hs-meter"><div class="hs-meter-fill" style="width:${pct}%;background:${strengthColors[result.strength]};"></div></div>
        <div class="hs-info-row"><span class="hs-info-label">Strength</span><span class="hs-info-value" style="color:${strengthColors[result.strength]};text-transform:uppercase;font-size:0.8rem;">${result.strength}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">Length</span><span class="hs-info-value">${result.length} characters</span></div>
        <div class="hs-info-row"><span class="hs-info-label">Charset pool</span><span class="hs-info-value">${result.charset} characters</span></div>
        <div class="hs-info-row"><span class="hs-info-label">Crack time (10B/s)</span><span class="hs-info-value">${result.crackTime}</span></div>`;
    if (result.patterns.length) {
      html += '<div style="margin-top:12px;"><span class="hs-label">Warnings</span>';
      for (const p of result.patterns) html += `<div style="font-size:0.8rem;color:#ffb74d;margin:4px 0;">${p}</div>`;
      html += "</div>";
    }
    html += "</div>";
    out.innerHTML = html;
  }
  entropyInput.addEventListener("input", updateEntropy);

  // --- Rainbow table panel (live) ---
  function updateRainbow() {
    const charset = parseInt(container.querySelector("#rt-charset").value, 10);
    const maxLen = parseInt(container.querySelector("#rt-maxlen").value, 10);
    const hashBits = parseInt(container.querySelector("#rt-hashbits").value, 10);
    const chain = parseInt(container.querySelector("#rt-chain").value, 10);
    const tables = parseInt(container.querySelector("#rt-tables").value, 10);
    container.querySelector("#rt-charset-val").textContent = charset;
    container.querySelector("#rt-maxlen-val").textContent = maxLen;
    container.querySelector("#rt-chain-val").textContent = chain;
    container.querySelector("#rt-tables-val").textContent = tables;
    const result = estimateRainbowTable(charset, maxLen, hashBits, chain, tables);
    const out = container.querySelector("#rt-output");
    out.innerHTML = `
      <div class="hs-card">
        <div class="hs-info-row"><span class="hs-info-label">Keyspace</span><span class="hs-info-value">${result.keyspaceFormatted}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">Chains</span><span class="hs-info-value">${result.numChains.toLocaleString()}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">Chain length</span><span class="hs-info-value">${result.chainLength.toLocaleString()}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">Single table</span><span class="hs-info-value">${result.singleTableFormatted}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">Total (${result.numTables} table${result.numTables > 1 ? "s" : ""})</span><span class="hs-info-value" style="color:#00d4ff;font-weight:700;">${result.totalFormatted}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">Success rate</span><span class="hs-info-value">${result.successRate}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">Compute time</span><span class="hs-info-value">${result.computeTime} (at 1B hashes/s)</span></div>
      </div>`;
  }
  ["rt-charset", "rt-maxlen", "rt-chain", "rt-tables"].forEach(id => {
    container.querySelector("#" + id).addEventListener("input", updateRainbow);
  });
  container.querySelector("#rt-hashbits").addEventListener("change", updateRainbow);
  updateRainbow();

  // --- KDF cost panel (live) ---
  function updateBcrypt() {
    const cost = parseInt(container.querySelector("#bcrypt-cost").value, 10);
    container.querySelector("#bcrypt-cost-val").textContent = cost;
    const result = bcryptCostEstimate(cost);
    const out = container.querySelector("#bcrypt-output");
    out.innerHTML = `
      <div style="margin-top:12px;">
        <div class="hs-info-row"><span class="hs-info-label">Iterations</span><span class="hs-info-value">${result.iterations.toLocaleString()}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">Time / hash</span><span class="hs-info-value">${result.timePerHash}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">H/s (CPU)</span><span class="hs-info-value">${result.hashesPerSecCPU.toLocaleString()}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">H/s (GPU)</span><span class="hs-info-value">${result.hashesPerSecGPU.toLocaleString()}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">Verdict</span><span class="hs-info-value" style="font-size:0.78rem;">${result.recommendation}</span></div>
      </div>`;
  }
  function updateScrypt() {
    const N = parseInt(container.querySelector("#scrypt-n").value, 10);
    const r = parseInt(container.querySelector("#scrypt-r").value, 10);
    const p = parseInt(container.querySelector("#scrypt-p").value, 10);
    container.querySelector("#scrypt-r-val").textContent = r;
    container.querySelector("#scrypt-p-val").textContent = p;
    const result = scryptCostEstimate(N, r, p);
    const out = container.querySelector("#scrypt-output");
    out.innerHTML = `
      <div style="margin-top:12px;">
        <div class="hs-info-row"><span class="hs-info-label">Memory</span><span class="hs-info-value">${result.memory}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">CPU cost</span><span class="hs-info-value">${result.cpuCost}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">Time / hash</span><span class="hs-info-value">${result.timePerHash}</span></div>
        <div class="hs-info-row"><span class="hs-info-label">Verdict</span><span class="hs-info-value" style="font-size:0.78rem;">${result.recommendation}</span></div>
        <div style="margin-top:8px;font-size:0.75rem;color:var(--txt-2,#8899aa);">${result.comparison.advantage}</div>
      </div>`;
  }
  container.querySelector("#bcrypt-cost").addEventListener("input", updateBcrypt);
  container.querySelector("#scrypt-n").addEventListener("change", updateScrypt);
  container.querySelector("#scrypt-r").addEventListener("input", updateScrypt);
  container.querySelector("#scrypt-p").addEventListener("input", updateScrypt);
  updateBcrypt();
  updateScrypt();

  // --- Reference panel: fill table ---
  const refBody = container.querySelector("#ref-table-body");
  const seen = new Set();
  for (const ht of HASH_TYPES) {
    if (seen.has(ht.name)) continue;
    seen.add(ht.name);
    const statusColors = {
      "Current": "hs-badge-green", "Modern": "hs-badge-blue", "KDF": "hs-badge-purple",
      "Deprecated": "hs-badge-red", "Broken": "hs-badge-red", "Legacy": "hs-badge-yellow",
      "Checksum": "hs-badge-yellow", "Windows": "hs-badge-yellow", "Unix": "hs-badge-blue",
      "Database": "hs-badge-yellow", "Framework": "hs-badge-blue", "National": "hs-badge-purple"
    };
    const badge = statusColors[ht.category] || "hs-badge-blue";
    const row = document.createElement("tr");
    row.innerHTML = `<td><strong>${ht.name}</strong></td><td>${ht.bits || "var"}</td><td>${ht.len || "—"}</td><td><span class="hs-badge ${badge}">${ht.category}</span></td><td style="font-size:0.75rem;">${ht.desc}</td>`;
    refBody.appendChild(row);
  }
}
