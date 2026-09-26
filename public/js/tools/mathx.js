// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Math & number mini-tools.

// ---- shared, dependency-free helpers (module-scoped, not imported) ----
const ERR = { error: "Enter valid number(s)." };

// clampInt: prefer host helper H.clampInt, fall back to local.
const _ci = (H, x, lo, hi, d) =>
  (H && typeof H.clampInt === "function")
    ? H.clampInt(x, lo, hi, d)
    : (() => {
        const n = parseInt(x, 10);
        if (!Number.isFinite(n)) return d;
        return Math.min(hi, Math.max(lo, n));
      })();

// parse a single real number ("" or bad -> NaN)
const _num = (x) => {
  if (x === undefined || x === null) return NaN;
  const s = String(x).trim();
  if (s === "") return NaN;
  const n = Number(s);
  return Number.isNaN(n) ? NaN : n;
};

// parse a strict integer string -> Number or NaN
const _int = (x) => {
  const s = String(x === undefined || x === null ? "" : x).trim();
  if (!/^[+-]?\d+$/.test(s)) return NaN;
  return Number(s);
};

// parse a strict integer string -> BigInt or null
const _big = (x) => {
  const s = String(x === undefined || x === null ? "" : x).trim();
  if (!/^[+-]?\d+$/.test(s)) return null;
  try { return BigInt(s); } catch (e) { return null; }
};

// parse a list of numbers (comma / space / newline separated). "" -> [], bad -> null
const _list = (s) => {
  if (s === undefined || s === null) return [];
  const t = String(s).trim();
  if (t === "") return [];
  const parts = t.split(/[\s,]+/).filter((p) => p.length);
  const out = [];
  for (const p of parts) {
    const n = Number(p);
    if (Number.isNaN(n) || !Number.isFinite(n)) return null;
    out.push(n);
  }
  return out;
};

// tidy number formatting (avoids long float tails)
const _fmt = (n) => {
  if (typeof n === "bigint") return n.toString();
  if (!Number.isFinite(n)) return String(n);
  if (Number.isInteger(n)) return String(n);
  return String(parseFloat(n.toPrecision(12)));
};

// arbitrary-base <-> BigInt
const _DIG = "0123456789abcdefghijklmnopqrstuvwxyz";
function _bigToBase(n, base) {
  if (n === 0n) return "0";
  const B = BigInt(base);
  let neg = n < 0n;
  if (neg) n = -n;
  let s = "";
  while (n > 0n) { s = _DIG[Number(n % B)] + s; n = n / B; }
  return (neg ? "-" : "") + s;
}
function _bigFromBase(str, base) {
  let t = String(str).trim().toLowerCase();
  let neg = false;
  if (t[0] === "-") { neg = true; t = t.slice(1); }
  else if (t[0] === "+") t = t.slice(1);
  if (t === "") return null;
  const B = BigInt(base);
  let v = 0n;
  for (const ch of t) {
    const k = _DIG.indexOf(ch);
    if (k < 0 || k >= base) return null;
    v = v * B + BigInt(k);
  }
  return neg ? -v : v;
}

// integer gcd / lcm (BigInt)
function _gcdBig(a, b) { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) { [a, b] = [b, a % b]; } return a; }

// number gcd (non-negative integers)
function _gcd(a, b) { a = Math.abs(a); b = Math.abs(b); while (b) { [a, b] = [b, a % b]; } return a; }

export const TOOLS = [
  // ---------- 1. base conversions ----------
  {
    id: "mx-base-convert", name: "Number Base Converter", cat: "math",
    desc: "Convert an integer between any two bases from 2 to 36.",
    tags: ["base", "radix", "convert", "hex", "binary"],
    inputs: [
      { k: "n", label: "Value", type: "text", placeholder: "e.g. ff or 1010" },
      { k: "from", label: "From base", type: "text", inputType: "number", value: "16" },
      { k: "to", label: "To base", type: "text", inputType: "number", value: "10" },
    ],
    run(v, H) {
      if (String(v.n ?? "").trim() === "") return "";
      const from = _ci(H, v.from, 2, 36, 10);
      const to = _ci(H, v.to, 2, 36, 10);
      const val = _bigFromBase(v.n, from);
      if (val === null) return { error: `Not a valid base-${from} number.` };
      return _bigToBase(val, to);
    },
  },
  {
    id: "mx-bin-convert", name: "Decimal ↔ Binary", cat: "math",
    desc: "Convert between decimal and binary integers.",
    tags: ["binary", "decimal", "base2"],
    inputs: [
      { k: "n", label: "Value", type: "text", placeholder: "e.g. 42" },
      { k: "dir", label: "Direction", type: "select", opts: [["d2b", "Decimal → Binary"], ["b2d", "Binary → Decimal"]], value: "d2b" },
    ],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      if (v.dir === "b2d") { const x = _bigFromBase(v.n, 2); return x === null ? { error: "Not a valid binary number." } : x.toString(); }
      const x = _big(v.n); return x === null ? ERR : _bigToBase(x, 2);
    },
  },
  {
    id: "mx-hex-convert", name: "Decimal ↔ Hexadecimal", cat: "math",
    desc: "Convert between decimal and hexadecimal integers.",
    tags: ["hex", "decimal", "base16"],
    inputs: [
      { k: "n", label: "Value", type: "text", placeholder: "e.g. 255 or ff" },
      { k: "dir", label: "Direction", type: "select", opts: [["d2h", "Decimal → Hex"], ["h2d", "Hex → Decimal"]], value: "d2h" },
    ],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      if (v.dir === "h2d") { const x = _bigFromBase(String(v.n).replace(/^0x/i, ""), 16); return x === null ? { error: "Not a valid hex number." } : x.toString(); }
      const x = _big(v.n); return x === null ? ERR : _bigToBase(x, 16);
    },
  },
  {
    id: "mx-oct-convert", name: "Decimal ↔ Octal", cat: "math",
    desc: "Convert between decimal and octal integers.",
    tags: ["octal", "decimal", "base8"],
    inputs: [
      { k: "n", label: "Value", type: "text", placeholder: "e.g. 64 or 100" },
      { k: "dir", label: "Direction", type: "select", opts: [["d2o", "Decimal → Octal"], ["o2d", "Octal → Decimal"]], value: "d2o" },
    ],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      if (v.dir === "o2d") { const x = _bigFromBase(v.n, 8); return x === null ? { error: "Not a valid octal number." } : x.toString(); }
      const x = _big(v.n); return x === null ? ERR : _bigToBase(x, 8);
    },
  },

  // ---------- bitwise ----------
  {
    id: "mx-bitwise-and", name: "Bitwise AND", cat: "math",
    desc: "Compute a & b on 32-bit integers.",
    tags: ["bitwise", "and", "logic"],
    inputs: [{ k: "a", label: "a", type: "text", inputType: "number" }, { k: "b", label: "b", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.a ?? "").trim() === "" || String(v.b ?? "").trim() === "") return "";
      const a = _int(v.a), b = _int(v.b);
      if (Number.isNaN(a) || Number.isNaN(b)) return ERR;
      return String((a & b) >>> 0);
    },
  },
  {
    id: "mx-bitwise-or", name: "Bitwise OR", cat: "math",
    desc: "Compute a | b on 32-bit integers.",
    tags: ["bitwise", "or", "logic"],
    inputs: [{ k: "a", label: "a", type: "text", inputType: "number" }, { k: "b", label: "b", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.a ?? "").trim() === "" || String(v.b ?? "").trim() === "") return "";
      const a = _int(v.a), b = _int(v.b);
      if (Number.isNaN(a) || Number.isNaN(b)) return ERR;
      return String((a | b) >>> 0);
    },
  },
  {
    id: "mx-bitwise-xor", name: "Bitwise XOR", cat: "math",
    desc: "Compute a ^ b on 32-bit integers.",
    tags: ["bitwise", "xor", "logic"],
    inputs: [{ k: "a", label: "a", type: "text", inputType: "number" }, { k: "b", label: "b", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.a ?? "").trim() === "" || String(v.b ?? "").trim() === "") return "";
      const a = _int(v.a), b = _int(v.b);
      if (Number.isNaN(a) || Number.isNaN(b)) return ERR;
      return String((a ^ b) >>> 0);
    },
  },
  {
    id: "mx-bitwise-not", name: "Bitwise NOT", cat: "math",
    desc: "Compute ~a on a 32-bit integer.",
    tags: ["bitwise", "not", "complement"],
    inputs: [{ k: "a", label: "a", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.a ?? "").trim() === "") return "";
      const a = _int(v.a);
      if (Number.isNaN(a)) return ERR;
      return `signed: ${~a}\nunsigned: ${(~a) >>> 0}`;
    },
  },
  {
    id: "mx-left-shift", name: "Left Shift", cat: "math",
    desc: "Compute a << b on 32-bit integers.",
    tags: ["bitwise", "shift", "left"],
    inputs: [{ k: "a", label: "a", type: "text", inputType: "number" }, { k: "b", label: "shift by", type: "text", inputType: "number", value: "1" }],
    run(v) {
      if (String(v.a ?? "").trim() === "") return "";
      const a = _int(v.a), b = _int(v.b);
      if (Number.isNaN(a) || Number.isNaN(b)) return ERR;
      return String(a << b);
    },
  },
  {
    id: "mx-right-shift", name: "Right Shift (signed)", cat: "math",
    desc: "Compute a >> b (sign-propagating) on 32-bit integers.",
    tags: ["bitwise", "shift", "right"],
    inputs: [{ k: "a", label: "a", type: "text", inputType: "number" }, { k: "b", label: "shift by", type: "text", inputType: "number", value: "1" }],
    run(v) {
      if (String(v.a ?? "").trim() === "") return "";
      const a = _int(v.a), b = _int(v.b);
      if (Number.isNaN(a) || Number.isNaN(b)) return ERR;
      return String(a >> b);
    },
  },
  {
    id: "mx-unsigned-right-shift", name: "Unsigned Right Shift", cat: "math",
    desc: "Compute a >>> b (zero-fill) on 32-bit integers.",
    tags: ["bitwise", "shift", "unsigned"],
    inputs: [{ k: "a", label: "a", type: "text", inputType: "number" }, { k: "b", label: "shift by", type: "text", inputType: "number", value: "1" }],
    run(v) {
      if (String(v.a ?? "").trim() === "") return "";
      const a = _int(v.a), b = _int(v.b);
      if (Number.isNaN(a) || Number.isNaN(b)) return ERR;
      return String(a >>> b);
    },
  },
  {
    id: "mx-twos-complement", name: "Two's Complement", cat: "math",
    desc: "Show the n-bit two's-complement representation of an integer.",
    tags: ["twos", "complement", "binary", "signed"],
    inputs: [
      { k: "n", label: "Integer", type: "text", inputType: "number" },
      { k: "bits", label: "Bit width", type: "text", inputType: "number", value: "8" },
    ],
    run(v, H) {
      if (String(v.n ?? "").trim() === "") return "";
      const n = _big(v.n);
      if (n === null) return ERR;
      const bits = _ci(H, v.bits, 1, 64, 8);
      const mod = 1n << BigInt(bits);
      if (n >= mod / 2n || n < -(mod / 2n)) return { error: `Value does not fit in ${bits} signed bits.` };
      const val = ((n % mod) + mod) % mod;
      return `${val.toString(2).padStart(bits, "0")}  (unsigned ${val.toString()})`;
    },
  },
  {
    id: "mx-popcount", name: "Population Count", cat: "math",
    desc: "Count the set (1) bits in a non-negative integer.",
    tags: ["popcount", "bits", "hamming"],
    inputs: [{ k: "n", label: "Non-negative integer", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      let n = _big(v.n);
      if (n === null) return ERR;
      if (n < 0n) return { error: "Enter a non-negative integer." };
      let c = 0;
      while (n > 0n) { c += Number(n & 1n); n >>= 1n; }
      return String(c);
    },
  },
  {
    id: "mx-float-bits", name: "IEEE-754 Float Bits", cat: "math",
    desc: "Show the binary bit pattern of a 32- or 64-bit floating-point number.",
    tags: ["float", "ieee754", "binary", "bits"],
    inputs: [
      { k: "x", label: "Number", type: "text", placeholder: "e.g. 3.14" },
      { k: "prec", label: "Precision", type: "select", opts: [["32", "32-bit (single)"], ["64", "64-bit (double)"]], value: "32" },
    ],
    run(v) {
      const raw = String(v.x ?? "").trim();
      if (raw === "") return "";
      const x = Number(raw);
      if (Number.isNaN(x) && raw.toLowerCase() !== "nan") return ERR;
      const bits = v.prec === "64" ? 64 : 32;
      const buf = new ArrayBuffer(bits / 8);
      const dv = new DataView(buf);
      if (bits === 32) dv.setFloat32(0, x, false); else dv.setFloat64(0, x, false);
      let s = "";
      for (let i = 0; i < bits / 8; i++) s += dv.getUint8(i).toString(2).padStart(8, "0");
      const eLen = bits === 32 ? 8 : 11;
      return `${s}\nsign=${s[0]} exponent=${s.slice(1, 1 + eLen)} mantissa=${s.slice(1 + eLen)}`;
    },
  },

  // ---------- number theory ----------
  {
    id: "mx-gcd", name: "Greatest Common Divisor", cat: "math",
    desc: "GCD of two or more integers.",
    tags: ["gcd", "divisor", "hcf"],
    inputs: [{ k: "nums", label: "Integers", type: "textarea", rows: 2, placeholder: "12, 18, 24" }],
    run(v) {
      if (String(v.nums ?? "").trim() === "") return "";
      const parts = String(v.nums).trim().split(/[\s,]+/).filter((p) => p.length);
      const arr = [];
      for (const p of parts) { const b = _big(p); if (b === null) return ERR; arr.push(b); }
      if (!arr.length) return "";
      let g = arr[0] < 0n ? -arr[0] : arr[0];
      for (let i = 1; i < arr.length; i++) g = _gcdBig(g, arr[i]);
      return g.toString();
    },
  },
  {
    id: "mx-lcm", name: "Least Common Multiple", cat: "math",
    desc: "LCM of two or more integers.",
    tags: ["lcm", "multiple"],
    inputs: [{ k: "nums", label: "Integers", type: "textarea", rows: 2, placeholder: "4, 6, 8" }],
    run(v) {
      if (String(v.nums ?? "").trim() === "") return "";
      const parts = String(v.nums).trim().split(/[\s,]+/).filter((p) => p.length);
      const arr = [];
      for (const p of parts) { const b = _big(p); if (b === null) return ERR; arr.push(b < 0n ? -b : b); }
      if (!arr.length) return "";
      if (arr.includes(0n)) return "0";
      let l = arr[0];
      for (let i = 1; i < arr.length; i++) l = (l / _gcdBig(l, arr[i])) * arr[i];
      return l.toString();
    },
  },
  {
    id: "mx-is-prime", name: "Is Prime?", cat: "math",
    desc: "Test whether an integer is prime.",
    tags: ["prime", "primality"],
    inputs: [{ k: "n", label: "Integer", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      const b = _big(v.n);
      if (b === null) return ERR;
      if (b < 2n) return `${b} is not prime.`;
      if (b < 4n) return `${b} is prime.`;
      if (b % 2n === 0n) return `${b} is not prime (divisible by 2).`;
      for (let i = 3n; i * i <= b; i += 2n) {
        if (b % i === 0n) return `${b} is not prime (divisible by ${i}).`;
      }
      return `${b} is prime.`;
    },
  },
  {
    id: "mx-prime-factorization", name: "Prime Factorization", cat: "math",
    desc: "Factor an integer into primes.",
    tags: ["prime", "factor", "factorization"],
    inputs: [{ k: "n", label: "Integer > 1", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      let n = _big(v.n);
      if (n === null) return ERR;
      if (n < 2n) return { error: "Enter an integer greater than 1." };
      const factors = [];
      for (let d = 2n; d * d <= n; d += (d === 2n ? 1n : 2n)) {
        while (n % d === 0n) { factors.push(d); n /= d; }
      }
      if (n > 1n) factors.push(n);
      const counts = new Map();
      for (const f of factors) counts.set(f.toString(), (counts.get(f.toString()) || 0) + 1);
      const pretty = [...counts.entries()].map(([p, e]) => (e > 1 ? `${p}^${e}` : p)).join(" × ");
      return `${factors.join(" × ")}\n= ${pretty}`;
    },
  },
  {
    id: "mx-next-prime", name: "Next Prime", cat: "math",
    desc: "Smallest prime strictly greater than n.",
    tags: ["prime", "next"],
    inputs: [{ k: "n", label: "Integer", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      let n = _big(v.n);
      if (n === null) return ERR;
      const isP = (x) => { if (x < 2n) return false; if (x % 2n === 0n) return x === 2n; for (let i = 3n; i * i <= x; i += 2n) if (x % i === 0n) return false; return true; };
      let c = n + 1n;
      if (c < 2n) c = 2n;
      while (!isP(c)) c += 1n;
      return c.toString();
    },
  },
  {
    id: "mx-primes-up-to", name: "Primes up to N (Sieve)", cat: "math",
    desc: "List all primes up to N using the Sieve of Eratosthenes.",
    tags: ["prime", "sieve", "eratosthenes", "list"],
    inputs: [{ k: "n", label: "Upper limit N", type: "text", inputType: "number", value: "100" }],
    run(v, H) {
      if (String(v.n ?? "").trim() === "") return "";
      if (Number.isNaN(_int(v.n))) return ERR;
      const n = _ci(H, v.n, 0, 5000000, 100);
      if (n < 2) return "(none)";
      const sieve = new Uint8Array(n + 1);
      const out = [];
      for (let i = 2; i <= n; i++) {
        if (!sieve[i]) { out.push(i); for (let j = i * i; j <= n; j += i) sieve[j] = 1; }
      }
      return `${out.length} prime(s):\n${out.join(", ")}`;
    },
  },
  {
    id: "mx-nth-prime", name: "Nth Prime", cat: "math",
    desc: "The nth prime number (1st = 2).",
    tags: ["prime", "nth", "index"],
    inputs: [{ k: "n", label: "n (1-based)", type: "text", inputType: "number", value: "10" }],
    run(v, H) {
      if (String(v.n ?? "").trim() === "") return "";
      if (Number.isNaN(_int(v.n))) return ERR;
      const n = _ci(H, v.n, 1, 200000, 1);
      let count = 0, cand = 1;
      const isP = (x) => { if (x < 2) return false; if (x % 2 === 0) return x === 2; for (let i = 3; i * i <= x; i += 2) if (x % i === 0) return false; return true; };
      while (count < n) { cand++; if (isP(cand)) count++; }
      return String(cand);
    },
  },
  {
    id: "mx-is-perfect", name: "Is Perfect Number?", cat: "math",
    desc: "Test whether a number equals the sum of its proper divisors.",
    tags: ["perfect", "divisors"],
    inputs: [{ k: "n", label: "Positive integer", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      const n = _int(v.n);
      if (Number.isNaN(n)) return ERR;
      if (n < 1) return { error: "Enter a positive integer." };
      let sum = 1;
      if (n === 1) sum = 0;
      for (let i = 2; i * i <= n; i++) { if (n % i === 0) { sum += i; if (i !== n / i) sum += n / i; } }
      return sum === n && n !== 1 ? `${n} is a perfect number (divisor sum = ${sum}).` : `${n} is not perfect (divisor sum = ${sum}).`;
    },
  },
  {
    id: "mx-is-armstrong", name: "Is Armstrong Number?", cat: "math",
    desc: "Test if a number equals the sum of its digits each raised to the digit count.",
    tags: ["armstrong", "narcissistic", "digits"],
    inputs: [{ k: "n", label: "Non-negative integer", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      const s = String(v.n).trim();
      if (!/^\d+$/.test(s)) return { error: "Enter a non-negative integer." };
      const p = s.length;
      let sum = 0n;
      for (const ch of s) sum += BigInt(ch) ** BigInt(p);
      return sum === BigInt(s) ? `${s} is an Armstrong number.` : `${s} is not an Armstrong number (sum = ${sum}).`;
    },
  },
  {
    id: "mx-is-palindrome-number", name: "Is Palindrome Number?", cat: "math",
    desc: "Test whether an integer reads the same forwards and backwards.",
    tags: ["palindrome", "reverse", "digits"],
    inputs: [{ k: "n", label: "Integer", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      const s = String(v.n).trim().replace(/^[+-]/, "");
      if (!/^\d+$/.test(s)) return ERR;
      const rev = s.split("").reverse().join("");
      return rev === s ? `${s} is a palindrome.` : `${s} is not a palindrome (reversed: ${rev}).`;
    },
  },
  {
    id: "mx-mod-exp", name: "Modular Exponentiation", cat: "math",
    desc: "Compute (a^b) mod m efficiently.",
    tags: ["modular", "exponent", "power", "mod"],
    inputs: [
      { k: "a", label: "base a", type: "text", inputType: "number" },
      { k: "b", label: "exponent b", type: "text", inputType: "number" },
      { k: "m", label: "modulus m", type: "text", inputType: "number" },
    ],
    run(v) {
      if ([v.a, v.b, v.m].some((x) => String(x ?? "").trim() === "")) return "";
      let a = _big(v.a), b = _big(v.b), m = _big(v.m);
      if (a === null || b === null || m === null) return ERR;
      if (m <= 0n) return { error: "Modulus must be positive." };
      if (b < 0n) return { error: "Exponent must be non-negative." };
      a = ((a % m) + m) % m;
      let r = 1n;
      while (b > 0n) { if (b & 1n) r = (r * a) % m; a = (a * a) % m; b >>= 1n; }
      return r.toString();
    },
  },
  {
    id: "mx-mod-inverse", name: "Modular Inverse", cat: "math",
    desc: "Find x such that (a·x) ≡ 1 (mod m) via the extended Euclidean algorithm.",
    tags: ["modular", "inverse", "euclid"],
    inputs: [{ k: "a", label: "a", type: "text", inputType: "number" }, { k: "m", label: "modulus m", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.a ?? "").trim() === "" || String(v.m ?? "").trim() === "") return "";
      let a = _big(v.a), m = _big(v.m);
      if (a === null || m === null) return ERR;
      if (m <= 0n) return { error: "Modulus must be positive." };
      let [old_r, r] = [((a % m) + m) % m, m];
      let [old_s, s] = [1n, 0n];
      while (r !== 0n) { const q = old_r / r; [old_r, r] = [r, old_r - q * r]; [old_s, s] = [s, old_s - q * s]; }
      if (old_r !== 1n) return { error: `No inverse: gcd(a, m) = ${old_r} ≠ 1.` };
      return (((old_s % m) + m) % m).toString();
    },
  },

  // ---------- roman ----------
  {
    id: "mx-roman-to-int", name: "Roman Numeral → Integer", cat: "math",
    desc: "Convert a Roman numeral to an integer.",
    tags: ["roman", "numeral", "convert"],
    inputs: [{ k: "s", label: "Roman numeral", type: "text", placeholder: "MCMXCIV" }],
    run(v) {
      if (String(v.s ?? "").trim() === "") return "";
      const s = String(v.s).trim().toUpperCase();
      const map = { I: 1, V: 5, X: 10, L: 50, C: 100, D: 500, M: 1000 };
      if (!/^[IVXLCDM]+$/.test(s)) return { error: "Not a valid Roman numeral." };
      let total = 0;
      for (let i = 0; i < s.length; i++) {
        const cur = map[s[i]], nxt = map[s[i + 1]] || 0;
        total += cur < nxt ? -cur : cur;
      }
      return String(total);
    },
  },
  {
    id: "mx-int-to-roman", name: "Integer → Roman Numeral", cat: "math",
    desc: "Convert an integer (1–3999) to a Roman numeral.",
    tags: ["roman", "numeral", "convert"],
    inputs: [{ k: "n", label: "Integer 1–3999", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      let n = _int(v.n);
      if (Number.isNaN(n)) return ERR;
      if (n < 1 || n > 3999) return { error: "Enter an integer from 1 to 3999." };
      const vals = [1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1];
      const sym = ["M", "CM", "D", "CD", "C", "XC", "L", "XL", "X", "IX", "V", "IV", "I"];
      let out = "";
      for (let i = 0; i < vals.length; i++) while (n >= vals[i]) { out += sym[i]; n -= vals[i]; }
      return out;
    },
  },

  // ---------- percentage / ratio / fraction ----------
  {
    id: "mx-percentage-of", name: "Percentage of a Number", cat: "math",
    desc: "Compute p% of a number.",
    tags: ["percent", "percentage"],
    inputs: [{ k: "p", label: "Percent p", type: "text", inputType: "number", value: "10" }, { k: "n", label: "of number", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.p ?? "").trim() === "" || String(v.n ?? "").trim() === "") return "";
      const p = _num(v.p), n = _num(v.n);
      if (Number.isNaN(p) || Number.isNaN(n)) return ERR;
      return _fmt((p / 100) * n);
    },
  },
  {
    id: "mx-what-percent", name: "What Percent (a of b)", cat: "math",
    desc: "Find what percentage a is of b.",
    tags: ["percent", "ratio"],
    inputs: [{ k: "a", label: "a", type: "text", inputType: "number" }, { k: "b", label: "b", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.a ?? "").trim() === "" || String(v.b ?? "").trim() === "") return "";
      const a = _num(v.a), b = _num(v.b);
      if (Number.isNaN(a) || Number.isNaN(b)) return ERR;
      if (b === 0) return { error: "b must be non-zero." };
      return _fmt((a / b) * 100) + "%";
    },
  },
  {
    id: "mx-percentage-change", name: "Percentage Change", cat: "math",
    desc: "Percent change from an old value to a new value.",
    tags: ["percent", "change", "delta"],
    inputs: [{ k: "old", label: "Old value", type: "text", inputType: "number" }, { k: "new", label: "New value", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.old ?? "").trim() === "" || String(v.new ?? "").trim() === "") return "";
      const o = _num(v.old), n = _num(v.new);
      if (Number.isNaN(o) || Number.isNaN(n)) return ERR;
      if (o === 0) return { error: "Old value must be non-zero." };
      const c = ((n - o) / Math.abs(o)) * 100;
      return `${_fmt(c)}% (${c >= 0 ? "increase" : "decrease"})`;
    },
  },
  {
    id: "mx-increase-decrease-percent", name: "Increase / Decrease by %", cat: "math",
    desc: "Apply a percentage increase or decrease to a value.",
    tags: ["percent", "increase", "decrease"],
    inputs: [
      { k: "n", label: "Value", type: "text", inputType: "number" },
      { k: "p", label: "Percent", type: "text", inputType: "number", value: "10" },
      { k: "mode", label: "Mode", type: "select", opts: [["inc", "Increase"], ["dec", "Decrease"]], value: "inc" },
    ],
    run(v) {
      if (String(v.n ?? "").trim() === "" || String(v.p ?? "").trim() === "") return "";
      const n = _num(v.n), p = _num(v.p);
      if (Number.isNaN(n) || Number.isNaN(p)) return ERR;
      const f = v.mode === "dec" ? 1 - p / 100 : 1 + p / 100;
      return _fmt(n * f);
    },
  },
  {
    id: "mx-ratio-simplify", name: "Simplify Ratio", cat: "math",
    desc: "Reduce a ratio a:b to lowest terms.",
    tags: ["ratio", "simplify", "reduce"],
    inputs: [{ k: "a", label: "a", type: "text", inputType: "number" }, { k: "b", label: "b", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.a ?? "").trim() === "" || String(v.b ?? "").trim() === "") return "";
      const a = _int(v.a), b = _int(v.b);
      if (Number.isNaN(a) || Number.isNaN(b)) return ERR;
      if (a === 0 && b === 0) return { error: "At least one value must be non-zero." };
      const g = _gcd(a, b) || 1;
      return `${a / g} : ${b / g}`;
    },
  },
  {
    id: "mx-fraction-to-decimal", name: "Fraction → Decimal", cat: "math",
    desc: "Convert a fraction like 3/4 to its decimal value.",
    tags: ["fraction", "decimal", "divide"],
    inputs: [{ k: "s", label: "Fraction (a/b)", type: "text", placeholder: "3/4" }],
    run(v) {
      if (String(v.s ?? "").trim() === "") return "";
      const m = String(v.s).trim().match(/^([+-]?\d+(?:\.\d+)?)\s*\/\s*([+-]?\d+(?:\.\d+)?)$/);
      if (!m) return { error: "Enter a fraction like 3/4." };
      const a = Number(m[1]), b = Number(m[2]);
      if (b === 0) return { error: "Denominator must be non-zero." };
      return _fmt(a / b);
    },
  },
  {
    id: "mx-decimal-to-fraction", name: "Decimal → Fraction", cat: "math",
    desc: "Approximate a decimal as a fraction via continued fractions.",
    tags: ["decimal", "fraction", "approximate"],
    inputs: [{ k: "x", label: "Decimal", type: "text", inputType: "number", placeholder: "0.375" }],
    run(v) {
      if (String(v.x ?? "").trim() === "") return "";
      const x = _num(v.x);
      if (Number.isNaN(x)) return ERR;
      if (Number.isInteger(x)) return `${x}/1`;
      const sign = x < 0 ? -1 : 1;
      let val = Math.abs(x);
      let h1 = 1, h0 = 0, k1 = 0, k0 = 1, b = val;
      const maxDen = 1000000;
      do {
        const a = Math.floor(b);
        let h2 = a * h1 + h0; let k2 = a * k1 + k0;
        if (k2 > maxDen) break;
        h0 = h1; h1 = h2; k0 = k1; k1 = k2;
        if (b - a < 1e-12) break;
        b = 1 / (b - a);
      } while (Math.abs(val - h1 / k1) > 1e-12);
      return `${sign * h1}/${k1}  (≈ ${_fmt(sign * h1 / k1)})`;
    },
  },
  {
    id: "mx-scientific-notation", name: "Scientific Notation ↔ Decimal", cat: "math",
    desc: "Convert between scientific notation and plain decimal.",
    tags: ["scientific", "notation", "exponent", "decimal"],
    inputs: [
      { k: "x", label: "Value", type: "text", placeholder: "e.g. 1.5e3 or 1500" },
      { k: "dir", label: "Direction", type: "select", opts: [["toSci", "→ Scientific"], ["toDec", "→ Decimal"]], value: "toSci" },
    ],
    run(v) {
      if (String(v.x ?? "").trim() === "") return "";
      const x = Number(String(v.x).trim());
      if (Number.isNaN(x)) return ERR;
      return v.dir === "toDec" ? x.toString() : x.toExponential();
    },
  },

  // ---------- algebra / combinatorics ----------
  {
    id: "mx-quadratic-solver", name: "Quadratic Equation Solver", cat: "math",
    desc: "Solve ax² + bx + c = 0 (real or complex roots).",
    tags: ["quadratic", "roots", "equation", "algebra"],
    inputs: [
      { k: "a", label: "a", type: "text", inputType: "number" },
      { k: "b", label: "b", type: "text", inputType: "number" },
      { k: "c", label: "c", type: "text", inputType: "number" },
    ],
    run(v) {
      if ([v.a, v.b, v.c].some((x) => String(x ?? "").trim() === "")) return "";
      const a = _num(v.a), b = _num(v.b), c = _num(v.c);
      if ([a, b, c].some(Number.isNaN)) return ERR;
      if (a === 0) {
        if (b === 0) return c === 0 ? "Infinite solutions." : "No solution.";
        return `x = ${_fmt(-c / b)}`;
      }
      const d = b * b - 4 * a * c;
      if (d >= 0) {
        const sq = Math.sqrt(d);
        return `x₁ = ${_fmt((-b + sq) / (2 * a))}\nx₂ = ${_fmt((-b - sq) / (2 * a))}`;
      }
      const re = -b / (2 * a), im = Math.sqrt(-d) / (2 * a);
      return `x₁ = ${_fmt(re)} + ${_fmt(im)}i\nx₂ = ${_fmt(re)} − ${_fmt(im)}i`;
    },
  },
  {
    id: "mx-discriminant", name: "Discriminant", cat: "math",
    desc: "Compute b² − 4ac for a quadratic.",
    tags: ["discriminant", "quadratic"],
    inputs: [
      { k: "a", label: "a", type: "text", inputType: "number" },
      { k: "b", label: "b", type: "text", inputType: "number" },
      { k: "c", label: "c", type: "text", inputType: "number" },
    ],
    run(v) {
      if ([v.a, v.b, v.c].some((x) => String(x ?? "").trim() === "")) return "";
      const a = _num(v.a), b = _num(v.b), c = _num(v.c);
      if ([a, b, c].some(Number.isNaN)) return ERR;
      const d = b * b - 4 * a * c;
      const kind = d > 0 ? "two real roots" : d === 0 ? "one repeated real root" : "two complex roots";
      return `${_fmt(d)}  (${kind})`;
    },
  },
  {
    id: "mx-factorial", name: "Factorial", cat: "math",
    desc: "Compute n! for a non-negative integer.",
    tags: ["factorial", "product"],
    inputs: [{ k: "n", label: "n (0–10000)", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      const n = _int(v.n);
      if (Number.isNaN(n)) return ERR;
      if (n < 0) return { error: "Enter a non-negative integer." };
      if (n > 10000) return { error: "n too large (max 10000)." };
      let r = 1n;
      for (let i = 2n; i <= BigInt(n); i++) r *= i;
      return r.toString();
    },
  },
  {
    id: "mx-permutations", name: "Permutations (nPr)", cat: "math",
    desc: "Number of ordered arrangements: n! / (n−r)!.",
    tags: ["permutations", "npr", "combinatorics"],
    inputs: [{ k: "n", label: "n", type: "text", inputType: "number" }, { k: "r", label: "r", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "" || String(v.r ?? "").trim() === "") return "";
      const n = _int(v.n), r = _int(v.r);
      if (Number.isNaN(n) || Number.isNaN(r)) return ERR;
      if (n < 0 || r < 0) return { error: "n and r must be non-negative." };
      if (r > n) return "0";
      let res = 1n;
      for (let i = BigInt(n - r) + 1n; i <= BigInt(n); i++) res *= i;
      return res.toString();
    },
  },
  {
    id: "mx-combinations", name: "Combinations (nCr)", cat: "math",
    desc: "Number of unordered selections: n! / (r!·(n−r)!).",
    tags: ["combinations", "ncr", "binomial", "combinatorics"],
    inputs: [{ k: "n", label: "n", type: "text", inputType: "number" }, { k: "r", label: "r", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "" || String(v.r ?? "").trim() === "") return "";
      const n = _int(v.n), r = _int(v.r);
      if (Number.isNaN(n) || Number.isNaN(r)) return ERR;
      if (n < 0 || r < 0) return { error: "n and r must be non-negative." };
      if (r > n) return "0";
      const k = Math.min(r, n - r);
      let num = 1n;
      for (let i = 0n; i < BigInt(k); i++) num = num * (BigInt(n) - i) / (i + 1n);
      return num.toString();
    },
  },
  {
    id: "mx-fibonacci", name: "Fibonacci", cat: "math",
    desc: "The nth Fibonacci number plus the sequence up to n.",
    tags: ["fibonacci", "sequence"],
    inputs: [{ k: "n", label: "n (0-based, 0–5000)", type: "text", inputType: "number", value: "10" }],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      const n = _int(v.n);
      if (Number.isNaN(n)) return ERR;
      if (n < 0) return { error: "Enter a non-negative integer." };
      if (n > 5000) return { error: "n too large (max 5000)." };
      const seq = [0n];
      if (n >= 1) seq.push(1n);
      for (let i = 2; i <= n; i++) seq.push(seq[i - 1] + seq[i - 2]);
      return `F(${n}) = ${seq[n].toString()}\nsequence: ${seq.map((x) => x.toString()).join(", ")}`;
    },
  },
  {
    id: "mx-sum-1-to-n", name: "Sum 1..n", cat: "math",
    desc: "Sum of all integers from 1 to n.",
    tags: ["sum", "series", "triangular"],
    inputs: [{ k: "n", label: "n", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      const n = _big(v.n);
      if (n === null) return ERR;
      if (n < 0n) return { error: "Enter a non-negative integer." };
      return (n * (n + 1n) / 2n).toString();
    },
  },
  {
    id: "mx-sum-list", name: "Sum of a List", cat: "math",
    desc: "Add up a list of numbers.",
    tags: ["sum", "total", "add"],
    inputs: [{ k: "nums", label: "Numbers", type: "textarea", rows: 3, placeholder: "1, 2, 3.5" }],
    run(v) {
      const a = _list(v.nums);
      if (a === null) return ERR;
      if (!a.length) return "";
      return _fmt(a.reduce((s, x) => s + x, 0));
    },
  },
  {
    id: "mx-product-list", name: "Product of a List", cat: "math",
    desc: "Multiply a list of numbers together.",
    tags: ["product", "multiply"],
    inputs: [{ k: "nums", label: "Numbers", type: "textarea", rows: 3, placeholder: "2, 3, 4" }],
    run(v) {
      const a = _list(v.nums);
      if (a === null) return ERR;
      if (!a.length) return "";
      return _fmt(a.reduce((s, x) => s * x, 1));
    },
  },

  // ---------- statistics ----------
  {
    id: "mx-mean", name: "Mean (Average)", cat: "math",
    desc: "Arithmetic mean of a list of numbers.",
    tags: ["mean", "average", "stats"],
    inputs: [{ k: "nums", label: "Numbers", type: "textarea", rows: 3, placeholder: "4, 8, 15, 16, 23, 42" }],
    run(v) {
      const a = _list(v.nums);
      if (a === null) return ERR;
      if (!a.length) return "";
      return _fmt(a.reduce((s, x) => s + x, 0) / a.length);
    },
  },
  {
    id: "mx-median", name: "Median", cat: "math",
    desc: "Middle value of a list of numbers.",
    tags: ["median", "stats"],
    inputs: [{ k: "nums", label: "Numbers", type: "textarea", rows: 3, placeholder: "4, 8, 15, 16, 23" }],
    run(v) {
      const a = _list(v.nums);
      if (a === null) return ERR;
      if (!a.length) return "";
      const s = [...a].sort((x, y) => x - y);
      const m = s.length >> 1;
      return _fmt(s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2);
    },
  },
  {
    id: "mx-mode", name: "Mode", cat: "math",
    desc: "Most frequently occurring value(s) in a list.",
    tags: ["mode", "frequency", "stats"],
    inputs: [{ k: "nums", label: "Numbers", type: "textarea", rows: 3, placeholder: "1, 2, 2, 3, 3, 4" }],
    run(v) {
      const a = _list(v.nums);
      if (a === null) return ERR;
      if (!a.length) return "";
      const counts = new Map();
      for (const x of a) counts.set(x, (counts.get(x) || 0) + 1);
      let max = 0;
      for (const c of counts.values()) if (c > max) max = c;
      if (max === 1) return "No mode (all values unique).";
      const modes = [...counts.entries()].filter(([, c]) => c === max).map(([k]) => k);
      return `${modes.map(_fmt).join(", ")}  (×${max})`;
    },
  },
  {
    id: "mx-range", name: "Range (max − min)", cat: "math",
    desc: "Difference between the largest and smallest values.",
    tags: ["range", "spread", "stats"],
    inputs: [{ k: "nums", label: "Numbers", type: "textarea", rows: 3 }],
    run(v) {
      const a = _list(v.nums);
      if (a === null) return ERR;
      if (!a.length) return "";
      return _fmt(Math.max(...a) - Math.min(...a));
    },
  },
  {
    id: "mx-variance", name: "Variance", cat: "math",
    desc: "Sample or population variance of a list.",
    tags: ["variance", "stats", "spread"],
    inputs: [
      { k: "nums", label: "Numbers", type: "textarea", rows: 3 },
      { k: "mode", label: "Type", type: "select", opts: [["sample", "Sample (n−1)"], ["pop", "Population (n)"]], value: "sample" },
    ],
    run(v) {
      const a = _list(v.nums);
      if (a === null) return ERR;
      if (!a.length) return "";
      const mean = a.reduce((s, x) => s + x, 0) / a.length;
      const ss = a.reduce((s, x) => s + (x - mean) ** 2, 0);
      const div = v.mode === "pop" ? a.length : a.length - 1;
      if (div <= 0) return { error: "Sample variance needs at least 2 values." };
      return _fmt(ss / div);
    },
  },
  {
    id: "mx-std-dev", name: "Standard Deviation", cat: "math",
    desc: "Sample or population standard deviation of a list.",
    tags: ["stddev", "deviation", "stats"],
    inputs: [
      { k: "nums", label: "Numbers", type: "textarea", rows: 3 },
      { k: "mode", label: "Type", type: "select", opts: [["sample", "Sample (n−1)"], ["pop", "Population (n)"]], value: "sample" },
    ],
    run(v) {
      const a = _list(v.nums);
      if (a === null) return ERR;
      if (!a.length) return "";
      const mean = a.reduce((s, x) => s + x, 0) / a.length;
      const ss = a.reduce((s, x) => s + (x - mean) ** 2, 0);
      const div = v.mode === "pop" ? a.length : a.length - 1;
      if (div <= 0) return { error: "Sample std dev needs at least 2 values." };
      return _fmt(Math.sqrt(ss / div));
    },
  },
  {
    id: "mx-min-max", name: "Min & Max", cat: "math",
    desc: "Smallest and largest value in a list.",
    tags: ["min", "max", "stats"],
    inputs: [{ k: "nums", label: "Numbers", type: "textarea", rows: 3 }],
    run(v) {
      const a = _list(v.nums);
      if (a === null) return ERR;
      if (!a.length) return "";
      return `min = ${_fmt(Math.min(...a))}\nmax = ${_fmt(Math.max(...a))}`;
    },
  },

  // ---------- scalar operations ----------
  {
    id: "mx-abs", name: "Absolute Value", cat: "math",
    desc: "The magnitude of a number, ignoring sign.",
    tags: ["abs", "magnitude"],
    inputs: [{ k: "x", label: "Number", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.x ?? "").trim() === "") return "";
      const x = _num(v.x);
      if (Number.isNaN(x)) return ERR;
      return _fmt(Math.abs(x));
    },
  },
  {
    id: "mx-sign", name: "Sign", cat: "math",
    desc: "Return −1, 0, or 1 for the sign of a number.",
    tags: ["sign", "signum"],
    inputs: [{ k: "x", label: "Number", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.x ?? "").trim() === "") return "";
      const x = _num(v.x);
      if (Number.isNaN(x)) return ERR;
      return String(Math.sign(x));
    },
  },
  {
    id: "mx-round-decimals", name: "Round to N Decimals", cat: "math",
    desc: "Round a number to a chosen number of decimal places.",
    tags: ["round", "decimals", "precision"],
    inputs: [{ k: "x", label: "Number", type: "text", inputType: "number" }, { k: "d", label: "Decimals", type: "text", inputType: "number", value: "2" }],
    run(v, H) {
      if (String(v.x ?? "").trim() === "") return "";
      const x = _num(v.x);
      if (Number.isNaN(x)) return ERR;
      const d = _ci(H, v.d, 0, 100, 2);
      const f = Math.pow(10, d);
      return String(Math.round((x + Number.EPSILON) * f) / f);
    },
  },
  {
    id: "mx-floor-ceil-trunc", name: "Floor / Ceil / Truncate", cat: "math",
    desc: "Round a number down, up, or toward zero.",
    tags: ["floor", "ceil", "truncate", "round"],
    inputs: [
      { k: "x", label: "Number", type: "text", inputType: "number" },
      { k: "op", label: "Operation", type: "select", opts: [["floor", "Floor (down)"], ["ceil", "Ceil (up)"], ["trunc", "Truncate (toward 0)"]], value: "floor" },
    ],
    run(v) {
      if (String(v.x ?? "").trim() === "") return "";
      const x = _num(v.x);
      if (Number.isNaN(x)) return ERR;
      if (v.op === "ceil") return _fmt(Math.ceil(x));
      if (v.op === "trunc") return _fmt(Math.trunc(x));
      return _fmt(Math.floor(x));
    },
  },
  {
    id: "mx-clamp", name: "Clamp Value", cat: "math",
    desc: "Constrain a value to the range [min, max].",
    tags: ["clamp", "constrain", "range"],
    inputs: [
      { k: "x", label: "Value", type: "text", inputType: "number" },
      { k: "lo", label: "Min", type: "text", inputType: "number" },
      { k: "hi", label: "Max", type: "text", inputType: "number" },
    ],
    run(v) {
      if ([v.x, v.lo, v.hi].some((x) => String(x ?? "").trim() === "")) return "";
      const x = _num(v.x), lo = _num(v.lo), hi = _num(v.hi);
      if ([x, lo, hi].some(Number.isNaN)) return ERR;
      if (lo > hi) return { error: "Min must be ≤ Max." };
      return _fmt(Math.min(hi, Math.max(lo, x)));
    },
  },
  {
    id: "mx-map-range", name: "Map Value Between Ranges", cat: "math",
    desc: "Re-scale a value from one range to another (linear map).",
    tags: ["map", "scale", "range", "remap"],
    inputs: [
      { k: "x", label: "Value", type: "text", inputType: "number" },
      { k: "inLo", label: "In min", type: "text", inputType: "number", value: "0" },
      { k: "inHi", label: "In max", type: "text", inputType: "number", value: "1" },
      { k: "outLo", label: "Out min", type: "text", inputType: "number", value: "0" },
      { k: "outHi", label: "Out max", type: "text", inputType: "number", value: "100" },
    ],
    run(v) {
      const keys = ["x", "inLo", "inHi", "outLo", "outHi"];
      if (keys.some((k) => String(v[k] ?? "").trim() === "")) return "";
      const [x, iLo, iHi, oLo, oHi] = keys.map((k) => _num(v[k]));
      if ([x, iLo, iHi, oLo, oHi].some(Number.isNaN)) return ERR;
      if (iLo === iHi) return { error: "Input range cannot be zero-width." };
      return _fmt(oLo + ((x - iLo) * (oHi - oLo)) / (iHi - iLo));
    },
  },
  {
    id: "mx-lerp", name: "Linear Interpolation (lerp)", cat: "math",
    desc: "Interpolate between a and b by fraction t.",
    tags: ["lerp", "interpolation", "blend"],
    inputs: [
      { k: "a", label: "a (t=0)", type: "text", inputType: "number" },
      { k: "b", label: "b (t=1)", type: "text", inputType: "number" },
      { k: "t", label: "t", type: "text", inputType: "number", value: "0.5" },
    ],
    run(v) {
      if ([v.a, v.b, v.t].some((x) => String(x ?? "").trim() === "")) return "";
      const a = _num(v.a), b = _num(v.b), t = _num(v.t);
      if ([a, b, t].some(Number.isNaN)) return ERR;
      return _fmt(a + (b - a) * t);
    },
  },

  // ---------- trig / geometry ----------
  {
    id: "mx-deg-rad", name: "Degrees ↔ Radians", cat: "math",
    desc: "Convert between degrees and radians.",
    tags: ["degrees", "radians", "angle", "convert"],
    inputs: [
      { k: "x", label: "Angle", type: "text", inputType: "number" },
      { k: "dir", label: "Direction", type: "select", opts: [["d2r", "Degrees → Radians"], ["r2d", "Radians → Degrees"]], value: "d2r" },
    ],
    run(v) {
      if (String(v.x ?? "").trim() === "") return "";
      const x = _num(v.x);
      if (Number.isNaN(x)) return ERR;
      return v.dir === "r2d" ? _fmt((x * 180) / Math.PI) : _fmt((x * Math.PI) / 180);
    },
  },
  {
    id: "mx-nth-root", name: "Nth Root", cat: "math",
    desc: "Compute the nth root of a number.",
    tags: ["root", "radical", "power"],
    inputs: [{ k: "x", label: "Value", type: "text", inputType: "number" }, { k: "n", label: "n (root)", type: "text", inputType: "number", value: "2" }],
    run(v) {
      if (String(v.x ?? "").trim() === "" || String(v.n ?? "").trim() === "") return "";
      const x = _num(v.x), n = _num(v.n);
      if (Number.isNaN(x) || Number.isNaN(n)) return ERR;
      if (n === 0) return { error: "Root n must be non-zero." };
      if (x < 0) {
        if (Number.isInteger(n) && Math.abs(n % 2) === 1) return _fmt(-Math.pow(-x, 1 / n));
        return { error: "Even/root of a negative number is not real." };
      }
      return _fmt(Math.pow(x, 1 / n));
    },
  },
  {
    id: "mx-log-base", name: "Logarithm (any base)", cat: "math",
    desc: "Compute log base b of x.",
    tags: ["log", "logarithm", "base"],
    inputs: [{ k: "x", label: "x", type: "text", inputType: "number" }, { k: "b", label: "base b", type: "text", inputType: "number", value: "10" }],
    run(v) {
      if (String(v.x ?? "").trim() === "" || String(v.b ?? "").trim() === "") return "";
      const x = _num(v.x), b = _num(v.b);
      if (Number.isNaN(x) || Number.isNaN(b)) return ERR;
      if (x <= 0) return { error: "x must be positive." };
      if (b <= 0 || b === 1) return { error: "Base must be positive and not 1." };
      return _fmt(Math.log(x) / Math.log(b));
    },
  },
  {
    id: "mx-hypotenuse", name: "Hypotenuse", cat: "math",
    desc: "Length of the hypotenuse √(a² + b²).",
    tags: ["hypotenuse", "pythagoras", "triangle"],
    inputs: [{ k: "a", label: "a", type: "text", inputType: "number" }, { k: "b", label: "b", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.a ?? "").trim() === "" || String(v.b ?? "").trim() === "") return "";
      const a = _num(v.a), b = _num(v.b);
      if (Number.isNaN(a) || Number.isNaN(b)) return ERR;
      return _fmt(Math.hypot(a, b));
    },
  },
  {
    id: "mx-distance-2d", name: "Distance Between Points", cat: "math",
    desc: "Euclidean distance between two 2D points.",
    tags: ["distance", "euclidean", "points", "geometry"],
    inputs: [
      { k: "x1", label: "x₁", type: "text", inputType: "number" },
      { k: "y1", label: "y₁", type: "text", inputType: "number" },
      { k: "x2", label: "x₂", type: "text", inputType: "number" },
      { k: "y2", label: "y₂", type: "text", inputType: "number" },
    ],
    run(v) {
      const keys = ["x1", "y1", "x2", "y2"];
      if (keys.some((k) => String(v[k] ?? "").trim() === "")) return "";
      const [x1, y1, x2, y2] = keys.map((k) => _num(v[k]));
      if ([x1, y1, x2, y2].some(Number.isNaN)) return ERR;
      return _fmt(Math.hypot(x2 - x1, y2 - y1));
    },
  },
  {
    id: "mx-midpoint", name: "Midpoint", cat: "math",
    desc: "Midpoint of the segment between two 2D points.",
    tags: ["midpoint", "points", "geometry"],
    inputs: [
      { k: "x1", label: "x₁", type: "text", inputType: "number" },
      { k: "y1", label: "y₁", type: "text", inputType: "number" },
      { k: "x2", label: "x₂", type: "text", inputType: "number" },
      { k: "y2", label: "y₂", type: "text", inputType: "number" },
    ],
    run(v) {
      const keys = ["x1", "y1", "x2", "y2"];
      if (keys.some((k) => String(v[k] ?? "").trim() === "")) return "";
      const [x1, y1, x2, y2] = keys.map((k) => _num(v[k]));
      if ([x1, y1, x2, y2].some(Number.isNaN)) return ERR;
      return `(${_fmt((x1 + x2) / 2)}, ${_fmt((y1 + y2) / 2)})`;
    },
  },
  {
    id: "mx-slope", name: "Slope of a Line", cat: "math",
    desc: "Slope (rise / run) between two 2D points.",
    tags: ["slope", "gradient", "line", "geometry"],
    inputs: [
      { k: "x1", label: "x₁", type: "text", inputType: "number" },
      { k: "y1", label: "y₁", type: "text", inputType: "number" },
      { k: "x2", label: "x₂", type: "text", inputType: "number" },
      { k: "y2", label: "y₂", type: "text", inputType: "number" },
    ],
    run(v) {
      const keys = ["x1", "y1", "x2", "y2"];
      if (keys.some((k) => String(v[k] ?? "").trim() === "")) return "";
      const [x1, y1, x2, y2] = keys.map((k) => _num(v[k]));
      if ([x1, y1, x2, y2].some(Number.isNaN)) return ERR;
      if (x1 === x2) return "Undefined (vertical line).";
      return _fmt((y2 - y1) / (x2 - x1));
    },
  },
  {
    id: "mx-area", name: "Area", cat: "math",
    desc: "Area of a circle, rectangle, or triangle.",
    tags: ["area", "geometry", "circle", "rectangle", "triangle"],
    inputs: [
      { k: "shape", label: "Shape", type: "select", opts: [["circle", "Circle (radius)"], ["rect", "Rectangle (w × h)"], ["tri", "Triangle (base, height)"]], value: "circle" },
      { k: "a", label: "a (radius / width / base)", type: "text", inputType: "number" },
      { k: "b", label: "b (height) — not for circle", type: "text", inputType: "number" },
    ],
    run(v) {
      if (String(v.a ?? "").trim() === "") return "";
      const a = _num(v.a);
      if (Number.isNaN(a)) return ERR;
      if (v.shape === "circle") return _fmt(Math.PI * a * a);
      const b = _num(v.b);
      if (String(v.b ?? "").trim() === "" || Number.isNaN(b)) return ERR;
      if (v.shape === "rect") return _fmt(a * b);
      return _fmt(0.5 * a * b);
    },
  },
  {
    id: "mx-circumference", name: "Circle Circumference", cat: "math",
    desc: "Circumference of a circle from its radius (2πr).",
    tags: ["circumference", "circle", "perimeter", "geometry"],
    inputs: [{ k: "r", label: "Radius", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.r ?? "").trim() === "") return "";
      const r = _num(v.r);
      if (Number.isNaN(r)) return ERR;
      if (r < 0) return { error: "Radius must be non-negative." };
      return `${_fmt(2 * Math.PI * r)}  (diameter ${_fmt(2 * r)})`;
    },
  },
  {
    id: "mx-is-power-of-two", name: "Is Power of Two?", cat: "math",
    desc: "Test whether a positive integer is a power of two.",
    tags: ["power", "two", "binary"],
    inputs: [{ k: "n", label: "Positive integer", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      const n = _big(v.n);
      if (n === null) return ERR;
      if (n < 1n) return `${n} is not a power of two.`;
      const isPow = (n & (n - 1n)) === 0n;
      if (!isPow) return `${n} is not a power of two.`;
      let e = 0n, t = n;
      while (t > 1n) { t >>= 1n; e++; }
      return `${n} = 2^${e}`;
    },
  },
  {
    id: "mx-next-power-of-two", name: "Next Power of Two", cat: "math",
    desc: "Smallest power of two greater than or equal to n.",
    tags: ["power", "two", "round-up"],
    inputs: [{ k: "n", label: "Positive integer", type: "text", inputType: "number" }],
    run(v) {
      if (String(v.n ?? "").trim() === "") return "";
      const n = _big(v.n);
      if (n === null) return ERR;
      if (n < 1n) return "1";
      let p = 1n, e = 0n;
      while (p < n) { p <<= 1n; e++; }
      return `${p.toString()} = 2^${e}`;
    },
  },
];
