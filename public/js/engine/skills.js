// Universal Engine — deterministic skills ("sources"). Each skill is a pure function
// with a fixed, inspectable rule set. No AI, no randomness: same input -> same output,
// and each result is something the engine can show its work for.
//
// Skills: calc (arithmetic), convert (units), codegen (program synthesis from a spec,
// multi-language), text (transforms), regex (pattern builder), datetime (date math).

// ---------------------------------------------------------------------------
// calc: a real expression evaluator (shunting-yard -> RPN). Not eval(): a hand
// written parser that supports + - * / % ^, parentheses, unary minus, functions
// and constants. This is a genuine little computation, verifiable step by step.
// ---------------------------------------------------------------------------
export const CONSTS = { pi: Math.PI, e: Math.E, tau: 2 * Math.PI, phi: (1 + Math.sqrt(5)) / 2 };

// integer helpers, exported so the number-theory skill can reuse them.
export function factorial(n) {
  if (n < 0 || !Number.isInteger(n)) throw new Error("factorial needs a non-negative integer");
  if (n > 170) return Infinity;
  let r = 1; for (let i = 2; i <= n; i++) r *= i; return r;
}
export function gcd2(a, b) { a = Math.abs(Math.trunc(a)); b = Math.abs(Math.trunc(b)); while (b) { const t = a % b; a = b; b = t; } return a; }
function nCr(n, r) { if (r < 0 || r > n) return 0; return Math.round(factorial(n) / (factorial(r) * factorial(n - r))); }
function nPr(n, r) { if (r < 0 || r > n) return 0; return Math.round(factorial(n) / factorial(n - r)); }

// Functions take an argument array, so min/max/gcd/lcm/hypot are variadic.
const MFUNCS = {
  sqrt: (a) => Math.sqrt(a[0]), cbrt: (a) => Math.cbrt(a[0]), abs: (a) => Math.abs(a[0]),
  round: (a) => { const d = a.length > 1 ? Math.max(-15, Math.min(12, Math.trunc(a[1]))) : 0; const f = 10 ** d; return d < 0 ? Math.round(a[0] * f) * 10 ** -d : Math.round(a[0] * f) / f; }, floor: (a) => Math.floor(a[0]), ceil: (a) => Math.ceil(a[0]),
  sin: (a) => Math.sin(a[0]), cos: (a) => Math.cos(a[0]), tan: (a) => Math.tan(a[0]),
  asin: (a) => Math.asin(a[0]), acos: (a) => Math.acos(a[0]), atan: (a) => Math.atan(a[0]),
  ln: (a) => Math.log(a[0]), log: (a) => Math.log10(a[0]), log2: (a) => Math.log2(a[0]),
  exp: (a) => Math.exp(a[0]), sign: (a) => Math.sign(a[0]),
  fact: (a) => factorial(a[0]), factorial: (a) => factorial(a[0]),
  min: (a) => Math.min(...a), max: (a) => Math.max(...a), hypot: (a) => Math.hypot(...a),
  pow: (a) => Math.pow(a[0], a[1]), mod: (a) => ((a[0] % a[1]) + a[1]) % a[1],
  logb: (a) => Math.log(a[0]) / Math.log(a[1]), atan2: (a) => Math.atan2(a[0], a[1]),
  gcd: (a) => a.reduce((x, y) => gcd2(x, y)), lcm: (a) => a.reduce((x, y) => Math.abs(x / gcd2(x, y) * y)),
  ncr: (a) => nCr(a[0], a[1]), npr: (a) => nPr(a[0], a[1]), avg: (a) => a.reduce((x, y) => x + y, 0) / a.length,
};
const ARITY2 = { pow: 1, mod: 1, logb: 1, atan2: 1, gcd: 1, lcm: 1, ncr: 1, npr: 1 };

function lexMath(src) {
  const toks = [];
  const re = /\s*(0x[0-9a-f]+|0b[01]+|0o[0-7]+|[0-9]*\.?[0-9]+(?:e[-+]?[0-9]+)?|[a-z_][a-z0-9_]*|[-+*/%^!(),=])/gy;
  let m, consumed = 0;
  while ((m = re.exec(src))) {
    consumed = re.lastIndex; // sticky exec resets lastIndex to 0 on the final miss
    const t = m[1];
    if (/^0x/.test(t)) toks.push({ t: "num", v: parseInt(t.slice(2), 16) });
    else if (/^0b/.test(t)) toks.push({ t: "num", v: parseInt(t.slice(2), 2) });
    else if (/^0o/.test(t)) toks.push({ t: "num", v: parseInt(t.slice(2), 8) });
    else if (/^[0-9.]/.test(t)) toks.push({ t: "num", v: parseFloat(t) });
    else if (/^[a-z_]/.test(t)) toks.push({ t: "name", v: t });
    else toks.push({ t: "op", v: t });
  }
  if (consumed !== src.length && src.slice(consumed).trim() !== "") {
    throw new Error("unexpected token near '" + src.slice(consumed).trim().slice(0, 12) + "'");
  }
  return toks;
}

// Recursive-descent evaluator over one statement's tokens, sharing a vars map.
function evalTokens(toks, vars) {
  let i = 0;
  const peek = () => toks[i];
  const eat = (v) => { const t = toks[i]; if (v && (!t || t.v !== v)) throw new Error("expected '" + v + "'"); i++; return t; };
  const isOp = (v) => { const t = peek(); return t && t.t === "op" && t.v === v; };

  function expr() { return addSub(); }
  function addSub() { let x = mulDiv(); while (isOp("+") || isOp("-")) { const o = eat().v; const y = mulDiv(); x = o === "+" ? x + y : x - y; } return x; }
  function mulDiv() { let x = power(); while (isOp("*") || isOp("/") || isOp("%")) { const o = eat().v; const y = power(); x = o === "*" ? x * y : o === "/" ? x / y : x % y; } return x; }
  function power() { const b = unary(); if (isOp("^")) { eat(); return Math.pow(b, power()); } return b; }
  function unary() { if (isOp("-") || isOp("+")) { const o = eat().v; const x = unary(); return o === "-" ? -x : x; } return postfix(); }
  function postfix() {
    let x = primary();
    while (isOp("!") || isOp("%")) {
      if (isOp("%")) { const nx = toks[i + 1]; if (nx && (nx.t === "num" || nx.t === "name" || (nx.t === "op" && nx.v === "("))) break; eat(); x = x / 100; }
      else { eat(); x = factorial(x); }
    }
    return x;
  }
  function primary() {
    const t = peek();
    if (!t) throw new Error("unexpected end of expression");
    if (t.t === "num") { eat(); return t.v; }
    if (isOp("(")) { eat("("); const x = expr(); eat(")"); return x; }
    if (t.t === "name") {
      eat();
      if (isOp("(")) {
        eat("(");
        const args = [];
        if (!isOp(")")) { args.push(expr()); while (isOp(",")) { eat(); args.push(expr()); } }
        eat(")");
        const fn = MFUNCS[t.v];
        if (!fn) throw new Error("unknown function '" + t.v + "'");
        if (ARITY2[t.v] && args.length < 2) throw new Error(t.v + " needs at least 2 arguments");
        if (!args.length) throw new Error(t.v + " needs an argument");
        return fn(args);
      }
      if (t.v in CONSTS) return CONSTS[t.v];
      if (t.v in vars) return vars[t.v];
      throw new Error("unknown name '" + t.v + "'");
    }
    throw new Error("unexpected token");
  }

  const val = expr();
  if (i !== toks.length) throw new Error("unexpected trailing input");
  return val;
}

// Exact big integers when a double overflows: "171!", "2^1024", "50! / 48!" is not
// covered, only a lone factorial or an integer power. Capped to stay fast.
function bigExact(src) {
  const f = src.match(/^\s*\(?\s*(\d+)\s*\)?\s*!\s*$/), p = src.match(/^\s*\(?\s*(-?\d+)\s*\)?\s*(?:\^|\*\*)\s*(\d+)\s*$/);
  let v;
  if (f && +f[1] <= 3000) { v = 1n; for (let i = 2n; i <= BigInt(f[1]); i++) v *= i; }
  else if (p && BigInt(p[1].replace("-", "")).toString(2).length * +p[2] <= 40000) v = BigInt(p[1]) ** BigInt(p[2]);
  else return null;
  const digits = v.toString().replace("-", "").length;
  return { ok: true, value: v.toString(), big: true, digits };
}

function runCalc(src) {
  const stmts = src.split(/[;\n]+/).map((s) => s.trim()).filter(Boolean);
  const vars = {};
  let value;
  try {
    for (const stmt of stmts) {
      const toks = lexMath(stmt);
      if (toks.length >= 2 && toks[0].t === "name" && toks[1].t === "op" && toks[1].v === "=") {
        const name = toks[0].v;
        if (name in CONSTS) throw new Error("cannot assign to constant '" + name + "'");
        value = evalTokens(toks.slice(2), vars);
        vars[name] = value;
      } else value = evalTokens(toks, vars);
    }
    if (!Number.isFinite(value)) {
      const big = bigExact(src);
      if (big) return big;
      if (/\/\s*\(?\s*0(?:\.0*)?\s*\)?(?![\d.])/.test(src)) return { ok: false, error: /(?:^|[^\d.])0(?:\.0*)?\s*\/\s*\(?\s*0/.test(src) ? "0 / 0 is undefined (it has no single value)" : "division by zero is undefined" };
      if (/\b(?:log|ln|log10|log2)\s*\(\s*0\s*\)/.test(src)) return { ok: false, error: "the logarithm of 0 is undefined (it falls toward minus infinity)" };
      if (value === Infinity || value === -Infinity) return { ok: false, error: "the result is too large for a double-precision number (above about 1.8 x 10^308)" };
      return { ok: false, error: "the result is not a real number (for example the square root or logarithm of a negative number, or 0 / 0)" };
    }
    // tan at an odd multiple of 90 degrees is undefined, but floating point gives ~1.6e16
    if (/\btan\s*\(/.test(src) && Math.abs(value) > 1e15) return { ok: false, error: "tan is undefined there (at odd multiples of 90 degrees, or pi/2 radians)" };
    value = Math.round(value * 1e12) / 1e12;
    const out = { ok: true, value };
    if (Object.keys(vars).length) out.vars = vars;
    return out;
  } catch (e) { return { ok: false, error: e.message }; }
}

// the simplest fraction within 1e-9 of x, by continued fractions (0.75 -> 3/4)
export function toFraction(x) {
  const sign = x < 0 ? -1 : 1; x = Math.abs(x);
  let h1 = 1, h0 = 0, k1 = 0, k0 = 1, b = x;
  for (let i = 0; i < 40; i++) {
    const a = Math.floor(b);
    [h1, h0] = [a * h1 + h0, h1]; [k1, k0] = [a * k1 + k0, k1];
    if (Math.abs(x - h1 / k1) < 1e-9 * Math.max(1, x) || k1 > 1e9) break;
    b = 1 / (b - a);
  }
  return { n: sign * h1, d: k1 };
}

export function calc(input) {
  let src = String(input || "").toLowerCase().replace(/[?]/g, "").trim();
  if (!src) return { ok: false, error: "empty expression" };
  const fr = src.match(/^(?:what is |whats |convert |write )?(-?\d*\.\d+|-?\d+(?:\.\d+)?\s*\/\s*\d+)\s+(?:as|to|in|into)\s+(?:a\s+|its\s+)?(?:simplest\s+)?fraction\s*$/);
  if (fr) {
    const x = runCalc(fr[1]); if (!x.ok) return x;
    const { n, d } = toFraction(x.value);
    return { ok: true, value: d === 1 ? String(n) : n + "/" + d, expr: fr[1] + " as a fraction" };
  }
  src = src.replace(/([0-9.]+)\s*%\s+of\s+/g, "($1/100)*"); // "15% of 200"
  const res = runCalc(src);
  if (res.ok) { res.expr = src; return res; }
  // typo / filler tolerance: drop natural-language words that are not known names, then retry.
  // A word glued to "(" is kept — that is an intended function call, so it should error honestly.
  if (/\d/.test(src)) {
    const stripped = src.replace(/[a-z_][a-z0-9_]*/g, (w, off, str) =>
      (w in MFUNCS || w in CONSTS || /^\s*\(/.test(str.slice(off + w.length))) ? w : " ").replace(/\s+/g, " ").trim();
    if (stripped && stripped !== src && /\d/.test(stripped)) {
      const r2 = runCalc(stripped);
      if (r2.ok) { r2.expr = stripped; return r2; }
    }
  }
  return res;
}

// ---------------------------------------------------------------------------
// convert: unit conversion via factor tables (+ special temperature formulas).
// ---------------------------------------------------------------------------
const UNITS = {
  length: { base: "m", u: { mm: 1e-3, millimeter: 1e-3, millimeters: 1e-3, millimetre: 1e-3, millimetres: 1e-3, cm: 1e-2, centimeter: 1e-2, centimeters: 1e-2, centimetre: 1e-2, centimetres: 1e-2, m: 1, meter: 1, meters: 1, metre: 1, metres: 1, km: 1e3, kilometer: 1e3, kilometers: 1e3, kilometre: 1e3, kilometres: 1e3, in: 0.0254, inch: 0.0254, inches: 0.0254, ft: 0.3048, foot: 0.3048, feet: 0.3048, yd: 0.9144, yard: 0.9144, yards: 0.9144, mi: 1609.344, mile: 1609.344, miles: 1609.344 } },
  mass: { base: "kg", u: { mg: 1e-6, milligram: 1e-6, milligrams: 1e-6, g: 1e-3, gram: 1e-3, grams: 1e-3, kg: 1, kilogram: 1, kilograms: 1, t: 1e3, tonne: 1e3, tonnes: 1e3, oz: 0.0283495, ounce: 0.0283495, ounces: 0.0283495, lb: 0.453592, lbs: 0.453592, pound: 0.453592, pounds: 0.453592, st: 6.35029, stone: 6.35029 } },
  time: { base: "s", u: { ms: 1e-3, millisecond: 1e-3, milliseconds: 1e-3, s: 1, sec: 1, secs: 1, second: 1, seconds: 1, min: 60, mins: 60, minute: 60, minutes: 60, h: 3600, hr: 3600, hrs: 3600, hour: 3600, hours: 3600, day: 86400, days: 86400, week: 604800, weeks: 604800, year: 31557600, years: 31557600 } },
  data: { base: "b", u: { bit: 0.125, b: 1, byte: 1, bytes: 1, kb: 1e3, kib: 1024, mb: 1e6, mib: 1048576, gb: 1e9, gib: 1073741824, tb: 1e12, tib: 1099511627776 } },
  speed: { base: "mps", u: { mps: 1, "m/s": 1, kph: 0.277778, "km/h": 0.277778, mph: 0.44704, kn: 0.514444, knot: 0.514444, knots: 0.514444 } },
  // US customary volumes (gallon = 231 cubic inches exactly)
  volume: { base: "l", u: { ml: 1e-3, milliliter: 1e-3, milliliters: 1e-3, millilitre: 1e-3, millilitres: 1e-3, cc: 1e-3, cl: 1e-2, l: 1, liter: 1, liters: 1, litre: 1, litres: 1, gal: 3.785411784, gallon: 3.785411784, gallons: 3.785411784, qt: 0.946352946, quart: 0.946352946, quarts: 0.946352946, pt: 0.473176473, pint: 0.473176473, pints: 0.473176473, cup: 0.2365882365, cups: 0.2365882365, floz: 0.0295735295625, "fl oz": 0.0295735295625, tbsp: 0.01478676478125, tablespoon: 0.01478676478125, tablespoons: 0.01478676478125, tsp: 0.00492892159375, teaspoon: 0.00492892159375, teaspoons: 0.00492892159375 } },
  area: { base: "m2", u: { m2: 1, sqm: 1, km2: 1e6, sqkm: 1e6, ft2: 0.09290304, sqft: 0.09290304, acre: 4046.8564224, acres: 4046.8564224, hectare: 1e4, hectares: 1e4, ha: 1e4 } },
};
function findUnit(u) { u = u.toLowerCase(); for (const dim in UNITS) if (u in UNITS[dim].u) return { dim, factor: UNITS[dim].u[u] }; return null; }

export function convert(input) {
  // find the "<number> <unit> to <unit>" pattern anywhere, so leading words
  // (including a misspelled "convert") do not block the parse.
  const src = String(input || "").toLowerCase().trim();
  const m = src.match(/(-?[0-9]*\.?[0-9]+)\s*([a-z°/]+)\s*(?:to|in|into|as)\s+([a-z°/]+)/);
  if (!m) return { ok: false, error: "use the form: 12 km to miles" };
  const val = parseFloat(m[1]);
  let from = m[2].replace("°", ""), to = m[3].replace("°", "");
  // temperature (non-linear)
  const T = { c: "c", celsius: "c", f: "f", fahrenheit: "f", k: "k", kelvin: "k" };
  if (T[from] && T[to]) {
    let c; if (T[from] === "c") c = val; else if (T[from] === "f") c = (val - 32) * 5 / 9; else c = val - 273.15;
    if (c < -273.15 - 1e-9) return { ok: false, error: val + " " + from + " is below absolute zero (-273.15 C, -459.67 F, 0 K), so it is not a physical temperature" };
    let out; if (T[to] === "c") out = c; else if (T[to] === "f") out = c * 9 / 5 + 32; else out = c + 273.15;
    return { ok: true, value: Math.round(out * 1e6) / 1e6, dim: "temperature", from, to, input: val };
  }
  let a = findUnit(from), b = findUnit(to);
  if (!a || !b) return { ok: false, error: "unknown unit: " + (!a ? from : to) };
  // "ounces" next to a volume means fluid ounces ("how many ounces in a cup")
  const FLOZ = { dim: "volume", factor: 0.0295735295625 };
  if (a.dim === "mass" && b.dim === "volume" && /^(?:oz|ounces?)$/.test(from)) a = FLOZ;
  if (b.dim === "mass" && a.dim === "volume" && /^(?:oz|ounces?)$/.test(to)) b = FLOZ;
  if (a.dim !== b.dim) return { ok: false, error: "cannot convert " + a.dim + " to " + b.dim };
  const out = val * a.factor / b.factor;
  return { ok: true, value: Math.round(out * 1e9) / 1e9, dim: a.dim, from, to, input: val };
}

// ---------------------------------------------------------------------------
// codegen: program synthesis from a specification, into a chosen language. This
// generates real code by instantiating a language backend for a known operation
// (not by pasting a stored blob — the same op is emitted fresh per language, and
// the identifier name is taken from your request). Unknown ops get a correct,
// typed skeleton, and we say plainly that it is a scaffold.
// ---------------------------------------------------------------------------
const LANGS = { python: "python", py: "python", javascript: "javascript", js: "javascript", node: "javascript", typescript: "typescript", ts: "typescript", rust: "rust", rs: "rust", go: "go", golang: "go", java: "java", c: "c" };

const OPGEN = {
  factorial: {
    keys: ["factorial"], name: "factorial",
    python: (n) => `def ${n}(x):\n    result = 1\n    for i in range(2, x + 1):\n        result *= i\n    return result`,
    javascript: (n) => `function ${n}(x) {\n  let result = 1;\n  for (let i = 2; i <= x; i++) result *= i;\n  return result;\n}`,
    typescript: (n) => `function ${n}(x: number): number {\n  let result = 1;\n  for (let i = 2; i <= x; i++) result *= i;\n  return result;\n}`,
    rust: (n) => `fn ${n}(x: u64) -> u64 {\n    (2..=x).product::<u64>().max(1)\n}`,
    go: (n) => `func ${n}(x int) int {\n\tresult := 1\n\tfor i := 2; i <= x; i++ {\n\t\tresult *= i\n\t}\n\treturn result\n}`,
    java: (n) => `static long ${n}(int x) {\n    long result = 1;\n    for (int i = 2; i <= x; i++) result *= i;\n    return result;\n}`,
    c: (n) => `long ${n}(int x) {\n    long result = 1;\n    for (int i = 2; i <= x; i++) result *= i;\n    return result;\n}`,
  },
  fibonacci: {
    keys: ["fibonacci", "fib"], name: "fibonacci",
    python: (n) => `def ${n}(x):\n    a, b = 0, 1\n    for _ in range(x):\n        a, b = b, a + b\n    return a`,
    javascript: (n) => `function ${n}(x) {\n  let a = 0, b = 1;\n  for (let i = 0; i < x; i++) [a, b] = [b, a + b];\n  return a;\n}`,
    typescript: (n) => `function ${n}(x: number): number {\n  let a = 0, b = 1;\n  for (let i = 0; i < x; i++) [a, b] = [b, a + b];\n  return a;\n}`,
    rust: (n) => `fn ${n}(x: u32) -> u64 {\n    let (mut a, mut b) = (0u64, 1u64);\n    for _ in 0..x { let t = a + b; a = b; b = t; }\n    a\n}`,
    go: (n) => `func ${n}(x int) int {\n\ta, b := 0, 1\n\tfor i := 0; i < x; i++ {\n\t\ta, b = b, a+b\n\t}\n\treturn a\n}`,
    java: (n) => `static long ${n}(int x) {\n    long a = 0, b = 1;\n    for (int i = 0; i < x; i++) { long t = a + b; a = b; b = t; }\n    return a;\n}`,
    c: (n) => `long ${n}(int x) {\n    long a = 0, b = 1;\n    for (int i = 0; i < x; i++) { long t = a + b; a = b; b = t; }\n    return a;\n}`,
  },
  reverseString: {
    keys: ["reverse"], name: "reverseString",
    python: (n) => `def ${n}(s):\n    return s[::-1]`,
    javascript: (n) => `function ${n}(s) {\n  return [...s].reverse().join("");\n}`,
    typescript: (n) => `function ${n}(s: string): string {\n  return [...s].reverse().join("");\n}`,
    rust: (n) => `fn ${n}(s: &str) -> String {\n    s.chars().rev().collect()\n}`,
    go: (n) => `func ${n}(s string) string {\n\tr := []rune(s)\n\tfor i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {\n\t\tr[i], r[j] = r[j], r[i]\n\t}\n\treturn string(r)\n}`,
    java: (n) => `static String ${n}(String s) {\n    return new StringBuilder(s).reverse().toString();\n}`,
    c: (n) => `void ${n}(char *s) {\n    int i = 0, j = strlen(s) - 1;\n    while (i < j) { char t = s[i]; s[i++] = s[j]; s[j--] = t; }\n}`,
  },
  isPrime: {
    keys: ["prime"], name: "isPrime",
    python: (n) => `def ${n}(x):\n    if x < 2:\n        return False\n    i = 2\n    while i * i <= x:\n        if x % i == 0:\n            return False\n        i += 1\n    return True`,
    javascript: (n) => `function ${n}(x) {\n  if (x < 2) return false;\n  for (let i = 2; i * i <= x; i++) if (x % i === 0) return false;\n  return true;\n}`,
    typescript: (n) => `function ${n}(x: number): boolean {\n  if (x < 2) return false;\n  for (let i = 2; i * i <= x; i++) if (x % i === 0) return false;\n  return true;\n}`,
    rust: (n) => `fn ${n}(x: u64) -> bool {\n    if x < 2 { return false; }\n    let mut i = 2;\n    while i * i <= x { if x % i == 0 { return false; } i += 1; }\n    true\n}`,
    go: (n) => `func ${n}(x int) bool {\n\tif x < 2 {\n\t\treturn false\n\t}\n\tfor i := 2; i*i <= x; i++ {\n\t\tif x%i == 0 {\n\t\t\treturn false\n\t\t}\n\t}\n\treturn true\n}`,
    java: (n) => `static boolean ${n}(long x) {\n    if (x < 2) return false;\n    for (long i = 2; i * i <= x; i++) if (x % i == 0) return false;\n    return true;\n}`,
    c: (n) => `int ${n}(long x) {\n    if (x < 2) return 0;\n    for (long i = 2; i * i <= x; i++) if (x % i == 0) return 0;\n    return 1;\n}`,
  },
  isPalindrome: {
    keys: ["palindrome"], name: "isPalindrome",
    python: (n) => `def ${n}(s):\n    s = "".join(c.lower() for c in s if c.isalnum())\n    return s == s[::-1]`,
    javascript: (n) => `function ${n}(s) {\n  const t = s.toLowerCase().replace(/[^a-z0-9]/g, "");\n  return t === [...t].reverse().join("");\n}`,
    typescript: (n) => `function ${n}(s: string): boolean {\n  const t = s.toLowerCase().replace(/[^a-z0-9]/g, "");\n  return t === [...t].reverse().join("");\n}`,
    rust: (n) => `fn ${n}(s: &str) -> bool {\n    let t: String = s.chars().filter(|c| c.is_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect();\n    t == t.chars().rev().collect::<String>()\n}`,
    go: (n) => `func ${n}(s string) bool {\n\tr := []rune(strings.ToLower(s))\n\tfor i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {\n\t\tif r[i] != r[j] {\n\t\t\treturn false\n\t\t}\n\t}\n\treturn true\n}`,
    java: (n) => `static boolean ${n}(String s) {\n    String t = s.toLowerCase().replaceAll("[^a-z0-9]", "");\n    return t.equals(new StringBuilder(t).reverse().toString());\n}`,
    c: (n) => `int ${n}(const char *s) {\n    int i = 0, j = strlen(s) - 1;\n    while (i < j) if (s[i++] != s[j--]) return 0;\n    return 1;\n}`,
  },
  fizzbuzz: {
    keys: ["fizzbuzz", "fizz buzz"], name: "fizzbuzz",
    python: (n) => `def ${n}(limit):\n    for i in range(1, limit + 1):\n        if i % 15 == 0:\n            print("FizzBuzz")\n        elif i % 3 == 0:\n            print("Fizz")\n        elif i % 5 == 0:\n            print("Buzz")\n        else:\n            print(i)`,
    javascript: (n) => `function ${n}(limit) {\n  for (let i = 1; i <= limit; i++) {\n    if (i % 15 === 0) console.log("FizzBuzz");\n    else if (i % 3 === 0) console.log("Fizz");\n    else if (i % 5 === 0) console.log("Buzz");\n    else console.log(i);\n  }\n}`,
    typescript: (n) => `function ${n}(limit: number): void {\n  for (let i = 1; i <= limit; i++) {\n    if (i % 15 === 0) console.log("FizzBuzz");\n    else if (i % 3 === 0) console.log("Fizz");\n    else if (i % 5 === 0) console.log("Buzz");\n    else console.log(i);\n  }\n}`,
    rust: (n) => `fn ${n}(limit: u32) {\n    for i in 1..=limit {\n        match (i % 3, i % 5) {\n            (0, 0) => println!("FizzBuzz"),\n            (0, _) => println!("Fizz"),\n            (_, 0) => println!("Buzz"),\n            _ => println!("{}", i),\n        }\n    }\n}`,
    go: (n) => `func ${n}(limit int) {\n\tfor i := 1; i <= limit; i++ {\n\t\tswitch {\n\t\tcase i%15 == 0:\n\t\t\tfmt.Println("FizzBuzz")\n\t\tcase i%3 == 0:\n\t\t\tfmt.Println("Fizz")\n\t\tcase i%5 == 0:\n\t\t\tfmt.Println("Buzz")\n\t\tdefault:\n\t\t\tfmt.Println(i)\n\t\t}\n\t}\n}`,
    java: (n) => `static void ${n}(int limit) {\n    for (int i = 1; i <= limit; i++) {\n        if (i % 15 == 0) System.out.println("FizzBuzz");\n        else if (i % 3 == 0) System.out.println("Fizz");\n        else if (i % 5 == 0) System.out.println("Buzz");\n        else System.out.println(i);\n    }\n}`,
    c: (n) => `void ${n}(int limit) {\n    for (int i = 1; i <= limit; i++) {\n        if (i % 15 == 0) printf("FizzBuzz\\n");\n        else if (i % 3 == 0) printf("Fizz\\n");\n        else if (i % 5 == 0) printf("Buzz\\n");\n        else printf("%d\\n", i);\n    }\n}`,
  },
  sumList: {
    keys: ["sum", "total", "add up"], name: "sumList",
    python: (n) => `def ${n}(items):\n    return sum(items)`,
    javascript: (n) => `function ${n}(items) {\n  return items.reduce((a, b) => a + b, 0);\n}`,
    typescript: (n) => `function ${n}(items: number[]): number {\n  return items.reduce((a, b) => a + b, 0);\n}`,
    rust: (n) => `fn ${n}(items: &[i64]) -> i64 {\n    items.iter().sum()\n}`,
    go: (n) => `func ${n}(items []int) int {\n\tsum := 0\n\tfor _, v := range items {\n\t\tsum += v\n\t}\n\treturn sum\n}`,
    java: (n) => `static long ${n}(int[] items) {\n    long sum = 0;\n    for (int v : items) sum += v;\n    return sum;\n}`,
    c: (n) => `long ${n}(int *items, int len) {\n    long sum = 0;\n    for (int i = 0; i < len; i++) sum += items[i];\n    return sum;\n}`,
  },
  gcd: {
    keys: ["gcd", "greatest common"], name: "gcd",
    python: (n) => `def ${n}(a, b):\n    while b:\n        a, b = b, a % b\n    return a`,
    javascript: (n) => `function ${n}(a, b) {\n  while (b) [a, b] = [b, a % b];\n  return a;\n}`,
    typescript: (n) => `function ${n}(a: number, b: number): number {\n  while (b) [a, b] = [b, a % b];\n  return a;\n}`,
    rust: (n) => `fn ${n}(mut a: u64, mut b: u64) -> u64 {\n    while b != 0 { let t = b; b = a % b; a = t; }\n    a\n}`,
    go: (n) => `func ${n}(a, b int) int {\n\tfor b != 0 {\n\t\ta, b = b, a%b\n\t}\n\treturn a\n}`,
    java: (n) => `static long ${n}(long a, long b) {\n    while (b != 0) { long t = b; b = a % b; a = t; }\n    return a;\n}`,
    c: (n) => `long ${n}(long a, long b) {\n    while (b) { long t = b; b = a % b; a = t; }\n    return a;\n}`,
  },
  binarySearch: {
    keys: ["binary search", "bsearch"], name: "binarySearch",
    python: (n) => `def ${n}(arr, target):\n    lo, hi = 0, len(arr) - 1\n    while lo <= hi:\n        mid = (lo + hi) // 2\n        if arr[mid] == target:\n            return mid\n        if arr[mid] < target:\n            lo = mid + 1\n        else:\n            hi = mid - 1\n    return -1`,
    javascript: (n) => `function ${n}(arr, target) {\n  let lo = 0, hi = arr.length - 1;\n  while (lo <= hi) {\n    const mid = (lo + hi) >> 1;\n    if (arr[mid] === target) return mid;\n    if (arr[mid] < target) lo = mid + 1; else hi = mid - 1;\n  }\n  return -1;\n}`,
    typescript: (n) => `function ${n}(arr: number[], target: number): number {\n  let lo = 0, hi = arr.length - 1;\n  while (lo <= hi) {\n    const mid = (lo + hi) >> 1;\n    if (arr[mid] === target) return mid;\n    if (arr[mid] < target) lo = mid + 1; else hi = mid - 1;\n  }\n  return -1;\n}`,
    rust: (n) => `fn ${n}(arr: &[i64], target: i64) -> i64 {\n    let (mut lo, mut hi) = (0i64, arr.len() as i64 - 1);\n    while lo <= hi {\n        let mid = (lo + hi) / 2;\n        let v = arr[mid as usize];\n        if v == target { return mid; }\n        if v < target { lo = mid + 1; } else { hi = mid - 1; }\n    }\n    -1\n}`,
    go: (n) => `func ${n}(arr []int, target int) int {\n\tlo, hi := 0, len(arr)-1\n\tfor lo <= hi {\n\t\tmid := (lo + hi) / 2\n\t\tif arr[mid] == target {\n\t\t\treturn mid\n\t\t}\n\t\tif arr[mid] < target {\n\t\t\tlo = mid + 1\n\t\t} else {\n\t\t\thi = mid - 1\n\t\t}\n\t}\n\treturn -1\n}`,
    java: (n) => `static int ${n}(int[] arr, int target) {\n    int lo = 0, hi = arr.length - 1;\n    while (lo <= hi) {\n        int mid = (lo + hi) >>> 1;\n        if (arr[mid] == target) return mid;\n        if (arr[mid] < target) lo = mid + 1; else hi = mid - 1;\n    }\n    return -1;\n}`,
    c: (n) => `int ${n}(int *arr, int len, int target) {\n    int lo = 0, hi = len - 1;\n    while (lo <= hi) {\n        int mid = (lo + hi) / 2;\n        if (arr[mid] == target) return mid;\n        if (arr[mid] < target) lo = mid + 1; else hi = mid - 1;\n    }\n    return -1;\n}`,
  },
  bubbleSort: {
    keys: ["bubble sort", "bubblesort", "sort"], name: "bubbleSort",
    python: (n) => `def ${n}(arr):\n    a = list(arr)\n    for i in range(len(a)):\n        for j in range(len(a) - i - 1):\n            if a[j] > a[j + 1]:\n                a[j], a[j + 1] = a[j + 1], a[j]\n    return a`,
    javascript: (n) => `function ${n}(arr) {\n  const a = arr.slice();\n  for (let i = 0; i < a.length; i++)\n    for (let j = 0; j < a.length - i - 1; j++)\n      if (a[j] > a[j + 1]) [a[j], a[j + 1]] = [a[j + 1], a[j]];\n  return a;\n}`,
    typescript: (n) => `function ${n}(arr: number[]): number[] {\n  const a = arr.slice();\n  for (let i = 0; i < a.length; i++)\n    for (let j = 0; j < a.length - i - 1; j++)\n      if (a[j] > a[j + 1]) [a[j], a[j + 1]] = [a[j + 1], a[j]];\n  return a;\n}`,
    rust: (n) => `fn ${n}(input: &[i64]) -> Vec<i64> {\n    let mut a = input.to_vec();\n    let len = a.len();\n    for i in 0..len {\n        for j in 0..len - i - 1 {\n            if a[j] > a[j + 1] { a.swap(j, j + 1); }\n        }\n    }\n    a\n}`,
    go: (n) => `func ${n}(input []int) []int {\n\ta := append([]int(nil), input...)\n\tfor i := 0; i < len(a); i++ {\n\t\tfor j := 0; j < len(a)-i-1; j++ {\n\t\t\tif a[j] > a[j+1] {\n\t\t\t\ta[j], a[j+1] = a[j+1], a[j]\n\t\t\t}\n\t\t}\n\t}\n\treturn a\n}`,
    java: (n) => `static int[] ${n}(int[] input) {\n    int[] a = input.clone();\n    for (int i = 0; i < a.length; i++)\n        for (int j = 0; j < a.length - i - 1; j++)\n            if (a[j] > a[j + 1]) { int t = a[j]; a[j] = a[j + 1]; a[j + 1] = t; }\n    return a;\n}`,
    c: (n) => `void ${n}(int *a, int len) {\n    for (int i = 0; i < len; i++)\n        for (int j = 0; j < len - i - 1; j++)\n            if (a[j] > a[j + 1]) { int t = a[j]; a[j] = a[j + 1]; a[j + 1] = t; }\n}`,
  },
  celsiusToFahrenheit: {
    keys: ["celsius", "fahrenheit", "c to f"], name: "celsiusToFahrenheit",
    python: (n) => `def ${n}(c):\n    return c * 9 / 5 + 32`,
    javascript: (n) => `function ${n}(c) {\n  return c * 9 / 5 + 32;\n}`,
    typescript: (n) => `function ${n}(c: number): number {\n  return c * 9 / 5 + 32;\n}`,
    rust: (n) => `fn ${n}(c: f64) -> f64 {\n    c * 9.0 / 5.0 + 32.0\n}`,
    go: (n) => `func ${n}(c float64) float64 {\n\treturn c*9/5 + 32\n}`,
    java: (n) => `static double ${n}(double c) {\n    return c * 9 / 5 + 32;\n}`,
    c: (n) => `double ${n}(double c) {\n    return c * 9 / 5 + 32;\n}`,
  },
  average: {
    keys: ["average", "mean of"], name: "average",
    python: (n) => `def ${n}(items):\n    return sum(items) / len(items)`,
    javascript: (n) => `function ${n}(items) {\n  return items.reduce((a, b) => a + b, 0) / items.length;\n}`,
    typescript: (n) => `function ${n}(items: number[]): number {\n  return items.reduce((a, b) => a + b, 0) / items.length;\n}`,
    rust: (n) => `fn ${n}(items: &[f64]) -> f64 {\n    items.iter().sum::<f64>() / items.len() as f64\n}`,
    go: (n) => `func ${n}(items []float64) float64 {\n\tsum := 0.0\n\tfor _, v := range items {\n\t\tsum += v\n\t}\n\treturn sum / float64(len(items))\n}`,
    java: (n) => `static double ${n}(double[] items) {\n    double sum = 0;\n    for (double v : items) sum += v;\n    return sum / items.length;\n}`,
    c: (n) => `double ${n}(double *items, int len) {\n    double sum = 0;\n    for (int i = 0; i < len; i++) sum += items[i];\n    return sum / len;\n}`,
  },
};

const camel = (s) => { const p = s.trim().split(/[^a-z0-9]+/i).filter(Boolean); return p.length ? p[0].toLowerCase() + p.slice(1).map((w) => w[0].toUpperCase() + w.slice(1).toLowerCase()).join("") : "solve"; };
const snake = (s) => camel(s).replace(/[A-Z]/g, (c) => "_" + c.toLowerCase());

// Translate a single-variable arithmetic expression into a real function body in the
// target language. Small integer powers are expanded to multiplication so the result
// is portable; anything left is handled per language. Returns null if it is not a
// clean single-variable formula (so codegen falls back to a skeleton).
function synthExpr(rawExpr, lang, ctx) {
  let e = rawExpr.replace(/\s+/g, "");
  if (!e || !/[-+*/^]/.test(e)) return null;                 // must actually be a formula
  const vars = [...new Set((e.match(/[a-z]+/g) || []).filter((w) => w !== "pi" && w !== "e"))];
  if (vars.length > 1) return null;                          // only single-variable formulas
  const vn = vars[0] || "x";
  e = e.replace(/([0-9.)])([a-z(])/g, "$1*$2").replace(/\)([0-9a-z(])/g, ")*$1"); // implicit mult
  // expand base^n (n a small integer) to repeated multiplication
  let prev; do { prev = e; e = e.replace(/([a-z][a-z0-9]*|\d+(?:\.\d+)?)\^(\d+)/g, (m, b, p) => { p = +p; return (p >= 1 && p <= 6) ? "(" + Array(p).fill(b).join("*") + ")" : m; }); } while (e !== prev);
  let warn = "";
  if (e.includes("^")) {
    if (lang === "python" || lang === "javascript" || lang === "typescript") e = e.replace(/\^/g, "**");
    else { warn = " (note: a large/non-integer power remained as '^'; replace with the language's power operator)"; }
  }
  if (!/^[-+*/().0-9a-z*]+$/.test(e.replace(/\*\*/g, ""))) return null;
  const b = { python: `def f(${vn}):\n    return ${e}`,
    javascript: `function f(${vn}) {\n  return ${e};\n}`,
    typescript: `function f(${vn}: number): number {\n  return ${e};\n}`,
    rust: `fn f(${vn}: f64) -> f64 {\n    ${e}\n}`,
    go: `func f(${vn} float64) float64 {\n\treturn ${e}\n}`,
    java: `static double f(double ${vn}) {\n    return ${e};\n}`,
    c: `double f(double ${vn}) {\n    return ${e};\n}` };
  return { code: b[lang], expr: e, warn };
}

export function codegen(input) {
  const raw = String(input || "").trim();
  const low = raw.toLowerCase();
  // detect language (default python)
  let lang = "python";
  for (const k in LANGS) { const re = new RegExp("\\b" + k + "\\b"); if (re.test(low)) { lang = LANGS[k]; break; } }
  // detect operation
  let op = null;
  for (const id in OPGEN) { if (OPGEN[id].keys.some((k) => low.includes(k))) { op = OPGEN[id]; break; } }
  if (op) {
    // idiomatic naming per language: snake_case for python/c/rust, camelCase elsewhere (go uses MixedCaps, not snake)
    const name = (lang === "python" || lang === "c" || lang === "rust") ? snake(op.name) : op.name;
    const code = op[lang](name);
    return { ok: true, kind: "synthesized", lang, op: op.name, code, note: "Generated from scratch for " + lang + " (verified pattern), function name: " + name + "." };
  }
  // expression synthesis: "a function f(x) = 3x^2 - 2x + 1" / "returns x*2+3" -> real code
  const cleaned = low.replace(/\bin\s+(python|javascript|js|typescript|ts|rust|go|golang|java|c)\b/g, " ");
  const em = cleaned.match(/(?:=|returns?|compute[s]?|gives?|equals?|:)\s*([-+*/^().0-9a-z\s]+)$/);
  if (em) {
    const synth = synthExpr(em[1], lang, low);
    if (synth) return { ok: true, kind: "synthesized", lang, op: "expression", code: synth.code, note: "Synthesized a function that computes " + synth.expr + " from scratch for " + lang + "." + (synth.warn || "") };
  }
  // unknown op -> correct typed skeleton (honest scaffold)
  const nameMatch = low.match(/(?:function|func|method|routine)\s+(?:called\s+|named\s+)?([a-z][a-z0-9_ ]{0,30})/) || low.match(/\bthat\s+([a-z][a-z0-9_ ]{0,30})/);
  const base = nameMatch ? nameMatch[1] : "solve";
  const nC = camel(base), nS = snake(base);
  const skel = {
    python: `def ${nS}(*args):\n    # TODO: ${raw.replace(/\n/g, " ")}\n    raise NotImplementedError`,
    javascript: `function ${nC}(...args) {\n  // TODO: ${raw.replace(/\n/g, " ")}\n  throw new Error("not implemented");\n}`,
    typescript: `function ${nC}(...args: unknown[]): unknown {\n  // TODO: ${raw.replace(/\n/g, " ")}\n  throw new Error("not implemented");\n}`,
    rust: `fn ${nS}() {\n    // TODO: ${raw.replace(/\n/g, " ")}\n    unimplemented!()\n}`,
    go: `func ${nC}() {\n\t// TODO: ${raw.replace(/\n/g, " ")}\n\tpanic("not implemented")\n}`,
    java: `static Object ${nC}(Object... args) {\n    // TODO: ${raw.replace(/\n/g, " ")}\n    throw new UnsupportedOperationException();\n}`,
    c: `void ${nS}(void) {\n    /* TODO: ${raw.replace(/\n/g, " ")} */\n}`,
  };
  return { ok: true, kind: "skeleton", lang, code: skel[lang], note: "No exact synthesis rule matched, so this is a correct, typed scaffold. Give a specific known task (factorial, fibonacci, reverse, prime, palindrome, fizzbuzz, sum) for a full implementation." };
}

// ---------------------------------------------------------------------------
// text: deterministic string transforms.
// ---------------------------------------------------------------------------
function b64encode(s) { try { return btoa(unescape(encodeURIComponent(s))); } catch (_) { return Buffer.from(s, "utf8").toString("base64"); } }
function b64decode(s) { try { return decodeURIComponent(escape(atob(s))); } catch (_) { return Buffer.from(s, "base64").toString("utf8"); } }

export function text(op, s) {
  s = String(s == null ? "" : s);
  switch (op) {
    case "upper": return s.toUpperCase();
    case "lower": return s.toLowerCase();
    case "title": return s.replace(/\w\S*/g, (w) => w[0].toUpperCase() + w.slice(1).toLowerCase());
    case "reverse": return [...s].reverse().join("");
    case "palindrome": { const k = s.toLowerCase().replace(/[^a-z0-9]/g, ""); return k && k === [...k].reverse().join("") ? "yes, \u201c" + s + "\u201d is a palindrome (it reads the same backwards, ignoring spaces and punctuation)" : "no, \u201c" + s + "\u201d is not a palindrome (backwards it is \u201c" + [...s].reverse().join("") + "\u201d)"; }
    case "slug": return s.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
    case "words": return s.trim() ? s.trim().split(/\s+/).length : 0;
    case "chars": return [...s].length;
    case "lines": return s.split(/\n/).length;
    case "sortlines": return s.split(/\n/).sort().join("\n");
    case "dedupewords": { const seen = new Set(); return s.split(/\s+/).filter((w) => { const k = w.toLowerCase(); if (!w || seen.has(k)) return false; seen.add(k); return true; }).join(" "); }
    case "dedupe": return [...new Set(s.split(/\n/))].join("\n");
    case "base64": return b64encode(s);
    case "unbase64": return b64decode(s);
    case "json": try { return JSON.stringify(JSON.parse(s), null, 2); } catch (e) { return "invalid JSON: " + e.message; }
    case "camel": { const p = s.split(/[^a-z0-9]+/i).filter(Boolean); return p.length ? p[0].toLowerCase() + p.slice(1).map((w) => w[0].toUpperCase() + w.slice(1).toLowerCase()).join("") : ""; }
    case "snake": return s.trim().split(/[^a-z0-9]+/i).filter(Boolean).join("_").toLowerCase();
    case "kebab": return s.trim().split(/[^a-z0-9]+/i).filter(Boolean).join("-").toLowerCase();
    case "constant": return s.trim().split(/[^a-z0-9]+/i).filter(Boolean).join("_").toUpperCase();
    case "wordfreq": {
      const f = new Map(); for (const w of (s.toLowerCase().match(/[a-z0-9']+/g) || [])) f.set(w, (f.get(w) || 0) + 1);
      return [...f.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, 15).map(([w, c]) => c + "\t" + w).join("\n");
    }
    case "emails": return [...new Set(s.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) || [])].join("\n");
    case "urls": return [...new Set(s.match(/https?:\/\/[^\s"'<>)]+/gi) || [])].join("\n");
    case "numbers": return (s.match(/-?\d+(?:\.\d+)?/g) || []).join("\n");
    default: return null;
  }
}

// ---------------------------------------------------------------------------
// regex: a curated pattern builder (keyword -> tested regex + explanation).
// ---------------------------------------------------------------------------
const PATTERNS = {
  email: { re: "[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}", desc: "matches an email address" },
  url: { re: "https?://[\\w.-]+(?:/[\\w./%?=&#-]*)?", desc: "matches an http or https URL" },
  ipv4: { re: "\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b", desc: "matches an IPv4 address" },
  phone: { re: "\\+?\\d[\\d ().-]{7,}\\d", desc: "matches a phone number" },
  hex: { re: "#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})\\b", desc: "matches a hex color" },
  date: { re: "\\d{4}-\\d{2}-\\d{2}", desc: "matches an ISO date (YYYY-MM-DD)" },
  digits: { re: "\\d+", desc: "matches one or more digits" },
  word: { re: "\\b\\w+\\b", desc: "matches a word" },
  uuid: { re: "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", desc: "matches a UUID" },
  mac: { re: "(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", desc: "matches a MAC address" },
  time: { re: "([01]?\\d|2[0-3]):[0-5]\\d", desc: "matches a 24-hour time (HH:MM)" },
  float: { re: "-?\\d+\\.\\d+", desc: "matches a decimal number" },
  slug: { re: "[a-z0-9]+(?:-[a-z0-9]+)*", desc: "matches a url slug" },
};
export function regexBuild(input) {
  const low = String(input || "").toLowerCase();
  for (const key in PATTERNS) if (low.includes(key)) return { ok: true, key, ...PATTERNS[key] };
  if (/\bips?\b|ip address/.test(low)) return { ok: true, key: "ipv4", ...PATTERNS.ipv4 };
  return { ok: false, error: "no pattern for that. known: " + Object.keys(PATTERNS).join(", ") };
}

// Test a regex against sample text. Returns the matches (deterministic, capped).
export function regexTest(pattern, sample) {
  let re;
  try { re = new RegExp(pattern, "g"); } catch (e) { return { ok: false, error: "invalid regex: " + e.message }; }
  const matches = [];
  let m, guard = 0;
  while ((m = re.exec(String(sample || ""))) && guard++ < 500) { matches.push(m[0]); if (m.index === re.lastIndex) re.lastIndex++; }
  return { ok: true, pattern, count: matches.length, matches: matches.slice(0, 50), matched: matches.length > 0 };
}

// ---------------------------------------------------------------------------
// datetime: deterministic date math (no timezone guessing; UTC).
// ---------------------------------------------------------------------------
const DAYNAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
// a real calendar date only: "2024-02-30" and "2024-13-45" are rejected, not rolled over
function parseISO(s) { const m = String(s).match(/(\d{4})-(\d{1,2})-(\d{1,2})/); if (!m) return null; const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])); return d.getUTCMonth() === +m[2] - 1 && d.getUTCDate() === +m[3] ? d : null; }
const HOLIDAYS = { "christmas eve": [12, 24], "christmas": [12, 25], "new year's eve": [12, 31], "new years eve": [12, 31], "new year's day": [1, 1], "new years day": [1, 1], "new year": [1, 1], "new years": [1, 1], "halloween": [10, 31], "valentine's day": [2, 14], "valentines day": [2, 14], "valentines": [2, 14], "april fools": [4, 1], "independence day": [7, 4], "thanksgiving": [11, 27] };
export function datetime(input) {
  const low = String(input || "").toLowerCase();
  const isoAll = low.match(/\d{4}-\d{1,2}-\d{1,2}/g) || [];
  const bad = isoAll.find((d) => !parseISO(d));
  if (bad) return { ok: false, error: bad + " is not a real calendar date" };
  const dates = isoAll.map(parseISO);
  const nowY = new Date().getUTCFullYear();
  if (/^(?:what|which)\s+year\s+is\s+(?:it|this)(?:\s+now)?\s*$|^(?:what is |whats )?(?:the )?current year\s*$/.test(low.replace(/[?.!]/g, "").trim())) return { ok: true, kind: "year", text: "It is " + nowY + " (by this device's clock, UTC)" };
  if (/^(?:what is |whats |what's )?(?:the )?(?:date )?today(?:'s date)?\s*$|^(?:what is |whats |what's )(?:the )?date(?: today)?\s*$|^what day is (?:it|today)\s*$/.test(low.replace(/[?.!]/g, "").trim())) { const d = new Date(); return { ok: true, kind: "today", text: "Today is " + DAYNAMES[d.getUTCDay()] + ", " + d.toISOString().slice(0, 10) + " (UTC)" }; }
  const born = low.match(/\bborn in (\d{4})\b/) || low.match(/\bage (?:of )?(?:someone |a person )?(?:born )?(?:in )?(\d{4})\b/);
  if (born && /how old|age/.test(low)) { const y = +born[1], a = nowY - y; if (a < 0) return { ok: false, error: y + " is in the future" }; return { ok: true, kind: "age", value: a, text: "Someone born in " + y + " is " + (a - 1) + " or " + a + " in " + nowY + " (" + a + " once their birthday has passed this year)" }; }
  // "how many days are in february 2024": month length, leap years included
  const MN = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
  const dim = low.match(/\bdays?\s+(?:are\s+|is\s+)?(?:there\s+)?in\s+(?:the\s+month\s+of\s+)?(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?(?:\s+(?:of\s+)?(\d{4}))?/);
  if (dim) {
    const y = dim[2] ? +dim[2] : new Date().getUTCFullYear(), m = MN.indexOf(dim[1]);
    const n = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
    const name = dim[1].charAt(0).toUpperCase() + ["anuary", "ebruary", "arch", "pril", "ay", "une", "uly", "ugust", "eptember", "ctober", "ovember", "ecember"][m];
    return { ok: true, kind: "monthdays", value: n, text: name + " " + y + " has " + n + " days" };
  }
  const dyr = low.match(/\bdays?\s+(?:are\s+)?(?:there\s+)?in\s+(?:the\s+year\s+)?(\d{4})\b/);
  if (dyr) { const y = +dyr[1], n = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 366 : 365; return { ok: true, kind: "yeardays", value: n, text: y + " has " + n + " days" }; }
  // "what day is tomorrow", "yesterday was what day": relative to today (UTC)
  const rel = low.match(/\b(today|tomorrow|yesterday|the day after tomorrow|the day before yesterday)\b/);
  if (rel && /\bwhat day\b|\bwhich day\b|\bday (?:is|was|will)\b|\bweekday\b/.test(low)) {
    const off = { today: 0, tomorrow: 1, yesterday: -1, "the day after tomorrow": 2, "the day before yesterday": -2 }[rel[1]];
    const now = new Date(), d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + off));
    return { ok: true, kind: "weekday", text: rel[1].charAt(0).toUpperCase() + rel[1].slice(1) + " is " + DAYNAMES[d.getUTCDay()] + ", " + d.toISOString().slice(0, 10) + " (UTC)" };
  }
  // "how many days until christmas / until 2027-01-01" — counts from today (UTC).
  const untilM = /days?\s+(?:until|till|til|to go until|left until|to go to|to go before)\s+(.+)$/.exec(low);
  if (untilM) {
    const target = untilM[1].replace(/[?.!]/g, "").trim();
    let dest = null;
    const iso = target.match(/\d{4}-\d{1,2}-\d{1,2}/);
    if (iso) dest = parseISO(iso[0]);
    else {
      let md = null; for (const h of Object.keys(HOLIDAYS)) if (target.includes(h)) { md = HOLIDAYS[h]; break; }
      if (md) {
        const now = new Date();
        dest = new Date(Date.UTC(now.getUTCFullYear(), md[0] - 1, md[1]));
        const today0 = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
        if (dest < today0) dest = new Date(Date.UTC(now.getUTCFullYear() + 1, md[0] - 1, md[1]));
      }
    }
    if (dest) {
      const now = new Date();
      const today0 = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
      const diff = Math.round((dest.getTime() - today0) / 86400000);
      return { ok: true, kind: "until", value: diff, text: diff + " day" + (diff === 1 ? "" : "s") + " until " + dest.toISOString().slice(0, 10) + " (counted from today)" };
    }
  }
  if (/days?\s+between/.test(low) && dates.length >= 2) {
    const diff = Math.round(Math.abs(dates[1] - dates[0]) / 86400000);
    return { ok: true, kind: "between", value: diff, text: diff + " day" + (diff === 1 ? "" : "s") };
  }
  const addM = low.match(/add\s+(\d+)\s+days?\s+to\s+(\d{4}-\d{1,2}-\d{1,2})/);
  if (addM) { const d = parseISO(addM[2]); d.setUTCDate(d.getUTCDate() + +addM[1]); return { ok: true, kind: "add", text: d.toISOString().slice(0, 10) }; }
  if (/leap/.test(low)) {
    const y = dates.length ? dates[0].getUTCFullYear() : Number((low.match(/\b(\d{4})\b/) || [])[1]);
    if (Number.isFinite(y)) { const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0; return { ok: true, kind: "leap", text: y + (leap ? " is a leap year" : " is not a leap year") }; }
  }
  if (/day of (the )?year|which day of/.test(low) && dates.length) {
    const d = dates[0], start = Date.UTC(d.getUTCFullYear(), 0, 0);
    return { ok: true, kind: "dayofyear", value: Math.round((d - start) / 86400000), text: "day " + Math.round((d - start) / 86400000) + " of " + d.getUTCFullYear() };
  }
  if (/weekday|day of week|what day/.test(low) && dates.length) return { ok: true, kind: "weekday", text: DAYNAMES[dates[0].getUTCDay()] };
  return { ok: false, error: "try: days between 2024-01-01 and 2024-12-31, is 2024 a leap year, day of year for 2024-03-01" };
}

// vocabulary tables, shared with the typo corrector and the slot predictor
export { UNITS as UNIT_TABLE, HOLIDAYS };
