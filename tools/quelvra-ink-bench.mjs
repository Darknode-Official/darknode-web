// Handwriting accuracy bench for Quelvra's stroke recogniser.
//
//   node tools/quelvra-ink-bench.mjs [-v] [--seed N]
//
// Synthesizes handwriting from the glyph geometry with a DIFFERENT seed than the built-in
// templates, then adds the habits real writers have that the templates do not show directly:
//   * joined strokes: the pen is not lifted between two strokes of one symbol ("x" as a loop,
//     "4" / "t" / "π" in one go), so the symbol arrives with fewer strokes than any template;
//   * a different stroke order and direction inside a symbol;
//   * messier writing (more rotation, shear, wobble and size variation).
// Reports single-symbol top-1 / top-3 and whole-expression exact match, plus SILENT errors:
// a wrong reading where no symbol was flagged as uncertain (the worst kind, since the reader
// is not asked to check it).
import { VARIANTS } from "../public/quelvra/engine/vision/glyphs.js";
import { distortStrokes, synthesizeStrokes } from "../public/quelvra/engine/vision/strokes.js";
import { recognizeStrokes } from "../public/quelvra/engine/vision/index.js";

const args = process.argv.slice(2);
const verbose = args.includes("-v");
const seedArg = args.indexOf("--seed");
const SEED = seedArg >= 0 ? Number(args[seedArg + 1]) : 99;

function mulberry(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const R = mulberry(SEED);

const LEVELS = {
  neat: { rot: 4, shear: 0.08, aniso: 0.08, jitter: 0.008, wobble: 0.015 },
  normal: { rot: 7, shear: 0.14, aniso: 0.12, jitter: 0.012, wobble: 0.022 },
  messy: { rot: 11, shear: 0.2, aniso: 0.18, jitter: 0.016, wobble: 0.032 },
};

// Pen habits applied to one symbol's strokes (pixel strokes, in writing order).
function habits(strokes, rand, { join = 0, shuffle = 0 } = {}) {
  let s = strokes.map((st) => st.slice());
  if (s.length > 1 && rand() < shuffle) s = s.map((st, i) => [rand(), st]).sort((a, b) => a[0] - b[0]).map((p) => p[1]);
  if (s.length > 1 && rand() < join) {
    // lift-free writing: connect each stroke's end to the next stroke's start
    const joined = [];
    for (const st of s) {
      if (joined.length) {
        const a = joined[joined.length - 1], b = st[0];
        const n = Math.max(2, Math.round(Math.hypot(b.x - a.x, b.y - a.y) / 2));
        for (let k = 1; k < n; k++) joined.push({ x: a.x + ((b.x - a.x) * k) / n, y: a.y + ((b.y - a.y) * k) / n });
      }
      joined.push(...st);
    }
    s = [joined];
  }
  return s;
}

// dots and "=" are not written lift-free ("=" joined is a "z")
const NEVER_JOINED = new Set(["=", "÷", "i", "j", "!", "≤", "≥"]);

// ---------------------------------------------------------------------------------------------
function symbolBench(level, habit) {
  let n = 0, top1 = 0, top3 = 0;
  const miss = {};
  for (const [ch, vs] of Object.entries(VARIANTS)) for (const v of vs) for (let k = 0; k < 3; k++) {
    const em = 28 + R() * 44;
    const raw = distortStrokes(v.strokes, R, { em, x: 80 + R() * 200, y: 150 + R() * 100, ...LEVELS[level] });
    const strokes = habits(raw, R, habit);
    if (habit.join && (strokes.length === raw.length || NEVER_JOINED.has(ch))) continue; // only symbols the habit changed and people do join
    const r = recognizeStrokes(strokes, { em });
    n++;
    const s = r.symbols.length === 1 ? r.symbols[0] : null;
    const cands = s ? [s.char, ...s.alternatives.map((a) => a.char)] : [];
    if (cands[0] === ch) top1++; else { const key = ch + "->" + (s ? s.char : r.symbols.map((q) => q.char).join("")); miss[key] = (miss[key] || 0) + 1; }
    if (cands.slice(0, 3).includes(ch)) top3++;
  }
  return { n, top1: top1 / n, top3: top3 / n, miss };
}

// Expressions: [typeset spec, expected text]. Specs use only glyphs that exist; the bench skips
// (and counts) any whose glyphs are missing, so it runs before and after new symbols are added.
const EXPRS = [
  ["2x+3=11", "2x+3=11"], [["x", { sup: "2" }, "-4=0"], "x^(2)-4=0"], [{ frac: ["1", "2"] }, "(1)/(2)"],
  ["y=3x-7", "y=3x-7"], [[{ sqrt: "x+1" }], "sqrt(x+1)"], ["a+b=c", "a+b=c"], ["7-2n", "7-2n"],
  [["e", { sup: "x" }], "e^(x)"], ["(x+1)(x-2)", "(x+1)(x-2)"], ["4t+9", "4t+9"], ["3.5x", "3.5x"],
  ["sin(x)", "sin(x)"], ["cos(2x)", "cos(2x)"], ["tan(x)", "tan(x)"], ["log(x)", "log(x)"], ["ln(x)", "ln(x)"],
  ["f(x)=x+1", "f(x)=x+1"], ["g(t)=2t", "g(t)=2t"], ["k+m=5", "k+m=5"], ["r=2", "r=2"], ["p-q", "p-q"],
  ["2π", "2π"], ["u+v", "u+v"], ["w=h+1", "w=h+1"], ["3s+4", "3s+4"], [["sin(x)", { sup: "2" }], "sin(x)^(2)"],
  ["6×7", "6×7"], ["x*y", "x*y"], [["sin(θ)"], "sin(θ)"], ["x≤9", "x≤9"],
];
const has = (s) => [...String(s)].every((c) => VARIANTS[c]);
function specChars(spec) {
  if (typeof spec === "string") return spec;
  if (Array.isArray(spec)) return spec.map(specChars).join("");
  if (spec.sup) return specChars(spec.sup);
  if (spec.sub) return specChars(spec.sub);
  if (spec.frac) return spec.frac.map(specChars).join("");
  if (spec.sqrt) return specChars(spec.sqrt);
  if (spec.glyph) return spec.glyph;
  return "";
}
// what the recogniser should output for a spec (display glyphs map to parser text)
const OUT = { "×": "*", "π": "pi", "θ": "theta", "≤": "<=" };
const expectText = (t) => [...t].map((c) => OUT[c] ?? c).join("");

function exprBench(level, habit, N = 5) {
  let n = 0, exact = 0, silent = 0, skipped = 0;
  const wrong = [];
  for (const [spec, want] of EXPRS) {
    if (!has(specChars(spec))) { skipped++; continue; }
    for (let k = 0; k < N; k++) {
      const { strokes, truth } = synthesizeStrokes(spec, R, { em: 30 + R() * 30, ...LEVELS[level] });
      // apply habits per glyph
      const out = [];
      for (const g of truth) out.push(...habits(g.strokeIds.map((i) => strokes[i]), R, NEVER_JOINED.has(g.char) ? { ...habit, join: 0 } : habit));
      const r = recognizeStrokes(out);
      n++;
      const target = expectText(want);
      const got = r.text.replace(/\s+/g, "");
      if (got === target.replace(/\s+/g, "")) exact++;
      else {
        if (!r.lowConfidence.length && r.parseable) silent++; // unparseable text is reported, not trusted
        const isSilent = !r.lowConfidence.length && r.parseable;
        if (wrong.length < 40) wrong.push(want + " => " + r.text + (isSilent ? "  [SILENT]" + (verbose ? "  " + r.symbols.map((q) => q.char + ":" + q.confidence.toFixed(2) + "[" + q.alternatives.map((a) => a.char + a.score.toFixed(2)).join(",") + "]").join(" ") : "") : ""));
      }
    }
  }
  return { n, exact: exact / n, silent, skipped, wrong };
}

const pct = (x) => (100 * x).toFixed(1) + "%";
const rows = [];
for (const level of ["neat", "normal", "messy"]) {
  const plain = symbolBench(level, {});
  const joined = symbolBench(level, { join: 1 });
  const order = symbolBench(level, { shuffle: 1 });
  rows.push(["symbols " + level, `top1 ${pct(plain.top1)} top3 ${pct(plain.top3)} (n=${plain.n})`]);
  rows.push(["  joined strokes", `top1 ${pct(joined.top1)} top3 ${pct(joined.top3)} (n=${joined.n})`]);
  rows.push(["  shuffled order", `top1 ${pct(order.top1)} top3 ${pct(order.top3)} (n=${order.n})`]);
  if (verbose) {
    const top = (m) => Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, v]) => k + "x" + v).join(" ");
    rows.push(["    misses", top(plain.miss)]);
    rows.push(["    joined misses", top(joined.miss)]);
  }
}
for (const level of ["neat", "normal"]) {
  const e = exprBench(level, {});
  const h = exprBench(level, { join: 0.35, shuffle: 0.35 });
  rows.push(["exprs " + level, `exact ${pct(e.exact)} silent-wrong ${e.silent} (n=${e.n}, skipped specs ${e.skipped})`]);
  rows.push(["  with pen habits", `exact ${pct(h.exact)} silent-wrong ${h.silent} (n=${h.n})`]);
  if (verbose) for (const w of [...e.wrong, ...h.wrong].slice(0, 60)) rows.push(["    ", w]);
}
for (const [a, b] of rows) console.log(a.padEnd(20) + b);
