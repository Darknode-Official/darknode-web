// Quelvra language engine: translates English math requests into Quelvra input text.
//
// It only TRANSLATES. It never computes an answer. Output:
//   { ok, math, goal, variable, interpretation, pattern, confidence, notes }
// or { ok: false, reason } when the sentence is not understood (it refuses to guess).
// The UI always shows `interpretation` so the user can see and correct what was understood.

import { parse, FUNCTIONS } from "./parse.js";

const NUMBER_WORDS = {
  zero: 0, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10,
  eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15, sixteen: 16, seventeen: 17, eighteen: 18, nineteen: 19,
  twenty: 20, thirty: 30, forty: 40, fifty: 50, sixty: 60, seventy: 70, eighty: 80, ninety: 90,
};
const SCALES = { hundred: 100, thousand: 1000, million: 1e6, billion: 1e9 };
const MULT_WORDS = { twice: 2, double: 2, triple: 3, thrice: 3, half: "1/2", quadruple: 4 };
const ORDINAL_DEN = { half: 2, halves: 2, third: 3, thirds: 3, quarter: 4, quarters: 4, fourth: 4, fourths: 4, fifth: 5, fifths: 5, sixth: 6, sixths: 6, eighth: 8, eighths: 8, tenth: 10, tenths: 10 };

// "twenty five" -> "25", "three hundred and two" -> "302", "two thirds" -> "(2/3)"
export function wordsToNumbers(s) {
  const toks = s.split(/(\s+|-)/);
  const out = [];
  let acc = null, cur = 0;
  const flush = () => { if (acc !== null || cur) { out.push(String((acc || 0) + cur), " "); } acc = null; cur = 0; };
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i], w = t.toLowerCase();
    if (/^\s+$|^-$/.test(t)) { if (acc === null && !cur) out.push(t); continue; }
    if (w in NUMBER_WORDS) { cur += NUMBER_WORDS[w]; continue; }
    if (w in SCALES && (cur || acc !== null)) { const sc = SCALES[w]; if (sc === 100) cur *= 100; else { acc = (acc || 0) + (cur || 1) * sc; cur = 0; } continue; }
    if (w === "and" && (cur || acc !== null) && toks[i + 2] && toks[i + 2].toLowerCase() in NUMBER_WORDS) continue;
    if (w in ORDINAL_DEN && (cur || acc !== null)) { const n = (acc || 0) + cur; acc = null; cur = 0; out.push(` (${n}/${ORDINAL_DEN[w]}) `); continue; }
    flush();
    out.push(t);
  }
  flush();
  return out.join("").replace(/\s+/g, " ").trim();
}

// Phrase-level operator translation (applied to already-numeric text).
const PHRASES = [
  [/\bthe square root of\b/g, "sqrt "], [/\bsquare root of\b/g, "sqrt "], [/\bcube root of\b/g, "cbrt "],
  [/\bthe (natural )?log(arithm)? of\b/g, "ln "], [/\bnatural log(arithm)? of\b/g, "ln "], [/\blog base (\S+) of\b/g, "log_$1 "],
  [/\babsolute value of\b/g, "abs "], [/\bthe factorial of\b/g, "factorial "],
  [/\b(\S+) squared\b/g, "($1)^2"], [/\b(\S+) cubed\b/g, "($1)^3"], [/\b(\S+) to the power of (\S+)/g, "($1)^($2)"], [/\b(\S+) raised to (the power )?(\S+)/g, "($1)^($3)"],
  [/\b(\S+) to the (\d+)(st|nd|rd|th)( power)?\b/g, "($1)^($2)"],
  [/\bplus\b/g, "+"], [/\bminus\b/g, "-"], [/\btimes\b/g, "*"], [/\bmultiplied by\b/g, "*"], [/\bdivided by\b/g, "/"], [/\bover\b/g, "/"],
  [/\bis greater than or equal to\b/g, ">="], [/\bis less than or equal to\b/g, "<="], [/\bis at least\b/g, ">="], [/\bis at most\b/g, "<="],
  [/\bis greater than\b/g, ">"], [/\bis less than\b/g, "<"], [/\bis more than\b/g, ">"], [/\bis not equal to\b/g, "!="],
  [/\bequals\b/g, "="], [/\bis equal to\b/g, "="], [/\bpi\b/g, "pi"], [/\bpercent\b/g, "%"],
  [/\bsine of\b/g, "sin "], [/\bcosine of\b/g, "cos "], [/\btangent of\b/g, "tan "], [/\bsin of\b/g, "sin "], [/\bcos of\b/g, "cos "], [/\btan of\b/g, "tan "],
  [/\bdegrees?\b/g, "°"],
];
function phrases(s) {
  let t = s;
  for (const [re, rep] of PHRASES) t = t.replace(re, rep);
  return t.replace(/\s+/g, " ").trim();
}

const MATHY = /^[\s\d.a-z+\-*/^()=<>!,|°%\[\]{}_'√πθ]*$/i;
const KNOWN_WORDS = new Set([...FUNCTIONS, "pi", "oo", "inf", "infinity", "int", "lim", "sum", "prod", "and", "or", "not", "theta", "alpha", "beta",
  "gamma", "lambda", "mu", "sigma", "phi", "omega", "delta", "km", "mi", "min", "log_2", "log_10", "arcsin", "arccos", "arctan"]);
// True when s is written in math notation: characters are mathematical, every word of three or
// more letters is a known function / constant, and the parser accepts it.
function looksLikeMath(s) {
  if (!MATHY.test(s)) return false;
  if (/\b(?:of|is|as|to|from|for|by|if|when|what|how|find|with|at|in|on)\b/i.test(s)) return false;
  // command words count as math only in call form: factor(x^2 - 1), not "factor x^2 - 1"
  if (/\b(?:solve|simplify|expand|factor|integrate|diff|derivative|plot|mean|median|mode|variance|stdev|gcd|lcm)\b(?!\()/i.test(s)) return false;
  const words = s.toLowerCase().match(/[a-z_0-9]*[a-z]{3,}[a-z_0-9]*/g) || [];
  if (words.map((w) => (/^log_/.test(w) ? w : w.replace(/_.*$/, ""))).some((w) => w && !KNOWN_WORDS.has(w) && !/^log_/.test(w) && !/^d[a-z]$/.test(w))) return false;
  try { parse(s); return true; } catch (_) { return false; }
}
const clean = (s) => s.replace(/[?.!]+$/, "").trim();

// Patterns: each returns a translation or null. Ordered from most to least specific.
const PATTERNS = [
  // ---- direct commands on math text ----
  { id: "derivative", re: /^(?:find |compute |what is )?(?:the )?(?:(second|third) )?derivative of (.+?)(?: with respect to ([a-z]))?$/i,
    build: (m) => { const ord = { second: 2, third: 3 }[m[1] && m[1].toLowerCase()] || 1; const v = m[3] || guessVar(m[2]);
      return { math: ord === 1 ? `d/d${v} (${expr(m[2])})` : `d^${ord}/d${v}^${ord} (${expr(m[2])})`, goal: "differentiate", variable: v, interpretation: `${ord > 1 ? ["", "", "second ", "third "][ord] : ""}derivative of ${expr(m[2])} with respect to ${v}` }; } },
  { id: "differentiate", re: /^differentiate (.+?)(?: with respect to ([a-z]))?$/i,
    build: (m) => { const v = m[2] || guessVar(m[1]); return { math: `d/d${v} (${expr(m[1])})`, goal: "differentiate", variable: v, interpretation: `derivative of ${expr(m[1])} with respect to ${v}` }; } },
  { id: "integral-def", re: /^(?:find |compute |evaluate )?(?:the )?(?:definite )?integral of (.+?) from (.+?) to (.+?)(?: with respect to ([a-z]))?$/i,
    build: (m) => { const v = m[4] || guessVar(m[1]); return { math: `integrate(${expr(m[1])}, ${v}, ${expr(m[2])}, ${expr(m[3])})`, goal: "integrate", variable: v, interpretation: `integral of ${expr(m[1])} from ${expr(m[2])} to ${expr(m[3])}` }; } },
  { id: "integral", re: /^(?:find |compute |evaluate )?(?:the )?(?:indefinite )?(?:integral|antiderivative) of (.+?)(?: with respect to ([a-z]))?$/i,
    build: (m) => { const v = m[2] || guessVar(m[1]); return { math: `integrate(${expr(m[1])}, ${v})`, goal: "integrate", variable: v, interpretation: `antiderivative of ${expr(m[1])} with respect to ${v}` }; } },
  { id: "integrate", re: /^integrate (.+?)(?: from (.+?) to (.+?))?(?: with respect to ([a-z]))?$/i,
    build: (m) => { const v = m[4] || guessVar(m[1]); return m[2] ? { math: `integrate(${expr(m[1])}, ${v}, ${expr(m[2])}, ${expr(m[3])})`, goal: "integrate", variable: v, interpretation: `integral of ${expr(m[1])} from ${expr(m[2])} to ${expr(m[3])}` }
      : { math: `integrate(${expr(m[1])}, ${v})`, goal: "integrate", variable: v, interpretation: `antiderivative of ${expr(m[1])}` }; } },
  { id: "limit", re: /^(?:find |compute |evaluate )?(?:the )?limit of (.+?) as ([a-z]) (?:approaches|goes to|tends to|->) (.+?)(?: from the (left|right|above|below))?$/i,
    build: (m) => { const side = m[4] ? (/(right|above)/i.test(m[4]) ? "^+" : "^-") : ""; const to = /infinity/i.test(m[3]) ? (/negative|minus/i.test(m[3]) ? "-oo" : "oo") : expr(m[3]);
      return { math: `lim_(${m[2]}->${to}${side}) (${expr(m[1])})`, goal: "limit", variable: m[2], interpretation: `limit of ${expr(m[1])} as ${m[2]} -> ${to}${side ? (side === "^+" ? " from the right" : " from the left") : ""}` }; } },
  { id: "percent-of", re: /^(?:what is |find |calculate )?(\S+?) ?(?:%|percent) of (\S+)$/i,
    build: (m) => ({ math: `${m[1]}/100 * ${m[2]}`, goal: "evaluate", interpretation: `${m[1]}% of ${m[2]}` }) },
  { id: "what-percent", re: /^(\S+) is what (?:%|percent) of (\S+)$/i,
    build: (m) => ({ math: `p/100 * ${m[2]} = ${m[1]}`, goal: "solve", variable: "p", interpretation: `find p with p% of ${m[2]} = ${m[1]}` }) },
  { id: "percent-change", re: /^(?:what is the )?percent(?:age)? (?:change|increase|decrease) from (\S+) to (\S+)$/i,
    build: (m) => ({ math: `(${m[2]} - ${m[1]})/${m[1]} * 100`, goal: "evaluate", interpretation: `100 (${m[2]} - ${m[1]})/${m[1]} percent` }) },
  { id: "gcd", re: /^(?:find |what is )?(?:the )?(?:gcd|gcf|hcf|greatest common (?:divisor|factor)) of (.+?)(?: and (.+))?$/i,
    build: (m) => ({ math: `gcd(${list(m[1], m[2])})`, goal: "evaluate", interpretation: `greatest common divisor of ${list(m[1], m[2])}` }) },
  { id: "lcm", re: /^(?:find |what is )?(?:the )?(?:lcm|least common multiple) of (.+?)(?: and (.+))?$/i,
    build: (m) => ({ math: `lcm(${list(m[1], m[2])})`, goal: "evaluate", interpretation: `least common multiple of ${list(m[1], m[2])}` }) },
  { id: "prime-factor", re: /^(?:find the )?prime factori[sz]ation of (\d+)$|^factori[sz]e (\d+)$/i,
    build: (m) => ({ math: `factorint(${m[1] || m[2]})`, goal: "evaluate", interpretation: `prime factorization of ${m[1] || m[2]}` }) },
  { id: "is-prime", re: /^is (\d+) (?:a )?prime(?: number)?$/i,
    build: (m) => ({ math: `isprime(${m[1]})`, goal: "evaluate", interpretation: `is ${m[1]} prime` }) },
  { id: "mean", re: /^(?:find |what is )?(?:the )?(mean|average|median|mode|variance|standard deviation) of (.+)$/i,
    build: (m) => { const f = { mean: "mean", average: "mean", median: "median", mode: "mode", variance: "variance", "standard deviation": "stdev" }[m[1].toLowerCase()];
      return { math: `${f}(${list(m[2])})`, goal: "evaluate", interpretation: `${m[1].toLowerCase()} of ${list(m[2])}` }; } },
  { id: "convert", re: /^convert (\S+) ?([a-z°/^0-9]+) (?:to|into|in) ([a-z°/^0-9]+)$/i,
    build: (m) => ({ math: `convert(${m[1]} ${m[2]}, ${m[3]})`, goal: "convert", interpretation: `${m[1]} ${m[2]} in ${m[3]}` }) },

  // ---- classic word problems (templates with explicit unknowns) ----
  { id: "number-plus", re: /^(?:a|some|the) number (?:plus|increased by|added to) (\S+) is (\S+)$/i,
    build: (m) => ({ math: `x + ${m[1]} = ${m[2]}`, goal: "solve", variable: "x", interpretation: `let x be the number: x + ${m[1]} = ${m[2]}` }) },
  { id: "number-minus", re: /^(?:a|some|the) number (?:minus|decreased by|less) (\S+) is (\S+)$/i,
    build: (m) => ({ math: `x - ${m[1]} = ${m[2]}`, goal: "solve", variable: "x", interpretation: `let x be the number: x - ${m[1]} = ${m[2]}` }) },
  { id: "k-times-number", re: /^(twice|double|triple|thrice|half|(\S+) times) (?:a|some|the) number (?:(plus|minus|increased by|decreased by) (\S+) )?(?:is|equals|gives) (\S+)$/i,
    build: (m) => { const k = MULT_WORDS[m[1].toLowerCase()] || m[2]; const op = m[3] ? (/plus|increased/i.test(m[3]) ? "+" : "-") : null;
      const lhs = `${paren(k)} x${op ? ` ${op} ${m[4]}` : ""}`;
      return { math: `${lhs} = ${m[5]}`, goal: "solve", variable: "x", interpretation: `let x be the number: ${lhs} = ${m[5]}` }; } },
  { id: "sum-difference", re: /^the sum of two numbers is (\S+) and their difference is (\S+)$/i,
    build: (m) => ({ math: `x + y = ${m[1]}, x - y = ${m[2]}`, goal: "solve", interpretation: `let the numbers be x >= y: x + y = ${m[1]}, x - y = ${m[2]}` }) },
  { id: "sum-product", re: /^the sum of two numbers is (\S+) and their product is (\S+)$/i,
    build: (m) => ({ math: `x + y = ${m[1]}, x*y = ${m[2]}`, goal: "solve", interpretation: `x + y = ${m[1]}, xy = ${m[2]}` }) },
  { id: "consecutive", re: /^the sum of (two|three|four|five|\d+) consecutive (even |odd )?integers is (\S+)$/i,
    build: (m) => { const n = +wordsToNumbers(m[1]); const step = m[2] ? 2 : 1; const terms = Array.from({ length: n }, (_, i) => (i ? `(n + ${i * step})` : "n")).join(" + ");
      return { math: `${terms} = ${m[3]}`, goal: "solve", variable: "n", interpretation: `let n be the smallest: ${terms} = ${m[3]}`, notes: ["Check that n is an integer" + (m[2] ? ` and ${m[2].trim()}` : "") + "."] }; } },
  { id: "distance", re: /^(?:a|the) (?:car|train|bike|runner|person|plane|boat) travels (\S+) ?(km|miles|m|mi) in (\S+) ?(hours?|h|minutes?|min|seconds?|s)(?:\.|,)? (?:what is|find) (?:its|the) (?:average )?speed$/i,
    build: (m) => ({ math: `${m[1]} ${unitOf(m[2])} / (${m[3]} ${unitOf(m[4])})`, goal: "evaluate", interpretation: `speed = distance / time = ${m[1]} ${m[2]} / ${m[3]} ${m[4]}` }) },
  { id: "simple-interest", re: /^(?:what is the )?simple interest on \$?(\S+) at (\S+) ?% (?:per year |a year |annually )?for (\S+) years?$/i,
    build: (m) => ({ math: `${m[1]} * ${m[2]}/100 * ${m[3]}`, goal: "evaluate", interpretation: `I = P r t = ${m[1]} * ${m[2]}% * ${m[3]}` }) },
  { id: "compound-interest", re: /^\$?(\S+) (?:is )?invested at (\S+) ?% (?:per year |a year |annually )?compounded (annually|monthly|quarterly|daily) for (\S+) years?(?:,)? (?:what is|find) the (?:final )?(?:amount|balance|value)$/i,
    build: (m) => { const n = { annually: 1, monthly: 12, quarterly: 4, daily: 365 }[m[3].toLowerCase()];
      return { math: `${m[1]} (1 + ${m[2]}/(100*${n}))^(${n}*${m[4]})`, goal: "evaluate", interpretation: `A = P (1 + r/n)^(n t) with P = ${m[1]}, r = ${m[2]}%, n = ${n}, t = ${m[4]}` }; } },
  { id: "rectangle", re: /^(?:a|the) rectangle has (?:a )?perimeter (?:of )?(\S+) and (?:its )?length is (\S+) more than (?:its )?width(?:\.|,)? find (?:the|its) dimensions$/i,
    build: (m) => ({ math: `2(w + ${m[2]}) + 2w = ${m[1]}`, goal: "solve", variable: "w", interpretation: `width w, length w + ${m[2]}: 2(w + ${m[2]}) + 2w = ${m[1]}` }) },
  { id: "age", re: /^(\w+) is (\S+) years older than (\w+)\. in (\S+) years,? (\w+) will be (twice|three times) as old as (\w+)\. how old is (\w+)(?: now)?$/i,
    build: (m) => { const k = /twice/i.test(m[6]) ? 2 : 3; const older = m[1], younger = m[3];
      const eqn = m[5].toLowerCase() === older.toLowerCase() ? `(y + ${m[2]}) + ${m[4]} = ${k}(y + ${m[4]})` : `y + ${m[4]} = ${k}((y + ${m[2]}) + ${m[4]})`;
      return { math: eqn, goal: "solve", variable: "y", interpretation: `let y be ${younger}'s age now (${older} is y + ${m[2]}): ${eqn}` }; } },

  // ---- generic verbs in front of math ----
  { id: "solve-for", re: /^(?:solve|find) (.+?) for ([a-z])$/i, build: (m) => ({ math: expr(m[1]), goal: "solve", variable: m[2], interpretation: `solve ${expr(m[1])} for ${m[2]}` }) },
  { id: "solve", re: /^(?:solve|find ([a-z]) (?:if|when|given|such that)) (.+)$/i, build: (m) => ({ math: expr(m[2]), goal: "solve", variable: m[1], interpretation: `solve ${expr(m[2])}` }) },
  { id: "simplify", re: /^(simplify|expand|factor|factorise|factorize) (.+)$/i, build: (m) => { const g = m[1].toLowerCase().replace(/is[e]$|iz[e]$/, "").replace(/^factor.*/, "factor"); return { math: `${g}(${expr(m[2])})`, goal: g, interpretation: `${g} ${expr(m[2])}` }; } },
  { id: "evaluate", re: /^(?:what is|what's|calculate|compute|evaluate|find the value of|how much is) (.+)$/i, build: (m) => ({ math: expr(m[1]), goal: "evaluate", interpretation: expr(m[1]) }) },
  { id: "plot", re: /^(?:plot|graph|draw|sketch) (?:the graph of )?(.+)$/i, build: (m) => ({ math: expr(m[1]), goal: "plot", interpretation: `graph of ${expr(m[1])}` }) },
];

function expr(s) { return phrases(wordsToNumbers(s)).replace(/^\s*the\s+/i, ""); }
function list(a, b) { return [a, b].filter(Boolean).join(",").split(/\s*(?:,|\band\b)\s*/).map((t) => expr(t)).filter(Boolean).join(", "); }
function paren(k) { return /^\d+$/.test(String(k)) ? String(k) : `(${k})`; }
function unitOf(u) { return { km: "km", miles: "mi", mi: "mi", m: "m", hours: "h", hour: "h", h: "h", minutes: "min", minute: "min", min: "min", seconds: "s", second: "s", s: "s" }[u.toLowerCase()] || u; }
// the variable of an expression: its free symbols from the parse tree (so e, pi and i, which are
// constants, never qualify), preferring x, then t, y, z
function guessVar(s) {
  const found = new Set();
  const walk = (u) => { if (!u) return; if (u.k === "sym") found.add(u.name); for (const a of u.args || []) walk(a); };
  try { walk(parse(expr(s))); } catch (_) { const m = expr(s).match(/\b([a-df-hj-z])\b/i); return m ? m[1] : "x"; }
  for (const v of ["x", "t", "y", "z", "u", "v", "theta", "s", "n"]) if (found.has(v)) return v;
  return [...found].sort()[0] || "x";
}

// Main entry.
export function translate(input) {
  const raw = clean(String(input || "").replace(/\s+/g, " "));
  if (!raw) return { ok: false, reason: "empty input" };
  // Already math: nothing to translate.
  if (looksLikeMath(raw)) return { ok: true, math: raw, goal: null, interpretation: raw, pattern: "math", confidence: 1, notes: [] };
  const lower = raw.replace(/^(?:please |can you |could you |help me )+/i, "");
  for (const p of PATTERNS) {
    const m = lower.match(p.re);
    if (!m) continue;
    const r = p.build(m);
    if (!r || !r.math) continue;
    const mathOk = looksLikeMath(r.math);
    if (!mathOk) return { ok: false, reason: `Understood the request as "${p.id}", but part of it is not recognisable math: "${r.math}". Please rewrite it using symbols.`, pattern: p.id };
    return { ok: true, pattern: p.id, confidence: p.id === "evaluate" || p.id === "solve" ? 0.9 : 0.95, notes: [], ...r };
  }
  // last resort: word-to-symbol translation only if the result is pure math
  const t = expr(lower);
  if (looksLikeMath(t)) return { ok: true, math: t, goal: null, interpretation: t, pattern: "phrases", confidence: 0.75, notes: ["Translated word by word; check the interpretation."] };
  return { ok: false, reason: "This sentence did not match any problem pattern Quelvra knows, so it will not guess. Try writing the equation directly, for example: 2x + 3 = 11." };
}
