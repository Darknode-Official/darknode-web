// Universal Engine — orchestrator. Predicts which skill a request wants (ranked,
// with confidence and alternatives = "predictive thinking"), runs the deterministic
// skill, and composes a full written answer that only states what it can back up.
// No AI: routing is scored pattern rules, answers are templated over real results.
import * as S from "/js/engine/skills.js";
import * as A from "/js/engine/advanced.js";
import * as D from "/js/engine/data.js";
import * as M from "/js/engine/more.js";
import { predictNext, complete, confidence as predConf, suggestWord, train, learn } from "/js/engine/predict.js";
import { mathPhrase, hasMathPhrase, numberWords, numberToWords, synonyms, naturalize, UNIT_WORDS } from "/js/engine/nlp.js";
import * as MX from "/js/engine/matrix.js";
import { unitMath } from "/js/engine/units.js";
import { synth, parseSpec } from "/js/engine/synth.js";
import * as F from "/js/engine/facts.js";
import * as H from "/js/engine/hash.js";
import { makeLexicon, withDictionary, withContext, rankFixes, isWord, correctText, correctWord, typoDistance, fuzzyPrefix } from "/js/engine/spell.js";
import { words as englishWords, band as wordBand } from "/js/engine/words.js";

// --- typo tolerance: nudge a near-miss command word to its canonical spelling ---
// This runs ONLY over the text used for routing, never over the payload a skill
// operates on, so it makes intent detection forgiving of misspellings ("convrt",
// "genarate", "revrse") without ever altering the user's actual content.
const KW = ["what", "calculate", "compute", "evaluate", "convert", "generate", "write", "implement", "function", "reverse", "uppercase", "lowercase", "fibonacci", "factorial", "palindrome", "fizzbuzz", "binary", "search", "bubble", "sort", "average", "median", "variance", "solve", "stats", "statistics", "factorize", "prime", "encode", "decode", "base64", "hexadecimal", "octal", "roman", "color", "json", "query", "weekday", "complete", "predict", "continue", "explain", "define", "regex", "email", "emails", "url", "urls", "number", "numbers", "celsius", "fahrenheit", "analyze", "summarize", "kebab", "camel", "snake", "constant", "slug", "dedupe", "frequency", "between", "total", "altogether", "combined", "difference", "remaining", "python", "javascript", "typescript", "rust", "golang", "java",
  // domain vocabulary protected as fixed points (never "corrected" into a keyword)
  "product", "matrix", "matrices", "determinant", "transpose", "vector", "vectors", "dot", "cross", "inverse", "union", "intersection", "sequence", "series", "progression", "combination", "combinations", "permutation", "permutations", "probability", "choose", "truth", "table", "discount",
  "sqrt", "cbrt", "root", "square", "squared", "cube", "cubed", "capital", "element", "atomic", "factor", "factors", "multiple", "multiples",
  // math verbs: "multiply" is one letter from "multiple", "divide" from "divine"...
  "multiply", "multiplied", "divide", "divided", "subtract", "subtracted", "plus", "minus", "times", "percent", "power", "double", "triple", "halve", "round",
  "rot", "sha", "tip", "mod", "vowel", "vowels", "consonants", "negative"];
const KWSET = new Set(KW);
function editDist(a, b) {
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > 2) return 3;
  const d = [];
  for (let i = 0; i <= m; i++) { d[i] = [i]; }
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++)
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[m][n];
}
function normalizeTypos(text) {
  return text.replace(/[a-z]{3,}/gi, (w) => {
    const lw = w.toLowerCase();
    if (KWSET.has(lw)) return w;
    let best = "", bd = 99;
    for (const k of KW) { const dd = editDist(lw, k); if (dd < bd) { bd = dd; best = k; } }
    const thr = lw.length <= 6 ? 1 : 2;
    return (best && bd > 0 && bd <= thr) ? best : w;
  });
}

const numCountOf = (t) => (t.match(/\d[\d,]*(?:\.\d+)?/g) || []).length;
// --- intent scoring: each rule adds evidence for a skill; we return a ranking. ---
function score(input) {
  const s = String(input || "").trim();
  // routing text: expand spelled-out numbers, canonicalize phrasings, fix typos.
  // This is used only to DETECT intent; skills receive the original input.
  const low = normalizeTypos(synonyms(numberWords(naturalize(s))));
  const has = (re) => re.test(low);
  const S0 = { calc: 0, convert: 0, codegen: 0, text: 0, regex: 0, datetime: 0, predict: 0, stats: 0, algebra: 0, numbertheory: 0, encode: 0, knowledge: 0, facts: 0, data: 0, base: 0, color: 0, jsonquery: 0, wordmath: 0, sequence: 0, logic: 0, setops: 0, matrix: 0, units: 0, combinatorics: 0, listops: 0, spelling: 0 };
  const why = {};
  const add = (k, n, reason) => { S0[k] += n; if (reason && (!why[k] || n > 0)) why[k] = reason; };
  // a code request needs a real code verb or an explicit "in <language>" — NOT the
  // bare noun "function", which also appears in prose like "what is a hash function".
  const codeAsk = has(/\b(code|implement|generate|write|refactor|coding|snippet)\b/) || has(/\bin\s+(python|javascript|js|typescript|ts|rust|go|golang|java|c)\b/) ||
    has(/\b(python|javascript|typescript|rust|golang|java|js|ts)\s+(function|func|method|class|program|script|snippet|one-?liner)\b/);
  // a broader "build something" intent — used only to route clearly-code requests,
  // not to over-claim (a whole app/game is handled honestly as out of scope).
  const buildAsk = has(/\b(make|build|create|develop|generate|write|implement|code|program)\b/);
  // "how do i / how to ..." is a how-to; with an algorithm keyword it means code.
  const howTo = has(/\bhow (?:do|to|can|would|should)\b/);
  const isDef = has(/^(what\s+(is|are)|define|explain|tell me about)\b/); // a definition question

  // explicit numeric conversion ("5 miles in km") outranks a definition question;
  // the bare "convert" verb is a weaker signal.
  if (has(/-?\d+(?:\.\d+)?\s*[a-z°/]+\s+(?:to|in|into|as)\s+[a-z°/]+/) && !has(/\d\s*[a-z]+\s*[+\-]\s*\d/) && !has(/\b0[xbo][0-9a-f]+\b/)) add("convert", 8, "a unit conversion"); // not unit arithmetic like "5 km + 300 m"
  else if (has(/\bconvert\b/) && !has(/\b(camel|snake|kebab|constant|title) ?case\b|uppercase|lowercase|\bslug/)) add("convert", 6, "looks like a unit conversion"); // "convert x to camel case" is a text transform
  if (has(/regex|regular expression|pattern for|pattern to match|test.*\/.*\/|\/.+\/\s+(on|against)/)) add("regex", 6, "asks for a regular expression");
  // number base + roman numerals (before convert, which is for physical units)
  if (has(/\b(to|in|into|as)\s+(hex\w*|bin\w*|oct\w*|dec\w*|roman|base\s*\d+)\b/) || has(/roman numeral|\bfrom roman\b/)) add("base", 8, "number base conversion");
  // tabular data / CSV
  if (has(/\bcsv\b|\bdataset\b|analy[sz]e.*(data|table|csv|column)|per[- ]?column|columns?\b/) || (/\n/.test(s) && /,[^,\n]*,/.test(s.split("\n")[0]))) add("data", 7, "tabular data analysis");
  // color conversion — an explicit color literal outranks a plain "to hex" base request
  if (has(/#[0-9a-f]{3,6}\b|rgba?\s*\(|hsl\s*\(/)) add("color", 9, "color conversion");
  else if (has(/\bcolou?r\b|to (rgb|hsl|hex)\b/)) add("color", 7, "color conversion");
  // JSON path query (a JSON blob plus a path or a get/query verb)
  if (/[[{][\s\S]*[\]}]/.test(s) && (has(/\b(get|query|path|value of|field|extract)\b/) || /\.[a-z_$]/i.test(s))) add("jsonquery", 8, "JSON path query");
  if (has(/days? between|day of (the )?week|weekday|what day|add \d+ days?|leap\s*year|day of (the )?year|which day of|days?\s+(?:until|till|til|to go|left)/)) add("datetime", 6, "date arithmetic")
  if (has(/\bdays?\s+(?:are\s+|is\s+)?(?:there\s+)?in\s+(?:the\s+(?:month|year)\s+(?:of\s+)?)?(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|\d{4}\b)/)) add("datetime", 8, "days in a month or year");
  const algoKW = has(/factorial|fibonacci|fib|reverse|prime|palindrome|fizzbuzz|binary search|bubble sort|\bsort\b|\bsearch\b|\bgcd\b|average|function|func|method|class/);
  const langKW = has(/\b(python|javascript|js|typescript|ts|rust|go|golang|java|c)\b/);
  // Route to code synthesis for an algorithm or a language-tagged function — but a
  // whole app/game noun without an algorithm keyword is out of scope, so skip it.
  if ((codeAsk || buildAsk || howTo) && (algoKW || (langKW && !APP_NOUN.test(low))))
    add("codegen", 7, "asks to generate code");
  // a well-formed function spec ("name(args) = body", "... that returns <expr>")
  // is synthesizable on its own, even without a verb like "write" or "generate".
  else if (parseSpec(s)) add("codegen", 7, "a function specification to synthesize");
  if (has(/uppercase|lowercase|\breverse\b|spell.*backwards|title case|camel ?case|snake ?case|kebab ?case|constant case|slug|word frequency|count (the )?words|word count|how many words|count (the )?(characters|letters)|how many (characters|letters|chars)|number of (characters|letters|words)|sort lines|dedupe|pretty ?print|format json|extract (emails?|urls?|links?|numbers?)|\bvowels?\b|\bconsonants?\b/))
    add("text", 6, "text transform");
  if (has(/complete|continue|predict|next word|finish (this|the) sentence|autocomplete/)) add("predict", 6, "asks for a prediction");
  // statistics
  if (has(/\bstats?\b|\bmean\b|\bmedian\b|\baverage\b|standard deviation|std ?dev|variance|quartile/) && has(/\d[ ,].*\d/)) add("stats", 7, "statistics over a list");
  // algebra: an equation with a variable (distinct from a bare calc assignment like x=5)
  if (!codeAsk && !has(/base64|\bencode|\bdecode|rot13|\bhex\b|\bhash\b|md5|\bsha/) && (has(/\bsolve\b/) || (has(/=/) && (has(/\d\s*[a-z]/) || has(/[a-z]\s*\^/))))) add("algebra", 8, "an equation to solve");
  // number theory (asking for a value, not code)
  if (!codeAsk && has(/factori[sz]e|prime factor|\bfactors?\s+of\b|\bfactor\s+\d|\bgcd\b|\blcm\b|greatest common|least common|is\s+\d+\s+prime|\d+(?:st|nd|rd|th)\s+(?:prime|fib)|nth\s+(?:prime|fib)|\bfirst\s+\d+\s+primes?\b|\bprimes?\s+(?:below|under|less than|up to)\s+\d/)) add("numbertheory", 7, "number theory");
  // encoding / hashing
  if (!isDef && has(/base64|\bhex\b|rot13|morse|url ?(en|de)code|to binary|from binary|crc32|fnv1a?|djb2|\bhash\b|\bmd5\b|\bsha-?(?:1|256)?\b/)) add("encode", 7, "encode / hash");
  // knowledge base (a definition question that is not math, code, or number theory)
  if (isDef && !codeAsk && !hasMathPhrase(low) && !has(/[-+*/^]/) && !has(/\d[a-z]/) && !has(/\b(sqrt|cbrt|max|min|round|abs|log|ln|sin|cos|tan)\s*\(/)) add("knowledge", 7, "a definition from the glossary");
  // fact packs: capitals, elements, constants — triggered by a domain keyword
  if (has(/\bcapital\b|\bcapital city\b/)) add("facts", 8, "country capital lookup");
  if (has(/\belement\b|\batomic\b|\bperiodic\b|\bchemical\b/) && !codeAsk) add("facts", 8, "periodic table lookup");
  if (has(/\bspeed of light\b|\bplanck\b|\bavogadro\b|\bboltzmann\b|\bgravitational constant\b|\bbohr\b|\bstefan.boltzmann\b|\bfine structure\b|\bearth mass\b|\bsolar mass\b|\blight year\b|\bparsec\b|\bstandard gravity\b|\bgas constant\b/)) add("facts", 9, "physical/mathematical constant");
  else if (has(/\bconstant\b/) && !has(/constant ?case/) && !codeAsk) add("facts", 7, "physical/mathematical constant");
  // "what is gold" / "what is pi": answer from a fact pack, but only when the
  // glossary has no entry of its own (a curated definition wins) and the subject
  // is not a lone letter ("what is c" is more likely the language than a constant).
  else if (!isDef && !codeAsk && numCountOf(low) === 0 && F.constant(s).ok && F.constant(s).name.length >= 4) add("facts", 7, "a named constant");
  else if (isDef && !codeAsk && (!has(/^what\s+(is|are)\s+[a-z]\s*\??$/) || /^what\s+(?:is|are)\s+(?:e|[ABD-Z][a-z]?)\s*\??$/.test(s)) && !has(/\d\s*[-+*/^]\s*\d/) && F.facts(s).ok && !A.lookup(s).ok) add("facts", 8, "a curated fact");
  const numCount = (low.match(/\d[\d,]*(?:\.\d+)?/g) || []).length;
  // linear algebra: a matrix literal [[...]], or a vector op named explicitly
  if (/\[\s*\[/.test(s) || has(/\bmatrix\b|matrices|determinant|transpose|dot product|cross product|scalar product|magnitude|\bnorm\b/) || (/\[\s*-?\d[^\]]*\]/.test(s) && has(/\bvector\b|dot|cross|magnitude|\bnorm\b|length of/))) add("matrix", 8, "linear algebra");
  // unit-aware arithmetic: two quantities with recognized units joined by +/-
  if (!/\[/.test(s) && !/\d{4}-\d{1,2}-\d{1,2}/.test(s) && /[+\-]/.test(s) && /\b(mm|cm|m|km|in|ft|yd|mi|miles?|inch|inches|feet|foot|met(er|re)s?|kg|mg|g|lbs?|oz|tonnes?|ms|secs?|seconds?|mins?|minutes?|hrs?|hours?|days?|weeks?|[kmgt]b|bytes?)\b/.test(low) && /\d\s*[a-z]/.test(low)) add("units", 7, "unit-aware arithmetic");
  // combinatorics / probability
  if (has(/\bchoose\b|combinations?|permutations?|\bpermute\b|\bncr\b|\bnpr\b|ways to (arrange|order)|arrangements? of|\bprobability\b|\bodds\b|\bchance\b/)) add("combinatorics", 7, "combinatorics / probability");
  // spelling: "how do you spell recieve", "spell check: ...", "spell out 1234"
  if (has(/\bhow (?:do|would|should|can|is) (?:you |i |u |we |it )?spell|^(?:please )?spell\b|spell ?check|spellcheck|proofread|check (?:the |my )?spelling|fix (?:the |my )?spelling|correct (?:the )?spelling|\bspelling of\b|\bspell(?:ed|t) (?:right|correctly|properly|wrong)|\bspell out\b|^(?:is it|which is (?:correct|right|it))[,:]?\s+[a-z]+\s+or\s+[a-z]+\s*\??$/)) add("spelling", 9, "a spelling question");
  // sorting a list of values ("sort 5 3 9", "put these in order: 4 1 3", "alphabetize pear apple fig")
  if (!codeAsk && !has(/ways to|\bsort lines\b/) && ((numCount >= 2 && has(/\b(sort|order|rank|arrange|ascending|descending)\b/)) || has(/\balphabeti[sz]e\b|\bsort (these |the |my )?(words|names|items|list)\b|alphabetical order/))) add("listops", 8, "sort a list");
  // truth table (keyword-gated so boolean "and/or" in prose never triggers it)
  if (has(/truth table/)) add("logic", 9, "boolean truth table");
  // set operations on two explicit sets
  if (has(/\bunion\b|\bintersection\b|symmetric difference|set difference/) || (has(/\bsets?\b/) && /\{[^}]*\}[\s\S]*\{[^}]*\}/.test(s)))
    add("setops", 8, "set operation");
  // number sequence / pattern (needs enough terms to be a real pattern)
  if (numCount >= 3 && has(/\bsequence\b|\bseries\b|\bprogression\b|next (in|number|term|two|three|few)|what comes next|nth term|find the pattern|continue the pattern/))
    add("sequence", 7, "number sequence");
  // math written in words ("twenty percent of 200 plus 30", "square root of 144").
  // Only claim it if we can actually translate it; a discount ("20% off $80")
  // is a word problem, so it is left to wordmath.
  if (hasMathPhrase(low) && !has(/\boff\b|discount|\bsale\b/) && mathPhrase(s)) add("calc", 6, "arithmetic expressed in words");
  // word problem: prose (no math operators) with two+ numbers and an operation cue.
  // Guarded so it never steals a plain expression ("9+1") or a stats list.
  if (!has(/[-+*/^=]/) && has(/[a-z]{3,}/) && numCount >= 2 && !has(/\bstats?\b|\bmedian\b|std ?dev|variance|quartile/) && !(hasMathPhrase(low) && mathPhrase(s)) &&
      has(/how (much|many)|in total|\btotal\b|altogether|in all|combined|\bsum\b|together|overall|left over|\bleft\b|remaining|remain\b|difference|fewer|less than|more than|spen[dt]|save[sd]?|gains?|earns?|deposit|split|shared|divid|\bper\b|each\b|multipl|\btimes\b|product|twice|double|triple|\boff\b|discount|\bsale\b|\badd\b|\bsum of\b/))
    add("wordmath", 6, "arithmetic word problem");
  // calc: math operators, a "what is <numbers>" request, or a variable assignment
  if (has(/[-+*/^]/) && has(/\d/)) add("calc", 5, "arithmetic expression");
  if (has(/^(what\s+is|calc(ulate)?|compute|evaluate)\b/) && has(/\d/)) add("calc", 4, "arithmetic request");
  if (has(/^[a-z_]\w*\s*=[^=]/)) add("calc", 4, "variable assignment");
  if (has(/\bsqrt|square root|factorial|\bpi\b|\bphi\b|\bsin\b|\bcos\b|\btan\b|\blog\b|\bgcd\(|\bmin\(|\bmax\(|\bround\(|\babs\(|\bcbrt\(|\bceil\(|\bfloor\(|\bexp\(|\bln\(/)) add("calc", 3, "math function");

  const ranked = Object.keys(S0).map((k) => ({ skill: k, score: S0[k], why: why[k] || "" }))
    .filter((r) => r.score > 0).sort((a, b) => b.score - a.score);
  return ranked;
}

// Public: predicted intents (top first). Empty => nothing matched.
export function route(input) { return score(input); }

// Compose the written answer for a resolved skill result.
function say(skill, res, input, model) {
  switch (skill) {
    case "calc":
      return res.ok
        ? { title: "Calculation", body: "The value of `" + res.expr + "` is **" + res.value + "**. I computed this by parsing the expression and evaluating it operator by operator, so the result is exact and reproducible.", result: res }
        : { title: "Calculation", body: "I could not evaluate that: " + res.error + ".", result: res };
    case "convert":
      return res.ok
        ? { title: "Unit conversion", body: "**" + res.input + " " + res.from + "** equals **" + res.value + " " + res.to + "** (" + res.dim + "). This uses a fixed conversion factor, so it is precise.", result: res }
        : { title: "Unit conversion", body: "I could not convert that: " + res.error + ".", result: res };
    case "codegen": {
      const lead = res.kind === "compiled"
        ? "I compiled `" + res.op + "` into **" + res.lang + "** from scratch — I parsed your spec into an abstract syntax tree and generated the code from it, so it is built for this request, not pasted from a snippet:"
        : res.kind === "synthesized"
          ? "Here is `" + res.op + "` generated from scratch for **" + res.lang + "**. I built it for this request, verified against the known-correct pattern for this operation:"
          : "I do not have an exact synthesis rule for that, so here is a correct, typed **" + res.lang + "** scaffold you can fill in:";
      return { title: "Code generation", body: lead, code: res.code, lang: res.lang, note: res.note, result: res };
    }
    case "text":
      return { title: "Text tool", body: typeof res === "number" ? "Result: **" + res + "**." : "Result:", pre: typeof res === "number" ? null : String(res), result: res };
    case "regex":
      if (res && res.pattern !== undefined) // regexTest result
        return { title: "Regex test", body: res.ok ? (res.matched ? "The pattern matched **" + res.count + "** time(s):" : "No matches.") : res.error, pre: res.ok && res.matches.length ? res.matches.join("\n") : null, result: res };
      return res.ok
        ? { title: "Regular expression", body: "This pattern " + res.desc + ":", pre: res.re, note: "Tested and ready to use. Add anchors (^ and $) if it must match the whole string.", result: res }
        : { title: "Regular expression", body: res.error, result: res };
    case "base":
      return res.ok ? { title: "Base conversion", body: "**" + res.text + "**. Exact integer conversion.", result: res }
        : { title: "Base conversion", body: res.error, result: res };
    case "color":
      return res.ok ? { title: "Color conversion", body: "That color in every format:", pre: "hex   " + res.hex + "\nrgb   " + res.rgb + "\nhsl   " + res.hsl, note: "Converted from " + res.src + " exactly.", result: res }
        : { title: "Color conversion", body: res.error, result: res };
    case "jsonquery":
      return res.ok ? { title: "JSON query", body: "`" + res.path + "` (" + res.type + "):", pre: res.value, note: "Navigated the JSON deterministically; no parsing guesswork.", result: res }
        : { title: "JSON query", body: res.error, result: res };
    case "data": {
      if (!res.ok) return { title: "Data analysis", body: res.error, result: res };
      const lines = res.cols.map((c) => c.type === "numeric"
        ? c.name + "  [numeric]  n=" + c.count + "  min=" + c.min + "  max=" + c.max + "  mean=" + c.mean + "  sum=" + c.sum
        : c.name + "  [text]  n=" + c.count + "  distinct=" + c.distinct + "  top: " + c.top.join(", "));
      return { title: "Data analysis", body: "Parsed **" + res.rows + " rows** across **" + res.columns + " columns**:", pre: lines.join("\n"), note: "Column types inferred from the values; numeric columns are summarized, text columns show their most common values.", result: res };
    }
    case "datetime":
      return res.ok
        ? { title: "Date math", body: "Answer: **" + res.text + "**. Computed in UTC to avoid timezone ambiguity.", result: res }
        : { title: "Date math", body: res.error, result: res };
    case "stats": {
      if (!res.ok) return { title: "Statistics", body: res.error, result: res };
      const body = "Summary of " + res.count + " values:";
      const rows = [["count", res.count], ["sum", res.sum], ["mean", res.mean], ["median", res.median],
        ["mode", res.mode.length ? res.mode.join(", ") : "none"], ["min", res.min], ["max", res.max], ["range", res.range],
        ["std dev (population)", res.stddev], ["std dev (sample)", res.sampleStddev], ["variance", res.variance], ["Q1", res.q1], ["Q3", res.q3]];
      return { title: "Statistics", body, pre: rows.map(([k, v]) => k.padEnd(22) + v).join("\n"), result: res };
    }
    case "algebra": {
      if (!res.ok) return { title: "Equation solver", body: res.error, result: res };
      if (!res.roots.length) return { title: "Equation solver", body: (res.note || "No real solution."), result: res };
      const kind = res.degree === 2 ? "quadratic" : "linear";
      const sol = res.roots.map((r) => res.variable + " = " + r).join("  or  ");
      return { title: "Equation solver", body: "Solved the " + kind + " equation. **" + sol + "**. I recovered the coefficients by sampling the equation and solved it in closed form, so the roots are exact.", result: res };
    }
    case "numbertheory":
      return res.ok ? { title: "Number theory", body: "**" + res.text + "**. Computed exactly by integer arithmetic.", result: res }
        : { title: "Number theory", body: res.error, result: res };
    case "wordmath":
      return res.ok
        ? { title: "Word problem", body: "I found the numbers **" + res.numbers.join(", ") + "** and the wording points to **" + res.op + "**, so I computed `" + res.expr + "` = **" + res.value + "**.", note: "I inferred the operation from the wording (this is the one place I make a reasoned guess). For an exact, unambiguous result, give me the arithmetic directly, e.g. “" + res.expr + "”.", result: res }
        : { title: "Word problem", body: res.error + ".", result: res };
    case "sequence": {
      if (!res.ok) return { title: "Sequence", body: res.error + ".", result: res };
      const parts = ["Pattern: **" + res.kind + "** — " + res.rule + ".", "Next terms: **" + res.next.join(", ") + "**."];
      if (res.nth) parts.push("Closed form: `" + res.nth + "`.");
      if (res.sum != null) parts.push("Sum of the given terms: **" + res.sum + "**.");
      return { title: "Sequence", body: parts.join(" "), note: "Found by checking for a constant difference, ratio, second difference, or additive rule — proven, not guessed.", result: res };
    }
    case "logic": {
      if (!res.ok) return { title: "Truth table", body: res.error + ".", result: res };
      const head = res.vars.join(" ") + " | " + res.expr;
      const line = "-".repeat(head.length);
      const body = res.rows.map((r) => res.vars.map((v) => r.assign[v] ? "T" : "F").join(" ") + " | " + (r.out ? "T" : "F")).join("\n");
      const verdict = res.tautology ? "This is a tautology (always true)." : res.contradiction ? "This is a contradiction (always false)." : "The expression is satisfiable but not always true.";
      return { title: "Truth table", body: verdict, pre: head + "\n" + line + "\n" + body, note: "Evaluated exhaustively over every assignment by a real parser — no eval, no shortcuts.", result: res };
    }
    case "setops":
      return res.ok
        ? { title: "Set operation", body: "**" + res.op + "** of {" + res.a.join(", ") + "} and {" + res.b.join(", ") + "}:", pre: "{" + res.result.join(", ") + "}  (" + res.result.length + " element" + (res.result.length === 1 ? "" : "s") + ")", result: res }
        : { title: "Set operation", body: res.error + ".", result: res };
    case "matrix": {
      if (!res.ok) return { title: "Linear algebra", body: res.error + ".", result: res };
      if (res.matrix) return { title: "Linear algebra", body: "The " + res.op + ":", pre: res.text, note: "Computed by exact matrix arithmetic (Gauss-Jordan for inverses).", result: res };
      if (res.vector) return { title: "Linear algebra", body: "The " + res.op + " is **[" + res.vector.join(", ") + "]**.", result: res };
      return { title: "Linear algebra", body: "The " + res.op + " is **" + res.value + "**.", result: res };
    }
    case "units":
      return res.ok
        ? { title: "Unit arithmetic", body: "`" + res.expr + "` = **" + res.value + " " + res.unit + "** (" + res.dim + "; " + res.base + " in base units).", note: "Combined with fixed conversion factors, so it is exact.", result: res }
        : { title: "Unit arithmetic", body: res.error + ".", result: res };
    case "combinatorics": {
      if (!res.ok) return { title: "Combinatorics", body: res.error + ".", result: res };
      if (res.op === "probability") return { title: "Probability", body: res.text, note: "Stated with its assumption; give exact counts for an exact fraction.", result: res };
      return { title: "Combinatorics", body: "**" + res.value + "** (" + res.op + ")." + (res.formula ? " Using `" + res.formula + "`." : ""), result: res };
    }
    case "knowledge":
      return res.ok ? { title: "Definition: " + res.term, body: res.text, note: "Source: Universal Engine glossary (curated, not generated). If a term is not covered I say so rather than invent an answer.", result: res }
        : { title: "Knowledge base", body: "I do not have a glossary entry for that, and I will not invent one. Covered terms include: " + (res.terms || []).slice(0, 12).join(", ") + ".", result: res };
    case "facts": {
      if (!res.ok) return { title: "Fact lookup", body: "I do not have that in my fact packs, and I will not invent it. I cover the **capital of every country**, all **118 elements**, and the main **physical, math, and astronomical constants**.", result: res };
      if (res.capital) return { title: "Capital of " + res.country, body: (res.reverse ? "**" + res.capital + "** is the capital of " + F.withThe(res.country).replace(res.country, "**" + res.country + "**") : "The capital of " + F.withThe(res.country).replace(res.country, "**" + res.country + "**") + " is **" + res.capital + "**") + (/\.$/.test(res.capital) ? "" : "."), note: "Source: Universal Engine curated fact pack (not generated).", result: res };
      if (res.trivia === true) return { title: "Fact", body: res.text.replace(/(\d+) known elements/, "**$1** known elements"), note: "Source: Universal Engine periodic table (118 elements, curated).", result: res };
      if (res.sym) return { title: "Element: " + res.name, body: (res.trivia ? "The " + res.trivia + " element is " : "") + "**" + res.name.charAt(0).toUpperCase() + res.name.slice(1) + "** (" + res.sym + "), atomic number " + res.z + ", atomic mass " + res.mass + " u. Category: " + res.cat + ".", note: "Source: Universal Engine periodic table (118 elements, curated).", result: res };
      if (res.unit) return { title: "Constant: " + res.name, body: "**" + F.sci(res.value) + (res.unit === "dimensionless" ? "" : " " + res.unit) + "** — " + res.desc, note: "Source: Universal Engine constants pack (curated reference values).", result: res };
      return { title: "Fact", body: JSON.stringify(res), result: res };
    }
    case "spelling": {
      if (!res.ok) return { title: "Spelling", body: res.error + ".", result: res };
      if (res.kind === "number") return { title: "Spelling", body: "**" + res.input + "** is spelled:", pre: res.words, result: res };
      if (res.kind === "choice") return { title: "Spelling", body: res.text, result: res };
      if (res.kind === "word") return { title: "Spelling", body: res.correct ? "**" + res.word + "** is spelled correctly." : res.best ? "The correct spelling is **" + res.best + "**" + (res.others.length ? " (other close words: " + res.others.join(", ") + ")" : "") + "." : "I do not recognize **" + res.word + "** and have no close match in my dictionary, so I will not guess.", result: res };
      return res.fixes.length
        ? { title: "Spelling", body: "I corrected **" + fixCount(res.fixes) + "** word" + (fixCount(res.fixes) === 1 ? "" : "s") + ": " + res.fixes.map((f) => f.from + " \u2192 " + f.to).join(", ") + ".", pre: res.text, note: "Checked against a 64,000-word English dictionary. Names (capitalised words), acronyms, quotes and code are left alone.", result: res }
        : { title: "Spelling", body: "I found no spelling mistakes.", pre: res.text, result: res };
    }
    case "listops":
      return res.ok ? { title: "Sorted list", body: "Sorted **" + res.items.length + " " + (res.numeric ? "numbers" : "items") + "** " + res.order + ":", pre: res.items.join(", "), note: res.numeric ? "Compared as numbers, so 10 comes after 9." : "Compared alphabetically, ignoring case.", result: res }
        : { title: "Sorted list", body: res.error + ".", result: res };
    case "encode":
      return { title: "Encode / hash (" + res.op + ")", body: "Result of `" + res.op + "` on your input:", pre: String(res.value), result: res };
    case "predict": {
      const cont = model ? complete(model, input.replace(/^(complete|continue|predict|autocomplete)\b[:,]?\s*/i, ""), 20) : "";
      const conf = model ? predConf(model, input) : 0;
      return { title: "Prediction", body: cont ? "Most likely continuation (statistical n-gram, confidence " + Math.round(conf * 100) + "%):" : "I need a few words to predict from.", pre: cont || null, note: "This is frequency-based next-word prediction from the bundled corpus, not comprehension.", result: { continuation: cont, confidence: conf } };
    }
    default: return { title: "Engine", body: "I am not sure what to do with that.", result: null };
  }
}

// Run a skill by name against the input.
function run(skill, input, model) {
  const low = input.toLowerCase();
  switch (skill) {
    case "calc": {
      const mp = mathPhrase(input); // arithmetic written in words -> an expression
      const first = mp ? S.calc(mp) : null;
      if (first && first.ok) return first;
      const r = S.calc(numberWords(input).replace(/^(what\s+is|calc(ulate)?|compute|evaluate)\b/i, ""));
      return (!r.ok && first) ? first : r;
    }
    case "convert": return S.convert(naturalize(input)); // rewrites "how many km in 5 miles" -> "5 miles in km"
    case "codegen": {
      // from-scratch synthesis: parse a function spec, compile its AST to the
      // target language. Falls back to the skill's own generator for named algorithms.
      const spec = parseSpec(input);
      if (spec) {
        const r = synth(spec);
        if (r.ok) {
          const LMAP = { py: "python", python: "python", js: "javascript", javascript: "javascript", node: "javascript", ts: "typescript", typescript: "typescript", rs: "rust", rust: "rust", go: "go", golang: "go", java: "java", c: "c" };
          let lang = "python"; for (const k in LMAP) if (new RegExp("\\b" + k + "\\b").test(low)) { lang = LMAP[k]; break; }
          const built = r.langs[lang];
          const imp = built.uses && built.uses.includes("math")
            ? ({ python: " Needs 'import math'.", go: ' Needs import "math".', c: " Needs #include <math.h>." }[lang] || "")
            : "";
          const shape = r.recursive ? " It compiled the self-reference into real recursion." : r.iterative ? " It compiled the aggregation into an accumulator loop." : "";
          return { ok: true, kind: "compiled", lang, op: r.name + "(" + r.params.join(", ") + ")", code: built.code, note: "Parsed your spec to an AST and compiled it to " + lang + " from scratch (no stored snippet)." + shape + imp, result: r };
        }
      }
      return S.codegen(input);
    }
    case "regex": {
      const tm = input.match(/\/(.+)\/\s*(?:on|against|=>|:)?\s*(.*)$/) || input.match(/test\s+(\S+)\s+(?:on|against)\s+(.+)$/i);
      if ((/\btest\b|against|\bmatch(es)?\b/i.test(low)) && tm && tm[2]) return S.regexTest(tm[1], tm[2]);
      return S.regexBuild(input);
    }
    case "datetime": return S.datetime(input);
    case "base": return D.numberBase(input);
    case "color": return M.colorConvert(input);
    case "jsonquery": return M.jsonQuery(input);
    case "data": {
      // accept literal \n from one-line pastes, and strip a leading label like "analyze csv:"
      const norm = input.replace(/\\n/g, "\n").replace(/^[^,\n]*:[ \t]*/, "");
      const lines = norm.split(/\n/);
      const start = lines.findIndex((l) => /,/.test(l));
      const csv = start >= 0 ? lines.slice(start).join("\n") : norm;
      return D.analyzeCSV(csv);
    }
    case "stats": return A.stats(input);
    case "algebra": return A.solveEquation(input);
    case "numbertheory": return A.numberTheory(input.replace(/\bfactors?\s+(of\s+)?(?=\d)/i, "factorize ").replace(/\bfactor\s+(?=\d)/i, "factorize "));
    case "wordmath": return A.wordMath(numberWords(input));
    case "sequence": return A.sequence(input);
    case "logic": return A.logic(input);
    case "setops": return A.setOps(input);
    case "matrix": return MX.linalg(input);
    case "units": return unitMath(input);
    case "combinatorics": return A.combinatorics(input);
    case "knowledge": return A.lookup(input);
    case "facts": return F.facts(input);
    case "listops": return listOps(input);
    case "spelling": return spelling(input, model);
    case "encode": {
      const eops = [["unbase64", /(?:decode\s+(?:this\s+)?(?:from\s+)?base64|from\s+base64|unbase64|base64\s+decode)/], ["base64", /base64/], ["unhex", /(?:from\s+hex|decode\s+hex|unhex)/], ["hex", /hex/], ["unurl", /url\s*decode|decode\s+url|unurl/], ["url", /url/], ["rot13", /rot13/], ["unbinary", /from\s+binary|decode\s+binary/], ["binary", /binary/], ["morse", /morse/], ["crc32", /crc32/], ["fnv1a", /fnv1a?/], ["djb2", /djb2/]];
      let eop = "base64"; for (const [name, re] of eops) if (re.test(low)) { eop = name; break; }
      if (/\bhash\b/.test(low) && !/crc32|fnv|djb2/.test(low)) eop = "fnv1a";
      const dg = /\bmd5\b/.test(low) ? "md5" : /\bsha-?1\b/.test(low) ? "sha1" : /\bsha(?:-?256)?\b/.test(low) ? "sha256" : null;
      if (dg) eop = dg;
      const q = input.match(/["']([^"']+)["']/); const c = input.indexOf(":");
      const STRIP = /^(?:base64|hex|url|rot13|binary|morse|crc32|fnv1a?|djb2|md5|sha-?256|sha-?1|sha|hash|digest|checksum|encode|decode|convert|to|from|of|the|into|as|please|give|me|compute|do|a|an|what|is|whats|calculate)\b[\s:]*/i;
      let payload;
      if (q) payload = q[1];
      else if (c >= 0) payload = input.slice(c + 1).trim();
      else { let t = input.trim(), prev; do { prev = t; t = t.replace(STRIP, ""); } while (t !== prev); payload = t; }
      if (dg) return { op: dg, value: H[dg](payload || ""), payload: payload || "" };
      return { op: eop, value: A.encode(eop, payload || ""), payload: payload || "" };
    }
    case "text": {
      const opMap = [["camel", /camel ?case/], ["snake", /snake ?case/], ["kebab", /kebab ?case/], ["constant", /constant case/], ["wordfreq", /word frequency|frequenc/], ["emails", /extract emails?|\bemails?\b/], ["urls", /extract (urls?|links?)|\burls?\b|\blinks?\b/], ["numbers", /extract numbers?|\bnumbers\b(?! in)/], ["vowels", /\bvowels?\b/], ["consonants", /\bconsonants?\b/], ["upper", /uppercase/], ["lower", /lowercase/], ["title", /title case/], ["slug", /slug/], ["reverse", /reverse|backwards/], ["chars", /count (the )?(characters|letters)|char count|how many (characters|letters|chars)|number of (characters|letters)/], ["words", /count (the )?words|word count|how many words|number of words/], ["sortlines", /sort lines/], ["dedupewords", /dedupe words|(?:duplicate|repeated) words/], ["dedupe", /dedupe|remove duplicate/], ["unbase64", /decode base64|from base64|unbase64/], ["json", /pretty ?print|format json/]];
      let op = "words"; for (const [name, re] of opMap) if (re.test(low)) { op = name; break; }
      const scan = op === "emails" || op === "urls" || op === "numbers" || op === "wordfreq"; // scan whole input, do not strip content
      const q = input.match(/["']([^"']+)["']/); const c = input.indexOf(":");
      let payload;
      if (q) payload = q[1];
      else if (c >= 0) payload = input.slice(c + 1).trim();
      else if (scan) payload = input;
      else {
        // "convert hello world to camel case": the target case is the command, not content
        input = input.replace(/\s+(?:to|into|in|as)\s+(?:(?:camel|snake|kebab|constant|title|upper|lower) ?case|uppercase|lowercase|a slug|slug)\s*$/i, "");
        const CMD = "reverse|backwards|the(?=\\s+(?:text|string|word|words|sentence|phrase|following|letters|characters|name|vowels|consonants)\\b)|text|sentence|phrase|vowels?|consonants?|camelcase|snakecase|kebabcase|titlecase|string|word|to|into|uppercase|lowercase|upper|lower|title|camel|snake|kebab|constant|case|slug|slugify|count|words?|characters?|letters?|chars?|frequency|sort|lines|dedupe|remove|duplicates?|please|make|convert|format|json|pretty|print|this|following|a|an|(?:can|could|would|will) (?:you|u)(?: please)?|how (?:do|can|would) (?:i|you|u)|how many|number of|i want to|i need to|help me";
        // if a command phrase ends in a boundary preposition, keep everything after it verbatim
        const pm = input.trim().match(new RegExp("^(?:(?:" + CMD + ")\\s+)*(?:in|of|from)\\s+(.+)$", "i"));
        if (pm) payload = pm[1];
        else { // otherwise strip only the leading run of command words (never eats content)
          const TSTRIP = new RegExp("^(?:" + CMD + "|in|of|from)\\b[\\s:]*", "i");
          let t = input.trim(), prev; do { prev = t; t = t.replace(TSTRIP, ""); } while (t !== prev);
          payload = t || input;
        }
      }
      if (op === "vowels" || op === "consonants") {
        const letters = String(payload).match(/[a-z]/gi) || [];
        const v = letters.filter((ch) => /[aeiou]/i.test(ch)).length;
        return op === "vowels" ? v : letters.length - v;
      }
      return S.text(op, payload);
    }
    default: return null;
  }
}

// Spelling: one word (is it right, and what is the right spelling), a sentence
// (proofread it), a choice ("is it seperate or separate"), or a number spelled out.
function spelling(input, model) {
  const lex = lexicon(model);
  let t = String(input || "").trim();
  const choice = t.match(/^(?:is it|which is (?:correct|right|it))[,:]?\s+([a-z']+)\s+or\s+([a-z']+)\s*\??$/i);
  if (choice) {
    const [a, b] = [choice[1], choice[2]], ra = isWord(lex, a), rb = isWord(lex, b);
    const text = ra && rb ? "Both **" + a + "** and **" + b + "** are real words; they mean different things (or are regional spellings)." : ra ? "**" + a + "** is correct; " + b + " is a misspelling." : rb ? "**" + b + "** is correct; " + a + " is a misspelling." : "Neither is right: the closest real word is **" + ((rankFixes(lex, a)[0] || rankFixes(lex, b)[0] || { to: "(none)" }).to) + "**.";
    return { ok: true, kind: "choice", text, a, b };
  }
  const q = t.match(/["\u201c']([^"\u201d']+)["\u201d']/), c = t.indexOf(":");
  if (q) t = q[1];
  else if (c >= 0) t = t.slice(c + 1).trim();
  else {
    t = t.replace(/^(?:please\s+)?(?:can you\s+|could you\s+)?(?:how (?:do|would|should|can|is) (?:you |i |u |we |it )?spell|(?:what is |whats )?(?:the )?(?:correct |right |proper )?spelling (?:of|for)|spell ?check|spellcheck|proofread|check (?:the |my )?spelling (?:of|in|on)|check (?:the |my )?spelling|fix (?:the |my )?spelling (?:of|in)|correct (?:the )?spelling (?:of|in)|spell out|spell)\s+/i, "");
    t = t.replace(/^is\s+/i, "").replace(/\s+(?:spelled|spelt|spelling)(?:\s+(?:right|correctly|properly|wrong))?\s*\??$/i, "").replace(/\s*\?$/, "").trim();
  }
  if (!t) return { ok: false, error: "tell me the word or text, e.g. 'how do you spell recieve' or 'spell check: teh wether is nice'" };
  if (/^-?\d+(?:\.\d+)?$/.test(t.replace(/,/g, ""))) {
    const words = numberToWords(t.replace(/,/g, ""));
    return words ? { ok: true, kind: "number", input: t, words } : { ok: false, error: "that number is too large to spell out (up to the trillions)" };
  }
  if (/^[A-Za-z']+$/.test(t)) {
    const w = t.toLowerCase();
    if (isWord(lex, w)) return { ok: true, kind: "word", word: t, correct: true };
    const r = rankFixes(lex, w).filter((x) => !/\s/.test(x.to) || x.cost <= 0.75);
    return { ok: true, kind: "word", word: t, correct: false, best: r[0] ? r[0].to : null, others: r.slice(1, 4).map((x) => x.to) };
  }
  const fixed = correctText(lex, t);
  const g = proofread(fixed.text);
  return { ok: true, kind: "text", input: t, text: g.text, fixes: [...fixed.fixes, ...g.fixes] };
}

// Common word confusions a spell checker alone cannot see (every word is real),
// fixed only in unambiguous frames, plus a lone "i" and sentence capitals.
const NOUNISH = "message|messages|name|car|house|phone|friend|friends|mom|mum|dad|family|email|account|password|order|book|dog|cat|work|job|help|team|code|computer|idea|question|answer|opinion|mother|father|brother|sister|life|time|home|money|birthday|room|school|teacher|boss|number|address|own|way|turn|fault|problem|choice|best";
const CONFUSIONS = [
  [/\b(should|could|would|must|might|may)\s+of\b/gi, "$1 have"],
  [/\byour\s+(welcome|right|wrong|not|going|so|very|too|always|never|the best|a)\b/gi, "you're $1"],
  [new RegExp("\\byou're\\s+(" + NOUNISH + ")\\b", "gi"), "your $1"],
  [new RegExp("\\bthere\\s+(" + NOUNISH + ")\\b", "gi"), "their $1"],
  [/\btheir\s+(is|are|was|were|will be|has been)\b/gi, "there $1"],
  [/\b(more|less|better|worse|bigger|smaller|faster|slower|rather|other|older|younger|higher|lower|greater|larger)\s+then\b/gi, "$1 than"],
  [/\bits\s+(a|an|the|not|been|going|so|very|too|ok|okay|over|all|just|really|about|like|raining|time to)\b/gi, "it's $1"],
  [/\bit's\s+(own|self)\b/gi, "its $1"],
  [/\bwho's\s+(car|house|phone|book|idea|turn|fault|dog|cat)\b/gi, "whose $1"],
  [/\bloose\s+(the game|weight|my|your|his|her|our|their|it|them|money|control|track)\b/gi, "lose $1"],
];
// how many words a fix list changed: "i -> I (x2)" is two, "3 sentence starts" is three
const fixCount = (fixes) => fixes.reduce((n, f) => n + Number((String(f.to).match(/\(x(\d+)\)$/) || String(f.from).match(/^(\d+) sentence start/) || [0, 1])[1]), 0);
function proofread(text) {
  const fixes = [];
  let t = text.replace(/\b[A-Za-z]+\b/g, (w) => { const c = CONTRACT[w.toLowerCase()]; if (!c) return w; fixes.push({ from: w, to: c }); return /^[A-Z]/.test(w) ? c.charAt(0).toUpperCase() + c.slice(1) : c; });
  for (const [re, to] of CONFUSIONS) t = t.replace(re, (...m) => { const out = m[0].replace(re, to); re.lastIndex = 0; if (out !== m[0]) fixes.push({ from: m[0], to: out }); return out; });
  t = t.replace(/(^|[^\w'])i(?=[\s,.!?']|$)/g, (m, a) => { fixes.push({ from: "i", to: "I" }); return a + "I"; });
  let caps = 0;
  t = t.replace(/(^\s*|[.!?]\s+)([a-z])/g, (m, a, ch) => { caps++; return a + ch.toUpperCase(); });
  if (caps) fixes.push({ from: caps + " sentence start" + (caps === 1 ? "" : "s"), to: "capitalised" });
  // the same fix made more than once is listed once, with how many times ("i -> I (x2)")
  const seen = new Map();
  for (const f of fixes) { const k = f.from + ">" + f.to; if (seen.has(k)) seen.get(k).times++; else seen.set(k, { ...f, times: 1 }); }
  return { text: t, fixes: [...seen.values()].map((f) => f.times > 1 ? { from: f.from, to: f.to + " (x" + f.times + ")" } : { from: f.from, to: f.to }) };
}

// Sort a list of numbers (numerically) or words (alphabetically), either way round.
function listOps(input) {
  const low = input.toLowerCase();
  const desc = /\bdesc|descending|decreasing|largest (?:to|first)|biggest (?:to|first)|highest (?:to|first)|high to low|greatest to|reverse (?:order|alphabetical)|z to a|z-a\b/.test(low);
  const nums = (numberWords(input).match(/-?\d+(?:\.\d+)?/g) || []).map(Number);
  if (nums.length >= 2 && !/\balphabeti|\bwords\b|\bnames\b/.test(low)) {
    const items = nums.slice().sort((a, b) => desc ? b - a : a - b);
    return { ok: true, numeric: true, items, order: desc ? "from largest to smallest" : "from smallest to largest", value: items };
  }
  const c = input.indexOf(":");
  let body = c >= 0 ? input.slice(c + 1) : input.replace(/^(?:please\s+)?(?:alphabeti[sz]e|sort|order|arrange|put)\s+(?:(?:these|the|my|following|in|alphabetical|order|words|names|items|list|of|alphabetically)\s+)*/i, "");
  body = body.replace(/\s+(?:in\s+)?(?:alphabetical(?:ly)?|reverse)?\s*(?:order)?\s*(?:a to z|z to a|ascending|descending|alphabetically)?\s*$/i, "");
  const items = body.split(/\s*,\s*|\s+and\s+|\s+/).map((x) => x.trim()).filter(Boolean);
  if (items.length < 2) return { ok: false, error: "give me at least two items, e.g. 'sort 5 3 9' or 'alphabetize pear, apple, fig'" };
  items.sort((a, b) => a.localeCompare(b, "en", { sensitivity: "base" }) * (desc ? -1 : 1));
  return { ok: true, numeric: false, items, order: desc ? "from Z to A" : "from A to Z" };
}

// Nouns that describe a whole application — beyond a single synthesizable function.
const APP_NOUN = /\b(game|app|apps|application|program|programme|website|web ?site|web ?page|webpage|site|page|tool|bot|server|api|script|ui|gui|interface|dashboard|clone|engine|simulator|simulation|animation|graphics|frontend|front-end|backend|back-end|database|db|os|operating system|compiler|browser|editor|chatbot|platform|feature|screen|menu|level)\b/;
const BUILD_VERB = /\b(make|build|create|develop|design|generate|write|code|implement|program|do|add|set up|setup)\b/;
// A request we understand the intent of, but that is a whole application rather
// than one function — answered honestly instead of with a shrug.
function classifyBuild(low) {
  if (BUILD_VERB.test(low) && APP_NOUN.test(low)) return (low.match(APP_NOUN) || [, "application"])[0].replace(/\s+/g, " ");
  return null;
}
// A word-level read of an unmatched request: which words the engine actually
// recognizes (so it can say what it understood rather than only what it did not).
function recognizedWords(low) {
  const known = { calc: /\b(add|plus|sum|minus|subtract|multiply|divide|square|sqrt|percent|factorial)\b/, convert: /\b(convert|kilometers?|km|kg|miles?|meters?|celsius|fahrenheit|kilograms?|bytes?|gigabytes?|megabytes?)\b/, text: /\b(reverse|uppercase|lowercase|camelcase|snakecase|kebab|slugify|slug)\b/, code: /\b(function|python|javascript|typescript|rust|golang|recursion)\b/, date: /\b(leap ?year|weekday|calendar|days? between)\b/, regex: /\b(regex|regular expression|pattern)\b/, facts: /\b(capital|element|atomic|periodic|planck|avogadro|speed of light)\b/ };
  const hits = [];
  for (const k in known) if (known[k].test(low)) hits.push(k);
  return hits;
}

// ---------------------------------------------------------------------------
// Typo tolerance for the whole request (not just command words). The corrector
// (spell.js) only ever swaps a word for a real vocabulary word; this is the
// vocabulary: everything the engine can act on, weighted above ordinary English
// so a request word wins a tie ("revrse" -> reverse, not reverie).
// ---------------------------------------------------------------------------
const LANGS = ["python", "javascript", "typescript", "rust", "go", "golang", "java", "c", "node"];
const TEXT_CMDS = "reverse backwards text string word words uppercase lowercase upper lower title camel snake kebab constant case slug slugify count characters letters chars frequency sort lines dedupe remove duplicates format json pretty print extract emails urls links numbers encode decode base64 hex url rot13 binary morse hash truth table union intersection difference symmetric set sets matrix determinant transpose inverse vector dot cross magnitude regex pattern match test against color rgb hsl".split(" ");
const ENGINE_WORDS = [...KW, ...LANGS, ...TEXT_CMDS, ...UNIT_WORDS, ...Object.keys(S.HOLIDAYS),
  "gcd", "lcm", "ncr", "npr", "factorize", "factor", "factors", "prime", "primes", "octal", "decimal", "roman", "numeral", "numerals", "leap", "weekday", "until", "days", "mean", "median", "mode", "variance", "deviation", "quartile", "sequence", "series", "next", "choose", "odds", "chance", "percent", "percentage", "sqrt", "square", "root", "cube", "cubed", "squared", "power", "capital", "capitals", "element", "elements", "atomic", "periodic", "symbol", "constant", "celsius", "fahrenheit", "kelvin", "kilometers", "kilometres", "then", "after", "finally", "also", "next", "what", "about", "same", "now", "it", "that", "result",
  // everyday words for the same operations (so "biggest" is not read as "bigger")
  "half", "third", "quarter", "thirds", "quarters", "twice", "biggest", "largest", "greatest", "highest", "smallest", "lowest", "least", "maximum", "minimum", "arrange", "arrangements", "ways", "caps", "flip", "mirror", "meaning", "definition", "comes", "light", "gravity", "earth", "value", "common", "divisor", "denominator", "till", "til",
  "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "sept", "oct", "nov", "dec", "january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december", "tip", "off", "sound", "proton", "electron", "neutron", "md5", "sha1", "sha256",
  "abs", "absolute", "cbrt", "log", "ln", "sin", "cos", "tan", "ceil", "floor", "min", "max", "avg", "hcf", "lcm", "gcd", "exp"];
const ENGINE_SET = new Set(ENGINE_WORDS.map((w) => w.toLowerCase()));
const CAPITAL_CITIES = new Set(Object.values(F.CAPITALS).map((c) => c.toLowerCase()));
const DOMAIN_WORDS = [...Object.keys(A.GLOSSARY), ...Object.keys(F.CAPITALS), ...Object.values(F.CAPITALS), ...F.ELEMENTS.map((e) => e.name), ...Object.keys(F.CONSTANTS)];
const lexCache = new WeakMap();
let lexStatic = null;
function lexicon(model) {
  const weighted = new Map(ENGINE_WORDS.map((w) => [w, 40]));
  if (!model) return lexStatic || (lexStatic = withDictionary(makeLexicon(weighted, DOMAIN_WORDS), englishWords(), wordBand));
  const hit = lexCache.get(model);
  if (hit && hit.tokens === model.tokens) return hit.lex; // rebuilt only when the model learned something
  const lex = withDictionary(makeLexicon(model.uni, weighted, DOMAIN_WORDS), englishWords(), wordBand);
  withContext(lex, (p, c) => { const m = model.bi.get(p); return m ? m.get(c) || 0 : 0; });
  lexCache.set(model, { tokens: model.tokens, lex });
  return lex;
}

// Public: correct a request. `text` has every fix applied (for routing and for
// skills that read meaning); `hybrid` fixes only command words and leaves the
// user's own content verbatim (for skills that transform content, like reverse).
export function fixTypos(input, model) {
  const lex = lexicon(model);
  const full = correctText(lex, input);
  const cmd = correctText(lex, input, (to) => ENGINE_SET.has(to));
  return { text: full.text, fixes: full.fixes, hybrid: cmd.text, hybridFixes: cmd.fixes };
}

// --- slot prediction: after "capital of", the next word is a country; after
// "5 km to", a unit of the same dimension; after "write ... in", a language. ---
const POP_COUNTRIES = ["france", "japan", "germany", "india", "canada", "australia", "brazil", "italy", "spain", "china", "mexico", "egypt"];
const POP_ELEMENTS = ["gold", "iron", "carbon", "oxygen", "hydrogen", "silver", "copper", "helium", "sodium", "uranium"];
const DIM_UNITS = { length: ["km", "miles", "m", "feet", "inches", "cm"], mass: ["kg", "pounds", "g", "oz"], time: ["seconds", "minutes", "hours", "days", "weeks"], data: ["mb", "gb", "kb", "tb", "bytes"], speed: ["mph", "km/h", "m/s", "knots"], temperature: ["celsius", "fahrenheit", "kelvin"], volume: ["liters", "ml", "gallons", "cups", "pints"], area: ["acres", "hectares", "sqft", "m2"] };
function unitDim(u) {
  u = u.toLowerCase();
  if (/^(c|f|k|celsius|fahrenheit|kelvin|degrees?)$/.test(u)) return "temperature";
  for (const d in S.UNIT_TABLE) if (u in S.UNIT_TABLE[d].u) return d;
  if (/^kilomet(er|re)s?$|^met(er|re)s?$|^inches$|^yards?$/.test(u)) return "length";
  if (/^(grams?|kilograms?|ounces?|tonnes?)$/.test(u)) return "mass";
  return null;
}
function slotWords(low) {
  if (/\bcapital (?:city )?of(?: the)?$/.test(low)) return [...POP_COUNTRIES, ...Object.keys(F.CAPITALS).sort()];
  if (/\b(?:element|atomic (?:number|mass|weight) of|symbol (?:for|of))$/.test(low)) return [...POP_ELEMENTS, ...F.ELEMENTS.map((e) => e.name)];
  const u = low.match(/(\d+(?:\.\d+)?)\s*([a-z/]+)\s+(?:to|in|into|as)$/);
  if (u) {
    const dim = unitDim(u[2]);
    if (dim) {
      const tbl = S.UNIT_TABLE[dim], from = u[2];
      return DIM_UNITS[dim].filter((x) => x !== from && !(tbl && tbl.u[x] != null && tbl.u[x] === tbl.u[from]));
    }
  }
  if (/\b(?:write|generate|implement|code|make|build|create)\b.*\bin$/.test(low)) return ["python", "javascript", "typescript", "rust", "go", "java", "c"];
  if (/\bdays? (?:until|till)$/.test(low)) return ["christmas", "halloween", "new year", "thanksgiving", "valentines day"];
  return null;
}

// Public: live suggestions as the user types. Corrects the finished words first
// (so a typo does not derail the context), fills a recognised slot, then falls
// back to the n-gram predictor; a half-typed word also completes fuzzily
// ("fibn" -> fibonacci). Returns { words, fix } where `fix` offers the corrected text.
export function predictWords(model, text, k = 6) {
  const v = String(text || "");
  if (!v.trim()) return { words: [], fix: null };
  const lex = lexicon(model);
  const pm = v.match(/[a-z0-9']+$/i);
  const partial = pm ? pm[0] : "";
  const head = partial ? v.slice(0, v.length - partial.length) : v;
  const fh = correctText(lex, head);
  const ctx = fh.text;
  const low = ctx.toLowerCase().replace(/\s+$/, "");
  const p = partial.toLowerCase();
  const out = [];
  const push = (w) => { if (w && w !== p && !out.includes(w) && out.length < k) out.push(w); };
  // a finished-looking but misspelled word: offer its correction first
  const pfix = p.length >= 4 ? correctWord(lex, p) : null;
  if (pfix) push(pfix);
  const slot = slotWords(low);
  if (slot) {
    const before = out.length;
    if (!p) slot.forEach(push);
    else {
      slot.filter((w) => w.startsWith(p)).forEach(push);
      if (p.length >= 3) slot.filter((w) => typoDistance(p, w.slice(0, p.length), 0.8) <= 0.8).forEach(push);
    }
    // a filled slot is the answer; generic n-gram filler ("a", "the") would only add noise
    if (out.length > before) return { words: out, fix: fh.fixes.length ? { text: ctx + partial, fixes: fh.fixes } : null };
  }
  if (p) {
    if (model) suggestWord(model, ctx + partial, k).forEach(push);
    if (out.length < k) fuzzyPrefix(lex, p, k).forEach(push);
  } else if (model) {
    predictNext(model, ctx, k * 2).map((r) => r.token).filter((t) => /^[a-z0-9']+$/.test(t)).forEach(push);
  }
  return { words: out, fix: fh.fixes.length ? { text: ctx + partial, fixes: fh.fixes } : null };
}

// Typical requests, so the predictor knows how people phrase commands (the
// corpus is prose; this is the command register). Counted, not generated.
const COMMANDS = `what is the capital of france. what is the capital of japan. what is the capital of the united kingdom.
convert 5 km to miles. convert 100 fahrenheit to celsius. convert 2 hours to minutes. convert 10 kg to pounds. convert 500 mb to gb.
how many km in 5 miles. how many seconds in a day. how many days until christmas. how many letters in mississippi.
what is 15 percent of 240. what is the square root of 144. what is 2 to the power of 10. what is 12 times 8.
write a function in python. write a fibonacci function in python. write a binary search in go. write a bubble sort in rust.
generate a factorial function in javascript. make a palindrome checker in java. implement gcd in c.
reverse hello world. uppercase hello world. convert hello world to camel case. count the words in this sentence.
solve x^2 - 5x + 6 = 0. factorize 360. is 97 prime. what is the 10th prime. what is the gcd of 48 and 60.
what is element 26. tell me about gold. what is the atomic number of carbon. what is the speed of light. what is planck's constant.
what is a hash map. what is recursion. explain big o notation. define a closure.
what day of the week is 2026-12-25. add 10 days to 2026-01-01. is 2024 a leap year. days between 2026-01-01 and 2026-12-31.
stats 4 8 15 16 23 42. what comes next in 2, 5, 8, 11. 10 choose 3. truth table for a and b.
255 to hex. 42 to binary. 2024 to roman numerals. convert #ff8800 to rgb. base64 encode hello.`;

// Public: the predictor the tab uses — the prose corpus, plus the glossary's own
// definitions and the command phrasebook, plus any extra text (e.g. examples).
export function buildModel(corpus, extra = "") {
  return train([corpus, Object.values(A.GLOSSARY).join("\n"), COMMANDS, extra].join("\n"));
}
export { learn };

// ---------------------------------------------------------------------------
// Texting shorthand. Runs before the spell corrector, which would otherwise read
// "wat" as "way": these are not typos but a register of their own. `all` false
// keeps to command words, so a text tool's content ("reverse i love u") is kept.
// ---------------------------------------------------------------------------
const SLANG_CMD = { wat: "what", wut: "what", wht: "what", wot: "what", wats: "whats", wuts: "whats", hw: "how", cnvrt: "convert", cnvt: "convert", cvt: "convert", conv: "convert", gimme: "give me", wanna: "want to", abt: "about", pls: "", plz: "", plez: "", ty: "", thx: "", tysm: "" };
const CONTRACT = { dont: "don't", doesnt: "doesn't", didnt: "didn't", isnt: "isn't", arent: "aren't", wasnt: "wasn't", werent: "weren't", cant: "can't", couldnt: "couldn't", wouldnt: "wouldn't", shouldnt: "shouldn't", wont: "won't", youre: "you're", theyre: "they're", im: "i'm", ive: "i've", thats: "that's", theres: "there's", hasnt: "hasn't", havent: "haven't" };
const SLANG_ALL = { ...SLANG_CMD, ...CONTRACT, u: "you", ur: "your", bro: "", bruh: "", dude: "", lol: "", lmao: "", b4: "before", tmrw: "tomorrow" };
export function slang(input, all = true) {
  const map = all ? SLANG_ALL : SLANG_CMD;
  const fixes = [];
  // never touch quoted content or text after a colon
  const cut = input.search(/["'`:]/);
  const head = cut >= 0 ? input.slice(0, cut) : input, tail = cut >= 0 ? input.slice(cut) : "";
  let t = head.replace(/\b[a-z0-9]+\b/gi, (w) => {
    const k = w.toLowerCase();
    if (!(k in map) || (k === "u" && /^U$/.test(w))) return w;
    fixes.push({ from: w, to: map[k] || "(dropped)" });
    return map[k];
  });
  // "10 kg 2 lbs": a "2" between two units means "to"
  if (all) t = t.replace(/(\d(?:\.\d+)?\s*([a-z°]+))\s+2\s+([a-z°]+)\b/gi, (m, q, u1, u2) => (UNIT_WORDS.has(u1.toLowerCase()) && UNIT_WORDS.has(u2.toLowerCase())) ? (fixes.push({ from: "2", to: "to" }), q + " to " + u2) : m);
  t = t.replace(/^[\s,.!]+/, "").replace(/\s+([,?.!])/g, "$1").replace(/,\s*,/g, ",").replace(/\s{2,}/g, " ");
  return { text: (t + tail).trim(), fixes };
}

// ---------------------------------------------------------------------------
// Rephrasing: casual shapes rewritten into the forms the skills already parse
// ("half of 90" -> "(90 / 2)", "flip X backwards" -> "reverse X", "is 17 a prime
// number" -> "is 17 prime"). Each rule is explicit, and the rewrite is shown to
// the user, so the engine says how it read a request instead of guessing quietly.
// ---------------------------------------------------------------------------
const NUM = "-?\\d+(?:\\.\\d+)?";
const LIST = "(" + NUM + "(?:\\s*,?\\s*(?:and\\s+)?" + NUM + ")+)";
const HOLI_KEYS = Object.keys(S.HOLIDAYS).sort((a, b) => b.length - a.length).map((k) => k.replace(/'/g, "'?"));
const pad2 = (n) => String(n).padStart(2, "0");
const MONTHS = "jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sept?(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?";
const MON_IDX = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
function isoDate(y, mo, d) {
  const m = MON_IDX[mo.toLowerCase().slice(0, 3)], day = Number(d);
  const dt = new Date(Date.UTC(Number(y), m - 1, day));
  return m && dt.getUTCDate() === day ? y + "-" + pad2(m) + "-" + pad2(day) : null; // reject Feb 30
}
const REPHRASE = [
  // conversational lead-ins left after a thank-you ("ty, now whats 9 squared")
  [/^(?:(?:ok|okay|alright|cool|nice|great|perfect|thanks|thank you)[,!.]?\s+)?(?:and\s+)?now[,]?\s+(?=\S)/i, ""],
  [/^(?:ok|okay|alright|cool|nice|great|perfect)[,!.]\s*(?=\S)/i, ""],
  [/^(?:you know|do you know|did you know|any idea|tell me)[,]?\s+(?=(?:what|whats|how|the|is|which|who)\b)/i, ""],
  // "5 x 5" / "12x12" is multiplication (but not hex "0x1f" and not algebra "3x = 12")
  [/(\d)\s*[x×]\s*(?=\d)/gi, (m, d, off, str) => {
    const hex = d === "0" && !/\s/.test(m) && (off === 0 || !/[\d.]/.test(str[off - 1]));
    return (hex || /=/.test(str)) ? m : d + " * ";
  }],
  // powers, roots and rounding said in words
  [new RegExp("(" + NUM + ")\\s+to the (" + NUM + ")(?:st|nd|rd|th)?(?:\\s+power)?\\b", "gi"), "$1 ^ $2"],
  [new RegExp("(" + NUM + ")\\s+(?:to the power|raised to(?: the power)?|to power)(?: of)?\\s+(" + NUM + ")", "gi"), "$1 ^ $2"],
  [new RegExp("\\b(?:square root|sqrt)\\s+(" + NUM + ")", "gi"), "sqrt($1)"],
  [new RegExp("\\b(?:cube root|cbrt)\\s+(" + NUM + ")", "gi"), "cbrt($1)"],
  [new RegExp("^(?:please\\s+)?round\\s+(" + NUM + ")\\s+to\\s+(\\d+)\\s*(?:decimal places?|decimals?|dp|places?|digits?)\\s*\\??$", "i"), "round($1, $2)"],
  [new RegExp("^(?:please\\s+)?round\\s+(" + NUM + ")(?:\\s+to the nearest (?:whole number|integer|one))?\\s*\\??$", "i"), "round($1)"],
  [new RegExp("\\bnegative\\s+(" + NUM + ")", "gi"), "-$1"],
  [new RegExp("^(?:what is |whats |calculate |the )?(?:the )?(abs|log|ln|sin|cos|tan|ceil|floor|exp)\\s+(?:of\\s+)?(" + NUM + ")\\s*\\??$", "i"), (m, f, n) => f.toLowerCase() + "(" + n + ")"],
  [new RegExp("\\b(?:the\\s+)?(?:absolute value|abs|magnitude|modulus) of\\s+(" + NUM + ")", "gi"), "abs($1)"],
  // "convert celsius to fahrenheit 100": the number came last
  [new RegExp("^(?:convert\\s+)?([a-z]+)\\s+(?:to|in|into)\\s+([a-z]+)\\s*[:,]?\\s*(" + NUM + ")\\s*\\??$", "i"), (m, a, b, n) => UNIT_WORDS.has(a.toLowerCase()) && UNIT_WORDS.has(b.toLowerCase()) ? "convert " + n + " " + a + " to " + b : m],
  // money: tips and discounts
  [new RegExp("(" + NUM + ")\\s*(?:%|percent)\\s+tip\\s+(?:on|for|of)\\s+\\$?(" + NUM + ")", "gi"), "$1% of $2"],
  [new RegExp("\\btip\\s+(?:of\\s+)?(" + NUM + ")\\s*(?:%|percent)\\s+(?:on|for)\\s+\\$?(" + NUM + ")", "gi"), "$1% of $2"],
  [new RegExp("^(?:what is |whats )?(" + NUM + ")\\s*(?:%|percent)\\s+off\\s+(?:of\\s+)?\\$?(" + NUM + ")(?:\\s*(?:dollars|usd|bucks|euros|pounds))?\\s*\\??$", "i"), "$2 - $1% of $2"],
  // "how much is a 20% tip on 45" -> "what is 20% of 45"
  [/^how much (?:is|are|would be|will be)\s+(?:a\s+|an\s+|the\s+)?(?=[\d$(-])/i, "what is "],
  // percentage change and share
  [new RegExp("^(?:what is |whats )?(?:increase|raise|add)\\s+\\$?(" + NUM + ")\\s+(?:by|plus)\\s+(" + NUM + ")\\s*(?:%|percent)\\s*\\??$", "i"), "$1 + $2% of $1"],
  [new RegExp("^(?:what is |whats )?(?:decrease|reduce|lower|cut|drop)\\s+\\$?(" + NUM + ")\\s+by\\s+(" + NUM + ")\\s*(?:%|percent)\\s*\\??$", "i"), "$1 - $2% of $1"],
  [new RegExp("^what (?:percent|percentage|%)\\s+(?:is|of)\\s+(" + NUM + ")\\s+(?:is\\s+)?(?:of|out of|from|in)\\s+(" + NUM + ")\\s*\\??$", "i"), "$1 / $2 * 100"],
  [new RegExp("^what (?:percent|percentage|%)\\s+of\\s+(" + NUM + ")\\s+is\\s+(" + NUM + ")\\s*\\??$", "i"), "$2 / $1 * 100"],
  [new RegExp("^(" + NUM + ")\\s+(?:is|out of)\\s+what (?:percent|percentage|%)\\s+(?:of\\s+)?(" + NUM + ")\\s*\\??$", "i"), "$1 / $2 * 100"],
  [new RegExp("^(?:split|divide|share)\\s+\\$?(" + NUM + ")(?:\\s*(?:dollars|bucks|euros|pounds))?\\s+(?:evenly\\s+|equally\\s+)?(?:between|among|amongst|across|by|into|with)\\s+(" + NUM + ")(?:\\s+[a-z]+)?\\s*\\??$", "i"), "$1 / $2"],
  // "where is paris" -> which country a capital city belongs to
  [/^where(?:'s| is)\s+([a-z][a-z .'-]*?)\s*\??$/i, (m, c) => CAPITAL_CITIES.has(c.toLowerCase()) ? c + " is the capital of which country" : m],
  // "carbon's atomic number" -> "atomic number of carbon"
  [/\b([a-z]+)'s\s+(atomic number|atomic mass|atomic weight|chemical symbol|symbol|capital(?: city)?)\b/gi, "$2 of $1"],
  // dice parity: "probability of rolling an even number" is 3 faces of 6
  [/^(?:what is |whats )?(?:the )?(?:probability|chance|odds)\s+(?:of\s+)?(?:rolling|getting|throwing)\s+an?\s+(?:even|odd)(?:\s+number)?(?:\s+(?:on|with)\s+(?:a|one)\s+(?:die|dice|6-sided die))?\s*\??$/i, "3/6"],
  // algebra said in words: "find x: x/2 = 8", "solve x squared = 64"
  [/^(?:find|solve for|get|what is)\s+([a-z])\s*[:,]\s*(.+=.+)$/i, "solve $2"],
  [/\b([a-z])\s+(squared|cubed)\b/gi, (m, v, p, off, str) => /=/.test(str) ? v + "^" + (p.toLowerCase() === "squared" ? 2 : 3) : m],
  // text: "capitalize every word in ...", "remove duplicate words from ..."
  [/^(?:capitali[sz]e|uppercase)\s+(?:the\s+first\s+letter\s+of\s+)?(?:every|each|all(?:\s+the)?)\s+words?(?:\s+(?:in|of))?\s*:?\s+(.+)$/i, "title case: $1"],
  [/^(?:remove|delete|drop|strip)\s+(?:the\s+)?(?:duplicate|repeated|double)\s+words\s+(?:from|in)\s*:?\s+(.+)$/i, "dedupe words: $1"],
  // "1 mile is how many km", "5 foot 10 in cm"
  [new RegExp("^(" + NUM + ")\\s*([a-z/]+)\\s+(?:is|are|equals|=|makes)\\s+how many\\s+([a-z/]+)\\s*\\??$", "i"), "$1 $2 to $3"],
  [/\b(\d+)\s*(?:foot|feet|ft|')\s*(\d+(?:\.\d+)?)\s*(?:inches|inch|in|")?\s+(in|to|into|as)\s+([a-z]+)/gi, (m, f, i, p, u) => (Number(f) * 12 + Number(i)) + " inches " + p + " " + u],
  // "binary of 10" -> "10 to binary"
  [/^(?:what is |whats )?(?:the )?(binary|hex|hexadecimal|octal)(?: value| representation| form| number)?\s+(?:of|for)\s+(\d+)\s*\??$/i, "$2 to $1"],
  // dice: "odds of rolling two sixes"
  [/\b(?:odds|chance|chances|probability)\s+(?:of\s+)?(?:rolling|getting|throwing)\s+(two|2|double|three|3|four|4)\s+(?:sixes|6s|fives|5s|fours|4s|threes|3s|twos|2s|ones|1s)\b|\b(?:odds|chance|probability)\s+(?:of\s+)?(?:rolling\s+)?snake eyes\b/gi, (m, n) => "(1/6)^" + ({ two: 2, double: 2, three: 3, four: 4 }[String(n || "two").toLowerCase()] || n)],
  // fractions and multiples of a single number
  [new RegExp("\\bhalf of (" + NUM + ")\\b", "gi"), "($1 / 2)"],
  [new RegExp("\\b(?:a|one) third of (" + NUM + ")\\b", "gi"), "($1 / 3)"],
  [new RegExp("\\b(?:a|one) (?:quarter|fourth) of (" + NUM + ")\\b", "gi"), "($1 / 4)"],
  [new RegExp("\\btwo thirds of (" + NUM + ")\\b", "gi"), "($1 * 2 / 3)"],
  [new RegExp("\\bthree quarters of (" + NUM + ")\\b", "gi"), "($1 * 3 / 4)"],
  [new RegExp("^((?:what is|whats|calculate)\\s+)?(?:double|twice) (" + NUM + ")\\s*\\??$", "i"), "$12 * $2"],
  [new RegExp("^((?:what is|whats|calculate)\\s+)?triple (" + NUM + ")\\s*\\??$", "i"), "$13 * $2"],
  [new RegExp("^((?:what is|whats|calculate)\\s+)?halve (" + NUM + ")\\s*\\??$", "i"), "$1$2 / 2"],
  [new RegExp("^(?:what is |whats )?(\\d+)\\s*factorial\\s*\\??$", "i"), "$1!"],
  [/^(?:what is |whats )?factorial (\d+)\s*\??$/i, "$1!"],
  // largest / smallest of a list
  [new RegExp("^(?:what is |whats |which is |find |give me )?(?:the )?(?:biggest|largest|greatest|highest|max|maximum)(?: number| value| one)?(?: of| in| among| from)?(?: these| the)?(?: numbers| values)?[:\\s]+" + LIST + "\\s*\\??$", "i"), (m, l) => "max(" + l.match(/-?\d+(?:\.\d+)?/g).join(", ") + ")"],
  [new RegExp("^(?:what is |whats |which is |find |give me )?(?:the )?(?:smallest|lowest|least|min|minimum)(?: number| value| one)?(?: of| in| among| from)?(?: these| the)?(?: numbers| values)?[:\\s]+" + LIST + "\\s*\\??$", "i"), (m, l) => "min(" + l.match(/-?\d+(?:\.\d+)?/g).join(", ") + ")"],
  // number theory names
  [/\b(?:lowest|least|smallest) common (?:multiple|denominator)\b/gi, "lcm"],
  [/\b(?:greatest|highest|biggest|largest) common (?:divisor|factor|denominator)\b|\bhcf\b/gi, "gcd"],
  [/^(?:is|was)\s+(\d+)\s+(?:a\s+)?prime(?:\s+number)?\s*\??$/i, "is $1 prime"],
  [/^(?:is|was)\s+(\d+)\s+(?:a\s+)?(?:composite|non-?prime)(?:\s+number)?\s*\??$/i, "is $1 prime"],
  // combinatorics: "how many ways can i arrange 4 books"
  [/\b(?:ways?\s+(?:can\s+(?:i|you|we|they)\s+|to\s+|of\s+|there are to\s+)?(?:arrange|order|line up|sort|permute|seat)|arrangements of)\s+(\d+)(?:\s+[a-z]+)?/gi, "ways to arrange $1"],
  // sequences
  [/\b(?:what comes after|what(?:'s| is|s) next (?:after|in)|next (?:number )?after|continue)\s+(?=-?\d)/gi, "what comes next in "],
  // dates: "christmas 2026" -> an ISO date; "how long until" -> days until
  [new RegExp("\\b(" + HOLI_KEYS.join("|") + ")(?:\\s+(?:of|in))?\\s+(\\d{4})\\b", "gi"), (m, h, y) => { const d = S.HOLIDAYS[h.toLowerCase()] || S.HOLIDAYS[h.toLowerCase().replace(/(\w)s\b/, "$1's")]; return d ? y + "-" + pad2(d[0]) + "-" + pad2(d[1]) : m; }],
  [new RegExp("\\b(" + MONTHS + ")\\.?\\s+(\\d{1,2})(?:st|nd|rd|th)?,?\\s+(\\d{4})\\b", "gi"), (m, mo, d, y) => isoDate(y, mo, d) || m],
  [new RegExp("\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+(?:of\\s+)?(" + MONTHS + ")\\.?,?\\s+(\\d{4})\\b", "gi"), (m, d, mo, y) => isoDate(y, mo, d) || m],
  [/\bhow (?:long|much time|many days)\s+(?:is it\s+|is there\s+|do (?:i|we) have\s+|left\s+)?(?:until|till|til|before|to)\b/gi, "how many days until"],
  // definitions
  [/^(?:what is |whats |tell me )?the (?:meaning|definition) of\s+(.+?)\s*\??$/i, "define $1"],
  [/^(?:meaning|definition|def) of\s+(.+?)\s*\??$/i, "define $1"],
  [/^what (?:does|do)\s+(?:an?\s+|the\s+)?(.+?)\s+(?:mean|stand for)\s*\??$/i, "define $1"],
  [/^what do you mean by\s+(.+?)\s*\??$/i, "define $1"],
  // roman numerals read back to a number (uppercase only: "mix" is a word)
  [/^(?:(?:what|which) (?:number|value) is|what is|whats|convert|read)\s+([MDCLXVI]{2,})(?:\s+(?:in|to|as)\s+(?:numbers?|decimal|arabic|digits|an? number))?\s*\??$/, "from roman $1"],
  [/^([MDCLXVI]{2,})\s+(?:in|to|as|into)\s+(?:numbers?|decimal|arabic|digits|an? number)\s*\??$/, "from roman $1"],
  // algebra: "what is x if 3x = 12" -> "solve 3x = 12"
  [/^(?:what is|whats|find|solve for|calculate|get)\s+([a-z])\s+(?:if|when|given|where|such that)\s+(.+=.+)$/i, "solve $2"],
  // facts phrased as questions
  [/^(?:what is |whats |what's )?(?:the )?(?:chemical |atomic )?symbol (?:for|of)\s+/i, "what is the chemical symbol for "],
  [/^(?:what is|whats|what's|value of|the value of)\s+(?:the\s+)?(?:number\s+|constant\s+)?e\s*\??$/i, "what is euler number"],
  [/^how fast (?:is|does)\s+(?:the\s+)?(?:speed of\s+)?light(?:\s+travel|\s+go)?\s*\??$/i, "speed of light"],
  [/\b(?:g|gravity|the gravity|acceleration due to gravity|gravitational acceleration) (?:on|of|at) (?:the )?earth\b/gi, "standard gravity"],
  [/^how (?:big|large|wide) is (?:the )?(earth|planet earth)\s*\??$/i, "what is the radius of the earth"],
  [/^how (?:heavy|massive) is (?:the )?(earth|sun)\s*\??$|^how much does (?:the )?(earth|sun) weigh\s*\??$/i, (m, a, b) => "what is the mass of the " + (a || b).toLowerCase()],
  [/^(?:what is |whats )?(?:the )?value of\s+([a-z][a-z' ]*?)\s*\??$/i, (m, x) => F.facts("what is " + x).ok ? "what is " + x : m],
  // text transforms in everyday words
  [/^(?:flip|mirror|invert)\s+(.+?)(?:\s+(?:backwards?|around|over|the other way))?\s*$/i, "reverse $1"],
  [/^(reverse\s+.+?)\s+backwards?\s*$/i, "$1"],
  [/^(?:write|say|spell|put)\s+(.+?)\s+backwards?\s*$/i, "reverse $1"],
  [/^(?:make|put|turn|convert|write|change|set|type)\s+(.+?)\s+(?:(?:in|into|to|as)\s+)?(?:all\s+)?(?:caps|capitals|capital letters|block letters|upper ?case|uppercase|big letters)\s*$/i, "uppercase $1"],
  [/^(?:all caps|caps|capitalize everything in|shout)\s*:?\s+(.+)$/i, "uppercase $1"],
  [/^(?:make|put|turn|convert|write|change|set|type)\s+(.+?)\s+(?:(?:in|into|to|as)\s+)?(?:all\s+)?(?:small letters|small|lower ?case|lowercase|little letters|no caps)\s*$/i, "lowercase $1"],
];
// A small function described in plain English becomes a spec the synthesizer
// compiles ("a javascript function that adds two numbers" -> add(a, b) = a + b).
const FN_DESC = [
  [/\b(?:adds?|sums?|adding|summing)\s+(?:up\s+)?(?:two|2)\s+numbers\b/, "add(a, b) = a + b"],
  [/\b(?:subtracts?|subtracting)\s+(?:two|2)\s+numbers\b/, "subtract(a, b) = a - b"],
  [/\b(?:multiplies|multiply|multiplying)\s+(?:two|2)\s+numbers\b/, "multiply(a, b) = a * b"],
  [/\b(?:divides|divide|dividing)\s+(?:two|2)\s+numbers\b/, "divide(a, b) = a / b"],
  [/\b(?:averages?|mean of)\s+(?:two|2)\s+numbers\b|\baverage of (?:two|2) numbers\b/, "average(a, b) = (a + b) / 2"],
  [/\b(?:max(?:imum)?|larger|bigger|greater)\s+(?:of\s+)?(?:two|2)\s+numbers\b/, "larger(a, b) = a > b ? a : b"],
  [/\b(?:min(?:imum)?|smaller|lesser)\s+(?:of\s+)?(?:two|2)\s+numbers\b/, "smaller(a, b) = a < b ? a : b"],
  [/\bsquares?\s+(?:a|the)\s+number\b/, "square(x) = x * x"],
  [/\bcubes?\s+(?:a|the)\s+number\b/, "cube(x) = x * x * x"],
  [/\b(?:is|checks?\s+(?:if|whether)\s+(?:a\s+)?(?:number\s+)?(?:is\s+)?)\s*even\b/, "is_even(n) = n % 2 == 0"],
  [/\b(?:is|checks?\s+(?:if|whether)\s+(?:a\s+)?(?:number\s+)?(?:is\s+)?)\s*odd\b/, "is_odd(n) = n % 2 != 0"],
  [/\babsolute value\b/, "absolute(x) = x < 0 ? -x : x"],
  [/\bcelsius to fahrenheit\b/, "celsius_to_fahrenheit(c) = c * 9 / 5 + 32"],
  [/\bfahrenheit to celsius\b/, "fahrenheit_to_celsius(f) = (f - 32) * 5 / 9"],
];
function describedFunction(t) {
  const low = t.toLowerCase();
  if (!/\b(function|func|method|fn|program|code)\b/.test(low) || parseSpec(t)) return t;
  for (const [re, spec] of FN_DESC) if (re.test(low)) {
    const lang = (low.match(/\b(python|javascript|js|typescript|ts|rust|golang|go|java|c)\b/) || [])[1];
    return spec + (lang ? " in " + lang : "");
  }
  return t;
}

// algebra written in words: "x squared minus 9 equals 0" -> "solve x^2 - 9 = 0"
function wordEquation(t) {
  if (!/\b(equals|equal to|is equal to)\b/i.test(t) || !/(^|\s)[a-z](\s|$)/i.test(t.replace(/\b(a|i)\b/gi, ""))) return t;
  let e = " " + numberWords(t.toLowerCase()) + " ";
  e = e.replace(/^\s*(?:solve|find|what is|whats)\s+/, " ").replace(/\b(?:is equal to|equal to|equals)\b/g, " = ").replace(/\bsquared\b/g, "^2").replace(/\bcubed\b/g, "^3")
    .replace(/\bplus\b/g, " + ").replace(/\bminus\b/g, " - ").replace(/\btimes\b|\bmultiplied by\b/g, " * ").replace(/\bdivided by\b|\bover\b/g, " / ").replace(/\s+/g, " ").trim();
  return /^[\d\sa-z^+\-*/=.()]+$/.test(e) && (e.match(/[a-z]+/g) || []).every((w) => w.length === 1) && /=/.test(e) ? "solve " + e : t;
}
export function rephrase(input) {
  let t = String(input || "").trim();
  for (const [re, to] of REPHRASE) t = t.replace(re, to);
  t = describedFunction(wordEquation(t));
  return t.replace(/\s{2,}/g, " ").trim();
}

// Public: full response for an input. Always returns something (asks a question
// when confidence is low), so the chat never dead-ends.
const SOLVE_FOR = /^(?:find|solve for|get|what is)\s+[a-z]\s*[:,]/i; // "find x: x/2 = 8" is algebra, not a function spec
export function respond(input, model) {
  const raw = String(input || "").trim();
  if (!raw) return { skill: null, confidence: 0, alternatives: [], title: "Engine", body: "Type a request: a calculation, a conversion, a code task, a text transform, a regex, date math, or ask me to complete a sentence." };
  // read through typos first. A code spec is identifiers, so it is never "corrected".
  const spec = parseSpec(raw) && !SOLVE_FOR.test(raw);
  let fx;
  if (spec) fx = { text: raw, fixes: [], hybrid: raw, hybridFixes: [] };
  else {
    // texting shorthand first, then spelling, then casual phrasing -> canonical form
    const sa = slang(raw, true), sc = slang(raw, false);
    const f1 = fixTypos(sa.text, model), f2 = fixTypos(sc.text, model);
    fx = { text: rephrase(f1.text), fixes: [...sa.fixes, ...f1.fixes], hybrid: rephrase(f2.hybrid), hybridFixes: [...sc.fixes, ...f2.hybridFixes], plain: f1.text, plainHybrid: f2.hybrid };
  }
  const s = fx.text;
  const ranked = score(s);
  if (!ranked.length) {
    const low = s.toLowerCase();
    // 1) A recognized-but-out-of-scope build request (a whole app/game/etc).
    const thing = classifyBuild(low);
    if (thing) {
      return {
        skill: null, confidence: 0, alternatives: [], smart: true,
        title: "That is a whole " + thing + ", not a single function",
        body: "I understand: you want to build a **" + thing + "**. Here is the honest boundary, and I will not pretend otherwise. This engine has no AI model. It synthesizes one function at a time from a spec — from scratch, in 7 languages — with real recursion and loops. A complete " + thing + " is a full application, and writing one from an open-ended description is exactly what a trained model does, not a rule-based engine.\n\nTwo real ways forward:\n- Turn on **Smart mode** (toggle, top right) to use your own Gemini key for open-ended requests like this one.\n- Or hand me the pieces as function specs and I will generate each right now, for example: `move(pos, velocity, dt) = pos + velocity * dt`, `clamp(x, lo, hi) = x < lo ? lo : (x > hi ? hi : x)`, `score(hits, misses) = hits - misses`.",
      };
    }
    // 2) Otherwise: say which words it did recognize, then ask to disambiguate.
    const hits = recognizedWords(low);
    const nameMap = { calc: "**calculate**", convert: "**convert**", text: "**transform text**", code: "**generate code**", date: "**date math**", regex: "**build a regex**", facts: "**look up a fact**" };
    const recognized = hits.length ? "I recognized words pointing at: " + hits.map((h) => nameMap[h]).join(", ") + ". Say which one and I will run it exactly.\n\n" : "";
    // Only offer a continuation when the text really reads like an unfinished sentence.
    const words = s.split(/\s+/).length;
    const midSentence = /(?:,|\b(?:the|a|an|of|to|and|or|but|in|on|with|for|is|are|was|that|which|because|as|by|from|my|your|their))$/i.test(s.trim()) && words >= 3 && !/\d/.test(s) && !BUILD_VERB.test(low) && !/^(calculate|convert|generate|reverse|solve|find|compute|show|give|list|sort|count|please|what|whats|how|define|explain|is|are|was|does|do|did|can|could|should|would|will|which|who|whom|whose|where|when|why|tell|put|flip|turn|change|make|meaning|symbol|value)\b/.test(low);
    const cont = (model && midSentence) ? complete(model, s, 16) : "";
    return {
      skill: null, confidence: 0, alternatives: [],
      title: "Not sure yet",
      body: recognized + "I could not confidently match that to one of my skills, and I do not guess like a language model. Tell me which you want: **calculate**, **convert**, **generate code**, **transform text**, **build a regex**, or **date math** — or turn on **Smart mode** to let your own Gemini key read a free-form request." + (cont ? "\n\nYou seem mid-sentence; my statistical continuation is below." : ""),
      pre: cont || null,
    };
  }
  const top = ranked[0];
  const total = ranked.reduce((a, r) => a + r.score, 0);
  const conf = Math.round((top.score / total) * 100) / 100;
  // skills that transform the user's own content get it verbatim (only command
  // words corrected); CSV data is never touched; everything else reads the fixed text.
  const VERBATIM = new Set(["listops", "text", "encode", "regex", "jsonquery", "setops", "matrix", "logic", "color"]);
  const useRaw = top.skill === "data" || top.skill === "spelling"; // a spelling question is about the user's exact letters
  const inputFor = useRaw ? raw : VERBATIM.has(top.skill) ? fx.hybrid : s;
  const applied = useRaw ? [] : VERBATIM.has(top.skill) ? fx.hybridFixes : fx.fixes;
  const res = run(top.skill, inputFor, model);
  const composed = say(top.skill, res, inputFor, model);
  const before = useRaw ? inputFor : VERBATIM.has(top.skill) ? fx.plainHybrid : fx.plain;
  if (before != null && before !== inputFor) composed.note = "Understood as \u201c" + inputFor + "\u201d." + (composed.note ? " " + composed.note : "");
  if (applied.length) composed.note = "Read " + applied.map((f) => f.to === "(dropped)" ? "past \u201c" + f.from + "\u201d" : "\u201c" + f.from + "\u201d as \u201c" + f.to + "\u201d").join(", ") + "." + (composed.note ? " " + composed.note : "");
  return {
    skill: top.skill,
    confidence: conf,
    why: top.why,
    alternatives: ranked.slice(1, 3).map((r) => ({ skill: r.skill, why: r.why })),
    fixed: applied,
    ...composed,
  };
}

// ---------------------------------------------------------------------------
// Agentic layer (deterministic). A request can be a PLAN of several steps
// ("calculate 15% of 240 then multiply it by 3 then is it prime"): it is split
// into steps, each step runs through the normal engine, and "it" / "that" /
// "the result" in a later step is bound to the previous step's value. A session
// remembers the last request, so a follow-up ("what about japan", "now in feet",
// "same in rust") re-runs it with one slot swapped. No model: explicit rules, and
// every rewrite is shown to the user.
// ---------------------------------------------------------------------------
const SEQ = /\s*,?\s*\b(?:and then|then|after that|afterwards|and finally|finally|next)\b[\s,:]*/i;
const CMD_HEAD = "(?:convert|calculate|compute|what(?:'s| is| are)|whats|write|generate|implement|reverse|uppercase|lowercase|count|solve|factori[sz]e|tell me|give me|encode|decode|how many|how much|define|explain|is\\s+(?:it|\\d)|check)\\b";
const AND_CMD = new RegExp("\\s*(?:;|,|\\band also\\b|\\balso\\b|\\band\\b)\\s*(?=" + CMD_HEAD + ")", "i");
const REF = /\b(?:the result|the answer|that number|the number|the value|that value|the output|it|that|this|them)\b/i;
const LEAD_OP = /^(?:plus|minus|times|multiplied by|divided by|over|to the power of|squared|cubed|mod|modulo|and\s+(?:add|subtract|multiply|divide))\b/i;

// Public: split a request into executable steps. A split is only accepted when
// every piece can run on its own (or refers back with "it"), so prose such as
// "Maya saved $45, then $62, then $58" stays one step.
export function splitSteps(input, model) {
  const s = String(input || "").trim();
  if (!s || parseSpec(s) || /[[{]/.test(s) || /\n/.test(s)) return [s];
  // text to check or transform ("spell check: ... then ...", "proofread: ...") is content, never steps
  if (/^(?:please\s+)?(?:spell ?check|spellcheck|proofread|(?:check|fix|correct) (?:the |my )?spelling(?: of| in)?|reverse|uppercase|lowercase|count (?:the )?words(?: in)?)\b[^:]*:/i.test(s)) return [s];
  const pieces = [];
  for (const part of s.split(SEQ)) for (const sub of part.split(AND_CMD)) if (sub && sub.trim()) pieces.push(sub.trim());
  if (pieces.length < 2) return [s];
  const runnable = (q, i) => (i > 0 && (REF.test(q) || LEAD_OP.test(q))) || score(fixTypos(q, model).text).length > 0;
  return pieces.every(runnable) ? pieces : [s];
}

// The single value a step produced, so the next step can use it.
function valueOf(r) {
  const x = r && r.result;
  if (!r || !r.skill || !x || x.ok === false) return null;
  const numIn = (t) => { const m = String(t).match(/(-?\d+(?:\.\d+)?)\s*$/); return m ? Number(m[1]) : null; };
  switch (r.skill) {
    case "convert": return { num: x.value, unit: x.to };
    case "units": return { num: x.value, unit: x.unit };
    case "facts": return x.capital ? { text: x.capital } : x.sym ? { text: x.name, num: x.z } : x.unit ? { num: x.value } : null;
    case "text": return typeof x === "number" ? { num: x } : { text: String(x) };
    case "encode": return { text: String(x.value) };
    case "codegen": return x.code ? { text: x.code, code: true } : null;
    case "numbertheory": { const n = x.kind === "isprime" || x.kind === "factorize" ? null : numIn(x.text); return n != null ? { num: n } : { text: x.text }; }
    case "base": return { text: String(x.value) };
    default:
      if (typeof x.value === "number") return { num: x.value };
      if (r.pre) return { text: String(r.pre) };
      return null;
  }
}
const fmtNum = (n) => String(Math.round(n * 1e9) / 1e9);

// Bind "it" / "that" / "the result" (or a leading operator) to the previous value.
function bindRefs(q, v) {
  if (!v) return q;
  if (v.num != null) {
    const n = fmtNum(v.num);
    if (LEAD_OP.test(q)) return n + " " + q.replace(/^and\s+/i, "");
    const qty = v.unit ? n + " " + v.unit : n;
    const OPS = [[/^(?:double)\s+(?:it|that|the result)\b/i, "2 * " + n], [/^(?:triple)\s+(?:it|that|the result)\b/i, "3 * " + n], [/^(?:halve)\s+(?:it|that|the result)\b/i, n + " / 2"],
      [/^(?:round)\s+(?:it|that|the result)\b/i, "round(" + n + ")"], [/^(?:square root of|sqrt(?: of)?)\s+(?:it|that|the result)\b/i, "sqrt(" + n + ")"], [/^(?:square)\s+(?:it|that|the result)\b/i, "(" + n + ")^2"],
      [/^(?:cube)\s+(?:it|that|the result)\b/i, "(" + n + ")^3"], [/^(?:negate)\s+(?:it|that|the result)\b/i, "-(" + n + ")"]];
    for (const [re, expr] of OPS) if (re.test(q)) return q.replace(re, expr);
    // "convert it to feet" keeps the unit; arithmetic ("multiply it by 3") uses the bare number
    const useQty = v.unit && /\b(?:convert|to|in|into|as)\b/i.test(q) && !/\b(?:multiply|divide|add|subtract|plus|minus|times)\b/i.test(q);
    return q.replace(REF, useQty ? qty : n);
  }
  if (v.text != null && !v.code) return q.replace(REF, '"' + v.text.replace(/"/g, "'") + '"'); // quoted, so a text tool keeps it verbatim
  return q;
}

// A follow-up re-runs the last request with one slot swapped. Returns the
// rewritten request, or null when the input is not a follow-up.
const LANG_RE = /^(python|javascript|js|typescript|ts|rust|go|golang|java|c)$/;
function followUp(q, last) {
  if (!last) return null;
  const low = q.toLowerCase().trim().replace(/[?.!]+$/, "");
  const prev = last.input;
  // "in feet", "now in rust", "and to celsius", "what about in kelvin"
  let m = low.match(/^(?:(?:and|now|ok|okay|so|then|what about|how about|same)\s+)*(?:in|to|into|as)\s+([a-z/°]+(?:\s+numerals?)?)$/);
  if (m) {
    const t = m[1];
    if (last.skill === "codegen" && LANG_RE.test(t)) return /\bin\s+(python|javascript|js|typescript|ts|rust|go|golang|java|c)\b/i.test(prev) ? prev.replace(/\bin\s+(python|javascript|js|typescript|ts|rust|go|golang|java|c)\b/i, "in " + t) : prev + " in " + t;
    if (last.skill === "convert" || last.skill === "base") return /\b(?:to|in|into|as)\s+[a-z/°]+(?:\s+numerals?)?\s*$/i.test(prev) ? prev.replace(/\b(?:to|in|into|as)\s+[a-z/°]+(?:\s+numerals?)?\s*$/i, "to " + t) : prev + " to " + t;
    if (last.skill === "units") return prev.replace(/\s+in\s+[a-z/°]+\s*$/i, "") + " in " + t;
    return null;
  }
  // "what about japan", "how about 10 km", "same for gold", "and 97?"
  m = low.match(/^(?:and\s+)?(?:what about|how about|what of|same for|same with|and for|and)\s+(?:the\s+)?(.+)$/);
  if (!m) return null;
  const x = m[1].trim();
  const qty = x.match(/^(-?\d+(?:\.\d+)?)\s*([a-z/°]+)$/);
  if (qty && /-?\d+(?:\.\d+)?\s*[a-z/°]+/i.test(prev)) return prev.replace(/-?\d+(?:\.\d+)?\s*[a-z/°]+/i, x);
  if (/^-?\d+(?:\.\d+)?$/.test(x) && /-?\d+(?:\.\d+)?/.test(prev)) return prev.replace(/-?\d+(?:\.\d+)?/, x);
  if (LANG_RE.test(x) && last.skill === "codegen") return followUp("in " + x, last);
  if (F.CAPITALS[x] && last.skill === "facts") {
    const k = Object.keys(F.CAPITALS).sort((a, b) => b.length - a.length).find((c) => new RegExp("\\b" + c + "\\b", "i").test(prev));
    return k ? prev.replace(new RegExp("\\b" + k + "\\b", "i"), x) : "capital of " + x;
  }
  if (last.skill === "facts" && F.element(x).ok) return "element " + x;
  if (last.skill === "facts" && F.constant(x).ok) return x;
  if (last.skill === "knowledge") return "what is " + x;
  if (last.skill === "text" || last.skill === "encode") { // same transform, new content
    const words = prev.trim().split(/\s+/), lead = [];
    for (const w of words) { if (ENGINE_SET.has(w.toLowerCase().replace(/[:,]$/, "")) || /^(the|a|an|to|in|of)$/i.test(w)) lead.push(w.replace(/:$/, "")); else break; }
    if (!lead.length) return null;
    const tail = (prev.match(/\s+(?:to|into|in|as)\s+(?:(?:camel|snake|kebab|constant|title|upper|lower) ?case|uppercase|lowercase|slug)\s*$/i) || [""])[0];
    return lead.join(" ") + ' "' + x.replace(/"/g, "'") + '"' + tail;
  }
  return null;
}

// Public: run a list of steps in order, feeding each step's value to the next.
// `session.last` carries context across calls (follow-ups).
export function runSteps(steps, model, session = {}) {
  const out = [];
  let prev = session.last || null;
  for (const step of steps) {
    let q = step, how = null;
    const fu = followUp(q, prev);
    if (fu) { q = fu; how = "follow-up to your last request"; }
    else if (prev && (REF.test(q) || LEAD_OP.test(q)) && prev.value) {
      const b = bindRefs(q, prev.value);
      if (b !== q) { q = b; how = "using the previous result"; }
    }
    const r = respond(q, model);
    if (how) r.note = "Read as “" + q + "” (" + how + ")." + (r.note ? " " + r.note : "");
    out.push({ step, ran: q, how, r });
    if (r.skill) prev = { input: q, skill: r.skill, value: valueOf(r) };
  }
  session.last = prev;
  return out;
}

// Public: the agent entry point the tab uses. One step -> a normal answer;
// several -> a plan with every step's answer.
export function agent(input, model, session = {}) {
  const raw = String(input || "").trim();
  if (!raw) return respond(raw, model);
  let base = parseSpec(raw) && !SOLVE_FOR.test(raw) ? raw : fixTypos(slang(raw, false).text, model).hybrid; // fix "thne" -> "then" without touching content
  // "capitals of france, spain and germany" asks one question per country
  const caps = base.match(/^(?:what are |whats |tell me |give me |list )?(?:the )?capitals? (?:cities )?of\s+(.+?)\s*\??$/i);
  if (caps) { const cs = caps[1].split(/\s*,\s*(?:and\s+)?|\s+and\s+/).filter(Boolean); if (cs.length > 1) base = cs.map((c) => "what is the capital of " + c).join(" and "); }
  const steps = splitSteps(base, model);
  const done = runSteps(steps.length > 1 ? steps : [steps[0] === base ? raw : steps[0]], model, session);
  if (done.length === 1) return done[0].r;
  const ok = done.filter((d) => d.r.skill).length;
  return {
    skill: "plan", agent: true, confidence: ok / done.length, alternatives: [], steps: done,
    title: "Plan: " + done.length + " steps",
    body: "I split your request into **" + done.length + " steps** and ran them in order" + (done.some((d) => d.how === "using the previous result") ? ", feeding each result into the next where you said “it” or “that”" : "") + ". " + (ok === done.length ? "All " + ok + " succeeded." : ok + " of " + done.length + " succeeded; the others say why."),
  };
}

// Re-export the predictor bits the UI wants for live autocomplete.
export { predictNext, suggestWord };
