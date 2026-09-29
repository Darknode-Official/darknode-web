// Universal Engine — the testable tab. Thin DOM layer over the engine modules.
// A chat UI that FEELS like an AI (typed request -> full written answer, live
// next-word prediction as you type, confidence and "did you mean" alternatives)
// while running 100% on-device with NO AI: deterministic skills + an n-gram
// predictor trained on a bundled corpus. Reuses the AWS console page classes.
import { CORPUS } from "/js/engine/corpus.js";
import { respond, route, predictWords, fixTypos, buildModel, learn, agent, runSteps } from "/js/engine/engine.js";
import { smartInterpret } from "/js/engine/smart.js";
import { loadLexicon } from "/js/engine/lexicon.js";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// tiny markdown: **bold**, `code`, "# heading" lines, newlines -> <br>, and
// ```lang fenced blocks -> <pre> with a Copy button (Smart mode writes code)
const mdInline = (s) => esc(s).replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, '<code>$1</code>')
  .replace(/^#{1,6} +(.+)$/gm, "<b>$1</b>").replace(/\n/g, "<br>");
const md = (s) => {
  // split() with two groups yields [text, lang, code, text, lang, code, ..., text]
  const parts = String(s == null ? "" : s).split(/```([\w+#.-]*)[ \t]*\n?([\s\S]*?)(?:```|$)/);
  let html = "";
  for (let i = 0; i < parts.length; i += 3) {
    html += mdInline((parts[i] || "").replace(/^\n+|\n+$/g, ""));
    if (i + 2 < parts.length) {
      const lang = parts[i + 1] || "", code = (parts[i + 2] || "").replace(/\n+$/, "");
      html += '<div class="ue-code"><div class="ue-code-bar"><span>' + esc(lang || "code") +
        '</span><button type="button" class="ue-copy">Copy</button></div><pre><code>' + esc(code) + '</code></pre></div>';
    }
  }
  return html;
};

const SOURCES = [
  ["Calculator", "variables, multi-arg functions, factorial, %, hex/binary — parsed and evaluated exactly"],
  ["Math in plain English", "understands spelled-out numbers and phrases: 'twenty percent of two hundred plus thirty'"],
  ["Word problems", "reads a worded problem, extracts the numbers, and shows the operation it used"],
  ["Sequences", "finds the pattern (arithmetic, geometric, quadratic, Fibonacci-like) and extends it"],
  ["Truth tables", "full truth table for any boolean expression: and, or, not, xor, ->, <->"],
  ["Set operations", "union, intersection, difference, symmetric difference of two sets"],
  ["Linear algebra", "matrices and vectors: determinant, inverse, product, transpose, dot, cross, magnitude"],
  ["Unit arithmetic", "add and subtract mixed units: 5 km + 300 m, 2 hours + 45 minutes"],
  ["Combinatorics", "combinations, permutations, arrangements, and clearly-stated probability"],
  ["Equation solver", "solves linear and quadratic equations in closed form"],
  ["Statistics", "mean, median, mode, variance, std dev, quartiles over a list"],
  ["Number theory", "prime test, factorization, gcd/lcm, nth prime, nth Fibonacci, first N primes"],
  ["Spelling", "a 64,000-word English dictionary with a noisy-channel corrector (keyboard slips, sound-alike letters, suffix rules, the word before): spell a word, spell-check or proofread a sentence, pick between two spellings, spell out a number"],
  ["Program library", "52 complete, hand-written programs, each compiled and run before shipping (tools/check-programs.sh): snake, pong, tic-tac-toe, hangman, quiz, to-do app, calculator, stopwatch, HTTP servers and REST APIs, file and JSON I/O, linked lists, trees, stacks, queues, sorts and more, in up to 12 languages"],
  ["Code generator", "synthesizes real code from a spec or formula across 7 languages: parses your spec to an AST and compiles it, with inferred int/float/bool types, multi-step let bindings, piecewise conditionals, recursion, iterative sum/prod/count loops and math calls (no stored snippets)"],
  ["Data / CSV", "parse a CSV and summarize every column, numeric or text"],
  ["Base convert", "decimal, hex, binary, octal, any base 2-36, and Roman numerals"],
  ["Unit convert", "length, mass, time, data, speed, temperature"],
  ["Encode / hash", "base64, hex, url, rot13, binary, morse, crc32, fnv1a, djb2"],
  ["Text tools", "case, camel/snake/kebab, slug, counts, word frequency, extract emails/urls"],
  ["Regex builder + tester", "build tested patterns, or run one against sample text"],
  ["Color convert", "hex, rgb and hsl, all three at once"],
  ["JSON query", "pull any value out of a JSON blob by path, e.g. .users[0].name"],
  ["Date math", "days between, add days, weekday, leap year, day of year — in UTC"],
  ["Knowledge base", "sourced definitions of 45+ CS and security terms, never invented"],
  ["Fact packs", "the capital of every country, all 118 elements (symbol, number, mass, category), and physical, math and astronomical constants — curated, never invented"],
  ["Predictor", "n-gram / Markov next-word prediction over the corpus"],
  ["Agent", "multi-step plans (\"... then ... then ...\"), passes each result on as \"it\", and remembers the last request for follow-ups like \"what about japan\" or \"now in rust\""],
];

const EXAMPLES = [
  "make a snake game",
  "tic tac toe in python",
  "http server in go",
  "sqrt(144) + gcd(48, 60) + 5!",
  "r = 3; pi * r^2",
  "solve x^2 - 5x + 6 = 0",
  "stats 4 8 15 16 23 42",
  "factorize 360",
  "255 to hex",
  "write a binary search in go",
  "write a function f(x) = 3x^2 - 2x + 1 in rust",
  "is_even(n) that returns n % 2 == 0",
  "clamp(x) = x < 0 ? 0 : (x > 100 ? 100 : x)",
  "root(a,b,c) = let d = b*b - 4*a*c; (-b + sqrt(d))/(2*a)",
  "gcd(a, b) = b == 0 ? a : gcd(b, a % b)",
  "fact(n) = prod(i, 1, n, i)",
  "fib(n) = n < 2 ? n : fib(n-1) + fib(n-2)",
  "convert #ff8800 to rgb",
  "what is a container",
  "get .users[0].name in {\"users\":[{\"name\":\"Ada\"}]}",
  "is 2024 a leap year",
  "analyze csv: name,age\\nAda,36\\nBob,41\\nAda,36",
  "Maya saved $45, then $62, then $58. How much in total?",
  "twenty percent of two hundred plus thirty",
  "what comes next in 2, 5, 8, 11",
  "truth table for (a and b) or not c",
  "union of {1,2,3} and {2,3,4}",
  "20% off $80",
  "determinant of [[1,2],[3,4]]",
  "5 km + 300 m in miles",
  "10 choose 3",
  "complete: the goal is to write code that is",
  "how much is 15 percent of 240",
  "how many km in 5 miles",
  "whats the square root of 2",
  "how many days until christmas",
  "how many letters in mississippi",
  "what is a hash map",
  "what is the capital of australia",
  "what is element 79",
  "speed of light",
  "what is planck's constant",
  "calculate 15 percent of 240 then multiply it by 3 then is it prime",
  "what is the capital of france then reverse it",
  "wat is half of 90",
  "flip hello world backwards",
  "how long until halloween",
  "sort these numbers 42 7 19 3",
  "md5 of hello",
  "javascript function that adds two numbers",
  "how do you spell recieve",
  "spell check: Teh wether is realy nice tomorow",
  "is it seperate or separate",
  "spell out 1234",
  "how many days are in february 2024",
  "increase 80 by 25%",
];

export function renderEngine(main) {
  // the dictionary is normally preloaded during boot; this covers a skipped or failed preload
  const conn = navigator.connection || {};
  if (!conn.saveData) loadLexicon();
  // the predictor: bundled corpus + glossary + command phrasebook + these examples,
  // then adapted to this viewer's own past requests (kept only in their browser)
  const model = buildModel(CORPUS, EXAMPLES.join(" .\n"));
  const HKEY = "di_history";
  let history = [];
  try { history = JSON.parse(localStorage.getItem(HKEY) || "[]"); if (!Array.isArray(history)) history = []; } catch (_) { history = []; }
  for (const h of history) if (typeof h === "string") learn(model, h, 3);
  function remember(s) {
    const clean = fixTypos(s, model).text; // learn the corrected text, never the typo
    learn(model, clean, 3);
    history.push(clean); if (history.length > 200) history = history.slice(-200);
    try { localStorage.setItem(HKEY, JSON.stringify(history)); } catch (_) {}
  }
  const log = [];
  const session = {}; // the agent's short-term memory: last request, for follow-ups and "it"

  main.innerHTML =
    '<style>' +
    '.ue-wrap{max-width:900px}' +
    '.ue-src{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px;margin:12px 0 18px}' +
    '.ue-src .arse-card{padding:10px 12px}' +
    '.ue-log{display:flex;flex-direction:column;gap:12px;margin:14px 0}' +
    '.ue-msg{max-width:88%;padding:11px 14px;border-radius:12px;border:1px solid var(--line);line-height:1.5}' +
    '.ue-me{align-self:flex-end;background:var(--acc);color:#04120a;border-color:transparent}' +
    '.ue-bot{align-self:flex-start;background:transparent}' +
    '.ue-bot .ue-title{font-weight:700;color:var(--acc);font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px}' +
    '.ue-bot pre{background:rgba(127,127,127,.12);border:1px solid var(--line);border-radius:8px;padding:10px 12px;overflow:auto;margin:8px 0 4px;font-size:.82rem}' +
    '.ue-meta{font-size:.7rem;color:var(--mut);margin-top:6px}' +
    '.ue-code{margin:8px 0 4px}.ue-code pre{margin:0;border-top-left-radius:0;border-top-right-radius:0;white-space:pre}' +
    '.ue-code-bar{display:flex;justify-content:space-between;align-items:center;font-size:.7rem;color:var(--mut);padding:4px 8px 4px 12px;border:1px solid var(--line);border-bottom:0;border-radius:8px 8px 0 0}' +
    '.ue-copy{font:inherit;color:inherit;background:transparent;border:1px solid var(--line);border-radius:6px;padding:2px 8px;cursor:pointer}' +
    '.ue-msg.ue-bot:has(.ue-code){max-width:100%;width:100%;box-sizing:border-box}' +
    '.ue-alt{display:inline-block;margin-left:6px;text-decoration:underline;cursor:pointer;color:var(--mut)}' +
    '.ue-pred{display:flex;gap:6px;flex-wrap:wrap;min-height:26px;margin:2px 0 8px}' +
    '.ue-pred .chip{cursor:pointer}' +
    '.ue-mode{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:2px 0 8px;font-size:.8rem}' +
    '.ue-switch{display:inline-flex;align-items:center;gap:7px;cursor:pointer;user-select:none}' +
    '.ue-switch input{appearance:none;-webkit-appearance:none;width:34px;height:19px;border-radius:11px;background:rgba(127,127,127,.4);position:relative;cursor:pointer;transition:background .15s;flex:none}' +
    '.ue-switch input:checked{background:var(--acc)}' +
    '.ue-switch input::after{content:"";position:absolute;top:2px;left:2px;width:15px;height:15px;border-radius:50%;background:#fff;transition:left .15s}' +
    '.ue-switch input:checked::after{left:17px}' +
    '.ue-modehint{color:var(--mut)}' +
    '.ue-bar{display:flex;gap:8px;align-items:flex-end}' +
    '.ue-bar textarea{flex:1;min-height:46px;max-height:160px;padding:11px 12px;border:1px solid var(--line);border-radius:10px;background:transparent;color:inherit;font:inherit;resize:vertical}' +
    '.ue-send{padding:11px 18px;border:none;border-radius:10px;background:var(--acc);color:#04120a;font-weight:700;cursor:pointer}' +
    '</style>' +
    '<div class="ue-wrap">' +
    '<h1 class="pg-h1">Deterministic Intelligence <span style="font-size:.5em;vertical-align:middle;opacity:.6;font-weight:600">DI</span></h1>' +
    '<p class="muted pg-sub">The deterministic counterpart to AI. Where an AI predicts an answer from a trained model, <b>DI</b> computes one from rules, synthesis, and sourced facts &mdash; with <b>no AI and no neural network</b>, entirely on your device. It routes your request across a dozen built-in sources, shows its confidence, and predicts as you type. Specific requests get exact, tested results; vague ones get a clarifying question, never a confident guess. It reads through typos itself (a keyboard-aware spelling corrector over its own vocabulary) and tells you what it corrected. Turn on <b>Smart mode</b> for open-ended requests and code: it works online through Darknode&rsquo;s servers, and DI still computes and verifies the answer whenever it can.</p>' +
    '<div class="ue-src">' + SOURCES.map(([n, d]) =>
      '<div class="arse-card"><div class="an">' + esc(n) + '</div><div class="ad">' + esc(d) + '</div></div>').join("") + '</div>' +
    '<div class="cs-filter" id="ueEx" style="margin-bottom:6px">' +
      EXAMPLES.map((e) => '<button class="chip" data-ex="' + esc(e) + '">' + esc(e) + '</button>').join("") + '</div>' +
    '<div class="ue-log" id="ueLog"></div>' +
    '<div class="ue-pred" id="uePred"></div>' +
    '<div class="ue-mode">' +
      '<label class="ue-switch"><input type="checkbox" id="ueSmart"><span>Smart mode</span></label>' +
      '<span class="ue-modehint" id="ueModeHint"></span>' +
    '</div>' +
    '<div class="ue-bar">' +
      '<textarea id="ueIn" placeholder="Ask for a calculation, a conversion, code, a regex, date math, or type a sentence to see it predict…"></textarea>' +
      '<button class="ue-send" id="ueSend">Run</button>' +
    '</div>' +
    '<p class="ue-meta">Predictions come from an n-gram model trained on the bundled corpus, glossary and a command phrasebook, then adapted to your own past requests (stored only in this browser). Typos are corrected against the engine vocabulary before predicting. Everything here is inspectable and reproducible.</p>' +
    '</div>';

  const logEl = main.querySelector("#ueLog");
  const predEl = main.querySelector("#uePred");
  const inEl = main.querySelector("#ueIn");

  const bubble = (cls, html) => { const d = document.createElement("div"); d.className = "ue-msg " + cls; d.innerHTML = html; logEl.appendChild(d); d.scrollIntoView({ block: "end" }); return d; };

  // q: the request this answers, so DI can offer to hand it to Smart mode
  function renderBot(r, q) {
    let html = '<div class="ue-title">' + esc(r.title || "Engine") + '</div><div>' + md(r.body || "") + '</div>';
    if (r.pre != null && r.pre !== "") html += '<pre>' + esc(r.pre) + '</pre>';
    if (r.code) html += md("```" + (r.lang || "") + "\n" + r.code + "\n```"); // code block with a Copy button
    if (r.note) html += '<div class="ue-meta">' + esc(r.note) + '</div>';
    const bits = [];
    if (r.skill) bits.push("source: " + esc(r.skill) + (r.confidence ? " (" + Math.round(r.confidence * 100) + "% confident)" : ""));
    if (r.why) bits.push(esc(r.why));
    let meta = bits.length ? '<div class="ue-meta">' + bits.join(" · ") + '</div>' : "";
    if (r.alternatives && r.alternatives.length) {
      meta += '<div class="ue-meta">Did you mean: ' + r.alternatives.map((a) =>
        '<span class="ue-alt" data-alt="' + esc(a.skill) + '">' + esc(a.skill) + '</span>').join("") + '</div>';
    }
    // DI could not write it (a scaffold, or an app outside its library): offer Smart mode in one click
    if (q && !smartOn() && (r.smart || (r.result && r.result.kind === "skeleton")))
      meta += '<div class="ue-meta"><button type="button" class="ue-copy" data-smartq="' + esc(q) + '">Write it with Smart mode</button></div>';
    bubble("ue-bot", html + meta);
  }

  const smartEl = main.querySelector("#ueSmart");
  const hintEl = main.querySelector("#ueModeHint");

  function smartOn() { return !!(smartEl && smartEl.checked); }
  function updateHint() {
    if (!hintEl) return;
    if (!smartOn()) { hintEl.textContent = "Deterministic: exact, verified, on-device. No AI."; return; }
    hintEl.textContent = "Smart mode (online): understands open-ended requests and writes code; DI still computes and verifies what it can.";
  }

  // restore saved mode
  try { if (smartEl && localStorage.getItem("di_smart") === "1") smartEl.checked = true; } catch (_) {}
  updateHint();
  if (smartEl) smartEl.addEventListener("change", () => {
    try { localStorage.setItem("di_smart", smartEl.checked ? "1" : "0"); } catch (_) {}
    updateHint();
  });

  async function send(txt) {
    const s = (txt != null ? txt : inEl.value).trim();
    if (!s) return;
    bubble("ue-me", md(s));
    inEl.value = "";
    updatePred();

    remember(s);
    if (!smartOn()) {
      const r = agent(s, model, session); // plans multi-step requests, resolves "it" and follow-ups
      log.push({ q: s, r });
      show(r, s);
      return;
    }
    await smartRun(s);
  }

  async function smartRun(s) {
    // Smart mode: the server PLANS the steps (with the recent conversation as
    // context); DI runs and verifies every step it can. Smart mode's own words
    // are shown only for what DI has no rule for, and are labelled unverified.
    const pend = bubble("ue-bot", '<div class="ue-title">Smart mode</div><div class="ue-meta">Thinking…</div>');
    let out;
    try { out = await smartInterpret(s, log.slice(-6).map((h) => ({ q: h.q, a: summary(h.r) }))); } catch (e) { out = { ok: false, error: (e && e.message) || "Smart mode failed." }; }
    if (pend && pend.parentNode) pend.parentNode.removeChild(pend);

    if (!out.ok) {
      const r = { title: "Smart mode", body: out.error, note: "You can still use DI without Smart mode: just turn the toggle off." };
      log.push({ q: s, r });
      renderBot(r);
      return;
    }
    const done = out.steps && out.steps.length ? runSteps(out.steps, model, session) : [];
    const verified = done.filter((d) => d.r.skill);
    for (const d of done) d.r.note = (d.r.note ? d.r.note + " " : "") + "Smart mode planned \u201c" + d.step + "\u201d; DI " + (d.r.skill ? "computed it deterministically." : "has no rule for it.");
    if (done.length === 1 && verified.length === 1 && !out.answer) { log.push({ q: s, r: done[0].r }); show(done[0].r); return; }
    if (done.length) {
      const plan = { agent: true, steps: done, title: "Smart plan: " + done.length + " step" + (done.length === 1 ? "" : "s"), body: "Smart mode planned **" + done.length + "** step" + (done.length === 1 ? "" : "s") + "; DI verified **" + verified.length + "** of them." };
      log.push({ q: s, r: plan });
      show(plan);
    }
    if (out.answer || !done.length) {
      const r = { title: "Smart mode", body: out.answer || "No answer.", note: "Written by Smart mode. This part is not verified by DI's deterministic core, so test code before relying on it." };
      log.push({ q: s, r });
      renderBot(r);
    }
  }

  // one answer, or a plan: a header bubble, then one bubble per step
  function show(r, q) {
    if (!r.agent) { renderBot(r, q); return; }
    bubble("ue-bot", '<div class="ue-title">' + esc(r.title) + '</div><div>' + md(r.body || "") + '</div>');
    r.steps.forEach((d, i) => renderBot(Object.assign({}, d.r, { title: "Step " + (i + 1) + " of " + r.steps.length + " · " + (d.r.title || "Engine") })));
  }
  // a short text form of an answer, for Smart mode's conversation context
  function summary(r) {
    if (!r) return "";
    if (r.agent) return r.steps.map((d) => summary(d.r)).join(" | ");
    return ((r.title ? r.title + ": " : "") + String(r.body || "") + (r.pre ? " " + r.pre : "")).replace(/\*\*/g, "").slice(0, 300);
  }

  // live next-word prediction as the user types (the "predictive thinking" feel)
  function updatePred() {
    const v = inEl.value;
    predEl.innerHTML = "";
    if (!v.trim()) return;
    const { words, fix } = predictWords(model, v, 6);
    if (fix) { // offer to correct the words already typed, showing exactly what changes
      const b = document.createElement("button");
      b.className = "chip"; b.dataset.fix = fix.text;
      b.title = "Correct the typos already typed";
      b.textContent = "fix: " + fix.fixes.map((f) => f.from + " -> " + f.to).join(", ");
      predEl.appendChild(b);
    }
    for (const w of words.slice(0, 6)) {
      const b = document.createElement("button");
      b.className = "chip"; b.textContent = w; b.dataset.word = w;
      predEl.appendChild(b);
    }
  }

  main.querySelector("#ueSend").addEventListener("click", () => send());
  inEl.addEventListener("input", updatePred);
  inEl.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } });

  // clicking a predicted word: complete the current word or append the next one
  predEl.addEventListener("click", (e) => {
    const fx = e.target.closest("[data-fix]");
    if (fx) { inEl.value = fx.dataset.fix; inEl.focus(); updatePred(); return; }
    const b = e.target.closest("[data-word]"); if (!b) return;
    const w = b.dataset.word, v = inEl.value;
    if (/[a-z0-9']$/i.test(v)) inEl.value = v.replace(/[a-z0-9']+$/i, w) + " ";
    else inEl.value = (v + (v.endsWith(" ") || v === "" ? "" : " ") + w + " ");
    inEl.focus(); updatePred();
  });

  main.querySelector("#ueEx").addEventListener("click", (e) => { const b = e.target.closest("[data-ex]"); if (b) send(b.dataset.ex); });
  logEl.addEventListener("click", (e) => {
    const sq = e.target.closest("[data-smartq]");
    if (sq) { sq.disabled = true; sq.textContent = "Sent to Smart mode"; smartRun(sq.dataset.smartq); return; }
    const c = e.target.closest(".ue-copy");
    if (!c) return;
    const code = c.closest(".ue-code").querySelector("code").textContent;
    const done = () => { c.textContent = "Copied"; setTimeout(() => { c.textContent = "Copy"; }, 1400); };
    try { navigator.clipboard.writeText(code).then(done, () => {}); } catch (_) {}
  });
  logEl.addEventListener("click", (e) => { const a = e.target.closest("[data-alt]"); if (a) { const last = log[log.length - 1]; if (last) renderBot(respond(last.q, model)); } });

  // greeting
  renderBot({ title: "Deterministic Intelligence", body: "Ready. I am **DI** &mdash; I run entirely on your device with no AI. Try an example chip above, or type a request. As you type I will predict the next word from the corpus. Ask me to `complete:` a sentence to see prediction in full." });
}
