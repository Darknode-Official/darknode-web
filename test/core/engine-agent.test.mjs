// Behavioural tests for the engine orchestrator (engine.js): typo reading, the
// agent (multi-step plans, "it", follow-ups) and typo-aware prediction.
// engine.js uses browser-absolute "/js/engine/..." imports, so it is loaded from a
// temporary copy of the engine folder with those specifiers rewritten to "./".
import { readdirSync, readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { test, group, assert } from "../harness.mjs";

const src = fileURLToPath(new URL("../../public/js/engine/", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "di-engine-"));
for (const f of readdirSync(src)) if (f.endsWith(".js")) writeFileSync(join(dir, f), readFileSync(join(src, f), "utf8").replace(/"\/js\/engine\//g, '"./'));
process.on("exit", () => { try { rmSync(dir, { recursive: true, force: true }); } catch (_) {} });

const E = await import(pathToFileURL(join(dir, "engine.js")).href);
const { CORPUS } = await import(pathToFileURL(join(dir, "corpus.js")).href);
const model = E.buildModel(CORPUS);
const text = (r) => String(r.pre || r.body || "").replace(/\*\*/g, "");

group("engine: reads through typos", () => {
  test("misspelled requests route and answer, and the fixes are reported", () => {
    const r = E.respond("whats the captial of frnace", model);
    assert.equal(r.skill, "facts");
    assert.ok(/Paris/.test(text(r)));
    assert.deepEqual(r.fixed.map((f) => f.to), ["capital", "france"]);
    assert.ok(/Read .captial. as .capital./.test(r.note));
  });
  test("many kinds of slip", () => {
    const cases = [["calcualte 15 percnt of 240", /36/], ["waht is the sqaure root of 144", /12/], ["is 97 prmie", /97 is prime/],
      ["sovle x^2 - 5x + 6 = 0", /x = 2/], ["convrt 5 kilometrs to mils", /3\.10685/], ["how mnay days untill christmas", /days until/], ["waht is recurison", /calls itself/]];
    for (const [q, re] of cases) assert.ok(re.test(text(E.respond(q, model))), q + " -> " + text(E.respond(q, model)).slice(0, 80));
  });
  test("a content transform fixes the command but keeps the user's words", () => {
    assert.equal(E.respond("revrse hello wrld", model).pre, "dlrw olleh");
  });
  test("a code spec is never corrected", () => {
    const r = E.respond("fib(n) = n < 2 ? n : fib(n-1) + fib(n-2)", model);
    assert.equal(r.skill, "codegen");
    assert.deepEqual(r.fixed, []);
  });
  test("names and word problems are left alone", () => {
    const r = E.respond("Maya saved $45, then $62, then $58. How much in total?", model);
    assert.equal(r.skill, "wordmath");
    assert.ok(/165/.test(text(r)));
  });
  test("math verbs are not 'corrected' into other words", () => {
    assert.ok(/108/.test(text(E.respond("multiply 36 by 3", model)))); // "multiply" != "multiple"
    assert.equal(E.respond("what is 36 times 3", model).skill, "calc"); // not element 36
  });
});

group("engine: texting shorthand and everyday phrasing", () => {
  const ans = (q) => { const r = E.agent(q, model, {}); return r.agent ? r.steps.map((d) => text(d.r)).join(" ") : text(r); };
  test("texting shorthand is read before spelling ('wat' is not 'way')", () => {
    const cases = [["wat is 5 plus 5", /10/], ["wut is 12 x 12", /144/], ["hw many km in 3 miles", /4\.828/], ["cnvrt 10 kg 2 lbs", /22\.04/], ["ty, now whats 9 squared", /81/], ["u know whats 2 plus 2", /4/]];
    for (const [q, re] of cases) assert.ok(re.test(ans(q)), q + " -> " + ans(q).slice(0, 80));
  });
  test("shorthand never rewrites a text tool's content", () => {
    assert.equal(E.respond("reverse we love u", model).pre, "u evol ew");
    assert.equal(E.slang("reverse we love u", false).text, "reverse we love u");
  });
  test("everyday words map onto the skills", () => {
    const cases = [["flip hello world backwards", /dlrow olleh/], ["make hello world all caps", /HELLO WORLD/], ["make HELLO small letters", /hello/],
      ["half of 90", /45/], ["double 21", /42/], ["what is a third of 99", /33/], ["is 17 a prime number", /17 is prime/], ["lowest common multiple of 4 and 6", /12/],
      ["biggest of 4 9 2", /9/], ["smallest number in 8 3 5", /3/], ["what day of the week is christmas 2026", /Friday/], ["how long until halloween", /days/],
      ["symbol for sodium", /Na/], ["how fast is light", /2\.99792458/], ["value of pi", /3\.14159/], ["whats g on earth", /9\.80665/], ["meaning of api", /interface/i],
      ["what number is XIV", /14/], ["x squared minus 9 equals 0", /3/], ["what is x if 3x = 12", /4/], ["5 factorial", /120/], ["how many ways to arrange 4 books", /24/], ["what comes after 2 4 8 16", /32/]];
    for (const [q, re] of cases) assert.ok(re.test(ans(q)), q + " -> " + ans(q).slice(0, 80));
  });
  test("a rephrase is shown, not hidden", () => {
    assert.ok(/Understood as .\(90 \/ 2\)./.test(E.respond("half of 90", model).note));
  });
  test("look-alikes are left alone: hex, algebra, word problems", () => {
    assert.ok(/31/.test(ans("0x1f to decimal")));
    assert.ok(/x = 3/.test(ans("solve 3x + 2 = 11")));
    assert.equal(E.rephrase("what is 3x = 12"), "what is 3x = 12");
    assert.equal(E.respond("Maya saved $45, then $62, then $58. How much in total?", model).skill, "wordmath");
  });
  test("an unmatched question gets no junk continuation", () => {
    assert.equal(E.respond("is the moon made of cheese", model).pre, null);
  });
});

group("engine: wider phrasing, sorting, digests, dictionary", () => {
  const ans = (q) => { const r = E.agent(q, model, {}); return r.agent ? r.steps.map((d) => text(d.r) + " " + (d.r.code || "")).join(" ") : text(r) + " " + (r.code || ""); };
  test("math phrasing", () => {
    const cases = [["2 to the 10th power", /1024/], ["square root 81", /\b9\b/], ["15% tip on 60", /\b9\b/], ["what is 30 percent off 200", /140/], ["round 3.14159 to 2 decimals", /3\.14\b/],
      ["what is 17 mod 5", /\b2\b/], ["negative 5 plus 3", /-2/], ["what is the absolute value of -5", /\b5\b/], ["cos of 0", /\b1\b/], ["odds of rolling two sixes", /0\.0277/]];
    for (const [q, re] of cases) assert.ok(re.test(ans(q)), q + " -> " + ans(q).slice(0, 80));
  });
  test("units, facts and encodings", () => {
    const cases = [["5 foot 10 in cm", /177\.8/], ["how many litres in a gallon", /3\.78/], ["1 mile is how many km", /1\.609/], ["convert celsius to fahrenheit 100", /212/],
      ["mass of a proton", /1\.67/], ["speed of sound", /343/], ["what is e", /2\.718/], ["what is H", /hydrogen/i],
      ["md5 of hello", /5d41402abc4b2a76b9719d911017c592/], ["sha256 of hello", /2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824/], ["base64 decode aGVsbG8=", /\bhello\b/], ["rot13 hello", /uryyb/],
      ["binary of 10", /1010/], ["days between jan 1 2026 and mar 1 2026", /59/], ["what day was july 4 1776", /Thursday/]];
    for (const [q, re] of cases) assert.ok(re.test(ans(q)), q + " -> " + ans(q).slice(0, 80));
  });
  test("sorting a list", () => {
    assert.equal(E.respond("sort these numbers 5 3 9", model).pre, "3, 5, 9");
    assert.equal(E.respond("sort 10 2 33 4 descending", model).pre, "33, 10, 4, 2");
    assert.equal(E.respond("alphabetize pear, apple, Fig", model).pre, "apple, Fig, pear");
    assert.equal(E.respond("write a bubble sort in rust", model).skill, "codegen");
  });
  test("plain-English functions compile to code", () => {
    assert.ok(/function add\(a, b\)/.test(E.agent("javascript function that adds two numbers", model, {}).code));
    assert.ok(/def is_even/.test(E.agent("write a python function to check if a number is even", model, {}).code));
    assert.ok(/def /.test(E.agent("python function to reverse a string", model, {}).code || ""));
  });
  test("text tools keep content words ('i', 'the') and count vowels", () => {
    assert.equal(E.respond("reverse i love u", model).pre, "u evol i");
    assert.ok(/The Quick Brown Fox/.test(ans("title case the quick brown fox")));
    assert.ok(/myVariableName/.test(ans("camelcase my variable name")));
    assert.ok(/\b2\b/.test(ans("count vowels in hello")));
    assert.ok(/\b4\b/.test(ans("number of words in a b c d")));
  });
  test("real words are never 'corrected', contractions without apostrophes are read", () => {
    const clean = ["what does api stand for", "what time does the bakery open on sundays", "my friend said the weather was weak today"];
    for (const q of clean) assert.deepEqual(E.fixTypos(q, model).fixes, [], q);
    assert.equal(E.slang("i dont know what thats for").text, "i don't know what that's for");
  });
});

group("engine: agent (plans, 'it', follow-ups)", () => {
  test("a multi-step plan feeds each result into the next", () => {
    const r = E.agent("calculate 15 percent of 240 then multiply it by 3 then is it prime", model, {});
    assert.ok(r.agent);
    assert.equal(r.steps.length, 3);
    assert.deepEqual(r.steps.map((d) => d.ran), ["calculate 15 percent of 240", "multiply 36 by 3", "is 108 prime"]);
    assert.ok(/108 is not prime/.test(text(r.steps[2].r)));
  });
  test("a text result is passed on quoted, so the next tool keeps it verbatim", () => {
    const r = E.agent("what is the capital of france then reverse it", model, {});
    assert.equal(r.steps[1].ran, 'reverse "Paris"');
    assert.equal(r.steps[1].r.pre, "siraP");
  });
  test("'and also' joins two independent commands; a unit carries into 'double it'", () => {
    const a = E.agent("factorize 360 and also convert 255 to hex", model, {});
    assert.deepEqual(a.steps.map((d) => d.r.skill), ["numbertheory", "base"]);
    const b = E.agent("convert 5 km to miles and then double it", model, {});
    assert.ok(/6\.2137/.test(text(b.steps[1].r)));
  });
  test("prose and built-in 'and' are not split", () => {
    for (const q of ["Maya saved $45, then $62, then $58. How much in total?", "r = 3; pi * r^2", "days between 2026-01-01 and 2026-12-31", "gcd of 48 and 60", "truth table for a and b"]) {
      assert.ok(!E.agent(q, model, {}).agent, q);
    }
  });
  test("a typo in the sequencing word still plans ('thne')", () => {
    const r = E.agent("calcualte 12 times 8 thne add 4 to it", model, {});
    assert.ok(r.agent);
    assert.ok(/100/.test(text(r.steps[1].r)));
  });
  test("follow-ups swap one slot of the last request", () => {
    const s = {};
    const run = (q) => E.agent(q, model, s);
    run("what is the capital of france");
    assert.ok(/Tokyo/.test(text(run("what about japan"))));
    assert.ok(/Berlin/.test(text(run("and germany"))));
    run("convert 5 km to miles");
    assert.ok(/feet/.test(text(run("now in feet"))));
    assert.ok(/^10 km/.test(text(run("what about 10 km"))));
    run("write a fibonacci function in python");
    assert.equal(run("now in rust").lang, "rust");
    run("reverse hello world");
    assert.equal(run("what about goodbye moon").pre, "noom eybdoog");
    run("is 97 prime");
    assert.ok(/91 is not prime/.test(text(run("what about 91"))));
  });
  test("a follow-up says how it was read", () => {
    const s = {};
    E.agent("capital of france", model, s);
    assert.ok(/Read as .capital of japan. \(follow-up/.test(E.agent("what about japan", model, s).note));
  });
  test("with no previous request, a follow-up phrase is just a request", () => {
    const r = E.agent("what about japan", model, {});
    assert.ok(!/follow-up/.test(r.note || ""));
  });
});

group("engine: typo-aware live prediction", () => {
  const words = (t) => E.predictWords(model, t, 6).words;
  test("slots: countries, same-dimension units, languages, holidays, elements", () => {
    assert.equal(words("whats the capital of ")[0], "france");
    assert.deepEqual(words("convert 5 km to ").slice(0, 2), ["miles", "m"]);
    assert.ok(!words("convert 5 km to ").includes("km"));
    assert.deepEqual(words("convert 100 fahrenheit to "), ["celsius", "kelvin"]);
    assert.equal(words("write a fibonacci function in ")[0], "python");
    assert.equal(words("how many days until ")[0], "christmas");
    assert.equal(words("tell me about element ")[0], "gold");
  });
  test("a typo earlier in the line does not derail it, and a fix is offered", () => {
    const r = E.predictWords(model, "whats the captial of fr", 6);
    assert.deepEqual(r.words, ["france"]);
    assert.equal(r.fix.text, "whats the capital of fr");
  });
  test("a mistyped half-word completes fuzzily", () => {
    assert.ok(words("fibn").includes("fibonacci"));
  });
  test("learn() adapts predictions to what the user types", () => {
    const m = E.buildModel(CORPUS);
    E.learn(m, "deploy to firebase hosting. deploy to firebase hosting.", 3);
    assert.equal(E.predictWords(m, "deploy to ", 3).words[0], "firebase");
  });
});

group("engine: spelling skill", () => {
  const all = (r) => String((r.body || "") + " " + (r.pre || "")).replace(/\*\*/g, "");
  const run = (q) => E.agent(q, model, {});
  test("single words: corrected, confirmed, or honestly not guessed", () => {
    assert.ok(/correct spelling is receive/.test(all(run("how do you spell recieve"))));
    assert.ok(/necessary/.test(all(run("how do u spell neccessary"))));
    assert.ok(/accommodate is spelled correctly/.test(all(run("spelling of accommodate"))));
    assert.ok(/will not guess/.test(all(run("how do you spell xqzv"))));
  });
  test("a choice between two spellings", () => {
    assert.ok(/separate is correct/.test(all(run("is it seperate or separate"))));
  });
  test("numbers are spelled out in words", () => {
    assert.equal(run("spell out 1234").pre, "one thousand two hundred thirty-four");
    assert.ok(/ninety thousand two hundred ten/.test(all(run("spell out 90210"))));
  });
  test("a sentence is spell-checked with context", () => {
    assert.equal(run("spell check: Teh wether is realy nice tomorow").pre, "The weather is really nice tomorrow");
    assert.equal(run("spell check: i dont know wether to go").pre, "I don't know whether to go");
    assert.ok(/believe[\s\S]*definitely[\s\S]*weird/.test(all(run("spell check: I beleive this is definately wierd"))));
  });
  test("proofreading fixes common word confusions", () => {
    assert.ok(/should have/.test(all(run("proofread: you should of told me"))));
    assert.ok(/your message/.test(all(run("proofread: thanks for you're message"))));
  });
  test("possessives keep their ending", () => {
    const r = run("what is carbon's atomic number");
    assert.ok(/atomic number 6/.test(all(r)));
    assert.ok(!/carbons/.test(r.note || ""));
  });
});

group("engine: everyday questions, round 4", () => {
  const all = (r) => (r.agent ? r.steps.map((d) => (d.r.body || "") + " " + (d.r.pre || "")).join(" ") : (r.body || "") + " " + (r.pre || "")).replace(/\*\*/g, "");
  const run = (q) => all(E.agent(q, model, {}));
  test("percentages said in words", () => {
    assert.ok(/\b100\b/.test(run("increase 80 by 25%")));
    assert.ok(/\b180\b/.test(run("decrease 200 by 10 percent")));
    assert.ok(/\b25\b/.test(run("what percent is 30 of 120")));
    assert.ok(/\b25\b/.test(run("20 is what percent of 80")));
    assert.ok(/\b9\b/.test(run("how much is a 20% tip on $45")));
    assert.ok(/\b30\b/.test(run("split 90 between 3 people")));
  });
  test("capitals: reverse lookup, UK nations, several at once", () => {
    assert.ok(/France/.test(run("where is paris")));
    assert.ok(/London/.test(run("capital of england")));
    const both = run("capitals of france and germany");
    assert.ok(/Paris/.test(both) && /Berlin/.test(both));
  });
  test("element trivia", () => {
    assert.ok(/118/.test(run("how many elements are there")));
    assert.ok(/oganesson/i.test(run("what is the heaviest element")));
    assert.ok(/hydrogen/i.test(run("what is the lightest element")));
  });
  test("glossary covers everyday computing words", () => {
    assert.ok(/markup/i.test(run("whats html")));
    assert.ok(/defect/.test(run("what is a bug in programming")));
  });
  test("dates: days in a month, relative weekdays", () => {
    assert.ok(/29 days/.test(run("how many days are in february 2024")));
    assert.ok(/28 days/.test(run("how many days in february 2023")));
    assert.ok(/366 days/.test(run("how many days are in 2024")));
    assert.ok(/Tomorrow is [A-Z][a-z]+day/.test(run("tomorrow is what day")));
  });
  test("algebra and primes in words", () => {
    assert.ok(/x = 16/.test(run("find x: x/2 = 8")));
    assert.ok(/8/.test(run("solve x squared = 64")));
    assert.ok(/2, 3, 5, 7, 11 \(5 primes\)/.test(run("first 5 primes")));
    assert.ok(/2, 3, 5, 7 \(4 primes\)/.test(run("primes below 10")));
  });
  test("text: title-case every word, drop duplicate words", () => {
    assert.ok(/Hello Big World/.test(run("capitalize every word in hello big world")));
    assert.ok(/a b c/.test(run("remove duplicate words from a a b b c")));
  });
});

group("engine: spell check keeps its text whole", () => {
  test("a colon payload with 'then' is one spell check, not a plan", () => {
    const r = E.agent("spell check: then Chester chose teh colour", model, {});
    assert.equal(r.skill, "spelling");
    assert.equal(r.pre, "Then Chester chose the colour");
  });
  test("repeated fixes are counted", () => {
    assert.ok(/corrected 2 words: i → I \(x2\)/.test(E.agent("proofread: i went home and then i slept", model, {}).body.replace(/\*\*/g, "")));
  });
});
