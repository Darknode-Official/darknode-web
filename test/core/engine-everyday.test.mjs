// Behavioural tests for the everyday tools (everyday.js), the curated how-to
// library (howto.js) and the Round 6 routing fixes around them: clock times must
// never be summed as digits, "flip a coin" is a draw not a text reverse, and
// travel time comes back as a formatted duration with units reconciled.
import { readdirSync, readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { test, group, assert } from "../harness.mjs";

const src = fileURLToPath(new URL("../../public/js/engine/", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "di-everyday-"));
for (const f of readdirSync(src)) if (f.endsWith(".js")) writeFileSync(join(dir, f), readFileSync(join(src, f), "utf8").replace(/"\/js\/engine\//g, '"./'));
process.on("exit", () => { try { rmSync(dir, { recursive: true, force: true }); } catch (_) {} });

const E = await import(pathToFileURL(join(dir, "engine.js")).href);
const EV = await import(pathToFileURL(join(dir, "everyday.js")).href);
const HT = await import(pathToFileURL(join(dir, "howto.js")).href);
const { CORPUS } = await import(pathToFileURL(join(dir, "corpus.js")).href);
const model = E.buildModel(CORPUS);
const text = (r) => [r.title, r.body, r.pre].filter(Boolean).join(" | ").replace(/\*\*/g, "");
const ask = (q) => text(E.respond(q, model));
const skill = (q) => E.respond(q, model).skill;
const year = new Date().getUTCFullYear();

group("everyday: clock arithmetic", () => {
  const cases = [
    ["how many hours between 9am and 5:30pm", /8 hours 30 minutes \(8\.5 hours\)/],
    ["hours between 9:00 and 17:00", /8 hours \(8 hours\)/],
    ["how long from 10pm to 6am", /8 hours .*next day/],
    ["time between noon and 3:15pm", /3 hours 15 minutes/],
    ["add 45 minutes to 10:20", /\b11:05\b/],
    ["what time is 2 hours after 11:30pm", /1:30 AM .*next day/],
    ["subtract 90 minutes from 1:00pm", /11:30 AM/],
    ["10:20 + 45 minutes", /\b11:05\b/],
    ["3 hours before noon", /9:00 AM/],
    ["9 to 5 is how many hours", /8 hours \(8 hours\), reading 5 as 5pm/],
    ["what time will it be in 3 hours and 20 minutes from 2:15pm", /5:35 PM/],
  ];
  for (const [q, re] of cases) test(q, () => { assert.equal(skill(q), "everyday", q + " routed to " + skill(q)); const t = ask(q); assert.ok(re.test(t), q + " -> " + t.slice(0, 140)); });
  test("clock times are never summed as digits by wordmath", () => {
    assert.ok(!/\b44\b/.test(ask("how many hours between 9am and 5:30pm")));
    assert.ok(!/\b75\b/.test(ask("add 45 minutes to 10:20")));
  });
  test("bad clock values are not claimed", () => {
    assert.equal(EV.ask("add 45 minutes to 25:70"), null);
    assert.equal(EV.ask("hours between 13pm and 5pm"), null);
  });
});

group("everyday: time zones", () => {
  test("a major city answers with its IANA zone and offset", () => {
    const r = E.respond("what time is it in tokyo", model);
    assert.equal(r.skill, "everyday");
    assert.ok(/Asia\/Tokyo, UTC\+9\)/.test(text(r)), text(r));
    assert.ok(/\b\d{2}:\d{2}\b/.test(text(r)));
  });
  test("abbreviations, countries and multi-word cities resolve", () => {
    assert.ok(/America\/New_York/.test(ask("current time in new york")));
    assert.ok(/Asia\/Kolkata/.test(ask("time in india")));
    assert.ok(/UTC\+0\)|UTC-0\)|UTC\)/.test(ask("what time is it in utc")) || /\(UTC, UTC\+0\)/.test(ask("what time is it in utc")));
    assert.ok(/Europe\/Paris/.test(ask("what is the time in cet")));
  });
  test("an unknown place is refused, not guessed", () => {
    const t = ask("what time is it in atlantis");
    assert.ok(/do not have a time zone/.test(t), t);
  });
});

group("everyday: random draws", () => {
  test("coin, dice, number, pick, shuffle, uuid", () => {
    for (let i = 0; i < 5; i++) assert.ok(/Heads|Tails/.test(ask("flip a coin")));
    assert.equal(skill("flip a coin"), "everyday");
    assert.ok(!/nioc/.test(ask("flip a coin")));
    for (let i = 0; i < 10; i++) { const m = ask("roll a dice").match(/rolled a (\d)/); assert.ok(m && +m[1] >= 1 && +m[1] <= 6); }
    assert.ok(/2d20/.test(ask("roll 2d20")));
    for (let i = 0; i < 10; i++) { const m = ask("random number between 1 and 100").match(/\| (\d+) \(between 1 and 100/); assert.ok(m && +m[1] >= 1 && +m[1] <= 100, ask("random number between 1 and 100")); }
    assert.ok(/between 1 and 10/.test(ask("pick a number from 1 to 10")));
    assert.ok(/^Pick \| (pizza|tacos)\./.test(ask("pick between pizza and tacos")));
    assert.ok(/(red|green|blue)\./.test(ask("choose one: red, green, blue")));
    assert.ok(/^Pick \| (red|blue)\./.test(ask("should i pick red or blue")));
    const sh = E.respond("shuffle a, b, c, d", model); assert.equal(sh.skill, "everyday"); assert.deepEqual(sh.pre.split("\n").sort(), ["a", "b", "c", "d"]);
    assert.ok(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(E.respond("uuid", model).pre));
    assert.equal(E.respond("generate 3 uuids", model).pre.split("\n").length, 3);
  });
  test("reverse is still reverse", () => {
    assert.ok(/dlrow olleh/.test(ask("flip hello world")));
  });
});

group("everyday: placeholder text", () => {
  test("lorem ipsum in words, sentences, paragraphs", () => {
    assert.equal(skill("lorem ipsum"), "everyday");
    assert.equal(E.respond("lorem ipsum 5 words", model).pre.split(/\s+/).length, 5);
    assert.equal(E.respond("3 paragraphs of lorem ipsum", model).pre.split("\n\n").length, 3);
    assert.ok(/^Lorem ipsum dolor/.test(E.respond("placeholder text", model).pre));
  });
});

group("everyday: money", () => {
  test("tip with a rate, with a table, with a split", () => {
    assert.ok(/18%: tip \$8\.55, total \$56\.05/.test(ask("tip on 47.50 at 18%")));
    const t = ask("tip on $80"); assert.ok(/15%: tip \$12\.00/.test(t) && /20%: tip \$16\.00/.test(t), t);
    assert.ok(/\$29\.40 each for 4/.test(ask("20% tip on 98 split 4 ways")));
  });
  test("loan payment is the standard amortised figure", () => {
    const t = ask("mortgage payment on 300000 at 6% for 30 years");
    assert.ok(/\$1,798\.65 per month/.test(t), t);
    assert.ok(/total interest\s+\$347,514\.57/.test(t), t);
    assert.ok(/\$188\.71 per month/.test(ask("car loan of $10,000 at 5% for 5 years")));
    assert.ok(/\$1,000\.00 per month/.test(ask("loan of 12000 at 0% for 12 months")));
    assert.ok(/\$495\.03 per month/.test(ask("monthly payment on a 25000 car loan at 7% over 5 years")));
    assert.ok(/\$2,555\.05 per month/.test(ask("mortgage 450000 at 5.5% 30 years")));
  });
  test("regular saving: plain and compounded", () => {
    const plain = ask("if i save 200 a month how much in 5 years");
    assert.ok(/\$12,000\.00 \(60 deposits/.test(plain), plain);
    assert.ok(!/\b205\b/.test(plain));
    const fv = ask("save 100 a month for 10 years at 6%");
    assert.ok(/\$16,387\.93/.test(fv), fv);
    assert.ok(/\$2,600\.00/.test(ask("put away 50 a week for a year")));
  });
});

group("everyday: body and travel", () => {
  test("bmi in metric and imperial", () => {
    assert.ok(/BMI 22\.9 \(normal weight\)/.test(ask("bmi 70 kg 175 cm")));
    assert.ok(/BMI 26\.6 \(overweight\)/.test(ask("what is my bmi at 180 lbs and 5 ft 9")));
    assert.ok(/BMI 17\.3 \(underweight\)/.test(ask("bmi for 50kg and 1.7m")));
    assert.ok(/BMI 22\.9 \(normal weight\)/.test(ask("bmi 70 kg 1.75 m")));
  });
  test("travel time is a duration, with units reconciled", () => {
    assert.ok(/5 hours \(5 hours\)/.test(ask("how long to travel 300 km at 60 km/h")));
    assert.ok(/4 hours 37 minutes \(4\.615 hours\)/.test(ask("how long to drive 300 miles at 65 mph")));
    const mixed = ask("how long to drive 300 km at 60 mph");
    assert.ok(/3 hours 6 minutes/.test(mixed), mixed);
    assert.ok(!/Calculation/.test(mixed));
    assert.ok(/\b200\b/.test(ask("how far can a car go at 100 km/h for 2 hours")));
  });
  test("steps to distance says it is an estimate", () => {
    const r = E.respond("how far is 10000 steps in miles", model);
    assert.ok(/4\.73 mi/.test(text(r)) && /Estimate/.test(r.note));
    assert.ok(/7\.62 km \(4\.73 miles\)/.test(ask("10000 steps")));
  });
});

group("everyday: ports and years", () => {
  test("service to port and port to service", () => {
    assert.ok(/HTTPS \(HTTP over TLS\) uses TCP port 443/.test(ask("what port does https use")));
    assert.ok(/TCP port 22/.test(ask("ssh port")));
    assert.ok(/TCP port 5432/.test(ask("default port for postgres")));
    assert.ok(/Port 3306 \(TCP\) is MySQL/.test(ask("what is port 3306")));
    assert.ok(/Port 8080 \(TCP\) is HTTP alternate/.test(ask("what port is 8080")));
    assert.ok(/UDP port 53|TCP\/UDP port 53/.test(ask("what port is dns on")));
    const t = ask("what is port 40000"); assert.ok(/no well-known assignment/.test(t) && /registered ports/.test(t), t);
    assert.ok(/only go up to 65535/.test(ask("port 70000")));
  });
  test("years ago / ahead / birth year", () => {
    assert.ok(new RegExp("\\b" + (year - 30) + "\\b").test(ask("what year was 30 years ago")));
    assert.ok(new RegExp("\\b" + (year + 10) + "\\b").test(ask("what year will it be in 10 years")));
    assert.ok(new RegExp((year - 25) + " if their birthday has already passed this year, otherwise " + (year - 26)).test(ask("what year was i born if i am 25")));
  });
});

group("everyday: does not over-claim", () => {
  test("lines that look close but are not tools return null", () => {
    for (const q of ["tip of the day", "port authority", "random thoughts", "pick up the phone", "how long is a piece of string", "save the whales", "bmi", "coin", "what is a port", "roll call", "steps to install python"])
      assert.equal(EV.ask(q), null, q + " was claimed");
  });
  test("existing skills keep their answers", () => {
    assert.ok(/\b36\b/.test(ask("what is 15% of 240")));
    assert.ok(/\b42\.66/.test(ask("split 128 dollars between 3 people")));
    assert.ok(/\b62\.993\b/.test(ask("what is 30% off 89.99")));
    assert.ok(/1628\.89/.test(ask("compound interest 1000 at 5% for 10 years")));
    assert.ok(/Password generator/.test(ask("generate a password")));
    assert.ok(/\b1,? ?2,? ?5,? ?9\b/.test(ask("sort 5, 2, 9, 1")));
  });
});

group("round 6: routing fixes", () => {
  test("compare accepts powers and 'compare A and B'", () => {
    assert.ok(/1\/3 is larger/.test(ask("compare 0.3 and 1/3")));
    assert.ok(/2\^10 is larger\. 2\^10 = 1024 and 10\^3 = 1000/.test(ask("which is bigger 2^10 or 10^3")));
    assert.ok(/equal/.test(ask("compare 50% to 0.5")));
  });
  test("palindrome phrasings", () => {
    assert.ok(/yes, .racecar. is a palindrome/.test(ask("palindrome check racecar")));
    assert.ok(/yes, .racecar. is a palindrome/.test(ask("is racecar palindrome")));
    assert.ok(/no, .hello./.test(ask("check palindrome: hello")));
  });
  test("feet and inches", () => {
    assert.ok(/180 cm equals 5 ft 10\.87 in \(70\.866142 inches in all\)/.test(ask("180 cm in feet and inches")));
    assert.ok(/6 ft 0 in/.test(ask("72 inches to feet and inches")));
    assert.ok(/1\.8288 m|1\.8288 meters/.test(ask("6 feet in m")) || /1\.8288/.test(ask("6 feet in m")));
  });
  test("hash is the glossary, boiling point knows its units", () => {
    assert.ok(/Definition: hash function/.test(ask("what is a hash")));
    assert.ok(/Definition: hash map/.test(ask("what is a hashmap")));
    assert.ok(/212 degrees F \(100 degrees C\)/.test(ask("boiling point of water in fahrenheit")));
    assert.ok(/100 degrees C/.test(ask("what is the boiling point of water")));
    assert.ok(/273\.15 K/.test(ask("freezing point of water in kelvin")));
  });
});

group("howto: curated snippets", () => {
  const cases = [
    ["git undo last commit", /git reset --soft HEAD~1/], ["how do i undo the last commit in git", /git revert HEAD/],
    ["how do i center a div", /place-items: center/], ["python list comprehension example", /\[x \* x for x in range\(10\)\]/],
    ["how to create a new branch in git", /git switch -c/], ["debounce function in javascript", /clearTimeout\(t\)/],
    ["how to make a file executable", /chmod \+x/], ["what is using port 3000", /lsof -i :3000/],
    ["docker shell into container", /docker exec -it/], ["sql left join example", /LEFT JOIN/],
    ["how to hash passwords securely", /Argon2id or bcrypt/], ["generate a random secret in the terminal", /openssl rand -hex 32/],
    ["json to yaml", /yq -P/], ["what is my ip", /cannot see your network/], ["python f-string format a float", /price:,\.2f/],
    ["git stash", /git stash pop/], ["regex for email", /EMAIL\.test/], ["create a venv", /python3 -m venv/],
    // dev jargon must survive the typo corrector ("footer" is not "footed", "params" is not "paeans")
    ["how to make a sticky footer", /min-height: 100dvh/], ["how to read query params in js", /URLSearchParams/], ["docker exec bash", /docker exec -it/],
  ];
  for (const [q, re] of cases) test(q, () => { const r = E.respond(q, model); assert.equal(r.skill, "howto", q + " routed to " + r.skill); const t = text(r); assert.ok(re.test(t), q + " -> " + t.slice(0, 160)); });
  test("every entry has a title, a language, code and a unique id", () => {
    const ids = new Set();
    for (const h of HT.ENTRIES) { assert.ok(h.title && h.lang && h.code.length > 10, h.id); assert.ok(!ids.has(h.id), "dup " + h.id); ids.add(h.id); assert.ok(h.re instanceof RegExp); }
    assert.ok(HT.ENTRIES.length >= 90, "entries: " + HT.ENTRIES.length);
  });
  test("a how-to never steals a definition, a calculation or a program", () => {
    assert.equal(skill("what is a hash"), "knowledge");
    assert.equal(skill("what is 15% of 240"), "calc");
    assert.equal(skill("make a snake game in python"), "codegen");
    assert.equal(skill("sort 5, 2, 9, 1"), "listops");
    assert.equal(HT.ask("git"), null);
    assert.equal(HT.ask("center"), null);
  });
  test("the answer says it is curated, not generated", () => {
    assert.ok(/hand-written and reviewed, not generated/.test(E.respond("git undo last commit", model).note));
  });
});

// Round 7: relative dates, honest currency / live-data / translation refusals,
// fraction and percentage forms, JSON and cron tools, and the calculus pointer.
group("everyday: round 7", () => {
  const iso = (off) => { const n = new Date(); return new Date(Date.UTC(n.getUTCFullYear(), n.getUTCMonth(), n.getUTCDate() + off)).toISOString().slice(0, 10); };
  test("N days from today is an offset, not today", () => {
    const r = E.respond("what day is 90 days from today", model);
    assert.equal(r.skill, "datetime"); assert.ok(text(r).includes(iso(90)), text(r));
    assert.ok(text(E.respond("what date is 3 weeks from now", model)).includes(iso(21)));
    assert.ok(text(E.respond("what day was 10 days ago", model)).includes(iso(-10)));
    assert.ok(text(E.respond("what day is it in 5 days", model)).includes(iso(5)));
  });
  test("month offsets clamp to the last day instead of overflowing", () => {
    const d = new Date(Date.UTC(2026, 0, 31)); // Jan 31 + 1 month must be Feb 28, not Mar 3
    const last = new Date(Date.UTC(2026, 2, 0)).getUTCDate(); assert.equal(Math.min(d.getUTCDate(), last), 28);
    const r = E.respond("what day is 2 months from today", model); assert.equal(r.skill, "datetime"); assert.ok(/\d{4}-\d{2}-\d{2}/.test(text(r)));
  });
  test("currency is refused honestly, mass units still convert", () => {
    assert.ok(/exchange rate/.test(ask("what is 100 usd in eur")));
    assert.ok(/exchange rate.*DOLLARS to GBP/.test(ask("convert 50 dollars to gbp")));
    assert.ok(/90\.7184 kg/.test(ask("200 pounds to kg")));
    assert.ok(/exchange rate/.test(ask("100 pounds to dollars")));
  });
  test("fractions: simplify, lowest terms, as a percent", () => {
    assert.ok(/simplifies to 3\/4/.test(ask("simplify 18/24")));
    assert.ok(/simplifies to 2\/3/.test(ask("10/15 in lowest terms")));
    assert.ok(/already in lowest terms/.test(ask("reduce 7/9")));
    assert.ok(/33\.3333%/.test(ask("what is 1/3 as a percent")));
    assert.ok(/25%/.test(ask("0.25 as a percentage")));
    assert.ok(/37\.5%/.test(ask("3/8 to percent")));
    assert.equal(skill("what is 15% of 80"), "calc"); // "of" is a percent-of calculation, untouched
  });
  test("json: format, minify, validate, and a located error", () => {
    assert.ok(/"a": 1/.test(ask('json format {"a":1,"b":[1,2]}')));
    assert.ok(/\{"a":1,"b":\[1,2\]\}/.test(ask('minify json { "a": 1, "b": [1, 2] }')));
    assert.ok(/^Valid JSON/.test(ask('is this valid json {"ok":true}')));
    assert.ok(/Invalid JSON.*line 1, column/.test(ask("validate json {'a': 1}")));
    assert.equal(skill('pretty print json {"a":1}'), "everyday");
    assert.equal(skill('write json {"a":1}'), "everyday"); // allowed past the code gate
  });
  test("cron: only when cron is named, exact five fields", () => {
    const c = [["cron every monday at 9am", "0 9 * * 1"], ["crontab every 15 minutes", "*/15 * * * *"], ["cron job every day at 6:30pm", "30 18 * * *"],
      ["cron expression for weekdays at 8am", "0 8 * * 1-5"], ["cron every hour", "0 * * * *"], ["cron at midnight", "0 0 * * *"],
      ["cron monthly on the 1st at 3am", "0 3 1 * *"], ["cron every saturday and sunday at noon", "0 12 * * 0,6"], ["cron every 2 hours", "0 */2 * * *"]];
    for (const [q, expr] of c) { const r = E.respond(q, model); assert.equal(r.skill, "everyday", q); assert.equal(r.result.expr, expr, q + " -> " + r.result.expr); }
    assert.equal(EV.cronOf("every 90 minutes"), null); // not expressible in one line
    assert.equal(EV.cronOf("every monday at 25:00"), null);
    assert.notEqual(skill("run a script every day"), "everyday"); // no "cron": the how-to snippet handles it
    assert.equal(skill("what is a cron job"), "knowledge");
  });
  test("calculus points at Quelvra with a prefilled link", () => {
    const r = E.respond("derivative of x^2", model); assert.equal(r.skill, "everyday");
    assert.ok(r.result.link.startsWith("/quelvra/?q=derivative%20of%20x%5E2"), r.result.link);
    assert.ok(/Quelvra/.test(text(r)));
    assert.equal(E.respond("integrate sin(x) dx", model).result.link, "/quelvra/?q=integrate%20sin(x)%20dx");
    assert.equal(skill("what is 7!"), "calc");
  });
  test("live data and translation are refused, not guessed", () => {
    assert.ok(/needs live data/.test(ask("what is the weather today")));
    assert.ok(/needs live data/.test(ask("bitcoin price")));
    assert.ok(/cannot translate thank you into French/.test(ask("how do you say thank you in french")));
    assert.ok(/cannot translate hello into Spanish/.test(ask("translate hello to spanish")));
    assert.equal(skill("what is 3 feet in cm"), "convert"); // "in <unit>" is not a language
  });
  test("random colour comes back as hex, rgb and hsl", () => {
    const r = E.respond("pick a random color", model); assert.equal(r.skill, "everyday");
    assert.ok(/^#[0-9a-f]{6}$/.test(r.result.hex)); assert.ok(/^rgb\(\d+, \d+, \d+\)$/.test(r.result.rgb)); assert.ok(/^hsl\(\d+, \d+%, \d+%\)$/.test(r.result.hsl));
  });
  test("base conversions name the source base", () => {
    assert.ok(/0b1010 \(binary\) = 10 \(decimal\)/.test(ask("convert 1010 binary to decimal")));
    assert.ok(/0xff \(hexadecimal\) = 255/.test(ask("hex ff to decimal")));
    assert.ok(/255 = 0xff/.test(ask("255 to hex")));
  });
  test("new trivia and the calendar-average note", () => {
    assert.ok(/384,400 km/.test(ask("how far is the moon")));
    assert.ok(/8,848\.86 m/.test(ask("how tall is mount everest")));
    assert.ok(/8 planets/.test(ask("how many planets are in the solar system")));
    assert.ok(/average calendar year/.test(ask("how many seconds in a year")));
    assert.ok(/fixed conversion factor/.test(ask("how many seconds in a day")));
  });
});
