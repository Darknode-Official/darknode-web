// Unescape Backslash Sequences read \101 as "101" (no octal), and did not know
// \u{1F600}, \U0001F600, \a or \e. The Unix Timestamp Converter turned a
// millisecond value in seconds mode into the year 56705 without a word, and never
// said how it read a date without a zone.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/devx.js";

const run = (id, v) => TOOLS.find((t) => t.id === id).run(v, H);
const un = (text) => run("dv-unescape-backslash", { text });

group("dv-unescape-backslash", () => {
  test("octal escapes", () => {
    assert.equal(un("\\101\\102"), "AB");
    assert.equal(un("a\\0b"), "a\0b");
    assert.equal(un("\\377"), "ÿ");
  });
  test("code point escapes", () => {
    assert.equal(un("\\u{1F600}"), "\u{1F600}");
    assert.equal(un("\\U0001F600"), "\u{1F600}");
    assert.equal(un("\\ud83d\\ude00"), "\u{1F600}");
  });
  test("bell and escape", () => assert.equal(un("\\e[0m\\a"), "\x1b[0m\x07"));
  test("existing escapes unchanged", () => assert.equal(un("a\\tb\\x41\\u00e9\\\\"), "a\tbAé\\"));
});

group("dv-epoch", () => {
  const e = (value, unit) => run("dv-epoch", { value, mode: "e2d", unit });
  test("a millisecond value in seconds mode is flagged", () => assert.ok(/looks like milliseconds; read that way it is 2024-09-25T16:00:00.000Z/.test(e("1727280000000", "s"))));
  test("a seconds value in ms mode is flagged", () => assert.ok(/looks like seconds; read that way it is 2024-09-25T16:00:00.000Z/.test(e("1727280000", "ms"))));
  test("a plausible value has no note", () => assert.ok(!/looks like/.test(e("1727280000", "s"))));
  test("date-only input is read as midnight UTC and says so", () => {
    const r = run("dv-epoch", { value: "2024-09-25", mode: "d2e", unit: "s" });
    assert.ok(r.includes("1727222400") && /midnight UTC/.test(r));
  });
  test("a date-time without a zone says it used local time", () => assert.ok(/local time zone/.test(run("dv-epoch", { value: "2024-09-25T16:00:00", mode: "d2e" }))));
});
