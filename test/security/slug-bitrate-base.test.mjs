// Filename slug dropped inner dots (archive.tar.gz became archivetar.gz), never
// cleaned an "extension" with a space (a.b c came back as is) and kept Windows
// device names (con.txt). Bitrate humanizer showed 999999 bps as 1000.00 kbps.
// Base converter refused 0xff in base 16 and 1_000, and printed -0.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/devx.js";

const run = (id, v) => TOOLS.find((t) => t.id === id).run(v, H);
const slug = (name) => run("dv-slug-filename", { name });
const base = (num, from, to) => run("dv-base-convert", { num, from, to });

group("dv-slug-filename", () => {
  test("double extension kept", () => assert.equal(slug("archive.tar.gz"), "archive.tar.gz"));
  test("inner dots become separators", () => assert.equal(slug("my.report.v2.pdf"), "my-report-v2.pdf"));
  test("no space survives", () => assert.equal(slug("a.b c"), "a-b-c"));
  test("Windows device names are changed", () => { assert.equal(slug("CON.txt"), "con-file.txt"); assert.equal(slug("nul"), "nul-file"); });
  test("existing behaviour", () => assert.equal(slug("My Report (Final v2).PDF"), "my-report-final-v2.pdf"));
});

group("dv-bitrate-humanize", () => {
  test("rolls over after rounding", () => assert.equal(run("dv-bitrate-humanize", { bps: "999999" }), "1.00 Mbps"));
});

group("dv-base-convert", () => {
  test("prefix of the source base", () => { assert.equal(base("0xff", 16, 10), "255"); assert.equal(base("0b101", 2, 10), "5"); });
  test("0b1 in base 16 is a hex number", () => assert.equal(base("0b1", 16, 10), "177"));
  test("_ separators", () => { assert.equal(base("1_000", 10, 16), "3e8"); assert.ok(base("1__0", 10, 2).error); });
  test("no -0 and no empty number", () => { assert.equal(base("-0", 10, 2), "0"); assert.ok(base("-", 10, 2).error); });
});
