// .env Parser and .env to export Lines split on the first = per line, so an
// inline "# comment" stayed in the value, a quoted value spanning lines broke,
// \n inside double quotes was not expanded and backtick quotes were kept. Both
// now use the dotenv package's rules; export skips names a shell cannot export.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/devx.js";

const run = (id, text) => TOOLS.find((t) => t.id === id).run({ text }, H);
const parsed = (text) => Object.fromEntries(run("dv-env-parse", text).split("\n").map((l) => /^(\S+)\s* = (.*?)(?:   \(set.*)?$/.exec(l).slice(1, 3)));

group("dv-env-parse (dotenv rules)", () => {
  test("inline comments are dropped, quoted # kept", () => {
    const r = parsed('B = two words # comment\nC="quoted # not comment"\nF=url#frag');
    assert.equal(r.B, "two words"); assert.equal(r.C, "quoted # not comment"); assert.equal(r.F, "url");
  });
  test("multi-line and escaped newlines", () => {
    const r = parsed('H="multi\nline"\nE="l1\\nl2"\nK=\'a\\nb\'');
    assert.equal(r.H, JSON.stringify("multi\nline"));
    assert.equal(r.E, JSON.stringify("l1\nl2"));
    assert.equal(r.K, "a\\nb");
  });
  test("backticks and export prefix", () => assert.deepEqual(parsed("export A=1\nJ=`bt`"), { A: "1", J: "bt" }));
  test("duplicate keys: last wins and it says so", () => assert.ok(/^A = 2   \(set 2 times; the last one wins\)$/.test(run("dv-env-parse", "A=1\nA=2"))));
});

group("dv-env-export", () => {
  test("comment not exported, multi-line kept, bad names skipped", () => {
    const r = run("dv-env-export", 'B = two words # c\nH="m\nl"\nx.y=1');
    assert.ok(r.includes("export B='two words'\n"));
    assert.ok(r.includes("export H='m\nl'"));
    assert.ok(r.includes("# skipped x.y"));
  });
});
