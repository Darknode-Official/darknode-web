// .env to JSON and .env Validator read a file as the dotenv package does: a # comment after
// a value, export lines, KEY: value, and quoted values that span lines or expand \n.
import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/dev.js";

const run = (id, env) => TOOLS.find((t) => t.id === id).run({ env }, H);

group(".env tools: dotenv rules", () => {
  test("comments, export, colons and quoted values", () => {
    assert.deepEqual(JSON.parse(run("d-env-to-json", 'A=1 # note\nexport B=2\nI: colon\nC="line1\nline2"\nD="a\\nb"\nE=\'x # y\'\nG.H=1')),
      { A: "1", B: "2", I: "colon", C: "line1\nline2", D: "a\nb", E: "x # y", "G.H": "1" });
  });
  test("the validator counts a value that is only a comment as blank and reports real line numbers", () => {
    assert.equal(run("d-env-validate", "\n\nA=1\n# c\nB=\nA=2 # again\nC=\"x\ny\"\nD= # none\n"),
      "4 unique key(s) found.\nDuplicate keys: A (line 6)\nBlank values: B (line 5), D (line 9)");
  });
});

import { TOOLS as DEVX } from "../../public/js/tools/devx.js";

group("JSON to .env: values read back the same", () => {
  const out = (o) => DEVX.find((t) => t.id === "dv-json-to-env").run({ text: JSON.stringify(o) }, H);
  test("a # or a quote is quoted the way dotenv reads it, and no escapes are added", () => {
    assert.equal(out({ db: { pw: "ab#cd" }, msg: "it's ok", p: "C:\\dir \"x\"", n: "a\nb" }), "DB_PW='ab#cd'\nMSG=it's ok\nP=C:\\dir \"x\"\nN='a\nb'");
  });
  test("a value no .env quoting can hold is skipped with a note", () => {
    assert.ok(/^# K skipped/.test(out({ k: "'`\"" })));
  });
});
