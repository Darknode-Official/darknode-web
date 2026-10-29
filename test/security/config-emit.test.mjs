// JSON to YAML / TOML: strings that a parser would misread or reject must come
// out quoted and escaped. Expected text is what PyYAML and Python's tomllib read
// back as the original value.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/coding.js";

const run = (id, v) => TOOLS.find((t) => t.id === id).run(v, H);

group("JSON to YAML quoting", () => {
  test("tab, CR and control characters are escaped inside quotes", () => {
  const y = run("cd-json-to-yaml", { json: JSON.stringify({ a: "tab\tx", b: "a\rb", c: "x\u0001y", d: "\u2028" }) });
  assert.equal(y, 'a: "tab\\tx"\nb: "a\\rb"\nc: "x\\u0001y"\nd: "\\u2028"\n');
});
  test(".inf and .nan stay strings", () => {
  assert.equal(run("cd-json-to-yaml", { json: '{"a":".inf","b":"-.NaN"}' }), 'a: ".inf"\nb: "-.NaN"\n');
});
});

group("JSON to TOML strings", () => {
  test("control characters are written as \\u escapes", () => {
  assert.equal(run("cd-json-to-toml", { json: '{"a":"x\\u0001y\\u007f"}' }), 'a = "x\\u0001y\\u007f"\n');
});
});

group("JSON to CSV rows", () => {
  test("an empty value in a single-column row is written as \"\" so readers keep the row", () => {
    assert.equal(run("cd-json-to-csv", { json: '[{"id":""},{"id":"a"}]', delim: ",", header: true }), 'id\n""\na\n');
  });
});
