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

group("YAML to JSON parser", () => {
  const parse = (yaml) => { const r = run("cd-yaml-to-json", { yaml }); return typeof r === "string" ? JSON.parse(r) : r; };
  // expected values are what PyYAML's safe_load returns for the same text
  test("nested lists written as - - a stay lists", () => {
    assert.deepEqual(parse("- - 1\n  - 2\n- - 3\n"), [[1, 2], [3]]);
  });
  test("a top-level flow mapping is a mapping, not one key", () => {
    assert.deepEqual(parse("{a: 1, b: [x, y]}\n"), { a: 1, b: ["x", "y"] });
  });
  test("| and > block scalars, with chomping", () => {
    assert.deepEqual(parse("run: |\n  echo a # kept\n\n  echo b\nf: >-\n  one\n  two\nk: |+\n  x\n\nz: 1\n"), { run: "echo a # kept\n\necho b\n", f: "one two", k: "x\n\n", z: 1 });
  });
  test("an apostrophe in plain text does not hide a comment", () => {
    assert.deepEqual(parse("a: don't # note\nb: 'it''s'\n"), { a: "don't", b: "it's" });
  });
  test("multi-line quoted and plain strings fold, flow collections span lines", () => {
    assert.deepEqual(parse("a: 'multi\n  line\n\n  para'\nb: plain\n  more\nc: [1,\n  2]\n"), { a: "multi line\npara", b: "plain more", c: [1, 2] });
  });
  test("YAML escapes in double quotes and URLs in flow maps", () => {
    assert.deepEqual(parse('a: "\\x41\\t\\e"\nu: {u: http://x.test/p}\n'), { a: "A\t\x1b", u: { u: "http://x.test/p" } });
  });
  test("content after the first node, anchors and second documents are errors, not dropped", () => {
    assert.ok(parse("a: 1\n- b\n").error);
    assert.ok(parse("a: &x 1\nb: *x\n").error);
    assert.ok(parse("a: 1\n---\nb: 2\n").error);
  });
});

group("TOML to JSON parser", () => {
  const parse = (toml) => { const r = run("cd-toml-to-json", { toml, indent: "Minify" }); return typeof r === "string" ? JSON.parse(r) : r; };
  // expected values are what Python's tomllib returns for the same text
  test("multi-line strings and arrays with comments, as in pyproject.toml", () => {
    assert.deepEqual(parse('d = """\nline1\nline2"""\nj = """a \\\n   b"""\nr = \'\'\'\nraw\\n\'\'\'\ndeps = [\n  "requests>=2",  # http\n  "rich",\n]\n'), { d: "line1\nline2", j: "a b", r: "raw\\n", deps: ["requests>=2", "rich"] });
  });
  test("a duplicate key or a table defined twice is an error, not last-wins", () => {
    assert.ok(parse("a = 1\na = 2\n").error);
    assert.ok(parse("[a]\nx = 1\n[a]\ny = 2\n").error);
    assert.ok(parse("[fruit]\napple.color = 'red'\n[fruit.apple]\n").error);
  });
  test("dotted keys and array-of-tables nesting follow the spec", () => {
    assert.deepEqual(parse("[[f]]\nn = 'a'\n[f.p]\nc = 'r'\n[[f.v]]\nn = 'x'\n[[f]]\nn = 'b'\n"), { f: [{ n: "a", p: { c: "r" }, v: [{ n: "x" }] }, { n: "b" }] });
    assert.deepEqual(parse("[a.b.c]\n[a]\nb.d = 1\n"), { a: { b: { c: {}, d: 1 } } });
  });
  test("integers past 2^53 keep every digit and an invalid token is an error", () => {
    assert.equal(run("cd-toml-to-json", { toml: "big = 9007199254740993\n", indent: "Minify" }), '{"big":9007199254740993}');
    assert.ok(parse("k = 1 x\n").error);
    assert.ok(parse("k = 01\n").error);
  });
});
