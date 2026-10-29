// Text Diff / Diff Summary Stats and the JSON Path Extractor.
import { test, assert, group } from "../harness.mjs";
import { TOOLS } from "../../public/js/tools/dev.js";

const tool = (id) => TOOLS.find((t) => t.id === id);

group("quick tools: Text Diff", () => {
  test("identical texts say so", () => {
    assert.equal(tool("d-diff").run({ a: "x\ny", b: "x\ny" }), "(identical)");
  });
  test("two large files with a few edits diff fast and minimally", () => {
    const big = Array.from({ length: 12000 }, (_, i) => "l" + i).join("\n");
    const b = big.replace("l500\n", "l500x\n") + "\nz";
    const t0 = Date.now();
    const out = tool("d-diff").run({ a: big, b });
    assert.ok(Date.now() - t0 < 300, "took " + (Date.now() - t0) + " ms");
    assert.deepEqual(out.split("\n").filter((l) => !l.startsWith("  ")), ["- l500", "+ l500x", "+ z"]);
    assert.equal(tool("d-diff-stats").run({ a: big, b }), "Added: 2\nRemoved: 1\nUnchanged: 11999");
  });
  test("the diff rebuilds both texts and keeps the longest common subsequence", () => {
    assert.equal(tool("d-diff").run({ a: "a\nb\nc\na\nb\nb\na", b: "c\nb\na\nb\na\nc" }).split("\n").filter((l) => l.startsWith("  ")).length, 4);
  });
});

group("quick tools: JSON Path Extractor reads the data's own keys", () => {
  const get = (path) => tool("d-json-path").run({ json: '{"a":{"b":1},"s":"abc","q":{"__proto__":7}}', path });
  test("inherited names are not found", () => {
    for (const p of ["a.constructor", "a.toString", "__proto__", "s.length"]) assert.deepEqual(get(p), { error: "Path not found." }, p);
  });
  test("own keys, including __proto__ in the data, are found", () => {
    assert.equal(get("a.b"), "1");
    assert.equal(get("q.__proto__"), "7");
  });
});
