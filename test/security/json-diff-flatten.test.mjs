// JSON Diff, JSON Flattener and JSON Schema Inferrer (public/js/tools/dev.js).

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/dev.js";

const run = (id, v) => TOOLS.find((t) => t.id === id).run(v, H);

group("JSON Diff and Flattener: paths and own keys", () => {
  test("a key named constructor is added, not changed from undefined", () => {
    assert.equal(run("d-json-diff", { a: "{}", b: '{"constructor":1}' }), "+ constructor: 1");
  });
  test("a dotted key and a nested key are different paths", () => {
    assert.equal(run("d-json-diff", { a: '{"a":{"b":1}}', b: '{"a.b":1}' }), '+ ["a.b"]: 1\n- a.b: 1');
    assert.deepEqual(JSON.parse(run("d-json-flatten", { json: '{"a":{"b":1},"a.b":2}' })), { "a.b": 1, '["a.b"]': 2 });
  });
  test("an empty root adds no $ entry; roots of different kinds are reported", () => {
    assert.equal(run("d-json-diff", { a: '{"a":{}}', b: "{}" }), "- a: {}");
    assert.equal(run("d-json-diff", { a: "[]", b: "{}" }), "~ (root): [] -> {}");
  });
  test("a __proto__ key is flattened like any other", () => {
    assert.equal(run("d-json-flatten", { json: '{"__proto__":5}' }).replace(/\s+/g, ""), '{"__proto__":5}');
  });
});

group("JSON Schema Inferrer: every array item", () => {
  test("item schemas merge: types union, required is what every item has", () => {
    const s = JSON.parse(run("d-json-schema-infer", { json: '[{"a":1},{"a":"x","b":2}]' }));
    assert.deepEqual(s.items, { type: "object", properties: { a: { type: ["integer", "string"] }, b: { type: "integer" } }, required: ["a"] });
    assert.deepEqual(JSON.parse(run("d-json-schema-infer", { json: "[1,2.5]" })).items, { type: "number" });
  });
});
