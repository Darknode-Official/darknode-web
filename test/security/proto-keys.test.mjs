// Quick tools that build objects from pasted keys: "__proto__" and "constructor"
// must stay ordinary keys. Before, unflatten and the INI parser wrote through to
// Object.prototype (every object on the page gained the property), merge and
// key-by dropped or crashed on them, and table/CSV output printed native source.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as CODING } from "../../public/js/tools/coding.js";
import { TOOLS as DEV } from "../../public/js/tools/dev.js";

const run = (id, v) => [...CODING, ...DEV].find((t) => t.id === id).run(v, H);
const clean = () => { const bad = ({}).polluted !== undefined || Object.polluted !== undefined; delete Object.prototype.polluted; delete Object.polluted; return !bad; };

group("prototype-named keys in pasted data", () => {
  test("JSON Unflatten keeps __proto__ as a key and leaves Object.prototype alone", () => {
    const out = JSON.parse(run("cd-json-unflatten", { json: '{"__proto__.polluted":1,"a.b":2}' }));
    assert.ok(clean());
    assert.deepEqual(Object.keys(out), ["__proto__", "a"]);
    assert.equal(out.__proto__ === Object.prototype, false);
  });
  test("INI to JSON keeps [__proto__] and [constructor] sections as data", () => {
    const out = JSON.parse(run("d-ini-to-json", { ini: "[__proto__]\npolluted = 1\n[constructor]\npolluted = 2\n" }));
    assert.ok(clean());
    assert.deepEqual(Object.keys(out), ["__proto__", "constructor"]);
  });
  test("JSON Deep Merge keeps a __proto__ key", () => {
    assert.ok(/"__proto__"/.test(run("cd-json-merge", { base: '{"a":1}', over: '{"__proto__":{"x":1}}' })));
    assert.ok(clean());
  });
  test("Key-By groups an id named constructor and keys one named __proto__", () => {
    const g = JSON.parse(run("cd-json-keyby", { json: '[{"id":"constructor"},{"id":"__proto__"}]', field: "id", mode: "Group by (array)" }));
    assert.deepEqual(Object.keys(g), ["constructor", "__proto__"]);
    const k = run("cd-json-keyby", { json: '[{"id":"__proto__"}]', field: "id", mode: "Key by (last wins)" });
    assert.ok(/"__proto__"/.test(k));
  });
  test("JSON to CSV and JSON to Table leave a missing constructor column empty", () => {
    assert.equal(run("cd-json-to-csv", { json: '[{"constructor":1},{"a":2}]', delim: ",", header: true }), 'constructor,a\n1,\n,2\n');
    assert.ok(!/native code/.test(run("d-json-to-table", { json: '[{"constructor":1},{"a":2}]' })));
  });
});
