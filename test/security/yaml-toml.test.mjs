// JSON to YAML / TOML write text a YAML or TOML reader gives back unchanged, and YAML to JSON
// reads the explicit "? key" form PyYAML writes for long or multi-line keys.
import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/coding.js";

const run = (id, k, text) => { const t = TOOLS.find((x) => x.id === id); const v = {}; for (const i of t.inputs) v[i.k] = i.value; v[k] = text; return t.run(v, H); };
const toYaml = (o) => run("cd-json-to-yaml", "json", JSON.stringify(o));
const fromYaml = (y) => JSON.parse(run("cd-yaml-to-json", "yaml", y));
const toToml = (o) => run("cd-json-to-toml", "json", JSON.stringify(o));

group("quick tools: YAML and TOML", () => {
  test("a << or = key is quoted (a YAML 1.1 merge key / value tag otherwise)", () => {
    const y = toYaml({ "<<": 1, "=": 2 });
    assert.ok(/^"<<": 1$/m.test(y) && /^"=": 2$/m.test(y), y);
    assert.deepEqual(fromYaml(y), { "<<": 1, "=": 2 });
  });
  test("a TOML key with a line break is escaped, not written raw", () => {
    const t = toToml({ "x\ny": 1, sec: { "a\tb\u0001": 2 } });
    assert.ok(!/x\ny/.test(t), t);
    assert.ok(t.includes('"x\\ny" = 1'), t);
    assert.deepEqual(JSON.parse(run("cd-toml-to-json", "toml", t)), { "x\ny": 1, sec: { "a\tb\u0001": 2 } });
  });
  test("explicit ? keys in block and flow mappings", () => {
    const long = "k".repeat(150);
    assert.deepEqual(fromYaml("? " + long + "\n: - 1\n  - a: 2\nb: 3\n"), { [long]: [1, { a: 2 }], b: 3 });
    assert.deepEqual(fromYaml("? 'x\n\n  y'\n: p: 1\nm:\n  ? ''\n  : null\n  ? q\n"), { "x\ny": { p: 1 }, m: { "": null, q: null } });
    assert.deepEqual(fromYaml("- ? a\n  : ? b\n    : 1\n"), [{ a: { b: 1 } }]);
    assert.deepEqual(fromYaml("{? 'x y' : 1, b: 2}"), { "x y": 1, b: 2 });
  });
});
