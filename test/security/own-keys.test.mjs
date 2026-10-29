// Names typed by the user are looked up as the data's own keys: constructor, toString and
// __proto__ are ordinary names, not Object.prototype members.
import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as DEVX } from "../../public/js/tools/devx.js";
import { TOOLS as CODING } from "../../public/js/tools/coding.js";
import { TOOLS as BLUE } from "../../public/js/tools/blueteam.js";

const tool = (list, id) => list.find((t) => t.id === id);

group("quick tools: prototype names are ordinary names", () => {
  test("Query String to JSON keeps constructor, toString and __proto__", () => {
    assert.equal(tool(DEVX, "dv-querystring").run({ text: "constructor=1&__proto__=x&toString=2&a=1&a=2", mode: "parse" }, H),
      '{\n  "constructor": "1",\n  "__proto__": "x",\n  "toString": "2",\n  "a": [\n    "1",\n    "2"\n  ]\n}');
  });
  test("envsubst leaves $constructor unfilled and substitutes a __proto__ variable", () => {
    assert.equal(tool(CODING, "cd-envsubst").run({ template: "a $constructor ${toString} $__proto__ $X", vars: "X=1\n__proto__=p" }, H), "a $constructor ${toString} p 1");
  });
  test("grok builder and tester report %{constructor} as unknown instead of crashing", () => {
    assert.deepEqual(tool(BLUE, "bt-grok-build").run({ tokens: "constructor x" }, H), { error: "Unknown grok pattern: constructor (see Grok Pattern Reference)." });
    assert.deepEqual(tool(BLUE, "bt-grok-test").run({ pattern: "%{toString:x}", sample: "abc" }, H), { error: "Unknown grok pattern(s): toString" });
  });
});
