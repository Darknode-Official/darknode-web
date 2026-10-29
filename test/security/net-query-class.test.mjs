// Network Query String Parser kept the #fragment in the last value and took
// "https://host/p?a" as the first key. IP Class labelled 0.x and 127.x as
// "Class A (1.0.0.0 - 126.255.255.255)", a range that does not contain them.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/network.js";

const run = (id, v) => TOOLS.find((t) => t.id === id).run(v, H);

group("n-query-parser", () => {
  test("fragment dropped", () => assert.equal(run("n-query-parser", { qs: "?x=1&y=2#frag" }), "x = 1\ny = 2"));
  test("full URL", () => assert.equal(run("n-query-parser", { qs: "https://h.test/p?a=1&b=2" }), "a = 1\nb = 2"));
  test("? inside a bare value stays", () => assert.equal(run("n-query-parser", { qs: "a=b?c" }), "a = b?c"));
  test("hash params", () => assert.equal(run("n-query-parser", { qs: "#t=1" }), "t = 1"));
});

group("n-ip-class", () => {
  test("Class A range covers 0 and 127", () => {
    assert.ok(run("n-ip-class", { ip: "0.0.0.1" }).startsWith("Class A (0.0.0.0 - 127.255.255.255)"));
    assert.ok(/loopback/.test(run("n-ip-class", { ip: "127.0.0.1" })));
    assert.equal(run("n-ip-class", { ip: "10.0.0.1" }), "Class A (0.0.0.0 - 127.255.255.255)");
  });
});
