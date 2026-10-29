// Reference tools that look a typed name up in a table: a built-in name like
// constructor or toString is not an entry. Before, the header and MIME lookups
// returned the source of Object() as the answer, Cache-Control printed it as a
// directive's note, and the severity normalizer took it as a level.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as WEB } from "../../public/js/tools/webhttp.js";
import { TOOLS as BLUE } from "../../public/js/tools/blueteam.js";

const run = (id, v) => [...WEB, ...BLUE].find((t) => t.id === id).run(v, H);

group("table lookups ignore built-in names", () => {
  test("request/response header reference", () => {
    assert.ok(run("wb-req-headers", { name: "constructor" }).error);
    assert.ok(run("wb-res-headers", { name: "toString" }).error);
    assert.ok(/authorization/.test(run("wb-req-headers", { name: "Authorization" }).out));
  });
  test("MIME by extension and favicon type", () => {
    assert.ok(run("wb-mime-by-ext", { ext: "x.constructor" }).error);
    assert.equal(run("wb-favicon-link", { href: "/a.constructor" }, H).out, '<link rel="icon" href="/a.constructor">');
  });
  test("Cache-Control: built-in names get no note; directives are case-insensitive", () => {
    assert.equal(run("wb-cachecontrol-parse", { cc: "toString, Public, no-store" }).out, "toString\nPublic  (may be cached by any cache)\nno-store  (never cache anywhere)");
  });
  test("severity normalizer rejects a built-in name", () => {
    assert.ok(run("bt-severity-normalize", { scale: "Qualitative (none/low/medium/high/critical)", value: "constructor" }).error);
  });
});
