// UUID v7 and ULID batches generated in one millisecond came out in random order,
// so the "sortable" IDs did not sort in generation order; within a millisecond each
// ID is now the previous one plus one. The npm name validator never checked the
// scope (@Sc ope/x passed), allowed ~, and missed core-module names such as http;
// it now follows validate-npm-package-name (the check npm publish runs).

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/devx.js";

const run = (id, v) => TOOLS.find((t) => t.id === id).run(v, H);
const frozen = (fn) => { const now = Date.now; Date.now = () => 1790000000000; try { return fn(); } finally { Date.now = now; } };

group("sortable ID batches", () => {
  for (const id of ["dv-uuid-v7", "dv-ulid"]) {
    test(id + " batch in one millisecond is ordered and unique", () => {
      const a = frozen(() => run(id, { count: 100 })).split("\n");
      assert.equal(a.length, 100);
      assert.equal(new Set(a).size, 100);
      assert.equal(a.join(), [...a].sort().join());
    });
  }
  test("v7 keeps version and variant bits", () => {
    for (const u of frozen(() => run("dv-uuid-v7", { count: 50 })).split("\n")) {
      assert.ok(/^0[0-9a-f]{7}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(u), u);
      assert.equal(parseInt(u.replace(/-/g, "").slice(0, 12), 16), 1790000000000);
    }
  });
});

group("dv-npm-name-validate", () => {
  const v = (name) => run("dv-npm-name-validate", { name });
  test("valid names", () => {
    assert.ok(v("@scope/my-pkg").startsWith("VALID"));
    assert.ok(v("left-pad").startsWith("VALID"));
  });
  test("scope part is checked", () => assert.ok(v("@sc ope/x").startsWith("INVALID:")));
  test("core module and ~ are refused for new packages", () => {
    assert.ok(v("http").startsWith("INVALID for new"));
    assert.ok(v("x~y").startsWith("INVALID for new"));
  });
  test("blocked names are case-insensitive", () => assert.ok(v("Favicon.ico").startsWith("INVALID:")));
  test("leading space is reported, not trimmed away", () => assert.ok(/spaces/.test(v(" x"))));
});
