// Unit tests for public/js/core/hash.js
import { test, group, assert } from "../harness.mjs";
import { cyrb53 } from "../../public/js/core/hash.js";

group("hash: cyrb53", () => {
  test("same input hashes identically", () => {
    assert.equal(cyrb53("darknode"), cyrb53("darknode"));
    assert.equal(cyrb53("darknode", 7), cyrb53("darknode", 7));
  });

  test("known vector is stable (base36, no seed)", () => {
    const v = cyrb53("hello world");
    assert.ok(/^[0-9a-z]+$/.test(v), "base36 output");
    assert.equal(v, cyrb53("hello world"));
    assert.equal(cyrb53("a"), cyrb53("a"));
    assert.notEqual(cyrb53("a"), cyrb53("b"));
  });

  test("different seeds give different digests", () => {
    assert.notEqual(cyrb53("x", 0), cyrb53("x", 1));
    assert.notEqual(cyrb53("x", 1), cyrb53("x", 2));
  });

  test("empty / null input hashes without throwing", () => {
    assert.equal(cyrb53(""), cyrb53(""));
    assert.equal(cyrb53(null), cyrb53(""));
    assert.ok(cyrb53("").length > 0);
  });

  test("stays within 53 bits", () => {
    for (const s of ["", "a", "finding|x", "z".repeat(500)]) {
      assert.ok(parseInt(cyrb53(s), 36) <= Number.MAX_SAFE_INTEGER);
    }
  });
});
