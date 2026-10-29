// Encoding quick tools (public/js/tools/encoding.js): Base64 / Base32 decode behaviour,
// and awkward input for HTML entities, Morse and A1Z26 (see the second group).

import { test, assert, group } from "../harness.mjs";
import { TOOLS } from "../../public/js/tools/encoding.js";
import { H } from "../../public/js/tools/_helpers.js";

const run = (id, v) => TOOLS.find((t) => t.id === id).run(v, H);

group("encoding tools: decode", () => {
  test("Base64 decode accepts base64url (- and _) without the URL-safe box", () => {
    const s = "emoji \u{1F600} ok \u0000\u0001";
    assert.equal(run("base64", { text: Buffer.from(s).toString("base64url"), mode: "Decode", url: false }), s);
    assert.equal(run("base64", { text: Buffer.from(s).toString("base64"), mode: "Decode", url: false }), s);
  });
  test("Base32 matches the RFC 4648 vectors and rejects characters outside the alphabet", () => {
    for (const [i, o] of [["f", "MY======"], ["fooba", "MZXW6YTB"], ["foobar", "MZXW6YTBOI======"]]) {
      assert.equal(run("base32", { text: i, mode: "Encode" }), o);
      assert.equal(run("base32", { text: o.toLowerCase(), mode: "Decode" }), i);
    }
    assert.ok(run("base32", { text: "0189abcd", mode: "Decode" }).error);
  });
});

group("encoding tools", () => {
  test("html entities: out-of-range and zero code points decode to U+FFFD", () => {
    assert.equal(run("html-entities", { text: "&#x110000;&#0;&#xD800;", mode: "Decode" }), "���");
  });
  test("html entities: built-in names are not entities", () => {
    assert.equal(run("html-entities", { text: "&constructor; &toString; &lt;", mode: "Decode" }), "&constructor; &toString; <");
  });
  test("html entities: &#1a; is not decimal 1", () => {
    assert.equal(run("html-entities", { text: "&#1a; &#65;", mode: "Decode" }), "&#1a; A");
  });
  test("morse: an unknown token decodes to nothing, not native source", () => {
    assert.equal(run("morse", { text: "... constructor ---", mode: "Morse → Text" }), "SO");
  });
  test("a1z26: keeps words and round-trips", () => {
    const enc = run("a1z26", { text: "Hello, World", mode: "Text → Numbers" });
    assert.equal(enc, "8-5-12-12-15, 23-15-18-12-4");
    assert.equal(run("a1z26", { text: enc, mode: "Numbers → Text" }), "hello, world");
  });
  test("a1z26: a plain space-separated list still decodes", () => {
    assert.equal(run("a1z26", { text: "8 5 12 12 15", mode: "Numbers → Text" }), "hello");
  });
});
