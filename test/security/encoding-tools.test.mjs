// Encoding quick tools on awkward input. The HTML entity decoder threw on a code
// point past U+10FFFF and printed native source for &constructor;, Morse decode
// did the same for a "constructor" token, and A1Z26 dropped word breaks so its
// own output could not be decoded back.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/encoding.js";

const run = (id, v) => TOOLS.find((t) => t.id === id).run(v, H);

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
