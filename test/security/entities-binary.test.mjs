// HTML Entity decode knew about eight names, so &eacute; &copy; &mdash; stayed
// encoded, &#150; became a C1 control instead of the en dash browsers show, and
// &copy without ";" was left alone. Base64 / Base32 / Hex decode turned bytes that
// are not UTF-8 into U+FFFD, so the data was lost; they now show hex.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/encoding.js";

const run = (id, v) => TOOLS.find((t) => t.id === id).run(v, H);
const dec = (text) => run("html-entities", { text, mode: "Decode" });

group("html-entities decode (HTML5 rules)", () => {
  test("HTML 4 named set", () => assert.equal(dec("&eacute;&copy;&mdash;&hellip;&euro;&alpha;"), "é©—…€α"));
  test("Windows-1252 numeric range", () => { assert.equal(dec("&#150;"), "–"); assert.equal(dec("&#x80;"), "€"); });
  test("legacy names without semicolon", () => { assert.equal(dec("&copy 2026"), "© 2026"); assert.equal(dec("&notit;"), "¬it;"); });
  test("numeric without semicolon", () => assert.equal(dec("&#65 &#x42"), "A B"));
  test("HTML5 lang/rang", () => assert.equal(dec("&lang;&rang;"), "⟨⟩"));
  test("unknown names stay", () => assert.equal(dec("&notanentity;x &xyz;"), "¬anentity;x &xyz;"));
  test("invalid code points are U+FFFD", () => assert.equal(dec("&#0;&#xD800;&#x110000;"), "���"));
});

group("binary decodes show hex", () => {
  test("base64 0xff", () => assert.equal(run("base64", { text: "/w==", mode: "Decode" }), "(not UTF-8 text - 1 bytes as hex)\nff"));
  test("base32 0xff", () => assert.ok(run("base32", { text: "74======", mode: "Decode" }).endsWith("\nff")));
  test("hex ff fe 41", () => assert.ok(run("hex-text", { text: "ff fe 41", mode: "Hex → Text" }).endsWith("\nff fe 41")));
  test("valid UTF-8 still text", () => { assert.equal(run("base64", { text: "8J+YgA==", mode: "Decode" }), "\u{1F600}"); assert.equal(run("base64", { text: "77+9", mode: "Decode" }), "�"); });
});
