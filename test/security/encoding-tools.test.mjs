// Encoding quick tools (public/js/tools/encoding.js): Base64 / Base32 decode behaviour.

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
