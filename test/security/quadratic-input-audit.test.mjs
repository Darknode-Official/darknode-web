// Uploaded text with a long run of one character must not stall an engine. The header normaliser
// stripped "(...)" and "[...]" with /\([^)]*\)/g, which rescans to the end of the text from every
// unclosed "(": a 30k "(" upload took 8s in Proxy hunt and 3s in DNS hunt, and grew with the square.
import { test, assert, group } from "../harness.mjs";
import { stripEnclosed, normHeader } from "../../public/js/ingest/parse.js";

const J = "../../public/js/";
const timed = (fn) => { const t = Date.now(); fn(); return Date.now() - t; };

group("Long single-character runs stay linear", () => {
  test("stripEnclosed gives the regex result", () => {
    const T = ["(", ")", "[", "]", "a", " ", "(x)"];
    for (let k = 0; k < 20000; k++) {
      let s = ""; for (let j = k % 11; j--;) s += T[(k * 7 + j * 13) % T.length];
      assert.equal(stripEnclosed(s, "(", ")"), s.replace(/\([^)]*\)/g, ""), JSON.stringify(s));
      assert.equal(stripEnclosed(s, "[", "]", " "), s.replace(/\[[^\]]*\]/g, " "), JSON.stringify(s));
    }
    assert.equal(normHeader("User Name (UPN) [Required]"), "username");
  });
  for (const [f, fn] of [["ops/proxyhunt-engine.js", "parseInput"], ["ops/dnshunt-engine.js", "parseInput"], ["risk/backupready-engine.js", "parseInput"], ["identity/jml-engine.js", "parseInput"]]) {
    test(f + " on 200k \"(\"", async () => {
      const m = await import(J + f);
      const ms = timed(() => { try { m[fn]("(".repeat(200000)); } catch (_) {} });
      assert.ok(ms < 1500, "took " + ms + "ms");
    });
  }
  test("access review name normaliser on 200k \"(\"", async () => {
    const m = await import(J + "identity/access-review-engine.js");
    assert.equal(m.normalizeName("John (Contractor) Doe"), "john doe");
    assert.ok(timed(() => m.normalizeName("(".repeat(200000))) < 1500);
  });
});
