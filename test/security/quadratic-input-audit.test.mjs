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
  test("risk register parseNum on a 200k digit run", async () => {
    const m = await import(J + "risk/riskreg-engine.js");
    assert.equal(m.parseNum("$1,250.5k"), 1250500); assert.equal(m.parseNum(".5"), 0.5); assert.equal(m.parseNum("5."), null);
    assert.ok(timed(() => assert.equal(m.parseNum("9".repeat(200000) + "g"), null)) < 500);
  });
  test("IOC extraction on long dotted and letter runs", async () => {
    for (const f of ["siem-engine.js", "threat-engine.js"]) {
      const m = await import(J + f);
      const r = m.extractIOCs("mail ops.team@corp.example.org from c2.evil-host.ru now");
      assert.ok(JSON.stringify(r).includes("ops.team@corp.example.org") && JSON.stringify(r).includes("c2.evil-host.ru"), f);
      for (const x of ["a.".repeat(100000) + "@", "1.".repeat(100000), "a".repeat(200000)]) assert.ok(timed(() => m.extractIOCs(x)) < 1500, f);
    }
  });
});
