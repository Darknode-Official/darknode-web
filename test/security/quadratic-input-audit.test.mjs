// Uploaded text with a long run of one character must not stall an engine. The header normaliser
// stripped "(...)" and "[...]" with /\([^)]*\)/g, which rescans to the end of the text from every
// unclosed "(": a 30k "(" upload took 8s in Proxy hunt and 3s in DNS hunt, and grew with the square.
import { test, assert, group } from "../harness.mjs";
import { stripEnclosed, normHeader } from "../../public/js/ingest/parse.js";

const J = "../../public/js/";
// Best of up to three runs, re-measured only when a run is slow: a shared CI runner can
// stall one linear run past the budget, while a real quadratic blow-up is slow every time
// (and a run over 5s is not retried).
const timed = (fn) => {
  let best = Infinity;
  for (let i = 0; i < 3 && best >= 300; i++) { const t = Date.now(); fn(); const ms = Date.now() - t; best = Math.min(best, ms); if (ms > 5000) break; }
  return best;
};

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

group("Trailing-whitespace trims stay linear", () => {
  test("Gemfile.lock line of 200k spaces then a letter", async () => {
    const { parseGemfileLock } = await import(J + "core/lockfiles.js");
    assert.ok(timed(() => parseGemfileLock(" ".repeat(200000) + "x\n")) < 500);
    assert.equal(parseGemfileLock("GEM\n  specs:\n    rack (2.2.3)   \n\nDEPENDENCIES\n  rack\n")[0].version, "2.2.3");
  });
  test("no /\\s+$/ replace left on user-data paths", async () => {
    const { readFileSync } = await import("node:fs");
    for (const f of ["core/lockfiles.js", "ingest/parse.js", "security-txt.js", "deck-ui.js", "tools/coding.js", "tools/forensics.js", "engine/engine.js", "appsec/apispec-engine.js"])
      assert.ok(!/\.replace\(\/\\s[+*]\$\//.test(readFileSync(new URL(J + f, import.meta.url), "utf8")), f);
  });
});

// /^\s*X/m: from every line start \s* ran across the whole blank-line run that follows, so a file
// of 30k newlines took about 3s in Firewall audit and 1.2s in network exposure and IaC scan.
group("Multiline ^\\s* anchors stay inside the line", () => {
  for (const [f, fn, wrap] of [["infra/firewall-audit-engine.js", "parseConfig"], ["appsec/iacscan-engine.js", "parseInput", true], ["exposure/netexposure-engine.js", "parseSslCert"], ["core/lockfiles.js", "detectFormat"], ["ops/pentestreg-engine.js", "parseInput"]]) {
    test(f + " " + fn + " on 200k newlines", async () => {
      const m = await import(J + f);
      const s = "\n".repeat(200000) + "x";
      assert.ok(timed(() => { try { m[fn](wrap ? [{ name: "f", text: s }] : s); } catch (_) {} }) < 1500);
    });
  }
  test("detection still sees an indented keyword after blank lines", async () => {
    const n = await import(J + "exposure/netexposure-engine.js");
    assert.equal(n.parseSslCert("\n\n   Subject: CN=a.test\n  Issuer: CN=ca\n").subject, "CN=a.test");
    const fw = await import(J + "infra/firewall-audit-engine.js");
    assert.equal(fw.detectFormat("\n\n  table inet filter {\n  chain input {\n type filter hook input\n").format, "nft");
  });
  test("no multiline /^\\s* left in live parsers", async () => {
    const { readFileSync } = await import("node:fs");
    for (const f of ["core/lockfiles.js", "exposure/netexposure-engine.js", "infra/firewall-audit-engine.js", "appsec/iacscan-engine.js", "ops/pentestreg-engine.js", "dataprotect/phish.js", "tools/dev.js", "tools/coding.js"])
      assert.ok(!/\/\^\\s\*(?:[^/\\\n\[]|\\.|\[(?:[^\]\\\n]|\\.)*\])*\/[gisuy]*m/.test(readFileSync(new URL(J + f, import.meta.url), "utf8")), f);
  });
});
