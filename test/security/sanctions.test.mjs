// Sanctions screening engine tests (public/js/finsec/sanctions-engine.js):
// deterministic watchlist name matching. Mirrors the in-engine selfTest and adds
// scoring, parsing and determinism assertions.

import { test, assert, group } from "../harness.mjs";
import {
  normName, tokens, levenshtein, band, buildIndex, screenName, screenBatch, parseOfac, selfTest,
} from "../../public/js/finsec/sanctions-engine.js";

group("sanctions: engine self-test", () => {
  test("all in-engine self-test checks pass", () => {
    const { pass, results } = selfTest();
    assert.ok(pass, "self-test failures: " + results.filter((r) => !r.pass).map((r) => r.name).join(", "));
  });
});

group("sanctions: normalization", () => {
  test("normName latinizes, lowercases, strips punctuation", () => {
    assert.equal(normName("José Peña S.A."), "jose pena s a");
  });
  test("tokens remove suffixes and short fragments", () => {
    assert.deepEqual(tokens("The Acme Holding Group Ltd"), ["acme"]);
  });
  test("levenshtein edit distance", () => {
    assert.equal(levenshtein("flaw", "lawn"), 2);
    assert.equal(levenshtein("abc", "abc"), 0);
  });
});

group("sanctions: matching", () => {
  const idx = buildIndex([
    { uid: "1", name: "MAERSK LINE", type: "entity", program: "X", names: ["MAERSK LINE"] },
    { uid: "2", name: "IVAN IVANOV", type: "individual", program: "RUSSIA", names: ["IVAN IVANOV", "Ivan Petrovich IVANOV"] },
  ]);
  test("exact match bands as exact", () => {
    const r = screenName("Maersk Line", idx);
    assert.equal(r[0].uid, "1");
    assert.equal(r[0].band, "exact");
  });
  test("one-token typo still screens in", () => {
    const r = screenName("Ivan Ivanof", idx);
    assert.ok(r.some((m) => m.uid === "2"));
  });
  test("alias name matches the entity", () => {
    const r = screenName("Ivan Petrovich Ivanov", idx);
    assert.ok(r.some((m) => m.uid === "2"));
  });
  test("a lone surname surfaces for review but not as a strong match", () => {
    const r = screenName("Ivanov", idx, { minScore: 60 });
    const m = r.find((x) => x.uid === "2");
    assert.ok(m, "single-token surname still surfaces (recall preserved)");
    assert.ok(m.score <= 78, "but it is damped below the strong band, got " + m.score);
    assert.ok(m.band === "possible" || m.band === "weak");
  });
  test("unrelated name returns clear", () => {
    assert.equal(screenName("Pacific Green Energy", idx).length, 0);
  });
  test("empty query is clear", () => {
    assert.equal(screenName("", idx).length, 0);
  });
  test("band thresholds", () => {
    assert.equal(band(96), "exact");
    assert.equal(band(88), "strong");
    assert.equal(band(72), "possible");
    assert.equal(band(50), "weak");
  });
});

group("sanctions: batch", () => {
  const idx = buildIndex([{ uid: "9", name: "ACME SHIPPING LLC", type: "entity", program: "SDGT", names: ["ACME SHIPPING LLC"] }]);
  test("batch returns one row per input, order preserved", () => {
    const r = screenBatch([{ id: "a", name: "Acme Shipping LLC" }, { id: "b", name: "Clean Vendor Inc" }], idx);
    assert.equal(r.length, 2);
    assert.equal(r[0].id, "a");
    assert.ok(r[0].hit);
    assert.equal(r[1].hit, false);
    assert.equal(r[1].topBand, "clear");
  });
  test("string rows are accepted and numbered", () => {
    const r = screenBatch(["Acme Shipping LLC"], idx);
    assert.equal(r[0].id, 1);
    assert.ok(r[0].hit);
  });
  test("deterministic across runs", () => {
    const a = JSON.stringify(screenBatch(["Acme Shipping LLC", "x"], idx));
    const b = JSON.stringify(screenBatch(["Acme Shipping LLC", "x"], idx));
    assert.equal(a, b);
  });
});

group("sanctions: OFAC parsing", () => {
  const sdn = [
    '36,"AEROCARIBBEAN AIRLINES",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ',
    '306,"BANCO NACIONAL DE CUBA","entity","CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"a.k.a. BNC"',
  ].join("\n");
  const alt = '36,12,"aka","AERO-CARIBBEAN",-0- ';
  test("parses SDN rows and skips blanks", () => {
    const p = parseOfac(sdn + "\n\n", alt);
    assert.equal(p.length, 2);
    assert.equal(p[0].name, "AEROCARIBBEAN AIRLINES");
    assert.equal(p[0].program, "CUBA");
  });
  test("folds ALT aliases into the right entry", () => {
    const p = parseOfac(sdn, alt);
    assert.ok(p[0].names.includes("AERO-CARIBBEAN"));
  });
  test("converts -0- sentinel to empty", () => {
    const p = parseOfac(sdn, alt);
    assert.equal(p[0].type, "");
    assert.equal(p[1].type, "entity");
  });
  test("ignores rows without a numeric uid", () => {
    const p = parseOfac('notanum,"X",-0- ,"Y"\n7,"REAL ENTRY",-0- ,"Z"', "");
    assert.equal(p.length, 1);
    assert.equal(p[0].uid, "7");
  });
});
