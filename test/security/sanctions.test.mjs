// Sanctions screening engine tests (public/js/finsec/sanctions-engine.js):
// deterministic watchlist name matching. Mirrors the in-engine selfTest and adds
// scoring, parsing and determinism assertions.

import { test, assert, group } from "../harness.mjs";
import {
  normName, tokens, levenshtein, band, buildIndex, screenName, screenBatch, screenBatchAsync,
  parseOfac, secondaryIds, entityClass, selfTest, toSinkFindings,
} from "../../public/js/finsec/sanctions-engine.js";
import { checkSinkFindings } from "./sink-check.mjs";
import { sampleShare, SAMPLE_SHARE } from "../../public/js/core/sink-map.js";

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
  test("normName folds atomic Latin letters NFKD can't (ø/ß/ł) so native spelling screens against the romanized SDN entry", () => {
    assert.equal(normName("Jørgen Halvorsen"), "jorgen halvorsen");
    assert.equal(normName("Gößmann"), "gossmann");
    assert.equal(normName("Łódź"), "lodz");
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

group("sanctions: list-field filters", () => {
  const idx = buildIndex([
    { uid: "1", name: "JOHN SMITH", type: "individual", program: "NARCO", names: ["JOHN SMITH"] },
    { uid: "2", name: "JOHN SMITH TRADING", type: "", program: "RUSSIA", names: ["JOHN SMITH TRADING"] },
    { uid: "3", name: "JOHN SMITH SHIPPING", type: "vessel", program: "IRAN", names: ["JOHN SMITH SHIPPING"] },
  ]);
  test("entity-type filter keeps only the requested class", () => {
    const r = screenName("John Smith", idx, { types: "individual", minScore: 60 });
    assert.ok(r.every((m) => m.uid === "1"));
    assert.ok(r.some((m) => m.uid === "1"));
  });
  test("blank OFAC type is treated as entity", () => {
    const r = screenName("John Smith", idx, { types: ["entity"], minScore: 60 });
    assert.ok(r.some((m) => m.uid === "2"));
    assert.ok(!r.some((m) => m.uid === "1" || m.uid === "3"));
  });
  test("program substring filter is case-insensitive", () => {
    const r = screenName("John Smith", idx, { program: "russ", minScore: 60 });
    assert.ok(r.length === 1 && r[0].uid === "2");
  });
  test("no filter (all) returns every class", () => {
    const r = screenName("John Smith", idx, { types: "all", minScore: 60 });
    assert.ok(r.length === 3);
  });
  test("entityClass collapses blank/individual/vessel/aircraft", () => {
    assert.equal(entityClass(""), "entity");
    assert.equal(entityClass("Individual"), "individual");
    assert.equal(entityClass("vessel"), "vessel");
    assert.equal(entityClass("aircraft"), "aircraft");
  });
});

group("sanctions: async batch", () => {
  const idx = buildIndex([{ uid: "9", name: "ACME SHIPPING LLC", type: "entity", program: "SDGT", names: ["ACME SHIPPING LLC"] }]);
  test("screenBatchAsync yields the same result as screenBatch", async () => {
    const names = [];
    for (let i = 0; i < 60; i++) names.push(i % 2 ? "Acme Shipping LLC" : "Clean Vendor " + i);
    const sync = screenBatch(names, idx, { chunk: 10 });
    const asyncRes = await screenBatchAsync(names, idx, { chunk: 10 });
    assert.equal(JSON.stringify(asyncRes), JSON.stringify(sync));
  });
  test("onProgress reports completion", async () => {
    let last = 0;
    await screenBatchAsync(["Acme Shipping LLC", "x", "y"], idx, { chunk: 1 }, (done, tot) => { last = done === tot ? tot : last; });
    assert.equal(last, 3);
  });
});

group("sanctions: secondary identifiers", () => {
  test("secondaryIds pulls DOB and nationality from remarks", () => {
    const s = secondaryIds("DOB 05 Dec 1960; POB Tehran, Iran; nationality Iran; Gender Male");
    assert.equal(s.dob, "05 Dec 1960");
    assert.equal(s.nationality, "Iran");
  });
  test("secondaryIds returns empty strings when absent (never fabricated)", () => {
    const s = secondaryIds("");
    assert.equal(s.dob, "");
    assert.equal(s.nationality, "");
  });
  test("parseOfac surfaces DOB/nationality from the SDN Remarks column", () => {
    const sdn = '100,"DOE, John","individual","SDGT",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"DOB 01 Jan 1970; nationality Iran"';
    const p = parseOfac(sdn, "");
    assert.equal(p[0].dob, "01 Jan 1970");
    assert.equal(p[0].nationality, "Iran");
    const hit = screenName("John Doe", buildIndex(p), { minScore: 60 })[0];
    assert.ok(hit && hit.dob === "01 Jan 1970" && hit.nationality === "Iran");
  });
  test("hits carry empty identifiers when the list omits remarks", () => {
    const idx = buildIndex([{ uid: "1", name: "ACME LLC", type: "", program: "X", names: ["ACME LLC"] }]);
    const hit = screenName("Acme LLC", idx)[0];
    assert.equal(hit.dob, "");
    assert.equal(hit.nationality, "");
  });
});

group("sanctions: Security Graph sink mapping", () => {
  const idx = buildIndex([
    { uid: "1", name: "MAERSK LINE", type: "entity", program: "X", names: ["MAERSK LINE"] },
    { uid: "2", name: "IVAN IVANOV", type: "individual", program: "RUSSIA", names: ["IVAN IVANOV", "Ivan Petrovich IVANOV"] },
  ]);
  const names = ["Maersk Line", "Ivan Ivanof", "Clear Counterparty Name"];
  test("one finding per hit, VENDOR counterparty, stable across runs, sample tagging", () => {
    const a = toSinkFindings(screenBatch(names, idx)), b = toSinkFindings(screenBatch(names, idx));
    const { items } = checkSinkFindings("sanctions", a, b, { minFindings: 2 });
    assert.equal(a.length, 2, "the clear name produces no finding");
    assert.ok(items.some((i) => i.type === "VENDOR" && i.name === "Maersk Line"));
    const exact = a.find((f) => f.title === "Sanctions list match: Maersk Line");
    assert.equal(exact.severity, "critical"); assert.equal(exact.status, "open"); assert.equal(exact.evidence[0].uid, "1");
  });
  test("disposition drives status and confirmed is critical; key ignores case and punctuation", () => {
    const rows = screenBatch(names, idx);
    const f = toSinkFindings(rows, { dispositions: { "Maersk Line": "cleared", "Ivan Ivanof": "confirmed" } });
    assert.equal(f.find((x) => x.assets[0].name === "Maersk Line").status, "resolved");
    const iv = f.find((x) => x.assets[0].name === "Ivan Ivanof");
    assert.equal(iv.severity, "critical"); assert.equal(iv.confidence, "confirmed");
    assert.equal(toSinkFindings(screenBatch(["MAERSK LINE."], idx))[0].id, toSinkFindings(rows)[0].id);
  });
  test("example list detection (no header row)", () => {
    const ex = "Darknode Test Shipping LLC\nVladimir Putin\nBank Melli Iran\nDarknode Test Trading Ltd\nNicolas Maduro\nTest User";
    assert.ok(sampleShare(ex, ex, 0) >= SAMPLE_SHARE);
    assert.ok(sampleShare("Vladimir Putin\nSome Real Vendor GmbH\nAnother Payee Ltd", ex, 0) < SAMPLE_SHARE);
  });
});
