// STRONGROOM engine tests (public/js/strongroom/engine.js): deterministic financial
// screens + cyber-financial fusion correlation. Mirrors the in-engine selfTest and adds
// parsing + determinism assertions.

import { test, assert, group } from "../harness.mjs";
import { analyze, parseAmount, parseDay, parseCSV, selfTest } from "../../public/js/strongroom/engine.js";

const rules = (r) => r.findings.map((f) => f.rule);

group("strongroom: engine self-test", () => {
  test("all in-engine self-test checks pass", () => {
    const { pass, results } = selfTest();
    assert.ok(pass, "self-test failures: " + results.filter((r) => !r.pass).map((r) => r.name).join(", "));
  });
});

group("strongroom: parsing", () => {
  test("parseAmount strips symbols and handles ()-negatives", () => {
    assert.equal(parseAmount("$1,234.50"), 1234.5);
    assert.equal(parseAmount("($1,234.50)"), -1234.5);
    assert.ok(Number.isNaN(parseAmount("")));
  });
  test("parseDay accepts ISO and US and agrees", () => {
    assert.equal(parseDay("2026-01-05"), parseDay("1/5/2026"));
    assert.equal(parseDay("not a date"), null);
  });
  test("parseCSV handles quoted commas", () => {
    const rows = parseCSV('a,b\n"x,y",z');
    assert.equal(rows[1][0], "x,y");
    assert.equal(rows[1][1], "z");
  });
});

const PAY = [
  "date,vendor,amount,invoice,approver,initiator",
  "2026-01-05,Acme,10000,INV-100,alice,bob",
  "2026-01-06,Acme,10000,INV-100,alice,bob",
  "2026-01-10,Globex,9500,INV-201,carol,carol",
  "2026-01-11,Globex,9400,INV-202,carol,carol",
  "2026-01-12,Globex,9300,INV-203,carol,carol",
  "2026-01-20,Initech,250000,INV-9,dave,erin",
].join("\n");
const ACCESS = [
  "date,actor,type,vendor,detail",
  "2026-01-19,dave,login_new_geo,,new ASN",
  "2026-01-02,,vendor_bank_change,Acme,IBAN changed",
].join("\n");

group("strongroom: money totals are cent-exact", () => {
  test("summing many 0.01 amounts does not drift", () => {
    const rows = ["date,vendor,amount,invoice,approver,initiator"];
    for (let i = 0; i < 1000; i++) rows.push(`2026-01-0${(i % 9) + 1},V${i},0.01,INV-${i},a,b`);
    const r = analyze(rows.join("\n"), "");
    assert.equal(r.summary.totalValue, 10); // 1000 * 0.01 exactly, no float tail
  });
});

group("strongroom: financial detections", () => {
  test("exact duplicate payment fires", () => assert.ok(rules(analyze(PAY, "")).includes("duplicate-payment")));
  test("segregation-of-duties fires on self-approval", () => assert.ok(rules(analyze(PAY, "")).includes("segregation-of-duties")));
  test("clean segregated data stays quiet on SoD", () => {
    const clean = "date,vendor,amount,invoice,approver,initiator\n2026-02-01,Clean,8000,INV-1,alice,bob";
    assert.ok(!rules(analyze(clean, "")).includes("segregation-of-duties"));
  });
});

group("strongroom: fusion detections", () => {
  test("BEC payment-redirect chain fires", () => assert.ok(rules(analyze(PAY, ACCESS)).includes("fusion-bec-payment-redirect")));
  test("account-takeover disbursement chain fires", () => assert.ok(rules(analyze(PAY, ACCESS)).includes("fusion-ato-disbursement")));
  test("no fusion rules without access feed", () => {
    assert.ok(!rules(analyze(PAY, "")).some((r) => r.startsWith("fusion-")));
  });
});

group("strongroom: determinism & safety", () => {
  test("identical input yields byte-identical findings", () => {
    assert.equal(JSON.stringify(analyze(PAY, ACCESS).findings), JSON.stringify(analyze(PAY, ACCESS).findings));
  });
  test("empty input is safe", () => assert.equal(analyze("", "").findings.length, 0));
});
