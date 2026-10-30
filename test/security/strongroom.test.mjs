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
  test("parseDay rejects a day the month does not have instead of rolling over", () => {
    assert.equal(parseDay("2026-02-31"), null);
    assert.equal(parseDay("4/31/2026"), null);
    assert.equal(parseDay("2028-02-29"), parseDay("2/29/2028"));
    assert.ok(parseDay("2028-02-29") != null);
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

// Typo-squatted / shell vendors and a bank account shared across payees.
const AP_FRAUD = [
  "date,vendor,amount,invoice,account,approver,initiator",
  "2026-03-01,Northwind Traders,5000,INV-1,DE89 3704 0044 0532,alice,bob",
  "2026-03-02,Northwind Tradrs,5200,INV-2,FR14 2004 1010 0505,carol,dave",   // 1-char typo-squat
  "2026-03-03,Globex Incorporated,7000,INV-3,GB29 NWBK 6016 1331,erin,frank",
  "2026-03-04,Initech LLC,8000,INV-4,GB29 NWBK 6016 1331,grace,heidi",        // same account, different vendor
].join("\n");

group("strongroom: AP-fraud structural detections", () => {
  test("near-duplicate vendor names cluster", () => {
    const r = analyze(AP_FRAUD, "");
    const f = r.findings.find((x) => x.rule === "duplicate-vendor-cluster");
    assert.ok(f, "expected a duplicate-vendor-cluster finding");
    assert.ok(/northwind/i.test(f.evidence.join(" ")), "cluster should name the typo-squatted pair");
  });
  test("shared bank account across vendors fires", () => {
    const r = analyze(AP_FRAUD, "");
    const f = r.findings.find((x) => x.rule === "shared-bank-account");
    assert.ok(f, "expected a shared-bank-account finding");
    assert.ok(f.rows.length >= 2);
  });
  test("distinct vendors + distinct/short accounts stay quiet", () => {
    const clean = "date,vendor,amount,invoice,account\n2026-03-01,Apple,5,INV-1,A1\n2026-03-02,Microsoft,6,INV-2,B2";
    const got = analyze(clean, "").findings.map((f) => f.rule);
    assert.ok(!got.includes("duplicate-vendor-cluster"));
    assert.ok(!got.includes("shared-bank-account"));
  });
  test("same vendor repeated does not self-cluster", () => {
    const same = "date,vendor,amount,invoice,account\n2026-03-01,Acme Supply Co,100,INV-1,ACCT-1\n2026-03-02,Acme Supply Co,200,INV-2,ACCT-2";
    assert.ok(!analyze(same, "").findings.some((f) => f.rule === "duplicate-vendor-cluster"));
  });
});

group("strongroom: Benford second-digit test", () => {
  const rows = ["date,vendor,amount,invoice"];
  for (let i = 0; i < 300; i++) rows.push(`2026-01-01,V,${((i * 37 + 100) % 9000) + 100}.${(i % 90) + 10},INV-${i}`);
  const r = analyze(rows.join("\n"), "");
  test("first-digit screen present on a large sample", () => {
    assert.ok(r.findings.some((f) => f.rule === "benford-first-digit"));
  });
  test("second-digit screen present on a large sample", () => {
    assert.ok(r.findings.some((f) => f.rule === "benford-second-digit"));
  });
  test("no Benford screen below the 200-amount floor", () => {
    const small = ["date,vendor,amount,invoice"];
    for (let i = 0; i < 50; i++) small.push(`2026-01-01,V,${i + 100}.50,INV-${i}`);
    assert.ok(!analyze(small.join("\n"), "").findings.some((f) => f.rule.startsWith("benford-")));
  });
});

group("strongroom: per-finding money is integer-cents exact", () => {
  test("a summed finding's money carries no float tail", () => {
    // three weekend payments; their float sum (910.1+920.2+930.3) has a tail — money must not.
    const pay = [
      "date,vendor,amount,invoice",
      "2026-01-03,Acme,910.10,INV-1", // 2026-01-03 is a Saturday
      "2026-01-03,Acme,920.20,INV-2",
      "2026-01-03,Acme,930.30,INV-3",
    ].join("\n");
    const f = analyze(pay, "").findings.find((x) => x.rule === "weekend-payment");
    assert.ok(f, "expected a weekend-payment finding");
    assert.equal(f.money, 2760.6);
    assert.equal(Math.round(f.money * 100), 276060); // cent-exact, no drift
  });
  test("weekend = Saturday+Sunday only: a Sunday payment is flagged, a Friday payment is not", () => {
    const run = (date) => analyze(["date,vendor,amount,invoice", `${date},Northwind,500.00,INV-9`].join("\n"), "")
      .findings.find((x) => x.rule === "weekend-payment");
    assert.ok(run("2026-01-04"), "2026-01-04 (Sunday) must be flagged");   // was missed by the old dow===5||6
    assert.ok(!run("2026-01-02"), "2026-01-02 (Friday) must NOT be flagged"); // was wrongly flagged by the old logic
  });
});
