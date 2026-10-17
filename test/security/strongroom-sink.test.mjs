// STRONGROOM -> Security Graph mapper tests (public/js/strongroom/strongroom-sink.js):
// only fusion chains publish, one high/critical finding per chain with its legs as
// evidence, stable keys across row reordering, links to vendors and identities, and
// no account numbers in the graph payload.

import { test, assert, group } from "../harness.mjs";
import { analyze } from "../../public/js/strongroom/engine.js";
import { fusionFindings } from "../../public/js/strongroom/strongroom-sink.js";
import { toEntities, findingKey } from "../../public/js/core/sink-map.js";

const HEAD = "date,vendor,amount,invoice,account,approver,initiator";
const PAY_ROWS = [
  "2026-01-05,Vendor A,10000,INV-100,DE89370400440532013000,user01,user02",
  "2026-01-06,Vendor A,30000,INV-101,DE89370400440532013000,user01,user02",
  "2026-01-10,Vendor B,9500,INV-201,GB29NWBK60161331926819,user03,user03",
  "2026-01-20,Vendor C,250000,INV-9,FR1420041010050500013M02606,user04,user05",
];
const ACC_HEAD = "date,actor,type,vendor,detail";
const ACC_ROWS = [
  "2026-01-19,user04,login_new_geo,,new ASN",
  "2026-01-02,,vendor_bank_change,Vendor A,IBAN changed by emailed request",
];
const run = (pay = PAY_ROWS, acc = ACC_ROWS) => analyze([HEAD, ...pay].join("\n"), [ACC_HEAD, ...acc].join("\n"));
const T = "strongroom";

group("strongroom-sink: fusion chains to findings", () => {
  test("only fusion chains publish, one finding per chain", () => {
    const r = run();
    const chains = r.findings.filter((f) => f.rule.startsWith("fusion-"));
    const out = fusionFindings(r);
    assert.ok(chains.length >= 2, "fixture should fire two chains");
    assert.equal(out.length, chains.length);
    assert.ok(r.findings.length > chains.length, "fixture also fires single-plane screens");
    assert.ok(out.every((f) => f.category === "Cyber-financial fusion"));
  });
  test("severity is always high or critical", () => {
    for (const f of fusionFindings(run())) assert.ok(f.severity === "high" || f.severity === "critical", f.severity);
    const bec = fusionFindings(run()).find((f) => f.tags.includes("fusion-bec-payment-redirect"));
    assert.equal(bec.severity, "critical"); // 40,000 moved after the bank change
  });
  test("evidence lists the access event, each payment and the exposure", () => {
    const bec = fusionFindings(run()).find((f) => f.tags.includes("fusion-bec-payment-redirect"));
    assert.equal(bec.evidence[0].leg, "access");
    assert.equal(bec.evidence[0].type, "vendor_bank_change");
    const pays = bec.evidence.filter((e) => e.leg === "payment");
    assert.equal(pays.length, 2);
    assert.deepEqual(pays.map((p) => p.amount).sort((a, b) => a - b), [10000, 30000]);
    assert.equal(bec.evidence[bec.evidence.length - 1].amount, 40000);
  });
  test("stable key survives row reordering and extra unrelated rows", () => {
    const a = fusionFindings(run()).map((f) => findingKey(T, f)).sort();
    const b = fusionFindings(run([...PAY_ROWS].reverse().concat(["2026-03-01,Vendor Z,10,INV-Z,X,user09,user08"]), [...ACC_ROWS].reverse())).map((f) => findingKey(T, f)).sort();
    assert.deepEqual(a, b);
  });
  test("chain finding links to the involved vendors and identities", () => {
    const out = fusionFindings(run());
    const ato = out.find((f) => f.tags.includes("fusion-ato-disbursement"));
    const names = ato.assets.map((x) => x.type + ":" + x.name);
    assert.ok(names.includes("IDENTITY:user04"));
    assert.ok(names.includes("VENDOR:Vendor C"));
    const { links } = toEntities(T, out);
    assert.ok(links.some((l) => l.rel === "affects" && l.to === "IDENTITY:user04"));
    assert.ok(links.some((l) => l.rel === "affects" && l.to === "VENDOR:Vendor A"));
  });
  test("bank account numbers never reach the graph payload", () => {
    const json = JSON.stringify(toEntities(T, fusionFindings(run())));
    for (const acct of ["DE89370400440532013000", "GB29NWBK60161331926819", "FR1420041010050500013M02606"]) assert.ok(!json.includes(acct), acct);
  });
  test("no access feed -> nothing to publish", () => {
    assert.equal(fusionFindings(analyze([HEAD, ...PAY_ROWS].join("\n"), "")).length, 0);
  });
});
