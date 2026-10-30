// Exposure/risk engine audit regressions (2026-10-30): one test per fix in
// riskreg, vendorrisk and breachclock. The vendorrisk test only fails pre-fix
// when run east of UTC (e.g. TZ=Asia/Kolkata npm test).

import { test, assert, group } from "../harness.mjs";
import { analyze as riskAnalyze } from "../../public/js/risk/riskreg-engine.js";
import { csvToRecords, daysUntil } from "../../public/js/risk/vendorrisk-engine.js";
import { parseCounts, parseTime } from "../../public/js/risk/breachclock-engine.js";

const R = (min, ml, max) => ({ min, ml, max });
const risk = (o) => ({ owner: "test@darknode.ai", status: "assessed", category: "cyber", currency: "USD", lef: R(1, 1, 1), lastReviewed: "2026-09-01", reviewDate: "2026-12-01", ...o });

group("exposure-risk audit", () => {
  test("riskreg: duplicate risk ids are both counted once in the portfolio", () => {
    const r = riskAnalyze({ records: [risk({ id: "R1", title: "Small", plm: R(500, 1000, 1500) }), risk({ id: "R1", title: "Large", plm: R(25000, 50000, 75000) })] }, { iterations: 2000, now: "2026-10-30T00:00:00Z" });
    const p = r.tables.portfolios[0];
    const sum = r.tables.risks.reduce((a, x) => a + x.inherent.mean, 0);
    assert.ok(Math.abs(p.current.mean - sum) < 1, `portfolio ${p.current.mean} vs ${sum}`);
    assert.deepEqual(p.topContributors.map((c) => c.title).sort(), ["Large", "Small"]);
  });

  test("vendorrisk: date-only renewal keeps its calendar day", () => {
    const recs = csvToRecords([{ "Legal name": "Vendor", Renewal: "Oct 30, 2026" }], { legalName: "Legal name", renewal: "Renewal" });
    assert.equal(recs.records[0].renewal, "2026-10-30");
    assert.equal(daysUntil("2026/11/15", "2026-11-15"), 0);
  });

  test("breachclock: tab-separated paste with a formatted count", () => {
    const r = parseCounts("Jurisdiction\tCount\nCalifornia\t1,200\nTexas\t650");
    const rows = r.rows || r;
    const ca = rows.find((x) => x.jurisdiction === "California");
    assert.ok(ca, JSON.stringify(r));
    assert.equal(ca.count, 1200);
  });

  test("breachclock: impossible calendar dates are rejected, leap day accepted", () => {
    assert.equal(parseTime("2026-02-30T10:00"), null);
    assert.equal(parseTime("2026-02-30T10:00Z"), null);
    assert.equal(parseTime("2026-04-31 10:00-04:00"), null);
    assert.equal(parseTime("2028-02-29T10:00Z"), Date.parse("2028-02-29T10:00:00Z"));
  });
});
