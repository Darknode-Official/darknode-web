// Unit tests for public/js/core/query.js
import { test, group, assert } from "../harness.mjs";
import {
  get, compare, predicate, from, Query,
  count, sum, avg, min, max, median, percentile, distinct, facet, groupBy, aggregate,
} from "../../public/js/core/query.js";

const vulns = [
  { id: "a", type: "VULNERABILITY", severity: "critical", data: { cvss: 9.8 }, tags: ["rce"] },
  { id: "b", type: "VULNERABILITY", severity: "high", data: { cvss: 7.5 }, tags: ["dos"] },
  { id: "c", type: "VULNERABILITY", severity: "high", data: { cvss: 8.1 }, tags: ["rce", "auth"] },
  { id: "d", type: "VULNERABILITY", severity: "low", data: { cvss: 3.1 }, tags: [] },
  { id: "e", type: "VULNERABILITY", severity: "medium", data: {}, tags: ["info"] },
];

group("query: field access + compare", () => {
  test("get reads dot paths", () => {
    assert.equal(get(vulns[0], "data.cvss"), 9.8);
    assert.equal(get(vulns[0], "id"), "a");
    assert.equal(get(vulns[0], "data.missing.deep"), undefined);
    assert.equal(get(null, "x"), undefined);
  });

  test("compare orders numbers, strings, and sinks nullish", () => {
    assert.ok(compare(1, 2) < 0);
    assert.ok(compare("b", "a") > 0);
    assert.ok(compare(null, 5) > 0); // null sinks to end
    assert.equal(compare(3, 3), 0);
  });
});

group("query: predicate language", () => {
  test("bare value means eq", () => {
    const p = predicate({ severity: "high" });
    assert.equal(vulns.filter(p).length, 2);
  });

  test("operators gte/lt on dot paths", () => {
    assert.equal(vulns.filter(predicate({ "data.cvss": { gte: 8 } })).length, 2);
    assert.equal(vulns.filter(predicate({ "data.cvss": { lt: 5 } })).length, 1);
  });

  test("in / nin", () => {
    assert.equal(vulns.filter(predicate({ severity: { in: ["low", "medium"] } })).length, 2);
    assert.equal(vulns.filter(predicate({ severity: { nin: ["low", "medium"] } })).length, 3);
  });

  test("contains works on arrays and strings", () => {
    assert.equal(vulns.filter(predicate({ tags: { contains: "rce" } })).length, 2);
    assert.equal(vulns.filter(predicate({ id: { contains: "A" } })).length, 1); // case-insensitive
  });

  test("between + exists", () => {
    assert.equal(vulns.filter(predicate({ "data.cvss": { between: [7, 8.2] } })).length, 2);
    assert.equal(vulns.filter(predicate({ "data.cvss": { exists: true } })).length, 4);
    assert.equal(vulns.filter(predicate({ "data.cvss": { exists: false } })).length, 1);
  });

  test("multiple clauses AND together", () => {
    const p = predicate({ severity: "high", "data.cvss": { gte: 8 } });
    assert.equal(vulns.filter(p).map((v) => v.id).join(""), "c");
  });

  test("unknown operator throws", () => {
    assert.throws(() => predicate({ x: { bogus: 1 } }));
  });

  test("a function predicate passes through", () => {
    const p = predicate((r) => r.id === "d");
    assert.equal(vulns.filter(p).length, 1);
  });
});

group("query: aggregates", () => {
  test("count/sum/avg/min/max over a field", () => {
    assert.equal(count(vulns), 5);
    assert.ok(Math.abs(sum(vulns, "data.cvss") - (9.8 + 7.5 + 8.1 + 3.1)) < 1e-9);
    assert.ok(Math.abs(avg(vulns, "data.cvss") - (28.5 / 4)) < 1e-9); // 4 numeric values
    assert.equal(min(vulns, "data.cvss"), 3.1);
    assert.equal(max(vulns, "data.cvss"), 9.8);
  });

  test("percentile + median", () => {
    const set = [{ v: 1 }, { v: 2 }, { v: 3 }, { v: 4 }];
    assert.equal(median(set, "v"), 2.5);
    assert.equal(percentile(set, "v", 0), 1);
    assert.equal(percentile(set, "v", 100), 4);
    assert.ok(Math.abs(percentile(set, "v", 75) - 3.25) < 1e-9);
  });

  test("percentile handles empty + single", () => {
    assert.equal(percentile([], "v", 50), undefined);
    assert.equal(percentile([{ v: 7 }], "v", 90), 7);
  });

  test("distinct preserves first-seen order", () => {
    assert.deepEqual(distinct(vulns, "severity"), ["critical", "high", "low", "medium"]);
  });

  test("facet counts sorted desc", () => {
    const f = facet(vulns, "severity");
    assert.equal(f[0].value, "high");
    assert.equal(f[0].count, 2);
  });

  test("groupBy buckets records", () => {
    const g = groupBy(vulns, "severity");
    assert.equal(g.get("high").length, 2);
    assert.equal(g.get("critical").length, 1);
  });

  test("aggregate rolls up with named specs", () => {
    const rows = aggregate(vulns, "severity", {
      avgCvss: { fn: "avg", field: "data.cvss" },
      top: { fn: "max", field: "data.cvss" },
    });
    const high = rows.find((r) => r.key === "high");
    assert.equal(high.count, 2);
    assert.ok(Math.abs(high.avgCvss - 7.8) < 1e-9);
    assert.equal(high.top, 8.1);
    // sorted by count desc -> 'high' (2) first
    assert.equal(rows[0].key, "high");
  });

  test("aggregate rejects unknown fn", () => {
    assert.throws(() => aggregate(vulns, "severity", { x: { fn: "nope" } }));
  });
});

group("query: chainable Query", () => {
  test("where + sort + pluck", () => {
    const ids = from(vulns).where({ severity: { in: ["high", "critical"] } }).sort("data.cvss", "desc").pluck("id");
    assert.deepEqual(ids, ["a", "c", "b"]);
  });

  test("whereEq / whereIn", () => {
    assert.equal(from(vulns).whereEq("severity", "high").count(), 2);
    assert.equal(from(vulns).whereIn("id", ["a", "d"]).count(), 2);
  });

  test("search across fields", () => {
    assert.equal(from(vulns).search("auth", ["tags"]).count(), 1);
  });

  test("limit / offset / page", () => {
    assert.equal(from(vulns).limit(2).count(), 2);
    assert.equal(from(vulns).offset(3).count(), 2);
    const p2 = from(vulns).sort("id").page(2, 2).pluck("id");
    assert.deepEqual(p2, ["c", "d"]);
  });

  test("first returns null when empty", () => {
    assert.equal(from(vulns).where({ severity: "nope" }).first(), null);
  });

  test("terminal aggregates on the chain", () => {
    assert.equal(from(vulns).where({ severity: "high" }).avg("data.cvss"), 7.8);
    const f = from(vulns).facet("severity");
    assert.equal(f[0].count, 2);
  });

  test("does not mutate the source array", () => {
    const src = vulns.slice();
    from(vulns).sort("data.cvss").limit(1).all();
    assert.deepEqual(vulns.map((v) => v.id), src.map((v) => v.id));
  });
});
