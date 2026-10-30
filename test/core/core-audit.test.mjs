// Regression tests for the 2026-10-30 Deck shared-core audit: prototype-key lookups,
// NaN scores, double-counted correlation legs, query/sigma parser edge cases.
import { test, group, assert } from "../harness.mjs";
import { canDo } from "../../public/js/core/workspace-roles.js";
import { can, requiredTier, tierFor, tierFrom } from "../../public/js/core/entitlements.js";
import { mergeList, liveValues, wins } from "../../public/js/core/graph-merge.js";
import { exposureScore } from "../../public/js/core/exposure-score.js";
import { correlate, materializeIncidents } from "../../public/js/core/correlate.js";
import { resolveAssets } from "../../public/js/core/resolve.js";
import { from, predicate, aggregate, min, max } from "../../public/js/core/query.js";
import { compileRule, evaluateRule } from "../../public/js/core/sigma.js";
import { reconcileRun } from "../../public/js/core/workflow.js";
import { statusText, timelineSentences, urgencySort } from "../../public/js/core/queue-format.js";
import { toCsv } from "../../public/js/core/export.js";

const PROTO = ["toString", "constructor", "hasOwnProperty", "valueOf", "__proto__"];

group("core-audit: workspace-roles + entitlements", () => {
  test("canDo with an Object.prototype op name is false, not a throw", () => {
    for (const op of PROTO) assert.equal(canDo("owner", op), false, op);
    assert.equal(canDo("owner", "write"), true);
    assert.equal(canDo("nobody", "read"), false);
    assert.equal(canDo(undefined, "read"), false);
  });

  test("requiredTier / tierFor never return an inherited function", () => {
    for (const k of PROTO) {
      assert.equal(requiredTier(k), null, k);
      assert.equal(tierFor(k, k), "free", k);
      assert.equal(can("free", k), true, k);
    }
    assert.equal(tierFor("findings", "detect"), "pro");
    assert.equal(tierFor("x", "risk"), "enterprise");
  });

  test("an entitlements object without a tier falls through to the tier field", () => {
    assert.equal(tierFrom({ tier: "team", entitlements: { seats: 3 } }), "team");
    assert.equal(tierFrom({ entitlements: { tier: "pro" } }), "pro");
    assert.equal(tierFrom({ entitlements: "team" }), "team");
    assert.equal(tierFrom({ tier: "free", plan: "enterprise" }), "free");
  });
});

group("core-audit: graph-merge", () => {
  test("a __proto__ record id is ignored, never re-parents the map", () => {
    const m = {};
    const changed = mergeList(m, [{ id: "__proto__", updatedAt: "2026-01-01", x: 1 }], "updatedAt");
    assert.deepEqual(changed, []);
    assert.equal(Object.getPrototypeOf(m), Object.prototype);
    assert.equal(m.x, undefined);
    assert.deepEqual(liveValues(m), []);
  });

  test("an inherited-name id is stored as a real record", () => {
    const m = {};
    assert.deepEqual(mergeList(m, [{ id: "toString", updatedAt: "2026-01-01" }], "updatedAt"), ["toString"]);
    assert.equal(liveValues(m).length, 1);
    // and a stale copy of it does not win over the stored one
    assert.deepEqual(mergeList(m, [{ id: "toString", updatedAt: "2025-01-01" }], "updatedAt"), []);
  });

  test("merging the same records twice is idempotent; a delete at the same instant wins", () => {
    const m = {};
    const recs = [{ id: "a", updatedAt: "2026-01-02T00:00:00Z", v: 1 }, { id: "b", updatedAt: "2026-01-02T00:00:00Z" }];
    assert.deepEqual(mergeList(m, recs, "updatedAt"), ["a", "b"]);
    assert.deepEqual(mergeList(m, recs, "updatedAt"), []);
    assert.deepEqual(mergeList(m, [{ id: "a", deleted: true, updatedAt: "2026-01-02T00:00:00.000Z" }], "updatedAt"), ["a"]);
    assert.equal(wins({ id: "a", updatedAt: "2026-01-02T00:00:00Z", v: 2 }, m.a, "updatedAt"), false);
    assert.deepEqual(liveValues(m).map((r) => r.id), ["b"]);
  });
});

group("core-audit: exposure-score + correlate + resolve", () => {
  test("an Object.prototype severity does not turn the score into NaN", () => {
    const r = exposureScore([
      { id: "a", type: "FINDING", severity: "high", status: "open" },
      { id: "b", type: "FINDING", severity: "constructor", status: "open" },
      { id: "c", type: "FINDING", severity: "toString", status: "open" },
    ], { now: 0 });
    assert.ok(Number.isFinite(r.score) && Number.isFinite(r.raw));
    assert.equal(r.contributing, 1);
    assert.equal(r.score, Math.round(100 * (1 - Math.exp(-6 / 50))));
  });

  test("empty input scores 0 within bounds", () => {
    const r = exposureScore([], { now: 0 });
    assert.equal(r.score, 0); assert.equal(r.raw, 0); assert.equal(r.contributing, 0);
    const many = Array.from({ length: 500 }, (_, i) => ({ id: "f" + i, type: "FINDING", severity: "critical", status: "open" }));
    assert.equal(exposureScore(many, { now: 0 }).score, 100);
  });

  const host = { id: "h", type: "ASSET", name: "web01.example.com" };
  const rdpKev = { id: "f1", type: "FINDING", name: "RDP open, known exploited", source: "netexposure", status: "open", tags: ["kev"], updatedAt: "2026-01-01T00:00:00Z", data: { category: "rdp", assets: ["web01.example.com"] } };

  test("one finding cannot satisfy two legs of a rule on its own", () => {
    assert.deepEqual(correlate([host, rdpKev]), []);
  });

  test("a second finding completes the chain, and the legs use different findings", () => {
    const vuln = { id: "f2", type: "FINDING", name: "CVE in web stack", source: "vulnimport", severity: "high", status: "open", updatedAt: "2026-01-02T00:00:00Z", data: { assets: ["web01.example.com"] } };
    const hits = correlate([host, rdpKev, vuln]).filter((h) => h.ruleId === "exploit-exposed-host");
    assert.equal(hits.length, 1);
    const ids = hits[0].legs.map((l) => l.findingId);
    assert.equal(new Set(ids).size, 2);
  });

  test("backtracks: a greedy first pick does not hide a valid pairing", () => {
    // f1 is newest and satisfies both legs; f0 only the vuln leg. Greedy gave vuln=f1 then no exposed.
    const older = { id: "f0", type: "FINDING", name: "known exploited service", source: "vulnimport", severity: "high", status: "open", updatedAt: "2025-12-31T00:00:00Z", data: { assets: ["web01.example.com"] } };
    const hits = correlate([host, rdpKev, older]).filter((h) => h.ruleId === "exploit-exposed-host");
    assert.equal(hits.length, 1);
    assert.deepEqual(hits[0].legs.map((l) => l.findingId), ["f0", "f1"]);
  });

  test("null entities are skipped, not a crash", () => {
    assert.deepEqual(correlate([null, host, undefined, rdpKev]), []);
    assert.deepEqual(materializeIncidents([], [null, rdpKev]), { entities: [], relationships: [] });
  });

  test("resolveAssets bySource accepts Object.prototype source names", () => {
    const c = resolveAssets([
      { id: "a", type: "ASSET", name: "x.example.com", source: "constructor" },
      { id: "b", type: "ASSET", name: "X.example.com", source: "__proto__" },
      { id: "c", type: "ASSET", name: "x.example.com", source: "toString" },
    ]);
    assert.equal(c.length, 1);
    assert.deepEqual(c[0].sources, ["__proto__", "constructor", "toString"]);
    assert.deepEqual(c[0].bySource.constructor, ["a"]);
  });
});

group("core-audit: query", () => {
  test("an Object.prototype operator or aggregate name throws like any unknown one", () => {
    assert.throws(() => predicate({ a: { constructor: 1 } }));
    assert.throws(() => predicate({ a: { toString: 1 } }));
    assert.throws(() => aggregate([{ a: 1 }], "a", { x: { fn: "constructor" } }));
    assert.equal(from([{ a: 1 }, { a: 2 }]).where({ a: { gte: 2 } }).count(), 1);
  });

  test("min / max over a large array do not overflow the stack", () => {
    const big = Array.from({ length: 300000 }, (_, i) => ({ v: i }));
    assert.equal(max(big, "v"), 299999);
    assert.equal(min(big, "v"), 0);
    assert.equal(max([], "v"), undefined);
  });

  test("desc sort keeps nullish last and ties in input order", () => {
    const rows = [{ id: 1, a: null }, { id: 2, a: 1 }, { id: 3, a: 2 }, { id: 4, a: 1 }, { id: 5 }];
    assert.deepEqual(from(rows).sort("a", "desc").pluck("id"), [3, 2, 4, 1, 5]);
    assert.deepEqual(from(rows).sort("a").pluck("id"), [2, 4, 3, 1, 5]);
    assert.deepEqual(from(rows).sort((x, y) => (x.a || 0) - (y.a || 0), "desc").pluck("id"), [3, 2, 4, 1, 5]);
  });

  test("regex operator: invalid pattern matches nothing, valid one is case-insensitive", () => {
    const rows = [{ n: "Web01" }, { n: "db" }];
    assert.equal(from(rows).where({ n: { regex: "^web" } }).count(), 1);
    assert.equal(from(rows).where({ n: { regex: "(" } }).count(), 0);
  });
});

group("core-audit: sigma conditions", () => {
  const rule = (cond) => "title: t\ndetection:\n  selection:\n    user: admin\n  filter:\n    host: dc01\n  condition: " + cond + "\n";
  const evs = [{ user: "admin", host: "dc01" }, { user: "admin", host: "web" }];

  test("\"N of them\" is case-insensitive at evaluation, as it already was at compile", () => {
    assert.equal(evaluateRule(rule("1 of Them"), evs).count, 2);
    assert.equal(evaluateRule(rule("ALL OF THEM"), evs).count, 1);
  });

  test("an incomplete condition is refused instead of running as something else", () => {
    for (const c of ["selection filter", "selection and", "selection and not", "selection and ()", "not", "( selection", "selection )", "selection or or filter"]) {
      assert.equal(compileRule(rule(c)).ok, false, c);
    }
  });

  test("well-formed conditions still compile and evaluate", () => {
    assert.equal(evaluateRule(rule("selection and not filter"), evs).count, 1);
    assert.equal(evaluateRule(rule("not (selection and filter)"), evs).count, 1);
    assert.equal(evaluateRule(rule("not not selection"), evs).count, 2);
    assert.equal(evaluateRule(rule("1 of sel* or filter"), evs).count, 2);
  });
});

group("core-audit: workflow + queue-format", () => {
  const F = (o) => ({ type: "FINDING", status: "open", ...o, data: { tool: "tool", dataset: "ds", ...(o.data || {}) } });

  test("a held key is not reopened even when the run still lists it", () => {
    const prev = [F({ id: "b", status: "resolved", data: { findingKey: "k", resolution: "fixed" } })];
    assert.equal(reconcileRun("tool", "ds", prev, ["k"], { now: 1, held: ["k"] }).regressed.length, 0);
    assert.equal(reconcileRun("tool", "ds", prev, ["k"], { now: 1 }).regressed.length, 1);
  });

  test("statusText / timelineSentences with an Object.prototype resolution do not throw", () => {
    assert.equal(statusText("resolved", "constructor"), "Resolved");
    assert.equal(statusText("resolved", "fixed"), "Resolved (fixed)");
    const s = timelineSentences([{ kind: "change", field: "resolution", to: "toString", uid: "u", ts: 1 }]);
    assert.equal(s[0].text, "u set the resolution to toString");
  });

  test("urgencySort ranks an Object.prototype severity below every real one", () => {
    const rows = [{ n: 1, severity: "low" }, { n: 2, severity: "constructor" }, { n: 3, severity: "high" }];
    assert.deepEqual(urgencySort(rows, () => ({ state: "none", dueAt: null })).map((r) => r.n), [3, 1, 2]);
  });
});

group("core-audit: CSV export", () => {
  test("formula cells are neutralised and quoting survives newlines and quotes", () => {
    const csv = toCsv([{ a: "=1+1", b: "+cmd", c: "-2", d: "@SUM(A1)", e: 'say "hi",\nbye', f: "\tx", g: "test@darknode.ai" }], ["a", "b", "c", "d", "e", "f", "g"]);
    const row = csv.split("\r\n").slice(1).join("\r\n");
    assert.ok(row.startsWith("'=1+1,'+cmd,'-2,'@SUM(A1),"), row);
    assert.ok(row.includes('"say ""hi"",\nbye"'), row);
    assert.ok(row.includes("'\tx"), row);
    assert.ok(row.includes(",test@darknode.ai\r\n"), row);
  });
});
