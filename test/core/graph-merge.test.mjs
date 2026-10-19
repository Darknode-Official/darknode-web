import { test, group, assert } from "../harness.mjs";
import { orderKey, wins, mergeList, liveValues, tombstone } from "../../public/js/core/graph-merge.js";

const K = "updatedAt";
const E = (id, t, extra) => ({ id, updatedAt: t, ...(extra || {}) });

group("core/graph-merge", () => {
  test("orderKey reads the key, missing sorts first", () => {
    assert.equal(orderKey(E("a", "2026-01-02"), K), "2026-01-02");
    assert.equal(orderKey({ id: "a" }, K), "");
    assert.equal(orderKey(null, K), "");
  });

  test("wins: later timestamp beats earlier, and absence of existing", () => {
    assert.equal(wins(E("a", "2026-02-01"), E("a", "2026-01-01"), K), true);
    assert.equal(wins(E("a", "2026-01-01"), E("a", "2026-02-01"), K), false);
    assert.equal(wins(E("a", "2026-01-01"), null, K), true);
    assert.equal(wins(null, E("a", "2026-01-01"), K), false);
  });

  test("wins: exact tie keeps existing (stable, no churn)", () => {
    assert.equal(wins(E("a", "2026-01-01"), E("a", "2026-01-01"), K), false);
  });

  test("wins: equal instants with different serializations are a tie, not string-ordered", () => {
    // "…Z" > "…000Z" and "+05:00" > "Z" lexically, but these are the SAME instant → keep existing.
    assert.equal(wins(E("a", "2026-01-01T00:00:00Z"), E("a", "2026-01-01T00:00:00.000Z"), K), false);
    assert.equal(wins(E("a", "2026-01-01T05:00:00+05:00"), E("a", "2026-01-01T00:00:00Z"), K), false);
    // a genuinely later instant still wins despite a lexically-smaller offset form
    assert.equal(wins(E("a", "2026-01-01T06:00:00+05:00"), E("a", "2026-01-01T00:00:00Z"), K), true);
  });

  test("wins: a tombstone beats a live record of the same timestamp", () => {
    const tomb = { id: "a", deleted: true, updatedAt: "2026-01-01" };
    assert.equal(wins(tomb, E("a", "2026-01-01"), K), true);
    // ...but a live record does NOT beat a tombstone of the same timestamp
    assert.equal(wins(E("a", "2026-01-01"), tomb, K), false);
    // a later live record DOES beat an earlier tombstone (resurrection by a real edit)
    assert.equal(wins(E("a", "2026-02-01"), tomb, K), true);
  });

  test("mergeList applies winners in place and returns the changed ids", () => {
    const map = { a: E("a", "2026-01-01"), b: E("b", "2026-01-01") };
    const changed = mergeList(map, [E("a", "2026-02-01"), E("b", "2025-12-01"), E("c", "2026-01-01")], K);
    assert.deepEqual(changed.sort(), ["a", "c"]);
    assert.equal(map.a.updatedAt, "2026-02-01"); // newer won
    assert.equal(map.b.updatedAt, "2026-01-01"); // older ignored
    assert.ok(map.c);                            // new id added
  });

  test("mergeList skips malformed records", () => {
    const map = {};
    const changed = mergeList(map, [null, {}, { id: "" }, { id: 5, updatedAt: "x" }, E("ok", "2026-01-01")], K);
    assert.deepEqual(changed, ["ok"]);
  });

  test("mergeList converges regardless of apply order", () => {
    const edits = [E("a", "2026-01-01"), E("a", "2026-03-01"), E("a", "2026-02-01")];
    const m1 = {}; mergeList(m1, edits, K);
    const m2 = {}; mergeList(m2, [...edits].reverse(), K);
    assert.equal(m1.a.updatedAt, "2026-03-01");
    assert.equal(m2.a.updatedAt, "2026-03-01");
  });

  test("liveValues drops tombstones", () => {
    const map = { a: E("a", "2026-01-01"), b: { id: "b", deleted: true, updatedAt: "2026-01-02" } };
    const live = liveValues(map);
    assert.equal(live.length, 1);
    assert.equal(live[0].id, "a");
  });

  test("tombstone carries id and ordering key only", () => {
    const t = tombstone("x", "2026-05-05", K);
    assert.equal(t.id, "x");
    assert.equal(t.deleted, true);
    assert.equal(t.updatedAt, "2026-05-05");
  });

  test("a delete then a remote edit: whichever is later wins, both directions", () => {
    // local deleted at T2, remote edited at T1 (<T2): delete wins
    assert.equal(wins(E("a", "2026-01-01"), tombstone("a", "2026-02-01", K), K), false);
    // local deleted at T1, remote edited at T2 (>T1): edit wins (resurrected)
    assert.equal(wins(E("a", "2026-02-01"), tombstone("a", "2026-01-01", K), K), true);
  });
});
