import { test, assert } from "../harness.mjs";
import { chargeQuota, refundQuota, takeQuota, quotaMessage, dailyLimit, isExempt, secondsToReset, utcDay, DAILY_MESSAGES, DAILY_CLAUDE, _resetLocalQuota } from "../../worker/quota.js";
import { RateLimiterDO } from "../../worker/auth.js";

function memStorage() {
  const m = new Map();
  return { m, get: async (k) => m.get(k), put: async (k, v) => { m.set(k, v); }, delete: async (k) => m.delete(k),
    list: async ({ prefix }) => new Map([...m].filter(([k]) => k.startsWith(prefix))) };
}
const user = (uid, claims = {}) => ({ kind: "user", uid, claims });
const NOON = Date.UTC(2026, 10, 1, 12, 0, 0);

test("admins are never limited", async () => {
  assert.equal(isExempt(user("o", { admin: true })), true);
  assert.equal(await chargeQuota({}, user("o", { admin: true }), "1.1.1.1", "messages", "enterprise"), null);
  assert.equal(await chargeQuota({}, user("o", { admin: true }), "", "claude", "enterprise"), null);
});

test("limits by plan, visitors get the smallest and no Claude", () => {
  assert.equal(dailyLimit("messages", "anonymous"), DAILY_MESSAGES.anonymous);
  assert.ok(dailyLimit("messages", "pro") > dailyLimit("messages", "free"));
  assert.equal(dailyLimit("claude", "anonymous"), 0);
  assert.equal(dailyLimit("claude", "nonsense"), DAILY_CLAUDE.free);
});

test("in-memory fallback stops at the limit and is per account", async () => {
  _resetLocalQuota();
  const lim = DAILY_MESSAGES.free;
  for (let i = 0; i < lim; i++) assert.equal((await chargeQuota({}, user("a"), "", "messages", "free", NOON)).ok, true);
  const q = await chargeQuota({}, user("a"), "", "messages", "free", NOON);
  assert.equal(q.ok, false); assert.equal(q.remaining, 0); assert.equal(q.resetIn, 12 * 3600);
  assert.equal((await chargeQuota({}, user("b"), "", "messages", "free", NOON)).ok, true);
  assert.equal((await chargeQuota({}, user("a"), "", "messages", "free", NOON + 12 * 3600 * 1000)).ok, true, "new UTC day resets");
});

test("visitors are counted per IP", async () => {
  _resetLocalQuota();
  for (let i = 0; i < DAILY_MESSAGES.anonymous; i++) await chargeQuota({}, { kind: "anonymous" }, "9.9.9.9", "messages", "free", NOON);
  assert.equal((await chargeQuota({}, { kind: "anonymous" }, "9.9.9.9", "messages", "free", NOON)).ok, false);
  assert.equal((await chargeQuota({}, { kind: "anonymous" }, "8.8.8.8", "messages", "free", NOON)).ok, true);
});

test("storage counter persists, refuses past the limit, drops old days", async () => {
  const st = memStorage();
  st.m.set("q:2026-10-31", 7);
  assert.deepEqual(await takeQuota(st, "2026-11-01", 2), { ok: true, used: 1, limit: 2 });
  assert.equal(st.m.has("q:2026-10-31"), false);
  assert.equal((await takeQuota(st, "2026-11-01", 2)).ok, true);
  assert.deepEqual(await takeQuota(st, "2026-11-01", 2), { ok: false, used: 2, limit: 2 });
});

test("Durable Object quota path and chargeQuota through RATE", async () => {
  const objs = new Map();
  const RATE = { idFromName: (n) => n, get: (id) => { if (!objs.has(id)) objs.set(id, new RateLimiterDO({ storage: memStorage() })); return objs.get(id); } };
  for (let i = 0; i < 3; i++) assert.equal((await chargeQuota({ RATE }, user("c"), "", "claude", "free", NOON)).ok, true);
  const before = await chargeQuota({ RATE }, user("c"), "", "claude", "free", NOON);
  assert.equal(before.used, 4); assert.equal(before.limit, DAILY_CLAUDE.free);
  // the sliding-window path still works on the same class
  const r = await new RateLimiterDO({ storage: memStorage() }).fetch(new Request("https://rate/?limit=1"));
  assert.equal((await r.json()).ok, true);
});

test("messages are plain and name the reset", () => {
  assert.ok(/50 AI messages.*1 hour/.test(quotaMessage("messages", { tier: "free", limit: 50, resetIn: 3600 })));
  assert.ok(/Sign in for more/.test(quotaMessage("messages", { tier: "anonymous", limit: 20, resetIn: 7200 })));
  assert.ok(/150 Claude messages/.test(quotaMessage("claude", { tier: "pro", limit: 150, resetIn: 7200 })));
  assert.equal(utcDay(NOON), "2026-11-01");
  assert.equal(secondsToReset(Date.UTC(2026, 10, 1, 23, 59, 59, 500)), 1);
});

test("a refund gives one message back and never goes below zero", async () => {
  const st = memStorage();
  await takeQuota(st, "2026-11-01", 2); await takeQuota(st, "2026-11-01", 2);
  assert.equal((await takeQuota(st, "2026-11-01", 2)).ok, false);
  assert.deepEqual(await takeQuota(st, "2026-11-01", 2, true), { ok: true, used: 1, limit: 2 });
  assert.equal((await takeQuota(st, "2026-11-01", 2)).ok, true);
  await takeQuota(st, "2026-11-02", 2, true);
  assert.equal(st.m.get("q:2026-11-02") | 0, 0);
  // chargeQuota/refundQuota round trip through the Durable Object
  const objs = new Map();
  const RATE = { idFromName: (n) => n, get: (id) => { if (!objs.has(id)) objs.set(id, new RateLimiterDO({ storage: memStorage() })); return objs.get(id); } };
  const u = user("rr");
  await chargeQuota({ RATE }, u, "", "messages", "free", NOON);
  await refundQuota({ RATE }, u, "", "messages", NOON);
  assert.equal((await chargeQuota({ RATE }, u, "", "messages", "free", NOON)).used, 1);
});
