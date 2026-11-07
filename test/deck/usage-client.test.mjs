// The desktop app's usage heartbeat (public/js/usage-ping.js) and the admin panel's
// "Nexus, desktop app & VMs" list (public/js/admin-usage.js).
import { test, group, assert } from "../harness.mjs";
import { pingAppUsage, usageOff, setUsageOff, OFF_KEY } from "../../public/js/usage-ping.js";
import { usageRows, usageSummary, render, ago } from "../../public/js/admin-usage.js";

const mem = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; };
const appWin = (native = {}) => ({ darknode: { desktop: { shell: "web", version: "2.55.4", platform: "linux" }, native } });
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

group("usage ping (desktop app)", () => {
  test("a browser never sends anything", async () => {
    let calls = 0;
    assert.equal(await pingAppUsage({ win: {}, store: mem(), api: async () => { calls++; } }), "not-app");
    assert.equal(calls, 0);
  });
  test("the app sends version, OS and VM counts, then waits 6 hours", async () => {
    const store = mem(), sent = [];
    const api = async (path, o) => { sent.push([path, o]); return { ok: true }; };
    const win = appWin({ vmUsage: async () => ({ count: 2, running: 1, lastStart: 1790000000000, disk: "/secret" }) });
    assert.equal(await pingAppUsage({ win, store, api, now: 1e13 }), "sent");
    assert.equal(sent[0][0], "/api/v1/usage");
    assert.deepEqual(sent[0][1].body, { product: "app", version: "2.55.4", os: "linux", vm: { count: 2, running: 1, lastStart: 1790000000000 } });
    assert.equal(await pingAppUsage({ win, store, api, now: 1e13 + 3600e3 }), "skipped");
    assert.equal(await pingAppUsage({ win, store, api, now: 1e13 + 7 * 3600e3 }), "sent");
  });
  test("an app without the VM bridge still reports itself", async () => {
    const sent = [];
    await pingAppUsage({ win: appWin(), store: mem(), api: async (p, o) => sent.push(o.body), now: 1e13 });
    assert.equal(sent[0].vm, undefined);
  });
  test("turning it off stops it; a failed send is retried next time", async () => {
    const store = mem();
    setUsageOff(true, store);
    assert.equal(store.getItem(OFF_KEY), "1");
    assert.ok(usageOff(store));
    assert.equal(await pingAppUsage({ win: appWin(), store, api: async () => {}, now: 1e13 }), "off");
    setUsageOff(false, store);
    assert.equal(await pingAppUsage({ win: appWin(), store, api: async () => { throw new Error("down"); }, now: 1e13 }), "failed");
    assert.equal(await pingAppUsage({ win: appWin(), store, api: async () => ({}), now: 1e13 + 1 }), "sent");
  });
});

group("admin usage list", () => {
  const NOW = Date.parse("2026-11-07T12:00:00Z");
  const docs = [
    { uid: "a", email: "test@darknode.ai", nexus: { last: NOW - 3600e3, first: NOW - 40 * 864e5, version: "2.56.0", os: "linux" }, app: { last: NOW - 20 * 864e5, version: "2.55.4", os: "darwin" } },
    { uid: "b", email: "", nexus: { last: NOW - 60e3, version: "2.56.0", os: "win32" }, vm: { last: NOW, count: 3, running: 1 } },
    { uid: "c", email: "x@y.z" },
  ];
  test("rows per product, most recent first; people without that product are left out", () => {
    assert.deepEqual(usageRows(docs, "nexus").map((r) => r.uid), ["b", "a"]);
    assert.deepEqual(usageRows(docs, "app").map((r) => r.uid), ["a"]);
    assert.equal(usageRows(docs, "vm")[0].count, 3);
  });
  test("summary counts everyone and the last 7 days", () => {
    const s = usageSummary(docs, NOW);
    assert.deepEqual(s.nexus, { total: 2, week: 2 });
    assert.deepEqual(s.app, { total: 1, week: 0 });
    assert.deepEqual(s.vm, { total: 1, week: 1 });
  });
  test("Firestore timestamps are read too", () => {
    const r = usageRows([{ uid: "t", nexus: { last: { toMillis: () => NOW } } }], "nexus");
    assert.equal(r[0].last, NOW);
  });
  test("render escapes emails and filters by search", () => {
    const host = { innerHTML: "" };
    render(host, [{ uid: "z", email: "<img src=x>", nexus: { last: NOW } }], { tab: "nexus", q: "" }, esc, NOW);
    assert.ok(host.innerHTML.includes("&lt;img") && !host.innerHTML.includes("<img"));
    render(host, docs, { tab: "nexus", q: "test@" }, esc, NOW);
    assert.ok(host.innerHTML.includes("test@darknode.ai") && host.innerHTML.includes("v2.56.0 · Linux"));
    assert.ok(!host.innerHTML.includes("Windows"));
    render(host, docs, { tab: "vm", q: "" }, esc, NOW);
    assert.ok(host.innerHTML.includes("3 VMs · 1 running"));
  });
  test("ago reads like a person wrote it", () => {
    assert.equal(ago(0, NOW), "never");
    assert.equal(ago(NOW - 30e3, NOW), "just now");
    assert.equal(ago(NOW - 5 * 60e3, NOW), "5 min ago");
    assert.equal(ago(NOW - 3 * 3600e3, NOW), "3 h ago");
  });
});
