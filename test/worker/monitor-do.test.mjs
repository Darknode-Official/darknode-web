// Unit tests for worker/monitor.js — the MonitorDO state machine, driven with an
// in-memory storage shim, a fake fetch (CT logs + webhook delivery) and no real sleeps.
import { test, group, assert } from "../harness.mjs";
import { MonitorDO } from "../../worker/monitor.js";

// minimal Durable Object storage shim
function memState() {
  const map = new Map(); let alarm = null;
  const storage = {
    async get(k) { return map.has(k) ? map.get(k) : undefined; },
    async put(k, v) { map.set(k, v); },
    async delete(k) { map.delete(k); },
    async setAlarm(ts) { alarm = ts; },
    async getAlarm() { return alarm; },
    _alarm: () => alarm,
  };
  return { storage, blockConcurrencyWhile: async (fn) => fn(), _map: map };
}

const day = (n) => new Date(Date.now() + n * 86400000).toISOString();
const ctCert = (notAfter) => ({ issuer_name: "Lets Encrypt", not_after: notAfter, not_before: day(-80), name_value: "x" });

// fake fetch: crt.sh serves the configured cert; any other URL is a webhook delivery.
function fakeNet(certNotAfter) {
  const deliveries = [];
  const fetch = async (url, opts) => {
    if (url.includes("crt.sh")) return { ok: true, status: 200, json: async () => [ctCert(certNotAfter)] };
    if (url.includes("certspotter")) return { ok: false, status: 404, json: async () => null };
    deliveries.push({ url, body: opts && opts.body }); return { ok: true, status: 200 };
  };
  return { fetch, deliveries };
}

async function post(doInst, body, role = "owner") {
  const res = await doInst.fetch(new Request("https://monitor/", { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json", "x-mon-uid": "u1", "x-mon-role": role } }));
  return { status: res.status, json: await res.json() };
}

group("monitor DO/lifecycle", () => {
  test("upsert creates a monitor, redacts channel secrets, and sets an alarm", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    const r = await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"] }, channels: [{ type: "webhook", url: "https://hook.test/x", secret: "shh" }] } });
    assert.equal(r.status, 200);
    assert.ok(r.json.monitor.id);
    assert.equal(r.json.monitor.channels[0].hasSecret, true);
    assert.equal(r.json.monitor.channels[0].secret, undefined, "secret never leaves the DO");
    assert.ok(st.storage._alarm() != null, "an alarm was scheduled");
  });

  test("a viewer cannot change monitors", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    const r = await post(mon, { op: "upsert", monitor: { type: "cert-expiry" } }, "viewer");
    assert.equal(r.status, 403);
  });

  test("list requires only read and returns history + deliveries", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    const r = await post(mon, { op: "list" }, "viewer");
    assert.equal(r.status, 200);
    assert.ok(Array.isArray(r.json.monitors) && Array.isArray(r.json.history));
  });
});

group("monitor DO/run + alert", () => {
  test("a run on an expiring cert delivers one alert and logs history", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"], warnDays: 21 }, channels: [{ type: "webhook", url: "https://hook.test/x" }] } });
    const net = fakeNet(day(10));
    const r = await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {}, deckUrl: "https://darknode.ai/deck" });
    assert.equal(r.ran.length, 1);
    assert.equal(r.ran[0].found, 1);
    assert.equal(r.ran[0].alerted, 1);
    assert.equal(net.deliveries.length, 1, "one webhook delivery");
    const body = JSON.parse(net.deliveries[0].body);
    assert.ok(JSON.stringify(body).includes("a.test.darknode.ai"));
    const hist = await st.storage.get("history");
    assert.equal(hist[0].alerted, 1);
  });

  test("a second identical run raises no new alert (only changes alert)", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"], warnDays: 21 }, channels: [{ type: "webhook", url: "https://hook.test/x" }] } });
    const net = fakeNet(day(10));
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    assert.equal(net.deliveries.length, 1, "no duplicate alert on an unchanged cert");
  });

  test("a healthy cert run finds nothing and alerts nothing", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"], warnDays: 21 }, channels: [{ type: "webhook", url: "https://hook.test/x" }] } });
    const net = fakeNet(day(300));
    const r = await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    assert.equal(r.ran[0].found, 0);
    assert.equal(net.deliveries.length, 0);
  });

  test("a paused monitor does not run", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    const up = await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"] }, channels: [] } });
    await post(mon, { op: "pause", id: up.json.monitor.id, paused: true });
    const net = fakeNet(day(5));
    const r = await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    assert.equal(r.ran.length, 0);
  });

  test("test-send delivers to a channel without creating a monitor", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    const net = fakeNet(day(5));
    // route test through the DO so delivery uses the DO's (global) fetch path; inject via _deliverWithRetry isn't exposed, so check via op with a real fake fetch:
    mon._deliverWithRetry = async (ch) => { net.deliveries.push({ url: ch.url }); return true; };
    const r = await post(mon, { op: "test", channel: { type: "slack", url: "https://hooks.slack.test/x" } });
    assert.equal(r.json.ok, true);
    assert.equal(net.deliveries.length, 1);
  });
});
