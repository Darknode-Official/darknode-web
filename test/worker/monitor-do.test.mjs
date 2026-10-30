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
    // Pin the run clock and the cert's expiry to one base so the day-count cannot drift across
    // the two runs (otherwise a run straddling a day boundary flips the title → a false change).
    const base = Date.now();
    const net = fakeNet(new Date(base + 10 * 86400000).toISOString());
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {}, now: base });
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {}, now: base });
    assert.equal(net.deliveries.length, 1, "no duplicate alert on an unchanged cert");
  });

  test("a day later the same expiring cert does not alert again; crossing into the last week does", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"], warnDays: 21 }, channels: [{ type: "webhook", url: "https://hook.test/x" }] } });
    const base = Date.now(), D = 86400000;
    const net = fakeNet(new Date(base + 10 * D).toISOString());
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {}, now: base });
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {}, now: base + D });
    assert.equal(net.deliveries.length, 1, "expires in 10 days -> 9 days is only a title change");
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {}, now: base + 4 * D });
    assert.equal(net.deliveries.length, 2, "high -> critical at 6 days alerts");
  });

  test("a run where the certificate logs do not answer keeps the finding open, and it does not re-alert when they are back", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"], warnDays: 21 }, channels: [{ type: "webhook", url: "https://hook.test/x" }] } });
    const base = Date.now();
    const net = fakeNet(new Date(base + 10 * 86400000).toISOString());
    const down = async (url, opts) => (url.includes("crt.sh") || url.includes("certspotter") ? { ok: false, status: 502, json: async () => null } : net.fetch(url, opts));
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {}, now: base });
    await mon.runDue({ force: true, fetch: down, sleep: async () => {}, now: base });
    const m = Object.values(await st.storage.get("monitors"))[0];
    assert.deepEqual(m.lastResults.map((f) => f.key), ["cert:a.test.darknode.ai"], "an outage is not a resolution");
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {}, now: base });
    assert.equal(net.deliveries.length, 1, "no resolved/new alert pair around the outage");
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

// ---- KEV / EPSS watch: reads the workspace graph inventory, matches feeds, alerts ----
// A graph-binding stub: GraphDO.get(wid).fetch(pull) returns the workspace's entities.
function graphEnv(entities) {
  return { GRAPH: { idFromName: (n) => n, get: () => ({ fetch: async () => ({ ok: true, status: 200, json: async () => ({ entities }) }) }) } };
}
// fake net: serves the two mirrored feeds; any other URL is a webhook delivery.
function kevNet(kevCves = ["CVE-2021-44228"], epssRows = []) {
  const deliveries = [];
  const fetch = async (url, opts) => {
    if (url.includes("cisa-kev-index")) return { ok: true, status: 200, json: async () => ({ data: kevCves.map((c) => ({ cve: c, dueDate: "2021-12-24" })) }) };
    if (url.includes("epss-top")) return { ok: true, status: 200, json: async () => ({ data: epssRows }) };
    deliveries.push({ url, body: opts && opts.body }); return { ok: true, status: 200 };
  };
  return { fetch, deliveries };
}

group("monitor DO/kev-epss", () => {
  test("a KEV match in the graph alerts, and an unchanged second run does not", async () => {
    const st = memState();
    const mon = new MonitorDO(st, graphEnv([{ name: "app server", data: { cves: ["CVE-2021-44228"] } }]));
    await st.storage.put("wid", "ws1");
    await post(mon, { op: "upsert", monitor: { name: "KEV", type: "kev-epss", config: { epssFloor: 0.5 }, channels: [{ type: "webhook", url: "https://hook.test/x" }] } });
    const net = kevNet();
    const r = await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    assert.equal(r.ran[0].found, 1);
    assert.equal(net.deliveries.length, 1, "a new KEV match alerts regardless of severity");
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    assert.equal(net.deliveries.length, 1, "no new change on the second run");
  });

  test("an EPSS score moving by a point is not a new alert", async () => {
    const st = memState();
    const mon = new MonitorDO(st, graphEnv([{ name: "app", data: { cves: ["CVE-2024-0001"] } }]));
    await st.storage.put("wid", "ws1");
    await post(mon, { op: "upsert", monitor: { name: "KEV", type: "kev-epss", config: { epssFloor: 0.5 }, channels: [{ type: "webhook", url: "https://hook.test/x" }] } });
    const a = kevNet([], [{ cve: "CVE-2024-0001", epss: 0.61 }]), b = kevNet([], [{ cve: "CVE-2024-0001", epss: 0.62 }]);
    await mon.runDue({ force: true, fetch: a.fetch, sleep: async () => {} });
    assert.equal(a.deliveries.length, 1, "the first EPSS match alerts");
    await mon.runDue({ force: true, fetch: b.fetch, sleep: async () => {} });
    assert.equal(b.deliveries.length, 0, "61% -> 62% only changes the title");
  });

  test("a feed or the inventory that does not answer fails the run instead of resolving every match", async () => {
    const st = memState();
    let graphUp = true;
    const env = { GRAPH: { idFromName: (n) => n, get: () => ({ fetch: async () => (graphUp ? { ok: true, status: 200, json: async () => ({ entities: [{ name: "app", data: { cves: ["CVE-2021-44228"] } }] }) } : { ok: false, status: 503, json: async () => null }) }) } };
    const mon = new MonitorDO(st, env);
    await st.storage.put("wid", "ws1");
    await post(mon, { op: "upsert", monitor: { name: "KEV", type: "kev-epss", config: { epssFloor: 0.5 }, channels: [{ type: "webhook", url: "https://hook.test/x" }] } });
    const net = kevNet();
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    const feedDown = async (url, opts) => (url.includes("epss-top") ? { ok: false, status: 500, json: async () => null } : net.fetch(url, opts));
    const r = await mon.runDue({ force: true, fetch: feedDown, sleep: async () => {} });
    assert.ok(r.ran[0].error, "the run reports the outage");
    graphUp = false;
    assert.ok((await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} })).ran[0].error);
    graphUp = true;
    const m = Object.values(await st.storage.get("monitors"))[0];
    assert.deepEqual(m.lastResults.map((f) => f.key), ["kev:CVE-2021-44228"]);
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    assert.equal(net.deliveries.length, 1, "the match is not alerted again after the outage");
  });

  test("no CVEs in the workspace graph means nothing found and nothing delivered", async () => {
    const st = memState();
    const mon = new MonitorDO(st, graphEnv([{ name: "host", data: {} }]));
    await st.storage.put("wid", "ws1");
    await post(mon, { op: "upsert", monitor: { name: "KEV", type: "kev-epss", config: {}, channels: [{ type: "webhook", url: "https://hook.test/x" }] } });
    const net = kevNet();
    const r = await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    assert.equal(r.ran[0].found, 0);
    assert.equal(net.deliveries.length, 0);
  });

  test("the monitor's own CVE writes are not re-read as inventory (no self-feedback loop)", async () => {
    // The graph holds ONLY a VULNERABILITY the monitor itself authored last run (source monitor:*).
    // Without the source filter this echoes back as inventory and the CVE could never clear.
    const st = memState();
    const mon = new MonitorDO(st, graphEnv([{ type: "VULNERABILITY", name: "CVE-2021-44228", source: "monitor:m1", data: {} }]));
    await st.storage.put("wid", "ws1");
    await post(mon, { op: "upsert", monitor: { name: "KEV", type: "kev-epss", config: {}, channels: [{ type: "webhook", url: "https://hook.test/x" }] } });
    const net = kevNet();
    const r = await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    assert.equal(r.ran[0].found, 0, "a monitor-authored CVE node is not genuine inventory");
    assert.equal(net.deliveries.length, 0);
  });

  test("a genuine (tool-authored) CVE node IS counted as inventory", async () => {
    const st = memState();
    const mon = new MonitorDO(st, graphEnv([{ type: "VULNERABILITY", name: "CVE-2021-44228", source: "vulnimport", data: {} }]));
    await st.storage.put("wid", "ws1");
    await post(mon, { op: "upsert", monitor: { name: "KEV", type: "kev-epss", config: {} } });
    const r = await mon.runDue({ force: true, fetch: kevNet().fetch, sleep: async () => {} });
    assert.equal(r.ran[0].found, 1, "a real inventory source still matches");
  });

  test("the DO remembers its workspace id from the x-mon-wid header", async () => {
    const st = memState();
    const mon = new MonitorDO(st, graphEnv([]));
    const res = await mon.fetch(new Request("https://monitor/", { method: "POST", body: JSON.stringify({ op: "list" }), headers: { "content-type": "application/json", "x-mon-uid": "u1", "x-mon-role": "owner", "x-mon-wid": "wsX" } }));
    assert.equal(res.status, 200);
    assert.equal(await st.storage.get("wid"), "wsX");
  });
});

// ---- Email & DNS posture drift ----
// fake DoH: zone maps "TYPE name" -> data rows or "fail"; other URLs are webhook deliveries.
function dohNet(zone) {
  const deliveries = [];
  const fetch = async (url, opts) => {
    if (!/cloudflare-dns\.com|dns\.google/.test(url)) { deliveries.push({ url, body: opts && opts.body }); return { ok: true, status: 200 }; }
    const u = new URL(url), type = u.searchParams.get("type"), name = u.searchParams.get("name"), rows = zone[type + " " + name];
    if (rows === "fail") return { ok: false, status: 502, json: async () => null };
    return { ok: true, status: 200, json: async () => ({ Status: 0, Answer: (rows || []).map((data) => ({ name, type: { TXT: 16, MX: 15, CAA: 257 }[type], data })) }) };
  };
  return { fetch, deliveries };
}

group("monitor DO/email-posture", () => {
  test("the baseline run obeys minSeverity; a later weakening alerts as drift; a failed lookup holds", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    await post(mon, { op: "upsert", monitor: { name: "Mail", type: "email-posture", config: { domains: ["example.com"] }, channels: [{ type: "webhook", url: "https://hook.test/x" }] } });
    const zone = { "TXT example.com": ["v=spf1 mx -all"], "TXT _dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:d@example.com"], "MX example.com": ["10 mx.example.net."] };
    const a = dohNet(zone);
    const r1 = await mon.runDue({ force: true, fetch: a.fetch, sleep: async () => {} });
    assert.equal(r1.ran[0].found, 1, "only the missing CAA (low)");
    assert.equal(a.deliveries.length, 0, "a low baseline finding does not alert");
    zone["TXT example.com"] = ["v=spf1 mx ~all"];
    const b = dohNet(zone);
    await mon.runDue({ force: true, fetch: b.fetch, sleep: async () => {} });
    assert.equal(b.deliveries.length, 1, "SPF weakened -all -> ~all alerts as drift");
    assert.ok(b.deliveries[0].body.includes("email:example.com:spf") || b.deliveries[0].body.includes("SPF on example.com"));
    zone["TXT example.com"] = "fail";
    const c = dohNet(zone);
    await mon.runDue({ force: true, fetch: c.fetch, sleep: async () => {} });
    assert.equal(c.deliveries.length, 0, "an unanswered lookup is not read as fixed");
    const m = Object.values(await st.storage.get("monitors"))[0];
    assert.ok(m.lastResults.some((f) => f.key === "email:example.com:spf"), "the SPF finding is held");
    const hist = (await post(mon, { op: "list" })).json.history;
    assert.equal(hist[0].skipped, 1, "the run records what could not be checked");
  });
  test("a domain added to an existing monitor gets its own baseline run, not drift alerts", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    const base = { name: "Mail", type: "email-posture", channels: [{ type: "webhook", url: "https://hook.test/x" }] };
    await post(mon, { op: "upsert", monitor: { ...base, config: { domains: ["example.com"] } } });
    const zone = { "TXT example.com": ["v=spf1 mx -all"], "TXT _dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:d@example.com"], "MX example.com": ["10 mx.example.net."],
      "TXT example.org": ["v=spf1 mx ~all"], "TXT _dmarc.example.org": ["v=DMARC1; p=quarantine; rua=mailto:d@example.org"], "MX example.org": ["10 mx.example.net."] };
    await mon.runDue({ force: true, fetch: dohNet(zone).fetch, sleep: async () => {} });
    const id = Object.keys(await st.storage.get("monitors"))[0];
    await post(mon, { op: "upsert", monitor: { ...base, id, config: { domains: ["example.com", "https://example.org/"] } } });
    const b = dohNet(zone);
    await mon.runDue({ force: true, fetch: b.fetch, sleep: async () => {} });
    assert.equal(b.deliveries.length, 0, "the new domain's low findings (~all, quarantine, no CAA) do not alert on its first run");
    zone["TXT example.org"] = ["v=spf1 mx ?all"];
    const c = dohNet(zone);
    await mon.runDue({ force: true, fetch: c.fetch, sleep: async () => {} });
    assert.equal(c.deliveries.length, 1, "once baselined, a weakening on it alerts as drift");
    const m = Object.values(await st.storage.get("monitors"))[0];
    assert.deepEqual(m.baselined.slice().sort(), ["example.com", "example.org"], "editing the monitor kept the existing domain's baseline");
  });
});

// ---- Graph sync: a monitor run writes its findings into the workspace GraphDO ----
// A capturing graph stub: records every POST body and still serves GET pulls (kev-epss).
function capturingGraphEnv(entities = []) {
  const pushes = [];
  const env = { GRAPH: { idFromName: (n) => n, get: () => ({ fetch: async (url, opts) => {
    if (opts && opts.method === "POST") { const body = JSON.parse(opts.body); pushes.push(body); return { ok: true, status: 200, json: async () => ({ applied: { entities: body.entities.length, relationships: body.relationships.length } }) }; }
    return { ok: true, status: 200, json: async () => ({ entities }) };
  } }) } };
  return { env, pushes };
}

group("monitor DO/graph sync", () => {
  test("a cert monitor run pushes a FINDING + DOMAIN into the workspace graph", async () => {
    const st = memState(); const g = capturingGraphEnv();
    const mon = new MonitorDO(st, g.env);
    await st.storage.put("wid", "ws1");
    await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"], warnDays: 21 } } });
    const net = fakeNet(day(10));
    const r = await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    assert.equal(g.pushes.length, 1, "one graph push");
    const body = g.pushes[0];
    const f = body.entities.find((e) => e.type === "FINDING");
    const d = body.entities.find((e) => e.type === "DOMAIN");
    assert.ok(f && d, "finding + domain entities pushed");
    assert.equal(f.source, "monitor:" + r.ran[0].id);
    assert.equal(f.status, "open");
    assert.ok(body.relationships.some((rel) => rel.type === "affects" && rel.fromId === f.id && rel.toId === d.id));
    assert.ok(r.ran[0].graphSynced > 0, "run reports a graph sync count");
  });

  test("a healthy cert run (no findings) pushes nothing", async () => {
    const st = memState(); const g = capturingGraphEnv();
    const mon = new MonitorDO(st, g.env);
    await st.storage.put("wid", "ws1");
    await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"], warnDays: 21 } } });
    await mon.runDue({ force: true, fetch: fakeNet(day(400)).fetch, sleep: async () => {} });
    assert.equal(g.pushes.length, 0, "no findings → no graph write");
  });

  test("an unchanged second run re-emits byte-identical records (a tie at the DO)", async () => {
    // KEV findings have a stable title (a CVE id, no drifting day count), so this is
    // deterministic regardless of wall-clock between the two runs.
    const st = memState(); const g = capturingGraphEnv([{ name: "app server", data: { cves: ["CVE-2021-44228"] } }]);
    const mon = new MonitorDO(st, g.env);
    await st.storage.put("wid", "ws1");
    await post(mon, { op: "upsert", monitor: { name: "KEV", type: "kev-epss", config: { epssFloor: 0.5 } } });
    const net = kevNet();
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    const a = g.pushes[0].entities.find((e) => e.type === "FINDING");
    const b = g.pushes[g.pushes.length - 1].entities.find((e) => e.type === "FINDING");
    assert.equal(a.createdAt, b.createdAt, "createdAt stable across runs (SLA clock preserved)");
    assert.equal(a.updatedAt, b.updatedAt, "updatedAt stable when nothing changed");
  });

  test("a resolved finding strictly wins at the graph: later run pushes status=resolved with a greater updatedAt", async () => {
    const st = memState(); const g = capturingGraphEnv();
    const mon = new MonitorDO(st, g.env);
    await st.storage.put("wid", "ws1");
    await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"], warnDays: 21 } } });
    const base = Date.now();
    // Run 1: cert expiring soon -> an open FINDING is pushed.
    await mon.runDue({ force: true, fetch: fakeNet(new Date(base + 10 * 86400000).toISOString()).fetch, sleep: async () => {}, now: base });
    const open = g.pushes[0].entities.find((e) => e.type === "FINDING");
    assert.equal(open.status, "open");
    // Run 2 (a day later): cert renewed (healthy) -> the finding is removed -> resolved push.
    await mon.runDue({ force: true, fetch: fakeNet(new Date(base + 400 * 86400000).toISOString()).fetch, sleep: async () => {}, now: base + 86400000 });
    const resolved = g.pushes[g.pushes.length - 1].entities.find((e) => e.type === "FINDING" && e.id === open.id);
    assert.ok(resolved, "the same FINDING id is re-pushed on resolve");
    assert.equal(resolved.status, "resolved");
    assert.equal(resolved.data.resolution, "fixed");
    assert.ok(resolved.updatedAt > open.updatedAt, "resolved updatedAt strictly later -> GraphDO.wins() applies it (not a tie)");
    assert.equal(resolved.createdAt, open.createdAt, "SLA createdAt preserved across the resolve");
  });

  test("a resolution survives a failed graph push: it is re-emitted on the next run until acked", async () => {
    // GRAPH env whose POST can be toggled to fail — models a transient push failure exactly
    // when the resolution is written.
    const pushes = [];
    let failPush = false;
    const env = { GRAPH: { idFromName: (n) => n, get: () => ({ fetch: async (url, opts) => {
      if (opts && opts.method === "POST") {
        const body = JSON.parse(opts.body); pushes.push(body);
        if (failPush) return { ok: false, status: 500, json: async () => ({}) };
        return { ok: true, status: 200, json: async () => ({ applied: { entities: body.entities.length, relationships: body.relationships.length } }) };
      }
      return { ok: true, status: 200, json: async () => ({ entities: [] }) };
    } }) } };
    const st = memState();
    const mon = new MonitorDO(st, env);
    await st.storage.put("wid", "ws1");
    await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"], warnDays: 21 } } });
    const base = Date.now();
    // Run 1: expiring cert -> open FINDING pushed (success).
    await mon.runDue({ force: true, fetch: fakeNet(new Date(base + 10 * 86400000).toISOString()).fetch, sleep: async () => {}, now: base });
    const open = pushes[0].entities.find((e) => e.type === "FINDING");
    assert.equal(open.status, "open");
    // Run 2 (next day): cert renewed -> resolved push, but the push FAILS.
    failPush = true;
    await mon.runDue({ force: true, fetch: fakeNet(new Date(base + 400 * 86400000).toISOString()).fetch, sleep: async () => {}, now: base + 86400000 });
    const r2 = pushes[pushes.length - 1].entities.find((e) => e.type === "FINDING" && e.id === open.id);
    assert.ok(r2 && r2.status === "resolved", "run 2 attempted the resolved push");
    // Run 3 (another day): still healthy -> the resolution MUST be re-emitted (push now succeeds).
    failPush = false;
    await mon.runDue({ force: true, fetch: fakeNet(new Date(base + 401 * 86400000).toISOString()).fetch, sleep: async () => {}, now: base + 2 * 86400000 });
    const r3 = pushes[pushes.length - 1].entities.find((e) => e.type === "FINDING" && e.id === open.id);
    assert.ok(r3 && r3.status === "resolved", "run 3 re-emits the resolved record after the earlier failure (not lost)");
    assert.equal(r3.createdAt, open.createdAt, "SLA createdAt still preserved");
    // Run 4: once acked, the resolution is forgotten — no more re-emits.
    const before = pushes.length;
    await mon.runDue({ force: true, fetch: fakeNet(new Date(base + 402 * 86400000).toISOString()).fetch, sleep: async () => {}, now: base + 3 * 86400000 });
    assert.equal(pushes.length, before, "run 4 pushes nothing — the acked resolution is no longer queued");
  });

  test("findings still reach the graph with no GRAPH binding, failing cleanly", async () => {
    const st = memState(); const mon = new MonitorDO(st, {}); // env with no GRAPH
    await st.storage.put("wid", "ws1");
    await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"], warnDays: 21 } } });
    const r = await mon.runDue({ force: true, fetch: fakeNet(day(10)).fetch, sleep: async () => {} });
    assert.equal(r.ran[0].graphSynced, 0, "no binding → nothing synced, no throw");
  });
});

group("monitor DO/prototype safety", () => {
  test("pause/delete/upsert with id __proto__ never touch Object.prototype", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    await post(mon, { op: "upsert", monitor: { name: "C", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"] }, channels: [] } });
    const paused = await post(mon, { op: "pause", id: "__proto__", paused: true });
    assert.equal(paused.status, 404);
    const del = await post(mon, { op: "delete", id: "__proto__" });
    assert.equal(del.status, 200);
    assert.equal(({}).paused, undefined, "Object.prototype.paused must be unset");
    const up = await post(mon, { op: "upsert", monitor: { id: "__proto__", type: "cert-expiry", config: { domains: ["b.test.darknode.ai"] }, channels: [] } });
    assert.notEqual(up.json.monitor.id, "__proto__");
  });
});

group("monitor DO/alert window + viewer redaction", () => {
  test("a cert inside the monitor's own warnDays (60) alerts at 40 days, not only inside the 21-day default", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"], warnDays: 60 }, channels: [{ type: "webhook", url: "https://hook.test/x" }] } });
    const net = fakeNet(day(40));
    const r = await mon.runDue({ force: true, fetch: net.fetch, sleep: async () => {} });
    assert.equal(r.ran[0].found, 1);
    assert.equal(r.ran[0].alerted, 1);
  });
  test("viewers see only the host of a webhook URL; writers see it whole", async () => {
    const st = memState(); const mon = new MonitorDO(st);
    await post(mon, { op: "upsert", monitor: { name: "Certs", type: "cert-expiry", config: { domains: ["a.test.darknode.ai"] }, channels: [{ type: "slack", url: "https://hooks.example.com/services/T0/B0/secretpart" }] } });
    const v = await post(mon, { op: "list" }, "viewer");
    assert.equal(v.json.monitors[0].channels[0].url, "https://hooks.example.com/…");
    const o = await post(mon, { op: "list" }, "owner");
    assert.ok(o.json.monitors[0].channels[0].url.endsWith("secretpart"));
  });
  test("an alert rule minSeverity of an Object.prototype name does not silence alerts", async () => {
    const { sevRank } = await import("../../worker/monitor-core.js");
    assert.equal(sevRank("constructor"), 0);
    assert.equal(sevRank("HIGH"), 3);
  });
});
