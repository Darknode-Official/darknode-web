// The Free plan's domain watch (worker/free-watch.js) and the email alert channel
// (worker/alert-email.js), end to end through the MonitorDO with an in-memory storage shim, a fake
// network and no real sleeps. Nothing here reaches Resend, Firebase or a real DNS resolver.
import { test, group, assert } from "../harness.mjs";
import { MonitorDO, handleMonitor, handleWatchStop } from "../../worker/monitor.js";
import { freeWatchDenied, freeAllowed, FREE_WATCH } from "../../worker/free-watch.js";
import { buildAlertEmail, buildTestEmail, explainEvent, ALERT_EMAILS_PER_DAY, stopToken, sendEmail, recipient, maskEmail } from "../../worker/alert-email.js";
import { FROM } from "../../worker/digest.js";
import { attachPrincipal } from "../../worker/auth.js";
import { _resetPlanCache } from "../../worker/plan.js";
import { _resetLocalQuota } from "../../worker/quota.js";

const ME = "test@darknode.ai";
const ENV = { RESEND_KEY: "re_test_only", DIGEST_SECRET: "unit-test-secret" };

function memState() {
  const map = new Map(); let alarm = null;
  const storage = {
    async get(k) { return map.has(k) ? map.get(k) : undefined; },
    async put(k, v) { map.set(k, v); },
    async delete(k) { map.delete(k); },
    async setAlarm(ts) { alarm = ts; },
    async getAlarm() { return alarm; },
  };
  return { storage, blockConcurrencyWhile: async (fn) => fn(), _map: map };
}
const newDO = () => { const st = memState(); const mon = new MonitorDO(st, { ...ENV }); return { st, mon }; };

// a request to the DO as handleMonitor sends it: free = the caller is below Pro
async function post(mon, body, { uid = "u1", free = false, email = ME, role = "owner", wid = "u1" } = {}) {
  const headers = { "content-type": "application/json", "x-mon-uid": uid, "x-mon-role": role, "x-mon-wid": wid };
  if (free) headers["x-mon-plan"] = "free";
  if (email) headers["x-mon-email"] = encodeURIComponent(email);
  const res = await mon.fetch(new Request("https://monitor/", { method: "POST", body: JSON.stringify(body), headers }));
  return { status: res.status, json: await res.json() };
}
const watch = (type, domain, extra = {}) => ({ op: "upsert", monitor: { name: "Watch " + domain, type, config: { domains: [domain], ...(type === "cert-expiry" ? { warnDays: 21 } : {}) }, channels: [{ type: "email" }], intervalMs: 86400000, ...extra } });

const day = (n, base = Date.now()) => new Date(base + n * 86400000).toISOString();
// fake network: crt.sh serves one certificate, DoH serves `zone`, Resend records each email
function net({ certNotAfter = null, zone = {}, resendStatus = 200 } = {}) {
  const emails = [], hooks = [];
  const fetch = async (url, opts = {}) => {
    url = String(url);
    if (url.includes("crt.sh")) return { ok: true, status: 200, json: async () => (certNotAfter ? [{ issuer_name: "C=US, O=Example CA, CN=E1", not_after: certNotAfter, not_before: day(-80), name_value: "example.com" }] : []) };
    if (url.includes("certspotter")) return { ok: false, status: 404, json: async () => null };
    if (/cloudflare-dns\.com|dns\.google/.test(url)) {
      const u = new URL(url), type = u.searchParams.get("type"), name = u.searchParams.get("name"), rows = zone[type + " " + name];
      return { ok: true, status: 200, json: async () => ({ Status: 0, Answer: (rows || []).map((data) => ({ name, type: { TXT: 16, MX: 15, CAA: 257 }[type], data })) }) };
    }
    if (url === "https://api.resend.com/emails") { emails.push({ headers: opts.headers, body: JSON.parse(opts.body) }); return { ok: resendStatus < 300, status: resendStatus, json: async () => (resendStatus < 300 ? { id: "e_" + emails.length } : { message: "rejected" }) }; }
    hooks.push(url); return { ok: true, status: 200 };
  };
  return { fetch, emails, hooks };
}
const quick = (n, extra = {}) => ({ force: true, fetch: n.fetch, sleep: async () => {}, ...extra });

// ---- the rules (pure) ---------------------------------------------------------------------------

group("free watch/rules", () => {
  const mon = (type, domains, channels = [{ type: "email", to: ME, uid: "u1" }], id = "m" + Math.random()) => ({ id, type, config: { domains }, channels });
  test("Free with one domain is allowed: certificate and email/DNS on the same domain", () => {
    assert.equal(freeWatchDenied(mon("cert-expiry", ["example.com"]), []), null);
    assert.equal(freeWatchDenied(mon("email-posture", ["https://Example.com/"]), [mon("cert-expiry", ["example.com"])]), null, "same host however it is written");
  });
  test("a second domain is denied, naming the one already watched", () => {
    const no = freeWatchDenied(mon("cert-expiry", ["example.org"]), [mon("cert-expiry", ["example.com"])]);
    assert.ok(no && /one domain/.test(no) && no.includes("example.com") && no.includes("example.org"), no);
    assert.ok(freeWatchDenied(mon("cert-expiry", ["example.com", "example.org"]), []), "two domains in one monitor");
  });
  test("a paused watch still counts toward the one domain", () => {
    assert.ok(freeWatchDenied(mon("email-posture", ["example.org"]), [{ ...mon("cert-expiry", ["example.com"]), paused: true }]));
  });
  test("kev-epss on Free is denied; so are chat and webhook channels", () => {
    assert.ok(/Pro plan/.test(freeWatchDenied(mon("kev-epss", []), [])));
    assert.ok(/account email/.test(freeWatchDenied(mon("cert-expiry", ["example.com"], [{ type: "slack", url: "https://hooks.example.com/x" }]), [])));
  });
  test("freeAllowed keeps the earliest-created domain when a lapsed plan left more", () => {
    const a = { ...mon("cert-expiry", ["example.org"], undefined, "a"), createdAt: 20 };
    const b = { ...mon("email-posture", ["example.com"], undefined, "b"), createdAt: 10 };
    const c = { ...mon("cert-expiry", ["example.com"], undefined, "c"), createdAt: 30 };
    const k = { ...mon("kev-epss", [], undefined, "k"), createdAt: 1 };
    const hook = { ...mon("cert-expiry", ["example.com"], [{ type: "webhook", url: "https://hooks.example.com/x" }], "h"), createdAt: 0 };
    assert.deepEqual([...freeAllowed({ a, b, c, k, h: hook })].sort(), ["b", "c"]);
  });
});

// ---- the route: who is Free, and the verified address -----------------------------------------

group("free watch/handleMonitor", () => {
  const capture = () => { const calls = []; return { calls, idFromName: (x) => x, get: () => ({ fetch: async (u, init) => { calls.push(init); return new Response(JSON.stringify({ ok: true }), { status: 200 }); } }) }; };
  const notFound = async () => ({ ok: false, status: 404, json: async () => ({}) });
  async function call(wid, body, claims) {
    _resetPlanCache();
    const real = globalThis.fetch; globalThis.fetch = notFound; // users/u1 has no tier: Free
    try {
      const MONITOR = capture(), json = (b, status = 200) => ({ status, body: b });
      const req = new Request("https://w.test/x", { method: "POST", body: JSON.stringify(body) });
      attachPrincipal(req, { kind: "user", uid: "u1", email: ME, token: "tok", claims });
      const r = await handleMonitor(req, { FIREBASE_PROJECT_ID: "p1", MONITOR }, wid, json);
      return { ...r, sent: MONITOR.calls[0] };
    } finally { globalThis.fetch = real; }
  }
  test("a Free caller's personal workspace is marked free; Pro is not", async () => {
    const free = await call("u1", watch("cert-expiry", "example.com"), { email_verified: true });
    assert.equal(free.sent.headers["x-mon-plan"], "free");
    const pro = await call("u1", watch("cert-expiry", "example.com"), { email_verified: true, plan: "pro" });
    assert.equal(pro.sent.headers["x-mon-plan"], undefined);
  });
  test("the email header is the token's address, and only when email_verified is true", async () => {
    assert.equal(decodeURIComponent((await call("u1", { op: "list" }, { email_verified: true })).sent.headers["x-mon-email"]), ME);
    assert.equal((await call("u1", { op: "list" }, { email_verified: false })).sent.headers["x-mon-email"], undefined);
    assert.equal((await call("u1", { op: "list" }, {})).sent.headers["x-mon-email"], undefined);
  });
});

// ---- the DO enforces it -------------------------------------------------------------------------

group("free watch/MonitorDO", () => {
  test("Free: one domain, both check types, email to the token's address, once a day", async () => {
    const { st, mon } = newDO();
    const a = await post(mon, watch("cert-expiry", "example.com", { intervalMs: 15 * 60000 }), { free: true });
    assert.equal(a.status, 200, JSON.stringify(a.json));
    const b = await post(mon, watch("email-posture", "example.com"), { free: true });
    assert.equal(b.status, 200);
    const stored = st._map.get("monitors")[a.json.monitor.id];
    assert.deepEqual(stored.channels, [{ type: "email", to: ME, uid: "u1" }]);
    assert.equal(stored.intervalMs, FREE_WATCH.minIntervalMs, "a Free watch runs at most once a day");
    assert.ok(stored.createdAt > 0);
    assert.equal(a.json.monitor.channels[0].to, ME, "the owner sees their own address");
  });
  test("Free: a second domain gets 402 plan:true", async () => {
    const { mon } = newDO();
    await post(mon, watch("cert-expiry", "example.com"), { free: true });
    const r = await post(mon, watch("email-posture", "example.org"), { free: true });
    assert.equal(r.status, 402); assert.equal(r.json.plan, true);
    assert.ok(r.json.error.includes("example.com"), r.json.error);
  });
  test("Free: kev-epss and webhook channels get 402 plan:true", async () => {
    const { mon } = newDO();
    const k = await post(mon, { op: "upsert", monitor: { type: "kev-epss", config: {} } }, { free: true });
    assert.equal(k.status, 402); assert.equal(k.json.plan, true);
    const w = await post(mon, { op: "upsert", monitor: { type: "cert-expiry", config: { domains: ["example.com"] }, channels: [{ type: "webhook", url: "https://hooks.example.com/x" }] } }, { free: true });
    assert.equal(w.status, 402);
  });
  test("Pro keeps today's behaviour: many domains, kev-epss, webhooks", async () => {
    const { mon } = newDO();
    assert.equal((await post(mon, watch("cert-expiry", "example.com"))).status, 200);
    assert.equal((await post(mon, watch("cert-expiry", "example.org"))).status, 200);
    assert.equal((await post(mon, { op: "upsert", monitor: { type: "kev-epss", config: {} } })).status, 200);
    assert.equal((await post(mon, { op: "upsert", monitor: { type: "cert-expiry", config: { domains: ["example.net"] }, channels: [{ type: "webhook", url: "https://hooks.example.com/x" }] } })).status, 200);
  });
  test("an address in the request is ignored: email goes to the verified account only", async () => {
    const { st, mon } = newDO();
    const r = await post(mon, { op: "upsert", monitor: { type: "cert-expiry", config: { domains: ["example.com"] }, channels: [{ type: "email", to: "someone@example.org", uid: "u2" }, { type: "email", to: "x@example.org" }] } });
    assert.deepEqual(st._map.get("monitors")[r.json.monitor.id].channels, [{ type: "email", to: ME, uid: "u1" }], "one email channel, the caller's own address");
  });
  test("no verified address: an email channel is refused (400), on any plan", async () => {
    const { mon } = newDO();
    assert.equal((await post(mon, watch("cert-expiry", "example.com"), { email: "" })).status, 400);
    assert.equal((await post(mon, watch("cert-expiry", "example.com"), { email: "", free: true })).status, 400);
  });
  test("Free with no channel gets email alerts by default", async () => {
    const { st, mon } = newDO();
    const r = await post(mon, { op: "upsert", monitor: { type: "email-posture", config: { domains: ["example.com"] }, channels: [] } }, { free: true });
    assert.deepEqual(st._map.get("monitors")[r.json.monitor.id].channels, [{ type: "email", to: ME, uid: "u1" }]);
  });
  test("another member sees the address masked", async () => {
    const { mon } = newDO();
    await post(mon, watch("cert-expiry", "example.com"));
    const l = await post(mon, { op: "list" }, { uid: "u2", role: "viewer" });
    assert.equal(l.json.monitors[0].channels[0].to, maskEmail(ME));
    assert.equal(l.json.monitors[0].channels[0].to, "t***@darknode.ai");
  });
  test("Free: Run now runs only the watch, at most once per 10 minutes", async () => {
    const { st, mon } = newDO();
    const keep = await post(mon, watch("cert-expiry", "example.com"));
    st._map.get("monitors")[keep.json.monitor.id].createdAt = 1;
    await post(mon, watch("cert-expiry", "example.org")); // left over from a paid plan
    const realFetch = globalThis.fetch; globalThis.fetch = net().fetch;
    try {
      const r1 = await post(mon, { op: "run" }, { free: true });
      assert.equal(r1.status, 200); assert.equal(r1.json.ran.length, 1); assert.equal(r1.json.ran[0].id, keep.json.monitor.id);
      const r2 = await post(mon, { op: "run" }, { free: true });
      assert.equal(r2.status, 429); assert.ok(/minute/.test(r2.json.error));
    } finally { globalThis.fetch = realFetch; }
  });
  test("Free: resuming a monitor outside the watch gets 402; the watch itself resumes", async () => {
    const { st, mon } = newDO();
    const keep = await post(mon, watch("cert-expiry", "example.com"));
    st._map.get("monitors")[keep.json.monitor.id].createdAt = 1;
    const other = await post(mon, watch("cert-expiry", "example.org"));
    await post(mon, { op: "pause", id: other.json.monitor.id, paused: true });
    await post(mon, { op: "pause", id: keep.json.monitor.id, paused: true });
    assert.equal((await post(mon, { op: "pause", id: other.json.monitor.id, paused: false }, { free: true })).status, 402);
    assert.equal((await post(mon, { op: "pause", id: keep.json.monitor.id, paused: false }, { free: true })).status, 200);
  });
  test("the alarm on a Free plan runs the watch and holds everything else", async () => {
    const { st, mon } = newDO();
    const keep = await post(mon, watch("cert-expiry", "example.com"));
    const hook = await post(mon, { op: "upsert", monitor: { type: "cert-expiry", config: { domains: ["example.com"] }, channels: [{ type: "webhook", url: "https://hooks.example.com/x" }] } });
    await st.storage.put("wid", "u1");
    mon.env = { ...ENV, FIREBASE_PROJECT_ID: "p1" };
    mon.planOpts = { token: async () => "sa", cache: new Map(), fetch: async () => ({ ok: true, status: 200, json: async () => ({ fields: { tier: { stringValue: "free" } } }) }) };
    const realFetch = globalThis.fetch; globalThis.fetch = net().fetch;
    try { await mon.alarm(); } finally { globalThis.fetch = realFetch; }
    const mons = st._map.get("monitors");
    assert.ok(mons[keep.json.monitor.id].lastRunAt > 0, "the watch ran");
    assert.equal(mons[keep.json.monitor.id].planHeld, undefined);
    assert.equal(mons[hook.json.monitor.id].planHeld, true, "the webhook monitor is held");
  });
});

// ---- the email --------------------------------------------------------------------------------

const NOW = Date.UTC(2026, 10, 25, 9, 30);
const certEv = { kind: "cert", key: "cert:example.com", severity: "high", title: "Certificate for example.com expires in 9 days", domain: "example.com", daysToExpiry: 9, notAfter: "2026-12-04T09:00:00.000Z", issuer: "C=US, O=Example CA, CN=E1" };
const dmarcEv = { kind: "drift", key: "email:example.com:dmarc", severity: "medium", title: "DMARC on example.com: DMARC p=none (monitor only).", domain: "example.com", check: "DMARC", advice: "Enforce with p=quarantine then p=reject.", was: "reject", now: "none", recordAt: "_dmarc.example.com" };

group("alert email/content", () => {
  test("what changed, why it matters, the exact fix", () => {
    const c = explainEvent(certEv);
    assert.equal(c.what, "Certificate for example.com expires in 9 days");
    assert.ok(/browsers block visitors to example.com/.test(c.why));
    assert.ok(c.fix.includes("Renew the certificate for example.com") && c.fix.includes("issued by Example CA") && c.fix.includes("valid until 2026-12-04"), c.fix);
    const d = explainEvent(dmarcEv);
    assert.equal(d.what, "DMARC policy for example.com weakened from reject to none");
    assert.ok(/phishing in your name/.test(d.why));
    assert.equal(d.fix, "Set the policy in the TXT record at _dmarc.example.com back to p=reject.");
    const removed = explainEvent({ ...dmarcEv, now: "missing", title: "DMARC on example.com: No DMARC record." });
    assert.equal(removed.what, "The DMARC record for example.com was removed (it had p=reject)");
    assert.ok(removed.fix.startsWith("Publish one TXT record at _dmarc.example.com: v=DMARC1; p=quarantine"));
    assert.equal(explainEvent({ key: "email:example.com:spf", severity: "low", title: "SPF on example.com: x", domain: "example.com", check: "SPF", was: "-all", now: "~all" }).what, "SPF for example.com weakened from -all to ~all");
  });
  test("a sample email: plain text + simple HTML, no tracking, no emojis, a stop link and the Deck path", () => {
    const stop = "https://darknode-proxy.darknode-ai.workers.dev/api/watch/stop?w=u1&u=u1&t=abc";
    const m = buildAlertEmail({ monitor: { id: "m1", name: "Watch example.com", type: "email-posture", intervalMs: 86400000 }, events: [dmarcEv], stopUrl: stop, sent: 1, now: NOW });
    process.stdout.write("\n----- sample alert email (text) -----\nSubject: " + m.subject + "\n\n" + m.text + "\n----- end sample -----\n\n");
    assert.equal(m.subject, "DMARC policy for example.com weakened from reject to none");
    for (const s of ["Why it matters:", "Fix: Set the policy in the TXT record at _dmarc.example.com back to p=reject.", "https://darknode.ai/monitors", "Stop these alerts: " + stop, "Monitors, then Pause or Delete", "once a day"]) assert.ok(m.text.includes(s), s);
    assert.ok(m.html.includes("Why it matters:") && m.html.includes(stop.replace(/&/g, "&amp;")));
    assert.ok(!/<img|<script|<style|tracking|pixel/i.test(m.html), "no images, scripts or trackers");
    assert.ok(!/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(m.text + m.html), "no emojis");
  });
  test("several changes: one email, numbered, the subject counts them", () => {
    const m = buildAlertEmail({ monitor: { name: "Watch example.com", intervalMs: 86400000 }, events: [certEv, dmarcEv], now: NOW });
    assert.equal(m.subject, "2 changes on example.com need attention");
    assert.ok(m.text.includes("1. Certificate for example.com expires in 9 days [High]") && m.text.includes("2. DMARC policy for example.com weakened"));
    assert.ok(!m.text.includes("Stop these alerts:"), "no stop link when none could be signed; the Deck path is still there");
    assert.ok(m.text.includes("Monitors, then Pause or Delete"));
  });
  test("the email that reaches the cap says so", () => {
    const m = buildAlertEmail({ monitor: {}, events: [certEv], sent: ALERT_EMAILS_PER_DAY, now: NOW });
    assert.ok(m.text.includes("This is alert email 5 of 5 today, the daily limit"));
    assert.ok(!buildAlertEmail({ monitor: {}, events: [certEv], sent: 4, now: NOW }).text.includes("daily limit"));
  });
  test("escapes what it shows", () => {
    const m = buildAlertEmail({ monitor: { name: "<b>x</b>" }, events: [{ ...certEv, title: "<i>t</i>", daysToExpiry: NaN }], now: NOW });
    assert.ok(!m.html.includes("<b>x</b>") && m.html.includes("&lt;b&gt;x&lt;/b&gt;"));
  });
  test("the Resend payload: digest sender, one recipient, one-click unsubscribe, idempotency key", async () => {
    const n = net();
    const r = await sendEmail(ENV, { to: ME, subject: "s", html: "<p>h</p>", text: "t", stop: "https://w.test/stop", idempotencyKey: "k1" }, n.fetch);
    assert.equal(r.ok, true);
    const e = n.emails[0];
    assert.equal(e.body.from, FROM); assert.deepEqual(e.body.to, [ME]);
    assert.equal(e.body.headers["List-Unsubscribe"], "<https://w.test/stop>");
    assert.equal(e.body.headers["List-Unsubscribe-Post"], "List-Unsubscribe=One-Click");
    assert.equal(e.headers["Idempotency-Key"], "k1");
    assert.equal((await sendEmail({}, { to: ME, subject: "s", html: "", text: "" }, n.fetch)).ok, false, "no key: a failure, not a silent skip");
  });
  test("the recipient is re-checked in Firebase Auth at send time", async () => {
    const ch = { type: "email", to: ME, uid: "u1" };
    assert.deepEqual(await recipient({}, ch, { account: async () => ({ email: "new@darknode.ai", verified: true }) }), { to: "new@darknode.ai" });
    assert.ok((await recipient({}, ch, { account: async () => null })).error);
    assert.ok((await recipient({}, ch, { account: async () => ({ email: ME, verified: false }) })).error);
    assert.ok((await recipient({}, ch, { account: async () => ({ email: ME, verified: true, disabled: true }) })).error);
    assert.ok((await recipient({}, ch, { account: async () => { throw new Error("down"); } })).error);
    assert.deepEqual(await recipient({}, ch, { account: async () => undefined }), { to: ME }, "no service account: the address verified at setup");
    assert.ok((await recipient({}, { type: "email" }, {})).error, "a channel without a verified address sends nothing");
  });
});

// ---- the DO sends it, and caps it ---------------------------------------------------------------

group("alert email/delivery", () => {
  test("a certificate run emails the watch's owner, with the stop link and Deck path", async () => {
    _resetLocalQuota();
    const { st, mon } = newDO();
    await st.storage.put("wid", "u1");
    await post(mon, watch("cert-expiry", "example.com"), { free: true });
    const n = net({ certNotAfter: day(9, NOW) });
    const r = await mon.runDue(quick(n, { now: NOW }));
    assert.equal(r.ran[0].delivered, 1);
    assert.equal(n.emails.length, 1);
    const e = n.emails[0].body;
    assert.deepEqual(e.to, [ME]);
    assert.equal(e.subject, "Certificate for example.com expires in 9 days");
    assert.ok(e.text.includes("/api/watch/stop?w=u1&u=u1&t=") && e.headers["List-Unsubscribe-Post"]);
    const d = st._map.get("deliveries")[0];
    assert.equal(d.type, "email"); assert.equal(d.ok, true); assert.equal(d.to, "t***@darknode.ai");
  });
  test("a DMARC weakening between runs is named: from reject to none", async () => {
    _resetLocalQuota();
    const { st, mon } = newDO();
    await post(mon, watch("email-posture", "example.com"), { free: true });
    const zone = { "TXT example.com": ["v=spf1 mx -all"], "TXT _dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:d@example.com"], "MX example.com": ["10 mx.example.net."], "CAA example.com": ['0 issue "ca.example.net"'] };
    const a = net({ zone });
    await mon.runDue(quick(a, { now: NOW }));
    assert.equal(a.emails.length, 0, "a healthy baseline sends nothing");
    zone["TXT _dmarc.example.com"] = ["v=DMARC1; p=none; rua=mailto:d@example.com"];
    const b = net({ zone });
    await mon.runDue(quick(b, { now: NOW + 86400000 }));
    assert.equal(b.emails.length, 1);
    assert.equal(b.emails[0].body.subject, "DMARC policy for example.com weakened from reject to none");
    assert.ok(b.emails[0].body.text.includes("Fix: Set the policy in the TXT record at _dmarc.example.com back to p=reject."));
    assert.equal(st._map.get("monitors")[Object.keys(st._map.get("monitors"))[0]].posture["example.com"].dmarc, "none");
  });
  test("the daily cap: 5 emails, then each further alert is logged as failed, not sent", async () => {
    _resetLocalQuota();
    const { st, mon } = newDO();
    await st.storage.put("wid", "u1");
    const n = net(); const realFetch = globalThis.fetch; globalThis.fetch = n.fetch;
    try {
      const out = [];
      for (let i = 0; i < ALERT_EMAILS_PER_DAY + 2; i++) out.push((await post(mon, { op: "test", channel: { type: "email", to: "someone@example.org" } }, { free: true })).json);
      assert.equal(n.emails.length, ALERT_EMAILS_PER_DAY, "only 5 sent");
      assert.ok(n.emails.every((e) => e.body.to[0] === ME), "always the account's own address, never the one in the request");
      assert.ok(n.emails[ALERT_EMAILS_PER_DAY - 1].body.text.includes("counts as 5 of 5 today"));
      assert.equal(out[ALERT_EMAILS_PER_DAY].ok, false); assert.equal(out[ALERT_EMAILS_PER_DAY].status, 429);
      assert.ok(/Daily alert email limit/.test(out[ALERT_EMAILS_PER_DAY].error));
      const log = st._map.get("deliveries");
      assert.equal(log[0].ok, false); assert.ok(/limit/.test(log[0].error), "the capped alert is in the delivery log as failed");
    } finally { globalThis.fetch = realFetch; }
  });
  test("a send that fails every attempt is logged as failed and does not use up the cap", async () => {
    _resetLocalQuota();
    const { st, mon } = newDO();
    await post(mon, watch("cert-expiry", "example.com"), { free: true });
    const bad = net({ certNotAfter: day(5, NOW), resendStatus: 422 });
    const r = await mon.runDue(quick(bad, { now: NOW }));
    assert.equal(r.ran[0].delivered, 0);
    assert.equal(bad.emails.length, 3, "three attempts");
    const log = st._map.get("deliveries");
    assert.equal(log.length, 3); assert.ok(log.every((d) => !d.ok && /Email provider error/.test(d.error)));
    const quota = []; // the next alert still gets a slot
    const { mon: m2 } = newDO();
    await post(m2, watch("cert-expiry", "example.com"), { free: true });
    await m2.runDue(quick(net({ certNotAfter: day(5, NOW) }), { now: NOW, emailQuota: async (k, l, at, refund) => { quota.push(refund); return { ok: true, used: 1, limit: l }; } }));
    assert.deepEqual(quota, [false], "a delivered email is charged once and not refunded");
  });
  test("a Free test of a webhook channel is refused; an email test needs a verified address", async () => {
    const { mon } = newDO();
    assert.equal((await post(mon, { op: "test", channel: { type: "webhook", url: "https://hooks.example.com/x" } }, { free: true })).status, 402);
    assert.equal((await post(mon, { op: "test", channel: { type: "email" } }, { free: true, email: "" })).status, 400);
  });
  test("the test email says it is a test", () => {
    const t = buildTestEmail({ sent: 1, now: NOW });
    assert.equal(t.subject, "Darknode alert email test");
    assert.ok(t.text.includes("This is a test"));
  });
});

// ---- the stop link ------------------------------------------------------------------------------

group("alert email/stop link", () => {
  const setup = async () => {
    const { st, mon } = newDO();
    await post(mon, watch("cert-expiry", "example.com"), { free: true });
    await post(mon, watch("email-posture", "example.com"), { free: true });
    await post(mon, { op: "upsert", monitor: { type: "cert-expiry", config: { domains: ["example.org"] }, channels: [{ type: "webhook", url: "https://hooks.example.com/x" }] } });
    const env = { ...ENV, MONITOR: { idFromName: (x) => x, get: () => ({ fetch: (u, init) => mon.fetch(new Request("https://monitor/", init)) }) } };
    const t = await stopToken("u1", "u1", ENV.DIGEST_SECRET);
    return { st, env, url: "https://w.test/api/watch/stop?w=u1&u=u1&t=" + t };
  };
  const paused = (st) => Object.values(st._map.get("monitors")).map((m) => !!m.paused);
  test("GET only shows a confirm page (a link scanner stops nothing)", async () => {
    const { st, env, url } = await setup();
    const res = await handleWatchStop(new Request(url), env);
    const html = await res.text();
    assert.ok(html.includes('<form method="post"') && html.includes("Stop alert emails"));
    assert.ok(!/<script/i.test(html) && /default-src 'none'/.test(res.headers.get("content-security-policy")));
    assert.deepEqual(paused(st), [false, false, false]);
  });
  test("POST (the button, or List-Unsubscribe one-click) pauses only the monitors that email that account", async () => {
    const { st, env, url } = await setup();
    const res = await handleWatchStop(new Request(url, { method: "POST", body: "List-Unsubscribe=One-Click" }), env);
    assert.ok((await res.text()).includes("Alert emails stopped"));
    assert.deepEqual(paused(st), [true, true, false], "the webhook monitor keeps running");
  });
  test("a wrong or altered token changes nothing", async () => {
    const { st, env, url } = await setup();
    for (const u of [url.replace(/t=[^&]+/, "t=forged"), url.replace("u=u1", "u=u2"), url.replace("w=u1", "w=u2")]) {
      const html = await (await handleWatchStop(new Request(u, { method: "POST" }), env)).text();
      assert.ok(html.includes("Link not valid"));
    }
    assert.deepEqual(paused(st), [false, false, false]);
    assert.equal(await stopToken("u1", "u1", ""), "", "no secret: no link is made");
  });
  test("the stop op cannot be reached through the Deck API", async () => {
    const { st } = await setup();
    const { mon } = newDO();
    const r = await post(mon, { op: "stopEmail", uid: "u1" });
    assert.equal(r.status, 400);
    assert.deepEqual(paused(st), [false, false, false]);
  });
});
