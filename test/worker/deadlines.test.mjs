// Deadlines (public/js/core/deadlines.js) and their place in the MonitorDO: the clock maths, the
// opt-ins, which KEV matches start a Cyber Resilience Act clock, the alert schedule and its email
// allowance, and the early-warning facts. In-memory storage, a fake network, no real sleeps;
// nothing here reaches Resend, Firebase or CISA.
import { test, group, assert } from "../harness.mjs";
import {
  CRA, HOUR, DAY, craClocks, kevDueAt, quarterAt, stateOf, fmtLeft, sortDeadlines, normSettings, checkSettings,
  craApplies, parseMemberStates, shippedMatches, kevDeadlines, certDeadlines, closeDeadline, reopenDeadline,
  updateCase, syncCaseClocks, craCase, craDeadlines, dueAlerts, nextAlertAt, craFacts, stepsOf, sourceOf, alertLine,
} from "../../public/js/core/deadlines.js";
import { MonitorDO, handleMonitor } from "../../worker/monitor.js";
import { buildDeadlineEmail, CRA_EMAILS_PER_DAY, ALERT_EMAILS_PER_DAY } from "../../worker/alert-email.js";
import { attachPrincipal } from "../../worker/auth.js";
import { _resetPlanCache } from "../../worker/plan.js";

const NOW = Date.UTC(2026, 10, 25, 9, 30);
const ME = "test@darknode.ai";
const LOG4J = "CVE-2021-44228", CITRIX = "CVE-2023-4966";

// a workspace graph: a CycloneDX finding for log4j-core (shipped) and a scanner finding on a web host (not shipped)
const INVENTORY = {
  entities: [
    { id: "f1", type: "FINDING", name: LOG4J + " — Remote code execution in log4j-core", source: "ingest:cyclonedx", data: { assets: ["log4j-core@2.14.1"] } },
    { id: "a1", type: "ASSET", name: "log4j-core@2.14.1", source: "ingest:cyclonedx", data: {} },
    { id: "f2", type: "FINDING", name: CITRIX + " — Information disclosure", source: "ingest:nessus", data: {} },
    { id: "a2", type: "ASSET", name: "web-01.test.darknode.ai", source: "ingest:nessus", data: {} },
  ],
  relationships: [{ id: "r1", fromId: "f1", toId: "a1", type: "affects" }, { id: "r2", fromId: "f2", toId: "a2", type: "affects" }],
};
const SHIPPED = [{ id: "a1", type: "ASSET", name: "log4j-core@2.14.1" }];
const kevFinding = (cve, extra = {}) => ({ key: "kev:" + cve, severity: "critical", status: "open", cve, kev: true, dueDate: "2021-12-24", dateAdded: "2021-12-10", ...extra });
const kevEvent = (cve) => ({ kind: "kev", key: "kev:" + cve, severity: "critical" });

group("deadlines/clock maths", () => {
  test("CRA clocks: 24 h and 72 h from becoming aware, 14 days from the fix", () => {
    const k = craClocks({ awareAt: NOW, fixAt: null });
    assert.equal(k.early, NOW + 24 * HOUR);
    assert.equal(k.notify, NOW + 72 * HOUR);
    assert.equal(k.final, null, "the final report clock waits for the fix");
    assert.equal(craClocks({ awareAt: NOW, fixAt: NOW + 5 * DAY }).final, NOW + 19 * DAY);
    assert.equal(CRA.appliesFrom, Date.UTC(2026, 8, 11), "Article 14 applies from 11 September 2026");
  });
  test("a KEV due date ends at the end of that day, UTC", () => {
    assert.equal(kevDueAt("2026-12-01"), Date.UTC(2026, 11, 1, 23, 59, 59));
    assert.equal(kevDueAt(""), null); assert.equal(kevDueAt("12/01/2026"), null);
  });
  test("the quarter-left point, states and time left", () => {
    const d = { status: "open", startedAt: NOW, dueAt: NOW + 24 * HOUR };
    assert.equal(quarterAt(d), NOW + 18 * HOUR);
    assert.equal(quarterAt({ startedAt: NOW, dueAt: NOW - 1 }), null, "already due when it started: no quarter point");
    assert.equal(quarterAt({ startedAt: null, dueAt: null }), null);
    assert.equal(stateOf(d, NOW), "open"); assert.equal(stateOf(d, NOW + 25 * HOUR), "overdue");
    assert.equal(stateOf({ status: "open", dueAt: null }, NOW), "waiting");
    assert.equal(stateOf({ ...d, status: "dismissed" }, NOW), "dismissed");
    assert.equal(fmtLeft(2 * DAY + 4 * HOUR + 59000), "2d 4h left");
    assert.equal(fmtLeft(5 * HOUR + 12 * 60000), "5h 12m left");
    assert.equal(fmtLeft(-(3 * HOUR + 5 * 60000)), "overdue by 3h 5m");
    assert.equal(fmtLeft(-1000), "overdue by 1m", "a second overdue is never shown as 0m");
  });
  test("soonest first, overdue included; waiting clocks next; closed last", () => {
    const L = [
      { id: "closed", status: "done", dueAt: NOW + HOUR, closedAt: NOW },
      { id: "later", status: "open", dueAt: NOW + 3 * DAY },
      { id: "waiting", status: "open", dueAt: null, createdAt: NOW },
      { id: "overdue", status: "open", dueAt: NOW - HOUR },
      { id: "soon", status: "open", dueAt: NOW + HOUR },
    ];
    assert.deepEqual(sortDeadlines(L, NOW).map((d) => d.id), ["overdue", "soon", "later", "waiting", "closed"]);
  });
});

group("deadlines/opt-ins", () => {
  test("nothing is assumed: both opt-ins are off by default", () => {
    assert.deepEqual(normSettings(undefined), { cra: false, bod2201: false, shipped: [] });
    assert.deepEqual(normSettings({ cra: "yes", bod2201: 1 }), { cra: false, bod2201: false, shipped: [] }, "only a real true turns one on");
  });
  test("below Pro an opt-in cannot be turned on, but can be turned off", () => {
    const r = checkSettings({ cra: true }, { free: true });
    assert.ok(r.error && r.plan);
    assert.ok(checkSettings({ bod2201: true }, { free: true }).plan);
    assert.deepEqual(checkSettings({ cra: false, shipped: SHIPPED }, { free: true }).settings.shipped, SHIPPED);
    assert.equal(checkSettings({ cra: true }, { free: false }).settings.cra, true);
    assert.ok(checkSettings({ shipped: "a1" }).error);
  });
  test("CRA clocks start only with the opt-in and after Article 14 applies", () => {
    assert.equal(craApplies({ cra: true }, NOW), true);
    assert.equal(craApplies({ cra: false }, NOW), false);
    assert.equal(craApplies({ cra: true }, Date.UTC(2026, 8, 10, 23)), false, "10 September 2026: not yet");
  });
  test("Member States: names or EU codes, Greece as EL or GR, anything else refused", () => {
    assert.deepEqual(parseMemberStates("DE, fr, Greece, GR"), { codes: ["DE", "FR", "EL"], bad: [] });
    assert.deepEqual(parseMemberStates("NL; Norway").bad, ["Norway"]);
  });
});

group("deadlines/created from a KEV event, only for shipped assets", () => {
  const run = (over = {}) => kevDeadlines({ events: [kevEvent(LOG4J), kevEvent(CITRIX)], findings: [kevFinding(LOG4J), kevFinding(CITRIX)], settings: { cra: true, shipped: SHIPPED }, inventory: INVENTORY, at: NOW, monitorId: "m1", ...over });
  test("the shipped component's CVE gets a case and three clocks; the unshipped host's does not", () => {
    const r = run();
    assert.equal(r.cases.length, 1);
    assert.equal(r.cases[0].cve, LOG4J);
    assert.deepEqual(r.cases[0].assets, ["log4j-core@2.14.1"]);
    assert.equal(r.cases[0].kevDateAdded, "2021-12-10");
    assert.equal(r.cases[0].awareAt, NOW, "became aware = when Darknode alerted, until corrected");
    assert.deepEqual(r.add.map((d) => d.id), ["cra:" + LOG4J + ":early", "cra:" + LOG4J + ":notify", "cra:" + LOG4J + ":final"]);
    const [early, notify, fin] = r.add;
    assert.equal(early.dueAt, NOW + 24 * HOUR); assert.equal(notify.dueAt, NOW + 72 * HOUR); assert.equal(fin.dueAt, null);
    assert.ok(r.add.every((d) => d.kind === "cra-exploited" && d.status === "open" && d.monitorId === "m1"));
  });
  test("no opt-in, no clocks; before 11 September 2026, no clocks", () => {
    assert.deepEqual(run({ settings: { cra: false, shipped: SHIPPED } }), { add: [], cases: [] });
    assert.deepEqual(run({ at: Date.UTC(2026, 7, 1) }), { add: [], cases: [] });
  });
  test("nothing marked as shipped, no clocks; a match by name works without the graph id", () => {
    assert.equal(run({ settings: { cra: true, shipped: [] } }).add.length, 0);
    assert.equal(run({ settings: { cra: true, shipped: [{ name: "LOG4J-CORE@2.14.1" }] } }).cases.length, 1);
    assert.equal(run({ settings: { cra: true, shipped: [{ type: "SOFTWARE", name: "log4j-core@2.14.1" }] } }).cases.length, 1, "the finding's affected-asset list has no type, so the name decides");
  });
  test("only a kev event starts it: a finding without an event, or an EPSS-only match, does not", () => {
    assert.equal(run({ events: [] }).add.length, 0);
    const epss = { key: "epss:" + LOG4J, cve: LOG4J, kev: false, epss: 0.97 };
    assert.equal(run({ events: [{ kind: "kev", key: epss.key }], findings: [epss] }).add.length, 0);
    assert.equal(run({ events: [{ kind: "new", key: "kev:" + LOG4J }] }).add.length, 0, "only the kev kind");
  });
  test("an existing case is never re-created, whatever its status", () => {
    assert.equal(run({ cases: { [LOG4J]: { cve: LOG4J } } }).add.length, 0);
  });
  test("BOD 22-01 opt-in: a kev-due deadline for every matched KEV CVE, due on the catalogue date", () => {
    const r = run({ settings: { bod2201: true } });
    assert.deepEqual(r.add.map((d) => d.id), ["kev-due:" + LOG4J, "kev-due:" + CITRIX]);
    assert.equal(r.add[0].dueAt, Date.UTC(2021, 11, 24, 23, 59, 59));
    assert.equal(r.cases.length, 0, "BOD alone starts no CRA clock");
    assert.equal(run({ settings: { bod2201: true }, existing: { ["kev-due:" + LOG4J]: {} } }).add.length, 1);
  });
  test("shippedMatches follows relationships both ways and a finding's affected assets", () => {
    assert.deepEqual(shippedMatches(LOG4J, INVENTORY, SHIPPED), SHIPPED);
    assert.deepEqual(shippedMatches(CITRIX, INVENTORY, SHIPPED), []);
    const reverse = { entities: INVENTORY.entities, relationships: [{ fromId: "a1", toId: "f1", type: "related_to" }] };
    assert.deepEqual(shippedMatches(LOG4J, { ...reverse, entities: reverse.entities.map((e) => (e.id === "f1" ? { ...e, data: {} } : e)) }, SHIPPED), SHIPPED);
    assert.deepEqual(shippedMatches("not a cve", INVENTORY, SHIPPED), []);
  });
});

group("deadlines/certificates", () => {
  const f = (domain, notAfter) => ({ key: "cert:" + domain, domain, notAfter, daysToExpiry: 10 });
  test("due when the certificate expires; started when the monitor first saw it; the monitor's alert is the created alert", () => {
    const na = new Date(NOW + 10 * DAY).toISOString();
    const r = certDeadlines({ findings: [f("example.com", na)], monitorId: "m1", firstSeen: { "cert:example.com": NOW - DAY }, alerted: new Set(["cert:example.com"]), at: NOW });
    assert.equal(r.add.length, 1);
    const d = r.add[0];
    assert.equal(d.id, "cert:example.com:" + na.slice(0, 10));
    assert.equal(d.dueAt, Date.parse(na)); assert.equal(d.startedAt, NOW - DAY);
    assert.deepEqual(d.alerts.created, { at: NOW, via: "monitor", sent: true });
    assert.deepEqual(dueAlerts([d], NOW), [], "no second created alert");
  });
  test("closes as done when the monitor no longer sees it, or when the domain leaves the watch", () => {
    const d = { id: "cert:example.com:2026-12-05", kind: "cert-expiry", status: "open", monitorId: "m1", subject: { value: "example.com" } };
    assert.equal(certDeadlines({ findings: [], existing: { [d.id]: d }, monitorId: "m1", watched: new Set(["example.com"]), at: NOW }).close[0].status, "done");
    assert.ok(/no longer in this watch/.test(certDeadlines({ findings: [], existing: { [d.id]: d }, monitorId: "m1", watched: new Set(), at: NOW }).close[0].reason));
    assert.equal(certDeadlines({ findings: [], existing: { [d.id]: d }, monitorId: "other", at: NOW }).close.length, 0, "another monitor's run leaves it alone");
  });
});

group("deadlines/alert schedule", () => {
  const d0 = (over = {}) => ({ id: "x", status: "open", startedAt: NOW, dueAt: NOW + 24 * HOUR, alerts: {}, ...over });
  test("created once the clock starts, then once when a quarter of the time is left", () => {
    assert.deepEqual(dueAlerts([d0()], NOW), [{ id: "x", stage: "created" }]);
    const sent = d0({ alerts: { created: { at: NOW } } });
    assert.deepEqual(dueAlerts([sent], NOW + 17 * HOUR), []);
    assert.deepEqual(dueAlerts([sent], NOW + 18 * HOUR), [{ id: "x", stage: "quarter" }]);
    assert.deepEqual(dueAlerts([d0({ alerts: { created: { at: NOW }, quarter: { at: NOW } } })], NOW + 20 * HOUR), []);
    assert.equal(nextAlertAt([sent], NOW), NOW + 18 * HOUR);
  });
  test("a quarter point already past its deadline is skipped; closed and waiting clocks are silent", () => {
    assert.deepEqual(dueAlerts([d0({ alerts: { created: { at: NOW } } })], NOW + 25 * HOUR), [{ id: "x", stage: "skip" }]);
    assert.deepEqual(dueAlerts([d0({ status: "done" }), d0({ dueAt: null })], NOW), []);
    assert.equal(nextAlertAt([d0({ status: "dismissed" })], NOW), null);
  });
  test("an alert held by quiet hours waits until they end", () => {
    const held = d0({ alerts: { holdUntil: NOW + 3 * HOUR } });
    assert.deepEqual(dueAlerts([held], NOW), []);
    assert.equal(nextAlertAt([held], NOW), NOW + 3 * HOUR);
    assert.deepEqual(dueAlerts([held], NOW + 3 * HOUR), [{ id: "x", stage: "created" }]);
  });
  test("alert lines quote Article 14(2) for CRA clocks and say how long is left", () => {
    const [early] = craDeadlines(craCase({ cve: LOG4J, assets: SHIPPED, kevDateAdded: "2021-12-10", alertedAt: NOW, monitorId: "m1" }), NOW);
    const l = alertLine(early, "quarter", NOW + 18 * HOUR);
    assert.ok(l.title.startsWith("CRA early warning: " + LOG4J));
    assert.ok(l.detail.includes("6h 0m left") && l.detail.includes("within 24 hours"));
    assert.ok(stepsOf(early).some((s) => /ENISA/.test(s)));
    assert.equal(sourceOf(early).url, "https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng");
  });
});

group("deadlines/edits and facts", () => {
  const c0 = () => craCase({ cve: LOG4J, assets: SHIPPED, kevDateAdded: "2021-12-10", alertedAt: NOW, monitorId: "m1" });
  test("correcting the became-aware time moves the 24 h and 72 h clocks; marking the fix starts the final one", () => {
    const c = c0(), existing = Object.fromEntries(craDeadlines(c, NOW).map((d) => [d.id, d]));
    const r = updateCase(c, { awareAt: NOW - 6 * HOUR }, NOW);
    const moved = syncCaseClocks(r.case, existing);
    assert.deepEqual(moved.map((d) => [d.clock, d.dueAt]), [["early", NOW + 18 * HOUR], ["notify", NOW + 66 * HOUR]]);
    const fix = syncCaseClocks(updateCase(r.case, { fixAt: NOW }, NOW).case, existing);
    assert.deepEqual(fix.map((d) => d.clock), ["early", "notify", "final"]);
    assert.equal(fix[2].startedAt, NOW); assert.equal(fix[2].dueAt, NOW + 14 * DAY);
  });
  test("case edits are checked: no future times, a known Member State, a bounded text", () => {
    assert.ok(updateCase(c0(), { awareAt: NOW + HOUR }, NOW).error);
    assert.ok(updateCase(c0(), { awareAt: NOW - 400 * DAY }, NOW).error);
    assert.ok(updateCase(c0(), { fixAt: NOW + DAY }, NOW).error);
    assert.ok(updateCase(c0(), { memberStates: "DE, Atlantis" }, NOW).error.includes("Atlantis"));
    assert.ok(updateCase(c0(), { measures: "x".repeat(2001) }, NOW).error);
    assert.equal(updateCase(c0(), { fixAt: null }, NOW).case.fixAt, null);
  });
  test("done or dismissed needs a reason; reopening clears it", () => {
    const d = { id: "x", status: "open" };
    assert.ok(closeDeadline(d, { status: "done", reason: "  ", at: NOW }).error);
    assert.ok(closeDeadline(d, { status: "closed", reason: "x", at: NOW }).error);
    const r = closeDeadline(d, { status: "dismissed", reason: "Not in the EU build", by: "u1", at: NOW });
    assert.deepEqual([r.deadline.status, r.deadline.reason, r.deadline.closedBy], ["dismissed", "Not in the EU build", "u1"]);
    assert.equal(reopenDeadline(r.deadline).deadline.status, "open");
  });
  test("the early-warning facts list what is known and say what is not", () => {
    const c = { ...c0(), awareAt: NOW - 2 * HOUR, memberStates: ["DE", "FR"], measures: "Upgrade log4j-core to 2.17.1." };
    const f = craFacts(c, {}, NOW);
    const row = (l) => (f.rows.find((r) => r[0] === l) || [])[1];
    assert.equal(row("Vulnerability"), LOG4J);
    assert.equal(row("Product or asset"), "log4j-core@2.14.1");
    assert.ok(row("Exploitation confirmed").includes("2021-12-10"));
    assert.ok(row("Became aware").startsWith("2026-11-25 07:30 UTC") && row("Became aware").includes("Darknode alerted 2026-11-25 09:30 UTC"));
    assert.equal(row("Member States where the product is made available"), "Germany (DE), France (FR)");
    assert.equal(row("Corrective or mitigating measures known"), "Upgrade log4j-core to 2.17.1.");
    assert.equal(row("Early warning due"), "2026-11-26 07:30 UTC");
    assert.ok(row("CISA KEV catalogue").startsWith("https://www.cisa.gov/known-exploited-vulnerabilities-catalog"));
    assert.equal(row("NVD"), "https://nvd.nist.gov/vuln/detail/" + LOG4J);
    assert.ok(f.text.includes("does not submit anything"));
    const empty = craFacts(c0(), {}, NOW);
    assert.equal(empty.rows.find((r) => r[0] === "Member States where the product is made available")[1], "Not entered yet");
    assert.equal(empty.rows.find((r) => r[0] === "Fix or mitigation available")[1], "Not marked yet");
    assert.notOk(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(f.text), "no emojis");
  });
});

// ---- in the MonitorDO ---------------------------------------------------------------------------

function memState() {
  const map = new Map(); let alarm = null;
  const storage = {
    async get(k) { return map.has(k) ? map.get(k) : undefined; },
    async put(k, v) { map.set(k, v); },
    async delete(k) { map.delete(k); },
    async list({ prefix = "" } = {}) { return new Map([...map].filter(([k]) => k.startsWith(prefix))); },
    async setAlarm(ts) { alarm = ts; },
    async getAlarm() { return alarm; },
  };
  return { storage, blockConcurrencyWhile: async (fn) => fn(), _map: map, alarm: () => alarm };
}
const graphEnv = (extra = {}) => ({ RESEND_KEY: "re_test_only", DIGEST_SECRET: "unit-test-secret", ...extra, GRAPH: { idFromName: (n) => n, get: () => ({ fetch: async () => ({ ok: true, status: 200, json: async () => INVENTORY }) }) } });
async function post(mon, body, { free = false, role = "owner" } = {}) {
  const headers = { "content-type": "application/json", "x-mon-uid": "u1", "x-mon-role": role, "x-mon-wid": "u1", "x-mon-email": encodeURIComponent(ME) };
  if (free) headers["x-mon-plan"] = "free";
  const res = await mon.fetch(new Request("https://monitor/", { method: "POST", body: JSON.stringify(body), headers }));
  return { status: res.status, json: await res.json() };
}
function kevNet() {
  const hooks = [], emails = [];
  const fetch = async (url, opts = {}) => {
    url = String(url);
    if (url.includes("cisa-kev-index")) return { ok: true, status: 200, json: async () => ({ data: [{ cve: LOG4J, dueDate: "2021-12-24", dateAdded: "2021-12-10" }, { cve: CITRIX, dueDate: "2023-11-08", dateAdded: "2023-10-18" }] }) };
    if (url.includes("epss-top")) return { ok: true, status: 200, json: async () => ({ data: [] }) };
    if (url.includes("crt.sh")) return { ok: true, status: 200, json: async () => [{ issuer_name: "C=US, O=Example CA", not_after: new Date(NOW + 10 * DAY).toISOString(), not_before: new Date(NOW - 80 * DAY).toISOString(), name_value: "example.com" }] };
    if (url.includes("certspotter")) return { ok: false, status: 404, json: async () => null };
    if (url === "https://api.resend.com/emails") { emails.push(JSON.parse(opts.body)); return { ok: true, status: 200, json: async () => ({ id: "e" + emails.length }) }; }
    hooks.push({ url, body: opts.body }); return { ok: true, status: 200 };
  };
  return { fetch, hooks, emails };
}
const quick = (n, extra = {}) => ({ force: true, fetch: n.fetch, sleep: async () => {}, now: NOW, ...extra });
const kevMonitor = (channels) => ({ op: "upsert", monitor: { name: "KEV", type: "kev-epss", config: {}, channels } });

group("deadlines/MonitorDO", () => {
  test("a KEV run with the CRA opt-in stores the case and three clocks, and alerts the case once", async () => {
    const st = memState(), mon = new MonitorDO(st, graphEnv());
    assert.equal((await post(mon, { op: "dlSettings", settings: { cra: true, shipped: SHIPPED } })).status, 200);
    await post(mon, kevMonitor([{ type: "webhook", url: "https://hook.test/x" }]));
    const n = kevNet();
    const r = await mon.runDue(quick(n));
    assert.equal(r.ran[0].found, 2);
    const list = (await post(mon, { op: "deadlines" })).json;
    assert.deepEqual(list.deadlines.map((d) => d.id), ["cra:" + LOG4J + ":early", "cra:" + LOG4J + ":notify", "cra:" + LOG4J + ":final"]);
    assert.equal(list.cases.length, 1); assert.equal(list.cases[0].kevDateAdded, "2021-12-10");
    assert.equal(n.hooks.length, 2, "the monitor's KEV alert and one CRA alert for the case");
    const cra = JSON.parse(n.hooks[1].body).alert;
    assert.equal(cra.severity, "critical");
    assert.equal(cra.deadline.items.length, 2, "early warning and notification in one alert; the final clock has not started");
    assert.ok(/single reporting platform/.test(cra.text) && /does not submit anything/.test(cra.text));
    await mon.runDue(quick(n, { now: NOW + HOUR }));
    assert.equal(n.hooks.length, 2, "nothing new an hour later");
    await mon.runDue(quick(n, { now: NOW + 18 * HOUR }));
    assert.equal(n.hooks.length, 3, "18 h in: a quarter of the early warning's 24 h is left");
    assert.ok(/early warning/i.test(n.hooks[2].body));
    assert.ok(st.alarm() != null, "the next reminder is scheduled");
  });
  test("without the opt-in a KEV run starts no clock", async () => {
    const st = memState(), mon = new MonitorDO(st, graphEnv());
    await post(mon, { op: "dlSettings", settings: { cra: false, shipped: SHIPPED } });
    await post(mon, kevMonitor([{ type: "webhook", url: "https://hook.test/x" }]));
    const n = kevNet();
    await mon.runDue(quick(n));
    assert.equal((await post(mon, { op: "deadlines" })).json.deadlines.length, 0);
    assert.equal(n.hooks.length, 1, "the monitor's own alert only");
  });
  test("settings: below Pro the opt-ins cannot be turned on (402); viewers cannot change them", async () => {
    const st = memState(), mon = new MonitorDO(st, graphEnv());
    const r = await post(mon, { op: "dlSettings", settings: { cra: true } }, { free: true });
    assert.equal(r.status, 402); assert.equal(r.json.plan, true);
    assert.equal((await post(mon, { op: "dlSettings", settings: { cra: false, shipped: SHIPPED } }, { free: true })).status, 200);
    assert.equal((await post(mon, { op: "dlSettings", settings: { cra: true } }, { role: "viewer" })).status, 403);
    assert.equal((await post(mon, { op: "deadlines" }, { role: "viewer" })).status, 200, "viewers can see deadlines");
  });
  test("case edits move the clocks; done and dismiss need a reason", async () => {
    const st = memState(), mon = new MonitorDO(st, graphEnv());
    await post(mon, { op: "dlSettings", settings: { cra: true, shipped: SHIPPED } });
    await post(mon, kevMonitor([]));
    await mon.runDue(quick(kevNet()));
    const fixAt = Date.now() - HOUR;
    const r = await post(mon, { op: "dlCase", cve: LOG4J, patch: { fixAt, memberStates: "DE, FR", measures: "Upgrade to 2.17.1" } });
    assert.equal(r.status, 200);
    const fin = (await post(mon, { op: "deadlines" })).json.deadlines.find((d) => d.clock === "final");
    assert.equal(fin.dueAt, fixAt + 14 * DAY);
    assert.equal((await post(mon, { op: "dlCase", cve: LOG4J, patch: { memberStates: "Atlantis" } })).status, 400);
    assert.equal((await post(mon, { op: "dlCase", cve: "CVE-2000-0001", patch: {} })).status, 404);
    const id = "cra:" + LOG4J + ":early";
    assert.equal((await post(mon, { op: "dlClose", id, status: "done", reason: "" })).status, 400);
    const done = await post(mon, { op: "dlClose", id, status: "done", reason: "Submitted, reference ENISA-123" });
    assert.equal(done.json.deadline.status, "done"); assert.equal(done.json.deadline.closedBy, "u1");
    assert.equal((await post(mon, { op: "dlReopen", id })).json.deadline.status, "open");
  });
  test("cap: CRA alerts use their own allowance, so a used-up monitor allowance does not hold them back", async () => {
    const st = memState(), mon = new MonitorDO(st, graphEnv());
    await post(mon, { op: "dlSettings", settings: { cra: true, shipped: SHIPPED } });
    await post(mon, kevMonitor([{ type: "email" }]));
    const n = kevNet(), keys = [];
    const emailQuota = async (key, limit) => { keys.push([key, limit]); return key.startsWith("alert-email:") ? { ok: false, used: limit, limit } : { ok: true, used: 1, limit }; };
    await mon.runDue(quick(n, { emailQuota }));
    assert.deepEqual(keys, [["alert-email:u1", ALERT_EMAILS_PER_DAY], ["deadline-email:u1", CRA_EMAILS_PER_DAY]]);
    assert.equal(n.emails.length, 1, "the CRA email went out while the monitor's own alert was capped");
    assert.ok(n.emails[0].subject.includes("CRA early warning"));
    assert.ok(n.emails[0].text.includes("single reporting platform") && n.emails[0].text.includes("does not submit anything"));
    const log = st._map.get("deliveries");
    assert.ok(log.some((d) => !d.ok && /Daily alert email limit/.test(d.error)), "the capped monitor alert is in the delivery log");
  });
  test("cap: a certificate reminder shares the monitor allowance and is logged when it is used up", async () => {
    const st = memState(), mon = new MonitorDO(st, graphEnv());
    await post(mon, { op: "upsert", monitor: { name: "Watch example.com", type: "cert-expiry", config: { domains: ["example.com"], warnDays: 21 }, channels: [{ type: "email" }] } });
    const n = kevNet();
    await mon.runDue(quick(n, { emailQuota: async (k, l) => ({ ok: true, used: 1, limit: l }) }));
    assert.equal(n.emails.length, 1, "the monitor's alert is the deadline's created alert: one email");
    const keys = [];
    await mon.runDue(quick(n, { now: NOW + 7.6 * DAY, emailQuota: async (k, l) => { keys.push(k); return { ok: false, used: l, limit: l }; } }));
    assert.deepEqual(keys, ["alert-email:u1"]);
    assert.equal(n.emails.length, 1);
    const dl = (await post(mon, { op: "deadlines" })).json.deadlines[0];
    assert.equal(dl.alerts.quarter.sent, false, "tried once, not retried every alarm");
  });
  test("deleting a monitor dismisses its open certificate deadlines", async () => {
    const st = memState(), mon = new MonitorDO(st, graphEnv());
    const m = (await post(mon, { op: "upsert", monitor: { name: "C", type: "cert-expiry", config: { domains: ["example.com"] }, channels: [] } })).json.monitor;
    await mon.runDue(quick(kevNet()));
    assert.equal((await post(mon, { op: "deadlines" })).json.deadlines[0].status, "open");
    await post(mon, { op: "delete", id: m.id });
    const d = (await post(mon, { op: "deadlines" })).json.deadlines[0];
    assert.equal(d.status, "dismissed"); assert.ok(/monitor was deleted/.test(d.reason));
  });
});

group("deadlines/route and email", () => {
  test("deadline settings below Pro go on marked free (the DO refuses only turning an opt-in on)", async () => {
    const calls = [];
    const MONITOR = { idFromName: (x) => x, get: () => ({ fetch: async (u, init) => { calls.push(init); return new Response("{}", { status: 200 }); } }) };
    const real = globalThis.fetch; globalThis.fetch = async () => ({ ok: false, status: 404, json: async () => ({}) });
    try {
      for (const claims of [{ email_verified: true }, { email_verified: true, plan: "pro" }]) {
        _resetPlanCache();
        const req = new Request("https://w.test/x", { method: "POST", body: JSON.stringify({ op: "dlSettings", settings: { cra: true } }) });
        attachPrincipal(req, { kind: "user", uid: "u1", email: ME, token: "tok", claims });
        await handleMonitor(req, { FIREBASE_PROJECT_ID: "p1", MONITOR }, "u1", (b, status = 200) => ({ status, body: b }));
      }
    } finally { globalThis.fetch = real; }
    assert.equal(calls[0].headers["x-mon-plan"], "free");
    assert.equal(calls[1].headers["x-mon-plan"], undefined);
  });
  test("the deadline email: what is due, where to file, the disclaimer, no emojis", () => {
    const [early] = craDeadlines(craCase({ cve: LOG4J, assets: SHIPPED, kevDateAdded: "2021-12-10", alertedAt: NOW, monitorId: "m1" }), NOW);
    const m = buildDeadlineEmail({ items: [{ ...alertLine(early, "created", NOW), kind: early.kind, stage: "created" }], cra: true, monitor: { name: "KEV" }, notes: [CRA.where], sent: 1, limit: CRA_EMAILS_PER_DAY, now: NOW });
    assert.ok(m.subject.startsWith("New deadline: CRA early warning: " + LOG4J));
    assert.ok(m.text.includes("Due 2026-11-26 09:30 UTC (1d 0h left)"));
    assert.ok(m.text.includes("https://darknode.ai/deadlines") && m.html.includes("Open Deadlines in the Deck"));
    assert.notOk(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(m.subject + m.text + m.html), "no emojis");
  });
});
