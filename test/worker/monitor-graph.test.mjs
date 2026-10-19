// Unit tests for worker/monitor-graph.js — mapping monitor findings into Security Graph
// entities with deterministic ids and content-stable timestamps (Trident Phase 2).
import { test, group, assert } from "../harness.mjs";
import { monitorFindingToCommon, buildGraphWrite, entId } from "../../worker/monitor-graph.js";

const T0 = Date.UTC(2026, 0, 1);
const DAY = 86400000;
const iso = (ms) => new Date(ms).toISOString();

const certF = (over = {}) => ({ key: "cert:x.test.darknode.ai", severity: "high", status: "open", title: "Certificate for x.test.darknode.ai expires in 9 days", domain: "x.test.darknode.ai", daysToExpiry: 9, issuer: "Lets Encrypt", notAfter: iso(T0 + 9 * DAY), category: "certificate", tool: "monitor:cert-expiry", ...over });
const kevF = (over = {}) => ({ key: "kev:CVE-2021-44228", severity: "critical", status: "open", title: "Known-exploited vulnerability in your inventory: CVE-2021-44228", cve: "CVE-2021-44228", kev: true, dueDate: "2021-12-24", epss: 0.97, category: "vulnerability", tool: "monitor:kev-epss", ...over });

const findOne = (entities, type) => entities.filter((e) => e.type === type);

group("monitor-graph: monitorFindingToCommon", () => {
  test("cert finding maps to a stable-titled FINDING with a DOMAIN asset", () => {
    const c = monitorFindingToCommon(certF(), "open");
    assert.equal(c.id, "cert:x.test.darknode.ai");                 // pins findingKey across runs
    assert.equal(c.title, "Certificate expiring: x.test.darknode.ai"); // stable (no drifting day count)
    assert.equal(c.category, "certificate");
    assert.deepEqual(c.assets, [{ type: "DOMAIN", name: "x.test.darknode.ai" }]);
    assert.equal(c.status, "open");
  });
  test("KEV finding carries a VULNERABILITY asset and the CISA BOD 22-01 control; EPSS has none", () => {
    const kev = monitorFindingToCommon(kevF(), "open");
    assert.deepEqual(kev.assets, [{ type: "VULNERABILITY", name: "CVE-2021-44228" }]);
    assert.deepEqual(kev.controls, [{ framework: "CISA", id: "BOD 22-01" }]);
    const epss = monitorFindingToCommon(kevF({ key: "epss:CVE-2020-0001", cve: "CVE-2020-0001", kev: false, epss: 0.8 }), "open");
    assert.deepEqual(epss.controls, []);
    assert.ok(epss.title.includes("High exploit-likelihood"));
  });
  test("a resolved mapping carries the resolution", () => {
    const c = monitorFindingToCommon(certF(), "resolved", "fixed");
    assert.equal(c.status, "resolved");
    assert.equal(c.resolution, "fixed");
  });
  test("an unknown check type falls back generically with no invented assets", () => {
    const g = monitorFindingToCommon({ key: "x:1", severity: "low", title: "Weird", detail: "d", foo: 1 }, "open");
    assert.equal(g.title, "Weird");
    assert.ok(!g.assets || g.assets.length === 0);
  });
});

group("monitor-graph: buildGraphWrite", () => {
  const meta = { "cert:x.test.darknode.ai": { firstSeen: T0, changedAt: T0 + DAY } };

  test("a cert finding yields a FINDING + DOMAIN and an affects relationship", () => {
    const { entities, relationships } = buildGraphWrite("m1", "Certs", [certF()], [], meta, T0 + 2 * DAY);
    const f = findOne(entities, "FINDING")[0], d = findOne(entities, "DOMAIN")[0];
    assert.ok(f && d);
    assert.equal(f.source, "monitor:m1");
    assert.equal(f.severity, "high");
    assert.equal(f.status, "open");
    assert.equal(f.createdAt, iso(T0), "createdAt is first-seen, not now");
    assert.equal(f.updatedAt, iso(T0 + DAY), "updatedAt is changed-at, not now");
    assert.equal(d.name, "x.test.darknode.ai");
    assert.equal(relationships.length, 1);
    assert.equal(relationships[0].type, "affects");
    assert.equal(relationships[0].fromId, f.id);
    assert.equal(relationships[0].toId, d.id);
    assert.equal(relationships[0].createdAt, f.createdAt, "rel createdAt tracks the finding (stable → no churn)");
    assert.equal(d.id, entId("DOMAIN", "x.test.darknode.ai"));
  });

  test("the write is byte-identical on an unchanged re-run (DO treats it as a tie)", () => {
    const a = buildGraphWrite("m1", "Certs", [certF()], [], meta, T0 + 2 * DAY);
    const b = buildGraphWrite("m1", "Certs", [certF()], [], meta, T0 + 5 * DAY); // later now, same meta
    assert.deepEqual(a, b, "same findings + same graphMeta → identical records regardless of now");
  });

  test("cold-start (no graphMeta) stamps createdAt = updatedAt = now", () => {
    const { entities } = buildGraphWrite("m1", "Certs", [certF()], [], {}, T0 + 2 * DAY);
    const f = findOne(entities, "FINDING")[0];
    assert.equal(f.createdAt, iso(T0 + 2 * DAY));
    assert.equal(f.updatedAt, iso(T0 + 2 * DAY));
  });

  test("a changed finding advances updatedAt but keeps createdAt", () => {
    const m2 = { "cert:x.test.darknode.ai": { firstSeen: T0, changedAt: T0 + 3 * DAY } };
    const f = findOne(buildGraphWrite("m1", "Certs", [certF()], [], m2, T0 + 4 * DAY).entities, "FINDING")[0];
    assert.equal(f.createdAt, iso(T0));
    assert.equal(f.updatedAt, iso(T0 + 3 * DAY));
  });

  test("a finding's day-count change does NOT churn its DOMAIN asset (updatedAt pinned to first-seen)", () => {
    // The cert finding changed (changedAt advanced), but the DOMAIN it affects has fixed content,
    // so its updatedAt must stay = createdAt = first-seen — a tie at the DO, no daily rewrite.
    const m2 = { "cert:x.test.darknode.ai": { firstSeen: T0, changedAt: T0 + 3 * DAY } };
    const d = findOne(buildGraphWrite("m1", "Certs", [certF()], [], m2, T0 + 4 * DAY).entities, "DOMAIN")[0];
    assert.equal(d.createdAt, iso(T0), "asset first-seen preserved");
    assert.equal(d.updatedAt, d.createdAt, "asset updatedAt pinned to first-seen (content-stable)");
  });

  test("a removed finding's resolved record strictly wins: updatedAt advances to the run clock", () => {
    // The MonitorDO bumps changedAt = now for removed findings; here we model that and confirm the
    // resolved record carries the later updatedAt (so GraphDO.wins() applies it, not a tie).
    const m2 = { "cert:x.test.darknode.ai": { firstSeen: T0, changedAt: T0 + 5 * DAY } };
    const f = findOne(buildGraphWrite("m1", "Certs", [], [certF()], m2, T0 + 5 * DAY).entities, "FINDING")[0];
    assert.equal(f.status, "resolved");
    assert.equal(f.data.resolution, "fixed");
    assert.equal(f.createdAt, iso(T0), "SLA createdAt preserved on resolve");
    assert.equal(f.updatedAt, iso(T0 + 5 * DAY), "updatedAt advanced so the resolve wins the merge");
  });

  test("a removed finding is written resolved + fixed", () => {
    const { entities } = buildGraphWrite("m1", "Certs", [], [certF()], meta, T0 + 2 * DAY);
    const f = findOne(entities, "FINDING")[0];
    assert.equal(f.status, "resolved");
    assert.equal(f.data.resolution, "fixed");
  });

  test("KEV finding yields FINDING + VULNERABILITY + CONTROL with related_to and mitigates links", () => {
    const km = { "kev:CVE-2021-44228": { firstSeen: T0, changedAt: T0 } };
    const { entities, relationships } = buildGraphWrite("m2", "KEV", [kevF()], [], km, T0);
    assert.ok(findOne(entities, "VULNERABILITY")[0]);
    assert.ok(findOne(entities, "CONTROL")[0]);
    const rels = relationships.map((r) => r.type).sort();
    assert.deepEqual(rels, ["mitigates", "related_to"], "FINDING->VULNERABILITY is related_to (not affects); CONTROL mitigates FINDING");
  });

  test("deterministic ids: same logical entity → same id across builds", () => {
    const a = buildGraphWrite("m1", "Certs", [certF()], [], meta, T0);
    const b = buildGraphWrite("m1", "Certs", [certF()], [], meta, T0);
    assert.deepEqual(a.entities.map((e) => e.id), b.entities.map((e) => e.id));
  });
});
