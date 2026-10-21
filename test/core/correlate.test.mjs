// Unit tests for public/js/core/correlate.js — the cross-tool correlation engine.
import { test, group, assert } from "../harness.mjs";
import { correlate, RULES, materializeIncidents, incidentId } from "../../public/js/core/correlate.js";

const DAY = 86400000;
const NOW = Date.parse("2026-10-17T00:00:00Z");
const day = (n) => new Date(NOW - n * DAY).toISOString();

// entity builders
const A = (name) => ({ id: "a:" + name, type: "ASSET", name, data: {}, source: "inv" });
const I = (name) => ({ id: "i:" + name, type: "IDENTITY", name, data: {}, source: "inv" });
// finding: carries source, data.category, data.assets (array of names), severity, updatedAt
let n = 0;
const F = (source, category, assets, sev = "high", opts = {}) => ({
  id: "f" + ++n, type: "FINDING", name: opts.title || `${source}/${category}`,
  severity: sev, source, tags: opts.tags || [],
  updatedAt: opts.at || day(1),
  data: { tool: source, category, assets: Array.isArray(assets) ? assets : [assets] },
});

const ids = (hits) => hits.map((h) => h.ruleId).sort();

group("correlate/account-takeover", () => {
  test("weak MFA + impossible travel on the same identity fires", () => {
    const hits = correlate([
      I("jane@corp.com"),
      F("caaudit", "mfa", "jane@corp.com"),
      F("vpnaudit", "impossible_travel", "jane@corp.com"),
    ]);
    const ato = hits.find((h) => h.ruleId === "account-takeover");
    assert.ok(ato, "account-takeover hit present");
    assert.equal(ato.subjectType, "identity");
    assert.equal(ato.subjectName, "jane@corp.com");
    assert.equal(ato.legs.length, 2);
    assert.ok(ato.attack.includes("T1078"));
  });

  test("only one leg present does not fire", () => {
    const hits = correlate([I("jane@corp.com"), F("caaudit", "mfa", "jane@corp.com")]);
    assert.equal(hits.length, 0);
  });

  test("legs on DIFFERENT identities do not fire", () => {
    const hits = correlate([
      I("jane@corp.com"), I("bob@corp.com"),
      F("caaudit", "mfa", "jane@corp.com"),
      F("vpnaudit", "impossible_travel", "bob@corp.com"),
    ]);
    assert.equal(hits.filter((h) => h.ruleId === "account-takeover").length, 0);
  });

  test("legs outside the time window do not fire", () => {
    const hits = correlate([
      I("jane@corp.com"),
      F("caaudit", "mfa", "jane@corp.com", "high", { at: day(1) }),
      F("vpnaudit", "impossible_travel", "jane@corp.com", "high", { at: day(200) }),
    ]);
    assert.equal(hits.filter((h) => h.ruleId === "account-takeover").length, 0);
  });

  test("leg selection is deterministic regardless of input order (newest finding wins)", () => {
    const jane = I("jane@corp.com");
    const mfa = F("caaudit", "mfa", "jane@corp.com", "high", { at: day(1) });
    const older = F("vpnaudit", "impossible_travel", "jane@corp.com", "high", { at: day(5) });
    const newer = F("vpnaudit", "impossible_travel", "jane@corp.com", "high", { at: day(2) });
    const pick = (arr) => correlate(arr).find((h) => h.ruleId === "account-takeover");
    const fwd = pick([jane, mfa, older, newer]);
    const rev = pick([newer, older, mfa, jane]);
    assert.ok(fwd && rev, "fires both ways");
    // identical leg selection no matter the order the entities arrived in
    assert.equal(JSON.stringify(fwd.legs), JSON.stringify(rev.legs));
    // and the newer of the two candidate findings is the one chosen
    assert.ok(fwd.legs.some((l) => l.findingId === newer.id), "newest matching finding is selected");
    assert.notOk(fwd.legs.some((l) => l.findingId === older.id), "older duplicate is not selected");
  });
});

group("correlate/identity rules", () => {
  test("leaver still active fires on jml leaver + vpn activity", () => {
    const hits = correlate([
      I("x@corp.com"),
      F("jml", "leaver", "x@corp.com", "medium"),
      F("vpnaudit", "large_transfer", "x@corp.com", "medium"),
    ]);
    assert.ok(hits.find((h) => h.ruleId === "leaver-active"));
  });

  test("privileged-no-mfa fires on privaudit standing-privilege + caaudit mfa", () => {
    const hits = correlate([
      I("adm@corp.com"),
      F("privaudit", "standing-privilege", "adm@corp.com"),
      F("caaudit", "mfa", "adm@corp.com"),
    ]);
    assert.ok(hits.find((h) => h.ruleId === "priv-no-mfa"));
  });
});

group("correlate/asset rules", () => {
  test("exploitable exposed host fires on high vuln + exposed service", () => {
    const hits = correlate([
      A("web01.corp.com"),
      F("vulnimport", "sla", "web01.corp.com", "high"),
      F("netexposure", "rdp", "web01.corp.com", "high"),
    ]);
    const h = hits.find((x) => x.ruleId === "exploit-exposed-host");
    assert.ok(h);
    assert.equal(h.severity, "critical");
    assert.equal(h.subjectName, "web01.corp.com");
  });

  test("KEV tag counts as the vuln leg even at low severity", () => {
    const hits = correlate([
      A("web01.corp.com"),
      F("vulnimport", "aging", "web01.corp.com", "low", { tags: ["kev"] }),
      F("netexposure", "smb", "web01.corp.com", "high"),
    ]);
    assert.ok(hits.find((x) => x.ruleId === "exploit-exposed-host"));
  });

  test("exposed-no-backup fires on exposure + backup gap", () => {
    const hits = correlate([
      A("db01.corp.com"),
      F("netexposure", "ssh", "db01.corp.com", "high"),
      F("backupready", "unprotected", "db01.corp.com", "high"),
    ]);
    assert.ok(hits.find((x) => x.ruleId === "exposed-no-backup"));
  });

  test("short name and FQDN resolve to one host", () => {
    const hits = correlate([
      A("web01"), A("web01.corp.com"),
      F("vulnimport", "sla", "web01", "high"),
      F("netexposure", "rdp", "web01.corp.com", "high"),
    ]);
    assert.ok(hits.find((x) => x.ruleId === "exploit-exposed-host"), "resolves across short/fqdn");
  });

});

group("correlate/new cross-tool rules", () => {
  test("live-priv-cred fires on an unrotated credential that is also privileged (same principal)", () => {
    const hits = correlate([
      I("svc-deploy@corp.com"),
      F("nhi", "rotation", "svc-deploy@corp.com", "high"),
      F("privaudit", "non-human-privilege", "svc-deploy@corp.com", "high"),
    ]);
    const h = hits.find((x) => x.ruleId === "live-priv-cred");
    assert.ok(h, "live-priv-cred hit present");
    assert.equal(h.subjectType, "identity");
    assert.equal(h.severity, "critical");
  });

  test("brute-force-success fires on spray/brute attempt + confirmed stuffing success", () => {
    const hits = correlate([
      I("jo@corp.com"),
      F("vpnaudit", "brute_force", "jo@corp.com", "high"),
      F("signins", "cred_stuffing_success", "jo@corp.com", "critical"),
    ]);
    assert.ok(hits.find((x) => x.ruleId === "brute-force-success"));
  });

  test("brute-force-success: a newer out-of-window attempt does not hide an older in-window chain", () => {
    // attempt leg has two matches; the NEWEST (spraying) is 50d from the success (outside the 14d
    // window), an OLDER brute_force is 5d from it (inside). The window search must still fire via
    // the in-window pair — extra corroborating evidence must never cause a false negative.
    const hits = correlate([
      I("jane@corp.com"),
      F("vpnaudit", "spraying", "jane@corp.com", "high", { at: day(0) }),            // newest attempt, out of window
      F("signins", "cred_stuffing_success", "jane@corp.com", "critical", { at: day(50) }),
      F("vpnaudit", "brute_force", "jane@corp.com", "high", { at: day(55) }),         // older attempt, in window
    ]);
    const h = hits.find((x) => x.ruleId === "brute-force-success");
    assert.ok(h, "fires via the in-window brute_force+success pair");
    assert.ok(h.legs.some((l) => l.findingTitle === "vpnaudit/brute_force"), "in-window evidence is chosen");
    assert.notOk(h.legs.some((l) => l.findingTitle === "vpnaudit/spraying"), "the out-of-window finding is not chosen");
  });

  test("a windowed rule does not correlate across a leg whose evidence has no timestamp", () => {
    // anomaly leg evidence has no updatedAt/createdAt (ts=0): it can't be placed in the 30d window,
    // so the pair must NOT fire (the old times.length>=2 guard silently skipped the window check).
    const anon = { id: "fx", type: "FINDING", name: "vpnaudit/impossible_travel", severity: "high", source: "vpnaudit", tags: [], updatedAt: "", data: { tool: "vpnaudit", category: "impossible_travel", assets: ["jane@corp.com"] } };
    const hits = correlate([
      I("jane@corp.com"),
      F("caaudit", "mfa", "jane@corp.com", "high", { at: day(1) }),
      anon,
    ]);
    assert.equal(hits.filter((h) => h.ruleId === "account-takeover").length, 0);
  });

  test("oauth-overscope fires on a high-scope grant by a weak-MFA account", () => {
    const hits = correlate([
      I("sam@corp.com"),
      F("oauthgov", "oauth", "sam@corp.com", "high"),
      F("caaudit", "mfa", "sam@corp.com", "high"),
    ]);
    assert.ok(hits.find((x) => x.ruleId === "oauth-overscope"));
  });

  test("domain-takeover fires on a dangling record we still serve certs for", () => {
    const hits = correlate([
      A("app.corp.com"),
      F("domainguard", "takeover", "app.corp.com", "high"),
      F("tlsfleet", "transport security", "app.corp.com", "medium"),
    ]);
    assert.ok(hits.find((x) => x.ruleId === "domain-takeover"));
  });

  test("beacon-exposed fires on C2 DNS behaviour from an internet-exposed host", () => {
    const hits = correlate([
      A("host7.corp.com"),
      F("dnshunt", "beacon", "host7.corp.com", "high"),
      F("netexposure", "rdp", "host7.corp.com", "high"),
    ]);
    assert.ok(hits.find((x) => x.ruleId === "beacon-exposed"));
  });

  test("leaver-active also fires on access-review activity after termination", () => {
    const hits = correlate([
      I("x@corp.com"),
      F("jml", "leaver", "x@corp.com", "medium"),
      F("accessreview", "activity_after_termination", "x@corp.com", "high"),
    ]);
    assert.ok(hits.find((h) => h.ruleId === "leaver-active"));
  });
});

group("correlate/contract", () => {
  test("every rule has id, legs, attack, severity", () => {
    for (const r of RULES) {
      assert.ok(r.id && r.title && r.severity, "rule meta " + r.id);
      assert.ok(Array.isArray(r.attack) && r.attack.length, "attack " + r.id);
      assert.ok(Array.isArray(r.legs) && r.legs.length >= 2, "legs " + r.id);
      assert.ok(["asset", "identity"].includes(r.subject), "subject " + r.id);
    }
  });

  test("hits are severity-sorted (critical before high)", () => {
    const hits = correlate([
      A("web01.corp.com"), I("jane@corp.com"),
      F("vulnimport", "sla", "web01.corp.com", "high"),
      F("netexposure", "rdp", "web01.corp.com", "high"),
      F("caaudit", "mfa", "jane@corp.com"),
      F("vpnaudit", "impossible_travel", "jane@corp.com"),
    ]);
    const sevs = hits.map((h) => h.severity);
    const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    for (let i = 1; i < sevs.length; i++) assert.ok(rank[sevs[i - 1]] >= rank[sevs[i]], "sorted");
  });

  test("empty graph yields no hits", () => {
    assert.equal(correlate([]).length, 0);
    assert.equal(correlate(null).length, 0);
  });

  test("deterministic: output independent of input order", () => {
    const base = [
      A("web01.corp.com"), I("jane@corp.com"),
      F("vulnimport", "sla", "web01.corp.com", "high"),
      F("netexposure", "rdp", "web01.corp.com", "high"),
      F("caaudit", "mfa", "jane@corp.com"),
      F("vpnaudit", "impossible_travel", "jane@corp.com"),
    ];
    const a = JSON.stringify(correlate(base));
    const b = JSON.stringify(correlate(base.slice().reverse()));
    assert.equal(a, b);
  });
});

group("correlate/incident materialization", () => {
  // Account-takeover legs with explicit createdAt/updatedAt so the incident clock is testable.
  // fa: first seen day(10), last changed day(10). fb: first seen day(5), last changed day(3).
  const atoGraph = () => [
    I("jane@corp.com"),
    { id: "fa", type: "FINDING", name: "caaudit/mfa", severity: "high", source: "caaudit", tags: [],
      createdAt: day(10), updatedAt: day(10), data: { tool: "caaudit", category: "mfa", assets: ["jane@corp.com"] } },
    { id: "fb", type: "FINDING", name: "vpnaudit/impossible_travel", severity: "high", source: "vpnaudit", tags: [],
      createdAt: day(5), updatedAt: day(3), data: { tool: "vpnaudit", category: "impossible_travel", assets: ["jane@corp.com"] } },
  ];

  test("a hit becomes one INCIDENT with an evidence_for link from every leg", () => {
    const ents = atoGraph();
    const ato = correlate(ents).find((h) => h.ruleId === "account-takeover");
    assert.ok(ato, "precondition: account-takeover fires");
    const { entities, relationships } = materializeIncidents([ato], ents);
    assert.equal(entities.length, 1);
    const inc = entities[0];
    assert.equal(inc.type, "INCIDENT");
    assert.equal(inc.status, "open");
    assert.equal(inc.data.rule, "account-takeover");
    assert.equal(inc.data.phase, "identification");
    assert.equal(relationships.length, ato.legs.length);
    for (const r of relationships) {
      assert.equal(r.type, "evidence_for");
      assert.equal(r.toId, inc.id);
      assert.ok(ato.legs.some((l) => l.findingId === r.fromId), "relationship comes from a contributing finding");
    }
  });

  test("the incident id is deterministic per rule + subject", () => {
    const ents = atoGraph();
    const ato = correlate(ents).find((h) => h.ruleId === "account-takeover");
    const { entities } = materializeIncidents([ato], ents);
    assert.equal(entities[0].id, incidentId("account-takeover", "identity", ato.subjectKey));
  });

  test("re-running on an unchanged graph is byte-identical (idempotent LWW tie)", () => {
    const a = JSON.stringify(materializeIncidents(correlate(atoGraph()), atoGraph()));
    const b = JSON.stringify(materializeIncidents(correlate(atoGraph()), atoGraph()));
    assert.equal(a, b);
  });

  test("createdAt = earliest leg first-seen, updatedAt = latest leg change", () => {
    const ents = atoGraph();
    const ato = correlate(ents).find((h) => h.ruleId === "account-takeover");
    const inc = materializeIncidents([ato], ents).entities[0];
    assert.equal(inc.createdAt, day(10)); // min(created): fa day(10) is earliest
    assert.equal(inc.updatedAt, day(3));  // max(updated): fb day(3) is most recent
  });

  test("a newer leg advances updatedAt only, not createdAt (SLA clock holds, LWW wins)", () => {
    const base = atoGraph();
    const inc0 = materializeIncidents(correlate(base), base).entities[0];
    const moved = atoGraph();
    moved.find((e) => e.id === "fb").updatedAt = day(0); // the anomaly re-fires today
    const inc1 = materializeIncidents(correlate(moved), moved).entities[0];
    assert.equal(inc1.id, inc0.id, "same incident id");
    assert.equal(inc1.createdAt, inc0.createdAt, "createdAt (SLA clock) unchanged");
    assert.ok(Date.parse(inc1.updatedAt) > Date.parse(inc0.updatedAt), "updatedAt advanced so it strictly wins");
  });

  test("priority maps from severity (critical -> p1)", () => {
    const g = [
      A("web01.corp.com"),
      { id: "v1", type: "FINDING", name: "vulnimport/sla", severity: "high", source: "vulnimport", tags: ["kev"],
        createdAt: day(2), updatedAt: day(2), data: { tool: "vulnimport", category: "sla", assets: ["web01.corp.com"] } },
      { id: "x1", type: "FINDING", name: "netexposure/rdp", severity: "high", source: "netexposure", tags: [],
        createdAt: day(2), updatedAt: day(2), data: { tool: "netexposure", category: "rdp", assets: ["web01.corp.com"] } },
    ];
    const hit = correlate(g).find((h) => h.ruleId === "exploit-exposed-host");
    assert.ok(hit && hit.severity === "critical", "precondition: critical hit");
    assert.equal(materializeIncidents([hit], g).entities[0].data.priority, "p1");
  });

  test("no hits yields empty record sets", () => {
    const r = materializeIncidents([], []);
    assert.deepEqual(r.entities, []);
    assert.deepEqual(r.relationships, []);
  });
});
