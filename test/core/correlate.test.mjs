// Unit tests for public/js/core/correlate.js — the cross-tool correlation engine.
import { test, group, assert } from "../harness.mjs";
import { correlate, RULES } from "../../public/js/core/correlate.js";

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

  test("live-secret fires on leaked secret + active key", () => {
    const hits = correlate([
      A("ci-host"),
      F("leakprobe", "secrets", "ci-host", "high", { title: "AWS secret key exposed" }),
      F("nhi", "rotation", "ci-host", "high"),
    ]);
    assert.ok(hits.find((x) => x.ruleId === "live-secret"));
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
