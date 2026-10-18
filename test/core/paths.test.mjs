// Unit tests for public/js/core/paths.js — choke-point analysis over correlation chains.
import { test, group, assert } from "../harness.mjs";
import { chokePoints } from "../../public/js/core/paths.js";

let n = 0;
const I = (name) => ({ id: "i:" + name, type: "IDENTITY", name, data: {}, source: "inv" });
const A = (name) => ({ id: "a:" + name, type: "ASSET", name, data: {}, source: "inv" });
const F = (id, source, category, assets, sev = "high") => ({
  id, type: "FINDING", name: `${source}/${category}`, severity: sev, source, tags: [],
  updatedAt: new Date().toISOString(), data: { tool: source, category, assets: [assets] },
});

group("paths/choke findings", () => {
  test("one finding that feeds two chains ranks first with count 2", () => {
    // caaudit mfa on adm is a leg in BOTH account-takeover and priv-no-mfa.
    const { findings, chains } = chokePoints([
      I("adm@corp.com"),
      F("f-mfa", "caaudit", "mfa", "adm@corp.com"),            // shared leg
      F("f-trav", "vpnaudit", "impossible_travel", "adm@corp.com"),
      F("f-priv", "privaudit", "standing-privilege", "adm@corp.com"),
    ]);
    assert.ok(chains.length >= 2, "two chains fired");
    assert.equal(findings[0].findingId, "f-mfa");
    assert.equal(findings[0].count, 2, "the shared finding breaks two chains");
  });

  test("subjects aggregate converging chains", () => {
    const { subjects } = chokePoints([
      I("adm@corp.com"),
      F("f-mfa", "caaudit", "mfa", "adm@corp.com"),
      F("f-trav", "vpnaudit", "impossible_travel", "adm@corp.com"),
      F("f-priv", "privaudit", "standing-privilege", "adm@corp.com"),
    ]);
    assert.equal(subjects[0].subjectName, "adm@corp.com");
    assert.ok(subjects[0].count >= 2);
    assert.ok(subjects[0].maxSeverity === "high");
  });

  test("no chains yields empty lists", () => {
    const r = chokePoints([A("lonely"), F("f1", "vulnimport", "sla", "lonely", "high")]);
    assert.equal(r.chains.length, 0);
    assert.equal(r.findings.length, 0);
    assert.equal(r.subjects.length, 0);
  });

  test("deterministic across input order", () => {
    const base = [
      I("adm@corp.com"), A("web01.corp.com"),
      F("f-mfa", "caaudit", "mfa", "adm@corp.com"),
      F("f-trav", "vpnaudit", "impossible_travel", "adm@corp.com"),
      F("f-priv", "privaudit", "standing-privilege", "adm@corp.com"),
      F("f-vuln", "vulnimport", "sla", "web01.corp.com", "high"),
      F("f-exp", "netexposure", "rdp", "web01.corp.com", "high"),
    ];
    const a = JSON.stringify(chokePoints(base));
    const b = JSON.stringify(chokePoints(base.slice().reverse()));
    assert.equal(a, b);
  });
});
