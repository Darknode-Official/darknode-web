// Unit tests for public/js/core/coverage.js — coverage-gap finding generation.
import { test, group, assert } from "../harness.mjs";
import { coverageFindings, ASSET_COV, IDENTITY_COV } from "../../public/js/core/coverage.js";

// A resolved inventory row is just { name, type, sources } as far as coverage cares.
const host = (name, sources) => ({ name, type: "ASSET", sources });
const id = (name, sources) => ({ name, type: "IDENTITY", sources });
const titles = (fs) => fs.map((f) => f.title).sort();

group("coverage/host gaps are scoped to managed hosts", () => {
  test("a managed host (scanned + fleet) with no backup → one backup gap", () => {
    const fs = coverageFindings([host("web-01.test.darknode.ai", ["vulnimport", "fleetcomply"])], []);
    assert.equal(fs.length, 1);
    assert.equal(fs[0].title, "Backup coverage gap: web-01.test.darknode.ai");
    assert.equal(fs[0].severity, "high");
    assert.equal(fs[0].category, "coverage-gap");
  });

  test("a DNS-only host (exposure source only) raises nothing — not in scope", () => {
    const fs = coverageFindings([host("www.test.darknode.ai", ["domainguard"])], []);
    assert.equal(fs.length, 0);
  });

  test("a scanned-only host → endpoint gap + backup gap (vuln is covered)", () => {
    const fs = coverageFindings([host("db-01.test.darknode.ai", ["vulnimport"])], []);
    assert.deepEqual(titles(fs), [
      "Backup coverage gap: db-01.test.darknode.ai",
      "Endpoint / fleet coverage gap: db-01.test.darknode.ai",
    ]);
  });

  test("a fleet-only host → vuln gap + backup gap (endpoint is covered)", () => {
    const fs = coverageFindings([host("ws-01.test.darknode.ai", ["fleetcomply"])], []);
    assert.deepEqual(titles(fs), [
      "Backup coverage gap: ws-01.test.darknode.ai",
      "Vuln scan coverage gap: ws-01.test.darknode.ai",
    ]);
  });

  test("a fully covered host raises nothing", () => {
    const fs = coverageFindings([host("srv-01.test.darknode.ai", ["vulnimport", "fleetcomply", "backupready"])], []);
    assert.equal(fs.length, 0);
  });

  test("a backup-only host raises nothing (not proven a managed host)", () => {
    const fs = coverageFindings([host("nas-01.test.darknode.ai", ["backupready"])], []);
    assert.equal(fs.length, 0);
  });
});

group("coverage/identity gaps", () => {
  test("a signed-in account not reconciled against HR/review → one access-review gap", () => {
    const fs = coverageFindings([], [id("user@test.darknode.ai", ["signins"])]);
    assert.equal(fs.length, 1);
    assert.equal(fs[0].title, "Access review coverage gap: user@test.darknode.ai");
    assert.equal(fs[0].severity, "high");
  });

  test("an HR/review account with no IdP presence → one identity-provider gap", () => {
    const fs = coverageFindings([], [id("svc@test.darknode.ai", ["accessreview"])]);
    assert.equal(fs.length, 1);
    assert.equal(fs[0].title, "Identity provider coverage gap: svc@test.darknode.ai");
    assert.equal(fs[0].severity, "medium");
  });

  test("a fully covered identity raises nothing", () => {
    const fs = coverageFindings([], [id("ok@test.darknode.ai", ["signins", "accessreview"])]);
    assert.equal(fs.length, 0);
  });
});

group("coverage/finding contract + determinism", () => {
  const input = () => [
    coverageFindings([host("db-01.test.darknode.ai", ["vulnimport"])], [id("user@test.darknode.ai", ["signins"])]),
  ];

  test("assets are {type,name} objects and controls are {framework,id} with CIS/ISO refs", () => {
    const f = coverageFindings([host("db-01.test.darknode.ai", ["vulnimport"])], []).find((x) => x.severity === "high");
    assert.ok(Array.isArray(f.assets) && f.assets[0] && f.assets[0].type === "ASSET" && f.assets[0].name === "db-01.test.darknode.ai");
    assert.ok(Array.isArray(f.controls) && f.controls.length > 0);
    assert.ok(f.controls.some((c) => c.framework === "CIS"), "has a CIS control");
    assert.ok(f.controls.some((c) => c.framework === "ISO27001"), "has an ISO 27001 control");
    assert.ok(f.recommendation && f.description, "has remediation and description");
  });

  test("identity gaps carry an IDENTITY asset", () => {
    const f = coverageFindings([], [id("user@test.darknode.ai", ["signins"])])[0];
    assert.equal(f.assets[0].type, "IDENTITY");
    assert.equal(f.assets[0].name, "user@test.darknode.ai");
  });

  test("same inventory produces byte-identical output", () => {
    assert.equal(JSON.stringify(input()), JSON.stringify(input()));
  });

  test("empty inventory produces no findings", () => {
    assert.equal(coverageFindings([], []).length, 0);
    assert.equal(coverageFindings(null, undefined).length, 0);
  });

  test("the config exposes finding:false areas that never emit (exposure, priv)", () => {
    assert.ok(ASSET_COV.find((c) => c.id === "exposure" && c.finding === false));
    assert.ok(IDENTITY_COV.find((c) => c.id === "priv" && c.finding === false));
  });
});
