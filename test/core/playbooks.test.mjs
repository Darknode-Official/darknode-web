// Unit tests for public/js/core/playbooks.js — the response-playbook selector.
import { test, group, assert } from "../harness.mjs";
import { playbookFor, getPlaybook, PLAYBOOK_IDS } from "../../public/js/core/playbooks.js";

const F = (over = {}) => ({ type: "FINDING", severity: "high", source: "", data: {}, ...over });

group("playbooks/playbookFor", () => {
  test("a known-exploited vulnerability gets the time-critical playbook", () => {
    const p = playbookFor(F({ type: "VULNERABILITY", data: { category: "vulnerability", kev: true } }));
    assert.equal(p.id, "known-exploited-vuln");
  });

  test("kev can be passed by the caller", () => {
    const p = playbookFor(F({ data: { category: "vulnerability" } }), { kev: true });
    assert.equal(p.id, "known-exploited-vuln");
  });

  test("a plain vulnerability gets the vulnerability playbook", () => {
    assert.equal(playbookFor(F({ type: "VULNERABILITY", data: { category: "vulnerability" } })).id, "vulnerability");
  });

  test("an exposed secret is matched by category", () => {
    assert.equal(playbookFor(F({ data: { category: "secret", tool: "codescan" } })).id, "exposed-secret");
  });

  test("identity findings match by category or by source tool", () => {
    assert.equal(playbookFor(F({ data: { category: "identity" } })).id, "identity");
    assert.equal(playbookFor(F({ data: { category: "", tool: "caaudit" } })).id, "identity");
  });

  test("exposure, cloud, phishing, data, financial and supply-chain map correctly", () => {
    assert.equal(playbookFor(F({ data: { category: "attack-surface" } })).id, "exposure");
    assert.equal(playbookFor(F({ data: { category: "misconfiguration", tool: "iacscan" } })).id, "cloud");
    assert.equal(playbookFor(F({ data: { category: "phishing" } })).id, "phishing");
    assert.equal(playbookFor(F({ data: { category: "data-exposure" } })).id, "data");
    assert.equal(playbookFor(F({ data: { category: "payment", tool: "payees" } })).id, "financial");
    assert.equal(playbookFor(F({ data: { category: "supply-chain" } })).id, "supplychain");
  });

  test("an unknown finding falls back to the generic playbook", () => {
    assert.equal(playbookFor(F({ data: { category: "something-odd" } })).id, "generic");
    assert.equal(playbookFor(null).id, "generic");
  });

  test("every playbook has steps, a verify step and is shaped right", () => {
    for (const id of PLAYBOOK_IDS) {
      const p = getPlaybook(id);
      assert.ok(p.title && p.when, id + " has title/when");
      assert.ok(Array.isArray(p.steps) && p.steps.length >= 3, id + " has steps");
      assert.ok(typeof p.verify === "string" && p.verify.length, id + " has a verify step");
      assert.ok(Array.isArray(p.references), id + " has references");
    }
  });

  test("selection is deterministic", () => {
    const f = F({ type: "VULNERABILITY", data: { category: "vulnerability", kev: true } });
    assert.equal(playbookFor(f).id, playbookFor(f).id);
  });
});
