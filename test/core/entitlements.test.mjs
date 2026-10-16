import { test, group, assert } from "../harness.mjs";
import { TIERS, FEATURES, normTier, tierFrom, rank, can, requiredTier, limit, planLabel } from "../../public/js/core/entitlements.js";

group("core/entitlements", () => {
  test("normTier clamps unknown input to free", () => {
    assert.equal(normTier("pro"), "pro");
    assert.equal(normTier("PRO"), "pro");
    assert.equal(normTier(""), "free");
    assert.equal(normTier(null), "free");
    assert.equal(normTier("galaxy"), "free");
  });

  test("tierFrom: owner always lands on the top tier", () => {
    assert.equal(tierFrom(null, true), "enterprise");
    assert.equal(tierFrom({ tier: "free" }, true), "enterprise");
    assert.equal(tierFrom({ admin: true }), "enterprise");
  });

  test("tierFrom reads claims, fields and strings", () => {
    assert.equal(tierFrom(null), "free");
    assert.equal(tierFrom("team"), "team");
    assert.equal(tierFrom({ tier: "pro" }), "pro");
    assert.equal(tierFrom({ plan: "team" }), "team");
    assert.equal(tierFrom({ entitlements: { tier: "pro" } }), "pro");
    assert.equal(tierFrom({ entitlements: "team" }), "team");
    assert.equal(tierFrom({ tier: "nonsense" }), "free");
  });

  test("rank orders the tiers", () => {
    assert.ok(rank("free") < rank("pro"));
    assert.ok(rank("pro") < rank("team"));
    assert.ok(rank("team") < rank("enterprise"));
    assert.equal(rank("bogus"), 0);
  });

  test("can() gates forward-looking features by tier", () => {
    assert.equal(can("free", "cloudSync"), false);
    assert.equal(can("pro", "cloudSync"), true);
    assert.equal(can("pro", "teamWorkspaces"), false);
    assert.equal(can("team", "teamWorkspaces"), true);
    assert.equal(can("team", "selfHosted"), false);
    assert.equal(can("enterprise", "selfHosted"), true);
  });

  test("can() never invents a lock for an undeclared feature", () => {
    assert.equal(can("free", "somethingFree"), true);
  });

  test("every declared feature maps to a known tier", () => {
    for (const [f, t] of Object.entries(FEATURES)) assert.ok(TIERS.includes(t), `${f} -> ${t}`);
  });

  test("requiredTier returns the gate or null", () => {
    assert.equal(requiredTier("teamWorkspaces"), "team");
    assert.equal(requiredTier("nope"), null);
  });

  test("limit returns per-tier numbers, -1 unlimited", () => {
    assert.equal(limit("free", "seats"), 1);
    assert.equal(limit("team", "seats"), 25);
    assert.equal(limit("enterprise", "seats"), -1);
    assert.equal(limit("free", "unknownKey"), -1);
  });

  test("planLabel is human-readable", () => {
    assert.equal(planLabel("free"), "Free");
    assert.equal(planLabel("enterprise"), "Enterprise");
    assert.equal(planLabel("bogus"), "Free");
  });
});
