// Semver quick tools (public/js/tools/devx.js): satisfies follows npm's range rules.

import { test, assert, group } from "../harness.mjs";
import { TOOLS } from "../../public/js/tools/devx.js";

const sat = (version, range) => TOOLS.find((t) => t.id === "dv-semver-satisfies").run({ version, range });

group("devx: semver satisfies", () => {
  test("ordinary ranges", () => {
    assert.ok(/^SATISFIES/.test(sat("1.4.2", "^1.2.0")));
    assert.ok(/^does NOT/.test(sat("2.0.0", "^1.2.0")));
    assert.ok(/^SATISFIES/.test(sat("0.1.5", "^0.1.0")));
  });
  test("a prerelease only matches a range naming a prerelease of the same version (npm)", () => {
    assert.ok(/^does NOT/.test(sat("2.0.0-0", "^1.2.3")));
    assert.ok(/^does NOT/.test(sat("1.2.4-beta.0", ">1.2.3")));
    assert.ok(/^does NOT/.test(sat("1.0.0-alpha", "<=1.2.3")));
    assert.ok(/^SATISFIES/.test(sat("1.2.4-beta.1", "^1.2.4-beta.0")));
    assert.ok(/^SATISFIES/.test(sat("1.0.0-alpha", "=1.0.0-alpha")));
  });
});

group("dv-semver-satisfies: full npm range syntax", () => {
  // checked against npm's semver package; these all returned "Range target is not valid semver"
  const yes = [["2.1.2", "2.x"], ["1.1.0", "*"], ["2.2.2", "^0.1.1 || ~2.2.1"], ["1.2.1", "0.0.1 - 1.3.1"], ["1.9.0", ">=1 <2"], ["1.4.0", "^1.2"], ["1.3.9", "1.0.0 - 1.3"], ["0.2.5", "~>0.2.1"], ["3.0.0", "> 2.9"]];
  const no = [["2.1.3", "~2.0"], ["2.0.3", "~1"], ["1.4.0", "1.0.0 - 1.3"], ["2.0.0", ">=1 <2"], ["2.9.5", ">2.9"], ["1.1.0-beta.1", ">=0.3.2 <1.1.3"]];
  test("ranges npm accepts give npm's answer", () => {
    for (const [v, r] of yes) assert.ok(/^SATISFIES/.test(sat(v, r)), v + " " + r);
    for (const [v, r] of no) assert.ok(/^does NOT satisfy/.test(sat(v, r)), v + " " + r);
  });
  test("the expansion is shown", () => {
    assert.ok(sat("1.4.0", "^1.2").includes(">=1.2.0 <2.0.0-0"));
  });
  test("ranges npm rejects are errors", () => {
    for (const r of ["01.2.3", "1.2.3.4", "a.b", ">="]) assert.ok(sat("1.2.3", r).error, r);
  });
});

const run = (id, v) => TOOLS.find((t) => t.id === id).run(v);
group("devx: semver parse and bump follow semver.org and npm semver.inc", () => {
  test("leading zeros, empty identifiers and an empty prerelease are invalid", () => {
    for (const v of ["1.01.0", "01.2.3", "1.2.3-rc.01", "1.2.3-", "1.2.3-a..b", "1.2.3+", "1.2.3+a..b"]) assert.ok(run("dv-semver-parse", { version: v }).error, v);
    for (const v of ["v1.2.3", "1.2.3-0", "1.2.3-0a.1", "1.2.3-rc.1+001"]) assert.ok(!run("dv-semver-parse", { version: v }).error, v);
  });
  test("bumping a prerelease releases it", () => {
    const bump = (version, type) => run("dv-semver-bump", { version, type });
    assert.equal(bump("2.0.0-rc.1", "major"), "2.0.0");
    assert.equal(bump("2.1.0-rc.1", "major"), "3.0.0");
    assert.equal(bump("1.3.0-rc.1", "minor"), "1.3.0");
    assert.equal(bump("1.3.1-rc.1", "minor"), "1.4.0");
    assert.equal(bump("1.2.1-rc.1", "patch"), "1.2.1");
    assert.equal(bump("1.2.1", "patch"), "1.2.2");
    assert.equal(bump("1.0.0-1.beta", "prerelease"), "1.0.0-2.beta");
    assert.equal(bump("1.0.0-beta", "prerelease"), "1.0.0-beta.0");
  });
});
