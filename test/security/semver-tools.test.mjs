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
