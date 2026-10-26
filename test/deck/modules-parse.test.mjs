// Every Deck module (and the shared modules its native tools load) must at least parse:
// most are only ever imported by the browser, so a syntax error (a duplicate const)
// would otherwise ship as a blank tab with no test failing.

import { test, group, assert } from "../harness.mjs";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const root = new URL("../../public/js/", import.meta.url).pathname;
const walk = (d) => readdirSync(d).flatMap((n) => { const f = join(d, n); return statSync(f).isDirectory() ? walk(f) : n.endsWith(".js") ? [f] : []; });
const files = [...walk(join(root, "deck")), join(root, "deck-ui.js"), join(root, "net.js"),
  ...["ct-fetch", "posture-collect", "posture", "posture-engine", "phish-engine", "phish", "tls-engine"].map((n) => join(root, "dataprotect", n + ".js"))];

group("deck: modules parse", () => {
  test(files.length + " modules are valid ES module syntax", () => {
    const bad = files
      .map((f) => [f, spawnSync(process.execPath, ["--check", "--input-type=module"], { input: readFileSync(f, "utf8"), encoding: "utf8" })])
      .filter(([, r]) => r.status !== 0)
      .map(([f, r]) => f.slice(root.length) + ": " + (r.stderr.split("\n").find((l) => /Error/.test(l)) || r.stderr.trim()));
    assert.equal(bad.join("\n"), "");
  });
});
