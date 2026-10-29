// Every quick tool (public/js/tools/*.js) run with Object.prototype names as typed input:
// a lookup like TABLE[input] must not print a native function as the answer.

import { test, assert, group } from "../harness.mjs";
import { readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const dir = fileURLToPath(new URL("../../public/js/tools/", import.meta.url));
const { H } = await import(dir + "_helpers.js");
const PROBES = ["constructor", "__proto__", "toString", "hasOwnProperty", "constructor:x"];
const LEAK = /function \w*\(\) \{ \[native code\] \}/;

group("quick tools: prototype names as input", () => {
  test("no tool answers with a native function", async () => {
    const leaks = [];
    for (const f of readdirSync(dir).filter((x) => x.endsWith(".js") && !x.startsWith("_"))) {
      const mod = await import(dir + f);
      const list = Object.values(mod).find((v) => Array.isArray(v) && v[0] && typeof v[0].run === "function") || [];
      for (const t of list) for (const p of PROBES) {
        const v = {};
        for (const i of t.inputs || []) v[i.k] = ["number", "select", "checkbox"].includes(i.type) ? i.value : p;
        let r;
        try { r = t.run(v, H); } catch (_) { continue; } // a throw is shown as an error by the runner
        if (r && typeof r.then === "function") { r.catch(() => {}); continue; }
        if (typeof r === "string" && LEAK.test(r)) leaks.push(t.id + " [" + p + "]");
      }
    }
    assert.deepEqual(leaks, []);
  });
});
