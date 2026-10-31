// Every business engine is fed its own example data with each value (and every other CSV
// header) replaced by an Object member name. A plain-object lookup table then finds an
// inherited member: Breach Clock threw on null.kind for a "constructor" jurisdiction, and
// License audit reported "constructor" as "read as function Object() { [native code] }".
import { test, assert, group } from "../harness.mjs";
import { readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("../../public/js/", import.meta.url));
const walk = (d) => readdirSync(d).flatMap((f) => { const p = path.join(d, f); return statSync(p).isDirectory() ? walk(p) : p.endsWith("-engine.js") ? [p] : []; });
const KEYS = ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf"];
const LEAK = /\[native code\]|function Object|\[object Object\]/;
const SKIP = new Set(["now", "label"]);

const poisonVal = (v, k, key) => SKIP.has(key) ? v : Array.isArray(v) ? v.map((x) => poisonVal(x, k)) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([a, b]) => [a, poisonVal(b, k, a)])) : typeof v === "string" ? k : v;
const poisonCsv = (t, k) => t.split("\n").map((l, i) => (i === 0 || !l ? l : l.split(",").map(() => k).join(","))).join("\n");
const poisonHdr = (t, k) => { const ls = t.split("\n"); ls[0] = ls[0].split(",").map((h, i) => (i % 2 ? k : h)).join(","); return ls.join("\n"); };
const poisonFile = (x, k, mode) => {
  const t = x.text || "";
  if (/\.json$/i.test(x.name || "") || /^\s*[\[{]/.test(t)) {
    if (mode === "headers") return x;
    try { return { ...x, text: JSON.stringify(poisonVal(JSON.parse(t), k)) }; } catch { return x; }
  }
  return { ...x, text: mode === "cells" ? poisonCsv(t, k) : poisonHdr(t, k) };
};

const engines = [];
for (const f of walk(root)) {
  const m = await import(f);
  if (m.parseInput && m.analyze && m.exampleDataset) engines.push([path.relative(root, f), m]);
}

group("business engines treat Object member names as ordinary values", () => {
  test("found the business engines", () => assert.ok(engines.length >= 25, "found " + engines.length));
  for (const [name, m] of engines) {
    test(name, () => {
      const ex = m.exampleDataset();
      const files = ex.files || ex.inputs || (Array.isArray(ex) ? ex : null);
      for (const k of KEYS) for (const mode of files ? ["cells", "headers"] : ["records"]) {
        let r;
        try {
          r = files ? m.analyze(m.parseInput(files.map((x) => poisonFile(x, k, mode)), ex.options || {}), ex.options || {})
            : m.analyze(poisonVal(ex.record || ex, k), {});
        } catch (e) { assert.ok(false, mode + "=" + k + " threw " + e.message); }
        const out = JSON.stringify(r) + (m.findingsToCsv ? m.findingsToCsv(r.findings || r) : "");
        const hit = LEAK.exec(out);
        assert.ok(!hit, mode + "=" + k + " output has " + (hit && JSON.stringify(out.slice(Math.max(0, hit.index - 60), hit.index + 30))));
      }
    });
  }
});
