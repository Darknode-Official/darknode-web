// CSV exports carry uploaded values (users, hosts, titles, certificate issuers, IOCs). A cell that
// opens with = + - @ tab or CR runs as a formula in a spreadsheet; every exporter must defuse it.
// Fleet compliance let "-1+cmd|..." through (it exempted any "-digit"); ORACLE and TLS fleet had no guard.
import { test, assert, group } from "../harness.mjs";
import { readdirSync, statSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { register } from "node:module";

// Some engines import "/js/..." site-absolute paths; map them to public/js (as deck-native-audit does) so
// a failed first import is not cached for the test files that run after this one.
const PUB = new URL("../../public", import.meta.url).href;
register("data:text/javascript," + encodeURIComponent(
  `export async function resolve(s, c, n) { return n(s.startsWith("/js/") ? ${JSON.stringify(PUB)} + s : s, c); }`));

const root = fileURLToPath(new URL("../../public/js/", import.meta.url));
const walk = (d) => readdirSync(d).flatMap((f) => { const p = path.join(d, f); return statSync(p).isDirectory() ? walk(p) : p.endsWith("-engine.js") ? [p] : []; });
const PAY = ['=HYPERLINK("http://x.test","zz1")', "+zz2+cmd|/C calc!A0", "@SUM(zz3)", "-1+zz4", "\t=zz5", "\r=zz6"];
// Columns the engine fills itself (detection ids, rule types), never from uploaded data.
const INTERNAL = { "identity/signin-forensics-engine.js": ["id"], "infra/firewall-audit-engine.js": ["id", "type"] };
const finding = (k, keep = []) => Object.fromEntries(Object.entries(poisoned(k)).map(([f, v]) => [f, keep.includes(f) ? "x" : v]));
const poisoned = (k) => ({ id: k, severity: "high", confidence: "high", category: k, title: k, description: k, recommendation: k, remediation: k,
  controls: [{ framework: k, id: k }], assets: [k, k], evidence: [{ a: k }], evidenceCount: 1, user: k, host: k, domain: k, ip: k, detail: k, summary: k, tags: [k], refs: [k] });
const parseCsv = (t) => { const rows = []; let row = [], cell = "", q = false;
  for (let i = 0; i < t.length; i++) { const c = t[i];
    if (q) { if (c === '"') { if (t[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c; }
    else if (c === '"') q = true; else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n" || (c === "\r" && t[i + 1] === "\n")) { if (c === "\r") i++; row.push(cell); rows.push(row); row = []; cell = ""; }
    else cell += c; }
  if (cell || row.length) { row.push(cell); rows.push(row); } return rows; };

const engines = [];
for (const f of walk(root)) {
  let m; try { m = await import(f); } catch { continue; }
  if (m.findingsToCsv && m.analyze) engines.push([path.relative(root, f), m]);
}

group("CSV exports defuse spreadsheet formulas", () => {
  test("found the exporters", () => assert.ok(engines.length >= 25, "found " + engines.length));
  for (const [name, m] of engines) {
    test(name, () => {
      let seen = 0;
      for (const k of PAY) for (const row of parseCsv(String(m.findingsToCsv([finding(k, INTERNAL[name])])))) for (const c of row) {
        if (!/zz[1-6]/.test(c)) continue;
        seen++;
        assert.ok(!/^[=+@\-\t\r]/.test(c), "formula cell " + JSON.stringify(c.slice(0, 30)));
      }
      assert.ok(seen > 0, "the payload reached the CSV");
    });
  }
  test("fleet compliance keeps negative numbers plain", async () => {
    const m = await import(root + "exposure/fleetcomply-engine.js");
    const row = parseCsv(m.findingsToCsv([{ ...finding("x"), title: "-5", description: "-3.25" }]))[1];
    assert.ok(row.includes("-5") && row.includes("-3.25"));
  });
  test("ORACLE and TLS fleet exports go through a guarded csvCell", () => {
    for (const f of ["oracle.js", "dataprotect/tlsfleet.js"]) {
      const s = readFileSync(root + f, "utf8");
      assert.ok(/const csvCell = .*\^\[=\+@\\t\\r\]/.test(s), f + " defines the guard");
      assert.ok(!/'"' \+ (i\.value|r\.refanged)/.test(s), f + " no hand-quoted cells");
    }
    assert.ok(/\]\.map\(csvCell\)\.join\(","\)/.test(readFileSync(root + "dataprotect/tlsfleet.js", "utf8")));
    assert.equal((readFileSync(root + "oracle.js", "utf8").match(/\.map\(csvCell\)\.join\(','\)/g) || []).length, 2);
  });
});
