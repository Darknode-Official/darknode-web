// Every engine CSV export neutralises a cell that would run as a spreadsheet formula
// (imported usernames, hostnames and app names are attacker-influenced).

import { test, assert, group } from "../harness.mjs";
import { findingsToCsv as jmlCsv } from "../../public/js/identity/jml-engine.js";
import { findingsToCsv as fwCsv } from "../../public/js/infra/firewall-audit-engine.js";
import { findingsToCsv as huntCsv } from "../../public/js/ops/log-hunter-engine.js";

const EVIL = '=HYPERLINK("http://x","y")';
group("CSV exports: formula guard", () => {
  test("JML findings CSV prefixes a formula cell, keeps negative numbers", () => {
    const out = jmlCsv([{ severity: "high", confidence: "high", category: "c", title: EVIL, description: "-5", recommendation: "@SUM(A1)", controls: [], evidence: [] }]);
    assert.ok(out.includes(`"'=HYPERLINK(""http://x"",""y"")"`), out);
    assert.ok(out.includes('"-5"') && out.includes(`"'@SUM(A1)"`), out);
  });
  test("firewall findings CSV prefixes a formula title", () => {
    const out = fwCsv([{ id: "x", severity: "high", confidence: "high", type: "t", title: EVIL, evidence: [], fix: "", refs: [], attack: "" }]);
    assert.ok(out.includes(`"'=HYPERLINK`) && !/,"=HYPERLINK/.test(out), out);
  });
  test("log hunter findings CSV prefixes a formula cell", () => {
    let out = "";
    try { out = huntCsv([{ id: "x", severity: "high", title: EVIL, entity: EVIL, evidence: [], count: 1 }]); } catch (e) { out = "ERR " + e.message; }
    assert.ok(!/(^|,)"=HYPERLINK/m.test(out), out);
  });
});

group("CSV exports: minus-led formulas and CR/tab-led cells", () => {
  const row = (v) => [{ id: v, title: v, severity: "high", confidence: "high", category: v, description: v, recommendation: v, entity: v, evidence: [v], controls: [], refs: [], count: 1 }];
  const leaks = (out, v) => out.split("\n").slice(1).some((l) => l.split(",").some((c) => c.replace(/^"/, "").startsWith(v)));
  test("cloudtrail + cloudspend prefix '-2+3' but keep '-5' and '-1.25'", async () => {
    for (const p of ["../../public/js/ops/cloudtrail-engine.js", "../../public/js/finsec/cloudspend-engine.js"]) {
      const { findingsToCsv } = await import(p);
      assert.ok(!leaks(findingsToCsv(row("-2+3")), "-2+3"), p);
      const out = findingsToCsv(row("-5")) + findingsToCsv(row("-1.25"));
      assert.ok(!out.includes("'-5") && !out.includes("'-1.25"), p + " " + out);
    }
  });
  test("k8saudit / iacscan / apispec / licenseaudit prefix a carriage-return or tab-led cell", async () => {
    for (const p of ["../../public/js/appsec/k8saudit-engine.js", "../../public/js/appsec/iacscan-engine.js", "../../public/js/appsec/apispec-engine.js", "../../public/js/appsec/licenseaudit-engine.js"]) {
      const { findingsToCsv } = await import(p);
      for (const v of ["\r=1", "\t=1"]) assert.ok(!leaks(findingsToCsv(row(v)), v), p + " " + JSON.stringify(v));
    }
  });
});
