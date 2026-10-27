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
