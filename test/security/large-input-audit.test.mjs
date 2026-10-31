// Engines must take a large upload: Array.prototype.push(...rows) passes every row as a call
// argument and overflows the stack (RangeError) somewhere past ~100k rows.
import { test, assert, group } from "../harness.mjs";
import * as riskreg from "../../public/js/risk/riskreg-engine.js";
import * as breachclock from "../../public/js/risk/breachclock-engine.js";
import * as domainguard from "../../public/js/exposure/domainguard-engine.js";
import * as privaudit from "../../public/js/identity/privaudit-engine.js";
import * as awareness from "../../public/js/compliance/awareness-engine.js";
import * as dataflow from "../../public/js/compliance/dataflow-engine.js";
import { readFileSync } from "fs";

const N = 150000;
const csv = (header, row) => header + "\n" + Array.from({ length: N }, (_, i) => row(i)).join("\n") + "\n";

group("large uploads (150k rows) do not overflow the call stack", () => {
  test("risk register CSV", () => {
    const p = riskreg.parseInput([{ name: "risks.csv", text: csv("title,likelihood,impact,owner", (i) => "Risk " + i + ",3,4,ops") }]);
    assert.ok(p.rows.length === N);
  });
  test("risk register JSON records", () => {
    const risks = Array.from({ length: N }, (_, i) => ({ id: "R" + i, title: "Risk " + i, likelihood: 3, impact: 4 }));
    riskreg.parseInput([{ name: "risks.json", text: JSON.stringify({ risks }) }]);
  });
  test("breach clock rows", () => {
    breachclock.parseInput([{ name: "a.csv", text: csv("jurisdiction,count", (i) => "US-CA," + i) }]);
  });
  test("domain list", () => {
    const p = domainguard.parseInput([{ name: "domains.txt", text: Array.from({ length: N }, (_, i) => "d" + i + ".example.com").join("\n") }]);
    assert.ok(p.domains.length > 100000);
  });
  test("privileged access CSV", () => {
    privaudit.parseInput([{ name: "admins.csv", text: csv("user,role,last_login", (i) => "u" + i + "@x.test,Global Administrator,2026-01-01") }]);
  });
  test("awareness history and data-flow inventory", () => {
    awareness.parseInput([{ name: "history.csv", text: csv("email,campaign,clicked,date", (i) => "u" + i + "@x.test,c1,yes,2026-01-01") }]);
    dataflow.parseInput([{ name: "ropa.csv", text: csv("activity,purpose,legal_basis,data_categories", (i) => "A" + i + ",billing,contract,email") }]);
  });
  test("no engine spreads an uploaded row list into push()", () => {
    const pats = [["risk/riskreg-engine.js", /push\(\.\.\.(rows|recs)\)/], ["risk/breachclock-engine.js", /rows\.push\(\.\.\.c\.rows/], ["identity/privaudit-engine.js", /rows\.push\(\.\.\.recs\)/],
      ["compliance/awareness-engine.js", /history\.push\(\.\.\./], ["compliance/dataflow-engine.js", /push\(\.\.\.(acts|ds)\.map/], ["exposure/domainguard-engine.js", /domains\.push\(\.\.\.dl\.domains\)/]];
    for (const [f, re] of pats) assert.ok(!re.test(readFileSync(new URL("../../public/js/" + f, import.meta.url), "utf8")), f);
  });
});
