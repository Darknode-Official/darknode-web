// Code Scanner baseline & diff tests (public/js/codescan/baseline.js):
// stable, line-independent finding keys and NEW / UNCHANGED / FIXED classification.

import { test, assert, group } from "../harness.mjs";
import { findingKey, serializeBaseline, diffFindings, baselineKeySet } from "../../public/js/codescan/baseline.js";

// A representative code finding (shape mirrors scanFile output + the path added in scanAll).
const codeFinding = (over = {}) => ({
  ruleId: "js.eval", title: "Dynamic code evaluation", sev: "high", cwe: 95,
  line: 42, col: 3, snippet: "eval(userInput)", kind: "code",
  why: "w", fix: "f", path: "src/app.js", ...over,
});
const secretFinding = (over = {}) => ({
  ruleId: "secret.aws-access-key", title: "AWS access key ID", sev: "high", cwe: 798,
  line: 10, col: 1, snippet: "const k = \"AKIA…WXYZ\"", kind: "secret", secret: "AKIA…WXYZ",
  path: "config.js", ...over,
});
const depFinding = (over = {}) => ({
  kind: "dep", ruleId: "dep.GHSA-xxxx", title: "ReDoS in lodash", sev: "medium",
  path: "package-lock.json", line: 120, col: 1, pkg: "lodash", version: "4.17.11",
  advisory: "GHSA-xxxx", cve: "CVE-2020-1", ...over,
});

group("codescan baseline: key stability", () => {
  test("key is independent of line and column", () => {
    const a = codeFinding({ line: 42, col: 3 });
    const b = codeFinding({ line: 999, col: 17 });
    assert.equal(findingKey(a), findingKey(b));
  });
  test("key is independent of surrounding whitespace in the snippet", () => {
    const a = codeFinding({ snippet: "eval(userInput)" });
    const b = codeFinding({ snippet: "\t  eval(userInput)   " }); // re-indented, trailing space
    assert.equal(findingKey(a), findingKey(b));
  });
  test("distinct rule, path or content give distinct keys", () => {
    const base = codeFinding();
    assert.notEqual(findingKey(base), findingKey(codeFinding({ ruleId: "js.inner-html" })));
    assert.notEqual(findingKey(base), findingKey(codeFinding({ path: "src/other.js" })));
    assert.notEqual(findingKey(base), findingKey(codeFinding({ snippet: "eval(otherInput)" })));
  });
  test("dependency key tracks package/version/advisory, not manifest line", () => {
    const a = depFinding({ line: 120 });
    const b = depFinding({ line: 7 });
    assert.equal(findingKey(a), findingKey(b));
    assert.notEqual(findingKey(a), findingKey(depFinding({ version: "4.17.20" })));
    assert.notEqual(findingKey(a), findingKey(depFinding({ advisory: "GHSA-yyyy" })));
  });
});

group("codescan baseline: diff classification", () => {
  const findings = [codeFinding(), secretFinding(), depFinding()];

  test("a scan diffed against its own baseline: 0 new, 0 fixed, all unchanged", () => {
    const base = serializeBaseline(findings, { ref: "gh:acme/repo" });
    const d = diffFindings(baselineKeySet(base), findings);
    assert.equal(d.newFindings.length, 0);
    assert.equal(d.fixedKeys.length, 0);
    assert.equal(d.unchanged.length, findings.length);
  });

  test("a finding moved to a different line stays UNCHANGED (key stable)", () => {
    const base = serializeBaseline(findings, {});
    const moved = [codeFinding({ line: 500 }), secretFinding({ line: 88 }), depFinding({ line: 3 })];
    const d = diffFindings(baselineKeySet(base), moved);
    assert.equal(d.newFindings.length, 0);
    assert.equal(d.fixedKeys.length, 0);
    assert.equal(d.unchanged.length, 3);
  });

  test("a removed finding is FIXED", () => {
    const base = serializeBaseline(findings, {});
    const current = [codeFinding(), secretFinding()]; // dep removed
    const d = diffFindings(baselineKeySet(base), current);
    assert.equal(d.fixedKeys.length, 1);
    assert.equal(d.fixedKeys[0], findingKey(depFinding()));
    assert.equal(d.newFindings.length, 0);
    assert.equal(d.unchanged.length, 2);
  });

  test("an added finding is NEW", () => {
    const base = serializeBaseline([codeFinding()], {});
    const added = codeFinding({ ruleId: "js.inner-html", title: "Unsanitised HTML sink", snippet: "el.innerHTML = x" });
    const d = diffFindings(baselineKeySet(base), [codeFinding(), added]);
    assert.equal(d.newFindings.length, 1);
    assert.equal(d.newFindings[0].ruleId, "js.inner-html");
    assert.equal(d.unchanged.length, 1);
    assert.equal(d.fixedKeys.length, 0);
  });

  test("combined: new + fixed + unchanged in one diff", () => {
    const base = serializeBaseline([codeFinding(), depFinding()], {}); // dep will be fixed
    const added = secretFinding(); // new
    const current = [codeFinding({ line: 60 }), added]; // code unchanged (moved), dep gone
    const d = diffFindings(baselineKeySet(base), current);
    assert.equal(d.newFindings.length, 1);
    assert.equal(d.unchanged.length, 1);
    assert.equal(d.fixedKeys.length, 1);
  });
});

group("codescan baseline: serialization", () => {
  test("serialized baseline is compact, deduped and stores no secret values", () => {
    const dup = [secretFinding(), secretFinding({ line: 11 })]; // same key, different line
    const base = serializeBaseline(dup, { ref: "gh:acme/repo", full: "acme/repo", sha: "abc1234", branch: "main", at: 1000 });
    assert.equal(base.items.length, 1, "duplicate keys collapse to one item");
    assert.equal(base.ref, "gh:acme/repo");
    assert.equal(base.at, 1000);
    const item = base.items[0];
    assert.ok(item.k && item.sev && item.kind, "item carries key + severity + kind");
    // The raw (even masked-with-full-length) secret must not be serialized as a field.
    const json = JSON.stringify(base);
    assert.notOk(/"secret"\s*:/.test(json), "no secret field is serialized");
    assert.notOk(json.includes("AKIA"), "no secret value is serialized");
  });
  test("baselineKeySet tolerates a malformed baseline", () => {
    assert.equal(baselineKeySet(null).size, 0);
    assert.equal(baselineKeySet({}).size, 0);
    assert.equal(baselineKeySet({ items: "nope" }).size, 0);
  });
});
