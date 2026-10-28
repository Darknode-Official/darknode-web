// Unit tests for public/js/core/sigma.js — the Sigma-subset detection evaluator.
import { test, group, assert } from "../harness.mjs";
import { compileRule, evaluateRule } from "../../public/js/core/sigma.js";

const RULE = (detection, extra = "") => `title: Test rule\nlevel: high\ndetection:\n${detection}\n${extra}`;

group("sigma/compileRule", () => {
  test("compiles a minimal valid rule", () => {
    const c = compileRule(RULE("  selection:\n    EventID: 4625\n  condition: selection"));
    assert.equal(c.ok, true);
    assert.equal(c.rule.title, "Test rule");
    assert.deepEqual(c.rule.selectionNames, ["selection"]);
  });

  test("reports a missing detection block", () => {
    const c = compileRule("title: x\n");
    assert.equal(c.ok, false);
    assert.ok(/detection/i.test(c.error));
  });

  test("reports a missing condition", () => {
    const c = compileRule("title: x\ndetection:\n  selection:\n    a: 1\n");
    assert.equal(c.ok, false);
    assert.ok(/condition/i.test(c.error));
  });
});

group("sigma/evaluateRule", () => {
  test("matches a simple field equality (case-insensitive)", () => {
    const r = evaluateRule(RULE("  selection:\n    EventID: 4625\n  condition: selection"),
      [{ EventID: 4625, user: "a" }, { EventID: 4624 }, { eventid: "4625" }]);
    assert.equal(r.count, 2); // numeric 4625 and string "4625", case-insensitive key
    assert.deepEqual(r.matches.map((m) => m.index), [0, 2]);
  });

  test("a list field value is OR", () => {
    const r = evaluateRule(RULE("  selection:\n    EventID:\n      - 4625\n      - 4740\n  condition: selection"),
      [{ EventID: 4740 }, { EventID: 1 }]);
    assert.equal(r.count, 1);
  });

  test("contains / startswith / endswith modifiers", () => {
    const r = evaluateRule(RULE("  selection:\n    CommandLine|contains: mimikatz\n  condition: selection"),
      [{ CommandLine: "C:/x/MIMIKATZ.exe -a" }, { CommandLine: "notepad" }]);
    assert.equal(r.count, 1);
    const r2 = evaluateRule(RULE("  selection:\n    Image|endswith: \\\\powershell.exe\n  condition: selection"),
      [{ Image: "C:\\\\windows\\\\powershell.exe" }, { Image: "C:\\\\x.exe" }]);
    assert.equal(r2.count, 1);
  });

  test("condition: selection and not filter", () => {
    const y = RULE("  selection:\n    EventID: 4625\n  filter:\n    user: svc\n  condition: selection and not filter");
    const r = evaluateRule(y, [{ EventID: 4625, user: "alice" }, { EventID: 4625, user: "svc" }]);
    assert.equal(r.count, 1);
    assert.equal(r.matches[0].event.user, "alice");
  });

  test("keyword list (fieldless) matches as substring over all values", () => {
    const r = evaluateRule(RULE("  keywords:\n    - whoami\n    - net group\n  condition: keywords"),
      [{ cmd: "ran whoami /all" }, { cmd: "dir" }]);
    assert.equal(r.count, 1);
  });

  test("keyword wildcards match like Sigma (*mimikatz*, ?)", () => {
    const r = evaluateRule(RULE("  keywords:\n    - '*sekurlsa::*'\n    - 'who?mi'\n  condition: keywords"),
      [{ cmd: "mimikatz SEKURLSA::logonpasswords" }, { cmd: "whoami" }, { cmd: "dir" }]);
    assert.equal(r.count, 2);
  });

  test("refuses a condition it would misread", () => {
    const sel = "  selection:\n    EventID: 4625\n";
    for (const c of ["selection | count() > 5", "selction", "selection and not fliter", "selection*", "(selection", "selection)", "1 of filter*"]) {
      const r = compileRule(RULE(sel + "  condition: " + c));
      assert.equal(r.ok, false, c);
    }
    for (const c of ["selection", "not selection", "1 of sel*", "all of them", "(selection or selection)"]) assert.equal(compileRule(RULE(sel + "  condition: " + c)).ok, true, c);
  });

  test("'1 of selection*' and 'all of them'", () => {
    const y = RULE("  selection_a:\n    EventID: 1\n  selection_b:\n    EventID: 2\n  condition: 1 of selection*");
    const r = evaluateRule(y, [{ EventID: 2 }, { EventID: 3 }]);
    assert.equal(r.count, 1);
    const y2 = RULE("  sel1:\n    a: 1\n  sel2:\n    b: 2\n  condition: all of them");
    const r2 = evaluateRule(y2, [{ a: 1, b: 2 }, { a: 1 }]);
    assert.equal(r2.count, 1);
  });

  test("or / and / parentheses in a condition", () => {
    const y = RULE("  s1:\n    a: 1\n  s2:\n    b: 2\n  s3:\n    c: 3\n  condition: s1 and (s2 or s3)");
    const r = evaluateRule(y, [{ a: 1, c: 3 }, { a: 1 }, { b: 2 }]);
    assert.equal(r.count, 1);
    assert.equal(r.matches[0].index, 0);
  });

  test("nested event fields are reachable by leaf name", () => {
    const r = evaluateRule(RULE("  selection:\n    EventID: 4688\n  condition: selection"),
      [{ winlog: { event_id: 4688, EventID: 4688 } }]);
    assert.equal(r.count, 1);
  });

  test("invalid YAML returns an error, not a throw", () => {
    const r = evaluateRule("title: x\ndetection: : :\n", [{}]);
    assert.equal(r.ok, false);
    assert.ok(r.error);
  });

  test("is deterministic and empty-safe", () => {
    const y = RULE("  selection:\n    EventID: 4625\n  condition: selection");
    assert.equal(evaluateRule(y, []).count, 0);
    assert.equal(JSON.stringify(evaluateRule(y, [{ EventID: 4625 }])), JSON.stringify(evaluateRule(y, [{ EventID: 4625 }])));
  });

  test("a condition identifier that is not a defined selection is false (no Object.prototype leak)", () => {
    // 'constructor' is not a selection; it must be false (was truthy via the plain-object proto chain).
    const y = RULE("  selection:\n    EventID: 4625\n  condition: selection and not constructor");
    assert.equal(compileRule(y).ok, false); // refused up front now
    const rule = { title: "t", detection: { selection: { EventID: 4625 } }, condition: "selection and not constructor", selectionNames: ["selection"] };
    assert.equal(evaluateRule(rule, [{ EventID: 4625 }]).count, 1);
  });

  test("'N of them' requires at least N selections to match", () => {
    const mk = (cond) => RULE("  s1:\n    a: 1\n  s2:\n    b: 2\n  s3:\n    c: 3\n  condition: " + cond);
    const ev = [{ a: 1, b: 2 }]; // s1 and s2 match; s3 does not
    assert.equal(evaluateRule(mk("2 of them"), ev).count, 1, "two match -> fires");
    assert.equal(evaluateRule(mk("3 of them"), ev).count, 0, "only two match -> does not fire");
    assert.equal(evaluateRule(mk("1 of them"), ev).count, 1);
  });
});

group("sigma/wildcards, escapes, exists, unsupported modifiers", () => {
  const R = (sel) => "title: t\ndetection:\n  sel:\n" + sel + "\n  condition: sel\n";
  const n = (sel, e) => evaluateRule(R(sel), [e]).count;
  const img = { Image: "C:\\Windows\\System32\\powershell.exe" };
  test("* and ? are wildcards in plain and modifier values", () => {
    assert.equal(n("    Image: '*\\powershell.exe'", img), 1);
    assert.equal(n("    Image: '*\\cmd.exe'", img), 0);
    assert.equal(n("    Image: 'C:\\Windows\\\\*\\power?hell.exe'", img), 1, "\\\\* is a backslash then a wildcard");
    assert.equal(n("    CommandLine|contains: 'enc*AAA'", { CommandLine: "ps -enc AAA" }), 1);
  });
  test("\\* is a literal star; a backslash before a normal letter stays a backslash", () => {
    assert.equal(n("    User: 'a\\*b'", { User: "a*b" }), 1);
    assert.equal(n("    User: 'a\\*b'", { User: "axb" }), 0);
    assert.equal(n("    Image|endswith: '\\powershell.exe'", img), 1);
  });
  test("exists: true / false", () => {
    assert.equal(n("    Image|exists: true", img), 1);
    assert.equal(n("    Foo|exists: true", img), 0);
    assert.equal(n("    Foo|exists: false", img), 1);
  });
  test("an unimplemented modifier is refused, not evaluated as plain equality", () => {
    const c = compileRule(R("    SrcIp|cidr: 10.0.0.0/8"));
    assert.equal(c.ok, false); assert.ok(/Unsupported field modifier: cidr/.test(c.error));
  });
});
