// ThreatForest engine tests (public/js/threatforest-engine.js).
// Focus: that detection fires on the right line, and that the co-location heuristic
// is HONEST — a sink whose own statement uses untrusted input is "input" (high
// confidence), while a sink merely near a source is "near" and is NOT inflated to
// high (proximity is not call-graph reachability).

import { test, assert, group } from "../harness.mjs";
import { analyze, buildTree, riskScore, detectLangs, RULES, GOALS } from "../../public/js/threatforest-engine.js";

const rids = (code) => analyze(code).findings.map((f) => f.rid);
const find = (code, rid) => analyze(code).findings.find((f) => f.rid === rid);

group("threatforest: rule base integrity", () => {
  test("every rule has a goal that exists in GOALS (or is a source)", () => {
    for (const r of RULES) assert.ok(GOALS[r.g], r.id + " has unknown goal " + r.g);
  });
  test("rule ids are unique", () => {
    const seen = new Set();
    for (const r of RULES) { assert.ok(!seen.has(r.id), "duplicate rule id " + r.id); seen.add(r.id); }
  });
  test("every rule carries CWE/CAPEC/ATT&CK/STRIDE refs", () => {
    for (const r of RULES) {
      assert.ok(/^CWE-\d+$/.test(r.cwe), r.id + " bad cwe");
      assert.ok(/^CAPEC-\d+$/.test(r.capec), r.id + " bad capec");
      assert.ok(Array.isArray(r.att) && r.att.length, r.id + " missing att");
      assert.ok(typeof r.stride === "string" && r.stride, r.id + " missing stride");
    }
  });
});

group("threatforest: detection", () => {
  test("shell command execution fires", () => assert.ok(rids("exec('ls ' + x)").includes("cmd-exec")));
  test("SQL concatenation fires", () => assert.ok(rids('q = "SELECT * FROM u WHERE id=" + id').includes("sqli-concat")));
  test("pickle deserialization fires", () => assert.ok(rids("data = pickle.loads(blob)").includes("deser-pickle")));
  test("AWS key id fires as high confidence", () => {
    const f = find("const k = 'AKIAQ3EGRT7XZPLM4NHA';", "secret-aws");
    assert.ok(f, "secret-aws should fire");
    assert.equal(f.confidence, "high");
  });
  test("weak hash fires", () => assert.ok(rids("hashlib.md5(p)").includes("weak-hash")));
  test("finding reports the correct 1-based line", () => {
    const f = find("line one\nline two\nexec('x ' + y)", "cmd-exec");
    assert.equal(f.line, 3);
  });
});

group("threatforest: co-location honesty (not reachability)", () => {
  test("untrusted input on the sink's own line => input-level, high confidence", () => {
    const f = find("app.get('/p', (req,res)=> exec('ping ' + req.query.host))", "cmd-exec");
    assert.ok(f);
    assert.equal(f.confidence, "high");
    assert.ok(f.coloc && f.coloc.level === "input", "expected input-level co-location");
    assert.ok(/this line/.test(f.coloc.text));
  });

  test("sink merely NEAR a source is 'near' and NOT inflated to high", () => {
    // source on line 1, sink on line 4; the sink's own line has no untrusted token.
    const code = "const u = req.query.cmd;\nconst x = u;\nconst y = x;\neval(y);";
    const f = find(code, "code-eval");
    assert.ok(f, "code-eval should fire");
    assert.ok(f.coloc && f.coloc.level === "near", "expected near-level co-location");
    assert.equal(f.confidence, "medium"); // proximity alone must not claim high confidence
    assert.ok(/near untrusted input/.test(f.coloc.text));
  });

  test("isolated sink with no source nearby has no co-location claim", () => {
    const f = find("const y = 2;\nconst z = 3;\neval(secret);", "code-eval");
    assert.ok(f, "code-eval should fire");
    assert.ok(!f.coloc, "no source nearby => no co-location label");
    assert.equal(f.confidence, "medium");
  });

  test("co-location never labels a finding as proven reachability", () => {
    const code = "app.get('/p', (req,res)=> exec('ping ' + req.query.host))";
    for (const f of analyze(code).findings) {
      if (f.coloc) assert.ok(!/reachab/i.test(f.coloc.text), "must not claim reachability: " + f.coloc.text);
    }
  });
});

group("threatforest: noise control", () => {
  test("csrf-missing is dropped when there is no input source", () => {
    assert.ok(!rids("app.post('/x', fn)").includes("csrf-missing"));
  });
  test("csrf-missing is kept when an input source is present", () => {
    assert.ok(rids("app.post('/x', (req,res)=>{ const a=req.body; })").includes("csrf-missing"));
  });
});

group("threatforest: risk scoring", () => {
  test("high confidence weighs 1.25x a medium one of the same severity", () => {
    const hi = riskScore([{ sev: 5, confidence: "high" }]);
    const med = riskScore([{ sev: 5, confidence: "medium" }]);
    assert.ok(hi.score > med.score, "high confidence should score higher");
    assert.equal(med.score, 28);
    assert.equal(hi.score, 35);
  });
  test("clean code grades A+", () => {
    const r = riskScore([]);
    assert.equal(r.grade, "A+");
    assert.equal(r.score, 0);
  });
  test("score is capped at 100", () => {
    const many = Array.from({ length: 20 }, () => ({ sev: 5, confidence: "high" }));
    assert.ok(riskScore(many).score <= 100);
  });
});

group("threatforest: tree synthesis + language detection", () => {
  test("findings group into goal branches sorted by severity", () => {
    const res = analyze("exec('ls ' + x)\nq = 'SELECT * FROM u WHERE id=' + id");
    const tree = buildTree(res.findings);
    assert.equal(tree.root, "Compromise the application");
    assert.ok(tree.branches.length >= 1);
    // branches are sorted by descending severity
    for (let i = 1; i < tree.branches.length; i++) assert.ok(tree.branches[i - 1].sev >= tree.branches[i].sev);
  });
  test("detectLangs recognises Python and JavaScript", () => {
    assert.ok(detectLangs("def foo():\n    print('x')").includes("Python"));
    assert.ok(detectLangs("const x = () => 1; console.log(x)").includes("JavaScript"));
  });
});
