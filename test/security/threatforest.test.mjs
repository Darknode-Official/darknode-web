// ThreatForest engine tests (public/js/threatforest-engine.js).
// Focus: that detection fires on the right line, and that the co-location heuristic
// is HONEST — a sink whose own statement uses untrusted input is "input" (high
// confidence), while a sink merely near a source is "near" and is NOT inflated to
// high (proximity is not call-graph reachability).

import { test, assert, group } from "../harness.mjs";
import { analyze, buildTree, riskScore, detectLangs, flowFindings, edgeWeight, RULES, GOALS } from "../../public/js/threatforest-engine.js";

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
    const f = find("const k = 'AKIAQ3EGRT7XZPLM4NHA';", "secret-aws"); // darknode-ignore: planted fake AWS key id for the detector test
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
    // A source sits a few lines above a sink, but the value that reaches the sink
    // (cfg.code) is unrelated to it, so the taint engine does NOT connect them. The
    // lexical heuristic may only say "near" — proximity, never reachability.
    const code = "const u = req.query.cmd;\nconsole.log('hi');\neval(cfg.code);";
    const f = find(code, "code-eval");
    assert.ok(f, "code-eval should fire");
    assert.ok(f.coloc && f.coloc.level === "near", "expected near-level co-location");
    assert.equal(f.confidence, "medium"); // proximity alone must not claim high confidence
    assert.ok(!f.reach, "co-location alone must never be marked confirmed/reachable");
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

group("threatforest: data-flow confirmation (JS/TS, reuses the taint engine)", () => {
  // A real source -> sink flow: req.query.host is required from child_process and
  // reaches exec() through a local variable. The taint engine traces every step.
  const FLOW = "const { exec } = require('child_process');\n" +
    "app.get('/r', (req, res) => {\n" +
    "  const host = req.query.host;\n" +
    "  exec('ping ' + host);\n" +
    "});";

  test("a traced source->sink flow becomes a CONFIRMED reachable node", () => {
    const f = find(FLOW, "flow.cmd");
    assert.ok(f, "expected a confirmed command-injection flow finding");
    assert.equal(f.confidence, "high");
    assert.ok(f.reach && f.reach.level === "confirmed", "finding must carry reach=confirmed");
    assert.ok(/reachable/i.test(f.reach.text), "reach text should state reachability (it was traced)");
    assert.ok(Array.isArray(f.reach.flow) && f.reach.flow.length >= 2, "the traced path must be cited");
    // the cited path starts at the untrusted source and ends at the sink
    assert.ok(/req\.query\.host/.test(f.reach.flow[0].label), "path should start at the source");
    assert.ok(/shell command/i.test(f.reach.flow[f.reach.flow.length - 1].label), "path should end at the sink");
    assert.ok(f.cwe === "CWE-78" && f.goal === "rce", "confirmed node keeps standard CWE/goal refs");
    assert.ok(/^CAPEC-\d+$/.test(f.capec) && Array.isArray(f.att) && f.att.length && f.stride, "confirmed node carries CAPEC/ATT&CK/STRIDE");
  });

  test("a confirmed flow supersedes the same-CWE lexical sink on that line", () => {
    const res = analyze(FLOW);
    const onSink = res.findings.filter((f) => f.line === 4 && f.cwe === "CWE-78");
    assert.equal(onSink.length, 1, "only the confirmed flow should remain for CWE-78 on the sink line");
    assert.equal(onSink[0].rid, "flow.cmd");
    assert.ok(res.confirmed >= 1, "analyze reports a confirmed count");
  });

  test("a chained flow through several assignments is still confirmed", () => {
    // req.query.cmd -> u -> x -> y -> eval(y): taint follows the whole chain.
    const f = find("const u = req.query.cmd;\nconst x = u;\nconst y = x;\neval(y);", "flow.code");
    assert.ok(f && f.reach, "multi-step flow should be confirmed");
    assert.ok(f.reach.steps >= 3, "the path should record the intermediate steps");
  });

  test("co-location WITHOUT a traceable flow is never confirmed", () => {
    // The source and the eval are near each other, but eval's argument is unrelated.
    const res = analyze("const u = req.query.cmd;\nconsole.log('hi');\neval(cfg.code);");
    assert.ok(!res.findings.some((f) => f.reach), "no finding may be confirmed when nothing was traced");
    assert.equal(res.confirmed, 0);
  });

  test("a sanitized flow is NOT confirmed (guarded code stays quiet)", () => {
    const code = "const { exec } = require('child_process');\n" +
      "app.get('/r', (req, res) => { const h = parseInt(req.query.host, 10); exec('ping ' + h); });";
    assert.equal(flowFindings(code).length, 0, "numeric conversion stops the flow, so nothing is confirmed");
    assert.ok(!analyze(code).findings.some((f) => f.reach));
  });

  test("confirmed findings come only from flow; reach is absent on lexical findings", () => {
    for (const f of analyze(FLOW).findings) {
      if (f.reach) { assert.ok(f.rid.startsWith("flow."), "reach only on flow.* findings"); assert.ok(f.reach.flow.length); }
      else assert.ok(!f.reach);
    }
  });

  test("non-JS input still works and is never flow-confirmed (regex only)", () => {
    const php = "<?php\n$id = $_GET['id'];\n$res = mysqli_query($conn, \"SELECT * FROM a WHERE id = $id\");\n$d = unserialize($_POST['b']);\n?>";
    const res = analyze(php);
    assert.ok(res.langs.includes("PHP"));
    assert.ok(res.findings.length >= 1, "regex rules still fire for PHP");
    assert.ok(!res.findings.some((f) => f.reach), "the JS taint engine must not confirm non-JS code");
    assert.equal(res.confirmed, 0);
  });
});

group("threatforest: path ranking (heuristic edge weights)", () => {
  test("every leaf and branch carries a heuristic likelihood in (0,1]", () => {
    const tree = buildTree(analyze("const { exec } = require('child_process');\napp.get('/r',(req,res)=>{ const h=req.query.host; exec('ping '+h); });").findings);
    for (const b of tree.branches) {
      assert.ok(b.weight && b.weight.heuristic === true, "weights are flagged heuristic, not measured");
      assert.ok(b.weight.p > 0 && b.weight.p <= 1, "branch likelihood in (0,1]");
      for (const l of b.leaves) { assert.ok(l.weight.p > 0 && l.weight.p <= 1); assert.ok(l.weight.cost >= 1 && l.weight.cost <= 5); }
    }
  });
  test("a confirmed leaf outranks a mere-proximity leaf of the same severity", () => {
    const confirmed = edgeWeight({ sev: 5, reach: {} });
    const near = edgeWeight({ sev: 5, coloc: { level: "near" } });
    assert.ok(confirmed.p > near.p, "confirmed reachability should weigh more than proximity");
  });
  test("confirmed branches lead within equal severity", () => {
    const tree = buildTree(analyze("const { exec } = require('child_process');\napp.get('/r',(req,res)=>{ const h=req.query.host; exec('ping '+h); });").findings);
    assert.ok(tree.branches[0].confirmed, "a confirmed branch should sort to the front");
  });
});

group("threatforest: risk weighting with confirmed flows", () => {
  test("a confirmed flow outweighs a high-confidence lexical hit of equal severity", () => {
    const confirmed = riskScore([{ sev: 5, confidence: "high", reach: {} }]);
    const lexHigh = riskScore([{ sev: 5, confidence: "high" }]);
    assert.ok(confirmed.score > lexHigh.score, "taint-confirmed evidence should score higher");
    assert.equal(confirmed.score, 42); // 28 * 1.5
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
