// Unit tests for public/js/core/result.js
import { test, group, assert } from "../harness.mjs";
import { ToolResult, RESULT_STATUS, result, ok, empty, error, fromJSON } from "../../public/js/core/result.js";

group("result: construction + status", () => {
  test("ok() builds an OK result then EMPTY if nothing produced", () => {
    const r = ok("scan").done();
    assert.equal(r.status, RESULT_STATUS.EMPTY);
    assert.ok(r.ok);
  });

  test("a result with findings stays OK", () => {
    const r = ok("scan").finding({ title: "x", severity: "low" }).done();
    assert.equal(r.status, RESULT_STATUS.OK);
  });

  test("fail() sets ERROR and captures message", () => {
    const r = ok("scan").fail(new TypeError("boom")).done();
    assert.equal(r.status, RESULT_STATUS.ERROR);
    assert.equal(r.errorInfo.name, "TypeError");
    assert.equal(r.errorInfo.message, "boom");
    assert.notOk(r.ok);
  });

  test("error() factory produces a failed result", () => {
    const r = error("scan", "nope").done();
    assert.equal(r.status, RESULT_STATUS.ERROR);
  });

  test("empty() factory", () => {
    assert.equal(empty("scan").status, RESULT_STATUS.EMPTY);
  });
});

group("result: findings + entities", () => {
  test("findings are normalized", () => {
    const r = ok("t").finding("just a string").finding({ title: "  spaced  ", severity: "bogus", tags: ["A", "b"] });
    assert.equal(r.findings[0].title, "just a string");
    assert.equal(r.findings[0].severity, null);
    assert.equal(r.findings[1].title, "spaced");
    assert.equal(r.findings[1].severity, null); // invalid severity dropped to null
    assert.deepEqual(r.findings[1].tags, ["a", "b"]);
  });

  test("valid entity is added", () => {
    const r = ok("t").entity("IP", "host", { address: "203.0.113.9" }, { severity: "high" });
    assert.equal(r.entities.length, 1);
    assert.equal(r.entities[0].severity, "high");
    assert.equal(r.warnings.length, 0);
  });

  test("invalid entity becomes a warning and downgrades to PARTIAL", () => {
    const r = ok("t").entity("IP", "host", { address: "not-an-ip" });
    assert.equal(r.entities.length, 0);
    assert.equal(r.warnings.length, 1);
    assert.equal(r.status, RESULT_STATUS.PARTIAL);
    assert.ok(r.ok); // partial still counts as ok
  });

  test("maxSeverity picks the highest across findings + entities", () => {
    const r = ok("t")
      .finding({ title: "a", severity: "low" })
      .entity("IP", "h", { address: "10.0.0.1" }, { severity: "critical" });
    assert.equal(r.maxSeverity, "critical");
  });

  test("maxSeverity is null when nothing is rated", () => {
    assert.equal(ok("t").finding("plain").maxSeverity, null);
  });
});

group("result: metrics, timing, serialization", () => {
  test("metric + metrics_ merge", () => {
    const r = ok("t").metric("a", 1).metrics_({ b: 2, c: 3 });
    assert.deepEqual(r.metrics, { a: 1, b: 2, c: 3 });
  });

  test("durationMs is non-negative after done()", () => {
    const r = ok("t").done();
    assert.ok(r.durationMs >= 0);
  });

  test("toJSON round-trips through fromJSON", () => {
    const r = ok("t").summary("hi").metric("n", 5)
      .finding({ title: "f", severity: "medium" })
      .entity("IP", "h", { address: "10.0.0.1" })
      .metaData({ ctx: "case-1" })
      .done();
    const j = r.toJSON();
    assert.equal(j.tool, "t");
    assert.equal(j.summary, "hi");
    assert.equal(j.maxSeverity, "medium");
    const back = fromJSON(j);
    assert.equal(back.tool, "t");
    assert.equal(back.summaryText, "hi");
    assert.equal(back.findings.length, 1);
    assert.equal(back.entities.length, 1);
    assert.equal(back.metrics.n, 5);
    assert.equal(back.meta.ctx, "case-1");
  });

  test("toText produces a readable digest", () => {
    const txt = ok("port-scan").summary("3 ports")
      .finding({ title: "SSH open", severity: "medium" })
      .metric("openPorts", 3)
      .done().toText();
    assert.ok(txt.includes("[port-scan]"));
    assert.ok(txt.includes("SSH open"));
    assert.ok(txt.includes("openPorts=3"));
  });

  test("result() factory honors explicit status", () => {
    assert.equal(result("t", RESULT_STATUS.PARTIAL).status, RESULT_STATUS.PARTIAL);
  });
});
