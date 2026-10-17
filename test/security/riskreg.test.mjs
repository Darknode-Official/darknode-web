// Risk Register engine tests (public/js/risk/riskreg-engine.js): self-test,
// determinism and empty-input safety.

import { test, assert, group } from "../harness.mjs";
import { selfTest, analyze, parseInput, exampleDataset } from "../../public/js/risk/riskreg-engine.js";

group("riskreg: engine", () => {
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });

  test("analyze is deterministic", () => {
    const { rows } = exampleDataset();
    assert.deepEqual(analyze(rows), analyze(rows));
  });

  test("empty input yields zero findings and does not throw", () => {
    const parsed = parseInput("");
    assert.equal(parsed.rows.length, 0);
    const r = analyze(parsed.rows);
    assert.equal(r.findings.length, 0);
    assert.equal(r.meta.rows, 0);
  });
});
