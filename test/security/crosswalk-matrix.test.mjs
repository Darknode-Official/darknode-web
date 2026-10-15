// GenAI Security Crosswalk coverage math (public/js/crosswalk-matrix.js):
// matrix counts, coverage gaps, and coverage breadth — all against the REAL
// public/data/crosswalk.json so the asserted numbers track the shipped data.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { test, assert, group } from "../harness.mjs";
import { buildMatrix, coverageGaps, coverageBreadth } from "../../public/js/crosswalk-matrix.js";

const here = dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(readFileSync(join(here, "../../public/data/crosswalk.json"), "utf8"));
const risks = data.risks;
const frameworks = data.frameworks;

group("crosswalk: buildMatrix (real data)", () => {
  const m = buildMatrix(risks, frameworks);

  test("every risk's row sums to its dataset mapping total", () => {
    let grand = 0;
    for (const r of risks) {
      const row = m.counts[r.id];
      const sum = Object.values(row).reduce((a, b) => a + b, 0);
      assert.equal(sum, r.maps.length, `${r.id}: row sum ${sum} != maps ${r.maps.length}`);
      assert.equal(m.rowTotals[r.id], r.maps.length, `${r.id} rowTotal`);
      grand += sum;
    }
    assert.equal(grand, data.meta.totals.mappings, "grand total matches meta.mappings");
  });

  test("column totals sum to the dataset mapping total", () => {
    const colSum = Object.values(m.colTotals).reduce((a, b) => a + b, 0);
    assert.equal(colSum, data.meta.totals.mappings);
  });

  test("a known risk/framework pair yields the expected count", () => {
    // LLM01 (Prompt Injection) has 3 MITRE ATLAS control mappings in v4.0.0.
    assert.equal(m.counts["LLM01"]["MITRE ATLAS"], 3);
  });

  test("matrix is shaped to the given frameworks only", () => {
    assert.equal(m.frameworks.length, frameworks.length);
    for (const r of risks) assert.equal(Object.keys(m.counts[r.id]).length, frameworks.length);
    assert.ok(m.maxCell >= 1, "maxCell is a positive count");
  });
});

group("crosswalk: coverageGaps (real data)", () => {
  test("gaps + covered == total risks, for every framework", () => {
    for (const f of frameworks) {
      const gaps = coverageGaps(risks, f.name);
      const covered = risks.filter((r) => r.maps.some((m) => m.f === f.name)).length;
      assert.equal(gaps.length + covered, risks.length, `${f.name}: ${gaps.length}+${covered}`);
    }
  });

  test("gaps are a stable Critical-first ordering", () => {
    const rank = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    const gaps = coverageGaps(risks, "DORA");
    for (let i = 1; i < gaps.length; i++) {
      assert.ok((rank[gaps[i - 1].sev] ?? 9) <= (rank[gaps[i].sev] ?? 9), "severity order");
    }
    // Every returned risk genuinely has zero DORA mappings.
    for (const g of gaps) assert.notOk(g.maps.some((m) => m.f === "DORA"), g.id);
  });

  test("an uncovered framework pairing is absent from the matrix row", () => {
    const m = buildMatrix(risks, frameworks);
    const gaps = coverageGaps(risks, "DORA");
    for (const g of gaps) assert.equal(m.counts[g.id]["DORA"], 0, g.id);
  });
});

group("crosswalk: coverageBreadth (real data)", () => {
  test("breadth is within [0, frameworks.length] for every risk", () => {
    for (const r of risks) {
      const b = coverageBreadth(r);
      assert.ok(b >= 0 && b <= frameworks.length, `${r.id} breadth ${b}`);
    }
  });

  test("breadth counts distinct frameworks (LLM01 spans all 26)", () => {
    const r = risks.find((x) => x.id === "LLM01");
    assert.equal(coverageBreadth(r), 26);
  });

  test("breadth matches the matrix row's non-zero column count", () => {
    const m = buildMatrix(risks, frameworks);
    for (const r of risks) {
      const nonzero = Object.values(m.counts[r.id]).filter((n) => n > 0).length;
      assert.equal(coverageBreadth(r), nonzero, r.id);
    }
  });
});

group("crosswalk: edge cases (fixture)", () => {
  const fwx = [{ name: "FW-A" }, { name: "FW-B" }, "FW-C"];
  const fix = [
    { id: "R1", sev: "High", maps: [{ f: "FW-A" }, { f: "FW-A" }, { f: "FW-B" }] },
    { id: "R2", sev: "Critical", maps: [] },
  ];

  test("empty maps -> zero row, zero breadth, counted as a gap", () => {
    const m = buildMatrix(fix, fwx);
    assert.equal(m.rowTotals["R2"], 0);
    assert.deepEqual(m.counts["R2"], { "FW-A": 0, "FW-B": 0, "FW-C": 0 });
    assert.equal(coverageBreadth(fix[1]), 0);
    assert.deepEqual(coverageGaps(fix, "FW-C").map((r) => r.id), ["R2", "R1"]);
  });

  test("duplicate framework mappings accumulate in one cell", () => {
    const m = buildMatrix(fix, fwx);
    assert.equal(m.counts["R1"]["FW-A"], 2);
    assert.equal(m.maxCell, 2);
    assert.equal(coverageBreadth(fix[0]), 2);
  });
});
