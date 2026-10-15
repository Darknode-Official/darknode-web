/**
 * DARKNODE — GenAI Security Crosswalk: coverage math (pure, no DOM).
 *
 * Deterministic matrix / gap computations split out so they can be unit-tested
 * on plain Node (see test/security/crosswalk-matrix.test.mjs) without a browser.
 * Everything is derived from the real crosswalk dataset — nothing fabricated.
 */

const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const fwName = (f) => (typeof f === "string" ? f : f && f.name);

/**
 * Coverage matrix: per-(risk, framework) control-mapping counts.
 * @param {Array} risks       dataset risks (each with .id and .maps:[{f,...}])
 * @param {Array} frameworks  framework list (objects with .name, or plain names)
 * @returns {{counts:Object, rowTotals:Object, colTotals:Object, frameworks:string[], maxCell:number}}
 *   counts[riskId][frameworkName] = number of control mappings for that pair
 *   rowTotals[riskId]            = total mappings for that risk (whole dataset)
 *   colTotals[frameworkName]     = total mappings for that framework (over given risks)
 *   maxCell                      = largest single-cell count (for heatmap scaling)
 */
export function buildMatrix(risks, frameworks) {
  const names = (frameworks || []).map(fwName).filter(Boolean);
  const counts = {}, rowTotals = {}, colTotals = {};
  names.forEach((n) => { colTotals[n] = 0; });
  let maxCell = 0;
  for (const r of risks || []) {
    const row = {};
    names.forEach((n) => { row[n] = 0; });
    let total = 0;
    for (const m of r.maps || []) {
      total++;
      if (Object.prototype.hasOwnProperty.call(row, m.f)) {
        row[m.f]++;
        colTotals[m.f]++;
        if (row[m.f] > maxCell) maxCell = row[m.f];
      }
    }
    counts[r.id] = row;
    rowTotals[r.id] = total;
  }
  return { counts, rowTotals, colTotals, frameworks: names, maxCell };
}

/**
 * Risks with ZERO control mappings to the given framework, Critical-first.
 * @param {Array} risks
 * @param {string} frameworkName
 * @returns {Array} the uncovered risk objects, sorted by severity then id
 */
export function coverageGaps(risks, frameworkName) {
  return (risks || [])
    .filter((r) => !(r.maps || []).some((m) => m.f === frameworkName))
    .slice()
    .sort((a, b) =>
      ((SEV_RANK[a.sev] ?? 9) - (SEV_RANK[b.sev] ?? 9)) ||
      String(a.id).localeCompare(String(b.id)));
}

/**
 * Number of DISTINCT frameworks that cover a risk (>=1 control mapping).
 * @param {Object} risk
 * @returns {number}
 */
export function coverageBreadth(risk) {
  const s = new Set();
  for (const m of (risk && risk.maps) || []) if (m.f) s.add(m.f);
  return s.size;
}
