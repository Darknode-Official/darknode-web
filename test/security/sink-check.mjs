// Shared assertions for tool -> Security Graph sink mappers (core/sink-map.js Finding
// shape). Not a *.test.mjs file, so run.mjs does not pick it up on its own; the tool
// test files call it with two independent runs of the same input.

import { assert } from "../harness.mjs";
import { toEntities, SEVERITIES } from "../../public/js/core/sink-map.js";

/**
 * a, b: mapper output from two separate runs over the same input.
 * Checks required fields, normalised severities, unique + stable ids and titles,
 * stable FINDING entity names, and that sample runs are tagged "sample" throughout.
 */
export function checkSinkFindings(toolId, a, b, { minFindings = 1, needAssets = true } = {}) {
  assert.ok(a.length >= minFindings, `${toolId}: expected at least ${minFindings} findings, got ${a.length}`);
  for (const f of a) {
    assert.ok(typeof f.id === "string" && f.id.length > 0, `${toolId}: id missing`);
    assert.ok(typeof f.title === "string" && f.title.trim().length > 0, `${toolId}: title missing`);
    assert.ok(SEVERITIES.includes(f.severity), `${toolId}: severity not normalised: ${f.severity}`);
    assert.ok(Array.isArray(f.evidence), `${toolId}: evidence not an array`);
    for (const c of f.controls || []) assert.ok(typeof c.framework === "string" && c.id, `${toolId}: bad control ${JSON.stringify(c)}`);
    for (const x of f.assets || []) assert.ok(x.type && String(x.name).trim(), `${toolId}: bad asset ${JSON.stringify(x)}`);
  }
  if (needAssets) assert.ok(a.some((f) => (f.assets || []).length), `${toolId}: no finding links an asset`);
  assert.equal(new Set(a.map((f) => f.id)).size, a.length, `${toolId}: ids not unique`);
  assert.deepEqual(a.map((f) => [f.id, f.title, f.severity]), b.map((f) => [f.id, f.title, f.severity]), `${toolId}: ids/titles not stable across runs`);

  const ra = toEntities(toolId, a), rb = toEntities(toolId, b);
  const names = (r) => r.items.filter((i) => i.type === "FINDING").map((i) => i.name);
  assert.equal(names(ra).length, a.length, `${toolId}: findings collapsed in toEntities`);
  assert.deepEqual(names(ra), names(rb), `${toolId}: FINDING names not stable across runs`);
  assert.ok(ra.items.every((i) => !(i.opts.tags || []).includes("sample")), `${toolId}: real run tagged sample`);

  const rs = toEntities(toolId, a, { sample: true });
  assert.ok(rs.items.length && rs.items.every((i) => (i.opts.tags || []).includes("sample")), `${toolId}: sample run not tagged sample on every entity`);
  return ra;
}
