// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Posture metrics over the security graph, counting REAL data only.
//
// Several tools write training/sample data into the shared graph (CRUCIBLE war-games,
// ORACLE built-in IOCs, PHANTOM demo captures, CITADEL example alerts, AEGIS sample
// flows). That data is useful inside those tools but must never move a posture number,
// so every Deck metric goes through these pure helpers instead of getStats().

export const SIM_TAGS = ["simulated", "sample"];

export function isSimulated(e) {
  if (!e) return false;
  const tags = (e.tags || []).map((t) => String(t).toLowerCase());
  if (tags.some((t) => SIM_TAGS.includes(t))) return true;
  if (e.data && e.data.simulated === true) return true;
  // AEGIS flow findings pushed before they were tagged come only from its built-in sample.
  if (tags.includes("aegis") && tags.includes("flow")) return true;
  return false;
}

export const realEntities = (list) => (list || []).filter((e) => !isSimulated(e));

// Same shape as security-graph getStats(), over real entities only, plus a count of
// what was excluded so the UI can say so. Relationships count only when both ends are real.
export function postureStats(entities, relationships) {
  const all = entities || [];
  const real = realEntities(all);
  const ids = new Set(real.map((e) => e.id));
  const byType = {}, byStatus = {}, bySeverity = {};
  for (const e of real) {
    byType[e.type] = (byType[e.type] || 0) + 1;
    const st = e.status || "none";
    byStatus[st] = (byStatus[st] || 0) + 1;
    const sv = e.severity || "none";
    bySeverity[sv] = (bySeverity[sv] || 0) + 1;
  }
  const totalRelationships = (relationships || []).filter((r) => ids.has(r.fromId) && ids.has(r.toId)).length;
  return { totalEntities: real.length, totalRelationships, byType, byStatus, bySeverity, simulated: all.length - real.length };
}
