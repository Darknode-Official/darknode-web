// Choke-point analysis (Deck D3). PURE — no DOM, no network, no graph writes.
//
// A single weak finding is often a leg in several correlation chains at once: one
// "no MFA" result can feed both an account-takeover chain and a privileged-access
// chain. Fixing that ONE finding breaks every chain it is part of. This module ranks
// findings and subjects by exactly that leverage, so the queue has a defensible
// "fix this first" order.
//
// HONESTY NOTE: this builds only on edges that exist in the graph — the correlation
// chains from core/correlate.js, which are themselves grounded in real findings. It
// does NOT invent host-to-host reachability or identity-to-asset access edges (the
// graph does not carry them), so it never presents a fabricated attack path. If tools
// that emit real reachability/access edges are added later, a true multi-hop path
// search can be layered on top of the same chains.
import { correlate } from "./correlate.js";

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEV_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };

// chokePoints(entities, opts) -> { chains, findings, subjects }
//   chains:  the raw correlation hits (core/correlate output), severity-sorted.
//   findings: [{ findingId, findingTitle, chains:[{ruleId,title,severity}], count,
//               score, maxSeverity }] — one row per finding that is a leg in >=1 chain,
//               ranked by how many chains it breaks (then severity). "count" is the
//               number of distinct chains fixing this finding resolves.
//   subjects: [{ subjectType, subjectKey, subjectName, chains:[...], count, score,
//               maxSeverity }] — hosts / identities ranked by converging chains.
export function chokePoints(entities, opts = {}) {
  const chains = correlate(entities, opts);

  const fMap = new Map();  // findingId -> row
  const sMap = new Map();  // subjectType:subjectKey -> row

  for (const h of chains) {
    const chainRef = { ruleId: h.ruleId, title: h.title, severity: h.severity, attack: h.attack.slice(), subjectName: h.subjectName };

    // per subject
    const sk = h.subjectType + ":" + h.subjectKey;
    if (!sMap.has(sk)) sMap.set(sk, { subjectType: h.subjectType, subjectKey: h.subjectKey, subjectName: h.subjectName, chains: [], count: 0, score: 0, maxSeverity: "info" });
    const srow = sMap.get(sk);
    srow.chains.push(chainRef); srow.count++; srow.score += SEV_WEIGHT[h.severity] || 0;
    if ((SEV_RANK[h.severity] || 0) > (SEV_RANK[srow.maxSeverity] || 0)) srow.maxSeverity = h.severity;

    // per finding leg (dedup a finding within one chain)
    const seen = new Set();
    for (const leg of h.legs) {
      if (seen.has(leg.findingId)) continue; seen.add(leg.findingId);
      if (!fMap.has(leg.findingId)) fMap.set(leg.findingId, { findingId: leg.findingId, findingTitle: leg.findingTitle, chains: [], count: 0, score: 0, maxSeverity: "info" });
      const frow = fMap.get(leg.findingId);
      frow.chains.push(chainRef); frow.count++; frow.score += SEV_WEIGHT[h.severity] || 0;
      if ((SEV_RANK[h.severity] || 0) > (SEV_RANK[frow.maxSeverity] || 0)) frow.maxSeverity = h.severity;
    }
  }

  const rank = (a, b) => b.count - a.count || b.score - a.score || (SEV_RANK[b.maxSeverity] || 0) - (SEV_RANK[a.maxSeverity] || 0);
  const findings = [...fMap.values()].sort((a, b) => rank(a, b) || String(a.findingId).localeCompare(String(b.findingId)));
  const subjects = [...sMap.values()].sort((a, b) => rank(a, b) || String(a.subjectKey).localeCompare(String(b.subjectKey)));
  return { chains, findings, subjects };
}
