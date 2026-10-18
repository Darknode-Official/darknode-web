// Control-mapping report (Deck D7). PURE — no DOM, no network, deterministic.
//
// An audit artifact: the workspace's OPEN findings grouped by the compliance controls they
// cite (finding.data.controls = [{framework, id}], set by the tools and the Finding
// contract). For each framework it lists the controls that currently have open findings
// mapped to them, with counts and severity. This reports only what the findings themselves
// assert — it does not reproduce any framework catalogue or guess coverage of controls that
// no finding mentions, so it stays honest and license-clean.
const str = (v) => String(v == null ? "" : v).trim();
const OPEN = new Set(["new", "open", "investigating"]);
const SEV = ["critical", "high", "medium", "low", "info"];
const isFinding = (e) => e && str(e.type).toLowerCase() === "finding";
const isOpen = (e) => OPEN.has(str(e.status).toLowerCase() || "new");
const emptySev = () => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
const sevOf = (e) => { const s = str(e.severity).toLowerCase(); return SEV.includes(s) ? s : "info"; };

/**
 * frameworkMap(entities) -> { frameworks:[{framework, open, bySeverity, controls:[{id, open,
 * bySeverity, findings:[{id,name,severity}]}]}], unmappedOpen, totalOpen }
 * Only open findings are counted. Everything is sorted for a stable, diffable report.
 */
export function frameworkMap(entities) {
  const findings = (Array.isArray(entities) ? entities : []).filter((e) => isFinding(e) && isOpen(e));
  const fw = new Map(); // frameworkLabel -> { controls: Map<id, {findings:[]}> }
  let unmappedOpen = 0;

  for (const e of findings) {
    const controls = Array.isArray(e.data && e.data.controls) ? e.data.controls.filter((c) => c && str(c.id)) : [];
    if (!controls.length) { unmappedOpen++; continue; }
    const seen = new Set(); // one finding counts once per (framework,id)
    for (const c of controls) {
      const label = str(c.framework) || "Unattributed";
      const id = str(c.id);
      const sig = label + "\u0000" + id;
      if (seen.has(sig)) continue; seen.add(sig);
      if (!fw.has(label)) fw.set(label, new Map());
      const ctrls = fw.get(label);
      if (!ctrls.has(id)) ctrls.set(id, []);
      ctrls.get(id).push({ id: e.id, name: str(e.name), severity: sevOf(e) });
    }
  }

  const frameworks = [...fw.entries()].map(([framework, ctrls]) => {
    const controls = [...ctrls.entries()].map(([id, fs]) => {
      const bySeverity = emptySev(); for (const f of fs) bySeverity[f.severity]++;
      fs.sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || String(a.id).localeCompare(String(b.id)));
      return { id, open: fs.length, bySeverity, findings: fs };
    }).sort((a, b) => cmpId(a.id, b.id));
    const bySeverity = emptySev(); let open = 0;
    for (const c of controls) { open += c.open; for (const s of SEV) bySeverity[s] += c.bySeverity[s]; }
    return { framework, open, bySeverity, controls };
  }).sort((a, b) => b.open - a.open || a.framework.localeCompare(b.framework));

  return { frameworks, unmappedOpen, totalOpen: findings.length };
}

// Sort control ids naturally: "6.3.3" before "6.10", "A.5.9" sensibly. Falls back to string.
function cmpId(a, b) {
  const pa = String(a).split(/[.\s]/), pb = String(b).split(/[.\s]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = parseInt(pa[i], 10), nb = parseInt(pb[i], 10);
    const aNum = !Number.isNaN(na) && /^\d+$/.test(pa[i] || ""), bNum = !Number.isNaN(nb) && /^\d+$/.test(pb[i] || "");
    if (aNum && bNum) { if (na !== nb) return na - nb; }
    else { const c = String(pa[i] || "").localeCompare(String(pb[i] || "")); if (c) return c; }
  }
  return 0;
}
