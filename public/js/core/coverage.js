// Coverage-gap findings (Deck D2). PURE — no DOM, no network, no graph writes.
//
// The coverage matrix (core/resolve.coverageMatrix) shows which control sources
// observed each host and identity; a "No" is a blind spot. This turns a blind spot
// into a deterministic, citable FINDING so it enters the work queue (owner, SLA,
// closure) instead of only being displayed. Idempotent: a stable title + category +
// asset yields a stable findingKey, and publishing the COMPLETE current set lets the
// sink auto-resolve a gap once the source that fills it appears.
//
// HONESTY / ANTI-NOISE: a gap is only raised as a finding when the subject is already
// in scope for that control — a host is only flagged "no backup" when another source
// proves it is a managed host (scanned or fleet-enrolled), never because a DNS record
// or a one-off observation lacks a backup. Each `finding:true` area declares which
// other coverage it requires as that proof. Areas with `finding:false` show in the
// matrix but never become findings (their absence is expected, not a risk).
import { coverageMatrix } from "./resolve.js";
import { controlsFromRefs } from "./sink-map.js";

// Control areas for hosts. `sources` are the real Deck tools that cover the area;
// `requires` are the other area ids, at least one of which must be covered for a gap
// to count as in-scope; `refs` cite CIS Controls v8 and ISO/IEC 27001:2022 Annex A.
export const ASSET_COV = [
  { id: "vuln", label: "Vuln scan", sources: ["vulnimport", "netexposure"],
    finding: true, requires: ["endpoint"], sev: "medium",
    refs: ["CIS v8 7.1", "ISO 27001 A.8.8"],
    what: "is enrolled in the fleet/endpoint tool but has never been vulnerability-scanned",
    fix: "Add the host to the vulnerability-management scope (Vulnerability Import or Attack Surface)." },
  { id: "endpoint", label: "Endpoint / fleet", sources: ["fleetcomply"],
    finding: true, requires: ["vuln"], sev: "medium",
    refs: ["CIS v8 1.1", "CIS v8 10.1"],
    what: "is scanned for vulnerabilities but is not enrolled in the fleet/endpoint tool, so its configuration and malware defences are not visible",
    fix: "Enrol the host in the fleet/endpoint tool (Fleet Compliance)." },
  { id: "backup", label: "Backup", sources: ["backupready"],
    finding: true, requires: ["vuln", "endpoint"], sev: "high",
    refs: ["CIS v8 11.2", "ISO 27001 A.8.13"],
    what: "is a managed host with no backup coverage, so it could not be recovered after ransomware or data loss",
    fix: "Bring the host into a backup policy with a tested restore (Backup Readiness)." },
  { id: "exposure", label: "External exposure", sources: ["domainguard", "posture", "tlsfleet", "netexposure"],
    finding: false },
];

// Control areas for identities.
export const IDENTITY_COV = [
  { id: "idp", label: "Identity provider", sources: ["signins", "caaudit"],
    finding: true, requires: ["review", "priv"], sev: "medium",
    refs: ["CIS v8 5.1", "ISO 27001 A.5.16"],
    what: "appears in access-review or privileged-access data but has no identity-provider presence, so it is not governed by conditional access or sign-in monitoring",
    fix: "Reconcile the account with the identity provider, or disable it if it is an unmanaged local account." },
  { id: "review", label: "Access review", sources: ["accessreview", "jml"],
    finding: true, requires: ["idp"], sev: "high",
    refs: ["CIS v8 5.1", "ISO 27001 A.5.9"],
    what: "signs in through the identity provider but is not reconciled against access review or HR, so it may be an orphan or leaver account",
    fix: "Include the identity in access review and reconcile it against HR (Access Review / Joiner-Mover-Leaver)." },
  { id: "priv", label: "Privileged access", sources: ["privaudit", "nhi"],
    finding: false },
];

// coverageFindings(assets, identities) -> Finding[] (the core/sink Finding contract).
// Deterministic: areas then rows, stable titles, no timestamps or randomness. The
// affected asset carries the resolved subject's own type and name, so the finding
// links to the existing inventory entity (merge by type + name) rather than creating
// a duplicate; refs are pre-converted to the sink's control shape.
export function coverageFindings(assets, identities) {
  return gapsFor(assets || [], ASSET_COV, "host", (r) => r.type || "ASSET")
    .concat(gapsFor(identities || [], IDENTITY_COV, "identity", () => "IDENTITY"));
}

function gapsFor(rows, cats, kind, typeOf) {
  const cov = coverageMatrix(rows, cats);
  const out = [];
  for (const cat of cats) {
    if (!cat.finding) continue;
    const req = cat.requires || [];
    const controls = controlsFromRefs(cat.refs);
    rows.forEach((row, i) => {
      const cover = (cov[i] && cov[i].cover) || {};
      if (cover[cat.id]) return;                                  // area covered — no gap
      if (req.length && !req.some((r) => cover[r])) return;       // subject not in scope for this control
      const name = row.name;
      out.push({
        title: cat.label + " coverage gap: " + name,
        severity: cat.sev,
        category: "coverage-gap",
        assets: [{ type: typeOf(row), name: name }],
        controls: controls,
        description: "This " + kind + " " + cat.what + ".",
        recommendation: cat.fix,
        confidence: "likely",
      });
    });
  }
  return out;
}
