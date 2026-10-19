// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Relationship semantics: constrain which entity types a relationship may join.
// A rule is { from: [types]|"*", to: [types]|"*" }. "*" means any entity type.
// This turns the flat RELATIONSHIP_TYPES list into a typed, checkable graph.
//
// PURE and import-free on purpose: security-graph.js enforces these rules in
// createRelationship, core/entities.js re-exports them, and core/sink-map.js uses
// them to pick a valid link type. entities.js imports security-graph.js, so the
// rules cannot live there without a circular import.
//
// Additions made when enforcement was switched on (each is a combo a real tool
// writes, verified against its source):
//   observed_in.from += ASSET, ENDPOINT : CITADEL links an alert's src/dst host
//                                         (a hostname becomes an ASSET) to the ALERT.
//   attributed_to.from += IP, DOMAIN    : ORACLE attributes IOC IPs / domains to a
//                                         THREAT_ACTOR.

export const ANY = "*";

export const RELATIONSHIP_RULES = {
  related_to: { from: ANY, to: ANY },
  contains: {
    from: ["ASSET", "ENDPOINT", "DOMAIN", "IP", "CASE", "INVESTIGATION", "INCIDENT", "CAMPAIGN", "VENDOR"],
    to: ANY,
  },
  affects: {
    from: ["VULNERABILITY", "MALWARE", "TECHNIQUE", "CAMPAIGN", "THREAT_ACTOR", "INCIDENT", "FINDING"],
    to: ["ASSET", "ENDPOINT", "SOFTWARE", "SERVICE", "DOMAIN", "IP", "IDENTITY", "VENDOR"],
  },
  observed_in: {
    from: ["INDICATOR", "MALWARE", "TECHNIQUE", "IP", "DOMAIN", "ASSET", "ENDPOINT"],
    to: ["EVENT", "ALERT", "INCIDENT", "CASE", "ASSET", "ENDPOINT"],
  },
  attributed_to: {
    from: ["CAMPAIGN", "MALWARE", "INCIDENT", "TECHNIQUE", "INDICATOR", "IP", "DOMAIN"],
    to: ["THREAT_ACTOR"],
  },
  mitigates: {
    from: ["CONTROL", "DETECTION", "PLAYBOOK"],
    to: ["VULNERABILITY", "TECHNIQUE", "MALWARE", "THREAT_ACTOR", "FINDING"],
  },
  exploits: {
    from: ["THREAT_ACTOR", "MALWARE", "CAMPAIGN", "TECHNIQUE"],
    to: ["VULNERABILITY", "SOFTWARE", "SERVICE"],
  },
  targets: {
    from: ["THREAT_ACTOR", "CAMPAIGN", "MALWARE"],
    to: ["ASSET", "ENDPOINT", "DOMAIN", "IP", "SOFTWARE", "IDENTITY", "VENDOR"],
  },
  part_of: { from: ANY, to: ["CASE", "INVESTIGATION", "INCIDENT", "CAMPAIGN", "REPORT"] },
  detected_by: {
    from: ["MALWARE", "TECHNIQUE", "INDICATOR", "VULNERABILITY", "THREAT_ACTOR"],
    to: ["DETECTION", "ALERT", "CONTROL"],
  },
  evidence_for: {
    from: ["EVIDENCE", "EVENT", "ALERT", "INDICATOR", "FINDING"],
    to: ["INCIDENT", "CASE", "INVESTIGATION", "FINDING", "THREAT_ACTOR"],
  },
};

/** Does the rule for `relType` allow `fromType -> toType`? Unknown rel types are not
 *  allowed. Entity-type membership is the caller's check (entities.isValidRelationship). */
export function ruleAllows(relType, fromType, toType) {
  const rule = Object.prototype.hasOwnProperty.call(RELATIONSHIP_RULES, relType) ? RELATIONSHIP_RULES[relType] : null;
  if (!rule) return false;
  return (rule.from === ANY || rule.from.includes(fromType)) && (rule.to === ANY || rule.to.includes(toType));
}
