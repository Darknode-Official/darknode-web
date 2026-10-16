// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// Entitlements: a pure, side-effect-free model of what each plan tier unlocks.
//
// The tier is set server-side only — a Firebase custom claim or an owner-written
// `tier` field on the user doc (Security Rules block self-escalation of `tier`).
// This module never decides a tier; it only ranks and answers `can(...)` so the UI
// can show honest locks. Gated FEATURES are forward-looking capabilities (cloud
// sync, shared workspaces, server-enforced Treasury, integrations) — nothing that
// already works for free today is gated here.

export const TIERS = ["free", "pro", "team", "enterprise"];

export const PLAN_LABEL = { free: "Free", pro: "Pro", team: "Team", enterprise: "Enterprise" };

// feature key -> the lowest tier that unlocks it.
export const FEATURES = {
  cloudSync: "pro",          // findings/reports synced across devices
  unlimitedReports: "pro",   // unlimited saved findings & reports
  priorityAI: "pro",         // higher AI limits
  teamWorkspaces: "team",    // shared workspaces & roles
  vaultServerEnforced: "team", // server-enforced VAULT approvals & audit
  integrations: "team",      // SIEM / ticketing / chat connectors
  sso: "team",               // Google SSO & activity log
  selfHosted: "enterprise",  // private / self-hosted deployment
  samlScim: "enterprise",    // SAML SSO, SCIM
  compliancePack: "enterprise",
};

// numeric limits per tier (−1 = unlimited).
export const LIMITS = {
  seats:      { free: 1, pro: 1, team: 25, enterprise: -1 },
  workspaces: { free: 1, pro: 1, team: 5,  enterprise: -1 },
};

// Normalise any input into a known tier string.
export function normTier(tier) {
  const t = String(tier || "").toLowerCase().trim();
  return TIERS.includes(t) ? t : "free";
}

// Resolve the effective tier from ID-token claims (or a plain field value). The
// owner is always treated as the top tier. Accepts a claims object, a tier string,
// or { tier, entitlements, admin }.
export function tierFrom(source, isOwner) {
  if (isOwner) return "enterprise";
  if (!source) return "free";
  if (typeof source === "string") return normTier(source);
  if (source.admin === true) return "enterprise";
  const ent = source.entitlements;
  const raw = (ent && (ent.tier || ent)) || source.tier || source.plan;
  return normTier(raw);
}

export const rank = (tier) => {
  const i = TIERS.indexOf(normTier(tier));
  return i < 0 ? 0 : i;
};

// Does `tier` unlock `feature`? Unknown features are treated as available (we never
// invent a lock that isn't declared above).
export function can(tier, feature) {
  const need = FEATURES[feature];
  if (!need) return true;
  return rank(tier) >= rank(need);
}

// The minimum tier required for a feature (for "Upgrade to X" copy), or null.
export function requiredTier(feature) {
  return FEATURES[feature] || null;
}

// Numeric limit for a tier, −1 meaning unlimited. Unknown keys return −1.
export function limit(tier, key) {
  const row = LIMITS[key];
  if (!row) return -1;
  const v = row[normTier(tier)];
  return v === undefined ? -1 : v;
}

export const planLabel = (tier) => PLAN_LABEL[normTier(tier)] || "Free";
