// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Paid AI models. The most expensive models run on the owner's own Anthropic and Google
// keys, so they are reserved for paid plans and the check is made HERE, on the server;
// the browser only hides them.
//
// The plan is the `tier` field on users/{uid}. Only the owner can write it (firestore.rules
// blocks self-escalation), and the Deck reads the same field. A custom claim (`plan`/`tier`)
// or the admin claim also counts. The doc is read with the CALLER'S OWN ID token (users may
// read their own doc) and cached per uid briefly. A failed read counts as free: failing open
// here would hand out the expensive models.

// Every model the built-in proxy will run on the owner's Gemini key (anything else is
// refused, so a client can't pick an arbitrary, pricier model), and the plan each needs.
export const GEMINI_MODELS = new Map([
  ["gemini-flash-latest", "free"],
  ["gemini-3.5-flash", "free"],
  ["gemini-flash-lite-latest", "free"],
  ["gemini-3.1-flash-lite", "free"],
  ["gemini-3.8-flash", "pro"],
]);

// Claude on the owner's Anthropic key: the plan each model needs.
export const CLAUDE_PLAN = new Map([
  ["claude-fable-5-1", "pro"],
  ["claude-opus-5-5", "pro"],
  ["claude-sonnet-5-5", "free"],
  ["claude-haiku-5-5", "free"],
]);

const RANK = { free: 0, pro: 1, team: 2, business: 3, enterprise: 4 };
export const planRank = (t) => RANK[String(t || "").toLowerCase()] ?? 0;
export const PLAN_LABEL = { pro: "Pro", team: "Team", enterprise: "Enterprise" };

const TTL_MS = 60 * 1000;
const _cache = new Map(); // uid -> { at, tier }

const USER_DOC = (projectId, uid) =>
  "https://firestore.googleapis.com/v1/projects/" + projectId +
  "/databases/(default)/documents/users/" + encodeURIComponent(uid) + "?mask.fieldPaths=tier";

// -> "free" | "pro" | "team" | "enterprise" ...
export async function userTier(projectId, principal, opts = {}) {
  const claims = (principal && principal.claims) || {};
  if (claims.admin === true) return "enterprise";
  const claimed = claims.plan || claims.tier;
  if (claimed && planRank(claimed) > 0) return String(claimed).toLowerCase();
  if (!projectId || !principal || !principal.uid || !principal.token) return "free";
  const cache = opts.cache || _cache, now = opts.now ?? Date.now();
  const hit = cache.get(principal.uid);
  if (hit && now - hit.at < TTL_MS) return hit.tier;
  let tier = "free";
  try {
    const r = await (opts.fetch || fetch)(USER_DOC(projectId, principal.uid), { headers: { Authorization: "Bearer " + principal.token } });
    if (r.ok) {
      const d = await r.json();
      const v = d && d.fields && d.fields.tier && d.fields.tier.stringValue;
      if (v && planRank(v) > 0) tier = v.toLowerCase();
    }
  } catch (_) { /* counts as free */ }
  if (cache.size > 5000) cache.clear();
  cache.set(principal.uid, { at: now, tier });
  return tier;
}

// null when allowed, else the message to show.
export function planDenied(need, tier) {
  if (planRank(tier) >= planRank(need)) return null;
  return "This model is part of the " + (PLAN_LABEL[need] || need) + " plan. Pick another model, or request an upgrade under Plans.";
}

export function _resetPlanCache() { _cache.clear(); }
