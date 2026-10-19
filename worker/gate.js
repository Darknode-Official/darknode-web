// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Server-enforced access suspension (Trident Phase 1).
//
// A banned email is blocked at sign-in on the client (auth.js accessAllowed), but that
// only signs the browser out: a banned user still holds a valid Firebase ID token for up
// to ~1h and could suppress the client sign-out and keep calling the worker (graph, vault,
// monitors, ingest keys). The ban is not real until the SERVER refuses them. This enforces
// it: every Firebase-authed worker route calls isSuspended() right after verifying the
// token, and a suspended principal is rejected with 403.
//
// Single source of truth: the ban list is the SAME document the admin UI already writes
// (Firestore settings/whitelist.banned) — no new store, no new write path. The worker
// reads it with the CALLER'S OWN ID token (that doc is readable by any signed-in user per
// firestore.rules), caches it in-isolate for a short TTL (the list is caller-independent),
// and matches on the lowercased email.
//
// Availability: a Firestore read error FAILS OPEN (treated as "not suspended", but any
// previously-loaded ban set is retained). Failing closed would lock out every user on a
// transient Firestore hiccup — worse than a banned user keeping access for up to one cache
// TTL, especially since the client sign-out still fires immediately.
//
// Scope: this guards the authenticated workspace-data routes only. The AI chat endpoints
// are unauthenticated (IP rate-limited, no Firebase token) and are intentionally not gated
// here — suspension is about access to a tenant's data, not the free assistant.

const BAN_DOC = (projectId) =>
  "https://firestore.googleapis.com/v1/projects/" + projectId +
  "/databases/(default)/documents/settings/whitelist";

const TTL_MS = 60 * 1000; // a ban takes effect server-side within this window, isolate-wide

// Module-level cache: the banned set is identical for every caller, so one isolate-wide
// entry is correct. Tests pass their own `cache` object via opts to stay isolated.
const _cache = { at: 0, set: null };

// Parse the Firestore REST representation of settings/whitelist into a Set of lowercased,
// trimmed emails. Tolerant of a missing doc / field / malformed entries.
export function parseBanned(doc) {
  const vals = doc && doc.fields && doc.fields.banned &&
    doc.fields.banned.arrayValue && doc.fields.banned.arrayValue.values;
  const set = new Set();
  if (Array.isArray(vals)) {
    for (const v of vals) {
      const s = v && typeof v.stringValue === "string" ? v.stringValue.trim().toLowerCase() : "";
      if (s) set.add(s);
    }
  }
  return set;
}

// Load the banned set, serving the cache when fresh. Reads with the caller's token.
async function loadBanned(projectId, token, fetchImpl, now, cache) {
  if (cache.set && now - cache.at < TTL_MS) return cache.set;
  try {
    const r = await fetchImpl(BAN_DOC(projectId), { headers: { Authorization: "Bearer " + token } });
    if (r.status === 404) { cache.set = new Set(); cache.at = now; return cache.set; } // no doc = nobody banned
    if (!r.ok) throw new Error("ban-list read " + r.status);
    const set = parseBanned(await r.json());
    cache.set = set; cache.at = now;
    return set;
  } catch (_) {
    // Fail open for availability: keep the last known set if we have one, else empty.
    // Negative-cache the failure for the TTL so a sustained Firestore outage doesn't make
    // every gated request re-attempt (and possibly stall on) the failing read. A still-known
    // ban keeps biting; a never-loaded gate stays open until Firestore recovers.
    cache.at = now;
    if (!cache.set) cache.set = new Set();
    return cache.set;
  }
}

// True if this principal's access is suspended. `who` is { uid, email } from verifyIdToken.
// opts (for tests): { fetch, now, cache }. In the worker runtime the globals are used.
export async function isSuspended(projectId, who, token, opts = {}) {
  const email = (who && who.email ? String(who.email) : "").trim().toLowerCase();
  if (!email || !projectId) return false; // nothing to match a ban against
  const fetchImpl = opts.fetch || fetch;
  const now = opts.now ?? Date.now();
  const cache = opts.cache || _cache;
  const banned = await loadBanned(projectId, token, fetchImpl, now, cache);
  return banned.has(email);
}

// Test helper: drop the isolate-wide cache.
export function _resetGateCache() { _cache.at = 0; _cache.set = null; }
