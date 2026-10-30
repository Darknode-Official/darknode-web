// Copyright (c) 2026 Darknode-Official. All rights reserved.
//
// Last-writer-wins (LWW) merge for the cloud-synced security graph. PURE: no DOM, no
// storage, no network — so the same logic runs in the browser (applying remote changes
// into the local graph), in the Cloudflare worker's GraphDO (merging pushes), and in
// tests. This is the security-graph's `ledger.js`: the one place the convergence rule
// lives.
//
// A record is a plain object with a string `id` and an ISO-8601 ordering key — for
// entities that is `updatedAt`, for relationships `createdAt` (relationships are
// immutable, so their only "update" is a tombstone). A deletion is carried as a
// tombstone record: { id, deleted: true, updatedAt: <iso> }. Because every record,
// live or tombstone, competes on the same clock, deletes converge like any other edit.
//
// LWW by a client-set wall-clock timestamp means a device with a badly skewed clock can
// win a conflict it shouldn't. That is the accepted, documented trade-off of a
// local-first graph (the same one every offline-first store makes); it is NOT used for
// anything with integrity requirements — money stays in VAULT, which is server-authored.

// The ordering key of a record, as a string ("" sorts before any real timestamp).
export function orderKey(rec, key) {
  if (!rec) return "";
  const v = rec[key];
  return typeof v === "string" ? v : (v == null ? "" : String(v));
}

// Should `incoming` replace `existing` under LWW? A strictly-later timestamp wins.
// On an exact tie we keep `existing` (stable — no needless churn), except a tombstone
// beats a live record of the same timestamp so a delete is not silently resurrected.
export function wins(incoming, existing, key) {
  if (!incoming) return false;
  if (!existing) return true;
  const si = orderKey(incoming, key), se = orderKey(existing, key);
  // Compare the actual instant when both are parseable timestamps, so equal instants with
  // different serializations ("…Z" vs "…000Z", a +NN:NN offset) are a true tie rather than
  // ordered by string bytes. Fall back to raw string compare otherwise ("" < any real value,
  // and non-date ordering keys still work).
  const pi = Date.parse(si), pe = Date.parse(se);
  if (!Number.isNaN(pi) && !Number.isNaN(pe)) {
    if (pi > pe) return true;
    if (pi < pe) return false;
  } else {
    if (si > se) return true;
    if (si < se) return false;
  }
  return !!incoming.deleted && !existing.deleted;
}

// Merge a list of incoming records into a map keyed by id, in place. Returns the ids
// that actually changed, so a caller can bump a revision or emit events for only those.
export function mergeList(map, incoming, key) {
  const changed = [];
  for (const rec of incoming || []) {
    // "__proto__" would hit the prototype setter (re-parenting the map instead of storing a
    // record) and an inherited name ("toString") would read a function as the existing record.
    if (!rec || typeof rec.id !== "string" || !rec.id || rec.id === "__proto__") continue;
    if (wins(rec, Object.prototype.hasOwnProperty.call(map, rec.id) ? map[rec.id] : undefined, key)) { map[rec.id] = rec; changed.push(rec.id); }
  }
  return changed;
}

// Live (non-tombstone) values of a record map, for handing back to callers that only
// care about present records.
export function liveValues(map) {
  const out = [];
  for (const id of Object.keys(map)) { const r = map[id]; if (r && !r.deleted) out.push(r); }
  return out;
}

// Turn a record into its tombstone at time `at` (ISO). Keeps the id and the ordering key
// so the tombstone competes correctly; drops the payload.
export function tombstone(id, at, key) {
  const t = { id, deleted: true };
  t[key] = at;
  return t;
}
