// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Daily AI message limits. Every chat on the built-in AI runs on the owner's keys, so
// each caller gets a number of messages per UTC day by plan, and Claude (the costliest)
// has its own smaller allowance inside that. Administrators (the admin custom claim)
// are never limited. Counts live in the RATE Durable Object's storage so they survive
// eviction; signed-in callers are counted per account, everyone else per IP address.
// The website and the desktop app share this Worker, so one rule covers both.

export const DAILY_MESSAGES = { anonymous: 20, free: 50, pro: 500, team: 1000, business: 1000, enterprise: 2000 };
export const DAILY_CLAUDE = { anonymous: 0, free: 15, pro: 150, team: 300, business: 300, enterprise: 500 };

export const isExempt = (principal) => !!(principal && principal.claims && principal.claims.admin === true);

// "anonymous" for callers who are not signed in, else their plan.
export const quotaTier = (principal, tier) => (principal && principal.kind === "user" ? String(tier || "free").toLowerCase() : "anonymous");

export function dailyLimit(kind, tierName) {
  const table = kind === "claude" ? DAILY_CLAUDE : DAILY_MESSAGES;
  return table[tierName] ?? table.free;
}

export const utcDay = (now = Date.now()) => new Date(now).toISOString().slice(0, 10);
export const secondsToReset = (now = Date.now()) => {
  const d = new Date(now);
  return Math.max(1, Math.ceil((Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1) - now) / 1000));
};

// Storage-side step, run inside the Durable Object (single-threaded per id, so the
// read-then-write cannot race). -> { ok, used, limit }
export async function takeQuota(storage, day, limit) {
  const key = "q:" + day;
  const used = (await storage.get(key)) | 0;
  if (used >= limit) return { ok: false, used, limit };
  await storage.put(key, used + 1);
  // First message of a new day: earlier days' counters are no longer needed.
  if (used === 0) for (const k of (await storage.list({ prefix: "q:" })).keys()) if (k !== key) await storage.delete(k);
  return { ok: true, used: used + 1, limit };
}

// In-memory fallback for when the Durable Object is unreachable (per isolate, so a
// little generous, but it keeps a hard ceiling instead of failing open).
const _mem = new Map();
function takeLocal(id, day, limit) {
  const k = id + "|" + day, used = _mem.get(k) | 0;
  if (_mem.size > 20000) _mem.clear();
  if (used >= limit) return { ok: false, used, limit };
  _mem.set(k, used + 1);
  return { ok: true, used: used + 1, limit };
}

// Count one message. -> null when exempt, else { ok, used, limit, remaining, resetIn }.
export async function chargeQuota(env, principal, ip, kind, tier, now = Date.now()) {
  if (isExempt(principal)) return null;
  const tierName = quotaTier(principal, tier);
  const limit = dailyLimit(kind, tierName);
  const who = principal && principal.kind === "user" && principal.uid ? "u:" + principal.uid : "ip:" + (ip || "unknown");
  const id = "quota:" + kind + ":" + who, day = utcDay(now);
  let out;
  if (limit <= 0) out = { ok: false, used: 0, limit: 0 };
  else if (env && env.RATE) {
    try {
      const res = await env.RATE.get(env.RATE.idFromName(id)).fetch("https://rate/quota?limit=" + limit + "&day=" + day);
      out = await res.json();
    } catch (_) { out = takeLocal(id, day, limit); }
  } else out = takeLocal(id, day, limit);
  return { ...out, tier: tierName, remaining: Math.max(0, limit - (out.used | 0)), resetIn: secondsToReset(now) };
}

export function quotaMessage(kind, q) {
  const hours = Math.max(1, Math.round(q.resetIn / 3600));
  const when = "It resets in about " + hours + (hours === 1 ? " hour" : " hours") + " (midnight UTC).";
  if (kind === "claude") {
    if (q.tier === "anonymous") return "Sign in to use Claude models.";
    return "You have used today's " + q.limit + " Claude messages. " + when + " Pick another model, or upgrade under Plans for more.";
  }
  if (q.tier === "anonymous") return "You have used today's " + q.limit + " free AI messages. Sign in for more, or try again later. " + when;
  return "You have used today's " + q.limit + " AI messages. " + when + " Upgrade under Plans for more.";
}

export function _resetLocalQuota() { _mem.clear(); }
