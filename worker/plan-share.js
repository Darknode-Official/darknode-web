// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Workspace plan sharing: a team workspace owner can let the workspace's members use the
// owner's plan inside that workspace (workspaces/{wid}.sharePlan, written by the owner only,
// see firebase/firestore.rules). Plans stay per-user everywhere else: personal workspaces and
// AI chat always use the caller's own plan.
//
// The Worker never trusts the tier written on the workspace doc. It checks that the person
// who turned sharing on is still the workspace's owner, then reads that person's live plan
// from users/{uid} with the service account (members cannot read another user's profile).
import { userTier, planRank } from "./plan.js";
import { isTeamWorkspaceId, workspaceMemberRole } from "./workspace.js";
import { googleToken } from "./digest.js";

const TTL_MS = 60 * 1000;
const _cache = new Map(); // wid -> { at, tier }  (the tier the workspace lends, "free" if none)

const fsDoc = (projectId, path, mask) =>
  "https://firestore.googleapis.com/v1/projects/" + projectId + "/databases/(default)/documents/" + path
  + mask.map((m, i) => (i ? "&" : "?") + "mask.fieldPaths=" + m).join("");

async function getFields(url, token, fetchImpl) {
  const r = await fetchImpl(url, { headers: { Authorization: "Bearer " + token } });
  if (!r.ok) return null;
  const d = await r.json().catch(() => null);
  return (d && d.fields) || {};
}

// The plan a team workspace lends its members right now. "free" when sharing is off, the
// sharer is no longer the owner, or anything cannot be read. Callers must have already
// checked that the caller is a member of `wid`.
export async function sharedWorkspaceTier(env, wid, principal, opts = {}) {
  const projectId = env.FIREBASE_PROJECT_ID;
  if (!projectId || !isTeamWorkspaceId(wid) || !principal || !principal.token) return "free";
  const cache = opts.cache || _cache, now = opts.now ?? Date.now();
  const hit = cache.get(wid);
  if (hit && now - hit.at < TTL_MS) return hit.tier;
  const f = opts.fetch || fetch;
  let tier = "free";
  try {
    const ws = await getFields(fsDoc(projectId, "workspaces/" + encodeURIComponent(wid), ["sharePlan", "sharePlanBy"]), principal.token, f);
    const by = ws && ws.sharePlan && ws.sharePlan.booleanValue === true && ws.sharePlanBy && ws.sharePlanBy.stringValue;
    if (by && (await workspaceMemberRole(projectId, wid, by, principal.token, f)) === "owner") {
      const sa = await (opts.token || googleToken)(env);
      const u = await getFields(fsDoc(projectId, "users/" + encodeURIComponent(by), ["tier", "admin"]), sa, f);
      if (u && u.admin && u.admin.booleanValue === true) tier = "enterprise";
      else {
        const v = u && u.tier && u.tier.stringValue;
        if (v && planRank(v) > 0) tier = v.toLowerCase();
      }
    }
  } catch (_) { /* nothing shared */ }
  if (cache.size > 5000) cache.clear();
  cache.set(wid, { at: now, tier });
  return tier;
}

// The plan that counts for `principal` inside workspace `wid`: their own, or the workspace
// owner's when the owner shares it and it is higher.
export async function workspaceTier(env, wid, principal, opts = {}) {
  const own = await userTier(env.FIREBASE_PROJECT_ID, principal, { fetch: opts.fetch, now: opts.now, cache: opts.userCache });
  if (!isTeamWorkspaceId(wid)) return own;
  const lent = await sharedWorkspaceTier(env, wid, principal, opts);
  return planRank(lent) > planRank(own) ? lent : own;
}

// The plan behind work that runs with no user request (monitor alarms, API-key ingest): the live
// plan of `uid` (whoever set the work up) inside `wid`, read with the service account. Work set
// up before the creator was recorded falls back to the workspace's owner: the personal
// workspace's own user, or a team workspace's createdBy. null when it cannot be read, so a
// Firestore blip never stops paid work; callers treat null as allowed.
const _live = new Map(); // wid|uid -> { at, tier }
export async function liveTier(env, wid, uid, opts = {}) {
  const projectId = (env || {}).FIREBASE_PROJECT_ID;
  if (!projectId || !wid) return null;
  const cache = opts.cache || _live, now = opts.now ?? Date.now(), ck = wid + "|" + (uid || "");
  const hit = cache.get(ck);
  if (hit && now - hit.at < TTL_MS) return hit.tier;
  const f = opts.fetch || fetch;
  try {
    const sa = await (opts.token || googleToken)(env);
    if (!uid) {
      if (!isTeamWorkspaceId(wid)) uid = wid;
      else { const w = await getFields(fsDoc(projectId, "workspaces/" + encodeURIComponent(wid), ["createdBy"]), sa, f); uid = w && w.createdBy && w.createdBy.stringValue; if (!uid) return null; }
    }
    const r = await f(fsDoc(projectId, "users/" + encodeURIComponent(uid), ["tier", "admin"]), { headers: { Authorization: "Bearer " + sa } });
    if (!r.ok && r.status !== 404) return null; // 404 = no profile = free
    const u = r.ok ? (((await r.json().catch(() => null)) || {}).fields || {}) : {};
    const v = u.tier && u.tier.stringValue;
    let tier = u.admin && u.admin.booleanValue === true ? "enterprise" : (v && planRank(v) > 0 ? v.toLowerCase() : "free");
    if (isTeamWorkspaceId(wid)) { const lent = await sharedWorkspaceTier(env, wid, { token: sa }, { fetch: opts.fetch, now: opts.now, token: opts.token, cache: opts.shareCache }); if (planRank(lent) > planRank(tier)) tier = lent; }
    if (cache.size > 5000) cache.clear();
    cache.set(ck, { at: now, tier });
    return tier;
  } catch (_) { return null; }
}

export const _resetShareCache = () => { _cache.clear(); _live.clear(); }; // tests
