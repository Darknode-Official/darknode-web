// POST /api/account/delete: a signed-in user deletes their own Darknode account, with no
// email to anyone and no manual step. Uses the Worker's service account (FIREBASE_SA).
//
// Order matters, and every step can be retried (a second call finishes a half-done one):
//   1. refuse unless the sign-in is recent (auth_time within RECENT_S) and the body says
//      {confirm: "DELETE"};
//   2. refuse while the user founded a team workspace or vault that still has other members.
//      Those members' work is not theirs to delete; they remove the members first;
//   3. wipe the Durable Objects of the personal workspace (graph, monitors and the free
//      watch, API keys) and of every team workspace or vault they hold alone;
//   4. delete their Firestore records: users/{uid} with its subcollections, usage,
//      deletionRequests, pairings, upgrade/tool requests, feedback, error reports, IP
//      reports, the waitlist entry for their email, and their member docs elsewhere;
//   5. delete the Firebase Auth account last, so a failure earlier leaves a user who
//      can still sign in and try again.
import { googleToken } from "./digest.js";

export const RECENT_S = 300;
const PAGE = 300;

// Collections holding docs the user wrote, and the field that names them.
export const OWNED_BY_FIELD = [
  ["pairings", "uid"], ["upgradeRequests", "uid"], ["toolRequests", "uid"],
  ["feedback", "uid"], ["errors", "uid"], ["ip_reports", "reporter_uid"],
];
// Docs keyed by the user's uid.
export const KEYED_BY_UID = ["usage", "deletionRequests"];

export function recentEnough(claims, now = Math.floor(Date.now() / 1000)) {
  const t = Number(claims && claims.auth_time);
  return Number.isFinite(t) && t > 0 && now - t <= RECENT_S;
}

// A thin Firestore REST client on one access token.
export function firestore(env, token, doFetch = fetch) {
  const root = "https://firestore.googleapis.com/v1/projects/" + env.FIREBASE_PROJECT_ID + "/databases/(default)/documents";
  const H = { Authorization: "Bearer " + token, "Content-Type": "application/json" };
  const ok = async (r, what) => { if (!r.ok && r.status !== 404) throw new Error(what + " failed (HTTP " + r.status + ")"); return r; };
  const name = (path) => "projects/" + env.FIREBASE_PROJECT_ID + "/databases/(default)/documents/" + path;
  const rel = (full) => String(full).split("/documents/")[1] || "";
  const val = (f) => (f ? f.stringValue ?? f.integerValue ?? f.booleanValue ?? null : null);
  return {
    rel, val,
    async del(path) { await ok(await doFetch(root + "/" + path, { method: "DELETE", headers: H }), "Delete " + path); },
    async get(path) {
      const r = await ok(await doFetch(root + "/" + path, { headers: H }), "Read " + path);
      return r.status === 404 ? null : r.json();
    },
    // every doc path in a collection
    async list(path) {
      const out = []; let next = "";
      for (let i = 0; i < 100; i++) {
        const r = await ok(await doFetch(root + "/" + path + "?pageSize=" + PAGE + (next ? "&pageToken=" + encodeURIComponent(next) : ""), { headers: H }), "List " + path);
        if (r.status === 404) break;
        const d = await r.json().catch(() => ({}));
        for (const doc of d.documents || []) out.push({ path: rel(doc.name), fields: doc.fields || {} });
        next = d.nextPageToken || ""; if (!next) break;
      }
      return out;
    },
    async subcollections(path) {
      const r = await ok(await doFetch(root + "/" + path + ":listCollectionIds", { method: "POST", headers: H, body: JSON.stringify({ pageSize: 100 }) }), "List subcollections of " + path);
      if (r.status === 404) return [];
      const d = await r.json().catch(() => ({}));
      return d.collectionIds || [];
    },
    // docs where field == value; group = search every collection with that id
    async where(collectionId, field, value, group = false) {
      const body = { structuredQuery: { from: [{ collectionId, allDescendants: group }], where: { fieldFilter: { field: { fieldPath: field }, op: "EQUAL", value: { stringValue: value } } }, limit: 1000 } };
      const r = await ok(await doFetch(root + ":runQuery", { method: "POST", headers: H, body: JSON.stringify(body) }), "Query " + collectionId);
      const rows = await r.json().catch(() => []);
      return (Array.isArray(rows) ? rows : []).filter((x) => x && x.document).map((x) => ({ path: rel(x.document.name), fields: x.document.fields || {} }));
    },
    name,
  };
}

// Delete a doc and everything under it (one level of subcollections and their own).
export async function deleteTree(fs, path, depth = 0) {
  if (depth < 3) {
    for (const c of await fs.subcollections(path)) {
      for (const d of await fs.list(path + "/" + c)) await deleteTree(fs, d.path, depth + 1);
    }
  }
  await fs.del(path);
}

// Where the user is a member: [{ kind: "workspaces"|"vaults", id, role, founder, others }]
export async function memberships(fs, uid) {
  const rows = await fs.where("members", "uid", uid, true);
  const out = [];
  for (const m of rows) {
    const [kind, id] = m.path.split("/");
    if ((kind !== "workspaces" && kind !== "vaults") || !id) continue;
    const role = fs.val(m.fields.role) || "";
    if (role === "removed") { out.push({ kind, id, role, founder: false, others: 0, name: "", memberPath: m.path }); continue; }
    const top = await fs.get(kind + "/" + id);
    const f = (top && top.fields) || {};
    const founder = fs.val(f.createdBy) === uid;
    const all = await fs.list(kind + "/" + id + "/members");
    const others = all.filter((x) => fs.val(x.fields.uid) !== uid && fs.val(x.fields.role) !== "removed").length;
    out.push({ kind, id, role, founder, others, name: fs.val(f.name) || id, memberPath: m.path });
  }
  return out;
}

// Wipe one Durable Object's storage through its internal /__wipe route.
async function wipeDO(ns, id) {
  if (!ns) return;
  const r = await ns.get(ns.idFromName(id)).fetch("https://do/__wipe", { method: "POST", headers: { "x-dn-wipe": "1" } });
  if (!r.ok) throw new Error("Could not clear stored data (HTTP " + r.status + ")");
}

// The /__wipe route each DO answers. Only the Worker builds that URL: every user-facing
// forward uses a fixed path ("/" or "/findings"), so outside input never reaches it.
export async function maybeWipe(request, storage) {
  if (new URL(request.url).pathname !== "/__wipe" || request.headers.get("x-dn-wipe") !== "1") return null;
  try { await storage.deleteAlarm(); } catch (_) {}
  await storage.deleteAll();
  return new Response('{"ok":true}', { headers: { "Content-Type": "application/json" } });
}

export async function handleAccountDelete(request, env, json, principal, opts = {}) {
  if (request.method !== "POST") return json({ error: "POST only" }, 405);
  if (!env.FIREBASE_PROJECT_ID) return json({ error: "FIREBASE_PROJECT_ID is not set" }, 503);
  const uid = principal && principal.uid;
  if (!uid || principal.kind !== "user") return json({ error: "Sign in required" }, 401);
  let body = {}; try { body = await request.json(); } catch (_) {}
  if (!body || body.confirm !== "DELETE") return json({ error: 'Send {"confirm":"DELETE"} to delete the account.' }, 400);
  if (!recentEnough(principal.claims, opts.now)) return json({ error: "Sign in again to confirm it's you, then delete.", reauth: true }, 401);

  const doFetch = opts.fetch || fetch;
  let token;
  try { token = await (opts.token || googleToken)(env); }
  catch (e) { return json({ error: "Server credentials unavailable: " + e.message }, 503); }
  const fs = firestore(env, token, doFetch);

  try {
    const mine = await memberships(fs, uid);
    const blocking = mine.filter((m) => m.founder && m.others > 0);
    if (blocking.length) {
      return json({
        error: "You created " + blocking.map((b) => '"' + b.name + '"').join(", ") + ", which still " + (blocking.length > 1 ? "have" : "has") + " other members. Remove them first, then delete your account.",
        blocking: blocking.map((b) => ({ kind: b.kind === "vaults" ? "vault" : "workspace", id: b.id, name: b.name, members: b.others })),
      }, 409);
    }
    // personal workspace (wid === uid) and every space they hold alone
    await wipeDO(env.GRAPH, uid); await wipeDO(env.MONITOR, uid); await wipeDO(env.INGEST, uid);
    for (const m of mine) {
      const alone = m.role !== "removed" && m.others === 0 && (m.founder || m.role === "owner");
      if (alone && m.kind === "workspaces") { await wipeDO(env.GRAPH, m.id); await wipeDO(env.MONITOR, m.id); await wipeDO(env.INGEST, m.id); await deleteTree(fs, "workspaces/" + m.id); }
      else if (alone && m.kind === "vaults") { await wipeDO(env.VAULT, m.id); await deleteTree(fs, "vaults/" + m.id); }
      else await fs.del(m.memberPath);
    }
    for (const [c, field] of OWNED_BY_FIELD) for (const d of await fs.where(c, field, uid)) await fs.del(d.path);
    if (principal.email) for (const d of await fs.where("waitlist", "email", principal.email)) await fs.del(d.path);
    for (const c of KEYED_BY_UID) await fs.del(c + "/" + uid);
    await deleteTree(fs, "users/" + uid);

    const r = await doFetch("https://identitytoolkit.googleapis.com/v1/projects/" + env.FIREBASE_PROJECT_ID + "/accounts:delete", {
      method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ localId: uid }),
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      if (!(d && d.error && /USER_NOT_FOUND/.test(d.error.message || ""))) throw new Error("Deleting the sign-in failed (HTTP " + r.status + ")");
    }
  } catch (e) {
    return json({ error: (e && e.message ? e.message : "Deletion failed") + ". Part of the account may already be deleted; try again to finish." }, 502);
  }
  return json({ ok: true });
}
