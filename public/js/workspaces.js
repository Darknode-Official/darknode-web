// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Team-workspace client (Phase B2) — the non-financial generalization of vault/remote.js.
// Membership and roles are Firestore documents (rules-enforced, firebase/firestore.rules);
// the shared security graph itself lives in the worker's GraphDO, synced by graph-sync.js.
// This module only manages WHO is in a workspace, and which one is active.
//
// A user always has a PERSONAL workspace (id = their uid, implicit owner, no Firestore
// doc — it is the Phase B1 graph). Team workspaces are Firestore-backed and shared.

import { ROLES } from "/js/core/workspace-roles.js";

const ACTIVE_WS_KEY = "dn_active_ws";
const rid = (n = 20) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[b % 62]).join("");

// Firebase is loaded lazily so importing this module (which the Deck does at load) never
// pulls in firebase.js / the Firestore CDN. Mirrors graph-sync.js, and keeps the Deck
// importable offline and in tests. Resolves to { auth, db, fns }.
let _deps = null;
async function deps() {
  if (_deps) return _deps;
  const [fb, fs] = await Promise.all([
    import("/js/firebase.js?v=20261018i"),
    import("https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js"),
  ]);
  _deps = { auth: fb.auth, db: fb.db, fns: fs };
  return _deps;
}

// The signed-in user, once firebase has been loaded by a prior call. Synchronous callers
// (e.g. the personal-workspace fallback) tolerate null before the first async call.
export const me = () => (_deps && _deps.auth && _deps.auth.currentUser) || null;

// The active workspace id, or null for the personal workspace. Stored as a shared pointer
// so security-graph.js (in the Deck and every tool iframe) scopes to the same store.
export function activeWorkspace() { try { return localStorage.getItem(ACTIVE_WS_KEY) || null; } catch (_) { return null; } }
export function setActiveWorkspace(wid) {
  try { if (wid) localStorage.setItem(ACTIVE_WS_KEY, wid); else localStorage.removeItem(ACTIVE_WS_KEY); } catch (_) {}
}

// The personal workspace descriptor. `uid` is passed by callers that have loaded firebase
// (so it works before me() is primed); falls back to me() otherwise.
export function personalWorkspace(name, uid) {
  const u = uid || (me() && me().uid) || null;
  return { wid: u, name: name || "Personal workspace", role: "owner", personal: true };
}

// Team workspaces the signed-in user belongs to (removed memberships skipped). Filtered to
// the workspaces/ collection so vault memberships (same collection-group) are excluded.
export async function myTeamWorkspaces() {
  const { auth, db, fns } = await deps();
  const u = auth.currentUser;
  if (!u) return [];
  const snap = await fns.getDocs(fns.query(fns.collectionGroup(db, "members"), fns.where("uid", "==", u.uid)));
  const out = [];
  for (const d of snap.docs) {
    const parent = d.ref.parent.parent;            // the workspace (or vault) doc
    if (!parent || parent.parent.id !== "workspaces") continue; // skip vault memberships
    const m = d.data();
    if (m.role === "removed" || !ROLES.includes(m.role)) continue;
    let name = parent.id;
    try { const w = await fns.getDoc(fns.doc(db, "workspaces", parent.id)); if (w.exists()) name = w.data().name || parent.id; } catch (_) {}
    out.push({ wid: parent.id, name, role: m.role, personal: false });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

// Every workspace the user can act in: personal first, then teams by name.
export async function myWorkspaces(personalName) {
  const { auth } = await deps();
  const uid = auth.currentUser && auth.currentUser.uid;
  return [personalWorkspace(personalName, uid), ...(await myTeamWorkspaces())];
}

// Found a workspace: workspace doc + the founder's owner membership + its log entry, in
// one batch (the shape the rules require). Returns the new workspace id.
export async function createWorkspace(name) {
  const { auth, db, fns } = await deps();
  const u = auth.currentUser;
  if (!u) throw new Error("Sign in to create a workspace.");
  const clean = String(name || "").trim().slice(0, 80);
  if (!clean) throw new Error("Give the workspace a name.");
  const wid = rid(20), logId = rid(20);
  const b = fns.writeBatch(db);
  b.set(fns.doc(db, "workspaces", wid), { name: clean, createdBy: u.uid, createdAt: fns.serverTimestamp() });
  b.set(fns.doc(db, "workspaces", wid, "members", u.uid), { uid: u.uid, role: "owner", by: u.uid, ts: fns.serverTimestamp(), logId, label: (u.email || u.displayName || "").slice(0, 120) });
  b.set(fns.doc(db, "workspaces", wid, "memberLog", logId), { uid: u.uid, role: "owner", by: u.uid, ts: fns.serverTimestamp() });
  await b.commit();
  return { wid, name: clean };
}

export async function listMembers(wid) {
  const { db, fns } = await deps();
  const [m, log] = await Promise.all([fns.getDocs(fns.collection(db, "workspaces", wid, "members")), fns.getDocs(fns.collection(db, "workspaces", wid, "memberLog"))]);
  const tsOf = (x) => (x && x.toMillis ? x.toMillis() : 0);
  return {
    members: m.docs.map((d) => d.data()).sort((a, b) => (a.role === "removed") - (b.role === "removed") || String(a.label || a.uid).localeCompare(String(b.label || b.uid))),
    log: log.docs.map((d) => ({ ...d.data(), ts: tsOf(d.data().ts) })).sort((a, b) => b.ts - a.ts),
  };
}

// Owner/admin-only (enforced by the rules): set a member's role, with its log entry.
export async function setMember(wid, uid, role, label) {
  const { auth, db, fns } = await deps();
  const u = auth.currentUser;
  if (!u) throw new Error("Sign in first.");
  if (!ROLES.includes(role)) throw new Error("Unknown role.");
  const logId = rid(20);
  const b = fns.writeBatch(db);
  const m = { uid, role, by: u.uid, ts: fns.serverTimestamp(), logId };
  if (label) m.label = String(label).slice(0, 120);
  b.set(fns.doc(db, "workspaces", wid, "members", uid), m);
  b.set(fns.doc(db, "workspaces", wid, "memberLog", logId), { uid, role, by: u.uid, ts: fns.serverTimestamp() });
  await b.commit();
}
