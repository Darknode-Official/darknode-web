// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// VAULT team-vault client. Membership and roles are Firestore documents (rules-enforced,
// see firebase/firestore.rules); every ledger operation is a call to the Darknode worker,
// which verifies the signed-in user and runs it in the vault's Durable Object.

import { auth, db } from "/js/firebase.js?v=20261021a";
import { collection, collectionGroup, query, where, getDocs, doc, getDoc, writeBatch, serverTimestamp } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";

const base = () => { try { return String(window.DARKNODE_PROXY_URL || "").replace(/\/api\/chat$/, ""); } catch (_) { return ""; } };
const rid = (n = 20) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[b % 62]).join("");

export const me = () => auth.currentUser;

async function call(vid, method, body, q = "") {
  const u = me();
  if (!u) throw new Error("Sign in to use a team vault.");
  if (!base()) throw new Error("The VAULT server is not configured on this site.");
  const r = await fetch(base() + "/api/vault/" + encodeURIComponent(vid) + q, {
    method, body: body ? JSON.stringify(body) : undefined,
    headers: { Authorization: "Bearer " + (await u.getIdToken()), ...(body ? { "Content-Type": "application/json" } : {}) },
  });
  let j = {};
  try { j = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error(j.error || "VAULT server error " + r.status);
  return j;
}
export const vaultState = (vid) => call(vid, "GET");
export const vaultVerify = (vid) => call(vid, "GET", null, "?verify=1");
export const vaultOp = (vid, op, args) => call(vid, "POST", { op, args });

// Vaults the signed-in user belongs to (removed memberships are skipped).
export async function myVaults() {
  const u = me();
  if (!u) return [];
  const snap = await getDocs(query(collectionGroup(db, "members"), where("uid", "==", u.uid)));
  const out = [];
  for (const d of snap.docs) {
    const m = d.data();
    if (m.role === "removed") continue;
    const vid = d.ref.parent.parent.id;
    let name = vid;
    try { const v = await getDoc(doc(db, "vaults", vid)); if (v.exists()) name = v.data().name || vid; } catch (_) {}
    out.push({ vid, name, role: m.role });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

// Founds a vault: vault doc + the founder's owner membership + its log entry, in one batch.
export async function createVault(name) {
  const u = me();
  if (!u) throw new Error("Sign in to create a team vault.");
  const vid = rid(20), logId = rid(20);
  const b = writeBatch(db);
  b.set(doc(db, "vaults", vid), { name, createdBy: u.uid, createdAt: serverTimestamp() });
  b.set(doc(db, "vaults", vid, "members", u.uid), { uid: u.uid, role: "owner", by: u.uid, ts: serverTimestamp(), logId, label: (u.email || u.displayName || "").slice(0, 120) });
  b.set(doc(db, "vaults", vid, "memberLog", logId), { uid: u.uid, role: "owner", by: u.uid, ts: serverTimestamp() });
  await b.commit();
  return vid;
}

export async function listMembers(vid) {
  const [m, log] = await Promise.all([getDocs(collection(db, "vaults", vid, "members")), getDocs(collection(db, "vaults", vid, "memberLog"))]);
  const tsOf = (x) => (x && x.toMillis ? x.toMillis() : 0);
  return {
    members: m.docs.map((d) => d.data()).sort((a, b) => (a.role === "removed") - (b.role === "removed") || String(a.label || a.uid).localeCompare(String(b.label || b.uid))),
    log: log.docs.map((d) => ({ ...d.data(), ts: tsOf(d.data().ts) })).sort((a, b) => b.ts - a.ts),
  };
}

// Owner-only (enforced by the rules): set a member's role, with its log entry.
export async function setMember(vid, uid, role, label) {
  const u = me();
  if (!u) throw new Error("Sign in first.");
  const logId = rid(20);
  const b = writeBatch(db);
  const m = { uid, role, by: u.uid, ts: serverTimestamp(), logId };
  if (label) m.label = String(label).slice(0, 120);
  b.set(doc(db, "vaults", vid, "members", uid), m);
  b.set(doc(db, "vaults", vid, "memberLog", logId), { uid, role, by: u.uid, ts: serverTimestamp() });
  await b.commit();
}
