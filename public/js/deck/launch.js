// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Deck launcher: loads the signed-in user's workspace profile, plan and notifications,
// then mounts the Deck. Shared by the web home (every signed-in user), the desktop app
// and the owner's Admin page.
import { db } from "/js/firebase.js?v=20261021a";
import {
  collection, getDocs, doc, getDoc, setDoc, serverTimestamp,
  addDoc, query, orderBy, updateDoc, limit,
} from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";

let _deckOff = null; // teardown of the mounted Deck, so relaunching never stacks two
// Mount the Deck for a signed-in user. `extra` adds renderDeck options: isOwner (from the
// admin custom claim; Security Rules enforce it server-side) unlocks the owner-only
// pieces, and onSignOut makes the Deck the primary UI (no console exit).
export async function openDeck(user, extra = {}) {
  const [{ renderDeck }, nav] = await Promise.all([
    import("/js/deck-ui.js?v=20261026b"),
    import("/js/console-nav.js?v=20261013k"),
  ]);
  // Workspace identity (A1): load the owner's workspace profile so the Deck header,
  // Plans and reports show it instead of a hardcoded label. Non-fatal if it fails.
  let wsProfile = {}, deckTier = "", onboarding = {};
  if (user) {
    try {
      const snap = await getDoc(doc(db, "users", user.uid));
      const d = snap.exists() ? snap.data() : {};
      wsProfile = { name: d.workspaceName || "", logo: d.workspaceLogo || "", accent: d.workspaceAccent || "" };
      deckTier = d.tier || "";
      onboarding = d.onboarding || {};
    } catch (_) {}
  }
  // Durable account notifications (A6): the owner's own recent account-level
  // messages (e.g. a granted upgrade). Low-volume subcollection; non-fatal.
  let accountNotifs = [];
  if (user) {
    try {
      const nsnap = await getDocs(query(collection(db, "users", user.uid, "notifications"), orderBy("ts", "desc"), limit(20)));
      accountNotifs = nsnap.docs.map((dd) => { const n = dd.data() || {}; return { id: dd.id, text: n.text || "", ts: typeof n.ts === "number" ? n.ts : 0, kind: n.kind || "", read: !!n.read }; });
    } catch (_) {}
  }
  // Never stack Decks: dispose the previous mount (root + listeners) first.
  if (_deckOff) { try { _deckOff(); } catch (_) {} _deckOff = null; }
  document.querySelectorAll("body > .dk").forEach((n) => n.remove());
  _deckOff = renderDeck(document.body, {
    groups: (nav.NAV || []).map((g) => ({ id: g.id, name: g.name, color: g.color, items: g.items || [] })),
    user: user ? { uid: user.uid || "", displayName: user.displayName || "", email: user.email || "", photoURL: user.photoURL || "" } : null,
    isOwner: false,
    tier: deckTier,
    workspace: wsProfile,
    onboarding,
    accountNotifs,
    onNotifRead: user ? async (ids) => {
      await Promise.all((ids || []).map((id) => updateDoc(doc(db, "users", user.uid, "notifications", id), { read: true }).catch(() => {})));
    } : null,
    onOnboarding: user ? async (partial) => {
      await setDoc(doc(db, "users", user.uid), { onboarding: partial || {} }, { merge: true });
    } : null,
    onUpgradeRequest: user ? async (tier, note) => {
      await addDoc(collection(db, "upgradeRequests"), {
        uid: user.uid, email: user.email || "", tier: String(tier || ""),
        note: String(note || "").slice(0, 2000), status: "pending", ts: serverTimestamp(),
      });
    } : null,
    onWorkspace: user ? async (partial) => {
      const map = {};
      if ("name" in partial) map.workspaceName = partial.name || "";
      if ("logo" in partial) map.workspaceLogo = partial.logo || "";
      if ("accent" in partial) map.workspaceAccent = partial.accent || "";
      map.workspaceUpdatedAt = serverTimestamp();
      await setDoc(doc(db, "users", user.uid), map, { merge: true });
    } : null,
    onExit: () => { _deckOff = null; },
    ...extra,
  });
  return _deckOff;
}
export function closeDeck() { if (_deckOff) { try { _deckOff(); } catch (_) {} _deckOff = null; } }
