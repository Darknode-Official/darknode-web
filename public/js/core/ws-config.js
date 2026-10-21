// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Shared per-workspace settings (the SLA policy now; alert rules later). Browser module.
//
// A team workspace keeps them in Firestore at workspaces/{wid}/config/{name}: every
// member reads, only an owner/admin writes (firebase/firestore.rules). The personal
// workspace (id = the user's uid, or no active workspace) keeps them at
// users/{uid}/config/{name}, owner-only. Each doc is { value: <map>, by: uid, ts }.
//
// Firebase loads lazily (same specifiers as workspaces.js) so importing this module never
// pulls in the Firestore CDN.

import { isPersonalWorkspace } from "./workspace-roles.js";
import { normalizePolicy, SLA_DEFAULTS } from "./workflow.js";

export const SLA_CONFIG = "sla";
const NAME_RE = /^[a-z0-9_-]{1,40}$/;
const ACTIVE_WS_KEY = "dn_active_ws";

let _deps = null;
async function deps() {
  if (_deps) return _deps;
  const [fb, fs] = await Promise.all([
    import("/js/firebase.js?v=20261021a"),
    import("https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js"),
  ]);
  try { if (fb.auth && fb.auth.authStateReady) await fb.auth.authStateReady(); } catch (_) {}
  _deps = { auth: fb.auth, db: fb.db, fns: fs };
  return _deps;
}

const activeWid = () => { try { return localStorage.getItem(ACTIVE_WS_KEY) || null; } catch (_) { return null; } };
const isMap = (v) => !!v && typeof v === "object" && !Array.isArray(v);

// The config doc for `name` in the active workspace, or null when signed out.
async function configRef(name) {
  if (!NAME_RE.test(String(name || ""))) throw new Error("Invalid config name");
  const { auth, db, fns } = await deps();
  const u = auth && auth.currentUser;
  if (!u) return null;
  const wid = activeWid();
  const ref = !wid || isPersonalWorkspace(wid, u.uid)
    ? fns.doc(db, "users", u.uid, "config", name)
    : fns.doc(db, "workspaces", wid, "config", name);
  return { ref, uid: u.uid, fns };
}

/**
 * The active workspace's config `name`, or null (unset, signed out, or not readable).
 * @param {string} name [a-z0-9_-]{1,40}
 * @returns {Promise<object|null>}
 */
export async function getConfig(name) {
  const c = await configRef(name);
  if (!c) return null;
  try {
    const snap = await c.fns.getDoc(c.ref);
    const v = snap.exists() ? snap.data().value : null;
    return isMap(v) ? v : null;
  } catch (_) { return null; }
}

/**
 * Save config `name` for the active workspace. Throws when signed out, when the value is
 * not a plain object, or when the rules refuse (a team member below admin).
 * @param {string} name
 * @param {object} value
 * @returns {Promise<void>}
 */
export async function setConfig(name, value) {
  if (!isMap(value)) throw new Error("Config value must be an object");
  const c = await configRef(name);
  if (!c) throw new Error("Sign in to save workspace settings.");
  try {
    await c.fns.setDoc(c.ref, { value, by: c.uid, ts: c.fns.serverTimestamp() });
  } catch (err) {
    if (err && err.code === "permission-denied") throw new Error("Only a workspace owner or admin can change this setting.");
    throw err;
  }
}

/**
 * Watch config `name` in the active workspace; cb(value|null) on every change and again
 * when the active workspace switches. Returns an unsubscribe function.
 * @param {string} name
 * @param {(value: object|null) => void} cb
 * @returns {() => void}
 */
export function onConfigChange(name, cb) {
  let stop = null, dead = false, seq = 0;
  const sub = async () => {
    const my = ++seq;
    if (stop) { try { stop(); } catch (_) {} stop = null; }
    try {
      const c = await configRef(name);
      if (dead || my !== seq) return;
      if (!c) { cb(null); return; }
      stop = c.fns.onSnapshot(c.ref, (s) => { const v = s.exists() ? s.data().value : null; cb(isMap(v) ? v : null); }, () => cb(null));
    } catch (_) { if (!dead && my === seq) cb(null); }
  };
  const onSwitch = (e) => { if (!e || e.type !== "storage" || e.key === ACTIVE_WS_KEY) sub(); };
  try { window.addEventListener("storage", onSwitch); document.addEventListener("secgraph:store-changed", onSwitch); } catch (_) {}
  sub();
  return () => {
    dead = true;
    if (stop) { try { stop(); } catch (_) {} }
    try { window.removeEventListener("storage", onSwitch); document.removeEventListener("secgraph:store-changed", onSwitch); } catch (_) {}
  };
}

/**
 * The active workspace's SLA policy (normalized), or the defaults when none is saved.
 * @returns {Promise<{critical:number|null,high:number|null,medium:number|null,low:number|null,info:number|null,kev:number|null}>}
 */
export async function getSlaPolicy() {
  let v = null;
  try { v = await getConfig(SLA_CONFIG); } catch (_) {}
  return normalizePolicy(v || SLA_DEFAULTS);
}
