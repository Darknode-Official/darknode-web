// Copyright (c) 2026 Darknode-Official. All rights reserved.
//
// Cloud sync for the security graph (Phase B1). The browser's security-graph.js stays the
// instant, synchronous source of truth; this layer mirrors it to and from the worker's
// GraphDO in the background, so the same graph follows a user across devices. Convergence
// is last-writer-wins — applied by the graph itself (applyRemote) and the server, using
// the one shared rule in core/graph-merge.js — so no tool code changes and nothing blocks
// on the network.
//
// The engine below is pure orchestration: it takes a transport (pull/push), a graph
// adapter (exportAll/applyRemote/subscribe) and injectable state + timers, so the entire
// pull → merge → push loop is tested offline against a fake server. The real wiring
// (startGraphSync) dynamically imports firebase + security-graph, so importing the engine
// in Node for tests never pulls in browser-only modules.

export function createSyncEngine(deps) {
  const {
    transport, graph, loadState, saveState,
    now = () => new Date().toISOString(),
    onStatus = () => {},
    debounceMs = 1500, pollMs = 20000,
    setTimer = setTimeout, clearTimer = clearTimeout,
  } = deps;

  let st = loadState() || { rev: 0, seeded: false };
  if (typeof st.rev !== "number") st.rev = 0;
  const pendingE = new Map(), pendingR = new Map();
  let flushTimer = null, pollTimer = null, running = false, busy = false;

  const emit = (s, info) => { try { onStatus(s, info); } catch (_) {} };
  const persist = () => { try { saveState(st); } catch (_) {} };
  const entTomb = (id) => ({ id, deleted: true, updatedAt: now() });
  const relTomb = (id) => ({ id, deleted: true, createdAt: now() });

  function queueEntity(e, deleted) { if (!e || !e.id) return; pendingE.set(e.id, deleted ? entTomb(e.id) : e); schedule(); }
  function queueRel(r, deleted) { if (!r || !r.id) return; pendingR.set(r.id, deleted ? relTomb(r.id) : r); schedule(); }

  function schedule() { if (!running || flushTimer) return; flushTimer = setTimer(() => { flushTimer = null; sync(); }, debounceMs); }

  function seedAll() {
    const all = graph.exportAll() || {};
    for (const e of all.entities || []) pendingE.set(e.id, e);
    for (const r of all.relationships || []) pendingR.set(r.id, r);
  }

  async function pushPending() {
    if (!pendingE.size && !pendingR.size) return;
    const payload = { entities: [...pendingE.values()], relationships: [...pendingR.values()] };
    pendingE.clear(); pendingR.clear();
    try {
      await transport.push(payload);
      // Deliberately do NOT adopt the push response's rev as our cursor. The records between
      // our current cursor and that new head may belong to OTHER writers (a teammate, or this
      // user's other device) and have not been pulled yet. Advancing the cursor to the push
      // head and then pulling from there would skip them forever (silent divergence). Only
      // pullDelta advances the cursor, and only to a head whose records it has actually applied.
    } catch (e) {
      // Never drop a local change on a failed push: requeue what did not go through
      // (a later real edit to the same id simply overwrites the requeued copy).
      for (const x of payload.entities) if (!pendingE.has(x.id)) pendingE.set(x.id, x);
      for (const x of payload.relationships) if (!pendingR.has(x.id)) pendingR.set(x.id, x);
      throw e;
    }
  }

  async function pullDelta() {
    const remote = await transport.pull(st.rev);
    if (remote) {
      if (remote.entities || remote.relationships) graph.applyRemote(remote);
      if (typeof remote.rev === "number") { st.rev = Math.max(st.rev, remote.rev); persist(); }
    }
  }

  async function sync() {
    if (!running || busy) return;
    busy = true; emit("syncing");
    try { await pushPending(); await pullDelta(); emit("synced", { rev: st.rev }); }
    catch (e) { emit("error", (e && e.message) || String(e)); }
    finally { busy = false; }
  }

  async function start() {
    if (running) return engine;
    running = true;
    if (graph.subscribe) graph.subscribe({ onEntity: queueEntity, onRelationship: queueRel });
    emit("syncing");
    try {
      await pullDelta();
      // First sync for this workspace: push the whole local graph up once so local-only
      // records reach the cloud. After that the saved rev + live edits drive it.
      if (!st.seeded) { seedAll(); st.seeded = true; persist(); }
      await pushPending();
      // Re-pull after seeding so the cursor advances to the head we just created (including our
      // own seeded records, re-applied idempotently) without ever jumping it past unpulled revs.
      await pullDelta();
      emit("synced", { rev: st.rev });
    } catch (e) { emit("error", (e && e.message) || String(e)); }
    if (pollMs > 0) {
      const tick = () => { sync().finally(() => { if (running) pollTimer = setTimer(tick, pollMs); }); };
      pollTimer = setTimer(tick, pollMs);
    }
    return engine;
  }

  function stop() {
    running = false;
    if (flushTimer) { clearTimer(flushTimer); flushTimer = null; }
    if (pollTimer) { clearTimer(pollTimer); pollTimer = null; }
    if (graph.unsubscribe) graph.unsubscribe();
  }

  const engine = { start, stop, syncNow: sync, state: () => ({ ...st }), pending: () => ({ entities: pendingE.size, relationships: pendingR.size }) };
  return engine;
}

// ---- Real wiring (browser only). Dynamically imports firebase + security-graph so the
// engine above stays importable in Node tests. ----

let _active = null;

const proxyBase = () => { try { return String(window.DARKNODE_PROXY_URL || "").replace(/\/api\/chat$/, ""); } catch (_) { return ""; } };

function realTransport(workspaceId, getToken) {
  const url = (q) => proxyBase() + "/api/graph/" + encodeURIComponent(workspaceId) + (q || "");
  return {
    async pull(since) {
      const r = await fetch(url("?since=" + (Number(since) || 0)), { headers: { Authorization: "Bearer " + (await getToken()) } });
      let j = {}; try { j = await r.json(); } catch (_) {}
      if (!r.ok) throw new Error(j.error || "sync pull failed (" + r.status + ")");
      return j;
    },
    async push(payload) {
      const r = await fetch(url(), { method: "POST", headers: { Authorization: "Bearer " + (await getToken()), "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      let j = {}; try { j = await r.json(); } catch (_) {}
      if (!r.ok) throw new Error(j.error || "sync push failed (" + r.status + ")");
      return j;
    },
  };
}

function graphAdapter(SG, isSim) {
  isSim = typeof isSim === "function" ? isSim : () => false;
  let subs = [];
  const on = (name, fn) => { document.addEventListener(name, fn); subs.push([name, fn]); };
  return {
    // Sample/simulated entities never leave the browser: drop them, and any relationship
    // that touches one, before anything is pushed to the cloud.
    exportAll: () => {
      const all = SG.exportAll() || {};
      const simIds = new Set((all.entities || []).filter(isSim).map((e) => e.id));
      return {
        entities: (all.entities || []).filter((e) => !simIds.has(e.id)),
        relationships: (all.relationships || []).filter((r) => !simIds.has(r.fromId) && !simIds.has(r.toId)),
      };
    },
    applyRemote: (r) => SG.applyRemote(r),
    subscribe: ({ onEntity, onRelationship }) => {
      const live = (e) => { const ent = e.detail && e.detail.entity; if (ent && !isSim(ent)) onEntity(ent, false); };
      on("secgraph:entity:created", live);
      on("secgraph:entity:updated", live);
      on("secgraph:entity:deleted", (e) => onEntity(e.detail && { id: e.detail.id }, true)); // deletes always propagate
      on("secgraph:relationship:created", (e) => onRelationship(e.detail && e.detail.relationship, false));
    },
    unsubscribe: () => { for (const [n, f] of subs) document.removeEventListener(n, f); subs = []; },
  };
}

// Start syncing the signed-in user's PRIVATE cloud graph (workspace id = their uid).
// Returns the engine, or null when sync can't run (no proxy, not signed in) — the caller
// then shows "Local only". onStatus(state, info) gets "syncing" | "synced" | "error".
export async function startGraphSync(opts = {}) {
  const onStatus = (s, info) => {
    try { document.dispatchEvent(new CustomEvent("graph-sync:status", { detail: { state: s, info } })); } catch (_) {}
    if (typeof opts.onStatus === "function") { try { opts.onStatus(s, info); } catch (_) {} }
  };
  if (!proxyBase()) { onStatus("local", { reason: "no-proxy" }); return null; }
  let SG, auth, isSim;
  try {
    ({ auth } = await import("/js/firebase.js?v=20261018i"));
    SG = await import("/js/security-graph.js");
    try { ({ isSimulated: isSim } = await import("/js/core/posture.js")); } catch (_) { isSim = null; }
  } catch (e) { onStatus("error", { reason: "import", message: String(e && e.message || e) }); return null; }
  const user = (auth && auth.currentUser) || null;
  if (!user) { onStatus("local", { reason: "signed-out" }); return null; }
  const wid = opts.workspaceId || user.uid;
  const getToken = () => user.getIdToken();
  const key = "dn_graph_sync_" + wid;
  const loadState = () => { try { return JSON.parse(localStorage.getItem(key) || "null"); } catch (_) { return null; } };
  const saveState = (s) => { try { localStorage.setItem(key, JSON.stringify(s)); } catch (_) {} };

  if (_active) { try { _active.stop(); } catch (_) {} _active = null; }
  _active = createSyncEngine({ transport: realTransport(wid, getToken), graph: graphAdapter(SG, isSim), loadState, saveState, onStatus });
  await _active.start();
  return _active;
}

export function stopGraphSync() { if (_active) { try { _active.stop(); } catch (_) {} _active = null; } }
export const activeSync = () => _active;
