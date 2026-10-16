// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
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
      const res = await transport.push(payload);
      if (res && typeof res.rev === "number") { st.rev = Math.max(st.rev, res.rev); persist(); }
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

function graphAdapter(SG) {
  let subs = [];
  const on = (name, fn) => { document.addEventListener(name, fn); subs.push([name, fn]); };
  return {
    exportAll: () => SG.exportAll(),
    applyRemote: (r) => SG.applyRemote(r),
    subscribe: ({ onEntity, onRelationship }) => {
      on("secgraph:entity:created", (e) => onEntity(e.detail && e.detail.entity, false));
      on("secgraph:entity:updated", (e) => onEntity(e.detail && e.detail.entity, false));
      on("secgraph:entity:deleted", (e) => onEntity(e.detail && { id: e.detail.id }, true));
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
  let SG, auth;
  try {
    ({ auth } = await import("/js/firebase.js?v=20261007a"));
    SG = await import("/js/security-graph.js");
  } catch (e) { onStatus("error", { reason: "import", message: String(e && e.message || e) }); return null; }
  const user = (auth && auth.currentUser) || null;
  if (!user) { onStatus("local", { reason: "signed-out" }); return null; }
  const wid = opts.workspaceId || user.uid;
  const getToken = () => user.getIdToken();
  const key = "dn_graph_sync_" + wid;
  const loadState = () => { try { return JSON.parse(localStorage.getItem(key) || "null"); } catch (_) { return null; } };
  const saveState = (s) => { try { localStorage.setItem(key, JSON.stringify(s)); } catch (_) {} };

  if (_active) { try { _active.stop(); } catch (_) {} _active = null; }
  _active = createSyncEngine({ transport: realTransport(wid, getToken), graph: graphAdapter(SG), loadState, saveState, onStatus });
  await _active.start();
  return _active;
}

export function stopGraphSync() { if (_active) { try { _active.stop(); } catch (_) {} _active = null; } }
export const activeSync = () => _active;
