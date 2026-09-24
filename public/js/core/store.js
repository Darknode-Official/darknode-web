// Darknode namespaced, versioned key-value store.
//
// Replaces the ~65+ hand-rolled, un-namespaced localStorage keys spread across
// the codebase (each module re-implementing `try { JSON.parse(...) || dflt }
// catch {}`) with one abstraction that provides:
//   - Namespacing: every key is stored as `dn:<namespace>:<key>`, unifying the
//     competing `sw_` / `dn_` / per-tool prefix conventions behind a registry.
//   - JSON (de)serialization with safe fallbacks — a corrupt value returns the
//     caller's default instead of throwing.
//   - A pluggable backend: real localStorage in the browser, an in-memory
//     backend in Node/tests/private-mode, chosen automatically.
//   - Schema versioning + migrations per namespace, so stored shapes can evolve.
//   - Quota-aware writes (QuotaExceededError is surfaced, not swallowed silently).
//   - Change subscription, so an app-level bridge can forward writes to the bus.
//
// Usage:
//   import { store } from "/js/core/store.js";
//   const prefs = store.namespace("prefs");
//   prefs.set("theme", "pro");
//   prefs.get("theme", "dark");        // -> "pro"
//   const graph = store.namespace("graph", { version: 2, migrations: { 2: (ns) => {...} } });

const ROOT = "dn"; // global key prefix for everything this store owns

// ---------------------------------------------------------------------------
// Backends. A backend implements the subset of the Web Storage API we use.
// ---------------------------------------------------------------------------

// In-memory backend — used in Node/tests, and as a graceful fallback when
// localStorage is unavailable or throws (Safari private mode, blocked storage).
export class MemoryBackend {
  constructor() { this._m = new Map(); }
  get length() { return this._m.size; }
  key(i) { return [...this._m.keys()][i] ?? null; }
  getItem(k) { return this._m.has(k) ? this._m.get(k) : null; }
  setItem(k, v) { this._m.set(k, String(v)); }
  removeItem(k) { this._m.delete(k); }
  clear() { this._m.clear(); }
}

// Pick the best available backend without throwing at import time.
function detectBackend() {
  try {
    if (typeof localStorage !== "undefined") {
      const probe = "__dn_probe__";
      localStorage.setItem(probe, "1");
      localStorage.removeItem(probe);
      return localStorage;
    }
  } catch (_) { /* blocked / private mode -> fall through */ }
  return new MemoryBackend();
}

export class StoreQuotaError extends Error {
  constructor(fullKey, cause) { super(`storage quota exceeded writing "${fullKey}"`); this.name = "StoreQuotaError"; this.cause = cause; this.key = fullKey; }
}

// ---------------------------------------------------------------------------
// Namespace — the object modules actually use.
// ---------------------------------------------------------------------------

class Namespace {
  /** @param {Store} store @param {string} name */
  constructor(store, name, { version = 1, migrations = {} } = {}) {
    this._store = store;
    this.name = name;
    this._prefix = `${ROOT}:${name}:`;
    this._version = version;
    this._migrations = migrations;
    this._runMigrations();
  }

  _full(key) { return this._prefix + key; }

  // Run any migration whose version is greater than the stored version and less
  // than or equal to the current version, in ascending order. Migrations receive
  // this namespace so they can read/rewrite keys freely.
  _runMigrations() {
    const metaKey = "__meta";
    const meta = this.get(metaKey, { v: 0 });
    const from = typeof meta.v === "number" ? meta.v : 0;
    // Meta writes are best-effort: a full disk must not crash namespace creation.
    const writeMeta = () => { try { this.set(metaKey, { v: this._version }); } catch (_) {} };
    if (from >= this._version) { if (from === 0) writeMeta(); return; }
    const steps = Object.keys(this._migrations)
      .map(Number).filter((v) => v > from && v <= this._version).sort((a, b) => a - b);
    for (const v of steps) {
      try { this._migrations[v](this); } catch (err) {
        try { console.error(`[store] migration ${this.name}->v${v} failed:`, err); } catch (_) {}
      }
    }
    writeMeta();
  }

  /** Read + JSON-parse a key, returning `fallback` if absent or corrupt. */
  get(key, fallback = null) {
    let raw;
    try { raw = this._store.backend.getItem(this._full(key)); } catch (_) { return fallback; }
    if (raw === null || raw === undefined) return fallback;
    try { return JSON.parse(raw); } catch (_) { return fallback; }
  }

  /** JSON-serialize + write a key. Returns true on success. Throws StoreQuotaError
   *  on a genuine quota failure so callers can react (e.g. prune history). */
  set(key, value) {
    const full = this._full(key);
    let raw;
    try { raw = JSON.stringify(value); } catch (err) {
      try { console.error(`[store] value for "${full}" is not serializable:`, err); } catch (_) {}
      return false;
    }
    try {
      this._store.backend.setItem(full, raw);
    } catch (err) {
      if (err && (err.name === "QuotaExceededError" || err.code === 22 || err.code === 1014)) {
        throw new StoreQuotaError(full, err);
      }
      return false;
    }
    // Internal bookkeeping keys (e.g. __meta) must not spam change subscribers.
    if (!key.startsWith("__")) this._store._notify(this.name, key, value);
    return true;
  }

  has(key) {
    try { return this._store.backend.getItem(this._full(key)) !== null; } catch (_) { return false; }
  }

  remove(key) {
    try { this._store.backend.removeItem(this._full(key)); } catch (_) { return false; }
    if (!key.startsWith("__")) this._store._notify(this.name, key, undefined);
    return true;
  }

  /** Update a stored object by merging a patch (shallow). Convenience for the
   *  extremely common read-modify-write pattern. */
  update(key, patch, fallback = {}) {
    const cur = this.get(key, fallback);
    const next = Object.assign({}, cur, typeof patch === "function" ? patch(cur) : patch);
    this.set(key, next);
    return next;
  }

  /** All keys in this namespace (without the prefix), excluding internal meta. */
  keys() {
    const out = [];
    const be = this._store.backend;
    for (let i = 0; i < be.length; i++) {
      const k = be.key(i);
      if (k && k.startsWith(this._prefix)) {
        const short = k.slice(this._prefix.length);
        if (short !== "__meta") out.push(short);
      }
    }
    return out;
  }

  /** Remove every key in this namespace (keeps the version meta). */
  clear() {
    for (const k of this.keys()) this.remove(k);
  }
}

// ---------------------------------------------------------------------------
// Store — the top-level factory + registry of namespaces.
// ---------------------------------------------------------------------------

export class Store {
  constructor({ backend } = {}) {
    this.backend = backend || detectBackend();
    this._namespaces = new Map();
    this._listeners = new Set();
    // Discoverability: a registry of namespaces that have been opened, so tooling
    // (and the "key registry" gap in the audit) has a single place to enumerate.
    this.registry = this._namespaces;
  }

  /** Whether persistent storage is actually available (vs the memory fallback). */
  get persistent() { return !(this.backend instanceof MemoryBackend); }

  /** Open (or reuse) a namespace. Options set the schema version + migrations the
   *  first time a namespace is opened in a session. */
  namespace(name, opts) {
    if (!/^[a-z][a-z0-9-]*$/.test(name)) throw new Error(`invalid namespace "${name}" (use kebab-case)`);
    let ns = this._namespaces.get(name);
    if (!ns) { ns = new Namespace(this, name, opts); this._namespaces.set(name, ns); }
    return ns;
  }

  /** Subscribe to every write across all namespaces. Returns an unsubscribe fn.
   *  The app bridges this to the event bus (STORAGE_CHANGED) so persistence and
   *  in-memory state stay in sync without coupling store.js to bus.js. */
  subscribe(listener) {
    this._listeners.add(listener);
    return () => this._listeners.delete(listener);
  }

  _notify(namespace, key, value) {
    for (const l of [...this._listeners]) {
      try { l({ namespace, key, value }); } catch (_) {}
    }
  }
}

// Process-wide singleton. Tests construct `new Store({ backend: new MemoryBackend() })`
// for isolation.
export const store = new Store();
