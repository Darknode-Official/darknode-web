// Darknode platform event bus.
//
// A single typed pub/sub hub. Subsystems publish and subscribe to named events
// instead of scattering `document.dispatchEvent(new CustomEvent(...))` calls and
// `window.*` globals (the pattern the codebase grew organically — see
// security-graph.js `_emit`, context-bar.js `darknode:context`, etc.).
//
// Design goals:
//   - One import, zero DOM dependency, so it runs in the browser AND in Node
//     tests without a build step.
//   - Handler isolation: one throwing subscriber never blocks the others or the
//     emitter.
//   - "Sticky" events: a subscriber that mounts AFTER an event last fired can opt
//     to immediately receive the last value (e.g. the active context / current
//     section), so late-mounting subsystems are not left blind.
//   - A frozen EVENTS catalog so event names are discoverable and typo-resistant.
//
// Usage:
//   import { bus, EVENTS } from "/js/core/bus.js";
//   const off = bus.on(EVENTS.CONTEXT_CHANGED, (ctx) => render(ctx));
//   bus.emit(EVENTS.CONTEXT_CHANGED, entity);
//   off(); // unsubscribe

// Canonical event names. Adding a subsystem event here makes it discoverable and
// prevents the silent-typo class of bug (subscribing to "context:changed" while
// emitting "contextChanged"). Values are namespaced strings so they read well in
// devtools and never collide with unrelated DOM events.
export const EVENTS = Object.freeze({
  // Navigation / shell
  SECTION_CHANGED: "nav:section-changed",
  NAV_REQUEST: "nav:request",
  // Active investigative context (the context-bar's selected entity)
  CONTEXT_CHANGED: "context:changed",
  // Entity store lifecycle (mirrors security-graph.js custom events)
  ENTITY_CREATED: "entity:created",
  ENTITY_UPDATED: "entity:updated",
  ENTITY_DELETED: "entity:deleted",
  RELATIONSHIP_CREATED: "entity:relationship-created",
  RELATIONSHIP_DELETED: "entity:relationship-deleted",
  // Persistence
  STORAGE_CHANGED: "storage:changed",
  // Tool platform
  TOOL_RESULT: "tool:result",
  // AI
  AI_CONTEXT_REQUEST: "ai:context-request",
  // User-facing notifications (lets any module raise a toast without importing it)
  NOTIFY: "ui:notify",
});

// Events that retain their last payload for replay to late subscribers. These are
// "current state" signals rather than transient notifications.
const STICKY = new Set([
  EVENTS.SECTION_CHANGED,
  EVENTS.CONTEXT_CHANGED,
]);

export class EventBus {
  constructor({ sticky = STICKY, onError = null } = {}) {
    /** @type {Map<string, Set<Function>>} */
    this._handlers = new Map();
    /** @type {Map<string, any>} last payload for sticky events */
    this._last = new Map();
    this._sticky = sticky instanceof Set ? sticky : new Set(sticky);
    // Where handler exceptions go. Defaults to console.error; tests can capture.
    this._onError = typeof onError === "function" ? onError : (err, name) => {
      try { console.error(`[bus] handler for "${name}" threw:`, err); } catch (_) {}
    };
  }

  /**
   * Subscribe to an event. Returns an unsubscribe function.
   * @param {string} name
   * @param {Function} handler
   * @param {{replayLast?: boolean}} [opts] replayLast (default true) delivers the
   *        last payload immediately for sticky events.
   */
  on(name, handler, opts = {}) {
    if (typeof handler !== "function") throw new TypeError("bus.on requires a handler function");
    let set = this._handlers.get(name);
    if (!set) { set = new Set(); this._handlers.set(name, set); }
    set.add(handler);
    if (opts.replayLast !== false && this._sticky.has(name) && this._last.has(name)) {
      try { handler(this._last.get(name)); } catch (err) { this._onError(err, name); }
    }
    return () => this.off(name, handler);
  }

  /** Subscribe for exactly one emission, then auto-unsubscribe. */
  once(name, handler, opts = {}) {
    const off = this.on(name, (payload) => { off(); handler(payload); }, opts);
    return off;
  }

  /** Remove a specific handler. */
  off(name, handler) {
    const set = this._handlers.get(name);
    if (!set) return false;
    const removed = set.delete(handler);
    if (set.size === 0) this._handlers.delete(name);
    return removed;
  }

  /**
   * Publish an event. Every current handler is invoked in registration order;
   * a throwing handler is isolated (reported, not propagated). Returns the number
   * of handlers notified.
   */
  emit(name, payload) {
    if (this._sticky.has(name)) this._last.set(name, payload);
    const set = this._handlers.get(name);
    if (!set || set.size === 0) return 0;
    // Snapshot so handlers that (un)subscribe during dispatch don't corrupt it.
    let n = 0;
    for (const handler of [...set]) {
      try { handler(payload); n++; } catch (err) { this._onError(err, name); }
    }
    return n;
  }

  /** Number of handlers registered for an event (or total across all events). */
  listenerCount(name) {
    if (name === undefined) {
      let total = 0; for (const set of this._handlers.values()) total += set.size; return total;
    }
    const set = this._handlers.get(name);
    return set ? set.size : 0;
  }

  /** The last payload emitted for a sticky event, or undefined. */
  peek(name) { return this._last.get(name); }

  /** Remove all handlers for one event, or (no arg) reset the whole bus. Sticky
   *  values are cleared too. Primarily for teardown and tests. */
  clear(name) {
    if (name === undefined) { this._handlers.clear(); this._last.clear(); return; }
    this._handlers.delete(name);
    this._last.delete(name);
  }
}

// Process-wide singleton the app uses. Tests construct their own EventBus for
// isolation instead of sharing this one.
export const bus = new EventBus();
