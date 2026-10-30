// Tool-side half of the Deck tool bridge (D8). Loaded only inside an embedded tool frame
// (/<sec>?embed=1 inside the admin Deck). It forwards every in-frame tool result to the host the
// instant the sink fires, so the host refreshes immediately instead of waiting for the localStorage
// `storage` event — the storage path still runs, so this is a speed-up, not a dependency. It also
// exposes window.dnBridge so a tool can ask the host to open an entity or another tool, and receive
// a "focus this subject" deep link. Everything is same-origin and guarded; if the host is absent or
// postMessage throws, the tool keeps working exactly as before.
import { bus, EVENTS } from "../core/bus.js";
import { makeMessage, parseMessage, MSG } from "../core/tool-bridge.js";

export function initEmbedBridge(win) {
  const w = win || window;
  // Only inside a real frame with a parent of the same origin.
  if (!w.parent || w.parent === w) return null;
  const origin = w.location.origin;
  const post = (type, payload) => {
    const m = makeMessage(type, payload);
    if (!m) return;
    try { w.parent.postMessage(m, origin); } catch (_) { /* host gone or cross-origin: ignore */ }
  };

  // Forward each tool result emitted on the in-frame bus (the sink fires EVENTS.TOOL_RESULT).
  let off = null;
  try {
    off = bus.on(EVENTS.TOOL_RESULT, (p) => post(MSG.RESULT, { tool: p && p.tool, created: p && p.created, updated: p && p.updated }));
  } catch (_) { off = null; }

  // Host -> tool focus deep links.
  const focusCbs = [];
  const onMsg = (e) => {
    if (e.origin !== origin || e.source !== w.parent) return; // host only
    const m = parseMessage(e.data);
    if (!m || m.type !== MSG.FOCUS) return;
    focusCbs.slice().forEach((cb) => { try { cb(m.payload); } catch (_) {} });
  };
  w.addEventListener("message", onMsg);

  const api = {
    announce: (r) => post(MSG.RESULT, r || {}),
    openEntity: (id) => post(MSG.OPEN_ENTITY, { id: String(id == null ? "" : id) }),
    openTool: (sec, focus) => post(MSG.OPEN_TOOL, { sec: String(sec == null ? "" : sec), focus: focus || null }),
    onFocus: (cb) => {
      if (typeof cb !== "function") return () => {};
      focusCbs.push(cb);
      return () => { const i = focusCbs.indexOf(cb); if (i >= 0) focusCbs.splice(i, 1); };
    },
    ready: () => post(MSG.READY, {}),
    palette: () => post(MSG.PALETTE, {}),
    teardown: () => { try { off && off(); } catch (_) {} w.removeEventListener("message", onMsg); try { if (w.dnBridge === api) delete w.dnBridge; } catch (_) {} },
  };
  try { w.dnBridge = api; } catch (_) {}
  api.ready(); // tells the host this frame is listening (lets it deliver a queued focus)
  return api;
}
