// Deck tool bridge (D8). PURE — no DOM, no network. It defines the tiny message protocol the
// Deck host and its embedded tool iframes speak over postMessage: a tool announces a result the
// instant it writes to the graph (so the host refreshes without waiting for the storage event),
// asks the host to open an entity's detail or another tool, and receives a "focus this subject"
// deep link. This module only builds and validates message objects; the origin and source-window
// checks live in the host/tool wiring, because they need live window references. Same-origin only.

export const BRIDGE = "dnbridge";
export const BRIDGE_VERSION = 1;

// Message types. RESULT/OPEN_ENTITY/OPEN_TOOL/READY/PALETTE travel tool -> host; FOCUS travels host -> tool.
export const MSG = {
  READY: "ready",
  RESULT: "result",
  OPEN_ENTITY: "open-entity",
  OPEN_TOOL: "open-tool",
  PALETTE: "palette", // Ctrl/Cmd+K pressed inside the tool: open the host's search
  FOCUS: "focus",
};
const TYPES = new Set(Object.keys(MSG).map((k) => MSG[k]));

/**
 * makeMessage(type, payload) -> a plain object safe to postMessage, or null for an unknown type.
 * The payload is always coerced to a plain object so the receiver never has to null-check it.
 */
export function makeMessage(type, payload) {
  if (!TYPES.has(type)) return null;
  return { __b: BRIDGE, v: BRIDGE_VERSION, type: type, payload: payload && typeof payload === "object" ? payload : {} };
}

/**
 * parseMessage(data) -> { type, payload } when `data` is a well-formed bridge message of this
 * protocol version, else null. Never throws. The caller still checks event.origin and
 * event.source before trusting the result.
 */
export function parseMessage(data) {
  if (!data || typeof data !== "object") return null;
  if (data.__b !== BRIDGE || data.v !== BRIDGE_VERSION) return null;
  if (!TYPES.has(data.type)) return null;
  return { type: data.type, payload: data.payload && typeof data.payload === "object" ? data.payload : {} };
}

export const isBridgeType = (t) => TYPES.has(t);
