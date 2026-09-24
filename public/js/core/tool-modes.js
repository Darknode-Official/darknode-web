// Darknode per-tool operational modes: SCOUTING / DEFENSIVE / OFFENSIVE.
//
// Each flagship tool can operate in three postures, and switching posture
// changes what the tool shows and does:
//   - scouting  — discover / enumerate / map ("what's out there, what's exposed?")
//   - defensive — monitor / detect / harden ("protect & detect") [default]
//   - offensive — SIMULATED adversary emulation to test defenses ("how would an
//                 attacker hit this, and do we catch it?") — wargaming, never a
//                 live attack capability.
//
// This module is the shared mechanism every flagship uses so the behavior,
// look, and persistence are identical everywhere:
//   - a canonical MODES catalog (id, label, accent, blurb)
//   - filterTabsByMode(): a tab declares `modes: ['scouting','offensive']`;
//     untagged tabs appear in every mode (mode-agnostic)
//   - per-tool persistence of the last-used mode (via core/store.js)
//   - mountModeSwitcher(): renders the segmented switcher, retints the tool via
//     a `data-tool-mode` attribute, and calls back with the filtered tab set
//
// The pure logic (catalog, filtering, get/set) is unit-tested; the DOM mount is
// verified in-browser.

import { store } from "./store.js";

export const MODES = Object.freeze([
  { id: "scouting", label: "SCOUTING", accent: "#f59e0b", blurb: "Discover, enumerate & map exposure" },
  { id: "defensive", label: "DEFENSIVE", accent: "#2563eb", blurb: "Monitor, detect & harden" },
  { id: "offensive", label: "OFFENSIVE", accent: "#dc2626", blurb: "Simulated adversary emulation" },
]);

export const MODE_IDS = Object.freeze(MODES.map((m) => m.id));
export const DEFAULT_MODE = "defensive";

export function isMode(id) { return MODE_IDS.includes(id); }

export function modeInfo(id) { return MODES.find((m) => m.id === id) || null; }

export function modeAccent(id) { const m = modeInfo(id); return m ? m.accent : MODES[1].accent; }

/**
 * Return the tabs visible in `modeId`. A tab with no `modes` array (or an empty
 * one) is mode-agnostic and shows in every mode. Otherwise it shows only when
 * its `modes` list includes the active mode.
 */
export function filterTabsByMode(tabs, modeId) {
  return (tabs || []).filter((t) => !Array.isArray(t.modes) || t.modes.length === 0 || t.modes.includes(modeId));
}

/** Which modes have at least one tab (so we never show an empty posture). */
export function availableModes(tabs) {
  const present = new Set();
  let hasAgnostic = false;
  for (const t of tabs || []) {
    if (!Array.isArray(t.modes) || t.modes.length === 0) hasAgnostic = true;
    else for (const m of t.modes) if (isMode(m)) present.add(m);
  }
  // Agnostic-only tools still get all three postures; otherwise honor declared set.
  const ids = hasAgnostic && present.size === 0 ? MODE_IDS.slice() : MODE_IDS.filter((m) => present.has(m));
  return MODES.filter((m) => ids.includes(m.id));
}

// --- persistence -------------------------------------------------------------

const _ns = () => store.namespace("tool-modes");

/** Last-used mode for a tool, falling back to a valid default. */
export function getToolMode(toolId, fallback = DEFAULT_MODE) {
  const v = _ns().get(String(toolId));
  if (isMode(v)) return v;
  return isMode(fallback) ? fallback : DEFAULT_MODE;
}

export function setToolMode(toolId, modeId) {
  if (!isMode(modeId)) return false;
  try { _ns().set(String(toolId), modeId); } catch (_) { /* quota: non-fatal */ }
  return true;
}

// --- DOM: the segmented switcher (browser only) ------------------------------

let _cssInjected = false;
function injectCss() {
  if (_cssInjected || typeof document === "undefined") return;
  _cssInjected = true;
  const el = document.createElement("style");
  el.id = "dn-tool-modes-css";
  el.textContent = `
.dn-modebar{display:inline-flex;align-items:center;gap:0;border:1px solid var(--brd,#e2e8f0);border-radius:8px;overflow:hidden;background:var(--card-bg,#fff)}
.dn-modebtn{appearance:none;border:none;background:transparent;color:var(--mut,#64748b);font:700 .72rem/1 ui-sans-serif,system-ui,sans-serif;letter-spacing:.06em;padding:8px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:background .15s,color .15s;border-right:1px solid var(--brd,#e2e8f0)}
.dn-modebtn:last-child{border-right:none}
.dn-modebtn:hover{background:var(--hover,#f1f5f9);color:var(--txt,#0f172a)}
.dn-modebtn .dn-modedot{width:8px;height:8px;border-radius:50%;background:currentColor;opacity:.5}
.dn-modebtn.on{color:#fff}
.dn-modebtn.on .dn-modedot{opacity:1;background:#fff}
.dn-modebar[data-mode=scouting] .dn-modebtn.on{background:#f59e0b}
.dn-modebar[data-mode=defensive] .dn-modebtn.on{background:#2563eb}
.dn-modebar[data-mode=offensive] .dn-modebtn.on{background:#dc2626}
.dn-modenote{font-size:.72rem;color:var(--mut,#64748b);margin-left:10px}
/* Per-mode accent applied to the tool wrapper via [data-tool-mode]. Tools can
   read var(--mode-accent) for buttons, active tabs, borders, etc. */
[data-tool-mode=scouting]{--mode-accent:#f59e0b;--mode-accent-soft:rgba(245,158,11,.12)}
[data-tool-mode=defensive]{--mode-accent:#2563eb;--mode-accent-soft:rgba(37,99,235,.12)}
[data-tool-mode=offensive]{--mode-accent:#dc2626;--mode-accent-soft:rgba(220,38,38,.12)}
`;
  (document.head || document.documentElement).appendChild(el);
}

/** Build the switcher markup for a set of modes (exported for testing/SSR). */
export function switcherHtml(modes, activeId) {
  return `<div class="dn-modebar" data-mode="${activeId}" role="tablist" aria-label="Operational mode">` +
    modes.map((m) => `<button class="dn-modebtn${m.id === activeId ? " on" : ""}" role="tab" aria-selected="${m.id === activeId}" data-mode-id="${m.id}" title="${m.blurb}"><span class="dn-modedot" style="color:${m.accent}"></span>${m.label}</button>`).join("") +
    `</div>`;
}

/**
 * Render the mode switcher and wire it up.
 * @param {object} opts
 *   toolId   — stable id used for persistence (e.g. "navarch")
 *   tabs     — the tool's full tab list (each may carry a `modes` array)
 *   mount    — element to render the switcher into
 *   host     — element to receive the `data-tool-mode` accent attribute
 *              (defaults to `mount`); usually the tool's outer wrapper
 *   onChange — (modeId, visibleTabs) => void, called on mount and each switch
 *   note     — optional element/selector to show the active mode's blurb in
 * @returns {{ mode:string, setMode:(id:string)=>void, modes:Array }}
 */
export function mountModeSwitcher(opts) {
  injectCss();
  const { toolId, tabs, mount, onChange } = opts;
  const host = opts.host || mount;
  const modes = availableModes(tabs);
  let active = getToolMode(toolId);
  if (!modes.some((m) => m.id === active)) active = (modes[0] && modes[0].id) || DEFAULT_MODE;

  function paint() {
    mount.innerHTML = switcherHtml(modes, active);
    if (host && host.setAttribute) host.setAttribute("data-tool-mode", active);
    const noteEl = opts.note ? (typeof opts.note === "string" ? document.querySelector(opts.note) : opts.note) : null;
    if (noteEl) noteEl.textContent = (modeInfo(active) || {}).blurb || "";
    mount.querySelectorAll("[data-mode-id]").forEach((b) => {
      b.addEventListener("click", () => select(b.dataset.modeId));
    });
  }

  function select(id) {
    if (!isMode(id) || id === active || !modes.some((m) => m.id === id)) {
      if (id === active) return; // no-op but still fine
    }
    if (!modes.some((m) => m.id === id)) return;
    active = id;
    setToolMode(toolId, id);
    paint();
    fire();
  }

  function fire() { if (typeof onChange === "function") onChange(active, filterTabsByMode(tabs, active)); }

  paint();
  fire();
  return { get mode() { return active; }, setMode: select, modes };
}
