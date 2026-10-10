// ============================================================================
// Troll mode — an opt-in, deliberately infuriating skin. Everything goes askew,
// panels tilt, text wobbles, the cursor is a permanent "wait", and clickable
// things flinch away from the pointer. Toggle it from Settings > Appearance.
//
// Escape is ALWAYS possible: the Settings toggle is marked data-troll-safe and a
// fixed "Turn off troll mode" button (which never dodges) is pinned bottom-right
// while it is on. Nothing here is destructive — it only adds a class, a <style>,
// a couple of listeners and one button, all removed the instant you turn it off.
//   window.dnTroll.set(on) / .toggle() / .isOn()
// ============================================================================

const LS = "dn_troll";
const CLS = "dn-troll";
const STYLE_ID = "dn-troll-css";
const ESC_ID = "dn-troll-escape";

// Selectors that must NEVER dodge or be messed with — the escape routes.
const SAFE = "[data-troll-safe], #" + ESC_ID + ", #" + ESC_ID + " *";

function read() { try { return localStorage.getItem(LS) === "1"; } catch (_) { return false; } }
function write(on) { try { on ? localStorage.setItem(LS, "1") : localStorage.removeItem(LS); } catch (_) {} }

const CSS = `
html.${CLS}, html.${CLS} body { cursor: progress !important; }
html.${CLS} body {
  transform: rotate(-0.6deg);
  transform-origin: 50% 40%;
}
/* Comic everything */
html.${CLS} body, html.${CLS} button, html.${CLS} input, html.${CLS} textarea,
html.${CLS} select, html.${CLS} h1, html.${CLS} h2, html.${CLS} h3, html.${CLS} p,
html.${CLS} a, html.${CLS} span, html.${CLS} div, html.${CLS} label {
  font-family: "Comic Sans MS", "Comic Sans", "Chalkboard SE", cursive !important;
  letter-spacing: .2px;
}
/* Tilt the furniture so nothing lines up */
html.${CLS} .panel, html.${CLS} .set-panel, html.${CLS} .card, html.${CLS} .tk-card,
html.${CLS} .dk-gcard, html.${CLS} .pg-head {
  transform: rotate(-1.4deg) translateX(6px);
  transition: transform .3s cubic-bezier(.2,.9,.3,1.3);
}
html.${CLS} .panel:nth-of-type(even), html.${CLS} .card:nth-of-type(even),
html.${CLS} .tk-card:nth-of-type(even) { transform: rotate(1.7deg) translateX(-9px); }
html.${CLS} .panel:nth-of-type(3n), html.${CLS} .card:nth-of-type(3n) { transform: rotate(-2.3deg) translateY(5px); }
html.${CLS} .panel:hover, html.${CLS} .card:hover { transform: rotate(0deg) scale(1.01); }
/* Headings refuse to sit straight */
html.${CLS} h1, html.${CLS} .pg-h1 { transform: skew(-6deg, 1deg) rotate(-1deg); display: inline-block; }
html.${CLS} h2, html.${CLS} h3 { transform: skew(4deg, -1deg); display: inline-block; }
/* Buttons are slightly wrong */
html.${CLS} .btn, html.${CLS} button {
  transform: rotate(1.2deg);
  transition: transform .18s ease;
}
html.${CLS} .btn:nth-of-type(even) { transform: rotate(-1.6deg); }
/* A lazy, nauseating wobble on a few things */
html.${CLS} .pg-head, html.${CLS} .set-panel-h, html.${CLS} .panel-h {
  animation: dnTrollWobble 2.6s ease-in-out infinite;
}
@keyframes dnTrollWobble {
  0%,100% { transform: translateX(0) rotate(-1deg); }
  25% { transform: translateX(4px) rotate(1.5deg); }
  50% { transform: translateX(-3px) rotate(-1.8deg); }
  75% { transform: translateX(5px) rotate(1deg); }
}
/* Images and logos join in */
html.${CLS} img { transform: rotate(2deg); filter: hue-rotate(18deg); }
/* The things that let you escape stay perfectly, boringly normal */
html.${CLS} ${SAFE} {
  transform: none !important;
  animation: none !important;
  cursor: pointer !important;
  font-family: inherit;
}
/* The pinned escape hatch */
#${ESC_ID} {
  position: fixed; right: 18px; bottom: 18px; z-index: 2147483000;
  padding: 11px 16px; border-radius: 10px; border: 1px solid var(--line, #2a3550);
  background: var(--acc, #2563eb); color: #fff; font-weight: 600; font-size: 13px;
  box-shadow: 0 10px 30px rgba(0,0,0,.5); cursor: pointer !important;
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif !important;
}
#${ESC_ID}:hover { filter: brightness(1.08); }
`;

let moveHandler = null;
let keyHandler = null;
let resetTimer = null;

// QWERTY neighbours for believable typos; falls back to a random letter.
const NEIGHBORS = {
  a: "qwsz", b: "vghn", c: "xdfv", d: "serfcx", e: "wsdr", f: "drtgvc", g: "ftyhbv",
  h: "gyujnb", i: "ujko", j: "huikmn", k: "jiolm", l: "kop", m: "njk", n: "bhjm",
  o: "iklp", p: "ol", q: "wa", r: "edft", s: "awedxz", t: "rfgy", u: "yhji",
  v: "cfgb", w: "qase", x: "zsdc", y: "tghu", z: "asx"
};
function wrongChar(ch) {
  const lower = ch.toLowerCase();
  const up = ch !== lower;
  let pick;
  const n = NEIGHBORS[lower];
  if (n) pick = n[Math.floor(Math.random() * n.length)];
  else if (/[0-9]/.test(ch)) pick = String(Math.floor(Math.random() * 10));
  else return ch === " " ? "  " : ch; // leave punctuation/space mostly alone
  return up ? pick.toUpperCase() : pick;
}
function fumbleTyping(e) {
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (!e.key || e.key.length !== 1) return;              // only printable single chars
  const t = e.target;
  if (!t || (t.tagName !== "INPUT" && t.tagName !== "TEXTAREA")) return;
  if (t.type === "password") return;                      // never sabotage credentials
  if (t.closest && t.closest(SAFE)) return;               // never the escape routes
  if (typeof t.selectionStart !== "number") return;       // needs a caret (not email/number inputs)
  if (Math.random() > 0.7) return;                        // ~70% of keys land on the wrong key
  e.preventDefault();
  // Usually a single wrong key; sometimes a mash of two for extra chaos.
  let wrong = wrongChar(e.key);
  if (e.key !== " " && Math.random() < 0.3) wrong += wrongChar(e.key);
  const s = t.selectionStart, en = t.selectionEnd;
  try { t.setRangeText(wrong, s, en, "end"); t.dispatchEvent(new Event("input", { bubbles: true })); } catch (_) {}
}

function injectStyle() {
  if (document.getElementById(STYLE_ID)) return;
  const s = document.createElement("style");
  s.id = STYLE_ID; s.textContent = CSS;
  document.head.appendChild(s);
}
function removeStyle() { const s = document.getElementById(STYLE_ID); if (s) s.remove(); }

function addEscapeButton() {
  if (document.getElementById(ESC_ID)) return;
  const b = document.createElement("button");
  b.id = ESC_ID; b.type = "button"; b.setAttribute("data-troll-safe", "");
  b.textContent = "Turn off troll mode";
  b.addEventListener("click", () => { set(false); });
  document.body.appendChild(b);
}
function removeEscapeButton() { const b = document.getElementById(ESC_ID); if (b) b.remove(); }

// Clickable things flinch away from the pointer — but only a limited, springy
// nudge, so a determined click still lands. Safe elements never move.
function dodgeFrom(e) {
  const t = e.target && e.target.closest ? e.target.closest(".btn, button, a, input[type=button], input[type=submit], [role=button]") : null;
  if (!t) return;
  if (t.closest(SAFE)) return;
  const r = t.getBoundingClientRect();
  const cxp = r.left + r.width / 2, cyp = r.top + r.height / 2;
  const dx = cxp - e.clientX, dy = cyp - e.clientY;
  const dist = Math.hypot(dx, dy) || 1;
  if (dist > 46) return; // only flinch when the pointer is close
  const push = 60 + Math.random() * 40;
  const nx = (dx / dist) * push + (Math.random() - 0.5) * 20;
  const ny = (dy / dist) * push + (Math.random() - 0.5) * 20;
  t.style.transition = "transform .12s ease-out";
  t.style.transform = `translate(${nx.toFixed(0)}px, ${ny.toFixed(0)}px) rotate(${(Math.random() * 10 - 5).toFixed(1)}deg)`;
  clearTimeout(resetTimer);
  resetTimer = setTimeout(() => { try { t.style.transform = ""; } catch (_) {} }, 650);
}

function enable() {
  document.documentElement.classList.add(CLS);
  injectStyle();
  addEscapeButton();
  if (!moveHandler) { moveHandler = (e) => dodgeFrom(e); document.addEventListener("pointermove", moveHandler, { passive: true }); }
  if (!keyHandler) { keyHandler = (e) => fumbleTyping(e); document.addEventListener("keydown", keyHandler, true); }
}
function disable() {
  document.documentElement.classList.remove(CLS);
  removeStyle();
  removeEscapeButton();
  if (moveHandler) { document.removeEventListener("pointermove", moveHandler); moveHandler = null; }
  if (keyHandler) { document.removeEventListener("keydown", keyHandler, true); keyHandler = null; }
  clearTimeout(resetTimer);
  // clear any inline transforms a dodge left behind
  try { document.querySelectorAll('[style*="translate"]').forEach((el) => { if (/translate/.test(el.style.transform)) el.style.transform = ""; }); } catch (_) {}
}

// Keep the viewport still when toggling — the font swap reflows text widths.
function preserveScroll(fn) {
  let anchor = null, top0 = 0;
  try {
    anchor = document.elementFromPoint(Math.round(innerWidth / 2), Math.round(Math.min(160, innerHeight * 0.3)));
    if (anchor) top0 = anchor.getBoundingClientRect().top;
  } catch (_) {}
  fn();
  if (anchor && anchor.isConnected) {
    try { const dy = anchor.getBoundingClientRect().top - top0; if (Math.abs(dy) > 0.5) scrollBy(0, dy); } catch (_) {}
  }
}

function set(on) {
  write(!!on);
  preserveScroll(() => (on ? enable() : disable()));
  try { if (window.showToast) window.showToast(on ? "Troll mode on. Good luck." : "Troll mode off. Order restored.", on ? "error" : "success"); } catch (_) {}
}
function toggle() { set(!read()); }
function isOn() { return read(); }

// Auto-apply on load if it was left on.
function init() { if (read()) { if (document.body) enable(); else document.addEventListener("DOMContentLoaded", enable, { once: true }); } }

window.dnTroll = { set, toggle, isOn };
init();

export { set, toggle, isOn };
