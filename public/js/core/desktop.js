// Desktop-mode detection.
//
// The Darknode desktop app serves this same website from its own local origin and,
// in the top-level frame only, adds window.darknode.desktop = { version, platform,
// arch, shell, caps: [...] } plus the matching native methods. Everything here reads
// that object defensively: a normal browser (or a tool iframe inside the app) has
// no desktop object and gets isDesktop() === false and caps() === [].
//
// This is a UX switch, never a security boundary. Page script can fake the object;
// the app's main process checks every native call on its own.

function desktopInfo(g) {
  try {
    const d = g && g.darknode && g.darknode.desktop;
    return d && typeof d === "object" && Array.isArray(d.caps) ? d : null;
  } catch (_) { return null; }
}

export function isDesktop(g = globalThis) { return !!desktopInfo(g); }

export function caps(g = globalThis) {
  const d = desktopInfo(g);
  return d ? d.caps.filter((c) => typeof c === "string") : [];
}

export function has(cap, g = globalThis) { return caps(g).includes(cap); }

export function info(g = globalThis) {
  const d = desktopInfo(g);
  return d ? { version: String(d.version || ""), platform: String(d.platform || ""), arch: String(d.arch || ""), caps: caps(g) } : null;
}

// What a colour looks like on screen after a CSS `filter` chain of invert() and
// hue-rotate() (the Deck draws its dark "ink" look by inverting a light design).
// Matrices per the Filter Effects spec; other filter functions are ignored.
export function filteredRgb(rgb, filter) {
  let [r, g, b] = rgb.map((v) => v / 255);
  const re = /(invert|hue-rotate)\(\s*([-\d.]+)(deg|turn|rad|%)?\s*\)/g;
  let m;
  while ((m = re.exec(String(filter || "")))) {
    if (m[1] === "invert") {
      const a = Math.min(1, Math.max(0, m[3] === "%" ? Number(m[2]) / 100 : Number(m[2])));
      [r, g, b] = [r, g, b].map((c) => a + c * (1 - 2 * a));
    } else {
      const deg = m[3] === "turn" ? Number(m[2]) * 360 : m[3] === "rad" ? Number(m[2]) * 180 / Math.PI : Number(m[2]);
      const c = Math.cos(deg * Math.PI / 180), s = Math.sin(deg * Math.PI / 180);
      [r, g, b] = [
        r * (0.213 + c * 0.787 - s * 0.213) + g * (0.715 - c * 0.715 - s * 0.715) + b * (0.072 - c * 0.072 + s * 0.928),
        r * (0.213 - c * 0.213 + s * 0.143) + g * (0.715 + c * 0.285 + s * 0.140) + b * (0.072 - c * 0.072 - s * 0.283),
        r * (0.213 - c * 0.213 - s * 0.787) + g * (0.715 - c * 0.715 + s * 0.715) + b * (0.072 + c * 0.928 + s * 0.072),
      ];
    }
  }
  return [r, g, b].map((v) => Math.round(Math.min(1, Math.max(0, v)) * 255));
}

// Keep the native window-controls overlay the same colour and height as the bar under
// it (Windows/Linux; macOS draws its own traffic lights): the Deck's header when the
// Deck is up, else the site's top bar. Re-runs when the theme flips or the Deck mounts.
export function syncTitlebar(doc = globalThis.document, g = globalThis) {
  if (!has("titlebar", g) || !doc || typeof g.darknode.titlebar !== "function") return;
  const rgbOf = (c) => {
    const m = String(c || "").match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)/);
    return !m || (m[4] !== undefined && Number(m[4]) === 0) ? null : [m[1], m[2], m[3]].map(Number);
  };
  const toHex = (rgb) => "#" + rgb.map((n) => n.toString(16).padStart(2, "0")).join("");
  let last = "";
  const apply = () => {
    try {
      const bar = (doc.querySelector && doc.querySelector("body > .dk .dk-top")) || doc.getElementById("topbar");
      const cs = bar && g.getComputedStyle(bar);
      const look = (rgb) => (rgb && cs ? filteredRgb(rgb, cs.filter) : rgb);
      const bg = (cs && rgbOf(cs.backgroundColor)) ? look(rgbOf(cs.backgroundColor)) : rgbOf(g.getComputedStyle(doc.body).backgroundColor);
      const fg = cs && rgbOf(cs.color) ? look(rgbOf(cs.color)) : null;
      // clientHeight leaves the bar's bottom border visible under the window buttons.
      const height = bar ? (bar.clientHeight || Math.round(bar.getBoundingClientRect().height)) : 0;
      const o = {};
      if (bg) o.color = toHex(bg);
      if (fg) o.symbolColor = toHex(fg);
      if (height >= 28 && height <= 80) o.height = height;
      const key = JSON.stringify(o);
      if (key !== "{}" && key !== last) { last = key; g.darknode.titlebar(o); }
    } catch (_) {}
  };
  apply();
  try {
    const mo = new g.MutationObserver(() => g.requestAnimationFrame(apply));
    mo.observe(doc.documentElement, { attributes: true, attributeFilter: ["data-theme", "data-style", "data-skin"] });
    mo.observe(doc.body, { attributes: true, attributeFilter: ["class"], childList: true });
  } catch (_) {}
}
