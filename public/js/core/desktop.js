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

// Keep the native window-controls overlay the same colour as the top bar
// (Windows/Linux; macOS draws its own traffic lights). Re-runs when the theme flips.
export function syncTitlebar(doc = globalThis.document, g = globalThis) {
  if (!has("titlebar", g) || !doc || typeof g.darknode.titlebar !== "function") return;
  const toHex = (c) => {
    const m = String(c || "").match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)/);
    if (!m || (m[4] !== undefined && Number(m[4]) === 0)) return null;
    return "#" + [m[1], m[2], m[3]].map((n) => Number(n).toString(16).padStart(2, "0")).join("");
  };
  const apply = () => {
    try {
      const bar = doc.getElementById("topbar");
      const cs = bar && g.getComputedStyle(bar);
      const color = (cs && toHex(cs.backgroundColor)) || toHex(g.getComputedStyle(doc.body).backgroundColor);
      const symbolColor = (cs && toHex(cs.color)) || null;
      const height = bar ? Math.round(bar.getBoundingClientRect().height) : 0;
      const o = {};
      if (color) o.color = color;
      if (symbolColor) o.symbolColor = symbolColor;
      if (height >= 28 && height <= 80) o.height = height;
      if (Object.keys(o).length) g.darknode.titlebar(o);
    } catch (_) {}
  };
  apply();
  try {
    const mo = new g.MutationObserver(() => g.requestAnimationFrame(apply));
    mo.observe(doc.documentElement, { attributes: true, attributeFilter: ["data-theme", "data-style", "data-skin"] });
    mo.observe(doc.body, { attributes: true, attributeFilter: ["class"] });
  } catch (_) {}
}
