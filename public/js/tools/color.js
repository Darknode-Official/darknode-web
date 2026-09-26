// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Color & design mini-tools.

// ---- shared helpers (module-scope, not exported) ----
const ERR = "Enter a color like #3276EA or rgb(50,118,234).";

const NAMED = {
  black:"#000000", white:"#ffffff", red:"#ff0000", lime:"#00ff00", blue:"#0000ff",
  yellow:"#ffff00", cyan:"#00ffff", aqua:"#00ffff", magenta:"#ff00ff", fuchsia:"#ff00ff",
  silver:"#c0c0c0", gray:"#808080", grey:"#808080", maroon:"#800000", olive:"#808000",
  green:"#008000", purple:"#800080", teal:"#008080", navy:"#000080", orange:"#ffa500",
  aliceblue:"#f0f8ff", antiquewhite:"#faebd7", aquamarine:"#7fffd4", azure:"#f0ffff",
  beige:"#f5f5dc", bisque:"#ffe4c4", blanchedalmond:"#ffebcd", blueviolet:"#8a2be2",
  brown:"#a52a2a", burlywood:"#deb887", cadetblue:"#5f9ea0", chartreuse:"#7fff00",
  chocolate:"#d2691e", coral:"#ff7f50", cornflowerblue:"#6495ed", cornsilk:"#fff8dc",
  crimson:"#dc143c", darkblue:"#00008b", darkcyan:"#008b8b", darkgoldenrod:"#b8860b",
  darkgray:"#a9a9a9", darkgreen:"#006400", darkkhaki:"#bdb76b", darkmagenta:"#8b008b",
  darkolivegreen:"#556b2f", darkorange:"#ff8c00", "darkorchid":"#9932cc", darkred:"#8b0000",
  darksalmon:"#e9967a", darkseagreen:"#8fbc8f", darkslateblue:"#483d8b",
  darkslategray:"#2f4f4f", darkturquoise:"#00ced1", darkviolet:"#9400d3",
  deeppink:"#ff1493", deepskyblue:"#00bfff", dimgray:"#696969", dodgerblue:"#1e90ff",
  firebrick:"#b22222", forestgreen:"#228b22", gold:"#ffd700", goldenrod:"#daa520",
  greenyellow:"#adff2f", hotpink:"#ff69b4", indianred:"#cd5c5c", indigo:"#4b0082",
  ivory:"#fffff0", khaki:"#f0e68c", lavender:"#e6e6fa", lightblue:"#add8e6",
  lightcoral:"#f08080", lightgreen:"#90ee90", lightpink:"#ffb6c1", lightyellow:"#ffffe0",
  limegreen:"#32cd32", linen:"#faf0e6", midnightblue:"#191970", mintcream:"#f5fffa",
  navajowhite:"#ffdead", "orchid":"#da70d6", palegreen:"#98fb98", peru:"#cd853f",
  pink:"#ffc0cb", plum:"#dda0dd", salmon:"#fa8072", seagreen:"#2e8b57", sienna:"#a0522d",
  skyblue:"#87ceeb", slateblue:"#6a5acd", slategray:"#708090", springgreen:"#00ff7f",
  steelblue:"#4682b4", tan:"#d2b48c", tomato:"#ff6347", turquoise:"#40e0d0",
  violet:"#ee82ee", wheat:"#f5deb3", whitesmoke:"#f5f5f5"
};

function clamp(x, a, b) { return x < a ? a : x > b ? b : x; }
function ci(x) { return clamp(Math.round(x), 0, 255); }
function r2(x) { return Math.round(x * 100) / 100; }
function isEmpty(s) { return s == null || String(s).trim() === ""; }

function parse(str) {
  if (str == null) return null;
  let s = String(str).trim().toLowerCase();
  if (!s) return null;
  if (NAMED[s]) s = NAMED[s];
  let m = s.match(/^#?([0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i);
  if (m) {
    let h = m[1];
    if (h.length === 3) h = h.split("").map(c => c + c).join("") ;
    if (h.length === 4) h = h.split("").map(c => c + c).join("");
    const r = parseInt(h.slice(0, 2), 16);
    const g = parseInt(h.slice(2, 4), 16);
    const b = parseInt(h.slice(4, 6), 16);
    const a = h.length === 8 ? parseInt(h.slice(6, 8), 16) / 255 : 1;
    return { r, g, b, a };
  }
  m = s.match(/^rgba?\(([^)]+)\)$/);
  let body = null;
  if (m) body = m[1];
  else if (/^-?\d/.test(s) && s.indexOf(",") >= 0) body = s;
  if (body != null) {
    const parts = body.split(/[\s,\/]+/).filter(x => x !== "");
    if (parts.length >= 3) {
      const conv = (p) => p.indexOf("%") >= 0 ? (parseFloat(p) / 100) * 255 : parseFloat(p);
      const r = conv(parts[0]), g = conv(parts[1]), b = conv(parts[2]);
      let a = 1;
      if (parts.length >= 4) {
        const p = parts[3];
        a = p.indexOf("%") >= 0 ? parseFloat(p) / 100 : parseFloat(p);
      }
      if ([r, g, b, a].some(x => isNaN(x))) return null;
      return { r: ci(r), g: ci(g), b: ci(b), a: clamp(a, 0, 1) };
    }
  }
  return null;
}

function toHex(r, g, b) {
  return "#" + [r, g, b].map(x => ci(x).toString(16).padStart(2, "0")).join("");
}
function toHex8(r, g, b, a) {
  return toHex(r, g, b) + clamp(Math.round(a * 255), 0, 255).toString(16).padStart(2, "0");
}
function nums(str) {
  return String(str).replace(/[%°]/g, "").trim().split(/[\s,]+/).filter(x => x !== "").map(Number);
}

function rgbToHsl(r, g, b) {
  r /= 255; g /= 255; b /= 255;
  const mx = Math.max(r, g, b), mn = Math.min(r, g, b);
  let h = 0, s = 0, l = (mx + mn) / 2;
  if (mx !== mn) {
    const d = mx - mn;
    s = l > 0.5 ? d / (2 - mx - mn) : d / (mx + mn);
    if (mx === r) h = (g - b) / d + (g < b ? 6 : 0);
    else if (mx === g) h = (b - r) / d + 2;
    else h = (r - g) / d + 4;
    h /= 6;
  }
  return [h * 360, s * 100, l * 100];
}
function hslToRgb(h, s, l) {
  h = (((h % 360) + 360) % 360) / 360; s /= 100; l /= 100;
  let r, g, b;
  if (s === 0) { r = g = b = l; }
  else {
    const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
    const p = 2 * l - q;
    const hue = (t) => {
      t = (t % 1 + 1) % 1;
      if (t < 1 / 6) return p + (q - p) * 6 * t;
      if (t < 1 / 2) return q;
      if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
      return p;
    };
    r = hue(h + 1 / 3); g = hue(h); b = hue(h - 1 / 3);
  }
  return [r * 255, g * 255, b * 255];
}
function rgbToHsv(r, g, b) {
  r /= 255; g /= 255; b /= 255;
  const mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn;
  let h = 0;
  if (d !== 0) {
    if (mx === r) h = ((g - b) / d) % 6;
    else if (mx === g) h = (b - r) / d + 2;
    else h = (r - g) / d + 4;
    h *= 60; if (h < 0) h += 360;
  }
  const s = mx === 0 ? 0 : d / mx;
  return [h, s * 100, mx * 100];
}
function hsvToRgb(h, s, v) {
  h = ((h % 360) + 360) % 360; s /= 100; v /= 100;
  const c = v * s, x = c * (1 - Math.abs((h / 60) % 2 - 1)), m = v - c;
  let r = 0, g = 0, b = 0;
  if (h < 60) { r = c; g = x; }
  else if (h < 120) { r = x; g = c; }
  else if (h < 180) { g = c; b = x; }
  else if (h < 240) { g = x; b = c; }
  else if (h < 300) { r = x; b = c; }
  else { r = c; b = x; }
  return [(r + m) * 255, (g + m) * 255, (b + m) * 255];
}
function rgbToCmyk(r, g, b) {
  r /= 255; g /= 255; b /= 255;
  const k = 1 - Math.max(r, g, b);
  if (k === 1) return [0, 0, 0, 100];
  return [((1 - r - k) / (1 - k)) * 100, ((1 - g - k) / (1 - k)) * 100, ((1 - b - k) / (1 - k)) * 100, k * 100];
}
function cmykToRgb(c, m, y, k) {
  c /= 100; m /= 100; y /= 100; k /= 100;
  return [255 * (1 - c) * (1 - k), 255 * (1 - m) * (1 - k), 255 * (1 - y) * (1 - k)];
}
function srgbToLin(c) { c /= 255; return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); }
function linToSrgb(c) { return 255 * (c <= 0.0031308 ? 12.92 * c : 1.055 * Math.pow(c, 1 / 2.4) - 0.055); }
function rgbToXyz(r, g, b) {
  const R = srgbToLin(r), G = srgbToLin(g), B = srgbToLin(b);
  return [
    (R * 0.4124564 + G * 0.3575761 + B * 0.1804375) * 100,
    (R * 0.2126729 + G * 0.7151522 + B * 0.0721750) * 100,
    (R * 0.0193339 + G * 0.1191920 + B * 0.9503041) * 100
  ];
}
function xyzToRgb(X, Y, Z) {
  X /= 100; Y /= 100; Z /= 100;
  const R = X * 3.2404542 - Y * 1.5371385 - Z * 0.4985314;
  const G = -X * 0.9692660 + Y * 1.8760108 + Z * 0.0415560;
  const B = X * 0.0556434 - Y * 0.2040259 + Z * 1.0572252;
  return [linToSrgb(R), linToSrgb(G), linToSrgb(B)];
}
const Xn = 95.047, Yn = 100, Zn = 108.883;
function xyzToLab(X, Y, Z) {
  const f = t => t > 0.008856 ? Math.cbrt(t) : 7.787 * t + 16 / 116;
  const fx = f(X / Xn), fy = f(Y / Yn), fz = f(Z / Zn);
  return [116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)];
}
function labToXyz(L, a, b) {
  const fy = (L + 16) / 116, fx = fy + a / 500, fz = fy - b / 200;
  const g = t => { const t3 = t * t * t; return t3 > 0.008856 ? t3 : (t - 16 / 116) / 7.787; };
  return [g(fx) * Xn, g(fy) * Yn, g(fz) * Zn];
}
function rgbToLab(r, g, b) { const [x, y, z] = rgbToXyz(r, g, b); return xyzToLab(x, y, z); }
function labToRgb(L, a, b) { const [x, y, z] = labToXyz(L, a, b); return xyzToRgb(x, y, z); }
function rgbToOklab(r, g, b) {
  const R = srgbToLin(r), G = srgbToLin(g), B = srgbToLin(b);
  const l = Math.cbrt(0.4122214708 * R + 0.5363325363 * G + 0.0514459929 * B);
  const m = Math.cbrt(0.2119034982 * R + 0.6806995451 * G + 0.1073969566 * B);
  const s = Math.cbrt(0.0883024619 * R + 0.2817188376 * G + 0.6299787005 * B);
  return [
    0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s
  ];
}
function oklabToRgb(L, a, b) {
  const l_ = L + 0.3963377774 * a + 0.2158037573 * b;
  const m_ = L - 0.1055613458 * a - 0.0638541728 * b;
  const s_ = L - 0.0894841775 * a - 1.2914855480 * b;
  const l = l_ * l_ * l_, m = m_ * m_ * m_, s = s_ * s_ * s_;
  const R = 4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s;
  const G = -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s;
  const B = -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s;
  return [linToSrgb(R), linToSrgb(G), linToSrgb(B)];
}
function relLum(r, g, b) {
  const R = srgbToLin(r), G = srgbToLin(g), B = srgbToLin(b);
  return 0.2126 * R + 0.7152 * G + 0.0722 * B;
}
function contrastRatio(c1, c2) {
  const l1 = relLum(c1.r, c1.g, c1.b), l2 = relLum(c2.r, c2.g, c2.b);
  const hi = Math.max(l1, l2), lo = Math.min(l1, l2);
  return (hi + 0.05) / (lo + 0.05);
}
function hslStr(r, g, b) {
  const [h, s, l] = rgbToHsl(r, g, b);
  return `hsl(${Math.round(h)}, ${Math.round(s)}%, ${Math.round(l)}%)`;
}
function rgbStr(r, g, b) { return `rgb(${ci(r)}, ${ci(g)}, ${ci(b)})`; }
function randBytes(H, n) {
  if (H && typeof H.randBytes === "function") return H.randBytes(n);
  const a = new Uint8Array(n);
  (globalThis.crypto || {}).getRandomValues ? globalThis.crypto.getRandomValues(a) : a.fill(0);
  return a;
}
function col(ph) { return { k: "c", label: "Color", type: "text", placeholder: ph || "#3276EA" }; }

export const TOOLS = [
  {
    id: "col-hex-rgb", name: "HEX to RGB", cat: "color", tags: ["hex", "rgb"],
    desc: "Convert between HEX and RGB in either direction.",
    inputs: [col("#3276EA"), { k: "mode", label: "Direction", type: "select", opts: ["HEX -> RGB", "RGB -> HEX"], value: "HEX -> RGB" }],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      return v.mode === "RGB -> HEX" ? toHex(c.r, c.g, c.b) : rgbStr(c.r, c.g, c.b);
    }
  },
  {
    id: "col-hex-rgba", name: "HEX to RGBA", cat: "color", tags: ["hex", "rgba", "alpha"],
    desc: "Convert a color (with optional alpha) between HEX and rgba().",
    inputs: [col("#3276EAff"), { k: "mode", label: "Direction", type: "select", opts: ["HEX -> RGBA", "RGBA -> HEX"], value: "HEX -> RGBA" }],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      return v.mode === "RGBA -> HEX" ? toHex8(c.r, c.g, c.b, c.a) : `rgba(${c.r}, ${c.g}, ${c.b}, ${r2(c.a)})`;
    }
  },
  {
    id: "col-rgb-hex", name: "RGB to HEX", cat: "color", tags: ["rgb", "hex"],
    desc: "Convert an RGB color to a #RRGGBB hex string.",
    inputs: [col("rgb(50,118,234)")],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      return toHex(c.r, c.g, c.b);
    }
  },
  {
    id: "col-rgb-hsl", name: "RGB / HSL", cat: "color", tags: ["rgb", "hsl"],
    desc: "Convert a color between RGB and HSL.",
    inputs: [col(), { k: "mode", label: "Direction", type: "select", opts: ["RGB -> HSL", "HSL -> RGB"], value: "RGB -> HSL" }],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      if (v.mode === "HSL -> RGB") {
        const [h, s, l] = rgbToHsl(c.r, c.g, c.b);
        return rgbStr(...hslToRgb(h, s, l));
      }
      return hslStr(c.r, c.g, c.b);
    }
  },
  {
    id: "col-rgb-hsv", name: "RGB to HSV", cat: "color", tags: ["rgb", "hsv"],
    desc: "Convert a color to HSV (hue, saturation, value).",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s, val] = rgbToHsv(c.r, c.g, c.b);
      return `hsv(${Math.round(h)}, ${Math.round(s)}%, ${Math.round(val)}%)`;
    }
  },
  {
    id: "col-rgb-cmyk", name: "RGB to CMYK", cat: "color", tags: ["rgb", "cmyk", "print"],
    desc: "Convert a color to CMYK print percentages.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [cy, m, y, k] = rgbToCmyk(c.r, c.g, c.b);
      return `cmyk(${Math.round(cy)}%, ${Math.round(m)}%, ${Math.round(y)}%, ${Math.round(k)}%)`;
    }
  },
  {
    id: "col-rgb-oklch", name: "RGB to OKLCH", cat: "color", tags: ["oklch", "rgb"],
    desc: "Convert a color to the OKLCH color space.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [L, a, b] = rgbToOklab(c.r, c.g, c.b);
      const C = Math.hypot(a, b);
      let h = Math.atan2(b, a) * 180 / Math.PI; if (h < 0) h += 360;
      return `oklch(${(L * 100).toFixed(1)}% ${C.toFixed(4)} ${h.toFixed(1)})`;
    }
  },
  {
    id: "col-rgb-oklab", name: "RGB to OKLab", cat: "color", tags: ["oklab", "rgb"],
    desc: "Convert a color to the perceptual OKLab color space.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [L, a, b] = rgbToOklab(c.r, c.g, c.b);
      return `oklab(${(L * 100).toFixed(1)}% ${a.toFixed(4)} ${b.toFixed(4)})`;
    }
  },
  {
    id: "col-rgb-xyz", name: "RGB to XYZ", cat: "color", tags: ["xyz", "rgb"],
    desc: "Convert a color to CIE 1931 XYZ (D65).",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [X, Y, Z] = rgbToXyz(c.r, c.g, c.b);
      return `X: ${r2(X)}  Y: ${r2(Y)}  Z: ${r2(Z)}`;
    }
  },
  {
    id: "col-rgb-lab", name: "RGB to LAB", cat: "color", tags: ["lab", "cielab", "rgb"],
    desc: "Convert a color to CIELAB (L*a*b*).",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [L, a, b] = rgbToLab(c.r, c.g, c.b);
      return `lab(${r2(L)} ${r2(a)} ${r2(b)})`;
    }
  },
  {
    id: "col-hex-hsl", name: "HEX to HSL", cat: "color", tags: ["hex", "hsl"],
    desc: "Convert a hex color to an HSL string.",
    inputs: [col("#3276EA")],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      return hslStr(c.r, c.g, c.b);
    }
  },
  {
    id: "col-hex-hsv", name: "HEX to HSV", cat: "color", tags: ["hex", "hsv"],
    desc: "Convert a hex color to an HSV string.",
    inputs: [col("#3276EA")],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s, val] = rgbToHsv(c.r, c.g, c.b);
      return `hsv(${Math.round(h)}, ${Math.round(s)}%, ${Math.round(val)}%)`;
    }
  },
  {
    id: "col-hex-cmyk", name: "HEX to CMYK", cat: "color", tags: ["hex", "cmyk"],
    desc: "Convert a hex color to CMYK percentages.",
    inputs: [col("#3276EA")],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [cy, m, y, k] = rgbToCmyk(c.r, c.g, c.b);
      return `cmyk(${Math.round(cy)}%, ${Math.round(m)}%, ${Math.round(y)}%, ${Math.round(k)}%)`;
    }
  },
  {
    id: "col-hsl-hex", name: "HSL to HEX", cat: "color", tags: ["hsl", "hex"],
    desc: "Convert HSL values (h, s%, l%) to a hex color.",
    inputs: [{ k: "t", label: "HSL", type: "text", placeholder: "210, 80, 50" }],
    run(v) {
      if (isEmpty(v.t)) return "";
      const n = nums(v.t); if (n.length < 3 || n.some(isNaN)) return { error: "Enter HSL like 210, 80, 50." };
      return toHex(...hslToRgb(n[0], n[1], n[2]));
    }
  },
  {
    id: "col-hsv-hex", name: "HSV to HEX", cat: "color", tags: ["hsv", "hex"],
    desc: "Convert HSV values (h, s%, v%) to a hex color.",
    inputs: [{ k: "t", label: "HSV", type: "text", placeholder: "210, 79, 92" }],
    run(v) {
      if (isEmpty(v.t)) return "";
      const n = nums(v.t); if (n.length < 3 || n.some(isNaN)) return { error: "Enter HSV like 210, 79, 92." };
      return toHex(...hsvToRgb(n[0], n[1], n[2]));
    }
  },
  {
    id: "col-name-hex", name: "CSS Name to HEX", cat: "color", tags: ["css", "name", "hex"],
    desc: "Look up the hex value of a CSS named color.",
    inputs: [{ k: "t", label: "Color name", type: "text", placeholder: "cornflowerblue" }],
    run(v) {
      if (isEmpty(v.t)) return "";
      const key = String(v.t).trim().toLowerCase();
      if (NAMED[key]) return NAMED[key];
      return { error: `Unknown CSS color name "${v.t}". Try e.g. crimson, teal, coral.` };
    }
  },
  {
    id: "col-hex-name", name: "Nearest CSS Name", cat: "color", tags: ["hex", "name", "nearest"],
    desc: "Find the closest CSS named color to any color.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      let best = null, bd = Infinity;
      for (const k in NAMED) {
        const n = parse(NAMED[k]);
        const d = (c.r - n.r) ** 2 + (c.g - n.g) ** 2 + (c.b - n.b) ** 2;
        if (d < bd) { bd = d; best = k; }
      }
      return `${best} (${NAMED[best]})${bd === 0 ? " — exact match" : ""}`;
    }
  },
  {
    id: "col-luminance", name: "Relative Luminance", cat: "color", tags: ["wcag", "luminance"],
    desc: "Compute the WCAG relative luminance of a color.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      return `Relative luminance: ${relLum(c.r, c.g, c.b).toFixed(4)}`;
    }
  },
  {
    id: "col-contrast", name: "WCAG Contrast Ratio", cat: "color", tags: ["wcag", "contrast", "a11y"],
    desc: "Compute the WCAG contrast ratio between two colors and report pass/fail.",
    inputs: [col("#ffffff"), { k: "c2", label: "Second color", type: "text", placeholder: "#333333" }],
    run(v) {
      if (isEmpty(v.c) || isEmpty(v.c2)) return "";
      const a = parse(v.c), b = parse(v.c2);
      if (!a || !b) return { error: ERR };
      const cr = contrastRatio(a, b);
      const p = (ok) => ok ? "PASS" : "fail";
      return [
        `Contrast ratio: ${cr.toFixed(2)}:1`,
        `Normal text  AA (>=4.5): ${p(cr >= 4.5)}   AAA (>=7): ${p(cr >= 7)}`,
        `Large text   AA (>=3):   ${p(cr >= 3)}   AAA (>=4.5): ${p(cr >= 4.5)}`
      ].join("\n");
    }
  },
  {
    id: "col-lighten", name: "Lighten", cat: "color", tags: ["lighten", "hsl"],
    desc: "Increase a color's HSL lightness by a percentage.",
    inputs: [col(), { k: "amt", label: "Amount %", type: "range", min: 0, max: 100, step: 1, value: 15 }],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s, l] = rgbToHsl(c.r, c.g, c.b);
      return toHex(...hslToRgb(h, s, clamp(l + Number(v.amt), 0, 100)));
    }
  },
  {
    id: "col-darken", name: "Darken", cat: "color", tags: ["darken", "hsl"],
    desc: "Decrease a color's HSL lightness by a percentage.",
    inputs: [col(), { k: "amt", label: "Amount %", type: "range", min: 0, max: 100, step: 1, value: 15 }],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s, l] = rgbToHsl(c.r, c.g, c.b);
      return toHex(...hslToRgb(h, s, clamp(l - Number(v.amt), 0, 100)));
    }
  },
  {
    id: "col-saturate", name: "Saturate", cat: "color", tags: ["saturate", "hsl"],
    desc: "Increase a color's HSL saturation by a percentage.",
    inputs: [col(), { k: "amt", label: "Amount %", type: "range", min: 0, max: 100, step: 1, value: 20 }],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s, l] = rgbToHsl(c.r, c.g, c.b);
      return toHex(...hslToRgb(h, clamp(s + Number(v.amt), 0, 100), l));
    }
  },
  {
    id: "col-desaturate", name: "Desaturate", cat: "color", tags: ["desaturate", "hsl"],
    desc: "Decrease a color's HSL saturation by a percentage.",
    inputs: [col(), { k: "amt", label: "Amount %", type: "range", min: 0, max: 100, step: 1, value: 20 }],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s, l] = rgbToHsl(c.r, c.g, c.b);
      return toHex(...hslToRgb(h, clamp(s - Number(v.amt), 0, 100), l));
    }
  },
  {
    id: "col-grayscale", name: "Grayscale", cat: "color", tags: ["grayscale", "desaturate"],
    desc: "Convert a color to grayscale using luminance weighting.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const y = ci(0.299 * c.r + 0.587 * c.g + 0.114 * c.b);
      return toHex(y, y, y);
    }
  },
  {
    id: "col-invert", name: "Invert Color", cat: "color", tags: ["invert", "negative"],
    desc: "Invert a color (photographic negative).",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      return toHex(255 - c.r, 255 - c.g, 255 - c.b);
    }
  },
  {
    id: "col-mix", name: "Mix Two Colors", cat: "color", tags: ["mix", "blend"],
    desc: "Mix two colors by a ratio (0% = all first, 100% = all second).",
    inputs: [col("#ff0000"), { k: "c2", label: "Second color", type: "text", placeholder: "#0000ff" }, { k: "amt", label: "Mix % toward 2nd", type: "range", min: 0, max: 100, step: 1, value: 50 }],
    run(v) {
      if (isEmpty(v.c) || isEmpty(v.c2)) return "";
      const a = parse(v.c), b = parse(v.c2);
      if (!a || !b) return { error: ERR };
      const t = clamp(Number(v.amt), 0, 100) / 100;
      return toHex(a.r + (b.r - a.r) * t, a.g + (b.g - a.g) * t, a.b + (b.b - a.b) * t);
    }
  },
  {
    id: "col-complementary", name: "Complementary Color", cat: "color", tags: ["harmony", "complementary"],
    desc: "Compute the complementary color (hue + 180 degrees).",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s, l] = rgbToHsl(c.r, c.g, c.b);
      return toHex(...hslToRgb(h + 180, s, l));
    }
  },
  {
    id: "col-analogous", name: "Analogous Colors", cat: "color", tags: ["harmony", "analogous"],
    desc: "Generate analogous colors at plus/minus 30 degrees hue.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s, l] = rgbToHsl(c.r, c.g, c.b);
      return [h - 30, h, h + 30].map(x => toHex(...hslToRgb(x, s, l))).join("  ");
    }
  },
  {
    id: "col-triadic", name: "Triadic Colors", cat: "color", tags: ["harmony", "triadic"],
    desc: "Generate a triadic color scheme (hues 120 degrees apart).",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s, l] = rgbToHsl(c.r, c.g, c.b);
      return [h, h + 120, h + 240].map(x => toHex(...hslToRgb(x, s, l))).join("  ");
    }
  },
  {
    id: "col-tetradic", name: "Tetradic Colors", cat: "color", tags: ["harmony", "tetradic"],
    desc: "Generate a tetradic (rectangle) color scheme of four hues.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s, l] = rgbToHsl(c.r, c.g, c.b);
      return [h, h + 90, h + 180, h + 270].map(x => toHex(...hslToRgb(x, s, l))).join("  ");
    }
  },
  {
    id: "col-split-comp", name: "Split-Complementary", cat: "color", tags: ["harmony", "split"],
    desc: "Generate a split-complementary color scheme.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s, l] = rgbToHsl(c.r, c.g, c.b);
      return [h, h + 150, h + 210].map(x => toHex(...hslToRgb(x, s, l))).join("  ");
    }
  },
  {
    id: "col-monochromatic", name: "Monochromatic Palette", cat: "color", tags: ["palette", "monochrome"],
    desc: "Generate N shades of one hue at varying lightness.",
    inputs: [col(), { k: "n", label: "Shades", type: "range", min: 2, max: 12, step: 1, value: 6 }],
    run(v, H) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const n = H && H.clampInt ? H.clampInt(v.n, 2, 12, 6) : clamp(parseInt(v.n) || 6, 2, 12);
      const [h, s] = rgbToHsl(c.r, c.g, c.b);
      const out = [];
      for (let i = 0; i < n; i++) out.push(toHex(...hslToRgb(h, s, 10 + (80 * i) / (n - 1))));
      return out.join("  ");
    }
  },
  {
    id: "col-tints", name: "Tints Generator", cat: "color", tags: ["tints", "palette"],
    desc: "Generate tints by mixing a color toward white.",
    inputs: [col(), { k: "n", label: "Steps", type: "range", min: 2, max: 12, step: 1, value: 6 }],
    run(v, H) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const n = H && H.clampInt ? H.clampInt(v.n, 2, 12, 6) : clamp(parseInt(v.n) || 6, 2, 12);
      const out = [];
      for (let i = 0; i < n; i++) {
        const t = i / (n - 1);
        out.push(toHex(c.r + (255 - c.r) * t, c.g + (255 - c.g) * t, c.b + (255 - c.b) * t));
      }
      return out.join("  ");
    }
  },
  {
    id: "col-shades", name: "Shades Generator", cat: "color", tags: ["shades", "palette"],
    desc: "Generate shades by mixing a color toward black.",
    inputs: [col(), { k: "n", label: "Steps", type: "range", min: 2, max: 12, step: 1, value: 6 }],
    run(v, H) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const n = H && H.clampInt ? H.clampInt(v.n, 2, 12, 6) : clamp(parseInt(v.n) || 6, 2, 12);
      const out = [];
      for (let i = 0; i < n; i++) {
        const t = i / (n - 1);
        out.push(toHex(c.r * (1 - t), c.g * (1 - t), c.b * (1 - t)));
      }
      return out.join("  ");
    }
  },
  {
    id: "col-linear-gradient", name: "CSS Linear Gradient", cat: "color", tags: ["css", "gradient"],
    desc: "Build a CSS linear-gradient from two colors and an angle.",
    inputs: [col("#3276EA"), { k: "c2", label: "End color", type: "text", placeholder: "#ff00aa" }, { k: "ang", label: "Angle (deg)", type: "range", min: 0, max: 360, step: 5, value: 90 }],
    run(v) {
      if (isEmpty(v.c) || isEmpty(v.c2)) return "";
      const a = parse(v.c), b = parse(v.c2);
      if (!a || !b) return { error: ERR };
      return `background: linear-gradient(${Math.round(Number(v.ang))}deg, ${toHex(a.r, a.g, a.b)}, ${toHex(b.r, b.g, b.b)});`;
    }
  },
  {
    id: "col-radial-gradient", name: "CSS Radial Gradient", cat: "color", tags: ["css", "gradient"],
    desc: "Build a CSS radial-gradient from two colors.",
    inputs: [col("#3276EA"), { k: "c2", label: "Edge color", type: "text", placeholder: "#000000" }],
    run(v) {
      if (isEmpty(v.c) || isEmpty(v.c2)) return "";
      const a = parse(v.c), b = parse(v.c2);
      if (!a || !b) return { error: ERR };
      return `background: radial-gradient(circle, ${toHex(a.r, a.g, a.b)}, ${toHex(b.r, b.g, b.b)});`;
    }
  },
  {
    id: "col-random-hex", name: "Random HEX Color", cat: "color", tags: ["random", "hex"],
    desc: "Generate a random hex color.",
    inputs: [],
    run(v, H) {
      const b = randBytes(H, 3);
      return toHex(b[0], b[1], b[2]);
    }
  },
  {
    id: "col-random-palette", name: "Random Palette", cat: "color", tags: ["random", "palette"],
    desc: "Generate a palette of N random hex colors.",
    inputs: [{ k: "n", label: "Colors", type: "range", min: 2, max: 12, step: 1, value: 5 }],
    run(v, H) {
      const n = H && H.clampInt ? H.clampInt(v.n, 2, 12, 5) : clamp(parseInt(v.n) || 5, 2, 12);
      const b = randBytes(H, n * 3);
      const out = [];
      for (let i = 0; i < n; i++) out.push(toHex(b[i * 3], b[i * 3 + 1], b[i * 3 + 2]));
      return out.join("  ");
    }
  },
  {
    id: "col-css-rgb", name: "To CSS rgb()", cat: "color", tags: ["css", "rgb"],
    desc: "Format any color as a CSS rgb() string.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      return rgbStr(c.r, c.g, c.b);
    }
  },
  {
    id: "col-css-hsl", name: "To CSS hsl()", cat: "color", tags: ["css", "hsl"],
    desc: "Format any color as a CSS hsl() string.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      return hslStr(c.r, c.g, c.b);
    }
  },
  {
    id: "col-alpha-composite", name: "Alpha Compositing", cat: "color", tags: ["alpha", "blend", "composite"],
    desc: "Blend a foreground color over a background at a given alpha.",
    inputs: [{ k: "fg", label: "Foreground", type: "text", placeholder: "#ff0000" }, { k: "bg", label: "Background", type: "text", placeholder: "#ffffff" }, { k: "amt", label: "Alpha %", type: "range", min: 0, max: 100, step: 1, value: 50 }],
    run(v) {
      if (isEmpty(v.fg) || isEmpty(v.bg)) return "";
      const f = parse(v.fg), b = parse(v.bg);
      if (!f || !b) return { error: ERR };
      const a = clamp(Number(v.amt), 0, 100) / 100;
      return toHex(f.r * a + b.r * (1 - a), f.g * a + b.g * (1 - a), f.b * a + b.b * (1 - a));
    }
  },
  {
    id: "col-hex8-rgba", name: "8-digit HEX / RGBA", cat: "color", tags: ["hex8", "rgba", "alpha"],
    desc: "Convert between 8-digit hex (with alpha) and rgba().",
    inputs: [col("#3276EAcc"), { k: "mode", label: "Direction", type: "select", opts: ["HEX8 -> RGBA", "RGBA -> HEX8"], value: "HEX8 -> RGBA" }],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      return v.mode === "RGBA -> HEX8" ? toHex8(c.r, c.g, c.b, c.a) : `rgba(${c.r}, ${c.g}, ${c.b}, ${r2(c.a)})`;
    }
  },
  {
    id: "col-rotate-hue", name: "Rotate Hue", cat: "color", tags: ["hsl", "hue", "rotate"],
    desc: "Rotate a color's HSL hue by N degrees.",
    inputs: [col(), { k: "deg", label: "Degrees", type: "range", min: -180, max: 180, step: 5, value: 60 }],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s, l] = rgbToHsl(c.r, c.g, c.b);
      return toHex(...hslToRgb(h + Number(v.deg), s, l));
    }
  },
  {
    id: "col-web-safe", name: "Nearest Web-Safe", cat: "color", tags: ["websafe", "216"],
    desc: "Snap a color to the nearest web-safe (216) color.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const snap = x => Math.round(x / 51) * 51;
      return toHex(snap(c.r), snap(c.g), snap(c.b));
    }
  },
  {
    id: "col-light-dark", name: "Light or Dark?", cat: "color", tags: ["brightness", "a11y"],
    desc: "Report whether a color is perceptually light or dark.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const yiq = (c.r * 299 + c.g * 587 + c.b * 114) / 1000;
      return `${yiq >= 128 ? "Light" : "Dark"} (perceived brightness ${Math.round(yiq)}/255)`;
    }
  },
  {
    id: "col-best-text", name: "Best Text Color", cat: "color", tags: ["a11y", "contrast", "text"],
    desc: "Pick black or white text for best contrast on a background.",
    inputs: [col("#3276EA")],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const black = parse("#000000"), white = parse("#ffffff");
      const cb = contrastRatio(c, black), cw = contrastRatio(c, white);
      return cb >= cw ? `#000000 (contrast ${cb.toFixed(2)}:1)` : `#ffffff (contrast ${cw.toFixed(2)}:1)`;
    }
  },
  {
    id: "col-kelvin-rgb", name: "Kelvin to RGB", cat: "color", tags: ["temperature", "kelvin", "white"],
    desc: "Approximate an RGB color from a color temperature in Kelvin.",
    inputs: [{ k: "amt", label: "Kelvin", type: "range", min: 1000, max: 12000, step: 100, value: 6500 }],
    run(v) {
      const t = clamp(Number(v.amt), 1000, 40000) / 100;
      let r, g, b;
      if (t <= 66) { r = 255; g = 99.4708025861 * Math.log(t) - 161.1195681661; }
      else { r = 329.698727446 * Math.pow(t - 60, -0.1332047592); g = 288.1221695283 * Math.pow(t - 60, -0.0755148492); }
      if (t >= 66) b = 255;
      else if (t <= 19) b = 0;
      else b = 138.5177312231 * Math.log(t - 10) - 305.0447927307;
      return toHex(ci(r), ci(g), ci(b));
    }
  },
  {
    id: "col-blindness", name: "Color Blindness Sim", cat: "color", tags: ["a11y", "cvd", "simulate"],
    desc: "Simulate how a color appears under common color-vision deficiencies.",
    inputs: [col(), { k: "mode", label: "Type", type: "select", opts: ["Protanopia", "Deuteranopia", "Tritanopia"], value: "Protanopia" }],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const M = {
        Protanopia: [[0.567, 0.433, 0], [0.558, 0.442, 0], [0, 0.242, 0.758]],
        Deuteranopia: [[0.625, 0.375, 0], [0.7, 0.3, 0], [0, 0.3, 0.7]],
        Tritanopia: [[0.95, 0.05, 0], [0, 0.433, 0.567], [0, 0.475, 0.525]]
      }[v.mode];
      const r = M[0][0] * c.r + M[0][1] * c.g + M[0][2] * c.b;
      const g = M[1][0] * c.r + M[1][1] * c.g + M[1][2] * c.b;
      const b = M[2][0] * c.r + M[2][1] * c.g + M[2][2] * c.b;
      return toHex(r, g, b);
    }
  },
  {
    id: "col-sepia", name: "Sepia Filter", cat: "color", tags: ["filter", "sepia"],
    desc: "Apply a sepia-tone transform to a color.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const r = 0.393 * c.r + 0.769 * c.g + 0.189 * c.b;
      const g = 0.349 * c.r + 0.686 * c.g + 0.168 * c.b;
      const b = 0.272 * c.r + 0.534 * c.g + 0.131 * c.b;
      return toHex(r, g, b);
    }
  },
  {
    id: "col-brightness", name: "Brightness Adjust", cat: "color", tags: ["filter", "brightness"],
    desc: "Scale a color's brightness by a percentage (100% = unchanged).",
    inputs: [col(), { k: "amt", label: "Brightness %", type: "range", min: 0, max: 300, step: 5, value: 120 }],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const f = Number(v.amt) / 100;
      return toHex(c.r * f, c.g * f, c.b * f);
    }
  },
  {
    id: "col-contrast-adjust", name: "Contrast Adjust", cat: "color", tags: ["filter", "contrast"],
    desc: "Adjust a color's contrast around mid-gray (100% = unchanged).",
    inputs: [col(), { k: "amt", label: "Contrast %", type: "range", min: 0, max: 300, step: 5, value: 150 }],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const f = Number(v.amt) / 100;
      const adj = x => (x - 128) * f + 128;
      return toHex(adj(c.r), adj(c.g), adj(c.b));
    }
  },
  {
    id: "col-hue-rotate-filter", name: "Hue-Rotate Filter", cat: "color", tags: ["filter", "css", "hue"],
    desc: "Apply a CSS-style hue-rotate matrix and return the CSS filter plus result.",
    inputs: [col(), { k: "deg", label: "Degrees", type: "range", min: 0, max: 360, step: 5, value: 90 }],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const a = Number(v.deg) * Math.PI / 180, cos = Math.cos(a), sin = Math.sin(a);
      const m = [
        0.213 + cos * 0.787 - sin * 0.213, 0.715 - cos * 0.715 - sin * 0.715, 0.072 - cos * 0.072 + sin * 0.928,
        0.213 - cos * 0.213 + sin * 0.143, 0.715 + cos * 0.285 + sin * 0.140, 0.072 - cos * 0.072 - sin * 0.283,
        0.213 - cos * 0.213 - sin * 0.787, 0.715 - cos * 0.715 + sin * 0.715, 0.072 + cos * 0.928 + sin * 0.072
      ];
      const r = m[0] * c.r + m[1] * c.g + m[2] * c.b;
      const g = m[3] * c.r + m[4] * c.g + m[5] * c.b;
      const b = m[6] * c.r + m[7] * c.g + m[8] * c.b;
      return `filter: hue-rotate(${Math.round(Number(v.deg))}deg);  ->  ${toHex(r, g, b)}`;
    }
  },
  {
    id: "col-rgb-int", name: "RGB to Integer", cat: "color", tags: ["integer", "rgb"],
    desc: "Convert a color to its 24-bit integer value.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const n = (c.r << 16) | (c.g << 8) | c.b;
      return `${n}  (0x${n.toString(16).padStart(6, "0").toUpperCase()})`;
    }
  },
  {
    id: "col-int-hex", name: "Integer to HEX", cat: "color", tags: ["integer", "hex"],
    desc: "Convert a 24-bit integer (decimal or 0x) to a hex color.",
    inputs: [{ k: "t", label: "Integer", type: "text", placeholder: "3307754" }],
    run(v) {
      if (isEmpty(v.t)) return "";
      const s = String(v.t).trim();
      const n = /^0x/i.test(s) ? parseInt(s, 16) : parseInt(s, 10);
      if (isNaN(n) || n < 0 || n > 0xFFFFFF) return { error: "Enter an integer from 0 to 16777215." };
      return toHex((n >> 16) & 255, (n >> 8) & 255, n & 255);
    }
  },
  {
    id: "col-hex-expand", name: "Expand Short HEX", cat: "color", tags: ["hex", "shorthand"],
    desc: "Expand a shorthand #abc hex into full #aabbcc form.",
    inputs: [{ k: "t", label: "Short hex", type: "text", placeholder: "#abc" }],
    run(v) {
      if (isEmpty(v.t)) return "";
      const m = String(v.t).trim().match(/^#?([0-9a-f]{3,4})$/i);
      if (!m) return { error: "Enter a 3- or 4-digit hex like #abc or #abcd." };
      return "#" + m[1].split("").map(c => c + c).join("");
    }
  },
  {
    id: "col-hex-validate", name: "Validate / Normalize HEX", cat: "color", tags: ["hex", "validate"],
    desc: "Validate a hex color and normalize it to lowercase #rrggbb.",
    inputs: [{ k: "t", label: "Hex", type: "text", placeholder: "#3276ea" }],
    run(v) {
      if (isEmpty(v.t)) return "";
      const c = parse(v.t);
      const raw = String(v.t).trim();
      if (!c || !/^#?[0-9a-f]{3,8}$/i.test(raw)) return { error: "Not a valid hex color." };
      return `Valid — normalized: ${toHex(c.r, c.g, c.b)}${c.a < 1 ? ` (alpha ${r2(c.a)})` : ""}`;
    }
  },
  {
    id: "col-rgb-percent", name: "RGB Percent / 0-255", cat: "color", tags: ["rgb", "percent"],
    desc: "Convert RGB channels between 0-255 and 0-100% notation.",
    inputs: [{ k: "t", label: "Values", type: "text", placeholder: "128, 64, 255" }, { k: "mode", label: "Direction", type: "select", opts: ["0-255 -> %", "% -> 0-255"], value: "0-255 -> %" }],
    run(v) {
      if (isEmpty(v.t)) return "";
      const n = nums(v.t); if (n.length < 3 || n.some(isNaN)) return { error: "Enter three numbers, e.g. 128, 64, 255." };
      if (v.mode === "% -> 0-255") return n.slice(0, 3).map(x => ci(x / 100 * 255)).join(", ");
      return n.slice(0, 3).map(x => r2(clamp(x, 0, 255) / 255 * 100) + "%").join(", ");
    }
  },
  {
    id: "col-hsl-rgb", name: "HSL to RGB", cat: "color", tags: ["hsl", "rgb"],
    desc: "Convert HSL values (h, s%, l%) to an rgb() string.",
    inputs: [{ k: "t", label: "HSL", type: "text", placeholder: "210, 80, 50" }],
    run(v) {
      if (isEmpty(v.t)) return "";
      const n = nums(v.t); if (n.length < 3 || n.some(isNaN)) return { error: "Enter HSL like 210, 80, 50." };
      return rgbStr(...hslToRgb(n[0], n[1], n[2]));
    }
  },
  {
    id: "col-hsv-rgb", name: "HSV to RGB", cat: "color", tags: ["hsv", "rgb"],
    desc: "Convert HSV values (h, s%, v%) to an rgb() string.",
    inputs: [{ k: "t", label: "HSV", type: "text", placeholder: "210, 79, 92" }],
    run(v) {
      if (isEmpty(v.t)) return "";
      const n = nums(v.t); if (n.length < 3 || n.some(isNaN)) return { error: "Enter HSV like 210, 79, 92." };
      return rgbStr(...hsvToRgb(n[0], n[1], n[2]));
    }
  },
  {
    id: "col-cmyk-rgb", name: "CMYK to RGB", cat: "color", tags: ["cmyk", "rgb"],
    desc: "Convert CMYK percentages (c, m, y, k) to a hex color.",
    inputs: [{ k: "t", label: "CMYK", type: "text", placeholder: "79, 50, 0, 8" }],
    run(v) {
      if (isEmpty(v.t)) return "";
      const n = nums(v.t); if (n.length < 4 || n.some(isNaN)) return { error: "Enter CMYK like 79, 50, 0, 8." };
      return toHex(...cmykToRgb(n[0], n[1], n[2], n[3]));
    }
  },
  {
    id: "col-distance", name: "Color Distance", cat: "color", tags: ["distance", "euclidean"],
    desc: "Compute the Euclidean RGB distance between two colors.",
    inputs: [col("#ff0000"), { k: "c2", label: "Second color", type: "text", placeholder: "#00ff00" }],
    run(v) {
      if (isEmpty(v.c) || isEmpty(v.c2)) return "";
      const a = parse(v.c), b = parse(v.c2);
      if (!a || !b) return { error: ERR };
      const d = Math.sqrt((a.r - b.r) ** 2 + (a.g - b.g) ** 2 + (a.b - b.b) ** 2);
      return `Distance: ${r2(d)} (max ${r2(Math.sqrt(3) * 255)})`;
    }
  },
  {
    id: "col-gradient-midpoint", name: "Gradient Midpoint", cat: "color", tags: ["gradient", "mix"],
    desc: "Compute the midpoint color between two colors.",
    inputs: [col("#3276EA"), { k: "c2", label: "Second color", type: "text", placeholder: "#ff00aa" }],
    run(v) {
      if (isEmpty(v.c) || isEmpty(v.c2)) return "";
      const a = parse(v.c), b = parse(v.c2);
      if (!a || !b) return { error: ERR };
      return toHex((a.r + b.r) / 2, (a.g + b.g) / 2, (a.b + b.b) / 2);
    }
  },
  {
    id: "col-scheme5", name: "5-Color Scheme", cat: "color", tags: ["palette", "scheme", "harmony"],
    desc: "Generate a 5-color scheme (base, complement, analogous, accent) from a base color.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s, l] = rgbToHsl(c.r, c.g, c.b);
      return [
        toHex(c.r, c.g, c.b),
        toHex(...hslToRgb(h - 30, s, l)),
        toHex(...hslToRgb(h + 30, s, l)),
        toHex(...hslToRgb(h + 180, s, l)),
        toHex(...hslToRgb(h + 180, clamp(s - 10, 0, 100), clamp(l + 15, 0, 100)))
      ].join("  ");
    }
  },
  {
    id: "col-hsl-hsv", name: "HSL to HSV", cat: "color", tags: ["hsl", "hsv"],
    desc: "Convert HSL values (h, s%, l%) to HSV.",
    inputs: [{ k: "t", label: "HSL", type: "text", placeholder: "210, 80, 50" }],
    run(v) {
      if (isEmpty(v.t)) return "";
      const n = nums(v.t); if (n.length < 3 || n.some(isNaN)) return { error: "Enter HSL like 210, 80, 50." };
      const [h, s, val] = rgbToHsv(...hslToRgb(n[0], n[1], n[2]));
      return `hsv(${Math.round(h)}, ${Math.round(s)}%, ${Math.round(val)}%)`;
    }
  },
  {
    id: "col-lum-sort", name: "Sort by Luminance", cat: "color", tags: ["sort", "luminance", "palette"],
    desc: "Sort a list of colors from darkest to lightest by relative luminance.",
    inputs: [{ k: "text", label: "Colors", type: "textarea", rows: 5, placeholder: "#3276EA\n#ff0000\nrgb(0,200,0)" }],
    run(v) {
      if (isEmpty(v.text)) return "";
      const items = String(v.text).match(/#[0-9a-fA-F]{3,8}|rgba?\([^)]*\)|[a-zA-Z]+/g) || [];
      const parsed = [];
      for (const it of items) {
        const c = parse(it);
        if (!c) return { error: `Could not parse "${it}". ` + ERR };
        parsed.push({ hex: toHex(c.r, c.g, c.b), y: relLum(c.r, c.g, c.b) });
      }
      parsed.sort((a, b) => a.y - b.y);
      return parsed.map(p => `${p.hex}  (${p.y.toFixed(3)})`).join("\n");
    }
  },
  {
    id: "col-hsv-hsl", name: "HSV to HSL", cat: "color", tags: ["hsv", "hsl"],
    desc: "Convert HSV values (h, s%, v%) to HSL.",
    inputs: [{ k: "t", label: "HSV", type: "text", placeholder: "210, 79, 92" }],
    run(v) {
      if (isEmpty(v.t)) return "";
      const n = nums(v.t); if (n.length < 3 || n.some(isNaN)) return { error: "Enter HSV like 210, 79, 92." };
      const [h, s, l] = rgbToHsl(...hsvToRgb(n[0], n[1], n[2]));
      return `hsl(${Math.round(h)}, ${Math.round(s)}%, ${Math.round(l)}%)`;
    }
  },
  {
    id: "col-average", name: "Average Colors", cat: "color", tags: ["average", "mix", "palette"],
    desc: "Compute the average color of a list of colors.",
    inputs: [{ k: "text", label: "Colors", type: "textarea", rows: 5, placeholder: "#ff0000\n#00ff00\n#0000ff" }],
    run(v) {
      if (isEmpty(v.text)) return "";
      const items = String(v.text).match(/#[0-9a-fA-F]{3,8}|rgba?\([^)]*\)|[a-zA-Z]+/g) || [];
      if (!items.length) return "";
      let r = 0, g = 0, b = 0;
      for (const it of items) {
        const c = parse(it);
        if (!c) return { error: `Could not parse "${it}". ` + ERR };
        r += c.r; g += c.g; b += c.b;
      }
      return toHex(r / items.length, g / items.length, b / items.length);
    }
  },
  {
    id: "col-warm-cool", name: "Warm or Cool?", cat: "color", tags: ["hue", "temperature"],
    desc: "Classify a color as warm or cool based on its hue.",
    inputs: [col()],
    run(v) {
      if (isEmpty(v.c)) return "";
      const c = parse(v.c); if (!c) return { error: ERR };
      const [h, s] = rgbToHsl(c.r, c.g, c.b);
      if (s < 5) return `Neutral (hue ${Math.round(h)}, low saturation)`;
      const cool = h > 90 && h < 270;
      return `${cool ? "Cool" : "Warm"} (hue ${Math.round(h)} degrees)`;
    }
  }
];
