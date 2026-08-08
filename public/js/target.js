// Shared recon target — one domain/IP remembered across the console (localStorage),
// so dorks, exploit-DB pivots, and recon tools pre-fill without retyping.
const KEY = "sw_target";
export function getTarget() { try { return localStorage.getItem(KEY) || ""; } catch (_) { return ""; } }
export function setTarget(v) {
  v = (v || "").trim();
  try { localStorage.setItem(KEY, v); } catch (_) {}
  try { document.dispatchEvent(new CustomEvent("sentinel:target", { detail: v })); } catch (_) {}
  return v;
}
export function onTarget(cb) { document.addEventListener("sentinel:target", (e) => cb(e.detail)); }
