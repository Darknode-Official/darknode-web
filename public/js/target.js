import { acctKey } from "/js/core/account.js"; // per-account storage key
// Shared recon target — one domain/IP remembered across the console (localStorage),
// so dorks, exploit-DB pivots, and recon tools pre-fill without retyping.
const KEY = "sw_target";
export function getTarget() { try { return localStorage.getItem(acctKey(KEY)) || ""; } catch (_) { return ""; } }
export function setTarget(v) {
  v = (v || "").trim();
  try { localStorage.setItem(acctKey(KEY), v); } catch (_) {}
  try { document.dispatchEvent(new CustomEvent("darknode:target", { detail: v })); } catch (_) {}
  return v;
}
export function onTarget(cb) { document.addEventListener("darknode:target", (e) => cb(e.detail)); }
