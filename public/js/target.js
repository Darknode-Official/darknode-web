import { acctKey } from "/js/core/account.js"; // per-account storage key
// Shared recon target: one domain/IP shared by the dorks, exploit-DB and recon tools on this
// page, so they pre-fill without retyping. Kept in memory only: a reload starts every box empty.
const KEY = "sw_target";
try { localStorage.removeItem(acctKey(KEY)); } catch (_) {} // drop the value older builds saved
let cur = "";
export function getTarget() { return cur; }
export function setTarget(v) {
  v = (v || "").trim();
  cur = v;
  try { document.dispatchEvent(new CustomEvent("darknode:target", { detail: v })); } catch (_) {}
  return v;
}
export function onTarget(cb) { document.addEventListener("darknode:target", (e) => cb(e.detail)); }
