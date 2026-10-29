// Per-account storage keys. localStorage is shared by every account that signs in on a
// browser, so anything a user saves for themselves is keyed by the signed-in account
// (window.__dnUid, kept by auth.js). Guests and Test Mode share one "guest" scope; with no
// account the scope is "nouser". Same rule as userScope() in security-graph.js. Data under a
// tool's old unscoped key is left in place and no longer read.
export function accountScope(uid) {
  let u = uid;
  if (u === undefined) { try { u = globalThis.__dnUid || null; } catch (_) { u = null; } }
  return !u ? "nouser" : /^(test|app-guest)-/.test(u) ? "guest" : "u_" + u;
}
export const acctKey = (base) => base + "__" + accountScope();
