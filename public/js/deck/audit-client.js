// Thin client for the GraphDO audit log (Deck D6). Reads the per-workspace, hash-chained
// record of graph writes over the same /api/graph/<wid> endpoint the cloud sync uses, with
// the signed-in user's Firebase token and the active workspace id. Owner/admin only — the
// worker enforces that; this is pure transport. The scene (deck/audit.js) owns the UI.
import { activeWorkspaceId } from "/js/security-graph.js";

const proxyBase = () => { try { return String(window.DARKNODE_PROXY_URL || "").replace(/\/api\/chat$/, ""); } catch (_) { return ""; } };

export function auditAvailable() { return !!proxyBase(); }

async function auditGet(query) {
  const base = proxyBase();
  if (!base) throw new Error("The audit log needs the cloud proxy, which this build has not configured.");
  const { auth } = await import("/js/firebase.js?v=20261018i");
  const user = (auth && auth.currentUser) || null;
  if (!user) throw new Error("Sign in to read the audit log.");
  const wid = activeWorkspaceId() || user.uid;
  const r = await fetch(base + "/api/graph/" + encodeURIComponent(wid) + "?" + query, {
    headers: { Authorization: "Bearer " + (await user.getIdToken()) },
  });
  let j = {}; try { j = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error(j.error || ("Audit request failed (" + r.status + ")"));
  return j;
}

// Most-recent audit entries first: { entries:[{n,ts,uid,op,entities,relationships,rev,ids,prev,hash}], count, head }.
export function auditLog(limit) { return auditGet("audit=1" + (limit ? "&limit=" + encodeURIComponent(limit) : "")); }

// Walk the whole chain from genesis: { ok, brokenAt, entries, count, head }.
export function auditVerify() { return auditGet("audit=verify"); }
