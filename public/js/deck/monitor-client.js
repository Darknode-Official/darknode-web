// Thin client for the MonitorDO (Deck D4). Posts to the worker's /api/monitor/<wid>
// with the signed-in user's Firebase token and the active workspace id — the same auth
// path as the cloud graph sync. Pure transport; the scene (deck/monitors.js) owns the UI.
import { activeWorkspaceId } from "/js/security-graph.js";

const proxyBase = () => { try { return String(window.DARKNODE_PROXY_URL || "").replace(/\/api\/chat$/, ""); } catch (_) { return ""; } };

export function monitoringAvailable() { return !!proxyBase(); }

// monitorApi(body) -> parsed JSON. Throws a readable Error on any non-2xx (the scene
// shows 503 "not configured on this deployment" verbatim, so a pre-deploy Deck is honest).
export async function monitorApi(body) {
  const base = proxyBase();
  if (!base) throw new Error("Monitoring needs the cloud proxy, which this build has not configured.");
  const { auth } = await import("/js/firebase.js?v=20261018i");
  const user = (auth && auth.currentUser) || null;
  if (!user) throw new Error("Sign in to use monitors.");
  const wid = activeWorkspaceId() || user.uid;
  const r = await fetch(base + "/api/monitor/" + encodeURIComponent(wid), {
    method: "POST",
    headers: { Authorization: "Bearer " + (await user.getIdToken()), "Content-Type": "application/json" },
    body: JSON.stringify(body || { op: "list" }),
  });
  let j = {}; try { j = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error(j.error || ("Monitor request failed (" + r.status + ")"));
  return j;
}
