// Thin client for the MonitorDO (Deck D4). Posts to the worker's /api/monitor/<wid>
// with the signed-in user's Firebase token and the active workspace id — the same auth
// path as the cloud graph sync. Pure transport; the scene (deck/monitors.js) owns the UI.
import { activeWorkspaceId } from "/js/security-graph.js";

const proxyBase = () => { try { return String(window.DARKNODE_PROXY_URL || "").replace(/\/api\/chat$/, ""); } catch (_) { return ""; } };

export function monitoringAvailable() { return !!proxyBase(); }

// monitorApi(body, { personal }) -> parsed JSON. Throws a readable Error on any non-2xx (the
// scene shows 503 "not configured on this deployment" verbatim, so a pre-deploy Deck is honest);
// the Error carries .status, and .plan when the plan does not include the request (402).
// personal: send to the caller's own workspace (where the Free plan's one-domain watch lives)
// whatever workspace is active.
export async function monitorApi(body, opts = {}) {
  const base = proxyBase();
  if (!base) throw new Error("Monitoring needs the cloud proxy, which this build has not configured.");
  const { auth } = await import("/js/firebase.js?v=20261021a");
  const user = (auth && auth.currentUser) || null;
  if (!user) throw new Error("Sign in to use monitors.");
  const wid = (opts.personal ? "" : activeWorkspaceId()) || user.uid;
  const r = await fetch(base + "/api/monitor/" + encodeURIComponent(wid), {
    method: "POST",
    headers: { Authorization: "Bearer " + (await user.getIdToken()), "Content-Type": "application/json" },
    body: JSON.stringify(body || { op: "list" }),
  });
  let j = {}; try { j = await r.json(); } catch (_) {}
  if (!r.ok) throw Object.assign(new Error(j.error || ("Monitor request failed (" + r.status + ")")), { status: r.status, plan: j.plan === true });
  return j;
}

// The domain watch: one daily monitor per check type, alerting by email. Free accounts get
// exactly this for one domain (worker/free-watch.js FREE_WATCH.types).
export const WATCH_TYPES = ["cert-expiry", "email-posture", "domain-expiry", "web-posture"];
export const WATCH_NAME = { "cert-expiry": "Certificate", "email-posture": "Email and DNS", "domain-expiry": "Domain registration", "web-posture": "Website" };
export const watchMonitor = (type, domain) => ({
  name: WATCH_NAME[type] + ": " + domain, type,
  config: type === "cert-expiry" ? { domains: [domain], warnDays: 21 } : type === "domain-expiry" ? { domains: [domain], warnDays: 30 } : { domains: [domain] },
  intervalMs: 86400000, channels: [{ type: "email" }],
});
