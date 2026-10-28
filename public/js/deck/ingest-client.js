// Client for the ingest API (Deck D5): manage workspace API keys and drain the server
// ingest queue into the Security Graph through the SAME sink every tool uses, so
// ingested findings are indistinguishable from a tool's own results.
import { activeWorkspaceId } from "/js/security-graph.js";

const proxyBase = () => { try { return String(window.DARKNODE_PROXY_URL || "").replace(/\/api\/chat$/, ""); } catch (_) { return ""; } };
export function ingestAvailable() { return !!proxyBase(); }
export function ingestBaseUrl() { return proxyBase(); }

async function widAndToken() {
  const { auth } = await import("/js/firebase.js?v=20261021a");
  const user = (auth && auth.currentUser) || null;
  if (!user) throw new Error("Sign in to manage API keys.");
  return { wid: activeWorkspaceId() || user.uid, token: await user.getIdToken() };
}
export async function ingestWorkspaceId() { try { return (await widAndToken()).wid; } catch (_) { return ""; } }

async function keysApi(body) {
  const base = proxyBase();
  if (!base) throw new Error("The ingest API needs the cloud proxy, which this build has not configured.");
  const { wid, token } = await widAndToken();
  const r = await fetch(base + "/api/keys/" + encodeURIComponent(wid), {
    method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  let j = {}; try { j = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error(j.error || ("Key request failed (" + r.status + ")"));
  return j;
}

export const listKeys = () => keysApi({ op: "list" });
export const createKey = (label, scopes) => keysApi({ op: "create", label, scopes });
export const revokeKey = (keyId) => keysApi({ op: "revoke", keyId });
export const peekQueue = () => keysApi({ op: "peek" });

// Drain the server queue and publish each batch through the normal sink. No dataset: a
// batch's source is only its format (ingest:sarif), so two repos' scans or two single
// alerts share it, and a dataset would offer every earlier batch's findings as "fixed".
export async function drainIngest() {
  const { batches } = await keysApi({ op: "drain" });
  if (!batches || !batches.length) return { batches: 0, created: 0, updated: 0 };
  const { publishFindings } = await import("/js/core/sink.js");
  let created = 0, updated = 0;
  for (const b of batches) {
    try { const r = await publishFindings(b.source || "ingest", b.findings || [], { quiet: true }); created += r.created || 0; updated += r.updated || 0; }
    catch (_) {}
  }
  return { batches: batches.length, created, updated };
}
