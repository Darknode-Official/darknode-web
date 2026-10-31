// Client for the ingest API (Deck D5): manage workspace API keys and drain the server
// ingest queue into the Security Graph through the SAME sink every tool uses, so
// ingested findings are indistinguishable from a tool's own results.
import { activeWorkspaceId } from "/js/security-graph.js";
import { api, apiBase } from "/js/core/api.js";

export function ingestAvailable() { return !!apiBase(); }
export function ingestBaseUrl() { return apiBase(); }

async function signedInUser() {
  const { auth } = await import("/js/firebase.js?v=20261021a");
  const user = (auth && auth.currentUser) || null;
  if (!user) throw new Error("Sign in to manage API keys.");
  return user;
}
export async function ingestWorkspaceId() { try { const u = await signedInUser(); return activeWorkspaceId() || u.uid; } catch (_) { return ""; } }

async function keysApi(body) {
  if (!apiBase()) throw new Error("The ingest API needs the cloud proxy, which this build has not configured.");
  const user = await signedInUser();
  return api("/api/keys/" + encodeURIComponent(activeWorkspaceId() || user.uid), { method: "POST", body, user, failed: "Key request failed" });
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
  if (!batches || !batches.length) return { batches: 0, created: 0, updated: 0, failed: 0 };
  const { publishFindings } = await import("/js/core/sink.js");
  let created = 0, updated = 0, failed = 0; // the server queue is already emptied: a failed batch must be reported, not dropped silently
  for (const b of batches) {
    try { const r = await publishFindings(b.source || "ingest", b.findings || [], { quiet: true }); created += r.created || 0; updated += r.updated || 0; }
    catch (_) { failed++; }
  }
  return { batches: batches.length, created, updated, failed };
}
