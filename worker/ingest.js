// IngestDO (Deck D5): one Durable Object per workspace holding its server-issued API
// keys (as SHA-256 hashes) and an ingest queue. A CI pipeline POSTs SARIF / CycloneDX /
// the Finding JSON contract with a key; the worker parses it to the Finding contract and
// queues it. The browser Deck drains the queue and publishes through the SAME sink every
// tool uses — so ingested findings get identical ids, merge and dedupe, with no fragile
// server-side copy of the graph write path.
import { generateKey, hashKey, keyIdOf, keyPrefix, normalizeScopes, hasScope, timingSafeEqual, SCOPES } from "./keys-core.js";
import { ingestToFindings } from "../public/js/ingest/formats.js";
import { verifyIdToken } from "./vault-auth.js";
import { isSuspended } from "./gate.js";
import { resolveWorkspaceRole, canDo } from "./workspace.js";

const WID = /^[A-Za-z0-9_-]{1,128}$/;
const QUEUE_CAP = 2000;           // max findings held awaiting a browser drain
const BODY_CAP = 4 * 1024 * 1024;
const now = () => Date.now();
const batchId = () => "b_" + now().toString(36) + Math.random().toString(36).slice(2, 8);

const safeKey = (k) => ({ keyId: k.keyId, prefix: keyPrefix(k.keyId), scopes: k.scopes, label: k.label, createdAt: k.createdAt, lastUsedAt: k.lastUsedAt || 0, revoked: !!k.revoked });

export class IngestDO {
  constructor(state) { this.state = state; this.storage = state.storage; }
  async _keys() { return (await this.storage.get("keys")) || {}; }
  async _queue() { return (await this.storage.get("queue")) || []; }

  async _verify(presented, scope) {
    const keyId = keyIdOf(presented);
    if (!keyId) return { ok: false, status: 401, error: "Malformed API key." };
    const keys = await this._keys();
    const rec = keys[keyId];
    if (!rec || rec.revoked) return { ok: false, status: 401, error: "Unknown or revoked API key." };
    const h = await hashKey(presented);
    if (!timingSafeEqual(h, rec.hash)) return { ok: false, status: 401, error: "Invalid API key." };
    if (scope && !hasScope(rec.scopes, scope)) return { ok: false, status: 403, error: `This key lacks the ${scope} scope.` };
    rec.lastUsedAt = now(); await this.storage.put("keys", keys);
    return { ok: true, keyId, scopes: rec.scopes };
  }

  async fetch(request) {
    const reply = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    const mgmtUid = request.headers.get("x-ing-uid");
    const apiKey = request.headers.get("x-ing-key");

    // ---- API-key data plane (ingest / read-back) ----
    if (apiKey) {
      const url = new URL(request.url);
      if (request.method === "GET" || url.pathname.endsWith("/findings")) {
        const v = await this._verify(apiKey, "findings:read"); if (!v.ok) return reply({ error: v.error }, v.status);
        const q = await this._queue();
        const findings = q.flatMap((b) => b.findings.map((f) => ({ title: f.title, severity: f.severity, category: f.category, source: b.source, receivedAt: b.receivedAt })));
        return reply({ pending: findings.length, findings });
      }
      const v = await this._verify(apiKey, "ingest:write"); if (!v.ok) return reply({ error: v.error }, v.status);
      const text = await request.text();
      if (text.length > BODY_CAP) return reply({ error: "Body too large." }, 413);
      const { format, findings, errors } = ingestToFindings(text);
      if (!findings.length) return reply({ format, accepted: 0, rejected: errors.length, errors: errors.slice(0, 20) }, errors.length ? 422 : 200);
      const queue = await this._queue();
      const source = "ingest:" + format;
      queue.push({ batchId: batchId(), source, findings, receivedAt: now() });
      // enforce the cap by dropping the oldest batches
      let total = queue.reduce((n, b) => n + b.findings.length, 0);
      while (total > QUEUE_CAP && queue.length > 1) { total -= queue.shift().findings.length; }
      await this.storage.put("queue", queue);
      return reply({ format, accepted: findings.length, rejected: errors.length, errors: errors.slice(0, 20), queued: total });
    }

    // ---- Firebase-authed management plane (keys + drain) ----
    if (!mgmtUid) return reply({ error: "forbidden" }, 403);
    const role = request.headers.get("x-ing-role") || "viewer";
    let body = {};
    try { body = JSON.parse((await request.text()) || "{}"); } catch (_) { return reply({ error: "Invalid JSON body" }, 400); }
    const op = body.op || "list";

    if (op === "list") {
      const keys = await this._keys();
      return reply({ keys: Object.values(keys).map(safeKey), scopes: SCOPES });
    }
    if (!canDo(role, "write")) return reply({ error: "Your role (" + role + ") cannot manage API keys." }, 403);

    if (op === "create") {
      const { key, keyId, prefix } = generateKey();
      const scopes = normalizeScopes(body.scopes);
      const keys = await this._keys();
      keys[keyId] = { keyId, hash: await hashKey(key), scopes, label: String(body.label || "").slice(0, 80) || "API key", createdAt: now(), lastUsedAt: 0, revoked: false };
      await this.storage.put("keys", keys);
      return reply({ key, keyId, prefix, scopes });   // full key shown once
    }
    if (op === "revoke") {
      const keys = await this._keys(); const rec = keys[body.keyId]; if (!rec) return reply({ error: "not found" }, 404);
      rec.revoked = true; await this.storage.put("keys", keys);
      return reply({ ok: true });
    }
    if (op === "drain") {
      const queue = await this._queue();
      await this.storage.put("queue", []);
      return reply({ batches: queue });   // the browser publishes these through the sink
    }
    if (op === "peek") {
      const queue = await this._queue();
      return reply({ pending: queue.reduce((n, b) => n + b.findings.length, 0), batches: queue.length });
    }
    return reply({ error: "unknown op: " + op }, 400);
  }
}

// Shared Firebase-token + workspace-role check for the management plane.
async function authWorkspace(request, env, wid, json) {
  const projectId = env.FIREBASE_PROJECT_ID;
  if (!projectId) return { err: json({ error: "FIREBASE_PROJECT_ID is not set" }, 503) };
  const m = /^Bearer\s+(\S+)$/.exec(request.headers.get("Authorization") || "");
  if (!m) return { err: json({ error: "Sign in required" }, 401) };
  let who;
  try { who = await verifyIdToken(m[1], projectId); } catch (e) { return { err: json({ error: "Invalid sign-in token: " + e.message }, 401) }; }
  if (await isSuspended(projectId, who, m[1])) return { err: json({ error: "Your access has been suspended by an administrator." }, 403) };
  let role;
  try { role = await resolveWorkspaceRole(projectId, wid, who.uid, m[1]); }
  catch (e) { return { err: json({ error: e.message }, 502) }; }
  if (!role) return { err: json({ error: "You are not a member of this workspace." }, 403) };
  return { uid: who.uid, role };
}

// POST /api/keys/<wid>  { op: list|create|revoke|drain|peek }  (Firebase token)
export async function handleKeys(request, env, wid, json) {
  if (!env.INGEST) return json({ error: "Ingest API is not configured on this deployment." }, 503);
  if (!WID.test(wid)) return json({ error: "Invalid workspace id" }, 400);
  if (request.method !== "POST") return json({ error: "POST only" }, 405);
  const a = await authWorkspace(request, env, wid, json); if (a.err) return a.err;
  const text = await request.text();
  if (text.length > 64 * 1024) return json({ error: "Request too large." }, 413);
  const stub = env.INGEST.get(env.INGEST.idFromName(wid));
  const res = await stub.fetch("https://ingest/", { method: "POST", body: text || "{}", headers: { "Content-Type": "application/json", "x-ing-uid": a.uid, "x-ing-role": a.role } });
  return json(await res.json(), res.status);
}

const presentedKey = (request) => request.headers.get("x-darknode-key") || (/^Bearer\s+(dk_\S+)$/.exec(request.headers.get("Authorization") || "") || [])[1] || "";

// POST /api/v1/ingest/<wid>   (API key)  — body: SARIF / CycloneDX / Finding JSON
// GET  /api/v1/findings/<wid> (API key)  — read-back of still-pending findings
export async function handleIngest(request, env, wid, json, kind) {
  if (!env.INGEST) return json({ error: "Ingest API is not configured on this deployment." }, 503);
  if (!WID.test(wid)) return json({ error: "Invalid workspace id" }, 400);
  const key = presentedKey(request);
  if (!key) return json({ error: "API key required (send header x-darknode-key or Authorization: Bearer dk_...)." }, 401);
  const isRead = kind === "findings";
  if (isRead ? request.method !== "GET" : request.method !== "POST") return json({ error: (isRead ? "GET" : "POST") + " only" }, 405);
  const bodyText = isRead ? null : await request.text();
  if (bodyText && bodyText.length > BODY_CAP) return json({ error: "Body too large." }, 413);
  const stub = env.INGEST.get(env.INGEST.idFromName(wid));
  const res = await stub.fetch("https://ingest/" + (isRead ? "findings" : ""), { method: isRead ? "GET" : "POST", body: bodyText, headers: { "x-ing-key": key, "Content-Type": "application/json" } });
  return json(await res.json(), res.status);
}
