// IngestDO (Deck D5): one Durable Object per workspace holding its server-issued API
// keys (as SHA-256 hashes) and an ingest queue. A CI pipeline POSTs SARIF / CycloneDX /
// the Finding JSON contract with a key; the worker parses it to the Finding contract and
// queues it. The browser Deck drains the queue and publishes through the SAME sink every
// tool uses — so ingested findings get identical ids, merge and dedupe, with no fragile
// server-side copy of the graph write path.
import { generateKey, hashKey, keyIdOf, keyPrefix, normalizeScopes, hasScope, timingSafeEqual, SCOPES } from "./keys-core.js";
import { ingestToFindings } from "../public/js/ingest/formats.js";
import { requireUser, presentedKey } from "./auth.js";
import { resolveWorkspaceRole, canDo } from "./workspace.js";
import { readCapped } from "./body-cap.js";

const WID = /^[A-Za-z0-9_-]{1,128}$/;
const QUEUE_CAP = 2000;           // max findings held awaiting a browser drain
const BODY_CAP = 4 * 1024 * 1024;
const CHUNK_BYTES = 1024 * 1024;  // well under the 2 MB DO value limit
const FIELD_CAP = 64 * 1024;      // one finding's text field, so a single finding always fits a chunk
const chunkKey = (batchId, i) => "qc:" + batchId + ":" + i;
const countOf = (b) => (Array.isArray(b.findings) ? b.findings.length : b.count || 0);
const now = () => Date.now();
const batchId = () => "b_" + now().toString(36) + Math.random().toString(36).slice(2, 8);

// Clip a finding's long free-text fields (rule help can be many KB, repeated per result).
const capFields = (f) => {
  const out = Object.assign({}, f);
  for (const k of ["title", "description", "recommendation"]) if (typeof out[k] === "string" && out[k].length > FIELD_CAP) out[k] = out[k].slice(0, FIELD_CAP) + " [truncated]";
  if (out.evidence != null && JSON.stringify(out.evidence).length > FIELD_CAP) out.evidence = ["[evidence over 64 KB was dropped at ingest]"];
  return out;
};

const safeKey = (k) => ({ keyId: k.keyId, prefix: keyPrefix(k.keyId), scopes: k.scopes, label: k.label, createdAt: k.createdAt, lastUsedAt: k.lastUsedAt || 0, revoked: !!k.revoked });

export class IngestDO {
  constructor(state) { this.state = state; this.storage = state.storage; }
  // Null-proto map: keyId comes from an API caller, so a key named "__proto__"/
  // "constructor" must be an ordinary own entry, never reach Object.prototype.
  async _keys() { return Object.assign(Object.create(null), await this.storage.get("keys")); }
  async _queue() { return (await this.storage.get("queue")) || []; }

  // A SQLite-backed DO caps one stored value at 2 MB, and a batch grows on parsing (every
  // SARIF result copies its rule's help text: a 95 KB upload became 2.7 MB of findings), so
  // the whole queue under one key failed to save. Each batch's findings now live in chunks of
  // at most CHUNK_BYTES under their own keys; "queue" holds only the small index. Index
  // entries written before this change carry `findings` inline and are still read.
  async _putBatch(entry, findings) {
    const chunks = []; let cur = [], size = 2;
    for (const f of findings) {
      const n = JSON.stringify(f).length + 1;
      if (cur.length && size + n > CHUNK_BYTES) { chunks.push(cur); cur = []; size = 2; }
      cur.push(f); size += n;
    }
    if (cur.length) chunks.push(cur);
    for (let i = 0; i < chunks.length; i++) await this.storage.put(chunkKey(entry.batchId, i), chunks[i]);
    return Object.assign(entry, { count: findings.length, chunks: chunks.length });
  }
  async _batchFindings(b) {
    if (Array.isArray(b.findings)) return b.findings;
    const out = [];
    for (let i = 0; i < (b.chunks || 0); i++) out.push(...((await this.storage.get(chunkKey(b.batchId, i))) || []));
    return out;
  }
  async _dropBatch(b) { for (let i = 0; i < (b.chunks || 0); i++) await this.storage.delete(chunkKey(b.batchId, i)); }

  async _verify(presented, scope) {
    const keyId = keyIdOf(presented);
    if (!keyId) return { ok: false, status: 401, error: "Malformed API key." };
    // read-modify-write of `keys` spans the non-storage hashKey() await, so the
    // automatic DO input gate does not cover it: serialize to stop a concurrent
    // revoke/create from being lost (and lastUsedAt from clobbering it).
    let out;
    await this.state.blockConcurrencyWhile(async () => {
      const keys = await this._keys();
      const rec = keys[keyId];
      if (!rec || rec.revoked) { out = { ok: false, status: 401, error: "Unknown or revoked API key." }; return; }
      const h = await hashKey(presented);
      if (!timingSafeEqual(h, rec.hash)) { out = { ok: false, status: 401, error: "Invalid API key." }; return; }
      if (scope && !hasScope(rec.scopes, scope)) { out = { ok: false, status: 403, error: `This key lacks the ${scope} scope.` }; return; }
      rec.lastUsedAt = now(); await this.storage.put("keys", keys);
      out = { ok: true, keyId, scopes: rec.scopes };
    });
    return out;
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
        const q = await this._queue(), findings = [];
        for (const b of q) for (const f of await this._batchFindings(b)) findings.push({ title: f.title, severity: f.severity, category: f.category, source: b.source, receivedAt: b.receivedAt });
        return reply({ pending: findings.length, findings });
      }
      const v = await this._verify(apiKey, "ingest:write"); if (!v.ok) return reply({ error: v.error }, v.status);
      const text = await request.text();
      if (text.length > BODY_CAP) return reply({ error: "Body too large." }, 413);
      const { format, findings: parsed, errors } = ingestToFindings(text);
      if (!parsed.length) return reply({ format, accepted: 0, rejected: errors.length, errors: errors.slice(0, 20) }, errors.length ? 422 : 200);
      const findings = parsed.map(capFields);
      const queue = await this._queue();
      const source = "ingest:" + format;
      queue.push(await this._putBatch({ batchId: batchId(), source, receivedAt: now() }, findings));
      // enforce the cap by dropping the oldest batches
      let total = queue.reduce((n, b) => n + countOf(b), 0);
      while (total > QUEUE_CAP && queue.length > 1) { const old = queue.shift(); total -= countOf(old); await this._dropBatch(old); }
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
      // hash the new key inside the gate: a plain read-modify-write here would
      // let a concurrent create/revoke drop this key (its await hashKey yields).
      await this.state.blockConcurrencyWhile(async () => {
        const keys = await this._keys();
        keys[keyId] = { keyId, hash: await hashKey(key), scopes, label: String(body.label || "").slice(0, 80) || "API key", createdAt: now(), lastUsedAt: 0, revoked: false };
        await this.storage.put("keys", keys);
      });
      return reply({ key, keyId, prefix, scopes });   // full key shown once
    }
    if (op === "revoke") {
      let missing = false;
      await this.state.blockConcurrencyWhile(async () => {
        const keys = await this._keys(); const rec = keys[body.keyId];
        if (!rec) { missing = true; return; }
        rec.revoked = true; await this.storage.put("keys", keys);
      });
      if (missing) return reply({ error: "not found" }, 404);
      return reply({ ok: true });
    }
    if (op === "drain") {
      const queue = await this._queue(), batches = [];
      for (const b of queue) batches.push({ batchId: b.batchId, source: b.source, receivedAt: b.receivedAt, findings: await this._batchFindings(b) });
      await this.storage.put("queue", []);
      for (const b of queue) await this._dropBatch(b);
      return reply({ batches });   // the browser publishes these through the sink
    }
    if (op === "peek") {
      const queue = await this._queue();
      return reply({ pending: queue.reduce((n, b) => n + countOf(b), 0), batches: queue.length });
    }
    return reply({ error: "unknown op: " + op }, 400);
  }
}

// Shared Firebase-token + workspace-role check for the management plane.
async function authWorkspace(request, env, wid, json) {
  const who = await requireUser(request, env, json);
  if (who.err) return who;
  const projectId = env.FIREBASE_PROJECT_ID;
  let role;
  try { role = await resolveWorkspaceRole(projectId, wid, who.uid, who.token); }
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
  const text = await readCapped(request, 64 * 1024);
  if (text === null) return json({ error: "Request too large." }, 413);
  const stub = env.INGEST.get(env.INGEST.idFromName(wid));
  const res = await stub.fetch("https://ingest/", { method: "POST", body: text || "{}", headers: { "Content-Type": "application/json", "x-ing-uid": a.uid, "x-ing-role": a.role } });
  return json(await res.json(), res.status);
}

// POST /api/v1/ingest/<wid>   (API key)  — body: SARIF / CycloneDX / Finding JSON
// GET  /api/v1/findings/<wid> (API key)  — read-back of still-pending findings
export async function handleIngest(request, env, wid, json, kind) {
  if (!env.INGEST) return json({ error: "Ingest API is not configured on this deployment." }, 503);
  if (!WID.test(wid)) return json({ error: "Invalid workspace id" }, 400);
  const key = presentedKey(request);
  if (!key) return json({ error: "API key required (send header x-darknode-key or Authorization: Bearer dk_...)." }, 401);
  const isRead = kind === "findings";
  if (isRead ? request.method !== "GET" : request.method !== "POST") return json({ error: (isRead ? "GET" : "POST") + " only" }, 405);
  const bodyText = isRead ? null : await readCapped(request, BODY_CAP);
  if (!isRead && bodyText === null) return json({ error: "Body too large." }, 413);
  const stub = env.INGEST.get(env.INGEST.idFromName(wid));
  const res = await stub.fetch("https://ingest/" + (isRead ? "findings" : ""), { method: isRead ? "GET" : "POST", body: bodyText, headers: { "x-ing-key": key, "Content-Type": "application/json" } });
  return json(await res.json(), res.status);
}
