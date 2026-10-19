// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Cloud-synced security graph — server side (Phase B1).
//
// The browser's security-graph.js stays the instant, synchronous source of truth; this
// Durable Object is the shared, durable copy that lets the same graph follow a user
// across devices (and, in Phase B2, a team across people). A GraphDO holds one
// workspace's entities and relationships and is the single writer of them. Convergence
// is last-writer-wins by the record's own timestamp, using the exact same pure rule the
// browser applies (public/js/core/graph-merge.js), so client and server never disagree.
//
// Access in B1 is private: the only workspace id a caller may touch is their own uid, so
// this is each user's personal cloud graph. B2 will swap the `wid === uid` check below
// for a Firestore membership lookup (exactly like memberRole in vault.js) to open a
// workspace to a team, without changing the storage or the merge.
//
// Unlike VAULT, nothing here is integrity-critical: it is operational data, LWW-merged.
// Money stays in VAULT, which is server-authored and hash-chained.

import { wins } from "../public/js/core/graph-merge.js";
import { verifyIdToken } from "./vault-auth.js";
import { isSuspended } from "./gate.js";
import { resolveWorkspaceRole, canDo } from "./workspace.js";
import { chainAppend, chainVerify, GENESIS, pad } from "./audit-chain.js";

// The audit chain is never trimmed: "verify from genesis" must stay meaningful. It only
// grows on a real change (an idle sync that writes nothing appends nothing), and each
// entry is a small summary, not a copy of the data.
const AUDIT_IDS_CAP = 40;     // ids summarised per write entry
const AUDIT_PAGE = 200;       // audit records returned per read page

// A workspace id is a Firebase uid (or, later, a workspace doc id).
export const GRAPH_ID = /^[A-Za-z0-9_-]{1,128}$/;

const MAX_PER_PUSH = 2000;    // records of each kind accepted in one push
const MAX_STORED = 200000;    // hard cap on stored records (entities + relationships)
const ENTITY_FIELDS = ["id", "type", "name", "data", "tags", "severity", "status", "source", "createdAt", "updatedAt"];
const REL_FIELDS = ["id", "fromId", "toId", "type", "createdAt"];

const clampStr = (v, max) => (typeof v === "string" ? v.slice(0, max) : v);

// Keep only known fields and bound the big ones, so a client cannot store an arbitrary
// oversized blob. A tombstone keeps just its id + ordering key + the deleted flag.
function sanitize(rec, fields, key) {
  if (rec.deleted) { const t = { id: rec.id, deleted: true }; t[key] = clampStr(rec[key], 40); return t; }
  const out = {};
  for (const f of fields) if (f in rec) out[f] = rec[f];
  out.id = rec.id;
  if (typeof out.name === "string") out.name = out.name.slice(0, 500);
  if (typeof out.source === "string") out.source = out.source.slice(0, 120);
  if (Array.isArray(out.tags)) out.tags = out.tags.slice(0, 50).map((t) => String(t).slice(0, 80));
  // Oversized/unserializable data is dropped to keep the DO value small, but NOT silently:
  // leave a marker so the client can see the entity's detail was truncated on sync.
  if (out.data != null) {
    try {
      if (JSON.stringify(out.data).length > 40000) out.data = { _truncated: true, _reason: "entity data exceeded 40000 bytes and was dropped on sync" };
    } catch (_) {
      out.data = { _truncated: true, _reason: "entity data was not serializable and was dropped on sync" };
    }
  }
  return out;
}

export class GraphDO {
  constructor(state) { this.state = state; this.storage = state.storage; }

  async meta() { return (await this.storage.get("meta")) || { rev: 0, count: 0 }; }

  // Everything changed after revision `since` (0 = full snapshot).
  async pull(since) {
    since = Number(since) || 0;
    const entities = [], relationships = [];
    for (const v of (await this.storage.list({ prefix: "e:" })).values()) if ((v._rev || 0) > since) entities.push(v);
    for (const v of (await this.storage.list({ prefix: "r:" })).values()) if ((v._rev || 0) > since) relationships.push(v);
    const m = await this.meta();
    return { rev: m.rev, entities, relationships };
  }

  async applyKind(list, prefix, key, state) {
    if (!Array.isArray(list) || !list.length) return 0;
    const items = list.slice(0, MAX_PER_PUSH).filter((r) => r && typeof r.id === "string" && r.id && GRAPH_ID.test(r.id));
    const keys = items.map((r) => prefix + r.id);
    const existing = keys.length ? await this.storage.get(keys) : new Map();
    let n = 0;
    for (const rec of items) {
      const k = prefix + rec.id;
      const cur = existing.get(k);
      if (!wins(rec, cur, key)) continue;
      if (!cur) { if (state.count >= MAX_STORED) continue; state.count++; }
      state.rev++;
      const fields = prefix === "e:" ? ENTITY_FIELDS : REL_FIELDS;
      state.put[k] = { ...sanitize(rec, fields, key), _rev: state.rev, _by: state.uid || "" };
      n++;
    }
    return n;
  }

  async auditMeta() { return (await this.storage.get("ameta")) || { n: 0, head: GENESIS }; }

  // One summary entry per write that actually changed something. Hash-chained: the record
  // commits to the previous head, so a tampered or dropped entry fails verification.
  appendAudit(am, entry) {
    const { rec, next } = chainAppend(am, entry);
    this.storage.put("a:" + pad(rec.n), rec);
    this.storage.put("ameta", next);
    return next;
  }

  async push(body, uid) {
    const m = await this.meta();
    const state = { rev: m.rev, count: m.count || 0, put: {}, uid: uid || "" };
    const entities = await this.applyKind(body && body.entities, "e:", "updatedAt", state);
    const relationships = await this.applyKind(body && body.relationships, "r:", "createdAt", state);
    const keys = Object.keys(state.put);
    if (keys.length) {
      // Durable Object storage.put takes at most 128 entries per call.
      for (let i = 0; i < keys.length; i += 128) {
        const chunk = {};
        for (const k of keys.slice(i, i + 128)) chunk[k] = state.put[k];
        this.storage.put(chunk);
      }
      this.storage.put("meta", { rev: state.rev, count: state.count });
      const am = await this.auditMeta();
      this.appendAudit(am, { ts: Date.now(), uid: state.uid, op: "push", entities, relationships, rev: state.rev, ids: keys.slice(0, AUDIT_IDS_CAP) });
    }
    return { rev: state.rev, applied: { entities, relationships }, count: state.count };
  }

  // Most-recent audit records first, for the Deck Audit Log scene.
  async auditPage(limit) {
    const am = await this.auditMeta();
    const entries = [...(await this.storage.list({ prefix: "a:", reverse: true, limit: Math.min(Number(limit) || AUDIT_PAGE, AUDIT_PAGE) })).values()];
    return { entries, count: am.n, head: am.head };
  }

  // Walk the whole chain from genesis and confirm it matches the stored head and count.
  async auditVerify() {
    const am = await this.auditMeta();
    const records = [...(await this.storage.list({ prefix: "a:" })).values()];
    return { ...chainVerify(records, am.head, am.n), count: am.n, head: am.head };
  }

  async fetch(request) {
    const reply = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    const uid = request.headers.get("x-graph-uid");
    if (!uid) return reply({ error: "forbidden" }, 403);
    const url = new URL(request.url);
    if (request.method === "GET") {
      const audit = url.searchParams.get("audit");
      if (audit === "verify") return reply(await this.auditVerify());
      if (audit) return reply(await this.auditPage(url.searchParams.get("limit")));
      return reply(await this.pull(url.searchParams.get("since")));
    }
    let body;
    try { body = await request.json(); } catch (_) { return reply({ error: "Invalid JSON body" }, 400); }
    let res;
    await this.state.blockConcurrencyWhile(async () => {
      try { res = await this.push(body || {}, uid); } catch (e) { res = { __err: String(e.message || e) }; }
    });
    if (res && res.__err) return reply({ error: res.__err }, 500);
    return reply(res);
  }
}

// Route: GET /api/graph/<wid>[?since=<rev>]  |  POST /api/graph/<wid>  {entities, relationships}
// Access (B2): a caller's own uid is their personal workspace (implicit owner, no member
// doc). Any other wid is a team workspace — the caller's role is read from Firestore
// (workspaces/{wid}/members/{uid}) with their own token. GET needs read, POST needs write.
export async function handleGraph(request, env, wid, json) {
  if (!env.GRAPH) return json({ error: "Cloud graph is not configured on this deployment." }, 503);
  if (!GRAPH_ID.test(wid)) return json({ error: "Invalid workspace id" }, 400);
  if (request.method !== "GET" && request.method !== "POST") return json({ error: "GET or POST only" }, 405);
  const projectId = env.FIREBASE_PROJECT_ID;
  if (!projectId) return json({ error: "FIREBASE_PROJECT_ID is not set" }, 503);
  const m = /^Bearer\s+(\S+)$/.exec(request.headers.get("Authorization") || "");
  if (!m) return json({ error: "Sign in required" }, 401);
  let who;
  try { who = await verifyIdToken(m[1], projectId); } catch (e) { return json({ error: "Invalid sign-in token: " + e.message }, 401); }
  if (await isSuspended(projectId, who, m[1])) return json({ error: "Your access has been suspended by an administrator." }, 403);
  let role;
  try { role = await resolveWorkspaceRole(projectId, wid, who.uid, m[1]); }
  catch (e) { return json({ error: e.message }, 502); }
  if (!role) return json({ error: "You are not a member of this workspace." }, 403);
  // The audit log is a trust surface, not operational data: only owners and admins read it.
  const isAudit = request.method === "GET" && new URL(request.url).searchParams.has("audit");
  if (isAudit) {
    if (!canDo(role, "manageMembers")) return json({ error: "Only an owner or admin can read the audit log." }, 403);
  } else {
    const op = request.method === "GET" ? "read" : "write";
    if (!canDo(role, op)) return json({ error: "Your role (" + role + ") cannot " + op + " this workspace's graph." }, 403);
  }
  let bodyText = null;
  if (request.method === "POST") {
    bodyText = await request.text();
    if (bodyText.length > 4 * 1024 * 1024) return json({ error: "Request too large — sync in smaller batches." }, 413);
  }
  const stub = env.GRAPH.get(env.GRAPH.idFromName(wid));
  const res = await stub.fetch("https://graph/" + (new URL(request.url).search || ""), {
    method: request.method, body: bodyText, headers: { "Content-Type": "application/json", "x-graph-uid": who.uid },
  });
  return json(await res.json(), res.status);
}
