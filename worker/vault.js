// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// VAULT server enforcement.
//
// A team vault lives in one Durable Object (VaultDO), which is the ONLY writer of its
// ledger. Every money operation runs through the same ledger.js the browser uses
// (BigInt cents, enforced double-entry, no-overdraft, idempotency, SHA-256 hash chain),
// but here the caller cannot edit the code, the clock or their own identity:
//   - identity is the uid from a verified Firebase ID token (vault-auth.js);
//   - the caller's role is read from Firestore (vaults/{vid}/members/{uid}) with the
//     caller's own token, so Firestore rules decide what that read returns, and only a
//     vault owner can write a member doc (firebase/firestore.rules);
//   - timestamps are the server's;
//   - every attempt, allowed or denied, is appended to a separate hash-chained audit log.
//
// VAULT still holds no money: it is the control and record layer for funds at a bank.

import { Ledger, toCents, fmtCents, hashStr, canon } from "../public/js/vault/ledger.js";
import { readCapped } from "./body-cap.js";
import { verifyIdToken } from "./vault-auth.js";
import { isSuspended } from "./gate.js";
import { ROLES, canDo } from "../public/js/vault/roles.js";

export { ROLES, canDo };

export const VAULT_ID = /^[A-Za-z0-9_-]{8,40}$/;

const GENESIS = "0".repeat(64);
const pad = (n) => String(n).padStart(10, "0");
const str = (v, max, name) => {
  const s = String(v == null ? "" : v).trim();
  if (s.length > max) throw new Error(name + " is longer than " + max + " characters");
  return s;
};
const rid = (p) => p + Array.from(crypto.getRandomValues(new Uint8Array(9)), (b) => b.toString(36).padStart(2, "0")).join("").slice(0, 14);

function checkPolicy(p) {
  const n = Number(p && p.minApprovers);
  if (!Number.isInteger(n) || n < 1 || n > 10) throw new Error("minApprovers must be a whole number from 1 to 10");
  const tiers = Array.isArray(p.tiers) ? p.tiers : [];
  if (tiers.length > 10) throw new Error("at most 10 approval tiers");
  const clean = tiers.map((t) => {
    if (!Array.isArray(t) || t.length !== 2) throw new Error("each tier is [amount, approvers]");
    const amt = toCents(t[0]);
    const req = Number(t[1]);
    if (amt <= 0n) throw new Error("tier amount must be > 0");
    if (!Number.isInteger(req) || req < 1 || req > 10) throw new Error("tier approvers must be 1 to 10");
    return [fmtCents(amt).replace(/[$,]/g, ""), req];
  });
  // Segregation of duties cannot be switched off on a server-enforced vault.
  return { minApprovers: n, dualControl: true, tiers: clean };
}

// Applies one operation to the ledger. Throws (leaving the caller to discard L) on any
// violation. Returns { result, touched: [transferIds], detail } for persistence + audit.
export function applyOp(L, op, a, actor, now) {
  a = a || {};
  const touched = [];
  let result = null, detail = {};
  if (op === "init") {
    if (L) throw new Error("vault already initialized");
    // No default policy: the owner chooses the approval rules; nothing is preset.
    if (!a.policy) throw new Error("choose the minimum number of approvers");
    L = new Ledger({ currency: "USD", policy: checkPolicy(a.policy) });
    L.openAccount({ id: "bank", name: str(a.bankName, 80, "account name") || "Operating account", type: "asset" });
    L.openAccount({ id: "equity", name: "Opening equity", type: "equity" });
    L.openAccount({ id: "clearing", name: "Outgoing clearing", type: "clearing" });
    const open = toCents(a.opening == null || a.opening === "" ? "0" : a.opening);
    if (open < 0n) throw new Error("opening balance cannot be negative");
    if (open > 0n) L.post({ memo: "opening balance", by: actor.uid, ts: now, postings: [{ account: "bank", side: "debit", amount: open }, { account: "equity", side: "credit", amount: open }] });
    detail = { opening: fmtCents(open) };
    return { L, result, touched, detail };
  }
  if (!L) throw new Error("vault not initialized");
  switch (op) {
    case "openAccount": {
      const name = str(a.name, 80, "account name");
      if (!name) throw new Error("account name required");
      const id = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 30) + "-" + rid("").slice(0, 6);
      result = L.openAccount({ id, name, type: String(a.type || "") });
      detail = { account: id, type: result.type };
      break;
    }
    case "post": {
      if (!Array.isArray(a.postings) || a.postings.length > 50) throw new Error("1 to 50 postings");
      const e = L.post({ memo: str(a.memo, 280, "memo"), by: actor.uid, ts: now, idempotencyKey: a.idempotencyKey == null ? undefined : str(a.idempotencyKey, 120, "idempotency key"),
        postings: a.postings.map((p) => ({ account: String(p.account || ""), side: p.side, amount: String(p.amount ?? "") })) });
      detail = { entry: e.seq, hash: e.hash };
      break;
    }
    case "setPolicy": {
      L.policy = checkPolicy(a);
      detail = { policy: L.policy };
      break;
    }
    case "createTransfer": {
      const id = rid("t");
      const t = L.createTransfer({ id, from: String(a.from || ""), to: String(a.to || ""), amount: String(a.amount ?? ""), memo: str(a.memo, 280, "memo"), payee: str(a.payee, 120, "payee"), by: actor.uid, ts: now });
      touched.push(id);
      result = { id };
      detail = { transfer: id, amount: fmtCents(t.amount), from: t.from, to: t.to, required: t.required, screen: t.screen.level };
      break;
    }
    case "approve": {
      const t = L.approve(String(a.id || ""), actor.uid);
      touched.push(t.id);
      detail = { transfer: t.id, approvals: t.approvers.length, required: t.required, status: t.status };
      break;
    }
    case "reject": {
      const t0 = L.transfers.get(String(a.id || ""));
      if (t0 && t0.status === "rejected") throw new Error("transfer already rejected");
      const t = L.reject(String(a.id || ""), actor.uid, str(a.reason, 280, "reason"));
      touched.push(t.id);
      detail = { transfer: t.id, reason: t.reason };
      break;
    }
    case "release": {
      const t0 = L.transfers.get(String(a.id || ""));
      if (t0 && t0.by === actor.uid) throw new Error("segregation of duties: the initiator cannot release their own transfer");
      const t = L.release(String(a.id || ""), actor.uid, now);
      touched.push(t.id);
      detail = { transfer: t.id, amount: fmtCents(t.amount), entry: t.releasedEntry };
      break;
    }
    case "reconcile": {
      const lines = Array.isArray(a.lines) ? a.lines : [];
      if (!lines.length || lines.length > 5000) throw new Error("1 to 5000 statement lines");
      const res = L.reconcile(lines.map((l) => ({ amount: String(l.amount ?? ""), ref: str(l.ref, 200, "reference") })));
      for (const m of res.matched) touched.push(m.transfer);
      result = res;
      detail = { matched: res.matched.length, unmatchedBank: res.unmatchedBank.length, unmatchedLedger: res.unmatchedLedger.length };
      break;
    }
    default: throw new Error("unknown operation: " + op);
  }
  return { L, result, touched, detail };
}

// Storage layout (one Durable Object per vault):
//   meta            {currency, policy, accounts, head, seq}
//   j:<seq>         journal entry (amounts as strings)
//   t:<id>          transfer (amount as string)
//   ameta           {n, head} of the audit chain
//   a:<n>           audit entry {n, ts, by, role, op, ok, detail|error, prev, hash}
const jOut = (e) => ({ ...e, postings: e.postings.map((p) => ({ ...p, amount: p.amount.toString() })) });
const tOut = (t) => ({ ...t, amount: t.amount.toString() });

export class VaultDO {
  constructor(state) { this.state = state; this.storage = state.storage; this.L = undefined; }

  async ledger() {
    if (this.L !== undefined) return this.L;
    const meta = await this.storage.get("meta");
    if (!meta) return (this.L = null);
    const journal = [...(await this.storage.list({ prefix: "j:" })).values()];
    const transfers = [...(await this.storage.list({ prefix: "t:" })).values()];
    this.L = Ledger.load({ currency: meta.currency, policy: meta.policy, accounts: meta.accounts, head: meta.head, seq: meta.seq,
      journal, transfers, idem: journal.map((e) => e.idem).filter(Boolean) });
    return this.L;
  }

  // Synchronous on purpose: the caller reads `am` first, so every put of one operation
  // happens without an intervening await and the storage layer commits them atomically.
  auditPut(am, entry) {
    const body = { n: am.n, ...entry };
    const hash = hashStr(am.head + "|" + canon(body));
    const rec = { ...body, prev: am.head, hash };
    this.storage.put("a:" + pad(am.n), rec);
    this.storage.put("ameta", { n: am.n + 1, head: hash });
    return rec;
  }

  async exec({ op, args }, actor) {
    const now = Date.now();
    const base = { ts: now, by: actor.uid, role: actor.role, op: String(op || "").slice(0, 40) };
    const am = (await this.storage.get("ameta")) || { n: 0, head: GENESIS };
    if (!canDo(actor.role, op)) {
      this.auditPut(am, { ...base, ok: false, error: "role " + actor.role + " may not " + op });
      return { status: 403, body: { error: "Your role (" + actor.role + ") cannot " + op + "." } };
    }
    const before = await this.ledger();
    const prevSeq = before ? before._seq : 0;
    let out;
    try { out = applyOp(before, op, args, actor, now); } catch (e) {
      this.L = undefined; // drop any partial in-memory change; storage is untouched
      this.auditPut(am, { ...base, ok: false, error: String(e.message || e).slice(0, 300) });
      return { status: 409, body: { error: e.message || String(e) } };
    }
    const L = out.L;
    this.storage.put("meta", { currency: L.currency, policy: L.policy, accounts: [...L.accounts.values()], head: L.head, seq: L._seq });
    for (const e of L.journal.slice(prevSeq)) this.storage.put("j:" + pad(e.seq), jOut(e));
    for (const id of new Set(out.touched)) this.storage.put("t:" + id, tOut(L.transfers.get(id)));
    this.auditPut(am, { ...base, ok: true, detail: out.detail });
    this.L = L;
    return { status: 200, body: { ok: true, result: out.result } };
  }

  async view(actor) {
    const L = await this.ledger();
    const am = (await this.storage.get("ameta")) || { n: 0, head: GENESIS };
    const audit = [...(await this.storage.list({ prefix: "a:", reverse: true, limit: 300 })).values()];
    return { uid: actor.uid, role: actor.role, enforced: true, ledger: L ? L.snapshot() : null, chain: L ? L.verifyChain() : null, audit, auditCount: am.n, auditHead: am.head };
  }

  // Walks the full audit chain from genesis.
  async verifyAudit() {
    let prev = GENESIS, i = 0;
    for (const e of (await this.storage.list({ prefix: "a:" })).values()) {
      const { prev: p, hash, ...body } = e;
      if (p !== prev || body.n !== i || hash !== hashStr(prev + "|" + canon(body))) return { ok: false, brokenAt: i };
      prev = hash; i++;
    }
    const am = (await this.storage.get("ameta")) || { n: 0, head: GENESIS };
    return { ok: prev === am.head && i === am.n, brokenAt: -1, entries: i };
  }

  async fetch(request) {
    const actor = { uid: request.headers.get("x-vault-uid") || "", role: request.headers.get("x-vault-role") || "" };
    const reply = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    if (!actor.uid || !ROLES.includes(actor.role)) return reply({ error: "forbidden" }, 403);
    if (request.method === "GET") {
      const v = new URL(request.url).searchParams.get("verify");
      return reply(v ? { audit: await this.verifyAudit(), ledger: (await this.ledger())?.verifyChain() || null } : await this.view(actor));
    }
    let body;
    try { body = await request.json(); } catch (_) { return reply({ error: "Invalid JSON body" }, 400); }
    let res;
    await this.state.blockConcurrencyWhile(async () => {
      try { res = await this.exec(body || {}, actor); } catch (e) { res = { status: 500, body: { error: String(e.message || e) } }; }
    });
    return reply(res.body, res.status);
  }
}

// The caller's role, read from Firestore with the caller's own ID token. Firestore rules
// only return the doc to vault members (or to the member themselves), and only a vault
// owner can write one, so a client cannot grant itself a role.
export async function memberRole(projectId, vid, uid, token, fetchImpl = fetch) {
  const url = "https://firestore.googleapis.com/v1/projects/" + projectId + "/databases/(default)/documents/vaults/" + vid + "/members/" + encodeURIComponent(uid);
  const r = await fetchImpl(url, { headers: { Authorization: "Bearer " + token } });
  if (r.status === 404 || r.status === 403) return null;
  if (!r.ok) throw new Error("membership lookup failed (" + r.status + ")");
  const d = await r.json();
  const f = (d && d.fields) || {};
  if (!f.uid || f.uid.stringValue !== uid) return null;
  const role = f.role && f.role.stringValue;
  return ROLES.includes(role) ? role : null;
}

// Route: GET /api/vault/<vid>[?verify=1]  |  POST /api/vault/<vid>  {op, args}
export async function handleVault(request, env, vid, json) {
  if (!env.VAULT) return json({ error: "Server-enforced VAULT is not configured on this deployment." }, 503);
  if (!VAULT_ID.test(vid)) return json({ error: "Invalid vault id" }, 400);
  if (request.method !== "GET" && request.method !== "POST") return json({ error: "GET or POST only" }, 405);
  const projectId = env.FIREBASE_PROJECT_ID;
  if (!projectId) return json({ error: "FIREBASE_PROJECT_ID is not set" }, 503);
  const m = /^Bearer\s+(\S+)$/.exec(request.headers.get("Authorization") || "");
  if (!m) return json({ error: "Sign in required" }, 401);
  let who;
  try { who = await verifyIdToken(m[1], projectId); } catch (e) { return json({ error: "Invalid sign-in token: " + e.message }, 401); }
  if (await isSuspended(projectId, who, m[1])) return json({ error: "Your access has been suspended by an administrator." }, 403);
  let role;
  try { role = await memberRole(projectId, vid, who.uid, m[1]); } catch (e) { return json({ error: e.message }, 502); }
  if (!role) return json({ error: "You are not a member of this vault." }, 403);
  let body = null;
  if (request.method === "POST") {
    body = await readCapped(request, 512 * 1024);
    if (body === null) return json({ error: "Request too large" }, 413);
  }
  const stub = env.VAULT.get(env.VAULT.idFromName(vid));
  const res = await stub.fetch("https://vault/" + (new URL(request.url).search || ""), {
    method: request.method, body, headers: { "Content-Type": "application/json", "x-vault-uid": who.uid, "x-vault-role": role },
  });
  return json(await res.json(), res.status);
}
