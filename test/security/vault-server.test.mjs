// Server-enforced VAULT (worker/vault.js, worker/vault-auth.js): the Durable Object that
// is the single writer of a team vault, the Firebase ID-token verifier, and the Firestore
// role lookup. Storage is an in-memory stand-in with the Durable Object storage API, and
// tokens are signed with a locally generated RSA key.

import { test, assert, group } from "../harness.mjs";
import { VaultDO, applyOp, canDo, memberRole, handleVault } from "../../worker/vault.js";
import { verifyIdToken } from "../../worker/vault-auth.js";
import { Ledger, hashStr, canon } from "../../public/js/vault/ledger.js";

const rejects = async (p, re, msg) => {
  try { await p; } catch (e) { if (re && !re.test(e.message)) throw new Error((msg || "wrong error") + ": " + e.message); return; }
  throw new Error(msg || "expected rejection");
};
const match = (s, re) => assert.ok(re.test(s), "expected " + JSON.stringify(s) + " to match " + re);

class MemStorage {
  constructor() { this.m = new Map(); }
  async get(k) { const v = this.m.get(k); return v === undefined ? undefined : structuredClone(v); }
  put(k, v) { this.m.set(k, structuredClone(v)); return Promise.resolve(); }
  async list({ prefix = "", reverse = false, limit = Infinity } = {}) {
    let keys = [...this.m.keys()].filter((k) => k.startsWith(prefix)).sort();
    if (reverse) keys.reverse();
    return new Map(keys.slice(0, limit).map((k) => [k, structuredClone(this.m.get(k))]));
  }
}
const mkDO = (storage = new MemStorage()) => new VaultDO({ storage, blockConcurrencyWhile: (fn) => fn() });
const POL = { minApprovers: 2, tiers: [] };
const call = async (d, uid, role, op, args) => {
  const r = await d.fetch(new Request("https://vault/", { method: "POST", headers: { "x-vault-uid": uid, "x-vault-role": role }, body: JSON.stringify({ op, args }) }));
  return { status: r.status, body: await r.json() };
};
const view = async (d, uid = "own", role = "owner", q = "") => (await d.fetch(new Request("https://vault/" + q, { headers: { "x-vault-uid": uid, "x-vault-role": role } }))).json();

group("vault server: roles", () => {
  test("role matrix", () => {
    assert.ok(canDo("owner", "init") && !canDo("admin", "init"));
    assert.ok(canDo("initiator", "createTransfer") && !canDo("initiator", "approve"));
    assert.ok(canDo("approver", "release") && !canDo("approver", "createTransfer"));
    assert.ok(!canDo("auditor", "approve") && !canDo("viewer", "createTransfer") && !canDo("owner", "nope"));
  });
});

group("vault server: durable object enforcement", () => {
  test("full flow with segregation of duties, all server-side", async () => {
    const d = mkDO();
    assert.equal((await call(d, "adm", "admin", "init", { opening: "1000.00", policy: POL })).status, 403);
    assert.equal((await call(d, "own", "owner", "init", { opening: "1000.00", policy: POL })).status, 200);
    assert.equal((await call(d, "own", "owner", "init", { policy: POL })).status, 409, "second init refused");
    const c = await call(d, "ini", "initiator", "createTransfer", { from: "bank", to: "clearing", amount: "250.00", payee: "Acme" });
    assert.equal(c.status, 200);
    const id = c.body.result.id;
    assert.equal((await call(d, "ini", "initiator", "approve", { id })).status, 403, "initiator role cannot approve");
    assert.equal((await call(d, "ini", "admin", "approve", { id })).status, 409, "initiator uid cannot self-approve under another role");
    assert.equal((await call(d, "ap1", "approver", "approve", { id })).status, 200);
    assert.equal((await call(d, "ap1", "approver", "approve", { id })).status, 409, "same approver twice");
    assert.equal((await call(d, "ap1", "approver", "release", { id })).status, 409, "not yet approved");
    assert.equal((await call(d, "ap2", "approver", "approve", { id })).status, 200);
    assert.equal((await call(d, "ini", "admin", "release", { id })).status, 409, "initiator cannot release");
    assert.equal((await call(d, "ap2", "approver", "release", { id })).status, 200);
    const v = await view(d);
    const L = Ledger.load(v.ledger);
    assert.equal(L.balance("bank").balance, 75000n);
    assert.equal(L.transfers.get(id).status, "released");
    assert.ok(v.chain.ok);
    assert.equal(v.ledger.journal[1].by, "ap2", "entry carries the verified releaser");
  });

  test("overdraft and bad amounts are refused and nothing is written", async () => {
    const d = mkDO();
    await call(d, "own", "owner", "init", { opening: "100.00", policy: POL });
    const id = (await call(d, "own", "owner", "createTransfer", { from: "bank", to: "clearing", amount: "500.00" })).body.result.id;
    await call(d, "a", "approver", "approve", { id }); await call(d, "b", "approver", "approve", { id });
    const r = await call(d, "a", "approver", "release", { id });
    assert.equal(r.status, 409);
    match(r.body.error, /insufficient funds/);
    assert.equal((await call(d, "own", "owner", "createTransfer", { from: "bank", to: "clearing", amount: "0.001" })).status, 409);
    const v = await view(d);
    assert.equal(v.ledger.journal.length, 1, "only the opening entry");
    assert.equal(v.ledger.transfers.find((t) => t.id === id).status, "approved");
  });

  test("server policy keeps dual control on and validates input", async () => {
    const d = mkDO();
    assert.equal((await call(d, "own", "owner", "init", { opening: "10" })).status, 409, "no preset policy: init needs one");
    assert.equal((await view(d)).ledger, null);
    await call(d, "own", "owner", "init", { policy: POL });
    assert.equal((await call(d, "own", "owner", "setPolicy", { minApprovers: 0 })).status, 409);
    assert.equal((await call(d, "own", "owner", "setPolicy", { minApprovers: 3, dualControl: false, tiers: [["10000", 4]] })).status, 200);
    const v = await view(d);
    assert.deepEqual(v.ledger.policy, { minApprovers: 3, dualControl: true, tiers: [["10000.00", 4]] });
    assert.equal((await call(d, "adm", "admin", "setPolicy", { minApprovers: 1 })).status, 403);
  });

  test("state survives a restart and every attempt is in a verifiable audit chain", async () => {
    const st = new MemStorage();
    const d = mkDO(st);
    await call(d, "own", "owner", "init", { opening: "50.00", policy: POL });
    await call(d, "own", "owner", "openAccount", { name: "Payroll", type: "asset" });
    await call(d, "vw", "viewer", "createTransfer", { from: "bank", to: "clearing", amount: "1" });
    const d2 = mkDO(st);
    const v = await view(d2, "aud", "auditor");
    assert.equal(v.ledger.accounts.length, 4);
    assert.equal(v.auditCount, 3);
    assert.deepEqual(v.audit.map((a) => [a.op, a.ok]), [["createTransfer", false], ["openAccount", true], ["init", true]]);
    assert.deepEqual((await view(d2, "aud", "auditor", "?verify=1")).audit, { ok: true, brokenAt: -1, entries: 3 });
    const rec = st.m.get("a:0000000001"); rec.by = "someone-else";
    assert.equal((await view(mkDO(st), "aud", "auditor", "?verify=1")).audit.ok, false, "edited audit entry detected");
  });

  test("a tampered journal entry is detected after reload", async () => {
    const st = new MemStorage();
    await call(mkDO(st), "own", "owner", "init", { opening: "50.00", policy: POL });
    st.m.get("j:0000000000").postings[0].amount = "999";
    assert.equal((await view(mkDO(st))).chain.ok, false);
  });

  test("requests without a server-set identity are refused", async () => {
    assert.equal((await call(mkDO(), "", "owner", "init", { policy: POL })).status, 403);
    assert.equal((await call(mkDO(), "x", "superuser", "init", { policy: POL })).status, 403);
  });

  test("applyOp audit detail never needs the client's clock or name", () => {
    const { L } = applyOp(null, "init", { opening: "5", policy: POL }, { uid: "u1" }, 1234);
    assert.equal(L.journal[0].ts, 1234);
    assert.equal(L.journal[0].by, "u1");
    assert.ok(hashStr("x|" + canon({ a: 1n })).length === 64);
  });
});

group("vault server: id token verification", () => {
  const PROJECT = "sentinel-b4194";
  const b64u = (buf) => Buffer.from(buf).toString("base64url");
  let kp, jwk;
  const sign = async (claims, header = { alg: "RS256", kid: "k1", typ: "JWT" }, key) => {
    kp ||= await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
    jwk ||= { ...(await crypto.subtle.exportKey("jwk", kp.publicKey)), kid: "k1" };
    const data = b64u(JSON.stringify(header)) + "." + b64u(JSON.stringify(claims));
    const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key || kp.privateKey, new TextEncoder().encode(data));
    return data + "." + b64u(sig);
  };
  const now = 1_800_000_000;
  const good = { aud: PROJECT, iss: "https://securetoken.google.com/" + PROJECT, sub: "user-1", iat: now - 10, exp: now + 3000, auth_time: now - 100, email: "a@b.c" };
  const check = async (tok) => verifyIdToken(tok, PROJECT, { keys: [jwk], now });

  test("valid token yields the uid", async () => { const { uid, email } = await check(await sign(good)); assert.deepEqual({ uid, email }, { uid: "user-1", email: "a@b.c" }); });
  test("rejects expired, wrong audience, wrong issuer, empty subject", async () => {
    await rejects(check(await sign({ ...good, exp: now - 1 })), /expired/);
    await rejects(check(await sign({ ...good, aud: "other" })), /audience/);
    await rejects(check(await sign({ ...good, iss: "https://evil" })), /issuer/);
    await rejects(check(await sign({ ...good, sub: "" })), /subject/);
  });
  test("rejects a forged signature, unknown key and alg none", async () => {
    const other = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign"]);
    await rejects(check(await sign(good, undefined, other.privateKey)), /signature/);
    await rejects(check(await sign(good, { alg: "RS256", kid: "nope" })), /unknown signing key/);
    const t = await sign(good);
    await rejects(check(b64u(JSON.stringify({ alg: "none", kid: "k1" })) + "." + t.split(".")[1] + "."), /algorithm/);
    const [h, , s] = t.split(".");
    await rejects(check(h + "." + b64u(JSON.stringify({ ...good, sub: "admin" })) + "." + s), /signature/, "edited claims");
  });
});

group("vault server: membership lookup", () => {
  const fake = (status, body) => async () => new Response(JSON.stringify(body), { status });
  const doc = (uid, role) => ({ fields: { uid: { stringValue: uid }, role: { stringValue: role } } });
  test("returns the role only for a matching member doc", async () => {
    assert.equal(await memberRole("p", "vault1234", "u1", "t", fake(200, doc("u1", "approver"))), "approver");
    assert.equal(await memberRole("p", "vault1234", "u1", "t", fake(200, doc("u2", "owner"))), null);
    assert.equal(await memberRole("p", "vault1234", "u1", "t", fake(200, doc("u1", "removed"))), null);
    assert.equal(await memberRole("p", "vault1234", "u1", "t", fake(403, {})), null);
    assert.equal(await memberRole("p", "vault1234", "u1", "t", fake(404, {})), null);
    await rejects(memberRole("p", "vault1234", "u1", "t", fake(500, {})));
  });
  test("route refuses before reaching the vault", async () => {
    const json = (o, s = 200) => ({ o, s });
    const env = { VAULT: {}, FIREBASE_PROJECT_ID: "p" };
    assert.equal((await handleVault(new Request("https://x/"), {}, "vault1234", json)).s, 503);
    assert.equal((await handleVault(new Request("https://x/"), env, "../etc", json)).s, 400);
    assert.equal((await handleVault(new Request("https://x/"), env, "vault1234", json)).s, 401);
    assert.equal((await handleVault(new Request("https://x/", { headers: { Authorization: "Bearer abc" } }), env, "vault1234", json)).s, 401);
  });
});
