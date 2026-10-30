// Regression tests for the worker auth/role audit (2026-10-30). No network: fetch is mocked.
import { test, assert, group } from "../harness.mjs";
import { verifyIdToken } from "../../worker/vault-auth.js";
import { resolveWorkspaceRole } from "../../worker/workspace.js";
import { isSuspended } from "../../worker/gate.js";
import { timingSafeEqual, normalizeScopes, keyIdOf } from "../../worker/keys-core.js";
import { deliver } from "../../worker/notify.js";
import { MonitorDO } from "../../worker/monitor.js";

const rejects = async (p, re, msg) => {
  let err = null;
  try { await p; } catch (e) { err = e; }
  if (!err) throw new Error(msg || "expected a rejection");
  if (re && !re.test(err.message)) throw new Error((msg || "wrong error") + ": " + err.message);
};

group("auth audit: id tokens", () => {
  const P = "proj-a";
  const b64u = (buf) => Buffer.from(buf).toString("base64url");
  let kp, jwk;
  const sign = async (claims, header = { alg: "RS256", kid: "k1" }) => {
    kp ||= await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
    jwk ||= { ...(await crypto.subtle.exportKey("jwk", kp.publicKey)), kid: "k1" };
    const data = b64u(JSON.stringify(header)) + "." + b64u(JSON.stringify(claims));
    return data + "." + b64u(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(data)));
  };
  const now = 1_800_000_000;
  const good = { aud: P, iss: "https://securetoken.google.com/" + P, sub: "u1", iat: now - 10, exp: now + 3000, auth_time: now - 100, email: "test@darknode.ai" };
  const jwksFetch = (keys, counter) => async () => { counter.n++; return new Response(JSON.stringify({ keys }), { status: 200, headers: { "cache-control": "public, max-age=21600" } }); };
  // the JWKS cache is module-wide: run each case at a clock far past any earlier entry
  let clock = Date.now() + 365 * 86400000;
  const withClock = async (fn) => { const real = Date.now; try { return await fn((ms) => { clock += ms; }, () => clock); } finally { Date.now = real; } };

  test("a token for another Firebase project is refused", async () => {
    const t = await sign({ ...good, aud: "proj-b", iss: "https://securetoken.google.com/proj-b" });
    await rejects(verifyIdToken(t, P, { keys: [jwk], now }), /audience/);
    await rejects(verifyIdToken(await sign({ ...good, iss: "https://securetoken.google.com/proj-b" }), P, { keys: [jwk], now }), /issuer/);
    await rejects(verifyIdToken(await sign({ ...good, aud: [P] }), P, { keys: [jwk], now }), /audience/);
  });

  test("alg other than RS256 and a missing iat are refused; iat skew is bounded", async () => {
    for (const alg of ["HS256", "RS384", "none", "rs256"]) await rejects(verifyIdToken(await sign(good, { alg, kid: "k1" }), P, { keys: [jwk], now }), /algorithm/, alg);
    await rejects(verifyIdToken(await sign({ ...good, iat: undefined }), P, { keys: [jwk], now }), /future/);
    await rejects(verifyIdToken(await sign({ ...good, iat: now + 301 }), P, { keys: [jwk], now }), /future/);
    await rejects(verifyIdToken(await sign({ ...good, exp: now }), P, { keys: [jwk], now }), /expired/);
  });

  test("an empty or unset project id never matches a token with no aud/iss (was accepted)", async () => {
    const t = await sign({ ...good, aud: undefined, iss: "https://securetoken.google.com/undefined" });
    await rejects(verifyIdToken(t, undefined, { keys: [jwk], now }), /project/);
    await rejects(verifyIdToken(await sign({ ...good, aud: "", iss: "https://securetoken.google.com/" }), "", { keys: [jwk], now }), /project/);
  });

  test("an empty JWKS answer is not cached (was: every sign-in refused for up to max-age)", async () => withClock(async (tick, cur) => {
    Date.now = cur; tick(0);
    const t = await sign(good), c = { n: 0 };
    await rejects(verifyIdToken(t, P, { fetch: jwksFetch([], c), now }), /signing keys/);
    const ok = await verifyIdToken(t, P, { fetch: jwksFetch([jwk], c), now });
    assert.equal(ok.uid, "u1");
    assert.equal(c.n, 2);
  }));

  test("an unseen kid refetches the key set (rate-limited), so rotation inside max-age works", async () => withClock(async (tick, cur) => {
    Date.now = cur; tick(86400000 * 2);
    await sign(good);
    const c = { n: 0 }, old = { ...jwk, kid: "old" };
    assert.equal((await verifyIdToken(await sign(good, { alg: "RS256", kid: "old" }), P, { fetch: jwksFetch([old], c), now })).uid, "u1"); // primes the cache with [old]
    assert.equal(c.n, 1);
    const t = await sign(good);                         // kid k1, not in the cached set
    await rejects(verifyIdToken(t, P, { fetch: jwksFetch([old, jwk], c), now }), /unknown signing key/);
    assert.equal(c.n, 1, "no refetch within the rate limit");
    tick(61000);
    assert.equal((await verifyIdToken(t, P, { fetch: jwksFetch([old, jwk], c), now })).uid, "u1");
    assert.equal(c.n, 2);
  }));
});

group("auth audit: workspace roles, suspension, keys", () => {
  const W = "abcdefghij0123456789";
  const doc = (uid, role) => async () => new Response(JSON.stringify({ fields: { uid: { stringValue: uid }, role: { stringValue: role } } }), { status: 200 });

  test("removed, unknown, prototype and padded role strings resolve to no role", async () => {
    for (const role of ["removed", "superadmin", "__proto__", "constructor", "Owner", " owner", "owner "]) {
      assert.equal(await resolveWorkspaceRole("p", W, "u1", "t", doc("u1", role)), null, JSON.stringify(role));
    }
    assert.equal(await resolveWorkspaceRole("p", W, "u1", "t", doc("u1", "viewer")), "viewer");
    assert.equal(await resolveWorkspaceRole("p", W, "u1", "t", doc("u2", "owner")), null, "someone else's doc");
    assert.equal(await resolveWorkspaceRole("p", "uid" + "x".repeat(25), "u1", "t", doc("u1", "owner")), null, "another user's personal id");
  });

  test("suspension matches regardless of case and surrounding whitespace", async () => {
    const ban = async () => new Response(JSON.stringify({ fields: { banned: { arrayValue: { values: [{ stringValue: " Test@Darknode.AI " }] } } } }), { status: 200 });
    assert.equal(await isSuspended("p", { uid: "u1", email: "TEST@darknode.ai\t" }, "t", { fetch: ban, cache: {} }), true);
    assert.equal(await isSuspended("p", { uid: "u1", email: "other@example.com" }, "t", { fetch: ban, cache: {} }), false);
  });

  test("key compare, scope cleaning and key id parsing refuse look-alikes", () => {
    assert.equal(timingSafeEqual("ab", "abc"), false);
    assert.deepEqual(normalizeScopes(["admin", "*", "findings:read "]), ["findings:read"]);
    assert.deepEqual(normalizeScopes("*"), ["ingest:write"]);
    assert.equal(keyIdOf("dk_ABCDEF0123_" + "x".repeat(20)), "");
  });
});

group("auth audit: alert delivery", () => {
  test("a channel type naming an Object.prototype member sends the generic payload (was a throw)", async () => {
    for (const type of ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf"]) {
      let body = "";
      const r = await deliver({ type, url: "https://example.com/hook" }, { title: "t", severity: "high" }, { fetch: async (u, i) => { body = i.body; return new Response("", { status: 200 }); } });
      assert.equal(r.ok, true, type);
      assert.equal(JSON.parse(body).type, "darknode.alert", type);
    }
  });

  test("one bad channel no longer fails the alarm, so the good channel is not re-alerted every retry", async () => {
    const map = new Map(); let alarm = null;
    const st = { storage: { async get(k) { return map.get(k); }, async put(k, v) { map.set(k, v); }, async delete(k) { map.delete(k); }, async setAlarm(t) { alarm = t; }, async getAlarm() { return alarm; } }, blockConcurrencyWhile: async (fn) => fn() };
    const mon = new MonitorDO(st);
    const day = (n) => new Date(Date.now() + n * 86400000).toISOString();
    let good = 0;
    const fetch = async (url) => {
      if (url.includes("crt.sh")) return { ok: true, status: 200, json: async () => [{ issuer_name: "CA", not_after: day(3), not_before: day(-80), name_value: "x" }] };
      if (url.includes("certspotter")) return { ok: false, status: 404, json: async () => null };
      if (url.includes("/good")) good++;
      return { ok: true, status: 200 };
    };
    await mon.fetch(new Request("https://m/", { method: "POST", headers: { "x-mon-uid": "u1", "x-mon-role": "owner" }, body: JSON.stringify({ op: "upsert", monitor: { name: "c", type: "cert-expiry", config: { domains: ["example.com"] }, channels: [{ type: "slack", url: "https://example.com/good" }, { type: "__proto__", url: "https://example.com/bad" }] } }) }));
    for (let i = 0; i < 3; i++) await mon.runDue({ force: true, fetch, sleep: async () => {} });
    assert.equal(good, 1, "alerted once, not once per alarm retry");
    assert.ok(Object.values(map.get("monitors"))[0].lastRunAt > 0, "the run was saved");
  });
});
