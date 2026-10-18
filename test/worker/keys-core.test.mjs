// Unit tests for worker/keys-core.js — workspace API key crypto.
import { test, group, assert } from "../harness.mjs";
import { generateKey, hashKey, keyIdOf, keyPrefix, normalizeScopes, hasScope, timingSafeEqual, SCOPES } from "../../worker/keys-core.js";

group("keys-core", () => {
  test("generateKey makes a dk_<id>_<secret> key with a 10-hex id", () => {
    const { key, keyId, prefix } = generateKey();
    assert.ok(/^dk_[0-9a-f]{10}_[A-Za-z0-9_-]{20,}$/.test(key), "key shape");
    assert.equal(keyId.length, 10);
    assert.equal(prefix, "dk_" + keyId + "_");
    assert.equal(keyIdOf(key), keyId);
  });

  test("two generated keys differ", () => {
    assert.ok(generateKey().key !== generateKey().key);
  });

  test("hashKey is a stable 64-char hex and differs per key", async () => {
    const k = generateKey().key;
    const a = await hashKey(k), b = await hashKey(k), c = await hashKey(generateKey().key);
    assert.equal(a.length, 64);
    assert.ok(/^[0-9a-f]+$/.test(a));
    assert.equal(a, b);
    assert.ok(a !== c);
  });

  test("keyIdOf rejects a malformed key", () => {
    assert.equal(keyIdOf("not-a-key"), "");
    assert.equal(keyIdOf("dk_short_x"), "");
    assert.equal(keyIdOf(""), "");
  });

  test("keyPrefix never reveals the secret", () => {
    assert.equal(keyPrefix("abcdef0123"), "dk_abcdef0123_…");
  });

  test("normalizeScopes keeps known scopes and defaults to ingest:write", () => {
    assert.deepEqual(normalizeScopes(["ingest:write", "findings:read", "bogus"]), ["ingest:write", "findings:read"]);
    assert.deepEqual(normalizeScopes([]), ["ingest:write"]);
    assert.deepEqual(normalizeScopes(["bogus"]), ["ingest:write"]);
    for (const s of SCOPES) assert.ok(normalizeScopes([s]).includes(s));
  });

  test("hasScope checks membership", () => {
    assert.ok(hasScope(["ingest:write"], "ingest:write"));
    assert.ok(!hasScope(["ingest:write"], "findings:read"));
    assert.ok(!hasScope(null, "ingest:write"));
  });

  test("timingSafeEqual compares equal-length strings correctly", () => {
    assert.ok(timingSafeEqual("abc", "abc"));
    assert.ok(!timingSafeEqual("abc", "abd"));
    assert.ok(!timingSafeEqual("abc", "abcd"));
  });
});
