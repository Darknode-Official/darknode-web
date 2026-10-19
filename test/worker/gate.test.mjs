// Unit tests for worker/gate.js — server-enforced access suspension.
// Covers: ban matching (case/whitespace), no-email, missing doc, the isolate cache
// (fresh hit avoids a fetch; expiry re-reads), and the fail-open behaviour on a
// Firestore error (empty when never loaded; retains the last known ban set otherwise).
import { test, group, assert } from "../harness.mjs";
import { parseBanned, isSuspended } from "../../worker/gate.js";

const PID = "sentinel-b4194";

// A Firestore-REST settings/whitelist document carrying the given banned emails.
const banDoc = (emails) => ({
  name: "projects/" + PID + "/databases/(default)/documents/settings/whitelist",
  fields: {
    banned: { arrayValue: { values: emails.map((e) => ({ stringValue: e })) } },
    enforce: { booleanValue: false },
  },
});

// A fake fetch that serves `doc` (or a status / thrown error) and counts calls.
function fakeFetch({ doc = banDoc([]), status = 200, throwErr = false } = {}) {
  const f = async () => {
    f.calls++;
    if (throwErr) throw new Error("network down");
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => doc,
    };
  };
  f.calls = 0;
  return f;
}

// Each test gets its own cache object so the module-level isolate cache never leaks.
const freshCache = () => ({ at: 0, set: null });

group("gate: parseBanned", () => {
  test("extracts lowercased, trimmed emails; tolerates junk", () => {
    assert.deepEqual([...parseBanned(banDoc(["A@B.com", "  c@d.com "]))].sort(), ["a@b.com", "c@d.com"]);
    assert.equal(parseBanned({}).size, 0);
    assert.equal(parseBanned(null).size, 0);
    assert.equal(parseBanned({ fields: {} }).size, 0);
    assert.equal(parseBanned({ fields: { banned: { arrayValue: { values: [{}, { stringValue: "" }] } } } }).size, 0);
  });
});

group("gate: isSuspended", () => {
  test("banned email is suspended (case/space-insensitive)", async () => {
    const fetch = fakeFetch({ doc: banDoc(["evil@x.com"]) });
    const cache = freshCache();
    assert.ok(await isSuspended(PID, { uid: "u1", email: "EVIL@x.com" }, "tok", { fetch, now: 1000, cache }));
    assert.ok(await isSuspended(PID, { uid: "u1", email: "  evil@x.com " }, "tok", { fetch, now: 1000, cache }));
  });

  test("a non-banned email is not suspended", async () => {
    const fetch = fakeFetch({ doc: banDoc(["evil@x.com"]) });
    assert.notOk(await isSuspended(PID, { uid: "u2", email: "good@x.com" }, "tok", { fetch, now: 1, cache: freshCache() }));
  });

  test("no email / no projectId short-circuits to not-suspended and never fetches", async () => {
    const fetch = fakeFetch({ doc: banDoc(["evil@x.com"]) });
    assert.notOk(await isSuspended(PID, { uid: "u3", email: "" }, "tok", { fetch, now: 1, cache: freshCache() }));
    assert.notOk(await isSuspended("", { uid: "u3", email: "evil@x.com" }, "tok", { fetch, now: 1, cache: freshCache() }));
    assert.equal(fetch.calls, 0);
  });

  test("a 404 (no whitelist doc) means nobody is banned", async () => {
    const fetch = fakeFetch({ status: 404 });
    assert.notOk(await isSuspended(PID, { uid: "u4", email: "evil@x.com" }, "tok", { fetch, now: 1, cache: freshCache() }));
  });

  test("the cache is served within the TTL and re-read after it", async () => {
    const fetch = fakeFetch({ doc: banDoc(["evil@x.com"]) });
    const cache = freshCache();
    await isSuspended(PID, { uid: "u", email: "good@x.com" }, "tok", { fetch, now: 0, cache });
    await isSuspended(PID, { uid: "u", email: "evil@x.com" }, "tok", { fetch, now: 30_000, cache }); // within 60s TTL
    assert.equal(fetch.calls, 1, "second call inside TTL should hit cache");
    const hit = await isSuspended(PID, { uid: "u", email: "evil@x.com" }, "tok", { fetch, now: 90_000, cache }); // past TTL
    assert.equal(fetch.calls, 2, "call past TTL should re-read");
    assert.ok(hit);
  });

  test("fails OPEN on a Firestore error when nothing was ever loaded", async () => {
    const fetch = fakeFetch({ throwErr: true });
    assert.notOk(await isSuspended(PID, { uid: "u", email: "evil@x.com" }, "tok", { fetch, now: 1, cache: freshCache() }));
  });

  test("negative-caches a sustained outage so it does not re-fetch every request", async () => {
    const cache = freshCache();
    const bad = fakeFetch({ throwErr: true });
    await isSuspended(PID, { uid: "u", email: "evil@x.com" }, "tok", { fetch: bad, now: 0, cache });
    await isSuspended(PID, { uid: "u", email: "evil@x.com" }, "tok", { fetch: bad, now: 30_000, cache });
    assert.equal(bad.calls, 1, "a within-TTL retry after a failed read should be suppressed");
  });

  test("retains the last known ban set when a later read errors", async () => {
    const cache = freshCache();
    const good = fakeFetch({ doc: banDoc(["evil@x.com"]) });
    assert.ok(await isSuspended(PID, { uid: "u", email: "evil@x.com" }, "tok", { fetch: good, now: 0, cache }));
    // TTL expired and the refresh fails: the known ban must still bite.
    const bad = fakeFetch({ throwErr: true });
    assert.ok(await isSuspended(PID, { uid: "u", email: "evil@x.com" }, "tok", { fetch: bad, now: 120_000, cache }));
  });
});
