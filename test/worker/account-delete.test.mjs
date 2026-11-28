// Unit tests for worker/account-delete.js: self-service account deletion. Firestore REST and
// Firebase Auth are an in-memory stand-in behind a fake fetch; Durable Objects are stubs.
import { test, group, assert } from "../harness.mjs";
import { handleAccountDelete, handleAccountExport, handleAdminDeletions, recentEnough, maybeWipe, plain, RECENT_S } from "../../worker/account-delete.js";
import { matchRoute, authorize } from "../../worker/auth.js";

const json = (body, status = 200) => ({ status, body });
const NOW = 1795000000;
const ROOT = "https://firestore.googleapis.com/v1/projects/p/databases/(default)/documents";
const S = (v) => ({ stringValue: v });

function fakeCloud(docs) {
  const db = new Map(Object.entries(docs).map(([k, v]) => [k, Object.fromEntries(Object.entries(v).map(([f, x]) => [f, S(x)]))]));
  const authDeleted = [];
  const res = (status, body) => ({ ok: status < 300, status, json: async () => body });
  const doc = (path) => ({ name: "projects/p/databases/(default)/documents/" + path, fields: db.get(path) });
  const fetch = async (url, init = {}) => {
    const m = init.method || "GET";
    if (url.endsWith("/accounts:delete")) { if (cloud.authFails) return res(500, {}); authDeleted.push(JSON.parse(init.body).localId); return res(200, {}); }
    if (url.endsWith("/accounts:lookup")) return res(200, { users: [{ localId: "u1", email: "test@darknode.ai", emailVerified: true, providerUserInfo: [{ providerId: "password" }], createdAt: "1793404800000" }] });
    if (url === ROOT + ":runQuery") {
      const q = JSON.parse(init.body).structuredQuery, from = q.from[0], ff = q.where.fieldFilter;
      const hits = [...db.keys()].filter((p) => {
        const seg = p.split("/"); if (seg.length % 2) return false;
        const coll = seg[seg.length - 2];
        if (coll !== from.collectionId || (!from.allDescendants && seg.length !== 2)) return false;
        const v = db.get(p)[ff.field.fieldPath]; return v && v.stringValue === ff.value.stringValue;
      });
      return res(200, hits.map((p) => ({ document: doc(p) })));
    }
    const path = decodeURIComponent(url.slice(ROOT.length + 1)).split("?")[0];
    if (path.endsWith(":listCollectionIds")) {
      const base = path.slice(0, -":listCollectionIds".length) + "/";
      const ids = new Set([...db.keys()].filter((p) => p.startsWith(base)).map((p) => p.slice(base.length).split("/")[0]).filter((c, _, a) => c));
      return res(200, { collectionIds: [...ids].filter((c) => [...db.keys()].some((p) => p.startsWith(base + c + "/") && p.slice(base.length).split("/").length === 2)) });
    }
    if (m === "DELETE") { db.delete(path); return res(200, {}); }
    if (path.split("/").length % 2) { // a collection
      const kids = [...db.keys()].filter((p) => p.startsWith(path + "/") && p.split("/").length === path.split("/").length + 1);
      return res(200, { documents: kids.map(doc) });
    }
    return db.has(path) ? res(200, doc(path)) : res(404, {});
  };
  const cloud = { db, fetch, authDeleted, authFails: false };
  return cloud;
}

function fakeDOs() {
  const wiped = [];
  const ns = (kind) => ({ idFromName: (n) => n, get: (id) => ({ fetch: async (u, init) => {
    if (u === "https://do/") { const op = JSON.parse(init.body).op; return { ok: true, status: 200, json: async () => kind === "monitor" ? (op === "list" ? { monitors: [{ id: "m1", target: "example.com", wid: id }], history: [] } : { deadlines: [] }) : { keys: [{ keyId: "k1", prefix: "dk_ab", scopes: ["ingest:write"] }] } }; }
    assert.equal(u, "https://do/__wipe"); assert.equal(init.headers["x-dn-wipe"], "1"); wiped.push(kind + ":" + id); return { ok: true, status: 200 }; } }) });
  return { wiped, env: { FIREBASE_PROJECT_ID: "p", GRAPH: ns("graph"), MONITOR: ns("monitor"), INGEST: ns("ingest"), VAULT: ns("vault") } };
}

const req = (body = { confirm: "DELETE" }) => ({ method: "POST", json: async () => body });
const me = (extra = {}) => ({ kind: "user", uid: "u1", email: "test@darknode.ai", claims: { auth_time: NOW - 30 }, ...extra });
const run = (cloud, dos, principal = me(), body) => handleAccountDelete(req(body), dos.env, json, principal, { fetch: cloud.fetch, token: async () => "t", now: NOW });

group("account-delete", () => {
  test("the route needs a signed-in user", () => {
    const { route } = matchRoute("/api/account/delete", "POST");
    assert.equal(route.id, "account-delete");
    assert.equal(authorize(route, { kind: "anonymous" }).status, 401);
    assert.equal(authorize(route, { kind: "key" }).status, 401);
    assert.equal(authorize(route, { kind: "user", claims: {} }), null);
  });

  test("a sign-in older than 5 minutes must sign in again", async () => {
    assert.equal(recentEnough({ auth_time: NOW - RECENT_S }, NOW), true);
    assert.equal(recentEnough({ auth_time: NOW - RECENT_S - 1 }, NOW), false);
    assert.equal(recentEnough({}, NOW), false);
    const cloud = fakeCloud({ "users/u1": { email: "test@darknode.ai" } }), dos = fakeDOs();
    const r = await run(cloud, dos, me({ claims: { auth_time: NOW - 3600 } }));
    assert.equal(r.status, 401); assert.equal(r.body.reauth, true);
    assert.ok(cloud.db.has("users/u1")); assert.equal(dos.wiped.length, 0); assert.equal(cloud.authDeleted.length, 0);
  });

  test("without the confirm word nothing happens", async () => {
    const cloud = fakeCloud({ "users/u1": {} }), dos = fakeDOs();
    const r = await run(cloud, dos, me(), { confirm: "yes" });
    assert.equal(r.status, 400); assert.ok(cloud.db.has("users/u1"));
  });

  test("everything the user owns is deleted; other people's data is kept", async () => {
    const cloud = fakeCloud({
      "users/u1": { email: "test@darknode.ai" }, "users/u1/notifications/n1": { text: "hi" }, "users/u1/config/deck": { a: "b" },
      "users/u2": { email: "other@darknode.ai" },
      "usage/u1": {}, "usage/u2": {}, "deletionRequests/u1": { uid: "u1" },
      "pairings/c1": { uid: "u1" }, "pairings/c2": { uid: "u2" },
      "upgradeRequests/r1": { uid: "u1" }, "toolRequests/t1": { uid: "u1" }, "feedback/f1": { uid: "u1" }, "errors/e1": { uid: "u1" },
      "ip_reports/i1": { reporter_uid: "u1" }, "ip_reports/i2": { reporter_uid: "u2" },
      "waitlist/w1": { email: "test@darknode.ai" }, "waitlist/w2": { email: "other@darknode.ai" },
      // a team workspace they created and hold alone: deleted with its stores
      "workspaces/solo0000000000000000": { createdBy: "u1", name: "Solo" }, "workspaces/solo0000000000000000/members/u1": { uid: "u1", role: "owner" },
      "workspaces/solo0000000000000000/memberLog/l1": { uid: "u1" },
      // someone else's workspace they joined: only their member doc goes
      "workspaces/team0000000000000000": { createdBy: "u2", name: "Team" }, "workspaces/team0000000000000000/members/u1": { uid: "u1", role: "analyst" },
      "workspaces/team0000000000000000/members/u2": { uid: "u2", role: "owner" },
      // a vault they created alone
      "vaults/vault0001": { createdBy: "u1", name: "V" }, "vaults/vault0001/members/u1": { uid: "u1", role: "owner" },
    }), dos = fakeDOs();
    const r = await run(cloud, dos);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const left = [...cloud.db.keys()].sort();
    assert.deepEqual(left, ["ip_reports/i2", "pairings/c2", "usage/u2", "users/u2", "waitlist/w2", "workspaces/team0000000000000000", "workspaces/team0000000000000000/members/u2"]);
    assert.deepEqual(cloud.authDeleted, ["u1"]);
    for (const w of ["graph:u1", "monitor:u1", "ingest:u1", "graph:solo0000000000000000", "monitor:solo0000000000000000", "ingest:solo0000000000000000", "vault:vault0001"]) assert.ok(dos.wiped.includes(w), w);
    assert.ok(!dos.wiped.some((w) => w.includes("team0000")));
  });

  test("a workspace they created that still has members blocks deletion, before anything is touched", async () => {
    const cloud = fakeCloud({
      "users/u1": {}, "workspaces/acme0000000000000000": { createdBy: "u1", name: "Acme" },
      "workspaces/acme0000000000000000/members/u1": { uid: "u1", role: "owner" },
      "workspaces/acme0000000000000000/members/u3": { uid: "u3", role: "viewer" },
      "workspaces/acme0000000000000000/members/u4": { uid: "u4", role: "removed" },
    }), dos = fakeDOs();
    const r = await run(cloud, dos);
    assert.equal(r.status, 409);
    assert.ok(/"Acme"/.test(r.body.error));
    assert.deepEqual(r.body.blocking, [{ kind: "workspace", id: "acme0000000000000000", name: "Acme", members: 1 }]);
    assert.ok(cloud.db.has("users/u1")); assert.equal(dos.wiped.length, 0); assert.equal(cloud.authDeleted.length, 0);
  });

  test("removed members don't count, and a second run finishes a half-done one", async () => {
    const cloud = fakeCloud({ "workspaces/acme0000000000000000": { createdBy: "u1", name: "Acme" }, "workspaces/acme0000000000000000/members/u1": { uid: "u1", role: "owner" }, "workspaces/acme0000000000000000/members/u4": { uid: "u4", role: "removed" } }), dos = fakeDOs();
    assert.equal((await run(cloud, dos)).status, 200);
    assert.equal(cloud.db.size, 0);
    assert.equal((await run(cloud, dos)).status, 200); // users/u1 already gone: still ok
  });

  test("a failure stops before the sign-in is deleted", async () => {
    const cloud = fakeCloud({ "users/u1": {} }), dos = fakeDOs();
    dos.env.MONITOR = { idFromName: (n) => n, get: () => ({ fetch: async () => ({ ok: false, status: 500 }) }) };
    const r = await run(cloud, dos);
    assert.equal(r.status, 502); assert.equal(cloud.authDeleted.length, 0); assert.ok(cloud.db.has("users/u1"));
  });

  test("the DO wipe route answers only the internal path and header", async () => {
    const calls = [];
    const storage = { deleteAlarm: async () => calls.push("alarm"), deleteAll: async () => calls.push("all") };
    const mk = (path, h) => ({ url: "https://do" + path, headers: { get: (k) => h[k] } });
    assert.equal(await maybeWipe(mk("/", { "x-dn-wipe": "1" }), storage), null);
    assert.equal(await maybeWipe(mk("/__wipe", {}), storage), null);
    assert.equal(calls.length, 0);
    const r = await maybeWipe(mk("/__wipe", { "x-dn-wipe": "1" }), storage);
    assert.equal(r.status, 200); assert.deepEqual(calls, ["alarm", "all"]);
  });

  test("export: the caller's own records, secrets redacted, other people's left out", async () => {
    const cloud = fakeCloud({
      "users/u1": { email: "test@darknode.ai", tier: "free" }, "users/u1/notifications/n1": { text: "hi" },
      "users/u2": { email: "other@darknode.ai" }, "pairings/c1": { uid: "u1", apiKey: "dk_secret" }, "pairings/c2": { uid: "u2" },
      "feedback/f1": { uid: "u1", message: "nice" }, "waitlist/w1": { email: "test@darknode.ai" },
      "workspaces/team0000000000000000": { createdBy: "u2", name: "Team" }, "workspaces/team0000000000000000/members/u1": { uid: "u1", role: "analyst" },
    }), dos = fakeDOs();
    const r = await handleAccountExport({ method: "GET" }, dos.env, json, me(), { fetch: cloud.fetch, token: async () => "t" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const b = r.body;
    assert.equal(b.account.email, "test@darknode.ai"); assert.deepEqual(b.account.signInMethods, ["password"]);
    assert.equal(b.profile.tier, "free");
    assert.deepEqual(b.profileCollections.notifications, [{ id: "n1", text: "hi" }]);
    assert.deepEqual(b.records.pairings, [{ id: "c1", uid: "u1", apiKey: "[redacted]" }]);
    assert.equal(b.records.feedback.length, 1); assert.equal(b.records.waitlist.length, 1);
    assert.deepEqual(b.memberships, [{ kind: "workspace", id: "team0000000000000000", name: "Team", role: "analyst", createdByYou: false }]);
    assert.equal(b.personalWorkspace.monitors[0].target, "example.com"); assert.equal(b.personalWorkspace.apiKeys[0].keyId, "k1");
    assert.ok(!JSON.stringify(b).includes("other@darknode.ai"));
    assert.equal(cloud.db.size, 9); // nothing was changed
  });

  test("export decodes every Firestore value type", () => {
    assert.deepEqual(plain({ mapValue: { fields: { a: { integerValue: "3" }, b: { arrayValue: { values: [{ booleanValue: true }, { nullValue: null }] } }, t: { timestampValue: "2026-11-27T00:00:00Z" } } } }),
      { a: 3, b: [true, null], t: "2026-11-27T00:00:00Z" });
  });

  test("admin deletions: owner only; lists requests; deletes only accounts that asked", async () => {
    const route = matchRoute("/api/admin/deletions", "POST").route;
    assert.equal(authorize(route, { kind: "user", claims: {} }).status, 403);
    assert.equal(authorize(route, { kind: "user", claims: { admin: true } }), null);
    const cloud = fakeCloud({ "deletionRequests/u1": { uid: "u1", email: "test@darknode.ai" }, "users/u1": {}, "users/u2": {}, "waitlist/w1": { email: "test@darknode.ai" } }), dos = fakeDOs();
    const o = { fetch: cloud.fetch, token: async () => "t" };
    const list = await handleAdminDeletions({ method: "GET" }, dos.env, json, o);
    assert.deepEqual(list.body.requests.map((x) => [x.uid, x.email]), [["u1", "test@darknode.ai"]]);
    const no = await handleAdminDeletions(req({ uid: "u2" }), dos.env, json, o);
    assert.equal(no.status, 404); assert.ok(cloud.db.has("users/u2"));
    const yes = await handleAdminDeletions(req({ uid: "u1" }), dos.env, json, o);
    assert.equal(yes.status, 200);
    assert.deepEqual([...cloud.db.keys()], ["users/u2"]); assert.deepEqual(cloud.authDeleted, ["u1"]);
  });

  test("admin deletions: if the sign-in delete fails the request stays, so it can be retried", async () => {
    const cloud = fakeCloud({ "deletionRequests/u1": { uid: "u1", email: "" }, "users/u1": {} }), dos = fakeDOs();
    cloud.authFails = true;
    const r = await handleAdminDeletions(req({ uid: "u1" }), dos.env, json, { fetch: cloud.fetch, token: async () => "t" });
    assert.equal(r.status, 502); assert.ok(cloud.db.has("deletionRequests/u1"));
  });
});
