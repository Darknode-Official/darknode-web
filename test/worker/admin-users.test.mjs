// Unit tests for worker/admin-users.js — the owner-only Firebase Auth account listing.
import { test, group, assert } from "../harness.mjs";
import { handleAdminUsers, authUserRow } from "../../worker/admin-users.js";
import { matchRoute, authorize } from "../../worker/auth.js";

const json = (body, status = 200) => ({ status, body });

group("admin-users", () => {
  test("the route is owner only", () => {
    const { route } = matchRoute("/api/admin/users", "GET");
    assert.equal(route.id, "admin-users");
    assert.equal(authorize(route, { kind: "user", claims: {} }).status, 403);
    assert.equal(authorize(route, { kind: "anonymous" }).status, 401);
    assert.equal(authorize(route, { kind: "user", claims: { admin: true } }), null);
  });
  test("an unverified email sign-up is listed with only the panel's fields", () => {
    const row = authUserRow({ localId: "u1", email: "test@darknode.ai", emailVerified: false, passwordHash: "x", providerUserInfo: [{ providerId: "password" }], createdAt: "1793404800000", lastLoginAt: "1793404800000" });
    assert.deepEqual(row, { uid: "u1", email: "test@darknode.ai", name: "", emailVerified: false, disabled: false, providers: ["password"], createdAt: 1793404800000, lastLoginAt: 1793404800000 });
  });
  test("every page is read", async () => {
    const pages = [{ users: [{ localId: "a" }], nextPageToken: "p2" }, { users: [{ localId: "b", providerUserInfo: [{ providerId: "google.com" }] }] }];
    const urls = [];
    const fetch = async (u) => { urls.push(u); return { ok: true, json: async () => pages[urls.length - 1] }; };
    const r = await handleAdminUsers({ FIREBASE_PROJECT_ID: "p" }, json, { fetch, token: async () => "t" });
    assert.deepEqual(r.body.users.map((u) => u.uid), ["a", "b"]);
    assert.deepEqual(r.body.users[1].providers, ["google"]);
    assert.ok(urls[1].includes("nextPageToken=p2"));
    assert.equal(r.body.truncated, false);
  });
  test("an upstream failure is an error, not an empty list", async () => {
    const r = await handleAdminUsers({ FIREBASE_PROJECT_ID: "p" }, json, { fetch: async () => ({ ok: false, status: 403 }), token: async () => "t" });
    assert.equal(r.status, 502);
  });
});
