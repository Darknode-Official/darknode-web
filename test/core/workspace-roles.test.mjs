import { test, group, assert } from "../harness.mjs";
import { ROLES, ACTIVE_ROLES, canDo, isPersonalWorkspace, ROLE_HELP } from "../../public/js/core/workspace-roles.js";
import { resolveWorkspaceRole, workspaceMemberRole } from "../../worker/workspace.js";

// A fake Firestore REST endpoint: maps member-doc URLs to a canned response.
function makeFirestore(docs) {
  return async (url) => {
    const m = /workspaces\/([^/]+)\/members\/([^/?]+)/.exec(url);
    const key = m ? decodeURIComponent(m[1]) + "/" + decodeURIComponent(m[2]) : null;
    const rec = key && docs[key];
    if (rec === "forbidden") return { status: 403, ok: false, json: async () => ({}) };
    if (!rec) return { status: 404, ok: false, json: async () => ({}) };
    if (rec === "error") return { status: 500, ok: false, json: async () => ({}) };
    return { status: 200, ok: true, json: async () => ({ fields: rec }) };
  };
}
const field = (uid, role) => ({ uid: { stringValue: uid }, role: { stringValue: role } });

group("workspace roles", () => {
  test("viewer can read but not write; analyst/responder can write; neither manages members", () => {
    assert.ok(canDo("viewer", "read"));
    assert.ok(!canDo("viewer", "write"));
    assert.ok(canDo("analyst", "write"));
    assert.ok(canDo("responder", "write"));
    assert.ok(!canDo("analyst", "manageMembers"));
    assert.ok(!canDo("responder", "manageMembers"));
  });

  test("admin manages members and renames; only owner sets roles and deletes", () => {
    assert.ok(canDo("admin", "manageMembers"));
    assert.ok(canDo("admin", "rename"));
    assert.ok(!canDo("admin", "setRole"));
    assert.ok(!canDo("admin", "delete"));
    assert.ok(canDo("owner", "setRole"));
    assert.ok(canDo("owner", "delete"));
    assert.ok(canDo("owner", "write"));
  });

  test("the removed tombstone can do nothing and is not an active role", () => {
    for (const op of Object.keys({ read: 1, write: 1, manageMembers: 1, rename: 1, delete: 1, setRole: 1 })) {
      assert.ok(!canDo("removed", op), "removed cannot " + op);
    }
    assert.ok(!ACTIVE_ROLES.includes("removed"));
    assert.ok(ACTIVE_ROLES.includes("owner") && ACTIVE_ROLES.includes("viewer"));
    assert.equal(ROLES.length, ACTIVE_ROLES.length + 1);
  });

  test("an unknown role can do nothing", () => {
    assert.ok(!canDo("superuser", "read"));
    assert.ok(!canDo("", "read"));
    assert.ok(!canDo(undefined, "write"));
  });

  test("every active role has help text", () => {
    for (const r of ACTIVE_ROLES) assert.ok(typeof ROLE_HELP[r] === "string" && ROLE_HELP[r].length);
  });

  test("a personal workspace is the caller's own uid", () => {
    assert.ok(isPersonalWorkspace("u123", "u123"));
    assert.ok(!isPersonalWorkspace("teamABCDEFGH", "u123"));
    assert.ok(!isPersonalWorkspace("", ""));
    assert.ok(!isPersonalWorkspace(null, null));
  });
});

group("workspace membership resolution (worker)", () => {
  const P = "proj";

  test("personal workspace resolves to owner without any Firestore read", async () => {
    let called = false;
    const role = await resolveWorkspaceRole(P, "u1", "u1", "tok", async () => { called = true; return { status: 500 }; });
    assert.equal(role, "owner");
    assert.ok(!called, "no membership lookup for a personal workspace");
  });

  test("a team member's role comes from their member doc", async () => {
    const fs = makeFirestore({ "teamABCDEFGH/u2": field("u2", "analyst") });
    const role = await resolveWorkspaceRole(P, "teamABCDEFGH", "u2", "tok", fs);
    assert.equal(role, "analyst");
  });

  test("a non-member of a team workspace resolves to null (404 or 403)", async () => {
    const fs = makeFirestore({ "teamABCDEFGH/u2": field("u2", "owner") });
    assert.equal(await resolveWorkspaceRole(P, "teamABCDEFGH", "stranger", "tok", fs), null);
    const forbidden = makeFirestore({ "teamABCDEFGH/stranger": "forbidden" });
    assert.equal(await resolveWorkspaceRole(P, "teamABCDEFGH", "stranger", "tok", forbidden), null);
  });

  test("a removed member is treated as not a member", async () => {
    const fs = makeFirestore({ "teamABCDEFGH/u3": field("u3", "removed") });
    assert.equal(await resolveWorkspaceRole(P, "teamABCDEFGH", "u3", "tok", fs), null);
  });

  test("a member doc whose uid field does not match is rejected", async () => {
    const fs = makeFirestore({ "teamABCDEFGH/u4": field("someoneElse", "owner") });
    assert.equal(await resolveWorkspaceRole(P, "teamABCDEFGH", "u4", "tok", fs), null);
  });

  test("a Firestore error (not 403/404) throws rather than silently denying", async () => {
    const fs = makeFirestore({ "teamABCDEFGH/u5": "error" });
    let threw = false;
    try { await workspaceMemberRole(P, "teamABCDEFGH", "u5", "tok", fs); } catch (_) { threw = true; }
    assert.ok(threw, "a 500 from Firestore is surfaced, not swallowed");
  });
});
