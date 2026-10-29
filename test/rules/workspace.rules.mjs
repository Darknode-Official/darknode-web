// Firestore rules tests for team workspaces (firebase/firestore.rules, Phase B2). Not
// part of `npm test`: they need Java and the Firestore emulator. Run from a folder that
// has @firebase/rules-unit-testing@4 and firebase@11 installed:
//   RULES=<repo>/firebase/firestore.rules firebase emulators:exec --only firestore \
//     --project demo-ws "node workspace.rules.mjs"
// The emulator must listen on 127.0.0.1:8181 (8080 is reserved locally).

import { readFileSync } from "node:fs";
import { initializeTestEnvironment, assertSucceeds, assertFails } from "@firebase/rules-unit-testing";
import firebase from "firebase/compat/app";
import "firebase/compat/firestore";

const ts = () => firebase.firestore.FieldValue.serverTimestamp();
const env = await initializeTestEnvironment({
  projectId: "demo-ws",
  firestore: { rules: readFileSync(process.env.RULES, "utf8"), host: "127.0.0.1", port: 8181 },
});
const as = (uid) => env.authenticatedContext(uid).firestore();
let pass = 0, fail = 0;
const t = async (name, p) => { try { await p; pass++; console.log("  ok  ", name); } catch (e) { fail++; console.log("  FAIL", name, "-", e.message.split("\n")[0]); } };

const found = (db, wid, uid, { log = "log" + wid, createdBy = uid, role = "owner", skipLog = false } = {}) => {
  const b = db.batch();
  b.set(db.doc(`workspaces/${wid}`), { name: "Blue Team", createdBy, createdAt: ts() });
  b.set(db.doc(`workspaces/${wid}/members/${uid}`), { uid, role, by: uid, ts: ts(), logId: log });
  if (!skipLog) b.set(db.doc(`workspaces/${wid}/memberLog/${log}`), { uid, role, by: uid, ts: ts() });
  return b.commit();
};
const setRole = (db, by, wid, uid, role, log, { skipLog = false } = {}) => {
  const b = db.batch();
  b.set(db.doc(`workspaces/${wid}/members/${uid}`), { uid, role, by, ts: ts(), logId: log });
  if (!skipLog) b.set(db.doc(`workspaces/${wid}/memberLog/${log}`), { uid, role, by, ts: ts() });
  return b.commit();
};

const A = as("alice"), B = as("bob"), C = as("carol"), D = as("dave");
const W = "teamABCD1234567890XY";

await t("founding without a log entry is refused", assertFails(found(A, W, "alice", { skipLog: true })));
await t("founding in someone else's name is refused", assertFails(found(B, W, "bob", { createdBy: "alice" })));
await t("founding as a non-owner role is refused", assertFails(found(A, W, "alice", { role: "admin" })));
await t("a workspace id shaped like a uid (another user's personal workspace) is refused", assertFails(found(A, "Vq3xY8kLm2NpR7sT4uWz9aBcD1e2", "alice", { log: "logSQUAT01" })));
await t("a short workspace id is refused", assertFails(found(A, "teamABCD12", "alice", { log: "logSHORT01" })));
await t("alice founds the workspace", assertSucceeds(found(A, W, "alice")));
await t("carol cannot re-found an existing workspace", assertFails(found(C, W, "carol", { log: "logCCCCCCC" })));
await t("bob cannot add himself", assertFails(setRole(B, "bob", W, "bob", "owner", "logBBBBBB1")));
await t("owner adds bob as admin", assertSucceeds(setRole(A, "alice", W, "bob", "admin", "logBBBBBB2")));
await t("owner cannot change their own role", assertFails(setRole(A, "alice", W, "alice", "admin", "logAAAAAA2")));
await t("admin bob adds carol as analyst", assertSucceeds(setRole(B, "bob", W, "carol", "analyst", "logCCCCCC1")));
await t("admin bob CANNOT mint another admin", assertFails(setRole(B, "bob", W, "dave", "admin", "logDDDDDD1")));
await t("admin bob CANNOT mint an owner", assertFails(setRole(B, "bob", W, "dave", "owner", "logDDDDDD2")));
await t("owner may mint a second admin", assertSucceeds(setRole(A, "alice", W, "dave", "admin", "logDDDDDD3")));
await t("analyst carol cannot add members", assertFails(setRole(C, "carol", W, "erin", "viewer", "logEEEEEE1")));
await t("role change without a log entry is refused", assertFails(setRole(A, "alice", W, "carol", "viewer", "logCCCCCC2", { skipLog: true })));
await t("reusing an old log entry is refused", assertFails(setRole(A, "alice", W, "carol", "analyst", "logCCCCCC1", { skipLog: true })));
await t("an unknown role is refused", assertFails(setRole(A, "alice", W, "erin", "god", "logEEEEEE2")));
await t("a forged by field is refused", assertFails(setRole(A, "carol", W, "erin", "viewer", "logEEEEEE3")));
await t("member log is append-only (update)", assertFails(A.doc(`workspaces/${W}/memberLog/logBBBBBB2`).update({ role: "owner" })));
await t("member log is append-only (delete)", assertFails(A.doc(`workspaces/${W}/memberLog/logBBBBBB2`).delete()));
await t("member docs cannot be deleted", assertFails(A.doc(`workspaces/${W}/members/bob`).delete()));
await t("workspace cannot be deleted", assertFails(A.doc(`workspaces/${W}`).delete()));
await t("admin may rename the workspace", assertSucceeds(B.doc(`workspaces/${W}`).update({ name: "Blue Team Ops" })));
await t("createdBy cannot be changed", assertFails(A.doc(`workspaces/${W}`).update({ createdBy: "carol" })));
await t("member carol reads the workspace", assertSucceeds(C.doc(`workspaces/${W}`).get()));
await t("member carol reads members", assertSucceeds(C.collection(`workspaces/${W}/members`).get()));
await t("non-member erin cannot read the workspace", assertFails(as("erin").doc(`workspaces/${W}`).get()));
await t("non-member erin cannot read members", assertFails(as("erin").doc(`workspaces/${W}/members/bob`).get()));
await t("erin may read her own (absent) member doc", assertSucceeds(as("erin").doc(`workspaces/${W}/members/erin`).get()));
await t("carol finds her workspaces by collection group", assertSucceeds(C.collectionGroup("members").where("uid", "==", "carol").get()));
await t("carol cannot list other people's memberships", assertFails(C.collectionGroup("members").where("uid", "==", "bob").get()));
await t("owner removes carol", assertSucceeds(setRole(A, "alice", W, "carol", "removed", "logCCCCCC3")));
await t("removed carol can no longer read the workspace", assertFails(C.doc(`workspaces/${W}`).get()));
await t("removed carol still sees her own member doc (for the worker)", assertSucceeds(C.doc(`workspaces/${W}/members/carol`).get()));

// Existing owner/admin member docs are owner-only; the founder's doc is locked.
const E = as("erin");
const roleIs = (db, uid, role) => db.doc(`workspaces/${W}/members/${uid}`).get().then((d) => { if (d.data().role !== role) throw new Error(uid + " is " + d.data().role); });
await t("owner makes erin a co-owner", assertSucceeds(setRole(A, "alice", W, "erin", "owner", "logEEEEEE4")));
await t("admin bob CANNOT demote owner erin", assertFails(setRole(B, "bob", W, "erin", "viewer", "logEEEEEE5")));
await t("admin bob CANNOT remove owner erin", assertFails(setRole(B, "bob", W, "erin", "removed", "logEEEEEE6")));
await t("admin bob CANNOT delete owner erin's member doc", assertFails(B.doc(`workspaces/${W}/members/erin`).delete()));
await t("admin bob CANNOT delete founder alice's member doc", assertFails(B.doc(`workspaces/${W}/members/alice`).delete()));
await t("admin bob CANNOT demote fellow admin dave", assertFails(setRole(B, "bob", W, "dave", "analyst", "logDDDDDD4")));
await t("owner alice demotes admin dave to analyst", assertSucceeds(setRole(A, "alice", W, "dave", "analyst", "logDDDDDD5")));
await t("admin bob manages analyst dave -> viewer", assertSucceeds(setRole(B, "bob", W, "dave", "viewer", "logDDDDDD6")));
await t("admin bob re-adds removed carol as responder", assertSucceeds(setRole(B, "bob", W, "carol", "responder", "logCCCCCC4")));
await t("co-owner erin CANNOT demote founder alice", assertFails(setRole(E, "erin", W, "alice", "admin", "logAAAAAA3")));
await t("co-owner erin CANNOT remove founder alice", assertFails(setRole(E, "erin", W, "alice", "removed", "logAAAAAA4")));
await t("co-owner erin may demote admin bob", assertSucceeds(setRole(E, "erin", W, "bob", "analyst", "logBBBBBB3")));
await t("founder alice demotes co-owner erin to admin", assertSucceeds(setRole(A, "alice", W, "erin", "admin", "logEEEEEE7")));
await t("founder alice is still owner", assertSucceeds(roleIs(A, "alice", "owner")));
await t("erin is now admin", assertSucceeds(roleIs(A, "erin", "admin")));

console.log(`\n${pass} passed, ${fail} failed`);
await env.cleanup();
process.exit(fail ? 1 : 0);
