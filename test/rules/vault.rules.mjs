// Firestore rules tests for VAULT team vaults (firebase/firestore.rules). Not part of
// `npm test`: they need Java and the Firestore emulator. Run from a folder that has
// @firebase/rules-unit-testing@4 and firebase@11 installed:
//   RULES=<repo>/firebase/firestore.rules firebase emulators:exec --only firestore \
//     --project demo-vault "node vault.rules.mjs"
// The emulator must listen on 127.0.0.1:8181 (8080 is reserved locally).

import { readFileSync } from "node:fs";
import { initializeTestEnvironment, assertSucceeds, assertFails } from "@firebase/rules-unit-testing";
import firebase from "firebase/compat/app";
import "firebase/compat/firestore";

const ts = () => firebase.firestore.FieldValue.serverTimestamp();
const env = await initializeTestEnvironment({
  projectId: "demo-vault",
  firestore: { rules: readFileSync(process.env.RULES, "utf8"), host: "127.0.0.1", port: 8181 },
});
const as = (uid) => env.authenticatedContext(uid).firestore();
let pass = 0, fail = 0;
const t = async (name, p) => { try { await p; pass++; console.log("  ok  ", name); } catch (e) { fail++; console.log("  FAIL", name, "-", e.message.split("\n")[0]); } };

const found = (db, vid, uid, { log = "log" + vid, createdBy = uid, role = "owner", skipLog = false } = {}) => {
  const b = db.batch();
  b.set(db.doc(`vaults/${vid}`), { name: "Treasury", createdBy, createdAt: ts() });
  b.set(db.doc(`vaults/${vid}/members/${uid}`), { uid, role, by: uid, ts: ts(), logId: log });
  if (!skipLog) b.set(db.doc(`vaults/${vid}/memberLog/${log}`), { uid, role, by: uid, ts: ts() });
  return b.commit();
};
const setRole = (db, by, vid, uid, role, log, { skipLog = false } = {}) => {
  const b = db.batch();
  b.set(db.doc(`vaults/${vid}/members/${uid}`), { uid, role, by, ts: ts(), logId: log });
  if (!skipLog) b.set(db.doc(`vaults/${vid}/memberLog/${log}`), { uid, role, by, ts: ts() });
  return b.commit();
};

const A = as("alice"), B = as("bob"), C = as("carol");
const V = "vaultAAAA1";

await t("founding without a log entry is refused", assertFails(found(A, V, "alice", { skipLog: true })));
await t("founding a vault in someone else's name is refused", assertFails(found(B, V, "bob", { createdBy: "alice" })));
await t("founding as a non-owner role is refused", assertFails(found(A, V, "alice", { role: "admin" })));
await t("alice founds the vault", assertSucceeds(found(A, V, "alice")));
await t("carol cannot re-found an existing vault", assertFails(found(C, V, "carol", { log: "logCCCCCCC" })));
await t("bob cannot add himself", assertFails(setRole(B, "bob", V, "bob", "owner", "logBBBBBB1")));
await t("owner adds bob as approver with a log entry", assertSucceeds(setRole(A, "alice", V, "bob", "approver", "logBBBBBB2")));
await t("owner change without a log entry is refused", assertFails(setRole(A, "alice", V, "bob", "admin", "logBBBBBB3", { skipLog: true })));
await t("reusing an old log entry is refused", assertFails(setRole(A, "alice", V, "bob", "approver", "logBBBBBB2", { skipLog: true })));
await t("owner cannot change their own role", assertFails(setRole(A, "alice", V, "alice", "admin", "logAAAAAA2")));
await t("an approver cannot add members", assertFails(setRole(B, "bob", V, "carol", "approver", "logCCCCCC1")));
await t("member log is append-only (update)", assertFails(A.doc(`vaults/${V}/memberLog/logBBBBBB2`).update({ role: "owner" })));
await t("member log is append-only (delete)", assertFails(A.doc(`vaults/${V}/memberLog/logBBBBBB2`).delete()));
await t("member docs cannot be deleted", assertFails(A.doc(`vaults/${V}/members/bob`).delete()));
await t("vault cannot be deleted", assertFails(A.doc(`vaults/${V}`).delete()));
await t("owner may rename only", assertSucceeds(A.doc(`vaults/${V}`).update({ name: "Ops treasury" })));
await t("createdBy cannot be changed", assertFails(A.doc(`vaults/${V}`).update({ createdBy: "carol" })));
await t("member bob reads the vault", assertSucceeds(B.doc(`vaults/${V}`).get()));
await t("member bob reads members", assertSucceeds(B.collection(`vaults/${V}/members`).get()));
await t("member bob reads the member log", assertSucceeds(B.collection(`vaults/${V}/memberLog`).get()));
await t("non-member carol cannot read the vault", assertFails(C.doc(`vaults/${V}`).get()));
await t("non-member carol cannot read members", assertFails(C.doc(`vaults/${V}/members/bob`).get()));
await t("carol may read her own (absent) member doc", assertSucceeds(C.doc(`vaults/${V}/members/carol`).get()));
await t("bob finds his vaults by collection group", assertSucceeds(B.collectionGroup("members").where("uid", "==", "bob").get()));
await t("bob cannot list other people's memberships", assertFails(B.collectionGroup("members").where("uid", "==", "alice").get()));
await t("owner removes bob", assertSucceeds(setRole(A, "alice", V, "bob", "removed", "logBBBBBB4")));
await t("removed bob can no longer read the vault", assertFails(B.doc(`vaults/${V}`).get()));
await t("removed bob still sees his own member doc (for the worker)", assertSucceeds(B.doc(`vaults/${V}/members/bob`).get()));
await t("owner makes carol a second owner", assertSucceeds(setRole(A, "alice", V, "carol", "owner", "logCCCCCC2")));
await t("an unknown role is refused", assertFails(setRole(A, "alice", V, "dave", "god", "logDDDDDD1")));
await t("a forged by field is refused", assertFails(setRole(A, "carol", V, "dave", "viewer", "logDDDDDD2")));

console.log(`\n${pass} passed, ${fail} failed`);
await env.cleanup();
process.exit(fail ? 1 : 0);
