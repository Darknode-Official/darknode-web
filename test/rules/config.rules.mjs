// Firestore rules tests for shared workspace settings (firebase/firestore.rules:
// workspaces/{wid}/config/{name} and users/{uid}/config/{name}, core/ws-config.js). Not
// part of `npm test`: they need Java and the Firestore emulator. Run from a folder that
// has @firebase/rules-unit-testing@4 and firebase@11 installed:
//   RULES=<repo>/firebase/firestore.rules firebase emulators:exec --only firestore \
//     --project demo-ws "node config.rules.mjs"
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
await env.clearFirestore();
const as = (uid) => env.authenticatedContext(uid).firestore();
let pass = 0, fail = 0;
const t = async (name, p) => { try { await p; pass++; console.log("  ok  ", name); } catch (e) { fail++; console.log("  FAIL", name, "-", e.message.split("\n")[0]); } };

const found = (db, wid, uid) => {
  const b = db.batch(), log = "log" + wid;
  b.set(db.doc(`workspaces/${wid}`), { name: "Blue Team", createdBy: uid, createdAt: ts() });
  b.set(db.doc(`workspaces/${wid}/members/${uid}`), { uid, role: "owner", by: uid, ts: ts(), logId: log });
  b.set(db.doc(`workspaces/${wid}/memberLog/${log}`), { uid, role: "owner", by: uid, ts: ts() });
  return b.commit();
};
const setRole = (db, by, wid, uid, role, log) => {
  const b = db.batch();
  b.set(db.doc(`workspaces/${wid}/members/${uid}`), { uid, role, by, ts: ts(), logId: log });
  b.set(db.doc(`workspaces/${wid}/memberLog/${log}`), { uid, role, by, ts: ts() });
  return b.commit();
};
const sla = { critical: 15, high: 30, medium: 90, low: 180, info: null, kev: 7 };
const put = (db, path, by, extra = {}) => db.doc(path).set({ value: sla, by, ts: ts(), ...extra });

const A = as("alice"), B = as("bob"), C = as("carol"), V = as("vic"), E = as("erin");
const W = "cfgTeam1234";
const P = `workspaces/${W}/config/sla`;

await t("alice founds the workspace", assertSucceeds(found(A, W, "alice")));
await t("owner adds bob as admin", assertSucceeds(setRole(A, "alice", W, "bob", "admin", "logCfgBob1")));
await t("owner adds carol as analyst", assertSucceeds(setRole(A, "alice", W, "carol", "analyst", "logCfgCar1")));
await t("owner adds vic as viewer", assertSucceeds(setRole(A, "alice", W, "vic", "viewer", "logCfgVic1")));

// Team config: managers write, members read.
await t("owner writes the SLA policy", assertSucceeds(put(A, P, "alice")));
await t("admin updates the SLA policy", assertSucceeds(put(B, P, "bob")));
await t("analyst cannot write config", assertFails(put(C, P, "carol")));
await t("viewer cannot write config", assertFails(put(V, P, "vic")));
await t("non-member cannot write config", assertFails(put(E, P, "erin")));
await t("analyst reads config", assertSucceeds(C.doc(P).get()));
await t("viewer reads config", assertSucceeds(V.doc(P).get()));
await t("non-member cannot read config", assertFails(E.doc(P).get()));
await t("forged by is refused", assertFails(put(A, P, "bob")));
await t("client-chosen ts is refused", assertFails(A.doc(P).set({ value: sla, by: "alice", ts: new Date(0) })));
await t("extra keys are refused", assertFails(put(A, P, "alice", { note: "x" })));
await t("missing ts is refused", assertFails(A.doc(P).set({ value: sla, by: "alice" })));
await t("non-map value is refused", assertFails(A.doc(P).set({ value: "fast", by: "alice", ts: ts() })));
await t("list value is refused", assertFails(A.doc(P).set({ value: [1, 2], by: "alice", ts: ts() })));
await t("bad config name is refused", assertFails(put(A, `workspaces/${W}/config/SLA!`, "alice")));
await t("over-long config name is refused", assertFails(put(A, `workspaces/${W}/config/${"a".repeat(41)}`, "alice")));
await t("team config cannot be deleted", assertFails(A.doc(P).delete()));
await t("owner removes bob", assertSucceeds(setRole(A, "alice", W, "bob", "removed", "logCfgBob2")));
await t("removed admin cannot write config", assertFails(put(B, P, "bob")));
await t("removed admin cannot read config", assertFails(B.doc(P).get()));

// Personal config: only the user.
const Q = "users/alice/config/sla";
await t("user writes personal config", assertSucceeds(put(A, Q, "alice")));
await t("user reads personal config", assertSucceeds(A.doc(Q).get()));
await t("another user cannot read personal config", assertFails(C.doc(Q).get()));
await t("another user cannot write personal config", assertFails(put(C, Q, "carol")));
await t("personal forged by is refused", assertFails(put(A, Q, "carol")));
await t("personal extra keys are refused", assertFails(put(A, Q, "alice", { x: 1 })));
await t("personal non-map value is refused", assertFails(A.doc(Q).set({ value: 3, by: "alice", ts: ts() })));
await t("personal bad name is refused", assertFails(put(A, "users/alice/config/Bad Name", "alice")));
await t("signed-out cannot read personal config", assertFails(env.unauthenticatedContext().firestore().doc(Q).get()));
await t("user deletes personal config", assertSucceeds(A.doc(Q).delete()));

console.log(`\n${pass} passed, ${fail} failed`);
await env.cleanup();
process.exit(fail ? 1 : 0);
