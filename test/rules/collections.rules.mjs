// Firestore rules tests for ip_reports, deletionRequests and pairings
// (firebase/firestore.rules). Not part of `npm test`: they need Java and the Firestore
// emulator. Run the same way as workspace.rules.mjs:
//   RULES=<repo>/firebase/firestore.rules firebase emulators:exec --only firestore \
//     --project demo-ws "node collections.rules.mjs"
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
const as = (uid, email) => env.authenticatedContext(uid, email ? { email } : {}).firestore();
let pass = 0, fail = 0;
const t = async (name, p) => { try { await p; pass++; console.log("  ok  ", name); } catch (e) { fail++; console.log("  FAIL", name, "-", e.message.split("\n")[0]); } };

const A = as("alice", "alice@test.darknode.ai"), B = as("bob", "bob@test.darknode.ai");
const ADM = env.authenticatedContext("root", { email: "test@darknode.ai", admin: true }).firestore();
const ANON = env.unauthenticatedContext().firestore();

// ---- ip_reports ----
const rep = (o = {}) => ({ ip: "203.0.113.7", reporter_uid: "alice", category: "Scanner", description: "port sweep", timestamp: ts(), ...o });
await t("signed-in user files a valid IP report", assertSucceeds(A.collection("ip_reports").add(rep())));
await t("empty description is allowed", assertSucceeds(A.collection("ip_reports").add(rep({ description: "" }))));
await t("report in someone else's name is refused", assertFails(A.collection("ip_reports").add(rep({ reporter_uid: "bob" }))));
await t("extra field is refused", assertFails(A.collection("ip_reports").add(rep({ score: 10 }))));
await t("missing description is refused", assertFails(A.collection("ip_reports").add((({ description, ...r }) => r)(rep()))));
await t("non-IPv4 ip is refused", assertFails(A.collection("ip_reports").add(rep({ ip: "not-an-ip" }))));
await t("unknown category is refused", assertFails(A.collection("ip_reports").add(rep({ category: "Ransomware" }))));
await t("description over 2000 chars is refused", assertFails(A.collection("ip_reports").add(rep({ description: "x".repeat(2001) }))));
await t("client-chosen timestamp is refused", assertFails(A.collection("ip_reports").add(rep({ timestamp: 1 }))));
await t("signed-out report is refused", assertFails(ANON.collection("ip_reports").add(rep())));
await t("signed-in user reads the recent feed (limit 20)", assertSucceeds(B.collection("ip_reports").orderBy("timestamp", "desc").limit(20).get()));
await t("per-IP query (limit 50) is allowed", assertSucceeds(B.collection("ip_reports").where("ip", "==", "203.0.113.7").limit(50).get()));
await t("unbounded list is refused", assertFails(B.collection("ip_reports").get()));
await t("list over 50 is refused", assertFails(B.collection("ip_reports").limit(100).get()));
await t("signed-out read is refused", assertFails(ANON.collection("ip_reports").limit(20).get()));
const anyRep = (await env.withSecurityRulesDisabled(async (c) => (await c.firestore().collection("ip_reports").limit(1).get()).docs[0].id));
await t("reporter cannot edit a report", assertFails(A.doc(`ip_reports/${anyRep}`).update({ category: "Other" })));
await t("reporter cannot delete a report", assertFails(A.doc(`ip_reports/${anyRep}`).delete()));
await t("admin may delete a report", assertSucceeds(ADM.doc(`ip_reports/${anyRep}`).delete()));

// ---- deletionRequests ----
const del = (db, id, o = {}) => db.doc(`deletionRequests/${id}`).set({ uid: id, email: "alice@test.darknode.ai", requestedAt: ts(), ...o }, { merge: true });
await t("alice files her own deletion request", assertSucceeds(del(A, "alice")));
await t("alice may re-file (merge set)", assertSucceeds(del(A, "alice")));
await t("alice cannot file for bob", assertFails(del(A, "bob", { email: "bob@test.darknode.ai" })));
await t("uid field must match the doc id", assertFails(A.doc("deletionRequests/alice").set({ uid: "bob", email: "", requestedAt: ts() })));
await t("someone else's email is refused", assertFails(del(A, "alice", { email: "bob@test.darknode.ai" })));
await t("extra field is refused", assertFails(del(A, "alice", { reason: "x" })));
await t("client-chosen requestedAt is refused", assertFails(del(A, "alice", { requestedAt: 1 })));
await t("user with no email files with empty email", assertSucceeds(del(as("noemail"), "noemail", { email: "" })));
await t("alice reads her own request", assertSucceeds(A.doc("deletionRequests/alice").get()));
await t("bob cannot read alice's request", assertFails(B.doc("deletionRequests/alice").get()));
await t("bob cannot list requests", assertFails(B.collection("deletionRequests").get()));
await t("admin reads all requests", assertSucceeds(ADM.collection("deletionRequests").get()));
await t("alice cannot delete her request", assertFails(A.doc("deletionRequests/alice").delete()));
await t("admin clears a request", assertSucceeds(ADM.doc("deletionRequests/alice").delete()));

// ---- pairings ----
const KEY = "sk-darknode-" + "0123456789abcdef".repeat(2);
const pair = (db, code, o = {}) => db.doc(`pairings/${code}`).set({ uid: "alice", email: "alice@test.darknode.ai", name: "Alice", apiKey: KEY, createdAt: ts(), expiresAt: Date.now() + 5 * 60 * 1000, ...o });
await t("alice creates a valid pairing code", assertSucceeds(pair(A, "ABCDEFGHJKLMNPQR")));
await t("extra field is refused", assertFails(pair(A, "ABCDEFGHJKLMNPQS", { refreshToken: "x" })));
await t("malformed apiKey is refused", assertFails(pair(A, "ABCDEFGHJKLMNPQT", { apiKey: "anything" })));
await t("long-lived code (2 days) is refused", assertFails(pair(A, "ABCDEFGHJKLMNPQU", { expiresAt: Date.now() + 2 * 86400000 })));
await t("non-integer expiresAt is refused", assertFails(pair(A, "ABCDEFGHJKLMNPQV", { expiresAt: "never" })));
await t("bad code id is refused", assertFails(pair(A, "short")));
await t("code for someone else is refused", assertFails(pair(A, "ABCDEFGHJKLMNPQW", { uid: "bob" })));
await t("client-chosen createdAt is refused", assertFails(pair(A, "ABCDEFGHJKLMNPQX", { createdAt: 1 })));
await t("pairing codes cannot be read", assertFails(A.doc("pairings/ABCDEFGHJKLMNPQR").get()));
await t("bob cannot delete alice's code", assertFails(B.doc("pairings/ABCDEFGHJKLMNPQR").delete()));
await t("alice may cancel her own code", assertSucceeds(A.doc("pairings/ABCDEFGHJKLMNPQR").delete()));

// ---- users/{uid}: no self-granted privilege fields ----
await t("alice creates her own user doc", assertSucceeds(A.doc("users/alice").set({ email: "alice@test.darknode.ai", name: "Alice" })));
await t("alice may update ordinary fields", assertSucceeds(A.doc("users/alice").set({ name: "A" }, { merge: true })));
for (const f of ["status", "codeVerified", "tier", "plan", "admin"])
  await t(`alice cannot set ${f} on her own doc`, assertFails(A.doc("users/alice").set({ [f]: f === "status" ? "allowed" : true }, { merge: true })));
await t("bob cannot create a user doc with status", assertFails(B.doc("users/bob").set({ email: "bob@test.darknode.ai", status: "allowed" })));
await t("the owner may set status", assertSucceeds(ADM.doc("users/alice").set({ status: "allowed" }, { merge: true })));

console.log(`\n${pass} passed, ${fail} failed`);
await env.cleanup();
process.exit(fail ? 1 : 0);
