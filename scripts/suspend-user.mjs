#!/usr/bin/env node
// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Suspend (or restore) a Darknode account for real.
//
// The Admin panel's ban list is only checked in the browser at sign-in, so a
// banned user who skips that script keeps working against Firestore and the
// Worker. This script enforces the suspension server-side:
//   - disables the Firebase Auth account, so no new ID token can be minted;
//   - revokes refresh tokens, so existing sessions die at their next refresh
//     (at most ~1 hour, which is when the current ID token expires);
//   - adds the email to settings/whitelist.banned, so the UI shows the notice.
//
// Auth: GOOGLE_APPLICATION_CREDENTIALS must point at a service-account JSON for
// sentinel-b4194 (never commit it), exactly as for set-admin.mjs.
//
//   node scripts/suspend-user.mjs user@example.com            # suspend
//   node scripts/suspend-user.mjs user@example.com --restore  # restore

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(__dirname, "..", "functions", "package.json"));
const { initializeApp, applicationDefault } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

const PROJECT_ID = "sentinel-b4194";

async function main() {
  const args = process.argv.slice(2);
  const restore = args.includes("--restore");
  const email = (args.find((a) => !a.startsWith("--")) || "").trim().toLowerCase();
  if (!email) { console.error("usage: node scripts/suspend-user.mjs <email> [--restore]"); process.exit(1); }
  if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) { console.error("error: set GOOGLE_APPLICATION_CREDENTIALS to a service-account JSON first."); process.exit(1); }

  initializeApp({ credential: applicationDefault(), projectId: PROJECT_ID });
  const auth = getAuth();
  const db = getFirestore();

  const user = await auth.getUserByEmail(email).catch((e) => { console.error(`error: no account for ${email} (${e.code || e.message}).`); process.exit(1); });
  if (!restore && user.customClaims && user.customClaims.admin === true) { console.error("error: refusing to suspend an admin account; revoke admin first."); process.exit(1); }

  await auth.updateUser(user.uid, { disabled: !restore });
  if (!restore) await auth.revokeRefreshTokens(user.uid);
  await db.collection("settings").doc("whitelist").set(
    { banned: restore ? FieldValue.arrayRemove(email) : FieldValue.arrayUnion(email) },
    { merge: true },
  );

  console.log(restore
    ? `restored ${email} (uid ${user.uid}); they can sign in again.`
    : `suspended ${email} (uid ${user.uid}): account disabled, sessions revoked (fully cut off within ~1 hour).`);
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
