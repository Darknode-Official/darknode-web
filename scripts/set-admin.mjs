#!/usr/bin/env node
// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Grant (or revoke) the single super-admin to a Darknode account.
//
// This replaces the old hardcoded OWNER_EMAIL that used to live in the shipped
// client bundle and the Firestore rules. Admin is now a Firebase custom claim
// (`admin: true`) carried in the user's signed ID token — the Security Rules
// check `request.auth.token.admin`, and the client reads it from the token (it
// cannot be forged client-side). We also stamp `admin: true` onto the owner's
// own users/{uid} doc so the owner-only admin panel can still badge that row.
//
// RUN THIS ONCE for the owner account BEFORE deploying the new firestore.rules,
// otherwise the owner temporarily loses admin access until the claim is set.
//
// Auth: point GOOGLE_APPLICATION_CREDENTIALS at a service-account JSON for the
// sentinel-b4194 project (Firebase console -> Project settings -> Service
// accounts -> Generate new private key). Never commit that file.
//
//   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/serviceAccount.json
//   node scripts/set-admin.mjs owner@example.com          # grant
//   node scripts/set-admin.mjs owner@example.com --revoke # revoke
//
// The claim takes effect on the user's next token refresh (sign out / in, or
// after ~1h). To force it immediately the user can re-authenticate.

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// firebase-admin is a dependency of ./functions, so resolve it from there.
const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(__dirname, "..", "functions", "package.json"));
const admin = require("firebase-admin");

const PROJECT_ID = "sentinel-b4194";

async function main() {
  const args = process.argv.slice(2);
  const revoke = args.includes("--revoke");
  const email = args.find((a) => !a.startsWith("--"));
  if (!email) {
    console.error("usage: node scripts/set-admin.mjs <email> [--revoke]");
    process.exit(1);
  }
  if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    console.error("error: set GOOGLE_APPLICATION_CREDENTIALS to a service-account JSON first.");
    process.exit(1);
  }

  admin.initializeApp({
    credential: admin.credential.applicationDefault(),
    projectId: PROJECT_ID,
  });

  const auth = admin.auth();
  const db = admin.firestore();

  const user = await auth.getUserByEmail(email).catch((e) => {
    console.error(`error: no account for ${email} (${e.code || e.message}).`);
    process.exit(1);
  });

  const existing = user.customClaims || {};
  const claims = { ...existing };
  if (revoke) delete claims.admin;
  else claims.admin = true;

  await auth.setCustomUserClaims(user.uid, claims);

  // Mirror onto the user doc so the owner-only admin UI can badge/exclude the row.
  // (The access decision itself relies on the token claim, not this field.)
  await db.collection("users").doc(user.uid).set(
    { admin: revoke ? admin.firestore.FieldValue.delete() : true },
    { merge: true },
  );

  console.log(`${revoke ? "revoked" : "granted"} admin for ${email} (uid ${user.uid}).`);
  console.log("Takes effect on the user's next token refresh (sign out/in to force it).");
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
