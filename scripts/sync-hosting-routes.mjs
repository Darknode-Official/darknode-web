#!/usr/bin/env node
// Regenerate firebase.json's Hosting rewrites from the app's route registries and the public
// page table (see scripts/lib/hosting-routes.mjs). Run it after adding a Deck tool, a console
// page or a public page; `npm test` fails until you do.  Usage: node scripts/sync-hosting-routes.mjs [--check]
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { syncFirebaseJson } from "./lib/hosting-routes.mjs";

const file = join(dirname(fileURLToPath(import.meta.url)), "..", "firebase.json");
const before = readFileSync(file, "utf8");
const after = syncFirebaseJson(before);
JSON.parse(after); // still valid JSON
if (process.argv.includes("--check")) {
  if (after !== before) { console.error("firebase.json rewrites are out of date: run node scripts/sync-hosting-routes.mjs"); process.exit(1); }
  console.log("firebase.json rewrites are up to date");
} else if (after === before) console.log("firebase.json rewrites already up to date");
else { writeFileSync(file, after); console.log("firebase.json rewrites updated"); }
