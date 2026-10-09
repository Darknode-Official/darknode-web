#!/usr/bin/env node
// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Publish a Beta Lab demo tool LIVE — no hosting redeploy.
//
// The Beta Lab (public/js/beta-lab.js) renders a live gallery from the Firestore
// `demoTools` collection (owner-writable, world-readable). Writing a doc here makes
// the demo appear in every open Beta Lab instantly, because the client subscribes
// with onSnapshot. So you can put a new prototype in front of users without a
// `firebase deploy`. The flagship from-scratch game synthesizer is built into the
// client and always present; THIS publishes additional demos.
//
// A demo doc:
//   { id?, name, tagline, description?, status, kind, html?, htmlFile?, url?, author?, order? }
//   kind: "html"    -> self-contained HTML, run in a sandboxed <iframe> (use html or htmlFile)
//         "concept" -> a described idea, optional `url` to learn more (no runnable code)
//   status: "concept" | "prototype" | "live-demo"   (shown as a tag)
//   order:  sort key ascending (default 100)
//
// Auth (same as set-admin.mjs): a service-account JSON for sentinel-b4194.
//   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/serviceAccount.json
//
// Usage:
//   node scripts/publish-demo.mjs <demo.json>      # upsert one demo (JSON file)
//   node scripts/publish-demo.mjs --html <file.html> --name "My Demo" --status prototype [--order 50] [--author Name]
//   node scripts/publish-demo.mjs --list           # list published demos
//   node scripts/publish-demo.mjs --rm <id>        # remove a demo
//
// HTML demos run sandboxed (allow-scripts, no same-origin), but they are STILL
// code you are putting in front of users — only publish HTML you wrote/reviewed.

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(__dirname, "..", "functions", "package.json"));
const admin = require("firebase-admin");

const PROJECT_ID = "sentinel-b4194";
const slug = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "demo";

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) { const k = a.slice(2); const v = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : true; out[k] = v; }
    else out._.push(a);
  }
  return out;
}

function demoFromArgs(args) {
  let demo;
  if (args._[0]) {
    demo = JSON.parse(readFileSync(args._[0], "utf8"));
  } else {
    demo = {
      name: args.name, tagline: args.tagline || "", description: args.description || "",
      status: args.status || "prototype", kind: args.html ? "html" : (args.url ? "concept" : "concept"),
      url: args.url, author: args.author, order: args.order ? Number(args.order) : undefined,
      htmlFile: args.html && args.html !== true ? args.html : undefined,
      id: args.id,
    };
  }
  if (demo.htmlFile) { demo.html = readFileSync(demo.htmlFile, "utf8"); delete demo.htmlFile; }
  if (!demo.name) throw new Error("a demo needs a name (--name or JSON name).");
  if (demo.kind === "html" && !demo.html) throw new Error("kind 'html' needs html or htmlFile.");
  if (typeof demo.html === "string" && demo.html.length > 900000) throw new Error("html is too large (>900KB); keep demos lean.");
  // normalise
  const doc = {
    name: String(demo.name).slice(0, 120),
    tagline: String(demo.tagline || "").slice(0, 240),
    description: String(demo.description || "").slice(0, 2000),
    status: ["concept", "prototype", "live-demo"].includes(demo.status) ? demo.status : "prototype",
    kind: ["html", "concept"].includes(demo.kind) ? demo.kind : "concept",
    order: Number.isFinite(demo.order) ? demo.order : 100,
    author: demo.author ? String(demo.author).slice(0, 80) : null,
    url: demo.url ? String(demo.url).slice(0, 2048) : null,
    html: demo.kind === "html" ? String(demo.html) : null,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  };
  const id = demo.id ? slug(demo.id) : slug(demo.name);
  return { id, doc };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    console.error("error: set GOOGLE_APPLICATION_CREDENTIALS to a service-account JSON first.");
    process.exit(1);
  }
  admin.initializeApp({ credential: admin.credential.applicationDefault(), projectId: PROJECT_ID });
  const db = admin.firestore();
  const col = db.collection("demoTools");

  if (args.list) {
    const snap = await col.orderBy("order", "asc").get();
    if (snap.empty) { console.log("(no demos published)"); process.exit(0); }
    snap.forEach((d) => { const x = d.data(); console.log(`${d.id}  [${x.status}/${x.kind}]  order=${x.order}  ${x.name}`); });
    process.exit(0);
  }
  if (args.rm) {
    await col.doc(slug(args.rm)).delete();
    console.log(`removed demo '${slug(args.rm)}'.`);
    process.exit(0);
  }

  const { id, doc } = demoFromArgs(args);
  await col.doc(id).set(doc, { merge: true });
  console.log(`published demo '${id}' (${doc.status}/${doc.kind}) — it is live now, no deploy needed.`);
  process.exit(0);
}

main().catch((e) => { console.error(e.message || e); process.exit(1); });
