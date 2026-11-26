// Firebase Hosting rewrites, generated from the routers' own registries so that the HTTP
// status matches what the page shows:
//   - each public page (js/site-meta.js PAGES) is served from dist/pages/<slug>.html, which
//     carries that page's title, description and canonical (scripts/build.mjs writes them);
//   - every path the signed-in app opens (js/deck/routes.js isAppPath with the same section
//     ids auth.js appSecs() uses) gets the app shell, index.html;
//   - anything else matches no rewrite, so Hosting answers 404 with dist/404.html (the same
//     app, which shows "Page not found").
// firebase.json holds the result; `node scripts/sync-hosting-routes.mjs` rewrites it, and
// test/build/hosting-routes.test.mjs fails when it drifts (a new Deck tool or page).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseBlurbs, parseConsoleNavIds } from "./deck-registry.mjs";
import { SCENES, SCENE_PATH, isAppPath } from "../../public/js/deck/routes.js";
import { PAGES } from "../../public/js/site-meta.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const read = (f) => readFileSync(join(ROOT, f), "utf8");

// The same three sources auth.js appSecs() reads: console catalog, retired ids, the Deck's own tools.
export function appSecs() {
  const cnav = read("public/js/console-nav.js"), auth = read("public/js/auth.js");
  const retired = [...(cnav.match(/export const RETIRED = new Set\(\[([^\]]*)/) || [, ""])[1].matchAll(/"([\w-]+)"/g)].map((m) => m[1]);
  return new Set([...parseConsoleNavIds(cnav), ...retired, ...parseBlurbs(auth).keys()]);
}

// One path segment per app page: section ids (camelCase ids also by their hyphenated path)
// and Deck scene paths, kept only where isAppPath itself says the app opens them.
export function appSegments(secs = appSecs()) {
  const out = new Set();
  for (const s of secs) {
    if (!/^[A-Za-z0-9-]+$/.test(s)) throw new Error("unexpected section id: " + s);
    out.add(s);
    if (/[A-Z]/.test(s)) out.add(s.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase()));
  }
  for (const k of Object.keys(SCENES)) { out.add(k); if (SCENE_PATH[k]) out.add(SCENE_PATH[k]); }
  return [...out].filter((p) => !p.startsWith("tool-") && isAppPath("/" + p, secs)).sort();
}

// RE2 (Firebase Hosting) pattern for every app path, with or without the old /console prefix
// and a trailing slash. Mini-tools (tool-<id>) match by shape; the app says "Page not found"
// for an id that no longer exists.
export function appPathRegex(segs = appSegments()) {
  return "^/(?:console(?:/|$))?(?:(?:area|personal|enterprise)/[\\w-]+|check/[^/]+|tool-[a-z0-9-]+|" + segs.join("|") + ")?/?$";
}

export function hostingRewrites() {
  return [
    { source: "/api/chat", function: { functionId: "chat", region: "us-central1" } },
    { source: "/version", destination: "/version.txt" },
    ...Object.entries(PAGES).map(([path, p]) => ({ regex: "^" + path + "/?$", destination: "/pages/" + p.slug + ".html" })),
    { regex: appPathRegex(), destination: "/index.html" },
  ];
}

// The rewrites block as firebase.json writes it (one rule per line, 6-space indent).
export function rewritesBlock(rules = hostingRewrites()) {
  const one = (r) => "{ " + Object.entries(r).map(([k, v]) => JSON.stringify(k) + ": " + (typeof v === "object" ? "{ " + Object.entries(v).map(([a, b]) => JSON.stringify(a) + ": " + JSON.stringify(b)).join(", ") + " }" : JSON.stringify(v))).join(", ") + " }";
  return '"rewrites": [\n' + rules.map((r) => "        " + one(r)).join(",\n") + "\n      ]";
}

// firebase.json text with every hosting site's rewrites replaced by the generated block.
export function syncFirebaseJson(text) {
  const re = /"rewrites": \[\n[\s\S]*?\n {6}\]/g;
  const n = (text.match(re) || []).length;
  if (!n) throw new Error("firebase.json: no rewrites block found");
  return text.replace(re, () => rewritesBlock());
}
