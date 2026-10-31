#!/usr/bin/env node
// Release build (architecture plan, Phase 0): public/ -> dist/ with content-derived
// cache-busters, so a release never needs a hand-bumped ?v= string or SW version.
//
// - Every local specifier that already carries ?v= (imports, import(), engineUrl,
//   modulepreload, <script src>) gets ?v=<hash>. The hash covers the target file
//   AND the versions of everything it imports, so changing a leaf module re-versions
//   every importer up the chain (import cycles are hashed together as one group).
//   Specifiers without ?v= are left alone: some modules are deliberately unversioned
//   singletons, and adding a query would create a second module instance.
// - sw.js gets CACHE = 'darknode-<hash of the whole build>', so any change to any
//   shipped file rotates the service-worker cache, and STATIC precaches the exact
//   versioned scripts/styles index.html loads first.
//
// Source files keep their old ?v= values, so serving public/ directly still works in
// development. Usage: node scripts/build.mjs [--out dist] [--check]
import { cpSync, rmSync, readFileSync, writeFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname, resolve, relative, sep, posix } from "node:path";
import { fileURLToPath } from "node:url";

const SPEC = /(["'`])((?:\.{1,2}\/|\/)[^"'`?\s$]+?\.(?:m?js|css|json|txt|svg|png|ico|webp|jpe?g|gif|woff2?))\?v=[A-Za-z0-9._-]+(\\?)\1/g;
const TEXT = /\.(?:m?js|html)$/;
// A module that builds specifiers at runtime (`import("./x.js" + V)`) declares its
// buster once as `const V = "?v=..."`; it gets the whole-build hash and depends on it.
const DYN_V = /const V = (["'])\?v=[A-Za-z0-9._-]+\1;/;
const SKIP = [/\.(?:exe|deb|AppImage|dmg)$/, /(^|\/)\.git(\/|$)/, /(^|\/)node_modules(\/|$)/, /^firebase\//];

const sha = (s) => createHash("sha256").update(s).digest("hex");

function walk(dir, root = dir, out = []) {
  for (const n of readdirSync(dir)) {
    const f = join(dir, n), rel = relative(root, f).split(sep).join("/");
    if (SKIP.some((r) => r.test(rel))) continue;
    if (statSync(f).isDirectory()) walk(f, root, out); else out.push(rel);
  }
  return out;
}

// A specifier inside `from` (a root-relative posix path) -> root-relative target path.
export function resolveSpec(from, spec) {
  return spec.startsWith("/") ? spec.slice(1) : posix.normalize(posix.join(posix.dirname(from), spec));
}

// files: Map<relPath, text> for every text file; exists(rel) for any shipped file.
// Returns Map<relPath, version> for every referenced target.
// salt: Map<relPath, string> mixed into a file's own hash (the build hash for DYN_V files).
export function computeVersions(files, exists, readBytes, salt = new Map()) {
  const deps = new Map();
  for (const [f, text] of files) {
    const d = new Set();
    for (const m of text.matchAll(SPEC)) { const t = resolveSpec(f, m[2]); if (exists(t)) d.add(t); }
    deps.set(f, [...d].sort());
  }
  const raw = new Map();
  const rawHash = (f) => { if (!raw.has(f)) raw.set(f, sha((files.has(f) ? files.get(f) : readBytes(f)) + (salt.get(f) || ""))); return raw.get(f); };
  // Tarjan SCC (iterative), then hash components in reverse topological order.
  const index = new Map(), low = new Map(), onStack = new Set(), stack = [], comps = [];
  let i = 0;
  const nodes = [...new Set([...deps.keys(), ...[...deps.values()].flat()])].sort();
  for (const start of nodes) {
    if (index.has(start)) continue;
    const work = [[start, 0]];
    index.set(start, i); low.set(start, i); i++; stack.push(start); onStack.add(start);
    while (work.length) {
      const top = work[work.length - 1], [v, k] = top, ds = deps.get(v) || [];
      if (k < ds.length) {
        top[1]++;
        const w = ds[k];
        if (!index.has(w)) { index.set(w, i); low.set(w, i); i++; stack.push(w); onStack.add(w); work.push([w, 0]); }
        else if (onStack.has(w)) low.set(v, Math.min(low.get(v), index.get(w)));
      } else {
        work.pop();
        if (work.length) { const u = work[work.length - 1][0]; low.set(u, Math.min(low.get(u), low.get(v))); }
        if (low.get(v) === index.get(v)) { const c = []; let w; do { w = stack.pop(); onStack.delete(w); c.push(w); } while (w !== v); comps.push(c.sort()); }
      }
    }
  }
  // Tarjan emits components dependencies-first, so every external dep is versioned already.
  const version = new Map();
  for (const c of comps) {
    const members = new Set(c);
    const ext = [...new Set(c.flatMap((f) => deps.get(f) || []))].filter((d) => !members.has(d)).sort();
    const h = sha(c.map((f) => f + ":" + rawHash(f)).join("|") + "#" + ext.map((d) => d + ":" + version.get(d)).join("|"));
    for (const f of c) version.set(f, sha(f + h).slice(0, 10));
  }
  return version;
}

export function rewrite(from, text, version, buildHash = "") {
  if (buildHash) text = text.replace(DYN_V, (all, q) => "const V = " + q + "?v=" + buildHash.slice(0, 10) + q + ";");
  return text.replace(SPEC, (all, q, spec, esc) => {
    const v = version.get(resolveSpec(from, spec));
    return v ? q + spec + "?v=" + v + esc + q : all;
  });
}

export function build({ src, out, check = false }) {
  const list = walk(src);
  const files = new Map(list.filter((f) => TEXT.test(f)).map((f) => [f, readFileSync(join(src, f), "utf8")]));
  const shipped = new Set(list);
  // The build hash covers every shipped byte of the source, so any change rotates it.
  const buildHash = sha(list.sort().map((f) => f + ":" + (files.has(f) ? sha(files.get(f)) : sha(readFileSync(join(src, f))))).join("|")).slice(0, 12);
  const salt = new Map([...files].filter(([, t]) => DYN_V.test(t)).map(([f]) => [f, buildHash]));
  const version = computeVersions(files, (f) => shipped.has(f), (f) => readFileSync(join(src, f)), salt);
  const unresolved = [];
  for (const [f, text] of files) for (const m of text.matchAll(SPEC)) if (!shipped.has(resolveSpec(f, m[2]))) unresolved.push(f + " -> " + m[2]);
  const outText = new Map([...files].map(([f, t]) => [f, rewrite(f, t, version, salt.has(f) ? buildHash : "")]));

  // Service worker: cache name from the whole build; precache what index.html loads first.
  if (outText.has("sw.js") && outText.has("index.html")) {
    const first = [...outText.get("index.html").matchAll(/<(?:script[^>]*\bsrc|link[^>]*\bhref)="(\/[^"]+\?v=[0-9a-f]{10})"/g)].map((m) => m[1]);
    let sw = outText.get("sw.js");
    const cacheRe = /const CACHE = '[^']*';/;
    if (!cacheRe.test(sw)) throw new Error("sw.js: CACHE declaration not found");
    sw = sw.replace(cacheRe, "const CACHE = 'darknode-" + buildHash + "';");
    if (first.length) sw = sw.replace(/const STATIC = \[\n/, (m) => m + [...new Set(first)].map((u) => "  '" + u + "',\n").join(""));
    outText.set("sw.js", sw);
  }
  if (check) return { files: list.length, versioned: version.size, unresolved, buildHash };

  rmSync(out, { recursive: true, force: true });
  cpSync(src, out, { recursive: true, filter: (p) => { const rel = relative(src, p).split(sep).join("/"); return !rel || !SKIP.some((r) => r.test(rel)); } });
  for (const [f, t] of outText) if (t !== files.get(f)) writeFileSync(join(out, f), t);
  writeFileSync(join(out, "build.json"), JSON.stringify({ build: buildHash, at: new Date().toISOString(), files: list.length }) + "\n");
  return { files: list.length, versioned: version.size, unresolved, buildHash };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const a = process.argv.slice(2);
  const out = resolve(root, a.includes("--out") ? a[a.indexOf("--out") + 1] : "dist");
  const r = build({ src: join(root, "public"), out, check: a.includes("--check") });
  for (const u of r.unresolved) console.error("unresolved: " + u);
  console.log(`build ${r.buildHash}: ${r.files} files, ${r.versioned} versioned targets${a.includes("--check") ? " (check only)" : " -> " + relative(root, out)}`);
  if (r.unresolved.length) process.exit(1);
}
