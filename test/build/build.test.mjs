// scripts/build.mjs: content-derived cache-busters and the generated service-worker
// cache name. The release pipeline relies on these instead of hand-bumped ?v= strings.
import { test, group, assert } from "../harness.mjs";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { computeVersions, rewrite, resolveSpec, build } from "../../scripts/build.mjs";

const V = (files) => computeVersions(new Map(Object.entries(files)), (f) => f in files, () => "");

group("build: content-derived versions", () => {
  test("resolveSpec handles absolute and relative specifiers", () => {
    assert.equal(resolveSpec("js/deck/a.js", "/js/b.js"), "js/b.js");
    assert.equal(resolveSpec("js/deck/a.js", "./c.js"), "js/deck/c.js");
    assert.equal(resolveSpec("js/deck/a.js", "../d.js"), "js/d.js");
  });
  test("a leaf change re-versions every importer up the chain and nothing else", () => {
    const base = { "a.js": 'import "./b.js?v=1";', "b.js": 'import "./c.js?v=1";', "c.js": "leaf", "d.js": "other" };
    const v1 = V(base), v2 = V({ ...base, "c.js": "leaf changed" });
    for (const f of ["a.js", "b.js", "c.js"]) assert.notEqual(v1.get(f), v2.get(f), f);
    assert.equal(v1.get("d.js"), v2.get("d.js"));
    assert.ok(/^[0-9a-f]{10}$/.test(v1.get("a.js")));
  });
  test("import cycles: a change below the cycle still reaches every member and their importers", () => {
    const base = { "top.js": 'import "./a.js?v=1";', "a.js": 'import "./b.js?v=1";', "b.js": 'import "./a.js?v=1"; import "./c.js?v=1";', "c.js": "x" };
    const v1 = V(base), v2 = V({ ...base, "c.js": "y" });
    for (const f of ["top.js", "a.js", "b.js"]) assert.notEqual(v1.get(f), v2.get(f), f);
    assert.notEqual(v1.get("a.js"), v1.get("b.js"));
  });
  test("versions are deterministic and ignore the old ?v= values", () => {
    const a = V({ "a.js": 'import "./b.js?v=old1";', "b.js": "b" }), b = V({ "a.js": 'import "./b.js?v=old2";', "b.js": "b" });
    assert.equal(a.get("b.js"), b.get("b.js"));
  });
  test("rewrite: only ?v= specifiers change; unversioned singletons and template paths stay", () => {
    const text = 'import "/js/x.js?v=1"; import "/js/sg.js"; import(`/js/${n}.js?v=1`); const s = "<img src=\\"/logo.svg?v=7\\">";';
    const out = rewrite("js/a.js", text, new Map([["js/x.js", "aaaaaaaaaa"], ["logo.svg", "bbbbbbbbbb"]]));
    assert.ok(out.includes('"/js/x.js?v=aaaaaaaaaa"') && out.includes('"/js/sg.js"') && out.includes("`/js/${n}.js?v=1`") && out.includes("/logo.svg?v=bbbbbbbbbb"), out);
  });
  test("rewrite: a runtime buster constant gets the build hash", () => {
    assert.equal(rewrite("a.js", 'const V = "?v=20261030c";', new Map(), "0123456789ab"), 'const V = "?v=0123456789";');
  });
});

group("build: end to end on a fixture tree", () => {
  const mk = (files) => {
    const root = mkdtempSync(join(tmpdir(), "dnbuild-"));
    for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(root, "public", f)), { recursive: true }); writeFileSync(join(root, "public", f), t); }
    return root;
  };
  const SW = "const CACHE = 'darknode-v1';\nconst STATIC = [\n  '/',\n];\n";
  const fixture = {
    "index.html": '<link rel="modulepreload" href="/js/app.js?v=1"><script type="module" src="/js/app.js?v=1"></script>',
    "sw.js": SW,
    "js/app.js": 'import { f } from "/js/store.js?v=a"; import { g } from "/js/firebase.js?v=20261021a"; import "./lazy.js?v=2"; const V = "?v=x"; import("./dyn.js" + V);',
    "js/lazy.js": 'import { f } from "/js/store.js?v=a";',
    "js/store.js": "export const f = 1;",
    "js/firebase.js": "export const g = 1;",
    "js/dyn.js": "export default 1;",
    "big.exe": "binary",
  };
  test("dist gets hashed busters, one version per target, generated SW cache and precache", () => {
    const root = mk(fixture);
    try {
      const r = build({ src: join(root, "public"), out: join(root, "dist") });
      assert.deepEqual(r.unresolved, []);
      const app = readFileSync(join(root, "dist/js/app.js"), "utf8"), lazy = readFileSync(join(root, "dist/js/lazy.js"), "utf8");
      const st = app.match(/store\.js\?v=([0-9a-f]{10})/)[1];
      assert.equal(lazy.match(/store\.js\?v=([0-9a-f]{10})/)[1], st); // one module instance
      assert.ok(app.includes('"/js/firebase.js?v=20261021a"')); // pinned
      assert.ok(app.includes('const V = "?v=' + r.buildHash.slice(0, 10) + '"'));
      const sw = readFileSync(join(root, "dist/sw.js"), "utf8");
      assert.ok(sw.includes("const CACHE = 'darknode-" + r.buildHash + "';"));
      assert.ok(/const STATIC = \[\n  '\/js\/app\.js\?v=[0-9a-f]{10}',\n  '\/',/.test(sw), sw);
      assert.equal(readFileSync(join(root, "public/js/app.js"), "utf8"), fixture["js/app.js"]); // source untouched
      let exe = true; try { readFileSync(join(root, "dist/big.exe")); } catch (_) { exe = false; }
      assert.equal(exe, false);
      assert.equal(JSON.parse(readFileSync(join(root, "dist/build.json"), "utf8")).build, r.buildHash);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
  test("changing a dynamically imported module rotates the build hash and the importer's version", () => {
    const a = mk(fixture), b = mk({ ...fixture, "js/dyn.js": "export default 2;" });
    try {
      const ra = build({ src: join(a, "public"), out: join(a, "dist") }), rb = build({ src: join(b, "public"), out: join(b, "dist") });
      assert.notEqual(ra.buildHash, rb.buildHash);
      const ver = (root) => readFileSync(join(root, "dist/index.html"), "utf8").match(/app\.js\?v=([0-9a-f]{10})/)[1];
      assert.notEqual(ver(a), ver(b));
    } finally { rmSync(a, { recursive: true, force: true }); rmSync(b, { recursive: true, force: true }); }
  });
  test("a pinned module keeps its URL, and changing it does not re-version its importers", () => {
    const plain = { "index.html": '<script type="module" src="/js/app.js?v=1"></script>', "js/app.js": 'import { g } from "/js/firebase.js?v=20261021a";', "js/firebase.js": "export const g = 1;" };
    const a = mk(plain), b = mk({ ...plain, "js/firebase.js": "export const g = 2;" });
    try {
      build({ src: join(a, "public"), out: join(a, "dist") }); build({ src: join(b, "public"), out: join(b, "dist") });
      const ver = (root) => readFileSync(join(root, "dist/index.html"), "utf8").match(/app\.js\?v=([0-9a-f]{10})/)[1];
      assert.equal(ver(a), ver(b));
    } finally { rmSync(a, { recursive: true, force: true }); rmSync(b, { recursive: true, force: true }); }
  });
  test("a ?v= specifier pointing at a missing file is reported", () => {
    const root = mk({ ...fixture, "js/lazy.js": 'import "./gone.js?v=1";' });
    try { assert.deepEqual(build({ src: join(root, "public"), out: join(root, "dist"), check: true }).unresolved, ["js/lazy.js -> ./gone.js"]); }
    finally { rmSync(root, { recursive: true, force: true }); }
  });
  test("the real public/ tree builds with no unresolved specifiers", () => {
    const here = dirname(new URL(import.meta.url).pathname);
    assert.deepEqual(build({ src: join(here, "../../public"), out: "", check: true }).unresolved, []);
  });
});
