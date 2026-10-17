// Duplicate-definition lint: a repeated object key, class method or same-scope
// function declaration silently overrides the earlier one (prometheus-web.js once
// carried 3 copies of getNodeById; the glossary in engine/advanced.js 14 repeated keys).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test, group, assert } from "../harness.mjs";
import { scanDuplicates } from "../../scripts/lib/dup-scan.mjs";
import { parseConsoleNavIds, parseExplainKeys, parseBlurbs, parseNavDef } from "../../scripts/lib/deck-registry.mjs";

const names = (src) => scanDuplicates(src).map((d) => d.kind + ":" + d.name);

group("dup-scan: duplicate keys and declarations", () => {
  test("object literal keys, quoted and numeric forms included", () => {
    assert.deepEqual(names(`const o = { a: 1, "a": 2, b: 3 };`), ["key:a"]);
    assert.deepEqual(names(`x = { 1: 2, "1": 3, 'dns': 1, dns: 2 };`), ["key:1", "key:dns"]);
    assert.deepEqual(names(`f({ a: 1, b: { a: 2, a: 3 } });`), ["key:a"]);
  });
  test("getter/setter pairs, separate literals and ternary branches are not duplicates", () => {
    assert.deepEqual(names(`const o = { get x() { return 1 }, set x(v) {}, y: { a: 1 }, z: { a: 2 } };`), []);
    assert.deepEqual(names(`x = c ? { a: 1 } : { a: 2 }; switch (k) { case 1: { let a; break } }`), []);
    assert.deepEqual(names(`const o = { class: 1, b: { c: 1 }, d: { c: 2 } };`), []);
  });
  test("strings, regexes and templates do not confuse the brace tracking", () => {
    assert.deepEqual(names(`const r = /{a:1,a:2}/g; if (x) /re/.test(y); const z = a / b / c; s = "{a:1,a:2}";`), []);
    assert.deepEqual(names("const t = `${ {a:1, a:2}.a } ${`${x}`}`; const q = { a: 1 };"), ["key:a"]);
  });
  test("same-scope function declarations, but not expressions or other scopes", () => {
    assert.deepEqual(names(`function outer(){ function g(a){} if (x) { function h(){} } function g(){} }`), ["function:g"]);
    assert.deepEqual(names(`var a = function g(){}; var b = function g(){};`), []);
    assert.deepEqual(names(`const f = () => { function a(){} }; const g = () => { function a(){} };`), []);
    assert.deepEqual(names(`foo()\nfunction a(){}\nfunction a(){}`), ["function:a"]);
  });
  test("class methods: static and accessors are distinct, a repeat is not", () => {
    assert.deepEqual(names(`class A { foo() {} static foo() {} get v() {} set v(x) {} bar() {} bar() {} }`), ["method:bar"]);
  });
  test("reports the later (winning) line and the first line", () => {
    const [d] = scanDuplicates(`const o = {\n  a: 1,\n  b: 2,\n  a: 3,\n};`);
    assert.equal(d.line, 4);
    assert.equal(d.firstLine, 2);
  });
});

group("dup-scan: the real tree", () => {
  test("public/js has no duplicate keys, class methods or same-scope function declarations", () => {
    const root = fileURLToPath(new URL("../../public/js/", import.meta.url));
    const walk = (d, o = []) => { for (const n of readdirSync(d)) { const f = join(d, n); if (statSync(f).isDirectory()) walk(f, o); else if (/\.m?js$/.test(n)) o.push(f); } return o; };
    const hits = [];
    const files = walk(root);
    for (const f of files) for (const d of scanDuplicates(readFileSync(f, "utf8"))) hits.push(`${f.slice(root.length)}:${d.line} ${d.kind} ${d.name} (first ${d.firstLine})`);
    assert.ok(files.length > 300, "walked the tree");
    assert.deepEqual(hits, []);
  });
});

group("deck-registry: repeated ids are reported, not dropped", () => {
  test("console-nav menu rows, EXPLAIN keys and SIDE_DESC ids", () => {
    const nav = parseConsoleNavIds(`G("a", "A", "x", [["dns","DNS"],["whois","WHOIS"]]),\nG("b", "B", "x", [["dns","DNS again"]]),\nconst FAVS = ["dns", "x"];`);
    assert.deepEqual(nav.dups, [{ id: "dns", line: 2 }]);
    assert.ok(nav.has("dns") && nav.has("whois"));
    assert.deepEqual(parseExplainKeys(`const E = {\n  "tool.a": { t: 1 },\n  "tool.a": { t: 2 },\n};`).dups, [{ id: "tool.a", line: 3 }]);
    assert.deepEqual(parseBlurbs(`const SIDE_DESC = {\n  a: "one",\n  a: "two",\n};`).dups, [{ id: "a", line: 3 }]);
  });
  test("NAV_DEF ids repeated across groups", () => {
    const src = `const NAV_DEF = [\n  { g: "One", items: [["tool", "dns", "DNS", IC.globe]] },\n  { g: "Two", items: [["tool", "dns", "DNS", IC.globe]] },\n];`;
    assert.deepEqual(parseNavDef(src).dups, [{ id: "dns", line: 3 }]);
  });
});
