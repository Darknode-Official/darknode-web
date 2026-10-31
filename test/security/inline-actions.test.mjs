// The site ships a CSP without 'unsafe-inline' in script-src (firebase.json). These
// checks keep it that way: no inline <script> or on*= attributes in the HTML, no real
// inline handlers in markup built by JS, and every data-on-* handler parses under the
// restricted grammar of public/js/core/inline-actions.js and only calls allowed names.

import { test, assert, group } from "../harness.mjs";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";
import vm from "node:vm";

const root = join(dirname(fileURLToPath(import.meta.url)), "../..");
const pub = join(root, "public");
const walk = (dir, out = []) => {
  for (const n of readdirSync(dir)) {
    const f = join(dir, n);
    if (statSync(f).isDirectory()) { if (n !== "vendor" && n !== "node_modules") walk(f, out); }
    else if (/\.(m?js|html)$/.test(n)) out.push(f);
  }
  return out;
};
const files = walk(pub);
const rel = (f) => relative(pub, f).split("\\").join("/");

// Files whose on*= matches are security-test sample strings shown as text, not handlers.
const SAMPLE_FILES = new Set(["js/xss-lab.js", "js/exploit-framework.js", "js/payload-gen.js", "js/api-fuzzer.js",
  "js/labs.js", "js/tools/appsec.js", "js/tools/websec.js", "js/diaries-data.js", "js/aegis-web.js",
  "js/log-analyzer.js", "js/ops/log-hunter-engine.js", "js/engine/programs.js"]);
const isSample = (r) => SAMPLE_FILES.has(r) || r.startsWith("data/");

// Load the dispatcher in a sandbox to get its real compile() and ALLOW set.
const sandbox = { console, setTimeout, navigator: {}, document: { addEventListener() {} } };
sandbox.window = sandbox;
vm.runInNewContext(readFileSync(join(pub, "js/core/inline-actions.js"), "utf8"), sandbox);
const compile = sandbox.__dnInlineCompile, ALLOW = sandbox.__dnInlineAllow;

group("csp: no unsafe-inline scripts", () => {
  test("firebase.json script-src has no 'unsafe-inline'", () => {
    const fj = readFileSync(join(root, "firebase.json"), "utf8");
    const srcs = fj.match(/script-src [^;]*/g) || [];
    assert.ok(srcs.length > 0, "no script-src found");
    for (const s of srcs) assert.ok(!s.includes("'unsafe-inline'"), s);
  });

  test("HTML pages have no inline <script> or on*= attributes", () => {
    const bad = [];
    for (const f of files.filter((x) => x.endsWith(".html"))) {
      const s = readFileSync(f, "utf8");
      for (const m of s.matchAll(/<script(\s[^>]*)?>([\s\S]*?)<\/script>/g)) {
        const a = m[1] || "";
        if (/\ssrc=/.test(a) || /ld\+json/.test(a)) continue;
        if (m[2].trim()) bad.push(rel(f) + ": inline <script>");
      }
      for (const m of s.matchAll(/<[a-z][^>]*?\son[a-z]+=/gi)) bad.push(rel(f) + ": " + m[0].slice(0, 60));
    }
    assert.deepEqual(bad, []);
  });

  test("JS-built markup uses data-on-* instead of inline on*= handlers", () => {
    const bad = [];
    for (const f of files.filter((x) => /\.m?js$/.test(x))) {
      const r = rel(f);
      if (isSample(r)) continue;
      const s = readFileSync(f, "utf8");
      for (const m of s.matchAll(/(?<![\w.$-])on(?!match=)[a-z]+=\\?["']/g)) {
        bad.push(r + ":" + (s.slice(0, m.index).split("\n").length) + " " + s.slice(m.index, m.index + 50));
      }
    }
    assert.deepEqual(bad, []);
  });
});

// Turn a handler body as written in JS source into what the browser will see at runtime,
// with concatenated or interpolated parts replaced by a literal placeholder.
const runtimeBody = (b) => b
  .replace(/\$\{[^}]*\}/g, "X")
  .replace(/\\'\s*\+[^+]*?\+\s*\\'/g, "\\'X\\'")
  .replace(/'\s*\+[^+]*?\+\s*'/g, "0")
  .replace(/\\'/g, "'").replace(/\\"/g, '"').replace(/&quot;/g, '"');

group("csp: data-on-* handlers", () => {
  test("every data-on-* handler parses and calls only allowed names", () => {
    const bad = [];
    let n = 0;
    for (const f of files) {
      const s = readFileSync(f, "utf8");
      for (const m of s.matchAll(/data-on-[a-z]+=(\\?["'])([\s\S]*?)(?<!\\)\1/g)) {
        const body = runtimeBody(m[2]);
        if (!body || body === "X" || body === "0") continue; // fully dynamic (e.g. btn(label, onclick)), checked below
        n++;
        try { compile(body); } catch (e) { bad.push(rel(f) + ": " + body.slice(0, 70) + " -> " + e.message); }
      }
    }
    assert.ok(n >= 50, "found only " + n + " handlers");
    assert.deepEqual(bad, []);
  });

  test("url-dissector btn() actions are allowed calls", () => {
    const s = readFileSync(join(pub, "js/url-dissector.js"), "utf8");
    const acts = [...s.matchAll(/btn\('[^']*',\s*'([^']*)'/g)].map((m) => m[1]);
    assert.ok(acts.length >= 5, "found " + acts.length);
    for (const a of acts) compile(a);
  });

  test("grammar rejects anything but allowed calls", () => {
    for (const src of ["alert(1)", "eval('1')", "window.alert(1)", "this.outerHTML='x'",
      "document.cookie", "fetch('/x')", "location.assign('x')", "this.remove()", "x=1",
      "_udTab(alert(1))", "constructor.constructor('x')()", "top['al'+'ert'](1)"]) {
      let threw = false;
      try { compile(src); } catch (_) { threw = true; }
      assert.ok(threw, "should reject: " + src);
    }
  });

  test("allowed calls run with the right arguments", () => {
    const calls = [];
    sandbox._udTab = (...a) => calls.push(["_udTab", ...a]);
    sandbox._udAnalyze = () => calls.push(["_udAnalyze"]);
    const el = { value: "v1", id: "ud-url" };
    compile("_udTab('net', this.value, 3, true)")({ el, event: null });
    let prevented = 0;
    const ev = { key: "Enter", target: el, preventDefault() { prevented++; } };
    compile("if(event.key==='Enter'&&event.target.id==='ud-url'){event.preventDefault();window._udAnalyze();}")({ el, event: ev });
    compile("if(event.key==='Enter')_udAnalyze()")({ el, event: { key: "a" } });
    assert.deepEqual(calls, [["_udTab", "net", "v1", 3, true], ["_udAnalyze"]]);
    assert.equal(prevented, 1);
    for (const n of ALLOW) assert.ok(/^[_$A-Za-z][\w$]*$/.test(n), n);
  });
});
