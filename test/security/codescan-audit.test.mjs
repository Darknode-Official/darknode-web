// Code Scanner audit: each test pins one reproduced bug (wrong result, missed flow,
// leaked secret, wrong column, or super-linear cost on an adversarial file).

import { test, assert, group } from "../harness.mjs";
import { scanFile } from "../../public/js/codescan/rules.js";
import { taintScan } from "../../public/js/codescan/taint-js.js";
import { api, parseRepo, osvVuln } from "../../public/js/codescan/github.js";

const fast = (fn, ms = 3000) => { const t0 = Date.now(); fn(); return Date.now() - t0 < ms; };
const ids = (path, src) => scanFile(path, src).map((f) => f.ruleId + "@" + f.line);
const flows = (src) => taintScan(src).map((f) => f.ruleId + "@" + f.line);
const resp = (status, body, h = {}) => ({ status, ok: status >= 200 && status < 300, headers: { get: (k) => h[k.toLowerCase()] ?? null }, json: async () => body, text: async () => JSON.stringify(body) });
const withFetch = async (fn, body) => { const prev = globalThis.fetch; globalThis.fetch = fn; try { return await body(); } finally { globalThis.fetch = prev; } };

group("codescan audit", () => {
  test("taint engine stays bounded on unbalanced or deeply nested code (was 29 s on 20 KB, cubic)", () => {
    assert.ok(fast(() => taintScan("const f = (a) => { ".repeat(1100))));
    assert.ok(fast(() => taintScan("f(".repeat(20000))));
    assert.ok(fast(() => taintScan("function f(a){ ".repeat(1400))));
    // real nesting still traces
    assert.deepEqual(flows("const f = (a) => {\n  const g = (b) => {\n    eval(req.query.x);\n  };\n};"), ["js.taint.code@3"]);
  });

  test("module-import scan stays linear on unclosed destructuring (was 7 s on 320 KB)", () => {
    assert.ok(fast(() => taintScan("const {a".repeat(40000))));
    assert.ok(fast(() => taintScan("import {a".repeat(40000))));
    assert.deepEqual(flows('const { exec: run } = require("child_process");\nrun("ls " + req.query.d);'), ["js.taint.cmd@2"]);
  });

  test("encodeURIComponent does not clear a code-evaluation flow (alert(1) passes through unencoded)", () => {
    assert.deepEqual(flows("const x = encodeURIComponent(req.query.x);\neval(x);"), ["js.taint.code@2"]);
    assert.deepEqual(flows('fetch("https://api.example.com/items/" + encodeURIComponent(req.query.id));'), []);
  });

  test("an existence check is not a validator: if (!fs.existsSync(p)) return still reaches readFileSync", () => {
    const src = 'app.get("/f", (req, res) => {\n  const p = req.query.f;\n  if (!fs.existsSync(p)) return res.sendStatus(404);\n  res.send(fs.readFileSync(p));\n});';
    assert.deepEqual(flows(src), ["js.taint.path@4"]);
    assert.deepEqual(flows('app.get("/f", (req, res) => {\n  const p = req.query.f;\n  if (!isSafeName(p)) return;\n  fs.readFileSync(p);\n});'), []);
  });

  test("a secret value containing $& does not paste the raw secret back into the snippet", () => {
    const val = "ab$&" + "Zq9xK2mP7vL4nR8tW";
    const f = scanFile("config.env", "API_SECRET=" + val)[0];
    assert.equal(f.ruleId, "secret.generic");
    assert.ok(!f.snippet.includes(val), f.snippet);
    assert.equal(f.snippet, "API_SECRET=" + f.secret);
  });

  test("a /* inside a // comment does not swallow the following code as a block comment", () => {
    const sql = 'rows, _ := db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id))';
    assert.deepEqual(ids("a.go", "// routes under /api/*\n" + sql), ["go.sql-sprintf@2"]);
    assert.deepEqual(ids("a.go", "/* routes under\n/api */\n" + sql), ["go.sql-sprintf@3"]);
    assert.deepEqual(ids("a.go", "/* open\n" + sql), []);
  });

  test("code after the end of a block comment reports its real column", () => {
    const f = scanFile("A.java", '/* start\n end */ Runtime.getRuntime().exec("ls " + x);');
    assert.equal(f.length, 1);
    assert.equal(f[0].line, 2);
    assert.equal(f[0].col, 9);
  });

  test("CRLF and a BOM keep taint lines and columns exact", () => {
    const f = taintScan("﻿const p = req.query.f;\r\n\r\n  fs.readFileSync(p);\r\n");
    assert.deepEqual(f.map((x) => [x.line, x.col]), [[3, 3]]);
  });

  test("Dockerfile: a USER in a builder stage does not make the final stage non-root", () => {
    assert.deepEqual(ids("Dockerfile", 'FROM node:20 AS build\nUSER node\nRUN npm ci\nFROM nginx:1.27\nCOPY --from=build /app /srv\nCMD ["nginx"]'), ["docker.runs-as-root@4"]);
    assert.deepEqual(ids("Dockerfile", 'FROM node:20 AS base\nUSER node\nFROM base\nCMD ["node"]'), []); // inherits USER, and "base" is a stage, not an unpinned image
    assert.deepEqual(ids("Dockerfile", "FROM node:20\nUSER app\nCMD node app.js"), []);
    assert.deepEqual(ids("Dockerfile", "FROM node:20\nUSER root"), ["docker.runs-as-root@2"]);
  });

  test("Dockerfile: FROM --platform=... with an unpinned image is still flagged", () => {
    assert.deepEqual(ids("Dockerfile", "FROM --platform=linux/amd64 node\nUSER node"), ["docker.latest-tag@1"]);
    assert.deepEqual(ids("Dockerfile", "FROM --platform=linux/amd64 node:20.11\nUSER node"), []);
    assert.ok(fast(() => scanFile("Dockerfile", "FROM " + "--a ".repeat(490) + "x"), 300));
  });

  test("GitHub secondary rate limit (429, or 403 with Retry-After) is reported as rate limiting", async () => {
    const e429 = await withFetch(async () => resp(429, {}, { "x-ratelimit-remaining": "4000", "retry-after": "30" }), () => api("/x").catch((e) => e));
    assert.equal(e429.rateLimited, true);
    assert.ok(/30 seconds/.test(e429.message), e429.message);
    const e403 = await withFetch(async () => resp(403, {}, { "x-ratelimit-remaining": "4000", "retry-after": "60" }), () => api("/x").catch((e) => e));
    assert.equal(e403.rateLimited, true);
    const plain = await withFetch(async () => resp(403, {}, { "x-ratelimit-remaining": "4000" }), () => api("/x").catch((e) => e));
    assert.ok(!plain.rateLimited && /refused/.test(plain.message));
  });

  test("parseRepo strips .git before or after a trailing slash", () => {
    assert.deepEqual(parseRepo("https://github.com/example/tool.git/"), { owner: "example", repo: "tool", branch: "" });
    assert.deepEqual(parseRepo("example/tool.git"), { owner: "example", repo: "tool", branch: "" });
  });

  test("a failed OSV advisory fetch is retried instead of cached as missing", async () => {
    let n = 0;
    await withFetch(async () => { n++; if (n === 1) throw new Error("offline"); return resp(200, { id: "GHSA-test-audit" }); }, async () => {
      assert.equal(await osvVuln("GHSA-test-audit"), null);
      await new Promise((r) => setTimeout(r, 0));
      assert.deepEqual(await osvVuln("GHSA-test-audit"), { id: "GHSA-test-audit" });
    });
  });
});
