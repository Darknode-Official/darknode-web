// LEAKPROBE engine tests (public/js/dataprotect/leakprobe-engine.js):
// asset discovery, source-map extraction, owner-needle scan, placement
// classification, backend-hygiene grading and exposure scoring.

import { test, assert, group } from "../harness.mjs";
import {
  assetGraph, extractImports, extractSourceMapUrl, parseSourceMap,
  needleScan, scanBytes, classifyPlacement, gradeCors, gradeErrorLeak,
  commonDebugRoutes, gradeRouteResponse, scoreExposure, selfTest,
} from "../../public/js/dataprotect/leakprobe-engine.js";

group("leakprobe: engine self-test", () => {
  test("all in-engine self-test checks pass", () => {
    const r = selfTest();
    assert.ok(r.pass, "failures: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
});

group("leakprobe: asset graph", () => {
  const html = `<!doctype html><html><head>
    <link rel="modulepreload" href="/js/a.mjs">
    <link rel="preload" as="font" href="/f/x.woff2">
    <link rel="stylesheet" href="css/main.css">
    <script src="https://cdn.test/vendor.js"></script>
    <script type="module" src="/js/main.mjs"></script>
    <script>const inline = 1;</script>
    </head><body></body></html>`;

  test("resolves relative and absolute asset URLs", () => {
    const g = assetGraph(html, "https://site.test/app/");
    assert.ok(g.scripts.includes("https://cdn.test/vendor.js"));
    assert.ok(g.modules.includes("https://site.test/js/main.mjs"));
    assert.ok(g.modules.includes("https://site.test/js/a.mjs"));
    assert.ok(g.styles.includes("https://site.test/app/css/main.css"));
    assert.ok(g.links.includes("https://site.test/f/x.woff2"));
  });
  test("captures inline scripts and seeds config endpoints", () => {
    const g = assetGraph(html, "https://site.test/");
    assert.ok(g.inline.some((i) => /inline/.test(i.text)));
    assert.ok(g.configs.includes("https://site.test/sw.js"));
  });
  test("finds service worker registration", () => {
    const g = assetGraph(`<script>navigator.serviceWorker.register('/sw.js')</script>`, "https://site.test/");
    assert.ok(g.sw.includes("https://site.test/sw.js"));
  });
});

group("leakprobe: module graph + source maps", () => {
  test("extractImports covers static, re-export and dynamic", () => {
    const u = extractImports(
      `import x from "./x.js";\nexport { y } from "../y.mjs";\nawait import("/lazy.js");\nimport "/side.js";`,
      "https://s.test/js/",
    );
    assert.ok(u.includes("https://s.test/js/x.js"));
    assert.ok(u.includes("https://s.test/y.mjs"));
    assert.ok(u.includes("https://s.test/lazy.js"));
    assert.ok(u.includes("https://s.test/side.js"));
  });
  test("extractSourceMapUrl resolves external and flags inline", () => {
    assert.equal(extractSourceMapUrl("x;\n//# sourceMappingURL=app.js.map", "https://s.test/app.js").url, "https://s.test/app.js.map");
    assert.ok(extractSourceMapUrl("x;\n//# sourceMappingURL=data:application/json;base64,AAA", "https://s.test/app.js").inlineData);
    assert.equal(extractSourceMapUrl("no map here", "https://s.test/app.js"), null);
  });
  test("parseSourceMap returns only populated sources", () => {
    const s = parseSourceMap(JSON.stringify({ sources: ["a.ts", "b.ts", "c.ts"], sourcesContent: ["A", null, "C"] }));
    assert.equal(s.length, 2);
    assert.equal(s[0].content, "A");
    assert.equal(s[1].content, "C");
  });
});

group("leakprobe: owner needle + byte scan", () => {
  test("needleScan locates exact secret, masks it, ignores short", () => {
    const hits = needleScan("line1\nkey=GEMINI-REAL-KEY-abcdef123456\nline3", ["GEMINI-REAL-KEY-abcdef123456"]);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].line, 2);
    assert.equal(hits[0].severity, "critical");
    assert.notOk(hits[0].masked.includes("abcdef123456"));
    assert.equal(needleScan("abc here", ["abc"]).length, 0);
  });
  test("scanBytes merges DLP detectors with owner needle and tags location", () => {
    const f = scanBytes(
      "const g='AIza" + "C".repeat(35) + "'; const mine='TRACK-abcd1234ef';",
      "backend-response", ["TRACK-abcd1234ef"],
    );
    assert.ok(f.some((x) => x.id === "gcp-key"));
    assert.ok(f.some((x) => x.id === "owner-secret"));
    assert.ok(f.every((x) => x.where === "backend-response"));
  });
});

group("leakprobe: placement verdict", () => {
  test("empty hits => server-side only PASS", () => {
    const v = classifyPlacement([]);
    assert.equal(v.level, "pass");
    assert.ok(/server-side/i.test(v.reason));
  });
  test("client asset => critical client-exposed", () => {
    assert.equal(classifyPlacement([{ where: "client-asset" }]).level, "critical");
    assert.equal(classifyPlacement([{ where: "source-map" }]).label, "Client-exposed");
  });
  test("backend response => critical backend-leaked", () => {
    const v = classifyPlacement([{ where: "backend-response" }]);
    assert.equal(v.level, "critical");
    assert.ok(/Backend-leaked/.test(v.label));
  });
  test("only a debug route => warning", () => {
    assert.equal(classifyPlacement([{ where: "debug-route" }]).level, "warning");
  });
  test("worst location wins", () => {
    assert.equal(classifyPlacement([{ where: "config-route" }, { where: "client-asset" }]).level, "critical");
  });
});

group("leakprobe: backend hygiene", () => {
  test("CORS grading", () => {
    assert.equal(gradeCors({ "access-control-allow-origin": "*", "access-control-allow-credentials": "true" }).level, "critical");
    assert.equal(gradeCors({ "access-control-allow-origin": "*" }).level, "warning");
    assert.equal(gradeCors({ "access-control-allow-origin": "https://app.test" }).level, "pass");
    assert.equal(gradeCors({}).level, "pass");
    assert.equal(gradeCors({ "access-control-allow-origin": "https://evil.test", "access-control-allow-credentials": "true" }, "https://evil.test").level, "warning");
  });
  test("error-leak grading catches stack/env/paths/secrets", () => {
    const el = gradeErrorLeak("Error\n    at f (/usr/src/app/s.js:10:2)\nDATABASE_URL=postgres://u:p@h/db");
    assert.equal(el.level, "critical");
    assert.ok(el.signals.some((s) => s.kind === "stack"));
    assert.ok(el.signals.some((s) => s.kind === "env"));
    assert.equal(gradeErrorLeak('{"error":"nope"}').level, "pass");
  });
  test("debug route wordlist is non-empty and GET-safe paths", () => {
    const list = commonDebugRoutes();
    assert.ok(list.length > 5);
    assert.ok(list.includes("/.env"));
    assert.ok(list.includes("/.git/HEAD"));
  });
  test("route response grading", () => {
    assert.equal(gradeRouteResponse("/.git/HEAD", 200, "ref: refs/heads/main").hit, true);
    assert.equal(gradeRouteResponse("/.env", 200, "API_KEY=sk-abc\nDATABASE_URL=x").hit, true);
    assert.equal(gradeRouteResponse("/debug", 200, '<!doctype html><html><body><div id="root"></div></body></html>').hit, false);
    assert.equal(gradeRouteResponse("/.env", 404, "nope").hit, false);
    assert.equal(gradeRouteResponse("/debug", 200, "ok").hit, false);
  });
});

group("leakprobe: exposure score", () => {
  test("client-exposed secret forces critical grade", () => {
    const s = scoreExposure([{ kind: "secret", severity: "high", where: "client-asset" }]);
    assert.equal(s.grade, "critical");
    assert.ok(s.clientExposed);
  });
  test("backend-leaked secret forces critical grade", () => {
    const s = scoreExposure([{ kind: "secret", severity: "high", where: "backend-response" }]);
    assert.equal(s.grade, "critical");
    assert.ok(s.backendLeaked);
  });
  test("clean on no findings", () => {
    assert.equal(scoreExposure([]).grade, "clean");
  });
  test("counts by where", () => {
    const s = scoreExposure([{ kind: "pii", severity: "low", where: "client-asset" }, { kind: "pii", severity: "low", where: "client-asset" }]);
    assert.equal(s.byWhere["client-asset"], 2);
  });
});
