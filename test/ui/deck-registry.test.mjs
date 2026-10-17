// Tests for scripts/lib/deck-registry.mjs: parsers, validation, patchers, stamps,
// stub templates and a lint() run against the real tree (gaps are printed, not asserted).

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { test, group, assert } from "../harness.mjs";
import {
  parseNavDef, parseIcons, parseRoutes, parseBlurbs, parseExplainKeys, parseHelpKeys, parseConsoleNavIds,
  parseStamps, collectStamps, nextStamp, validateSpec, targetFiles,
  patchSideDesc, patchRoute, patchNavDef, patchExplain, bumpStamps,
  renderEngineStub, renderUiStub, renderTestStub, blankLiterals, lint,
} from "../../scripts/lib/deck-registry.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/* ---------------------------------------------------------------- fixtures */

const AUTH = [
  "// header",
  "const SIDE_DESC = {",
  "  home: \"Your home base — activity, stats and quick links.\",",
  "  // Mission Control",
  "  leakprobe: \"Finds secrets reachable from the browser.\",",
  "  setup: \"Install guide.\",",
  "};",
  "function other() {",
  "  if (sec === \"home\") return;",
  "}",
  "  function show(sec, more, skipPush) {",
  "    if (sec === \"math\") { _prevCleanup = renderQuelvra(main, more); }",
  "    else if (sec === \"leakprobe\") { import(\"/js/dataprotect/leakprobe.js?v=20261015e\").then(m => live() && m.renderLeakprobe(main)); }",
  "    else if (sec === \"setup\") renderSetup(main, more);",
  "    else if (sec === \"admin\") { import(\"/js/admin.js?v=20261015f\").then(m => live() && m.renderAdmin(main, user)); }",
  "  }",
  "",
].join("\n");

const DECK = [
  "// deck",
  "import { attachExplain } from \"/js/ui/explain.js?v=20261015f\";",
  "const IC = {",
  "  shield: SVG('<path d=\"M12 3\"/>'),",
  "  search: SVG('<circle/>'),",
  "  key: SVG('<circle/>'),",
  "  home: SVG('<path/>'),",
  "};",
  "function deck(opts) {",
  "  const NAV_DEF = [",
  "    { g: \"\", items: [[\"scene\", \"overview\", \"Security Overview\", IC.home]] },",
  "    { id: \"identity\", g: \"Identity\", items: [[\"tool\", \"signins\", \"Sign-in Forensics\", IC.search], [\"tool\", \"accessreview\", \"Access Review\", IC.shield]] },",
  "    { id: \"empty\", g: \"Empty\", items: [] },",
  "    { id: \"compliance\", g: \"Compliance\", items: [[\"scene\", \"compliance\", \"Frameworks\", IC.shield], [\"tool\", \"leakprobe\", \"Secret Exposure\", IC.key]] },",
  "    { g: \"Platform\", items: [[\"scene\", \"con\", \"Integrations\", IC.home]].concat(opts.isOwner ? [[\"tool\", \"admin\", \"Admin\", IC.key]] : []) },",
  "  ];",
  "}",
  "",
].join("\n");

const EXPLAIN = [
  "export const EXPLAIN = {",
  "  \"scene.overview\": { title: \"Overview\", body: \"The overview scene with the main KPIs.\" },",
  "  \"tool.signins\": { title: \"Sign-in Forensics\", body: \"Load a sign-in export and find spraying.\" },",
  "  \"tool.leakprobe\": { title: \"Secret Exposure\", body: \"Proves whether a secret is reachable.\", src: \"Proxy fetches.\" },",
  "  \"kpi.open\": { title: \"Open\", body: \"Open findings across the workspace.\" },",
  "};",
  "",
].join("\n");

const HELP = "export const HELP = {\n  \"home\": { what: \"x\", when: \"y\" },\n  \"accessreview\": { what: \"x\", when: \"y\" },\n};\n";
const CONSOLE_NAV = "export const NAV = [\n  G(\"flagships\", \"Command Centers\", \"blue\", [[\"prometheus\",\"SOC\",\"live\"],[\"hydra\",\"Attack Path\"]]),\n];\n";
const ADMIN = "x();\n          import(\"/js/deck-ui.js?v=20261015f\"),\n";
const INDEX = "<link rel=\"modulepreload\" href=\"/js/auth.js?v=20261015f\">\n<script type=\"module\" src=\"/js/auth.js?v=20261015f\"></script>\n";
const SW = "const CACHE = 'darknode-v145';\nconst X = 1;\n";
const STAMPS = { adminSrc: ADMIN, deckUiSrc: DECK, indexSrc: INDEX, swSrc: SW };

const SPEC = { id: "zzdemo", label: "Demo Tool", group: "identity", prefix: "zzd", dir: "identity", fn: "renderZzDemo", icon: "shield", blurb: "Demo blurb long enough to pass the explain rule.", src: "Synthetic." };
const ctx = (over = {}) => ({
  nav: parseNavDef(DECK), icons: parseIcons(DECK), routes: parseRoutes(AUTH), blurbs: parseBlurbs(AUTH),
  explainKeys: parseExplainKeys(EXPLAIN), helpKeys: parseHelpKeys(HELP), consoleIds: parseConsoleNavIds(CONSOLE_NAV), exists: () => false, ...over,
});

/* ----------------------------------------------------------------- parsers */

group("deck-registry/parsers", () => {
  test("parseNavDef finds groups, ids, items and the owner-only concat item", () => {
    const nav = parseNavDef(DECK);
    assert.equal(nav.start, 10); assert.equal(nav.end, 16);
    assert.deepEqual(nav.groups.map((g) => g.id), [null, "identity", "empty", "compliance", null]);
    assert.deepEqual(nav.groups[1].items[0], { kind: "tool", id: "signins", label: "Sign-in Forensics", icon: "search" });
    assert.equal(nav.groups[1].line, 12);
    assert.deepEqual(nav.groups[2].items, []);
    assert.deepEqual(nav.groups[4].items.map((i) => i.id), ["con", "admin"]);
  });

  test("parseNavDef throws when the anchor is missing", () => {
    assert.throws(() => parseNavDef("const X = [];"));
  });

  test("parseIcons reads the IC block only", () => {
    assert.deepEqual([...parseIcons(DECK)].sort(), ["home", "key", "search", "shield"]);
  });

  test("parseRoutes maps import and inline branches inside show() only", () => {
    const r = parseRoutes(AUTH);
    assert.deepEqual(r.get("leakprobe"), { path: "/js/dataprotect/leakprobe.js", fn: "renderLeakprobe", line: 13 });
    assert.deepEqual(r.get("setup"), { path: null, fn: "renderSetup", line: 14 });
    assert.equal(r.get("math").fn, "renderQuelvra");
    assert.equal(r.get("admin").fn, "renderAdmin");
    assert.notOk(r.has("home"), "sec === outside show() must be ignored");
  });

  test("parseBlurbs reads SIDE_DESC entries and skips comments", () => {
    const b = parseBlurbs(AUTH);
    assert.equal(b.size, 3);
    assert.equal(b.get("leakprobe"), "Finds secrets reachable from the browser.");
  });

  test("parseExplainKeys and parseHelpKeys return key sets", () => {
    assert.deepEqual([...parseExplainKeys(EXPLAIN)], ["scene.overview", "tool.signins", "tool.leakprobe", "kpi.open"]);
    assert.deepEqual([...parseHelpKeys(HELP)], ["home", "accessreview"]);
  });

  test("parseConsoleNavIds reads item ids", () => {
    assert.deepEqual([...parseConsoleNavIds(CONSOLE_NAV)].sort(), ["hydra", "prometheus"]);
  });

  test("parseStamps reads all 5 sites", () => {
    assert.deepEqual(parseStamps(STAMPS), { admin: "20261015f", deckUi: "20261015f", index: ["20261015f", "20261015f"], sw: 145 });
  });

  test("parseStamps throws when index.html has one auth stamp", () => {
    assert.throws(() => parseStamps({ ...STAMPS, indexSrc: "<script src=\"/js/auth.js?v=20261015f\"></script>" }));
  });

  test("collectStamps gathers every ?v= value", () => {
    assert.deepEqual(collectStamps(AUTH), ["20261015e", "20261015f"]);
  });
});

/* ------------------------------------------------------------------ stamps */

group("deck-registry/nextStamp", () => {
  const d = new Date(2026, 9, 16);
  test("no stamp today -> a", () => assert.equal(nextStamp(["20261015f", "20261013b"], d), "20261016a"));
  test("next free letter after the highest used today", () => assert.equal(nextStamp(["20261016a", "20261016c", "20261015z"], d), "20261016d"));
  test("rolls over to a new day", () => assert.equal(nextStamp(["20261016z"], new Date(2026, 9, 17)), "20261017a"));
  test("continues with za after z", () => assert.equal(nextStamp(["20261016z", "20261016y"], d), "20261016za"));
  test("za..zz ordered after single letters", () => assert.equal(nextStamp(["20261016zc", "20261016q"], d), "20261016zd"));
  test("throws when letters are exhausted", () => assert.throws(() => nextStamp(["20261016zz"], d)));
});

/* ---------------------------------------------------------------- validate */

group("deck-registry/validateSpec", () => {
  test("a good spec has no problems", () => assert.deepEqual(validateSpec(SPEC, ctx()), []));
  test("bad id", () => assert.ok(validateSpec({ ...SPEC, id: "Zz-1" }, ctx()).some((p) => /^id/.test(p))));
  test("missing group", () => assert.ok(validateSpec({ ...SPEC, group: "risk" }, ctx()).some((p) => /group "risk"/.test(p))));
  test("bad icon", () => assert.ok(validateSpec({ ...SPEC, icon: "sparkle" }, ctx()).some((p) => /icon "sparkle"/.test(p))));
  test("emoji in label and blurb", () => {
    const p = validateSpec({ ...SPEC, label: "Demo 🚀", blurb: "Long enough blurb with an emoji 🔒 inside." }, ctx());
    assert.ok(p.includes("label contains an emoji")); assert.ok(p.includes("blurb contains an emoji"));
  });
  test("short blurb", () => assert.ok(validateSpec({ ...SPEC, blurb: "Too short." }, ctx()).some((p) => /at least 21/.test(p))));
  test("bad fn, prefix and dir", () => {
    const p = validateSpec({ ...SPEC, fn: "zzdemo", prefix: "toolong", dir: "Bad_Dir" }, ctx());
    assert.ok(p.some((x) => /^fn/.test(x))); assert.ok(p.some((x) => /^prefix/.test(x))); assert.ok(p.some((x) => /^dir/.test(x)));
  });
  test("duplicate ids in routes, blurbs, NAV_DEF, EXPLAIN and console-nav", () => {
    assert.ok(validateSpec({ ...SPEC, id: "leakprobe" }, ctx()).length >= 4);
    assert.ok(validateSpec({ ...SPEC, id: "hydra" }, ctx()).some((p) => /console-nav/.test(p)));
    assert.ok(validateSpec({ ...SPEC, id: "signins" }, ctx()).some((p) => /NAV_DEF/.test(p)));
  });
  test("existing target file", () => {
    const p = validateSpec(SPEC, ctx({ exists: (f) => f.endsWith("zzdemo.js") }));
    assert.deepEqual(p, ["target file exists: public/js/identity/zzdemo.js"]);
    assert.deepEqual(targetFiles(SPEC), ["public/js/identity/zzdemo-engine.js", "public/js/identity/zzdemo.js", "test/security/zzdemo.test.mjs"]);
  });
});

/* ---------------------------------------------------------------- patchers */

group("deck-registry/patchers", () => {
  test("patchSideDesc inserts before the closing brace and escapes quotes", () => {
    const out = patchSideDesc(AUTH, "zzdemo", "Say \"hi\" to the demo.").split("\n");
    assert.equal(out[6], "  zzdemo: \"Say \\\"hi\\\" to the demo.\",");
    assert.equal(out[7], "};");
    assert.equal(parseBlurbs(out.join("\n")).get("zzdemo"), "Say \"hi\" to the demo.");
  });
  test("patchSideDesc is not re-applicable", () => {
    const once = patchSideDesc(AUTH, "zzdemo", "x");
    assert.throws(() => patchSideDesc(once, "zzdemo", "x"));
  });
  test("patchSideDesc throws without its anchor", () => assert.throws(() => patchSideDesc("const X = {\n};", "a", "b")));

  test("patchRoute inserts directly before the setup branch", () => {
    const out = patchRoute(AUTH, "zzdemo", "identity", "renderZzDemo", "20261016a").split("\n");
    assert.equal(out[13], "    else if (sec === \"zzdemo\") { import(\"/js/identity/zzdemo.js?v=20261016a\").then(m => live() && m.renderZzDemo(main)); }");
    assert.equal(out[14], "    else if (sec === \"setup\") renderSetup(main, more);");
    assert.equal(parseRoutes(out.join("\n")).get("zzdemo").path, "/js/identity/zzdemo.js");
  });
  test("patchRoute is not re-applicable and needs its anchor", () => {
    const once = patchRoute(AUTH, "zzdemo", "identity", "renderZzDemo", "20261016a");
    assert.throws(() => patchRoute(once, "zzdemo", "identity", "renderZzDemo", "20261016b"));
    assert.throws(() => patchRoute(AUTH.replace("renderSetup(main, more)", "renderSetup(main)"), "q", "d", "renderQ", "20261016a"));
    assert.throws(() => patchRoute(AUTH + AUTH, "q", "d", "renderQ", "20261016a"), "two anchors must throw");
  });

  test("patchNavDef appends to the right group", () => {
    const out = patchNavDef(DECK, "identity", "zzdemo", "Demo Tool", "shield");
    const nav = parseNavDef(out);
    assert.deepEqual(nav.groups[1].items.map((i) => i.id), ["signins", "accessreview", "zzdemo"]);
    assert.ok(out.includes("IC.shield], [\"tool\", \"zzdemo\", \"Demo Tool\", IC.shield]] },"));
    assert.equal(nav.groups[3].items.length, 2, "other groups untouched");
  });
  test("patchNavDef handles an empty items array", () => {
    const nav = parseNavDef(patchNavDef(DECK, "empty", "zzdemo", "Demo Tool", "key"));
    assert.deepEqual(nav.groups[2].items, [{ kind: "tool", id: "zzdemo", label: "Demo Tool", icon: "key" }]);
  });
  test("patchNavDef is not re-applicable and rejects unknown groups", () => {
    const once = patchNavDef(DECK, "identity", "zzdemo", "Demo Tool", "shield");
    assert.throws(() => patchNavDef(once, "identity", "zzdemo", "Demo Tool", "shield"));
    assert.throws(() => patchNavDef(DECK, "risk", "zzdemo", "Demo Tool", "shield"));
  });

  test("patchExplain inserts after the last tool.* entry", () => {
    const out = patchExplain(EXPLAIN, "zzdemo", "Demo Tool", "Demo blurb long enough to pass the explain rule.", "Synthetic.").split("\n");
    assert.equal(out[4], "  \"tool.zzdemo\": { title: \"Demo Tool\", body: \"Demo blurb long enough to pass the explain rule.\", src: \"Synthetic.\" },");
    assert.ok(out[5].startsWith("  \"kpi.open\""));
    assert.ok(parseExplainKeys(out.join("\n")).has("tool.zzdemo"));
  });
  test("patchExplain omits src when empty, is not re-applicable, needs an anchor", () => {
    const out = patchExplain(EXPLAIN, "zzdemo", "Demo Tool", "Demo blurb long enough.", "");
    assert.ok(out.includes("body: \"Demo blurb long enough.\" },"));
    assert.throws(() => patchExplain(out, "zzdemo", "Demo Tool", "Demo blurb long enough.", ""));
    assert.throws(() => patchExplain("export const EXPLAIN = {\n  \"scene.a\": { title: \"A\", body: \"b\" },\n};", "q", "Q", "b", ""));
  });

  test("bumpStamps rewrites all 5 sites, keeps index identical, increments sw", () => {
    const b = bumpStamps(STAMPS, "20261016a");
    const st = parseStamps(b);
    assert.deepEqual(st, { admin: "20261016a", deckUi: "20261016a", index: ["20261016a", "20261016a"], sw: 146 });
    assert.ok(b.swSrc.startsWith("const CACHE = 'darknode-v146';\n"));
    assert.ok(b.deckUiSrc.includes("const NAV_DEF"), "rest of the file preserved");
  });
  test("bumpStamps is not re-applicable and rejects mismatched index stamps", () => {
    const b = bumpStamps(STAMPS, "20261016a");
    assert.throws(() => bumpStamps(b, "20261016a"));
    assert.throws(() => bumpStamps({ ...STAMPS, indexSrc: INDEX.replace("20261015f", "20261015e") }, "20261016a"));
  });
});

/* --------------------------------------------------------------- templates */

group("deck-registry/templates", () => {
  test("engine stub exports the contract", () => {
    const s = renderEngineStub(SPEC);
    for (const e of ["export const TOOL_ID = \"zzdemo\"", "export const VERSION = \"0.1.0\"", "export const COLUMNS", "export const DEFAULTS",
      "export function parseInput(text)", "export function analyze(rows, opts = {}, ctx)", "export function findingsToCsv(findings)",
      "export function selfTest()", "export function exampleDataset(", "from \"../ingest/parse.js\"", "ctx?.progress?.(i, n)", "skipped.push({ check:"]) {
      assert.ok(s.includes(e), "engine stub missing: " + e);
    }
    assert.notOk(/\{\{\w+\}\}/.test(s), "unfilled template var");
  });
  test("ui stub mounts under the prefix and uses the kit", () => {
    const s = renderUiStub(SPEC, "20261016a");
    for (const e of ["export function renderZzDemo(main)", "P + \"-css\"", ".zzd-root{", ".zzd-pill", "Runs entirely in your browser. Nothing is uploaded.",
      "from \"../ingest/dropzone.js\"", "from \"../ingest/worker.js\"", "from \"../core/sink.js\"", "from \"../core/export.js\"", "from \"../core/sink-map.js\"",
      "\"./zzdemo-engine.js?v=20261016a\"", "runInWorker(ENGINE, \"analyze\", [rows, opts()]", "attachSinkButton(", "Load example (synthetic)", "window.showToast"]) {
      assert.ok(s.includes(e), "ui stub missing: " + e);
    }
    assert.notOk(/\balert\(|\bconfirm\(|\bprompt\(/.test(s), "native dialogs are banned");
    assert.notOk(/\{\{\w+\}\}/.test(s), "unfilled template var");
  });
  test("ui stub declares the <style id=\"<prefix>-css\"> via P", () => {
    const s = renderUiStub(SPEC, "20261016a");
    assert.ok(s.includes("const P = \"zzd\";") && s.includes("st.id = P + \"-css\""));
  });
  test("test stub imports the engine and covers the 3 rules", () => {
    const s = renderTestStub(SPEC);
    assert.ok(s.includes("from \"../../public/js/identity/zzdemo-engine.js\""));
    assert.ok(s.includes("selfTest()") && s.includes("assert.deepEqual(analyze(rows), analyze(rows))") && s.includes("parseInput(\"\")"));
  });
  test("stubs are syntactically valid JavaScript (node --check)", async () => {
    const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { execFileSync } = await import("node:child_process");
    const dir = mkdtempSync(join(tmpdir(), "deck-registry-"));
    try {
      [renderEngineStub(SPEC), renderUiStub(SPEC, "20261016a"), renderTestStub(SPEC)].forEach((s, i) => {
        const f = join(dir, `stub${i}.mjs`);
        writeFileSync(f, s);
        execFileSync(process.execPath, ["--check", f], { stdio: "pipe" });
      });
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

/* -------------------------------------------------------------------- lint */

group("deck-registry/lint", () => {
  test("blankLiterals hides string and regex contents, keeps code", () => {
    assert.equal(blankLiterals("x = /document\\.cookie/i; y = \"window.a\"; z = window.b; // document"), "x = /                /i; y = \"        \"; z = window.b;            ");
    assert.ok(/\bdocument\s*\./.test(blankLiterals("const d = document.body;")));
  });
  test("lint() on the real tree returns an array (gaps printed, not asserted)", () => {
    const probs = lint(ROOT);
    assert.ok(Array.isArray(probs));
    for (const p of probs) assert.ok(p.severity === "error" || p.severity === "warn");
    if (probs.length) console.log("\n  [deck-registry lint] current gaps in the real tree:\n" + probs.map((p) => `    ${p.severity}: ${p.msg}${p.file ? ` [${p.file}${p.line ? ":" + p.line : ""}]` : ""}`).join("\n"));
  });
});
