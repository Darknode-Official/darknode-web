// js/tools-manifest.js is generated from js/tools-registry.js; the console shell boots from
// the manifest alone. If a tool is added or renamed without re-running the build, the
// Services menu and tool count go stale, so this compares the two exactly.
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { test, group, assert } from "../harness.mjs";
import { loadRegistry, manifestSource } from "../../tools/tools-manifest-build.mjs";

const manifestPath = fileURLToPath(new URL("../../public/js/tools-manifest.js", import.meta.url));
const manifest = await import(pathToFileURL(manifestPath).href);
const registry = await loadRegistry();

group("tools manifest: in sync with the registry", () => {
  test("same tool ids, names and categories in the same order", () => {
    const fromRegistry = registry.TOOLS.map((t) => ({ id: t.id, name: t.name, cat: t.cat }));
    assert.deepEqual(manifest.TOOL_META, fromRegistry, "run: node tools/tools-manifest-build.mjs");
  });
  test("same TOOL_CATS", () => {
    assert.deepEqual(manifest.TOOL_CATS, registry.TOOL_CATS, "run: node tools/tools-manifest-build.mjs");
  });
  test("file on disk is exactly what the generator produces", () => {
    assert.equal(readFileSync(manifestPath, "utf8"), manifestSource(registry), "run: node tools/tools-manifest-build.mjs");
  });
  test("manifest carries no tool code", () => {
    const src = readFileSync(manifestPath, "utf8");
    assert.ok(!/\brun\s*[:(]/.test(src) && !/import\s/.test(src), "manifest must be data only");
    assert.ok(src.length < 120_000, "manifest should stay small: " + src.length);
  });
});
