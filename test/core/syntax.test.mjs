// Every browser script must at least parse: a stray apostrophe inside a single-quoted string
// once took the whole DI tab down while every engine test still passed.
import { readdirSync, readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test, group, assert } from "../harness.mjs";

const js = fileURLToPath(new URL("../../public/js/", import.meta.url));

group("syntax: browser scripts parse", () => {
  test("every public/js script is valid JavaScript", () => {
    const dir = mkdtempSync(join(tmpdir(), "di-syntax-"));
    const bad = [];
    try {
      const files = readdirSync(js).filter((f) => f.endsWith(".js"));
      for (const f of files) {
        const src = readFileSync(join(js, f), "utf8");
        const tmp = join(dir, f.replace(/\.js$/, ".mjs")); // parse as a module (import/export allowed)
        writeFileSync(tmp, src);
        let r = spawnSync(process.execPath, ["--check", tmp], { encoding: "utf8" });
        if (r.status !== 0) r = spawnSync(process.execPath, ["--check", join(js, f)], { encoding: "utf8" }); // classic script
        if (r.status !== 0) bad.push(f + ": " + (r.stderr.split("\n").find((l) => /Error/.test(l)) || "syntax error"));
      }
      assert.ok(files.length > 50, "found the scripts");
    } finally { rmSync(dir, { recursive: true, force: true }); }
    assert.deepEqual(bad, []);
  });
});
