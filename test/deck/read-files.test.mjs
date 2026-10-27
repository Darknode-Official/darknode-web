// Deck file pickers (Code secrets, Repository sweep, Safe to share) read folders through
// readFiles. A picked repository lists node_modules before src, so the file cap must be
// applied after dependency folders are dropped, or the project's own files are never read.

import { test, group, assert } from "../harness.mjs";
import { readFiles } from "../../public/js/deck/native/ui.js";

const F = (p, t) => ({ webkitRelativePath: p, name: p.split("/").pop(), size: t.length, text: async () => t });

group("deck: readFiles", () => {
  test("dependency folders do not use up the file cap", async () => {
    const list = [];
    for (let i = 0; i < 2500; i++) list.push(F("repo/node_modules/p" + i + "/index.js", "x"));
    list.push(F("repo/src/config.js", "secret"), F("repo/README.md", "hi"));
    const r = await readFiles(list);
    assert.equal(r.files.map((f) => f.path).join(","), "repo/src/config.js,repo/README.md");
    assert.equal(r.skipped.length, 2500);
  });
  test("files past the cap are reported as skipped, not dropped silently", async () => {
    const r = await readFiles([F("a.js", "1"), F("b.js", "2"), F("c.js", "3")], { maxFiles: 2 });
    assert.equal(r.files.length, 2); assert.equal(r.skipped.join(), "c.js");
  });
});
