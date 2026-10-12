import { readFileSync } from "node:fs";
import { test, group, assert } from "../harness.mjs";
import { EXPLAIN, tipPosition } from "../../public/js/ui/explain.js";

const deck = readFileSync(new URL("../../public/js/deck-ui.js", import.meta.url), "utf8");
const ids = (re) => [...new Set([...deck.matchAll(re)].map((m) => m[1]))];

group("ui/explain", () => {
  test("every registry entry has a title and a plain-text body", () => {
    for (const [id, e] of Object.entries(EXPLAIN)) {
      assert.ok(typeof e.title === "string" && e.title.length > 1, id + " title");
      assert.ok(typeof e.body === "string" && e.body.length > 20, id + " body");
      assert.notOk(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(e.title + e.body + (e.src || "")), id + " has an emoji");
    }
  });

  test("every data-explain id used in the Deck exists", () => {
    const used = ids(/data-explain="([\w.]+)"/g);
    assert.ok(used.length >= 20, "expected the Deck to tag its controls, found " + used.length);
    for (const id of used) assert.ok(EXPLAIN[id], "missing EXPLAIN entry: " + id);
  });

  test("every overview KPI and nav scene has an explanation", () => {
    for (const k of ids(/\$\{kpi\("(\w+)"/g)) assert.ok(EXPLAIN["kpi." + k], "missing kpi." + k);
    const scenes = ids(/\["scene",\s*"(\w+)"/g);
    assert.ok(scenes.length >= 5, "expected nav scenes, found " + scenes.length);
    for (const s of scenes) assert.ok(EXPLAIN["scene." + s], "missing scene." + s);
  });

  test("every sidebar tool has an explanation (registry or section help)", async () => {
    const { HELP: a } = await import("../../public/js/section-help-a.js");
    const { HELP: b } = await import("../../public/js/section-help-b.js");
    const tools = ids(/\["tool",\s*"(\w+)"/g);
    assert.ok(tools.length >= 8, "expected sidebar tools, found " + tools.length);
    for (const t of tools) assert.ok(EXPLAIN["tool." + t] || a[t] || b[t], "no explanation for tool " + t);
  });

  test("tipPosition sits below the anchor when it fits", () => {
    const p = tipPosition({ left: 100, top: 100, bottom: 130 }, 300, 80, 1280, 800);
    assert.deepEqual(p, { left: 100, top: 140, side: "below" });
  });

  test("tipPosition flips above near the bottom edge", () => {
    const p = tipPosition({ left: 100, top: 700, bottom: 730 }, 300, 80, 1280, 800);
    assert.equal(p.side, "above");
    assert.equal(p.top, 610);
  });

  test("tipPosition clamps inside the viewport", () => {
    const p = tipPosition({ left: 1200, top: 10, bottom: 40 }, 300, 80, 1280, 800);
    assert.equal(p.left, 1280 - 300 - 8);
    const q = tipPosition({ left: -50, top: 10, bottom: 40 }, 300, 80, 1280, 800);
    assert.equal(q.left, 8);
    const tall = tipPosition({ left: 10, top: 300, bottom: 330 }, 300, 790, 1280, 800);
    assert.ok(tall.top >= 8 || tall.top === 800 - 790 - 8);
  });
});
