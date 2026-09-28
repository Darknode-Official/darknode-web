// Unit tests for public/js/learndo-data.js (the Learn & Do hub catalog + helpers)
import { readFileSync } from "node:fs";
import { test, group, assert } from "../harness.mjs";
import {
  ACTIVITIES, CATEGORIES, LEVELS,
  filterActivities, progressStats, validActivities,
} from "../../public/js/learndo-data.js";

const read = (p) => readFileSync(new URL(p, import.meta.url), "utf8");
// console-nav.js imports via an absolute "/js/..." URL Node can't resolve, so read the NAV
// section ids straight out of its source: every item is written ["sec","Label"(,"badge")].
const NAV_SRC = read("../../public/js/console-nav.js");
const NAV_SECS = new Set([...NAV_SRC.matchAll(/\["([a-z0-9-]+)","[^"]+"(?:,"[^"]*")?\]/g)].map((m) => m[1]));

group("learndo: catalog integrity", () => {
  test("nav parse sanity (found the real section list)", () => {
    assert.ok(NAV_SECS.size > 100, "expected 100+ nav sections, got " + NAV_SECS.size);
    assert.ok(NAV_SECS.has("learn") && NAV_SECS.has("cyberrange"));
  });

  test("the hub itself is in the nav", () => {
    assert.ok(NAV_SECS.has("learndo"));
  });

  test("every activity points at a REAL nav section (no dead cards)", () => {
    const dead = ACTIVITIES.filter((a) => !NAV_SECS.has(a.sec)).map((a) => a.id + "->" + a.sec);
    assert.deepEqual(dead, []);
  });

  test("the hub's quick-jump chips point at real sections", () => {
    const src = read("../../public/js/learndo.js");
    const secs = [...src.matchAll(/data-sec="([a-z0-9-]+)"/g)].map((m) => m[1]);
    assert.ok(secs.length >= 3);
    assert.deepEqual(secs.filter((s) => !NAV_SECS.has(s)), []);
  });

  test("ids are unique and every field is well-formed", () => {
    const ids = new Set();
    const catIds = new Set(CATEGORIES.map((c) => c.id));
    const levelIds = new Set(LEVELS.map((l) => l.id));
    for (const a of ACTIVITIES) {
      assert.ok(!ids.has(a.id), "duplicate id " + a.id); ids.add(a.id);
      assert.ok(a.title && a.desc, "missing text on " + a.id);
      assert.ok(catIds.has(a.cat), "unknown cat " + a.cat + " on " + a.id);
      assert.ok(levelIds.has(a.level), "unknown level " + a.level + " on " + a.id);
      assert.ok(Number.isFinite(a.mins) && a.mins > 0, "bad mins on " + a.id);
    }
  });

  test("every collection has something to do, at more than one level overall", () => {
    for (const c of CATEGORIES) assert.ok(ACTIVITIES.some((a) => a.cat === c.id), "empty collection " + c.id);
    for (const l of LEVELS) assert.ok(ACTIVITIES.some((a) => a.level === l.id), "no activities at level " + l.id);
  });

  test("home-page copy matches the real catalog size", () => {
    const auth = read("../../public/js/auth.js");
    const m = auth.match(/(\d+) hands-on activities in (\d+) collections/);
    assert.ok(m, "home Learn & Do tile copy not found");
    assert.equal(Number(m[1]), ACTIVITIES.length);
    assert.equal(Number(m[2]), CATEGORIES.length);
  });

  test("the router dispatches the learndo section", () => {
    assert.ok(/sec === "learndo"[^\n]*renderLearnDo/.test(read("../../public/js/auth.js")));
  });

  test("no emojis anywhere in the hub", () => {
    const re = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/u;
    for (const f of ["../../public/js/learndo.js", "../../public/js/learndo-data.js"]) {
      const bad = [...read(f)].filter((ch) => re.test(ch) && ch !== "✓");
      assert.deepEqual(bad, [], f);
    }
  });
});

group("learndo: filterActivities", () => {
  const list = [
    { id: "a", title: "Decode a JWT", desc: "tokens", cat: "web", level: "core" },
    { id: "b", title: "Map DNS", desc: "records", cat: "recon", level: "intro" },
    { id: "c", title: "Fuzz an API", desc: "break it", cat: "web", level: "advanced" },
  ];
  test("'all' / missing opts return everything", () => {
    assert.equal(filterActivities(list, {}).length, 3);
    assert.equal(filterActivities(list, { cat: "all", level: "all", q: "" }).length, 3);
    assert.equal(filterActivities(list).length, 3);
  });
  test("filters by category and level, and combines them", () => {
    assert.deepEqual(filterActivities(list, { cat: "web" }).map((a) => a.id), ["a", "c"]);
    assert.deepEqual(filterActivities(list, { level: "intro" }).map((a) => a.id), ["b"]);
    assert.deepEqual(filterActivities(list, { cat: "web", level: "advanced" }).map((a) => a.id), ["c"]);
  });
  test("search is case-insensitive over title/desc/cat and trims", () => {
    assert.deepEqual(filterActivities(list, { q: "  jwt " }).map((a) => a.id), ["a"]);
    assert.deepEqual(filterActivities(list, { q: "RECORDS" }).map((a) => a.id), ["b"]);
    assert.deepEqual(filterActivities(list, { q: "recon" }).map((a) => a.id), ["b"]);
    assert.deepEqual(filterActivities(list, { q: "nothing-matches" }), []);
  });
  test("null list is safe", () => { assert.deepEqual(filterActivities(null, { cat: "web" }), []); });
});

group("learndo: progressStats", () => {
  test("empty progress", () => {
    const s = progressStats(ACTIVITIES, []);
    assert.equal(s.total, ACTIVITIES.length);
    assert.equal(s.done, 0);
    assert.equal(s.pct, 0);
  });
  test("counts done per category and ignores unknown/blank ids", () => {
    const list = [
      { id: "a", cat: "web" }, { id: "b", cat: "web" }, { id: "c", cat: "recon" },
    ];
    const s = progressStats(list, ["a", "c", "ghost", "", null]);
    assert.equal(s.done, 2);
    assert.equal(s.total, 3);
    assert.equal(s.pct, 67);
    assert.deepEqual(s.byCat.web, { total: 2, done: 1 });
    assert.deepEqual(s.byCat.recon, { total: 1, done: 1 });
  });
  test("every catalog category appears in byCat even when untouched", () => {
    const s = progressStats([], []);
    for (const c of CATEGORIES) assert.deepEqual(s.byCat[c.id], { total: 0, done: 0 });
    assert.equal(s.pct, 0);
  });
});

group("learndo: validActivities", () => {
  test("drops cards whose section vanished; null = keep all", () => {
    const list = [{ id: "a", sec: "learn" }, { id: "b", sec: "gone" }];
    assert.deepEqual(validActivities(list, new Set(["learn"])).map((a) => a.id), ["a"]);
    assert.equal(validActivities(list, null).length, 2);
  });
});
