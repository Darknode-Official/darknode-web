// public/js/deck/routes.js isAppPath: the signed-out site shows "Page not found" only for paths
// the signed-in app does not open. Every Deck nav entry, scene and console page must count as
// an app path (checked against the real registries), and a mistyped path must not.
import { test, group, assert } from "../harness.mjs";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { isAppPath, SCENES, SCENE_PATH } from "../../public/js/deck/routes.js";
import { parseNavDef, parseBlurbs, parseConsoleNavIds } from "../../scripts/lib/deck-registry.mjs";

const JS = join(dirname(fileURLToPath(import.meta.url)), "../../public/js");
const read = (f) => readFileSync(join(JS, f), "utf8");
const deck = read("deck-ui.js"), auth = read("auth.js"), cnav = read("console-nav.js");
const retired = new Set([...(cnav.match(/export const RETIRED = new Set\(\[([^\]]*)/) || [, ""])[1].matchAll(/"([\w-]+)"/g)].map((m) => m[1]));
// the same three sources auth.js appSecs() reads: console catalog, retired ids, the Deck's own tools
const secs = new Set([...parseConsoleNavIds(cnav), ...retired, ...parseBlurbs(auth).keys()]);

group("deck routes: isAppPath", () => {
  test("every Deck nav entry opens as an app path", () => {
    const nav = parseNavDef(deck);
    const items = nav.groups.flatMap((g) => g.items);
    assert.ok(items.length > 20, "nav parsed");
    const missing = items.filter((i) => !isAppPath("/" + (i.kind === "scene" ? (SCENE_PATH[i.id] ?? i.id) : i.id), secs)).map((i) => i.id);
    assert.deepEqual(missing, []);
  });
  test("scenes, sections, spaces, console links and the home page are app paths", () => {
    for (const k of Object.keys(SCENES)) if (k !== "section") assert.ok(isAppPath("/" + (SCENE_PATH[k] ?? k), secs), k);
    for (const p of ["/", "/index.html", "/area/exposure", "/personal/certs", "/enterprise/team", "/console", "/console/dns", "/console/emailauth/", "/all-tools", "/compliance-center"])
      assert.ok(isAppPath(p, secs), p);
  });
  test("mistyped paths and removed pages are not app paths", () => {
    for (const p of ["/nonexistent-page-xyz", "/get-started", "/tool-zzz-nope", "/emailauth/extra", "/area/a/b", "/console/nope-nope"])
      assert.notOk(isAppPath(p, secs), p);
  });
  test("a shareable domain check is an app path, one segment only", () => {
    for (const p of ["/check/example.com", "/check/example.com/", "/check/xn--bcher-kva.example"]) assert.ok(isAppPath(p, secs), p);
    for (const p of ["/check", "/check/", "/check/a/b"]) assert.notOk(isAppPath(p, secs), p);
  });
  test("hyphenated paths map to camelCase section ids", () => {
    assert.ok(isAppPath("/a-b", new Set(["aB"])));
    assert.notOk(isAppPath("/a-b", new Set(["a-b"])));
    assert.ok(isAppPath("/tool-x-y", new Set(["tool-x-y"])));
  });
});
