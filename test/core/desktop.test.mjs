// Unit tests for public/js/core/desktop.js (desktop-app detection).
import { test, group, assert } from "../harness.mjs";
import { isDesktop, caps, has, info, syncTitlebar, filteredRgb } from "../../public/js/core/desktop.js";

const app = (extra = {}) => ({ darknode: { desktop: { version: "2.54.0", platform: "linux", arch: "x64", caps: ["auth.google", "titlebar", 7] }, ...extra } });

group("desktop", () => {
  test("a plain browser is not desktop", () => {
    assert.equal(isDesktop({}), false);
    assert.deepEqual(caps({}), []);
    assert.equal(has("auth.google", {}), false);
    assert.equal(info({}), null);
  });
  test("the site's own window.darknode namespace alone is not desktop", () => {
    assert.equal(isDesktop({ darknode: { control: () => {} } }), false);
    assert.equal(isDesktop({ darknode: { desktop: { caps: "auth.google" } } }), false);
  });
  test("reads version, platform and string caps", () => {
    const g = app();
    assert.equal(isDesktop(g), true);
    assert.deepEqual(caps(g), ["auth.google", "titlebar"]);
    assert.equal(has("titlebar", g), true);
    assert.equal(has("fs", g), false);
    assert.deepEqual(info(g), { version: "2.54.0", platform: "linux", arch: "x64", caps: ["auth.google", "titlebar"] });
  });
  test("a throwing getter is treated as not desktop", () => {
    const g = {}; Object.defineProperty(g, "darknode", { get() { throw new Error("x"); } });
    assert.equal(isDesktop(g), false);
  });
  test("syncTitlebar sends the top bar colours and height", () => {
    const sent = [];
    const g = app({ titlebar: (o) => sent.push(o) });
    g.getComputedStyle = () => ({ backgroundColor: "rgb(255, 255, 255)", color: "rgb(31, 41, 55)" });
    g.MutationObserver = class { observe() {} };
    g.requestAnimationFrame = (f) => f();
    const doc = { getElementById: () => ({ getBoundingClientRect: () => ({ height: 48 }) }), body: {}, documentElement: {} };
    syncTitlebar(doc, g);
    assert.deepEqual(sent[0], { color: "#ffffff", symbolColor: "#1f2937", height: 48 });
  });
  test("syncTitlebar is a no-op without the titlebar capability", () => {
    let called = false;
    const g = { darknode: { desktop: { caps: [] }, titlebar: () => { called = true; } } };
    syncTitlebar({ getElementById: () => null, body: {}, documentElement: {} }, g);
    assert.equal(called, false);
  });
  test("filteredRgb reproduces invert + hue-rotate (the Deck's ink header)", () => {
    assert.deepEqual(filteredRgb([255, 255, 255], "invert(1)"), [0, 0, 0]);
    assert.deepEqual(filteredRgb([10, 20, 30], "none"), [10, 20, 30]);
    assert.deepEqual(filteredRgb([10, 20, 30], "hue-rotate(0deg)"), [10, 20, 30]);
    const [r, g, b] = filteredRgb([230, 229, 226], "invert(1) hue-rotate(180deg)");
    assert.ok(r < 40 && g < 40 && b < 40, "light grey header shows as near-black");
  });
  test("syncTitlebar follows the Deck header when the Deck is mounted", () => {
    const sent = [];
    const g = app({ titlebar: (o) => sent.push(o) });
    const dkTop = { id: "dk", getBoundingClientRect: () => ({ height: 56 }) };
    g.getComputedStyle = (el) => el === dkTop ? { backgroundColor: "rgb(255, 255, 255)", color: "rgb(0, 0, 0)", filter: "invert(1)" } : { backgroundColor: "rgb(1, 2, 3)", color: "rgb(4, 5, 6)" };
    g.MutationObserver = class { observe() {} };
    g.requestAnimationFrame = (f) => f();
    const doc = { querySelector: (q) => (q === "body > .dk .dk-top" ? dkTop : null), getElementById: () => ({ getBoundingClientRect: () => ({ height: 48 }) }), body: {}, documentElement: {} };
    syncTitlebar(doc, g);
    assert.deepEqual(sent[0], { color: "#000000", symbolColor: "#ffffff", height: 56 });
  });
});
