// Unit tests for public/js/core/tool-modes.js (pure logic; DOM verified in-browser)
import { test, group, assert } from "../harness.mjs";
import {
  MODES, MODE_IDS, DEFAULT_MODE, isMode, modeInfo, modeAccent,
  filterTabsByMode, availableModes, getToolMode, setToolMode, switcherHtml,
} from "../../public/js/core/tool-modes.js";

const tabs = [
  { id: "overview", label: "Overview" }, // agnostic
  { id: "recon", label: "Recon", modes: ["scouting"] },
  { id: "monitor", label: "Monitor", modes: ["defensive"] },
  { id: "attack", label: "Attack Sim", modes: ["offensive"] },
  { id: "map", label: "Map", modes: ["scouting", "defensive"] },
];

group("tool-modes: catalog", () => {
  test("three canonical modes in order", () => {
    assert.deepEqual(MODE_IDS, ["scouting", "defensive", "offensive"]);
    assert.equal(DEFAULT_MODE, "defensive");
    assert.equal(MODES.length, 3);
  });

  test("isMode / modeInfo / modeAccent", () => {
    assert.ok(isMode("offensive"));
    assert.notOk(isMode("chaos"));
    assert.equal(modeInfo("scouting").label, "SCOUTING");
    assert.equal(modeAccent("offensive"), "#dc2626");
    assert.equal(modeAccent("bogus"), modeAccent("defensive")); // safe fallback
  });
});

group("tool-modes: tab filtering", () => {
  test("agnostic tabs show in every mode", () => {
    for (const m of MODE_IDS) {
      assert.ok(filterTabsByMode(tabs, m).some((t) => t.id === "overview"));
    }
  });

  test("tagged tabs show only in their modes", () => {
    assert.deepEqual(filterTabsByMode(tabs, "scouting").map((t) => t.id), ["overview", "recon", "map"]);
    assert.deepEqual(filterTabsByMode(tabs, "defensive").map((t) => t.id), ["overview", "monitor", "map"]);
    assert.deepEqual(filterTabsByMode(tabs, "offensive").map((t) => t.id), ["overview", "attack"]);
  });

  test("empty modes array is treated as agnostic", () => {
    const t = [{ id: "x", modes: [] }];
    assert.equal(filterTabsByMode(t, "offensive").length, 1);
  });
});

group("tool-modes: availableModes", () => {
  test("returns only postures that have tabs", () => {
    const only = [{ id: "a", modes: ["scouting"] }, { id: "b", modes: ["defensive"] }];
    assert.deepEqual(availableModes(only).map((m) => m.id), ["scouting", "defensive"]);
  });

  test("agnostic-only tool still offers all three", () => {
    assert.deepEqual(availableModes([{ id: "a" }]).map((m) => m.id), MODE_IDS);
  });

  test("mixed keeps declared order (scouting, defensive, offensive)", () => {
    assert.deepEqual(availableModes(tabs).map((m) => m.id), MODE_IDS);
  });
});

group("tool-modes: persistence", () => {
  test("get returns default before any set", () => {
    assert.equal(getToolMode("brand-new-tool-xyz"), DEFAULT_MODE);
    assert.equal(getToolMode("brand-new-tool-xyz", "scouting"), "scouting");
  });

  test("set then get round-trips; invalid mode rejected", () => {
    assert.ok(setToolMode("navarch", "offensive"));
    assert.equal(getToolMode("navarch"), "offensive");
    assert.notOk(setToolMode("navarch", "nope"));
    assert.equal(getToolMode("navarch"), "offensive"); // unchanged
  });

  test("invalid stored fallback still yields a valid mode", () => {
    assert.ok(isMode(getToolMode("navarch", "garbage")));
  });
});

group("tool-modes: switcherHtml", () => {
  test("marks the active mode and renders all", () => {
    const html = switcherHtml(MODES, "offensive");
    assert.ok(html.includes('data-mode="offensive"'));
    assert.ok(html.includes('data-mode-id="scouting"'));
    assert.ok(html.includes('data-mode-id="offensive"'));
    // active one carries the 'on' class
    assert.ok(/class="dn-modebtn on"[^>]*data-mode-id="offensive"/.test(html) || html.includes('dn-modebtn on'));
  });
});
