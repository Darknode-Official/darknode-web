// GenAI Security Crosswalk data-contract tests (public/data/crosswalk.json).
// The crosswalk tool (public/js/crosswalk.js) renders straight off this JSON with
// no engine in between, so the data IS the contract. These tests pin the headline
// totals and the record/mapping shapes the UI reads, so a bad data refresh fails
// loudly instead of silently breaking the view.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test, assert, group } from "../harness.mjs";

const dataPath = fileURLToPath(new URL("../../public/data/crosswalk.json", import.meta.url));
const data = JSON.parse(readFileSync(dataPath, "utf8"));

group("crosswalk: headline totals", () => {
  test("51 risks (array length and meta agree)", () => {
    assert.equal(data.risks.length, 51);
    assert.equal(data.meta.totals.risks, 51);
  });
  test("26 frameworks (array length and meta agree)", () => {
    assert.equal(data.frameworks.length, 26);
    assert.equal(data.meta.totals.frameworks, 26);
  });
  test("3771 mappings (declared total equals the summed maps across every risk)", () => {
    const summed = data.risks.reduce((a, r) => a + r.maps.length, 0);
    assert.equal(data.meta.totals.mappings, 3771);
    assert.equal(summed, 3771);
  });
  test("1190 controls declared", () => {
    assert.equal(data.meta.totals.controls, 1190);
  });
});

group("crosswalk: meta shape the UI reads", () => {
  test("meta has a version string", () => {
    assert.equal(typeof data.meta.version, "string");
    assert.ok(data.meta.version.length > 0);
  });
  test("meta.lists entries each have id/label/count", () => {
    assert.ok(Array.isArray(data.meta.lists));
    assert.ok(data.meta.lists.length > 0);
    for (const l of data.meta.lists) {
      assert.equal(typeof l.id, "string");
      assert.equal(typeof l.label, "string");
      assert.equal(typeof l.count, "number");
    }
  });
});

group("crosswalk: framework record shape", () => {
  test("every framework has a non-empty name", () => {
    for (const f of data.frameworks) {
      assert.equal(typeof f.name, "string");
      assert.ok(f.name.length > 0);
    }
  });
  test("framework names are unique", () => {
    const names = data.frameworks.map((f) => f.name);
    assert.equal(new Set(names).size, names.length);
  });
});

group("crosswalk: risk + mapping record shape", () => {
  test("every risk has id, name, list, sev, aud[] and maps[]", () => {
    for (const r of data.risks) {
      assert.equal(typeof r.id, "string", "risk id");
      assert.ok(r.id.length > 0, "risk id non-empty");
      assert.equal(typeof r.name, "string", "risk name");
      assert.equal(typeof r.list, "string", "risk list");
      assert.equal(typeof r.sev, "string", "risk sev");
      assert.ok(Array.isArray(r.aud), "risk aud array (" + r.id + ")");
      assert.ok(Array.isArray(r.maps), "risk maps array (" + r.id + ")");
      assert.ok(r.maps.length > 0, "risk has at least one mapping (" + r.id + ")");
    }
  });
  test("risk ids are unique", () => {
    const ids = data.risks.map((r) => r.id);
    assert.equal(new Set(ids).size, ids.length);
  });
  test("every risk.list resolves to a declared meta.lists id", () => {
    const listIds = new Set(data.meta.lists.map((l) => l.id));
    for (const r of data.risks) {
      assert.ok(listIds.has(r.list), "risk " + r.id + " references unknown list " + r.list);
    }
  });
  test("every mapping has framework (f) and control code (c)", () => {
    for (const r of data.risks) {
      for (const m of r.maps) {
        assert.equal(typeof m.f, "string", "mapping framework (" + r.id + ")");
        assert.ok(m.f.length > 0, "mapping framework non-empty (" + r.id + ")");
        assert.equal(typeof m.c, "string", "mapping control code (" + r.id + ")");
      }
    }
  });
  test("every mapping framework name exists in the frameworks list", () => {
    const fwNames = new Set(data.frameworks.map((f) => f.name));
    for (const r of data.risks) {
      for (const m of r.maps) {
        assert.ok(fwNames.has(m.f), "mapping in " + r.id + " references unknown framework " + m.f);
      }
    }
  });
});
