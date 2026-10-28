// Native-space lists and run history live in localStorage, which every account signing in on the
// same browser shares; they are keyed by the signed-in uid so the next user does not see them.

import { test, group, assert } from "../harness.mjs";
import { readList, writeList, readRuns, recordRun } from "../../public/js/deck/native/ui.js";

const mem = new Map();
globalThis.localStorage = { getItem: (k) => (mem.has(k) ? mem.get(k) : null), setItem: (k, v) => mem.set(k, String(v)), removeItem: (k) => mem.delete(k) };
globalThis.window = globalThis.window || {};
if (!window.dispatchEvent) window.dispatchEvent = () => {};

group("deck: native space storage is per account", () => {
  test("one account's saved domains and runs are not visible to the next", () => {
    mem.clear();
    window.__dnUid = "userA"; writeList("personal", "certs", ["a.example"]); recordRun("personal", { tool: "certs", target: "1 domain", summary: "ok", level: "good" });
    window.__dnUid = "userB";
    assert.equal(readList("personal", "certs").length, 0); assert.equal(readRuns("personal").length, 0);
    window.__dnUid = "userA";
    assert.equal(readList("personal", "certs").join(), "a.example"); assert.equal(readRuns("personal").length, 1);
  });
  test("data saved before scoping moves to the first signed-in account, once", () => {
    mem.clear(); mem.set("dn_space_org_domains", JSON.stringify(["old.example"]));
    window.__dnUid = "userA"; assert.equal(readList("org", "domains").join(), "old.example");
    assert.equal(mem.has("dn_space_org_domains"), false);
    window.__dnUid = "userB"; assert.equal(readList("org", "domains").length, 0);
  });
  test("no uid, or a per-session guest / Test Mode uid, keeps the plain key", () => {
    mem.clear(); window.__dnUid = null; writeList("personal", "domain", ["x.example"]);
    window.__dnUid = "test-0a1b"; writeList("personal", "certs", ["y.example"]); assert.ok(mem.has("dn_space_personal_certs"));
    assert.ok(mem.has("dn_space_personal_domain"));
  });
});

group("space runs: a re-run replaces the same check only", () => {
  test("a clean email from the same sender domain does not replace a flagged one", () => {
    mem.clear(); window.__dnUid = null;
    recordRun("personal", { tool: "phish", target: "example.com", key: "email <a@example.com>", summary: "Likely phishing", level: "bad" });
    recordRun("personal", { tool: "phish", target: "example.com", key: "email <b@example.com>", summary: "No warning signs", level: "good" });
    assert.equal(readRuns("personal").filter((r) => r.level === "bad").length, 1);
    recordRun("personal", { tool: "phish", target: "example.com", key: "email <a@example.com>", summary: "No warning signs", level: "good" });
    assert.equal(readRuns("personal").length, 2);
    assert.equal(readRuns("personal").filter((r) => r.level === "bad").length, 0);
  });
  test("without a key the target still decides", () => {
    mem.clear(); window.__dnUid = null;
    recordRun("personal", { tool: "domain", target: "example.com", summary: "Grade F", level: "bad" });
    recordRun("personal", { tool: "domain", target: "example.com", summary: "Grade A", level: "good" });
    assert.equal(readRuns("personal").length, 1);
  });
});
