// Unit tests for public/js/core/registry.js
import { test, group, assert } from "../harness.mjs";
import { Registry } from "../../public/js/core/registry.js";

const seed = (reg) => reg.registerAll([
  { id: "port-scan", label: "Port Scanner", category: "Recon", module: "/js/port-scan.js", keywords: ["nmap", "ports"], order: 10 },
  { id: "dns-recon", label: "DNS Recon", category: "Recon", module: "/js/dns.js", render: "renderDns", order: 20 },
  { id: "phantom", label: "PHANTOM", category: "Flagships", module: "/js/phantom.js", flagship: true, order: 1, aliases: ["phantom-suite"] },
  { id: "case-detail", label: "Case Detail", category: "Cases", module: "/js/case.js", hidden: true, order: 30 },
]);

group("registry: registration + validation", () => {
  test("registers valid routes and reports size", () => {
    const reg = new Registry();
    assert.equal(seed(reg), 4);
    assert.equal(reg.size, 4);
  });

  test("rejects invalid ids and missing fields", () => {
    const reg = new Registry();
    assert.throws(() => reg.register({ id: "Bad Id", label: "x", module: "/m.js" }));
    assert.throws(() => reg.register({ id: "ok", module: "/m.js" })); // no label
    assert.throws(() => reg.register({ id: "ok", label: "x" })); // no module
  });

  test("rejects duplicate ids and colliding aliases", () => {
    const reg = new Registry();
    reg.register({ id: "a", label: "A", module: "/a.js" });
    assert.throws(() => reg.register({ id: "a", label: "A2", module: "/a2.js" }));
    reg.register({ id: "b", label: "B", module: "/b.js", aliases: ["bee"] });
    assert.throws(() => reg.register({ id: "bee", label: "C", module: "/c.js" })); // id collides with alias
    assert.throws(() => reg.register({ id: "d", label: "D", module: "/d.js", aliases: ["a"] })); // alias collides with id
  });
});

group("registry: lookup", () => {
  test("get resolves ids and aliases", () => {
    const reg = new Registry(); seed(reg);
    assert.equal(reg.get("phantom").label, "PHANTOM");
    assert.equal(reg.get("phantom-suite").id, "phantom");
    assert.equal(reg.get("nope"), null);
    assert.ok(reg.has("dns-recon"));
    assert.notOk(reg.has("ghost"));
  });

  test("list hides hidden by default, sorts by order", () => {
    const reg = new Registry(); seed(reg);
    const ids = reg.list().map((r) => r.id);
    assert.deepEqual(ids, ["phantom", "port-scan", "dns-recon"]); // case-detail hidden
    assert.ok(reg.list({ includeHidden: true }).some((r) => r.id === "case-detail"));
  });

  test("categories in order, byCategory groups", () => {
    const reg = new Registry(); seed(reg);
    assert.deepEqual(reg.categories(), ["Flagships", "Recon"]);
    const groups = reg.byCategory();
    assert.equal(groups.Recon.length, 2);
    assert.equal(groups.Flagships[0].id, "phantom");
  });

  test("flagships filter", () => {
    const reg = new Registry(); seed(reg);
    assert.deepEqual(reg.flagships().map((r) => r.id), ["phantom"]);
  });
});

group("registry: search", () => {
  test("exact label match ranks first", () => {
    const reg = new Registry(); seed(reg);
    assert.equal(reg.search("port scanner")[0].id, "port-scan");
  });

  test("keyword hit finds a tool", () => {
    const reg = new Registry(); seed(reg);
    const res = reg.search("nmap");
    assert.equal(res[0].id, "port-scan");
  });

  test("prefix beats substring", () => {
    const reg = new Registry(); seed(reg);
    const res = reg.search("dns");
    assert.equal(res[0].id, "dns-recon");
  });

  test("empty query returns nothing", () => {
    const reg = new Registry(); seed(reg);
    assert.deepEqual(reg.search(""), []);
  });

  test("respects limit", () => {
    const reg = new Registry(); seed(reg);
    assert.ok(reg.search("re", { limit: 1 }).length <= 1);
  });
});

group("registry: load", () => {
  test("loads a module via injected loader and returns the render fn", async () => {
    const fake = async (spec) => ({ render: () => `rendered ${spec}` });
    const reg = new Registry({ loader: fake });
    reg.register({ id: "x", label: "X", module: "/x.js" });
    const { route, render } = await reg.load("x");
    assert.equal(route.id, "x");
    assert.equal(render(), "rendered /x.js");
  });

  test("uses the route's custom render export name", async () => {
    const fake = async () => ({ renderDns: () => "dns!" });
    const reg = new Registry({ loader: fake });
    reg.register({ id: "d", label: "D", module: "/d.js", render: "renderDns" });
    const { render } = await reg.load("d");
    assert.equal(render(), "dns!");
  });

  test("throws when the export is missing", async () => {
    const fake = async () => ({ somethingElse: () => {} });
    const reg = new Registry({ loader: fake });
    reg.register({ id: "d", label: "D", module: "/d.js" });
    let threw = false;
    try { await reg.load("d"); } catch (_) { threw = true; }
    assert.ok(threw);
  });

  test("throws for unknown route", async () => {
    const reg = new Registry({ loader: async () => ({}) });
    let threw = false;
    try { await reg.load("ghost"); } catch (_) { threw = true; }
    assert.ok(threw);
  });
});
