// Unit tests for public/js/core/sink-map.js (pure half of the findings sink)
import { test, group, assert } from "../harness.mjs";
import { DATA_CAP, findingKey, fitUnder, dedupe, toEntities, summarize } from "../../public/js/core/sink-map.js";

const T = "vendor-risk";
const f1 = {
  title: "Vendor lacks SOC 2", severity: "high", confidence: "likely", category: "third-party",
  description: "No current SOC 2 report on file.", recommendation: "Request report.",
  controls: [{ framework: "ISO27001", id: "A.15.1.1" }, { framework: "NIST-CSF", id: "ID.SC-2" }],
  assets: [{ type: "VENDOR", name: "Acme Payroll" }, { type: "DOMAIN", name: "acme.example" }],
  evidence: [{ k: 1 }, { k: 2 }], tags: ["tprm"],
};
const f2 = {
  title: "Vendor holds bank details without dual control", severity: "critical", confidence: "confirmed",
  category: "payments", controls: [{ framework: "ISO27001", id: "A.15.1.1" }],
  assets: [{ type: "VENDOR", name: "Acme Payroll", data: { tier: "critical" } }],
};
const shuffle = (a) => a.slice().sort(() => 0.5 - Math.random());
const sortItems = (x) => x.items.map((i) => i.type + ":" + i.name);

group("sink-map: findingKey", () => {
  test("stable across calls and independent of asset order", () => {
    const a = findingKey(T, f1);
    const b = findingKey(T, { ...f1, assets: f1.assets.slice().reverse() });
    assert.equal(a, b);
    assert.equal(a, findingKey(T, f1));
  });
  test("uses f.id when present", () => {
    assert.equal(findingKey(T, { id: "X1", title: "a" }), findingKey(T, { id: "X1", title: "b" }));
  });
  test("differs by tool, title, category", () => {
    assert.notEqual(findingKey(T, f1), findingKey("other", f1));
    assert.notEqual(findingKey(T, f1), findingKey(T, { ...f1, title: f1.title + "!" }));
    assert.notEqual(findingKey(T, f1), findingKey(T, { ...f1, category: "x" }));
  });
});

group("sink-map: dedupe", () => {
  test("last wins, first-seen order kept, dropped counted", () => {
    const later = { ...f1, severity: "low" };
    const r = dedupe([f1, f2, later], T);
    assert.equal(r.findings.length, 2);
    assert.equal(r.dropped, 1);
    assert.equal(r.findings[0].severity, "low");
    assert.equal(r.findings[1], f2);
  });
  test("no duplicates: passthrough", () => {
    const r = dedupe([f1, f2], T);
    assert.deepEqual(r.findings, [f1, f2]);
    assert.equal(r.dropped, 0);
  });
});

group("sink-map: fitUnder", () => {
  const big = { description: "d".repeat(5000), evidence: Array.from({ length: 200 }, (_, i) => ({ i, blob: "x".repeat(400) })) };
  test("returns input copy unchanged when under cap", () => {
    const d = { a: 1, evidence: [1, 2] };
    const out = fitUnder(d, 1000);
    assert.deepEqual(out, d);
    assert.notEqual(out, d);
  });
  test("drops evidence rows from the end until under cap, flags truncation", () => {
    const out = fitUnder(big, 20000);
    assert.ok(JSON.stringify(out).length <= 20000, "under cap");
    assert.equal(out.evidenceTruncated, true);
    assert.equal(out.evidenceCount, 200);
    assert.ok(out.evidence.length > 0 && out.evidence.length < 200);
    assert.equal(out.evidence[0].i, 0, "kept from the front");
  });
  test("never mutates the input", () => {
    const snap = JSON.stringify(big);
    fitUnder(big, 3000);
    assert.equal(JSON.stringify(big), snap);
  });
  test("falls through to description cut and evidence drop", () => {
    const out = fitUnder(big, 3000);
    assert.ok(JSON.stringify(out).length <= 3000);
    assert.equal(out.description.length, 2000);
    assert.notOk("evidence" in out);
    assert.equal(out.evidenceTruncated, true);
    assert.equal(out.evidenceCount, 200);
  });
  test("default cap is DATA_CAP (below the worker's 40000 limit)", () => {
    assert.ok(DATA_CAP < 40000);
    const out = fitUnder({ evidence: Array.from({ length: 2000 }, () => ({ s: "y".repeat(100) })) });
    assert.ok(JSON.stringify(out).length <= DATA_CAP);
  });
});

group("sink-map: toEntities", () => {
  test("deterministic regardless of input order", () => {
    const a = toEntities(T, [f1, f2], { dataset: "q3" });
    const b = toEntities(T, shuffle([f2, f1]), { dataset: "q3" });
    assert.deepEqual(a, b);
  });
  test("FINDING name contains tool id and finding key; data carries key", () => {
    const { items } = toEntities(T, [f1]);
    const fi = items.find((i) => i.type === "FINDING");
    const key = findingKey(T, f1);
    assert.ok(fi.name.endsWith(`(${T}:${key})`), fi.name);
    assert.ok(fi.name.startsWith(f1.title));
    assert.equal(fi.data.findingKey, key);
    assert.equal(fi.data.tool, T);
    assert.equal(fi.data.evidenceCount, 2);
    assert.deepEqual(fi.data.assets, ["Acme Payroll", "acme.example"]);
  });
  test("FINDING opts: severity, status default open, tags include sink + tool", () => {
    const fi = toEntities(T, [f1]).items.find((i) => i.type === "FINDING");
    assert.equal(fi.opts.severity, "high");
    assert.equal(fi.opts.status, "open");
    assert.deepEqual(fi.opts.tags, ["sink", T, "tprm"]);
    const fs = toEntities(T, [{ ...f1, status: "resolved", severity: "bogus" }]).items.find((i) => i.type === "FINDING");
    assert.equal(fs.opts.status, "resolved");
    assert.equal(fs.opts.severity, "info");
  });
  test("assets shared by two findings produce one item, two affects links", () => {
    const { items, links } = toEntities(T, [f1, f2]);
    const vendors = items.filter((i) => i.type === "VENDOR");
    assert.equal(vendors.length, 1);
    assert.equal(vendors[0].name, "Acme Payroll");
    const toVendor = links.filter((l) => l.to === "VENDOR:Acme Payroll" && l.rel === "affects");
    assert.equal(toVendor.length, 2);
    assert.ok(toVendor.every((l) => l.from.startsWith("FINDING:")));
  });
  test("CONTROL items named `framework id`, link CONTROL→FINDING mitigates, shared controls merge", () => {
    const { items, links } = toEntities(T, [f1, f2]);
    const controls = items.filter((i) => i.type === "CONTROL").map((i) => i.name);
    assert.deepEqual(controls, ["ISO27001 A.15.1.1", "NIST-CSF ID.SC-2"]);
    const c = items.find((i) => i.name === "ISO27001 A.15.1.1");
    assert.deepEqual(c.data, { framework: "ISO27001", controlId: "A.15.1.1" });
    const mit = links.filter((l) => l.from === "CONTROL:ISO27001 A.15.1.1");
    assert.equal(mit.length, 2);
    assert.ok(mit.every((l) => l.rel === "mitigates" && l.to.startsWith("FINDING:")));
  });
  test("items sorted by (type, name) and links sorted", () => {
    const { items, links } = toEntities(T, [f2, f1]);
    const keys = sortItems({ items });
    assert.deepEqual(keys, keys.slice().sort());
    const lk = links.map((l) => l.from + l.rel + l.to);
    assert.deepEqual(lk, lk.slice().sort());
  });
  test("sample:true tags every item sample; real run tags none", () => {
    const s = toEntities(T, [f1, f2], { sample: true });
    assert.ok(s.items.length >= 5);
    assert.ok(s.items.every((i) => i.opts.tags.includes("sample")));
    const r = toEntities(T, [f1, f2]);
    assert.ok(r.items.every((i) => !i.opts.tags.includes("sample")));
  });
  test("asset data passes through; dataset recorded; blank titles skipped", () => {
    const { items } = toEntities(T, [f2, { title: "   " }, null], { dataset: "oct" });
    assert.equal(items.filter((i) => i.type === "FINDING").length, 1);
    assert.deepEqual(items.find((i) => i.type === "VENDOR").data, { tier: "critical" });
    assert.equal(items.find((i) => i.type === "FINDING").data.dataset, "oct");
  });
  test("oversize evidence is fitted under DATA_CAP", () => {
    const huge = { ...f1, evidence: Array.from({ length: 1000 }, (_, i) => ({ i, s: "e".repeat(200) })) };
    const fi = toEntities(T, [huge]).items.find((i) => i.type === "FINDING");
    assert.ok(JSON.stringify(fi.data).length <= DATA_CAP);
    assert.equal(fi.data.evidenceTruncated, true);
    assert.equal(fi.data.evidenceCount, 1000);
  });
});

group("sink-map: summarize", () => {
  test("counts total, severity buckets and confidence", () => {
    const s = summarize([f1, f2, { title: "x", severity: "weird", confidence: 0.4 }, null]);
    assert.equal(s.total, 3);
    assert.deepEqual(s.bySeverity, { critical: 1, high: 1, medium: 0, low: 0, info: 1 });
    assert.deepEqual(s.byConfidence, { likely: 1, confirmed: 1, "0.4": 1 });
  });
  test("empty input", () => {
    assert.deepEqual(summarize([]), { total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, byConfidence: {} });
  });
});
