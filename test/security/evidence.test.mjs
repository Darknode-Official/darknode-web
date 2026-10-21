// Control Evidence engine tests (public/js/compliance/evidence-engine.js): catalogs,
// scoping and bulk create, period maths, readiness, findings (positive and negative),
// tool-run suggestions, SHA-256, auditor package zip, ICS, import, register round-trip.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { test, assert, group } from "../harness.mjs";
import {
  FRAMEWORKS, TOOL_EVIDENCE_MAP, REGISTER_SCHEMA, DEFAULTS,
  checkCatalog, catalogsHaveCrosswalk, normFrequency, normFramework, normControlId, normStatus, scopedRows, bulkCreate, assignOwners,
  addPeriod, addMonths, toDay, analyze, controlState, toolRuns, suggest, suggestionEvidence, sha256HexSync, sha256Hex, isSha256,
  buildPackage, icsEvents, calendarItems, parseInput, importRows, detectMapping, mergeRecords, addHistory, normalizeRecord,
  registerCsv, findingsToCsv, summaryText, exampleDataset, selfTest,
} from "../../public/js/compliance/evidence-engine.js";
import { zipFiles, toIcs } from "../../public/js/core/export.js";
import { unpackAll } from "../../public/js/ingest/unpack.js";
import { openRegister } from "../../public/js/core/register.js";

const here = dirname(fileURLToPath(import.meta.url));
const CAT = {};
for (const f of FRAMEWORKS) CAT[f.key] = JSON.parse(readFileSync(join(here, "../../public/data/controls/" + f.key + ".json"), "utf8"));
const NOW = "2026-10-16";
const ev = (collectedAt, extra = {}) => ({ kind: "file", name: "e-" + collectedAt + ".pdf", sha256: sha256HexSync(collectedAt), size: 10, collectedAt, ...extra });
const rec = (o = {}) => normalizeRecord({ refs: [{ fw: "soc2", id: "CC6.2" }], title: "Access provisioning", owner: "ava@test.darknode.ai", frequency: "quarterly", status: "collected", scopedAt: "2026-01-01", ...o });
const run = (records, opts = {}) => analyze({ records, catalogs: CAT, graphRuns: [] }, { now: NOW, ...opts });
const byCat = (r, c) => r.findings.filter((f) => f.category === c);

group("evidence: catalogs", () => {
  test("all five catalogs load with a valid envelope and unique ids", () => {
    for (const f of FRAMEWORKS) {
      const c = checkCatalog(CAT[f.key]);
      assert.ok(c.ok, f.key + ": " + c.errors.join("; "));
      assert.ok(c.count > 50, f.key + " has " + c.count + " controls");
    }
  });
  test("catalog shape: license, version, updated and the row fields", () => {
    for (const f of FRAMEWORKS) {
      const c = CAT[f.key];
      assert.ok(c.license.length > 40 && /\d{4}-\d{2}-\d{2}/.test(c.updated) && c.version);
      for (const r of c.data) assert.ok(r.id && r.title && r.domain && Array.isArray(r.evidenceHints), f.key + " " + r.id);
    }
  });
  test("every catalog defaultFrequency normalises to a known frequency", () => {
    for (const f of FRAMEWORKS) for (const r of CAT[f.key].data) assert.ok(normFrequency(r.defaultFrequency), f.key + " " + r.id + " " + r.defaultFrequency);
  });
  test("shipped catalogs carry no crosswalk; a catalog with mappings is detected", () => {
    assert.equal(catalogsHaveCrosswalk(CAT), false);
    assert.equal(catalogsHaveCrosswalk({ soc2: { data: [{ id: "CC6.2", mappings: { iso27001: ["5.18"] } }] } }), true);
  });
  test("every tool-to-control mapping id exists in the loaded catalog", () => {
    let n = 0;
    for (const [tool, m] of Object.entries(TOOL_EVIDENCE_MAP)) {
      for (const [fw, ids] of Object.entries(m.refs)) {
        assert.ok(CAT[fw], tool + ": unknown framework " + fw);
        for (const id of ids) { n++; assert.ok(CAT[fw].data.some((r) => r.id === id), tool + ": " + fw + " " + id + " not in catalog"); }
      }
    }
    assert.ok(n > 60);
  });
  test("framework and control id normalisation", () => {
    assert.equal(normFramework("SOC 2 Type II"), "soc2");
    assert.equal(normFramework("ISO/IEC 27001:2022"), "iso27001");
    assert.equal(normFramework("PCI DSS v4.0.1"), "pci4");
    assert.equal(normFramework("CIS Controls v8.1"), "cisv8");
    assert.equal(normFramework("NIST CSF 2.0"), "nistcsf2");
    assert.equal(normFramework("HIPAA"), "");
    assert.equal(normControlId("iso27001", "A.5.18"), "5.18");
    assert.equal(normControlId("soc2", "cc 6.2"), "CC6.2");
    assert.equal(normControlId("pci4", "Req. 11.3.1"), "11.3.1");
    assert.equal(normStatus("Approved"), "accepted");
    assert.equal(normStatus("In progress"), "collecting");
  });
});

group("evidence: scoping and bulk create", () => {
  test("SOC 2 Security only selects the Common Criteria", () => {
    const rows = scopedRows(CAT, { frameworks: ["soc2"] });
    assert.equal(rows.length, CAT.soc2.data.filter((r) => /^CC/.test(r.id)).length);
    assert.ok(rows.every((x) => /^CC/.test(x.row.id)));
  });
  test("SOC 2 categories add only the chosen criteria", () => {
    const rows = scopedRows(CAT, { frameworks: ["soc2"], soc2Categories: ["privacy"] });
    assert.ok(rows.some((x) => x.row.id === "P1.1"));
    assert.ok(!rows.some((x) => /^A1\./.test(x.row.id)));
    assert.ok(!rows.some((x) => /^PI1\./.test(x.row.id)));
  });
  test("CIS IG1 picks the 56 IG1 safeguards; IG3 picks all 153", () => {
    assert.equal(scopedRows(CAT, { frameworks: ["cisv8"], cisIG: 1 }).length, 56);
    assert.equal(scopedRows(CAT, { frameworks: ["cisv8"], cisIG: 3 }).length, 153);
  });
  test("PCI default levels skip the twelve principal requirement rows", () => {
    const rows = scopedRows(CAT, { frameworks: ["pci4"] });
    assert.ok(!rows.some((x) => x.row.level === "requirement"));
    assert.equal(rows.length, CAT.pci4.data.filter((r) => r.level !== "requirement").length);
  });
  test("bulkCreate makes one in-scope record per control with defaults from the catalog", () => {
    const out = bulkCreate(CAT, { frameworks: ["iso27001"], pciLabel: "SAQ D" }, { now: NOW + "T10:00:00Z", by: "ava@test.darknode.ai" });
    assert.equal(out.records.length, 93);
    const r = out.records.find((x) => x.refs[0].id === "5.18");
    assert.equal(r.title, CAT.iso27001.data.find((x) => x.id === "5.18").title);
    assert.equal(r.status, "not-started");
    assert.equal(r.scope, "in");
    assert.equal(r.scopedAt, NOW);
    assert.ok(r.history.length === 1 && r.history[0].by === "ava@test.darknode.ai");
  });
  test("exclusions become out-of-scope records with the reason, shown in the package", () => {
    const out = bulkCreate(CAT, { frameworks: ["soc2"], exclusions: { "soc2:CC6.4": "No company-operated data centre" } }, { now: NOW });
    assert.equal(out.excluded.length, 1);
    assert.equal(out.excluded[0].scope, "out");
    assert.equal(out.excluded[0].outReason, "No company-operated data centre");
    const files = buildPackage(out.records.concat(out.excluded), { now: NOW });
    const ex = files.find((f) => f.name === "exclusions.csv").text;
    assert.ok(ex.includes("out of scope: No company-operated data centre"));
    const r = run(out.records.concat(out.excluded));
    assert.equal(r.summary.outOfScope, 1);
    assert.equal(r.summary.inScope, out.records.length);
  });
  test("bulkCreate keeps existing records, including refs linked into another record", () => {
    const existing = [rec({ refs: [{ fw: "soc2", id: "CC6.2" }, { fw: "iso27001", id: "5.18" }] })];
    const out = bulkCreate(CAT, { frameworks: ["soc2", "iso27001"] }, { existing, now: NOW });
    assert.equal(out.kept, 2);
    assert.ok(!out.records.some((r) => r.refs.some((x) => (x.fw === "soc2" && x.id === "CC6.2") || (x.fw === "iso27001" && x.id === "5.18"))));
  });
  test("assignOwners fills empty owners by domain and overwrites only when asked", () => {
    const a = rec({ id: "a", owner: "", domain: "Logical and Physical Access" });
    const b = rec({ id: "b", owner: "old@test.darknode.ai", domain: "Logical and Physical Access" });
    const map = { "Logical and Physical Access": "noor@test.darknode.ai" };
    assert.deepEqual(assignOwners([a, b], map, { now: NOW }).map((r) => r.id), ["a"]);
    assert.deepEqual(assignOwners([a, b], map, { now: NOW, overwrite: true }).map((r) => r.id).sort(), ["a", "b"]);
  });
});

group("evidence: period maths", () => {
  test("daily and weekly", () => {
    assert.equal(addPeriod("2026-12-31", "daily"), "2027-01-01");
    assert.equal(addPeriod("2026-12-29", "weekly"), "2027-01-05");
  });
  test("monthly clamps Jan 31 to Feb 28, or Feb 29 in a leap year", () => {
    assert.equal(addPeriod("2027-01-31", "monthly"), "2027-02-28");
    assert.equal(addPeriod("2028-01-31", "monthly"), "2028-02-29");
    assert.equal(addPeriod("2026-03-31", "monthly"), "2026-04-30");
    assert.equal(addPeriod("2026-12-15", "monthly"), "2027-01-15");
  });
  test("quarterly and semi-annual clamp to month end", () => {
    assert.equal(addPeriod("2027-11-30", "quarterly"), "2028-02-29");
    assert.equal(addPeriod("2026-11-30", "quarterly"), "2027-02-28");
    assert.equal(addPeriod("2026-08-31", "semi-annual"), "2027-02-28");
    assert.equal(addPeriod("2027-08-31", "semiannual"), "2028-02-29");
  });
  test("annual: Feb 29 rolls to Feb 28, otherwise same day", () => {
    assert.equal(addPeriod("2028-02-29", "annual"), "2029-02-28");
    assert.equal(addPeriod("2026-10-16", "annual"), "2027-10-16");
    assert.equal(addPeriod("2096-02-29", "annual"), "2097-02-28");
  });
  test("continuous follows the configured sample cadence; on-event has no due date", () => {
    assert.equal(addPeriod("2026-01-31", "continuous"), "2026-02-28");
    assert.equal(addPeriod("2026-01-31", "continuous", { continuousPeriod: "weekly" }), "2026-02-07");
    assert.equal(addPeriod("2026-01-31", "on-event"), null);
    assert.equal(addPeriod("2026-01-31", "event"), null);
  });
  test("addMonths handles negative offsets and year boundaries; 2100 is not a leap year", () => {
    assert.equal(addMonths("2026-03-31", -1), "2026-02-28");
    assert.equal(addMonths("2026-01-15", -2), "2025-11-15");
    assert.equal(addMonths("2100-01-31", 1), "2100-02-28");
    assert.equal(addMonths("2000-01-31", 1), "2000-02-29");
  });
  test("toDay parses ISO, ISO datetimes and US m/d/yyyy; rejects impossible dates", () => {
    assert.equal(toDay("2026-10-16T23:30:00Z"), "2026-10-16");
    assert.equal(toDay("3/7/2026"), "2026-03-07");
    assert.equal(toDay("2026-02-30"), null);
    assert.equal(toDay(""), null);
    assert.equal(toDay("not a date"), null);
  });
});

group("evidence: readiness", () => {
  test("readiness = ready / in scope; exceptions counted separately", () => {
    const recs = [
      rec({ id: "r1", evidence: [ev("2026-09-01")] }),
      rec({ id: "r2", status: "accepted", evidence: [ev("2026-08-01")] }),
      rec({ id: "r3", status: "not-started" }),
      rec({ id: "r4", status: "exception", exceptions: [{ reason: "x", approvedBy: "cfo@test.darknode.ai", expires: "2027-01-01" }] }),
    ];
    const r = run(recs);
    const s = r.tables.readiness.find((x) => x.fw === "soc2");
    assert.equal(s.inScope, 4);
    assert.equal(s.ready, 2);
    assert.equal(s.exceptions, 1);
    assert.equal(s.pct, 50);
    assert.equal(r.summary.readiness.soc2, 50);
  });
  test("collected evidence older than its period is stale and not ready", () => {
    const r = run([rec({ evidence: [ev("2026-06-01")] })]); // quarterly: period ended 2026-09-01
    assert.equal(r.tables.controls[0].ready, false);
    assert.equal(r.tables.stale.length, 1);
    assert.equal(r.summary.readiness.soc2, 0);
  });
  test("current evidence with status 'collecting' is not counted ready", () => {
    const r = run([rec({ status: "collecting", evidence: [ev("2026-10-01")] })]);
    assert.equal(r.tables.controls[0].current, true);
    assert.equal(r.tables.controls[0].ready, false);
  });
  test("on-event evidence is current within onEventMonths and has no due date", () => {
    const fresh = controlState(rec({ frequency: "on-event", evidence: [ev("2026-01-10")] }), NOW);
    assert.equal(fresh.current, true);
    assert.equal(fresh.nextDue, null);
    const old = controlState(rec({ frequency: "on-event", evidence: [ev("2025-09-10")] }), NOW);
    assert.equal(old.current, false);
    assert.equal(controlState(rec({ frequency: "on-event", evidence: [ev("2025-09-10")] }), NOW, { onEventMonths: 18 }).current, true);
  });
  test("a record covering two frameworks counts in both", () => {
    const r = run([rec({ refs: [{ fw: "soc2", id: "CC6.2" }, { fw: "iso27001", id: "5.18" }], evidence: [ev("2026-10-01")] })]);
    assert.equal(r.summary.readiness.soc2, 100);
    assert.equal(r.summary.readiness.iso27001, 100);
    assert.equal(r.tables.coverageByDomain.length, 2);
  });
});

group("evidence: findings", () => {
  test("overdue by 30 days or less is medium", () => {
    const r = run([rec({ evidence: [ev("2026-06-20")] })]); // due 2026-09-20, 26 days overdue
    const f = byCat(r, "overdue");
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, "medium");
    assert.ok(f[0].controls.some((c) => c.framework === "SOC2" && c.id === "CC6.2"));
    assert.ok(f[0].controls.some((c) => c.framework === "ISO27001" && c.id === "Clause 9.1"));
    assert.ok(f[0].controls.some((c) => c.id === "Clause 9.2"));
    assert.equal(f[0].assets[0].name, "ava@test.darknode.ai");
  });
  test("overdue threshold edge: exactly overdueHighDays is medium, one more is high", () => {
    const at30 = run([rec({ evidence: [ev("2026-06-16")] })]); // due 2026-09-16 -> 30 days
    assert.equal(at30.tables.controls[0].daysOverdue, 30);
    assert.equal(byCat(at30, "overdue")[0].severity, "medium");
    const at31 = run([rec({ evidence: [ev("2026-06-15")] })]);
    assert.equal(byCat(at31, "overdue")[0].severity, "high");
    assert.equal(byCat(run([rec({ evidence: [ev("2026-06-15")] })], { overdueHighDays: 31 }), "overdue")[0].severity, "medium");
  });
  test("due today or later is not overdue; due-soon window edge is inclusive", () => {
    const r = run([rec({ evidence: [ev("2026-07-16")] })]); // due 2026-10-16
    assert.equal(byCat(r, "overdue").length, 0);
    assert.equal(r.summary.dueSoon, 1);
    const later = run([rec({ evidence: [ev("2026-08-15")] })]); // due 2026-11-15 = now + 30
    assert.equal(later.summary.dueSoon, 1);
    assert.equal(run([rec({ evidence: [ev("2026-08-16")] })]).summary.dueSoon, 0);
  });
  test("an active exception suppresses the overdue finding", () => {
    const r = run([rec({ status: "exception", evidence: [ev("2026-03-01")], exceptions: [{ reason: "migration", approvedBy: "cfo@test.darknode.ai", expires: "2026-12-01" }] })]);
    assert.equal(byCat(r, "overdue").length, 0);
    assert.equal(r.summary.exceptions, 1);
    assert.equal(r.tables.exceptionsExpiring.length, 0);
    assert.equal(run([rec({ exceptions: [{ reason: "m", approvedBy: "c", expires: "2026-11-01" }] })]).tables.exceptionsExpiring.length, 1);
  });
  test("due override replaces the computed date; first due counts from scoping", () => {
    const o = run([rec({ evidence: [ev("2026-10-01")], dueOverride: "2026-10-10" })]);
    assert.equal(o.tables.controls[0].dueSource, "override");
    assert.equal(byCat(o, "overdue").length, 1);
    const first = controlState(rec({ scopedAt: "2026-10-01" }), NOW);
    assert.equal(first.nextDue, "2026-10-31");
    assert.equal(first.dueSource, "first");
    assert.equal(controlState(rec({ scopedAt: "2026-10-01" }), NOW, { firstDueDays: 10 }).nextDue, "2026-10-11");
  });
  test("no-owner finding is low and lists the controls; silent when every control has an owner", () => {
    const r = run([rec({ id: "a", owner: "", evidence: [ev("2026-10-01")] }), rec({ id: "b", evidence: [ev("2026-10-01")] })]);
    const f = byCat(r, "ownership");
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, "low");
    assert.equal(f[0].evidenceCount, 1);
    assert.equal(byCat(run([rec({ evidence: [ev("2026-10-01")] })]), "ownership").length, 0);
  });
  test("no-evidence finding is medium; silent once any evidence exists", () => {
    const r = run([rec({ scopedAt: "2026-10-10" })]);
    const f = byCat(r, "coverage");
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, "medium");
    assert.equal(byCat(r, "overdue").length, 0, "first due date not reached yet");
    assert.equal(byCat(run([rec({ evidence: [ev("2026-10-01")] })]), "coverage").length, 0);
  });
  test("expired exception is high; silent while active or once evidence is current", () => {
    const x = { reason: "legacy firewall", approvedBy: "ciso@test.darknode.ai", expires: "2026-10-01" };
    const r = run([rec({ status: "exception", exceptions: [x] })]);
    const f = byCat(r, "exception");
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, "high");
    assert.equal(byCat(r, "overdue").length, 0, "reported once, as the expired exception");
    assert.equal(byCat(run([rec({ status: "exception", exceptions: [{ ...x, expires: "2026-12-01" }] })]), "exception").length, 0);
    assert.equal(byCat(run([rec({ exceptions: [x], evidence: [ev("2026-10-05")] })]), "exception").length, 0);
  });
  test("analysis is deterministic (byte-identical JSON)", () => {
    const ex = exampleDataset(7, { now: NOW, catalogs: CAT });
    const a = analyze({ records: ex.records, catalogs: CAT, graphRuns: ex.graphRuns }, { now: NOW });
    const b = analyze({ records: ex.records.slice().reverse(), catalogs: CAT, graphRuns: ex.graphRuns }, { now: NOW });
    assert.equal(JSON.stringify(a), JSON.stringify(b));
  });
  test("skipped checks are reported, never guessed; empty input is safe", () => {
    const r = analyze([], { now: NOW });
    assert.equal(r.findings.length, 0);
    assert.ok(r.skipped.some((s) => s.check === "catalog titles"));
    assert.ok(r.skipped.some((s) => s.check === "tool-run suggestions"));
    assert.equal(analyze({ records: [], catalogs: CAT, graphRuns: [] }, { now: NOW }).skipped.length, 0);
  });
  test("unknown control ids are listed against the loaded catalog", () => {
    const r = run([rec({ refs: [{ fw: "soc2", id: "CC99.9" }] })]);
    assert.equal(r.tables.unknownRefs.length, 1);
  });
});

group("evidence: suggestions", () => {
  const ents = [
    { id: "1", type: "FINDING", source: "accessreview", severity: "high", updatedAt: "2026-10-12T10:00:00Z", tags: [] },
    { id: "2", type: "FINDING", source: "accessreview", severity: "low", updatedAt: "2026-10-12T11:00:00Z", tags: [] },
    { id: "3", type: "ASSET", source: "accessreview", updatedAt: "2026-10-12T11:00:00Z", tags: [] },
    { id: "4", type: "FINDING", source: "vulnimport", severity: "critical", updatedAt: "2026-10-14T09:00:00Z", tags: ["sample"] },
    { id: "5", type: "FINDING", source: "Code Scanner", updatedAt: "2026-10-14T09:00:00Z", tags: [] },
    { id: "6", type: "INCIDENT", source: "breachclock", updatedAt: "2026-10-14T09:00:00Z", tags: [] },
  ];
  test("tool runs group by tool and day; sample data, unknown tools and other types are ignored", () => {
    const runs = toolRuns(ents);
    assert.equal(runs.length, 1);
    assert.equal(runs[0].tool, "accessreview");
    assert.equal(runs[0].findingCount, 2);
    assert.equal(runs[0].entityCount, 3);
    assert.deepEqual(runs[0].bySeverity, { high: 1, low: 1 });
  });
  test("suggestions only for in-scope mapped ids, and not once attached", () => {
    const recs = [rec({ id: "a" }), rec({ id: "b", refs: [{ fw: "soc2", id: "CC1.1" }] }), rec({ id: "c", refs: [{ fw: "iso27001", id: "5.18" }], scope: "out" })];
    const s = suggest(recs, ents);
    assert.deepEqual(s.map((x) => x.recordId), ["a"]);
    assert.equal(s[0].attached, false);
    const item = suggestionEvidence(s[0], { now: NOW, by: "ava@test.darknode.ai" });
    assert.equal(item.kind, "tool run");
    assert.equal(item.findingCount, 2);
    assert.equal(item.runDate, "2026-10-12");
    const again = suggest([rec({ id: "a", evidence: [item] })], ents);
    assert.equal(again[0].attached, true);
    const r = analyze({ records: [rec({ id: "a", evidence: [item] })], graphRuns: ents }, { now: NOW });
    assert.equal(r.suggestions.length, 0, "attached suggestions are not offered again");
  });
});

group("evidence: hashing", () => {
  test("pure SHA-256 matches the FIPS 180-2 vectors", () => {
    assert.equal(sha256HexSync("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert.equal(sha256HexSync(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert.equal(sha256HexSync("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  });
  test("WebCrypto helper matches the known vector and the pure implementation", async () => {
    assert.ok(globalThis.crypto && globalThis.crypto.subtle);
    assert.equal(await sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const big = new Uint8Array(300001);
    for (let i = 0; i < big.length; i++) big[i] = (i * 31 + 7) & 255;
    assert.equal(await sha256Hex(big), sha256HexSync(big));
    assert.ok(isSha256(await sha256Hex(big)));
    assert.equal(isSha256("abc"), false);
  });
});

group("evidence: package, calendar, import, register", () => {
  test("auditor package zip contains the five files; index carries hashes; no evidence files", async () => {
    const ex = exampleDataset(7, { now: NOW, catalogs: CAT });
    const files = buildPackage(ex.records, { now: NOW, catalogs: CAT, org: ex.org });
    const zip = await zipFiles(files.map((f) => ({ ...f, name: "auditor-package/" + f.name, date: new Date(Date.UTC(2026, 9, 16)) })));
    const { entries } = await unpackAll(zip, { name: "pkg.zip" });
    const names = entries.map((e) => e.name).sort();
    assert.deepEqual(names, ["auditor-package/README.txt", "auditor-package/exceptions.csv", "auditor-package/exclusions.csv", "auditor-package/index.csv", "auditor-package/readiness.txt"]);
    const text = (n) => entries.find((e) => e.name.endsWith(n)).text();
    const idx = text("index.csv");
    assert.ok(idx.startsWith("framework,control_id,title,owner,frequency,status,next_due,current,evidence_name,kind,sha256"));
    const withHash = ex.records.find((r) => r.evidence.length);
    assert.ok(idx.includes(withHash.evidence[0].sha256));
    assert.ok(/not.*included|NOT in this archive/i.test(text("README.txt")));
    assert.ok(text("README.txt").includes("sha256sum"));
    assert.ok(text("readiness.txt").includes("Test Org (synthetic)"));
    const exc = text("exceptions.csv");
    assert.ok(exc.includes(",expired") && exc.includes(",active"));
  });
  test("ICS: one all-day VEVENT per due date in the next 12 months; deterministic; daily rolled up weekly", () => {
    const recs = [
      rec({ id: "q", evidence: [ev("2026-09-01")] }),
      rec({ id: "d", refs: [{ fw: "pci4", id: "10.4.1" }], frequency: "daily", evidence: [ev("2026-10-15")] }),
      rec({ id: "o", refs: [{ fw: "soc2", id: "CC1.1" }], frequency: "annual", evidence: [ev("2025-09-01")] }),
    ];
    const events = icsEvents(recs, { now: NOW });
    const q = events.filter((e) => e.uid.startsWith("q-"));
    assert.deepEqual(q.map((e) => e.start.slice(0, 10)), ["2026-12-01", "2027-03-01", "2027-06-01", "2027-09-01"]);
    const d = events.filter((e) => e.uid.startsWith("d-"));
    assert.ok(d.length >= 52 && d.length <= 54, "weekly checkpoints: " + d.length);
    assert.ok(events.some((e) => e.summary.startsWith("OVERDUE")));
    const ics = toIcs(events);
    assert.ok(ics.startsWith("BEGIN:VCALENDAR\r\n") && ics.trimEnd().endsWith("END:VCALENDAR"));
    assert.equal((ics.match(/BEGIN:VEVENT/g) || []).length, events.length);
    assert.ok(ics.includes("DTSTART;VALUE=DATE:20261201"));
    assert.equal(new Set(events.map((e) => e.uid)).size, events.length);
    assert.equal(toIcs(icsEvents(recs, { now: NOW })), ics);
    assert.ok(calendarItems(recs, { now: NOW }).every((c) => c.date <= "2027-10-16"));
  });
  test("parseInput recognises a register JSON export", () => {
    const p = parseInput([{ name: "evidence-register.json", text: JSON.stringify([rec({ id: "x" })]) }]);
    assert.equal(p.format, "evidence-register");
    assert.equal(p.confidence, "high");
    assert.equal(p.rows[0].id, "x");
  });
  test("CSV evidence spreadsheet: mapping detected with high confidence and rows normalised", () => {
    const csv = [
      "Framework,Control ID,Control Name,Owner,Frequency,Last Collected,Status,Evidence,SHA256,Notes",
      "SOC 2,CC 6.2,User access provisioning,ava@test.darknode.ai,Quarterly,2026-08-01,Done,q3-access-review.xlsx," + sha256HexSync("q3") + ",",
      "SOC 2,CC6.2,User access provisioning,ava@test.darknode.ai,Quarterly,2026-05-02,Done,q2-access-review.xlsx,,",
      "ISO 27001,A.5.18,Access rights,noor@test.darknode.ai,Annually,10/01/2026,Approved,access-policy.pdf,deadbeef,signed",
      "HIPAA,164.308,Security management,,Annually,,,,,",
      "ISO 27001,A.9.9,Not a control,,Weird,,,,,",
    ].join("\n");
    const p = parseInput(csv);
    assert.equal(p.format, "csv");
    assert.equal(p.confidence, "high");
    assert.equal(p.mapping.controlId, "Control ID");
    assert.equal(p.mapping.lastCollected, "Last Collected");
    const res = importRows(p.rows, p.mapping, { catalogs: CAT, now: NOW });
    assert.equal(res.records.length, 3);
    const soc = res.records.find((r) => r.refs[0].id === "CC6.2");
    assert.equal(soc.evidence.length, 2);
    assert.equal(soc.frequency, "quarterly");
    assert.equal(soc.status, "collected");
    assert.ok(isSha256(soc.evidence.find((e) => e.name === "q3-access-review.xlsx").sha256));
    const iso = res.records.find((r) => r.refs[0].id === "5.18");
    assert.equal(iso.status, "accepted");
    assert.equal(iso.evidence[0].collectedAt, "2026-10-01");
    assert.equal(iso.evidence[0].sha256, "");
    assert.ok(res.skipped.some((s) => s.row === 5 && /framework/.test(s.reason)));
    assert.ok(res.warnings.some((w) => w.row === 6 && /not in the loaded catalog/.test(w.reason)));
    assert.ok(res.warnings.some((w) => /SHA-256/.test(w.reason)));
  });
  test("low mapping confidence without a framework column; a default framework still imports", () => {
    const p = parseInput("Ref,Description\nCC7.1,Vulnerability management\n");
    assert.equal(p.confidence, "low");
    assert.equal(detectMapping(["Framework", "Control"]).confidence, "medium");
    const res = importRows(p.rows, { controlId: "Ref", title: "Description" }, { catalogs: CAT, defaultFramework: "soc2", now: NOW });
    assert.equal(res.records[0].refs[0].id, "CC7.1");
    assert.equal(res.records[0].frequency, normFrequency(CAT.soc2.data.find((r) => r.id === "CC7.1").defaultFrequency));
  });
  test("register round-trip with Map storage and a fake graph (CONTROL entities)", () => {
    const m = new Map();
    const storage = { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
    const E = {}; let n = 0;
    const graph = {
      create: (type, name, data, o) => { const e = { id: "g" + (++n), type, name, data, severity: o.severity, status: o.status, source: o.source }; E[e.id] = e; return e; },
      update: (id, u) => Object.assign(E[id], u), remove: (id) => delete E[id],
      list: (type) => Object.values(E).filter((e) => e.type === type), get: (id) => E[id] || null,
    };
    const reg = openRegister("evidence", "CONTROL", { schema: REGISTER_SCHEMA, storage, graph, now: () => NOW + "T11:00:00.000Z" });
    const r0 = rec({ refs: [{ fw: "soc2", id: "CC6.2" }, { fw: "iso27001", id: "5.18" }], evidence: [ev("2026-10-01")] });
    const saved = reg.upsert(r0);
    const e = E[saved.graphId];
    assert.equal(e.type, "CONTROL");
    assert.equal(e.source, "evidence");
    assert.equal(e.data.controlId, "CC6.2");
    assert.equal(e.data.framework, "SOC 2");
    assert.equal(e.data.implementation, "implemented");
    assert.equal(e.data.covers, "SOC 2 CC6.2 + ISO 27001 5.18");
    assert.equal(e.data._full.evidence[0].sha256, sha256HexSync("2026-10-01"));
    storage.setItem("dn_active_ws", "team1");
    const team = openRegister("evidence", "CONTROL", { schema: REGISTER_SCHEMA, storage, graph, now: () => NOW });
    assert.equal(team.list()[0].id, saved.id, "team members see the control from the graph");
    storage.removeItem("dn_active_ws");
    reg.upsert({ ...reg.get(saved.id), status: "not-started", evidence: [] });
    assert.equal(E[saved.graphId].data.implementation, "not-implemented");
    const json = reg.exportJson();
    assert.ok(reg.remove(saved.id));
    assert.equal(Object.keys(E).length, 0);
    const back = reg.importJson(json);
    assert.equal(back.added, 1);
    assert.ok(registerCsv(reg.list()).startsWith("ID,Controls,Title,Domain,Owner,Frequency,Status"));
  });
  test("mergeRecords unions refs, evidence and history and keeps the tighter frequency", () => {
    const a = rec({ id: "a", frequency: "annual", evidence: [ev("2026-01-01")] });
    const b = rec({ id: "b", refs: [{ fw: "iso27001", id: "5.18" }], frequency: "quarterly", evidence: [ev("2026-02-01"), ev("2026-01-01")], exceptions: [{ reason: "r", approvedBy: "x", expires: "" }] });
    const m = mergeRecords(a, b, NOW);
    assert.equal(m.id, "a");
    assert.equal(m.refs.length, 2);
    assert.equal(m.evidence.length, 2, "identical evidence is not duplicated");
    assert.equal(m.exceptions.length, 1);
    assert.equal(m.frequency, "quarterly");
    assert.ok(/Linked ISO 27001 5.18/.test(m.history[m.history.length - 1].action));
  });
  test("history is capped at 50 entries, newest kept", () => {
    let r = rec();
    for (let i = 0; i < 60; i++) r = addHistory(r, "2026-01-01T00:00:" + String(i).padStart(2, "0"), "step " + i);
    assert.equal(r.history.length, 50);
    assert.equal(r.history[49].action, "step 59");
    assert.equal(normalizeRecord({ ...r, history: r.history.concat(r.history) }).history.length, 50);
  });
});

group("evidence: example, exports, selfTest", () => {
  test("synthetic example: ~40 controls, test.darknode.ai owners, two exceptions, overdue items, real digests", () => {
    const ex = exampleDataset(7, { now: NOW, catalogs: CAT });
    assert.ok(ex.records.length >= 38 && ex.records.length <= 42, String(ex.records.length));
    assert.ok(/synthetic/i.test(ex.label) && ex.org === "Test Org (synthetic)");
    assert.ok(ex.records.every((r) => !r.owner || r.owner.endsWith("@test.darknode.ai")));
    assert.equal(ex.records.filter((r) => r.exceptions.length).length, 2);
    assert.ok(ex.records.some((r) => r.refs.length === 2 && r.refs[1].fw === "iso27001"));
    const r = analyze({ records: ex.records, catalogs: CAT }, { now: NOW });
    assert.ok(r.summary.overdue >= 3);
    assert.ok(r.summary.noOwner >= 1);
    assert.ok(r.summary.readiness.soc2 > 0 && r.summary.readiness.soc2 < 100);
    for (const rec0 of ex.records) for (const e of rec0.evidence) assert.ok(isSha256(e.sha256));
    assert.equal(JSON.stringify(exampleDataset(7, { now: NOW, catalogs: CAT })), JSON.stringify(ex));
  });
  test("findingsToCsv header row and escaping", () => {
    const r = run([rec({ evidence: [ev("2026-06-20")], title: 'Has "quotes", commas' })]);
    const csv = findingsToCsv(r.findings);
    const lines = csv.trim().split("\n");
    assert.equal(lines[0], "severity,confidence,category,title,description,recommendation,controls,evidenceCount");
    assert.equal(lines.length, 1 + r.findings.length);
    assert.ok(csv.includes('""quotes""'));
    assert.equal(findingsToCsv([]).trim(), lines[0]);
  });
  test("summary text lists readiness and findings", () => {
    const r = run([rec({ evidence: [ev("2026-06-20")] })]);
    const t = summaryText(r);
    assert.ok(t.includes("SOC 2: 0.0%") && t.includes("Evidence overdue"));
  });
  test("every finding carries controls, confidence and a recommendation", () => {
    const ex = exampleDataset(7, { now: NOW, catalogs: CAT });
    const r = analyze({ records: ex.records, catalogs: CAT }, { now: NOW });
    assert.ok(r.findings.length > 3);
    for (const f of r.findings) {
      assert.ok(f.controls.length >= 1 && ["confirmed", "likely", "review"].includes(f.confidence) && f.recommendation);
      assert.ok((f.evidence || []).length <= 50);
    }
  });
  test("in-engine self-test passes", () => {
    const s = selfTest();
    assert.ok(s.pass, "failed: " + s.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
  test("DEFAULTS are the documented values", () => {
    assert.equal(DEFAULTS.dueSoonDays, 30);
    assert.equal(DEFAULTS.overdueHighDays, 30);
    assert.equal(DEFAULTS.calendarMonths, 12);
  });
});

group("evidence: prototype-key safety (reserved-word external keys)", () => {
  test("normFramework ignores inherited Object.prototype keys", () => {
    // "constructor" normalizes to a key that indexes Object's constructor (truthy);
    // without a hasOwnProperty guard it leaked back as a bogus framework id and crashed
    // the plain-object catalog/tool lookups downstream.
    assert.equal(normFramework("constructor"), "");
    assert.equal(normFramework("__proto__"), "");
    assert.equal(normFramework("toString"), "");
    assert.equal(normFramework("valueOf"), "");
  });
  test("toolRuns tolerates a constructor-source entity without crashing", () => {
    const runs = toolRuns([{ type: "FINDING", source: "constructor", updatedAt: "2026-01-01T00:00:00Z" }]);
    assert.ok(Array.isArray(runs));
    assert.equal(runs.length, 0);
  });
});
