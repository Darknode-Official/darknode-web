// Breach Clock engine tests (public/js/risk/breachclock-engine.js): every regime's
// deadline maths, state thresholds from a fixture shaped like
// public/data/ref/us-breach-laws.json, safe harbors, law-enforcement delay,
// missing facts, register round-trip, ICS, determinism and selfTest.

import { test, assert, group } from "../harness.mjs";
import {
  assess, analyze, parseInput, parseCounts, parseTime, addCalendarDays, addMonths, addBusinessDays, holidaySet,
  resolveJurisdiction, toFindings, findingsToCsv, checklistToCsv, icsEvents, exportBundle, summaryText, draftNotice,
  exampleDataset, selfTest, REGISTER_SCHEMA, snapshot, VERIFY_LINE, REGIMES, formatLocal,
} from "../../public/js/risk/breachclock-engine.js";
import { openRegister } from "../../public/js/core/register.js";
import { toIcs } from "../../public/js/core/export.js";

// Fixture shaped exactly like public/data/ref/us-breach-laws.json (envelope + record keys).
const LAWS = {
  version: "2026-10", updated: "2026-10-16", verifyWithCounsel: true, sources: ["https://www.ncsl.org/technology-and-communication/security-breach-notification-laws"], notes: "fixture",
  data: [
    { jurisdiction: "California", code: "CA", statute: "Cal. Civ. Code 1798.82", deadlineDays: null, deadlineText: "most expedient time possible and without unreasonable delay", agDeadlineDays: null, agThreshold: 500, creditBureauThreshold: null, substituteNoticeAllowed: true, riskOfHarmTrigger: false, piiDefinitionNotes: "Broad definition: name plus SSN, driver's licence/ID, account number with access code, medical information, health-insurance information, biometric data, passport, tax ID, or username/email with password.", confidence: "curated", sourceUrl: "https://www.ncsl.org/technology-and-communication/security-breach-notification-laws" },
    { jurisdiction: "Colorado", code: "CO", statute: "Colo. Rev. Stat. 6-1-716", deadlineDays: 30, deadlineText: "30 days after determination that a security breach occurred", agDeadlineDays: 30, agThreshold: 500, creditBureauThreshold: 1000, substituteNoticeAllowed: true, riskOfHarmTrigger: true, piiDefinitionNotes: "Name plus SSN, driver's licence/ID, medical information; or username/email with password or security question.", confidence: "curated", sourceUrl: "https://www.ncsl.org/technology-and-communication/security-breach-notification-laws" },
    { jurisdiction: "Connecticut", code: "CT", statute: "Conn. Gen. Stat. 36a-701b", deadlineDays: 60, deadlineText: "60 days after discovery of the breach", agDeadlineDays: 60, agThreshold: 0, creditBureauThreshold: null, substituteNoticeAllowed: true, riskOfHarmTrigger: true, piiDefinitionNotes: "Name plus SSN, taxpayer ID, driver's licence/ID, account number with access code.", confidence: "curated", sourceUrl: "https://www.ncsl.org/technology-and-communication/security-breach-notification-laws" },
    { jurisdiction: "Kansas", code: "KS", statute: "Kan. Stat. 50-7a01 et seq.", deadlineDays: null, deadlineText: "most expedient time possible and without unreasonable delay", agDeadlineDays: null, agThreshold: null, creditBureauThreshold: 1000, substituteNoticeAllowed: true, riskOfHarmTrigger: true, piiDefinitionNotes: "Name plus SSN, driver's licence/ID, or account number with access code.", confidence: "verify", sourceUrl: "https://www.ncsl.org/technology-and-communication/security-breach-notification-laws" },
    { jurisdiction: "Texas", code: "TX", statute: "Tex. Bus. & Com. Code 521.053", deadlineDays: 60, deadlineText: "60 days after determination of the breach", agDeadlineDays: 30, agThreshold: 250, creditBureauThreshold: 10000, substituteNoticeAllowed: true, riskOfHarmTrigger: false, piiDefinitionNotes: "Sensitive personal information: name plus SSN, driver's licence/ID, account number with access code; or health-related information.", confidence: "curated", sourceUrl: "https://www.ncsl.org/technology-and-communication/security-breach-notification-laws" },
  ],
};
const HOL = { version: "2026-10", data: [{ date: "2026-11-11", name: "Veterans Day" }, { date: "2026-11-26", name: "Thanksgiving Day" }, { date: "2026-12-25", name: "Christmas Day" }] };
const ob = (a, id) => a.obligations.find((o) => o.id === id);
const base = { discoveredAt: "2026-01-10T10:00:00Z", encrypted: "no", dataTypes: ["ssn"], harm: "risk", timeZone: "UTC" };
const run = (facts, opts = {}) => assess({ ...base, ...facts }, { now: "2026-01-10T12:00:00Z", breachLaws: LAWS, holidays: HOL, ...opts });

group("breachclock: GDPR / UK GDPR", () => {
  test("Art. 33: 72 hours from discovery", () => {
    const a = run({ sectors: ["eu"] });
    assert.equal(ob(a, "gdpr-33").deadline, "2026-01-13T10:00:00.000Z");
    assert.equal(ob(a, "gdpr-33").deadlineKind, "hours");
    assert.equal(ob(a, "gdpr-33").applies, "likely");
  });
  test("wall-clock input is read in the incident time zone", () => {
    const a = run({ sectors: ["eu"], discoveredAt: "2026-03-02T10:00", timeZone: "Europe/Berlin" });
    assert.equal(ob(a, "gdpr-33").triggerTime, "2026-03-02T09:00:00.000Z");
    assert.equal(ob(a, "gdpr-33").deadline, "2026-03-05T09:00:00.000Z");
    assert.ok(ob(a, "gdpr-33").deadlineLocal.startsWith("2026-03-05 10:00"));
  });
  test("harm unlikely: Art. 33 possible, Art. 34 not indicated", () => {
    const a = run({ sectors: ["eu"], harm: "unlikely" });
    assert.equal(ob(a, "gdpr-33").applies, "possible");
    assert.equal(ob(a, "gdpr-34").applies, "not-indicated");
  });
  test("high risk: Art. 34 likely, no fixed deadline; encryption removes it (Art. 34(3)(a))", () => {
    const a = run({ sectors: ["eu"], harm: "high" });
    assert.equal(ob(a, "gdpr-34").applies, "likely");
    assert.equal(ob(a, "gdpr-34").deadline, null);
    assert.equal(ob(a, "gdpr-34").deadlineKind, "without-undue-delay");
    assert.equal(ob(run({ sectors: ["eu"], harm: "high", encrypted: "yes" }), "gdpr-34").applies, "not-indicated");
  });
  test("EU data subjects without the EU sector: possible (Art. 3(2))", () => {
    const a = run({ sectors: ["general"], counts: [{ jurisdiction: "Germany", count: 40 }] });
    assert.equal(ob(a, "gdpr-33").applies, "possible");
  });
  test("UK GDPR: ICO 72 hours", () => {
    const a = run({ sectors: ["uk"] });
    assert.equal(ob(a, "ukgdpr-33").recipient, "Information Commissioner's Office (ICO)");
    assert.equal(ob(a, "ukgdpr-33").deadline, "2026-01-13T10:00:00.000Z");
    assert.equal(ob(run({ counts: [{ jurisdiction: "United Kingdom", count: 3 }] }), "ukgdpr-33").applies, "possible");
  });
});

group("breachclock: NIS2", () => {
  test("24 h early warning, 72 h notification, 1 month final report", () => {
    const a = run({ sectors: ["nis2"], memberState: "Ireland", nis2Significant: "yes", discoveredAt: "2026-01-30T08:00:00Z" });
    assert.equal(ob(a, "nis2-early").deadline, "2026-01-31T08:00:00.000Z");
    assert.equal(ob(a, "nis2-notify").deadline, "2026-02-02T08:00:00.000Z");
    assert.equal(ob(a, "nis2-final").deadline, "2026-03-02T08:00:00.000Z");
    assert.equal(ob(a, "nis2-early").applies, "likely");
    assert.ok(ob(a, "nis2-early").recipient.includes("Ireland"));
  });
  test("final report counts from the recorded notification time", () => {
    const a = run({ sectors: ["nis2"], nis2Significant: "yes", discoveredAt: "2026-01-30T08:00:00Z" }, { statuses: { "nis2-notify": { state: "sent", at: "2026-01-31T12:00:00Z" } } });
    assert.equal(ob(a, "nis2-final").deadline, "2026-02-28T12:00:00.000Z");
  });
  test("significance drives applicability and missing facts", () => {
    assert.equal(ob(run({ sectors: ["nis2"], nis2Significant: "no" }), "nis2-notify").applies, "not-indicated");
    const a = run({ sectors: ["nis2"] });
    assert.equal(ob(a, "nis2-notify").applies, "possible");
    assert.ok(a.missing.some((m) => m.field === "nis2Significant"));
    assert.ok(a.missing.some((m) => m.field === "memberState"));
  });
  test("addMonths clamps to the end of a shorter month", () => {
    assert.equal(new Date(addMonths(Date.parse("2026-01-31T10:00:00Z"), 1, "UTC")).toISOString(), "2026-02-28T10:00:00.000Z");
  });
});

group("breachclock: SEC Form 8-K Item 1.05", () => {
  test("4 business days across a weekend (Thu -> Wed 5:30 pm ET)", () => {
    const a = run({ sectors: ["sec"], materialityAt: "2026-10-15T14:00:00Z" });
    assert.equal(ob(a, "sec-8k").deadline, "2026-10-21T21:30:00.000Z");
    assert.equal(ob(a, "sec-8k").deadlineKind, "business-days");
    assert.ok(ob(a, "sec-8k").deadlineEt.startsWith("2026-10-21 17:30"));
  });
  test("4 business days across a federal holiday (Thanksgiving)", () => {
    const a = run({ sectors: ["sec"], materialityAt: "2026-11-23T15:00:00Z" });
    assert.equal(ob(a, "sec-8k").deadline, "2026-11-30T22:30:00.000Z");
    assert.ok(ob(a, "sec-8k").why.join(" ").includes("2026-11-26 (holiday)"));
  });
  test("determination on a Saturday counts from Monday", () => {
    const r = addBusinessDays(Date.parse("2026-10-17T15:00:00Z"), 4, holidaySet(HOL));
    assert.equal(r.date, "2026-10-22");
  });
  test("no materiality determination: possible, no deadline, reported missing", () => {
    const a = run({ sectors: ["sec"] });
    assert.equal(ob(a, "sec-8k").applies, "possible");
    assert.equal(ob(a, "sec-8k").deadline, null);
    assert.ok(a.missing.some((m) => m.field === "materialityAt"));
  });
  test("only an Attorney General determination pauses the SEC clock", () => {
    const le = { requested: true, from: "2026-10-16T00:00:00Z", until: "2026-10-26T00:00:00Z" };
    const plain = run({ sectors: ["sec"], materialityAt: "2026-10-15T14:00:00Z", leDelay: le });
    assert.equal(ob(plain, "sec-8k").deadline, "2026-10-21T21:30:00.000Z");
    const ag = run({ sectors: ["sec"], materialityAt: "2026-10-15T14:00:00Z", leDelay: { ...le, agDetermination: true } });
    assert.equal(ob(ag, "sec-8k").deadline, "2026-10-31T21:30:00.000Z");
  });
  test("holiday data absent is reported as skipped", () => {
    const a = run({ sectors: ["sec"], materialityAt: "2026-10-15T14:00:00Z" }, { holidays: null });
    assert.ok(a.skipped.some((s) => s.check === "sec-holidays"));
  });
});

group("breachclock: HIPAA", () => {
  test("individuals: 60 calendar days after discovery", () => {
    const a = run({ sectors: ["hipaa-ce"], dataTypes: ["phi"], total: 20 });
    assert.equal(ob(a, "hipaa-individuals").deadline, "2026-03-11T10:00:00.000Z");
    assert.equal(ob(a, "hipaa-individuals").deadlineKind, "calendar-days");
  });
  test("HHS: 60 days when 500 or more, annual log otherwise", () => {
    assert.equal(ob(run({ sectors: ["hipaa-ce"], dataTypes: ["phi"], total: 500 }), "hipaa-hhs").deadline, "2026-03-11T10:00:00.000Z");
    assert.equal(ob(run({ sectors: ["hipaa-ce"], dataTypes: ["phi"], total: 499 }), "hipaa-hhs").deadline, "2027-03-02T00:00:00.000Z");
  });
  test("media notice only when more than 500 residents of a state", () => {
    const a = run({ sectors: ["hipaa-ce"], dataTypes: ["phi"], counts: [{ jurisdiction: "TX", count: 501 }, { jurisdiction: "CA", count: 500 }] });
    assert.ok(ob(a, "hipaa-media-TX"));
    assert.equal(ob(a, "hipaa-media-CA"), undefined);
  });
  test("encrypted (secured) PHI is not indicated", () => {
    assert.equal(ob(run({ sectors: ["hipaa-ce"], dataTypes: ["phi"], encrypted: "yes", total: 10 }), "hipaa-individuals").applies, "not-indicated");
  });
  test("business associate -> covered entity within 60 days", () => {
    const a = run({ sectors: ["hipaa-ba"], dataTypes: ["medical"] });
    assert.equal(ob(a, "hipaa-ba-ce").deadline, "2026-03-11T10:00:00.000Z");
    assert.equal(ob(a, "hipaa-individuals"), undefined);
  });
  test("law-enforcement delay pauses the HIPAA clock", () => {
    const a = run({ sectors: ["hipaa-ce"], dataTypes: ["phi"], total: 5, leDelay: { requested: true, from: "2026-01-20T10:00:00Z", until: "2026-02-19T10:00:00Z" } });
    assert.equal(ob(a, "hipaa-individuals").deadline, "2026-04-10T10:00:00.000Z");
    assert.equal(ob(a, "hipaa-individuals").lawEnforcementDelay.pausedHours, 720);
  });
});

group("breachclock: GLBA, NYDFS, CERT-In, PIPEDA, NDB, PCI", () => {
  test("GLBA: 30 days, 500-consumer threshold, encryption", () => {
    assert.equal(ob(run({ sectors: ["glba"], total: 500 }), "glba-ftc").deadline, "2026-02-09T10:00:00.000Z");
    assert.equal(ob(run({ sectors: ["glba"], total: 500 }), "glba-ftc").applies, "likely");
    assert.equal(ob(run({ sectors: ["glba"], total: 499 }), "glba-ftc").applies, "not-indicated");
    assert.equal(ob(run({ sectors: ["glba"], total: 5000, encrypted: "yes" }), "glba-ftc").applies, "not-indicated");
  });
  test("NYDFS: 72 hours from determination", () => {
    const a = run({ sectors: ["nydfs"], determinedAt: "2026-01-11T09:00:00Z" });
    assert.equal(ob(a, "nydfs-72h").deadline, "2026-01-14T09:00:00.000Z");
  });
  test("NYDFS: no determination falls back to discovery and is reported missing", () => {
    const a = run({ sectors: ["nydfs"] });
    assert.equal(ob(a, "nydfs-72h").deadline, "2026-01-13T10:00:00.000Z");
    assert.ok(a.missing.some((m) => m.field === "determinedAt"));
    assert.ok(a.skipped.some((s) => s.check === "nydfs-extortion"));
  });
  test("NYDFS extortion payment: 24 hours and 30 days", () => {
    const a = run({ sectors: ["nydfs"], ransomPaidAt: "2026-01-12T00:00:00Z" });
    assert.equal(ob(a, "nydfs-extortion-24h").deadline, "2026-01-13T00:00:00.000Z");
    assert.equal(ob(a, "nydfs-extortion-30d").deadline, "2026-02-11T00:00:00.000Z");
  });
  test("CERT-In: 6 hours from noticing", () => {
    const a = run({ sectors: ["in"] });
    assert.equal(ob(a, "certin-6h").deadline, "2026-01-10T16:00:00.000Z");
    assert.equal(ob(run({ counts: [{ jurisdiction: "India", count: 9 }] }), "certin-6h").applies, "possible");
  });
  test("PIPEDA: as soon as feasible (no fixed deadline); records always kept", () => {
    const a = run({ sectors: ["ca"], harm: "unlikely" });
    assert.equal(ob(a, "pipeda-opc").deadlineKind, "as-soon-as-practicable");
    assert.equal(ob(a, "pipeda-opc").deadline, null);
    assert.equal(ob(a, "pipeda-opc").applies, "not-indicated");
    assert.equal(ob(a, "pipeda-records").applies, "likely");
  });
  test("Australia NDB: assessment within 30 days", () => {
    const a = run({ sectors: ["au"] });
    assert.equal(ob(a, "ndb-assess").deadline, "2026-02-09T10:00:00.000Z");
    assert.equal(ob(a, "ndb-oaic").deadlineKind, "as-soon-as-practicable");
  });
  test("PCI: card numbers without the sector are possible, verify confidence", () => {
    const a = run({ dataTypes: ["pan"] });
    assert.equal(ob(a, "pci-acquirer").applies, "possible");
    assert.equal(ob(a, "pci-acquirer").confidence, "verify");
    assert.equal(ob(a, "pci-acquirer").clock, "immediately, per your acquirer contract");
  });
  test("every built-in regime has a citation, trigger, clock, recipient and https source", () => {
    for (const r of REGIMES) assert.ok(r.citation && r.trigger && r.clock && r.recipients && /^https:\/\//.test(r.sourceUrl), r.id);
  });
});

group("breachclock: US states from reference data", () => {
  test("determination-based clock (Colorado 30 days) uses the determination time", () => {
    const a = run({ counts: [{ jurisdiction: "Colorado", count: 10 }], determinedAt: "2026-01-12T10:00:00Z" });
    assert.equal(ob(a, "us-CO-residents").deadline, "2026-02-11T10:00:00.000Z");
  });
  test("discovery-based clock (Connecticut 60 days)", () => {
    const a = run({ counts: [{ jurisdiction: "CT", count: 10 }], determinedAt: "2026-01-12T10:00:00Z" });
    assert.equal(ob(a, "us-CT-residents").deadline, "2026-03-11T10:00:00.000Z");
  });
  test("no statutory day count: without unreasonable delay, no deadline", () => {
    const o = ob(run({ counts: [{ jurisdiction: "California", count: 10 }] }), "us-CA-residents");
    assert.equal(o.deadline, null);
    assert.equal(o.deadlineKind, "without-undue-delay");
    assert.ok(o.clock.startsWith("deadline not fixed by statute: without unreasonable delay"));
  });
  test("agThreshold 0 means every breach", () => {
    assert.equal(ob(run({ counts: [{ jurisdiction: "CT", count: 1 }] }), "us-CT-regulator").applies, "likely");
  });
  test("regulator threshold: below, exactly at, above", () => {
    const f = (n) => ob(run({ counts: [{ jurisdiction: "Texas", count: n }] }), "us-TX-regulator").applies;
    assert.equal(f(249), "not-indicated");
    assert.equal(f(250), "possible");
    assert.equal(f(251), "likely");
    assert.equal(ob(run({ counts: [{ jurisdiction: "Texas", count: 300 }] }), "us-TX-regulator").deadline, "2026-02-09T10:00:00.000Z");
  });
  test("agThreshold null: no regulator obligation, reported as skipped", () => {
    const a = run({ counts: [{ jurisdiction: "Kansas", count: 5000 }] });
    assert.equal(ob(a, "us-KS-regulator"), undefined);
    assert.ok(a.skipped.some((s) => s.check === "us-KS-regulator"));
  });
  test("credit bureau threshold", () => {
    assert.equal(ob(run({ counts: [{ jurisdiction: "Colorado", count: 1001 }] }), "us-CO-cra").applies, "likely");
    assert.equal(ob(run({ counts: [{ jurisdiction: "Colorado", count: 999 }] }), "us-CO-cra").applies, "not-indicated");
  });
  test("data type not in the state's definition: not indicated", () => {
    assert.equal(ob(run({ dataTypes: ["geo"], counts: [{ jurisdiction: "Kansas", count: 50 }] }), "us-KS-residents").applies, "not-indicated");
    assert.equal(ob(run({ dataTypes: ["emailpw"], counts: [{ jurisdiction: "California", count: 50 }] }), "us-CA-residents").applies, "likely");
  });
  test("encryption safe harbor: not indicated; unknown: possible and missing", () => {
    assert.equal(ob(run({ encrypted: "yes", counts: [{ jurisdiction: "Texas", count: 50 }] }), "us-TX-residents").applies, "not-indicated");
    const a = run({ encrypted: "unknown", counts: [{ jurisdiction: "Texas", count: 50 }] });
    assert.equal(ob(a, "us-TX-residents").applies, "possible");
    assert.ok(a.missing.some((m) => m.field === "encrypted"));
  });
  test("reference confidence 'verify' is carried through", () => {
    assert.equal(ob(run({ counts: [{ jurisdiction: "Kansas", count: 5 }] }), "us-KS-residents").confidence, "verify");
  });
  test("law-enforcement delay pauses state clocks and marks them verify", () => {
    const a = run({ counts: [{ jurisdiction: "CT", count: 5 }], leDelay: { requested: true, until: "2026-01-20T10:00:00Z" } });
    assert.equal(ob(a, "us-CT-residents").deadline, "2026-03-21T10:00:00.000Z");
    assert.equal(ob(a, "us-CT-residents").confidence, "verify");
  });
  test("risk-of-harm exception with harm unlikely: possible", () => {
    assert.equal(ob(run({ harm: "unlikely", counts: [{ jurisdiction: "CT", count: 5 }] }), "us-CT-residents").applies, "possible");
  });
  test("jurisdiction resolution: codes, names, countries, unknown", () => {
    const st = LAWS.data;
    assert.equal(resolveJurisdiction("CA", st).name, "California");
    assert.equal(resolveJurisdiction("US-TX", st).code, "TX");
    assert.equal(resolveJurisdiction("Canada", st).kind, "ca");
    assert.equal(resolveJurisdiction("country:DE", st).name, "Germany");
    assert.equal(resolveJurisdiction("Atlantis", st).kind, "unknown");
    const a = run({ counts: [{ jurisdiction: "Atlantis", count: 3 }] });
    assert.ok(a.skipped.some((s) => s.check === "jurisdiction:Atlantis"));
  });
  test("state rows without the reference file are skipped, not guessed", () => {
    const a = assess({ ...base, counts: [{ jurisdiction: "Texas", count: 5 }] }, { now: "2026-01-10T12:00:00Z" });
    assert.ok(a.skipped.some((s) => s.check === "us-states" || s.check === "jurisdiction:Texas"));
    assert.equal(a.obligations.filter((o) => o.id.startsWith("us-")).length, 0);
  });
});

group("breachclock: time maths and inputs", () => {
  test("calendar days keep local wall-clock time across DST", () => {
    const t = parseTime("2026-10-20T09:00", "America/Chicago");
    const d = addCalendarDays(t, 30, "America/Chicago");
    assert.ok(formatLocal(d, "America/Chicago").startsWith("2026-11-19 09:00"));
  });
  test("parseTime: offsets, wall time, garbage", () => {
    assert.equal(parseTime("2026-01-01T00:00:00+02:00"), Date.parse("2025-12-31T22:00:00Z"));
    assert.equal(parseTime("2026-07-01 12:00", "America/New_York"), Date.parse("2026-07-01T16:00:00Z"));
    assert.equal(parseTime("yesterday"), null);
  });
  test("parseCounts: header, thousands separators, bad rows", () => {
    const r = parseCounts("jurisdiction,count\nCalifornia,\"1,200\"\nTexas\t600\nNew York;300\nOhio,lots\n");
    assert.deepEqual(r.rows, [{ jurisdiction: "California", count: 1200 }, { jurisdiction: "Texas", count: 600 }, { jurisdiction: "New York", count: 300 }]);
    assert.equal(r.skipped.length, 1);
    assert.equal(r.skipped[0].line, 5);
  });
  test("missing facts are listed when the form is empty", () => {
    const a = assess({}, {});
    const fields = a.missing.map((m) => m.field);
    for (const f of ["discoveredAt", "sectors", "dataTypes", "encrypted", "timeZone", "total"]) assert.ok(fields.includes(f), f);
    assert.equal(a.now, null);
  });
  test("unreadable timestamps are reported as skipped", () => {
    assert.ok(run({ determinedAt: "next tuesday" }).skipped.some((s) => s.check === "determinedAt"));
  });
});

group("breachclock: findings, exports, register", () => {
  const facts = { ...base, sectors: ["eu", "in", "glba"], total: 800 };
  test("severity by time left: overdue critical, <24h high, <72h medium, later none", () => {
    const sev = (now) => analyze({ facts }, { now, breachLaws: LAWS }).findings.map((f) => f.id + ":" + f.severity);
    const s1 = sev("2026-01-10T12:00:00Z");
    assert.ok(s1.includes("breachclock:certin-6h:high"));
    assert.ok(s1.includes("breachclock:gdpr-33:medium"));
    assert.ok(!s1.some((x) => x.startsWith("breachclock:glba-ftc")));
    const s2 = sev("2026-01-13T11:00:00Z");
    assert.ok(s2.includes("breachclock:certin-6h:critical"));
    assert.ok(s2.includes("breachclock:gdpr-33:critical"));
  });
  test("sent / not-required obligations raise no finding", () => {
    const r = analyze({ facts, statuses: { "certin-6h": { state: "sent", at: "2026-01-10T14:00:00Z" }, "gdpr-33": { state: "not-required", reason: "no personal data" } } }, { now: "2026-01-10T12:00:00Z" });
    assert.equal(r.findings.length, 0);
  });
  test("findings follow the Deck contract", () => {
    const r = analyze({ facts }, { now: "2026-01-13T11:00:00Z" });
    assert.ok(r.findings.length > 0);
    for (const f of r.findings) {
      assert.ok(["critical", "high", "medium"].includes(f.severity));
      assert.ok(["likely", "review"].includes(f.confidence));
      assert.ok(f.controls.length >= 1 && f.assets.length >= 1 && f.evidence.length <= 50);
      assert.ok(f.description.includes(VERIFY_LINE));
    }
  });
  test("findingsToCsv header row", () => {
    assert.equal(findingsToCsv([]).split("\n")[0], "severity,confidence,category,title,description,recommendation,controls,evidenceCount");
  });
  test("checklist CSV covers every applicable obligation", () => {
    const a = run({ sectors: ["eu"] });
    const csv = checklistToCsv(a.checklist);
    assert.equal(csv.split("\n")[0], "obligation_id,obligation,step,owner,done");
    assert.ok(csv.includes("\"gdpr-33\""));
    assert.ok(a.checklist.every((c) => c.done === false));
  });
  test("not-indicated obligations stay off the timeline", () => {
    const a = run({ sectors: ["glba"], total: 10 });
    assert.equal(ob(a, "glba-ftc").applies, "not-indicated");
    assert.ok(!a.timeline.some((x) => x.id === "glba-ftc"));
  });
  test("ICS: one VEVENT per open fixed deadline, deterministic", () => {
    const a = run({ sectors: ["eu", "in"] });
    const ics = toIcs(icsEvents(a, "Test incident"));
    assert.equal((ics.match(/BEGIN:VEVENT/g) || []).length, 2);
    assert.ok(ics.includes("DTSTART:20260113T100000Z"));
    assert.ok(ics.includes("DTSTART:20260110T160000Z"));
    assert.equal(ics, toIcs(icsEvents(run({ sectors: ["eu", "in"] }), "Test incident")));
  });
  test("obligations JSON re-imports through parseInput", () => {
    const rec = { id: "inc-1", title: "Round trip", facts: { ...facts }, statuses: { "gdpr-33": { state: "drafted" } }, notes: "n" };
    const a = analyze(rec, { now: "2026-01-10T12:00:00Z" }).assessment;
    const text = JSON.stringify(exportBundle(rec, a));
    const p = parseInput([{ name: "export.json", text }]);
    assert.equal(p.format, "breachclock-incident");
    assert.equal(p.rows[0].id, "inc-1");
    const again = analyze(p.rows, { now: "2026-01-10T12:00:00Z" }).assessment;
    assert.deepEqual(again.obligations, a.obligations);
    assert.equal(ob(again, "gdpr-33").status, "drafted");
  });
  test("counts CSV through parseInput feeds analyze", () => {
    const p = parseInput("jurisdiction,count\nTexas,300\n");
    assert.equal(p.format, "jurisdiction-counts");
    const r = analyze(p.rows, { breachLaws: LAWS });
    assert.ok(r.assessment.obligations.some((o) => o.id === "us-TX-residents"));
  });
  test("register round-trip with Map storage and a fake graph", () => {
    const m = new Map();
    const storage = { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
    const E = {}; let n = 0;
    const graph = {
      create: (type, name, data, opts) => { const e = { id: "g" + (++n), type, name, data, severity: opts.severity, status: opts.status, source: opts.source }; E[e.id] = e; return e; },
      update: (id, u) => Object.assign(E[id], u), remove: (id) => delete E[id],
      list: (type) => Object.values(E).filter((e) => e.type === type), get: (id) => E[id] || null,
    };
    const reg = openRegister("breachclock", "INCIDENT", { schema: REGISTER_SCHEMA, storage, graph, now: () => "2026-01-13T11:00:00.000Z" });
    const rec0 = { id: "inc-7", title: "Overdue one", status: "open", facts, statuses: {}, notes: "" };
    const a = analyze(rec0, { now: "2026-01-13T11:00:00Z" }).assessment;
    const saved = reg.upsert(snapshot(rec0, a));
    const e = E[saved.graphId];
    assert.equal(e.type, "INCIDENT");
    assert.equal(e.data.registerId, "breachclock");
    assert.equal(e.severity, "critical");
    assert.equal(e.data._full.facts.sectors.join(","), "eu,in,glba");
    assert.ok(saved.overdueCount >= 2);
    storage.setItem("dn_active_ws", "team1");
    const team = openRegister("breachclock", "INCIDENT", { schema: REGISTER_SCHEMA, storage, graph, now: () => "2026-01-13T11:00:00.000Z" });
    assert.equal(team.list()[0].id, "inc-7", "team members see the incident from the graph");
    storage.removeItem("dn_active_ws");
    reg.upsert({ ...reg.get("inc-7"), status: "closed" });
    assert.equal(E[saved.graphId].status, "closed");
    assert.ok(reg.remove("inc-7"));
    assert.equal(Object.keys(E).length, 0);
  });
  test("summary text and draft notice carry the counsel line; draft is a template", () => {
    const a = run({ sectors: ["eu"] });
    assert.ok(summaryText(a, "T").includes(VERIFY_LINE));
    const d = draftNotice(ob(a, "gdpr-33"), { ...base, sectors: ["eu"], title: "T" });
    assert.ok(d.startsWith("TEMPLATE"));
    assert.ok(d.includes("GDPR Art. 33(1)"));
  });
});

group("breachclock: determinism and example", () => {
  test("analyze is byte-identical across runs", () => {
    const ex = exampleDataset(7, "2026-10-16T15:00:00Z");
    const o = { now: "2026-10-16T15:00:00Z", breachLaws: LAWS, holidays: HOL };
    assert.equal(JSON.stringify(analyze(ex.record, o)), JSON.stringify(analyze(ex.record, o)));
  });
  test("example: discovered 2 days before now, EU + three states, GDPR due", () => {
    const ex = exampleDataset(0, "2026-10-16T15:00:00Z");
    assert.equal(parseTime(ex.record.facts.discoveredAt, ex.record.facts.timeZone), Date.parse("2026-10-14T15:00:00Z"));
    const r = analyze(ex.record, { now: "2026-10-16T15:00:00Z", breachLaws: LAWS });
    assert.ok(ob(r.assessment, "gdpr-33"));
    assert.ok(ob(r.assessment, "us-TX-regulator"));
    assert.ok(r.findings.some((f) => f.id === "breachclock:gdpr-33"));
  });
  test("default now is the newest fact timestamp", () => {
    const a = assess({ discoveredAt: "2026-01-01T00:00:00Z", determinedAt: "2026-01-02T00:00:00Z" });
    assert.equal(a.now, "2026-01-02T00:00:00.000Z");
  });
  test("empty input yields zero findings and does not throw", () => {
    const r = analyze(parseInput("").rows);
    assert.equal(r.findings.length, 0);
    assert.equal(r.meta.tool, "breachclock");
  });
  test("selfTest passes", () => {
    const r = selfTest();
    assert.ok(r.pass, r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
});
