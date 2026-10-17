// Data Inventory & Processing Register engine tests (public/js/compliance/dataflow-engine.js):
// calendar arithmetic, DSAR deadlines, WP248 DPIA screening, transfers against the shipped
// adequacy reference file, lawful-basis / retention / security / minimisation checks,
// imports (ICO documentation template CSV, this tool's ROPA and DSAR CSV, register JSON),
// exports, determinism and the register round-trip.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { test, assert, group } from "../harness.mjs";
import {
  selfTest, analyze, parseInput, exampleDataset, findingsToCsv, addMonths, rollWeekend, dsarDue, screenDpia, parseRetention, parseLegalBasis, parseArt9,
  parseMechanism, normCountry, suggestCategories, CATEGORIES, csvToActivities, csvToDsars, ropaCsv, dsarCsv, dpiaMemo, icsEvents, summaryText, detectDateOrder,
  parseDate, assessTransfer, adequacyIndex, ACTIVITY_SCHEMA, DSAR_SCHEMA, TOOL_ID, normalizeActivity, validateDsar,
} from "../../public/js/compliance/dataflow-engine.js";
import { DETECTORS } from "../../public/js/dataprotect/dlp-engine.js";
import { openRegister } from "../../public/js/core/register.js";
import { toIcs } from "../../public/js/core/export.js";

const here = dirname(fileURLToPath(import.meta.url));
const ADEQ = JSON.parse(readFileSync(join(here, "../../public/data/ref/eu-adequacy.json"), "utf8"));
const NOW = "2026-10-16T12:00:00Z";
const ORG = { name: "Test Org", contact: "privacy@test.darknode.ai" };
const base = (over = {}) => ({
  id: "a1", name: "Activity", role: "controller", purpose: "Run the service", dataSubjects: ["customers"], dataCategories: ["contact"], categoryUses: { contact: "Notices" },
  recipients: ["none"], legalBasis: "b", retention: "6 years", oldestRecord: "2025-01-01", securityMeasures: "MFA, encryption", lastReview: "2026-06-01", ...over,
});
const run = (acts, opts = {}, dsars = []) => analyze({ activities: acts, dsars }, { now: NOW, adequacy: ADEQ, org: ORG, knownVendors: [], ...opts });
const ids = (r) => r.findings.map((f) => f.id.split(":")[1]);
const has = (r, check) => ids(r).includes(check);

// ICO "Documentation template for controllers" (gdpr-documentation-controller-template.xlsx, "Template" sheet),
// saved as CSV. The 30 column headers of row 9 verbatim, columns A-AD.
const ICO_HEADERS = ["Business function", "Purpose of processing", "Name and contact details of joint controller (if applicable)", "Categories of individuals",
  "Categories of personal data", "Categories of recipients", "Link to contract with processor",
  "Names of third countries or international organisations that personal data are transferred to (if applicable)",
  "Safeguards for exceptional transfers of personal data to third countries or international organisations (if applicable)", "Retention schedule (if possible)",
  "General description of technical and organisational security measures (if possible)", "Article 6 lawful basis for processing personal data",
  "Article 9 condition for processing special category data", "Legitimate interests for the processing (if applicable)",
  "Link to record of legitimate interests assessment (if applicable)", "Rights available to individuals",
  "Existence of automated decision-making, including profiling (if applicable)", "The source of the personal data (if applicable)", "Link to record of consent",
  "Location of personal data", "Data Protection Impact Assessment required?", "Data Protection Impact Assessment progress", "Link to Data Protection Impact Assessment",
  "Has a personal data breach occurred?", "Link to record of personal data breach", "Data Protection Act 2018 Schedule 1 Condition for processing",
  "GDPR Article 6 lawful basis for processing", "Link to retention and erasure policy document",
  "Is personal data retained and erased in accordance with the policy document?", "Reasons for not adhering to policy document (if applicable)"];
const icoLine = (cells) => cells.map((c) => '"' + c + '"').join(",");
const ICO_ROWS = [
  ["Finance", "Payroll", "", "Employees", "Names, bank details, health data (sickness absence)", "Payroll provider; HMRC", "https://contracts.test.darknode.ai/payroll", "India",
    "Standard contractual clauses", "6 years after employment ends", "Role-based access, encryption", "Legal obligation", "Article 9(2)(b) employment law", "", "",
    "Access, rectification", "No", "Employee", "", "HR system", "No", "", "", "No", "", "Schedule 1 Part 1 paragraph 1", "Article 6(1)(c) legal obligation",
    "https://policies.test.darknode.ai/retention", "Yes", ""],
  ["Marketing", "Newsletter", "", "Customers, prospects", "Email address, IP address, cookies", "Mail provider Inc", "", "United States", "", "Indefinite", "",
    "Article 6(1)(f) legitimate interests", "", "Direct marketing", "", "Objection", "Yes - profiling for segmentation", "Website forms", "", "CRM", "Yes", "In progress",
    "DPIA-12", "No", "", "", "", "", "", ""],
];
const ICO_CSV = [icoLine(ICO_HEADERS), ...ICO_ROWS.map(icoLine)].join("\r\n");
// The same sheet saved whole: controller / DPO / representative block (rows 1-6), blank row 7, section titles (row 8).
const ICO_PREAMBLE = [
  "Controller,,,,,",
  "Name and contact details,,Data Protection Officer (if applicable),,Representative (if applicable),",
  "Name,Larkspur Cloudworks Ltd,Name,Privacy Office,Name,N/A",
  "Address,\"1 Test Street, London\",Address,\"1 Test Street, London\",Address,N/A",
  "Email,privacy@test.darknode.ai,Email,dpo@test.darknode.ai,Email,N/A",
  "Telephone,,Telephone,,Telephone,N/A",
  ",,,,,",
  "Article 30 Record of Processing Activities,,,,,,,,,,,Privacy Notices,,,,,,,Consent,Access Requests,Data Protection Impact Assessments,,,Personal Data Breaches,,Data Protection Act 2018 - Special Category or Criminal Conviction and Offence data,,,,",
].join("\r\n");

const DSAR_CSV = [
  "Reference,Request type,Received,Identity verified,Extended,Extension notified,Completed,Owner,Notes",
  "T-100,Subject access request,15/09/2026,17/09/2026,no,,,privacy@test.darknode.ai,",
  "T-101,Erasure,03/02/2026,,yes,20/02/2026,30/04/2026,privacy@test.darknode.ai,",
  "T-102,Right to object,31/01/2026,,no,,27/02/2026,privacy@test.darknode.ai,",
].join("\n");

group("dataflow: engine basics", () => {
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
  test("analyze is byte-identical across runs (example)", () => {
    const ex = exampleDataset();
    const o = { now: ex.now, adequacy: ADEQ, org: ex.org, knownVendors: ex.knownVendors, regime: "both" };
    assert.equal(JSON.stringify(analyze(ex, o)), JSON.stringify(analyze(ex, o)));
  });
  test("input order does not change the output", () => {
    const ex = exampleDataset();
    const o = { now: ex.now, adequacy: ADEQ, org: ex.org, knownVendors: ex.knownVendors };
    const rev = { activities: ex.activities.slice().reverse(), dsars: ex.dsars.slice().reverse() };
    assert.equal(JSON.stringify(analyze(ex, o)), JSON.stringify(analyze(rev, o)));
  });
  test("empty input yields zero findings and does not throw", () => {
    const parsed = parseInput("");
    assert.equal(parsed.activities.length, 0);
    const r = analyze({}, { now: NOW });
    assert.equal(r.findings.length, 0);
    assert.equal(r.meta.rows, 0);
  });
  test("every finding has controls, a confidence class and capped evidence", () => {
    const ex = exampleDataset();
    const r = analyze(ex, { now: ex.now, adequacy: ADEQ, org: ex.org, knownVendors: ex.knownVendors });
    assert.ok(r.findings.length > 15);
    for (const f of r.findings) {
      assert.ok(f.controls.length >= 1, f.id);
      assert.ok(["confirmed", "likely", "review"].includes(f.confidence), f.id);
      assert.ok(["critical", "high", "medium", "low", "info"].includes(f.severity), f.id);
      assert.ok(f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length, f.id);
      assert.ok(f.controls.some((c) => c.framework === "ISO 27001:2022" && c.id === "A.5.34"), f.id);
    }
  });
  test("progress callback reaches the total", () => {
    const calls = [];
    const ex = exampleDataset();
    analyze(ex, { now: ex.now }, { progress: (i, n) => calls.push([i, n]) });
    assert.deepEqual(calls[calls.length - 1], [18, 18]);
  });
  test("no current time: newest date in the data is used and reported", () => {
    const r = analyze({ activities: [base()] }, { adequacy: ADEQ, org: ORG, knownVendors: [] });
    assert.ok(r.skipped.some((s) => s.check === "clock" && s.reason.includes("2026-06-01")));
  });
  test("synthetic example uses only test.darknode.ai addresses and is labelled", () => {
    const ex = exampleDataset();
    const emails = JSON.stringify(ex).match(/[\w.-]+@[\w.-]+/g) || [];
    assert.ok(emails.length > 5);
    assert.ok(emails.every((e) => e.endsWith("@test.darknode.ai")), emails.join(","));
    assert.ok(/synthetic/i.test(ex.label) && /fictional/i.test(ex.org.name));
  });
});

group("dataflow: dates and DSAR deadlines", () => {
  test("calendar months clamp to the end of the month", () => {
    assert.equal(addMonths("2026-01-31", 1), "2026-02-28");
    assert.equal(addMonths("2028-01-31", 1), "2028-02-29");
    assert.equal(addMonths("2026-03-31", 1), "2026-04-30");
    assert.equal(addMonths("2026-11-30", 3), "2027-02-28");
    assert.equal(addMonths("2026-01-15", 1), "2026-02-15");
  });
  test("weekend roll: Saturday and Sunday move to Monday, weekdays stay", () => {
    assert.equal(rollWeekend("2026-10-31"), "2026-11-02");
    assert.equal(rollWeekend("2026-11-01"), "2026-11-02");
    assert.equal(rollWeekend("2026-10-20"), "2026-10-20");
  });
  test("dsarDue: base, extended, identity clock and no-roll", () => {
    assert.equal(dsarDue({ received: "2026-01-31" }).due, "2026-03-02"); // 28 Feb 2026 is a Saturday
    assert.equal(dsarDue({ received: "2026-01-31" }, { rollWeekends: false }).due, "2026-02-28");
    assert.equal(dsarDue({ received: "2026-05-05", extended: true }).due, "2026-08-05");
    assert.equal(dsarDue({ received: "2026-09-20", identityVerified: "2026-09-24" }, { clockStart: "identity" }).due, "2026-10-26"); // 24 Oct is a Saturday
    assert.equal(dsarDue({ received: "2026-09-20", identityVerified: "2026-09-24" }).due, "2026-10-20");
  });
  test("overdue fires, on-time completion stays silent, median computed", () => {
    const r = run([], {}, [
      { id: "d1", ref: "A", type: "access", received: "2026-08-31" },
      { id: "d2", ref: "B", type: "access", received: "2026-08-01", completed: "2026-08-11" },
      { id: "d3", ref: "C", type: "erasure", received: "2026-08-01", completed: "2026-08-21" },
    ]);
    assert.ok(r.findings.some((f) => f.id === "dfr:dsar-overdue:d1" && f.severity === "high"));
    assert.ok(!r.findings.some((f) => f.id.endsWith(":d2") || f.id.endsWith(":d3")));
    assert.equal(r.summary.dsarMedianDays, 15);
    assert.equal(r.summary.dsarOverdue, 1);
  });
  test("at-risk threshold edge: due in exactly N days fires, N+1 does not", () => {
    // received 2026-09-23 -> due 2026-10-23 (Fri) = 7 days after 2026-10-16
    const at = run([], { dsarAtRiskDays: 7 }, [{ id: "d", ref: "X", type: "access", received: "2026-09-23" }]);
    assert.ok(has(at, "dsar-at-risk"));
    const not = run([], { dsarAtRiskDays: 6 }, [{ id: "d", ref: "X", type: "access", received: "2026-09-23" }]);
    assert.ok(!has(not, "dsar-at-risk") && !has(not, "dsar-overdue"));
  });
  test("late completion and late extension notice are flagged", () => {
    const r = run([], {}, [
      { id: "l", ref: "L", type: "access", received: "2026-03-31", completed: "2026-05-08" },
      { id: "e", ref: "E", type: "restriction", received: "2026-07-31", extended: true, extensionNotified: "2026-09-05", completed: "2026-10-10" },
      { id: "ok", ref: "OK", type: "portability", received: "2026-05-05", extended: true, extensionNotified: "2026-05-29", completed: "2026-07-15" },
      { id: "nn", ref: "NN", type: "portability", received: "2026-05-05", extended: true, completed: "2026-07-15" },
    ]);
    assert.ok(r.findings.some((f) => f.id === "dfr:dsar-late:l"));
    assert.ok(r.findings.some((f) => f.id === "dfr:dsar-extension-late:e"));
    assert.ok(!r.findings.some((f) => f.id.endsWith(":ok")));
    assert.ok(r.findings.some((f) => f.id === "dfr:dsar-extension-notice:nn" && f.confidence === "review"));
  });
  test("DSAR controls cite Art. 12(3) and the right's article", () => {
    const r = run([], {}, [{ id: "d1", ref: "A", type: "erasure", received: "2026-08-31" }]);
    const f = r.findings.find((x) => x.id === "dfr:dsar-overdue:d1");
    assert.ok(f.controls.some((c) => c.framework === "GDPR" && c.id === "Art.12(3)"));
    assert.ok(f.controls.some((c) => c.id === "Art.17"));
  });
  test("validateDsar requires a reference and a received date", () => {
    assert.equal(validateDsar({}).length, 2);
    assert.equal(validateDsar({ ref: "A", received: "2026-01-01" }).length, 0);
    assert.equal(validateDsar({ ref: "A", received: "2026-02-01", completed: "2026-01-01" }).length, 1);
  });
});

group("dataflow: DPIA screening (WP248)", () => {
  test("derived criteria: special data and vulnerable subjects", () => {
    const s = screenDpia({ dataSubjects: ["employees"], dataCategories: ["health"] });
    assert.equal(s.count, 2);
    assert.ok(s.likely);
    assert.ok(s.criteria.find((c) => c.id === "sensitive").why.includes("Health"));
  });
  test("two criteria without a completed DPIA -> high; one criterion silent", () => {
    const two = run([base({ dpiaCriteria: ["scoring", "combining"] })]);
    assert.ok(two.findings.some((f) => f.id === "dfr:dpia-required:a1" && f.severity === "high"));
    const one = run([base({ dpiaCriteria: ["scoring"] })]);
    assert.ok(!has(one, "dpia-required") && !has(one, "dpia-not-needed"));
  });
  test("completed DPIA silences, not-needed gives a review, processors are not screened", () => {
    const done = run([base({ dpiaCriteria: ["scoring", "combining"], dpiaStatus: "completed", dpiaDate: "2026-01-01" })]);
    assert.ok(!has(done, "dpia-required") && !has(done, "dpia-stale"));
    const nn = run([base({ dpiaCriteria: ["scoring", "combining"], dpiaStatus: "not-needed" })]);
    assert.ok(nn.findings.some((f) => f.id === "dfr:dpia-not-needed:a1" && f.confidence === "review"));
    const proc = run([base({ role: "processor", controllerName: "Client", dpiaCriteria: ["scoring", "combining"] })]);
    assert.ok(!has(proc, "dpia-required"));
  });
  test("DPIA re-assessment threshold edge", () => {
    const rec = base({ dpiaStatus: "completed", dpiaDate: "2023-10-16" });
    assert.ok(!has(run([rec], { dpiaReviewMonths: 36 }), "dpia-stale"), "due today is not overdue");
    assert.ok(has(run([rec], { dpiaReviewMonths: 35 }), "dpia-stale"));
    assert.ok(has(run([base({ dpiaStatus: "completed" })]), "dpia-no-date"));
  });
});

group("dataflow: transfers vs adequacy reference", () => {
  const tr = (t, opts) => run([base({ transfers: [t] })], opts);
  test("third country with no mechanism is high", () => {
    const r = tr({ country: "Philippines", recipient: "BPO", mechanism: "none" });
    const f = r.findings.find((x) => x.id.startsWith("dfr:transfer-no-mechanism:"));
    assert.ok(f && f.severity === "high" && f.confidence === "confirmed");
    assert.ok(f.controls.some((c) => c.id === "Art.44") && f.controls.some((c) => c.id === "Art.46"));
    assert.ok(f.assets.some((a) => a.type === "VENDOR" && a.name === "BPO"));
  });
  test("SCCs without a TIA -> review; with a TIA silent", () => {
    assert.ok(has(tr({ country: "IN", mechanism: "scc-2021" }), "transfer-no-tia"));
    const ok = tr({ country: "IN", mechanism: "scc-2021", tia: true });
    assert.ok(!ok.findings.some((f) => f.category === "transfer"));
  });
  test("US: adequacy only for DPF-certified recipients", () => {
    assert.ok(tr({ country: "US", mechanism: "adequacy", dpfCertified: "no" }).findings.some((f) => f.id.startsWith("dfr:transfer-us-not-dpf:") && f.severity === "high"));
    const unk = tr({ country: "United States", mechanism: "adequacy" });
    assert.ok(unk.findings.some((f) => f.id.startsWith("dfr:transfer-us-dpf-unknown:") && f.confidence === "review"));
    assert.ok(!tr({ country: "USA", mechanism: "adequacy", dpfCertified: "yes" }).findings.some((f) => f.category === "transfer"));
  });
  test("EEA destination is not a transfer; Switzerland adequate; Japan limited scope", () => {
    assert.equal(tr({ country: "Germany" }).tables.transfers.length, 0);
    assert.ok(!tr({ country: "CH", mechanism: "adequacy" }).findings.some((f) => f.category === "transfer"));
    assert.ok(has(tr({ country: "JP", mechanism: "adequacy" }), "transfer-adequacy-scope"));
  });
  test("Brazil's proposed decision is not treated as adequacy", () => {
    assert.ok(has(tr({ country: "Brazil", mechanism: "adequacy" }), "transfer-false-adequacy"));
    assert.ok(has(tr({ country: "BR", mechanism: "" }), "transfer-no-mechanism"));
  });
  test("Art. 49 derogation and unknown country are review items", () => {
    assert.ok(tr({ country: "IN", mechanism: "derogations" }).findings.some((f) => f.id.startsWith("dfr:transfer-derogation:") && f.confidence === "review"));
    assert.ok(has(tr({ country: "Atlantis" }), "transfer-unknown-country"));
  });
  test("UK regime: EU SCCs alone flagged, EEA adequate, UK GDPR controls", () => {
    const r = tr({ country: "IN", mechanism: "scc-2021", tia: true }, { regime: "uk" });
    const f = r.findings.find((x) => x.id.startsWith("dfr:transfer-uk-scc-only:"));
    assert.ok(f && f.controls.every((c) => c.framework !== "GDPR"));
    assert.ok(f.controls.some((c) => c.framework === "UK GDPR"));
    assert.ok(!tr({ country: "FR" }, { regime: "uk" }).findings.some((x) => x.category === "transfer"));
    assert.ok(!tr({ country: "KR", mechanism: "adequacy" }, { regime: "uk" }).findings.some((x) => x.category === "transfer"));
  });
  test("regime both: one finding per regime, labelled", () => {
    const r = tr({ country: "PH", mechanism: "none" }, { regime: "both" });
    const fs = r.findings.filter((x) => x.id.startsWith("dfr:transfer-no-mechanism:"));
    assert.equal(fs.length, 2);
    assert.ok(fs.some((x) => x.title.endsWith("(UK GDPR)")) && fs.some((x) => x.title.endsWith("(EU GDPR)")));
  });
  test("without the reference file transfers are skipped, not guessed", () => {
    const r = analyze({ activities: [base({ transfers: [{ country: "PH", mechanism: "none" }] })] }, { now: NOW, org: ORG, knownVendors: [] });
    assert.ok(!r.findings.some((f) => f.category === "transfer"));
    assert.ok(r.skipped.some((s) => s.check === "transfers"));
    assert.equal(run([base()]).meta.reference.version, ADEQ.version);
  });
  test("adequacyIndex reads the envelope (EU data and UK list)", () => {
    const eu = adequacyIndex(ADEQ, "eu"), uk = adequacyIndex(ADEQ, "uk");
    assert.ok(eu.get("US").certifiedOnly && eu.get("BR").proposed && !eu.get("CH").limited);
    assert.ok(uk.get("DE") && uk.get("KR") && uk.get("US").certifiedOnly);
    assert.equal(assessTransfer({ country: "GB" }, uk, "uk").status, "n/a");
  });
});

group("dataflow: record checks", () => {
  test("clean controller record has no activity findings", () => {
    const r = run([base()]);
    assert.equal(r.findings.length, 0, ids(r).join(","));
  });
  test("missing lawful basis is high; processors are not asked for one", () => {
    assert.ok(run([base({ legalBasis: "" })]).findings.some((f) => f.id === "dfr:no-legal-basis:a1" && f.severity === "high"));
    assert.ok(!has(run([base({ legalBasis: "", role: "processor", controllerName: "Client" })]), "no-legal-basis"));
  });
  test("Art. 30 completeness lists missing fields; processor needs the controller", () => {
    const r = run([base({ purpose: "", dataSubjects: [], recipients: [] })]);
    const f = r.findings.find((x) => x.id === "dfr:ropa-incomplete:a1");
    assert.ok(f && /purposes/.test(f.description) && /data subjects/.test(f.description) && /recipients/.test(f.description));
    assert.ok(run([base({ role: "processor" })]).findings.some((x) => x.id === "dfr:ropa-incomplete:a1" && /controller on whose behalf/.test(x.description)));
  });
  test("consent for employees and legitimate interests without an LIA are review items", () => {
    assert.ok(has(run([base({ legalBasis: "a", dataSubjects: ["employees"] })]), "consent-employees"));
    assert.ok(!has(run([base({ legalBasis: "a" })]), "consent-employees"));
    assert.ok(has(run([base({ legalBasis: "f" })]), "li-no-lia"));
    assert.ok(!has(run([base({ legalBasis: "f", liaRef: "LIA-1" })]), "li-no-lia"));
  });
  test("special category needs an Art. 9(2) condition; criminal data an Art. 10 basis", () => {
    assert.ok(has(run([base({ dataCategories: ["contact", "health"], categoryUses: { contact: "x", health: "y" } })]), "art9-no-condition"));
    assert.ok(!has(run([base({ dataCategories: ["health"], categoryUses: { health: "y" }, art9Condition: "b" })]), "art9-no-condition"));
    assert.ok(has(run([base({ dataCategories: ["criminal"], categoryUses: { criminal: "y" } })]), "art10-no-basis"));
    assert.ok(!has(run([base({ dataCategories: ["criminal"], categoryUses: { criminal: "y" }, criminalBasis: "DPA 2018 Sch 1 para 6" })]), "art10-no-basis"));
  });
  test("retention: missing, indefinite, overdue edge, and skipped without an oldest-record date", () => {
    assert.ok(has(run([base({ retention: "" })]), "retention-missing"));
    assert.ok(has(run([base({ retention: "kept indefinitely" })]), "retention-indefinite"));
    assert.ok(has(run([base({ retention: "90 days", oldestRecord: "2026-07-17" })]), "retention-overdue")); // ends 2026-10-15
    assert.ok(!has(run([base({ retention: "90 days", oldestRecord: "2026-07-18" })]), "retention-overdue")); // ends today
    const nod = run([base({ oldestRecord: "" })]);
    assert.ok(!has(nod, "retention-overdue") && nod.skipped.some((s) => s.check === "retention-overdue"));
  });
  test("missing security measures (Art. 32)", () => {
    const f = run([base({ securityMeasures: "" })]).findings.find((x) => x.id === "dfr:no-security-measures:a1");
    assert.ok(f && f.controls.some((c) => c.id === "Art.32"));
  });
  test("review overdue threshold edge and never reviewed", () => {
    assert.ok(!has(run([base({ lastReview: "2025-10-16" })], { reviewMonths: 12 }), "review-overdue"));
    assert.ok(has(run([base({ lastReview: "2025-10-15" })], { reviewMonths: 12 }), "review-overdue"));
    assert.ok(has(run([base({ lastReview: "" })]), "never-reviewed"));
  });
  test("minimisation: categories without a use, and the many-categories edge", () => {
    assert.ok(has(run([base({ categoryUses: {} })]), "min-no-use"));
    const cats = ["identity", "contact", "usage", "online-id"];
    const uses = Object.fromEntries(cats.map((c) => [c, "x"]));
    assert.ok(!has(run([base({ dataCategories: cats, categoryUses: uses })], { maxCategories: 4 }), "min-many-categories"));
    assert.ok(has(run([base({ dataCategories: cats, categoryUses: uses })], { maxCategories: 3 }), "min-many-categories"));
  });
  test("recipients missing from the vendor register; internal recipients ignored; skipped without a register", () => {
    const r = run([base({ recipients: ["Acme Mail Inc", "Internal HR team", "Revenue authority"] })], { knownVendors: ["Other Ltd"] });
    const f = r.findings.find((x) => x.id === "dfr:recipient-not-in-register:a1");
    assert.ok(f && f.evidenceCount === 1 && f.assets[0].name === "Acme Mail Inc");
    assert.ok(!has(run([base({ recipients: ["Acme Mail, Inc."] })], { knownVendors: ["Acme Mail Inc"] }), "recipient-not-in-register"));
    const nr = analyze({ activities: [base()] }, { now: NOW, adequacy: ADEQ, org: ORG });
    assert.ok(nr.skipped.some((s) => s.check === "recipient-not-in-register"));
  });
  test("organisation details are required once", () => {
    assert.ok(has(run([base()], { org: { name: "", contact: "" } }), "org-details"));
  });
});

group("dataflow: parsing", () => {
  test("parseRetention reads units, ISO durations and indefinite", () => {
    assert.equal(parseRetention("6 years").months, 72);
    assert.equal(parseRetention("18 months after closure").months, 18);
    assert.equal(parseRetention("90 days").days, 90);
    assert.equal(parseRetention("2 weeks").days, 14);
    assert.equal(parseRetention("P1Y6M").months, 18);
    assert.ok(parseRetention("Indefinite").indefinite);
    assert.equal(parseRetention("until no longer needed").months, null);
  });
  test("lawful basis, Art. 9 condition and mechanism from free text", () => {
    assert.equal(parseLegalBasis("Article 6(1)(f) legitimate interests"), "f");
    assert.equal(parseLegalBasis("Legal obligation"), "c");
    assert.equal(parseLegalBasis("(b)"), "b");
    assert.equal(parseLegalBasis("whatever"), "");
    assert.equal(parseArt9("Article 9(2)(b) employment law"), "b");
    assert.equal(parseArt9("Explicit consent"), "a");
    assert.equal(parseArt9("n/a"), "");
    assert.equal(parseMechanism("Standard contractual clauses"), "scc-2021");
    assert.equal(parseMechanism("UK Addendum"), "uk-idta");
    assert.equal(parseMechanism("BCRs"), "bcr");
    assert.equal(parseMechanism("EU-US Data Privacy Framework"), "adequacy");
  });
  test("country names, codes and aliases", () => {
    assert.equal(normCountry("UK").code, "GB");
    assert.equal(normCountry("United States of America").code, "US");
    assert.equal(normCountry("ph").code, "PH");
    assert.equal(normCountry("EEA").code, "EU");
    assert.equal(normCountry("Narnia").code, "");
  });
  test("dates: order detection and parsing", () => {
    assert.equal(detectDateOrder(["15/09/2026", "03/02/2026"]), "dmy");
    assert.equal(detectDateOrder(["09/15/2026"]), "mdy");
    assert.equal(detectDateOrder(["03/02/2026"]), "ambiguous");
    assert.equal(parseDate("03/02/2026", "dmy"), "2026-02-03");
    assert.equal(parseDate("03/02/2026", "mdy"), "2026-03-02");
    assert.equal(parseDate("12 Jan 2026"), "2026-01-12");
    assert.equal(parseDate("31/02/2026"), "");
  });
  test("ICO documentation template CSV: detected, mapped high, converted", () => {
    const p = parseInput([{ name: "ico-ropa.csv", text: ICO_CSV }]);
    const file = p.files[0];
    assert.equal(file.kind, "activities");
    assert.equal(file.format, "ICO documentation template (controller) CSV");
    assert.equal(file.confidence, "high");
    assert.equal(file.mapping.dataSubjects, "Categories of individuals");
    assert.equal(file.mapping.transfers, "Names of third countries or international organisations that personal data are transferred to (if applicable)");
    const { records } = csvToActivities(file.rows, file.mapping);
    assert.equal(records.length, 2);
    const [pay, news] = records;
    assert.equal(pay.name, "Finance - Payroll");
    assert.equal(pay.legalBasis, "c");
    assert.equal(pay.art9Condition, "b");
    assert.deepEqual(pay.dataCategories, ["bank", "health", "identity"]);
    assert.equal(pay.transfers[0].country, "IN");
    assert.equal(pay.transfers[0].mechanism, "scc-2021");
    assert.equal(pay.dpiaStatus, "not-needed");
    assert.deepEqual(pay.systems, ["HR system"]);
    assert.equal(news.legalBasis, "f");
    assert.equal(news.dpiaStatus, "in-progress");
    assert.ok(news.dpiaCriteria.includes("scoring"));
    assert.equal(news.transfers[0].country, "US");
    assert.ok(parseRetention(news.retention).indefinite);
    assert.equal(file.headers.length, 30);
    assert.equal(file.mapping.art9Condition, "Article 9 condition for processing special category data");
    assert.equal(file.mapping.dpiaRef, "Link to Data Protection Impact Assessment");
    assert.equal(news.dpiaRef, "DPIA-12");
  });
  test("ICO template saved whole as CSV: controller block and section-title rows skipped", () => {
    const p = parseInput([{ name: "ico-full.csv", text: ICO_PREAMBLE + "\r\n" + ICO_CSV }]);
    const file = p.files[0];
    assert.equal(file.format, "ICO documentation template (controller) CSV");
    assert.equal(file.confidence, "high");
    assert.equal(file.headers[0], "Business function");
    assert.equal(file.rows.length, 2);
    assert.equal(csvToActivities(file.rows, file.mapping).records[0].name, "Finance - Payroll");
  });
  test("ICO template: one row per data category for the same activity folds into one activity", () => {
    const NA = "N/A";
    const row = (cat, rec) => ["Finance", "Payroll", NA, "Employees", cat, rec, NA, NA, NA, "3 years post-employment", "Encrypted storage and transfer",
      "Article 6(1)(c) - legal obligation", NA, NA, NA, "Access and rectification", "No", "Data subject", NA, "Finance payroll system", "No", NA, NA, "No", NA, NA, NA, NA, NA, NA];
    const text = [ICO_HEADERS, row("Bank details", "HMRC"), row("Salary", "Pension provider"), row("Contact details", "HMRC")].map(icoLine).join("\r\n");
    const file = parseInput([{ name: "ico-rows.csv", text }]).files[0];
    const { records, skipped } = csvToActivities(file.rows, file.mapping);
    assert.equal(records.length, 1);
    assert.equal(records[0].name, "Finance - Payroll");
    assert.ok(records[0].dataCategories.length >= 2, JSON.stringify(records[0].dataCategories));
    assert.deepEqual(records[0].recipients, ["HMRC", "Pension provider"]);
    assert.ok(skipped.some((x) => /2 row\(s\) repeated an activity/.test(x.reason)));
  });
  test("ICO template N/A cells (as in the template's Example sheet) read as blank", () => {
    const NA = "N/A";
    const ex = ["Finance", "Payroll", NA, "Employees", "Bank details", "HMRC", NA, NA, NA, "3 years post-employment", "Encrypted storage and transfer",
      "Article 6(1)(c) - legal obligation", NA, NA, NA, "Access and rectification", "No", "Data subject", NA, "Finance payroll system", "No", NA, NA, "No", NA, NA, NA, NA, NA, NA];
    const file = parseInput([{ name: "ico-ex.csv", text: icoLine(ICO_HEADERS) + "\r\n" + icoLine(ex) }]).files[0];
    const [a] = csvToActivities(file.rows, file.mapping).records;
    assert.deepEqual([a.jointController, a.art9Condition, a.liaRef, a.dpiaRef, a.legalBasis, a.transfers.length], ["", "", "", "", "c", 0]);
  });
  test("this tool's ROPA CSV re-imports (round trip)", () => {
    const ex = exampleDataset();
    const csv = ropaCsv(ex.activities, { variant: "controller", org: ex.org });
    const p = parseInput([{ name: "ropa.csv", text: csv }]);
    assert.equal(p.files[0].kind, "activities");
    assert.equal(p.files[0].confidence, "high");
    const { records } = csvToActivities(p.files[0].rows, p.files[0].mapping);
    assert.equal(records.length, 7);
    const pay = records.find((r) => r.name === "Payroll and HR administration");
    assert.equal(pay.legalBasis, "c");
    assert.equal(pay.art9Condition, "b");
    assert.ok(pay.dataCategories.includes("health") && pay.dataCategories.includes("bank"));
    assert.equal(pay.transfers[0].country, "IN");
    assert.ok(pay.transfers[0].tia);
  });
  test("DSAR log CSV: detected, dates read day-first, converted", () => {
    const p = parseInput([{ name: "dsar.csv", text: DSAR_CSV }]);
    const file = p.files[0];
    assert.equal(file.kind, "dsar");
    assert.equal(file.confidence, "high");
    assert.equal(file.dateOrder, "dmy");
    const { records } = csvToDsars(file.rows, file.mapping, { dateOrder: file.dateOrder });
    assert.equal(records.length, 3);
    assert.equal(records[0].type, "access");
    assert.equal(records[0].received, "2026-09-15");
    assert.equal(records[1].type, "erasure");
    assert.ok(records[1].extended);
    assert.equal(records[2].type, "objection");
    const r = run([], {}, records);
    assert.ok(r.findings.some((f) => f.id.startsWith("dfr:dsar-overdue:")));
  });
  test("this tool's DSAR CSV re-imports (round trip)", () => {
    const ex = exampleDataset();
    const res = analyze(ex, { now: ex.now });
    const csv = dsarCsv(ex.dsars, res);
    assert.ok(csv.startsWith("Reference,Request type,Article,Received,Identity verified,Clock start,Extended,Extension notified,Due,Completed,Status"));
    const p = parseInput(csv);
    assert.equal(p.kind, "dsar");
    const { records } = csvToDsars(p.rows, p.mapping);
    assert.equal(records.length, 10);
    assert.equal(records.find((d) => d.ref === "DSR-2026-006").extensionNotified, "2026-09-05");
  });
  test("register JSON (this tool's export) parses both record types", () => {
    const ex = exampleDataset();
    const p = parseInput([{ name: "dataflow-register.json", text: JSON.stringify({ tool: TOOL_ID, activities: ex.activities, dsars: ex.dsars }) }]);
    assert.equal(p.format, "dataflow-register");
    assert.equal(p.activities.length, 8);
    assert.equal(p.dsars.length, 10);
    assert.ok(parseInput([{ name: "x.json", text: '{"a":1}' }]).skipped.length === 1);
  });
  test("CSV without a name or purpose column reports the gap", () => {
    const p = parseInput("foo,bar\n1,2\n");
    assert.ok(p.skipped.some((s) => /no activity name or purpose column/.test(s.reason)));
    assert.equal(p.files[0].confidence, "low");
  });
  test("free-text categories map to the vocabulary (special categories recognised)", () => {
    const a = normalizeActivity({ dataCategories: "Full name; email address; medical history; trade union membership; fingerprints; favourite colour" });
    assert.deepEqual(a.dataCategories, ["biometric", "contact", "favourite colour", "health", "identity", "trade-union"]);
  });
});

group("dataflow: DLP seeding and exports", () => {
  test("categories are seeded from every DLP personal-data detector", () => {
    for (const d of DETECTORS.filter((x) => x.kind === "pii")) assert.ok(CATEGORIES.some((c) => c.dlp.includes(d.id)), d.id);
  });
  test("suggestCategories scans a sample and masks values", () => {
    const s = suggestCategories("Ada Test, ada@test.darknode.ai, card 4111 1111 1111 1111, IBAN GB82WEST12345698765432");
    const ids2 = s.map((x) => x.category);
    assert.ok(ids2.includes("contact") && ids2.includes("payment-card") && ids2.includes("bank"), ids2.join(","));
    assert.ok(!JSON.stringify(s).includes("4111 1111 1111 1111"));
    assert.equal(suggestCategories("nothing here").length, 0);
  });
  test("findingsToCsv header row", () => {
    const csv = findingsToCsv([{ id: "x", severity: "high", confidence: "likely", title: "T", controls: [{ framework: "GDPR", id: "Art.6(1)" }], evidence: [{}] }]);
    assert.equal(csv.split("\r\n")[0], "id,severity,confidence,category,title,description,recommendation,controls,assets,evidenceCount");
    assert.ok(csv.includes("GDPR Art.6(1)"));
  });
  test("ROPA processor variant carries Art. 30(2) fields only for processor records", () => {
    const ex = exampleDataset();
    const csv = ropaCsv(ex.activities, { variant: "processor", org: ex.org });
    const lines = csv.trim().split("\r\n");
    assert.equal(lines.length, 2);
    assert.ok(lines[0].startsWith("Processor name and contact details,Data protection officer,Representative,Processing activity,Controller on whose behalf"));
    assert.ok(lines[1].includes("Philippines - Vendor E Support BPO"));
  });
  test("DPIA memo lists the nine criteria and the counsel caveat", () => {
    const ex = exampleDataset();
    const memo = dpiaMemo(ex.activities.find((a) => a.id === "testorg-act-04"), { now: ex.now, org: ex.org, example: true });
    assert.ok(memo.includes("SYNTHETIC EXAMPLE"));
    assert.equal((memo.match(/^\s+\d\. \[/gm) || []).length, 9);
    assert.ok(memo.includes("Criteria met: 4 of 9"));
    assert.ok(/DPIA LIKELY REQUIRED/.test(memo) && /Verify with counsel/.test(memo));
  });
  test("ICS: open DSAR deadlines, extension-notice dates, reviews and DPIA re-assessments", () => {
    const ex = exampleDataset();
    const ev = icsEvents(ex, { now: ex.now });
    assert.equal(ev.filter((e) => /^DSAR .* due/.test(e.summary)).length, 3);
    assert.ok(ev.some((e) => e.summary.startsWith("Re-assess DPIA: Payroll")));
    assert.equal(ev.filter((e) => e.summary.startsWith("Review processing activity")).length, 8);
    const ics = toIcs(ev);
    assert.ok(ics.includes("DTSTART;VALUE=DATE:20261020"));
    assert.equal(JSON.stringify(icsEvents(ex, { now: ex.now })), JSON.stringify(ev));
  });
  test("summary text names the reference version and the counsel caveat", () => {
    const ex = exampleDataset();
    const t = summaryText(analyze(ex, { now: ex.now, adequacy: ADEQ, org: ex.org }), { org: ex.org, example: true });
    assert.ok(t.includes("reference data " + ADEQ.version) && t.includes("verify with counsel"));
    assert.ok(t.includes("does not make the organisation compliant"));
  });
});

group("dataflow: register round-trip", () => {
  test("activities mirror as CONTROL and DSARs as CASE; team members see the same register", () => {
    const m = new Map();
    const storage = { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
    const E = {}; let n = 0;
    const graph = { create: (type, name, data, o) => { const e = { id: "g" + (++n), type, name, data, source: o.source, severity: o.severity, status: o.status }; E[e.id] = e; return e; }, update: (id, u) => Object.assign(E[id], u), remove: (id) => delete E[id], list: (t) => Object.values(E).filter((e) => e.type === t), get: (id) => E[id] || null };
    const reg = openRegister(TOOL_ID, "CONTROL", { schema: ACTIVITY_SCHEMA, storage, graph, now: () => NOW });
    const dreg = openRegister(TOOL_ID + "-dsar", "CASE", { schema: DSAR_SCHEMA, storage, graph, now: () => NOW });
    const ex = exampleDataset();
    const saved = reg.upsert(ex.activities[1]);
    const ds = dreg.upsert(ex.dsars[7]);
    const e = E[saved.graphId];
    assert.equal(e.type, "CONTROL");
    assert.equal(e.name, "Processing activity: Payroll and HR administration");
    assert.equal(e.data.controlId, "Art.30");
    assert.equal(e.data.registerId, TOOL_ID);
    assert.equal(E[ds.graphId].type, "CASE");
    assert.equal(E[ds.graphId].status, "open");
    assert.equal(E[ds.graphId].data.state, "open");
    m.set("dn_active_ws", "team1");
    const team = openRegister(TOOL_ID, "CONTROL", { schema: ACTIVITY_SCHEMA, storage, graph, now: () => NOW });
    assert.equal(team.list()[0].transfers[0].mechanism, "scc-2021");
    m.delete("dn_active_ws");
    const back = JSON.parse(reg.exportJson());
    const r = analyze({ activities: back, dsars: JSON.parse(dreg.exportJson()) }, { now: NOW, adequacy: ADEQ, org: ORG, knownVendors: [] });
    assert.equal(r.summary.activities, 1);
    assert.equal(r.summary.dsarOverdue, 1);
    assert.ok(reg.remove(saved.id) && !E[saved.graphId]);
  });
});
