// Awareness & Phishing-Test Analytics engine tests (public/js/compliance/awareness-engine.js):
// one parser test per export layout, rates and denominators, privacy suppression,
// repeat clickers across imports and the saved history (register round-trip),
// high-risk roles, training checks, trend flags, exports, determinism, selfTest.

import { test, assert, group } from "../harness.mjs";
import {
  selfTest, analyze, parseInput, detect, remapFile, parseTime, truthy, normEmail, twoPropZ, mergeHistory, csvCell,
  findingsToCsv, repeatClickersCsv, departmentScorecardCsv, remedialAssignmentsCsv, summaryText, exampleDataset, exampleParsed,
  REGISTER_SCHEMA, DEFAULTS, TOOL_ID,
} from "../../public/js/compliance/awareness-engine.js";
import { openRegister } from "../../public/js/core/register.js";

// ---- fixtures in the vendor layouts ----
// GoPhish "Export CSV - Results" (Result model JSON fields, in export order).
const GOPHISH_RESULTS = [
  "id,status,ip,latitude,longitude,send_date,reported,modified_date,email,first_name,last_name,position",
  "1,Email Sent,,0,0,2026-03-03T14:00:00.123456789Z,false,2026-03-03T14:00:00.123456789Z,ava.ash@test.darknode.ai,Ava,Ash,Engineer",
  "2,Clicked Link,203.0.113.5,0,0,2026-03-03T14:00:20Z,false,2026-03-03T15:00:00Z,ben.birch@test.darknode.ai,Ben,Birch,Controller",
  "3,Submitted Data,203.0.113.6,0,0,2026-03-03T14:00:40Z,true,2026-03-03T15:10:00Z,cy.cole@test.darknode.ai,Cy,Cole,Sales Rep",
  "4,Email Opened,,0,0,2026-03-03T14:01:00Z,true,2026-03-03T14:30:00Z,di.dale@test.darknode.ai,Di,Dale,Engineer",
  "5,Error,,0,0,0001-01-01T00:00:00Z,false,2026-03-03T14:01:20Z,ed.elm@test.darknode.ai,Ed,Elm,Engineer",
  "6,Scheduled,,0,0,2026-03-04T14:00:00Z,false,2026-03-03T14:01:20Z,fi.fox@test.darknode.ai,Fi,Fox,Engineer",
].join("\n");

// GoPhish "Export CSV - Raw Events" (Event model: campaign_id, email, time, message, details).
const GOPHISH_EVENTS = [
  "campaign_id,email,time,message,details",
  "7,,2026-04-01T09:59:00Z,Campaign Created,",
  "7,ava.ash@test.darknode.ai,2026-04-01T10:00:00Z,Email Sent,",
  "7,ava.ash@test.darknode.ai,2026-04-01T10:05:00Z,Email Opened,\"{\"\"payload\"\":{\"\"rid\"\":[\"\"x\"\"]}}\"",
  "7,ava.ash@test.darknode.ai,2026-04-01T10:20:00Z,Clicked Link,\"{\"\"payload\"\":{\"\"rid\"\":[\"\"x\"\"]}}\"",
  "7,ava.ash@test.darknode.ai,2026-04-01T10:22:00Z,Submitted Data,\"{\"\"payload\"\":{\"\"password\"\":[\"\"never-stored\"\"]}}\"",
  "7,ben.birch@test.darknode.ai,2026-04-01T10:00:20Z,Email Sent,",
  "7,ben.birch@test.darknode.ai,2026-04-01T10:10:20Z,Email Reported,",
  "7,cy.cole@test.darknode.ai,2026-04-01T10:00:40Z,Email Sent,",
  "7,cy.cole@test.darknode.ai,2026-04-01T11:00:40Z,Clicked Link,",
  "7,cy.cole@test.darknode.ai,2026-04-01T11:30:40Z,Email Reported,",
].join("\n");

// GoPhish API: GET /api/campaigns/:id (name, launch_date, results[], timeline[]).
const GOPHISH_JSON = JSON.stringify({
  id: 9, name: "Parcel lure", created_date: "2026-05-01T08:00:00-05:00", launch_date: "2026-05-01T09:00:00-05:00", status: "Completed",
  results: [{ id: "r1", email: "ava.ash@test.darknode.ai", first_name: "Ava", last_name: "Ash", position: "", status: "Clicked Link", ip: "", latitude: 0, longitude: 0, send_date: "2026-05-01T09:00:00-05:00", reported: false, modified_date: "2026-05-01T09:30:00-05:00" }],
  timeline: [
    { campaign_id: 9, email: "", time: "2026-05-01T08:00:00-05:00", message: "Campaign Created", details: "" },
    { campaign_id: 9, email: "ava.ash@test.darknode.ai", time: "2026-05-01T09:00:00-05:00", message: "Email Sent", details: "" },
    { campaign_id: 9, email: "ava.ash@test.darknode.ai", time: "2026-05-01T09:30:00-05:00", message: "Clicked Link", details: "{}" },
  ],
});

// KnowBe4 Reporting API: /v1/phishing/security_tests/{pst_id}/recipients
const KB4_JSON = JSON.stringify([
  { recipient_id: 1, pst_id: 55, user: { id: 10, first_name: "Ava", last_name: "Ash", email: "Ava.Ash@test.darknode.ai" }, template: { id: 1, name: "t" }, scheduled_at: "2026-06-01T10:00:00.000Z", delivered_at: "2026-06-01T10:00:05.000Z", opened_at: null, clicked_at: "2026-06-01T10:30:05.000Z", replied_at: null, attachment_opened_at: null, macro_enabled_at: null, data_entered_at: null, qr_code_scanned: null, reported_at: null, bounced_at: null, ip: null, ip_location: null, browser: null, browser_version: null, os: null },
  { recipient_id: 2, pst_id: 55, user: { id: 11, first_name: "Ben", last_name: "Birch", email: "ben.birch@test.darknode.ai" }, template: { id: 1, name: "t" }, scheduled_at: "2026-06-01T10:00:00.000Z", delivered_at: "2026-06-01T10:00:06.000Z", opened_at: "2026-06-01T10:02:00.000Z", clicked_at: null, replied_at: null, attachment_opened_at: null, macro_enabled_at: null, data_entered_at: null, qr_code_scanned: null, reported_at: "2026-06-01T10:03:00.000Z", bounced_at: null, ip: null, ip_location: null, browser: null, browser_version: null, os: null },
  { recipient_id: 3, pst_id: 55, user: { id: 12, first_name: "Cy", last_name: "Cole", email: "cy.cole@test.darknode.ai" }, template: { id: 1, name: "t" }, scheduled_at: "2026-06-01T10:00:00.000Z", delivered_at: null, opened_at: null, clicked_at: null, replied_at: null, attachment_opened_at: null, macro_enabled_at: null, data_entered_at: null, qr_code_scanned: null, reported_at: null, bounced_at: "2026-06-01T10:00:07.000Z", ip: null, ip_location: null, browser: null, browser_version: null, os: null },
]);

// KnowBe4 console CSV (column layout not verified: KnowBe4 publishes no export column list publicly).
const KB4_CSV = "First Name,Last Name,Email,Delivered At,Opened At,Clicked At,Replied At,Attachment Opened At,Macro Enabled At,Data Entered At,Reported At,Bounced At\n" +
  "Ava,Ash,ava.ash@test.darknode.ai,2026-07-01 10:00:00,2026-07-01 10:01:00,2026-07-01 10:02:00,,,,2026-07-01 10:03:00,,\n" +
  "Ben,Birch,ben.birch@test.darknode.ai,2026-07-01 10:00:00,,,,,,,2026-07-01 10:04:00,\n";

// Microsoft Graph: security/attackSimulation/simulations/{id}/report/simulationUsers (userSimulationDetails).
const MDO_JSON = JSON.stringify({
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#Collection(microsoft.graph.userSimulationDetails)",
  value: [
    { assignedTrainingsCount: 1, completedTrainingsCount: 0, compromisedDateTime: "2026-08-01T10:10:00Z", inProgressTrainingsCount: 0, isCompromised: true, latestSimulationActivity: "Compromised", reportedPhishDateTime: null, simulationEvents: [{ eventName: "SuccessfullyDeliveredEmail", eventDateTime: "2026-08-01T10:00:00Z" }, { eventName: "EmailLinkClicked", eventDateTime: "2026-08-01T10:08:00Z" }], simulationUser: { userId: "u1", displayName: "Ava Ash", email: "ava.ash@test.darknode.ai" }, trainingEvents: [] },
    { assignedTrainingsCount: 0, completedTrainingsCount: 0, compromisedDateTime: null, inProgressTrainingsCount: 0, isCompromised: false, latestSimulationActivity: "Reported", reportedPhishDateTime: "2026-08-01T10:05:00Z", simulationEvents: [{ eventName: "SuccessfullyDeliveredEmail", eventDateTime: "2026-08-01T10:00:00Z" }], simulationUser: { userId: "u2", displayName: "Ben Birch", email: "ben.birch@test.darknode.ai" }, trainingEvents: [] },
  ],
});

const MDO_CSV = "Name,Email,Simulation name,Compromised,Clicked,Reported\nAva Ash,ava.ash@test.darknode.ai,Payroll update,Yes,Yes,No\nBen Birch,ben.birch@test.darknode.ai,Payroll update,No,No,Yes\n";
const PFPT_CSV = "First Name,Last Name,Email Address,Campaign Title,Clicked,Clicked Date,Data Entered,Reported,Reported Date\nAva,Ash,ava.ash@test.darknode.ai,Q3 Benefits,Yes,9/2/2026 10:15 AM,No,No,\nBen,Birch,ben.birch@test.darknode.ai,Q3 Benefits,No,,No,Yes,9/2/2026 10:05 AM\n";
// Documented layouts. Build a CSV from a header list and per-row {header: value} objects.
const layoutCsv = (headers, rows) => [headers.join(",")].concat(rows.map((o) => headers.map((h) => (o[h] == null ? "" : o[h])).join(","))).join("\n") + "\n";
// Defender Attack simulation training CSV export fields, in documented order
// (learn.microsoft.com/en-us/defender-office-365/attack-simulation-training-insights, Appendix).
const MDO_EXPORT_HEADERS = ["UserName", "UserMail", "Compromised", "AttachmentOpened_TimeStamp", "AttachmentOpened_Browser", "AttachmentOpened_IP", "AttachmentOpened_Device",
  "AttachmentLinkClicked_TimeStamp", "AttachmentLinkClicked_Browser", "AttachmentLinkClicked_IP", "AttachmentLinkClicked_Device", "EmailLinkClicked_TimeStamp", "EmailLinkClicked_Browser",
  "EmailLinkClicked_IP", "EmailLinkClicked_Device", "EmailLinkClicked_ClickSource", "CredSupplied_TimeStamp(Compromised)", "CredSupplied_Browser", "CredSupplied_IP", "CredSupplied_Device",
  "SuccessfullyDeliveredEmail_TimeStamp", "MessageRead_TimeStamp", "MessageDeleted_TimeStamp", "MessageReplied_TimeStamp", "MessageForwarded_TimeStamp", "OutOfOfficeDays",
  "PositiveReinforcementMessageDelivered_TimeStamp", "PositiveReinforcementMessageFailed_TimeStamp", "JustSimulationMessageDelivered_TimeStamp", "JustSimulationMessageFailed_TimeStamp",
  "TrainingAssignmentMessageDelivered_TimeStamp", "TrainingAssignmentMessageFailed_TimeStamp", "FailedToDeliverEmail_TimeStamp", "Last Simulation Activity", "Assigned Trainings",
  "Completed Trainings", "Training Status", "Phishing Reported On", "Department", "Company", "Title", "Office", "City", "Country", "Manager"];
const MDO_EXPORT = layoutCsv(MDO_EXPORT_HEADERS, [
  { UserName: "Ava Ash", UserMail: "ava.ash@test.darknode.ai", Compromised: "Yes", SuccessfullyDeliveredEmail_TimeStamp: "2026-08-01T10:00:00Z", MessageRead_TimeStamp: "2026-08-01T10:04:00Z", EmailLinkClicked_TimeStamp: "2026-08-01T10:08:00Z", "CredSupplied_TimeStamp(Compromised)": "2026-08-01T10:09:00Z", Title: "Controller" },
  { UserName: "Ben Birch", UserMail: "ben.birch@test.darknode.ai", Compromised: "No", JustSimulationMessageDelivered_TimeStamp: "2026-08-01T10:00:00Z", "Phishing Reported On": "2026-08-01T10:03:00Z" },
  { UserName: "Cy Cole", UserMail: "cy.cole@test.darknode.ai", Compromised: "Yes", SuccessfullyDeliveredEmail_TimeStamp: "2026-08-01T10:00:00Z", AttachmentOpened_TimeStamp: "2026-08-01T10:20:00Z" },
  { UserName: "Di Dale", UserMail: "di.dale@test.darknode.ai", Compromised: "No", FailedToDeliverEmail_TimeStamp: "2026-08-01T10:00:00Z" },
]);
// Defender simulation details "Users" tab columns (attack-simulation-training-simulations, Users tab).
const MDO_USERS_TAB = "Name,Compromised,Reported,Training status,Other actions,Compromised on,Reported on,Failed deliveries,Username\n" +
  "Ava Ash,Yes,No,Not started,,2026-08-02T09:10:00Z,,,ava.ash@test.darknode.ai\n" +
  "Ben Birch,No,Yes,Not assigned,,,2026-08-02T09:05:00Z,,ben.birch@test.darknode.ai\n";
// Proofpoint Security Awareness (ThreatSim) data-entry campaign CSV header definitions, in documented order
// (as republished by Proofpoint partners; official Proofpoint docs require a customer login).
const PFPT_DATA_ENTRY_HEADERS = ["First Name", "Last Name", "Campaign Guid", "Users Guid", "Primary Email Opened", "Date Email Opened", "Primary Clicked", "Date Clicked",
  "Primary Compromised Login", "Date Login Compromised", "Multi Email Open", "Multi Click Event", "Multi Compromised", "Email Address", "Date Sent", "Campaign Title",
  "Template Sophistication", "Campaign Recipient List", "Email Opened IP Address", "Email Opened Browser", "Email Opened Browser Version", "Email Opened OS", "Email Opened OS Version",
  "Email Opened User Agent", "Clicked IP Address", "Clicked Host Name", "Clicked Browser", "Clicked Browser Version", "Clicked OS", "Clicked OS Version", "Clicked User Agent", "Username",
  "Teachable Moment Started", "Acknowledgement Completed", "Date Acknowledged", "Weak Egress", "Reported", "Date Reported", "Email Bounced", "Passed?", "Password Entered",
  "Vulnerability Count", "Phishing Template"];
const PF_NO = { "Primary Email Opened": "FALSE", "Primary Clicked": "FALSE", "Primary Compromised Login": "FALSE", Reported: "FALSE", "Email Bounced": "FALSE", "Campaign Title": "Q4 Payroll", "Date Sent": "2026-10-01 09:00:00" };
const PFPT_DATA_ENTRY = layoutCsv(PFPT_DATA_ENTRY_HEADERS, [
  { ...PF_NO, "First Name": "Ava", "Last Name": "Ash", "Email Address": "ava.ash@test.darknode.ai", "Primary Email Opened": "TRUE", "Date Email Opened": "2026-10-01 09:05:00", "Primary Clicked": "TRUE", "Date Clicked": "2026-10-01 09:12:00", "Primary Compromised Login": "TRUE", "Date Login Compromised": "2026-10-01 09:13:00", Username: "typed-name", "Passed?": "FALSE" },
  { ...PF_NO, "First Name": "Ben", "Last Name": "Birch", "Email Address": "ben.birch@test.darknode.ai", Reported: "TRUE", "Date Reported": "2026-10-01 09:02:00", "Passed?": "TRUE" },
  { ...PF_NO, "First Name": "Cy", "Last Name": "Cole", "Email Address": "cy.cole@test.darknode.ai", "Email Bounced": "TRUE", "Date Sent": "" },
]);
// Proofpoint attachment campaign: opening the attachment is the failure, in "Primary Attachment Opened".
const PFPT_ATTACH = "First Name,Last Name,Email Address,Date Sent,Campaign Title,Primary Clicked,Date Clicked,Primary Attachment Opened,Date Attachment Opened,Reported,Date Reported,Email Bounced\n" +
  "Ava,Ash,ava.ash@test.darknode.ai,2026-10-05 09:00:00,Invoice attachment,FALSE,,TRUE,2026-10-05 09:30:00,FALSE,,FALSE\n" +
  "Ben,Birch,ben.birch@test.darknode.ai,2026-10-05 09:00:00,Invoice attachment,FALSE,,FALSE,,TRUE,2026-10-05 09:10:00,FALSE\n";
const LMS_CSV = "user,course,assigned,due,completed\nava.ash@test.darknode.ai,Annual Awareness,2026-01-05,2026-02-01,\nben.birch@test.darknode.ai,Annual Awareness,2026-01-05,2026-02-01,2026-01-20\n";
const ROSTER_CSV = "email,department,title,manager,hire date,privileged,finance,exec\nava.ash@test.darknode.ai,Engineering,Engineer,mo@test.darknode.ai,2020-01-01,no,no,no\nben.birch@test.darknode.ai,Finance,Controller,mo@test.darknode.ai,2026-06-01,no,yes,no\n";

// ---- helpers ----
const P = (name, text, campaign) => { const f = parseInput([{ name, text }]).files[0]; f.campaign = campaign || ""; return f; };
const people = (n, dept = "Sales") => Array.from({ length: n }, (_, i) => ({ email: "p" + i + "." + dept.toLowerCase() + "@test.darknode.ai", dept }));
// Generic results CSV with explicit columns.
function genericCsv(campaign, date, rows) {
  return "email,campaign,sent,clicked,submitted,reported\n" + rows.map((r) => [r.email, campaign, date, r.c ? date : "", r.s ? date : "", r.r ? date : ""].join(",")).join("\n") + "\n";
}
function rosterCsv(list, extra = {}) {
  return "email,department,title,manager,hire date,privileged,finance,exec\n" + list.map((p) => [p.email, p.dept, extra.title || "Analyst", "boss@test.darknode.ai", "2022-01-01", "no", extra.finance ? "yes" : "no", "no"].join(",")).join("\n") + "\n";
}
const ids = (r) => r.findings.map((f) => f.id);

group("awareness: parsers", () => {
  test("GoPhish results CSV detected with high confidence and status ladder applied", () => {
    const f = P("res.csv", GOPHISH_RESULTS, "Invoice");
    assert.equal(f.kind, "gophish-results"); assert.equal(f.confidence, "high");
    const r = analyze({ files: [f] });
    const c = r.tables.campaigns[0];
    assert.equal(c.campaign, "Invoice");
    assert.equal(c.delivered, 4, "error and scheduled rows are not delivered");
    assert.equal(c.clicked.num, 2); assert.equal(c.submitted.num, 1); assert.equal(c.reported.num, 2); assert.equal(c.opened.num, 3);
    assert.equal(c.clicked.den, 4);
  });
  test("GoPhish raw events CSV detected; times, report-before-click and medians", () => {
    const f = P("ev.csv", GOPHISH_EVENTS);
    assert.equal(f.kind, "gophish-events"); assert.equal(f.confidence, "high");
    const r = analyze({ files: [f] });
    const c = r.tables.campaigns[0];
    assert.equal(c.campaign, "GoPhish campaign 7");
    assert.equal(c.delivered, 3); assert.equal(c.clicked.num, 2); assert.equal(c.reported.num, 2);
    assert.equal(c.reportBeforeClick.num, 1, "ben reported without clicking; cy reported after clicking");
    assert.equal(c.medianMinutesToClick, 40, "median of 20 and 60 minutes");
    assert.equal(c.date, "2026-04-01");
    assert.equal(r.meta.warnings.length, 0, "Campaign Created rows are not a warning");
    assert.ok(!JSON.stringify(r).includes("never-stored"), "event details are never carried");
  });
  test("GoPhish API JSON uses the campaign name and timezone offsets", () => {
    const f = P("c.json", GOPHISH_JSON);
    assert.equal(f.kind, "gophish-json");
    const r = analyze({ files: [f] });
    assert.equal(r.tables.campaigns[0].campaign, "Parcel lure");
    assert.equal(r.tables.campaigns[0].medianMinutesToClick, 30);
    assert.equal(r.meta.now, "2026-05-01T14:30:00.000Z");
  });
  test("KnowBe4 Reporting API JSON: emails normalised, bounce not delivered", () => {
    const f = P("kb.json", KB4_JSON);
    assert.equal(f.kind, "knowbe4-json"); assert.equal(f.confidence, "high");
    const r = analyze({ files: [f] });
    const c = r.tables.campaigns[0];
    assert.equal(c.campaign, "KnowBe4 PST 55");
    assert.equal(c.delivered, 2); assert.equal(c.clicked.num, 1); assert.equal(c.reported.num, 1); assert.equal(c.reportBeforeClick.num, 1);
    assert.equal(c.medianMinutesToClick, 30);
  });
  test("KnowBe4 console CSV is medium confidence with an auto mapping", () => {
    const f = P("kb.csv", KB4_CSV, "KB July");
    assert.equal(f.kind, "knowbe4-csv"); assert.equal(f.confidence, "medium");
    assert.equal(f.mapping.clicked, "Clicked At"); assert.equal(f.mapping.submitted, "Data Entered At");
    const c = analyze({ files: [f] }).tables.campaigns[0];
    assert.equal(c.submitted.num, 1); assert.equal(c.reported.num, 1);
  });
  test("Microsoft Graph attack simulation JSON: compromised counts as click and submission", () => {
    const f = P("mdo.json", MDO_JSON, "Payroll");
    assert.equal(f.kind, "mdo-json");
    const c = analyze({ files: [f] }).tables.campaigns[0];
    assert.equal(c.clicked.num, 1); assert.equal(c.submitted.num, 1); assert.equal(c.reported.num, 1);
    assert.equal(c.medianMinutesToClick, 8);
  });
  test("Defender CSV and Proofpoint CSV are medium confidence and read campaign columns", () => {
    const m = P("mdo.csv", MDO_CSV), p = P("pf.csv", PFPT_CSV);
    assert.equal(m.kind, "mdo-csv"); assert.equal(m.confidence, "medium");
    assert.equal(p.kind, "proofpoint-csv"); assert.equal(p.confidence, "medium");
    const r = analyze({ files: [m, p] });
    assert.deepEqual(r.tables.campaigns.map((c) => c.campaign).sort(), ["Payroll update", "Q3 Benefits"]);
    const q = r.tables.campaigns.find((c) => c.campaign === "Q3 Benefits");
    assert.equal(q.clicked.num, 1); assert.equal(q.date, "2026-09-02");
  });
  test("Defender documented CSV export: high confidence, per-technique columns and delivery failures", () => {
    const f = P("Attack simulation report - Microsoft Defender.csv", MDO_EXPORT, "Payroll Aug");
    assert.equal(f.kind, "mdo-csv"); assert.equal(f.confidence, "high");
    assert.equal(f.mapping.email, "UserMail"); assert.equal(f.mapping.submitted, "Compromised");
    assert.equal(f.mapping.reported, "Phishing Reported On"); assert.equal(f.mapping.bounced, "FailedToDeliverEmail_TimeStamp");
    const c = analyze({ files: [f] }).tables.campaigns[0];
    assert.equal(c.delivered, 3); assert.equal(c.clicked.num, 2); assert.equal(c.submitted.num, 2); assert.equal(c.reported.num, 1);
    assert.equal(c.medianMinutesToClick, 14);
  });
  test("Defender Users tab columns map at medium confidence; no click column is reported, not guessed", () => {
    const f = P("users.csv", MDO_USERS_TAB, "Payroll Aug");
    assert.equal(f.kind, "mdo-csv"); assert.equal(f.confidence, "medium");
    assert.equal(f.mapping.email, "Username"); assert.equal(f.mapping.submittedTime, "Compromised on"); assert.equal(f.mapping.reportedTime, "Reported on");
    assert.deepEqual(f.missing, ["clicked"]);
    assert.ok(analyze({ files: [f] }).skipped.some((x) => /required column/.test(x.reason)));
  });
  test("Proofpoint documented data-entry CSV: high confidence, TRUE/FALSE flags, typed Username ignored", () => {
    const f = P("pfpt.csv", PFPT_DATA_ENTRY);
    assert.equal(f.kind, "proofpoint-csv"); assert.equal(f.confidence, "high");
    assert.equal(f.mapping.email, "Email Address"); assert.equal(f.mapping.campaign, "Campaign Title");
    assert.equal(f.mapping.clicked, "Primary Clicked"); assert.equal(f.mapping.clickedTime, "Date Clicked");
    assert.equal(f.mapping.submitted, "Primary Compromised Login"); assert.equal(f.mapping.bounced, "Email Bounced");
    const c = analyze({ files: [f] }).tables.campaigns[0];
    assert.equal(c.campaign, "Q4 Payroll");
    assert.equal(c.delivered, 2); assert.equal(c.clicked.num, 1); assert.equal(c.submitted.num, 1); assert.equal(c.reported.num, 1);
    assert.equal(c.medianMinutesToClick, 12);
  });
  test("Proofpoint attachment campaign counts the attachment open as the click", () => {
    const f = P("pfpt-attach.csv", PFPT_ATTACH);
    assert.equal(f.kind, "proofpoint-csv");
    const c = analyze({ files: [f] }).tables.campaigns[0];
    assert.equal(c.clicked.num, 1); assert.equal(c.reported.num, 1); assert.equal(c.medianMinutesToClick, 30);
  });
  test("LMS and roster templates are detected with high confidence", () => {
    assert.equal(P("lms.csv", LMS_CSV).kind, "lms"); assert.equal(P("lms.csv", LMS_CSV).confidence, "high");
    const r = P("hr.csv", ROSTER_CSV);
    assert.equal(r.kind, "roster"); assert.equal(r.confidence, "high"); assert.equal(r.mapping.hireDate, "hire date");
  });
  test("history JSON exported by this tool is recognised", () => {
    const f = P("h.json", JSON.stringify([{ id: "a@test.darknode.ai", email: "a@test.darknode.ai", campaigns: [{ campaign: "X", date: "2026-01-01", clicked: true }] }]));
    assert.equal(f.kind, "history");
  });
  test("unknown file is skipped with a reason; remapFile makes it usable", () => {
    const f = P("odd.csv", "mailbox,hit\nava.ash@test.darknode.ai,yes\n", "Odd");
    assert.equal(f.kind, "unknown");
    const r = analyze({ files: [f] });
    assert.ok(r.skipped.some((s) => s.check === "file odd.csv"));
    const g = remapFile(f, "generic-phish", { email: "mailbox", clicked: "hit" });
    assert.equal(g.confidence, "user");
    assert.equal(analyze({ files: [{ ...g, campaign: "Odd" }] }).tables.campaigns[0].clicked.num, 1);
  });
  test("required mapping missing is reported, not guessed", () => {
    const f = remapFile(P("kb.csv", KB4_CSV), "knowbe4-csv", { email: "Email" });
    assert.deepEqual(f.missing, ["clicked"]);
    assert.ok(analyze({ files: [f] }).skipped.some((s) => /Clicked/.test(s.reason)));
  });
  test("single-string parseInput keeps the contract shape", () => {
    const p = parseInput(GOPHISH_RESULTS);
    assert.equal(p.format, "csv"); assert.equal(p.rows.length, 6); assert.equal(p.headers[0], "id");
    assert.equal(parseInput("").files[0].format, "empty");
  });
});

group("awareness: value helpers", () => {
  test("parseTime handles nanoseconds, offsets, US dates and GoPhish zero time", () => {
    assert.equal(parseTime("2026-03-03T14:00:00.123456789Z"), Date.UTC(2026, 2, 3, 14, 0, 0, 123));
    assert.equal(parseTime("2026-05-01T09:00:00-05:00"), Date.UTC(2026, 4, 1, 14));
    assert.equal(parseTime("9/2/2026 12:15 PM"), Date.UTC(2026, 8, 2, 12, 15));
    assert.equal(parseTime("9/2/2026 12:15 AM"), Date.UTC(2026, 8, 2, 0, 15));
    assert.equal(parseTime("0001-01-01T00:00:00Z"), null);
    assert.equal(parseTime("soon"), null);
  });
  test("truthy reads flags, timestamps and negatives", () => {
    for (const v of ["Yes", "TRUE", "1", "2026-01-01", true, 2]) assert.ok(truthy(v), String(v));
    for (const v of ["", "No", "false", "0", "Not Clicked", null, "n/a", false]) assert.ok(!truthy(v), String(v));
    assert.equal(normEmail(" MAILTO:Ava@Test.Darknode.AI "), "ava@test.darknode.ai");
  });
  test("twoPropZ and csvCell", () => {
    assert.equal(twoPropZ(0, 0, 1, 2), null);
    assert.ok(Math.abs(twoPropZ(10, 100, 30, 100) - 3.536) < 0.01);
    assert.equal(csvCell("=HYPERLINK(1)"), "\"'=HYPERLINK(1)\"");
  });
});

group("awareness: analysis", () => {
  const sales = people(6, "Sales"), legal = people(3, "Legal");
  const all = sales.concat(legal);
  const roster = P("hr.csv", rosterCsv(all));

  test("department breakdown suppresses groups under the minimum and edits apply", () => {
    const f = P("a.csv", genericCsv("A", "2026-01-10", all.map((p, i) => ({ email: p.email, c: i % 2 === 0 }))));
    const r = analyze({ files: [f, roster] });
    const d = r.tables.breakdowns.department;
    assert.equal(d.find((g) => g.group === "Legal").suppressed, true);
    assert.equal(d.find((g) => g.group === "Legal").clicked, null);
    assert.equal(d.find((g) => g.group === "Sales").people, 6);
    const r3 = analyze({ files: [f, roster] }, { minGroupSize: 3 });
    assert.equal(r3.tables.breakdowns.department.find((g) => g.group === "Legal").suppressed, false, "edge: exactly the minimum is shown");
    assert.ok(r.tables.breakdowns.tenure && r.tables.breakdowns.manager && r.tables.breakdowns.title);
  });
  test("missing roster skips breakdowns and high-risk with reasons", () => {
    const f = P("a.csv", genericCsv("A", "2026-01-10", [{ email: "x@test.darknode.ai", c: true }]));
    const r = analyze({ files: [f] });
    assert.ok(r.skipped.some((s) => /breakdowns/.test(s.check)));
    assert.ok(r.skipped.some((s) => s.check === "high-risk roles"));
    assert.ok(r.skipped.some((s) => s.check === "overdue training"));
  });
  test("missing report column is skipped per campaign", () => {
    const f = P("pf.csv", "email,campaign,clicked\nx@test.darknode.ai,A,yes\n");
    const r = analyze({ files: [f] });
    assert.ok(r.skipped.some((s) => s.check === "report rate: A"));
    assert.equal(r.tables.campaigns[0].hasReport, false);
  });
  test("repeat clickers: threshold edge and needs-follow-up label", () => {
    const a = P("a.csv", genericCsv("A", "2026-01-10", [{ email: "r@test.darknode.ai", c: true }, { email: "o@test.darknode.ai", c: true }]));
    const b = P("b.csv", genericCsv("B", "2026-02-10", [{ email: "r@test.darknode.ai", c: true }, { email: "o@test.darknode.ai" }]));
    const r = analyze({ files: [a, b] });
    assert.deepEqual(r.tables.repeatClickers.map((x) => x.email), ["r@test.darknode.ai"]);
    assert.equal(r.tables.repeatClickers[0].status, "needs follow-up training");
    assert.ok(ids(r).includes("repeat-click"));
    assert.equal(r.findings.find((f) => f.id === "repeat-click").severity, "medium");
    assert.equal(analyze({ files: [a, b] }, { repeatClickMin: 3 }).tables.repeatClickers.length, 0);
    assert.ok(!/shame|worst|offender/i.test(JSON.stringify(r.findings)), "no shaming language");
  });
  test("repeat credential submitters are high severity", () => {
    const a = P("a.csv", genericCsv("A", "2026-01-10", [{ email: "s@test.darknode.ai", c: true, s: true }]));
    const b = P("b.csv", genericCsv("B", "2026-02-10", [{ email: "s@test.darknode.ai", c: true, s: true }]));
    const r = analyze({ files: [a, b] });
    assert.ok(ids(r).includes("repeat-submit"));
    assert.ok(!ids(r).includes("repeat-click"));
    assert.equal(r.findings[0].severity, "high");
    assert.equal(r.findings.find((f) => f.id === "repeat-submit").assets[0].type, "IDENTITY");
    assert.ok(ids(r).includes("submissions"));
  });
  test("history accumulates across imports via mergeHistory", () => {
    const a = P("a.csv", genericCsv("A", "2026-01-10", [{ email: "h@test.darknode.ai", c: true }]));
    const first = analyze({ files: [a] });
    assert.equal(first.tables.repeatClickers.length, 0);
    const hist = mergeHistory([], first.tables.personCampaigns);
    assert.equal(hist.length, 1); assert.equal(hist[0].clicks, 1);
    assert.ok(!("subject" in hist[0].campaigns[0]) && !("body" in hist[0].campaigns[0]));
    const b = P("b.csv", genericCsv("B", "2026-03-10", [{ email: "h@test.darknode.ai", c: true }]));
    const second = analyze({ files: [b], history: hist });
    assert.equal(second.tables.repeatClickers[0].campaignsClicked, 2);
    assert.equal(second.tables.repeatClickers[0].fromHistory, 1);
    const again = analyze({ files: [a], history: hist });
    assert.equal(again.tables.repeatClickers.length, 0, "the same campaign re-imported is not counted twice");
  });
  test("register round-trip with Map storage and a fake graph", () => {
    const m = new Map();
    const storage = { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
    const E = {}; let n = 0;
    const graph = {
      create: (type, name, data, o) => { const e = { id: "g" + (++n), type, name, data, severity: o.severity, source: o.source }; E[e.id] = e; return e; },
      update: (id, u) => Object.assign(E[id], u), remove: (id) => delete E[id], list: (type) => Object.values(E).filter((e) => e.type === type), get: (id) => E[id] || null,
    };
    const reg = openRegister(TOOL_ID, "IDENTITY", { schema: REGISTER_SCHEMA, storage, graph, now: () => "2026-10-01T00:00:00.000Z" });
    const recs = mergeHistory([], [{ email: "h@test.darknode.ai", campaign: "A", date: "2026-01-10", clicked: true }, { email: "h@test.darknode.ai", campaign: "B", date: "2026-02-10", clicked: true, submitted: true }]);
    for (const r of recs) reg.upsert(r);
    const saved = reg.get("h@test.darknode.ai");
    assert.equal(E[saved.graphId].type, "IDENTITY");
    assert.equal(E[saved.graphId].name, "h@test.darknode.ai");
    assert.equal(E[saved.graphId].severity, "medium");
    assert.equal(E[saved.graphId].data._full.campaigns.length, 2);
    const merged = mergeHistory(reg.list(), [{ email: "H@test.darknode.ai", campaign: "C", date: "2026-03-10", clicked: true, submitted: true }]);
    reg.upsert(merged[0]);
    assert.equal(reg.get("h@test.darknode.ai").submissions, 2);
    assert.equal(E[saved.graphId].severity, "high");
    assert.ok(reg.remove("h@test.darknode.ai"));
    assert.equal(Object.keys(E).length, 0);
  });
  test("high-risk roles: flag gives confirmed, title keyword gives likely; negative stays silent", () => {
    const fin = [{ email: "f@test.darknode.ai", dept: "Finance" }];
    const r1 = analyze({ files: [P("a.csv", genericCsv("A", "2026-01-10", [{ email: "f@test.darknode.ai", c: true, s: true }])), P("hr.csv", rosterCsv(fin, { finance: true }))] });
    const f1 = r1.findings.find((f) => f.id === "highrisk-submit");
    assert.equal(f1.severity, "high"); assert.equal(f1.confidence, "confirmed");
    const r2 = analyze({ files: [P("a.csv", genericCsv("A", "2026-01-10", [{ email: "f@test.darknode.ai", c: true }])), P("hr.csv", rosterCsv(fin, { title: "Payroll Specialist" }))] });
    assert.equal(r2.findings.find((f) => f.id === "highrisk-click").confidence, "likely");
    const r3 = analyze({ files: [P("a.csv", genericCsv("A", "2026-01-10", [{ email: "f@test.darknode.ai", c: true }])), P("hr.csv", rosterCsv(fin, { title: "Analyst" }))] });
    assert.ok(!ids(r3).some((x) => x.startsWith("highrisk")));
    const r4 = analyze({ files: [P("a.csv", genericCsv("A", "2026-01-10", [{ email: "f@test.darknode.ai", c: true }])), P("hr.csv", rosterCsv(fin, { title: "Accounts Payable" }))] }, { highRiskKeywords: "" });
    assert.ok(!ids(r4).some((x) => x.startsWith("highrisk")), "editable keyword list");
  });
  test("overdue training fires past due and stays silent when completed or not yet due", () => {
    const lms = P("lms.csv", LMS_CSV);
    const r = analyze({ files: [lms] }, { now: "2026-03-01T00:00:00Z" });
    const f = r.findings.find((x) => x.id === "overdue");
    assert.equal(f.evidenceCount, 1); assert.equal(f.evidence[0].email, "ava.ash@test.darknode.ai"); assert.equal(f.evidence[0].daysOverdue, 28);
    assert.ok(!ids(analyze({ files: [lms] }, { now: "2026-01-31T00:00:00Z" })).includes("overdue"));
  });
  test("remedial training window: missing, satisfied, and still pending", () => {
    const res = P("a.csv", genericCsv("A", "2026-01-10", [{ email: "a@test.darknode.ai", c: true }, { email: "b@test.darknode.ai", c: true }]));
    const lms = P("lms.csv", "user,course,assigned,due,completed\nb@test.darknode.ai,Remedial links,2026-01-15,2026-01-30,2026-01-20\na@test.darknode.ai,Annual,2025-12-01,2025-12-31,2025-12-10\n");
    const r = analyze({ files: [res, lms] }, { now: "2026-03-01T00:00:00Z", remedialDays: 30 });
    const f = r.findings.find((x) => x.id === "remedial");
    assert.deepEqual(f.evidence.map((e) => e.email), ["a@test.darknode.ai"]);
    const pend = analyze({ files: [res, lms] }, { now: "2026-01-20T00:00:00Z", remedialDays: 30 });
    assert.ok(!ids(pend).includes("remedial")); assert.equal(pend.tables.remedialPending, 2);
    const kw = analyze({ files: [res, lms] }, { now: "2026-03-01T00:00:00Z", remedialDays: 30, remedialCourse: "nothing-matches" });
    assert.equal(kw.findings.find((x) => x.id === "remedial").evidenceCount, 2);
  });
  test("trend flags need the sample size and a real difference", () => {
    const mk = (name, date, n, clicks) => P(name + ".csv", genericCsv(name, date, Array.from({ length: n }, (_, i) => ({ email: "t" + i + "@test.darknode.ai", c: i < clicks, r: i >= n - 5 }))));
    const worse = analyze({ files: [mk("A", "2026-01-10", 100, 10), mk("B", "2026-06-10", 100, 30)] });
    assert.ok(ids(worse).includes("trend-worse")); assert.equal(worse.tables.trend.flags[0].direction, "worsening");
    const better = analyze({ files: [mk("A", "2026-01-10", 100, 30), mk("B", "2026-06-10", 100, 10)] });
    assert.ok(ids(better).includes("trend-better"));
    const flat = analyze({ files: [mk("A", "2026-01-10", 100, 20), mk("B", "2026-06-10", 100, 22)] });
    assert.ok(!ids(flat).some((x) => x.startsWith("trend")));
    const small = analyze({ files: [mk("A", "2026-01-10", 100, 10), mk("B", "2026-06-10", 100, 30)] }, { minTrendSample: 101 });
    assert.ok(small.skipped.some((s) => s.check === "trend"));
  });
  test("baseline and report target are optional and user-entered", () => {
    const f = P("a.csv", genericCsv("A", "2026-01-10", [{ email: "a@test.darknode.ai", c: true }, { email: "b@test.darknode.ai", r: true }]));
    const none = analyze({ files: [f] });
    assert.ok(!ids(none).includes("baseline") && !ids(none).includes("report-target"));
    const r = analyze({ files: [f] }, { baselineClickRate: 20, reportTargetRate: 60 });
    assert.ok(/above the baseline/.test(r.findings.find((x) => x.id === "baseline").title));
    assert.ok(ids(r).includes("report-target"));
    assert.ok(!ids(analyze({ files: [f] }, { reportTargetRate: 50 })).includes("report-target"), "edge: equal to target is not flagged");
  });
  test("every finding cites controls and keeps evidence capped with the full count", () => {
    const list = Array.from({ length: 70 }, (_, i) => ({ email: "z" + i + "@test.darknode.ai", c: true }));
    const r = analyze({ files: [P("a.csv", genericCsv("A", "2026-01-10", list)), P("b.csv", genericCsv("B", "2026-02-10", list))] });
    const f = r.findings.find((x) => x.id === "repeat-click");
    assert.equal(f.evidence.length, 50); assert.equal(f.evidenceCount, 70);
    for (const x of r.findings) { assert.ok(x.controls.length >= 1); assert.ok(["confirmed", "likely", "review"].includes(x.confidence)); }
  });
});

group("awareness: exports, determinism, example", () => {
  const ex = exampleParsed();
  const r = analyze({ files: ex.parsed.files }, { now: ex.now });
  test("analyze is deterministic (byte-identical JSON)", () => {
    assert.equal(JSON.stringify(analyze({ files: ex.parsed.files }, { now: ex.now })), JSON.stringify(r));
  });
  test("findingsToCsv header row", () => {
    assert.equal(findingsToCsv(r.findings).split("\n")[0], '"severity","confidence","category","title","description","recommendation","controls","evidenceCount"');
  });
  test("follow-up, department scorecard and remedial CSVs", () => {
    const rep = repeatClickersCsv(r).trim().split("\n");
    assert.equal(rep.length, r.tables.repeatClickers.length + 1);
    assert.ok(rep[1].includes("needs follow-up training"));
    const dept = departmentScorecardCsv(r);
    assert.ok(/"Legal",.*suppressed/.test(dept));
    const rem = remedialAssignmentsCsv(r, "Spot the Lure 101").trim().split("\n");
    assert.equal(rem[0], '"email","course","reason"');
    assert.ok(rem.slice(1).every((l) => l.includes("Spot the Lure 101")));
  });
  test("summary text includes rates with denominators and the sensitivity note", () => {
    const s = summaryText(r);
    assert.ok(/Click rate: \d+(\.\d)?% \(\d+\/\d+\)/.test(s));
    assert.ok(/not to discipline/.test(s));
  });
  test("example is synthetic, uses test.darknode.ai and has 60 people", () => {
    const e = exampleDataset();
    assert.ok(/synthetic/.test(e.label));
    assert.equal(r.summary.people, 60);
    assert.ok(e.files.every((f) => !/example\.com|contoso/i.test(f.text)));
    assert.equal(e.files.length, 8);
  });
  test("progress is reported and optional", () => {
    const calls = [];
    analyze({ files: ex.parsed.files }, { now: ex.now }, { progress: (i, n) => calls.push([i, n]) });
    assert.ok(calls.length >= 2); assert.equal(calls[calls.length - 1][0], calls[calls.length - 1][1]);
  });
  test("defaults are exposed and empty input is safe", () => {
    assert.equal(DEFAULTS.minGroupSize, 5); assert.equal(DEFAULTS.repeatClickMin, 2);
    const e = analyze(parseInput("").rows);
    assert.equal(e.findings.length, 0); assert.equal(e.meta.rows, 0);
    assert.equal(detect([]).kind, "unknown");
  });
  test("in-engine self-test passes", () => {
    const s = selfTest();
    assert.ok(s.pass, "failed: " + s.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
});
