// Card Audit engine tests (public/js/finsec/cardaudit-engine.js). One fixture per export
// layout with the vendor headers verbatim, money / date / masking helpers, every detection
// on a crafted positive and a negative, split-window edges, MCC list parsing, skipped-check
// reporting, determinism, exports and the in-engine self-test.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, DEFAULTS, FORMATS, BUILTIN_MCC, parseInput, analyze, detectFile, classifyHeaders, parseCents, fmtCents, parseWhen,
  maskCard, maskPans, merchantKey, nameKey, parseMccList, findingsToCsv, followupToCsv, recoveryToCsv, summaryText, exampleDataset, selfTest,
} from "../../public/js/finsec/cardaudit-engine.js";

// ---- fixtures (headers exactly as the vendors export them) ----
const AMEX = [
  "Date,Description,Card Member,Account #,Amount,Extended Details,Appears On Your Statement As,Address,City/State,Zip Code,Country,Reference,Category",
  '08/03/2026,DELTA AIR LINES ATLANTA,AVERY LIN,-71006,612.40,"Airline ticket 0062345678901",DELTA AIR LINES,1030 DELTA BLVD,"ATLANTA\nGA",30354,UNITED STATES,\'320262150123456789\',Travel-Airline',
  "08/04/2026,BLUE BOTTLE COFFEE,AVERY LIN,-71006,18.25,,BLUE BOTTLE COFFEE,1 FERRY BLDG,SAN FRANCISCO CA,94111,UNITED STATES,'320262160123456790',Restaurant-Restaurant",
  "08/05/2026,AUTOPAY PAYMENT - THANK YOU,AVERY LIN,-71006,-630.65,,,,,,,'320262170123456791',",
].join("\n");
const BREX_H = "Transaction Date,Posted Date,Description,Amount,Currency,Card Holder,Card Last Four,Merchant Category,MCC,Receipt Status,Memo,Category,Department";
const BREX = [BREX_H,
  "2026-08-10,2026-08-11,SQ *BLUE BOTTLE #102,24.10,USD,Avery Lin,4417,Eating Places and Restaurants,5812,Submitted,,Meals,Finance",
  "2026-08-11,2026-08-12,AWS,310.00,USD,Avery Lin,4417,Computer Software Stores,5734,Missing,,Software,Finance",
].join("\n");
const RAMP = [
  "Transaction Time,User,Card,Merchant,Merchant Category Code,Amount,Currency,Receipt,Memo,Accounting Category,Department,Location,Reviewer,Review Status",
  "2026-08-12 14:22:05,Avery Lin,Avery Lin Physical Card 4417,Notion Labs,5734,96.00,USD,Yes,Team plan,Software,Finance,HQ,Riley Chen,Approved",
  "2026-08-13T09:05:00Z,Avery Lin,Avery Lin Physical Card 4417,Lyft,4121,23.80,USD,No,Airport,Travel,Finance,HQ,Riley Chen,Approved",
].join("\n");
const EXPENSIFY = [
  "Timestamp,Merchant,Amount,MCC,Category,Tag,Comment,Reimbursable,Original Currency,Original Amount,Receipt,Report ID,Report Name,Submitter,Approver",
  "2026-08-14 12:00:00,Joe's Diner,42.50,5812,Meals,Sales,Lunch with client,Yes,USD,42.50,https://www.expensify.com/receipts/w_1.jpg,R0001,August,avery.lin@test.darknode.ai,riley.chen@test.darknode.ai",
  "2026-08-15 08:30:00,Shell,61.00,5541,Fuel,Sales,,No,USD,61.00,,R0001,August,avery.lin@test.darknode.ai,riley.chen@test.darknode.ai",
].join("\n");
const CONCUR_H = "Report ID,Report Name,Employee,Employee ID,Expense Type,Transaction Date,Vendor,City,Country,Payment Type,Amount,Currency,Approved Amount,Receipt Received,Approver,Approval Status,Submit Date,Policy";
const CONCUR = [CONCUR_H,
  "R-100,August travel,\"Lin, Avery\",E1,Hotel,08/18/2026,Hilton Chicago,Chicago,US,Personal Card,289.10,USD,289.10,Y,\"Chen, Riley\",Approved,08/22/2026,US Employee Policy",
  "R-100,August travel,\"Lin, Avery\",E1,Meals,08/19/2026,Portillo's,Chicago,US,Corporate Card,31.75,USD,31.75,N,\"Chen, Riley\",Approved,08/22/2026,US Employee Policy",
].join("\n");
const ROSTER_H = "employee_id,name,email,department,title,manager_id,hire_date,termination_date,status";
const ROSTER = [ROSTER_H,
  "E1,Avery Lin,avery.lin@test.darknode.ai,Finance,Analyst,E2,2022-01-10,,Active",
  "E2,Riley Chen,riley.chen@test.darknode.ai,Finance,Controller,E3,2020-05-04,,Active",
  "E3,Dana Wright,dana.wright@test.darknode.ai,Finance,CFO,,2018-02-01,,Active",
  "E4,Morgan Hale,morgan.hale@test.darknode.ai,Sales,AE,E3,2026-03-01,2026-08-31,Terminated",
].join("\n");
const POLICY = "category,limit_per_txn,limit_per_day,currency\nMeals,75.00,120.00,USD\n";

const GEN_H = ["date", "employee", "employee_id", "card_last4", "merchant", "mcc", "amount", "currency", "receipt", "approver", "report_id", "category", "memo", "city", "country", "reimbursable"];
const q = (v) => (/[",\n]/.test(String(v)) ? '"' + String(v).replace(/"/g, '""') + '"' : String(v));
/** Generic CSV from row objects (only the columns given in `cols`). */
function gen(rows, cols = ["date", "employee", "merchant", "mcc", "amount", "currency"]) {
  return [cols.join(","), ...rows.map((r) => cols.map((c) => q(r[c] == null ? "" : r[c])).join(","))].join("\n");
}
const file = (name, text, role) => ({ name, text, ...(role ? { role } : {}) });
const run = (files, opts) => analyze(files, opts || {});
const of = (r, check) => r.findings.filter((f) => f.check === check);
const skippedHas = (r, check) => r.skipped.some((s) => s.check === check);

group("cardaudit: parsers", () => {
  test("American Express activity CSV: exact headers, masked account, credit set aside", () => {
    const p = parseInput([file("activity.csv", AMEX)]);
    assert.equal(p.files[0].format, "amex");
    assert.equal(p.files[0].confidence, 1);
    assert.equal(p.rows.length, 2);
    assert.equal(p.rows[0].card, "****1006");
    assert.equal(p.rows[0].cents, 61240);
    assert.equal(p.rows[0].currency, "");
    assert.equal(p.rows[0].date, "2026-08-03");
    assert.ok(!JSON.stringify(p).includes("0062345678901"), "long number in memo masked");
  });
  test("Brex transactions CSV", () => {
    const p = parseInput([file("brex.csv", BREX)]);
    assert.equal(p.files[0].format, "brex");
    assert.equal(p.rows.length, 2);
    assert.equal(p.rows[1].mcc, "5734");
    assert.equal(p.rows[0].card, "****4417");
    assert.equal(p.rows[0].kind, "card");
  });
  test("Ramp transactions CSV with timestamps and reviewer", () => {
    const p = parseInput([file("ramp.csv", RAMP)]);
    assert.equal(p.files[0].format, "ramp");
    assert.equal(p.rows[0].approver, "Riley Chen");
    assert.equal(p.rows[0].card, "****4417");
    assert.equal(p.rows[1].date, "2026-08-13");
  });
  test("Expensify export: Reimbursable decides out-of-pocket vs card", () => {
    const p = parseInput([file("expensify.csv", EXPENSIFY)]);
    assert.equal(p.files[0].format, "expensify");
    assert.equal(p.rows[0].kind, "reimb");
    assert.equal(p.rows[1].kind, "card");
    assert.equal(p.rows[0].report, "R0001");
    assert.equal(p.rows[0].cents, 4250);
  });
  test("SAP Concur report export: US dates, payment type, Last, First names", () => {
    const p = parseInput([file("concur.csv", CONCUR), file("roster.csv", ROSTER)]);
    const c = p.files.find((f) => f.name === "concur.csv");
    assert.equal(c.format, "concur");
    assert.equal(p.rows[0].date, "2026-08-18");
    assert.equal(p.rows[0].kind, "reimb");
    assert.equal(p.rows[1].kind, "card");
    assert.equal(p.rows[0].employee, "Avery Lin", "resolved through the roster");
  });
  test("HR roster and policy CSVs are recognised with high confidence", () => {
    assert.deepEqual(classifyHeaders(ROSTER_H.split(",")), { format: "roster", confidence: 1 });
    assert.deepEqual(classifyHeaders(POLICY.split("\n")[0].split(",")), { format: "policy", confidence: 1 });
  });
  test("generic CSV maps by alias with medium confidence; overrides apply", () => {
    const text = "Txn Date,Spender,Payee,Total\n2026-08-03,Avery Lin,Acme,10.00\n";
    const d = detectFile({ name: "g.csv", text });
    assert.equal(d.format, "generic");
    assert.equal(d.confidenceLabel, "medium");
    const text2 = "When,Who,Shop,Money\n2026-08-03,Avery Lin,Acme,10.00\n";
    assert.equal(parseInput([{ name: "x.csv", text: text2 }]).rows.length, 0);
    const p = parseInput([{ name: "x.csv", text: text2, role: "transactions", columns: { date: "When", employee: "Who", merchant: "Shop", amount: "Money" } }]);
    assert.equal(p.rows.length, 1);
    assert.equal(p.rows[0].cents, 1000);
  });
  test("vendor layout with a missing column drops to medium confidence", () => {
    const h = BREX_H.split(",").filter((x) => x !== "Memo");
    assert.deepEqual(classifyHeaders(h), { format: "brex", confidence: 0.75 });
  });
  test("header row after a preamble is found", () => {
    const p = parseInput([file("amex.csv", "Transaction Details\nPrepared for AVERY LIN\n" + AMEX)]);
    assert.equal(p.files[0].format, "amex");
    assert.equal(p.rows.length, 2);
  });
  test("JSON array input is read through the generic mapping", () => {
    const p = parseInput([file("t.json", JSON.stringify([{ date: "2026-08-03", employee: "Avery Lin", merchant: "Acme", amount: "12.5" }]))]);
    assert.equal(p.rows.length, 1);
    assert.equal(p.rows[0].cents, 1250);
  });
  test("unrecognised file is reported, not guessed", () => {
    const p = parseInput([file("notes.txt", "hello\nworld\n")]);
    assert.equal(p.files[0].format, "unknown");
    assert.equal(p.rows.length, 0);
  });
});

group("cardaudit: helpers", () => {
  test("parseCents handles symbols, separators, parentheses and signs", () => {
    assert.equal(parseCents("$1,234.56"), 123456);
    assert.equal(parseCents("(12.30)"), -1230);
    assert.equal(parseCents("USD -7.5"), -750);
    assert.equal(parseCents("1.234,56"), 123456);
    assert.equal(parseCents("12,5"), 1250);
    assert.equal(parseCents("0.105"), 11);
    assert.equal(parseCents("12.00-"), -1200);
    assert.equal(parseCents("abc"), null);
    assert.equal(parseCents(""), null);
    assert.equal(fmtCents(123456789), "1,234,567.89");
    assert.equal(fmtCents(-5), "-0.05");
  });
  test("parseWhen reads ISO, US, month-name dates and rejects impossible dates", () => {
    assert.equal(parseWhen("2026-08-13T09:05:00Z").min, 545);
    assert.equal(parseWhen("08/13/2026 2:30 PM").min, 870);
    assert.equal(parseWhen("13 Aug 2026").day, parseWhen("2026-08-13").day);
    assert.equal(parseWhen("Aug 13, 2026").day, parseWhen("2026-08-13").day);
    assert.equal(parseWhen("2026-02-30"), null);
    assert.equal(parseWhen("soon"), null);
  });
  test("card masking keeps the last four only", () => {
    assert.equal(maskCard("4111 1111 1111 1111"), "****1111");
    assert.equal(maskCard("-71006"), "****1006");
    assert.equal(maskCard("4417"), "****4417");
    assert.equal(maskCard(""), "");
    assert.equal(maskPans("refund to 4111-1111-1111-1111 ok"), "refund to ****1111 ok");
    assert.equal(maskPans("order 12345"), "order 12345");
  });
  test("merchant and name keys normalise vendor noise", () => {
    assert.equal(merchantKey("SQ *BLUE BOTTLE #102"), "blue bottle");
    assert.equal(merchantKey("Blue Bottle"), "blue bottle");
    assert.equal(merchantKey("BEST BUY 00123"), "best buy");
    assert.equal(nameKey("Lin, Avery"), nameKey("AVERY J LIN"));
  });
  test("MCC list parsing: codes, ranges, labels, comments and errors", () => {
    const r = parseMccList("7995 Gambling\n# comment\n6010-6011, cash\n\n5813\n12345\n6011-6010");
    assert.equal(r.entries.length, 3);
    assert.deepEqual(r.entries[0], { lo: "5813", hi: "5813", label: "" });
    assert.deepEqual(r.entries[1], { lo: "6010", hi: "6011", label: "cash" });
    assert.equal(r.entries[2].label, "Gambling");
    assert.equal(r.errors.length, 2);
    assert.equal(r.errors[0].line, 6);
  });
  test("built-in review list holds 4-digit codes with labels and severities", () => {
    assert.ok(BUILTIN_MCC.every((b) => /^\d{4}$/.test(b.mcc) && b.label && ["medium", "low", "info"].includes(b.severity)));
    assert.ok(BUILTIN_MCC.some((b) => b.mcc === "7995"));
    assert.equal(DEFAULTS.cardTxnLimit, null);
    assert.equal(DEFAULTS.mccList, "");
  });
});

group("cardaudit: split transactions", () => {
  const rows = (amts, dates) => amts.map((a, i) => ({ date: dates[i], employee: "Avery Lin", merchant: "Dell", mcc: "5045", amount: a, currency: "USD" }));
  test("charges each under the limit that together exceed it are flagged high/likely", () => {
    const r = run([file("g.csv", gen(rows(["2400.00", "2300.00"], ["2026-08-12", "2026-08-12"])))], { cardTxnLimit: 2500 });
    const f = of(r, "split");
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, "high");
    assert.equal(f[0].confidence, "likely");
    assert.equal(f[0].evidenceCount, 2);
  });
  test("group that stays under the limit is silent", () => {
    const r = run([file("g.csv", gen(rows(["1000.00", "1400.00"], ["2026-08-12", "2026-08-12"])))], { cardTxnLimit: 2500 });
    assert.equal(of(r, "split").length, 0);
  });
  test("a charge at the limit is not part of a split group", () => {
    const r = run([file("g.csv", gen(rows(["2500.00", "100.00"], ["2026-08-12", "2026-08-12"])))], { cardTxnLimit: 2500 });
    assert.equal(of(r, "split").length, 0);
  });
  test("window edge: exactly 24 hours apart is inside", () => {
    const r = run([file("g.csv", gen(rows(["2000.00", "2000.00"], ["2026-08-12 09:00", "2026-08-13 09:00"])))], { cardTxnLimit: 2500, splitHours: 24 });
    assert.equal(of(r, "split").length, 1);
  });
  test("window edge: one minute past 24 hours is outside", () => {
    const r = run([file("g.csv", gen(rows(["2000.00", "2000.00"], ["2026-08-12 09:00", "2026-08-13 09:01"])))], { cardTxnLimit: 2500, splitHours: 24 });
    assert.equal(of(r, "split").length, 0);
  });
  test("blank card limit skips the check with a reason", () => {
    const r = run([file("g.csv", gen(rows(["2400.00", "2300.00"], ["2026-08-12", "2026-08-12"])))], {});
    assert.equal(of(r, "split").length, 0);
    assert.ok(skippedHas(r, "split"));
  });
});

group("cardaudit: duplicates", () => {
  test("same merchant, date and amount claimed by a second employee out of pocket", () => {
    const card = gen([{ date: "2026-07-21", employee: "Priya Shah", merchant: "BLUE BOTTLE CATERING", mcc: "5811", amount: "486.20", currency: "USD" }]);
    const claim = gen([{ date: "2026-07-21", employee: "Sam Okafor", merchant: "Blue Bottle Catering", amount: "486.20", currency: "USD", reimbursable: "Yes", report_id: "R-9" }], ["date", "employee", "merchant", "amount", "currency", "reimbursable", "report_id"]);
    const r = run([file("card.csv", card), file("claims.csv", claim)]);
    const f = of(r, "dup_cross");
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, "high");
    assert.deepEqual(f[0].employees, ["Priya Shah", "Sam Okafor"]);
    assert.equal(r.tables.recovery[0].recoverable, "486.20");
    assert.equal(r.summary.duplicateAmount.USD, 48620);
  });
  test("two card charges by two employees with no claim are not duplicates", () => {
    const r = run([file("card.csv", gen([
      { date: "2026-07-21", employee: "Priya Shah", merchant: "Sweetgreen", amount: "15.40", currency: "USD" },
      { date: "2026-07-21", employee: "Sam Okafor", merchant: "Sweetgreen", amount: "15.40", currency: "USD" }]))]);
    assert.equal(of(r, "dup_cross").length + of(r, "dup_self").length, 0);
  });
  test("card charge also claimed out of pocket by the same employee", () => {
    const card = gen([{ date: "2026-08-02", employee: "Avery Lin", merchant: "Hilton", amount: "289.10", currency: "USD" }]);
    const claim = gen([{ date: "2026-08-02", employee: "Avery Lin", merchant: "HILTON", amount: "289.10", currency: "USD", reimbursable: "yes", report_id: "R-1" }], ["date", "employee", "merchant", "amount", "currency", "reimbursable", "report_id"]);
    const f = of(run([file("a.csv", card), file("b.csv", claim)]), "dup_self");
    assert.equal(f.length, 1);
    assert.ok(f[0].description.includes("card charge also claimed out of pocket"));
  });
  test("same line submitted in two reports", () => {
    const claim = gen([
      { date: "2026-08-05", employee: "Alex Kim", merchant: "Lyft", amount: "38.40", currency: "USD", reimbursable: "Yes", report_id: "R-1" },
      { date: "2026-08-05", employee: "Alex Kim", merchant: "Lyft", amount: "38.40", currency: "USD", reimbursable: "Yes", report_id: "R-2" }], ["date", "employee", "merchant", "amount", "currency", "reimbursable", "report_id"]);
    const r = run([file("b.csv", claim)]);
    assert.equal(of(r, "dup_self").length, 1);
    assert.equal(r.tables.recovery[0].type, "same expense in two reports");
  });
  test("company-card report line is matched to the card feed and counted once", () => {
    const r = run([file("brex.csv", BREX_H + "\n2026-08-19,2026-08-20,PORTILLOS,31.75,USD,Avery Lin,4417,Eating Places and Restaurants,5812,Submitted,,Meals,Finance\n"), file("concur.csv", CONCUR)]);
    assert.equal(r.summary.linkedReportLines, 1);
    assert.equal(r.summary.transactions, 2);
    assert.equal(of(r, "dup_self").length, 0);
  });
});

group("cardaudit: merchant category codes", () => {
  const casino = gen([{ date: "2026-08-03", employee: "Chris Doyle", merchant: "BELLAGIO", mcc: "7995", amount: "1200.00", currency: "USD" },
    { date: "2026-08-04", employee: "Chris Doyle", merchant: "Office Depot", mcc: "5943", amount: "20.00", currency: "USD" }]);
  test("built-in review list flags 7995 as review", () => {
    const f = of(run([file("g.csv", casino)]), "mcc_review");
    assert.equal(f.length, 1);
    assert.equal(f[0].confidence, "review");
    assert.equal(f[0].evidenceCount, 1);
  });
  test("user list makes it high and takes precedence; built-in toggle off is silent", () => {
    const r = run([file("g.csv", casino)], { mccList: "7995 Gambling" });
    assert.equal(of(r, "mcc_user")[0].severity, "high");
    assert.equal(of(r, "mcc_review").length, 0);
    assert.equal(run([file("g.csv", casino)], { useBuiltinMcc: false }).findings.filter((f) => f.check.startsWith("mcc")).length, 0);
  });
  test("files without an MCC column skip the MCC checks", () => {
    const r = run([file("amex.csv", AMEX)]);
    assert.ok(skippedHas(r, "mcc"));
  });
});

group("cardaudit: calendar and people checks", () => {
  test("weekend and federal holiday spend outside travel", () => {
    const r = run([file("g.csv", gen([
      { date: "2026-08-22", employee: "Avery Lin", merchant: "Target", amount: "40.12", currency: "USD" },
      { date: "2026-09-07", employee: "Avery Lin", merchant: "Target", amount: "33.10", currency: "USD" },
      { date: "2026-08-24", employee: "Avery Lin", merchant: "Target", amount: "12.10", currency: "USD" }]))], { holidays: { version: "t", data: [{ date: "2026-09-07", name: "Labor Day" }] } });
    const f = of(r, "weekend_holiday");
    assert.equal(f.length, 1);
    assert.equal(f[0].evidenceCount, 2);
    assert.ok(f[0].evidence.some((e) => e.day === "Labor Day"));
  });
  test("weekend travel is excluded and missing holiday data is reported", () => {
    const r = run([file("g.csv", gen([
      { date: "2026-08-22", employee: "Avery Lin", merchant: "United", mcc: "3000", amount: "400.12", currency: "USD" },
      { date: "2026-08-23", employee: "Avery Lin", merchant: "Marriott", mcc: "3509", amount: "200.12", currency: "USD" }]))]);
    assert.equal(of(r, "weekend_holiday").length, 0);
    assert.ok(skippedHas(r, "weekend_holiday (holidays)"));
  });
  test("spend after termination is critical; grace days respected", () => {
    const tx = gen([{ date: "2026-09-04", employee: "Morgan Hale", merchant: "Best Buy", amount: "899.99", currency: "USD" },
      { date: "2026-08-20", employee: "Morgan Hale", merchant: "Best Buy", amount: "99.99", currency: "USD" }]);
    const r = run([file("t.csv", tx), file("roster.csv", ROSTER)]);
    const f = of(r, "post_termination");
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, "critical");
    assert.equal(f[0].evidenceCount, 1);
    assert.equal(r.summary.postTerminationSpend.USD, 89999);
    assert.equal(of(run([file("t.csv", tx), file("roster.csv", ROSTER)], { terminationGraceDays: 5 }), "post_termination").length, 0);
  });
  test("spend before hire date is medium review", () => {
    const r = run([file("t.csv", gen([{ date: "2026-02-10", employee: "Morgan Hale", merchant: "Delta", amount: "300.12", currency: "USD" }])), file("roster.csv", ROSTER)]);
    assert.equal(of(r, "pre_hire")[0].severity, "medium");
  });
  test("roster checks are skipped without a roster", () => {
    const r = run([file("t.csv", gen([{ date: "2026-09-04", employee: "Morgan Hale", merchant: "Best Buy", amount: "899.99", currency: "USD" }]))]);
    assert.ok(skippedHas(r, "post_termination / pre_hire"));
    assert.equal(of(r, "post_termination").length, 0);
  });
  test("self-approval by roster id is confirmed; an independent approver is silent", () => {
    const cols = ["date", "employee", "employee_id", "merchant", "amount", "currency", "approver", "report_id"];
    const r = run([file("t.csv", gen([{ date: "2026-08-03", employee: "Riley Chen", employee_id: "E2", merchant: "Zuni", amount: "56.10", currency: "USD", approver: "Chen, Riley", report_id: "R-5" },
      { date: "2026-08-03", employee: "Avery Lin", employee_id: "E1", merchant: "Zuni", amount: "56.20", currency: "USD", approver: "Riley Chen", report_id: "R-6" }], cols)), file("roster.csv", ROSTER)]);
    const f = of(r, "self_approval");
    assert.equal(f.length, 1);
    assert.equal(f[0].confidence, "confirmed");
    assert.deepEqual(f[0].employees, ["Riley Chen"]);
    assert.equal(of(r, "approver_reports_to_submitter").length, 0);
  });
  test("approver who reports (indirectly) to the submitter is flagged", () => {
    const cols = ["date", "employee", "merchant", "amount", "currency", "approver", "report_id"];
    const r = run([file("t.csv", gen([{ date: "2026-08-03", employee: "Dana Wright", merchant: "Zuni", amount: "356.80", currency: "USD", approver: "Avery Lin", report_id: "R-7" }], cols)), file("roster.csv", ROSTER)]);
    const f = of(r, "approver_reports_to_submitter");
    assert.equal(f.length, 1);
    assert.equal(f[0].evidence[0].levelsBelow, 2);
  });
  test("no approver column skips approval checks", () => {
    assert.ok(skippedHas(run([file("brex.csv", BREX)]), "self_approval"));
  });
});

group("cardaudit: policy, receipts and screens", () => {
  test("per-transaction and per-day policy limits; currency mismatch not compared", () => {
    const cols = ["date", "employee", "merchant", "amount", "currency", "category"];
    const r = run([file("t.csv", gen([
      { date: "2026-08-03", employee: "Avery Lin", merchant: "Nobu", amount: "80.00", currency: "USD", category: "Meals" },
      { date: "2026-08-04", employee: "Avery Lin", merchant: "Cafe", amount: "70.00", currency: "USD", category: "Meals" },
      { date: "2026-08-04", employee: "Avery Lin", merchant: "Bistro", amount: "60.00", currency: "USD", category: "Meals" },
      { date: "2026-08-05", employee: "Avery Lin", merchant: "Pub", amount: "90.00", currency: "EUR", category: "Meals" },
      { date: "2026-08-06", employee: "Avery Lin", merchant: "Deli", amount: "20.00", currency: "USD", category: "Meals" }], cols)), file("policy.csv", POLICY)]);
    const f = of(r, "policy_limit");
    assert.equal(f.length, 1);
    assert.equal(f[0].evidenceCount, 3);
    assert.ok(skippedHas(r, "policy_limit (currency)"));
  });
  test("policy check is skipped without a policy file", () => {
    assert.ok(skippedHas(run([file("brex.csv", BREX)]), "policy_limit"));
  });
  test("missing receipts above the threshold; exactly at the threshold is silent", () => {
    const cols = ["date", "employee", "merchant", "amount", "currency", "receipt"];
    const r = run([file("t.csv", gen([
      { date: "2026-08-03", employee: "Avery Lin", merchant: "A", amount: "75.00", currency: "USD", receipt: "Missing" },
      { date: "2026-08-04", employee: "Avery Lin", merchant: "B", amount: "75.01", currency: "USD", receipt: "" },
      { date: "2026-08-05", employee: "Avery Lin", merchant: "C", amount: "500.00", currency: "USD", receipt: "Attached" },
      { date: "2026-08-06", employee: "Avery Lin", merchant: "D", amount: "500.00", currency: "USD", receipt: "Not required" }], cols))]);
    const f = of(r, "missing_receipt");
    assert.equal(f.length, 1);
    assert.equal(f[0].evidenceCount, 1);
    assert.equal(f[0].severity, "low");
  });
  test("evidence is capped at 50 rows while the full count is kept", () => {
    const rows = []; for (let i = 0; i < 61; i++) rows.push({ date: "2026-08-" + String(1 + (i % 28)).padStart(2, "0"), employee: "Avery Lin", merchant: "M" + i, amount: "100." + String(10 + (i % 80)), currency: "USD", receipt: "no" });
    const f = of(run([file("t.csv", gen(rows, ["date", "employee", "merchant", "amount", "currency", "receipt"]))]), "missing_receipt")[0];
    assert.equal(f.evidence.length, 50);
    assert.equal(f.evidenceCount, 61);
  });
  test("round-number bias against the fleet baseline", () => {
    const rows = [];
    for (let i = 0; i < 60; i++) rows.push({ date: "2026-08-" + String(1 + (i % 28)).padStart(2, "0"), employee: "Other " + (i % 6), merchant: "Shop" + (i % 9), amount: (20 + i) + "." + String(11 + (i % 80)), currency: "USD" });
    for (let i = 0; i < 20; i++) rows.push({ date: "2026-08-" + String(1 + (i % 28)).padStart(2, "0"), employee: "Avery Lin", merchant: "Cash" + (i % 7), amount: (50 + i * 5) + ".00", currency: "USD" });
    const r = run([file("t.csv", gen(rows))]);
    const f = of(r, "round_number");
    assert.equal(f.length, 1);
    assert.deepEqual(f[0].employees, ["Avery Lin"]);
    assert.ok(/z = /.test(f[0].description));
  });
  test("round-number check skips below the minimum sample", () => {
    const r = run([file("t.csv", gen([{ date: "2026-08-03", employee: "Avery Lin", merchant: "A", amount: "10.00", currency: "USD" }]))]);
    assert.ok(skippedHas(r, "round_number"));
  });
  test("monthly spike against own history (robust z)", () => {
    const rows = [];
    const months = ["03", "04", "05", "06", "07"];
    months.forEach((m, j) => { for (let i = 0; i < 4; i++) rows.push({ date: "2026-" + m + "-1" + i, employee: "Avery Lin", merchant: "Shop" + i, amount: (100 + j * 3 + i) + ".25", currency: "USD" }); });
    rows.push({ date: "2026-08-12", employee: "Avery Lin", merchant: "Apple", amount: "2400.10", currency: "USD" });
    const f = of(run([file("t.csv", gen(rows))]), "velocity");
    assert.equal(f.length, 1);
    assert.equal(f[0].evidence[0].month, "2026-08");
  });
  test("velocity needs enough months and says so", () => {
    const r = run([file("t.csv", gen([{ date: "2026-08-03", employee: "Avery Lin", merchant: "A", amount: "10.12", currency: "USD" }, { date: "2026-09-03", employee: "Avery Lin", merchant: "A", amount: "900.12", currency: "USD" }]))]);
    assert.equal(of(r, "velocity").length, 0);
    assert.ok(skippedHas(r, "velocity"));
  });
  test("gift card keywords flag only rows without an MCC", () => {
    const cols = ["date", "employee", "merchant", "amount", "currency", "memo"];
    const r = run([file("t.csv", gen([{ date: "2026-08-03", employee: "Sam Okafor", merchant: "Visa Prepaid Gift Card", amount: "500.00", currency: "USD" },
      { date: "2026-08-03", employee: "Avery Lin", merchant: "CVS", amount: "50.00", currency: "USD", memo: "Western Union transfer" }], cols))]);
    assert.equal(of(r, "gift_card").length, 2);
    const withMcc = run([file("t.csv", gen([{ date: "2026-08-03", employee: "Sam Okafor", merchant: "Amazon gift card", mcc: "5942", amount: "500.00", currency: "USD" }]))]);
    assert.equal(of(withMcc, "gift_card").length, 0);
  });
  test("same merchant on consecutive weekends (review only)", () => {
    const sat = ["2026-08-01", "2026-08-08", "2026-08-16"];
    const r = run([file("t.csv", gen(sat.map((d) => ({ date: d, employee: "Avery Lin", merchant: "Whole Foods", amount: "88.12", currency: "USD" }))))]);
    const f = of(r, "personal_weekends");
    assert.equal(f.length, 1);
    assert.equal(f[0].confidence, "review");
    const gap = run([file("t.csv", gen(["2026-08-01", "2026-08-08", "2026-08-22"].map((d) => ({ date: d, employee: "Avery Lin", merchant: "Whole Foods", amount: "88.12", currency: "USD" }))))]);
    assert.equal(of(gap, "personal_weekends").length, 0);
  });
  test("meals in the home city on non-travel days need a roster city", () => {
    const roster = "employee_id,name,email,department,title,manager_id,hire_date,termination_date,status,city\nE1,Avery Lin,avery.lin@test.darknode.ai,Finance,Analyst,,2022-01-10,,Active,Chicago\n";
    const cols = ["date", "employee", "merchant", "mcc", "amount", "currency", "city"];
    const rows = ["2026-08-03", "2026-08-04", "2026-08-05", "2026-08-06"].map((d) => ({ date: d, employee: "Avery Lin", merchant: "Portillos", mcc: "5812", amount: "31.75", currency: "USD", city: "CHICAGO, IL" }));
    rows.push({ date: "2026-08-06", employee: "Avery Lin", merchant: "United", mcc: "3000", amount: "300.12", currency: "USD", city: "CHICAGO" });
    const r = run([file("t.csv", gen(rows, cols)), file("roster.csv", roster, "roster")]);
    const f = of(r, "home_city_meals");
    assert.equal(f.length, 1);
    assert.equal(f[0].evidenceCount, 3);
    assert.ok(skippedHas(run([file("t.csv", gen(rows, cols)), file("roster.csv", ROSTER)]), "home_city_meals"));
  });
});

group("cardaudit: contract", () => {
  const ex = exampleDataset();
  const opts = { ...ex.suggestedOpts, holidays: [{ date: "2026-09-07", name: "Labor Day" }] };
  test("analyze is deterministic (byte-identical JSON)", () => {
    assert.equal(JSON.stringify(analyze(ex, opts)), JSON.stringify(analyze(exampleDataset(), opts)));
  });
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
  test("example uses exact vendor headers and test.darknode.ai people", () => {
    assert.equal(ex.files[0].text.split("\n")[0], FORMATS.brex.headers.join(","));
    assert.equal(ex.files[1].text.split("\n")[0], FORMATS.concur.headers.join(","));
    assert.equal(ex.files[2].text.split("\n")[0], FORMATS.roster.headers.join(","));
    assert.ok(ex.files[2].text.includes("@test.darknode.ai"));
    assert.ok(!/example\.com|contoso/i.test(JSON.stringify(ex)));
  });
  test("example seeds each scheme the brief requires", () => {
    const r = analyze(ex, opts);
    for (const c of ["split", "dup_cross", "mcc_review", "post_termination", "self_approval"]) assert.ok(of(r, c).length >= 1, c);
  });
  test("every finding carries controls, a valid confidence and capped evidence", () => {
    const r = analyze(ex, opts);
    for (const f of r.findings) {
      assert.ok(f.controls.length >= 1 && f.controls.every((c) => c.framework && c.id), f.title);
      assert.ok(["confirmed", "likely", "review"].includes(f.confidence));
      assert.ok(["critical", "high", "medium", "low", "info"].includes(f.severity));
      assert.ok(f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length);
      assert.ok(f.recommendation && f.description);
      assert.ok(!/\bfraud\b(?! tree)/i.test(f.title + " " + f.description.replace(/ACFE/g, "")), "no fraud verdicts: " + f.title);
    }
  });
  test("identity assets carry department, total and flag count", () => {
    const f = of(analyze(ex, opts), "post_termination")[0];
    assert.equal(f.assets[0].type, "IDENTITY");
    assert.equal(f.assets[0].name, "User 08");
    assert.equal(f.assets[0].data.department, "Sales");
    assert.ok(f.assets[0].data.flags >= 1 && /USD/.test(f.assets[0].data.total));
  });
  test("no full card or account number survives into the results", () => {
    const amex = AMEX.replace("-71006", "378282246310005").replace("0062345678901", "4111111111111111");
    const s = JSON.stringify(analyze([file("a.csv", amex)], { useBuiltinMcc: true, receiptRequiredOver: 0 }));
    assert.ok(!s.includes("378282246310005") && !s.includes("4111111111111111"));
    const p = parseInput([file("a.csv", amex)]);
    assert.ok(!JSON.stringify(p).includes("378282246310005"));
    assert.equal(p.rows[0].card, "****0005");
    assert.ok(p.rows[0].merchant.length > 0);
  });
  test("tables: employees, merchants and monthly are populated and sorted", () => {
    const r = analyze(ex, opts);
    assert.equal(r.tables.employees.length, 10);
    assert.ok(r.tables.employees[0].riskScore >= r.tables.employees[9].riskScore);
    assert.ok(r.tables.merchants.length > 0 && r.tables.monthly.length >= 7);
    assert.ok(r.tables.monthly.every((m, i, a) => i === 0 || a[i - 1].month <= m.month));
    assert.ok(r.tables.followup.every((x) => x.items > 0 && x.reasons));
  });
  test("findingsToCsv header row and one line per finding", () => {
    const r = analyze(ex, opts);
    const lines = findingsToCsv(r.findings).trim().split("\n");
    assert.equal(lines[0], "severity,confidence,category,title,description,recommendation,controls,employees,evidenceCount");
    assert.equal(lines.length, r.findings.length + 1);
  });
  test("follow-up and recovery CSV headers; formula injection neutralised", () => {
    assert.equal(followupToCsv([]).split("\n")[0], "employee,employee_id,manager,department,items,amount,risk_score,reasons");
    assert.equal(recoveryToCsv([]).split("\n")[0], "type,merchant,date,amount,currency,claims,recoverable,employees,reports,files");
    assert.ok(recoveryToCsv([{ merchant: "=HYPERLINK(1)" }]).includes("'=HYPERLINK(1)"));
  });
  test("summary text lists skipped checks", () => {
    const r = analyze([file("brex.csv", BREX)], {});
    const t = summaryText(r);
    assert.ok(t.includes("Skipped or limited checks") && t.includes("split"));
  });
  test("progress callback is optional and is called", () => {
    let calls = 0;
    analyze(ex, opts, { progress: () => { calls++; } });
    assert.ok(calls > 0);
    assert.equal(analyze(ex, opts).meta.tool, TOOL_ID);
  });
  test("empty input yields zero findings and does not throw", () => {
    const p = parseInput("");
    assert.equal(p.rows.length, 0);
    const r = analyze([], {});
    assert.equal(r.findings.length, 0);
    assert.equal(r.meta.rows, 0);
  });
});
