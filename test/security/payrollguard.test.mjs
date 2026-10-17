// Payroll Integrity engine tests (public/js/finsec/payrollguard-engine.js): parsers per
// vendor layout, SSN rules, masking, every detection positive / negative, payday window
// edges, determinism, selfTest and CSV shape.

import { test, assert, group } from "../harness.mjs";
import {
  selfTest, analyze, parseInput, exampleDataset, classifyFile, resolveColumns, toCents, formatCents, ssnCheck, accountInfo,
  findingsToCsv, worklistCsv, bankChangesCsv, summaryText, DEFAULTS, TOOL_ID,
} from "../../public/js/finsec/payrollguard-engine.js";

const csv = (rows) => rows.map((r) => r.join(",")).join("\n");
const file = (name, rows) => ({ name, text: csv(rows) });
const run = (files, opts) => analyze(parseInput(files), opts);
const ids = (r) => r.findings.map((f) => f.id);
const hasId = (r, prefix) => r.findings.some((f) => f.id.startsWith(prefix));

// Valid ABA routing numbers (3-7-1 checksum): 021000021, 011000015, 121000358.
const GEN_REG = ["employee_id", "name", "pay_date", "period_start", "period_end", "gross", "net", "tax", "deductions", "regular_hours", "overtime_hours", "bank_account", "routing", "payment_method", "department"];
const GEN_ROSTER = ["employee_id", "name", "ssn_or_national_id", "date_of_birth", "address", "city", "postal_code", "phone", "email", "department", "manager_id", "hire_date", "termination_date", "status", "pay_type", "salary", "hourly_rate"];
const GEN_BANK = ["employee_id", "changed_at", "changed_by", "old_account_last4", "new_account", "new_routing", "channel", "ip"];
const GEN_TS = ["employee_id", "date", "hours", "approved_by", "project"];

// Biweekly periods starting 2026-01-04; pay date = period end + 5.
function period(k) {
  const start = Date.UTC(2026, 0, 4) + k * 14 * 86400000;
  const iso = (ms) => new Date(ms).toISOString().slice(0, 10);
  return { start: iso(start), end: iso(start + 13 * 86400000), pay: iso(start + 18 * 86400000) };
}
function regRow(id, name, k, { gross = "2000.00", net = "1500.00", tax = "400.00", ded = "100.00", reg = "", ot = "", acct = "", routing = "", dept = "Ops" } = {}) {
  const p = period(k);
  return [id, name, p.pay, p.start, p.end, gross, net, tax, ded, reg, ot, acct, routing, "Direct Deposit", dept];
}
function rosterRow(id, name, o = {}) {
  return [id, name, o.ssn ?? "212-34-" + (5000 + Number(id.replace(/\D/g, ""))), "1980-01-01", o.addr ?? id + " Main St", "Harrow Point", o.postal ?? "02101", o.phone ?? "555-0" + id.replace(/\D/g, "").padStart(3, "0"),
    o.email ?? id.toLowerCase() + "@test.darknode.ai", o.dept ?? "Ops", o.mgr ?? "", o.hire ?? "2020-01-01", o.term ?? "", o.status ?? "Active", o.type ?? "Salaried", o.salary ?? "52000.00", o.rate ?? ""];
}
const baseRoster = (extra = []) => file("roster.csv", [GEN_ROSTER, rosterRow("E1", "Ana One"), rosterRow("E2", "Ben Two"), rosterRow("E3", "Cy Three"), ...extra]);

group("payrollguard: primitives", () => {
  test("toCents handles symbols, thousands, parentheses and rounding", () => {
    assert.equal(toCents("$1,234.56"), 123456);
    assert.equal(toCents("(12.50)"), -1250);
    assert.equal(toCents("-3.1"), -310);
    assert.equal(toCents("1.005"), 101);
    assert.equal(toCents("1.234,56"), 123456);
    assert.equal(toCents(""), null);
    assert.equal(toCents("abc"), null);
  });
  test("formatCents formats integer cents", () => {
    assert.equal(formatCents(123456789), "1,234,567.89");
    assert.equal(formatCents(-5), "-0.05");
  });
  test("SSN rules: area 000, 666, 9xx rejected", () => {
    for (const x of ["000-12-3456", "666-12-3456", "912-34-5678", "999-99-9999"]) assert.equal(ssnCheck(x).valid, false, x);
  });
  test("SSN rules: group 00 and serial 0000 rejected; valid shape accepted", () => {
    assert.equal(ssnCheck("123-00-4567").valid, false);
    assert.equal(ssnCheck("123-45-0000").valid, false);
    assert.equal(ssnCheck("212345678").valid, true);
    assert.equal(ssnCheck("212-34-5678").masked, "***-**-5678");
  });
  test("non-SSN national ids are kept unvalidated and masked", () => {
    const r = ssnCheck("AB123456C");
    assert.equal(r.kind, "national"); assert.equal(r.valid, null); assert.equal(r.masked, "****456C");
  });
  test("accountInfo masks and refuses to key a masked account", () => {
    const a = accountInfo("123456789012", "021000021");
    assert.equal(a.label, "acct ****9012 / RTN 021000021");
    assert.ok(a.key);
    assert.equal(accountInfo("XXXXXX9012", "021000021").key, null);
  });
});

group("payrollguard: parsers (verbatim vendor headers)", () => {
  test("ADP Workforce Now payroll register", () => {
    const t = "Company Code,File #,Name,Pay Date,Period Start,Period End,Regular Hours,Overtime Hours,Regular Earnings,Overtime Earnings,Gross Pay,Federal Income Tax,Social Security,Medicare,State Tax,Deductions,Net Pay,Check/Voucher #,Department\n" +
      "K7Q,000123,\"Marlow, Ines\",01/23/2026,01/04/2026,01/17/2026,80.00,2.00,\"2,000.00\",75.00,\"2,075.00\",210.00,128.65,30.09,80.00,50.00,\"1,576.26\",100045,Finance";
    const p = parseInput({ name: "adp.csv", text: t });
    const f = p.files[0];
    assert.equal(f.kind, "register"); assert.equal(f.vendor, "adp"); assert.equal(f.confidence, "high");
    const c = resolveColumns(f, "register");
    assert.equal(c.employeeId, "File #"); assert.equal(c.gross, "Gross Pay"); assert.equal(c.fit, "Federal Income Tax"); assert.equal(c.checkNo, "Check/Voucher #");
    const r = analyze(p);
    assert.equal(r.summary.grossCents, 207500);
    assert.equal(r.summary.netCents, 157626);
    assert.ok(r.tables.employees[0].employee.includes("123"));
  });
  test("Gusto payroll journal", () => {
    const t = "Pay Period Start,Pay Period End,Check Date,Employee,Employee ID,Gross Earnings,Employee Taxes,Employee Deductions,Net Pay,Employer Taxes,Payment Method,Regular Hours,Overtime Hours\n2026-01-04,2026-01-17,2026-01-23,Dara Feld,E7,2346.15,502.08,150.00,1694.07,179.48,Direct Deposit,80.00,0.00";
    const f = parseInput({ name: "g.csv", text: t }).files[0];
    assert.equal(f.vendor, "gusto"); assert.equal(f.confidence, "high");
    const c = resolveColumns(f, "register");
    assert.equal(c.name, "Employee"); assert.equal(c.employeeId, "Employee ID"); assert.equal(c.tax, "Employee Taxes"); assert.equal(c.deductions, "Employee Deductions"); assert.equal(c.payDate, "Check Date");
  });
  test("Workday pay results maps the last-4 column to last 4, not a full account", () => {
    const t = "Worker,Employee ID,Pay Group,Payment Date,Period Start Date,Period End Date,Gross Amount,Net Amount,Hours,Payment Type,Bank Account (last 4)\nYara Quint,21004,US Biweekly,2026-01-23,2026-01-04,2026-01-17,3230.77,2401.12,80,Regular,4719";
    const f = parseInput({ name: "wd.csv", text: t }).files[0];
    assert.equal(f.vendor, "workday"); assert.equal(f.confidence, "high");
    const c = resolveColumns(f, "register");
    assert.equal(c.bankLast4, "Bank Account (last 4)"); assert.equal(c.bankAccount, undefined); assert.equal(c.hours, "Hours");
    const r = analyze(parseInput({ name: "wd.csv", text: t }));
    assert.ok(r.skipped.some((s) => s.check === "no_withholding"), "Workday pay results have no tax columns");
  });
  test("Paychex payroll journal detected at medium confidence (mapping panel)", () => {
    const t = "Employee ID,Employee Name,Check Date,Period Begin,Period End,Reg Hours,OT Hours,Gross,Fed Income Tax,Social Security,Medicare,State Income Tax,Net,Check Number\n311,Kofi Marsh,01/23/2026,01/04/2026,01/17/2026,80,0,2000.00,180.00,124.00,29.00,70.00,1597.00,50511";
    const f = parseInput({ name: "px.csv", text: t }).files[0];
    assert.equal(f.kind, "register"); assert.equal(f.vendor, "paychex"); assert.equal(f.confidence, "medium");
    const c = resolveColumns(f, "register");
    assert.equal(c.gross, "Gross"); assert.equal(c.net, "Net"); assert.equal(c.regHours, "Reg Hours"); assert.equal(c.otHours, "OT Hours");
  });
  test("generic register", () => {
    const f = parseInput(file("r.csv", [GEN_REG, regRow("E1", "Ana One", 0)])).files[0];
    assert.equal(f.kind, "register"); assert.equal(f.vendor, "generic"); assert.equal(f.confidence, "high");
  });
  test("generic HR roster", () => {
    const f = parseInput(baseRoster()).files[0];
    assert.equal(f.kind, "roster"); assert.equal(f.confidence, "high");
    assert.equal(resolveColumns(f, "roster").ssn, "ssn_or_national_id");
  });
  test("BambooHR roster variant with aliases", () => {
    const h = ["Employee #", "First Name", "Last Name", "SSN", "Hire Date", "Termination Date", "Department", "Reports To", "Pay Type", "Status", "Work Email"];
    const f = parseInput({ name: "bamboo.csv", text: h.join(",") + "\n42,Ana,One,212-34-5678,2020-01-01,,Ops,Ben Two,Salary,Active,ana@test.darknode.ai" }).files[0];
    assert.equal(f.kind, "roster"); assert.equal(f.vendor, "bamboohr"); assert.equal(f.confidence, "medium");
    const c = resolveColumns(f, "roster");
    assert.equal(c.employeeId, "Employee #"); assert.equal(c.firstName, "First Name"); assert.equal(c.ssn, "SSN");
  });
  test("Workday roster variant", () => {
    const h = ["Employee ID", "Worker", "National ID", "Hire Date", "Termination Date", "Supervisory Organization", "Manager", "Primary Work Email"];
    const f = parseInput({ name: "wdr.csv", text: h.join(",") + "\n21004,Yara Quint,212-34-5678,2019-03-01,,Finance,Ines Marlow,yara@test.darknode.ai" }).files[0];
    assert.equal(f.vendor, "workday"); assert.equal(f.kind, "roster");
    assert.equal(resolveColumns(f, "roster").department, "Supervisory Organization");
  });
  test("generic bank change log", () => {
    const f = parseInput(file("b.csv", [GEN_BANK, ["E1", "2026-01-20T10:00:00Z", "E1", "1111", "123456789012", "021000021", "self-service", "198.51.100.1"]])).files[0];
    assert.equal(f.kind, "bank"); assert.equal(f.confidence, "high");
  });
  test("ADP direct-deposit change audit (long form) groups field rows into one change", () => {
    const t = "Company Code,File #,Employee Name,Change Date,Changed By,Field,Old Value,New Value\nK7Q,000001,Ana One,2026-01-21,helpdesk.t2,Account Number,XXXX1111,987654321098\nK7Q,000001,Ana One,2026-01-21,helpdesk.t2,Routing Number,011000015,021000021";
    const p = parseInput({ name: "adp-dd.csv", text: t });
    assert.equal(p.files[0].vendor, "adp-audit");
    const r = run([file("r.csv", [GEN_REG, regRow("E1", "Ana One", 0)]), { name: "adp-dd.csv", text: t }]);
    assert.equal(r.tables.bankChanges.length, 1);
    assert.equal(r.tables.bankChanges[0].new_account, "acct ****1098 / RTN 021000021");
    assert.equal(r.tables.bankChanges[0].old_account, "****1111");
  });
  test("Workday business process audit keeps only payment-election events", () => {
    const t = "Business Process,Subject,Employee ID,Initiated On,Initiated By,Status\nChange Payment Elections,Ana One,E1,2026-01-21,ana.one,Successfully Completed\nChange Job,Ben Two,E2,2026-01-21,hr.admin,Successfully Completed";
    const p = parseInput({ name: "wd-bp.csv", text: t });
    assert.equal(p.files[0].vendor, "workday-bp");
    const r = run([file("r.csv", [GEN_REG, regRow("E1", "Ana One", 0), regRow("E2", "Ben Two", 0)]), { name: "wd-bp.csv", text: t }]);
    assert.equal(r.tables.bankChanges.length, 1);
    assert.equal(r.tables.bankChanges[0].days_to_payday, 1);
  });
  test("Gusto bank-account change history (medium)", () => {
    const h = "Employee,Employee ID,Change Date,Changed By,Routing Number,Account Number";
    const f = parseInput({ name: "gb.csv", text: h + "\nAna One,E1,2026-01-21,Ana One,021000021,123456789012" }).files[0];
    assert.equal(f.kind, "bank"); assert.equal(f.vendor, "gusto-history");
  });
  test("timesheets", () => {
    const f = parseInput(file("t.csv", [GEN_TS, ["E1", "2026-01-05", "8", "E2", "Dock"]])).files[0];
    assert.equal(f.kind, "timesheet"); assert.equal(f.confidence, "high");
  });
  test("unknown headers are reported, never guessed", () => {
    const p = parseInput({ name: "x.csv", text: "foo,bar\n1,2" });
    assert.equal(p.files[0].kind, "unknown");
    assert.ok(p.skipped.some((s) => s.check === "classify"));
  });
});

group("payrollguard: ghost employees", () => {
  test("paid id absent from roster fires; roster member does not", () => {
    const r = run([file("r.csv", [GEN_REG, regRow("E1", "Ana One", 0), regRow("E9", "Zed Nine", 0)]), baseRoster()]);
    assert.ok(hasId(r, "ghost-not-on-roster:e9"));
    assert.ok(!hasId(r, "ghost-not-on-roster:e1"));
  });
  test("ADP zero-padded File # matches roster id", () => {
    const r = run([file("r.csv", [GEN_REG, regRow("0001", "Ana One", 0)]), baseRoster([rosterRow("1", "Ana One")])]);
    assert.ok(!hasId(r, "ghost-not-on-roster"));
  });
  test("paid for a period starting after termination fires; final period containing termination does not", () => {
    const p1 = period(1);
    const roster = baseRoster([rosterRow("E4", "Di Four", { term: p1.start })]);
    const pos = run([file("r.csv", [GEN_REG, regRow("E4", "Di Four", 2)]), roster]);
    assert.ok(hasId(pos, "ghost-after-term:e4"));
    const neg = run([file("r.csv", [GEN_REG, regRow("E4", "Di Four", 1)]), roster]);
    assert.ok(!hasId(neg, "ghost-after-term"));
  });
  test("paid before hire date fires; period ending on hire date does not", () => {
    const roster = baseRoster([rosterRow("E5", "Eve Five", { hire: period(1).end })]);
    assert.ok(hasId(run([file("r.csv", [GEN_REG, regRow("E5", "Eve Five", 0)]), roster]), "ghost-before-hire:e5"));
    assert.ok(!hasId(run([file("r.csv", [GEN_REG, regRow("E5", "Eve Five", 1)]), roster]), "ghost-before-hire"));
  });
  test("no withholding fires for W-2 pay; contractors are excluded", () => {
    const roster = baseRoster([rosterRow("E6", "Flo Six", { type: "1099 Contractor" })]);
    const r = run([file("r.csv", [GEN_REG, regRow("E1", "Ana One", 0, { tax: "0.00" }), regRow("E6", "Flo Six", 0, { tax: "0.00" })]), roster]);
    const f = r.findings.find((x) => x.id === "ghost-signal:no-tax-withheld");
    assert.ok(f);
    assert.equal(f.evidenceCount, 1);
    assert.ok(f.assets[0].name.includes("Ana One"));
  });
  test("no deductions vs department peers fires only with 3+ peers who have them", () => {
    const rows = [GEN_REG, ...["E1", "E2", "E3", "E4"].map((id, i) => regRow(id, "P" + i, 0, { ded: id === "E4" ? "0.00" : "100.00" }))];
    const roster = baseRoster([rosterRow("E4", "P3")]);
    assert.ok(hasId(run([file("r.csv", rows), roster]), "ghost-signal:no-deductions-while"));
    assert.ok(!hasId(run([file("r.csv", rows.slice(0, 1).concat(rows.slice(2))), roster]), "ghost-signal:no-deductions-while"));
  });
  test("two weak signals stack into a high ghost-indicator finding; one does not", () => {
    const roster = baseRoster([rosterRow("E7", "Gus Seven", { ssn: "", addr: "", phone: "", email: "" })]);
    const r = run([file("r.csv", [GEN_REG, regRow("E7", "Gus Seven", 0)]), roster]);
    const combo = r.findings.find((f) => f.id === "ghost-combo:e7");
    assert.ok(combo); assert.equal(combo.severity, "high");
    const r2 = run([file("r.csv", [GEN_REG, regRow("E7", "Gus Seven", 0)]), baseRoster([rosterRow("E7", "Gus Seven", { ssn: "" })])]);
    assert.ok(!hasId(r2, "ghost-combo"));
    assert.ok(hasId(r2, "ghost-signal:missing-SSN"));
  });
  test("invalid SSN pattern is flagged and masked", () => {
    const r = run([file("r.csv", [GEN_REG, regRow("E1", "Ana One", 0)]), file("roster.csv", [GEN_ROSTER, rosterRow("E1", "Ana One", { ssn: "666-12-3456" })])]);
    const f = r.findings.find((x) => x.id === "ghost-signal:invalid-SSN");
    assert.ok(f);
    assert.equal(f.evidence[0].ssn, "***-**-3456");
  });
  test("roster checks are skipped with a reason when no roster is loaded", () => {
    const r = run([file("r.csv", [GEN_REG, regRow("E1", "Ana One", 0)])]);
    assert.ok(r.skipped.some((s) => s.check === "not_on_roster" && /roster/.test(s.reason)));
  });
});

group("payrollguard: shared identifiers", () => {
  test("two employees paid into one account: high", () => {
    const r = run([file("r.csv", [GEN_REG, regRow("E1", "Ana One", 0, { acct: "123456789012", routing: "021000021" }), regRow("E2", "Ben Two", 0, { acct: "123456789012", routing: "021000021" }), regRow("E3", "Cy Three", 0, { acct: "555566667777", routing: "021000021" })]), baseRoster()]);
    const f = r.findings.find((x) => x.id.startsWith("shared-bank"));
    assert.ok(f); assert.equal(f.severity, "high"); assert.equal(f.assets.length, 2);
    assert.equal(r.summary.sharedBankAccounts, 1);
  });
  test("shared SSN is high; shared address is low / review and says families exist", () => {
    const roster = file("roster.csv", [GEN_ROSTER, rosterRow("E1", "Ana One", { ssn: "212-34-5678", addr: "9 Elm St", postal: "02101" }), rosterRow("E2", "Ben Two", { ssn: "212-34-5678", addr: "9 Elm St", postal: "02101" })]);
    const r = run([file("r.csv", [GEN_REG, regRow("E1", "Ana One", 0), regRow("E2", "Ben Two", 0)]), roster]);
    const ssn = r.findings.find((x) => x.id.startsWith("shared-ssn"));
    const addr = r.findings.find((x) => x.id.startsWith("shared-address"));
    assert.equal(ssn.severity, "high");
    assert.equal(addr.severity, "low"); assert.equal(addr.confidence, "review");
    assert.ok(/[Ff]amilies/.test(addr.description));
  });
  test("terminated employee's account later used by another employee: high", () => {
    const roster = baseRoster([rosterRow("E4", "Di Four", { term: "2026-01-10" })]);
    const bank = file("b.csv", [GEN_BANK, ["E4", "2025-06-01", "E4", "1111", "999988887777", "021000021", "self-service", ""], ["E2", "2026-02-02", "E2", "2222", "999988887777", "021000021", "self-service", ""]]);
    const r = run([file("r.csv", [GEN_REG, regRow("E2", "Ben Two", 0)]), roster, bank]);
    const f = r.findings.find((x) => x.title.startsWith("Terminated employee's bank account"));
    assert.ok(f); assert.equal(f.severity, "high");
  });
  test("distinct accounts produce no shared finding", () => {
    const r = run([file("r.csv", [GEN_REG, regRow("E1", "A", 0, { acct: "111122223333", routing: "021000021" }), regRow("E2", "B", 0, { acct: "444455556666", routing: "021000021" })])]);
    assert.ok(!hasId(r, "shared-bank"));
  });
});

group("payrollguard: payroll diversion", () => {
  const reg = () => file("r.csv", [GEN_REG, regRow("E1", "Ana One", 0), regRow("E2", "Ben Two", 0), regRow("E3", "Cy Three", 0)]);
  const pay0 = period(0).pay; // 2026-01-22
  const daysBefore = (n) => new Date(Date.parse(pay0) - n * 86400000).toISOString().slice(0, 10);
  test("helpdesk change 2 days before payday is critical", () => {
    const r = run([reg(), baseRoster(), file("b.csv", [GEN_BANK, ["E1", daysBefore(2) + "T18:55:00Z", "helpdesk.t2@test.darknode.ai", "1111", "880044119275", "021000021", "helpdesk", "192.0.2.144"]])]);
    const f = r.findings.find((x) => x.id.startsWith("diversion:e1"));
    assert.ok(f); assert.equal(f.severity, "critical");
    assert.ok(f.controls.some((c) => c.id === "T1566") && f.controls.some((c) => c.id === "T1078"));
    assert.equal(r.tables.bankChanges[0].days_to_payday, 2);
  });
  test("self-service change inside the window is high", () => {
    const r = run([reg(), file("b.csv", [GEN_BANK, ["E1", daysBefore(3), "E1", "1111", "880044119275", "021000021", "self-service", ""]])]);
    assert.equal(r.findings.find((x) => x.id.startsWith("diversion:e1")).severity, "high");
  });
  test("window edge: exactly bankChangeDays fires, one more day does not", () => {
    const mk = (n) => run([reg(), file("b.csv", [GEN_BANK, ["E1", daysBefore(n), "E1", "1111", "880044119275", "021000021", "self-service", ""]])]);
    assert.ok(hasId(mk(DEFAULTS.bankChangeDays), "diversion:e1"));
    assert.ok(!hasId(mk(DEFAULTS.bankChangeDays + 1), "diversion:e1"));
    assert.ok(hasId(mk(0), "diversion:e1"), "a change on payday itself is inside the window");
  });
  test("threshold is editable", () => {
    const r = run([reg(), file("b.csv", [GEN_BANK, ["E1", daysBefore(8), "E1", "1111", "880044119275", "021000021", "self-service", ""]])], { bankChangeDays: 10 });
    assert.ok(hasId(r, "diversion:e1"));
  });
  test("pay that went to the old account suppresses the diversion finding", () => {
    const regAcct = file("r.csv", [GEN_REG, regRow("E1", "Ana One", 0, { acct: "111122223333", routing: "021000021" })]);
    const r = run([regAcct, file("b.csv", [GEN_BANK, ["E1", daysBefore(2), "E1", "3333", "880044119275", "021000021", "self-service", ""]])]);
    assert.ok(!hasId(r, "diversion:e1"));
    assert.equal(r.tables.bankChanges[0].paid_to_new_account, false);
  });
  test("pay that went to the new account raises confidence to likely", () => {
    const regAcct = file("r.csv", [GEN_REG, regRow("E1", "Ana One", 0, { acct: "880044119275", routing: "021000021" })]);
    const r = run([regAcct, file("b.csv", [GEN_BANK, ["E1", daysBefore(2), "E1", "3333", "880044119275", "021000021", "self-service", ""]])]);
    assert.equal(r.findings.find((x) => x.id.startsWith("diversion:e1")).confidence, "likely");
  });
  test("three employees to the same routing in the window is a critical campaign; two is not", () => {
    const rows = [["E1", daysBefore(4), "E1", "1", "740000918822", "121000358", "self-service", "203.0.113.77"], ["E2", daysBefore(4), "E2", "2", "740000918839", "121000358", "self-service", "203.0.113.77"], ["E3", daysBefore(3), "E3", "3", "740000918846", "121000358", "self-service", "203.0.113.77"]];
    const r = run([reg(), file("b.csv", [GEN_BANK, ...rows])]);
    const f = r.findings.find((x) => x.id.startsWith("diversion-campaign:"));
    assert.ok(f); assert.equal(f.severity, "critical"); assert.equal(f.assets.length, 3);
    assert.ok(!hasId(run([reg(), file("b.csv", [GEN_BANK, ...rows.slice(0, 2)])]), "diversion-campaign"));
  });
  test("change by someone other than the employee is medium; self is silent", () => {
    const r = run([reg(), baseRoster(), file("b.csv", [GEN_BANK, ["E1", "2026-01-01", "hr.admin@test.darknode.ai", "1", "880044119275", "021000021", "admin", ""], ["E2", "2026-01-01", "e2@test.darknode.ai", "2", "880044119282", "021000021", "self-service", ""]])]);
    const f = r.findings.find((x) => x.id === "bank-changed-by-other");
    assert.ok(f); assert.equal(f.severity, "medium"); assert.equal(f.evidenceCount, 1);
  });
  test("invalid routing number is high; valid is silent", () => {
    const r = run([reg(), file("b.csv", [GEN_BANK, ["E1", "2026-01-01", "E1", "1", "880044119275", "021000022", "self-service", ""], ["E2", "2026-01-01", "E2", "2", "880044119282", "021000021", "self-service", ""]])]);
    const f = r.findings.find((x) => x.id === "bank-invalid-routing");
    assert.ok(f); assert.equal(f.severity, "high"); assert.equal(f.evidenceCount, 1);
  });
  test("administrator changing their own deposit via admin channel is an SoD finding", () => {
    const r = run([reg(), baseRoster(), file("b.csv", [GEN_BANK, ["E1", "2026-01-01", "E1", "1", "880044119275", "021000021", "admin", ""]])]);
    const f = r.findings.find((x) => x.id === "bank-own-record-admin");
    assert.ok(f); assert.ok(f.controls.some((c) => c.id === "AC-5"));
  });
  test("no bank log: diversion skipped with reason", () => {
    assert.ok(run([reg()]).skipped.some((s) => s.check === "payroll_diversion"));
  });
});

group("payrollguard: falsified wages", () => {
  test("pay spike above robust z with enough periods fires", () => {
    const rows = [GEN_REG];
    for (let k = 0; k < 8; k++) rows.push(regRow("E1", "Ana One", k, { gross: k === 7 ? "6000.00" : String(2000 + (k % 3) * 10) + ".00" }));
    const r = run([file("r.csv", rows)]);
    const f = r.findings.find((x) => x.id === "pay-spike:e1");
    assert.ok(f); assert.equal(f.evidenceCount, 1); assert.ok(/n = 8/.test(f.description));
  });
  test("pay spike is skipped below minimum periods", () => {
    const rows = [GEN_REG];
    for (let k = 0; k < 5; k++) rows.push(regRow("E1", "Ana One", k, { gross: k === 4 ? "6000.00" : String(2000 + k * 10) + ".00" }));
    const r = run([file("r.csv", rows)]);
    assert.ok(!hasId(r, "pay-spike"));
    assert.ok(r.skipped.some((s) => s.check === "pay_spike"));
  });
  test("salaried gross above roster salary fires; matching salary is silent", () => {
    const roster = baseRoster([rosterRow("E8", "Hal Eight", { salary: "52000.00" })]);
    const ok = run([file("r.csv", [GEN_REG, regRow("E8", "Hal Eight", 0, { gross: "2000.00" })]), roster]);
    assert.ok(!hasId(ok, "salary-change"));
    const bad = run([file("r.csv", [GEN_REG, regRow("E8", "Hal Eight", 0, { gross: "2600.00" })]), roster]);
    assert.ok(hasId(bad, "salary-change:e8"));
  });
  test("overtime above max per week-equivalent fires; at the limit does not", () => {
    const at = run([file("r.csv", [GEN_REG, regRow("E1", "A", 0, { reg: "80", ot: "40" })])]);
    assert.ok(!hasId(at, "overtime-outlier"), "40 h over 2 weeks = 20 h/week, not above");
    const over = run([file("r.csv", [GEN_REG, regRow("E1", "A", 0, { reg: "80", ot: "42" })])]);
    assert.ok(hasId(over, "overtime-outlier"));
  });
  test("physically implausible weekly hours fire", () => {
    const r = run([file("r.csv", [GEN_REG, regRow("E1", "A", 0, { reg: "190", ot: "20" })])], { maxOvertime: 100 });
    const f = r.findings.find((x) => x.id === "overtime-outlier");
    assert.ok(f && /total h\/week/.test(f.evidence[0].reason));
  });
  test("hourly pay with zero hours fires; salaried is silent", () => {
    const roster = baseRoster([rosterRow("E4", "Di Four", { type: "Hourly", salary: "", rate: "25.00" })]);
    const r = run([file("r.csv", [GEN_REG, regRow("E4", "Di Four", 0, { reg: "0", ot: "0" }), regRow("E1", "Ana One", 0, { reg: "", ot: "" })]), roster]);
    const f = r.findings.find((x) => x.id === "pay-without-hours");
    assert.ok(f); assert.equal(f.evidenceCount, 1);
  });
  test("paid hours above approved timesheet hours fire; matching hours are silent", () => {
    const roster = baseRoster([rosterRow("E4", "Di Four", { type: "Hourly", salary: "", rate: "25.00", mgr: "E1" })]);
    const ts = (h) => file("t.csv", [GEN_TS, ...Array.from({ length: 10 }, (_, i) => ["E4", "2026-01-" + String(5 + i).padStart(2, "0"), String(h), "E1", "Dock"])]);
    const reg = file("r.csv", [GEN_REG, regRow("E4", "Di Four", 0, { reg: "80", ot: "0" })]);
    assert.ok(!hasId(run([reg, roster, ts(8)]), "pay-without-hours"));
    assert.ok(hasId(run([reg, roster, ts(6)]), "pay-without-hours"));
  });
  test("timesheet reconciliation skipped without timesheets", () => {
    assert.ok(run([file("r.csv", [GEN_REG, regRow("E1", "A", 0)])]).skipped.some((s) => s.check === "timesheet_reconciliation"));
  });
  test("self-approved timesheet and approval by a direct report fire; manager approval is silent", () => {
    const roster = baseRoster([rosterRow("E4", "Di Four", { mgr: "E1" }), rosterRow("E5", "Eve Five", { mgr: "E4" })]);
    const reg = file("r.csv", [GEN_REG, regRow("E4", "Di Four", 0)]);
    const self = run([reg, roster, file("t.csv", [GEN_TS, ["E4", "2026-01-05", "8", "E4", "Dock"]])]);
    assert.ok(hasId(self, "self-approval"));
    const sub = run([reg, roster, file("t.csv", [GEN_TS, ["E4", "2026-01-05", "8", "E5", "Dock"]])]);
    assert.ok(/direct report/.test(sub.findings.find((f) => f.id === "self-approval").evidence[0].reason));
    assert.ok(!hasId(run([reg, roster, file("t.csv", [GEN_TS, ["E4", "2026-01-05", "8", "E1", "Dock"]])]), "self-approval"));
  });
  test("duplicate pay for overlapping periods fires; consecutive periods and bonuses do not", () => {
    const dup = run([file("r.csv", [GEN_REG, regRow("E1", "A", 0), regRow("E1", "A", 0)])]);
    const f = dup.findings.find((x) => x.id === "duplicate-pay");
    assert.ok(f); assert.equal(f.severity, "high"); assert.equal(f.confidence, "likely");
    assert.ok(!hasId(run([file("r.csv", [GEN_REG, regRow("E1", "A", 0), regRow("E1", "A", 1)])]), "duplicate-pay"));
    const h = GEN_REG.concat(["payment type"]);
    assert.ok(!hasId(run([file("r.csv", [h, regRow("E1", "A", 0).concat(["Regular"]), regRow("E1", "A", 0).concat(["Bonus"])])]), "duplicate-pay"));
  });
});

group("payrollguard: masking, determinism, exports", () => {
  const ex = exampleDataset();
  const r = analyze(parseInput(ex.files));
  test("example: planned detections all fire", () => {
    for (const p of ["ghost-not-on-roster:e1099", "ghost-after-term:e1009", "shared-bank", "diversion:e1004", "diversion-campaign:", "overtime-outlier"]) assert.ok(hasId(r, p), p);
    assert.equal(r.findings.find((f) => f.id.startsWith("diversion:e1004")).severity, "critical");
  });
  test("example uses test.darknode.ai people and never-issued 9xx SSNs", () => {
    const roster = ex.files.find((f) => /roster/.test(f.name)).text;
    assert.ok(/@test\.darknode\.ai/.test(roster));
    const ssns = roster.split("\n").slice(1).map((l) => l.split(",")[2]);
    assert.ok(ssns.length === 12 && ssns.every((s) => /^9\d\d-/.test(s)));
  });
  test("no full SSN or full account number in analyze output or any export", () => {
    const fullSsns = ex.files.find((f) => /roster/.test(f.name)).text.split("\n").slice(1).map((l) => l.split(",")[2]);
    const accts = ex.files.find((f) => /deposit/.test(f.name)).text.split("\n").slice(1).map((l) => l.split(",")[4]);
    const outs = [JSON.stringify(r), findingsToCsv(r.findings), worklistCsv(r), bankChangesCsv(r), summaryText(r)];
    for (const o of outs) {
      for (const s of fullSsns) { assert.ok(!o.includes(s), "ssn leaked"); assert.ok(!o.includes(s.replace(/-/g, "")), "ssn digits leaked"); }
      for (const a of accts) assert.ok(!o.includes(a), "account leaked: " + a);
    }
  });
  test("masking also holds for register bank accounts", () => {
    const out = run([file("r.csv", [GEN_REG, regRow("E1", "A", 0, { acct: "123456789012", routing: "021000021" }), regRow("E2", "B", 0, { acct: "123456789012", routing: "021000021" })])]);
    assert.ok(!JSON.stringify(out).includes("123456789012"));
    assert.ok(JSON.stringify(out).includes("****9012"));
  });
  test("analyze is deterministic", () => {
    assert.equal(JSON.stringify(analyze(parseInput(ex.files))), JSON.stringify(r));
  });
  test("file order does not change findings", () => {
    const r2 = analyze(parseInput(ex.files.slice().reverse()));
    assert.deepEqual(r2.findings.map((f) => f.id), r.findings.map((f) => f.id));
  });
  test("every finding has controls, a confidence class and <= 50 evidence", () => {
    for (const f of r.findings) {
      assert.ok(f.controls.length >= 1 && ["confirmed", "likely", "review"].includes(f.confidence) && f.evidence.length <= 50 && f.recommendation);
      assert.ok(!/\bfraud\b(?! tree)/i.test(f.title + " " + f.description), "verdict wording: " + f.title);
    }
  });
  test("IDENTITY assets carry department, flags and amount at risk", () => {
    const a = r.findings.find((f) => f.id.startsWith("ghost-after-term")).assets[0];
    assert.equal(a.type, "IDENTITY");
    assert.equal(a.data.department, "Operations");
    assert.ok(a.data.flags.includes("paid after termination") && a.data.amountAtRisk);
  });
  test("tables: employees, bankChanges, shared, periods", () => {
    assert.equal(r.tables.periods.length, 8);
    assert.equal(r.tables.bankChanges.length, 7);
    assert.ok(r.tables.shared.some((s) => s.type === "bank" && s.count === 2));
    assert.ok(r.tables.employees.length >= 13);
    assert.ok(r.summary.grossCents > 0 && Number.isInteger(r.summary.grossCents));
  });
  test("progress callback is called and optional", () => {
    const seen = [];
    analyze(parseInput(ex.files), {}, { progress: (i, n) => seen.push([i, n]) });
    assert.ok(seen.length >= 2 && seen[seen.length - 1][0] === seen[seen.length - 1][1]);
  });
  test("findingsToCsv header row and one line per finding", () => {
    const lines = findingsToCsv(r.findings).split("\n");
    assert.equal(lines[0], "severity,confidence,category,title,description,recommendation,controls,evidenceCount,amountAtRisk,assets");
    assert.equal(lines.length, r.findings.length + 1);
  });
  test("worklist and bank-change CSV shapes", () => {
    assert.equal(worklistCsv(r).split("\n")[0], "employee,department,manager,status,risk,reason,amount_at_risk,next_step");
    assert.equal(bankChangesCsv(r).split("\n").length, 8);
  });
  test("CSV cells are guarded against formula injection", () => {
    const out = run([file("r.csv", [GEN_REG, regRow("E9", "=HYPERLINK(1)", 0)]), baseRoster()]);
    assert.ok(!/"=HYPERLINK/.test(worklistCsv(out)));
  });
  test("empty input yields zero findings and does not throw", () => {
    const e = analyze(parseInput(""));
    assert.equal(e.findings.length, 0); assert.equal(e.meta.rows, 0); assert.equal(e.meta.tool, TOOL_ID);
  });
  test("in-engine self-test passes", () => {
    const st = selfTest();
    assert.ok(st.pass, "failed: " + st.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
});
