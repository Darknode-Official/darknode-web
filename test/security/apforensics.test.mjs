// AP Forensics engine tests (public/js/finsec/apforensics-engine.js): one fixture per export
// layout with the vendor's verbatim headers, money / date / invoice normalisation, every
// detection on a crafted positive and a silent negative, Benford refusal, holiday handling
// with and without the reference file, masking of bank and tax ids, determinism, the
// in-engine self-test and the CSV serialisers.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, FORMATS, DEFAULTS, toCents, fmtMoney, parseDay, dayISO, normInvoice, normName, editDistance1, isTransposition, robustZ, benfordTest,
  classifyHeaders, detectFile, parseInput, kindOf, analyze, findingsToCsv, recoveryToCsv, vendorsToCsv, summaryText, exampleDataset, selfTest, RECOVERY_COLS, VENDOR_COLS,
} from "../../public/js/finsec/apforensics-engine.js";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------
const q = (v) => (/[",\n]/.test(String(v)) ? '"' + String(v).replace(/"/g, '""') + '"' : String(v));
const csvOf = (headers, rows) => [headers.map(q).join(","), ...rows.map((r) => headers.map((h) => q(r[h] == null ? "" : r[h])).join(","))].join("\n") + "\n";
const fmtFile = (name, format, rows) => ({ name, text: csvOf(FORMATS[format].headers, rows) });
const ledger = (rows, name = "ledger.csv") => fmtFile(name, "generic-ledger", rows);
const vmaster = (rows, name = "vendors.csv") => fmtFile(name, "generic-vendors", rows);
const roster = (rows, name = "employees.csv") => fmtFile(name, "generic-employees", rows);
const pay = (o) => ({ vendor: "Northwind Parts Test Co", vendor_id: "V100", invoice_number: "1001", invoice_date: "2026-03-02", payment_date: "2026-03-20", amount: "1,234.56", currency: "USD", ...o });
const run = (files, o) => analyze(files, { now: "2026-10-16", ...o });
const hit = (r, id) => r.findings.find((f) => f.check === id);
const skippedFor = (r, id) => r.skipped.filter((s) => s.check === id);
const addDays = (iso, n) => dayISO(parseDay(iso) + n);

// ---------------------------------------------------------------------------
group("apforensics: export formats (verbatim headers)", () => {
  test("QuickBooks Transaction List by Vendor: title lines, vendor sections, totals and bill payments", () => {
    const text = [
      "Transaction List by Vendor", "Fernhill Test Holdings", '"January 1 - December 31, 2026"', "",
      ",Date,Transaction Type,Num,Posting,Memo/Description,Account,Split,Amount,Balance",
      "Northwind Parts Test Co,,,,,,,,,",
      ",03/02/2026,Bill,INV-1001,Yes,Gaskets,Accounts Payable (A/P),Job Materials,500.00,500.00",
      ",03/20/2026,Bill Payment (Check),2201,Yes,,Checking,Accounts Payable (A/P),-500.00,0.00",
      ",04/02/2026,Vendor Credit,VC-7,Yes,,Accounts Payable (A/P),Job Materials,-50.00,-50.00",
      "Total for Northwind Parts Test Co,,,,,,,,$-50.00,",
      "Bluegill Fasteners Test Ltd,,,,,,,,,",
      ',03/05/2026,Bill,B-77,Yes,Bolts,Accounts Payable (A/P),Job Materials,"1,250.00","1,250.00"',
      "Total for Bluegill Fasteners Test Ltd,,,,,,,,\"$1,250.00\",",
    ].join("\n");
    const p = parseInput([{ name: "qbo.csv", text }]);
    assert.equal(p.sources[0].format, "qbo-txn-vendor");
    assert.equal(p.sources[0].confidence, "high");
    assert.equal(p.ledger.length, 3);
    assert.deepEqual(p.ledger.map((r) => r.vendor), ["Northwind Parts Test Co", "Northwind Parts Test Co", "Bluegill Fasteners Test Ltd"]);
    assert.deepEqual(p.ledger.map((r) => r.kind), ["bill", "payment", "bill"]);
    assert.equal(p.sources[0].dropped["credit / journal / void type"], 1);
    const r = run([{ name: "qbo.csv", text }]);
    assert.equal(r.summary.invoices, 2, "payments settle bills and leave the test population");
    assert.equal(r.summary.totalPaidCents, 50000, "paid = payment rows only");
  });

  test("QuickBooks layout with a Name column (header exactly as exported)", () => {
    const f = fmtFile("qbo2.csv", "qbo-txn-vendor", [
      { Date: "03/02/2026", "Transaction Type": "Bill", Num: "1001", Posting: "Yes", Name: "Northwind Parts Test Co", "Memo/Description": "", Account: "Accounts Payable (A/P)", Split: "Supplies", Amount: "75.10", Balance: "75.10" },
      { Date: "03/04/2026", "Transaction Type": "Expense", Num: "", Posting: "Yes", Name: "Elmstead Test Printing", "Memo/Description": "Flyers", Account: "Checking", Split: "Advertising", Amount: "210.00", Balance: "" },
    ]);
    const p = parseInput([f]);
    assert.equal(p.sources[0].format, "qbo-txn-vendor");
    assert.deepEqual(p.ledger.map((r) => [r.vendor, r.kind, r.cents]), [["Northwind Parts Test Co", "bill", 7510], ["Elmstead Test Printing", "expense", 21000]]);
  });

  test("Xero Bills export: line items roll up to one bill", () => {
    const base = { ContactName: "Saltmarsh Test Logistics", InvoiceNumber: "SL-1001", InvoiceDate: "2026-03-02", DueDate: "2026-04-01", Total: "330.00", Quantity: "1", AccountCode: "429", TaxType: "Tax on Purchases", Currency: "NZD" };
    const p = parseInput([fmtFile("xero.csv", "xero-bills", [{ ...base, Description: "Freight", UnitAmount: "200.00" }, { ...base, Description: "Fuel levy", UnitAmount: "100.00" }])]);
    assert.equal(p.sources[0].format, "xero-bills");
    assert.equal(p.ledger.length, 1);
    assert.equal(p.ledger[0].cents, 33000);
    assert.equal(p.ledger[0].currency, "NZD");
  });

  test("Xero Payable Invoice Detail", () => {
    const p = parseInput([fmtFile("xpid.csv", "xero-payable", [{ Contact: "Foxglove Test Catering", "Invoice Date": "02 Mar 2026", "Invoice Number": "FC-88", Reference: "Lunch", "Due Date": "16 Mar 2026", "Invoice Total": "450.00", Paid: "450.00", Due: "0.00", Status: "Paid" }])]);
    assert.equal(p.sources[0].format, "xero-payable");
    assert.equal(p.ledger[0].invNorm, "FC88");
    assert.equal(dayISO(p.ledger[0].invDay), "2026-03-02");
  });

  test("NetSuite vendor payments: voided rows and bill credits are excluded", () => {
    const p = parseInput([fmtFile("ns.csv", "netsuite-payments", [
      { Date: "3/2/2026", Type: "Bill", "Document Number": "INV-55", Name: "Cobalt Ridge Test Machining", Memo: "", Account: "Accounts Payable", Amount: "900.00", Status: "Paid In Full" },
      { Date: "3/9/2026", Type: "Bill Payment", "Document Number": "PMT-12", Name: "Cobalt Ridge Test Machining", Memo: "", Account: "Operating", Amount: "-900.00", Status: "" },
      { Date: "3/10/2026", Type: "Bill Payment", "Document Number": "PMT-13", Name: "Cobalt Ridge Test Machining", Memo: "", Account: "Operating", Amount: "-900.00", Status: "Voided" },
      { Date: "3/11/2026", Type: "Bill Credit", "Document Number": "BC-1", Name: "Cobalt Ridge Test Machining", Memo: "", Account: "Accounts Payable", Amount: "-20.00", Status: "" },
    ])]);
    assert.equal(p.sources[0].format, "netsuite-payments");
    assert.deepEqual(p.ledger.map((r) => r.kind), ["bill", "payment"]);
  });

  test("SAP FBL1N: trailing-minus amounts, dotted dates, zero-padded vendor linked to the master", () => {
    const fb = fmtFile("fbl1n.csv", "sap-fbl1n", [{ "Company Code": "1000", Vendor: "0000100234", "Document Number": "5100000001", "Document Type": "KR", "Posting Date": "15.03.2026", "Document Date": "14.03.2026",
      "Amount in local currency": "1.234,56-", "Local Currency": "EUR", Reference: "RE-0042", Text: "Bearings", "Clearing Document": "1500000009", "Clearing date": "02.04.2026", "Payment Method": "T", "User Name": "APCLERK1" }]);
    const vm = fmtFile("lfa1.csv", "sap-vendors", [{ Vendor: "100234", "Name 1": "Granite Arch Test Engineering GmbH", Street: "Hafenstrasse 4", City: "Hamburg", "Postal Code": "20095", Country: "DE", "Tax Number 1": "DE123456789", "Created On": "01.02.2024", "Created By": "VMDATA" }]);
    const p = parseInput([fb, vm]);
    assert.equal(p.sources[0].format, "sap-fbl1n");
    assert.equal(p.sources[1].format, "sap-vendors");
    const rec = p.ledger[0];
    assert.equal(rec.cents, 123456);
    assert.equal(dayISO(rec.postDay), "2026-03-15");
    assert.equal(dayISO(rec.payDay), "2026-04-02");
    assert.equal(rec.enteredBy, "apclerk1");
    const r = run([fb, vm]);
    assert.equal(r.tables.vendors[0].vendor, "Granite Arch Test Engineering GmbH");
    assert.equal(r.summary.currency, "EUR");
    assert.equal(r.summary.totalPaid, "EUR 1,234.56");
  });

  test("Sage Intacct AP payments", () => {
    const p = parseInput([fmtFile("sage.csv", "sage-intacct-ap", [{ "Vendor ID": "V-20", "Vendor Name": "Driftwood Test Janitorial", "Bill Number": "DJ-301", "Bill Date": "03/01/2026", "Payment Date": "03/15/2026", "Payment Method": "ACH", "Reference Number": "ACH-77", "Amount Paid": "$2,400.00", Currency: "USD", State: "Cleared" }])]);
    assert.equal(p.sources[0].format, "sage-intacct-ap");
    assert.equal(p.ledger[0].cents, 240000);
    assert.equal(p.ledger[0].vendorIdN, "V20");
  });

  test("generic ledger with the documented header set is recognised with high confidence", () => {
    const d = detectFile(ledger([pay()]));
    assert.equal(d.format, "generic-ledger");
    assert.equal(d.confidence, "high");
  });

  test("QuickBooks Vendor Contact List: Account # is not read as a bank account", () => {
    const f = fmtFile("qbv.csv", "qbo-vendors", [{ Vendor: "Kestrel Mail Test Services", "Company name": "Kestrel Mail Test Services", "Street Address": "PO Box 4471", City: "Springfield", State: "IL", ZIP: "62790", Country: "US", Phone: "", Email: "billing@test.darknode.ai", "Account #": "778899001122", "Tax ID": "91-7654321", "1099 Tracking": "Yes", "Open Balance": "0.00" }]);
    const p = parseInput([f]);
    assert.equal(p.sources[0].format, "qbo-vendors");
    assert.equal(p.vendors[0].bankH, "");
    assert.equal(p.vendors[0].tax4, "****4321");
    assert.ok(!JSON.stringify(p).includes("7654321"));
  });

  test("SAP vendor master: bank key, IBAN and blocks", () => {
    const p = parseInput([fmtFile("lfa1.csv", "sap-vendors", [{ Vendor: "100109", "Name 1": "Ironbridge Test Freight Ltd", Street: "1 Dock Road", City: "Springfield", "Postal Code": "62701", Country: "US", "Tax Number 1": "941234567", "Bank Key": "021000021", "Bank Account": "7712345678", IBAN: "", "Created On": "03/01/2024", "Created By": "VMDATA", "Central posting block": "", "Payment block": "A" }])]);
    const v = p.vendors[0];
    assert.ok(v.paymentBlock && !v.postingBlock);
    assert.ok(v.abaCheck.ok);
    assert.equal(v.bank4, "****5678");
  });

  test("generic vendor master and employee roster (exact header sets)", () => {
    const p = parseInput([vmaster([{ vendor_id: "V1", name: "Amberfield Test Packaging", tax_id: "12-3456789", created_date: "2026-01-02" }]), roster([{ employee_id: "E1", name: "Dana Test", email: "dana.test@test.darknode.ai" }])]);
    assert.deepEqual(p.sources.map((s) => [s.format, s.role, s.confidence]), [["generic-vendors", "vendors", "high"], ["generic-employees", "employees", "high"]]);
  });

  test("BambooHR-style roster: first and last name aliases build the name", () => {
    const text = "Employee #,First Name,Last Name,Address Line 1,City,Zip Code,Home Phone,Work Email,Hire Date,Termination Date,Department\n12,Avery,Test,10 Elm Court,Springfield,62800,555-0110,avery.test@test.darknode.ai,2020-01-10,,Finance\n";
    const p = parseInput([{ name: "bamboo.csv", text }]);
    assert.equal(p.sources[0].role, "employees");
    assert.equal(p.employees[0].name, "Avery Test");
  });

  test("unrecognised layout is low confidence; a column override maps it", () => {
    const text = "Payee Name,Bill Ref,Paid On,Sum\nNorthwind Parts Test Co,A-1,2026-03-01,100.00\n";
    const d = detectFile({ name: "x.csv", text });
    assert.equal(d.confidence, "low");
    const p = parseInput([{ name: "x.csv", text }], { roles: { "x.csv": "ledger" }, columns: { "x.csv": { vendor: "Payee Name", invoice: "Bill Ref", paymentDate: "Paid On", amount: "Sum" } } });
    assert.equal(p.ledger.length, 1);
    assert.equal(p.ledger[0].vendor, "Northwind Parts Test Co");
    const p2 = parseInput([{ name: "x.csv", text }], { roles: { "x.csv": "ledger" } });
    assert.ok(p2.skipped.some((s) => /Amount/.test(s.reason)), "no amount mapped -> file skipped with reason");
  });

  test("empty and JSON files are skipped with reasons", () => {
    const p = parseInput([{ name: "a.csv", text: "" }, { name: "b.json", text: '[{"a":1}]' }]);
    assert.equal(p.skipped.length, 2);
  });
});

group("apforensics: normalisation and arithmetic", () => {
  test("invoice normalisation", () => {
    assert.equal(normInvoice("INV-004512"), "4512");
    assert.equal(normInvoice("#4512"), "4512");
    assert.equal(normInvoice("inv 00045-12"), "4512");
    assert.equal(normInvoice("Invoice No. 77"), "77");
    assert.equal(normInvoice("A-0012"), "A0012");
    assert.equal(normInvoice("0000"), "");
  });
  test("toCents handles symbols, separators, negatives and rounding", () => {
    assert.equal(toCents("$1,234.56"), 123456);
    assert.equal(toCents("(1,234.56)"), -123456);
    assert.equal(toCents("1.234,56-"), -123456);
    assert.equal(toCents("1 234,5 EUR"), 123450);
    assert.equal(toCents("-0.10"), -10);
    assert.equal(toCents("12.345"), 1235);
    assert.equal(toCents("abc"), null);
    assert.equal(toCents(""), null);
  });
  test("cents arithmetic is exact (no float drift)", () => {
    const rows = [pay({ invoice_number: "1", amount: "0.10" }), pay({ invoice_number: "2", amount: "0.20" }), pay({ invoice_number: "3", amount: "0.70" })];
    const r = run([ledger(rows)]);
    assert.equal(r.summary.totalPaidCents, 100);
    assert.equal(r.summary.totalPaid, "USD 1.00");
    assert.equal(fmtMoney(123456789, "USD"), "USD 1,234,567.89");
  });
  test("dates: ISO, US, day-first when unambiguous, dotted SAP, month names, invalid", () => {
    assert.equal(dayISO(parseDay("2026-03-04")), "2026-03-04");
    assert.equal(dayISO(parseDay("03/04/2026")), "2026-03-04");
    assert.equal(dayISO(parseDay("03/04/2026", "dmy")), "2026-04-03");
    assert.equal(dayISO(parseDay("25/04/2026")), "2026-04-25");
    assert.equal(dayISO(parseDay("04.03.2026")), "2026-03-04");
    assert.equal(dayISO(parseDay("Mar 4, 2026")), "2026-03-04");
    assert.equal(dayISO(parseDay("4 Mar 2026")), "2026-03-04");
    assert.equal(parseDay("02/30/2026"), null);
  });
  test("vendor name normalisation, edit distance and transposition", () => {
    assert.equal(normName("Bluegill Fasteners Test, Ltd."), normName("BLUEGILL FASTENERS TEST LIMITED"));
    assert.equal(normName("Acme & Sons Test Inc"), "acme and sons test");
    assert.ok(isTransposition("58213", "58123"));
    assert.ok(!isTransposition("58213", "58231x"));
    assert.equal(editDistance1("1001", "1002"), 1);
    assert.equal(editDistance1("1001", "10010"), 1);
    assert.equal(editDistance1("1001", "2002"), 2);
  });
  test("transaction kinds", () => {
    assert.deepEqual(["Bill", "Bill Payment (Check)", "Vendor Credit", "KR", "KZ", "Expense", "Journal Entry", ""].map(kindOf), ["bill", "payment", "exclude", "bill", "payment", "expense", "exclude", "generic"]);
  });
  test("robust z-score uses median and MAD", () => {
    const z = robustZ([100, 110, 90, 105, 95, 1000]);
    assert.ok(z.z[5] > 3 && Math.abs(z.z[0]) < 1);
  });
});

group("apforensics: duplicates", () => {
  test("exact duplicate: same vendor, normalized invoice and amount -> high, confirmed", () => {
    const r = run([ledger([pay({ invoice_number: "INV-004512" }), pay({ invoice_number: "4512", payment_date: "2026-04-01" }), pay({ invoice_number: "4513", amount: "99.00" })])]);
    const f = hit(r, "dup_exact");
    assert.ok(f);
    assert.equal(f.severity, "high");
    assert.equal(f.confidence, "confirmed");
    assert.equal(f.evidenceCount, 1);
    assert.equal(r.summary.potentialDuplicateCents, 123456, "the later payment is at risk");
  });
  test("exact duplicate negative: different amount or vendor", () => {
    const r = run([ledger([pay(), pay({ amount: "1,234.57" }), pay({ vendor: "Other Test Co", vendor_id: "V200" })])]);
    assert.ok(!hit(r, "dup_exact"));
  });
  test("transposed invoice digits within the window -> likely, counted at risk", () => {
    const r = run([ledger([pay({ invoice_number: "58213" }), pay({ invoice_number: "58123", invoice_date: "2026-03-11" })])]);
    const f = hit(r, "dup_transposed");
    assert.ok(f && f.confidence === "likely");
    assert.equal(r.summary.potentialDuplicateCents, 123456);
  });
  test("transposed outside the duplicate window is silent", () => {
    const r = run([ledger([pay({ invoice_number: "58213" }), pay({ invoice_number: "58123", invoice_date: "2026-05-11" })])]);
    assert.ok(!hit(r, "dup_transposed"));
    const r2 = run([ledger([pay({ invoice_number: "58213" }), pay({ invoice_number: "58123", invoice_date: "2026-05-11" })])], { dupWindowDays: 90 });
    assert.ok(hit(r2, "dup_transposed"), "window is a threshold");
  });
  test("one character apart -> review and not counted in the at-risk total", () => {
    const r = run([ledger([pay({ invoice_number: "7001" }), pay({ invoice_number: "7002", invoice_date: "2026-03-09" })])]);
    const f = hit(r, "dup_one_edit");
    assert.ok(f && f.confidence === "review");
    assert.equal(r.summary.potentialDuplicateCents, 0);
  });
  test("same invoice paid under two vendor records with matching names", () => {
    const r = run([ledger([pay({ vendor: "Bluegill Fasteners Test Ltd", vendor_id: "V1" }), pay({ vendor: "Bluegill Fasteners Test Limited", vendor_id: "V2", invoice_date: "2026-03-05" }),
      pay({ vendor: "Unrelated Test Co", vendor_id: "V3", invoice_date: "2026-03-06" })])]);
    const f = hit(r, "dup_cross_vendor");
    assert.ok(f);
    assert.equal(f.evidenceCount, 1, "the unrelated vendor is not paired");
  });
  test("recovery worksheet lists each pair with the vendor's reason", () => {
    const r = run([ledger([pay({ invoice_number: "INV-1" }), pay({ invoice_number: "1", payment_date: "2026-04-01" })])]);
    const csv = recoveryToCsv(r.tables.duplicates);
    assert.equal(csv.split("\n")[0], RECOVERY_COLS.join(","));
    assert.ok(/1,234.56/.test(csv) && /same vendor, invoice number/.test(csv));
  });
});

group("apforensics: vendor master and employees", () => {
  const V = (o) => ({ vendor_id: "V1", name: "Harrow Lane Supply Test LLC", address: "12 Orchard Lane", city: "Springfield", postal_code: "62704", country: "US", tax_id: "94-1112223", bank_account: "7790031144", routing: "021000021", created_date: "2024-01-05", created_by: "vmdata", phone: "555-0100", ...o });
  const E = (o) => ({ employee_id: "E7", name: "Dana Test", address: "9 Elm Court", city: "Springfield", postal_code: "62800", phone: "555-0177", email: "dana.test@test.darknode.ai", bank_account: "6600001111", routing: "011000015", department: "Accounts Payable", hire_date: "2021-02-01", ...o });

  test("duplicate vendor records by tax id", () => {
    const r = run([vmaster([V(), V({ vendor_id: "V2", name: "Harrow Lane Supplies Test", bank_account: "7700000000" })])]);
    const f = hit(r, "vendor_dupes");
    assert.ok(f && f.evidenceCount === 2 && /same tax id/.test(f.evidence[0].matchedOn));
  });
  test("distinct vendors are not grouped", () => {
    const r = run([vmaster([V(), V({ vendor_id: "V2", name: "Other Test Co", tax_id: "94-9998887", bank_account: "7700000000", address: "1 Mill Road", phone: "555-0199" })])]);
    assert.ok(!hit(r, "vendor_dupes"));
  });
  test("vendor sharing a bank account with an employee -> high, likely, IDENTITY asset", () => {
    const r = run([vmaster([V()]), roster([E({ bank_account: "7790031144", routing: "021000021" })])]);
    const f = hit(r, "vendor_employee");
    assert.ok(f && f.severity === "high" && f.confidence === "likely");
    assert.ok(/bank account \*\*\*\*1144/.test(f.evidence[0].matchedOn));
    assert.ok(f.assets.some((a) => a.type === "IDENTITY" && a.name === "dana.test@test.darknode.ai"));
    assert.ok(f.assets.some((a) => a.type === "VENDOR" && a.data.taxIdLast4 === "****2223"));
  });
  test("same account number at a different bank (routing differs) is not a match", () => {
    const r = run([vmaster([V()]), roster([E({ bank_account: "7790031144", routing: "011000015" })])]);
    assert.ok(!hit(r, "vendor_employee"));
  });
  test("address + postal code and phone matches", () => {
    const r = run([vmaster([V()]), roster([E({ address: "12 Orchard Ln.", postal_code: "62704-1234", phone: "(555) 0100" })])]);
    const f = hit(r, "vendor_employee");
    assert.ok(f && /address and postal code/.test(f.evidence[0].matchedOn) && /phone/.test(f.evidence[0].matchedOn));
  });
  test("no roster -> employee check skipped with reason", () => {
    assert.equal(skippedFor(run([vmaster([V()])]), "vendor_employee").length, 1);
  });
  test("new vendor paid within the window; exactly at the window is silent", () => {
    const vm = vmaster([V({ created_date: "2026-03-17" })]);
    const r = run([vm, ledger([pay({ vendor_id: "V1", vendor: "Harrow Lane Supply Test LLC", payment_date: "2026-03-20" })])]);
    assert.equal(hit(r, "new_vendor_paid").evidence[0].days, 3);
    const r2 = run([vmaster([V({ created_date: "2026-03-13" })]), ledger([pay({ vendor_id: "V1", payment_date: "2026-03-20" })])]);
    assert.ok(!hit(r2, "new_vendor_paid"));
  });
  test("payments after inactivation; before is silent", () => {
    const r = run([vmaster([V({ inactivated_date: "2026-03-10" })]), ledger([pay({ vendor_id: "V1", payment_date: "2026-03-20" })])]);
    assert.ok(hit(r, "paid_after_inactivation"));
    const r2 = run([vmaster([V({ inactivated_date: "2026-03-25" })]), ledger([pay({ vendor_id: "V1", payment_date: "2026-03-20" })])]);
    assert.ok(!hit(r2, "paid_after_inactivation"));
  });
  test("payment block on a paid vendor (SAP master)", () => {
    const vm = fmtFile("lfa1.csv", "sap-vendors", [{ Vendor: "V1", "Name 1": "Ironbridge Test Freight", "Payment block": "A", "Created On": "01/01/2024" }, { Vendor: "V2", "Name 1": "Other Test Freight", "Payment block": "", "Created On": "01/01/2024" }]);
    const r = run([vm, ledger([pay({ vendor_id: "V1" }), pay({ vendor_id: "V2", invoice_number: "9" })])]);
    const f = hit(r, "blocked_vendor_paid");
    assert.ok(f && f.evidenceCount === 1 && /Ironbridge/.test(f.evidence[0].vendor));
  });
  test("P.O. box with no phone flagged; with a phone silent", () => {
    const r = run([vmaster([V({ address: "PO Box 4471", phone: "" }), V({ vendor_id: "V2", name: "Postfach Test GmbH", address: "Postfach 1234", phone: "555-0111", tax_id: "", bank_account: "" })])]);
    const f = hit(r, "po_box");
    assert.equal(f.evidenceCount, 1);
    assert.equal(f.evidence[0].phone, "blank");
  });
  test("bank checksum: invalid ABA and IBAN flagged, valid ones silent", () => {
    const r = run([vmaster([V({ routing: "021000022" }), V({ vendor_id: "V2", name: "Granite Arch Test", tax_id: "", bank_account: "", routing: "", iban: "DE89370400440532013001", country: "DE", address: "a", phone: "1" }),
      V({ vendor_id: "V3", name: "Good Test Co", tax_id: "", bank_account: "", routing: "", iban: "DE89370400440532013000", country: "DE", address: "b", phone: "2" })])]);
    const f = hit(r, "bank_checksum");
    assert.equal(f.evidenceCount, 2);
    assert.equal(f.confidence, "confirmed");
    assert.ok(!JSON.stringify(r).includes("0532013001"), "IBAN is masked");
  });
  test("segregation of duties: vendor creator entered its invoices; self-approval", () => {
    const vm = vmaster([V({ created_by: "CORP\\DTEST" })]);
    const r = run([vm, ledger([pay({ vendor_id: "V1", entered_by: "dtest@test.darknode.ai", approver: "mrivera" }), pay({ vendor_id: "V1", invoice_number: "2", entered_by: "apclerk1", approver: "apclerk1" })])]);
    assert.ok(hit(r, "sod_vendor_creator"));
    assert.equal(hit(r, "sod_self_approval").evidenceCount, 1);
    assert.ok(hit(r, "sod_vendor_creator").controls.some((c) => c.framework === "ISO27001" && c.id === "A.5.3"));
  });
  test("segregation of duties skipped when the ledger has no user columns", () => {
    const text = "vendor,vendor_id,invoice_number,payment_date,amount\nHarrow Lane Supply Test LLC,V1,1,2026-03-20,10.00\n";
    const r = run([vmaster([V()]), { name: "l.csv", text }]);
    assert.equal(skippedFor(r, "sod_vendor_creator").length, 1);
    assert.equal(skippedFor(r, "sod_self_approval").length, 1);
  });
});

group("apforensics: patterns and statistics", () => {
  test("split invoices: needs a threshold; positive cluster; negative when the sum stays under", () => {
    const rows = [pay({ invoice_number: "1", amount: "4,800.00", invoice_date: "2026-03-02" }), pay({ invoice_number: "2", amount: "3,900.00", invoice_date: "2026-03-03" }), pay({ invoice_number: "3", amount: "2,700.00", invoice_date: "2026-03-05" })];
    assert.equal(skippedFor(run([ledger(rows)]), "split_invoices").length, 1, "blank threshold skips");
    const f = hit(run([ledger(rows)], { approvalThreshold: 10000 }), "split_invoices");
    assert.ok(f && f.evidence[0].count === 3 && f.evidence[0].total === "USD 11,400.00");
    assert.ok(!hit(run([ledger(rows)], { approvalThreshold: 12000 }), "split_invoices"));
    assert.ok(!hit(run([ledger(rows)], { approvalThreshold: 10000, splitDays: 0 }), "split_invoices"), "split window is a threshold");
  });
  test("histogram spike just under the threshold", () => {
    const rows = [];
    for (let i = 0; i < 8; i++) rows.push(pay({ vendor_id: "V" + i, vendor: "Test Vendor " + i, invoice_number: "S" + i, amount: (9500 + i * 10) + ".00", invoice_date: addDays("2026-01-05", i * 9) }));
    rows.push(pay({ vendor_id: "VX", invoice_number: "X1", amount: "8,500.00" }));
    assert.ok(hit(run([ledger(rows)], { approvalThreshold: 10000 }), "threshold_spike"));
    assert.ok(!hit(run([ledger(rows.slice(0, 4))], { approvalThreshold: 10000 }), "threshold_spike"), "fewer than 5 is silent");
  });
  test("round-amount bias per vendor", () => {
    const rows = [];
    for (let i = 0; i < 12; i++) rows.push(pay({ vendor_id: "R1", vendor: "Copperleaf Test Consulting", invoice_number: "C" + (i * 37), amount: (1000 + i * 500) + ".00", invoice_date: addDays("2025-01-05", i * 30) }));
    for (let i = 0; i < 40; i++) rows.push(pay({ vendor_id: "N" + (i % 4), vendor: "Other " + (i % 4), invoice_number: "N" + i * 13, amount: (123 + i * 7) + "." + String(10 + i), invoice_date: addDays("2025-01-05", i * 9) }));
    const f = hit(run([ledger(rows)]), "round_amounts");
    assert.ok(f && f.evidenceCount === 1 && /Copperleaf/.test(f.evidence[0].vendor));
    assert.ok(!hit(run([ledger(rows)], { minVendorInvoices: 13 }), "round_amounts"), "minimum invoices is a threshold");
  });
  test("sequential invoice numbers over a long period; short span is silent", () => {
    const rows = [];
    for (let i = 0; i < 12; i++) rows.push(pay({ vendor_id: "S1", vendor: "Saltmarsh Test Logistics", invoice_number: "SL-" + (1001 + i), amount: (300 + i * 17) + ".45", invoice_date: addDays("2025-01-06", i * 30) }));
    assert.ok(hit(run([ledger(rows)]), "sequential_invoices"));
    const short = rows.map((r, i) => ({ ...r, invoice_date: addDays("2025-01-06", i * 5) }));
    assert.ok(!hit(run([ledger(short)]), "sequential_invoices"));
  });
  test("Benford refuses small samples and conforming data is not flagged", () => {
    const few = [];
    for (let i = 0; i < 50; i++) few.push(1000 + i * 37);
    assert.ok(benfordTest(few, "first", 300).refused);
    const r = run([ledger(few.map((c, i) => pay({ invoice_number: "B" + i, amount: (c / 100).toFixed(2) })))]);
    assert.equal(skippedFor(r, "benford").length, 1);
    // Exact Benford proportions (1000 amounts) conform.
    const conf = [];
    for (let d = 1; d <= 9; d++) { const n = Math.round(1000 * Math.log10(1 + 1 / d)); for (let k = 0; k < n; k++) conf.push(d * 10000 + k + 1); }
    const t = benfordTest(conf, "first", 300);
    assert.ok(!t.refused && !t.nonconforming && t.conformity === "close conformity");
  });
  test("Benford flags a ledger dominated by one leading digit", () => {
    const rows = [];
    for (let i = 0; i < 400; i++) rows.push(pay({ vendor_id: "B" + (i % 40), vendor: "Vendor " + (i % 40), invoice_number: "BF" + i, amount: (i % 3 === 0 ? 4000 + i : 4500 + i) + ".13", invoice_date: addDays("2025-01-01", i) }));
    const f = hit(run([ledger(rows)]), "benford_ledger");
    assert.ok(f && f.confidence === "review" && /400 amounts/.test(f.description));
  });
  test("first-two-digit test is used once the larger minimum is met", () => {
    const amts = [];
    for (let d = 10; d <= 99; d++) { const n = Math.round(2000 * Math.log10(1 + 1 / d)); for (let k = 0; k < n; k++) amts.push(d * 1000 + k); }
    const t = benfordTest(amts, "firstTwo", 1000);
    assert.equal(t.rows.length, 90);
    assert.ok(!t.nonconforming);
    assert.ok(benfordTest(amts.slice(0, 500), "firstTwo", 1000).refused);
  });
  test("weekend postings flagged; weekdays silent", () => {
    const r = run([ledger([pay({ payment_date: "2026-03-21" }), pay({ invoice_number: "2", payment_date: "2026-03-23" })])]);
    const f = hit(r, "weekend_postings");
    assert.equal(f.evidenceCount, 1);
    assert.equal(f.evidence[0].day, "Saturday");
  });
  test("holiday check with the reference envelope, and skipped without it", () => {
    const env = { version: "2026-10", verifyWithCounsel: true, data: [{ date: "2026-07-03", name: "Independence Day (observed)" }, { date: "2025-12-25", name: "Christmas Day" }] };
    const files = [ledger([pay({ payment_date: "2026-07-03" }), pay({ invoice_number: "2", payment_date: "2026-07-06" }), pay({ invoice_number: "3", payment_date: "2031-01-02" })])];
    const r = run(files, { holidays: env });
    const f = hit(r, "holiday_postings");
    assert.equal(f.evidenceCount, 1);
    assert.ok(/verify with counsel/.test(f.description));
    assert.ok(skippedFor(r, "holiday_postings").some((s) => /outside the holiday reference coverage/.test(s.reason)));
    const r2 = run(files);
    assert.ok(!hit(r2, "holiday_postings"));
    assert.ok(skippedFor(r2, "holiday_postings").some((s) => /us-holidays\.json/.test(s.reason)));
    assert.ok(hit(run(files, { holidays: ["2026-07-03"] }), "holiday_postings"), "a plain date list also works");
  });
  test("missing PO / invoice number only when the column exists", () => {
    const r = run([ledger([pay({ po_number: "PO-1" }), pay({ invoice_number: "", po_number: "", amount: "50.00" })])]);
    assert.equal(hit(r, "missing_po").evidenceCount, 1);
    assert.equal(hit(r, "missing_invoice").evidenceCount, 1);
    const text = "vendor,invoice_number,payment_date,amount\nA Test Co,1,2026-03-01,10.00\n";
    assert.equal(skippedFor(run([{ name: "n.csv", text }]), "missing_po").length, 1);
  });
  test("monthly spend spike against the vendor's own history", () => {
    const rows = [];
    for (let m = 1; m <= 9; m++) rows.push(pay({ vendor_id: "L1", vendor: "Larkspur Test Facilities", invoice_number: "LF" + m * 13, amount: (m === 8 ? "38,125.00" : (1900 + m * 20) + ".00"), invoice_date: "2026-0" + m + "-15" }));
    const f = hit(run([ledger(rows)]), "spend_spike");
    assert.ok(f && f.evidenceCount === 1 && f.evidence[0].month === "2026-08");
    assert.equal(skippedFor(run([ledger(rows.slice(0, 5))]), "spend_spike").length, 1, "under 6 months is skipped");
    assert.ok(!hit(run([ledger(rows)], { spikeZ: 1000 }), "spend_spike"), "z threshold is editable");
  });
});

group("apforensics: output contract", () => {
  const ex = exampleDataset();
  const r = analyze(ex.files, { ...ex.opts, now: ex.now });

  test("example: planted patterns are found", () => {
    const f = (id) => hit(r, id);
    assert.equal(f("dup_exact").evidenceCount, 3);
    assert.equal(f("dup_transposed").evidenceCount, 1);
    assert.ok(f("vendor_employee").evidence.some((e) => /Vendor C/.test(e.vendor)));
    assert.ok(f("split_invoices").evidence.some((e) => /Vendor D/.test(e.vendor)));
    assert.ok(f("new_vendor_paid").evidence.some((e) => /Vendor E/.test(e.vendor) && e.days === 3));
    assert.ok(r.summary.rows >= 750 && r.summary.rows <= 900);
    assert.ok(ex.files[2].text.includes("@test.darknode.ai") && !/contoso|example\.com/i.test(ex.files.map((x) => x.text).join("")));
  });
  test("masking: no full bank account, IBAN or tax id in the output", () => {
    const out = JSON.stringify(r);
    const vm = ex.files[1].text.split("\n").slice(1).filter(Boolean).map((l) => l.split(","));
    for (const cells of vm) for (const i of [6, 8, 9]) if (cells[i] && cells[i].length > 4) assert.ok(!out.includes(cells[i]), "leaked " + i + ": " + cells[i]);
    const em = ex.files[2].text.split("\n").slice(1).filter(Boolean).map((l) => l.split(","));
    for (const cells of em) assert.ok(!out.includes(cells[7]), "leaked employee account");
  });
  test("analyze is deterministic (byte-identical JSON)", () => {
    assert.equal(JSON.stringify(analyze(ex.files, { ...ex.opts, now: ex.now })), JSON.stringify(r));
  });
  test("every finding has controls, a confidence class, capped evidence and the full count", () => {
    for (const f of r.findings) {
      assert.ok(f.controls.length >= 1 && ["confirmed", "likely", "review"].includes(f.confidence) && f.recommendation);
      assert.ok(f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length);
      assert.ok(!/\bfraud\b/i.test(f.title));
    }
  });
  test("VENDOR assets carry legalName, taxIdLast4, totalPaid and flags", () => {
    const a = hit(r, "dup_exact").assets[0];
    assert.equal(a.type, "VENDOR");
    assert.ok("legalName" in a.data && "taxIdLast4" in a.data && "totalPaid" in a.data && Array.isArray(a.data.flags));
  });
  test("summary: potential duplicates equals the at-risk pairs", () => {
    const sum = r.tables.duplicates.reduce((a, d) => a + d.atRiskCents, 0);
    assert.equal(r.summary.potentialDuplicateCents, sum);
    assert.ok(r.summary.flaggedVendors > 0 && r.summary.flaggedVendors <= r.summary.vendors);
  });
  test("tables: vendors, duplicates, benford, monthly", () => {
    assert.ok(r.tables.vendors.length && r.tables.duplicates.length);
    assert.equal(r.tables.benford.rows.length, 9);
    assert.equal(r.tables.monthly.rows[0].totals.length, r.tables.monthly.months.length);
  });
  test("progress callback is called", () => {
    const calls = [];
    analyze(ex.files, ex.opts, { progress: (i, n, l) => calls.push(l) });
    assert.ok(calls.length >= 2 && calls.includes("done"));
  });
  test("empty input yields no findings and reports the skipped ledger", () => {
    const e = analyze([]);
    assert.equal(e.findings.length, 0);
    assert.ok(e.skipped.some((s) => s.check === "ledger"));
  });
  test("selfTest passes", () => {
    const s = selfTest();
    assert.ok(s.pass, "failed: " + s.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
  test("CSV serialisers have fixed header rows", () => {
    assert.equal(findingsToCsv(r.findings).split("\n")[0], "severity,confidence,category,title,description,recommendation,controls,evidenceCount,assets");
    assert.equal(findingsToCsv([]).trim(), "severity,confidence,category,title,description,recommendation,controls,evidenceCount,assets");
    assert.equal(vendorsToCsv(r.tables.vendors).split("\n")[0], VENDOR_COLS.join(","));
    assert.ok(/AP Forensics summary/.test(summaryText(r)));
  });
  test("defaults: approval threshold ships blank, tool id fixed", () => {
    assert.equal(DEFAULTS.approvalThreshold, null);
    assert.equal(TOOL_ID, "apforensics");
    assert.equal(classifyHeaders(FORMATS["sap-fbl1n"].headers).confidence, "high");
  });
});
