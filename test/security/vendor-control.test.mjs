// Vendor / payee bank-change control engine tests (public/js/finsec/vendor-engine.js):
// bank-detail validators + the deterministic change-control state machine. Mirrors the
// in-engine selfTest and adds focused assertions.

import { test, assert, group } from "../harness.mjs";
import {
  validateIBAN, validateABA, validateBIC, validateBank, bankKey, bankLabel,
  createVendor, proposeChange, recordCallback, approveChange, rejectChange,
  refresh, canPay, screenFlags, markPaid, selfTest, HOLD_HOURS, WATCH_DAYS, toSinkFindings,
} from "../../public/js/finsec/vendor-engine.js";
import { checkSinkFindings } from "./sink-check.mjs";

group("vendor: engine self-test", () => {
  test("all in-engine self-test checks pass", () => {
    const { pass, results } = selfTest();
    assert.ok(pass, "self-test failures: " + results.filter((r) => !r.pass).map((r) => r.name).join(", "));
  });
});

group("vendor: bank-detail validators", () => {
  test("IBAN mod-97 accepts real, rejects tampered", () => {
    assert.ok(validateIBAN("GB82 WEST 1234 5698 7654 32").ok);
    assert.ok(!validateIBAN("GB82 WEST 1234 5698 7654 33").ok);
  });
  test("IBAN length enforced per country", () => {
    assert.ok(!validateIBAN("DE8937040044").ok);
  });
  test("ABA routing checksum", () => {
    assert.ok(validateABA("111000025").ok);
    assert.ok(!validateABA("111000026").ok);
    assert.ok(!validateABA("1110000").ok);
  });
  test("BIC format 8 and 11", () => {
    assert.ok(validateBIC("BOFAUS3N").ok);
    assert.ok(validateBIC("BOFAUS3NXXX").ok);
    assert.ok(!validateBIC("BOFA").ok);
  });
  test("validateBank aggregates errors", () => {
    assert.ok(validateBank({ kind: "aba", account: "123456789", routing: "021000021" }).ok);
    const bad = validateBank({ kind: "aba", account: "x", routing: "000" });
    assert.ok(!bad.ok && bad.errors.length === 2);
  });
  test("bankKey distinguishes accounts, bankLabel masks", () => {
    assert.notEqual(bankKey({ kind: "aba", account: "123456789", routing: "021000021" }), bankKey({ kind: "aba", account: "987654321", routing: "021000021" }));
    assert.ok(bankLabel({ kind: "aba", account: "123456789", routing: "021000021" }).includes("6789"));
  });
});

group("vendor: change control", () => {
  const t0 = 1_700_000_000_000;
  const H = HOLD_HOURS * 3600000;
  const mk = () => createVendor({ id: "v", name: "Acme", bank: { kind: "aba", account: "123456789", routing: "021000021" }, by: "alice", at: t0 });

  test("new vendor starts pending with an opening change, no live bank", () => {
    const v = mk();
    assert.equal(v.status, "pending");
    assert.equal(v.bank, null);
    assert.ok(v.change && v.change.by === "alice");
  });

  test("approval requires a recorded callback", () => {
    const v = mk();
    assert.ok(!approveChange(v, { by: "bob", at: t0 + 1 }).ok);
    recordCallback(v, { by: "bob", note: "called known number", phone: "+1-555-0100", at: t0 + 2 });
    assert.ok(approveChange(v, { by: "bob", at: t0 + 3 }).ok);
  });

  test("the callback gate has substance: empty caller or number is rejected", () => {
    const v = mk();
    // an empty callback must NOT satisfy the gate (anti-BEC)
    assert.ok(!recordCallback(v, {}).ok, "empty callback rejected");
    assert.ok(!recordCallback(v, { by: "bob" }).ok, "caller without a number rejected");
    assert.ok(!recordCallback(v, { phone: "+1-555-0100" }).ok, "number without a caller rejected");
    // the change is still pending and unapprovable while the callback is unrecorded
    assert.ok(!v.change.callback, "no callback recorded");
    assert.ok(!approveChange(v, { by: "bob", at: t0 + 2 }).ok, "cannot approve without a real callback");
    // a complete callback unlocks approval
    assert.ok(recordCallback(v, { by: "bob", phone: "+1-555-0100", note: "verified", at: t0 + 3 }).ok);
    assert.ok(approveChange(v, { by: "bob", at: t0 + 4 }).ok);
  });

  test("approver must differ from proposer (separation of duties)", () => {
    const v = mk();
    recordCallback(v, { by: "alice", note: "n", phone: "+1-555-0100", at: t0 + 1 });
    assert.ok(!approveChange(v, { by: "alice", at: t0 + 2 }).ok);
    assert.ok(approveChange(v, { by: "bob", at: t0 + 3 }).ok);
  });

  test("approved account is held then becomes active after the cool-down", () => {
    const v = mk();
    recordCallback(v, { by: "bob", note: "n", phone: "+1-555-0100", at: t0 + 1 });
    approveChange(v, { by: "bob", at: t0 + 2 });
    assert.equal(v.status, "held");
    assert.ok(!canPay(v, t0 + 3).ok);
    refresh(v, t0 + H + 10);
    assert.equal(v.status, "active");
    assert.ok(canPay(v, t0 + H + 10).ok);
  });

  test("a later bank change archives the old account and re-holds", () => {
    const v = mk();
    recordCallback(v, { by: "bob", note: "n", phone: "+1-555-0100", at: t0 + 1 });
    approveChange(v, { by: "bob", at: t0 + 2 });
    refresh(v, t0 + H + 10);
    assert.ok(proposeChange(v, { bank: { kind: "iban", iban: "DE89370400440532013000" }, by: "alice", at: t0 + H + 11 }).ok);
    assert.ok(!canPay(v, t0 + H + 12).ok); // blocked while pending
    recordCallback(v, { by: "carol", note: "n", phone: "+1-555-0100", at: t0 + H + 13 });
    approveChange(v, { by: "carol", at: t0 + H + 14 });
    assert.equal(v.history.length, 1);
    assert.equal(v.status, "held");
  });

  test("duplicate bank details are rejected", () => {
    const v = mk();
    recordCallback(v, { by: "bob", note: "n", phone: "+1-555-0100", at: t0 + 1 });
    approveChange(v, { by: "bob", at: t0 + 2 });
    refresh(v, t0 + H + 10);
    const r = proposeChange(v, { bank: { kind: "aba", account: "123456789", routing: "021000021" }, by: "alice", at: t0 + H + 11 });
    assert.ok(!r.ok);
  });

  test("reject leaves the live bank unchanged", () => {
    const v = mk();
    recordCallback(v, { by: "bob", note: "n", phone: "+1-555-0100", at: t0 + 1 });
    approveChange(v, { by: "bob", at: t0 + 2 });
    refresh(v, t0 + H + 10);
    const before = bankKey(v.bank);
    proposeChange(v, { bank: { kind: "iban", iban: "DE89370400440532013000" }, by: "alice", at: t0 + H + 11 });
    rejectChange(v, { by: "carol", reason: "could not verify", at: t0 + H + 12 });
    assert.equal(bankKey(v.bank), before);
    assert.equal(v.status, "active");
  });

  test("screen flags: first-payment and recently-changed", () => {
    const v = mk();
    recordCallback(v, { by: "bob", note: "n", phone: "+1-555-0100", at: t0 + 1 });
    approveChange(v, { by: "bob", at: t0 + 2 });
    refresh(v, t0 + H + 10);
    let flags = screenFlags(v, t0 + H + 10).map((f) => f.code);
    assert.ok(flags.includes("first-payment"));
    assert.ok(flags.includes("recently-changed"));
    markPaid(v, t0 + H + 11);
    flags = screenFlags(v, t0 + H + 11).map((f) => f.code);
    assert.ok(!flags.includes("first-payment"));
    // beyond the watch window, recently-changed clears
    flags = screenFlags(v, t0 + WATCH_DAYS * 86400000 + H + 100).map((f) => f.code);
    assert.ok(!flags.includes("recently-changed"));
  });

  test("audit log is append-only and records every transition", () => {
    const v = mk();
    recordCallback(v, { by: "bob", note: "n", phone: "+1-555-0100", at: t0 + 1 });
    approveChange(v, { by: "bob", at: t0 + 2 });
    const actions = v.audit.map((a) => a.action);
    assert.ok(actions.includes("vendor-created"));
    assert.ok(actions.includes("callback-recorded"));
    assert.ok(actions.includes("change-approved"));
  });
});

group("vendor: Security Graph sink mapping", () => {
  const T = Date.UTC(2026, 9, 10, 12, 0, 0), H = 3600000, D = 24 * H;
  const IBAN1 = "GB82 WEST 1234 5698 7654 32", IBAN2 = "DE89 3704 0044 0532 0130 00";
  const live = (id, name, at) => {
    const v = createVendor({ id, name, bank: { kind: "iban", iban: IBAN1 }, by: "clerk", at });
    recordCallback(v, { by: "clerk", phone: "+1 555 0100", at }); approveChange(v, { by: "approver", at });
    return v;
  };
  // One payee mid-change, one live and paid long ago (clean), one new and still held,
  // one awaiting its opening verification; an OFAC hit on the held one.
  const register = () => {
    const changing = live("py_1", "Payee One", T - 60 * D); markPaid(changing, T - 50 * D);
    proposeChange(changing, { bank: { kind: "iban", iban: IBAN2 }, by: "clerk", at: T - H });
    const clean = live("py_2", "Payee Two", T - 90 * D); markPaid(clean, T - 80 * D);
    const held = live("py_3", "Payee Three", T - 2 * H);
    const opening = createVendor({ id: "py_4", name: "Payee Four", bank: { kind: "iban", iban: IBAN2 }, by: "clerk", at: T - H });
    return [changing, clean, held, opening].map((v) => refresh(v, T));
  };
  const sanctions = (v) => (v.name === "Payee Three" ? { code: "ofac", level: "high", text: "OFAC strong match: PAYEE THREE (TEST)" } : null);
  test("required fields, normalised severity, stable ids/titles across runs, sample tagging", () => {
    const a = toSinkFindings(register(), { sanctions, at: T }), b = toSinkFindings(register(), { sanctions, at: T });
    const { items } = checkSinkFindings("payees", a, b, { minFindings: 4 });
    assert.ok(items.some((i) => i.type === "VENDOR" && i.name === "Payee One"));
    assert.deepEqual(a.map((f) => f.title).sort(), [
      "Bank-detail change pending approval: Payee One", "New payee bank details pending verification: Payee Four",
      "OFAC name match on payee: Payee Three", "Payee bank account under BEC watch: Payee Three",
    ]);
    assert.equal(a.find((f) => f.title.startsWith("Bank-detail change")).severity, "high");
    assert.equal(a.find((f) => f.title.startsWith("OFAC")).severity, "high");
    assert.ok(!a.some((f) => f.assets[0].name === "Payee Two"), "a clean, long-paid payee yields nothing");
  });
  test("only masked account labels and no callback phone leave the mapper", () => {
    const s = JSON.stringify(toSinkFindings(register(), { sanctions, at: T }));
    for (const raw of [IBAN1, IBAN2]) assert.ok(!s.includes(raw.replace(/\s/g, "")) && !s.includes(raw), "full IBAN leaked");
    assert.ok(!s.includes("555 0100"), "callback phone leaked");
  });
  test("a second bank change is a new finding, not a merge into the first", () => {
    const [v] = register();
    const first = toSinkFindings([v], { at: T })[0].id;
    recordCallback(v, { by: "clerk", phone: "+1 555 0100", at: T }); approveChange(v, { by: "approver", at: T });
    proposeChange(v, { bank: { kind: "iban", iban: IBAN1 }, by: "clerk", at: T + 2 * D });
    const second = toSinkFindings([v], { at: T + 2 * D }).find((f) => f.title.startsWith("Bank-detail change")).id;
    assert.notEqual(first, second);
  });
});
