// VAULT ledger tests (public/js/vault/ledger.js): the fund-safety invariants that must
// NEVER break. Includes the in-engine self-test, SHA-256 vectors, and seeded property/fuzz
// runs that assert the ledger can never go out of balance, never silently overdraw a
// no-overdraft account, and always detect tampering.

import { test, assert, group } from "../harness.mjs";
import { Ledger, toCents, fmtCents, sha256hex, hashStr, selfTest } from "../../public/js/vault/ledger.js";

// small seeded PRNG so fuzz runs are deterministic + reproducible
function rng(seed) { let s = seed >>> 0; return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 0x100000000; }; }

group("vault: engine self-test", () => {
  test("all self-test checks pass", () => {
    const { pass, results } = selfTest();
    assert.ok(pass, "failures: " + results.filter((r) => !r.pass).map((r) => r.name).join(", "));
  });
});

group("vault: sha-256 known-answer", () => {
  test("empty string", () => assert.equal(sha256hex(new Uint8Array(0)), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  test("abc", () => assert.equal(hashStr("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  test("long message (448-bit boundary)", () => assert.equal(hashStr("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
});

group("vault: money is exact (no floats)", () => {
  test("classic 0.1+0.2 stays exact in cents", () => assert.equal(toCents("0.10") + toCents("0.20"), 30n));
  test("sub-cent rejected", () => assert.throws(() => toCents("1.234")));
  test("trailing sub-cent zeros allowed", () => assert.equal(toCents("1.2300"), 123n));
  test("fmt round-trips random values", () => {
    const r = rng(7);
    for (let i = 0; i < 500; i++) {
      const cents = BigInt(Math.floor(r() * 1e11)) - 50000000000n;
      assert.equal(toCents(fmtCents(cents)), cents, "round-trip " + cents);
    }
  });
});

group("vault: double-entry invariant (fuzz)", () => {
  test("1000 random balanced posts keep the trial balance at zero and the chain intact", () => {
    const r = rng(42);
    const L = new Ledger();
    const accts = ["a", "b", "c", "d", "e"];
    for (const id of accts) L.openAccount({ id, name: id, type: id === "a" ? "equity" : "asset" });
    // seed with opening capital so balances move around
    L.post({ memo: "open", postings: [{ account: "b", side: "debit", amount: "1000000.00" }, { account: "a", side: "credit", amount: "1000000.00" }] });
    for (let i = 0; i < 1000; i++) {
      const from = accts[1 + Math.floor(r() * 4)];
      let to = accts[1 + Math.floor(r() * 4)];
      if (to === from) to = accts[1 + ((accts.indexOf(from)) % 4)];
      const cents = BigInt(1 + Math.floor(r() * 50000));
      // always balanced by construction
      L.post({ memo: "f" + i, postings: [{ account: to, side: "debit", amount: cents }, { account: from, side: "credit", amount: cents }] });
      if (i % 137 === 0) assert.ok(L.trialBalance().balanced, "unbalanced at " + i);
    }
    assert.ok(L.trialBalance().balanced, "final trial balance");
    assert.equal(L.trialBalance().debits, L.trialBalance().credits);
    assert.ok(L.verifyChain().ok, "chain intact after fuzz");
    // sum of all account balances (signed by normal side) must net to zero
    let net = 0n; for (const id of accts) { const a = L.accounts.get(id); const b = L.balance(id); net += a.normal === "debit" ? b.balance : -b.balance; }
    assert.equal(net, 0n, "signed balances net to zero");
  });
});

group("vault: no-overdraft guard never breaks (fuzz)", () => {
  test("500 random approved releases never drive the bank negative", () => {
    const r = rng(99);
    const L = new Ledger({ policy: { minApprovers: 1, dualControl: true } });
    L.openAccount({ id: "bank", type: "asset" });
    L.openAccount({ id: "eq", type: "equity" });
    L.openAccount({ id: "out", type: "clearing" });
    L.post({ memo: "open", postings: [{ account: "bank", side: "debit", amount: "100000.00" }, { account: "eq", side: "credit", amount: "100000.00" }] });
    for (let i = 0; i < 500; i++) {
      const cents = BigInt(1 + Math.floor(r() * 2000000)); // up to $20k, often exceeding balance
      const id = "t" + i;
      L.createTransfer({ id, from: "bank", to: "out", amount: cents, by: "alice", payee: "P" + (i % 9) });
      L.approve(id, "bob");
      let released = false;
      try { L.release(id, "carol"); released = true; } catch (_) { /* refused when insufficient */ }
      // invariant: bank balance is NEVER negative, whether or not the release went through
      assert.ok(L.balance("bank").balance >= 0n, "bank went negative at i=" + i + " bal=" + L.balance("bank").balance);
      if (released) assert.ok(L.transfers.get(id).status === "released");
    }
    assert.ok(L.verifyChain().ok);
    assert.ok(L.trialBalance().balanced);
  });
});

group("vault: tamper detection (fuzz)", () => {
  test("mutating any committed amount breaks the chain", () => {
    const r = rng(5);
    const L2 = new Ledger();
    L2.openAccount({ id: "x", type: "asset" }); L2.openAccount({ id: "y", type: "equity" });
    for (let i = 0; i < 40; i++) { const c = BigInt(1 + Math.floor(r() * 1000)); L2.post({ memo: "m" + i, postings: [{ account: "x", side: "debit", amount: c }, { account: "y", side: "credit", amount: c }] }); }
    assert.ok(L2.verifyChain().ok, "clean chain verifies");
    const idx = 17;
    L2.journal[idx].postings[0].amount += 1n;
    const v = L2.verifyChain();
    assert.ok(!v.ok, "tamper detected");
    assert.equal(v.brokenAt, idx, "breaks exactly at the tampered entry");
  });
});

group("vault: segregation of duties + idempotency", () => {
  test("initiator can never approve own transfer", () => {
    const L = new Ledger({ policy: { minApprovers: 1, dualControl: true } });
    L.openAccount({ id: "bank", type: "asset" }); L.openAccount({ id: "eq", type: "equity" }); L.openAccount({ id: "out", type: "clearing" });
    L.post({ postings: [{ account: "bank", side: "debit", amount: "500.00" }, { account: "eq", side: "credit", amount: "500.00" }] });
    L.createTransfer({ id: "t", from: "bank", to: "out", amount: "100.00", by: "alice" });
    assert.throws(() => L.approve("t", "alice"));
  });
  test("initiator can never release own transfer", () => {
    const L = new Ledger({ policy: { minApprovers: 1, dualControl: true } });
    L.openAccount({ id: "bank", type: "asset" }); L.openAccount({ id: "eq", type: "equity" }); L.openAccount({ id: "out", type: "clearing" });
    L.post({ postings: [{ account: "bank", side: "debit", amount: "500.00" }, { account: "eq", side: "credit", amount: "500.00" }] });
    L.createTransfer({ id: "t", from: "bank", to: "out", amount: "100.00", by: "alice" });
    L.approve("t", "bob");
    assert.throws(() => L.release("t", "alice"), "initiator cannot release own transfer");
    L.release("t", "carol");
    assert.equal(L.transfers.get("t").status, "released");
  });
  test("released transfer cannot double-post (idempotent)", () => {
    const L = new Ledger({ policy: { minApprovers: 1, dualControl: true } });
    L.openAccount({ id: "bank", type: "asset" }); L.openAccount({ id: "eq", type: "equity" }); L.openAccount({ id: "out", type: "clearing" });
    L.post({ postings: [{ account: "bank", side: "debit", amount: "500.00" }, { account: "eq", side: "credit", amount: "500.00" }] });
    L.createTransfer({ id: "t", from: "bank", to: "out", amount: "100.00", by: "alice" });
    L.approve("t", "bob"); L.release("t", "carol");
    assert.throws(() => L.release("t", "carol"), "re-release must be refused");
  });
});

group("vault: movement screen", () => {
  test("a payee seen only on a rejected transfer is still first-time", () => {
    const L = new Ledger();
    L.openAccount({ id: "bank", type: "asset" }); L.openAccount({ id: "c", type: "clearing" });
    L.createTransfer({ id: "t1", from: "bank", to: "c", amount: "5", by: "u1", payee: "Payee X" });
    L.reject("t1", "u2", "suspicious");
    const t2 = L.createTransfer({ id: "t2", from: "bank", to: "c", amount: "5", by: "u1", payee: "Payee X" });
    assert.ok(t2.screen.flags.some((f) => f.startsWith("first-time payee")));
  });
});
