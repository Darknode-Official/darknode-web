// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// VAULT ledger core — the safeguarding/treasury control plane's money engine.
//
// IMPORTANT: VAULT does not hold or move real money. It is the record-of-truth and
// control layer for funds a company holds at its own regulated, insured bank(s). Real
// settlement happens at the bank; VAULT enforces the controls, keeps a tamper-evident
// ledger, and reconciles against the bank's statements. It is NOT a bank, NOT a custodian,
// and collects no deposits.
//
// Design rules that make "no bugs with funds" an enforced property, not a wish:
//   1. All money is integer cents as BigInt. There is NO floating point anywhere. Sub-cent
//      input is rejected, not rounded.
//   2. Double-entry is enforced on EVERY posting: sum(debits) === sum(credits) per currency,
//      every amount > 0, >= 2 lines, accounts must exist. A violation throws; nothing partial
//      is ever committed (fail-closed).
//   3. Balances are DERIVED by folding postings, never stored — so a balance can never drift
//      from the journal. The trial balance (sum of all debits === sum of all credits) must
//      always hold and is checkable at any time.
//   4. The journal is append-only and SHA-256 hash-chained; any later edit breaks the chain
//      and is detected by verifyChain().
//   5. Idempotency keys make double-posting impossible.
//   6. Fund release enforces segregation of duties + N distinct approvers + a balance check;
//      you cannot release more than an account holds (when flagged no-overdraft).
//
// Everything is deterministic and isomorphic (same result in Node and the browser), so the
// test suite can hammer it exhaustively.

// ------------------------------- SHA-256 (pure, synchronous) -------------------------------
// Standard FIPS 180-4 SHA-256 over a Uint8Array -> lowercase hex. Verified against the
// "abc" test vector in selfTest(). Synchronous so the ledger append stays simple + atomic.

const _K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

export function sha256hex(bytes) {
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const l = bytes.length;
  const total = ((l + 8) >> 6) + 1 << 6;       // bytes, multiple of 64, room for 0x80 + 64-bit length
  const buf = new Uint8Array(total);
  buf.set(bytes);
  buf[l] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 8, Math.floor(l / 0x20000000)); // high 32 bits of (l*8)
  dv.setUint32(total - 4, (l << 3) >>> 0);             // low 32 bits of (l*8)
  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let i = 0; i < total; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + _K[t] + w[t]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  const hx = (x) => (x >>> 0).toString(16).padStart(8, "0");
  return hx(h0) + hx(h1) + hx(h2) + hx(h3) + hx(h4) + hx(h5) + hx(h6) + hx(h7);
}
const _enc = new TextEncoder();
export const hashStr = (s) => sha256hex(_enc.encode(s));

// ------------------------------- money (BigInt cents, no floats) -------------------------------

// Parse "$1,234.56" / "1234.56" / 1234 / -5 / "(5.00)" -> BigInt cents. Rejects sub-cent.
export function toCents(v) {
  if (typeof v === "bigint") return v;
  let s = String(v == null ? "" : v).trim().replace(/[$,\s]/g, "");
  if (s === "") throw new Error("empty amount");
  let neg = false;
  if (/^\(.*\)$/.test(s)) { neg = true; s = s.slice(1, -1); }
  if (s[0] === "-") { neg = true; s = s.slice(1); }
  else if (s[0] === "+") s = s.slice(1);
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error("invalid amount: " + v);
  const dot = s.indexOf(".");
  let whole = dot < 0 ? s : s.slice(0, dot);
  let frac = dot < 0 ? "" : s.slice(dot + 1);
  if (frac.length > 2) {
    if (/[1-9]/.test(frac.slice(2))) throw new Error("sub-cent precision not allowed: " + v);
    frac = frac.slice(0, 2);
  }
  frac = (frac + "00").slice(0, 2);
  const cents = BigInt(whole) * 100n + BigInt(frac);
  return neg ? -cents : cents;
}
export function fmtCents(c) {
  const neg = c < 0n;
  let a = neg ? -c : c;
  const dollars = (a / 100n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const rem = (a % 100n).toString().padStart(2, "0");
  return (neg ? "-" : "") + "$" + dollars + "." + rem;
}

// Canonical, deterministic JSON (sorted keys, BigInt -> "<n>c") for hashing.
export function canon(obj) {
  if (typeof obj === "bigint") return JSON.stringify(obj.toString() + "c");
  if (Array.isArray(obj)) return "[" + obj.map(canon).join(",") + "]";
  if (obj && typeof obj === "object") {
    return "{" + Object.keys(obj).sort().map((k) => JSON.stringify(k) + ":" + canon(obj[k])).join(",") + "}";
  }
  return JSON.stringify(obj);
}

// ------------------------------- account model -------------------------------

// Normal balance side by account type. Debit-normal: asset. Credit-normal: liability, equity.
const NORMAL = { asset: "debit", omnibus: "debit", clearing: "debit", liability: "credit", customer: "credit", equity: "credit", income: "credit", expense: "debit" };

// ------------------------------- the ledger -------------------------------

export class Ledger {
  constructor(opts = {}) {
    this.currency = opts.currency || "USD";
    this.accounts = new Map();          // id -> {id,name,type,normal,noOverdraft}
    this.journal = [];                  // append-only hash-chained entries
    this.transfers = new Map();         // id -> transfer (control workflow)
    this.head = "0".repeat(64);         // genesis prev-hash
    this._idem = new Set();
    this._seq = 0;
    this.policy = Object.assign({ minApprovers: 2, dualControl: true, tiers: [] }, opts.policy || {});
  }

  openAccount({ id, name, type, noOverdraft }) {
    if (!id) throw new Error("account id required");
    if (this.accounts.has(id)) throw new Error("account exists: " + id);
    const normal = NORMAL[type];
    if (!normal) throw new Error("unknown account type: " + type);
    const acct = { id, name: name || id, type, normal, noOverdraft: type === "asset" || type === "omnibus" || !!noOverdraft };
    this.accounts.set(id, acct);
    return acct;
  }

  // Fold postings to get an account's balance (in cents, signed by its normal side).
  balance(id) {
    if (!this.accounts.has(id)) throw new Error("no such account: " + id);
    const acct = this.accounts.get(id);
    let dr = 0n, cr = 0n;
    for (const e of this.journal) for (const p of e.postings) {
      if (p.account !== id) continue;
      if (p.side === "debit") dr += p.amount; else cr += p.amount;
    }
    const bal = acct.normal === "debit" ? dr - cr : cr - dr;
    return { debits: dr, credits: cr, balance: bal };
  }

  // The global invariant: across the whole journal, total debits === total credits.
  trialBalance() {
    let dr = 0n, cr = 0n;
    for (const e of this.journal) for (const p of e.postings) {
      if (p.side === "debit") dr += p.amount; else cr += p.amount;
    }
    return { debits: dr, credits: cr, balanced: dr === cr };
  }

  // Post a balanced double-entry transaction. Validates everything; throws on any violation
  // BEFORE mutating state, so a rejected entry leaves the ledger untouched.
  post({ memo, postings, idempotencyKey, by, ts, meta }) {
    if (!Array.isArray(postings) || postings.length < 2) throw new Error("need >= 2 postings");
    if (idempotencyKey != null) {
      if (this._idem.has(idempotencyKey)) throw new Error("duplicate idempotencyKey: " + idempotencyKey);
    }
    let dr = 0n, cr = 0n;
    const norm = [];
    for (const p of postings) {
      if (!this.accounts.has(p.account)) throw new Error("no such account: " + p.account);
      if (p.side !== "debit" && p.side !== "credit") throw new Error("side must be debit|credit");
      const amt = typeof p.amount === "bigint" ? p.amount : toCents(p.amount);
      if (amt <= 0n) throw new Error("posting amount must be > 0");
      if (p.side === "debit") dr += amt; else cr += amt;
      norm.push({ account: p.account, side: p.side, amount: amt });
    }
    if (dr !== cr) throw new Error("unbalanced: debits " + fmtCents(dr) + " != credits " + fmtCents(cr));

    const seq = this._seq;
    const body = { seq, ts: ts == null ? 0 : ts, memo: memo || "", postings: norm, by: by || "", meta: meta || null, idem: idempotencyKey == null ? "" : String(idempotencyKey) };
    const hash = hashStr(this.head + "|" + canon(body));
    const entry = Object.assign({}, body, { prev: this.head, hash });
    // commit
    this.journal.push(entry);
    this.head = hash;
    this._seq++;
    if (idempotencyKey != null) this._idem.add(idempotencyKey);
    return entry;
  }

  // Recompute the hash chain from genesis; report the first broken link, if any.
  verifyChain() {
    let prev = "0".repeat(64);
    for (let i = 0; i < this.journal.length; i++) {
      const e = this.journal[i];
      const body = { seq: e.seq, ts: e.ts, memo: e.memo, postings: e.postings, by: e.by, meta: e.meta, idem: e.idem };
      const expect = hashStr(prev + "|" + canon(body));
      if (e.prev !== prev || e.hash !== expect) return { ok: false, brokenAt: i };
      prev = e.hash;
    }
    return { ok: prev === this.head, brokenAt: -1 };
  }

  // ---- fund-movement control workflow (the "safeguarding" part) ----
  // A transfer is an INSTRUCTION to move funds from one account to another. It posts nothing
  // until it is approved by enough distinct people (none of them the initiator) and released.

  _approversRequired(amountCents) {
    let n = this.policy.minApprovers;
    for (const [thr, req] of (this.policy.tiers || [])) if (amountCents >= toCents(thr)) n = Math.max(n, req);
    return n;
  }

  createTransfer({ id, from, to, amount, memo, by, payee, ts }) {
    if (!id) throw new Error("transfer id required");
    if (this.transfers.has(id)) throw new Error("transfer exists: " + id);
    if (!this.accounts.has(from)) throw new Error("no such from account: " + from);
    if (!this.accounts.has(to)) throw new Error("no such to account: " + to);
    if (from === to) throw new Error("from and to must differ");
    if (!by) throw new Error("initiator (by) required");
    const amt = typeof amount === "bigint" ? amount : toCents(amount);
    if (amt <= 0n) throw new Error("transfer amount must be > 0");
    const t = {
      id, from, to, amount: amt, memo: memo || "", payee: payee || "", by,
      status: "pending", approvers: [], required: this._approversRequired(amt),
      createdTs: ts == null ? 0 : ts, releasedEntry: null, reconciled: false,
      screen: screenTransfer(this, { from, amount: amt, payee, by }),
    };
    this.transfers.set(id, t);
    return t;
  }

  approve(id, approver) {
    const t = this.transfers.get(id);
    if (!t) throw new Error("no such transfer: " + id);
    if (t.status !== "pending") throw new Error("transfer not pending: " + t.status);
    if (!approver) throw new Error("approver required");
    if (this.policy.dualControl && approver === t.by) throw new Error("segregation of duties: initiator cannot approve own transfer");
    if (t.approvers.includes(approver)) throw new Error("already approved by " + approver);
    t.approvers.push(approver);
    if (t.approvers.length >= t.required) t.status = "approved";
    return t;
  }

  reject(id, by, reason) {
    const t = this.transfers.get(id);
    if (!t) throw new Error("no such transfer: " + id);
    if (t.status === "released" || t.status === "settled") throw new Error("cannot reject a released transfer");
    t.status = "rejected"; t.rejectedBy = by || ""; t.reason = reason || "";
    return t;
  }

  // Release an approved transfer: enforces the balance check, then posts the double entry.
  release(id, by, ts) {
    const t = this.transfers.get(id);
    if (!t) throw new Error("no such transfer: " + id);
    if (t.status !== "approved") throw new Error("transfer must be approved before release (is " + t.status + ")");
    // Separation of duties on release, enforced at the ledger so it holds in local
    // mode and everywhere else, not only in the worker: the initiator cannot be the
    // one who releases their own transfer.
    if (this.policy.dualControl) {
      if (!by) throw new Error("releaser required");
      if (by === t.by) throw new Error("segregation of duties: initiator cannot release own transfer");
    }
    const fromAcct = this.accounts.get(t.from);
    if (fromAcct.noOverdraft) {
      const bal = this.balance(t.from).balance;
      if (bal < t.amount) throw new Error("insufficient funds in " + t.from + ": have " + fmtCents(bal) + ", need " + fmtCents(t.amount));
    }
    // moving funds from -> to: debit destination, credit source
    const entry = this.post({
      memo: t.memo || ("transfer " + t.id), by: by || t.by, ts,
      idempotencyKey: "transfer:" + t.id,
      meta: { transfer: t.id, payee: t.payee },
      postings: [{ account: t.to, side: "debit", amount: t.amount }, { account: t.from, side: "credit", amount: t.amount }],
    });
    t.status = "released"; t.releasedEntry = entry.hash; t.releasedBy = by || t.by;
    return t;
  }

  // Reconcile released transfers against imported bank statement lines (date/amount/ref).
  // Marks matches settled; returns {matched, unmatchedBank, unmatchedLedger}.
  reconcile(statementLines) {
    const released = [...this.transfers.values()].filter((t) => t.status === "released" && !t.reconciled);
    const bank = (statementLines || []).map((l, i) => ({ i, amount: typeof l.amount === "bigint" ? l.amount : toCents(l.amount), ref: String(l.ref || ""), used: false }));
    const matched = [];
    for (const t of released) {
      const hit = bank.find((b) => !b.used && b.amount === t.amount && (!t.payee || b.ref.toLowerCase().includes(t.payee.toLowerCase().slice(0, 4)) || b.ref.includes(t.id)));
      if (hit) { hit.used = true; t.reconciled = true; t.status = "settled"; matched.push({ transfer: t.id, bankLine: hit.i }); }
    }
    return {
      matched,
      unmatchedBank: bank.filter((b) => !b.used).map((b) => ({ amount: fmtCents(b.amount), ref: b.ref })),
      unmatchedLedger: released.filter((t) => !t.reconciled).map((t) => ({ id: t.id, amount: fmtCents(t.amount) })),
    };
  }

  // Snapshot for persistence (BigInt -> string). Reload with Ledger.load().
  snapshot() {
    return {
      v: 1, currency: this.currency, head: this.head, seq: this._seq, policy: this.policy,
      accounts: [...this.accounts.values()],
      journal: this.journal.map((e) => ({ ...e, postings: e.postings.map((p) => ({ ...p, amount: p.amount.toString() })) })),
      transfers: [...this.transfers.values()].map((t) => ({ ...t, amount: t.amount.toString() })),
      idem: [...this._idem],
    };
  }
  static load(snap) {
    const L = new Ledger({ currency: snap.currency, policy: snap.policy });
    for (const a of snap.accounts) L.accounts.set(a.id, a);
    L.journal = (snap.journal || []).map((e) => ({ ...e, postings: e.postings.map((p) => ({ ...p, amount: BigInt(p.amount) })) }));
    L.transfers = new Map((snap.transfers || []).map((t) => [t.id, { ...t, amount: BigInt(t.amount) }]));
    L.head = snap.head; L._seq = snap.seq; L._idem = new Set(snap.idem || []);
    return L;
  }
}

// ------------------------------- movement risk screen (STRONGROOM-style, inline) -------------------------------

// A lightweight, deterministic pre-flight on a proposed transfer. Returns {level, flags[]}.
// Leads, not verdicts — surfaces reasons a human should look before releasing.
export function screenTransfer(ledger, { from, amount, payee, by }) {
  const flags = [];
  const amt = typeof amount === "bigint" ? amount : toCents(amount);
  // round & large
  if (amt >= 1000000n && amt % 100000n === 0n) flags.push("round-and-large: exact multiple of $1,000 at/over $10,000");
  // just under a tier threshold
  for (const [thr] of (ledger.policy.tiers || [])) {
    const t = toCents(thr);
    if (amt >= (t * 90n) / 100n && amt < t) flags.push("just below approval tier " + fmtCents(t));
  }
  // first-time payee (not seen in any prior released transfer)
  if (payee) {
    const seen = [...ledger.transfers.values()].some((t) => t.status !== "pending" && (t.payee || "").toLowerCase() === payee.toLowerCase());
    if (!seen) flags.push("first-time payee: " + payee);
  }
  const level = flags.length >= 2 ? "high" : flags.length === 1 ? "medium" : "low";
  return { level, flags };
}

// ------------------------------- self-test (invariants + crypto vectors) -------------------------------

export function selfTest() {
  const results = [];
  const ok = (name, cond) => results.push({ name, pass: !!cond });
  const threw = (name, fn) => { try { fn(); results.push({ name, pass: false }); } catch (_) { results.push({ name, pass: true }); } };

  // SHA-256 known-answer tests
  ok("sha256('') vector", sha256hex(new Uint8Array(0)) === "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  ok("sha256('abc') vector", hashStr("abc") === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  // money parsing — exactness and rejection
  ok("toCents dollars", toCents("1,234.56") === 123456n);
  ok("toCents integer", toCents(1000) === 100000n);
  ok("toCents negative paren", toCents("($5.00)") === -500n);
  threw("toCents rejects sub-cent", () => toCents("0.001"));
  threw("toCents rejects junk", () => toCents("12x.5"));
  ok("fmtCents round-trip", fmtCents(123456n) === "$1,234.56");
  ok("fmtCents zero", fmtCents(0n) === "$0.00");

  // ledger invariants
  const L = new Ledger({ policy: { minApprovers: 2, dualControl: true, tiers: [["10000.00", 3]] } });
  L.openAccount({ id: "bank", name: "Operating (bank)", type: "asset" });
  L.openAccount({ id: "equity", name: "Opening equity", type: "equity" });
  L.openAccount({ id: "payee-clearing", name: "Outgoing clearing", type: "clearing" });
  // fund the bank (opening balance): debit bank, credit equity
  L.post({ memo: "opening", by: "system", postings: [{ account: "bank", side: "debit", amount: "100000.00" }, { account: "equity", side: "credit", amount: "100000.00" }] });
  ok("balance after opening", L.balance("bank").balance === 10000000n);
  ok("trial balance holds", L.trialBalance().balanced);
  threw("unbalanced post rejected", () => L.post({ postings: [{ account: "bank", side: "debit", amount: "5.00" }, { account: "equity", side: "credit", amount: "4.00" }] }));
  threw("single-line post rejected", () => L.post({ postings: [{ account: "bank", side: "debit", amount: "5.00" }] }));
  threw("unknown account rejected", () => L.post({ postings: [{ account: "ghost", side: "debit", amount: "1.00" }, { account: "bank", side: "credit", amount: "1.00" }] }));
  ok("idempotency: duplicate key blocked", (() => { L.post({ idempotencyKey: "x1", postings: [{ account: "bank", side: "credit", amount: "1.00" }, { account: "equity", side: "debit", amount: "1.00" }] }); try { L.post({ idempotencyKey: "x1", postings: [{ account: "bank", side: "credit", amount: "1.00" }, { account: "equity", side: "debit", amount: "1.00" }] }); return false; } catch (_) { return true; } })());

  // transfer workflow + SoD + thresholds + balance guard
  const t = L.createTransfer({ id: "t1", from: "bank", to: "payee-clearing", amount: "2500.00", memo: "pay vendor", by: "alice", payee: "Acme" });
  threw("initiator cannot self-approve", () => L.approve("t1", "alice"));
  L.approve("t1", "bob");
  ok("not released until approvals met", L.transfers.get("t1").status === "pending");
  L.approve("t1", "carol");
  ok("approved after 2 distinct approvers", L.transfers.get("t1").status === "approved");
  threw("cannot release more than balance", () => { const big = L.createTransfer({ id: "tbig", from: "bank", to: "payee-clearing", amount: "99999999.00", by: "alice" }); L.approve("tbig", "bob"); L.approve("tbig", "carol"); L.approve("tbig", "dave"); L.release("tbig", "bob"); });
  L.release("t1", "bob");
  ok("release posts the entry", L.transfers.get("t1").status === "released");
  ok("bank reduced by transfer", L.balance("bank").balance === 10000000n - 100n - 250000n); // opening 10,000,000 − idem credit 100 − transfer 250,000
  ok("chain verifies after releases", L.verifyChain().ok);

  // tamper detection
  const L2 = Ledger.load(L.snapshot());
  ok("snapshot/load preserves chain", L2.verifyChain().ok);
  L2.journal[0].postings[0].amount = 999n; // tamper
  ok("tamper is detected", !L2.verifyChain().ok);

  // high-tier requires 3 approvers
  const t3 = L.createTransfer({ id: "t3", from: "bank", to: "payee-clearing", amount: "10000.00", by: "alice", payee: "BigCo" });
  ok("tier raises approvers to 3", t3.required === 3);

  const pass = results.every((r) => r.pass);
  return { pass, results };
}
