// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Vendor / payee bank-change control engine — pure, deterministic, dependency-free.
//
// The control that actually stops vendor-bank-change (business email compromise)
// wire fraud: a change to a payee's bank details does not quietly overwrite the
// record. It opens a change request that requires a SECOND approver and a recorded
// out-of-band callback verification, then the new account is HELD for a cool-down
// window before the first payment is allowed — and first-payment / recently-changed
// accounts are flagged for screening. STRONGROOM detects a redirected payment after
// the money moves; this prevents it before.
//
// This module is pure state + validation logic (no DOM, no storage). The UI layer
// persists the vendor master and drives these functions; the same inputs always
// produce the same outputs, so every transition is auditable and testable.

// ------------------------------- bank-detail validation -------------------------------

// IBAN: ISO 13616 mod-97 check (move first 4 chars to the end, A=10..Z=35, ≡ 1 mod 97),
// plus a per-country length table for the common cases.
const IBAN_LEN = {
  AD: 24, AE: 23, AT: 20, BE: 16, BG: 22, CH: 21, CY: 28, CZ: 24, DE: 22, DK: 18,
  EE: 20, ES: 24, FI: 18, FR: 27, GB: 22, GR: 27, HR: 21, HU: 28, IE: 22, IL: 23,
  IS: 26, IT: 27, LT: 20, LU: 20, LV: 21, MT: 31, NL: 18, NO: 15, PL: 28, PT: 25,
  RO: 24, SA: 24, SE: 24, SI: 19, SK: 24, TR: 26, UA: 29,
};
export function validateIBAN(raw) {
  const s = String(raw || "").replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(s)) return { ok: false, reason: "Not an IBAN format (CCkk followed by alphanumerics)." };
  const cc = s.slice(0, 2);
  if (IBAN_LEN[cc] && s.length !== IBAN_LEN[cc]) return { ok: false, reason: `Wrong length for ${cc} (expected ${IBAN_LEN[cc]}, got ${s.length}).` };
  const rearranged = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const v = ch >= "A" && ch <= "Z" ? ch.charCodeAt(0) - 55 : ch.charCodeAt(0) - 48;
    rem = (rem * (v > 9 ? 100 : 10) + v) % 97;
  }
  return rem === 1 ? { ok: true, normalized: s, country: cc } : { ok: false, reason: "Checksum failed (mod-97)." };
}

// US ABA routing number: 9 digits, weighted mod-10 checksum 3-7-1.
export function validateABA(raw) {
  const s = String(raw || "").replace(/\s|-/g, "");
  if (!/^\d{9}$/.test(s)) return { ok: false, reason: "Must be 9 digits." };
  const d = s.split("").map(Number);
  const sum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + 1 * (d[2] + d[5] + d[8]);
  return sum % 10 === 0 ? { ok: true, normalized: s } : { ok: false, reason: "Checksum failed (3-7-1 mod-10)." };
}

// SWIFT/BIC: 4 letters (institution) + 2 letters (ISO country) + 2 alnum (location)
// + optional 3 alnum (branch). 8 or 11 chars.
export function validateBIC(raw) {
  const s = String(raw || "").replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(s)) return { ok: false, reason: "Not a BIC (AAAACCLL or AAAACCLLBBB)." };
  return { ok: true, normalized: s, country: s.slice(4, 6) };
}

// Validate a bank-detail object. kind: "iban" (iban [+ bic]) or "aba" (account + routing).
export function validateBank(bank) {
  const b = bank || {};
  const errs = [];
  if (b.kind === "iban") {
    const r = validateIBAN(b.iban); if (!r.ok) errs.push("IBAN: " + r.reason);
    if (b.swift) { const s = validateBIC(b.swift); if (!s.ok) errs.push("SWIFT/BIC: " + s.reason); }
  } else if (b.kind === "aba") {
    if (!/^\d{4,17}$/.test(String(b.account || "").replace(/\s|-/g, ""))) errs.push("Account number: 4–17 digits.");
    const r = validateABA(b.routing); if (!r.ok) errs.push("Routing (ABA): " + r.reason);
  } else {
    errs.push("Unknown bank-detail kind.");
  }
  return { ok: errs.length === 0, errors: errs };
}

// A stable, human-readable fingerprint of a bank account (so a "change" is detected
// by content, not by object identity). Last 4 shown; full value hashed-ish for compare.
export function bankKey(bank) {
  const b = bank || {};
  if (b.kind === "iban") return "iban:" + String(b.iban || "").replace(/\s+/g, "").toUpperCase();
  if (b.kind === "aba") return "aba:" + String(b.routing || "").replace(/\s|-/g, "") + ":" + String(b.account || "").replace(/\s|-/g, "");
  return "?";
}
export function bankLabel(bank) {
  const b = bank || {};
  if (b.kind === "iban") { const v = String(b.iban || "").replace(/\s+/g, "").toUpperCase(); return v ? "IBAN ••••" + v.slice(-4) : "IBAN"; }
  if (b.kind === "aba") { const v = String(b.account || "").replace(/\s|-/g, ""); return "Acct ••••" + v.slice(-4) + " / ABA " + String(b.routing || "").slice(-4); }
  return "—";
}

// ------------------------------- change-control state machine -------------------------------

export const HOLD_HOURS = 24;   // new-account cool-down before the first payment is allowed
export const WATCH_DAYS = 30;   // "recently changed" screening window

// Status values: "active" (verified, past hold), "held" (verified, in cool-down),
// "pending" (a change request is open, awaiting a second approver + callback).
//
// A vendor record carries its current bank, its status, timestamps, an open change
// request (or null), and an append-only history of prior banks.

// Create a vendor. The initial bank is treated as a held change requiring the same
// controls as any later change (so onboarding fraud is caught too).
export function createVendor({ id, name, bank, by, at }) {
  const now = at || Date.now();
  const v = {
    id, name: String(name || "").trim(), bank: null,
    status: "pending", createdAt: now, activatedAt: null, firstPaymentAt: null,
    holdUntil: null, change: null, history: [], audit: [],
  };
  // The first bank is proposed as the opening change — it is not live until it has
  // been through the same callback + second-approver control as any later change.
  if (bank) v.change = { bank, by: by || null, at: now, approvedBy: null, callback: null };
  pushAudit(v, "vendor-created", by, now, { name: v.name });
  return v;
}

function pushAudit(v, action, by, at, extra) {
  v.audit.push(Object.assign({ action, by: by || null, at: at || Date.now() }, extra || {}));
}

// Propose a bank-detail change. Opens a change request; does NOT alter the live bank.
export function proposeChange(v, { bank, by, at }) {
  const now = at || Date.now();
  const r = validateBank(bank);
  if (!r.ok) return { ok: false, errors: r.errors };
  if (v.status === "pending") return { ok: false, errors: ["A change is already pending for this vendor."] };
  if (v.bank && bankKey(v.bank) === bankKey(bank)) return { ok: false, errors: ["These bank details match the current ones."] };
  v.change = { bank, by: by || null, at: now, approvedBy: null, callback: null };
  v.status = "pending";
  pushAudit(v, "change-proposed", by, now, { to: bankLabel(bank) });
  return { ok: true };
}

// Record the out-of-band callback verification (who called the known-good number,
// what was confirmed). Required before approval.
export function recordCallback(v, { by, note, phone, at }) {
  if (!v.change) return { ok: false, errors: ["No change is pending."] };
  const caller = String(by || "").trim();
  const num = String(phone || "").trim();
  const errs = [];
  // This is the single most important anti-BEC control, so it must have substance:
  // an empty "callback" can no longer satisfy the approval gate.
  if (!caller) errs.push("Record who made the verification call.");
  if (!num) errs.push("Record the phone number that was called (the vendor's known-good number, not one from the change request).");
  if (errs.length) return { ok: false, errors: errs };
  const now = at || Date.now();
  v.change.callback = { by: caller, note: String(note || "").trim(), phone: num, at: now };
  pushAudit(v, "callback-recorded", caller, now, { phone: num });
  return { ok: true };
}

// Approve the pending change. Requires a DIFFERENT approver from the proposer and a
// recorded callback. On approval the old bank is archived, the new bank goes live but
// HELD for the cool-down window.
export function approveChange(v, { by, at }) {
  const now = at || Date.now();
  if (!v.change) return { ok: false, errors: ["No change is pending."] };
  if (!by) return { ok: false, errors: ["An approver is required."] };
  if (v.change.by && by === v.change.by) return { ok: false, errors: ["The approver must be different from the person who proposed the change (separation of duties)."] };
  if (!v.change.callback || !v.change.callback.by || !v.change.callback.phone) return { ok: false, errors: ["Record the out-of-band callback verification (caller and number) before approving."] };
  if (v.bank) v.history.push({ bank: v.bank, retiredAt: now, label: bankLabel(v.bank) });
  v.change.approvedBy = by;
  v.bank = v.change.bank;
  v.status = "held";
  v.activatedAt = now;
  v.holdUntil = now + HOLD_HOURS * 3600 * 1000;
  v.firstPaymentAt = null;
  const c = v.change; v.change = null;
  pushAudit(v, "change-approved", by, now, { account: bankLabel(v.bank), holdUntil: v.holdUntil, proposedBy: c.by });
  return { ok: true };
}

// Reject the pending change; the live bank is unchanged.
export function rejectChange(v, { by, reason, at }) {
  const now = at || Date.now();
  if (!v.change) return { ok: false, errors: ["No change is pending."] };
  const c = v.change; v.change = null;
  v.status = v.bank ? (v.holdUntil && now < v.holdUntil ? "held" : "active") : "pending";
  if (!v.bank) v.change = c; // a rejected OPENING change leaves the vendor pending with its proposal intact
  pushAudit(v, "change-rejected", by, now, { reason: String(reason || "").trim() });
  return { ok: true };
}

// Refresh a vendor's derived status (held -> active once the cool-down passes).
export function refresh(v, at) {
  const now = at || Date.now();
  if (v.status === "held" && v.holdUntil && now >= v.holdUntil) v.status = "active";
  return v;
}

// Can a payment be released to this vendor right now? Returns {ok, reason}.
export function canPay(v, at) {
  const now = at || Date.now();
  if (!v.bank) return { ok: false, reason: "No verified bank details." };
  if (v.status === "pending") return { ok: false, reason: "A bank-detail change is pending approval." };
  if (v.status === "held" && v.holdUntil && now < v.holdUntil) {
    const hrs = Math.ceil((v.holdUntil - now) / 3600000);
    return { ok: false, reason: `New account held ${hrs}h more before first payment.` };
  }
  return { ok: true };
}

// Screening flags for a payment to this vendor (feed into a payment review).
export function screenFlags(v, at) {
  const now = at || Date.now();
  const flags = [];
  if (v.status === "pending") flags.push({ code: "change-pending", level: "block", text: "Bank change pending — do not pay." });
  if (v.status === "held" && v.holdUntil && now < v.holdUntil) flags.push({ code: "new-account-hold", level: "high", text: "New bank account within its cool-down window." });
  if (v.bank && !v.firstPaymentAt) flags.push({ code: "first-payment", level: "high", text: "First payment to this account." });
  if (v.activatedAt && now - v.activatedAt < WATCH_DAYS * 86400000) flags.push({ code: "recently-changed", level: "medium", text: `Bank account changed in the last ${WATCH_DAYS} days.` });
  return flags;
}

// Mark that a payment was released (records the first-payment timestamp once).
export function markPaid(v, at) {
  const now = at || Date.now();
  if (!v.firstPaymentAt) v.firstPaymentAt = now;
  pushAudit(v, "payment-released", null, now, {});
  return v;
}

// ------------------------------- Security Graph sink -------------------------------

// Register -> common Finding shape (core/sink-map.js). Per payee: an open bank-detail
// change (the BEC redirection point), a live account still inside the watch window
// (hold / recently changed / never paid, merged into one finding per account), and an
// OFAC name hit when the caller passes one (`sanctions(v)` -> the UI's flag or null).
// Ids carry the vendor id + change count + masked account so each new change is a new
// finding; only masked account labels leave this function, never full account numbers
// or callback phone numbers.
const OFAC_SEV = { block: "critical", high: "high", medium: "medium" };
export function toSinkFindings(list, { sanctions, at } = {}) {
  const now = at || Date.now();
  const iso = (t) => (t ? new Date(t).toISOString() : "");
  const out = [];
  for (const v of list || []) {
    if (!v || !v.id) continue;
    const asset = { type: "VENDOR", name: v.name, data: { role: "payee", status: v.status, account: v.bank ? bankLabel(v.bank) : "" } };
    const ttp = [{ framework: "MITRE", id: "T1657" }];
    if (v.status === "pending" && v.change) {
      const c = v.change, isChange = !!v.bank;
      out.push({
        id: `${v.id}|${isChange ? "change" : "onboard"}|${v.history.length}|${bankLabel(c.bank)}`,
        title: isChange ? `Bank-detail change pending approval: ${v.name}` : `New payee bank details pending verification: ${v.name}`,
        severity: isChange ? "high" : "medium", confidence: "confirmed", status: "open", category: "bank-change",
        description: `${isChange ? `A change from ${bankLabel(v.bank)} to ${bankLabel(c.bank)}` : `Opening bank details ${bankLabel(c.bank)}`} was proposed by ${c.by || "unknown"} and is not yet approved. Callback verification: ${c.callback ? "recorded" : "not recorded"}. Payments are blocked until a second approver signs off.`,
        recommendation: "Verify the change by calling the payee on a number already on file (never one from the change request), record the callback, and have a second person approve. Treat an urgent or emailed request for new bank details as business email compromise until verified.",
        evidence: [{ field: "proposed account", value: bankLabel(c.bank) }, { field: "current account", value: v.bank ? bankLabel(v.bank) : "none" }, { field: "proposed by", value: c.by || "" }, { field: "proposed at", value: iso(c.at) }, { field: "callback", value: c.callback ? "recorded by " + (c.callback.by || "") + " at " + iso(c.callback.at) : "not recorded" }],
        assets: [asset], controls: ttp, tags: ["payees", "bec"],
      });
    }
    if (v.bank && v.status !== "pending") {
      const flags = screenFlags(v, now), codes = new Set(flags.map((f) => f.code));
      if (codes.size) {
        const onboarding = !v.history.length;
        let sev = codes.has("new-account-hold") ? "high" : codes.has("recently-changed") ? (codes.has("first-payment") ? "high" : "medium") : "low";
        if (onboarding && sev === "high") sev = "medium";
        out.push({
          id: `${v.id}|watch|${v.history.length}|${bankLabel(v.bank)}`,
          title: `Payee bank account under BEC watch: ${v.name}`,
          severity: sev, confidence: "confirmed", status: "open", category: "bank-change",
          description: `${bankLabel(v.bank)} went live ${iso(v.activatedAt) || "at an unknown time"}${onboarding ? " as the payee's first account" : `, replacing ${bankLabel(v.history[v.history.length - 1].bank)}`}. ${flags.map((f) => f.text).join(" ")}`,
          recommendation: "Screen payments to this account before release: confirm the invoice and amount with the payee through a known contact, and watch for urgency or a second change request shortly after this one.",
          evidence: [...flags.map((f) => ({ field: f.code, value: f.text })), { field: "account", value: bankLabel(v.bank) }, { field: "activated at", value: iso(v.activatedAt) }, { field: "hold until", value: iso(v.holdUntil) }, { field: "first payment at", value: iso(v.firstPaymentAt) || "none yet" }],
          assets: [asset], controls: ttp, tags: ["payees", "bec"],
        });
      }
    }
    const s = typeof sanctions === "function" ? sanctions(v) : null;
    if (s) {
      out.push({
        id: `${v.id}|ofac`, title: `OFAC name match on payee: ${v.name}`,
        severity: OFAC_SEV[s.level] || "medium", confidence: "review", status: "open", category: "sanctions",
        description: `${s.text}. Name matching is a screening aid, not a determination; verify identifiers against the official list.`,
        recommendation: "Hold payments to this payee and escalate to compliance; confirm or clear the match in Sanctions Screening against the official entry's identifiers.",
        evidence: [{ field: "match", value: s.text }],
        assets: [asset], tags: ["payees", "ofac"],
      });
    }
  }
  return out;
}

// ------------------------------- self-test -------------------------------

export function selfTest() {
  const results = [];
  const ok = (name, cond) => results.push({ name, pass: !!cond });

  // validators
  ok("valid IBAN passes (DE)", validateIBAN("DE89 3704 0044 0532 0130 00").ok);
  ok("IBAN bad checksum fails", !validateIBAN("DE89 3704 0044 0532 0130 01").ok);
  ok("IBAN wrong length fails", !validateIBAN("DE89 3704").ok);
  ok("valid ABA passes", validateABA("021000021").ok);
  ok("ABA bad checksum fails", !validateABA("021000022").ok);
  ok("valid BIC (8) passes", validateBIC("DEUTDEFF").ok);
  ok("valid BIC (11) passes", validateBIC("DEUTDEFF500").ok);
  ok("bad BIC fails", !validateBIC("DEUT1EFF").ok);

  const t0 = 1_000_000_000_000;
  const H = HOLD_HOURS * 3600000;

  // onboarding: create -> callback -> approve (needs 2nd approver) -> held -> active
  let v = createVendor({ id: "v1", name: "Vendor A Supply", bank: { kind: "iban", iban: "DE89370400440532013000" }, by: "user01", at: t0 });
  ok("new vendor is pending", v.status === "pending");
  ok("approve without callback is blocked", !approveChange(v, { by: "user02", at: t0 + 1 }).ok);
  recordCallback(v, { by: "user02", note: "called CFO on file", phone: "+1-555-0100", at: t0 + 2 });
  ok("approve by proposer is blocked (SoD)", !approveChange(v, { by: "user01", at: t0 + 3 }).ok);
  ok("approve by different approver works", approveChange(v, { by: "user02", at: t0 + 4 }).ok);
  ok("after approval status is held", v.status === "held");
  ok("cannot pay during hold", !canPay(v, t0 + 5).ok);
  ok("first-payment + new-account flags present", screenFlags(v, t0 + 5).some((f) => f.code === "new-account-hold") && screenFlags(v, t0 + 5).some((f) => f.code === "first-payment"));
  refresh(v, t0 + H + 100);
  ok("held -> active after cool-down", v.status === "active");
  ok("can pay after hold", canPay(v, t0 + H + 100).ok);
  markPaid(v, t0 + H + 101);
  ok("first-payment flag clears after paying", !screenFlags(v, t0 + H + 101).some((f) => f.code === "first-payment"));

  // bank change later: archives old, needs controls again
  ok("duplicate bank change rejected", !proposeChange(v, { bank: { kind: "iban", iban: "DE89370400440532013000" }, by: "user01", at: t0 + H + 110 }).ok);
  ok("valid change opens pending", proposeChange(v, { bank: { kind: "aba", account: "123456789", routing: "021000021" }, by: "user01", at: t0 + H + 111 }).ok);
  ok("payment blocked while change pending", !canPay(v, t0 + H + 112).ok);
  recordCallback(v, { by: "user03", note: "verified", phone: "+1-555-0100", at: t0 + H + 113 });
  ok("change approved by second approver", approveChange(v, { by: "user03", at: t0 + H + 114 }).ok);
  ok("prior bank archived to history", v.history.length === 1);
  ok("new account re-enters hold", v.status === "held" && !canPay(v, t0 + H + 115).ok);
  ok("audit trail recorded", v.audit.some((a) => a.action === "change-approved") && v.audit.length >= 6);

  // determinism
  const run = () => { const x = createVendor({ id: "d", name: "D", bank: { kind: "aba", account: "123456789", routing: "021000021" }, by: "a", at: t0 }); recordCallback(x, { by: "b", note: "n", phone: "+1-555-0100", at: t0 + 1 }); approveChange(x, { by: "b", at: t0 + 2 }); refresh(x, t0 + H + 1); return JSON.stringify(x); };
  ok("deterministic", run() === run());

  return { pass: results.every((r) => r.pass), results };
}
