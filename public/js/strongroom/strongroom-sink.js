// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Pure mapper: STRONGROOM fusion chains -> the common Finding shape (core/sink-map.js)
// for the Security Graph (docs/STRONGROOM-FUSION-ENGINE.md §14). Each intrusion ->
// fund-theft chain becomes one high/critical finding whose evidence lists the access
// event and the payments it led to, linked to the vendors and identities involved.
// Single-plane financial screens are not published here. Account numbers never leave.
// Tested in test/security/strongroom-sink.test.mjs.

const str = (v) => String(v == null ? "" : v).trim();
const norm = (v) => str(v).toLowerCase().replace(/\s+/g, " ");

const CONFIDENCE = { exact: "confirmed", precise: "confirmed", heuristic: "likely", screen: "review" };
const ADVICE = {
  "fusion-bec-payment-redirect": "Verify the bank-detail change or mailbox rule out-of-band with a known vendor contact; hold further payments and recall the listed ones if it is not confirmed.",
  "fusion-ato-disbursement": "Treat the identity as compromised: revoke sessions and the new factor, then confirm each listed payment with the approver through a separate channel.",
  "fusion-insider-export-newvendor": "Review who exported the vendor data and validate the newly paid vendors (registration, bank ownership) before further payment.",
};
const MAX_PAYMENTS = 25;

/**
 * analyze() result -> one finding per fusion chain.
 * @param {{ findings: object[] }} res STRONGROOM engine analyze() output
 * @returns {object[]}
 */
export function fusionFindings(res) {
  const out = [];
  for (const f of (res && res.findings) || []) {
    if (!f || !str(f.rule).startsWith("fusion-")) continue;
    const ch = f.chain || null;
    const ev = (ch && ch.event) || {};
    const pays = (ch && ch.payments) || [];
    const isVendorChain = f.rule === "fusion-bec-payment-redirect";
    const subject = isVendorChain ? str(ev.vendor || f.vendor) : str(ev.actor);
    // Stable across re-runs and row reordering: rule + who/what + when + event type.
    const id = ch ? ["strongroom", f.rule, norm(subject), str(ev.date), str(ev.type)].join("|") : "strongroom|" + f.id;

    const assets = [];
    const seen = new Set();
    const add = (type, name) => { const n = str(name); const k = type + ":" + n.toLowerCase(); if (n && !seen.has(k) && assets.length < 16) { seen.add(k); assets.push({ type, name: n }); } };
    add("VENDOR", ev.vendor || f.vendor);
    add("IDENTITY", ev.actor);
    for (const p of pays) add("VENDOR", p.vendor);
    if (f.rule === "fusion-ato-disbursement") for (const p of pays) { add("IDENTITY", p.approver); add("IDENTITY", p.initiator); }

    const evidence = ch
      ? [{ leg: "access", row: ev.row, date: str(ev.date), type: str(ev.type), actor: str(ev.actor), vendor: str(ev.vendor), detail: str(ev.detail).slice(0, 200) }]
        .concat(pays.slice(0, MAX_PAYMENTS).map((p) => ({ leg: "payment", row: p.row, date: str(p.date), vendor: str(p.vendor), amount: p.amount, approver: str(p.approver), initiator: str(p.initiator) })))
        .concat([{ leg: "exposure", amount: f.money, payments: pays.length }])
      : (f.evidence || []).map((e) => ({ leg: "record", text: str(e) })).concat([{ leg: "exposure", amount: f.money }]);

    out.push({
      id,
      title: `${str(f.title)}: ${subject || "unattributed"}`,
      severity: f.severity === "critical" ? "critical" : "high",
      confidence: CONFIDENCE[f.soundness] || "review",
      category: "Cyber-financial fusion",
      description: str(f.why),
      recommendation: ADVICE[f.rule],
      evidence,
      assets,
      tags: ["fusion", f.rule],
    });
  }
  return out;
}
