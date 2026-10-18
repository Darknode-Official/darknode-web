// Append-only, tamper-evident hash chain (Deck D6 platform audit log). PURE — no DOM, no
// network, no storage. It reuses the exact SHA-256 + canonical-JSON primitives the VAULT
// ledger uses for its money audit chain (public/js/vault/ledger.js), so the scheme is the
// same one already proven there: each record commits to the previous head, so a single
// altered or removed entry breaks verification from that point on.
//
//   record = { n, ...entry, prev, hash }   hash = SHA256(prev + "|" + canon({n, ...entry}))
//   chain state = { n, head }               genesis head = 64 zeros
import { hashStr, canon } from "../public/js/vault/ledger.js";

export const GENESIS = "0".repeat(64);
export const pad = (n) => String(n).padStart(10, "0"); // sortable storage key: a:<pad n>

// Append `entry` to the chain whose current state is {n, head}. Returns the stored record
// and the next chain state. Synchronous (hashStr is a synchronous SHA-256) so a caller can
// put the record and the new meta without an intervening await.
export function chainAppend(state, entry) {
  const n = (state && state.n) || 0;
  const prev = (state && state.head) || GENESIS;
  const body = { n, ...entry };
  const hash = hashStr(prev + "|" + canon(body));
  return { rec: { ...body, prev, hash }, next: { n: n + 1, head: hash } };
}

// Verify an in-order array of records (oldest first). When expectHead / expectN are given
// (the chain's stored meta), confirm the chain is complete, not just internally consistent.
export function chainVerify(records, expectHead, expectN) {
  let prev = GENESIS, i = 0;
  for (const e of records) {
    const { prev: p, hash, ...body } = e;
    if (p !== prev || body.n !== i || hash !== hashStr(prev + "|" + canon(body))) return { ok: false, brokenAt: i, entries: i };
    prev = hash; i++;
  }
  const okHead = expectHead == null || prev === expectHead;
  const okN = expectN == null || i === expectN;
  return { ok: okHead && okN, brokenAt: -1, entries: i };
}
