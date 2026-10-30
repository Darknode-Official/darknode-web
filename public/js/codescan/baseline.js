// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Code Scanner — baseline & diff (pure, DOM-free, no network, no storage here).
//
// A baseline is a snapshot of one scan's findings, keyed so the next scan of the
// same target can be classified as NEW / UNCHANGED / FIXED. The caller persists
// the serialized baseline in localStorage (this browser only) and reads it back.
//
// The finding key is deliberately line-independent: it hashes the path, the rule
// id and the normalized matched content (masked secret / code line, or the
// dependency's package@version@advisory). A finding that merely moves to another
// line keeps the same key, so it reads as UNCHANGED rather than fixed-and-new,
// while two genuinely different issues get distinct keys.

// Collapse all whitespace runs so indentation / reflow drift does not change a key.
function norm(s) { return String(s == null ? "" : s).replace(/\s+/g, " ").trim(); }

// cyrb53 — a fast, well-distributed 53-bit string hash (public-domain algorithm),
// returned base36 so keys stay compact. Not cryptographic; only used to bucket.
function hashStr(str) {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const n = 4294967296 * (2097151 & h2) + (h1 >>> 0);
  return n.toString(36);
}

// Stable identity for a finding across scans. Does NOT depend on the line number.
export function findingKey(finding) {
  const f = finding || {};
  const parts = [String(f.path || ""), String(f.ruleId || "")];
  if (f.kind === "dep") {
    // A dependency advisory is identified by the exact package, version and advisory
    // id — the manifest line can move without changing the vulnerability.
    parts.push(String(f.pkg || ""), String(f.version || ""), String(f.advisory || ""));
  } else {
    // Secrets carry a masked line; code carries the trimmed source line. Either is the
    // matched content independent of where it sits in the file.
    parts.push(norm(f.snippet) || String(f.secret || ""));
  }
  return hashStr(parts.join("\u0000"));
}

// Compact, serializable snapshot the caller stores (as JSON) in localStorage.
// Keeps only stable keys + severity + kind + a short label/path for the resolved
// list, plus the target ref and timestamp. No secret values are ever stored.
export function serializeBaseline(findings, meta = {}) {
  const seen = new Map();
  const items = [];
  for (const f of findings || []) {
    const k = findingKey(f);
    if (seen.has(k)) { seen.get(k).n++; continue; } // identical copies share a key: count them
    const it = {
      k,
      n: 1,
      sev: f.sev || "low",
      kind: f.kind || "code",
      // A human label for the FIXED list (file-anchored location is gone by then).
      label: String(f.kind === "dep" ? ((f.pkg || "") + " " + (f.version || "") + ": " + (f.title || f.advisory || "")) : (f.title || f.ruleId || "")).slice(0, 180),
      path: String(f.path || ""),
    };
    seen.set(k, it);
    items.push(it);
  }
  return {
    v: 1,
    ref: String(meta.ref || ""),
    full: String(meta.full || ""),
    sha: String(meta.sha || ""),
    branch: String(meta.branch || ""),
    at: Number(meta.at || Date.now()),
    total: items.length,
    items,
  };
}

// Set of stable keys from a stored baseline (tolerates a missing / malformed one).
export function baselineKeySet(baseline) {
  const items = (baseline && Array.isArray(baseline.items)) ? baseline.items : [];
  return new Set(items.map((it) => it && it.k).filter(Boolean));
}

// Key -> how many copies the baseline holds (items saved before counts existed count 1).
export function baselineKeyCounts(baseline) {
  const items = (baseline && Array.isArray(baseline.items)) ? baseline.items : [];
  const m = new Map();
  for (const it of items) if (it && it.k) m.set(it.k, (m.get(it.k) || 0) + (Number(it.n) > 0 ? Number(it.n) : 1));
  return m;
}

// Classify current findings against a baseline key set, or a key -> count Map
// (baselineKeyCounts). With counts, a second identical copy pasted into a file is NEW
// and removing one of two copies lists that key as fixed; a Set treats copies as one.
//   newFindings — current findings whose key is not in the baseline
//   unchanged   — current findings whose key is in the baseline
//   fixedKeys   — baseline keys with no current finding (resolved; no file location)
export function diffFindings(baselineKeys, currentFindings) {
  const base = baselineKeys instanceof Map ? baselineKeys
    : new Map([...(baselineKeys instanceof Set ? baselineKeys : new Set(baselineKeys || []))].map((k) => [k, Infinity]));
  const newFindings = [], unchanged = [];
  const present = new Map();
  for (const f of currentFindings || []) {
    const k = findingKey(f), c = (present.get(k) || 0) + 1;
    present.set(k, c);
    if (c <= (base.get(k) || 0)) unchanged.push(f); else newFindings.push(f);
  }
  const fixedKeys = [];
  for (const [k, n] of base) if ((present.get(k) || 0) < (n === Infinity ? 1 : n)) fixedKeys.push(k);
  return { newFindings, unchanged, fixedKeys };
}

// Per-file diff for commit-by-commit scanning. `oldFindings` are the file's findings
// before the change, as raw findings or as stored baseline items (which carry `k`);
// `newFindings` are the findings after it. For a rename pass `asPath` = the old path,
// so a finding that only moved with its file keeps its key and is not new + fixed.
//   added     — new findings whose key was not present before
//   unchanged — new findings whose key was present before
//   fixed     — old findings / items whose key is gone
export function diffFile(oldFindings, newFindings, { asPath } = {}) {
  const old = new Map();
  for (const it of oldFindings || []) { const k = (it && it.k) || findingKey(it); if (!old.has(k)) old.set(k, it); }
  const seen = new Set();
  const added = [], unchanged = [];
  for (const f of newFindings || []) {
    const k = asPath ? findingKey({ ...f, path: asPath }) : ((f && f.k) || findingKey(f));
    if (seen.has(k)) continue;
    seen.add(k);
    (old.has(k) ? unchanged : added).push(f);
  }
  const fixed = [];
  for (const [k, it] of old) if (!seen.has(k)) fixed.push(it);
  return { added, unchanged, fixed };
}
