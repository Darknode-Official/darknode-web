// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Sanctions screening engine — pure, deterministic, dependency-free.
//
// Screens payee / vendor / counterparty names against a sanctions list (the US
// Treasury OFAC SDN + alias exports, or any list in the normalized shape below).
// Every match is produced by explicit, auditable rules; the same inputs always
// yield byte-identical results, and nothing is uploaded — matching runs in the
// browser on data YOU load.
//
// Honesty: name matching against a watchlist is a SCREENING AID, not a compliance
// determination. A hit means "review this against the official source"; it is not
// proof the party is sanctioned. Common names produce false positives by design —
// the screen favours recall. Clearing a hit, and any blocking/reporting decision,
// is a human + legal responsibility (OFAC 50% rule, licences, etc. are out of scope).

// ------------------------------- normalization -------------------------------

// Business suffixes and honorifics carry little identifying signal and vary wildly
// across lists, so they are dropped before matching to cut noise.
const STOP = new Set([
  "the", "and", "of", "co", "company", "corp", "corporation", "inc", "incorporated",
  "llc", "ltd", "limited", "plc", "gmbh", "sa", "sas", "srl", "spa", "ag", "nv", "bv",
  "oao", "ooo", "pjsc", "ojsc", "jsc", "llp", "lp", "pte", "pty", "fze", "fzco",
  "group", "holding", "holdings", "trading", "international", "intl", "mr", "mrs",
  "ms", "dr", "aka", "fka", "nka", "al", "el", "bin", "ibn", "abu", "de", "da", "van",
  "von", "der", "den", "la", "le", "du", "des", "wal", "bint",
]);

// Latin-ize accents, strip punctuation, collapse whitespace, lower-case.
export function normName(s) {
  return String(s == null ? "" : s)
    .normalize("NFKD").replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// Significant tokens: normalized, stop-words and 1-char fragments removed.
export function tokens(s) {
  return normName(s).split(" ").filter((t) => t && t.length > 1 && !STOP.has(t));
}

// ------------------------------- distance -------------------------------

// Levenshtein edit distance (iterative, two-row). Used only on short tokens.
export function levenshtein(a, b) {
  a = String(a); b = String(b);
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    let cur = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
    }
    prev = cur;
  }
  return prev[b.length];
}

// Token similarity in [0,1]: 1 on exact, else 1 - edits/maxlen, floored at 0.
function tokenSim(a, b) {
  if (a === b) return 1;
  const d = levenshtein(a, b);
  const m = Math.max(a.length, b.length);
  return m ? Math.max(0, 1 - d / m) : 0;
}

// ------------------------------- scoring -------------------------------

// Score a query token set against one list-entry token set, in [0,100].
//
// For each query token we take its best near-match among the entry tokens
// (a token counts as matched when similarity >= TOK_T). The score is the
// coverage of query tokens weighted by match quality, with a small penalty
// when the entry has many more tokens than matched (guards against a short
// query matching one word of a long unrelated name).
const TOK_T = 0.8;
function scorePair(qToks, eToks) {
  if (!qToks.length || !eToks.length) return { score: 0, hits: [] };
  let sum = 0, matched = 0;
  const hits = [];
  for (const q of qToks) {
    let best = 0, bestTok = null;
    for (const e of eToks) {
      const s = tokenSim(q, e);
      if (s > best) { best = s; bestTok = e; }
    }
    if (best >= TOK_T) { matched++; sum += best; hits.push({ q, e: bestTok, s: +best.toFixed(3) }); }
  }
  if (!matched) return { score: 0, hits: [] };
  const coverage = sum / qToks.length;          // quality-weighted query coverage
  const specificity = matched / Math.max(qToks.length, eToks.length);
  // Blend: coverage dominates, specificity trims long-entry false hits.
  const score = Math.round(100 * (0.7 * coverage + 0.3 * specificity));
  return { score, hits };
}

export function band(score) {
  if (score >= 95) return "exact";
  if (score >= 85) return "strong";
  if (score >= 70) return "possible";
  return "weak";
}

// ------------------------------- list shape -------------------------------

// Normalized list entry: { uid, name, type, program, remarks, names:[all names] }.
// buildIndex precomputes token sets so screening many queries is cheap.
export function buildIndex(entries) {
  return (entries || []).map((e) => ({
    ...e,
    _toks: (e.names && e.names.length ? e.names : [e.name]).map((n) => ({ raw: n, t: tokens(n) })),
  }));
}

// Screen one query name against a built index. Returns matches >= minScore,
// best first, capped at `limit`.
export function screenName(query, index, opts = {}) {
  const minScore = opts.minScore == null ? 70 : opts.minScore;
  const limit = opts.limit == null ? 20 : opts.limit;
  const qToks = tokens(query);
  if (!qToks.length) return [];
  const out = [];
  for (const e of index) {
    let best = 0, bestName = e.name, bestHits = [];
    for (const nm of e._toks) {
      const { score, hits } = scorePair(qToks, nm.t);
      if (score > best) { best = score; bestName = nm.raw; bestHits = hits; }
    }
    if (best >= minScore) {
      out.push({ uid: e.uid, name: e.name, matchedName: bestName, type: e.type,
        program: e.program, remarks: e.remarks, score: best, band: band(best), hits: bestHits });
    }
  }
  out.sort((a, b) => b.score - a.score || String(a.name).localeCompare(String(b.name)));
  return out.slice(0, limit);
}

// Screen a batch of { id?, name } rows. Returns one result row per input, each
// with its matches (empty when clear). Deterministic order = input order.
export function screenBatch(rows, index, opts = {}) {
  return (rows || []).map((r, i) => {
    const name = typeof r === "string" ? r : (r && r.name) || "";
    const id = (r && r.id) != null ? r.id : i + 1;
    const matches = screenName(name, index, opts);
    const top = matches[0] || null;
    return { id, name, matches, hit: !!top, topScore: top ? top.score : 0, topBand: top ? top.band : "clear" };
  });
}

// --------------------------- OFAC export parsing ---------------------------

// Parse an OFAC SDN.CSV body into normalized entries. The SDN file has no header;
// columns are: ent_num, SDN_Name, SDN_Type, Program, Title, Call_Sign, Vess_type,
// Tonnage, GRT, Vess_flag, Vess_owner, Remarks. The sentinel "-0- " means empty.
// An optional ALT.CSV body (ent_num, alt_num, alt_type, alt_name, remarks) folds
// aliases into the matching entry's name list.
export function parseOfac(sdnBody, altBody) {
  const cells = (line) => {
    const out = []; let f = "", q = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (q) { if (c === '"') { if (line[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
      else if (c === '"') q = true;
      else if (c === ",") { out.push(f); f = ""; }
      else f += c;
    }
    out.push(f);
    return out.map((x) => { const t = x.trim(); return t === "-0-" ? "" : t; });
  };
  const byId = new Map();
  for (const line of String(sdnBody || "").split(/\r?\n/)) {
    if (!line.trim()) continue;
    const c = cells(line);
    if (c.length < 4) continue;
    const uid = c[0];
    if (!/^\d+$/.test(uid)) continue;
    byId.set(uid, {
      uid, name: c[1], type: c[2] || "", program: c[3] || "", remarks: c[11] || "",
      names: [c[1]].filter(Boolean),
    });
  }
  if (altBody) {
    for (const line of String(altBody).split(/\r?\n/)) {
      if (!line.trim()) continue;
      const c = cells(line);
      if (c.length < 4) continue;
      const ent = byId.get(c[0]);
      if (ent && c[3]) ent.names.push(c[3]);
    }
  }
  return [...byId.values()];
}

// ------------------------------- self-test -------------------------------

export function selfTest() {
  const results = [];
  const ok = (name, cond) => results.push({ name, pass: !!cond });

  ok("normName strips accents + punctuation", normName("Müller & Co., Ltd.") === "muller co ltd");
  ok("tokens drop stopwords/suffixes", JSON.stringify(tokens("Acme Trading Co., Ltd.")) === JSON.stringify(["acme"]));
  ok("levenshtein basic", levenshtein("kitten", "sitting") === 3);

  const list = buildIndex([
    { uid: "1", name: "VLADIMIR PUTIN", type: "individual", program: "RUSSIA", names: ["VLADIMIR PUTIN", "Vladimir Vladimirovich PUTIN"] },
    { uid: "2", name: "ACME SHIPPING LLC", type: "entity", program: "SDGT", names: ["ACME SHIPPING LLC"] },
    { uid: "3", name: "JOHN SMITH", type: "individual", program: "NARCO", names: ["JOHN SMITH"] },
  ]);

  const exact = screenName("Vladimir Putin", list);
  ok("exact name scores >=95", exact[0] && exact[0].uid === "1" && exact[0].score >= 95);

  const typo = screenName("Vladmir Putn", list);
  ok("typo still matches", typo[0] && typo[0].uid === "1" && typo[0].score >= 70);

  const alias = screenName("Vladimir Vladimirovich Putin", list);
  ok("alias via name list matches", alias.some((m) => m.uid === "1"));

  const suffixOnly = screenName("Acme Logistics Inc", list);
  ok("different entity, shared suffix only -> no false hit", !suffixOnly.some((m) => m.uid === "2"));

  const clear = screenName("Totally Unrelated Widgets", list);
  ok("unrelated name is clear", clear.length === 0);

  const batch = screenBatch([{ id: "a", name: "John Smith" }, { id: "b", name: "Jane Doe" }], list);
  ok("batch preserves order + flags hits", batch.length === 2 && batch[0].id === "a" && batch[0].hit && !batch[1].hit);

  // determinism
  const r1 = JSON.stringify(screenBatch(["John Smith", "Acme Shipping LLC"], list));
  const r2 = JSON.stringify(screenBatch(["John Smith", "Acme Shipping LLC"], list));
  ok("deterministic", r1 === r2);

  // OFAC parse
  const sdn = '36,"AEROCARIBBEAN AIRLINES",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- \n' +
              '306,"BANCO NACIONAL DE CUBA","entity","CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"a.k.a. BNC"';
  const alt = '36,12,"aka","AERO-CARIBBEAN",-0- ';
  const parsed = parseOfac(sdn, alt);
  ok("parseOfac reads SDN rows", parsed.length === 2 && parsed[0].name === "AEROCARIBBEAN AIRLINES");
  ok("parseOfac folds aliases", parsed[0].names.includes("AERO-CARIBBEAN"));
  ok("parseOfac empties -0- sentinel", parsed[0].type === "");

  return { pass: results.every((r) => r.pass), results };
}
