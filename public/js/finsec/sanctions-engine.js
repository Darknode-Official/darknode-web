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
  let score = Math.round(100 * (0.7 * coverage + 0.3 * specificity));
  // A single-token query (e.g. a lone surname) is inherently low-specificity and
  // matches many multi-word entries; damp it below the "strong" band so it still
  // surfaces for review (recall preserved) without raising a strong-match alert.
  if (qToks.length === 1 && eToks.length > 1) score = Math.min(score, 78);
  return { score, hits };
}

export function band(score) {
  if (score >= 95) return "exact";
  if (score >= 85) return "strong";
  if (score >= 70) return "possible";
  return "weak";
}

// ------------------------------- list-field filters -------------------------------

// Collapse OFAC's SDN_Type into a stable class. A blank type in the SDN file means an
// entity (the common case), so "" maps to "entity"; individuals/vessels/aircraft keep
// their own class. Used by the entity-type filter so a dropdown stays tiny and honest.
export function entityClass(t) {
  const s = String(t == null ? "" : t).trim().toLowerCase();
  if (!s) return "entity";
  if (s.startsWith("indiv")) return "individual";
  if (s.startsWith("vessel")) return "vessel";
  if (s.startsWith("aircraft")) return "aircraft";
  return s;
}

// Normalize a caller's entity-type filter (string | string[] | "all" | null) into a Set
// of classes to keep, or null for "no filter". Empty / "all" means no filter.
function normalizeTypeFilter(types) {
  if (!types) return null;
  const arr = Array.isArray(types) ? types : [types];
  const set = new Set(arr.map((t) => String(t).trim().toLowerCase()).filter((t) => t && t !== "all"));
  return set.size ? set : null;
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
// opts: { minScore, limit, types, program }
//   minScore  minimum match score to report (default 70)
//   limit     cap on matches returned, best first (default 20)
//   types     entity-type filter: class name | class[] | "all" | null (no filter)
//   program   case-insensitive substring an entry's program must contain (optional)
export function screenName(query, index, opts = {}) {
  const minScore = opts.minScore == null ? 70 : opts.minScore;
  const limit = opts.limit == null ? 20 : opts.limit;
  const typeFilter = normalizeTypeFilter(opts.types);
  const progFilter = opts.program ? String(opts.program).trim().toLowerCase() : "";
  const qToks = tokens(query);
  if (!qToks.length) return [];
  const out = [];
  for (const e of index) {
    // Pre-filter on list fields the feed actually carries, before the (costly) scoring.
    if (typeFilter && !typeFilter.has(entityClass(e.type))) continue;
    if (progFilter && !String(e.program || "").toLowerCase().includes(progFilter)) continue;
    let best = 0, bestName = e.name, bestHits = [];
    for (const nm of e._toks) {
      const { score, hits } = scorePair(qToks, nm.t);
      if (score > best) { best = score; bestName = nm.raw; bestHits = hits; }
    }
    if (best >= minScore) {
      // Secondary identifiers (program, type, and — only if the loaded list carries
      // them — DOB / nationality) ride along so common names can be disambiguated.
      out.push({ uid: e.uid, name: e.name, matchedName: bestName, type: e.type,
        program: e.program, remarks: e.remarks || "", dob: e.dob || "", nationality: e.nationality || "",
        score: best, band: band(best), hits: bestHits });
    }
  }
  out.sort((a, b) => b.score - a.score || String(a.name).localeCompare(String(b.name)));
  return out.slice(0, limit);
}

function screenRow(r, i, index, opts) {
  const name = typeof r === "string" ? r : (r && r.name) || "";
  const id = (r && r.id) != null ? r.id : i + 1;
  const matches = screenName(name, index, opts);
  const top = matches[0] || null;
  return { id, name, matches, hit: !!top, topScore: top ? top.score : 0, topBand: top ? top.band : "clear" };
}

// Screen a batch of { id?, name } rows. Returns one result row per input, each
// with its matches (empty when clear). Deterministic order = input order.
export function screenBatch(rows, index, opts = {}) {
  return (rows || []).map((r, i) => screenRow(r, i, index, opts));
}

// Async batch: identical output to screenBatch but yields to the event loop every
// `opts.chunk` rows (default 25) so screening a long name list against the ~19k-entry
// OFAC index never blocks the UI thread. `onProgress(done, total)` is optional.
export async function screenBatchAsync(rows, index, opts = {}, onProgress) {
  const list = rows || [];
  const chunk = opts.chunk && opts.chunk > 0 ? opts.chunk : 25;
  const out = [];
  for (let i = 0; i < list.length; i++) {
    out.push(screenRow(list[i], i, index, opts));
    if ((i + 1) % chunk === 0) {
      if (typeof onProgress === "function") onProgress(i + 1, list.length);
      await new Promise((res) => setTimeout(res, 0)); // hand the frame back
    }
  }
  if (typeof onProgress === "function") onProgress(list.length, list.length);
  return out;
}

// --------------------------- Security Graph sink ---------------------------

// Screen rows -> common Finding shape (core/sink-map.js), one per screened name with
// a hit, keyed by the normalized name so re-screening the same counterparty merges.
// The counterparty is a VENDOR asset (the party being paid or contracted). Severity
// follows the match band; the analyst's disposition sets the status (cleared ->
// resolved, escalate -> investigating) and a confirmed match is always critical.
// opts: { dispositions: { [name]: "pending"|"cleared"|"escalate"|"confirmed" }, listSource, listUpdated }
const SINK_SEV = { exact: "critical", strong: "high", possible: "medium", weak: "low" };
const SINK_STATUS = { pending: "open", escalate: "investigating", confirmed: "open", cleared: "resolved" };
export function toSinkFindings(rows, opts = {}) {
  const disp = opts.dispositions || {};
  return (rows || []).filter((r) => r && r.hit && r.matches.length).map((r) => {
    const top = r.matches[0], d = disp[r.name] || "pending";
    const list = opts.listSource || "OFAC SDN";
    return {
      id: "sanctions:" + normName(r.name),
      title: `Sanctions list match: ${r.name}`,
      severity: d === "confirmed" ? "critical" : SINK_SEV[top.band] || "medium",
      confidence: d === "confirmed" ? "confirmed" : top.band === "exact" || top.band === "strong" ? "likely" : "review",
      status: SINK_STATUS[d] || "open", category: "sanctions",
      description: `"${r.name}" scored ${top.score} (${top.band}) against ${list} entry "${top.name}"${top.matchedName && top.matchedName !== top.name ? ` (alias "${top.matchedName}")` : ""}${top.program ? `, program ${top.program}` : ""}. Disposition: ${d}. Name matching is a screening aid, not a determination: verify identifiers against the official list.`,
      recommendation: d === "cleared" ? "Cleared by the analyst; keep the screening record with the disposition and the list version it ran against."
        : "Hold payments and onboarding for this counterparty, compare secondary identifiers (date of birth, nationality, address, registration number) with the official entry, and escalate to compliance before any blocking or reporting decision.",
      evidence: r.matches.slice(0, 10).map((m) => ({ list, listUpdated: opts.listUpdated || "", uid: m.uid, entry: m.name, matchedName: m.matchedName, type: m.type || "", program: m.program || "", score: m.score, band: m.band, dob: m.dob || "", nationality: m.nationality || "" })),
      evidenceCount: r.matches.length,
      assets: [{ type: "VENDOR", name: r.name, data: { role: "counterparty", sanctionsBand: top.band, disposition: d } }],
      tags: ["ofac", top.band],
    };
  });
}

// --------------------------- OFAC export parsing ---------------------------

// Parse an OFAC SDN.CSV body into normalized entries. The SDN file has no header;
// columns are: ent_num, SDN_Name, SDN_Type, Program, Title, Call_Sign, Vess_type,
// Tonnage, GRT, Vess_flag, Vess_owner, Remarks. The sentinel "-0- " means empty.
// An optional ALT.CSV body (ent_num, alt_num, alt_type, alt_name, remarks) folds
// aliases into the matching entry's name list.
// OFAC embeds DOB / nationality (and much else) inside the free-text Remarks field,
// e.g. "DOB 05 Dec 1960; nationality Iran; Gender Male". Pull those two out so common
// personal names can be disambiguated. Returns {} values when absent — never fabricated.
// (The daily same-origin JSON mirror drops Remarks for size, so these are populated only
// when a raw OFAC export WITH remarks is parsed; the UI shows only what is present.)
export function secondaryIds(remarks) {
  const s = String(remarks == null ? "" : remarks);
  const grab = (re) => { const m = [...s.matchAll(re)].map((x) => x[1].trim()).filter(Boolean); return [...new Set(m)].join("; "); };
  return {
    dob: grab(/\bDOB\s+([^;]+)/gi),
    nationality: grab(/\bnationalit(?:y|ies)\s+([^;]+)/gi),
  };
}

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
    const remarks = c[11] || "";
    const sec = secondaryIds(remarks);
    byId.set(uid, {
      uid, name: c[1], type: c[2] || "", program: c[3] || "", remarks,
      dob: sec.dob, nationality: sec.nationality,
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
  ok("tokens drop stopwords/suffixes", JSON.stringify(tokens("Darknode Trading Co., Ltd.")) === JSON.stringify(["darknode"]));
  ok("levenshtein basic", levenshtein("kitten", "sitting") === 3);

  const list = buildIndex([
    { uid: "1", name: "VLADIMIR PUTIN", type: "individual", program: "RUSSIA", names: ["VLADIMIR PUTIN", "Vladimir Vladimirovich PUTIN"] },
    { uid: "2", name: "DARKNODE SHIPPING LLC", type: "entity", program: "SDGT", names: ["DARKNODE SHIPPING LLC"] },
    { uid: "3", name: "TEST USER", type: "individual", program: "NARCO", names: ["TEST USER"] },
  ]);

  const exact = screenName("Vladimir Putin", list);
  ok("exact name scores >=95", exact[0] && exact[0].uid === "1" && exact[0].score >= 95);

  const typo = screenName("Vladmir Putn", list);
  ok("typo still matches", typo[0] && typo[0].uid === "1" && typo[0].score >= 70);

  const alias = screenName("Vladimir Vladimirovich Putin", list);
  ok("alias via name list matches", alias.some((m) => m.uid === "1"));

  const suffixOnly = screenName("Darknode Logistics Inc", list);
  ok("different entity, shared suffix only -> no false hit", !suffixOnly.some((m) => m.uid === "2"));

  const clear = screenName("Totally Unrelated Widgets", list);
  ok("unrelated name is clear", clear.length === 0);

  const batch = screenBatch([{ id: "a", name: "Test User" }, { id: "b", name: "Unlisted Person" }], list);
  ok("batch preserves order + flags hits", batch.length === 2 && batch[0].id === "a" && batch[0].hit && !batch[1].hit);

  // determinism
  const r1 = JSON.stringify(screenBatch(["Test User", "Darknode Shipping LLC"], list));
  const r2 = JSON.stringify(screenBatch(["Test User", "Darknode Shipping LLC"], list));
  ok("deterministic", r1 === r2);

  // OFAC parse
  const sdn = '36,"AEROCARIBBEAN AIRLINES",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- \n' +
              '306,"BANCO NACIONAL DE CUBA","entity","CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"a.k.a. BNC"';
  const alt = '36,12,"aka","AERO-CARIBBEAN",-0- ';
  const parsed = parseOfac(sdn, alt);
  ok("parseOfac reads SDN rows", parsed.length === 2 && parsed[0].name === "AEROCARIBBEAN AIRLINES");
  ok("parseOfac folds aliases", parsed[0].names.includes("AERO-CARIBBEAN"));
  ok("parseOfac empties -0- sentinel", parsed[0].type === "");

  // entity-type filter: PUTIN is an individual, DARKNODE SHIPPING an entity (blank type).
  const indivOnly = screenName("Darknode Shipping LLC", list, { types: ["individual"], minScore: 60 });
  ok("entity-type filter excludes non-matching class", !indivOnly.some((m) => m.uid === "2"));
  const entityOnly = screenName("Darknode Shipping LLC", list, { types: ["entity"], minScore: 60 });
  ok("entity-type filter keeps matching class", entityOnly.some((m) => m.uid === "2"));

  // program filter: only entries whose program contains the substring survive.
  const narco = screenName("Test User", list, { program: "narco", minScore: 60 });
  ok("program filter keeps matching program", narco.some((m) => m.uid === "3"));
  ok("program filter drops non-matching program", screenName("Test User", list, { program: "russia", minScore: 60 }).length === 0);

  // secondary identifiers pulled from remarks (never fabricated when absent).
  const sec = secondaryIds("DOB 05 Dec 1960; POB Tehran; nationality Iran; Gender Male");
  ok("secondaryIds extracts DOB", sec.dob === "05 Dec 1960");
  ok("secondaryIds extracts nationality", sec.nationality === "Iran");
  ok("secondaryIds empty when absent", secondaryIds("").dob === "" && secondaryIds("").nationality === "");

  ok("entityClass maps blank type to entity", entityClass("") === "entity" && entityClass("Individual") === "individual");

  return { pass: results.every((r) => r.pass), results };
}
