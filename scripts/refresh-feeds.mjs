#!/usr/bin/env node
/*
 * refresh-feeds.mjs - Darknode live threat-feed refresher.
 *
 * Zero external dependencies: uses the global fetch and node:fs only.
 *
 * Maps each threat-feed JSON under public/data/feeds/ that has a CLEAR,
 * PUBLIC, KEYLESS upstream to that upstream, fetches it, validates the
 * payload, reshapes it into Darknode's on-disk feed format, and writes it
 * back in place. Feeds with no obvious keyless upstream are intentionally
 * omitted from the map and left untouched (do not invent a source).
 *
 * Safety contract:
 *   - A single feed that fails to fetch/parse/validate is SKIPPED, not fatal.
 *   - The process exits non-zero only if EVERY configured feed failed.
 *   - A feed file is only rewritten when the transform yields valid data.
 *
 * Usage:   node scripts/refresh-feeds.mjs
 */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const FEEDS_DIR = join(HERE, "..", "public", "data", "feeds");
const FETCH_TIMEOUT_MS = 60000;
const UA = "darknode-feed-refresher/1.0 (+https://darknode.ai)";

const nowIso = () => new Date().toISOString();

// ---------------------------------------------------------------------------
// Transforms. Each receives the raw upstream response body (string) and returns
// a feed object in Darknode's on-disk shape { updated, source, count, data }.
// Throw on any malformed/empty payload so the caller skips the feed.
// ---------------------------------------------------------------------------

// CISA Known Exploited Vulnerabilities catalog.
// Upstream shape: { title, catalogVersion, dateReleased, count, vulnerabilities:[...] }
// On-disk shape keeps the 500 most recently added entries, matching the
// existing file and the tools that render it.
function transformCisaKev(body) {
  const src = JSON.parse(body);
  const vulns = Array.isArray(src.vulnerabilities) ? src.vulnerabilities : null;
  if (!vulns || !vulns.length) throw new Error("CISA KEV: missing or empty vulnerabilities array");
  const rows = vulns.map((v) => {
    const row = {
      cve: v.cveID,
      vendor: v.vendorProject,
      product: v.product,
      name: v.vulnerabilityName,
      description: v.shortDescription,
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      action: v.requiredAction,
    };
    if (v.knownRansomwareCampaignUse) row.ransomware = v.knownRansomwareCampaignUse;
    return row;
  });
  // Newest first by dateAdded (ISO yyyy-mm-dd sorts lexicographically).
  rows.sort((a, b) => String(b.dateAdded || "").localeCompare(String(a.dateAdded || "")));
  const data = rows.slice(0, 500);
  return { updated: nowIso(), source: "CISA KEV", count: data.length, data };
}

// stamparm/ipsum aggregated malicious-IP list (feeds the FireHOL + IPSUM view).
// Upstream is a plain-text file: comment lines beginning with '#', then
// "<ip>\t<hitcount>" rows already sorted by hit count (descending). The hit
// count doubles as the reputation score. Keeps the top 500.
function transformIpsum(body) {
  const rows = [];
  for (const line of body.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const parts = t.split(/\s+/);
    if (parts.length < 2) continue;
    const ip = parts[0];
    const score = parseInt(parts[1], 10);
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || !Number.isFinite(score)) continue;
    rows.push({ ip, score, source: "ipsum" });
  }
  if (!rows.length) throw new Error("IPSUM: no valid rows parsed");
  rows.sort((a, b) => b.score - a.score);
  const data = rows.slice(0, 500);
  return { updated: nowIso(), source: "FireHOL + stamparm IPSUM", count: data.length, data };
}

// US Treasury OFAC Specially Designated Nationals (SDN) list + alias export.
// Two public, keyless CSVs: SDN.CSV (primary names, no header) and ALT.CSV
// (a.k.a. / f.k.a. aliases). Reshaped into one entry per designated party with
// all its names folded in, for the browser-side Sanctions Screening tool.
// `altBody` is passed through transformOfac via a closure set up in refreshOne.
function makeOfacTransform(altGetter) {
  const cell = (line) => {
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
  return function transformOfac(body) {
    const byId = new Map();
    for (const line of body.split(/\r?\n/)) {
      if (!line.trim()) continue;
      const c = cell(line);
      if (c.length < 4 || !/^\d+$/.test(c[0])) continue;
      // remarks (c[11]) are not used by the screening tool and nearly double the
      // on-disk size, so they are intentionally omitted to keep the daily commit small.
      byId.set(c[0], { uid: c[0], name: c[1], type: c[2] || "", program: c[3] || "", names: [c[1]].filter(Boolean) });
    }
    if (!byId.size) throw new Error("OFAC SDN: no entries parsed");
    const altBody = altGetter();
    if (altBody) {
      for (const line of altBody.split(/\r?\n/)) {
        if (!line.trim()) continue;
        const c = cell(line);
        if (c.length < 4) continue;
        const ent = byId.get(c[0]);
        if (ent && c[3]) ent.names.push(c[3]);
      }
    }
    const data = [...byId.values()];
    return { updated: nowIso(), source: "US Treasury OFAC SDN", count: data.length, data };
  };
}

// ---------------------------------------------------------------------------
// Feed map. Only feeds with a clear public keyless upstream appear here.
//
// Deliberately NOT mapped (no clear keyless upstream; left frozen on purpose):
//   threat-iocs.json      - ThreatFox (abuse.ch) API now requires an Auth-Key.
//   botnet-c2.json        - Feodo Tracker (abuse.ch) now gated behind Auth-Key.
//   malware-urls.json     - URLhaus (abuse.ch) now gated behind Auth-Key.
//   ransomware-groups.json- curated "Darknode Threat Intelligence", no upstream.
// ---------------------------------------------------------------------------
const FEEDS = [
  {
    file: "cisa-kev.json",
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    transform: transformCisaKev,
  },
  {
    file: "malicious-ips.json",
    url: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    transform: transformIpsum,
  },
  {
    file: "ofac-sdn.json",
    url: "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV",
    alt: "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ALT.CSV",
    makeTransform: makeOfacTransform,
  },
];

async function fetchText(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      redirect: "follow",
      signal: ctrl.signal,
      headers: { "User-Agent": UA, Accept: "application/json, text/plain, */*" },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

async function refreshOne(feed) {
  const dest = join(FEEDS_DIR, feed.file);
  const body = await fetchText(feed.url);
  // A feed may carry an auxiliary file (e.g. OFAC aliases) and build its transform
  // from it. The aux fetch is best-effort: aliases improve recall but are not required.
  let transform = feed.transform;
  if (feed.makeTransform) {
    let altBody = "";
    if (feed.alt) { try { altBody = await fetchText(feed.alt); } catch (e) { console.error(`[warn] ${feed.file}: alias fetch failed (${e && e.message}); continuing without aliases`); } }
    transform = feed.makeTransform(() => altBody);
  }
  const out = transform(body);
  if (!out || !Array.isArray(out.data) || !out.data.length) {
    throw new Error("transform produced no data");
  }
  // Validate the serialized form round-trips as JSON before touching disk. Large
  // feeds (thousands of rows) are stored compact to keep the daily commit small;
  // small feeds stay pretty-printed for readable diffs.
  const serialized = (out.data.length > 2000 ? JSON.stringify(out) : JSON.stringify(out, null, 1)) + "\n";
  JSON.parse(serialized);
  writeFileSync(dest, serialized);
  return out.count;
}

async function main() {
  let ok = 0;
  let failed = 0;
  for (const feed of FEEDS) {
    try {
      const n = await refreshOne(feed);
      ok += 1;
      console.log(`[ok]   ${feed.file}: ${n} records from ${feed.url}`);
    } catch (err) {
      failed += 1;
      console.error(`[skip] ${feed.file}: ${err && err.message ? err.message : err}`);
    }
  }
  console.log(`\nrefresh complete: ${ok} ok, ${failed} skipped, ${FEEDS.length} total`);
  // Non-zero only when nothing at all refreshed.
  if (ok === 0) {
    console.error("all feeds failed to refresh");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("fatal:", err && err.stack ? err.stack : err);
  process.exit(1);
});
