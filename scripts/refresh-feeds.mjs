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
 *          node scripts/refresh-feeds.mjs --only epss-top,eol-products
 *            (--only takes feed names = file names without .json; default is all)
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { gunzipSync } from "node:zlib";
import { parseEpssCsv, selectEpssTop, compactEolProduct, EOL_PRODUCTS } from "./lib/feeds-lib.mjs";

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

// KEV entries added in the last 14 days, for the weekly email digest. Kept tiny so the
// free-plan Worker can read it inside its CPU limit (the 500-row file is ~400 KB).
function transformCisaKevRecent(body) {
  const src = JSON.parse(body);
  const vulns = Array.isArray(src.vulnerabilities) ? src.vulnerabilities : null;
  if (!vulns || !vulns.length) throw new Error("CISA KEV: missing or empty vulnerabilities array");
  const since = new Date(Date.now() - 14 * 86400000).toISOString().slice(0, 10);
  const data = vulns.filter((v) => String(v.dateAdded || "") >= since).map((v) => ({
    cve: v.cveID, vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName,
    dateAdded: v.dateAdded, dueDate: v.dueDate, ransomware: v.knownRansomwareCampaignUse === "Known",
  })).sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)));
  return { updated: nowIso(), source: "CISA KEV (last 14 days)", catalogVersion: src.catalogVersion || "", since, count: data.length, data };
}

// Full KEV catalog, compact (cve + dates + ransomware flag only), for tools that
// MATCH CVEs against KEV (vulnimport, EPSS union). cisa-kev.json stays the 500
// newest with descriptions for the dashboards that render it.
function transformCisaKevIndex(body) {
  const src = JSON.parse(body);
  const vulns = Array.isArray(src.vulnerabilities) ? src.vulnerabilities : null;
  if (!vulns || !vulns.length) throw new Error("CISA KEV: missing or empty vulnerabilities array");
  const data = vulns
    .filter((v) => v && v.cveID)
    .map((v) => {
      const row = { cve: v.cveID, dateAdded: v.dateAdded, dueDate: v.dueDate };
      if (v.knownRansomwareCampaignUse === "Known") row.ransomware = "Known";
      return row;
    })
    .sort((a, b) => a.cve.localeCompare(b.cve));
  return { updated: nowIso(), source: "CISA KEV (full catalog index)", catalogVersion: src.catalogVersion || "", count: data.length, data };
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

// FIRST EPSS (Exploit Prediction Scoring System) daily scores.
// Upstream is a ~390k-row gzipped CSV (one row per CVE). Only the top-N by
// EPSS (EPSS_TOP_N) plus every CVE in the just-written cisa-kev-index.json (full KEV) are shipped, so
// the browser gets a ~320 KB file that still covers everything known-exploited.
const EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz";
const EPSS_TOP_N = 4500; // + full-KEV union (cisa-kev-index) lands ~5.4k rows, ~320 KB

function readKevCves() {
  try {
    let file = join(FEEDS_DIR, "cisa-kev-index.json");
    if (!existsSync(file)) file = join(FEEDS_DIR, "cisa-kev.json");
    const kev = JSON.parse(readFileSync(file, "utf8"));
    return new Set((Array.isArray(kev.data) ? kev.data : []).map((r) => r && r.cve).filter(Boolean));
  } catch (e) {
    console.error(`[warn] epss-top: could not read cisa-kev.json (${e && e.message}); continuing without KEV union`);
    return new Set();
  }
}

async function loadEpss() {
  const gz = await fetchBytes(EPSS_URL);
  return gunzipSync(gz).toString("utf8");
}

function transformEpss(body) {
  const { modelVersion, scoreDate, rows } = parseEpssCsv(body);
  const data = selectEpssTop(rows, readKevCves(), EPSS_TOP_N);
  if (!data.length) throw new Error("EPSS: selection produced no rows");
  return { updated: nowIso(), source: "FIRST EPSS", model: modelVersion, scoreDate, count: data.length, data };
}

// endoflife.date product lifecycle data.
// all.json lists every known slug; the allowlist in feeds-lib is intersected
// with it (misses are logged, never fatal) and each product is then fetched
// sequentially with a short pause so the daily job stays polite to the API.
const EOL_API = "https://endoflife.date/api";
const EOL_PAUSE_MS = 150;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function loadEol() {
  const all = JSON.parse(await fetchText(`${EOL_API}/all.json`));
  if (!Array.isArray(all) || !all.length) throw new Error("EOL: all.json is not a non-empty array");
  const known = new Set(all);
  const missing = EOL_PRODUCTS.filter((s) => !known.has(s));
  if (missing.length) console.error(`[warn] eol-products: ${missing.length} allowlisted slug(s) not on endoflife.date: ${missing.join(", ")}`);
  const products = [];
  for (const slug of EOL_PRODUCTS) {
    if (!known.has(slug)) continue;
    try {
      products.push(compactEolProduct(JSON.parse(await fetchText(`${EOL_API}/${slug}.json`)), slug));
    } catch (e) {
      console.error(`[warn] eol-products: ${slug} skipped (${e && e.message})`);
    }
    await sleep(EOL_PAUSE_MS);
  }
  return products;
}

function transformEol(products) {
  if (!Array.isArray(products) || !products.length) throw new Error("EOL: no products loaded");
  return { updated: nowIso(), source: "endoflife.date", count: products.length, data: products };
}

// ---------------------------------------------------------------------------
// Feed map. Only feeds with a clear public keyless upstream appear here.
//
// Optional per-feed hooks:
//   load:    async () => body  - replaces the single fetchText(url) step so a
//            feed can do multi-request or binary loading; `url` stays as the
//            documented primary upstream for logging.
//   compact: true              - always write one-line JSON (default: only
//            when data.length > 2000).
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
    file: "cisa-kev-index.json",
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    transform: transformCisaKevIndex,
  },
  {
    file: "kev-recent.json",
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    transform: transformCisaKevRecent,
  },
  {
    file: "malicious-ips.json",
    url: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    transform: transformIpsum,
  },

  // Listed after cisa-kev on purpose: the EPSS selection unions in the KEV
  // CVEs from the cisa-kev.json written earlier in the same run.
  {
    file: "epss-top.json",
    url: EPSS_URL,
    load: loadEpss,
    transform: transformEpss,
  },
  {
    file: "eol-products.json",
    url: `${EOL_API}/all.json`,
    load: loadEol,
    transform: transformEol,
    compact: true,
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

// Binary twin of fetchText (gzip, zip, etc.). Returns a Node Buffer.
async function fetchBytes(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      redirect: "follow",
      signal: ctrl.signal,
      headers: { "User-Agent": UA, Accept: "application/octet-stream, */*" },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    return Buffer.from(await res.arrayBuffer());
  } finally {
    clearTimeout(timer);
  }
}

async function refreshOne(feed) {
  const dest = join(FEEDS_DIR, feed.file);
  const body = feed.load ? await feed.load() : await fetchText(feed.url);
  // A feed may carry an auxiliary file (e.g. an alias list) and build its transform
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
  const serialized = (feed.compact || out.data.length > 2000 ? JSON.stringify(out) : JSON.stringify(out, null, 1)) + "\n";
  JSON.parse(serialized);
  writeFileSync(dest, serialized);
  return out.count;
}

// `--only a,b` restricts the run to the named feeds (file name sans .json).
// Unknown names are reported and the run proceeds with the known ones.
function selectFeeds(argv) {
  const i = argv.indexOf("--only");
  const inline = argv.find((a) => a.startsWith("--only="));
  const raw = i >= 0 ? argv[i + 1] : inline ? inline.slice("--only=".length) : null;
  if (raw == null) return FEEDS;
  const names = raw.split(",").map((s) => s.trim()).filter(Boolean);
  const byName = new Map(FEEDS.map((f) => [f.file.replace(/\.json$/, ""), f]));
  const unknown = names.filter((n) => !byName.has(n));
  if (unknown.length) console.error(`[warn] --only: unknown feed(s) ignored: ${unknown.join(", ")}`);
  return names.filter((n) => byName.has(n)).map((n) => byName.get(n));
}

async function main() {
  let ok = 0;
  let failed = 0;
  const feeds = selectFeeds(process.argv.slice(2));
  if (!feeds.length) {
    console.error("no feeds selected");
    process.exit(1);
  }
  for (const feed of feeds) {
    try {
      const n = await refreshOne(feed);
      ok += 1;
      console.log(`[ok]   ${feed.file}: ${n} records from ${feed.url}`);
    } catch (err) {
      failed += 1;
      console.error(`[skip] ${feed.file}: ${err && err.message ? err.message : err}`);
    }
  }
  console.log(`\nrefresh complete: ${ok} ok, ${failed} skipped, ${feeds.length} total`);
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
