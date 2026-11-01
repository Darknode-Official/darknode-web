// CISA Known Exploited Vulnerabilities, for tools that list recent KEV entries.
//
// First choice: the same-origin copy the daily refresh-feeds workflow writes from the real
// CISA catalog (the newest 500 entries with full fields, plus the full-catalog count from
// the compact index). Fetching the live ~1.8 MB catalog through the edge proxy overruns the
// free Worker's CPU limit (Cloudflare error 1102, sent without CORS headers), so the live
// path is only a fallback. Rows use CISA's own field names, so callers need no mapping.
import { dnFetchJSON } from "/js/net.js";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
let _p = null, _at = 0;

async function loadStatic() {
  const [recent, index] = await Promise.all([
    fetch("/data/feeds/cisa-kev.json", { cache: "no-cache" }).then((r) => (r.ok ? r.json() : null)),
    fetch("/data/feeds/cisa-kev-index.json", { cache: "no-cache" }).then((r) => (r.ok ? r.json() : null)).catch(() => null),
  ]);
  const rows = (recent && Array.isArray(recent.data) && recent.data) || [];
  if (!rows.length) throw new Error("local KEV copy missing");
  const vulnerabilities = rows.filter((v) => v && v.cve).map((v) => ({
    cveID: v.cve, vendorProject: v.vendor || "", product: v.product || "", vulnerabilityName: v.name || "",
    shortDescription: v.description || "", dateAdded: v.dateAdded || "", dueDate: v.dueDate || "",
    requiredAction: v.action || "", knownRansomwareCampaignUse: v.ransomware || "Unknown",
  }));
  const count = (index && parseInt(index.count, 10)) || vulnerabilities.length;
  return { vulnerabilities, count, catalogVersion: (index && index.catalogVersion) || "", updated: recent.updated || "", source: "local" };
}

async function loadLive() {
  const d = await dnFetchJSON(KEV_URL, { timeout: 25000, max: 4000000 });
  const vulnerabilities = (d && d.vulnerabilities) || [];
  if (!vulnerabilities.length) throw new Error("live KEV catalog empty");
  return { vulnerabilities, count: parseInt(d.count, 10) || vulnerabilities.length, catalogVersion: d.catalogVersion || "", updated: d.dateReleased || "", source: "live" };
}

// { vulnerabilities, count (full catalog size), catalogVersion, updated, source }.
// Held 10 minutes; a failure is not cached.
export function loadKevCatalog() {
  if (_p && Date.now() - _at < 600000) return _p;
  _at = Date.now();
  _p = loadStatic().catch(() => loadLive()).catch((e) => { _p = null; throw e; });
  return _p;
}
