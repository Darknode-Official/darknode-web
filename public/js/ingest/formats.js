// Ingest format parsers (Deck D5). PURE — no DOM, no network. Maps the formats a CI
// pipeline or scanner emits into the Deck Finding contract (see core/sink-map.js), so
// `POST /api/v1/ingest` and the browser drag-drop share one mapping. The findings are
// then published through the normal sink, exactly like a tool's own results.
//
// Finding contract (subset we populate):
//   { title, severity, category?, description?, recommendation?, status?,
//     controls?:[{framework,id}], assets?:[{type,name,data?}], tags?, evidence? }
//
// Beyond the three JSON formats below, any native scanner export the vulnimport engine
// already parses (Nessus/Qualys/OpenVAS XML, Trivy/Grype/Snyk JSON, Defender/Rapid7/CSV)
// falls through to that engine, which emits the same Finding contract. Same engine the
// browser drop zone uses — no second, divergent parser.
import { detectFormat as vulnDetectFormat, analyze as vulnAnalyze, FORMATS as VULN_FORMATS } from "../exposure/vulnimport-engine.js";

const SEV = ["critical", "high", "medium", "low", "info"];
const str = (v) => String(v == null ? "" : v).trim();
const normSev = (v) => { const s = str(v).toLowerCase(); return SEV.includes(s) ? s : ({ error: "high", warning: "medium", note: "low", none: "info", moderate: "medium", informational: "info", unknown: "info" }[s] || null); };
// CVSS-style 0–10 numeric severity (SARIF security-severity, CycloneDX ratings).
const sevFromScore = (n) => { const x = Number(n); if (!Number.isFinite(x)) return null; if (x >= 9) return "critical"; if (x >= 7) return "high"; if (x >= 4) return "medium"; if (x > 0) return "low"; return "info"; };

// -------- detection --------
export function detectFormat(obj) {
  if (!obj || typeof obj !== "object") return "unknown";
  if (Array.isArray(obj)) return obj.every((x) => x && typeof x === "object" && "title" in x) ? "findings" : "unknown";
  if (Array.isArray(obj.runs) && (obj.version === "2.1.0" || /sarif/i.test(str(obj.$schema)))) return "sarif";
  if (obj.bomFormat === "CycloneDX" || (Array.isArray(obj.vulnerabilities) && obj.bomFormat)) return "cyclonedx";
  if (Array.isArray(obj.findings)) return "findings";
  if ("title" in obj && ("severity" in obj || "category" in obj)) return "findings";
  return "unknown";
}

// -------- Finding JSON contract (passthrough + validate) --------
export function parseFindingContract(obj) {
  const list = Array.isArray(obj) ? obj : Array.isArray(obj && obj.findings) ? obj.findings : (obj && "title" in obj ? [obj] : []);
  const findings = [], errors = [];
  list.forEach((f, i) => {
    if (!f || typeof f !== "object") { errors.push(`item ${i}: not an object`); return; }
    const title = str(f.title);
    if (!title) { errors.push(`item ${i}: missing title`); return; }
    const sev = normSev(f.severity) || "info";
    const out = { title, severity: sev };
    if (f.category) out.category = str(f.category);
    if (f.description) out.description = str(f.description);
    if (f.recommendation) out.recommendation = str(f.recommendation);
    if (f.status) out.status = str(f.status);
    if (Array.isArray(f.controls)) out.controls = f.controls.filter((c) => c && c.id).map((c) => ({ framework: str(c.framework), id: str(c.id) }));
    if (Array.isArray(f.assets)) out.assets = f.assets.filter((a) => a && a.name).map((a) => ({ type: str(a.type).toUpperCase() || "ASSET", name: str(a.name), data: a.data || {} }));
    if (Array.isArray(f.tags)) out.tags = f.tags.map(str).filter(Boolean);
    if (Array.isArray(f.evidence)) out.evidence = f.evidence;
    findings.push(out);
  });
  return { findings, errors };
}

// -------- SARIF 2.1.0 --------
export function parseSarif(obj) {
  const findings = [], errors = [];
  const runs = (obj && obj.runs) || [];
  for (const run of runs) {
    const tool = (run.tool && run.tool.driver) || {};
    const rulesById = new Map();
    for (const r of (tool.rules || [])) if (r && r.id) rulesById.set(r.id, r);
    for (const res of (run.results || [])) {
      const rule = rulesById.get(res.ruleId) || {};
      const title = str((res.message && (res.message.text || res.message.id)) || rule.name || rule.id || res.ruleId) || "SARIF result";
      // severity: numeric security-severity wins, else level, else rule default.
      const secSev = (res.properties && res.properties["security-severity"]) || (rule.properties && rule.properties["security-severity"]);
      const level = res.level || (rule.defaultConfiguration && rule.defaultConfiguration.level);
      const severity = sevFromScore(secSev) || normSev(level) || "medium";
      const assets = [];
      for (const loc of (res.locations || [])) {
        const uri = loc && loc.physicalLocation && loc.physicalLocation.artifactLocation && loc.physicalLocation.artifactLocation.uri;
        const line = loc && loc.physicalLocation && loc.physicalLocation.region && loc.physicalLocation.region.startLine;
        if (uri) assets.push({ type: "ASSET", name: str(uri), data: line ? { line } : {} });
      }
      const f = { title, severity, category: str(res.ruleId || rule.id) || (tool.name ? str(tool.name) : "sarif"), tags: ["sarif", ...(tool.name ? [str(tool.name).toLowerCase()] : [])] };
      const help = rule.help && (rule.help.text || rule.help.markdown);
      const desc = rule.fullDescription && rule.fullDescription.text;
      if (desc) f.description = str(desc);
      if (help) f.recommendation = str(help);
      if (assets.length) f.assets = assets;
      findings.push(f);
    }
  }
  return { findings, errors };
}

// -------- CycloneDX (vulnerabilities) --------
export function parseCycloneDX(obj) {
  const findings = [], errors = [];
  const comps = new Map();
  for (const c of (obj.components || [])) if (c && c["bom-ref"]) comps.set(c["bom-ref"], c);
  for (const v of (obj.vulnerabilities || [])) {
    const id = str(v.id) || "vuln";
    const ratings = v.ratings || [];
    const score = ratings.map((r) => r.score).find((s) => s != null && s !== "" && Number.isFinite(Number(s)));
    const named = ratings.map((r) => r.severity).find(Boolean);
    const severity = sevFromScore(score) || normSev(named) || "medium";
    const affects = [];
    for (const a of (v.affects || [])) { const c = comps.get(a.ref); if (c && c.name) affects.push({ type: "SOFTWARE", name: str(c.name) + (c.version ? "@" + str(c.version) : ""), data: {} }); }
    const f = { title: id + (v.description ? " — " + str(v.description).slice(0, 120) : ""), severity, category: "dependency", tags: ["cyclonedx"] };
    if (v.description) f.description = str(v.description);
    if (v.recommendation) f.recommendation = str(v.recommendation);
    if (affects.length) f.assets = affects;
    findings.push(f);
  }
  return { findings, errors };
}

const PARSERS = { findings: parseFindingContract, sarif: parseSarif, cyclonedx: parseCycloneDX };
// What the ingest endpoint advertises: the three native JSON contracts plus every scanner
// export the vulnimport engine understands (minus "baseline", which is this tool's own JSON).
export const SUPPORTED_FORMATS = [...Object.keys(PARSERS), ...Object.keys(VULN_FORMATS).filter((f) => f !== "baseline" && !Object.keys(PARSERS).includes(f))];

const UNRECOGNISED = "unrecognised format — expected the Finding JSON contract, SARIF 2.1.0, CycloneDX, or a supported scanner export (Nessus, Qualys, OpenVAS, Trivy, Grype, Snyk, Rapid7, Defender or a CSV with asset and CVE columns)";

const SCAN_ROW_CAP = 10000; // protect the graph / queue from a pathologically large export

// Map one open register row (as the engine computed it) to a Finding. This is a thin
// presentation of the engine's own fields — not a second parser — so ingest brings the
// scanned vulnerabilities into the graph as ASSET + VULNERABILITY entities with affects
// links, the same data the vulnimport tool's "Add to Security Graph" button produces.
function rowToFinding(row) {
  const cve = str(row.cve);
  const asset = str(row.assetName) || str(row.assetKey) || "unknown asset";
  const label = cve || str(row.title) || "Vulnerability";
  const title = (cve && row.title ? `${cve} — ${str(row.title)}` : label) + " on " + asset;
  const descParts = [];
  if (row.title && cve) descParts.push(str(row.title) + ".");
  if (row.package) descParts.push(`Affects ${str(row.package)}${row.installed ? " " + str(row.installed) : ""}${row.fixedVersion ? " (fixed in " + str(row.fixedVersion) + ")" : ""}.`);
  if (row.cvss != null) descParts.push(`CVSS ${row.cvss}${row.cvssSource ? " (" + str(row.cvssSource) + ")" : ""}.`);
  if (row.epss != null) descParts.push(`EPSS ${row.epss}.`);
  if (row.kev) descParts.push("In the CISA Known Exploited Vulnerabilities catalog" + (row.ransomware ? ", used in ransomware campaigns" : "") + ".");
  if (row.scanners) descParts.push("Reported by " + str(row.scanners) + ".");
  const controls = [{ framework: "CIS v8", id: "7.7" }];
  if (row.kev) controls.push({ framework: "CISA", id: "BOD 22-01" });
  const vulnData = {};
  if (row.cvss != null) vulnData.cvss = row.cvss;
  if (row.epss != null) vulnData.epss = row.epss;
  if (row.kev) { vulnData.kev = true; if (row.kevDue) vulnData.kevDue = str(row.kevDue); if (row.ransomware) vulnData.ransomware = true; }
  if (row.title) vulnData.title = str(row.title);
  const assetData = {};
  for (const k of ["ip", "fqdn", "os", "kind"]) if (row[k]) assetData[k] = str(row[k]);
  const assets = [];
  if (cve) assets.push({ type: "VULNERABILITY", name: cve, data: vulnData });
  assets.push({ type: "ASSET", name: asset, data: assetData });
  const out = {
    title,
    severity: SEV.includes(str(row.severity).toLowerCase()) ? str(row.severity).toLowerCase() : "info",
    category: "vulnerability",
    description: descParts.join(" ") || (label + " reported on " + asset + "."),
    recommendation: str(row.solution) || (row.fixedVersion ? `Upgrade ${str(row.package) || "the affected component"} to ${str(row.fixedVersion)} or later.` : "Patch or apply the vendor mitigation on the affected asset."),
    controls,
    assets,
    evidence: [{ asset, cve: cve || undefined, package: str(row.package) || undefined, installed: str(row.installed) || undefined, fixedVersion: str(row.fixedVersion) || undefined, port: str(row.port) || undefined, scanners: str(row.scanners) || undefined }],
    tags: ["vulnerability", ...(row.kev ? ["kev"] : []), ...(row.internetFacing ? ["internet-facing"] : [])],
  };
  if (row.references) out.references = str(row.references);
  return out;
}

// Run the shared vulnimport engine over a raw scanner export. No feeds (KEV/EPSS) are
// passed, so there is no enrichment and no network — the engine stays pure. An unrecognised
// export comes back with format "unknown".
function parseScannerExport(text) {
  try {
    const det = vulnDetectFormat(text);
    if (!det || det.format === "unknown") return { format: "unknown", findings: [], errors: [] };
    const r = vulnAnalyze([{ name: "ingest", text }]);
    const rows = ((r.tables && r.tables.vulns) || []).filter((v) => v && v.status !== "fixed" && !v.aggregate);
    const errors = (r.skipped || []).map((s) => (s && s.reason) || String(s));
    let use = rows;
    if (rows.length > SCAN_ROW_CAP) { use = rows.slice(0, SCAN_ROW_CAP); errors.push(`export has ${rows.length} vulnerabilities; ingesting the first ${SCAN_ROW_CAP}`); }
    return { format: det.format, findings: use.map(rowToFinding), errors };
  } catch (e) { return { format: "unknown", findings: [], errors: ["scanner parse failed: " + ((e && e.message) || e)] }; }
}

// ingestToFindings(input) -> { format, findings, errors }
// input: a raw string (JSON, XML or CSV export) or an already-parsed object. Never throws.
export function ingestToFindings(input) {
  if (typeof input === "string") {
    const t = input.replace(/^﻿/, "").trimStart();
    if (t[0] === "{" || t[0] === "[") {
      let obj;
      try { obj = JSON.parse(input); } catch (e) { return { format: "unknown", findings: [], errors: ["invalid JSON: " + (e.message || e)] }; }
      const format = detectFormat(obj);
      const parser = PARSERS[format];
      if (parser) { const r = parser(obj); return { format, findings: r.findings, errors: r.errors }; }
      // Valid JSON but not a native contract — maybe a scanner's own JSON (Trivy/Grype/Snyk).
      const sc = parseScannerExport(input);
      if (sc.format !== "unknown") return sc;
      return { format: "unknown", findings: [], errors: [UNRECOGNISED] };
    }
    // Non-JSON text: XML / CSV scanner exports go straight to the engine.
    const sc = parseScannerExport(input);
    if (sc.format !== "unknown") return sc;
    return { format: "unknown", findings: [], errors: sc.errors.length ? sc.errors : [UNRECOGNISED] };
  }
  const format = detectFormat(input);
  const parser = PARSERS[format];
  if (!parser) return { format, findings: [], errors: [UNRECOGNISED] };
  const r = parser(input);
  return { format, findings: r.findings, errors: r.errors };
}
