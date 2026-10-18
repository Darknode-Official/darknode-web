// Ingest format parsers (Deck D5). PURE — no DOM, no network. Maps the formats a CI
// pipeline or scanner emits into the Deck Finding contract (see core/sink-map.js), so
// `POST /api/v1/ingest` and the browser drag-drop share one mapping. The findings are
// then published through the normal sink, exactly like a tool's own results.
//
// Finding contract (subset we populate):
//   { title, severity, category?, description?, recommendation?, status?,
//     controls?:[{framework,id}], assets?:[{type,name,data?}], tags?, evidence? }

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
    const score = ratings.map((r) => r.score).find((s) => Number.isFinite(Number(s)));
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
export const SUPPORTED_FORMATS = Object.keys(PARSERS);

// ingestToFindings(input) -> { format, findings, errors }
// input: a JSON string or an already-parsed object. Never throws.
export function ingestToFindings(input) {
  let obj = input;
  if (typeof input === "string") { try { obj = JSON.parse(input); } catch (e) { return { format: "unknown", findings: [], errors: ["invalid JSON: " + (e.message || e)] }; } }
  const format = detectFormat(obj);
  const parser = PARSERS[format];
  if (!parser) return { format, findings: [], errors: ["unrecognised format — expected the Finding JSON contract, SARIF 2.1.0 or CycloneDX"] };
  const r = parser(obj);
  return { format, findings: r.findings, errors: r.errors };
}
