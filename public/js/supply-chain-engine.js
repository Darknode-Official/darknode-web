// Supply Chain Risk Analyzer — pure engine (manifest/lockfile parsing, typosquat
// detection by edit distance, CVSS v3 base-score math, OSV advisory summarizing,
// risk scoring, SBOM). No network here; the UI pairs this with live OSV.dev queries.
// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.

// OSV.dev ecosystem names keyed by our internal ecosystem id.
export const OSV_ECOSYSTEM = { npm: "npm", pypi: "PyPI", gem: "RubyGems", go: "Go", maven: "Maven", nuget: "NuGet" };

// ---------------------------------------------------------------------------
// Popular package names per ecosystem — the reference set a typosquat imitates.
// Edit distance against this list catches novel squats (not a fixed misspelling
// table). Kept deliberately to well-known names to limit false positives.
// ---------------------------------------------------------------------------
const POP = {
  npm: ["lodash", "react", "react-dom", "express", "axios", "chalk", "commander", "debug", "moment", "webpack",
    "babel", "jquery", "underscore", "request", "async", "bluebird", "vue", "next", "typescript", "eslint",
    "prettier", "jest", "mocha", "chai", "dotenv", "cors", "body-parser", "mongoose", "passport", "socket.io",
    "redux", "rxjs", "uuid", "classnames", "styled-components", "tailwindcss", "vite", "rollup", "esbuild", "yargs",
    "node-fetch", "semver", "glob", "minimist", "cross-env", "nodemon", "ws", "ioredis", "pg", "mysql2"],
  pypi: ["requests", "urllib3", "numpy", "pandas", "flask", "django", "scipy", "pillow", "cryptography", "setuptools",
    "pip", "boto3", "pytest", "scrapy", "tensorflow", "torch", "matplotlib", "beautifulsoup4", "sqlalchemy", "celery",
    "fastapi", "pydantic", "aiohttp", "jinja2", "pyyaml", "click", "rich", "certifi", "paramiko", "redis"],
  gem: ["rails", "rake", "bundler", "nokogiri", "rack", "devise", "puma", "sidekiq", "rspec", "pg"],
  go: ["github.com/gin-gonic/gin", "github.com/stretchr/testify", "golang.org/x/crypto", "golang.org/x/net", "github.com/gorilla/mux"],
  maven: ["org.apache.logging.log4j:log4j-core", "com.fasterxml.jackson.core:jackson-databind", "org.springframework:spring-core", "com.google.guava:guava", "junit:junit"],
  nuget: ["Newtonsoft.Json", "System.Text.Json", "Serilog", "AutoMapper", "Dapper"],
};
export const POPULAR = Object.fromEntries(Object.entries(POP).map(([k, v]) => [k, new Set(v)]));

// Levenshtein edit distance (iterative, O(mn)).
export function levenshtein(a, b) {
  a = String(a || ""); b = String(b || "");
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    prev = cur;
  }
  return prev[b.length];
}

// A possible typosquat of a popular package: near in edit distance but not equal.
export function typosquat(name, ecosystem) {
  const set = POPULAR[ecosystem];
  if (!set) return null;
  const n = String(name || "").toLowerCase();
  if (n.length < 3 || set.has(n)) return null; // it IS a known-good package
  let best = null, bestD = 3;
  for (const p of set) {
    const d = levenshtein(n, p);
    if (d > 0 && d < bestD) { bestD = d; best = p; }
  }
  if (best && bestD <= 2 && Math.abs(n.length - best.length) <= 2) return { real: best, distance: bestD };
  return null;
}

// ---------------------------------------------------------------------------
// CVSS v3.x base score from a vector string (official formula). Returns a number
// 0.0–10.0 or null if the vector is missing/unparseable.
// ---------------------------------------------------------------------------
export function cvssV3BaseScore(vector) {
  if (!vector || !/CVSS:3\.[01]/i.test(vector)) return null;
  const m = {};
  String(vector).split("/").forEach((p) => { const [k, v] = p.split(":"); if (k && v) m[k.toUpperCase()] = v.toUpperCase(); });
  const scopeChanged = m.S === "C";
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const PR = (scopeChanged ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 })[m.PR];
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const val = { H: 0.56, L: 0.22, N: 0 };
  const C = val[m.C], I = val[m.I], A = val[m.A];
  if ([AV, AC, PR, UI, C, I, A].some((x) => x == null)) return null;
  const iss = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploit = 8.22 * AV * AC * PR * UI;
  const roundup = (x) => Math.ceil(x * 10) / 10;
  if (impact <= 0) return 0;
  return roundup(Math.min(scopeChanged ? 1.08 * (impact + exploit) : impact + exploit, 10));
}

export function severityFromCvss(score) {
  if (score == null) return "";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "none";
}

// Summarize an OSV vulnerability object into the finding fields the UI shows.
export function summarizeVuln(v) {
  if (!v) return null;
  const aliases = v.aliases || [];
  const cve = aliases.find((a) => /^CVE-/i.test(a)) || aliases[0] || v.id;
  const summary = String(v.summary || v.details || "").replace(/\s+/g, " ").trim().slice(0, 300);
  // Prefer a real CVSS vector; fall back to a qualitative GHSA/database severity.
  let cvss = null;
  for (const s of v.severity || []) { const sc = cvssV3BaseScore(s.score); if (sc != null) { cvss = sc; break; } }
  let severity = severityFromCvss(cvss);
  if (!severity || severity === "none") {
    const lbl = String((v.database_specific && v.database_specific.severity) || "").toUpperCase();
    severity = { LOW: "low", MODERATE: "medium", MEDIUM: "medium", HIGH: "high", CRITICAL: "critical" }[lbl] || "medium";
  }
  const fixed = new Set();
  for (const aff of v.affected || []) for (const rg of aff.ranges || []) for (const ev of rg.events || []) if (ev.fixed) fixed.add(ev.fixed);
  return { id: v.id, cve, summary, severity, cvss, fixed: [...fixed].join(", ") };
}

// ---------------------------------------------------------------------------
// Manifest / lockfile parsers. Each returns an array of
// { name, version, spec, exact, type, ecosystem } or null.
// `exact` = the version is pinned (lockfile or a fixed spec), so OSV results are
// authoritative; otherwise `version` is the lower bound of a range.
// ---------------------------------------------------------------------------
function floorVersion(spec) {
  const s = String(spec == null ? "" : spec).trim();
  const cleaned = s.replace(/^[\^~>=<\s]+/, "").split(/\s|\|\||,|-/)[0].trim();
  const exact = cleaned !== "" && s === cleaned && /^\d+(\.\d+){0,3}/.test(cleaned);
  return { version: cleaned, exact };
}

export function parsePackageJson(text) {
  let pkg; try { pkg = JSON.parse(text); } catch (_) { return null; }
  if (!pkg || (!pkg.dependencies && !pkg.devDependencies && !pkg.peerDependencies)) return null;
  const deps = [];
  const add = (obj, type) => { if (obj) for (const [name, spec] of Object.entries(obj)) { const { version, exact } = floorVersion(spec); deps.push({ name, version, spec: String(spec), exact, type, ecosystem: "npm" }); } };
  add(pkg.dependencies, "production"); add(pkg.devDependencies, "development"); add(pkg.peerDependencies, "peer");
  return deps.length ? deps : null;
}

// package-lock.json (npm v1 "dependencies" or v2/v3 "packages") — exact versions.
export function parsePackageLock(text) {
  let j; try { j = JSON.parse(text); } catch (_) { return null; }
  if (!j || (!j.packages && !j.dependencies) || !(j.lockfileVersion || j.packages)) return null;
  const deps = []; const seen = new Set();
  if (j.packages) {
    for (const [path, info] of Object.entries(j.packages)) {
      if (!path || !info || !info.version) continue; // "" is the root project
      const name = path.replace(/^.*node_modules\//, "");
      if (!name || seen.has(name + "@" + info.version)) continue;
      seen.add(name + "@" + info.version);
      deps.push({ name, version: info.version, spec: info.version, exact: true, type: info.dev ? "development" : "production", ecosystem: "npm" });
    }
  }
  if (!deps.length && j.dependencies) {
    for (const [name, info] of Object.entries(j.dependencies)) if (info && info.version) deps.push({ name, version: info.version, spec: info.version, exact: true, type: info.dev ? "development" : "production", ecosystem: "npm" });
  }
  return deps.length ? deps : null;
}

export function parseRequirementsTxt(text) {
  const deps = [];
  for (let line of String(text).split("\n")) {
    line = line.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const m = line.match(/^([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|!=|>|<)?\s*([0-9][^\s;#]*)?/);
    if (!m) continue;
    const spec = (m[2] || "") + (m[3] || "");
    deps.push({ name: m[1].toLowerCase(), version: (m[3] || "").trim(), spec, exact: m[2] === "==", type: "production", ecosystem: "pypi" });
  }
  return deps.length ? deps : null;
}

export function parseGemfile(text) {
  const deps = [];
  for (const line of String(text).split("\n")) {
    const m = line.match(/gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/);
    if (m) { const { version, exact } = floorVersion(m[2] || ""); deps.push({ name: m[1], version, spec: String(m[2] || ""), exact, type: "production", ecosystem: "gem" }); }
  }
  return deps.length ? deps : null;
}

export function parseGoMod(text) {
  const deps = []; let inReq = false;
  for (let line of String(text).split("\n")) {
    line = line.trim();
    if (line === "require (") { inReq = true; continue; }
    if (line === ")") { inReq = false; continue; }
    if (inReq || line.startsWith("require ")) {
      const m = line.match(/^(?:require\s+)?([^\s]+)\s+v?([^\s]+)/);
      if (m && /\./.test(m[1])) deps.push({ name: m[1], version: m[2].replace(/^v/, ""), spec: m[2], exact: true, type: "production", ecosystem: "go" });
    }
  }
  return deps.length ? deps : null;
}

export function parsePomXml(text) {
  const deps = []; const re = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const raw = (m[3] || "").trim();
    if (/^\$\{/.test(raw) || raw === "") continue; // property ref / managed version — no concrete version to scan
    const { version, exact } = floorVersion(raw.replace(/[[\]()]/g, ""));
    deps.push({ name: m[1].trim() + ":" + m[2].trim(), version, spec: raw, exact, type: "production", ecosystem: "maven" });
  }
  return deps.length ? deps : null;
}

export function autoDetectAndParse(text) {
  const t = String(text || "").trim();
  if (!t) return null;
  if (t.startsWith("{")) {
    // a lock file has lockfileVersion or a packages/dependencies tree with versions
    if (/"lockfileVersion"|"node_modules\//.test(t)) { const lk = parsePackageLock(t); if (lk) return lk; }
    return parsePackageJson(t) || parsePackageLock(t);
  }
  if (t.includes("<dependency>")) return parsePomXml(t);
  if (/^\s*gem\s+['"]/m.test(t)) return parseGemfile(t);
  if (/^\s*module\s+/m.test(t) && /\brequire\b/.test(t)) return parseGoMod(t);
  return parseRequirementsTxt(t);
}

// Risk score: 100 minus weighted deductions, floored at 0.
export function scoreRisk(findings) {
  const w = { critical: 15, high: 8, medium: 3, low: 1 };
  let score = 100;
  for (const f of findings) score -= (w[f.severity] || 1);
  return Math.max(0, score);
}

// SBOM generation (CycloneDX XML or SPDX tag-value).
export function generateSBOM(deps, format) {
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  if (format === "cyclonedx") {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">\n  <components>\n';
    for (const d of deps) xml += `    <component type="library">\n      <name>${esc(d.name)}</name>\n      <version>${esc(d.version)}</version>\n      <purl>pkg:${d.ecosystem}/${encodeURIComponent(d.name)}@${encodeURIComponent(d.version)}</purl>\n    </component>\n`;
    return xml + "  </components>\n</bom>";
  }
  let spdx = "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\nDocumentName: supply-chain-analysis\nDocumentNamespace: https://darknode.ai/spdx/" + Date.now() + "\n\n";
  deps.forEach((d, i) => { spdx += `PackageName: ${d.name}\nSPDXID: SPDXRef-Package-${i + 1}\nPackageVersion: ${d.version}\nPackageDownloadLocation: NOASSERTION\nExternalRef: PACKAGE-MANAGER purl pkg:${d.ecosystem}/${encodeURIComponent(d.name)}@${encodeURIComponent(d.version)}\n\n`; });
  return spdx;
}
