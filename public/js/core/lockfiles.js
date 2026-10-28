// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Shared manifest / lockfile parsers for the Supply Chain analyzer
// (supply-chain-engine.js), the Code Scanner's dependency check (codescan/rules.js,
// also run by the Node CLI and the GitHub Action) and License Audit
// (appsec/licenseaudit-engine.js). Pure and dependency-free: no DOM, no network.
//
// Every parser takes the file text and returns an array of dependencies, or null
// when the text holds none (malformed JSON included):
//   { name, version, spec, exact, type, ecosystem, direct, line, ... }
//   version    the pinned version, or the lower bound of a range when exact is false
//   exact      true when the version is pinned (a lockfile, or a fixed spec)
//   type       "production" | "development" | "peer"
//   ecosystem  npm | pypi | gem | go | maven | cargo | composer (OSV_ECOSYSTEM maps to OSV names)
//   direct     true / false where the format records it, otherwise undefined
//   line       1-based line that declares the entry (for jumping to it)
// pnpm-lock.yaml and Cargo.lock entries also carry `requires` (["name@version"]);
// Cargo.lock marks workspace crates (no registry source) `local: true`;
// composer.lock entries carry `license` (string[]).

// OSV.dev ecosystem names keyed by our internal ecosystem id.
export const OSV_ECOSYSTEM = { npm: "npm", pypi: "PyPI", gem: "RubyGems", go: "Go", maven: "Maven", nuget: "NuGet", cargo: "crates.io", composer: "Packagist" };

const linesOf = (text) => String(text == null ? "" : text).split(/\r?\n/);
const jsonOf = (text) => { try { return JSON.parse(text); } catch (_) { return null; } };
// First line declaring each JSON key ("key": ...), so lookups stay linear on large lockfiles.
function keyLines(lines) {
  const at = new Map();
  lines.forEach((l, i) => { const m = /^\s*"((?:[^"\\]|\\.)*)"\s*:/.exec(l); if (m && !at.has(m[1])) at.set(m[1], i + 1); });
  return at;
}

// A spec's version: an exact pin ("1.2.3", "=1.2.3", "v1.2.3-rc.1") or the lower bound of a range.
export function floorVersion(spec) {
  const s = String(spec == null ? "" : spec).trim();
  const pin = /^=?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?)$/.exec(s);
  if (pin) return { version: pin[1], exact: true };
  // An upper bound or an exclusion (<2.0, <=2, !=1.4) has no floor: its number is a version
  // the install is NOT, so scanning at it missed the installed 1.x and its advisories.
  if (/^(<|!=)/.test(s)) return { version: "", exact: false };
  let cleaned = s.replace(/^[\^~>=<\s]+/, "").split(/\s|\|\||,|-/)[0].trim().replace(/^v(?=\d)/, "");
  if (/^\d+(\.(\d+|[xX*]))*$/.test(cleaned) && /[xX*]/.test(cleaned)) { const p = cleaned.split(".").map((x) => (/^\d+$/.test(x) ? x : "0")); while (p.length < 3) p.push("0"); cleaned = p.join("."); } // 1.x -> 1.0.0
  if (!/^\d/.test(cleaned)) return { version: "", exact: false }; // *, latest, a git/file/url source: no version to scan at
  const exact = s === cleaned && /^\d+(\.\d+){0,3}/.test(cleaned);
  return { version: cleaned, exact };
}

// package.json: what the project asked for directly (ranges included).
export function parsePackageJson(text) {
  const pkg = jsonOf(text);
  if (!pkg || (!pkg.dependencies && !pkg.devDependencies && !pkg.peerDependencies && !pkg.optionalDependencies)) return null;
  const at = keyLines(linesOf(text));
  const deps = [];
  const add = (obj, type) => { if (obj && typeof obj === "object") for (const [name, spec] of Object.entries(obj)) { const { version, exact } = floorVersion(spec); deps.push({ name, version, spec: String(spec), exact, type, ecosystem: "npm", direct: true, line: at.get(name) || 1 }); } };
  add(pkg.dependencies, "production"); add(pkg.optionalDependencies, "production"); add(pkg.devDependencies, "development"); add(pkg.peerDependencies, "peer");
  return deps.length ? deps : null;
}

// package-lock.json / npm-shrinkwrap.json (v1 "dependencies" tree or v2/v3 "packages"
// map): the full resolved tree. `direct` comes from the root project's declared
// dependencies (v2/v3) or tree depth (v1). Aliased installs report the real package.
export function parsePackageLock(text) {
  const j = jsonOf(text);
  if (!j || (!j.packages && !j.dependencies) || !(j.lockfileVersion || j.packages)) return null;
  const at = keyLines(linesOf(text));
  const deps = []; const seen = new Set();
  const push = (name, version, dev, direct, line) => {
    if (!name || !version) return;
    const key = name + "@" + version;
    if (seen.has(key)) return;
    seen.add(key);
    deps.push({ name, version, spec: version, exact: true, type: dev ? "development" : "production", ecosystem: "npm", direct, line });
  };
  if (j.packages) {
    const root = j.packages[""] || {};
    const directSet = new Set([
      ...Object.keys(root.dependencies || {}), ...Object.keys(root.devDependencies || {}),
      ...Object.keys(root.optionalDependencies || {}), ...Object.keys(root.peerDependencies || {}),
    ]);
    for (const [path, info] of Object.entries(j.packages)) {
      if (!path || !info || !info.version || info.link) continue; // "" is the root project; links point at workspace folders
      const installed = path.replace(/^.*node_modules\//, "");
      const topLevel = path.split("node_modules/").length === 2; // exactly one node_modules segment
      const direct = directSet.size ? (topLevel && directSet.has(installed)) : topLevel;
      push(info.name || installed, info.version, info.dev, direct, at.get(path) || 1);
    }
  }
  if (!deps.length && j.dependencies) {
    const walk = (obj, direct) => {
      for (const [name, info] of Object.entries(obj || {})) {
        if (!info) continue;
        push(name, info.version, info.dev, direct, at.get(name) || 1);
        if (info.dependencies) walk(info.dependencies, false);
      }
    };
    walk(j.dependencies, true);
  }
  return deps.length ? deps : null;
}

// yarn.lock (classic v1 and berry v2+). A block header is an un-indented line ending
// in ":" listing one or more specifiers; the block's `version` pins them all.
// Berry workspace entries (name@workspace:...) are the project itself and are skipped.
export function parseYarnLock(text) {
  const lines = linesOf(text);
  const deps = []; const seen = new Set();
  for (let i = 0; i < lines.length; i++) {
    const header = lines[i];
    if (!header || /^\s/.test(header) || header.startsWith("#") || header.startsWith("__metadata")) continue;
    if (!/:\s*$/.test(header)) continue;
    let version = "";
    for (let k = i + 1; k < lines.length && (/^\s/.test(lines[k]) || !lines[k]); k++) {
      const vm = /^\s+version:?\s+"?([^"\n]+)"?/.exec(lines[k]);
      if (vm) { version = vm[1].trim(); break; }
    }
    if (!version) continue;
    for (const spec of header.replace(/:\s*$/, "").split(",")) {
      const s = spec.trim().replace(/^"|"$/g, "");
      if (!s || /@workspace:/.test(s)) continue;
      const atSign = s.lastIndexOf("@");
      if (atSign <= 0) continue;
      const name = s.slice(0, atSign);
      if (!name || seen.has(name + "@" + version)) continue;
      seen.add(name + "@" + version);
      deps.push({ name, version, spec: version, exact: true, type: "production", ecosystem: "npm", line: i + 1 });
    }
  }
  return deps.length ? deps : null;
}

// pnpm-lock.yaml (v5.x, v6, v9). Packages and snapshots pin name@version with their
// own dependency edges; the root's declared dependencies (top-level sections in v5/v6,
// importers['.'] in v9) say which are direct. A v9 snapshot with no dependencies is
// written inline ("name@1.0.0: {}").
export function parsePnpmLock(text) {
  const lines = linesOf(text);
  const ver = (String(text).match(/^lockfileVersion:\s*'?([\d.]+)'?/m) || [])[1] || "";
  const pkgs = new Map(); // name@version -> { name, version, dev, deps, line }
  const direct = new Map(); // name -> { version, dev }
  let section = "", sub = "", cur = null, inDeps = false, importer = "", impSec = "", impDep = "";
  const keyOf = (raw) => {
    let k = raw.trim().replace(/:\s*\{\s*\}$/, ":").replace(/^['"]|['"]:?$/g, "").replace(/:$/, "").replace(/^['"]|['"]$/g, "").replace(/^\//, "");
    k = k.replace(/\(.*$/, "").replace(/_[^/@]*$/, (m) => (/^_\d/.test(m) ? m : ""));
    if (/^\d/.test(ver) && parseFloat(ver) < 6 && !/@[^@/]+$/.test(k.replace(/^@/, ""))) {
      const i = k.lastIndexOf("/");
      return i > 0 ? { name: k.slice(0, i), version: k.slice(i + 1).replace(/_.*$/, "") } : null;
    }
    const at = k.lastIndexOf("@");
    return at > 0 ? { name: k.slice(0, at), version: k.slice(at + 1) } : null;
  };
  const cleanVer = (v) => String(v || "").trim().replace(/^['"]|['"]$/g, "").replace(/\(.*$/, "").replace(/_.*$/, "");
  lines.forEach((raw, idx) => {
    if (!raw.trim() || /^\s*#/.test(raw)) return;
    const ind = raw.match(/^ */)[0].length;
    const line = raw.trim();
    if (ind === 0) { section = line.replace(/:.*$/, ""); sub = ""; cur = null; importer = ""; return; }
    if (section === "packages" || section === "snapshots") {
      if (ind === 2) { const k = keyOf(line); cur = k ? k.name + "@" + k.version : null; if (cur && !pkgs.has(cur)) pkgs.set(cur, { name: k.name, version: k.version, dev: false, deps: [], line: idx + 1 }); inDeps = false; return; }
      if (!cur) return;
      if (ind === 4) { inDeps = /^(dependencies|optionalDependencies):/.test(line); if (/^dev:\s*true/.test(line)) pkgs.get(cur).dev = true; return; }
      if (ind === 6 && inDeps) { const m = line.match(/^['"]?([^'":]+(?:\/[^'":]+)?)['"]?:\s*['"]?([^'"\s]+)/); if (m) pkgs.get(cur).deps.push(m[1] + "@" + cleanVer(m[2])); }
      return;
    }
    if (section === "dependencies" || section === "devDependencies" || section === "optionalDependencies") {
      if (ind === 2) { const m = line.match(/^['"]?([^'":]+(?:\/[^'":]+)?)['"]?:\s*(.*)$/); if (m) { sub = m[1]; direct.set(sub, { version: m[2] ? cleanVer(m[2]) : "", dev: section === "devDependencies" }); } }
      else if (ind === 4 && /^version:/.test(line) && sub) direct.get(sub).version = cleanVer(line.replace(/^version:\s*/, ""));
      return;
    }
    if (section === "importers") {
      if (ind === 2) { importer = line.replace(/:$/, "").replace(/^['"]|['"]$/g, ""); return; }
      if (importer !== ".") return;
      if (ind === 4) { impSec = line.replace(/:.*$/, ""); return; }
      if (ind === 6 && /ependencies$/.test(impSec)) { impDep = line.replace(/:.*$/, "").replace(/^['"]|['"]$/g, ""); direct.set(impDep, { version: "", dev: impSec === "devDependencies" }); return; }
      if (ind === 8 && /^version:/.test(line) && impDep) direct.get(impDep).version = cleanVer(line.replace(/^version:\s*/, ""));
    }
  });
  const deps = [...pkgs.values()].map((p) => {
    const d = direct.get(p.name);
    const isDirect = direct.size ? !!(d && d.version === p.version) : undefined;
    return { name: p.name, version: p.version, spec: p.version, exact: true, type: p.dev || (isDirect && d.dev) ? "development" : "production", ecosystem: "npm", direct: isDirect, line: p.line, requires: p.deps };
  });
  return deps.length ? deps : null;
}

// requirements*.txt: `==` / `===` pins are exact, >= ~= > give a lower bound, and < <= != give no version (not the installed one).
export function parseRequirementsTxt(text) {
  const deps = [];
  linesOf(text).forEach((raw, i) => {
    const line = raw.replace(/(^|\s)#.*/, "").trim();
    if (!line || line.startsWith("-")) return;
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(===|==|>=|<=|~=|!=|>|<)?\s*([0-9][^\s;,#]*)?/);
    if (!m) return;
    const spec = (m[2] || "") + (m[3] || "");
    const noFloor = m[2] === "<" || m[2] === "<=" || m[2] === "!="; // an upper bound or exclusion is not the installed version
    deps.push({ name: m[1].toLowerCase(), version: noFloor ? "" : (m[3] || "").trim(), spec, exact: m[2] === "==" || m[2] === "===", type: "production", ecosystem: "pypi", direct: true, line: i + 1 });
  });
  return deps.length ? deps : null;
}

// [[package]] blocks of a TOML lockfile with their header line.
function tomlPackages(text) {
  const lines = linesOf(text);
  const out = [];
  let cur = null;
  lines.forEach((l, i) => {
    if (/^\[\[package\]\]\s*$/.test(l)) { cur = { line: i + 1, body: [] }; out.push(cur); return; }
    if (/^\[/.test(l)) { cur = null; return; }
    if (cur) cur.body.push(l);
  });
  return out.map((p) => {
    const body = p.body.join("\n");
    const str = (key) => (body.match(new RegExp("^\\s*" + key + "\\s*=\\s*\"([^\"]*)\"", "m")) || [])[1];
    const arr = (body.match(/^\s*dependencies\s*=\s*\[([\s\S]*?)\]/m) || [])[1] || "";
    return { line: p.line, name: str("name"), version: str("version"), source: str("source") || "", category: str("category"), deps: [...arr.matchAll(/"([^"]+)"/g)].map((m) => m[1].split(" ")) };
  });
}

// poetry.lock: every [[package]] pins the full tree; direct deps live in pyproject.toml.
export function parsePoetryLock(text) {
  const deps = []; const seen = new Set();
  for (const p of tomlPackages(text)) {
    if (!p.name || !p.version) continue;
    const name = p.name.toLowerCase();
    if (seen.has(name + "@" + p.version)) continue;
    seen.add(name + "@" + p.version);
    deps.push({ name, version: p.version, spec: p.version, exact: true, type: p.category === "dev" ? "development" : "production", ecosystem: "pypi", line: p.line });
  }
  return deps.length ? deps : null;
}

// Cargo.lock: registry and git crates plus the workspace's own crates (no source,
// marked local). `requires` resolves each "name" / "name version" edge to name@version;
// a crate a local crate requires is direct.
export function parseCargoLock(text) {
  const pkgs = tomlPackages(text).filter((p) => p.name && p.version);
  const byName = new Map();
  for (const p of pkgs) { if (!byName.has(p.name)) byName.set(p.name, []); byName.get(p.name).push(p); }
  const ref = ([n, v]) => { const cands = byName.get(n) || []; const hit = v ? cands.find((c) => c.version === v) : cands[0]; return hit ? hit.name + "@" + hit.version : n; };
  const locals = pkgs.filter((p) => !p.source);
  const directSet = new Set(locals.flatMap((p) => p.deps.map(ref)));
  const deps = pkgs.map((p) => ({
    name: p.name, version: p.version, spec: p.version, exact: true, type: "production", ecosystem: "cargo",
    direct: locals.length ? directSet.has(p.name + "@" + p.version) : undefined, line: p.line,
    requires: p.deps.map(ref), source: p.source, ...(p.source ? {} : { local: true }),
  }));
  return deps.length ? deps : null;
}

// Pipfile.lock: "default" and "develop" sections, versions written as ==x.y.z.
export function parsePipfileLock(text) {
  const j = typeof text === "object" && text ? text : jsonOf(text);
  if (!j || (!j.default && !j.develop)) return null;
  const at = typeof text === "string" ? keyLines(linesOf(text)) : new Map();
  const deps = [];
  for (const [sec, dev] of [["default", false], ["develop", true]]) {
    for (const [name, v] of Object.entries(j[sec] || {}).sort()) {
      const version = String((v && v.version) || "").replace(/^==/, "");
      if (!version) continue;
      deps.push({ name: name.toLowerCase(), version, spec: "==" + version, exact: true, type: dev ? "development" : "production", ecosystem: "pypi", line: at.get(name) || 1 });
    }
  }
  return deps.length ? deps : null;
}

// composer.lock: "packages" and "packages-dev", with each package's declared licenses.
export function parseComposerLock(text) {
  const j = typeof text === "object" && text ? text : jsonOf(text);
  if (!j || (!Array.isArray(j.packages) && !Array.isArray(j["packages-dev"]))) return null;
  const at = new Map();
  if (typeof text === "string") linesOf(text).forEach((l, i) => { const m = /"name"\s*:\s*"([^"]+)"/.exec(l); if (m && !at.has(m[1])) at.set(m[1], i + 1); });
  const deps = [];
  for (const [sec, dev] of [["packages", false], ["packages-dev", true]]) {
    for (const p of Array.isArray(j[sec]) ? j[sec] : []) {
      if (!p || !p.name) continue;
      const version = String(p.version || "").replace(/^v(?=\d)/, "");
      const license = Array.isArray(p.license) ? p.license.filter(Boolean).map(String) : p.license ? [String(p.license)] : [];
      deps.push({ name: p.name, version, spec: String(p.version || ""), exact: true, type: dev ? "development" : "production", ecosystem: "composer", line: at.get(p.name) || 1, license });
    }
  }
  return deps.length ? deps : null;
}

// go.sum: one line per module hash; the build list, deduped by module@version.
export function parseGoSum(text) {
  const deps = []; const seen = new Set();
  linesOf(text).forEach((raw, i) => {
    const m = raw.trim().match(/^(\S+)\s+(v\S+?)(\/go\.mod)?\s+h1:/);
    if (!m) return;
    const name = m[1];
    const version = m[2].replace(/^v/, "");
    if (!/\./.test(name) || seen.has(name + "@" + version)) return;
    seen.add(name + "@" + version);
    deps.push({ name, version, spec: "v" + version, exact: true, type: "production", ecosystem: "go", line: i + 1 });
  });
  return deps.length ? deps : null;
}

// go.mod require lines (single or block); "// indirect" marks transitive modules.
export function parseGoMod(text) {
  const deps = []; let inReq = false;
  linesOf(text).forEach((raw, i) => {
    const line = raw.trim();
    if (/^require\s*\($/.test(line)) { inReq = true; return; }
    if (inReq && line === ")") { inReq = false; return; }
    if (inReq || /^require\s/.test(line)) {
      const m = line.match(/^(?:require\s+)?(\S+)\s+v?(\d\S*)/);
      if (m && /\./.test(m[1])) deps.push({ name: m[1], version: m[2].replace(/\+incompatible$/, ""), spec: "v" + m[2], exact: true, type: "production", ecosystem: "go", direct: !/\/\/\s*indirect/.test(line), line: i + 1 });
    }
  });
  return deps.length ? deps : null;
}

// Gemfile.lock: `specs:` under GEM / GIT / PATH is the resolved tree; DEPENDENCIES
// lists the gems the Gemfile declares. Platform suffixes (1.2.3-x86_64-linux) are dropped.
export function parseGemfileLock(text) {
  const specs = []; const directSet = new Set();
  let section = "";
  linesOf(text).forEach((raw, i) => {
    const line = raw.replace(/\s+$/, "");
    if (/^\S/.test(line)) { section = line.trim().replace(/:$/, ""); return; }
    if (section === "GEM" || section === "GIT" || section === "PATH") {
      const m = line.match(/^ {4}([A-Za-z0-9_.-]+) \(([^)]+)\)\s*$/); // 4-space indent = a resolved package
      if (m) specs.push({ name: m[1], version: m[2].split(/[\s,]/)[0].replace(/-.*$/, ""), line: i + 1 });
    } else if (section === "DEPENDENCIES") {
      const m = line.match(/^ {2}([A-Za-z0-9_.-]+)/);
      if (m) directSet.add(m[1].replace(/!$/, ""));
    }
  });
  const seen = new Set();
  const deps = [];
  for (const s of specs) {
    if (seen.has(s.name + "@" + s.version)) continue;
    seen.add(s.name + "@" + s.version);
    deps.push({ name: s.name, version: s.version, spec: s.version, exact: true, type: "production", ecosystem: "gem", direct: directSet.size ? directSet.has(s.name) : undefined, line: s.line });
  }
  return deps.length ? deps : null;
}

// Gemfile: declared gems and their version constraints.
export function parseGemfile(text) {
  const deps = [];
  linesOf(text).forEach((line, i) => {
    const m = line.match(/^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/);
    if (m) { const { version, exact } = floorVersion(m[2] || ""); deps.push({ name: m[1], version, spec: String(m[2] || ""), exact, type: "production", ecosystem: "gem", direct: true, line: i + 1 }); }
  });
  return deps.length ? deps : null;
}

// pom.xml <dependency> entries with a literal version (property refs and managed versions are skipped).
export function parsePomXml(text) {
  const t = String(text == null ? "" : text);
  const deps = []; const re = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/g;
  let m;
  while ((m = re.exec(t)) !== null) {
    const raw = (m[3] || "").trim();
    if (/^\$\{/.test(raw) || raw === "") continue;
    const { version, exact } = floorVersion(raw.replace(/[[\]()]/g, ""));
    deps.push({ name: m[1].trim() + ":" + m[2].trim(), version, spec: raw, exact, type: "production", ecosystem: "maven", direct: true, line: t.slice(0, m.index).split("\n").length });
  }
  return deps.length ? deps : null;
}

// gradle.lockfile: group:artifact:version=configurations, one per line.
export function parseGradleLockfile(text) {
  const deps = [];
  linesOf(text).forEach((l, i) => {
    const m = l.match(/^([\w.-]+):([\w.-]+):([0-9][^=\s]*)=(.*)$/);
    if (!m) return;
    const confs = m[4].split(",").map((c) => c.trim()).filter(Boolean); // only test configurations = a test dependency
    deps.push({ name: m[1] + ":" + m[2], version: m[3], spec: m[3], exact: true, type: confs.length && confs.every((c) => /^test/i.test(c)) ? "development" : "production", ecosystem: "maven", line: i + 1 });
  });
  return deps.length ? deps : null;
}

// Format id -> parser. Ids match License Audit's format names.
export const LOCKFILE_PARSERS = {
  "npm-manifest": parsePackageJson, "package-lock": parsePackageLock, "yarn-lock": parseYarnLock, "pnpm-lock": parsePnpmLock,
  "requirements": parseRequirementsTxt, "poetry-lock": parsePoetryLock, "pipfile-lock": parsePipfileLock,
  "go-mod": parseGoMod, "go-sum": parseGoSum, "cargo-lock": parseCargoLock, "gemfile": parseGemfile, "gemfile-lock": parseGemfileLock,
  "composer-lock": parseComposerLock, "pom": parsePomXml, "gradle-lockfile": parseGradleLockfile,
};
const BY_NAME = {
  "package.json": "npm-manifest", "package-lock.json": "package-lock", "npm-shrinkwrap.json": "package-lock", "yarn.lock": "yarn-lock",
  "pnpm-lock.yaml": "pnpm-lock", "poetry.lock": "poetry-lock", "Pipfile.lock": "pipfile-lock", "go.mod": "go-mod", "go.sum": "go-sum",
  "Cargo.lock": "cargo-lock", "Gemfile": "gemfile", "Gemfile.lock": "gemfile-lock", "composer.lock": "composer-lock", "pom.xml": "pom",
  "gradle.lockfile": "gradle-lockfile",
};

/** Format id for a file path by its name, or null. */
export function formatForName(path) {
  const base = String(path || "").split(/[\\/]/).pop();
  return BY_NAME[base] || (/^requirements[\w.-]*\.txt$/i.test(base) ? "requirements" : null);
}

/** Format id for pasted text by its content; falls back to "requirements". Empty text gives null. */
export function detectFormat(text) {
  const t = String(text || "").replace(/^\uFEFF/, "").trim();
  if (!t) return null;
  if (t.startsWith("{")) {
    const j = jsonOf(t);
    if (j && j._meta && (j.default || j.develop)) return "pipfile-lock";
    if (j && Array.isArray(j.packages) && ("content-hash" in j || "packages-dev" in j)) return "composer-lock";
    if (/"lockfileVersion"|"node_modules\//.test(t) && parsePackageLock(t)) return "package-lock";
    return parsePackageJson(t) ? "npm-manifest" : "package-lock";
  }
  if (t.includes("<dependency>")) return "pom";
  if (/^lockfileVersion:/m.test(t) && /^(?:packages|importers):/m.test(t)) return "pnpm-lock";
  if (/^#\s*yarn lockfile/m.test(t) || /^__metadata:/m.test(t) || /^"?[^"\n@][^"\n]*@[^"\n]+":?\s*\n\s+version:?\s+/m.test(t)) return "yarn-lock";
  if (/\[\[package\]\]/.test(t)) return /@generated by Cargo|^source = "(?:registry|git)\+|^checksum = "[0-9a-f]{64}"/m.test(t) ? "cargo-lock" : "poetry-lock";
  if (/^GEM$/m.test(t) || /^DEPENDENCIES$/m.test(t)) return "gemfile-lock";
  if (/\s+h1:/.test(t) && /\/go\.mod\s+h1:/.test(t)) return "go-sum";
  if (/^\s*gem\s+['"]/m.test(t)) return "gemfile";
  if (/^\s*module\s+/m.test(t) && /\brequire\b/.test(t)) return "go-mod";
  if (/^# This is a Gradle generated file/m.test(t) || /^[\w.-]+:[\w.-]+:[0-9][^=\s]*=/m.test(t)) return "gradle-lockfile";
  return "requirements";
}

/** Parse `text` as `format`; Cargo workspace crates (not published packages) are left out. */
export function parseLockfile(format, text) {
  const parse = LOCKFILE_PARSERS[format];
  const deps = parse ? parse(text) : null;
  if (!deps || format !== "cargo-lock") return deps;
  const published = deps.filter((d) => !d.local);
  return published.length ? published : null;
}
