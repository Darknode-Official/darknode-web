// IaC Scanner engine (iacscan). Deterministic infrastructure-as-code
// misconfiguration scanner: Terraform (HCL, plan JSON, state), CloudFormation
// (YAML/JSON), Kubernetes manifests and Helm-rendered output, Dockerfiles,
// docker-compose, Azure ARM JSON and GitHub Actions workflows, plus a secrets
// sweep over every text file. Pure: no DOM, no network, no clock. Safe to run
// inside a Blob module Worker and under node tests.

import { parseHcl, parseYamlSubset } from "../ingest/parse.js";
import { detector, findAll } from "../core/secret-detectors.js";

export const TOOL_ID = "iacscan";
export const VERSION = "1.0.0";

/** File kinds and the names / extensions that hint at them (content decides). */
export const COLUMNS = {
  terraform: [".tf"],
  tfvars: [".tfvars", ".auto.tfvars"],
  tfplan: ["plan.json", "tfplan.json"],
  tfstate: [".tfstate"],
  cloudformation: [".yaml", ".yml", ".json", ".template"],
  kubernetes: [".yaml", ".yml", ".json"],
  dockerfile: ["Dockerfile", "Containerfile", ".dockerfile"],
  compose: ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"],
  arm: [".json"],
  "github-actions": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
  bicep: [".bicep"],
  "helm-values": ["values.yaml"],
};

/** Tunable options; the UI renders these as the settings panel. */
export const DEFAULTS = {
  minSeverity: "info",            // lowest severity to report
  ignoreRules: [],                // rule ids switched off
  maxEvidence: 50,                // evidence rows kept per finding
  maxFileBytes: 8 * 1024 * 1024,  // larger files are secret-scanned only
};

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const PLATFORMS = ["aws", "azure", "gcp", "kubernetes", "docker", "compose", "github-actions", "secrets"];

/* ------------------------------------------------------------------------ */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------ */

const splitLines = (t) => String(t == null ? "" : t).split(/\r?\n/);
const reEsc = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const lc = (v) => String(v == null ? "" : v).toLowerCase();
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const base = (name) => String(name || "").split(/[\\/]/).pop();

function findLine(lines, re, from = 0, to = lines.length) {
  for (let i = Math.max(0, from); i < Math.min(to, lines.length); i++) if (re.test(lines[i])) return i + 1;
  return 0;
}

function snippetAt(lines, line) {
  const t = line > 0 && line <= lines.length ? lines[line - 1].trim() : "";
  return t.length > 220 ? t.slice(0, 217) + "..." : t;
}

/** Mask a secret: first 4 + last 2 characters kept. */
export function mask(v) {
  const s = String(v == null ? "" : v);
  if (s.length <= 6) return "*".repeat(s.length);
  return s.slice(0, 4) + "*".repeat(Math.min(12, s.length - 6)) + s.slice(-2);
}

/** True when a value cannot be resolved statically (reference, expression, intrinsic). */
export function isDyn(v) {
  if (typeof v === "string") return /\$\{[^}]*\}/.test(v) || /^\[\s*[a-zA-Z]+\(/.test(v);
  if (!v || typeof v !== "object" || Array.isArray(v)) return false;
  const k = Object.keys(v);
  if (k.length !== 1) return false;
  const key = k[0];
  return key === "ref" || key === "raw" || key === "Ref" || key === "Condition" || key.startsWith("Fn::") || key.startsWith("!");
}

/** Path getter "a.b.c"; descends into the first element of block lists. */
export function get(o, path) {
  let cur = o;
  for (const k of String(path).split(".")) {
    if (cur == null) return undefined;
    if (Array.isArray(cur)) {
      if (/^\d+$/.test(k)) { cur = cur[Number(k)]; continue; }
      cur = cur[0];
      if (cur == null) return undefined;
    }
    if (typeof cur !== "object") return undefined;
    cur = cur[k];
  }
  return cur;
}

/** First defined value among "a.b|c.d" alternatives. */
export function pick(o, paths) {
  for (const p of String(paths).split("|")) { const v = get(o, p.trim()); if (v !== undefined) return v; }
  return undefined;
}

const isTrue = (v) => v === true || lc(v) === "true" || v === 1;
const isFalse = (v) => v === false || lc(v) === "false" || v === 0;
const arr = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);
const num = (v) => { const n = typeof v === "number" ? v : Number(String(v == null ? "" : v).trim()); return String(v == null ? "" : v).trim() === "" ? NaN : n; };
const anyCidr = (c) => { const s = lc(c).trim(); return s === "0.0.0.0/0" || s === "::/0" || s === "*" || s === "any" || s === "internet" || s === "0.0.0.0"; };

/** Does a port range include p? ("*", "-1" = all). */
function rangeCovers(from, to, p) {
  if (String(from) === "*" || String(from) === "-1") return true;
  const s = String(from);
  if (/^\d+-\d+$/.test(s)) { const [a, b] = s.split("-").map(Number); return a <= p && b >= p; }
  const f = num(from), t = to === undefined || to === null || to === "" ? f : num(to);
  if (!Number.isFinite(f)) return false;
  if (f === 0 && (t === 0 || t === 65535)) return true;
  return f <= p && (Number.isFinite(t) ? t : f) >= p;
}

/* ------------------------------------------------------------------------ */
/* IAM-style policy documents                                                */
/* ------------------------------------------------------------------------ */

/** Normalise a policy (JSON string, object, jsonencode(...), data doc) to statements, or null when unknown. */
export function policyStatements(v) {
  let doc = v;
  if (doc == null) return null;
  if (typeof doc === "string") {
    const s = doc.trim();
    if (!s.startsWith("{")) return null;
    try { doc = JSON.parse(s); } catch (_) { return null; }
  } else if (doc && typeof doc === "object" && typeof doc.raw === "string" && /^jsonencode\s*\(/.test(doc.raw)) {
    const inner = doc.raw.replace(/^jsonencode\s*\(/, "").replace(/\)\s*$/, "");
    try { doc = parseHcl("x = " + inner).attrs.x; } catch (_) { return null; }
  } else if (isDyn(doc)) return null;
  if (!doc || typeof doc !== "object") return null;
  const raw = arr(doc.Statement || doc.statement);
  if (!raw.length) return null;
  return raw.filter((st) => st && typeof st === "object").map((st) => ({
    effect: String(st.Effect || st.effect || "Allow"),
    actions: arr(st.Action || st.actions).map((a) => (typeof a === "string" ? a : "<dynamic>")),
    resources: arr(st.Resource || st.resources).map((a) => (typeof a === "string" ? a : "<dynamic>")),
    principal: st.Principal !== undefined ? st.Principal : arr(st.principals).some((p) => arr(p && p.identifiers).includes("*")) ? "*" : undefined,
    condition: st.Condition || (arr(st.condition).length ? st.condition : undefined),
  }));
}

function principalIsPublic(p) {
  if (p === "*") return true;
  if (!p || typeof p !== "object") return false;
  return Object.values(p).some((x) => arr(x).includes("*"));
}

/* ------------------------------------------------------------------------ */
/* File classification                                                       */
/* ------------------------------------------------------------------------ */

/** Classify a file by name + content -> { kind, confidence: high|medium|low, reason }. */
export function classify(name, text) {
  const n = String(name || ""), b = lc(base(n)), t = String(text || "");
  const head = t.slice(0, 65536);
  const ext = b.includes(".") ? b.slice(b.lastIndexOf(".")) : "";
  const inWorkflows = /(^|[\\/])\.github[\\/]workflows[\\/]/i.test(n);
  const res = (kind, confidence, reason) => ({ kind, confidence, reason });

  if (!t.trim()) return res("empty", "low", "empty file");
  if (ext === ".bicep") return res("bicep", "high", "Bicep is not supported; compile with `az bicep build` and scan the ARM JSON");
  if (/^values([-.][\w.-]+)?\.ya?ml$/.test(b)) return res("helm-values", "high", "Helm values are not scannable alone; render with `helm template` and scan the output");
  if (b === "chart.yaml" || b === "chart.lock") return res("helm-chart", "high", "Helm chart metadata, not a workload; render with `helm template`");
  if (!inWorkflows && /(^|[^$])\{\{-?\s*(\.Values|\.Release|\.Chart|\.Capabilities|include\s|template\s|if\s|range\s|with\s|toYaml|\/\*)/.test(head) && /\.(ya?ml|tpl)$/.test(b)) return res("helm-template", "high", "unrendered Helm template; run `helm template` and scan the output");
  if (b === "dockerfile" || b === "containerfile" || /^dockerfile[.-]/.test(b) || ext === ".dockerfile") {
    return res("dockerfile", /^[^\S\n\r\u2028\u2029]*(FROM|ARG)\s/im.test(head) ? "high" : "medium", "Dockerfile");
  }
  if (ext === ".tf") return res("terraform", /^[^\S\n\r\u2028\u2029]*(resource|data|module|provider|variable|terraform|locals|output)\b/m.test(head) ? "high" : "medium", "Terraform HCL");
  if (ext === ".tfvars") return res("tfvars", "high", "Terraform variable values; secret-scanned only");
  if (ext === ".tfstate" || /\.tfstate\.backup$/.test(b)) return res("tfstate", "high", "Terraform state JSON");

  const c0 = head[head.search(/\S/)];
  if (c0 === "{" || c0 === "[") {
    let j = null; try { j = JSON.parse(t); } catch (_) { j = null; }
    if (j && typeof j === "object" && !Array.isArray(j)) {
      if (j.planned_values || (j.format_version && j.resource_changes)) return res("tfplan", "high", "terraform show -json plan");
      if (j.terraform_version !== undefined && Array.isArray(j.resources)) return res("tfstate", "high", "Terraform state JSON");
      if (typeof j.$schema === "string" && /deploymentparameters/i.test(j.$schema)) return res("arm-parameters", "high", "ARM parameters file; scan the template it feeds");
      if (typeof j.$schema === "string" && /deploymenttemplate/i.test(j.$schema)) return res("arm", "high", "Azure Resource Manager template");
      if (j.AWSTemplateFormatVersion || (j.Resources && typeof j.Resources === "object" && Object.values(j.Resources).some((r) => r && typeof r.Type === "string" && /^(AWS|Custom)::/.test(r.Type)))) return res("cloudformation", "high", "CloudFormation template JSON");
      if (j.apiVersion && j.kind) return res("kubernetes", "high", "Kubernetes object JSON");
      if (Array.isArray(j.resources) && j.resources.some((r) => r && r.apiVersion && typeof r.type === "string" && r.type.includes("/"))) return res("arm", "medium", "ARM-shaped resources (no $schema)");
    }
    if (Array.isArray(j) && j.length && j.every((x) => x && x.apiVersion && x.kind)) return res("kubernetes", "medium", "array of Kubernetes objects");
    return res("json", "low", "JSON without a recognised IaC shape; secret-scanned only");
  }

  const yamlExt = ext === ".yaml" || ext === ".yml";
  if (inWorkflows && yamlExt) return res("github-actions", /^jobs\s*:/m.test(head) ? "high" : "medium", "GitHub Actions workflow");
  if (yamlExt || ext === ".template") {
    if (/^AWSTemplateFormatVersion\s*:/m.test(head) || (/^Resources\s*:/m.test(head) && /Type:\s*['"]?(AWS|Custom)::/.test(head))) return res("cloudformation", "high", "CloudFormation template YAML");
    if (/^apiVersion\s*:/m.test(head) && /^kind\s*:/m.test(head)) return res("kubernetes", "high", "Kubernetes manifest");
    if (/^services\s*:/m.test(head)) return res("compose", /compose/.test(b) ? "high" : "medium", "docker-compose services");
    if (/^jobs\s*:/m.test(head) && /^["']?on["']?\s*:/m.test(head)) return res("github-actions", "medium", "workflow-shaped YAML outside .github/workflows");
    return res("yaml", "low", "YAML without a recognised IaC shape; secret-scanned only");
  }
  if (!ext && /^[^\S\n\r\u2028\u2029]*FROM\s+\S/m.test(head) && /^[^\S\n\r\u2028\u2029]*(RUN|COPY|CMD|ENTRYPOINT|USER|EXPOSE)\b/m.test(head)) return res("dockerfile", "medium", "Dockerfile-shaped content");
  if (/^[^\S\n\r\u2028\u2029]*(resource|data|module|provider)\s+"[^"]+"/m.test(head)) return res("terraform", "medium", "HCL-shaped content");
  return res("text", "low", "not an IaC format; secret-scanned only");
}

/* ------------------------------------------------------------------------ */
/* Parsers -> normalised resources                                           */
/* resource: { platform, format, mode, type, name, id, props, file, line, endLine, ns?, doc? } */
/* ------------------------------------------------------------------------ */

function tfPlatform(type) {
  if (type.startsWith("aws_")) return "aws";
  if (/^(azurerm|azuread|azapi)_/.test(type)) return "azure";
  if (type.startsWith("google_")) return "gcp";
  if (type.startsWith("kubernetes_") || type.startsWith("helm_")) return "kubernetes";
  return "terraform";
}

function hclProps(block) {
  const p = {};
  for (const [k, v] of Object.entries(block.attrs || {})) p[k] = v;
  for (const b of block.blocks || []) {
    if (b.type === "dynamic") { p.__dynamic = (p.__dynamic || []).concat(b.labels[0] || "?"); continue; }
    const sub = hclProps(b);
    p[b.type] = Array.isArray(p[b.type]) ? p[b.type].concat([sub]) : [sub];
  }
  return p;
}

function addRes(f, r) { f.resources.push(r); }

/** Replace top-level `key = jsonencode({...})` raw values with the parsed object, read from source. */
function resolveJsonencode(props, src, from, to) {
  for (const [k, v] of Object.entries(props)) {
    if (!v || typeof v !== "object" || typeof v.raw !== "string" || !/^jsonencode\s*\(/.test(v.raw)) continue;
    const re = new RegExp("\\b" + reEsc(k) + "\\s*=\\s*jsonencode\\s*\\(", "g");
    re.lastIndex = from;
    const m = re.exec(src);
    if (!m || m.index > to) continue;
    let i = m.index + m[0].length, depth = 1, q = false;
    const start = i;
    for (; i < src.length && depth; i++) {
      const ch = src[i];
      if (q) { if (ch === "\\") i++; else if (ch === '"') q = false; continue; }
      if (ch === '"') q = true; else if (ch === "(") depth++; else if (ch === ")") depth--;
    }
    if (depth) continue;
    try { const val = parseHcl("x = " + src.slice(start, i - 1)).attrs.x; if (val && typeof val === "object" && !isDyn(val)) props[k] = val; } catch (_) { /* keep raw: reported as not evaluated */ }
  }
}

function parseTerraformFile(f) {
  let parsed;
  try { parsed = parseHcl(f.text); } catch (e) { f.skipped.push({ check: "parse", reason: "HCL parse error: " + ((e && e.message) || e) }); return; }
  const lines = splitLines(f.text);
  const found = [];
  let cursor = 0;
  for (const blk of parsed.blocks) {
    const lbl = blk.labels.map((l) => `(?:"${reEsc(l)}"|${reEsc(l)})`).join("\\s+");
    const re = new RegExp("^\\s*" + reEsc(blk.type) + (lbl ? "\\s+" + lbl : "") + "\\s*\\{");
    let line = findLine(lines, re, cursor) || findLine(lines, re, 0);
    if (line) cursor = line;
    found.push({ blk, line });
  }
  const starts = found.map((x) => x.line).filter(Boolean).sort((a, b) => a - b);
  const endOf = (line) => { const nx = starts.find((s) => s > line); return nx ? nx - 1 : lines.length; };
  f.blocks = parsed.blocks.length;
  const offs = [0];
  for (const l of lines) offs.push(offs[offs.length - 1] + l.length + 1);
  for (const { blk, line } of found) {
    const props = hclProps(blk);
    if (line) resolveJsonencode(props, f.text, offs[line - 1], offs[line ? endOf(line) : lines.length] || f.text.length);
    const L = line || 1, E = line ? endOf(line) : lines.length;
    if ((blk.type === "resource" || blk.type === "data") && blk.labels.length >= 2) {
      const [type, name] = blk.labels;
      addRes(f, { platform: tfPlatform(type), format: "terraform", mode: blk.type === "data" ? "data" : "managed", type, name, id: (blk.type === "data" ? "data." : "") + type + "." + name, props, file: f.name, line: L, endLine: E });
    } else if (["module", "provider", "variable", "output", "terraform", "locals"].includes(blk.type)) {
      const nm = blk.labels[0] || blk.type;
      addRes(f, { platform: "terraform", format: "terraform", mode: blk.type, type: blk.type, name: nm, id: blk.type + "." + nm, props, file: f.name, line: L, endLine: E });
    }
  }
}

function walkPlanModule(mod, f, lines) {
  for (const r of arr(mod && mod.resources)) {
    if (!r || typeof r !== "object" || !r.type) continue;
    const type = String(r.type), name = String(r.name || "");
    const addr = String(r.address || type + "." + name);
    const line = findLine(lines, new RegExp('"address"\\s*:\\s*"' + reEsc(addr) + '"')) || 1;
    addRes(f, { platform: tfPlatform(type), format: "tfplan", mode: r.mode === "data" ? "data" : "managed", type, name, id: addr, props: r.values && typeof r.values === "object" ? r.values : {}, file: f.name, line, endLine: line });
  }
  for (const c of arr(mod && mod.child_modules)) walkPlanModule(c, f, lines);
}

function parseTfPlanFile(f) {
  let j; try { j = JSON.parse(f.text); } catch (e) { f.skipped.push({ check: "parse", reason: "JSON parse error: " + ((e && e.message) || e) }); return; }
  const root = j && j.planned_values && j.planned_values.root_module;
  if (!root) { f.skipped.push({ check: "parse", reason: "no planned_values.root_module (use `terraform show -json tfplan`)" }); return; }
  f.docs = 1;
  walkPlanModule(root, f, splitLines(f.text));
}

function parseTfStateFile(f) {
  let j; try { j = JSON.parse(f.text); } catch (e) { f.skipped.push({ check: "parse", reason: "JSON parse error: " + ((e && e.message) || e) }); return; }
  if (!Array.isArray(j && j.resources)) { f.skipped.push({ check: "parse", reason: "state has no resources[] (format version 4 expected)" }); return; }
  const lines = splitLines(f.text);
  f.docs = 1;
  for (const r of j.resources) {
    if (!r || !r.type) continue;
    const type = String(r.type), name = String(r.name || "");
    const insts = arr(r.instances);
    const line = findLine(lines, new RegExp('"name"\\s*:\\s*"' + reEsc(name) + '"')) || 1;
    insts.forEach((inst, i) => {
      const idx = inst && inst.index_key !== undefined ? "[" + JSON.stringify(inst.index_key) + "]" : insts.length > 1 ? "[" + i + "]" : "";
      addRes(f, { platform: tfPlatform(type), format: "tfstate", mode: r.mode === "data" ? "data" : "managed", type, name: name + idx, id: (r.module ? r.module + "." : "") + (r.mode === "data" ? "data." : "") + type + "." + name + idx, props: inst && inst.attributes && typeof inst.attributes === "object" ? inst.attributes : {}, file: f.name, line, endLine: line });
    });
  }
}

function parseOneDoc(text) {
  const t = String(text || "");
  const c0 = t[t.search(/\S/)];
  if (c0 === "{" || c0 === "[") { try { return JSON.parse(t); } catch (_) { /* YAML is a JSON superset; fall through */ } }
  const v = parseYamlSubset(t);
  return Array.isArray(v) && v.length && v.every((d) => d && typeof d === "object" && !Array.isArray(d)) && /^---/m.test(t) ? v[0] : v;
}

/** Map entries of a top-level YAML/JSON map key to line ranges. */
function childLines(lines, parentRe, names) {
  const pl = findLine(lines, parentRe);
  const at = new Map();
  for (const n of names) at.set(n, findLine(lines, new RegExp("^\\s+[\"']?" + reEsc(n) + "[\"']?\\s*:"), pl) || pl || 1);
  const starts = [...at.values()].sort((a, b) => a - b);
  const range = (n) => { const l = at.get(n); const nx = starts.find((s) => s > l); return [l, nx ? nx - 1 : lines.length]; };
  return range;
}

function parseCfnFile(f) {
  let doc; try { doc = parseOneDoc(f.text); } catch (e) { f.skipped.push({ check: "parse", reason: "template parse error: " + ((e && e.message) || e) }); return; }
  const resources = doc && doc.Resources && typeof doc.Resources === "object" ? doc.Resources : null;
  if (!resources) { f.skipped.push({ check: "parse", reason: "no Resources map in template" }); return; }
  f.docs = 1;
  const lines = splitLines(f.text);
  const names = Object.keys(resources);
  const range = childLines(lines, /^\s*["']?Resources["']?\s*:/, names);
  for (const name of names) {
    const r = resources[name];
    if (!r || typeof r !== "object") continue;
    const type = typeof r.Type === "string" ? r.Type : "<dynamic>";
    const [line, endLine] = range(name);
    addRes(f, { platform: /^(AWS|Custom)::/.test(type) ? "aws" : "cloudformation", format: "cloudformation", mode: "managed", type, name, id: type + "." + name, props: r.Properties && typeof r.Properties === "object" ? r.Properties : {}, file: f.name, line, endLine });
  }
}

function yamlSegments(text) {
  const lines = splitLines(text);
  const segs = []; let start = 0;
  for (let i = 0; i < lines.length; i++) if (/^---(\s|$)/.test(lines[i])) { segs.push({ start, end: i, lines: lines.slice(start, i) }); start = i + 1; }
  segs.push({ start, end: lines.length, lines: lines.slice(start) });
  return segs.filter((s) => s.lines.some((l) => l.trim() && !l.trim().startsWith("#")));
}

function parseK8sFile(f) {
  const t = String(f.text || "");
  const lines = splitLines(t);
  const pushDoc = (doc, start, end, idx) => {
    if (!doc || typeof doc !== "object" || Array.isArray(doc)) return;
    if (/List$/.test(String(doc.kind)) && Array.isArray(doc.items)) { doc.items.forEach((d, i) => pushDoc(d, start, end, idx + "." + i)); return; }
    if (!doc.kind || !doc.apiVersion) { f.skipped.push({ check: "doc " + idx, reason: "document has no apiVersion/kind" }); return; }
    const kind = String(doc.kind), name = String(get(doc, "metadata.name") || get(doc, "metadata.generateName") || "<unnamed>");
    const ns = get(doc, "metadata.namespace");
    const line = findLine(lines, /^\s*"?kind"?\s*:/, start, end) || start + 1;
    addRes(f, { platform: "kubernetes", format: "kubernetes", mode: "managed", type: kind, name: (ns ? ns + "/" : "") + name, id: kind + "/" + (ns ? ns + "/" : "") + name, ns: ns == null ? null : String(ns), props: doc, file: f.name, line, endLine: end, doc: idx });
  };
  const c0 = t[t.search(/\S/)];
  if (c0 === "{" || c0 === "[") {
    let j; try { j = JSON.parse(t); } catch (e) { f.skipped.push({ check: "parse", reason: "JSON parse error: " + ((e && e.message) || e) }); return; }
    arr(j).forEach((d, i) => pushDoc(d, 0, lines.length, String(i)));
    f.docs = arr(j).length;
    return;
  }
  const segs = yamlSegments(t);
  f.docs = segs.length;
  segs.forEach((seg, i) => {
    let doc;
    try { doc = parseYamlSubset(seg.lines.join("\n")); } catch (e) { f.skipped.push({ check: "doc " + i, reason: "YAML parse error: " + ((e && e.message) || e) }); return; }
    pushDoc(doc, seg.start, seg.end, String(i));
  });
}

/** Dockerfile -> [{cmd, args, line, stage}] with continuation lines joined. */
export function parseDockerfile(text) {
  const lines = splitLines(text);
  const ins = []; let stage = 0, i = 0, escCh = "\\";
  while (i < lines.length) {
    const raw = lines[i];
    const dir = /^\s*#\s*escape\s*=\s*(\S)/i.exec(raw);
    if (dir && !ins.length) { escCh = dir[1]; i++; continue; }
    if (!raw.trim() || raw.trim().startsWith("#")) { i++; continue; }
    const start = i;
    let acc = raw;
    while (acc.trimEnd().endsWith(escCh) && i + 1 < lines.length) {
      acc = acc.trimEnd().slice(0, -1);
      i++;
      if (lines[i].trim().startsWith("#")) { acc += escCh; continue; }
      acc += "\n" + lines[i];
    }
    i++;
    const m = /^\s*([A-Za-z]+)\s*([\s\S]*)$/.exec(acc);
    if (!m) continue;
    const cmd = m[1].toUpperCase();
    if (cmd === "FROM" && ins.some((x) => x.cmd === "FROM")) stage++;
    ins.push({ cmd, args: m[2].replace(/\s*\n\s*/g, " ").trim(), line: start + 1, stage });
  }
  return ins;
}

function parseDockerfileFile(f) {
  const ins = parseDockerfile(f.text);
  if (!ins.some((x) => x.cmd === "FROM")) { f.skipped.push({ check: "parse", reason: "no FROM instruction" }); return; }
  f.blocks = ins.length;
  addRes(f, { platform: "docker", format: "dockerfile", mode: "managed", type: "Dockerfile", name: f.name, id: "Dockerfile:" + f.name, props: { instructions: ins, stages: ins.filter((x) => x.cmd === "FROM").length }, file: f.name, line: ins[0].line, endLine: splitLines(f.text).length });
}

function parseComposeFile(f) {
  let doc;
  try { doc = parseOneDoc(f.text); } catch (e) {
    const msg = String((e && e.message) || e);
    f.skipped.push({ check: "parse", reason: "YAML parse error: " + msg + (/anchor|alias/i.test(msg) ? " (expand YAML anchors with `docker compose config` and scan that output)" : "") });
    return;
  }
  const services = doc && doc.services && typeof doc.services === "object" ? doc.services : null;
  if (!services) { f.skipped.push({ check: "parse", reason: "no services map" }); return; }
  f.docs = 1;
  const lines = splitLines(f.text);
  const names = Object.keys(services);
  const range = childLines(lines, /^["']?services["']?\s*:/, names);
  for (const name of names) {
    const s = services[name];
    if (!s || typeof s !== "object") continue;
    const [line, endLine] = range(name);
    addRes(f, { platform: "compose", format: "compose", mode: "managed", type: "service", name, id: "service." + name, props: s, file: f.name, line, endLine });
  }
}

function parseArmFile(f) {
  let j; try { j = JSON.parse(f.text); } catch (e) { f.skipped.push({ check: "parse", reason: "JSON parse error: " + ((e && e.message) || e) }); return; }
  const res = arr(j && j.resources);
  if (!res.length) { f.skipped.push({ check: "parse", reason: "no resources[] array" }); return; }
  f.docs = 1;
  const lines = splitLines(f.text);
  const seen = new Map();
  const walk = (r, parentType) => {
    if (!r || typeof r !== "object" || typeof r.type !== "string") return;
    const type = parentType && r.type.split("/").length < 3 && !r.type.includes(".") ? parentType + "/" + r.type : r.type;
    const n = seen.get(r.type) || 0; seen.set(r.type, n + 1);
    const re = new RegExp('"type"\\s*:\\s*"' + reEsc(r.type) + '"');
    let line = 0, k = -1;
    for (let i = 0; i < lines.length; i++) if (re.test(lines[i]) && ++k === n) { line = i + 1; break; }
    const name = typeof r.name === "string" ? r.name : "<dynamic>";
    addRes(f, { platform: "azure", format: "arm", mode: "managed", type, name, id: type + "/" + name, props: r.properties && typeof r.properties === "object" ? r.properties : {}, arm: r, file: f.name, line: line || 1, endLine: line || 1 });
    for (const c of arr(r.resources)) walk(c, type);
  };
  for (const r of res) walk(r, null);
}

function parseWorkflowFile(f) {
  let doc; try { doc = parseOneDoc(f.text); } catch (e) { f.skipped.push({ check: "parse", reason: "YAML parse error: " + ((e && e.message) || e) }); return; }
  if (!doc || typeof doc !== "object" || !doc.jobs || typeof doc.jobs !== "object") { f.skipped.push({ check: "parse", reason: "no jobs map (not a workflow)" }); return; }
  f.docs = 1;
  const on = doc.on !== undefined ? doc.on : doc["true"];
  addRes(f, { platform: "github-actions", format: "github-actions", mode: "managed", type: "workflow", name: String(doc.name || base(f.name)), id: "workflow:" + f.name, props: { ...doc, on }, file: f.name, line: 1, endLine: splitLines(f.text).length });
}

const PARSERS = {
  terraform: parseTerraformFile, tfplan: parseTfPlanFile, tfstate: parseTfStateFile, cloudformation: parseCfnFile,
  kubernetes: parseK8sFile, dockerfile: parseDockerfileFile, compose: parseComposeFile, arm: parseArmFile, "github-actions": parseWorkflowFile,
};
const UNSUPPORTED = new Set(["bicep", "helm-values", "helm-template", "helm-chart", "arm-parameters"]);

/** Kinds whose resources are rule-checked (others are secret-scanned only). */
export const SCANNABLE = Object.keys(PARSERS);

/**
 * Parse dropped files. Accepts a string, one {name,text} or an array of them.
 * Returns { format:"iac", headers, files:[{name, kind, confidence, note, docs, blocks, resources, skipped}], rows:[resources], skipped }.
 * Never throws; per-file problems are listed in files[i].skipped.
 */
export function parseInput(input, opts = {}) {
  const items = typeof input === "string" ? [{ name: "input", text: input }] : Array.isArray(input) ? input : input ? [input] : [];
  const maxBytes = opts.maxFileBytes || DEFAULTS.maxFileBytes;
  const files = [], rows = [];
  for (const it of items) {
    if (!it) continue;
    const name = String(it.name || "input");
    const text = typeof it === "string" ? it : typeof it.text === "string" ? it.text : "";
    const c = classify(name, text);
    const f = { name, kind: c.kind, confidence: c.confidence, note: c.reason, bytes: text.length, lines: text ? splitLines(text).length : 0, docs: 0, blocks: 0, resources: [], skipped: [], text };
    if (/[\u0000-\u0008\u000e-\u001a]/.test(text.slice(0, 4096))) { f.kind = "binary"; f.confidence = "high"; f.note = "binary content; skipped"; f.text = ""; }
    else if (text.length > maxBytes) f.skipped.push({ check: "size", reason: "over " + Math.round(maxBytes / 1048576) + " MB; secret-scanned only" });
    else if (PARSERS[f.kind]) PARSERS[f.kind](f);
    else if (UNSUPPORTED.has(f.kind)) f.skipped.push({ check: "unsupported", reason: c.reason });
    for (const r of f.resources) rows.push(r);
    files.push(f);
  }
  files.sort((a, b) => cmp(a.name, b.name));
  rows.sort((a, b) => cmp(a.file, b.file) || a.line - b.line || cmp(a.id, b.id));
  return { format: "iac", headers: ["file", "kind", "platform", "type", "name", "line"], files, rows, skipped: [] };
}

/* ------------------------------------------------------------------------ */
/* Rule framework                                                            */
/* A rule: { id, title, severity, kind (platform), frameworks, recommendation, */
/*           applies(resource), check(ctx) -> hits[] }                        */
/* A hit:  { detail, key?, line?, conf?, dyn? }                               */
/* ------------------------------------------------------------------------ */

const CA = "CIS AWS Foundations v3.0", CZ = "CIS Azure Foundations", CG = "CIS GCP Foundations v2.0", CK = "CIS Kubernetes v1.9";
const CD = "CIS Docker Benchmark", CS = "CIS Software Supply Chain", N = "NIST 800-53", M = "MITRE ATT&CK";

const fw = (pairs) => pairs.map(([framework, id]) => ({ framework, id }));
const RULE_LIST = [];
function rule(id, severity, kind, types, title, frameworks, recommendation, check) {
  const set = Array.isArray(types) ? new Set(types) : null;
  const applies = typeof types === "function" ? types : (r) => set.has(r.type);
  RULE_LIST.push({ id, title, severity, kind, frameworks: fw(frameworks), recommendation, applies, check });
}

const isCfnRes = (r) => r.format === "cloudformation";
const TFFMT = new Set(["terraform", "tfplan", "tfstate"]);

/** Does value v refer to resource r (TF traversal, CFN Ref/GetAtt, or concrete id in plan/state)? */
function refersTo(v, r) {
  if (v == null) return false;
  const s = typeof v === "string" ? v : JSON.stringify(v);
  if (r.format === "cloudformation") {
    return s.includes('"Ref":"' + r.name + '"') || s.includes('"!Ref":"' + r.name + '"') || new RegExp('"(?:Fn::GetAtt|!GetAtt)":\\[?"' + reEsc(r.name) + '[".]').test(s);
  }
  if (new RegExp("(^|[^\\w-])" + reEsc(r.type + "." + r.name) + "(\\.|$|[^\\w-])").test(s)) return true;
  const ids = [r.props.id, r.props.bucket, r.props.arn, r.props.name].filter((x) => typeof x === "string" && x);
  return typeof v === "string" && ids.includes(v);
}

/** Resources of `types` linked to r through attribute `key`; unknown=true when some link cannot be resolved. */
function related(c, types, key) {
  const set = new Set(types), out = []; let unknown = false;
  for (const o of c.all) {
    if (!set.has(o.type) || o === c.r) continue;
    if (TFFMT.has(c.r.format) !== TFFMT.has(o.format)) continue;
    const v = pick(o.props, key);
    if (refersTo(v, c.r)) out.push(o);
    else if (v == null || (isDyn(v) && !/^(aws|azurerm|google)_/.test(String(v.ref || v.raw || "").replace(/^data\./, "")))) unknown = true;
  }
  return { list: out, unknown };
}

/** Required-true check: absent -> `absent` confidence (or no hit when null), false -> confirmed. */
function needTrue(tf, cfn, label, absent = "likely") {
  return (c) => {
    const path = c.cfn ? cfn : tf;
    if (!path) return [];
    const v = pick(c.p, path);
    const key = path.split("|")[0].split(".").pop();
    if (v === undefined || v === null) return absent ? [c.H(label + " is not set (the default is off)", key, absent)] : [];
    if (isDyn(v)) return [c.D(key)];
    if (isTrue(v)) return [];
    return [c.H(label + " is " + JSON.stringify(v), key, "confirmed")];
  };
}
/** Must-not-be-true check: fires only on an explicit true (or on absence when absentHit is set). */
function needNotTrue(tf, cfn, label, absentHit = null) {
  return (c) => {
    const path = c.cfn ? cfn : tf;
    if (!path) return [];
    const v = pick(c.p, path);
    const key = path.split("|")[0].split(".").pop();
    if (v === undefined || v === null) return absentHit ? [c.H(label + " is not set and defaults to on", key, absentHit)] : [];
    if (isDyn(v)) return [c.D(key)];
    return isTrue(v) ? [c.H(label + " is true", key, "confirmed")] : [];
  };
}
/** Value present check. */
function needSet(tf, cfn, label, conf = "likely") {
  return (c) => {
    const path = c.cfn ? cfn : tf;
    if (!path) return [];
    const v = pick(c.p, path);
    if (v === undefined || v === null || v === "" || (Array.isArray(v) && !v.length)) return [c.H(label, path.split("|")[0].split(".").pop(), conf)];
    return [];
  };
}

const SECRET_KEY_RE = /(pass(word|wd)?|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|credential|auth[_-]?key|client[_-]?secret|conn(ection)?[_-]?string)/i;
const NOT_SECRET_KEY_RE = /(_file|_path|_url|_uri|_arn|_id|_name|_length|_ttl|_version|_policy|_type|_enabled|_rotation|_mode|_ref|_secret_name|_secret_key_ref)$|^(token_endpoint|secret_name|secretname)$/i;
const AKIA_RE = /\b(AKIA|ASIA)[0-9A-Z]{16}\b/;

/** A literal value that looks like a real secret (not a reference, placeholder or empty). */
export function isLiteralSecret(v) {
  if (typeof v !== "string") return typeof v === "number" ? String(v).length >= 6 : false;
  const s = v.trim();
  if (s.length < 4) return false;
  if (/\$\{|\{\{|\$\(|^\$[A-Za-z_]|^%[A-Za-z_]+%$|^<[^>]*>$|^(var|local|data|module)\./.test(s)) return false;
  if (/^(true|false|null|none|nil|undefined|yes|no|on|off|required|optional|enabled|disabled|redacted|\*+|x+|changeit_in_vault)$/i.test(s)) return false;
  if (/^(arn:|projects\/|https?:\/\/|\/|\.\/|secret(s)?\/|vault:|ssm:|sm:|kv\/|ref\+)/i.test(s)) return false;
  if (/^(.)\1+$/.test(s)) return false;
  return true;
}

function secretEnvHits(c, entries, keyName = "variables") {
  const hits = [];
  for (const [k, v] of entries) {
    if (isDyn(v)) continue;
    const sv = typeof v === "string" ? v : typeof v === "number" ? String(v) : null;
    if (sv == null) continue;
    let h = null;
    if (AKIA_RE.test(sv)) h = c.H("environment variable " + k + " holds an AWS access key id (" + mask(sv.match(AKIA_RE)[0]) + ")", k, "confirmed");
    else if (SECRET_KEY_RE.test(k) && !NOT_SECRET_KEY_RE.test(k) && isLiteralSecret(sv)) h = c.H("environment variable " + k + " is a literal value (" + mask(sv) + ")", k, "likely");
    if (h) { h.secret = sv; hits.push(h); }
  }
  return hits;
}

/* ---------------------------- AWS ---------------------------------------- */

const S3B = ["aws_s3_bucket", "AWS::S3::Bucket"];
const PUBLIC_ACLS = new Set(["public-read", "public-read-write", "authenticated-read", "publicread", "publicreadwrite", "authenticatedread"]);

rule("AWS-S3-001", "high", "aws", ["aws_s3_bucket", "aws_s3_bucket_acl", "AWS::S3::Bucket"], "S3 bucket has a public canned ACL",
  [[CA, "2.1.4"], [N, "AC-3"], [N, "AC-21"], [M, "T1530"]],
  "Remove the public canned ACL, set object ownership to BucketOwnerEnforced and enable S3 Block Public Access.",
  (c) => {
    const v = c.cfn ? c.p.AccessControl : c.p.acl;
    if (v == null) return [];
    if (isDyn(v)) return [c.D(c.cfn ? "AccessControl" : "acl")];
    return PUBLIC_ACLS.has(lc(v).replace(/[^a-z-]/g, "")) || PUBLIC_ACLS.has(lc(v)) ? [c.H("canned ACL is " + v, c.cfn ? "AccessControl" : "acl", "confirmed")] : [];
  });

const POLICY_TYPES = {
  aws_iam_policy: "policy", aws_iam_role_policy: "policy", aws_iam_user_policy: "policy", aws_iam_group_policy: "policy",
  aws_iam_policy_document: null, aws_s3_bucket_policy: "policy", aws_sqs_queue_policy: "policy", aws_sns_topic_policy: "policy",
  aws_ecr_repository_policy: "policy", aws_kms_key: "policy", aws_s3_bucket: "policy", aws_sqs_queue: "policy", aws_sns_topic: "policy",
  aws_iam_role: "inline_policy.policy",
  "AWS::IAM::Policy": "PolicyDocument", "AWS::IAM::ManagedPolicy": "PolicyDocument", "AWS::S3::BucketPolicy": "PolicyDocument",
  "AWS::SQS::QueuePolicy": "PolicyDocument", "AWS::SNS::TopicPolicy": "PolicyDocument", "AWS::ECR::Repository": "RepositoryPolicyText",
  "AWS::KMS::Key": "KeyPolicy", "AWS::IAM::Role": "Policies", "AWS::IAM::User": "Policies", "AWS::IAM::Group": "Policies",
};
/** Policy documents carried by a resource: [{stmts|null, key}] */
function policiesOf(r) {
  if (!Object.prototype.hasOwnProperty.call(POLICY_TYPES, r.type)) return []; // r.type is parser-controlled; `in` would walk the prototype chain ("constructor"/"__proto__")
  const p = r.props;
  if (r.type === "aws_iam_policy_document") return [{ stmts: policyStatements({ statement: p.statement }), key: "statement" }];
  const path = POLICY_TYPES[r.type];
  if (path === "Policies") return arr(p.Policies).map((x) => ({ stmts: x && x.PolicyDocument ? policyStatements(x.PolicyDocument) : null, key: "PolicyDocument" }));
  if (path === "inline_policy.policy") return arr(p.inline_policy).map((x) => ({ stmts: policyStatements(x && x.policy), key: "policy", dyn: isDyn(x && x.policy) }));
  const v = p[path];
  if (v == null) return [];
  return [{ stmts: policyStatements(v), key: path, dyn: isDyn(v) || (v && typeof v === "object" && typeof v.raw === "string") }];
}
const IDENTITY_POLICY = new Set(["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_policy_document", "aws_iam_role", "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"]);
const RESOURCE_POLICY = new Set(["aws_s3_bucket_policy", "aws_sqs_queue_policy", "aws_sns_topic_policy", "aws_ecr_repository_policy", "aws_kms_key", "aws_s3_bucket", "aws_sqs_queue", "aws_sns_topic", "aws_iam_policy_document", "AWS::S3::BucketPolicy", "AWS::SQS::QueuePolicy", "AWS::SNS::TopicPolicy", "AWS::ECR::Repository", "AWS::KMS::Key"]);

function publicPolicyCheck(types) {
  return (c) => {
    const hits = [];
    for (const pol of policiesOf(c.r)) {
      if (!pol.stmts) { if (pol.dyn) hits.push(c.D(pol.key)); continue; }
      for (const st of pol.stmts) {
        if (lc(st.effect) !== "allow" || !principalIsPublic(st.principal)) continue;
        const cond = st.condition && Object.keys(st.condition).length;
        if (c.r.type === "aws_iam_policy_document" && !types.includes("doc")) continue;
        hits.push(c.H("Allow to Principal \"*\" for " + st.actions.slice(0, 4).join(", ") + (cond ? " (with a Condition; review that it restricts the caller)" : " with no Condition"), pol.key, cond ? "review" : "confirmed"));
      }
    }
    return hits;
  };
}

rule("AWS-S3-002", "critical", "aws", ["aws_s3_bucket_policy", "aws_s3_bucket", "AWS::S3::BucketPolicy"], "S3 bucket policy grants access to everyone",
  [[CA, "2.1.4"], [N, "AC-3"], [N, "AC-21"], [M, "T1530"]],
  "Scope the Principal to specific accounts or roles, or add aws:PrincipalOrgID / aws:SourceVpce conditions; keep Block Public Access on.",
  publicPolicyCheck(["s3"]));

function s3Cross(c, types, key) { return related(c, types, key); }

rule("AWS-S3-003", "medium", "aws", S3B, "S3 bucket has no Block Public Access configuration",
  [[CA, "2.1.4"], [N, "AC-3"], [M, "T1530"]],
  "Add aws_s3_bucket_public_access_block (or PublicAccessBlockConfiguration) with all four settings true.",
  (c) => {
    const FLAGS = c.cfn ? ["BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"] : ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"];
    let cfg;
    if (c.cfn) cfg = c.p.PublicAccessBlockConfiguration;
    else {
      const rel = s3Cross(c, ["aws_s3_bucket_public_access_block"], "bucket");
      if (!rel.list.length && rel.unknown) return [c.D("bucket", "an aws_s3_bucket_public_access_block exists but its bucket link could not be resolved")];
      cfg = rel.list.length ? rel.list[0].props : null;
    }
    if (!cfg) return [c.H("no public access block is defined for this bucket in the scanned files (account-level block may still apply)", null, "likely")];
    if (isDyn(cfg)) return [c.D("PublicAccessBlockConfiguration")];
    const off = FLAGS.filter((k) => !isTrue(cfg[k]) && !isDyn(cfg[k]));
    return off.length ? [c.H("public access block leaves " + off.join(", ") + " off", off[0], "confirmed")] : [];
  });

rule("AWS-S3-004", "medium", "aws", S3B, "S3 bucket versioning is not enabled",
  [[N, "CP-9"], [N, "SI-12"], [M, "T1485"]],
  "Enable versioning (aws_s3_bucket_versioning status = \"Enabled\" or VersioningConfiguration.Status: Enabled) so overwritten or deleted objects can be recovered.",
  (c) => {
    if (c.cfn) {
      const s = get(c.p, "VersioningConfiguration.Status");
      if (s == null) return [c.H("VersioningConfiguration is not set", null, "likely")];
      if (isDyn(s)) return [c.D("Status")];
      return lc(s) === "enabled" ? [] : [c.H("versioning status is " + s, "Status", "confirmed")];
    }
    const inline = get(c.p, "versioning.enabled");
    if (isTrue(inline)) return [];
    const rel = s3Cross(c, ["aws_s3_bucket_versioning"], "bucket");
    const st = rel.list.map((o) => get(o.props, "versioning_configuration.status"));
    if (st.some((s) => lc(s) === "enabled")) return [];
    if (st.some((s) => isDyn(s)) || (!rel.list.length && rel.unknown)) return [c.D("versioning")];
    if (isFalse(inline) || st.length) return [c.H("versioning is " + (st.length ? st.join(", ") : "disabled"), "versioning", "confirmed")];
    return [c.H("no versioning configuration for this bucket in the scanned files", null, "likely")];
  });

rule("AWS-S3-005", "low", "aws", S3B, "S3 bucket has no explicit default encryption configuration",
  [[N, "SC-28"], [N, "SC-12"]],
  "Declare server-side encryption explicitly, with SSE-KMS and a customer-managed key for sensitive data. Since January 2023 AWS applies SSE-S3 to new objects even when this is absent.",
  (c) => {
    if (c.cfn) return c.p.BucketEncryption == null ? [c.H("BucketEncryption is not set (AWS applies SSE-S3 by default since 2023-01-05)", null, "likely")] : [];
    if (c.p.server_side_encryption_configuration) return [];
    const rel = s3Cross(c, ["aws_s3_bucket_server_side_encryption_configuration"], "bucket");
    if (rel.list.length) return [];
    if (rel.unknown) return [c.D("server_side_encryption_configuration")];
    return [c.H("no server-side encryption configuration in the scanned files (AWS applies SSE-S3 by default since 2023-01-05)", null, "likely")];
  });

rule("AWS-S3-006", "low", "aws", S3B, "S3 server access logging is not enabled",
  [[N, "AU-2"], [N, "AU-12"]],
  "Enable server access logging (aws_s3_bucket_logging or LoggingConfiguration) to a dedicated log bucket, or CloudTrail data events.",
  (c) => {
    if (c.cfn) return c.p.LoggingConfiguration == null ? [c.H("LoggingConfiguration is not set", null, "likely")] : [];
    if (c.p.logging) return [];
    const rel = s3Cross(c, ["aws_s3_bucket_logging"], "bucket");
    if (rel.list.length) return [];
    if (rel.unknown) return [c.D("logging")];
    return [c.H("no access logging configuration for this bucket in the scanned files", null, "likely")];
  });

rule("AWS-S3-007", "low", "aws", S3B, "S3 MFA delete is not enabled",
  [[CA, "2.1.2"], [N, "CP-9"], [M, "T1485"]],
  "Enable MFA delete on versioned buckets that hold critical data (root credentials are required to set it).",
  (c) => {
    if (c.cfn) return [c.S("CloudFormation has no property for MFA delete; verify it with `aws s3api get-bucket-versioning`")];
    if (isTrue(get(c.p, "versioning.mfa_delete"))) return [];
    const rel = s3Cross(c, ["aws_s3_bucket_versioning"], "bucket");
    if (rel.list.some((o) => lc(get(o.props, "versioning_configuration.mfa_delete")) === "enabled")) return [];
    if (!rel.list.length && rel.unknown) return [c.D("mfa_delete")];
    return [c.H("MFA delete is not enabled", "mfa_delete", "likely")];
  });

rule("AWS-S3-008", "low", "aws", S3B, "S3 bucket policy does not deny unencrypted (HTTP) requests",
  [[CA, "2.1.1"], [N, "SC-8"]],
  "Add a Deny statement for all principals when aws:SecureTransport is false.",
  (c) => {
    const pols = [];
    if (c.cfn) { for (const o of c.all) if (o.type === "AWS::S3::BucketPolicy" && refersTo(o.props.Bucket, c.r)) pols.push(...policiesOf(o)); }
    else {
      pols.push(...policiesOf(c.r));
      const rel = s3Cross(c, ["aws_s3_bucket_policy"], "bucket");
      for (const o of rel.list) pols.push(...policiesOf(o));
      if (!rel.list.length && rel.unknown) return [c.D("policy")];
    }
    if (pols.some((p) => !p.stmts)) return pols.some((p) => p.dyn) ? [c.D("policy")] : [];
    const ok = pols.some((p) => p.stmts.some((s) => lc(s.effect) === "deny" && /securetransport/i.test(JSON.stringify(s.condition || {}))));
    return ok ? [] : [c.H(pols.length ? "bucket policy has no aws:SecureTransport deny" : "no bucket policy in the scanned files", null, "likely")];
  });

/* Encryption at rest */
rule("AWS-EBS-001", "medium", "aws", ["aws_ebs_volume", "AWS::EC2::Volume"], "EBS volume is not encrypted",
  [[CA, "2.2.1"], [N, "SC-28"]],
  "Set encrypted = true (Encrypted: true) with a KMS key, and enable EBS encryption by default for the account and region.",
  (c) => (c.all.some((o) => o.type === "aws_ebs_encryption_by_default" && isTrue(o.props.enabled)) ? [] : needTrue("encrypted", "Encrypted", "encrypted")(c)));
rule("AWS-EBS-002", "medium", "aws", ["aws_ebs_encryption_by_default"], "EBS encryption by default is disabled",
  [[CA, "2.2.1"], [N, "SC-28"]], "Set enabled = true on aws_ebs_encryption_by_default.",
  (c) => (isFalse(c.p.enabled) ? [c.H("enabled is false", "enabled", "confirmed")] : []));

const RDS = ["aws_db_instance", "aws_rds_cluster", "AWS::RDS::DBInstance", "AWS::RDS::DBCluster"];
rule("AWS-RDS-001", "high", "aws", RDS, "RDS storage is not encrypted",
  [[CA, "2.3.1"], [N, "SC-28"], [M, "T1530"]],
  "Set storage_encrypted = true (StorageEncrypted: true) with a KMS key. Existing instances must be restored from an encrypted snapshot copy.",
  (c) => {
    if (c.cfn && (c.p.SourceDBInstanceIdentifier || c.p.DBClusterIdentifier)) return [];
    if (!c.cfn && c.r.type === "aws_db_instance" && (c.p.replicate_source_db || c.p.cluster_identifier)) return [];
    return needTrue("storage_encrypted", "StorageEncrypted", "storage encryption")(c);
  });
rule("AWS-RDS-002", "high", "aws", ["aws_db_instance", "AWS::RDS::DBInstance", "aws_rds_cluster_instance"], "RDS instance is publicly accessible",
  [[CA, "2.3.3"], [N, "SC-7"], [M, "T1190"]], "Set publicly_accessible = false and reach the database through private subnets, a bastion or SSM.",
  needNotTrue("publicly_accessible", "PubliclyAccessible", "publicly accessible"));
rule("AWS-RDS-003", "medium", "aws", RDS, "RDS automated backups are disabled",
  [[N, "CP-9"], [M, "T1490"]], "Set backup_retention_period (BackupRetentionPeriod) to at least 7 days.",
  (c) => {
    const k = c.cfn ? "BackupRetentionPeriod" : "backup_retention_period";
    const v = c.p[k];
    if (v == null) return [];
    if (isDyn(v)) return [c.D(k)];
    return num(v) === 0 ? [c.H("backup retention is 0 days", k, "confirmed")] : [];
  });
rule("AWS-RDS-004", "low", "aws", RDS, "RDS deletion protection is off",
  [[N, "CP-9"], [M, "T1485"]], "Set deletion_protection = true (DeletionProtection: true) for production databases.",
  needTrue("deletion_protection", "DeletionProtection", "deletion protection"));
rule("AWS-RDS-005", "info", "aws", ["aws_db_instance", "AWS::RDS::DBInstance"], "RDS instance is not Multi-AZ",
  [[N, "CP-10"]], "Use multi_az = true (MultiAZ: true) for production databases that need availability during an AZ outage.",
  (c) => (c.p.replicate_source_db || c.p.cluster_identifier || c.p.DBClusterIdentifier ? [] : needTrue("multi_az", "MultiAZ", "Multi-AZ")(c)));
rule("AWS-RDS-006", "low", "aws", ["aws_db_instance", "AWS::RDS::DBInstance"], "RDS automatic minor version upgrade is disabled",
  [[CA, "2.3.2"], [N, "SI-2"]], "Leave auto_minor_version_upgrade at its default (true) so security patches are applied in the maintenance window.",
  (c) => { const k = c.cfn ? "AutoMinorVersionUpgrade" : "auto_minor_version_upgrade"; return isFalse(c.p[k]) ? [c.H("automatic minor upgrades disabled", k, "confirmed")] : []; });

rule("AWS-EFS-001", "medium", "aws", ["aws_efs_file_system", "AWS::EFS::FileSystem"], "EFS file system is not encrypted",
  [[CA, "2.4.1"], [N, "SC-28"]], "Set encrypted = true (Encrypted: true); encryption can only be chosen at creation.",
  needTrue("encrypted", "Encrypted", "encryption"));
rule("AWS-ELC-001", "medium", "aws", ["aws_elasticache_replication_group", "AWS::ElastiCache::ReplicationGroup"], "ElastiCache data at rest is not encrypted",
  [[N, "SC-28"]], "Set at_rest_encryption_enabled = true (AtRestEncryptionEnabled: true).",
  needTrue("at_rest_encryption_enabled", "AtRestEncryptionEnabled", "at-rest encryption"));
rule("AWS-ELC-002", "medium", "aws", ["aws_elasticache_replication_group", "AWS::ElastiCache::ReplicationGroup"], "ElastiCache in-transit encryption is off",
  [[N, "SC-8"], [M, "T1040"]], "Set transit_encryption_enabled = true and require AUTH / RBAC.",
  needTrue("transit_encryption_enabled", "TransitEncryptionEnabled", "in-transit encryption"));
rule("AWS-RS-001", "low", "aws", ["aws_redshift_cluster", "AWS::Redshift::Cluster"], "Redshift cluster encryption is not set",
  [[N, "SC-28"]], "Set encrypted = true with a customer-managed KMS key (newer clusters are encrypted by default; declare it explicitly).",
  needTrue("encrypted", "Encrypted", "encryption"));
rule("AWS-RS-002", "high", "aws", ["aws_redshift_cluster", "AWS::Redshift::Cluster"], "Redshift cluster is publicly accessible",
  [[N, "SC-7"], [M, "T1190"]], "Set publicly_accessible = false.",
  needNotTrue("publicly_accessible", "PubliclyAccessible", "publicly accessible"));
rule("AWS-SNS-001", "low", "aws", ["aws_sns_topic", "AWS::SNS::Topic"], "SNS topic is not encrypted with KMS",
  [[N, "SC-28"]], "Set kms_master_key_id (KmsMasterKeyId), for example alias/aws/sns or a customer-managed key.",
  needSet("kms_master_key_id", "KmsMasterKeyId", "no KMS key is configured"));
rule("AWS-SQS-001", "low", "aws", ["aws_sqs_queue", "AWS::SQS::Queue"], "SQS queue server-side encryption is disabled",
  [[N, "SC-28"]], "Remove sqs_managed_sse_enabled = false or set kms_master_key_id.",
  (c) => {
    const kms = c.cfn ? c.p.KmsMasterKeyId : c.p.kms_master_key_id;
    const sse = c.cfn ? c.p.SqsManagedSseEnabled : c.p.sqs_managed_sse_enabled;
    return !kms && isFalse(sse) ? [c.H("SSE-SQS is explicitly disabled and no KMS key is set", c.cfn ? "SqsManagedSseEnabled" : "sqs_managed_sse_enabled", "confirmed")] : [];
  });
rule("AWS-DDB-001", "info", "aws", ["aws_dynamodb_table", "AWS::DynamoDB::Table"], "DynamoDB table uses an AWS-owned key, not a customer-managed key",
  [[N, "SC-12"]], "Enable server_side_encryption with a customer-managed KMS key where key control or audit is required (tables are always encrypted at rest).",
  needTrue("server_side_encryption.enabled", "SSESpecification.SSEEnabled", "customer-managed SSE"));
rule("AWS-DDB-002", "low", "aws", ["aws_dynamodb_table", "AWS::DynamoDB::Table"], "DynamoDB point-in-time recovery is off",
  [[N, "CP-9"], [M, "T1485"]], "Enable point_in_time_recovery (PointInTimeRecoverySpecification).",
  needTrue("point_in_time_recovery.enabled", "PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled", "point-in-time recovery"));

/* Security groups and NACLs */
/** Ingress / egress rules of SG-like resources -> [{dir, cidrs, from, to, proto, key}] */
function sgRules(r) {
  const p = r.props, out = [];
  const tfR = (x, dir) => out.push({ dir, cidrs: arr(x.cidr_blocks).concat(arr(x.ipv6_cidr_blocks)), from: x.from_port, to: x.to_port, proto: x.protocol, key: "cidr_blocks", dyn: isDyn(x.cidr_blocks) || isDyn(x.from_port) });
  switch (r.type) {
    case "aws_security_group": case "aws_default_security_group":
      for (const x of arr(p.ingress)) if (x && typeof x === "object") tfR(x, "ingress");
      for (const x of arr(p.egress)) if (x && typeof x === "object") tfR(x, "egress");
      break;
    case "aws_security_group_rule": tfR(p, lc(p.type) === "egress" ? "egress" : "ingress"); break;
    case "aws_vpc_security_group_ingress_rule": case "aws_vpc_security_group_egress_rule":
      out.push({ dir: r.type.includes("ingress") ? "ingress" : "egress", cidrs: [p.cidr_ipv4, p.cidr_ipv6].filter((x) => x != null), from: p.from_port, to: p.to_port, proto: p.ip_protocol, key: p.cidr_ipv4 != null ? "cidr_ipv4" : "cidr_ipv6", dyn: isDyn(p.cidr_ipv4) || isDyn(p.cidr_ipv6) });
      break;
    case "AWS::EC2::SecurityGroup":
      for (const x of arr(p.SecurityGroupIngress)) if (x) out.push({ dir: "ingress", cidrs: [x.CidrIp, x.CidrIpv6].filter((v) => v != null), from: x.FromPort, to: x.ToPort, proto: x.IpProtocol, key: x.CidrIp != null ? "CidrIp" : "CidrIpv6", dyn: isDyn(x.CidrIp) || isDyn(x.CidrIpv6) });
      for (const x of arr(p.SecurityGroupEgress)) if (x) out.push({ dir: "egress", cidrs: [x.CidrIp, x.CidrIpv6].filter((v) => v != null), from: x.FromPort, to: x.ToPort, proto: x.IpProtocol, key: x.CidrIp != null ? "CidrIp" : "CidrIpv6", dyn: isDyn(x.CidrIp) });
      break;
    case "AWS::EC2::SecurityGroupIngress": case "AWS::EC2::SecurityGroupEgress":
      out.push({ dir: r.type.endsWith("Ingress") ? "ingress" : "egress", cidrs: [p.CidrIp, p.CidrIpv6].filter((v) => v != null), from: p.FromPort, to: p.ToPort, proto: p.IpProtocol, key: p.CidrIp != null ? "CidrIp" : "CidrIpv6", dyn: isDyn(p.CidrIp) || isDyn(p.CidrIpv6) });
      break;
  }
  return out;
}
const SG_TYPES = ["aws_security_group", "aws_default_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule", "AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress"];
const allProto = (pr) => ["-1", "all", "*"].includes(lc(pr)) || pr === -1;
const portsLabel = (x) => (allProto(x.proto) ? "all ports" : x.from === x.to || x.to == null ? "port " + x.from : "ports " + x.from + "-" + x.to);
const covers = (x, port) => allProto(x.proto) || rangeCovers(x.from, x.to, port);
const isV6Any = (cidr) => lc(cidr).trim() === "::/0";

function sgCheck(pred, label) {
  return (c) => {
    const hits = [];
    for (const x of sgRules(c.r)) {
      if (x.dir !== "ingress") continue;
      if (x.dyn) { hits.push(c.D(x.key)); continue; }
      for (const cidr of x.cidrs) if (anyCidr(cidr) && pred(x, cidr)) hits.push(c.H("ingress from " + cidr + " on " + portsLabel(x) + label, x.key, "confirmed"));
    }
    return hits;
  };
}
rule("AWS-SG-001", "high", "aws", SG_TYPES, "Security group allows SSH or RDP from 0.0.0.0/0",
  [[CA, "5.2"], [N, "SC-7"], [N, "AC-17"], [M, "T1133"], [M, "T1021.004"]],
  "Restrict administrative ports to a VPN or bastion CIDR, or use SSM Session Manager instead of open SSH/RDP.",
  sgCheck((x, cidr) => !isV6Any(cidr) && !allProto(x.proto) && (covers(x, 22) || covers(x, 3389)), ""));
rule("AWS-SG-002", "high", "aws", SG_TYPES, "Security group allows SSH or RDP from ::/0",
  [[CA, "5.3"], [N, "SC-7"], [N, "AC-17"], [M, "T1133"]],
  "Remove the IPv6 any-address rule for administrative ports.",
  sgCheck((x, cidr) => isV6Any(cidr) && !allProto(x.proto) && (covers(x, 22) || covers(x, 3389)), ""));
rule("AWS-SG-003", "critical", "aws", SG_TYPES, "Security group allows all traffic from the internet",
  [[CA, "5.2"], [N, "SC-7"], [M, "T1190"]],
  "Replace the all-ports rule with the specific ports the workload serves.",
  sgCheck((x) => allProto(x.proto) || (num(x.from) === 0 && num(x.to) === 65535), ""));
const DB_PORTS = { 1433: "SQL Server", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 9042: "Cassandra" };
rule("AWS-SG-004", "high", "aws", SG_TYPES, "Security group exposes a database port to the internet",
  [[N, "SC-7"], [M, "T1190"]], "Keep database ports reachable only from application subnets or security groups.",
  sgCheck((x) => !allProto(x.proto) && !(num(x.from) === 0 && num(x.to) === 65535) && Object.keys(DB_PORTS).some((p) => covers(x, Number(p))), " (database port)"));
rule("AWS-SG-005", "low", "aws", SG_TYPES, "Security group allows all egress to the internet",
  [[N, "SC-7"], [M, "T1048"]], "Limit egress to required destinations, or route through a proxy / NAT with egress filtering.",
  (c) => sgRules(c.r).filter((x) => x.dir === "egress" && !x.dyn && allProto(x.proto) && x.cidrs.some(anyCidr)).map((x) => c.H("egress to " + x.cidrs.filter(anyCidr).join(", ") + " on all ports", x.key, "confirmed")));
rule("AWS-SG-006", "low", "aws", ["aws_default_security_group"], "Default security group has rules",
  [[CA, "5.4"], [N, "SC-7"]], "Leave the default security group with no ingress or egress rules and use purpose-built groups.",
  (c) => (sgRules(c.r).length ? [c.H(sgRules(c.r).length + " rule(s) on the default security group", "ingress", "confirmed")] : []));
rule("AWS-NACL-001", "medium", "aws", ["aws_network_acl", "aws_network_acl_rule", "AWS::EC2::NetworkAclEntry"], "Network ACL allows SSH or RDP from 0.0.0.0/0",
  [[CA, "5.1"], [N, "SC-7"], [M, "T1133"]], "Deny 0.0.0.0/0 to ports 22 and 3389 in network ACLs.",
  (c) => {
    const ents = [];
    if (c.r.type === "aws_network_acl") for (const x of arr(c.p.ingress)) ents.push({ cidr: x.cidr_block || x.ipv6_cidr_block, from: x.from_port, to: x.to_port, proto: x.protocol, allow: lc(x.action) === "allow", key: "cidr_block" });
    else if (c.r.type === "aws_network_acl_rule") { if (!isTrue(c.p.egress)) ents.push({ cidr: c.p.cidr_block || c.p.ipv6_cidr_block, from: c.p.from_port, to: c.p.to_port, proto: c.p.protocol, allow: lc(c.p.rule_action) === "allow", key: "cidr_block" }); }
    else if (!isTrue(c.p.Egress)) ents.push({ cidr: c.p.CidrBlock || c.p.Ipv6CidrBlock, from: get(c.p, "PortRange.From"), to: get(c.p, "PortRange.To"), proto: c.p.Protocol, allow: lc(c.p.RuleAction) === "allow", key: "CidrBlock" });
    return ents.filter((e) => e.allow && anyCidr(e.cidr) && (allProto(e.proto) || covers(e, 22) || covers(e, 3389))).map((e) => c.H("allow " + e.cidr + " on " + portsLabel(e), e.key, "confirmed"));
  });

/* IAM */
const POLICY_ALL = Object.keys(POLICY_TYPES).filter((t) => IDENTITY_POLICY.has(t));
function stmtCheck(pred, describe, types = IDENTITY_POLICY) {
  return (c) => {
    if (!types.has(c.r.type)) return [];
    const hits = [];
    for (const pol of policiesOf(c.r)) {
      if (!pol.stmts) { if (pol.dyn) hits.push(c.D(pol.key)); continue; }
      for (const st of pol.stmts) if (lc(st.effect) === "allow" && pred(st)) hits.push(c.H(describe(st), pol.key, "confirmed"));
    }
    return hits;
  };
}
const hasStarRes = (st) => st.resources.includes("*");
rule("AWS-IAM-001", "critical", "aws", POLICY_ALL, "IAM policy grants full administrative access (\"*\" on \"*\")",
  [[CA, "1.16"], [N, "AC-6"], [M, "T1078.004"]],
  "Replace Action \"*\" / Resource \"*\" with the specific actions and resource ARNs the principal needs.",
  stmtCheck((st) => st.actions.includes("*") && hasStarRes(st), () => "Allow Action \"*\" on Resource \"*\""));
rule("AWS-IAM-002", "medium", "aws", POLICY_ALL, "IAM policy grants a service-wide wildcard on all resources",
  [[N, "AC-6"], [M, "T1078.004"]], "Scope service:* actions to the specific API calls and resources required.",
  stmtCheck((st) => hasStarRes(st) && !st.actions.includes("*") && st.actions.some((a) => /^[a-z0-9-]+:\*$/i.test(a) && !/^iam:/i.test(a)), (st) => "Allow " + st.actions.filter((a) => /:\*$/.test(a)).join(", ") + " on Resource \"*\""));
rule("AWS-IAM-003", "high", "aws", POLICY_ALL, "IAM policy allows iam:PassRole or iam:* on any resource",
  [[N, "AC-6"], [M, "T1098"]], "Restrict iam:PassRole to the specific role ARNs and add an iam:PassedToService condition.",
  stmtCheck((st) => hasStarRes(st) && st.actions.some((a) => /^iam:(passrole|\*)$/i.test(a) || /^iam:pass\*$/i.test(a)), (st) => "Allow " + st.actions.filter((a) => /^iam:/i.test(a)).join(", ") + " on Resource \"*\""));
rule("AWS-IAM-004", "medium", "aws", ["aws_iam_user_policy", "aws_iam_user_policy_attachment", "aws_iam_policy_attachment", "AWS::IAM::User"], "IAM permissions attached directly to a user",
  [[CA, "1.15"], [N, "AC-2"], [N, "AC-6"]], "Attach policies to groups or roles and add users to groups.",
  (c) => {
    if (c.r.type === "AWS::IAM::User") return arr(c.p.Policies).length || arr(c.p.ManagedPolicyArns).length ? [c.H("user carries " + (arr(c.p.Policies).length + arr(c.p.ManagedPolicyArns).length) + " direct policy(ies)", arr(c.p.Policies).length ? "Policies" : "ManagedPolicyArns", "confirmed")] : [];
    if (c.r.type === "aws_iam_policy_attachment") return arr(c.p.users).length ? [c.H("policy attached to users", "users", "confirmed")] : [];
    return [c.H(c.r.type === "aws_iam_user_policy" ? "inline policy on a user" : "managed policy attached to a user", c.r.type === "aws_iam_user_policy" ? "policy" : "user", "confirmed")];
  });
rule("AWS-IAM-005", "medium", "aws", ["aws_iam_account_password_policy"], "IAM password policy minimum length is below 14",
  [[CA, "1.8"], [N, "IA-5"]], "Set minimum_password_length to 14 or more.",
  (c) => { const v = c.p.minimum_password_length; if (v == null) return [c.H("minimum_password_length not set (AWS default is 8)", null, "likely")]; if (isDyn(v)) return [c.D("minimum_password_length")]; return num(v) < 14 ? [c.H("minimum length is " + v, "minimum_password_length", "confirmed")] : []; });
rule("AWS-IAM-006", "low", "aws", ["aws_iam_account_password_policy"], "IAM password policy does not prevent password reuse",
  [[CA, "1.9"], [N, "IA-5"]], "Set password_reuse_prevention to 24.",
  (c) => { const v = c.p.password_reuse_prevention; if (v == null) return [c.H("password_reuse_prevention not set", null, "likely")]; if (isDyn(v)) return [c.D("password_reuse_prevention")]; return num(v) < 24 ? [c.H("reuse prevention is " + v, "password_reuse_prevention", "confirmed")] : []; });
rule("AWS-IAM-007", "info", "aws", ["aws_iam_user_login_profile"], "Console users defined but no account password policy in the scanned files",
  [[CA, "1.8"], [N, "IA-5"]], "Manage aws_iam_account_password_policy alongside console users, or confirm it is set elsewhere.",
  (c) => (c.all.some((o) => o.type === "aws_iam_account_password_policy") ? [] : [c.H("no aws_iam_account_password_policy in the scanned files", null, "review")]));
rule("AWS-IAM-008", "critical", "aws", ["aws_iam_role", "AWS::IAM::Role"], "IAM role trust policy lets any principal assume it",
  [[N, "AC-3"], [N, "AC-6"], [M, "T1078.004"]], "Name the trusted accounts, services or OIDC providers explicitly and add sts:ExternalId or aws:PrincipalOrgID conditions.",
  (c) => {
    const k = c.cfn ? "AssumeRolePolicyDocument" : "assume_role_policy";
    const v = c.p[k];
    if (v == null) return [];
    const sts = policyStatements(v);
    if (!sts) return isDyn(v) || (v && v.raw) ? [c.D(k)] : [];
    return sts.filter((s) => lc(s.effect) === "allow" && principalIsPublic(s.principal)).map((s) => c.H("trust policy allows Principal \"*\"" + (s.condition ? " (has a Condition; review it)" : " with no Condition"), k, s.condition ? "review" : "confirmed"));
  });
rule("AWS-IAM-009", "medium", "aws", ["aws_iam_access_key", "AWS::IAM::AccessKey"], "Long-lived IAM user access key created in IaC",
  [[N, "IA-5"], [M, "T1078.004"], [M, "T1552.001"]], "Prefer roles, IAM Identity Center or OIDC federation; if a key is unavoidable keep its secret out of state (pgp_key) and rotate it.",
  (c) => [c.H("access key resource for " + (c.p.user ? (typeof c.p.user === "string" ? c.p.user : "a user") : c.p.UserName ? "a user" : "a user") + (c.r.format === "tfstate" && c.p.secret ? "; the secret is stored in state" : ""), c.cfn ? "UserName" : "user", "confirmed")]);
rule("AWS-IAM-010", "high", "aws", ["aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment", "aws_iam_policy_attachment", "AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"], "AdministratorAccess managed policy attached",
  [[CA, "1.16"], [N, "AC-6"], [M, "T1078.004"]], "Grant job-specific permissions instead of AdministratorAccess; keep break-glass admin roles behind MFA and monitoring.",
  (c) => {
    const arns = c.cfn ? arr(c.p.ManagedPolicyArns) : [c.p.policy_arn];
    return arns.filter((a) => typeof a === "string" && /:policy\/AdministratorAccess$/.test(a)).map((a) => c.H(a, c.cfn ? "ManagedPolicyArns" : "policy_arn", "confirmed"));
  });

/* IAM privilege-escalation paths: every action in a set must be allowed by the same policy document. */
export const IAM_PRIVESC = [
  { name: "CreatePolicyVersion", sev: "critical", actions: ["iam:CreatePolicyVersion"], why: "can publish a new default version of a managed policy with any permissions, including on a policy attached to itself" },
  { name: "SetDefaultPolicyVersion", sev: "critical", actions: ["iam:SetDefaultPolicyVersion"], why: "can switch a managed policy to an older, more permissive version" },
  { name: "AttachUserPolicy", sev: "critical", actions: ["iam:AttachUserPolicy"], why: "can attach AdministratorAccess to its own user" },
  { name: "AttachGroupPolicy", sev: "critical", actions: ["iam:AttachGroupPolicy"], why: "can attach AdministratorAccess to a group it belongs to" },
  { name: "AttachRolePolicy", sev: "critical", actions: ["iam:AttachRolePolicy"], why: "can attach AdministratorAccess to a role it can assume" },
  { name: "PutUserPolicy", sev: "critical", actions: ["iam:PutUserPolicy"], why: "can write an inline admin policy on its own user" },
  { name: "PutGroupPolicy", sev: "critical", actions: ["iam:PutGroupPolicy"], why: "can write an inline admin policy on a group it belongs to" },
  { name: "PutRolePolicy", sev: "critical", actions: ["iam:PutRolePolicy"], why: "can write an inline admin policy on a role it can assume" },
  { name: "PassRole to Lambda", sev: "critical", actions: ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], why: "can create and invoke a Lambda function that runs as a more privileged role" },
  { name: "PassRole to EC2", sev: "critical", actions: ["iam:PassRole", "ec2:RunInstances"], why: "can launch an instance with a privileged instance profile and read its credentials" },
  { name: "PassRole to CloudFormation", sev: "critical", actions: ["iam:PassRole", "cloudformation:CreateStack"], why: "can create a stack that provisions resources as a more privileged role" },
  { name: "CreateAccessKey", sev: "high", actions: ["iam:CreateAccessKey"], why: "can mint access keys for another, more privileged user" },
  { name: "CreateLoginProfile", sev: "high", actions: ["iam:CreateLoginProfile"], why: "can set a console password on a privileged user that has none" },
  { name: "UpdateLoginProfile", sev: "high", actions: ["iam:UpdateLoginProfile"], why: "can change the console password of a more privileged user" },
  { name: "AddUserToGroup", sev: "high", actions: ["iam:AddUserToGroup"], why: "can add itself to an administrators group" },
  { name: "UpdateAssumeRolePolicy", sev: "high", actions: ["iam:UpdateAssumeRolePolicy"], why: "can rewrite a role's trust policy so it can assume that role" },
  { name: "PassRole to Glue", sev: "high", actions: ["iam:PassRole", "glue:CreateDevEndpoint"], why: "can create a Glue dev endpoint with a privileged role and use its credentials over SSH" },
  { name: "PassRole to Data Pipeline", sev: "high", actions: ["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "datapipeline:ActivatePipeline"], why: "can run arbitrary commands in a pipeline that executes as a privileged role" },
  { name: "UpdateFunctionCode", sev: "high", actions: ["lambda:UpdateFunctionCode"], why: "can replace an existing function's code and act with that function's role" },
  { name: "PassRole to SageMaker", sev: "high", actions: ["iam:PassRole", "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"], why: "can open a notebook that runs as a privileged role" },
  { name: "SSM StartSession", sev: "high", actions: ["ssm:StartSession"], why: "can open a shell on instances and use their instance-profile credentials" },
  { name: "PassRole to CodeBuild", sev: "high", actions: ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"], why: "can run a build that executes as a privileged role" },
  { name: "PassRole to CodeStar", sev: "medium", actions: ["iam:PassRole", "codestar:CreateProject"], why: "can create a CodeStar project whose service role grants further permissions" },
];
const actionRe = (pat) => new RegExp("^" + String(pat).split("").map((ch) => (ch === "*" ? ".*" : ch === "?" ? "." : reEsc(ch))).join("") + "$", "i");
/** Escalation paths fully allowed by one policy document's statements: [{ path, scoped }]. */
export function privescPaths(stmts) {
  const allow = (stmts || []).filter((st) => lc(st.effect) === "allow");
  if (allow.some((st) => st.actions.includes("*") && st.resources.includes("*"))) return []; // full admin: AWS-IAM-001
  const deny = (stmts || []).filter((st) => lc(st.effect) === "deny" && !st.condition && st.resources.includes("*"));
  const grant = (a) => {
    if (deny.some((st) => st.actions.some((p) => actionRe(p).test(a)))) return null;
    const by = allow.filter((st) => st.actions.some((p) => p !== "<dynamic>" && actionRe(p).test(a)));
    return !by.length ? null : by.some((st) => st.resources.includes("*") && !st.condition) ? "any" : "scoped";
  };
  const out = [];
  for (const path of IAM_PRIVESC) { const g = path.actions.map(grant); if (g.every(Boolean)) out.push({ path, scoped: g.includes("scoped") }); }
  return out;
}
function privescCheck(sev) {
  return (c) => {
    if (!IDENTITY_POLICY.has(c.r.type)) return [];
    const hits = [];
    for (const pol of policiesOf(c.r)) {
      if (!pol.stmts) { if (pol.dyn) hits.push(c.D(pol.key)); continue; }
      for (const { path, scoped } of privescPaths(pol.stmts)) if (path.sev === sev) hits.push(c.H(path.name + " (" + path.actions.join(" + ") + "): " + path.why + (scoped ? "; the grant is limited by resource or condition, check whether it reaches privileged targets" : ""), pol.key, scoped ? "review" : "confirmed"));
    }
    return hits;
  };
}
rule("AWS-IAM-011", "critical", "aws", POLICY_ALL, "IAM policy allows privilege escalation by rewriting policies or passing a role to compute",
  [[N, "AC-6"], [M, "T1098"], [M, "T1078.004"]], "Remove the listed actions or scope them to specific ARNs, add a permissions boundary, and block self-escalation with an SCP.",
  privescCheck("critical"));
rule("AWS-IAM-012", "high", "aws", POLICY_ALL, "IAM policy allows privilege escalation through another identity or service",
  [[N, "AC-6"], [M, "T1098"], [M, "T1078.004"]], "Restrict the listed actions to specific resources (or to the caller's own user via ${aws:username}) and limit iam:PassRole with iam:PassedToService.",
  privescCheck("high"));
rule("AWS-IAM-013", "medium", "aws", POLICY_ALL, "IAM policy allows an indirect privilege-escalation path",
  [[N, "AC-6"], [M, "T1098"]], "Limit iam:PassRole to the specific service roles the workflow needs.",
  privescCheck("medium"));

/* CloudTrail */
const CT = ["aws_cloudtrail", "AWS::CloudTrail::Trail"];
rule("AWS-CT-001", "medium", "aws", CT, "CloudTrail trail is not multi-region",
  [[CA, "3.1"], [N, "AU-2"], [N, "AU-12"], [M, "T1562.008"]], "Set is_multi_region_trail = true (IsMultiRegionTrail: true).",
  needTrue("is_multi_region_trail", "IsMultiRegionTrail", "multi-region"));
rule("AWS-CT-002", "medium", "aws", CT, "CloudTrail log file validation is disabled",
  [[CA, "3.2"], [N, "AU-9"]], "Set enable_log_file_validation = true (EnableLogFileValidation: true).",
  needTrue("enable_log_file_validation", "EnableLogFileValidation", "log file validation"));
rule("AWS-CT-003", "medium", "aws", CT, "CloudTrail logs are not encrypted with a KMS key",
  [[CA, "3.5"], [N, "AU-9"], [N, "SC-28"]], "Set kms_key_id (KMSKeyId) to a customer-managed KMS key.",
  needSet("kms_key_id", "KMSKeyId", "no KMS key is configured"));
rule("AWS-CT-004", "high", "aws", CT, "CloudTrail logging is turned off",
  [[N, "AU-12"], [M, "T1562.008"]], "Set enable_logging = true (IsLogging: true).",
  (c) => { const k = c.cfn ? "IsLogging" : "enable_logging"; return isFalse(c.p[k]) ? [c.H("logging is disabled", k, "confirmed")] : []; });
rule("AWS-CT-005", "low", "aws", CT, "CloudTrail is not sent to CloudWatch Logs",
  [[CA, "section 3 (Logging)"], [N, "AU-6"]], "Set cloud_watch_logs_group_arn and cloud_watch_logs_role_arn so metric filters and alarms can run.",
  needSet("cloud_watch_logs_group_arn", "CloudWatchLogsLogGroupArn", "no CloudWatch Logs group configured"));

/* KMS */
rule("AWS-KMS-001", "medium", "aws", ["aws_kms_key", "AWS::KMS::Key"], "KMS key rotation is disabled",
  [[CA, "3.6"], [N, "SC-12"]], "Set enable_key_rotation = true (EnableKeyRotation: true) for symmetric keys.",
  (c) => {
    const spec = c.cfn ? c.p.KeySpec : c.p.customer_master_key_spec || c.p.key_spec;
    if (spec && !isDyn(spec) && lc(spec) !== "symmetric_default") return [];
    return needTrue("enable_key_rotation", "EnableKeyRotation", "key rotation")(c);
  });
rule("AWS-KMS-002", "critical", "aws", ["aws_kms_key", "AWS::KMS::Key"], "KMS key policy allows any principal",
  [[N, "AC-3"], [N, "SC-12"]], "Limit the key policy to the account root and named roles; add kms:CallerAccount or aws:PrincipalOrgID conditions.",
  publicPolicyCheck(["kms"]));

/* Lambda */
rule("AWS-LMB-001", "high", "aws", ["aws_lambda_permission", "AWS::Lambda::Permission"], "Lambda resource policy allows any principal",
  [[N, "AC-3"], [M, "T1190"]], "Set principal to the specific service or account and add source_arn / source_account.",
  (c) => {
    const k = c.cfn ? "Principal" : "principal";
    const v = c.p[k];
    if (isDyn(v)) return [c.D(k)];
    const scoped = c.cfn ? c.p.SourceArn || c.p.SourceAccount || c.p.PrincipalOrgID : c.p.source_arn || c.p.source_account || c.p.principal_org_id;
    return v === "*" ? [c.H("principal is \"*\"" + (scoped ? " (scoped by source ARN/account)" : ""), k, scoped ? "review" : "confirmed")] : [];
  });
rule("AWS-LMB-002", "medium", "aws", ["aws_lambda_function_url", "AWS::Lambda::Url"], "Lambda function URL requires no authentication",
  [[N, "AC-3"], [N, "IA-2"], [M, "T1190"]], "Use authorization_type = \"AWS_IAM\" unless the function is meant to be public and validates callers itself.",
  (c) => { const k = c.cfn ? "AuthType" : "authorization_type"; return lc(c.p[k]) === "none" ? [c.H("auth type NONE", k, "confirmed")] : []; });
rule("AWS-LMB-003", "high", "aws", ["aws_lambda_function", "AWS::Lambda::Function"], "Lambda environment variables contain secrets",
  [[N, "IA-5"], [N, "SC-28"], [M, "T1552.001"]], "Move secrets to Secrets Manager or SSM Parameter Store (SecureString) and read them at runtime.",
  (c) => {
    const vars = c.cfn ? get(c.p, "Environment.Variables") : get(c.p, "environment.variables");
    if (!vars || typeof vars !== "object" || isDyn(vars)) return [];
    return secretEnvHits(c, Object.entries(vars).sort((a, b) => cmp(a[0], b[0])));
  });
const DEPRECATED_RUNTIMES = new Set(["python2.7", "python3.6", "python3.7", "python3.8", "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x", "ruby2.5", "ruby2.7", "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1", "dotnet5.0", "dotnet6", "go1.x", "java8"]);
rule("AWS-LMB-004", "medium", "aws", ["aws_lambda_function", "AWS::Lambda::Function"], "Lambda uses a deprecated runtime",
  [[N, "SI-2"], [N, "SA-22"]], "Move to a supported runtime; deprecated runtimes no longer receive security patches.",
  (c) => { const k = c.cfn ? "Runtime" : "runtime"; const v = c.p[k]; return typeof v === "string" && DEPRECATED_RUNTIMES.has(lc(v)) ? [c.H("runtime " + v, k, "confirmed")] : []; });

/* Load balancers and CloudFront */
const LISTENERS = ["aws_lb_listener", "aws_alb_listener", "AWS::ElasticLoadBalancingV2::Listener"];
rule("AWS-ELB-001", "medium", "aws", LISTENERS, "Load balancer listener serves HTTP without redirecting to HTTPS",
  [[N, "SC-8"], [M, "T1557"]], "Make the HTTP listener's default action a redirect to HTTPS (status HTTP_301).",
  (c) => {
    const proto = c.cfn ? c.p.Protocol : c.p.protocol;
    if (lc(proto) !== "http") return [];
    const acts = c.cfn ? arr(c.p.DefaultActions).map((a) => a && a.Type) : arr(c.p.default_action).map((a) => a && a.type);
    return acts.some((t) => lc(t) === "redirect") ? [] : [c.H("HTTP listener default action is " + (acts.join(", ") || "unset"), c.cfn ? "Protocol" : "protocol", "confirmed")];
  });
const WEAK_TLS_POLICY = (s) => /TLS-1-0|TLS-1-1|TLS13-1-0|TLS13-1-1|FS-1-1|^ELBSecurityPolicy-2016-08$|^ELBSecurityPolicy-2015-05$|^ELBSecurityPolicy-FS-2018-06$/.test(String(s));
rule("AWS-ELB-002", "medium", "aws", LISTENERS, "Load balancer TLS policy allows TLS versions below 1.2",
  [[N, "SC-8"], [N, "SC-13"]], "Use ELBSecurityPolicy-TLS13-1-2-2021-06 (or newer) as ssl_policy.",
  (c) => {
    const k = c.cfn ? "SslPolicy" : "ssl_policy";
    const proto = lc(c.cfn ? c.p.Protocol : c.p.protocol);
    const v = c.p[k];
    if (proto !== "https" && proto !== "tls") return [];
    if (v == null) return [c.H("no ssl_policy set; the default ELBSecurityPolicy-2016-08 allows TLS 1.0", k, "likely")];
    return WEAK_TLS_POLICY(v) ? [c.H("policy " + v, k, "confirmed")] : [];
  });
rule("AWS-ELB-003", "low", "aws", ["aws_lb", "aws_alb", "AWS::ElasticLoadBalancingV2::LoadBalancer"], "Load balancer access logging is disabled",
  [[N, "AU-2"], [N, "AU-12"]], "Enable access_logs with an S3 bucket.",
  (c) => {
    if (c.cfn) { const a = arr(c.p.LoadBalancerAttributes).find((x) => x && x.Key === "access_logs.s3.enabled"); return a && lc(a.Value) === "true" ? [] : [c.H("access_logs.s3.enabled is not true", "LoadBalancerAttributes", "likely")]; }
    if (lc(c.p.load_balancer_type) === "gateway") return [];
    return isTrue(get(c.p, "access_logs.enabled")) || (get(c.p, "access_logs.bucket") && get(c.p, "access_logs.enabled") == null) ? [] : [c.H("access logs not enabled", "access_logs", "likely")];
  });
rule("AWS-CF-001", "medium", "aws", ["aws_cloudfront_distribution", "AWS::CloudFront::Distribution"], "CloudFront allows plain HTTP to viewers",
  [[N, "SC-8"]], "Set viewer_protocol_policy to redirect-to-https or https-only on every cache behavior.",
  (c) => {
    const pols = c.cfn ? [get(c.p, "DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy"), ...arr(get(c.p, "DistributionConfig.CacheBehaviors")).map((b) => b && b.ViewerProtocolPolicy)]
      : [get(c.p, "default_cache_behavior.viewer_protocol_policy"), ...arr(c.p.ordered_cache_behavior).map((b) => b && b.viewer_protocol_policy)];
    return pols.filter((v) => lc(v) === "allow-all").map(() => c.H("viewer protocol policy allow-all", c.cfn ? "ViewerProtocolPolicy" : "viewer_protocol_policy", "confirmed"));
  });
rule("AWS-CF-002", "medium", "aws", ["aws_cloudfront_distribution", "AWS::CloudFront::Distribution"], "CloudFront minimum TLS version is below 1.2",
  [[N, "SC-8"], [N, "SC-13"]], "Use a custom certificate with minimum_protocol_version TLSv1.2_2021.",
  (c) => {
    const k = c.cfn ? "MinimumProtocolVersion" : "minimum_protocol_version";
    const v = c.cfn ? get(c.p, "DistributionConfig.ViewerCertificate.MinimumProtocolVersion") : get(c.p, "viewer_certificate.minimum_protocol_version");
    return typeof v === "string" && /^(SSLv3|TLSv1|TLSv1_2016|TLSv1\.1_2016)$/.test(v) ? [c.H("minimum protocol " + v, k, "confirmed")] : [];
  });

/* EKS */
rule("AWS-EKS-001", "medium", "aws", ["aws_eks_cluster", "AWS::EKS::Cluster"], "EKS API endpoint is public to the internet",
  [[N, "SC-7"], [N, "AC-17"], [M, "T1133"]], "Set endpoint_public_access = false, or restrict public_access_cidrs to known ranges.",
  (c) => {
    const pub = c.cfn ? get(c.p, "ResourcesVpcConfig.EndpointPublicAccess") : get(c.p, "vpc_config.endpoint_public_access");
    const cidrs = c.cfn ? get(c.p, "ResourcesVpcConfig.PublicAccessCidrs") : get(c.p, "vpc_config.public_access_cidrs");
    if (isFalse(pub)) return [];
    if (isDyn(pub) || isDyn(cidrs)) return [c.D("endpoint_public_access")];
    if (cidrs && arr(cidrs).length && !arr(cidrs).some(anyCidr)) return [];
    return [c.H("public endpoint " + (pub == null ? "enabled by default" : "enabled") + " for " + (cidrs ? arr(cidrs).join(", ") : "0.0.0.0/0 (default)"), c.cfn ? "EndpointPublicAccess" : "endpoint_public_access", pub == null ? "likely" : "confirmed")];
  });
rule("AWS-EKS-002", "medium", "aws", ["aws_eks_cluster", "AWS::EKS::Cluster"], "EKS control plane audit logging is not enabled",
  [[N, "AU-2"], [N, "AU-12"], [M, "T1562.008"]], "Enable at least the audit and authenticator control plane log types.",
  (c) => {
    const types = c.cfn ? arr(get(c.p, "Logging.ClusterLogging.EnabledTypes")).map((x) => (x && x.Type) || x) : c.p.enabled_cluster_log_types;
    if (isDyn(types)) return [c.D("enabled_cluster_log_types")];
    const t = arr(types).map(lc);
    return t.includes("audit") ? [] : [c.H(t.length ? "enabled log types: " + t.join(", ") + " (no audit)" : "no control plane log types enabled", c.cfn ? "Logging" : "enabled_cluster_log_types", t.length ? "confirmed" : "likely")];
  });
rule("AWS-EKS-003", "low", "aws", ["aws_eks_cluster", "AWS::EKS::Cluster"], "EKS secrets are not envelope-encrypted with KMS",
  [[N, "SC-28"], [N, "SC-12"]], "Add encryption_config with resources = [\"secrets\"] and a KMS key.",
  needSet("encryption_config", "EncryptionConfig", "no encryption_config for secrets"));

/* EC2 */
rule("AWS-EC2-001", "medium", "aws", ["aws_instance", "aws_launch_template", "aws_launch_configuration", "AWS::EC2::LaunchTemplate"], "EC2 instance metadata allows IMDSv1",
  [[CA, "5.6"], [N, "SC-7"], [M, "T1552.005"]], "Set metadata_options { http_tokens = \"required\" } (HttpTokens: required).",
  (c) => {
    const v = c.cfn ? get(c.p, "LaunchTemplateData.MetadataOptions.HttpTokens") : get(c.p, "metadata_options.http_tokens");
    const ep = c.cfn ? get(c.p, "LaunchTemplateData.MetadataOptions.HttpEndpoint") : get(c.p, "metadata_options.http_endpoint");
    if (lc(ep) === "disabled") return [];
    if (v == null) return [c.H("http_tokens not set; IMDSv1 stays available unless the AMI or account default requires IMDSv2", "metadata_options", "likely")];
    if (isDyn(v)) return [c.D("http_tokens")];
    return lc(v) === "required" ? [] : [c.H("http_tokens = " + v, c.cfn ? "HttpTokens" : "http_tokens", "confirmed")];
  });
rule("AWS-EC2-002", "low", "aws", ["aws_instance", "aws_launch_template", "aws_launch_configuration", "AWS::EC2::Instance"], "EC2 instance gets a public IP address",
  [[N, "SC-7"], [M, "T1190"]], "Place instances in private subnets behind a load balancer or NAT; set associate_public_ip_address = false.",
  (c) => {
    if (c.cfn) return arr(c.p.NetworkInterfaces).filter((n) => n && isTrue(n.AssociatePublicIpAddress)).map(() => c.H("AssociatePublicIpAddress true", "AssociatePublicIpAddress", "confirmed"));
    const v = c.r.type === "aws_launch_template" ? arr(c.p.network_interfaces).map((n) => n && n.associate_public_ip_address) : [c.p.associate_public_ip_address];
    return v.filter(isTrue).map(() => c.H("associate_public_ip_address = true", "associate_public_ip_address", "confirmed"));
  });
rule("AWS-EC2-003", "medium", "aws", ["aws_instance", "aws_launch_template", "AWS::EC2::Instance"], "EC2 root or block device volume is not encrypted",
  [[CA, "2.2.1"], [N, "SC-28"]], "Set encrypted = true on root_block_device / ebs_block_device, or enable EBS encryption by default.",
  (c) => {
    if (c.all.some((o) => o.type === "aws_ebs_encryption_by_default" && isTrue(o.props.enabled))) return [];
    if (c.cfn) return arr(c.p.BlockDeviceMappings).filter((b) => b && b.Ebs && !isTrue(b.Ebs.Encrypted) && !isDyn(b.Ebs.Encrypted)).map((b) => c.H("device " + (b.DeviceName || "?") + " not encrypted", "Encrypted", "likely"));
    if (c.r.type === "aws_launch_template") return arr(c.p.block_device_mappings).filter((b) => b && b.ebs && !isTrue(get(b, "ebs.encrypted"))).map((b) => c.H("device " + (b.device_name || "?") + " not encrypted", "encrypted", "likely"));
    const root = arr(c.p.root_block_device)[0];
    const hits = [];
    if (!root || !isTrue(root.encrypted)) { if (root && isDyn(root.encrypted)) hits.push(c.D("encrypted")); else hits.push(c.H(root ? "root_block_device.encrypted is " + JSON.stringify(root.encrypted ?? "unset") : "root_block_device not declared (unencrypted unless account default encryption is on)", root ? "encrypted" : null, root && isFalse(root.encrypted) ? "confirmed" : "likely")); }
    for (const b of arr(c.p.ebs_block_device)) if (b && !isTrue(b.encrypted) && !isDyn(b.encrypted)) hits.push(c.H("ebs_block_device " + (b.device_name || "?") + " not encrypted", "ebs_block_device", "likely"));
    return hits;
  });
rule("AWS-EC2-004", "low", "aws", ["aws_subnet", "AWS::EC2::Subnet"], "Subnet assigns public IPs on launch",
  [[N, "SC-7"]], "Set map_public_ip_on_launch = false and assign public addresses only where needed.",
  needNotTrue("map_public_ip_on_launch", "MapPublicIpOnLaunch", "map public IP on launch"));
rule("AWS-VPC-001", "low", "aws", ["aws_vpc", "AWS::EC2::VPC"], "VPC has no flow log in the scanned files",
  [[CA, "3.7"], [N, "AU-12"], [N, "SI-4"]], "Add aws_flow_log (AWS::EC2::FlowLog) for the VPC with traffic_type ALL or REJECT.",
  (c) => {
    if (c.cfn) return c.all.some((o) => o.type === "AWS::EC2::FlowLog" && refersTo(o.props.ResourceId, c.r)) ? [] : [c.H("no AWS::EC2::FlowLog references this VPC", null, "review")];
    const rel = related(c, ["aws_flow_log"], "vpc_id");
    if (rel.list.length) return [];
    if (rel.unknown) return [c.D("vpc_id")];
    return [c.H("no aws_flow_log references this VPC", null, "review")];
  });

/* ECR */
rule("AWS-ECR-001", "low", "aws", ["aws_ecr_repository", "AWS::ECR::Repository"], "ECR image tags are mutable",
  [[N, "CM-14"], [N, "SI-7"], [M, "T1525"]], "Set image_tag_mutability = \"IMMUTABLE\" so a tag cannot be repointed to a different image.",
  (c) => { const k = c.cfn ? "ImageTagMutability" : "image_tag_mutability"; const v = c.p[k]; if (isDyn(v)) return [c.D(k)]; return lc(v).startsWith("immutable") ? [] : [c.H("tag mutability is " + (v || "MUTABLE (default)"), k, v ? "confirmed" : "likely")]; });
rule("AWS-ECR-002", "low", "aws", ["aws_ecr_repository", "AWS::ECR::Repository"], "ECR scan on push is disabled",
  [[N, "RA-5"], [N, "SI-3"]], "Enable image_scanning_configuration { scan_on_push = true } or registry-level enhanced scanning.",
  (c) => (c.all.some((o) => o.type === "aws_ecr_registry_scanning_configuration") ? [] : needTrue("image_scanning_configuration.scan_on_push", "ImageScanningConfiguration.ScanOnPush", "scan on push")(c)));
rule("AWS-ECR-003", "high", "aws", ["aws_ecr_repository_policy", "AWS::ECR::Repository"], "ECR repository policy allows any principal",
  [[N, "AC-3"], [M, "T1525"]], "Restrict the repository policy to specific accounts or roles.",
  publicPolicyCheck(["ecr"]));
rule("AWS-SQS-002", "high", "aws", ["aws_sqs_queue_policy", "aws_sqs_queue", "AWS::SQS::QueuePolicy"], "SQS queue policy allows any principal",
  [[N, "AC-3"]], "Name the producers and consumers in the Principal, or add aws:SourceArn / aws:SourceAccount conditions.",
  publicPolicyCheck(["sqs"]));
rule("AWS-SNS-002", "high", "aws", ["aws_sns_topic_policy", "aws_sns_topic", "AWS::SNS::TopicPolicy"], "SNS topic policy allows any principal",
  [[N, "AC-3"]], "Name the publishers in the Principal, or add aws:SourceArn / aws:SourceAccount conditions.",
  publicPolicyCheck(["sns"]));
rule("AWS-POL-001", "medium", "aws", ["aws_iam_policy_document"], "Policy document grants access to Principal \"*\"",
  [[N, "AC-3"]], "Check where this policy document is used; scope the principal or add restricting conditions.",
  publicPolicyCheck(["doc"]));

/* Other data stores */
const OS = ["aws_elasticsearch_domain", "aws_opensearch_domain", "AWS::OpenSearchService::Domain", "AWS::Elasticsearch::Domain"];
rule("AWS-OS-001", "medium", "aws", OS, "OpenSearch domain is not encrypted at rest",
  [[N, "SC-28"]], "Enable encrypt_at_rest (EncryptionAtRestOptions.Enabled).",
  needTrue("encrypt_at_rest.enabled", "EncryptionAtRestOptions.Enabled", "encryption at rest"));
rule("AWS-OS-002", "medium", "aws", OS, "OpenSearch node-to-node encryption is off",
  [[N, "SC-8"]], "Enable node_to_node_encryption (NodeToNodeEncryptionOptions.Enabled).",
  needTrue("node_to_node_encryption.enabled", "NodeToNodeEncryptionOptions.Enabled", "node-to-node encryption"));
rule("AWS-SM-001", "high", "aws", ["aws_secretsmanager_secret_version", "aws_ssm_parameter", "AWS::SecretsManager::Secret"], "Secret value is written literally in IaC",
  [[N, "IA-5"], [N, "SC-28"], [M, "T1552.001"]], "Generate the secret (random_password, GenerateSecretString) or load it outside Terraform; never commit the value. Literal values also land in state.",
  (c) => {
    if (c.r.type === "aws_ssm_parameter" && lc(c.p.type) !== "securestring") return [];
    const k = c.cfn ? "SecretString" : c.r.type === "aws_ssm_parameter" ? (c.p.value != null ? "value" : "insecure_value") : "secret_string";
    const v = c.p[k];
    return isLiteralSecret(v) && !isDyn(v) ? [c.H("literal value " + mask(v), k, "confirmed")] : [];
  });

/* ---------------------------- Azure -------------------------------------- */

const isArm = (c) => c.r.format === "arm";
const AZ = (tf, arm) => (c) => (isArm(c) ? arm : tf);
const azv = (c, tf, arm) => pick(c.p, isArm(c) ? arm : tf);

/** NSG inbound rules -> [{name, access, src[], ports[], proto, key}] */
function nsgRules(r) {
  const out = [];
  const tf = (x) => out.push({ name: x.name, dir: lc(x.direction), access: lc(x.access), src: arr(x.source_address_prefix).concat(arr(x.source_address_prefixes)), ports: arr(x.destination_port_range).concat(arr(x.destination_port_ranges)), proto: x.protocol, key: "source_address_prefix" });
  const arm = (name, x) => x && out.push({ name, dir: lc(x.direction), access: lc(x.access), src: arr(x.sourceAddressPrefix).concat(arr(x.sourceAddressPrefixes)), ports: arr(x.destinationPortRange).concat(arr(x.destinationPortRanges)), proto: x.protocol, key: "sourceAddressPrefix" });
  if (r.type === "azurerm_network_security_rule") tf(r.props);
  else if (r.type === "azurerm_network_security_group") for (const x of arr(r.props.security_rule)) x && tf(x);
  else if (/^Microsoft\.Network\/networkSecurityGroups$/i.test(r.type)) for (const x of arr(r.props.securityRules)) arm(x && x.name, x && x.properties);
  else if (/^Microsoft\.Network\/networkSecurityGroups\/securityRules$/i.test(r.type)) arm(r.name, r.props);
  return out;
}
const NSG = (r) => ["azurerm_network_security_rule", "azurerm_network_security_group"].includes(r.type) || /^Microsoft\.Network\/networkSecurityGroups(\/securityRules)?$/i.test(r.type);
const azAny = (s) => anyCidr(s) || ["internet", "*"].includes(lc(s));
const portHit = (ports, p) => ports.some((x) => rangeCovers(String(x).includes("-") ? String(x) : x, undefined, p));
function nsgCheck(pred, label) {
  return (c) => {
    const hits = [];
    for (const x of nsgRules(c.r)) {
      if (x.dir !== "inbound" || x.access !== "allow") continue;
      if (x.src.some(isDyn) || x.ports.some(isDyn)) { hits.push(c.D(x.key)); continue; }
      if (!x.src.some(azAny)) continue;
      if (pred(x)) hits.push(c.H("rule " + (x.name || "?") + " allows " + x.src.filter(azAny).join(", ") + " to port(s) " + x.ports.join(", ") + label, x.key, "confirmed"));
    }
    return hits;
  };
}
rule("AZ-NSG-001", "high", "azure", NSG, "NSG allows SSH from the internet",
  [[CZ, "section 6 (Networking)"], [N, "SC-7"], [N, "AC-17"], [M, "T1021.004"]],
  "Restrict port 22 to a management range or use Azure Bastion / just-in-time access.",
  nsgCheck((x) => portHit(x.ports, 22) && !x.ports.includes("*"), ""));
rule("AZ-NSG-002", "high", "azure", NSG, "NSG allows RDP from the internet",
  [[CZ, "section 6 (Networking)"], [N, "SC-7"], [N, "AC-17"], [M, "T1021.001"]],
  "Restrict port 3389 to a management range or use Azure Bastion / just-in-time access.",
  nsgCheck((x) => portHit(x.ports, 3389) && !x.ports.includes("*"), ""));
rule("AZ-NSG-003", "critical", "azure", NSG, "NSG allows all ports from the internet",
  [[CZ, "section 6 (Networking)"], [N, "SC-7"], [M, "T1190"]],
  "Replace the any-port rule with the specific service ports.",
  nsgCheck((x) => x.ports.some((p) => String(p) === "*" || String(p) === "0-65535"), ""));

const STG = ["azurerm_storage_account", "Microsoft.Storage/storageAccounts"];
rule("AZ-ST-001", "high", "azure", STG, "Storage account allows public blob access",
  [[CZ, "section 3 (Storage Accounts)"], [N, "AC-3"], [M, "T1530"]],
  "Set allow_nested_items_to_be_public = false (allowBlobPublicAccess: false).",
  (c) => {
    const k = isArm(c) ? "allowBlobPublicAccess" : c.p.allow_nested_items_to_be_public !== undefined ? "allow_nested_items_to_be_public" : "allow_blob_public_access";
    const v = c.p[k];
    if (v == null) return isArm(c) ? [] : [c.H("not set; azurerm 3.x defaults allow_nested_items_to_be_public to true", null, "review")];
    if (isDyn(v)) return [c.D(k)];
    return isTrue(v) ? [c.H(k + " is true", k, "confirmed")] : [];
  });
rule("AZ-ST-002", "high", "azure", [...STG, "azurerm_storage_container"], "Storage container is publicly readable",
  [[CZ, "section 3 (Storage Accounts)"], [N, "AC-3"], [M, "T1530"]], "Set container_access_type = \"private\".",
  (c) => (c.r.type === "azurerm_storage_container" && ["blob", "container"].includes(lc(c.p.container_access_type)) ? [c.H("container_access_type = " + c.p.container_access_type, "container_access_type", "confirmed")] : []));
rule("AZ-ST-003", "high", "azure", STG, "Storage account accepts plain HTTP",
  [[CZ, "section 3 (Storage Accounts)"], [N, "SC-8"]], "Set https_traffic_only_enabled = true (supportsHttpsTrafficOnly: true).",
  (c) => {
    const k = isArm(c) ? "supportsHttpsTrafficOnly" : c.p.https_traffic_only_enabled !== undefined ? "https_traffic_only_enabled" : "enable_https_traffic_only";
    return isFalse(c.p[k]) ? [c.H(k + " is false", k, "confirmed")] : [];
  });
rule("AZ-ST-004", "medium", "azure", STG, "Storage account minimum TLS version is below 1.2",
  [[CZ, "section 3 (Storage Accounts)"], [N, "SC-8"], [N, "SC-13"]], "Set min_tls_version = \"TLS1_2\" (minimumTlsVersion: TLS1_2).",
  (c) => { const k = isArm(c) ? "minimumTlsVersion" : "min_tls_version"; const v = c.p[k]; return /^TLS1_[01]$/i.test(String(v || "")) ? [c.H(k + " = " + v, k, "confirmed")] : []; });
rule("AZ-ST-005", "low", "azure", STG, "Storage account network default action is Allow",
  [[CZ, "section 3 (Storage Accounts)"], [N, "SC-7"]], "Set network_rules default_action = \"Deny\" and allow selected networks or private endpoints.",
  (c) => { const v = azv(c, "network_rules.default_action", "networkAcls.defaultAction"); return lc(v) === "allow" ? [c.H("default action Allow", isArm(c) ? "defaultAction" : "default_action", "confirmed")] : []; });

const SQLS = ["azurerm_mssql_server", "azurerm_sql_server", "Microsoft.Sql/servers"];
rule("AZ-SQL-001", "medium", "azure", SQLS, "SQL server public network access is enabled",
  [[CZ, "section 4 (Database Services)"], [N, "SC-7"], [M, "T1190"]], "Set public_network_access_enabled = false and connect over private endpoints.",
  (c) => {
    if (isArm(c)) { const v = c.p.publicNetworkAccess; return v == null ? [c.H("publicNetworkAccess not set (defaults to Enabled)", null, "likely")] : lc(v) === "enabled" ? [c.H("publicNetworkAccess Enabled", "publicNetworkAccess", "confirmed")] : []; }
    if (c.r.type === "azurerm_sql_server") return [];
    const v = c.p.public_network_access_enabled;
    if (isDyn(v)) return [c.D("public_network_access_enabled")];
    return v == null ? [c.H("public_network_access_enabled not set (defaults to true)", null, "likely")] : isTrue(v) ? [c.H("public_network_access_enabled = true", "public_network_access_enabled", "confirmed")] : [];
  });
const SQLFW = ["azurerm_mssql_firewall_rule", "azurerm_sql_firewall_rule", "Microsoft.Sql/servers/firewallRules"];
const fwIps = (c) => (isArm(c) ? [c.p.startIpAddress, c.p.endIpAddress] : [c.p.start_ip_address, c.p.end_ip_address]);
rule("AZ-SQL-002", "critical", "azure", SQLFW, "SQL firewall rule allows the whole internet",
  [[CZ, "section 4 (Database Services)"], [N, "SC-7"], [M, "T1190"]], "Remove the 0.0.0.0 - 255.255.255.255 rule; allow only known client ranges.",
  (c) => { const [s, e] = fwIps(c); return s === "0.0.0.0" && e === "255.255.255.255" ? [c.H("start " + s + " end " + e, isArm(c) ? "startIpAddress" : "start_ip_address", "confirmed")] : []; });
rule("AZ-SQL-003", "low", "azure", SQLFW, "SQL firewall allows all Azure services",
  [[CZ, "section 4 (Database Services)"], [N, "SC-7"]], "The 0.0.0.0 rule admits traffic from any Azure tenant; prefer private endpoints or VNet rules.",
  (c) => { const [s, e] = fwIps(c); return s === "0.0.0.0" && e === "0.0.0.0" ? [c.H("AllowAllWindowsAzureIps (0.0.0.0)", isArm(c) ? "startIpAddress" : "start_ip_address", "confirmed")] : []; });
rule("AZ-SQL-004", "medium", "azure", SQLS, "SQL server auditing is not configured",
  [[CZ, "section 4 (Database Services)"], [N, "AU-2"], [N, "AU-12"]], "Add azurerm_mssql_server_extended_auditing_policy (or auditingSettings with state Enabled).",
  (c) => {
    if (isArm(c)) {
      const kids = arr(c.r.arm && c.r.arm.resources).filter((x) => /auditingSettings$/i.test(String(x && x.type)));
      const top = c.all.filter((o) => /^Microsoft\.Sql\/servers\/(extendedA|a)uditingSettings$/i.test(o.type));
      return kids.concat(top.map((o) => ({ properties: o.props }))).some((x) => lc(get(x, "properties.state")) === "enabled") ? [] : [c.H("no enabled auditingSettings in the template", null, "likely")];
    }
    if (c.p.extended_auditing_policy) return [];
    const rel = related(c, ["azurerm_mssql_server_extended_auditing_policy"], "server_id");
    if (rel.list.length) return [];
    return rel.unknown ? [c.D("server_id")] : [c.H("no extended auditing policy references this server", null, "likely")];
  });
rule("AZ-SQL-005", "high", "azure", ["azurerm_mssql_database", "Microsoft.Sql/servers/databases/transparentDataEncryption"], "SQL transparent data encryption is disabled",
  [[CZ, "section 4 (Database Services)"], [N, "SC-28"]], "Leave TDE enabled (the default) and use a customer-managed key where required.",
  (c) => (isArm(c) ? (lc(c.p.state) === "disabled" ? [c.H("TDE state Disabled", "state", "confirmed")] : []) : isFalse(c.p.transparent_data_encryption_enabled) ? [c.H("transparent_data_encryption_enabled = false", "transparent_data_encryption_enabled", "confirmed")] : []));
rule("AZ-SQL-006", "medium", "azure", SQLS, "SQL server minimum TLS version is below 1.2",
  [[CZ, "section 4 (Database Services)"], [N, "SC-8"]], "Set minimum_tls_version = \"1.2\".",
  (c) => { const k = isArm(c) ? "minimalTlsVersion" : "minimum_tls_version"; const v = c.p[k]; return v != null && /^(1\.0|1\.1|disabled|none)$/i.test(String(v)) ? [c.H(k + " = " + v, k, "confirmed")] : []; });

const KV = ["azurerm_key_vault", "Microsoft.KeyVault/vaults"];
rule("AZ-KV-001", "medium", "azure", KV, "Key Vault purge protection is off",
  [[CZ, "section 8 (Key Vault)"], [N, "CP-9"], [N, "SC-12"], [M, "T1485"]], "Set purge_protection_enabled = true (enablePurgeProtection: true).",
  (c) => needTrue(isArm(c) ? "enablePurgeProtection" : "purge_protection_enabled", null, "purge protection")({ ...c, cfn: false }));
rule("AZ-KV-002", "high", "azure", KV, "Key Vault soft delete is disabled",
  [[CZ, "section 8 (Key Vault)"], [N, "CP-9"], [M, "T1485"]], "Remove enableSoftDelete: false; soft delete is mandatory on new vaults.",
  (c) => { const k = isArm(c) ? "enableSoftDelete" : "soft_delete_enabled"; return isFalse(c.p[k]) ? [c.H(k + " = false", k, "confirmed")] : []; });
rule("AZ-KV-003", "low", "azure", KV, "Key Vault network default action is Allow",
  [[CZ, "section 8 (Key Vault)"], [N, "SC-7"]], "Set network_acls default_action = \"Deny\" and use private endpoints or allowed networks.",
  (c) => { const v = azv(c, "network_acls.default_action", "networkAcls.defaultAction"); if (v == null) return [c.H("no network ACLs; the vault is reachable from all networks", null, "likely")]; return lc(v) === "allow" ? [c.H("default action Allow", isArm(c) ? "defaultAction" : "default_action", "confirmed")] : []; });

const VMS = ["azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine", "azurerm_virtual_machine", "Microsoft.Compute/virtualMachines"];
rule("AZ-VM-001", "low", "azure", VMS, "VM disks have no host or customer-managed encryption",
  [[CZ, "section 7 (Virtual Machines)"], [N, "SC-28"]], "Enable encryption_at_host_enabled or attach a disk_encryption_set_id (platform-managed SSE is always on; this adds temp-disk/cache and key control).",
  (c) => {
    if (isArm(c)) return isTrue(get(c.p, "securityProfile.encryptionAtHost")) || get(c.p, "storageProfile.osDisk.managedDisk.diskEncryptionSet") ? [] : [c.H("no encryptionAtHost and no disk encryption set", "securityProfile", "likely")];
    if (c.r.type === "azurerm_virtual_machine") return [];
    return isTrue(c.p.encryption_at_host_enabled) || get(c.p, "os_disk.disk_encryption_set_id") ? [] : [c.H("no encryption_at_host_enabled and no disk_encryption_set_id", "os_disk", "likely")];
  });
rule("AZ-VM-002", "medium", "azure", ["azurerm_linux_virtual_machine", "Microsoft.Compute/virtualMachines"], "Linux VM allows password authentication",
  [[CZ, "section 7 (Virtual Machines)"], [N, "IA-2"], [N, "IA-5"], [M, "T1110"]], "Set disable_password_authentication = true and use SSH keys.",
  (c) => { const k = isArm(c) ? "disablePasswordAuthentication" : "disable_password_authentication"; const v = isArm(c) ? get(c.p, "osProfile.linuxConfiguration.disablePasswordAuthentication") : c.p[k]; return isFalse(v) ? [c.H(k + " = false", k, "confirmed")] : []; });

const APPS = ["azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_app_service", "azurerm_linux_function_app", "azurerm_windows_function_app", "azurerm_function_app", "Microsoft.Web/sites"];
rule("AZ-APP-001", "medium", "azure", APPS, "App Service does not enforce HTTPS",
  [[CZ, "section 9 (App Service)"], [N, "SC-8"]], "Set https_only = true (httpsOnly: true).",
  (c) => needTrue(isArm(c) ? "httpsOnly" : "https_only", null, "HTTPS only")({ ...c, cfn: false }));
rule("AZ-APP-002", "medium", "azure", APPS, "App Service allows plain FTP",
  [[CZ, "section 9 (App Service)"], [N, "SC-8"], [N, "CM-7"]], "Set ftps_state = \"Disabled\" (or FtpsOnly).",
  (c) => { const v = azv(c, "site_config.ftps_state", "siteConfig.ftpsState"); return lc(v) === "allallowed" ? [c.H("ftps_state AllAllowed", isArm(c) ? "ftpsState" : "ftps_state", "confirmed")] : []; });
rule("AZ-APP-003", "low", "azure", APPS, "App Service has no managed identity",
  [[CZ, "section 9 (App Service)"], [N, "IA-5"]], "Add an identity block (SystemAssigned or UserAssigned) and use it instead of stored credentials.",
  (c) => ((isArm(c) ? c.r.arm && c.r.arm.identity : c.p.identity) ? [] : [c.H("no identity configured", null, "likely")]));
rule("AZ-APP-004", "medium", "azure", APPS, "App Service minimum TLS version is below 1.2",
  [[CZ, "section 9 (App Service)"], [N, "SC-8"]], "Set site_config minimum_tls_version = \"1.2\".",
  (c) => { const v = azv(c, "site_config.minimum_tls_version", "siteConfig.minTlsVersion"); return v != null && /^1\.[01]$/.test(String(v)) ? [c.H("minimum TLS " + v, isArm(c) ? "minTlsVersion" : "minimum_tls_version", "confirmed")] : []; });

const AKS = ["azurerm_kubernetes_cluster", "Microsoft.ContainerService/managedClusters"];
rule("AZ-AKS-001", "high", "azure", AKS, "AKS cluster has Kubernetes RBAC disabled",
  [[N, "AC-3"], [N, "AC-6"]], "Set role_based_access_control_enabled = true (enableRBAC: true) and integrate Entra ID.",
  (c) => { const k = isArm(c) ? "enableRBAC" : "role_based_access_control_enabled"; return isFalse(c.p[k]) ? [c.H(k + " = false", k, "confirmed")] : []; });
rule("AZ-AKS-002", "medium", "azure", AKS, "AKS API server is public with no authorized IP ranges",
  [[N, "SC-7"], [N, "AC-17"], [M, "T1133"]], "Enable private_cluster_enabled or set api_server_access_profile authorized_ip_ranges.",
  (c) => {
    const priv = azv(c, "private_cluster_enabled", "apiServerAccessProfile.enablePrivateCluster");
    const ips = azv(c, "api_server_access_profile.authorized_ip_ranges|api_server_authorized_ip_ranges", "apiServerAccessProfile.authorizedIPRanges");
    if (isTrue(priv) || (ips && arr(ips).length && !arr(ips).some(anyCidr))) return [];
    if (isDyn(priv) || isDyn(ips)) return [c.D("api_server_access_profile")];
    return [c.H("public API server, no authorized IP ranges", null, "likely")];
  });
rule("AZ-AKS-003", "low", "azure", AKS, "AKS local accounts are enabled",
  [[N, "AC-2"], [N, "IA-2"]], "Set local_account_disabled = true (disableLocalAccounts: true) so access goes through Entra ID.",
  (c) => needTrue(isArm(c) ? "disableLocalAccounts" : "local_account_disabled", null, "local accounts disabled")({ ...c, cfn: false }));
rule("AZ-AKS-004", "low", "azure", AKS, "AKS cluster has no network policy engine",
  [[N, "SC-7"]], "Set network_profile network_policy to azure, calico or cilium.",
  (c) => (azv(c, "network_profile.network_policy", "networkProfile.networkPolicy") ? [] : [c.H("no network policy engine", null, "likely")]));

/* ---------------------------- GCP ---------------------------------------- */

const PUBLIC_MEMBERS = new Set(["allusers", "allauthenticatedusers"]);
rule("GCP-GCS-001", "critical", "gcp", ["google_storage_bucket_iam_member", "google_storage_bucket_iam_binding", "google_storage_bucket_access_control", "google_storage_default_object_access_control", "google_storage_object_access_control"], "Cloud Storage bucket is public (allUsers / allAuthenticatedUsers)",
  [[CG, "5.1"], [N, "AC-3"], [M, "T1530"]], "Remove allUsers and allAuthenticatedUsers grants; enforce public access prevention.",
  (c) => {
    const m = arr(c.p.member).concat(arr(c.p.members), arr(c.p.entity));
    return m.filter((x) => typeof x === "string" && PUBLIC_MEMBERS.has(lc(x).replace(/^(user|group)-/, ""))).map((x) => c.H(x + " granted " + (c.p.role || "access"), c.p.member != null ? "member" : c.p.members != null ? "members" : "entity", "confirmed"));
  });
rule("GCP-GCS-002", "medium", "gcp", ["google_storage_bucket"], "Uniform bucket-level access is disabled",
  [[CG, "5.2"], [N, "AC-3"]], "Set uniform_bucket_level_access = true so object ACLs cannot grant access.",
  needTrue("uniform_bucket_level_access", null, "uniform bucket-level access"));
rule("GCP-GCS-003", "low", "gcp", ["google_storage_bucket"], "Bucket versioning is not enabled",
  [[N, "CP-9"], [M, "T1485"]], "Add versioning { enabled = true } or a retention policy.",
  needTrue("versioning.enabled", null, "versioning"));
rule("GCP-GCS-004", "low", "gcp", ["google_storage_bucket"], "Bucket public access prevention is not enforced",
  [[CG, "5.1"], [N, "AC-3"]], "Set public_access_prevention = \"enforced\".",
  (c) => (lc(c.p.public_access_prevention) === "enforced" ? [] : [c.H("public_access_prevention = " + (c.p.public_access_prevention || "inherited (unset)"), "public_access_prevention", c.p.public_access_prevention ? "confirmed" : "likely")]));

const GCE = ["google_compute_instance", "google_compute_instance_template"];
const defaultSa = (sa) => !sa || !sa.email || /-compute@developer\.gserviceaccount\.com$/.test(String(sa.email)) || lc(sa.email) === "default";
rule("GCP-CE-001", "high", "gcp", GCE, "Instance uses the default service account with full cloud-platform scope",
  [[CG, "4.2"], [N, "AC-6"], [M, "T1078.004"]], "Use a dedicated least-privilege service account and request only the scopes needed.",
  (c) => {
    const sa = arr(c.p.service_account)[0];
    if (!sa) return [];
    if (isDyn(sa.email)) return [c.D("email")];
    return defaultSa(sa) && arr(sa.scopes).some((s) => /cloud-platform$/.test(String(s))) ? [c.H("default compute service account with cloud-platform scope", "scopes", "confirmed")] : [];
  });
rule("GCP-CE-002", "medium", "gcp", GCE, "Instance uses the default compute service account",
  [[CG, "4.1"], [N, "AC-6"]], "Create a dedicated service account with only the roles this workload needs.",
  (c) => {
    const sa = arr(c.p.service_account)[0];
    if (!sa) return [];
    if (isDyn(sa.email)) return [];
    return defaultSa(sa) && !arr(sa.scopes).some((s) => /cloud-platform$/.test(String(s))) ? [c.H(sa.email ? "service account " + sa.email : "service_account block with no email (default account)", "service_account", sa.email ? "confirmed" : "likely")] : [];
  });
const meta = (c) => (c.p.metadata && typeof c.p.metadata === "object" && !isDyn(c.p.metadata) ? c.p.metadata : {});
rule("GCP-CE-003", "low", "gcp", GCE, "Project-wide SSH keys are not blocked",
  [[CG, "4.3"], [N, "AC-17"]], "Set metadata block-project-ssh-keys = true, or use OS Login.",
  (c) => (isTrue(meta(c)["block-project-ssh-keys"]) || isTrue(meta(c)["enable-oslogin"]) ? [] : [c.H("block-project-ssh-keys not set", "metadata", "likely")]));
rule("GCP-CE-004", "medium", "gcp", [...GCE, "google_compute_project_metadata", "google_compute_project_metadata_item"], "Serial port access is enabled",
  [[CG, "4.5"], [N, "CM-7"], [N, "AC-17"]], "Remove serial-port-enable or set it to false.",
  (c) => {
    if (c.r.type === "google_compute_project_metadata_item") return lc(c.p.key) === "serial-port-enable" && isTrue(c.p.value) ? [c.H("serial-port-enable = " + c.p.value, "value", "confirmed")] : [];
    const v = meta(c)["serial-port-enable"];
    return isTrue(v) || lc(v) === "1" ? [c.H("serial-port-enable = " + v, "serial-port-enable", "confirmed")] : [];
  });
rule("GCP-CE-005", "medium", "gcp", [...GCE, "google_compute_project_metadata", "google_compute_project_metadata_item"], "OS Login is disabled",
  [[CG, "4.4"], [N, "IA-2"], [N, "AC-2"]], "Set enable-oslogin = TRUE in project metadata and do not override it per instance.",
  (c) => {
    if (c.r.type === "google_compute_project_metadata_item") return lc(c.p.key) === "enable-oslogin" && isFalse(c.p.value) ? [c.H("enable-oslogin = " + c.p.value, "value", "confirmed")] : [];
    const v = meta(c)["enable-oslogin"];
    if (c.r.type === "google_compute_project_metadata" && v == null) return [c.H("project metadata does not set enable-oslogin", "metadata", "likely")];
    return isFalse(v) ? [c.H("enable-oslogin = " + v, "enable-oslogin", "confirmed")] : [];
  });
rule("GCP-CE-006", "low", "gcp", GCE, "Instance has an external IP address",
  [[N, "SC-7"], [M, "T1190"]], "Remove access_config and reach the instance through IAP, a load balancer or Cloud NAT.",
  (c) => (arr(c.p.network_interface).some((n) => n && arr(n.access_config).length) ? [c.H("network_interface has access_config (external IP)", "access_config", "confirmed")] : []));
rule("GCP-CE-007", "low", "gcp", GCE, "Shielded VM secure boot is off",
  [[CG, "4.8"], [N, "SI-7"]], "Add shielded_instance_config { enable_secure_boot = true, enable_vtpm = true, enable_integrity_monitoring = true }.",
  needTrue("shielded_instance_config.enable_secure_boot", null, "secure boot"));
rule("GCP-CE-008", "low", "gcp", GCE, "Instance IP forwarding is enabled",
  [[CG, "4.6"], [N, "SC-7"]], "Set can_ip_forward = false unless the instance is a router or NAT appliance.",
  needNotTrue("can_ip_forward", null, "IP forwarding"));

function gcpFw(c) {
  if (lc(c.p.direction || "INGRESS") !== "ingress" || isTrue(c.p.disabled)) return null;
  const src = arr(c.p.source_ranges);
  if (isDyn(c.p.source_ranges)) return "dyn";
  if (!src.some(anyCidr)) return null;
  return arr(c.p.allow).map((a) => ({ proto: lc(a.protocol), ports: arr(a.ports).map(String) }));
}
function gcpFwCheck(pred, label) {
  return (c) => {
    const al = gcpFw(c);
    if (al === "dyn") return [c.D("source_ranges")];
    if (!al) return [];
    return al.filter(pred).map((a) => c.H("0.0.0.0/0 allowed " + a.proto + (a.ports.length ? " ports " + a.ports.join(", ") : " (all ports)") + label, "source_ranges", "confirmed"));
  };
}
const gAll = (a) => a.proto === "all" || ((a.proto === "tcp" || a.proto === "udp") && !a.ports.length) || a.ports.includes("0-65535");
const gPort = (a, p) => !gAll(a) && (a.proto === "tcp" || a.proto === "all") && a.ports.some((x) => rangeCovers(x, undefined, p));
rule("GCP-FW-001", "high", "gcp", ["google_compute_firewall"], "Firewall allows SSH from 0.0.0.0/0",
  [[CG, "3.6"], [N, "SC-7"], [N, "AC-17"], [M, "T1021.004"]], "Restrict source_ranges for port 22 (for example to IAP 35.235.240.0/20).",
  gcpFwCheck((a) => gPort(a, 22), ""));
rule("GCP-FW-002", "high", "gcp", ["google_compute_firewall"], "Firewall allows RDP from 0.0.0.0/0",
  [[CG, "3.7"], [N, "SC-7"], [N, "AC-17"], [M, "T1021.001"]], "Restrict source_ranges for port 3389.",
  gcpFwCheck((a) => gPort(a, 3389), ""));
rule("GCP-FW-003", "critical", "gcp", ["google_compute_firewall"], "Firewall allows all ports from 0.0.0.0/0",
  [[N, "SC-7"], [M, "T1190"]], "List only the service ports in allow and narrow source_ranges.",
  gcpFwCheck(gAll, ""));

const GSQL = ["google_sql_database_instance"];
rule("GCP-SQL-001", "critical", "gcp", GSQL, "Cloud SQL authorizes 0.0.0.0/0",
  [[CG, "6.5"], [N, "SC-7"], [M, "T1190"]], "Remove the 0.0.0.0/0 authorized network; use private IP or the Cloud SQL Auth Proxy.",
  (c) => arr(get(c.p, "settings.ip_configuration.authorized_networks")).filter((n) => n && anyCidr(n.value)).map((n) => c.H("authorized network " + (n.name ? n.name + " " : "") + n.value, "authorized_networks", "confirmed")));
rule("GCP-SQL-002", "medium", "gcp", GSQL, "Cloud SQL instance has a public IP",
  [[CG, "6.6"], [N, "SC-7"]], "Set ip_configuration ipv4_enabled = false and use private_network.",
  (c) => { const v = get(c.p, "settings.ip_configuration.ipv4_enabled"); if (isDyn(v)) return [c.D("ipv4_enabled")]; return isFalse(v) ? [] : [c.H(v == null ? "ipv4_enabled not set (defaults to true)" : "ipv4_enabled = true", "ipv4_enabled", v == null ? "likely" : "confirmed")]; });
rule("GCP-SQL-003", "medium", "gcp", GSQL, "Cloud SQL does not require SSL",
  [[CG, "6.4"], [N, "SC-8"]], "Set ip_configuration ssl_mode = \"ENCRYPTED_ONLY\" (or TRUSTED_CLIENT_CERTIFICATE_REQUIRED).",
  (c) => {
    const ic = get(c.p, "settings.ip_configuration") || {};
    if (isTrue(ic.require_ssl) || ["encrypted_only", "trusted_client_certificate_required"].includes(lc(ic.ssl_mode))) return [];
    return [c.H("ssl_mode = " + (ic.ssl_mode || "unset") + ", require_ssl = " + (ic.require_ssl ?? "unset"), ic.ssl_mode ? "ssl_mode" : "ip_configuration", ic.ssl_mode || ic.require_ssl != null ? "confirmed" : "likely")];
  });
rule("GCP-SQL-004", "medium", "gcp", GSQL, "Cloud SQL automated backups are disabled",
  [[CG, "6.7"], [N, "CP-9"], [M, "T1490"]], "Add settings backup_configuration { enabled = true }.",
  (c) => (lc(c.p.instance_type) === "read_replica_instance" || c.p.master_instance_name ? [] : needTrue("settings.backup_configuration.enabled", null, "automated backups")(c)));

const GKE = ["google_container_cluster"];
rule("GCP-GKE-001", "high", "gcp", GKE, "GKE legacy ABAC is enabled",
  [[N, "AC-3"], [N, "AC-6"]], "Set enable_legacy_abac = false and use Kubernetes RBAC.",
  needNotTrue("enable_legacy_abac", null, "legacy ABAC"));
rule("GCP-GKE-002", "high", "gcp", GKE, "GKE basic authentication is configured",
  [[N, "IA-2"], [N, "IA-5"]], "Remove master_auth username/password; authenticate with Google identities.",
  (c) => { const u = get(c.p, "master_auth.username"); return typeof u === "string" && u ? [c.H("master_auth username set", "username", "confirmed")] : []; });
rule("GCP-GKE-003", "medium", "gcp", GKE, "GKE issues legacy client certificates",
  [[N, "IA-5"]], "Set master_auth client_certificate_config issue_client_certificate = false.",
  needNotTrue("master_auth.client_certificate_config.issue_client_certificate", null, "client certificate issuance"));
rule("GCP-GKE-004", "medium", "gcp", GKE, "GKE nodes are not private",
  [[N, "SC-7"]], "Add private_cluster_config { enable_private_nodes = true }.",
  needTrue("private_cluster_config.enable_private_nodes", null, "private nodes"));
rule("GCP-GKE-005", "low", "gcp", GKE, "GKE network policy enforcement is off",
  [[N, "SC-7"]], "Enable network_policy { enabled = true } or Dataplane V2 (datapath_provider = ADVANCED_DATAPATH).",
  (c) => (lc(c.p.datapath_provider) === "advanced_datapath" ? [] : needTrue("network_policy.enabled", null, "network policy")(c)));
rule("GCP-GKE-006", "medium", "gcp", GKE, "GKE control plane has no authorized networks",
  [[N, "SC-7"], [N, "AC-17"], [M, "T1133"]], "Add master_authorized_networks_config with your admin CIDRs, or make the endpoint private.",
  (c) => (isTrue(get(c.p, "private_cluster_config.enable_private_endpoint")) || c.p.master_authorized_networks_config ? [] : [c.H("no master_authorized_networks_config", null, "likely")]));
rule("GCP-GKE-007", "low", "gcp", GKE, "GKE Workload Identity is not enabled",
  [[N, "IA-5"], [M, "T1552.005"]], "Add workload_identity_config { workload_pool = \"PROJECT.svc.id.goog\" }.",
  needSet("workload_identity_config", null, "no workload_identity_config"));
rule("GCP-IAM-001", "medium", "gcp", ["google_project_iam_member", "google_project_iam_binding", "google_organization_iam_member", "google_folder_iam_member"], "Primitive Owner or Editor role granted",
  [[CG, "section 1 (IAM)"], [N, "AC-6"], [M, "T1078.004"]], "Grant predefined or custom roles scoped to the job instead of roles/owner or roles/editor.",
  (c) => (/^roles\/(owner|editor)$/.test(String(c.p.role)) ? [c.H(c.p.role + " to " + arr(c.p.member).concat(arr(c.p.members)).filter((x) => typeof x === "string").join(", "), "role", "confirmed")] : []));
rule("GCP-KMS-001", "low", "gcp", ["google_kms_crypto_key"], "KMS key rotation period is missing or longer than 90 days",
  [[CG, "section 1 (IAM / KMS)"], [N, "SC-12"]], "Set rotation_period = \"7776000s\" (90 days) or less.",
  (c) => {
    if (c.p.purpose && lc(c.p.purpose) !== "encrypt_decrypt") return [];
    const v = c.p.rotation_period;
    if (v == null) return [c.H("no rotation_period", null, "likely")];
    const s = num(String(v).replace(/s$/, ""));
    return Number.isFinite(s) && s > 7776000 ? [c.H("rotation every " + Math.round(s / 86400) + " days", "rotation_period", "confirmed")] : [];
  });

/* ---------------------------- Kubernetes --------------------------------- */

const WORKLOADS = new Set(["Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob"]);
const LONG_RUNNING = new Set(["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController"]);
const isWorkload = (r) => r.platform === "kubernetes" && r.format === "kubernetes" && WORKLOADS.has(r.type);

/** The pod spec of a workload object. */
export function podSpec(doc) {
  if (!doc || typeof doc !== "object") return null;
  if (doc.kind === "Pod") return doc.spec || null;
  if (doc.kind === "CronJob") return get(doc, "spec.jobTemplate.spec.template.spec") || null;
  return get(doc, "spec.template.spec") || null;
}
function containersOf(spec) {
  const out = [];
  for (const k of ["initContainers", "containers", "ephemeralContainers"]) arr(spec && spec[k]).forEach((ct) => { if (ct && typeof ct === "object") out.push({ ct, group: k }); });
  return out;
}
/** Run fn(container, podSpec, c) for each container; tag hits with the container name. */
function perContainer(fn, groups = ["initContainers", "containers", "ephemeralContainers"]) {
  return (c) => {
    const spec = podSpec(c.p);
    if (!spec) return [];
    const hits = [];
    for (const { ct, group } of containersOf(spec)) {
      if (!groups.includes(group)) continue;
      const after = ct.name ? new RegExp("^\\s*(?:-\\s*)?name\\s*:\\s*[\"']?" + reEsc(ct.name) + "[\"']?\\s*$") : null;
      for (const h of fn(ct, spec, c) || []) { h.detail = "container " + (ct.name || "?") + ": " + h.detail; if (after && !h.after) h.after = after; hits.push(h); }
    }
    return hits;
  };
}
const effSC = (ct, spec, k) => { const v = get(ct, "securityContext." + k); return v !== undefined ? v : get(spec, "securityContext." + k); };

rule("K8S-001", "critical", "kubernetes", isWorkload, "Container runs privileged",
  [[CK, "5.2.2"], [N, "AC-6"], [N, "CM-7"], [M, "T1611"]], "Remove privileged: true; grant only the specific capabilities required.",
  perContainer((ct, s, c) => (isTrue(get(ct, "securityContext.privileged")) ? [c.H("privileged: true", "privileged")] : [])));
rule("K8S-002", "high", "kubernetes", isWorkload, "Pod shares the host PID namespace",
  [[CK, "5.2.3"], [N, "SC-39"], [M, "T1611"]], "Remove hostPID: true.",
  (c) => (isTrue(get(podSpec(c.p), "hostPID")) ? [c.H("hostPID: true", "hostPID")] : []));
rule("K8S-003", "high", "kubernetes", isWorkload, "Pod shares the host IPC namespace",
  [[CK, "5.2.4"], [N, "SC-39"], [M, "T1611"]], "Remove hostIPC: true.",
  (c) => (isTrue(get(podSpec(c.p), "hostIPC")) ? [c.H("hostIPC: true", "hostIPC")] : []));
rule("K8S-004", "high", "kubernetes", isWorkload, "Pod uses the host network",
  [[CK, "5.2.5"], [N, "SC-7"], [M, "T1611"]], "Remove hostNetwork: true unless the workload is a node-level network agent.",
  (c) => (isTrue(get(podSpec(c.p), "hostNetwork")) ? [c.H("hostNetwork: true", "hostNetwork")] : []));
const SOCKETS = /\/(docker|containerd|crio|cri-dockerd)\.sock$|^\/var\/run\/(docker|containerd|crio)(\/|$)|^\/run\/containerd/;
rule("K8S-005", "high", "kubernetes", isWorkload, "Pod mounts a hostPath volume",
  [[CK, "5.2.12"], [N, "AC-6"], [M, "T1611"]], "Replace hostPath with emptyDir, a PVC, a ConfigMap or a CSI volume.",
  (c) => arr(get(podSpec(c.p), "volumes")).filter((v) => v && v.hostPath && !SOCKETS.test(String(get(v, "hostPath.path")))).map((v) => c.H("volume " + v.name + " -> hostPath " + get(v, "hostPath.path"), "path", "confirmed", new RegExp("name\\s*:\\s*[\"']?" + reEsc(String(v.name)) + "[\"']?\\s*$"))));
rule("K8S-006", "critical", "kubernetes", isWorkload, "Pod mounts the container runtime socket",
  [[CK, "5.2.12"], [N, "AC-6"], [M, "T1611"], [M, "T1610"]], "Do not mount docker.sock / containerd.sock; it gives root on the node.",
  (c) => arr(get(podSpec(c.p), "volumes")).filter((v) => v && v.hostPath && SOCKETS.test(String(get(v, "hostPath.path")))).map((v) => c.H("volume " + v.name + " -> " + get(v, "hostPath.path"), "path", "confirmed", new RegExp("name\\s*:\\s*[\"']?" + reEsc(String(v.name)) + "[\"']?\\s*$"))));
rule("K8S-007", "medium", "kubernetes", isWorkload, "Container allows privilege escalation",
  [[CK, "5.2.6"], [N, "AC-6"], [M, "T1068"]], "Set securityContext.allowPrivilegeEscalation: false.",
  perContainer((ct, s, c) => { const v = get(ct, "securityContext.allowPrivilegeEscalation"); return isFalse(v) ? [] : [c.H(v == null ? "allowPrivilegeEscalation not set (defaults to true)" : "allowPrivilegeEscalation: true", v == null ? null : "allowPrivilegeEscalation", v == null ? "likely" : "confirmed")]; }));
rule("K8S-008", "high", "kubernetes", isWorkload, "Container runs as UID 0",
  [[CK, "5.2.7"], [N, "AC-6"], [M, "T1611"]], "Set runAsUser to a non-zero UID and runAsNonRoot: true.",
  perContainer((ct, s, c) => (num(effSC(ct, s, "runAsUser")) === 0 ? [c.H("runAsUser: 0", "runAsUser")] : [])));
rule("K8S-009", "medium", "kubernetes", isWorkload, "Container is not required to run as non-root",
  [[CK, "5.2.7"], [N, "AC-6"]], "Set securityContext.runAsNonRoot: true (pod or container level).",
  perContainer((ct, s, c) => { if (num(effSC(ct, s, "runAsUser")) === 0) return []; const v = effSC(ct, s, "runAsNonRoot"); return isTrue(v) ? [] : [c.H(v == null ? "runAsNonRoot not set" : "runAsNonRoot: false", v == null ? null : "runAsNonRoot", v == null ? "likely" : "confirmed")]; }));
const DANGEROUS_CAPS = new Set(["ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO", "BPF", "PERFMON"]);
const SYS_ADMIN_NOTE = (caps) => (caps.some((x) => x === "SYS_ADMIN" || x === "ALL") ? " (SYS_ADMIN permits the cgroup v1 release_agent container escape, CVE-2022-0492)" : "");
const UNCONFINED_NOTE = " (unshare is no longer blocked, a precondition for the CVE-2022-0185 and CVE-2022-0492 container escapes)";
rule("K8S-010", "high", "kubernetes", isWorkload, "Container adds dangerous Linux capabilities",
  [[CK, "5.2.9"], [N, "AC-6"], [M, "T1611"]], "Remove the added capabilities; drop ALL and add back only narrowly required ones (for example NET_BIND_SERVICE).",
  perContainer((ct, s, c) => { const add = arr(get(ct, "securityContext.capabilities.add")).map((x) => String(x).toUpperCase().replace(/^CAP_/, "")); const bad = add.filter((x) => DANGEROUS_CAPS.has(x)); return bad.length ? [c.H("capabilities.add: " + bad.join(", ") + SYS_ADMIN_NOTE(bad), "add")] : []; }));
rule("K8S-011", "low", "kubernetes", isWorkload, "Container does not drop NET_RAW",
  [[CK, "5.2.8"], [N, "CM-7"], [M, "T1040"]], "Add capabilities.drop: [\"ALL\"] (or at least NET_RAW).",
  perContainer((ct, s, c) => { if (isTrue(get(ct, "securityContext.privileged"))) return []; const drop = arr(get(ct, "securityContext.capabilities.drop")).map((x) => String(x).toUpperCase()); return drop.includes("ALL") || drop.includes("NET_RAW") || drop.includes("CAP_NET_RAW") ? [] : [c.H("NET_RAW not dropped", drop.length ? "drop" : null, "likely")]; }));
rule("K8S-012", "low", "kubernetes", isWorkload, "Container has no CPU or memory limits",
  [[CK, "section 5.7 (General Policies)"], [N, "SC-6"]], "Set resources.limits.memory (and cpu where appropriate) so one pod cannot starve the node.",
  perContainer((ct, s, c) => { const l = get(ct, "resources.limits") || {}; const miss = ["cpu", "memory"].filter((k) => l[k] == null); return miss.length ? [c.H("no " + miss.join("/") + " limit", l && Object.keys(l).length ? "limits" : null, "confirmed")] : []; }, ["containers"]));
rule("K8S-013", "info", "kubernetes", isWorkload, "Container has no resource requests",
  [[N, "SC-6"]], "Set resources.requests so the scheduler can place the pod correctly.",
  perContainer((ct, s, c) => { const r = get(ct, "resources.requests") || {}; return r.cpu == null && r.memory == null ? [c.H("no cpu/memory requests", null, "confirmed")] : []; }, ["containers"]));

/** Split an image reference into { repo, tag, digest }. */
export function parseImage(img) {
  const s = String(img || "").trim();
  const at = s.indexOf("@");
  const digest = at >= 0 ? s.slice(at + 1) : "";
  const noDigest = at >= 0 ? s.slice(0, at) : s;
  const slash = noDigest.lastIndexOf("/");
  const colon = noDigest.lastIndexOf(":");
  const tag = colon > slash ? noDigest.slice(colon + 1) : "";
  return { repo: colon > slash ? noDigest.slice(0, colon) : noDigest, tag, digest };
}
const dynImage = (s) => /\$\{|\$[A-Za-z_]|\{\{/.test(String(s));
rule("K8S-014", "medium", "kubernetes", isWorkload, "Container image uses :latest or no tag",
  [[CK, "section 5.7 (General Policies)"], [N, "CM-2"], [N, "SI-7"], [M, "T1525"]], "Pin the image to a version tag, ideally with an @sha256 digest.",
  perContainer((ct, s, c) => { const im = parseImage(ct.image); if (!ct.image || dynImage(ct.image) || im.digest) return []; return !im.tag || lc(im.tag) === "latest" ? [c.H("image " + ct.image, "image")] : []; }));
rule("K8S-015", "info", "kubernetes", isWorkload, "Container image is not pinned by digest",
  [[N, "SI-7"], [N, "CM-14"], [M, "T1525"]], "Reference images by @sha256 digest so the deployed bytes cannot change under a tag.",
  perContainer((ct, s, c) => { const im = parseImage(ct.image); return ct.image && !dynImage(ct.image) && !im.digest && im.tag && lc(im.tag) !== "latest" ? [c.H("image " + ct.image, "image")] : []; }));
rule("K8S-016", "low", "kubernetes", (r) => isWorkload(r) && LONG_RUNNING.has(r.type), "Container has no readiness probe",
  [[N, "SC-5"]], "Add a readinessProbe so traffic only reaches ready pods.",
  perContainer((ct, s, c) => (ct.readinessProbe ? [] : [c.H("no readinessProbe", null, "confirmed")]), ["containers"]));
rule("K8S-017", "low", "kubernetes", (r) => isWorkload(r) && LONG_RUNNING.has(r.type), "Container has no liveness probe",
  [[N, "SC-5"]], "Add a livenessProbe so hung containers are restarted.",
  perContainer((ct, s, c) => (ct.livenessProbe ? [] : [c.H("no livenessProbe", null, "confirmed")]), ["containers"]));
rule("K8S-018", "info", "kubernetes", isWorkload, "Secret passed as an environment variable",
  [[CK, "5.4.1"], [N, "SC-28"]], "Mount secrets as files instead of env vars; env vars leak into logs, crash dumps and child processes.",
  perContainer((ct, s, c) => arr(ct.env).filter((e) => e && get(e, "valueFrom.secretKeyRef")).map((e) => c.H("env " + e.name + " from secret " + get(e, "valueFrom.secretKeyRef.name"), "secretKeyRef"))));
rule("K8S-019", "high", "kubernetes", isWorkload, "Literal secret in container environment",
  [[CK, "5.4.1"], [N, "IA-5"], [M, "T1552.001"]], "Store the value in a Secret (or an external secret store) and reference it.",
  perContainer((ct, s, c) => secretEnvHits(c, arr(ct.env).filter((e) => e && e.name && e.value != null).map((e) => [String(e.name), e.value]))));
rule("K8S-020", "low", "kubernetes", isWorkload, "Service account token is auto-mounted",
  [[CK, "5.1.6"], [N, "AC-6"], [M, "T1528"]], "Set automountServiceAccountToken: false unless the pod calls the Kubernetes API.",
  (c) => {
    const spec = podSpec(c.p); if (!spec) return [];
    const v = spec.automountServiceAccountToken;
    if (isFalse(v)) return [];
    const saName = spec.serviceAccountName || spec.serviceAccount || "default";
    const sa = c.all.find((o) => o.type === "ServiceAccount" && String(get(o.props, "metadata.name")) === saName && (o.ns || "default") === (c.r.ns || "default"));
    if (v == null && sa && isFalse(sa.props.automountServiceAccountToken)) return [];
    return [c.H((v == null ? "automountServiceAccountToken not set" : "automountServiceAccountToken: true") + " (service account " + saName + ")", v == null ? null : "automountServiceAccountToken", v == null ? "likely" : "confirmed")];
  });
rule("K8S-021", "low", "kubernetes", (r) => r.platform === "kubernetes" && r.format === "kubernetes" && !["Namespace", "ClusterRole", "ClusterRoleBinding", "CustomResourceDefinition", "PersistentVolume", "StorageClass", "PriorityClass", "IngressClass", "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration", "APIService", "PodSecurityPolicy", "RuntimeClass"].includes(r.type), "Object is in the default namespace",
  [[CK, "5.7.4"], [N, "AC-4"]], "Create a dedicated namespace and set metadata.namespace explicitly.",
  (c) => { const ns = get(c.p, "metadata.namespace"); if (ns === "default") return [c.H("namespace: default", "namespace", "confirmed")]; return ns == null ? [c.H("no metadata.namespace; lands in the default namespace unless applied with -n", null, "review")] : []; });
rule("K8S-022", "info", "kubernetes", ["Service"], "Service is exposed outside the cluster (LoadBalancer / NodePort)",
  [[N, "SC-7"]], "Confirm the exposure is intended; prefer an Ingress with TLS, and set loadBalancerSourceRanges.",
  (c) => { const t = get(c.p, "spec.type"); return ["LoadBalancer", "NodePort"].includes(t) ? [c.H("type " + t + (t === "LoadBalancer" && !arr(get(c.p, "spec.loadBalancerSourceRanges")).length ? " with no loadBalancerSourceRanges" : ""), "type")] : []; });
rule("K8S-023", "medium", "kubernetes", ["Ingress"], "Ingress has no TLS",
  [[N, "SC-8"], [M, "T1557"]], "Add spec.tls with a certificate secret for every host.",
  (c) => (arr(get(c.p, "spec.tls")).length ? [] : [c.H("no spec.tls", null, "confirmed")]));
const RBAC_ROLES = ["Role", "ClusterRole"];
const rbacRules = (c) => arr(get(c.p, "rules")).filter((r) => r && typeof r === "object");
rule("K8S-024", "high", "kubernetes", RBAC_ROLES, "RBAC role uses wildcards",
  [[CK, "5.1.3"], [N, "AC-6"]], "Replace \"*\" in verbs, resources and apiGroups with explicit values.",
  (c) => rbacRules(c).filter((r) => arr(r.verbs).includes("*") || arr(r.resources).includes("*")).map((r) => c.H("verbs [" + arr(r.verbs).join(", ") + "] on resources [" + arr(r.resources).join(", ") + "]", arr(r.verbs).includes("*") ? "verbs" : "resources")));
rule("K8S-025", "high", "kubernetes", ["RoleBinding", "ClusterRoleBinding"], "Binding grants cluster-admin",
  [[CK, "5.1.1"], [N, "AC-6"], [M, "T1078"]], "Bind a narrower role; reserve cluster-admin for break-glass accounts.",
  (c) => (get(c.p, "roleRef.name") === "cluster-admin" ? [c.H("cluster-admin bound to " + arr(c.p.subjects).map((s) => s && s.kind + "/" + s.name).join(", "), "roleRef")] : []));
rule("K8S-026", "critical", "kubernetes", ["RoleBinding", "ClusterRoleBinding"], "Binding grants permissions to anonymous or all authenticated users",
  [[CK, "section 5.1 (RBAC)"], [N, "AC-3"], [M, "T1078"]], "Remove system:anonymous, system:unauthenticated and system:authenticated subjects.",
  (c) => arr(c.p.subjects).filter((s) => s && ["system:anonymous", "system:unauthenticated", "system:authenticated"].includes(s.name)).map((s) => c.H(s.name + " bound to " + get(c.p, "roleRef.name"), "subjects")));
rule("K8S-027", "low", "kubernetes", ["Pod"], "Bare Pod without a controller",
  [[N, "CP-10"]], "Run workloads through a Deployment, StatefulSet, DaemonSet or Job so they are rescheduled.",
  (c) => (arr(get(c.p, "metadata.ownerReferences")).length ? [] : [c.H("kind: Pod", "kind")]));
rule("K8S-028", "low", "kubernetes", isWorkload, "No seccomp profile set",
  [[CK, "5.7.2"], [N, "CM-7"]], "Set securityContext.seccompProfile.type: RuntimeDefault at pod level.",
  perContainer((ct, s, c) => { const t = effSC(ct, s, "seccompProfile.type"); const ann = get(c.p, "metadata.annotations") || {}; return t || Object.keys(ann).some((k) => /seccomp/.test(k)) ? [] : [c.H("no seccompProfile", null, "likely")]; }));
rule("K8S-029", "medium", "kubernetes", isWorkload, "Seccomp profile is Unconfined",
  [[CK, "5.7.2"], [N, "CM-7"], [M, "T1611"]], "Use seccompProfile.type: RuntimeDefault or a Localhost profile.",
  perContainer((ct, s, c) => (lc(effSC(ct, s, "seccompProfile.type")) === "unconfined" ? [c.H("seccompProfile Unconfined" + UNCONFINED_NOTE, "type")] : [])));
rule("K8S-030", "low", "kubernetes", isWorkload, "Container root filesystem is writable",
  [[CK, "section 5.7 (General Policies)"], [N, "CM-7"], [N, "SI-7"]], "Set securityContext.readOnlyRootFilesystem: true and mount emptyDir where writes are needed.",
  perContainer((ct, s, c) => (isTrue(get(ct, "securityContext.readOnlyRootFilesystem")) ? [] : [c.H("readOnlyRootFilesystem not true", null, "likely")]), ["containers"]));
rule("K8S-031", "medium", "kubernetes", isWorkload, "Container binds a hostPort",
  [[CK, "5.2.13"], [N, "SC-7"]], "Remove hostPort and expose the workload through a Service.",
  perContainer((ct, s, c) => arr(ct.ports).filter((p) => p && p.hostPort != null && num(p.hostPort) !== 0).map((p) => c.H("hostPort " + p.hostPort, "hostPort"))));
rule("K8S-032", "medium", "kubernetes", RBAC_ROLES, "RBAC role can read Secrets",
  [[CK, "5.1.2"], [N, "AC-6"], [M, "T1552.007"]], "Restrict get/list/watch on secrets to the components that need them, by resourceNames where possible.",
  (c) => rbacRules(c).filter((r) => (arr(r.resources).includes("secrets") || arr(r.resources).includes("*")) && arr(r.verbs).some((v) => ["get", "list", "watch", "*"].includes(v)) && !arr(r.resourceNames).length).map((r) => c.H("verbs [" + arr(r.verbs).join(", ") + "] on secrets", "resources")));
rule("K8S-033", "high", "kubernetes", RBAC_ROLES, "RBAC role allows escalation verbs or pod exec",
  [[CK, "section 5.1 (RBAC)"], [N, "AC-6"], [M, "T1098"]], "Remove escalate, bind and impersonate verbs and create on pods/exec unless strictly required.",
  (c) => {
    const hits = [];
    for (const r of rbacRules(c)) {
      const v = arr(r.verbs);
      const esc = v.filter((x) => ["escalate", "bind", "impersonate"].includes(x));
      if (esc.length) hits.push(c.H("verbs " + esc.join(", ") + " on " + arr(r.resources).join(", "), "verbs"));
      if (arr(r.resources).some((x) => x === "pods/exec" || x === "pods/attach") && v.some((x) => x === "create" || x === "*")) hits.push(c.H("create on pods/exec", "resources"));
    }
    return hits;
  });
rule("K8S-034", "low", "kubernetes", (r) => r.type === "Namespace" || isWorkload(r), "Namespace has no NetworkPolicy in the scanned files",
  [[CK, "5.3.2"], [N, "SC-7"]], "Add a default-deny NetworkPolicy per namespace, then allow required flows.",
  (c) => {
    const ns = c.r.type === "Namespace" ? String(get(c.p, "metadata.name")) : c.r.ns || "default";
    if (c.r.type !== "Namespace" && c.all.some((o) => o.type === "Namespace" && String(get(o.props, "metadata.name")) === ns)) return [];
    if (c.r.type !== "Namespace" && c.all.some((o) => isWorkload(o) && (o.ns || "default") === ns && cmp(o.id + o.file, c.r.id + c.r.file) < 0)) return [];
    return c.all.some((o) => o.type === "NetworkPolicy" && (o.ns || "default") === ns) ? [] : [c.H("no NetworkPolicy for namespace " + ns, null, "review")];
  });
rule("K8S-035", "high", "kubernetes", isWorkload, "Windows HostProcess container",
  [[CK, "5.2.11"], [N, "AC-6"], [M, "T1611"]], "Remove windowsOptions.hostProcess: true unless the workload is a node agent.",
  perContainer((ct, s, c) => (isTrue(effSC(ct, s, "windowsOptions.hostProcess")) ? [c.H("hostProcess: true", "hostProcess")] : [])));
rule("K8S-036", "medium", "kubernetes", isWorkload, "Pod uses the default service account",
  [[CK, "5.1.5"], [N, "AC-6"]], "Create a dedicated ServiceAccount per workload and set serviceAccountName.",
  (c) => { const s = podSpec(c.p); if (!s) return []; const n = s.serviceAccountName || s.serviceAccount; return !n || n === "default" ? [c.H(n ? "serviceAccountName: default" : "no serviceAccountName (uses default)", n ? "serviceAccountName" : null, n ? "confirmed" : "likely")] : []; });
const PROC_FD = /^["']?\/proc\/(self|thread-self|\d+)\/fd(\/|["']?$)/;
const RUNC_NOTE = "; with runc before 1.1.12 a leaked host directory descriptor gives the process the host filesystem (CVE-2024-21626, Leaky Vessels)";
rule("K8S-037", "critical", "kubernetes", isWorkload, "Container workingDir points into /proc/*/fd (runc CVE-2024-21626 escape pattern)",
  [[N, "SI-2"], [N, "SC-39"], [M, "T1611"]], "Never set workingDir under /proc/*/fd; upgrade runc to 1.1.12 or later on every node.",
  perContainer((ct, s, c) => (typeof ct.workingDir === "string" && PROC_FD.test(ct.workingDir.trim()) ? [c.H("workingDir: " + ct.workingDir + RUNC_NOTE, "workingDir")] : [])));

/* ---------------------------- Dockerfile --------------------------------- */

const DF = ["Dockerfile"];
const ins = (c) => c.p.instructions || [];
const lastStage = (c) => { const all = ins(c); const s = all.length ? all[all.length - 1].stage : 0; return all.filter((x) => x.stage === s); };
const insHits = (c, cmd, re, detail) => ins(c).filter((x) => x.cmd === cmd && re.test(x.args)).map((x) => c.H(detail(x), null, "confirmed", null, x.line));
// Piece-wise instead of one regex: `\b(curl|wget)\b[^|;&]*\|` retried from every curl
// in a long RUN line was quadratic (a 140 KB line took seconds).
const PIPE_TO = /^\s*(sudo\s+)?((-?\w*\/)?(ba|z|da|k)?sh|python\d?|perl|ruby|node)\b/i;
const PIPE_SH = { test: (v) => {
  const s = String(v);
  if (/\b(ba)?sh\s+-c\s+["']?\$\((curl|wget)\b|\bsh\s+<\(\s*(curl|wget)/i.test(s)) return true;
  const parts = s.split(/([|;&])/);
  for (let i = 0; i + 2 < parts.length; i += 2) if (parts[i + 1] === "|" && /\b(curl|wget)\b/i.test(parts[i]) && PIPE_TO.test(parts[i + 2])) return true;
  return false;
} };

// "<tool> ... <flag>" within one command, tested per command (one regex was quadratic on long RUN lines).
const after = (p, tool, flag) => { const i = p.search(tool); return i >= 0 && flag.test(p.slice(i)); };
const TLS_OFF = { test: (v) => String(v).split(/[;&|]/).some((p) => after(p, /\bcurl\b/, /\s(-k|--insecure)\b/) || after(p, /\bwget\b/, /--no-check-certificate/) || after(p, /\bapk\b/, /--allow-untrusted/) || after(p, /\bpip3?\b/, /--trusted-host/))
  || /--allow-unauthenticated|npm\s+config\s+set\s+strict-ssl\s+false|GIT_SSL_NO_VERIFY/.test(String(v)) };

rule("DKR-001", "medium", "docker", DF, "Image has no USER instruction (runs as root)",
  [[CD, "4.1"], [N, "AC-6"], [M, "T1611"]], "Create an unprivileged user and add USER <name> in the final stage.",
  (c) => (lastStage(c).some((x) => x.cmd === "USER") ? [] : [c.H("final stage has no USER", null, "likely", null, lastStage(c)[0] ? lastStage(c)[0].line : 1)]));
rule("DKR-002", "high", "docker", DF, "Final USER is root",
  [[CD, "4.1"], [N, "AC-6"], [M, "T1611"]], "End the final stage with USER set to a non-root user.",
  (c) => { const u = lastStage(c).filter((x) => x.cmd === "USER").pop(); return u && /^(root|0)(:|$)/.test(u.args.trim()) ? [c.H("USER " + u.args, null, "confirmed", null, u.line)] : []; });
rule("DKR-003", "low", "docker", DF, "ADD used instead of COPY",
  [[CD, "4.9"], [N, "CM-7"]], "Use COPY for local files; fetch remote content in a RUN step with checksum verification.",
  (c) => ins(c).filter((x) => x.cmd === "ADD" && !/^(--[\w-]+(=\S+)?\s+)*(?![a-z][\w+.-]*:\/\/)\S+\.(tar|tar\.gz|tgz|tar\.bz2|tar\.xz)\s/i.test(x.args + " ")).map((x) => c.H("ADD " + x.args, null, /https?:\/\//.test(x.args) ? "confirmed" : "likely", null, x.line)));
rule("DKR-004", "high", "docker", DF, "Remote script piped into a shell",
  [[CS, "section 3 (Dependencies)"], [N, "SR-3"], [N, "SI-7"], [M, "T1059.004"]], "Download to a file, verify a pinned checksum or signature, then execute; better, use a package manager.",
  (c) => insHits(c, "RUN", PIPE_SH, (x) => "RUN " + x.args));
rule("DKR-005", "info", "docker", DF, "apt-get install without --no-install-recommends",
  [[CD, "4.3"], [N, "CM-7"]], "Add --no-install-recommends to keep the attack surface and image small.",
  (c) => insHits(c, "RUN", /apt-get\s+(-\S+\s+)*install\b(?![^&;|]*--no-install-recommends)/, (x) => "RUN " + x.args));
const STAGES = (c) => new Set(ins(c).filter((x) => x.cmd === "FROM").map((x) => (/\bAS\s+(\S+)/i.exec(x.args) || [])[1]).filter(Boolean).map(lc));
const fromImage = (x) => x.args.replace(/^(--[\w-]+=\S+\s+)+/, "").split(/\s+/)[0];
rule("DKR-006", "medium", "docker", DF, "Base image uses :latest or no tag",
  [[CD, "4.2"], [N, "CM-2"], [N, "SI-7"], [M, "T1525"]], "Pin FROM to a version tag and @sha256 digest.",
  (c) => { const st = STAGES(c); return ins(c).filter((x) => x.cmd === "FROM").filter((x) => { const im = fromImage(x); if (lc(im) === "scratch" || st.has(lc(im)) || dynImage(im)) return false; const p = parseImage(im); return !p.digest && (!p.tag || lc(p.tag) === "latest"); }).map((x) => c.H("FROM " + fromImage(x), null, "confirmed", null, x.line)); });
rule("DKR-007", "info", "docker", DF, "Base image is not pinned by digest",
  [[CD, "4.2"], [N, "SI-7"], [M, "T1525"]], "Append @sha256:<digest> to FROM so rebuilds use identical bytes.",
  (c) => { const st = STAGES(c); return ins(c).filter((x) => x.cmd === "FROM").filter((x) => { const im = fromImage(x); if (lc(im) === "scratch" || st.has(lc(im)) || dynImage(im)) return false; const p = parseImage(im); return !p.digest && p.tag && lc(p.tag) !== "latest"; }).map((x) => c.H("FROM " + fromImage(x), null, "confirmed", null, x.line)); });
function kvArgs(x) {
  const out = [];
  if (x.cmd === "ARG") { const m = /^([A-Za-z_][\w]*)(?:=(.*))?$/.exec(x.args.trim()); if (m && m[2] != null) out.push([m[1], m[2].replace(/^["']|["']$/g, "")]); return out; }
  const s = x.args.trim();
  if (/^[A-Za-z_][\w]*\s+[^=]*$/.test(s) && !s.includes("=")) { const i = s.search(/\s/); out.push([s.slice(0, i), s.slice(i + 1).trim().replace(/^["']|["']$/g, "")]); return out; }
  const re = /([A-Za-z_][\w]*)=("(?:[^"\\]|\\.)*"|'[^']*'|\S+)/g; let m;
  while ((m = re.exec(s))) out.push([m[1], m[2].replace(/^["']|["']$/g, "")]);
  return out;
}
rule("DKR-008", "high", "docker", DF, "Secret value baked into ENV or ARG",
  [[CD, "4.10"], [N, "IA-5"], [M, "T1552.001"]], "Pass secrets at build time with RUN --mount=type=secret and at runtime through a secret store; ENV/ARG values are visible in image history.",
  (c) => { const hits = []; for (const x of ins(c)) if (x.cmd === "ENV" || x.cmd === "ARG") for (const h of secretEnvHits(c, kvArgs(x))) { h.line = x.line; h.detail = x.cmd + " " + h.detail.replace(/^environment variable /, ""); hits.push(h); } return hits; });
rule("DKR-009", "medium", "docker", DF, "Image exposes SSH (port 22)",
  [[CD, "section 4 (Container Images and Build File)"], [N, "CM-7"], [M, "T1021.004"]], "Do not run sshd in containers; use kubectl exec / docker exec for access.",
  (c) => insHits(c, "EXPOSE", /(^|\s)22(\/tcp)?(\s|$)/, (x) => "EXPOSE " + x.args));
rule("DKR-010", "info", "docker", DF, "No HEALTHCHECK instruction",
  [[CD, "4.6"], [N, "SI-6"]], "Add a HEALTHCHECK (or rely on orchestrator probes and note that here).",
  (c) => (ins(c).some((x) => x.cmd === "HEALTHCHECK" && !/^none$/i.test(x.args)) ? [] : [c.H("no HEALTHCHECK", null, "confirmed", null, 1)]));
rule("DKR-011", "medium", "docker", DF, "World-writable permissions (chmod 777)",
  [[N, "AC-3"], [N, "CM-6"]], "Grant the minimum permissions needed, owned by the runtime user.",
  (c) => insHits(c, "RUN", /\bchmod\s+(-\S+\s+)*(0?777|a\+rwx|ugo\+rwx)\b/, (x) => "RUN " + x.args));
rule("DKR-012", "medium", "docker", DF, "sudo installed or used in the image",
  [[N, "AC-6"], [M, "T1548.003"]], "Do not install sudo; run privileged steps before USER and drop to the runtime user.",
  (c) => insHits(c, "RUN", /(\b(apt-get|apt|apk|yum|dnf|microdnf|zypper)\b[^;&|]*\b(install|add)\b[^;&|]*\bsudo\b)|(^|[;&|]\s*)sudo\s/, (x) => "RUN " + x.args));
rule("DKR-013", "low", "docker", DF, "apt-get update in its own RUN layer",
  [[CD, "4.7"], [N, "SI-2"]], "Combine apt-get update and install in one RUN so cached stale indexes are not reused.",
  (c) => insHits(c, "RUN", /^(?!.*\binstall\b).*\bapt(-get)?\s+update\b/, (x) => "RUN " + x.args));
rule("DKR-014", "medium", "docker", DF, "TLS or signature verification disabled during build",
  [[N, "SI-7"], [N, "SC-8"], [M, "T1195.002"]], "Remove --insecure / -k / --no-check-certificate / --allow-untrusted / --trusted-host and fix the trust store instead.",
  (c) => insHits(c, "RUN", TLS_OFF, (x) => "RUN " + x.args));
const exposed = (x) => x.args.split(/\s+/).map((t) => /^(\d+)(?:-(\d+))?(?:\/(?:tcp|udp|sctp))?$/i.exec(t)).filter(Boolean).map((m) => ({ from: Number(m[1]), to: Number(m[2] || m[1]) }));
const exposeHits = (ports) => (c) => ins(c).filter((x) => x.cmd === "EXPOSE").flatMap((x) => {
  const names = [...new Set(exposed(x).flatMap((e) => Object.keys(ports).filter((p) => e.from <= Number(p) && Number(p) <= e.to).map((p) => p + " " + ports[p])))];
  return names.length ? [c.H("EXPOSE " + x.args + " (" + names.join(", ") + ")", null, "confirmed", null, x.line)] : [];
});
rule("DKR-015", "low", "docker", DF, "Image exposes a database port",
  [[CD, "5.8"], [N, "CM-7"], [N, "SC-7"], [M, "T1190"]], "Expose only the ports the service needs; run databases as their own service and reach them over a private network. EXPOSE also publishes the port under docker run -P.",
  exposeHits(DB_PORTS));
const ADMIN_PORTS = { 23: "Telnet", 2375: "Docker API (plaintext)", 2376: "Docker API (TLS)", 3389: "RDP", 10250: "kubelet API" };
rule("DKR-016", "medium", "docker", DF, "Image exposes a remote-admin or container control-plane port",
  [[CD, "5.8"], [N, "CM-7"], [M, "T1021"]], "Remove the EXPOSE; administer containers with docker exec / kubectl exec and never publish the Docker or kubelet API from an image.",
  exposeHits(ADMIN_PORTS));
const cacheMount = (x) => /--mount=[^\s]*type=cache/.test(x.args);
const PIP_INSTALL = /\bpip(3(\.\d+)?)?\s+(-\S+\s+)*install\b|\bpython(3(\.\d+)?)?\s+-m\s+pip\s+(-\S+\s+)*install\b/;
rule("DKR-017", "info", "docker", DF, "pip install without --no-cache-dir in the final image",
  [[N, "CM-7"]], "Add --no-cache-dir (or ENV PIP_NO_CACHE_DIR=1) so downloaded wheels are not kept in the image layer.",
  (c) => (ins(c).some((x) => (x.cmd === "ENV" || x.cmd === "ARG") && /\bPIP_NO_CACHE_DIR\b/.test(x.args)) ? [] : lastStage(c).filter((x) => x.cmd === "RUN" && PIP_INSTALL.test(x.args) && !/--no-cache-dir\b/.test(x.args) && !cacheMount(x)).map((x) => c.H("RUN " + x.args, null, "confirmed", null, x.line))));
rule("DKR-018", "info", "docker", DF, "apt package lists not removed in the same layer",
  [[N, "CM-7"]], "End the RUN that installs packages with rm -rf /var/lib/apt/lists/*; a later RUN cannot shrink an earlier layer.",
  (c) => lastStage(c).filter((x) => x.cmd === "RUN" && /\bapt(-get)?\s+(-\S+\s+)*install\b/.test(x.args) && !/\brm\s+(-\S+\s+)*\/var\/lib\/apt\/lists/.test(x.args) && !cacheMount(x)).map((x) => c.H("RUN " + x.args, null, "confirmed", null, x.line)));
const copySources = (x) => { if (/(^|\s)--from=/.test(x.args)) return []; const rest = x.args.replace(/^(--[\w-]+(=\S+)?\s+)+/, "").trim(); let toks; if (rest.startsWith("[")) { try { toks = JSON.parse(rest); } catch (_) { return []; } } else toks = rest.split(/\s+/); return Array.isArray(toks) ? toks.slice(0, -1).map(String) : []; };
rule("DKR-019", "low", "docker", DF, "COPY copies the whole build context",
  [[N, "CM-7"], [M, "T1552.001"]], "Copy only the paths the image needs and keep a .dockerignore that excludes .git, .env files and credentials.",
  (c) => ins(c).filter((x) => x.cmd === "COPY" && copySources(x).some((s) => s === "." || s === "./")).map((x) => c.H("COPY " + x.args, null, "likely", null, x.line)));
const BUILD_STEP = /\b(go\s+build|cargo\s+build|mvnw?\s|gradlew?\s|dotnet\s+(build|publish)|(npm|yarn|pnpm)\s+(run\s+)?build\b|cmake\s|g?cc\s|g\+\+\s|make(\s|$))|\bbuild-essential\b/;
rule("DKR-020", "info", "docker", DF, "Single-stage build ships the build toolchain",
  [[N, "CM-7"]], "Compile in a builder stage and COPY --from only the artifacts into a minimal runtime image.",
  (c) => { if (ins(c).filter((x) => x.cmd === "FROM").length !== 1) return []; const b = ins(c).find((x) => x.cmd === "RUN" && BUILD_STEP.test(x.args)); return b ? [c.H("one FROM and a build step: RUN " + b.args, null, "likely", null, b.line)] : []; });
rule("DKR-021", "critical", "docker", DF, "WORKDIR points into /proc/*/fd (runc CVE-2024-21626 escape pattern)",
  [[N, "SI-2"], [N, "SC-39"], [M, "T1611"]], "Never set WORKDIR under /proc/*/fd; build and run only on runc 1.1.12 or later, and treat any image containing this as hostile.",
  (c) => insHits(c, "WORKDIR", PROC_FD, (x) => "WORKDIR " + x.args + RUNC_NOTE));

/* ---------------------------- docker-compose ----------------------------- */

const CMP = ["service"];
const isCompose = (r) => r.format === "compose";
const svcEnv = (p) => { const e = p.environment; if (Array.isArray(e)) return e.map((x) => { const s = String(x); const i = s.indexOf("="); return i > 0 ? [s.slice(0, i), s.slice(i + 1)] : [s, null]; }); if (e && typeof e === "object") return Object.entries(e); return []; };
const vols = (p) => arr(p.volumes).map((v) => (typeof v === "string" ? { src: v.split(":")[0], dst: v.split(":")[1] || "", ro: /:ro(,|$)/.test(v), raw: v } : v && typeof v === "object" ? { src: String(v.source || ""), dst: String(v.target || ""), ro: isTrue(v.read_only), raw: (v.source || "") + ":" + (v.target || "") } : null)).filter(Boolean);
rule("CMP-001", "critical", "compose", (r) => isCompose(r), "Service runs privileged",
  [[CD, "5.4"], [N, "AC-6"], [M, "T1611"]], "Remove privileged: true; add only required capabilities.",
  (c) => (isTrue(c.p.privileged) ? [c.H("privileged: true", "privileged")] : []));
rule("CMP-002", "high", "compose", isCompose, "Service uses the host network",
  [[CD, "5.9"], [N, "SC-7"], [M, "T1611"]], "Use a bridge network and publish only required ports.",
  (c) => (lc(c.p.network_mode) === "host" ? [c.H("network_mode: host", "network_mode")] : []));
rule("CMP-003", "high", "compose", isCompose, "Service shares the host PID namespace",
  [[CD, "5.15"], [N, "SC-39"], [M, "T1611"]], "Remove pid: host.",
  (c) => (lc(c.p.pid) === "host" ? [c.H("pid: host", "pid")] : []));
rule("CMP-004", "medium", "compose", isCompose, "Service shares the host IPC namespace",
  [[CD, "5.16"], [N, "SC-39"]], "Remove ipc: host.",
  (c) => (lc(c.p.ipc) === "host" ? [c.H("ipc: host", "ipc")] : []));
rule("CMP-005", "critical", "compose", isCompose, "Service mounts the Docker socket",
  [[CD, "section 5 (Container Runtime)"], [N, "AC-6"], [M, "T1611"], [M, "T1610"]], "Do not mount /var/run/docker.sock; use a socket proxy with an allow-list if the API is truly needed.",
  (c) => vols(c.p).filter((v) => SOCKETS.test(v.src)).map((v) => c.H("volume " + v.raw, "docker.sock")));
rule("CMP-006", "high", "compose", isCompose, "Service adds dangerous capabilities",
  [[CD, "5.3"], [N, "AC-6"], [M, "T1611"]], "Remove cap_add entries such as SYS_ADMIN and ALL; prefer cap_drop: [ALL].",
  (c) => { const bad = arr(c.p.cap_add).map((x) => String(x).toUpperCase().replace(/^CAP_/, "")).filter((x) => DANGEROUS_CAPS.has(x)); return bad.length ? [c.H("cap_add: " + bad.join(", ") + SYS_ADMIN_NOTE(bad), "cap_add")] : []; });
function publishedPorts(p) {
  const out = [];
  for (const x of arr(p.ports)) {
    if (x && typeof x === "object") { out.push({ host: x.host_ip || "", pub: String(x.published || ""), target: String(x.target || ""), raw: JSON.stringify(x) }); continue; }
    const s = String(x).replace(/\/(tcp|udp)$/, "");
    const parts = s.split(":");
    if (parts.length === 1) out.push({ host: "", pub: "", target: parts[0], raw: s });
    else if (parts.length === 2) out.push({ host: "", pub: parts[0], target: parts[1], raw: s });
    else out.push({ host: parts.slice(0, -2).join(":").replace(/^\[|\]$/g, ""), pub: parts[parts.length - 2], target: parts[parts.length - 1], raw: s });
  }
  return out;
}
rule("CMP-007", "medium", "compose", isCompose, "Database port published on all interfaces",
  [[CD, "5.13"], [N, "SC-7"], [M, "T1190"]], "Bind to 127.0.0.1 (\"127.0.0.1:5432:5432\") or drop the published port and use the service network.",
  (c) => publishedPorts(c.p).filter((x) => x.pub && (!x.host || x.host === "0.0.0.0" || x.host === "::") && Object.keys(DB_PORTS).some((p) => rangeCovers(x.target, undefined, Number(p)))).map((x) => c.H("ports " + x.raw + " (" + (DB_PORTS[x.target] || "database") + ")", "ports")));
rule("CMP-008", "high", "compose", isCompose, "Seccomp or AppArmor confinement disabled",
  [[CD, "5.1"], [CD, "5.21"], [N, "CM-7"], [M, "T1611"]], "Remove seccomp:unconfined / apparmor:unconfined from security_opt.",
  (c) => arr(c.p.security_opt).filter((s) => /^(seccomp|apparmor)[:=]unconfined$/i.test(String(s).trim())).map((s) => c.H("security_opt " + s + (/^seccomp/i.test(String(s).trim()) ? UNCONFINED_NOTE : ""), "security_opt")));
rule("CMP-009", "high", "compose", isCompose, "Plaintext credentials in service environment",
  [[N, "IA-5"], [M, "T1552.001"]], "Use Compose secrets or an env_file kept out of version control; reference ${VARIABLES} instead of literals.",
  (c) => secretEnvHits(c, svcEnv(c.p).filter(([, v]) => v != null)));
rule("CMP-010", "medium", "compose", isCompose, "Service image uses :latest or no tag",
  [[CD, "4.2"], [N, "CM-2"], [M, "T1525"]], "Pin the image to a version tag and digest.",
  (c) => { const im = c.p.image; if (typeof im !== "string" || dynImage(im)) return []; const p = parseImage(im); return !p.digest && (!p.tag || lc(p.tag) === "latest") ? [c.H("image " + im, "image")] : []; });
const SENSITIVE_HOST = /^(\/|\/etc(\/.*)?|\/proc(\/.*)?|\/sys(\/.*)?|\/boot|\/root(\/.*)?|\/var\/run|\/run|\/dev|\/home|\/var\/lib\/docker(\/.*)?|\/var\/lib\/kubelet(\/.*)?)$/;
rule("CMP-011", "high", "compose", isCompose, "Sensitive host path mounted read-write",
  [[CD, "5.5"], [N, "AC-6"], [M, "T1611"]], "Avoid mounting host system directories; if required, mount read-only (:ro).",
  (c) => vols(c.p).filter((v) => !v.ro && SENSITIVE_HOST.test(v.src.replace(/\/$/, "") || "/") && v.src.startsWith("/") && !SOCKETS.test(v.src)).map((v) => c.H("volume " + v.raw, "volumes")));
rule("CMP-012", "medium", "compose", isCompose, "Service runs as root",
  [[CD, "section 5 (Container Runtime)"], [N, "AC-6"]], "Set user to a non-root UID:GID.",
  (c) => (/^(root|0)(:|$)/.test(String(c.p.user || "")) ? [c.H("user: " + c.p.user, "user")] : []));
rule("CMP-013", "info", "compose", isCompose, "no-new-privileges is not set",
  [[CD, "5.25"], [N, "AC-6"]], "Add security_opt: [\"no-new-privileges:true\"].",
  (c) => (arr(c.p.security_opt).some((s) => /^no-new-privileges(:true)?$/i.test(String(s).trim())) ? [] : [c.H("no-new-privileges not set", null, "likely")]));

/* ---------------------------- GitHub Actions ----------------------------- */

const GHA = ["workflow"];
const onEvents = (p) => { const on = p.on; if (typeof on === "string") return [on]; if (Array.isArray(on)) return on.map(String); if (on && typeof on === "object") return Object.keys(on); return []; };
const jobs = (p) => Object.entries(p.jobs || {}).filter(([, j]) => j && typeof j === "object").sort((a, b) => cmp(a[0], b[0]));
const steps = (p) => { const out = []; for (const [id, j] of jobs(p)) arr(j.steps).forEach((s, i) => { if (s && typeof s === "object") out.push({ job: id, i, s }); }); return out; };
const stepRe = (s) => (s.uses ? new RegExp("uses\\s*:\\s*[\"']?" + reEsc(String(s.uses))) : s.run ? new RegExp("run\\s*:") : null);
/** Line of a step's uses:/run: (nth occurrence of the same text). */
function stepLine(c, st) {
  const lines = c.lines; const re = stepRe(st.s); if (!re) return 0;
  const same = steps(c.p).filter((x) => x.s.uses === st.s.uses && !!x.s.run === !!st.s.run);
  let n = same.findIndex((x) => x === st || (x.job === st.job && x.i === st.i)); if (n < 0) n = 0;
  if (st.s.name && !st.s.uses) { const l = findLine(lines, new RegExp("name\\s*:\\s*[\"']?" + reEsc(String(st.s.name)))); if (l) return findLine(lines, /run\s*:/, l - 1) || l; }
  let k = -1; for (let i = 0; i < lines.length; i++) if (re.test(lines[i]) && ++k === n) return i + 1;
  return 0;
}
const SHA40 = /^[0-9a-f]{40}$/i;
const PR_HEAD = /github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs\/pull\/.*\/(head|merge)|github\.event\.workflow_run\.head_(sha|branch)/;
rule("GHA-001", "critical", "github-actions", GHA, "pull_request_target checks out untrusted PR code",
  [[CS, "section 2 (Build Pipelines)"], [N, "SR-3"], [N, "CM-5"], [M, "T1195.002"]], "Use pull_request for untrusted code; if pull_request_target is required, never check out or run the PR head with secrets in scope.",
  (c) => {
    const ev = onEvents(c.p);
    if (!ev.includes("pull_request_target") && !ev.includes("workflow_run")) return [];
    return steps(c.p).filter(({ s }) => (/^actions\/checkout@/i.test(String(s.uses || "")) && PR_HEAD.test(JSON.stringify(s.with || {}))) || (s.run && /(gh\s+pr\s+checkout|git\s+(fetch|checkout)[^\n]*(pull\/|\$\{\{\s*github\.(event\.pull_request\.head|head_ref)))/.test(String(s.run)))).map((st) => c.H("job " + st.job + " checks out the PR head under " + (ev.includes("pull_request_target") ? "pull_request_target" : "workflow_run"), null, "confirmed", null, stepLine(c, st)));
  });
rule("GHA-002", "low", "github-actions", GHA, "Workflow runs on pull_request_target",
  [[CS, "section 2 (Build Pipelines)"], [N, "CM-5"]], "Confirm the workflow never executes code from the fork; it runs with the base repository's secrets and write token.",
  (c) => (onEvents(c.p).includes("pull_request_target") ? [c.H("on: pull_request_target", "pull_request_target")] : []));
const actionRef = (u) => { const s = typeof u === "string" ? u.trim() : ""; if (!s || s.startsWith("./") || s.startsWith("docker://")) return null; const at = s.lastIndexOf("@"); return at < 0 ? { owner: s.split("/")[0], ref: "" } : { owner: s.slice(0, s.indexOf("/")), ref: s.slice(at + 1) }; };
const unpinned = (gh) => (c) => {
  const items = steps(c.p).map((st) => ({ uses: st.s.uses, st })).concat(jobs(c.p).filter(([, j]) => j.uses).map(([job, j]) => ({ uses: j.uses, st: { job, i: -1, s: { uses: j.uses } } })));
  return items.filter((x) => { const r = actionRef(x.uses); if (!r || SHA40.test(r.ref)) return false; const own = ["actions", "github"].includes(lc(r.owner)); return gh ? own : !own; })
    .map((x) => c.H("uses " + x.uses + " (job " + x.st.job + ")", null, "confirmed", null, stepLine(c, x.st)));
};
rule("GHA-003", "medium", "github-actions", GHA, "Third-party action not pinned to a commit SHA",
  [[CS, "section 2 (Build Pipelines)"], [N, "SR-3"], [N, "SI-7"], [M, "T1195.002"]], "Pin to the full 40-character commit SHA (keep the version in a comment) and update with Dependabot.",
  unpinned(false));
rule("GHA-004", "low", "github-actions", GHA, "GitHub-owned action not pinned to a commit SHA",
  [[CS, "section 2 (Build Pipelines)"], [N, "SR-3"]], "Pin actions/* and github/* actions to a full commit SHA as well.",
  unpinned(true));
rule("GHA-005", "high", "github-actions", GHA, "Workflow token has write-all permissions",
  [[CS, "section 2 (Build Pipelines)"], [N, "AC-6"]], "Declare least-privilege permissions (for example contents: read) at workflow and job level.",
  (c) => { const hits = []; if (lc(c.p.permissions) === "write-all") hits.push(c.H("permissions: write-all (workflow)", "permissions")); for (const [id, j] of jobs(c.p)) if (lc(j.permissions) === "write-all") hits.push(c.H("permissions: write-all (job " + id + ")", "permissions")); return hits; });
rule("GHA-006", "medium", "github-actions", GHA, "No top-level permissions block",
  [[CS, "section 2 (Build Pipelines)"], [N, "AC-6"]], "Add permissions: { contents: read } at the top so jobs do not inherit the repository default token scope.",
  (c) => { if (c.p.permissions !== undefined) return []; const j = jobs(c.p); if (j.length && j.every(([, x]) => x.permissions !== undefined || x.uses)) return []; return [c.H("permissions not declared; jobs get the repository default token permissions", null, "likely", null, 1)]; });
const UNTRUSTED_CTX = /github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|pages\.[^}]*\.page_name|commits\.[^}]*\.(message|author\.(email|name))|head_commit\.(message|author\.(email|name)|committer\.(email|name))|workflow_run\.(head_branch|head_commit\.(message|author\.(email|name))|display_title)|discussion\.(title|body)|release\.(name|body))|github\.head_ref/;
rule("GHA-007", "high", "github-actions", GHA, "Untrusted event data interpolated into a run script",
  [[CS, "section 2 (Build Pipelines)"], [N, "SI-10"], [M, "T1059.004"]], "Pass the value through env: (for example TITLE: ${{ github.event.issue.title }}) and reference \"$TITLE\" in the script.",
  (c) => {
    const hits = [];
    for (const st of steps(c.p)) {
      if (typeof st.s.run !== "string" && !/actions\/github-script@/.test(String(st.s.uses || ""))) continue;
      const body = typeof st.s.run === "string" ? st.s.run : String(get(st.s, "with.script") || "");
      const exprs = body.match(/\$\{\{[^}]*\}\}/g) || [];
      const bad = exprs.filter((e) => UNTRUSTED_CTX.test(e)), maybe = exprs.filter((e) => /github\.event\./.test(e) && !UNTRUSTED_CTX.test(e) && !/\.(number|id|sha|action)\s*\}\}|\.(number|id)\b/.test(e));
      if (bad.length) hits.push(c.H("job " + st.job + ": " + [...new Set(bad)].join(", "), null, "confirmed", null, stepLine(c, st)));
      else if (maybe.length) hits.push(c.H("job " + st.job + ": " + [...new Set(maybe)].join(", "), null, "review", null, stepLine(c, st)));
    }
    return hits;
  });
rule("GHA-008", "high", "github-actions", GHA, "Secret written to the log",
  [[CS, "section 2 (Build Pipelines)"], [N, "IA-5"], [M, "T1552"]], "Never echo secrets; GitHub masking is best-effort and transformed values are not masked.",
  (c) => steps(c.p).filter(({ s }) => typeof s.run === "string" && /(^|[;&|\n]\s*)(echo|printf|cat\s*<<)[^\n]*\$\{\{\s*secrets\./.test(s.run)).map((st) => c.H("job " + st.job + " prints a secrets.* expression", null, "confirmed", null, stepLine(c, st))));
rule("GHA-009", "medium", "github-actions", GHA, "Checkout persists credentials on pull_request_target",
  [[CS, "section 2 (Build Pipelines)"], [N, "AC-6"], [M, "T1528"]], "Set with: persist-credentials: false on actions/checkout.",
  (c) => (onEvents(c.p).includes("pull_request_target") ? steps(c.p).filter(({ s }) => /^actions\/checkout@/i.test(String(s.uses || "")) && !isFalse(get(s, "with.persist-credentials"))).map((st) => c.H("job " + st.job + " checkout keeps the token in .git/config", null, "confirmed", null, stepLine(c, st))) : []));
rule("GHA-010", "info", "github-actions", GHA, "Job runs on a self-hosted runner",
  [[CS, "section 2 (Build Pipelines)"], [N, "SC-39"]], "Do not use self-hosted runners for public repositories; use ephemeral, isolated runners otherwise.",
  (c) => jobs(c.p).filter(([, j]) => JSON.stringify(j["runs-on"] || "").includes("self-hosted")).map(([id]) => c.H("job " + id + " runs-on self-hosted", "runs-on")));
rule("GHA-011", "medium", "github-actions", GHA, "Remote script piped into a shell in a workflow",
  [[CS, "section 3 (Dependencies)"], [N, "SR-3"], [M, "T1059.004"]], "Download, verify a checksum or signature, then run; or use a pinned action.",
  (c) => steps(c.p).filter(({ s }) => typeof s.run === "string" && PIPE_SH.test(s.run)).map((st) => c.H("job " + st.job + " pipes curl/wget into a shell", null, "confirmed", null, stepLine(c, st))));
rule("GHA-012", "high", "github-actions", GHA, "ACTIONS_ALLOW_UNSECURE_COMMANDS enabled",
  [[CS, "section 2 (Build Pipelines)"], [N, "SI-10"]], "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS; use $GITHUB_ENV and $GITHUB_PATH files.",
  (c) => { const envs = [c.p.env, ...jobs(c.p).map(([, j]) => j.env), ...steps(c.p).map(({ s }) => s.env)]; return envs.some((e) => e && isTrue(e.ACTIONS_ALLOW_UNSECURE_COMMANDS)) ? [c.H("ACTIONS_ALLOW_UNSECURE_COMMANDS: true", "ACTIONS_ALLOW_UNSECURE_COMMANDS")] : []; });
rule("GHA-013", "low", "github-actions", GHA, "Reusable workflow inherits all secrets",
  [[CS, "section 2 (Build Pipelines)"], [N, "AC-6"]], "Pass only the named secrets the called workflow needs.",
  (c) => jobs(c.p).filter(([, j]) => j.uses && lc(j.secrets) === "inherit").map(([id]) => c.H("job " + id + " secrets: inherit", "secrets")));

/* ---------------------------- Secrets (all text) ------------------------- */

// What each secret looks like comes from the shared catalogue (core/secret-detectors.js);
// these entries keep the IaC scanner's own rule ids, severities and titles.
export const SECRET_PATTERNS = [
  { id: "SEC-001", severity: "critical", title: "AWS access key id in file", detectors: ["aws-key"] },
  { id: "SEC-002", severity: "critical", title: "Private key in file", detectors: ["private-key"] },
  { id: "SEC-003", severity: "critical", title: "GitHub token in file", detectors: ["github-token", "github-pat-fine"] },
  { id: "SEC-004", severity: "high", title: "Slack token in file", detectors: ["slack-token"] },
  { id: "SEC-005", severity: "high", title: "Google API key in file", detectors: ["gcp-key"] },
  { id: "SEC-006", severity: "medium", title: "Hard-coded password or secret assignment", detectors: ["pat-assignment", "config-assignment"], generic: true },
  { id: "SEC-007", severity: "critical", title: "AWS secret access key in file", detectors: ["aws-secret"] },
  { id: "SEC-008", severity: "critical", title: "Stripe live secret key in file", detectors: ["stripe-key"] },
  { id: "SEC-009", severity: "medium", title: "Slack incoming webhook URL in file", detectors: ["slack-webhook"] },
  { id: "SEC-010", severity: "critical", title: "Azure storage account key in file", detectors: ["azure-storage-key"] },
  { id: "SEC-011", severity: "critical", title: "API token or key in file", detectors: ["openai-key", "anthropic-key", "gitlab-pat", "npm-token", "pypi-token", "huggingface-token", "sendgrid-key", "twilio-api-key", "digitalocean-token", "planetscale-token", "shopify-token", "google-oauth"] },
  { id: "SEC-012", severity: "high", title: "Database URL with an inline password", detectors: ["conn-string"] },
];
for (const sp of SECRET_PATTERNS) {
  RULE_LIST.push({ id: sp.id, title: sp.title, severity: sp.severity, kind: "secrets",
    frameworks: fw([[N, "IA-5"], [N, "SC-28"], [M, "T1552.001"], ...(sp.generic ? [] : [[CS, "section 1 (Source Code)"]])]),
    recommendation: "Remove the value from the file and from git history, rotate it at the issuer, and load it from a secret store at deploy or run time.",
    applies: () => false, check: () => [], secret: sp });
}

/** Scan raw text for secret patterns -> [{ruleId, line, value, masked, snippet}] */
// YAML file kinds, where an unquoted `password: value` is a literal string.
const UNQUOTED_KINDS = new Set(["yaml", "helm-values", "kubernetes", "compose", "github-actions", "cloudformation"]);
export function scanSecrets(text, kind = "") {
  const out = [];
  const lines = splitLines(text);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;
    for (const sp of SECRET_PATTERNS) {
      for (const h of sp.detectors.flatMap((id) => id === "config-assignment" && !UNQUOTED_KINDS.has(kind) ? [] : findAll(detector(id), l))) {
        const m = h.m, val = h.value;
        if (sp.generic) {
          if (NOT_SECRET_KEY_RE.test(m[1]) || !isLiteralSecret(val) || AKIA_RE.test(val) || /^(?:sha256|sha1|md5):|^[a-z]+(\.[a-z]+)+$/i.test(val)) continue;
        }
        const masked = sp.id === "SEC-002" ? val : mask(val);
        out.push({ ruleId: sp.id, line: i + 1, value: val, masked, snippet: (l.split(val).join(masked)).trim().slice(0, 220) });
      }
    }
  }
  return out;
}

export const RULES = RULE_LIST;
/* ------------------------------------------------------------------------ */
/* Analysis                                                                  */
/* ------------------------------------------------------------------------ */

const CONF_RANK = { confirmed: 0, likely: 1, review: 2 };
const PLATFORM_LABEL = { aws: "AWS", azure: "Azure", gcp: "Google Cloud", kubernetes: "Kubernetes", docker: "Dockerfile", compose: "Docker Compose", "github-actions": "GitHub Actions", secrets: "Secrets", terraform: "Terraform (other)", cloudformation: "CloudFormation (other)" };
export { PLATFORM_LABEL };

/** Mask known secret values and anything the secret patterns match in a snippet. */
function redact(s, extra = []) {
  let out = String(s || "");
  for (const v of extra) out = out.split(v).join(mask(v));
  for (const h of scanSecrets(out)) if (h.ruleId !== "SEC-002") out = out.split(h.value).join(h.masked);
  return out;
}

function locate(r, hit, lines) {
  if (hit.line) return hit.line;
  const from = Math.max(0, r.line - 1), to = Math.min(lines.length, Math.max(r.endLine || r.line, r.line));
  let start = from;
  if (hit.after) { const a = findLine(lines, hit.after, from, to); if (a) start = a - 1; }
  if (hit.key) {
    const k = reEsc(String(hit.key));
    const l = findLine(lines, new RegExp("(^|[\\s\"'{,\\-])[\"']?" + k + "[\"']?\\s*[:=]"), start, to) || findLine(lines, new RegExp(k), start, to);
    if (l) return l;
  }
  return start > from ? start + 1 : r.line || 1;
}

/**
 * Analyze IaC files. dataset: the parseInput() result, or raw [{name, text}] files.
 * opts: { ignoreRules: [ids], minSeverity: "info".."critical", maxEvidence }.
 * Returns { summary, findings, tables: { files, resources, rules }, skipped, meta }.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  const parsed = dataset && dataset.format === "iac" && Array.isArray(dataset.files) ? dataset : parseInput(dataset || [], o);
  const files = parsed.files, all = parsed.rows;
  const ignore = new Set(arr(o.ignoreRules).map(String));
  const minRank = SEV_RANK[o.minSeverity] != null ? SEV_RANK[o.minSeverity] : 4;
  const maxEv = Math.max(1, Number(o.maxEvidence) || 50);
  const skipped = [];
  const linesOf = new Map(files.map((f) => [f.name, splitLines(f.text)]));
  const ruleStat = new Map(RULE_LIST.map((r) => [r.id, { hits: 0, unresolved: 0, unresolvedOn: new Set(), skipReasons: new Set() }]));
  const raw = []; // { rule, r, hits }
  const n = all.length;
  const active = RULE_LIST.filter((rl) => !rl.secret && !ignore.has(rl.id));

  for (let i = 0; i < n; i++) {
    if (i % 200 === 0) ctx?.progress?.(i, n + files.length, "rules");
    const r = all[i];
    if (r.mode !== "managed" && r.mode !== "data") continue;
    const lines = linesOf.get(r.file) || [];
    const c = {
      r, p: r.props || {}, cfn: isCfnRes(r), all, lines,
      H: (detail, key = null, conf = "confirmed", after = null, line = 0) => ({ detail, key, conf, after, line }),
      D: (key = null, detail = "") => ({ dyn: true, key, detail }),
      S: (reason) => ({ skip: reason }),
    };
    for (const rl of active) {
      if (!rl.applies(r)) continue;
      let hits;
      try { hits = rl.check(c) || []; } catch (e) { skipped.push({ check: rl.id, reason: "rule error on " + r.id + " in " + r.file + ": " + ((e && e.message) || e) }); continue; }
      const st = ruleStat.get(rl.id);
      const real = [];
      for (const h of hits) {
        if (!h) continue;
        if (h.skip) { st.skipReasons.add(h.skip); continue; }
        if (h.dyn) { st.unresolved++; st.unresolvedOn.add(r.id); continue; }
        real.push(h);
      }
      if (real.length) raw.push({ rule: rl, r, hits: real });
    }
  }

  // Build findings from rule hits
  const findings = [];
  const cited = new Set();
  for (const { rule: rl, r, hits } of raw) {
    const lines = linesOf.get(r.file) || [];
    const secrets = hits.map((h) => h.secret).filter((x) => typeof x === "string" && x.length >= 4);
    const ev = hits.map((h) => { const line = locate(r, h, lines); return { file: r.file, line, snippet: redact(snippetAt(lines, line), secrets), detail: h.detail }; });
    ev.sort((a, b) => a.line - b.line || cmp(a.detail, b.detail));
    for (const e of ev) cited.add(r.file + ":" + e.line);
    const conf = hits.map((h) => h.conf || "confirmed").sort((a, b) => CONF_RANK[a] - CONF_RANK[b])[0];
    findings.push(makeFinding(rl, r, ev, conf, maxEv));
  }

  // Secrets sweep over every text file
  if (SECRET_PATTERNS.some((sp) => !ignore.has(sp.id))) {
    files.forEach((f, fi) => {
      ctx?.progress?.(n + fi, n + files.length, "secrets");
      if (f.kind === "binary" || !f.text) return;
      const hits = scanSecrets(f.text, f.kind).filter((h) => !ignore.has(h.ruleId) && !(h.ruleId === "SEC-006" && cited.has(f.name + ":" + h.line)));
      const by = new Map();
      for (const h of hits) { if (!by.has(h.ruleId)) by.set(h.ruleId, []); by.get(h.ruleId).push(h); }
      for (const [rid, hs] of [...by].sort((a, b) => cmp(a[0], b[0]))) {
        const rl = RULE_LIST.find((x) => x.id === rid);
        const res = { platform: "secrets", format: f.kind, type: "file", name: f.name, id: "file:" + f.name, file: f.name, line: hs[0].line };
        const ev = hs.map((h) => ({ file: f.name, line: h.line, snippet: h.snippet, detail: rl.title + " (" + h.masked + ")" }));
        findings.push(makeFinding(rl, res, ev, rid === "SEC-006" ? "likely" : "confirmed", maxEv));
      }
    });
  }

  // Per-rule skip and unresolved reporting
  for (const rl of RULE_LIST) {
    const st = ruleStat.get(rl.id);
    for (const reason of [...st.skipReasons].sort()) skipped.push({ check: rl.id, reason });
    if (st.unresolved) skipped.push({ check: rl.id, reason: st.unresolved + " value(s) on " + [...st.unresolvedOn].sort().slice(0, 5).join(", ") + (st.unresolvedOn.size > 5 ? " and " + (st.unresolvedOn.size - 5) + " more" : "") + " are variables, references or intrinsics and were not evaluated" });
  }
  const present = new Set(all.map((r) => r.platform));
  for (const pl of PLATFORMS) {
    if (pl === "secrets" || present.has(pl)) continue;
    const count = RULE_LIST.filter((r) => r.kind === pl).length;
    if (count) skipped.push({ check: pl + " rules", reason: "no " + (PLATFORM_LABEL[pl] || pl) + " resources in the input (" + count + " rules not applicable)" });
  }
  for (const f of files) for (const s of f.skipped) skipped.push({ check: f.name + (s.check ? " (" + s.check + ")" : ""), reason: s.reason });

  // Filter, sort
  const kept = findings.filter((f) => SEV_RANK[f.severity] <= minRank);
  kept.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || cmp(a.ruleId, b.ruleId) || cmp(a.file, b.file) || a.line - b.line || cmp(a.resource, b.resource));
  for (const f of kept) ruleStat.get(f.ruleId).hits++;

  // Tables
  const hitsByRes = new Map();
  for (const f of kept) { const k = f.file + "\u0000" + f.resource; if (!hitsByRes.has(k)) hitsByRes.set(k, []); hitsByRes.get(k).push(f.ruleId); }
  const resources = all.filter((r) => r.mode === "managed" || r.mode === "data").map((r) => {
    const ids = [...new Set(hitsByRes.get(r.file + "\u0000" + r.id) || [])].sort();
    return { file: r.file, format: r.format, platform: r.platform, type: r.type, name: r.name, id: r.id, line: r.line, mode: r.mode, hits: (hitsByRes.get(r.file + "\u0000" + r.id) || []).length, rules: ids };
  });
  const rulesTable = RULE_LIST.map((rl) => {
    const st = ruleStat.get(rl.id);
    return { id: rl.id, title: rl.title, severity: rl.severity, platform: rl.kind, frameworks: rl.frameworks.map((x) => x.framework + " " + x.id).join("; "), enabled: !ignore.has(rl.id), belowThreshold: SEV_RANK[rl.severity] > minRank, hits: st.hits, unresolved: st.unresolved };
  });
  const fileTable = files.map((f) => ({ name: f.name, kind: f.kind, confidence: f.confidence, note: f.note, bytes: f.bytes, lines: f.lines, docs: f.docs, blocks: f.blocks, resources: f.resources.length, scannable: SCANNABLE.includes(f.kind) && !f.skipped.some((s) => s.check === "parse" || s.check === "size"), skipped: f.skipped.map((s) => s.reason) }));

  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  const byConfidence = { confirmed: 0, likely: 0, review: 0 };
  const byPlatform = {};
  for (const pl of PLATFORMS.concat(["terraform", "cloudformation"])) byPlatform[pl] = { resources: 0, findings: 0 };
  for (const r of resources) { if (!byPlatform[r.platform]) byPlatform[r.platform] = { resources: 0, findings: 0 }; byPlatform[r.platform].resources++; }
  for (const f of kept) { bySeverity[f.severity]++; byConfidence[f.confidence]++; if (!byPlatform[f.platform]) byPlatform[f.platform] = { resources: 0, findings: 0 }; byPlatform[f.platform].findings++; }
  for (const k of Object.keys(byPlatform)) if (!byPlatform[k].resources && !byPlatform[k].findings) delete byPlatform[k];
  const kinds = {};
  for (const f of files) kinds[f.kind] = (kinds[f.kind] || 0) + 1;

  ctx?.progress?.(n + files.length, n + files.length, "done");
  const summary = {
    files: files.length, scannableFiles: fileTable.filter((f) => f.scannable).length, resources: resources.length,
    findings: kept.length, bySeverity, byConfidence, byPlatform, fileKinds: Object.fromEntries(Object.entries(kinds).sort((a, b) => cmp(a[0], b[0]))),
    rulesTotal: RULE_LIST.length, rulesEnabled: RULE_LIST.length - RULE_LIST.filter((r) => ignore.has(r.id)).length, minSeverity: SEV_RANK[o.minSeverity] != null ? o.minSeverity : "info",
    filteredOut: findings.length - kept.length,
  };
  skipped.sort((a, b) => cmp(a.check, b.check) || cmp(a.reason, b.reason));
  return { summary, findings: kept, tables: { files: fileTable, resources, rules: rulesTable }, skipped, meta: { tool: TOOL_ID, version: VERSION, rows: resources.length, files: files.length, rules: RULE_LIST.length, ignoreRules: [...ignore].sort() } };
}

function makeFinding(rl, r, ev, conf, maxEv) {
  const details = [...new Set(ev.map((e) => e.detail))];
  const resLabel = r.platform === "secrets" ? r.file : r.id;
  return {
    id: rl.id + ":" + r.file + ":" + r.id,
    ruleId: rl.id,
    title: rl.title,
    severity: rl.severity,
    confidence: conf,
    category: r.platform,
    platform: r.platform,
    resource: resLabel,
    resourceType: r.type,
    file: r.file,
    line: ev.length ? ev[0].line : r.line || 1,
    description: rl.title + " - " + resLabel + " (" + r.file + "): " + details.slice(0, 6).join("; ") + (details.length > 6 ? "; and " + (details.length - 6) + " more" : ""),
    recommendation: rl.recommendation,
    controls: rl.frameworks.slice(),
    evidence: ev.slice(0, maxEv),
    evidenceCount: ev.length,
    assets: [{ type: "ASSET", name: r.platform === "secrets" ? r.file : r.id + " (" + r.file + ")", data: { kind: "iac-resource", platform: r.platform, type: r.type, file: r.file } }],
    tags: [rl.id, r.platform, conf],
  };
}

/* ------------------------------------------------------------------------ */
/* Exports                                                                   */
/* ------------------------------------------------------------------------ */

const FINDING_COLS = ["severity", "confidence", "rule", "title", "platform", "resource", "resource_type", "file", "line", "controls", "description", "recommendation", "evidence_count"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const q = (v) => { const s = String(v == null ? "" : v); return /[",\n\r]|^[=+\-@\t\r]/.test(s) ? '"' + (/^[=+\-@\t\r]/.test(s) ? "'" : "") + s.replace(/"/g, '""') + '"' : s; };
  const body = (findings || []).map((f) => [f.severity, f.confidence, f.ruleId, f.title, f.platform, f.resource, f.resourceType, f.file, f.line,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), f.description, f.recommendation, f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length].map(q).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n") + "\n";
}

const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
const SEC_SEVERITY = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };
function fp(s) { let h1 = 0xdeadbeef, h2 = 0x41c6ce57; for (let i = 0; i < s.length; i++) { const ch = s.charCodeAt(i); h1 = Math.imul(h1 ^ ch, 2654435761); h2 = Math.imul(h2 ^ ch, 1597334677); } h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909); h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909); return (h2 >>> 0).toString(16).padStart(8, "0") + (h1 >>> 0).toString(16).padStart(8, "0"); }
const sarifUri = (f) => String(f).replace(/\\/g, "/").replace(/^\/+/, "").split("/").map(encodeURIComponent).join("/"); // per segment: encodeURI leaves # and ?

/** SARIF 2.1.0 log for code-scanning upload. */
export function toSarif(result) {
  const findings = (result && result.findings) || [];
  const rules = RULE_LIST.map((rl) => ({
    id: rl.id, name: rl.id.replace(/[^A-Za-z0-9]/g, ""),
    shortDescription: { text: rl.title }, fullDescription: { text: rl.title + ". " + rl.recommendation },
    help: { text: rl.recommendation + "\nReferences: " + rl.frameworks.map((x) => x.framework + " " + x.id).join("; ") },
    defaultConfiguration: { level: SARIF_LEVEL[rl.severity] },
    properties: { tags: ["security", "iac", rl.kind], "security-severity": SEC_SEVERITY[rl.severity], severity: rl.severity, frameworks: rl.frameworks.map((x) => x.framework + " " + x.id) },
  }));
  const index = new Map(rules.map((r, i) => [r.id, i]));
  const results = findings.map((f) => ({
    ruleId: f.ruleId, ruleIndex: index.has(f.ruleId) ? index.get(f.ruleId) : -1, level: SARIF_LEVEL[f.severity] || "warning",
    message: { text: f.description },
    locations: [{ physicalLocation: { artifactLocation: { uri: sarifUri(f.file) }, region: { startLine: Math.max(1, f.line || 1) } }, logicalLocations: [{ name: String(f.resource), kind: "resource" }] }],
    partialFingerprints: { "iacscan/v1": fp(f.ruleId + "|" + f.file + "|" + f.resource) },
    properties: { severity: f.severity, confidence: f.confidence, platform: f.platform, resourceType: f.resourceType, evidenceCount: f.evidenceCount },
  }));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0",
    runs: [{ tool: { driver: { name: "Darknode IaC Scanner", semanticVersion: VERSION, version: VERSION, informationUri: "https://darknode.ai", rules } }, columnKind: "utf16CodeUnits", results }],
  };
}

/** Plain-text summary. */
export function toTxt(result) {
  const r = result || { summary: {}, findings: [], skipped: [] };
  const s = r.summary || {};
  const out = ["IaC Scanner summary (" + TOOL_ID + " " + VERSION + ")", "",
    "Files: " + (s.files || 0) + " (" + (s.scannableFiles || 0) + " scanned for misconfigurations)", "Resources: " + (s.resources || 0), "Findings: " + (s.findings || 0),
    "By severity: " + SEVERITIES.map((k) => k + " " + ((s.bySeverity || {})[k] || 0)).join(", "),
    "By platform: " + Object.entries(s.byPlatform || {}).map(([k, v]) => (PLATFORM_LABEL[k] || k) + " " + v.resources + " resources / " + v.findings + " findings").join("; "), ""];
  for (const f of r.findings || []) out.push("[" + f.severity.toUpperCase() + "] " + f.ruleId + " " + f.title, "  " + f.file + ":" + f.line + "  " + f.resource + "  (" + f.confidence + ")", "  " + f.description, "  Fix: " + f.recommendation, "  Controls: " + (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), "");
  if ((r.skipped || []).length) { out.push("Not evaluated:"); for (const k of r.skipped) out.push("  - " + k.check + ": " + k.reason); }
  return out.join("\n") + "\n";
}

/* ------------------------------------------------------------------------ */
/* Synthetic example and self-test                                           */
/* ------------------------------------------------------------------------ */

/** A small seeded SYNTHETIC repository (every file is labelled; not real infrastructure). */
export function exampleDataset(seed = 7) {
  let s = seed >>> 0 || 7;
  const rnd = () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 4294967296; };
  const sfx = Math.floor(rnd() * 9000 + 1000);
  const app = ["ledger", "orders", "billing", "catalog"][Math.floor(rnd() * 4)];
  const H = "SYNTHETIC EXAMPLE - generated for the IaC Scanner demo, not real infrastructure";
  const files = [
    { name: "infra/main.tf", text: `# ${H}
provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "${app}_exports" {
  bucket = "${app}-exports-${sfx}"
  acl    = "public-read"
}

resource "aws_security_group" "${app}_admin" {
  name        = "${app}-admin"
  description = "Admin access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "${app}_deployer" {
  name = "${app}-deployer"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_db_instance" "${app}" {
  identifier          = "${app}-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "${app}admin"
  password            = var.db_password
  publicly_accessible = true
  skip_final_snapshot = true
}
` },
    { name: "cloudformation/queue.yaml", text: `# ${H}
AWSTemplateFormatVersion: '2010-09-09'
Description: ${app} work queue
Resources:
  WorkQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub '\${AWS::StackName}-work'
      SqsManagedSseEnabled: false
  ArchiveBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '\${AWS::StackName}-archive-${sfx}'
  Trail:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      S3BucketName: !Ref ArchiveBucket
      IsMultiRegionTrail: false
` },
    { name: "k8s/deployment.yaml", text: `# ${H}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${app}-api
  namespace: ${app}
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ${app}-api
  template:
    metadata:
      labels:
        app: ${app}-api
    spec:
      containers:
        - name: api
          image: example.registry.local/${app}-api:latest
          ports:
            - containerPort: 8080
          securityContext:
            privileged: true
---
apiVersion: v1
kind: Service
metadata:
  name: ${app}-api
  namespace: ${app}
spec:
  type: LoadBalancer
  selector:
    app: ${app}-api
  ports:
    - port: 80
      targetPort: 8080
` },
    { name: "Dockerfile", text: `# ${H}
FROM node:20
WORKDIR /app
RUN curl -fsSL https://example.invalid/install.sh | sh
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 8080
CMD ["node", "server.js"]
` },
    { name: "docker-compose.yml", text: `# ${H}
services:
  api:
    build: .
    ports:
      - "8080:8080"
    privileged: true
  db:
    image: postgres
    ports:
      - "5432:5432"
    environment:
      POSTGRES_USER: ${app}
      POSTGRES_PASSWORD: "synthetic-demo-${sfx}"
` },
    { name: ".github/workflows/ci.yml", text: `# ${H}
name: ci
on:
  pull_request_target:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: some-org/setup-tool@v1
      - name: Greet
        run: echo "Testing \${{ github.event.pull_request.title }}"
      - run: npm test
` },
  ];
  return { label: "synthetic example repository (not real infrastructure)", files };
}

/** Deterministic checks of the engine on its own synthetic example. */
export function selfTest() {
  const tests = [];
  const ex = exampleDataset();
  const r = analyze(ex.files);
  const ids = new Set(r.findings.map((f) => f.ruleId));
  for (const id of ["AWS-S3-001", "AWS-SG-001", "AWS-IAM-001", "AWS-RDS-002", "AWS-CT-001", "K8S-001", "K8S-014", "DKR-001", "DKR-004", "CMP-001", "CMP-009", "GHA-001", "GHA-003", "GHA-007"]) tests.push({ name: id + " fires on the synthetic example", pass: ids.has(id) });
  tests.push({ name: "at least 120 rules", pass: RULES.length >= 120 });
  tests.push({ name: "rule ids unique", pass: new Set(RULES.map((x) => x.id)).size === RULES.length });
  tests.push({ name: "every rule cites a control", pass: RULES.every((x) => x.frameworks.length > 0) });
  tests.push({ name: "deterministic", pass: JSON.stringify(analyze(ex.files)) === JSON.stringify(r) });
  tests.push({ name: "empty input yields no findings", pass: analyze([]).findings.length === 0 });
  const sarif = toSarif(r);
  tests.push({ name: "SARIF 2.1.0 shape", pass: sarif.version === "2.1.0" && sarif.runs[0].tool.driver.rules.length === RULES.length && sarif.runs[0].results.length === r.findings.length });
  tests.push({ name: "ignoreRules removes a rule", pass: !analyze(ex.files, { ignoreRules: ["AWS-S3-001"] }).findings.some((f) => f.ruleId === "AWS-S3-001") });
  return { pass: tests.every((t) => t.pass), tests };
}
