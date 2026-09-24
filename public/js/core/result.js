// Darknode normalized ToolResult.
//
// Today every tool renders its own output and, if it feeds the security graph,
// hand-rolls the graph-bridge calls. There is no common shape for "what a tool
// produced", which makes cross-tool features (a unified results feed, an AI that
// can read any tool's output, export, history) impossible to build generically.
//
// ToolResult is that common shape. A tool builds one and returns it; consumers
// (the results feed, the AI context builder, graph-bridge, exporters) all speak
// the same structure:
//
//   const r = ok("port-scan")
//     .summary("3 open ports on 203.0.113.5")
//     .finding({ title: "SSH exposed", severity: "medium" })
//     .entity("IP", "203.0.113.5", { address: "203.0.113.5" }, { severity: "low" })
//     .metric("openPorts", 3)
//     .done();
//
// Findings and entities are validated through core/entities.js so a malformed
// producer surfaces its mistakes instead of silently poisoning the graph.

import { validateEntity, SEVERITIES } from "./entities.js";

export const RESULT_STATUS = Object.freeze({
  OK: "ok",
  PARTIAL: "partial", // produced some output but also hit recoverable errors
  ERROR: "error",
  EMPTY: "empty", // ran fine, found nothing
});

const now = () => Date.now();
const iso = (t) => new Date(t).toISOString();

// A finding is a lighter-weight observation than a full graph entity: it always
// renders in the results feed, and may optionally be promoted to an entity.
function normFinding(input) {
  const f = input && typeof input === "object" ? input : { title: String(input) };
  const severity = SEVERITIES.includes(f.severity) ? f.severity : null;
  return {
    title: String(f.title || "Untitled finding").trim(),
    detail: f.detail ? String(f.detail) : "",
    severity,
    tags: Array.isArray(f.tags) ? f.tags.map((t) => String(t).toLowerCase()).filter(Boolean) : [],
    ref: f.ref ? String(f.ref) : null,
  };
}

export class ToolResult {
  constructor(tool, status = RESULT_STATUS.OK) {
    this.tool = String(tool || "unknown");
    this.status = status;
    this.startedAt = now();
    this.finishedAt = null;
    this.summaryText = "";
    this.data = null; // arbitrary structured payload the tool owns
    this.findings = [];
    this.entities = []; // validated { type, name, data, tags, severity, status, source }
    this.warnings = [];
    this.errorInfo = null;
    this.metrics = {};
    this.meta = {}; // free-form: context id, target, params echoes, etc.
  }

  // --- fluent builders (each returns `this`) --------------------------------

  summary(text) { this.summaryText = String(text || ""); return this; }

  set(data) { this.data = data; return this; }

  metric(key, value) { this.metrics[String(key)] = value; return this; }

  metrics_(obj) { Object.assign(this.metrics, obj || {}); return this; }

  metaData(obj) { Object.assign(this.meta, obj || {}); return this; }

  warn(msg) { if (msg) this.warnings.push(String(msg)); return this; }

  finding(f) { this.findings.push(normFinding(f)); return this; }

  /** Add a validated graph entity. Invalid entities become warnings instead of
   *  being silently accepted, and downgrade an OK result to PARTIAL. */
  entity(type, name, data, opts) {
    const v = validateEntity(type, name, data, opts);
    if (v.ok) {
      this.entities.push(v.entity);
    } else {
      this.warnings.push(`rejected ${type} entity "${name}": ${v.errors.join("; ")}`);
      if (this.status === RESULT_STATUS.OK) this.status = RESULT_STATUS.PARTIAL;
    }
    return this;
  }

  /** Mark the result as failed with an error. */
  fail(err) {
    this.status = RESULT_STATUS.ERROR;
    this.errorInfo = err instanceof Error
      ? { name: err.name, message: err.message }
      : { name: "Error", message: String(err) };
    return this;
  }

  // --- finalization ---------------------------------------------------------

  /** Stamp finish time, auto-derive EMPTY status, and freeze timing. */
  done() {
    this.finishedAt = now();
    if (this.status === RESULT_STATUS.OK && this.findings.length === 0 && this.entities.length === 0 && this.data == null) {
      this.status = RESULT_STATUS.EMPTY;
    }
    return this;
  }

  get durationMs() { return (this.finishedAt || now()) - this.startedAt; }

  get ok() { return this.status === RESULT_STATUS.OK || this.status === RESULT_STATUS.PARTIAL || this.status === RESULT_STATUS.EMPTY; }

  /** Highest severity among findings + entities (null if none). */
  get maxSeverity() {
    let idx = 0; // 0 == null in SEVERITIES
    for (const src of [this.findings, this.entities]) {
      for (const item of src) {
        const i = SEVERITIES.indexOf(item.severity);
        if (i > idx) idx = i;
      }
    }
    return SEVERITIES[idx];
  }

  /** Plain-object snapshot for persistence / bus payloads / export. */
  toJSON() {
    return {
      tool: this.tool,
      status: this.status,
      startedAt: iso(this.startedAt),
      finishedAt: this.finishedAt ? iso(this.finishedAt) : null,
      durationMs: this.durationMs,
      summary: this.summaryText,
      data: this.data,
      findings: this.findings,
      entities: this.entities,
      warnings: this.warnings,
      error: this.errorInfo,
      metrics: this.metrics,
      meta: this.meta,
      maxSeverity: this.maxSeverity,
    };
  }

  /** Compact, human/AI-readable text digest — used to ground AI context and for
   *  the collapsed results-feed row. */
  toText() {
    const lines = [`[${this.tool}] ${this.status.toUpperCase()}${this.summaryText ? " — " + this.summaryText : ""}`];
    if (this.findings.length) {
      lines.push(`Findings (${this.findings.length}):`);
      for (const f of this.findings.slice(0, 20)) {
        lines.push(`  - ${f.severity ? "[" + f.severity + "] " : ""}${f.title}${f.detail ? ": " + f.detail : ""}`);
      }
      if (this.findings.length > 20) lines.push(`  … and ${this.findings.length - 20} more`);
    }
    if (this.entities.length) lines.push(`Entities: ${this.entities.length} (${[...new Set(this.entities.map((e) => e.type))].join(", ")})`);
    const mk = Object.keys(this.metrics);
    if (mk.length) lines.push("Metrics: " + mk.map((k) => `${k}=${this.metrics[k]}`).join(", "));
    if (this.warnings.length) lines.push("Warnings: " + this.warnings.length);
    if (this.errorInfo) lines.push("Error: " + this.errorInfo.message);
    return lines.join("\n");
  }
}

// --- convenience factories ---------------------------------------------------

export function result(tool, status) { return new ToolResult(tool, status); }
export function ok(tool) { return new ToolResult(tool, RESULT_STATUS.OK); }
export function empty(tool) { return new ToolResult(tool, RESULT_STATUS.EMPTY); }
export function error(tool, err) { return new ToolResult(tool, RESULT_STATUS.OK).fail(err); }

/** Rehydrate a plain object (from storage/bus) back into a ToolResult. */
export function fromJSON(obj) {
  const r = new ToolResult(obj.tool, obj.status);
  r.startedAt = obj.startedAt ? Date.parse(obj.startedAt) : now();
  r.finishedAt = obj.finishedAt ? Date.parse(obj.finishedAt) : null;
  r.summaryText = obj.summary || "";
  r.data = obj.data ?? null;
  r.findings = Array.isArray(obj.findings) ? obj.findings : [];
  r.entities = Array.isArray(obj.entities) ? obj.entities : [];
  r.warnings = Array.isArray(obj.warnings) ? obj.warnings : [];
  r.errorInfo = obj.error || null;
  r.metrics = obj.metrics || {};
  r.meta = obj.meta || {};
  return r;
}
