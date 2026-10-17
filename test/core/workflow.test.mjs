// Unit tests for public/js/core/workflow.js (findings workflow engine) and the
// workflow-field protection in core/sink-map.js (mergeToolData / nextStatus / toolSeverity).
import { test, group, assert } from "../harness.mjs";
import {
  SLA_DEFAULTS, SLA_SOURCES, VIEWS, VIEW_LABEL, RESOLUTIONS, WORKFLOW_FIELDS, DAY_MS,
  normalizePolicy, computeDue, slaState, applyChange, applyBulk, reconcileRun,
  expiredExceptions, inView, timeline, isKnownExploited, cveIds,
} from "../../public/js/core/workflow.js";
import { mergeToolData, nextStatus, toolSeverity, toEntities } from "../../public/js/core/sink-map.js";

const T0 = Date.UTC(2026, 0, 1);            // first seen
const NOW = T0 + 10 * DAY_MS;               // "now" in most tests
const ISO = new Date(T0).toISOString();
const ctx = { uid: "u1", now: NOW };

const deepFreeze = (o) => { if (o && typeof o === "object" && !Object.isFrozen(o)) { Object.freeze(o); for (const k of Object.keys(o)) deepFreeze(o[k]); } return o; };
const F = (over = {}) => {
  const { data, ...rest } = over;
  return deepFreeze({ id: "f1", type: "FINDING", name: "Open S3 bucket (tool:k1)", severity: "high", status: "open", tags: ["sink", "tool"], createdAt: ISO, updatedAt: ISO, data: { findingKey: "k1", tool: "tool", dataset: "ds.csv", ...(data || {}) }, ...rest });
};
// Apply updates the way security-graph updateEntity does (shallow data merge).
const applied = (e, u) => ({ ...e, ...(u.status ? { status: u.status } : {}), ...(u.severity ? { severity: u.severity } : {}), data: { ...e.data, ...(u.data || {}) } });
const exc = (days = 30, now = NOW) => ({ reason: "Compensating WAF", approver: "CISO", expiresAt: now + days * DAY_MS, riskId: null, by: "u1", ts: now });

group("workflow: constants", () => {
  test("defaults, sources, views and resolutions match the contract", () => {
    assert.deepEqual(SLA_DEFAULTS, { critical: 30, high: 60, medium: 90, low: 180, info: null, kev: 14 });
    assert.ok(SLA_SOURCES.critical.includes("PCI DSS") && SLA_SOURCES.kev.includes("BOD 22-01") && SLA_SOURCES.other);
    assert.deepEqual(VIEWS, ["mine", "unassigned", "overdue", "due_week", "excepted", "open", "all"]);
    for (const v of VIEWS) assert.ok(VIEW_LABEL[v], v);
    assert.deepEqual(RESOLUTIONS, ["fixed", "accepted", "false_positive", "duplicate"]);
  });
});

group("workflow: normalizePolicy", () => {
  test("garbage gives the defaults", () => {
    for (const g of [null, undefined, 5, "x", [], [1, 2]]) assert.deepEqual(normalizePolicy(g), SLA_DEFAULTS);
  });
  test("keeps positive integers and explicit null, replaces bad values per key", () => {
    const p = normalizePolicy({ critical: 7, high: "21", medium: -1, low: 1.5, info: 365, kev: null, extra: 9 });
    assert.deepEqual(p, { critical: 7, high: 21, medium: 90, low: 180, info: 365, kev: null });
    assert.equal(normalizePolicy({ critical: 0 }).critical, 30);
    assert.equal(normalizePolicy({ critical: "abc" }).critical, 30);
  });
});

group("workflow: computeDue", () => {
  test("severity days from createdAt", () => {
    assert.equal(computeDue(F(), SLA_DEFAULTS), T0 + 60 * DAY_MS);
    assert.equal(computeDue(F({ severity: "critical" }), SLA_DEFAULTS), T0 + 30 * DAY_MS);
    assert.equal(computeDue(F({ severity: "low", createdAt: T0 }), SLA_DEFAULTS), T0 + 180 * DAY_MS, "numeric createdAt");
  });
  test("info, missing severity and a null policy entry give null", () => {
    assert.equal(computeDue(F({ severity: "info" }), SLA_DEFAULTS), null);
    assert.equal(computeDue(F({ severity: null }), SLA_DEFAULTS), null);
    assert.equal(computeDue(F(), { ...SLA_DEFAULTS, high: null }), null);
    assert.equal(computeDue(F({ createdAt: "garbage" }), SLA_DEFAULTS), null);
  });
  test("known-exploited uses kev days when sooner", () => {
    assert.equal(computeDue(F({ data: { kev: true } }), SLA_DEFAULTS), T0 + 14 * DAY_MS);
    assert.equal(computeDue(F({ severity: "critical", data: { kev: true } }), { ...SLA_DEFAULTS, critical: 7 }), T0 + 7 * DAY_MS, "severity sooner than kev");
    assert.equal(computeDue(F({ data: { kev: true } }), { ...SLA_DEFAULTS, kev: null }), T0 + 60 * DAY_MS);
  });
  test("KEV via kevSet on data.cve, data.cves, the name or evidence", () => {
    const kev = new Set(["CVE-2024-1234"]);
    assert.equal(computeDue(F({ data: { cve: "CVE-2024-1234" } }), SLA_DEFAULTS, { kevSet: kev }), T0 + 14 * DAY_MS);
    assert.equal(computeDue(F({ data: { cves: ["CVE-2020-1", "cve-2024-1234"] } }), SLA_DEFAULTS, { kevSet: kev }), T0 + 14 * DAY_MS);
    assert.equal(computeDue(F({ name: "CVE-2024-1234 on web01 (tool:k1)" }), SLA_DEFAULTS, { kevSet: ["CVE-2024-1234"] }), T0 + 14 * DAY_MS, "array kevSet");
    assert.equal(computeDue(F({ data: { evidence: [{ ref: "see CVE-2024-1234" }] } }), SLA_DEFAULTS, { kevSet: kev }), T0 + 14 * DAY_MS);
    assert.equal(computeDue(F({ data: { cve: "CVE-2024-9999" } }), SLA_DEFAULTS, { kevSet: kev }), T0 + 60 * DAY_MS);
    assert.equal(computeDue(F({ data: { cve: "CVE-2024-1234" } }), SLA_DEFAULTS), T0 + 60 * DAY_MS, "no kevSet");
    assert.deepEqual(cveIds(F({ name: "CVE-2021-44228 x", data: { cve: "cve-2021-44228" } })), ["CVE-2021-44228"]);
    assert.ok(isKnownExploited(F({ data: { kev: true } })));
  });
  test("a manual dueAt override wins, even for info", () => {
    const at = T0 + 3 * DAY_MS;
    assert.equal(computeDue(F({ data: { dueAt: at, kev: true } }), SLA_DEFAULTS), at);
    assert.equal(computeDue(F({ severity: "info", data: { dueAt: at } }), SLA_DEFAULTS), at);
  });
});

group("workflow: slaState", () => {
  const P = SLA_DEFAULTS;
  test("on_track, due_soon, overdue with daysLeft", () => {
    assert.deepEqual(slaState(F(), P, NOW), { dueAt: T0 + 60 * DAY_MS, daysLeft: 50, state: "on_track" });
    const soon = slaState(F(), P, T0 + 55 * DAY_MS);
    assert.equal(soon.state, "due_soon"); assert.equal(soon.daysLeft, 5);
    assert.equal(slaState(F(), P, T0 + 53 * DAY_MS).state, "due_soon", "exactly 7 days is due soon");
    const late = slaState(F(), P, T0 + 63 * DAY_MS);
    assert.equal(late.state, "overdue"); assert.equal(late.daysLeft, -3);
    assert.equal(slaState(F(), P, T0 + 60 * DAY_MS).state, "due_soon", "due moment itself is not yet overdue");
    assert.equal(slaState(F(), P, T0 + 60 * DAY_MS + 1000).daysLeft, 0, "less than a day late is 0, never -0");
    assert.ok(!Object.is(slaState(F(), P, T0 + 60 * DAY_MS + 1000).daysLeft, -0));
  });
  test("none, closed and excepted", () => {
    assert.equal(slaState(F({ severity: "info" }), P, NOW).state, "none");
    assert.equal(slaState(F({ severity: "info" }), P, NOW).daysLeft, null);
    assert.equal(slaState(F({ status: "resolved" }), P, T0 + 99 * DAY_MS).state, "closed");
    assert.equal(slaState(F({ status: "closed" }), P, NOW).state, "closed");
    assert.equal(slaState(F({ data: { exception: exc(5) } }), P, T0 + 99 * DAY_MS - 5 * DAY_MS).state, "overdue", "expired exception does not shield");
    assert.equal(slaState(F({ data: { exception: exc(100) } }), P, T0 + 99 * DAY_MS).state, "excepted");
  });
});

group("workflow: applyChange basics", () => {
  test("never mutates the (deep-frozen) input", () => {
    const e = F({ data: { history: [{ ts: 1, uid: "x", field: "owner", from: null, to: "x" }], exception: exc(), tickets: [], comments: [] } });
    const ops = [
      { op: "assign", owner: "u2" }, { op: "status", status: "investigating" }, { op: "comment", text: "hi" },
      { op: "severity", severity: "critical", reason: "internet facing" }, { op: "due", dueAt: NOW + DAY_MS, reason: "board" },
      { op: "exception", reason: "r", approver: "a", expiresAt: NOW + DAY_MS }, { op: "revokeException" },
      { op: "ticket", url: "https://jira.example/T-1", label: "T-1" },
    ];
    for (const c of ops) { const r = applyChange(e, c, ctx); assert.ok(r.updates, c.op + ": " + r.error); }
    assert.equal(e.data.history.length, 1);
  });
  test("read-only role is refused; a write role is allowed", () => {
    assert.deepEqual(applyChange(F(), { op: "assign", owner: "u2" }, { ...ctx, role: "viewer" }), { error: "Read-only role" });
    assert.deepEqual(applyChange(F(), { op: "assign", owner: "u2" }, { ...ctx, role: "removed" }), { error: "Read-only role" });
    assert.ok(applyChange(F(), { op: "assign", owner: "u2" }, { ...ctx, role: "analyst" }).updates);
  });
  test("unknown op and missing entity are errors", () => {
    assert.ok(applyChange(F(), { op: "explode" }, ctx).error);
    assert.ok(applyChange(null, { op: "assign", owner: "x" }, ctx).error);
  });
  test("history is capped at 100 with historyCount as the total", () => {
    const hist = Array.from({ length: 100 }, (_, i) => ({ ts: i, uid: "x", field: "owner", from: null, to: "o" + i }));
    const r = applyChange(F({ data: { history: hist, historyCount: 250 } }), { op: "assign", owner: "u9" }, ctx);
    assert.equal(r.updates.data.history.length, 100);
    assert.equal(r.updates.data.history[0].to, "o1", "oldest dropped");
    assert.deepEqual(r.updates.data.history[99], { ts: NOW, uid: "u1", field: "owner", from: null, to: "u9" });
    assert.equal(r.updates.data.historyCount, 251);
    assert.equal(applyChange(F(), { op: "assign", owner: "u9" }, ctx).updates.data.historyCount, 1, "starts from 0");
  });
});

group("workflow: assign", () => {
  test("sets owner + label with a history entry; unassign clears", () => {
    const r = applyChange(F(), { op: "assign", owner: "u2", ownerLabel: "Bob" }, ctx);
    assert.equal(r.updates.data.owner, "u2"); assert.equal(r.updates.data.ownerLabel, "Bob");
    assert.equal(r.updates.status, undefined);
    const e2 = applied(F(), r.updates);
    const r2 = applyChange(e2, { op: "assign", owner: null }, ctx);
    assert.equal(r2.updates.data.owner, null); assert.equal(r2.updates.data.ownerLabel, null);
    assert.deepEqual(r2.updates.data.history.map((h) => [h.field, h.from, h.to]), [["owner", null, "u2"], ["owner", "u2", null]]);
  });
  test("same owner is a no-op", () => {
    const r = applyChange(F({ data: { owner: "u2", ownerLabel: null } }), { op: "assign", owner: "u2" }, ctx);
    assert.ok(r.noop); assert.deepEqual(r.updates, {});
  });
});

group("workflow: status", () => {
  test("validates status and resolution", () => {
    assert.equal(applyChange(F(), { op: "status", status: "done" }, ctx).error, "Unknown status");
    assert.equal(applyChange(F(), { op: "status", status: "resolved" }, ctx).error, "Choose a resolution");
    assert.equal(applyChange(F(), { op: "status", status: "closed", resolution: "wontfix" }, ctx).error, "Unknown resolution");
  });
  test("resolve as fixed sets status + resolution with history", () => {
    const r = applyChange(F(), { op: "status", status: "resolved", resolution: "fixed" }, ctx);
    assert.equal(r.updates.status, "resolved");
    assert.equal(r.updates.data.resolution, "fixed");
    assert.deepEqual(r.updates.data.history.map((h) => h.field), ["status", "resolution"]);
  });
  test("accepted needs an active exception", () => {
    assert.equal(applyChange(F(), { op: "status", status: "resolved", resolution: "accepted" }, ctx).error, "Accepting a risk needs an exception with an expiry");
    assert.equal(applyChange(F({ data: { exception: exc(-1) } }), { op: "status", status: "closed", resolution: "accepted" }, ctx).error, "Accepting a risk needs an exception with an expiry");
    assert.equal(applyChange(F({ data: { exception: exc(30) } }), { op: "status", status: "closed", resolution: "accepted" }, ctx).updates.data.resolution, "accepted");
  });
  test("reopening clears the resolution", () => {
    const r = applyChange(F({ status: "resolved", data: { resolution: "false_positive" } }), { op: "status", status: "open" }, ctx);
    assert.equal(r.updates.status, "open");
    assert.equal(r.updates.data.resolution, null);
    assert.ok(applyChange(F(), { op: "status", status: "open" }, ctx).noop);
  });
});

group("workflow: comment", () => {
  test("trims, appends and counts", () => {
    const r = applyChange(F(), { op: "comment", text: "  looks real  " }, ctx);
    assert.deepEqual(r.updates.data.comments, [{ ts: NOW, uid: "u1", text: "looks real" }]);
    assert.equal(r.updates.data.commentCount, 1);
    assert.equal(r.updates.data.history, undefined, "comments are not history entries");
  });
  test("rejects empty and over-long comments", () => {
    assert.ok(applyChange(F(), { op: "comment", text: "   " }, ctx).error);
    assert.ok(applyChange(F(), { op: "comment", text: "x".repeat(4001) }, ctx).error);
    assert.ok(applyChange(F(), { op: "comment", text: "x".repeat(4000) }, ctx).updates);
  });
  test("capped at 200 newest with commentCount total", () => {
    const comments = Array.from({ length: 200 }, (_, i) => ({ ts: i, uid: "x", text: "c" + i }));
    const r = applyChange(F({ data: { comments, commentCount: 500 } }), { op: "comment", text: "new" }, ctx);
    assert.equal(r.updates.data.comments.length, 200);
    assert.equal(r.updates.data.comments[0].text, "c1");
    assert.equal(r.updates.data.commentCount, 501);
  });
});

group("workflow: severity", () => {
  test("requires a reason and a valid severity", () => {
    assert.ok(applyChange(F(), { op: "severity", severity: "critical" }, ctx).error);
    assert.ok(applyChange(F(), { op: "severity", severity: "extreme", reason: "x" }, ctx).error);
  });
  test("sets severity and severityOverride", () => {
    const r = applyChange(F(), { op: "severity", severity: "critical", reason: "internet facing" }, ctx);
    assert.equal(r.updates.severity, "critical");
    assert.deepEqual(r.updates.data.severityOverride, { from: "high", to: "critical", reason: "internet facing", uid: "u1", ts: NOW });
    assert.deepEqual(r.updates.data.history.map((h) => [h.field, h.from, h.to]), [["severity", "high", "critical"]]);
  });
});

group("workflow: due", () => {
  test("setting needs a reason; null clears", () => {
    assert.ok(applyChange(F(), { op: "due", dueAt: NOW + DAY_MS }, ctx).error);
    assert.ok(applyChange(F(), { op: "due", dueAt: "soon", reason: "x" }, ctx).error);
    const r = applyChange(F(), { op: "due", dueAt: NOW + DAY_MS, reason: "audit" }, ctx);
    assert.equal(r.updates.data.dueAt, NOW + DAY_MS); assert.equal(r.updates.data.dueReason, "audit");
    const e2 = applied(F(), r.updates);
    assert.equal(computeDue(e2, SLA_DEFAULTS), NOW + DAY_MS);
    const c = applyChange(e2, { op: "due", dueAt: null }, ctx);
    assert.equal(c.updates.data.dueAt, null); assert.equal(c.updates.data.dueReason, null);
    assert.equal(computeDue(applied(e2, c.updates), SLA_DEFAULTS), T0 + 60 * DAY_MS, "back to the policy");
    assert.ok(applyChange(F(), { op: "due", dueAt: null }, ctx).noop);
  });
});

group("workflow: exception", () => {
  test("validates reason, approver and expiry window", () => {
    const base = { op: "exception", reason: "WAF", approver: "CISO", expiresAt: NOW + 30 * DAY_MS };
    assert.ok(applyChange(F(), { ...base, reason: "" }, ctx).error);
    assert.ok(applyChange(F(), { ...base, approver: " " }, ctx).error);
    assert.ok(applyChange(F(), { ...base, expiresAt: NOW }, ctx).error, "must be in the future");
    assert.ok(applyChange(F(), { ...base, expiresAt: NOW + 366 * DAY_MS }, ctx).error, "max 365 days");
    assert.ok(applyChange(F(), { ...base, expiresAt: NOW + 365 * DAY_MS }, ctx).updates);
  });
  test("sets data.exception; replacing keeps the old one in exceptionHistory", () => {
    const r = applyChange(F(), { op: "exception", reason: "WAF", approver: "CISO", expiresAt: NOW + DAY_MS, riskId: "R-7" }, ctx);
    assert.deepEqual(r.updates.data.exception, { reason: "WAF", approver: "CISO", expiresAt: NOW + DAY_MS, riskId: "R-7", by: "u1", ts: NOW });
    const r2 = applyChange(applied(F(), r.updates), { op: "exception", reason: "extended", approver: "CISO", expiresAt: NOW + 9 * DAY_MS }, ctx);
    assert.equal(r2.updates.data.exceptionHistory.length, 1);
    assert.equal(r2.updates.data.exceptionHistory[0].reason, "WAF");
  });
  test("revoke clears it and reopens an accepted finding", () => {
    assert.ok(applyChange(F(), { op: "revokeException" }, ctx).error);
    const e = F({ status: "closed", data: { exception: exc(), resolution: "accepted" } });
    const r = applyChange(e, { op: "revokeException", reason: "WAF removed" }, ctx);
    assert.equal(r.updates.data.exception, null);
    assert.equal(r.updates.status, "open");
    assert.equal(r.updates.data.resolution, null);
    assert.equal(r.updates.data.exceptionHistory[0].revokeReason, "WAF removed");
    const r2 = applyChange(F({ data: { exception: exc() } }), { op: "revokeException" }, ctx);
    assert.equal(r2.updates.status, undefined, "an open finding stays open");
  });
});

group("workflow: ticket", () => {
  test("https only", () => {
    assert.ok(applyChange(F(), { op: "ticket", url: "http://jira.example/T-1" }, ctx).error);
    assert.ok(applyChange(F(), { op: "ticket", url: "javascript:alert(1)" }, ctx).error);
    assert.ok(applyChange(F(), { op: "ticket", url: "not a url" }, ctx).error);
  });
  test("appends, dedupes by url and caps at 20", () => {
    const r = applyChange(F(), { op: "ticket", url: "https://jira.example/T-1", label: "T-1" }, ctx);
    assert.deepEqual(r.updates.data.tickets, [{ url: "https://jira.example/T-1", label: "T-1", ts: NOW, uid: "u1" }]);
    const e2 = applied(F(), r.updates);
    assert.ok(applyChange(e2, { op: "ticket", url: "https://jira.example/T-1", label: "T-1" }, ctx).noop);
    assert.equal(applyChange(e2, { op: "ticket", url: "https://jira.example/T-1", label: "renamed" }, ctx).updates.data.tickets.length, 1);
    const many = Array.from({ length: 20 }, (_, i) => ({ url: "https://t.example/" + i, label: "" + i, ts: i, uid: "x" }));
    const r3 = applyChange(F({ data: { tickets: many } }), { op: "ticket", url: "https://t.example/new" }, ctx);
    assert.equal(r3.updates.data.tickets.length, 20);
    assert.equal(r3.updates.data.tickets[19].label, "t.example", "label defaults to the host");
  });
});

group("workflow: applyBulk", () => {
  test("per-entity updates or errors, one shared now", () => {
    const a = F({ id: "a" }), b = F({ id: "b", status: "resolved", data: { resolution: "fixed" } });
    const out = applyBulk([a, b], { op: "status", status: "resolved", resolution: "duplicate" }, ctx);
    assert.equal(out[0].id, "a"); assert.equal(out[0].updates.status, "resolved");
    assert.equal(out[1].id, "b"); assert.equal(out[1].updates.data.resolution, "duplicate");
    const errs = applyBulk([a, b], { op: "status", status: "resolved", resolution: "accepted" }, ctx);
    assert.ok(errs.every((x) => x.error && x.id));
    assert.equal(applyBulk([a], { op: "assign", owner: "z" }, { uid: "u1", now: NOW })[0].updates.data.history[0].ts, NOW);
  });
});

group("workflow: reconcileRun", () => {
  const prev = [
    F({ id: "gone", data: { findingKey: "k-gone" } }),
    F({ id: "stays", data: { findingKey: "k-stays" } }),
    F({ id: "back", status: "resolved", data: { findingKey: "k-back", resolution: "fixed" } }),
    F({ id: "fp", status: "closed", data: { findingKey: "k-fp", resolution: "false_positive" } }),
    F({ id: "acc", status: "resolved", data: { findingKey: "k-acc", resolution: "accepted", exception: exc() } }),
    F({ id: "dup", status: "resolved", data: { findingKey: "k-dup", resolution: "duplicate" } }),
    F({ id: "other-tool", data: { findingKey: "k-o1", tool: "othertool" } }),
    F({ id: "other-ds", data: { findingKey: "k-o2", dataset: "other.csv" } }),
    F({ id: "sample", tags: ["sink", "tool", "sample"], data: { findingKey: "k-s" } }),
    F({ id: "inv", status: "investigating", data: { findingKey: "k-inv" } }),
  ];
  const cur = ["k-stays", "k-back", "k-fp", "k-acc", "k-dup"];
  test("fixed: open findings of the same tool+dataset missing from the run", () => {
    const r = reconcileRun("tool", "ds.csv", prev, cur, { now: NOW });
    assert.deepEqual(r.fixed.map((x) => x.id), ["gone", "inv"]);
    const u = r.fixed[0].updates;
    assert.equal(u.status, "resolved");
    assert.equal(u.data.resolution, "fixed"); assert.equal(u.data.verifiedBy, "tool"); assert.equal(u.data.verifiedAt, NOW);
    assert.ok(u.data.history.every((h) => h.uid === "system:tool" && h.ts === NOW));
    assert.equal(u.data.history[0].field, "status");
  });
  test("regressed: fixed findings back in the run reopen; other resolutions untouched", () => {
    const r = reconcileRun("tool", "ds.csv", prev, cur, { now: NOW });
    assert.deepEqual(r.regressed.map((x) => x.id), ["back"]);
    const u = r.regressed[0].updates;
    assert.equal(u.status, "open");
    assert.equal(u.data.resolution, null); assert.equal(u.data.regressed, true); assert.equal(u.data.regressedAt, NOW);
    assert.deepEqual(u.data.history.map((h) => [h.field, h.from, h.to]), [["status", "resolved", "open"], ["resolution", "fixed", null]]);
  });
  test("scope: other tool, other dataset and sample are never touched", () => {
    const r = reconcileRun("tool", "ds.csv", prev, [], { now: NOW });
    const ids = [...r.fixed, ...r.regressed].map((x) => x.id);
    for (const id of ["other-tool", "other-ds", "sample", "fp", "acc", "dup"]) assert.ok(!ids.includes(id), id);
  });
  test("no dataset name marks nothing fixed; regressOnly ignores dataset scope", () => {
    assert.deepEqual(reconcileRun("tool", undefined, prev, [], { now: NOW }).fixed, []);
    const back2 = F({ id: "back2", status: "closed", data: { findingKey: "k-b2", resolution: "fixed", dataset: "elsewhere" } });
    const r = reconcileRun("tool", undefined, [...prev, back2], ["k-b2", "k-back"], { now: NOW, regressOnly: true });
    assert.deepEqual(r.fixed, []);
    assert.deepEqual(r.regressed.map((x) => x.id).sort(), ["back", "back2"]);
  });
  test("does not mutate the input entities", () => {
    reconcileRun("tool", "ds.csv", prev, cur, { now: NOW });
    assert.equal(prev[0].status, "open"); assert.equal(prev[0].data.history, undefined);
  });
});

group("workflow: expiredExceptions", () => {
  test("lapses expired exceptions and reopens accepted findings", () => {
    const acc = F({ id: "acc", status: "resolved", data: { resolution: "accepted", exception: exc(-1) } });
    const open = F({ id: "open", data: { exception: exc(0) } });
    const live = F({ id: "live", data: { exception: exc(5) } });
    const out = expiredExceptions([acc, open, live, F({ id: "none" })], NOW);
    assert.deepEqual(out.map((x) => x.id), ["acc", "open"]);
    const a = out[0].updates;
    assert.equal(a.status, "open"); assert.equal(a.data.resolution, null); assert.equal(a.data.exception, null);
    assert.equal(a.data.exceptionHistory.length, 1); assert.equal(a.data.exceptionHistory[0].expiredAt, NOW);
    assert.ok(a.data.history.some((h) => h.field === "exception" && h.uid === "system:sla"));
    assert.equal(out[1].updates.status, undefined, "an open finding keeps its status");
  });
  test("exceptionHistory capped at 20", () => {
    const hist = Array.from({ length: 20 }, (_, i) => ({ reason: "r" + i }));
    const out = expiredExceptions([F({ data: { exception: exc(-1), exceptionHistory: hist } })], NOW);
    assert.equal(out[0].updates.data.exceptionHistory.length, 20);
    assert.equal(out[0].updates.data.exceptionHistory[0].reason, "r1");
  });
});

group("workflow: inView", () => {
  const o = { uid: "u1", now: NOW, policy: SLA_DEFAULTS };
  test("mine and unassigned", () => {
    assert.ok(inView(F({ data: { owner: "u1" } }), "mine", o));
    assert.ok(!inView(F({ data: { owner: "u2" } }), "mine", o));
    assert.ok(!inView(F({ status: "resolved", data: { owner: "u1", resolution: "fixed" } }), "mine", o), "closed excluded");
    assert.ok(!inView(F({ data: { owner: "u1" } }), "mine", { ...o, uid: null }));
    assert.ok(inView(F(), "unassigned", o));
    assert.ok(!inView(F({ data: { owner: "u2" } }), "unassigned", o));
  });
  test("overdue and due_week", () => {
    assert.ok(inView(F(), "overdue", { ...o, now: T0 + 61 * DAY_MS }));
    assert.ok(!inView(F(), "overdue", o));
    assert.ok(inView(F(), "due_week", { ...o, now: T0 + 55 * DAY_MS }));
    assert.ok(!inView(F(), "due_week", { ...o, now: T0 + 61 * DAY_MS }), "overdue is not due this week");
    assert.ok(!inView(F({ status: "closed", data: { resolution: "fixed" } }), "overdue", { ...o, now: T0 + 99 * DAY_MS }));
  });
  test("excepted, open and all; sample only in all", () => {
    assert.ok(inView(F({ data: { exception: exc() } }), "excepted", o));
    assert.ok(!inView(F({ data: { exception: exc(-1) } }), "excepted", o));
    assert.ok(inView(F({ status: "investigating" }), "open", o));
    assert.ok(!inView(F({ status: "resolved" }), "open", o));
    assert.ok(inView(F({ status: "closed" }), "all", o));
    const s = F({ tags: ["sample"] });
    for (const v of VIEWS) assert.equal(inView(s, v, o), v === "all", v);
    assert.ok(!inView(F(), "nonsense", o));
  });
});

group("workflow: timeline + determinism", () => {
  test("merges history and comments ascending by ts", () => {
    const e = F({ data: {
      history: [{ ts: 30, uid: "a", field: "status", from: "open", to: "resolved" }, { ts: 10, uid: "a", field: "owner", from: null, to: "a" }],
      comments: [{ ts: 20, uid: "b", text: "why" }, { ts: 30, uid: "b", text: "same ts" }],
    } });
    const tl = timeline(e);
    assert.deepEqual(tl.map((x) => x.ts), [10, 20, 30, 30]);
    assert.deepEqual(tl.map((x) => x.kind), ["change", "comment", "change", "comment"]);
    assert.deepEqual(tl[1], { ts: 20, uid: "b", kind: "comment", text: "why" });
    assert.deepEqual(tl[0], { ts: 10, uid: "a", kind: "change", field: "owner", from: null, to: "a" });
    assert.deepEqual(timeline(F()), []);
  });
  test("same inputs give identical outputs", () => {
    const c = { op: "exception", reason: "r", approver: "a", expiresAt: NOW + DAY_MS };
    assert.deepEqual(applyChange(F(), c, ctx), applyChange(F(), c, ctx));
    assert.deepEqual(slaState(F(), SLA_DEFAULTS, NOW), slaState(F(), SLA_DEFAULTS, NOW));
    assert.deepEqual(reconcileRun("tool", "ds.csv", [F()], [], { now: NOW }), reconcileRun("tool", "ds.csv", [F()], [], { now: NOW }));
  });
});

group("workflow fields survive tool re-runs (sink-map)", () => {
  const wf = {
    owner: "u1", ownerLabel: "Ana", history: [{ ts: 1 }], historyCount: 1, comments: [{ ts: 2, text: "x" }], commentCount: 1,
    exception: exc(), exceptionHistory: [], tickets: [{ url: "https://t.example/1" }], dueAt: 5, dueReason: "r",
    severityOverride: { from: "high", to: "critical" }, regressed: true, regressedAt: 3, verifiedBy: "tool", verifiedAt: 4,
  };
  test("WORKFLOW_FIELDS lists every protected field", () => {
    assert.deepEqual(WORKFLOW_FIELDS.slice().sort(), Object.keys(wf).sort());
  });
  test("a same-tool re-run keeps every workflow field and the resolution", () => {
    const prev = { findingKey: "k1", tool: "tool", description: "old", resolution: "fixed", ...wf, _toolSource: "tool" };
    const { items } = toEntities("tool", [{ title: "t", severity: "high", description: "new" }], { dataset: "ds" });
    const inc = { ...items.find((i) => i.type === "FINDING").data, owner: "attacker", history: [], exception: null };
    const m = mergeToolData(prev, inc, "tool");
    for (const k of WORKFLOW_FIELDS) assert.deepEqual(m[k], wf[k], k);
    assert.equal(m.description, "new");
    assert.equal(m.resolution, "fixed", "an unset incoming resolution keeps the recorded one");
    assert.equal(mergeToolData(prev, { resolution: "duplicate" }, "tool").resolution, "duplicate", "an explicit resolution still applies");
  });
  test("a second tool cannot set or move workflow fields, and bySource never holds them", () => {
    const prev = { a: 1, ...wf, _toolSource: "t1" };
    const m = mergeToolData(prev, { b: 2, owner: "x", tickets: [] }, "t2");
    for (const k of WORKFLOW_FIELDS) assert.deepEqual(m[k], wf[k], k);
    for (const src of Object.values(m.bySource)) for (const k of WORKFLOW_FIELDS) assert.ok(!(k in src), k);
    const fresh = mergeToolData({ a: 1, _toolSource: "t1" }, { owner: "x" }, "t1");
    assert.ok(!("owner" in fresh), "a tool cannot introduce a workflow field");
  });
  test("a severity override is not reset by a re-run", () => {
    assert.equal(toolSeverity({ severityOverride: { to: "critical" } }, "low"), null);
    assert.equal(toolSeverity({}, "low"), "low");
    assert.equal(toolSeverity(null, undefined), null);
  });
  test("a sink finding is reopened only by reconcileRun, never by nextStatus", () => {
    assert.equal(nextStatus("resolved", "open", "fixed", true), null);
    assert.equal(nextStatus("closed", "new", "fixed", true), null);
    assert.equal(nextStatus("resolved", "open", "fixed"), "open", "non-sink entities keep the old behaviour");
    assert.equal(nextStatus("open", "resolved", undefined, true), "resolved", "a tool may still resolve");
  });
});
