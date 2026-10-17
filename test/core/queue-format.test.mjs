// Unit tests for public/js/core/queue-format.js (Deck findings work-queue presentation).
import { test, group, assert } from "../harness.mjs";
import {
  RESOLUTION_LABEL, dueChip, slaBasis, urgencySort, cleanTitle, memberName, whoLabel, timelineSentences,
  evidenceLines, summarizeBulk, dateInputToMs, localDay, exceptionMaxDay, normalizeSaved, upsertSaved, removeSaved,
  statusText, isoDay,
} from "../../public/js/core/queue-format.js";
import { DAY_MS, SLA_DEFAULTS, slaState, timeline, applyChange, applyBulk, RESOLUTIONS, VIEWS } from "../../public/js/core/workflow.js";

const T0 = Date.UTC(2026, 0, 1);
const F = (over = {}) => ({ id: "f1", type: "FINDING", name: "Open bucket (tool:k1)", severity: "high", status: "open", createdAt: new Date(T0).toISOString(), data: { tool: "tool", findingKey: "k1" }, ...over });

group("queue-format: due chip", () => {
  test("overdue shows whole days overdue, at least 1", () => {
    const due = T0 + 60 * DAY_MS;
    assert.deepEqual(dueChip({ state: "overdue", dueAt: due, daysLeft: -3 }, due + 3 * DAY_MS), { cls: "overdue", text: "3d overdue" });
    assert.deepEqual(dueChip({ state: "overdue", dueAt: due, daysLeft: 0 }, due + 3600000), { cls: "overdue", text: "1d overdue" });
  });
  test("due soon, on track, exception and none", () => {
    assert.deepEqual(dueChip({ state: "due_soon", dueAt: 1, daysLeft: 4 }, 0), { cls: "soon", text: "Due in 4d" });
    assert.deepEqual(dueChip({ state: "due_soon", dueAt: 1, daysLeft: 0 }, 0), { cls: "soon", text: "Due today" });
    assert.deepEqual(dueChip({ state: "on_track", dueAt: Date.UTC(2026, 2, 2), daysLeft: 40 }, 0), { cls: "track", text: "2026-03-02" });
    assert.deepEqual(dueChip({ state: "excepted", dueAt: 5, daysLeft: 1 }, 0), { cls: "exc", text: "Exception" });
    assert.deepEqual(dueChip({ state: "none", dueAt: null, daysLeft: null }, 0), { cls: "none", text: "-" });
    assert.deepEqual(dueChip({ state: "closed", dueAt: 5, daysLeft: 1 }, 0), { cls: "none", text: "-" });
  });
  test("agrees with slaState for a real finding", () => {
    const e = F();
    const now = T0 + 65 * DAY_MS;
    assert.equal(dueChip(slaState(e, SLA_DEFAULTS, now), now).text, "5d overdue");
  });
});

group("queue-format: SLA basis", () => {
  test("severity, KEV, manual and no-SLA lines", () => {
    assert.equal(slaBasis(F(), SLA_DEFAULTS), "High: 60 days from first seen (2026-01-01)");
    assert.equal(slaBasis(F({ name: "CVE-2024-1234 in lib" }), SLA_DEFAULTS, new Set(["CVE-2024-1234"])), "Known exploited (CISA KEV): 14 days from first seen");
    assert.equal(slaBasis(F({ data: { dueAt: T0, dueReason: "Vendor patch date" } }), SLA_DEFAULTS), "Set manually: Vendor patch date");
    assert.equal(slaBasis(F({ severity: "info" }), SLA_DEFAULTS), "No SLA for info severity");
    assert.equal(slaBasis(F({ severity: "low" }), { ...SLA_DEFAULTS, low: null }), "No SLA for low severity");
    assert.equal(slaBasis(F({ severity: null }), SLA_DEFAULTS), "No severity, so no SLA");
  });
  test("KEV does not lengthen a shorter severity SLA", () => {
    assert.equal(slaBasis(F({ severity: "critical", name: "CVE-2024-1234" }), { ...SLA_DEFAULTS, critical: 7 }, new Set(["CVE-2024-1234"])), "Critical: 7 days from first seen (2026-01-01)");
  });
});

group("queue-format: urgency sort", () => {
  test("overdue first (most overdue first), then due soon, on track, none; ties by severity", () => {
    const rows = [
      { id: "none", severity: "critical", s: { state: "none", dueAt: null } },
      { id: "track", severity: "low", s: { state: "on_track", dueAt: 900 } },
      { id: "soon", severity: "low", s: { state: "due_soon", dueAt: 500 } },
      { id: "od2", severity: "low", s: { state: "overdue", dueAt: 200 } },
      { id: "od1", severity: "medium", s: { state: "overdue", dueAt: 100 } },
      { id: "od1b", severity: "critical", s: { state: "overdue", dueAt: 100 } },
    ];
    assert.deepEqual(urgencySort(rows, (r) => r.s).map((r) => r.id), ["od1b", "od1", "od2", "soon", "track", "none"]);
    assert.equal(rows[0].id, "none", "input not mutated");
  });
});

group("queue-format: names and labels", () => {
  test("cleanTitle strips only the sink suffix", () => {
    assert.equal(cleanTitle(F()), "Open bucket");
    assert.equal(cleanTitle(F({ name: "Manual note (tool:other)" })), "Manual note (tool:other)");
    assert.equal(cleanTitle({ name: "Plain" }), "Plain");
  });
  test("memberName: label, you, fallback, short uid, unassigned", () => {
    const members = [{ uid: "u1", label: "Analyst One" }, { uid: "u2", label: "" }];
    assert.equal(memberName("u1", members), "Analyst One");
    assert.equal(memberName("u1", members, { myUid: "u1" }), "Analyst One (you)");
    assert.equal(memberName("gone", members, { fallback: "Former member" }), "Former member");
    assert.equal(memberName("abcdefghijklmnop", members), "abcdefgh...");
    assert.equal(memberName(null, members), "Unassigned");
  });
  test("whoLabel renders tool re-runs and the expiry check", () => {
    assert.equal(whoLabel("system:codescan"), "codescan re-run");
    assert.equal(whoLabel("system:sla"), "Exception expiry check");
    assert.equal(whoLabel("system:codescan", null, (t) => (t === "codescan" ? "Code Scanner" : null)), "Code Scanner re-run");
    assert.equal(whoLabel("system:other", null, () => null), "other re-run");
    assert.equal(whoLabel(null), "Someone");
    assert.equal(whoLabel("u1", (u) => "Name " + u), "Name u1");
  });
  test("statusText and every resolution has a label", () => {
    assert.equal(statusText("resolved", "false_positive"), "Resolved (false positive)");
    assert.equal(statusText("open", null), "Open");
    for (const r of RESOLUTIONS) assert.ok(RESOLUTION_LABEL[r], r);
  });
});

group("queue-format: timeline sentences", () => {
  const nameOf = (u) => ({ u1: "Analyst One", u2: "Lead Two" }[u] || u);
  test("status + resolution merge into one sentence; assign; severity; due; ticket; comment", () => {
    let e = F();
    const step = (change, uid, now) => { const r = applyChange(e, change, { uid, now }); assert.ok(!r.error, r.error); e = { ...e, ...(r.updates.status ? { status: r.updates.status } : {}), ...(r.updates.severity ? { severity: r.updates.severity } : {}), data: { ...e.data, ...r.updates.data } }; };
    step({ op: "assign", owner: "u2", ownerLabel: "Lead Two" }, "u1", T0 + 1);
    step({ op: "severity", severity: "critical", reason: "Internet facing" }, "u1", T0 + 2);
    step({ op: "due", dueAt: Date.UTC(2026, 1, 1), reason: "Change window" }, "u2", T0 + 3);
    step({ op: "ticket", url: "https://tracker.test/browse/SEC-1", label: "SEC-1" }, "u2", T0 + 4);
    step({ op: "comment", text: "Patched on staging\nprod next" }, "u2", T0 + 5);
    step({ op: "status", status: "resolved", resolution: "fixed" }, "u2", T0 + 6);
    step({ op: "assign", owner: null }, "u1", T0 + 7);
    step({ op: "assign", owner: "u1" }, "u1", T0 + 8);
    const s = timelineSentences(timeline(e), { nameOf });
    assert.deepEqual(s.map((x) => x.text), [
      "Analyst One assigned to Lead Two",
      "Analyst One changed severity from high to critical",
      "Lead Two set the due date to 2026-02-01",
      "Lead Two linked a ticket",
      "Lead Two commented",
      "Lead Two changed status from open to resolved (fixed)",
      "Analyst One unassigned the finding",
      "Analyst One took ownership",
    ]);
    assert.equal(s[4].comment, "Patched on staging\nprod next");
  });
  test("tool re-run regression and exception lifecycle", () => {
    const rows = [
      { ts: 1, uid: "system:codescan", kind: "change", field: "status", from: "resolved", to: "open" },
      { ts: 1, uid: "system:codescan", kind: "change", field: "resolution", from: "fixed", to: null },
      { ts: 2, uid: "u1", kind: "change", field: "exception", from: null, to: Date.UTC(2026, 5, 30) },
      { ts: 3, uid: "u1", kind: "change", field: "exception", from: Date.UTC(2026, 5, 30), to: Date.UTC(2026, 6, 30) },
      { ts: 4, uid: "u1", kind: "change", field: "exception", from: Date.UTC(2026, 6, 30), to: null },
      { ts: 5, uid: "system:sla", kind: "change", field: "exception", from: 9, to: null },
      { ts: 6, uid: "u1", kind: "change", field: "resolution", from: null, to: "duplicate" },
      { ts: 7, uid: "u1", kind: "change", field: "dueAt", from: Date.UTC(2026, 1, 1), to: null },
    ];
    assert.deepEqual(timelineSentences(rows, { nameOf }).map((x) => x.text), [
      "codescan re-run changed status from resolved to open",
      "Analyst One added a risk exception until 2026-06-30",
      "Analyst One replaced the risk exception (now until 2026-07-30)",
      "Analyst One revoked the risk exception",
      "The risk exception expired",
      "Analyst One set the resolution to duplicate",
      "Analyst One cleared the manual due date",
    ]);
  });
});

group("queue-format: evidence and bulk summaries", () => {
  test("evidenceLines caps lines and reports the rest", () => {
    const ev = evidenceLines({ evidence: ["a\nb", { k: 1 }, "c"], evidenceTruncated: true }, 3);
    assert.deepEqual(ev, { lines: ["a", "b", '{"k":1}'], more: 1, truncated: true });
    assert.deepEqual(evidenceLines({}), { lines: [], more: 0, truncated: false });
  });
  test("summarizeBulk counts updates, no-ops and skip reasons", () => {
    assert.equal(summarizeBulk([{ id: "a", updates: {} }, { id: "b", updates: {} }, { id: "c", updates: {} }, { id: "d", error: "Accepting a risk needs an exception with an expiry" }]).text,
      "3 updated, 1 skipped: Accepting a risk needs an exception with an expiry");
    assert.equal(summarizeBulk([{ id: "a", updates: {}, noop: true }, { id: "b", error: "X" }, { id: "c", error: "Y" }, { id: "d", error: "Y" }]).text, "0 updated, 1 unchanged, 3 skipped: X (1); Y (2)");
  });
  test("real applyBulk: accepted without an exception is skipped with the engine's reason", () => {
    const now = T0 + DAY_MS;
    const withExc = F({ id: "f2", data: { tool: "tool", findingKey: "k2", exception: { reason: "r", approver: "a", expiresAt: now + 30 * DAY_MS } } });
    const res = applyBulk([F(), withExc], { op: "status", status: "resolved", resolution: "accepted" }, { uid: "u1", now });
    assert.equal(summarizeBulk(res).text, "1 updated, 1 skipped: Accepting a risk needs an exception with an expiry");
  });
});

group("queue-format: dates", () => {
  test("dateInputToMs is the end of that local day, clamped, and rejects bad input", () => {
    const ms = dateInputToMs("2026-03-04");
    const d = new Date(ms);
    assert.deepEqual([d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(), d.getMinutes()], [2026, 2, 4, 23, 59]);
    assert.equal(dateInputToMs("2026-03-04", { maxMs: 5 }), 5);
    assert.equal(dateInputToMs("2026-02-30"), null);
    assert.equal(dateInputToMs("03/04/2026"), null);
    assert.equal(localDay(ms), "2026-03-04");
  });
  test("exception max day is 365 days out and accepted by the engine once clamped", () => {
    const now = Date.UTC(2026, 0, 10, 12);
    const max = exceptionMaxDay(now);
    const exp = dateInputToMs(max, { maxMs: now + 365 * DAY_MS });
    const r = applyChange(F(), { op: "exception", reason: "r", approver: "a", expiresAt: exp }, { uid: "u1", now });
    assert.ok(!r.error, r.error);
    assert.equal(isoDay(Date.UTC(2026, 0, 2)), "2026-01-02");
  });
});

group("queue-format: saved views", () => {
  test("normalize, upsert (case-insensitive replace) and remove", () => {
    let list = normalizeSaved([{ name: " Mine ", view: "mine", f: { q: "s3", sim: 1 } }, { name: "mine", view: "all" }, { name: "", view: "all" }, { name: "Bad", view: "nope" }, null], VIEWS);
    assert.deepEqual(list.map((v) => [v.name, v.view, v.f.q, v.f.sim]), [["Mine", "mine", "s3", true], ["Bad", "open", "", false]]);
    list = upsertSaved(list, { name: "MINE", view: "overdue", f: { severity: "high" }, ts: 1 }, VIEWS);
    assert.deepEqual(list.map((v) => [v.name, v.view, v.f.severity]), [["Bad", "open", ""], ["MINE", "overdue", "high"]]);
    list = removeSaved(list, "bad", VIEWS);
    assert.deepEqual(list.map((v) => v.name), ["MINE"]);
    assert.deepEqual(normalizeSaved("junk", VIEWS), []);
  });
});
