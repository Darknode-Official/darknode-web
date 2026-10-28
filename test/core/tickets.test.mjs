// Unit tests for public/js/core/tickets.js (pure ticket export formats)
import { test, group, assert } from "../harness.mjs";
import {
  TICKET_TARGETS, TICKET_LIMITS, ticketFields, toJiraCsv, toServiceNowCsv, toAzureDevOpsCsv, githubIssuePayload,
  csvCell, jiraLabel, adoTag, ghLabel, parseRepo, hasGithubTicket, isoDate, exportable,
} from "../../public/js/core/tickets.js";

// Minimal RFC 4180 parser so assertions read cells, not raw text.
function parseCsv(text) {
  const rows = []; let row = [], cell = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; } else if (c === '"') q = false; else cell += c; }
    else if (c === '"') q = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\r" && text[i + 1] === "\n") { row.push(cell); rows.push(row); row = []; cell = ""; i++; }
    else cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows;
}

const F = (over = {}) => ({
  id: "ent1", type: "FINDING", name: "Public bucket (cloudposture:abc123)", severity: "high", status: "open",
  createdAt: new Date(2026, 9, 1, 12).getTime(), updatedAt: new Date(2026, 9, 2, 12).getTime(), tags: ["sink", "cloudposture"],
  ...over,
  data: {
    findingKey: "abc123", tool: "cloudposture", dataset: "run-1", assets: ["bucket-a", "bucket-b"],
    controls: [{ framework: "CIS", id: "2.1.1" }, { framework: "NIST-CSF", id: "PR.DS-1" }],
    evidence: [{ bucket: "bucket-a", acl: "public-read" }], description: "Bucket allows anonymous read.", recommendation: "Block public access.",
    ...(over.data || {}),
  },
});

group("core/tickets", () => {
  test("targets list", () => {
    assert.deepEqual(TICKET_TARGETS, ["jira", "servicenow", "azure_devops", "github"]);
  });

  test("ticketFields shape and title strips the (tool:key) suffix", () => {
    const t = ticketFields(F());
    assert.deepEqual(Object.keys(t).sort(), ["assets", "body", "dueDate", "labels", "priority", "severity", "sourceRef", "title"]);
    assert.equal(t.title, "Public bucket");
    assert.equal(t.severity, "high");
    assert.equal(t.priority, "High");
    assert.deepEqual(t.labels, ["darknode", "high", "cloudposture"]);
    assert.deepEqual(t.assets, ["bucket-a", "bucket-b"]);
    assert.equal(t.dueDate, null);
    assert.equal(t.sourceRef, "Darknode finding: abc123 (cloudposture)");
  });

  test("body carries description, recommendation, assets, controls, evidence, dates and the reference line", () => {
    const b = ticketFields(F({ data: { dueAt: new Date(2026, 10, 15, 12).toISOString() } })).body;
    for (const s of ["Bucket allows anonymous read.", "Block public access.", "bucket-b", "CIS 2.1.1", "NIST-CSF PR.DS-1", "acl: public-read", "First seen: 2026-10-01", "Due: 2026-11-15", "Darknode finding: abc123 (cloudposture)"])
      assert.ok(b.includes(s), "body has " + s);
    assert.ok(b.trim().endsWith("Darknode finding: abc123 (cloudposture)"));
  });

  test("evidence is capped at 10 lines with a remainder note", () => {
    const ev = Array.from({ length: 14 }, (_, i) => ({ n: i }));
    const b = ticketFields(F({ data: { evidence: ev, evidenceCount: 30 } })).body;
    assert.ok(b.includes("n: 9"));
    assert.notOk(b.includes("n: 10"));
    assert.ok(b.includes("20 more evidence item(s)"));
  });

  test("priority mapping, generic (Jira scale)", () => {
    const p = (s) => ticketFields(F({ severity: s })).priority;
    assert.deepEqual(["critical", "high", "medium", "low", "info"].map(p), ["Highest", "High", "Medium", "Low", "Lowest"]);
    assert.equal(p("bogus"), "Lowest");
  });

  test("isoDate handles ms, ISO, plain dates, Firestore timestamps and junk", () => {
    assert.equal(isoDate(new Date(2026, 0, 2, 12).getTime()), "2026-01-02");
    assert.equal(isoDate(new Date(2026, 2, 4, 10).toISOString()), "2026-03-04");
    assert.equal(isoDate("2026-03-04"), "2026-03-04");
    assert.equal(isoDate({ seconds: new Date(2026, 4, 6, 12).getTime() / 1000 }), "2026-05-06");
    assert.equal(isoDate({ toMillis: () => new Date(2026, 6, 8, 12).getTime() }), "2026-07-08");
    assert.equal(isoDate("not a date"), null);
    // a due date picked as Nov 5 is stored as 23:59:59 local; it must not export as Nov 6
    assert.equal(isoDate(new Date(2026, 10, 5, 23, 59, 59).getTime()), "2026-11-05");
    assert.equal(isoDate(null), null);
  });

  test("Jira CSV header row repeats Labels once per label", () => {
    const rows = parseCsv(toJiraCsv([F()]));
    assert.deepEqual(rows[0], ["Summary", "Issue Type", "Priority", "Due Date", "Description", "Labels", "Labels", "Labels"]);
    assert.deepEqual(rows[1].slice(0, 4), ["Public bucket", "Task", "High", ""]);
    assert.deepEqual(rows[1].slice(5), ["darknode", "high", "cloudposture"]);
  });

  test("Jira CSV custom issue type, due date and wider label set pads shorter rows", () => {
    const rows = parseCsv(toJiraCsv([F({ data: { dueAt: new Date(2026, 10, 1, 12).getTime() } }), F({ id: "e2", severity: "low" })], { issueType: "Bug", labels: ["team red"] }));
    assert.equal(rows[0].filter((h) => h === "Labels").length, 4);
    assert.equal(rows[1][1], "Bug");
    assert.equal(rows[1][3], "2026-11-01");
    assert.deepEqual(rows[1].slice(5), ["darknode", "high", "cloudposture", "team-red"]);
    assert.equal(rows[2][2], "Low");
  });

  test("Jira label sanitisation: no whitespace, deduped case-insensitively", () => {
    assert.equal(jiraLabel("  cloud  posture\tscan "), "cloud-posture-scan");
    const rows = parseCsv(toJiraCsv([F()], { labels: ["DARKNODE", "High"] }));
    assert.deepEqual(rows[1].slice(5), ["darknode", "high", "cloudposture"]);
  });

  test("Jira summary capped at 255 characters", () => {
    const rows = parseCsv(toJiraCsv([F({ name: "x".repeat(400) })]));
    assert.equal(rows[1][0].length, TICKET_LIMITS.jiraSummary);
    assert.ok(rows[1][0].endsWith("..."));
  });

  test("ServiceNow CSV header row uses incident field names", () => {
    const rows = parseCsv(toServiceNowCsv([F()]));
    assert.deepEqual(rows[0], ["short_description", "description", "impact", "urgency", "category", "due_date", "correlation_id", "correlation_display"]);
    assert.deepEqual([rows[1][0], rows[1][4], rows[1][6], rows[1][7]], ["Public bucket", "", "abc123", "Darknode"]);
  });

  test("ServiceNow impact/urgency follow the 1-3 scale (lookup gives P1..P5)", () => {
    const iu = (s) => parseCsv(toServiceNowCsv([F({ severity: s })]))[1].slice(2, 4);
    assert.deepEqual(iu("critical"), ["1", "1"]);
    assert.deepEqual(iu("high"), ["2", "1"]);
    assert.deepEqual(iu("medium"), ["2", "2"]);
    assert.deepEqual(iu("low"), ["2", "3"]);
    assert.deepEqual(iu("info"), ["3", "3"]);
  });

  test("ServiceNow fields never contain double quotes; short_description capped at 160", () => {
    const out = toServiceNowCsv([F({ name: 'Say "hi" ' + "y".repeat(300), data: { description: 'He said "no"' } })], { category: "security" });
    const rows = parseCsv(out);
    assert.notOk(rows[1].some((c) => c.includes('"')));
    assert.ok(rows[1][1].includes("He said 'no'"));
    assert.equal(rows[1][0].length, TICKET_LIMITS.snowShortDescription);
    assert.equal(rows[1][4], "security");
  });

  test("Azure DevOps CSV header row has the required columns and no ID", () => {
    const rows = parseCsv(toAzureDevOpsCsv([F()]));
    assert.deepEqual(rows[0], ["Work Item Type", "Title", "Description", "Priority", "Tags"]);
    assert.notOk(rows[0].includes("ID"));
    assert.deepEqual([rows[1][0], rows[1][1], rows[1][3], rows[1][4]], ["Task", "Public bucket", "2", "darknode; high; cloudposture"]);
  });

  test("Azure DevOps priority 1-4 and custom work item type", () => {
    const pr = (s) => parseCsv(toAzureDevOpsCsv([F({ severity: s })], { workItemType: "Bug" }))[1];
    assert.deepEqual(["critical", "high", "medium", "low", "info"].map((s) => pr(s)[3]), ["1", "2", "3", "4", "4"]);
    assert.equal(pr("high")[0], "Bug");
  });

  test("Azure DevOps description is escaped HTML and tags strip the ; separator", () => {
    const rows = parseCsv(toAzureDevOpsCsv([F({ data: { description: "a <script> & b\nline two" } })], { labels: ["x;y"] }));
    assert.ok(rows[1][2].startsWith("<p>a &lt;script&gt; &amp; b</p><p>line two</p>"));
    assert.ok(rows[1][4].endsWith("; x y"));
    assert.equal(adoTag(" a ; b "), "a b");
  });

  test("CSV escaping: commas, quotes and newlines are quoted per RFC 4180", () => {
    assert.equal(csvCell("plain"), "plain");
    assert.equal(csvCell("a,b"), '"a,b"');
    assert.equal(csvCell('say "x"'), '"say ""x"""');
    assert.equal(csvCell("l1\nl2"), '"l1\nl2"');
    assert.equal(csvCell("l1\r\nl2"), '"l1\r\nl2"');
    const rows = parseCsv(toJiraCsv([F({ name: 'Weak, "default" creds' })]));
    assert.equal(rows[1][0], 'Weak, "default" creds');
    assert.ok(rows[1][4].includes("\n"), "multi-line description survives a round trip");
  });

  test("CSV rows end with CRLF", () => {
    const out = toAzureDevOpsCsv([F()]);
    assert.ok(out.endsWith("\r\n"));
    assert.equal(out.split("\r\n")[0], "Work Item Type,Title,Description,Priority,Tags");
  });

  test("formula-injection guard prefixes = + - @ TAB CR", () => {
    for (const s of ["=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "\rx"]) assert.ok(csvCell(s).replace(/^"/, "").startsWith("'" + s[0]), s);
    assert.equal(csvCell("safe=1"), "safe=1");
    const rows = parseCsv(toJiraCsv([F({ name: '=HYPERLINK("http://x","y")' })]));
    assert.ok(rows[1][0].startsWith("'="));
    const sn = parseCsv(toServiceNowCsv([F({ data: { description: "@evil" } })]));
    assert.ok(sn[1][1].startsWith("'@"));
  });

  test("sample and simulated entities are excluded from every export", () => {
    const list = [F(), F({ id: "s1", name: "Sample one", tags: ["sink", "sample"] }), F({ id: "s2", name: "Sim two", data: { simulated: true } })];
    assert.equal(exportable(list).length, 1);
    assert.equal(parseCsv(toJiraCsv(list)).length, 2);
    assert.equal(parseCsv(toServiceNowCsv(list)).length, 2);
    assert.equal(parseCsv(toAzureDevOpsCsv(list)).length, 2);
    assert.equal(githubIssuePayload(list[1]), null);
    assert.equal(githubIssuePayload(list[2]), null);
  });

  test("empty input gives a header-only CSV", () => {
    assert.equal(parseCsv(toJiraCsv([])).length, 1);
    assert.equal(parseCsv(toJiraCsv([]))[0].filter((h) => h === "Labels").length, 1);
    assert.equal(toServiceNowCsv(null).split("\r\n").length, 2);
  });

  test("GitHub payload shape", () => {
    const p = githubIssuePayload(F());
    assert.deepEqual(Object.keys(p).sort(), ["body", "labels", "title"]);
    assert.equal(p.title, "Public bucket");
    assert.deepEqual(p.labels, ["darknode", "high", "cloudposture"]);
    assert.ok(p.body.includes("### Recommendation"));
    assert.ok(p.body.endsWith("Darknode finding: abc123 (cloudposture)"));
  });

  test("GitHub label limits: 50 chars each, at most 10, commas removed", () => {
    assert.equal(ghLabel("a,b  c"), "a b c");
    assert.equal(ghLabel("z".repeat(80)).length, TICKET_LIMITS.ghLabel);
    const many = Array.from({ length: 20 }, (_, i) => "extra" + i);
    const p = githubIssuePayload(F(), { labels: many });
    assert.equal(p.labels.length, TICKET_LIMITS.ghLabels);
    assert.deepEqual(p.labels.slice(0, 3), ["darknode", "high", "cloudposture"]);
  });

  test("GitHub title capped at 256 and body at 65536 code points keeping the reference", () => {
    const p = githubIssuePayload(F({ name: "t".repeat(300), data: { description: "d".repeat(70000) } }));
    assert.equal(p.title.length, 256);
    assert.equal(Array.from(p.body).length, TICKET_LIMITS.ghBody);
    assert.ok(p.body.endsWith("Darknode finding: abc123 (cloudposture)"));
  });

  test("parseRepo validates owner/repo", () => {
    assert.deepEqual(parseRepo(" my-org/my.repo_1 "), { owner: "my-org", repo: "my.repo_1" });
    for (const bad of ["", "owner", "owner/", "/repo", "a/b/c", "-bad/repo", "owner/repo.git", "own er/repo", "owner/..", "https://github.com/a/b"])
      assert.equal(parseRepo(bad), null, bad);
  });

  test("hasGithubTicket matches the same repo only, case-insensitively", () => {
    const e = F({ data: { tickets: [{ url: "https://github.com/My-Org/Repo/issues/7", label: "GitHub #7" }, { url: "https://jira.invalid/browse/X-1" }] } });
    assert.ok(hasGithubTicket(e, "my-org", "repo"));
    assert.notOk(hasGithubTicket(e, "my-org", "repo2"));
    assert.notOk(hasGithubTicket(F(), "my-org", "repo"));
  });

  test("deterministic: identical input gives identical bytes, input not mutated", () => {
    const a = [F(), F({ id: "e2", severity: "critical", name: "Other (cloudposture:def456)", data: { findingKey: "def456" } })];
    const snap = JSON.stringify(a);
    assert.equal(toJiraCsv(a), toJiraCsv(JSON.parse(snap)));
    assert.equal(toServiceNowCsv(a), toServiceNowCsv(JSON.parse(snap)));
    assert.equal(toAzureDevOpsCsv(a), toAzureDevOpsCsv(JSON.parse(snap)));
    assert.deepEqual(githubIssuePayload(a[1]), githubIssuePayload(JSON.parse(snap)[1]));
    assert.equal(JSON.stringify(a), snap);
  });

  test("tolerates sparse entities", () => {
    const t = ticketFields({ id: "x9", type: "FINDING", name: "Bare" });
    assert.equal(t.title, "Bare");
    assert.equal(t.severity, "info");
    assert.equal(t.sourceRef, "Darknode finding: x9 (darknode)");
    assert.equal(parseCsv(toAzureDevOpsCsv([{ id: "x9", name: "Bare" }])).length, 2);
  });
});
