// Code Scanner commit watch, CI workflow generator and CLI.
// Commit-range diffing runs on fixture data (GitHub API shapes, no network); the CLI
// runs against a throwaway git repository with a planted fake secret and a taint flow.
// This file holds deliberately vulnerable samples, so .darknodeignore excludes it.

import { test, assert, group } from "../harness.mjs";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { scanFile } from "../../public/js/codescan/rules.js";
import { diffFile, findingKey } from "../../public/js/codescan/baseline.js";
import { ignoreMatcher } from "../../public/js/codescan/github.js";
import { newWatch, listNewCommits, commitMeta, planCommit, applyCommit, chip, graphItem, toItem, watchKey } from "../../public/js/codescan/watch.js";
import { workflowYaml, toBase64, SCANNER_FILES, WORKFLOW_PATH } from "../../public/js/codescan/ci.js";
import { main, parseArgs, parseNameStatus } from "../../public/js/codescan/cli.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");
const scan = (path, text) => scanFile(path, text).map((f) => ({ ...f, path }));

// Fixture sources: a planted (fake) AWS key, and an Express handler feeding a query
// parameter into child_process.exec (a real taint flow the engine traces).
const SECRET_SRC = 'const k = "AKIAQ3EGRT7XZPLM4NHA";\nmodule.exports = k;\n';
const TAINT_SRC = 'const { exec } = require("child_process");\nconst app = require("express")();\napp.get("/run", (req, res) => {\n  const host = req.query.host;\n  exec("ping -c 1 " + host, () => res.end());\n});\n';
const CLEAN_SRC = "export const add = (a, b) => a + b;\n";

// GitHub /commits list entries, newest first.
const gc = (sha, parent, msg, login = "dev") => ({ sha, parents: parent ? [{ sha: parent }] : [], author: { login }, html_url: "https://github.com/o/r/commit/" + sha, commit: { message: msg + "\n\nbody", committer: { date: "2026-10-01T10:00:00Z" } } });
const history = ["s9", "s8", "s7", "s6", "s5", "s4", "s3", "s2", "s1"].map((s, i, a) => gc(s, a[i + 1] || "", "commit " + s));
const pager = (list) => async (page, per) => list.slice((page - 1) * per, page * per);

group("codescan watch: listing new commits", () => {
  test("stops at the last scanned commit, oldest first", async () => {
    const r = await listNewCommits(pager(history), "s6", 100);
    assert.deepEqual(r.commits.map((c) => c.sha), ["s7", "s8", "s9"]);
    assert.ok(r.found && !r.capped && !r.exhausted);
  });
  test("nothing new when HEAD is the last scanned commit", async () => {
    const r = await listNewCommits(pager(history), "s9", 100);
    assert.equal(r.commits.length, 0); assert.ok(r.found);
  });
  test("walks several pages", async () => {
    const long = Array.from({ length: 150 }, (_, i) => gc("c" + (149 - i), i < 149 ? "c" + (148 - i) : "", "m"));
    const calls = [];
    const r = await listNewCommits(async (page, per) => { calls.push([page, per]); return long.slice((page - 1) * per, page * per); }, "c0", 200);
    assert.deepEqual(calls, [[1, 100], [2, 100]]);
    assert.equal(r.commits.length, 149); assert.ok(r.found);
    assert.equal(r.commits[0].sha, "c1"); assert.equal(r.commits[148].sha, "c149");
  });
  test("caps the walk and says so", async () => {
    const r = await listNewCommits(pager(history), "s1", 4);
    assert.deepEqual(r.commits.map((c) => c.sha), ["s6", "s7", "s8", "s9"]);
    assert.ok(r.capped && !r.found && !r.exhausted);
  });
  test("force-push: the known commit is not in the branch history", async () => {
    const r = await listNewCommits(pager(history), "deadbeef", 100);
    assert.ok(r.exhausted && !r.found && !r.capped);
    assert.equal(r.commits.length, 9);
  });
  test("commitMeta keeps the first message line, author, parent and time", () => {
    const m = commitMeta(gc("abc", "p1", "fix: thing <b>"), "o/r");
    assert.equal(m.msg, "fix: thing <b>"); assert.equal(m.parent, "p1"); assert.equal(m.author, "dev"); assert.ok(m.at > 0);
    assert.equal(m.url, "https://github.com/o/r/commit/abc");
  });
});

group("codescan watch: per-commit new and fixed", () => {
  const ig = ignoreMatcher("fixtures/\n");
  const inScope = (p) => !ig.test(p) && !/\.png$/.test(p);
  // Baseline: a full scan at s1 where server.js has the taint flow and util.js is clean.
  const start = () => newWatch({ full: "o/r", branch: "main", sha: "s1", findings: scan("server.js", TAINT_SRC), paths: ["server.js", "util.js"] });

  test("a commit that plants a secret: 1 new, 0 fixed", () => {
    const files = [{ filename: "util.js", status: "modified" }];
    const plan = planCommit(files, inScope, start().known);
    assert.deepEqual(plan.map((p) => [p.path, p.head, p.base]), [["util.js", true, false]], "known file: no previous version needed");
    const { state, record, added } = applyCommit(start(), [{ path: "util.js", status: "modified", findings: scan("util.js", SECRET_SRC) }], { sha: "s2", parent: "s1" });
    assert.equal(record.newItems.length, 1); assert.equal(record.newItems[0].rule, "secret.aws-access-key");
    assert.equal(record.fixedCount, 0); assert.equal(record.counts.high, 1);
    assert.equal(added[0].ruleId, "secret.aws-access-key");
    assert.equal(state.lastSha, "s2"); assert.equal(state.commits[0].sha, "s2");
    assert.ok(!JSON.stringify(state).includes("AKIAQ3EGRT7XZPLM4NHA"), "the stored watch never holds the secret value");
  });
  test("deleting a file fixes its findings", () => {
    const plan = planCommit([{ filename: "server.js", status: "removed" }], inScope, start().known);
    assert.equal(plan[0].status, "removed"); assert.equal(plan[0].base, false);
    const { state, record } = applyCommit(start(), [{ path: "server.js", status: "removed", findings: [] }], { sha: "s2", parent: "s1" });
    assert.equal(record.fixedCount, 1); assert.equal(record.fixedItems[0].rule, "js.taint.cmd"); assert.equal(record.newItems.length, 0);
    assert.ok(!state.files["server.js"] && !state.known["server.js"]);
  });
  test("an edit that removes the flow fixes it; unrelated edits are clean", () => {
    let s = start();
    const r1 = applyCommit(s, [{ path: "server.js", status: "modified", findings: scan("server.js", TAINT_SRC + "// tweak\n") }], { sha: "s2", parent: "s1" });
    assert.equal(r1.record.newItems.length, 0); assert.equal(r1.record.fixedCount, 0); assert.equal(chip(r1.record).text, "Clean");
    s = r1.state;
    const r2 = applyCommit(s, [{ path: "server.js", status: "modified", findings: scan("server.js", CLEAN_SRC) }], { sha: "s3", parent: "s2" });
    assert.equal(r2.record.fixedCount, 1); assert.equal(chip(r2.record).text, "fixed 1");
    assert.deepEqual(r2.state.commits.map((c) => c.sha), ["s3", "s2"]);
  });
  test("a rename that keeps the content is neither new nor fixed", () => {
    const plan = planCommit([{ filename: "src/server.js", status: "renamed", previous_filename: "server.js" }], inScope, start().known);
    assert.equal(plan[0].oldPath, "server.js"); assert.equal(plan[0].base, false);
    const { state, record } = applyCommit(start(), [{ path: "src/server.js", oldPath: "server.js", status: "renamed", findings: scan("src/server.js", TAINT_SRC) }], { sha: "s2" });
    assert.equal(record.newItems.length, 0); assert.equal(record.fixedCount, 0);
    assert.ok(state.files["src/server.js"] && !state.files["server.js"]);
  });
  test("a file the baseline never saw is compared with its previous version", () => {
    const lazy = newWatch({ full: "o/r", branch: "main", sha: "s1", mode: "lazy" });
    const plan = planCommit([{ filename: "server.js", status: "modified" }, { filename: "new.js", status: "added" }], inScope, lazy.known);
    assert.deepEqual(plan.map((p) => [p.path, p.base]), [["server.js", true], ["new.js", false]]);
    const { record } = applyCommit(lazy, [
      { path: "server.js", status: "modified", findings: scan("server.js", TAINT_SRC), oldFindings: scan("server.js", TAINT_SRC) },
      { path: "new.js", status: "added", findings: scan("new.js", SECRET_SRC) },
    ], { sha: "s2", parent: "s1" });
    assert.equal(record.newItems.length, 1, "the pre-existing flow is not new; the added secret is");
    assert.equal(record.newItems[0].path, "new.js");
  });
  test("ignored and binary paths are excluded, never reported as fixed", () => {
    const plan = planCommit([{ filename: "fixtures/x.js", status: "modified" }, { filename: "logo.png", status: "added" }, { filename: "z.js", status: "unchanged" }], inScope, {});
    assert.deepEqual(plan.map((p) => p.status), ["excluded", "excluded"]);
    const s = newWatch({ full: "o/r", branch: "main", sha: "s1", findings: scan("fixtures/x.js", SECRET_SRC), paths: ["fixtures/x.js"] });
    const { state, record } = applyCommit(s, [{ path: "fixtures/x.js", status: "excluded", findings: [] }], { sha: "s2" });
    assert.equal(record.fixedCount, 0); assert.ok(!state.files["fixtures/x.js"]);
  });
  test("a file that could not be read keeps its baseline and marks the commit partial", () => {
    const { state, record } = applyCommit(start(), [{ path: "server.js", status: "modified", findings: null }], { sha: "s2" });
    assert.equal(record.status, "partial"); assert.equal(record.failed, 1); assert.equal(record.fixedCount, 0);
    assert.equal(state.files["server.js"].length, 1);
    assert.equal(chip(record).text, "Clean (partial)");
  });
  test("a range of commits applied in order", () => {
    let s = start();
    const steps = [
      ["s2", [{ path: "util.js", status: "modified", findings: scan("util.js", SECRET_SRC) }]],
      ["s3", [{ path: "server.js", status: "removed", findings: [] }]],
      ["s4", [{ path: "util.js", status: "modified", findings: scan("util.js", CLEAN_SRC) }]],
    ];
    const out = [];
    for (const [sha, results] of steps) { const r = applyCommit(s, results, { sha }); s = r.state; out.push([r.record.newItems.length, r.record.fixedCount]); }
    assert.deepEqual(out, [[1, 0], [0, 1], [0, 1]]);
    assert.deepEqual(Object.keys(s.files), []);
    assert.equal(s.lastSha, "s4");
  });
  test("chip text for new findings and states", () => {
    assert.equal(chip({ status: "done", counts: { critical: 1, high: 2, medium: 0, low: 1 }, fixedCount: 3 }).text, "4 new: 1 critical, 2 high · fixed 3");
    assert.equal(chip({ status: "done", counts: { critical: 1 }, fixedCount: 0 }).cls, "crit");
    assert.equal(chip({ status: "scanning" }).text, "Scanning");
    assert.equal(chip({ status: "error" }).text, "Error");
  });
  test("graph entity names match the scanner's and carry the commit", () => {
    const f = scan("util.js", SECRET_SRC)[0];
    const g = graphItem(f, { full: "o/r", sha: "abc123" });
    assert.equal(g.name, f.title + " (o/r:util.js:1)");
    assert.equal(g.data.commit, "abc123"); assert.equal(g.data.evidence[0].commit, "abc123");
    assert.equal(g.opts.severity, "high");
  });
  test("items are compact and keyed like the baseline", () => {
    const f = scan("util.js", SECRET_SRC)[0];
    const it = toItem(f);
    assert.equal(it.k, findingKey(f)); assert.equal(toItem(it), it);
    assert.ok(!("snippet" in it) && !("secret" in it));
    assert.equal(watchKey("O/R", "main"), "o/r@main");
  });
  test("diffFile treats items and raw findings alike", () => {
    const a = scan("util.js", SECRET_SRC);
    const d = diffFile(a.map(toItem), a);
    assert.equal(d.added.length, 0); assert.equal(d.unchanged.length, 1); assert.equal(d.fixed.length, 0);
    const d2 = diffFile(a, []);
    assert.equal(d2.fixed.length, 1);
  });
});

group("codescan ci: workflow generator", () => {
  const y = workflowYaml();
  test("pinned actions, history, permissions and SARIF upload", () => {
    for (const s of ["actions/checkout@v4", "fetch-depth: 0", "actions/setup-node@v4", 'node-version: "20"', "github/codeql-action/upload-sarif@v3", "security-events: write", "contents: read", "sarif_file: darknode.sarif"]) assert.ok(y.includes(s), "missing " + s);
    assert.ok(/on:\n  push:\n    branches: \["\*\*"\]\n  pull_request:/.test(y));
    assert.ok(!/\t/.test(y), "YAML must not contain tabs");
  });
  test("downloads every engine module from the site, as an ES module package", () => {
    for (const f of SCANNER_FILES) assert.ok(y.includes(f));
    assert.ok(y.includes('curl -fsSL --retry 3 "https://darknode.ai/js/codescan/$f"'));
    assert.ok(y.includes(`echo '{"type":"module"}'`));
    for (const f of SCANNER_FILES) assert.ok(existsSync(join(root, "public", "js", "codescan", f)), f + " must be served from public/js/codescan/");
  });
  test("diffs against the previous commit or PR base, full scan for a new branch", () => {
    assert.ok(y.includes("github.event.pull_request.base.sha || github.event.before"));
    assert.ok(y.includes('"$BASE_SHA" != "0000000000000000000000000000000000000000"'));
    const exprLines = y.split("\n").filter((l) => l.includes("${{"));
    assert.ok(exprLines.length && exprLines.every((l) => /^\s*(BASE_SHA:|group:)/.test(l)), "event data reaches the script only through env");
  });
  test("options change the CLI flags", () => {
    const cmd = (yy) => yy.split("\n").find((l) => l.includes('node "$RUNNER_TEMP/darknode/cli.mjs"'));
    assert.equal(cmd(y).trim(), 'node "$RUNNER_TEMP/darknode/cli.mjs" . --sarif darknode.sarif --full-sarif --fail-on high $diff');
    const y2 = cmd(workflowYaml({ failOn: "medium", deps: true, failOnReview: true }));
    assert.ok(y2.includes("--fail-on medium") && y2.includes("--deps") && y2.includes("--fail-on-review"));
    assert.ok(workflowYaml({ failOn: "bogus" }).includes("--fail-on high"));
    assert.ok(workflowYaml({ site: "https://staging.darknode.ai/" }).includes('"https://staging.darknode.ai/js/codescan/$f"'));
    assert.throws(() => workflowYaml({ site: "http://x.test" }));
    assert.throws(() => workflowYaml({ site: "https://x.test/$(id)" }));
  });
  test("the repository's own workflow uses the same gate", () => {
    const own = readFileSync(join(root, ".github", "workflows", "darknode-scan.yml"), "utf8");
    for (const s of ["actions/checkout@v4", "fetch-depth: 0", "actions/setup-node@v4", "github/codeql-action/upload-sarif@v3", "security-events: write", "node scripts/darknode-scan.mjs . --sarif darknode.sarif --full-sarif --fail-on high $diff"]) assert.ok(own.includes(s), "missing " + s);
    assert.equal(WORKFLOW_PATH, ".github/workflows/darknode-scan.yml");
  });
  test("base64 for the contents API is UTF-8 safe", () => {
    const s = "name: scan\n# naïve – ü\n";
    assert.equal(Buffer.from(toBase64(s), "base64").toString("utf8"), s);
  });
});

group("codescan cli", () => {
  const sh = (dir, ...args) => execFileSync("git", ["-C", dir, "-c", "user.name=Test", "-c", "user.email=test@darknode.ai", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  const quiet = { log: () => {}, env: {} };
  let dir, c1, c2;
  const setup = () => {
    if (dir) return;
    dir = mkdtempSync(join(tmpdir(), "dn-scan-"));
    sh(dir, "init", "-q");
    mkdirSync(join(dir, "src"));
    writeFileSync(join(dir, "src", "util.js"), CLEAN_SRC);
    writeFileSync(join(dir, "src", "legacy.js"), 'const legacy = "AKIAZ7YXWVUT5SRQ3PON";\n');
    writeFileSync(join(dir, ".darknodeignore"), "vendor-data/\n");
    mkdirSync(join(dir, "vendor-data"));
    writeFileSync(join(dir, "vendor-data", "keys.js"), SECRET_SRC);
    sh(dir, "add", "-A"); sh(dir, "commit", "-q", "-m", "base");
    c1 = sh(dir, "rev-parse", "HEAD");
    writeFileSync(join(dir, "src", "config.js"), SECRET_SRC);
    writeFileSync(join(dir, "src", "server.js"), TAINT_SRC);
    sh(dir, "add", "-A"); sh(dir, "commit", "-q", "-m", "add server");
    c2 = sh(dir, "rev-parse", "HEAD");
  };

  test("argument parsing", () => {
    assert.deepEqual(parseArgs(["x", "--fail-on", "MEDIUM", "--deps"]).failOn, "medium");
    assert.throws(() => parseArgs(["--fail-on", "severe"]));
    assert.throws(() => parseArgs(["--sarif"]));
    assert.throws(() => parseArgs(["--nope"]));
  });
  test("git name-status parsing, renames included", () => {
    assert.deepEqual(parseNameStatus("M\0a.js\0R087\0old.js\0new.js\0D\0gone.js\0A\0add.js\0"), [
      { status: "modified", path: "a.js", oldPath: "" }, { status: "renamed", path: "new.js", oldPath: "old.js" },
      { status: "removed", path: "gone.js", oldPath: "" }, { status: "added", path: "add.js", oldPath: "" }]);
  });
  test("diff mode: only NEW findings gate, SARIF 2.1.0 written", async () => {
    setup();
    const out = join(dir, "out.sarif");
    const r = await main([dir, "--diff-base", c1, "--sarif", out, "--fail-on", "high"], quiet);
    assert.equal(r.mode, "diff"); assert.equal(r.code, 1);
    const rules = r.added.map((f) => f.ruleId).sort();
    assert.deepEqual(rules, ["js.taint.cmd", "secret.aws-access-key"], "the old key in legacy.js and the ignored folder are not new");
    const s = JSON.parse(readFileSync(out, "utf8"));
    assert.equal(s.version, "2.1.0");
    const res = s.runs[0].results;
    assert.ok(res.every((x) => x.locations[0].physicalLocation.artifactLocation.uri.startsWith("src/")));
    const flow = res.find((x) => x.ruleId === "js.taint.cmd");
    assert.equal(flow.level, "error"); assert.ok(flow.codeFlows[0].threadFlows[0].locations.length >= 2);
    assert.ok(!readFileSync(out, "utf8").includes("AKIAQ3EGRT7XZPLM4NHA"), "SARIF carries the masked value only");
    const rule = s.runs[0].tool.driver.rules.find((x) => x.id === "js.taint.cmd");
    assert.equal(rule.properties["security-severity"], "9.5");
  });
  test("diff mode: nothing new since HEAD passes; --full-sarif still covers the tree", async () => {
    setup();
    const out = join(dir, "full.sarif");
    const r = await main([dir, "--diff-base", c2, "--sarif", out, "--full-sarif"], quiet);
    assert.equal(r.code, 0); assert.equal(r.added.length, 0);
    const uris = JSON.parse(readFileSync(out, "utf8")).runs[0].results.map((x) => x.locations[0].physicalLocation.artifactLocation.uri);
    assert.ok(uris.includes("src/legacy.js") && uris.includes("src/server.js"));
    assert.ok(!uris.some((u) => u.startsWith("vendor-data/")), ".darknodeignore is respected");
  });
  test("fixed findings are reported when a file is deleted", async () => {
    setup();
    const d = mkdtempSync(join(tmpdir(), "dn-scan-"));
    try {
      sh(d, "init", "-q");
      writeFileSync(join(d, "a.js"), SECRET_SRC); sh(d, "add", "-A"); sh(d, "commit", "-q", "-m", "a");
      const base = sh(d, "rev-parse", "HEAD");
      sh(d, "rm", "-q", "a.js"); writeFileSync(join(d, "b.js"), CLEAN_SRC); sh(d, "add", "-A"); sh(d, "commit", "-q", "-m", "b");
      const r = await main([d, "--diff-base", base], quiet);
      assert.equal(r.code, 0); assert.equal(r.fixed.length, 1); assert.equal(r.added.length, 0);
    } finally { rmSync(d, { recursive: true, force: true }); }
  });
  test("full scan gates on everything; fail-on none never fails; unknown base falls back", async () => {
    setup();
    assert.equal((await main([dir], quiet)).code, 1);
    assert.equal((await main([dir, "--fail-on", "none"], quiet)).code, 0);
    assert.equal((await main([dir, "--fail-on", "critical", "--diff-base", c1], quiet)).code, 1, "the taint flow is critical");
    const r = await main([dir, "--diff-base", "0123456789abcdef0123456789abcdef01234567"], quiet);
    assert.equal(r.mode, "full"); assert.ok(/not in this checkout/.test(r.note));
    const z = await main([dir, "--diff-base", "0000000000000000000000000000000000000000"], quiet);
    assert.equal(z.mode, "full"); assert.ok(/new branch/.test(z.note));
  });
  test("job summary lists the new findings, masked", async () => {
    setup();
    const sum = join(dir, "summary.md");
    await main([dir, "--diff-base", c1], { log: () => {}, env: { GITHUB_STEP_SUMMARY: sum, GITHUB_REPOSITORY: "o/r", GITHUB_SHA: c2 } });
    const md = readFileSync(sum, "utf8");
    assert.ok(md.includes("### New findings") && md.includes("Gate failed"));
    assert.ok(md.includes(`https://github.com/o/r/blob/${c2}/src/server.js#L5`));
    assert.ok(!md.includes("AKIAQ3EGRT7XZPLM4NHA"));
  });
  test("the repo entry point exits 1 on a new finding and 2 on bad usage", () => {
    setup();
    const bin = join(root, "scripts", "darknode-scan.mjs");
    const a = spawnSync(process.execPath, [bin, dir, "--diff-base", c1, "--quiet"], { encoding: "utf8" });
    assert.equal(a.status, 1);
    const b = spawnSync(process.execPath, [bin, dir, "--diff-base", c2, "--quiet"], { encoding: "utf8" });
    assert.equal(b.status, 0);
    const c = spawnSync(process.execPath, [bin, "--fail-on", "nope"], { encoding: "utf8" });
    assert.equal(c.status, 2);
    rmSync(dir, { recursive: true, force: true });
  });
});
