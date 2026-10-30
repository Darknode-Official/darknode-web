// Code Scanner rule tests (public/js/codescan/rules.js): every rule family gets a
// positive case (must fire, on the right line) and a negative case (must stay quiet),
// plus manifest parsing, CVSS scoring and SARIF shape.

import { test, assert, group } from "../harness.mjs";
import { ignoreMatcher } from "../../public/js/codescan/github.js";
import { scanFile, parseManifest, cvssBase, osvSeverity, osvFixed, toSarif, langOf, repoScore } from "../../public/js/codescan/rules.js";

const ids = (path, src) => scanFile(path, src).map((f) => f.ruleId);
const hit = (path, src, id) => assert.ok(ids(path, src).includes(id), id + " should fire on: " + src);
const miss = (path, src, id) => assert.ok(!ids(path, src).includes(id), id + " should NOT fire on: " + src);

group("codescan: secrets", () => {
  test("AWS key id fires and is masked", () => {
    const f = scanFile("src/a.js", 'const k = "AKIAQ3EGRT7XZPLM4NHA";');
    assert.equal(f[0].ruleId, "secret.aws-access-key");
    assert.ok(!f[0].snippet.includes("AKIAQ3EGRT7XZPLM4NHA"), "raw secret must not appear in snippet");
  });
  test("placeholder AWS key ignored", () => miss("src/a.js", 'k = "AKIAIOSFODNN7EXAMPLE"', "secret.aws-access-key"));
  test("placeholders are counted so a UI can say why nothing was found", () => { const r = scanFile("a.py", 'k = "AKIAIOSFODNN7EXAMPLE"\nt = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n'); assert.equal(r.length, 0); assert.equal(r.placeholders, 2); assert.equal(scanFile("b.py", "x = 1\n").placeholders, 0); });
  test("GitHub token", () => hit("x.py", "t = 'ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'", "secret.github-token"));
  test("private key block", () => {
    hit("id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW", "secret.private-key");
    miss("detect.js", "const re = /-----BEGIN OPENSSH PRIVATE KEY-----/;", "secret.private-key"); // a detector's pattern, no key
  });
  test("teaching examples and public values are not secrets", () => {
    miss("a.js", 'x = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"', "secret.github-token");
    miss("a.js", 'u = "postgres://user:pass@host:5432/db"', "secret.db-url");
    hit("a.js", 'u = "postgres://app:Vq7rT2xK9m@db.internal:5432/prod"', "secret.db-url");
    miss("firebase.js", 'const cfg = {\n  apiKey: "AIzaSyD3CJO7PLQdRvPOWDqehSlRwEeA5odCTDE",\n  authDomain: "x.firebaseapp.com" };', "secret.google-api-key");
    miss("firebase.js", 'const cfg = {\n  apiKey: "AIzaSyD3CJO7PLQdRvPOWDqehSlRwEeA5odCTDE",\n  authDomain: "x.firebaseapp.com" };', "secret.generic");
    miss("a.js", '<input autocomplete="${s ? "new-password" : "current-password"}">', "secret.generic");
  });
  test("generic needs entropy", () => {
    hit("cfg.js", 'const apiKey = "q8Zr2LmX9vT4kP1sW7yB";', "secret.generic");
    miss("cfg.js", 'const password = "aaaaaaaaaaaaaaaa";', "secret.generic");
    miss("cfg.js", "const token = process.env.TOKEN_VALUE_HERE;", "secret.generic");
    miss("seed.js", '"password" : "$2a$10$8Zo/1e8KM8QzqOKqbDlYlONBOzukWXrM.IiyzqHRYDXqwB3gzDsba",', "secret.generic");
  });
  test("db url with password", () => hit("app.py", 'DB = "postgres://admin:S3cr3tPw@db.internal:5432/app"', "secret.db-url"));
  test("secrets in test paths are downgraded to low", () => {
    const f = scanFile("test/fixtures/keys.js", 'const k = "AKIAQ3EGRT7XZPLM4NHA";');
    assert.equal(f[0].sev, "low");
  });
  test("darknode-ignore suppresses", () => miss("a.js", 'const k = "AKIAQ3EGRT7XZPLM4NHA"; // darknode-ignore', "secret.aws-access-key"));
});

group("codescan: javascript", () => {
  test("eval with variable", () => { hit("a.js", "eval(userInput)", "js.eval"); miss("a.js", 'eval("1+1")', "js.eval"); });
  test("child_process exec concat", () => {
    hit("a.js", 'const { exec } = require("child_process");\nexec("ls " + dir);', "js.child-process-exec");
    miss("a.js", 'db.exec("ls " + dir);', "js.child-process-exec");
  });
  test("child_process exec still fires in every call form", () => {
    const cp = 'const cp = require("child_process");\n';
    hit("a.js", cp + "cp.exec(cmd + arg);", "js.child-process-exec");
    hit("a.js", cp + "cp.execSync(`git log ${ref}`);", "js.child-process-exec");
    hit("a.js", cp + "child_process.exec(cmd, cb);", "js.child-process-exec");
    hit("a.js", 'require("child_process").exec("rm -rf " + dir);', "js.child-process-exec");
    hit("a.js", "import { execSync } from \"node:child_process\";\nexecSync(\"tar xf \" + file);", "js.child-process-exec");
    hit("a.js", 'import * as childProcess from "child_process";\nchildProcess.exec(`ping ${host}`);', "js.child-process-exec");
  });
  test("RegExp.prototype.exec is not a shell call, even near child_process", () => {
    const cp = 'const { exec } = require("child_process");\n';
    miss("a.js", cp + "const m = rule.re.exec(raw);", "js.child-process-exec");
    miss("a.js", cp + "const m = /a(b)/g.exec(line);", "js.child-process-exec");
    miss("a.js", cp + "while ((m = re.exec(text))) out.push(m);", "js.child-process-exec");
    miss("a.js", cp + "const m = URL_RE.exec(s);", "js.child-process-exec");
    miss("a.js", cp + "const m = urlRe.exec(s);", "js.child-process-exec");
    miss("a.js", cp + "const m = tokenPattern.exec(src);", "js.child-process-exec");
    miss("a.js", cp + "const m = regex.exec(input);", "js.child-process-exec");
    miss("a.js", cp + "const m = matcher.exec(input);", "js.child-process-exec");
  });
  test("innerHTML", () => {
    hit("a.js", "el.innerHTML = data.name;", "js.inner-html");
    miss("a.js", 'el.innerHTML = "<b>hi</b>";', "js.inner-html");
    miss("a.js", "el.innerHTML = DOMPurify.sanitize(x);", "js.inner-html");
  });
  test("commented code ignored", () => miss("a.js", "// el.innerHTML = data.name;", "js.inner-html"));
  test("block comment ignored", () => miss("a.js", "/*\n el.innerHTML = data.name;\n*/", "js.inner-html"));
  test("sql concat", () => {
    hit("a.js", "db.query(`SELECT * FROM u WHERE id=${id}`)", "js.sql-concat");
    miss("a.js", "db.query('SELECT * FROM u WHERE id=$1', [id])", "js.sql-concat");
  });
  test("tls disabled", () => hit("a.js", "agent = new https.Agent({ rejectUnauthorized: false })", "js.tls-disabled"));
  test("insecure random near token", () => {
    hit("a.js", "const token = Math.random().toString(36);", "js.insecure-random");
    miss("a.js", "const x = Math.random() * width;", "js.insecure-random");
  });
  test("open redirect", () => {
    hit("a.vue", "res.redirect(req.query.next)", "js.open-redirect"); // pattern rule still covers files the flow engine skips
    hit("a.js", "res.redirect(req.query.next)", "js.taint.redirect"); // a traced flow supersedes the pattern hit
  });
  test("postMessage *", () => hit("a.js", 'w.postMessage(data, "*")', "js.postmessage-wildcard"));
});

group("codescan: python / go / php / java / infra", () => {
  test("yaml.load", () => { hit("a.py", "yaml.load(f)", "py.yaml-load"); miss("a.py", "yaml.load(f, Loader=yaml.SafeLoader)", "py.yaml-load"); });
  test("pickle", () => hit("a.py", "obj = pickle.loads(blob)", "py.pickle"));
  test("shell=True", () => hit("a.py", "subprocess.run(cmd, shell=True)", "py.shell-true"));
  test("sql f-string", () => { hit("a.py", 'cur.execute(f"SELECT * FROM t WHERE id={i}")', "py.sql-format"); miss("a.py", 'cur.execute("SELECT * FROM t WHERE id=%s", (i,))', "py.sql-format"); });
  test("verify=False", () => hit("a.py", "requests.get(u, verify=False)", "py.tls-disabled"));
  test("python comment ignored", () => miss("a.py", "# requests.get(u, verify=False)", "py.tls-disabled"));
  test("go InsecureSkipVerify", () => hit("a.go", "cfg := &tls.Config{InsecureSkipVerify: true}", "go.tls-skip-verify"));
  test("go sprintf sql", () => hit("a.go", 'rows, _ := db.Query(fmt.Sprintf("SELECT * FROM u WHERE n=%s", n))', "go.sql-sprintf"));
  test("php exec input", () => hit("a.php", "system($_GET['cmd']);", "php.exec-input"));
  test("php include input", () => hit("a.php", "include($_GET['page']);", "php.include-input"));
  test("java concat sql", () => hit("A.java", 'stmt.executeQuery("SELECT * FROM u WHERE id=" + id);', "java.sql-concat"));
  test("java weak crypto", () => { hit("A.java", 'Cipher.getInstance("AES/ECB/PKCS5Padding")', "java.weak-crypto"); miss("A.java", 'Cipher.getInstance("AES/GCM/NoPadding")', "java.weak-crypto"); });
  test("dockerfile root + curl|sh", () => {
    const f = ids("Dockerfile", "FROM node:20\nRUN curl -sL https://x.sh | bash\nCMD node app.js");
    assert.ok(f.includes("docker.runs-as-root") && f.includes("docker.curl-pipe-shell"));
    miss("Dockerfile", "FROM node:20\nUSER app\nCMD node app.js", "docker.runs-as-root");
  });
  test("GitHub Actions script injection", () => hit(".github/workflows/ci.yml", "    steps:\n      - run: echo \"${{ github.event.issue.title }}\"", "gha.script-injection"));
  test("langOf", () => { assert.equal(langOf("a/b/Dockerfile"), "docker"); assert.equal(langOf(".github/workflows/x.yml"), "gha"); assert.equal(langOf("x.tsx"), "js"); });
  test("langOf returns '' for an extension that names an Object.prototype member (no inherited function)", () => {
    assert.equal(langOf("x.constructor"), "");
    assert.equal(langOf("x.toString"), "");
    assert.equal(langOf("x.unknownext"), "");
  });
});

group("codescan: manifests + scoring", () => {
  test("package-lock v3", () => {
    const src = JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "app" }, "node_modules/lodash": { version: "4.17.20" }, "node_modules/@scope/x": { version: "1.0.0" } } }, null, 2);
    const d = parseManifest("package-lock.json", src);
    assert.equal(d.length, 2);
    assert.equal(d[0].name, "lodash");
    assert.ok(d[0].line > 1);
    assert.equal(d[1].name, "@scope/x");
  });
  test("yarn.lock v1", () => {
    const d = parseManifest("yarn.lock", '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.22.5"\n\nlodash@^4.17.0:\n  version "4.17.21"\n');
    assert.deepEqual(d.map((x) => x.name + "@" + x.version), ["@babel/core@7.22.5", "lodash@4.17.21"]);
  });
  test("requirements pins only", () => {
    const d = parseManifest("requirements.txt", "django==3.2.0\nrequests>=2.0\nflask[async]==2.0.1 # web\n");
    assert.deepEqual(d.map((x) => x.name), ["django", "flask"]);
    assert.equal(d[1].line, 3);
  });
  test("go.mod", () => {
    const d = parseManifest("go.mod", "module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.7.0\n\tgolang.org/x/net v0.0.1 // indirect\n)\n");
    assert.equal(d.length, 2); assert.equal(d[0].version, "1.7.0"); assert.equal(d[0].ecosystem, "Go");
  });
  test("Cargo.lock + Gemfile.lock", () => {
    assert.equal(parseManifest("Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.100"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')[0].ecosystem, "crates.io");
    assert.equal(parseManifest("Gemfile.lock", "GEM\n  remote: x\n  specs:\n    rails (6.0.0)\n      actionpack (= 6.0.0)\n")[0].name, "rails");
  });
  test("CVSS 3.1 base scores", () => {
    assert.equal(cvssBase("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
    assert.equal(cvssBase("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10);
    assert.equal(cvssBase("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
  });
  test("OSV severity + fixed version", () => {
    assert.equal(osvSeverity({ database_specific: { severity: "MODERATE" } }), "medium");
    assert.equal(osvSeverity({ severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] }), "critical");
    assert.equal(osvFixed({ affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] }, "lodash"), "4.17.21");
    // multi-branch advisory listed highest-first: must return the LOWEST fixed version (minimal upgrade), not fixes[0].
    assert.equal(osvFixed({ affected: [
      { package: { name: "pkg" }, ranges: [{ events: [{ introduced: "2.0.0" }, { fixed: "2.0.1" }] }] },
      { package: { name: "pkg" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "1.2.3" }] }] },
    ] }, "pkg"), "1.2.3");
  });
  test("score + SARIF", () => {
    assert.equal(repoScore([]), 100);
    assert.ok(repoScore([{ sev: "critical" }]) < 100);
    const s = toSarif([{ ruleId: "js.eval", title: "x", sev: "high", path: "a.js", line: 3, col: 1 }], { repo: "o/r", sha: "abc" });
    assert.equal(s.version, "2.1.0");
    assert.equal(s.runs[0].results[0].locations[0].physicalLocation.region.startLine, 3);
  });
  test("SARIF locations are relative URIs: a space or # in a path is percent-encoded per segment", () => {
    const uri = (p) => toSarif([{ ruleId: "js.eval", title: "x", sev: "high", path: p, line: 1, col: 1 }]).runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    assert.equal(uri("sub/my conf.py"), "sub/my%20conf.py");
    assert.equal(uri("a#b/c?.js"), "a%23b/c%3F.js");
    assert.equal(uri("src/app.js"), "src/app.js");
  });
  test("data-flow findings replace a pattern hit on the same line and carry a SARIF code flow", () => {
    const src = `const { exec } = require("child_process");
app.get("/p", (req, res) => {
  const h = req.query.h;
  exec("ping " + h);
});`;
    const f = scanFile("src/a.js", src).filter((x) => x.line === 4 && x.cwe === 78);
    assert.equal(f.length, 1);
    assert.equal(f[0].ruleId, "js.taint.cmd");
    assert.equal(f[0].confidence, "high");
    assert.deepEqual(f[0].flow.map((s) => s.line), [3, 3, 4]);
    const flow = toSarif(f.map((x) => ({ ...x, path: "src/a.js" }))).runs[0].results[0].codeFlows[0].threadFlows[0].locations;
    assert.equal(flow.length, 3);
    assert.equal(flow[2].location.physicalLocation.region.startLine, 4);
  });
  test("darknode-ignore silences a data-flow finding", () => {
    const src = `app.get("/", (req, res) => { res.redirect(req.query.next); }); // darknode-ignore`;
    assert.ok(!scanFile("a.js", src).some((x) => x.ruleId.startsWith("js.taint.")));
    assert.ok(scanFile("a.js", src.replace(" // darknode-ignore", "")).some((x) => x.ruleId === "js.taint.redirect"));
  });
  test("data flow is not run on non-JS files", () => assert.ok(!scanFile("a.py", "x = req.query.h").some((x) => x.flow)));
  test("an HTML sink with no traced input stays visible as a needs-review item, never hidden", () => {
    const f = scanFile("a.js", "el.innerHTML = `<b>${count}</b>`;").find((x) => x.ruleId === "js.inner-html");
    assert.equal(f.sev, "high"); // keeps its real severity — not demoted to "info" and hidden
    assert.equal(f.confidence, "review"); // but clearly labelled lower-confidence
    assert.ok(repoScore([f]) < 100, "a needs-review finding still costs score"); // not silently free
    assert.ok(repoScore([f]) > repoScore([{ sev: "high" }]), "but it costs less than a confirmed high"); // discounted
    // Same code where the flow engine never runs (.vue) must look the same, not worse.
    assert.equal(scanFile("a.vue", "el.innerHTML = `<b>${count}</b>`;").find((x) => x.ruleId === "js.inner-html").sev, "high");
  });
  test("a dangerous dynamic sink the flow engine cannot trace is never silently dropped", () => {
    // eval of a computed (non-constant) value: real bug, but no known taint source → review.
    const f = scanFile("a.js", "const r = eval(buildExpr(a, b));").find((x) => x.ruleId === "js.eval");
    assert.ok(f, "js.eval must still be reported when the engine can't trace a source");
    assert.equal(f.sev, "high"); // real severity preserved
    assert.equal(f.confidence, "review");
    assert.ok(repoScore([f]) < 100); // and it counts against the score
    // A constant argument is still correctly not a finding at all.
    assert.ok(!scanFile("a.js", 'eval("1+1")').some((x) => x.ruleId === "js.eval"));
  });
  test("a taint-confirmed finding supersedes the pattern hit and is not marked review", () => {
    const src = `app.get("/p", (req, res) => { res.redirect(req.query.next); });`;
    const f = scanFile("a.js", src).find((x) => x.ruleId === "js.taint.redirect");
    assert.ok(f && f.confidence === "high", "confirmed flow keeps high confidence");
    assert.ok(!scanFile("a.js", src).some((x) => x.confidence === "review" && x.cwe === 601));
  });
  test("JWT none is flagged only where verification accepts it", () => {
    hit("a.js", 'jwt.verify(t, key, { algorithms: ["HS256", "none"] })', "js.jwt-none");
    hit("a.py", 'jwt.decode(t, key, algorithms=["none"])', "js.jwt-none");
    miss("a.js", 'return { algorithm: header.alg || "none" };', "js.jwt-none");
  });
  test("public test vectors, sample JWTs and game randomness are not findings", () => {
    miss("a.js", 'example: { secret: "GEZDGNBVGY3TQOJQ", counter: "0" }', "secret.generic");
    miss("a.js", 'example: { token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc" }', "secret.generic");
    miss("a.js", "const secret = Math.floor(Math.random() * 100) + 1;", "js.insecure-random");
    hit("a.js", "const token = Math.random().toString(36).slice(2);", "js.insecure-random");
    hit("a.js", "const otp = Math.floor(Math.random() * 1000000);", "js.insecure-random");
  });
  test(".darknodeignore follows gitignore path rules", () => {
    const g = ignoreMatcher("# reference data\npublic/data/\n*.fixture.js\n/top.js\n**/samples/**\n!keep.js");
    for (const p of ["public/data/x.js", "a/b/c.fixture.js", "top.js", "samples/a.js", "deep/samples/z/a.js"]) assert.ok(g.test(p), p);
    for (const p of ["src/public/data/x.js", "x/top.js", "public/database.js", "keep.js"]) assert.ok(!g.test(p), p);
  });
});

group("codescan: sql concat with a quoted value", () => {
  test("js/py: a literal ending in a quote before + still fires", () => {
    hit("a.js", `db.query("SELECT * FROM u WHERE name='" + n + "'")`, "js.sql-concat");
    hit("a.py", `cur.execute("SELECT * FROM t WHERE a='" + n + "'")`, "py.sql-format");
  });
  test("go: plain string concatenation into Query fires; literal + literal does not", () => {
    hit("a.go", 'db.Query("SELECT * FROM u WHERE id=" + id)', "go.sql-sprintf");
    hit("a.go", `db.Query("SELECT * FROM u WHERE n='" + n + "'")`, "go.sql-sprintf");
    miss("a.go", 'db.Query("SELECT * FROM u " + "WHERE id=$1", id)', "go.sql-sprintf");
    miss("a.go", 'db.Query("SELECT * FROM u WHERE id=$1", id)', "go.sql-sprintf");
  });
});
