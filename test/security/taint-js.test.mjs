// Code Scanner data-flow engine (public/js/codescan/taint-js.js). Every sink family gets
// flows that must be found (with the right line and a step-by-step path) and nearby code
// that must stay quiet: validated, converted, escaped, parameterised or constant input.

import { test, assert, group } from "../harness.mjs";
import { taintScan, tokenize } from "../../public/js/codescan/taint-js.js";

const kinds = (src) => taintScan(src).map((f) => f.kind);
const hit = (src, kind, line) => {
  const f = taintScan(src).find((x) => x.kind === kind);
  assert.ok(f, kind + " should be found in:\n" + src);
  if (line) assert.equal(f.line, line, kind + " sink line");
  return f;
};
const quiet = (src) => assert.deepEqual(kinds(src), [], "should stay quiet:\n" + src);

group("taint: tokenizer", () => {
  test("strings, templates, regex and comments", () => {
    const T = tokenize("const a = `x${b + 1}y` // c\nconst r = /a\\/b[/]/g; /* x */ a / 2");
    assert.equal(T.find((t) => t.t === "tpl").parts[0].map((t) => t.v).join(" "), "b + 1");
    assert.equal(T.find((t) => t.t === "re").v, "/a\\/b[/]/g");
    assert.ok(T.some((t) => t.v === "/" && t.t === "p"), "division stays an operator");
    assert.equal(T.find((t) => t.v === "r").line, 2);
  });
});

group("taint: server flows", () => {
  test("command injection through a variable and a template", () => {
    const f = hit(`const { exec } = require("child_process");
app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec(\`ping -c 1 \${host}\`, (e, out) => res.send(out));
});`, "cmd", 4);
    assert.equal(f.sev, "critical");
    assert.deepEqual(f.flow.map((s) => s.line), [3, 3, 4]);
    assert.ok(/req\.query\.host/.test(f.flow[0].label));
  });
  test("cp.execSync with a module alias", () => hit(`const cp = require('child_process')
function h(req, res) { cp.execSync("tar xf " + req.body.file) }`, "cmd", 2));
  test("execFile with a fixed program and argument array is quiet", () => quiet(`const { execFile } = require("child_process");
app.get("/", (req, res) => execFile("ping", ["-c", "1", "localhost"]));`));
  test("SQL built by concatenation", () => {
    const f = hit(`app.post("/login", async (req, res) => {
  const { user } = req.body;
  const sql = "SELECT * FROM users WHERE name = '" + user + "'";
  const rows = await db.query(sql);
});`, "sql", 4);
    assert.equal(f.cwe, 89);
  });
  test("parameterised SQL is quiet", () => quiet(`app.post("/login", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE name = $1", [req.body.user]);
});`));
  test("numeric conversion clears the flow", () => quiet(`app.get("/u", (req, res) => {
  const id = parseInt(req.params.id, 10);
  db.query("SELECT * FROM t WHERE id = " + id);
});`));
  test("an allowlist guard that returns clears the flow", () => quiet(`const ALLOWED = ["a", "b"];
app.get("/r", (req, res) => {
  const name = req.query.name;
  if (!ALLOWED.includes(name)) return res.sendStatus(400);
  fs.readFile("/data/" + name, () => {});
});`));
  test("a positive regex guard protects its block only", () => {
    const src = `app.get("/r", (req, res) => {
  const f = req.query.f;
  if (/^[a-z]+$/.test(f)) { fs.readFile("/d/" + f, cb); }
  fs.readFileSync("/d/" + f);
});`;
    const fs = taintScan(src).filter((x) => x.kind === "path");
    assert.deepEqual(fs.map((x) => x.line), [4]);
  });
  test("path traversal via path.join, basename clears it", () => {
    hit(`const fs = require("fs"), path = require("path");
app.get("/f", (req, res) => { res.send(fs.readFileSync(path.join(__dirname, "files", req.query.name))) });`, "path", 2);
    quiet(`const fs = require("fs"), path = require("path");
app.get("/f", (req, res) => { fs.readFileSync(path.join(__dirname, "files", path.basename(req.query.name))) });`);
  });
  test("res.sendFile with a root option is quiet", () => quiet(`app.get("/f", (req, res) => res.sendFile(req.params.name, { root: "public" }));`));
  test("SSRF only when the host is not fixed", () => {
    hit(`app.get("/proxy", async (req, res) => { const r = await fetch(req.query.url); res.json(await r.json()); });`, "ssrf", 1);
    quiet(`app.get("/p", async (req, res) => { const r = await fetch("https://api.example.com/items/" + encodeURIComponent(req.query.id)); });`);
  });
  test("open redirect", () => hit(`app.get("/go", (req, res) => { res.redirect(302, req.query.next); });`, "redirect", 1));
  test("reflected XSS is medium, escaping clears it", () => {
    assert.equal(hit(`app.get("/", (req, res) => { res.status(200).send("<h1>" + req.query.q + "</h1>"); });`, "xss", 1).sev, "medium");
    quiet(`app.get("/", (req, res) => { res.send("<h1>" + escapeHtml(req.query.q) + "</h1>"); });`);
  });
  test("eval and new Function", () => {
    hit(`app.post("/calc", (req, res) => { res.json({ v: eval(req.body.expr) }); });`, "code", 1);
    hit(`app.post("/f", (req, res) => { const fn = new Function("x", req.body.code); });`, "code", 1);
  });
  test("RegExp from input", () => hit(`app.get("/s", (req, res) => { const re = new RegExp(req.query.pattern); });`, "regex", 1));
  test("NoSQL operator injection, String() clears it", () => {
    hit(`app.post("/login", async (req, res) => { const u = await User.findOne({ email: req.body.email, password: req.body.password }); });`, "nosql", 1);
    quiet(`app.post("/login", async (req, res) => { const u = await User.findOne({ email: String(req.body.email) }); });`);
  });
  test("array.find is not a database query", () => quiet(`app.get("/", (req, res) => { const it = items.find((i) => i.id === req.query.id); });`));
  test("regex exec is not a shell or SQL call", () => quiet(`app.get("/", (req, res) => { const m = /x(\\d+)/.exec(req.query.s); const n = re.exec(req.query.s); });`));
  test("constant input is quiet", () => quiet(`const { exec } = require("child_process");
exec("ls -la", () => {}); db.query("SELECT 1"); document.body.innerHTML = "<p>hi</p>";`));
});

group("taint: flows across functions", () => {
  test("a helper that runs its parameter as a command", () => {
    const f = hit(`const { exec } = require("child_process");
function run(cmd) {
  return exec(cmd);
}
app.post("/run", (req, res) => { run("git " + req.body.args); });`, "cmd", 3);
    const labels = f.flow.map((s) => s.label).join(" | ");
    assert.ok(/passed to run\(\)/.test(labels), labels);
    assert.equal(f.flow[0].line, 5);
  });
  test("a helper called with a constant is quiet", () => quiet(`const { exec } = require("child_process");
const run = (cmd) => exec(cmd);
run("uptime");`));
  test("a function returning input taints its result", () => hit(`function term() { return location.hash.slice(1); }
document.getElementById("out").innerHTML = term();`, "xss", 2));
  test("parameters shadow outer tainted names", () => quiet(`const q = location.search;
function show(q) { document.body.innerHTML = q; }
show("static");`));
});

group("taint: browser flows", () => {
  test("DOM XSS from location.hash", () => {
    const f = hit(`const params = new URLSearchParams(location.search);
const name = params.get("name");
document.querySelector("#hi").innerHTML = "Hello " + name;`, "xss", 3);
    assert.equal(f.flow.length, 4);
  });
  test("textContent is not a sink", () => quiet(`const name = new URLSearchParams(location.search).get("name");
document.querySelector("#hi").textContent = name;`));
  test("DOMPurify clears HTML sinks", () => quiet(`el.innerHTML = DOMPurify.sanitize(location.hash.slice(1));`));
  test("postMessage data to innerHTML", () => hit(`window.addEventListener("message", (e) => {
  box.innerHTML = e.data.html;
});`, "xss", 2));
  test("message data is not a source without a message listener", () => quiet(`fetchThing().then((e) => { box.innerHTML = e.data.html; });`));
  test("location assignment from the URL", () => hit(`const next = new URLSearchParams(location.search).get("next");
window.location.href = next;`, "redirect", 2));
  test("React dangerouslySetInnerHTML", () => hit(`function Page() {
  const [sp] = useSearchParams();
  return <div dangerouslySetInnerHTML={{ __html: sp.get("bio") }} />;
}`, "xss", 3));
  test("server-only sinks ignore browser sources", () => quiet(`const r = await fetch(location.hash.slice(1));`));
});

group("taint: robustness", () => {
  test("malformed code never throws", () => {
    for (const s of ["", "{{{", "const = ;", "`${", "/*", "a = /", "function (", "x => {", "'unterminated"]) assert.ok(Array.isArray(taintScan(s)));
  });
  test("TypeScript annotations", () => hit(`export async function GET(request: Request): Promise<Response> {
  const body: { cmd: string } = await request.json();
  const { exec } = await import("node:child_process");
  execSync(body.cmd);
}
import { execSync } from "child_process";`, "cmd", 4));
});

group("taint: callbacks", () => {
  test("forEach element reaches a sink", () => hit(`const { exec } = require("child_process");
app.post("/batch", (req, res) => {
  req.body.hosts.forEach((h) => exec("ping " + h));
});`, "cmd", 3));
  test("promise .then value reaches a sink", () => hit(`app.post("/x", (req, res) => {
  request.json().then(function (b) { db.query("DELETE FROM t WHERE id = " + b.id); });
});`, "sql", 2));
  test("map result is what the callback returns", () => {
    hit(`const parts = location.hash.split(",").map((p) => p.trim());
out.innerHTML = parts.join("");`, "xss", 2);
    quiet(`const parts = location.hash.split(",").map((p) => esc(p.trim()));
out.innerHTML = parts.join("");`);
    quiet(`const rows = document.cookie.split(";").map((c) => {
  const [name, ...rest] = c.split("=");
  return { name: esc(name), value: esc(rest.join("=")) };
});
list.innerHTML = rows.map((r) => r.name + r.value).join("");`);
  });
  test("elements of a constant list are clean", () => quiet(`const { exec } = require("child_process");
["a", "b"].forEach((x) => exec("echo " + x));`));
  test("command-line arguments are not a trust boundary", () => quiet(`const fs = require("fs");
const dir = process.argv[2];
fs.readFileSync(dir + "/a.json");`));
});
