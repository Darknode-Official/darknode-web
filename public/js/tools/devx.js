// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Developer utility mini-tools.

const S = (v) => (v == null ? "" : String(v));

// ---- shared semver helpers ----
const SEMVER_RE = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/;
function parseSemver(str) {
  const m = SEMVER_RE.exec(String(str).trim().replace(/^v/, ""));
  if (!m) return null;
  return {
    major: +m[1], minor: +m[2], patch: +m[3],
    prerelease: m[4] || "", build: m[5] || "",
  };
}
function cmpIds(a, b) {
  const an = /^\d+$/.test(a), bn = /^\d+$/.test(b);
  if (an && bn) return Number(a) - Number(b);
  if (an) return -1;
  if (bn) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}
function cmpSemver(a, b) {
  const pa = parseSemver(a), pb = parseSemver(b);
  if (!pa || !pb) return NaN;
  if (pa.major !== pb.major) return pa.major < pb.major ? -1 : 1;
  if (pa.minor !== pb.minor) return pa.minor < pb.minor ? -1 : 1;
  if (pa.patch !== pb.patch) return pa.patch < pb.patch ? -1 : 1;
  if (pa.prerelease && !pb.prerelease) return -1;
  if (!pa.prerelease && pb.prerelease) return 1;
  if (!pa.prerelease && !pb.prerelease) return 0;
  const ai = pa.prerelease.split("."), bi = pb.prerelease.split(".");
  for (let i = 0; i < Math.max(ai.length, bi.length); i++) {
    if (ai[i] === undefined) return -1;
    if (bi[i] === undefined) return 1;
    const c = cmpIds(ai[i], bi[i]);
    if (c !== 0) return c < 0 ? -1 : 1;
  }
  return 0;
}

// ---- shared cron field parser ----
function cronField(field, min, max) {
  const set = new Set();
  const parts = String(field).split(",");
  for (let raw of parts) {
    raw = raw.trim();
    if (raw === "") return null;
    let step = 1, range = raw;
    const si = raw.indexOf("/");
    if (si >= 0) { step = parseInt(raw.slice(si + 1), 10); range = raw.slice(0, si); if (!(step > 0)) return null; }
    let lo, hi;
    if (range === "*") { lo = min; hi = max; }
    else if (range.indexOf("-") > 0) {
      const [a, b] = range.split("-"); lo = parseInt(a, 10); hi = parseInt(b, 10);
    } else {
      lo = hi = parseInt(range, 10);
    }
    if (isNaN(lo) || isNaN(hi) || lo < min || hi > max || lo > hi) return null;
    for (let i = lo; i <= hi; i += step) set.add(i);
  }
  return set;
}

const ULID_ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export const TOOLS = [
  {
    id: "dv-uuid-v4", name: "UUID v4 Generator", cat: "devx",
    desc: "Generate one or many random RFC 4122 version-4 UUIDs.",
    tags: ["uuid", "guid", "v4", "random", "id"],
    inputs: [{ k: "count", label: "How many", type: "range", min: 1, max: 100, step: 1, value: 5 }],
    run(v, H) {
      const n = H.clampInt(v.count, 1, 100, 5);
      const out = [];
      for (let i = 0; i < n; i++) out.push(H.uuid());
      return out.join("\n");
    },
  },
  {
    id: "dv-uuid-v7", name: "UUID v7 (time-ordered)", cat: "devx",
    desc: "Generate version-7 UUIDs whose leading bits encode the current Unix millisecond, so they sort chronologically.",
    tags: ["uuid", "v7", "sortable", "id", "time"],
    inputs: [{ k: "count", label: "How many", type: "range", min: 1, max: 100, step: 1, value: 5 }],
    run(v, H) {
      const n = H.clampInt(v.count, 1, 100, 5);
      const out = [];
      for (let i = 0; i < n; i++) {
        const ts = Date.now();
        const r = H.randBytes(10);
        const b = new Uint8Array(16);
        b[0] = Math.floor(ts / 2 ** 40) & 0xff;
        b[1] = Math.floor(ts / 2 ** 32) & 0xff;
        b[2] = Math.floor(ts / 2 ** 24) & 0xff;
        b[3] = Math.floor(ts / 2 ** 16) & 0xff;
        b[4] = Math.floor(ts / 2 ** 8) & 0xff;
        b[5] = ts & 0xff;
        b[6] = 0x70 | (r[0] & 0x0f);
        b[7] = r[1];
        b[8] = 0x80 | (r[2] & 0x3f);
        for (let j = 9; j < 16; j++) b[j] = r[j - 6];
        const h = H.toHex(b);
        out.push(`${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`);
      }
      return out.join("\n");
    },
  },
  {
    id: "dv-uuid-nil", name: "NIL / MAX UUID", cat: "devx",
    desc: "Emit the special all-zero NIL UUID and the all-ones MAX UUID.",
    tags: ["uuid", "nil", "max", "zero"],
    inputs: [{ k: "which", label: "Variant", type: "select", opts: [["nil", "NIL (all zero)"], ["max", "MAX (all ones)"]], value: "nil" }],
    run(v) {
      return v.which === "max"
        ? "ffffffff-ffff-ffff-ffff-ffffffffffff"
        : "00000000-0000-0000-0000-000000000000";
    },
  },
  {
    id: "dv-ulid", name: "ULID Generator", cat: "devx",
    desc: "Generate lexicographically sortable ULIDs: 48-bit millisecond timestamp plus 80 bits of randomness, Crockford base32.",
    tags: ["ulid", "id", "sortable", "base32"],
    inputs: [{ k: "count", label: "How many", type: "range", min: 1, max: 100, step: 1, value: 5 }],
    run(v, H) {
      const n = H.clampInt(v.count, 1, 100, 5);
      const out = [];
      for (let i = 0; i < n; i++) {
        let ts = Date.now();
        let t = "";
        for (let j = 0; j < 10; j++) { t = ULID_ALPHA[ts % 32] + t; ts = Math.floor(ts / 32); }
        const rb = H.randBytes(16);
        let r = "";
        for (let j = 0; j < 16; j++) r += ULID_ALPHA[rb[j] % 32];
        out.push(t + r);
      }
      return out.join("\n");
    },
  },
  {
    id: "dv-nanoid", name: "NanoID Generator", cat: "devx",
    desc: "Generate URL-friendly NanoIDs with a configurable size and alphabet.",
    tags: ["nanoid", "id", "random", "url-safe"],
    inputs: [
      { k: "size", label: "Size", type: "range", min: 1, max: 128, step: 1, value: 21 },
      { k: "alphabet", label: "Alphabet", type: "text", placeholder: "leave blank for default" },
      { k: "count", label: "How many", type: "range", min: 1, max: 50, step: 1, value: 1 },
    ],
    run(v, H) {
      const size = H.clampInt(v.size, 1, 128, 21);
      const alpha = v.alphabet && v.alphabet.length ? v.alphabet : "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";
      const n = H.clampInt(v.count, 1, 50, 1);
      const out = [];
      for (let c = 0; c < n; c++) {
        const rb = H.randBytes(size);
        let s = "";
        for (let i = 0; i < size; i++) s += alpha[rb[i] % alpha.length];
        out.push(s);
      }
      return out.join("\n");
    },
  },
  {
    id: "dv-snowflake-decode", name: "Snowflake ID Decoder", cat: "devx",
    desc: "Break a Twitter/Discord-style Snowflake ID into its timestamp, worker/datacenter, and sequence components.",
    tags: ["snowflake", "id", "twitter", "discord", "decode"],
    inputs: [
      { k: "id", label: "Snowflake ID", type: "text", placeholder: "175928847299117063" },
      { k: "epoch", label: "Epoch", type: "select", opts: [["1288834974657", "Twitter (2010-11-04)"], ["1420070400000", "Discord (2015-01-01)"], ["0", "Unix (0)"]], value: "1288834974657" },
    ],
    run(v) {
      if (!S(v.id).trim()) return "";
      let id;
      try { id = BigInt(S(v.id).trim()); } catch (e) { return { error: "Not a valid integer ID." }; }
      const epoch = Number(v.epoch || 0);
      const ts = Number(id >> 22n) + epoch;
      const datacenter = Number((id >> 17n) & 0x1fn);
      const worker = Number((id >> 12n) & 0x1fn);
      const seq = Number(id & 0xfffn);
      const d = new Date(ts);
      return [
        `Timestamp   : ${ts} ms`,
        `Date (UTC)  : ${isNaN(d.getTime()) ? "invalid" : d.toISOString()}`,
        `Datacenter  : ${datacenter}`,
        `Worker      : ${worker}`,
        `Sequence    : ${seq}`,
      ].join("\n");
    },
  },
  {
    id: "dv-semver-parse", name: "Semver Parse", cat: "devx",
    desc: "Split a semantic version into major, minor, patch, prerelease, and build metadata.",
    tags: ["semver", "version", "parse"],
    inputs: [{ k: "version", label: "Version", type: "text", placeholder: "1.4.2-rc.1+build.9" }],
    run(v) {
      if (!S(v.version).trim()) return "";
      const p = parseSemver(v.version);
      if (!p) return { error: "Not a valid semantic version." };
      return [
        `major      : ${p.major}`,
        `minor      : ${p.minor}`,
        `patch      : ${p.patch}`,
        `prerelease : ${p.prerelease || "(none)"}`,
        `build      : ${p.build || "(none)"}`,
      ].join("\n");
    },
  },
  {
    id: "dv-semver-compare", name: "Semver Compare", cat: "devx",
    desc: "Compare two semantic versions and report which is greater (precedence ignores build metadata).",
    tags: ["semver", "version", "compare"],
    inputs: [
      { k: "a", label: "Version A", type: "text", placeholder: "1.2.0" },
      { k: "b", label: "Version B", type: "text", placeholder: "1.2.0-rc.1" },
    ],
    run(v) {
      if (!S(v.a).trim() || !S(v.b).trim()) return "";
      const c = cmpSemver(v.a, v.b);
      if (isNaN(c)) return { error: "One or both versions are invalid." };
      const rel = c < 0 ? "<" : c > 0 ? ">" : "=";
      const word = c < 0 ? "A is lower than B" : c > 0 ? "A is higher than B" : "A equals B";
      return `${v.a} ${rel} ${v.b}\n${word}\ncompare() => ${c}`;
    },
  },
  {
    id: "dv-semver-bump", name: "Semver Bump", cat: "devx",
    desc: "Increment a semantic version by the chosen release type.",
    tags: ["semver", "version", "bump", "increment"],
    inputs: [
      { k: "version", label: "Version", type: "text", placeholder: "1.4.2" },
      { k: "type", label: "Release", type: "select", opts: ["major", "minor", "patch", "prerelease"], value: "patch" },
    ],
    run(v) {
      if (!S(v.version).trim()) return "";
      const p = parseSemver(v.version);
      if (!p) return { error: "Not a valid semantic version." };
      if (v.type === "major") return `${p.major + 1}.0.0`;
      if (v.type === "minor") return `${p.major}.${p.minor + 1}.0`;
      if (v.type === "patch") return `${p.major}.${p.minor}.${p.patch + 1}`;
      // prerelease
      if (!p.prerelease) return `${p.major}.${p.minor}.${p.patch + 1}-0`;
      const ids = p.prerelease.split(".");
      const last = ids[ids.length - 1];
      if (/^\d+$/.test(last)) ids[ids.length - 1] = String(Number(last) + 1);
      else ids.push("0");
      return `${p.major}.${p.minor}.${p.patch}-${ids.join(".")}`;
    },
  },
  {
    id: "dv-semver-satisfies", name: "Semver Satisfies", cat: "devx",
    desc: "Test whether a version satisfies a basic range: caret (^), tilde (~), exact, or a single comparator (>=, >, <=, <, =).",
    tags: ["semver", "range", "caret", "tilde", "satisfies"],
    inputs: [
      { k: "version", label: "Version", type: "text", placeholder: "1.4.2" },
      { k: "range", label: "Range", type: "text", placeholder: "^1.2.0" },
    ],
    run(v) {
      if (!S(v.version).trim() || !S(v.range).trim()) return "";
      const p = parseSemver(v.version);
      if (!p) return { error: "Version is not valid semver." };
      const r = S(v.range).trim();
      const m = /^(\^|~|>=|<=|>|<|=)?\s*(.+)$/.exec(r);
      const op = m[1] || "=";
      const base = parseSemver(m[2]);
      if (!base) return { error: "Range target is not valid semver." };
      let lo, hi; // [lo, hi)
      const bstr = `${base.major}.${base.minor}.${base.patch}`;
      if (op === "^") {
        lo = bstr;
        hi = base.major > 0 ? `${base.major + 1}.0.0` : base.minor > 0 ? `0.${base.minor + 1}.0` : `0.0.${base.patch + 1}`;
      } else if (op === "~") {
        lo = bstr; hi = `${base.major}.${base.minor + 1}.0`;
      } else {
        const c = cmpSemver(v.version, bstr);
        let ok = false;
        if (op === "=") ok = c === 0;
        else if (op === ">") ok = c > 0;
        else if (op === ">=") ok = c >= 0;
        else if (op === "<") ok = c < 0;
        else if (op === "<=") ok = c <= 0;
        return `${ok ? "SATISFIES" : "does NOT satisfy"}: ${v.version} ${op} ${bstr}`;
      }
      const ok = cmpSemver(v.version, lo) >= 0 && cmpSemver(v.version, hi) < 0;
      return `${ok ? "SATISFIES" : "does NOT satisfy"}: ${v.version} in [${lo}, ${hi})`;
    },
  },
  {
    id: "dv-chmod-sym-to-oct", name: "chmod Symbolic to Octal", cat: "devx",
    desc: "Convert a symbolic permission string (e.g. rwxr-xr-- or -rwxr-xr--) into its octal mode.",
    tags: ["chmod", "permissions", "octal", "unix"],
    inputs: [{ k: "sym", label: "Symbolic", type: "text", placeholder: "rwxr-xr--" }],
    run(v) {
      let s = S(v.sym).trim();
      if (!s) return "";
      if (s.length === 10) s = s.slice(1); // drop leading file-type char
      if (s.length !== 9 || !/^[rwxsStT-]{9}$/.test(s)) return { error: "Expected 9 permission characters." };
      const bit = (ch, val) => (ch === "-" ? 0 : val);
      let special = 0;
      const trip = (str, idx) => {
        const r = str[0] === "r" ? 4 : 0;
        const w = str[1] === "w" ? 2 : 0;
        const xc = str[2];
        let x = xc === "x" || xc === "s" || xc === "t" ? 1 : 0;
        if ((xc === "s" || xc === "S") && idx < 2) special |= idx === 0 ? 4 : 2;
        if ((xc === "t" || xc === "T") && idx === 2) special |= 1;
        return r + w + x;
      };
      const o = trip(s.slice(0, 3), 0);
      const g = trip(s.slice(3, 6), 1);
      const u = trip(s.slice(6, 9), 2);
      const oct = `${special}${o}${g}${u}`;
      return special ? oct : `${o}${g}${u}`;
    },
  },
  {
    id: "dv-chmod-oct-to-sym", name: "chmod Octal to Symbolic", cat: "devx",
    desc: "Convert an octal mode (e.g. 755 or 4755) into a symbolic permission string.",
    tags: ["chmod", "permissions", "symbolic", "unix"],
    inputs: [{ k: "oct", label: "Octal", type: "text", placeholder: "755" }],
    run(v) {
      let s = S(v.oct).trim();
      if (!s) return "";
      if (!/^[0-7]{3,4}$/.test(s)) return { error: "Expected 3 or 4 octal digits (0-7)." };
      let special = 0;
      if (s.length === 4) { special = +s[0]; s = s.slice(1); }
      const map = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"];
      let out = map[+s[0]] + map[+s[1]] + map[+s[2]];
      const arr = out.split("");
      if (special & 4) arr[2] = arr[2] === "x" ? "s" : "S";
      if (special & 2) arr[5] = arr[5] === "x" ? "s" : "S";
      if (special & 1) arr[8] = arr[8] === "x" ? "t" : "T";
      return arr.join("");
    },
  },
  {
    id: "dv-umask", name: "umask Resolver", cat: "devx",
    desc: "Show the resulting permissions after applying a umask to the default file (666) or directory (777) base.",
    tags: ["umask", "permissions", "octal", "unix"],
    inputs: [
      { k: "mask", label: "umask", type: "text", placeholder: "022" },
      { k: "kind", label: "Base", type: "select", opts: [["666", "File (666)"], ["777", "Directory (777)"]], value: "666" },
    ],
    run(v) {
      const m = S(v.mask).trim();
      if (!m) return "";
      if (!/^[0-7]{1,4}$/.test(m)) return { error: "umask must be octal (0-7)." };
      const mask = parseInt(m, 8);
      const base = parseInt(v.kind || "666", 8);
      const res = base & ~mask;
      const oct = res.toString(8).padStart(3, "0");
      const map = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"];
      const sym = oct.split("").map((d) => map[+d]).join("");
      return `umask ${m} on ${v.kind}\n=> ${oct}  (${sym})`;
    },
  },
  {
    id: "dv-gitignore", name: ".gitignore Generator", cat: "devx",
    desc: "Produce a starter .gitignore for a common stack.",
    tags: ["gitignore", "git", "template"],
    inputs: [{ k: "stack", label: "Stack", type: "select", opts: ["node", "python", "go", "rust", "java"], value: "node" }],
    run(v) {
      const T = {
        node: "# Node\nnode_modules/\nnpm-debug.log*\nyarn-error.log\n.pnpm-debug.log\ndist/\nbuild/\ncoverage/\n.env\n.env.local\n.DS_Store\n*.log",
        python: "# Python\n__pycache__/\n*.py[cod]\n*.egg-info/\n.eggs/\nbuild/\ndist/\n.venv/\nvenv/\nenv/\n.pytest_cache/\n.mypy_cache/\n.coverage\n.env",
        go: "# Go\n/bin/\n/vendor/\n*.exe\n*.test\n*.out\ncoverage.txt\n.env",
        rust: "# Rust\n/target/\n**/*.rs.bk\nCargo.lock\n.env",
        java: "# Java\n*.class\ntarget/\nbuild/\n.gradle/\n*.jar\n*.war\nhs_err_pid*\n.env",
      };
      return T[v.stack] || T.node;
    },
  },
  {
    id: "dv-dockerignore", name: ".dockerignore Generator", cat: "devx",
    desc: "Produce a .dockerignore tuned to a common stack, keeping build context lean.",
    tags: ["dockerignore", "docker", "template"],
    inputs: [{ k: "stack", label: "Stack", type: "select", opts: ["node", "python", "go", "generic"], value: "node" }],
    run(v) {
      const common = ".git\n.gitignore\n*.md\nDockerfile*\n.dockerignore\n.env\n.env.*\n*.log";
      const T = {
        node: `${common}\nnode_modules\nnpm-debug.log\ndist\ncoverage\n.next\n.cache`,
        python: `${common}\n__pycache__\n*.pyc\n.venv\nvenv\n.pytest_cache\ndist\nbuild`,
        go: `${common}\nbin\nvendor\n*.test`,
        generic: `${common}\nbuild\ndist\ntmp`,
      };
      return T[v.stack] || T.generic;
    },
  },
  {
    id: "dv-editorconfig", name: ".editorconfig Generator", cat: "devx",
    desc: "Build an .editorconfig root block from indent, line-ending, and charset settings.",
    tags: ["editorconfig", "formatting", "indent"],
    inputs: [
      { k: "style", label: "Indent style", type: "select", opts: ["space", "tab"], value: "space" },
      { k: "size", label: "Indent size", type: "range", min: 1, max: 8, step: 1, value: 2 },
      { k: "eol", label: "Line ending", type: "select", opts: ["lf", "crlf", "cr"], value: "lf" },
      { k: "charset", label: "Charset", type: "select", opts: ["utf-8", "utf-8-bom", "latin1"], value: "utf-8" },
      { k: "finalnl", label: "Insert final newline", type: "checkbox", value: true },
      { k: "trim", label: "Trim trailing whitespace", type: "checkbox", value: true },
    ],
    run(v, H) {
      const size = H.clampInt(v.size, 1, 8, 2);
      const lines = [
        "root = true", "", "[*]",
        `indent_style = ${v.style}`,
        `indent_size = ${size}`,
        `end_of_line = ${v.eol}`,
        `charset = ${v.charset}`,
        `insert_final_newline = ${v.finalnl ? "true" : "false"}`,
        `trim_trailing_whitespace = ${v.trim ? "true" : "false"}`,
      ];
      return lines.join("\n");
    },
  },
  {
    id: "dv-cron-build", name: "Crontab Expression Builder", cat: "devx",
    desc: "Assemble a five-field cron expression from individual minute, hour, day, month, and weekday fields.",
    tags: ["cron", "crontab", "schedule", "builder"],
    inputs: [
      { k: "min", label: "Minute (0-59)", type: "text", placeholder: "*" },
      { k: "hour", label: "Hour (0-23)", type: "text", placeholder: "*" },
      { k: "dom", label: "Day of month (1-31)", type: "text", placeholder: "*" },
      { k: "mon", label: "Month (1-12)", type: "text", placeholder: "*" },
      { k: "dow", label: "Day of week (0-6)", type: "text", placeholder: "*" },
    ],
    run(v) {
      const f = (x) => (S(x).trim() || "*");
      return `${f(v.min)} ${f(v.hour)} ${f(v.dom)} ${f(v.mon)} ${f(v.dow)}`;
    },
  },
  {
    id: "dv-cron-explain", name: "Crontab Field Explainer", cat: "devx",
    desc: "Describe each field of a five-field cron expression in plain words.",
    tags: ["cron", "crontab", "explain", "schedule"],
    inputs: [{ k: "expr", label: "Cron expression", type: "text", placeholder: "*/15 9-17 * * 1-5" }],
    run(v) {
      const parts = S(v.expr).trim().split(/\s+/);
      if (!S(v.expr).trim()) return "";
      if (parts.length !== 5) return { error: "Expected exactly 5 fields." };
      const names = ["minute", "hour", "day of month", "month", "day of week"];
      const describe = (fld) => {
        if (fld === "*") return "every value";
        if (fld.startsWith("*/")) return `every ${fld.slice(2)}`;
        if (fld.includes("-")) return `range ${fld}`;
        if (fld.includes(",")) return `values ${fld}`;
        return `at ${fld}`;
      };
      return parts.map((p, i) => `${names[i].padEnd(13)}: ${p}  (${describe(p)})`).join("\n");
    },
  },
  {
    id: "dv-curl-build", name: "curl Command Builder", cat: "devx",
    desc: "Compose a curl command from a URL, method, header lines, and an optional body.",
    tags: ["curl", "http", "builder", "request"],
    inputs: [
      { k: "url", label: "URL", type: "text", placeholder: "https://api.example.com/v1/items" },
      { k: "method", label: "Method", type: "select", opts: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"], value: "GET" },
      { k: "headers", label: "Headers (one per line: Name: value)", type: "textarea", rows: 4, placeholder: "Authorization: Bearer TOKEN" },
      { k: "body", label: "Body", type: "textarea", rows: 3, placeholder: '{"name":"x"}' },
    ],
    run(v) {
      if (!S(v.url).trim()) return "";
      const q = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;
      let parts = ["curl"];
      if (v.method && v.method !== "GET") parts.push(`-X ${v.method}`);
      S(v.headers).split("\n").forEach((h) => { if (h.trim()) parts.push(`-H ${q(h.trim())}`); });
      if (S(v.body).trim()) parts.push(`--data ${q(v.body)}`);
      parts.push(q(v.url.trim()));
      return parts.join(" \\\n  ");
    },
  },
  {
    id: "dv-curl-to-fetch", name: "curl to fetch()", cat: "devx",
    desc: "Convert a basic curl command into an equivalent JavaScript fetch() call.",
    tags: ["curl", "fetch", "javascript", "convert"],
    inputs: [{ k: "cmd", label: "curl command", type: "textarea", rows: 4, placeholder: "curl -X POST https://x.com -H 'Content-Type: application/json' -d '{}'" }],
    run(v) {
      const cmd = S(v.cmd).trim();
      if (!cmd) return "";
      // tokenize honoring single/double quotes
      const toks = [];
      const re = /'([^']*)'|"((?:\\.|[^"])*)"|(\S+)/g;
      let m;
      while ((m = re.exec(cmd))) toks.push(m[1] !== undefined ? m[1] : m[2] !== undefined ? m[2] : m[3]);
      let url = "", method = "", body = "";
      const headers = {};
      for (let i = 0; i < toks.length; i++) {
        const t = toks[i];
        if (t === "curl") continue;
        if (t === "-X" || t === "--request") method = toks[++i] || "";
        else if (t === "-H" || t === "--header") { const h = toks[++i] || ""; const ci = h.indexOf(":"); if (ci > 0) headers[h.slice(0, ci).trim()] = h.slice(ci + 1).trim(); }
        else if (t === "-d" || t === "--data" || t === "--data-raw") body = toks[++i] || "";
        else if (!t.startsWith("-")) url = t;
      }
      if (!url) return { error: "No URL found in command." };
      if (!method) method = body ? "POST" : "GET";
      const opts = { method };
      if (Object.keys(headers).length) opts.headers = headers;
      if (body) opts.body = body;
      return `fetch(${JSON.stringify(url)}, ${JSON.stringify(opts, null, 2)});`;
    },
  },
  {
    id: "dv-http-raw", name: "Raw HTTP Request Builder", cat: "devx",
    desc: "Assemble a raw HTTP/1.1 request message from method, path, host, headers, and body.",
    tags: ["http", "raw", "request", "protocol"],
    inputs: [
      { k: "method", label: "Method", type: "select", opts: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], value: "GET" },
      { k: "path", label: "Path", type: "text", placeholder: "/v1/items?id=3" },
      { k: "host", label: "Host", type: "text", placeholder: "api.example.com" },
      { k: "headers", label: "Extra headers (Name: value per line)", type: "textarea", rows: 3, placeholder: "Accept: application/json" },
      { k: "body", label: "Body", type: "textarea", rows: 3 },
    ],
    run(v) {
      const path = S(v.path).trim() || "/";
      const host = S(v.host).trim();
      if (!host) return "";
      const lines = [`${v.method} ${path} HTTP/1.1`, `Host: ${host}`];
      S(v.headers).split("\n").forEach((h) => { if (h.trim()) lines.push(h.trim()); });
      const body = S(v.body);
      if (body) lines.push(`Content-Length: ${new TextEncoder().encode(body).length}`);
      lines.push("");
      lines.push(body);
      return lines.join("\r\n");
    },
  },
  {
    id: "dv-ascii-table", name: "ASCII Reference Table", cat: "devx",
    desc: "List the printable ASCII characters with their decimal, hex, and octal codes.",
    tags: ["ascii", "table", "reference", "hex"],
    inputs: [{ k: "ctrl", label: "Include control chars (0-31)", type: "checkbox", value: false }],
    run(v) {
      const ctrlNames = ["NUL", "SOH", "STX", "ETX", "EOT", "ENQ", "ACK", "BEL", "BS", "HT", "LF", "VT", "FF", "CR", "SO", "SI", "DLE", "DC1", "DC2", "DC3", "DC4", "NAK", "SYN", "ETB", "CAN", "EM", "SUB", "ESC", "FS", "GS", "RS", "US"];
      const start = v.ctrl ? 0 : 32;
      const rows = ["Dec  Hex  Oct   Char"];
      for (let i = start; i <= 126; i++) {
        const label = i < 32 ? ctrlNames[i] : i === 32 ? "SPACE" : String.fromCharCode(i);
        rows.push(`${String(i).padStart(3)}  ${i.toString(16).padStart(2, "0")}   ${i.toString(8).padStart(3, "0")}   ${label}`);
      }
      return rows.join("\n");
    },
  },
  {
    id: "dv-ansi-ref", name: "ANSI Color Reference", cat: "devx",
    desc: "List the 16 standard ANSI foreground and background color codes.",
    tags: ["ansi", "color", "terminal", "reference"],
    inputs: [],
    run() {
      const names = ["Black", "Red", "Green", "Yellow", "Blue", "Magenta", "Cyan", "White"];
      const rows = ["Color      FG   BG   FG(bright) BG(bright)"];
      names.forEach((n, i) => {
        rows.push(`${n.padEnd(10)} ${30 + i}   ${40 + i}   ${90 + i}         ${100 + i}`);
      });
      rows.push("", "Reset = 0   Bold = 1   Underline = 4");
      return rows.join("\n");
    },
  },
  {
    id: "dv-ansi-build", name: "ANSI Escape Builder", cat: "devx",
    desc: "Build an ANSI SGR escape sequence from a style and foreground/background color.",
    tags: ["ansi", "escape", "sgr", "terminal"],
    inputs: [
      { k: "style", label: "Style", type: "select", opts: [["0", "none"], ["1", "bold"], ["2", "dim"], ["3", "italic"], ["4", "underline"], ["7", "reverse"]], value: "1" },
      { k: "fg", label: "Foreground", type: "select", opts: [["", "default"], ["30", "black"], ["31", "red"], ["32", "green"], ["33", "yellow"], ["34", "blue"], ["35", "magenta"], ["36", "cyan"], ["37", "white"]], value: "31" },
      { k: "bg", label: "Background", type: "select", opts: [["", "default"], ["40", "black"], ["41", "red"], ["42", "green"], ["43", "yellow"], ["44", "blue"], ["45", "magenta"], ["46", "cyan"], ["47", "white"]], value: "" },
      { k: "text", label: "Sample text", type: "text", placeholder: "hello" },
    ],
    run(v) {
      const codes = [];
      if (v.style && v.style !== "0") codes.push(v.style);
      if (v.fg) codes.push(v.fg);
      if (v.bg) codes.push(v.bg);
      if (!codes.length) codes.push("0");
      const seq = codes.join(";");
      const txt = S(v.text) || "text";
      return [
        `\\e[${seq}m${txt}\\e[0m`,
        `\\033[${seq}m${txt}\\033[0m`,
        `\\x1b[${seq}m${txt}\\x1b[0m`,
      ].join("\n");
    },
  },
  {
    id: "dv-ascii-box", name: "ASCII Box Drawer", cat: "devx",
    desc: "Wrap multi-line text in a box using ASCII or Unicode box-drawing characters.",
    tags: ["box", "ascii", "unicode", "banner"],
    inputs: [
      { k: "text", label: "Text", type: "textarea", rows: 3, placeholder: "Hello\nWorld" },
      { k: "style", label: "Style", type: "select", opts: ["ascii", "single", "double", "rounded"], value: "single" },
      { k: "pad", label: "Padding", type: "range", min: 0, max: 4, step: 1, value: 1 },
    ],
    run(v, H) {
      const text = S(v.text);
      if (!text) return "";
      const styles = {
        ascii: ["+", "+", "+", "+", "-", "|"],
        single: ["┌", "┐", "└", "┘", "─", "│"],
        double: ["╔", "╗", "╚", "╝", "═", "║"],
        rounded: ["╭", "╮", "╰", "╯", "─", "│"],
      };
      const [tl, tr, bl, br, hz, vt] = styles[v.style] || styles.single;
      const pad = H.clampInt(v.pad, 0, 4, 1);
      const lines = text.split("\n");
      const w = Math.max(...lines.map((l) => l.length));
      const inner = w + pad * 2;
      const top = tl + hz.repeat(inner) + tr;
      const bot = bl + hz.repeat(inner) + br;
      const body = lines.map((l) => vt + " ".repeat(pad) + l.padEnd(w) + " ".repeat(pad) + vt);
      return [top, ...body, bot].join("\n");
    },
  },
  {
    id: "dv-esc-shell", name: "Shell Escape (POSIX)", cat: "devx",
    desc: "Safely single-quote a string for POSIX shells so it is passed literally.",
    tags: ["escape", "shell", "bash", "posix", "quote"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 3 }],
    run(v) {
      const t = S(v.text);
      if (!t) return "";
      return `'${t.replace(/'/g, "'\\''")}'`;
    },
  },
  {
    id: "dv-esc-dquote", name: "Double-Quote Escape", cat: "devx",
    desc: "Escape a string for use inside double quotes (backslash, double-quote, dollar, and backtick).",
    tags: ["escape", "shell", "double-quote"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 3 }],
    run(v) {
      const t = S(v.text);
      if (!t) return "";
      return `"${t.replace(/[\\"$`]/g, (c) => "\\" + c)}"`;
    },
  },
  {
    id: "dv-esc-regex", name: "Regex Escape", cat: "devx",
    desc: "Escape a string so every character is matched literally in a regular expression.",
    tags: ["escape", "regex", "regexp"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 3 }],
    run(v) {
      const t = S(v.text);
      if (!t) return "";
      return t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    },
  },
  {
    id: "dv-esc-sql", name: "SQL Literal Escape", cat: "devx",
    desc: "Escape a string as a single-quoted SQL literal by doubling embedded quotes.",
    tags: ["escape", "sql", "literal", "quote"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 3 }],
    run(v) {
      const t = S(v.text);
      if (!t) return "";
      return `'${t.replace(/'/g, "''")}'`;
    },
  },
  {
    id: "dv-unescape-backslash", name: "Unescape Backslash Sequences", cat: "devx",
    desc: "Interpret C-style backslash escapes (\\n \\t \\r \\0 \\xHH \\uHHHH) into their literal characters.",
    tags: ["unescape", "backslash", "escape", "decode"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4, placeholder: "line1\\nline2\\x41" }],
    run(v) {
      const t = S(v.text);
      if (!t) return "";
      const map = { n: "\n", t: "\t", r: "\r", "0": "\0", b: "\b", f: "\f", v: "\v", "\\": "\\", "'": "'", '"': '"' };
      return t.replace(/\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)/g, (m, g) => {
        if (g[0] === "u") return String.fromCharCode(parseInt(g.slice(1), 16));
        if (g[0] === "x") return String.fromCharCode(parseInt(g.slice(1), 16));
        return map[g] !== undefined ? map[g] : g;
      });
    },
  },
  {
    id: "dv-base-convert", name: "Base Converter (2-36)", cat: "devx",
    desc: "Convert an integer between any two bases from 2 to 36, using big integers for arbitrary size.",
    tags: ["base", "radix", "convert", "hex", "binary"],
    inputs: [
      { k: "num", label: "Number", type: "text", placeholder: "ff" },
      { k: "from", label: "From base", type: "range", min: 2, max: 36, step: 1, value: 16 },
      { k: "to", label: "To base", type: "range", min: 2, max: 36, step: 1, value: 2 },
    ],
    run(v, H) {
      let raw = S(v.num).trim().toLowerCase();
      if (!raw) return "";
      const from = H.clampInt(v.from, 2, 36, 16);
      const to = H.clampInt(v.to, 2, 36, 2);
      let neg = false;
      if (raw[0] === "-") { neg = true; raw = raw.slice(1); }
      const digits = "0123456789abcdefghijklmnopqrstuvwxyz";
      let val = 0n;
      const B = BigInt(from);
      for (const ch of raw) {
        const d = digits.indexOf(ch);
        if (d < 0 || d >= from) return { error: `Digit '${ch}' is invalid for base ${from}.` };
        val = val * B + BigInt(d);
      }
      let out = "";
      const T = BigInt(to);
      if (val === 0n) out = "0";
      else while (val > 0n) { out = digits[Number(val % T)] + out; val /= T; }
      return (neg ? "-" : "") + out;
    },
  },
  {
    id: "dv-bytes-humanize", name: "Byte Size Humanizer", cat: "devx",
    desc: "Turn a raw byte count into a human-readable size, in decimal (1000) or binary (1024) units.",
    tags: ["bytes", "size", "humanize", "kb", "mb"],
    inputs: [
      { k: "bytes", label: "Bytes", type: "text", inputType: "number", placeholder: "1536000" },
      { k: "base", label: "Base", type: "select", opts: [["1024", "Binary (1024, KiB)"], ["1000", "Decimal (1000, KB)"]], value: "1024" },
    ],
    run(v) {
      const raw = S(v.bytes).trim();
      if (!raw) return "";
      const n = Number(raw);
      if (!isFinite(n)) return { error: "Enter a numeric byte count." };
      const base = Number(v.base) === 1000 ? 1000 : 1024;
      const units = base === 1000 ? ["B", "KB", "MB", "GB", "TB", "PB"] : ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
      let x = Math.abs(n), i = 0;
      while (x >= base && i < units.length - 1) { x /= base; i++; }
      const sign = n < 0 ? "-" : "";
      return `${sign}${i === 0 ? x : x.toFixed(2)} ${units[i]}`;
    },
  },
  {
    id: "dv-bytes-parse", name: "Byte Size Parser", cat: "devx",
    desc: 'Parse a human size such as "5 MB" or "2.5GiB" back into an exact byte count.',
    tags: ["bytes", "size", "parse"],
    inputs: [{ k: "text", label: "Size", type: "text", placeholder: "5 MB" }],
    run(v) {
      const t = S(v.text).trim();
      if (!t) return "";
      const m = /^([\d.]+)\s*([a-zA-Z]*)$/.exec(t);
      if (!m) return { error: "Could not parse size." };
      const num = parseFloat(m[1]);
      const unit = m[2].toLowerCase();
      const dec = { "": 1, b: 1, kb: 1e3, mb: 1e6, gb: 1e9, tb: 1e12, pb: 1e15 };
      const bin = { kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3, tib: 1024 ** 4, pib: 1024 ** 5 };
      const mult = dec[unit] !== undefined ? dec[unit] : bin[unit];
      if (mult === undefined) return { error: `Unknown unit '${m[2]}'.` };
      return `${Math.round(num * mult)} bytes`;
    },
  },
  {
    id: "dv-bitrate-humanize", name: "Bitrate Humanizer", cat: "devx",
    desc: "Convert a raw bits-per-second value into kbps / Mbps / Gbps (decimal SI).",
    tags: ["bitrate", "bandwidth", "mbps", "network"],
    inputs: [{ k: "bps", label: "Bits per second", type: "text", inputType: "number", placeholder: "2500000" }],
    run(v) {
      const raw = S(v.bps).trim();
      if (!raw) return "";
      const n = Number(raw);
      if (!isFinite(n)) return { error: "Enter a numeric bitrate." };
      const units = ["bps", "kbps", "Mbps", "Gbps", "Tbps"];
      let x = Math.abs(n), i = 0;
      while (x >= 1000 && i < units.length - 1) { x /= 1000; i++; }
      return `${n < 0 ? "-" : ""}${i === 0 ? x : x.toFixed(2)} ${units[i]}`;
    },
  },
  {
    id: "dv-cron-next", name: "Cron Next Runs", cat: "devx",
    desc: "Compute the next N run times for a standard five-field cron expression, starting from now (local time).",
    tags: ["cron", "schedule", "next", "crontab"],
    inputs: [
      { k: "expr", label: "Cron expression", type: "text", placeholder: "*/15 9-17 * * 1-5" },
      { k: "count", label: "How many", type: "range", min: 1, max: 20, step: 1, value: 5 },
    ],
    run(v, H) {
      const parts = S(v.expr).trim().split(/\s+/);
      if (!S(v.expr).trim()) return "";
      if (parts.length !== 5) return { error: "Expected exactly 5 fields." };
      const mins = cronField(parts[0], 0, 59);
      const hrs = cronField(parts[1], 0, 23);
      const doms = cronField(parts[2], 1, 31);
      const mons = cronField(parts[3], 1, 12);
      let dows = cronField(parts[4], 0, 7);
      if (!mins || !hrs || !doms || !mons || !dows) return { error: "A field is out of range or malformed." };
      if (dows.has(7)) dows.add(0);
      const domRestricted = parts[2] !== "*";
      const dowRestricted = parts[4] !== "*";
      const count = H.clampInt(v.count, 1, 20, 5);
      const out = [];
      const d = new Date();
      d.setSeconds(0, 0);
      d.setMinutes(d.getMinutes() + 1);
      let guard = 0;
      while (out.length < count && guard < 366 * 24 * 60 * 2) {
        guard++;
        if (mins.has(d.getMinutes()) && hrs.has(d.getHours()) && mons.has(d.getMonth() + 1)) {
          const domOk = doms.has(d.getDate());
          const dowOk = dows.has(d.getDay());
          const dayOk = domRestricted && dowRestricted ? (domOk || dowOk) : (domOk && dowOk);
          if (dayOk) out.push(d.toString().replace(/ \(.*\)$/, ""));
        }
        d.setMinutes(d.getMinutes() + 1);
      }
      return out.length ? out.join("\n") : "No matching times within one year.";
    },
  },
  {
    id: "dv-env-parse", name: ".env Parser", cat: "devx",
    desc: "Parse a .env file into a clean key / value table, stripping comments and surrounding quotes.",
    tags: ["dotenv", "env", "parse", "config"],
    inputs: [{ k: "text", label: ".env contents", type: "textarea", rows: 6, placeholder: 'PORT=3000\nNAME="my app"' }],
    run(v) {
      const t = S(v.text);
      if (!t.trim()) return "";
      const rows = [];
      for (const line of t.split("\n")) {
        const s = line.trim();
        if (!s || s.startsWith("#")) continue;
        const eq = s.indexOf("=");
        if (eq < 0) continue;
        let key = s.slice(0, eq).replace(/^export\s+/, "").trim();
        let val = s.slice(eq + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) val = val.slice(1, -1);
        rows.push([key, val]);
      }
      if (!rows.length) return { error: "No KEY=VALUE pairs found." };
      const kw = Math.max(...rows.map((r) => r[0].length));
      return rows.map((r) => `${r[0].padEnd(kw)} = ${r[1]}`).join("\n");
    },
  },
  {
    id: "dv-env-export", name: ".env to export Lines", cat: "devx",
    desc: "Convert .env entries into shell export statements with safely quoted values.",
    tags: ["dotenv", "env", "export", "shell"],
    inputs: [{ k: "text", label: ".env contents", type: "textarea", rows: 6, placeholder: "PORT=3000" }],
    run(v) {
      const t = S(v.text);
      if (!t.trim()) return "";
      const out = [];
      for (const line of t.split("\n")) {
        const s = line.trim();
        if (!s || s.startsWith("#")) continue;
        const eq = s.indexOf("=");
        if (eq < 0) continue;
        const key = s.slice(0, eq).replace(/^export\s+/, "").trim();
        let val = s.slice(eq + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) val = val.slice(1, -1);
        out.push(`export ${key}='${val.replace(/'/g, "'\\''")}'`);
      }
      return out.length ? out.join("\n") : { error: "No KEY=VALUE pairs found." };
    },
  },
  {
    id: "dv-json-to-env", name: "JSON to .env", cat: "devx",
    desc: "Flatten a JSON object into .env lines, upper-casing keys and joining nested paths with underscores.",
    tags: ["json", "dotenv", "env", "convert"],
    inputs: [{ k: "text", label: "JSON object", type: "textarea", rows: 6, placeholder: '{"port":3000,"db":{"host":"localhost"}}' }],
    run(v) {
      const t = S(v.text).trim();
      if (!t) return "";
      let obj;
      try { obj = JSON.parse(t); } catch (e) { return { error: "Invalid JSON: " + e.message }; }
      if (typeof obj !== "object" || obj === null || Array.isArray(obj)) return { error: "Expected a JSON object." };
      const out = [];
      const walk = (o, prefix) => {
        for (const k of Object.keys(o)) {
          const key = (prefix ? prefix + "_" : "") + String(k).toUpperCase().replace(/[^A-Z0-9]+/g, "_");
          const val = o[k];
          if (val && typeof val === "object" && !Array.isArray(val)) walk(val, key);
          else out.push(`${key}=${Array.isArray(val) ? JSON.stringify(val) : String(val)}`);
        }
      };
      walk(obj, "");
      return out.join("\n");
    },
  },
  {
    id: "dv-tab-spaces", name: "Tabs / Spaces Converter", cat: "devx",
    desc: "Convert leading indentation between tabs and spaces at a chosen width.",
    tags: ["indent", "tabs", "spaces", "whitespace"],
    inputs: [
      { k: "text", label: "Code", type: "textarea", rows: 6 },
      { k: "mode", label: "Direction", type: "select", opts: [["t2s", "Tabs to spaces"], ["s2t", "Spaces to tabs"]], value: "t2s" },
      { k: "width", label: "Tab width", type: "range", min: 1, max: 8, step: 1, value: 2 },
    ],
    run(v, H) {
      const t = S(v.text);
      if (!t) return "";
      const w = H.clampInt(v.width, 1, 8, 2);
      const sp = " ".repeat(w);
      return t.split("\n").map((line) => {
        const m = /^([\t ]*)(.*)$/.exec(line);
        let indent = m[1];
        if (v.mode === "t2s") indent = indent.replace(/\t/g, sp);
        else {
          indent = indent.replace(/\t/g, sp); // normalize first
          const n = indent.length;
          indent = "\t".repeat(Math.floor(n / w)) + " ".repeat(n % w);
        }
        return indent + m[2];
      }).join("\n");
    },
  },
  {
    id: "dv-line-endings", name: "Line-Ending Converter", cat: "devx",
    desc: "Normalize a text's line endings to LF, CRLF, or CR.",
    tags: ["line-ending", "eol", "crlf", "lf", "newline"],
    inputs: [
      { k: "text", label: "Text", type: "textarea", rows: 6 },
      { k: "target", label: "Target", type: "select", opts: [["lf", "LF (\\n)"], ["crlf", "CRLF (\\r\\n)"], ["cr", "CR (\\r)"]], value: "lf" },
    ],
    run(v) {
      const t = S(v.text);
      if (!t) return "";
      const nl = { lf: "\n", crlf: "\r\n", cr: "\r" }[v.target] || "\n";
      return t.replace(/\r\n|\r|\n/g, nl);
    },
  },
  {
    id: "dv-strip-trailing", name: "Strip Trailing Whitespace", cat: "devx",
    desc: "Remove trailing spaces and tabs from every line, and optionally collapse trailing blank lines.",
    tags: ["whitespace", "trim", "cleanup", "lint"],
    inputs: [
      { k: "text", label: "Text", type: "textarea", rows: 6 },
      { k: "endblank", label: "Also trim trailing blank lines", type: "checkbox", value: true },
    ],
    run(v) {
      let t = S(v.text);
      if (!t) return "";
      t = t.split("\n").map((l) => l.replace(/[ \t]+$/, "")).join("\n");
      if (v.endblank) t = t.replace(/\n+$/, "\n");
      return t;
    },
  },
  {
    id: "dv-sort-imports", name: "Sort Import Lines", cat: "devx",
    desc: "Sort import (or any) lines alphabetically, keeping blank-line groups optional.",
    tags: ["imports", "sort", "organize"],
    inputs: [
      { k: "text", label: "Import lines", type: "textarea", rows: 6 },
      { k: "ci", label: "Case-insensitive", type: "checkbox", value: true },
    ],
    run(v) {
      const t = S(v.text);
      if (!t.trim()) return "";
      const lines = t.split("\n").filter((l) => l.trim() !== "");
      lines.sort((a, b) => {
        const x = v.ci ? a.toLowerCase() : a, y = v.ci ? b.toLowerCase() : b;
        return x < y ? -1 : x > y ? 1 : 0;
      });
      return lines.join("\n");
    },
  },
  {
    id: "dv-dedupe-sort", name: "Dedupe & Sort List", cat: "devx",
    desc: "Remove duplicate lines and sort the remainder ascending or descending.",
    tags: ["dedupe", "unique", "sort", "list"],
    inputs: [
      { k: "text", label: "Lines", type: "textarea", rows: 6 },
      { k: "ci", label: "Case-insensitive", type: "checkbox", value: false },
      { k: "order", label: "Order", type: "select", opts: [["asc", "Ascending"], ["desc", "Descending"], ["none", "Keep original order"]], value: "asc" },
    ],
    run(v) {
      const t = S(v.text);
      if (!t.trim()) return "";
      const seen = new Set();
      const out = [];
      for (const line of t.split("\n")) {
        const key = v.ci ? line.toLowerCase() : line;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(line);
      }
      if (v.order !== "none") {
        out.sort((a, b) => {
          const x = v.ci ? a.toLowerCase() : a, y = v.ci ? b.toLowerCase() : b;
          return x < y ? -1 : x > y ? 1 : 0;
        });
        if (v.order === "desc") out.reverse();
      }
      return out.join("\n");
    },
  },
  {
    id: "dv-random-token", name: "Secure Random Token", cat: "devx",
    desc: "Generate a cryptographically random token in hex, base64, or URL-safe base64.",
    tags: ["token", "random", "secret", "hex", "base64"],
    inputs: [
      { k: "bytes", label: "Bytes of entropy", type: "range", min: 4, max: 128, step: 1, value: 32 },
      { k: "format", label: "Format", type: "select", opts: ["hex", "base64", "base64url"], value: "hex" },
    ],
    run(v, H) {
      const n = H.clampInt(v.bytes, 4, 128, 32);
      const rb = H.randBytes(n);
      if (v.format === "hex") return H.toHex(rb);
      const b = H.fromBytes(rb);
      // fromBytes may mangle non-UTF8; encode raw bytes to base64 directly instead
      let bin = "";
      for (let i = 0; i < rb.length; i++) bin += String.fromCharCode(rb[i]);
      let out = btoa(bin);
      if (v.format === "base64url") out = out.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      return out;
    },
  },
  {
    id: "dv-htaccess-redirect", name: ".htaccess Redirect Builder", cat: "devx",
    desc: "Build an Apache .htaccess redirect line for a source path to a target URL.",
    tags: ["htaccess", "apache", "redirect", "301"],
    inputs: [
      { k: "from", label: "From path", type: "text", placeholder: "/old-page" },
      { k: "to", label: "To URL", type: "text", placeholder: "https://example.com/new" },
      { k: "code", label: "Type", type: "select", opts: [["301", "301 permanent"], ["302", "302 temporary"]], value: "301" },
      { k: "style", label: "Directive", type: "select", opts: [["redirect", "Redirect"], ["rewrite", "RewriteRule"]], value: "redirect" },
    ],
    run(v) {
      const from = S(v.from).trim(), to = S(v.to).trim();
      if (!from || !to) return "";
      if (v.style === "rewrite") {
        const pat = "^" + from.replace(/^\//, "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "/?$";
        return `RewriteEngine On\nRewriteRule ${pat} ${to} [R=${v.code},L]`;
      }
      return `Redirect ${v.code} ${from} ${to}`;
    },
  },
  {
    id: "dv-nginx-redirect", name: "nginx Redirect Builder", cat: "devx",
    desc: "Build an nginx location block that redirects a path to a target URL.",
    tags: ["nginx", "redirect", "location", "return"],
    inputs: [
      { k: "path", label: "Location path", type: "text", placeholder: "/old" },
      { k: "to", label: "Target URL", type: "text", placeholder: "https://example.com/new" },
      { k: "code", label: "Code", type: "select", opts: [["301", "301 permanent"], ["302", "302 temporary"]], value: "301" },
    ],
    run(v) {
      const path = S(v.path).trim(), to = S(v.to).trim();
      if (!path || !to) return "";
      return `location ${path} {\n    return ${v.code} ${to};\n}`;
    },
  },
  {
    id: "dv-npm-name-validate", name: "npm Package Name Validator", cat: "devx",
    desc: "Check a package name against npm's naming rules and report any violations.",
    tags: ["npm", "package", "validate", "name"],
    inputs: [{ k: "name", label: "Package name", type: "text", placeholder: "@scope/my-pkg" }],
    run(v) {
      const name = S(v.name).trim();
      if (!name) return "";
      const errs = [];
      if (name.length > 214) errs.push("longer than 214 characters");
      if (name !== name.toLowerCase()) errs.push("contains uppercase letters");
      if (/^[._]/.test(name)) errs.push("starts with a dot or underscore");
      if (/^\s|\s$/.test(name)) errs.push("has leading or trailing spaces");
      const scoped = /^@([^/]+)\/([^/]+)$/.exec(name);
      const testable = scoped ? scoped[2] : name;
      if (!scoped && name.startsWith("@")) errs.push("scoped name must be @scope/name");
      if (!/^[a-z0-9._~-]+$/.test(testable)) errs.push("contains characters that are not URL-safe (a-z 0-9 . _ ~ -)");
      const reserved = ["node_modules", "favicon.ico"];
      if (reserved.includes(name)) errs.push("is a reserved name");
      return errs.length ? `INVALID:\n- ${errs.join("\n- ")}` : "VALID npm package name.";
    },
  },
  {
    id: "dv-dockerfile-healthcheck", name: "Dockerfile HEALTHCHECK Builder", cat: "devx",
    desc: "Assemble a Dockerfile HEALTHCHECK instruction from interval, timeout, retries, and a test command.",
    tags: ["docker", "healthcheck", "dockerfile"],
    inputs: [
      { k: "cmd", label: "Test command", type: "text", placeholder: "curl -f http://localhost/ || exit 1" },
      { k: "interval", label: "Interval", type: "text", placeholder: "30s" },
      { k: "timeout", label: "Timeout", type: "text", placeholder: "5s" },
      { k: "retries", label: "Retries", type: "range", min: 1, max: 10, step: 1, value: 3 },
      { k: "start", label: "Start period", type: "text", placeholder: "10s" },
    ],
    run(v, H) {
      const cmd = S(v.cmd).trim();
      if (!cmd) return "";
      const opts = [];
      if (S(v.interval).trim()) opts.push(`--interval=${v.interval.trim()}`);
      if (S(v.timeout).trim()) opts.push(`--timeout=${v.timeout.trim()}`);
      if (S(v.start).trim()) opts.push(`--start-period=${v.start.trim()}`);
      opts.push(`--retries=${H.clampInt(v.retries, 1, 10, 3)}`);
      return `HEALTHCHECK ${opts.join(" ")} \\\n  CMD ${cmd}`;
    },
  },
  {
    id: "dv-systemd-unit", name: "systemd Unit Skeleton", cat: "devx",
    desc: "Generate a systemd service unit file from a description, command, user, and restart policy.",
    tags: ["systemd", "service", "unit", "linux"],
    inputs: [
      { k: "desc", label: "Description", type: "text", placeholder: "My app" },
      { k: "exec", label: "ExecStart", type: "text", placeholder: "/usr/bin/node /srv/app/index.js" },
      { k: "user", label: "User", type: "text", placeholder: "www-data" },
      { k: "after", label: "After", type: "text", placeholder: "network.target" },
      { k: "restart", label: "Restart", type: "select", opts: ["always", "on-failure", "no"], value: "always" },
    ],
    run(v) {
      const exec = S(v.exec).trim();
      if (!exec) return "";
      const after = S(v.after).trim() || "network.target";
      const lines = [
        "[Unit]",
        `Description=${S(v.desc).trim() || "Service"}`,
        `After=${after}`,
        "",
        "[Service]",
        "Type=simple",
        `ExecStart=${exec}`,
      ];
      if (S(v.user).trim()) lines.push(`User=${v.user.trim()}`);
      lines.push(`Restart=${v.restart}`, "RestartSec=3", "", "[Install]", "WantedBy=multi-user.target");
      return lines.join("\n");
    },
  },
  {
    id: "dv-makefile-target", name: "Makefile Target Skeleton", cat: "devx",
    desc: "Generate a Makefile target with prerequisites, recipe lines (tab-indented), and optional .PHONY.",
    tags: ["makefile", "make", "target", "build"],
    inputs: [
      { k: "name", label: "Target name", type: "text", placeholder: "build" },
      { k: "deps", label: "Prerequisites (space-separated)", type: "text", placeholder: "clean deps" },
      { k: "recipe", label: "Recipe (one command per line)", type: "textarea", rows: 3, placeholder: "npm run build" },
      { k: "phony", label: "Mark as .PHONY", type: "checkbox", value: true },
    ],
    run(v) {
      const name = S(v.name).trim();
      if (!name) return "";
      const deps = S(v.deps).trim();
      const out = [];
      if (v.phony) out.push(`.PHONY: ${name}`);
      out.push(`${name}:${deps ? " " + deps : ""}`);
      const recipe = S(v.recipe).split("\n").filter((l) => l.trim() !== "");
      if (!recipe.length) out.push("\t@echo TODO");
      else recipe.forEach((l) => out.push("\t" + l.trim()));
      return out.join("\n");
    },
  },
  {
    id: "dv-gitattributes", name: ".gitattributes Line", cat: "devx",
    desc: "Build a .gitattributes line applying an attribute to a file pattern.",
    tags: ["gitattributes", "git", "lfs", "eol"],
    inputs: [
      { k: "pattern", label: "Pattern", type: "text", placeholder: "*.png" },
      { k: "attr", label: "Attribute", type: "select", opts: [["text", "text (normalize eol)"], ["-text", "-text (never modify)"], ["binary", "binary"], ["text eol=lf", "text eol=lf"], ["text eol=crlf", "text eol=crlf"], ["filter=lfs diff=lfs merge=lfs -text", "Git LFS"]], value: "text" },
    ],
    run(v) {
      const p = S(v.pattern).trim();
      if (!p) return "";
      return `${p} ${v.attr}`;
    },
  },
  {
    id: "dv-license-header", name: "License Header Generator", cat: "devx",
    desc: "Generate a source-file license/copyright header as a comment block for the chosen language.",
    tags: ["license", "header", "copyright", "comment"],
    inputs: [
      { k: "lang", label: "Language", type: "select", opts: [["c", "C / JS / Java (/* */)"], ["hash", "Python / Shell (#)"], ["html", "HTML (<!-- -->)"], ["lua", "Lua / SQL (--)"]], value: "c" },
      { k: "license", label: "License", type: "select", opts: ["MIT", "Apache-2.0", "GPL-3.0", "Proprietary"], value: "MIT" },
      { k: "author", label: "Author / Owner", type: "text", placeholder: "Acme Inc." },
      { k: "year", label: "Year", type: "text", placeholder: "2026" },
    ],
    run(v) {
      const author = S(v.author).trim() || "The Authors";
      const year = S(v.year).trim() || String(new Date().getFullYear());
      const blurbs = {
        MIT: `Copyright (c) ${year} ${author}\nSPDX-License-Identifier: MIT\nPermission is granted, free of charge, under the terms of the MIT License.`,
        "Apache-2.0": `Copyright ${year} ${author}\nSPDX-License-Identifier: Apache-2.0\nLicensed under the Apache License, Version 2.0.`,
        "GPL-3.0": `Copyright (C) ${year} ${author}\nSPDX-License-Identifier: GPL-3.0-or-later\nThis program is free software under the GNU GPL v3 or later.`,
        Proprietary: `Copyright (c) ${year} ${author}. All rights reserved.\nUnauthorized copying or distribution is prohibited.`,
      };
      const body = blurbs[v.license].split("\n");
      if (v.lang === "c") return ["/*", ...body.map((l) => ` * ${l}`), " */"].join("\n");
      if (v.lang === "hash") return body.map((l) => `# ${l}`).join("\n");
      if (v.lang === "lua") return body.map((l) => `-- ${l}`).join("\n");
      return ["<!--", ...body.map((l) => `  ${l}`), "-->"].join("\n");
    },
  },
  {
    id: "dv-todo-extract", name: "TODO / FIXME Extractor", cat: "devx",
    desc: "Scan pasted code and list every line containing TODO, FIXME, HACK, XXX, or NOTE with its line number.",
    tags: ["todo", "fixme", "extract", "comments"],
    inputs: [
      { k: "code", label: "Code", type: "textarea", rows: 8 },
      { k: "tags", label: "Tags", type: "text", placeholder: "TODO,FIXME,HACK,XXX,NOTE" },
    ],
    run(v) {
      const code = S(v.code);
      if (!code.trim()) return "";
      const tags = (S(v.tags).trim() || "TODO,FIXME,HACK,XXX,NOTE").split(",").map((t) => t.trim()).filter(Boolean);
      const re = new RegExp("\\b(" + tags.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")\\b", "i");
      const out = [];
      code.split("\n").forEach((line, i) => { if (re.test(line)) out.push(`${String(i + 1).padStart(4)}: ${line.trim()}`); });
      return out.length ? out.join("\n") : "No matches found.";
    },
  },
  {
    id: "dv-cloc", name: "Count Lines of Code", cat: "devx",
    desc: "Count total, blank, comment, and code lines in pasted source (single-line comment heuristic).",
    tags: ["cloc", "lines", "count", "metrics"],
    inputs: [
      { k: "code", label: "Code", type: "textarea", rows: 10 },
      { k: "comment", label: "Comment prefix", type: "select", opts: [["//", "// (C/JS/Go)"], ["#", "# (Python/Shell)"], ["--", "-- (SQL/Lua)"], [";", "; (Lisp/INI)"]], value: "//" },
    ],
    run(v) {
      const code = S(v.code);
      if (!code.trim()) return "";
      const lines = code.split("\n");
      let blank = 0, comment = 0, codeLines = 0;
      const pre = v.comment;
      for (const line of lines) {
        const t = line.trim();
        if (t === "") blank++;
        else if (t.startsWith(pre)) comment++;
        else codeLines++;
      }
      return [
        `Total   : ${lines.length}`,
        `Code    : ${codeLines}`,
        `Comment : ${comment}`,
        `Blank   : ${blank}`,
      ].join("\n");
    },
  },
  {
    id: "dv-slug-filename", name: "Filename Slugifier", cat: "devx",
    desc: "Turn an arbitrary filename or title into a safe, lower-case, hyphenated slug (extension preserved).",
    tags: ["slug", "filename", "kebab", "sanitize"],
    inputs: [{ k: "name", label: "Filename or title", type: "text", placeholder: "My Report (Final v2).PDF" }],
    run(v) {
      const raw = S(v.name).trim();
      if (!raw) return "";
      const dot = raw.lastIndexOf(".");
      let base = raw, ext = "";
      if (dot > 0 && dot < raw.length - 1) { base = raw.slice(0, dot); ext = raw.slice(dot + 1).toLowerCase(); }
      const slug = base.toLowerCase().normalize("NFKD").replace(/[^\w\s-]/g, "").trim().replace(/[\s_-]+/g, "-").replace(/^-+|-+$/g, "");
      return ext ? `${slug || "file"}.${ext}` : (slug || "file");
    },
  },
  {
    id: "dv-mime-ext", name: "MIME from Extension", cat: "devx",
    desc: "Look up the common MIME type for a file extension.",
    tags: ["mime", "content-type", "extension"],
    inputs: [{ k: "ext", label: "Extension or filename", type: "text", placeholder: ".json" }],
    run(v) {
      const raw = S(v.ext).trim().toLowerCase();
      if (!raw) return "";
      const ext = raw.replace(/^.*\./, "").replace(/^\./, "");
      const T = {
        html: "text/html", htm: "text/html", css: "text/css", js: "text/javascript", mjs: "text/javascript",
        json: "application/json", xml: "application/xml", txt: "text/plain", csv: "text/csv", md: "text/markdown",
        png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", svg: "image/svg+xml", webp: "image/webp", ico: "image/x-icon",
        pdf: "application/pdf", zip: "application/zip", gz: "application/gzip", tar: "application/x-tar",
        mp3: "audio/mpeg", wav: "audio/wav", ogg: "audio/ogg", mp4: "video/mp4", webm: "video/webm",
        woff: "font/woff", woff2: "font/woff2", ttf: "font/ttf", otf: "font/otf",
        wasm: "application/wasm", yaml: "application/yaml", yml: "application/yaml",
      };
      return T[ext] || "application/octet-stream";
    },
  },
  {
    id: "dv-http-status", name: "HTTP Status Quick-Ref", cat: "devx",
    desc: "Look up the reason phrase and category for an HTTP status code.",
    tags: ["http", "status", "code", "reference"],
    inputs: [{ k: "code", label: "Status code", type: "text", inputType: "number", placeholder: "404" }],
    run(v) {
      const raw = S(v.code).trim();
      if (!raw) return "";
      const code = parseInt(raw, 10);
      if (isNaN(code) || code < 100 || code > 599) return { error: "Enter a code from 100-599." };
      const T = {
        100: "Continue", 101: "Switching Protocols", 200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 206: "Partial Content",
        301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 409: "Conflict",
        410: "Gone", 418: "I'm a teapot", 422: "Unprocessable Entity", 429: "Too Many Requests",
        500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
      };
      const cat = code < 200 ? "Informational" : code < 300 ? "Success" : code < 400 ? "Redirection" : code < 500 ? "Client Error" : "Server Error";
      return `${code} ${T[code] || "(unassigned reason phrase)"}\nCategory: ${cat} (${Math.floor(code / 100)}xx)`;
    },
  },
  {
    id: "dv-regex-common", name: "Common Regex Patterns", cat: "devx",
    desc: "Return a ready-to-use regular expression for a common data type.",
    tags: ["regex", "pattern", "email", "url", "validation"],
    inputs: [{ k: "kind", label: "Pattern", type: "select", opts: ["email", "url", "ipv4", "uuid", "date"], value: "email" }],
    run(v) {
      const P = {
        email: "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
        url: "^https?:\\/\\/[^\\s/$.?#].[^\\s]*$",
        ipv4: "^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$",
        uuid: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        date: "^\\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])$",
      };
      return P[v.kind] || P.email;
    },
  },
  {
    id: "dv-random-port", name: "Random Ephemeral Port", cat: "devx",
    desc: "Pick random port numbers from the IANA ephemeral range (49152-65535).",
    tags: ["port", "random", "ephemeral", "network"],
    inputs: [{ k: "count", label: "How many", type: "range", min: 1, max: 20, step: 1, value: 1 }],
    run(v, H) {
      const n = H.clampInt(v.count, 1, 20, 1);
      const lo = 49152, hi = 65535, span = hi - lo + 1;
      const out = [];
      for (let i = 0; i < n; i++) {
        const rb = H.randBytes(2);
        const r = (rb[0] << 8) | rb[1];
        out.push(lo + (r % span));
      }
      return out.join("\n");
    },
  },
  {
    id: "dv-jwt-decode", name: "JWT Decoder", cat: "devx",
    desc: "Decode a JWT's header and payload from base64url without verifying the signature.",
    tags: ["jwt", "token", "decode", "base64url"],
    inputs: [{ k: "jwt", label: "JWT", type: "textarea", rows: 4, placeholder: "eyJhbGc...header.payload.sig" }],
    run(v, H) {
      const t = S(v.jwt).trim();
      if (!t) return "";
      const parts = t.split(".");
      if (parts.length < 2) return { error: "A JWT has at least two dot-separated parts." };
      const dec = (seg) => {
        try {
          const json = H.b64decode(seg, { url: true });
          return JSON.stringify(JSON.parse(json), null, 2);
        } catch (e) { return "(could not decode: " + e.message + ")"; }
      };
      return `--- HEADER ---\n${dec(parts[0])}\n\n--- PAYLOAD ---\n${dec(parts[1])}\n\n--- SIGNATURE ---\n${parts[2] || "(none)"}`;
    },
  },
  {
    id: "dv-commit-lint", name: "Conventional Commit Linter", cat: "devx",
    desc: "Validate a commit message subject against the Conventional Commits format.",
    tags: ["git", "commit", "conventional", "lint"],
    inputs: [{ k: "msg", label: "Commit subject", type: "text", placeholder: "feat(api): add pagination" }],
    run(v) {
      const msg = S(v.msg).trim();
      if (!msg) return "";
      const re = /^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([^)]+\))?(!)?: .+/;
      const m = re.exec(msg);
      const errs = [];
      if (!m) errs.push("does not match <type>(scope): description");
      if (msg.length > 72) errs.push(`subject is ${msg.length} chars (recommend <= 72)`);
      if (m) {
        return `VALID\ntype        : ${m[1]}\nscope       : ${m[2] ? m[2].slice(1, -1) : "(none)"}\nbreaking    : ${m[3] ? "yes" : "no"}` + (errs.length ? `\nwarnings    : ${errs.join("; ")}` : "");
      }
      return `INVALID:\n- ${errs.join("\n- ")}\nExpected: type(scope): description  (types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert)`;
    },
  },
  {
    id: "dv-ua-parse", name: "User-Agent Parser", cat: "devx",
    desc: "Extract the likely browser, engine, and operating system from a User-Agent string (heuristic).",
    tags: ["user-agent", "ua", "browser", "parse"],
    inputs: [{ k: "ua", label: "User-Agent", type: "textarea", rows: 3, placeholder: "Mozilla/5.0 (X11; Linux x86_64) ..." }],
    run(v) {
      const ua = S(v.ua).trim();
      if (!ua) return "";
      let browser = "Unknown", ver = "";
      const bm =
        /(Edg|Edge)\/([\d.]+)/.exec(ua) ? ["Edge", /(?:Edg|Edge)\/([\d.]+)/.exec(ua)[1]] :
        /OPR\/([\d.]+)/.exec(ua) ? ["Opera", /OPR\/([\d.]+)/.exec(ua)[1]] :
        /Firefox\/([\d.]+)/.exec(ua) ? ["Firefox", /Firefox\/([\d.]+)/.exec(ua)[1]] :
        /Chrome\/([\d.]+)/.exec(ua) ? ["Chrome", /Chrome\/([\d.]+)/.exec(ua)[1]] :
        /Version\/([\d.]+).*Safari/.exec(ua) ? ["Safari", /Version\/([\d.]+)/.exec(ua)[1]] : null;
      if (bm) { browser = bm[0]; ver = bm[1]; }
      let os = "Unknown";
      if (/Windows NT 10/.test(ua)) os = "Windows 10/11";
      else if (/Windows NT/.test(ua)) os = "Windows";
      else if (/Android/.test(ua)) os = "Android";
      else if (/iPhone|iPad|iPod/.test(ua)) os = "iOS";
      else if (/Mac OS X/.test(ua)) os = "macOS";
      else if (/Linux/.test(ua)) os = "Linux";
      const engine = /Gecko\/|rv:/.test(ua) && /Firefox/.test(ua) ? "Gecko" : /AppleWebKit/.test(ua) ? "WebKit/Blink" : "Unknown";
      return `Browser : ${browser}${ver ? " " + ver : ""}\nEngine  : ${engine}\nOS      : ${os}`;
    },
  },
  {
    id: "dv-querystring", name: "Query String / JSON", cat: "devx",
    desc: "Convert a URL query string to a JSON object, or a flat JSON object to a query string.",
    tags: ["querystring", "url", "json", "params"],
    inputs: [
      { k: "text", label: "Input", type: "textarea", rows: 4, placeholder: "a=1&b=hello%20world" },
      { k: "mode", label: "Direction", type: "select", opts: [["parse", "Query string to JSON"], ["build", "JSON to query string"]], value: "parse" },
    ],
    run(v) {
      const t = S(v.text).trim();
      if (!t) return "";
      if (v.mode === "parse") {
        const qs = t.replace(/^[?#]/, "");
        const obj = {};
        for (const pair of qs.split("&")) {
          if (!pair) continue;
          const eq = pair.indexOf("=");
          const k = decodeURIComponent((eq < 0 ? pair : pair.slice(0, eq)).replace(/\+/g, " "));
          const val = eq < 0 ? "" : decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, " "));
          if (k in obj) { if (!Array.isArray(obj[k])) obj[k] = [obj[k]]; obj[k].push(val); }
          else obj[k] = val;
        }
        return JSON.stringify(obj, null, 2);
      }
      let obj;
      try { obj = JSON.parse(t); } catch (e) { return { error: "Invalid JSON: " + e.message }; }
      if (typeof obj !== "object" || obj === null) return { error: "Expected a JSON object." };
      const parts = [];
      for (const k of Object.keys(obj)) {
        const val = obj[k];
        const arr = Array.isArray(val) ? val : [val];
        for (const item of arr) parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(item))}`);
      }
      return parts.join("&");
    },
  },
  {
    id: "dv-epoch", name: "Unix Timestamp Converter", cat: "devx",
    desc: "Convert between Unix epoch time and an ISO-8601 date string.",
    tags: ["epoch", "unix", "timestamp", "date", "iso"],
    inputs: [
      { k: "value", label: "Value", type: "text", placeholder: "1727280000 or 2024-09-25T16:00:00Z" },
      { k: "mode", label: "Direction", type: "select", opts: [["e2d", "Epoch to ISO date"], ["d2e", "ISO date to epoch"]], value: "e2d" },
      { k: "unit", label: "Epoch unit", type: "select", opts: [["s", "seconds"], ["ms", "milliseconds"]], value: "s" },
    ],
    run(v) {
      const raw = S(v.value).trim();
      if (!raw) return "";
      if (v.mode === "e2d") {
        const n = Number(raw);
        if (!isFinite(n)) return { error: "Enter a numeric epoch value." };
        const ms = v.unit === "s" ? n * 1000 : n;
        const d = new Date(ms);
        if (isNaN(d.getTime())) return { error: "Out-of-range timestamp." };
        return `ISO (UTC) : ${d.toISOString()}\nLocal     : ${d.toString().replace(/ \(.*\)$/, "")}`;
      }
      const d = new Date(raw);
      if (isNaN(d.getTime())) return { error: "Could not parse date." };
      const ms = d.getTime();
      return `seconds      : ${Math.floor(ms / 1000)}\nmilliseconds : ${ms}`;
    },
  },
];
