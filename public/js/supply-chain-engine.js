// Supply Chain Risk Analyzer — pure engine (manifest/lockfile parsing, typosquat
// detection by edit distance, CVSS v3 base-score math, OSV advisory summarizing,
// risk scoring, SBOM). No network here; the UI pairs this with live OSV.dev queries.
// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.

// OSV.dev ecosystem names keyed by our internal ecosystem id.
export const OSV_ECOSYSTEM = { npm: "npm", pypi: "PyPI", gem: "RubyGems", go: "Go", maven: "Maven", nuget: "NuGet" };

// ---------------------------------------------------------------------------
// Popular package names per ecosystem — the reference set a typosquat imitates.
// Edit distance against this list catches novel squats (not a fixed misspelling
// table). A large, curated set of genuinely high-download packages: wide enough
// to catch real campaigns, well-known enough that the distance+length guards in
// typosquat() keep false positives low. All entries are lower-cased when the
// POPULAR sets are built so matching is case-insensitive across ecosystems.
// ---------------------------------------------------------------------------
const POP = {
  npm: [
    "lodash", "react", "react-dom", "react-router", "react-router-dom", "react-redux", "redux", "redux-thunk",
    "redux-saga", "@reduxjs/toolkit", "express", "axios", "chalk", "commander", "debug", "moment", "webpack",
    "webpack-cli", "webpack-dev-server", "babel", "@babel/core", "@babel/preset-env", "@babel/runtime", "jquery",
    "underscore", "request", "async", "bluebird", "vue", "vue-router", "vuex", "next", "nuxt", "svelte", "typescript",
    "eslint", "eslint-plugin-react", "eslint-plugin-import", "eslint-config-airbnb", "eslint-config-prettier",
    "prettier", "jest", "mocha", "chai", "sinon", "ava", "tape", "jasmine", "karma", "nyc", "cypress", "playwright",
    "puppeteer", "supertest", "nock", "jsdom", "enzyme", "dotenv", "cors", "body-parser", "cookie-parser",
    "express-session", "helmet", "morgan", "multer", "compression", "mongoose", "passport", "socket.io",
    "socket.io-client", "rxjs", "uuid", "classnames", "styled-components", "@emotion/react", "@emotion/styled",
    "tailwindcss", "postcss", "autoprefixer", "sass", "node-sass", "less", "vite", "rollup", "esbuild", "parcel",
    "gulp", "grunt", "browserify", "yargs", "node-fetch", "cross-fetch", "isomorphic-fetch", "undici", "got",
    "superagent", "semver", "glob", "fast-glob", "globby", "minimist", "cross-env", "nodemon", "concurrently",
    "ws", "ioredis", "redis", "pg", "mysql", "mysql2", "sqlite3", "mongodb", "sequelize", "typeorm", "prisma",
    "knex", "graphql", "apollo-server", "@apollo/client", "core-js", "regenerator-runtime", "tslib", "rimraf",
    "mkdirp", "fs-extra", "graceful-fs", "chokidar", "nanoid", "immer", "zustand", "mobx", "formik", "yup", "joi",
    "zod", "ajv", "validator", "bcrypt", "bcryptjs", "jsonwebtoken", "winston", "pino", "bunyan", "date-fns",
    "dayjs", "luxon", "numeral", "qs", "query-string", "url-parse", "cheerio", "nest", "@nestjs/core", "fastify",
    "koa", "hapi", "amqplib", "kafkajs", "bull", "node-cron", "pm2", "inquirer", "ora", "boxen", "figlet",
    "cli-table3", "colors", "kleur", "picocolors", "ansi-colors", "strip-ansi", "wrap-ansi", "chalk-template",
    "enquirer", "prompts", "meow", "execa", "cross-spawn", "shelljs", "which", "del", "make-dir", "tempy",
    "write-file-atomic", "lowdb", "level", "pouchdb", "@faker-js/faker", "chance", "handlebars", "ejs", "pug",
    "marked", "markdown-it", "highlight.js", "prismjs", "moment-timezone", "object-assign", "prop-types",
    "scheduler", "loose-envify", "js-tokens", "inherits", "safe-buffer", "readable-stream", "string_decoder",
    "ms", "mime", "mime-types", "negotiator", "accepts", "type-is", "on-finished", "ee-first", "merge-descriptors",
  ],
  pypi: [
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "scipy", "pillow", "cryptography", "setuptools",
    "pip", "wheel", "six", "boto3", "botocore", "s3transfer", "awscli", "pytest", "pytest-cov", "pytest-django",
    "pytest-asyncio", "pytest-mock", "scrapy", "tensorflow", "torch", "torchvision", "keras", "scikit-learn",
    "matplotlib", "seaborn", "plotly", "bokeh", "dash", "streamlit", "beautifulsoup4", "soupsieve", "lxml",
    "html5lib", "sqlalchemy", "alembic", "celery", "kombu", "amqp", "billiard", "vine", "fastapi", "pydantic",
    "starlette", "uvicorn", "gunicorn", "aiohttp", "httpx", "httpcore", "anyio", "sniffio", "h11", "websockets",
    "jinja2", "markupsafe", "werkzeug", "itsdangerous", "blinker", "pyyaml", "click", "rich", "colorama",
    "termcolor", "tqdm", "certifi", "idna", "charset-normalizer", "paramiko", "redis", "pymongo", "psycopg2",
    "psycopg2-binary", "pymysql", "mysqlclient", "attrs", "packaging", "typing-extensions", "importlib-metadata",
    "zipp", "python-dateutil", "pytz", "cffi", "pycparser", "pyopenssl", "pynacl", "bcrypt", "passlib", "pyjwt",
    "oauthlib", "requests-oauthlib", "google-auth", "grpcio", "protobuf", "selenium", "mock", "coverage", "tox",
    "flake8", "pylint", "black", "isort", "mypy", "bandit", "pyflakes", "pycodestyle", "autopep8", "yapf",
    "marshmallow", "flask-sqlalchemy", "flask-migrate", "flask-login", "flask-cors", "djangorestframework",
    "gevent", "greenlet", "eventlet", "tornado", "twisted", "nltk", "spacy", "gensim", "opencv-python", "imageio",
    "networkx", "sympy", "statsmodels", "jupyter", "ipython", "notebook", "openpyxl", "xlrd", "xlsxwriter",
    "tabulate", "loguru", "structlog", "sentry-sdk", "prometheus-client", "faker", "factory-boy", "hypothesis",
    "freezegun", "python-dotenv", "pyparsing", "chardet", "future", "jmespath", "docutils", "babel", "pygments",
  ],
  gem: [
    "rails", "rake", "bundler", "nokogiri", "rack", "devise", "puma", "sidekiq", "rspec", "rspec-rails", "pg",
    "actionpack", "actionview", "actionmailer", "actioncable", "activerecord", "activesupport", "activemodel",
    "activejob", "activestorage", "railties", "sprockets", "sprockets-rails", "sass-rails", "turbolinks", "jbuilder",
    "byebug", "capybara", "factory_bot", "factory_bot_rails", "faker", "pry", "pry-rails", "rubocop", "rubocop-rails",
    "redis", "sinatra", "httparty", "faraday", "jwt", "bcrypt", "dotenv-rails", "kaminari", "will_paginate",
    "carrierwave", "shrine", "paperclip", "delayed_job", "resque", "mysql2", "sqlite3", "webpacker", "listen",
    "spring", "bootsnap", "mini_magick", "image_processing", "omniauth", "cancancan", "pundit", "ransack",
    "simplecov", "webmock", "vcr", "rails-i18n", "sassc", "nio4r", "websocket-driver", "concurrent-ruby",
  ],
  go: [
    "github.com/gin-gonic/gin", "github.com/stretchr/testify", "golang.org/x/crypto", "golang.org/x/net",
    "golang.org/x/sync", "golang.org/x/text", "golang.org/x/sys", "golang.org/x/tools", "golang.org/x/oauth2",
    "github.com/gorilla/mux", "github.com/gorilla/websocket", "github.com/sirupsen/logrus", "github.com/spf13/cobra",
    "github.com/spf13/viper", "github.com/spf13/pflag", "github.com/pkg/errors", "github.com/go-sql-driver/mysql",
    "github.com/lib/pq", "github.com/jinzhu/gorm", "gorm.io/gorm", "github.com/labstack/echo",
    "github.com/gofiber/fiber", "google.golang.org/grpc", "google.golang.org/protobuf", "github.com/golang/protobuf",
    "github.com/prometheus/client_golang", "go.uber.org/zap", "github.com/json-iterator/go", "github.com/google/uuid",
    "github.com/golang-jwt/jwt", "github.com/aws/aws-sdk-go", "github.com/hashicorp/go-multierror",
    "github.com/davecgh/go-spew", "github.com/pmezard/go-difflib", "gopkg.in/yaml.v2", "gopkg.in/yaml.v3",
  ],
  maven: [
    "org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j:log4j-api",
    "com.fasterxml.jackson.core:jackson-databind", "com.fasterxml.jackson.core:jackson-core",
    "com.fasterxml.jackson.core:jackson-annotations", "org.springframework:spring-core",
    "org.springframework:spring-context", "org.springframework:spring-web", "com.google.guava:guava", "junit:junit",
    "org.junit.jupiter:junit-jupiter", "org.slf4j:slf4j-api", "ch.qos.logback:logback-classic",
    "org.apache.commons:commons-lang3", "commons-io:commons-io", "commons-codec:commons-codec",
    "org.springframework.boot:spring-boot", "org.springframework.boot:spring-boot-starter-web",
    "org.hibernate:hibernate-core", "mysql:mysql-connector-java", "com.h2database:h2", "org.projectlombok:lombok",
    "org.mockito:mockito-core", "org.assertj:assertj-core", "com.squareup.okhttp3:okhttp",
    "com.squareup.retrofit2:retrofit", "io.netty:netty-all", "org.apache.httpcomponents:httpclient",
    "com.google.code.gson:gson", "org.yaml:snakeyaml", "org.postgresql:postgresql", "org.apache.kafka:kafka-clients",
  ],
  nuget: [
    "Newtonsoft.Json", "System.Text.Json", "Serilog", "AutoMapper", "Dapper", "EntityFramework",
    "Microsoft.EntityFrameworkCore", "Moq", "xunit", "NUnit", "FluentAssertions", "Polly", "MediatR",
    "FluentValidation", "RestSharp", "NLog", "log4net", "Swashbuckle.AspNetCore", "StackExchange.Redis",
    "Microsoft.Extensions.Logging", "Microsoft.Extensions.DependencyInjection", "Castle.Core", "HtmlAgilityPack",
    "CsvHelper", "NodaTime", "MassTransit", "Humanizer", "Bogus", "Hangfire", "IdentityServer4",
  ],
};
export const POPULAR = Object.fromEntries(Object.entries(POP).map(([k, v]) => [k, new Set(v.map((x) => x.toLowerCase()))]));

// Levenshtein edit distance (iterative, O(mn)).
export function levenshtein(a, b) {
  a = String(a || ""); b = String(b || "");
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    prev = cur;
  }
  return prev[b.length];
}

// A possible typosquat of a popular package: near in edit distance but not equal.
export function typosquat(name, ecosystem) {
  const set = POPULAR[ecosystem];
  if (!set) return null;
  const n = String(name || "").toLowerCase();
  if (n.length < 3 || set.has(n)) return null; // it IS a known-good package
  let best = null, bestD = 3;
  for (const p of set) {
    const d = levenshtein(n, p);
    if (d > 0 && d < bestD) { bestD = d; best = p; }
  }
  if (best && bestD <= 2 && Math.abs(n.length - best.length) <= 2) return { real: best, distance: bestD };
  return null;
}

// ---------------------------------------------------------------------------
// CVSS v3.x base score from a vector string (official formula). Returns a number
// 0.0–10.0 or null if the vector is missing/unparseable.
// ---------------------------------------------------------------------------
export function cvssV3BaseScore(vector) {
  if (!vector || !/CVSS:3\.[01]/i.test(vector)) return null;
  const m = {};
  String(vector).split("/").forEach((p) => { const [k, v] = p.split(":"); if (k && v) m[k.toUpperCase()] = v.toUpperCase(); });
  const scopeChanged = m.S === "C";
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const PR = (scopeChanged ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 })[m.PR];
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const val = { H: 0.56, L: 0.22, N: 0 };
  const C = val[m.C], I = val[m.I], A = val[m.A];
  if ([AV, AC, PR, UI, C, I, A].some((x) => x == null)) return null;
  const iss = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploit = 8.22 * AV * AC * PR * UI;
  const roundup = (x) => Math.ceil(x * 10) / 10;
  if (impact <= 0) return 0;
  return roundup(Math.min(scopeChanged ? 1.08 * (impact + exploit) : impact + exploit, 10));
}

export function severityFromCvss(score) {
  if (score == null) return "";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "none";
}

// Summarize an OSV vulnerability object into the finding fields the UI shows.
export function summarizeVuln(v) {
  if (!v) return null;
  const aliases = v.aliases || [];
  const cve = aliases.find((a) => /^CVE-/i.test(a)) || aliases[0] || v.id;
  const summary = String(v.summary || v.details || "").replace(/\s+/g, " ").trim().slice(0, 300);
  // Prefer a real CVSS vector; fall back to a qualitative GHSA/database severity.
  let cvss = null;
  for (const s of v.severity || []) { const sc = cvssV3BaseScore(s.score); if (sc != null) { cvss = sc; break; } }
  let severity = severityFromCvss(cvss);
  if (!severity || severity === "none") {
    const lbl = String((v.database_specific && v.database_specific.severity) || "").toUpperCase();
    severity = { LOW: "low", MODERATE: "medium", MEDIUM: "medium", HIGH: "high", CRITICAL: "critical" }[lbl] || "medium";
  }
  const fixed = new Set();
  for (const aff of v.affected || []) for (const rg of aff.ranges || []) for (const ev of rg.events || []) if (ev.fixed) fixed.add(ev.fixed);
  return { id: v.id, cve, summary, severity, cvss, fixed: [...fixed].join(", ") };
}

// ---------------------------------------------------------------------------
// Manifest / lockfile parsers. Each returns an array of
// { name, version, spec, exact, type, ecosystem } or null.
// `exact` = the version is pinned (lockfile or a fixed spec), so OSV results are
// authoritative; otherwise `version` is the lower bound of a range.
// ---------------------------------------------------------------------------
function floorVersion(spec) {
  const s = String(spec == null ? "" : spec).trim();
  const cleaned = s.replace(/^[\^~>=<\s]+/, "").split(/\s|\|\||,|-/)[0].trim();
  const exact = cleaned !== "" && s === cleaned && /^\d+(\.\d+){0,3}/.test(cleaned);
  return { version: cleaned, exact };
}

export function parsePackageJson(text) {
  let pkg; try { pkg = JSON.parse(text); } catch (_) { return null; }
  if (!pkg || (!pkg.dependencies && !pkg.devDependencies && !pkg.peerDependencies)) return null;
  const deps = [];
  // A bare manifest only lists what you asked for directly; the transitive tree
  // lives in the lockfile, so everything here is marked `direct: true`.
  const add = (obj, type) => { if (obj) for (const [name, spec] of Object.entries(obj)) { const { version, exact } = floorVersion(spec); deps.push({ name, version, spec: String(spec), exact, type, ecosystem: "npm", direct: true }); } };
  add(pkg.dependencies, "production"); add(pkg.devDependencies, "development"); add(pkg.peerDependencies, "peer");
  return deps.length ? deps : null;
}

// package-lock.json (npm v1 "dependencies" tree or v2/v3 "packages" map) — exact
// versions for the FULL resolved tree, direct and transitive. `direct` is derived
// from the root project's declared dependencies (v2/v3) or tree depth (v1).
export function parsePackageLock(text) {
  let j; try { j = JSON.parse(text); } catch (_) { return null; }
  if (!j || (!j.packages && !j.dependencies) || !(j.lockfileVersion || j.packages)) return null;
  const deps = []; const seen = new Set();
  const push = (name, version, dev, direct) => {
    if (!name || !version) return;
    const key = name + "@" + version;
    if (seen.has(key)) return;
    seen.add(key);
    deps.push({ name, version, spec: version, exact: true, type: dev ? "development" : "production", ecosystem: "npm", direct });
  };
  if (j.packages) {
    // The root project is key "". Its declared deps are the direct set.
    const root = j.packages[""] || {};
    const directSet = new Set([
      ...Object.keys(root.dependencies || {}), ...Object.keys(root.devDependencies || {}),
      ...Object.keys(root.optionalDependencies || {}), ...Object.keys(root.peerDependencies || {}),
    ]);
    for (const [path, info] of Object.entries(j.packages)) {
      if (!path || !info || !info.version) continue; // "" is the root project
      const name = path.replace(/^.*node_modules\//, "");
      const topLevel = path.split("node_modules/").length === 2; // exactly one node_modules segment
      const direct = directSet.size ? (topLevel && directSet.has(name)) : topLevel;
      push(name, info.version, info.dev, direct);
    }
  }
  if (!deps.length && j.dependencies) {
    // npm v1: a nested tree. Top level = direct, anything in a nested
    // `dependencies` object is transitive.
    const walk = (obj, direct) => {
      for (const [name, info] of Object.entries(obj || {})) {
        if (!info) continue;
        push(name, info.version, info.dev, direct);
        if (info.dependencies) walk(info.dependencies, false);
      }
    };
    walk(j.dependencies, true);
  }
  return deps.length ? deps : null;
}

// yarn.lock (classic v1 and berry v2+). Resolves every entry to its pinned
// version. A lockfile alone does not record which specs were declared directly,
// so `direct` is left undefined (the UI shows these as resolved-tree entries).
export function parseYarnLock(text) {
  const deps = []; const seen = new Set();
  const blocks = String(text).split(/\n(?=\S)/); // split on un-indented lines (block headers)
  for (const block of blocks) {
    const lines = block.split("\n");
    const header = lines[0];
    if (!header || header.startsWith("#") || header.startsWith("__metadata")) continue;
    if (!/:\s*$/.test(header)) continue; // a block header ends with ":"
    const vm = block.match(/\n\s+version:?\s+"?([^"\n]+)"?/);
    if (!vm) continue;
    const version = vm[1].trim();
    // Header is one or more comma-separated specifiers: name@range (name may be
    // scoped like @babel/core, and berry uses name@npm:range).
    for (const spec of header.replace(/:\s*$/, "").split(",")) {
      const s = spec.trim().replace(/^"|"$/g, "");
      if (!s) continue;
      const at = s.lastIndexOf("@");
      if (at <= 0) continue;
      const name = s.slice(0, at);
      if (!name || seen.has(name + "@" + version)) continue;
      seen.add(name + "@" + version);
      deps.push({ name, version, spec: version, exact: true, type: "production", ecosystem: "npm" });
    }
  }
  return deps.length ? deps : null;
}

// Gemfile.lock. `specs:` under GEM is the full resolved tree; the DEPENDENCIES
// section lists the direct deps declared in the Gemfile.
export function parseGemfileLock(text) {
  const lines = String(text).split("\n");
  const specs = []; const directSet = new Set();
  let section = "";
  for (const raw of lines) {
    const line = raw.replace(/\s+$/, "");
    if (/^\S/.test(line)) { section = line.trim().replace(/:$/, ""); continue; }
    if (section === "GEM" || section === "GIT" || section === "PATH") {
      const m = line.match(/^ {4}([A-Za-z0-9_.-]+) \(([^)]+)\)\s*$/); // 4-space indent = a resolved package
      if (m) specs.push({ name: m[1], version: m[2].split(/[\s,]/)[0] });
    } else if (section === "DEPENDENCIES") {
      const m = line.match(/^ {2}([A-Za-z0-9_.-]+)/);
      if (m) directSet.add(m[1].replace(/!$/, ""));
    }
  }
  if (!specs.length) return null;
  const seen = new Set();
  const deps = [];
  for (const s of specs) {
    if (seen.has(s.name + "@" + s.version)) continue;
    seen.add(s.name + "@" + s.version);
    deps.push({ name: s.name, version: s.version, spec: s.version, exact: true, type: "production", ecosystem: "gem", direct: directSet.size ? directSet.has(s.name) : undefined });
  }
  return deps.length ? deps : null;
}

// poetry.lock (TOML). Each [[package]] block pins name + version for the full
// tree. Direct vs transitive is recorded in pyproject.toml, not here.
export function parsePoetryLock(text) {
  const deps = []; const seen = new Set();
  const blocks = String(text).split(/\[\[package\]\]/).slice(1);
  for (const block of blocks) {
    const nm = block.match(/\n\s*name\s*=\s*"([^"]+)"/) || block.match(/^\s*name\s*=\s*"([^"]+)"/);
    const vm = block.match(/\n\s*version\s*=\s*"([^"]+)"/);
    if (!nm || !vm) continue;
    const name = nm[1].toLowerCase();
    const version = vm[1];
    if (seen.has(name + "@" + version)) continue;
    seen.add(name + "@" + version);
    const cat = (block.match(/\n\s*category\s*=\s*"([^"]+)"/) || [])[1];
    deps.push({ name, version, spec: version, exact: true, type: cat === "dev" ? "development" : "production", ecosystem: "pypi" });
  }
  return deps.length ? deps : null;
}

// go.sum. One line per module hash (module version h1:… and module version/go.mod
// h1:…). The build list, deduped by module@version. Direct is in go.mod, not here.
export function parseGoSum(text) {
  const deps = []; const seen = new Set();
  for (const raw of String(text).split("\n")) {
    const m = raw.trim().match(/^(\S+)\s+(v\S+?)(\/go\.mod)?\s+h1:/);
    if (!m) continue;
    const name = m[1];
    const version = m[2].replace(/^v/, "");
    if (!/\./.test(name) || seen.has(name + "@" + version)) continue;
    seen.add(name + "@" + version);
    deps.push({ name, version, spec: "v" + version, exact: true, type: "production", ecosystem: "go" });
  }
  return deps.length ? deps : null;
}

export function parseRequirementsTxt(text) {
  const deps = [];
  for (let line of String(text).split("\n")) {
    line = line.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const m = line.match(/^([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|!=|>|<)?\s*([0-9][^\s;#]*)?/);
    if (!m) continue;
    const spec = (m[2] || "") + (m[3] || "");
    deps.push({ name: m[1].toLowerCase(), version: (m[3] || "").trim(), spec, exact: m[2] === "==", type: "production", ecosystem: "pypi", direct: true });
  }
  return deps.length ? deps : null;
}

export function parseGemfile(text) {
  const deps = [];
  for (const line of String(text).split("\n")) {
    const m = line.match(/gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/);
    if (m) { const { version, exact } = floorVersion(m[2] || ""); deps.push({ name: m[1], version, spec: String(m[2] || ""), exact, type: "production", ecosystem: "gem", direct: true }); }
  }
  return deps.length ? deps : null;
}

export function parseGoMod(text) {
  const deps = []; let inReq = false;
  for (let raw of String(text).split("\n")) {
    const line = raw.trim();
    if (line === "require (") { inReq = true; continue; }
    if (line === ")") { inReq = false; continue; }
    if (inReq || line.startsWith("require ")) {
      const m = line.match(/^(?:require\s+)?([^\s]+)\s+v?([^\s]+)/);
      // go.mod marks transitive requirements with a trailing "// indirect" comment.
      if (m && /\./.test(m[1])) deps.push({ name: m[1], version: m[2].replace(/^v/, ""), spec: m[2], exact: true, type: "production", ecosystem: "go", direct: !/\/\/\s*indirect/.test(line) });
    }
  }
  return deps.length ? deps : null;
}

export function parsePomXml(text) {
  const deps = []; const re = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const raw = (m[3] || "").trim();
    if (/^\$\{/.test(raw) || raw === "") continue; // property ref / managed version — no concrete version to scan
    const { version, exact } = floorVersion(raw.replace(/[[\]()]/g, ""));
    deps.push({ name: m[1].trim() + ":" + m[2].trim(), version, spec: raw, exact, type: "production", ecosystem: "maven", direct: true });
  }
  return deps.length ? deps : null;
}

export function autoDetectAndParse(text) {
  const t = String(text || "").trim();
  if (!t) return null;
  if (t.startsWith("{")) {
    // a lock file has lockfileVersion or a packages/dependencies tree with versions
    if (/"lockfileVersion"|"node_modules\//.test(t)) { const lk = parsePackageLock(t); if (lk) return lk; }
    return parsePackageJson(t) || parsePackageLock(t);
  }
  if (t.includes("<dependency>")) return parsePomXml(t);
  // Lockfiles with their own text formats — detected before the single-line manifests.
  if (/^#\s*yarn lockfile/m.test(t) || /^__metadata:/m.test(t) || /^"?[^"\n@][^"\n]*@[^"\n]+":?\s*\n\s+version:?\s+/m.test(t)) {
    const y = parseYarnLock(t); if (y) return y;
  }
  if (/\[\[package\]\]/.test(t)) { const p = parsePoetryLock(t); if (p) return p; }
  if (/^GEM$/m.test(t) || /^DEPENDENCIES$/m.test(t)) { const g = parseGemfileLock(t); if (g) return g; }
  if (/\s+h1:/.test(t) && /\/go\.mod\s+h1:/.test(t)) { const s = parseGoSum(t); if (s) return s; }
  if (/^\s*gem\s+['"]/m.test(t)) return parseGemfile(t);
  if (/^\s*module\s+/m.test(t) && /\brequire\b/.test(t)) return parseGoMod(t);
  return parseRequirementsTxt(t);
}

// ---------------------------------------------------------------------------
// Threat-intelligence weighting. CVSS says how bad a flaw COULD be; KEV and EPSS
// say whether it is actually being exploited in the wild. A finding may carry:
//   kev:  true  — its CVE is in the CISA Known Exploited Vulnerabilities catalog
//   epss: 0..1  — FIRST EPSS probability of exploitation in the next 30 days
// Both come from live/mirrored data (see kevCveSet / parseEpss) and are set by
// the UI before scoring; the pure math lives here so it is testable.
// ---------------------------------------------------------------------------

// Extra deduction a finding earns from exploitation signals, beyond its severity.
export function threatWeight(f) {
  if (!f) return 0;
  if (f.kev) return 10;                       // actively exploited — the strongest signal
  const e = typeof f.epss === "number" ? f.epss : null;
  if (e == null) return 0;
  if (e >= 0.5) return 6;                      // very likely to be exploited soon
  if (e >= 0.1) return 3;
  if (e >= 0.01) return 1;
  return 0;
}

// Risk score: 100 minus weighted deductions, floored at 0. Severity sets the
// base weight; KEV/EPSS add to it so exploited flaws cost more than theoretical ones.
export function scoreRisk(findings) {
  const w = { critical: 15, high: 8, medium: 3, low: 1 };
  let score = 100;
  for (const f of findings) score -= (w[f.severity] || 1) + threatWeight(f);
  return Math.max(0, score);
}

// Build a Set of upper-cased CVE IDs from the mirrored CISA KEV feed
// (/data/feeds/cisa-kev.json, shape { data: [{ cve, ... }] }) or a raw array.
export function kevCveSet(feed) {
  const rows = Array.isArray(feed) ? feed : (feed && Array.isArray(feed.data) ? feed.data : []);
  const set = new Set();
  for (const r of rows) {
    const cve = typeof r === "string" ? r : (r && (r.cve || r.cveID));
    if (cve) set.add(String(cve).toUpperCase());
  }
  return set;
}

// Parse a FIRST EPSS API response ({ data: [{ cve, epss, percentile }] }) into a
// Map of upper-cased CVE -> { epss, percentile } with numeric values.
export function parseEpss(json) {
  const out = new Map();
  const rows = json && Array.isArray(json.data) ? json.data : [];
  for (const r of rows) {
    if (!r || !r.cve) continue;
    const epss = parseFloat(r.epss);
    if (!Number.isFinite(epss)) continue;
    const percentile = parseFloat(r.percentile);
    out.set(String(r.cve).toUpperCase(), { epss, percentile: Number.isFinite(percentile) ? percentile : null });
  }
  return out;
}

// SBOM generation (CycloneDX XML or SPDX tag-value).
export function generateSBOM(deps, format) {
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  if (format === "cyclonedx") {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">\n  <components>\n';
    for (const d of deps) xml += `    <component type="library">\n      <name>${esc(d.name)}</name>\n      <version>${esc(d.version)}</version>\n      <purl>pkg:${d.ecosystem}/${encodeURIComponent(d.name)}@${encodeURIComponent(d.version)}</purl>\n    </component>\n`;
    return xml + "  </components>\n</bom>";
  }
  let spdx = "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\nDocumentName: supply-chain-analysis\nDocumentNamespace: https://darknode.ai/spdx/" + Date.now() + "\n\n";
  deps.forEach((d, i) => { spdx += `PackageName: ${d.name}\nSPDXID: SPDXRef-Package-${i + 1}\nPackageVersion: ${d.version}\nPackageDownloadLocation: NOASSERTION\nExternalRef: PACKAGE-MANAGER purl pkg:${d.ecosystem}/${encodeURIComponent(d.name)}@${encodeURIComponent(d.version)}\n\n`; });
  return spdx;
}
