// Supply Chain Risk Analyzer — pure engine (manifest/lockfile parsing, typosquat
// detection by edit distance, CVSS v3 base-score math, OSV advisory summarizing,
// risk scoring, SBOM). No network here; the UI pairs this with live OSV.dev queries.
// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.

import { OSV_ECOSYSTEM, detectFormat, parseLockfile } from "./core/lockfiles.js";

// OSV.dev ecosystem names keyed by our internal ecosystem id, and the parsers, live in
// core/lockfiles.js (shared with the Code Scanner and License Audit).
export { OSV_ECOSYSTEM };

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
// Manifest / lockfile parsers (core/lockfiles.js). Each returns an array of
// { name, version, spec, exact, type, ecosystem, direct, line } or null.
// `exact` = the version is pinned (lockfile or a fixed spec), so OSV results are
// authoritative; otherwise `version` is the lower bound of a range.
// ---------------------------------------------------------------------------
export {
  parsePackageJson, parsePackageLock, parseYarnLock, parsePnpmLock, parseGemfileLock, parsePoetryLock, parseGoSum,
  parseRequirementsTxt, parseGemfile, parseGoMod, parsePomXml, parseCargoLock, parsePipfileLock, parseComposerLock,
  parseGradleLockfile,
} from "./core/lockfiles.js";

// Pasted text: recognise the format by content, then parse it.
export function autoDetectAndParse(text) {
  const t = String(text || "").trim();
  return t ? parseLockfile(detectFormat(t), t) : null;
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
