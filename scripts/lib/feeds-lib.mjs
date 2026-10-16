/*
 * feeds-lib.mjs - pure, side-effect-free helpers for scripts/refresh-feeds.mjs.
 *
 * Everything here is deterministic and testable in isolation (test/data/
 * feeds-lib.test.mjs). Network, filesystem and clock access stay in the
 * refresher script. Node 20 builtins only, no dependencies.
 */

const round5 = (v) => Math.round(v * 1e5) / 1e5;

/**
 * Parse the FIRST EPSS daily CSV (epss_scores-current.csv, gunzipped).
 *
 * Shape:
 *   #model_version:v2025.03.14,score_date:2025-10-16T00:00:00+0000
 *   cve,epss,percentile
 *   CVE-1999-0001,0.04753,0.91763
 *
 * The leading comment line is optional; the header line is required. Scores
 * are rounded to 5 decimals (the upstream precision) so that re-serialising
 * never produces float noise like 0.1234500000001.
 */
export function parseEpssCsv(text) {
  if (typeof text !== "string" || !text.trim()) throw new Error("EPSS: empty body");
  const lines = text.split(/\r?\n/);
  let i = 0;
  let modelVersion = null;
  let scoreDate = null;
  // Comment / metadata lines.
  while (i < lines.length && lines[i].startsWith("#")) {
    const meta = lines[i].slice(1);
    const mv = /model_version:\s*([^,\s]+)/.exec(meta);
    const sd = /score_date:\s*([^,\s]+)/.exec(meta);
    if (mv) modelVersion = mv[1];
    if (sd) scoreDate = sd[1];
    i++;
  }
  while (i < lines.length && !lines[i].trim()) i++;
  const header = (lines[i] || "").trim().toLowerCase().split(",");
  const ci = header.indexOf("cve");
  const ei = header.indexOf("epss");
  const pi = header.indexOf("percentile");
  if (ci < 0 || ei < 0 || pi < 0) throw new Error(`EPSS: unexpected header "${lines[i] || ""}"`);
  i++;
  const rows = [];
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (!line || line.startsWith("#")) continue;
    const c = line.split(",");
    const cve = (c[ci] || "").trim();
    const epss = parseFloat(c[ei]);
    const percentile = parseFloat(c[pi]);
    if (!/^CVE-\d{4}-\d{4,}$/i.test(cve) || !Number.isFinite(epss) || !Number.isFinite(percentile)) continue;
    rows.push({ cve: cve.toUpperCase(), epss: round5(epss), percentile: round5(percentile) });
  }
  if (!rows.length) throw new Error("EPSS: no rows parsed");
  return { modelVersion, scoreDate, rows };
}

function byEpssDescThenCve(a, b) {
  if (b.epss !== a.epss) return b.epss - a.epss;
  return a.cve < b.cve ? -1 : a.cve > b.cve ? 1 : 0;
}

/**
 * Pick the top-n rows by EPSS (ties broken by CVE id ascending) and union in
 * every row whose CVE is in `kevCves` (CISA Known Exploited Vulnerabilities),
 * so a KEV entry with a low model score is never dropped from the shipped
 * slice. Output is deduped by CVE and sorted epss desc, then cve asc.
 */
export function selectEpssTop(rows, kevCves = new Set(), n = 5000) {
  const seen = new Map();
  for (const r of Array.isArray(rows) ? rows : []) {
    if (!r || !r.cve) continue;
    const key = String(r.cve).toUpperCase();
    const prev = seen.get(key);
    if (!prev || r.epss > prev.epss) seen.set(key, { cve: key, epss: r.epss, percentile: r.percentile });
  }
  const all = [...seen.values()].sort(byEpssDescThenCve);
  const picked = new Map();
  for (let i = 0; i < all.length && i < n; i++) picked.set(all[i].cve, all[i]);
  if (kevCves && kevCves.size) {
    const kev = new Set([...kevCves].map((c) => String(c).toUpperCase()));
    for (const r of all) if (kev.has(r.cve) && !picked.has(r.cve)) picked.set(r.cve, r);
  }
  return [...picked.values()].sort(byEpssDescThenCve);
}

/**
 * Reduce an endoflife.date per-product response (https://endoflife.date/api/<slug>.json)
 * to the fields the EOL tools need. Field values on that API are string|boolean
 * (e.g. `eol: "2027-04-30"` or `eol: false`, `lts: true`); they are kept as-is
 * and missing fields become null so every cycle has the same keys.
 */
const EOL_FIELDS = ["cycle", "releaseDate", "eol", "latest", "lts", "support", "extendedSupport"];
export function compactEolProduct(apiJson, slug) {
  if (!Array.isArray(apiJson)) throw new Error(`EOL ${slug}: expected an array of cycles`);
  const cycles = apiJson
    .filter((c) => c && typeof c === "object")
    .map((c) => {
      const out = {};
      for (const f of EOL_FIELDS) out[f] = c[f] === undefined ? null : c[f];
      out.cycle = String(out.cycle == null ? "" : out.cycle);
      return out;
    })
    .filter((c) => c.cycle !== "");
  if (!cycles.length) throw new Error(`EOL ${slug}: no cycles`);
  return { product: slug, cycles };
}

/**
 * Allowlist of endoflife.date product slugs shipped in eol-products.json.
 * Slugs were verified against https://endoflife.date/api/all.json on 2026-10-16;
 * the refresher re-verifies at runtime and logs (never fails on) any miss.
 * Spelling notes: alpine-linux (not alpine), mssqlserver (not sqlserver),
 * apache-http-server (not apache), tomcat, chrome, esxi/vcenter, msexchange,
 * panos (not pan-os), cisco-ios-xe, openjdk-builds-from-oracle / eclipse-temurin
 * (no plain "openjdk"/"java"). Not on endoflife.date at all: iis, helm, edge,
 * safari.
 */
export const EOL_PRODUCTS = Object.freeze([
  // Operating systems
  "windows", "windows-server", "windows-embedded", "macos", "ios", "android",
  "ubuntu", "debian", "rhel", "almalinux", "rocky-linux", "centos", "oracle-linux",
  "amazon-linux", "alpine-linux", "sles", "fedora", "freebsd", "openwrt", "routeros",
  // Runtimes and languages
  "nodejs", "python", "openjdk-builds-from-oracle", "eclipse-temurin", "dotnet",
  "dotnetfx", "php", "ruby", "go", "rust", "perl",
  // Databases and data stores
  "postgresql", "mysql", "mariadb", "mongodb", "redis", "elasticsearch", "opensearch",
  "mssqlserver", "oracle-database", "sqlite", "apache-kafka", "rabbitmq",
  // Web, proxy, crypto
  "nginx", "apache-http-server", "tomcat", "haproxy", "openssl", "openvpn",
  // Containers and orchestration
  "kubernetes", "docker-engine", "containerd", "red-hat-openshift", "rancher", "istio",
  "argo-cd", "nomad", "consul", "hashicorp-vault", "terraform", "ansible",
  // Browsers and clients
  "chrome", "firefox", "electron", "visual-studio",
  // Enterprise infrastructure
  "esxi", "vcenter", "proxmox-ve", "msexchange", "office", "sharepoint",
  "citrix-vad", "big-ip", "fortios", "panos", "cisco-ios-xe", "veeam-backup-and-replication",
  // Apps, CMS and frameworks
  "jenkins", "gitlab", "confluence", "jira-software", "keycloak", "nextcloud",
  "wordpress", "drupal", "django", "rails", "spring-framework", "spring-boot",
  "angular", "react", "vue", "laravel", "symfony", "log4j",
  // Observability, security tooling, mail, directory
  "grafana", "prometheus", "kibana", "splunk", "zabbix", "samba", "bind-9", "exim", "postfix",
]);
