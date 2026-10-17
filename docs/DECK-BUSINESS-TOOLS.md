# Deck Business Tools — program reference

Thirty business-only tools for the admin Deck, built on a shared kit. This file is the
contract every tool is built against and the running status of the program.

Standing rules: nothing simulated (synthetic examples are seeded, format-faithful and
labelled "Load example (synthetic)"); inputs ship empty; no emojis; no native dialogs
(`window.dnModal` / `dnConfirm` / `dnPrompt`, `window.showToast(msg, type)` with
type in `info|success|error|warning`); zero browser dependencies; plain-noun names;
full-width layouts on the ink theme; every detection cites a standard; ask before deploy.

## 1. Shared kit (Wave 0) — merged 2026-10-16, suite 1719 green

| Module | Purpose | Key exports |
|---|---|---|
| `public/js/ingest/parse.js` | Format sniffing and streaming parsers | `sniff`, `decodeText`, `iterCsv`, `parseCsv`, `iterNdjson`, `iterJson`, `iterRecords`, `parseXml`, `xmlLite`, `xmlFind`, `xmlFindAll`, `xmlText`, `findColumn`, `normHeader`, `mapColumns`, `flatten`, `parseCef`, `parseLeef`, `parseYamlSubset`, `parseHcl` |
| `public/js/ingest/unpack.js` | zip / gzip in the browser (native `DecompressionStream`) | `unpack`, `unpackAll`, `unzip`, `gunzip`, `inflateRaw`, `canUnpack`, `isArchiveName`, `magic` |
| `public/js/ingest/dropzone.js` | Drag-drop + paste + browse input, auto-unpacks archives | `mountDropzone(el, { onFiles, maxBytes, maxFiles, unpack, paste })` |
| `public/js/ingest/worker.js` | Run an engine function in a Blob module worker with progress | `runInWorker(engineUrl, fn, args, { onProgress })`, `engineUrl(rel, import.meta)` |
| `public/js/core/hash.js` | Stable string hash | `cyrb53` |
| `public/js/core/sink-map.js` | Pure mapping Finding -> graph entities | `DATA_CAP`, `findingKey`, `fitUnder`, `dedupe`, `toEntities`, `summarize` |
| `public/js/core/sink.js` | Browser side: write findings to the Security Graph | `publishFindings`, `attachSinkButton` |
| `public/js/core/register.js` | Team-shareable list of records (graph-mirrored) | `openRegister`, `wsKey`, `isTeam` |
| `public/js/core/export.js` | Downloads and serialisers | `download`, `toCsv`, `toJson`, `toNdjson`, `fileStamp`, `toIcs`, `zipFiles` |
| `scripts/new-deck-tool.mjs` | Scaffold + register a tool; `--check` lints the registry | CLI |
| `public/data/feeds/epss-top.json`, `eol-products.json` | Daily mirrors (FIRST EPSS top-N + KEV; endoflife.date) | via `scripts/refresh-feeds.mjs` |
| `public/data/ref/*.json`, `public/data/controls/*.json` | Static reference tables (breach laws, adequacy, holidays, control catalogs) | `verifyWithCounsel: true` |

Pure modules (`parse`, `unpack`, `worker`, `hash`, `sink-map`, `register`, `export`)
use relative imports only and never touch `window`/`document` at module scope, so they
load in node tests and inside a Blob worker. `graph-bridge.js` cannot load in node
(absolute `/js/` imports), which is why the sink is split into `sink-map` (pure) and
`sink` (browser).

### The Finding shape

```js
{
  id?: string,                      // optional stable id from the engine
  title: string,
  severity: "critical"|"high"|"medium"|"low"|"info",
  confidence: "confirmed"|"likely"|"review",   // what the evidence supports
  status?: "open"|"new"|"investigating"|"resolved"|"closed",
  category?: string,
  description?: string,
  recommendation?: string,
  controls: [{ framework: "MITRE"|"CIS"|"ISO27001"|"NIST-CSF"|"NIST-800-53"|"SOC2"|"PCI"|"GDPR"|string, id: string }],
  evidence?: object[],              // rows (keep <= 50; the engine keeps the full count)
  assets?: [{ type: "ASSET"|"DOMAIN"|"IP"|"IDENTITY"|"VENDOR"|"VULNERABILITY", name: string, data?: object }],
  tags?: string[]
}
```

`toEntities()` names FINDING entities `"<title> (<toolId>:<key>)"` because the graph
bridge de-duplicates by type + lowercased name. Synthetic datasets are tagged `sample`
on every entity, which keeps them out of Findings, Reports and KPIs and prevents merging
with real records. Entity `data` is kept under 38 KB (the worker empties anything over 40 KB).

### Registration (4 sites + cache-busters)

1. `public/js/auth.js` `SIDE_DESC` — blurb.
2. `public/js/auth.js` `show()` — `else if (sec === "<id>") { import("/js/<dir>/<id>.js?v=<stamp>").then(m => live() && m.render<X>(main)); }` inserted before the `setup` branch.
3. `public/js/deck-ui.js` `NAV_DEF` — `["tool", "<id>", "<Label>", IC.<icon>]` in the group.
4. `public/js/ui/explain.js` `EXPLAIN["tool.<id>"]` — enforced by `test/ui/explain.test.mjs`.

Cache-busters: the route `?v=`, `admin.js` (deck-ui import), `deck-ui.js` (explain import),
`index.html` (auth.js twice, identical), `public/sw.js` `CACHE`. The scaffold does all of this:

```
node scripts/new-deck-tool.mjs --id caaudit --label "Conditional Access Audit" --group identity \
  --dir identity --prefix caa --fn renderCaAudit --icon shield --blurb "..." [--write]
node scripts/new-deck-tool.mjs --check
```

## 2. Tool contract (what every agent is held to)

Files: `public/js/<dir>/<id>-engine.js` (pure), `public/js/<dir>/<id>.js` (UI,
`render<X>(main)`, one `<style id="<prefix>-css">`), `test/security/<id>.test.mjs`.
Nothing else is touched by the tool author; registration is central.

Engine: `parseInput(text|files) -> { format, headers, rows, skipped }`,
`analyze(rows, opts, ctx?) -> { summary, findings, tables, skipped, meta }`,
`findingsToCsv(findings)`, `selfTest() -> { pass, tests }`, `DEFAULTS` (thresholds),
`COLUMNS` (header aliases per logical column). Deterministic: the same input produces
byte-identical JSON. A detection whose columns are missing is skipped and reported in
`skipped[]` with a reason — never guessed. Every finding has at least one `controls`
reference, a confidence class and a remediation. `ctx.progress(done, total, label)` is
called every ~1000 rows and must be optional.

UI: header with a one-line honesty note (what runs locally, what — if anything — is
fetched live) → dropzone → auto-detected format with confidence → column-mapping panel
when confidence is not high → thresholds panel (defaults shown, editable) → run in a
worker with a progress bar → KPI strip → sortable findings table (severity pill,
confidence, control chips, evidence count) → evidence drawer → exports (CSV, JSON,
summary TXT, plus tool-specific) → "Add to Security Graph" → "Load example (synthetic)".

Tests: at least 30 cases — one parser test per real export format using a fixture in
the exact vendor layout, determinism, skipped-column reporting, threshold edges,
`selfTest().pass`, `findingsToCsv` shape.

## 3. Catalog and status

Legend: planned · scaffolded · built · merged · deployed

### Wave 1 — Identity & SaaS governance (group `identity`)

| route | Label | prefix | status |
|---|---|---|---|
| `caaudit` | Conditional Access Audit | `caa-` | merged |
| `privaudit` | Privileged Access Audit | `prv-` | merged |
| `nhi` | Non-Human Identity Lifecycle | `nhi-` | merged |
| `jml` | Lifecycle & Offboarding Verifier | `jml-` | merged |
| `oauthgov` | OAuth App Governance | `oag-` | merged |

### Wave 2 — Cloud, infra & fleet

| route | Label | group | prefix | status |
|---|---|---|---|---|
| `iacscan` | IaC Scanner | code | `iac-` | planned |
| `k8saudit` | Kubernetes Audit | code | `k8s-` | planned |
| `cloudtrail` | Cloud Audit Log Hunter | detect | `ctl-` | planned |
| `vulnimport` | Vulnerability Import & SLA | exposure | `vim-` | planned |
| `fleetcomply` | Endpoint Fleet Compliance | exposure | `flt-` | planned |

### Wave 3 — Finance & fraud forensics

| route | Label | group | prefix | status |
|---|---|---|---|---|
| `apforensics` | Accounts Payable Forensics | finsec | `apf-` | planned |
| `cardaudit` | Corporate Card Audit | finsec | `crd-` | planned |
| `payrollguard` | Payroll Integrity | finsec | `pay-` | planned |
| `cloudspend` | Cloud Spend Anomaly | finsec | `csa-` | planned |
| `breachclock` | Breach Notification Clock | risk | `bnc-` | planned |

### Wave 4 — Risk & resilience, compliance ops

| route | Label | group | prefix | status |
|---|---|---|---|---|
| `riskreg` | Risk Register | risk | `rsk-` | planned |
| `evidence` | Control Evidence Calendar | compliance | `evd-` | planned |
| `vendorrisk` | Third-Party Risk Monitor | risk | `tpr-` | planned |
| `backupready` | Backup & Ransomware Readiness | risk | `bkr-` | planned |
| `dmarcreports` | DMARC Report Analyzer | exposure | `dmr-` | planned |

### Wave 5 — Exposure & SecOps data sources

| route | Label | group | prefix | status |
|---|---|---|---|---|
| `domainguard` | Domain Portfolio Guard | exposure | `dmg-` | planned |
| `dnshunt` | DNS Log Threat Hunter | detect | `dnh-` | planned |
| `proxyhunt` | Web Gateway & Shadow SaaS | detect | `pxh-` | planned |
| `netexposure` | Network Scan Diff | exposure | `nxp-` | planned |
| `vpnaudit` | Remote Access Audit | identity | `vpa-` | planned |

### Wave 6 — AppSec, data & governance

| route | Label | group | prefix | status |
|---|---|---|---|---|
| `licenseaudit` | License Compliance | code | `lic-` | planned |
| `apispec` | API Security Review | code | `api-` | planned |
| `dataflow` | Data Inventory & Processing Register | compliance | `dfr-` | planned |
| `awareness` | Awareness & Phishing-Test Analytics | compliance | `awr-` | planned |
| `pentestreg` | Pentest & Audit Finding Tracker | detect | `ptr-` | planned |

The sidebar group `risk` ("Risk") is added with the first risk tool (Wave 3) so the
sidebar never shows an empty group.

## 4. Feeds — what is live and what is frozen

Refreshed daily by `.github/workflows/refresh-feeds.yml` → `scripts/refresh-feeds.mjs`:
`cisa-kev`, `malicious-ips`, `ofac-sdn`, `epss-top`, `eol-products`.
Frozen snapshots (abuse.ch now requires an API key): `malware-urls`, `threat-iocs`,
`botnet-c2`, `ransomware-groups`. A tool that reads a frozen feed shows its `updated`
date and never relies on it as the primary detection. Live, no-key, CORS-friendly sources
used from the browser: FIRST EPSS (`api.first.org`), DNS-over-HTTPS (`dns.google`,
`cloudflare-dns.com`), RDAP, OSV.dev, crt.sh — all already allowed by the hosting CSP.
Anything else goes through the worker's `/api/fetch` proxy (`public/js/net.js dnFetch`).

## 5. Wave procedure

1. Scaffold the wave's tools (one wiring commit), write the five agent briefs.
2. Fan out five agents in isolated worktrees — disjoint files only.
3. Merge; `node test/run.mjs`; `node scripts/new-deck-tool.mjs --check`; browser pass at
   390 / 900 / 1440 / 1920 (render in the Deck iframe, drop a real-format fixture and an
   archive, exports download, "Add to Security Graph" lands in Findings, no overflow or
   clipped text, light and Deck-invert both clean).
4. Commit per tool + wiring, push `origin/main`. Ask before deploy.
5. Update the status tables above.
