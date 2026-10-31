# Darknode — Analysis Engine Master Plan

> A plan to build **hundreds of deterministic, non-AI analysis engines** that
> companies can trust to inspect their **code, dependencies, cloud, configuration
> and financial records** for real defects — accurately, repeatably, and with
> every result backed by evidence a human can verify.
>
> This is heavy machinery, not a class project. The organising principle is
> **soundness and provability over cleverness**: an engine that is small but
> provably correct beats a large one that is occasionally wrong. We would rather
> ship ten engines we can defend line-by-line than a hundred we cannot.

Last updated: 2026-10-11 · Status: PLAN (nothing here is built yet unless noted)

---

## 0. Reading this honestly — what "no errors" actually means

The owner's requirement is "absolutely no errors." We will hold that bar, but we
have to be precise about what is and isn't achievable, because selling a false
promise is the opposite of trustworthy.

There are two very different claims:

1. **Engine correctness — achievable, and non-negotiable.** The engine itself
   must never crash, never produce nondeterministic output, never silently drop
   input, never emit a finding it cannot point to evidence for, and never report
   a location that doesn't exist. Given the same input and the same rule-pack
   version, it must produce **byte-identical** output every time. This is a
   solved engineering problem and we treat any deviation as a release-blocking
   bug. **This is the "no errors" we guarantee.**

2. **Perfect verdicts on every program — provably impossible.** "Does this code
   have a vulnerability?" and "is this transaction fraudulent?" are, in the
   general case, undecidable or unknowable. By Rice's theorem, no analyzer can
   decide non-trivial semantic properties of arbitrary programs with zero false
   positives **and** zero false negatives. Any vendor claiming otherwise is
   lying or measuring a rigged benchmark (see §8 on how benchmark scores are
   gamed). The honest, world-class position is:
   - each rule declares whether it is **sound** (no false negatives, may
     over-report) or **precise** (no false positives, may under-report), and why;
   - every finding carries its **evidence and confidence**, so a human can
     confirm it in seconds;
   - our false-positive and false-negative rates are **measured on public
     corpora and published**, not asserted.

So the product promise is: *"Every finding is explainable and reproducible; the
engine is deterministic and never wrong about its own logic; and our accuracy is
measured in the open, not marketed."* That is a promise we can keep and defend in
front of a CISO. "Magic zero-error AI judgement" is not, and we will never claim
it. This is also why the engines are **non-AI**: a deterministic rule can be
audited, versioned, and proven; a model's verdict cannot.

---

## 1. Design principles (every engine obeys these)

1. **Deterministic.** No randomness, no wall-clock, no network, no model. Same
   input + same rule-pack version ⇒ identical output. Determinism is tested, not
   hoped for (§8.4).
2. **Evidence-first.** A finding without a precise, re-displayable piece of
   evidence (a source span, a data-flow path, a transaction id, a config key) is
   a bug. No "trust me" findings.
3. **Explainable.** Every finding answers: *what* (the defect), *where* (exact
   location/record), *why it matters* (impact), *how we know* (the evidence/path),
   *how to fix it* (concrete remediation), and *how sure we are* (confidence +
   soundness class) with references (CWE/CVE/standard/clause).
4. **Offline-first / self-hostable.** The whole analysis runs on the customer's
   machine or in their VPC. Their source and their ledgers **never leave their
   estate**. This is the core trust differentiator and a hard requirement.
5. **Pure logic, separately testable.** Detection logic is pure functions with no
   I/O (the pattern already used in `public/js/codescan/rules.js`:
   `scanFile(path, src) -> findings[]`). I/O (reading repos, ledgers) lives in a
   thin adapter layer. This is what makes exhaustive unit testing possible.
6. **Versioned rule packs.** Rules are data with stable IDs, a semantic version,
   a changelog, and a soundness/precision declaration. A scan records exactly
   which rule-pack version produced it, so results are reproducible months later.
7. **Standard output.** Findings serialise to **SARIF 2.1.0 (+errata01)** for
   code/config and to a documented JSON schema for financial/data findings, so
   results drop into CI, code review, GRC tooling and dashboards unchanged.
8. **Fail loud, never fake.** If an input can't be parsed, say so and mark that
   file/record **unanalyzed** — never guess, never emit a fabricated result,
   never silently skip. Coverage is reported honestly ("1,482 of 1,500 files
   analyzed; 18 unparseable, listed").

---

## 2. The shared engine core (build this first — everything depends on it)

Before any "hundreds of tools," there is one core. Hundreds of thin, correct
engines on a rock-solid core; never hundreds of independent one-off scripts.

```
            ┌──────────────────────────── Darknode Engine Core ───────────────────────────┐
  inputs →  │  Adapters (repo / archive / paste / ledger / cloud-export)                   │
            │        ↓ (bytes + path/record metadata, no logic)                            │
            │  Decoders & Parsers  →  Normalised IR per domain                              │
            │     • code: tokenizer → AST → CFG → DFG (per language)                        │
            │     • manifests/lockfiles → dependency graph                                  │
            │     • config/IaC → typed resource tree                                        │
            │     • ledgers → canonical double-entry journal model                          │
            │        ↓                                                                       │
            │  Rule Engine (runs versioned rule packs over the IR)                          │
            │        ↓                                                                       │
            │  Finding model  →  dedup / suppress (baseline, ignores) → severity model      │
            │        ↓                                                                       │
            │  Serializers: SARIF 2.1.0 · JSON · CSV · PDF report · provenance manifest     │
            └──────────────────────────────────────────────────────────────────────────────┘
```

**Core components to build:**

- **`engine/core/finding.js`** — the one canonical Finding type (ruleId, title,
  severity, confidence, soundnessClass, location(s), evidence, dataFlow?, fix,
  references[], fingerprint). One shape for every engine. (Generalises the
  finding object already in `codescan/rules.js`.)
- **`engine/core/fingerprint.js`** — stable, content-based finding IDs so the
  same defect gets the same fingerprint across runs/branches (enables baselines,
  "new findings only" in CI, and trend tracking). Must be location-insensitive to
  line drift where possible (hash of normalized context, not raw line number).
- **`engine/core/ruleset.js`** — rule-pack loader: id, version, changelog,
  per-rule soundness/precision + CWE/standard mapping; validates every pack
  against a schema at load; refuses to run an unversioned pack.
- **`engine/core/severity.js`** — deterministic severity from real inputs:
  CVSS 3.1/4.0 base vectors (we already compute CVSS 3.1 in `codescan/rules.js`),
  CISA KEV membership, FIRST EPSS probability. Never a vibe; always a cited basis.
- **`engine/core/sarif.js`** — SARIF 2.1.0 writer (extends `toSarif` already in
  `codescan/rules.js`) + a JSON-schema validator so we never emit invalid SARIF.
- **`engine/core/suppress.js`** — baselines, inline ignores
  (`darknode-ignore`, already supported in codescan), and policy files; every
  suppression is logged with reason, never silent.
- **`engine/core/provenance.js`** — a signed run manifest: input digests,
  engine + rule-pack versions, UTC timestamp, coverage stats, environment. This
  is the artifact an auditor keeps. Reproducibility is provable from it.
- **`engine/core/pool.js`** — bounded-concurrency scheduler (the `pool` pattern
  already in `codescan/github.js`) for scanning large estates without blowing up.

**Reuse, don't rewrite.** The core generalises what already works:
`public/js/codescan/rules.js` (detection, CVSS, SARIF, entropy, manifests) and
`public/js/tools/cloud.js` (69 real offline cloud/K8s/Docker linters) are the
seed. We refactor them onto the core, we do not throw them away.

**Zero-dependency discipline** (matches the platform + Nexus constraint): parsers
and analysis are built on language built-ins. Where a real grammar is needed we
vendor a **permissively licensed** parser (e.g. Tree-sitter grammars, MIT) with
attribution, never leaked/proprietary source. No rule or corpus is ever copied
from a source-available competitor whose license forbids it (e.g. Semgrep's
registry rules) — all rules are written clean-room from the primary standard
(CWE, the language spec, the cloud provider's own docs, the accounting standard).

---

## 3. Engine families (where the "hundreds of tools" actually come from)

The count comes from **rules**, not from hundreds of separate apps. One SAST
engine with 400 audited CWE rules is "hundreds of checks" the honest way. Each
family below is a rule pack (or a small set of them) on the shared core.

### A. Code security — SAST (the flagship)
Real static analysis, not regex grep. Per language: tokenizer → AST → control-flow
graph (CFG) → data-flow graph (DFG) → **taint analysis** (untrusted sources →
sanitizers → dangerous sinks). This is what separates us from toy scanners.
- **Techniques:** AST pattern rules, intra-procedural data-flow, taint tracking
  with source/sanitizer/sink catalogs, control-flow reachability, constant
  propagation, basic inter-procedural summaries where tractable.
- **Rule coverage by CWE:** injection (SQLi, command, LDAP, XPath, template/SSTI),
  XSS (reflected/stored/DOM), path traversal, SSRF, insecure deserialization,
  XXE, open redirect, weak crypto / hardcoded keys, auth/session defects, unsafe
  reflection, prototype pollution, ReDoS, race conditions, etc.
- **Language waves:** JS/TS → Python → Go → Java/Kotlin → PHP → C# → Ruby →
  C/C++ (hardest, last). Each language ships with its own test corpus before it
  ships to users.
- **Seed:** the ~36 code rules already in `codescan/rules.js` become the
  regex/AST-lite tier; the CFG/DFG/taint tier is the new heavy machinery.

### B. Software composition analysis — SCA (dependencies & licenses)
- **Techniques:** parse every manifest **and lockfile** (we already parse
  package-lock, yarn.lock, requirements, go.mod, Cargo.lock, Gemfile.lock in
  `codescan/rules.js`), build the full transitive dependency graph, resolve
  installed versions, match against the **OSV** advisory database with correct
  semver/version-range evaluation, compute whether a fix version exists and the
  minimal safe upgrade. Add **license compliance** (SPDX detection, policy:
  flag copyleft/forbidden licenses), and **dependency-confusion / typosquat**
  heuristics.
- **Determinism note:** advisory data is a versioned snapshot pinned per scan, so
  a re-run of an old scan reproduces exactly. We never silently pull "latest."

### C. Secrets & credential exposure
- **Techniques:** structured detectors per provider (AWS, GCP, GitHub, Stripe,
  Slack, private keys…) + Shannon entropy + context + **optional live
  verification** (is the key actually valid?) to kill false positives — all
  already prototyped in `codescan/rules.js` (15 secret rules, entropy, masking,
  placeholder exclusion, test-path downgrade). Extend to full git-history scan.

### D. Infrastructure-as-code & cloud posture
- **Techniques:** typed resource parsing + policy rules for Terraform,
  CloudFormation, Kubernetes manifests, Dockerfiles, Helm, and cloud config
  exports; IAM policy over-permission analysis (wildcard action/resource), public
  exposure, missing encryption, weak TLS, logging gaps.
- **Seed:** `public/js/tools/cloud.js` already has 69 real offline linters
  (IAM policy linter, S3/bucket policy, security groups, K8s, Dockerfile). These
  become rule packs on the core, plus honest read-only connectors later.

### E. Financial integrity & forensic analytics (the second flagship, non-AI)
Deterministic audit-analytics on a customer's ledgers/journals/AP/AR data. Grounded
in established forensic-accounting method (Nigrini, *Forensic Analytics*), **not**
AI guessing. Every flag is a mathematically defined screen with a stated meaning.
- **Structural integrity (exact, sound):**
  - double-entry validation — every entry balances; debits = credits; sub-ledgers
    reconcile to the general ledger; trial balance ties out.
  - control-total & footing checks; period cut-off integrity; opening/closing
    balance continuity across periods.
  - referential integrity — orphan transactions, dangling vendor/customer/account
    references, broken foreign keys.
- **Anomaly screens (probabilistic, clearly labelled as screens, not proof):**
  - **Benford's Law** first-digit / first-two-digit tests on invoice amounts,
    expenses, journal lines — a deviation points to populations needing review.
    We report the statistic (e.g. MAD, chi-square) and what it does and doesn't
    mean, per Nigrini's own caveat.
  - **duplicate-payment detection** — exact and fuzzy (same vendor+amount+near
    date; transposed invoice numbers; same invoice to merged vendor records).
  - **threshold/structuring tests** — invoices clustered just under approval
    limits; round-number bias; even-amount anomalies.
  - **sequence & gap analysis** — missing/duplicated cheque or invoice numbers,
    out-of-sequence postings.
  - **off-hours / weekend / backdated journal-entry risk**, dormant-account
    reactivation, vendor–employee bank/address matches.
  - **time-series outliers** — spend spikes vs. the account's own history
    (deterministic statistical bounds, not a model).
- **Compliance checks:** GAAP/IFRS presentation sanity checks, tax-arithmetic
  verification, payroll recomputation vs. recorded, VAT/sales-tax recomputation.
- **Input adapters:** CSV/XLSX/OFX/QIF/MT940/CAMT.053 and general-ledger exports,
  all parsed into one canonical double-entry journal model. (Parsing is
  deterministic and heavily fuzz-tested — financial data is messy.)

### F. Data privacy, PII & data-protection
- **Techniques:** typed PII detectors (validated, not naive regex — e.g. Luhn for
  cards, checksum-validated national IDs/IBANs, we already have Luhn in the
  toolkit), PII flow analysis in code (sensitive source → log/response sink),
  data-map generation, GDPR/PCI-DSS/HIPAA scoping reports. Determinism + no data
  egress matters doubly here.

### G. Configuration, crypto-misuse, API & protocol hardening
- App/server config hardening (headers, TLS config, cookie flags — several real
  tools already exist: CSP evaluator, cookie analyzer, email-auth/SPF-DKIM-DMARC),
  crypto API misuse (ECB mode, static IV/salt, weak KDF cost, deprecated algos),
  OpenAPI/API security linting, auth-flow checks.

> Rough honest count at maturity: SAST ~400–600 CWE rules across languages, SCA
> (advisory-driven, effectively unbounded + license policy), secrets ~60–100
> detectors, IaC/cloud ~300+ rules, financial ~60–120 defined tests, privacy
> ~40–80, config/crypto/API ~150+. That is "hundreds of tools" with every single
> one being a named, versioned, tested, explainable check — zero filler.

---

## 4. The finding — the unit everything produces

Every engine, every family, emits the same shape. Example (code):

```jsonc
{
  "ruleId": "js.taint.sql-injection",
  "title": "User input reaches a SQL query without parameterization",
  "severity": "high",            // from CVSS/KEV/EPSS, with basis recorded
  "confidence": "high",
  "soundnessClass": "precise",   // declared per rule: sound | precise | heuristic
  "cwe": ["CWE-89"],
  "location": { "path": "src/users.js", "startLine": 42, "endLine": 42, "startCol": 12 },
  "evidence": {
    "snippet": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
    "dataFlow": [                // the proof: untrusted source → sink
      { "path": "src/users.js", "line": 40, "note": "source: req.params.id (untrusted)" },
      { "path": "src/users.js", "line": 42, "note": "sink: db.query() with interpolated input" }
    ]
  },
  "fix": "Use a parameterized query: db.query('SELECT * FROM users WHERE id = $1', [id]).",
  "references": ["https://cwe.mitre.org/data/definitions/89.html"],
  "fingerprint": "a1b2c3…"       // stable across runs
}
```

The financial finding is the same shape with `location` as a record reference and
`evidence` as the transaction(s) + the exact test statistic that fired.

---

## 5. Accuracy & trust infrastructure (this is what makes it "dependable")

This section is the real product. Anyone can write rules; the moat is proving they
are right and keeping them right.

- **5.1 Golden corpora.** Each engine is scored against public, labelled datasets:
  SAST against **OWASP Benchmark v1.2** (CWE-mapped, Youden-index scored) and
  NIST **Juliet**; SCA against known-vulnerable fixtures with pinned advisory
  snapshots; secrets against labelled true/false fixtures; financial against
  synthetic ledgers with injected, documented fraud patterns and clean controls.
- **5.2 Measured, published accuracy.** We compute and record **true-positive and
  false-positive rates per rule and per engine** (reported separately — never
  hidden behind a single blended index, which is how benchmarks get gamed) and
  ship them in the docs. A rule whose numbers we can't state doesn't ship.
- **5.3 CI accuracy gates.** A rule change that regresses TP rate or inflates FP
  rate beyond its declared budget **fails the build**. Accuracy is a test, not a
  marketing slide.
- **5.4 Determinism gate.** Every engine is run twice on the same input in CI and
  the outputs must be byte-identical; any nondeterminism (map ordering, timestamps
  leaking in, locale) fails the build.
- **5.5 Parser robustness.** Parsers are **fuzzed** and property-tested — they must
  never crash, hang, or mis-locate on malformed/huge/adversarial input; they must
  terminate within bounded time (critical for ReDoS-style self-inflicted hangs).
- **5.6 Differential & metamorphic testing.** Semantically-neutral code
  transformations (rename a var, reformat, add comments) must not change findings;
  where we can, cross-check against another sound tool and investigate every diff.
- **5.7 False-positive discipline.** Every confirmed FP becomes a permanent
  regression test. The FP corpus only grows. This is how precision ratchets up and
  never silently regresses.
- **5.8 Versioning & reproducibility.** Rule packs are semver'd with changelogs;
  advisory data is snapshot-pinned; every scan emits a provenance manifest (§2) so
  a result is reproducible byte-for-byte later. An auditor can re-run and verify.
- **5.9 Explainability review.** No rule ships until a human can read a real
  finding and a real non-finding and immediately see why each is correct. If the
  evidence doesn't make it obvious, the rule isn't done.

---

## 6. Phased roadmap (each wave ships complete, tested, and useful on its own)

No big-bang. Each wave is independently valuable and fully tested before the next.

- **Wave 0 — Core.** Finding model, fingerprinting, ruleset loader, severity,
  SARIF writer+validator, suppression, provenance, pool. Refactor existing
  `codescan/rules.js` + `tools/cloud.js` onto it. Gate: determinism + SARIF-valid
  + all existing tests green. *(The Code Scanner shipped this session is the
  bridgehead — it already does evidence-first, line-anchored, SARIF-exporting
  findings. Wave 0 generalises its guts into the core.)*
- **Wave 1 — SAST tier 1 (JS/TS) with real CFG/DFG/taint** + the OWASP Benchmark
  harness and published accuracy numbers. Proves the method end-to-end on one
  language before scaling.
- **Wave 2 — SCA + licenses** (OSV matching, transitive graph, SPDX policy) and
  **secrets at full strength** (history scan + verification). Both are high-value
  and build on parsers we already have.
- **Wave 3 — IaC/cloud posture** rule packs (fold in the 69 cloud linters) +
  honest read-only cloud connectors.
- **Wave 4 — Financial integrity engine:** structural checks first (exact, sound —
  double-entry, reconciliation, sequence/gap), then the anomaly screens (Benford,
  duplicates, thresholds, time-series) with synthetic corpora and published
  detection rates.
- **Wave 5 — SAST languages 2–4** (Python, Go, Java), each with its own corpus +
  accuracy gate before release.
- **Wave 6 — Privacy/PII + config/crypto/API hardening** packs.
- **Wave 7+ — remaining SAST languages, deeper inter-procedural analysis, more
  financial/compliance checks**, continuous corpus and FP-corpus growth.

Each wave's acceptance gate: deterministic, SARIF/JSON-valid, measured accuracy
published, FP corpus updated, `npm test` green, docs updated, demoable in the Deck.

---

## 7. How it plugs into the product we already have

- **Surface:** these engines power the Deck's Code tab (Code Scanner), a new
  **Cloud** posture workbench, and a new **Financial Integrity** workspace, plus
  the CLI (`darknode`/Nexus), the REST API, and the MCP server — same core,
  many front-ends. Self-hosted/air-gapped is a first-class deployment.
- **Reuse map:** `codescan/rules.js` (detection/CVSS/SARIF/manifests/entropy),
  `codescan/github.js` (repo + OSV adapters, bounded pool), `tools/cloud.js`
  (cloud linters), the toolkit's validated checksums (Luhn/IBAN) for financial
  PII, the core spine in `public/js/core/` (bus/store/entities/result/registry),
  and the existing test harness (`npm test`).
- **No AI in the verdict path.** AI may *explain* a finding in plain English on
  request, but it never decides whether something is a finding, never sets
  severity, and is never required for a scan to run. The engines stand alone.

---

## 8. Risks & hard truths (stated up front, not buried)

- **Undecidability is real (§0).** We compete on measured precision/recall,
  evidence quality, determinism and self-hosting — not on an impossible
  zero-error claim. That honesty is itself a selling point to serious buyers.
- **Benchmark scores are routinely gamed.** Published SAST scores swing wildly
  with benchmark version, CWE subset, and matching rule; most vendors don't
  disclose those. We publish all three and report TP/FP separately, so our
  numbers are reproducible and comparable. (This is a credibility moat.)
- **Benford's Law is a screen, not proof.** We present it exactly as forensic
  accountants do: a pointer to populations that need review, with the statistic
  shown — never "fraud detected."
- **Parsers are the risk surface.** Real-world code and ledgers are malformed in
  endless ways. Robustness (fuzzing, bounded time, honest "unparseable" reporting)
  is treated as core, not polish.
- **License hygiene.** Every vendored grammar is permissively licensed with
  attribution; no rule/corpus is lifted from a license-incompatible competitor.
  All rules are written clean-room from primary standards. This protects the
  owner legally (consistent with the project's standing clean-room rule).
- **Scope honesty.** "Hundreds of tools" is hundreds of audited rules/checks on
  one trustworthy core — never hundreds of shallow scripts. If a round number
  would need filler, we stop and say so.

---

## Appendix — grounding references

- OWASP Benchmark (CWE-mapped Java suite; Youden-index scorecard; v1.2) —
  <https://owasp.org/www-project-benchmark/>
- SARIF v2.1.0 + Errata 01 (OASIS Standard, 2023-08-28) —
  <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os.html>
- OSV — distributed vulnerability database & API — <https://osv.dev/>
- CWE — <https://cwe.mitre.org/> · CVSS — <https://www.first.org/cvss/> ·
  EPSS — <https://www.first.org/epss/> · CISA KEV catalog.
- Mark J. Nigrini, *Forensic Analytics: Methods and Techniques for Forensic
  Accounting Investigations* (2nd ed.) — Benford's Law, duplicate/outlier/
  time-series tests, staged screening methodology.
