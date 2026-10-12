# STRONGROOM — Cyber-Financial Fusion Engine (Master Plan)

> Codename **STRONGROOM** (the hardened vault room of a bank). Placeholder — rename like any
> Darknode flagship. Status: **PLAN ONLY**. Nothing in this document is built yet.
> Companion to [`ENGINE-MASTERPLAN.md`](./ENGINE-MASTERPLAN.md): that plan is the deterministic
> *analysis* platform (code SAST, SCA, secrets, cloud, financial forensics). STRONGROOM is the
> *detection & prevention* platform that sits on top of it and fuses two worlds that every
> existing product keeps apart.

Date: 2026-10-11. Author: Darknode. Target: a genuine multi-thousand-module engine, **≥ 50,000
lines of real, non-filler code** (LOC budget justified in §11).

---

## 0. One sentence

**STRONGROOM is a self-hosted, deterministic engine that watches a company's IT telemetry and its
money telemetry at the same time, stitches them into one timeline per identity / vendor / account,
and raises an alert the moment an intrusion starts turning into a theft — before the wire leaves.**

The event it treats as the crown jewel is not "malware detected." It is **"money is about to move,
and something upstream is wrong."**

---

## 1. The problem STRONGROOM exists to solve

Real corporate theft is almost never one event. It is a **kill chain that crosses the IT/finance
border**, and the border is exactly where today's tools stop seeing:

```
  CYBER SIDE                         ← the border →            FINANCIAL SIDE
  ----------------------------------------------------------------------------------
  phishing / cred theft   →  mailbox rule added  →  vendor "bank change" email
  OAuth token grant       →  MFA device enrolled  →  AP master-data edit (IBAN)
  EDR: LOLBin / persistence→  VPN from new ASN     →  new payee + under-threshold run
  privilege escalation    →  after-hours logon     →  duplicate / split payment
  DLP: finance files moved →  export of vendor list →  wire approval by lone approver
```

- An **email-security** product sees the mailbox rule and the lookalike domain, but has no idea a
  vendor's IBAN just changed in SAP. (Confirmed by the landscape review — email-only tools "can't
  escalate without a finance-side signal.")
- A **payment-fraud / vendor-validation** product (Trustpair, AppZen) sees the IBAN change inside
  the ERP, but has no idea the requester's mailbox was compromised an hour earlier.
- **SIEM / XDR / UEBA** (Exabeam, CrowdStrike, Sentinel) see the logons and the EDR alerts, but
  treat the ledger as out of scope — the review found their financial-transaction coverage
  "generic" at best.

Each silo sees one half. **The theft lives in the seam.** STRONGROOM is built *in the seam*.

### The honest novelty statement (read this before claiming "nothing like it exists")

Every individual capability below already exists somewhere. What does **not** exist, after the
competitive review, is a single product that is **all** of these at once:

1. **Fusion-native** — cyber telemetry and financial/ERP telemetry are first-class peers in one
   correlation graph, not one bolted onto the other.
2. **Deterministic & auditable** — detections are versioned rules with explainable, reproducible
   logic; AI may *explain* an alert, never decide it or set its severity (same discipline as
   [`ENGINE-MASTERPLAN.md`](./ENGINE-MASTERPLAN.md)).
3. **Self-hosted / air-gappable** — the company's ledgers, vendor master, and payroll never leave
   its estate. Every comparable fraud product in the review is cloud SaaS.
4. **Money-weighted** — risk is scored in dollars-at-risk and kill-chain completeness, not an
   abstract 0–100 "anomaly score."

So the claim we can defend in writing is precise: *"No self-hosted, deterministic engine fuses
intrusion telemetry with transaction integrity to detect the end-to-end fund-theft kill chain."*
We will **not** claim we invented UEBA, Benford analysis, or BEC detection — that would be false and
legally reckless. (See §13 and the TOS "no guarantee of detection" clause.)

---

## 2. Competitive landscape (grounding for §1, from the 2026-10-11 review)

| Category | Examples | What they do | The seam they miss |
|---|---|---|---|
| Vendor/payment validation | Trustpair, AppZen | Validate vendor bank accounts, screen AP master data, block risky payees in the payment run — **inside the ERP, cloud SaaS** | No mailbox, identity, or endpoint context |
| Email / BEC security | Abnormal, Proofpoint | Score inbound email, lookalike domains, forwarding rules | No ledger; "can't escalate without a finance-side signal" |
| SIEM / XDR | Splunk, MS Sentinel, CrowdStrike | Centralize cyber telemetry, correlate within the cyber ecosystem | Ledger out of scope; financial coverage generic |
| UEBA | Exabeam | Behavioral baselines on users/entities | Flags "unusual transactions" abstractly, not ERP-grounded |
| Continuous controls monitoring | Tungsten PROCESSIT, ACL/Galvanize | Duplicate-payment, Benford, rounded-amount on the ledger | No live cyber signal; batch/audit cadence |
| OSS forensic analytics | academic Benford R libraries | Statistical screens on a data dump | Not an engine, not live, not fused |

**Takeaway:** the market is mature *within* each column and empty *across* the columns. STRONGROOM
is the horizontal bar across the table. (Sources listed at the end of this file.)

---

## 3. Design principles (non-negotiable)

1. **Deterministic core, AI at the edges.** A detection either fires or it does not, from
   versioned rule logic, reproducibly. The same inputs always yield byte-identical findings and
   fingerprints. An LLM may draft the human-readable narrative of an alert and suggest next steps;
   it never gates, scores, or suppresses. (Mirrors [`ENGINE-MASTERPLAN.md`](./ENGINE-MASTERPLAN.md).)
2. **Your data stays yours.** Default deployment is on-prem / air-gapped. Connectors read from the
   company's own systems; nothing phones home. This is a feature and a legal shield (§13).
3. **No simulations, ever.** No fabricated vendors, demo fraud, or "sample alerts" presented as
   real. Every alert traces to real ingested events or is clearly an empty state. (Darknode house
   rule — see the darkweb-osint cleanup precedent.)
4. **Explainable or it doesn't ship.** Every detection renders its exact triggering evidence,
   the rule id + version, and the kill-chain nodes it stitched. No black boxes.
5. **Measured accuracy, stated honestly.** Each detection declares `sound | precise | heuristic`.
   Precision/recall are measured on labeled corpora and public fraud datasets and published as
   TP/FP, never as a single blended marketing number. Rice's theorem applies: zero-FP + zero-FN on
   arbitrary adversarial behavior is impossible and we say so.
6. **Prevention is a privilege, detection is the default.** STRONGROOM ships in *detect/advise*
   mode. Any *blocking* action (hold a payment run, quarantine an account) is opt-in, reversible,
   dual-controlled, and fully logged. We never silently move or stop money.

---

## 4. Architecture

```
            ┌──────────────────────────── STRONGROOM ────────────────────────────┐
            │                                                                     │
  CYBER     │   Connectors ─▶ Normalizer ─▶ Canonical Event Bus (OCSF-aligned)    │
  sources ──┼──▶ identity / EDR / network / email / DLP / cloud audit             │
            │                                   │                                 │
            │                                   ▼                                 │
  FINANCIAL │   Connectors ─▶ Normalizer ─▶ Canonical Txn Bus (double-entry model)│
  sources ──┼──▶ GL / AP / AR / payroll / treasury / vendor master / expense      │
            │                                   │                                 │
            │                 ┌─────────────────┴─────────────────┐               │
            │                 ▼                                   ▼               │
            │        Entity Resolution                   Detection Engines        │
            │        (identity⇄vendor⇄account⇄asset)      (cyber · fin · FUSION)   │
            │                 │                                   │               │
            │                 ▼                                   ▼               │
            │          Temporal Fusion Graph  ◀───────────  Rule results          │
            │          (kill-chain stitcher)                                      │
            │                 │                                                   │
            │                 ▼                                                   │
            │     Risk Scoring (money-at-risk × chain completeness × confidence)  │
            │                 │                                                   │
            │                 ▼                                                   │
            │   Case Manager ─▶ Response (advise | dual-control block) ─▶ SARIF/   │
            │                                                     report / graph  │
            └─────────────────────────────────────────────────────────────────────┘
```

### 4.1 Shared engine core (built first — reuse, don't rewrite)
Reuse the STRONGROOM core from the [`ENGINE-MASTERPLAN.md`](./ENGINE-MASTERPLAN.md) core: finding
model, deterministic fingerprint, ruleset loader, severity (CVSS/KEV/EPSS for cyber; dollar-impact
for financial), SARIF 2.1.0 writer, suppression, provenance manifest, bounded worker pool. Add:
- **Canonical event schema** aligned to **OCSF** (Open Cybersecurity Schema Framework) for the
  cyber plane so connectors map once.
- **Canonical transaction schema** built on the **double-entry invariant** (every txn balances;
  sub-ledger ↔ GL reconciles) for the financial plane — seeded by the financial engine already
  specified in [`ENGINE-MASTERPLAN.md`](./ENGINE-MASTERPLAN.md) §financial.

### 4.2 Connectors (ingestion)
All read-only by default; each is a small, independently-tested adapter emitting canonical events.

- **Cyber:** Windows Security/Sysmon, Linux auditd, Okta/Entra ID (sign-ins, MFA, OAuth grants,
  app consent), Google Workspace & M365 audit (mailbox rules, delegate adds, forwarding),
  EDR alert feeds (CrowdStrike/Defender export formats), firewall/VPN/NetFlow, DLP events,
  CASB/cloud audit (CloudTrail, Azure Activity, GCP Admin).
- **Financial:** SAP (ECC/S4) GL+AP tables, Oracle ERP/NetSuite, QuickBooks/Xero, ADP/payroll,
  Kyriba/treasury, expense (Concur/Expensify), **vendor master** change logs, bank statement
  (BAI2/MT940/camt.053), payment files (ISO 20022 pain.001 / NACHA / SWIFT).
- Ingestion is **batch or streaming**; STRONGROOM is correct either way (replayable, idempotent).

### 4.3 Entity resolution
The join that makes fusion possible. Resolve and link:
`identity (human)` ⇄ `mailbox` ⇄ `ERP user` ⇄ `approver role` ⇄ `vendor record` ⇄ `bank account`
⇄ `endpoint/asset` ⇄ `payment`. Deterministic matching (exact keys, normalized names, domain and
IBAN canonicalization) with confidence tiers; no fuzzy guess silently drives a block.

### 4.4 Temporal Fusion Graph
The heart. A time-ordered graph where nodes are canonical events/txns and entities, edges are
`same-actor`, `same-vendor`, `same-account`, `causally-before-within-Δt`. Kill-chain stitching
walks the graph to assemble candidate chains (§5.3) and compute completeness.

---

## 5. Detection content (what actually fires)

Three libraries of **versioned, audited rules**. Hundreds of rules on one core — never hundreds of
scripts. Each rule: id, version, soundness class, data requirements, rationale citing a primary
source (MITRE ATT&CK technique, ACFE/Nigrini fraud scheme, or a regulator advisory), and a labeled
test fixture.

### 5.1 Cyber detections (the "something upstream is wrong" signals)
Grounded in **MITRE ATT&CK**. Examples (non-exhaustive): impossible-travel & new-ASN logon, MFA
fatigue / device-enrollment anomaly, OAuth illicit-consent grant, new inbox forwarding/hiding rule,
mailbox delegate add, EDR persistence/LOLBin, privilege escalation, DLP export of finance artifacts
(vendor list, payment template), after-hours admin on finance systems.

### 5.2 Financial-integrity detections (the "money is moving wrong" signals)
Grounded in **ACFE scheme taxonomy** and **Nigrini forensic analytics**. Structural/exact first,
then statistical screens:
- **Structural/exact:** double-entry imbalance, sub-ledger↔GL break, trial-balance drift, broken
  payment sequence/gaps, cut-off violations, PO↔invoice↔receipt (3-way match) failure.
- **Scheme rules:** new vendor paid within N days of creation, vendor bank account changed then
  paid, duplicate invoice (vendor×number×amount fuzzy), split/under-threshold structuring, round-
  number clustering, vendor-employee bank/address/tax-id collision (ghost vendor), lone-approver
  wire, dormant-vendor reactivation, payroll ghost employee, expense policy evasion.
- **Statistical screens (labeled as screens, not proof):** Benford first/first-two-digit MAD &
  chi-square, duplicate/near-duplicate clustering, time-series payment-volume outliers, off-hours
  / weekend / period-end journal entries, manual-JE concentration by user.

### 5.3 FUSION detections — the novel core (cyber × financial)
These are what no competitor can express, because no competitor has both planes in one graph. Each
is a **correlated chain** with a time window and an entity join. Illustrative catalogue:

| Fusion rule | Cyber leg | Financial leg | Join / window |
|---|---|---|---|
| **BEC payment redirect** | inbox forwarding rule or VEC lookalike email to AP | vendor IBAN change + payment to new account | same vendor/approver, ≤ 30d |
| **Account-takeover disbursement** | impossible-travel / new-device logon for finance user | that user initiates/approves a wire | same identity, ≤ 24h |
| **Illicit-consent exfil→fraud** | OAuth app granted mailbox scope | vendor list exported, then new payee added | same mailbox→ERP user, ≤ 7d |
| **Insider ghost vendor** | DLP export of vendor master by employee | new vendor sharing that employee's bank/address | same person, ≤ 90d |
| **Privilege-escalation JE** | priv-esc on finance host | manual journal entry / masterdata edit from it | same asset→session, ≤ 1h |
| **After-hours structuring** | after-hours VPN from new ASN | burst of under-threshold payments | same approver, same night |

A fusion alert's severity is driven by **(dollars at risk) × (kill-chain completeness) ×
(leg confidence)** — see §8. A single leg alone is a low-severity advisory; a stitched chain to a
pending disbursement is a top-severity, block-eligible case.

---

## 6. Canonical data model (abridged)

- **Cyber event:** `{ts, actor_identity, src_asset, action (OCSF class), target, channel, raw_ref}`
- **Transaction:** `{ts, type, debit[], credit[], amount, currency, vendor_ref, account_ref,
  initiator, approver[], source_system, doc_refs[]}` — always balances.
- **Entities:** `Identity, Mailbox, ErpUser, Role, Vendor, BankAccount, Asset, Payment, Invoice,
  JournalEntry, Employee` — each with resolution keys and a change-history log.
- **Chain:** `{id, rule_id@version, nodes[], entities[], window, money_at_risk, completeness,
  confidence, status, evidence[]}`.

Everything is content-addressed; a chain's fingerprint is stable across runs (dedupe + audit).

---

## 7. Correlation engine

Deterministic, replayable stream/graph processor: ingest → resolve entities → append to temporal
graph → evaluate windowed fusion rules on each new node → emit/extend chains. Backpressure via the
bounded pool. Exactly-once chain identity via fingerprint. Replay of a captured event log must
reproduce identical chains (a core test).

---

## 8. Risk scoring (money-weighted, deterministic)

`risk = normalize( money_at_risk ) · chain_completeness · min(leg_confidence)` with an SSVC-style
decision layer (Act / Attend / Track) rather than a fake grade. Every input is shown on the alert:
"USD 340,000 pending · chain 5/6 stages · lowest-confidence leg: IBAN-change (exact)." Never a
single opaque number, never a letter grade, never a "certification."

---

## 9. Case management & response

- **Case manager:** chains become cases; timeline view over the fusion graph; assignment, notes,
  disposition, SLA; immutable audit log; export to SARIF / PDF / the existing Security Graph.
- **Response ladder (opt-in, reversible, dual-control):** advise → require out-of-band vendor
  verification (phone number from *original* master record, per the BEC guidance) → hold payee in
  the next payment run → freeze account. Blocking actions always need two approvers and are fully
  logged. STRONGROOM **never** moves money and never blocks silently.

---

## 10. Roadmap (waves)

- **Wave 0 — Core & schemas.** Finding model, OCSF event + double-entry txn schemas, fingerprint,
  ruleset loader, provenance, bounded pool, SARIF. Reuse the ENGINE-MASTERPLAN core.
- **Wave 1 — Financial plane.** Connectors (QuickBooks/Xero/CSV first, then SAP/Oracle/NetSuite),
  structural + scheme + statistical detections. Validated on public fraud datasets.
- **Wave 2 — Cyber plane.** Connectors (Entra/Okta, M365/Google audit, Sysmon/auditd, EDR export),
  ATT&CK-mapped detections.
- **Wave 3 — Entity resolution + Temporal Fusion Graph.** The join + graph + replay harness.
- **Wave 4 — Fusion detections.** The §5.3 catalogue; money-weighted scoring.
- **Wave 5 — Case manager + advise-mode response.** Timelines, dispositions, reporting.
- **Wave 6 — Dual-control prevention + deeper connectors (ISO 20022, SWIFT, treasury).**
- **Wave 7 — Accuracy program + hardening** (§12).

Each wave ships real, tested capability; none ships filler.

---

## 11. LOC budget (how ≥ 50,000 lines are honest, not padded)

Rough, defensible module budget for genuine engine code (excludes generated code, vendored MIT
parsers, and tests, which add more on top):

| Area | Modules | Est. LOC |
|---|---|---|
| Shared core (schemas, fingerprint, loader, SARIF, pool, provenance) | ~18 | 4,500 |
| Cyber connectors (≈12 sources, one adapter each + normalizers) | ~30 | 7,000 |
| Financial connectors (≈12 sources incl. SAP/Oracle/ISO 20022/BAI2) | ~34 | 9,000 |
| Entity resolution (matchers, canonicalizers, confidence) | ~16 | 3,500 |
| Temporal fusion graph + correlation engine | ~20 | 5,500 |
| Cyber detections (ATT&CK-mapped rules + helpers) | ~120 rules | 6,000 |
| Financial detections (structural + scheme + statistical) | ~140 rules | 7,000 |
| **Fusion detections** (the novel chains) | ~60 rules | 4,000 |
| Risk scoring + SSVC decision layer | ~10 | 1,500 |
| Case manager + timeline + reporting (SARIF/PDF/graph) | ~26 | 5,500 |
| Response ladder + dual-control + audit log | ~14 | 2,500 |
| **Subtotal (engine)** | | **~55,500** |
| Test fixtures + corpora harness (separate, additive) | | +12,000 |

The number is reached by **breadth of real connectors and audited rules on one core**, which is
exactly how the fusion value is delivered — not by inflating any single file. (Same anti-filler
discipline as the Nexus and core-spine work.)

---

## 12. Accuracy & verification program

- **Labeled corpora:** public fraud datasets (e.g. synthetic-but-labeled AP datasets, PaySim-style
  transaction sets), MITRE ATT&CK evaluation logs, and internally labeled fusion scenarios.
- **Metrics:** per-rule precision/recall, reported as TP/FP/FN separately, versioned. No blended
  score. Regression-gated in CI.
- **Replay determinism test:** a captured event log must produce byte-identical chains and
  fingerprints on every run and platform.
- **Red-team fixtures:** each fusion rule ships with an adversarial fixture that *evades* a
  single-plane tool but is caught by the fused chain — this is the proof of the thesis.

---

## 13. What STRONGROOM is NOT (legal & scope honesty)

Ties directly to the business TOS work (the "No guarantee of detection" and financial-analysis
disclaimers):
- **Not an auditor.** Financial detections are investigative screens, not an audit, not an
  accusation of fraud, not accounting/legal/tax advice.
- **Not a guarantee.** It cannot catch every theft; false negatives are inevitable (Rice's theorem,
  adversarial evasion). A quiet dashboard is not proof of safety.
- **Not autonomous over money.** It never initiates, moves, or silently blocks funds.
- **Not a surveillance tool to deploy on people without authority.** Monitoring employees and
  financial data carries employment-law, privacy, and works-council obligations that vary by
  jurisdiction. STRONGROOM ships guidance to deploy lawfully; the customer is responsible for doing
  so. **A licensed attorney and the customer's compliance function must review deployment** —
  especially outside the US.

---

## 14. Fit with the existing Darknode ecosystem

- **Security Graph:** chains and entities feed the existing graph via `graph-bridge`.
- **Deck:** a new "Fund Protection" / "Fusion" workspace surfaces cases and the money-at-risk board.
- **ENGINE-MASTERPLAN financial engine:** STRONGROOM's financial plane *is* that engine, promoted
  from batch analysis to live detection.
- **Self-host / worker:** on-prem bundle; the Cloudflare worker proxy is only for optional public
  enrichment, never for customer ledger data.

---

## Sources (2026-10-11 competitive review)

- Trustpair in SAP ERP — https://www.sap.com/products/financial-management/partners/trustpair-trustpair-payment-fraud-prevention.html and https://trustpair.com/gb/connect/sap-ecc6/
- Abnormal AI, vendor fraud detection (BEC + ERP correlation guidance) — https://abnormal.ai/learning/vendor-fraud-detection
- Exabeam, UEBA vs XDR / SIEM augmentation — https://www.exabeam.com/blog/siem-trends/ueba-vs-xdr-rethinking-siem-augmentation-in-the-ai-era/
- Palo Alto, What is UEBA — https://events.paloaltonetworks.com/cyberpedia/what-is-user-entity-behavior-analytics-ueba
- Tungsten PROCESSIT Auditor (duplicate-payment, Benford, rounded-amount) — https://docshield.tungstenautomation.com/RSPIT/en_US/7.4.1/help/PROCESSIT/presentations/SEARCH_AUDITOR.html
- Benford's-law fraud method, open R library (MethodsX 2021) — https://www.ncbi.nlm.nih.gov/pmc/articles/PMC8720889/
- FBI IC3: BEC losses ≈ $2.77B (US, 2024), cited in the Abnormal guide above.

Standards referenced for detection content: MITRE ATT&CK, OCSF, ACFE fraud scheme taxonomy,
Nigrini *Forensic Analytics*, ISO 20022 / BAI2 / NACHA / SWIFT payment formats, SARIF 2.1.0.
