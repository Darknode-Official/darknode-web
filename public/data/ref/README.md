# Reference data (`public/data/ref/` and `public/data/controls/`)

Hand-curated, static JSON tables that feed Darknode's deterministic regulatory
and compliance tools (breach-notification deadline calculator, transfer-mechanism
checker, SEC business-day math, evidence calendar). Nothing here is fetched at
runtime from a third party; the files are versioned with the app and reviewed by
hand.

**Verify with counsel.** Every `ref/` file carries `"verifyWithCounsel": true`.
Statutes, adequacy decisions and holiday calendars change; the tables are a
starting point for a conversation with a lawyer or compliance officer, not legal
advice. Entries that were amended recently or could not be confirmed with
certainty carry `"confidence": "verify"`; everything else is `"curated"`.

## Envelope

```json
{
  "version": "2026-10",
  "updated": "2026-10-16",
  "verifyWithCounsel": true,
  "sources": ["https://..."],
  "notes": "...",
  "data": [ ... ]
}
```

Control catalogs under `controls/` use
`{ framework, version, updated, license, notes, sourceUrl, data }` and no
`verifyWithCounsel` flag (they are indices, not legal positions).

## Files

| File | What it is | Primary sources |
| --- | --- | --- |
| `ref/us-breach-laws.json` | 54 jurisdictions (50 states, DC, PR, VI, GU): statute citation, resident-notice deadline, regulator (AG) notice deadline and threshold, credit-bureau threshold, substitute notice, risk-of-harm trigger, PII definition notes. | NCSL breach-law compendium, IAPP state breach chart, Perkins Coie chart, the state codes themselves |
| `ref/eu-adequacy.json` | European Commission adequacy decisions (GDPR Art. 45) with scope, decision date and review status; `ukAdequacy` (destinations the UK treats as adequate); `transferMechanisms` (Art. 45/46/47/49 instruments, 2021 SCCs, UK IDTA). | European Commission adequacy page, EUR-Lex, EDPB first-review report, ICO |
| `ref/us-holidays.json` | US federal holidays 2025-2030 on their observed dates (Saturday to Friday, Sunday to Monday) plus one-off closures EDGAR honoured; `nyseHolidays` 2025-2027. Used for SEC "four business days" math. | OPM federal holidays, 5 U.S.C. 6103, SEC EDGAR hours, NYSE calendar |
| `controls/soc2.json` | AICPA Trust Services Criteria 2017 (2022 points of focus): CC1.1-CC9.2, A1, C1, PI1, P1-P8. IDs and short paraphrases only. | AICPA |
| `controls/iso27001.json` | ISO/IEC 27001:2022 Annex A, 93 controls in four themes. IDs and short titles only. | ISO |
| `controls/pci4.json` | PCI DSS v4.0.1: 12 principal requirements, x.y sub-requirements, and selected x.y.z requirements whose cadence the standard prescribes. IDs and paraphrases only. | PCI SSC Document Library |
| `controls/cisv8.json` | CIS Controls v8.1: 18 controls, 153 safeguards with Implementation Group flags. IDs and paraphrases only. | Center for Internet Security |
| `controls/nistcsf2.json` | NIST CSF 2.0: 6 functions, 22 categories, 106 subcategories (public domain; titles verbatim). | NIST CSWP 29 |

## Field conventions

- `deadlineDays` is `null` when the statute only says "without unreasonable
  delay" (or similar); `deadlineText` always carries the statutory standard and
  the trigger (discovery vs determination of breach).
- `agThreshold` / `creditBureauThreshold`: `0` means notice is due for every
  breach that triggers resident notice; `null` means no duty was identified; a
  positive number is the resident count at which the duty starts.
- `riskOfHarmTrigger: true` means the law lets the entity skip notice after a
  documented determination that harm is not reasonably likely.
- `defaultFrequency` in the control catalogs is one of `continuous`, `daily`,
  `weekly`, `monthly`, `quarterly`, `semiannual`, `annual`, `event`. It is
  Darknode's suggested evidence-collection cadence unless the framework itself
  prescribes one (PCI DSS rows with `level: "req"`, some CIS safeguards).

## Licensing of the control catalogs

ISO 27001/27002, PCI DSS, the AICPA TSC and the CIS Controls document are
copyrighted (CIS under CC BY-NC-ND 4.0). The catalogs store identifiers and short
original paraphrases plus Darknode's own evidence hints. They are an index for
scheduling evidence collection, not a substitute for the standards. NIST CSF 2.0
is public domain and its titles are reproduced verbatim.

## How to update

1. Edit the JSON by hand (keep the envelope and field names) or regenerate from
   your working notes; bump `version` (YYYY-MM) and `updated` (ISO date).
2. For breach laws, check the NCSL compendium and the state code for every row
   you touch; set `confidence` to `"verify"` on anything amended in the current
   legislative session and clear it only after reading the enacted text.
3. For adequacy, check the Commission's adequacy page for new, renewed or sunset
   decisions (the UK and US decisions have review and sunset clauses).
4. For holidays, extend the year range and re-check OPM and NYSE calendars; add
   any one-off executive closures EDGAR announces.
5. Run `node test/run.mjs`; `test/data/ref-data.test.mjs` enforces the envelope,
   uniqueness and count invariants listed above.
