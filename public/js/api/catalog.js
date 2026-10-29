// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// AI tool catalog: the Deck tools any AI can run through the Darknode MCP server
// (`darknode mcp`) or another client. One entry per Deck sidebar tool whose engine is
// pure (no DOM, no network, no clock), so the exact engine the Deck runs in the
// browser runs on the caller's machine and the data never leaves it.
//
//   id       the Deck route (same id the sidebar, links and plan gating use)
//   group    the Deck sidebar group, which sets the plan tier (core/entitlements.js)
//   engine   module path relative to /js/
//   kind     how the engine is called:
//              "files"  parseInput(files) then analyze(parsed, options)   (most tools)
//              "text"   the tool's own one-text entry point, see run() below
//   input    what to hand it, written for the AI choosing the tool
//
// Loaded by the MCP server with no DOM, so this module imports only pure modules.

import { PLAN_GROUP, PLAN_ITEM, tierFor } from "../core/entitlements.js";

export const CATALOG_VERSION = 1;

const T = (id, name, group, engine, kind, does, input) => ({ id, name, group, engine, kind, does, input });

export const TOOLS = [
  // Exposure
  T("fwaudit", "Firewall Audit", "exposure", "infra/firewall-audit-engine.js", "text", "Audits a firewall or cloud security-group config: rules open to the internet, shadowed and redundant rules, risky services, missing default deny.", "One config as text: iptables-save, nftables, Cisco ASA, pfSense/OPNsense XML, AWS security groups JSON, Azure NSG JSON or GCP firewall JSON."),
  T("vulnimport", "Scan Imports", "exposure", "exposure/vulnimport-engine.js", "files", "Builds one de-duplicated vulnerability register from scanner exports, enriched with CISA KEV, with SLA status per finding.", "Scanner exports: Nessus .nessus, Qualys XML/CSV, OpenVAS XML, Trivy/Grype/Snyk JSON, Defender or Rapid7 CSV."),
  T("fleetcomply", "Devices", "exposure", "exposure/fleetcomply-engine.js", "files", "Reconciles endpoint inventories (MDM, EDR, directory) to find unmanaged, unprotected, unencrypted and stale devices.", "Device exports as CSV/JSON: Intune, Jamf, Kandji, CrowdStrike, Defender, SentinelOne, Entra/Google devices."),
  T("dmarcreports", "DMARC Reports", "exposure", "exposure/dmarcreports-engine.js", "files", "Reads DMARC aggregate reports: who sends mail as your domain, SPF/DKIM alignment failures, spoofing sources, readiness for p=reject.", "DMARC aggregate (RUA) XML reports, one file per report."),
  T("domainguard", "Domains", "exposure", "exposure/domainguard-engine.js", "files", "Grades a domain portfolio: NS/SOA/MX health, SPF include count, DMARC, dangling records and takeover risk.", "A list of domains (one per line or CSV) and/or DNS zone files."),
  T("netexposure", "Network Scans", "exposure", "exposure/netexposure-engine.js", "files", "Turns network scans into an exposure inventory, flags risky exposed services and diffs scans over time.", "nmap -oX/-oG, masscan JSON/XML, naabu JSON lines, Nessus, Shodan NDJSON, or a port-list CSV. Two or more scans are diffed."),
  // Identity
  T("signins", "Sign-ins", "identity", "identity/signin-forensics-engine.js", "text", "Sign-in forensics: impossible travel, password spraying, MFA fatigue, legacy auth and risky sign-ins per user.", "One sign-in log export as text: Entra ID sign-in CSV/JSON, Okta System Log, Google Workspace login audit."),
  T("caaudit", "Conditional Access", "identity", "identity/caaudit-engine.js", "files", "Audits Entra Conditional Access policies for gaps: users or apps with no MFA, legacy auth not blocked, risky exclusions.", "Conditional Access policy JSON (Graph export) plus optional named locations and sign-in exports."),
  T("privaudit", "Privileged Access", "identity", "identity/privaudit-engine.js", "files", "Finds standing admin access, admins without MFA, stale or orphaned privileged accounts and role sprawl.", "Role assignment exports: Entra roles, AWS IAM credential report or policies, Google Workspace admins, Okta admins."),
  T("nhi", "Service Accounts", "identity", "identity/nhi-engine.js", "files", "Non-human identities: expired, expiring, unused and never-rotated keys and secrets, and service accounts owned by leavers.", "AWS IAM credential report, Entra app credentials, GCP service account keys, Okta, Kubernetes or GitHub token exports."),
  T("jml", "Joiners & Leavers", "identity", "identity/jml-engine.js", "files", "Checks joiner/mover/leaver hygiene: leavers still active, movers keeping old access, joiners provisioned late.", "An HR roster CSV plus directory and app account exports."),
  T("oauthgov", "OAuth Apps", "identity", "identity/oauthgov-engine.js", "files", "Builds one OAuth app inventory and flags over-privileged, unverified, unused and risky third-party apps.", "OAuth/enterprise app exports from Entra ID, Google Workspace, Okta, Slack or GitHub."),
  T("vpnaudit", "VPN & Remote Access", "identity", "identity/vpnaudit-engine.js", "files", "Audits VPN and zero-trust access logs against the HR roster: leavers still connecting, shared accounts, odd locations.", "VPN/ZTNA logs (Cisco, Palo Alto GlobalProtect, Fortinet, Zscaler, Cloudflare) plus an HR roster CSV."),
  // Application security
  T("iacscan", "Infrastructure as Code", "code", "appsec/iacscan-engine.js", "files", "Scans infrastructure-as-code for misconfigurations and committed secrets.", "Terraform (HCL, plan or state JSON), CloudFormation, Kubernetes manifests, Helm output, Dockerfiles, docker-compose, GitHub Actions workflows."),
  T("k8saudit", "Kubernetes", "code", "appsec/k8saudit-engine.js", "files", "Audits the live state of a Kubernetes cluster: privileged pods, RBAC risks, missing network policies, end-of-life versions.", "kubectl get ... -A -o json|yaml dumps, kube-bench JSON."),
  T("licenseaudit", "Licenses", "code", "appsec/licenseaudit-engine.js", "files", "Builds a license inventory and flags copyleft, unknown and policy-violating licenses.", "Lockfiles (npm, yarn, pnpm, pip, Poetry, Go, Cargo, Bundler, Composer, Maven), license-checker reports or SBOMs."),
  T("apispec", "API Definitions", "code", "appsec/apispec-engine.js", "files", "Reviews API definitions against the OWASP API Security Top 10 2023.", "OpenAPI 3.x or Swagger 2.0 (JSON/YAML), Postman collections, GraphQL SDL or introspection JSON."),
  // Security operations
  T("phishtriage", "Phishing", "detect", "dataprotect/phish-engine.js", "text", "Triages suspicious links: lookalike and punycode domains, raw IPs, credential-harvesting paths, URL shorteners and odd ports.", "URLs as text, one per line (up to 500)."),
  T("loghunt", "Log Search", "detect", "ops/log-hunter-engine.js", "text", "Hunts attacks in raw logs: brute force, web attacks (SQLi, XSS, traversal), scanners, suspicious commands; returns IOCs and a timeline.", "One log as text: syslog/auth.log, Apache/nginx access logs, Windows event CSV, JSON lines."),
  T("cloudtrail", "Cloud Audit Logs", "detect", "ops/cloudtrail-engine.js", "files", "Hunts cloud audit logs for root use, disabled logging, privilege escalation, key creation and data exfiltration.", "AWS CloudTrail JSON/NDJSON, Azure Activity Log, GCP Cloud Audit Logs."),
  T("dnshunt", "DNS Logs", "detect", "ops/dnshunt-engine.js", "files", "Finds DNS tunnelling, DGA domains, beaconing and lookups of known-bad or newly seen domains.", "Resolver logs: Zeek dns.log, BIND, Windows DNS debug, Pi-hole/dnsmasq, Unbound, Route 53 Resolver, Umbrella CSV."),
  T("proxyhunt", "Proxy Logs", "detect", "ops/proxyhunt-engine.js", "files", "Finds data leaving the company (uploads to personal storage, paste sites, webmail, AI tools), shadow SaaS and anonymizers.", "Secure web gateway / proxy logs: Zscaler, Squid, Blue Coat, Palo Alto URL, Netskope, Cloudflare Gateway CSV/JSON."),
  T("pentestreg", "Pentest Findings", "detect", "ops/pentestreg-engine.js", "files", "Tracks pentest and audit findings: de-duplicates across reports, retest status and overdue remediation.", "Burp XML, OWASP ZAP JSON/XML, Nuclei JSONL, or a findings CSV/JSON."),
  // Fraud & abuse
  T("cloudspend", "Cloud Spend", "finsec", "finsec/cloudspend-engine.js", "files", "Finds cloud spend anomalies that signal abuse (cryptomining, leaked keys, runaway resources).", "AWS CUR or Cost Explorer CSV, Azure cost details, GCP billing export CSV/JSON."),
  // Risk & resilience
  T("breachclock", "Breach Deadlines", "risk", "risk/breachclock-engine.js", "files", "Works out which breach-notification obligations may apply to an incident and each deadline to the hour. A decision aid, not legal advice.", "An incident record JSON exported by the tool, or a jurisdiction,count CSV of affected people."),
  T("riskreg", "Risk Register", "risk", "risk/riskreg-engine.js", "files", "Scores a risk register: inherent and residual risk, overdue reviews, risks with no owner or treatment.", "A risk register CSV or JSON."),
  T("vendorrisk", "Vendors", "risk", "risk/vendorrisk-engine.js", "files", "Scores a vendor register: inherent risk, assurance on file, expiring documents and review dates.", "A vendor register CSV or JSON."),
  T("backupready", "Backups", "risk", "risk/backupready-engine.js", "files", "Proves whether you can recover from ransomware: failed or missing jobs, no immutable copy, untested restores, RPO gaps.", "Backup exports: Veeam, Commvault, Rubrik, AWS Backup, Azure Backup or a jobs CSV."),
  // Compliance
  T("dlp", "Sensitive Data", "compliance", "dataprotect/dlp-engine.js", "text", "Finds sensitive data in text: card numbers (Luhn-checked), IBANs, national IDs, credentials and high-entropy secrets.", "Any text: a document, a CSV, logs or source code."),
  T("evidence", "Audit Evidence", "compliance", "compliance/evidence-engine.js", "files", "Runs the evidence program for SOC 2, ISO 27001, PCI DSS, CIS and NIST CSF: what evidence is due, missing or stale.", "An evidence register JSON exported by the tool or an evidence spreadsheet CSV."),
  T("dataflow", "Data Inventory", "compliance", "compliance/dataflow-engine.js", "files", "Checks a processing register (ROPA) and DSAR log: missing lawful basis, unsafe transfers, overdue requests.", "A ROPA activity CSV and/or a DSAR log CSV, or the tool's register JSON."),
  T("awareness", "Security Training", "compliance", "compliance/awareness-engine.js", "files", "Analyzes phishing simulations: click and report rates, repeat clickers, teams at risk.", "GoPhish, KnowBe4 or Microsoft Attack Simulation Training exports (CSV/JSON)."),
].map((t) => Object.assign(t, { tier: tierFor(t.id, t.group) }));

export const PLAN_TABLES = { PLAN_GROUP, PLAN_ITEM };

export const toolById = (id) => TOOLS.find((t) => t.id === id) || null;

// Run one catalog tool on a loaded engine module E.
//   files    [{ name, text }]
//   options  engine options (DEFAULTS overrides). Engines take "now" from the data unless
//            options.now is given, the same as in the Deck.
export async function run(tool, E, files, options = {}) {
  const opts = Object.assign({}, options);
  if (tool.kind === "files") {
    const parsed = await E.parseInput(files);
    return E.analyze(parsed, opts);
  }
  const text = files.map((f) => f.text).join("\n");
  switch (tool.id) {
    case "fwaudit": return E.audit(text, opts);
    case "loghunt": return E.analyzeText(text, opts, files.length === 1 ? files[0].name : "");
    case "dlp": return E.scan(text, opts);
    case "phishtriage": { const urls = text.split(/\s+/).filter((u) => /^[a-z][a-z0-9+.-]*:\/\/|^[\w-]+(\.[\w-]+)+/i.test(u)).slice(0, 500); return { urls: urls.map((u) => E.analyzeUrl(u)) }; }
    case "signins": { const p = E.parseAll(text); const r = E.analyze(p.records, opts, p); r.parse = { source: p.source, format: p.format, records: p.records.length, warnings: p.warnings }; return r; }
    default: throw new Error("no runner for " + tool.id);
  }
}
