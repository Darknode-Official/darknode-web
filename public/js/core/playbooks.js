// Response playbooks (Deck D9). PURE — no DOM, no network, deterministic. Given one finding,
// it returns a short, standard response runbook appropriate to that finding's type: triage →
// contain → remediate → verify, where the verify step ties back to the D1 "re-run the source
// tool" mechanic (a fixed finding that no longer appears is auto-marked verified-fixed).
//
// The content is generic, well-established security practice (the kind in NIST SP 800-61 and
// the CIS Controls). It is written here in our own words and keyed to the Deck's own finding
// categories; it reproduces no third-party catalogue text. References cite framework control
// IDs only (IDs are facts, not protected text).

const low = (v) => String(v == null ? "" : v).toLowerCase();
const has = (hay, ...needles) => { const s = low(hay); return needles.some((n) => s.includes(n)); };

// Tools grouped to a response domain, for findings whose category is thin but whose source
// tool is telling. Kept small and honest — only tools that clearly map to one domain.
const TOOL_DOMAIN = {
  identity: ["caaudit", "signins", "signin-forensics", "privaudit", "jml", "accessreview", "oauthgov", "nhi", "vpnaudit"],
  exposure: ["netexposure", "domainguard", "tlsfleet", "posture", "surface"],
  cloud: ["iacscan", "k8saudit", "cloudtrail", "fleetcomply"],
  secret: ["codescan", "leakprobe", "dlp", "iacscan"],
  phishing: ["phishtriage"],
  data: ["dlp"],
  financial: ["payees", "strongroom", "apforensics", "vault"],
  supplychain: ["supplychain", "supply-chain-analyzer", "licenseaudit"],
};
function domainOfTool(tool) {
  const t = low(tool);
  for (const [dom, tools] of Object.entries(TOOL_DOMAIN)) if (tools.includes(t)) return dom;
  return "";
}

// The library. Each entry: { id, title, when, steps:[string], verify:string, references:[{framework,id}] }.
const PLAYBOOKS = {
  "known-exploited-vuln": {
    id: "known-exploited-vuln", title: "Known-exploited vulnerability",
    when: "A vulnerability on CISA KEV or with a high exploit probability.",
    steps: [
      "Treat as time-critical: known-exploited issues are being used in the wild now.",
      "Identify every asset the vulnerability affects from the finding's linked assets, not just the one reported.",
      "If a vendor fix exists, schedule emergency patching; if not, apply the vendor's documented mitigation or remove the exposure (restrict the port, disable the feature).",
      "Check logs on the affected assets for signs the flaw was already exploited; if found, open an incident.",
      "Record a risk exception with an owner and expiry only if remediation genuinely cannot meet the SLA.",
    ],
    verify: "Re-run the scanner that reported it; a finding that no longer appears is auto-marked verified-fixed.",
    references: [{ framework: "CISA", id: "BOD 22-01" }, { framework: "CIS v8", id: "7.7" }],
  },
  vulnerability: {
    id: "vulnerability", title: "Vulnerability remediation",
    when: "A software or configuration vulnerability.",
    steps: [
      "Confirm the finding applies to a real, in-scope asset (not a false positive from an unused component).",
      "Decide remediate vs. accept: patch or upgrade to the fixed version where one exists.",
      "If no fix is available yet, apply the documented mitigation and set a due date to revisit.",
      "Prioritise by severity, internet exposure and asset criticality — the SLA date already reflects these.",
    ],
    verify: "Re-run the source scanner once patched; the finding clears automatically when it no longer reports.",
    references: [{ framework: "CIS v8", id: "7.1" }, { framework: "PCI DSS 4.0", id: "6.3.3" }],
  },
  "exposed-secret": {
    id: "exposed-secret", title: "Exposed secret / credential",
    when: "A key, token or password found in code, logs or a data store.",
    steps: [
      "Assume the secret is compromised the moment it was exposed — rotate it, do not just delete the finding.",
      "Revoke the exposed credential at its provider and issue a fresh one to the systems that need it.",
      "Review access logs for the credential for any use you cannot account for.",
      "Remove the secret from the source (and its version-control history) and move it into a secrets manager.",
    ],
    verify: "Re-scan the source after rotation; confirm the old secret is gone and not reachable in history.",
    references: [{ framework: "CIS v8", id: "3.11" }, { framework: "OWASP", id: "A07:2021" }],
  },
  identity: {
    id: "identity", title: "Identity / access risk",
    when: "An account, privilege, MFA or sign-in finding.",
    steps: [
      "Confirm whether the account is still needed and who owns it.",
      "For a risky sign-in: force a password reset, revoke active sessions and tokens, and require MFA.",
      "For excess privilege: remove standing admin rights; grant just-in-time or least-privilege access instead.",
      "For a leaver with access: disable the account and revoke tokens, don't just mark it for later.",
      "Enable or enforce phishing-resistant MFA where it is missing.",
    ],
    verify: "Re-run the identity review (sign-ins, CA audit or access review); the issue clears when the account is fixed.",
    references: [{ framework: "CIS v8", id: "6.3" }, { framework: "NIST CSF 2.0", id: "PR.AA" }],
  },
  exposure: {
    id: "exposure", title: "Internet exposure",
    when: "An externally reachable service, port, certificate or domain issue.",
    steps: [
      "Confirm the service is meant to be internet-facing; if not, remove it from the public edge.",
      "If it must stay public, restrict it (allow-list, VPN, auth) and ensure it is patched and monitored.",
      "For certificates: renew before expiry and fix chain or protocol weaknesses.",
      "For a dangling or lookalike domain: reclaim or take down the record and watch for reuse.",
    ],
    verify: "Re-run the exposure or certificate check; a closed exposure stops reporting.",
    references: [{ framework: "CIS v8", id: "12.2" }, { framework: "NIST CSF 2.0", id: "PR.IR" }],
  },
  cloud: {
    id: "cloud", title: "Cloud / infrastructure misconfiguration",
    when: "An IAM, storage, network or container misconfiguration.",
    steps: [
      "Confirm the resource and its owner; check whether the misconfiguration is already being exploited.",
      "Apply least privilege: tighten the IAM policy, security group or bucket ACL to what is actually needed.",
      "Fix the setting in the infrastructure-as-code source, not only in the live console, so it does not drift back.",
      "Enable logging/guardrails to catch the same misconfiguration next time.",
    ],
    verify: "Re-run the IaC or cloud posture scan; the finding clears when the corrected config is in place.",
    references: [{ framework: "CIS v8", id: "4.1" }, { framework: "NIST CSF 2.0", id: "PR.PS" }],
  },
  phishing: {
    id: "phishing", title: "Phishing report",
    when: "A reported or detected phishing message.",
    steps: [
      "Confirm it is malicious and determine who received it and who interacted.",
      "Remove the message from all mailboxes and block the sender, URLs and attachments.",
      "For anyone who clicked or entered credentials: reset passwords, revoke sessions and check for mailbox rules.",
      "Capture the indicators and feed them to your mail and web filtering.",
    ],
    verify: "Confirm the message is removed everywhere and no affected account shows follow-on activity.",
    references: [{ framework: "NIST CSF 2.0", id: "RS.MI" }, { framework: "CIS v8", id: "9.7" }],
  },
  data: {
    id: "data", title: "Data exposure",
    when: "Sensitive data found where it should not be.",
    steps: [
      "Classify what was exposed and determine who could reach it.",
      "Remove or lock down the exposed data and tighten the control that let it leak.",
      "Assess notification obligations if regulated or personal data was involved.",
      "Add a detection so the same class of exposure is caught earlier next time.",
    ],
    verify: "Re-run the DLP or exposure scan; confirm the data is no longer reachable from the exposed path.",
    references: [{ framework: "NIST CSF 2.0", id: "PR.DS" }, { framework: "CIS v8", id: "3.3" }],
  },
  financial: {
    id: "financial", title: "Financial / payment fraud risk",
    when: "A payee, payment or treasury control finding.",
    steps: [
      "Before releasing any payment, independently verify the payee's bank details through a known, out-of-band contact.",
      "Hold or recall suspicious payments and freeze the payee pending verification.",
      "Check whether a bank-detail change was authorised and by whom; look for a matching mailbox rule or account compromise.",
      "Require dual control for payee changes and high-value payments.",
    ],
    verify: "Confirm the payee is verified or blocked and the control gap (dual control, change approval) is closed.",
    references: [{ framework: "NIST CSF 2.0", id: "PR.AA" }, { framework: "COSO", id: "Control Activities" }],
  },
  supplychain: {
    id: "supplychain", title: "Supply-chain / dependency risk",
    when: "A vulnerable, abandoned or risky third-party dependency.",
    steps: [
      "Confirm the dependency is actually used and reachable in your build, not just present.",
      "Upgrade to a fixed version, or replace the component if it is unmaintained.",
      "Pin and verify dependencies (lockfile, integrity hashes) to stop silent substitution.",
      "Record the component in your inventory/SBOM so future advisories match automatically.",
    ],
    verify: "Re-run the dependency or SBOM scan; the finding clears when the fixed version is in place.",
    references: [{ framework: "CIS v8", id: "2.3" }, { framework: "OWASP", id: "A06:2021" }],
  },
  generic: {
    id: "generic", title: "General response",
    when: "Any finding without a more specific playbook.",
    steps: [
      "Confirm the finding is real and in scope, and identify the owner.",
      "Contain any active risk first, then remediate the root cause.",
      "If you cannot remediate within the SLA, record a risk exception with an approver and an expiry.",
      "Document what you changed so the fix can be audited.",
    ],
    verify: "Re-run the source tool; a resolved finding that no longer appears is auto-marked verified-fixed.",
    references: [{ framework: "NIST CSF 2.0", id: "RS.MA" }],
  },
};

/**
 * playbookFor(finding) -> the best-matching playbook object (always returns one; falls back to
 * "generic"). Deterministic: the first matching rule wins, in a fixed order.
 * @param {object} finding a FINDING entity: { severity, source, type, data:{category,tool,kev,cves,tags} }
 * @param {{ kev?: boolean }} [opts] pass kev:true when the caller already knows it is known-exploited
 */
export function playbookFor(finding, opts = {}) {
  const e = finding || {}, d = e.data || {};
  const cat = low(d.category);
  const tool = d.tool || e.source || "";
  const dom = domainOfTool(tool);
  const tags = (Array.isArray(d.tags) ? d.tags : []).map(low);
  const kev = !!opts.kev || d.kev === true;
  const isVuln = low(e.type) === "vulnerability" || cat === "vulnerability" || has(cat, "vuln") || dom === "vulnerability";

  if (kev && isVuln) return PLAYBOOKS["known-exploited-vuln"];
  if (cat === "secret" || has(cat, "secret", "credential") || tags.includes("secret") || (dom === "secret" && has(cat, "secret"))) return PLAYBOOKS["exposed-secret"];
  if (isVuln) return PLAYBOOKS.vulnerability;
  if (cat === "identity" || has(cat, "identity", "access", "account", "privilege", "auth", "mfa") || dom === "identity") return PLAYBOOKS.identity;
  if (has(cat, "phish") || dom === "phishing") return PLAYBOOKS.phishing;
  if (has(cat, "data", "dlp", "pii") || (has(cat, "leak") && !has(cat, "exposure")) || dom === "data") return PLAYBOOKS.data;
  if (has(cat, "exposure", "surface", "certificate", "domain", "tls") || dom === "exposure") return PLAYBOOKS.exposure;
  if (has(cat, "cloud", "misconfig", "iam", "container", "kubernetes") || dom === "cloud") return PLAYBOOKS.cloud;
  if (has(cat, "secret", "credential") || dom === "secret") return PLAYBOOKS["exposed-secret"];
  if (has(cat, "payment", "payee", "financial", "fraud", "treasury") || dom === "financial") return PLAYBOOKS.financial;
  if (has(cat, "supply", "dependency", "sbom", "license") || dom === "supplychain") return PLAYBOOKS.supplychain;
  return PLAYBOOKS.generic;
}

export const PLAYBOOK_IDS = Object.keys(PLAYBOOKS);
export function getPlaybook(id) { return PLAYBOOKS[id] || null; }
