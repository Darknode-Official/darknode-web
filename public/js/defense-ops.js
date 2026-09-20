// Darknode Defense Operations & Security Operations Center Engine
// SOC maturity, incident response, threat intelligence, compliance mapping
// Educational / authorized-defense content for cybersecurity operations.

// ── SOC Maturity Model ───────────────────────────────────────────────────

export const SOC_MATURITY_MODEL = [
  {
    level: 0,
    name: "Initial / Ad-Hoc",
    description: "No formal SOC. Security monitoring is reactive and inconsistent.",
    capabilities: [
      "Basic firewall and antivirus deployed",
      "No centralized logging or SIEM",
      "Incident response is ad-hoc, handled by IT generalists",
      "No documented procedures or playbooks",
      "Threat intelligence limited to vendor advisories"
    ],
    staffing: { fte: "0-1 dedicated security", roles: ["IT administrator (part-time security)"] },
    tools: ["Firewall", "Endpoint AV", "Email gateway"],
    processes: ["None formalized"],
    metrics: { mttd: ">30 days", mttr: ">7 days", false_positive_rate: "Unknown", coverage: "<20%" },
    recommendations: [
      "Deploy centralized log management (ELK, Graylog, or cloud SIEM)",
      "Document incident response plan",
      "Establish 24x7 monitoring via MSSP if budget constrained",
      "Implement MFA on all admin and remote access accounts",
      "Subscribe to CISA alerts and sector-specific ISACs"
    ]
  },
  {
    level: 1,
    name: "Managed",
    description: "Basic SOC established with centralized monitoring and documented procedures.",
    capabilities: [
      "SIEM deployed with basic log sources (firewall, AD, endpoint)",
      "Documented incident response plan",
      "Basic alert triage during business hours",
      "Vulnerability scanning on a schedule (monthly/quarterly)",
      "Security awareness training program started"
    ],
    staffing: { fte: "2-4 dedicated security", roles: ["SOC Analyst (Tier 1)", "Security Engineer", "Security Manager"] },
    tools: ["SIEM (Splunk/ELK/Sentinel)", "Vulnerability scanner (Nessus/Qualys)", "EDR (basic)", "Ticketing system"],
    processes: ["Incident response plan", "Vulnerability management process", "Alert triage procedures"],
    metrics: { mttd: "7-30 days", mttr: "2-7 days", false_positive_rate: ">60%", coverage: "20-50%" },
    recommendations: [
      "Expand log sources to cover cloud, email, DNS, proxy",
      "Implement SOAR for alert enrichment and basic automation",
      "Establish Tier 2 analysis capability",
      "Begin threat hunting program (hypothesis-driven)",
      "Integrate threat intelligence feeds into SIEM",
      "Conduct tabletop exercises quarterly"
    ]
  },
  {
    level: 2,
    name: "Defined",
    description: "SOC processes are documented, repeatable, and measured. Proactive capabilities emerging.",
    capabilities: [
      "Comprehensive log collection across IT and cloud environments",
      "Tiered analyst model (Tier 1 triage, Tier 2 investigation, Tier 3 hunting)",
      "SOAR platform for playbook automation",
      "Threat intelligence integration (commercial + open source feeds)",
      "Regular red team / purple team exercises",
      "Proactive threat hunting (scheduled campaigns)",
      "Vulnerability management with risk-based prioritization"
    ],
    staffing: { fte: "5-10 dedicated security", roles: ["SOC Manager", "Tier 1 Analysts (2-3)", "Tier 2 Analysts (1-2)", "Threat Hunter", "Security Engineer (2)", "Threat Intel Analyst"] },
    tools: ["Enterprise SIEM", "SOAR (Cortex XSOAR, Splunk SOAR, Swimlane)", "EDR (CrowdStrike, SentinelOne, Defender)", "TIP (MISP, ThreatConnect)", "NDR (Zeek, Corelight)", "Cloud security (CSPM/CWPP)"],
    processes: ["Playbooks for top 20 alert types", "Threat hunting methodology", "Threat intelligence lifecycle", "Purple team exercises", "Metrics reporting (monthly)"],
    metrics: { mttd: "1-7 days", mttr: "4-48 hours", false_positive_rate: "30-60%", coverage: "50-75%" },
    recommendations: [
      "Expand OT/ICS monitoring if applicable",
      "Implement deception technology (honeypots, honey tokens)",
      "Develop custom detection content (Sigma/YARA rules)",
      "Establish formal CTI program with intelligence requirements",
      "Begin measuring and benchmarking SOC metrics",
      "Pursue SOC 2 Type II attestation"
    ]
  },
  {
    level: 3,
    name: "Quantitatively Managed",
    description: "SOC performance is measured, benchmarked, and continuously improved. Advanced capabilities operational.",
    capabilities: [
      "24x7 monitoring with follow-the-sun or dedicated shifts",
      "Advanced analytics and ML-based detection",
      "Full MITRE ATT&CK coverage mapping",
      "Automated response for common threats",
      "Threat intelligence production (not just consumption)",
      "OT/ICS security monitoring",
      "Cloud-native security operations",
      "Insider threat detection program",
      "Digital forensics and incident response (DFIR) capability"
    ],
    staffing: { fte: "10-25 dedicated security", roles: ["SOC Director", "SOC Managers (shift leads)", "Tier 1-3 Analysts (8-12)", "Threat Hunters (2-3)", "Threat Intel Team (2-3)", "DFIR Specialists (2)", "Detection Engineers (2)", "Security Architects", "Automation Engineers"] },
    tools: ["Enterprise SIEM (multi-tenant)", "SOAR with 100+ playbooks", "XDR platform", "UEBA", "NDR/NTA", "Deception platform", "Threat intel platform", "DFIR toolkit (Velociraptor, GRR)", "Attack surface management", "Cloud security posture management"],
    processes: ["ATT&CK-based detection engineering", "Continuous purple teaming", "CTI production cycle", "Automated enrichment and triage", "KPI/KRI dashboard reporting", "Tabletop exercises (monthly)", "After-action reviews"],
    metrics: { mttd: "1-24 hours", mttr: "1-4 hours", false_positive_rate: "10-30%", coverage: "75-90%" },
    recommendations: [
      "Pursue MITRE ATT&CK Evaluations benchmarking",
      "Implement zero trust architecture",
      "Develop AI/ML models for advanced detection",
      "Establish threat-informed defense program",
      "Share intelligence with sector ISACs and trusted partners",
      "Implement continuous control validation"
    ]
  },
  {
    level: 4,
    name: "Optimizing",
    description: "World-class SOC with predictive capabilities, full automation, and continuous innovation.",
    capabilities: [
      "Predictive threat detection using AI/ML",
      "Full attack simulation and continuous validation (BAS)",
      "Threat intelligence sharing and co-production with peers",
      "Zero trust architecture fully implemented",
      "Autonomous response for known threat patterns",
      "Adversary emulation (mimicking specific APT TTPs)",
      "Supply chain security monitoring",
      "Quantum-ready cryptography evaluation",
      "Proactive vulnerability discovery (bug bounty, responsible disclosure)"
    ],
    staffing: { fte: "25+ dedicated security", roles: ["CISO", "SOC Director", "Multiple shift leads", "Large analyst team", "Dedicated detection engineering", "CTI production team", "Red team", "Purple team", "DFIR team", "Security data science", "Automation/DevSecOps"] },
    tools: ["Custom detection platform", "AI/ML security analytics", "Breach and attack simulation", "Adversary emulation framework (Caldera, Atomic Red Team)", "Continuous control validation", "Advanced deception grid", "Threat intelligence co-production platform", "Custom SOAR workflows"],
    processes: ["Continuous ATT&CK coverage optimization", "Predictive risk modeling", "Automated adversary tracking", "Continuous improvement cycles (OODA loop)", "Peer intelligence sharing", "Regulatory engagement", "Innovation pipeline"],
    metrics: { mttd: "<1 hour", mttr: "<30 minutes (automated)", false_positive_rate: "<10%", coverage: ">90%" },
    recommendations: [
      "Mentor and share capabilities with less mature organizations",
      "Contribute to open source security tools and detection content",
      "Publish threat research and advisories",
      "Engage with policy and regulatory bodies",
      "Evaluate emerging technologies (AI security, quantum readiness)"
    ]
  }
];


// ── Alert Triage Decision Tree ───────────────────────────────────────────

export const ALERT_TRIAGE = {
  categories: [
    {
      type: "Malware Detection",
      severity_map: { endpoint_quarantined: "medium", endpoint_not_quarantined: "high", server_affected: "critical", multiple_hosts: "critical" },
      actions: [
        { condition: "EDR quarantined the file", action: "Verify quarantine, check for persistence mechanisms, scan for related IOCs across environment", sla: "4 hours", escalation: "Tier 1" },
        { condition: "EDR did not quarantine", action: "Isolate host immediately, collect forensic image, scan for lateral movement indicators", sla: "1 hour", escalation: "Tier 2 + IR Lead" },
        { condition: "Multiple hosts affected", action: "Declare incident, activate IR plan, isolate affected segment, engage DFIR", sla: "30 minutes", escalation: "IR Team + CISO" },
        { condition: "Ransomware indicators", action: "IMMEDIATE: Isolate network segment, preserve evidence, activate ransomware playbook, notify legal", sla: "15 minutes", escalation: "CISO + Legal + Executive" }
      ]
    },
    {
      type: "Suspicious Authentication",
      severity_map: { single_failure: "low", brute_force: "medium", impossible_travel: "high", admin_account: "critical" },
      actions: [
        { condition: "Single failed login", action: "Log and monitor, no immediate action unless pattern develops", sla: "24 hours", escalation: "None" },
        { condition: "5+ failures from same source in 5 minutes", action: "Verify if brute force, check if account locked, review source IP reputation", sla: "2 hours", escalation: "Tier 1" },
        { condition: "Impossible travel (login from 2 geolocations within impossible timeframe)", action: "Verify with user, force password reset if unverified, review session for suspicious activity", sla: "1 hour", escalation: "Tier 2" },
        { condition: "Admin/privileged account compromise indicators", action: "Disable account immediately, rotate credentials, audit all actions taken with the account, check for persistence", sla: "30 minutes", escalation: "Tier 2 + IR Lead" }
      ]
    },
    {
      type: "Data Exfiltration",
      severity_map: { small_volume: "medium", large_volume: "high", to_known_bad_ip: "critical", sensitive_data: "critical" },
      actions: [
        { condition: "Unusual outbound data volume (>baseline + 3 std dev)", action: "Identify source host, verify business justification, check destination reputation", sla: "2 hours", escalation: "Tier 2" },
        { condition: "Data transfer to known malicious IP/domain", action: "Block destination, isolate source host, forensic investigation, check for C2 communication", sla: "30 minutes", escalation: "Tier 2 + IR Lead" },
        { condition: "Sensitive/classified data indicators in transfer", action: "Block transfer if possible, isolate host, activate data breach playbook, notify DPO/privacy officer", sla: "15 minutes", escalation: "IR Team + Legal + DPO" },
        { condition: "DNS tunneling indicators", action: "Block suspicious DNS queries, isolate source, analyze DNS payload for exfiltrated data", sla: "1 hour", escalation: "Tier 2" }
      ]
    },
    {
      type: "Phishing",
      severity_map: { reported_not_clicked: "low", link_clicked: "medium", credentials_entered: "high", attachment_executed: "critical" },
      actions: [
        { condition: "User reported phishing email, did not interact", action: "Analyze email headers, extract IOCs, search mailboxes for same campaign, block sender/domain", sla: "4 hours", escalation: "Tier 1" },
        { condition: "User clicked link", action: "Check if credentials were presented, scan endpoint for drive-by download, block URL across environment", sla: "2 hours", escalation: "Tier 1" },
        { condition: "User entered credentials on phishing page", action: "Force password reset immediately, revoke active sessions, check for follow-on access, enable MFA if not already", sla: "30 minutes", escalation: "Tier 2" },
        { condition: "User opened attachment (macro/executable)", action: "Isolate endpoint, forensic triage, check for lateral movement, block hash across environment", sla: "30 minutes", escalation: "Tier 2 + IR Lead" }
      ]
    },
    {
      type: "Insider Threat",
      severity_map: { policy_violation: "medium", data_hoarding: "high", sabotage_indicators: "critical" },
      actions: [
        { condition: "Excessive file access outside normal pattern", action: "Review access logs, verify business need, flag for HR/management review", sla: "24 hours", escalation: "Tier 2 + HR" },
        { condition: "Mass download or USB transfer of sensitive data", action: "Preserve evidence, notify HR and legal, consider account restriction", sla: "4 hours", escalation: "Tier 2 + HR + Legal" },
        { condition: "Sabotage indicators (deletion, corruption, backdoor installation)", action: "Isolate access immediately, preserve forensic evidence, activate insider threat playbook", sla: "30 minutes", escalation: "IR Team + HR + Legal + Executive" }
      ]
    },
    {
      type: "Vulnerability Exploitation",
      severity_map: { scan_detected: "low", exploit_attempt_blocked: "medium", exploit_successful: "critical" },
      actions: [
        { condition: "Vulnerability scan from external source", action: "Log source IP, verify perimeter controls, no immediate action unless targeted", sla: "24 hours", escalation: "None" },
        { condition: "Exploit attempt detected and blocked by WAF/IPS", action: "Analyze payload, verify block was effective, check for bypass attempts, update signatures if needed", sla: "4 hours", escalation: "Tier 1" },
        { condition: "Successful exploitation indicators (post-exploit activity)", action: "Isolate host, forensic investigation, patch vulnerability, scan for similar vulnerable hosts", sla: "30 minutes", escalation: "Tier 2 + IR Lead" }
      ]
    }
  ]
};


// ── Incident Classification System ───────────────────────────────────────

export const INCIDENT_CLASSIFICATION = {
  severity_levels: [
    { level: "SEV-1", name: "Critical", color: "#FF0000", response_time: "15 minutes", description: "Active breach with confirmed data loss, ransomware encryption in progress, critical infrastructure compromise, or safety risk", notification: ["CISO", "CEO", "Legal", "Board (if public company)", "Regulators (if required)"], sla_containment: "1 hour", sla_eradication: "24 hours" },
    { level: "SEV-2", name: "High", color: "#FF8800", response_time: "30 minutes", description: "Confirmed compromise of sensitive system, active C2 communication, privilege escalation on critical server, or targeted attack in progress", notification: ["CISO", "IT Director", "Legal"], sla_containment: "4 hours", sla_eradication: "72 hours" },
    { level: "SEV-3", name: "Medium", color: "#FFCC00", response_time: "2 hours", description: "Malware detection on single endpoint (contained), phishing campaign targeting org, brute-force attack, or policy violation with security impact", notification: ["SOC Manager", "IT Manager"], sla_containment: "24 hours", sla_eradication: "1 week" },
    { level: "SEV-4", name: "Low", color: "#00CC00", response_time: "24 hours", description: "Reconnaissance activity, single failed exploit attempt, minor policy violation, or informational security event", notification: ["SOC Analyst"], sla_containment: "1 week", sla_eradication: "30 days" }
  ],
  categories: [
    { id: "MAL", name: "Malware", subcategories: ["Ransomware", "Trojan/RAT", "Worm", "Cryptominer", "Wiper", "Rootkit", "Adware/PUA", "Fileless malware"] },
    { id: "UNA", name: "Unauthorized Access", subcategories: ["Credential compromise", "Privilege escalation", "Lateral movement", "Account hijacking", "Session hijacking", "Physical intrusion"] },
    { id: "DOS", name: "Denial of Service", subcategories: ["Volumetric DDoS", "Application-layer DoS", "Protocol exploitation", "Resource exhaustion", "Ransom DDoS"] },
    { id: "PHI", name: "Phishing/Social Engineering", subcategories: ["Spear phishing", "Business email compromise", "Vishing", "Smishing", "Pretexting", "Watering hole"] },
    { id: "DAT", name: "Data Breach", subcategories: ["PII exposure", "PHI exposure", "Financial data", "Intellectual property", "Credentials", "Source code"] },
    { id: "INS", name: "Insider Threat", subcategories: ["Data theft", "Sabotage", "Fraud", "Policy violation", "Inadvertent disclosure"] },
    { id: "SUP", name: "Supply Chain", subcategories: ["Software supply chain", "Hardware supply chain", "Third-party breach", "MSP compromise"] },
    { id: "WEB", name: "Web Application Attack", subcategories: ["SQL injection", "XSS", "CSRF", "API abuse", "Web shell", "Defacement"] },
    { id: "ICS", name: "ICS/OT Incident", subcategories: ["PLC manipulation", "SCADA compromise", "Safety system interference", "Process disruption", "Firmware tampering"] },
    { id: "CRY", name: "Cryptographic Incident", subcategories: ["Certificate compromise", "Key exposure", "Weak encryption discovery", "PKI breach"] }
  ]
};


// ── STIX 2.1 Object Definitions ──────────────────────────────────────────

export const STIX_OBJECTS = {
  version: "2.1",
  domain_objects: [
    {
      type: "attack-pattern",
      description: "A type of TTP that describes ways threat actors attempt to compromise targets",
      required_fields: ["type", "spec_version", "id", "created", "modified", "name"],
      optional_fields: ["description", "aliases", "kill_chain_phases", "external_references"],
      example: { type: "attack-pattern", spec_version: "2.1", id: "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5", created: "2016-05-12T08:17:27.000Z", modified: "2016-05-12T08:17:27.000Z", name: "Spear Phishing", description: "Targeted phishing attack against specific individuals", kill_chain_phases: [{ kill_chain_name: "lockheed-martin-cyber-kill-chain", phase_name: "delivery" }] }
    },
    {
      type: "campaign",
      description: "A grouping of adversarial behaviors that describes a set of malicious activities or attacks over a period of time against a specific set of targets",
      required_fields: ["type", "spec_version", "id", "created", "modified", "name"],
      optional_fields: ["description", "aliases", "first_seen", "last_seen", "objective"]
    },
    {
      type: "course-of-action",
      description: "A recommendation for mitigating a vulnerability or threat",
      required_fields: ["type", "spec_version", "id", "created", "modified", "name"],
      optional_fields: ["description", "action"]
    },
    {
      type: "grouping",
      description: "Explicitly asserts that the referenced STIX objects have a shared context",
      required_fields: ["type", "spec_version", "id", "created", "modified", "name", "context", "object_refs"],
      optional_fields: ["description"]
    },
    {
      type: "identity",
      description: "Represents individuals, organizations, or groups and classes of individuals/organizations/groups",
      required_fields: ["type", "spec_version", "id", "created", "modified", "name"],
      optional_fields: ["description", "roles", "identity_class", "sectors", "contact_information"]
    },
    {
      type: "indicator",
      description: "Contains a pattern that can be used to detect suspicious or malicious cyber activity",
      required_fields: ["type", "spec_version", "id", "created", "modified", "name", "pattern", "pattern_type", "valid_from"],
      optional_fields: ["description", "indicator_types", "valid_until", "kill_chain_phases"],
      pattern_types: ["stix", "pcre", "sigma", "snort", "suricata", "yara"],
      example: { type: "indicator", spec_version: "2.1", id: "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f", created: "2016-04-06T20:03:48.000Z", modified: "2016-04-06T20:03:48.000Z", name: "Malicious URL", pattern: "[url:value = 'http://evil.example.com/malware.exe']", pattern_type: "stix", valid_from: "2016-01-01T00:00:00Z" }
    },
    {
      type: "infrastructure",
      description: "Represents a type of TTP and describes systems, software, and physical resources used by threat actors",
      required_fields: ["type", "spec_version", "id", "created", "modified", "name"],
      optional_fields: ["description", "infrastructure_types", "aliases", "kill_chain_phases", "first_seen", "last_seen"]
    },
    {
      type: "intrusion-set",
      description: "A grouped set of adversarial behaviors and resources with common properties believed to be orchestrated by a single organization",
      required_fields: ["type", "spec_version", "id", "created", "modified", "name"],
      optional_fields: ["description", "aliases", "first_seen", "last_seen", "goals", "resource_level", "primary_motivation", "secondary_motivations"]
    },
    {
      type: "location",
      description: "Represents a geographic location",
      required_fields: ["type", "spec_version", "id", "created", "modified"],
      optional_fields: ["name", "description", "latitude", "longitude", "precision", "region", "country", "administrative_area", "city", "street_address", "postal_code"]
    },
    {
      type: "malware",
      description: "A type of TTP representing malicious code",
      required_fields: ["type", "spec_version", "id", "created", "modified", "name", "is_family"],
      optional_fields: ["description", "malware_types", "aliases", "kill_chain_phases", "first_seen", "last_seen", "operating_system_refs", "architecture_execution_envs", "implementation_languages", "capabilities", "sample_refs"],
      malware_types: ["adware", "backdoor", "bot", "bootkit", "ddos", "downloader", "dropper", "exploit-kit", "keylogger", "ransomware", "remote-access-trojan", "resource-exploitation", "rogue-security-software", "rootkit", "screen-capture", "spyware", "trojan", "unknown", "virus", "webshell", "wiper", "worm"]
    },
    {
      type: "malware-analysis",
      description: "The metadata and results of a particular static or dynamic analysis performed on a malware instance or family",
      required_fields: ["type", "spec_version", "id", "created", "modified", "product", "result"],
      optional_fields: ["version", "host_vm_ref", "operating_system_ref", "installed_software_refs", "configuration_version", "modules", "analysis_engine_version", "analysis_definition_version", "submitted", "analysis_started", "analysis_ended", "result_name", "analysis_sco_refs"]
    },
    {
      type: "note",
      description: "Conveys informative text to provide further context and/or to provide additional analysis not contained in the STIX Objects",
      required_fields: ["type", "spec_version", "id", "created", "modified", "content", "object_refs"],
      optional_fields: ["abstract", "authors"]
    },
    {
      type: "observed-data",
      description: "Conveys information observed on systems and networks using the Cyber Observable specification",
      required_fields: ["type", "spec_version", "id", "created", "modified", "first_observed", "last_observed", "number_observed"],
      optional_fields: ["object_refs"]
    },
    {
      type: "opinion",
      description: "An assessment of the correctness of the information in a STIX Object produced by a different entity",
      required_fields: ["type", "spec_version", "id", "created", "modified", "opinion", "object_refs"],
      opinion_values: ["strongly-disagree", "disagree", "neutral", "agree", "strongly-agree"]
    },
    {
      type: "report",
      description: "Collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique",
      required_fields: ["type", "spec_version", "id", "created", "modified", "name", "published", "object_refs"],
      optional_fields: ["description", "report_types"]
    },
    {
      type: "threat-actor",
      description: "Individuals, groups, or organizations believed to be operating with malicious intent",
      required_fields: ["type", "spec_version", "id", "created", "modified", "name"],
      optional_fields: ["description", "threat_actor_types", "aliases", "first_seen", "last_seen", "roles", "goals", "sophistication", "resource_level", "primary_motivation", "secondary_motivations", "personal_motivations"],
      sophistication_levels: ["none", "minimal", "intermediate", "advanced", "expert", "innovator", "strategic"],
      resource_levels: ["individual", "club", "contest", "team", "organization", "government"],
      motivations: ["accidental", "coercion", "dominance", "ideology", "notoriety", "organizational-gain", "personal-gain", "personal-satisfaction", "revenge", "unpredictable"]
    },
    {
      type: "tool",
      description: "Legitimate software that can be used by threat actors to perform attacks",
      required_fields: ["type", "spec_version", "id", "created", "modified", "name"],
      optional_fields: ["description", "tool_types", "aliases", "kill_chain_phases", "tool_version"],
      tool_types: ["denial-of-service", "exploitation", "information-gathering", "network-capture", "credential-exploitation", "remote-access", "vulnerability-scanning", "unknown"]
    },
    {
      type: "vulnerability",
      description: "A mistake in software that can be used by a hacker to gain access to a system or network",
      required_fields: ["type", "spec_version", "id", "created", "modified", "name"],
      optional_fields: ["description", "external_references"],
      example: { type: "vulnerability", spec_version: "2.1", id: "vulnerability--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061", created: "2016-05-12T08:17:27.000Z", modified: "2016-05-12T08:17:27.000Z", name: "CVE-2021-44228", description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints", external_references: [{ source_name: "cve", external_id: "CVE-2021-44228" }] }
    }
  ],
  relationship_types: [
    "uses", "targets", "attributed-to", "indicates", "mitigates",
    "derived-from", "duplicate-of", "related-to", "variant-of",
    "impersonates", "located-at", "based-on", "delivers",
    "consists-of", "authored-by", "investigates", "remediates",
    "has", "hosts", "owns", "characterizes", "analysis-of",
    "communicates-with", "controls", "drops", "exploits"
  ]
};


// ── Vulnerability Management Lifecycle ───────────────────────────────────

export const VULN_MANAGEMENT = {
  lifecycle: [
    {
      phase: "Discovery",
      description: "Identify assets and scan for vulnerabilities",
      activities: [
        "Maintain accurate asset inventory (CMDB)",
        "Conduct authenticated vulnerability scans (weekly for critical, monthly for standard)",
        "Perform unauthenticated external scans",
        "Monitor vendor advisories and CISA KEV",
        "Accept vulnerability reports through responsible disclosure program",
        "Review cloud security posture (CSPM findings)"
      ],
      tools: ["Nessus", "Qualys", "Rapid7", "Tenable.io", "AWS Inspector", "Azure Defender", "GCP Security Command Center"],
      metrics: ["Scan coverage %", "Assets not scanned in 30 days", "New vulnerabilities discovered per scan"]
    },
    {
      phase: "Assessment",
      description: "Evaluate vulnerability severity and relevance to the organization",
      activities: [
        "Validate scan findings (eliminate false positives)",
        "Enrich with asset criticality (business impact)",
        "Check exploit availability (ExploitDB, Metasploit, PoC on GitHub)",
        "Correlate with threat intelligence (is this being exploited in the wild?)",
        "Calculate risk score: CVSS Base × Asset Criticality × Threat Intel × Exposure"
      ],
      risk_formula: "Risk = CVSS_Base * Asset_Criticality * (Exploit_Available ? 1.5 : 1.0) * (In_CISA_KEV ? 2.0 : 1.0) * (Internet_Facing ? 1.5 : 1.0)",
      metrics: ["False positive rate", "Time from scan to assessment", "Vulnerabilities assessed per analyst per day"]
    },
    {
      phase: "Prioritization",
      description: "Rank vulnerabilities for remediation based on risk",
      activities: [
        "Apply risk-based prioritization formula",
        "Group vulnerabilities by remediation action (same patch fixes multiple CVEs)",
        "Consider remediation complexity and potential business impact of fix",
        "Identify quick wins (low effort, high risk reduction)",
        "Flag CISA KEV entries for mandatory remediation within due date"
      ],
      priority_matrix: [
        { risk: "Critical (9.0-10.0)", internet_facing: true, exploit_available: true, sla: "24 hours" },
        { risk: "Critical (9.0-10.0)", internet_facing: false, exploit_available: true, sla: "72 hours" },
        { risk: "High (7.0-8.9)", internet_facing: true, exploit_available: true, sla: "7 days" },
        { risk: "High (7.0-8.9)", internet_facing: false, exploit_available: false, sla: "30 days" },
        { risk: "Medium (4.0-6.9)", internet_facing: true, exploit_available: false, sla: "30 days" },
        { risk: "Medium (4.0-6.9)", internet_facing: false, exploit_available: false, sla: "90 days" },
        { risk: "Low (0.1-3.9)", internet_facing: false, exploit_available: false, sla: "180 days or accept" }
      ],
      metrics: ["Mean vulnerability age by severity", "% of critical vulns remediated within SLA", "Risk reduction over time"]
    },
    {
      phase: "Remediation",
      description: "Fix or mitigate vulnerabilities",
      activities: [
        "Apply vendor patches (preferred)",
        "Implement compensating controls if patch unavailable (WAF rules, network segmentation, configuration changes)",
        "Update/upgrade end-of-life software",
        "Accept risk formally (documented risk acceptance with expiration) for low-risk items",
        "Coordinate with change management for production changes",
        "Test patches in staging before production deployment"
      ],
      remediation_types: [
        { type: "Patch", desc: "Apply vendor-supplied security update", effectiveness: "High", effort: "Low-Medium" },
        { type: "Configuration Change", desc: "Disable vulnerable feature, restrict access, harden settings", effectiveness: "Medium-High", effort: "Low" },
        { type: "Compensating Control", desc: "WAF rule, IPS signature, network segmentation", effectiveness: "Medium", effort: "Medium" },
        { type: "Upgrade/Replace", desc: "Move to non-vulnerable version or alternative product", effectiveness: "High", effort: "High" },
        { type: "Risk Acceptance", desc: "Document and accept the risk (requires management sign-off)", effectiveness: "None", effort: "Low" }
      ],
      metrics: ["Patch compliance %", "Mean time to remediate (MTTR) by severity", "Remediation backlog size"]
    },
    {
      phase: "Verification",
      description: "Confirm vulnerabilities have been successfully remediated",
      activities: [
        "Re-scan remediated assets to verify fix",
        "Penetration test to validate compensating controls",
        "Review change records for completeness",
        "Update vulnerability status in tracking system"
      ],
      metrics: ["Verification scan pass rate", "Vulnerabilities reopened after remediation", "Time from remediation to verification"]
    },
    {
      phase: "Reporting",
      description: "Communicate vulnerability management status to stakeholders",
      activities: [
        "Generate executive dashboard (risk trends, SLA compliance, top vulnerabilities)",
        "Produce technical reports for remediation teams",
        "Report compliance metrics (PCI, HIPAA, SOX requirements)",
        "Benchmark against industry peers",
        "Track improvement over time"
      ],
      kpis: [
        { kpi: "Mean Time to Remediate (MTTR)", target: "Critical: <72h, High: <7d, Medium: <30d" },
        { kpi: "Scan Coverage", target: ">95% of known assets scanned within policy" },
        { kpi: "SLA Compliance", target: ">90% of vulnerabilities remediated within SLA" },
        { kpi: "Vulnerability Density", target: "Trending downward over 12-month window" },
        { kpi: "Risk Score Trend", target: "Organizational risk score decreasing quarter-over-quarter" },
        { kpi: "CISA KEV Compliance", target: "100% remediated by BOD 22-01 due dates" }
      ]
    }
  ]
};


// ── Compliance Cross-Reference Matrix ────────────────────────────────────

export const COMPLIANCE_MATRIX = {
  frameworks: ["NIST 800-53", "ISO 27001", "SOC 2", "PCI DSS 4.0", "HIPAA", "GDPR", "CMMC 2.0"],
  controls: [
    {
      domain: "Access Control",
      mappings: {
        "NIST 800-53": ["AC-1", "AC-2", "AC-3", "AC-5", "AC-6", "AC-7", "AC-17"],
        "ISO 27001": ["A.9.1", "A.9.2", "A.9.4"],
        "SOC 2": ["CC6.1", "CC6.2", "CC6.3"],
        "PCI DSS 4.0": ["7.1", "7.2", "7.3", "8.1", "8.2", "8.3"],
        "HIPAA": ["164.312(a)(1)", "164.312(d)"],
        "GDPR": ["Art. 5(1)(f)", "Art. 32(1)(b)"],
        "CMMC 2.0": ["AC.L1-3.1.1", "AC.L1-3.1.2", "AC.L2-3.1.5"]
      }
    },
    {
      domain: "Audit & Accountability",
      mappings: {
        "NIST 800-53": ["AU-1", "AU-2", "AU-3", "AU-6", "AU-8", "AU-9", "AU-12"],
        "ISO 27001": ["A.12.4.1", "A.12.4.2", "A.12.4.3"],
        "SOC 2": ["CC7.1", "CC7.2"],
        "PCI DSS 4.0": ["10.1", "10.2", "10.3", "10.4", "10.5", "10.6", "10.7"],
        "HIPAA": ["164.312(b)"],
        "GDPR": ["Art. 5(2)", "Art. 30"],
        "CMMC 2.0": ["AU.L2-3.3.1", "AU.L2-3.3.2"]
      }
    },
    {
      domain: "Configuration Management",
      mappings: {
        "NIST 800-53": ["CM-1", "CM-2", "CM-3", "CM-6", "CM-7", "CM-8"],
        "ISO 27001": ["A.12.1.2", "A.12.5.1", "A.12.6.2"],
        "SOC 2": ["CC6.8", "CC7.1"],
        "PCI DSS 4.0": ["2.1", "2.2", "6.3", "6.4"],
        "HIPAA": ["164.310(d)(2)(iii)"],
        "GDPR": ["Art. 25", "Art. 32"],
        "CMMC 2.0": ["CM.L2-3.4.1", "CM.L2-3.4.2"]
      }
    },
    {
      domain: "Incident Response",
      mappings: {
        "NIST 800-53": ["IR-1", "IR-2", "IR-3", "IR-4", "IR-5", "IR-6", "IR-7", "IR-8"],
        "ISO 27001": ["A.16.1.1", "A.16.1.2", "A.16.1.4", "A.16.1.5", "A.16.1.6"],
        "SOC 2": ["CC7.3", "CC7.4", "CC7.5"],
        "PCI DSS 4.0": ["12.10"],
        "HIPAA": ["164.308(a)(6)"],
        "GDPR": ["Art. 33", "Art. 34"],
        "CMMC 2.0": ["IR.L2-3.6.1", "IR.L2-3.6.2"]
      }
    },
    {
      domain: "Risk Assessment",
      mappings: {
        "NIST 800-53": ["RA-1", "RA-2", "RA-3", "RA-5"],
        "ISO 27001": ["A.8.2.1", "A.12.6.1"],
        "SOC 2": ["CC3.1", "CC3.2", "CC3.3"],
        "PCI DSS 4.0": ["6.1", "11.3", "12.2"],
        "HIPAA": ["164.308(a)(1)(ii)(A)"],
        "GDPR": ["Art. 35"],
        "CMMC 2.0": ["RA.L2-3.11.1", "RA.L2-3.11.2"]
      }
    },
    {
      domain: "Data Protection / Encryption",
      mappings: {
        "NIST 800-53": ["SC-8", "SC-12", "SC-13", "SC-28"],
        "ISO 27001": ["A.10.1.1", "A.10.1.2", "A.18.1.5"],
        "SOC 2": ["CC6.1", "CC6.7"],
        "PCI DSS 4.0": ["3.1", "3.3", "3.4", "3.5", "4.1", "4.2"],
        "HIPAA": ["164.312(a)(2)(iv)", "164.312(e)(1)", "164.312(e)(2)(ii)"],
        "GDPR": ["Art. 32(1)(a)"],
        "CMMC 2.0": ["SC.L2-3.13.8", "SC.L2-3.13.11"]
      }
    },
    {
      domain: "Personnel Security & Training",
      mappings: {
        "NIST 800-53": ["AT-1", "AT-2", "AT-3", "PS-1", "PS-3", "PS-4", "PS-5"],
        "ISO 27001": ["A.7.1.1", "A.7.2.2", "A.7.3.1"],
        "SOC 2": ["CC1.4"],
        "PCI DSS 4.0": ["12.6"],
        "HIPAA": ["164.308(a)(3)", "164.308(a)(5)"],
        "GDPR": ["Art. 39(1)(b)"],
        "CMMC 2.0": ["AT.L2-3.2.1", "AT.L2-3.2.2"]
      }
    },
    {
      domain: "Physical Security",
      mappings: {
        "NIST 800-53": ["PE-1", "PE-2", "PE-3", "PE-6"],
        "ISO 27001": ["A.11.1.1", "A.11.1.2", "A.11.1.3", "A.11.2.1"],
        "SOC 2": ["CC6.4"],
        "PCI DSS 4.0": ["9.1", "9.2", "9.3", "9.4"],
        "HIPAA": ["164.310(a)", "164.310(b)", "164.310(c)"],
        "GDPR": ["Art. 32(1)(b)"],
        "CMMC 2.0": ["PE.L1-3.10.1", "PE.L2-3.10.3"]
      }
    },
    {
      domain: "System & Communications Protection",
      mappings: {
        "NIST 800-53": ["SC-1", "SC-5", "SC-7", "SC-8", "SC-12", "SC-13", "SC-20", "SC-23"],
        "ISO 27001": ["A.13.1.1", "A.13.1.3", "A.13.2.1"],
        "SOC 2": ["CC6.1", "CC6.6", "CC6.7"],
        "PCI DSS 4.0": ["1.1", "1.2", "1.3", "1.4", "4.1"],
        "HIPAA": ["164.312(c)(1)", "164.312(e)(1)"],
        "GDPR": ["Art. 32"],
        "CMMC 2.0": ["SC.L1-3.13.1", "SC.L2-3.13.5"]
      }
    },
    {
      domain: "Vulnerability Management",
      mappings: {
        "NIST 800-53": ["RA-5", "SI-2", "SI-5"],
        "ISO 27001": ["A.12.6.1"],
        "SOC 2": ["CC7.1"],
        "PCI DSS 4.0": ["6.1", "6.2", "6.3", "11.3"],
        "HIPAA": ["164.308(a)(1)(ii)(B)"],
        "GDPR": ["Art. 32(1)(d)"],
        "CMMC 2.0": ["RA.L2-3.11.2", "SI.L1-3.14.1"]
      }
    }
  ]
};


// ── Tabletop Exercise Scenarios ──────────────────────────────────────────

export const TABLETOP_EXERCISES = [
  {
    id: "TTX-001",
    name: "Ransomware Attack on Enterprise",
    duration: "2-3 hours",
    difficulty: "Intermediate",
    participants: ["IT/Security team", "Executive leadership", "Legal", "Communications", "HR"],
    scenario: "Monday 2:14 AM — Your SOC receives alerts of mass file encryption across 3 file servers. By 6 AM, 40% of endpoint workstations display a ransom note demanding 50 Bitcoin ($2.1M). Your backup server shows signs of compromise. The attackers claim to have exfiltrated 200GB of data and threaten to publish it in 72 hours.",
    injects: [
      { time: "T+0", inject: "SOC alert: Unusual SMB activity detected across file servers. Volume: 15,000 files modified per minute. Known ransomware file extension detected (.locked)." },
      { time: "T+30min", inject: "Help desk reports 50+ tickets from early-arriving employees unable to access files. Ransom note found on desktops." },
      { time: "T+1hr", inject: "Backup team confirms: backup server's VSS snapshots were deleted 3 days ago. Last clean off-site backup is 7 days old." },
      { time: "T+2hr", inject: "Attacker emails CEO directly with sample of exfiltrated data (employee PII, financial records, customer contracts). Threatens leak to media and dark web in 72 hours." },
      { time: "T+3hr", inject: "Local journalist contacts communications team asking about 'reports of a cyberattack' at the company." },
      { time: "T+4hr", inject: "FBI Cyber Division contacts CISO offering to assist. They indicate they've seen this group before and payment does NOT guarantee decryption." },
      { time: "T+6hr", inject: "Board member calls CEO asking about the attack after seeing discussion on social media." },
      { time: "T+8hr", inject: "Insurance company requires formal incident notification and preliminary impact assessment before they authorize coverage." }
    ],
    discussion_questions: [
      "What is the first action you take upon discovering the ransomware?",
      "Who has the authority to make the decision to pay or not pay the ransom?",
      "How do you communicate with employees, customers, and the public?",
      "At what point do you notify law enforcement? Regulators? Customers?",
      "How do you determine the scope of data exfiltration?",
      "What is your recovery strategy given compromised backups?",
      "If you decide not to pay, what is your plan for the threatened data leak?",
      "How will this incident affect your cyber insurance renewal?"
    ]
  },
  {
    id: "TTX-002",
    name: "Nation-State APT Compromise",
    duration: "3-4 hours",
    difficulty: "Advanced",
    participants: ["Security team", "IT infrastructure", "Executive leadership", "Legal", "Government affairs"],
    scenario: "CISA notifies your organization that a nation-state threat actor (attributed to APT29/Cozy Bear) has been identified in your network. The compromise appears to have been active for approximately 6 months. Initial access was through a compromised software update from one of your IT management vendors. The threat actor has been observed accessing email servers, file shares, and your Active Directory infrastructure.",
    injects: [
      { time: "T+0", inject: "CISA call: 'We have evidence of a sophisticated threat actor in your environment. Indicators match APT29 activity. We're seeing beaconing from 3 of your IP addresses to known C2 infrastructure.'" },
      { time: "T+1hr", inject: "Initial forensic sweep identifies Cobalt Strike beacons on 12 servers, including domain controllers. C2 communication has been occurring over HTTPS to CDN-hosted redirectors." },
      { time: "T+2hr", inject: "Evidence of Kerberos Golden Ticket usage found. All domain trust relationships may be compromised." },
      { time: "T+4hr", inject: "Email server logs show the attacker accessed C-suite email accounts for the past 4 months. Board meeting minutes and M&A discussions were accessed." },
      { time: "T+6hr", inject: "CISA informs you that 3 other organizations in your sector were also compromised through the same vendor. This is being treated as a supply chain incident of national significance." },
      { time: "T+8hr", inject: "Your IT vendor confirms their build server was compromised. The malicious update was signed with their legitimate code signing certificate." }
    ],
    discussion_questions: [
      "How do you verify CISA's notification is legitimate and not social engineering?",
      "Do you immediately contain (tip off the attacker) or monitor to understand the scope?",
      "How do you rebuild trust in Active Directory after Golden Ticket compromise?",
      "What are the legal implications of a nation-state actor accessing M&A information?",
      "How do you coordinate with other affected organizations?",
      "What is your communication strategy given the sensitive nature of state-sponsored attribution?",
      "How do you evaluate and address the compromised vendor relationship?",
      "What changes to your supply chain security program result from this incident?"
    ]
  },
  {
    id: "TTX-003",
    name: "Insider Threat — Data Exfiltration",
    duration: "2 hours",
    difficulty: "Intermediate",
    participants: ["Security team", "HR", "Legal", "Management"],
    scenario: "Your DLP system alerts on a senior engineer who has been downloading large volumes of proprietary source code and design documents over the past 2 weeks. HR confirms the engineer submitted their 2-week notice 3 days ago and has accepted a position at a direct competitor. The engineer has legitimate access to the files as part of their role.",
    injects: [
      { time: "T+0", inject: "DLP alert: 2.4GB of source code repositories cloned to personal USB drive over past 14 days. Files include core product IP." },
      { time: "T+30min", inject: "Email monitoring shows the engineer forwarded 47 emails with attachments to a personal Gmail account in the past week." },
      { time: "T+1hr", inject: "Cloud access logs show the engineer shared a company Google Drive folder with an external email address belonging to the competitor." },
      { time: "T+2hr", inject: "The engineer's manager reports the engineer has been 'mentoring' a junior developer, giving them access to systems they normally wouldn't access." }
    ],
    discussion_questions: [
      "At what point do you restrict the engineer's access without tipping them off?",
      "How do you preserve evidence for potential legal action?",
      "What are your obligations regarding the engineer's employment rights during the investigation?",
      "Do you involve law enforcement? At what point?",
      "How do you notify the competitor that they may be receiving stolen trade secrets?",
      "What changes to your offboarding process result from this incident?"
    ]
  },
  {
    id: "TTX-004",
    name: "Critical Infrastructure — Water Treatment Attack",
    duration: "2-3 hours",
    difficulty: "Advanced",
    participants: ["OT security", "Operations", "Emergency management", "Government liaison", "Communications"],
    scenario: "Operators at your water treatment facility notice unusual readings on the HMI. Sodium hydroxide (lye) levels appear to have been changed from 100 ppm to 11,100 ppm — a potentially lethal concentration. The change was made via the remote access system. This mirrors the Oldsmar, Florida attack.",
    injects: [
      { time: "T+0", inject: "Operator reports: 'The mouse moved on its own on the HMI. Someone changed the NaOH setpoint from 100 to 11,100. I changed it back immediately.'" },
      { time: "T+15min", inject: "Security review shows the remote access was via TeamViewer using a shared credential. The connection originated from a VPN service." },
      { time: "T+30min", inject: "A second HMI at a different treatment plant shows the same unauthorized connection attempt, but it was unsuccessful." },
      { time: "T+1hr", inject: "Water quality sensors confirm no contamination reached the distribution system. However, public has become aware through a leaked internal email." },
      { time: "T+2hr", inject: "Media inquiries begin. City council demands an emergency briefing. EPA regional office requests incident details." }
    ],
    discussion_questions: [
      "What immediate actions do you take to ensure public safety?",
      "How do you secure remote access to prevent further attacks?",
      "When and how do you notify the public about the incident?",
      "What are your obligations to report to EPA, CISA, FBI?",
      "How do you assess whether the water supply was actually contaminated?",
      "What operational changes do you implement to prevent recurrence?"
    ]
  },
  {
    id: "TTX-005",
    name: "Business Email Compromise (BEC)",
    duration: "1.5-2 hours",
    difficulty: "Beginner-Intermediate",
    participants: ["Finance", "Security", "Legal", "Executive"],
    scenario: "Your CFO receives an urgent email that appears to be from the CEO requesting an immediate wire transfer of $890,000 to a 'new vendor' for a 'confidential acquisition.' The email came from an account that looks identical to the CEO's but uses a lookalike domain (darkn0de.ai instead of darknode.ai). The CFO's executive assistant initiated the transfer before verifying.",
    injects: [
      { time: "T+0", inject: "Bank confirms wire transfer of $890,000 was processed 2 hours ago to an account at a bank in Hong Kong." },
      { time: "T+30min", inject: "Bank fraud department says they can attempt a recall but success rate drops significantly after 24 hours. They need a formal request." },
      { time: "T+1hr", inject: "IT confirms the lookalike domain darkn0de.ai was registered 48 hours ago using privacy protection." },
      { time: "T+2hr", inject: "Further investigation reveals the CEO's actual email account was compromised 2 weeks ago. The attacker had been reading emails to understand ongoing business deals and the CEO's writing style." }
    ],
    discussion_questions: [
      "What immediate steps do you take to attempt fund recovery?",
      "How do you verify the CEO's actual account compromise and scope of access?",
      "What process changes prevent similar BEC attacks in the future?",
      "How do you handle the EA who initiated the transfer — is this a training issue or a process failure?",
      "Do you report to law enforcement? Insurance? Regulators?",
      "What is the financial impact if funds cannot be recovered?"
    ]
  }
];


// ── Security Metrics Dashboard ───────────────────────────────────────────

export const SECURITY_METRICS = {
  kpis: [
    { id: "mttd", name: "Mean Time to Detect (MTTD)", unit: "hours", target: 4, industry_avg: 197 * 24, description: "Average time from initial compromise to detection", formula: "Sum(detection_time - compromise_time) / incident_count" },
    { id: "mttr", name: "Mean Time to Respond (MTTR)", unit: "hours", target: 1, industry_avg: 69 * 24, description: "Average time from detection to initial containment", formula: "Sum(containment_time - detection_time) / incident_count" },
    { id: "mttc", name: "Mean Time to Contain (MTTC)", unit: "hours", target: 4, industry_avg: 80 * 24, description: "Average time from detection to full containment", formula: "Sum(full_containment_time - detection_time) / incident_count" },
    { id: "fp_rate", name: "False Positive Rate", unit: "percent", target: 15, industry_avg: 45, description: "Percentage of alerts that are false positives", formula: "false_positive_alerts / total_alerts * 100" },
    { id: "alert_vol", name: "Alert Volume", unit: "alerts/day", target: null, description: "Total alerts generated per day (track trend)", formula: "count(alerts) per 24h period" },
    { id: "vuln_age", name: "Mean Vulnerability Age", unit: "days", target: 30, industry_avg: 67, description: "Average age of unpatched vulnerabilities by severity", formula: "Sum(today - vuln_discovery_date) / open_vuln_count" },
    { id: "patch_rate", name: "Patch Compliance Rate", unit: "percent", target: 95, industry_avg: 72, description: "Percentage of systems with current security patches", formula: "patched_systems / total_systems * 100" },
    { id: "phish_click", name: "Phishing Click Rate", unit: "percent", target: 3, industry_avg: 12, description: "Percentage of employees who click simulated phishing links", formula: "clicked_users / targeted_users * 100" },
    { id: "coverage", name: "Detection Coverage", unit: "percent", target: 85, industry_avg: 39, description: "Percentage of MITRE ATT&CK techniques with detection rules", formula: "techniques_with_detection / total_techniques * 100" },
    { id: "dwell", name: "Dwell Time", unit: "days", target: 1, industry_avg: 16, description: "Time an attacker remains undetected in the environment", formula: "detection_date - initial_access_date" },
    { id: "sec_train", name: "Security Training Completion", unit: "percent", target: 100, industry_avg: 78, description: "Percentage of employees who completed annual security awareness training", formula: "completed_employees / total_employees * 100" },
    { id: "mfa_coverage", name: "MFA Coverage", unit: "percent", target: 100, industry_avg: 64, description: "Percentage of user accounts with MFA enabled", formula: "mfa_enabled_accounts / total_accounts * 100" }
  ]
};


// ── After-Action Report Template ─────────────────────────────────────────

export function generateAfterActionReport(incident) {
  const sections = [
    {
      title: "1. Executive Summary",
      content: `Incident ID: ${incident.id || "INC-XXXX"}\nClassification: ${incident.classification || "TBD"}\nSeverity: ${incident.severity || "TBD"}\nDate Detected: ${incident.detected || "YYYY-MM-DD"}\nDate Contained: ${incident.contained || "YYYY-MM-DD"}\nDate Resolved: ${incident.resolved || "YYYY-MM-DD"}\nImpact: ${incident.impact || "TBD"}`
    },
    {
      title: "2. Incident Timeline",
      content: "Document chronological sequence of events from initial compromise through detection, containment, eradication, and recovery.\n\n| Time | Event | Source | Action Taken |\n|------|-------|--------|--------------|"
    },
    {
      title: "3. Root Cause Analysis",
      content: "Identify the root cause(s) that enabled the incident:\n- Initial access vector\n- Vulnerabilities exploited\n- Security control gaps\n- Process failures\n- Contributing factors"
    },
    {
      title: "4. Impact Assessment",
      content: "Quantify the impact:\n- Systems affected: \n- Data compromised: \n- Users impacted: \n- Financial impact: \n- Operational downtime: \n- Regulatory implications: \n- Reputational impact:"
    },
    {
      title: "5. Response Effectiveness",
      content: "Evaluate the response:\n- Detection: How was it detected? Could it have been detected sooner?\n- Containment: Was containment timely and effective?\n- Eradication: Was the threat fully removed?\n- Recovery: Was recovery smooth? Were backups effective?\n- Communication: Were stakeholders informed appropriately?"
    },
    {
      title: "6. Lessons Learned",
      content: "What went well:\n- \n\nWhat could be improved:\n- \n\nWhat was missing:\n- "
    },
    {
      title: "7. Recommendations",
      content: "Priority | Recommendation | Owner | Due Date | Status\n---------|----------------|-------|----------|-------"
    },
    {
      title: "8. Action Items",
      content: "Track specific follow-up actions to prevent recurrence."
    }
  ];

  return sections.map(s => `## ${s.title}\n\n${s.content}`).join("\n\n---\n\n");
}


// ── Patch Management Decision Engine ─────────────────────────────────────

export function recommendPatchUrgency(cvss, assetCriticality, exploitAvailable, inKEV, internetFacing) {
  let urgency = 0;

  if (cvss >= 9.0) urgency += 40;
  else if (cvss >= 7.0) urgency += 25;
  else if (cvss >= 4.0) urgency += 10;
  else urgency += 3;

  const critMap = { critical: 30, high: 20, medium: 10, low: 5 };
  urgency += critMap[assetCriticality] || 10;

  if (exploitAvailable) urgency += 20;
  if (inKEV) urgency += 25;
  if (internetFacing) urgency += 15;

  let recommendation, sla;
  if (urgency >= 80) { recommendation = "Emergency patch — deploy within 24 hours"; sla = "24 hours"; }
  else if (urgency >= 60) { recommendation = "Critical — deploy within 72 hours"; sla = "72 hours"; }
  else if (urgency >= 40) { recommendation = "High — deploy within 7 days"; sla = "7 days"; }
  else if (urgency >= 20) { recommendation = "Medium — deploy within 30 days"; sla = "30 days"; }
  else { recommendation = "Low — deploy within 90 days or accept risk"; sla = "90 days"; }

  return { urgency: Math.min(100, urgency), recommendation, sla, factors: { cvss, assetCriticality, exploitAvailable, inKEV, internetFacing } };
}


// ── IOC Lifecycle Management ─────────────────────────────────────────────

export function createIOC(type, value, source, confidence, tlp) {
  return {
    id: "ioc-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    type,
    value,
    source,
    confidence: Math.min(100, Math.max(0, confidence)),
    tlp: tlp || "TLP:AMBER",
    created: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    expiry: null,
    tags: [],
    enrichments: [],
    status: "active",
    sightings: 1
  };
}

export function enrichIOC(ioc, enrichmentType, data) {
  ioc.enrichments.push({
    type: enrichmentType,
    data,
    timestamp: new Date().toISOString()
  });
  return ioc;
}

export function ageIOC(ioc, maxAgeDays) {
  const age = (Date.now() - new Date(ioc.last_seen).getTime()) / (1000 * 60 * 60 * 24);
  if (age > maxAgeDays) {
    ioc.status = "expired";
    ioc.confidence = Math.max(0, ioc.confidence - Math.floor(age - maxAgeDays));
  } else if (age > maxAgeDays * 0.75) {
    ioc.status = "aging";
    ioc.confidence = Math.max(0, ioc.confidence - 10);
  }
  return ioc;
}

export function scoreIOCRelevance(ioc, orgSectors, orgRegions) {
  let relevance = ioc.confidence;
  if (ioc.tags.some(t => orgSectors.includes(t))) relevance += 15;
  if (ioc.tags.some(t => orgRegions.includes(t))) relevance += 10;
  if (ioc.sightings > 10) relevance += 10;
  if (ioc.status === "expired") relevance -= 30;
  return Math.min(100, Math.max(0, relevance));
}


// ── Utility ──────────────────────────────────────────────────────────────

export function assessSOCMaturity(answers) {
  let score = 0;
  const weights = {
    has_siem: 15, has_edr: 10, has_soar: 10, has_tip: 8,
    has_247: 12, has_threat_hunting: 10, has_ir_plan: 8,
    has_playbooks: 8, has_metrics: 7, has_purple_team: 7,
    has_deception: 5
  };
  for (const [k, w] of Object.entries(weights)) {
    if (answers[k]) score += w;
  }
  let level;
  if (score >= 85) level = 4;
  else if (score >= 65) level = 3;
  else if (score >= 45) level = 2;
  else if (score >= 20) level = 1;
  else level = 0;
  return { score, level, maturity: SOC_MATURITY_MODEL[level] };
}

export function lookupComplianceControl(domain, framework) {
  const ctrl = COMPLIANCE_MATRIX.controls.find(c => c.domain.toLowerCase() === domain.toLowerCase());
  if (!ctrl) return null;
  if (framework) return ctrl.mappings[framework] || null;
  return ctrl.mappings;
}

export function getTabletopExercise(id) {
  return TABLETOP_EXERCISES.find(t => t.id === id) || null;
}
