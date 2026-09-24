// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Compliance Checker -- security compliance assessment, gap analysis, and audit readiness.

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const STORAGE_KEY = "dn_compliance_data";

function loadData() {
  try { const d = localStorage.getItem(STORAGE_KEY); return d ? JSON.parse(d) : {}; } catch (_) { return {}; }
}
function saveData(data) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch (_) {}
}

const STATUSES = ["Not Started", "In Progress", "Implemented", "Not Applicable"];
const PRIORITIES = ["Critical", "High", "Medium", "Low"];
const STATUS_COLORS = { "Not Started": "#ef4444", "In Progress": "#f59e0b", "Implemented": "#22c55e", "Not Applicable": "#6b7280" };

// ---- FRAMEWORK DEFINITIONS ----

const FRAMEWORKS = {
  "NIST CSF 2.0": {
    description: "NIST Cybersecurity Framework 2.0 -- voluntary framework for managing cybersecurity risk",
    categories: ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"],
    controls: [
      { id: "GV.OC-01", title: "Organizational Context", desc: "The organizational mission is understood and informs cybersecurity risk management", category: "Govern", priority: "High", evidence: "Mission statement, risk appetite documentation, stakeholder analysis", mapping: { "ISO 27001": "4.1, 4.2", "CIS v8": "N/A", "PCI DSS": "12.1" } },
      { id: "GV.OC-02", title: "Internal Stakeholders", desc: "Internal stakeholders understand and contribute to cybersecurity risk management", category: "Govern", priority: "High", evidence: "RACI matrix, training records, meeting minutes", mapping: { "ISO 27001": "5.1, 5.3", "CIS v8": "N/A", "PCI DSS": "12.4" } },
      { id: "GV.OC-03", title: "Legal and Regulatory Requirements", desc: "Legal, regulatory, and contractual requirements are understood and managed", category: "Govern", priority: "Critical", evidence: "Compliance register, legal opinions, contract reviews", mapping: { "ISO 27001": "A.18.1", "CIS v8": "N/A", "PCI DSS": "12.1.1" } },
      { id: "GV.OC-04", title: "Critical Objectives", desc: "Critical objectives, capabilities, and services are understood and communicated", category: "Govern", priority: "High", evidence: "BIA results, service catalog, critical asset inventory", mapping: { "ISO 27001": "A.8.1", "CIS v8": "1.1", "PCI DSS": "2.4" } },
      { id: "GV.OC-05", title: "Outcomes and Priorities", desc: "Outcomes, capabilities, and services dependency on other organizations are understood", category: "Govern", priority: "Medium", evidence: "Supply chain documentation, third-party inventory, SLAs", mapping: { "ISO 27001": "A.15.1", "CIS v8": "15.1", "PCI DSS": "12.8" } },
      { id: "GV.RM-01", title: "Risk Management Strategy", desc: "Risk management objectives are established and communicated", category: "Govern", priority: "Critical", evidence: "Risk management policy, risk appetite statement", mapping: { "ISO 27001": "6.1", "CIS v8": "N/A", "PCI DSS": "12.2" } },
      { id: "GV.RM-02", title: "Risk Appetite", desc: "Risk appetite and risk tolerance statements are determined and communicated", category: "Govern", priority: "High", evidence: "Risk appetite statement, board approval records", mapping: { "ISO 27001": "6.1.2", "CIS v8": "N/A", "PCI DSS": "12.2" } },
      { id: "GV.RM-03", title: "Risk Results Integration", desc: "Cybersecurity risk management results are incorporated into enterprise risk management", category: "Govern", priority: "High", evidence: "Enterprise risk register, board reports, executive briefings", mapping: { "ISO 27001": "9.3", "CIS v8": "N/A", "PCI DSS": "12.2" } },
      { id: "GV.RM-04", title: "Strategic Direction", desc: "Strategic direction that describes appropriate risk response options is established", category: "Govern", priority: "Medium", evidence: "Risk response procedures, treatment plans", mapping: { "ISO 27001": "6.1.3", "CIS v8": "N/A", "PCI DSS": "12.2" } },
      { id: "GV.RR-01", title: "Leadership Accountability", desc: "Organizational leadership is accountable for cybersecurity risk", category: "Govern", priority: "Critical", evidence: "CISO appointment letter, board charter, org chart", mapping: { "ISO 27001": "5.1", "CIS v8": "N/A", "PCI DSS": "12.4.1" } },
      { id: "GV.RR-02", title: "Roles and Responsibilities", desc: "Roles and responsibilities for cybersecurity are established, communicated, and enforced", category: "Govern", priority: "High", evidence: "Job descriptions, RACI charts, security policy", mapping: { "ISO 27001": "5.3, A.6.1", "CIS v8": "N/A", "PCI DSS": "12.4" } },
      { id: "GV.SC-01", title: "Supply Chain Program", desc: "A cybersecurity supply chain risk management program is established", category: "Govern", priority: "High", evidence: "SCRM policy, vendor assessment procedures", mapping: { "ISO 27001": "A.15.1", "CIS v8": "15.1", "PCI DSS": "12.8" } },
      { id: "ID.AM-01", title: "Hardware Inventory", desc: "Inventories of hardware managed by the organization are maintained", category: "Identify", priority: "Critical", evidence: "Asset inventory, CMDB exports, network scan results", mapping: { "ISO 27001": "A.8.1.1", "CIS v8": "1.1", "PCI DSS": "2.4" } },
      { id: "ID.AM-02", title: "Software Inventory", desc: "Inventories of software, services, and systems managed by the organization are maintained", category: "Identify", priority: "Critical", evidence: "Software inventory, license management records, SaaS catalog", mapping: { "ISO 27001": "A.8.1.1", "CIS v8": "2.1", "PCI DSS": "2.4" } },
      { id: "ID.AM-03", title: "Data Mapping", desc: "Representations of the organization's authorized network communication and data flows are maintained", category: "Identify", priority: "High", evidence: "Network diagrams, data flow diagrams, architecture docs", mapping: { "ISO 27001": "A.13.1", "CIS v8": "12.4", "PCI DSS": "1.1.2" } },
      { id: "ID.AM-04", title: "External Service Inventory", desc: "Inventories of services provided by suppliers are maintained", category: "Identify", priority: "Medium", evidence: "Vendor inventory, SaaS/IaaS register, third-party risk assessments", mapping: { "ISO 27001": "A.15.1.2", "CIS v8": "15.2", "PCI DSS": "12.8.1" } },
      { id: "ID.AM-05", title: "Asset Prioritization", desc: "Assets are prioritized based on classification, criticality, and value to the organization", category: "Identify", priority: "High", evidence: "Asset classification scheme, criticality ratings, BIA", mapping: { "ISO 27001": "A.8.2", "CIS v8": "1.1", "PCI DSS": "9.6.1" } },
      { id: "ID.RA-01", title: "Vulnerability Identification", desc: "Vulnerabilities in assets are identified, validated, and recorded", category: "Identify", priority: "Critical", evidence: "Vulnerability scan reports, penetration test results, CVE tracking", mapping: { "ISO 27001": "A.12.6", "CIS v8": "7.1", "PCI DSS": "6.1" } },
      { id: "ID.RA-02", title: "Threat Intelligence", desc: "Cyber threat intelligence is received from information sharing forums and sources", category: "Identify", priority: "High", evidence: "Threat intel subscriptions, ISAC membership, intel reports", mapping: { "ISO 27001": "A.6.1.4", "CIS v8": "17.2", "PCI DSS": "6.1" } },
      { id: "ID.RA-03", title: "Threat Identification", desc: "Internal and external threats to the organization are identified and recorded", category: "Identify", priority: "High", evidence: "Threat register, risk assessment reports, threat modeling results", mapping: { "ISO 27001": "6.1.2", "CIS v8": "N/A", "PCI DSS": "6.1" } },
      { id: "ID.RA-04", title: "Impact Analysis", desc: "Potential impacts and likelihoods of threats exploiting vulnerabilities are identified", category: "Identify", priority: "High", evidence: "Risk assessment matrix, impact analysis documentation", mapping: { "ISO 27001": "6.1.2", "CIS v8": "N/A", "PCI DSS": "6.1" } },
      { id: "ID.RA-05", title: "Risk Prioritization", desc: "Risks are prioritized and used for decision making", category: "Identify", priority: "Critical", evidence: "Risk register, risk treatment plan, board risk report", mapping: { "ISO 27001": "6.1.3", "CIS v8": "N/A", "PCI DSS": "6.1" } },
      { id: "PR.AA-01", title: "Identity Management", desc: "Identities and credentials for authorized users, services, and hardware are managed", category: "Protect", priority: "Critical", evidence: "Identity management policy, user provisioning procedures, MFA deployment", mapping: { "ISO 27001": "A.9.2", "CIS v8": "5.1", "PCI DSS": "8.1" } },
      { id: "PR.AA-02", title: "Access Management", desc: "Identities are proofed and bound to credentials based on the context of interactions", category: "Protect", priority: "Critical", evidence: "Access control policy, identity verification procedures", mapping: { "ISO 27001": "A.9.2.1", "CIS v8": "5.2", "PCI DSS": "8.2" } },
      { id: "PR.AA-03", title: "Remote Access", desc: "Remote access integrity and confidentiality are enforced", category: "Protect", priority: "High", evidence: "VPN configuration, remote access policy, MFA for remote", mapping: { "ISO 27001": "A.6.2.2", "CIS v8": "3.10", "PCI DSS": "8.3" } },
      { id: "PR.AA-04", title: "Access Permissions", desc: "Access permissions and authorizations are managed, incorporating least privilege and separation of duties", category: "Protect", priority: "Critical", evidence: "RBAC documentation, access reviews, SoD matrix", mapping: { "ISO 27001": "A.9.1.2, A.9.4", "CIS v8": "6.1", "PCI DSS": "7.1" } },
      { id: "PR.AA-05", title: "Network Integrity", desc: "The integrity, confidentiality, and availability of network resources are protected", category: "Protect", priority: "High", evidence: "Network segmentation docs, firewall rules, IDS/IPS config", mapping: { "ISO 27001": "A.13.1", "CIS v8": "12.1", "PCI DSS": "1.1" } },
      { id: "PR.AT-01", title: "Security Awareness", desc: "Personnel are provided with awareness and training", category: "Protect", priority: "High", evidence: "Training completion records, awareness program docs, phishing test results", mapping: { "ISO 27001": "A.7.2.2", "CIS v8": "14.1", "PCI DSS": "12.6" } },
      { id: "PR.AT-02", title: "Privileged Users Training", desc: "Individuals in specialized roles are provided with awareness and training", category: "Protect", priority: "High", evidence: "Specialized training records, admin certification", mapping: { "ISO 27001": "A.7.2.2", "CIS v8": "14.9", "PCI DSS": "12.6" } },
      { id: "PR.DS-01", title: "Data-at-Rest Protection", desc: "The confidentiality, integrity, and availability of data-at-rest are protected", category: "Protect", priority: "Critical", evidence: "Encryption policy, FDE deployment, database encryption config", mapping: { "ISO 27001": "A.10.1, A.8.2.3", "CIS v8": "3.6", "PCI DSS": "3.4" } },
      { id: "PR.DS-02", title: "Data-in-Transit Protection", desc: "The confidentiality, integrity, and availability of data-in-transit are protected", category: "Protect", priority: "Critical", evidence: "TLS configuration, VPN setup, certificate management", mapping: { "ISO 27001": "A.10.1, A.13.1", "CIS v8": "3.10", "PCI DSS": "4.1" } },
      { id: "PR.DS-10", title: "Data Integrity", desc: "The confidentiality, integrity, and availability of data-in-use are protected", category: "Protect", priority: "High", evidence: "DLP configuration, endpoint protection, access controls", mapping: { "ISO 27001": "A.8.2.3", "CIS v8": "3.1", "PCI DSS": "3.1" } },
      { id: "PR.PS-01", title: "Configuration Management", desc: "Configuration management practices are established and applied", category: "Protect", priority: "High", evidence: "Baseline configurations, hardening standards, change management records", mapping: { "ISO 27001": "A.12.1.2", "CIS v8": "4.1", "PCI DSS": "2.2" } },
      { id: "PR.PS-02", title: "Software Maintenance", desc: "Software is maintained, replaced, and removed commensurate with risk", category: "Protect", priority: "High", evidence: "Patch management policy, patching records, EOL tracking", mapping: { "ISO 27001": "A.12.6.1", "CIS v8": "7.3", "PCI DSS": "6.2" } },
      { id: "PR.PS-04", title: "Log Records", desc: "Log records are generated and made available for continuous monitoring", category: "Protect", priority: "Critical", evidence: "Logging policy, SIEM configuration, log retention records", mapping: { "ISO 27001": "A.12.4", "CIS v8": "8.2", "PCI DSS": "10.1" } },
      { id: "PR.PS-05", title: "Installation and Execution", desc: "Installation and execution of unauthorized software are prevented", category: "Protect", priority: "High", evidence: "Application whitelisting config, software restriction policies", mapping: { "ISO 27001": "A.12.5.1", "CIS v8": "2.5", "PCI DSS": "6.4" } },
      { id: "PR.IR-01", title: "Resilience Requirements", desc: "Resilience requirements are established for technology infrastructure", category: "Protect", priority: "Medium", evidence: "SLAs, recovery objectives (RPO/RTO), infrastructure redundancy docs", mapping: { "ISO 27001": "A.17.1", "CIS v8": "11.1", "PCI DSS": "12.10" } },
      { id: "PR.IR-02", title: "Technology Recovery", desc: "Technology infrastructure resilience mechanisms are adequate", category: "Protect", priority: "High", evidence: "Backup procedures, DR plans, failover test results", mapping: { "ISO 27001": "A.17.1", "CIS v8": "11.2", "PCI DSS": "12.10.1" } },
      { id: "DE.CM-01", title: "Network Monitoring", desc: "Networks and network services are monitored for anomalous events", category: "Detect", priority: "Critical", evidence: "IDS/IPS deployment, netflow analysis, monitoring dashboards", mapping: { "ISO 27001": "A.12.4", "CIS v8": "13.1", "PCI DSS": "10.6" } },
      { id: "DE.CM-02", title: "Physical Environment Monitoring", desc: "The physical environment is monitored for anomalous events", category: "Detect", priority: "Medium", evidence: "Camera systems, environmental sensors, access logs", mapping: { "ISO 27001": "A.11.1", "CIS v8": "N/A", "PCI DSS": "9.1" } },
      { id: "DE.CM-03", title: "Personnel Activity Monitoring", desc: "Personnel activity and technology usage are monitored", category: "Detect", priority: "High", evidence: "UEBA configuration, privileged access monitoring, audit logs", mapping: { "ISO 27001": "A.12.4.3", "CIS v8": "8.5", "PCI DSS": "10.2" } },
      { id: "DE.CM-06", title: "External Service Monitoring", desc: "External service provider activities and services are monitored", category: "Detect", priority: "Medium", evidence: "Third-party monitoring, SLA tracking, vendor audit reports", mapping: { "ISO 27001": "A.15.2", "CIS v8": "15.4", "PCI DSS": "12.8.4" } },
      { id: "DE.CM-09", title: "Computing Hardware/Software Monitoring", desc: "Computing hardware, software, runtime environments, and their data are monitored", category: "Detect", priority: "High", evidence: "EDR deployment, SIEM rules, FIM configuration", mapping: { "ISO 27001": "A.12.4", "CIS v8": "8.1", "PCI DSS": "10.5" } },
      { id: "DE.AE-02", title: "Event Analysis", desc: "Potentially adverse events are analyzed to better understand associated activities", category: "Detect", priority: "High", evidence: "SOC procedures, alert triage documentation, investigation playbooks", mapping: { "ISO 27001": "A.16.1.4", "CIS v8": "17.4", "PCI DSS": "12.10" } },
      { id: "DE.AE-03", title: "Event Correlation", desc: "Information is correlated from multiple sources", category: "Detect", priority: "High", evidence: "SIEM correlation rules, log aggregation config, threat intel integration", mapping: { "ISO 27001": "A.12.4.1", "CIS v8": "8.11", "PCI DSS": "10.6" } },
      { id: "DE.AE-06", title: "Incident Declaration", desc: "Information on adverse events is provided to authorized staff and tools", category: "Detect", priority: "High", evidence: "Alerting configuration, escalation procedures, notification records", mapping: { "ISO 27001": "A.16.1.2", "CIS v8": "17.3", "PCI DSS": "12.10.1" } },
      { id: "RS.MA-01", title: "Incident Management", desc: "The incident response plan is executed in coordination with relevant third parties", category: "Respond", priority: "Critical", evidence: "IR plan, exercise results, third-party coordination agreements", mapping: { "ISO 27001": "A.16.1", "CIS v8": "17.1", "PCI DSS": "12.10" } },
      { id: "RS.MA-02", title: "Incident Reporting", desc: "Incident reports are triaged and validated", category: "Respond", priority: "High", evidence: "Incident ticketing system, triage procedures, validation criteria", mapping: { "ISO 27001": "A.16.1.2", "CIS v8": "17.2", "PCI DSS": "12.10.3" } },
      { id: "RS.MA-03", title: "Incident Categorization", desc: "Incidents are categorized and prioritized", category: "Respond", priority: "High", evidence: "Incident classification scheme, severity definitions, SLA documentation", mapping: { "ISO 27001": "A.16.1.4", "CIS v8": "17.4", "PCI DSS": "12.10" } },
      { id: "RS.MA-04", title: "Incident Escalation", desc: "Incidents are escalated or elevated as needed", category: "Respond", priority: "High", evidence: "Escalation matrix, communication plans, management notifications", mapping: { "ISO 27001": "A.16.1.4", "CIS v8": "17.4", "PCI DSS": "12.10.1" } },
      { id: "RS.AN-03", title: "Incident Analysis", desc: "Analysis is performed to understand attack scope and impact", category: "Respond", priority: "Critical", evidence: "Forensic reports, root cause analysis, timeline reconstruction", mapping: { "ISO 27001": "A.16.1.6", "CIS v8": "17.5", "PCI DSS": "12.10.4" } },
      { id: "RS.AN-06", title: "Response Improvement", desc: "Lessons learned are shared and processes are updated", category: "Respond", priority: "Medium", evidence: "Post-incident reviews, lessons learned documents, process updates", mapping: { "ISO 27001": "A.16.1.6", "CIS v8": "17.8", "PCI DSS": "12.10.6" } },
      { id: "RS.MI-01", title: "Incident Containment", desc: "Incidents are contained", category: "Respond", priority: "Critical", evidence: "Containment procedures, network isolation capabilities, playbooks", mapping: { "ISO 27001": "A.16.1.5", "CIS v8": "17.5", "PCI DSS": "12.10.5" } },
      { id: "RS.MI-02", title: "Incident Eradication", desc: "Incidents are eradicated", category: "Respond", priority: "Critical", evidence: "Eradication procedures, malware removal records, system rebuild docs", mapping: { "ISO 27001": "A.16.1.5", "CIS v8": "17.5", "PCI DSS": "12.10.5" } },
      { id: "RS.CO-02", title: "Internal Communication", desc: "Internal stakeholders are notified of incidents", category: "Respond", priority: "High", evidence: "Communication templates, notification records, stakeholder contact list", mapping: { "ISO 27001": "A.16.1.2", "CIS v8": "17.3", "PCI DSS": "12.10.1" } },
      { id: "RS.CO-03", title: "External Communication", desc: "External stakeholders are notified as required", category: "Respond", priority: "High", evidence: "Regulatory notification procedures, breach disclosure templates", mapping: { "ISO 27001": "A.16.1.2", "CIS v8": "17.3", "PCI DSS": "12.10.1" } },
      { id: "RC.RP-01", title: "Recovery Planning", desc: "The recovery portion of the incident response plan is executed", category: "Recover", priority: "Critical", evidence: "Recovery plan, DR procedures, recovery test results", mapping: { "ISO 27001": "A.17.1", "CIS v8": "17.7", "PCI DSS": "12.10" } },
      { id: "RC.RP-02", title: "Recovery Execution", desc: "Recovery activities are prioritized and performed", category: "Recover", priority: "Critical", evidence: "Recovery logs, system restoration records, verification checklists", mapping: { "ISO 27001": "A.17.1.3", "CIS v8": "17.7", "PCI DSS": "12.10" } },
      { id: "RC.RP-03", title: "Integrity Verification", desc: "The integrity of backups and restored assets is verified", category: "Recover", priority: "High", evidence: "Backup integrity tests, hash verification records, restoration validation", mapping: { "ISO 27001": "A.12.3.1", "CIS v8": "11.4", "PCI DSS": "12.10" } },
      { id: "RC.CO-03", title: "Recovery Communication", desc: "Recovery activities and progress are communicated to stakeholders", category: "Recover", priority: "Medium", evidence: "Status reports, recovery timeline communications, post-recovery briefings", mapping: { "ISO 27001": "A.17.1", "CIS v8": "17.8", "PCI DSS": "12.10.6" } },
    ]
  },
  "ISO 27001:2022": {
    description: "ISO/IEC 27001:2022 -- international standard for information security management systems",
    categories: ["Organizational", "People", "Physical", "Technological"],
    controls: [
      { id: "A.5.1", title: "Policies for Information Security", desc: "Information security policy and topic-specific policies shall be defined, approved, published, communicated, and reviewed", category: "Organizational", priority: "Critical", evidence: "Approved IS policy, topic-specific policies, distribution records, review schedule", mapping: { "NIST CSF": "GV.PO-01", "CIS v8": "N/A", "PCI DSS": "12.1" } },
      { id: "A.5.2", title: "Information Security Roles", desc: "Information security roles and responsibilities shall be defined and allocated", category: "Organizational", priority: "High", evidence: "RACI matrix, job descriptions, org chart, appointment letters", mapping: { "NIST CSF": "GV.RR-02", "CIS v8": "N/A", "PCI DSS": "12.4" } },
      { id: "A.5.3", title: "Segregation of Duties", desc: "Conflicting duties and areas of responsibility shall be segregated", category: "Organizational", priority: "High", evidence: "SoD matrix, access control documentation, periodic reviews", mapping: { "NIST CSF": "PR.AA-04", "CIS v8": "6.1", "PCI DSS": "7.1" } },
      { id: "A.5.4", title: "Management Responsibilities", desc: "Management shall require all personnel to apply information security", category: "Organizational", priority: "High", evidence: "Management commitment statement, security in employment contracts", mapping: { "NIST CSF": "GV.RR-01", "CIS v8": "N/A", "PCI DSS": "12.4.1" } },
      { id: "A.5.7", title: "Threat Intelligence", desc: "Information relating to information security threats shall be collected and analyzed", category: "Organizational", priority: "High", evidence: "Threat intel feeds, analysis reports, ISAC participation", mapping: { "NIST CSF": "ID.RA-02", "CIS v8": "17.2", "PCI DSS": "6.1" } },
      { id: "A.5.8", title: "Information Security in Project Management", desc: "Information security shall be integrated into project management", category: "Organizational", priority: "Medium", evidence: "Project security checklists, SDLC security gates, risk assessments", mapping: { "NIST CSF": "GV.OC-01", "CIS v8": "16.1", "PCI DSS": "6.3" } },
      { id: "A.5.9", title: "Inventory of Information Assets", desc: "An inventory of information and associated assets shall be developed and maintained", category: "Organizational", priority: "Critical", evidence: "Asset register, CMDB, data classification records", mapping: { "NIST CSF": "ID.AM-01, ID.AM-02", "CIS v8": "1.1, 2.1", "PCI DSS": "2.4" } },
      { id: "A.5.10", title: "Acceptable Use", desc: "Rules for acceptable use and handling of information and assets shall be identified and documented", category: "Organizational", priority: "Medium", evidence: "AUP document, signed acknowledgments, handling procedures", mapping: { "NIST CSF": "PR.AA-04", "CIS v8": "N/A", "PCI DSS": "12.3" } },
      { id: "A.5.15", title: "Access Control", desc: "Rules to control physical and logical access shall be established based on requirements", category: "Organizational", priority: "Critical", evidence: "Access control policy, RBAC documentation, access review records", mapping: { "NIST CSF": "PR.AA-04", "CIS v8": "6.1", "PCI DSS": "7.1" } },
      { id: "A.5.23", title: "Cloud Services Security", desc: "Processes for acquisition, use, management and exit from cloud services shall be established", category: "Organizational", priority: "High", evidence: "Cloud security policy, CSA STAR assessments, cloud inventory", mapping: { "NIST CSF": "ID.AM-04", "CIS v8": "15.1", "PCI DSS": "12.8" } },
      { id: "A.5.24", title: "Incident Management Planning", desc: "Incident management shall be planned and prepared for", category: "Organizational", priority: "Critical", evidence: "IR plan, contact lists, escalation procedures, tabletop exercises", mapping: { "NIST CSF": "RS.MA-01", "CIS v8": "17.1", "PCI DSS": "12.10" } },
      { id: "A.5.28", title: "Collection of Evidence", desc: "Procedures for identification, collection, acquisition and preservation of evidence", category: "Organizational", priority: "High", evidence: "Evidence handling procedures, chain of custody forms, forensic tools", mapping: { "NIST CSF": "RS.AN-03", "CIS v8": "17.5", "PCI DSS": "12.10.4" } },
      { id: "A.5.29", title: "IS During Disruption", desc: "Organization shall plan how to maintain IS at an appropriate level during disruption", category: "Organizational", priority: "High", evidence: "BCP/DR plans with security considerations, recovery security procedures", mapping: { "NIST CSF": "RC.RP-01", "CIS v8": "17.7", "PCI DSS": "12.10" } },
      { id: "A.5.30", title: "ICT Readiness for BC", desc: "ICT readiness shall be planned, implemented, maintained and tested", category: "Organizational", priority: "High", evidence: "DR test results, RTO/RPO documentation, backup verification", mapping: { "NIST CSF": "PR.IR-02", "CIS v8": "11.1", "PCI DSS": "12.10.1" } },
      { id: "A.5.34", title: "Privacy and PII", desc: "Privacy and protection of PII shall be ensured as required", category: "Organizational", priority: "Critical", evidence: "Privacy policy, DPIA records, consent management, data mapping", mapping: { "NIST CSF": "GV.OC-03", "CIS v8": "N/A", "PCI DSS": "3.1" } },
      { id: "A.5.36", title: "Compliance with Policies", desc: "Compliance with the IS policy and topic-specific policies shall be regularly reviewed", category: "Organizational", priority: "High", evidence: "Compliance audit reports, exception registers, review schedules", mapping: { "NIST CSF": "GV.OC-03", "CIS v8": "N/A", "PCI DSS": "12.11" } },
      { id: "A.6.1", title: "Screening", desc: "Background verification checks on candidates shall be carried out prior to joining", category: "People", priority: "High", evidence: "Background check policy, screening records, contractor verification", mapping: { "NIST CSF": "PR.AA-01", "CIS v8": "N/A", "PCI DSS": "12.7" } },
      { id: "A.6.3", title: "IS Awareness and Training", desc: "Personnel and relevant interested parties shall receive appropriate IS awareness and training", category: "People", priority: "High", evidence: "Training program, completion records, awareness materials, quizzes", mapping: { "NIST CSF": "PR.AT-01", "CIS v8": "14.1", "PCI DSS": "12.6" } },
      { id: "A.6.5", title: "Responsibilities After Termination", desc: "IS responsibilities that remain valid after termination shall be defined and enforced", category: "People", priority: "Medium", evidence: "Exit procedures, NDA enforcement, offboarding checklist", mapping: { "NIST CSF": "PR.AA-01", "CIS v8": "N/A", "PCI DSS": "8.1.3" } },
      { id: "A.7.1", title: "Physical Security Perimeters", desc: "Security perimeters shall be defined and used to protect sensitive areas", category: "Physical", priority: "High", evidence: "Physical security assessment, perimeter documentation, access control logs", mapping: { "NIST CSF": "PR.AA-05", "CIS v8": "N/A", "PCI DSS": "9.1" } },
      { id: "A.7.4", title: "Physical Security Monitoring", desc: "Premises shall be continuously monitored for unauthorized physical access", category: "Physical", priority: "Medium", evidence: "CCTV coverage map, monitoring procedures, guard schedules", mapping: { "NIST CSF": "DE.CM-02", "CIS v8": "N/A", "PCI DSS": "9.1.1" } },
      { id: "A.8.1", title: "User Endpoint Devices", desc: "Information stored on, processed by or accessible via user endpoint devices shall be protected", category: "Technological", priority: "High", evidence: "MDM configuration, endpoint protection, device encryption", mapping: { "NIST CSF": "PR.DS-01", "CIS v8": "4.1", "PCI DSS": "5.1" } },
      { id: "A.8.2", title: "Privileged Access Rights", desc: "Allocation and use of privileged access rights shall be restricted and managed", category: "Technological", priority: "Critical", evidence: "PAM deployment, privileged access policy, admin account inventory", mapping: { "NIST CSF": "PR.AA-04", "CIS v8": "5.4", "PCI DSS": "7.1" } },
      { id: "A.8.5", title: "Secure Authentication", desc: "Secure authentication technologies and procedures shall be established", category: "Technological", priority: "Critical", evidence: "MFA deployment, password policy, authentication standards", mapping: { "NIST CSF": "PR.AA-02", "CIS v8": "5.2", "PCI DSS": "8.2" } },
      { id: "A.8.7", title: "Protection Against Malware", desc: "Protection against malware shall be implemented", category: "Technological", priority: "Critical", evidence: "AV/EDR deployment, malware protection policy, scan schedules", mapping: { "NIST CSF": "DE.CM-09", "CIS v8": "10.1", "PCI DSS": "5.1" } },
      { id: "A.8.8", title: "Management of Technical Vulnerabilities", desc: "Information about technical vulnerabilities shall be obtained, evaluated, and remediated", category: "Technological", priority: "Critical", evidence: "Vulnerability management program, scan reports, patch metrics", mapping: { "NIST CSF": "ID.RA-01", "CIS v8": "7.1", "PCI DSS": "6.1" } },
      { id: "A.8.9", title: "Configuration Management", desc: "Configurations including security configurations shall be established and managed", category: "Technological", priority: "High", evidence: "Baseline configurations, CIS benchmarks, config drift detection", mapping: { "NIST CSF": "PR.PS-01", "CIS v8": "4.1", "PCI DSS": "2.2" } },
      { id: "A.8.12", title: "Data Leakage Prevention", desc: "Data leakage prevention measures shall be applied to systems and networks", category: "Technological", priority: "High", evidence: "DLP policy, DLP tool configuration, monitoring reports", mapping: { "NIST CSF": "PR.DS-10", "CIS v8": "3.1", "PCI DSS": "3.1" } },
      { id: "A.8.15", title: "Logging", desc: "Logs that record activities, exceptions, faults and other relevant events shall be produced and stored", category: "Technological", priority: "Critical", evidence: "Logging standards, SIEM configuration, log retention policy, integrity checks", mapping: { "NIST CSF": "PR.PS-04", "CIS v8": "8.2", "PCI DSS": "10.1" } },
      { id: "A.8.16", title: "Monitoring Activities", desc: "Networks, systems and applications shall be monitored for anomalous behavior", category: "Technological", priority: "Critical", evidence: "SOC procedures, monitoring dashboards, alert rules, SOAR playbooks", mapping: { "NIST CSF": "DE.CM-01", "CIS v8": "13.1", "PCI DSS": "10.6" } },
      { id: "A.8.20", title: "Networks Security", desc: "Networks and network devices shall be secured, managed and controlled", category: "Technological", priority: "High", evidence: "Network security policy, firewall rules, segmentation docs, switch configs", mapping: { "NIST CSF": "PR.AA-05", "CIS v8": "12.1", "PCI DSS": "1.1" } },
      { id: "A.8.24", title: "Use of Cryptography", desc: "Rules for effective use of cryptography including key management shall be defined", category: "Technological", priority: "High", evidence: "Cryptography policy, key management procedures, algorithm inventory", mapping: { "NIST CSF": "PR.DS-01", "CIS v8": "3.6", "PCI DSS": "3.5, 4.1" } },
      { id: "A.8.25", title: "Secure Development Lifecycle", desc: "Rules for secure development of software and systems shall be established", category: "Technological", priority: "High", evidence: "SDLC policy, code review requirements, SAST/DAST reports, security gates", mapping: { "NIST CSF": "PR.PS-01", "CIS v8": "16.1", "PCI DSS": "6.3" } },
      { id: "A.8.28", title: "Secure Coding", desc: "Secure coding principles shall be applied to software development", category: "Technological", priority: "High", evidence: "Coding standards, OWASP guidelines, code review checklists, training", mapping: { "NIST CSF": "PR.PS-01", "CIS v8": "16.1", "PCI DSS": "6.5" } },
      { id: "A.8.31", title: "Separation of Environments", desc: "Development, testing and production environments shall be separated", category: "Technological", priority: "High", evidence: "Environment architecture, access segregation, change management", mapping: { "NIST CSF": "PR.PS-01", "CIS v8": "16.1", "PCI DSS": "6.4.1" } },
    ]
  },
  "PCI DSS v4.0": {
    description: "Payment Card Industry Data Security Standard v4.0 -- security for cardholder data",
    categories: ["Build and Maintain", "Protect Cardholder Data", "Vulnerability Management", "Access Control", "Monitor and Test", "Information Security Policy"],
    controls: [
      { id: "1.1", title: "Network Security Controls", desc: "Network security controls (NSCs) are defined and understood", category: "Build and Maintain", priority: "Critical", evidence: "NSC policy, network diagram, data flow diagram", mapping: { "NIST CSF": "PR.AA-05", "ISO 27001": "A.8.20" } },
      { id: "1.2.1", title: "NSC Configuration Standards", desc: "Configuration standards for NSCs are defined, implemented, and maintained", category: "Build and Maintain", priority: "High", evidence: "Firewall/router configs, hardening standards, change records", mapping: { "NIST CSF": "PR.PS-01", "ISO 27001": "A.8.9" } },
      { id: "1.3.1", title: "Inbound Traffic Restriction", desc: "Inbound traffic to the CDE is restricted to only necessary traffic", category: "Build and Maintain", priority: "Critical", evidence: "Firewall rules, CDE network segmentation validation", mapping: { "NIST CSF": "PR.AA-05", "ISO 27001": "A.8.20" } },
      { id: "1.4.1", title: "NSC Between Trusted/Untrusted", desc: "NSCs are implemented between trusted and untrusted networks", category: "Build and Maintain", priority: "Critical", evidence: "DMZ architecture, segmentation testing results", mapping: { "NIST CSF": "PR.AA-05", "ISO 27001": "A.8.20" } },
      { id: "2.2", title: "System Configuration Standards", desc: "System components are configured and managed securely", category: "Build and Maintain", priority: "High", evidence: "CIS benchmarks, hardening procedures, config audit reports", mapping: { "NIST CSF": "PR.PS-01", "ISO 27001": "A.8.9" } },
      { id: "3.1", title: "CHD Storage Minimization", desc: "Processes and mechanisms for protecting stored account data are defined", category: "Protect Cardholder Data", priority: "Critical", evidence: "Data retention policy, storage location inventory, purging procedures", mapping: { "NIST CSF": "PR.DS-01", "ISO 27001": "A.8.10" } },
      { id: "3.4", title: "PAN Display Restriction", desc: "Access to displays of full PAN and ability to copy cardholder data are restricted", category: "Protect Cardholder Data", priority: "Critical", evidence: "Masking configuration, access controls, application screenshots", mapping: { "NIST CSF": "PR.DS-01", "ISO 27001": "A.8.11" } },
      { id: "3.5", title: "PAN Encryption", desc: "Primary account number (PAN) is secured wherever it is stored", category: "Protect Cardholder Data", priority: "Critical", evidence: "Encryption configuration, key management procedures, algorithm docs", mapping: { "NIST CSF": "PR.DS-01", "ISO 27001": "A.8.24" } },
      { id: "4.1", title: "Transmission Encryption", desc: "Processes and mechanisms for protecting cardholder data with strong cryptography during transmission are defined", category: "Protect Cardholder Data", priority: "Critical", evidence: "TLS configuration, certificate management, transmission inventory", mapping: { "NIST CSF": "PR.DS-02", "ISO 27001": "A.8.24" } },
      { id: "5.2", title: "Malware Prevention", desc: "Malicious software is prevented, or detected and addressed", category: "Vulnerability Management", priority: "Critical", evidence: "AV/EDR deployment, update schedules, scan logs", mapping: { "NIST CSF": "DE.CM-09", "ISO 27001": "A.8.7" } },
      { id: "5.3", title: "Anti-Malware Mechanisms", desc: "Anti-malware mechanisms and processes are active, maintained, and monitored", category: "Vulnerability Management", priority: "High", evidence: "AV management console, update verification, monitoring alerts", mapping: { "NIST CSF": "DE.CM-09", "ISO 27001": "A.8.7" } },
      { id: "6.1", title: "Vulnerability Management", desc: "Processes and mechanisms for identifying security vulnerabilities are defined", category: "Vulnerability Management", priority: "Critical", evidence: "Vulnerability management policy, CVE monitoring, scan schedules", mapping: { "NIST CSF": "ID.RA-01", "ISO 27001": "A.8.8" } },
      { id: "6.2", title: "Secure Development", desc: "Bespoke and custom software are developed securely", category: "Vulnerability Management", priority: "High", evidence: "SDLC documentation, code review records, SAST/DAST results", mapping: { "NIST CSF": "PR.PS-01", "ISO 27001": "A.8.25" } },
      { id: "6.4", title: "Web Application Protection", desc: "Public-facing web applications are protected against attacks", category: "Vulnerability Management", priority: "Critical", evidence: "WAF configuration, web app testing, vulnerability remediation", mapping: { "NIST CSF": "PR.PS-05", "ISO 27001": "A.8.28" } },
      { id: "7.1", title: "Access Restriction Processes", desc: "Processes and mechanisms for restricting access to system components and CHD are defined", category: "Access Control", priority: "Critical", evidence: "Access control policy, RBAC documentation, need-to-know validation", mapping: { "NIST CSF": "PR.AA-04", "ISO 27001": "A.5.15" } },
      { id: "8.2", title: "User Identification", desc: "User identification and related accounts are strictly managed", category: "Access Control", priority: "Critical", evidence: "User account management procedures, unique ID enforcement, account reviews", mapping: { "NIST CSF": "PR.AA-01", "ISO 27001": "A.8.5" } },
      { id: "8.3", title: "Strong Authentication", desc: "Strong authentication for users and administrators is established and managed", category: "Access Control", priority: "Critical", evidence: "MFA deployment, password policy, authentication configuration", mapping: { "NIST CSF": "PR.AA-02", "ISO 27001": "A.8.5" } },
      { id: "9.1", title: "Physical Access Processes", desc: "Processes and mechanisms for restricting physical access to cardholder data are defined", category: "Access Control", priority: "High", evidence: "Physical security policy, access badge system, visitor logs", mapping: { "NIST CSF": "PR.AA-05", "ISO 27001": "A.7.1" } },
      { id: "10.1", title: "Logging and Monitoring", desc: "Processes and mechanisms for logging and monitoring are defined", category: "Monitor and Test", priority: "Critical", evidence: "Logging policy, SIEM configuration, monitoring procedures", mapping: { "NIST CSF": "PR.PS-04", "ISO 27001": "A.8.15" } },
      { id: "10.2", title: "Audit Logs", desc: "Audit logs are implemented to support the detection of anomalies and suspicious activity", category: "Monitor and Test", priority: "Critical", evidence: "Audit log configuration, event categories captured, sample logs", mapping: { "NIST CSF": "DE.CM-01", "ISO 27001": "A.8.15" } },
      { id: "10.4", title: "Log Review", desc: "Audit logs are reviewed to identify anomalies or suspicious activity", category: "Monitor and Test", priority: "Critical", evidence: "Log review procedures, review schedules, finding documentation", mapping: { "NIST CSF": "DE.AE-02", "ISO 27001": "A.8.16" } },
      { id: "11.3", title: "Vulnerability Scanning", desc: "External and internal vulnerabilities are regularly identified, prioritized, and addressed", category: "Monitor and Test", priority: "Critical", evidence: "ASV scan reports, internal scan reports, remediation tracking", mapping: { "NIST CSF": "ID.RA-01", "ISO 27001": "A.8.8" } },
      { id: "11.4", title: "Penetration Testing", desc: "External and internal penetration testing is regularly performed", category: "Monitor and Test", priority: "Critical", evidence: "Pentest reports, methodology docs, remediation validation", mapping: { "NIST CSF": "ID.RA-01", "ISO 27001": "A.8.8" } },
      { id: "12.1", title: "IS Policy", desc: "A comprehensive information security policy is known by all personnel", category: "Information Security Policy", priority: "Critical", evidence: "IS policy document, acknowledgment records, annual review", mapping: { "NIST CSF": "GV.PO-01", "ISO 27001": "A.5.1" } },
      { id: "12.6", title: "Security Awareness", desc: "Security awareness education is an ongoing activity", category: "Information Security Policy", priority: "High", evidence: "Training program, completion records, phishing test results", mapping: { "NIST CSF": "PR.AT-01", "ISO 27001": "A.6.3" } },
      { id: "12.8", title: "Third-Party Management", desc: "Risk to information assets from relationships with service providers is managed", category: "Information Security Policy", priority: "High", evidence: "TPRM policy, vendor assessments, contract requirements", mapping: { "NIST CSF": "GV.SC-01", "ISO 27001": "A.5.23" } },
      { id: "12.10", title: "Incident Response", desc: "Security incidents and suspected security incidents are responded to immediately", category: "Information Security Policy", priority: "Critical", evidence: "IR plan, team roster, contact info, tabletop exercise results", mapping: { "NIST CSF": "RS.MA-01", "ISO 27001": "A.5.24" } },
    ]
  },
  "CIS Controls v8": {
    description: "Center for Internet Security Controls v8 -- prioritized set of actions to defend against cyber attacks",
    categories: ["Basic", "Foundational", "Organizational"],
    controls: [
      { id: "1.1", title: "Enterprise Asset Inventory", desc: "Establish and maintain a detailed enterprise asset inventory", category: "Basic", priority: "Critical", evidence: "CMDB exports, automated discovery scans, asset register", mapping: { "NIST CSF": "ID.AM-01", "ISO 27001": "A.5.9" } },
      { id: "2.1", title: "Software Inventory", desc: "Establish and maintain a detailed software inventory", category: "Basic", priority: "Critical", evidence: "Software inventory tool output, license management records", mapping: { "NIST CSF": "ID.AM-02", "ISO 27001": "A.5.9" } },
      { id: "3.1", title: "Data Management Process", desc: "Establish and maintain a data management process", category: "Basic", priority: "High", evidence: "Data classification policy, data inventory, handling procedures", mapping: { "NIST CSF": "PR.DS-10", "ISO 27001": "A.8.10" } },
      { id: "4.1", title: "Secure Configuration", desc: "Establish and maintain a secure configuration process for enterprise assets", category: "Basic", priority: "Critical", evidence: "CIS benchmarks, baseline configs, configuration audit results", mapping: { "NIST CSF": "PR.PS-01", "ISO 27001": "A.8.9" } },
      { id: "5.1", title: "Account Inventory", desc: "Establish and maintain an inventory of all accounts managed in the enterprise", category: "Basic", priority: "Critical", evidence: "User account inventory, service account list, access reviews", mapping: { "NIST CSF": "PR.AA-01", "ISO 27001": "A.8.2" } },
      { id: "5.2", title: "Use Unique Passwords", desc: "Use unique passwords for all enterprise assets", category: "Basic", priority: "High", evidence: "Password policy, password manager deployment, policy enforcement", mapping: { "NIST CSF": "PR.AA-02", "ISO 27001": "A.8.5" } },
      { id: "5.4", title: "Restrict Admin Privileges", desc: "Restrict administrator privileges to dedicated administrator accounts", category: "Basic", priority: "Critical", evidence: "Separate admin accounts, PAM deployment, privilege audit", mapping: { "NIST CSF": "PR.AA-04", "ISO 27001": "A.8.2" } },
      { id: "6.1", title: "Access Granting Process", desc: "Establish an access granting process", category: "Basic", priority: "High", evidence: "Access request workflow, approval records, provisioning procedures", mapping: { "NIST CSF": "PR.AA-04", "ISO 27001": "A.5.15" } },
      { id: "7.1", title: "Vulnerability Management", desc: "Establish and maintain a vulnerability management process", category: "Foundational", priority: "Critical", evidence: "VM policy, scan schedules, remediation SLAs, metrics", mapping: { "NIST CSF": "ID.RA-01", "ISO 27001": "A.8.8" } },
      { id: "8.2", title: "Audit Log Management", desc: "Collect audit logs", category: "Foundational", priority: "Critical", evidence: "SIEM deployment, log sources, retention configuration", mapping: { "NIST CSF": "PR.PS-04", "ISO 27001": "A.8.15" } },
      { id: "9.1", title: "Email and Browser Protections", desc: "Ensure use of only fully supported browsers and email clients", category: "Foundational", priority: "High", evidence: "Browser standards, email gateway configuration, extension policy", mapping: { "NIST CSF": "PR.PS-02", "ISO 27001": "A.8.1" } },
      { id: "10.1", title: "Deploy Anti-Malware", desc: "Deploy and maintain anti-malware software on all enterprise assets", category: "Foundational", priority: "Critical", evidence: "EDR/AV deployment records, management console, coverage report", mapping: { "NIST CSF": "DE.CM-09", "ISO 27001": "A.8.7" } },
      { id: "11.1", title: "Data Recovery Practice", desc: "Establish and maintain a data recovery practice", category: "Foundational", priority: "High", evidence: "Backup policy, backup schedules, recovery test results", mapping: { "NIST CSF": "PR.IR-02", "ISO 27001": "A.5.30" } },
      { id: "12.1", title: "Network Infrastructure Management", desc: "Ensure network infrastructure is up-to-date", category: "Foundational", priority: "High", evidence: "Network device inventory, firmware versions, patching records", mapping: { "NIST CSF": "PR.AA-05", "ISO 27001": "A.8.20" } },
      { id: "13.1", title: "Network Monitoring and Defense", desc: "Centralize network-based security event alerting", category: "Foundational", priority: "Critical", evidence: "IDS/IPS deployment, SIEM network rules, alert procedures", mapping: { "NIST CSF": "DE.CM-01", "ISO 27001": "A.8.16" } },
      { id: "14.1", title: "Security Awareness Program", desc: "Establish and maintain a security awareness program", category: "Organizational", priority: "High", evidence: "Awareness program charter, annual plan, completion metrics", mapping: { "NIST CSF": "PR.AT-01", "ISO 27001": "A.6.3" } },
      { id: "15.1", title: "Service Provider Management", desc: "Establish and maintain an inventory of service providers", category: "Organizational", priority: "High", evidence: "Vendor inventory, risk assessments, contract reviews", mapping: { "NIST CSF": "GV.SC-01", "ISO 27001": "A.5.23" } },
      { id: "16.1", title: "Application Software Security", desc: "Establish and maintain a secure application development process", category: "Organizational", priority: "High", evidence: "SDLC documentation, security gates, SAST/DAST results", mapping: { "NIST CSF": "PR.PS-01", "ISO 27001": "A.8.25" } },
      { id: "17.1", title: "Incident Response Process", desc: "Designate one key person and at least one backup for incident handling", category: "Organizational", priority: "Critical", evidence: "IR team roster, contact information, on-call schedule", mapping: { "NIST CSF": "RS.MA-01", "ISO 27001": "A.5.24" } },
      { id: "18.1", title: "Penetration Testing", desc: "Establish and maintain a penetration testing program", category: "Organizational", priority: "High", evidence: "Pentest policy, scope documents, vendor contracts, reports", mapping: { "NIST CSF": "ID.RA-01", "ISO 27001": "A.8.8" } },
    ]
  },
  "HIPAA": {
    description: "Health Insurance Portability and Accountability Act -- protecting health information",
    categories: ["Administrative", "Physical", "Technical"],
    controls: [
      { id: "164.308(a)(1)", title: "Security Management Process", desc: "Implement policies and procedures to prevent, detect, contain, and correct security violations", category: "Administrative", priority: "Critical", evidence: "Risk analysis, risk management plan, sanction policy, IS activity review", mapping: { "NIST CSF": "GV.RM-01", "ISO 27001": "6.1" } },
      { id: "164.308(a)(2)", title: "Assigned Security Responsibility", desc: "Identify the security official responsible for developing and implementing security policies", category: "Administrative", priority: "Critical", evidence: "Security officer appointment, job description, org chart", mapping: { "NIST CSF": "GV.RR-01", "ISO 27001": "A.5.2" } },
      { id: "164.308(a)(3)", title: "Workforce Security", desc: "Implement policies to ensure all workforce members have appropriate access to ePHI", category: "Administrative", priority: "High", evidence: "Authorization procedures, clearance procedures, termination procedures", mapping: { "NIST CSF": "PR.AA-04", "ISO 27001": "A.5.15" } },
      { id: "164.308(a)(4)", title: "Information Access Management", desc: "Implement policies and procedures for authorizing access to ePHI", category: "Administrative", priority: "Critical", evidence: "Access authorization policy, access establishment/modification procedures", mapping: { "NIST CSF": "PR.AA-04", "ISO 27001": "A.5.15" } },
      { id: "164.308(a)(5)", title: "Security Awareness and Training", desc: "Implement a security awareness and training program for all workforce members", category: "Administrative", priority: "High", evidence: "Training materials, completion records, phishing test results, log-in monitoring", mapping: { "NIST CSF": "PR.AT-01", "ISO 27001": "A.6.3" } },
      { id: "164.308(a)(6)", title: "Security Incident Procedures", desc: "Implement policies and procedures to address security incidents", category: "Administrative", priority: "Critical", evidence: "Incident response plan, incident tracking system, response procedures", mapping: { "NIST CSF": "RS.MA-01", "ISO 27001": "A.5.24" } },
      { id: "164.308(a)(7)", title: "Contingency Plan", desc: "Establish policies and procedures for responding to an emergency or occurrence that damages systems with ePHI", category: "Administrative", priority: "Critical", evidence: "Data backup plan, DR plan, emergency mode operation plan, testing results", mapping: { "NIST CSF": "RC.RP-01", "ISO 27001": "A.5.30" } },
      { id: "164.308(a)(8)", title: "Evaluation", desc: "Perform periodic technical and nontechnical evaluation of security policies and procedures", category: "Administrative", priority: "High", evidence: "Risk assessment reports, internal audit results, evaluation schedule", mapping: { "NIST CSF": "GV.OC-03", "ISO 27001": "A.5.36" } },
      { id: "164.308(b)(1)", title: "Business Associate Contracts", desc: "A covered entity may permit a BA to create, receive, maintain, or transmit ePHI only with written contract", category: "Administrative", priority: "Critical", evidence: "BAA templates, executed BAAs, vendor inventory", mapping: { "NIST CSF": "GV.SC-01", "ISO 27001": "A.5.23" } },
      { id: "164.310(a)(1)", title: "Facility Access Controls", desc: "Implement policies and procedures to limit physical access to electronic information systems", category: "Physical", priority: "High", evidence: "Facility security plan, access control logs, maintenance records", mapping: { "NIST CSF": "PR.AA-05", "ISO 27001": "A.7.1" } },
      { id: "164.310(b)", title: "Workstation Use", desc: "Implement policies and procedures for proper workstation use and access", category: "Physical", priority: "Medium", evidence: "Workstation use policy, physical safeguards, positioning standards", mapping: { "NIST CSF": "PR.DS-01", "ISO 27001": "A.8.1" } },
      { id: "164.310(c)", title: "Workstation Security", desc: "Implement physical safeguards for all workstations that access ePHI", category: "Physical", priority: "Medium", evidence: "Physical security measures, cable locks, screen locks", mapping: { "NIST CSF": "PR.DS-01", "ISO 27001": "A.8.1" } },
      { id: "164.310(d)(1)", title: "Device and Media Controls", desc: "Implement policies for disposal, re-use, accountability, and data backup of hardware and media", category: "Physical", priority: "High", evidence: "Media disposal procedures, destruction certificates, device tracking", mapping: { "NIST CSF": "PR.DS-01", "ISO 27001": "A.8.10" } },
      { id: "164.312(a)(1)", title: "Access Control", desc: "Implement technical policies and procedures for access to ePHI systems", category: "Technical", priority: "Critical", evidence: "Unique user ID, emergency access procedures, auto-logoff, encryption", mapping: { "NIST CSF": "PR.AA-04", "ISO 27001": "A.8.5" } },
      { id: "164.312(b)", title: "Audit Controls", desc: "Implement hardware, software, and procedural mechanisms for recording and examining access to ePHI", category: "Technical", priority: "Critical", evidence: "Audit log configuration, review procedures, SIEM deployment", mapping: { "NIST CSF": "PR.PS-04", "ISO 27001": "A.8.15" } },
      { id: "164.312(c)(1)", title: "Integrity", desc: "Implement policies and procedures to protect ePHI from improper alteration or destruction", category: "Technical", priority: "High", evidence: "Integrity verification mechanisms, checksums, FIM deployment", mapping: { "NIST CSF": "PR.DS-10", "ISO 27001": "A.8.24" } },
      { id: "164.312(d)", title: "Person or Entity Authentication", desc: "Implement procedures to verify the identity of persons or entities seeking access to ePHI", category: "Technical", priority: "Critical", evidence: "Authentication mechanisms, MFA deployment, identity proofing procedures", mapping: { "NIST CSF": "PR.AA-02", "ISO 27001": "A.8.5" } },
      { id: "164.312(e)(1)", title: "Transmission Security", desc: "Implement technical security measures to guard against unauthorized access to ePHI transmitted over networks", category: "Technical", priority: "Critical", evidence: "TLS configuration, VPN deployment, encryption standards", mapping: { "NIST CSF": "PR.DS-02", "ISO 27001": "A.8.24" } },
    ]
  },
  "GDPR": {
    description: "General Data Protection Regulation -- EU data protection and privacy regulation",
    categories: ["Lawfulness", "Rights", "Security", "Governance"],
    controls: [
      { id: "Art.5", title: "Principles of Processing", desc: "Personal data shall be processed lawfully, fairly, transparently, for specified purposes, minimized, accurate, stored with limitation, and secure", category: "Lawfulness", priority: "Critical", evidence: "Processing principles documentation, data minimization assessment", mapping: { "NIST CSF": "GV.OC-03", "ISO 27001": "A.5.34" } },
      { id: "Art.6", title: "Lawfulness of Processing", desc: "Processing must have a lawful basis: consent, contract, legal obligation, vital interests, public task, or legitimate interests", category: "Lawfulness", priority: "Critical", evidence: "Lawful basis register, consent records, LIA documentation", mapping: { "NIST CSF": "GV.OC-03", "ISO 27001": "A.5.34" } },
      { id: "Art.7", title: "Conditions for Consent", desc: "Where consent is the basis, controller must demonstrate consent; withdrawal must be as easy as giving", category: "Lawfulness", priority: "High", evidence: "Consent management system, opt-in/opt-out mechanisms, records", mapping: { "NIST CSF": "GV.OC-03", "ISO 27001": "A.5.34" } },
      { id: "Art.12-14", title: "Transparency and Information", desc: "Data subjects must be provided with information about processing in a concise, transparent manner", category: "Rights", priority: "Critical", evidence: "Privacy notices, layered notices, information provided at collection", mapping: { "NIST CSF": "GV.OC-03", "ISO 27001": "A.5.34" } },
      { id: "Art.15", title: "Right of Access", desc: "Data subjects have the right to obtain confirmation and access to their personal data", category: "Rights", priority: "Critical", evidence: "SAR procedures, response templates, tracking system", mapping: { "NIST CSF": "GV.OC-03", "ISO 27001": "A.5.34" } },
      { id: "Art.17", title: "Right to Erasure", desc: "Data subjects have the right to have their personal data erased ('right to be forgotten')", category: "Rights", priority: "High", evidence: "Erasure procedures, data mapping for deletion, verification process", mapping: { "NIST CSF": "GV.OC-03", "ISO 27001": "A.5.34" } },
      { id: "Art.20", title: "Right to Data Portability", desc: "Data subjects have the right to receive their data in a structured, commonly used format", category: "Rights", priority: "Medium", evidence: "Export procedures, supported formats, automated mechanisms", mapping: { "NIST CSF": "GV.OC-03", "ISO 27001": "A.5.34" } },
      { id: "Art.25", title: "Data Protection by Design", desc: "Controller shall implement appropriate measures designed to implement data-protection principles effectively", category: "Security", priority: "Critical", evidence: "Privacy by design checklists, DPIA process, architecture reviews", mapping: { "NIST CSF": "PR.PS-01", "ISO 27001": "A.5.8" } },
      { id: "Art.28", title: "Processor Obligations", desc: "Processing by a processor shall be governed by a contract with data protection provisions", category: "Governance", priority: "Critical", evidence: "DPA templates, executed DPAs, sub-processor management", mapping: { "NIST CSF": "GV.SC-01", "ISO 27001": "A.5.23" } },
      { id: "Art.30", title: "Records of Processing", desc: "Each controller and processor shall maintain a record of processing activities (ROPA)", category: "Governance", priority: "Critical", evidence: "ROPA register, regular updates, completeness review", mapping: { "NIST CSF": "ID.AM-03", "ISO 27001": "A.5.9" } },
      { id: "Art.32", title: "Security of Processing", desc: "Controller and processor shall implement appropriate technical and organizational measures for security", category: "Security", priority: "Critical", evidence: "Security measures inventory, encryption, pseudonymization, testing", mapping: { "NIST CSF": "PR.DS-01", "ISO 27001": "A.5.1" } },
      { id: "Art.33", title: "Breach Notification to Authority", desc: "Controller shall notify the supervisory authority within 72 hours of becoming aware of a personal data breach", category: "Security", priority: "Critical", evidence: "Breach notification procedures, template, 72-hour timeline, records", mapping: { "NIST CSF": "RS.CO-03", "ISO 27001": "A.5.24" } },
      { id: "Art.34", title: "Breach Communication to Subjects", desc: "When a breach is likely to result in high risk, the controller shall communicate to data subjects", category: "Security", priority: "High", evidence: "Communication templates, high-risk assessment criteria, notification records", mapping: { "NIST CSF": "RS.CO-03", "ISO 27001": "A.5.24" } },
      { id: "Art.35", title: "Data Protection Impact Assessment", desc: "Where processing is likely to result in a high risk, the controller shall carry out a DPIA", category: "Governance", priority: "High", evidence: "DPIA methodology, completed DPIAs, risk mitigation actions", mapping: { "NIST CSF": "ID.RA-04", "ISO 27001": "A.5.8" } },
      { id: "Art.37", title: "Data Protection Officer", desc: "Controller and processor shall designate a DPO in certain circumstances", category: "Governance", priority: "High", evidence: "DPO appointment, contact details published, independence documentation", mapping: { "NIST CSF": "GV.RR-01", "ISO 27001": "A.5.2" } },
    ]
  },
};

// ---- RENDERING ----

function renderFrameworkSelector(main, data) {
  const fwNames = Object.keys(FRAMEWORKS);
  // Real cross-framework aggregates (computed from the built-in control library
  // plus the user's own progress — no fabricated numbers).
  var aggCtrl = 0, aggImpl = 0, aggMap = 0;
  for (var a = 0; a < fwNames.length; a++) {
    var afw = FRAMEWORKS[fwNames[a]];
    var afwData = data[fwNames[a]] || {};
    aggCtrl += afw.controls.length;
    for (var b = 0; b < afw.controls.length; b++) {
      if ((afwData[afw.controls[b].id] || {}).status === "Implemented") aggImpl++;
      aggMap += Object.keys(afw.controls[b].mapping || {}).length;
    }
  }
  var aggPct = aggCtrl > 0 ? Math.round((aggImpl / aggCtrl) * 100) : 0;
  var ccCell = function (n, label, key) {
    return '<div class="cc-sm" data-k="' + key + '"><span class="cc-sm-n">' + n + '</span><span class="cc-sm-l">' + label + '</span></div>';
  };
  var html = '<div class="pg-head"><h1 class="pg-h1">Compliance Checker</h1>' +
    '<p class="muted pg-sub">Assess your organization against major security frameworks. Track controls, map across standards, and generate audit-ready reports.</p></div>' +
    '<div class="cc-summary">' +
      ccCell(fwNames.length, "Frameworks", "fw") +
      ccCell(aggCtrl, "Total controls", "ctrl") +
      ccCell(aggImpl, "Implemented", "impl") +
      ccCell(aggPct + "%", "Overall readiness", "pct") +
      ccCell(aggMap, "Cross-mappings", "map") +
    '</div>' +
    '<div class="cc-fw-grid">';
  for (var i = 0; i < fwNames.length; i++) {
    var fw = FRAMEWORKS[fwNames[i]];
    var fwData = data[fwNames[i]] || {};
    var total = fw.controls.length;
    var implemented = 0;
    for (var j = 0; j < fw.controls.length; j++) {
      if ((fwData[fw.controls[j].id] || {}).status === "Implemented") implemented++;
    }
    var pct = total > 0 ? Math.round((implemented / total) * 100) : 0;
    var barColor = pct >= 80 ? "#22c55e" : pct >= 50 ? "#f59e0b" : "#ef4444";
    html += '<div class="cc-fw-card" data-fw="' + esc(fwNames[i]) + '">' +
      '<div class="cc-fw-name">' + esc(fwNames[i]) + '</div>' +
      '<div class="cc-fw-desc">' + esc(fw.description) + '</div>' +
      '<div class="cc-fw-stats">' +
        '<span>' + total + ' controls</span>' +
        '<span>' + implemented + ' implemented</span>' +
        '<span style="font-weight:600;color:' + barColor + '">' + pct + '% ready</span>' +
      '</div>' +
      '<div class="cc-bar-bg"><div class="cc-bar-fill" style="width:' + pct + '%;background:' + barColor + '"></div></div>' +
    '</div>';
  }
  html += '</div>';
  main.innerHTML = html;

  main.querySelectorAll('.cc-fw-card').forEach(function(card) {
    card.onclick = function() {
      renderFrameworkDetail(main, card.dataset.fw, data);
    };
  });
}

function renderFrameworkDetail(main, fwName, data) {
  var fw = FRAMEWORKS[fwName];
  if (!fw) return;
  var fwData = data[fwName] || {};
  var cats = fw.categories;

  var html = '<div style="margin-bottom:12px">' +
    '<button class="btn sm" id="cc-back">Back to Frameworks</button>' +
    '<span style="margin-left:12px;font-size:1.1rem;font-weight:600">' + esc(fwName) + '</span>' +
  '</div>' +
  '<div class="cc-tabs" id="cc-tabs">' +
    '<button class="tab active" data-tab="controls">Controls</button>' +
    '<button class="tab" data-tab="gap">Gap Analysis</button>' +
    '<button class="tab" data-tab="mapping">Cross-Mapping</button>' +
    '<button class="tab" data-tab="export">Export Report</button>' +
  '</div>' +
  '<div id="cc-tab-content"></div>';

  main.innerHTML = html;

  main.querySelector('#cc-back').onclick = function() {
    renderFrameworkSelector(main, data);
  };

  function switchTab(tabId) {
    main.querySelectorAll('#cc-tabs .tab').forEach(function(t) {
      t.classList.toggle('active', t.dataset.tab === tabId);
    });
    var content = main.querySelector('#cc-tab-content');
    if (tabId === 'controls') renderControlsTab(content, fw, fwName, fwData, data);
    else if (tabId === 'gap') renderGapTab(content, fw, fwName, fwData);
    else if (tabId === 'mapping') renderMappingTab(content, fw, fwName);
    else if (tabId === 'export') renderExportTab(content, fw, fwName, fwData);
  }

  main.querySelector('#cc-tabs').onclick = function(e) {
    var btn = e.target.closest('.tab');
    if (btn) switchTab(btn.dataset.tab);
  };

  switchTab('controls');
}

function renderControlsTab(container, fw, fwName, fwData, allData) {
  var cats = fw.categories;
  var filterHtml = '<div class="cc-filter">' +
    '<select id="cc-cat-filter" style="margin-right:8px"><option value="all">All Categories</option>';
  for (var i = 0; i < cats.length; i++) {
    filterHtml += '<option value="' + esc(cats[i]) + '">' + esc(cats[i]) + '</option>';
  }
  filterHtml += '</select>' +
    '<select id="cc-status-filter"><option value="all">All Statuses</option>';
  for (var s = 0; s < STATUSES.length; s++) {
    filterHtml += '<option value="' + esc(STATUSES[s]) + '">' + esc(STATUSES[s]) + '</option>';
  }
  filterHtml += '</select></div>';

  var controlsHtml = '';
  for (var j = 0; j < fw.controls.length; j++) {
    var ctrl = fw.controls[j];
    var cd = fwData[ctrl.id] || {};
    var status = cd.status || "Not Started";
    var priority = cd.priority || ctrl.priority;
    var notes = cd.notes || "";
    var responsible = cd.responsible || "";
    var targetDate = cd.targetDate || "";
    var sc = STATUS_COLORS[status] || "#6b7280";

    controlsHtml += '<div class="cc-ctrl" data-cat="' + esc(ctrl.category) + '" data-status="' + esc(status) + '">' +
      '<div class="cc-ctrl-header">' +
        '<span class="cc-ctrl-id">' + esc(ctrl.id) + '</span>' +
        '<span class="cc-ctrl-title">' + esc(ctrl.title) + '</span>' +
        '<span class="cc-status-badge" style="background:' + sc + '">' + esc(status) + '</span>' +
      '</div>' +
      '<div class="cc-ctrl-desc">' + esc(ctrl.desc) + '</div>' +
      '<div class="cc-ctrl-evidence"><strong>Evidence needed:</strong> ' + esc(ctrl.evidence) + '</div>' +
      '<div class="cc-ctrl-fields">' +
        '<label>Status: <select class="cc-field" data-ctrl="' + esc(ctrl.id) + '" data-field="status">';
    for (var si = 0; si < STATUSES.length; si++) {
      controlsHtml += '<option' + (STATUSES[si] === status ? ' selected' : '') + '>' + esc(STATUSES[si]) + '</option>';
    }
    controlsHtml += '</select></label>' +
        '<label>Priority: <select class="cc-field" data-ctrl="' + esc(ctrl.id) + '" data-field="priority">';
    for (var pi = 0; pi < PRIORITIES.length; pi++) {
      controlsHtml += '<option' + (PRIORITIES[pi] === priority ? ' selected' : '') + '>' + esc(PRIORITIES[pi]) + '</option>';
    }
    controlsHtml += '</select></label>' +
        '<label>Responsible: <input class="cc-field cc-text-field" data-ctrl="' + esc(ctrl.id) + '" data-field="responsible" value="' + esc(responsible) + '" placeholder="Assignee"></label>' +
        '<label>Target: <input type="date" class="cc-field cc-text-field" data-ctrl="' + esc(ctrl.id) + '" data-field="targetDate" value="' + esc(targetDate) + '"></label>' +
      '</div>' +
      '<div class="cc-ctrl-notes">' +
        '<textarea class="cc-field cc-notes-field" data-ctrl="' + esc(ctrl.id) + '" data-field="notes" placeholder="Evidence notes, links, findings..." rows="2">' + esc(notes) + '</textarea>' +
      '</div>' +
    '</div>';
  }

  container.innerHTML = filterHtml + '<div id="cc-controls">' + controlsHtml + '</div>';

  // Filter logic
  function applyFilter() {
    var catVal = container.querySelector('#cc-cat-filter').value;
    var statusVal = container.querySelector('#cc-status-filter').value;
    container.querySelectorAll('.cc-ctrl').forEach(function(el) {
      var catMatch = catVal === 'all' || el.dataset.cat === catVal;
      var statusMatch = statusVal === 'all' || el.dataset.status === statusVal;
      el.style.display = (catMatch && statusMatch) ? '' : 'none';
    });
  }
  container.querySelector('#cc-cat-filter').onchange = applyFilter;
  container.querySelector('#cc-status-filter').onchange = applyFilter;

  // Save on change
  container.querySelectorAll('.cc-field').forEach(function(field) {
    var evtName = field.tagName === 'SELECT' ? 'change' : 'input';
    field.addEventListener(evtName, function() {
      var ctrlId = field.dataset.ctrl;
      var fieldName = field.dataset.field;
      if (!allData[fwName]) allData[fwName] = {};
      if (!allData[fwName][ctrlId]) allData[fwName][ctrlId] = {};
      allData[fwName][ctrlId][fieldName] = field.value;
      saveData(allData);
      // Update badge color if status changed
      if (fieldName === 'status') {
        var ctrlEl = field.closest('.cc-ctrl');
        if (ctrlEl) {
          ctrlEl.dataset.status = field.value;
          var badge = ctrlEl.querySelector('.cc-status-badge');
          if (badge) {
            badge.textContent = field.value;
            badge.style.background = STATUS_COLORS[field.value] || "#6b7280";
          }
        }
      }
    });
  });
}

function renderGapTab(container, fw, fwName, fwData) {
  var total = fw.controls.length;
  var byStatus = {};
  var byPriority = {};
  var byCat = {};

  for (var s = 0; s < STATUSES.length; s++) byStatus[STATUSES[s]] = 0;
  for (var p = 0; p < PRIORITIES.length; p++) byPriority[PRIORITIES[p]] = 0;
  for (var c = 0; c < fw.categories.length; c++) byCat[fw.categories[c]] = { total: 0, implemented: 0 };

  for (var i = 0; i < fw.controls.length; i++) {
    var ctrl = fw.controls[i];
    var cd = fwData[ctrl.id] || {};
    var status = cd.status || "Not Started";
    var priority = cd.priority || ctrl.priority;
    byStatus[status] = (byStatus[status] || 0) + 1;
    byPriority[priority] = (byPriority[priority] || 0) + 1;
    if (!byCat[ctrl.category]) byCat[ctrl.category] = { total: 0, implemented: 0 };
    byCat[ctrl.category].total++;
    if (status === "Implemented") byCat[ctrl.category].implemented++;
  }

  var implemented = byStatus["Implemented"] || 0;
  var score = total > 0 ? Math.round((implemented / total) * 100) : 0;
  var scoreColor = score >= 80 ? "#22c55e" : score >= 50 ? "#f59e0b" : "#ef4444";

  var html = '<div class="cc-gap-header">' +
    '<div class="cc-score-card">' +
      '<div class="cc-score-num" style="color:' + scoreColor + '">' + score + '</div>' +
      '<div class="cc-score-label">Audit Readiness Score</div>' +
      '<div class="cc-score-sub">' + implemented + ' of ' + total + ' controls implemented</div>' +
    '</div>' +
  '</div>' +
  '<h3 style="margin:16px 0 8px">Status Breakdown</h3>' +
  '<div class="cc-gap-grid">';

  for (var status in byStatus) {
    var cnt = byStatus[status];
    var pct = total > 0 ? Math.round((cnt / total) * 100) : 0;
    html += '<div class="cc-gap-item">' +
      '<div class="cc-gap-label"><span class="cc-dot" style="background:' + (STATUS_COLORS[status] || "#6b7280") + '"></span>' + esc(status) + '</div>' +
      '<div class="cc-gap-val">' + cnt + ' (' + pct + '%)</div>' +
    '</div>';
  }
  html += '</div>';

  html += '<h3 style="margin:16px 0 8px">Category Coverage</h3><div class="cc-gap-grid">';
  var catNames = Object.keys(byCat);
  for (var ci = 0; ci < catNames.length; ci++) {
    var cat = byCat[catNames[ci]];
    var cpct = cat.total > 0 ? Math.round((cat.implemented / cat.total) * 100) : 0;
    var cColor = cpct >= 80 ? "#22c55e" : cpct >= 50 ? "#f59e0b" : "#ef4444";
    html += '<div class="cc-gap-item">' +
      '<div class="cc-gap-label">' + esc(catNames[ci]) + '</div>' +
      '<div class="cc-gap-val" style="color:' + cColor + '">' + cat.implemented + '/' + cat.total + ' (' + cpct + '%)</div>' +
    '</div>';
  }
  html += '</div>';

  html += '<h3 style="margin:16px 0 8px">Priority Breakdown</h3><div class="cc-gap-grid">';
  var prioColors = { "Critical": "#ef4444", "High": "#f59e0b", "Medium": "#3b82f6", "Low": "#6b7280" };
  for (var pri in byPriority) {
    html += '<div class="cc-gap-item">' +
      '<div class="cc-gap-label"><span class="cc-dot" style="background:' + (prioColors[pri] || "#6b7280") + '"></span>' + esc(pri) + '</div>' +
      '<div class="cc-gap-val">' + byPriority[pri] + '</div>' +
    '</div>';
  }
  html += '</div>';

  // Critical gaps
  html += '<h3 style="margin:16px 0 8px">Critical Gaps (unimplemented critical controls)</h3><div class="cc-critical-gaps">';
  var hasCritGaps = false;
  for (var gi = 0; gi < fw.controls.length; gi++) {
    var gctrl = fw.controls[gi];
    var gcd = fwData[gctrl.id] || {};
    var gstatus = gcd.status || "Not Started";
    var gpriority = gcd.priority || gctrl.priority;
    if (gpriority === "Critical" && gstatus !== "Implemented" && gstatus !== "Not Applicable") {
      hasCritGaps = true;
      html += '<div class="cc-crit-gap">' +
        '<span class="cc-ctrl-id">' + esc(gctrl.id) + '</span> ' + esc(gctrl.title) +
        ' <span class="cc-status-badge" style="background:' + (STATUS_COLORS[gstatus] || "#6b7280") + ';font-size:.65rem">' + esc(gstatus) + '</span>' +
      '</div>';
    }
  }
  if (!hasCritGaps) html += '<div style="color:var(--mut)">No critical gaps -- all critical controls are implemented or N/A.</div>';
  html += '</div>';

  container.innerHTML = html;
}

function renderMappingTab(container, fw, fwName) {
  var html = '<h3 style="margin:0 0 12px">Cross-Framework Mapping</h3>' +
    '<p class="muted" style="margin-bottom:12px">Shows how ' + esc(fwName) + ' controls map to other frameworks. Use this to identify overlapping compliance efforts.</p>' +
    '<div class="cc-mapping-table-wrap"><table class="cc-mapping-table">' +
    '<tr><th>' + esc(fwName) + ' Control</th><th>Title</th>';

  // Collect all mapped framework names
  var mappedFws = {};
  for (var i = 0; i < fw.controls.length; i++) {
    if (fw.controls[i].mapping) {
      var keys = Object.keys(fw.controls[i].mapping);
      for (var k = 0; k < keys.length; k++) mappedFws[keys[k]] = true;
    }
  }
  var mfwList = Object.keys(mappedFws);
  for (var mi = 0; mi < mfwList.length; mi++) {
    html += '<th>' + esc(mfwList[mi]) + '</th>';
  }
  html += '</tr>';

  for (var j = 0; j < fw.controls.length; j++) {
    var ctrl = fw.controls[j];
    html += '<tr><td>' + esc(ctrl.id) + '</td><td>' + esc(ctrl.title) + '</td>';
    for (var mj = 0; mj < mfwList.length; mj++) {
      var mapped = (ctrl.mapping && ctrl.mapping[mfwList[mj]]) || "--";
      html += '<td>' + esc(mapped) + '</td>';
    }
    html += '</tr>';
  }
  html += '</table></div>';
  container.innerHTML = html;
}

function renderExportTab(container, fw, fwName, fwData) {
  var total = fw.controls.length;
  var implemented = 0;
  for (var i = 0; i < fw.controls.length; i++) {
    if ((fwData[fw.controls[i].id] || {}).status === "Implemented") implemented++;
  }
  var score = total > 0 ? Math.round((implemented / total) * 100) : 0;

  var report = "COMPLIANCE ASSESSMENT REPORT\n";
  report += "============================\n\n";
  report += "Framework: " + fwName + "\n";
  report += "Date: " + new Date().toISOString().split('T')[0] + "\n";
  report += "Audit Readiness Score: " + score + "%\n";
  report += "Controls Assessed: " + total + "\n";
  report += "Controls Implemented: " + implemented + "\n\n";
  report += "CONTROL DETAILS\n";
  report += "---------------\n\n";

  for (var j = 0; j < fw.controls.length; j++) {
    var ctrl = fw.controls[j];
    var cd = fwData[ctrl.id] || {};
    report += ctrl.id + " - " + ctrl.title + "\n";
    report += "  Status: " + (cd.status || "Not Started") + "\n";
    report += "  Priority: " + (cd.priority || ctrl.priority) + "\n";
    report += "  Category: " + ctrl.category + "\n";
    if (cd.responsible) report += "  Responsible: " + cd.responsible + "\n";
    if (cd.targetDate) report += "  Target Date: " + cd.targetDate + "\n";
    report += "  Description: " + ctrl.desc + "\n";
    report += "  Evidence: " + ctrl.evidence + "\n";
    if (cd.notes) report += "  Notes: " + cd.notes + "\n";
    report += "\n";
  }

  container.innerHTML = '<h3 style="margin:0 0 12px">Export Assessment Report</h3>' +
    '<p class="muted" style="margin-bottom:12px">Copy the report below or use the button to copy to clipboard.</p>' +
    '<button class="btn sm" id="cc-copy-report">Copy to Clipboard</button>' +
    '<textarea class="tk-in" id="cc-report-text" rows="20" readonly style="margin-top:8px">' + esc(report) + '</textarea>';

  container.querySelector('#cc-copy-report').onclick = function() {
    var text = container.querySelector('#cc-report-text').value;
    navigator.clipboard.writeText(text).then(function() {
      container.querySelector('#cc-copy-report').textContent = 'Copied';
      setTimeout(function() { container.querySelector('#cc-copy-report').textContent = 'Copy to Clipboard'; }, 2000);
    });
  };
}

// ---- STYLES ----

var STYLE = '<style>' +
  '.cc-fw-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin-top:16px}' +
  '.cc-fw-card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;cursor:pointer;transition:border-color .15s}' +
  '.cc-fw-card:hover{border-color:var(--acc)}' +
  '.cc-fw-name{font-weight:600;font-size:1rem;margin-bottom:4px}' +
  '.cc-fw-desc{font-size:.75rem;color:var(--mut);margin-bottom:10px;line-height:1.4}' +
  '.cc-fw-stats{display:flex;justify-content:space-between;font-size:.72rem;color:var(--mut);margin-bottom:6px}' +
  '.cc-bar-bg{height:4px;background:var(--line);border-radius:2px;overflow:hidden}' +
  '.cc-bar-fill{height:100%;border-radius:2px;transition:width .3s}' +
  '.cc-tabs{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px}' +
  '.cc-filter{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}' +
  '.cc-filter select{background:var(--card);border:1px solid var(--line);color:var(--txt);padding:6px 10px;border-radius:6px;font-size:.78rem;font-family:inherit}' +
  '.cc-ctrl{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;margin-bottom:8px}' +
  '.cc-ctrl-header{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}' +
  '.cc-ctrl-id{font-family:var(--mono);font-size:.75rem;font-weight:600;color:var(--acc);background:var(--acc-soft,rgba(0,212,255,.1));padding:2px 8px;border-radius:4px}' +
  '.cc-ctrl-title{font-weight:600;font-size:.88rem}' +
  '.cc-status-badge{font-size:.68rem;padding:2px 8px;border-radius:4px;color:#fff;font-weight:500}' +
  '.cc-ctrl-desc{font-size:.8rem;color:var(--mut);margin-bottom:6px;line-height:1.4}' +
  '.cc-ctrl-evidence{font-size:.75rem;color:var(--mut);margin-bottom:8px;padding:6px 10px;background:var(--card2,#111);border-radius:4px}' +
  '.cc-ctrl-fields{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:6px;font-size:.78rem}' +
  '.cc-ctrl-fields label{display:flex;align-items:center;gap:4px;color:var(--mut)}' +
  '.cc-ctrl-fields select{background:var(--card);border:1px solid var(--line);color:var(--txt);padding:3px 6px;border-radius:4px;font-size:.75rem;font-family:inherit}' +
  '.cc-text-field{background:var(--card);border:1px solid var(--line);color:var(--txt);padding:3px 6px;border-radius:4px;font-size:.75rem;font-family:inherit;width:120px}' +
  '.cc-notes-field{width:100%;background:var(--card2,#111);border:1px solid var(--line);color:var(--txt);padding:6px 8px;border-radius:4px;font-size:.75rem;font-family:inherit;resize:vertical}' +
  '.cc-gap-header{display:flex;justify-content:center;margin:16px 0}' +
  '.cc-score-card{text-align:center;padding:20px 40px;background:var(--card);border:1px solid var(--line);border-radius:12px}' +
  '.cc-score-num{font-size:3rem;font-weight:700;line-height:1}' +
  '.cc-score-label{font-size:.85rem;color:var(--mut);margin-top:4px}' +
  '.cc-score-sub{font-size:.72rem;color:var(--mut);margin-top:2px}' +
  '.cc-gap-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;margin-bottom:12px}' +
  '.cc-gap-item{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:var(--card);border:1px solid var(--line);border-radius:6px;font-size:.8rem}' +
  '.cc-gap-label{display:flex;align-items:center;gap:6px}' +
  '.cc-dot{width:8px;height:8px;border-radius:50%;display:inline-block}' +
  '.cc-gap-val{font-weight:600}' +
  '.cc-crit-gap{padding:6px 10px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:4px;margin-bottom:4px;font-size:.8rem}' +
  '.cc-mapping-table-wrap{overflow-x:auto}' +
  '.cc-mapping-table{width:100%;border-collapse:collapse;font-size:.75rem}' +
  '.cc-mapping-table th,.cc-mapping-table td{padding:6px 8px;border:1px solid var(--line);text-align:left}' +
  '.cc-mapping-table th{background:var(--card);font-weight:600;position:sticky;top:0}' +
  '.cc-mapping-table tr:nth-child(even){background:var(--card)}' +
'</style>';

export function renderComplianceChecker(main) {
  var data = loadData();
  main.innerHTML = STYLE;
  var content = document.createElement('div');
  main.appendChild(content);
  renderFrameworkSelector(content, data);
}
