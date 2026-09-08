/**
 * compliance.js -- Security Frameworks, Compliance Checklists, Risk Matrices, and Policy Templates
 * Comprehensive reference for security compliance and governance
 * Generated for darknode-web
 */

// =============================================================================
// 1. FRAMEWORKS -- Major Security Frameworks
// =============================================================================

const FRAMEWORKS = [
  // =========================================================================
  // (a) NIST Cybersecurity Framework (CSF) 2.0
  // =========================================================================
  {
    name: "NIST Cybersecurity Framework",
    org: "National Institute of Standards and Technology (NIST)",
    version: "2.0",
    description:
      "A voluntary framework consisting of standards, guidelines, and best practices to manage cybersecurity risk. Widely adopted across industries, it provides a common language for understanding, managing, and expressing cybersecurity risk to internal and external stakeholders.",
    domains: [
      {
        name: "GOVERN (GV)",
        description:
          "Establish and monitor the organization's cybersecurity risk management strategy, expectations, and policy.",
        controls: [
          {
            id: "GV.OC-01",
            title: "Organizational Context",
            description:
              "The organizational mission is understood and informs cybersecurity risk management.",
            implementation:
              "Document business objectives, critical services, and stakeholder expectations. Map cybersecurity requirements to mission priorities.",
            evidence:
              "Mission statement, business impact analysis, stakeholder register, cybersecurity strategy document.",
          },
          {
            id: "GV.OC-02",
            title: "Internal Stakeholders",
            description:
              "Internal stakeholders understand and are aligned with the cybersecurity risk management strategy.",
            implementation:
              "Conduct awareness training, publish internal communications on cybersecurity posture, establish cross-functional cybersecurity committees.",
            evidence:
              "Training records, meeting minutes, internal memos, role-based responsibility matrices.",
          },
          {
            id: "GV.OC-03",
            title: "Legal and Regulatory Requirements",
            description:
              "Legal, regulatory, and contractual requirements regarding cybersecurity are understood and managed.",
            implementation:
              "Maintain a register of applicable laws, regulations, and contractual obligations. Conduct periodic compliance reviews.",
            evidence:
              "Compliance register, legal review reports, contractual obligation tracker.",
          },
          {
            id: "GV.OC-04",
            title: "Critical Objectives",
            description:
              "Critical objectives, capabilities, and services that stakeholders depend on are understood and communicated.",
            implementation:
              "Perform business impact analysis, identify critical business processes, establish recovery priorities.",
            evidence:
              "BIA report, critical services catalog, recovery priority documentation.",
          },
          {
            id: "GV.OC-05",
            title: "Outcomes and Priorities",
            description:
              "Outcomes, capabilities, and services that the organization depends on are understood and prioritized.",
            implementation:
              "Rank business services by criticality, map dependencies, establish minimum viable service levels.",
            evidence:
              "Service dependency maps, priority matrices, minimum service level agreements.",
          },
          {
            id: "GV.RM-01",
            title: "Risk Management Strategy",
            description:
              "Risk management objectives are established and agreed upon by organizational stakeholders.",
            implementation:
              "Develop risk management strategy aligned to business objectives. Define risk appetite and tolerance levels.",
            evidence:
              "Risk management strategy document, risk appetite statement, board approval records.",
          },
          {
            id: "GV.RM-02",
            title: "Risk Appetite",
            description:
              "Risk appetite and risk tolerance statements are established, communicated, and maintained.",
            implementation:
              "Define quantitative and qualitative risk thresholds. Communicate to all decision-makers.",
            evidence:
              "Risk appetite statement, risk tolerance thresholds, communication records.",
          },
          {
            id: "GV.RM-03",
            title: "Risk Management Activities",
            description:
              "Cybersecurity risk management activities and outcomes are included in enterprise risk management processes.",
            implementation:
              "Integrate cybersecurity risk into ERM framework. Report cyber risks alongside operational, financial, and strategic risks.",
            evidence:
              "ERM reports including cyber risks, integrated risk registers, board risk reports.",
          },
          {
            id: "GV.RM-04",
            title: "Strategic Direction",
            description:
              "Strategic direction that describes appropriate risk response options is established and communicated.",
            implementation:
              "Define risk response strategies (accept, mitigate, transfer, avoid) with criteria for each.",
            evidence:
              "Risk response procedures, decision trees, escalation policies.",
          },
          {
            id: "GV.RR-01",
            title: "Roles and Responsibilities",
            description:
              "Organizational leadership defines and approves roles, responsibilities, and authorities related to cybersecurity risk.",
            implementation:
              "Document RACI matrices for cybersecurity activities. Appoint CISO and security team leads.",
            evidence:
              "RACI matrix, organizational chart, role descriptions, appointment letters.",
          },
          {
            id: "GV.RR-02",
            title: "Accountability",
            description:
              "Roles, responsibilities, and authorities related to cybersecurity risk are established, communicated, and enforced.",
            implementation:
              "Include cybersecurity responsibilities in job descriptions. Implement accountability mechanisms.",
            evidence:
              "Job descriptions, performance objectives, accountability framework documentation.",
          },
          {
            id: "GV.RR-03",
            title: "Adequate Resources",
            description:
              "Adequate resources are allocated commensurate with the cybersecurity risk strategy, roles, responsibilities, and policies.",
            implementation:
              "Budget for cybersecurity personnel, tools, and training. Review resource adequacy annually.",
            evidence:
              "Cybersecurity budget, staffing plans, resource allocation reports.",
          },
          {
            id: "GV.RR-04",
            title: "Cybersecurity in HR",
            description:
              "Cybersecurity is included in human resources practices.",
            implementation:
              "Include security requirements in hiring, onboarding, role transitions, and offboarding processes.",
            evidence:
              "HR procedures, background check policies, onboarding checklists, exit procedures.",
          },
          {
            id: "GV.PO-01",
            title: "Cybersecurity Policy",
            description:
              "A policy for managing cybersecurity risks is established based on organizational context, strategy, and priorities.",
            implementation:
              "Develop comprehensive cybersecurity policy. Review and update annually.",
            evidence:
              "Cybersecurity policy document, revision history, approval records.",
          },
          {
            id: "GV.PO-02",
            title: "Policy Review",
            description:
              "Cybersecurity policy is reviewed, updated, communicated, and enforced.",
            implementation:
              "Establish policy review cycle. Communicate updates to all stakeholders. Enforce through technical and administrative controls.",
            evidence:
              "Policy review schedule, communication logs, enforcement records.",
          },
          {
            id: "GV.SC-01",
            title: "Supply Chain Risk Management",
            description:
              "A cybersecurity supply chain risk management program is established.",
            implementation:
              "Develop supply chain risk management policy. Assess supplier cybersecurity posture. Include security requirements in contracts.",
            evidence:
              "Supply chain risk management policy, supplier assessments, contract security clauses.",
          },
          {
            id: "GV.SC-02",
            title: "Supplier Assessment",
            description:
              "Cybersecurity roles and responsibilities for suppliers, customers, and partners are established and coordinated.",
            implementation:
              "Define security responsibilities in contracts and SLAs. Conduct regular supplier security assessments.",
            evidence:
              "Supplier responsibility matrices, SLAs with security requirements, assessment reports.",
          },
        ],
      },
      {
        name: "IDENTIFY (ID)",
        description:
          "Help determine the current cybersecurity risk to the organization. Understanding assets, threats, vulnerabilities, and risk.",
        controls: [
          {
            id: "ID.AM-01",
            title: "Hardware Asset Inventory",
            description:
              "Inventories of hardware managed by the organization are maintained.",
            implementation:
              "Deploy automated asset discovery tools. Maintain a CMDB with hardware inventory. Conduct quarterly reconciliation.",
            evidence:
              "Asset inventory reports, CMDB records, discovery scan logs, reconciliation reports.",
          },
          {
            id: "ID.AM-02",
            title: "Software Asset Inventory",
            description:
              "Inventories of software, services, and systems managed by the organization are maintained.",
            implementation:
              "Deploy software asset management tools. Track all installed software, SaaS subscriptions, and custom applications.",
            evidence:
              "Software inventory, SaaS catalog, license management records.",
          },
          {
            id: "ID.AM-03",
            title: "Data Flow Mapping",
            description:
              "Representations of the organization's authorized network communication and internal and external data flows are maintained.",
            implementation:
              "Create and maintain network diagrams, data flow diagrams, and system interconnection documentation.",
            evidence:
              "Network diagrams, data flow diagrams, system interconnection maps.",
          },
          {
            id: "ID.AM-04",
            title: "External Systems Catalog",
            description:
              "Inventories of services provided by suppliers are maintained.",
            implementation:
              "Catalog all external service providers, cloud services, and third-party integrations.",
            evidence:
              "Supplier catalog, cloud services inventory, integration documentation.",
          },
          {
            id: "ID.AM-05",
            title: "Asset Prioritization",
            description:
              "Assets are prioritized based on classification, criticality, and business value.",
            implementation:
              "Classify assets by data sensitivity and business criticality. Apply tiered protection based on classification.",
            evidence:
              "Asset classification records, criticality ratings, protection tier assignments.",
          },
          {
            id: "ID.AM-07",
            title: "Asset Lifecycle",
            description:
              "Inventories of data and corresponding metadata for designated data types are maintained.",
            implementation:
              "Create data inventories. Classify data by type and sensitivity. Track data lifecycle from creation to disposal.",
            evidence:
              "Data inventory, classification labels, retention schedules, disposal records.",
          },
          {
            id: "ID.AM-08",
            title: "System Hardening",
            description:
              "Systems, hardware, software, and services are managed consistent with the organization's risk strategy.",
            implementation:
              "Apply hardening baselines to all systems. Disable unnecessary services. Enforce least functionality principle.",
            evidence:
              "Hardening checklists, configuration baselines, system audit reports.",
          },
          {
            id: "ID.RA-01",
            title: "Vulnerability Identification",
            description:
              "Vulnerabilities in assets are identified, validated, and recorded.",
            implementation:
              "Conduct regular vulnerability scanning and penetration testing. Subscribe to vulnerability intelligence feeds.",
            evidence:
              "Vulnerability scan reports, penetration test reports, vulnerability database subscriptions.",
          },
          {
            id: "ID.RA-02",
            title: "Threat Intelligence",
            description:
              "Cyber threat intelligence is received from information sharing forums and sources.",
            implementation:
              "Subscribe to threat intelligence feeds (ISACs, CERTs, commercial feeds). Participate in information sharing communities.",
            evidence:
              "Threat intelligence subscriptions, ISAC membership, threat briefing records.",
          },
          {
            id: "ID.RA-03",
            title: "Threat Identification",
            description:
              "Internal and external threats to the organization are identified and recorded.",
            implementation:
              "Conduct threat modeling exercises. Maintain a threat register. Assess both internal and external threat actors.",
            evidence:
              "Threat models, threat register, threat assessment reports.",
          },
          {
            id: "ID.RA-04",
            title: "Impact Analysis",
            description:
              "Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded.",
            implementation:
              "Perform risk assessments mapping threats to vulnerabilities. Estimate impact and likelihood using standardized scales.",
            evidence:
              "Risk assessment reports, impact-likelihood matrices, risk register.",
          },
          {
            id: "ID.RA-05",
            title: "Risk Determination",
            description:
              "Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response priorities.",
            implementation:
              "Calculate risk scores. Prioritize risks based on organizational risk appetite. Develop risk treatment plans.",
            evidence:
              "Risk register with scores, risk treatment plans, residual risk assessments.",
          },
          {
            id: "ID.RA-06",
            title: "Risk Response",
            description:
              "Risk responses are chosen, prioritized, planned, tracked, and communicated.",
            implementation:
              "Select appropriate risk treatment (accept, mitigate, transfer, avoid). Track remediation to completion.",
            evidence:
              "Risk treatment plans, remediation trackers, risk acceptance records.",
          },
          {
            id: "ID.RA-07",
            title: "Risk Change Tracking",
            description:
              "Changes and exceptions are managed, assessed for risk impact, recorded, and tracked.",
            implementation:
              "Implement change management process with security impact assessment. Track exceptions with expiration dates.",
            evidence:
              "Change requests, security impact assessments, exception logs.",
          },
          {
            id: "ID.RA-08",
            title: "Vulnerability Disclosure",
            description:
              "Processes for receiving, analyzing, and responding to vulnerability disclosures are established.",
            implementation:
              "Publish vulnerability disclosure policy. Establish intake process for reported vulnerabilities.",
            evidence:
              "VDP policy, disclosure intake records, response timelines.",
          },
          {
            id: "ID.RA-09",
            title: "Attack Surface Analysis",
            description:
              "The authenticity and integrity of hardware and software are assessed prior to acquisition and use.",
            implementation:
              "Verify software integrity through checksums and digital signatures. Assess hardware provenance.",
            evidence:
              "Integrity verification logs, provenance documentation, pre-acquisition assessments.",
          },
          {
            id: "ID.RA-10",
            title: "Critical Supplier Assessment",
            description:
              "Critical suppliers are assessed prior to acquisition.",
            implementation:
              "Conduct due diligence on critical suppliers including security assessments, financial stability, and compliance status.",
            evidence:
              "Supplier assessment reports, due diligence records, risk ratings.",
          },
          {
            id: "ID.IM-01",
            title: "Improvement from Assessments",
            description:
              "Improvements are identified from evaluations.",
            implementation:
              "Review findings from assessments, audits, and exercises. Create improvement action plans.",
            evidence:
              "Assessment findings, improvement plans, corrective action tracking.",
          },
          {
            id: "ID.IM-02",
            title: "Improvement from Operations",
            description:
              "Improvements are identified from security tests and exercises including those done in coordination with suppliers and partners.",
            implementation:
              "Conduct tabletop exercises, red team engagements, and after-action reviews. Document lessons learned.",
            evidence:
              "Exercise reports, after-action reviews, lessons learned documentation.",
          },
          {
            id: "ID.IM-03",
            title: "Improvement Execution",
            description:
              "Improvements are identified from execution of operational processes, procedures, and activities.",
            implementation:
              "Analyze operational metrics and incident trends. Identify process improvements and efficiency gains.",
            evidence:
              "Operational metrics, trend analysis, process improvement proposals.",
          },
        ],
      },
      {
        name: "PROTECT (PR)",
        description:
          "Use safeguards to prevent or reduce cybersecurity risk. Implement controls to ensure delivery of critical services.",
        controls: [
          {
            id: "PR.AA-01",
            title: "Identity Management",
            description:
              "Identities and credentials for authorized users, services, and hardware are managed by the organization.",
            implementation:
              "Implement centralized identity management (IAM). Enforce unique identifiers. Manage service accounts and certificates.",
            evidence:
              "IAM system records, identity lifecycle documentation, credential management procedures.",
          },
          {
            id: "PR.AA-02",
            title: "Identity Verification",
            description:
              "Identities are proofed and bound to credentials based on the context of interactions.",
            implementation:
              "Implement identity proofing for onboarding. Bind credentials to verified identities. Use strong authentication methods.",
            evidence:
              "Identity proofing procedures, credential binding records, authentication configuration.",
          },
          {
            id: "PR.AA-03",
            title: "Multi-Factor Authentication",
            description:
              "Users, services, and hardware are authenticated.",
            implementation:
              "Deploy MFA for all user access. Implement certificate-based authentication for services. Use 802.1X for hardware.",
            evidence:
              "MFA enrollment records, authentication logs, certificate inventory.",
          },
          {
            id: "PR.AA-04",
            title: "Identity Assertions",
            description:
              "Identity assertions are protected, conveyed, and verified.",
            implementation:
              "Use secure protocols for identity federation (SAML, OIDC). Validate identity tokens. Protect assertion integrity.",
            evidence:
              "Federation configuration, token validation logs, protocol security settings.",
          },
          {
            id: "PR.AA-05",
            title: "Access Permissions",
            description:
              "Access permissions, entitlements, and authorizations are defined and managed in accordance with least privilege and separation of duties.",
            implementation:
              "Implement RBAC or ABAC. Enforce least privilege. Conduct quarterly access reviews. Separate incompatible duties.",
            evidence:
              "Access control policies, role definitions, access review reports, SoD matrices.",
          },
          {
            id: "PR.AA-06",
            title: "Physical Access",
            description:
              "Physical access to assets is managed, monitored, and enforced.",
            implementation:
              "Implement badge access systems. Monitor physical entry points. Escort visitors. Secure server rooms.",
            evidence:
              "Physical access logs, badge system records, visitor logs, CCTV recordings.",
          },
          {
            id: "PR.AT-01",
            title: "Security Awareness Training",
            description:
              "Personnel are provided cybersecurity awareness and training.",
            implementation:
              "Conduct annual security awareness training. Deliver role-based training. Run phishing simulations.",
            evidence:
              "Training completion records, phishing simulation results, training content materials.",
          },
          {
            id: "PR.AT-02",
            title: "Privileged User Training",
            description:
              "Individuals in specialized roles are provided with awareness and training.",
            implementation:
              "Provide advanced training for administrators, developers, and incident responders. Conduct hands-on exercises.",
            evidence:
              "Specialized training records, certification records, exercise participation logs.",
          },
          {
            id: "PR.DS-01",
            title: "Data-at-Rest Protection",
            description:
              "The confidentiality, integrity, and availability of data-at-rest are protected.",
            implementation:
              "Encrypt sensitive data at rest using AES-256. Implement key management procedures. Apply data loss prevention controls.",
            evidence:
              "Encryption configuration, key management records, DLP policy documentation.",
          },
          {
            id: "PR.DS-02",
            title: "Data-in-Transit Protection",
            description:
              "The confidentiality, integrity, and availability of data-in-transit are protected.",
            implementation:
              "Enforce TLS 1.2+ for all communications. Implement certificate management. Use VPN for remote access.",
            evidence:
              "TLS configuration, certificate inventory, VPN configuration, network capture analysis.",
          },
          {
            id: "PR.DS-10",
            title: "Data-in-Use Protection",
            description:
              "The confidentiality, integrity, and availability of data-in-use are protected.",
            implementation:
              "Implement memory protection. Use secure enclaves where applicable. Enforce screen lock policies.",
            evidence:
              "Memory protection configuration, secure enclave deployment records, endpoint policy settings.",
          },
          {
            id: "PR.DS-11",
            title: "Data Backup",
            description:
              "Backups of data are created, protected, maintained, and tested.",
            implementation:
              "Implement 3-2-1 backup strategy. Encrypt backup data. Test restoration quarterly. Store offsite copies.",
            evidence:
              "Backup schedules, restoration test reports, offsite storage records.",
          },
          {
            id: "PR.PS-01",
            title: "Configuration Management",
            description:
              "Configuration management practices are established and applied.",
            implementation:
              "Establish configuration baselines. Implement configuration management database (CMDB). Track configuration changes.",
            evidence:
              "Configuration baselines, CMDB records, change logs.",
          },
          {
            id: "PR.PS-02",
            title: "Software Maintenance",
            description:
              "Software is maintained, replaced, and removed consistent with risk.",
            implementation:
              "Implement patch management process. Remove end-of-life software. Test patches before deployment.",
            evidence:
              "Patch management reports, software lifecycle records, patch testing results.",
          },
          {
            id: "PR.PS-03",
            title: "Hardware Maintenance",
            description:
              "Hardware is maintained, replaced, and removed consistent with risk.",
            implementation:
              "Implement hardware maintenance schedules. Sanitize hardware before disposal. Track hardware lifecycle.",
            evidence:
              "Maintenance schedules, disposal records, sanitization certificates.",
          },
          {
            id: "PR.PS-04",
            title: "Log Generation",
            description:
              "Log records are generated and made available for continuous monitoring.",
            implementation:
              "Enable logging on all systems. Centralize log collection. Define log retention policies.",
            evidence:
              "Logging configuration, SIEM deployment records, log retention policy.",
          },
          {
            id: "PR.PS-05",
            title: "Installation and Execution Controls",
            description:
              "Installation and execution of unauthorized software are prevented.",
            implementation:
              "Implement application whitelisting. Deploy endpoint protection. Restrict installation privileges.",
            evidence:
              "Whitelisting configuration, endpoint protection deployment records, privilege restriction settings.",
          },
          {
            id: "PR.PS-06",
            title: "Secure Development",
            description:
              "Secure software development practices are integrated and their performance is monitored.",
            implementation:
              "Implement SDLC with security gates. Conduct code reviews and SAST/DAST. Train developers on secure coding.",
            evidence:
              "SDLC documentation, code review records, SAST/DAST reports, developer training records.",
          },
          {
            id: "PR.IR-01",
            title: "Network Protection",
            description:
              "Networks and environments are protected from unauthorized logical access and usage.",
            implementation:
              "Implement network segmentation, firewalls, and IDS/IPS. Define and enforce network access policies.",
            evidence:
              "Network architecture diagrams, firewall rules, IDS/IPS configuration, network access policies.",
          },
          {
            id: "PR.IR-02",
            title: "Authorized Use Protection",
            description:
              "The organization's technology assets are protected from unauthorized use.",
            implementation:
              "Implement acceptable use policies. Deploy DRM and access controls. Monitor for unauthorized usage.",
            evidence:
              "Acceptable use policy, DRM configuration, monitoring alerts, usage reports.",
          },
          {
            id: "PR.IR-03",
            title: "Communication Protection",
            description:
              "Mechanisms are implemented to achieve resilience requirements in normal and adverse situations.",
            implementation:
              "Implement redundant communications. Deploy load balancing. Establish failover procedures.",
            evidence:
              "Redundancy configuration, load balancer settings, failover test results.",
          },
          {
            id: "PR.IR-04",
            title: "Resilience",
            description:
              "Adequate resource capacity to ensure availability is maintained.",
            implementation:
              "Implement capacity monitoring and planning. Deploy auto-scaling where applicable. Maintain capacity reserves.",
            evidence:
              "Capacity plans, monitoring dashboards, auto-scaling configuration.",
          },
        ],
      },
      {
        name: "DETECT (DE)",
        description:
          "Find and analyze possible cybersecurity attacks and compromises. Enable timely discovery of cybersecurity events.",
        controls: [
          {
            id: "DE.CM-01",
            title: "Network Monitoring",
            description:
              "Networks and network services are monitored to find potentially adverse events.",
            implementation:
              "Deploy network monitoring tools (IDS/IPS, NetFlow, packet capture). Establish baseline traffic patterns. Alert on anomalies.",
            evidence:
              "Network monitoring configuration, alert rules, baseline documentation, monitoring reports.",
          },
          {
            id: "DE.CM-02",
            title: "Physical Environment Monitoring",
            description:
              "The physical environment is monitored to find potentially adverse events.",
            implementation:
              "Install environmental monitors (temperature, humidity, water detection). Deploy CCTV and motion sensors.",
            evidence:
              "Environmental monitoring configuration, sensor inventory, CCTV footage retention.",
          },
          {
            id: "DE.CM-03",
            title: "Personnel Activity Monitoring",
            description:
              "Personnel activity and technology usage are monitored to find potentially adverse events.",
            implementation:
              "Implement UEBA tools. Monitor privileged user actions. Track data access patterns.",
            evidence:
              "UEBA deployment records, privileged access monitoring logs, data access reports.",
          },
          {
            id: "DE.CM-06",
            title: "External Service Provider Monitoring",
            description:
              "External service provider activities and services are monitored to find potentially adverse events.",
            implementation:
              "Monitor third-party service availability and security events. Review supplier security reports.",
            evidence:
              "Third-party monitoring dashboards, supplier security reports, SLA compliance reports.",
          },
          {
            id: "DE.CM-09",
            title: "Endpoint Monitoring",
            description:
              "Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events.",
            implementation:
              "Deploy EDR solutions. Monitor endpoint health and configuration compliance. Detect malware and anomalous behavior.",
            evidence:
              "EDR deployment records, endpoint compliance reports, malware detection logs.",
          },
          {
            id: "DE.AE-02",
            title: "Event Analysis",
            description:
              "Potentially adverse events are analyzed to better understand associated activities.",
            implementation:
              "Implement SIEM correlation rules. Conduct event triage and investigation. Enrich events with threat intelligence.",
            evidence:
              "SIEM correlation rules, investigation playbooks, enriched event records.",
          },
          {
            id: "DE.AE-03",
            title: "Event Correlation",
            description:
              "Information is correlated from multiple sources.",
            implementation:
              "Aggregate logs from multiple sources in SIEM. Cross-correlate events across security tools. Apply detection analytics.",
            evidence:
              "SIEM data source inventory, correlation rule documentation, cross-tool integration records.",
          },
          {
            id: "DE.AE-04",
            title: "Impact Estimation",
            description:
              "The estimated impact and scope of adverse events are understood.",
            implementation:
              "Classify events by severity. Estimate blast radius. Assess potential business impact during triage.",
            evidence:
              "Severity classification procedures, impact assessment templates, triage documentation.",
          },
          {
            id: "DE.AE-06",
            title: "Incident Declaration",
            description:
              "Information on adverse events is provided to authorized staff and tools.",
            implementation:
              "Define incident declaration criteria. Implement automated alerting and notification workflows.",
            evidence:
              "Incident declaration criteria, notification workflows, escalation procedures.",
          },
          {
            id: "DE.AE-07",
            title: "Threat Intelligence Integration",
            description:
              "Cyber threat intelligence and other contextual information are integrated into the analysis.",
            implementation:
              "Feed threat intelligence into SIEM and detection tools. Use IOCs for proactive threat hunting.",
            evidence:
              "Threat intelligence feed integration, IOC matching records, threat hunting reports.",
          },
          {
            id: "DE.AE-08",
            title: "False Positive Reduction",
            description:
              "Incidents are declared when adverse events meet defined criteria.",
            implementation:
              "Tune detection rules to reduce false positives. Validate alerts before escalation. Track false positive rates.",
            evidence:
              "Alert tuning records, false positive rate metrics, validation procedures.",
          },
        ],
      },
      {
        name: "RESPOND (RS)",
        description:
          "Take action regarding a detected cybersecurity incident. Support the ability to contain the impact of incidents.",
        controls: [
          {
            id: "RS.MA-01",
            title: "Incident Management",
            description:
              "The incident response plan is executed in coordination with relevant third parties.",
            implementation:
              "Activate incident response plan. Coordinate with ISACs, law enforcement, and third-party responders as needed.",
            evidence:
              "Incident response plan, activation records, third-party communication logs.",
          },
          {
            id: "RS.MA-02",
            title: "Incident Triage",
            description:
              "Incident reports are triaged and validated.",
            implementation:
              "Classify incidents by type and severity. Validate reported incidents. Assign incident handlers.",
            evidence:
              "Triage procedures, incident classification records, handler assignments.",
          },
          {
            id: "RS.MA-03",
            title: "Incident Categorization",
            description:
              "Incidents are categorized and prioritized.",
            implementation:
              "Apply incident taxonomy. Prioritize based on impact and urgency. Escalate critical incidents.",
            evidence:
              "Incident taxonomy, prioritization matrix, escalation records.",
          },
          {
            id: "RS.MA-04",
            title: "Incident Escalation",
            description:
              "Incidents are escalated or elevated as needed.",
            implementation:
              "Define escalation criteria and paths. Implement automated escalation for time-sensitive incidents.",
            evidence:
              "Escalation procedures, escalation history, notification logs.",
          },
          {
            id: "RS.MA-05",
            title: "Forensic Investigation",
            description:
              "The criteria for initiating incident recovery are applied.",
            implementation:
              "Conduct forensic analysis. Preserve evidence chain of custody. Determine root cause.",
            evidence:
              "Forensic analysis reports, chain of custody logs, root cause analysis.",
          },
          {
            id: "RS.AN-03",
            title: "Incident Analysis",
            description:
              "Analysis is performed to establish what has taken place during an incident and the root cause.",
            implementation:
              "Perform deep-dive analysis of incidents. Identify attack vectors, compromised assets, and data exposure.",
            evidence:
              "Incident analysis reports, timeline reconstructions, attack vector documentation.",
          },
          {
            id: "RS.AN-06",
            title: "Investigation Actions",
            description:
              "Actions performed during an investigation are recorded.",
            implementation:
              "Document all investigation actions. Maintain investigation timeline. Record evidence collected.",
            evidence:
              "Investigation logs, action records, evidence collection documentation.",
          },
          {
            id: "RS.AN-07",
            title: "Artifact Collection",
            description:
              "Incident data and metadata are collected and integrity and provenance are preserved.",
            implementation:
              "Collect and preserve digital artifacts. Maintain chain of custody. Use write-blockers and forensic imaging.",
            evidence:
              "Artifact inventory, chain of custody forms, forensic image hashes.",
          },
          {
            id: "RS.AN-08",
            title: "Lessons Learned",
            description:
              "An incident's cause is estimated and validated.",
            implementation:
              "Conduct post-incident review. Document lessons learned. Update procedures based on findings.",
            evidence:
              "Post-incident review reports, lessons learned documentation, procedure updates.",
          },
          {
            id: "RS.CO-02",
            title: "Internal Reporting",
            description:
              "Internal and external stakeholders are notified of incidents.",
            implementation:
              "Notify affected stakeholders per communication plan. Report to management and board as required.",
            evidence:
              "Notification records, stakeholder communication logs, management briefings.",
          },
          {
            id: "RS.CO-03",
            title: "External Reporting",
            description:
              "Information is shared with designated internal and external stakeholders.",
            implementation:
              "Report to regulators, law enforcement, and ISACs as required. Share IOCs with trusted partners.",
            evidence:
              "Regulatory notifications, law enforcement reports, ISAC submissions.",
          },
          {
            id: "RS.MI-01",
            title: "Incident Containment",
            description:
              "Incidents are contained.",
            implementation:
              "Isolate affected systems. Block malicious traffic. Revoke compromised credentials. Apply emergency patches.",
            evidence:
              "Containment action records, isolation confirmations, credential revocation logs.",
          },
          {
            id: "RS.MI-02",
            title: "Incident Eradication",
            description:
              "Incidents are eradicated.",
            implementation:
              "Remove malware and unauthorized access. Patch exploited vulnerabilities. Rebuild compromised systems.",
            evidence:
              "Eradication action records, malware removal confirmations, patch verification.",
          },
        ],
      },
      {
        name: "RECOVER (RC)",
        description:
          "Restore assets and operations that were impacted by a cybersecurity incident. Support timely restoration of normal operations.",
        controls: [
          {
            id: "RC.RP-01",
            title: "Recovery Plan Execution",
            description:
              "The recovery portion of the incident response plan is executed once initiated.",
            implementation:
              "Execute recovery procedures. Restore systems from clean backups. Verify system integrity before reconnection.",
            evidence:
              "Recovery action records, backup restoration logs, integrity verification results.",
          },
          {
            id: "RC.RP-02",
            title: "Recovery Selection",
            description:
              "Recovery actions are selected, scoped, and prioritized.",
            implementation:
              "Prioritize recovery based on business criticality. Define recovery sequence. Allocate resources.",
            evidence:
              "Recovery priority list, resource allocation records, recovery sequence documentation.",
          },
          {
            id: "RC.RP-03",
            title: "Integrity Verification",
            description:
              "The integrity of backups and other restoration assets is verified before using them for restoration.",
            implementation:
              "Verify backup integrity through checksums. Test restoration in isolated environment before production deployment.",
            evidence:
              "Backup integrity verification logs, test restoration results.",
          },
          {
            id: "RC.RP-04",
            title: "Critical Function Recovery",
            description:
              "Critical mission functions and cybersecurity risk management are considered to establish post-incident operational norms.",
            implementation:
              "Validate critical functions are restored. Implement enhanced monitoring post-recovery. Update risk assessments.",
            evidence:
              "Function restoration verification, enhanced monitoring configuration, updated risk assessments.",
          },
          {
            id: "RC.RP-05",
            title: "System Restoration",
            description:
              "The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed.",
            implementation:
              "Conduct validation testing after restoration. Monitor for indicators of persistent compromise. Confirm operational status.",
            evidence:
              "Validation test results, monitoring reports, operational status confirmations.",
          },
          {
            id: "RC.CO-03",
            title: "Recovery Communication",
            description:
              "Recovery activities and progress in restoring operational capabilities are communicated to stakeholders.",
            implementation:
              "Provide regular status updates during recovery. Communicate restoration milestones to stakeholders.",
            evidence:
              "Status update records, milestone notifications, stakeholder communication logs.",
          },
          {
            id: "RC.CO-04",
            title: "Public Communication",
            description:
              "Public updates on incident recovery are shared using approved methods and messaging.",
            implementation:
              "Coordinate public communications with legal and PR teams. Provide accurate and timely public statements.",
            evidence:
              "Public statements, press releases, social media communications.",
          },
        ],
      },
    ],
  },

  // =========================================================================
  // (b) ISO/IEC 27001:2022
  // =========================================================================
  {
    name: "ISO/IEC 27001:2022",
    org: "International Organization for Standardization (ISO)",
    version: "2022",
    description:
      "An international standard for information security management systems (ISMS). It specifies requirements for establishing, implementing, maintaining, and continually improving an ISMS within the context of the organization. It also includes requirements for the assessment and treatment of information security risks.",
    domains: [
      {
        name: "A.5 Organizational Controls",
        description:
          "Controls related to organizational policies, roles, responsibilities, and management of information security.",
        controls: [
          {
            id: "A.5.1",
            title: "Policies for Information Security",
            description:
              "A set of policies for information security shall be defined, approved by management, published, and communicated to relevant personnel and interested parties.",
            implementation:
              "Develop an ISMS policy framework. Include overarching information security policy and topic-specific policies. Review annually.",
            evidence:
              "Information security policy, topic-specific policies, approval records, communication records.",
          },
          {
            id: "A.5.2",
            title: "Information Security Roles and Responsibilities",
            description:
              "Information security roles and responsibilities shall be defined and allocated.",
            implementation:
              "Define security roles in job descriptions. Appoint an information security manager. Establish a security committee.",
            evidence:
              "Role descriptions, appointment letters, committee charter, RACI matrices.",
          },
          {
            id: "A.5.3",
            title: "Segregation of Duties",
            description:
              "Conflicting duties and conflicting areas of responsibility shall be segregated.",
            implementation:
              "Identify conflicting duties. Implement compensating controls where segregation is not possible.",
            evidence:
              "SoD matrix, compensating controls documentation, access control records.",
          },
          {
            id: "A.5.4",
            title: "Management Responsibilities",
            description:
              "Management shall require all personnel to apply information security in accordance with the established policies and procedures.",
            implementation:
              "Include security responsibilities in employment contracts. Conduct management security reviews.",
            evidence:
              "Employment contracts, management review minutes, policy acknowledgment records.",
          },
          {
            id: "A.5.5",
            title: "Contact with Authorities",
            description:
              "Appropriate contacts with relevant authorities shall be maintained.",
            implementation:
              "Maintain a contact list of relevant authorities (regulators, law enforcement, CERTs).",
            evidence:
              "Authority contact list, communication records, regulatory liaison documentation.",
          },
          {
            id: "A.5.6",
            title: "Contact with Special Interest Groups",
            description:
              "Appropriate contacts with special interest groups or other specialist security forums shall be maintained.",
            implementation:
              "Join industry ISACs and security forums. Participate in threat intelligence sharing communities.",
            evidence:
              "Membership records, participation logs, intelligence sharing agreements.",
          },
          {
            id: "A.5.7",
            title: "Threat Intelligence",
            description:
              "Information relating to information security threats shall be collected and analyzed to produce threat intelligence.",
            implementation:
              "Subscribe to threat intelligence feeds. Analyze threat data for relevance. Integrate findings into risk management.",
            evidence:
              "Threat intelligence reports, feed subscriptions, analysis records.",
          },
          {
            id: "A.5.8",
            title: "Information Security in Project Management",
            description:
              "Information security shall be integrated into project management.",
            implementation:
              "Include security requirements in project initiation. Conduct security reviews at project milestones.",
            evidence:
              "Project security requirements, milestone review records, security sign-off documentation.",
          },
          {
            id: "A.5.9",
            title: "Inventory of Information and Other Associated Assets",
            description:
              "An inventory of information and other associated assets shall be developed and maintained.",
            implementation:
              "Maintain asset register including information assets, hardware, software, and services. Assign asset owners.",
            evidence:
              "Asset register, ownership assignments, inventory review records.",
          },
          {
            id: "A.5.10",
            title: "Acceptable Use of Information and Other Associated Assets",
            description:
              "Rules for the acceptable use of information and other associated assets shall be identified, documented, and implemented.",
            implementation:
              "Develop acceptable use policy covering information handling, internet use, email, and removable media.",
            evidence:
              "Acceptable use policy, user acknowledgment records, policy violation reports.",
          },
          {
            id: "A.5.11",
            title: "Return of Assets",
            description:
              "Personnel and other interested parties shall return all organizational assets in their possession upon change or termination.",
            implementation:
              "Implement asset return procedures as part of offboarding. Track asset assignments and returns.",
            evidence:
              "Asset return forms, offboarding checklists, asset tracking records.",
          },
          {
            id: "A.5.12",
            title: "Classification of Information",
            description:
              "Information shall be classified according to the information security needs of the organization.",
            implementation:
              "Define classification scheme (e.g., Public, Internal, Confidential, Restricted). Apply classifications to all information assets.",
            evidence:
              "Classification policy, classification labels, handling procedures per classification level.",
          },
          {
            id: "A.5.13",
            title: "Labelling of Information",
            description:
              "An appropriate set of procedures for information labelling shall be developed and implemented.",
            implementation:
              "Implement labeling procedures for documents, emails, and data stores. Use automated classification tools where possible.",
            evidence:
              "Labeling procedures, automated classification tool configuration, sample labeled documents.",
          },
          {
            id: "A.5.14",
            title: "Information Transfer",
            description:
              "Information transfer rules, procedures, or agreements shall be in place for all types of transfer facilities.",
            implementation:
              "Define secure transfer methods for each classification level. Implement encryption for sensitive data transfers.",
            evidence:
              "Transfer procedures, encryption standards, transfer agreements, audit logs.",
          },
          {
            id: "A.5.15",
            title: "Access Control",
            description:
              "Rules to control physical and logical access to information and other associated assets shall be established and implemented.",
            implementation:
              "Implement role-based access control. Apply least privilege principle. Conduct periodic access reviews.",
            evidence:
              "Access control policy, RBAC configuration, access review reports.",
          },
          {
            id: "A.5.16",
            title: "Identity Management",
            description:
              "The full lifecycle of identities shall be managed.",
            implementation:
              "Manage identity lifecycle from provisioning to deprovisioning. Implement automated provisioning and deprovisioning.",
            evidence:
              "Identity lifecycle procedures, provisioning records, deprovisioning verification.",
          },
          {
            id: "A.5.17",
            title: "Authentication Information",
            description:
              "Allocation and management of authentication information shall be controlled.",
            implementation:
              "Implement password policies. Deploy MFA. Manage certificates and API keys securely.",
            evidence:
              "Authentication policy, password policy settings, MFA enrollment records.",
          },
          {
            id: "A.5.18",
            title: "Access Rights",
            description:
              "Access rights to information and other associated assets shall be provisioned, reviewed, modified, and removed.",
            implementation:
              "Implement access request and approval workflows. Conduct quarterly access reviews. Revoke access upon role change or termination.",
            evidence:
              "Access request forms, approval records, access review reports, revocation logs.",
          },
          {
            id: "A.5.19",
            title: "Information Security in Supplier Relationships",
            description:
              "Processes and procedures for managing information security risks associated with the use of supplier products or services shall be established.",
            implementation:
              "Conduct supplier risk assessments. Include security requirements in contracts. Monitor supplier compliance.",
            evidence:
              "Supplier risk assessment reports, contract security clauses, compliance monitoring records.",
          },
          {
            id: "A.5.20",
            title: "Addressing Information Security within Supplier Agreements",
            description:
              "Relevant information security requirements shall be established and agreed with each supplier.",
            implementation:
              "Define security requirements per supplier classification. Include in contracts and SLAs.",
            evidence:
              "Supplier agreements, security requirement specifications, SLA documentation.",
          },
          {
            id: "A.5.21",
            title: "Managing Information Security in the ICT Supply Chain",
            description:
              "Processes and procedures for managing information security risks associated with the ICT supply chain shall be defined.",
            implementation:
              "Assess ICT supply chain risks. Require security certifications from ICT suppliers. Monitor for supply chain compromises.",
            evidence:
              "Supply chain risk assessments, certification requirements, monitoring records.",
          },
          {
            id: "A.5.22",
            title: "Monitoring, Review and Change Management of Supplier Services",
            description:
              "The organization shall regularly monitor, review, evaluate, and manage change in supplier information security practices.",
            implementation:
              "Conduct periodic supplier security reviews. Monitor supplier security incidents. Manage changes in supplier services.",
            evidence:
              "Supplier review reports, incident notifications, change management records.",
          },
          {
            id: "A.5.23",
            title: "Information Security for Use of Cloud Services",
            description:
              "Processes for acquisition, use, management, and exit from cloud services shall be established.",
            implementation:
              "Define cloud security requirements. Implement cloud access security broker (CASB). Plan for cloud service transitions.",
            evidence:
              "Cloud security policy, CASB configuration, cloud service inventory, exit procedures.",
          },
          {
            id: "A.5.24",
            title: "Information Security Incident Management Planning and Preparation",
            description:
              "The organization shall plan and prepare for managing information security incidents.",
            implementation:
              "Develop incident response plan. Define incident categories and severity levels. Establish incident response team.",
            evidence:
              "Incident response plan, team roster, severity classification, communication procedures.",
          },
          {
            id: "A.5.25",
            title: "Assessment and Decision on Information Security Events",
            description:
              "The organization shall assess information security events and decide if they are to be categorized as incidents.",
            implementation:
              "Define event assessment criteria. Implement triage procedures. Document assessment decisions.",
            evidence:
              "Assessment criteria, triage procedures, event assessment records.",
          },
          {
            id: "A.5.26",
            title: "Response to Information Security Incidents",
            description:
              "Information security incidents shall be responded to in accordance with the documented procedures.",
            implementation:
              "Execute incident response procedures. Coordinate response activities. Document all response actions.",
            evidence:
              "Incident response records, action logs, coordination records.",
          },
          {
            id: "A.5.27",
            title: "Learning from Information Security Incidents",
            description:
              "Knowledge gained from information security incidents shall be used to strengthen and improve controls.",
            implementation:
              "Conduct post-incident reviews. Document lessons learned. Update policies and procedures based on findings.",
            evidence:
              "Post-incident review reports, lessons learned, policy and procedure updates.",
          },
          {
            id: "A.5.28",
            title: "Collection of Evidence",
            description:
              "The organization shall establish and implement procedures for the identification, collection, acquisition, and preservation of evidence.",
            implementation:
              "Define evidence handling procedures. Train investigators on forensic techniques. Maintain chain of custody.",
            evidence:
              "Evidence handling procedures, training records, chain of custody forms.",
          },
          {
            id: "A.5.29",
            title: "Information Security During Disruption",
            description:
              "The organization shall plan how to maintain information security at an appropriate level during disruption.",
            implementation:
              "Include information security in business continuity plans. Test security controls during DR exercises.",
            evidence:
              "BCP with security provisions, DR exercise results, continuity test reports.",
          },
          {
            id: "A.5.30",
            title: "ICT Readiness for Business Continuity",
            description:
              "ICT readiness shall be planned, implemented, maintained, and tested based on business continuity objectives.",
            implementation:
              "Define ICT continuity requirements. Implement redundancy and failover. Test ICT recovery procedures.",
            evidence:
              "ICT continuity plan, redundancy configuration, recovery test results.",
          },
          {
            id: "A.5.31",
            title: "Legal, Statutory, Regulatory and Contractual Requirements",
            description:
              "Legal, statutory, regulatory, and contractual requirements relevant to information security shall be identified.",
            implementation:
              "Maintain compliance requirements register. Conduct periodic compliance assessments. Track regulatory changes.",
            evidence:
              "Compliance register, assessment reports, regulatory change tracking.",
          },
          {
            id: "A.5.32",
            title: "Intellectual Property Rights",
            description:
              "The organization shall implement appropriate procedures to protect intellectual property rights.",
            implementation:
              "Implement software license management. Protect proprietary information. Enforce IP clauses in contracts.",
            evidence:
              "License management records, IP protection procedures, contract IP clauses.",
          },
          {
            id: "A.5.33",
            title: "Protection of Records",
            description:
              "Records shall be protected from loss, destruction, falsification, unauthorized access, and unauthorized release.",
            implementation:
              "Implement records management program. Define retention periods. Protect records integrity.",
            evidence:
              "Records management policy, retention schedules, integrity controls.",
          },
          {
            id: "A.5.34",
            title: "Privacy and Protection of PII",
            description:
              "The organization shall identify and meet the requirements regarding the preservation of privacy and protection of PII.",
            implementation:
              "Conduct data privacy impact assessments. Implement privacy controls. Appoint data protection officer where required.",
            evidence:
              "Privacy impact assessments, privacy controls, DPO appointment, consent records.",
          },
          {
            id: "A.5.35",
            title: "Independent Review of Information Security",
            description:
              "The organization's approach to managing information security shall be independently reviewed at planned intervals.",
            implementation:
              "Conduct annual independent security audits. Engage external auditors. Track audit findings to resolution.",
            evidence:
              "Audit reports, auditor engagement letters, finding remediation tracking.",
          },
          {
            id: "A.5.36",
            title: "Compliance with Policies, Rules and Standards for Information Security",
            description:
              "Compliance with the organization's information security policy, topic-specific policies, rules, and standards shall be regularly reviewed.",
            implementation:
              "Conduct periodic compliance reviews. Implement automated compliance monitoring. Address non-compliance.",
            evidence:
              "Compliance review reports, monitoring tool output, corrective action records.",
          },
          {
            id: "A.5.37",
            title: "Documented Operating Procedures",
            description:
              "Operating procedures for information processing facilities shall be documented and made available.",
            implementation:
              "Document standard operating procedures for all information processing activities. Review and update regularly.",
            evidence:
              "SOPs, procedure review records, staff acknowledgment records.",
          },
        ],
      },
      {
        name: "A.6 People Controls",
        description:
          "Controls related to human resource security including screening, terms of employment, awareness, and disciplinary processes.",
        controls: [
          {
            id: "A.6.1",
            title: "Screening",
            description:
              "Background verification checks on all candidates for employment shall be carried out prior to joining.",
            implementation:
              "Conduct background checks including criminal records, employment history, and qualification verification.",
            evidence:
              "Background check records, screening policy, verification results.",
          },
          {
            id: "A.6.2",
            title: "Terms and Conditions of Employment",
            description:
              "Employment contractual agreements shall state the personnel's and the organization's responsibilities for information security.",
            implementation:
              "Include security responsibilities, NDA, and acceptable use clauses in employment contracts.",
            evidence:
              "Employment contracts, NDA records, policy acknowledgments.",
          },
          {
            id: "A.6.3",
            title: "Information Security Awareness, Education and Training",
            description:
              "Personnel and relevant interested parties shall receive appropriate information security awareness, education, and training.",
            implementation:
              "Conduct annual security awareness training. Provide role-based training. Run phishing simulations.",
            evidence:
              "Training records, completion rates, phishing simulation results, training content.",
          },
          {
            id: "A.6.4",
            title: "Disciplinary Process",
            description:
              "A disciplinary process shall be formalized and communicated to take action against personnel who have committed an information security policy violation.",
            implementation:
              "Define disciplinary process for security violations. Communicate to all personnel. Document violations and actions.",
            evidence:
              "Disciplinary policy, violation records, action documentation.",
          },
          {
            id: "A.6.5",
            title: "Responsibilities After Termination or Change of Employment",
            description:
              "Information security responsibilities and duties that remain valid after termination or change of employment shall be defined, enforced, and communicated.",
            implementation:
              "Define post-employment security obligations. Include in exit procedures. Enforce NDA obligations.",
            evidence:
              "Exit procedures, post-employment obligations, NDA enforcement records.",
          },
          {
            id: "A.6.6",
            title: "Confidentiality or Non-Disclosure Agreements",
            description:
              "Confidentiality or non-disclosure agreements reflecting the organization's needs shall be identified, documented, reviewed, and signed by personnel.",
            implementation:
              "Develop NDA templates. Require signing before granting access. Review annually.",
            evidence:
              "NDA templates, signed NDAs, review records.",
          },
          {
            id: "A.6.7",
            title: "Remote Working",
            description:
              "Security measures shall be implemented when personnel are working remotely to protect information accessed, processed, or stored outside the organization's premises.",
            implementation:
              "Define remote working security policy. Require VPN usage. Implement endpoint security for remote devices.",
            evidence:
              "Remote working policy, VPN usage logs, endpoint security deployment records.",
          },
          {
            id: "A.6.8",
            title: "Information Security Event Reporting",
            description:
              "The organization shall provide a mechanism for personnel to report observed or suspected information security events through appropriate channels in a timely manner.",
            implementation:
              "Establish security event reporting channels. Train personnel on reporting procedures. Acknowledge and track reports.",
            evidence:
              "Reporting channels documentation, training records, event report logs.",
          },
        ],
      },
      {
        name: "A.7 Physical Controls",
        description:
          "Controls related to physical security of facilities, equipment, and information.",
        controls: [
          {
            id: "A.7.1",
            title: "Physical Security Perimeters",
            description:
              "Security perimeters shall be defined and used to protect areas that contain information and other associated assets.",
            implementation:
              "Define physical security zones. Implement barriers, walls, and access points. Mark security boundaries.",
            evidence:
              "Security zone maps, perimeter specifications, access point inventory.",
          },
          {
            id: "A.7.2",
            title: "Physical Entry",
            description:
              "Secure areas shall be protected by appropriate entry controls and access points.",
            implementation:
              "Implement badge access systems. Deploy mantraps for sensitive areas. Log all physical access.",
            evidence:
              "Access control system records, entry logs, mantrap configuration.",
          },
          {
            id: "A.7.3",
            title: "Securing Offices, Rooms and Facilities",
            description:
              "Physical security for offices, rooms, and facilities shall be designed and implemented.",
            implementation:
              "Implement locks, alarms, and CCTV. Secure server rooms with environmental controls. Restrict access to sensitive areas.",
            evidence:
              "Physical security specifications, alarm system records, CCTV footage retention.",
          },
          {
            id: "A.7.4",
            title: "Physical Security Monitoring",
            description:
              "Premises shall be continuously monitored for unauthorized physical access.",
            implementation:
              "Deploy CCTV with recording capability. Implement intrusion detection systems. Monitor 24/7.",
            evidence:
              "CCTV deployment records, intrusion detection logs, monitoring schedules.",
          },
          {
            id: "A.7.5",
            title: "Protecting Against Physical and Environmental Threats",
            description:
              "Protection against physical and environmental threats shall be designed and implemented.",
            implementation:
              "Implement fire suppression, flood detection, UPS, and climate control systems.",
            evidence:
              "Environmental protection systems, maintenance records, test results.",
          },
          {
            id: "A.7.6",
            title: "Working in Secure Areas",
            description:
              "Security measures for working in secure areas shall be designed and implemented.",
            implementation:
              "Define clean desk policy. Restrict photography. Control access to secure areas.",
            evidence:
              "Secure area procedures, clean desk policy, access restriction records.",
          },
          {
            id: "A.7.7",
            title: "Clear Desk and Clear Screen",
            description:
              "Clear desk rules for papers and removable storage media and clear screen rules for information processing facilities shall be defined.",
            implementation:
              "Implement automatic screen lock. Enforce clean desk policy. Provide secure storage for documents.",
            evidence:
              "Screen lock policy settings, clean desk audit results, secure storage provisions.",
          },
          {
            id: "A.7.8",
            title: "Equipment Siting and Protection",
            description:
              "Equipment shall be sited and protected to reduce the risks from physical and environmental threats.",
            implementation:
              "Site critical equipment in protected areas. Implement environmental controls. Use raised floors and cable management.",
            evidence:
              "Equipment placement plans, environmental control records, cable management documentation.",
          },
          {
            id: "A.7.9",
            title: "Security of Assets Off-Premises",
            description:
              "Off-site assets shall be protected.",
            implementation:
              "Encrypt portable devices. Implement remote wipe capability. Track off-site equipment.",
            evidence:
              "Encryption configuration, remote wipe capabilities, off-site asset tracking.",
          },
          {
            id: "A.7.10",
            title: "Storage Media",
            description:
              "Storage media shall be managed through their lifecycle of acquisition, use, transportation, and disposal.",
            implementation:
              "Track storage media. Encrypt sensitive media. Implement secure disposal procedures.",
            evidence:
              "Media tracking records, encryption records, disposal certificates.",
          },
          {
            id: "A.7.11",
            title: "Supporting Utilities",
            description:
              "Information processing facilities shall be protected from power failures and other disruptions caused by failures in supporting utilities.",
            implementation:
              "Deploy UPS and generators. Implement redundant power feeds. Test backup power regularly.",
            evidence:
              "UPS and generator records, redundancy configuration, test results.",
          },
          {
            id: "A.7.12",
            title: "Cabling Security",
            description:
              "Cables carrying power and data shall be protected from interception, interference, and damage.",
            implementation:
              "Use conduits and cable trays. Separate power and data cables. Implement fiber optics for sensitive connections.",
            evidence:
              "Cabling specifications, separation documentation, fiber optic deployment records.",
          },
          {
            id: "A.7.13",
            title: "Equipment Maintenance",
            description:
              "Equipment shall be maintained correctly to ensure availability, integrity, and confidentiality of information.",
            implementation:
              "Implement maintenance schedules. Use authorized service providers. Clear sensitive data before maintenance.",
            evidence:
              "Maintenance schedules, service provider agreements, data clearing records.",
          },
          {
            id: "A.7.14",
            title: "Secure Disposal or Re-use of Equipment",
            description:
              "Items of equipment containing storage media shall be verified to ensure that any sensitive data and licensed software has been removed or securely overwritten prior to disposal or re-use.",
            implementation:
              "Implement data sanitization procedures (NIST SP 800-88). Verify sanitization. Obtain destruction certificates.",
            evidence:
              "Sanitization procedures, verification records, destruction certificates.",
          },
        ],
      },
      {
        name: "A.8 Technological Controls",
        description:
          "Controls related to technology implementation including access, cryptography, malware protection, logging, and network security.",
        controls: [
          {
            id: "A.8.1",
            title: "User Endpoint Devices",
            description:
              "Information stored on, processed by, or accessible via user endpoint devices shall be protected.",
            implementation:
              "Deploy endpoint protection. Implement MDM for mobile devices. Enforce device encryption.",
            evidence:
              "Endpoint protection deployment, MDM configuration, encryption compliance reports.",
          },
          {
            id: "A.8.2",
            title: "Privileged Access Rights",
            description:
              "The allocation and use of privileged access rights shall be restricted and managed.",
            implementation:
              "Implement PAM solution. Restrict privileged access to minimum necessary. Monitor privileged sessions.",
            evidence:
              "PAM system records, privilege allocation records, session monitoring logs.",
          },
          {
            id: "A.8.3",
            title: "Information Access Restriction",
            description:
              "Access to information and other associated assets shall be restricted in accordance with the established topic-specific policy on access control.",
            implementation:
              "Implement access controls based on classification. Apply need-to-know principle. Review access regularly.",
            evidence:
              "Access control configuration, classification-based access rules, access review records.",
          },
          {
            id: "A.8.4",
            title: "Access to Source Code",
            description:
              "Read and write access to source code, development tools, and software libraries shall be appropriately managed.",
            implementation:
              "Restrict source code repository access. Implement branch protection. Use code review workflows.",
            evidence:
              "Repository access settings, branch protection rules, code review records.",
          },
          {
            id: "A.8.5",
            title: "Secure Authentication",
            description:
              "Secure authentication technologies and procedures shall be established and implemented.",
            implementation:
              "Implement strong authentication mechanisms. Enforce password complexity and MFA. Use adaptive authentication.",
            evidence:
              "Authentication configuration, password policy settings, MFA deployment records.",
          },
          {
            id: "A.8.6",
            title: "Capacity Management",
            description:
              "The use of resources shall be monitored and adjusted in line with current and expected capacity requirements.",
            implementation:
              "Monitor resource utilization. Implement capacity planning. Set up alerting for capacity thresholds.",
            evidence:
              "Capacity monitoring dashboards, planning documents, threshold alert configuration.",
          },
          {
            id: "A.8.7",
            title: "Protection Against Malware",
            description:
              "Protection against malware shall be implemented and supported by appropriate user awareness.",
            implementation:
              "Deploy anti-malware on all endpoints and servers. Keep signatures current. Implement behavioral detection.",
            evidence:
              "Anti-malware deployment records, signature update logs, detection event records.",
          },
          {
            id: "A.8.8",
            title: "Management of Technical Vulnerabilities",
            description:
              "Information about technical vulnerabilities of information systems in use shall be obtained and appropriate measures taken.",
            implementation:
              "Conduct regular vulnerability scans. Implement patch management. Track vulnerabilities to remediation.",
            evidence:
              "Vulnerability scan reports, patch management records, remediation tracking.",
          },
          {
            id: "A.8.9",
            title: "Configuration Management",
            description:
              "Configurations, including security configurations, of hardware, software, services, and networks shall be established, documented, implemented, monitored, and reviewed.",
            implementation:
              "Define security configuration baselines. Implement configuration management tools. Monitor for drift.",
            evidence:
              "Configuration baselines, management tool records, drift detection reports.",
          },
          {
            id: "A.8.10",
            title: "Information Deletion",
            description:
              "Information stored in information systems, devices, or in any other storage media shall be deleted when no longer required.",
            implementation:
              "Implement data retention and deletion policies. Use secure deletion methods. Verify deletion completion.",
            evidence:
              "Retention policy, deletion procedures, verification records.",
          },
          {
            id: "A.8.11",
            title: "Data Masking",
            description:
              "Data masking shall be used in accordance with the organization's topic-specific policy on access control.",
            implementation:
              "Implement data masking for non-production environments. Mask PII in logs and reports.",
            evidence:
              "Data masking configuration, masked data samples, masking policy.",
          },
          {
            id: "A.8.12",
            title: "Data Leakage Prevention",
            description:
              "Data leakage prevention measures shall be applied to systems, networks, and any other devices that process, store, or transmit sensitive information.",
            implementation:
              "Deploy DLP solutions for email, web, and endpoints. Define sensitive data patterns. Monitor and alert on policy violations.",
            evidence:
              "DLP deployment records, policy configuration, violation reports.",
          },
          {
            id: "A.8.13",
            title: "Information Backup",
            description:
              "Backup copies of information, software, and systems shall be maintained and regularly tested.",
            implementation:
              "Implement automated backup schedules. Test restorations quarterly. Store backups offsite.",
            evidence:
              "Backup schedules, restoration test results, offsite storage records.",
          },
          {
            id: "A.8.14",
            title: "Redundancy of Information Processing Facilities",
            description:
              "Information processing facilities shall be implemented with redundancy sufficient to meet availability requirements.",
            implementation:
              "Deploy redundant systems. Implement clustering and failover. Test redundancy regularly.",
            evidence:
              "Redundancy architecture, failover configuration, test results.",
          },
          {
            id: "A.8.15",
            title: "Logging",
            description:
              "Logs that record activities, exceptions, faults, and other relevant events shall be produced, stored, protected, and analyzed.",
            implementation:
              "Enable comprehensive logging. Centralize in SIEM. Protect log integrity. Define retention periods.",
            evidence:
              "Logging configuration, SIEM deployment, log protection measures, retention policy.",
          },
          {
            id: "A.8.16",
            title: "Monitoring Activities",
            description:
              "Networks, systems, and applications shall be monitored for anomalous behavior and appropriate actions taken to evaluate potential information security events.",
            implementation:
              "Deploy monitoring tools. Define anomaly detection rules. Implement alerting and response procedures.",
            evidence:
              "Monitoring tool deployment, detection rules, alert configuration, response procedures.",
          },
          {
            id: "A.8.17",
            title: "Clock Synchronization",
            description:
              "The clocks of information processing systems used by the organization shall be synchronized to approved time sources.",
            implementation:
              "Configure NTP synchronization to authoritative time sources. Monitor synchronization accuracy.",
            evidence:
              "NTP configuration, time source documentation, synchronization monitoring.",
          },
          {
            id: "A.8.18",
            title: "Use of Privileged Utility Programs",
            description:
              "The use of utility programs that might be capable of overriding system and application controls shall be restricted and tightly controlled.",
            implementation:
              "Restrict access to privileged utilities. Log utility usage. Remove unnecessary utilities.",
            evidence:
              "Utility access restrictions, usage logs, utility inventory.",
          },
          {
            id: "A.8.19",
            title: "Installation of Software on Operational Systems",
            description:
              "Procedures and measures shall be implemented to securely manage software installation on operational systems.",
            implementation:
              "Restrict software installation privileges. Implement application whitelisting. Use centralized software deployment.",
            evidence:
              "Installation restriction settings, whitelist configuration, deployment tool records.",
          },
          {
            id: "A.8.20",
            title: "Networks Security",
            description:
              "Networks and network devices shall be secured, managed, and controlled to protect information in systems and applications.",
            implementation:
              "Implement network segmentation. Deploy firewalls and IDS/IPS. Harden network devices.",
            evidence:
              "Network architecture, firewall rules, IDS/IPS configuration, hardening records.",
          },
          {
            id: "A.8.21",
            title: "Security of Network Services",
            description:
              "Security mechanisms, service levels, and service requirements of network services shall be identified, implemented, and monitored.",
            implementation:
              "Define network service security requirements. Include in SLAs. Monitor service security posture.",
            evidence:
              "Service security requirements, SLA documentation, monitoring records.",
          },
          {
            id: "A.8.22",
            title: "Segregation of Networks",
            description:
              "Groups of information services, users, and information systems shall be segregated in the organization's networks.",
            implementation:
              "Implement VLANs and network segmentation. Apply micro-segmentation for critical assets.",
            evidence:
              "Network segmentation design, VLAN configuration, micro-segmentation rules.",
          },
          {
            id: "A.8.23",
            title: "Web Filtering",
            description:
              "Access to external websites shall be managed to reduce exposure to malicious content.",
            implementation:
              "Deploy web filtering/proxy. Block malicious and inappropriate categories. Monitor web access.",
            evidence:
              "Web filter configuration, category blocking rules, web access reports.",
          },
          {
            id: "A.8.24",
            title: "Use of Cryptography",
            description:
              "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
            implementation:
              "Define cryptographic standards. Implement key management lifecycle. Use approved algorithms and key lengths.",
            evidence:
              "Cryptographic standards document, key management procedures, algorithm inventory.",
          },
          {
            id: "A.8.25",
            title: "Secure Development Life Cycle",
            description:
              "Rules for the secure development of software and systems shall be established and applied.",
            implementation:
              "Implement SDLC with security gates. Conduct threat modeling, code review, and security testing.",
            evidence:
              "SDLC documentation, security gate criteria, code review records, test results.",
          },
          {
            id: "A.8.26",
            title: "Application Security Requirements",
            description:
              "Information security requirements shall be identified, specified, and approved when developing or acquiring applications.",
            implementation:
              "Define security requirements for applications. Include in RFPs and development specifications.",
            evidence:
              "Security requirements documents, RFP specifications, requirement traceability.",
          },
          {
            id: "A.8.27",
            title: "Secure System Architecture and Engineering Principles",
            description:
              "Principles for engineering secure systems shall be established, documented, maintained, and applied to any information system development activity.",
            implementation:
              "Document secure design principles. Apply defense in depth, least privilege, and fail-secure principles.",
            evidence:
              "Architecture principles document, design review records, architecture diagrams.",
          },
          {
            id: "A.8.28",
            title: "Secure Coding",
            description:
              "Secure coding principles shall be applied to software development.",
            implementation:
              "Define secure coding standards. Train developers. Conduct static and dynamic analysis.",
            evidence:
              "Coding standards, developer training records, SAST/DAST results.",
          },
          {
            id: "A.8.29",
            title: "Security Testing in Development and Acceptance",
            description:
              "Security testing processes shall be defined and implemented in the development lifecycle.",
            implementation:
              "Conduct security testing at each SDLC phase. Perform penetration testing before release. Validate security controls.",
            evidence:
              "Test plans, test results, penetration test reports, control validation records.",
          },
          {
            id: "A.8.30",
            title: "Outsourced Development",
            description:
              "The organization shall direct, monitor, and review the activities related to outsourced system development.",
            implementation:
              "Include security requirements in outsourcing contracts. Review outsourced code. Conduct acceptance testing.",
            evidence:
              "Outsourcing contracts, code review records, acceptance test results.",
          },
          {
            id: "A.8.31",
            title: "Separation of Development, Test and Production Environments",
            description:
              "Development, testing, and production environments shall be separated and secured.",
            implementation:
              "Maintain separate environments. Restrict access between environments. Use sanitized test data.",
            evidence:
              "Environment separation documentation, access control records, data sanitization records.",
          },
          {
            id: "A.8.32",
            title: "Change Management",
            description:
              "Changes to information processing facilities and information systems shall be subject to change management procedures.",
            implementation:
              "Implement formal change management process. Assess security impact of changes. Maintain change records.",
            evidence:
              "Change management procedures, change records, security impact assessments.",
          },
          {
            id: "A.8.33",
            title: "Test Information",
            description:
              "Test information shall be appropriately selected, protected, and managed.",
            implementation:
              "Use synthetic or anonymized data for testing. Protect production data used in testing. Control access to test data.",
            evidence:
              "Test data management procedures, anonymization records, access controls.",
          },
          {
            id: "A.8.34",
            title: "Protection of Information Systems During Audit Testing",
            description:
              "Audit tests and other assurance activities involving assessment of operational systems shall be planned and agreed between the tester and appropriate management.",
            implementation:
              "Plan audit testing windows. Minimize production impact. Protect audit tools and results.",
            evidence:
              "Audit planning documents, testing schedules, impact mitigation records.",
          },
        ],
      },
    ],
  },

  // =========================================================================
  // (c) CIS Controls v8
  // =========================================================================
  {
    name: "CIS Controls v8",
    org: "Center for Internet Security (CIS)",
    version: "8.0",
    description:
      "A prioritized set of actions that collectively form a defense-in-depth set of best practices to mitigate the most common attacks against systems and networks. Organized into 18 control areas with Implementation Groups (IG1, IG2, IG3) for prioritization.",
    domains: [
      {
        name: "Basic Controls (IG1)",
        description:
          "Essential cyber hygiene controls that every organization should implement. IG1 represents the minimum standard of information security for all enterprises.",
        controls: [
          {
            id: "CIS-1",
            title: "Inventory and Control of Enterprise Assets",
            description:
              "Actively manage all enterprise assets connected to the infrastructure to accurately know the totality of assets that need to be monitored and protected.",
            implementation:
              "Deploy automated asset discovery. Maintain hardware and virtual asset inventory. Track DHCP and DNS for rogue devices. Review inventory weekly.",
            evidence:
              "Asset inventory database, discovery scan reports, weekly review records.",
          },
          {
            id: "CIS-2",
            title: "Inventory and Control of Software Assets",
            description:
              "Actively manage all software on the network so that only authorized software is installed and can execute, and unauthorized and unmanaged software is found and prevented from installation or execution.",
            implementation:
              "Maintain authorized software inventory. Deploy application whitelisting. Use software asset management tools. Block unauthorized installations.",
            evidence:
              "Software inventory, whitelist configuration, SAM tool reports, blocked installation logs.",
          },
          {
            id: "CIS-3",
            title: "Data Protection",
            description:
              "Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.",
            implementation:
              "Classify data by sensitivity. Implement encryption for sensitive data. Deploy DLP. Define retention and disposal procedures.",
            evidence:
              "Data classification records, encryption configuration, DLP reports, retention schedules.",
          },
          {
            id: "CIS-4",
            title: "Secure Configuration of Enterprise Assets and Software",
            description:
              "Establish and maintain the secure configuration of enterprise assets and software.",
            implementation:
              "Develop security baselines using CIS Benchmarks. Implement configuration management. Scan for drift. Harden new deployments.",
            evidence:
              "Configuration baselines, CIS Benchmark compliance scans, drift detection reports.",
          },
          {
            id: "CIS-5",
            title: "Account Management",
            description:
              "Use processes and tools to assign and manage authorization to credentials for user accounts, including administrator accounts, as well as service accounts.",
            implementation:
              "Implement centralized account management. Enforce unique accounts. Disable inactive accounts. Manage service accounts separately.",
            evidence:
              "Account inventory, inactive account reports, service account documentation.",
          },
          {
            id: "CIS-6",
            title: "Access Control Management",
            description:
              "Use processes and tools to create, assign, manage, and revoke access credentials and privileges for user, administrator, and service accounts.",
            implementation:
              "Implement RBAC. Enforce least privilege. Require MFA for administrative access. Conduct access reviews quarterly.",
            evidence:
              "RBAC configuration, privilege assignments, MFA enrollment, access review reports.",
          },
        ],
      },
      {
        name: "Foundational Controls (IG2)",
        description:
          "Controls for organizations with moderate risk profiles, building on IG1 with additional technical capabilities.",
        controls: [
          {
            id: "CIS-7",
            title: "Continuous Vulnerability Management",
            description:
              "Develop a plan to continuously assess and track vulnerabilities on all enterprise assets to remediate and minimize the window of opportunity for attackers.",
            implementation:
              "Conduct automated vulnerability scans at least monthly. Prioritize by CVSS score. Remediate critical vulnerabilities within 15 days. Track remediation metrics.",
            evidence:
              "Vulnerability scan reports, remediation tracking, metrics dashboards, SLA compliance records.",
          },
          {
            id: "CIS-8",
            title: "Audit Log Management",
            description:
              "Collect, alert, review, and retain audit logs of events that could help detect, understand, or recover from an attack.",
            implementation:
              "Enable audit logging on all systems. Centralize logs in SIEM. Define retention periods (minimum 90 days). Review critical logs daily.",
            evidence:
              "Logging configuration, SIEM deployment, retention policy, log review records.",
          },
          {
            id: "CIS-9",
            title: "Email and Web Browser Protections",
            description:
              "Improve protections and detections of threats from email and web vectors, as these are opportunities for attackers to manipulate human behavior.",
            implementation:
              "Deploy email security gateway. Implement DMARC/DKIM/SPF. Enable web filtering. Block script execution in email. Deploy browser isolation.",
            evidence:
              "Email gateway configuration, DMARC records, web filter rules, browser security settings.",
          },
          {
            id: "CIS-10",
            title: "Malware Defenses",
            description:
              "Prevent or control the installation, spread, and execution of malicious applications, code, or scripts on enterprise assets.",
            implementation:
              "Deploy anti-malware on all endpoints and servers. Enable auto-update of signatures. Implement behavioral detection. Configure anti-exploit mitigations.",
            evidence:
              "Anti-malware deployment records, update compliance, detection logs, exploit mitigation settings.",
          },
          {
            id: "CIS-11",
            title: "Data Recovery",
            description:
              "Establish and maintain data recovery practices sufficient to restore in-scope enterprise assets to a pre-incident and trusted state.",
            implementation:
              "Implement automated backups. Test restorations quarterly. Maintain offline copies. Encrypt backup data.",
            evidence:
              "Backup schedules, restoration test results, offline backup verification, encryption records.",
          },
          {
            id: "CIS-12",
            title: "Network Infrastructure Management",
            description:
              "Establish and maintain the secure configuration of network devices.",
            implementation:
              "Maintain network device inventory. Apply security configurations. Implement network segmentation. Update firmware regularly.",
            evidence:
              "Device inventory, configuration baselines, segmentation design, firmware update records.",
          },
          {
            id: "CIS-13",
            title: "Network Monitoring and Defense",
            description:
              "Operate processes and tooling to establish and maintain comprehensive network monitoring and defense against security threats.",
            implementation:
              "Deploy IDS/IPS. Implement network monitoring. Collect NetFlow data. Deploy network-based DLP. Analyze DNS traffic.",
            evidence:
              "IDS/IPS deployment, monitoring configuration, NetFlow collection, DNS analysis reports.",
          },
        ],
      },
      {
        name: "Organizational Controls (IG3)",
        description:
          "Advanced controls for organizations with sophisticated adversaries. Builds on IG1 and IG2 with mature security programs.",
        controls: [
          {
            id: "CIS-14",
            title: "Security Awareness and Skills Training",
            description:
              "Establish and maintain a security awareness program to influence behavior among the workforce to be security conscious and properly skilled.",
            implementation:
              "Conduct annual awareness training. Provide role-based training. Run phishing simulations monthly. Track and report on training metrics.",
            evidence:
              "Training program documentation, completion rates, phishing simulation results, metrics reports.",
          },
          {
            id: "CIS-15",
            title: "Service Provider Management",
            description:
              "Develop a process to evaluate service providers who hold sensitive data, or are responsible for an enterprise's critical IT platforms or processes.",
            implementation:
              "Classify service providers by risk. Conduct security assessments. Include security in contracts. Monitor provider security posture.",
            evidence:
              "Provider classification, assessment reports, contract security clauses, monitoring records.",
          },
          {
            id: "CIS-16",
            title: "Application Software Security",
            description:
              "Manage the security lifecycle of in-house developed, hosted, or acquired software to prevent, detect, and remediate security weaknesses.",
            implementation:
              "Implement secure SDLC. Conduct SAST/DAST. Perform security code reviews. Maintain a vulnerability disclosure program.",
            evidence:
              "SDLC documentation, SAST/DAST reports, code review records, VDP.",
          },
          {
            id: "CIS-17",
            title: "Incident Response Management",
            description:
              "Establish a program to develop and maintain an incident response capability to prepare, detect, and quickly respond to an attack.",
            implementation:
              "Develop incident response plan. Define roles and responsibilities. Conduct tabletop exercises biannually. Integrate with threat intelligence.",
            evidence:
              "IRP document, team roster, exercise reports, threat intelligence integration records.",
          },
          {
            id: "CIS-18",
            title: "Penetration Testing",
            description:
              "Test the effectiveness and resiliency of enterprise assets through identifying and exploiting weaknesses in controls and simulating the objectives and actions of an attacker.",
            implementation:
              "Conduct external and internal penetration tests annually. Perform red team exercises. Validate remediation of findings.",
            evidence:
              "Penetration test reports, red team reports, remediation validation records.",
          },
        ],
      },
    ],
  },

  // =========================================================================
  // (d) PCI DSS v4.0
  // =========================================================================
  {
    name: "PCI DSS v4.0",
    org: "Payment Card Industry Security Standards Council",
    version: "4.0",
    description:
      "The Payment Card Industry Data Security Standard is a set of security standards designed to ensure that all companies that accept, process, store, or transmit credit card information maintain a secure environment. PCI DSS v4.0 introduces a customized approach alongside the defined approach.",
    domains: [
      {
        name: "Build and Maintain a Secure Network and Systems",
        description:
          "Requirements 1-2: Establish and maintain network security controls and secure system configurations.",
        controls: [
          {
            id: "PCI-1.1",
            title: "Network Security Controls Defined and Understood",
            description:
              "Processes and mechanisms for installing and maintaining network security controls are defined and understood.",
            implementation:
              "Document all network security controls. Define roles responsible for maintaining network security. Maintain network diagrams.",
            evidence:
              "Network security policy, responsibility assignments, current network diagrams.",
          },
          {
            id: "PCI-1.2",
            title: "Network Security Controls Configured and Maintained",
            description:
              "Network security controls (NSCs) are configured and maintained.",
            implementation:
              "Configure firewalls to restrict traffic. Implement stateful inspection. Restrict inbound and outbound traffic to necessary flows only.",
            evidence:
              "Firewall rulesets, traffic flow documentation, NSC configuration records.",
          },
          {
            id: "PCI-1.3",
            title: "Network Access to CDE is Restricted",
            description:
              "Network access to and from the cardholder data environment is restricted.",
            implementation:
              "Segment CDE from other networks. Implement DMZ for public-facing systems. Restrict direct public access to CDE.",
            evidence:
              "Network segmentation documentation, DMZ configuration, access restriction rules.",
          },
          {
            id: "PCI-1.4",
            title: "Network Connections Between Trusted and Untrusted Networks",
            description:
              "Network connections between trusted and untrusted networks are controlled.",
            implementation:
              "Implement network security controls at all trust boundaries. Configure personal firewalls on mobile devices.",
            evidence:
              "Trust boundary documentation, NSC placement, personal firewall configuration.",
          },
          {
            id: "PCI-1.5",
            title: "Risks to the CDE from Computing Devices",
            description:
              "Risks to the CDE from computing devices that are able to connect to both untrusted networks and the CDE are mitigated.",
            implementation:
              "Implement controls on dual-homed devices. Restrict access from untrusted networks through to the CDE.",
            evidence:
              "Dual-homed device inventory, access restriction configuration, risk mitigation documentation.",
          },
          {
            id: "PCI-2.1",
            title: "Secure Configurations Defined and Understood",
            description:
              "Processes and mechanisms for applying secure configurations to all system components are defined and understood.",
            implementation:
              "Develop configuration standards for all system components. Document deviations with justification and approval.",
            evidence:
              "Configuration standards, deviation records, approval documentation.",
          },
          {
            id: "PCI-2.2",
            title: "System Components Configured Securely",
            description:
              "System components are configured and managed securely.",
            implementation:
              "Apply CIS Benchmarks or vendor hardening guides. Remove default accounts and passwords. Disable unnecessary services. Enable only required functionality.",
            evidence:
              "Hardening compliance scans, default account removal verification, service configuration.",
          },
          {
            id: "PCI-2.3",
            title: "Wireless Environments Configured Securely",
            description:
              "Wireless environments are configured and managed securely.",
            implementation:
              "Change wireless defaults. Implement WPA3 or equivalent. Conduct wireless scanning quarterly.",
            evidence:
              "Wireless configuration, scan reports, default change verification.",
          },
        ],
      },
      {
        name: "Protect Account Data",
        description:
          "Requirements 3-4: Protect stored account data and protect cardholder data with strong cryptography during transmission over open, public networks.",
        controls: [
          {
            id: "PCI-3.1",
            title: "Account Data Protection Defined and Understood",
            description:
              "Processes and mechanisms for protecting stored account data are defined and understood.",
            implementation:
              "Define data retention policy. Implement procedures to securely delete data when no longer needed. Document data flows.",
            evidence:
              "Data retention policy, deletion procedures, data flow diagrams.",
          },
          {
            id: "PCI-3.2",
            title: "Storage of Account Data Minimized",
            description:
              "Storage of account data is kept to a minimum.",
            implementation:
              "Do not store sensitive authentication data after authorization. Implement automated data purge processes. Minimize data retention periods.",
            evidence:
              "Retention schedules, purge process documentation, data inventory.",
          },
          {
            id: "PCI-3.3",
            title: "Sensitive Authentication Data Not Stored",
            description:
              "Sensitive authentication data (SAD) is not stored after authorization.",
            implementation:
              "Verify no storage of full track data, CVV, or PIN blocks after authorization. Implement automated checks.",
            evidence:
              "Data storage scans, verification reports, automated check results.",
          },
          {
            id: "PCI-3.4",
            title: "Access to PAN is Restricted",
            description:
              "Access to displays of full PAN and ability to copy cardholder data are restricted.",
            implementation:
              "Mask PAN when displayed (show first 6 and last 4 only). Restrict access based on business need-to-know.",
            evidence:
              "Masking configuration, access control records, display verification.",
          },
          {
            id: "PCI-3.5",
            title: "PAN is Secured Wherever Stored",
            description:
              "Primary account number (PAN) is secured wherever it is stored.",
            implementation:
              "Render PAN unreadable using encryption, truncation, tokenization, or hashing. Implement key management procedures.",
            evidence:
              "Encryption configuration, tokenization records, key management documentation.",
          },
          {
            id: "PCI-3.6",
            title: "Cryptographic Keys Protected",
            description:
              "Cryptographic keys used to protect stored account data are secured.",
            implementation:
              "Implement key management lifecycle. Store keys securely using HSMs. Rotate keys per policy. Maintain split knowledge and dual control.",
            evidence:
              "Key management procedures, HSM configuration, key rotation records.",
          },
          {
            id: "PCI-4.1",
            title: "Transmission Protection Defined",
            description:
              "Processes and mechanisms for protecting cardholder data with strong cryptography during transmission over open, public networks are defined and understood.",
            implementation:
              "Document cryptographic requirements for data transmission. Define acceptable protocols and cipher suites.",
            evidence:
              "Transmission security policy, protocol requirements, cipher suite documentation.",
          },
          {
            id: "PCI-4.2",
            title: "PAN Protected During Transmission",
            description:
              "PAN is protected with strong cryptography during transmission.",
            implementation:
              "Enforce TLS 1.2 or higher for PAN transmission. Disable SSL and early TLS. Implement certificate validation.",
            evidence:
              "TLS configuration, protocol scan results, certificate management records.",
          },
        ],
      },
      {
        name: "Maintain a Vulnerability Management Program",
        description:
          "Requirements 5-6: Protect all systems and networks from malicious software and develop and maintain secure systems and software.",
        controls: [
          {
            id: "PCI-5.1",
            title: "Malicious Software Prevention Defined",
            description:
              "Processes and mechanisms for protecting all systems and networks from malicious software are defined and understood.",
            implementation:
              "Develop anti-malware strategy. Define system types requiring protection. Document exceptions with risk-based justification.",
            evidence:
              "Anti-malware policy, system coverage inventory, exception documentation.",
          },
          {
            id: "PCI-5.2",
            title: "Malicious Software Prevented or Detected",
            description:
              "Malicious software is prevented or detected and addressed.",
            implementation:
              "Deploy anti-malware on all in-scope systems. Enable real-time scanning. Keep signatures current. Monitor for and respond to detections.",
            evidence:
              "Anti-malware deployment records, signature update status, detection and response logs.",
          },
          {
            id: "PCI-5.3",
            title: "Anti-Malware Mechanisms Active and Maintained",
            description:
              "Anti-malware mechanisms and processes are active, maintained, and monitored.",
            implementation:
              "Monitor anti-malware health. Alert on disabled or outdated agents. Prevent tampering with anti-malware software.",
            evidence:
              "Health monitoring dashboards, alert configuration, tamper protection settings.",
          },
          {
            id: "PCI-5.4",
            title: "Anti-Phishing Mechanisms",
            description:
              "Anti-phishing mechanisms protect users against phishing attacks.",
            implementation:
              "Deploy email security with anti-phishing capability. Implement link protection. Conduct phishing awareness training.",
            evidence:
              "Anti-phishing configuration, training records, phishing simulation results.",
          },
          {
            id: "PCI-6.1",
            title: "Secure Development Defined",
            description:
              "Processes and mechanisms for developing and maintaining secure systems and software are defined and understood.",
            implementation:
              "Establish secure development lifecycle. Define security requirements for custom software. Train developers on secure coding.",
            evidence:
              "SDLC documentation, security requirements, developer training records.",
          },
          {
            id: "PCI-6.2",
            title: "Bespoke and Custom Software Developed Securely",
            description:
              "Bespoke and custom software is developed securely.",
            implementation:
              "Conduct code reviews. Implement SAST and DAST. Follow OWASP Top 10 guidelines. Test for common vulnerabilities.",
            evidence:
              "Code review records, SAST/DAST reports, vulnerability testing results.",
          },
          {
            id: "PCI-6.3",
            title: "Security Vulnerabilities Identified and Addressed",
            description:
              "Security vulnerabilities are identified and addressed.",
            implementation:
              "Subscribe to vulnerability notifications. Assess and prioritize vulnerabilities. Install critical patches within 30 days.",
            evidence:
              "Vulnerability notification subscriptions, assessment records, patch installation records.",
          },
          {
            id: "PCI-6.4",
            title: "Public-Facing Web Applications Protected",
            description:
              "Public-facing web applications are protected against attacks.",
            implementation:
              "Deploy WAF in front of public-facing applications. Review WAF rules regularly. Conduct web application penetration testing.",
            evidence:
              "WAF deployment and configuration, rule review records, penetration test reports.",
          },
          {
            id: "PCI-6.5",
            title: "Changes Managed Securely",
            description:
              "Changes to all system components in the production environment are managed securely.",
            implementation:
              "Implement change management process. Assess security impact. Test changes before deployment. Maintain rollback procedures.",
            evidence:
              "Change management records, security impact assessments, test results, rollback procedures.",
          },
        ],
      },
      {
        name: "Implement Strong Access Control Measures",
        description:
          "Requirements 7-9: Restrict access to system components and cardholder data by business need to know, identify users and authenticate access, and restrict physical access.",
        controls: [
          {
            id: "PCI-7.1",
            title: "Access Control Defined",
            description:
              "Processes and mechanisms for restricting access to system components and cardholder data by business need to know are defined and understood.",
            implementation:
              "Define access control policy. Implement role-based access. Document access requirements for each role.",
            evidence:
              "Access control policy, role definitions, access requirement documentation.",
          },
          {
            id: "PCI-7.2",
            title: "Access Appropriately Defined and Assigned",
            description:
              "Access to system components and data is appropriately defined and assigned.",
            implementation:
              "Assign access based on job classification and function. Implement default deny-all. Grant access by explicit approval only.",
            evidence:
              "Access assignments, default deny configuration, approval records.",
          },
          {
            id: "PCI-7.3",
            title: "Access Managed via Access Control Systems",
            description:
              "Access to system components and data is managed via an access control system(s).",
            implementation:
              "Deploy centralized access control. Implement automated provisioning and deprovisioning. Monitor access violations.",
            evidence:
              "Access control system configuration, provisioning workflows, violation monitoring.",
          },
          {
            id: "PCI-8.1",
            title: "User Identification and Authentication Defined",
            description:
              "Processes and mechanisms for identifying users and authenticating access are defined and understood.",
            implementation:
              "Define authentication policy. Implement unique user IDs. Manage shared and group accounts with compensating controls.",
            evidence:
              "Authentication policy, unique ID assignment records, shared account controls.",
          },
          {
            id: "PCI-8.2",
            title: "User Identification Managed",
            description:
              "User identification and related accounts for users and administrators are strictly managed throughout the account lifecycle.",
            implementation:
              "Manage account lifecycle from creation to deletion. Disable inactive accounts within 90 days. Remove terminated user accounts promptly.",
            evidence:
              "Account lifecycle procedures, inactive account reports, termination processing records.",
          },
          {
            id: "PCI-8.3",
            title: "Strong Authentication Established",
            description:
              "Strong authentication for users and administrators is established and managed.",
            implementation:
              "Enforce minimum password length of 12 characters. Require complexity. Implement MFA for all access into the CDE. Lock accounts after failed attempts.",
            evidence:
              "Password policy configuration, MFA deployment, lockout settings.",
          },
          {
            id: "PCI-8.4",
            title: "Multi-Factor Authentication Implemented",
            description:
              "Multi-factor authentication (MFA) is implemented to secure access into the CDE.",
            implementation:
              "Deploy MFA for all non-console administrative access. Implement MFA for all remote network access. Use time-based or challenge-response MFA.",
            evidence:
              "MFA configuration, enrollment records, access logs showing MFA use.",
          },
          {
            id: "PCI-8.5",
            title: "MFA Systems Configured Properly",
            description:
              "Multi-factor authentication systems are configured to prevent misuse.",
            implementation:
              "Configure MFA to prevent replay attacks. Ensure MFA cannot be bypassed. Implement rate limiting on MFA attempts.",
            evidence:
              "MFA system configuration, replay attack prevention settings, bypass prevention controls.",
          },
          {
            id: "PCI-9.1",
            title: "Physical Access Controls Defined",
            description:
              "Processes and mechanisms for restricting physical access to cardholder data are defined and understood.",
            implementation:
              "Define physical security policy. Identify areas with cardholder data. Implement physical access controls.",
            evidence:
              "Physical security policy, CDE physical location inventory, access control configuration.",
          },
          {
            id: "PCI-9.2",
            title: "Physical Access Managed",
            description:
              "Physical access controls manage entry into facilities and systems containing cardholder data.",
            implementation:
              "Implement badge access for CDE. Distinguish between employees and visitors. Monitor physical access points.",
            evidence:
              "Badge system configuration, visitor procedures, access monitoring records.",
          },
          {
            id: "PCI-9.3",
            title: "Physical Access for Personnel and Visitors Controlled",
            description:
              "Physical access for personnel and visitors is authorized and managed.",
            implementation:
              "Authorize physical access based on job function. Escort visitors in sensitive areas. Revoke access upon termination.",
            evidence:
              "Authorization records, visitor escort logs, revocation records.",
          },
          {
            id: "PCI-9.4",
            title: "Media with Cardholder Data Secured",
            description:
              "Media with cardholder data is managed and secured.",
            implementation:
              "Classify and secure media containing cardholder data. Track media distribution. Destroy media when no longer needed.",
            evidence:
              "Media classification records, distribution logs, destruction certificates.",
          },
          {
            id: "PCI-9.5",
            title: "POI Devices Protected from Tampering",
            description:
              "Point-of-interaction (POI) devices are protected from tampering and unauthorized substitution.",
            implementation:
              "Maintain POI device inventory. Periodically inspect devices for tampering. Train personnel to detect tampering.",
            evidence:
              "POI inventory, inspection records, training records.",
          },
        ],
      },
      {
        name: "Regularly Monitor and Test Networks",
        description:
          "Requirements 10-11: Log and monitor all access to system components and cardholder data, and test security of systems and networks regularly.",
        controls: [
          {
            id: "PCI-10.1",
            title: "Logging and Monitoring Defined",
            description:
              "Processes and mechanisms for logging and monitoring all access to system components and cardholder data are defined and understood.",
            implementation:
              "Define logging policy. Implement log review process. Deploy centralized log management.",
            evidence:
              "Logging policy, review procedures, centralized log system deployment.",
          },
          {
            id: "PCI-10.2",
            title: "Audit Logs Implemented",
            description:
              "Audit logs are implemented to support the detection of anomalies and suspicious activity.",
            implementation:
              "Log all access to cardholder data. Log all administrative actions. Log authentication events. Include timestamp, user, event type, and result.",
            evidence:
              "Audit log configuration, sample log entries, log field documentation.",
          },
          {
            id: "PCI-10.3",
            title: "Audit Logs Protected",
            description:
              "Audit logs are protected from destruction and unauthorized modifications.",
            implementation:
              "Implement write-once storage. Restrict access to log systems. Monitor for log tampering. Back up logs to secure location.",
            evidence:
              "Log protection configuration, access restrictions, tamper detection, backup records.",
          },
          {
            id: "PCI-10.4",
            title: "Audit Logs Reviewed",
            description:
              "Audit logs are reviewed to identify anomalies or suspicious activity.",
            implementation:
              "Review logs daily using SIEM. Implement automated alerting. Investigate all anomalies. Document review results.",
            evidence:
              "SIEM configuration, alert rules, investigation records, review documentation.",
          },
          {
            id: "PCI-10.5",
            title: "Audit Log History Retained",
            description:
              "Audit log history is retained and available for analysis.",
            implementation:
              "Retain audit logs for at least 12 months. Keep at least 3 months immediately available for analysis.",
            evidence:
              "Retention configuration, log availability verification, storage capacity monitoring.",
          },
          {
            id: "PCI-10.6",
            title: "Time Synchronization",
            description:
              "Time-synchronization mechanisms support consistent time settings across all systems.",
            implementation:
              "Synchronize all system clocks using NTP. Use internal and external time sources. Monitor synchronization accuracy.",
            evidence:
              "NTP configuration, time source documentation, synchronization monitoring records.",
          },
          {
            id: "PCI-10.7",
            title: "Critical Security Control Failures Detected and Reported",
            description:
              "Failures of critical security control systems are detected, reported, and responded to promptly.",
            implementation:
              "Monitor security control health. Alert on control failures. Respond to failures per documented procedures.",
            evidence:
              "Control monitoring configuration, failure alerts, response records.",
          },
          {
            id: "PCI-11.1",
            title: "Security Testing Defined",
            description:
              "Processes and mechanisms for regularly testing security of systems and networks are defined and understood.",
            implementation:
              "Define security testing policy. Schedule regular testing activities. Document testing scope and methodology.",
            evidence:
              "Testing policy, testing schedule, scope documentation.",
          },
          {
            id: "PCI-11.2",
            title: "Wireless Access Points Managed",
            description:
              "Wireless access points are identified and monitored, and unauthorized wireless access points are addressed.",
            implementation:
              "Conduct quarterly wireless scans. Detect and investigate rogue access points. Maintain authorized wireless inventory.",
            evidence:
              "Wireless scan reports, rogue AP investigation records, wireless inventory.",
          },
          {
            id: "PCI-11.3",
            title: "Vulnerabilities Identified and Addressed",
            description:
              "External and internal vulnerabilities are regularly identified, prioritized, and addressed.",
            implementation:
              "Conduct quarterly internal and external vulnerability scans. Use ASV for external scans. Remediate critical and high vulnerabilities. Rescan to verify.",
            evidence:
              "Internal scan reports, ASV scan reports, remediation records, rescan results.",
          },
          {
            id: "PCI-11.4",
            title: "Penetration Testing Performed",
            description:
              "External and internal penetration testing is regularly performed, and exploitable vulnerabilities and security weaknesses are corrected.",
            implementation:
              "Conduct annual penetration testing (internal and external). Test network and application layers. Remediate findings and retest.",
            evidence:
              "Penetration test reports, remediation records, retest results.",
          },
          {
            id: "PCI-11.5",
            title: "Network Intrusions Detected and Responded To",
            description:
              "Network intrusions and unexpected file changes are detected and responded to.",
            implementation:
              "Deploy IDS/IPS at CDE perimeter. Implement file integrity monitoring. Alert on suspicious changes and intrusion attempts.",
            evidence:
              "IDS/IPS deployment, FIM configuration, alert records, response documentation.",
          },
          {
            id: "PCI-11.6",
            title: "Unauthorized Changes Detected and Responded To",
            description:
              "Unauthorized changes on payment pages are detected and responded to.",
            implementation:
              "Implement change detection on payment pages. Monitor for script injection. Alert on unauthorized modifications.",
            evidence:
              "Change detection configuration, monitoring logs, alert and response records.",
          },
        ],
      },
      {
        name: "Maintain an Information Security Policy",
        description:
          "Requirement 12: Support information security with organizational policies and programs.",
        controls: [
          {
            id: "PCI-12.1",
            title: "Information Security Policy Established",
            description:
              "A comprehensive information security policy that governs and provides direction for protection of the entity's information assets is known and current.",
            implementation:
              "Develop comprehensive information security policy. Review annually. Communicate to all personnel.",
            evidence:
              "Information security policy, review records, communication records.",
          },
          {
            id: "PCI-12.2",
            title: "Acceptable Use Policies Defined",
            description:
              "Acceptable use policies for end-user technologies are defined and implemented.",
            implementation:
              "Define acceptable use policies for all end-user technologies. Communicate and enforce policies.",
            evidence:
              "Acceptable use policies, acknowledgment records, enforcement records.",
          },
          {
            id: "PCI-12.3",
            title: "Risks to CDE Formally Managed",
            description:
              "Risks to the cardholder data environment are formally identified, evaluated, and managed.",
            implementation:
              "Conduct annual risk assessment. Identify threats and vulnerabilities to the CDE. Document and track risk treatment.",
            evidence:
              "Risk assessment reports, threat identification, risk treatment plans.",
          },
          {
            id: "PCI-12.4",
            title: "PCI DSS Compliance Managed",
            description:
              "PCI DSS compliance is managed.",
            implementation:
              "Assign PCI DSS compliance responsibility. Establish compliance management program. Conduct annual assessments.",
            evidence:
              "Compliance responsibility assignments, program documentation, assessment records.",
          },
          {
            id: "PCI-12.5",
            title: "PCI DSS Scope Documented",
            description:
              "PCI DSS scope is documented and validated.",
            implementation:
              "Document all in-scope systems, processes, and people. Validate scope annually or upon significant changes.",
            evidence:
              "Scope documentation, validation records, change impact assessments.",
          },
          {
            id: "PCI-12.6",
            title: "Security Awareness Education Ongoing",
            description:
              "Security awareness education is an ongoing activity.",
            implementation:
              "Conduct annual security awareness training for all personnel. Include PCI DSS-specific content. Track completion.",
            evidence:
              "Training materials, completion records, PCI-specific training content.",
          },
          {
            id: "PCI-12.7",
            title: "Personnel Screened",
            description:
              "Personnel are screened to reduce risks from insider threats.",
            implementation:
              "Conduct background checks on personnel with access to CDE. Screen before granting access.",
            evidence:
              "Background check records, screening policy, pre-access verification.",
          },
          {
            id: "PCI-12.8",
            title: "Third Party Service Providers Managed",
            description:
              "Risk to information assets associated with third-party service provider (TPSP) relationships is managed.",
            implementation:
              "Maintain inventory of TPSPs. Include PCI DSS requirements in contracts. Monitor TPSP compliance annually.",
            evidence:
              "TPSP inventory, contract requirements, compliance monitoring records.",
          },
          {
            id: "PCI-12.9",
            title: "TPSPs Acknowledge Responsibilities",
            description:
              "Third-party service providers (TPSPs) support their customers' PCI DSS compliance.",
            implementation:
              "Obtain written acknowledgment from TPSPs of their PCI DSS responsibilities. Monitor TPSP compliance status.",
            evidence:
              "TPSP acknowledgment letters, compliance status reports.",
          },
          {
            id: "PCI-12.10",
            title: "Incident Response Plan Ready",
            description:
              "Suspected and confirmed security incidents that could impact the CDE are responded to immediately.",
            implementation:
              "Develop incident response plan covering payment card breaches. Define escalation procedures. Test plan annually.",
            evidence:
              "Incident response plan, escalation procedures, annual test results.",
          },
        ],
      },
    ],
  },

  // =========================================================================
  // (e) SOC 2
  // =========================================================================
  {
    name: "SOC 2",
    org: "American Institute of Certified Public Accountants (AICPA)",
    version: "2017 Trust Services Criteria",
    description:
      "SOC 2 is an auditing procedure that ensures service providers securely manage data to protect the interests of the organization and the privacy of its clients. Based on five Trust Service Criteria: Security, Availability, Processing Integrity, Confidentiality, and Privacy.",
    domains: [
      {
        name: "Security (Common Criteria)",
        description:
          "The system is protected against unauthorized access, unauthorized disclosure of information, and damage to systems that could compromise the availability, integrity, confidentiality, and privacy of information.",
        controls: [
          {
            id: "CC1.1",
            title: "COSO Principle 1 - Integrity and Ethical Values",
            description:
              "The entity demonstrates a commitment to integrity and ethical values.",
            implementation:
              "Establish code of conduct. Define and communicate ethical standards. Implement whistleblower mechanisms.",
            evidence:
              "Code of conduct, ethical standards documentation, whistleblower policy.",
          },
          {
            id: "CC1.2",
            title: "COSO Principle 2 - Board Independence",
            description:
              "The board of directors demonstrates independence from management and exercises oversight of the development and performance of internal control.",
            implementation:
              "Establish independent board oversight. Define board committees for risk and security. Conduct regular board briefings.",
            evidence:
              "Board charter, committee documentation, briefing records.",
          },
          {
            id: "CC1.3",
            title: "COSO Principle 3 - Management Oversight",
            description:
              "Management establishes, with board oversight, structures, reporting lines, and appropriate authorities and responsibilities.",
            implementation:
              "Define organizational structure for security. Establish clear reporting lines. Assign authorities and responsibilities.",
            evidence:
              "Organization charts, reporting structures, responsibility assignments.",
          },
          {
            id: "CC1.4",
            title: "COSO Principle 4 - Competent Personnel",
            description:
              "The entity demonstrates a commitment to attract, develop, and retain competent individuals in alignment with objectives.",
            implementation:
              "Define competency requirements for security roles. Provide training and development. Conduct performance evaluations.",
            evidence:
              "Job descriptions, training records, performance evaluation records.",
          },
          {
            id: "CC1.5",
            title: "COSO Principle 5 - Accountability",
            description:
              "The entity holds individuals accountable for their internal control responsibilities.",
            implementation:
              "Define accountability mechanisms. Implement performance measures for security responsibilities. Apply corrective actions.",
            evidence:
              "Accountability framework, performance measures, corrective action records.",
          },
          {
            id: "CC2.1",
            title: "Information and Communication - Internal",
            description:
              "The entity obtains or generates and uses relevant, quality information to support the functioning of internal control.",
            implementation:
              "Implement information management processes. Define data quality requirements. Distribute security information internally.",
            evidence:
              "Information management procedures, data quality standards, internal communications.",
          },
          {
            id: "CC2.2",
            title: "Information and Communication - Internal Communication",
            description:
              "The entity internally communicates information, including objectives and responsibilities for internal control, necessary to support the functioning of internal control.",
            implementation:
              "Communicate security policies and procedures. Provide regular security updates. Ensure security awareness across the organization.",
            evidence:
              "Communication records, policy distribution logs, awareness materials.",
          },
          {
            id: "CC2.3",
            title: "Information and Communication - External",
            description:
              "The entity communicates with external parties regarding matters affecting the functioning of internal control.",
            implementation:
              "Communicate with external stakeholders on security matters. Publish security commitments. Report incidents to affected parties.",
            evidence:
              "External communication records, published commitments, incident notifications.",
          },
          {
            id: "CC3.1",
            title: "Risk Assessment - Objectives",
            description:
              "The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks relating to objectives.",
            implementation:
              "Define security objectives aligned with business goals. Specify measurable criteria for objective achievement.",
            evidence:
              "Security objectives documentation, measurement criteria, alignment records.",
          },
          {
            id: "CC3.2",
            title: "Risk Assessment - Risk Identification",
            description:
              "The entity identifies risks to the achievement of its objectives across the entity and analyzes risks as a basis for determining how the risks should be managed.",
            implementation:
              "Conduct comprehensive risk assessments. Identify internal and external threats. Analyze risk likelihood and impact.",
            evidence:
              "Risk assessment reports, threat catalogs, risk analysis documentation.",
          },
          {
            id: "CC3.3",
            title: "Risk Assessment - Fraud Risk",
            description:
              "The entity considers the potential for fraud in assessing risks to the achievement of objectives.",
            implementation:
              "Include fraud risk in risk assessments. Identify fraud schemes relevant to the organization. Implement anti-fraud controls.",
            evidence:
              "Fraud risk assessments, fraud scheme documentation, anti-fraud control records.",
          },
          {
            id: "CC3.4",
            title: "Risk Assessment - Change Identification",
            description:
              "The entity identifies and assesses changes that could significantly impact the system of internal control.",
            implementation:
              "Monitor for significant changes. Assess impact of changes on security controls. Update risk assessments accordingly.",
            evidence:
              "Change monitoring records, impact assessments, updated risk assessments.",
          },
          {
            id: "CC4.1",
            title: "Monitoring Activities - Ongoing Evaluations",
            description:
              "The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning.",
            implementation:
              "Implement continuous monitoring. Conduct periodic security assessments. Track control effectiveness metrics.",
            evidence:
              "Monitoring configuration, assessment reports, control effectiveness metrics.",
          },
          {
            id: "CC4.2",
            title: "Monitoring Activities - Deficiency Communication",
            description:
              "The entity evaluates and communicates internal control deficiencies in a timely manner to those parties responsible for taking corrective action.",
            implementation:
              "Report control deficiencies to appropriate stakeholders. Track remediation progress. Escalate unresolved deficiencies.",
            evidence:
              "Deficiency reports, remediation tracking, escalation records.",
          },
          {
            id: "CC5.1",
            title: "Control Activities - Selection",
            description:
              "The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels.",
            implementation:
              "Select controls based on risk assessment results. Implement preventive and detective controls. Document control design rationale.",
            evidence:
              "Control selection documentation, implementation records, design rationale.",
          },
          {
            id: "CC5.2",
            title: "Control Activities - Technology Controls",
            description:
              "The entity also selects and develops general control activities over technology to support the achievement of objectives.",
            implementation:
              "Implement technology controls for access management, change management, and operations. Deploy security technologies.",
            evidence:
              "Technology control inventory, configuration records, deployment documentation.",
          },
          {
            id: "CC5.3",
            title: "Control Activities - Policies and Procedures",
            description:
              "The entity deploys control activities through policies that establish what is expected and in procedures that put policies into action.",
            implementation:
              "Develop and publish security policies and procedures. Train personnel on procedures. Monitor compliance.",
            evidence:
              "Policy documents, procedure documentation, training records, compliance monitoring.",
          },
          {
            id: "CC6.1",
            title: "Logical and Physical Access Controls",
            description:
              "The entity implements logical access security software, infrastructure, and architectures over protected information assets.",
            implementation:
              "Implement identity and access management. Deploy authentication mechanisms. Configure authorization controls.",
            evidence:
              "IAM configuration, authentication settings, authorization policies.",
          },
          {
            id: "CC6.2",
            title: "User Registration and Authorization",
            description:
              "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.",
            implementation:
              "Implement user registration process. Require management approval for access. Verify identity before credential issuance.",
            evidence:
              "Registration procedures, approval records, identity verification records.",
          },
          {
            id: "CC6.3",
            title: "Role-Based Access",
            description:
              "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system design and changes.",
            implementation:
              "Implement RBAC. Modify access based on role changes. Remove access upon role change or termination.",
            evidence:
              "RBAC configuration, access modification records, termination processing.",
          },
          {
            id: "CC6.6",
            title: "System Boundary Protection",
            description:
              "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
            implementation:
              "Deploy firewalls and IDS/IPS at system boundaries. Implement network segmentation. Monitor boundary traffic.",
            evidence:
              "Firewall configuration, IDS/IPS deployment, segmentation design, traffic monitoring.",
          },
          {
            id: "CC6.7",
            title: "Data Transmission Restrictions",
            description:
              "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.",
            implementation:
              "Implement DLP controls. Restrict data transfer methods. Encrypt data in transit. Monitor data movements.",
            evidence:
              "DLP configuration, transfer restriction settings, encryption configuration, monitoring logs.",
          },
          {
            id: "CC6.8",
            title: "Malicious Software Prevention",
            description:
              "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.",
            implementation:
              "Deploy anti-malware solutions. Implement application whitelisting. Scan email attachments and downloads.",
            evidence:
              "Anti-malware deployment, whitelist configuration, scanning records.",
          },
          {
            id: "CC7.1",
            title: "Infrastructure and Software Monitoring",
            description:
              "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.",
            implementation:
              "Monitor configuration changes. Conduct vulnerability scanning. Implement change detection mechanisms.",
            evidence:
              "Configuration monitoring tools, vulnerability scan reports, change detection records.",
          },
          {
            id: "CC7.2",
            title: "Anomaly Monitoring",
            description:
              "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors.",
            implementation:
              "Implement SIEM with anomaly detection. Monitor system logs and performance metrics. Alert on anomalous behavior.",
            evidence:
              "SIEM configuration, anomaly detection rules, alert records.",
          },
          {
            id: "CC7.3",
            title: "Security Event Evaluation",
            description:
              "The entity evaluates detected security events and determines whether they could or have resulted in a failure of the entity to meet its objectives and quantifies the effect thereof.",
            implementation:
              "Triage security events. Assess potential impact. Classify events and determine incident status.",
            evidence:
              "Event triage records, impact assessments, classification records.",
          },
          {
            id: "CC7.4",
            title: "Incident Response",
            description:
              "The entity responds to identified security incidents by executing a defined incident response program.",
            implementation:
              "Execute incident response procedures. Contain and eradicate threats. Recover affected systems. Conduct post-incident review.",
            evidence:
              "Incident response records, containment actions, recovery records, post-incident reviews.",
          },
          {
            id: "CC7.5",
            title: "Incident Recovery",
            description:
              "The entity identifies, develops, and implements activities to recover from identified security incidents.",
            implementation:
              "Implement recovery procedures. Restore systems from backups. Validate recovery completeness. Resume normal operations.",
            evidence:
              "Recovery procedures, restoration records, validation results.",
          },
          {
            id: "CC8.1",
            title: "Change Management",
            description:
              "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.",
            implementation:
              "Implement formal change management process. Require change authorization. Test changes before deployment. Document all changes.",
            evidence:
              "Change management procedures, authorization records, test results, change documentation.",
          },
          {
            id: "CC9.1",
            title: "Risk Mitigation",
            description:
              "The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.",
            implementation:
              "Identify business disruption risks. Develop mitigation strategies. Implement business continuity plans.",
            evidence:
              "Risk mitigation plans, business continuity plans, strategy documentation.",
          },
          {
            id: "CC9.2",
            title: "Vendor and Business Partner Risk Management",
            description:
              "The entity assesses and manages risks associated with vendors and business partners.",
            implementation:
              "Assess vendor security posture. Include security requirements in contracts. Monitor vendor compliance.",
            evidence:
              "Vendor assessments, contract requirements, compliance monitoring records.",
          },
        ],
      },
      {
        name: "Availability",
        description:
          "The system is available for operation and use as committed or agreed.",
        controls: [
          {
            id: "A1.1",
            title: "Capacity Planning",
            description:
              "The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand.",
            implementation:
              "Monitor system capacity. Plan for capacity growth. Implement auto-scaling where applicable.",
            evidence:
              "Capacity monitoring reports, planning documents, auto-scaling configuration.",
          },
          {
            id: "A1.2",
            title: "Recovery Planning and Testing",
            description:
              "The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup, and recovery infrastructure.",
            implementation:
              "Implement disaster recovery infrastructure. Test DR plans regularly. Maintain backup systems.",
            evidence:
              "DR infrastructure documentation, test results, backup system records.",
          },
          {
            id: "A1.3",
            title: "Recovery Procedures Testing",
            description:
              "The entity tests recovery plan procedures supporting system recovery to meet its objectives.",
            implementation:
              "Conduct regular DR tests. Validate recovery time objectives. Document test results and improvements.",
            evidence:
              "DR test plans, test results, RTO validation records, improvement documentation.",
          },
        ],
      },
      {
        name: "Processing Integrity",
        description:
          "System processing is complete, valid, accurate, timely, and authorized.",
        controls: [
          {
            id: "PI1.1",
            title: "Processing Quality Objectives",
            description:
              "The entity obtains or generates, uses, and communicates relevant, quality information regarding the objectives related to processing to support the use of the products or services.",
            implementation:
              "Define processing quality objectives. Implement input, processing, and output controls. Monitor processing integrity.",
            evidence:
              "Quality objectives documentation, control implementation records, monitoring reports.",
          },
          {
            id: "PI1.2",
            title: "Processing Accuracy and Completeness",
            description:
              "The entity implements policies and procedures over system inputs, including controls over completeness and accuracy.",
            implementation:
              "Implement input validation. Conduct reconciliation checks. Verify output accuracy. Monitor for processing errors.",
            evidence:
              "Validation rules, reconciliation reports, accuracy verification, error monitoring.",
          },
          {
            id: "PI1.3",
            title: "Processing Error Identification",
            description:
              "The entity implements policies and procedures to make available or deliver output completely, accurately, and timely in accordance with specifications to meet the entity's objectives.",
            implementation:
              "Implement output verification controls. Define delivery specifications. Monitor for delivery failures.",
            evidence:
              "Output verification records, delivery specifications, failure monitoring.",
          },
        ],
      },
      {
        name: "Confidentiality",
        description:
          "Information designated as confidential is protected as committed or agreed.",
        controls: [
          {
            id: "C1.1",
            title: "Confidential Information Identification",
            description:
              "The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality.",
            implementation:
              "Classify information by sensitivity. Tag and label confidential information. Maintain confidentiality requirements.",
            evidence:
              "Classification policy, tagged information inventory, confidentiality requirements.",
          },
          {
            id: "C1.2",
            title: "Confidential Information Disposal",
            description:
              "The entity disposes of confidential information to meet the entity's objectives related to confidentiality.",
            implementation:
              "Implement secure disposal procedures. Verify disposal completion. Maintain disposal records.",
            evidence:
              "Disposal procedures, verification records, disposal certificates.",
          },
        ],
      },
      {
        name: "Privacy",
        description:
          "Personal information is collected, used, retained, disclosed, and disposed of to meet the entity's objectives.",
        controls: [
          {
            id: "P1.1",
            title: "Privacy Notice",
            description:
              "The entity provides notice to data subjects about its privacy practices.",
            implementation:
              "Publish privacy notice. Include purpose, collection methods, use, sharing, and rights. Update as practices change.",
            evidence:
              "Privacy notice, publication records, update history.",
          },
          {
            id: "P2.1",
            title: "Choice and Consent",
            description:
              "The entity communicates choices available regarding the collection, use, retention, disclosure, and disposal of personal information.",
            implementation:
              "Provide opt-in/opt-out mechanisms. Obtain explicit consent where required. Document consent records.",
            evidence:
              "Consent mechanisms, consent records, choice documentation.",
          },
          {
            id: "P3.1",
            title: "Personal Information Collection",
            description:
              "Personal information is collected consistent with the entity's objectives related to privacy.",
            implementation:
              "Collect only necessary personal information. Document collection purposes. Implement data minimization.",
            evidence:
              "Collection procedures, purpose documentation, minimization records.",
          },
          {
            id: "P4.1",
            title: "Personal Information Use",
            description:
              "The entity limits the use of personal information to the purposes identified in the entity's objectives related to privacy.",
            implementation:
              "Limit use to stated purposes. Implement use restrictions. Monitor for unauthorized use.",
            evidence:
              "Use limitation policies, restriction configuration, monitoring records.",
          },
          {
            id: "P5.1",
            title: "Personal Information Retention and Disposal",
            description:
              "The entity retains personal information consistent with the entity's objectives related to privacy.",
            implementation:
              "Define retention periods. Implement automated disposal. Verify disposal completion.",
            evidence:
              "Retention schedules, automated disposal configuration, verification records.",
          },
          {
            id: "P6.1",
            title: "Personal Information Access",
            description:
              "The entity provides data subjects with access to their personal information for review and update.",
            implementation:
              "Implement data subject access request procedures. Provide self-service access. Respond within required timelines.",
            evidence:
              "DSAR procedures, access portal, response timeline records.",
          },
          {
            id: "P6.2",
            title: "Personal Information Correction",
            description:
              "The entity corrects, amends, or appends personal information based on information provided by data subjects.",
            implementation:
              "Implement correction request procedures. Process corrections promptly. Notify third parties of corrections.",
            evidence:
              "Correction procedures, processing records, third-party notifications.",
          },
          {
            id: "P7.1",
            title: "Personal Information Disclosure",
            description:
              "The entity discloses personal information to third parties with the consent of the data subject.",
            implementation:
              "Obtain consent before disclosure. Document disclosures. Implement data processing agreements with recipients.",
            evidence:
              "Consent records, disclosure logs, data processing agreements.",
          },
          {
            id: "P8.1",
            title: "Privacy Incident Management",
            description:
              "The entity implements a process for receiving, addressing, resolving, and communicating the resolution of inquiries, complaints, and disputes from data subjects.",
            implementation:
              "Implement privacy incident response process. Handle complaints per procedures. Track and resolve disputes.",
            evidence:
              "Incident response procedures, complaint records, resolution documentation.",
          },
        ],
      },
    ],
  },

  // =========================================================================
  // (f) HIPAA
  // =========================================================================
  {
    name: "HIPAA",
    org: "U.S. Department of Health and Human Services (HHS)",
    version: "Security Rule - 45 CFR Part 164",
    description:
      "The Health Insurance Portability and Accountability Act (HIPAA) Security Rule establishes national standards to protect electronic personal health information (ePHI). It requires appropriate administrative, physical, and technical safeguards to ensure the confidentiality, integrity, and security of ePHI.",
    domains: [
      {
        name: "Administrative Safeguards",
        description:
          "Administrative actions, policies, and procedures to manage the selection, development, implementation, and maintenance of security measures to protect ePHI.",
        controls: [
          {
            id: "164.308(a)(1)",
            title: "Security Management Process",
            description:
              "Implement policies and procedures to prevent, detect, contain, and correct security violations.",
            implementation:
              "Conduct risk analysis. Implement risk management program. Apply sanctions for violations. Review information system activity.",
            evidence:
              "Risk analysis report, risk management plan, sanction policy, activity review records.",
          },
          {
            id: "164.308(a)(2)",
            title: "Assigned Security Responsibility",
            description:
              "Identify the security official who is responsible for the development and implementation of security policies and procedures.",
            implementation:
              "Designate a HIPAA Security Officer. Define security responsibilities. Ensure adequate authority and resources.",
            evidence:
              "Security officer designation, role description, authority documentation.",
          },
          {
            id: "164.308(a)(3)",
            title: "Workforce Security",
            description:
              "Implement policies and procedures to ensure that all members of the workforce have appropriate access to ePHI.",
            implementation:
              "Implement authorization procedures. Establish workforce clearance procedures. Define termination procedures for access revocation.",
            evidence:
              "Authorization procedures, clearance records, termination checklists.",
          },
          {
            id: "164.308(a)(4)",
            title: "Information Access Management",
            description:
              "Implement policies and procedures for authorizing access to ePHI.",
            implementation:
              "Implement access authorization policies. Establish procedures for granting access. Conduct access reviews.",
            evidence:
              "Access authorization policy, access request forms, review records.",
          },
          {
            id: "164.308(a)(5)",
            title: "Security Awareness and Training",
            description:
              "Implement a security awareness and training program for all workforce members.",
            implementation:
              "Conduct HIPAA security training at hire and annually. Include phishing awareness, password management, and incident reporting.",
            evidence:
              "Training program, completion records, training materials, phishing test results.",
          },
          {
            id: "164.308(a)(6)",
            title: "Security Incident Procedures",
            description:
              "Implement policies and procedures to address security incidents.",
            implementation:
              "Develop incident response plan. Define incident identification and reporting procedures. Document and respond to incidents.",
            evidence:
              "Incident response plan, incident reports, response documentation.",
          },
          {
            id: "164.308(a)(7)",
            title: "Contingency Plan",
            description:
              "Establish and implement policies and procedures for responding to an emergency or other occurrence that damages systems containing ePHI.",
            implementation:
              "Develop data backup plan. Develop disaster recovery plan. Develop emergency mode operation plan. Test and update plans regularly.",
            evidence:
              "Backup plan, DR plan, emergency mode plan, testing records, plan updates.",
          },
          {
            id: "164.308(a)(8)",
            title: "Evaluation",
            description:
              "Perform a periodic technical and nontechnical evaluation based on standards and in response to environmental or operational changes.",
            implementation:
              "Conduct periodic HIPAA security evaluations. Assess compliance with security rules. Identify and remediate gaps.",
            evidence:
              "Evaluation reports, compliance assessments, gap remediation records.",
          },
          {
            id: "164.308(b)(1)",
            title: "Business Associate Contracts",
            description:
              "A covered entity may permit a business associate to create, receive, maintain, or transmit ePHI only if the covered entity obtains satisfactory assurances.",
            implementation:
              "Execute Business Associate Agreements (BAAs). Include required security provisions. Monitor BA compliance.",
            evidence:
              "BAAs, security provisions, compliance monitoring records.",
          },
        ],
      },
      {
        name: "Physical Safeguards",
        description:
          "Physical measures, policies, and procedures to protect electronic information systems and related buildings and equipment from natural and environmental hazards and unauthorized intrusion.",
        controls: [
          {
            id: "164.310(a)(1)",
            title: "Facility Access Controls",
            description:
              "Implement policies and procedures to limit physical access to electronic information systems and the facilities in which they are housed.",
            implementation:
              "Develop contingency operations procedures. Implement facility security plan. Control and validate visitor access. Maintain maintenance records.",
            evidence:
              "Facility security plan, access control records, visitor logs, maintenance records.",
          },
          {
            id: "164.310(b)",
            title: "Workstation Use",
            description:
              "Implement policies and procedures that specify the proper functions to be performed and the manner in which those functions are to be performed.",
            implementation:
              "Define workstation use policy. Restrict workstation access to authorized users. Define acceptable use for ePHI access.",
            evidence:
              "Workstation use policy, access restrictions, acceptable use documentation.",
          },
          {
            id: "164.310(c)",
            title: "Workstation Security",
            description:
              "Implement physical safeguards for all workstations that access ePHI to restrict access to authorized users.",
            implementation:
              "Physically secure workstations. Implement cable locks for portable devices. Position screens to prevent unauthorized viewing.",
            evidence:
              "Physical security measures, cable lock deployment, screen positioning documentation.",
          },
          {
            id: "164.310(d)(1)",
            title: "Device and Media Controls",
            description:
              "Implement policies and procedures that govern the receipt and removal of hardware and electronic media that contain ePHI.",
            implementation:
              "Implement disposal procedures for ePHI-containing media. Develop media re-use procedures. Maintain accountability and track data backups.",
            evidence:
              "Disposal procedures, media re-use procedures, accountability records, backup tracking.",
          },
        ],
      },
      {
        name: "Technical Safeguards",
        description:
          "The technology and the policy and procedures for its use that protect ePHI and control access to it.",
        controls: [
          {
            id: "164.312(a)(1)",
            title: "Access Control",
            description:
              "Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons or software programs.",
            implementation:
              "Assign unique user IDs. Implement emergency access procedures. Enable automatic logoff. Encrypt ePHI.",
            evidence:
              "Unique ID assignments, emergency access procedures, logoff settings, encryption configuration.",
          },
          {
            id: "164.312(b)",
            title: "Audit Controls",
            description:
              "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI.",
            implementation:
              "Enable audit logging on all ePHI systems. Record access events. Review audit logs regularly.",
            evidence:
              "Audit log configuration, access event records, log review records.",
          },
          {
            id: "164.312(c)(1)",
            title: "Integrity",
            description:
              "Implement policies and procedures to protect ePHI from improper alteration or destruction.",
            implementation:
              "Implement mechanisms to authenticate ePHI. Detect unauthorized alterations. Use checksums and digital signatures.",
            evidence:
              "Integrity mechanisms, alteration detection configuration, verification records.",
          },
          {
            id: "164.312(d)",
            title: "Person or Entity Authentication",
            description:
              "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.",
            implementation:
              "Implement multi-factor authentication. Verify identity before granting ePHI access. Use strong authentication mechanisms.",
            evidence:
              "MFA configuration, identity verification procedures, authentication records.",
          },
          {
            id: "164.312(e)(1)",
            title: "Transmission Security",
            description:
              "Implement technical security measures to guard against unauthorized access to ePHI that is being transmitted over an electronic communications network.",
            implementation:
              "Implement integrity controls for ePHI in transit. Encrypt ePHI during transmission using TLS 1.2 or higher.",
            evidence:
              "Encryption configuration, TLS settings, transmission security documentation.",
          },
        ],
      },
      {
        name: "Organizational Requirements",
        description:
          "Requirements related to business associate agreements and group health plan documentation.",
        controls: [
          {
            id: "164.314(a)",
            title: "Business Associate Contracts or Other Arrangements",
            description:
              "The contract or other arrangement between the covered entity and its business associate must meet requirements.",
            implementation:
              "Execute BAAs with all business associates. Include required provisions (breach notification, termination, return/destroy). Review annually.",
            evidence:
              "BAA inventory, BAA documents, annual review records.",
          },
          {
            id: "164.314(b)",
            title: "Requirements for Group Health Plans",
            description:
              "Group health plans must include certain provisions in plan documents regarding the handling of ePHI.",
            implementation:
              "Include HIPAA security provisions in group health plan documents. Define plan sponsor obligations.",
            evidence:
              "Plan documents, security provisions, sponsor obligation documentation.",
          },
        ],
      },
      {
        name: "Policies, Procedures, and Documentation Requirements",
        description:
          "Requirements for maintaining written policies, procedures, and documentation.",
        controls: [
          {
            id: "164.316(a)",
            title: "Policies and Procedures",
            description:
              "Implement reasonable and appropriate policies and procedures to comply with the standards, implementation specifications, and other requirements.",
            implementation:
              "Develop and maintain HIPAA security policies and procedures. Review and update as needed based on environmental changes.",
            evidence:
              "Policy documents, procedure documents, review and update records.",
          },
          {
            id: "164.316(b)(1)",
            title: "Documentation",
            description:
              "Maintain the policies and procedures implemented to comply with this subpart in written (which may be electronic) form.",
            implementation:
              "Maintain written documentation for 6 years from creation or last effective date. Make documentation available to responsible persons.",
            evidence:
              "Documentation inventory, retention records, availability verification.",
          },
        ],
      },
    ],
  },

  // =========================================================================
  // (g) GDPR
  // =========================================================================
  {
    name: "GDPR",
    org: "European Union",
    version: "Regulation (EU) 2016/679",
    description:
      "The General Data Protection Regulation is a regulation on data protection and privacy in the European Union and the European Economic Area. It addresses the transfer of personal data outside the EU and EEA areas. GDPR gives individuals control over their personal data and simplifies the regulatory environment for international business.",
    domains: [
      {
        name: "Principles of Processing",
        description:
          "Core principles that govern the processing of personal data under GDPR.",
        controls: [
          {
            id: "Art.5(1)(a)",
            title: "Lawfulness, Fairness and Transparency",
            description:
              "Personal data shall be processed lawfully, fairly, and in a transparent manner in relation to the data subject.",
            implementation:
              "Identify lawful basis for each processing activity. Provide clear privacy notices. Ensure fair processing practices.",
            evidence:
              "Lawful basis register, privacy notices, processing records.",
          },
          {
            id: "Art.5(1)(b)",
            title: "Purpose Limitation",
            description:
              "Personal data shall be collected for specified, explicit, and legitimate purposes and not further processed in a manner incompatible with those purposes.",
            implementation:
              "Document purposes for each processing activity. Assess compatibility before new uses. Implement purpose limitation controls.",
            evidence:
              "Purpose documentation, compatibility assessments, processing limitation records.",
          },
          {
            id: "Art.5(1)(c)",
            title: "Data Minimization",
            description:
              "Personal data shall be adequate, relevant, and limited to what is necessary in relation to the purposes for which they are processed.",
            implementation:
              "Review data collection for necessity. Remove unnecessary data fields. Implement collection limitation controls.",
            evidence:
              "Data minimization reviews, field justification records, collection limitation documentation.",
          },
          {
            id: "Art.5(1)(d)",
            title: "Accuracy",
            description:
              "Personal data shall be accurate and, where necessary, kept up to date.",
            implementation:
              "Implement data quality procedures. Provide mechanisms for data subjects to update their data. Conduct accuracy reviews.",
            evidence:
              "Data quality procedures, update mechanisms, accuracy review records.",
          },
          {
            id: "Art.5(1)(e)",
            title: "Storage Limitation",
            description:
              "Personal data shall be kept in a form which permits identification of data subjects for no longer than is necessary.",
            implementation:
              "Define retention periods for each data category. Implement automated deletion. Anonymize data where possible.",
            evidence:
              "Retention schedules, automated deletion configuration, anonymization records.",
          },
          {
            id: "Art.5(1)(f)",
            title: "Integrity and Confidentiality",
            description:
              "Personal data shall be processed in a manner that ensures appropriate security, including protection against unauthorized or unlawful processing and against accidental loss, destruction, or damage.",
            implementation:
              "Implement technical and organizational security measures. Encrypt personal data. Apply access controls.",
            evidence:
              "Security measures documentation, encryption configuration, access control records.",
          },
          {
            id: "Art.5(2)",
            title: "Accountability",
            description:
              "The controller shall be responsible for, and be able to demonstrate compliance with, the processing principles.",
            implementation:
              "Maintain records of processing activities. Conduct DPIAs. Implement compliance monitoring. Document compliance efforts.",
            evidence:
              "ROPA, DPIA reports, compliance monitoring records, accountability documentation.",
          },
        ],
      },
      {
        name: "Lawful Basis and Consent",
        description:
          "Requirements for establishing lawful basis for processing and obtaining valid consent.",
        controls: [
          {
            id: "Art.6",
            title: "Lawfulness of Processing",
            description:
              "Processing shall be lawful only if at least one of the specified conditions applies (consent, contract, legal obligation, vital interests, public task, legitimate interests).",
            implementation:
              "Document the lawful basis for each processing activity. Conduct legitimate interest assessments where applicable. Review lawful basis periodically.",
            evidence:
              "Lawful basis documentation, legitimate interest assessments, periodic review records.",
          },
          {
            id: "Art.7",
            title: "Conditions for Consent",
            description:
              "Where processing is based on consent, the controller shall be able to demonstrate that the data subject has consented. Consent must be freely given, specific, informed, and unambiguous.",
            implementation:
              "Implement granular consent mechanisms. Record consent with timestamp and details. Provide easy withdrawal of consent.",
            evidence:
              "Consent mechanisms, consent records, withdrawal procedures.",
          },
          {
            id: "Art.8",
            title: "Child's Consent",
            description:
              "Where consent is the basis, for information society services offered directly to a child, processing is lawful only where the child is at least 16 years old (or as low as 13 per member state).",
            implementation:
              "Implement age verification mechanisms. Obtain parental consent for children below the applicable age. Document age verification process.",
            evidence:
              "Age verification mechanisms, parental consent records, process documentation.",
          },
          {
            id: "Art.9",
            title: "Processing of Special Categories of Data",
            description:
              "Processing of special categories of personal data (racial or ethnic origin, political opinions, religious beliefs, health data, biometric data, etc.) is prohibited except under specific conditions.",
            implementation:
              "Identify special category data processing. Ensure explicit consent or other legal basis. Implement enhanced security measures.",
            evidence:
              "Special category data inventory, legal basis documentation, enhanced security measures.",
          },
        ],
      },
      {
        name: "Data Subject Rights",
        description:
          "Rights of individuals regarding the processing of their personal data.",
        controls: [
          {
            id: "Art.12",
            title: "Transparent Information and Communication",
            description:
              "The controller shall take appropriate measures to provide any information and any communication relating to processing in a concise, transparent, intelligible, and easily accessible form.",
            implementation:
              "Use clear and plain language in privacy communications. Provide information in accessible formats. Respond to requests within one month.",
            evidence:
              "Privacy notices, communication templates, response timeline records.",
          },
          {
            id: "Art.13",
            title: "Information to be Provided at Collection",
            description:
              "Where personal data are collected from the data subject, the controller shall provide specified information at the time when personal data are obtained.",
            implementation:
              "Provide privacy notice at point of collection including controller identity, purposes, lawful basis, recipients, retention, and rights.",
            evidence:
              "Collection-point privacy notices, information provision records.",
          },
          {
            id: "Art.15",
            title: "Right of Access",
            description:
              "The data subject shall have the right to obtain from the controller confirmation as to whether personal data concerning them are being processed, and access to the data.",
            implementation:
              "Implement subject access request (SAR) procedures. Provide data in commonly used electronic format. Respond within one month.",
            evidence:
              "SAR procedures, response records, data provision documentation.",
          },
          {
            id: "Art.16",
            title: "Right to Rectification",
            description:
              "The data subject shall have the right to obtain from the controller without undue delay the rectification of inaccurate personal data.",
            implementation:
              "Implement rectification request procedures. Update records promptly. Notify recipients of rectifications.",
            evidence:
              "Rectification procedures, update records, recipient notifications.",
          },
          {
            id: "Art.17",
            title: "Right to Erasure (Right to be Forgotten)",
            description:
              "The data subject shall have the right to obtain from the controller the erasure of personal data concerning them without undue delay under specific conditions.",
            implementation:
              "Implement erasure request procedures. Assess legal grounds for erasure. Delete data and notify processors. Handle exceptions.",
            evidence:
              "Erasure procedures, assessment records, deletion confirmations, exception documentation.",
          },
          {
            id: "Art.18",
            title: "Right to Restriction of Processing",
            description:
              "The data subject shall have the right to obtain from the controller restriction of processing under certain conditions.",
            implementation:
              "Implement processing restriction procedures. Mark restricted data. Limit processing to storage only during restriction.",
            evidence:
              "Restriction procedures, data marking records, processing limitation documentation.",
          },
          {
            id: "Art.20",
            title: "Right to Data Portability",
            description:
              "The data subject shall have the right to receive the personal data concerning them in a structured, commonly used, and machine-readable format.",
            implementation:
              "Implement data portability procedures. Provide data in machine-readable formats (JSON, CSV). Enable direct transfer to other controllers where feasible.",
            evidence:
              "Portability procedures, export functionality, format documentation.",
          },
          {
            id: "Art.21",
            title: "Right to Object",
            description:
              "The data subject shall have the right to object at any time to processing of personal data concerning them based on legitimate interests or for direct marketing.",
            implementation:
              "Implement objection handling procedures. Cease processing upon objection unless compelling grounds exist. Provide opt-out for direct marketing.",
            evidence:
              "Objection procedures, processing cessation records, marketing opt-out mechanisms.",
          },
          {
            id: "Art.22",
            title: "Automated Individual Decision-Making Including Profiling",
            description:
              "The data subject shall have the right not to be subject to a decision based solely on automated processing, including profiling, which produces legal or similarly significant effects.",
            implementation:
              "Identify automated decision-making processes. Implement human oversight. Provide data subjects the right to contest decisions.",
            evidence:
              "Automated decision inventory, oversight documentation, contest mechanism.",
          },
        ],
      },
      {
        name: "Controller and Processor Obligations",
        description:
          "Responsibilities of data controllers and processors under GDPR.",
        controls: [
          {
            id: "Art.24",
            title: "Responsibility of the Controller",
            description:
              "The controller shall implement appropriate technical and organizational measures to ensure and demonstrate that processing is performed in accordance with GDPR.",
            implementation:
              "Implement data protection policies. Conduct regular compliance reviews. Maintain processing records and documentation.",
            evidence:
              "Data protection policies, compliance review records, processing documentation.",
          },
          {
            id: "Art.25",
            title: "Data Protection by Design and by Default",
            description:
              "The controller shall implement appropriate technical and organizational measures to integrate data protection into processing activities from the design stage.",
            implementation:
              "Incorporate privacy into system design. Apply data minimization by default. Conduct privacy impact assessments for new systems.",
            evidence:
              "Privacy by design documentation, default settings, PIA records.",
          },
          {
            id: "Art.28",
            title: "Processor",
            description:
              "Where processing is to be carried out on behalf of a controller, the controller shall use only processors providing sufficient guarantees.",
            implementation:
              "Execute data processing agreements with all processors. Include required GDPR provisions. Monitor processor compliance.",
            evidence:
              "DPA agreements, processor vetting records, compliance monitoring.",
          },
          {
            id: "Art.30",
            title: "Records of Processing Activities",
            description:
              "Each controller shall maintain a record of processing activities under its responsibility.",
            implementation:
              "Create and maintain Record of Processing Activities (ROPA). Include required information (purposes, categories, recipients, transfers, retention).",
            evidence:
              "ROPA document, maintenance records.",
          },
          {
            id: "Art.32",
            title: "Security of Processing",
            description:
              "The controller and processor shall implement appropriate technical and organizational security measures considering the state of the art, costs, and risks.",
            implementation:
              "Implement pseudonymization and encryption. Ensure confidentiality, integrity, availability, and resilience. Test and evaluate regularly.",
            evidence:
              "Security measures inventory, encryption deployment, testing and evaluation records.",
          },
          {
            id: "Art.33",
            title: "Notification of Breach to Supervisory Authority",
            description:
              "In the case of a personal data breach, the controller shall notify the competent supervisory authority within 72 hours.",
            implementation:
              "Implement breach detection and notification procedures. Define 72-hour notification workflow. Maintain breach register.",
            evidence:
              "Breach notification procedures, notification records, breach register.",
          },
          {
            id: "Art.34",
            title: "Communication of Breach to Data Subject",
            description:
              "When a breach is likely to result in a high risk to the rights and freedoms of natural persons, the controller shall communicate the breach to the data subject without undue delay.",
            implementation:
              "Define criteria for data subject notification. Implement notification procedures. Document notifications and responses.",
            evidence:
              "Notification criteria, notification procedures, communication records.",
          },
          {
            id: "Art.35",
            title: "Data Protection Impact Assessment",
            description:
              "Where processing is likely to result in a high risk, the controller shall carry out an assessment of the impact of the envisaged processing on the protection of personal data.",
            implementation:
              "Identify processing requiring DPIA. Conduct DPIAs before processing begins. Consult supervisory authority when risk cannot be mitigated.",
            evidence:
              "DPIA screening records, DPIA reports, supervisory authority consultations.",
          },
          {
            id: "Art.37",
            title: "Designation of the Data Protection Officer",
            description:
              "The controller and processor shall designate a data protection officer in certain circumstances.",
            implementation:
              "Assess requirement for DPO appointment. Designate DPO with appropriate expertise. Ensure DPO independence and resources.",
            evidence:
              "DPO assessment, appointment documentation, independence provisions.",
          },
          {
            id: "Art.44",
            title: "General Principle for Transfers to Third Countries",
            description:
              "Any transfer of personal data to a third country or international organization shall take place only under specified conditions.",
            implementation:
              "Identify cross-border data transfers. Implement appropriate transfer mechanisms (adequacy decisions, SCCs, BCRs). Conduct transfer impact assessments.",
            evidence:
              "Transfer inventory, transfer mechanisms, TIA records.",
          },
        ],
      },
    ],
  },

  // =========================================================================
  // (h) OWASP ASVS v4.0
  // =========================================================================
  {
    name: "OWASP ASVS v4.0",
    org: "Open Web Application Security Project (OWASP)",
    version: "4.0.3",
    description:
      "The OWASP Application Security Verification Standard (ASVS) provides a basis for testing web application technical security controls and a list of requirements for secure development. It defines three security verification levels with increasing rigor.",
    domains: [
      {
        name: "V1: Architecture, Design and Threat Modeling",
        description:
          "Ensure a verified application satisfies architectural and design security requirements.",
        controls: [
          {
            id: "V1.1",
            title: "Secure Software Development Lifecycle",
            description:
              "A secure software development lifecycle is in use that addresses security in all stages.",
            implementation:
              "Integrate security into all SDLC phases. Conduct threat modeling. Perform security requirements analysis.",
            evidence:
              "SDLC documentation, threat models, security requirements.",
          },
          {
            id: "V1.2",
            title: "Authentication Architecture",
            description:
              "Authentication is designed and implemented according to a proven secure pattern.",
            implementation:
              "Use proven authentication frameworks. Implement centralized authentication services. Apply defense in depth to authentication.",
            evidence:
              "Authentication architecture documentation, framework selection rationale.",
          },
          {
            id: "V1.4",
            title: "Access Control Architecture",
            description:
              "Access control is designed and implemented according to a proven secure pattern.",
            implementation:
              "Implement centralized access control. Enforce at server side. Apply deny-by-default.",
            evidence:
              "Access control architecture, server-side enforcement configuration.",
          },
          {
            id: "V1.5",
            title: "Input and Output Architecture",
            description:
              "Input and output requirements clearly define how to handle and process data safely.",
            implementation:
              "Define input validation strategy. Implement output encoding. Design against injection attacks.",
            evidence:
              "Input/output architecture, validation strategy documentation.",
          },
          {
            id: "V1.6",
            title: "Cryptographic Architecture",
            description:
              "There is an explicit cryptographic architecture that provides a foundation for the proper handling of cryptographic materials.",
            implementation:
              "Define cryptographic standards. Implement key management procedures. Use approved algorithms and key lengths.",
            evidence:
              "Cryptographic architecture document, key management procedures.",
          },
          {
            id: "V1.7",
            title: "Errors, Logging and Auditing Architecture",
            description:
              "Error handling and logging architecture is designed to collect sufficient detail for incident analysis.",
            implementation:
              "Design centralized error handling. Implement structured logging. Plan for log analysis and SIEM integration.",
            evidence:
              "Error handling design, logging architecture, SIEM integration plan.",
          },
          {
            id: "V1.8",
            title: "Data Protection and Privacy Architecture",
            description:
              "Application architecture considers data protection and privacy requirements.",
            implementation:
              "Classify data by sensitivity. Design for data minimization. Implement privacy by design principles.",
            evidence:
              "Data classification, privacy architecture documentation.",
          },
          {
            id: "V1.9",
            title: "Communications Architecture",
            description:
              "Communication security is designed to protect against eavesdropping and man-in-the-middle attacks.",
            implementation:
              "Enforce TLS for all communications. Implement certificate pinning where appropriate. Design for mutual authentication.",
            evidence:
              "Communications security design, TLS configuration, certificate pinning implementation.",
          },
          {
            id: "V1.10",
            title: "Malicious Software Architecture",
            description:
              "The application does not contain malicious code or unnecessary functionality.",
            implementation:
              "Conduct code reviews for malicious code. Implement software composition analysis. Remove dead code and unused features.",
            evidence:
              "Code review records, SCA results, code cleanup documentation.",
          },
          {
            id: "V1.11",
            title: "Business Logic Architecture",
            description:
              "Business logic is designed to be inherently secure and resilient to common attack patterns.",
            implementation:
              "Document business logic flows. Identify abuse cases. Implement rate limiting and anti-automation controls.",
            evidence:
              "Business logic documentation, abuse case analysis, rate limiting configuration.",
          },
          {
            id: "V1.12",
            title: "Secure File Upload Architecture",
            description:
              "File upload functionality is designed to securely handle uploaded files.",
            implementation:
              "Restrict file types and sizes. Store uploads outside web root. Implement virus scanning for uploads.",
            evidence:
              "File upload architecture, restriction configuration, virus scanning setup.",
          },
          {
            id: "V1.14",
            title: "Configuration Architecture",
            description:
              "The application's configuration is hardened and follows secure defaults.",
            implementation:
              "Implement secure default configuration. Externalize sensitive configuration. Use environment-specific configuration management.",
            evidence:
              "Configuration architecture, default settings documentation, configuration management.",
          },
        ],
      },
      {
        name: "V2: Authentication",
        description:
          "Verify that the application correctly verifies the identity of users.",
        controls: [
          {
            id: "V2.1",
            title: "Password Security",
            description:
              "Passwords are stored and validated securely using current best practices.",
            implementation:
              "Hash passwords using bcrypt, scrypt, or Argon2id. Enforce minimum 8-character passwords. Check against breached password databases.",
            evidence:
              "Password hashing implementation, password policy, breach database integration.",
          },
          {
            id: "V2.2",
            title: "General Authenticator Security",
            description:
              "General authenticator requirements are implemented including resistance to brute force and credential stuffing.",
            implementation:
              "Implement account lockout or rate limiting. Use generic error messages. Log authentication failures.",
            evidence:
              "Rate limiting configuration, error message review, authentication logging.",
          },
          {
            id: "V2.3",
            title: "Authenticator Lifecycle",
            description:
              "Authenticator lifecycle management ensures secure provisioning, rotation, and revocation.",
            implementation:
              "Implement secure credential provisioning. Support credential rotation. Enable credential revocation.",
            evidence:
              "Provisioning procedures, rotation mechanisms, revocation procedures.",
          },
          {
            id: "V2.4",
            title: "Credential Storage",
            description:
              "Credentials are stored securely using current best practices.",
            implementation:
              "Use adaptive one-way functions for password storage. Implement proper salting. Never store plaintext credentials.",
            evidence:
              "Storage implementation review, salting verification, plaintext check results.",
          },
          {
            id: "V2.5",
            title: "Credential Recovery",
            description:
              "Credential recovery mechanisms do not reveal current credentials and are secure.",
            implementation:
              "Implement secure password reset via email or MFA. Use time-limited tokens. Never send passwords in clear text.",
            evidence:
              "Password reset implementation, token expiration settings, communication security.",
          },
          {
            id: "V2.7",
            title: "Out of Band Verifier",
            description:
              "Out of band authenticator verification requirements for secure delivery of authentication codes.",
            implementation:
              "Use push notifications or TOTP over SMS when possible. Implement code expiration. Limit code reuse.",
            evidence:
              "OOB implementation, code expiration settings, reuse prevention.",
          },
          {
            id: "V2.8",
            title: "One-Time Verifier",
            description:
              "Time-based and other one-time password requirements are implemented securely.",
            implementation:
              "Implement TOTP per RFC 6238. Use 6 or more digits. Enforce time skew limits.",
            evidence:
              "TOTP implementation, digit configuration, time skew settings.",
          },
          {
            id: "V2.9",
            title: "Cryptographic Verifier",
            description:
              "Cryptographic-based authentication such as hardware tokens and FIDO2/WebAuthn is implemented securely.",
            implementation:
              "Support FIDO2/WebAuthn. Implement hardware token support. Verify cryptographic operations server-side.",
            evidence:
              "FIDO2 implementation, hardware token support, server-side verification.",
          },
          {
            id: "V2.10",
            title: "Service Authentication",
            description:
              "Service-to-service authentication is implemented securely.",
            implementation:
              "Use mTLS for service authentication. Implement API key rotation. Avoid hardcoded credentials.",
            evidence:
              "mTLS configuration, API key management, credential scanning results.",
          },
        ],
      },
      {
        name: "V3: Session Management",
        description:
          "Verify that the application correctly manages user sessions.",
        controls: [
          {
            id: "V3.1",
            title: "Fundamental Session Management",
            description:
              "Sessions are properly created, managed, and destroyed.",
            implementation:
              "Generate sessions server-side. Use cryptographically random session identifiers. Invalidate sessions on logout.",
            evidence:
              "Session management implementation, randomness verification, logout behavior.",
          },
          {
            id: "V3.2",
            title: "Session Binding",
            description:
              "Sessions are bound to the authenticated user and protected from hijacking.",
            implementation:
              "Bind sessions to user identity. Implement session fixation protections. Regenerate session ID on authentication.",
            evidence:
              "Session binding implementation, fixation protection, ID regeneration verification.",
          },
          {
            id: "V3.3",
            title: "Session Termination",
            description:
              "Sessions are terminated appropriately including timeout and explicit logout.",
            implementation:
              "Implement idle timeout. Implement absolute timeout. Provide logout functionality. Invalidate server-side sessions.",
            evidence:
              "Timeout configuration, logout implementation, server-side invalidation.",
          },
          {
            id: "V3.4",
            title: "Cookie-based Session Management",
            description:
              "Cookies used for session management are configured securely.",
            implementation:
              "Set Secure, HttpOnly, and SameSite attributes. Use __Host- prefix. Set appropriate path and domain.",
            evidence:
              "Cookie configuration, attribute verification, prefix usage.",
          },
          {
            id: "V3.5",
            title: "Token-based Session Management",
            description:
              "Token-based sessions including JWTs are managed securely.",
            implementation:
              "Validate JWT signatures server-side. Implement token expiration. Use secure algorithms (RS256, ES256).",
            evidence:
              "JWT validation implementation, expiration settings, algorithm configuration.",
          },
        ],
      },
      {
        name: "V4: Access Control",
        description:
          "Verify that the application enforces proper access control.",
        controls: [
          {
            id: "V4.1",
            title: "General Access Control Design",
            description:
              "Access control follows deny-by-default and least privilege principles.",
            implementation:
              "Implement deny-by-default. Enforce access control on every request. Apply least privilege.",
            evidence:
              "Access control design, default-deny verification, privilege assignment records.",
          },
          {
            id: "V4.2",
            title: "Operation Level Access Control",
            description:
              "Users can only access functions and data for which they possess specific authorization.",
            implementation:
              "Implement function-level access control. Verify authorization for each operation. Enforce at server side.",
            evidence:
              "Function-level access control implementation, authorization checks, server-side enforcement.",
          },
          {
            id: "V4.3",
            title: "Other Access Control Considerations",
            description:
              "Additional access control mechanisms including rate limiting and administrative access protection.",
            implementation:
              "Implement rate limiting. Protect administrative interfaces. Restrict access to configuration files.",
            evidence:
              "Rate limiting configuration, administrative protection, file access restrictions.",
          },
        ],
      },
      {
        name: "V5: Validation, Sanitization and Encoding",
        description:
          "Verify that the application correctly validates, sanitizes, and encodes data.",
        controls: [
          {
            id: "V5.1",
            title: "Input Validation",
            description:
              "Input validation is performed on all input data.",
            implementation:
              "Validate all input on the server side. Use positive validation (allow lists). Validate data type, length, range, and format.",
            evidence:
              "Input validation implementation, allow list configuration, validation rule documentation.",
          },
          {
            id: "V5.2",
            title: "Sanitization and Sandboxing",
            description:
              "Potentially dangerous input is sanitized or sandboxed appropriately.",
            implementation:
              "Sanitize HTML input using approved libraries. Implement sandboxing for untrusted content. Apply context-appropriate sanitization.",
            evidence:
              "Sanitization library usage, sandbox implementation, context-specific sanitization.",
          },
          {
            id: "V5.3",
            title: "Output Encoding and Injection Prevention",
            description:
              "Output is encoded to prevent XSS and injection attacks.",
            implementation:
              "Apply context-appropriate output encoding (HTML, JavaScript, CSS, URL). Use parameterized queries. Implement Content Security Policy.",
            evidence:
              "Output encoding implementation, parameterized query usage, CSP configuration.",
          },
          {
            id: "V5.4",
            title: "Memory, String, and Unmanaged Code",
            description:
              "Memory safety requirements for applications using unmanaged code.",
            implementation:
              "Use safe string functions. Implement buffer overflow protections. Apply ASLR and DEP.",
            evidence:
              "Safe function usage, buffer protection, ASLR/DEP configuration.",
          },
          {
            id: "V5.5",
            title: "Deserialization Prevention",
            description:
              "Serialized objects are protected from creation and tampering.",
            implementation:
              "Avoid deserializing untrusted data. Use signed serialization formats. Implement integrity checks.",
            evidence:
              "Deserialization controls, signing implementation, integrity check configuration.",
          },
        ],
      },
      {
        name: "V6: Stored Cryptography",
        description:
          "Verify that the application implements proper cryptographic controls.",
        controls: [
          {
            id: "V6.1",
            title: "Data Classification",
            description:
              "Data is classified and protected according to sensitivity level.",
            implementation:
              "Classify all data by sensitivity. Apply appropriate cryptographic protection per classification. Document classification scheme.",
            evidence:
              "Data classification records, cryptographic protection mapping, classification documentation.",
          },
          {
            id: "V6.2",
            title: "Algorithms",
            description:
              "Only approved cryptographic algorithms are used.",
            implementation:
              "Use approved algorithms (AES-256, RSA-2048+, SHA-256+). Avoid deprecated algorithms (DES, MD5, SHA-1). Follow NIST guidelines.",
            evidence:
              "Algorithm inventory, deprecated algorithm scan results, NIST compliance check.",
          },
          {
            id: "V6.3",
            title: "Random Values",
            description:
              "Cryptographically secure random values are used where required.",
            implementation:
              "Use CSPRNG for all security-relevant random values. Ensure adequate entropy. Never use Math.random() for security purposes.",
            evidence:
              "Random value generation review, CSPRNG usage verification, entropy source documentation.",
          },
          {
            id: "V6.4",
            title: "Secret Management",
            description:
              "Secrets and credentials are managed securely.",
            implementation:
              "Store secrets in vault or HSM. Never hardcode secrets. Implement secret rotation. Audit secret access.",
            evidence:
              "Vault deployment, hardcoded secret scanning, rotation procedures, audit logs.",
          },
        ],
      },
      {
        name: "V7: Error Handling and Logging",
        description:
          "Verify that the application implements proper error handling and logging.",
        controls: [
          {
            id: "V7.1",
            title: "Log Content",
            description:
              "Security-relevant events are logged with sufficient detail.",
            implementation:
              "Log authentication events, access control failures, input validation failures, and security exceptions. Include who, what, when, where.",
            evidence:
              "Logging configuration, log content review, event coverage analysis.",
          },
          {
            id: "V7.2",
            title: "Log Processing",
            description:
              "Logs are processed and analyzed to detect security events.",
            implementation:
              "Centralize logs. Implement automated analysis. Set up alerting for security events. Retain logs per policy.",
            evidence:
              "Log centralization setup, analysis rules, alert configuration, retention settings.",
          },
          {
            id: "V7.3",
            title: "Log Protection",
            description:
              "Logs are protected from unauthorized access and tampering.",
            implementation:
              "Restrict access to log systems. Implement log integrity controls. Protect against log injection.",
            evidence:
              "Access restrictions, integrity controls, injection prevention measures.",
          },
          {
            id: "V7.4",
            title: "Error Handling",
            description:
              "Error handling does not reveal sensitive information.",
            implementation:
              "Use generic error messages for users. Log detailed errors server-side. Do not expose stack traces or system information.",
            evidence:
              "Error message review, server-side logging verification, information disclosure testing.",
          },
        ],
      },
      {
        name: "V8: Data Protection",
        description:
          "Verify that the application protects sensitive data.",
        controls: [
          {
            id: "V8.1",
            title: "General Data Protection",
            description:
              "Sensitive data is identified and protected throughout its lifecycle.",
            implementation:
              "Identify sensitive data types. Apply encryption at rest and in transit. Implement access controls. Define retention policies.",
            evidence:
              "Data inventory, encryption configuration, access controls, retention policies.",
          },
          {
            id: "V8.2",
            title: "Client-side Data Protection",
            description:
              "Sensitive data is not stored or exposed in client-side code or storage.",
            implementation:
              "Do not store sensitive data in local storage, session storage, or cookies. Clear sensitive data from memory. Prevent caching of sensitive pages.",
            evidence:
              "Client-side storage review, memory clearing implementation, cache control headers.",
          },
          {
            id: "V8.3",
            title: "Sensitive Private Data",
            description:
              "Sensitive personal data is handled in compliance with applicable regulations.",
            implementation:
              "Implement privacy controls per applicable regulations. Provide data subject rights functionality. Conduct privacy impact assessments.",
            evidence:
              "Privacy controls, rights functionality, PIA documentation.",
          },
        ],
      },
      {
        name: "V9: Communication",
        description:
          "Verify that the application secures all communications.",
        controls: [
          {
            id: "V9.1",
            title: "Client Communication Security",
            description:
              "TLS is used for all client communications with appropriate configuration.",
            implementation:
              "Enforce TLS 1.2 or higher. Use strong cipher suites. Implement HSTS. Validate certificates.",
            evidence:
              "TLS configuration, cipher suite settings, HSTS headers, certificate validation.",
          },
          {
            id: "V9.2",
            title: "Server Communication Security",
            description:
              "Server-to-server communications use secure protocols.",
            implementation:
              "Use TLS for all backend communications. Implement mutual TLS where appropriate. Validate server certificates.",
            evidence:
              "Backend TLS configuration, mTLS implementation, certificate validation.",
          },
        ],
      },
      {
        name: "V10: Malicious Code",
        description:
          "Verify that the application does not contain malicious code.",
        controls: [
          {
            id: "V10.1",
            title: "Code Integrity Controls",
            description:
              "Controls are in place to ensure code integrity.",
            implementation:
              "Implement code signing. Use Subresource Integrity for third-party resources. Conduct code reviews.",
            evidence:
              "Code signing configuration, SRI implementation, code review records.",
          },
          {
            id: "V10.2",
            title: "Malicious Code Search",
            description:
              "Application source code does not contain malicious code.",
            implementation:
              "Conduct regular code reviews. Implement automated code scanning. Review third-party dependencies.",
            evidence:
              "Code review records, scanning tool output, dependency review records.",
          },
          {
            id: "V10.3",
            title: "Application Integrity",
            description:
              "Deployed application integrity is verified and protected.",
            implementation:
              "Implement deployment verification. Use integrity monitoring. Protect against unauthorized modifications.",
            evidence:
              "Deployment verification records, integrity monitoring configuration, modification detection.",
          },
        ],
      },
      {
        name: "V11: Business Logic",
        description:
          "Verify that the application has secure business logic.",
        controls: [
          {
            id: "V11.1",
            title: "Business Logic Security",
            description:
              "Business logic flows are protected from abuse.",
            implementation:
              "Enforce business rules server-side. Implement rate limiting. Validate business logic sequences. Prevent privilege escalation.",
            evidence:
              "Server-side enforcement, rate limiting configuration, sequence validation, privilege controls.",
          },
        ],
      },
      {
        name: "V12: Files and Resources",
        description:
          "Verify that the application securely handles file uploads and resource access.",
        controls: [
          {
            id: "V12.1",
            title: "File Upload",
            description:
              "File upload functionality is implemented securely.",
            implementation:
              "Validate file types. Restrict file sizes. Store files outside web root. Scan uploads for malware.",
            evidence:
              "File type validation, size restrictions, storage configuration, malware scanning.",
          },
          {
            id: "V12.3",
            title: "File Execution",
            description:
              "Uploaded files are not executed or interpreted by the application.",
            implementation:
              "Prevent execution of uploaded files. Set appropriate content types. Use separate domains for user content.",
            evidence:
              "Execution prevention controls, content type configuration, domain separation.",
          },
          {
            id: "V12.4",
            title: "File Storage",
            description:
              "Files are stored securely.",
            implementation:
              "Store files in non-web-accessible locations. Implement access controls. Use unique, non-guessable filenames.",
            evidence:
              "Storage location configuration, access controls, filename generation.",
          },
          {
            id: "V12.6",
            title: "SSRF Prevention",
            description:
              "Server-side request forgery (SSRF) vulnerabilities are prevented.",
            implementation:
              "Validate and sanitize URLs. Implement URL allow lists. Block requests to internal resources.",
            evidence:
              "URL validation implementation, allow list configuration, internal resource blocking.",
          },
        ],
      },
      {
        name: "V13: API and Web Service",
        description:
          "Verify that the application secures APIs and web services.",
        controls: [
          {
            id: "V13.1",
            title: "Generic Web Service Security",
            description:
              "Web services use secure transport and authentication.",
            implementation:
              "Enforce HTTPS for all API endpoints. Implement API authentication. Validate content types.",
            evidence:
              "HTTPS enforcement, authentication configuration, content type validation.",
          },
          {
            id: "V13.2",
            title: "RESTful Web Service",
            description:
              "RESTful APIs implement proper security controls.",
            implementation:
              "Validate JSON schema. Implement rate limiting. Protect against mass assignment. Use proper HTTP methods.",
            evidence:
              "JSON schema validation, rate limiting, mass assignment protection, HTTP method enforcement.",
          },
          {
            id: "V13.3",
            title: "SOAP Web Service",
            description:
              "SOAP web services implement proper security controls.",
            implementation:
              "Validate XML against XSD schemas. Implement WS-Security. Protect against XXE and SSRF.",
            evidence:
              "XSD validation, WS-Security implementation, XXE/SSRF protection.",
          },
          {
            id: "V13.4",
            title: "GraphQL",
            description:
              "GraphQL implementations use proper security controls.",
            implementation:
              "Implement query depth limiting. Apply query cost analysis. Disable introspection in production.",
            evidence:
              "Depth limiting configuration, cost analysis implementation, introspection settings.",
          },
        ],
      },
      {
        name: "V14: Configuration",
        description:
          "Verify that the application is securely configured.",
        controls: [
          {
            id: "V14.1",
            title: "Build and Deploy",
            description:
              "Build and deployment processes are hardened and secure.",
            implementation:
              "Use CI/CD with security checks. Implement build reproducibility. Verify dependency integrity.",
            evidence:
              "CI/CD pipeline configuration, reproducibility verification, dependency integrity checks.",
          },
          {
            id: "V14.2",
            title: "Dependency",
            description:
              "Third-party dependencies are managed and monitored for vulnerabilities.",
            implementation:
              "Maintain dependency inventory. Scan for known vulnerabilities. Update vulnerable dependencies promptly.",
            evidence:
              "Dependency inventory, vulnerability scan results, update records.",
          },
          {
            id: "V14.3",
            title: "Unintended Security Disclosure",
            description:
              "The application does not unintentionally disclose security-relevant information.",
            implementation:
              "Disable debug modes in production. Remove server version headers. Implement custom error pages.",
            evidence:
              "Debug mode settings, header configuration, error page implementation.",
          },
          {
            id: "V14.4",
            title: "HTTP Security Headers",
            description:
              "Appropriate HTTP security headers are configured.",
            implementation:
              "Implement Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, and Referrer-Policy headers.",
            evidence:
              "Header configuration, header analysis scan results.",
          },
          {
            id: "V14.5",
            title: "HTTP Request Header Validation",
            description:
              "HTTP request headers are validated and sanitized.",
            implementation:
              "Validate Host headers. Validate Origin and Referer for CSRF protection. Reject unexpected headers.",
            evidence:
              "Header validation implementation, CSRF protection, rejection rules.",
          },
        ],
      },
    ],
  },
];

// =============================================================================
// 2. COMPLIANCE_CHECKLISTS -- Quick-Reference Checklists
// =============================================================================

const COMPLIANCE_CHECKLISTS = [
  // NIST CSF Checklists
  {
    framework: "NIST CSF",
    category: "Identify - Asset Management",
    items: [
      { check: "Hardware inventory is complete and current", description: "All hardware assets are documented with owner, location, and classification.", priority: "High" },
      { check: "Software inventory is maintained", description: "All software including licenses, versions, and patch status is tracked.", priority: "High" },
      { check: "Data flow diagrams are current", description: "Network topology and data flow diagrams reflect the actual environment.", priority: "Medium" },
      { check: "External information systems are cataloged", description: "All third-party services and cloud assets are inventoried.", priority: "Medium" },
      { check: "Assets are classified by criticality", description: "All assets are classified based on business value and data sensitivity.", priority: "High" },
      { check: "Asset lifecycle is managed", description: "Processes exist for onboarding, maintaining, and decommissioning assets.", priority: "Medium" },
    ],
  },
  {
    framework: "NIST CSF",
    category: "Protect - Access Control",
    items: [
      { check: "Identities and credentials are managed", description: "Unique identifiers are assigned and credentials are properly provisioned.", priority: "Critical" },
      { check: "Multi-factor authentication is deployed", description: "MFA is enforced for all privileged and remote access.", priority: "Critical" },
      { check: "Least privilege access is enforced", description: "Access rights are limited to minimum necessary for job functions.", priority: "High" },
      { check: "Access reviews are conducted regularly", description: "Quarterly access reviews validate appropriateness of access rights.", priority: "High" },
      { check: "Physical access controls are in place", description: "Badge access, CCTV, and visitor management are operational.", priority: "Medium" },
      { check: "Separation of duties is implemented", description: "Conflicting duties are separated and compensating controls exist.", priority: "High" },
    ],
  },
  {
    framework: "NIST CSF",
    category: "Detect - Continuous Monitoring",
    items: [
      { check: "Network monitoring is active", description: "IDS/IPS and network flow monitoring are deployed and generating alerts.", priority: "Critical" },
      { check: "Endpoint detection and response is deployed", description: "EDR agents are installed on all endpoints and servers.", priority: "High" },
      { check: "SIEM is operational", description: "Security events are collected, correlated, and analyzed in a SIEM platform.", priority: "High" },
      { check: "Alert thresholds are tuned", description: "Detection rules are tuned to minimize false positives while maintaining visibility.", priority: "Medium" },
      { check: "User behavior analytics are configured", description: "UEBA tools monitor for anomalous user and entity behavior.", priority: "Medium" },
      { check: "Threat intelligence is integrated", description: "Threat feeds are ingested and correlated with internal events.", priority: "Medium" },
    ],
  },
  {
    framework: "NIST CSF",
    category: "Respond - Incident Management",
    items: [
      { check: "Incident response plan exists and is current", description: "A documented IRP covers detection, containment, eradication, and recovery.", priority: "Critical" },
      { check: "Incident response team is established", description: "Roles, responsibilities, and contact information are documented and current.", priority: "Critical" },
      { check: "Escalation procedures are defined", description: "Clear escalation paths and criteria are documented for incident severity levels.", priority: "High" },
      { check: "Communication plans are ready", description: "Internal and external communication plans are documented and tested.", priority: "High" },
      { check: "Forensic capability is available", description: "Forensic tools and trained personnel are available for investigations.", priority: "Medium" },
      { check: "Post-incident reviews are conducted", description: "Lessons learned are documented and applied after every significant incident.", priority: "High" },
    ],
  },

  // ISO 27001 Checklists
  {
    framework: "ISO 27001",
    category: "Information Security Management System",
    items: [
      { check: "ISMS scope is defined", description: "The boundaries and applicability of the ISMS are clearly documented.", priority: "Critical" },
      { check: "Information security policy is approved", description: "Top management has approved the information security policy.", priority: "Critical" },
      { check: "Risk assessment methodology is defined", description: "A systematic approach to risk assessment is documented and applied.", priority: "High" },
      { check: "Statement of Applicability is current", description: "SoA documents all controls and their implementation status.", priority: "High" },
      { check: "Management review is scheduled", description: "Regular management reviews of the ISMS are planned and conducted.", priority: "High" },
      { check: "Internal audit program is established", description: "An audit program covering all ISMS requirements is planned and executed.", priority: "High" },
      { check: "Corrective actions are tracked", description: "Nonconformities are documented and corrective actions are tracked to closure.", priority: "Medium" },
      { check: "Continual improvement is demonstrated", description: "Evidence of ISMS improvement over time is maintained.", priority: "Medium" },
    ],
  },
  {
    framework: "ISO 27001",
    category: "People Security",
    items: [
      { check: "Background checks are performed", description: "Verification checks are conducted on all candidates before employment.", priority: "High" },
      { check: "Security responsibilities are in employment terms", description: "Information security responsibilities are included in contracts.", priority: "High" },
      { check: "Security awareness training is delivered", description: "All personnel receive appropriate security awareness training.", priority: "High" },
      { check: "Disciplinary process is defined", description: "Formal process exists for security policy violations.", priority: "Medium" },
      { check: "Exit procedures include security", description: "Offboarding processes include asset return and access revocation.", priority: "High" },
      { check: "NDAs are signed", description: "Confidentiality agreements are executed by all personnel and contractors.", priority: "High" },
    ],
  },

  // PCI DSS Checklists
  {
    framework: "PCI DSS",
    category: "Cardholder Data Protection",
    items: [
      { check: "Cardholder data environment is defined", description: "All systems, networks, and processes in the CDE are identified and documented.", priority: "Critical" },
      { check: "PAN is rendered unreadable in storage", description: "Stored PAN is encrypted, truncated, tokenized, or hashed.", priority: "Critical" },
      { check: "Sensitive authentication data is not stored", description: "Full track data, CVV, and PIN blocks are never stored after authorization.", priority: "Critical" },
      { check: "Encryption keys are managed properly", description: "Key management procedures cover generation, distribution, storage, rotation, and destruction.", priority: "High" },
      { check: "Data retention policy is enforced", description: "Cardholder data retention periods are defined and data is purged on schedule.", priority: "High" },
      { check: "PAN is masked when displayed", description: "Only the first 6 and last 4 digits of PAN are shown in displays.", priority: "High" },
      { check: "TLS 1.2+ is used for transmission", description: "All PAN transmission uses TLS 1.2 or higher with strong cipher suites.", priority: "Critical" },
    ],
  },
  {
    framework: "PCI DSS",
    category: "Vulnerability Management",
    items: [
      { check: "Anti-malware is deployed on all in-scope systems", description: "Anti-malware with current signatures is active on all applicable systems.", priority: "Critical" },
      { check: "Quarterly internal vulnerability scans are performed", description: "Internal scans are run quarterly and findings are remediated.", priority: "High" },
      { check: "Quarterly external ASV scans pass", description: "External vulnerability scans by an Approved Scanning Vendor achieve passing status.", priority: "High" },
      { check: "Annual penetration testing is completed", description: "Internal and external penetration tests are conducted annually.", priority: "High" },
      { check: "Critical patches are applied within 30 days", description: "Critical security patches are installed within one month of release.", priority: "Critical" },
      { check: "WAF is deployed for public-facing web apps", description: "Web application firewall protects all public-facing web applications.", priority: "High" },
      { check: "Secure development practices are followed", description: "Custom code is developed following secure coding guidelines and reviewed.", priority: "High" },
    ],
  },

  // SOC 2 Checklists
  {
    framework: "SOC 2",
    category: "Security (Common Criteria)",
    items: [
      { check: "Information security policies are documented", description: "Comprehensive security policies are published and communicated.", priority: "Critical" },
      { check: "Risk assessment is performed annually", description: "Formal risk assessment covers all in-scope systems and processes.", priority: "High" },
      { check: "Access controls are implemented", description: "Logical and physical access controls protect system resources.", priority: "Critical" },
      { check: "Change management process is followed", description: "All changes go through formal approval, testing, and documentation.", priority: "High" },
      { check: "Monitoring and alerting is operational", description: "Security monitoring with alerting is active for all in-scope systems.", priority: "High" },
      { check: "Incident response plan is tested", description: "IRP is tested at least annually through tabletop or simulation exercises.", priority: "High" },
      { check: "Vendor risk management is active", description: "Third-party vendors are assessed and monitored for security risks.", priority: "Medium" },
    ],
  },
  {
    framework: "SOC 2",
    category: "Availability",
    items: [
      { check: "Uptime SLAs are defined and monitored", description: "Service level agreements for availability are documented and tracked.", priority: "High" },
      { check: "Disaster recovery plan exists", description: "DR plan covers critical systems with defined RTO and RPO.", priority: "Critical" },
      { check: "DR plan is tested regularly", description: "DR tests are conducted at least annually with documented results.", priority: "High" },
      { check: "Capacity planning is performed", description: "System capacity is monitored and planned for growth.", priority: "Medium" },
      { check: "Backup and restoration is verified", description: "Backups are performed and restoration is tested regularly.", priority: "High" },
    ],
  },

  // HIPAA Checklists
  {
    framework: "HIPAA",
    category: "Administrative Safeguards",
    items: [
      { check: "Risk analysis is completed", description: "Comprehensive risk analysis of all ePHI processing is documented.", priority: "Critical" },
      { check: "Security officer is designated", description: "A named individual is responsible for HIPAA security compliance.", priority: "Critical" },
      { check: "Workforce training is completed", description: "All workforce members receive HIPAA security awareness training.", priority: "High" },
      { check: "Sanction policy is defined", description: "Consequences for security policy violations are documented and enforced.", priority: "High" },
      { check: "Contingency plan is developed", description: "Data backup, DR, and emergency mode operation plans exist.", priority: "High" },
      { check: "BAAs are executed with all BAs", description: "Business Associate Agreements are signed with all entities handling ePHI.", priority: "Critical" },
      { check: "Security evaluation is performed periodically", description: "Technical and nontechnical evaluations are conducted regularly.", priority: "High" },
    ],
  },
  {
    framework: "HIPAA",
    category: "Technical Safeguards",
    items: [
      { check: "Unique user identification is enforced", description: "Each user has a unique identifier for accessing ePHI systems.", priority: "Critical" },
      { check: "Emergency access procedure exists", description: "Procedures exist for obtaining access to ePHI during an emergency.", priority: "High" },
      { check: "Automatic logoff is enabled", description: "Sessions terminate after a defined period of inactivity.", priority: "High" },
      { check: "ePHI is encrypted at rest", description: "Encryption is applied to ePHI in storage.", priority: "High" },
      { check: "ePHI is encrypted in transit", description: "Transmission security using TLS protects ePHI during transport.", priority: "Critical" },
      { check: "Audit controls are implemented", description: "Audit logging records access to ePHI systems.", priority: "High" },
      { check: "Integrity controls are in place", description: "Mechanisms exist to protect ePHI from improper alteration.", priority: "High" },
    ],
  },

  // GDPR Checklists
  {
    framework: "GDPR",
    category: "Data Subject Rights",
    items: [
      { check: "Privacy notice is published", description: "Clear privacy notice explains data processing purposes, rights, and contacts.", priority: "Critical" },
      { check: "DSAR process is operational", description: "Procedures exist to handle data subject access requests within 30 days.", priority: "Critical" },
      { check: "Right to erasure can be fulfilled", description: "Systems support deletion of personal data upon valid request.", priority: "High" },
      { check: "Data portability is supported", description: "Personal data can be exported in machine-readable format.", priority: "Medium" },
      { check: "Consent management is implemented", description: "Consent is obtained, recorded, and can be withdrawn easily.", priority: "High" },
      { check: "Automated decision-making is disclosed", description: "Data subjects are informed about automated processing and can contest decisions.", priority: "Medium" },
    ],
  },
  {
    framework: "GDPR",
    category: "Controller Obligations",
    items: [
      { check: "ROPA is maintained", description: "Record of Processing Activities documents all personal data processing.", priority: "Critical" },
      { check: "DPIAs are conducted for high-risk processing", description: "Data Protection Impact Assessments are completed before high-risk processing.", priority: "High" },
      { check: "DPO is appointed (if required)", description: "Data Protection Officer is designated where required by regulation.", priority: "High" },
      { check: "Data processing agreements are in place", description: "DPAs with required GDPR provisions are signed with all processors.", priority: "Critical" },
      { check: "Breach notification procedures are ready", description: "Process exists to notify supervisory authority within 72 hours of breach discovery.", priority: "Critical" },
      { check: "International transfer mechanisms are implemented", description: "Appropriate safeguards (SCCs, BCRs) are in place for cross-border data transfers.", priority: "High" },
      { check: "Privacy by design is integrated into development", description: "Data protection is considered from the design phase of all new systems.", priority: "High" },
    ],
  },

  // OWASP Checklists
  {
    framework: "OWASP ASVS",
    category: "Authentication Security",
    items: [
      { check: "Passwords are hashed with modern algorithms", description: "bcrypt, scrypt, or Argon2id is used for password storage.", priority: "Critical" },
      { check: "Account lockout or rate limiting is implemented", description: "Brute force protection is active on all authentication endpoints.", priority: "Critical" },
      { check: "MFA is available and encouraged", description: "Multi-factor authentication option is provided for all user accounts.", priority: "High" },
      { check: "Session tokens are cryptographically random", description: "Session identifiers use CSPRNG with at least 128 bits of entropy.", priority: "High" },
      { check: "Password reset is secure", description: "Password recovery uses time-limited tokens and does not reveal current credentials.", priority: "High" },
      { check: "Credentials are checked against breach databases", description: "New passwords are verified against known compromised password lists.", priority: "Medium" },
    ],
  },
  {
    framework: "OWASP ASVS",
    category: "Input Validation and Output Encoding",
    items: [
      { check: "All input is validated server-side", description: "Input validation occurs on the server regardless of client-side validation.", priority: "Critical" },
      { check: "Parameterized queries are used", description: "SQL queries use parameterized statements, not string concatenation.", priority: "Critical" },
      { check: "Output encoding is context-appropriate", description: "Output is encoded for the specific context (HTML, JS, CSS, URL).", priority: "Critical" },
      { check: "Content Security Policy is implemented", description: "CSP headers restrict resource loading and inline script execution.", priority: "High" },
      { check: "File uploads are validated", description: "Uploaded file type, size, and content are validated server-side.", priority: "High" },
      { check: "Deserialization of untrusted data is prevented", description: "Application does not deserialize data from untrusted sources.", priority: "High" },
    ],
  },

  // CIS Controls Checklist
  {
    framework: "CIS Controls",
    category: "Essential Cyber Hygiene (IG1)",
    items: [
      { check: "Enterprise asset inventory is complete", description: "All devices connected to the network are identified and tracked.", priority: "Critical" },
      { check: "Software inventory is maintained", description: "All installed software is tracked with authorized software list enforced.", priority: "Critical" },
      { check: "Data protection measures are implemented", description: "Sensitive data is classified, encrypted, and handled per policy.", priority: "High" },
      { check: "Secure configuration baselines are applied", description: "CIS Benchmarks or equivalent baselines are applied to all systems.", priority: "High" },
      { check: "Account management is enforced", description: "User accounts are managed with unique IDs, inactive account cleanup, and service account controls.", priority: "High" },
      { check: "Access control is implemented", description: "RBAC, least privilege, and MFA for administrative access are enforced.", priority: "Critical" },
      { check: "Vulnerability management is continuous", description: "Regular vulnerability scanning with prioritized remediation is active.", priority: "High" },
      { check: "Audit log management is configured", description: "Logging is enabled, centralized, and retained per policy.", priority: "High" },
    ],
  },
];

// =============================================================================
// 3. RISK_MATRICES -- Risk Assessment Templates
// =============================================================================

const RISK_MATRICES = [
  // 5x5 Risk Matrix entries
  { name: "Negligible Risk", likelihood: "Rare", impact: "Negligible", riskLevel: "Low", description: "Event is very unlikely to occur and would have minimal impact. Accept the risk with basic monitoring." },
  { name: "Negligible Risk (Unlikely)", likelihood: "Unlikely", impact: "Negligible", riskLevel: "Low", description: "Event is unlikely and would have negligible consequences. Standard controls are sufficient." },
  { name: "Negligible Risk (Possible)", likelihood: "Possible", impact: "Negligible", riskLevel: "Low", description: "Event may occur but impact would be negligible. Monitor and review periodically." },
  { name: "Negligible Risk (Likely)", likelihood: "Likely", impact: "Negligible", riskLevel: "Low", description: "Event is likely but impact remains negligible. Implement basic preventive controls." },
  { name: "Negligible Risk (Almost Certain)", likelihood: "Almost Certain", impact: "Negligible", riskLevel: "Medium", description: "Event is almost certain but impact is negligible. Implement controls to manage frequency." },

  { name: "Minor Risk (Rare)", likelihood: "Rare", impact: "Minor", riskLevel: "Low", description: "Event is very unlikely with minor impact. Accept risk with standard monitoring procedures." },
  { name: "Minor Risk (Unlikely)", likelihood: "Unlikely", impact: "Minor", riskLevel: "Low", description: "Event is unlikely with minor consequences. Standard controls and periodic review are adequate." },
  { name: "Minor Risk (Possible)", likelihood: "Possible", impact: "Minor", riskLevel: "Medium", description: "Event may occur with minor impact. Implement additional monitoring and basic preventive controls." },
  { name: "Minor Risk (Likely)", likelihood: "Likely", impact: "Minor", riskLevel: "Medium", description: "Event is likely to occur with minor impact. Implement preventive controls and regular monitoring." },
  { name: "Minor Risk (Almost Certain)", likelihood: "Almost Certain", impact: "Minor", riskLevel: "High", description: "Event is almost certain with minor impact. Requires active risk management and mitigation planning." },

  { name: "Moderate Risk (Rare)", likelihood: "Rare", impact: "Moderate", riskLevel: "Low", description: "Event is very unlikely but would have moderate impact if it occurred. Monitor and have response plans ready." },
  { name: "Moderate Risk (Unlikely)", likelihood: "Unlikely", impact: "Moderate", riskLevel: "Medium", description: "Event is unlikely with moderate consequences. Implement preventive controls and response procedures." },
  { name: "Moderate Risk (Possible)", likelihood: "Possible", impact: "Moderate", riskLevel: "Medium", description: "Event may occur with moderate impact. Active risk management with monitoring and defined response procedures required." },
  { name: "Moderate Risk (Likely)", likelihood: "Likely", impact: "Moderate", riskLevel: "High", description: "Event is likely with moderate impact. Requires comprehensive risk treatment plan with defined controls and monitoring." },
  { name: "Moderate Risk (Almost Certain)", likelihood: "Almost Certain", impact: "Moderate", riskLevel: "High", description: "Event is almost certain with moderate impact. Urgent risk mitigation required with escalation to senior management." },

  { name: "Major Risk (Rare)", likelihood: "Rare", impact: "Major", riskLevel: "Medium", description: "Event is very unlikely but would have major impact. Develop contingency plans and ensure detection capability." },
  { name: "Major Risk (Unlikely)", likelihood: "Unlikely", impact: "Major", riskLevel: "Medium", description: "Event is unlikely but impact would be major. Implement preventive controls and tested response plans." },
  { name: "Major Risk (Possible)", likelihood: "Possible", impact: "Major", riskLevel: "High", description: "Event may occur with major impact. Comprehensive risk treatment with senior management oversight required." },
  { name: "Major Risk (Likely)", likelihood: "Likely", impact: "Major", riskLevel: "Critical", description: "Event is likely with major impact. Immediate risk mitigation required. Escalate to executive leadership." },
  { name: "Major Risk (Almost Certain)", likelihood: "Almost Certain", impact: "Major", riskLevel: "Critical", description: "Event is almost certain with major impact. Emergency risk response required. Board-level attention needed." },

  { name: "Catastrophic Risk (Rare)", likelihood: "Rare", impact: "Catastrophic", riskLevel: "Medium", description: "Event is very unlikely but would be catastrophic. Robust contingency plans and insurance required." },
  { name: "Catastrophic Risk (Unlikely)", likelihood: "Unlikely", impact: "Catastrophic", riskLevel: "High", description: "Event is unlikely but impact would be catastrophic. Significant investment in prevention and preparedness required." },
  { name: "Catastrophic Risk (Possible)", likelihood: "Possible", impact: "Catastrophic", riskLevel: "Critical", description: "Event may occur with catastrophic impact. Maximum risk treatment priority. Board-level oversight required." },
  { name: "Catastrophic Risk (Likely)", likelihood: "Likely", impact: "Catastrophic", riskLevel: "Critical", description: "Event is likely with catastrophic impact. Immediate executive action required. Consider fundamental changes to operations." },
  { name: "Catastrophic Risk (Almost Certain)", likelihood: "Almost Certain", impact: "Catastrophic", riskLevel: "Critical", description: "Event is almost certain with catastrophic impact. Operations may not be viable without fundamental risk transformation." },

  // Impact definitions
  { name: "Impact Scale - Negligible", likelihood: "N/A", impact: "Negligible", riskLevel: "Reference", description: "No measurable impact. No regulatory notification required. No media attention. Financial loss under $10,000. No service disruption." },
  { name: "Impact Scale - Minor", likelihood: "N/A", impact: "Minor", riskLevel: "Reference", description: "Minor operational impact. Limited data exposure (<100 records). Financial loss $10,000-$100,000. Service disruption under 1 hour." },
  { name: "Impact Scale - Moderate", likelihood: "N/A", impact: "Moderate", riskLevel: "Reference", description: "Noticeable operational impact. Data exposure (100-10,000 records). Regulatory notification may be required. Financial loss $100,000-$1M. Service disruption 1-8 hours." },
  { name: "Impact Scale - Major", likelihood: "N/A", impact: "Major", riskLevel: "Reference", description: "Significant operational impact. Large-scale data breach (10,000-1M records). Regulatory penalties likely. Financial loss $1M-$10M. Service disruption 8-72 hours." },
  { name: "Impact Scale - Catastrophic", likelihood: "N/A", impact: "Catastrophic", riskLevel: "Reference", description: "Existential threat to organization. Massive data breach (>1M records). Major regulatory action. Financial loss >$10M. Service disruption >72 hours. Potential loss of key customers or contracts." },

  // Likelihood definitions
  { name: "Likelihood Scale - Rare", likelihood: "Rare", impact: "N/A", riskLevel: "Reference", description: "Less than 5% probability in 12 months. May only occur in exceptional circumstances. No history of occurrence." },
  { name: "Likelihood Scale - Unlikely", likelihood: "Unlikely", impact: "N/A", riskLevel: "Reference", description: "5-25% probability in 12 months. Could occur at some time but not expected. Limited historical precedent." },
  { name: "Likelihood Scale - Possible", likelihood: "Possible", impact: "N/A", riskLevel: "Reference", description: "25-50% probability in 12 months. Might occur at some time. Some history of occurrence in similar organizations." },
  { name: "Likelihood Scale - Likely", likelihood: "Likely", impact: "N/A", riskLevel: "Reference", description: "50-80% probability in 12 months. Will probably occur in most circumstances. Regular occurrence in similar organizations." },
  { name: "Likelihood Scale - Almost Certain", likelihood: "Almost Certain", impact: "N/A", riskLevel: "Reference", description: "Greater than 80% probability in 12 months. Expected to occur in most circumstances. Historical pattern of frequent occurrence." },

  // Threat-specific risk scenarios
  { name: "Ransomware Attack", likelihood: "Likely", impact: "Major", riskLevel: "Critical", description: "Ransomware encrypts critical systems and data. Operations halt, demanding ransom payment. Recovery requires clean backups and may take days to weeks." },
  { name: "Phishing Compromise", likelihood: "Almost Certain", impact: "Moderate", riskLevel: "High", description: "Credential theft via phishing leads to unauthorized access. May result in data exfiltration, BEC fraud, or lateral movement within the network." },
  { name: "Insider Threat - Malicious", likelihood: "Unlikely", impact: "Major", riskLevel: "Medium", description: "Disgruntled or compromised insider deliberately exfiltrates data or sabotages systems. Access to sensitive information amplifies impact." },
  { name: "Insider Threat - Negligent", likelihood: "Likely", impact: "Moderate", riskLevel: "High", description: "Employee inadvertently exposes sensitive data through misconfiguration, misdirected email, or loss of device. Common cause of data breaches." },
  { name: "Third-Party Breach", likelihood: "Possible", impact: "Major", riskLevel: "High", description: "A vendor or service provider is compromised, exposing shared data or providing attack path into the organization. Supply chain risk amplifies impact." },
  { name: "DDoS Attack", likelihood: "Likely", impact: "Moderate", riskLevel: "High", description: "Distributed denial-of-service attack overwhelms internet-facing services, causing availability disruption. May mask other attack activity." },
  { name: "Zero-Day Exploitation", likelihood: "Unlikely", impact: "Catastrophic", riskLevel: "High", description: "Exploitation of unknown vulnerability in critical software. No patch available. May enable full system compromise before detection." },
  { name: "Cloud Misconfiguration", likelihood: "Likely", impact: "Major", riskLevel: "Critical", description: "Cloud storage or service misconfiguration exposes sensitive data to the internet. Common cause of large-scale data breaches." },
  { name: "Physical Security Breach", likelihood: "Unlikely", impact: "Moderate", riskLevel: "Medium", description: "Unauthorized physical access to facilities enables device theft, network tapping, or direct system access." },
  { name: "Business Email Compromise", likelihood: "Likely", impact: "Major", riskLevel: "Critical", description: "Attacker impersonates executive or vendor to authorize fraudulent wire transfers or data disclosure. Average loss exceeds $100,000." },
  { name: "SQL Injection Attack", likelihood: "Possible", impact: "Major", riskLevel: "High", description: "SQL injection vulnerability enables unauthorized database access, data exfiltration, or data manipulation in web applications." },
  { name: "API Security Breach", likelihood: "Possible", impact: "Major", riskLevel: "High", description: "Insecure API enables unauthorized data access, rate abuse, or service disruption. API vulnerabilities are increasingly common attack vectors." },
  { name: "Cryptographic Failure", likelihood: "Possible", impact: "Major", riskLevel: "High", description: "Weak encryption, improper key management, or deprecated algorithms expose protected data. May affect data at rest and in transit." },
  { name: "DNS Hijacking", likelihood: "Unlikely", impact: "Major", riskLevel: "Medium", description: "DNS records are manipulated to redirect traffic to attacker-controlled servers, enabling credential theft or malware distribution." },
  { name: "Data Center Outage", likelihood: "Unlikely", impact: "Catastrophic", riskLevel: "High", description: "Complete data center failure due to power, cooling, or natural disaster. Extended outage affecting all hosted services and data." },
];

// =============================================================================
// 4. SECURITY_POLICIES -- Policy Templates
// =============================================================================

const SECURITY_POLICIES = [
  {
    name: "Acceptable Use Policy",
    purpose:
      "Define acceptable and unacceptable use of organizational information systems, networks, and data to protect the organization from legal and security risks.",
    scope:
      "Applies to all employees, contractors, consultants, temporary workers, and third parties who access organizational information systems and networks.",
    policy: [
      "All information systems and data are the property of the organization and are provided for business purposes.",
      "Users must use information systems responsibly and in compliance with all applicable laws, regulations, and organizational policies.",
      "Personal use of information systems is permitted in moderation provided it does not interfere with work duties, consume excessive resources, or violate any policy.",
      "Users must not attempt to access systems, data, or networks for which they are not authorized.",
      "Users must not install unauthorized software on organizational devices without IT approval.",
      "Users must not share their credentials with others or use another person's credentials.",
      "Users must not transmit sensitive or confidential information through insecure channels.",
      "Users must not use organizational systems for illegal activities, harassment, discrimination, or activities that could damage the organization's reputation.",
      "Users must not connect unauthorized devices to the organizational network without IT approval.",
      "Users must not disable or circumvent security controls including antivirus, firewall, or endpoint protection software.",
      "Users must lock their workstations when leaving them unattended.",
      "Users must report suspected security incidents or policy violations immediately to the security team.",
      "Internet and email usage may be monitored by the organization to ensure compliance with this policy.",
      "Violations of this policy may result in disciplinary action up to and including termination, and may also result in civil or criminal liability.",
    ],
    responsibilities: [
      "All Users: Comply with this policy and report violations.",
      "IT Department: Implement and maintain technical controls to enforce this policy.",
      "Management: Ensure staff understand and comply with this policy.",
      "Information Security: Monitor compliance and investigate violations.",
      "Human Resources: Enforce disciplinary actions for policy violations.",
    ],
  },
  {
    name: "Incident Response Policy",
    purpose:
      "Establish a structured approach to managing and responding to information security incidents to minimize impact and restore normal operations as quickly as possible.",
    scope:
      "Applies to all information security events and incidents affecting organizational systems, data, or services. Covers all employees, contractors, and third parties.",
    policy: [
      "The organization shall maintain an Incident Response Team (IRT) with defined roles and responsibilities.",
      "All employees must report suspected security incidents immediately through designated reporting channels.",
      "The IRT shall triage all reported events to determine if they constitute a security incident.",
      "Incidents shall be classified by severity (Critical, High, Medium, Low) with defined response timelines for each level.",
      "Critical incidents must be escalated to senior management within 1 hour of identification.",
      "The IRT shall follow documented incident response procedures covering preparation, identification, containment, eradication, recovery, and lessons learned.",
      "Short-term containment actions shall be taken immediately to limit incident impact.",
      "Long-term containment shall address the root cause while maintaining business operations.",
      "Eradication activities shall remove all traces of the incident from affected systems.",
      "Recovery shall restore systems to normal operations using verified clean backups or rebuilds.",
      "Evidence shall be preserved using forensically sound methods to support potential legal proceedings.",
      "External notifications (regulators, law enforcement, affected individuals) shall be made in compliance with applicable laws and regulations.",
      "Post-incident reviews shall be conducted within 5 business days of incident closure.",
      "Lessons learned shall be documented and used to improve security controls and incident response procedures.",
      "The incident response plan shall be tested at least annually through tabletop exercises or simulations.",
      "All incident response activities shall be documented in the incident tracking system.",
    ],
    responsibilities: [
      "Incident Response Team Lead: Coordinate incident response activities and manage communications.",
      "IRT Members: Execute incident response procedures and document activities.",
      "All Employees: Report security events promptly through designated channels.",
      "IT Operations: Provide technical support for containment and recovery activities.",
      "Legal Counsel: Advise on regulatory notification requirements and evidence preservation.",
      "Communications: Manage external communications regarding incidents.",
      "CISO: Provide strategic oversight and report to executive management.",
    ],
  },
  {
    name: "Password and Authentication Policy",
    purpose:
      "Establish requirements for creating, managing, and protecting authentication credentials to prevent unauthorized access to organizational systems and data.",
    scope:
      "Applies to all users and systems that require authentication, including employees, contractors, service accounts, and administrative accounts.",
    policy: [
      "All users must be assigned a unique identifier (username) for system access.",
      "Passwords must be a minimum of 12 characters in length.",
      "Passwords must include characters from at least three of the following categories: uppercase letters, lowercase letters, numbers, and special characters.",
      "Passwords must not contain the user's name, username, or common dictionary words.",
      "Passwords must not be reused within the last 12 password generations.",
      "Passwords must be changed at least every 90 days for standard accounts and every 60 days for privileged accounts.",
      "Accounts must be locked after 5 consecutive failed authentication attempts. Lockout duration shall be a minimum of 30 minutes or until manually unlocked.",
      "Multi-factor authentication (MFA) is required for all remote access, privileged access, and access to sensitive systems.",
      "Default passwords on all systems and devices must be changed before deployment.",
      "Passwords must never be stored in plaintext. Systems must use approved one-way hashing algorithms (bcrypt, scrypt, or Argon2id).",
      "Passwords must never be shared, written down in accessible locations, or transmitted in cleartext.",
      "Service account passwords must be a minimum of 25 characters and managed through a privileged access management solution.",
      "Password recovery mechanisms must verify identity before allowing password reset.",
      "Administrative access must use separate accounts dedicated to administrative functions.",
      "Session timeouts must be configured: 15 minutes for standard users, 5 minutes for privileged sessions.",
    ],
    responsibilities: [
      "All Users: Create strong passwords, protect credentials, and use MFA where required.",
      "IT Administration: Configure authentication systems per policy requirements.",
      "Information Security: Monitor authentication events and investigate anomalies.",
      "Help Desk: Verify identity before performing password resets.",
      "System Owners: Ensure systems comply with authentication requirements.",
    ],
  },
  {
    name: "Data Classification and Handling Policy",
    purpose:
      "Define a framework for classifying organizational data based on sensitivity and business value, and establish handling requirements for each classification level.",
    scope:
      "Applies to all data created, received, maintained, or transmitted by the organization in any format (electronic, paper, verbal).",
    policy: [
      "All organizational data must be classified into one of four levels: Public, Internal, Confidential, or Restricted.",
      "PUBLIC data is information approved for public disclosure. No special handling required.",
      "INTERNAL data is information intended for internal use only. Not sensitive but not for public distribution.",
      "CONFIDENTIAL data is sensitive information whose unauthorized disclosure could cause harm. Includes PII, financial data, and business strategies.",
      "RESTRICTED data is the most sensitive information whose unauthorized disclosure could cause severe harm. Includes regulated data (ePHI, PAN), trade secrets, and security credentials.",
      "Data owners are responsible for classifying data and reviewing classifications annually.",
      "Data must be labeled according to its classification level using approved marking methods.",
      "Restricted data must be encrypted at rest using AES-256 or equivalent and in transit using TLS 1.2 or higher.",
      "Confidential data should be encrypted at rest and must be encrypted in transit.",
      "Access to Confidential and Restricted data must follow least privilege and need-to-know principles.",
      "Restricted data must not be stored on personal devices, removable media, or unauthorized cloud services.",
      "Data must be disposed of securely when no longer needed, using methods appropriate to its classification level.",
      "Paper documents containing Confidential or Restricted data must be cross-cut shredded.",
      "Electronic media containing Confidential or Restricted data must be sanitized per NIST SP 800-88 guidelines.",
      "Data classification must be considered when sharing information with third parties. Appropriate agreements (NDAs, DPAs) must be in place.",
      "Violations of data handling requirements must be reported as security incidents.",
    ],
    responsibilities: [
      "Data Owners: Classify data, approve access, review classifications annually.",
      "Data Custodians: Implement appropriate handling controls based on classification.",
      "All Users: Handle data according to its classification. Report misclassified or mishandled data.",
      "Information Security: Define classification criteria, provide guidance, monitor compliance.",
      "Legal/Compliance: Advise on regulatory classification requirements.",
    ],
  },
  {
    name: "Bring Your Own Device (BYOD) Policy",
    purpose:
      "Define requirements and restrictions for using personally-owned devices to access organizational systems and data, balancing productivity with security.",
    scope:
      "Applies to all employees and authorized contractors who use personally-owned devices (smartphones, tablets, laptops) to access organizational systems, data, or networks.",
    policy: [
      "Use of personal devices for work purposes is a privilege, not a right, and may be revoked at any time.",
      "Personal devices must be registered with IT before accessing organizational resources.",
      "Personal devices must meet minimum security requirements: current operating system with latest patches, device encryption enabled, screen lock with PIN/password/biometric, and approved anti-malware (where applicable).",
      "The organization reserves the right to install a Mobile Device Management (MDM) agent on personal devices used for work.",
      "Organizational data on personal devices must be segregated from personal data using containerization or approved work profiles.",
      "The organization reserves the right to remotely wipe organizational data from personal devices in case of loss, theft, or policy violation.",
      "Personal devices must not be used to access Restricted data unless explicitly approved by the CISO.",
      "Users must not root, jailbreak, or otherwise modify the operating system of devices used for work.",
      "Users must not connect personal devices to the corporate network except through approved methods (VPN, guest WiFi).",
      "Users must notify IT immediately if a personal device used for work is lost, stolen, or compromised.",
      "The organization is not responsible for personal data loss during device wiping or management activities.",
      "Users must back up personal data separately from organizational data.",
      "Personal devices used for work may be subject to examination during security investigations, with appropriate legal authorization.",
      "Users must remove all organizational data and access upon termination or when the device is no longer used for work.",
    ],
    responsibilities: [
      "Employees: Register devices, maintain security requirements, report lost/stolen devices.",
      "IT Department: Manage device registration, deploy MDM, provide technical support.",
      "Information Security: Define security requirements, monitor compliance, respond to incidents.",
      "HR: Communicate policy to employees, enforce compliance.",
      "Legal: Advise on privacy and employment law considerations.",
    ],
  },
  {
    name: "Remote Work Security Policy",
    purpose:
      "Establish security requirements for remote work arrangements to protect organizational information and systems when accessed from outside the corporate environment.",
    scope:
      "Applies to all employees, contractors, and authorized third parties who work remotely or access organizational systems from outside the corporate network.",
    policy: [
      "Remote work arrangements must be approved by management and documented.",
      "Remote workers must use organization-provided or approved devices that meet security requirements.",
      "All remote access to organizational networks must use an approved VPN with multi-factor authentication.",
      "Remote workers must ensure their home network is secured with a strong WiFi password and current router firmware.",
      "Public WiFi must not be used for accessing organizational systems without VPN protection.",
      "Remote workspaces must prevent unauthorized viewing of sensitive information (e.g., privacy screens, private rooms for calls).",
      "Organizational data must not be printed on personal printers unless approved. Printed materials must be securely stored and shredded when no longer needed.",
      "Remote workers must lock their devices when stepping away and store them securely when not in use.",
      "Video conferencing must use approved platforms with appropriate security settings (passwords, waiting rooms).",
      "Remote workers must not allow unauthorized individuals to use their work devices or observe sensitive work activities.",
      "Remote workers must maintain the same security posture as in-office workers, including keeping software updated and security tools active.",
      "Remote workers must report security incidents immediately, including lost or stolen devices.",
      "The organization may monitor remote access connections for security purposes.",
      "Remote work arrangements may be modified or terminated based on security concerns.",
    ],
    responsibilities: [
      "Remote Workers: Comply with all security requirements, maintain secure work environment.",
      "Managers: Approve remote work arrangements, ensure staff compliance.",
      "IT Department: Provide secure remote access infrastructure, support remote workers.",
      "Information Security: Define security requirements, monitor remote access, investigate incidents.",
      "HR: Establish remote work policies and agreements.",
    ],
  },
  {
    name: "Vulnerability Management Policy",
    purpose:
      "Establish a systematic approach to identifying, evaluating, treating, and reporting on security vulnerabilities in organizational systems to reduce the attack surface and minimize risk.",
    scope:
      "Applies to all information systems, applications, network devices, and cloud services owned, operated, or managed by the organization.",
    policy: [
      "All systems in scope must be subject to regular vulnerability assessment using approved scanning tools.",
      "Automated vulnerability scans must be conducted at least monthly for internal systems and quarterly for external-facing systems (or as required by compliance frameworks).",
      "Authenticated scans must be used where possible to achieve comprehensive vulnerability detection.",
      "Newly discovered vulnerabilities must be assessed and prioritized using the Common Vulnerability Scoring System (CVSS) and organizational context.",
      "Critical vulnerabilities (CVSS 9.0-10.0) must be remediated or mitigated within 15 calendar days.",
      "High vulnerabilities (CVSS 7.0-8.9) must be remediated or mitigated within 30 calendar days.",
      "Medium vulnerabilities (CVSS 4.0-6.9) must be remediated or mitigated within 90 calendar days.",
      "Low vulnerabilities (CVSS 0.1-3.9) must be remediated within 180 calendar days or accepted with documented justification.",
      "Exceptions to remediation timelines must be approved by the CISO with documented business justification and compensating controls.",
      "Penetration testing must be conducted at least annually by qualified internal or external resources.",
      "Web application security testing must be conducted before production deployment and annually thereafter.",
      "Vulnerability scan results must be tracked in a centralized system with assigned ownership and remediation status.",
      "Monthly vulnerability metrics must be reported to IT management. Quarterly reports must be provided to senior leadership.",
      "Zero-day vulnerabilities with active exploitation must be treated as critical incidents and addressed through the incident response process.",
      "Third-party and open-source software components must be included in vulnerability management scope.",
    ],
    responsibilities: [
      "Information Security: Manage scanning program, analyze results, track remediation, report metrics.",
      "System Owners: Remediate vulnerabilities within defined timelines on their systems.",
      "IT Operations: Apply patches and configuration changes per remediation plans.",
      "Application Development: Remediate application vulnerabilities and follow secure coding practices.",
      "CISO: Approve exceptions and provide strategic oversight.",
      "Third-Party Risk Management: Ensure vendor systems are included in vulnerability management.",
    ],
  },
  {
    name: "Change Management Policy",
    purpose:
      "Establish a structured process for managing changes to information systems to minimize the risk of disruptions and security incidents caused by uncontrolled changes.",
    scope:
      "Applies to all changes to production information systems, applications, databases, network configurations, and security infrastructure.",
    policy: [
      "All changes to production systems must be authorized through the formal change management process.",
      "Changes must be classified as Standard (pre-approved, low-risk), Normal (requires CAB review), or Emergency (urgent, post-implementation review).",
      "A change request must document the change description, business justification, risk assessment, implementation plan, test plan, rollback plan, and required approvals.",
      "All Normal changes must be reviewed and approved by the Change Advisory Board (CAB) before implementation.",
      "Security impact assessments must be completed for all changes that affect security controls, access permissions, or data handling.",
      "Changes must be tested in a non-production environment before production deployment.",
      "Emergency changes may be implemented without prior CAB approval but must be documented and reviewed within 5 business days.",
      "All changes must have a documented rollback plan that has been validated before implementation.",
      "Change implementers must not be the same persons who approved the change (separation of duties).",
      "Post-implementation reviews must verify that changes achieved their objectives without introducing issues.",
      "Failed changes must be rolled back and documented with root cause analysis.",
      "The change management system must maintain a complete audit trail of all change requests, approvals, and implementation records.",
      "Change windows must be defined to minimize business impact. Production changes outside defined windows require additional approval.",
      "Unauthorized changes detected through monitoring must be investigated as potential security incidents.",
    ],
    responsibilities: [
      "Change Requestor: Submit change requests with complete documentation.",
      "Change Advisory Board: Review and approve Normal changes.",
      "Change Manager: Coordinate change management process and maintain records.",
      "Change Implementer: Execute approved changes per implementation plan.",
      "System Owners: Approve changes to their systems and validate post-implementation.",
      "Information Security: Conduct security impact assessments and monitor for unauthorized changes.",
    ],
  },
  {
    name: "Business Continuity and Disaster Recovery Policy",
    purpose:
      "Establish requirements for maintaining business operations and recovering information systems following disruptive events to minimize impact and ensure organizational resilience.",
    scope:
      "Applies to all critical business processes, information systems, facilities, and personnel essential for maintaining organizational operations.",
    policy: [
      "The organization shall maintain a Business Continuity Management System (BCMS) that addresses prevention, preparedness, response, and recovery.",
      "Business Impact Analysis (BIA) must be conducted annually to identify critical business processes and their dependencies.",
      "Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO) must be defined for all critical systems based on BIA results.",
      "Business Continuity Plans (BCP) must be developed for all critical business processes.",
      "Disaster Recovery Plans (DRP) must be developed for all critical information systems with detailed recovery procedures.",
      "Critical data must be backed up according to defined schedules. Backup frequency must meet or exceed RPO requirements.",
      "Backups must follow the 3-2-1 rule: at least 3 copies, on 2 different media types, with 1 copy offsite.",
      "Backup restoration must be tested quarterly, and full DR tests must be conducted at least annually.",
      "Alternate processing sites or cloud-based recovery must be maintained for systems with RTO of 24 hours or less.",
      "Business continuity and disaster recovery plans must be tested at least annually through tabletop exercises, walkthrough tests, or full simulation exercises.",
      "Plan updates must occur after significant changes to the business, IT environment, or after plan activation.",
      "Emergency communication procedures must be documented and tested, including out-of-band communication methods.",
      "Succession plans must be documented for key personnel to ensure continuity of critical functions.",
      "Third-party service provider continuity must be addressed through contractual requirements and regular assessment.",
      "Post-incident and post-test reviews must identify improvements and update plans accordingly.",
    ],
    responsibilities: [
      "Business Continuity Manager: Maintain BCMS, coordinate planning and testing.",
      "Business Unit Leaders: Participate in BIA, develop department BCPs, participate in exercises.",
      "IT Operations: Develop and maintain DRPs, manage backups, maintain recovery infrastructure.",
      "Information Security: Ensure security is maintained during continuity events.",
      "Executive Management: Approve plans, allocate resources, participate in exercises.",
      "All Employees: Understand their roles in continuity plans and participate in exercises.",
    ],
  },
  {
    name: "Third-Party Risk Management Policy",
    purpose:
      "Establish a framework for identifying, assessing, and managing security risks associated with third-party vendors, service providers, and business partners who access or process organizational data.",
    scope:
      "Applies to all third parties including vendors, suppliers, contractors, service providers, and business partners who have access to organizational systems, data, or facilities.",
    policy: [
      "All third parties must be subject to risk assessment before being granted access to organizational systems or data.",
      "Third parties must be classified by risk tier (Critical, High, Medium, Low) based on the sensitivity of data accessed and criticality of services provided.",
      "Critical and High-risk third parties must complete a comprehensive security assessment including questionnaire, evidence review, and where applicable, on-site assessment.",
      "Security requirements must be included in all third-party contracts, including data protection obligations, incident notification requirements, and audit rights.",
      "Third parties processing personal data must execute Data Processing Agreements (DPAs) meeting applicable regulatory requirements.",
      "Third parties must maintain security certifications or demonstrate equivalent controls as appropriate for their risk tier.",
      "Ongoing monitoring of third-party security posture must be conducted at intervals based on risk tier: Critical (quarterly), High (semi-annually), Medium (annually), Low (biannually).",
      "Third parties must notify the organization of security incidents affecting organizational data within 24 hours of detection.",
      "Third-party access must follow the principle of least privilege and be limited to the minimum necessary for the contracted services.",
      "Third-party access must be reviewed at least annually and revoked upon contract termination.",
      "A centralized inventory of all third-party relationships must be maintained including risk tier, data shared, access granted, and contract status.",
      "Fourth-party (subcontractor) risk must be addressed in contracts, requiring notification and approval before subcontracting.",
      "Exit strategies and transition plans must be documented for critical third-party relationships.",
      "Third-party risk metrics must be reported to senior management quarterly.",
    ],
    responsibilities: [
      "Third-Party Risk Management Team: Conduct assessments, maintain inventory, monitor compliance.",
      "Procurement: Include security requirements in RFPs and contracts.",
      "Business Owners: Identify and sponsor third-party relationships, participate in risk assessment.",
      "Legal: Review and approve contracts including security and data protection clauses.",
      "Information Security: Define security requirements, review assessments, respond to third-party incidents.",
      "CISO: Approve high-risk third-party engagements and review quarterly metrics.",
    ],
  },
];

// =============================================================================
// Module Exports
// =============================================================================

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    FRAMEWORKS,
    COMPLIANCE_CHECKLISTS,
    RISK_MATRICES,
    SECURITY_POLICIES,
  };
}
