// Incident Response Database — comprehensive IR playbooks, forensic commands, evidence handling, and regulatory requirements

export const IR_DATABASE = {
  phases: [
    {
      name: "Preparation",
      description: "Establish incident response capability before incidents occur. Build the team, tools, and processes needed for effective response.",
      activities: [
        "Develop and maintain incident response plan (IRP)",
        "Establish incident response team (IRT) with defined roles",
        "Create communication plans for internal and external stakeholders",
        "Deploy and configure monitoring, logging, and alerting infrastructure",
        "Conduct tabletop exercises and red team drills quarterly",
        "Maintain asset inventory and network diagrams",
        "Establish relationships with law enforcement and CERT contacts",
        "Create forensic toolkit with validated tools and procedures",
        "Define incident classification and severity levels",
        "Establish evidence handling and chain of custody procedures",
        "Deploy endpoint detection and response (EDR) agents",
        "Configure centralized log aggregation (SIEM)",
        "Maintain runbooks and playbooks for common incident types",
        "Train all employees on security awareness and incident reporting",
        "Establish retainer agreements with external IR firms"
      ]
    },
    {
      name: "Identification",
      description: "Detect, validate, and classify the incident. Determine scope, impact, and affected systems.",
      activities: [
        "Monitor alerts from SIEM, IDS/IPS, EDR, and AV",
        "Validate alert — determine if it is a true positive",
        "Classify incident type (malware, data breach, unauthorized access, etc.)",
        "Determine severity level based on classification criteria",
        "Document initial indicators of compromise (IOCs)",
        "Identify affected systems, users, and data",
        "Preserve volatile evidence (memory dumps, network connections)",
        "Create incident ticket with timeline and initial findings",
        "Notify incident commander and relevant team members",
        "Begin evidence collection and chain of custody documentation"
      ]
    },
    {
      name: "Containment",
      description: "Limit the scope and impact of the incident. Prevent further damage while preserving evidence.",
      activities: [
        "Short-term containment: isolate affected systems from network",
        "Implement firewall rules to block attacker IP addresses",
        "Disable compromised user accounts",
        "Block malicious domains and IP addresses at DNS/proxy",
        "Take forensic images of affected systems before remediation",
        "Implement network segmentation to contain spread",
        "Deploy additional monitoring on adjacent systems",
        "Change credentials for affected and potentially affected accounts",
        "Preserve system logs and memory dumps",
        "Document all containment actions taken with timestamps"
      ]
    },
    {
      name: "Eradication",
      description: "Remove the threat from the environment. Eliminate malware, close vulnerabilities, and remove unauthorized access.",
      activities: [
        "Remove malware and backdoors from affected systems",
        "Patch exploited vulnerabilities",
        "Reset all potentially compromised credentials",
        "Rebuild compromised systems from known-good images",
        "Remove unauthorized user accounts and access",
        "Update firewall, IDS, and AV signatures",
        "Verify removal with additional scanning",
        "Review and harden configurations on affected systems",
        "Validate that attacker persistence mechanisms are eliminated",
        "Document root cause analysis"
      ]
    },
    {
      name: "Recovery",
      description: "Restore systems to normal operations. Validate that the threat is eliminated and monitor for recurrence.",
      activities: [
        "Restore systems from clean backups or rebuild",
        "Validate system integrity before returning to production",
        "Gradually restore network connectivity",
        "Implement enhanced monitoring for 30-90 days",
        "Verify business operations are functioning normally",
        "Monitor for indicators of re-compromise",
        "Validate that all patches and mitigations are in place",
        "Restore user access with new credentials",
        "Communicate restoration status to stakeholders",
        "Continue forensic analysis to ensure completeness"
      ]
    },
    {
      name: "Lessons Learned",
      description: "Conduct post-incident review. Improve processes, tools, and training based on incident findings.",
      activities: [
        "Hold post-incident review meeting within 2 weeks",
        "Document complete incident timeline",
        "Identify what worked well and what needs improvement",
        "Update incident response plan based on findings",
        "Implement additional security controls to prevent recurrence",
        "Update detection rules and monitoring",
        "Share threat intelligence with trusted partners (TLP protocol)",
        "Conduct additional training based on gaps identified",
        "Update asset inventory and network diagrams",
        "File final incident report with executive summary"
      ]
    }
  ],

  playbooks: [
    {
      name: "Ransomware Incident",
      severity: "Critical",
      description: "Ransomware has encrypted files on one or more systems. May involve data exfiltration (double extortion). Time-critical: encryption may be spreading.",
      indicators: [
        "Files with new extensions (.encrypted, .locked, .crypt, etc.)",
        "Ransom notes on desktop or in directories",
        "Mass file modification events in short timeframe",
        "Spike in CPU usage from encryption processes",
        "Failed access to shared drives or databases",
        "Outbound connections to known ransomware C2 infrastructure",
        "vssadmin or wmic shadowcopy delete commands executed",
        "Disabled or tampered antivirus/EDR",
        "BCDEdit commands modifying boot configuration",
        "PowerShell or WMI used for lateral movement"
      ],
      immediateActions: [
        "Isolate affected systems from network immediately (disconnect cable/disable WiFi)",
        "Do NOT power off systems — volatile memory contains decryption keys",
        "Identify and isolate patient zero (first infected system)",
        "Block C2 domains/IPs at firewall and DNS",
        "Disable affected user accounts",
        "Capture memory dumps of infected systems before reboot",
        "Preserve ransom note — contains variant identification clues",
        "Check if ransomware variant has known decryptor (NoMoreRansom.org)",
        "Activate incident response team and notify management"
      ],
      containmentSteps: [
        "Segment network to prevent lateral movement",
        "Disable SMB (TCP 445) and RDP (TCP 3389) across network if feasible",
        "Block lateral movement protocols at network boundary",
        "Disable administrative shares (C$, ADMIN$)",
        "Force password reset for all domain accounts",
        "Disable Group Policy if used for deployment",
        "Take forensic images of infected systems",
        "Identify encryption scope: local drives, network shares, cloud storage",
        "Check backup integrity — ransomware may have targeted backups",
        "Deploy additional EDR coverage on unaffected systems"
      ],
      eradicationSteps: [
        "Identify ransomware variant and initial access vector",
        "Remove ransomware binaries and associated files",
        "Remove scheduled tasks and registry persistence",
        "Patch the vulnerability used for initial access",
        "Reset all credentials, especially domain admin",
        "Rebuild affected systems from known-good images",
        "Scan all systems for dormant ransomware components",
        "Review and reset service account credentials",
        "Verify backup integrity before restoration"
      ],
      recoverySteps: [
        "Restore from clean backups (test in isolated environment first)",
        "Prioritize restoration by business criticality",
        "Validate restored data integrity",
        "Re-enable network connectivity gradually",
        "Monitor restored systems intensively for 30 days",
        "Implement MFA on all remote access",
        "Deploy improved endpoint protection",
        "Conduct user awareness training on phishing"
      ],
      evidenceCollection: [
        "Memory dumps from infected systems",
        "Ransomware binary samples",
        "Ransom notes (all variants found)",
        "Network traffic logs showing C2 communication",
        "Windows Event Logs (Security, System, PowerShell)",
        "Firewall and proxy logs",
        "Email headers of initial phishing email",
        "File system timestamps showing encryption pattern",
        "Registry hives from infected systems",
        "Active Directory logs showing lateral movement"
      ],
      communicationPlan: "Notify executive leadership immediately. Brief legal counsel on regulatory obligations. Prepare customer notification if data exfiltrated. Contact cyber insurance carrier. Consider engaging law enforcement (FBI IC3, CISA). Do NOT communicate with threat actor without legal guidance. Prepare public statement if breach becomes public.",
      lessonsLearned: [
        "Was initial access vector identified and remediated?",
        "Were backups sufficient and tested regularly?",
        "Was network segmentation adequate to limit blast radius?",
        "Were detection capabilities sufficient for early warning?",
        "Was the response time acceptable?",
        "Were communication procedures followed?"
      ]
    },
    {
      name: "Data Breach / Data Exfiltration",
      severity: "Critical",
      description: "Confirmed unauthorized access to and/or exfiltration of sensitive data including PII, financial data, healthcare records, or intellectual property.",
      indicators: [
        "Large data transfers to external destinations",
        "Unusual database queries or bulk data exports",
        "Access to data stores from unauthorized systems or accounts",
        "Data found on dark web or paste sites",
        "Customer reports of identity theft or fraud",
        "DLP alerts for sensitive data leaving the network",
        "Cloud storage buckets accessed from unexpected locations",
        "Abnormal API usage patterns or rate increases",
        "Archive files (ZIP, RAR, 7z) created on servers",
        "DNS tunneling or steganographic data channels"
      ],
      immediateActions: [
        "Identify what data was accessed and potentially exfiltrated",
        "Determine data classification level (PII, PHI, PCI, trade secrets)",
        "Isolate affected data stores and systems",
        "Revoke access tokens and API keys",
        "Engage legal counsel immediately",
        "Preserve all logs and evidence",
        "Notify privacy officer and DPO",
        "Begin regulatory notification clock tracking"
      ],
      containmentSteps: [
        "Block exfiltration channels (IPs, domains, protocols)",
        "Disable compromised accounts and API keys",
        "Implement additional DLP rules",
        "Segment affected data stores",
        "Monitor for continued unauthorized access",
        "Revoke all active sessions for affected accounts",
        "Disable VPN and remote access for affected users",
        "Capture network traffic for forensic analysis"
      ],
      eradicationSteps: [
        "Remove unauthorized access mechanisms",
        "Patch vulnerabilities that enabled access",
        "Reset all credentials for affected systems",
        "Rotate encryption keys and certificates",
        "Review and restrict data access permissions",
        "Implement additional access controls and monitoring"
      ],
      recoverySteps: [
        "Restore secure access with enhanced controls",
        "Implement data loss prevention tools",
        "Deploy database activity monitoring",
        "Conduct data classification review",
        "Implement enhanced access logging",
        "Review and update data retention policies"
      ],
      evidenceCollection: [
        "Database query logs showing unauthorized access",
        "Network traffic captures showing data transfer",
        "DLP alert logs",
        "Cloud access logs (CloudTrail, Azure Activity Log, GCP Audit Log)",
        "VPN and remote access logs",
        "Email server logs",
        "File server access logs",
        "API gateway logs"
      ],
      communicationPlan: "Engage legal counsel before any external notification. Determine regulatory notification requirements based on data type and jurisdiction. Prepare breach notification letters. Notify affected individuals within required timeframes. File reports with relevant regulators (state AG, HHS, PCI Council, SEC). Offer credit monitoring for PII breaches. Prepare FAQ for customer support.",
      lessonsLearned: [
        "Was data classified and access controlled appropriately?",
        "Were DLP tools effective at detecting exfiltration?",
        "Were regulatory notifications timely and complete?",
        "Was the data inventory accurate?",
        "Were encryption controls adequate?"
      ]
    },
    {
      name: "Insider Threat",
      severity: "High",
      description: "Malicious or negligent insider is accessing, stealing, or sabotaging systems and data. May be a current employee, contractor, or recently terminated individual.",
      indicators: [
        "Access to systems or data outside job responsibilities",
        "Large file downloads or copies to removable media",
        "Email forwarding rules to personal accounts",
        "After-hours system access without business justification",
        "Accessing systems after termination (delayed account disable)",
        "Unusual cloud storage uploads (personal Google Drive, Dropbox)",
        "Screenshots or recordings of sensitive data",
        "Database queries not consistent with job role",
        "Attempting to access privileged accounts or systems",
        "Behavioral indicators: disgruntlement, financial stress, resignation notice"
      ],
      immediateActions: [
        "Confirm and document the suspicious activity with evidence",
        "Engage HR and legal counsel before confronting the individual",
        "Preserve all evidence without alerting the subject",
        "Review access logs to determine full scope of access",
        "Ensure the individual's account access is being monitored",
        "Coordinate with physical security if needed"
      ],
      containmentSteps: [
        "Restrict access to sensitive systems without alerting subject (if investigation ongoing)",
        "If termination: immediately disable all accounts, badges, and remote access",
        "Collect and preserve company devices",
        "Block personal email and cloud storage uploads",
        "Disable USB and removable media access",
        "Review and revoke API keys and service account access",
        "Change shared credentials the individual had access to"
      ],
      eradicationSteps: [
        "Remove all access and accounts",
        "Change credentials for all shared accounts",
        "Review systems accessed for backdoors or unauthorized changes",
        "Audit data access to determine what was compromised",
        "Remove any personal devices from network access"
      ],
      recoverySteps: [
        "Implement enhanced monitoring for similar behavior patterns",
        "Review access control policies and principle of least privilege",
        "Implement user behavior analytics (UBA/UEBA)",
        "Update termination procedures to include immediate access revocation",
        "Conduct security awareness training"
      ],
      evidenceCollection: [
        "System access logs with timestamps",
        "File access and download logs",
        "Email logs showing forwarding rules or data transfers",
        "USB device connection logs",
        "Badge access logs (physical security)",
        "Cloud storage audit logs",
        "Database query logs",
        "Screenshots and recordings of suspicious activity"
      ],
      communicationPlan: "Coordinate with HR and legal before any action. Follow employment law requirements for investigation. Document all evidence in admissible format. Consider law enforcement referral for criminal activity. Maintain confidentiality during investigation. Brief executive leadership on situation and risks.",
      lessonsLearned: [
        "Were access controls and least privilege followed?",
        "Were DLP and UBA tools effective?",
        "Was the termination process timely?",
        "Were behavioral indicators identified early enough?",
        "Were background checks adequate?"
      ]
    },
    {
      name: "DDoS Attack",
      severity: "High",
      description: "Distributed denial of service attack overwhelming network bandwidth, server resources, or application capacity. May be volumetric, protocol, or application layer.",
      indicators: [
        "Sudden spike in inbound traffic volume",
        "Services becoming unresponsive or extremely slow",
        "High CPU/memory usage on servers and network equipment",
        "Unusual traffic patterns (single URL, geographic anomaly)",
        "SYN flood indicators (half-open connections)",
        "DNS amplification traffic (large DNS responses)",
        "NTP amplification traffic (monlist responses)",
        "HTTP flood (excessive requests to specific endpoints)",
        "Slowloris indicators (many connections held open with partial headers)"
      ],
      immediateActions: [
        "Activate DDoS mitigation service (Cloudflare, Akamai, AWS Shield)",
        "Enable rate limiting on edge infrastructure",
        "Identify attack type: volumetric, protocol, or application layer",
        "Null-route or blackhole attacking IP ranges if identifiable",
        "Scale infrastructure horizontally if cloud-based",
        "Engage ISP for upstream filtering",
        "Communicate service status to users"
      ],
      containmentSteps: [
        "Deploy WAF rules to filter malicious traffic patterns",
        "Implement geo-blocking if attack originates from specific regions",
        "Enable SYN cookies to mitigate SYN floods",
        "Configure connection rate limits per IP",
        "Enable CAPTCHA or JavaScript challenges for suspicious traffic",
        "Increase server capacity and connection limits",
        "Implement connection timeout reductions"
      ],
      eradicationSteps: [
        "Maintain DDoS mitigation until attack subsides",
        "Analyze attack patterns for future prevention",
        "Block identified botnet IPs permanently",
        "Update incident playbook with attack signatures"
      ],
      recoverySteps: [
        "Gradually reduce mitigation as attack subsides",
        "Monitor for follow-up attacks",
        "Review and optimize DDoS protection configuration",
        "Conduct capacity planning for future attacks",
        "Implement always-on DDoS protection"
      ],
      evidenceCollection: [
        "Network flow data (NetFlow, sFlow)",
        "Firewall and IDS logs",
        "Web server access logs",
        "DDoS mitigation service reports",
        "Network packet captures (sampled)",
        "ISP communication records"
      ],
      communicationPlan: "Update status page for affected services. Notify customers via email and social media. Engage ISP and DDoS mitigation provider. File report with law enforcement if significant business impact. Consider threat intelligence sharing with industry peers.",
      lessonsLearned: [
        "Was DDoS mitigation activated quickly enough?",
        "Was infrastructure scaling adequate?",
        "Were communication procedures effective?",
        "Is always-on DDoS protection justified?",
        "Were application-layer attacks properly identified?"
      ]
    },
    {
      name: "Phishing / Credential Compromise",
      severity: "High",
      description: "User credentials have been compromised via phishing email, credential stuffing, or social engineering. May affect single user or multiple accounts.",
      indicators: [
        "User reports clicking phishing link or providing credentials",
        "Impossible travel logins (same account from distant locations)",
        "Login from known-bad IP or TOR exit node",
        "New email forwarding rules created",
        "MFA bypass or MFA fatigue attacks detected",
        "OAuth consent granted to malicious application",
        "Unusual email sending patterns from compromised account",
        "Password spray alerts (many accounts, few passwords)"
      ],
      immediateActions: [
        "Reset password for compromised accounts immediately",
        "Revoke all active sessions and refresh tokens",
        "Remove unauthorized email forwarding rules",
        "Revoke unauthorized OAuth app consent",
        "Check for MFA enrollment changes and revert",
        "Block sender domain and reported phishing URLs",
        "Search email for similar phishing messages sent to other users"
      ],
      containmentSteps: [
        "Force password reset for all potentially affected accounts",
        "Enable MFA if not already enabled",
        "Review account activity for unauthorized actions",
        "Block phishing infrastructure at email gateway, proxy, and DNS",
        "Deploy phishing email search across all mailboxes",
        "Quarantine identified phishing emails",
        "Review and revoke OAuth grants for affected accounts"
      ],
      eradicationSteps: [
        "Remove phishing emails from all mailboxes",
        "Block sending domain and lookalike domains",
        "Report phishing site to hosting provider and Google Safe Browsing",
        "Update email security rules to detect similar campaigns",
        "Review and strengthen email authentication (SPF/DKIM/DMARC)"
      ],
      recoverySteps: [
        "Verify compromised accounts are fully secured",
        "Monitor accounts for 30 days for suspicious activity",
        "Conduct targeted phishing awareness training",
        "Implement enhanced email filtering rules",
        "Consider deploying phishing-resistant MFA (FIDO2/WebAuthn)"
      ],
      evidenceCollection: [
        "Original phishing email with full headers",
        "URLs and domains used in phishing",
        "Authentication logs showing unauthorized access",
        "Email forwarding rule creation logs",
        "OAuth consent grant logs",
        "Screenshots of phishing landing page"
      ],
      communicationPlan: "Notify affected users individually with remediation steps. Send company-wide phishing alert if campaign is widespread. Brief management on scope and impact. Report phishing to APWG (reportphishing@apwg.org) and relevant authorities.",
      lessonsLearned: [
        "Was phishing detected by technology or user report?",
        "Were email security controls effective?",
        "Was MFA in place and resistant to the attack type?",
        "Were users able to identify and report phishing?",
        "Was response time acceptable?"
      ]
    },
    {
      name: "Business Email Compromise (BEC)",
      severity: "Critical",
      description: "Attacker has compromised or spoofed a business email to conduct fraud — wire transfer requests, invoice manipulation, payroll diversion, or sensitive data theft.",
      indicators: [
        "Unusual wire transfer or payment change requests",
        "Executive email requesting urgent financial action",
        "Vendor requesting payment to new bank account",
        "Email from spoofed or lookalike domain",
        "Payroll or HR requests for employee W-2/tax forms",
        "Requests to bypass normal approval processes",
        "Slight variations in sender email address"
      ],
      immediateActions: [
        "If funds transferred: contact bank immediately to initiate recall",
        "Contact FBI IC3 and file complaint for wire fraud",
        "Preserve all email evidence with full headers",
        "Disable compromised email account",
        "Notify finance department to halt pending payments",
        "Verify request through out-of-band communication (phone call)"
      ],
      containmentSteps: [
        "Block spoofed/compromised sender domains",
        "Review all recent financial requests for fraud",
        "Implement additional verification for payment changes",
        "Review email rules for auto-forwarding to external addresses",
        "Scan for similar BEC attempts targeting other employees"
      ],
      eradicationSteps: [
        "Remove unauthorized access to email accounts",
        "Implement DMARC enforcement to prevent domain spoofing",
        "Update financial controls with dual-approval for changes",
        "Reset credentials for compromised accounts"
      ],
      recoverySteps: [
        "Work with banks and law enforcement for fund recovery",
        "Implement mandatory verbal verification for payment changes",
        "Deploy advanced email security with BEC detection",
        "Conduct targeted BEC awareness training for finance and HR"
      ],
      evidenceCollection: [
        "BEC emails with full headers",
        "Wire transfer records and bank communication",
        "Authentication logs for compromised accounts",
        "Email gateway logs",
        "Financial approval records"
      ],
      communicationPlan: "Contact bank immediately for fund recall. File FBI IC3 complaint. Engage legal counsel for liability assessment. Notify insurance carrier. Brief executive leadership. Do NOT tip off the attacker if account is being monitored.",
      lessonsLearned: [
        "Were financial verification procedures followed?",
        "Was DMARC enforcement in place?",
        "Were employees trained to recognize BEC?",
        "Were dual-approval controls effective?",
        "Was fund recovery successful?"
      ]
    },
    {
      name: "Supply Chain Compromise",
      severity: "Critical",
      description: "Trusted third-party software, hardware, or service has been compromised, introducing malicious code or backdoors into the organization through legitimate update channels.",
      indicators: [
        "Unexpected behavior from recently updated trusted software",
        "Network connections to unknown destinations from trusted applications",
        "Vendor advisory or public disclosure of compromise",
        "Unsigned or unexpectedly signed software updates",
        "Hash mismatch on downloaded packages",
        "New processes or services appearing after vendor update",
        "Threat intelligence reports of vendor compromise"
      ],
      immediateActions: [
        "Identify all systems running the compromised software/version",
        "Isolate affected systems from network",
        "Block update mechanisms for the compromised vendor",
        "Check for indicators of compromise (IOCs) published by vendor/researchers",
        "Assess whether the compromised component has access to sensitive data"
      ],
      containmentSteps: [
        "Disable or remove compromised software from all systems",
        "Block network connections to known malicious infrastructure",
        "Review all changes made by the compromised software",
        "Segment systems that cannot immediately remove the software",
        "Implement network monitoring for IOCs"
      ],
      eradicationSteps: [
        "Remove compromised software version from all systems",
        "Install clean version from verified source (if available)",
        "Review and reset credentials the software had access to",
        "Audit systems for persistence mechanisms left by the compromise",
        "Review software supply chain for similar risks"
      ],
      recoverySteps: [
        "Implement software composition analysis (SCA)",
        "Require vendor security assessments",
        "Implement integrity verification for software updates",
        "Deploy application allowlisting",
        "Review and reduce third-party software dependencies"
      ],
      evidenceCollection: [
        "Compromised software binaries and update packages",
        "Hash values of compromised vs clean versions",
        "Network traffic logs showing malicious connections",
        "System logs from affected hosts",
        "Vendor communications and advisories"
      ],
      communicationPlan: "Coordinate with vendor on timeline and remediation. Share IOCs with trusted industry peers (ISAC). Notify customers if their data may be affected. Brief board and executive team on risk. File regulatory notifications if required.",
      lessonsLearned: [
        "Was the supply chain risk identified in vendor assessment?",
        "Were software integrity checks in place?",
        "Was the response time adequate?",
        "Were alternative solutions available?",
        "Was vendor communication timely and transparent?"
      ]
    },
    {
      name: "APT Intrusion",
      severity: "Critical",
      description: "Advanced persistent threat actor has established long-term presence in the network. Characterized by sophisticated techniques, custom malware, and objectives aligned with nation-state or organized crime interests.",
      indicators: [
        "Custom malware not detected by commercial AV",
        "Long-dwell-time indicators (months of access)",
        "Living-off-the-land techniques (PowerShell, WMI, scheduled tasks)",
        "Data staging in unusual directories",
        "Lateral movement via stolen credentials or token manipulation",
        "DNS tunneling or covert communication channels",
        "Compromise of domain controllers or authentication infrastructure",
        "Targeting of specific high-value individuals or data",
        "Use of zero-day exploits"
      ],
      immediateActions: [
        "Do NOT tip off the attacker — they will destroy evidence and find new footholds",
        "Engage specialized APT incident response firm",
        "Begin covert monitoring of attacker activity",
        "Identify all compromised systems and accounts through threat hunting",
        "Prepare for coordinated eradication (simultaneous across all footholds)",
        "Brief executive leadership with appropriate classification"
      ],
      containmentSteps: [
        "Map the full extent of compromise before taking action",
        "Identify all persistence mechanisms and backdoors",
        "Build a parallel clean infrastructure for cutover",
        "Prepare new credentials for coordinated reset",
        "Coordinate eradication timing — must be simultaneous",
        "Establish out-of-band communication channels (assume email is compromised)"
      ],
      eradicationSteps: [
        "Execute coordinated eradication plan across all systems simultaneously",
        "Reset all credentials including Kerberos KRBTGT (twice)",
        "Rebuild domain controllers from scratch",
        "Remove all identified persistence mechanisms",
        "Implement new security monitoring focused on known TTPs",
        "Rotate all certificates and API keys"
      ],
      recoverySteps: [
        "Rebuild critical infrastructure with enhanced security",
        "Implement network segmentation and zero-trust architecture",
        "Deploy advanced threat detection (EDR, NDR, deception)",
        "Conduct ongoing threat hunting for 6-12 months",
        "Implement privileged access management (PAM)",
        "Review and enhance security architecture"
      ],
      evidenceCollection: [
        "Malware samples and custom tools",
        "Memory dumps from compromised systems",
        "Full disk images of key systems",
        "Network traffic captures",
        "Active Directory database copies",
        "DNS query logs",
        "Authentication logs spanning months",
        "Timeline of attacker activity"
      ],
      communicationPlan: "Engage external IR firm under legal privilege (through counsel). Brief board of directors. Coordinate with law enforcement (FBI, CISA) under NDA. Use out-of-band communication only. Prepare for potential public disclosure. Consider intelligence-sharing with ISACs.",
      lessonsLearned: [
        "How did the attacker gain initial access?",
        "What was the total dwell time?",
        "Were detection capabilities adequate?",
        "Was the eradication plan coordinated effectively?",
        "Were all persistence mechanisms identified?",
        "Has the security architecture been improved to prevent recurrence?"
      ]
    },
    {
      name: "Cryptomining / Cryptojacking",
      severity: "Medium",
      description: "Unauthorized cryptocurrency mining software has been deployed on systems, consuming compute resources and electricity. May indicate broader compromise.",
      indicators: [
        "High CPU/GPU usage on servers or workstations",
        "Connections to known mining pool domains/IPs",
        "Stratum protocol traffic on unusual ports",
        "Increased electricity costs",
        "Performance degradation reported by users",
        "Unknown processes consuming significant CPU",
        "Kubernetes pods with high resource requests",
        "Cloud bill spike from unauthorized compute instances"
      ],
      immediateActions: [
        "Identify and terminate mining processes",
        "Block mining pool domains and IP addresses",
        "Identify how the miner was deployed (vulnerability, credential theft, insider)",
        "Check for additional compromise — miners often accompany other malware"
      ],
      containmentSteps: [
        "Block Stratum mining protocol at network level",
        "Remove cryptocurrency mining binaries",
        "Patch the vulnerability used for deployment",
        "Reset credentials if used for lateral deployment",
        "Review container images for embedded miners",
        "Audit cloud resources for unauthorized instances"
      ],
      eradicationSteps: [
        "Remove all mining software and associated persistence",
        "Patch exploited vulnerabilities",
        "Clean or rebuild compromised container images",
        "Terminate unauthorized cloud instances",
        "Scan all systems for additional miners"
      ],
      recoverySteps: [
        "Implement resource monitoring and alerting",
        "Deploy cloud cost anomaly detection",
        "Implement container image scanning in CI/CD",
        "Review and restrict outbound network access"
      ],
      evidenceCollection: [
        "Mining binary samples",
        "Process execution logs",
        "Network connections to mining pools",
        "Resource usage logs (CPU, GPU, memory)",
        "Cloud billing records",
        "Container deployment logs"
      ],
      communicationPlan: "Notify IT and security teams. Report to management if cloud costs are significant. No external notification typically required unless part of larger breach.",
      lessonsLearned: [
        "How was the miner deployed?",
        "Were resource monitoring alerts in place?",
        "Was the compromised system part of a larger attack?",
        "Were container images properly validated?",
        "Were cloud resource limits configured?"
      ]
    },
    {
      name: "Web Defacement",
      severity: "Medium",
      description: "Unauthorized modification of website content. May indicate deeper compromise of web servers or content management systems.",
      indicators: [
        "Visual changes to website not authorized by content team",
        "Web monitoring alerts for content changes",
        "Modified HTML/JS/CSS files on web server",
        "Unauthorized CMS admin account activity",
        "Search engine indexing of defaced content"
      ],
      immediateActions: [
        "Take screenshot and preserve defaced content as evidence",
        "Restore website from known-good backup or CDN cache",
        "Take web server offline if backup not immediately available",
        "Identify how the attacker gained access",
        "Check for additional compromise (backdoors, webshells)"
      ],
      containmentSteps: [
        "Isolate web server from network",
        "Reset all CMS and server credentials",
        "Review file integrity monitoring logs",
        "Scan for web shells and backdoors",
        "Review web server access logs for attack vector"
      ],
      eradicationSteps: [
        "Remove unauthorized modifications and backdoors",
        "Patch vulnerability used for access",
        "Rebuild web server if compromise extent is unclear",
        "Update CMS and all plugins/themes",
        "Reset all administrative credentials"
      ],
      recoverySteps: [
        "Restore clean website content",
        "Implement file integrity monitoring",
        "Deploy WAF with virtual patching",
        "Implement content approval workflows",
        "Set up automated content monitoring"
      ],
      evidenceCollection: [
        "Screenshots of defaced content",
        "Modified files with timestamps",
        "Web server access and error logs",
        "FTP/SSH/CMS login logs",
        "File integrity monitoring reports"
      ],
      communicationPlan: "Notify web team and management. Issue public statement if site is customer-facing. Report to law enforcement if politically motivated. Request search engine removal of cached defaced pages.",
      lessonsLearned: [
        "What vulnerability was exploited?",
        "Was file integrity monitoring in place?",
        "Were CMS and plugins up to date?",
        "Were administrative credentials strong and unique?",
        "Was WAF effective?"
      ]
    },
    {
      name: "Credential Theft / Pass-the-Hash",
      severity: "High",
      description: "Attacker has obtained credential material (password hashes, Kerberos tickets, tokens) and is using them for lateral movement or privilege escalation.",
      indicators: [
        "NTLM authentication from unexpected sources",
        "Pass-the-hash or pass-the-ticket activity",
        "Mimikatz or similar tool execution detected",
        "LSASS process memory access by unusual processes",
        "Kerberoasting or AS-REP roasting activity",
        "Golden or silver ticket usage",
        "DCSync replication requests from non-DC systems",
        "Unusual service ticket requests"
      ],
      immediateActions: [
        "Identify all compromised credential material",
        "Reset passwords for affected accounts",
        "Revoke Kerberos tickets (reset KRBTGT if golden ticket suspected)",
        "Isolate systems where credential theft tools were detected",
        "Enable enhanced authentication logging"
      ],
      containmentSteps: [
        "Reset KRBTGT password twice if golden ticket suspected",
        "Reset all service account passwords",
        "Disable NTLM where possible, enforce Kerberos",
        "Enable Credential Guard on Windows 10+ endpoints",
        "Implement LSASS protection (RunAsPPL)",
        "Deploy PAM solution for privileged accounts"
      ],
      eradicationSteps: [
        "Remove credential theft tools from all systems",
        "Reset all potentially compromised credentials",
        "Review and remove unnecessary service accounts",
        "Implement managed service accounts (gMSA)",
        "Enable AES-only Kerberos (disable RC4)"
      ],
      recoverySteps: [
        "Implement privileged access workstations (PAWs)",
        "Deploy LAPS for local admin passwords",
        "Implement tiered administration model",
        "Enable Advanced Audit Policy for credential events",
        "Deploy deception tokens and honey accounts"
      ],
      evidenceCollection: [
        "Memory dumps showing credential material",
        "Event logs (4624, 4625, 4768, 4769, 4771, 4776)",
        "PowerShell script block logs",
        "Sysmon logs showing LSASS access",
        "Network traffic showing NTLM/Kerberos anomalies"
      ],
      communicationPlan: "Notify Active Directory administrators. Brief CISO on credential compromise scope. Coordinate KRBTGT reset during maintenance window if needed.",
      lessonsLearned: [
        "Were credential theft detection tools effective?",
        "Was Credential Guard deployed?",
        "Were service accounts using strong passwords?",
        "Was tiered administration in place?",
        "Was KRBTGT rotated regularly?"
      ]
    },
    {
      name: "Cloud Account Compromise",
      severity: "High",
      description: "Unauthorized access to cloud infrastructure (AWS, Azure, GCP) via stolen credentials, access keys, or exploited cloud services.",
      indicators: [
        "CloudTrail/Activity Log events from unusual locations",
        "New IAM users or roles created without authorization",
        "API calls from unexpected IP addresses or user agents",
        "Unauthorized EC2 instances or cloud resources launched",
        "S3 bucket policy modifications",
        "Security group or firewall rule changes",
        "Cloud billing alerts for unexpected usage",
        "Access key usage after employee departure"
      ],
      immediateActions: [
        "Disable compromised IAM users and access keys",
        "Revoke active sessions",
        "Enable CloudTrail/audit logging if not active",
        "Identify all API actions performed by compromised credentials",
        "Check for new resources (EC2, Lambda, IAM) created by attacker"
      ],
      containmentSteps: [
        "Apply restrictive IAM policies (deny all) to compromised accounts",
        "Remove unauthorized IAM users, roles, and access keys",
        "Revert security group and network ACL changes",
        "Delete unauthorized compute resources",
        "Review and revoke cross-account trust relationships",
        "Check for compromised Lambda functions or container images"
      ],
      eradicationSteps: [
        "Rotate all access keys and credentials",
        "Remove unauthorized resources and configurations",
        "Review and fix IAM policies (least privilege)",
        "Enable MFA on all IAM users",
        "Review service control policies (SCPs)"
      ],
      recoverySteps: [
        "Implement AWS Organizations SCPs or Azure Policy",
        "Enable GuardDuty/Security Center/SCC",
        "Implement cloud security posture management (CSPM)",
        "Deploy cloud workload protection (CWPP)",
        "Implement infrastructure as code for drift detection"
      ],
      evidenceCollection: [
        "CloudTrail/Activity Log/Audit Log entries",
        "IAM credential report",
        "Resource creation and modification timeline",
        "VPC flow logs",
        "Cloud billing records",
        "S3 access logs"
      ],
      communicationPlan: "Notify cloud security team and account owners. Brief CISO on blast radius. Engage cloud provider support if needed. Assess data exposure and regulatory requirements.",
      lessonsLearned: [
        "Were access keys rotated regularly?",
        "Was MFA enforced for all IAM users?",
        "Were cloud security monitoring tools effective?",
        "Were IAM policies following least privilege?",
        "Were SCPs/guardrails in place?"
      ]
    },
    {
      name: "DNS Hijacking",
      severity: "High",
      description: "Attacker has modified DNS records to redirect traffic from legitimate domains to attacker-controlled infrastructure. May be at registrar, DNS provider, or local DNS level.",
      indicators: [
        "DNS records changed without authorization",
        "Users redirected to unexpected IP addresses",
        "SSL certificate errors for legitimate domains",
        "New SSL certificates issued for company domains by unknown CAs",
        "DNS query responses pointing to unexpected IPs",
        "Certificate Transparency log alerts for unauthorized certificates"
      ],
      immediateActions: [
        "Verify current DNS records against expected values",
        "If registrar compromised: contact registrar emergency support immediately",
        "Lock domain at registrar level",
        "Change registrar account credentials and enable 2FA",
        "Notify DNS provider of unauthorized changes",
        "Monitor Certificate Transparency logs for unauthorized certs"
      ],
      containmentSteps: [
        "Restore correct DNS records",
        "Enable registry lock on domains",
        "Reduce DNS TTL for faster propagation of fixes",
        "Implement DNSSEC if not already enabled",
        "Review all DNS zones for additional unauthorized changes"
      ],
      eradicationSteps: [
        "Secure registrar account with strong credentials and hardware MFA",
        "Revoke unauthorized SSL certificates via CA",
        "Review and secure all DNS management accounts",
        "Implement domain monitoring for unauthorized changes"
      ],
      recoverySteps: [
        "Enable registry lock on all critical domains",
        "Implement DNSSEC",
        "Set up Certificate Transparency monitoring",
        "Configure DNS change alerting",
        "Review and reduce DNS management access"
      ],
      evidenceCollection: [
        "DNS record change history",
        "Registrar account activity logs",
        "Certificate Transparency logs",
        "DNS query logs showing redirected resolutions",
        "Network traffic captures during hijack period"
      ],
      communicationPlan: "Notify customers that traffic may have been intercepted. Advise password changes for users who accessed services during hijack period. Report to registrar and relevant CERT.",
      lessonsLearned: [
        "Was registrar account secured with MFA?",
        "Was registry lock enabled?",
        "Was DNSSEC implemented?",
        "Were DNS changes monitored?",
        "Was CT monitoring in place?"
      ]
    },
    {
      name: "Zero-Day Exploitation",
      severity: "Critical",
      description: "Exploitation of a previously unknown vulnerability with no available patch. Requires rapid response and creative mitigation until vendor provides a fix.",
      indicators: [
        "Vendor advisory for actively exploited vulnerability",
        "Threat intelligence reports of in-the-wild exploitation",
        "Unusual process behavior matching reported exploitation patterns",
        "Network traffic matching published IOCs",
        "Evidence of exploitation in system logs"
      ],
      immediateActions: [
        "Identify all systems running the vulnerable software/version",
        "Assess exposure — is the vulnerable service internet-facing?",
        "Apply vendor-provided mitigations or workarounds immediately",
        "Implement virtual patching via WAF/IPS rules",
        "Check for indicators that exploitation has already occurred"
      ],
      containmentSteps: [
        "If exploited: follow appropriate playbook for the result (ransomware, data breach, etc.)",
        "If not yet exploited: implement compensating controls",
        "Restrict network access to vulnerable services",
        "Implement additional monitoring for exploitation attempts",
        "Apply vendor workarounds (disable features, restrict access)"
      ],
      eradicationSteps: [
        "Apply vendor patch as soon as available",
        "Verify patch is effective",
        "Remove any exploitation artifacts",
        "Review systems for compromise during exposure window"
      ],
      recoverySteps: [
        "Validate patch deployment across all systems",
        "Remove temporary workarounds",
        "Conduct threat hunting for exploitation during exposure window",
        "Review vulnerability management program for improvement"
      ],
      evidenceCollection: [
        "Exploitation attempts in logs",
        "Malware or backdoors deployed via exploitation",
        "Network traffic matching exploitation patterns",
        "Vendor advisories and IOC lists"
      ],
      communicationPlan: "Brief security team and management on risk. Communicate patch timeline. Share IOCs with trusted peers. Coordinate with vendor on patch availability.",
      lessonsLearned: [
        "Was the response time adequate?",
        "Were compensating controls effective?",
        "Was the vulnerable surface minimized?",
        "Was patch deployment fast enough?",
        "Were threat hunting capabilities adequate?"
      ]
    },
    {
      name: "Lateral Movement Detected",
      severity: "High",
      description: "Attacker is moving through the network from the initially compromised system to reach high-value targets. Uses legitimate tools and credentials to blend in.",
      indicators: [
        "Remote execution via PsExec, WMI, WinRM, or SSH from unusual sources",
        "RDP connections between servers (unusual pattern)",
        "Administrative share access (C$, ADMIN$) from workstations",
        "PowerShell remoting from unexpected systems",
        "SMB connections to multiple hosts in succession",
        "Use of tools like CrackMapExec, Impacket, or Evil-WinRM",
        "Service installation on remote systems"
      ],
      immediateActions: [
        "Identify the source and destination of lateral movement",
        "Isolate both source (compromised) and destination systems",
        "Disable account credentials used for movement",
        "Deploy enhanced monitoring on adjacent systems",
        "Begin threat hunting across the network"
      ],
      containmentSteps: [
        "Block SMB, RDP, WinRM, and SSH between workstation tiers",
        "Implement network micro-segmentation",
        "Disable remote admin shares",
        "Force credential reset for all accounts accessed",
        "Deploy deception hosts to detect continued movement"
      ],
      eradicationSteps: [
        "Remove persistence and tools from all compromised systems",
        "Reset credentials used during lateral movement",
        "Rebuild compromised systems",
        "Patch vulnerabilities used for lateral movement",
        "Remove unauthorized access to remote management tools"
      ],
      recoverySteps: [
        "Implement tiered admin model (Tier 0/1/2)",
        "Deploy PAW for privileged access",
        "Implement LAPS for local admin passwords",
        "Enable Windows Firewall rules restricting lateral protocols",
        "Deploy EDR with lateral movement detection"
      ],
      evidenceCollection: [
        "Windows Event Logs (4624 type 3/10, 4648, 5140, 5145)",
        "Sysmon logs (Event ID 1, 3, 11, 17/18, 25)",
        "PowerShell script block logs",
        "Network traffic showing lateral protocols",
        "Firewall logs showing east-west traffic"
      ],
      communicationPlan: "Notify SOC and IR team. Brief CISO on scope of compromise. Coordinate containment timing to avoid alerting attacker.",
      lessonsLearned: [
        "Was network segmentation adequate?",
        "Were lateral movement detection rules effective?",
        "Was a tiered admin model in place?",
        "Were local admin passwords unique (LAPS)?",
        "Were deception technologies deployed?"
      ]
    }
  ],

  forensicCommands: {
    windows: {
      processes: [
        { command: "tasklist /v", description: "List all running processes with verbose details" },
        { command: "wmic process get Name,ProcessId,ParentProcessId,CommandLine", description: "Get process tree with command lines" },
        { command: "Get-Process | Select-Object Id,ProcessName,Path,StartTime | Format-Table", description: "PowerShell process listing with paths and start times" },
        { command: "wmic process where 'ParentProcessId=PID' get Name,ProcessId,CommandLine", description: "Find child processes of a specific PID" },
        { command: "tasklist /m", description: "List all processes with loaded DLLs" }
      ],
      network: [
        { command: "netstat -anob", description: "All connections with owning process and binary name" },
        { command: "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess", description: "PowerShell TCP connections with process IDs" },
        { command: "ipconfig /displaydns", description: "Display DNS resolver cache" },
        { command: "arp -a", description: "Display ARP cache" },
        { command: "route print", description: "Display routing table" },
        { command: "netsh interface portproxy show all", description: "Show port forwarding rules" }
      ],
      persistence: [
        { command: "schtasks /query /fo LIST /v", description: "List all scheduled tasks with details" },
        { command: "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", description: "Registry Run key (HKLM)" },
        { command: "reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", description: "Registry Run key (HKCU)" },
        { command: "wmic startup list full", description: "All startup items" },
        { command: "sc query type= service state= all", description: "List all services including stopped" },
        { command: "Get-WmiObject Win32_Service | Select-Object Name,PathName,StartMode,State", description: "Service paths and start modes" },
        { command: "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services", description: "All registered services in registry" }
      ],
      eventLogs: [
        { command: "wevtutil qe Security /c:50 /f:text /rd:true", description: "Last 50 Security events in text format" },
        { command: 'Get-WinEvent -FilterHashtable @{LogName="Security";ID=4624} -MaxEvents 50', description: "Last 50 successful logon events" },
        { command: 'Get-WinEvent -FilterHashtable @{LogName="Security";ID=4625} -MaxEvents 50', description: "Last 50 failed logon events" },
        { command: 'Get-WinEvent -FilterHashtable @{LogName="Security";ID=4688} -MaxEvents 50', description: "Last 50 process creation events" },
        { command: 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"} -MaxEvents 50', description: "Last 50 PowerShell operational events" },
        { command: 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"} -MaxEvents 50', description: "Last 50 Sysmon events" }
      ],
      memory: [
        { command: "procdump -ma lsass.exe lsass.dmp", description: "Dump LSASS process memory (for analysis, not credential theft)" },
        { command: "winpmem_mini_x64.exe memdump.raw", description: "Full physical memory dump with WinPmem" },
        { command: "volatility -f memdump.raw imageinfo", description: "Identify memory dump profile" },
        { command: "volatility -f memdump.raw --profile=Win10x64 pslist", description: "List processes from memory dump" },
        { command: "volatility -f memdump.raw --profile=Win10x64 netscan", description: "Network connections from memory dump" }
      ],
      fileSystem: [
        { command: "dir /a /s /od C:\\Users\\*\\AppData\\Roaming\\*.exe", description: "Find executables in user AppData, sorted by date" },
        { command: "forfiles /S /M *.exe /D +01/01/2024 /C \"cmd /c echo @path @fdate @ftime\"", description: "Find executables created after date" },
        { command: "Get-ChildItem -Path C:\\ -Recurse -Include *.exe -ErrorAction SilentlyContinue | Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-7)}", description: "Executables created in last 7 days" },
        { command: "certutil -hashfile file.exe SHA256", description: "Calculate SHA256 hash of file" },
        { command: "Get-FileHash -Algorithm SHA256 file.exe", description: "PowerShell hash calculation" }
      ]
    },
    linux: {
      processes: [
        { command: "ps auxf", description: "All processes with full details and tree view" },
        { command: "ls -la /proc/PID/exe", description: "Get actual binary path for a process" },
        { command: "cat /proc/PID/cmdline | tr '\\0' ' '", description: "Full command line of a process" },
        { command: "cat /proc/PID/environ | tr '\\0' '\\n'", description: "Environment variables of a process" },
        { command: "ls -la /proc/PID/fd/", description: "Open file descriptors for a process" },
        { command: "strace -p PID -f", description: "Trace system calls of running process" }
      ],
      network: [
        { command: "ss -tulnp", description: "All listening TCP/UDP sockets with process info" },
        { command: "ss -antp", description: "All TCP connections with process info" },
        { command: "lsof -i -n -P", description: "All network connections with process details" },
        { command: "iptables -L -n -v", description: "All firewall rules with counters" },
        { command: "cat /proc/net/tcp", description: "Raw TCP connection table from kernel" },
        { command: "ip neigh", description: "ARP table (neighbor cache)" },
        { command: "conntrack -L", description: "Connection tracking table" }
      ],
      persistence: [
        { command: "crontab -l -u root", description: "Root cron jobs" },
        { command: "for u in $(cut -f1 -d: /etc/passwd); do echo \"--- $u ---\"; crontab -l -u $u 2>/dev/null; done", description: "All users' cron jobs" },
        { command: "ls -la /etc/cron.*", description: "System cron directories" },
        { command: "systemctl list-unit-files --type=service --state=enabled", description: "All enabled systemd services" },
        { command: "cat /etc/rc.local", description: "rc.local startup script" },
        { command: "ls -la /etc/init.d/", description: "Init.d scripts" },
        { command: "cat /etc/ld.so.preload", description: "LD_PRELOAD entries (rootkit indicator)" },
        { command: "ls -la /root/.ssh/authorized_keys", description: "Root SSH authorized keys" }
      ],
      logs: [
        { command: "grep 'Failed password' /var/log/auth.log | tail -50", description: "Recent failed login attempts" },
        { command: "grep 'Accepted' /var/log/auth.log | tail -50", description: "Recent successful logins" },
        { command: "last -50", description: "Last 50 logins from wtmp" },
        { command: "lastb -50", description: "Last 50 failed logins from btmp" },
        { command: "journalctl --since '1 hour ago' --no-pager", description: "Last hour of systemd journal" },
        { command: "ausearch -m USER_LOGIN -ts today", description: "Today's login events from auditd" },
        { command: "grep -r 'sudo' /var/log/auth.log | tail -20", description: "Recent sudo usage" }
      ],
      fileSystem: [
        { command: "find / -mtime -1 -type f -executable 2>/dev/null", description: "Executables modified in last 24 hours" },
        { command: "find / -perm -4000 -type f 2>/dev/null", description: "All SUID binaries" },
        { command: "find / -perm -2000 -type f 2>/dev/null", description: "All SGID binaries" },
        { command: "find /tmp /var/tmp /dev/shm -type f 2>/dev/null", description: "Files in temp directories" },
        { command: "find / -name '.*' -type f 2>/dev/null | head -50", description: "Hidden files" },
        { command: "rpm -Va 2>/dev/null || debsums -c 2>/dev/null", description: "Verify package integrity (modified files)" },
        { command: "sha256sum /usr/bin/sudo", description: "Hash a binary to verify integrity" }
      ],
      memory: [
        { command: "dd if=/dev/mem of=memdump.raw bs=1M", description: "Raw memory dump (may require LiME)" },
        { command: "insmod lime.ko 'path=/tmp/memdump.lime format=lime'", description: "LiME kernel module memory dump" },
        { command: "volatility -f memdump.lime --profile=LinuxUbuntu2204x64 linux_pslist", description: "List processes from Linux memory dump" },
        { command: "strings memdump.raw | grep -i password", description: "Search memory dump for passwords" }
      ]
    }
  },

  evidenceHandling: {
    chainOfCustody: {
      description: "Maintain an unbroken chain of custody for all evidence to ensure admissibility in legal proceedings.",
      requirements: [
        "Document who collected the evidence, when, where, and how",
        "Record every person who handles the evidence",
        "Store evidence in a secure, access-controlled location",
        "Use tamper-evident bags for physical media",
        "Calculate and record cryptographic hashes (SHA256) at collection time",
        "Verify hashes before and after any analysis",
        "Document all analysis performed on evidence",
        "Maintain a chain of custody log for each evidence item",
        "Use write-blockers when imaging drives",
        "Create forensic copies — never analyze the original"
      ],
      logFields: [
        "Evidence ID (unique identifier)",
        "Description of evidence",
        "Date and time of collection",
        "Collected by (name and role)",
        "Collection method and tools used",
        "Hash values (SHA256 at minimum)",
        "Storage location",
        "Access log (who, when, why)",
        "Transfer log (from whom, to whom, when)"
      ]
    },
    acquisitionOrder: {
      description: "Collect evidence in order of volatility — most volatile first, as it will be lost soonest.",
      order: [
        "CPU registers and cache (lost immediately)",
        "RAM / running processes / network connections (lost on reboot)",
        "Network routing tables, ARP cache, DNS cache",
        "Temporary file systems (/tmp, swap)",
        "Hard drive / SSD data",
        "Remote logging and monitoring data",
        "Physical configuration, network topology",
        "Backup media and archives"
      ]
    }
  },

  regulatoryNotification: [
    {
      regulation: "GDPR (EU General Data Protection Regulation)",
      timeframe: "72 hours from discovery",
      authority: "Relevant supervisory authority (data protection authority of lead establishment)",
      details: "Must notify supervisory authority within 72 hours. Must notify affected individuals without undue delay if high risk to rights and freedoms. Must document the breach including facts, effects, and remedial action. Fines up to 4% of global annual revenue.",
      dataTypes: ["Personal data of EU residents"]
    },
    {
      regulation: "HIPAA (Health Insurance Portability and Accountability Act)",
      timeframe: "60 days from discovery",
      authority: "HHS Office for Civil Rights (OCR)",
      details: "Must notify affected individuals within 60 days. Must notify HHS OCR. If breach affects 500+ individuals, must notify prominent media outlets. Must post on HHS breach portal. Individuals must be notified by first-class mail or email (with consent).",
      dataTypes: ["Protected Health Information (PHI)"]
    },
    {
      regulation: "PCI DSS (Payment Card Industry Data Security Standard)",
      timeframe: "Immediately upon discovery",
      authority: "Card brands (Visa, Mastercard, etc.) and acquiring bank",
      details: "Must notify acquiring bank and card brands immediately. PCI Forensic Investigator (PFI) engagement may be required. Must contain and remediate. May face fines, increased transaction fees, or loss of card processing ability.",
      dataTypes: ["Cardholder data, payment card information"]
    },
    {
      regulation: "SEC Cybersecurity Disclosure Rules",
      timeframe: "4 business days from materiality determination",
      authority: "Securities and Exchange Commission",
      details: "Public companies must disclose material cybersecurity incidents on Form 8-K within 4 business days of determining materiality. Annual report (10-K) must describe cybersecurity risk management, strategy, and governance.",
      dataTypes: ["Any data where breach is material to investors"]
    },
    {
      regulation: "US State Breach Notification Laws",
      timeframe: "Varies by state (30-90 days typically)",
      authority: "State Attorney General and/or consumer protection agency",
      details: "All 50 states have breach notification laws. Requirements vary: some require notification within 30 days (Florida), others 60 days (many states), some have no specific timeframe (most expedient possible). Many require AG notification above certain thresholds.",
      dataTypes: ["PII as defined by each state (typically SSN, financial account, driver's license)"]
    },
    {
      regulation: "CCPA/CPRA (California Consumer Privacy Act)",
      timeframe: "Most expedient time possible, without unreasonable delay",
      authority: "California Attorney General / California Privacy Protection Agency",
      details: "Must notify affected California residents. Private right of action for data breaches due to failure to maintain reasonable security. Statutory damages of $100-$750 per consumer per incident.",
      dataTypes: ["Personal information of California residents"]
    },
    {
      regulation: "NIS2 Directive (EU Network and Information Security)",
      timeframe: "24 hours (early warning), 72 hours (full notification)",
      authority: "National CSIRT or competent authority",
      details: "Essential and important entities must report significant incidents. 24-hour early warning, 72-hour incident notification, 1-month final report. Penalties up to 10M EUR or 2% of global turnover.",
      dataTypes: ["Network and information systems of essential services"]
    },
    {
      regulation: "Australia Notifiable Data Breaches (NDB) Scheme",
      timeframe: "30 days from awareness",
      authority: "Office of the Australian Information Commissioner (OAIC)",
      details: "Must notify OAIC and affected individuals of eligible data breaches likely to result in serious harm. Assessment must be completed within 30 days.",
      dataTypes: ["Personal information under the Privacy Act 1988"]
    }
  ],

  communicationTemplates: {
    executiveBrief: {
      subject: "Security Incident Brief — [SEVERITY] — [DATE]",
      sections: [
        "Incident Summary: What happened in 2-3 sentences",
        "Current Status: Active/Contained/Eradicated/Resolved",
        "Business Impact: Systems affected, data at risk, operational disruption",
        "Actions Taken: Key containment and response steps completed",
        "Recommendations: Immediate decisions needed from leadership",
        "Next Steps: Planned actions and timeline",
        "Resource Requirements: Additional budget, personnel, or vendor engagement needed"
      ]
    },
    customerNotification: {
      subject: "Important Security Notice from [Company]",
      sections: [
        "What Happened: Brief, factual description of the incident",
        "What Information Was Involved: Specific data types affected",
        "What We Are Doing: Steps taken to address the incident",
        "What You Can Do: Recommended protective actions for the customer",
        "Contact Information: Dedicated phone line and email for questions",
        "Additional Resources: Identity protection services offered"
      ]
    },
    regulatoryReport: {
      subject: "Data Breach Notification — [Regulation] — [Company]",
      sections: [
        "Organization Details: Legal name, contact information, DPO details",
        "Nature of Breach: Category (confidentiality, integrity, availability)",
        "Data Subjects Affected: Number and categories of individuals",
        "Data Categories: Types of personal data involved",
        "Likely Consequences: Assessment of potential impact on individuals",
        "Measures Taken: Steps to address and mitigate the breach",
        "Cross-Border Impact: Whether data subjects in other jurisdictions affected"
      ]
    }
  }
};
