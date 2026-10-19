// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Phased incident-response playbooks (detection, containment, eradication, recovery,
// lessons learned) with per-phase roles, tools, evidence and checklists, plus the
// severity SLA table, communication templates and the stakeholder notification matrix.
// Pure data; incident-tracker.js runs these against a persisted incident record.

// Incident Tracker type -> phased playbook key (types with no close match have none).
export const TYPE_PLAYBOOK = {
  "Ransomware": "ransomware", "Data Breach": "databreach", "Phishing": "phishing", "DDoS": "ddos",
  "Insider Threat": "insider", "Supply Chain": "supplychain", "Malware": "malware", "Cryptomining": "malware",
  "Credential Theft": "accountcompromise", "Unauthorized Access": "accountcompromise", "BEC": "accountcompromise",
};

export const IR_PLAYBOOKS = {
  ransomware: {
    name: 'Ransomware Attack', severity: 'P1',
    phases: {
      detection: {
        title: 'Detection & Analysis', time: '0-2 hours',
        roles: ['SOC Analyst', 'IR Lead', 'Threat Intel'],
        tools: ['SIEM', 'EDR', 'Network Monitor', 'Sandbox'],
        evidence: ['Ransom note screenshot', 'Encrypted file samples', 'Process memory dump', 'Network logs', 'Email headers (if phishing vector)'],
        checks: ['Identify ransomware variant/family', 'Determine encryption scope (files, drives, network shares)', 'Identify patient zero and initial access vector', 'Check for data exfiltration indicators', 'Assess lateral movement extent', 'Verify backup integrity before connecting']
      },
      containment: {
        title: 'Containment', time: '2-6 hours',
        roles: ['IR Lead', 'Network Admin', 'Sys Admin'],
        tools: ['Firewall', 'EDR', 'AD Console', 'Network Segmentation'],
        evidence: ['Firewall rule changes log', 'Isolated system inventory', 'AD audit logs'],
        checks: ['Isolate affected systems from network', 'Block C2 IP addresses and domains at firewall', 'Disable compromised accounts', 'Segment network to prevent spread', 'Preserve forensic images of key systems', 'Disable SMB/RDP on unaffected systems']
      },
      eradication: {
        title: 'Eradication', time: '6-48 hours',
        roles: ['Malware Analyst', 'Sys Admin', 'IR Lead'],
        tools: ['AV/EDR', 'Forensic Suite', 'Reimaging Tools'],
        evidence: ['Malware samples', 'IOCs extracted', 'Persistence mechanisms found'],
        checks: ['Remove ransomware binaries and persistence', 'Patch exploited vulnerability', 'Reset all potentially compromised credentials', 'Scan all systems with updated signatures', 'Verify no backdoors remain', 'Update detection rules for variant']
      },
      recovery: {
        title: 'Recovery', time: '2-7 days',
        roles: ['Sys Admin', 'Business Ops', 'IR Lead'],
        tools: ['Backup Systems', 'Monitoring', 'Deployment Tools'],
        evidence: ['Restoration logs', 'Integrity verification results', 'System baseline comparisons'],
        checks: ['Restore systems from clean backups', 'Rebuild systems that cannot be cleaned', 'Verify data integrity post-restoration', 'Monitor restored systems for re-infection', 'Gradually reconnect to network', 'Validate business operations restored']
      },
      lessons: {
        title: 'Lessons Learned', time: '1-2 weeks post',
        roles: ['IR Lead', 'CISO', 'All Stakeholders'],
        tools: ['Documentation', 'Meeting Platform'],
        evidence: ['Timeline document', 'Cost assessment', 'Improvement recommendations'],
        checks: ['Conduct post-incident review meeting', 'Document complete incident timeline', 'Identify detection gaps', 'Update IR playbook based on findings', 'Implement recommended security improvements', 'Brief executive leadership']
      }
    }
  },
  databreach: {
    name: 'Data Breach / Exfiltration', severity: 'P1',
    phases: {
      detection: {
        title: 'Detection & Analysis', time: '0-4 hours',
        roles: ['SOC Analyst', 'IR Lead', 'DLP Admin'],
        tools: ['DLP', 'SIEM', 'UEBA', 'Network Monitor'],
        evidence: ['DLP alerts', 'Network flow data', 'Access logs', 'Database query logs'],
        checks: ['Identify what data was accessed/exfiltrated', 'Determine data classification level', 'Identify affected data subjects', 'Trace access path and actor', 'Assess volume of data exposed', 'Check for ongoing exfiltration']
      },
      containment: {
        title: 'Containment', time: '2-8 hours',
        roles: ['IR Lead', 'Network Admin', 'Legal'],
        tools: ['Firewall', 'DLP', 'IAM', 'Proxy'],
        evidence: ['Blocked connection logs', 'Account lockout records', 'Data flow diagrams'],
        checks: ['Block exfiltration channels', 'Revoke compromised access tokens', 'Enable enhanced DLP monitoring', 'Preserve evidence with forensic copies', 'Notify legal counsel', 'Assess regulatory notification requirements']
      },
      eradication: {
        title: 'Eradication', time: '1-3 days',
        roles: ['Sys Admin', 'DB Admin', 'Security Engineer'],
        tools: ['Vulnerability Scanner', 'Code Review', 'IAM'],
        evidence: ['Vulnerability assessment', 'Access control audit', 'Configuration changes'],
        checks: ['Patch exploited vulnerabilities', 'Remediate access control gaps', 'Rotate affected encryption keys', 'Review and harden database security', 'Audit all privileged access', 'Remove unauthorized access paths']
      },
      recovery: {
        title: 'Recovery', time: '1-4 weeks',
        roles: ['Legal', 'PR', 'CISO', 'Compliance'],
        tools: ['Notification Platform', 'Credit Monitoring', 'PR Tools'],
        evidence: ['Notification records', 'Regulatory filings', 'Credit monitoring enrollment'],
        checks: ['Notify affected individuals per regulations', 'File regulatory notifications (GDPR 72hr, etc.)', 'Offer credit monitoring if PII exposed', 'Issue public statement if required', 'Implement enhanced monitoring', 'Verify no further data access']
      },
      lessons: {
        title: 'Lessons Learned', time: '2-4 weeks post',
        roles: ['CISO', 'Legal', 'IR Lead', 'Compliance'],
        tools: ['Documentation', 'GRC Platform'],
        evidence: ['Root cause analysis', 'Regulatory correspondence', 'Cost report'],
        checks: ['Complete root cause analysis', 'Update data classification policies', 'Enhance DLP rules', 'Review access control model', 'Update vendor risk assessments', 'Report to board/executives']
      }
    }
  },
  phishing: {
    name: 'Phishing Campaign', severity: 'P2',
    phases: {
      detection: {
        title: 'Detection & Analysis', time: '0-1 hour',
        roles: ['SOC Analyst', 'Email Admin'],
        tools: ['Email Gateway', 'Sandbox', 'URL Scanner'],
        evidence: ['Phishing email samples (.eml)', 'Email headers', 'Malicious URLs/attachments', 'Recipient list'],
        checks: ['Collect phishing email sample', 'Analyze headers for origin', 'Detonate attachments in sandbox', 'Check URLs against threat intel', 'Determine campaign scope (recipients)', 'Identify if credentials were harvested']
      },
      containment: {
        title: 'Containment', time: '1-4 hours',
        roles: ['Email Admin', 'SOC Analyst', 'Help Desk'],
        tools: ['Email Gateway', 'IAM', 'EDR'],
        evidence: ['Purge confirmation', 'Blocked sender/domain list', 'Compromised account list'],
        checks: ['Purge phishing emails from all mailboxes', 'Block sender domain/IP at email gateway', 'Block malicious URLs at proxy/firewall', 'Reset credentials for users who clicked', 'Revoke active sessions for compromised accounts', 'Send user awareness notification']
      },
      eradication: {
        title: 'Eradication', time: '4-24 hours',
        roles: ['SOC Analyst', 'Sys Admin'],
        tools: ['EDR', 'AV', 'Email Gateway'],
        evidence: ['Scan results', 'Payload analysis', 'IOC list'],
        checks: ['Scan systems of users who clicked', 'Remove any downloaded payloads', 'Check for persistence mechanisms', 'Update email filtering rules', 'Add IOCs to blocklists', 'Verify no lateral movement occurred']
      },
      recovery: {
        title: 'Recovery', time: '1-3 days',
        roles: ['Help Desk', 'Security Awareness', 'IR Lead'],
        tools: ['Training Platform', 'Email Gateway', 'IAM'],
        evidence: ['Training completion records', 'New filter rules', 'MFA enrollment records'],
        checks: ['Re-enable accounts after credential reset', 'Enroll affected users in security training', 'Implement/verify MFA on affected accounts', 'Monitor for follow-up phishing waves', 'Update email authentication (SPF/DKIM/DMARC)', 'Verify no unauthorized email forwarding rules']
      },
      lessons: {
        title: 'Lessons Learned', time: '1 week post',
        roles: ['IR Lead', 'Security Awareness'],
        tools: ['Documentation', 'Training Platform'],
        evidence: ['Click rate metrics', 'Training gaps identified', 'Filter improvements'],
        checks: ['Calculate user click/report rates', 'Identify training gaps', 'Update phishing simulation program', 'Improve email filtering rules', 'Review user reporting procedures', 'Brief management on campaign details']
      }
    }
  },
  ddos: {
    name: 'DDoS Attack', severity: 'P1',
    phases: {
      detection: {
        title: 'Detection & Analysis', time: '0-30 min',
        roles: ['NOC', 'SOC Analyst', 'Network Engineer'],
        tools: ['Network Monitor', 'Flow Analyzer', 'WAF', 'CDN Dashboard'],
        evidence: ['Traffic graphs', 'Flow data', 'Attack vector details', 'Source IP analysis'],
        checks: ['Confirm DDoS vs legitimate traffic spike', 'Identify attack type (volumetric/protocol/application)', 'Determine attack vector and source distribution', 'Assess service impact and affected systems', 'Check if part of multi-vector attack', 'Activate DDoS response team']
      },
      containment: {
        title: 'Containment', time: '30 min - 2 hours',
        roles: ['Network Engineer', 'CDN/ISP Contact', 'NOC'],
        tools: ['WAF', 'CDN', 'BGP Blackhole', 'Rate Limiter'],
        evidence: ['Mitigation rules applied', 'Traffic filtering logs', 'ISP communication records'],
        checks: ['Activate DDoS mitigation service', 'Implement rate limiting rules', 'Apply geographic or ASN-based filtering', 'Enable CDN caching for static content', 'Contact upstream ISP for scrubbing', 'Consider BGP blackhole for targeted IPs']
      },
      eradication: {
        title: 'Eradication', time: '2-24 hours',
        roles: ['Network Engineer', 'Security Engineer'],
        tools: ['Firewall', 'IPS', 'WAF', 'Load Balancer'],
        evidence: ['Attack pattern signatures', 'Botnet C2 indicators', 'Infrastructure changes'],
        checks: ['Fine-tune filtering to minimize false positives', 'Block identified botnet C2 infrastructure', 'Verify no secondary attack in progress', 'Check for application-layer exploits during DDoS', 'Update WAF rules for attack patterns', 'Validate service integrity']
      },
      recovery: {
        title: 'Recovery', time: '1-3 days',
        roles: ['NOC', 'Sys Admin', 'Business Ops'],
        tools: ['Monitoring', 'Load Balancer', 'CDN'],
        evidence: ['Service restoration timeline', 'Performance baselines', 'Customer impact metrics'],
        checks: ['Gradually restore normal traffic flow', 'Verify all services operational', 'Re-baseline performance metrics', 'Remove temporary mitigation rules', 'Monitor for attack resurgence', 'Communicate restoration to stakeholders']
      },
      lessons: {
        title: 'Lessons Learned', time: '1-2 weeks post',
        roles: ['Network Engineer', 'IR Lead', 'CISO'],
        tools: ['Documentation', 'Capacity Planning'],
        evidence: ['Attack analysis report', 'Capacity assessment', 'Mitigation effectiveness data'],
        checks: ['Document attack characteristics and timeline', 'Evaluate mitigation effectiveness', 'Review capacity and scaling plans', 'Assess DDoS protection service adequacy', 'Update runbooks with lessons learned', 'Consider additional redundancy measures']
      }
    }
  },
  insider: {
    name: 'Insider Threat', severity: 'P2',
    phases: {
      detection: {
        title: 'Detection & Analysis', time: '0-24 hours',
        roles: ['SOC Analyst', 'HR', 'Legal', 'IR Lead'],
        tools: ['UEBA', 'DLP', 'SIEM', 'IAM Logs'],
        evidence: ['Access logs', 'UEBA alerts', 'DLP events', 'HR records'],
        checks: ['Identify anomalous user behavior patterns', 'Review data access and download history', 'Check for policy violations', 'Coordinate with HR and Legal before action', 'Determine if malicious or negligent', 'Preserve evidence chain of custody']
      },
      containment: {
        title: 'Containment', time: '1-8 hours',
        roles: ['IR Lead', 'HR', 'Legal', 'IAM Admin'],
        tools: ['IAM', 'DLP', 'Endpoint Monitor'],
        evidence: ['Access revocation records', 'Enhanced monitoring logs', 'Legal hold notices'],
        checks: ['Restrict account access (do not alert subject)', 'Enable enhanced monitoring on subject', 'Implement legal hold on relevant data', 'Secure physical access if applicable', 'Document all actions with timestamps', 'Brief need-to-know personnel only']
      },
      eradication: {
        title: 'Eradication', time: '1-7 days',
        roles: ['IR Lead', 'Forensics', 'Legal', 'HR'],
        tools: ['Forensic Suite', 'eDiscovery', 'IAM'],
        evidence: ['Forensic images', 'Activity timeline', 'Data impact assessment'],
        checks: ['Complete forensic analysis of subject systems', 'Identify all data accessed/exfiltrated', 'Review shared access and collaborators', 'Assess damage and data exposure', 'Prepare evidence for potential legal action', 'Review and update access control policies']
      },
      recovery: {
        title: 'Recovery', time: '1-4 weeks',
        roles: ['HR', 'Legal', 'CISO', 'Management'],
        tools: ['IAM', 'DLP', 'Training Platform'],
        evidence: ['HR action records', 'Policy updates', 'Training records'],
        checks: ['Take appropriate HR/legal action', 'Rotate credentials for shared resources', 'Review access for similar-role employees', 'Implement enhanced monitoring controls', 'Update insider threat program', 'Brief leadership on findings']
      },
      lessons: {
        title: 'Lessons Learned', time: '2-4 weeks post',
        roles: ['CISO', 'HR', 'Legal', 'IR Lead'],
        tools: ['Documentation', 'UEBA', 'Policy Management'],
        evidence: ['Case summary', 'Policy recommendations', 'Control improvements'],
        checks: ['Review insider threat detection capabilities', 'Update behavioral baselines in UEBA', 'Enhance least-privilege access model', 'Improve separation of duties', 'Update employee off-boarding procedures', 'Conduct awareness training for managers']
      }
    }
  },
  supplychain: {
    name: 'Supply Chain Compromise', severity: 'P1',
    phases: {
      detection: {
        title: 'Detection & Analysis', time: '0-24 hours',
        roles: ['SOC Analyst', 'IR Lead', 'Vendor Management'],
        tools: ['SIEM', 'EDR', 'Software Composition Analysis', 'Threat Intel'],
        evidence: ['Compromised package/update details', 'Affected version info', 'Vendor advisory', 'IOCs from threat intel'],
        checks: ['Identify compromised vendor/package/update', 'Determine affected versions and deployment scope', 'Assess what access the compromise grants', 'Check threat intel for known exploitation', 'Inventory all instances of affected software', 'Contact vendor for confirmation and guidance']
      },
      containment: {
        title: 'Containment', time: '2-12 hours',
        roles: ['Sys Admin', 'Network Admin', 'DevOps'],
        tools: ['Package Manager', 'Firewall', 'EDR', 'CI/CD Pipeline'],
        evidence: ['Rollback records', 'Network blocks applied', 'Affected system inventory'],
        checks: ['Roll back to last known-good version', 'Block vendor update channels temporarily', 'Isolate systems running compromised version', 'Disable auto-update for affected software', 'Block IOCs at network perimeter', 'Halt CI/CD pipelines using affected components']
      },
      eradication: {
        title: 'Eradication', time: '1-7 days',
        roles: ['Security Engineer', 'DevOps', 'IR Lead'],
        tools: ['SCA', 'Code Review', 'EDR', 'Forensics'],
        evidence: ['Clean version verification', 'Backdoor analysis', 'Affected code audit'],
        checks: ['Remove compromised software completely', 'Install verified clean version or alternative', 'Audit for backdoors or persistence from compromise', 'Review build pipeline integrity', 'Verify code signing and checksums', 'Scan all dependencies for related compromises']
      },
      recovery: {
        title: 'Recovery', time: '1-4 weeks',
        roles: ['DevOps', 'Vendor Management', 'CISO'],
        tools: ['SCA', 'Monitoring', 'Vendor Portal'],
        evidence: ['Updated vendor assessments', 'SCA scan results', 'New policy documents'],
        checks: ['Re-enable updates from verified vendor', 'Implement software supply chain controls', 'Add vendor to enhanced monitoring', 'Verify all systems running clean versions', 'Update software bill of materials (SBOM)', 'Review and update vendor security requirements']
      },
      lessons: {
        title: 'Lessons Learned', time: '2-4 weeks post',
        roles: ['CISO', 'Procurement', 'IR Lead'],
        tools: ['Documentation', 'GRC Platform', 'SCA'],
        evidence: ['Vendor risk reassessment', 'Supply chain security review', 'Process improvements'],
        checks: ['Document supply chain attack vector', 'Review third-party risk management program', 'Implement or enhance SBOM practices', 'Evaluate alternative vendors/packages', 'Update procurement security requirements', 'Brief board on supply chain risk posture']
      }
    }
  },
  malware: {
    name: 'Malware Outbreak', severity: 'P2',
    phases: {
      detection: {
        title: 'Detection & Analysis', time: '0-2 hours',
        roles: ['SOC Analyst', 'Malware Analyst'],
        tools: ['EDR', 'AV', 'Sandbox', 'SIEM'],
        evidence: ['Malware samples', 'AV alerts', 'Behavioral indicators', 'Network C2 traffic'],
        checks: ['Identify malware type and family', 'Determine infection vector', 'Assess spread and scope', 'Analyze C2 communication', 'Check for data exfiltration capability', 'Identify affected systems and users']
      },
      containment: {
        title: 'Containment', time: '2-8 hours',
        roles: ['SOC Analyst', 'Network Admin', 'Sys Admin'],
        tools: ['EDR', 'Firewall', 'Network Segmentation'],
        evidence: ['Quarantine records', 'Network blocks', 'Isolated system list'],
        checks: ['Quarantine infected systems', 'Block C2 domains and IPs', 'Disable network shares if worm-like', 'Push emergency AV signature update', 'Segment network to limit spread', 'Preserve samples for analysis']
      },
      eradication: {
        title: 'Eradication', time: '1-3 days',
        roles: ['Malware Analyst', 'Sys Admin'],
        tools: ['AV/EDR', 'Forensics', 'Reimaging'],
        evidence: ['Removal confirmation', 'Persistence audit', 'IOC list'],
        checks: ['Remove malware from all systems', 'Eliminate persistence mechanisms', 'Patch exploited vulnerabilities', 'Update AV/EDR signatures', 'Verify removal with full scans', 'Check for rootkit components']
      },
      recovery: {
        title: 'Recovery', time: '1-5 days',
        roles: ['Sys Admin', 'Help Desk', 'Business Ops'],
        tools: ['Imaging', 'Monitoring', 'Backup'],
        evidence: ['Restoration logs', 'Clean scan results', 'User notifications'],
        checks: ['Rebuild/reimage severely infected systems', 'Restore data from clean backups', 'Reconnect systems to network gradually', 'Monitor for reinfection indicators', 'Verify business operations restored', 'Notify affected users']
      },
      lessons: {
        title: 'Lessons Learned', time: '1-2 weeks post',
        roles: ['IR Lead', 'CISO', 'Security Awareness'],
        tools: ['Documentation', 'Training Platform'],
        evidence: ['Infection timeline', 'Gap analysis', 'Training plan'],
        checks: ['Document infection chain and timeline', 'Identify detection and prevention gaps', 'Update endpoint protection policies', 'Enhance user security awareness training', 'Review patch management process', 'Update IR playbook for malware type']
      }
    }
  },
  accountcompromise: {
    name: 'Account Compromise', severity: 'P2',
    phases: {
      detection: {
        title: 'Detection & Analysis', time: '0-2 hours',
        roles: ['SOC Analyst', 'IAM Admin'],
        tools: ['SIEM', 'IAM', 'UEBA', 'MFA Logs'],
        evidence: ['Login anomalies', 'MFA bypass attempts', 'Session tokens', 'Access logs'],
        checks: ['Identify compromised account(s)', 'Determine compromise method (phishing, brute force, credential stuffing)', 'Assess scope of unauthorized access', 'Check for privilege escalation', 'Review accessed resources and data', 'Identify if part of larger campaign']
      },
      containment: {
        title: 'Containment', time: '30 min - 2 hours',
        roles: ['IAM Admin', 'SOC Analyst'],
        tools: ['IAM', 'SSO', 'MFA Platform'],
        evidence: ['Session termination logs', 'Password reset records', 'Account lockout logs'],
        checks: ['Force password reset on compromised account', 'Terminate all active sessions', 'Revoke OAuth tokens and API keys', 'Enable or reset MFA', 'Review and remove unauthorized access grants', 'Check for persistence (mail rules, app passwords)']
      },
      eradication: {
        title: 'Eradication', time: '2-24 hours',
        roles: ['IAM Admin', 'Security Engineer', 'IR Lead'],
        tools: ['IAM', 'Email Gateway', 'Cloud Console'],
        evidence: ['Config change audit', 'Delegated access review', 'API key inventory'],
        checks: ['Remove unauthorized email forwarding rules', 'Revoke delegated access and app consents', 'Rotate shared secrets the account accessed', 'Check for created backdoor accounts', 'Audit cloud resource changes', 'Review code repository access and commits']
      },
      recovery: {
        title: 'Recovery', time: '1-3 days',
        roles: ['Help Desk', 'IAM Admin', 'User'],
        tools: ['IAM', 'MFA', 'Training Platform'],
        evidence: ['Account restoration records', 'MFA enrollment', 'User notification'],
        checks: ['Restore account with new credentials', 'Verify MFA is properly configured', 'Brief user on what happened', 'Monitor account for suspicious activity', 'Review and restore any altered data', 'Verify no unauthorized purchases/transactions']
      },
      lessons: {
        title: 'Lessons Learned', time: '1 week post',
        roles: ['IR Lead', 'IAM Admin', 'Security Awareness'],
        tools: ['Documentation', 'IAM', 'Training'],
        evidence: ['Compromise root cause', 'Control improvements', 'Policy updates'],
        checks: ['Determine how credentials were compromised', 'Evaluate MFA coverage and strength', 'Review password policy effectiveness', 'Assess credential monitoring capabilities', 'Update account compromise playbook', 'Enhance detection rules for similar attacks']
      }
    }
  }
};

export const IR_SEVERITY = {
  P1: { label: 'P1 — Critical', color: '#ff1744', sla: '15 min response, 1 hr update cycle' },
  P2: { label: 'P2 — High', color: '#ff9100', sla: '30 min response, 2 hr update cycle' },
  P3: { label: 'P3 — Medium', color: '#ffd600', sla: '2 hr response, 4 hr update cycle' },
  P4: { label: 'P4 — Low', color: '#00e676', sla: '4 hr response, daily updates' },
  P5: { label: 'P5 — Info', color: '#00b0ff', sla: 'Next business day, weekly updates' }
};

export const IR_COMM_TEMPLATES = {
  initial: {
    name: 'Initial Notification',
    template: `INCIDENT NOTIFICATION — [SEVERITY]
Incident ID: [ID]
Date/Time Detected: [DATETIME]
Type: [TYPE]
Severity: [SEVERITY]

Summary:
A [TYPE] incident has been detected affecting [SCOPE]. The incident response team has been activated and is currently in the [PHASE] phase.

Current Status:
- Impact: [IMPACT]
- Systems Affected: [SYSTEMS]
- Data at Risk: [DATA]

Immediate Actions Taken:
- [ACTION1]
- [ACTION2]
- [ACTION3]

Next Update: [NEXT_UPDATE]
IR Lead: [IR_LEAD]
Bridge Line: [BRIDGE]`
  },
  status: {
    name: 'Status Update',
    template: `INCIDENT STATUS UPDATE — [SEVERITY]
Incident ID: [ID]
Update #: [UPDATE_NUM]
Date/Time: [DATETIME]

Current Phase: [PHASE]
Status: [STATUS]

Progress Since Last Update:
- [PROGRESS1]
- [PROGRESS2]

Outstanding Actions:
- [ACTION1]
- [ACTION2]

Risks/Blockers:
- [RISK1]

Next Steps:
- [NEXT1]
- [NEXT2]

Next Update: [NEXT_UPDATE]`
  },
  final: {
    name: 'Final Report',
    template: `INCIDENT CLOSURE REPORT
Incident ID: [ID]
Type: [TYPE]
Severity: [SEVERITY]
Duration: [DURATION]

Executive Summary:
[EXEC_SUMMARY]

Timeline:
- [TIME1]: [EVENT1]
- [TIME2]: [EVENT2]
- [TIME3]: [EVENT3]

Root Cause:
[ROOT_CAUSE]

Impact Assessment:
- Systems Affected: [SYSTEMS]
- Data Impacted: [DATA]
- Business Impact: [BIZ_IMPACT]
- Estimated Cost: [COST]

Remediation Actions:
- [REMEDIATION1]
- [REMEDIATION2]

Recommendations:
1. [REC1]
2. [REC2]
3. [REC3]

Lessons Learned:
- [LESSON1]
- [LESSON2]`
  }
};

export const IR_STAKEHOLDERS = [
  { role: 'CISO', notify: 'P1,P2', method: 'Phone + Email', timing: 'Immediate' },
  { role: 'CTO', notify: 'P1', method: 'Phone', timing: 'Within 15 min' },
  { role: 'CEO', notify: 'P1', method: 'Phone', timing: 'Within 30 min' },
  { role: 'Legal Counsel', notify: 'P1,P2', method: 'Email + Phone', timing: 'Within 1 hr' },
  { role: 'PR/Communications', notify: 'P1', method: 'Email', timing: 'Within 2 hr' },
  { role: 'HR Director', notify: 'P1,P2 (if insider)', method: 'Phone', timing: 'Immediate' },
  { role: 'IT Director', notify: 'P1,P2,P3', method: 'Email', timing: 'Within 1 hr' },
  { role: 'Business Unit Leads', notify: 'P1,P2', method: 'Email', timing: 'Within 2 hr' },
  { role: 'External Counsel', notify: 'P1 (breach)', method: 'Phone', timing: 'Within 4 hr' },
  { role: 'Insurance Carrier', notify: 'P1', method: 'Email', timing: 'Within 24 hr' },
  { role: 'Regulators', notify: 'P1 (breach, per req)', method: 'Formal Filing', timing: 'Per regulation (72 hr GDPR)' },
  { role: 'Board of Directors', notify: 'P1', method: 'Briefing', timing: 'Within 48 hr' }
];
