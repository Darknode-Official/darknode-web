import { esc } from '/js/shared.js';

const IR_PLAYBOOKS = {
  ransomware: {
    name: 'Ransomware Attack', icon: '\u{1F512}', severity: 'P1',
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
    name: 'Data Breach / Exfiltration', icon: '\u{1F4E4}', severity: 'P1',
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
    name: 'Phishing Campaign', icon: '\u{1F3A3}', severity: 'P2',
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
    name: 'DDoS Attack', icon: '\u{1F30A}', severity: 'P1',
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
    name: 'Insider Threat', icon: '\u{1F46E}', severity: 'P2',
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
    name: 'Supply Chain Compromise', icon: '\u{1F517}', severity: 'P1',
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
    name: 'Malware Outbreak', icon: '\u{1F41B}', severity: 'P2',
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
    name: 'Account Compromise', icon: '\u{1F511}', severity: 'P2',
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

const IR_SEVERITY = {
  P1: { label: 'P1 — Critical', color: '#ff1744', sla: '15 min response, 1 hr update cycle' },
  P2: { label: 'P2 — High', color: '#ff9100', sla: '30 min response, 2 hr update cycle' },
  P3: { label: 'P3 — Medium', color: '#ffd600', sla: '2 hr response, 4 hr update cycle' },
  P4: { label: 'P4 — Low', color: '#00e676', sla: '4 hr response, daily updates' },
  P5: { label: 'P5 — Info', color: '#00b0ff', sla: 'Next business day, weekly updates' }
};

const IR_COMM_TEMPLATES = {
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

const IR_STAKEHOLDERS = [
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

export function renderIncidentResponse(container) {
  let activeTab = 'playbooks';
  let selectedPlaybook = null;
  let activePhase = 'detection';
  let incident = null;
  let checkStates = {};
  let timelineEntries = [];

  function startIncident(pbKey) {
    const pb = IR_PLAYBOOKS[pbKey];
    incident = {
      id: 'IR-' + Date.now().toString(36).toUpperCase(),
      type: pb.name,
      playbook: pbKey,
      severity: pb.severity,
      startTime: new Date(),
      phase: 'detection',
      status: 'Active'
    };
    checkStates = {};
    timelineEntries = [{ time: new Date(), event: `Incident declared: ${pb.name}`, phase: 'detection', auto: true }];
    activePhase = 'detection';
    activeTab = 'active';
    render();
  }

  function toggleCheck(phase, idx) {
    const k = `${phase}-${idx}`;
    checkStates[k] = !checkStates[k];
    if (checkStates[k]) {
      timelineEntries.push({ time: new Date(), event: `Completed: ${IR_PLAYBOOKS[incident.playbook].phases[phase].checks[idx]}`, phase, auto: false });
    }
    render();
  }

  function advancePhase() {
    const phases = Object.keys(IR_PLAYBOOKS[incident.playbook].phases);
    const ci = phases.indexOf(incident.phase);
    if (ci < phases.length - 1) {
      incident.phase = phases[ci + 1];
      activePhase = incident.phase;
      timelineEntries.push({ time: new Date(), event: `Advanced to: ${IR_PLAYBOOKS[incident.playbook].phases[incident.phase].title}`, phase: incident.phase, auto: true });
      render();
    }
  }

  function getPhaseProgress(phase) {
    const checks = IR_PLAYBOOKS[incident.playbook].phases[phase].checks;
    let done = 0;
    checks.forEach((_, i) => { if (checkStates[`${phase}-${i}`]) done++; });
    return { done, total: checks.length, pct: Math.round((done / checks.length) * 100) };
  }

  function formatTime(d) {
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }

  function elapsed() {
    if (!incident) return '—';
    const ms = Date.now() - incident.startTime.getTime();
    const h = Math.floor(ms / 3600000);
    const m = Math.floor((ms % 3600000) / 60000);
    return `${h}h ${m}m`;
  }

  function renderPlaybooks() {
    return Object.entries(IR_PLAYBOOKS).map(([k, pb]) => {
      const sev = IR_SEVERITY[pb.severity];
      const phaseCount = Object.keys(pb.phases).length;
      const totalChecks = Object.values(pb.phases).reduce((s, p) => s + p.checks.length, 0);
      return `<div class="ir-playbook-card" onclick="document.querySelector('.ir-wrap').__irSelect('${k}')">
        <div class="ir-pb-icon">${pb.icon}</div>
        <div class="ir-pb-info">
          <div class="ir-pb-name">${esc(pb.name)}</div>
          <div class="ir-pb-meta">
            <span class="ir-sev-badge" style="background:${sev.color}20;color:${sev.color};border:1px solid ${sev.color}40">${pb.severity}</span>
            <span>${phaseCount} phases</span>
            <span>${totalChecks} checklist items</span>
          </div>
        </div>
        <button class="ir-btn ir-btn-sm" onclick="event.stopPropagation();document.querySelector('.ir-wrap').__irStart('${k}')">Activate</button>
      </div>`;
    }).join('');
  }

  function renderPlaybookDetail(k) {
    const pb = IR_PLAYBOOKS[k];
    const sev = IR_SEVERITY[pb.severity];
    return `<div class="ir-detail-back" onclick="document.querySelector('.ir-wrap').__irBack()">← All Playbooks</div>
      <div class="ir-detail-header">
        <span class="ir-pb-icon-lg">${pb.icon}</span>
        <div>
          <h3 class="ir-detail-title">${esc(pb.name)}</h3>
          <span class="ir-sev-badge" style="background:${sev.color}20;color:${sev.color};border:1px solid ${sev.color}40">${sev.label}</span>
          <span class="ir-sla">${esc(sev.sla)}</span>
        </div>
        <button class="ir-btn" onclick="document.querySelector('.ir-wrap').__irStart('${k}')">Activate Playbook</button>
      </div>
      <div class="ir-phase-nav">${Object.entries(pb.phases).map(([pk, p]) =>
        `<button class="ir-phase-btn ${activePhase === pk ? 'active' : ''}" onclick="document.querySelector('.ir-wrap').__irPhase('${pk}')">${esc(p.title)}</button>`
      ).join('')}</div>
      ${renderPhaseDetail(pb, activePhase, false)}`;
  }

  function renderPhaseDetail(pb, phase, isActive) {
    const p = pb.phases[phase];
    return `<div class="ir-phase-detail">
      <div class="ir-phase-row">
        <div class="ir-phase-col">
          <div class="ir-phase-label">Estimated Time</div>
          <div class="ir-phase-value">${esc(p.time)}</div>
        </div>
        <div class="ir-phase-col">
          <div class="ir-phase-label">Roles</div>
          <div class="ir-phase-value">${p.roles.map(r => `<span class="ir-role-tag">${esc(r)}</span>`).join(' ')}</div>
        </div>
      </div>
      <div class="ir-phase-row">
        <div class="ir-phase-col">
          <div class="ir-phase-label">Tools Required</div>
          <div class="ir-phase-value">${p.tools.map(t => `<span class="ir-tool-tag">${esc(t)}</span>`).join(' ')}</div>
        </div>
      </div>
      <div class="ir-phase-section">
        <h4>Evidence to Collect</h4>
        <ul class="ir-evidence-list">${p.evidence.map(e => `<li>${esc(e)}</li>`).join('')}</ul>
      </div>
      <div class="ir-phase-section">
        <h4>Checklist</h4>
        <div class="ir-checklist">${p.checks.map((c, i) => {
          const checked = isActive && checkStates[`${phase}-${i}`];
          return `<label class="ir-check-item ${checked ? 'done' : ''}" ${isActive ? `onclick="document.querySelector('.ir-wrap').__irToggle('${phase}',${i})"` : ''}>
            <span class="ir-checkbox">${checked ? 'Y' : ''}</span>
            <span>${esc(c)}</span>
          </label>`;
        }).join('')}</div>
      </div>
    </div>`;
  }

  function renderActive() {
    if (!incident) return `<div class="ir-empty">No active incident. Select a playbook to begin.</div>`;
    const pb = IR_PLAYBOOKS[incident.playbook];
    const sev = IR_SEVERITY[incident.severity];
    const phases = Object.keys(pb.phases);
    const prog = getPhaseProgress(incident.phase);
    const canAdvance = prog.pct === 100 && phases.indexOf(incident.phase) < phases.length - 1;

    return `<div class="ir-incident-bar">
        <div class="ir-ib-left">
          <span class="ir-ib-id">${incident.id}</span>
          <span class="ir-sev-badge" style="background:${sev.color}20;color:${sev.color};border:1px solid ${sev.color}40">${incident.severity}</span>
          <span class="ir-ib-type">${esc(incident.type)}</span>
        </div>
        <div class="ir-ib-right">
          <span class="ir-ib-elapsed">${elapsed()}</span>
          <span class="ir-ib-status ir-status-active">ACTIVE</span>
        </div>
      </div>
      <div class="ir-phase-progress">
        ${phases.map((pk, i) => {
          const isCurrent = pk === incident.phase;
          const isDone = i < phases.indexOf(incident.phase);
          const p = getPhaseProgress(pk);
          return `<div class="ir-pp-step ${isDone ? 'done' : ''} ${isCurrent ? 'current' : ''}">
            <div class="ir-pp-dot">${isDone ? 'Y' : i + 1}</div>
            <div class="ir-pp-label">${esc(pb.phases[pk].title)}</div>
            ${isCurrent ? `<div class="ir-pp-pct">${p.pct}%</div>` : ''}
          </div>`;
        }).join('<div class="ir-pp-line"></div>')}
      </div>
      <div class="ir-phase-nav">${phases.map(pk =>
        `<button class="ir-phase-btn ${activePhase === pk ? 'active' : ''}" onclick="document.querySelector('.ir-wrap').__irPhase('${pk}')">${esc(pb.phases[pk].title)}</button>`
      ).join('')}</div>
      <div class="ir-progress-bar"><div class="ir-progress-fill" style="width:${prog.pct}%"></div></div>
      <div class="ir-progress-text">${prog.done}/${prog.total} tasks complete (${prog.pct}%)</div>
      ${renderPhaseDetail(pb, activePhase, true)}
      ${canAdvance ? `<button class="ir-btn ir-btn-advance" onclick="document.querySelector('.ir-wrap').__irAdvance()">Advance to Next Phase →</button>` : ''}`;
  }

  function renderTimeline() {
    if (!incident) return `<div class="ir-empty">No active incident. Start one from the Playbooks tab.</div>`;
    const pb = IR_PLAYBOOKS[incident.playbook];
    return `<div class="ir-timeline-header">
        <h3>Incident Timeline — ${incident.id}</h3>
        <span class="ir-ib-elapsed">${elapsed()}</span>
      </div>
      <div class="ir-timeline">
        ${timelineEntries.slice().reverse().map(e => {
          const phaseInfo = pb.phases[e.phase];
          return `<div class="ir-tl-entry ${e.auto ? 'auto' : 'manual'}">
            <div class="ir-tl-time">${formatTime(e.time)}</div>
            <div class="ir-tl-dot"></div>
            <div class="ir-tl-content">
              <div class="ir-tl-event">${esc(e.event)}</div>
              <div class="ir-tl-phase">${esc(phaseInfo?.title || e.phase)}</div>
            </div>
          </div>`;
        }).join('')}
      </div>
      <div class="ir-tl-add">
        <input class="ir-input ir-tl-input" placeholder="Add manual timeline entry..." id="ir-tl-text"/>
        <button class="ir-btn ir-btn-sm" onclick="const inp=document.getElementById('ir-tl-text');if(inp.value.trim()){document.querySelector('.ir-wrap').__irAddTL(inp.value.trim());inp.value='';}">Add</button>
      </div>`;
  }

  function renderComms() {
    return `<div class="ir-comms-grid">
        <div class="ir-comms-templates">
          <h3>Communication Templates</h3>
          ${Object.entries(IR_COMM_TEMPLATES).map(([k, t]) =>
            `<div class="ir-comm-card">
              <div class="ir-comm-name">${esc(t.name)}</div>
              <pre class="ir-comm-preview">${esc(t.template)}</pre>
              <button class="ir-btn ir-btn-sm" onclick="navigator.clipboard.writeText(document.querySelectorAll('.ir-comm-preview')[${Object.keys(IR_COMM_TEMPLATES).indexOf(k)}].textContent)">Copy Template</button>
            </div>`
          ).join('')}
        </div>
        <div class="ir-stakeholder-section">
          <h3>Stakeholder Notification Matrix</h3>
          <table class="ir-table">
            <thead><tr><th>Role</th><th>Notify For</th><th>Method</th><th>Timing</th></tr></thead>
            <tbody>${IR_STAKEHOLDERS.map(s =>
              `<tr><td>${esc(s.role)}</td><td>${esc(s.notify)}</td><td>${esc(s.method)}</td><td>${esc(s.timing)}</td></tr>`
            ).join('')}</tbody>
          </table>
        </div>
      </div>`;
  }

  function renderReport() {
    if (!incident) return `<div class="ir-empty">No active incident. Start one to generate a report.</div>`;
    const pb = IR_PLAYBOOKS[incident.playbook];
    const phases = Object.keys(pb.phases);
    const totalChecks = phases.reduce((s, pk) => s + pb.phases[pk].checks.length, 0);
    const doneChecks = phases.reduce((s, pk) => {
      return s + pb.phases[pk].checks.filter((_, i) => checkStates[`${pk}-${i}`]).length;
    }, 0);

    const report = `INCIDENT RESPONSE REPORT
${'='.repeat(50)}
Incident ID: ${incident.id}
Type: ${incident.type}
Severity: ${IR_SEVERITY[incident.severity].label}
Status: ${incident.status}
Started: ${incident.startTime.toISOString()}
Duration: ${elapsed()}
Current Phase: ${pb.phases[incident.phase].title}
Overall Progress: ${doneChecks}/${totalChecks} tasks (${Math.round((doneChecks/totalChecks)*100)}%)

PHASE BREAKDOWN
${'-'.repeat(50)}
${phases.map(pk => {
  const p = pb.phases[pk];
  const prog = getPhaseProgress(pk);
  return `\n[${p.title}] — ${prog.done}/${prog.total} (${prog.pct}%)
${p.checks.map((c, i) => `  ${checkStates[`${pk}-${i}`] ? '[x]' : '[ ]'} ${c}`).join('\n')}`;
}).join('\n')}

TIMELINE
${'-'.repeat(50)}
${timelineEntries.map(e => `${formatTime(e.time)} | ${e.event}`).join('\n')}

EVIDENCE CHECKLIST
${'-'.repeat(50)}
${phases.map(pk => {
  const p = pb.phases[pk];
  return `${p.title}:\n${p.evidence.map(e => `  [ ] ${e}`).join('\n')}`;
}).join('\n\n')}
`;

    return `<div class="ir-report-header">
        <h3>Incident Report — ${incident.id}</h3>
        <div class="ir-report-actions">
          <button class="ir-btn ir-btn-sm" onclick="navigator.clipboard.writeText(document.getElementById('ir-report-text').textContent)">Copy Report</button>
          <button class="ir-btn ir-btn-sm" onclick="const b=new Blob([document.getElementById('ir-report-text').textContent],{type:'text/plain'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='${incident.id}-report.txt';a.click()">Download</button>
        </div>
      </div>
      <pre class="ir-report-output" id="ir-report-text">${esc(report)}</pre>`;
  }

  function render() {
    const tabs = [
      { id: 'playbooks', label: 'Playbooks' },
      { id: 'active', label: 'Active Incident' },
      { id: 'timeline', label: 'Timeline' },
      { id: 'comms', label: 'Communications' },
      { id: 'report', label: 'Report' }
    ];

    let content = '';
    if (activeTab === 'playbooks') {
      if (selectedPlaybook) {
        content = renderPlaybookDetail(selectedPlaybook);
      } else {
        content = `<div class="ir-playbook-grid">${renderPlaybooks()}</div>`;
      }
    } else if (activeTab === 'active') {
      content = renderActive();
    } else if (activeTab === 'timeline') {
      content = renderTimeline();
    } else if (activeTab === 'comms') {
      content = renderComms();
    } else if (activeTab === 'report') {
      content = renderReport();
    }

    container.innerHTML = `<div class="ir-wrap">
      <div class="ir-header">
        <h2 class="ir-title">\u{1F6A8} Incident Response Manager</h2>
        <div class="ir-subtitle">Interactive playbook-driven incident response workflow</div>
      </div>
      <div class="ir-tabs">${tabs.map(t =>
        `<button class="ir-tab ${activeTab === t.id ? 'active' : ''}" data-tab="${t.id}">${t.label}${t.id === 'active' && incident ? ' \u{1F534}' : ''}</button>`
      ).join('')}</div>
      <div class="ir-content">${content}</div>
    </div>`;

    const wrap = container.querySelector('.ir-wrap');
    wrap.__irSelect = k => { selectedPlaybook = k; activePhase = 'detection'; render(); };
    wrap.__irBack = () => { selectedPlaybook = null; render(); };
    wrap.__irStart = k => { startIncident(k); };
    wrap.__irPhase = p => { activePhase = p; render(); };
    wrap.__irToggle = (p, i) => { toggleCheck(p, i); };
    wrap.__irAdvance = () => { advancePhase(); };
    wrap.__irAddTL = t => {
      timelineEntries.push({ time: new Date(), event: t, phase: incident.phase, auto: false });
      render();
    };

    container.querySelectorAll('.ir-tab').forEach(btn => {
      btn.addEventListener('click', () => { activeTab = btn.dataset.tab; render(); });
    });
  }

  if (!document.getElementById('ir-styles')) {
    const style = document.createElement('style');
    style.id = 'ir-styles';
    style.textContent = `
.ir-wrap { background: #080c14; color: #c8d6e5; font-family: 'Segoe UI', system-ui, sans-serif; border-radius: 8px; overflow: hidden; }
.ir-header { padding: 20px 24px 12px; background: linear-gradient(135deg, #0a1628 0%, #0f1f3a 100%); border-bottom: 1px solid #1a2a44; }
.ir-title { margin: 0; font-size: 22px; color: #fff; font-weight: 700; }
.ir-subtitle { color: #6a8caf; font-size: 13px; margin-top: 4px; }
.ir-tabs { display: flex; background: #0a0e18; border-bottom: 1px solid #1a2a44; overflow-x: auto; }
.ir-tab { background: none; border: none; color: #6a8caf; padding: 12px 20px; cursor: pointer; font-size: 13px; white-space: nowrap; border-bottom: 2px solid transparent; transition: all .2s; }
.ir-tab:hover { color: #c8d6e5; background: #0f1726; }
.ir-tab.active { color: #00aaff; border-bottom-color: #00aaff; }
.ir-content { padding: 20px 24px; min-height: 400px; }
.ir-empty { text-align: center; padding: 60px 20px; color: #4a6a8a; font-size: 15px; }

/* Playbook Cards */
.ir-playbook-grid { display: flex; flex-direction: column; gap: 10px; }
.ir-playbook-card { display: flex; align-items: center; gap: 16px; padding: 16px 20px; background: #0f1726; border: 1px solid #1a2a44; border-radius: 8px; cursor: pointer; transition: all .2s; }
.ir-playbook-card:hover { border-color: #00aaff; background: #111d30; }
.ir-pb-icon { font-size: 28px; }
.ir-pb-icon-lg { font-size: 36px; }
.ir-pb-info { flex: 1; }
.ir-pb-name { font-size: 15px; font-weight: 600; color: #e2e8f0; margin-bottom: 4px; }
.ir-pb-meta { display: flex; gap: 10px; align-items: center; font-size: 12px; color: #6a8caf; }
.ir-sev-badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
.ir-sla { font-size: 12px; color: #6a8caf; }
.ir-btn { background: #00aaff; color: #fff; border: none; padding: 8px 18px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; transition: background .2s; }
.ir-btn:hover { background: #0088cc; }
.ir-btn-sm { padding: 6px 12px; font-size: 12px; }
.ir-btn-advance { margin-top: 16px; background: #00e676; color: #000; }
.ir-btn-advance:hover { background: #00c853; }

/* Detail View */
.ir-detail-back { color: #00aaff; cursor: pointer; font-size: 13px; margin-bottom: 12px; }
.ir-detail-back:hover { text-decoration: underline; }
.ir-detail-header { display: flex; align-items: center; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }
.ir-detail-title { margin: 0; font-size: 20px; color: #fff; }
.ir-phase-nav { display: flex; gap: 6px; margin-bottom: 16px; overflow-x: auto; }
.ir-phase-btn { background: #0f1726; border: 1px solid #1a2a44; color: #8ab4d6; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 12px; white-space: nowrap; transition: all .2s; }
.ir-phase-btn:hover { background: #162036; border-color: #2a3a5a; }
.ir-phase-btn.active { background: #00aaff20; border-color: #00aaff; color: #00aaff; }

/* Phase Detail */
.ir-phase-detail { background: #0f1726; border: 1px solid #1a2a44; border-radius: 8px; padding: 20px; }
.ir-phase-row { display: flex; gap: 24px; margin-bottom: 16px; flex-wrap: wrap; }
.ir-phase-col { flex: 1; min-width: 200px; }
.ir-phase-label { font-size: 11px; color: #4a6a8a; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
.ir-phase-value { font-size: 14px; color: #e2e8f0; display: flex; flex-wrap: wrap; gap: 4px; }
.ir-role-tag { background: #1a2a44; padding: 3px 8px; border-radius: 4px; font-size: 12px; color: #8ab4d6; }
.ir-tool-tag { background: #0a1628; border: 1px solid #1a2a44; padding: 3px 8px; border-radius: 4px; font-size: 12px; color: #00aaff; }
.ir-phase-section { margin-top: 16px; }
.ir-phase-section h4 { margin: 0 0 10px; font-size: 14px; color: #e2e8f0; }
.ir-evidence-list { margin: 0; padding-left: 20px; }
.ir-evidence-list li { font-size: 13px; color: #8ab4d6; margin-bottom: 4px; }

/* Checklist */
.ir-checklist { display: flex; flex-direction: column; gap: 6px; }
.ir-check-item { display: flex; align-items: flex-start; gap: 10px; padding: 8px 12px; background: #0a1628; border-radius: 6px; cursor: pointer; font-size: 13px; transition: all .2s; user-select: none; }
.ir-check-item:hover { background: #111d30; }
.ir-check-item.done { opacity: 0.6; }
.ir-check-item.done span:last-child { text-decoration: line-through; }
.ir-checkbox { width: 18px; height: 18px; min-width: 18px; border: 2px solid #2a3a5a; border-radius: 4px; display: flex; align-items: center; justify-content: center; font-size: 12px; color: #00e676; }
.ir-check-item.done .ir-checkbox { border-color: #00e676; background: #00e67620; }

/* Incident Bar */
.ir-incident-bar { display: flex; justify-content: space-between; align-items: center; background: #0f1726; border: 1px solid #1a2a44; border-radius: 8px; padding: 12px 20px; margin-bottom: 16px; flex-wrap: wrap; gap: 8px; }
.ir-ib-left, .ir-ib-right { display: flex; align-items: center; gap: 10px; }
.ir-ib-id { font-weight: 700; color: #fff; font-family: monospace; }
.ir-ib-type { color: #8ab4d6; font-size: 13px; }
.ir-ib-elapsed { color: #ffd600; font-size: 13px; font-family: monospace; }
.ir-status-active { background: #ff174420; color: #ff1744; padding: 3px 10px; border-radius: 4px; font-size: 12px; font-weight: 700; animation: ir-pulse 2s infinite; }
@keyframes ir-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }

/* Phase Progress */
.ir-phase-progress { display: flex; align-items: center; justify-content: center; gap: 0; margin-bottom: 20px; padding: 16px 0; overflow-x: auto; }
.ir-pp-step { display: flex; flex-direction: column; align-items: center; gap: 4px; min-width: 80px; }
.ir-pp-dot { width: 32px; height: 32px; border-radius: 50%; background: #1a2a44; border: 2px solid #2a3a5a; display: flex; align-items: center; justify-content: center; font-size: 13px; color: #6a8caf; font-weight: 700; }
.ir-pp-step.done .ir-pp-dot { background: #00e676; border-color: #00e676; color: #000; }
.ir-pp-step.current .ir-pp-dot { background: #00aaff20; border-color: #00aaff; color: #00aaff; }
.ir-pp-label { font-size: 10px; color: #6a8caf; text-align: center; max-width: 90px; }
.ir-pp-step.current .ir-pp-label { color: #00aaff; }
.ir-pp-pct { font-size: 11px; color: #00aaff; font-weight: 600; }
.ir-pp-line { width: 30px; height: 2px; background: #1a2a44; margin-bottom: 20px; }
.ir-pp-step.done + .ir-pp-line { background: #00e676; }
.ir-progress-bar { height: 4px; background: #1a2a44; border-radius: 2px; margin-bottom: 8px; overflow: hidden; }
.ir-progress-fill { height: 100%; background: linear-gradient(90deg, #00aaff, #00e676); border-radius: 2px; transition: width .3s; }
.ir-progress-text { font-size: 12px; color: #6a8caf; margin-bottom: 16px; }

/* Timeline */
.ir-timeline-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.ir-timeline-header h3 { margin: 0; color: #fff; font-size: 16px; }
.ir-timeline { position: relative; padding-left: 20px; border-left: 2px solid #1a2a44; }
.ir-tl-entry { display: flex; gap: 12px; margin-bottom: 12px; position: relative; }
.ir-tl-time { font-size: 12px; color: #4a6a8a; font-family: monospace; min-width: 70px; padding-top: 2px; }
.ir-tl-dot { width: 10px; height: 10px; min-width: 10px; border-radius: 50%; background: #00aaff; margin-top: 4px; position: absolute; left: -26px; }
.ir-tl-entry.auto .ir-tl-dot { background: #00e676; }
.ir-tl-content { flex: 1; }
.ir-tl-event { font-size: 13px; color: #e2e8f0; }
.ir-tl-phase { font-size: 11px; color: #4a6a8a; margin-top: 2px; }
.ir-tl-add { display: flex; gap: 8px; margin-top: 16px; }
.ir-input { background: #0f1726; border: 1px solid #1a2a44; color: #c8d6e5; padding: 8px 12px; border-radius: 6px; font-size: 13px; flex: 1; outline: none; }
.ir-input:focus { border-color: #00aaff; }
.ir-tl-input { flex: 1; }

/* Communications */
.ir-comms-grid { display: flex; flex-direction: column; gap: 20px; }
.ir-comms-templates h3, .ir-stakeholder-section h3 { margin: 0 0 12px; color: #fff; font-size: 16px; }
.ir-comm-card { background: #0f1726; border: 1px solid #1a2a44; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
.ir-comm-name { font-size: 14px; font-weight: 600; color: #e2e8f0; margin-bottom: 8px; }
.ir-comm-preview { background: #0a0e18; border: 1px solid #1a2a44; border-radius: 6px; padding: 12px; font-size: 12px; color: #8ab4d6; max-height: 200px; overflow-y: auto; white-space: pre-wrap; word-break: break-word; margin: 0 0 10px; }
.ir-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.ir-table th { background: #0f1726; color: #8ab4d6; padding: 10px 12px; text-align: left; border-bottom: 2px solid #1a2a44; font-weight: 600; }
.ir-table td { padding: 8px 12px; border-bottom: 1px solid #0f1726; color: #c8d6e5; }
.ir-table tr:hover td { background: #0f172680; }

/* Report */
.ir-report-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px; }
.ir-report-header h3 { margin: 0; color: #fff; font-size: 16px; }
.ir-report-actions { display: flex; gap: 8px; }
.ir-report-output { background: #0a0e18; border: 1px solid #1a2a44; border-radius: 8px; padding: 20px; font-size: 13px; color: #c8d6e5; font-family: 'JetBrains Mono', 'Fira Code', monospace; white-space: pre-wrap; word-break: break-word; max-height: 600px; overflow-y: auto; margin: 0; }

@media (max-width: 768px) {
  .ir-content { padding: 12px; }
  .ir-phase-row { flex-direction: column; }
  .ir-incident-bar { flex-direction: column; text-align: center; }
  .ir-phase-progress { flex-wrap: wrap; }
  .ir-detail-header { flex-direction: column; align-items: flex-start; }
  .ir-comm-preview { max-height: 120px; }
}`;
    document.head.appendChild(style);
  }

  render();
}
