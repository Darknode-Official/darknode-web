// Darknode Blue Team & Incident Response Engine
// Defensive security automation, forensics, threat hunting, compliance.
"use strict";

// ═══════════════════════════════════════════════════════════════════════════════
// INCIDENT RESPONSE PLAYBOOKS
// ═══════════════════════════════════════════════════════════════════════════════

export const IR_PLAYBOOKS = [
  {
    id: "ransomware", name: "Ransomware Incident", severity: "critical", priority: 1,
    detection: [
      "Mass file encryption activity detected (canary files triggered)",
      "Known ransomware signatures in EDR/AV alerts",
      "Users reporting inability to open files, ransom notes appearing",
      "Volume Shadow Copy deletion (vssadmin delete shadows)",
      "Unusual process activity: vssadmin.exe, wbadmin.exe, bcdedit.exe",
      "Event ID 4663 — mass file access/modification",
    ],
    containment: [
      "IMMEDIATELY isolate affected systems from network (disconnect cable, disable WiFi)",
      "Disable network shares to prevent lateral spread: net use * /delete /y",
      "Block known C2 IPs/domains at the firewall and DNS level",
      "Disable compromised user accounts in Active Directory",
      "Identify and isolate the patient zero (first infected system)",
      "Snapshot any running VMs before shutting down for forensic preservation",
      "Block lateral movement: disable SMB (TCP 445), RDP (TCP 3389), WMI, PsExec on uninfected systems",
      "Enable enhanced monitoring on all remaining systems",
    ],
    eradication: [
      "Identify ransomware family (ID Ransomware, No More Ransom project)",
      "Check for available decryptor tools before paying ransom",
      "Remove malware from all affected systems using offline AV scan",
      "Reset credentials for all compromised accounts (domain-wide if DC affected)",
      "Rotate KRBTGT password twice if domain compromise is suspected",
      "Patch the vulnerability used for initial access",
      "Remove all persistence mechanisms (scheduled tasks, services, registry keys)",
    ],
    recovery: [
      "Restore from clean, verified offline backups (verify backup integrity first)",
      "Rebuild systems from known-good images if no clean backup available",
      "Restore data from the most recent clean backup",
      "Re-enable network connectivity for restored systems gradually",
      "Monitor restored systems for signs of reinfection",
      "Verify all critical business applications are functional",
      "Update all endpoint protection signatures and rules",
    ],
    lessons_learned: [
      "Conduct a blameless post-incident review within 72 hours",
      "Document the full timeline from initial compromise to recovery",
      "Identify the initial access vector and close the gap",
      "Review and improve backup procedures (frequency, isolation, testing)",
      "Assess whether security controls detected the attack in time",
      "Update IR playbook based on what worked and what didn't",
      "Provide targeted training based on the attack vector used",
    ],
  },
  {
    id: "data_breach", name: "Data Breach", severity: "critical", priority: 1,
    detection: [
      "DLP alert — sensitive data leaving the network",
      "Unusual data access patterns (bulk download, off-hours access)",
      "Cloud storage alerts — large data transfers to external accounts",
      "Database query anomalies — SELECT * or bulk export queries",
      "Third-party breach notification mentioning your organization",
      "Dark web monitoring alerts — company data for sale",
    ],
    containment: [
      "Identify the scope: what data, how much, who accessed it",
      "Revoke access for compromised accounts immediately",
      "Block the exfiltration channel (IP, domain, cloud service)",
      "Preserve all logs and evidence before they rotate",
      "Engage legal counsel — determine regulatory notification requirements",
      "Activate the incident response team and brief leadership",
    ],
    eradication: [
      "Remove the attacker's access completely (close all backdoors)",
      "Reset all credentials that may have been exposed",
      "Patch the vulnerability that enabled the breach",
      "Review and tighten access controls on affected data",
      "Implement additional DLP rules to prevent recurrence",
    ],
    recovery: [
      "Verify data integrity in affected systems",
      "Restore any modified or deleted data from backups",
      "Implement enhanced monitoring on previously breached systems",
      "Engage PR/communications for external messaging if needed",
    ],
    lessons_learned: [
      "Determine the total impact: records exposed, regulatory implications",
      "Calculate costs: notification, credit monitoring, legal, reputational",
      "Review data classification and access control policies",
      "Assess whether DLP controls were adequate",
      "Update the data breach response plan",
    ],
    regulatory: {
      gdpr: "Notify supervisory authority within 72 hours of discovery (Article 33). Notify affected individuals without undue delay if high risk (Article 34).",
      hipaa: "Notify HHS within 60 days of discovery. Notify affected individuals within 60 days. Notify media if >500 individuals in a state.",
      pci: "Notify acquiring bank and card brands within 24-72 hours. Engage PCI Forensic Investigator (PFI).",
      state_laws: "Most US states require notification within 30-90 days. Check specific state requirements.",
    },
  },
  {
    id: "insider_threat", name: "Insider Threat", severity: "high", priority: 2,
    detection: [
      "DLP alerts from a specific user accessing unusual data",
      "After-hours access to sensitive systems by a user not typically active then",
      "Large file downloads or uploads to personal cloud storage",
      "USB device usage in violation of policy",
      "Badge access anomalies (accessing areas outside normal scope)",
      "HR notification of disgruntled or terminated employee",
      "User accessing systems after resignation notice",
    ],
    containment: [
      "Do NOT alert the suspect — coordinate with HR and legal first",
      "Enable enhanced monitoring on the suspect's accounts and devices",
      "Preserve all evidence: email, file access logs, badge logs, CCTV",
      "Restrict access to sensitive data without raising suspicion if possible",
      "If imminent threat: disable accounts and collect devices with HR/legal present",
    ],
    eradication: [
      "Disable all accounts and access upon termination",
      "Collect all company devices, badges, and credentials",
      "Revoke VPN, cloud, and remote access",
      "Change shared credentials the insider had access to",
      "Remove any personal devices from the corporate network",
    ],
    recovery: [
      "Audit all data and systems the insider had access to",
      "Verify no backdoor accounts or unauthorized access paths remain",
      "Review and adjust access controls based on the incident",
      "Update the insider threat program based on lessons learned",
    ],
    lessons_learned: [
      "Review the warning signs that were missed",
      "Assess whether behavioral analytics tools would have detected earlier",
      "Update offboarding procedures",
      "Review least-privilege access implementation",
      "Consider implementing a formal insider threat program (NITTF framework)",
    ],
  },
  {
    id: "ddos", name: "DDoS Attack", severity: "high", priority: 2,
    detection: [
      "Sudden spike in inbound traffic volume",
      "Website/service unresponsive or extremely slow",
      "Network monitoring showing bandwidth saturation",
      "Firewall/IPS alert for SYN flood, UDP flood, or amplification",
      "CDN/cloud provider DDoS notification",
    ],
    containment: [
      "Activate DDoS mitigation service (Cloudflare, AWS Shield, Akamai)",
      "Enable rate limiting on edge devices",
      "Implement geo-blocking if attack originates from specific regions",
      "Blackhole route if necessary to protect upstream infrastructure",
      "Scale up infrastructure if cloud-hosted (auto-scaling groups)",
      "Engage ISP for upstream filtering of volumetric attacks",
    ],
    eradication: [
      "Identify and block attack sources (may be spoofed)",
      "Tune DDoS mitigation rules based on attack patterns",
      "Verify no application-layer DDoS (slowloris, HTTP floods)",
      "Check for associated intrusion attempts (DDoS as distraction)",
    ],
    recovery: [
      "Gradually lift blackhole routing and geo-blocks",
      "Monitor for attack resumption",
      "Verify all services are fully operational",
      "Review capacity and scaling thresholds",
    ],
    lessons_learned: [
      "Evaluate DDoS mitigation service effectiveness",
      "Review network architecture for DDoS resilience",
      "Test auto-scaling and failover mechanisms",
      "Update the DDoS response runbook",
    ],
  },
  {
    id: "bec", name: "Business Email Compromise", severity: "high", priority: 2,
    detection: [
      "Finance team reports suspicious wire transfer request from executive",
      "Email forwarding rules created without user knowledge",
      "Unusual login locations for executive accounts",
      "Inbox rules redirecting or deleting emails (hiding the compromise)",
      "Vendor reports payment sent to wrong account",
    ],
    containment: [
      "Contact the bank immediately to recall the wire transfer",
      "Reset the compromised email account password",
      "Remove malicious inbox/forwarding rules",
      "Enable MFA on the compromised account",
      "Review all recent emails from the compromised account",
      "Notify all parties who received emails from the compromised account",
    ],
    eradication: [
      "Identify the initial compromise method (phishing, credential stuffing)",
      "Check for OAuth app consents that grant mailbox access",
      "Review and revoke any suspicious Azure AD/O365 app registrations",
      "Reset credentials for any accounts the attacker could have accessed",
    ],
    recovery: [
      "Verify no ongoing unauthorized access to email",
      "Restore any deleted or modified emails from backup",
      "Work with finance/bank on fund recovery",
      "File a report with the FBI IC3 (Internet Crime Complaint Center)",
    ],
    lessons_learned: [
      "Implement phishing-resistant MFA (FIDO2/WebAuthn)",
      "Review wire transfer authorization procedures",
      "Implement conditional access policies",
      "Train finance team on BEC recognition",
    ],
  },
  {
    id: "apt", name: "Advanced Persistent Threat", severity: "critical", priority: 1,
    detection: [
      "Threat intelligence alert matching APT indicators in your environment",
      "Unusual beaconing patterns in network traffic (regular interval callbacks)",
      "Living-off-the-land binary (LOLBin) execution from unusual contexts",
      "Discovery commands (whoami, net group, nltest) from non-admin workstations",
      "Unusual PowerShell activity: encoded commands, download cradles",
      "Kerberos anomalies: Golden/Silver ticket indicators, encryption downgrades",
    ],
    containment: [
      "DO NOT tip off the attacker — maintain normal operations while investigating",
      "Engage a specialized incident response firm (Mandiant, CrowdStrike, Secureworks)",
      "Implement enhanced monitoring without alerting the adversary",
      "Begin parallel investigation on an isolated network",
      "Preserve all evidence with forensic integrity",
      "Identify all compromised systems before taking containment action",
      "Plan a coordinated remediation event (cut all access at once)",
    ],
    eradication: [
      "Execute coordinated remediation: simultaneously reset all credentials, remove persistence, rebuild compromised systems",
      "Reset KRBTGT password twice (current + previous hash)",
      "Rotate all service account credentials",
      "Rebuild domain controllers from clean media if domain is fully compromised",
      "Re-image all compromised workstations and servers",
      "Review and close the initial access vector",
      "Remove all persistence mechanisms (web shells, scheduled tasks, services, registry)",
    ],
    recovery: [
      "Gradually restore services with enhanced monitoring",
      "Implement additional security controls based on APT TTPs observed",
      "Deploy deception technology to detect re-entry attempts",
      "Establish threat hunting program focused on known APT techniques",
    ],
    lessons_learned: [
      "Full incident timeline and attack path documentation",
      "Gap analysis: what controls failed and why",
      "Threat model update based on observed adversary capabilities",
      "Long-term security improvement roadmap",
    ],
  },
  {
    id: "supply_chain", name: "Supply Chain Compromise", severity: "critical", priority: 1,
    detection: [
      "Vendor security notification about compromised software/update",
      "Unusual behavior after a software update (new network connections, processes)",
      "Threat intelligence report about compromised software supply chain",
      "File integrity monitoring alert on vendor-supplied binaries",
      "Unexpected code signing certificate changes on vendor software",
    ],
    containment: [
      "Stop deploying the compromised software/update immediately",
      "Isolate systems that have the compromised version installed",
      "Block C2 infrastructure associated with the compromise",
      "Identify all systems with the affected software version",
      "Roll back to the last known-good version if possible",
    ],
    eradication: [
      "Remove the compromised software from all systems",
      "Scan all affected systems for indicators of compromise",
      "Reset credentials on systems where the compromised software ran",
      "Review and verify the integrity of other vendor-supplied software",
    ],
    recovery: [
      "Install a verified clean version of the affected software",
      "Monitor recovered systems for signs of ongoing compromise",
      "Work with the vendor on remediation and timeline",
    ],
    lessons_learned: [
      "Review software supply chain security practices",
      "Implement SBOM (Software Bill of Materials) tracking",
      "Evaluate vendor security assessment procedures",
      "Consider code signing verification and hash checking for all updates",
    ],
  },
  {
    id: "credential_compromise", name: "Credential Compromise", severity: "high", priority: 2,
    detection: [
      "Impossible travel alert (login from two distant locations in short time)",
      "Multiple failed login attempts followed by a success",
      "Login from known-bad IP (threat intel feed match)",
      "Credential found in dark web monitoring",
      "Unusual MFA bypass or enrollment from unknown device",
    ],
    containment: [
      "Reset the compromised password immediately",
      "Revoke all active sessions for the account",
      "Enable MFA if not already enabled",
      "Review recent account activity for unauthorized actions",
      "Check for mailbox rules, OAuth consents, or delegated access",
    ],
    eradication: [
      "Determine how credentials were compromised (phishing, breach, keylogger)",
      "If phishing: identify all users who received the same phishing email",
      "If breach: check all user credentials against known breach databases",
      "Remove any malware or keyloggers from the user's device",
    ],
    recovery: [
      "Restore any changes made by the attacker",
      "Verify no persistent access methods remain",
      "Monitor the account for continued unauthorized access",
    ],
    lessons_learned: [
      "Review password policy and MFA coverage",
      "Assess need for phishing-resistant MFA (FIDO2)",
      "Evaluate credential monitoring and alerting capabilities",
    ],
  },
  {
    id: "web_defacement", name: "Web Defacement", severity: "medium", priority: 3,
    detection: [
      "Website monitoring alert — content changed unexpectedly",
      "User reports of unfamiliar content on the website",
      "File integrity monitoring alert on web root files",
      "Web server access logs showing unauthorized file modifications",
    ],
    containment: [
      "Take the defaced website offline immediately",
      "Preserve the defaced version for forensic analysis",
      "Switch to a static maintenance page or CDN-cached version",
      "Block the attacker's IP if identified in access logs",
    ],
    eradication: [
      "Identify the vulnerability used (SQLi, file upload, RCE, stolen creds)",
      "Remove any web shells or backdoors planted by the attacker",
      "Patch the vulnerability that allowed the defacement",
      "Reset all CMS and server credentials",
    ],
    recovery: [
      "Restore the website from a known-good backup or deployment",
      "Verify all web server files match the expected deployment",
      "Implement file integrity monitoring for web root",
      "Enable WAF rules to prevent the attack vector used",
    ],
    lessons_learned: [
      "Review web application security posture",
      "Implement automated deployment (immutable infrastructure)",
      "Review access controls on web server administration",
    ],
  },
  {
    id: "cryptomining", name: "Cryptomining/Cryptojacking", severity: "medium", priority: 3,
    detection: [
      "Unusual CPU/GPU utilization spikes across multiple systems",
      "EDR alert for known cryptominer signatures",
      "Network connections to known mining pools",
      "Cloud billing spike (compute costs increased unexpectedly)",
      "Fans running constantly on servers/workstations",
    ],
    containment: [
      "Kill the mining process on affected systems",
      "Block network connections to mining pools at firewall/DNS",
      "Identify and isolate the entry point used by the attacker",
      "For cloud: stop or terminate unauthorized compute instances",
    ],
    eradication: [
      "Remove mining software and any persistence mechanisms",
      "Patch the vulnerability used for initial access",
      "Reset compromised credentials",
      "Scan all systems for additional mining software",
    ],
    recovery: [
      "Verify normal CPU/GPU usage levels restored",
      "Monitor for mining activity resumption",
      "Review cloud IAM policies and spending alerts",
    ],
    lessons_learned: [
      "Implement CPU/GPU monitoring thresholds and alerts",
      "Set up cloud spending alerts and budgets",
      "Review and harden container/cloud security",
    ],
  },
  {
    id: "phishing_incident", name: "Phishing Campaign", severity: "medium", priority: 2,
    detection: ["User reports phishing email", "Email gateway quarantine alerts", "Multiple users receiving the same suspicious email", "Credential harvesting page identified by URL filtering"],
    containment: ["Block the sender domain/address at the email gateway", "Remove the phishing email from all mailboxes (Search-Mailbox or Content Search)", "Block the phishing URL at web proxy and DNS", "Identify all users who clicked the link or opened the attachment", "Reset passwords for users who entered credentials"],
    eradication: ["Scan devices of users who clicked for malware", "Remove any downloaded payloads", "Verify no persistence mechanisms installed"],
    recovery: ["Restore normal email flow after blocking rules confirmed", "Monitor accounts of affected users for suspicious activity"],
    lessons_learned: ["Analyze phishing email for bypass of controls", "Update email filtering rules", "Conduct targeted phishing awareness training"],
  },
  {
    id: "malware_infection", name: "Malware Infection", severity: "high", priority: 2,
    detection: ["EDR/AV alert for known malware", "Behavioral detection of suspicious process activity", "Network IDS/IPS alert for C2 traffic", "User reports unusual system behavior"],
    containment: ["Isolate infected system from network", "Kill malicious processes", "Block C2 IPs/domains at firewall", "Identify other potentially infected systems"],
    eradication: ["Run full malware scan with updated signatures", "Remove all malware components", "Patch vulnerability used for infection", "Reset credentials used on infected system"],
    recovery: ["Re-image system if infection was severe", "Restore user data from backup", "Reconnect to network with enhanced monitoring"],
    lessons_learned: ["Identify initial infection vector", "Review endpoint protection effectiveness", "Update detection signatures and rules"],
  },
  {
    id: "unauthorized_access", name: "Unauthorized Access", severity: "high", priority: 2,
    detection: ["Login from unusual location or device", "Access to resources outside user's normal scope", "Audit log showing access by unknown account", "Badge access anomaly"],
    containment: ["Disable the unauthorized account", "Revoke all active sessions", "Change credentials for any systems accessed", "Preserve access logs"],
    eradication: ["Determine how unauthorized access was gained", "Close the access path", "Review and tighten access controls"],
    recovery: ["Verify no data was modified or exfiltrated", "Restore normal access controls", "Monitor for re-entry"],
    lessons_learned: ["Review access provisioning processes", "Implement or improve access reviews", "Assess MFA coverage"],
  },
  {
    id: "privilege_escalation", name: "Privilege Escalation", severity: "high", priority: 2,
    detection: ["User account suddenly appears in admin groups", "Event ID 4672 — special privileges assigned at logon", "Sudo/su usage by unexpected users", "UAC bypass detection", "New service or scheduled task running as SYSTEM"],
    containment: ["Remove the escalated privileges", "Disable the compromised account", "Identify how escalation was achieved"],
    eradication: ["Patch the vulnerability used for escalation", "Remove any tools used (mimikatz, potato exploits)", "Reset KRBTGT if domain admin was compromised"],
    recovery: ["Audit all admin-level accounts", "Review group policy and OU permissions", "Implement PAM/PIM solutions"],
    lessons_learned: ["Review privilege management practices", "Assess need for Credential Guard and LAPS", "Implement tiered admin model"],
  },
  {
    id: "lateral_movement", name: "Lateral Movement", severity: "high", priority: 2,
    detection: ["Unusual RDP/SMB/WinRM connections between workstations", "PsExec or WMI usage from non-admin systems", "Event ID 4624 Type 3 (network logon) between workstations", "Pass-the-Hash/Ticket indicators"],
    containment: ["Isolate compromised systems", "Block lateral protocols between workstations (SMB, RDP)", "Reset credentials for accounts used in lateral movement"],
    eradication: ["Remove attacker access from all systems reached", "Reset all potentially compromised credentials", "Patch systems exploited during lateral movement"],
    recovery: ["Restore network connectivity gradually with monitoring", "Verify no persistence on systems the attacker touched"],
    lessons_learned: ["Review network segmentation", "Implement workstation-to-workstation traffic restrictions", "Deploy deception/honeypots for lateral movement detection"],
  },
  {
    id: "data_exfiltration", name: "Data Exfiltration", severity: "critical", priority: 1,
    detection: ["DLP alert for data leaving the network", "Large outbound transfers to unusual destinations", "DNS tunneling indicators (high query volume, long subdomain labels)", "Cloud storage upload alerts"],
    containment: ["Block the exfiltration channel immediately", "Identify the full scope of data exfiltrated", "Preserve all network logs and flow data", "Notify legal counsel"],
    eradication: ["Remove attacker access", "Close the exfiltration path", "Patch exploited vulnerabilities"],
    recovery: ["Assess regulatory notification requirements", "Implement enhanced DLP controls", "Monitor for continued exfiltration attempts"],
    lessons_learned: ["Review DLP policy coverage", "Assess network monitoring capabilities", "Evaluate data classification effectiveness"],
  },
  {
    id: "dns_hijack", name: "DNS Hijacking", severity: "high", priority: 2,
    detection: ["DNS records changed without authorization", "Certificate transparency log showing new certs for your domain", "Users redirected to unknown sites", "DNS monitoring alerts"],
    containment: ["Correct DNS records at the registrar", "Enable registrar lock", "Change registrar account credentials", "Enable DNSSEC"],
    eradication: ["Determine how DNS was modified (registrar compromise, DNS server compromise)", "Secure the registrar account with MFA", "Review all DNS records for unauthorized changes"],
    recovery: ["Verify all DNS records are correct", "Monitor for DNS propagation", "Check for any cached poisoned records"],
    lessons_learned: ["Implement registrar lock and DNSSEC", "Review registrar account security", "Monitor DNS changes proactively"],
  },
  {
    id: "cloud_compromise", name: "Cloud Account Compromise", severity: "critical", priority: 1,
    detection: ["CloudTrail/Activity Log showing unusual API calls", "New IAM users or roles created", "Compute instances launched in unusual regions", "Access key usage from unusual IP", "Cost anomaly alerts"],
    containment: ["Disable compromised IAM credentials/access keys", "Terminate unauthorized resources (EC2, VMs, functions)", "Apply restrictive SCP/policy to the account", "Enable CloudTrail/audit logging if not already active"],
    eradication: ["Remove unauthorized IAM entities", "Rotate all access keys and secrets", "Review and remove malicious policies", "Check for Lambda/function backdoors"],
    recovery: ["Restore original IAM configuration", "Verify no remaining unauthorized access", "Review all cloud resources for modifications"],
    lessons_learned: ["Review IAM policies (least privilege)", "Implement cloud security posture management (CSPM)", "Set up cost alerts and resource quotas"],
  },
  {
    id: "container_escape", name: "Container Escape", severity: "critical", priority: 1,
    detection: ["Unusual processes running on container host", "Container breakout indicators in audit logs", "Host filesystem access from container", "Unexpected privileged container creation"],
    containment: ["Stop the compromised container", "Isolate the container host from the network", "Preserve container image and runtime state"],
    eradication: ["Identify the escape method (docker socket, privileged mode, kernel exploit)", "Patch the host kernel if kernel exploit was used", "Remove malicious containers and images"],
    recovery: ["Rebuild container host from clean image", "Deploy containers with hardened configurations", "Implement pod security policies/standards"],
    lessons_learned: ["Review container security policies", "Audit privileged container usage", "Consider gVisor/Kata for workload isolation"],
  },
  {
    id: "zero_day", name: "Zero-Day Exploitation", severity: "critical", priority: 1,
    detection: ["Vendor advisory about actively exploited vulnerability", "EDR behavioral detection of unknown exploit", "Threat intelligence report about zero-day in your stack", "Unusual crash patterns in affected software"],
    containment: ["Apply vendor-provided mitigations/workarounds immediately", "Isolate or disable affected systems if no mitigation available", "Increase monitoring on potentially affected systems", "Block known exploitation indicators"],
    eradication: ["Apply the official patch as soon as available", "Scan for indicators of compromise specific to the zero-day", "Reset credentials on systems where exploitation occurred"],
    recovery: ["Verify systems are patched and clean", "Monitor for exploitation attempts against the patched vulnerability"],
    lessons_learned: ["Review vulnerability management process speed", "Assess virtual patching capabilities (WAF, IPS)", "Evaluate threat intelligence integration"],
  },
];

export function getPlaybook(incidentType) {
  return IR_PLAYBOOKS.find((p) => p.id === incidentType) || null;
}

export function getPlaybooksByPriority() {
  return [...IR_PLAYBOOKS].sort((a, b) => a.priority - b.priority);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTAINMENT ACTIONS LIBRARY
// ═══════════════════════════════════════════════════════════════════════════════

export const CONTAINMENT_ACTIONS = {
  network_isolation: {
    windows: [
      { action: "Disable network adapter", command: "netsh interface set interface \"Ethernet\" disable", description: "Immediately cuts network connectivity" },
      { action: "Block all outbound traffic", command: "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound", description: "Windows Firewall blocks everything" },
      { action: "Allow only specific IP (SIEM/forensics)", command: "netsh advfirewall firewall add rule name=\"Allow SIEM\" dir=out action=allow remoteip=10.0.0.50", description: "Allow communication to forensics server only" },
    ],
    linux: [
      { action: "Drop all traffic except SSH from forensics", command: "iptables -P INPUT DROP && iptables -P OUTPUT DROP && iptables -P FORWARD DROP && iptables -A INPUT -s 10.0.0.50 -p tcp --dport 22 -j ACCEPT && iptables -A OUTPUT -d 10.0.0.50 -p tcp --sport 22 -j ACCEPT", description: "Isolate system, allow only forensics SSH" },
      { action: "Disable network interface", command: "ip link set eth0 down", description: "Immediately disconnect from network" },
    ],
  },
  account_lockout: {
    active_directory: [
      { action: "Disable AD account", command: "Disable-ADAccount -Identity compromised_user", description: "Disables the account in Active Directory" },
      { action: "Reset password and require change", command: "Set-ADAccountPassword -Identity compromised_user -Reset -NewPassword (ConvertTo-SecureString 'TempP@ss123!' -AsPlainText -Force) && Set-ADUser -Identity compromised_user -ChangePasswordAtLogon $true", description: "Force password reset" },
      { action: "Remove from all groups", command: "Get-ADUser compromised_user -Properties MemberOf | ForEach { $_.MemberOf | Remove-ADGroupMember -Members compromised_user -Confirm:$false }", description: "Strip all group memberships" },
    ],
    cloud: [
      { action: "AWS — Disable access keys", command: "aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive --user-name compromised_user", description: "Disable AWS access keys" },
      { action: "Azure — Block sign-in", command: "Set-AzureADUser -ObjectId user@domain.com -AccountEnabled $false", description: "Block Azure AD sign-in" },
      { action: "GCP — Disable service account", command: "gcloud iam service-accounts disable SA_EMAIL", description: "Disable GCP service account" },
    ],
  },
  firewall_blocks: {
    iptables: [
      { action: "Block specific IP", command: "iptables -I INPUT -s ATTACKER_IP -j DROP && iptables -I OUTPUT -d ATTACKER_IP -j DROP", description: "Block attacker IP in both directions" },
      { action: "Block port range", command: "iptables -A INPUT -p tcp --dport 4444:4450 -j DROP", description: "Block common C2 ports" },
      { action: "Block country (using ipset)", command: "ipset create BLOCK_COUNTRY hash:net && ipset add BLOCK_COUNTRY CIDR_RANGE && iptables -I INPUT -m set --match-set BLOCK_COUNTRY src -j DROP", description: "Geo-block via ipset" },
    ],
    windows_firewall: [
      { action: "Block IP", command: "netsh advfirewall firewall add rule name=\"Block Attacker\" dir=in action=block remoteip=ATTACKER_IP", description: "Block attacker IP on Windows" },
      { action: "Block port", command: "netsh advfirewall firewall add rule name=\"Block C2\" dir=out action=block protocol=TCP localport=4444", description: "Block outbound C2 port" },
    ],
    aws_security_group: [
      { action: "Revoke all ingress", command: "aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol all --cidr 0.0.0.0/0", description: "Remove all inbound rules from a security group" },
    ],
    azure_nsg: [
      { action: "Block IP", command: "az network nsg rule create --resource-group RG --nsg-name NSG --name BlockAttacker --priority 100 --direction Inbound --access Deny --source-address-prefixes ATTACKER_IP --destination-port-ranges '*' --protocol '*'", description: "Block IP in Azure NSG" },
    ],
  },
  dns_sinkhole: [
    { action: "Sinkhole domain (BIND)", command: "zone \"malicious-domain.com\" { type master; file \"/etc/bind/db.sinkhole\"; };", description: "Redirect malicious domain to sinkhole" },
    { action: "Sinkhole (Pi-hole)", command: "pihole -b malicious-domain.com", description: "Block domain via Pi-hole" },
    { action: "Sinkhole (Windows DNS)", command: "Add-DnsServerZone -Name malicious-domain.com -ZoneFile sinkhole.dns", description: "Create a sinkhole zone in Windows DNS" },
  ],
};

// ═══════════════════════════════════════════════════════════════════════════════
// WINDOWS FORENSIC ARTIFACT DATABASE
// ═══════════════════════════════════════════════════════════════════════════════

export const WINDOWS_ARTIFACTS = [
  { category: "Registry - Persistence", artifacts: [
    { name: "Run Keys", path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", description: "Programs that run at every logon for all users" },
    { name: "RunOnce Keys", path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", description: "Programs that run once at next logon then self-delete" },
    { name: "User Run Keys", path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", description: "Per-user autostart programs" },
    { name: "Services", path: "HKLM\\SYSTEM\\CurrentControlSet\\Services", description: "All registered Windows services — check for malicious entries" },
    { name: "Winlogon", path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", description: "Shell, Userinit values — modified for persistence" },
    { name: "Active Setup", path: "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components", description: "Commands run once per user profile — used for persistence" },
    { name: "BootExecute", path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute", description: "Programs run during boot before Windows fully loads" },
    { name: "AppInit DLLs", path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs", description: "DLLs loaded into every process that loads user32.dll" },
    { name: "Image File Execution Options", path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", description: "Debugger hijacking — redirects execution of a binary" },
    { name: "Print Monitors", path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", description: "DLLs loaded by the print spooler service" },
    { name: "LSA Packages", path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", description: "Security packages, authentication packages — SSP injection target" },
  ]},
  { category: "Registry - User Activity", artifacts: [
    { name: "UserAssist", path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist", description: "ROT13-encoded list of programs executed by the user with run counts and last run time" },
    { name: "RecentDocs", path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", description: "Recently opened documents by extension" },
    { name: "TypedPaths", path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", description: "Paths typed in Explorer address bar" },
    { name: "TypedURLs", path: "HKCU\\SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs", description: "URLs typed in Internet Explorer address bar" },
    { name: "WordWheelQuery", path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery", description: "Search terms entered in Explorer" },
    { name: "MountPoints2", path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2", description: "USB devices and network shares the user connected to" },
    { name: "ComDlg32 MRU", path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32", description: "Open/Save dialog most recently used files and locations" },
  ]},
  { category: "Registry - System", artifacts: [
    { name: "ShimCache (AppCompatCache)", path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache", description: "Evidence of program execution — file path, size, last modified time" },
    { name: "Amcache.hve", path: "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", description: "Program execution evidence including SHA1 hash, path, publisher" },
    { name: "BAM/DAM", path: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings", description: "Background Activity Moderator — execution timestamps per user" },
    { name: "NetworkList", path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList", description: "List of networks the system has connected to with timestamps" },
    { name: "USB Device History", path: "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", description: "All USB storage devices ever connected — serial number, vendor, product" },
    { name: "TimeZone", path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation", description: "System timezone — important for correlating timestamps" },
  ]},
  { category: "Event Logs", artifacts: [
    { name: "Successful Logon", event_id: 4624, log: "Security", description: "Account successfully logged on — check Logon Type (2=interactive, 3=network, 10=RDP)" },
    { name: "Failed Logon", event_id: 4625, log: "Security", description: "Failed logon attempt — brute force indicator when many from same source" },
    { name: "Explicit Credential Logon", event_id: 4648, log: "Security", description: "Logon using explicit credentials (RunAs, accessing network resource with different creds)" },
    { name: "Special Privileges Assigned", event_id: 4672, log: "Security", description: "Admin privileges assigned to a logon session — privilege escalation indicator" },
    { name: "Process Creation", event_id: 4688, log: "Security", description: "New process created — requires command-line auditing for full context" },
    { name: "Service Installed", event_id: 7045, log: "System", description: "New service installed — persistence mechanism indicator" },
    { name: "Service Installed (Security)", event_id: 4697, log: "Security", description: "Service installed — similar to 7045 but in Security log" },
    { name: "Scheduled Task Created", event_id: 4698, log: "Security", description: "New scheduled task created — persistence/execution indicator" },
    { name: "User Account Created", event_id: 4720, log: "Security", description: "New user account created — check for unauthorized account creation" },
    { name: "User Account Deleted", event_id: 4726, log: "Security", description: "User account deleted — potential evidence destruction" },
    { name: "Audit Log Cleared", event_id: 1102, log: "Security", description: "Security audit log was cleared — anti-forensics indicator" },
    { name: "System Log Cleared", event_id: 104, log: "System", description: "System event log was cleared" },
    { name: "PowerShell Script Block", event_id: 4104, log: "Microsoft-Windows-PowerShell/Operational", description: "PowerShell script block logging — captures actual script content" },
    { name: "PowerShell Module Load", event_id: 4103, log: "Microsoft-Windows-PowerShell/Operational", description: "PowerShell module loaded — detects Invoke-Mimikatz, etc." },
    { name: "WMI Activity", event_id: 5861, log: "Microsoft-Windows-WMI-Activity/Operational", description: "WMI event subscription — persistence via WMI" },
    { name: "RDP Session Connect", event_id: 1149, log: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", description: "RDP connection from source IP — lateral movement indicator" },
    { name: "Task Scheduler", event_id: 106, log: "Microsoft-Windows-TaskScheduler/Operational", description: "Scheduled task registered — persistence indicator" },
    { name: "Firewall Rule Change", event_id: 2004, log: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", description: "Firewall rule added — defense evasion" },
    { name: "Kerberos TGT Request", event_id: 4768, log: "Security", description: "Kerberos AS-REQ — authentication events, AS-REP roasting indicator" },
    { name: "Kerberos Service Ticket", event_id: 4769, log: "Security", description: "Kerberos TGS-REQ — Kerberoasting indicator when many from one user" },
    { name: "Account Lockout", event_id: 4740, log: "Security", description: "User account was locked out — brute force indicator" },
    { name: "Security Group Changed", event_id: 4735, log: "Security", description: "Security-enabled local group changed — privilege escalation" },
    { name: "Password Change Attempt", event_id: 4723, log: "Security", description: "User attempted to change their password" },
    { name: "Password Reset", event_id: 4724, log: "Security", description: "Password was reset by another user — could be attacker" },
    { name: "Object Access", event_id: 4663, log: "Security", description: "An attempt was made to access an object — file/registry access auditing" },
  ]},
  { category: "Filesystem", artifacts: [
    { name: "Prefetch", path: "C:\\Windows\\Prefetch\\", description: "Evidence of program execution — timestamps, run count, referenced files" },
    { name: "$MFT", path: "C:\\$MFT", description: "Master File Table — metadata for every file on NTFS volume including deleted files" },
    { name: "$UsnJrnl", path: "C:\\$Extend\\$UsnJrnl", description: "USN Journal — filesystem change journal, tracks file creates/deletes/renames" },
    { name: "$LogFile", path: "C:\\$LogFile", description: "NTFS transaction log — can recover recently deleted or modified files" },
    { name: "Recycle Bin", path: "C:\\$Recycle.Bin\\{SID}\\", description: "Deleted files with original path and deletion timestamp" },
    { name: "Jump Lists", path: "%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\", description: "Recently and frequently accessed files per application" },
    { name: "Shellbags", path: "HKCU\\Software\\Microsoft\\Windows\\Shell\\BagMRU", description: "Evidence of folder access — even if folder no longer exists" },
    { name: "LNK Files", path: "%APPDATA%\\Microsoft\\Windows\\Recent\\", description: "Shortcut files — contain target path, MAC timestamps, volume info" },
    { name: "Thumbcache", path: "%LocalAppData%\\Microsoft\\Windows\\Explorer\\thumbcache_*.db", description: "Thumbnail database — proves images existed even if deleted" },
    { name: "RDP Bitmap Cache", path: "%LocalAppData%\\Microsoft\\Terminal Server Client\\Cache\\", description: "Cached RDP session bitmaps — can reconstruct what was displayed" },
    { name: "SRUM Database", path: "C:\\Windows\\System32\\sru\\SRUDB.dat", description: "System Resource Usage Monitor — network usage, app usage per-process for 60 days" },
    { name: "Windows.edb", path: "C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb", description: "Windows Search index — contains file contents and metadata even for deleted files" },
  ]},
];

// ═══════════════════════════════════════════════════════════════════════════════
// LINUX FORENSIC ARTIFACT DATABASE
// ═══════════════════════════════════════════════════════════════════════════════

export const LINUX_ARTIFACTS = [
  { category: "Log Files", artifacts: [
    { name: "auth.log / secure", path: "/var/log/auth.log (Debian) or /var/log/secure (RHEL)", description: "Authentication events: SSH logins, sudo usage, su commands, PAM events" },
    { name: "syslog / messages", path: "/var/log/syslog or /var/log/messages", description: "General system events, kernel messages, service activity" },
    { name: "wtmp", path: "/var/log/wtmp", description: "Login/logout records (use 'last' command to read)" },
    { name: "btmp", path: "/var/log/btmp", description: "Failed login attempts (use 'lastb' command to read)" },
    { name: "lastlog", path: "/var/log/lastlog", description: "Last login time for each user (use 'lastlog' command)" },
    { name: "kern.log", path: "/var/log/kern.log", description: "Kernel messages — USB connections, driver loads, kernel panics" },
    { name: "cron.log", path: "/var/log/cron or /var/log/syslog (grep CRON)", description: "Cron job execution logs" },
    { name: "dpkg.log / yum.log", path: "/var/log/dpkg.log or /var/log/yum.log", description: "Package installation/removal history" },
    { name: "apache/nginx access", path: "/var/log/apache2/access.log or /var/log/nginx/access.log", description: "Web server access logs — IPs, URLs, user agents" },
    { name: "audit.log", path: "/var/log/audit/audit.log", description: "Linux Audit Framework logs — syscall auditing, file access, execve" },
    { name: "journal", path: "journalctl", description: "Systemd journal — structured logging for all systemd services" },
  ]},
  { category: "User Activity", artifacts: [
    { name: "bash_history", path: "~/.bash_history", description: "Command history for each user (also .zsh_history, .python_history)" },
    { name: ".ssh/authorized_keys", path: "~/.ssh/authorized_keys", description: "SSH public keys authorized for login — check for unauthorized keys" },
    { name: ".ssh/known_hosts", path: "~/.ssh/known_hosts", description: "SSH servers the user has connected to — lateral movement evidence" },
    { name: ".ssh/config", path: "~/.ssh/config", description: "SSH client configuration — may reveal tunnels and port forwards" },
    { name: ".gnupg/", path: "~/.gnupg/", description: "GPG keyring — encryption keys used by the user" },
    { name: "Desktop files", path: "~/.local/share/recently-used.xbel", description: "Recently accessed files in the desktop environment" },
    { name: ".viminfo", path: "~/.viminfo", description: "Vim editor history — files edited, search patterns, commands" },
    { name: ".wget-hsts", path: "~/.wget-hsts", description: "Websites downloaded with wget — evidence of tool/malware downloads" },
    { name: ".mysql_history", path: "~/.mysql_history", description: "MySQL command history — database queries executed" },
  ]},
  { category: "System Configuration", artifacts: [
    { name: "crontab", path: "/etc/crontab and /var/spool/cron/crontabs/", description: "Scheduled tasks — check for malicious cron entries" },
    { name: "systemd services", path: "/etc/systemd/system/ and /lib/systemd/system/", description: "Systemd service unit files — persistence mechanism" },
    { name: "systemd timers", path: "/etc/systemd/system/*.timer", description: "Systemd timer units — scheduled execution" },
    { name: "/etc/passwd", path: "/etc/passwd", description: "User accounts — check for unauthorized users, UID 0 accounts" },
    { name: "/etc/shadow", path: "/etc/shadow", description: "Password hashes — check for recently changed passwords" },
    { name: "/etc/group", path: "/etc/group", description: "Group membership — check for unauthorized group additions" },
    { name: "/etc/sudoers", path: "/etc/sudoers and /etc/sudoers.d/", description: "Sudo configuration — check for privilege escalation entries" },
    { name: "/etc/rc.local", path: "/etc/rc.local", description: "Startup script — persistence location" },
    { name: "/etc/hosts", path: "/etc/hosts", description: "DNS overrides — check for DNS hijacking" },
    { name: "/etc/resolv.conf", path: "/etc/resolv.conf", description: "DNS server configuration — may be modified for DNS hijacking" },
    { name: "LD_PRELOAD", path: "/etc/ld.so.preload and LD_PRELOAD env var", description: "Library preloading — used for rootkit-style interception" },
    { name: "PAM config", path: "/etc/pam.d/", description: "PAM authentication configuration — persistence and credential theft" },
    { name: "inetd/xinetd", path: "/etc/inetd.conf or /etc/xinetd.d/", description: "Network daemon configuration — backdoor services" },
  ]},
  { category: "Process & Network", artifacts: [
    { name: "/proc/*/cmdline", path: "/proc/PID/cmdline", description: "Command line of running processes" },
    { name: "/proc/*/exe", path: "/proc/PID/exe", description: "Symlink to the executable — even if deleted from disk" },
    { name: "/proc/*/fd", path: "/proc/PID/fd/", description: "Open file descriptors — network connections, open files" },
    { name: "/proc/*/maps", path: "/proc/PID/maps", description: "Memory mappings — detect injected libraries" },
    { name: "/proc/*/environ", path: "/proc/PID/environ", description: "Environment variables of the process" },
    { name: "Network connections", path: "/proc/net/tcp and /proc/net/udp", description: "Current network connections — detect C2 and backdoors" },
    { name: "/tmp artifacts", path: "/tmp/ and /var/tmp/ and /dev/shm/", description: "Temporary files — common malware staging locations" },
  ]},
];

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT HUNTING QUERIES (Splunk SPL)
// ═══════════════════════════════════════════════════════════════════════════════

export const THREAT_HUNTING_QUERIES = [
  // Credential Access
  { id: "TH001", category: "Credential Access", hypothesis: "Kerberoasting — mass TGS requests for service tickets", query: 'index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 | stats count by Account_Name, Service_Name | where count > 5 | sort -count', description: "Detects RC4-encrypted TGS requests (Kerberoasting uses RC4 downgrade)", mitre: "T1558.003" },
  { id: "TH002", category: "Credential Access", hypothesis: "LSASS memory access — credential dumping attempt", query: 'index=sysmon EventCode=10 TargetImage="*lsass.exe" NOT SourceImage IN ("*\\MsMpEng.exe","*\\csrss.exe","*\\wmiprvse.exe") | stats count by SourceImage, SourceUser | sort -count', description: "Detects non-standard processes accessing LSASS memory", mitre: "T1003.001" },
  { id: "TH003", category: "Credential Access", hypothesis: "DCSync replication from non-DC", query: 'index=wineventlog EventCode=4662 Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" | stats count by SubjectUserName, SubjectDomainName | where NOT SubjectUserName LIKE "%$"', description: "Detects directory replication (DCSync) from non-machine accounts", mitre: "T1003.006" },
  { id: "TH004", category: "Credential Access", hypothesis: "Password spraying — single password against many accounts", query: 'index=wineventlog EventCode=4625 | bin _time span=5m | stats dc(TargetUserName) as unique_users count by _time, IpAddress | where unique_users > 10', description: "Multiple failed logins to different accounts from same source in short period", mitre: "T1110.003" },
  { id: "TH005", category: "Credential Access", hypothesis: "Credential dumping via registry — SAM/SECURITY hive access", query: 'index=sysmon EventCode=1 (CommandLine="*reg save*" OR CommandLine="*reg.exe save*") (CommandLine="*HKLM\\SAM*" OR CommandLine="*HKLM\\SECURITY*" OR CommandLine="*HKLM\\SYSTEM*")', description: "Detects registry hive export (SAM database extraction)", mitre: "T1003.002" },
  { id: "TH006", category: "Credential Access", hypothesis: "Mimikatz detection via command arguments", query: 'index=sysmon EventCode=1 (CommandLine="*sekurlsa*" OR CommandLine="*kerberos::*" OR CommandLine="*lsadump::*" OR CommandLine="*crypto::*" OR CommandLine="*dpapi::*" OR CommandLine="*privilege::debug*")', description: "Detects common Mimikatz command arguments", mitre: "T1003" },
  { id: "TH007", category: "Credential Access", hypothesis: "AS-REP roasting — pre-auth disabled accounts", query: 'index=wineventlog EventCode=4768 Pre_Authentication_Type=0 | stats count by Account_Name, Client_Address | where count > 3', description: "Kerberos AS requests without pre-authentication", mitre: "T1558.004" },
  { id: "TH008", category: "Credential Access", hypothesis: "NTDS.dit extraction via ntdsutil", query: 'index=sysmon EventCode=1 (CommandLine="*ntdsutil*" OR CommandLine="*vssadmin*create shadow*" OR CommandLine="*esentutl*" OR Image="*\\ntdsutil.exe")', description: "Detects Active Directory database extraction attempts", mitre: "T1003.003" },

  // Lateral Movement
  { id: "TH010", category: "Lateral Movement", hypothesis: "PsExec lateral movement", query: 'index=wineventlog EventCode=7045 Service_Name="PSEXESVC" OR (EventCode=1 Image="*\\PSEXESVC.exe") | stats count by ComputerName, Account_Name | sort -count', description: "Detects PsExec service installation on remote hosts", mitre: "T1021.002" },
  { id: "TH011", category: "Lateral Movement", hypothesis: "Workstation-to-workstation lateral movement via SMB", query: 'index=wineventlog EventCode=4624 Logon_Type=3 Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" | eval src_class=if(like(Source_Network_Address,"10.%") OR like(Source_Network_Address,"192.168.%"),"internal","external") | where src_class="internal" | stats count by Source_Network_Address, Workstation_Name, Account_Name | where count > 1', description: "Detects network logons between internal workstations", mitre: "T1021.002" },
  { id: "TH012", category: "Lateral Movement", hypothesis: "WMI-based lateral movement", query: 'index=sysmon EventCode=1 Image="*\\WmiPrvSE.exe" ParentImage!="*\\svchost.exe" | stats count by ParentImage, CommandLine', description: "Detects WMI process creation from unusual parents", mitre: "T1047" },
  { id: "TH013", category: "Lateral Movement", hypothesis: "RDP brute force or lateral movement", query: 'index=wineventlog source="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" EventCode=1149 | stats count by param1, Source_Network_Address | sort -count', description: "RDP connections — high count from single source indicates brute force", mitre: "T1021.001" },
  { id: "TH014", category: "Lateral Movement", hypothesis: "Pass-the-Hash — NTLM logon type 3 with admin accounts", query: 'index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM | search Account_Name!="ANONYMOUS LOGON" Account_Name!="*$" | stats count by Account_Name, Source_Network_Address, Workstation_Name | sort -count', description: "Detects NTLM network logons which may indicate Pass-the-Hash", mitre: "T1550.002" },

  // Persistence
  { id: "TH020", category: "Persistence", hypothesis: "New Windows service created for persistence", query: 'index=wineventlog EventCode=7045 | where NOT Service_Name LIKE "Windows%" AND NOT Service_Name LIKE "Microsoft%" | stats count by Service_Name, Service_File_Name, Account_Name', description: "New services that aren't from Microsoft", mitre: "T1543.003" },
  { id: "TH021", category: "Persistence", hypothesis: "Scheduled task created for persistence", query: 'index=wineventlog EventCode=4698 | stats count by SubjectUserName, TaskName | table SubjectUserName, TaskName', description: "New scheduled tasks — check for suspicious names and command lines", mitre: "T1053.005" },
  { id: "TH022", category: "Persistence", hypothesis: "Registry Run key modification", query: 'index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*" | stats count by Image, TargetObject, Details | sort -count', description: "Detects modifications to autostart registry keys", mitre: "T1547.001" },
  { id: "TH023", category: "Persistence", hypothesis: "WMI event subscription persistence", query: 'index=sysmon EventCode=19 OR EventCode=20 OR EventCode=21 | stats count by EventType, Operation, User', description: "Detects WMI event filter/consumer/binding creation", mitre: "T1546.003" },
  { id: "TH024", category: "Persistence", hypothesis: "Web shell deployment", query: 'index=sysmon EventCode=11 (TargetFilename="*\\inetpub\\*" OR TargetFilename="*\\wwwroot\\*" OR TargetFilename="*\\htdocs\\*") (TargetFilename="*.aspx" OR TargetFilename="*.php" OR TargetFilename="*.jsp")', description: "New files in web directories — potential web shell", mitre: "T1505.003" },
  { id: "TH025", category: "Persistence", hypothesis: "SSH authorized_keys modification", query: 'index=linux sourcetype=linux:audit type=PATH name="*authorized_keys*" | stats count by hostname, auid', description: "Detects SSH authorized_keys file modifications", mitre: "T1098.004" },
  { id: "TH026", category: "Persistence", hypothesis: "Crontab modification for persistence", query: 'index=linux ("crontab -e" OR "crontab -l" OR "/etc/cron" OR "/var/spool/cron") | stats count by host, user', description: "Detects cron job modifications", mitre: "T1053.003" },
  { id: "TH027", category: "Persistence", hypothesis: "New user account created", query: 'index=wineventlog EventCode=4720 | stats count by SubjectUserName, TargetUserName | sort -count', description: "New user accounts created — check for unauthorized creation", mitre: "T1136.001" },

  // Execution
  { id: "TH030", category: "Execution", hypothesis: "Encoded PowerShell execution", query: 'index=sysmon EventCode=1 Image="*\\powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-e *" OR CommandLine="*FromBase64*")', description: "Detects base64-encoded PowerShell — common malware technique", mitre: "T1059.001" },
  { id: "TH031", category: "Execution", hypothesis: "PowerShell download cradle", query: 'index=sysmon EventCode=1 Image="*\\powershell.exe" (CommandLine="*Invoke-WebRequest*" OR CommandLine="*wget*" OR CommandLine="*curl*" OR CommandLine="*Net.WebClient*" OR CommandLine="*DownloadString*" OR CommandLine="*DownloadFile*" OR CommandLine="*iwr*" OR CommandLine="*Invoke-RestMethod*")', description: "Detects PowerShell downloading files from the internet", mitre: "T1059.001" },
  { id: "TH032", category: "Execution", hypothesis: "LOLBin execution — mshta, certutil, bitsadmin", query: 'index=sysmon EventCode=1 (Image="*\\mshta.exe" OR Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe" OR Image="*\\cmstp.exe" OR Image="*\\msiexec.exe" OR Image="*\\regsvr32.exe") | stats count by Image, ParentImage, CommandLine', description: "Detects living-off-the-land binary execution", mitre: "T1218" },
  { id: "TH033", category: "Execution", hypothesis: "Unusual parent-child process relationships", query: 'index=sysmon EventCode=1 | search (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\powerpnt.exe") (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe")', description: "Office applications spawning script interpreters — macro execution indicator", mitre: "T1204.002" },
  { id: "TH034", category: "Execution", hypothesis: "Certutil used for file download or encoding", query: 'index=sysmon EventCode=1 Image="*\\certutil.exe" (CommandLine="*-urlcache*" OR CommandLine="*-decode*" OR CommandLine="*-encode*")', description: "Certutil abused for downloading or encoding/decoding payloads", mitre: "T1105" },
  { id: "TH035", category: "Execution", hypothesis: "Rundll32 loading DLL from unusual location", query: 'index=sysmon EventCode=1 Image="*\\rundll32.exe" NOT CommandLine="*\\System32\\*" NOT CommandLine="*\\SysWOW64\\*" | stats count by CommandLine, ParentImage', description: "Rundll32 loading DLLs from non-standard locations", mitre: "T1218.011" },

  // Defense Evasion
  { id: "TH040", category: "Defense Evasion", hypothesis: "Event log cleared — anti-forensics", query: 'index=wineventlog (EventCode=1102 OR EventCode=104) | stats count by ComputerName, Account_Name', description: "Security or System event log was cleared", mitre: "T1070.001" },
  { id: "TH041", category: "Defense Evasion", hypothesis: "Timestomping — MACE timestamp manipulation", query: 'index=sysmon EventCode=2 | eval time_diff=abs(CreationUtcTime-PreviousCreationUtcTime) | where time_diff > 86400 | stats count by Image, TargetFilename', description: "File creation timestamp changed — timestomping indicator", mitre: "T1070.006" },
  { id: "TH042", category: "Defense Evasion", hypothesis: "Disable Windows Defender", query: 'index=sysmon EventCode=1 (CommandLine="*Set-MpPreference*DisableRealtimeMonitoring*" OR CommandLine="*sc stop WinDefend*" OR CommandLine="*sc config WinDefend start= disabled*")', description: "Attempts to disable Windows Defender", mitre: "T1562.001" },
  { id: "TH043", category: "Defense Evasion", hypothesis: "Process masquerading — name mismatch", query: 'index=sysmon EventCode=1 | eval proc_name=lower(mvindex(split(Image,"\\"),-1)) | eval parent_name=lower(mvindex(split(ParentImage,"\\"),-1)) | where (proc_name="svchost.exe" AND NOT like(ParentImage,"%\\services.exe")) OR (proc_name="csrss.exe" AND NOT like(ParentImage,"%\\smss.exe"))', description: "System processes launched by unexpected parents", mitre: "T1036.005" },
  { id: "TH044", category: "Defense Evasion", hypothesis: "Firewall rule modification", query: 'index=wineventlog EventCode=2004 OR (EventCode=1 CommandLine="*netsh advfirewall*") | stats count by ComputerName, Account_Name', description: "Windows Firewall rules modified — defense evasion", mitre: "T1562.004" },
  { id: "TH045", category: "Defense Evasion", hypothesis: "Audit policy change", query: 'index=wineventlog EventCode=4719 | stats count by SubjectUserName, CategoryId, SubcategoryGuid', description: "Audit policy changed — may disable logging", mitre: "T1562.002" },

  // Exfiltration
  { id: "TH050", category: "Exfiltration", hypothesis: "DNS tunneling — high volume long queries", query: 'index=dns | eval query_len=len(query) | where query_len > 50 | stats count avg(query_len) as avg_len by src_ip, query_domain | where count > 100 AND avg_len > 40', description: "DNS queries with unusually long labels — DNS tunneling indicator", mitre: "T1048.003" },
  { id: "TH051", category: "Exfiltration", hypothesis: "Large outbound data transfer", query: 'index=network sourcetype=firewall action=allowed direction=outbound | stats sum(bytes_out) as total_bytes by src_ip, dest_ip | where total_bytes > 104857600 | sort -total_bytes', description: "Single source sending >100MB outbound — exfiltration indicator", mitre: "T1041" },
  { id: "TH052", category: "Exfiltration", hypothesis: "Data staging — archive creation before exfiltration", query: 'index=sysmon EventCode=1 (Image="*\\7z.exe" OR Image="*\\rar.exe" OR Image="*\\zip.exe" OR CommandLine="*Compress-Archive*" OR CommandLine="*tar *" OR CommandLine="*makecab*")', description: "Archive tools used — potential data staging for exfiltration", mitre: "T1560.001" },
  { id: "TH053", category: "Exfiltration", hypothesis: "Cloud storage upload for exfiltration", query: 'index=proxy (dest_host="*dropbox.com*" OR dest_host="*drive.google.com*" OR dest_host="*onedrive.live.com*" OR dest_host="*mega.nz*") http_method=POST | stats sum(bytes_out) as upload_bytes by src_ip, dest_host | where upload_bytes > 10485760', description: "Large uploads to cloud storage services", mitre: "T1567.002" },

  // Discovery
  { id: "TH060", category: "Discovery", hypothesis: "Internal reconnaissance — enumeration commands", query: 'index=sysmon EventCode=1 (CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*net group*" OR CommandLine="*nltest*" OR CommandLine="*systeminfo*" OR CommandLine="*gpresult*" OR CommandLine="*net localgroup*" OR CommandLine="*dsquery*" OR CommandLine="*arp -a*" OR CommandLine="*ipconfig /all*" OR CommandLine="*netstat -an*") | stats count by User, CommandLine | sort -count', description: "Multiple reconnaissance commands from a single user — post-compromise discovery", mitre: "T1087" },
  { id: "TH061", category: "Discovery", hypothesis: "BloodHound/SharpHound data collection", query: 'index=sysmon EventCode=1 (CommandLine="*SharpHound*" OR CommandLine="*Invoke-BloodHound*" OR CommandLine="*-CollectionMethod*" OR Image="*\\SharpHound.exe")', description: "BloodHound data collection — AD attack path enumeration", mitre: "T1087.002" },
  { id: "TH062", category: "Discovery", hypothesis: "Port scanning from internal system", query: 'index=network sourcetype=firewall direction=outbound | stats dc(dest_port) as unique_ports count by src_ip | where unique_ports > 100', description: "Internal system connecting to many ports — port scan indicator", mitre: "T1046" },

  // Command and Control
  { id: "TH070", category: "Command and Control", hypothesis: "Beaconing — periodic C2 callbacks", query: 'index=proxy | bucket _time span=1m | stats count by _time, src_ip, dest_host | streamstats count as seq by src_ip, dest_host | eventstats stdev(count) as stddev avg(count) as avg by src_ip, dest_host | where stddev < 1 AND avg > 0 AND seq > 60 | stats values(dest_host) by src_ip', description: "Detect regular-interval callbacks to same host — C2 beaconing pattern", mitre: "T1071.001" },
  { id: "TH071", category: "Command and Control", hypothesis: "Connections to newly registered domains", query: 'index=proxy | lookup domain_age_lookup dest_host OUTPUT domain_age | where domain_age < 30 | stats count by src_ip, dest_host, domain_age', description: "Traffic to domains registered in the last 30 days", mitre: "T1583.001" },
  { id: "TH072", category: "Command and Control", hypothesis: "DGA domain detection — high entropy domain names", query: 'index=dns | eval entropy=0 | eval query_stripped=replace(query,"\\..*$","") | eval qlen=len(query_stripped) | where qlen > 10 AND match(query_stripped,"^[a-z0-9]{10,}$") | stats count by query, src_ip | where count > 5', description: "Algorithmically generated domain names — C2 indicator", mitre: "T1568.002" },
  { id: "TH073", category: "Command and Control", hypothesis: "Tor exit node connections", query: 'index=proxy | lookup tor_exit_nodes dest_ip OUTPUT is_tor | where is_tor=1 | stats count by src_ip, dest_ip', description: "Connections to known Tor exit nodes — anonymization attempt", mitre: "T1090.003" },
  { id: "TH074", category: "Command and Control", hypothesis: "Self-signed certificate detection", query: 'index=network ssl_issuer=ssl_subject | stats count by src_ip, dest_ip, ssl_subject | sort -count', description: "TLS connections where issuer equals subject — self-signed cert for C2", mitre: "T1573.002" },
];

// ═══════════════════════════════════════════════════════════════════════════════
// COMPLIANCE MAPPER
// ═══════════════════════════════════════════════════════════════════════════════

export const COMPLIANCE_MAPPINGS = [
  { family: "Access Control", nist: "AC-1 to AC-25", iso27001: "A.9", soc2: "CC6.1-CC6.8", pci: "Req 7, 8", hipaa: "164.312(a)(1)", gdpr: "Art. 25, 32" },
  { family: "Audit & Accountability", nist: "AU-1 to AU-16", iso27001: "A.12.4", soc2: "CC7.1-CC7.4", pci: "Req 10", hipaa: "164.312(b)", gdpr: "Art. 30" },
  { family: "Security Assessment", nist: "CA-1 to CA-9", iso27001: "A.18.2", soc2: "CC4.1", pci: "Req 11", hipaa: "164.308(a)(8)", gdpr: "Art. 32" },
  { family: "Configuration Management", nist: "CM-1 to CM-11", iso27001: "A.12.5, A.14.2", soc2: "CC8.1", pci: "Req 2", hipaa: "164.310(a)(2)", gdpr: "Art. 25" },
  { family: "Contingency Planning", nist: "CP-1 to CP-13", iso27001: "A.17", soc2: "A1.1-A1.3", pci: "Req 12.10", hipaa: "164.308(a)(7)", gdpr: "Art. 32" },
  { family: "Identification & Authentication", nist: "IA-1 to IA-12", iso27001: "A.9.2, A.9.4", soc2: "CC6.1", pci: "Req 8", hipaa: "164.312(d)", gdpr: "Art. 32" },
  { family: "Incident Response", nist: "IR-1 to IR-10", iso27001: "A.16", soc2: "CC7.3-CC7.5", pci: "Req 12.10", hipaa: "164.308(a)(6)", gdpr: "Art. 33, 34" },
  { family: "Media Protection", nist: "MP-1 to MP-8", iso27001: "A.8.3", soc2: "CC6.5", pci: "Req 3, 9", hipaa: "164.310(d)(1)", gdpr: "Art. 32" },
  { family: "Physical & Environmental", nist: "PE-1 to PE-23", iso27001: "A.11", soc2: "CC6.4", pci: "Req 9", hipaa: "164.310(a,b,c)", gdpr: "Art. 32" },
  { family: "Planning", nist: "PL-1 to PL-9", iso27001: "A.5", soc2: "CC1.1-CC1.5", pci: "Req 12", hipaa: "164.308(a)(1)", gdpr: "Art. 24" },
  { family: "Personnel Security", nist: "PS-1 to PS-9", iso27001: "A.7", soc2: "CC1.4", pci: "Req 12.7", hipaa: "164.308(a)(3)", gdpr: "Art. 39" },
  { family: "Risk Assessment", nist: "RA-1 to RA-7", iso27001: "A.12.6, A.8.2", soc2: "CC3.1-CC3.4", pci: "Req 6.1, 12.2", hipaa: "164.308(a)(1)(ii)(A)", gdpr: "Art. 35" },
  { family: "System Acquisition", nist: "SA-1 to SA-22", iso27001: "A.14", soc2: "CC8.1", pci: "Req 6", hipaa: "164.308(a)(1)", gdpr: "Art. 25" },
  { family: "System & Comms Protection", nist: "SC-1 to SC-44", iso27001: "A.10, A.13", soc2: "CC6.6-CC6.7", pci: "Req 1, 4", hipaa: "164.312(a)(2)(iv), 164.312(e)", gdpr: "Art. 32" },
  { family: "System & Info Integrity", nist: "SI-1 to SI-19", iso27001: "A.12.2, A.12.6", soc2: "CC7.1-CC7.2", pci: "Req 5, 6", hipaa: "164.308(a)(5)", gdpr: "Art. 32" },
  { family: "Supply Chain Risk", nist: "SR-1 to SR-12", iso27001: "A.15", soc2: "CC9.2", pci: "Req 12.8", hipaa: "164.308(b)(1)", gdpr: "Art. 28" },
  { family: "Privacy / Data Protection", nist: "PT-1 to PT-8", iso27001: "A.18.1", soc2: "P1.1", pci: "Req 3", hipaa: "164.502, 164.514", gdpr: "Art. 5, 6, 7, 9" },
  { family: "Awareness & Training", nist: "AT-1 to AT-6", iso27001: "A.7.2.2", soc2: "CC1.4", pci: "Req 12.6", hipaa: "164.308(a)(5)", gdpr: "Art. 39" },
];

// ═══════════════════════════════════════════════════════════════════════════════
// RISK ASSESSMENT CALCULATOR
// ═══════════════════════════════════════════════════════════════════════════════

const RISK_LABELS = ["Very Low", "Low", "Medium", "High", "Critical"];
const RISK_MATRIX = [
  [1,1,2,2,3], // likelihood 1
  [1,2,2,3,3], // likelihood 2
  [2,2,3,3,4], // likelihood 3
  [2,3,3,4,4], // likelihood 4
  [3,3,4,4,5], // likelihood 5
];

export function calculateRisk(likelihood, impact) {
  const l = Math.max(1, Math.min(5, Math.round(likelihood))) - 1;
  const i = Math.max(1, Math.min(5, Math.round(impact))) - 1;
  const score = RISK_MATRIX[l][i];
  return { score, label: RISK_LABELS[score - 1], likelihood, impact, matrix: "5x5 qualitative" };
}

export function annualizedLossExpectancy(assetValue, exposureFactor, annualRateOfOccurrence) {
  const sle = assetValue * exposureFactor;
  const ale = sle * annualRateOfOccurrence;
  return { singleLossExpectancy: sle, annualizedLossExpectancy: ale, assetValue, exposureFactor, annualRateOfOccurrence };
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMMUNICATION TEMPLATES
// ═══════════════════════════════════════════════════════════════════════════════

export const COMMUNICATION_TEMPLATES = {
  breach_customer: {
    subject: "Important Security Notice from {{company}}",
    body: `Dear {{customer_name}},

We are writing to inform you of a security incident that may have affected your personal information.

What Happened: On {{discovery_date}}, we discovered that {{incident_description}}.

What Information Was Involved: {{data_types}}

What We Are Doing: {{remediation_steps}}

What You Can Do: {{customer_actions}}

For More Information: Please contact us at {{contact_info}} or visit {{incident_page}}.

We sincerely apologize for any inconvenience and are committed to protecting your information.

{{company}} Security Team`,
  },
  breach_regulator: {
    subject: "Data Breach Notification — {{company}} — {{date}}",
    body: `To: {{regulator_name}}

This notification is submitted pursuant to {{regulation}} regarding a data security incident.

Reporting Entity: {{company}}, {{address}}
DPO/Privacy Officer: {{dpo_name}}, {{dpo_contact}}

Date of Discovery: {{discovery_date}}
Date of Incident: {{incident_date}} (estimated)
Number of Individuals Affected: {{affected_count}}

Nature of the Breach: {{breach_type}}
Categories of Data: {{data_categories}}
Likely Consequences: {{consequences}}
Measures Taken: {{measures}}

Contact: {{contact_info}}`,
  },
  internal_escalation: {
    subject: "[SECURITY INCIDENT] {{severity}} — {{incident_type}} — {{date}}",
    body: `SECURITY INCIDENT ESCALATION

Severity: {{severity}}
Type: {{incident_type}}
Status: {{status}}
Incident Commander: {{ic_name}}

Summary: {{summary}}

Impact: {{impact}}

Current Actions: {{current_actions}}

Required Decisions: {{decisions_needed}}

Next Update: {{next_update_time}}

War Room: {{war_room_link}}
Slack Channel: {{slack_channel}}`,
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
// TABLETOP EXERCISE SCENARIOS
// ═══════════════════════════════════════════════════════════════════════════════

export const TABLETOP_SCENARIOS = [
  {
    id: 1, name: "Ransomware Attack on Critical Infrastructure",
    scenario: "It's Monday morning. Multiple employees report they cannot access files. Ransom notes appear demanding 50 BTC. The file server, ERP system, and email are all encrypted. Backups were last verified 3 months ago.",
    injects: [
      { time: "T+0", event: "Help desk receives first call about inaccessible files" },
      { time: "T+15min", event: "IT confirms ransomware on 3 servers and 15 workstations" },
      { time: "T+30min", event: "Ransom note found — 50 BTC demanded, 48-hour deadline" },
      { time: "T+1hr", event: "CEO asks if we should pay the ransom" },
      { time: "T+2hr", event: "Media calls asking about a rumored cyber attack" },
      { time: "T+4hr", event: "Backup team reports last verified backup is 3 months old" },
      { time: "T+8hr", event: "Attacker contacts via email threatening to publish stolen data" },
    ],
    discussion_questions: [
      "At what point do we declare an incident? Who has authority?",
      "What is our communication plan for employees, customers, and media?",
      "Under what circumstances would we consider paying the ransom?",
      "How do we prioritize system recovery?",
      "What are our regulatory notification obligations?",
    ],
  },
  {
    id: 2, name: "Supply Chain Compromise — SolarWinds-style",
    scenario: "Threat intelligence reports that a widely-used IT management tool in your environment has been backdoored. The malicious update was installed 6 months ago. The backdoor provides the attacker with persistent, stealthy access to all systems managed by the tool.",
    injects: [
      { time: "T+0", event: "Vendor advisory received about compromised software update" },
      { time: "T+30min", event: "IT confirms affected version is deployed on 200+ systems" },
      { time: "T+1hr", event: "Security team finds C2 beaconing from 12 systems" },
      { time: "T+2hr", event: "Evidence of lateral movement to domain controllers" },
      { time: "T+4hr", event: "KRBTGT hash may have been compromised (Golden Ticket risk)" },
      { time: "T+8hr", event: "Customer data access logs show anomalous queries over past 3 months" },
    ],
    discussion_questions: [
      "How do we assess the full scope of compromise after 6 months of access?",
      "Do we need to rebuild the entire Active Directory domain?",
      "How do we communicate with the vendor and other affected organizations?",
      "What is our obligation to notify customers whose data may have been accessed?",
      "How do we prevent similar supply chain compromises in the future?",
    ],
  },
  {
    id: 3, name: "Insider Threat — Data Theft by Departing Employee",
    scenario: "HR notifies security that a senior engineer submitted their resignation. They're going to work for a direct competitor. The employee has access to source code, customer lists, and trade secrets. They gave 2 weeks notice.",
    injects: [
      { time: "T+0", event: "HR notification of resignation to competitor" },
      { time: "T+2hr", event: "DLP alert: employee uploaded 2GB to personal Google Drive last night" },
      { time: "T+4hr", event: "Badge logs show employee accessed server room at 11 PM last night" },
      { time: "T+6hr", event: "USB device was connected to their workstation (not company-issued)" },
      { time: "T+8hr", event: "Employee's manager suspects they've been downloading code repos for weeks" },
    ],
    discussion_questions: [
      "What are the legal considerations for monitoring an employee who has resigned?",
      "Should we terminate the employee immediately or continue monitoring?",
      "How do we preserve evidence for potential legal proceedings?",
      "What data can we legally prevent them from taking?",
      "How do we protect our intellectual property going forward?",
    ],
  },
  {
    id: 4, name: "Zero-Day Exploit in Internet-Facing Application",
    scenario: "A zero-day vulnerability is being actively exploited in your primary web application framework. No patch is available. Proof-of-concept exploit code has been published on Twitter. Your application is internet-facing and processes customer PII.",
    injects: [
      { time: "T+0", event: "CVE published with CVSS 9.8, no patch available" },
      { time: "T+30min", event: "PoC exploit code published — trivial to exploit" },
      { time: "T+1hr", event: "WAF vendor releases a virtual patch rule" },
      { time: "T+2hr", event: "Your SOC detects exploitation attempts against your application" },
      { time: "T+4hr", event: "Evidence that one server was compromised before WAF rule deployed" },
    ],
    discussion_questions: [
      "Do we take the application offline? What is the business impact?",
      "How effective are virtual patches (WAF rules) as temporary mitigations?",
      "How do we communicate with customers about potential exposure?",
      "What compensating controls can we implement until a vendor patch is available?",
    ],
  },
  {
    id: 5, name: "Business Email Compromise — $2M Wire Transfer",
    scenario: "The CFO receives an urgent email from the CEO (who is traveling internationally) requesting an immediate wire transfer of $2M for a confidential acquisition. The email appears legitimate — correct email address, correct signature, references a real upcoming deal.",
    injects: [
      { time: "T+0", event: "CFO receives wire transfer request from CEO" },
      { time: "T+30min", event: "CFO's assistant processes the wire to the provided account" },
      { time: "T+2hr", event: "Real CEO calls about an unrelated matter — denies sending the email" },
      { time: "T+3hr", event: "IT discovers the CEO's email was compromised via a phishing attack 2 weeks ago" },
      { time: "T+4hr", event: "Bank reports the receiving account has already been emptied" },
    ],
    discussion_questions: [
      "Could this wire transfer have been prevented? What controls failed?",
      "What is our process for verifying unusual financial requests?",
      "What can the bank do to recover the funds? What is our cyber insurance coverage?",
      "Should we report this to law enforcement? When?",
    ],
  },
  {
    id: 6, name: "Cloud Account Compromise — Cryptomining Operation",
    scenario: "Your AWS bill has spiked from $5,000/month to $150,000 in the current billing period. Investigation reveals hundreds of GPU instances launched across multiple regions by a compromised IAM access key. The key was leaked in a public GitHub repository.",
    injects: [
      { time: "T+0", event: "AWS Cost Explorer shows 30x cost increase" },
      { time: "T+30min", event: "Security finds 400+ p3.16xlarge instances across 8 regions" },
      { time: "T+1hr", event: "Compromised IAM key found in public GitHub commit from 3 days ago" },
      { time: "T+2hr", event: "AWS advises the charges are valid and the key owner is responsible" },
      { time: "T+4hr", event: "After terminating instances, new ones keep appearing — multiple keys compromised" },
    ],
    discussion_questions: [
      "How can we prevent IAM keys from being committed to public repositories?",
      "What compensating controls should be in place (billing alerts, SCPs, instance limits)?",
      "Will AWS waive the charges? What is our negotiating position?",
      "How do we identify all compromised credentials and close all access paths?",
    ],
  },
  {
    id: 7, name: "DDoS Attack During Peak Business Period",
    scenario: "During your busiest sales period (Black Friday equivalent), your e-commerce site goes down due to a massive DDoS attack. Traffic volume is 100x normal. Your DDoS mitigation service is partially effective but the site is still slow. A ransom demand arrives via email: pay 10 BTC or the attack continues through the weekend.",
    injects: [
      { time: "T+0", event: "Website becomes unreachable, monitoring alerts fire" },
      { time: "T+15min", event: "CDN/DDoS provider confirms 500 Gbps volumetric attack" },
      { time: "T+1hr", event: "Site restored but intermittent, response times 30+ seconds" },
      { time: "T+2hr", event: "Ransom email received demanding 10 BTC" },
      { time: "T+4hr", event: "Estimated revenue loss: $500K/hour of downtime" },
    ],
    discussion_questions: [
      "Do we pay the ransom to stop the attack?",
      "What is our DDoS mitigation plan and is it adequate?",
      "How do we communicate with customers about service disruption?",
      "Should we involve law enforcement?",
    ],
  },
  {
    id: 8, name: "Physical Security Breach — Rogue Network Device",
    scenario: "A maintenance worker found a small Raspberry Pi-sized device plugged into a network port behind a printer on the 3rd floor. It has a cellular antenna and appears to have been there for several weeks. The device has WiFi, LAN, and 4G connectivity.",
    injects: [
      { time: "T+0", event: "Unknown device discovered connected to internal network" },
      { time: "T+30min", event: "Device has outbound 4G connection — active C2 channel" },
      { time: "T+1hr", event: "DHCP logs show device has been on the network for 3 weeks" },
      { time: "T+2hr", event: "Network traffic analysis shows the device was performing internal scans and capturing credentials" },
      { time: "T+4hr", event: "CCTV review shows an individual in a contractor vest planted the device" },
    ],
    discussion_questions: [
      "How did a physical implant go undetected for 3 weeks?",
      "What data could the attacker have accessed in that time?",
      "How do we improve physical security to prevent this?",
      "Should we implement 802.1X network access control?",
      "Is this a nation-state or corporate espionage scenario? How does that change our response?",
    ],
  },
  {
    id: 9, name: "AI-Powered Social Engineering Attack",
    scenario: "An employee receives a phone call that sounds exactly like their CEO using AI voice cloning. The 'CEO' instructs them to urgently transfer vendor payment details to a new account. Simultaneously, a deepfake video call occurs with the CFO. The attacks are coordinated and use information gathered from social media.",
    injects: [
      { time: "T+0", event: "Finance employee receives AI-cloned voice call from 'CEO'" },
      { time: "T+15min", event: "CFO receives deepfake video call from 'vendor representative'" },
      { time: "T+30min", event: "Bank details changed for a major vendor based on the calls" },
      { time: "T+2hr", event: "Real vendor calls about missing payment — fraud discovered" },
      { time: "T+4hr", event: "Audio analysis confirms AI voice cloning was used" },
    ],
    discussion_questions: [
      "How do we verify identity in an era of AI voice and video cloning?",
      "Should we implement code words or challenge phrases for sensitive requests?",
      "What technology controls can detect AI-generated content?",
      "How do we train employees to recognize AI-powered social engineering?",
    ],
  },
  {
    id: 10, name: "Regulatory Investigation — Cross-Border Data Breach",
    scenario: "A data breach involving EU customer data triggers GDPR notification requirements. The breach also affected California residents (CCPA), healthcare data (HIPAA), and payment card data (PCI DSS). Multiple regulators must be notified within different timeframes.",
    injects: [
      { time: "T+0", event: "Breach confirmed — 50,000 EU residents, 20,000 US residents affected" },
      { time: "T+24hr", event: "GDPR 72-hour notification clock is ticking" },
      { time: "T+48hr", event: "Payment card brand requires PFI engagement" },
      { time: "T+72hr", event: "GDPR notification deadline reached" },
      { time: "T+1 week", event: "Class action lawsuit filed by affected individuals" },
    ],
    discussion_questions: [
      "How do we coordinate notifications across multiple regulatory frameworks?",
      "What information do we include vs withhold in initial notifications?",
      "How do we handle conflicting requirements between jurisdictions?",
      "What is our legal exposure and insurance coverage?",
      "How do we preserve evidence while also conducting remediation?",
    ],
  },
];

// ═══════════════════════════════════════════════════════════════════════════════
// HARDENING CHECKLISTS
// ═══════════════════════════════════════════════════════════════════════════════

export const HARDENING = {
  windows: [
    { check: "Disable SMBv1", risk: "EternalBlue-class exploits", command: "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol", fix: "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" },
    { check: "Enable PowerShell script block logging", risk: "Undetected malicious scripts", command: "Get-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", fix: "Set-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1" },
    { check: "Enable command-line process auditing", risk: "No visibility into process commands", command: "auditpol /get /subcategory:\"Process Creation\"", fix: "auditpol /set /subcategory:\"Process Creation\" /success:enable" },
    { check: "Disable LLMNR", risk: "LLMNR poisoning for credential theft", command: "Get-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient -Name EnableMulticast", fix: "New-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient -Name EnableMulticast -Value 0 -PropertyType DWORD" },
    { check: "Disable NBT-NS", risk: "NBT-NS poisoning for credential theft", command: "Check network adapter advanced settings", fix: "Set NetBIOS over TCP/IP to Disabled on all adapters via GPO" },
    { check: "Enable Credential Guard", risk: "LSASS credential theft", command: "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard", fix: "Enable via Group Policy: Computer Configuration > Administrative Templates > System > Device Guard" },
    { check: "Configure LAPS", risk: "Shared local admin passwords", command: "Get-AdmPwdPassword -ComputerName *", fix: "Deploy Microsoft LAPS via Group Policy" },
    { check: "Restrict WDigest authentication", risk: "Cleartext password in memory", command: "Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest -Name UseLogonCredential", fix: "Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest -Name UseLogonCredential -Value 0" },
    { check: "Enable LSA protection", risk: "LSASS manipulation", command: "Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RunAsPPL", fix: "Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RunAsPPL -Value 1" },
    { check: "Restrict NTLM authentication", risk: "Pass-the-Hash attacks", command: "Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name LmCompatibilityLevel", fix: "Set LmCompatibilityLevel to 5 (Send NTLMv2 response only, refuse LM & NTLM)" },
  ],
  linux: [
    { check: "Disable root SSH login", risk: "Direct root access via SSH", command: "grep PermitRootLogin /etc/ssh/sshd_config", fix: "Set PermitRootLogin no in /etc/ssh/sshd_config" },
    { check: "Enforce SSH key authentication", risk: "Password brute force", command: "grep PasswordAuthentication /etc/ssh/sshd_config", fix: "Set PasswordAuthentication no in /etc/ssh/sshd_config" },
    { check: "Set file permissions on sensitive files", risk: "Unauthorized access to credentials", command: "ls -la /etc/shadow /etc/gshadow", fix: "chmod 640 /etc/shadow /etc/gshadow" },
    { check: "Configure automatic security updates", risk: "Unpatched vulnerabilities", command: "apt list --installed 2>/dev/null | grep unattended-upgrades", fix: "apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades" },
    { check: "Enable auditd", risk: "No syscall-level auditing", command: "systemctl status auditd", fix: "systemctl enable auditd && systemctl start auditd" },
    { check: "Restrict SUID binaries", risk: "Privilege escalation via SUID", command: "find / -perm -4000 -type f 2>/dev/null", fix: "Remove unnecessary SUID bits: chmod u-s /path/to/binary" },
    { check: "Configure fail2ban", risk: "Brute force attacks", command: "systemctl status fail2ban", fix: "apt install fail2ban && systemctl enable fail2ban" },
    { check: "Disable unused services", risk: "Expanded attack surface", command: "systemctl list-unit-files --type=service --state=enabled", fix: "systemctl disable SERVICE_NAME" },
    { check: "Configure firewall (UFW/iptables)", risk: "Unrestricted network access", command: "ufw status verbose", fix: "ufw default deny incoming && ufw default allow outgoing && ufw enable" },
    { check: "Set password complexity with PAM", risk: "Weak passwords", command: "grep pam_pwquality /etc/pam.d/common-password", fix: "apt install libpam-pwquality && configure /etc/security/pwquality.conf" },
  ],
};

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export function searchHuntingQueries(keyword) {
  const q = (keyword || "").toLowerCase();
  return THREAT_HUNTING_QUERIES.filter((h) =>
    h.hypothesis.toLowerCase().includes(q) ||
    h.category.toLowerCase().includes(q) ||
    h.query.toLowerCase().includes(q) ||
    (h.mitre || "").toLowerCase().includes(q)
  );
}

export function getHuntingByCategory(category) {
  return THREAT_HUNTING_QUERIES.filter((h) => h.category === category);
}

export function getArtifactsByCategory(os, category) {
  const db = os === "windows" ? WINDOWS_ARTIFACTS : LINUX_ARTIFACTS;
  if (!category) return db;
  return db.filter((c) => c.category.toLowerCase().includes(category.toLowerCase()));
}

export function getComplianceByFramework(framework) {
  const key = framework.toLowerCase();
  return COMPLIANCE_MAPPINGS.map((m) => ({
    family: m.family,
    control: m[key] || m[Object.keys(m).find((k) => k.toLowerCase().includes(key))] || "N/A",
  }));
}
