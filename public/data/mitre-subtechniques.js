// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Complete MITRE ATT&CK v14 Technique & Sub-technique Database
// Covers all 14 tactics with detailed techniques, detections, and mitigations.

export const MITRE_TACTICS = [
  { id: "TA0043", name: "Reconnaissance", description: "The adversary is trying to gather information they can use to plan future operations." },
  { id: "TA0042", name: "Resource Development", description: "The adversary is trying to establish resources they can use to support operations." },
  { id: "TA0001", name: "Initial Access", description: "The adversary is trying to get into your network." },
  { id: "TA0002", name: "Execution", description: "The adversary is trying to run malicious code." },
  { id: "TA0003", name: "Persistence", description: "The adversary is trying to maintain their foothold." },
  { id: "TA0004", name: "Privilege Escalation", description: "The adversary is trying to gain higher-level permissions." },
  { id: "TA0005", name: "Defense Evasion", description: "The adversary is trying to avoid being detected." },
  { id: "TA0006", name: "Credential Access", description: "The adversary is trying to steal account names and passwords." },
  { id: "TA0007", name: "Discovery", description: "The adversary is trying to figure out your environment." },
  { id: "TA0008", name: "Lateral Movement", description: "The adversary is trying to move through your environment." },
  { id: "TA0009", name: "Collection", description: "The adversary is trying to gather data of interest to their goal." },
  { id: "TA0011", name: "Command and Control", description: "The adversary is trying to communicate with compromised systems to control them." },
  { id: "TA0010", name: "Exfiltration", description: "The adversary is trying to steal data." },
  { id: "TA0040", name: "Impact", description: "The adversary is trying to manipulate, interrupt, or destroy your systems and data." },
];

export const MITRE_TECHNIQUES = [

  // ================================================================
  // RECONNAISSANCE (TA0043)
  // ================================================================

  { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance",
    description: "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans involve probing victim infrastructure directly, as opposed to passive collection of information.",
    platforms: ["PRE"], permissions_required: [],
    data_sources: ["Network Traffic: Network Traffic Flow", "Network Traffic: Network Traffic Content"],
    detection: "Monitor for suspicious network traffic that could be indicative of scanning, such as large quantities of connection attempts from a single source. Analyze web server logs for reconnaissance patterns.",
    mitigations: [{ id: "M1056", name: "Pre-compromise", description: "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls." }],
    procedure_examples: [{ group: "APT28", description: "APT28 has performed large-scale scanning of target networks to identify vulnerable services." }, { group: "Sandworm Team", description: "Sandworm Team has scanned for vulnerable mail servers and VPN appliances." }]
  },
  { id: "T1595.001", name: "Active Scanning: Scanning IP Blocks", tactic: "Reconnaissance",
    description: "Adversaries may scan victim IP blocks to gather information that can be used during targeting. Scans may include ICMP ping sweeps, TCP/UDP port scans, and banner grabbing to identify running services and their versions.",
    platforms: ["PRE"], permissions_required: [],
    data_sources: ["Network Traffic: Network Traffic Flow"],
    detection: "Monitor network traffic for indicators of port scanning (SYN scans, connect scans) and service enumeration. IDS/IPS can detect common scanning patterns.",
    mitigations: [{ id: "M1056", name: "Pre-compromise", description: "Cannot be easily mitigated at the enterprise level. Rate limiting and blocking known scanner IPs may help." }],
    procedure_examples: [{ group: "Volt Typhoon", description: "Volt Typhoon has scanned internet-facing devices for known vulnerabilities in SOHO network equipment." }]
  },
  { id: "T1595.002", name: "Active Scanning: Vulnerability Scanning", tactic: "Reconnaissance",
    description: "Adversaries may scan victims for vulnerabilities that can be used during targeting. Vulnerability scans typically check running software for known CVEs and misconfigurations that could be exploited.",
    platforms: ["PRE"], permissions_required: [],
    data_sources: ["Network Traffic: Network Traffic Flow", "Network Traffic: Network Traffic Content"],
    detection: "Monitor for indicators of vulnerability scanning such as Nessus, OpenVAS, or Qualys user-agent strings. Detect patterns consistent with automated vulnerability scanners.",
    mitigations: [{ id: "M1056", name: "Pre-compromise", description: "Organizations can minimize the information available to scanners by hardening internet-facing services and keeping software updated." }],
    procedure_examples: [{ group: "APT41", description: "APT41 has scanned targets for vulnerable Citrix, Cisco, and Zoho ManageEngine installations." }]
  },
  { id: "T1592", name: "Gather Victim Host Information", tactic: "Reconnaissance",
    description: "Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include hardware, software, configurations, installed security products, and patch levels.",
    platforms: ["PRE"], permissions_required: [],
    data_sources: ["Internet Scan: Response Content"],
    detection: "Much of this activity occurs outside the visibility of the target organization. Monitor for suspicious inquiries about technical infrastructure.",
    mitigations: [{ id: "M1056", name: "Pre-compromise", description: "Limit public exposure of technical infrastructure details." }],
    procedure_examples: [{ group: "Lazarus Group", description: "Lazarus Group has gathered information on target systems through watering hole sites and spear-phishing." }]
  },
  { id: "T1589", name: "Gather Victim Identity Information", tactic: "Reconnaissance",
    description: "Adversaries may gather information about the victim's identity that can be used during targeting. This includes employee names, email addresses, credentials, and organizational roles.",
    platforms: ["PRE"], permissions_required: [],
    data_sources: ["Network Traffic: Network Traffic Content"],
    detection: "Monitor for credential exposure on paste sites and dark web forums. Watch for social engineering attempts against employees.",
    mitigations: [{ id: "M1056", name: "Pre-compromise", description: "Limit publicly available information about employees. Use breach monitoring services." }],
    procedure_examples: [{ group: "APT29", description: "APT29 has harvested employee email addresses from public sources for use in spear-phishing campaigns." }]
  },

  // ================================================================
  // RESOURCE DEVELOPMENT (TA0042)
  // ================================================================

  { id: "T1583", name: "Acquire Infrastructure", tactic: "Resource Development",
    description: "Adversaries may buy, lease, or rent infrastructure to support their operations. This includes servers, domains, VPS instances, and cloud accounts used for staging, C2, and phishing.",
    platforms: ["PRE"], permissions_required: [],
    data_sources: ["Domain Name: Active DNS", "Domain Name: Passive DNS", "Internet Scan: Response Content"],
    detection: "Monitor for newly registered domains that closely resemble the organization's domain. Track new infrastructure associated with known threat actor patterns.",
    mitigations: [{ id: "M1056", name: "Pre-compromise", description: "Monitor for typosquatting and similar domains. Report malicious infrastructure to hosting providers." }],
    procedure_examples: [{ group: "APT28", description: "APT28 has registered domains mimicking legitimate NATO and government websites." }, { group: "Lazarus Group", description: "Lazarus Group has set up cryptocurrency-themed phishing infrastructure." }]
  },
  { id: "T1583.001", name: "Acquire Infrastructure: Domains", tactic: "Resource Development",
    description: "Adversaries may acquire domains that can be used during targeting. Domains may be purchased through registrars that offer privacy protection, or through previously expired domain auctions to inherit existing reputation.",
    platforms: ["PRE"], permissions_required: [],
    data_sources: ["Domain Name: Active DNS", "Domain Name: Domain Registration"],
    detection: "Monitor domain registration feeds for domains similar to organizational names. Use brand monitoring services.",
    mitigations: [{ id: "M1056", name: "Pre-compromise", description: "Register common typosquatting variants of your domain proactively." }],
    procedure_examples: [{ group: "Kimsuky", description: "Kimsuky has registered domains impersonating South Korean government and media organizations." }]
  },
  { id: "T1587", name: "Develop Capabilities", tactic: "Resource Development",
    description: "Adversaries may build capabilities that can be used during targeting. This includes developing malware, exploits, and self-signed certificates rather than purchasing or stealing them.",
    platforms: ["PRE"], permissions_required: [],
    data_sources: ["Malware Repository: Malware Content", "Internet Scan: Response Content"],
    detection: "Monitor malware repositories for new samples that target your organization or sector. Analyze newly seen malware for connections to known threat actors.",
    mitigations: [{ id: "M1056", name: "Pre-compromise", description: "This cannot be easily mitigated as it occurs outside the target's environment." }],
    procedure_examples: [{ group: "Equation Group", description: "Equation Group developed sophisticated malware platforms including EquationDrug and GrayFish." }]
  },

  // ================================================================
  // INITIAL ACCESS (TA0001)
  // ================================================================

  { id: "T1566", name: "Phishing", tactic: "Initial Access",
    description: "Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering aimed at tricking users into executing malicious content or revealing credentials.",
    platforms: ["Windows", "macOS", "Linux", "SaaS", "Office 365", "Google Workspace"],
    permissions_required: ["User"],
    data_sources: ["Application Log: Application Log Content", "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    detection: "Monitor email gateways for suspicious attachments and links. Analyze email headers for spoofing indicators. Use URL detonation sandboxes.",
    mitigations: [
      { id: "M1049", name: "Antivirus/Antimalware", description: "Use email security solutions that scan attachments for malware." },
      { id: "M1031", name: "Network Intrusion Prevention", description: "Use email filtering and IPS to detect phishing attempts." },
      { id: "M1017", name: "User Training", description: "Train users to identify and report phishing emails." }
    ],
    procedure_examples: [{ group: "APT29", description: "APT29 has used spear-phishing emails with malicious links to HTML Smuggling pages to deliver ISO files containing Cobalt Strike beacons." }, { group: "Kimsuky", description: "Kimsuky has sent spear-phishing emails with malicious HWP (Hangul Word Processor) documents." }]
  },
  { id: "T1566.001", name: "Phishing: Spearphishing Attachment", tactic: "Initial Access",
    description: "Adversaries may send spear-phishing emails with a malicious attachment in an attempt to gain access. The attachment may be a Microsoft Office document with macros, a PDF with embedded JavaScript, an executable disguised with a document icon, or an archive containing malicious files.",
    platforms: ["Windows", "macOS", "Linux"],
    permissions_required: ["User"],
    data_sources: ["Application Log: Application Log Content", "File: File Creation", "Network Traffic: Network Traffic Content"],
    detection: "Monitor email for suspicious attachments. Sandbox attachments before delivery. Monitor for child processes spawned by Office applications, PDF readers, and archive utilities.",
    mitigations: [
      { id: "M1049", name: "Antivirus/Antimalware", description: "Scan email attachments and block known malicious file types." },
      { id: "M1031", name: "Network Intrusion Prevention", description: "Filter malicious attachments at the email gateway." },
      { id: "M1054", name: "Software Configuration", description: "Disable macros in Office documents from the internet. Enable Protected View." }
    ],
    procedure_examples: [{ group: "APT28", description: "APT28 has sent spear-phishing emails with malicious Word documents exploiting CVE-2017-0199." }, { group: "Lazarus Group", description: "Lazarus Group has used weaponized HWP documents and Excel files with macros in spear-phishing campaigns." }]
  },
  { id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access",
    description: "Adversaries may send spear-phishing emails with a malicious link to download malware or harvest credentials. The link may point to a credential harvesting page, a drive-by download site, or a legitimate service hosting malicious content.",
    platforms: ["Windows", "macOS", "Linux", "SaaS"],
    permissions_required: ["User"],
    data_sources: ["Application Log: Application Log Content", "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    detection: "Monitor for clicks on suspicious URLs in email. Use URL reputation services and sandboxing to analyze linked content before delivery.",
    mitigations: [
      { id: "M1021", name: "Restrict Web-Based Content", description: "Block access to known malicious domains and URLs." },
      { id: "M1017", name: "User Training", description: "Train users to verify URLs before clicking, especially in unexpected emails." }
    ],
    procedure_examples: [{ group: "APT29", description: "APT29 has sent phishing emails with links to attacker-controlled websites hosting malicious HTML applications." }]
  },
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access",
    description: "Adversaries may attempt to exploit a weakness in an internet-facing host or service to initially access a network. Common targets include web servers, email servers, VPN gateways, and cloud services with known vulnerabilities.",
    platforms: ["Windows", "Linux", "macOS", "Containers", "IaaS", "Network", "SaaS"],
    permissions_required: [],
    data_sources: ["Application Log: Application Log Content", "Network Traffic: Network Traffic Content"],
    detection: "Monitor application logs for exploitation indicators. Use WAF rules to detect and block known exploit payloads. Monitor for unusual process creation on internet-facing servers.",
    mitigations: [
      { id: "M1048", name: "Application Isolation and Sandboxing", description: "Run internet-facing applications in sandboxed environments." },
      { id: "M1030", name: "Network Segmentation", description: "Segment internet-facing servers from internal networks." },
      { id: "M1051", name: "Update Software", description: "Apply security patches promptly, especially for internet-facing services." }
    ],
    procedure_examples: [{ group: "HAFNIUM", description: "HAFNIUM exploited ProxyLogon vulnerabilities in Exchange Server to gain initial access to organizations worldwide." }, { group: "APT41", description: "APT41 has exploited Citrix ADC, Cisco routers, and Zoho ManageEngine for initial access." }]
  },
  { id: "T1133", name: "External Remote Services", tactic: "Initial Access",
    description: "Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and RDP may allow users to connect to internal network resources from external locations.",
    platforms: ["Windows", "Linux", "macOS", "Containers"],
    permissions_required: ["User"],
    data_sources: ["Application Log: Application Log Content", "Logon Session: Logon Session Creation", "Network Traffic: Network Traffic Flow"],
    detection: "Monitor for unusual VPN and remote access connections, especially from unusual geographic locations or at unusual times. Detect brute-force attempts against remote access services.",
    mitigations: [
      { id: "M1035", name: "Limit Access to Resource Over Network", description: "Limit access to remote services to only necessary users and networks." },
      { id: "M1032", name: "Multi-factor Authentication", description: "Require MFA for all remote access." },
      { id: "M1030", name: "Network Segmentation", description: "Place remote access infrastructure in a DMZ." }
    ],
    procedure_examples: [{ group: "APT29", description: "APT29 has used stolen VPN credentials to maintain access to victim networks." }, { group: "Volt Typhoon", description: "Volt Typhoon has exploited Fortinet FortiGuard devices for initial access to target networks." }]
  },
  { id: "T1078", name: "Valid Accounts", tactic: "Initial Access",
    description: "Adversaries may obtain and abuse credentials of existing accounts to gain Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls.",
    platforms: ["Windows", "Linux", "macOS", "SaaS", "IaaS", "Containers", "Network", "Office 365", "Azure AD", "Google Workspace"],
    permissions_required: ["User", "Administrator"],
    data_sources: ["Logon Session: Logon Session Creation", "User Account: User Account Authentication"],
    detection: "Monitor for logon attempts using known compromised credentials. Detect impossible travel (logins from geographically distant locations in short timeframes). Alert on after-hours authentication activity.",
    mitigations: [
      { id: "M1032", name: "Multi-factor Authentication", description: "Enforce MFA on all accounts, especially privileged accounts." },
      { id: "M1027", name: "Password Policies", description: "Enforce strong password policies and regular rotation." },
      { id: "M1026", name: "Privileged Account Management", description: "Minimize the number of privileged accounts and audit their usage." }
    ],
    procedure_examples: [{ group: "APT28", description: "APT28 has used stolen credentials from credential phishing to access victim organizations." }, { group: "Scattered Spider", description: "Scattered Spider has used social engineering to obtain MFA tokens and valid credentials from IT helpdesks." }]
  },

  // ================================================================
  // EXECUTION (TA0002)
  // ================================================================

  { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution",
    description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are common on all major platforms.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User"],
    data_sources: ["Command: Command Execution", "Process: Process Creation", "Script: Script Execution"],
    detection: "Monitor for execution of interpreters (cmd, powershell, bash, python) with suspicious arguments. Log and analyze script execution events.",
    mitigations: [
      { id: "M1049", name: "Antivirus/Antimalware", description: "Use endpoint security that monitors for malicious script execution." },
      { id: "M1038", name: "Execution Prevention", description: "Use application allowlisting to prevent unauthorized interpreters from running." },
      { id: "M1042", name: "Disable or Remove Feature or Program", description: "Remove unnecessary scripting engines from systems." }
    ],
    procedure_examples: [{ group: "APT29", description: "APT29 has used PowerShell extensively for execution, including encoded commands and custom cmdlets." }]
  },
  { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution",
    description: "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in Windows. Adversaries can use PowerShell to perform actions including discovery, execution of code, and download of additional payloads.",
    platforms: ["Windows"], permissions_required: ["User"],
    data_sources: ["Command: Command Execution", "Module: Module Load", "Process: Process Creation", "Script: Script Execution"],
    detection: "Enable PowerShell Script Block Logging (Event ID 4104), Module Logging, and Transcription. Monitor for encoded commands (-enc), download cradles (IEX, Invoke-Expression), and AMSI bypass attempts.",
    mitigations: [
      { id: "M1045", name: "Code Signing", description: "Set PowerShell execution policy to AllSigned." },
      { id: "M1042", name: "Disable or Remove Feature or Program", description: "Remove PowerShell 2.0 which lacks logging capabilities." },
      { id: "M1049", name: "Antivirus/Antimalware", description: "Enable AMSI integration in security products." }
    ],
    procedure_examples: [{ group: "APT29", description: "APT29 has extensively used PowerShell for initial execution, download of payloads, and lateral movement." }, { group: "FIN7", description: "FIN7 has used PowerShell scripts to download and execute Carbanak and other payloads." }]
  },
  { id: "T1059.003", name: "Command and Scripting Interpreter: Windows Command Shell", tactic: "Execution",
    description: "Adversaries may abuse the Windows command shell (cmd.exe) for execution of commands. The command shell is the primary command prompt on Windows systems and is used by adversaries for system commands, file operations, and launching other programs.",
    platforms: ["Windows"], permissions_required: ["User"],
    data_sources: ["Command: Command Execution", "Process: Process Creation"],
    detection: "Monitor process creation events for cmd.exe with suspicious parent processes (Word, Excel, PowerPoint, PDF readers). Detect unusual command-line arguments.",
    mitigations: [
      { id: "M1038", name: "Execution Prevention", description: "Use application allowlisting to control which users can run cmd.exe." }
    ],
    procedure_examples: [{ group: "APT41", description: "APT41 has used cmd.exe for initial execution and lateral movement commands." }]
  },
  { id: "T1059.004", name: "Command and Scripting Interpreter: Unix Shell", tactic: "Execution",
    description: "Adversaries may abuse Unix shell commands and scripts for execution. Unix shells such as bash, sh, zsh, and dash provide a command-line interface for interacting with the operating system and executing scripts.",
    platforms: ["macOS", "Linux"], permissions_required: ["User"],
    data_sources: ["Command: Command Execution", "Process: Process Creation"],
    detection: "Monitor for shell processes spawned by unusual parent processes (web servers, database services). Log and analyze bash history. Use auditd to monitor command execution.",
    mitigations: [
      { id: "M1038", name: "Execution Prevention", description: "Use restricted shells or RBAC to limit command execution." }
    ],
    procedure_examples: [{ group: "Sandworm Team", description: "Sandworm Team has used bash scripts for deployment of destructive malware on Linux systems." }]
  },

  // ================================================================
  // PERSISTENCE (TA0003)
  // ================================================================

  { id: "T1053", name: "Scheduled Task/Job", tactic: "Persistence",
    description: "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time.",
    platforms: ["Windows", "Linux", "macOS", "Containers"],
    permissions_required: ["User", "Administrator"],
    data_sources: ["Command: Command Execution", "File: File Creation", "Process: Process Creation", "Scheduled Job: Scheduled Job Creation"],
    detection: "Monitor for creation of scheduled tasks/cron jobs, especially those executing from unusual locations or with suspicious commands. Windows Event IDs 4698 (task created) and 4702 (task updated).",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Restrict who can create scheduled tasks to trusted administrators." },
      { id: "M1028", name: "Operating System Configuration", description: "Configure the task scheduler to require elevated privileges for task creation." }
    ],
    procedure_examples: [{ group: "APT29", description: "APT29 has used scheduled tasks for persistence, naming them to blend in with legitimate Windows tasks." }, { group: "Lazarus Group", description: "Lazarus Group has created scheduled tasks to execute malware at system startup." }]
  },
  { id: "T1053.005", name: "Scheduled Task/Job: Scheduled Task", tactic: "Persistence",
    description: "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. The schtasks utility can be used to create tasks that execute programs at system boot or on a recurring schedule.",
    platforms: ["Windows"], permissions_required: ["Administrator"],
    data_sources: ["Command: Command Execution", "Process: Process Creation", "Scheduled Job: Scheduled Job Creation"],
    detection: "Monitor Event ID 4698 for new scheduled task creation. Audit scheduled tasks for suspicious commands or executables in unusual paths (e.g., %TEMP%, %APPDATA%).",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Restrict task creation to specific administrative accounts." }
    ],
    procedure_examples: [{ group: "FIN7", description: "FIN7 has created scheduled tasks named 'GoogleUpdater' for persistence." }]
  },
  { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence",
    description: "Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence. Operating systems have mechanisms to automatically run programs on startup.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User", "Administrator"],
    data_sources: ["Command: Command Execution", "File: File Creation", "File: File Modification", "Process: Process Creation", "Windows Registry: Windows Registry Key Modification"],
    detection: "Monitor the Run/RunOnce registry keys, startup folders, and similar autostart locations for new or modified entries. On Linux, monitor systemd services, init.d scripts, and rc.local.",
    mitigations: [
      { id: "M1038", name: "Execution Prevention", description: "Use application allowlisting to prevent unauthorized programs from running at startup." }
    ],
    procedure_examples: [{ group: "APT28", description: "APT28 has used Run registry keys and scheduled tasks for persistence." }, { group: "Turla", description: "Turla has registered malicious DLLs as services for persistence." }]
  },
  { id: "T1547.001", name: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", tactic: "Persistence",
    description: "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the run keys causes the program referenced to be executed when a user logs in.",
    platforms: ["Windows"], permissions_required: ["User", "Administrator"],
    data_sources: ["File: File Creation", "Windows Registry: Windows Registry Key Modification"],
    detection: "Monitor Registry modifications to HKLM and HKCU Run/RunOnce keys. Monitor the Startup folder for new files. Event ID 13 (Sysmon RegistryEvent) tracks registry changes.",
    mitigations: [
      { id: "M1038", name: "Execution Prevention", description: "Block execution of programs from the Startup folder and unusual Run key paths." }
    ],
    procedure_examples: [{ group: "APT41", description: "APT41 has added entries to the Run registry key for persistence of their backdoors." }]
  },
  { id: "T1136", name: "Create Account", tactic: "Persistence",
    description: "Adversaries may create new accounts to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that does not require deploying persistent remote access tools.",
    platforms: ["Windows", "Linux", "macOS", "IaaS", "SaaS", "Azure AD", "Office 365", "Google Workspace"],
    permissions_required: ["Administrator"],
    data_sources: ["Process: Process Creation", "User Account: User Account Creation"],
    detection: "Monitor for new account creation events. Windows Event IDs 4720 (user created) and 4722 (user enabled). On Linux, monitor /etc/passwd and /etc/shadow for modifications. In cloud, monitor IAM account creation events.",
    mitigations: [
      { id: "M1032", name: "Multi-factor Authentication", description: "Require MFA for new account creation." },
      { id: "M1030", name: "Network Segmentation", description: "Limit who can create accounts through network controls." },
      { id: "M1026", name: "Privileged Account Management", description: "Restrict account creation privileges to necessary personnel." }
    ],
    procedure_examples: [{ group: "Scattered Spider", description: "Scattered Spider has created new admin accounts in Azure AD and Okta for persistent access." }]
  },

  // ================================================================
  // PRIVILEGE ESCALATION (TA0004)
  // ================================================================

  { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation",
    description: "Adversaries may exploit software vulnerabilities to escalate privileges. Exploitation of a vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel.",
    platforms: ["Windows", "macOS", "Linux", "Containers"],
    permissions_required: ["User"],
    data_sources: ["Process: Process Creation"],
    detection: "Monitor for unusual process behavior that could indicate exploitation, such as spawning SYSTEM-level processes from user-level contexts. Detect common exploit indicators like unusual DLL loading or memory corruption.",
    mitigations: [
      { id: "M1048", name: "Application Isolation and Sandboxing", description: "Run vulnerable applications in sandboxed environments." },
      { id: "M1019", name: "Threat Intelligence Program", description: "Track and patch known exploited vulnerabilities." },
      { id: "M1051", name: "Update Software", description: "Keep all software up to date to minimize the attack surface." }
    ],
    procedure_examples: [{ group: "APT28", description: "APT28 has used kernel exploits including CVE-2015-1701 and CVE-2016-7255 for privilege escalation." }]
  },
  { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation",
    description: "Adversaries may circumvent mechanisms designed to control elevated privileges to gain higher-level permissions. Most modern systems contain mechanisms to gate processes or commands to elevated privileges, but adversaries can find ways to bypass these.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User", "Administrator"],
    data_sources: ["Command: Command Execution", "File: File Modification", "Process: Process Creation", "Windows Registry: Windows Registry Key Modification"],
    detection: "Monitor for UAC bypass attempts on Windows, sudo abuse on Linux, and authorization plugin abuse on macOS. Detect known UAC bypass patterns in registry or file system changes.",
    mitigations: [
      { id: "M1047", name: "Audit", description: "Check for proper UAC settings and monitor for bypass attempts." },
      { id: "M1028", name: "Operating System Configuration", description: "Set UAC to 'Always Notify' on Windows. Configure sudoers properly on Linux." },
      { id: "M1026", name: "Privileged Account Management", description: "Remove users from the local Administrators group where possible." }
    ],
    procedure_examples: [{ group: "APT29", description: "APT29 has used multiple UAC bypass techniques including CMSTP and fodhelper.exe." }]
  },
  { id: "T1548.002", name: "Abuse Elevation Control Mechanism: Bypass User Account Control", tactic: "Privilege Escalation",
    description: "Adversaries may bypass UAC mechanisms to elevate process privileges on Windows systems. UAC allows programs to request elevation using an auto-elevation mechanism, consent prompt, or other means, which adversaries may exploit.",
    platforms: ["Windows"], permissions_required: ["User"],
    data_sources: ["Command: Command Execution", "Process: Process Creation", "Windows Registry: Windows Registry Key Modification"],
    detection: "Monitor for known UAC bypass techniques: fodhelper.exe, eventvwr.exe, sdclt.exe, CMSTP, DiskCleanup, SilentCleanup, and others. Detect modifications to UAC-related registry keys.",
    mitigations: [
      { id: "M1047", name: "Audit", description: "Monitor for UAC bypass attempts." },
      { id: "M1026", name: "Privileged Account Management", description: "Remove users from local administrators group." },
      { id: "M1051", name: "Update Software", description: "Keep Windows updated to patch UAC bypass methods." }
    ],
    procedure_examples: [{ group: "FIN7", description: "FIN7 has used several UAC bypass techniques including the CMSTP bypass." }]
  },

  // ================================================================
  // DEFENSE EVASION (TA0005)
  // ================================================================

  { id: "T1055", name: "Process Injection", tactic: "Defense Evasion",
    description: "Adversaries may inject code into processes to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User"],
    data_sources: ["Module: Module Load", "Process: OS API Execution", "Process: Process Access", "Process: Process Modification"],
    detection: "Monitor for processes that exhibit suspicious behavior, such as loading unexpected DLLs, accessing remote process memory, or creating remote threads. Sysmon Event IDs 8 (CreateRemoteThread) and 10 (ProcessAccess) are key indicators.",
    mitigations: [
      { id: "M1040", name: "Behavior Prevention on Endpoint", description: "Use EDR solutions that detect and block process injection techniques." },
      { id: "M1026", name: "Privileged Account Management", description: "Limit SeDebugPrivilege to prevent non-admin users from injecting into other processes." }
    ],
    procedure_examples: [{ group: "Lazarus Group", description: "Lazarus Group has injected malicious code into legitimate processes using process hollowing and APC injection." }, { group: "Turla", description: "Turla has injected code into browser processes for credential theft." }]
  },
  { id: "T1055.001", name: "Process Injection: Dynamic-link Library Injection", tactic: "Defense Evasion",
    description: "Adversaries may inject dynamic-link libraries (DLLs) into processes to evade process-based defenses. DLL injection is performed by writing the path to a malicious DLL inside the virtual address space of the target process and then creating a remote thread to load it.",
    platforms: ["Windows"], permissions_required: ["User"],
    data_sources: ["Module: Module Load", "Process: OS API Execution", "Process: Process Access"],
    detection: "Monitor for suspicious DLL loading, especially DLLs loaded from unusual paths. Track CreateRemoteThread API calls. Sysmon Event ID 7 (ImageLoaded) can detect unexpected DLL loads.",
    mitigations: [
      { id: "M1040", name: "Behavior Prevention on Endpoint", description: "Use endpoint protection that monitors for DLL injection patterns." }
    ],
    procedure_examples: [{ group: "APT41", description: "APT41 has used DLL injection to load malicious code into svchost.exe and other legitimate processes." }]
  },
  { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion",
    description: "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User"],
    data_sources: ["Command: Command Execution", "File: File Creation", "File: File Metadata", "Process: Process Creation"],
    detection: "Detect use of encoding/encryption utilities (certutil, base64). Monitor for files with high entropy. Analyze PowerShell scripts for obfuscation patterns (string concatenation, character substitution, base64 encoding).",
    mitigations: [
      { id: "M1049", name: "Antivirus/Antimalware", description: "Use security products with deobfuscation and emulation capabilities." },
      { id: "M1040", name: "Behavior Prevention on Endpoint", description: "Use behavioral detection to identify malicious actions regardless of file obfuscation." }
    ],
    procedure_examples: [{ group: "APT29", description: "APT29 has used multiple layers of encoding including base64 and XOR for payload obfuscation." }, { group: "FIN7", description: "FIN7 has heavily obfuscated their JavaScript and PowerShell payloads." }]
  },
  { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion",
    description: "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something associated with their actions.",
    platforms: ["Windows", "macOS", "Linux", "Containers", "Network"],
    permissions_required: ["User", "Administrator"],
    data_sources: ["Command: Command Execution", "File: File Deletion", "File: File Modification", "Process: OS API Execution", "Windows Registry: Windows Registry Key Deletion"],
    detection: "Monitor for event log clearing (Windows Event ID 1102). Detect bulk file deletions. Monitor for timestomping using Sysmon or file integrity monitoring.",
    mitigations: [
      { id: "M1029", name: "Remote Data Storage", description: "Forward logs to a central SIEM that cannot be modified by the adversary." },
      { id: "M1041", name: "Encrypt Sensitive Information", description: "Encrypt and sign log data to detect tampering." }
    ],
    procedure_examples: [{ group: "APT41", description: "APT41 has cleared Windows event logs after compromising systems to remove evidence." }]
  },

  // ================================================================
  // CREDENTIAL ACCESS (TA0006)
  // ================================================================

  { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access",
    description: "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or clear text password, from the operating system and software.",
    platforms: ["Windows", "Linux", "macOS"], permissions_required: ["Administrator", "SYSTEM"],
    data_sources: ["Command: Command Execution", "File: File Access", "Process: OS API Execution", "Process: Process Access", "Process: Process Creation"],
    detection: "Monitor for tools like Mimikatz, Lazagne, and gsecdump. Detect LSASS access (Sysmon Event ID 10 with TargetImage lsass.exe). Monitor for ntds.dit access or shadow copy creation. Watch for DCSync indicators (Directory Service replication requests from non-DC sources).",
    mitigations: [
      { id: "M1043", name: "Credential Access Protection", description: "Enable Credential Guard on Windows 10+ to protect LSASS." },
      { id: "M1025", name: "Privileged Process Integrity", description: "Enable LSA Protection (RunAsPPL) to prevent unauthorized LSASS access." },
      { id: "M1026", name: "Privileged Account Management", description: "Limit the number of accounts with DCSync privileges." }
    ],
    procedure_examples: [{ group: "APT29", description: "APT29 has used Mimikatz, ntdsutil, and custom tools to dump credentials from LSASS and Active Directory." }, { group: "Scattered Spider", description: "Scattered Spider has used credential dumping tools and DCSync to obtain domain admin credentials." }]
  },
  { id: "T1003.001", name: "OS Credential Dumping: LSASS Memory", tactic: "Credential Access",
    description: "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). LSASS stores credentials for users who are currently logged in, including NTLM hashes, Kerberos tickets, and plaintext passwords.",
    platforms: ["Windows"], permissions_required: ["SYSTEM"],
    data_sources: ["Process: OS API Execution", "Process: Process Access", "Process: Process Creation"],
    detection: "Monitor for processes accessing LSASS memory. Sysmon Event ID 10 with TargetImage containing lsass.exe. Detect MiniDump creation of LSASS. Monitor for suspicious use of comsvcs.dll MiniDump, procdump, or Task Manager dump creation.",
    mitigations: [
      { id: "M1043", name: "Credential Access Protection", description: "Enable Windows Credential Guard." },
      { id: "M1025", name: "Privileged Process Integrity", description: "Enable LSA Protection (RunAsPPL)." },
      { id: "M1028", name: "Operating System Configuration", description: "Disable WDigest authentication to prevent plaintext credential storage in LSASS." }
    ],
    procedure_examples: [{ group: "APT28", description: "APT28 has used Mimikatz to dump credentials from LSASS on compromised workstations and servers." }]
  },
  { id: "T1110", name: "Brute Force", tactic: "Credential Access",
    description: "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Techniques include password guessing, password spraying, and credential stuffing.",
    platforms: ["Windows", "Linux", "macOS", "SaaS", "IaaS", "Azure AD", "Office 365", "Google Workspace"],
    permissions_required: [],
    data_sources: ["Application Log: Application Log Content", "User Account: User Account Authentication"],
    detection: "Monitor for multiple failed authentication attempts. Detect password spray patterns (many accounts, few password attempts per account). Watch for credential stuffing indicators (multiple accounts authenticated in rapid succession).",
    mitigations: [
      { id: "M1032", name: "Multi-factor Authentication", description: "Enforce MFA to mitigate the impact of compromised credentials." },
      { id: "M1036", name: "Account Use Policies", description: "Implement account lockout policies after a threshold of failed attempts." },
      { id: "M1027", name: "Password Policies", description: "Enforce complex passwords and check against known breached passwords." }
    ],
    procedure_examples: [{ group: "APT28", description: "APT28 has conducted large-scale password spraying campaigns against government and military targets." }]
  },

  // ================================================================
  // DISCOVERY (TA0007)
  // ================================================================

  { id: "T1082", name: "System Information Discovery", tactic: "Discovery",
    description: "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. This information may be used to shape follow-on behaviors.",
    platforms: ["Windows", "macOS", "Linux", "IaaS"], permissions_required: ["User"],
    data_sources: ["Command: Command Execution", "Process: OS API Execution", "Process: Process Creation"],
    detection: "Monitor for execution of system information discovery commands: systeminfo, uname -a, cat /etc/os-release, sw_vers. Detect rapid enumeration of system properties.",
    mitigations: [],
    procedure_examples: [{ group: "APT29", description: "APT29 has used systeminfo and other commands to enumerate system details on compromised hosts." }]
  },
  { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery",
    description: "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User"],
    data_sources: ["Command: Command Execution", "Process: OS API Execution", "Process: Process Creation"],
    detection: "Monitor for file enumeration commands: dir, ls, find, tree. Detect mass file listing operations, especially targeting sensitive directories like Documents, Desktop, and known credential stores.",
    mitigations: [],
    procedure_examples: [{ group: "Lazarus Group", description: "Lazarus Group has searched victim systems for documents and files related to cryptocurrency." }]
  },

  // ================================================================
  // LATERAL MOVEMENT (TA0008)
  // ================================================================

  { id: "T1021", name: "Remote Services", tactic: "Lateral Movement",
    description: "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. The adversary may then perform actions as the logged-on user.",
    platforms: ["Windows", "macOS", "Linux", "IaaS"], permissions_required: ["User", "Administrator"],
    data_sources: ["Logon Session: Logon Session Creation", "Network Traffic: Network Traffic Flow", "Process: Process Creation"],
    detection: "Monitor for unusual remote service connections. Track lateral movement patterns where one compromised host initiates connections to multiple other hosts. Detect RDP (Event ID 4624 Type 10), SSH, and SMB authentication from unexpected sources.",
    mitigations: [
      { id: "M1032", name: "Multi-factor Authentication", description: "Require MFA for remote access services." },
      { id: "M1018", name: "User Account Management", description: "Limit which accounts can use remote services." },
      { id: "M1035", name: "Limit Access to Resource Over Network", description: "Use network segmentation to restrict lateral movement paths." }
    ],
    procedure_examples: [{ group: "APT29", description: "APT29 has used RDP and SMB for lateral movement within compromised networks." }]
  },
  { id: "T1021.001", name: "Remote Services: Remote Desktop Protocol", tactic: "Lateral Movement",
    description: "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). RDP allows a user to log into an interactive session on a remote computer.",
    platforms: ["Windows"], permissions_required: ["User", "Administrator"],
    data_sources: ["Logon Session: Logon Session Creation", "Network Traffic: Network Traffic Flow"],
    detection: "Monitor Windows Event ID 4624 (Type 10 for RemoteInteractive logon) and 4625 (failed RDP logon). Track RDP session durations and activity patterns. Detect RDP from unusual source IPs or at unusual times.",
    mitigations: [
      { id: "M1047", name: "Audit", description: "Audit RDP access and session activity." },
      { id: "M1032", name: "Multi-factor Authentication", description: "Require NLA (Network Level Authentication) for RDP." },
      { id: "M1030", name: "Network Segmentation", description: "Restrict RDP access between network segments." }
    ],
    procedure_examples: [{ group: "Scattered Spider", description: "Scattered Spider has used RDP extensively for lateral movement after gaining initial access." }]
  },
  { id: "T1570", name: "Lateral Tool Transfer", tactic: "Lateral Movement",
    description: "Adversaries may transfer tools or other files between systems in a compromised environment. Files may be copied from one system to another to stage adversary tools or other files over the course of an operation.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User"],
    data_sources: ["Command: Command Execution", "File: File Creation", "Named Pipe: Named Pipe Metadata", "Network Share: Network Share Access", "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    detection: "Monitor for file transfers between internal systems, especially executables, scripts, and archives. Detect use of admin shares (C$, ADMIN$), SMB file transfers, and SCP/SFTP between workstations.",
    mitigations: [
      { id: "M1037", name: "Filter Network Traffic", description: "Use network monitoring to detect unusual internal file transfers." },
      { id: "M1031", name: "Network Intrusion Prevention", description: "Inspect internal network traffic for lateral tool transfer patterns." }
    ],
    procedure_examples: [{ group: "APT41", description: "APT41 has transferred malware to additional systems using SMB and admin shares." }]
  },

  // ================================================================
  // COLLECTION (TA0009)
  // ================================================================

  { id: "T1005", name: "Data from Local System", tactic: "Collection",
    description: "Adversaries may search local system sources, such as file systems and configuration files, to find files of interest and sensitive data prior to Exfiltration.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User"],
    data_sources: ["Command: Command Execution", "File: File Access"],
    detection: "Monitor for access to sensitive file locations. Detect bulk file reads, especially of documents, credentials, and database files. Monitor for compression of collected data.",
    mitigations: [
      { id: "M1057", name: "Data Loss Prevention", description: "Use DLP solutions to monitor and restrict access to sensitive data." }
    ],
    procedure_examples: [{ group: "APT29", description: "APT29 has collected documents, emails, and credentials from compromised systems." }]
  },
  { id: "T1113", name: "Screen Capture", tactic: "Collection",
    description: "Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality is included as a feature of many RATs.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User"],
    data_sources: ["Command: Command Execution", "Process: OS API Execution"],
    detection: "Monitor for use of screen capture APIs (BitBlt, CopyFromScreen on Windows; screencapture on macOS; xwd/import on Linux). Detect creation of image files in unusual locations.",
    mitigations: [],
    procedure_examples: [{ group: "Kimsuky", description: "Kimsuky has used screen capture functionality in their RATs to monitor victim activity." }]
  },

  // ================================================================
  // COMMAND AND CONTROL (TA0011)
  // ================================================================

  { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control",
    description: "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic.",
    platforms: ["Windows", "macOS", "Linux", "Network"], permissions_required: ["User"],
    data_sources: ["Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    detection: "Analyze network traffic for unusual patterns in common protocols. Use deep packet inspection to detect C2 traffic disguised as legitimate HTTP/HTTPS, DNS, or SMTP traffic. Monitor for beaconing behavior (regular interval connections).",
    mitigations: [
      { id: "M1031", name: "Network Intrusion Prevention", description: "Use IDS/IPS with signatures for known C2 frameworks." },
      { id: "M1030", name: "Network Segmentation", description: "Segment networks to limit C2 communication paths." }
    ],
    procedure_examples: [{ group: "APT29", description: "APT29 has used HTTPS for C2 communications with Cobalt Strike beacons." }, { group: "Turla", description: "Turla has used HTTP and email protocols for C2 communication." }]
  },
  { id: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control",
    description: "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection. HTTP and HTTPS are the most common, as web traffic is ubiquitous in most environments.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User"],
    data_sources: ["Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    detection: "Monitor HTTP/HTTPS traffic for indicators of C2 communication: unusual User-Agent strings, beaconing patterns, data encoding in HTTP headers or body, connections to known-bad domains. Use JA3/JA3S fingerprinting for TLS-based C2 detection.",
    mitigations: [
      { id: "M1031", name: "Network Intrusion Prevention", description: "Deploy SSL inspection for outbound HTTPS traffic." }
    ],
    procedure_examples: [{ group: "APT28", description: "APT28 has used HTTP and HTTPS for C2 traffic with their X-Agent and Zebrocy malware families." }]
  },
  { id: "T1071.004", name: "Application Layer Protocol: DNS", tactic: "Command and Control",
    description: "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection. DNS tunneling encodes C2 data within DNS query and response packets, which are often permitted through firewalls.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User"],
    data_sources: ["Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    detection: "Monitor for high volumes of DNS queries to a single domain. Detect unusually long subdomain labels (characteristic of DNS tunneling). Analyze DNS traffic for high-entropy query names. Monitor for DNS queries to newly registered domains.",
    mitigations: [
      { id: "M1037", name: "Filter Network Traffic", description: "Block known DNS tunneling tools and unusual DNS query patterns." },
      { id: "M1031", name: "Network Intrusion Prevention", description: "Use DNS-aware IDS/IPS to detect tunneling." }
    ],
    procedure_examples: [{ group: "APT34", description: "APT34 has used DNS tunneling for C2 communication with their BONDUPDATER and QUADAGENT malware." }]
  },
  { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control",
    description: "Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User"],
    data_sources: ["File: File Creation", "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    detection: "Monitor for file downloads using common utilities (curl, wget, certutil, bitsadmin, PowerShell). Detect creation of new executables from network connections. Analyze network traffic for large data transfers from external sources.",
    mitigations: [
      { id: "M1031", name: "Network Intrusion Prevention", description: "Use network security tools to detect and block tool downloads." }
    ],
    procedure_examples: [{ group: "Lazarus Group", description: "Lazarus Group has downloaded additional malware and tools from C2 servers after initial compromise." }]
  },

  // ================================================================
  // EXFILTRATION (TA0010)
  // ================================================================

  { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration",
    description: "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel with the C2 server.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User"],
    data_sources: ["Command: Command Execution", "File: File Access", "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    detection: "Monitor for large data transfers over C2 channels. Analyze network traffic for unusual data volumes in C2 communications. Detect data encoding patterns in outbound traffic.",
    mitigations: [
      { id: "M1031", name: "Network Intrusion Prevention", description: "Monitor for large data transfers and unusual traffic patterns." },
      { id: "M1057", name: "Data Loss Prevention", description: "Use DLP solutions to detect sensitive data in network traffic." }
    ],
    procedure_examples: [{ group: "APT29", description: "APT29 has exfiltrated collected data over their HTTPS C2 channels." }]
  },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration",
    description: "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternative network location from the main C2 server.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["User"],
    data_sources: ["Command: Command Execution", "File: File Access", "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    detection: "Monitor for use of protocols not typically used in the environment for data transfer. Detect DNS exfiltration, ICMP tunneling, and use of cloud storage APIs. Watch for unusual outbound connections on non-standard ports.",
    mitigations: [
      { id: "M1037", name: "Filter Network Traffic", description: "Restrict outbound traffic to only necessary protocols and destinations." },
      { id: "M1057", name: "Data Loss Prevention", description: "Monitor for sensitive data leaving the network via any protocol." },
      { id: "M1030", name: "Network Segmentation", description: "Segment networks to control data flows." }
    ],
    procedure_examples: [{ group: "APT34", description: "APT34 has exfiltrated data via DNS tunneling to avoid network monitoring." }]
  },

  // ================================================================
  // IMPACT (TA0040)
  // ================================================================

  { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact",
    description: "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. This is commonly associated with ransomware.",
    platforms: ["Windows", "macOS", "Linux", "IaaS"], permissions_required: ["User", "Administrator"],
    data_sources: ["Command: Command Execution", "File: File Creation", "File: File Modification", "Process: Process Creation"],
    detection: "Monitor for rapid file modification patterns (many files modified in short time with changed extensions). Detect use of encryption APIs. Watch for deletion of Volume Shadow Copies. Alert on creation of ransom notes.",
    mitigations: [
      { id: "M1053", name: "Data Backup", description: "Maintain offline, tested backups of critical data." },
      { id: "M1040", name: "Behavior Prevention on Endpoint", description: "Use EDR solutions with ransomware-specific detection." }
    ],
    procedure_examples: [{ group: "LockBit", description: "LockBit ransomware encrypts files using AES-256 and RSA-2048, appending .lockbit extension." }, { group: "BlackCat/ALPHV", description: "BlackCat uses Rust-based ransomware that encrypts files on Windows and Linux." }]
  },
  { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact",
    description: "Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system. This ensures that recovery tools and services cannot be used to restore the system after a destructive attack.",
    platforms: ["Windows", "macOS", "Linux"], permissions_required: ["Administrator", "SYSTEM"],
    data_sources: ["Command: Command Execution", "File: File Deletion", "Process: Process Creation", "Service: Service Metadata", "Windows Registry: Windows Registry Key Modification"],
    detection: "Monitor for deletion of Volume Shadow Copies (vssadmin, wmic shadowcopy delete). Detect modification of boot configuration (bcdedit). Watch for disabling of Windows Recovery Environment.",
    mitigations: [
      { id: "M1053", name: "Data Backup", description: "Maintain offline backups that cannot be accessed from the compromised network." },
      { id: "M1028", name: "Operating System Configuration", description: "Restrict access to tools that modify system recovery options." }
    ],
    procedure_examples: [{ group: "REvil", description: "REvil ransomware deletes shadow copies and disables recovery mode before encrypting files." }]
  },
  { id: "T1485", name: "Data Destruction", tactic: "Impact",
    description: "Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques.",
    platforms: ["Windows", "macOS", "Linux", "IaaS"], permissions_required: ["User", "Administrator"],
    data_sources: ["Command: Command Execution", "File: File Deletion", "File: File Modification", "Process: Process Creation"],
    detection: "Monitor for use of disk wiping tools. Detect overwriting of MBR/GPT. Watch for mass file deletion or zeroing. Alert on unusual file system activity patterns consistent with data destruction.",
    mitigations: [
      { id: "M1053", name: "Data Backup", description: "Maintain geographically distributed backups." }
    ],
    procedure_examples: [{ group: "Sandworm Team", description: "Sandworm Team has deployed multiple wiper malware families including NotPetya, Olympic Destroyer, and CaddyWiper against Ukrainian targets." }]
  },
  { id: "T1499", name: "Endpoint Denial of Service", tactic: "Impact",
    description: "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting system resources, exploiting application vulnerabilities, or flooding services with requests.",
    platforms: ["Windows", "macOS", "Linux", "IaaS"], permissions_required: [],
    data_sources: ["Application Log: Application Log Content", "Network Traffic: Network Traffic Flow", "Sensor Health: Host Status"],
    detection: "Monitor for unusual resource consumption on endpoints. Detect application crashes and service failures. Watch for traffic patterns consistent with DoS attacks.",
    mitigations: [
      { id: "M1037", name: "Filter Network Traffic", description: "Use rate limiting and traffic filtering to mitigate DoS attacks." }
    ],
    procedure_examples: [{ group: "Lazarus Group", description: "Lazarus Group has conducted DDoS attacks against South Korean financial institutions." }]
  },
];

export const searchTechniques = (q) => { const l = q.toLowerCase(); return MITRE_TECHNIQUES.filter(t => t.id.toLowerCase().includes(l) || t.name.toLowerCase().includes(l) || t.tactic.toLowerCase().includes(l) || t.description.toLowerCase().includes(l)); };
export const getTacticTechniques = (tactic) => MITRE_TECHNIQUES.filter(t => t.tactic === tactic);
export const getSubtechniques = (parentId) => MITRE_TECHNIQUES.filter(t => t.id.startsWith(parentId + "."));
