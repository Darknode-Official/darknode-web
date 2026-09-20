// Threat Hunting Engine — Proactive threat hunting hypotheses, detection queries, and log references
// Real MITRE technique IDs, real Windows Event IDs, real Sysmon events, real query syntax

// ═══════════════════════════════════════════════════════════════════════════════
// HUNTING HYPOTHESIS LIBRARY — organized by MITRE ATT&CK tactic
// ═══════════════════════════════════════════════════════════════════════════════

export const HUNTING_HYPOTHESES = [
  // ── INITIAL ACCESS ──────────────────────────────────────────────────────────
  {
    id: "HUNT-IA-001", tactic: "Initial Access", technique: "T1566.001",
    name: "Spearphishing Attachment",
    hypothesis: "An adversary delivered a malicious document via email that spawned a child process",
    dataSources: ["Sysmon Event 1", "Email gateway logs", "Windows Event 4688"],
    splunk: 'index=sysmon EventCode=1 (ParentImage="*\\\\WINWORD.EXE" OR ParentImage="*\\\\EXCEL.EXE" OR ParentImage="*\\\\POWERPNT.EXE" OR ParentImage="*\\\\OUTLOOK.EXE") (Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\mshta.exe" OR Image="*\\\\rundll32.exe")',
    kql: 'DeviceProcessEvents | where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe") and FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe")',
    expectedResults: "Office applications spawning scripting engines or command interpreters",
    falsePositives: ["Legitimate macros in business documents", "IT automation triggered by email attachments"],
    severity: "high",
  },
  {
    id: "HUNT-IA-002", tactic: "Initial Access", technique: "T1566.002",
    name: "Spearphishing Link",
    hypothesis: "Users clicked phishing links that downloaded and executed payloads",
    dataSources: ["Web proxy logs", "Sysmon Event 1", "DNS logs"],
    splunk: 'index=proxy action=allowed (url="*drive.google.com/uc*" OR url="*dropbox.com/s/*" OR url="*onedrive.live.com*" OR url="*.sharepoint.com*") earliest=-24h | stats count by src_ip, url, user',
    kql: 'DeviceNetworkEvents | where RemoteUrl has_any ("drive.google.com/uc","dropbox.com/s/","onedrive.live.com") | summarize count() by DeviceName, RemoteUrl',
    expectedResults: "Downloads from cloud storage services initiated by email link clicks",
    falsePositives: ["Legitimate file sharing via cloud platforms"],
    severity: "medium",
  },
  {
    id: "HUNT-IA-003", tactic: "Initial Access", technique: "T1190",
    name: "Exploit Public-Facing Application",
    hypothesis: "Web server was exploited and a web shell was dropped",
    dataSources: ["Web server logs", "File creation events", "Sysmon Event 11"],
    splunk: 'index=sysmon EventCode=11 (TargetFilename="*\\\\inetpub\\\\wwwroot\\\\*" OR TargetFilename="*\\\\www\\\\*" OR TargetFilename="*\\\\htdocs\\\\*") (TargetFilename="*.aspx" OR TargetFilename="*.asp" OR TargetFilename="*.php" OR TargetFilename="*.jsp" OR TargetFilename="*.jspx")',
    kql: 'DeviceFileEvents | where ActionType == "FileCreated" and FolderPath has_any ("inetpub","wwwroot","htdocs","www") and FileName endswith_cs ".aspx" or FileName endswith_cs ".php" or FileName endswith_cs ".jsp"',
    expectedResults: "New script files created in web server directories",
    falsePositives: ["Legitimate web deployments", "CMS updates creating new files"],
    severity: "critical",
  },
  {
    id: "HUNT-IA-004", tactic: "Initial Access", technique: "T1195.002",
    name: "Supply Chain Compromise",
    hypothesis: "A trusted software update delivered malicious code",
    dataSources: ["Sysmon Event 1", "Software inventory", "File hash logs"],
    splunk: 'index=sysmon EventCode=1 Image="*\\\\update*" OR Image="*\\\\setup*" | where NOT [| inputlookup known_good_hashes | fields sha256] | stats count by Image, sha256, ParentImage',
    kql: 'DeviceProcessEvents | where FileName contains "update" or FileName contains "setup" | where not(SHA256 in (known_good_hashes)) | summarize count() by FileName, SHA256, InitiatingProcessFileName',
    expectedResults: "Software updaters running with unknown hashes or spawning unusual children",
    falsePositives: ["New legitimate software versions not yet in hash allowlist"],
    severity: "critical",
  },
  {
    id: "HUNT-IA-005", tactic: "Initial Access", technique: "T1078",
    name: "Valid Accounts — Compromised Credentials",
    hypothesis: "An adversary is using stolen credentials to access systems",
    dataSources: ["Windows Event 4624/4625", "VPN logs", "Azure AD sign-in logs"],
    splunk: 'index=wineventlog EventCode=4624 LogonType=10 | stats dc(src_ip) as unique_sources, values(src_ip) as sources by TargetUserName | where unique_sources > 3',
    kql: 'SecurityEvent | where EventID == 4624 and LogonType == 10 | summarize dcount(IpAddress), make_set(IpAddress) by TargetUserName | where dcount_IpAddress > 3',
    expectedResults: "Single accounts authenticating from multiple geographic locations",
    falsePositives: ["VPN users connecting from different locations", "Shared service accounts"],
    severity: "high",
  },
  {
    id: "HUNT-IA-006", tactic: "Initial Access", technique: "T1078.004",
    name: "Cloud Account Compromise",
    hypothesis: "Adversary accessed cloud tenant using compromised credentials from unusual location",
    dataSources: ["Azure AD sign-in logs", "AWS CloudTrail", "Google Workspace logs"],
    splunk: 'index=azure sourcetype=azure:signin properties.status.errorCode=0 | iplocation properties.ipAddress | stats dc(Country) as countries values(Country) as locations by properties.userPrincipalName | where countries > 2',
    kql: 'SigninLogs | where ResultType == 0 | extend Country = LocationDetails.countryOrRegion | summarize dcount(Country), make_set(Country) by UserPrincipalName | where dcount_Country > 2',
    expectedResults: "Successful logins from geographically impossible travel patterns",
    falsePositives: ["Users traveling internationally", "VPN exit nodes in different countries"],
    severity: "high",
  },

  // ── EXECUTION ───────────────────────────────────────────────────────────────
  {
    id: "HUNT-EX-001", tactic: "Execution", technique: "T1059.001",
    name: "Suspicious PowerShell Execution",
    hypothesis: "Adversary used encoded or obfuscated PowerShell for execution",
    dataSources: ["Sysmon Event 1", "PowerShell ScriptBlock logging (Event 4104)", "Windows Event 4688"],
    splunk: 'index=sysmon EventCode=1 Image="*\\\\powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-e *" OR CommandLine="*encodedcommand*" OR CommandLine="*frombase64*" OR CommandLine="*invoke-expression*" OR CommandLine="*iex*" OR CommandLine="*downloadstring*" OR CommandLine="*downloadfile*" OR CommandLine="*webclient*" OR CommandLine="*bitstransfer*")',
    kql: 'DeviceProcessEvents | where FileName =~ "powershell.exe" and (ProcessCommandLine contains "-enc" or ProcessCommandLine contains "encodedcommand" or ProcessCommandLine contains "frombase64" or ProcessCommandLine contains "downloadstring" or ProcessCommandLine contains "invoke-expression")',
    expectedResults: "PowerShell processes with encoded commands, download cradles, or obfuscation",
    falsePositives: ["Legitimate IT administration scripts", "SCCM/Intune deployment scripts"],
    severity: "high",
  },
  {
    id: "HUNT-EX-002", tactic: "Execution", technique: "T1059.005",
    name: "VBScript/JScript Execution",
    hypothesis: "Adversary used Windows scripting hosts for code execution",
    dataSources: ["Sysmon Event 1", "Windows Event 4688"],
    splunk: 'index=sysmon EventCode=1 (Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe") | eval suspicious=if(match(CommandLine, "(?i)(http|ftp|\\\\\\\\|temp|appdata|programdata)"), "yes", "no") | where suspicious="yes"',
    kql: 'DeviceProcessEvents | where FileName in~ ("wscript.exe","cscript.exe") and (ProcessCommandLine has "http" or ProcessCommandLine has "temp" or ProcessCommandLine has "appdata")',
    expectedResults: "Script hosts executing files from temporary or user-writable locations, or fetching remote content",
    falsePositives: ["Login scripts", "Legitimate VBScript automation"],
    severity: "medium",
  },
  {
    id: "HUNT-EX-003", tactic: "Execution", technique: "T1047",
    name: "WMI Execution",
    hypothesis: "Adversary used WMI for remote code execution",
    dataSources: ["Sysmon Event 1", "WMI logs (Event 5857-5861)", "Windows Event 4688"],
    splunk: 'index=sysmon EventCode=1 Image="*\\\\WMIC.exe" (CommandLine="*process call create*" OR CommandLine="*node:*")',
    kql: 'DeviceProcessEvents | where FileName =~ "wmic.exe" and (ProcessCommandLine contains "process call create" or ProcessCommandLine contains "/node:")',
    expectedResults: "WMIC used for remote process creation on other machines",
    falsePositives: ["Legitimate remote administration using WMIC"],
    severity: "high",
  },
  {
    id: "HUNT-EX-004", tactic: "Execution", technique: "T1053.005",
    name: "Scheduled Task Creation",
    hypothesis: "Adversary created scheduled tasks for execution or persistence",
    dataSources: ["Windows Event 4698", "Sysmon Event 1"],
    splunk: 'index=wineventlog EventCode=4698 | eval suspicious=if(match(TaskContent, "(?i)(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)"), "yes", "no") | where suspicious="yes"',
    kql: 'SecurityEvent | where EventID == 4698 | where EventData contains "powershell" or EventData contains "cmd.exe" or EventData contains "mshta" or EventData contains "rundll32"',
    expectedResults: "New scheduled tasks executing scripting engines or LOLBins",
    falsePositives: ["Software installations creating tasks", "Windows Update tasks"],
    severity: "medium",
  },

  // ── PERSISTENCE ─────────────────────────────────────────────────────────────
  {
    id: "HUNT-PE-001", tactic: "Persistence", technique: "T1547.001",
    name: "Registry Run Key Persistence",
    hypothesis: "Adversary added a registry Run key for persistence",
    dataSources: ["Sysmon Event 13", "Windows Event 4657"],
    splunk: 'index=sysmon EventCode=13 (TargetObject="*\\\\CurrentVersion\\\\Run*" OR TargetObject="*\\\\CurrentVersion\\\\RunOnce*") | where NOT match(Details, "(?i)(microsoft|windows|google|adobe|mozilla|intel|nvidia|realtek)")',
    kql: 'DeviceRegistryEvents | where RegistryKey has "CurrentVersion\\\\Run" and ActionType == "RegistryValueSet" | where not(RegistryValueData has_any ("Microsoft","Windows","Google","Adobe"))',
    expectedResults: "New or modified Run/RunOnce registry values pointing to unusual executables",
    falsePositives: ["Legitimate software registering for autostart"],
    severity: "high",
  },
  {
    id: "HUNT-PE-002", tactic: "Persistence", technique: "T1543.003",
    name: "Service Installation for Persistence",
    hypothesis: "Adversary installed a new Windows service for persistence",
    dataSources: ["Windows Event 7045", "Sysmon Event 13", "Windows Event 4697"],
    splunk: 'index=wineventlog EventCode=7045 | where NOT match(ServiceFileName, "(?i)(system32|syswow64|program files|programdata\\\\microsoft)") | table _time, ComputerName, ServiceName, ServiceFileName, ServiceType, StartType',
    kql: 'SecurityEvent | where EventID == 7045 | where ServiceFileName !contains "System32" and ServiceFileName !contains "Program Files" | project TimeGenerated, Computer, ServiceName, ServiceFileName',
    expectedResults: "New services with executables in unusual locations",
    falsePositives: ["Legitimate software installations", "IT management agents"],
    severity: "high",
  },
  {
    id: "HUNT-PE-003", tactic: "Persistence", technique: "T1546.003",
    name: "WMI Event Subscription Persistence",
    hypothesis: "Adversary created WMI event subscriptions for persistence",
    dataSources: ["Sysmon Event 19/20/21", "WMI logs"],
    splunk: 'index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21) | table _time, Computer, EventType, Operation, User, Consumer, Filter, Name',
    kql: 'DeviceEvents | where ActionType in ("WmiBindEventFilterToConsumer","WmiCreateEventConsumer","WmiCreateEventFilter")',
    expectedResults: "New WMI event filter-to-consumer bindings, especially CommandLineEventConsumer or ActiveScriptEventConsumer",
    falsePositives: ["SCCM WMI subscriptions", "Monitoring tool WMI events"],
    severity: "critical",
  },
  {
    id: "HUNT-PE-004", tactic: "Persistence", technique: "T1574.001",
    name: "DLL Search Order Hijacking",
    hypothesis: "Adversary placed a malicious DLL in a search path to hijack a legitimate application",
    dataSources: ["Sysmon Event 7", "Sysmon Event 11"],
    splunk: 'index=sysmon EventCode=7 (ImageLoaded="*\\\\Users\\\\*" OR ImageLoaded="*\\\\Temp\\\\*" OR ImageLoaded="*\\\\ProgramData\\\\*") Signed=false | stats count by Image, ImageLoaded, sha256',
    kql: 'DeviceImageLoadEvents | where FolderPath has_any ("Users","Temp","ProgramData") and not(IsSigned) | summarize count() by InitiatingProcessFileName, FileName, SHA256',
    expectedResults: "Unsigned DLLs loaded from writable directories by legitimate signed applications",
    falsePositives: ["Development environments", "Portable applications"],
    severity: "high",
  },

  // ── PRIVILEGE ESCALATION ────────────────────────────────────────────────────
  {
    id: "HUNT-PR-001", tactic: "Privilege Escalation", technique: "T1548.002",
    name: "UAC Bypass",
    hypothesis: "Adversary bypassed UAC to gain elevated privileges",
    dataSources: ["Sysmon Event 1", "Sysmon Event 13"],
    splunk: 'index=sysmon EventCode=1 IntegrityLevel=High (ParentImage="*\\\\explorer.exe" OR ParentImage="*\\\\cmd.exe") | where NOT match(Image, "(?i)(consent\\.exe|mmc\\.exe|taskmgr\\.exe)") | eval uac_bypass=if(match(Image, "(?i)(fodhelper|computerdefaults|sdclt|eventvwr|cmstp|mshta)"), "known_bypass", "check")',
    kql: 'DeviceProcessEvents | where ProcessIntegrityLevel == "High" and InitiatingProcessFileName in~ ("explorer.exe","cmd.exe") and FileName in~ ("fodhelper.exe","computerdefaults.exe","sdclt.exe","eventvwr.exe")',
    expectedResults: "Auto-elevated Windows binaries being used to bypass UAC",
    falsePositives: ["Legitimate use of these tools by administrators"],
    severity: "high",
  },
  {
    id: "HUNT-PR-002", tactic: "Privilege Escalation", technique: "T1134.001",
    name: "Token Manipulation",
    hypothesis: "Adversary manipulated access tokens to escalate privileges",
    dataSources: ["Sysmon Event 10", "Windows Event 4672", "Windows Event 4624"],
    splunk: 'index=wineventlog EventCode=4672 SubjectUserName!="SYSTEM" SubjectUserName!="*$" | stats count by SubjectUserName, PrivilegeList | where PrivilegeList="*SeDebugPrivilege*"',
    kql: 'SecurityEvent | where EventID == 4672 and SubjectUserName != "SYSTEM" and SubjectAccount !endswith "$" | where PrivilegeList contains "SeDebugPrivilege"',
    expectedResults: "Non-system accounts acquiring SeDebugPrivilege or SeImpersonatePrivilege",
    falsePositives: ["Debugging by developers", "Legitimate admin operations"],
    severity: "high",
  },

  // ── DEFENSE EVASION ─────────────────────────────────────────────────────────
  {
    id: "HUNT-DE-001", tactic: "Defense Evasion", technique: "T1070.001",
    name: "Event Log Clearing",
    hypothesis: "Adversary cleared Windows event logs to cover tracks",
    dataSources: ["Windows Event 1102", "Windows Event 104", "Sysmon Event 1"],
    splunk: 'index=wineventlog (EventCode=1102 OR EventCode=104) | table _time, ComputerName, SubjectUserName, SubjectDomainName',
    kql: 'SecurityEvent | where EventID == 1102 or EventID == 104 | project TimeGenerated, Computer, SubjectUserName',
    expectedResults: "Security or System event log cleared by any user",
    falsePositives: ["Legitimate log rotation (rare)", "Accidental clearing by admins"],
    severity: "critical",
  },
  {
    id: "HUNT-DE-002", tactic: "Defense Evasion", technique: "T1070.006",
    name: "Timestomping",
    hypothesis: "Adversary modified file timestamps to blend in with legitimate files",
    dataSources: ["Sysmon Event 2", "NTFS $MFT analysis"],
    splunk: 'index=sysmon EventCode=2 | where CreationUtcTime!=PreviousCreationUtcTime | eval time_diff=abs(strptime(CreationUtcTime,"%Y-%m-%d %H:%M:%S")-strptime(PreviousCreationUtcTime,"%Y-%m-%d %H:%M:%S")) | where time_diff > 86400',
    kql: 'DeviceFileEvents | where ActionType == "FileTimestampModified" | where Timestamp - PreviousFileCreationTime > 1d',
    expectedResults: "Files with creation timestamps modified to appear older than they are",
    falsePositives: ["File copy operations that preserve timestamps", "Zip extraction"],
    severity: "medium",
  },
  {
    id: "HUNT-DE-003", tactic: "Defense Evasion", technique: "T1055",
    name: "Process Injection",
    hypothesis: "Adversary injected code into a legitimate process",
    dataSources: ["Sysmon Event 8", "Sysmon Event 10", "Sysmon Event 25"],
    splunk: 'index=sysmon EventCode=8 | where SourceImage!=TargetImage | eval suspicious=if(match(TargetImage, "(?i)(explorer|svchost|lsass|winlogon|csrss|services|smss)"), "yes", "no") | where suspicious="yes"',
    kql: 'DeviceEvents | where ActionType == "CreateRemoteThreadApiCall" | where InitiatingProcessFileName != FileName | where FileName in~ ("explorer.exe","svchost.exe","lsass.exe")',
    expectedResults: "Remote thread creation in system processes from unexpected source processes",
    falsePositives: ["Security tools injecting for monitoring", "Application compatibility shims"],
    severity: "critical",
  },
  {
    id: "HUNT-DE-004", tactic: "Defense Evasion", technique: "T1218.011",
    name: "Rundll32 Proxy Execution",
    hypothesis: "Adversary used rundll32.exe to proxy execution of malicious code",
    dataSources: ["Sysmon Event 1", "Windows Event 4688"],
    splunk: 'index=sysmon EventCode=1 Image="*\\\\rundll32.exe" | where NOT match(CommandLine, "(?i)(shell32|setupapi|advapi|shdocvw|ieproxy|printui|desk\\.cpl)") | where match(CommandLine, "(?i)(http|temp|appdata|users|public)")',
    kql: 'DeviceProcessEvents | where FileName =~ "rundll32.exe" and (ProcessCommandLine has "http" or ProcessCommandLine has "Temp" or ProcessCommandLine has "AppData")',
    expectedResults: "Rundll32 loading DLLs from unusual locations or with suspicious parameters",
    falsePositives: ["Legitimate system DLL loading via rundll32"],
    severity: "medium",
  },
  {
    id: "HUNT-DE-005", tactic: "Defense Evasion", technique: "T1562.001",
    name: "Security Tool Tampering",
    hypothesis: "Adversary disabled or tampered with security tools",
    dataSources: ["Sysmon Event 1", "Windows Event 4688", "Endpoint protection logs"],
    splunk: 'index=sysmon EventCode=1 (CommandLine="*sc stop*" OR CommandLine="*sc delete*" OR CommandLine="*net stop*" OR CommandLine="*taskkill*") | where match(CommandLine, "(?i)(defender|malware|antivirus|crowdstrike|sentinel|carbon|cylance|symantec|mcafee|eset|kaspersky|sophos|trend|panda|avg|avast|bitdefender)")',
    kql: 'DeviceProcessEvents | where (ProcessCommandLine contains "sc stop" or ProcessCommandLine contains "sc delete" or ProcessCommandLine contains "net stop" or ProcessCommandLine contains "taskkill") and ProcessCommandLine has_any ("Defender","MsMpSvc","WinDefend","CrowdStrike","SentinelAgent","CarbonBlack")',
    expectedResults: "Processes attempting to stop, disable, or uninstall security software",
    falsePositives: ["Legitimate security tool upgrades", "IT admin maintenance"],
    severity: "critical",
  },

  // ── CREDENTIAL ACCESS ───────────────────────────────────────────────────────
  {
    id: "HUNT-CA-001", tactic: "Credential Access", technique: "T1003.001",
    name: "LSASS Memory Credential Dumping",
    hypothesis: "Adversary dumped LSASS process memory to extract credentials",
    dataSources: ["Sysmon Event 10", "Windows Event 4656", "Sysmon Event 1"],
    splunk: 'index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe" GrantedAccess="0x1010" OR GrantedAccess="0x1038" | where NOT match(SourceImage, "(?i)(csrss|wininit|wmiprvse|svchost|mrt\\.exe|taskmgr)")',
    kql: 'DeviceEvents | where ActionType == "OpenProcessApiCall" and FileName == "lsass.exe" and not(InitiatingProcessFileName in~ ("csrss.exe","wininit.exe","svchost.exe"))',
    expectedResults: "Processes accessing LSASS memory with read permissions (mimikatz, procdump, etc.)",
    falsePositives: ["Credential Guard enrollment", "Antivirus scanning LSASS"],
    severity: "critical",
  },
  {
    id: "HUNT-CA-002", tactic: "Credential Access", technique: "T1558.003",
    name: "Kerberoasting",
    hypothesis: "Adversary requested TGS tickets for service accounts to crack offline",
    dataSources: ["Windows Event 4769"],
    splunk: 'index=wineventlog EventCode=4769 TicketEncryptionType=0x17 ServiceName!="krbtgt" ServiceName!="*$" | stats count by TargetUserName, ServiceName, IpAddress | where count > 5',
    kql: 'SecurityEvent | where EventID == 4769 and TicketEncryptionType == "0x17" and ServiceName != "krbtgt" and ServiceName !endswith "$" | summarize count() by TargetUserName, ServiceName, IpAddress | where count_ > 5',
    expectedResults: "Bulk TGS requests using RC4 encryption for multiple service accounts",
    falsePositives: ["Legitimate service ticket requests (but usually not in bulk with RC4)"],
    severity: "high",
  },
  {
    id: "HUNT-CA-003", tactic: "Credential Access", technique: "T1003.003",
    name: "NTDS.dit Extraction",
    hypothesis: "Adversary extracted the NTDS.dit file to obtain all domain password hashes",
    dataSources: ["Sysmon Event 1", "Windows Event 4688", "VSS logs"],
    splunk: 'index=sysmon EventCode=1 (CommandLine="*ntds*" OR CommandLine="*vssadmin*shadow*" OR CommandLine="*ntdsutil*" OR CommandLine="*secretsdump*") | where match(CommandLine, "(?i)(copy|create|ifm|snapshot)")',
    kql: 'DeviceProcessEvents | where ProcessCommandLine has_any ("ntds.dit","vssadmin create shadow","ntdsutil ifm","secretsdump")',
    expectedResults: "Commands to create volume shadow copies or extract NTDS.dit from domain controllers",
    falsePositives: ["Legitimate DC backups (but should be from authorized backup tools)"],
    severity: "critical",
  },
  {
    id: "HUNT-CA-004", tactic: "Credential Access", technique: "T1110.003",
    name: "Password Spraying",
    hypothesis: "Adversary attempted a small number of passwords against many accounts",
    dataSources: ["Windows Event 4625", "Azure AD sign-in logs"],
    splunk: 'index=wineventlog EventCode=4625 | bin _time span=1h | stats dc(TargetUserName) as unique_accounts, count by src_ip, _time | where unique_accounts > 20 AND count < unique_accounts * 3',
    kql: 'SecurityEvent | where EventID == 4625 | summarize UniqueAccounts=dcount(TargetUserName), Attempts=count() by IpAddress, bin(TimeGenerated, 1h) | where UniqueAccounts > 20',
    expectedResults: "Many failed logins to different accounts from same source, with few attempts per account",
    falsePositives: ["Vulnerability scanners", "Misconfigured service accounts"],
    severity: "high",
  },

  // ── DISCOVERY ───────────────────────────────────────────────────────────────
  {
    id: "HUNT-DI-001", tactic: "Discovery", technique: "T1087.002",
    name: "Domain Account Enumeration",
    hypothesis: "Adversary enumerated domain accounts for reconnaissance",
    dataSources: ["Sysmon Event 1", "Windows Event 4688", "Windows Event 4661"],
    splunk: 'index=sysmon EventCode=1 (CommandLine="*net user /domain*" OR CommandLine="*net group*" OR CommandLine="*Get-ADUser*" OR CommandLine="*Get-ADGroup*" OR CommandLine="*dsquery*" OR CommandLine="*ldapsearch*" OR CommandLine="*adfind*")',
    kql: 'DeviceProcessEvents | where ProcessCommandLine has_any ("net user /domain","net group","Get-ADUser","Get-ADGroup","dsquery","adfind")',
    expectedResults: "Tools or commands enumerating Active Directory users and groups",
    falsePositives: ["IT administration scripts", "Helpdesk user lookups"],
    severity: "medium",
  },
  {
    id: "HUNT-DI-002", tactic: "Discovery", technique: "T1046",
    name: "Network Service Scanning",
    hypothesis: "Adversary performed internal network scanning",
    dataSources: ["Firewall logs", "IDS/IPS", "Sysmon Event 3"],
    splunk: 'index=sysmon EventCode=3 | bin _time span=5m | stats dc(DestinationPort) as ports, dc(DestinationIp) as hosts by SourceIp, _time | where ports > 20 OR hosts > 50',
    kql: 'DeviceNetworkEvents | summarize PortCount=dcount(RemotePort), HostCount=dcount(RemoteIP) by DeviceName, bin(Timestamp, 5m) | where PortCount > 20 or HostCount > 50',
    expectedResults: "Single host connecting to many ports or many hosts in a short time window",
    falsePositives: ["Vulnerability scanners", "IT monitoring tools", "SCCM client discovery"],
    severity: "high",
  },

  // ── LATERAL MOVEMENT ────────────────────────────────────────────────────────
  {
    id: "HUNT-LM-001", tactic: "Lateral Movement", technique: "T1021.002",
    name: "SMB/Windows Admin Shares",
    hypothesis: "Adversary used administrative shares for lateral movement",
    dataSources: ["Windows Event 5140/5145", "Sysmon Event 3", "Sysmon Event 17/18"],
    splunk: 'index=wineventlog EventCode=5140 ShareName="\\\\\\\\*\\\\C$" OR ShareName="\\\\\\\\*\\\\ADMIN$" | where NOT match(SubjectUserName, "(?i)(SYSTEM|\\$)") | stats count by SubjectUserName, IpAddress, ShareName',
    kql: 'SecurityEvent | where EventID == 5140 and (ShareName endswith "C$" or ShareName endswith "ADMIN$") and SubjectUserName != "SYSTEM" | summarize count() by SubjectUserName, IpAddress, ShareName',
    expectedResults: "Non-system accounts accessing administrative shares on remote systems",
    falsePositives: ["IT administrators managing systems", "Backup systems accessing admin shares"],
    severity: "high",
  },
  {
    id: "HUNT-LM-002", tactic: "Lateral Movement", technique: "T1021.001",
    name: "Suspicious RDP Activity",
    hypothesis: "Adversary used RDP for lateral movement",
    dataSources: ["Windows Event 4624 (Type 10)", "Windows Event 1149", "Sysmon Event 3"],
    splunk: 'index=wineventlog EventCode=4624 LogonType=10 | stats count, dc(TargetUserName) as unique_users by IpAddress | where unique_users > 3',
    kql: 'SecurityEvent | where EventID == 4624 and LogonType == 10 | summarize count(), dcount(TargetUserName) by IpAddress | where dcount_TargetUserName > 3',
    expectedResults: "Single source IP using RDP to authenticate as multiple different users",
    falsePositives: ["IT helpdesk using RDP to support multiple users", "Jump servers"],
    severity: "high",
  },
  {
    id: "HUNT-LM-003", tactic: "Lateral Movement", technique: "T1021.006",
    name: "WinRM Lateral Movement",
    hypothesis: "Adversary used Windows Remote Management for lateral movement",
    dataSources: ["Windows Event 4688", "Sysmon Event 1", "Windows Event 91"],
    splunk: 'index=sysmon EventCode=1 Image="*\\\\wsmprovhost.exe" | stats count by Computer, User, ParentImage',
    kql: 'DeviceProcessEvents | where FileName =~ "wsmprovhost.exe" | summarize count() by DeviceName, AccountName, InitiatingProcessFileName',
    expectedResults: "WinRM provider host spawning on systems, indicating remote PowerShell sessions",
    falsePositives: ["Legitimate remote PowerShell administration", "DSC (Desired State Configuration)"],
    severity: "medium",
  },

  // ── COMMAND AND CONTROL ─────────────────────────────────────────────────────
  {
    id: "HUNT-C2-001", tactic: "Command and Control", technique: "T1071.004",
    name: "DNS Tunneling",
    hypothesis: "Adversary used DNS for command and control or data exfiltration",
    dataSources: ["DNS query logs", "Sysmon Event 22"],
    splunk: 'index=dns | eval domain_length=len(query) | where domain_length > 50 | stats count, avg(domain_length) as avg_len by src_ip | where count > 100 AND avg_len > 40',
    kql: 'DnsEvents | extend DomainLength = strlen(Name) | where DomainLength > 50 | summarize Count=count(), AvgLength=avg(DomainLength) by ClientIP | where Count > 100 and AvgLength > 40',
    expectedResults: "High volume of DNS queries with unusually long domain names (encoded data in subdomains)",
    falsePositives: ["CDN domains with long subdomains", "Anti-spam DNSBL lookups"],
    severity: "high",
  },
  {
    id: "HUNT-C2-002", tactic: "Command and Control", technique: "T1573.002",
    name: "Encrypted C2 with Self-Signed Certificate",
    hypothesis: "Adversary used HTTPS with self-signed certificates for C2",
    dataSources: ["Network traffic logs", "TLS inspection logs", "Zeek logs"],
    splunk: 'index=zeek sourcetype=zeek:ssl validation_status="self signed certificate" | stats count by id.resp_h, server_name | where count > 10',
    kql: 'NetworkSession | where TlsValidation == "SelfSigned" | summarize count() by RemoteIP, RemoteUrl | where count_ > 10',
    expectedResults: "Repeated HTTPS connections to servers with self-signed or invalid certificates",
    falsePositives: ["Internal development servers", "Lab environments", "IoT devices with self-signed certs"],
    severity: "medium",
  },
  {
    id: "HUNT-C2-003", tactic: "Command and Control", technique: "T1090.002",
    name: "Beaconing Detection",
    hypothesis: "Adversary implant is beaconing to a C2 server at regular intervals",
    dataSources: ["Firewall logs", "Proxy logs", "Network flow data"],
    splunk: 'index=firewall action=allowed dest_port=443 | bin _time span=1m | stats count by src_ip, dest_ip, _time | streamstats count as beacon_count reset_after="count=0" by src_ip, dest_ip | where beacon_count > 60',
    kql: 'NetworkSession | where RemotePort == 443 | summarize count() by LocalIP, RemoteIP, bin(Timestamp, 1m) | where count_ > 0 | summarize BeaconMinutes=count() by LocalIP, RemoteIP | where BeaconMinutes > 60',
    expectedResults: "Consistent, periodic connections to the same destination over extended periods",
    falsePositives: ["Software update checks", "Health monitoring endpoints", "Keep-alive connections"],
    severity: "high",
  },

  // ── EXFILTRATION ────────────────────────────────────────────────────────────
  {
    id: "HUNT-EF-001", tactic: "Exfiltration", technique: "T1048.003",
    name: "Data Exfiltration over Alternative Protocol",
    hypothesis: "Adversary exfiltrated data using DNS, ICMP, or other non-standard protocols",
    dataSources: ["DNS logs", "Network flow data", "IDS/IPS"],
    splunk: 'index=dns | stats sum(bytes) as total_bytes by src_ip, query_type | where query_type="TXT" AND total_bytes > 1000000',
    kql: 'DnsEvents | where QueryType == "TXT" | summarize TotalBytes=sum(ResponseSize) by ClientIP | where TotalBytes > 1000000',
    expectedResults: "Large volume of DNS TXT queries or unusually sized ICMP packets indicating data exfiltration",
    falsePositives: ["SPF/DKIM DNS lookups", "Legitimate TXT record queries"],
    severity: "critical",
  },
  {
    id: "HUNT-EF-002", tactic: "Exfiltration", technique: "T1567.002",
    name: "Exfiltration to Cloud Storage",
    hypothesis: "Adversary uploaded stolen data to cloud storage services",
    dataSources: ["Proxy logs", "DLP alerts", "Sysmon Event 3"],
    splunk: 'index=proxy (url="*upload*" OR url="*put*") (url="*drive.google.com*" OR url="*dropbox.com*" OR url="*mega.nz*" OR url="*sendspace*" OR url="*wetransfer*" OR url="*file.io*" OR url="*transfer.sh*") | stats sum(bytes_out) as uploaded by src_ip, user | where uploaded > 10000000',
    kql: 'DeviceNetworkEvents | where RemoteUrl has_any ("drive.google.com","dropbox.com","mega.nz","wetransfer.com","file.io","transfer.sh") | summarize TotalSent=sum(SentBytes) by DeviceName | where TotalSent > 10000000',
    expectedResults: "Large uploads to file sharing or cloud storage services",
    falsePositives: ["Legitimate file sharing", "Cloud backup services"],
    severity: "high",
  },

  // ── IMPACT ──────────────────────────────────────────────────────────────────
  {
    id: "HUNT-IM-001", tactic: "Impact", technique: "T1486",
    name: "Ransomware Indicators",
    hypothesis: "Ransomware is encrypting files on the system",
    dataSources: ["Sysmon Event 11", "Sysmon Event 1", "File system monitoring"],
    splunk: 'index=sysmon EventCode=11 | bin _time span=1m | stats dc(TargetFilename) as files_created by Computer, _time | where files_created > 100',
    kql: 'DeviceFileEvents | where ActionType == "FileCreated" | summarize FileCount=count() by DeviceName, bin(Timestamp, 1m) | where FileCount > 100',
    expectedResults: "Rapid creation of files with new extensions (encrypted files) or ransom note files",
    falsePositives: ["Software installations creating many files", "Build processes"],
    severity: "critical",
  },
  {
    id: "HUNT-IM-002", tactic: "Impact", technique: "T1490",
    name: "Backup Deletion",
    hypothesis: "Adversary deleted backups or volume shadow copies before ransomware deployment",
    dataSources: ["Sysmon Event 1", "Windows Event 4688"],
    splunk: 'index=sysmon EventCode=1 (CommandLine="*vssadmin*delete*shadow*" OR CommandLine="*wmic*shadowcopy*delete*" OR CommandLine="*bcdedit*recoveryenabled*no*" OR CommandLine="*wbadmin*delete*catalog*")',
    kql: 'DeviceProcessEvents | where ProcessCommandLine has_any ("vssadmin delete shadows","wmic shadowcopy delete","bcdedit /set recoveryenabled no","wbadmin delete catalog")',
    expectedResults: "Commands deleting shadow copies, disabling recovery, or deleting backup catalogs",
    falsePositives: ["Legitimate shadow copy management (very rare to delete all)"],
    severity: "critical",
  },
];

// ═══════════════════════════════════════════════════════════════════════════════
// WINDOWS EVENT LOG REFERENCE — Security-relevant Event IDs
// ═══════════════════════════════════════════════════════════════════════════════

export const WINDOWS_EVENT_IDS = {
  // Security log
  4624: { category: "Logon", description: "Successful logon", hunting: "Identify unusual logon types, sources, or times", importance: "high" },
  4625: { category: "Logon", description: "Failed logon attempt", hunting: "Detect brute force, password spray, credential stuffing", importance: "high" },
  4634: { category: "Logon", description: "Account logoff", hunting: "Correlate with logon events for session duration analysis", importance: "low" },
  4648: { category: "Logon", description: "Explicit credential logon (RunAs)", hunting: "Detect lateral movement using explicit credentials", importance: "high" },
  4656: { category: "Object Access", description: "Handle to object requested", hunting: "Detect access to sensitive files, LSASS, SAM", importance: "medium" },
  4657: { category: "Object Access", description: "Registry value modified", hunting: "Detect persistence via registry modification", importance: "high" },
  4663: { category: "Object Access", description: "Attempt to access object", hunting: "File access auditing for sensitive data", importance: "medium" },
  4672: { category: "Logon", description: "Special privileges assigned", hunting: "Detect privilege escalation, SeDebugPrivilege assignment", importance: "high" },
  4688: { category: "Process", description: "New process created", hunting: "Process creation auditing — baseline for all process-based detection", importance: "critical" },
  4689: { category: "Process", description: "Process exited", hunting: "Correlate with 4688 for process lifetime analysis", importance: "low" },
  4697: { category: "System", description: "Service installed", hunting: "Detect persistence via service installation", importance: "high" },
  4698: { category: "System", description: "Scheduled task created", hunting: "Detect persistence via scheduled tasks", importance: "high" },
  4699: { category: "System", description: "Scheduled task deleted", hunting: "Adversary cleanup of persistence mechanism", importance: "medium" },
  4702: { category: "System", description: "Scheduled task updated", hunting: "Modification of existing tasks for persistence", importance: "medium" },
  4720: { category: "Account Mgmt", description: "User account created", hunting: "Detect unauthorized account creation", importance: "high" },
  4722: { category: "Account Mgmt", description: "User account enabled", hunting: "Reactivation of disabled accounts", importance: "medium" },
  4724: { category: "Account Mgmt", description: "Password reset attempt", hunting: "Unauthorized password resets", importance: "medium" },
  4728: { category: "Account Mgmt", description: "Member added to security group", hunting: "Privilege escalation via group membership", importance: "high" },
  4732: { category: "Account Mgmt", description: "Member added to local group", hunting: "Local admin group modification", importance: "high" },
  4735: { category: "Account Mgmt", description: "Local group changed", hunting: "Unauthorized group modification", importance: "medium" },
  4738: { category: "Account Mgmt", description: "User account changed", hunting: "Account modification for persistence or escalation", importance: "medium" },
  4740: { category: "Account Mgmt", description: "Account locked out", hunting: "Brute force detection", importance: "medium" },
  4756: { category: "Account Mgmt", description: "Member added to universal group", hunting: "Domain-level privilege escalation", importance: "high" },
  4768: { category: "Kerberos", description: "TGT requested (AS-REQ)", hunting: "Detect AS-REP roasting (RC4 encryption)", importance: "medium" },
  4769: { category: "Kerberos", description: "TGS requested (TGS-REQ)", hunting: "Detect Kerberoasting (RC4 TGS requests)", importance: "high" },
  4770: { category: "Kerberos", description: "TGS renewed", hunting: "Golden Ticket detection (unusual renewal patterns)", importance: "medium" },
  4771: { category: "Kerberos", description: "Kerberos pre-auth failed", hunting: "Password spraying via Kerberos", importance: "medium" },
  4776: { category: "Credential Validation", description: "NTLM authentication", hunting: "Detect pass-the-hash, NTLM relay", importance: "high" },
  4778: { category: "Logon", description: "Session reconnected", hunting: "RDP session hijacking", importance: "medium" },
  4779: { category: "Logon", description: "Session disconnected", hunting: "RDP session monitoring", importance: "low" },
  4946: { category: "Firewall", description: "Firewall rule added", hunting: "Adversary modifying firewall rules", importance: "medium" },
  4948: { category: "Firewall", description: "Firewall rule deleted", hunting: "Adversary removing firewall rules", importance: "medium" },
  5136: { category: "Directory Service", description: "Directory object modified", hunting: "AD object modification, GPO changes", importance: "high" },
  5140: { category: "File Share", description: "Network share accessed", hunting: "Lateral movement via file shares, admin shares", importance: "high" },
  5145: { category: "File Share", description: "Network share object access checked", hunting: "Detailed file share access auditing", importance: "medium" },
  5156: { category: "Firewall", description: "WFP allowed connection", hunting: "Outbound connection monitoring", importance: "low" },
  5157: { category: "Firewall", description: "WFP blocked connection", hunting: "Blocked outbound connections (C2 attempts)", importance: "medium" },

  // System log
  7034: { category: "Service", description: "Service crashed", hunting: "Exploit-caused service crashes", importance: "medium" },
  7036: { category: "Service", description: "Service started/stopped", hunting: "Security service tampering", importance: "medium" },
  7040: { category: "Service", description: "Service start type changed", hunting: "Persistence via service modification", importance: "high" },
  7045: { category: "Service", description: "New service installed", hunting: "Persistence via new service installation", importance: "critical" },

  // Other
  1102: { category: "Audit", description: "Security log cleared", hunting: "Evidence destruction", importance: "critical" },
  104: { category: "Audit", description: "Event log cleared", hunting: "Evidence destruction (System log)", importance: "critical" },
};

// ═══════════════════════════════════════════════════════════════════════════════
// SYSMON EVENT REFERENCE — All event types with detection guidance
// ═══════════════════════════════════════════════════════════════════════════════

export const SYSMON_EVENTS = {
  1: { name: "Process Creation", description: "Logs process creation with full command line, hashes, parent process", keyFields: ["Image", "CommandLine", "ParentImage", "User", "Hashes", "IntegrityLevel"], hunting: "Foundation of process-based detection — baseline normal, detect anomalies" },
  2: { name: "File Creation Time Changed", description: "Detects timestomping — modification of file creation timestamps", keyFields: ["Image", "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime"], hunting: "Detect anti-forensic timestamp manipulation" },
  3: { name: "Network Connection", description: "Logs TCP/UDP connections with source/dest IP and port", keyFields: ["Image", "DestinationIp", "DestinationPort", "SourceIp", "SourcePort", "Protocol"], hunting: "Detect C2, lateral movement, scanning, data exfiltration" },
  5: { name: "Process Terminated", description: "Logs when a process terminates", keyFields: ["Image", "ProcessId"], hunting: "Correlate with Event 1 for process lifetime analysis" },
  6: { name: "Driver Loaded", description: "Logs kernel driver loading", keyFields: ["ImageLoaded", "Hashes", "Signed", "Signature"], hunting: "Detect rootkits and malicious kernel drivers" },
  7: { name: "Image Loaded", description: "Logs DLL loading into processes", keyFields: ["Image", "ImageLoaded", "Hashes", "Signed"], hunting: "Detect DLL injection, sideloading, unsigned DLL loading" },
  8: { name: "CreateRemoteThread", description: "Logs remote thread creation in another process", keyFields: ["SourceImage", "TargetImage", "StartAddress", "StartModule"], hunting: "Detect process injection techniques" },
  9: { name: "RawAccessRead", description: "Logs raw disk read operations", keyFields: ["Image", "Device"], hunting: "Detect credential dumping from disk (SAM, NTDS.dit)" },
  10: { name: "ProcessAccess", description: "Logs process access operations (OpenProcess)", keyFields: ["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"], hunting: "Detect LSASS credential dumping, process injection" },
  11: { name: "FileCreate", description: "Logs file creation or overwrite", keyFields: ["Image", "TargetFilename", "CreationUtcTime"], hunting: "Detect malware dropping files, web shell creation, ransomware" },
  12: { name: "RegistryEvent (Create/Delete)", description: "Logs registry key/value creation or deletion", keyFields: ["Image", "TargetObject", "EventType"], hunting: "Detect persistence mechanisms, configuration changes" },
  13: { name: "RegistryEvent (Value Set)", description: "Logs registry value modifications", keyFields: ["Image", "TargetObject", "Details"], hunting: "Detect Run key persistence, service modification, security tool tampering" },
  14: { name: "RegistryEvent (Rename)", description: "Logs registry key/value renames", keyFields: ["Image", "TargetObject", "NewName"], hunting: "Detect evasion via registry renaming" },
  15: { name: "FileCreateStreamHash", description: "Logs creation of alternate data streams (ADS)", keyFields: ["Image", "TargetFilename", "Hash"], hunting: "Detect data hiding in NTFS alternate data streams" },
  17: { name: "PipeEvent (Create)", description: "Logs named pipe creation", keyFields: ["Image", "PipeName"], hunting: "Detect C2 channels, lateral movement tools (Cobalt Strike, PsExec)" },
  18: { name: "PipeEvent (Connect)", description: "Logs named pipe connections", keyFields: ["Image", "PipeName"], hunting: "Detect tools connecting to known malicious pipe names" },
  19: { name: "WmiEvent (Filter)", description: "WMI event filter created", keyFields: ["EventType", "Operation", "User", "EventNamespace", "Name", "Query"], hunting: "Detect WMI persistence" },
  20: { name: "WmiEvent (Consumer)", description: "WMI event consumer created", keyFields: ["EventType", "Operation", "User", "Name", "Type", "Destination"], hunting: "Detect WMI persistence — CommandLineEventConsumer is high risk" },
  21: { name: "WmiEvent (Binding)", description: "WMI filter-consumer binding", keyFields: ["EventType", "Operation", "User", "Consumer", "Filter"], hunting: "WMI persistence binding — completes the persistence chain" },
  22: { name: "DNSEvent", description: "DNS query results", keyFields: ["Image", "QueryName", "QueryResults", "QueryStatus"], hunting: "Detect C2 domains, DGA domains, DNS tunneling" },
  23: { name: "FileDelete", description: "File deletion logged with archived content", keyFields: ["Image", "TargetFilename", "Hashes", "IsExecutable"], hunting: "Detect evidence destruction, malware self-deletion" },
  24: { name: "ClipboardChange", description: "Clipboard content change", keyFields: ["Image", "Session", "ClientInfo"], hunting: "Detect clipboard data theft" },
  25: { name: "ProcessTampering", description: "Process image modification (hollowing/herpaderp)", keyFields: ["Image", "Type"], hunting: "Detect advanced process manipulation techniques" },
  26: { name: "FileDeleteDetected", description: "File deletion detected (no archiving)", keyFields: ["Image", "TargetFilename"], hunting: "Lightweight file deletion monitoring" },
};

// ═══════════════════════════════════════════════════════════════════════════════
// LINUX AUDIT LOG REFERENCE
// ═══════════════════════════════════════════════════════════════════════════════

export const LINUX_AUDIT_REFERENCE = {
  keyLogFiles: [
    { path: "/var/log/auth.log", description: "Authentication events (SSH, sudo, PAM)", hunting: "Brute force, privilege escalation, unauthorized access" },
    { path: "/var/log/syslog", description: "System events and service logs", hunting: "Service manipulation, system changes" },
    { path: "/var/log/kern.log", description: "Kernel messages", hunting: "Kernel exploits, module loading, hardware issues" },
    { path: "/var/log/cron", description: "Cron job execution logs", hunting: "Persistence via cron, unauthorized scheduled tasks" },
    { path: "/var/log/secure", description: "Authentication and authorization (RHEL/CentOS)", hunting: "Same as auth.log for Red Hat based systems" },
    { path: "/var/log/audit/audit.log", description: "Linux audit daemon logs", hunting: "Detailed system call auditing, file access, process execution" },
    { path: "/var/log/wtmp", description: "Login records (binary)", hunting: "Login history, session tracking" },
    { path: "/var/log/btmp", description: "Failed login records (binary)", hunting: "Brute force attack detection" },
    { path: "/var/log/lastlog", description: "Last login per user (binary)", hunting: "Identify dormant accounts being used" },
    { path: "/var/log/faillog", description: "Failed login attempts per user", hunting: "Account targeting" },
    { path: "~/.bash_history", description: "Bash command history per user", hunting: "Post-compromise activity reconstruction" },
  ],
  auditdRules: [
    { rule: '-w /etc/passwd -p wa -k identity', description: "Monitor password file changes" },
    { rule: '-w /etc/shadow -p wa -k identity', description: "Monitor shadow file changes" },
    { rule: '-w /etc/sudoers -p wa -k privilege_escalation', description: "Monitor sudoers modifications" },
    { rule: '-w /etc/ssh/sshd_config -p wa -k ssh_config', description: "Monitor SSH config changes" },
    { rule: '-a always,exit -F arch=b64 -S execve -k process_execution', description: "Log all process executions" },
    { rule: '-w /tmp -p x -k tmp_exec', description: "Monitor execution from /tmp" },
    { rule: '-w /var/tmp -p x -k vartmp_exec', description: "Monitor execution from /var/tmp" },
    { rule: '-w /dev/shm -p x -k shm_exec', description: "Monitor execution from shared memory" },
    { rule: '-a always,exit -F arch=b64 -S connect -k network_connect', description: "Log network connections" },
    { rule: '-w /etc/crontab -p wa -k cron_persistence', description: "Monitor crontab changes" },
    { rule: '-w /etc/cron.d/ -p wa -k cron_persistence', description: "Monitor cron.d directory" },
    { rule: '-w /var/spool/cron/ -p wa -k cron_persistence', description: "Monitor user crontabs" },
    { rule: '-a always,exit -F arch=b64 -S ptrace -k process_injection', description: "Monitor ptrace (debugging/injection)" },
    { rule: '-a always,exit -F arch=b64 -S init_module -S finit_module -k kernel_module', description: "Monitor kernel module loading" },
    { rule: '-w /etc/ld.so.preload -p wa -k ld_preload', description: "Monitor LD_PRELOAD persistence" },
  ],
};

// ═══════════════════════════════════════════════════════════════════════════════
// CLOUD LOG REFERENCE — Security-relevant events
// ═══════════════════════════════════════════════════════════════════════════════

export const CLOUD_LOG_REFERENCE = {
  aws: {
    name: "AWS CloudTrail",
    criticalEvents: [
      { event: "ConsoleLogin", description: "AWS Console sign-in", hunting: "Unusual login times, locations, MFA status" },
      { event: "CreateUser", description: "New IAM user created", hunting: "Unauthorized user creation" },
      { event: "CreateAccessKey", description: "New access key created", hunting: "Persistence via access keys" },
      { event: "AttachUserPolicy", description: "Policy attached to user", hunting: "Privilege escalation" },
      { event: "AttachRolePolicy", description: "Policy attached to role", hunting: "Privilege escalation via role" },
      { event: "PutBucketPolicy", description: "S3 bucket policy changed", hunting: "Data exposure, exfiltration setup" },
      { event: "PutBucketAcl", description: "S3 bucket ACL changed", hunting: "Making buckets public" },
      { event: "DeleteTrail", description: "CloudTrail trail deleted", hunting: "Evidence destruction" },
      { event: "StopLogging", description: "CloudTrail logging stopped", hunting: "Evidence destruction" },
      { event: "AuthorizeSecurityGroupIngress", description: "Security group rule added", hunting: "Opening ports to attackers" },
      { event: "RunInstances", description: "EC2 instance launched", hunting: "Cryptomining, C2 infrastructure" },
      { event: "CreateFunction", description: "Lambda function created", hunting: "Backdoor via Lambda" },
      { event: "PutRolePolicy", description: "Inline policy on role changed", hunting: "Privilege escalation" },
      { event: "AssumeRole", description: "Role assumed", hunting: "Lateral movement between accounts" },
      { event: "GetSecretValue", description: "Secrets Manager secret read", hunting: "Credential theft" },
      { event: "CreateKeyPair", description: "EC2 key pair created", hunting: "Persistence via SSH keys" },
      { event: "ModifyInstanceAttribute", description: "EC2 instance modified", hunting: "Disabling termination protection" },
      { event: "DeactivateMFADevice", description: "MFA device deactivated", hunting: "Weakening authentication" },
      { event: "CreateLoginProfile", description: "Console password created for IAM user", hunting: "Enabling console access" },
    ],
  },
  azure: {
    name: "Azure Activity Log / Azure AD",
    criticalEvents: [
      { event: "Sign-in activity", description: "User sign-in to Azure AD", hunting: "Impossible travel, unusual locations, compromised accounts" },
      { event: "Add member to role", description: "User added to Azure AD role", hunting: "Privilege escalation" },
      { event: "Add owner to application", description: "Owner added to app registration", hunting: "Persistence via app ownership" },
      { event: "Add app role assignment", description: "App permission granted", hunting: "Excessive API permissions" },
      { event: "Consent to application", description: "OAuth app consent granted", hunting: "Illicit consent grant attack" },
      { event: "Update application", description: "App registration modified", hunting: "Credential addition to apps" },
      { event: "Add service principal", description: "Service principal created", hunting: "Backdoor via service principals" },
      { event: "Reset user password", description: "Password reset by admin", hunting: "Account takeover" },
      { event: "Disable Strong Authentication", description: "MFA disabled for user", hunting: "Authentication weakening" },
      { event: "Create or update NSG rule", description: "Network security group modified", hunting: "Opening network access" },
      { event: "Delete diagnostic setting", description: "Logging disabled", hunting: "Evidence destruction" },
      { event: "Create or update key vault", description: "Key Vault modification", hunting: "Credential access" },
    ],
  },
  gcp: {
    name: "GCP Admin Activity / Data Access Audit Logs",
    criticalEvents: [
      { event: "google.login.LoginService.loginSuccess", description: "Successful console login", hunting: "Unusual login patterns" },
      { event: "SetIamPolicy", description: "IAM policy modified", hunting: "Privilege escalation" },
      { event: "CreateServiceAccount", description: "Service account created", hunting: "Persistence" },
      { event: "CreateServiceAccountKey", description: "Service account key created", hunting: "Credential theft/persistence" },
      { event: "storage.buckets.update", description: "Storage bucket modified", hunting: "Data exposure" },
      { event: "compute.instances.insert", description: "VM instance created", hunting: "Cryptomining, C2" },
      { event: "compute.firewalls.insert", description: "Firewall rule created", hunting: "Opening network access" },
      { event: "logging.sinks.delete", description: "Log sink deleted", hunting: "Evidence destruction" },
      { event: "SetBucketIamPolicy", description: "Bucket IAM policy changed", hunting: "Data access modification" },
    ],
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
// HUNT SCORING MODEL
// ═══════════════════════════════════════════════════════════════════════════════

export function scoreHunt({ threatLikelihood, orgRelevance, dataAvailability, detectionGap, effort }) {
  const clamp = v => Math.max(0, Math.min(10, v || 0));
  const tl = clamp(threatLikelihood);
  const or_ = clamp(orgRelevance);
  const da = clamp(dataAvailability);
  const dg = clamp(detectionGap);
  const ef = clamp(effort);

  const score = (tl * 0.25 + or_ * 0.25 + dg * 0.20 + da * 0.15 + (10 - ef) * 0.15);
  let priority;
  if (score >= 8) priority = "critical";
  else if (score >= 6) priority = "high";
  else if (score >= 4) priority = "medium";
  else priority = "low";

  return {
    score: Math.round(score * 10) / 10, priority,
    breakdown: { threatLikelihood: tl, orgRelevance: or_, dataAvailability: da, detectionGap: dg, effort: ef },
    recommendation: priority === "critical" ? "Execute this hunt immediately" :
      priority === "high" ? "Schedule within this sprint" :
      priority === "medium" ? "Add to hunt backlog" :
      "Nice-to-have — execute when resources allow",
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

export function searchHypotheses(query) {
  const q = query.toLowerCase();
  return HUNTING_HYPOTHESES.filter(h =>
    h.name.toLowerCase().includes(q) ||
    h.hypothesis.toLowerCase().includes(q) ||
    h.tactic.toLowerCase().includes(q) ||
    h.technique.toLowerCase().includes(q) ||
    h.id.toLowerCase().includes(q)
  );
}

export function getHypothesesByTactic(tactic) {
  return HUNTING_HYPOTHESES.filter(h => h.tactic.toLowerCase() === tactic.toLowerCase());
}

export function getHypothesesByTechnique(techniqueId) {
  return HUNTING_HYPOTHESES.filter(h => h.technique === techniqueId);
}

export function getHypothesesBySeverity(severity) {
  return HUNTING_HYPOTHESES.filter(h => h.severity === severity);
}

export function getEventInfo(eventId) {
  return WINDOWS_EVENT_IDS[eventId] || SYSMON_EVENTS[eventId] || null;
}

export function getHighValueEvents() {
  const result = [];
  for (const [id, info] of Object.entries(WINDOWS_EVENT_IDS)) {
    if (info.importance === "critical" || info.importance === "high") {
      result.push({ source: "Windows Security", eventId: parseInt(id), ...info });
    }
  }
  for (const [id, info] of Object.entries(SYSMON_EVENTS)) {
    result.push({ source: "Sysmon", eventId: parseInt(id), name: info.name, description: info.description, hunting: info.hunting });
  }
  return result;
}

export function generateHuntPlan(targetEnvironment) {
  const env = (targetEnvironment || "").toLowerCase();
  let hunts;

  if (env.includes("windows") || env.includes("active directory") || env.includes("ad")) {
    hunts = HUNTING_HYPOTHESES.filter(h => h.splunk || h.dataSources.some(d => /windows|sysmon|event/i.test(d)));
  } else if (env.includes("cloud") || env.includes("aws") || env.includes("azure") || env.includes("gcp")) {
    hunts = HUNTING_HYPOTHESES.filter(h => h.dataSources.some(d => /cloud|azure|aws|gcp/i.test(d)) || h.technique.includes("078.004"));
  } else if (env.includes("linux")) {
    hunts = HUNTING_HYPOTHESES.filter(h => h.dataSources.some(d => /linux|audit/i.test(d)));
  } else {
    hunts = HUNTING_HYPOTHESES;
  }

  return {
    environment: targetEnvironment || "General",
    totalHunts: hunts.length,
    bySeverity: {
      critical: hunts.filter(h => h.severity === "critical").length,
      high: hunts.filter(h => h.severity === "high").length,
      medium: hunts.filter(h => h.severity === "medium").length,
    },
    hunts: hunts.sort((a, b) => {
      const sev = { critical: 3, high: 2, medium: 1, low: 0 };
      return (sev[b.severity] || 0) - (sev[a.severity] || 0);
    }),
  };
}
