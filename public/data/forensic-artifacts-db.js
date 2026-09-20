// Digital Forensic Artifacts Reference Database
// Comprehensive forensic artifact locations, analysis tools, and investigative value
// For incident response, threat hunting, and digital forensics education

export const FORENSIC_ARTIFACTS_DB = [
  // ============================================================
  // WINDOWS — REGISTRY HIVES
  // ============================================================
  {
    os: "Windows",
    category: "Registry",
    artifact: "SAM (Security Account Manager)",
    path: "C:\\Windows\\System32\\config\\SAM",
    description: "Contains local user accounts, password hashes (NTLM), account creation times, last login times, login counts, and account policies. Locked by OS during runtime — requires offline access or volume shadow copies.",
    tool: "impacket-secretsdump, mimikatz, Registry Explorer, RECmd",
    reveals: "Local user accounts, NTLM password hashes, account creation dates, last logon timestamps, bad password counts, account lockout status",
    mitre: "T1003.002 — OS Credential Dumping: Security Account Manager",
    evidenceType: "Credential Access, User Account Activity"
  },
  {
    os: "Windows",
    category: "Registry",
    artifact: "SYSTEM Hive",
    path: "C:\\Windows\\System32\\config\\SYSTEM",
    description: "Contains system configuration: services, drivers, hardware profiles, boot configuration, control sets (CurrentControlSet), computer name, timezone, network interfaces, and the Boot Key needed to decrypt SAM hashes.",
    tool: "Registry Explorer, RECmd, RegRipper",
    reveals: "Computer name, timezone (TimeZoneInformation), services and drivers (Services key), mounted devices, network interfaces (Tcpip\\Parameters), USB device history, shutdown time (Windows\\CurrentVersion\\ShutdownTime)",
    mitre: "T1012 — Query Registry",
    evidenceType: "System Configuration, Timeline Correlation"
  },
  {
    os: "Windows",
    category: "Registry",
    artifact: "SOFTWARE Hive",
    path: "C:\\Windows\\System32\\config\\SOFTWARE",
    description: "Machine-wide software settings: installed programs, OS version, networking config, startup programs (Run/RunOnce keys), registered COM objects, TypedURLs, and application-specific settings.",
    tool: "Registry Explorer, RECmd, RegRipper",
    reveals: "Installed software (Uninstall key), OS version and build (CurrentVersion), registered file associations, network profiles (NetworkList\\Profiles), autorun programs, last-used applications",
    mitre: "T1012 — Query Registry",
    evidenceType: "Software Inventory, Persistence Mechanisms"
  },
  {
    os: "Windows",
    category: "Registry",
    artifact: "SECURITY Hive",
    path: "C:\\Windows\\System32\\config\\SECURITY",
    description: "Contains LSA secrets (cached service account credentials, auto-logon passwords, VPN/WiFi passwords), security policies, cached domain logon credentials (DCC2 hashes), and audit policies.",
    tool: "impacket-secretsdump, mimikatz, Registry Explorer",
    reveals: "Cached domain credentials (last 10 domain logons), LSA secrets (service account passwords, DefaultPassword), security audit policies, trust relationships",
    mitre: "T1003.004 — OS Credential Dumping: LSA Secrets",
    evidenceType: "Credential Access, Security Configuration"
  },
  {
    os: "Windows",
    category: "Registry",
    artifact: "NTUSER.DAT",
    path: "C:\\Users\\<username>\\NTUSER.DAT",
    description: "Per-user registry hive (HKEY_CURRENT_USER). Contains user preferences, recently accessed files, typed URLs, search queries, application MRU (Most Recently Used) lists, and user-specific autorun entries.",
    tool: "Registry Explorer, RECmd, RegRipper",
    reveals: "Recent documents (RecentDocs), typed paths (TypedPaths), typed URLs (TypedURLs), Run/RunOnce autoruns, mounted network drives (Map Network Drive MRU), search history (WordWheelQuery), user assist (program launch counts and timestamps)",
    mitre: "T1552.002 — Unsecured Credentials: Credentials in Registry",
    evidenceType: "User Activity, Program Execution"
  },
  {
    os: "Windows",
    category: "Registry",
    artifact: "UsrClass.dat",
    path: "C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat",
    description: "User-specific class registrations including ShellBags — records of every folder the user has browsed in Explorer, including folders on network shares, USB drives, and zip files that no longer exist.",
    tool: "ShellBags Explorer, Registry Explorer, SBECmd",
    reveals: "Folder access history (ShellBags) with timestamps, including deleted folders, network shares accessed, USB drive contents browsed, zip file contents viewed, control panel items accessed",
    mitre: "T1083 — File and Directory Discovery",
    evidenceType: "User Activity, File Access History"
  },
  {
    os: "Windows",
    category: "Registry",
    artifact: "Amcache.hve",
    path: "C:\\Windows\\AppCompat\\Programs\\Amcache.hve",
    description: "Application compatibility cache — records metadata about every executable that has been run or installed. Includes SHA1 hash, full path, size, publisher, compile time, and first run time. Survives file deletion.",
    tool: "AmcacheParser (Eric Zimmerman), Registry Explorer",
    reveals: "Executed program paths and SHA1 hashes, program size and compile timestamp, publisher information, installation source path, first execution time, USB device connections (DevicePnp key)",
    mitre: "T1059 — Command and Scripting Interpreter",
    evidenceType: "Program Execution, Malware Analysis"
  },
  {
    os: "Windows",
    category: "Registry",
    artifact: "ShimCache (AppCompatCache)",
    path: "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
    description: "Application Compatibility Cache — records file path, size, and last modified time for executables the OS has seen. On Windows 10+, tracks whether the file was executed. Entries persist across reboots in SYSTEM hive. Up to 1024 entries.",
    tool: "AppCompatCacheParser (Eric Zimmerman), ShimCacheParser",
    reveals: "File paths of executed (or referenced) programs, file sizes, last modified timestamps, execution flag (Win10+). Proves a file existed on the system even if since deleted.",
    mitre: "T1059 — Command and Scripting Interpreter",
    evidenceType: "Program Execution, File Existence"
  },
  {
    os: "Windows",
    category: "Registry",
    artifact: "BAM/DAM (Background Activity Moderator)",
    path: "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\<SID>",
    description: "Windows 10 1709+ artifact — tracks the full path and last execution time of programs run by each user. Updated in real-time and survives reboots. Limited to recent executions (not historical).",
    tool: "Registry Explorer, RECmd",
    reveals: "Full path of executed program, execution timestamp with user SID attribution. Directly ties program execution to a specific user account.",
    mitre: "T1059 — Command and Scripting Interpreter",
    evidenceType: "Program Execution, User Attribution"
  },
  {
    os: "Windows",
    category: "Registry",
    artifact: "UserAssist",
    path: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
    description: "Tracks GUI program execution: programs launched from Start Menu, Desktop, taskbar. Values are ROT13 encoded. Records run count, focus time, and last execution time for each program.",
    tool: "UserAssist (Didier Stevens), Registry Explorer, NirSoft UserAssistView",
    reveals: "Programs launched via GUI (not command-line), execution count, total focus time in foreground, last execution timestamp. ROT13 encoding on keys — trivial to decode.",
    mitre: "T1204.002 — User Execution: Malicious File",
    evidenceType: "Program Execution, User Interaction"
  },
  {
    os: "Windows",
    category: "Registry",
    artifact: "MUICache",
    path: "NTUSER.DAT\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
    description: "Records the display name of every executable that has been run. Stores the application name string for UI display. Simple but useful — no timestamps but proves execution.",
    tool: "Registry Explorer, NirSoft MUICacheView",
    reveals: "Executed program paths and their friendly display names. Lightweight execution evidence — confirms a program was run by the user.",
    mitre: "T1059 — Command and Scripting Interpreter",
    evidenceType: "Program Execution"
  },

  // ============================================================
  // WINDOWS — EVENT LOGS
  // ============================================================
  {
    os: "Windows",
    category: "Event Logs",
    artifact: "Security Event Log",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    description: "Primary security audit log. Records logon/logoff events, object access, privilege use, account management, policy changes, and detailed process tracking when audit policies are enabled.",
    tool: "Event Viewer, EvtxECmd (Eric Zimmerman), Chainsaw, hayabusa, Get-WinEvent PowerShell",
    reveals: "4624 (successful logon with type), 4625 (failed logon), 4634/4647 (logoff), 4648 (explicit credential logon — runas), 4672 (special privileges assigned), 4688 (process creation with command line), 4720/4726 (account created/deleted), 4728/4732 (group membership changes), 4768/4769/4771 (Kerberos events), 5140/5145 (share access), 1102 (audit log cleared)",
    mitre: "T1070.001 — Indicator Removal: Clear Windows Event Logs",
    evidenceType: "Authentication, Process Execution, Account Management"
  },
  {
    os: "Windows",
    category: "Event Logs",
    artifact: "System Event Log",
    path: "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
    description: "System-level events: service start/stop, driver loading, system time changes, shutdown/startup events, disk errors, group policy processing, Windows Update.",
    tool: "Event Viewer, EvtxECmd, Chainsaw",
    reveals: "7034/7035/7036 (service crash/start/stop), 7040 (service start type changed), 7045 (new service installed — persistence/lateral movement indicator), 6005/6006/6008 (system startup/shutdown/unexpected), 104 (event log cleared), 1 (system time changed)",
    mitre: "T1543.003 — Create or Modify System Process: Windows Service",
    evidenceType: "System Events, Service Activity, Persistence"
  },
  {
    os: "Windows",
    category: "Event Logs",
    artifact: "PowerShell Operational Log",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
    description: "Logs PowerShell activity when script block logging and module logging are enabled. Captures full script content, including decoded/deobfuscated commands.",
    tool: "Event Viewer, EvtxECmd, Chainsaw, PowerShell ISE",
    reveals: "4103 (module logging — cmdlets executed), 4104 (script block logging — full script content, including decoded layers), 4105/4106 (script block start/stop). Critical for detecting encoded PowerShell, fileless malware, and Living-off-the-Land techniques.",
    mitre: "T1059.001 — Command and Scripting Interpreter: PowerShell",
    evidenceType: "Script Execution, Malware Detection"
  },
  {
    os: "Windows",
    category: "Event Logs",
    artifact: "Sysmon Event Log",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
    description: "Sysmon (System Monitor) provides detailed endpoint telemetry when installed. Logs process creation with full command lines, network connections, file creation/modification times, registry changes, WMI events, DNS queries, and more.",
    tool: "Event Viewer, EvtxECmd, Chainsaw, hayabusa",
    reveals: "Event 1 (process creation with hashes, parent process), Event 3 (network connection with dest IP/port), Event 7 (image loaded — DLL), Event 8 (CreateRemoteThread — injection), Event 10 (ProcessAccess — credential dumping), Event 11 (file created), Event 13 (registry value set), Event 22 (DNS query), Event 23 (file deleted archived), Event 25 (process tampering — hollowing/herpaderping)",
    mitre: "T1562.001 — Impair Defenses: Disable or Modify Tools",
    evidenceType: "Detailed Endpoint Telemetry"
  },
  {
    os: "Windows",
    category: "Event Logs",
    artifact: "Windows Defender Operational Log",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx",
    description: "Records Windows Defender detection events, scan results, definition updates, exclusion changes, tamper protection events, and real-time protection status.",
    tool: "Event Viewer, EvtxECmd",
    reveals: "1116/1117 (malware detected/action taken), 5001 (real-time protection disabled), 5007 (configuration changed — exclusions added), 1006/1007 (scan results), 1013 (malware history deleted). Exclusion additions are a key indicator of defense evasion.",
    mitre: "T1562.001 — Impair Defenses: Disable or Modify Tools",
    evidenceType: "Malware Detection, Defense Evasion"
  },
  {
    os: "Windows",
    category: "Event Logs",
    artifact: "Task Scheduler Operational Log",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx",
    description: "Records scheduled task creation, modification, execution, and deletion events. Critical for detecting persistence via scheduled tasks.",
    tool: "Event Viewer, EvtxECmd",
    reveals: "106 (task registered), 140 (task updated), 141 (task deleted), 200/201 (task started/completed). Task creation from unusual contexts (cmd.exe, PowerShell, SYSTEM) indicates potential persistence mechanism.",
    mitre: "T1053.005 — Scheduled Task/Job: Scheduled Task",
    evidenceType: "Persistence, Task Execution"
  },
  {
    os: "Windows",
    category: "Event Logs",
    artifact: "TerminalServices-RemoteConnectionManager",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    description: "Records incoming RDP connection attempts with source IP, regardless of authentication outcome. Essential for tracking lateral movement via RDP.",
    tool: "Event Viewer, EvtxECmd",
    reveals: "1149 (RDP authentication succeeded — source IP and username), 261 (listener receiving connection). Correlate with Security 4624 logon type 10 for complete RDP session tracking.",
    mitre: "T1021.001 — Remote Services: Remote Desktop Protocol",
    evidenceType: "Remote Access, Lateral Movement"
  },
  {
    os: "Windows",
    category: "Event Logs",
    artifact: "WMI-Activity Operational Log",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-WMI-Activity%4Operational.evtx",
    description: "Records WMI provider and consumer activity. WMI is heavily used for lateral movement (wmiexec), persistence (event subscriptions), and reconnaissance.",
    tool: "Event Viewer, EvtxECmd",
    reveals: "5857 (WMI provider loaded), 5858 (WMI query errors), 5859/5860 (WMI event subscription created). WMI event subscriptions are a stealthy persistence mechanism — monitor creation events.",
    mitre: "T1047 — Windows Management Instrumentation",
    evidenceType: "Lateral Movement, Persistence"
  },

  // ============================================================
  // WINDOWS — FILE SYSTEM ARTIFACTS
  // ============================================================
  {
    os: "Windows",
    category: "Filesystem",
    artifact: "Prefetch Files",
    path: "C:\\Windows\\Prefetch\\*.pf",
    description: "Windows Prefetch records metadata about every executable that runs. Tracks last 8 execution times (Win8+), run count, file/directory references, and volume information. Created on first execution, updated on subsequent runs.",
    tool: "PECmd (Eric Zimmerman), WinPrefetchView (NirSoft)",
    reveals: "Executable name and path, last 8 execution timestamps, total run count, files and directories referenced during execution, volume serial number and creation time. Proves program execution even after the executable is deleted.",
    mitre: "T1059 — Command and Scripting Interpreter",
    evidenceType: "Program Execution, Timeline"
  },
  {
    os: "Windows",
    category: "Filesystem",
    artifact: "$MFT (Master File Table)",
    path: "C:\\ (raw disk access, $MFT is the first file)",
    description: "NTFS metadata file containing an entry for every file and directory on the volume. Records file name, size, timestamps (Created, Modified, Accessed, Entry Modified — MACE), parent directory, data runs, alternate data streams, and security descriptors.",
    tool: "MFTECmd (Eric Zimmerman), analyzeMFT, Autopsy",
    reveals: "Complete file listing including deleted files (entries may persist), all four NTFS timestamps (MACE) in both $STANDARD_INFORMATION and $FILE_NAME attributes, file sizes, parent directory relationships, alternate data streams, resident file data (<~700 bytes stored in MFT entry itself)",
    mitre: "T1070.004 — Indicator Removal: File Deletion",
    evidenceType: "File System Forensics, Timeline, Deleted File Recovery"
  },
  {
    os: "Windows",
    category: "Filesystem",
    artifact: "$UsnJrnl (USN Change Journal)",
    path: "C:\\$Extend\\$UsnJrnl:$J (raw access)",
    description: "NTFS change journal recording every file system operation: creation, deletion, rename, data change, attribute change. Rolling log — older entries are purged as journal grows. $J is the data stream, $Max contains journal metadata.",
    tool: "MFTECmd (Eric Zimmerman), fsutil usn readjournal",
    reveals: "File creation/deletion/rename/modification events with timestamps, parent directory, reason flags (DATA_OVERWRITE, FILE_DELETE, RENAME_NEW_NAME, etc.). Critical for timeline analysis — shows file operations in chronological order even for deleted files.",
    mitre: "T1070.004 — Indicator Removal: File Deletion",
    evidenceType: "File Activity Timeline, Deleted File Evidence"
  },
  {
    os: "Windows",
    category: "Filesystem",
    artifact: "SRUM (System Resource Usage Monitor)",
    path: "C:\\Windows\\System32\\SRU\\SRUDB.dat",
    description: "Windows 8+ artifact tracking resource usage per application: network data sent/received, CPU time, energy usage. Retains 30-60 days of data. ESE database format.",
    tool: "srum-dump, SrumECmd (Eric Zimmerman), Autopsy",
    reveals: "Network bytes sent/received per application with timestamps, CPU cycles used, energy usage, application launch count. Proves an application was running and transferred data even if no longer present. Associates network activity with specific executables.",
    mitre: "T1049 — System Network Connections Discovery",
    evidenceType: "Network Activity, Application Usage"
  },
  {
    os: "Windows",
    category: "Filesystem",
    artifact: "LNK Files (Shortcuts)",
    path: "C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk",
    description: "Automatically created when a user opens a file. Contains target file metadata: path, size, timestamps, volume serial, MAC address of host machine. Persist even after target file is deleted.",
    tool: "LECmd (Eric Zimmerman), NirSoft ShortcutLinkView",
    reveals: "Target file path (including network paths — UNC), target file timestamps (Created/Modified/Accessed), target file size, volume name/serial/type, machine MAC address and NetBIOS name (for network targets). Proves file was accessed from specific location.",
    mitre: "T1204.002 — User Execution: Malicious File",
    evidenceType: "File Access, Network Share Access"
  },
  {
    os: "Windows",
    category: "Filesystem",
    artifact: "Jump Lists",
    path: "C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*.automaticDestinations-ms\nC:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\*.customDestinations-ms",
    description: "Taskbar and Start Menu recent/pinned items per application. Each application has a unique AppID. Automatic destinations track recently opened files; custom destinations track pinned items.",
    tool: "JLECmd (Eric Zimmerman), JumpList Explorer",
    reveals: "Recently opened files per application with timestamps, application AppIDs (identify which program opened which file), embedded LNK entries with full target metadata. Traces file access back to specific applications.",
    mitre: "T1204.002 — User Execution: Malicious File",
    evidenceType: "File Access, Application Usage"
  },
  {
    os: "Windows",
    category: "Filesystem",
    artifact: "Recycle Bin",
    path: "C:\\$Recycle.Bin\\<SID>\\$I* (metadata) and $R* (content)",
    description: "Deleted files metadata and content. $I files contain original path, deletion timestamp, and file size. $R files contain the actual deleted file content. Per-user SID directories.",
    tool: "RBCmd (Eric Zimmerman), Autopsy, manual analysis",
    reveals: "Original file path before deletion, deletion timestamp, original file size, actual deleted file content (in $R file). SID in path identifies which user deleted the file.",
    mitre: "T1070.004 — Indicator Removal: File Deletion",
    evidenceType: "Deleted File Recovery, Anti-Forensics Detection"
  },
  {
    os: "Windows",
    category: "Filesystem",
    artifact: "Thumbcache",
    path: "C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db",
    description: "Thumbnail database — Windows generates thumbnails for images, documents, and videos browsed in Explorer. Thumbnails persist in cache even after original files are deleted.",
    tool: "Thumbcache Viewer, Autopsy",
    reveals: "Thumbnail images of files that were browsed in Explorer, including files that have been deleted. Proves visual content existed on the system. Different cache sizes (32, 96, 256, 1024, custom).",
    mitre: "T1083 — File and Directory Discovery",
    evidenceType: "File Content Evidence, Deleted File Remnants"
  },
  {
    os: "Windows",
    category: "Filesystem",
    artifact: "Windows.edb (Windows Search Index)",
    path: "C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb",
    description: "Windows Search index database — contains indexed metadata and partial content of files, emails, and messages on the system. ESE database format. Can contain content of files that have been deleted.",
    tool: "ESEDatabaseView (NirSoft), Autopsy, WinSearchDBAnalyzer",
    reveals: "File paths, metadata (author, dates, tags), partial file content of indexed documents, email subjects and bodies, chat messages. May contain searchable content of files even after deletion.",
    mitre: "T1005 — Data from Local System",
    evidenceType: "File Content, Email Content, Deleted Data Recovery"
  },
  {
    os: "Windows",
    category: "Filesystem",
    artifact: "Volume Shadow Copies",
    path: "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*",
    description: "Point-in-time snapshots of entire volumes. Created by System Restore, Windows Backup, and VSS-aware applications. Contains complete file system state at snapshot time — including deleted or modified files.",
    tool: "vssadmin list shadows, ShadowExplorer, Arsenal Image Mounter",
    reveals: "Previous versions of modified files, deleted files that existed at snapshot time, previous registry hive states, previous event logs. Critical for recovering evidence that the attacker attempted to destroy.",
    mitre: "T1490 — Inhibit System Recovery",
    evidenceType: "Historical File System State, Evidence Recovery"
  },
  {
    os: "Windows",
    category: "Filesystem",
    artifact: "Alternate Data Streams (ADS)",
    path: "Any NTFS file — check with dir /r or Get-Item -Stream *",
    description: "NTFS feature allowing additional data streams attached to any file. The Zone.Identifier ADS marks files downloaded from the internet. Malware can hide payloads in alternate data streams.",
    tool: "streams.exe (Sysinternals), Get-Item -Stream *, dir /r",
    reveals: "Hidden data in alternate streams, Zone.Identifier (download source URL and referrer), Mark of the Web (MotW) data. Files downloaded from internet/email carry Zone.Identifier — absence may indicate defense evasion.",
    mitre: "T1564.004 — Hide Artifacts: NTFS File Attributes",
    evidenceType: "Data Hiding, Download Source, Defense Evasion"
  },

  // ============================================================
  // WINDOWS — BROWSER ARTIFACTS
  // ============================================================
  {
    os: "Windows",
    category: "Browser",
    artifact: "Chrome History & Downloads",
    path: "C:\\Users\\<username>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
    description: "SQLite database containing browsing history (URLs, visit times, visit counts, transition types), download history (URL, path, size, start/end time), and keyword search terms.",
    tool: "DB Browser for SQLite, ChromeHistoryView (NirSoft), Hindsight",
    reveals: "Visited URLs with timestamps and visit count, downloaded file names/paths/URLs, search queries, autofill data. Download timestamps and source URLs are critical for tracking malware delivery.",
    mitre: "T1217 — Browser Information Discovery",
    evidenceType: "Web Activity, Download Source, Malware Delivery"
  },
  {
    os: "Windows",
    category: "Browser",
    artifact: "Chrome Login Data",
    path: "C:\\Users\\<username>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
    description: "SQLite database containing saved website credentials. Passwords encrypted with DPAPI (user-specific key). Can be decrypted with user's Windows password or DPAPI master key.",
    tool: "ChromePass (NirSoft), mimikatz (dpapi::chrome), HackBrowserData",
    reveals: "Saved usernames and passwords for websites, URL of the login page, date created, date last used. Critical target for attackers performing credential theft.",
    mitre: "T1555.003 — Credentials from Password Stores: Credentials from Web Browsers",
    evidenceType: "Credential Access"
  },
  {
    os: "Windows",
    category: "Browser",
    artifact: "Firefox places.sqlite",
    path: "C:\\Users\\<username>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<profile>\\places.sqlite",
    description: "Firefox browsing history, bookmarks, and download history. SQLite database with moz_places (URLs), moz_historyvisits (timestamps), moz_bookmarks, and moz_annos tables.",
    tool: "DB Browser for SQLite, Hindsight, Autopsy",
    reveals: "Complete browsing history with visit timestamps, bookmarks with creation dates, downloaded files with source URLs, favicon references. Firefox stores more detailed visit type information than Chrome.",
    mitre: "T1217 — Browser Information Discovery",
    evidenceType: "Web Activity, Download Source"
  },
  {
    os: "Windows",
    category: "Browser",
    artifact: "Edge/Chrome Session & Tabs",
    path: "C:\\Users\\<username>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Sessions\\*\nC:\\Users\\<username>\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Sessions\\*",
    description: "Session restore data — records all open tabs at the time of last browser close. SNSS format containing tab URLs, titles, and navigation history per tab.",
    tool: "ChromeSessionParser, Hindsight, NirSoft ChromeTabsCounter",
    reveals: "All tabs open when browser was last closed or crashed, navigation history within each tab, timestamps. Shows what the user was actively viewing at a specific time.",
    mitre: "T1217 — Browser Information Discovery",
    evidenceType: "Real-Time User Activity"
  },

  // ============================================================
  // WINDOWS — MEMORY AND PROCESS ARTIFACTS
  // ============================================================
  {
    os: "Windows",
    category: "Memory",
    artifact: "LSASS Process Memory",
    path: "In-memory (lsass.exe, PID from tasklist)",
    description: "Local Security Authority Subsystem Service — holds plaintext passwords (WDigest if enabled), NTLM hashes, Kerberos tickets, and SSP credentials for logged-on users. Primary target for credential dumping.",
    tool: "mimikatz, procdump, comsvcs.dll MiniDump, Task Manager dump",
    reveals: "Plaintext passwords (if WDigest enabled), NTLM password hashes, Kerberos TGT/TGS tickets, SSP/TsPkg credentials, DPAPI master keys. Forensically: check for LSASS access events (Sysmon Event 10) and mini-dump file creation.",
    mitre: "T1003.001 — OS Credential Dumping: LSASS Memory",
    evidenceType: "Credential Access, Attack Detection"
  },
  {
    os: "Windows",
    category: "Memory",
    artifact: "Pagefile.sys",
    path: "C:\\pagefile.sys",
    description: "Virtual memory paging file — contains memory pages that were swapped out of RAM. May contain fragments of passwords, encryption keys, documents, and process data that were in memory.",
    tool: "strings, Volatility, page_brute, bulk_extractor",
    reveals: "Fragments of in-memory data: passwords, URLs, email content, document fragments, process command lines, encryption keys. Cannot be reliably structured — string searching and carving are primary analysis methods.",
    mitre: "T1005 — Data from Local System",
    evidenceType: "Memory Residue, Credential Fragments"
  },
  {
    os: "Windows",
    category: "Memory",
    artifact: "Hibernation File",
    path: "C:\\hiberfil.sys",
    description: "Contains complete memory snapshot when system enters hibernation. Compressed memory image — can be converted to raw format for full memory analysis with Volatility.",
    tool: "Volatility (hibernation layer), Arsenal Image Mounter, hibr2bin",
    reveals: "Complete memory state at hibernation time: all running processes, open network connections, loaded DLLs, kernel structures, credential material, decrypted data. Equivalent to a full memory dump at a specific point in time.",
    mitre: "T1005 — Data from Local System",
    evidenceType: "Complete Memory State Snapshot"
  },

  // ============================================================
  // WINDOWS — NETWORK AND USB ARTIFACTS
  // ============================================================
  {
    os: "Windows",
    category: "Network",
    artifact: "WLAN AutoConfig Log",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx",
    description: "Wireless network connection events — records SSIDs connected to, connection/disconnection times, authentication types, and connection failures.",
    tool: "Event Viewer, EvtxECmd",
    reveals: "WiFi networks connected (SSID names), connection/disconnection timestamps, authentication types (WPA2, WPA3, Open), connection failures with reasons. Proves physical location via known WiFi network names.",
    mitre: "T1016 — System Network Configuration Discovery",
    evidenceType: "Network Activity, Physical Location"
  },
  {
    os: "Windows",
    category: "USB",
    artifact: "USB Device Registry Entries",
    path: "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\nSOFTWARE\\Microsoft\\Windows Portable Devices\\Devices",
    description: "Records every USB storage device that has been connected — device class, vendor, product, serial number, first/last connection times, drive letter assignment.",
    tool: "Registry Explorer, USBDeview (NirSoft), USB Forensic Tracker",
    reveals: "USB device vendor/product/serial number, first install timestamp, last connection timestamp, last removal timestamp, assigned drive letter, volume name, and friendly name. Cross-reference with setupapi.dev.log for additional timestamps.",
    mitre: "T1025 — Data from Removable Media",
    evidenceType: "USB Device History, Data Exfiltration"
  },
  {
    os: "Windows",
    category: "USB",
    artifact: "setupapi.dev.log",
    path: "C:\\Windows\\INF\\setupapi.dev.log",
    description: "Device installation log — records the first time any device (including USB) was connected to the system. Contains exact timestamp and device identifiers.",
    tool: "Text editor, grep/findstr",
    reveals: "First connection timestamp for each USB device, device instance ID, driver installation details, device class. The earliest evidence of USB device connection — more reliable than registry timestamps.",
    mitre: "T1025 — Data from Removable Media",
    evidenceType: "USB First Connection Time"
  },

  // ============================================================
  // LINUX — AUTHENTICATION AND SYSTEM LOGS
  // ============================================================
  {
    os: "Linux",
    category: "Auth Logs",
    artifact: "auth.log / secure",
    path: "/var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL/CentOS)",
    description: "Primary authentication log. Records all authentication events: SSH logins (success/fail), sudo usage, su commands, PAM module events, account lockouts, and key-based auth events.",
    tool: "grep, awk, journalctl -u ssh, GoAccess, Splunk",
    reveals: "SSH login attempts with source IP and username, brute force patterns (rapid failures), sudo command execution with full command line, user switching (su), PAM authentication results, SSH key fingerprints used, account creation/deletion via useradd/userdel",
    mitre: "T1078 — Valid Accounts",
    evidenceType: "Authentication, Privilege Escalation, Remote Access"
  },
  {
    os: "Linux",
    category: "Auth Logs",
    artifact: "wtmp (Login Records)",
    path: "/var/log/wtmp",
    description: "Binary log of all user logins and logouts, system boots, and shutdowns. Each entry contains username, terminal, remote host, login/logout time. Read with 'last' command.",
    tool: "last, utmpdump, who -a",
    reveals: "User login sessions (start/end time), source IP for remote logins, terminal device used (pts/0 = SSH, tty1 = console), system reboot/shutdown events. 'last -f /var/log/wtmp' shows complete login history.",
    mitre: "T1078 — Valid Accounts",
    evidenceType: "Login History, Session Duration"
  },
  {
    os: "Linux",
    category: "Auth Logs",
    artifact: "btmp (Failed Login Records)",
    path: "/var/log/btmp",
    description: "Binary log of failed login attempts. Same format as wtmp but records only failures. Critical for detecting brute force attacks.",
    tool: "lastb, utmpdump",
    reveals: "Failed login usernames (including misspelled names and credential stuffing attempts), source IPs, timestamps, target terminals. High-volume entries from single IP = brute force attack.",
    mitre: "T1110 — Brute Force",
    evidenceType: "Failed Authentication, Brute Force Detection"
  },
  {
    os: "Linux",
    category: "Auth Logs",
    artifact: "lastlog",
    path: "/var/log/lastlog",
    description: "Records the most recent login for each user (sparse file indexed by UID). Quick way to identify which accounts have been actively used.",
    tool: "lastlog",
    reveals: "Last login time, source IP/hostname, and terminal for each system user account. Accounts that have never logged in show 'Never logged in'. Dormant accounts with recent logins may indicate compromise.",
    mitre: "T1078 — Valid Accounts",
    evidenceType: "Account Usage, Dormant Account Detection"
  },

  // ============================================================
  // LINUX — SYSTEM LOGS
  // ============================================================
  {
    os: "Linux",
    category: "System Logs",
    artifact: "syslog / messages",
    path: "/var/log/syslog (Debian/Ubuntu) or /var/log/messages (RHEL/CentOS)",
    description: "General system log — catch-all for kernel messages, service events, cron execution, network events, and application messages not directed to specific log files.",
    tool: "grep, journalctl, less, Splunk, ELK",
    reveals: "Service start/stop events, kernel warnings/errors, USB device connections/disconnections, network interface changes, DHCP events, cron job execution, mount operations, OOM killer events, hardware failures",
    mitre: "T1070.002 — Indicator Removal: Clear Linux or Mac System Logs",
    evidenceType: "System Activity, Hardware Events"
  },
  {
    os: "Linux",
    category: "System Logs",
    artifact: "systemd Journal",
    path: "/var/log/journal/<machine-id>/*.journal (persistent) or /run/log/journal/ (volatile)",
    description: "Structured binary log managed by systemd-journald. Contains all system, kernel, and service logs with rich metadata (PID, UID, unit name, priority). Replaces traditional syslog on systemd systems.",
    tool: "journalctl, journalctl --output=json, systemd-journal-remote",
    reveals: "All system messages with precise timestamps, process attribution (PID, UID, GID, executable path), systemd unit context, kernel messages, boot logs per boot ID. 'journalctl -b -1' shows previous boot, 'journalctl --since yesterday' for time-based filtering.",
    mitre: "T1070.002 — Indicator Removal: Clear Linux or Mac System Logs",
    evidenceType: "Complete System Activity, Process Attribution"
  },
  {
    os: "Linux",
    category: "System Logs",
    artifact: "kern.log",
    path: "/var/log/kern.log",
    description: "Kernel-level messages: module loading/unloading, hardware detection, filesystem errors, network interface events, security module alerts (SELinux/AppArmor), and kernel panics.",
    tool: "dmesg, journalctl -k, grep",
    reveals: "Kernel module loading (insmod/modprobe — rootkit detection), USB device detection, filesystem mount/unmount events, segfault/OOM events, SELinux/AppArmor denials, network interface state changes, iptables/nftables log messages",
    mitre: "T1547.006 — Boot or Logon Autostart Execution: Kernel Modules and Extensions",
    evidenceType: "Kernel Activity, Rootkit Detection"
  },
  {
    os: "Linux",
    category: "System Logs",
    artifact: "dmesg (Kernel Ring Buffer)",
    path: "/var/log/dmesg (boot messages) or 'dmesg' command (current ring buffer)",
    description: "Kernel ring buffer messages from current boot. Contains hardware detection, driver loading, filesystem mounting, and kernel-level errors. The boot dmesg file is static; the live buffer is circular and can be overwritten.",
    tool: "dmesg, dmesg --human --color, journalctl -k",
    reveals: "Boot sequence events, hardware detection and driver binding, USB device connections with vendor/product IDs, filesystem mount operations, network interface initialization, kernel security messages",
    mitre: "T1082 — System Information Discovery",
    evidenceType: "Boot Activity, Hardware Detection"
  },

  // ============================================================
  // LINUX — SHELL AND USER ACTIVITY
  // ============================================================
  {
    os: "Linux",
    category: "User Activity",
    artifact: ".bash_history",
    path: "/home/<username>/.bash_history (or ~/.zsh_history, ~/.ash_history)",
    description: "Command history for bash shell. By default, written on session exit (not real-time). Contains every command executed by the user. Can be configured to include timestamps (HISTTIMEFORMAT).",
    tool: "cat, grep, less",
    reveals: "All commands executed by user (default last 500-2000), including commands with sensitive data (passwords in command line, SSH connections, file operations, downloads, compiled malware). If HISTTIMEFORMAT is set, includes timestamps. Check for gaps — history clearing is an anti-forensics indicator.",
    mitre: "T1552.003 — Unsecured Credentials: Bash History",
    evidenceType: "User Command Execution, Credential Exposure"
  },
  {
    os: "Linux",
    category: "User Activity",
    artifact: ".bash_profile / .bashrc / .profile",
    path: "/home/<username>/.bashrc, /home/<username>/.bash_profile, /home/<username>/.profile, /etc/profile, /etc/bash.bashrc",
    description: "Shell initialization files executed on login (.bash_profile, .profile) or interactive shell start (.bashrc). Attackers modify these for persistence — malicious commands execute every time user opens a shell.",
    tool: "cat, diff (compare with default), AIDE/OSSEC",
    reveals: "Persistence mechanisms: backdoor commands, reverse shells, environment variable manipulation (PATH hijacking), alias hijacking (alias sudo='keylogger && sudo'), malicious function definitions. Compare with default /etc/skel/.bashrc.",
    mitre: "T1546.004 — Event Triggered Execution: Unix Shell Configuration Modification",
    evidenceType: "Persistence, Backdoor Detection"
  },
  {
    os: "Linux",
    category: "User Activity",
    artifact: ".ssh/ Directory",
    path: "/home/<username>/.ssh/ (authorized_keys, known_hosts, config, id_*)",
    description: "SSH configuration and key storage. authorized_keys controls who can log in, known_hosts tracks servers connected to, config has connection shortcuts, and id_rsa/id_ed25519 are private keys.",
    tool: "cat, ssh-keygen -l (fingerprint), diff",
    reveals: "authorized_keys: who has SSH access (look for unexpected keys), known_hosts: what servers this user has connected to, config: SSH connection aliases and proxy configurations, private keys: potential lateral movement material. Hashed known_hosts require ssh-keygen -H to verify specific hosts.",
    mitre: "T1098.004 — Account Manipulation: SSH Authorized Keys",
    evidenceType: "Remote Access, Lateral Movement, Persistence"
  },
  {
    os: "Linux",
    category: "User Activity",
    artifact: ".gnupg/ Directory",
    path: "/home/<username>/.gnupg/",
    description: "GPG keyring and configuration. Contains private keys used for encryption/signing, trust database, and recently encrypted/decrypted file metadata.",
    tool: "gpg --list-keys, gpg --list-secret-keys",
    reveals: "User's encryption keys (public and private), key trust levels, key creation and expiration dates, associated email addresses. Private key access enables decryption of seized encrypted files.",
    mitre: "T1552.004 — Unsecured Credentials: Private Keys",
    evidenceType: "Encryption Keys, Identity"
  },
  {
    os: "Linux",
    category: "User Activity",
    artifact: ".wget-hsts / .python_history / .*_history",
    path: "/home/<username>/.wget-hsts, .python_history, .mysql_history, .psql_history, .node_repl_history",
    description: "Application-specific history files. Track URLs downloaded (wget), Python commands executed, database queries run, and Node.js REPL sessions.",
    tool: "cat, grep",
    reveals: "wget HSTS: URLs previously downloaded. Python history: scripts and commands executed. MySQL history: database queries including potential data exfiltration. PostgreSQL history: similar. Node history: JavaScript execution. These often contain credentials passed on command line.",
    mitre: "T1552.003 — Unsecured Credentials: Bash History",
    evidenceType: "Application Activity, Credential Exposure"
  },

  // ============================================================
  // LINUX — CRON AND SCHEDULED TASKS
  // ============================================================
  {
    os: "Linux",
    category: "Cron",
    artifact: "Crontab Files",
    path: "/var/spool/cron/crontabs/<username> (user crons)\n/etc/crontab (system crontab)\n/etc/cron.d/* (drop-in cron files)\n/etc/cron.{daily,hourly,weekly,monthly}/* (periodic scripts)",
    description: "Scheduled task definitions. User crontabs are per-user; system crontab and cron.d are system-wide. Attackers frequently use cron for persistence — tasks survive reboots and run as specified user.",
    tool: "crontab -l (per user), cat, find /etc/cron* -type f",
    reveals: "Scheduled commands with timing, user context, and full command line. Look for: reverse shells, wget/curl downloads, encoded/obfuscated commands, pipes to sh/bash, connections to external IPs. Cron job modification timestamps help establish timeline.",
    mitre: "T1053.003 — Scheduled Task/Job: Cron",
    evidenceType: "Persistence, Scheduled Execution"
  },
  {
    os: "Linux",
    category: "Cron",
    artifact: "systemd Timers",
    path: "/etc/systemd/system/*.timer (system timers)\n/home/<username>/.config/systemd/user/*.timer (user timers)",
    description: "Modern replacement for cron jobs. Timers trigger associated .service units on schedule. More flexible than cron — supports monotonic timers, random delays, and dependency chains.",
    tool: "systemctl list-timers --all, systemctl cat <timer>",
    reveals: "Scheduled service execution with timing, associated service unit (contains actual command), activation timestamps. 'systemctl list-timers' shows all active timers. Check for recently created timers that don't match known system services.",
    mitre: "T1053.006 — Scheduled Task/Job: Systemd Timers",
    evidenceType: "Persistence, Scheduled Execution"
  },
  {
    os: "Linux",
    category: "Cron",
    artifact: "at Queue",
    path: "/var/spool/at/* (queued jobs)\n/var/spool/at/past/* (completed jobs on some systems)",
    description: "One-time scheduled task queue. 'at' jobs execute once at specified time — sometimes used for delayed persistence or time-bomb execution. Jobs contain full shell scripts.",
    tool: "atq (list queue), at -c <jobid> (show job content)",
    reveals: "Scheduled one-time commands with execution time, job content (full shell script), user who created the job. Delayed execution can indicate time-bomb payloads or delayed lateral movement.",
    mitre: "T1053.001 — Scheduled Task/Job: At",
    evidenceType: "Delayed Execution, Persistence"
  },

  // ============================================================
  // LINUX — PROCESS AND KERNEL ARTIFACTS
  // ============================================================
  {
    os: "Linux",
    category: "Process",
    artifact: "/proc Filesystem",
    path: "/proc/<PID>/ (per-process info)\n/proc/modules, /proc/net/, /proc/mounts, /proc/version",
    description: "Virtual filesystem providing real-time kernel and process information. Each PID directory contains process details. /proc/net/ has network connections, /proc/modules has loaded kernel modules.",
    tool: "cat, ls -la /proc/<PID>/, ps aux, lsof",
    reveals: "/proc/<PID>/cmdline (full command), /proc/<PID>/exe (link to executable — shows path even if file deleted), /proc/<PID>/fd/ (open file descriptors), /proc/<PID>/maps (memory mappings), /proc/<PID>/environ (environment variables including secrets), /proc/<PID>/status (UID/GID, threads, memory usage)",
    mitre: "T1057 — Process Discovery",
    evidenceType: "Running Process Analysis, Live Forensics"
  },
  {
    os: "Linux",
    category: "Process",
    artifact: "/proc/<PID>/exe (Deleted Executable Recovery)",
    path: "/proc/<PID>/exe",
    description: "Symlink to the executable that started the process. Even if the original file is deleted, the link and the file content remain accessible as long as the process runs — critical for recovering deleted malware.",
    tool: "cp /proc/<PID>/exe /tmp/recovered_malware, readlink /proc/<PID>/exe",
    reveals: "Full binary of running process, even if the file has been deleted from disk (shows '(deleted)' suffix). Enables malware sample recovery from live systems without requiring disk forensics.",
    mitre: "T1070.004 — Indicator Removal: File Deletion",
    evidenceType: "Malware Recovery, Anti-Forensics Detection"
  },
  {
    os: "Linux",
    category: "Kernel",
    artifact: "Loaded Kernel Modules",
    path: "/proc/modules (or lsmod output)\n/lib/modules/$(uname -r)/",
    description: "Currently loaded kernel modules. Rootkits often load as kernel modules to hide processes, files, and network connections. Compare loaded modules against known-good list.",
    tool: "lsmod, modinfo <module>, /proc/modules",
    reveals: "All loaded kernel modules with size and dependencies. Unknown modules or modules loaded from unusual paths (/tmp/, /dev/shm/) are rootkit indicators. 'modinfo' shows module description, author, and file path.",
    mitre: "T1547.006 — Boot or Logon Autostart Execution: Kernel Modules and Extensions",
    evidenceType: "Rootkit Detection, Kernel Integrity"
  },

  // ============================================================
  // LINUX — AUDIT AND SECURITY
  // ============================================================
  {
    os: "Linux",
    category: "Audit",
    artifact: "auditd Logs",
    path: "/var/log/audit/audit.log",
    description: "Linux Audit Framework logs — detailed system call auditing when auditd is running. Records syscalls, file access, process execution, network connections, and user commands based on configured audit rules.",
    tool: "ausearch, aureport, auditctl -l (list rules), Splunk, ELK",
    reveals: "SYSCALL events (execve for process creation, open for file access, connect for network), PATH events (file paths accessed), USER_CMD (sudo commands with full command line), USER_AUTH (authentication events), ANOM_ABEND (crashed processes). Audit provides the most detailed Linux forensic data available.",
    mitre: "T1562.012 — Impair Defenses: Disable or Modify Linux Audit System",
    evidenceType: "Detailed System Activity Audit"
  },
  {
    os: "Linux",
    category: "Audit",
    artifact: "SELinux/AppArmor Audit Log",
    path: "/var/log/audit/audit.log (SELinux AVCs)\n/var/log/syslog or /var/log/kern.log (AppArmor)",
    description: "Mandatory Access Control (MAC) denial logs. SELinux logs Access Vector Cache (AVC) denials; AppArmor logs DENIED/ALLOWED events. Both indicate processes attempting to exceed their security policy.",
    tool: "ausearch -m avc, sealert, aa-logprof",
    reveals: "Security policy violations: processes accessing files/ports/capabilities outside their policy. Exploitation attempts often trigger MAC denials before succeeding. AVC denials can reveal attacker reconnaissance (probing what's accessible).",
    mitre: "T1562.001 — Impair Defenses: Disable or Modify Tools",
    evidenceType: "Security Policy Violations, Attack Detection"
  },
  {
    os: "Linux",
    category: "Security",
    artifact: "fail2ban Log",
    path: "/var/log/fail2ban.log",
    description: "fail2ban intrusion prevention logs — records banned IPs, jail triggers, ban durations, and unban events. Tracks brute force attempts that triggered automated blocking.",
    tool: "fail2ban-client status <jail>, grep, less",
    reveals: "Source IPs that triggered brute force detection, which services were targeted (SSH, HTTP, etc.), ban/unban timestamps, number of failures before ban. Historical attack source IPs for threat intelligence correlation.",
    mitre: "T1110 — Brute Force",
    evidenceType: "Brute Force Detection, Attack Source"
  },

  // ============================================================
  // LINUX — NETWORK AND SERVICE ARTIFACTS
  // ============================================================
  {
    os: "Linux",
    category: "Network",
    artifact: "iptables/nftables Logs",
    path: "/var/log/kern.log or /var/log/messages (iptables LOG target)\n/var/log/ufw.log (Ubuntu UFW)",
    description: "Firewall log messages for packets matching LOG rules. Contains source/destination IP, port, protocol, interface, and packet flags for accepted and dropped connections.",
    tool: "grep, journalctl -k, iptables -L -v -n",
    reveals: "Blocked connection attempts (potential scanning or exploitation), accepted connections to services, outbound connection attempts (C2 communication, exfiltration), port scan patterns, DDoS indicators.",
    mitre: "T1046 — Network Service Discovery",
    evidenceType: "Network Security Events, Attack Detection"
  },
  {
    os: "Linux",
    category: "Network",
    artifact: "Apache/Nginx Access Logs",
    path: "/var/log/apache2/access.log or /var/log/nginx/access.log\n/var/log/httpd/access_log (RHEL)",
    description: "Web server access logs — records every HTTP request: source IP, timestamp, method, URL, status code, response size, user agent, referrer. Essential for detecting web application attacks.",
    tool: "GoAccess, AWStats, grep, awk, Splunk, ELK",
    reveals: "SQL injection attempts (UNION SELECT, OR 1=1 in URL), XSS payloads, directory traversal (../), brute force login attempts (POST to /login with 401 responses), web shell access (200 on unusual PHP/ASPX), scanner signatures in User-Agent, exfiltration via GET parameters",
    mitre: "T1190 — Exploit Public-Facing Application",
    evidenceType: "Web Attack Detection, Access Logging"
  },
  {
    os: "Linux",
    category: "Network",
    artifact: "Apache/Nginx Error Logs",
    path: "/var/log/apache2/error.log or /var/log/nginx/error.log",
    description: "Web server error logs — records server errors, configuration issues, and application crashes. Often contains more detail about failed attack attempts than access logs.",
    tool: "grep, tail -f, less",
    reveals: "Application errors triggered by exploitation attempts (PHP fatal errors, permission denied, file not found for traversal), ModSecurity/WAF blocks with rule IDs and matched patterns, SSL/TLS negotiation failures, backend service connection errors",
    mitre: "T1190 — Exploit Public-Facing Application",
    evidenceType: "Attack Evidence, Application Errors"
  },
  {
    os: "Linux",
    category: "Network",
    artifact: "SSH Server Logs (in auth.log)",
    path: "/var/log/auth.log (search for 'sshd')",
    description: "SSH daemon logs within auth.log. Records connection attempts, authentication methods tried, key fingerprints, accepted/rejected connections, and session events.",
    tool: "grep sshd /var/log/auth.log, journalctl -u ssh",
    reveals: "SSH connection source IPs and ports, authentication methods attempted (password, publickey, keyboard-interactive), accepted key fingerprints (match to specific keys), invalid user attempts, session open/close events, X11 forwarding requests, port forwarding requests, forced-command executions",
    mitre: "T1021.004 — Remote Services: SSH",
    evidenceType: "Remote Access, Authentication"
  },
  {
    os: "Linux",
    category: "Service",
    artifact: "Docker/Container Logs",
    path: "/var/lib/docker/containers/<container-id>/<container-id>-json.log\n/var/log/containers/ (Kubernetes)",
    description: "Container stdout/stderr captured by Docker/container runtime. Contains application output, error messages, and any logging from containerized services.",
    tool: "docker logs <container>, kubectl logs <pod>, jq",
    reveals: "Application-level activity within containers, error messages from exploited services, process execution output, network connection logs from container services, container start/stop events with timestamps",
    mitre: "T1610 — Deploy Container",
    evidenceType: "Container Activity, Application Logs"
  },
  {
    os: "Linux",
    category: "Service",
    artifact: "MySQL/PostgreSQL Logs",
    path: "/var/log/mysql/mysql.log (general query log)\n/var/log/mysql/error.log\n/var/log/postgresql/postgresql-*-main.log",
    description: "Database server logs — general query log records all SQL queries (normally disabled for performance), error log records errors and warnings, slow query log records long-running queries.",
    tool: "grep, mysqlbinlog (binary log), pgbadger (PostgreSQL)",
    reveals: "SQL injection attempts (UNION SELECT, SLEEP, BENCHMARK in queries), database credential brute force (connection failures), data exfiltration queries (SELECT INTO OUTFILE, large result sets), privilege escalation (GRANT statements), stored procedure creation for persistence",
    mitre: "T1190 — Exploit Public-Facing Application",
    evidenceType: "Database Activity, SQL Injection Detection"
  },

  // ============================================================
  // LINUX — FILESYSTEM ARTIFACTS
  // ============================================================
  {
    os: "Linux",
    category: "Filesystem",
    artifact: "File Timestamps (MAC times)",
    path: "Any file — use stat or find with -newer",
    description: "Every file has three timestamps: Modify (content change), Access (read — often disabled with noatime), Change (metadata change including permissions, ownership). ext4 adds Birth (creation) time.",
    tool: "stat, ls -la, find -newer, debugfs (birth time on ext4), mactime (Sleuth Kit)",
    reveals: "When files were created, modified, accessed, and metadata changed. Timeline analysis correlates file activity across the system. 'find / -newer /tmp/timestamp -newermt '2024-01-01' -ls' finds files modified after a date. Timestamp manipulation (timestomp) can be detected by comparing against $CHANGE_TIME.",
    mitre: "T1070.006 — Indicator Removal: Timestomp",
    evidenceType: "Timeline Analysis, Anti-Forensics Detection"
  },
  {
    os: "Linux",
    category: "Filesystem",
    artifact: "/tmp and /dev/shm",
    path: "/tmp/, /var/tmp/, /dev/shm/",
    description: "Temporary and shared memory directories — world-writable, commonly used by attackers to stage tools, compile exploits, store exfiltrated data, and run malware. /dev/shm is RAM-backed (contents lost on reboot).",
    tool: "ls -laR, find with -newer/-user/-perm, lsof +D /tmp",
    reveals: "Attacker tools and scripts, compiled exploits, downloaded malware, encoded/encrypted exfiltration staging, named pipes for covert channels. /dev/shm contents are volatile — capture before reboot. Look for hidden files (dotfiles), unusual permissions, and files owned by service accounts.",
    mitre: "T1074.001 — Data Staged: Local Data Staging",
    evidenceType: "Attacker Tooling, Staged Data"
  },
  {
    os: "Linux",
    category: "Filesystem",
    artifact: "/etc/passwd and /etc/shadow",
    path: "/etc/passwd (user accounts), /etc/shadow (password hashes), /etc/group (groups)",
    description: "User account database. /etc/passwd contains usernames, UIDs, home directories, and shells. /etc/shadow contains password hashes and account expiration. Look for unauthorized accounts, UID 0 accounts, and accounts with /bin/bash shell that shouldn't have one.",
    tool: "cat, grep, awk, john (hash cracking), getent",
    reveals: "All user accounts including backdoor accounts, UID 0 accounts (root-equivalent), service accounts with interactive shells (shouldn't have /bin/bash), password hash types and ages, account creation dates (in shadow), accounts with no password (empty hash field)",
    mitre: "T1136.001 — Create Account: Local Account",
    evidenceType: "Account Discovery, Backdoor Detection"
  },
  {
    os: "Linux",
    category: "Filesystem",
    artifact: "SUID/SGID Binaries",
    path: "find / -perm -4000 -o -perm -2000 (system-wide search)",
    description: "Binaries with Set-User-ID or Set-Group-ID bits — execute with the file owner's privileges (usually root). Attackers create or modify SUID binaries for persistent privilege escalation.",
    tool: "find / -perm -4000 -type f -ls, rpm -Va (verify against package manager)",
    reveals: "Custom SUID binaries in unusual locations (/tmp/, /home/, /opt/) are privilege escalation backdoors. Compare against package manager database (dpkg -V, rpm -Va) to find modified system SUID binaries. New SUID files in system directories may indicate rootkit installation.",
    mitre: "T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid",
    evidenceType: "Privilege Escalation, Persistence"
  },
  {
    os: "Linux",
    category: "Filesystem",
    artifact: "Package Manager Logs",
    path: "/var/log/dpkg.log (Debian/Ubuntu)\n/var/log/yum.log or /var/log/dnf.log (RHEL/CentOS)\n/var/log/pacman.log (Arch)",
    description: "Records all software installations, removals, and upgrades. Timestamps show when packages were added or modified. Attackers may install tools (nmap, netcat, gcc) via package manager.",
    tool: "grep, less, rpm -qa --last (RPM-based)",
    reveals: "Software installed/removed with timestamps, package versions, installation method (manual vs. dependency). Unexpected installations of security tools (nmap, netcat, socat, gcc, python-pip) or removal of security software (fail2ban, ossec, aide) indicate attacker activity.",
    mitre: "T1072 — Software Deployment Tools",
    evidenceType: "Software Changes, Tool Installation"
  },
  {
    os: "Linux",
    category: "Filesystem",
    artifact: "/etc/ld.so.preload and LD_PRELOAD",
    path: "/etc/ld.so.preload\nProcess environment: /proc/<PID>/environ",
    description: "Shared library preloading — forces specified libraries to load before all others. Primary mechanism for userland rootkits: intercept libc functions (open, readdir, stat) to hide files, processes, and network connections.",
    tool: "cat /etc/ld.so.preload, ldd <binary>, strace",
    reveals: "Rootkit shared libraries listed in ld.so.preload, environment-based preloading via LD_PRELOAD. Library files in unusual locations (/tmp/, /dev/shm/) are rootkit indicators. Strace can reveal intercepted syscalls returning filtered results.",
    mitre: "T1574.006 — Hijack Execution Flow: Dynamic Linker Hijacking",
    evidenceType: "Rootkit Detection, Library Hijacking"
  },

  // ============================================================
  // CROSS-PLATFORM — CLOUD AND NETWORK
  // ============================================================
  {
    os: "Cross-Platform",
    category: "Cloud",
    artifact: "AWS CloudTrail Logs",
    path: "S3 bucket (configured) or CloudTrail console\naws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin",
    description: "Records every AWS API call: who (IAM identity), what (API action), when (timestamp), from where (source IP), and what was affected (resource ARN). Essential for cloud incident response.",
    tool: "AWS Console, aws cli, Athena, Splunk, ElasticSearch",
    reveals: "Console logins (with source IP and MFA status), IAM key usage, S3 access (GetObject/PutObject), EC2 instance actions, security group changes, IAM policy modifications, KMS key usage, cross-account access, API calls from unusual IPs or at unusual times",
    mitre: "T1078.004 — Valid Accounts: Cloud Accounts",
    evidenceType: "Cloud Activity Audit, API Activity"
  },
  {
    os: "Cross-Platform",
    category: "Cloud",
    artifact: "Azure Activity Log / Sign-in Logs",
    path: "Azure Portal > Monitor > Activity Log, or Azure AD > Sign-in logs\naz monitor activity-log list",
    description: "Azure subscription-level operations log (Activity Log) and Azure AD authentication log (Sign-in logs). Records management plane operations and all authentication events including MFA status, conditional access results, and risk detections.",
    tool: "Azure Portal, az cli, Azure Sentinel, Log Analytics workspace",
    reveals: "Azure AD sign-ins (success/failure, source IP, device info, MFA method), risky sign-ins (flagged by Identity Protection), resource creation/modification/deletion, role assignments, policy changes, key vault access, storage account operations",
    mitre: "T1078.004 — Valid Accounts: Cloud Accounts",
    evidenceType: "Cloud Authentication, Resource Management"
  },
  {
    os: "Cross-Platform",
    category: "Cloud",
    artifact: "GCP Audit Logs",
    path: "GCP Console > Logging > Logs Explorer\ngcloud logging read",
    description: "Google Cloud audit logging: Admin Activity (always on — resource modifications), Data Access (configurable — resource reads), System Events, and Policy Denied logs.",
    tool: "GCP Console, gcloud cli, BigQuery, Chronicle",
    reveals: "Service account key creation/usage, IAM policy changes, Compute Engine actions, Cloud Storage access, GKE cluster operations, Cloud Function invocations, SQL database operations, API call source IPs and user agents",
    mitre: "T1078.004 — Valid Accounts: Cloud Accounts",
    evidenceType: "Cloud Activity Audit"
  },
  {
    os: "Cross-Platform",
    category: "Network",
    artifact: "PCAP Files (Packet Capture)",
    path: "Varies — created by tcpdump, Wireshark, network TAP, or IDS",
    description: "Full network packet capture — raw network traffic recorded in PCAP/PCAPNG format. Contains complete packet data: headers and payloads. The gold standard for network forensics but requires significant storage.",
    tool: "Wireshark, tshark, tcpdump, NetworkMiner, Zeek/Bro, Arkime (Moloch)",
    reveals: "Complete network communications: HTTP requests/responses with content, DNS queries and responses, file transfers (extract with NetworkMiner), credential transmission (cleartext protocols), malware downloads, C2 communications, lateral movement traffic, data exfiltration streams",
    mitre: "T1040 — Network Sniffing",
    evidenceType: "Complete Network Evidence"
  },
  {
    os: "Cross-Platform",
    category: "Network",
    artifact: "NetFlow / IPFIX Records",
    path: "Collected by network devices (routers, firewalls) and sent to collector",
    description: "Network flow metadata — records connections without full payload: source/destination IP and port, protocol, byte/packet counts, timestamps, TCP flags, ToS. Less storage than PCAP, covers longer time periods.",
    tool: "nfdump, SiLK, ntopng, Scrutinizer, Splunk Stream",
    reveals: "Communication patterns between hosts (who talked to whom, when, how much data), top talkers, anomalous data transfers (large outbound flows), beaconing patterns (regular interval callbacks to C2), lateral movement flows (internal host communicating with many others), port scan patterns",
    mitre: "T1049 — System Network Connections Discovery",
    evidenceType: "Network Metadata, Traffic Patterns"
  },
  {
    os: "Cross-Platform",
    category: "Network",
    artifact: "DNS Query Logs",
    path: "/var/log/named/queries.log (BIND)\nWindows DNS Server event log\nPi-hole: /var/log/pihole.log",
    description: "DNS server query logs — records every DNS lookup: queried domain, query type (A/AAAA/TXT/MX), source IP, response, and timestamp. Critical for detecting DNS tunneling, DGA malware, and C2 communication.",
    tool: "grep, awk, dnstop, PassiveDNS, Splunk",
    reveals: "Malware C2 domain lookups, DGA (Domain Generation Algorithm) patterns (random subdomain strings), DNS tunneling (long encoded subdomains, high query rates), data exfiltration via DNS TXT records, NXDOMAIN floods from DGA, newly registered domain queries, fast-flux domain resolution patterns",
    mitre: "T1071.004 — Application Layer Protocol: DNS",
    evidenceType: "C2 Detection, Malware Communication"
  }
];

// Total: 78 forensic artifact entries
// Categories covered: Windows (Registry, Event Logs, Filesystem, Browser, Memory, Network, USB)
//   Linux (Auth, System Logs, User Activity, Cron, Process, Kernel, Audit, Security, Network,
//   Service, Filesystem), Cross-Platform (Cloud, Network)
