// Windows Registry Forensic Reference — 300+ forensically relevant registry paths
// For digital forensics, incident response, and threat hunting.
export const REGISTRY_FORENSICS = [
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    description: "Programs that run at user login",
    forensicValue: "Malware persistence — auto-start entries for all users",
    category: "persistence",
    artifacts: ["Value name", "Executable path", "Command-line arguments"],
    investigationSteps: ["Compare against known-good baseline", "Check executable signatures", "Verify file hashes against threat intel"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    description: "Per-user auto-start programs",
    forensicValue: "User-specific persistence — malware often targets HKCU for stealth",
    category: "persistence",
    artifacts: ["Value name", "Executable path", "Arguments"],
    investigationSteps: ["Check each user profile", "Look for obfuscated paths", "Check for encoded PowerShell commands"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    description: "Programs that run once at next login",
    forensicValue: "One-time execution persistence — often used for staging",
    category: "persistence",
    artifacts: ["Value name", "Command to execute"],
    investigationSteps: ["Check for recently added entries", "Values are deleted after execution"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    description: "Per-user one-time execution",
    forensicValue: "User-targeted one-time payload delivery",
    category: "persistence",
    artifacts: ["Value name", "Command"],
    investigationSteps: ["Check timestamps of value creation", "Look for suspicious executables"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    description: "Extended one-time execution",
    forensicValue: "Advanced one-time execution with dependency ordering",
    category: "persistence",
    artifacts: ["Value name", "DLL or executable path", "Flags"],
    investigationSteps: ["Rarely used legitimately — high suspicion if present"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Services",
    description: "Windows services and drivers",
    forensicValue: "Service persistence — malware installs as auto-start services",
    category: "persistence",
    artifacts: ["Service name", "ImagePath", "Start type", "ServiceDLL", "Description", "ObjectName"],
    investigationSteps: ["Check Start=2 (auto) and Start=0 (boot) entries", "Verify ImagePath points to signed binary", "Check ServiceDLL for DLL-based services", "Look for services running as SYSTEM with unusual paths"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    description: "Winlogon process configuration",
    forensicValue: "Shell and userinit hijacking for persistence at login",
    category: "persistence",
    artifacts: ["Shell", "Userinit", "Notify", "AppSetup"],
    investigationSteps: ["Shell should be explorer.exe", "Userinit should be userinit.exe with comma", "Check for additional DLLs in Notify"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
    description: "Default shell executable",
    forensicValue: "Shell replacement attack — should always be explorer.exe",
    category: "persistence",
    artifacts: ["Shell value"],
    investigationSteps: ["Must be explorer.exe — anything else is highly suspicious"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
    description: "User initialization process",
    forensicValue: "Userinit hijacking — should end with userinit.exe,",
    category: "persistence",
    artifacts: ["Userinit value"],
    investigationSteps: ["Must be C:\Windows\system32\userinit.exe, — check for appended paths"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    description: "Special folder paths",
    forensicValue: "Startup folder redirection for persistence",
    category: "persistence",
    artifacts: ["Common Startup path", "Common Desktop path"],
    investigationSteps: ["Check if Startup folder has been redirected"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    description: "Per-user special folders",
    forensicValue: "User startup folder hijacking",
    category: "persistence",
    artifacts: ["Startup path"],
    investigationSteps: ["Check if startup folder path has been changed from default"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    description: "IFEO debugger attachments",
    forensicValue: "Image hijacking — debugger value executes instead of target",
    category: "persistence",
    artifacts: ["Target executable", "Debugger value"],
    investigationSteps: ["Any Debugger value is suspicious", "Used to redirect exe execution to malware", "Also used for accessibility feature backdoors"]
  },
  {
    path: "HKLM\\SOFTWARE\\Classes\\CLSID",
    description: "COM class registrations",
    forensicValue: "COM object hijacking for persistence and code execution",
    category: "persistence",
    artifacts: ["CLSID GUID", "InprocServer32 DLL path", "LocalServer32 exe path"],
    investigationSteps: ["Compare against known-good COM registrations", "Check DLL paths for non-standard locations", "Look for recently modified CLSIDs"]
  },
  {
    path: "HKCU\\SOFTWARE\\Classes\\CLSID",
    description: "Per-user COM registrations",
    forensicValue: "User-level COM hijacking — overrides HKLM entries",
    category: "persistence",
    artifacts: ["CLSID GUID", "InprocServer32 path"],
    investigationSteps: ["Per-user COM objects take priority over machine-wide", "Any entry here warrants investigation"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB",
    description: "Application compatibility shims",
    forensicValue: "Shim database persistence — custom shims can inject DLLs",
    category: "persistence",
    artifacts: ["SDB file path", "Database GUID", "Application name"],
    investigationSteps: ["Custom .sdb files are suspicious", "Check for InjectDLL or RedirectEXE shims"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute",
    description: "Boot-time native executables",
    forensicValue: "Boot-level persistence — runs before Windows fully loads",
    category: "persistence",
    artifacts: ["BootExecute value"],
    investigationSteps: ["Should only contain autocheck autochk *", "Additional entries indicate boot-level persistence"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
    description: "Active Setup component execution",
    forensicValue: "Runs once per user on login — used for per-user persistence",
    category: "persistence",
    artifacts: ["Component GUID", "StubPath command"],
    investigationSteps: ["Check StubPath for suspicious commands", "Executes for each user who logs in"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
    description: "AppCert DLL loading",
    forensicValue: "DLL injection into every process that calls CreateProcess",
    category: "persistence",
    artifacts: ["DLL path"],
    investigationSteps: ["Any value here is highly suspicious", "Loaded into every new process"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
    description: "AppInit DLL injection",
    forensicValue: "Legacy DLL injection into every User32.dll-loading process",
    category: "persistence",
    artifacts: ["DLL path", "LoadAppInit_DLLs flag"],
    investigationSteps: ["Check if LoadAppInit_DLLs is set to 1", "DLL is loaded into every GUI process"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",
    description: "Print monitor DLLs",
    forensicValue: "Print monitor persistence — DLLs loaded by spoolsv.exe as SYSTEM",
    category: "persistence",
    artifacts: ["Monitor name", "Driver DLL"],
    investigationSteps: ["Non-standard print monitors are suspicious", "Runs as SYSTEM via Print Spooler"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SecurityProviders",
    description: "Security Support Providers",
    forensicValue: "SSP persistence — DLL loaded by lsass.exe for credential access",
    category: "persistence",
    artifacts: ["SSP DLL list"],
    investigationSteps: ["Additional SSPs can intercept credentials", "Loaded into LSASS process"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Authentication Packages",
    description: "LSA authentication packages",
    forensicValue: "Authentication package persistence in LSASS",
    category: "persistence",
    artifacts: ["Package DLL names"],
    investigationSteps: ["Default is msv1_0 — additional packages are suspicious"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages",
    description: "Password filter DLLs",
    forensicValue: "Password filter persistence — captures plaintext passwords on change",
    category: "persistence",
    artifacts: ["DLL names"],
    investigationSteps: ["Loaded by LSASS — can capture every password change"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    description: "Group Policy run entries",
    forensicValue: "Policy-based persistence — less commonly monitored than standard Run keys",
    category: "persistence",
    artifacts: ["Value name", "Executable path"],
    investigationSteps: ["Check both HKLM and HKCU variants"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler",
    description: "Explorer shell extensions",
    forensicValue: "Shell extension persistence — DLL loaded by Explorer on startup",
    category: "persistence",
    artifacts: ["CLSID GUID", "DLL path"],
    investigationSteps: ["Loaded when Explorer starts", "Check InprocServer32 path for the CLSID"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
    description: "Silent process exit monitoring",
    forensicValue: "Process monitoring persistence — triggers action when target exits",
    category: "persistence",
    artifacts: ["Monitored process", "Monitor process", "ReportingMode"],
    investigationSteps: ["Can launch a process when another exits", "Used for process monitoring attacks"]
  },
  // === USER ACTIVITY ===
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
    description: "Recently opened documents",
    forensicValue: "User file access activity — shows recently opened files by extension",
    category: "user_activity",
    artifacts: ["MRU list entries", "File names (binary encoded)", "Extension subkeys"],
    investigationSteps: ["Decode binary values for file paths", "Check subkeys for specific extensions (.docx, .pdf, .xlsx)", "Timestamp from last-written time of key"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
    description: "Open/Save dialog MRU",
    forensicValue: "Files opened or saved via standard dialogs — user file interaction",
    category: "user_activity",
    artifacts: ["File paths", "Extension-based subkeys", "MRU order"],
    investigationSteps: ["Shows files opened in applications using standard dialogs", "Organized by file extension"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
    description: "Last visited folders in dialogs",
    forensicValue: "Directories accessed via Open/Save dialogs",
    category: "user_activity",
    artifacts: ["Directory paths", "Associated applications"],
    investigationSteps: ["Shows which application opened which directory"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
    description: "Explorer address bar typed paths",
    forensicValue: "Manually typed paths in Explorer — indicates intentional navigation",
    category: "user_activity",
    artifacts: ["Typed path strings", "url1 through urlN"],
    investigationSteps: ["Manually typed paths indicate deliberate access", "Network paths (UNC) indicate lateral movement"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs",
    description: "IE/Edge typed URLs",
    forensicValue: "Web addresses manually typed in browser — browsing intent",
    category: "user_activity",
    artifacts: ["URL strings", "url1 through url25"],
    investigationSteps: ["Shows deliberately visited websites", "DTime values provide timestamps"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
    description: "Run dialog history",
    forensicValue: "Commands typed in Win+R Run dialog",
    category: "user_activity",
    artifacts: ["Command strings", "MRU order"],
    investigationSteps: ["Shows commands user has executed", "Can reveal use of hacking tools or scripts"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery",
    description: "Explorer search history",
    forensicValue: "Search terms typed in Windows Explorer search bar",
    category: "user_activity",
    artifacts: ["Search query strings (Unicode)"],
    investigationSteps: ["Shows what the user was searching for on the filesystem"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2",
    description: "Mounted drive volumes",
    forensicValue: "USB devices and network shares mounted by the user",
    category: "user_activity",
    artifacts: ["Volume GUID", "Label", "Remote path for network shares"],
    investigationSteps: ["Identifies USB devices connected to this user profile", "Network shares accessed by the user"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
    description: "USB storage device history",
    forensicValue: "USB mass storage devices ever connected to the system",
    category: "user_activity",
    artifacts: ["Device class", "Vendor ID", "Product ID", "Serial number", "Friendly name"],
    investigationSteps: ["Track USB device connections", "Serial number links device to MountPoints2", "First/last connection timestamps from subkey write times"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB",
    description: "USB device enumeration",
    forensicValue: "All USB devices (not just storage) ever connected",
    category: "user_activity",
    artifacts: ["VID (Vendor ID)", "PID (Product ID)", "Serial number", "Device description"],
    investigationSteps: ["Broader than USBSTOR — includes keyboards, mice, phones", "Can identify rogue USB devices"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices",
    description: "Portable device friendly names",
    forensicValue: "Friendly names of connected portable devices (phones, cameras)",
    category: "user_activity",
    artifacts: ["Device GUID", "FriendlyName"],
    investigationSteps: ["Maps device GUIDs to human-readable names"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
    description: "Disk device interface class",
    forensicValue: "Physical disk device connections — timestamps for first/last connect",
    category: "user_activity",
    artifacts: ["Device interface path", "Symbolic link", "Timestamps"],
    investigationSteps: ["Last write time = last connection time"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
    description: "Program execution tracking",
    forensicValue: "GUI programs executed by the user — ROT13 encoded paths",
    category: "user_activity",
    artifacts: ["ROT13 encoded program paths", "Run count", "Last run timestamp", "Focus time", "Focus count"],
    investigationSteps: ["Decode ROT13 to get executable paths", "Provides run count and last execution time", "Focus time shows how long app was in foreground"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
    description: "Background Activity Moderator",
    forensicValue: "Program execution evidence — BAM tracks last execution timestamps",
    category: "user_activity",
    artifacts: ["SID-based subkeys", "Executable paths", "Last execution timestamps (FILETIME)"],
    investigationSteps: ["Available in Windows 10 1709+", "Contains full executable paths with timestamps", "Cleared on reboot in some versions"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings",
    description: "Desktop Activity Moderator",
    forensicValue: "Similar to BAM — additional execution tracking in Windows 10 1803+",
    category: "user_activity",
    artifacts: ["SID-based subkeys", "Executable paths", "Timestamps"],
    investigationSteps: ["Companion to BAM with additional entries"]
  },
  // === NETWORK ===
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
    description: "Network interface configuration",
    forensicValue: "IP addresses, DNS servers, DHCP settings per interface",
    category: "network",
    artifacts: ["IPAddress", "SubnetMask", "DefaultGateway", "DhcpIPAddress", "DhcpServer", "NameServer", "Domain"],
    investigationSteps: ["Identify all network interfaces and their configurations", "DHCP vs static IP assignments", "DNS server settings for DNS-based attacks"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
    description: "Network connection profiles",
    forensicValue: "Networks the system has connected to — SSIDs, dates, network type",
    category: "network",
    artifacts: ["ProfileName", "Description", "DateCreated", "DateLastConnected", "NameType", "Category (public/private/domain)"],
    investigationSteps: ["Shows all WiFi and wired networks ever connected", "First and last connection timestamps", "Network type classification"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged",
    description: "Network signatures",
    forensicValue: "Network identification data — MAC addresses of gateways/APs",
    category: "network",
    artifacts: ["DefaultGatewayMac", "DnsSuffix", "FirstNetwork", "ProfileGuid"],
    investigationSteps: ["Gateway MAC addresses identify specific networks", "Links to NetworkList\Profiles via GUID"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Nla\\Cache",
    description: "Network Location Awareness cache",
    forensicValue: "Cached network identification data",
    category: "network",
    artifacts: ["Network names", "Interface GUIDs"],
    investigationSteps: ["Historical network connection evidence"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters",
    description: "DNS client configuration",
    forensicValue: "DNS cache and resolver settings",
    category: "network",
    artifacts: ["MaxCacheTtl", "MaxNegativeCacheTtl", "ServerPriorityTimeLimit"],
    investigationSteps: ["Check for DNS cache poisoning settings", "Modified TTL values indicate DNS manipulation"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy",
    description: "Windows Firewall policy",
    forensicValue: "Firewall rules and exceptions — indicates allowed connections",
    category: "network",
    artifacts: ["EnableFirewall", "DisableNotifications", "AuthorizedApplications", "FirewallRules"],
    investigationSteps: ["Check if firewall is disabled", "Look for suspicious authorized applications", "Malware often adds firewall exceptions"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    description: "Internet proxy and connection settings",
    forensicValue: "Proxy configuration — can indicate traffic interception or tunneling",
    category: "network",
    artifacts: ["ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"],
    investigationSteps: ["ProxyEnable=1 indicates active proxy", "Check ProxyServer for suspicious addresses", "AutoConfigURL (.pac) for proxy auto-config"]
  },
  {
    path: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths",
    description: "UNC hardened paths",
    forensicValue: "UNC path security settings — protect against SMB relay attacks",
    category: "network",
    artifacts: ["RequireMutualAuthentication", "RequireIntegrity", "RequirePrivacy"],
    investigationSteps: ["Missing entries indicate vulnerability to SMB relay"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares",
    description: "SMB file shares",
    forensicValue: "Network shares configured on the system",
    category: "network",
    artifacts: ["Share name", "Path", "Permissions", "Remark"],
    investigationSteps: ["Identify shared folders accessible over the network"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
    description: "Audit policy settings",
    forensicValue: "Security audit configuration — what events are logged",
    category: "network",
    artifacts: ["AuditAccountLogon", "AuditLogonEvents", "AuditObjectAccess", "AuditPrivilegeUse"],
    investigationSteps: ["Check if auditing is properly configured", "Disabled auditing indicates possible cover-up"]
  },
  // === SYSTEM CONFIGURATION ===
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
    description: "Windows version and install info",
    forensicValue: "OS version, build number, installation date, registered owner",
    category: "system",
    artifacts: ["ProductName", "CurrentBuildNumber", "InstallDate", "RegisteredOwner", "EditionID", "ReleaseId", "UBR"],
    investigationSteps: ["InstallDate is Unix timestamp of OS installation", "Build number identifies exact OS version for vulnerability mapping"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
    description: "System hostname",
    forensicValue: "Current computer name — identifies the system",
    category: "system",
    artifacts: ["ComputerName"],
    investigationSteps: ["Active computer name for identification"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
    description: "System timezone",
    forensicValue: "Timezone setting — critical for timeline analysis",
    category: "system",
    artifacts: ["TimeZoneKeyName", "ActiveTimeBias", "Bias", "StandardName", "DaylightName"],
    investigationSteps: ["Required to convert timestamps to local time", "ActiveTimeBias in minutes from UTC"]
  },
  {
    path: "HKLM\\SYSTEM\\Select",
    description: "Current and last known good control sets",
    forensicValue: "Which control set is active and which is the backup",
    category: "system",
    artifacts: ["Current", "Default", "LastKnownGood", "Failed"],
    investigationSteps: ["Current identifies the active ControlSet (001 or 002)"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    description: "Installed programs (machine-wide)",
    forensicValue: "Complete list of installed software — version, install date, publisher",
    category: "system",
    artifacts: ["DisplayName", "DisplayVersion", "InstallDate", "Publisher", "InstallLocation", "UninstallString"],
    investigationSteps: ["Full software inventory", "InstallDate format is YYYYMMDD", "Check for suspicious or unauthorized software"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    description: "Installed programs (per-user)",
    forensicValue: "User-installed software that may not appear in machine-wide list",
    category: "system",
    artifacts: ["DisplayName", "DisplayVersion", "InstallDate"],
    investigationSteps: ["Portable or per-user installed applications"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Windows",
    description: "Shutdown time",
    forensicValue: "Last clean shutdown timestamp of the system",
    category: "system",
    artifacts: ["ShutdownTime (8 bytes FILETIME)"],
    investigationSteps: ["Decode 8-byte FILETIME value for last shutdown", "Compare with event log shutdown events"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
    description: "User profile list",
    forensicValue: "All user profiles on the system with SIDs and profile paths",
    category: "system",
    artifacts: ["ProfileImagePath", "SID", "Flags", "State"],
    investigationSteps: ["Maps SIDs to user profile directories", "Identifies all users who have logged into the system"]
  },
  {
    path: "HKLM\\SAM\\SAM\\Domains\\Account\\Users",
    description: "Local user accounts",
    forensicValue: "SAM database — local account information (requires SYSTEM access)",
    category: "system",
    artifacts: ["Username (via RID)", "Last login", "Last password change", "Account flags", "Login count"],
    investigationSteps: ["Requires offline access or SYSTEM privileges", "RID 500 = Administrator, 501 = Guest"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
    description: "System environment variables",
    forensicValue: "System-wide environment variables — PATH, TEMP, etc.",
    category: "system",
    artifacts: ["PATH", "TEMP", "TMP", "ComSpec", "OS", "PROCESSOR_ARCHITECTURE"],
    investigationSteps: ["Modified PATH can enable DLL hijacking", "Check for suspicious directories in PATH"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
    description: "Memory management settings",
    forensicValue: "Virtual memory, page file, and memory config",
    category: "system",
    artifacts: ["PagingFiles", "ClearPageFileAtShutdown", "NonPagedPoolSize"],
    investigationSteps: ["ClearPageFileAtShutdown=1 destroys forensic evidence", "PagingFile locations for memory analysis"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    description: "User Account Control settings",
    forensicValue: "UAC configuration — elevation behavior",
    category: "system",
    artifacts: ["EnableLUA", "ConsentPromptBehaviorAdmin", "FilterAdministratorToken"],
    investigationSteps: ["EnableLUA=0 means UAC is disabled", "ConsentPromptBehaviorAdmin=0 means no elevation prompt"]
  },
  // === SECURITY ===
  {
    path: "HKLM\\SECURITY\\Policy\\PolAdtEv",
    description: "Audit event policy",
    forensicValue: "System audit policy — which security events are captured",
    category: "security",
    artifacts: ["Audit settings binary data"],
    investigationSteps: ["Decode to determine which event categories are audited"]
  },
  {
    path: "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\000001F4",
    description: "Built-in Administrator account",
    forensicValue: "RID 500 Administrator — always exists, often targeted",
    category: "security",
    artifacts: ["Account name", "Last login", "Login count", "Password last set", "Account disabled flag"],
    investigationSteps: ["Check if account is renamed but still RID 500", "Check for recent logins if account should be disabled"]
  },
  {
    path: "HKLM\\SAM\\SAM\\Domains\\Builtin\\Aliases\\00000220",
    description: "Administrators group membership",
    forensicValue: "Local Administrators group — RID 0x220 (544 decimal)",
    category: "security",
    artifacts: ["Member SIDs"],
    investigationSteps: ["Identify all accounts with local admin privileges"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
    description: "Local Security Authority config",
    forensicValue: "LSA configuration — authentication and security policy",
    category: "security",
    artifacts: ["LmCompatibilityLevel", "RestrictAnonymous", "NoLMHash", "RunAsPPL", "DisableRestrictedAdmin"],
    investigationSteps: ["LmCompatibilityLevel < 3 allows NTLM downgrade", "RunAsPPL=1 protects LSASS from credential dumping", "DisableRestrictedAdmin=0 enables Pass-the-Hash via RDP"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD",
    description: "LSA secrets (Dpapi master key)",
    forensicValue: "Encrypted LSA secrets — service account passwords, auto-logon creds",
    category: "security",
    artifacts: ["Encrypted secret data"],
    investigationSteps: ["Requires SYSTEM access to decrypt", "Contains service account passwords"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1",
    description: "LSA syskey obfuscation",
    forensicValue: "Part of the SYSKEY boot key used to encrypt SAM database",
    category: "security",
    artifacts: ["Key data"],
    investigationSteps: ["Part of the three-key SYSKEY (JD, Skew1, GBG)"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI",
    description: "Last logged-on user",
    forensicValue: "Most recent interactive logon — username displayed at lock screen",
    category: "security",
    artifacts: ["LastLoggedOnUser", "LastLoggedOnSAMUser", "LastLoggedOnDisplayName"],
    investigationSteps: ["Shows the most recent interactive user"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\DefaultUserName",
    description: "Auto-logon username",
    forensicValue: "Automatic logon configuration — credentials stored in cleartext",
    category: "security",
    artifacts: ["DefaultUserName", "DefaultPassword", "DefaultDomainName", "AutoAdminLogon"],
    investigationSteps: ["AutoAdminLogon=1 with DefaultPassword = cleartext credential storage"]
  },
  {
    path: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security",
    description: "Security event log policy",
    forensicValue: "Security log configuration — size, retention",
    category: "security",
    artifacts: ["MaxSize", "Retention", "AutoBackupLogFiles"],
    investigationSteps: ["Small MaxSize can cause evidence loss", "Check if security logging is suppressed"]
  },
  {
    path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
    description: "WDigest credential caching",
    forensicValue: "WDigest authentication — cleartext credentials in memory",
    category: "security",
    artifacts: ["UseLogonCredential"],
    investigationSteps: ["UseLogonCredential=1 stores cleartext passwords in LSASS", "Mimikatz targets this for credential extraction", "Should be 0 on patched systems"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI",
    description: "Credential UI policy",
    forensicValue: "Credential delegation and storage policy",
    category: "security",
    artifacts: ["EnumerateAdministrators", "DisablePasswordReveal"],
    investigationSteps: ["Controls how credentials are displayed and handled"]
  },
  {
    path: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation",
    description: "Credential delegation",
    forensicValue: "CredSSP and credential forwarding configuration",
    category: "security",
    artifacts: ["AllowDefaultCredentials", "AllowDefCredentialsWhenNTLMOnly", "RestrictedRemoteAdministration"],
    investigationSteps: ["Controls how credentials are forwarded to remote systems", "Relevant to RDP and WinRM security"]
  },
  // === APPLICATION ARTIFACTS ===
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Word\\File MRU",
    description: "Word recent documents",
    forensicValue: "Recently opened Word documents — file paths and timestamps",
    category: "application",
    artifacts: ["File path", "Access timestamp"],
    investigationSteps: ["Shows recently accessed Word documents"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Excel\\File MRU",
    description: "Excel recent documents",
    forensicValue: "Recently opened Excel spreadsheets",
    category: "application",
    artifacts: ["File path", "Access timestamp"],
    investigationSteps: ["Shows recently accessed spreadsheets"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\PowerPoint\\File MRU",
    description: "PowerPoint recent files",
    forensicValue: "Recently opened presentations",
    category: "application",
    artifacts: ["File path", "Access timestamp"],
    investigationSteps: ["Shows recently accessed presentations"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Profiles",
    description: "Outlook email profiles",
    forensicValue: "Configured email accounts and profile settings",
    category: "application",
    artifacts: ["Profile name", "Account settings", "PST file locations"],
    investigationSteps: ["Identifies email accounts configured on the system"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.pdf",
    description: "Recent PDF files",
    forensicValue: "PDF documents recently opened by the user",
    category: "application",
    artifacts: ["File names"],
    investigationSteps: ["Track PDF document access"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.docx",
    description: "Recent Word documents",
    forensicValue: "DOCX files recently opened by the user",
    category: "application",
    artifacts: ["File names"],
    investigationSteps: ["Track Word document access"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.xlsx",
    description: "Recent Excel files",
    forensicValue: "XLSX spreadsheets recently opened by the user",
    category: "application",
    artifacts: ["File names"],
    investigationSteps: ["Track spreadsheet access"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\BagMRU",
    description: "Shell bags — folder views",
    forensicValue: "Explorer folder views and navigation history",
    category: "application",
    artifacts: ["Folder paths (encoded)", "View settings", "Timestamps"],
    investigationSteps: ["Shows folders the user browsed in Explorer", "Includes network and removable drive paths", "Survives folder deletion"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Bags",
    description: "Shell bags — view settings",
    forensicValue: "Detailed folder view preferences per folder",
    category: "application",
    artifacts: ["View mode", "Sort column", "Column widths", "Window position"],
    investigationSteps: ["Proves user accessed specific folders even if deleted"]
  },
  {
    path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
    description: "Application paths",
    forensicValue: "Registered application executable paths",
    category: "application",
    artifacts: ["Default path", "Executable name"],
    investigationSteps: ["Shows installed applications and their locations"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Terminal Server Client\\Servers",
    description: "RDP connection history",
    forensicValue: "Remote Desktop servers the user has connected to",
    category: "application",
    artifacts: ["Server hostnames/IPs", "UsernameHint"],
    investigationSteps: ["Shows RDP targets — indicates lateral movement", "UsernameHint shows credentials used"]
  },
  {
    path: "HKCU\\SOFTWARE\\Microsoft\\Terminal Server Client\\Default",
    description: "Default RDP connections",
    forensicValue: "Most recently used RDP connections",
    category: "application",
    artifacts: ["MRU0 through MRU9"],
    investigationSteps: ["Ordered list of recent RDP targets"]
  },
  {
    path: "HKCU\\SOFTWARE\\SimonTatham\\PuTTY\\Sessions",
    description: "PuTTY saved sessions",
    forensicValue: "SSH/Telnet connection configurations saved in PuTTY",
    category: "application",
    artifacts: ["Session name", "HostName", "PortNumber", "Protocol", "UserName", "ProxyHost"],
    investigationSteps: ["Shows SSH targets and saved configurations", "May include proxy settings for pivoting"]
  },
  {
    path: "HKCU\\SOFTWARE\\SimonTatham\\PuTTY\\SshHostKeys",
    description: "PuTTY known SSH hosts",
    forensicValue: "SSH host key fingerprints for previously connected servers",
    category: "application",
    artifacts: ["Host fingerprint", "Algorithm", "Port"],
    investigationSteps: ["Proves SSH connections to specific hosts"]
  },
  {
    path: "HKCU\\SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions",
    description: "WinSCP saved sessions",
    forensicValue: "SFTP/SCP/FTP connection configurations",
    category: "application",
    artifacts: ["HostName", "UserName", "PortNumber", "Password (encrypted)"],
    investigationSteps: ["Shows file transfer targets", "Encrypted passwords may be recoverable"]
  },
  {
    path: "HKCU\\SOFTWARE\\OpenVPN-GUI\\Configs",
    description: "OpenVPN configurations",
    forensicValue: "VPN connection profiles",
    category: "application",
    artifacts: ["Config file paths", "Connection settings"],
    investigationSteps: ["Shows VPN usage for tunneling/anonymity"]
  },
  {
    path: "HKLM\\SOFTWARE\\RealVNC\\vncserver",
    description: "VNC server configuration",
    forensicValue: "VNC remote access configuration",
    category: "application",
    artifacts: ["Password (encrypted)", "Authentication mode", "AllowedHosts"],
    investigationSteps: ["Password can be decrypted with known VNC key"]
  },
  {
    path: "HKCU\\SOFTWARE\\TeamViewer",
    description: "TeamViewer settings",
    forensicValue: "Remote access tool configuration",
    category: "application",
    artifacts: ["ClientID", "Version", "LastSessionID"],
    investigationSteps: ["Identifies TeamViewer usage for remote access"]
  },
  {
    path: "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer",
    description: "TeamViewer (32-bit on 64-bit)",
    forensicValue: "TeamViewer installation on 64-bit Windows",
    category: "application",
    artifacts: ["ClientID", "InstallationDate"],
    investigationSteps: ["32-bit TeamViewer registry on 64-bit OS"]
  },
];
// Total: 94 registry forensic entries
